//! The agent's brain: what state we are in, when to re-inject, and every call
//! into the rest of the client.
//!
//! The platform's agent crate draws; this decides. The split is deliberate -- a
//! window procedure stays a pure function of [`Status`], and nothing here knows a
//! control handle. Which is also why this is in the core and not in the Windows
//! agent that was its first caller: the re-injection schedule below is the whole
//! of what keeps a ticket alive, and a second platform reimplementing it would be
//! a second chance to get it wrong.
//!
//! What it cannot do without a UI it asks for, through [`Host`].
//!
//! **Threading.** Sign-in blocks on a browser and two network round trips, and
//! an elevated one-shot blocks on UAC, so both run on worker threads. A worker
//! never touches this module's state: it queues an [`Event`] and wakes the UI
//! thread, which applies it in [`drain`]. So all mutable state lives in one
//! thread-local `RefCell` with no lock and no data race, and the only shared
//! items are the ones the workers genuinely need -- a cancel flag, the queue, and
//! the in-memory refresh token.
//!
//! **The lifecycle this implements.** Windows renews an injected TGT at T−15m,
//! the KDC grants it, and Windows never installs the result (measured); worse, a
//! TGT that expires while an SMB session is open drops the redirector into a
//! stuck NTLM fallback, which only an elevated restart of Windows Workstation
//! service clears. So
//! re-injection at ~50 % of ticket lifetime is not a convenience -- it is the
//! thing that prevents the worst measured failure mode, and it must always land
//! before End Time.

mod commands;
mod failure;
mod status;
mod worker;

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::config::{Grant, Settings};
use crate::describe::{Action, Fault};
use crate::discovery::{Defaults, DeviceGrantConfig, KerberosConfig, OidcConfig};
use crate::strings::{days, duration, fill, tr};
use crate::{enroll, log, tickets, time};

use worker::Trigger;

/// One `agent::` surface, whichever file an item is filed under: a caller has no
/// reason to know which side of the threading seam a command runs on, or whether
/// what it reads is assembled next to the state or beside the verbs.
pub use commands::{
    SettingsChange, SettingsView, apply_settings, autostart_sign_in, cancel_sign_in, drop_ticket,
    give_up_grant_now, interruption_gate, open_log, open_log_folder, renew_now, settings_view,
    sign_in, sign_out_idp, silent, status_closed,
};
pub use status::{Status, TicketClock, status};
pub use worker::{begin_enroll, begin_reenroll, begin_repair, begin_unenroll, create_grant, drain};

/// Escalate the "sign in again" notification this close to End Time.
const ESCALATE_SECS: i64 = 20 * 60;
/// Floor on the re-injection delay, so a short-lived ticket cannot spin.
const MIN_REFRESH_DELAY: i64 = 60;
/// Never schedule a re-injection closer than this to End Time.
const EXPIRY_GRACE: i64 = 30;
/// How long to wait before another go at the autostart sign-in: the first step
/// of the backoff a `Fault::Network` failure keeps doubling from -- see
/// [`next_backoff`]. A logon race is the expected reason for the first one to
/// fail -- the agent is running before the network is, which usually resolves in
/// seconds -- but "usually" is not "always", and a machine that gave up outright
/// would need a click or a reboot to notice a VPN that came up two minutes late.
/// So this never stops on its own; it only ever backs off, to the same ceiling
/// [`PROBE_MAX_SECS`] doubles to.
const STARTUP_RETRY_SECS: i64 = 5;
/// How long between retries for a startup failure that is *not* `Fault::Network`
/// -- an explicit refusal, or no credential to be silent with. Left slower than
/// [`STARTUP_RETRY_SECS`] on purpose: none of those resolve themselves by being
/// asked again sooner, and a denied credential retried three times in quick
/// succession is the wrong shape to present to an IdP.
const STARTUP_RETRY_BOUNDED_SECS: i64 = 20;
/// How many times a non-network startup failure retries before it stops. See
/// [`STARTUP_RETRY_BOUNDED_SECS`].
const STARTUP_RETRIES: u8 = 3;
/// When a device grant's deadline starts being worth saying out loud -- for the
/// status surface's clock and for the notification alike, so the two cannot
/// disagree about what "soon" is.
///
/// Seven days, matching the operator-facing default the broker ships with. The
/// person who has to act *is* at the keyboard, since clearing it means signing
/// in through the browser here, and a week covers a holiday weekend without
/// turning a once-a-month chore into permanent furniture. The fleet-wide early
/// warning is the operator's, not this one's.
pub const GRANT_DUE_SOON_SECS: i64 = 7 * 86_400;
/// How long transport has to have been failing before the surface says so.
///
/// A duration, not a distance: the schedule re-arms from the ticket midpoint, so
/// "the next attempt is far away" would go quiet exactly as the machine
/// approaches the lapse. Long enough that a closed lid or a VPN reconnect passes
/// unmentioned, short enough that a real outage is described while the ticket
/// still has hours on it.
const FLAKY_QUIET_SECS: i64 = 15 * 60;
/// How much of a ticket's life has to be gone before "it will stop" is news.
///
/// A fraction rather than a duration, because ticket lifetimes are the
/// deployment's to choose and a fixed hour is most of a short one and a rounding
/// error on a long one. `WillStop` says a certainty about the end of *this*
/// ticket; on a ten-hour ticket this puts it two hours out, which is inside the
/// working session it interrupts.
const LATE_ELAPSED: f32 = 0.8;
/// How long after a failure to run the probe again, and the ceiling the interval
/// doubles to. See [`Probe`].
///
/// Nothing else ever looks outside a `Fault::Network` retry: the re-injection
/// schedule runs only while a ticket is held, and a startup failure that is not
/// `Fault::Network` stops after three, so without this a machine whose broker
/// has come back keeps reporting "can't reach", and one that started before its
/// network never finds its broker. Neither leg needs a credential, which is also
/// what makes the probe the one thing a machine with nothing to be silent with
/// can usefully do.
const PROBE_FIRST_SECS: i64 = 30;
const PROBE_MAX_SECS: i64 = 10 * 60;
/// How often to look for a TGT absent before its End Time.
///
/// The check is an LSA round trip and the condition it finds persists until
/// something clears it, so running it at the tick's 1 Hz would buy nothing but
/// wake-ups.
const LOSS_POLL_SECS: i64 = 30;
/// The delay before the second recovery attempt of a [`TgtLoss`] episode, and
/// the ceiling it doubles to. The first attempt is immediate; the ceiling
/// repeats rather than ending the sequence.
const LOSS_FIRST_SECS: i64 = 60;
const LOSS_MAX_SECS: i64 = 3_600;

// ---- the UI seam -----------------------------------------------------------

/// What a token from the platform's own token store came to -- WAM on
/// Windows, and whatever holds the account on the next platform.
pub enum NativeToken {
    /// A bearer access token for the broker API, issued by the OS.
    Token(crate::secret::Secret),
    /// The platform cannot serve this request. The caller falls back to the browser.
    ///
    /// There is no third answer for a dismissed platform dialog: asking the OS
    /// is silent or it is nothing, because the dialog worth showing is a sign-in
    /// and the OS has none to show that this agent is allowed to want.
    Unavailable,
}

/// How loud a notification is. Keyed on the condition it announces, never on
/// which code path emitted it, so a recovery and a failure cannot end up wearing
/// the same icon.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Severity {
    /// Something worked. No icon.
    Info,
    /// A deadline the user can still act before.
    Warning,
    /// It has already stopped, or an operation failed.
    Error,
}

/// What an unsolicited interruption may do now: a notification the machine
/// raised, or a status surface that nobody opened with a click.
///
/// Silent mode decides it once policy, the user or an accepted broker document
/// resolves it. Before that, the built-in `false` applies only after the current
/// discovery attempt ends without a document. Until then nobody knows whether the
/// deployment wants silence, so a notification waits (`client/DESIGN.md`
/// § Notifications).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InterruptionGate {
    /// Unresolved, and the current discovery attempt has not ended. The core
    /// holds the newest notification; the host drops a surface request.
    Defer,
    Allow,
    Suppress,
}

/// One notification: title, body and severity. The body can hold `{action}`,
/// which [`deliver`] fills.
type Notice = (String, String, Severity);

/// What one of the hosted operations came to, in the vocabulary its dialog
/// renders.
///
/// The core decides the sentence, because the sentence is translated copy; the
/// host decides *where* it lands, because only the host knows whether a surface
/// is on screen to carry it (`client/DESIGN.md` § Notifications, gate 2).
pub enum Outcome {
    /// The user said no at the elevation prompt. A decision rather than a fault:
    /// it returns the dialog to its question, unchanged and silent.
    Declined,
    /// `detail` is a second, independent fact -- the only operation with one is
    /// giving up a grant, where the key here and the record at the broker can
    /// disagree.
    Done {
        message: String,
        detail: Option<String>,
    },
    Failed {
        message: String,
    },
}

/// The half of the agent that needs a UI, implemented once per platform and
/// installed by [`init`].
///
/// A runtime seam rather than a `#[cfg]` one -- unlike [`crate::sys`] -- because
/// the implementation lives *above* this crate, in the agent binary, and the core
/// cannot name a type it does not depend on. Every method is called with the
/// agent state unborrowed, so an implementation may call back in.
pub trait Host: Sync {
    /// Arrange for [`drain`] to run on the UI thread. Called from worker threads;
    /// must not block and must not run the drain itself.
    fn wake(&self);
    /// A passive notification: a tray balloon, a Notification Center banner.
    ///
    /// The core has logged it and passed it through the [`InterruptionGate`].
    /// Gate 2 lives here: each platform judges for itself whether a surface is
    /// already on screen saying this.
    fn notify(&self, title: &str, body: &str, severity: Severity);
    /// One of the six hosted operations finished. The host renders it where it
    /// belongs -- in its modal while one is up, as a notification once it is not.
    fn finished(&self, action: Action, outcome: Outcome);
    /// The elevation prompt has been answered and the privileged step is
    /// running. The only moment between "the prompt is up" and "the work is
    /// running" that anything can observe -- the secure desktop reports nothing
    /// -- and the one a four-phase dialog needs to leave its *waiting* phase.
    fn elevating(&self, action: Action);
    /// The label of the offer this surface is leading with, for the two
    /// notifications that name it. The priority that picks it is the surface's:
    /// `actions` is deliberately flat and each platform arranges it differently.
    fn primary_action_label(&self) -> String;
    /// Hand a file or folder to the desktop shell.
    fn open_path(&self, path: &str);
    /// Ask the platform's token store for a broker token, so sign-in and
    /// every re-injection after it need no browser.
    ///
    /// Silent only. An app cannot sign an OS account out -- Microsoft reserves
    /// that to the user, and `RemoveAsync` drops app-only accounts, never
    /// OS-wide ones -- so this agent never demands a fresh authentication here.
    /// Doing so would retire no session and spend the silent renewal that is the
    /// whole point of asking the OS at all.
    fn native_token(&self, oidc: &OidcConfig) -> NativeToken;
}

static HOST: OnceLock<&'static dyn Host> = OnceLock::new();

fn host() -> &'static dyn Host {
    *HOST.get().expect("agent::init installed the host")
}

// ---- state -----------------------------------------------------------------

/// What the agent is doing. Internal machinery: what a *surface* says is
/// [`crate::describe`]'s, computed from facts rather than from this.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    SignedOut,
    SigningIn,
    Connected,
    /// The ticket reached End Time without a renewal landing. A distinct phase, not
    /// a clock comparison against `Connected`, so the expiry is announced exactly
    /// once instead of on every timer tick.
    Expired,
    Error,
}

/// The identity of one broker-document request. The URL is the effective
/// [`Settings::broker_url`] at issue time, not the `base_url` returned by the
/// broker.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DiscoveryStamp {
    requested_broker_url: String,
    generation: u64,
}

/// One credential-free request for the broker document: `/config` at the
/// effective broker URL, or, with no broker URL, the `_kerbridge._tcp` SRV
/// lookup that looks for one. An SRV answer starts the `/config` probe on the
/// next tick.
enum Probe {
    Srv { generation: u64 },
    Config(DiscoveryStamp),
}

/// Every broker-owned value published by one `/config` document.
#[derive(Clone, Default, PartialEq, Eq)]
struct BrokerSnapshot {
    kerberos: KerberosConfig,
    device_grant: DeviceGrantConfig,
    defaults: Defaults,
    help_url: Option<String>,
    idp_name: String,
    source: String,
}

struct BusyOperation {
    stamp: DiscoveryStamp,
    action: Action,
}

/// Silent recovery from a TGT seen absent before its End Time.
///
/// Absence is an observation, not a diagnosis. An access that falls back to
/// NTLM evicts the TGT (research spike `windows-tgt-followup-entra-joined`,
/// lines 787-792), but the TGT has also gone with access intact on an
/// Entra-joined Windows 11 25H2 workstation. So the response is a silent
/// re-injection. It is never a browser and never a Workstation restart.
///
/// An episode opens at the first absence. A landed re-injection pauses it but
/// does not end it, so a replacement that disappears too backs off further.
/// Only a replacement that survives to its scheduled re-injection, a successful
/// repair, or a session reset ends it.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
struct TgtLoss {
    /// Absences seen and recovery attempts failed in this episode. 0 = none open.
    streak: u32,
    /// Seen absent, and no exchange has landed since.
    absent: bool,
    /// When the next recovery attempt is due, while absent.
    retry_at: Option<i64>,
    /// A hard refusal, or nothing to be silent with: no recovery attempt until
    /// an exchange lands. The midpoint re-injection continues.
    suspended: bool,
}

struct Agent {
    settings: Settings,
    /// The newest discovery-document request or invalidation. Only a result with
    /// both this generation and this exact effective requested broker URL may publish.
    discovery_generation: u64,
    discovery_target: Option<String>,
    /// A discovery attempt at the current target has ended. Without an accepted
    /// document, the built-in `silent = false` then opens the
    /// [`InterruptionGate`].
    discovery_ended: bool,
    /// The newest notification that [`InterruptionGate::Defer`] holds.
    deferred: Option<Notice>,
    /// Realm/KDC/services as last discovered, falling back to the config cache
    /// so the agent can name the realm before its first successful discovery.
    kerberos: KerberosConfig,
    enroll_state: enroll::State,
    phase: Phase,
    principal: String,
    start: i64,
    end: i64,
    renew_till: i64,
    /// When to silently re-inject.
    refresh_at: Option<i64>,
    message: String,
    /// What class of failure [`Self::message`] is about, or `None` when it is a
    /// note rather than a fault.
    fault: Option<Fault>,
    /// The first transport failure with nothing landed after it, in Unix
    /// seconds. What makes `Flaky` a duration.
    first_failure_at: Option<i64>,
    /// When to run the [`Probe`] again, and how long to wait after that. Armed
    /// by a failed probe or a transport failure; an accepted document or a
    /// retarget resets it. See [`PROBE_FIRST_SECS`].
    probe_at: Option<i64>,
    probe_backoff: i64,
    /// The generation of the probe that runs. At most one runs at a time. A
    /// retarget forgets it, so its result is inert.
    probe_in_flight: Option<u64>,
    /// Backoff for [`Self::refresh_at`] while a network failure stands: doubles
    /// on each further failed attempt, clamped under the ordinary midpoint so a
    /// retry never lands later than today's schedule already would have tried.
    /// 0 outside a network failure streak.
    refresh_backoff: i64,
    /// What is running, in the surface's vocabulary. At most one of these holds
    /// the busy slot; cloud sign-out and revocation use their own workers.
    in_flight: Vec<Action>,
    busy_operation: Option<BusyOperation>,
    cloud_sign_out: Option<DiscoveryStamp>,
    grant_cleanup_generation: u64,
    grant_cleanup: Option<u64>,
    /// A grant was created and nothing has happened since.
    just_authorized: bool,
    /// The exchange that grant itself started, which must not be what clears
    /// [`Self::just_authorized`]: it is the second half of the authorization the
    /// user just performed, not news arriving after it.
    granted_exchange_pending: bool,
    /// A silent renewal has failed, so the ticket will run out unless the user
    /// signs in again. Drives the amber state before End Time actually arrives.
    silent_failed: bool,
    /// When to retry the autostart sign-in, or a silent attempt that failed on
    /// transport with no ticket held where one is expected, and how many
    /// non-network goes are left. Nothing pending is also what a user-initiated
    /// sign-in or a sign-out leaves behind: a retry that fires after either
    /// would be the agent acting on its own against what the user just did.
    startup_retry_at: Option<i64>,
    startup_retries: u8,
    /// Backoff for [`Self::startup_retry_at`] through a streak of
    /// `Fault::Network` failures: doubles on each further failure and never runs
    /// out, unlike [`Self::startup_retries`]. 0 outside a streak; a landed
    /// exchange, a failure that is not a transport failure, or a session reset
    /// ends it.
    startup_backoff: i64,
    /// The autostart sign-in declined only because no broker URL was known. An
    /// SRV answer consumes it to start that sign-in late. A session reset or a
    /// user sign-in clears it, so a late answer cannot override either.
    autostart_awaits_broker: bool,
    /// The "your session is about to lapse" balloon has been shown for this ticket.
    escalated: bool,
    /// What this deployment allows in the way of device grants, as last
    /// discovered. Memory only and off until a discovery says otherwise, so an
    /// agent that has not reached its broker yet offers nothing -- and an operator
    /// turning the feature off is obeyed on the next discovery rather than at
    /// the next reinstall. The grant itself lives in [`Settings`], because it is
    /// the one part that has to survive a restart.
    device_grant: DeviceGrantConfig,
    /// Where the agent menu's *Help* goes, as last discovered. `None` until a
    /// discovery lands, and on every broker that publishes no page -- the
    /// surface has its own default and this only ever replaces it.
    help_url: Option<String>,
    /// What to call the IdP, as last discovered. Empty before the first
    /// discovery, which no label shows: the two that name the IdP appear only
    /// after a sign-in, and a sign-in needs the discovery first.
    idp_name: String,
    /// Which source this machine authenticates against, as last discovered.
    /// `base_url` is never persisted, so this is known only per run: empty until
    /// a discovery lands, and on a broker that names no source.
    source: String,
    loss: TgtLoss,
    /// When the TGT is next looked for; 0 = as soon as the conditions hold.
    loss_check_at: i64,
    /// When the grant deadline was last announced. The one notification with
    /// slack, so the one that waits for a human -- and then stays quiet for a day
    /// whether or not they acted.
    grant_notified_at: Option<i64>,
}

thread_local! {
    static AGENT: RefCell<Option<Agent>> = const { RefCell::new(None) };
}

/// Shared with worker threads -- the only state that crosses a thread boundary.
static BUSY: AtomicBool = AtomicBool::new(false);
static CANCEL: AtomicBool = AtomicBool::new(false);
/// True while local key deletion and old-broker revocation are unfinished.
static GRANT_CLEANUP: AtomicBool = AtomicBool::new(false);

/// The OIDC refresh token. **Memory only, never persisted, never logged.** It is
/// what makes re-injection silent; losing it (quit, logoff, reboot) costs one
/// click, which is the trade the design chose over writing a credential to disk.
static REFRESH_TOKEN: Mutex<Option<crate::secret::Secret>> = Mutex::new(None);

/// Whether a browser sign-in is waiting on its loopback redirect. [`CANCEL`] is
/// read there and nowhere else, so this is the whole of when cancelling does
/// anything -- a sign-in worker is also in discovery, in the platform's blocking
/// credential dialog, and in the ticket exchange, and a Cancel drawn over those
/// is a control that does nothing when pressed.
static BROWSER_LEG: AtomicBool = AtomicBool::new(false);

fn with<T>(f: impl FnOnce(&mut Agent) -> T) -> T {
    AGENT.with(|a| f(a.borrow_mut().as_mut().expect("agent initialized in main")))
}

impl Agent {
    fn new(settings: Settings) -> Self {
        let kerberos = settings.cache().to_kerberos();
        let enroll_state = enroll::state(&kerberos);
        let discovery_target = settings.broker_url().map(str::to_owned);
        Self {
            settings,
            discovery_generation: 0,
            discovery_target,
            discovery_ended: false,
            deferred: None,
            kerberos,
            enroll_state,
            phase: Phase::SignedOut,
            principal: String::new(),
            start: 0,
            end: 0,
            renew_till: 0,
            refresh_at: None,
            message: String::new(),
            fault: None,
            first_failure_at: None,
            probe_at: None,
            probe_backoff: 0,
            probe_in_flight: None,
            refresh_backoff: 0,
            in_flight: Vec::new(),
            busy_operation: None,
            cloud_sign_out: None,
            grant_cleanup_generation: 0,
            grant_cleanup: None,
            just_authorized: false,
            granted_exchange_pending: false,
            silent_failed: false,
            startup_retry_at: None,
            startup_retries: 0,
            startup_backoff: 0,
            autostart_awaits_broker: false,
            escalated: false,
            device_grant: DeviceGrantConfig::default(),
            help_url: None,
            idp_name: String::new(),
            source: String::new(),
            loss: TgtLoss::default(),
            loss_check_at: 0,
            grant_notified_at: None,
        }
    }

    /// Advance the request identity and bind it to the effective requested broker
    /// URL. Calling this without launching a request invalidates every outstanding one.
    fn advance_discovery(&mut self) -> Option<DiscoveryStamp> {
        self.discovery_generation = self
            .discovery_generation
            .checked_add(1)
            .expect("broker discovery generation exhausted");
        self.discovery_target = self.settings.broker_url().map(str::to_owned);
        self.discovery_target.clone().map(|requested_broker_url| DiscoveryStamp {
            requested_broker_url,
            generation: self.discovery_generation,
        })
    }

    fn interruption_gate(&self) -> InterruptionGate {
        match self.settings.resolved_silent() {
            Some(true) => InterruptionGate::Suppress,
            Some(false) => InterruptionGate::Allow,
            None if self.discovery_ended => InterruptionGate::Allow,
            None => InterruptionGate::Defer,
        }
    }

    /// Pass one notification through the gate. Returns it when it is to be
    /// delivered now. It replaces a deferred one, which it is newer than.
    fn admit(&mut self, notice: Notice) -> Option<Notice> {
        self.deferred = None;
        match self.interruption_gate() {
            InterruptionGate::Allow => Some(notice),
            InterruptionGate::Suppress => None,
            InterruptionGate::Defer => {
                self.deferred = Some(notice);
                None
            }
        }
    }

    /// The deferred notification once the gate settles: returned to deliver on
    /// `Allow`, dropped on `Suppress`.
    fn settle_deferred(&mut self) -> Option<Notice> {
        match self.interruption_gate() {
            InterruptionGate::Defer => None,
            InterruptionGate::Allow => self.deferred.take(),
            InterruptionGate::Suppress => {
                if self.deferred.take().is_some() {
                    log::info("silent mode is on; the deferred notification is dropped");
                }
                None
            }
        }
    }

    fn discovery_is_current(&self, stamp: &DiscoveryStamp) -> bool {
        stamp.generation == self.discovery_generation
            && self.discovery_target.as_deref() == Some(stamp.requested_broker_url.as_str())
            && self.settings.broker_url() == Some(stamp.requested_broker_url.as_str())
    }

    /// Replace one accepted broker payload in memory. Validation is first, so a
    /// rejected payload does not read enrollment state, clear a fault, or mutate
    /// the persisted cache image.
    fn replace_broker_snapshot(
        &mut self,
        stamp: &DiscoveryStamp,
        snapshot: BrokerSnapshot,
    ) -> Option<bool> {
        if !self.discovery_is_current(stamp) {
            return None;
        }

        if self.phase != Phase::SignedOut
            && !self.kerberos.realm.is_empty()
            && self.kerberos.realm != snapshot.kerberos.realm
        {
            let old_realm = self.kerberos.realm.clone();
            log::warn(&format!(
                "broker realm changed from {old_realm} to {}; ending the old session",
                snapshot.kerberos.realm
            ));
            #[cfg(not(test))]
            purge_realm(&old_realm);
            self.expect(false);
            self.reset_session();
        }
        let enroll_state = enroll::state(&snapshot.kerberos);
        let cache_changed = self.settings.set_cache(&snapshot.kerberos);
        self.settings.set_defaults(snapshot.defaults);
        self.kerberos = snapshot.kerberos;
        self.enroll_state = enroll_state;
        self.device_grant = snapshot.device_grant;
        self.help_url = snapshot.help_url;
        self.idp_name = snapshot.idp_name;
        self.source = snapshot.source;

        // The discovery document landed. Clear a transport fault only after the
        // complete replacement, so rejection cannot make an old failure vanish.
        if self.fault == Some(Fault::Network) {
            self.record(None, String::new());
        }
        self.reset_probe();
        Some(cache_changed)
    }

    /// Start one probe at the current target. `None` while one runs, or while
    /// cloud sign-out owns the discovery generation.
    fn begin_probe(&mut self, now: i64) -> Option<Probe> {
        if self.probe_in_flight.is_some() || self.cloud_sign_out.is_some() {
            return None;
        }
        let probe = match self.advance_discovery() {
            Some(stamp) => Probe::Config(stamp),
            None => Probe::Srv { generation: self.discovery_generation },
        };
        self.probe_in_flight = Some(self.discovery_generation);
        self.arm_probe(now);
        Some(probe)
    }

    /// The probe of `generation` finished. False when it is not the one that
    /// runs: a retarget forgot it, and its result must change nothing.
    fn end_probe(&mut self, generation: u64, now: i64) -> bool {
        if self.probe_in_flight != Some(generation) {
            return false;
        }
        self.probe_in_flight = None;
        // From the end of the attempt, so a slow failure cannot shorten the wait.
        if self.probe_at.is_some() {
            self.probe_at = Some(now + self.probe_backoff);
        }
        true
    }

    /// Arm the probe at its first step, unless it is already armed. Armed once
    /// and then left to its own backoff: re-arming on every failure would hold
    /// the interval at its floor.
    fn arm_probe(&mut self, now: i64) {
        if self.probe_at.is_none() {
            self.probe_backoff = PROBE_FIRST_SECS;
            self.probe_at = Some(now + PROBE_FIRST_SECS);
        }
    }

    fn reset_probe(&mut self) {
        self.probe_at = None;
        self.probe_backoff = 0;
    }

    /// Probe a new target at the next tick, from the first step. The running
    /// probe is forgotten, so its result is inert.
    fn restart_probe(&mut self, now: i64) {
        self.probe_in_flight = None;
        self.probe_backoff = 0;
        self.probe_at = Some(now);
    }

    /// Clear broker-owned state after a requested broker URL change. User and policy values,
    /// including a once-applied autostart choice, stay in [`Settings`].
    fn clear_broker_snapshot(&mut self) {
        self.discovery_ended = false;
        self.kerberos = KerberosConfig::default();
        self.enroll_state = enroll::State::NotEnrolled;
        self.device_grant = DeviceGrantConfig::default();
        self.help_url = None;
        self.idp_name.clear();
        self.source.clear();
        self.settings.clear_defaults();
        self.settings.clear_broker_state();
    }

    fn invalidate_broker_snapshot(&mut self) {
        let _ = self.advance_discovery();
        self.clear_broker_snapshot();
    }

    /// Adopt a live TGT after startup. Returns true when the ticket belongs to
    /// somebody other than the stored device grant and must be replaced.
    fn adopt_existing_ticket(&mut self) -> bool {
        if self.phase != Phase::SignedOut || self.kerberos.realm.is_empty() {
            return false;
        }
        let Ok(Some(ticket)) = tickets::realm_tgt(&self.kerberos.realm) else {
            return false;
        };
        if ticket.end <= time::now() {
            return false;
        }
        self.adopt_cached_ticket(ticket)
    }

    fn adopt_cached_ticket(&mut self, ticket: tickets::CachedTgt) -> bool {
        let pinned = self.settings.grant_for().is_some();
        if !is_the_grants(self.settings.grant(), pinned, &ticket.principal) {
            self.startup_retries = STARTUP_RETRIES;
            log::warn(&format!(
                "the {} ticket in this session belongs to {}, not to this machine's device grant; \
                 starting re-injection instead of adopting it",
                self.kerberos.realm, ticket.principal
            ));
            return true;
        }

        self.principal = ticket.principal;
        self.start = ticket.start;
        self.end = ticket.end;
        self.renew_till = ticket.renew_till;
        self.phase = Phase::Connected;
        self.refresh_at = Some(midpoint(ticket.start.max(time::now()), ticket.end));
        self.expect(true);
        log::info(&format!(
            "adopted the existing {} ticket for {} (ends {})",
            self.kerberos.realm,
            self.principal,
            time::local_stamp(ticket.end)
        ));
        false
    }

    /// Forget everything about the current session, including the schedule.
    fn reset_session(&mut self) {
        self.phase = Phase::SignedOut;
        self.startup_retry_at = None;
        self.startup_retries = 0;
        self.startup_backoff = 0;
        self.autostart_awaits_broker = false;
        self.principal.clear();
        self.start = 0;
        self.end = 0;
        self.renew_till = 0;
        self.refresh_at = None;
        self.silent_failed = false;
        self.escalated = false;
        self.message.clear();
        self.fault = None;
        self.first_failure_at = None;
        // The episode was about a ticket this session no longer has.
        self.loss = TgtLoss::default();
        self.loss_check_at = 0;
        self.deferred = None;
    }

    /// What this machine would be working as right now: the realm, and the
    /// account it gets tickets for when that is not whoever signs in. `None` before any
    /// realm is known, because there is nothing to expect yet.
    fn scope(&self) -> Option<String> {
        (!self.kerberos.realm.is_empty()).then(|| {
            format!("{}|{}", self.kerberos.realm, self.settings.grant_for().unwrap_or_default())
        })
    }

    /// **H** -- this machine is supposed to be working here.
    ///
    /// A comparison rather than a flag, so the two things that void the
    /// expectation cost no event: retargeting the broker changes the realm, and
    /// a machine-wide `GrantFor` changed under the agent changes the account.
    fn expected(&self) -> bool {
        self.scope().is_some_and(|s| self.settings.expected_working_as() == Some(s.as_str()))
    }

    /// Remember, or forget, that expectation.
    fn expect(&mut self, on: bool) {
        let scope = if on { self.scope() } else { None };
        // Only when it is news: `Event::SignedIn` fires on every landed
        // exchange, silent renewals included, and an unconditional write would
        // rewrite `config.toml` every few hours.
        if self.settings.set_expected_working_as(scope.as_deref())
            && let Err(e) = self.settings.save()
        {
            log::warn(&format!("could not record what this device works as: {e:#}"));
        }
    }

    /// True while the injected ticket is still usable, whatever the agent is doing.
    fn holds_live_ticket(&self) -> bool {
        self.holds_live_ticket_at(time::now())
    }

    fn holds_live_ticket_at(&self, now: i64) -> bool {
        matches!(self.phase, Phase::Connected | Phase::SigningIn)
            && self.end > now
            && !self.principal.is_empty()
    }

    /// Record what happened and what class it was; open the flaky window and arm
    /// the probe on the first transport failure with nothing landed after it,
    /// and close the window on anything that is not one.
    ///
    /// The single owner of the flaky window, which is why a landed exchange
    /// clears it through here rather than by hand. The probe runs on until a
    /// document is accepted.
    fn record(&mut self, fault: Option<Fault>, message: String) {
        self.message = message;
        self.fault = fault;
        if fault == Some(Fault::Network) {
            let now = time::now();
            // A new streak starts the probe at its first step, not at the
            // interval an earlier failed probe reached.
            if self.first_failure_at.is_none() {
                self.first_failure_at = Some(now);
                self.probe_at = None;
            }
            self.arm_probe(now);
        } else {
            self.first_failure_at = None;
        }
    }

    /// Say something with nothing wrong behind it. The surface keys its fault
    /// ink and its offer of the log on the fault, never on the message.
    fn note(&mut self, message: &str) {
        self.message = message.to_string();
        self.fault = None;
    }

    /// Mark an operation as running, so the surface disables its control rather
    /// than hiding it.
    fn started(&mut self, action: Action) {
        if !self.in_flight.contains(&action) {
            self.in_flight.push(action);
        }
    }

    fn started_busy(&mut self, stamp: DiscoveryStamp, action: Action) {
        self.started(action);
        self.busy_operation = Some(BusyOperation { stamp, action });
    }

    /// Release only the operation that owns this stamp. A delayed terminal event
    /// cannot release a newer operation that reused the global slot.
    fn finish_busy(&mut self, stamp: &DiscoveryStamp, stale: bool) -> bool {
        if self.busy_operation.as_ref().map(|op| &op.stamp) != Some(stamp) {
            return false;
        }
        let operation = self.busy_operation.take().unwrap();
        self.in_flight.retain(|action| *action != operation.action);
        BUSY.store(false, Ordering::Relaxed);
        if stale && self.phase == Phase::SigningIn {
            self.phase = if self.holds_live_ticket() { Phase::Connected } else { Phase::SignedOut };
        }
        true
    }

    fn finish_cloud_sign_out(&mut self, stamp: &DiscoveryStamp) -> bool {
        if self.cloud_sign_out.as_ref() != Some(stamp) {
            return false;
        }
        self.cloud_sign_out = None;
        self.in_flight.retain(|action| *action != Action::SignOutIdp);
        true
    }

    fn started_grant_cleanup(&mut self) -> u64 {
        self.grant_cleanup_generation = self
            .grant_cleanup_generation
            .checked_add(1)
            .expect("grant cleanup generation exhausted");
        let generation = self.grant_cleanup_generation;
        self.grant_cleanup = Some(generation);
        self.started(Action::GiveUpGrant);
        generation
    }

    fn finish_grant_cleanup(&mut self, generation: u64) -> bool {
        if self.grant_cleanup != Some(generation) {
            return false;
        }
        self.grant_cleanup = None;
        self.in_flight.retain(|action| *action != Action::GiveUpGrant);
        true
    }

    /// The TGT was seen absent. Opens or advances the episode and schedules
    /// its attempt, unless there is nothing to be silent with.
    fn loss_observed(&mut self, now: i64, supply: bool) {
        self.loss.absent = true;
        self.loss.streak += 1;
        log::warn(&format!(
            "the {} TGT is absent {} before its End Time (loss streak {})",
            self.kerberos.realm,
            duration(self.end - now),
            self.loss.streak
        ));
        if !supply {
            self.loss_suspend();
        } else if !self.loss.suspended {
            self.loss.retry_at = Some(now + loss_delay(self.loss.streak));
        }
    }

    /// The TGT is back without an exchange of ours landing.
    fn loss_present(&mut self) {
        self.loss.absent = false;
        self.loss.retry_at = None;
        log::info(&format!(
            "the {} TGT is present again{}",
            self.kerberos.realm,
            if self.loss.suspended { "" } else { "; recovery paused" }
        ));
    }

    /// An exchange landed. Returns true when it replaced an absent TGT.
    fn loss_landed(&mut self) -> bool {
        let recovered = self.loss.absent;
        self.loss.absent = false;
        self.loss.retry_at = None;
        self.loss.suspended = false;
        recovered
    }

    /// An exchange failed while the TGT was absent. Transport, server and local
    /// failures retry on the backoff; a refusal, or nothing to be silent with,
    /// suspends. Only a landed exchange lifts a suspension.
    fn loss_failed(&mut self, fault: Option<Fault>, now: i64) {
        self.loss.streak += 1;
        match fault {
            Some(Fault::Network | Fault::Other) if !self.loss.suspended => {
                self.loss.retry_at = Some(now + loss_delay(self.loss.streak));
            }
            Some(Fault::Network | Fault::Other) => {}
            None | Some(Fault::Refused | Fault::GrantRefused) => self.loss_suspend(),
        }
    }

    fn loss_suspend(&mut self) {
        self.loss.suspended = true;
        self.loss.retry_at = None;
        // Without recovery the ticket runs out: arm the escalation.
        self.silent_failed = true;
        log::warn("TGT recovery attempts suspended until an exchange lands");
    }
}

/// The realm as last discovered. The one piece of discovery a *surface* needs
/// directly: the enrollment confirmation shows the literal `ksetup` plan, and the
/// plan is built from the KDC list rather than from the realm's name.
pub fn kerberos_config() -> KerberosConfig {
    with(|a| a.kerberos.clone())
}

fn host_of(url: &str) -> String {
    url.trim_start_matches("https://").trim_start_matches("http://").trim_end_matches('/').into()
}

/// Purge one known realm without consulting broker-owned state.
fn purge_realm(realm: &str) -> bool {
    if realm.is_empty() {
        return true;
    }
    match tickets::purge_realm(realm) {
        Ok(n) => {
            log::info(&format!("signed out of {realm} ({n} ticket(s) purged)"));
            true
        }
        Err(e) => {
            log::warn(&format!("sign-out purge failed: {e:#}"));
            false
        }
    }
}

/// Invalidate discovery and remove everything tied to the old route. The
/// broker snapshot is cleared separately from ticket, device-grant, and cloud-session
/// teardown so neither can accidentally preserve the other.
fn retarget(a: &mut Agent, old_broker: Option<String>) -> bool {
    let old_realm = a.settings.cache().realm.clone();
    let old_grant = a.settings.grant().cloned();
    if !purge_realm(&old_realm) {
        return false;
    }
    a.invalidate_broker_snapshot();
    a.restart_probe(time::now());
    a.cloud_sign_out = None;
    a.in_flight.retain(|action| *action != Action::SignOutIdp);
    CANCEL.store(true, Ordering::Relaxed);
    *REFRESH_TOKEN.lock().unwrap() = None;
    a.reset_session();

    let saved = match a.settings.save() {
        Ok(()) => true,
        Err(e) => {
            log::warn(&format!("could not clear state from the previous broker: {e:#}"));
            false
        }
    };
    if let Some(grant) = old_grant {
        worker::give_up_captured_grant(a, old_broker, grant, saved, false);
    }
    true
}

// ---- lifecycle -------------------------------------------------------------

/// Build the agent and adopt whatever the machine already offers: the saved
/// settings, the cached realm, the OS's enrollment state, and any live ticket left
/// in the logon session by a previous run.
///
/// The host goes in first: the discovery this ends with runs on a worker thread
/// and will wake it.
pub fn init(h: &'static dyn Host) {
    let _ = HOST.set(h);
    let mut settings = Settings::load();
    // Before anything reads it. A policy value is the one autostart answer that
    // has to hold with no network: `enforce_autostart` runs again after the
    // first `/config`, for the deployment default that only arrives there.
    if settings.enforce_autostart()
        && let Err(e) = settings.save()
    {
        log::warn(&format!("could not record the autostart entry: {e:#}"));
    }
    let mut agent = Agent::new(settings);

    // A ticket can outlive the agent. Adoption reports the existing login
    // session and schedules its next re-injection instead of appearing signed out.
    let reinject = agent.adopt_existing_ticket();

    AGENT.with(|a| *a.borrow_mut() = Some(agent));

    // After the agent is installed, because the worker reads it. Startup's
    // rules are the ones that fit: silent, quiet on failure, and retried a few
    // times to ride out the logon race an unattended machine boots into.
    if reinject {
        worker::start_worker(Trigger::Startup);
    }
    // A worker that holds the slot fetches `/config` itself. Otherwise the probe
    // does, or asks DNS for a broker when nothing names one.
    if !BUSY.load(Ordering::Relaxed) {
        worker::discover_in_background();
    }
}

/// Is the ticket in the cache one this machine's own grant produced?
///
/// True whenever no grant is held, because then there is nothing for a ticket to
/// disagree with and adopting is unconditionally right. With a grant, the only
/// evidence is the principal that grant last obtained: the grant's `kb1|` identity
/// is an issuer and a subject, which no Kerberos name can be compared against.
///
/// A grant that has never run an exchange is the case worth stating. On a **pinned**
/// machine it answers false: the whole point of the pin is that the account this
/// machine works as is nobody who stands at it, so a ticket it did not produce is
/// somebody else's until proven otherwise. Unpinned there is nobody else it could
/// be -- an unpinned grant always works as the account that authorized it -- and
/// answering false there would have every machine that upgrades holding a grant
/// refuse its own live ticket at each boot until one exchange recorded a
/// principal, which offline is a whole session reading "not signed in" over a
/// cache that works.
fn is_the_grants(grant: Option<&Grant>, pinned: bool, principal: &str) -> bool {
    match grant {
        None => true,
        Some(g) if g.principal.is_none() => !pinned,
        Some(g) => g.principal.as_deref() == Some(principal),
    }
}

/// Halfway between now and expiry, pulled a little earlier at random, floored so
/// a short ticket cannot spin and clamped so the attempt always lands *before*
/// End Time -- a re-injection that arrives after expiry is precisely the failure
/// this mechanism exists to prevent.
///
/// The jitter only ever subtracts. That is the whole reason it is safe: moving
/// earlier cannot break the invariant the clamp exists to hold, so this needs no
/// interaction with it. It is applied before the floor, which therefore still
/// means what it says.
///
/// Unjittered the delay is exactly `remaining/2` on every client, so each cycle
/// *preserves* the gap between two machines rather than decaying it: agents that
/// sign in together -- a VDI pool, a shift start, a mass reboot after patching, a
/// fleet retrying the moment the broker comes back -- stay in step indefinitely.
/// Ten percent of a five-hour delay is half an hour of spread, which turns that
/// spike into a trickle without moving any one client's renewal noticeably.
fn midpoint(now: i64, end: i64) -> i64 {
    let half = (end - now) / 2;
    let delay = (half - jitter(half / 10)).max(MIN_REFRESH_DELAY);
    (now + delay).min(end - EXPIRY_GRACE).max(now + 1)
}

/// How long to wait after the previous attempt in a backoff series: twice the
/// last interval, clamped to `[first, max]`.
///
/// Doubling rather than a fixed period because the cases this serves are far
/// apart -- a machine that booted seconds ahead of its network wants to be told
/// quickly, and one whose broker is off for the weekend must not spend two days
/// asking every thirty seconds.
fn next_backoff(held: i64, first: i64, max: i64) -> i64 {
    (held * 2).clamp(first, max)
}

/// The wait before recovery attempt `streak` of a [`TgtLoss`] episode: none for
/// the first, then [`LOSS_FIRST_SECS`] doubling to [`LOSS_MAX_SECS`], less up to
/// a tenth. The jitter subtracts, as in [`midpoint`], so the ceiling holds.
fn loss_delay(streak: u32) -> i64 {
    if streak <= 1 {
        return 0;
    }
    let base = (LOSS_FIRST_SECS << (streak - 2).min(16)).min(LOSS_MAX_SECS);
    base - jitter(base / 10)
}

/// A uniform value in `0..=span` seconds, and 0 for a span that is not positive.
///
/// An RNG failure degrades to the unjittered schedule rather than to an error:
/// this spreads load, it decides nothing about identity, and an agent that refused
/// to schedule a re-injection because the system RNG was unavailable would have
/// turned a cosmetic problem into the lapsed-ticket failure everything here
/// exists to avoid.
fn jitter(span: i64) -> i64 {
    if span <= 0 {
        return 0;
    }
    let mut buf = [0u8; 8];
    if getrandom::fill(&mut buf).is_err() {
        return 0;
    }
    (u64::from_le_bytes(buf) % (span as u64 + 1)) as i64
}

// ---- the timer -------------------------------------------------------------

/// Called once a second by the platform agent. Returns true when the status window
/// should be rebuilt.
///
/// Notifications are collected and fired *after* the agent borrow is released:
/// `Shell_NotifyIcon` re-enters the message machinery, and a balloon raised while
/// the state is still borrowed would be a latent panic.
pub fn tick() -> bool {
    let now = time::now();
    let busy = BUSY.load(Ordering::Relaxed);
    let due = with(|a| {
        tick_at(a, now, busy, &|realm| tickets::realm_tgt(realm).map(|tgt| tgt.is_some()))
    });

    announce(due.notice);
    if let Some(trigger) = due.start {
        if trigger == Trigger::Startup {
            log::info("retrying the silent sign-in");
        }
        worker::start_worker(trigger);
    }
    // After the worker: one that took the slot asks `/config` the same question.
    if due.probe && !BUSY.load(Ordering::Relaxed) {
        worker::discover_in_background();
    }
    due.redraw
}

/// What one [`tick`] decided, for it to carry out once the borrow is released.
#[derive(Default)]
struct Due {
    redraw: bool,
    notice: Option<Notice>,
    probe: bool,
    /// One worker at most: the busy slot takes one, and every schedule that is
    /// due in the same second wants the same exchange.
    start: Option<Trigger>,
}

/// [`tick`] against one reading of the clock and the busy slot. `present` asks
/// the ticket cache whether the realm's TGT is there.
fn tick_at(
    a: &mut Agent,
    now: i64,
    busy: bool,
    present: &dyn Fn(&str) -> anyhow::Result<bool>,
) -> Due {
    let mut due = Due::default();
    if let Some(notice) = grant_deadline_due(a, now) {
        a.grant_notified_at = Some(now);
        due.notice = Some(notice);
    }
    // Above the phase gate, because a broker that went away is worth asking
    // about whether or not this machine holds a ticket. Re-armed before the
    // attempt, so a failure cannot produce a tight loop; skipped while a
    // worker holds the slot, which is already asking that endpoint the same
    // question, and while the previous probe runs.
    if a.probe_at.is_some_and(|t| now >= t) && !busy && a.probe_in_flight.is_none() {
        a.probe_backoff = next_backoff(a.probe_backoff, PROBE_FIRST_SECS, PROBE_MAX_SECS);
        a.probe_at = Some(now + a.probe_backoff);
        due.probe = true;
    }
    // The ticket ran out: with an SMB session open this is the state that
    // drops the redirector into a stuck NTLM fallback, and the whole of what
    // the re-injection schedule exists to prevent.
    if a.phase == Phase::Connected && now >= a.end {
        log::warn(&format!("{} ticket expired at {}", a.kerberos.realm, time::local_stamp(a.end)));
        a.phase = Phase::Expired;
        a.loss.absent = false;
        a.loss.retry_at = None;
        due.redraw = true;
        // With a re-injection still due, its outcome is the announcement.
        if a.refresh_at.is_none() {
            due.notice = Some((
                fill(tr().notify_stopped_title, &[("realm", &a.kerberos.realm)]),
                tr().notify_stopped_body.into(),
                Severity::Error,
            ));
        }
    }
    // A re-injection due before End Time that never ran: after sleep, one tick
    // passes both. It runs silently, and the status shows no access until it
    // lands. Re-armed, not cleared: `start_worker` can decline without a trace,
    // and only the worker's outcome clears it.
    if a.phase == Phase::Expired {
        if a.refresh_at.is_some_and(|t| now >= t) && !busy {
            a.refresh_at = Some(now + MIN_REFRESH_DELAY);
            due.start = Some(Trigger::Renewal);
        }
        return due;
    }
    if a.phase != Phase::Connected {
        if a.startup_retry_at.is_some_and(|t| now >= t) && !busy {
            a.startup_retry_at = None;
            if matches!(a.phase, Phase::SignedOut | Phase::Error) {
                due.start = Some(Trigger::Startup);
            }
        }
        return due;
    }
    // Look for the TGT the agent believes in. A query error is unknown, never
    // an absence. Skipped while a worker holds the busy slot: re-injection
    // purges the realm before it submits, and that window looks exactly like
    // an absence.
    let mut seen = None;
    if now >= a.loss_check_at && !a.kerberos.realm.is_empty() && !busy {
        a.loss_check_at = now + LOSS_POLL_SECS;
        seen = Some(present(&a.kerberos.realm).ok());
        match seen {
            Some(Some(false)) if !a.loss.absent => {
                a.loss_observed(now, status::silent_supply(a, now));
                due.redraw = true;
            }
            Some(Some(true)) if a.loss.absent => {
                a.loss_present();
                due.redraw = true;
            }
            _ => {}
        }
    }
    // A recovery attempt goes ahead only while the TGT is still absent.
    // Re-armed before the attempt, so one that never reports back cannot stall
    // the episode.
    if a.loss.absent && a.loss.retry_at.is_some_and(|t| now >= t) && !busy {
        match seen.unwrap_or_else(|| present(&a.kerberos.realm).ok()) {
            None => a.loss.retry_at = Some(now + LOSS_POLL_SECS),
            Some(true) => {
                a.loss_present();
                due.redraw = true;
            }
            Some(false) => {
                a.loss.retry_at = Some(now + loss_delay(a.loss.streak + 1));
                due.start = Some(Trigger::Renewal);
            }
        }
    }
    if a.refresh_at.is_some_and(|t| now >= t) && !busy {
        // The replacement lasted its whole interval: the episode is over.
        if a.loss.streak > 0 && !a.loss.absent {
            log::info(&format!("the {} TGT is stable again; loss streak reset", a.kerberos.realm));
            a.loss = TgtLoss::default();
        }
        // Re-arm before the attempt so a failure cannot produce a tight loop;
        // a failed silent renewal retries at the next midpoint, and the user
        // gets a notification either way.
        a.refresh_at = Some(midpoint(now, a.end));
        due.start = Some(Trigger::Renewal);
    }
    if !a.escalated && a.silent_failed && a.end - now <= ESCALATE_SECS {
        a.escalated = true;
        due.redraw = true;
        due.notice = Some((
            fill(
                tr().notify_expiring_title,
                &[("realm", &a.kerberos.realm), ("duration", &duration(a.end - now))],
            ),
            tr().notify_expiring_body.into(),
            Severity::Warning,
        ));
    }
    due
}

// ---- notifications ---------------------------------------------------------

/// How long after the last keystroke or click somebody still counts as being at
/// the machine.
const PRESENT_SECS: i64 = 5 * 60;
/// How rarely the grant deadline may be repeated once it has been said.
const GRANT_NOTIFY_INTERVAL: i64 = 86_400;

/// The grant deadline, when it is inside the window, nobody has been told today,
/// and somebody is at the keyboard to be told.
///
/// The only notification with slack, so the only one that waits for a human --
/// a toast at 03:00 into an empty room reaches nobody, and the deadline is days
/// away. It infers nothing about the machine's purpose and it fails safe: an
/// unknown idle time counts as present, so a platform that cannot answer gets a
/// toast on time rather than none.
///
/// Evaluated again on every tick, so it waits for the [`InterruptionGate`]
/// instead of being held by it, and the daily accounting is not spent while the
/// gate defers.
fn grant_deadline_due(a: &Agent, now: i64) -> Option<Notice> {
    if a.interruption_gate() != InterruptionGate::Allow {
        return None;
    }
    let deadline = a.settings.grant()?.sign_in_required_by;
    if deadline <= now || deadline - now > GRANT_DUE_SOON_SECS {
        return None;
    }
    if a.grant_notified_at.is_some_and(|t| now - t < GRANT_NOTIFY_INTERVAL) {
        return None;
    }
    if crate::sys::seconds_since_input().is_some_and(|idle| idle > PRESENT_SECS) {
        return None;
    }
    let left = days(((deadline - now + 86_399) / 86_400).max(1));
    Some((
        fill(tr().notify_grant_due_title, &[("days", &left)]),
        fill(
            tr().notify_grant_due_body,
            &[("realm", &a.kerberos.realm), ("date", &time::local_date_string(deadline))],
        ),
        Severity::Warning,
    ))
}

/// Raise `notice`, or with none, deliver or drop a deferred notification if the
/// [`InterruptionGate`] has settled.
///
/// Only ever called with the agent borrow released, as [`notify`] is.
fn announce(notice: Option<Notice>) {
    match notice {
        Some(notice) => notify(notice),
        None => release_deferred(),
    }
}

/// Raise a notification through the [`InterruptionGate`]. A deferred one that
/// the gate has settled goes first, so a newer one cannot replace it after the
/// gate opens.
///
/// Only ever called with the agent borrow released: the host reads [`status`] to
/// answer, and `Shell_NotifyIcon` re-enters the message machinery.
fn notify(notice: Notice) {
    release_deferred();
    // Logged whatever the gate and the host do with it: the record is the
    // core's, and both gates suppress the interruption rather than the fact.
    log::info(&format!("notify: {} -- {}", notice.0, with_action(&notice.1)));
    if let Some(notice) = with(|a| a.admit(notice)) {
        deliver(notice);
    }
}

fn release_deferred() {
    if let Some(notice) = with(Agent::settle_deferred) {
        log::info(&format!("notify: delivering the deferred \"{}\"", notice.0));
        deliver(notice);
    }
}

/// Hand a notification to the host. `{action}` is filled at delivery, against
/// whatever the surface leads with then.
fn deliver((title, body, severity): Notice) {
    host().notify(&title, &with_action(&body), severity);
}

fn with_action(body: &str) -> String {
    if body.contains("{action}") {
        fill(body, &[("action", &host().primary_action_label())])
    } else {
        body.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FileConfig;
    use crate::describe::Blocker;

    fn test_agent(broker_url: &str) -> Agent {
        Agent::new(Settings::for_test(FileConfig {
            broker_url: Some(broker_url.to_owned()),
            ..FileConfig::default()
        }))
    }

    fn snapshot(realm: &str, source: &str) -> BrokerSnapshot {
        BrokerSnapshot {
            kerberos: KerberosConfig {
                realm: realm.to_owned(),
                kdcs: vec![format!("kdc.{}", realm.to_ascii_lowercase())],
                services: vec![format!("nas.{}", realm.to_ascii_lowercase())],
            },
            device_grant: DeviceGrantConfig { days: 30, audience: format!("kerbridge://{realm}") },
            defaults: Defaults {
                autostart: None,
                windows_sign_in: Some(false),
                ntlm_fallback_recovery: Some(false),
                silent: Some(true),
            },
            help_url: Some(format!("https://help.{}/", realm.to_ascii_lowercase())),
            idp_name: format!("IdP {realm}"),
            source: source.to_owned(),
        }
    }

    fn assert_broker_snapshot(a: &Agent, expected: &BrokerSnapshot) {
        assert!(a.kerberos == expected.kerberos);
        assert!(a.settings.cache().to_kerberos() == expected.kerberos);
        assert!(a.device_grant == expected.device_grant);
        assert_eq!(a.help_url, expected.help_url);
        assert_eq!(a.idp_name, expected.idp_name);
        assert_eq!(a.source, expected.source);
        assert!(a.settings.defaults_ready());
        assert_eq!(a.settings.silent(), expected.defaults.silent.unwrap_or(false));
    }

    #[test]
    fn late_old_target_document_has_no_side_effects_after_retarget() {
        let mut a = test_agent("https://a.example.site");
        let first_a = a.advance_discovery().unwrap();
        let snapshot_a = snapshot("A.SITE", "a");
        assert!(a.replace_broker_snapshot(&first_a, snapshot_a).is_some());

        let delayed_a = a.advance_discovery().unwrap();
        a.settings.set_broker_url("https://b.example.site");
        a.invalidate_broker_snapshot();
        assert!(a.kerberos.realm.is_empty());
        assert!(a.settings.cache().realm.is_empty());
        assert!(!a.device_grant.enabled());
        assert!(a.help_url.is_none());
        assert!(a.idp_name.is_empty());
        assert!(a.source.is_empty());
        assert!(!a.settings.defaults_ready());
        assert_eq!(a.enroll_state, enroll::State::NotEnrolled);

        let request_b = a.advance_discovery().unwrap();
        let snapshot_b = snapshot("B.SITE", "b");
        assert!(a.replace_broker_snapshot(&request_b, snapshot_b.clone()).is_some());
        a.record(Some(Fault::Network), "B is temporarily unreachable".to_owned());
        let probe_at = a.probe_at;
        let enrollment = format!("{:?}", a.enroll_state);
        let generation = a.discovery_generation;
        let target = a.discovery_target.clone();

        assert!(a.replace_broker_snapshot(&delayed_a, snapshot("LATE.SITE", "late")).is_none());
        assert_broker_snapshot(&a, &snapshot_b);
        assert_eq!(format!("{:?}", a.enroll_state), enrollment);
        assert_eq!(a.discovery_generation, generation);
        assert_eq!(a.discovery_target, target);
        assert_eq!(a.fault, Some(Fault::Network));
        assert_eq!(a.message, "B is temporarily unreachable");
        assert_eq!(a.probe_at, probe_at);
    }

    #[test]
    fn only_the_newest_same_target_generation_can_publish() {
        for newest_finishes_first in [false, true] {
            let mut a = test_agent("https://a.example.site");
            let older = a.advance_discovery().unwrap();
            let newer = a.advance_discovery().unwrap();
            assert!(older.generation < newer.generation);
            let current = snapshot("NEW.SITE", "new");

            if newest_finishes_first {
                assert!(a.replace_broker_snapshot(&newer, current.clone()).is_some());
                assert!(a.replace_broker_snapshot(&older, snapshot("OLD.SITE", "old")).is_none());
            } else {
                assert!(a.replace_broker_snapshot(&older, snapshot("OLD.SITE", "old")).is_none());
                assert!(a.replace_broker_snapshot(&newer, current.clone()).is_some());
            }
            assert_broker_snapshot(&a, &current);
        }
    }

    #[test]
    fn accepted_snapshot_replaces_present_values_with_absence() {
        let mut a = test_agent("https://a.example.site");
        let first = a.advance_discovery().unwrap();
        assert!(a.replace_broker_snapshot(&first, snapshot("A.SITE", "a")).is_some());

        let next = a.advance_discovery().unwrap();
        let replacement = BrokerSnapshot {
            kerberos: KerberosConfig { realm: "B.SITE".into(), ..KerberosConfig::default() },
            idp_name: "IdP B".into(),
            ..BrokerSnapshot::default()
        };
        assert!(a.replace_broker_snapshot(&next, replacement.clone()).is_some());

        assert_broker_snapshot(&a, &replacement);
        assert!(a.kerberos.kdcs.is_empty());
        assert!(a.kerberos.services.is_empty());
        assert!(!a.device_grant.enabled());
        assert!(a.help_url.is_none());
        assert!(a.source.is_empty());
        assert!(!a.settings.silent());
    }

    #[test]
    fn changed_realm_cannot_relabel_a_live_session() {
        let mut a = test_agent("https://broker.example.site");
        let first = a.advance_discovery().unwrap();
        assert!(a.replace_broker_snapshot(&first, snapshot("A.SITE", "a")).is_some());
        a.phase = Phase::Connected;
        a.principal = "riku@A.SITE".into();
        a.start = 100;
        a.end = 200;
        a.refresh_at = Some(150);
        a.loss = TgtLoss { streak: 2, absent: true, ..TgtLoss::default() };
        a.expect(true);

        let next = a.advance_discovery().unwrap();
        assert!(a.replace_broker_snapshot(&next, snapshot("B.SITE", "b")).is_some());

        assert_eq!(a.kerberos.realm, "B.SITE");
        assert!(a.phase == Phase::SignedOut);
        assert!(a.principal.is_empty());
        assert_eq!(a.start, 0);
        assert_eq!(a.end, 0);
        assert!(a.refresh_at.is_none());
        assert_eq!(a.loss, TgtLoss::default());
        assert!(!a.expected());
    }

    #[test]
    fn cached_realm_is_available_before_dns() {
        let settings = Settings::for_test(FileConfig {
            cache: crate::config::Cache {
                realm: "EXAMPLE.SITE".into(),
                ..crate::config::Cache::default()
            },
            ..FileConfig::default()
        });
        let mut a = Agent::new(settings);
        assert_eq!(a.kerberos.realm, "EXAMPLE.SITE");

        let now = time::now();
        assert!(!a.adopt_cached_ticket(tickets::CachedTgt {
            principal: "riku@EXAMPLE.SITE".into(),
            start: now - 60,
            end: now + 3_600,
            renew_till: now + 7_200,
        }));

        assert!(a.phase == Phase::Connected);
        assert_eq!(a.principal, "riku@EXAMPLE.SITE");
        assert!(a.refresh_at.is_some());
        assert!(a.expected());
    }

    #[test]
    fn returned_source_path_is_not_the_request_identity() {
        let requested = "https://kerbridge.example.site";
        let mut a = test_agent(requested);
        let stamp = a.advance_discovery().unwrap();
        let mut found = snapshot("EXAMPLE.SITE", "");
        found.source = crate::discovery::source_name("https://kerbridge.example.site/entra");

        assert_eq!(stamp.requested_broker_url, requested);
        assert!(a.replace_broker_snapshot(&stamp, found).is_some());
        assert_eq!(a.discovery_target.as_deref(), Some(requested));
        assert_eq!(a.source, "entra");
    }

    fn grant(principal: Option<&str>) -> Grant {
        Grant {
            grant_id: "1a2b3c4d".into(),
            identity: "kb1|entra|subject".into(),
            principal: principal.map(str::to_owned),
            audience: "kerbridge://EXAMPLE.SITE".into(),
            sign_in_required_by: 1_785_000_000,
        }
    }

    /// The rule startup adoption turns on, and the reason it exists: the third
    /// case is a `--no-grant` run's leftovers, which look exactly like a working
    /// session and are somebody else's.
    #[test]
    fn only_the_grants_own_ticket_may_be_adopted() {
        for pinned in [true, false] {
            assert!(is_the_grants(None, pinned, "riku@EXAMPLE.SITE"), "pinned={pinned}");
        }

        let obtained = grant(Some("svc-builder@EXAMPLE.SITE"));
        assert!(is_the_grants(Some(&obtained), true, "svc-builder@EXAMPLE.SITE"));
        assert!(!is_the_grants(Some(&obtained), true, "riku@EXAMPLE.SITE"));
    }

    /// The backoff reaches its ceiling and stays there, and cannot be talked
    /// below its floor -- which is what would turn the re-probe into a poll.
    #[test]
    fn the_probe_backs_off_to_a_ceiling() {
        let mut held = PROBE_FIRST_SECS;
        let mut seen = vec![held];
        for _ in 0..8 {
            held = next_backoff(held, PROBE_FIRST_SECS, PROBE_MAX_SECS);
            seen.push(held);
        }
        assert_eq!(seen, [30, 60, 120, 240, 480, 600, 600, 600, 600]);
        assert_eq!(
            next_backoff(0, PROBE_FIRST_SECS, PROBE_MAX_SECS),
            PROBE_FIRST_SECS,
            "a lost interval restarts, never spins"
        );
    }

    /// A failed silent renewal backs off from `MIN_REFRESH_DELAY`, not from the
    /// probe's floor -- issue #30: the first retry after a transient failure must
    /// be soon, not half a ticket lifetime away.
    #[test]
    fn the_refresh_backs_off_from_the_floor_a_renewal_can_use() {
        let mut held = MIN_REFRESH_DELAY;
        let mut seen = vec![held];
        for _ in 0..5 {
            held = next_backoff(held, MIN_REFRESH_DELAY, PROBE_MAX_SECS);
            seen.push(held);
        }
        assert_eq!(seen, [60, 120, 240, 480, 600, 600]);
    }

    /// A startup failure keeps the tight first step the logon race wants, but
    /// backs off from there instead of stopping after three -- a Wi-Fi or VPN
    /// that comes up late is not a reason to sit at "not signed in" until
    /// somebody clicks.
    #[test]
    fn the_startup_retry_backs_off_instead_of_giving_up() {
        let mut held = STARTUP_RETRY_SECS;
        let mut seen = vec![held];
        for _ in 0..8 {
            held = next_backoff(held, STARTUP_RETRY_SECS, PROBE_MAX_SECS);
            seen.push(held);
        }
        assert_eq!(seen, [5, 10, 20, 40, 80, 160, 320, 600, 600]);
    }

    /// A grant that has never run an exchange, which is every grant on a machine
    /// that upgraded holding one -- and the two answers are opposite for a reason.
    #[test]
    fn a_grant_that_has_never_run_an_exchange_trusts_the_cache_only_when_unpinned() {
        // Pinned: the account this machine works as is nobody who stands at it,
        // so a ticket it did not produce is the authorizing engineer's.
        assert!(!is_the_grants(Some(&grant(None)), true, "riku@EXAMPLE.SITE"));

        // Unpinned: there is nobody else it could be. Refusing here would have
        // every upgraded machine re-inject at each boot to learn what it already
        // knew, and offline that is a session spent reporting "not signed in"
        // over a cache that works.
        assert!(is_the_grants(Some(&grant(None)), false, "riku@EXAMPLE.SITE"));
    }

    // ---- TGT loss --------------------------------------------------------------

    const T0: i64 = 1_000_000;
    const LIFETIME: i64 = 36_000;
    const REALM: &str = "EXAMPLE.SITE";

    /// A live ticket for `[T0, T0 + LIFETIME)`, its midpoint re-injection armed
    /// and its first TGT check due. `supply` is a device grant; without one the
    /// machine is delegated, which has nothing to be silent with on any platform
    /// whatever the refresh token holds.
    fn holding(supply: bool) -> Agent {
        let mut a = Agent::new(Settings::for_test(FileConfig {
            broker_url: Some("https://kerbridge.example.site".into()),
            grant_for: (!supply).then(|| "svc-builder".into()),
            cache: crate::config::Cache { realm: REALM.into(), ..crate::config::Cache::default() },
            ..FileConfig::default()
        }));
        if supply {
            a.settings.set_grant(Some(Grant {
                sign_in_required_by: T0 + 30 * 86_400,
                ..grant(Some("riku@EXAMPLE.SITE"))
            }));
        }
        a.enroll_state = enroll::State::Enrolled;
        a.phase = Phase::Connected;
        a.principal = "riku@EXAMPLE.SITE".into();
        a.start = T0;
        a.end = T0 + LIFETIME;
        a.renew_till = a.end;
        a.refresh_at = Some(T0 + LIFETIME / 2);
        a.expect(true);
        a
    }

    fn gone(_: &str) -> anyhow::Result<bool> {
        Ok(false)
    }

    fn there(_: &str) -> anyhow::Result<bool> {
        Ok(true)
    }

    fn unreadable(_: &str) -> anyhow::Result<bool> {
        Err(anyhow::anyhow!("LSA said no"))
    }

    fn not_polled(_: &str) -> anyhow::Result<bool> {
        panic!("the ticket cache was read while a worker held the busy slot")
    }

    /// `Trigger::Renewal` is the silent trigger: no browser and no platform
    /// dialog can open from it.
    fn silent_attempt(due: &Due) -> bool {
        due.start == Some(Trigger::Renewal)
    }

    #[test]
    fn the_first_absence_starts_one_silent_attempt_at_once() {
        let mut a = holding(true);
        let now = T0 + 600;

        let due = tick_at(&mut a, now, false, &gone);
        assert!(silent_attempt(&due));
        assert_eq!((a.loss.streak, a.loss.absent, a.loss.suspended), (1, true, false));
        assert_eq!(a.refresh_at, Some(T0 + LIFETIME / 2), "the midpoint schedule stands");
        let st = status::status_at(&a, now);
        assert!(st.blockers.contains(&Blocker::TgtAbsent));
        assert_eq!(
            st.actions.contains(&Action::RestartWorkstation),
            a.settings.ntlm_fallback_recovery(),
            "offered where policy allows it, and never started"
        );

        // The worker holds the slot: no second attempt, and no read of a cache
        // the re-injection is about to purge.
        let due = tick_at(&mut a, now + 1, true, &not_polled);
        assert!(due.start.is_none());
    }

    #[test]
    fn a_query_error_is_unknown_and_starts_nothing() {
        let mut a = holding(true);
        let due = tick_at(&mut a, T0 + 600, false, &unreadable);
        assert!(due.start.is_none());
        assert_eq!(a.loss, TgtLoss::default());
        assert!(!status::status_at(&a, T0 + 600).blockers.contains(&Blocker::TgtAbsent));
    }

    #[test]
    fn a_delayed_attempt_rechecks_the_cache_first() {
        let failed_once = || {
            let mut a = holding(true);
            let now = T0 + 600;
            assert!(silent_attempt(&tick_at(&mut a, now, false, &gone)));
            a.loss_failed(Some(Fault::Network), now + 5);
            let due_at = a.loss.retry_at.expect("a transport failure retries");
            assert!((now + 5 + 54..=now + 5 + 60).contains(&due_at));
            assert!(tick_at(&mut a, due_at - 1, false, &gone).start.is_none());
            (a, due_at)
        };

        // Unknown: the attempt waits for one poll interval rather than guessing.
        let (mut unknown, due_at) = failed_once();
        unknown.loss_check_at = due_at + 1_000;
        assert!(tick_at(&mut unknown, due_at, false, &unreadable).start.is_none());
        assert_eq!(unknown.loss.retry_at, Some(due_at + LOSS_POLL_SECS));
        assert!(unknown.loss.absent);

        // Present again: nothing to do, and nothing further scheduled.
        let (mut back, due_at) = failed_once();
        let due = tick_at(&mut back, due_at, false, &there);
        assert!(due.start.is_none());
        assert!(!back.loss.absent);
        assert_eq!(back.loss.retry_at, None);
        assert_eq!(back.loss.streak, 2, "the streak outlives the pause");

        // Still absent: it goes ahead, with its watchdog re-armed first.
        let (mut a, due_at) = failed_once();
        let due = tick_at(&mut a, due_at, false, &gone);
        assert!(silent_attempt(&due));
        assert!(a.loss.retry_at.is_some_and(|t| t > due_at));
    }

    #[test]
    fn a_replacement_that_disappears_keeps_the_streak_and_backs_off() {
        let mut a = holding(true);
        let mut now = T0 + 600;
        assert!(silent_attempt(&tick_at(&mut a, now, false, &gone)));

        for streak in 2..=9u32 {
            // The attempt landed: paused while the replacement is present.
            assert!(a.loss_landed());
            a.loss_check_at = 0;
            now += 1;
            assert!(tick_at(&mut a, now, false, &there).start.is_none());
            assert!(!a.loss.absent);

            // It vanished too. The streak goes on; the wait grows.
            now += LOSS_POLL_SECS;
            let due = tick_at(&mut a, now, false, &gone);
            assert!(due.start.is_none(), "streak {streak}: waits");
            assert_eq!(a.loss.streak, streak);
            let base = (LOSS_FIRST_SECS << (streak - 2)).min(LOSS_MAX_SECS);
            let wait = a.loss.retry_at.unwrap() - now;
            assert!((base - base / 10..=base).contains(&wait), "streak {streak}: {wait}");

            now = a.loss.retry_at.unwrap();
            assert!(silent_attempt(&tick_at(&mut a, now, false, &gone)), "streak {streak}");
        }
    }

    #[test]
    fn the_recovery_backoff_doubles_to_an_hour_and_stays() {
        assert_eq!(loss_delay(0), 0);
        assert_eq!(loss_delay(1), 0, "the first attempt does not wait");
        let bases = [60, 120, 240, 480, 960, 1_920, 3_600, 3_600, 3_600, 3_600];
        for (i, base) in bases.into_iter().enumerate() {
            let streak = i as u32 + 2;
            for _ in 0..50 {
                let d = loss_delay(streak);
                assert!((base - base / 10..=base).contains(&d), "streak {streak}: {d}");
            }
        }
        assert!((3_240..=3_600).contains(&loss_delay(u32::MAX)), "no overflow past the ceiling");
    }

    #[test]
    fn transient_failures_retry_and_refusals_suspend() {
        for fault in [Fault::Network, Fault::Other] {
            let mut a = holding(true);
            assert!(silent_attempt(&tick_at(&mut a, T0 + 600, false, &gone)));
            a.loss_failed(Some(fault), T0 + 605);
            assert!(!a.loss.suspended, "{fault:?}");
            assert_eq!(a.loss.streak, 2, "{fault:?}");
            assert!(a.loss.retry_at.is_some(), "{fault:?}");
            assert_eq!(a.refresh_at, Some(T0 + LIFETIME / 2), "{fault:?}");
        }
        for fault in [None, Some(Fault::Refused), Some(Fault::GrantRefused)] {
            let mut a = holding(true);
            assert!(silent_attempt(&tick_at(&mut a, T0 + 600, false, &gone)));
            a.loss_failed(fault, T0 + 605);
            assert!(a.loss.suspended, "{fault:?}");
            assert!(a.loss.retry_at.is_none(), "{fault:?}");
            assert!(a.silent_failed, "{fault:?}: the escalation is armed");

            // Suspended: no recovery attempt before the midpoint, and a
            // transient failure of another exchange does not lift it.
            a.loss_failed(Some(Fault::Network), T0 + 606);
            assert!(a.loss.suspended && a.loss.retry_at.is_none(), "{fault:?}");
            for now in (T0 + 607..T0 + LIFETIME / 2).step_by(997) {
                assert!(tick_at(&mut a, now, false, &gone).start.is_none(), "{fault:?} {now}");
            }

            // An explicit exchange that lands lifts it; the streak stays.
            assert!(a.loss_landed());
            assert!(!a.loss.suspended);
            assert_eq!(a.loss.streak, 3);
        }
    }

    #[test]
    fn nothing_to_be_silent_with_suspends_without_an_attempt() {
        let mut a = holding(false);
        let due = tick_at(&mut a, T0 + 600, false, &gone);
        assert!(due.start.is_none());
        assert!(a.loss.absent && a.loss.suspended);
        assert!(a.silent_failed);
        assert!(status::status_at(&a, T0 + 600).blockers.contains(&Blocker::TgtAbsent));
    }

    #[test]
    fn the_loss_episode_ends_only_on_a_reset_condition() {
        // A replacement that lasts to its scheduled re-injection.
        let mut a = holding(true);
        assert!(silent_attempt(&tick_at(&mut a, T0 + 600, false, &gone)));
        assert!(a.loss_landed());
        a.refresh_at = Some(midpoint(T0 + 605, a.end));
        let due_at = a.refresh_at.unwrap();
        assert!(tick_at(&mut a, due_at - 1, false, &there).start.is_none());
        assert_eq!(a.loss.streak, 1, "the landing alone resets nothing");
        assert!(silent_attempt(&tick_at(&mut a, due_at, false, &there)));
        assert_eq!(a.loss, TgtLoss::default());

        // A session reset.
        let mut a = holding(true);
        assert!(silent_attempt(&tick_at(&mut a, T0 + 600, false, &gone)));
        a.reset_session();
        assert_eq!(a.loss, TgtLoss::default());
    }

    /// Field case: the machine slept across End Time with its midpoint
    /// re-injection overdue. The first tick after resume starts it, silently,
    /// and says there is no access until it lands.
    #[test]
    fn a_tick_past_end_time_runs_the_overdue_re_injection() {
        let mut a = holding(true);
        let now = a.end + 4 * 3_600;

        let due = tick_at(&mut a, now, false, &not_polled);
        assert!(silent_attempt(&due));
        assert!(due.notice.is_none(), "the attempt's outcome is the announcement");
        assert!(a.phase == Phase::Expired);
        let st = status::status_at(&a, now);
        assert_eq!(st.condition, crate::describe::Condition::Stopped);
        assert!(st.ticket.is_none());
        assert!(!st.blockers.contains(&Blocker::TgtAbsent));

        // Not again while it runs; the phase stays stopped until it lands.
        assert!(tick_at(&mut a, now + 1, false, &not_polled).start.is_none());
        assert_eq!(a.refresh_at, Some(now + MIN_REFRESH_DELAY));
    }

    /// `start_worker` declines without a trace during grant cleanup, a cloud
    /// sign-out, or with no broker to stamp. The attempt comes round again
    /// until an outcome clears it.
    #[test]
    fn an_overdue_re_injection_that_never_started_comes_round_again() {
        let mut a = holding(true);
        let now = a.end + 60;
        assert!(silent_attempt(&tick_at(&mut a, now, false, &not_polled)));
        let again = now + MIN_REFRESH_DELAY;
        assert!(tick_at(&mut a, again - 1, false, &not_polled).start.is_none());
        assert!(silent_attempt(&tick_at(&mut a, again, false, &not_polled)));
        assert!(a.phase == Phase::Expired);
    }

    #[test]
    fn a_busy_worker_holds_the_overdue_re_injection_after_end_time() {
        let mut a = holding(true);
        let now = a.end + 60;
        assert!(tick_at(&mut a, now, true, &not_polled).start.is_none());
        assert!(a.phase == Phase::Expired);
        assert!(silent_attempt(&tick_at(&mut a, now + 5, false, &not_polled)));
    }

    #[test]
    fn end_time_with_nothing_scheduled_is_announced() {
        let mut a = holding(true);
        a.refresh_at = None;
        let now = a.end;
        let due = tick_at(&mut a, now, false, &not_polled);
        assert!(due.start.is_none());
        assert!(due.notice.is_some());
        assert!(a.phase == Phase::Expired);
    }
}
