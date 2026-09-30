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
use crate::{enroll, log, srv, tickets, time};

use worker::{Event, Trigger};

/// One `agent::` surface, whichever file an item is filed under: a caller has no
/// reason to know which side of the threading seam a command runs on, or whether
/// what it reads is assembled next to the state or beside the verbs.
pub use commands::{
    SettingsChange, SettingsView, apply_settings, autostart_sign_in, cancel_sign_in, drop_ticket,
    give_up_grant_now, notification_authorization_eligible, open_log, open_log_folder, renew_now,
    settings_view, sign_in, sign_out_idp, silent, status_closed,
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
/// How long after a transport failure to ask the broker for `/config` again, and
/// the ceiling the interval doubles to.
///
/// Nothing else ever looks outside a `Fault::Network` retry: the re-injection
/// schedule runs only while a ticket is held, and a startup failure that is not
/// `Fault::Network` stops after three, so without this a machine whose broker
/// has come back keeps reporting "can't reach". `/config` needs no credential,
/// which is also what makes it the one thing a machine with nothing to be silent
/// with can usefully ask.
const PROBE_FIRST_SECS: i64 = 30;
const PROBE_MAX_SECS: i64 = 10 * 60;
/// How often to look for a vanished TGT (the NTLM-fallback signature).
///
/// The check is an LSA round trip and the condition it finds persists until
/// something clears it, so running it at the tick's 1 Hz would buy nothing but
/// wake-ups.
const FALLBACK_POLL_SECS: i64 = 30;

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

/// What a raise-request is about: the subject the surface should open on, never
/// a view for it to render.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Raise {
    Status,
    Repair,
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
    /// **Suppression lives here, not in the core.** The core emits and logs
    /// unconditionally, so being quiet never costs the record, and each platform
    /// judges for itself whether a surface is already on screen saying this.
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
    /// Bring the status surface up *without* taking the foreground, and say
    /// what it is about: a machine whose drives just broke would otherwise get
    /// an unexplained flyout. It must never open a modal -- a machine-initiated
    /// modal is a rung of the escalation ladder the situation has not earned.
    fn raise(&self, target: Raise);
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

/// Where the agent is in an NTLM-fallback episode.
///
/// An episode opens when the injected TGT vanishes *before* its End Time -- the
/// measured signature of an access that fell back to NTLM, which evicts the
/// TGT `(1)→(0)` immediately
/// (research spike `windows-tgt-followup-entra-joined`, lines 787-792)
/// -- and closes only when a ticket exchange lands or the agent restarts.
///
/// That is the whole rate limit: one raised status window per episode.
#[derive(Clone, Copy, PartialEq, Eq)]
enum NtlmFallback {
    /// No episode open.
    Clear,
    /// Detected. Restarting `LanmanWorkstation` drops every SMB session on the
    /// machine, not just the realm's, so the agent never does it on its own --
    /// this state only raises the surface for the user-consented elevated
    /// repair.
    Confirmed,
}

struct Agent {
    settings: Settings,
    /// The newest discovery-document request or invalidation. Only a result with
    /// both this generation and this exact effective requested broker URL may publish.
    discovery_generation: u64,
    discovery_target: Option<String>,
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
    /// When to ask the broker for `/config` again, and how long to wait after
    /// that. Set only while a transport failure stands; see [`PROBE_FIRST_SECS`].
    probe_at: Option<i64>,
    probe_backoff: i64,
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
    /// When to retry the autostart sign-in, and how many non-network goes are
    /// left. Nothing pending is also what a user-initiated sign-in or a sign-out
    /// leaves behind: a retry that fires after either would be the agent acting
    /// on its own against what the user just did.
    startup_retry_at: Option<i64>,
    startup_retries: u8,
    /// Backoff for [`Self::startup_retry_at`] while a `Fault::Network` failure
    /// stands: doubles on each further failure and never runs out, unlike
    /// [`Self::startup_retries`]. 0 outside a network failure streak.
    startup_backoff: i64,
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
    fallback: NtlmFallback,
    /// When the next NTLM-fallback check is due; 0 = as soon as the conditions hold.
    fallback_check_at: i64,
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
            escalated: false,
            device_grant: DeviceGrantConfig::default(),
            help_url: None,
            idp_name: String::new(),
            source: String::new(),
            fallback: NtlmFallback::Clear,
            fallback_check_at: 0,
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
        Some(cache_changed)
    }

    /// Clear broker-owned state after a requested broker URL change. User and policy values,
    /// including a once-applied autostart choice, stay in [`Settings`].
    fn clear_broker_snapshot(&mut self) {
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
        self.probe_at = None;
        // The episode was about a ticket this session no longer has.
        self.fallback = NtlmFallback::Clear;
        self.fallback_check_at = 0;
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
    /// the re-probe on the first transport failure with nothing landed after it,
    /// and close both on anything that is not one.
    ///
    /// The single owner of both clocks, which is why a landed exchange clears
    /// them through here rather than by hand.
    fn record(&mut self, fault: Option<Fault>, message: String) {
        self.message = message;
        self.fault = fault;
        if fault == Some(Fault::Network) {
            self.first_failure_at.get_or_insert_with(time::now);
            // Armed once and then left to its own backoff: this runs on every
            // failure, including the ones the probe itself provokes, and
            // re-arming would hold the interval at its shortest for ever.
            if self.probe_at.is_none() {
                self.probe_backoff = PROBE_FIRST_SECS;
                self.probe_at = Some(time::now() + PROBE_FIRST_SECS);
            }
        } else {
            self.first_failure_at = None;
            self.probe_at = None;
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
    } else {
        // Ticket adoption and sign-out bypass sign-in; fetch the discovery document now.
        worker::discover_in_background();
    }

    // Nothing named a broker, so ask the network whether it knows one. Off the
    // UI thread: a dead resolver would otherwise hold up the status icon itself.
    if with(|a| a.settings.broker_url().is_none()) {
        std::thread::spawn(|| {
            if let Some(url) = srv::discover_broker() {
                worker::post(Event::BrokerDiscovered { url });
            }
        });
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
    let mut redraw = false;
    let mut want_refresh = false;
    let mut want_startup = false;
    let mut want_raise = false;
    let mut want_probe = false;
    let mut pending: Option<(String, String, Severity)> = None;

    with(|a| {
        if let Some(due) = grant_deadline_due(a, now) {
            a.grant_notified_at = Some(now);
            pending = Some(due);
        }
        // Above the phase gate, because a broker that went away is worth asking
        // about whether or not this machine holds a ticket. Re-armed before the
        // attempt, so a failure cannot produce a tight loop; skipped while a
        // worker holds the slot, which is already asking that endpoint the same
        // question.
        if a.probe_at.is_some_and(|t| now >= t) && !BUSY.load(Ordering::Relaxed) {
            a.probe_backoff = next_backoff(a.probe_backoff, PROBE_FIRST_SECS, PROBE_MAX_SECS);
            a.probe_at = Some(now + a.probe_backoff);
            want_probe = true;
        }
        if a.phase != Phase::Connected {
            if a.startup_retry_at.is_some_and(|t| now >= t) && !BUSY.load(Ordering::Relaxed) {
                a.startup_retry_at = None;
                want_startup = a.phase == Phase::SignedOut;
            }
            return;
        }
        // The ticket ran out: with an SMB session open this is the state that
        // drops the redirector into a stuck NTLM fallback, and the whole of what
        // the re-injection schedule exists to prevent.
        if now >= a.end {
            log::warn(&format!(
                "{} ticket expired at {}",
                a.kerberos.realm,
                time::local_stamp(a.end)
            ));
            a.phase = Phase::Expired;
            a.refresh_at = None;
            redraw = true;
            pending = Some((
                fill(tr().notify_stopped_title, &[("realm", &a.kerberos.realm)]),
                tr().notify_stopped_body.into(),
                Severity::Error,
            ));
            return;
        }
        // The NTLM fallback, detected rather than guessed at. An access that
        // fell back evicts the injected TGT immediately, before its End Time
        // (research spike `windows-tgt-followup-entra-joined`, lines 787-792),
        // so a TGT that is simply *gone* while the agent still believes in one is
        // the positive signal the restart has to be gated behind -- through the
        // LSA query the agent already runs, with no SMB knowledge involved.
        //
        // Skipped while a worker holds the busy slot: re-injection purges the
        // realm before it submits, and that window looks exactly like this.
        if a.fallback == NtlmFallback::Clear
            && a.settings.ntlm_fallback_recovery()
            && now >= a.fallback_check_at
            && !a.kerberos.realm.is_empty()
            && !BUSY.load(Ordering::Relaxed)
        {
            a.fallback_check_at = now + FALLBACK_POLL_SECS;
            if matches!(tickets::realm_tgt(&a.kerberos.realm), Ok(None)) {
                log::warn(&format!(
                    "the injected {} ticket is gone {} before its End Time -- treating it as an \
                     NTLM fallback; repairing it requires a LanmanWorkstation restart",
                    a.kerberos.realm,
                    duration(a.end - now)
                ));
                a.fallback = NtlmFallback::Confirmed;
                want_raise = true;
                redraw = true;
            }
        }
        if a.refresh_at.is_some_and(|t| now >= t) && !BUSY.load(Ordering::Relaxed) {
            // Re-arm before the attempt so a failure cannot produce a tight loop;
            // a failed silent renewal retries at the next midpoint, and the user
            // gets a notification either way.
            a.refresh_at = Some(midpoint(now, a.end));
            want_refresh = true;
        }
        if !a.escalated && a.silent_failed && a.end - now <= ESCALATE_SECS {
            a.escalated = true;
            redraw = true;
            pending = Some((
                fill(
                    tr().notify_expiring_title,
                    &[("realm", &a.kerberos.realm), ("duration", &duration(a.end - now))],
                ),
                tr().notify_expiring_body.into(),
                Severity::Warning,
            ));
        }
    });

    if let Some((title, body, severity)) = pending {
        notify(&title, &body, severity);
    }
    // Without focus, same as any other raise: worth interrupting for broken
    // drives, not worth stealing the foreground for.
    if want_raise {
        host().raise(Raise::Repair);
    }
    if want_probe {
        worker::discover_in_background();
    }
    if want_refresh {
        worker::start_worker(Trigger::Renewal);
    }
    if want_startup {
        log::info("autostart: retrying the silent sign-in");
        worker::start_worker(Trigger::Startup);
    }
    redraw
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
fn grant_deadline_due(a: &Agent, now: i64) -> Option<(String, String, Severity)> {
    if a.settings.resolved_silent() != Some(false) {
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

/// Raise a notification, resolving `{action}` against whatever the surface is
/// leading with.
///
/// Only ever called with the agent borrow released: the host reads [`status`] to
/// answer, and `Shell_NotifyIcon` re-enters the message machinery.
fn notify(title: &str, body: &str, severity: Severity) {
    let body = if body.contains("{action}") {
        fill(body, &[("action", &host().primary_action_label())])
    } else {
        body.to_owned()
    };
    // Logged whatever the host does with it: the record is the core's, and gate 2
    // suppresses the interruption rather than the fact.
    log::info(&format!("notify: {title} -- {body}"));
    host().notify(title, &body, severity);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FileConfig;

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
        a.fallback = NtlmFallback::Confirmed;
        a.expect(true);

        let next = a.advance_discovery().unwrap();
        assert!(a.replace_broker_snapshot(&next, snapshot("B.SITE", "b")).is_some());

        assert_eq!(a.kerberos.realm, "B.SITE");
        assert!(a.phase == Phase::SignedOut);
        assert!(a.principal.is_empty());
        assert_eq!(a.start, 0);
        assert_eq!(a.end, 0);
        assert!(a.refresh_at.is_none());
        assert!(a.fallback == NtlmFallback::Clear);
        assert!(!a.expected());
    }

    #[test]
    fn grant_deadline_waits_until_silent_mode_resolves() {
        let mut a = test_agent("https://broker.example.site");
        a.settings.set_grant(Some(Grant {
            grant_id: "1a2b3c4d".into(),
            identity: "kb1|entra|subject".into(),
            principal: None,
            audience: "kerbridge://EXAMPLE.SITE".into(),
            sign_in_required_by: time::now() + 86_400,
        }));

        assert!(!a.settings.defaults_ready());
        assert!(grant_deadline_due(&a, time::now()).is_none());
        assert!(a.grant_notified_at.is_none());
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
}
