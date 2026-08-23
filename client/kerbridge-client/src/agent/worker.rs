//! The agent's worker threads: everything that leaves the UI thread and reports
//! back through [`Event`].
//!
//! The seam is the threading rule stated in the parent module: a worker never
//! touches agent state, it queues an [`Event`] and wakes the UI thread, which
//! applies it in [`drain`]. So what lives here is what blocks -- a browser, two
//! network round trips, UAC -- plus the queue itself and the `apply` that drains
//! it, which is the one place every transition of the state machine is legible.
//!
//! The elevated one-shots below are dead at runtime on macOS, not compiled out:
//! `elevate::run_elevated` refuses there. That is deliberate -- it keeps `#[cfg]`
//! out of the agent entirely (`client/DESIGN.md` @ what each platform does
//! instead). Do not turn it into a `#[cfg]` seam.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::config::Grant;
use crate::describe::{Action, Fault};
use crate::discovery::{BrokerConfig, DeviceGrantConfig, KerberosConfig};
use crate::session::{InjectError, Injected};
use crate::strings::{days, duration, fill, tr};
use crate::{broker, discovery, elevate, enroll, log, oidc, session, time};

use super::failure::{
    Failure, describe_discovery_error, describe_grant_error, describe_inject_error,
    describe_token_error,
};
use super::{
    Agent, BROWSER_LEG, BUSY, CANCEL, FALLBACK_POLL_SECS, MIN_REFRESH_DELAY, NEW_BROWSER_SESSION,
    NativeToken, NtlmFallback, Outcome, PROBE_MAX_SECS, Phase, REFRESH_TOKEN,
    STARTUP_RETRY_BOUNDED_SECS, STARTUP_RETRY_SECS, Severity, host, host_of, is_the_grants,
    midpoint, next_backoff, notify, with,
};

// ---- the queue -------------------------------------------------------------

/// What workers have finished, waiting for the UI thread to apply it. See [`post`].
static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());

/// Set by a worker that has just established this machine's stored grant is
/// dead. Consumed on the UI thread, which is the only place that owns settings.
///
/// One way in: the broker refused it -- expired, clamped, revoked, or the key is
/// gone. Authorizing again is not a second way, because the key is reused and a
/// refused renewal leaves the stored grant working.
/// Left in the file, a dead grant costs a wasted round trip before every browser
/// fallback and -- worse -- leaves the status window announcing a deadline, and Settings
/// offering to extend, something that no longer exists.
static GRANT_STALE: AtomicBool = AtomicBool::new(false);

/// Why a sign-in worker is running. It decides two things: whether a window may
/// open on its own, and what a failure means to the person at the keyboard.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Trigger {
    /// The user clicked Sign in. A window -- the platform's own dialog or the browser -- may open,
    /// and a failure is an answer to something they asked for, so it is shown.
    User,
    /// The re-injection schedule. Silent, and a failure is worth a balloon: the
    /// session lapses without one.
    Renewal,
    /// Autostart at logon. Silent, and a failure is unremarkable -- there may be no
    /// Windows credential to ride, or no network yet -- so it goes to the log and
    /// the agent sits in "not signed in" rather than announcing anything.
    Startup,
    /// A grant was just created, and the machine has no ticket of that grant's
    /// yet. Silent -- it holds a grant, so a
    /// browser here would make nonsense of the button that was pressed -- and
    /// quiet, because the "done" dialog is already on screen and a failure
    /// balloon behind it would contradict it.
    Granted,
}

impl Trigger {
    /// True when nothing may open a window: the attempt succeeds from a credential
    /// already held, or it does not happen.
    fn silent(self) -> bool {
        self != Trigger::User
    }
}

/// What a worker reports back. Queued by [`post`], applied by [`drain`].
pub enum Event {
    SignedIn {
        injected: Injected,
        kerberos: KerberosConfig,
        device_grant: DeviceGrantConfig,
        help_url: Option<String>,
        idp_name: String,
        /// The exchange was proved with this machine's grant, so the principal
        /// that came back is what the grant works as -- the one fact that lets a
        /// later startup tell this machine's ticket from anybody else's.
        via_grant: bool,
    },
    SignInFailed {
        /// What class of failure it was, or `None` where nothing failed and
        /// there was simply nothing to be silent with -- an absence the blocker
        /// list already explains, and not something to dress as a breakage.
        fault: Option<Fault>,
        message: String,
        quiet: bool,
    },
    Cancelled,
    /// An elevated one-shot finished. `outcome` is what the child reported,
    /// already user-facing, plus the two things only this side can know: that
    /// the prompt was declined, and that nothing readable came back.
    Elevated {
        action: Action,
        outcome: Outcome,
        recheck_enrollment: bool,
    },
    /// DNS answered with a broker for a client that had none configured.
    BrokerDiscovered {
        url: String,
    },
    /// What `/config` said, reported the moment it is read rather than only
    /// when a sign-in built on it lands. The realm is the half that used to be
    /// discarded: a broker can answer perfectly and the sign-in after it fail
    /// for reasons that have nothing to do with which realm it serves.
    Discovered {
        kerberos: KerberosConfig,
        device_grant: DeviceGrantConfig,
        help_url: Option<String>,
        idp_name: String,
        source: String,
    },
    /// This machine may now skip the browser sign-in.
    GrantCreated {
        grant: Grant,
    },
    /// It may not, and this is why. Already user-facing, and carrying its class:
    /// a refused authorization is a standing fact about the account, not a
    /// transient the surface may forget once its balloon has gone.
    GrantFailed {
        fault: Option<Fault>,
        message: String,
    },
    /// The cloud logout finished. Outside the busy slot, so it frees nothing but
    /// itself.
    /// `asked` is whether the authority was reached at all. A sign-out that never
    /// left the machine must not be recorded as one that did.
    CloudSignedOut {
        asked: bool,
    },
    /// The revoke worker finished. The key on this device is gone either way;
    /// `revoked` is the second, independent fact -- whether the broker was told.
    /// `saved` is a third: this device could not update its own record.
    GrantGivenUp {
        revoked: bool,
        saved: bool,
    },
    /// The elevation prompt has been answered and the child is running. The one
    /// observable moment between the two phases a dialog can distinguish; the
    /// secure desktop reports nothing.
    ElevationGranted {
        action: Action,
    },
}

/// Queue a worker's result and ask the UI thread for a turn. Called from worker
/// threads only.
pub(super) fn post(ev: Event) {
    EVENTS.lock().unwrap().push(ev);
    host().wake();
}

/// Apply everything workers have finished. Called on the UI thread, from
/// whatever [`Host::wake`] arranged. Returns true when it applied anything, so a
/// wake-up that raced an earlier drain costs no repaint.
pub fn drain() -> bool {
    let events = std::mem::take(&mut *EVENTS.lock().unwrap());
    let applied = !events.is_empty();
    for ev in events {
        apply(ev);
    }
    applied
}

/// One worker's result. As in [`tick`], the balloon is raised only after the
/// agent borrow is released.
fn apply(ev: Event) {
    // Every event but these is a worker reporting in, and that is what releases
    // the busy slot. The broker lookup, the cloud logout and the revoke run
    // outside the slot entirely, so clearing it for them would free a sign-in
    // that is still running.
    //
    // `Discovered` is the one that is not a report at all: `run_sign_in` posts it
    // from the middle of its own run, so freeing the slot here would let a tick
    // start a second sign-in beside the first -- two browsers, two exchanges --
    // and empty `in_flight` while the work it names is still going.
    if !matches!(
        ev,
        Event::BrokerDiscovered { .. }
            | Event::Discovered { .. }
            | Event::CloudSignedOut { .. }
            | Event::GrantGivenUp { .. }
            | Event::ElevationGranted { .. }
    ) {
        BUSY.store(false, Ordering::Relaxed);
        // The slot carries one action at a time and whichever it was is over.
        with(|a| a.in_flight.retain(|act| act.outside_busy_slot()));
    }
    let mut pending: Option<(String, String, Severity)> = None;
    let mut finished: Option<(Action, Outcome)> = None;
    let mut grant_sign_in = false;
    let mut elevating = None;

    // The UI thread owns the settings, so a worker's verdict on the stored grant
    // is applied here -- and before the event itself, so a `GrantCreated` in the
    // same pass writes the new grant over the cleared old one, not the reverse.
    if GRANT_STALE.swap(false, Ordering::Relaxed) {
        with(|a| {
            if a.settings.grant().is_none() {
                return;
            }
            a.settings.set_grant(None);
            if let Err(e) = a.settings.save() {
                log::warn(&format!("could not forget the dead device grant: {e:#}"));
            }
            log::info("this device's grant is no longer usable; a browser sign-in is needed again");
        });
    }

    with(|a| {
        // Before the match, so no arm can be the one that forgets: the browser
        // leg that set this may be followed by a success, a failed injection or
        // a cancel, and the session exists in every one of them.
        if NEW_BROWSER_SESSION.swap(false, Ordering::Relaxed)
            && a.settings.set_browser_session(true)
            && let Err(e) = a.settings.save()
        {
            log::warn(&format!("could not record the browser session: {e:#}"));
        }
        match ev {
            Event::SignedIn { injected, kerberos, device_grant, help_url, idp_name, via_grant } => {
                // Gate 1: a session starting is news, and so is a fault clearing.
                // A midpoint renewal that simply worked moves no condition and says
                // nothing.
                let news = a.phase != Phase::Connected || a.fault.is_some() || a.silent_failed;
                // Recorded before anything else reads it: this is how a later
                // startup knows the ticket in the cache is this machine's own.
                if via_grant && a.settings.set_grant_principal(&injected.principal) {
                    if let Err(e) = a.settings.save() {
                        log::warn(&format!("could not record what the grant works as: {e:#}"));
                    }
                    log::info(&format!("this device's grant works as {}", injected.principal));
                }
                a.principal = injected.principal;
                a.start = injected.start;
                a.end = injected.end;
                a.renew_till = injected.renew_till;
                a.phase = Phase::Connected;
                a.message.clear();
                a.fault = None;
                a.first_failure_at = None;
                a.silent_failed = false;
                a.escalated = false;
                a.refresh_backoff = 0;
                a.refresh_at = Some(midpoint(time::now(), injected.end));
                a.startup_retry_at = None;
                a.startup_retries = 0;
                a.startup_backoff = 0;
                a.device_grant = device_grant;
                a.help_url = help_url;
                a.idp_name = idp_name;
                // Everything except the exchange a fresh grant started itself: that
                // one is the second half of the authorization the user just
                // performed, not news arriving after it.
                if a.granted_exchange_pending {
                    a.granted_exchange_pending = false;
                } else {
                    a.just_authorized = false;
                }
                // A landed exchange is what ends a fallback episode and re-arms
                // detection -- see [`NtlmFallback`]. Nothing else does, so a broker
                // outage cannot turn it into a raise loop.
                a.fallback = NtlmFallback::Clear;
                a.fallback_check_at = time::now() + FALLBACK_POLL_SECS;
                if !kerberos.realm.is_empty() {
                    if a.settings.set_cache(&kerberos)
                        && let Err(e) = a.settings.save()
                    {
                        // Not silent: an unwritten realm means the next start adopts
                        // no ticket and reports no access over a cache that works.
                        log::warn(&format!("could not cache the realm: {e:#}"));
                    }
                    a.kerberos = kerberos;
                    a.enroll_state = enroll::state(&a.kerberos);
                }
                // After the realm is current, because that is half of the scope: a
                // landed exchange is what makes a later lapse read as a fault
                // rather than as a machine that never started.
                a.expect(true);
                if news {
                    let identity = fill(
                        if a.settings.grant_for().is_some() {
                            tr().id_working_as
                        } else {
                            tr().id_signed_in_as
                        },
                        &[("account", &a.principal)],
                    );
                    pending = Some((
                        fill(tr().notify_ready_title, &[("realm", &a.kerberos.realm)]),
                        fill(
                            tr().notify_ready_body,
                            &[
                                ("identity", &identity),
                                ("duration", &duration(a.end - time::now())),
                            ],
                        ),
                        Severity::Info,
                    ));
                }
            }
            Event::SignInFailed { fault, message, quiet } => {
                log::warn(&format!("sign-in failed: {message}"));
                // Recorded on every path, quiet or not: what the surface says is not
                // the same question as whether anyone is interrupted, and a
                // transport failure nobody asked about is exactly what `Flaky` is
                // measured from.
                let fresh_streak = a.first_failure_at.is_none();
                a.record(fault, message);
                // Whether this was a silent renewal or the user clicking Sign in, a
                // failure does not invalidate the ticket already in the cache. Leaving
                // Connected here would cancel the re-injection schedule outright -- the
                // exact path to a ticket lapsing under an open SMB session.
                if a.holds_live_ticket() {
                    // Silent, deliberately: the ticket still works and the condition
                    // has not moved. What this arms is the escalation in [`tick`],
                    // which speaks once the deadline is close enough to be worth an
                    // interruption.
                    a.phase = Phase::Connected;
                    a.silent_failed = true;
                    // A transport failure is retried soon, then progressively less
                    // often -- never later than the midpoint `tick()` already armed
                    // before this attempt. A refused credential is not: hammering
                    // that helps nothing and risks the IdP's own lockout policy, so
                    // it keeps the ordinary midpoint schedule untouched.
                    if fault == Some(Fault::Network) {
                        a.refresh_backoff = if fresh_streak {
                            MIN_REFRESH_DELAY
                        } else {
                            next_backoff(a.refresh_backoff, MIN_REFRESH_DELAY, PROBE_MAX_SECS)
                        };
                        let now = time::now();
                        a.refresh_at = Some((now + a.refresh_backoff).min(midpoint(now, a.end)));
                    }
                } else if quiet {
                    // Nobody asked for this one. Leave the agent exactly as a logon with
                    // no credential should look -- not signed in, one click away -- and
                    // give the network a moment in case that was the problem.
                    a.phase = Phase::SignedOut;
                    if fault == Some(Fault::Network) {
                        // A network fault at logon is the case this exists for --
                        // Wi-Fi or a VPN still coming up -- so it backs off instead
                        // of giving up outright.
                        a.startup_backoff = if fresh_streak {
                            STARTUP_RETRY_SECS
                        } else {
                            next_backoff(a.startup_backoff, STARTUP_RETRY_SECS, PROBE_MAX_SECS)
                        };
                        a.startup_retry_at = Some(time::now() + a.startup_backoff);
                    } else if a.startup_retries > 0 {
                        a.startup_retries -= 1;
                        a.startup_retry_at = Some(time::now() + STARTUP_RETRY_BOUNDED_SECS);
                    }
                } else {
                    // Somebody asked for this, and there is no ticket to show for
                    // it. There is no per-failure headline anywhere in the product,
                    // so the condition this leaves the machine in is the title and
                    // the mechanism sentence is the body -- and the flyout, if it is
                    // up, suppresses the toast under gate 2.
                    a.phase = Phase::Error;
                    pending = Some((tr().cond_stopped.into(), a.message.clone(), Severity::Error));
                }
            }
            Event::Cancelled => {
                // Same reasoning: cancelling a sign-in must not throw away a session
                // that is still working.
                if a.phase == Phase::SigningIn {
                    a.phase =
                        if a.holds_live_ticket() { Phase::Connected } else { Phase::SignedOut };
                }
            }
            Event::Discovered { kerberos, device_grant, help_url, idp_name, source } => {
                // The broker answered, so transport works -- whatever else does not.
                // Cleared here and not only in `SignedIn`: on a machine with nothing
                // to be silent with this is the only thing that ever lands, so a
                // "can't reach" would otherwise stand over a server that answers.
                if a.fault == Some(Fault::Network) {
                    a.record(None, String::new());
                }
                // Only where there is no realm: a landed sign-in has the same answer
                // from the same endpoint and has already stored it, and this can
                // arrive while one is still in flight.
                if !kerberos.realm.is_empty() && a.kerberos.realm.is_empty() {
                    if a.settings.set_cache(&kerberos)
                        && let Err(e) = a.settings.save()
                    {
                        // Not silent: an unwritten realm means the next start adopts
                        // no ticket and reports no access over a cache that works.
                        log::warn(&format!("could not cache the realm: {e:#}"));
                    }
                    a.kerberos = kerberos;
                    a.enroll_state = enroll::state(&a.kerberos);
                }
                // Only ever fills a gap, and no longer asks after the phase: an agent
                // that is signed out needs this answer most, since the button is how
                // it stops needing to be signed in by hand. A sign-in that landed
                // while this was in flight has the same answer from the same
                // endpoint, one round trip fresher, so it is not overwritten.
                if a.device_grant.days == 0 {
                    a.device_grant = device_grant;
                }
                // Unconditional: unlike the grant policy above there is nothing
                // fresher to overwrite, and a tray that has not signed in still has
                // a Help item to point somewhere.
                a.help_url = help_url;
                a.idp_name = idp_name;
                a.source = source;
            }
            Event::BrokerDiscovered { url } => {
                // The user may have typed one into Settings while the lookup ran;
                // theirs wins, and `broker_url` already says so -- but re-checking
                // keeps the log honest about which address is in play.
                if a.settings.broker_url().is_none() {
                    log::info(&format!("using the broker DNS advertises: {url}"));
                    a.settings.set_discovered(url);
                    // Nothing else will ask. The startup `/config` read is gated on
                    // a broker already being configured, which on the zero-touch
                    // path it is not, and `autostart_sign_in` has already run and
                    // refused for the same reason. Without this the machine sits at
                    // "no settings from <host>" with an empty action list -- nothing
                    // to press, nothing scheduled, and `discovered` is not persisted,
                    // so the next start reproduces it exactly.
                    a.startup_retry_at = Some(time::now());
                }
            }
            Event::GrantCreated { grant } => {
                // Rounded up, like the rest of the UI: a 30-day grant reads as 30.
                let left =
                    days(((grant.sign_in_required_by - time::now() + 86_399) / 86_400).max(1));
                log::info(&format!(
                    "device grant {} created; this machine can skip the browser sign-in until {}",
                    grant.grant_id,
                    time::local_stamp(grant.sign_in_required_by)
                ));
                a.settings.set_grant(Some(grant));
                // Reported, not just logged. The key exists and a slot at the broker
                // has been spent, but an unwritten grant is gone at the next start --
                // so "won't need a browser sign-in for 30 days" would be exactly
                // wrong, and wrong about the thing the user pressed the button for.
                let unsaved = a.settings.save().is_err_and(|e| {
                    log::warn(&format!("could not save the device grant: {e:#}"));
                    true
                });
                // A grant is permission to get tickets, not a ticket. Pressed while
                // signed out -- which is exactly when someone reaches for it -- without
                // this the agent reports "not signed in" while holding a fresh grant
                // and an identity proved seconds earlier, and nothing else is going to
                // sign in for hours.
                //
                // On a pinned machine a live session is no longer a reason to skip
                // it: a fresh grant has never run an exchange, and what is in the
                // cache is the authorizing engineer's, by the same argument
                // [`is_the_grants`] makes. Unpinned, the new grant is for whoever is
                // already signed in, so this stays what it always was.
                let pinned = a.settings.grant_for().is_some();
                grant_sign_in = !is_the_grants(a.settings.grant(), pinned, &a.principal)
                    || a.phase != Phase::Connected;
                // The one moment the agent knows it put a session somewhere and
                // knows the machine no longer needs one.
                a.just_authorized = true;
                a.granted_exchange_pending = grant_sign_in;
                // Same question the sign-out offer asks: is there a browser session
                // of ours left to recommend leaving?
                a.note(&if a.settings.browser_session() {
                    fill(tr().granted_note, &[("idp", &a.idp_name)])
                } else {
                    tr().granted_note_wam.to_string()
                });
                finished = Some((
                    Action::CreateGrant,
                    Outcome::Done {
                        message: fill(tr().grant_done, &[("days", &left)]),
                        detail: unsaved.then(|| tr().dlg_grant_unsaved.to_string()),
                    },
                ));
            }
            Event::GrantFailed { fault, message } => {
                log::warn(&format!("device grant not created: {message}"));
                // Recorded, not just announced. Every one of these needs somebody
                // else to act -- an administrator, or a correction to the account
                // this machine names -- so the answer has to still be on the surface
                // when the user goes looking for it, which is after the balloon.
                a.record(fault, message.clone());
                finished = Some((Action::CreateGrant, Outcome::Failed { message }));
            }
            Event::CloudSignedOut { asked } => {
                a.in_flight.retain(|act| *act != Action::SignOutIdp);
                // Forgetting the session is what makes the offer go away, so it waits
                // for the trip that was the point of the offer. Not proof the
                // authority ended anything -- opening a URL never is -- but it is the
                // difference between "there is no session" and "we meant there to be
                // none".
                if asked
                    && a.settings.set_browser_session(false)
                    && let Err(e) = a.settings.save()
                {
                    log::warn(&format!("could not forget the browser session: {e:#}"));
                }
            }
            Event::GrantGivenUp { revoked, saved } => {
                a.in_flight.retain(|act| *act != Action::GiveUpGrant);
                let broker = a.settings.broker_url().map(host_of).unwrap_or_default();
                // Two independent facts, and the second is the one that costs
                // something later: the key is gone either way, but a directory row
                // that survives holds a `device_grant_max_per_user` slot, and the
                // bill arrives as a refused authorization on a machine that has
                // forgotten why. A third, when this device could not even write down
                // that it no longer holds one.
                let mut detail = fill(
                    if revoked {
                        tr().dlg_grant_off_result_sub
                    } else {
                        tr().dlg_grant_off_result_stale
                    },
                    &[("broker", &broker)],
                );
                if !revoked {
                    log::warn(
                        "this device's grant is gone but its record at the broker is not; an \
                     administrator clears it with `kbmanage device revoke`",
                    );
                }
                if !saved {
                    detail.push_str("\r\n");
                    detail.push_str(tr().dlg_grant_unsaved);
                }
                finished = Some((
                    Action::GiveUpGrant,
                    Outcome::Done {
                        message: tr().dlg_grant_off_result.to_string(),
                        detail: Some(detail),
                    },
                ));
            }
            Event::ElevationGranted { action } => elevating = Some(action),
            Event::Elevated { action, outcome, recheck_enrollment } => {
                if recheck_enrollment {
                    a.enroll_state = enroll::state(&a.kerberos);
                }
                let succeeded = matches!(outcome, Outcome::Done { .. });
                // A successful elevated one-shot during an episode is the repair the
                // confirmed status window asked for. Nothing else is running one
                // mid-episode. It asks for a ticket and deliberately leaves the
                // episode open: the TGT that was evicted is still gone, so re-arming
                // detection here would find it missing 30 s later and raise the
                // surface again, and again, until the scheduled re-injection. Only a
                // landed exchange ends an episode.
                if succeeded && a.fallback != NtlmFallback::Clear {
                    a.refresh_at = Some(time::now());
                }
                // A failure is also a fault the surface has to keep showing after
                // the dialog is dismissed; a decline and a success are not.
                if let Outcome::Failed { message } = &outcome {
                    a.record(Some(Fault::Other), message.clone());
                }
                finished = Some((action, outcome));
            }
        }
    });

    // Before the dialog rather than after it: the modal pumps messages, so the
    // exchange lands while it is still on screen and dismissing it reveals a
    // connected agent instead of starting the wait.
    if grant_sign_in {
        start_worker(Trigger::Granted);
    }
    if let Some((title, body, severity)) = pending {
        notify(&title, &body, severity);
    }
    // The host decides where this lands: its own dialog while one is up, a
    // notification once it is not. That is gate 2, and it lives there because
    // only a surface knows whether it is on screen.
    if let Some(action) = elevating {
        host().elevating(action);
    }
    if let Some((action, outcome)) = finished {
        host().finished(action, outcome);
    }
}

/// Ask the broker for `/config` on a thread of its own.
///
/// Needs no credential and never opens a window, so it is safe anywhere: at
/// startup, where it is the only thing that fetches the grant policy for a
/// machine that will not sign in for hours, and on the re-probe backoff, where it
/// is the only thing that can notice a broker coming back. It does not take the
/// busy slot and `apply` does not release one for it.
///
/// A failure is logged and nothing else: the surface is already saying the broker
/// is unreachable, and the backoff in [`super::tick`] is what answers it.
pub(super) fn discover_in_background() {
    let Some(url) = with(|a| a.settings.broker_url().map(str::to_owned)) else {
        return;
    };
    std::thread::spawn(move || match discovery::discover(&url) {
        Ok(config) => post(Event::Discovered {
            kerberos: config.kerberos,
            device_grant: config.device_grant,
            help_url: config.help_url,
            idp_name: config.oidc.display_name,
            source: discovery::source_name(&config.base_url),
        }),
        Err(e) => log::info(&format!("could not reach the broker for its settings: {e:#}")),
    });
}

// ---- sign-in ---------------------------------------------------------------

/// Spawn the sign-in worker. `silent` prefers the in-memory refresh token and
/// never opens a browser on its own; it falls back by *reporting* failure, so
/// the user is asked rather than surprised by a browser window.
pub(super) fn start_worker(trigger: Trigger) {
    if BUSY.swap(true, Ordering::Relaxed) {
        return;
    }
    let silent = trigger.silent();
    CANCEL.store(false, Ordering::Relaxed);

    let Some(broker) = with(|a| a.settings.broker_url().map(str::to_owned)) else {
        BUSY.store(false, Ordering::Relaxed);
        return;
    };
    // Read on the UI thread and carried in: the settings live in this module's
    // thread-local, which a worker must never touch.
    let use_native = with(|a| a.settings.windows_sign_in());
    let grant = with(|a| a.settings.grant().cloned());
    let pin = with(|a| a.settings.grant_for().map(str::to_owned));
    // Work nobody launched still gets an action's name: a scheduled renewal and
    // a clicked *Renew now* are the same thing to the button that has to be
    // disabled, and only the user's own sign-in can reach a browser.
    with(|a| {
        a.started(if trigger == Trigger::User { Action::SignIn } else { Action::ReinjectTicket });
    });
    if !silent {
        with(|a| {
            a.phase = Phase::SigningIn;
            a.message.clear();
            a.fault = None;
        });
    }

    std::thread::spawn(move || {
        // Catch a panic rather than let the thread die silently: the worker owns the
        // agent's only busy slot, and a slot that is never released stops every
        // future re-injection. A dependency panicking on malformed input (the ccache
        // parser runs over broker-supplied bytes) is the realistic way in.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_sign_in(&broker, silent, use_native, grant.as_ref(), pin.as_deref())
        }));
        let quiet = matches!(trigger, Trigger::Startup | Trigger::Granted);
        match outcome {
            Ok(Ok(Some((injected, config, via_grant)))) => post(Event::SignedIn {
                injected,
                kerberos: config.kerberos,
                device_grant: config.device_grant,
                help_url: config.help_url,
                idp_name: config.oidc.display_name,
                via_grant,
            }),
            Ok(Ok(None)) => post(Event::Cancelled),
            Ok(Err((fault, message))) => post(Event::SignInFailed { fault, message, quiet }),
            Err(_) => post(Event::SignInFailed {
                fault: Some(Fault::Other),
                message: fill(tr().err_internal, &[("detail", "panic in the sign-in worker")]),
                quiet,
            }),
        }
    });
}

/// The worker body. Runs off the UI thread; returns user-facing text on failure,
/// and on success whether the grant is what proved the exchange.
fn run_sign_in(
    broker_url: &str,
    silent: bool,
    use_native: bool,
    grant: Option<&Grant>,
    pin: Option<&str>,
) -> Result<Option<(Injected, BrokerConfig, bool)>, Failure> {
    let config: BrokerConfig =
        discovery::discover(broker_url).map_err(|e| describe_discovery_error(&e, broker_url))?;
    // Reported now, not on the way out. Everything below can fail -- no
    // credential to be silent with is the ordinary case on a machine that has
    // just been retargeted -- and the realm this broker serves is known either
    // way. Held to the end, a failure here left the surface saying "no settings
    // from <host>" about a broker that had just answered.
    post(Event::Discovered {
        kerberos: config.kerberos.clone(),
        device_grant: config.device_grant.clone(),
        help_url: config.help_url.clone(),
        idp_name: config.oidc.display_name.clone(),
        source: discovery::source_name(&config.base_url),
    });
    // Every exchange below hangs off the source the broker confirmed: the
    // configured address carries no source segment when DNS supplied it.
    let base_url = config.base_url.clone();
    let broker_url = base_url.as_str();

    // A granted device proves possession of its TPM key instead of presenting a
    // token, and that is the entire feature: this path must not reach
    // `acquire_token`, or an unattended machine would still be waiting for a
    // browser. `InvalidProof` is one failure worth falling through -- expired,
    // clamped, revoked, or the key is gone -- because a browser sign-in is exactly
    // its fix. So are two of the 403s: the deployment switching the feature off,
    // and this account leaving the device-grant group. Both say the grant is
    // finished while the person can still sign in that minute, so stopping on
    // them locks a machine out instead of sending it to the browser. The
    // caller's rules then decide whether one may open: a silent run reports the
    // failure, a user-triggered one goes to the browser.
    //
    // `refused` carries why the grant did not work when that is a policy answer
    // rather than a dead key: a pinned machine has no browser to fall through
    // to, and telling its operator to re-authorize would be telling them to
    // repeat the one thing that cannot help.
    let mut refused = None;
    if let Some(grant) = grant {
        match session::inject_with_grant(broker_url, grant) {
            Ok(injected) => return Ok(Some((injected, config, true))),
            // Not marked stale, unlike the refusal below: both of these are the
            // operator's to undo, and a grant put back in the group works again
            // untouched. Forgetting it would cost a browser sign-in to rebuild
            // something that had never broken.
            Err(InjectError::Broker(broker::BrokerError::NotAdmitted(why)))
                if why == broker::REFUSED_GRANTS_DISABLED || why == broker::REFUSED_NOT_GRANTED =>
            {
                refused = Some((
                    Some(Fault::GrantRefused),
                    fill(tr().err_not_admitted, &[("detail", &why)]),
                ));
                log::warn(&format!(
                    "this device's grant is no longer accepted ({why}); signing in instead"
                ))
            }
            Err(InjectError::Broker(broker::BrokerError::InvalidProof(why))) => {
                GRANT_STALE.store(true, Ordering::Relaxed);
                log::warn(&format!("this device's grant was refused ({why}); signing in instead"))
            }
            Err(e) => return Err(describe_inject_error(&e, &host_of(broker_url))),
        }
    }

    // Everything below gets a ticket for whoever signs in, and on a pinned
    // machine that is the wrong person by construction -- the pin exists because
    // the account this machine works as is not the account of anyone who ever
    // stands at it. So a pinned machine reaches `/ticket` with a device-grant
    // assertion or not at all, and a grant that is gone is asked for again
    // rather than papered over with the engineer's own session.
    if let Some(target) = pin {
        // No fault where nothing broke: a delegated machine with no grant is
        // waiting to be authorized, which `NoGrant` says without red ink.
        return Err(refused
            .unwrap_or_else(|| (None, fill(tr().err_grant_reauthorize, &[("target", target)]))));
    }

    let token = match acquire_token(&config, silent, use_native)? {
        Some(t) => t,
        None => return Ok(None),
    };

    match session::inject(broker_url, &token) {
        Ok(injected) => Ok(Some((injected, config, false))),
        Err(e) => Err(describe_inject_error(&e, &host_of(broker_url))),
    }
}

/// Windows first when the user has enabled it, then the refresh token if this is
/// a silent renewal, then the browser. The access token is dropped by the caller
/// the moment the ticket comes back.
fn acquire_token(
    config: &BrokerConfig,
    silent: bool,
    use_native: bool,
) -> Result<Option<String>, Failure> {
    // The platform's own credential source, silently on both paths: that is what
    // keeps re-injection unattended without this process holding a refresh token
    // at all, and a silent success is also the only evidence that the OS has an
    // account here worth preferring to the browser. Anything short of a token
    // falls through to what was always here -- see the host implementation for
    // what "anything" covers, and why a failure is not escalated into the
    // platform's own dialog.
    if use_native {
        match host().native_token(&config.oidc) {
            NativeToken::Token(token) => return Ok(Some(token)),
            NativeToken::Unavailable => {}
        }
    }

    if silent {
        let saved = REFRESH_TOKEN.lock().unwrap().clone();
        // Nothing failed here: this machine simply has nothing to be silent
        // with, which is what `NoSupply` is for. The two sentences differ by
        // whether a mechanism was tried -- an empty WAM is a mechanism state,
        // and a machine with the checkbox off never consulted one.
        let refresh_token = saved.ok_or_else(|| {
            (
                None,
                if use_native { tr().err_wam_empty } else { tr().err_browser_required }.to_string(),
            )
        })?;
        let tokens = oidc::refresh(&config.oidc, &refresh_token)
            .map_err(|e| describe_token_error(&e, tr().err_silent_refresh))?;
        if let Some(rt) = tokens.refresh_token {
            *REFRESH_TOKEN.lock().unwrap() = Some(rt);
        }
        return Ok(Some(tokens.access_token));
    }

    // The marker is the whole of when Cancel means anything: the flag it pairs
    // with is read in the accept loop inside this call and nowhere else. A guard
    // rather than two stores, so a panic in there cannot leave a dead Cancel
    // button on screen for the life of the process.
    let leg = BrowserLeg::open();
    let outcome = oidc::login(&config.oidc, &CANCEL);
    drop(leg);
    match outcome {
        Ok(Some(tokens)) => {
            *REFRESH_TOKEN.lock().unwrap() = tokens.refresh_token;
            // A session of ours now exists in a browser. This is a worker
            // thread, so it can only flag the fact; `apply` writes it down.
            NEW_BROWSER_SESSION.store(true, Ordering::Relaxed);
            Ok(Some(tokens.access_token))
        }
        Ok(None) => Ok(None),
        Err(e) => Err(describe_token_error(&e, tr().err_sign_in)),
    }
}

/// Marks a browser leg for as long as it is held. See [`BROWSER_LEG`].
struct BrowserLeg;

impl BrowserLeg {
    fn open() -> Self {
        BROWSER_LEG.store(true, Ordering::Relaxed);
        BrowserLeg
    }
}

impl Drop for BrowserLeg {
    fn drop(&mut self) {
        BROWSER_LEG.store(false, Ordering::Relaxed);
    }
}

// ---- device grants ---------------------------------------------------------

/// Give up this machine's device grant: forget it here, then destroy the TPM key
/// and tell the broker on a worker. Nothing after this can get a ticket without a
/// browser.
///
/// **The round trip must not run on the UI thread.** The case that produces the
/// two-fact outcome -- key destroyed, broker not told -- is a broker that cannot
/// be reached, so on the message loop it freezes the very surface that was going
/// to report it, for the whole timeout, and dismiss-on-blur then eats the
/// result.
///
/// `broker` is passed rather than read here because the one caller that changes
/// it -- retargeting the agent -- must self-revoke at the broker that issued the
/// grant, not at the one the user has just typed in.
pub(super) fn give_up_grant(a: &mut Agent, broker: Option<String>) -> bool {
    let Some(grant) = a.settings.grant().cloned() else {
        return false;
    };
    a.settings.set_grant(None);
    // One of the two things that clear the expectation: whatever this machine
    // was authorized to be, it is not that now.
    a.settings.set_expected_working_as(None);
    let saved = match a.settings.save() {
        Ok(()) => true,
        Err(e) => {
            log::warn(&format!("could not forget the device grant: {e:#}"));
            false
        }
    };
    a.started(Action::GiveUpGrant);
    std::thread::spawn(move || {
        // The key first and unconditionally, so this works offline: see
        // `session::revoke_this_device` for why that order is not negotiable.
        let revoked = session::revoke_this_device(broker.as_deref(), &grant);
        log::info(&format!("gave up device grant {}", grant.grant_id));
        post(Event::GrantGivenUp { revoked, saved });
    });
    true
}

/// Authorize this machine to obtain tickets without a browser sign-in.
///
/// The IdP login *is* the authorization, so this runs the ordinary sign-in
/// first and registers the key on the token it produces. Every failure is
/// reported at click time and none is probed for in advance: one path
/// covers no TPM, a TPM that is not prepared, lockout, policy and the device cap
/// alike, and a cached verdict would be stale exactly when it mattered.
pub fn create_grant() -> bool {
    if BUSY.swap(true, Ordering::Relaxed) {
        return false;
    }
    CANCEL.store(false, Ordering::Relaxed);
    let Some(broker) = with(|a| a.settings.broker_url().map(str::to_owned)) else {
        BUSY.store(false, Ordering::Relaxed);
        return false;
    };
    let use_native = with(|a| a.settings.windows_sign_in());
    let target = with(|a| a.settings.grant_for().map(str::to_owned));
    with(|a| a.started(Action::CreateGrant));

    std::thread::spawn(move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_create_grant(&broker, use_native, target.as_deref())
        }));
        post(match outcome {
            Ok(Ok(Some(grant))) => Event::GrantCreated { grant },
            Ok(Ok(None)) => Event::Cancelled,
            Ok(Err((fault, message))) => Event::GrantFailed { fault, message },
            Err(_) => Event::GrantFailed {
                fault: Some(Fault::Other),
                message: fill(tr().err_internal, &[("detail", "panic in the authorize worker")]),
            },
        });
    });
    true
}

/// The grant worker's body: discover, sign in, make a key, register it.
fn run_create_grant(
    broker_url: &str,
    use_native: bool,
    target: Option<&str>,
) -> Result<Option<Grant>, Failure> {
    let config: BrokerConfig =
        discovery::discover(broker_url).map_err(|e| describe_discovery_error(&e, broker_url))?;
    // The button is drawn from a discovery that may be minutes old; this is the
    // fresh one, and an operator who has since turned the feature off wins.
    if !config.device_grant.enabled() {
        return Err((Some(Fault::GrantRefused), tr().err_grant_disabled.to_string()));
    }
    let base_url = config.base_url.clone();
    let broker_url = base_url.as_str();

    // Never silent: a device grant is the user authorizing *this machine*, and
    // authorizing it needs them to have just proved who they are.
    let Some(token) = acquire_token(&config, false, use_native)? else {
        return Ok(None);
    };

    // Nothing is marked stale here. `create_grant` reuses the key this machine
    // already has, so a renewal refused -- at the cap, outside the group, a
    // broker that went away mid-call -- leaves the stored grant working, and
    // clearing it would cost the user a browser sign-in to recover something
    // that never broke. On success the new grant is written over the old one
    // anyway; and a grant that really is dead is caught where it shows, at the
    // next exchange, by the `InvalidProof` arm above.
    session::create_grant(broker_url, &token, &config.device_grant.audience, target)
        .map(Some)
        .map_err(|e| match e {
            session::GrantError::Broker(e) => describe_grant_error(&e, &host_of(broker_url)),
            session::GrantError::Local(e) => {
                (Some(Fault::Other), fill(tr().err_grant_key, &[("detail", &format!("{e:#}"))]))
            }
        })
}

// ---- elevated one-shots ----------------------------------------------------

/// Relaunch ourselves elevated to register the realm with Windows, then re-check.
pub fn begin_enroll() -> bool {
    let Some(broker) = with(|a| a.settings.broker_url().map(str::to_owned)) else {
        return false;
    };
    spawn_elevated(vec!["--enroll".to_string(), broker], true, Action::Enroll)
}

/// Relaunch ourselves elevated to restart the Workstation service.
pub fn begin_repair() -> bool {
    spawn_elevated(vec!["--repair".to_string()], false, Action::RestartWorkstation)
}

/// Relaunch ourselves elevated to remove the realm's registration from Windows.
pub fn begin_unenroll() -> bool {
    let Some(broker) = with(|a| a.settings.broker_url().map(str::to_owned)) else {
        return false;
    };
    spawn_elevated(vec!["--unenroll".to_string(), broker], true, Action::Unenroll)
}

/// Relaunch ourselves elevated to force a re-apply of the realm registration.
pub fn begin_reenroll() -> bool {
    let Some(broker) = with(|a| a.settings.broker_url().map(str::to_owned)) else {
        return false;
    };
    spawn_elevated(vec!["--reenroll".to_string(), broker], true, Action::Reenroll)
}

/// Run one privileged step in a second copy of this exe and report what it came
/// to.
///
/// **The child renders nothing.** UIPI runs the right way for this -- it can
/// report down to the medium-IL tray, and the tray could never drive its UI --
/// so the confirmation happened here, before the prompt, and what comes back is
/// an exit code plus one sentence through a file whose path this side chose.
/// Absent or unreadable is *couldn't confirm*, never a fabricated success.
fn spawn_elevated(mut args: Vec<String>, recheck_enrollment: bool, action: Action) -> bool {
    if BUSY.swap(true, Ordering::Relaxed) {
        return false;
    }
    with(|a| a.started(action));
    let result = result_path();
    args.push("--result".to_string());
    args.push(result.to_string_lossy().into_owned());
    let args = Arc::new(args);
    // Logged at every step, unlike anything else the agent starts. These are the
    // operations that change the machine outside this process -- a Workstation
    // restart disconnects every network drive the user has open, ours or not --
    // so "did it run, and what did it say" has to be answerable afterwards from
    // the log alone, by someone helping a user who has already lost the window.
    log::info(&format!("elevated {action:?}: requesting elevation"));
    std::thread::spawn(move || {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
            let ran = elevate::run_elevated(&borrowed, &|| {
                log::info(&format!("elevated {action:?}: granted, child started"));
                post(Event::ElevationGranted { action });
            });
            let sentence = std::fs::read_to_string(&result).ok();
            let _ = std::fs::remove_file(&result);
            match &ran {
                Ok(elevate::Elevated::Declined) => {
                    log::info(&format!("elevated {action:?}: declined at the prompt"));
                }
                Ok(elevate::Elevated::Unavailable) => {
                    log::warn(&format!("elevated {action:?}: elevation unavailable"));
                }
                Ok(elevate::Elevated::Ran(code)) => log::info(&format!(
                    "elevated {action:?}: child exited {code}, reported {}",
                    sentence.as_deref().map_or("nothing", str::trim)
                )),
                Err(e) => log::error(&format!("elevated {action:?}: could not start: {e:#}")),
            }
            match ran {
                // A decline is a decision: it returns the dialog to its question
                // and says nothing anywhere else.
                Ok(elevate::Elevated::Declined) => Outcome::Declined,
                Ok(elevate::Elevated::Unavailable) => {
                    Outcome::Failed { message: tr().err_elevation_unavailable.to_string() }
                }
                Ok(elevate::Elevated::Ran(code)) => match sentence.as_deref().map(str::trim) {
                    Some(s) if !s.is_empty() && code == 0 => {
                        Outcome::Done { message: s.to_owned(), detail: None }
                    }
                    Some(s) if !s.is_empty() => Outcome::Failed { message: s.to_owned() },
                    // It ran, and left nothing to say what happened.
                    _ => Outcome::Failed { message: tr().err_elevated_unconfirmed.to_string() },
                },
                Err(e) => Outcome::Failed {
                    message: fill(tr().err_elevation_failed, &[("detail", &format!("{e:#}"))]),
                },
            }
        }));
        let outcome = outcome.unwrap_or_else(|_| Outcome::Failed {
            message: fill(tr().err_internal, &[("detail", "panic in the elevation worker")]),
        });
        // Post either way -- the event is what releases the busy slot.
        post(Event::Elevated { action, outcome, recheck_enrollment });
    });
    true
}

/// Where the elevated child leaves its one sentence. Named for this process, so
/// two agents in two logon sessions cannot read each other's.
fn result_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("kerbridge-elevated-{}.txt", std::process::id()))
}
