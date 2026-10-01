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

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use crate::config::Grant;
use crate::describe::{Action, Fault};
use crate::discovery::{BrokerConfig, BrokerDocument};
use crate::session::{InjectError, Injected};
use crate::strings::{days, duration, fill, tr};
use crate::{broker, discovery, elevate, enroll, log, oidc, session, time};

use super::failure::{
    Failure, describe_discovery_error, describe_grant_error, describe_inject_error,
    describe_token_error,
};
use super::{
    Agent, BROWSER_LEG, BUSY, BrokerSnapshot, CANCEL, DiscoveryStamp, GRANT_CLEANUP,
    LOSS_POLL_SECS, MIN_REFRESH_DELAY, NativeToken, Outcome, PROBE_MAX_SECS, Phase, REFRESH_TOKEN,
    STARTUP_RETRY_BOUNDED_SECS, STARTUP_RETRY_SECS, Severity, TgtLoss, host, host_of,
    is_the_grants, midpoint, next_backoff, notify, purge_realm, with,
};

// ---- the queue -------------------------------------------------------------

/// What workers have finished, waiting for the UI thread to apply it. See [`post`].
static EVENTS: Mutex<Vec<Event>> = Mutex::new(Vec::new());

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

#[derive(Default)]
enum RefreshUpdate {
    #[default]
    Keep,
    Set(Option<crate::secret::Secret>),
}

#[derive(Default)]
pub(super) struct WorkerEffects {
    refresh_token: RefreshUpdate,
    browser_session_started: bool,
    grant_stale: bool,
    injection_realm: Option<String>,
}

impl WorkerEffects {
    /// Apply worker-local mutations only after the terminal stamp is accepted.
    fn apply(self, a: &mut Agent) {
        let mut save = false;
        if let RefreshUpdate::Set(refresh_token) = self.refresh_token {
            *REFRESH_TOKEN.lock().unwrap() = refresh_token;
        }
        if self.browser_session_started {
            save |= a.settings.set_browser_session(true);
        }
        if self.grant_stale && a.settings.grant().is_some() {
            a.settings.set_grant(None);
            save = true;
            log::info("this device's grant is no longer usable; a browser sign-in is needed again");
        }
        if save && let Err(e) = a.settings.save() {
            log::warn(&format!("could not save worker session state: {e:#}"));
        }
    }
}

/// What a worker reports back. Queued by [`post`], applied by [`drain`].
pub(super) enum Event {
    SignedIn {
        stamp: DiscoveryStamp,
        injected: Injected,
        realm: String,
        effects: WorkerEffects,
        /// The exchange was proved with this machine's grant, so the principal
        /// that came back is what the grant works as -- the one fact that lets a
        /// later startup tell this machine's ticket from anybody else's.
        via_grant: bool,
    },
    SignInFailed {
        stamp: DiscoveryStamp,
        effects: WorkerEffects,
        /// What class of failure it was, or `None` where nothing failed and
        /// there was simply nothing to be silent with -- an absence the blocker
        /// list already explains, and not something to dress as a breakage.
        fault: Option<Fault>,
        message: String,
        quiet: bool,
    },
    Cancelled {
        stamp: DiscoveryStamp,
        effects: WorkerEffects,
    },
    /// An elevated operation finished. The parent supplies outcomes the child
    /// cannot report: permission declined or an unreadable result file.
    ElevatedFinished {
        action: Action,
        outcome: Outcome,
        recheck_enrollment: bool,
    },
    /// DNS answered with a broker for a client that had none configured.
    BrokerDiscovered {
        url: String,
    },
    /// One complete discovery document. This is the only event that publishes
    /// broker-owned snapshot fields. `accepted` lets an operation wait before it
    /// starts OIDC discovery.
    Discovered {
        stamp: DiscoveryStamp,
        snapshot: BrokerSnapshot,
        accepted: Option<std::sync::mpsc::Sender<bool>>,
    },
    /// Ask whether a worker's requested broker URL and generation are still
    /// current before an external side effect.
    Current {
        stamp: DiscoveryStamp,
        current: std::sync::mpsc::Sender<bool>,
    },
    /// This machine may now skip the browser sign-in.
    GrantCreated {
        stamp: DiscoveryStamp,
        grant: Grant,
        broker_url: String,
        effects: WorkerEffects,
    },
    /// It may not, and this is why. Already user-facing, and carrying its class:
    /// a refused authorization is a standing fact about the account, not a
    /// transient the surface may forget once its balloon has gone.
    GrantFailed {
        stamp: DiscoveryStamp,
        effects: WorkerEffects,
        fault: Option<Fault>,
        message: String,
    },
    /// The cloud sign-out finished. It does not own the busy slot.
    /// `asked` is whether the authority was reached at all. A sign-out that never
    /// left the machine must not be recorded as one that did.
    CloudSignedOut {
        stamp: DiscoveryStamp,
        asked: bool,
    },
    /// Cleanup for a device grant that was created after its stamp became stale.
    StaleGrantCompensated {
        stamp: DiscoveryStamp,
    },
    /// The revoke worker finished. The key on this device is gone either way;
    /// `revoked` is the second, independent fact -- whether the captured `broker`
    /// was told. `saved` is a third: this device could not update its own record.
    /// `report` is true only for a user-requested cleanup.
    GrantGivenUp {
        generation: u64,
        broker: Option<String>,
        revoked: bool,
        saved: bool,
        report: bool,
    },
    /// The elevation prompt has been answered and the child is running. The one
    /// observable moment between the two phases a dialog can distinguish; the
    /// secure desktop reports nothing.
    ElevationGranted {
        action: Action,
    },
}

impl BrokerSnapshot {
    fn from_document(document: &BrokerDocument) -> Self {
        Self {
            kerberos: document.kerberos.clone(),
            device_grant: document.device_grant.clone(),
            defaults: document.defaults,
            help_url: document.help_url.clone(),
            idp_name: document.idp_name.clone(),
            source: discovery::source_name(&document.base_url),
        }
    }
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
    let mut applied = false;
    for ev in events {
        applied |= apply(ev);
    }
    applied
}

fn reject_stale_terminal(ev: Event) -> bool {
    match ev {
        Event::SignedIn { stamp, realm, .. } => {
            log::warn("discarding a ticket injected after its broker request became stale");
            purge_realm(&realm);
            with(|a| a.finish_busy(&stamp, true))
        }
        Event::SignInFailed { stamp, effects, .. } => {
            if let Some(realm) = effects.injection_realm {
                purge_realm(&realm);
            }
            with(|a| a.finish_busy(&stamp, true))
        }
        Event::Cancelled { stamp, .. } | Event::GrantFailed { stamp, .. } => {
            with(|a| a.finish_busy(&stamp, true))
        }
        Event::GrantCreated { stamp, grant, broker_url, .. } => {
            log::warn("removing a device grant created after its broker request became stale");
            std::thread::spawn(move || {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    session::revoke_this_device(Some(&broker_url), &grant)
                }));
                post(Event::StaleGrantCompensated { stamp });
            });
            false
        }
        Event::CloudSignedOut { stamp, .. } => with(|a| a.finish_cloud_sign_out(&stamp)),
        _ => unreachable!("only stamped terminal events can be stale"),
    }
}

/// One worker's result. As in [`tick`], the balloon is raised only after the
/// agent borrow is released.
fn apply(ev: Event) -> bool {
    // These events only answer a worker that is waiting. They publish no state.
    let ev = match ev {
        Event::Current { stamp, current } => {
            let _ = current.send(with(|a| a.discovery_is_current(&stamp)));
            return false;
        }
        Event::Discovered { stamp, snapshot, accepted } => {
            let applied = with(|a| {
                let Some(cache_changed) = a.replace_broker_snapshot(&stamp, snapshot) else {
                    return false;
                };
                let autostart_changed = a.settings.enforce_autostart();
                if (cache_changed || autostart_changed)
                    && let Err(e) = a.settings.save()
                {
                    log::warn(&format!("could not save the accepted broker settings: {e:#}"));
                }
                true
            });
            if let Some(reply) = accepted {
                let _ = reply.send(applied);
            }
            return applied;
        }
        Event::StaleGrantCompensated { stamp } => {
            return with(|a| a.finish_busy(&stamp, true));
        }
        other => other,
    };

    let terminal_stamp = match &ev {
        Event::SignedIn { stamp, .. }
        | Event::SignInFailed { stamp, .. }
        | Event::Cancelled { stamp, .. }
        | Event::GrantCreated { stamp, .. }
        | Event::GrantFailed { stamp, .. }
        | Event::CloudSignedOut { stamp, .. } => Some(stamp),
        _ => None,
    };
    if terminal_stamp.is_some_and(|stamp| !with(|a| a.discovery_is_current(stamp))) {
        return reject_stale_terminal(ev);
    }

    // Elevated operations use the busy slot without a discovery stamp.
    if matches!(ev, Event::ElevatedFinished { .. }) {
        BUSY.store(false, Ordering::Relaxed);
        with(|a| a.in_flight.retain(|action| action.outside_busy_slot()));
    }
    let mut pending: Option<(String, String, Severity)> = None;
    let mut finished: Option<(Action, Outcome)> = None;
    let mut grant_sign_in = false;
    let mut elevating = None;
    let mut discover = false;

    with(|a| {
        match ev {
            Event::SignedIn { stamp, injected, effects, via_grant, .. } => {
                a.finish_busy(&stamp, false);
                effects.apply(a);
                // Gate 1: a session starting is news, and so is a fault clearing.
                // A midpoint renewal that simply worked moves no condition and says
                // nothing, and neither does a replaced TGT -- unless the
                // escalation already announced its episode's failures.
                let recovered = a.loss_landed();
                let news = a.phase != Phase::Connected
                    || ((!recovered || a.escalated) && (a.fault.is_some() || a.silent_failed));
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
                // Everything except the exchange a fresh grant started itself: that
                // one is the second half of the authorization the user just
                // performed, not news arriving after it.
                if a.granted_exchange_pending {
                    a.granted_exchange_pending = false;
                } else {
                    a.just_authorized = false;
                }
                // The episode stays open -- see [`TgtLoss`] -- and the next look
                // for the TGT is a poll interval away.
                a.loss_check_at = time::now() + LOSS_POLL_SECS;
                // The accepted broker snapshot already supplied the realm. Success
                // changes ticket and session facts only.
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
            Event::SignInFailed { stamp, effects, fault, message, quiet } => {
                a.finish_busy(&stamp, false);
                effects.apply(a);
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
                    // it keeps the ordinary midpoint schedule untouched. With the
                    // TGT absent, the episode's own backoff decides instead.
                    if a.loss.absent {
                        a.loss_failed(fault, time::now());
                    } else if fault == Some(Fault::Network) {
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
                    a.refresh_at = None;
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
                    // Somebody asked for this, or an overdue re-injection ran
                    // after End Time, and no ticket came of it. The product has
                    // no per-failure headline: the resulting condition is the
                    // title, and the mechanism sentence is the body. If the
                    // flyout is up, gate 2 suppresses the toast.
                    a.phase = Phase::Error;
                    a.refresh_at = None;
                    pending = Some((tr().cond_stopped.into(), a.message.clone(), Severity::Error));
                }
            }
            Event::Cancelled { stamp, effects } => {
                a.finish_busy(&stamp, false);
                effects.apply(a);
                // Same reasoning: cancelling a sign-in must not throw away a session
                // that is still working.
                if a.phase == Phase::SigningIn {
                    a.phase =
                        if a.holds_live_ticket() { Phase::Connected } else { Phase::SignedOut };
                }
            }
            Event::Discovered { .. }
            | Event::Current { .. }
            | Event::StaleGrantCompensated { .. } => {
                unreachable!("worker acknowledgements are handled before shared events")
            }
            Event::BrokerDiscovered { url } => {
                // The user may have typed one into Settings while the lookup ran;
                // theirs wins, and `broker_url` already says so.
                if a.settings.broker_url().is_none() {
                    log::info(&format!("using the broker DNS advertises: {url}"));
                    a.settings.set_discovered(url);
                    let _ = a.advance_discovery();
                    // Fetch `/config`: ticket adoption skips startup retry.
                    discover = true;
                    // Autostart ran before DNS discovery; retry only when signed out.
                    if a.phase == Phase::SignedOut {
                        a.startup_retry_at = Some(time::now());
                    }
                }
            }
            Event::GrantCreated { stamp, grant, effects, .. } => {
                a.finish_busy(&stamp, false);
                effects.apply(a);
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
            Event::GrantFailed { stamp, effects, fault, message } => {
                a.finish_busy(&stamp, false);
                effects.apply(a);
                log::warn(&format!("device grant not created: {message}"));
                // Recorded, not just announced. Every one of these needs somebody
                // else to act -- an administrator, or a correction to the account
                // this machine names -- so the answer has to still be on the surface
                // when the user goes looking for it, which is after the balloon.
                a.record(fault, message.clone());
                finished = Some((Action::CreateGrant, Outcome::Failed { message }));
            }
            Event::CloudSignedOut { stamp, asked } => {
                a.finish_cloud_sign_out(&stamp);
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
            Event::GrantGivenUp { generation, broker, revoked, saved, report } => {
                if !a.finish_grant_cleanup(generation) {
                    return;
                }
                GRANT_CLEANUP.store(false, Ordering::Relaxed);
                // A surviving directory row holds a device-grant slot. Log it
                // even when retarget cleanup has no user-facing result.
                if !revoked {
                    log::warn(
                        "this device's grant is gone but its record at the broker is not; an \
                     administrator clears it with `kbmanage device revoke`",
                    );
                }
                if report {
                    let broker = broker.as_deref().map(host_of).unwrap_or_default();
                    let mut detail = fill(
                        if revoked {
                            tr().dlg_grant_off_result_sub
                        } else {
                            tr().dlg_grant_off_result_stale
                        },
                        &[("broker", &broker)],
                    );
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
            }
            Event::ElevationGranted { action } => elevating = Some(action),
            Event::ElevatedFinished { action, outcome, recheck_enrollment } => {
                if recheck_enrollment && !a.kerberos.realm.is_empty() {
                    a.enroll_state = enroll::state(&a.kerberos);
                }
                // A successful repair ends the loss episode. The TGT is looked
                // for at once, and a fresh episode starts if it is still absent.
                if action == Action::RestartWorkstation && matches!(outcome, Outcome::Done { .. }) {
                    a.loss = TgtLoss::default();
                    a.loss_check_at = 0;
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

    // Run after the agent borrow: discovery reads settings.
    if discover {
        #[cfg(not(test))]
        discover_in_background();
    }
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
    true
}

/// Ask the broker for `/config` on a thread of its own.
///
/// Needs no credential and never opens a window. It runs at startup, where it is
/// the only thing that fetches the device-grant policy for a machine that will not sign
/// in for hours, and on the re-probe backoff, where it is the only thing that can
/// notice a broker coming back. It waits while cloud sign-out owns the current
/// discovery generation. It does not take the busy slot and `apply` does not
/// release one for it.
///
/// A failure is logged and nothing else: the surface is already saying the broker
/// is unreachable, and the backoff in [`super::tick`] is what answers it.
pub(super) fn discover_in_background() {
    let Some(stamp) =
        with(|a| if a.cloud_sign_out.is_some() { None } else { a.advance_discovery() })
    else {
        return;
    };
    std::thread::spawn(move || match discovery::broker_document(&stamp.requested_broker_url) {
        Ok(document) => post(Event::Discovered {
            snapshot: BrokerSnapshot::from_document(&document),
            stamp,
            accepted: None,
        }),
        Err(e) => log::info(&format!("could not reach the broker for its settings: {e:#}")),
    });
}

/// Publish one discovery document and wait for the UI thread to accept its stamp.
fn publish_and_wait(stamp: DiscoveryStamp, document: &BrokerDocument) -> bool {
    let (send, receive) = std::sync::mpsc::channel();
    post(Event::Discovered {
        stamp,
        snapshot: BrokerSnapshot::from_document(document),
        accepted: Some(send),
    });
    receive.recv().unwrap_or(false)
}

fn still_current(stamp: &DiscoveryStamp) -> bool {
    let (send, receive) = std::sync::mpsc::channel();
    post(Event::Current { stamp: stamp.clone(), current: send });
    receive.recv().unwrap_or(false)
}

/// Make publication a completed first leg. The second leg does not start when
/// the snapshot lost its requested broker URL or generation while the request was running.
fn after_broker_document<D, T, E>(
    document: D,
    publish: impl FnOnce(&D) -> bool,
    next: impl FnOnce(D) -> Result<T, E>,
) -> Result<Option<T>, E> {
    if !publish(&document) {
        return Ok(None);
    }
    next(document).map(Some)
}

fn discover_oidc_after_publication(
    stamp: &DiscoveryStamp,
    document: BrokerDocument,
) -> anyhow::Result<Option<BrokerConfig>> {
    after_broker_document(
        document,
        |document| publish_and_wait(stamp.clone(), document),
        BrokerDocument::discover_oidc,
    )
}

// ---- sign-in ---------------------------------------------------------------

/// Spawn the sign-in worker. `silent` prefers the in-memory refresh token and
/// never opens a browser on its own; it falls back by *reporting* failure, so
/// the user is asked rather than surprised by a browser window.
pub(super) fn start_worker(trigger: Trigger) {
    if GRANT_CLEANUP.load(Ordering::Relaxed) || with(|a| a.cloud_sign_out.is_some()) {
        if trigger == Trigger::Startup {
            with(|a| a.startup_retry_at = Some(time::now() + 1));
        }
        return;
    }
    if BUSY.swap(true, Ordering::Relaxed) {
        return;
    }
    let silent = trigger.silent();
    CANCEL.store(false, Ordering::Relaxed);

    let Some((stamp, use_native, grant, pin)) = with(|a| {
        let stamp = a.advance_discovery()?;
        Some((
            stamp,
            a.settings.windows_sign_in(),
            a.settings.grant().cloned(),
            a.settings.grant_for().map(str::to_owned),
        ))
    }) else {
        BUSY.store(false, Ordering::Relaxed);
        return;
    };
    let action = if trigger == Trigger::User { Action::SignIn } else { Action::ReinjectTicket };
    // Work nobody launched still gets an action's name: a scheduled renewal and
    // a clicked *Renew now* are the same thing to the button that has to be
    // disabled, and only the user's own sign-in can reach a browser.
    with(|a| a.started_busy(stamp.clone(), action));
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
        let mut effects = WorkerEffects::default();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_sign_in(&stamp, silent, use_native, grant.as_ref(), pin.as_deref(), &mut effects)
        }));
        let quiet = matches!(trigger, Trigger::Startup | Trigger::Granted);
        match outcome {
            Ok(Ok(Some((injected, via_grant, realm)))) => {
                post(Event::SignedIn { stamp, injected, realm, effects, via_grant })
            }
            Ok(Ok(None)) => post(Event::Cancelled { stamp, effects }),
            Ok(Err((fault, message))) => {
                post(Event::SignInFailed { stamp, effects, fault, message, quiet })
            }
            Err(_) => post(Event::SignInFailed {
                stamp,
                effects,
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
    stamp: &DiscoveryStamp,
    silent: bool,
    use_native: bool,
    grant: Option<&Grant>,
    pin: Option<&str>,
    effects: &mut WorkerEffects,
) -> Result<Option<(Injected, bool, String)>, Failure> {
    let requested_broker_url = stamp.requested_broker_url.clone();
    let document = discovery::broker_document(&requested_broker_url)
        .map_err(|e| describe_discovery_error(&e, &requested_broker_url))?;
    // The discovery document must be accepted before the IdP is asked. A later IdP
    // failure cannot undo it, and a stale payload cannot start the second leg.
    let Some(config) = discover_oidc_after_publication(stamp, document)
        .map_err(|e| describe_discovery_error(&e, &requested_broker_url))?
    else {
        return Ok(None);
    };
    // Every exchange below hangs off the source the broker confirmed: the
    // configured address carries no source segment when DNS supplied it.
    let base_url = config.base_url.clone();
    let broker_url = base_url.as_str();
    let realm = config.kerberos.realm.clone();

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
    if !still_current(stamp) {
        return Ok(None);
    }
    if let Some(grant) = grant {
        effects.injection_realm = Some(realm.clone());
        match session::inject_with_grant(broker_url, grant) {
            Ok(injected) => return Ok(Some((injected, true, realm))),
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
                effects.grant_stale = true;
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

    if !still_current(stamp) {
        return Ok(None);
    }
    let token = match acquire_token(&config, silent, use_native, effects)? {
        Some(t) => t,
        None => return Ok(None),
    };
    if !still_current(stamp) {
        return Ok(None);
    }

    effects.injection_realm = Some(realm.clone());
    match session::inject(broker_url, token.expose()) {
        Ok(injected) => Ok(Some((injected, false, realm))),
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
    effects: &mut WorkerEffects,
) -> Result<Option<crate::secret::Secret>, Failure> {
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
        let tokens = oidc::refresh(&config.oidc, refresh_token.expose())
            .map_err(|e| describe_token_error(&e, tr().err_silent_refresh))?;
        if let Some(refresh_token) = tokens.refresh_token {
            effects.refresh_token = RefreshUpdate::Set(Some(refresh_token));
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
            effects.refresh_token = RefreshUpdate::Set(tokens.refresh_token);
            effects.browser_session_started = true;
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

/// Discover the current authority, then ask it to end the browser session. It
/// has its own worker but waits until ticket or device-grant work leaves the busy slot.
pub(super) fn begin_cloud_sign_out() -> bool {
    // A concurrent discovery document would supersede ticket or device-grant work between
    // its final stamp check and its external side effect.
    if BUSY.load(Ordering::Relaxed) {
        return false;
    }
    let Some(stamp) = with(|a| {
        if !a.settings.browser_session() || a.cloud_sign_out.is_some() {
            return None;
        }
        let stamp = a.advance_discovery()?;
        a.started(Action::SignOutIdp);
        a.cloud_sign_out = Some(stamp.clone());
        Some(stamp)
    }) else {
        return false;
    };
    *REFRESH_TOKEN.lock().unwrap() = None;

    std::thread::spawn(move || {
        let requested_broker_url = stamp.requested_broker_url.clone();
        let asked = match discovery::broker_document(&requested_broker_url) {
            Ok(document) => match discover_oidc_after_publication(&stamp, document) {
                Ok(Some(config)) if still_current(&stamp) => oidc::logout(&config.oidc),
                Ok(Some(_)) | Ok(None) => false,
                Err(e) => {
                    log::warn(&format!("cloud sign-out: OIDC discovery failed: {e:#}"));
                    false
                }
            },
            Err(e) => {
                log::warn(&format!("cloud sign-out: broker discovery failed: {e:#}"));
                false
            }
        };
        post(Event::CloudSignedOut { stamp, asked });
    });
    true
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
    if BUSY.load(Ordering::Relaxed) || GRANT_CLEANUP.load(Ordering::Relaxed) {
        return false;
    }
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
    give_up_captured_grant(a, broker, grant, saved, true)
}

/// `report` is false for retarget cleanup, so an internal grant release cannot
/// open a result surface.
pub(super) fn give_up_captured_grant(
    a: &mut Agent,
    broker: Option<String>,
    grant: Grant,
    saved: bool,
    report: bool,
) -> bool {
    if GRANT_CLEANUP.swap(true, Ordering::Relaxed) {
        return false;
    }
    let generation = a.started_grant_cleanup();
    std::thread::spawn(move || {
        // The key first and unconditionally, so this works offline: see
        // `session::revoke_this_device` for why that order is not negotiable.
        let revoked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            session::revoke_this_device(broker.as_deref(), &grant)
        }))
        .unwrap_or(false);
        log::info(&format!("gave up device grant {}", grant.grant_id));
        post(Event::GrantGivenUp { generation, broker, revoked, saved, report });
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
    if GRANT_CLEANUP.load(Ordering::Relaxed)
        || with(|a| a.cloud_sign_out.is_some())
        || BUSY.swap(true, Ordering::Relaxed)
    {
        return false;
    }
    CANCEL.store(false, Ordering::Relaxed);
    let Some((stamp, use_native, target)) = with(|a| {
        let stamp = a.advance_discovery()?;
        Some((stamp, a.settings.windows_sign_in(), a.settings.grant_for().map(str::to_owned)))
    }) else {
        BUSY.store(false, Ordering::Relaxed);
        return false;
    };
    with(|a| a.started_busy(stamp.clone(), Action::CreateGrant));

    std::thread::spawn(move || {
        let mut effects = WorkerEffects::default();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_create_grant(&stamp, use_native, target.as_deref(), &mut effects)
        }));
        post(match outcome {
            Ok(Ok(Some((grant, broker_url)))) => {
                Event::GrantCreated { stamp, grant, broker_url, effects }
            }
            Ok(Ok(None)) => Event::Cancelled { stamp, effects },
            Ok(Err((fault, message))) => Event::GrantFailed { stamp, effects, fault, message },
            Err(_) => Event::GrantFailed {
                stamp,
                effects,
                fault: Some(Fault::Other),
                message: fill(tr().err_internal, &[("detail", "panic in the authorize worker")]),
            },
        });
    });
    true
}

/// The device-grant work: discover, sign in, create a device key, register it.
fn run_create_grant(
    stamp: &DiscoveryStamp,
    use_native: bool,
    target: Option<&str>,
    effects: &mut WorkerEffects,
) -> Result<Option<(Grant, String)>, Failure> {
    let requested_broker_url = stamp.requested_broker_url.clone();
    let document = discovery::broker_document(&requested_broker_url)
        .map_err(|e| describe_discovery_error(&e, &requested_broker_url))?;
    let Some(config) = discover_oidc_after_publication(stamp, document)
        .map_err(|e| describe_discovery_error(&e, &requested_broker_url))?
    else {
        return Ok(None);
    };
    // The button is drawn from a discovery that may be minutes old; this is the
    // fresh one, and an operator who has since turned the feature off wins.
    if !config.device_grant.enabled() {
        return Err((Some(Fault::GrantRefused), tr().err_grant_disabled.to_string()));
    }
    let base_url = config.base_url.clone();
    let broker_url = base_url.as_str();

    // Creating a device grant never runs silently: the user must have just
    // proved who they are.
    if !still_current(stamp) {
        return Ok(None);
    }
    let Some(token) = acquire_token(&config, false, use_native, effects)? else {
        return Ok(None);
    };
    if !still_current(stamp) {
        return Ok(None);
    }

    // Nothing is marked stale here. `create_grant` reuses the key this machine
    // already has, so a renewal refused -- at the cap, outside the group, a
    // broker that went away mid-call -- leaves the stored grant working, and
    // clearing it would cost the user a browser sign-in to recover something
    // that never broke. On success the new grant is written over the old one
    // anyway; and a grant that really is dead is caught where it shows, at the
    // next exchange, by the `InvalidProof` arm above.
    match session::create_grant(broker_url, token.expose(), &config.device_grant.audience, target) {
        Ok(grant) => Ok(Some((grant, base_url))),
        Err(session::GrantError::Broker(e)) => Err(describe_grant_error(&e, &host_of(broker_url))),
        Err(session::GrantError::Local(e)) => {
            Err((Some(Fault::Other), fill(tr().err_grant_key, &[("detail", &format!("{e:#}"))])))
        }
    }
}

// ---- elevated operations -----------------------------------------------------

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
/// report down to the medium-IL agent, and the agent could never drive its UI --
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
        post(Event::ElevatedFinished { action, outcome, recheck_enrollment });
    });
    true
}

/// Where the elevated child leaves its one sentence. Named for this process, so
/// two agents in two logon sessions cannot read each other's.
fn result_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("kerbridge-elevated-{}.txt", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FileConfig;
    use crate::discovery::{Defaults, DeviceGrantConfig, KerberosConfig};
    use std::cell::{Cell, RefCell};

    static STATE_LOCK: Mutex<()> = Mutex::new(());

    fn install_agent(broker_url: &str) {
        let settings = crate::config::Settings::for_test(FileConfig {
            broker_url: Some(broker_url.to_owned()),
            ..FileConfig::default()
        });
        super::super::AGENT.with(|slot| *slot.borrow_mut() = Some(Agent::new(settings)));
        BUSY.store(false, Ordering::Relaxed);
        GRANT_CLEANUP.store(false, Ordering::Relaxed);
        *REFRESH_TOKEN.lock().unwrap() = None;
    }

    fn snapshot(realm: &str, source: &str) -> BrokerSnapshot {
        BrokerSnapshot {
            kerberos: KerberosConfig {
                realm: realm.to_owned(),
                kdcs: vec![format!("kdc.{}", realm.to_ascii_lowercase())],
                services: vec![format!("nas.{}", realm.to_ascii_lowercase())],
            },
            device_grant: DeviceGrantConfig { days: 30, audience: format!("kerbridge://{realm}") },
            defaults: Defaults { silent: Some(false), ..Defaults::default() },
            help_url: Some(format!("https://help.{}/", realm.to_ascii_lowercase())),
            idp_name: format!("IdP {realm}"),
            source: source.to_owned(),
        }
    }

    fn discovered(stamp: DiscoveryStamp, snapshot: BrokerSnapshot) -> Event {
        Event::Discovered { stamp, snapshot, accepted: None }
    }

    fn finish_test() {
        BUSY.store(false, Ordering::Relaxed);
        GRANT_CLEANUP.store(false, Ordering::Relaxed);
        *REFRESH_TOKEN.lock().unwrap() = None;
        super::super::AGENT.with(|slot| *slot.borrow_mut() = None);
    }

    #[test]
    fn device_grant_and_sign_in_flow_publish_before_oidc_failure() {
        let published = Cell::new(false);
        let order = RefCell::new(Vec::new());
        let result: Result<Option<()>, &str> = after_broker_document(
            "discovery document",
            |_| {
                order.borrow_mut().push("published");
                published.set(true);
                true
            },
            |_| {
                assert!(published.get());
                order.borrow_mut().push("OIDC failed");
                Err("OIDC failed")
            },
        );

        assert_eq!(result, Err("OIDC failed"));
        assert!(published.get(), "the accepted snapshot remains published");
        assert_eq!(&*order.borrow(), &["published", "OIDC failed"]);
    }

    #[test]
    fn broker_snapshot_is_applied_before_following_oidc_failure() {
        let _guard = STATE_LOCK.lock().unwrap();
        install_agent("https://a.example.site");
        let stamp = with(Agent::advance_discovery).unwrap();
        let expected = snapshot("A.SITE", "a");

        let result: Result<Option<()>, &str> = after_broker_document(
            "parsed discovery document",
            |_| apply(discovered(stamp.clone(), expected.clone())),
            |_| Err("OIDC failed"),
        );

        assert_eq!(result, Err("OIDC failed"));
        with(|a| {
            assert!(a.kerberos == expected.kerberos);
            assert_eq!(a.help_url, expected.help_url);
            assert_eq!(a.idp_name, expected.idp_name);
            assert_eq!(a.source, expected.source);
            assert!(a.settings.defaults_ready());
        });
        finish_test();
    }

    #[test]
    fn event_application_rejects_late_target_and_same_target_generations() {
        let _guard = STATE_LOCK.lock().unwrap();
        install_agent("https://a.example.site");
        let accepted_a = with(Agent::advance_discovery).unwrap();
        assert!(apply(discovered(accepted_a, snapshot("A.SITE", "a"))));
        let late_a = with(Agent::advance_discovery).unwrap();

        with(|a| {
            a.settings.set_broker_url("https://b.example.site");
            a.invalidate_broker_snapshot();
        });
        let older_b = with(Agent::advance_discovery).unwrap();
        let newest_b = with(Agent::advance_discovery).unwrap();
        assert!(!apply(discovered(older_b, snapshot("OLD.SITE", "old"))));
        let expected_b = snapshot("B.SITE", "b");
        assert!(apply(discovered(newest_b, expected_b.clone())));
        assert!(!apply(discovered(late_a, snapshot("LATE.SITE", "late"))));

        with(|a| {
            assert!(a.kerberos == expected_b.kerberos);
            assert_eq!(a.help_url, expected_b.help_url);
            assert_eq!(a.idp_name, expected_b.idp_name);
            assert_eq!(a.source, expected_b.source);
        });
        finish_test();
    }

    #[test]
    fn stale_terminal_discards_worker_effects_and_releases_only_its_operation() {
        let _guard = STATE_LOCK.lock().unwrap();
        install_agent("https://a.example.site");
        let accepted = with(Agent::advance_discovery).unwrap();
        assert!(apply(discovered(accepted, snapshot("A.SITE", "a"))));
        with(|a| {
            a.settings.set_grant(Some(Grant {
                grant_id: "1a2b3c4d".into(),
                identity: "kb1|entra|subject".into(),
                principal: None,
                audience: "kerbridge://A.SITE".into(),
                sign_in_required_by: 1_785_000_000,
            }));
        });
        *REFRESH_TOKEN.lock().unwrap() = Some(crate::secret::Secret::new("current"));

        let stale = with(|a| {
            let stamp = a.advance_discovery().unwrap();
            a.started_busy(stamp.clone(), Action::SignIn);
            a.phase = Phase::SigningIn;
            stamp
        });
        BUSY.store(true, Ordering::Relaxed);
        let _newer = with(|a| {
            let stamp = a.advance_discovery().unwrap();
            a.record(Some(Fault::Network), "current fault".into());
            stamp
        });
        let effects = WorkerEffects {
            refresh_token: RefreshUpdate::Set(None),
            browser_session_started: true,
            grant_stale: true,
            injection_realm: None,
        };
        assert!(apply(Event::SignInFailed {
            stamp: stale,
            effects,
            fault: Some(Fault::Refused),
            message: "stale fault".into(),
            quiet: false,
        }));

        with(|a| {
            assert_eq!(a.fault, Some(Fault::Network));
            assert_eq!(a.message, "current fault");
            assert!(a.settings.grant().is_some());
            assert!(!a.settings.browser_session());
            assert!(a.busy_operation.is_none());
            assert!(!a.in_flight.contains(&Action::SignIn));
        });
        assert!(REFRESH_TOKEN.lock().unwrap().is_some());
        assert!(!BUSY.load(Ordering::Relaxed));
        finish_test();
    }

    #[test]
    fn stale_terminal_cannot_release_newer_busy_or_cloud_work() {
        let _guard = STATE_LOCK.lock().unwrap();
        install_agent("https://a.example.site");
        let accepted = with(Agent::advance_discovery).unwrap();
        assert!(apply(discovered(accepted, snapshot("A.SITE", "a"))));
        with(|a| assert!(a.settings.set_browser_session(true)));
        let stale = with(Agent::advance_discovery).unwrap();
        let newer = with(|a| {
            let stamp = a.advance_discovery().unwrap();
            a.started_busy(stamp.clone(), Action::CreateGrant);
            a.started(Action::SignOutIdp);
            a.cloud_sign_out = Some(stamp.clone());
            stamp
        });
        BUSY.store(true, Ordering::Relaxed);

        assert!(!apply(Event::Cancelled {
            stamp: stale.clone(),
            effects: WorkerEffects::default(),
        }));
        assert!(!apply(Event::CloudSignedOut { stamp: stale, asked: true }));
        with(|a| {
            assert_eq!(a.busy_operation.as_ref().map(|op| &op.stamp), Some(&newer));
            assert_eq!(a.cloud_sign_out.as_ref(), Some(&newer));
            assert!(a.in_flight.contains(&Action::CreateGrant));
            assert!(a.in_flight.contains(&Action::SignOutIdp));
            assert!(a.settings.browser_session());
        });
        assert!(BUSY.load(Ordering::Relaxed));
        finish_test();
    }

    #[test]
    fn broker_change_is_rejected_while_worker_owns_the_slot() {
        let _guard = STATE_LOCK.lock().unwrap();
        install_agent("https://a.example.site");
        let generation = with(|a| a.discovery_generation);
        BUSY.store(true, Ordering::Relaxed);

        super::super::commands::apply_settings(super::super::commands::SettingsChange {
            broker_url: Some("https://b.example.site"),
            ..super::super::commands::SettingsChange::default()
        });

        with(|a| {
            assert_eq!(a.settings.broker_url(), Some("https://a.example.site"));
            assert_eq!(a.discovery_generation, generation);
        });
        finish_test();
    }

    #[test]
    fn cloud_sign_out_serializes_generation_allocating_work_in_both_directions() {
        let _guard = STATE_LOCK.lock().unwrap();
        install_agent("https://a.example.site");
        let accepted = with(Agent::advance_discovery).unwrap();
        assert!(apply(discovered(accepted, snapshot("A.SITE", "a"))));
        with(|a| assert!(a.settings.set_browser_session(true)));
        let cloud = with(|a| {
            let stamp = a.advance_discovery().unwrap();
            a.cloud_sign_out = Some(stamp.clone());
            a.started(Action::SignOutIdp);
            stamp
        });
        let generation = with(|a| a.discovery_generation);

        discover_in_background();
        start_worker(Trigger::Startup);
        assert!(!create_grant());
        with(|a| {
            assert_eq!(a.discovery_generation, generation);
            assert_eq!(a.cloud_sign_out.as_ref(), Some(&cloud));
            assert!(a.startup_retry_at.is_some());
        });
        assert!(!BUSY.load(Ordering::Relaxed));

        with(|a| {
            a.cloud_sign_out = None;
            a.in_flight.retain(|action| *action != Action::SignOutIdp);
        });
        BUSY.store(true, Ordering::Relaxed);
        assert!(!begin_cloud_sign_out());
        assert_eq!(with(|a| a.discovery_generation), generation);
        finish_test();
    }

    #[test]
    fn background_grant_cleanup_does_not_present_a_result() {
        let _guard = STATE_LOCK.lock().unwrap();
        install_agent("https://new.example.site");
        let generation = with(Agent::started_grant_cleanup);
        GRANT_CLEANUP.store(true, Ordering::Relaxed);

        assert!(apply(Event::GrantGivenUp {
            generation,
            broker: Some("https://old.example.site".into()),
            revoked: true,
            saved: true,
            report: false,
        }));

        with(|a| {
            assert!(a.grant_cleanup.is_none());
            assert!(!a.in_flight.contains(&Action::GiveUpGrant));
        });
        assert!(!GRANT_CLEANUP.load(Ordering::Relaxed));
        finish_test();
    }

    #[test]
    fn dns_discovery_keeps_1_0_1_persisted_state() {
        let _guard = STATE_LOCK.lock().unwrap();
        let url = "https://kerbridge.example.site";
        let settings = crate::config::Settings::for_test(FileConfig {
            grant: Some(Grant {
                grant_id: "1a2b3c4d".into(),
                identity: "kb1|entra|subject".into(),
                principal: None,
                audience: "kerbridge://EXAMPLE.SITE".into(),
                sign_in_required_by: 1_785_000_000,
            }),
            browser_session: true,
            cache: crate::config::Cache {
                realm: "EXAMPLE.SITE".into(),
                ..crate::config::Cache::default()
            },
            ..FileConfig::default()
        });
        super::super::AGENT.with(|slot| *slot.borrow_mut() = Some(Agent::new(settings)));
        with(|a| {
            assert_eq!(a.kerberos.realm, "EXAMPLE.SITE");
            assert!(a.settings.grant().is_some());
            assert!(a.settings.browser_session());
        });

        assert!(apply(Event::BrokerDiscovered { url: url.into() }));
        with(|a| {
            assert_eq!(a.settings.broker_url(), Some(url));
            assert_eq!(a.kerberos.realm, "EXAMPLE.SITE");
            assert!(a.settings.grant().is_some());
            assert!(a.settings.browser_session());
        });
        finish_test();
    }

    #[test]
    fn rejected_first_leg_never_starts_oidc() {
        let oidc_started = Cell::new(false);
        let result: Result<Option<()>, ()> = after_broker_document(
            "stale discovery document",
            |_| false,
            |_| {
                oidc_started.set(true);
                Ok(())
            },
        );

        assert_eq!(result, Ok(None));
        assert!(!oidc_started.get());
    }

    // ---- TGT loss --------------------------------------------------------------

    /// Counts notifications, so a test can say none was raised.
    struct TestHost;

    static NOTIFIED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    impl super::super::Host for TestHost {
        fn wake(&self) {}
        fn notify(&self, _: &str, _: &str, _: Severity) {
            NOTIFIED.fetch_add(1, Ordering::Relaxed);
        }
        fn finished(&self, _: Action, _: Outcome) {}
        fn elevating(&self, _: Action) {}
        fn primary_action_label(&self) -> String {
            String::new()
        }
        fn open_path(&self, _: &str) {}
        fn native_token(&self, _: &crate::discovery::OidcConfig) -> NativeToken {
            NativeToken::Unavailable
        }
    }

    /// A live ticket whose TGT is absent, one recovery attempt already failed on
    /// transport, and the next one running in the busy slot.
    fn recovering() -> DiscoveryStamp {
        install_agent("https://a.example.site");
        let _ = super::super::HOST.set(&TestHost);
        let accepted = with(Agent::advance_discovery).unwrap();
        assert!(apply(discovered(accepted, snapshot("A.SITE", "a"))));
        let now = time::now();
        let stamp = with(|a| {
            a.phase = Phase::Connected;
            a.principal = "riku@A.SITE".into();
            a.start = now - 600;
            a.end = now + 36_000;
            a.refresh_at = Some(now + 17_000);
            a.loss = TgtLoss { streak: 2, absent: true, ..TgtLoss::default() };
            a.silent_failed = true;
            a.record(Some(Fault::Network), "broker down".into());
            let stamp = a.advance_discovery().unwrap();
            a.started_busy(stamp.clone(), Action::ReinjectTicket);
            stamp
        });
        BUSY.store(true, Ordering::Relaxed);
        stamp
    }

    fn landed(stamp: DiscoveryStamp) -> Event {
        let now = time::now();
        Event::SignedIn {
            stamp,
            injected: Injected {
                principal: "riku@A.SITE".into(),
                start: now,
                end: now + 36_000,
                renew_till: now + 36_000,
            },
            realm: "A.SITE".into(),
            effects: WorkerEffects::default(),
            via_grant: false,
        }
    }

    fn failed(stamp: DiscoveryStamp, fault: Option<Fault>) -> Event {
        Event::SignInFailed {
            stamp,
            effects: WorkerEffects::default(),
            fault,
            message: "no".into(),
            quiet: false,
        }
    }

    #[test]
    fn a_replaced_tgt_lands_silently_and_keeps_the_streak() {
        let _guard = STATE_LOCK.lock().unwrap();
        let stamp = recovering();
        let notified = NOTIFIED.load(Ordering::Relaxed);

        assert!(apply(landed(stamp)));

        assert_eq!(NOTIFIED.load(Ordering::Relaxed), notified, "a recovery says nothing");
        with(|a| {
            assert!(!a.loss.absent);
            assert_eq!(a.loss.streak, 2, "injection success alone resets nothing");
            assert!(a.fault.is_none());
            assert!(a.phase == Phase::Connected);
        });
        assert!(!BUSY.load(Ordering::Relaxed));
        finish_test();
    }

    #[test]
    fn a_failed_recovery_follows_the_episode_backoff() {
        let _guard = STATE_LOCK.lock().unwrap();
        let stamp = recovering();
        let refresh_at = with(|a| a.refresh_at);

        assert!(apply(Event::SignInFailed {
            stamp,
            effects: WorkerEffects::default(),
            fault: Some(Fault::Network),
            message: "broker down".into(),
            quiet: false,
        }));

        with(|a| {
            assert!(a.phase == Phase::Connected);
            assert_eq!(a.refresh_at, refresh_at, "the midpoint schedule is untouched");
            assert_eq!(a.loss.streak, 3);
            let wait = a.loss.retry_at.unwrap() - time::now();
            assert!((107..=120).contains(&wait), "{wait}");
        });
        finish_test();
    }

    #[test]
    fn only_a_repair_that_worked_ends_the_loss_episode() {
        let _guard = STATE_LOCK.lock().unwrap();
        let cases = [
            (
                Action::RestartWorkstation,
                Outcome::Done { message: "ok".into(), detail: None },
                true,
            ),
            (Action::RestartWorkstation, Outcome::Declined, false),
            (Action::Reenroll, Outcome::Done { message: "ok".into(), detail: None }, false),
        ];
        for (action, outcome, ends) in cases {
            recovering();
            let before = with(|a| a.loss);
            assert!(apply(Event::ElevatedFinished { action, outcome, recheck_enrollment: false }));
            with(|a| {
                if ends {
                    assert_eq!(a.loss, TgtLoss::default());
                    assert_eq!(a.loss_check_at, 0, "the TGT is looked for at once");
                } else {
                    assert_eq!(a.loss, before, "{action:?}");
                }
            });
            finish_test();
        }
    }

    /// Once the escalation has spoken about the episode, its end is news.
    #[test]
    fn a_recovery_after_the_escalation_sends_one_all_clear() {
        let _guard = STATE_LOCK.lock().unwrap();
        let stamp = recovering();
        let due = with(|a| {
            let near = a.end - 60;
            super::super::tick_at(a, near, true, &|_| Ok(false))
        });
        assert!(due.notice.is_some(), "the escalation fired");
        assert!(with(|a| a.escalated));
        let notified = NOTIFIED.load(Ordering::Relaxed);

        assert!(apply(landed(stamp)));

        assert_eq!(NOTIFIED.load(Ordering::Relaxed), notified + 1);
        with(|a| assert!(!a.escalated && !a.loss.absent));
        finish_test();
    }

    #[test]
    fn a_refusal_or_no_credential_suspends_recovery_quietly() {
        let _guard = STATE_LOCK.lock().unwrap();
        for fault in [Some(Fault::Refused), None] {
            let stamp = recovering();
            let (refresh_at, notified) = (with(|a| a.refresh_at), NOTIFIED.load(Ordering::Relaxed));

            assert!(apply(failed(stamp, fault)));

            assert_eq!(NOTIFIED.load(Ordering::Relaxed), notified, "{fault:?}");
            with(|a| {
                assert!(a.loss.suspended && a.loss.absent, "{fault:?}");
                assert!(a.loss.retry_at.is_none(), "{fault:?}");
                assert_eq!(a.refresh_at, refresh_at, "{fault:?}: the midpoint continues");
                assert!(a.phase == Phase::Connected, "{fault:?}");
            });
            finish_test();
        }
    }

    /// *Renew now* is not gated by a suspension: it takes the busy slot and
    /// runs, and a transient failure of it leaves the suspension standing.
    #[test]
    fn renew_now_runs_while_recovery_is_suspended() {
        let _guard = STATE_LOCK.lock().unwrap();
        recovering();
        with(|a| {
            // Plaintext: the HTTPS-only agent refuses it before any socket or
            // proxy is used.
            a.settings.set_broker_url("http://127.0.0.1:1");
            a.busy_operation = None;
            a.in_flight.clear();
            a.loss.suspended = true;
            a.loss.retry_at = None;
        });
        BUSY.store(false, Ordering::Relaxed);

        super::super::renew_now();
        assert!(BUSY.load(Ordering::Relaxed));
        assert!(with(|a| a.in_flight.contains(&Action::ReinjectTicket)));

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while BUSY.load(Ordering::Relaxed) {
            assert!(std::time::Instant::now() < deadline, "the worker never reported");
            drain();
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        with(|a| {
            assert_eq!(a.fault, Some(Fault::Network));
            assert!(a.loss.suspended && a.loss.retry_at.is_none());
        });
        finish_test();
    }

    #[test]
    fn a_failed_re_injection_after_end_time_says_so_once() {
        let _guard = STATE_LOCK.lock().unwrap();
        let stamp = recovering();
        let now = time::now();
        with(|a| {
            a.phase = Phase::Expired;
            a.end = now - 60;
            a.refresh_at = Some(now + MIN_REFRESH_DELAY);
            a.loss = TgtLoss::default();
        });
        let notified = NOTIFIED.load(Ordering::Relaxed);

        assert!(apply(failed(stamp, Some(Fault::Network))));

        assert_eq!(NOTIFIED.load(Ordering::Relaxed), notified + 1);
        with(|a| {
            assert!(a.phase == Phase::Error);
            assert!(a.refresh_at.is_none(), "nothing further comes round");
        });
        finish_test();
    }
}
