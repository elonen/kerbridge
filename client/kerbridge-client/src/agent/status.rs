//! What the host is told: the snapshot a surface draws itself from.
//!
//! [`status`] is a pure function of the agent's state, called on the UI thread
//! whenever something might have changed. It carries no view of its own -- five
//! independent values and the clocks behind them, which each platform arranges
//! into its own surface (`client/DESIGN.md` @ the status model).

use std::sync::atomic::Ordering;

use crate::describe::{Action, Blocker, Condition, Description, Facts, Supply, describe};
use crate::time;

use super::{Agent, BROWSER_LEG, FLAKY_QUIET_SECS, LATE_ELAPSED, REFRESH_TOKEN, host_of, with};

/// An immutable snapshot for rendering. The UI holds one of these for the
/// duration of a repaint and never reads agent state directly.
///
/// Every judgment in it is made here, once. A surface that re-derived any of
/// these would be a second place the lifecycle is settled.
pub struct Status {
    /// The headline, the icon, and the severity of the explanation block.
    pub condition: Condition,
    /// What is missing right now. Unordered: ordering is not a fact.
    pub blockers: Vec<Blocker>,
    /// What may be offered at all. The surface decides what is primary.
    pub actions: Vec<Action>,
    /// What is running, in the same vocabulary -- so a control is disabled
    /// rather than hidden. An action can be in both lists.
    pub in_flight: Vec<Action>,
    /// Which silent path stands behind the next renewal.
    pub supply: Supply,
    /// A ticket this machine holds could actually be spent: a realm is known and
    /// the OS is registered for it. The details drawer hangs off this -- every
    /// row of it would otherwise describe a ticket nothing can use.
    pub usable: bool,
    pub realm: String,
    /// Which source of the realm this machine authenticates against. Empty until
    /// a discovery lands this session, and on a broker that names no source --
    /// a row nothing draws rather than a row drawn empty.
    pub source: String,
    /// Broker host, for the "can't reach …" message. Empty when unconfigured.
    pub broker_host: String,
    /// Where the menu's *Help* goes, when the deployment publishes a page.
    /// Empty otherwise, which the surface reads as "use your own".
    pub help_url: String,
    /// Fills `{idp}` in every label that names the IdP.
    pub idp_name: String,
    pub principal: String,
    /// The live injected ticket's clock, and `None` at or after its End Time.
    /// Historical clocks stay in the agent and never use current-access copy.
    pub ticket: Option<TicketClock>,
    /// The soonest the agent will try again, in Unix seconds. A floor, not a
    /// ceiling.
    pub next_attempt_at_earliest: Option<i64>,
    /// Detail, already user-facing: a failure's sentence, or a note after a
    /// deliberate act.
    pub message: String,
    /// Something is *wrong*, as opposed to something merely being said. A
    /// sign-off note sets [`Self::message`] with nothing behind it, and must
    /// draw neither fault ink nor an offer of the log.
    pub fault: bool,
    /// This machine holds a device grant, whatever its deadline says.
    pub holds_grant: bool,
    /// That grant's browser-sign-in deadline in Unix seconds. One clock, exposed
    /// once; when it is worth warning about is the surface's call -- see
    /// [`super::GRANT_DUE_SOON_SECS`].
    pub grant_expiry: Option<i64>,
    /// Whom this machine authorizes itself for, when it is delegated. Non-empty
    /// is the whole of "delegated": it is the identity line's subject, and a
    /// browser sign-in here proves the engineer rather than this machine.
    pub grant_target: String,
    /// A grant was just created and nothing has happened since. Promotes signing
    /// out of the cloud to the primary offer, exactly once: the one moment the
    /// agent knows it put a session in a browser and knows the machine no longer
    /// needs one.
    pub just_authorized: bool,
}

/// Everything time-dependent about the ticket this machine holds, worked out
/// once in [`status`] against one reading of the clock.
///
/// No methods, deliberately: a surface able to recompute any of this is a second
/// place the lifecycle is settled, and two rows of one drawer would disagree
/// about which second it is.
pub struct TicketClock {
    /// End Time, in Unix seconds.
    pub end: i64,
    /// Seconds left. Strictly positive while this clock is exposed.
    pub remaining: i64,
    /// How much of the ticket's lifetime is still to run, 0.0–1.0.
    pub fraction: f32,
    /// The KDC granted a renewable ticket -- `renew_till` beyond `end`.
    pub renewable: bool,
}

pub fn status() -> Status {
    with(|a| status_at(a, time::now()))
}

/// True when a silent exchange has something to run on: the [`Supply`] the
/// surface shows.
pub(super) fn silent_supply(a: &Agent, now: i64) -> bool {
    described_at(a, now).supply != Supply::None
}

fn described_at(a: &Agent, now: i64) -> Description {
    let grant_expiry = a.settings.grant().map(|g| g.sign_in_required_by);
    let holds_live_ticket = a.holds_live_ticket_at(now);
    describe(&Facts {
        broker: a.settings.broker_url().is_some(),
        realm_known: !a.kerberos.realm.is_empty(),
        enrolled: !a.enroll_state.needs_action(),
        ticket: holds_live_ticket,
        ticket_late: a.end != 0
            && (now - a.start) as f32 >= (a.end - a.start).max(1) as f32 * LATE_ELAPSED,
        expected: a.expected(),
        delegated: a.settings.grant_for().is_some(),
        grant_valid: grant_expiry.is_some_and(|t| t > now),
        refresh_token: REFRESH_TOKEN.lock().unwrap().is_some(),
        cloud_session: a.settings.browser_session(),
        windows_sign_in: a.settings.windows_sign_in(),
        grants_enabled: a.device_grant.enabled() && crate::device::AVAILABLE,
        ntlm_recovery: a.settings.ntlm_fallback_recovery(),
        tgt_absent: a.loss.absent && holds_live_ticket,
        fault: a.fault,
        flaky_elapsed: a.first_failure_at.is_some_and(|t| now - t > FLAKY_QUIET_SECS),
        enrollment_platform: cfg!(windows),
        browser_leg: BROWSER_LEG.load(Ordering::Relaxed),
    })
}

pub(super) fn status_at(a: &Agent, now: i64) -> Status {
    let grant_expiry = a.settings.grant().map(|g| g.sign_in_required_by);
    let holds_live_ticket = a.holds_live_ticket_at(now);
    let described = described_at(a, now);
    Status {
        condition: described.condition,
        blockers: described.blockers,
        actions: described.actions,
        in_flight: a.in_flight.clone(),
        supply: described.supply,
        usable: described.usable,
        realm: a.kerberos.realm.clone(),
        source: a.source.clone(),
        broker_host: a.settings.broker_url().map(host_of).unwrap_or_default(),
        help_url: a.help_url.clone().unwrap_or_default(),
        idp_name: a.idp_name.clone(),
        principal: a.principal.clone(),
        ticket: holds_live_ticket.then(|| {
            let remaining = a.end - now;
            let lifetime = (a.end - a.start).max(1);
            TicketClock {
                end: a.end,
                remaining,
                fraction: (remaining as f32 / lifetime as f32).clamp(0.0, 1.0),
                renewable: a.renew_till > a.end,
            }
        }),
        next_attempt_at_earliest: soonest([
            a.refresh_at,
            a.startup_retry_at,
            a.probe_at,
            a.loss.retry_at,
        ]),
        message: a.message.clone(),
        fault: a.fault.is_some(),
        holds_grant: a.settings.grant().is_some(),
        grant_expiry,
        grant_target: a.settings.grant_for().unwrap_or_default().to_string(),
        just_authorized: a.just_authorized,
    }
}

/// The soonest of the schedule clocks, any of which may not be running.
///
/// The re-probe counts: it is the only one a machine with no ticket and nothing
/// to be silent with ever has, and without it the drawer omits the row entirely.
fn soonest(clocks: [Option<i64>; 4]) -> Option<i64> {
    clocks.into_iter().flatten().min()
}

#[cfg(test)]
mod tests {
    use super::super::Phase;
    use super::*;
    use crate::config::{Cache, FileConfig, Settings};
    use crate::describe::{Action, Condition};
    use crate::enroll;
    use crate::present;

    const START: i64 = 1_000;
    const END: i64 = 2_000;

    fn connected_agent() -> Agent {
        let settings = Settings::for_test(FileConfig {
            broker_url: Some("https://kerbridge.example.site".into()),
            expected_working_as: Some("EXAMPLE.SITE|".into()),
            cache: Cache { realm: "EXAMPLE.SITE".into(), ..Cache::default() },
            ..FileConfig::default()
        });
        let mut agent = Agent::new(settings);
        agent.enroll_state = enroll::State::Enrolled;
        agent.phase = Phase::Connected;
        agent.principal = "riku@EXAMPLE.SITE".into();
        agent.start = START;
        agent.end = END;
        agent.renew_till = END + 1_000;
        agent
    }

    #[test]
    fn ticket_clock_exists_only_before_end_time() {
        let agent = connected_agent();

        let before = status_at(&agent, END - 1);
        assert_eq!(before.ticket.as_ref().map(|ticket| ticket.remaining), Some(1));
        assert!(present::holds_access(&before));

        for now in [END, END + 1] {
            let stopped = status_at(&agent, now);
            assert_eq!(stopped.condition, Condition::Stopped, "now={now}");
            assert!(stopped.ticket.is_none(), "now={now}");
            assert!(!present::holds_access(&stopped), "now={now}");
            assert!(present::identity(&stopped).is_none(), "now={now}");
            assert_eq!(stopped.principal, "riku@EXAMPLE.SITE", "now={now}");
            assert!(stopped.actions.contains(&Action::SignIn), "now={now}");
            assert!(!stopped.actions.contains(&Action::DropKrbTicket), "now={now}");
        }
    }

    #[test]
    fn newly_landed_exchange_replaces_the_expired_clock() {
        let mut agent = connected_agent();
        agent.phase = Phase::Expired;
        assert!(status_at(&agent, END + 1).ticket.is_none());

        agent.phase = Phase::Connected;
        agent.principal = "maija@EXAMPLE.SITE".into();
        agent.start = 3_000;
        agent.end = 4_000;
        agent.renew_till = 5_000;

        let landed = status_at(&agent, 3_100);
        let ticket = landed.ticket.as_ref().expect("the new exchange is live");
        assert_eq!(landed.condition, Condition::Working);
        assert_eq!(landed.principal, "maija@EXAMPLE.SITE");
        assert!(present::holds_access(&landed));
        assert!(present::identity(&landed).is_some());
        assert_eq!(ticket.end, 4_000);
        assert_eq!(ticket.remaining, 900);
        assert_eq!(ticket.fraction, 0.9);
        assert!(ticket.renewable);
    }
}
