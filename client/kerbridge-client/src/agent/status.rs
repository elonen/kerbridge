//! What the host is told: the snapshot a surface draws itself from.
//!
//! [`status`] is a pure function of the agent's state, called on the UI thread
//! whenever something might have changed. It carries no view of its own -- five
//! independent values and the clocks behind them, which each platform arranges
//! into its own surface (`client/DESIGN.md` @ the status model).

use std::sync::atomic::Ordering;

use crate::describe::{Action, Blocker, Condition, Facts, Supply, describe};
use crate::time;

use super::{
    BROWSER_LEG, FLAKY_QUIET_SECS, LATE_ELAPSED, NtlmFallback, REFRESH_TOKEN, host_of, with,
};

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
    /// The injected ticket's clock, and `None` when this machine holds no
    /// ticket at all -- which is not the same as holding a lapsed one.
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
    /// Seconds left, clamped at 0. A lapsed ticket is `Some(0)`, not `None`.
    pub remaining: i64,
    /// How much of the ticket's lifetime is still to run, 0.0–1.0.
    pub fraction: f32,
    /// The KDC granted a renewable ticket -- `renew_till` beyond `end`.
    pub renewable: bool,
}

pub fn status() -> Status {
    with(|a| {
        let now = time::now();
        let grant_expiry = a.settings.grant().map(|g| g.sign_in_required_by);
        let described = describe(&Facts {
            broker: a.settings.broker_url().is_some(),
            realm_known: !a.kerberos.realm.is_empty(),
            enrolled: !a.enroll_state.needs_action(),
            ticket: a.holds_live_ticket(),
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
            ntlm_confirmed: a.fallback == NtlmFallback::Confirmed,
            fault: a.fault,
            flaky_elapsed: a.first_failure_at.is_some_and(|t| now - t > FLAKY_QUIET_SECS),
            enrollment_platform: cfg!(windows),
            browser_leg: BROWSER_LEG.load(Ordering::Relaxed),
        });
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
            ticket: (a.end != 0).then(|| {
                let remaining = (a.end - now).max(0);
                let lifetime = (a.end - a.start).max(1);
                TicketClock {
                    end: a.end,
                    remaining,
                    fraction: (remaining as f32 / lifetime as f32).clamp(0.0, 1.0),
                    renewable: a.renew_till > a.end,
                }
            }),
            next_attempt_at_earliest: soonest([a.refresh_at, a.startup_retry_at, a.probe_at]),
            message: a.message.clone(),
            fault: a.fault.is_some(),
            holds_grant: a.settings.grant().is_some(),
            grant_expiry,
            grant_target: a.settings.grant_for().unwrap_or_default().to_string(),
            just_authorized: a.just_authorized,
        }
    })
}

/// The soonest of the schedule clocks, any of which may not be running.
///
/// The re-probe counts: it is the only one a machine with no ticket and nothing
/// to be silent with ever has, and without it the drawer omits the row entirely.
fn soonest(clocks: [Option<i64>; 3]) -> Option<i64> {
    clocks.into_iter().flatten().min()
}
