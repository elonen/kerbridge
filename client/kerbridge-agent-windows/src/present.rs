//! `Status` in, this surface's ordering and color roles out. No window, no Win32
//! drawing -- but everything here is the flyout's own judgment.
//!
//! The words are not: `kerbridge_client::present` holds the headline, the
//! identity line, the blocker sentences and the action labels, because they are
//! the product's copy and the Mac renders the same ones. What is left here is
//! what a 340 dip popup with two buttons decides for itself -- [`ranked`] is the
//! only ordering in this product, and [`infotip`] is bounded by `szTip` rather
//! than by anything a menu bar cares about.

use kerbridge_client::agent::{self, Status};
use kerbridge_client::describe::{Action, Blocker, Condition};
use kerbridge_client::present::{blocker_line, headline};

use crate::ui::{
    ROLE_DANGER, ROLE_OK, ROLE_RULE_DANGER, ROLE_RULE_SUB, ROLE_RULE_WARN, ROLE_SUB, ROLE_WARN,
};

/// `szTip` is 128 UTF-16 units *including* the NUL.
const TIP_MAX: usize = 127;

/// The surface's own ordering, and the only one in the product.
///
/// `actions` is flat by construction, so this is where "what is primary" is
/// decided -- with four gates that keep an offer off the front page without
/// taking it out of the model. `ReinjectTicket` outranks `SignIn` deliberately:
/// wherever both are ranked the cheap one is believed to work while the expensive
/// one walks the whole sign-in loop to the same ticket.
pub(crate) fn ranked(st: &Status) -> Vec<Action> {
    const ORDER: [Action; 8] = [
        Action::OpenSettings,
        Action::SignOutIdp,
        Action::Enroll,
        Action::RestartWorkstation,
        Action::CreateGrant,
        Action::ReinjectTicket,
        Action::SignIn,
        Action::DropKrbTicket,
    ];
    let due_soon = st
        .grant_expiry
        .is_some_and(|t| t - kerbridge_client::time::now() <= agent::GRANT_DUE_SOON_SECS);
    ORDER
        .into_iter()
        .filter(|act| st.actions.contains(act))
        .filter(|act| match act {
            // The menu carries the hunch path; the front page offers it only
            // where the agent has diagnosed one.
            Action::RestartWorkstation => st.blockers.contains(&Blocker::NtlmFallback),
            Action::CreateGrant => (!st.grant_target.is_empty() && !st.holds_grant) || due_soon,
            Action::SignIn => st.condition != Condition::Working,
            Action::SignOutIdp => st.just_authorized,
            _ => true,
        })
        .collect()
}

/// The infotip: the app, the headline, then blocker lines one at a time while the
/// whole stays inside `szTip`. Stops cleanly rather than truncating mid-word --
/// the flyout holds whatever did not fit, which is where a user looks anyway.
pub(crate) fn infotip(status: &Status) -> String {
    let mut tip = kerbridge_client::strings::tr().app_name.to_string();
    if let Some(headline) = headline(status) {
        tip.push_str(" — ");
        tip.push_str(headline);
    }
    for line in status.blockers.iter().map(|b| blocker_line(*b, status)) {
        let candidate = format!("{tip}\n{line}");
        if candidate.chars().count() > TIP_MAX {
            break;
        }
        tip = candidate;
    }
    tip
}

pub(crate) fn condition_role(c: Condition) -> isize {
    match c {
        Condition::Working => ROLE_OK,
        Condition::Flaky | Condition::WillStop => ROLE_WARN,
        Condition::Stopped => ROLE_DANGER,
        Condition::NotStarted => ROLE_SUB,
    }
}

/// The explanation rule carries the severity, so the lines inside it do not.
/// Danger once access has stopped, neutral on a machine that has never worked,
/// warn otherwise -- and neutral for a message with no fault behind it, so a
/// deliberate sign-off is not dressed as a breakage.
pub(crate) fn rule_role(st: &Status) -> isize {
    match st.condition {
        Condition::Stopped => ROLE_RULE_DANGER,
        Condition::NotStarted => ROLE_RULE_SUB,
        _ if !st.fault && st.blockers.iter().all(|b| *b == Blocker::NoSupply) => ROLE_RULE_SUB,
        _ => ROLE_RULE_WARN,
    }
}
