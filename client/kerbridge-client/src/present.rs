//! What a surface *says* about the state, as words.
//!
//! [`crate::describe`] decides what the machine's state means; this decides the
//! sentence it means it in. In the core rather than in an agent crate for the
//! same reason [`crate::strings`] is: two agents wording one refusal differently
//! is two translation sets to keep in step and one of them stale.
//!
//! What is **not** here is anything a surface decides for itself -- which offer
//! is primary, which color carries the severity, how much of it fits. Those
//! differ per platform by construction (`client/DESIGN.md` @ what the surface
//! decides), and each agent owns its own.

use crate::agent::Status;
use crate::describe::{Action, Blocker, Condition};
use crate::strings::{fill, tr};
use crate::time;

/// The condition's headline, and the one case where `NotStarted` takes one.
///
/// A delegated box stood down with *Sign off* holds a valid grant and no ticket,
/// so without this the surface would render *Working as svc-builder* as its only
/// line -- asserting work that is not happening.
pub fn headline(st: &Status) -> Option<&'static str> {
    let s = tr();
    Some(match st.condition {
        Condition::Working => s.cond_working,
        Condition::Flaky => s.cond_flaky,
        Condition::WillStop => s.cond_will_stop,
        Condition::Stopped => s.cond_stopped,
        Condition::NotStarted if identity(st).is_some() => s.cond_off,
        Condition::NotStarted => return None,
    })
}

/// Who this machine is, in one line and with no state table.
///
/// Delegated always names the target: it is the only identity available before a
/// ticket exists, and on a delegated machine `principal` is the target's anyway.
/// Otherwise the principal, while there is a ticket or a grant to make it true --
/// a `Stopped` laptop showing *Signed in as…* would assert a session that the
/// lapsed ticket is the evidence against.
pub fn identity(st: &Status) -> Option<String> {
    if !st.grant_target.is_empty() {
        return Some(fill(tr().id_working_as, &[("account", &st.grant_target)]));
    }
    if st.principal.is_empty() || !(holds_access(st) || st.holds_grant) {
        return None;
    }
    Some(fill(tr().id_signed_in_as, &[("account", &st.principal)]))
}

/// **T** as a surface needs it: a ticket that is live *and* one the OS could
/// spend.
pub fn holds_access(st: &Status) -> bool {
    st.usable && st.ticket.as_ref().is_some_and(|t| t.remaining > 0)
}

pub fn blocker_line(b: Blocker, st: &Status) -> String {
    let s = tr();
    match b {
        Blocker::NoBrokerUrl => s.blk_no_broker_url.into(),
        Blocker::NetworkError => fill(s.blk_network_error, &[("broker", &st.broker_host)]),
        Blocker::RealmUnknown => fill(s.blk_realm_unknown, &[("broker", &st.broker_host)]),
        Blocker::RealmNotRegistered => fill(s.blk_realm_not_registered, &[("realm", &st.realm)]),
        Blocker::NoSupply => s.blk_no_supply.into(),
        // `grant_target` is never empty here: the blocker is raised only on a
        // machine that names an account to work as.
        Blocker::NoGrant => fill(s.blk_no_grant, &[("account", &st.grant_target)]),
        Blocker::GrantRefused => s.blk_grant_refused.into(),
        Blocker::Refused => s.blk_refused.into(),
        Blocker::NtlmFallback => s.blk_ntlm_fallback.into(),
    }
}

/// One label per action, and the two that are chosen by state rather than by
/// call site.
pub fn action_label(act: Action, st: &Status) -> String {
    let s = tr();
    match act {
        // One mechanism, two consequences: with no ticket the sign-in loop *gets*
        // access, with one it *prolongs* it.
        Action::SignIn if holds_access(st) => s.act_sign_in_extend.into(),
        Action::SignIn => s.act_sign_in.into(),
        Action::CreateGrant if st.holds_grant => s.act_create_grant_again.into(),
        Action::CreateGrant => s.act_create_grant.into(),
        Action::ReinjectTicket => s.act_reinject.into(),
        Action::Cancel => s.act_cancel.into(),
        Action::DropKrbTicket => s.act_drop_ticket.into(),
        Action::SignOutIdp => fill(s.act_sign_out_idp, &[("idp", &st.idp_name)]),
        Action::GiveUpGrant => s.act_give_up_grant.into(),
        Action::Enroll => s.act_enroll.into(),
        Action::Reenroll => s.act_reenroll.into(),
        Action::Unenroll => fill(s.act_unenroll, &[("realm", &st.realm)]),
        Action::RestartWorkstation => s.act_restart_workstation.into(),
        Action::OpenSettings => s.act_open_settings.into(),
    }
}

/// Whole days until `deadline`, rounded up and never below one. The strings say
/// "expires in N days", which has to stay true -- rounding a deadline a few hours
/// away down to zero would read as no deadline at all.
pub fn days_until(deadline: i64) -> i64 {
    ((deadline - time::now() + 86_399) / 86_400).max(1)
}
