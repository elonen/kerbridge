//! Turns a failed lookup or issuance into an HTTP status. Also sends an operator
//! notification for the failures that only a human can repair.
//!
//! The raises and the clear are one policy, thus one module. [`ROLE_PROBLEMS`]
//! is the table that both ends read. A raise that the clear does not know about
//! would report for as long as the deployment lives.

use axum::http::StatusCode;
use kerbridge_core::ExternalIdentity;
use kerbridge_notify::{Event, Severity};

use crate::directory::{Denied, LookupError};
use crate::http::Failure;
use crate::issuer::IssuerError;
use crate::state::AppState;

/// List of every role-group problem that this service can raise. Cleared as a set: a
/// realm can go from no marked group to two and never be healthy in between, so
/// a clear of only the last raise would leave the other one open for as long as
/// the deployment lives.
///
/// `<role>-group-misconfigured` is absent on purpose. The broker finds a role
/// group by its marker and never reads the operator's configuration, so it
/// cannot see the two disagree -- only sync can, and `Problems::resolve` is
/// keyed per component, so a clear here could not reach sync's record anyway.
pub const ROLE_PROBLEMS: [&str; 4] = [
    "admission-group-missing",
    "admission-group-ambiguous",
    "grant-group-missing",
    "grant-group-ambiguous",
];

/// Clear every problem that a completed lookup disproves. Written once, thus
/// the ticket path and the device paths cannot drift apart on it.
///
/// A lookup that got all the way through proves that the directory answered and
/// that the role groups are readable and unambiguous. This is the only evidence
/// that the broker ever sees that one of those cleared: the broker is
/// request-driven and cannot re-evaluate on a schedule the way sync does. It
/// costs nothing when no problem is open, which is every request on a healthy
/// deployment.
pub async fn resolved_cleanly(state: &AppState, identity: &ExternalIdentity) {
    for problem in ROLE_PROBLEMS {
        state.notifier.resolve(problem).await;
    }
    state.notifier.resolve("directory-unavailable").await;
    state.notifier.resolve_subject("identity-ambiguous", &identity.label().to_string()).await;
}

/// Which of [`ROLE_PROBLEMS`] a lookup failure is: which role the marker names,
/// and which way it is wrong.
fn role_slug(marker: &str, fault: &str) -> &'static str {
    let role = if marker == kerbridge_core::state::ROLE_ADMISSION {
        "admission-group"
    } else {
        "grant-group"
    };
    ROLE_PROBLEMS
        .into_iter()
        .find(|p| p.starts_with(role) && p.ends_with(fault))
        .expect("every role and fault pair is in the table")
}

async fn role_group_failure(state: &AppState, problem: &'static str, why: String) -> Failure {
    state
        .notifier
        .send(
            Event::new(problem, Severity::Error, why.clone())
                // The reason is the subject. Two groups with the marker and
                // three with it are one problem, but a different reason under
                // the same slug must not sit behind the first one's repeat
                // interval.
                .subject(why.clone()),
        )
        .await;
    Failure::new(StatusCode::BAD_GATEWAY, "directory unavailable", why)
}

/// The status for a refused directory write. The device cap is the one refusal
/// that a user can act on, thus it keeps a status of its own.
pub fn grant_write_failure(error: IssuerError) -> Failure {
    match error {
        IssuerError::Refused(why) if why.contains("cap") => {
            Failure::new(StatusCode::CONFLICT, "too many devices", why)
        }
        IssuerError::Refused(why) => {
            Failure::new(StatusCode::INTERNAL_SERVER_ERROR, "directory write failed", why)
        }
        IssuerError::Unavailable(e) => {
            Failure::new(StatusCode::SERVICE_UNAVAILABLE, "issuer unavailable", format!("{e:#}"))
        }
    }
}

/// The status for a failed issuance, plus a notification when the failure is a
/// fault.
///
/// Only one of the two is a fault. `issuerd` re-checks what the broker checked,
/// independently, thus a *refusal* means the two disagree about an account that
/// already passed admission. A divergence of that shape in `sam.rs` can let
/// accounts synchronize cleanly and never obtain a ticket. An issuer that this
/// process cannot reach is the realm container down, which its own healthcheck
/// reports and which recovers by itself.
pub async fn issuer_failure(state: &AppState, account: &str, error: IssuerError) -> Failure {
    match error {
        IssuerError::Refused(why) => {
            state
                .notifier
                .send(
                    Event::new(
                        "issuer-refused",
                        Severity::Error,
                        format!("the issuer refused an account the broker admitted: {account}"),
                    )
                    // Per account: a second account that diverges is a second
                    // problem, and must not sit behind the first one's repeat
                    // interval.
                    .subject(account)
                    .detail(why.clone()),
                )
                .await;
            Failure::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ticket issuance failed",
                format!("issuer refused {account}: {why}"),
            )
        }
        IssuerError::Unavailable(e) => {
            Failure::new(StatusCode::SERVICE_UNAVAILABLE, "issuer unavailable", format!("{e:#}"))
        }
    }
}

/// The status for a failed directory lookup, plus the cases that an operator
/// must hear about out of band.
///
/// A missing or ambiguous admission group answers the client exactly as an
/// ordinary directory failure does: the client learns nothing new, because the
/// client can do nothing. But it also freezes every login in the deployment
/// until a human repairs it, thus it leaves by the notification channel too.
pub async fn directory_failure(
    state: &AppState,
    identity: &ExternalIdentity,
    error: LookupError,
) -> Failure {
    match error {
        // Each denial keeps its own reason, unlike `http::unauthorized`, which
        // says only "invalid identity proof" however it failed. The difference
        // is who asks. Anyone who holds any string reaches a 401; only someone
        // whose token already verified reaches this, so the reason goes to
        // someone that the deployment already admitted. It is also the whole
        // self-service story: the tray shows "your account is not admitted to
        // the realm" and the user acts on it, where a flat 403 is a helpdesk
        // ticket.
        //
        // On a request that named a *target*, the reason is about that account
        // and not the caller's own. An admitted caller can thus learn whether a
        // login name exists, is enabled, and is in the grant group. Accepted:
        // all three are one authenticated LDAP read away already, and the
        // caller resolves first, so someone who is not admitted at all still
        // learns nothing.
        LookupError::Denied(denied) => {
            // One denial is not a policy answer at all. Two objects that claim
            // one identity is a directory-integrity fault. Only an operator can
            // clear it, and it fails this user's login every time until they
            // do, where "not provisioned", "disabled" and "not admitted" all
            // work as designed. The client hears the same thing either way.
            if let Denied::Ambiguous(n) = denied {
                state
                    .notifier
                    .send(
                        Event::new(
                            "identity-ambiguous",
                            Severity::Error,
                            format!("{n} directory objects carry one external identity"),
                        )
                        .subject(identity.label().to_string())
                        .detail(format!(
                            "{}; sync writes one marker per account, so this is a manual edit \
                             or a restored object",
                            identity.label()
                        )),
                    )
                    .await;
            }
            Failure::new(
                StatusCode::FORBIDDEN,
                match denied {
                    Denied::NotFound | Denied::Ambiguous(_) => "identity is not provisioned",
                    Denied::Disabled => "account is disabled",
                    Denied::NotAdmitted => "account is not admitted to the realm",
                    // 403 like the others: the identity is good and a new
                    // sign-in does not help. A dead grant is a 401.
                    Denied::NotGranted => "account may not authorize a device",
                    Denied::NotDelegate => "you may not authorize a device for that account",
                },
                denied.to_string(),
            )
        }
        LookupError::RoleMissing { marker, why } => {
            role_group_failure(state, role_slug(marker, "missing"), why).await
        }
        LookupError::RoleAmbiguous { marker, why } => {
            role_group_failure(state, role_slug(marker, "ambiguous"), why).await
        }
        LookupError::Unavailable(e) => {
            // While this is true, every login in the deployment fails. A
            // refused bind -- a rotated `svc-kerbridge-broker` password --
            // looks the same from here as a directory that is down. Both need
            // a human.
            state
                .notifier
                .send(
                    Event::new(
                        "directory-unavailable",
                        Severity::Error,
                        "the directory is not answering, so no login can succeed",
                    )
                    .detail(format!("{e:#}")),
                )
                .await;
            Failure::new(StatusCode::BAD_GATEWAY, "directory unavailable", format!("{e:#}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every slug that a lookup failure raises must be one that
    /// `resolved_cleanly` clears. A raise that the clear does not know about
    /// would outlive the condition it reports, for as long as the deployment
    /// lives.
    #[test]
    fn every_role_slug_raised_is_one_a_clean_lookup_clears() {
        use kerbridge_core::state::{ROLE_ADMISSION, ROLE_DEVICE_GRANT};

        let raised: Vec<_> = [ROLE_ADMISSION, ROLE_DEVICE_GRANT]
            .into_iter()
            .flat_map(|m| ["missing", "ambiguous"].map(|f| role_slug(m, f)))
            .collect();
        assert_eq!(raised.len(), ROLE_PROBLEMS.len(), "two roles, two faults, four slugs");
        for problem in ROLE_PROBLEMS {
            assert!(raised.contains(&problem), "{problem} is cleared but never raised");
        }
    }
}
