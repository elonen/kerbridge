//! What a failed lookup or issuance becomes: the status the client is told, and
//! which failures a human additionally hears about out of band.
//!
//! One module because the raises and the clear are one policy: [`ROLE_PROBLEMS`]
//! is the table both ends read, and a raise added beside a clear that does not
//! know about it would report for as long as the deployment lives.

use axum::http::StatusCode;
use kerbridge_core::ExternalIdentity;
use kerbridge_notify::{Event, Severity};

use crate::directory::{Denied, LookupError};
use crate::http::Failure;
use crate::issuer::IssuerError;
use crate::state::AppState;

/// Every role-group problem this service can raise. Cleared as a set, because a
/// realm can go from no marked group to two without ever being healthy in
/// between: clearing only the one just raised would leave the other open for as
/// long as the deployment lives.
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

/// What a completed lookup proves, recorded once so the ticket path and the
/// device paths cannot drift on it.
///
/// A lookup that got all the way through proves the directory answered and the
/// role groups are readable and unambiguous -- the only evidence this service
/// ever sees that any of those have cleared, since it is request-driven and
/// cannot re-evaluate on a schedule the way sync does. Costs nothing when
/// nothing is open, which is every request on a healthy deployment.
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
                // The reason is the subject: two groups carrying the marker and
                // three carrying it are one problem, but a reworded reason for
                // the same slug must not sit behind the first one's repeat
                // interval.
                .subject(why.clone()),
        )
        .await;
    Failure::new(StatusCode::BAD_GATEWAY, "directory unavailable", why)
}

/// A refused directory write. The cap is the one refusal a user can act on, so
/// it keeps its own status; everything else is the issuer being the issuer.
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

/// What a failed issuance becomes.
///
/// The two are told apart because only one of them is a fault. `issuerd`
/// independently re-checks what the broker checked, so a *refusal* means the two
/// disagree about an account that already passed admission -- the shape of the
/// `sam.rs` divergence that once let accounts synchronize cleanly and never
/// obtain a ticket. An issuer that cannot be reached is the realm container being
/// down, which its own healthcheck already reports and which recovers by itself.
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
                    // Per account: a second one diverging is a second problem,
                    // and must not sit behind the first one's repeat interval.
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

/// What a failed directory lookup becomes, and the one case an operator has to
/// hear about out of band.
///
/// A missing or ambiguous admission group answers exactly as it did when it was
/// an ordinary directory failure -- the client learns nothing new, because there
/// is nothing the client can do -- but it is also the condition that freezes
/// every login in the deployment until a human fixes it, so it leaves by the
/// notification channel as well.
pub async fn directory_failure(
    state: &AppState,
    identity: &ExternalIdentity,
    error: LookupError,
) -> Failure {
    match error {
        // Five states, told apart on purpose -- and deliberately unlike
        // `http::unauthorized`, which says only "invalid identity proof"
        // however it failed. The difference is who is asking. A 401 is reached by anyone holding
        // any string; this is reached only by someone whose token already
        // verified, so the reason is being told to someone the deployment has
        // already admitted. It is also the whole self-service story: "your
        // account is not admitted to the realm" is a sentence the tray shows
        // and the user acts on, where a flat 403 is a helpdesk ticket.
        //
        // On a request that named a *target*, the reason is about that account
        // rather than the caller's own -- so an admitted caller can learn
        // whether a login name exists, is enabled, and is in the grant group.
        // Accepted: all three are an authenticated LDAP read away already, and
        // the caller is resolved first, so someone not admitted at all still
        // learns nothing.
        LookupError::Denied(denied) => {
            // One of the four is not a policy answer at all. Two objects claiming
            // one identity is a directory-integrity fault that only an operator
            // can clear, and it fails this user's login every time until they do
            // -- where "not provisioned", "disabled" and "not admitted" are all
            // working as designed. The client is told the same thing either way.
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
                    // 403 like the others: the identity is fine and signing in
                    // again will not help -- unlike a dead grant, which is 401.
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
            // Every login in the deployment is failing while this is true, and a
            // rejected bind -- a rotated `svc-kerbridge-broker` password -- looks exactly the
            // same from here as the directory being down. Both need a human.
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

    /// Every slug a lookup failure can raise is one `resolved_cleanly` clears.
    /// A raise the clear does not know about would survive the condition it
    /// reports for as long as the deployment lives.
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
