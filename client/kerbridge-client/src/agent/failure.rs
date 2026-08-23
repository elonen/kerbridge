//! What a failure is called in front of the user: an error from one leg of the
//! sign-in, turned into the fault the icon shows and the sentence beside it.
//!
//! A sibling of [`crate::describe`], and the division is what each one reads.
//! That decides what a *state* means; this decides what a *failure* means.
//! Both are pure functions -- neither touches agent state -- so the vocabulary
//! can be read and changed without tracing a worker.
//!
//! Every sentence takes one form: **`<mechanism state>: <what it means for
//! you>`**. The tag is the sysadmin's handle and the sentence is the end user's
//! consequence, so no message here predicts that an action will fail and none
//! promises a fix.

use crate::broker;
use crate::describe::Fault;
use crate::session::InjectError;
use crate::strings::{fill, tr};

use super::host_of;

/// A failure as the surface needs it: the sentence, and what class it belongs
/// to. `None` is an absence rather than a breakage -- nothing to be silent with,
/// or a machine waiting to be authorized -- which the blocker list already
/// explains and which must not be dressed in fault ink.
pub(super) type Failure = (Option<Fault>, String);

/// Discovery is the first thing every sign-in does, so an untrusted broker
/// certificate is met here rather than at `/ticket`.
///
/// The host comes from the failure and not from `broker_url`, because the same
/// call also fetches the IdP's discovery document: naming the broker for a
/// certificate the IdP presented would send its reader to the wrong machine.
pub(super) fn describe_discovery_error(e: &anyhow::Error, broker_url: &str) -> Failure {
    let s = tr();
    if let Some(host) = crate::http::untrusted_host(e) {
        return (Some(Fault::Network), fill(s.err_tls_untrusted, &[("broker", host)]));
    }
    // Not a network fault: the broker answered, and the address it was asked at
    // is one segment short.
    if let Some(a) = e.chain().find_map(|c| c.downcast_ref::<crate::discovery::AmbiguousSource>()) {
        return (
            Some(Fault::Other),
            fill(
                s.err_broker_ambiguous_source,
                &[("broker", &host_of(broker_url)), ("sources", &a.sources.join(", "))],
            ),
        );
    }
    (
        Some(Fault::Network),
        fill(
            s.err_broker_unreachable,
            &[("broker", &host_of(broker_url)), ("detail", &format!("{e:#}"))],
        ),
    )
}

/// A token-endpoint failure. `/config` and `/ticket` are always the broker;
/// this is the one call that reaches the IdP instead, so both hosts that appear
/// here come from the failure rather than from us.
///
/// `template` is the caller's `{detail}` sentence -- a browser sign-in and a
/// silent renewal fail at the same call and mean different things. The two typed
/// causes outrank it, because each has a sentence of its own that says more than
/// "the renewal failed, here is a chain".
pub(super) fn describe_token_error(e: &anyhow::Error, template: &str) -> Failure {
    let s = tr();
    if let Some(host) = crate::http::untrusted_host(e) {
        return (Some(Fault::Network), fill(s.err_tls_untrusted, &[("broker", host)]));
    }
    if let Some(refused) = e.chain().find_map(|c| c.downcast_ref::<crate::oidc::Refused>()) {
        return (
            Some(Fault::Refused),
            fill(s.err_idp_refused, &[("issuer", &refused.issuer), ("detail", &refused.reason)]),
        );
    }
    if e.chain().any(|c| c.downcast_ref::<crate::oidc::TimedOut>().is_some()) {
        // Nobody finished it, which is not the same as something breaking -- but
        // it is still why there is no ticket, so it keeps a fault of its own.
        return (Some(Fault::Other), s.err_sign_in_timeout.to_string());
    }
    (Some(Fault::Other), fill(template, &[("detail", &format!("{e:#}"))]))
}

/// Map a refused registration to something the user can act on. The device cap
/// gets its own message: it is the one failure the person at the keyboard can
/// clear themselves, by giving up a machine they no longer use.
pub(super) fn describe_grant_error(e: &broker::BrokerError, broker: &str) -> Failure {
    let s = tr();
    match e {
        broker::BrokerError::Conflict(m) => {
            (Some(Fault::GrantRefused), fill(s.err_grant_too_many, &[("detail", m)]))
        }
        // The one refusal that is about somebody *else's* account: the sign-in
        // worked and this person is admitted, they are simply not a delegate of
        // the account this machine names. Sending them to a browser would repeat
        // the half that already succeeded.
        broker::BrokerError::NotAdmitted(m) if m == broker::REFUSED_NOT_DELEGATE => {
            (Some(Fault::GrantRefused), fill(s.err_grant_not_delegate, &[("detail", m)]))
        }
        broker::BrokerError::NotAdmitted(m) => {
            (Some(Fault::GrantRefused), fill(s.err_grant_not_allowed, &[("detail", m)]))
        }
        other => transport(other, broker).unwrap_or_else(|| {
            (Some(Fault::Other), fill(s.err_grant_failed, &[("detail", &other.to_string())]))
        }),
    }
}

/// Map a failed injection to something the user can act on. The distinction that
/// matters: a 403 means re-trying will not help -- only an administrator can --
/// while a 5xx or a transport error is worth retrying.
pub(super) fn describe_inject_error(e: &InjectError, broker: &str) -> Failure {
    let s = tr();
    let InjectError::Broker(e) = e else {
        // A local failure: the ccache would not parse, or the LSA refused the
        // submission. Nothing about the broker to name.
        return (Some(Fault::Other), fill(s.err_internal, &[("detail", &e.to_string())]));
    };
    match e {
        // Three sentences, not one. `err_not_admitted` says the account is not
        // allowed on the realm, which is false of someone refused only a device
        // grant -- they are admitted, and a browser sign-in works for them right
        // now. Sending all four 403 reasons to it told a user with one problem to
        // go and solve another, in whichever of eleven languages they read.
        broker::BrokerError::NotAdmitted(m) if m == broker::REFUSED_NOT_GRANTED => {
            (Some(Fault::GrantRefused), fill(s.err_grant_not_allowed, &[("detail", m)]))
        }
        broker::BrokerError::NotAdmitted(m) if m == broker::REFUSED_GRANTS_DISABLED => {
            (Some(Fault::GrantRefused), s.err_grant_disabled.to_string())
        }
        broker::BrokerError::NotAdmitted(m) => {
            (Some(Fault::Refused), fill(s.err_not_admitted, &[("detail", m)]))
        }
        other => transport(other, broker).unwrap_or_else(|| {
            (Some(Fault::Other), fill(s.err_internal, &[("detail", &other.to_string())]))
        }),
    }
}

/// The refusals that mean the same thing wherever they arrive: the broker
/// itself, its transport, and its side of the contract. `None` leaves the
/// caller's own arm to answer.
fn transport(e: &broker::BrokerError, broker: &str) -> Option<Failure> {
    let s = tr();
    let (fault, template, detail) = match e {
        broker::BrokerError::InvalidProof(m) => (Fault::Refused, s.err_invalid_proof, m.clone()),
        broker::BrokerError::RateLimited => (Fault::Network, s.err_rate_limited, String::new()),
        broker::BrokerError::ServerUnavailable(m) => {
            (Fault::Network, s.err_server_unavailable, m.clone())
        }
        broker::BrokerError::Unreachable(m) => {
            (Fault::Network, s.err_broker_unreachable, m.clone())
        }
        // No `{detail}`: the detail is a certificate, and it is already in the
        // log. The flyout says what happened and where the rest of it is.
        broker::BrokerError::Untrusted(_) => (Fault::Network, s.err_tls_untrusted, String::new()),
        // Ours, not the user's: a request this client built was rejected as
        // malformed. Named as a protocol fault so a support request reaches the
        // right people rather than sending someone to sign in again.
        broker::BrokerError::BadRequest(m) => (Fault::Other, s.err_bad_request, m.clone()),
        broker::BrokerError::BadResponse(m) => (Fault::Other, s.err_broker_protocol, m.clone()),
        broker::BrokerError::Unexpected(code, m) => {
            (Fault::Other, s.err_broker_protocol, format!("{code}: {m}"))
        }
        _ => return None,
    };
    Some((Some(fault), fill(template, &[("broker", broker), ("detail", &detail)])))
}
