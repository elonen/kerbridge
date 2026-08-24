//! `POST /{source}/ticket`: exchange an identity proof for a TGT.
//!
//! Both identity proofs arrive here, and the two meet at the same directory
//! lookup. The admission path is thus one path by construction, not by
//! discipline.

use std::sync::Arc;
use std::time::Instant;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use kerbridge_core::grant::{self, DeviceGrant};
use kerbridge_core::issuer::{IssueRequest, Request as IssuerRequest, TouchGrantRequest};
use serde::Serialize;
use serde_json::json;

use crate::device;
use crate::directory::Account;
use crate::http::{Failure, Proof, enabled, now, proof, request_id, same_source, unauthorized};
use crate::problems::{directory_failure, issuer_failure, resolved_cleanly};
use crate::state::{AppState, SourceState};

#[derive(Serialize)]
pub struct TicketResponse {
    principal: String,
    ccache_b64: String,
}

pub async fn ticket(
    State(state): State<Arc<AppState>>,
    Path(source): Path<String>,
    headers: HeaderMap,
) -> Response {
    let request_id = request_id(&state.rng);
    let started = Instant::now();
    // Claimed before any work, and released however the request ends. Refused
    // and not queued: a queue is the same unbounded work with a delay in front
    // of it, and the helper already backs off on a 429.
    //
    // One budget for the whole process, not one per source. It protects the
    // single directory and the single issuer behind all of them.
    let outcome = match state.inflight.try_acquire() {
        Ok(_permit) => match state.source(&source) {
            Ok(src) => issue(&state, src, &headers, &request_id).await,
            Err(failure) => Err(failure),
        },
        Err(_) => Err(Failure::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many requests in flight",
            format!("all {} in-flight slots are taken", state.config.max_inflight),
        )),
    };
    match outcome {
        Ok(response) => {
            eprintln!(
                "[broker] ISSUE {request_id} {} in {} ms",
                response.principal,
                started.elapsed().as_millis()
            );
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(failure) => {
            eprintln!(
                "[broker] DENY  {request_id} {} ({}) in {} ms: {}",
                failure.status.as_u16(),
                failure.client,
                started.elapsed().as_millis(),
                failure.detail
            );
            (failure.status, Json(json!({"error": failure.client, "request_id": request_id})))
                .into_response()
        }
    }
}

/// Verify the proof, resolve the account, and get a TGT for it.
async fn issue(
    state: &AppState,
    src: &SourceState,
    headers: &HeaderMap,
    request_id: &str,
) -> Result<TicketResponse, Failure> {
    let now = now()?;
    let (identity, device) = match proof(headers) {
        Some(Proof::Bearer(token)) => {
            (src.idp.identify(token, now).await.map_err(|why| unauthorized(why.0))?, None)
        }
        Some(Proof::DeviceGrant(assertion)) => {
            enabled(&state.config.device_grants)?;
            let proof =
                device::verify(assertion, &state.config.device_grants.audience, &state.nonces, now)
                    .map_err(|why| unauthorized(why.0))?;
            (proof.identity, Some(proof.thumbprint))
        }
        None => {
            return Err(Failure::new(
                StatusCode::BAD_REQUEST,
                "malformed request",
                "no Bearer or DeviceGrant credential",
            ));
        }
    };
    same_source(&src.source, &identity)?;

    // Safe to log: a source and a subject are directory coordinates, not
    // credentials. The token that carried them is never logged.
    eprintln!(
        "[broker] AUTH  {request_id} {}{}",
        identity.label(),
        device.as_ref().map_or(String::new(), |t| format!(
            " device={}",
            grant::short_id(t).unwrap_or_default()
        ))
    );

    // A device grant must satisfy the admission group *and* the grant group. A
    // bearer token must satisfy the first alone.
    let lookup = match &device {
        Some(_) => src.directory.resolve_for_grant(&identity).await,
        None => src.directory.resolve(&identity).await,
    };
    let account = match lookup {
        Ok(account) => {
            resolved_cleanly(state, &identity).await;
            account
        }
        Err(e) => return Err(directory_failure(state, &identity, e).await),
    };

    // The grant itself: on this object, and inside its effective window. Both
    // are re-read here and not trusted from the assertion. That is what keeps
    // `kbmanage device revoke` and the duration setting effective within one
    // ticket lifetime, like every other revocation lever.
    let live = match &device {
        Some(thumbprint) => Some(live_grant(state, &account, thumbprint, now)?),
        None => None,
    };

    let issued = state
        .issuer
        .issue(IssueRequest {
            request_id: request_id.to_owned(),
            account_sid: account.sid.clone(),
            lifetime_seconds: Some(state.config.ticket_lifetime_seconds),
            renewable_lifetime_seconds: Some(state.config.ticket_renewable_seconds),
        })
        .await;
    let ticket = match issued {
        Ok(ticket) => {
            state.notifier.resolve_subject("issuer-refused", &account.sam_account_name).await;
            ticket
        }
        Err(e) => return Err(issuer_failure(state, &account.sam_account_name, e).await),
    };

    if let Some(grant) = live {
        touch(state, &account, grant, request_id, now).await;
    }

    eprintln!(
        "[broker] ISSUE {request_id} {} sid={} expires={} renew_until={}",
        ticket.principal, account.sid, ticket.expires_at, ticket.renew_until
    );
    Ok(TicketResponse { principal: ticket.principal, ccache_b64: ticket.ccache_b64 })
}

/// The grant that this assertion claims, if the directory still agrees that it
/// is usable.
///
/// **401, not 403.** After a revoked, expired or clamped grant, the correct next
/// move for the client is a browser sign-in, and 401 is what says that to the
/// tray. 403 means the identity is good and a new sign-in does not help: true of
/// "not in the grant group", false of every case here.
fn live_grant<'a>(
    state: &AppState,
    account: &'a Account,
    thumbprint: &str,
    now: i64,
) -> Result<&'a DeviceGrant, Failure> {
    let grant = account
        .grants
        .iter()
        .find(|g| g.thumbprint == thumbprint)
        .ok_or_else(|| unauthorized("no such grant on this account"))?;
    if !grant.valid_at(now as u64, state.config.device_grants.days) {
        return Err(unauthorized(format!(
            "grant {} expired at {}",
            grant.short_id(),
            grant.effective_end(state.config.device_grants.days)
        )));
    }
    Ok(grant)
}

/// Stamp the last-use day of the grant, if the schedule asks for it.
///
/// Fire and forget by design: a failed stamp must never fail a ticket exchange,
/// because the stamp is for display and is not data. `issuerd` re-evaluates the
/// schedule against the stored value before it writes, thus a race between two
/// devices on one account costs a wasted call and not a double write.
async fn touch(
    state: &AppState,
    account: &Account,
    grant: &DeviceGrant,
    request_id: &str,
    now: i64,
) {
    if !grant::needs_touch(grant.seen, now as u64) {
        return;
    }
    let request = IssuerRequest::TouchGrant(TouchGrantRequest {
        request_id: request_id.to_owned(),
        account_sid: account.sid.clone(),
        thumbprint: grant.thumbprint.clone(),
        seen: now as u64,
    });
    if let Err(e) = state.issuer.write(request).await {
        eprintln!("[broker] TOUCH {request_id} {} failed, ignored: {e}", grant.short_id());
    }
}
