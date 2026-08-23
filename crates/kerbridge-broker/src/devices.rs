//! The device-grant surface: `GET /{source}/nonce` and `/{source}/devices`.
//!
//! None of it decides admission of its own -- it only ever registers, lists or
//! removes a key, and the directory answers the rest on every exchange. Every
//! write it implies goes through `issuerd`, so the broker's LDAP identity stays
//! read-only: a broker that could write the directory could grant itself
//! admission.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use kerbridge_core::grant::{self, DeviceGrant};
use kerbridge_core::issuer::{GrantDeviceRequest, Request as IssuerRequest, RevokeGrantRequest};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::device;
use crate::directory::{Account, Authorized, Target};
use crate::http::{
    Failure, Proof, enabled, now, proof, refuse, request_id, same_source, unauthorized,
};
use crate::problems::{directory_failure, grant_write_failure, resolved_cleanly};
use crate::state::{AppState, SourceState};

/// A fresh single-use nonce for a device assertion.
///
/// Deliberately unauthenticated, like `GET /{source}/config`: it hands out
/// sixteen random bytes, which tells a caller nothing and lets nobody in. What
/// bounds it is the store ceiling and Caddy in front of both routes.
///
/// One store for the whole process: a nonce is unforgeable randomness with a
/// deadline and carries no identity, so which source spends it is decided by the
/// assertion wrapped around it and not by where it came from.
pub async fn nonce(State(state): State<Arc<AppState>>, Path(source): Path<String>) -> Response {
    let outcome = (|| {
        state.source(&source)?;
        enabled(&state.config.device_grants)?;
        let now = now()?;
        state.nonces.issue(&state.rng, now).ok_or_else(|| {
            Failure::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "too many requests in flight",
                "the nonce store is full",
            )
        })
    })();
    match outcome {
        Ok(nonce) => (
            StatusCode::OK,
            Json(json!({"nonce": nonce, "expires_in": state.nonces.ttl_seconds()})),
        )
            .into_response(),
        Err(failure) => refuse("NONCE", "-", failure),
    }
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    alg: String,
    /// The raw uncompressed public point, base64url. The broker derives the
    /// thumbprint from it rather than taking one, so what is stored is always a
    /// digest of a key that was actually presented.
    key: String,
    label: String,
    /// Whom this key is authorized for. Absent is the caller themselves;
    /// present and different needs the delegate group.
    #[serde(default, rename = "for")]
    target: Option<String>,
}

/// The same target, for the two routes that carry no body.
#[derive(Deserialize)]
pub struct TargetQuery {
    #[serde(rename = "for")]
    target: Option<String>,
}

#[derive(Serialize)]
struct DeviceView {
    /// The operator handle, and what `DELETE /devices/{id}` takes.
    grant_id: String,
    /// The account's own `kb1|` value -- what a device must claim to be
    /// resolved. Stated by the server rather than derived by the client, because
    /// the encoding has exactly one implementation and a client that spelled it
    /// differently would be refused on every exchange with nothing to point at.
    ///
    /// Under delegation it is also the *only* place the client learns whose
    /// grant this is: the caller presented their own token and never spelled the
    /// target's identity. Persisting it is what makes a later rename of the
    /// target harmless to a machine already holding a grant.
    identity: String,
    label: String,
    added: u64,
    /// Absent until the grant has been used. Day-granular by construction -- see
    /// [`kerbridge_core::grant::needs_touch`].
    #[serde(skip_serializing_if = "Option::is_none")]
    last_seen: Option<u64>,
    /// When the device must next see a browser sign-in. Already clamped by the
    /// current `configs/main.toml` `device_grant_days`, so this is what will
    /// actually happen and not merely what was stamped.
    sign_in_required_by: u64,
    /// Whether the knob has moved that deadline in below the stamped one.
    clamped: bool,
}

impl DeviceView {
    fn of(grant: &DeviceGrant, identity: &str, days: u32) -> Self {
        Self {
            grant_id: grant.short_id(),
            identity: identity.to_owned(),
            label: grant.label.clone(),
            added: grant.start,
            last_seen: grant.seen,
            sign_in_required_by: grant.effective_end(days),
            clamped: grant.clamped(days),
        }
    }
}

/// Authorize this device to skip the browser sign-in.
///
/// The Entra login *is* the authorization: this runs immediately after one, on a
/// token the broker has just validated for an account it has just confirmed is
/// synced, enabled, admitted and in the grant group. No second admission
/// decision is invented; an existing one is lent to a key for a bounded
/// period.
///
/// With a `for`, the login authorizes the key for *that* account instead, and
/// the delegate group is the second thing checked. The ticket this key later
/// obtains is the target's; nothing here issues one for the caller.
pub async fn register_device(
    State(state): State<Arc<AppState>>,
    Path(source): Path<String>,
    headers: HeaderMap,
    Json(body): Json<RegisterRequest>,
) -> Response {
    let request_id = request_id(&state.rng);
    let outcome = async {
        let src = state.source(&source)?;
        let (auth, now) = grant_holder(&state, src, &headers, body.target.as_deref()).await?;
        let account = &auth.target;
        let Some(alg) = grant::algorithm(&body.alg) else {
            return Err(Failure::new(
                StatusCode::BAD_REQUEST,
                "unsupported key algorithm",
                format!("algorithm {:?}", body.alg),
            ));
        };
        let key = kerbridge_idp::b64url(&body.key).map_err(|_| {
            Failure::new(StatusCode::BAD_REQUEST, "malformed request", "key is not base64url")
        })?;
        let thumbprint = device::thumbprint(&key);
        let expires_at = now as u64 + u64::from(state.config.device_grants.days) * 86_400;

        state
            .issuer
            .write(IssuerRequest::GrantDevice(GrantDeviceRequest {
                request_id: request_id.clone(),
                account_sid: account.sid.clone(),
                alg: body.alg.clone(),
                thumbprint: thumbprint.clone(),
                label: body.label.clone(),
                expires_at,
            }))
            .await
            .map_err(grant_write_failure)?;

        // The reply is rendered from the grant that was just written rather than
        // assembled beside it, so the deadline a client is shown comes through
        // `effective_end` like every other one.
        let grant = DeviceGrant {
            label: grant::sanitize_label(&body.label),
            alg,
            thumbprint,
            start: now as u64,
            end: expires_at,
            seen: None,
        };
        state.record(format!(
            "[broker] GRANT {request_id} {} {}{}",
            account.sam_account_name,
            grant.short_id(),
            by(auth.delegate.as_deref())
        ));
        Ok(DeviceView::of(&grant, &account.identity, state.config.device_grants.days))
    }
    .await;
    match outcome {
        Ok(view) => (StatusCode::CREATED, Json(view)).into_response(),
        Err(failure) => refuse("DEVICE", &request_id, failure),
    }
}

/// The devices this user -- or, with a `for`, the account they are a delegate
/// of -- has authorized. Read straight off that directory object, so it is the
/// same source `kbmanage device list` reads.
pub async fn list_devices(
    State(state): State<Arc<AppState>>,
    Path(source): Path<String>,
    Query(query): Query<TargetQuery>,
    headers: HeaderMap,
) -> Response {
    let request_id = request_id(&state.rng);
    let held = async {
        let src = state.source(&source)?;
        grant_holder(&state, src, &headers, query.target.as_deref()).await
    }
    .await;
    match held {
        Ok((auth, _)) => {
            let days = state.config.device_grants.days;
            let devices: Vec<DeviceView> = auth
                .target
                .grants
                .iter()
                .map(|g| DeviceView::of(g, &auth.target.identity, days))
                .collect();
            (StatusCode::OK, Json(json!({ "devices": devices }))).into_response()
        }
        Err(failure) => refuse("DEVICE", &request_id, failure),
    }
}

/// Remove one device.
///
/// Removing *another* device needs an Entra token, because a compromised machine
/// must not be able to knock the user's other devices offline. Removing
/// *itself* does not: leaving is not an attack, and the rule is self-enforcing
/// because the grant path never produces an Entra token.
pub async fn revoke_device(
    State(state): State<Arc<AppState>>,
    Path((source, id)): Path<(String, String)>,
    Query(query): Query<TargetQuery>,
    headers: HeaderMap,
) -> Response {
    let request_id = request_id(&state.rng);
    let outcome = async {
        let src = state.source(&source)?;
        enabled(&state.config.device_grants)?;
        if !device::is_grant_handle(&id) {
            return Err(Failure::new(
                StatusCode::NOT_FOUND,
                "no such device",
                format!("{id:?} is not a grant handle"),
            ));
        }
        // Two credential paths, and only the token one can be delegated.
        let (account, delegate) = match proof(&headers) {
            Some(Proof::DeviceGrant(assertion)) => {
                let account =
                    self_revocation(&state, src, assertion, &id, query.target.as_deref()).await?;
                (account, None)
            }
            Some(Proof::Bearer(_)) => {
                let (auth, _) =
                    grant_holder(&state, src, &headers, query.target.as_deref()).await?;
                (auth.target, auth.delegate)
            }
            None => {
                return Err(Failure::new(
                    StatusCode::BAD_REQUEST,
                    "malformed request",
                    "no Bearer or DeviceGrant credential",
                ));
            }
        };

        let grant = account.grants.iter().find(|g| g.short_id() == id).ok_or_else(|| {
            Failure::new(StatusCode::NOT_FOUND, "no such device", format!("no grant {id}"))
        })?;
        state
            .issuer
            .write(IssuerRequest::RevokeGrant(RevokeGrantRequest {
                request_id: request_id.clone(),
                account_sid: account.sid.clone(),
                thumbprint: grant.thumbprint.clone(),
            }))
            .await
            .map_err(grant_write_failure)?;
        state.record(format!(
            "[broker] REVOKE {request_id} {} {id}{}",
            account.sam_account_name,
            by(delegate.as_deref())
        ));
        Ok(())
    }
    .await;
    match outcome {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(failure) => refuse("DEVICE", &request_id, failure),
    }
}

/// A machine removing itself, on the one credential that cannot be delegated.
///
/// Deliberately does not require the grant group -- a user dropped from it still
/// gets a clean sign-out rather than a stale entry -- which is why it resolves
/// here instead of through [`grant_holder`].
async fn self_revocation(
    state: &AppState,
    src: &SourceState,
    assertion: &str,
    id: &str,
    target: Option<&str>,
) -> Result<Account, Failure> {
    // A machine may name only its own identity -- the same rule that already
    // binds it to its own thumbprint -- so a target here is a malformed request
    // rather than a refused one.
    if target.is_some() {
        return Err(Failure::new(
            StatusCode::BAD_REQUEST,
            "malformed request",
            "a device-grant assertion may not name another account",
        ));
    }
    let now = now()?;
    let proof = device::verify(assertion, &state.config.device_grants.audience, &state.nonces, now)
        .map_err(|why| unauthorized(why.0))?;
    if grant::short_id(&proof.thumbprint).as_deref() != Some(id) {
        return Err(Failure::new(
            StatusCode::FORBIDDEN,
            "a device may only remove itself",
            "device-grant assertion named another device",
        ));
    }
    same_source(&src.source, &proof.identity)?;
    match src.directory.resolve(&proof.identity).await {
        Ok(account) => {
            resolved_cleanly(state, &proof.identity).await;
            Ok(account)
        }
        Err(e) => Err(directory_failure(state, &proof.identity, e).await),
    }
}

/// The account a `/devices` request acts on, and whether this caller may act on
/// it. Every route that is not a self-revocation starts here.
///
/// One helper for all three on purpose: the rule is that the target is checked
/// for the device-grant group and the caller for admission plus, when they
/// differ, the target's delegate group -- and three routes drifting apart on
/// that would drift silently and in the wrong direction.
async fn grant_holder(
    state: &AppState,
    src: &SourceState,
    headers: &HeaderMap,
    target: Option<&str>,
) -> Result<(Authorized, i64), Failure> {
    enabled(&state.config.device_grants)?;
    let now = now()?;
    // Creating or listing grants needs a browser sign-in at the cloud IdP. A
    // device grant is deliberately not enough: a machine must not be able to
    // enroll more machines, or one compromise would become permanent by itself.
    let Some(Proof::Bearer(token)) = proof(headers) else {
        return Err(Failure::new(
            StatusCode::UNAUTHORIZED,
            "invalid identity proof",
            "this route requires a browser sign-in",
        ));
    };
    let target = target
        .map(Target::parse)
        .transpose()
        .map_err(|why| Failure::new(StatusCode::BAD_REQUEST, "malformed request", why))?;
    let identity = src.idp.identify(token, now).await.map_err(|why| unauthorized(why.0))?;
    match src.directory.authorize_device_request(&identity, target.as_ref()).await {
        Ok(authorized) => {
            resolved_cleanly(state, &identity).await;
            Ok((authorized, now))
        }
        Err(e) => Err(directory_failure(state, &identity, e).await),
    }
}

/// The audit line's second party, present only when there is one. Per the
/// design this log *is* the record of who authorized what: nothing durable in
/// the directory names the delegate.
fn by(delegate: Option<&str>) -> String {
    delegate.map_or(String::new(), |sam| format!(" by={sam}"))
}
