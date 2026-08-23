//! The vocabulary every route speaks: the one failure type, the two identity
//! proofs, and the few checks that belong to no single route.
//!
//! Deliberately a leaf -- nothing here reaches [`crate::state::AppState`], so
//! what the routes share cannot quietly grow into a second place the process is
//! wired together.

use axum::Json;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use kerbridge_core::{ExternalIdentity, Source};
use serde_json::json;

use crate::config::DeviceGrantConfig;

/// Every failure is one of these. The client sees the status and a short
/// reason; the detail goes to the log under the same request id, because a
/// caller who is told exactly which check refused them has been told how to
/// pass it.
pub struct Failure {
    pub status: StatusCode,
    pub client: &'static str,
    pub detail: String,
}

impl Failure {
    pub fn new(status: StatusCode, client: &'static str, detail: impl Into<String>) -> Self {
        Self { status, client, detail: detail.into() }
    }
}

/// One `DENY` line and one response body, shared by every route that is not
/// `POST /ticket` -- which has its own, because it also logs a duration.
pub fn refuse(route: &str, request_id: &str, failure: Failure) -> Response {
    eprintln!(
        "[broker] DENY  {request_id} {route} {} ({}): {}",
        failure.status.as_u16(),
        failure.client,
        failure.detail
    );
    (failure.status, Json(json!({"error": failure.client, "request_id": request_id})))
        .into_response()
}

/// Every rejected identity proof is one status and one sentence, whichever check
/// failed and whichever proof it was: a caller told exactly which check refused
/// them has been told how to pass it.
pub fn unauthorized(detail: impl Into<String>) -> Failure {
    Failure::new(StatusCode::UNAUTHORIZED, "invalid identity proof", detail)
}

pub fn now() -> Result<i64, Failure> {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).map_err(|e| {
        Failure::new(StatusCode::INTERNAL_SERVER_ERROR, "server error", format!("clock: {e}"))
    })
}

/// An identity may only be used under the source it was minted by.
///
/// A bearer token cannot fail this: the adapter that verified it stamps its own
/// source name into the identity, so the two agree by construction. A
/// device-grant assertion is the case that needs it -- it carries an encoded
/// identity and is verified against a deployment-wide audience, so nothing else
/// stops one minted under source A from being spent at source B's path, where
/// B's admission group would be the one consulted.
pub fn same_source(source: &Source, identity: &ExternalIdentity) -> Result<(), Failure> {
    if identity.source() == source {
        return Ok(());
    }
    Err(unauthorized(format!(
        "an identity from source {} was presented to source {source}",
        identity.source()
    )))
}

/// Refuse everything device-grant if the deployment has the feature off. The
/// tray never asks, because `GET /{source}/config` says `days: 0`; this is what
/// answers anything else that does.
pub fn enabled(grants: &DeviceGrantConfig) -> Result<(), Failure> {
    if grants.enabled() {
        return Ok(());
    }
    Err(Failure::new(
        StatusCode::FORBIDDEN,
        "device grants are not enabled",
        "main.toml: device_grant_days is 0",
    ))
}

/// The two identity proofs, told apart by their scheme.
pub enum Proof<'a> {
    Bearer(&'a str),
    DeviceGrant(&'a str),
}

/// Parse the `Authorization` scheme. Exactly one must match; anything else is
/// `None`, so an unrecognized scheme is rejected outright rather than falling
/// through to a weaker check.
///
/// RFC 6750 says the scheme is case-insensitive; Windows and curl disagree about
/// which case they send.
pub fn proof(headers: &HeaderMap) -> Option<Proof<'_>> {
    let value = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, credential) = value.split_once(' ')?;
    let credential = credential.trim();
    if credential.is_empty() {
        return None;
    }
    if scheme.eq_ignore_ascii_case("bearer") {
        return Some(Proof::Bearer(credential));
    }
    if scheme.eq_ignore_ascii_case("devicegrant") {
        return Some(Proof::DeviceGrant(credential));
    }
    None
}

/// Correlates the client's error response with the server's log lines. Random
/// rather than sequential so it carries no information about traffic volume.
pub fn request_id(rng: &ring::rand::SystemRandom) -> String {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 8];
    if rng.fill(&mut bytes).is_err() {
        return "unseeded".into();
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests;
