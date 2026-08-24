//! The vocabulary every route speaks: failure type, identity proofs, and
//! the checks that belong to no single route.
//!
//! This module is a leaf on purpose: nothing here must read
//! [`crate::state::AppState`].

use axum::Json;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use kerbridge_core::{ExternalIdentity, Source};
use serde_json::json;

use crate::config::DeviceGrantConfig;

/// Every failure is one of these. The client sees the status and a short
/// reason. The detail goes to the log under the same request id: a caller who
/// learns exactly which check refused them has learned how to pass it.
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

/// A refusal of an identity proof. Always one status and one sentence, whichever
/// check failed and whichever proof it was.
pub fn unauthorized(detail: impl Into<String>) -> Failure {
    Failure::new(StatusCode::UNAUTHORIZED, "invalid identity proof", detail)
}

/// Unix time, in seconds. A clock before the epoch is a 500.
pub fn now() -> Result<i64, Failure> {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).map_err(|e| {
        Failure::new(StatusCode::INTERNAL_SERVER_ERROR, "server error", format!("clock: {e}"))
    })
}

/// Refuse an identity that arrived at a different source than the one that
/// minted it.
///
/// A bearer token cannot fail this test: the adapter that verified the token
/// stamps its own source name into the identity, thus the two agree by
/// construction. The device-grant assertion is the case that needs the test. It
/// carries an encoded identity and is verified against a deployment-wide
/// audience, thus nothing else stops an assertion minted under source A from
/// being spent at the path of source B, where B's admission group would decide.
pub fn same_source(source: &Source, identity: &ExternalIdentity) -> Result<(), Failure> {
    if identity.source() == source {
        return Ok(());
    }
    Err(unauthorized(format!(
        "an identity from source {} was presented to source {source}",
        identity.source()
    )))
}

/// Refuse every device-grant route when the deployment has the feature off. The
/// tray never asks, because `GET /{source}/config` says `days: 0`. This answers
/// anything else that asks.
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

/// Parse the `Authorization` header into the proof it carries. Exactly one
/// scheme must match; anything else is `None`. An unknown scheme is thus refused
/// outright and does not fall through to a weaker check.
///
/// RFC 6750 makes the scheme case-insensitive. Windows and curl disagree about
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

/// A fresh id that ties the client's error response to the server's log lines.
/// Random and not sequential, thus it tells a client nothing about traffic
/// volume.
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
