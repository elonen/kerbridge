//! `GET /config` and `GET /{source}/config` -- what a client bootstraps from.
//!
//! The document itself is [`crate::config::Discovery`]; these two routes are
//! only about which source's copy of it a caller gets.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::http::refuse;
use crate::state::AppState;

pub async fn discovery(State(state): State<Arc<AppState>>, Path(source): Path<String>) -> Response {
    match state.source(&source) {
        Ok(src) => (StatusCode::OK, Json(state.config.discovery(src.idp.client_config(), &source)))
            .into_response(),
        Err(failure) => refuse("CONFIG", "-", failure),
    }
}

/// `GET /config`, for a client that found this broker in DNS and so has no
/// source name to ask under.
///
/// Answered only where one source makes the answer unambiguous. Guessing is the
/// failure the segment exists to prevent: the client would authenticate against
/// whichever source sorted first, successfully, forever.
///
/// The refusal lists the names because the operator has to put one in a URL, and
/// the client tells this 404 from every other one by that list, not by the
/// status.
pub async fn sole_discovery(State(state): State<Arc<AppState>>) -> Response {
    let mut names = state.sources.keys();
    let (Some(name), None) = (names.next(), names.next()) else {
        let sources: Vec<&String> = state.sources.keys().collect();
        eprintln!(
            "[broker] DENY  - CONFIG 404 (ambiguous): /config needs a source segment; {} are \
             configured",
            sources.len()
        );
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "which source?", "sources": sources})),
        )
            .into_response();
    };
    discovery(State(state.clone()), Path(name.clone())).await
}
