//! Browser sign-in: OAuth 2.0 authorization code + PKCE with a loopback
//! redirect, plus the silent refresh-token grant the tray re-injects with.
//!
//! A faithful port of `testbench/entra-tenant/pkce.py`, which is proven against
//! the live tenant. The public client holds no secret; the code is bound to a
//! one-time PKCE verifier this process keeps in memory, and the redirect lands
//! on an ephemeral `127.0.0.1` port. Entra ignores the port when matching a
//! registered `http://127.0.0.1` loopback URI, so no fixed port is registered.
//!
//! The refresh token, when the authority issues one, is returned for the tray's
//! silent re-injection and is **never written to disk** -- it lives in the tray
//! process's memory and dies with it.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use sha2::{Digest, Sha256};

use crate::discovery::OidcConfig;

/// How long to wait for the user to complete the browser sign-in.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);

pub struct Tokens {
    pub access_token: String,
    /// Present only if `offline_access` was granted. Memory-only.
    pub refresh_token: Option<String>,
}

/// Run the browser sign-in. `Ok(None)` means the caller set `cancel` (the tray's
/// Cancel button) -- a normal outcome, not an error to report.
pub fn login(cfg: &OidcConfig, cancel: &AtomicBool) -> Result<Option<Tokens>> {
    let verifier = random_urlsafe(48)?;
    let challenge = b64url(Sha256::digest(verifier.as_bytes()).as_slice());
    let state = random_urlsafe(24)?;

    // Port 0: the OS assigns a free ephemeral port, which becomes the redirect.
    let listener =
        TcpListener::bind("127.0.0.1:0").context("binding the loopback redirect listener")?;
    let redirect = format!("http://127.0.0.1:{}", listener.local_addr()?.port());
    let scope = cfg.scopes.join(" ");

    let auth_url = authorize_url(cfg, &redirect, &state, &challenge);

    crate::log::info("opening the system browser for sign-in");
    // Best effort: a failure here surfaces as the login timeout.
    let _ = webbrowser::open(&auth_url);

    let Some(code) = wait_for_code(&listener, &state, cancel)? else {
        crate::log::info("sign-in cancelled by the user");
        return Ok(None);
    };

    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", &cfg.client_id)
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", &code)
        .append_pair("redirect_uri", &redirect)
        .append_pair("code_verifier", &verifier)
        .append_pair("scope", &scope)
        .finish();

    token_request(cfg, body).map(Some)
}

/// The authorization request URL. Pure, so the ordering rule below is testable
/// without a browser or a listener.
///
/// The broker's `extra_auth_params` go on **first** and the flow's own pairs
/// after them, so an adapter that names one of ours does not displace it on any
/// authority that reads the last duplicate. Which one an authority reads is its
/// framework's choice, not a rule -- Django takes the last, Werkzeug the first --
/// so this ordering decides whether such a request works, never whether it is
/// safe. Safety is local and does not depend on it: `state` is compared against
/// the value this process generated, and the verifier never leaves this process,
/// so a displaced reserved name costs a sign-in rather than a check.
fn authorize_url(cfg: &OidcConfig, redirect: &str, state: &str, challenge: &str) -> String {
    let scope = cfg.scopes.join(" ");
    let mut query = form_urlencoded::Serializer::new(String::new());
    for (name, value) in &cfg.extra_auth_params {
        query.append_pair(name, value);
    }
    let query = query
        .append_pair("client_id", &cfg.client_id)
        .append_pair("response_type", "code")
        .append_pair("redirect_uri", redirect)
        .append_pair("response_mode", "query")
        .append_pair("scope", &scope)
        .append_pair("state", state)
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256")
        .finish();
    format!("{}?{}", cfg.authorization_endpoint, query)
}

/// Silent re-authentication with a refresh token -- what makes re-injection
/// invisible. A failure here is expected eventually (the refresh token has its
/// own lifetime, and conditional access can revoke it); the caller falls back to
/// `login`.
pub fn refresh(cfg: &OidcConfig, refresh_token: &str) -> Result<Tokens> {
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", &cfg.client_id)
        .append_pair("grant_type", "refresh_token")
        .append_pair("refresh_token", refresh_token)
        .append_pair("scope", &cfg.scopes.join(" "))
        .finish();
    token_request(cfg, body)
}

/// Who a token says it was issued to, for display only.
///
/// Read straight out of the payload with the signature ignored, which is safe
/// here for one reason: nothing is decided on it. Its only use is the default
/// label a delegated device grant carries, which the broker sanitizes and no
/// check ever consults -- the authorization itself is the token, validated by
/// the broker. `preferred_username` is what Entra's v2.0 tokens carry and `upn`
/// what v1.0 ones do; anything else yields `None` and the label simply says
/// less.
pub fn token_account(access_token: &str) -> Option<String> {
    let payload = access_token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    ["preferred_username", "upn"]
        .iter()
        .find_map(|claim| claims.get(claim).and_then(|v| v.as_str()))
        .map(str::to_owned)
}

/// Open the authority's RP-initiated logout page in the system browser, so the
/// cloud SSO cookie is cleared and the next sign-in prompts for real. Dropping our
/// in-memory refresh token only forgets *our* copy; the browser session outlives
/// it, which is why "sign out of the cloud" has to reach the IdP. Best effort and
/// non-fatal: a missing endpoint or a failed launch just means the browser session
/// stays, and the caller has already forgotten the token regardless.
///
/// Returns whether the authority was actually asked. The caller records the
/// session on disk, and a session it stops recording without ever asking is one
/// nothing will offer to end again.
pub fn logout(cfg: &OidcConfig) -> bool {
    let Some(endpoint) = cfg.end_session_endpoint.as_deref() else {
        crate::log::info("no end_session_endpoint advertised; skipping browser logout");
        return false;
    };
    // The URL, because what the browser then shows is an account picker over every
    // session it holds -- so a failure there ("tenant not found") is usually about
    // the account that was picked, not about the address we opened, and the log has
    // to make the two distinguishable. Public discovery metadata, not a secret.
    crate::log::info(&format!("opening the system browser for cloud sign-out: {endpoint}"));
    webbrowser::open(endpoint).is_ok()
}

/// The authority answered the token endpoint with an error of its own. Typed
/// rather than a message for the same reason [`crate::http::Untrusted`] is: it
/// names a host that is *not* the broker, and a chain naming neither sends its
/// reader to the wrong machine.
#[derive(Debug)]
pub struct Refused {
    pub issuer: String,
    /// The `error` slug alone. The body can echo the authorization code, so the
    /// rest of it never leaves this function.
    pub reason: String,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} rejected the token request: {}", self.issuer, self.reason)
    }
}

impl std::error::Error for Refused {}

/// The browser sign-in was never completed. Carries nothing: the whole of what
/// happened is that nobody finished it.
#[derive(Debug)]
pub struct TimedOut;

impl std::fmt::Display for TimedOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "timed out after {}s waiting for the browser sign-in", LOGIN_TIMEOUT.as_secs())
    }
}

impl std::error::Error for TimedOut {}

/// POST a grant to the token endpoint and parse the response. Neither the
/// request body nor the response is ever logged: both carry live credentials.
fn token_request(cfg: &OidcConfig, body: String) -> Result<Tokens> {
    let mut resp = crate::http::agent()
        .post(&cfg.token_endpoint)
        .content_type("application/x-www-form-urlencoded")
        .send(body)
        .map_err(|e| {
            let failure = crate::http::describe(&cfg.token_endpoint, &e);
            // Typed, like discovery's: a refused certificate here is the IdP's,
            // and an untyped chain naming no host sends its reader to the wrong
            // machine -- or to no machine at all.
            if failure.untrusted {
                anyhow::Error::new(crate::http::Untrusted::new(
                    &cfg.token_endpoint,
                    failure.message,
                ))
            } else {
                anyhow!("token endpoint POST failed: {}", failure.message)
            }
        })?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().context("reading token response")?;
    if status != 200 {
        // The body can echo the authorization code, so only the error slug is
        // surfaced, never the whole response.
        let reason = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned))
            .unwrap_or_else(|| format!("HTTP {status}"));
        return Err(anyhow::Error::new(Refused {
            issuer: crate::http::host_of_url(&cfg.token_endpoint),
            reason,
        }));
    }

    let token: serde_json::Value = serde_json::from_str(&text).context("parsing token response")?;
    let access_token = token
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("token response carried no access_token"))?
        .to_owned();
    let refresh_token = token.get("refresh_token").and_then(|v| v.as_str()).map(str::to_owned);
    Ok(Tokens { access_token, refresh_token })
}

/// Serve the loopback redirect until the authorization response arrives, then
/// return its `code`. Rejects a `state` that does not match the one sent.
/// `Ok(None)` = `cancel` was set while waiting.
fn wait_for_code(
    listener: &TcpListener,
    expected_state: &str,
    cancel: &AtomicBool,
) -> Result<Option<String>> {
    listener.set_nonblocking(true).context("setting the redirect listener non-blocking")?;
    let deadline = Instant::now() + LOGIN_TIMEOUT;

    loop {
        if cancel.load(Ordering::Relaxed) {
            return Ok(None);
        }
        if Instant::now() >= deadline {
            return Err(anyhow::Error::new(TimedOut));
        }
        match listener.accept() {
            Ok((stream, _)) => {
                // A browser fetches /favicon.ico and similar; only the request
                // carrying the OAuth parameters ends the wait.
                if let Some(result) = handle_redirect(stream, expected_state)? {
                    return Ok(Some(result));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(anyhow!("accepting the redirect connection: {e}")),
        }
    }
}

/// Parse one HTTP request. Returns `Some(code)` for the OAuth redirect,
/// `None` for anything else (favicon, etc.), and an error for an OAuth
/// `error=` response or a state mismatch.
fn handle_redirect(mut stream: TcpStream, expected_state: &str) -> Result<Option<String>> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut request_line = String::new();
    // Browsers speculatively open loopback connections and send nothing on them.
    // Such a socket must be dropped like a favicon probe, not treated as a failed
    // sign-in -- the real redirect may still be on its way.
    if BufReader::new(&stream).read_line(&mut request_line).is_err() {
        return Ok(None);
    }

    // "GET /?code=...&state=... HTTP/1.1"
    let path = request_line.split_whitespace().nth(1).unwrap_or("");
    let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");

    let mut code = None;
    let mut state = None;
    let mut oauth_error = None;
    for (key, value) in form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "code" => code = Some(value.into_owned()),
            "state" => state = Some(value.into_owned()),
            "error" => oauth_error = Some(value.into_owned()),
            _ => {}
        }
    }

    // Not the redirect (e.g. a favicon probe): answer politely and keep waiting.
    if code.is_none() && oauth_error.is_none() {
        respond(
            &mut stream,
            "Waiting for sign-in…",
            "Finish signing in in the window that just opened.",
            false,
        );
        return Ok(None);
    }

    respond(
        &mut stream,
        "You're signed in",
        "Sign-in complete -- you can close this tab and return to NAS Access.",
        true,
    );

    if let Some(err) = oauth_error {
        bail!("the identity provider returned an error: {err}");
    }
    // A returned state that does not match is a forged or replayed redirect.
    if state.as_deref() != Some(expected_state) {
        bail!("OAuth state did not match: rejecting a possibly forged redirect");
    }
    Ok(Some(code.expect("code present: checked above")))
}

fn respond(stream: &mut TcpStream, heading: &str, detail: &str, success: bool) {
    let body = page(heading, detail, success);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// The self-contained page the loopback server shows in the browser. It answers
/// exactly one request and then the process moves on, so everything is inline --
/// no external CSS, fonts or images to fetch. Theme-aware, and branded so the tab
/// plainly belongs to KerBridge rather than looking like a bare error page.
fn page(heading: &str, detail: &str, success: bool) -> String {
    let mark = if success { CHECK_MARK } else { SPINNER };
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n\
         <meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>KerBridge sign-in</title>\n<style>{PAGE_STYLE}</style>\n</head>\n\
         <body>\n<main class=\"card\">\n\
         <div class=\"brand\">KerBridge · NAS Access</div>\n{mark}\n\
         <h1>{heading}</h1>\n<p>{detail}</p>\n</main>\n</body>\n</html>"
    )
}

const CHECK_MARK: &str = "<svg class=\"mark\" viewBox=\"0 0 52 52\" aria-hidden=\"true\">\
    <circle cx=\"26\" cy=\"26\" r=\"24\"/><path d=\"M15 27l7 7 15-16\"/></svg>";
const SPINNER: &str = "<div class=\"spinner\" aria-hidden=\"true\"></div>";

const PAGE_STYLE: &str = r#"
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    font-family: -apple-system, "Segoe UI", Roboto, system-ui, sans-serif;
    background: #f3f3f6; color: #1a1a1a;
  }
  .card {
    background: #fff; border-radius: 16px; padding: 44px 40px;
    max-width: 380px; width: calc(100% - 32px); text-align: center;
    box-shadow: 0 10px 40px rgba(0,0,0,.10); border: 1px solid rgba(0,0,0,.05);
  }
  .brand {
    font-size: 13px; letter-spacing: .12em; text-transform: uppercase;
    color: #6a6a72; margin-bottom: 24px;
  }
  .mark { width: 64px; height: 64px; margin: 0 auto 20px; display: block; }
  .mark circle { fill: none; stroke: #2fa25a; stroke-width: 3; }
  .mark path { fill: none; stroke: #2fa25a; stroke-width: 4; stroke-linecap: round; stroke-linejoin: round; }
  .spinner {
    width: 40px; height: 40px; margin: 0 auto 20px; border-radius: 50%;
    border: 3px solid rgba(0,0,0,.12); border-top-color: #0067c0; animation: spin 1s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  h1 { font-size: 20px; font-weight: 600; margin: 0 0 8px; }
  p { font-size: 14px; line-height: 1.5; color: #55555c; margin: 0; }
  @media (prefers-color-scheme: dark) {
    body { background: #1e1e20; color: #f0f0f0; }
    .card { background: #2b2b2d; border-color: rgba(255,255,255,.06); box-shadow: 0 10px 40px rgba(0,0,0,.4); }
    .brand { color: #9a9aa2; }
    .mark circle, .mark path { stroke: #57c98a; }
    p { color: #b0b0b8; }
    .spinner { border-color: rgba(255,255,255,.14); border-top-color: #4cc2ff; }
  }
"#;

/// A URL-safe random string, used for the PKCE verifier and the state nonce.
fn random_urlsafe(bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).map_err(|e| anyhow!("system RNG failed: {e}"))?;
    Ok(b64url(&buf))
}

fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(extras: &[(&str, &str)]) -> OidcConfig {
        OidcConfig {
            client_id: "public-client".into(),
            display_name: "Example ID".into(),
            authority: "https://idp.example.site".into(),
            scopes: vec!["openid".into(), "profile".into()],
            extra_auth_params: extras
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            authorization_endpoint: "https://idp.example.site/authorize".into(),
            token_endpoint: "https://idp.example.site/token".into(),
            end_session_endpoint: None,
        }
    }

    /// The escape hatch reaches the authorization request without the IdP being
    /// named anywhere in this file.
    #[test]
    fn an_extra_parameter_the_broker_named_is_on_the_authorization_request() {
        let cfg = config(&[("access_type", "offline"), ("prompt", "consent")]);
        let pairs = query_of(&authorize_url(&cfg, "http://127.0.0.1:1234", "st", "ch"));

        assert!(pairs.contains(&("access_type".to_owned(), "offline".to_owned())));
        assert!(pairs.contains(&("prompt".to_owned(), "consent".to_owned())));
        assert!(pairs.contains(&("code_challenge".to_owned(), "ch".to_owned())));
        assert!(pairs.contains(&("scope".to_owned(), "openid profile".to_owned())));
    }

    /// `extra_auth_params` reaches here from an adapter's `client_config`, so a
    /// reserved name in it is an adapter's mistake rather than an attack -- but it
    /// still must not be the copy an authority reads.
    #[test]
    fn a_reserved_name_in_the_extras_cannot_displace_ours() {
        let cfg = config(&[
            ("state", "forged"),
            ("code_challenge_method", "plain"),
            ("code_challenge", "attacker-chosen"),
            ("redirect_uri", "https://elsewhere.example/"),
            ("client_id", "someone-else"),
            ("response_type", "token"),
            ("response_mode", "fragment"),
            ("scope", "nothing"),
        ]);
        let url = authorize_url(&cfg, "http://127.0.0.1:1234", "generated-state", "generated-ch");
        let pairs = query_of(&url);

        // Our own output, not an authority's behaviour: this asserts which copy
        // is last, and authorities differ on which one they then read. Measured
        // on authentik 2026.8.0: the last, for `state` and `code_challenge` both.
        for (name, ours) in [
            ("state", "generated-state"),
            ("code_challenge", "generated-ch"),
            ("code_challenge_method", "S256"),
            ("redirect_uri", "http://127.0.0.1:1234"),
            ("client_id", "public-client"),
            ("response_type", "code"),
            ("response_mode", "query"),
            ("scope", "openid profile"),
        ] {
            let last = pairs
                .iter()
                .rev()
                .find(|(k, _)| k == name)
                .unwrap_or_else(|| panic!("`{name}` is on the URL at all"));
            assert_eq!(last.1, ours, "the last `{name}` must be ours, not the extras'");
        }
    }

    fn query_of(url: &str) -> Vec<(String, String)> {
        let query = url.split_once('?').expect("the URL carries a query").1;
        form_urlencoded::parse(query.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    fn token(claims: serde_json::Value) -> String {
        format!("{}.{}.{}", b64url(b"{}"), b64url(claims.to_string().as_bytes()), b64url(b"sig"))
    }

    #[test]
    fn a_token_names_who_signed_in_and_nothing_else_does() {
        assert_eq!(
            token_account(&token(serde_json::json!({ "preferred_username": "riku@example.site" })))
                .as_deref(),
            Some("riku@example.site")
        );
        // v1.0 tokens spell it `upn`.
        assert_eq!(
            token_account(&token(serde_json::json!({ "upn": "riku@example.site" }))).as_deref(),
            Some("riku@example.site")
        );
        // Anything unreadable costs a shorter label, never a failed grant.
        assert_eq!(token_account(&token(serde_json::json!({ "oid": "1234" }))), None);
        assert_eq!(token_account("not.a.token"), None);
        assert_eq!(token_account(""), None);
    }
}
