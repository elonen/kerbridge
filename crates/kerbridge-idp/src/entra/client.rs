//! The live Microsoft Graph HTTP client: an app-only token, and paginated delta
//! reads with the exact retry, resync, and throttling behavior measured in
//! Research spike `entra-directory-sync` @1.2.
//!
//! Runtime rules that are mandatory, not cosmetic:
//! - Only `@odata.deltaLink` terminates a stream; an empty page with a
//!   `nextLink` is not the last page.
//! - `429` sleeps exactly `Retry-After` seconds and retries the *same* URL; a
//!   `5xx`, a network error, or a `429` with no header backs off exponentially.
//! - `410 Gone` carries a `Location` with an empty `$deltatoken` -- restart a
//!   full resync from it. A `400 "Badly formed token"` carries *no* `Location`;
//!   the stored cursor is corrupt, so it is discarded and the read restarts from
//!   a fresh delta, and the caller alerts. Only on a request that *carried* a
//!   cursor: a `400` on a URL built here from constants is a fault to surface,
//!   not a cursor to throw away.
//! - A read runs until the stream ends. Only a stall stops it early -- no page for
//!   [`STALL_LIMIT`] -- and that returns [`StreamResult::Stalled`], which the caller
//!   discards. A whole read has no time bound: a large tenant is not a fault, and a
//!   read that did not finish must not reach the planner.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use kerbridge_core::secret::Secret;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use url::Url;

use super::wire::{Page, RawGroup, RawUser};

const GRAPH: &str = "https://graph.microsoft.com/v1.0";
/// Exactly what the desired state is built from, and nothing else. A field nobody
/// decides on is tenant data read on every cycle for no reason.
///
/// A stored `deltaLink` bakes in the `$select` it was created with, so a deployment
/// upgrading across a change here keeps receiving the old field set until its next
/// full resync. That is harmless -- the wire structs ignore unknown fields -- but it
/// is why a *removal* cannot be assumed to take effect on the next cycle.
const USER_SELECT: &str =
    "id,displayName,userPrincipalName,mail,otherMails,accountEnabled,userType";
const GROUP_SELECT: &str = "id,displayName,members";
/// Exponential-backoff ceiling for header-less throttling and transient errors.
const BACKOFF_CAP_SECS: u64 = 300;
/// How long a read may make no progress before it is abandoned. Bounds the gap
/// between two pages, never the whole read, so it puts no limit on directory
/// (IdP) size. Set against the backoff ceiling, so a run of throttling is ridden out
/// rather than reported as a fault.
const STALL_LIMIT: Duration = Duration::from_secs(3 * BACKOFF_CAP_SECS);

pub struct GraphClient {
    http: reqwest::Client,
    tenant: String,
    client_id: String,
    secret: Secret,
}

/// A stored delta cursor after a completed stream read, or a signal that the
/// stream must be handled specially before it can complete.
#[derive(Debug)]
pub enum StreamResult<T> {
    /// The whole stream was read. `delta_link` is the cursor for next cycle
    /// (always present on a delta stream; absent only on a plain list).
    Complete { items: Vec<T>, delta_link: Option<String> },
    /// `410`: the cursor expired (>7 days). The caller resyncs fully. The Gone
    /// response's `Location` carries an empty `$deltatoken`, so a fresh `/delta`
    /// is equivalent and is what the caller starts from.
    Resync,
    /// `400`: the stored cursor is corrupt. Discard it, resync from a fresh
    /// delta, and alert -- this is local state corruption, not a Graph outage.
    CursorCorrupt,
    /// No page arrived for [`STALL_LIMIT`]. Graph is unreachable or is refusing
    /// every attempt; discard and produce no plan.
    Stalled,
}

/// A credential failure the caller must surface to an operator, kept distinct
/// from a transient Graph error so it can drive the expiry notifications.
#[derive(Debug)]
pub enum TokenError {
    /// `AADSTS7000222`: the credential has expired. Every Graph read is now dead.
    Expired(String),
    /// `AADSTS7000215`: the credential was rejected -- classically the *Secret
    /// ID* pasted in place of the secret *Value*.
    Invalid(String),
    /// Anything else: network, 5xx, an unrecognized `AADSTS` code.
    Other(anyhow::Error),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::Expired(d) => write!(f, "sync credential expired: {d}"),
            TokenError::Invalid(d) => write!(f, "sync credential rejected: {d}"),
            TokenError::Other(e) => write!(f, "{e:#}"),
        }
    }
}

enum Outcome<T> {
    Page(Page<T>),
    /// `429`: sleep this many seconds (if the header gave one) and retry.
    Throttled(Option<u64>),
    Resync,
    CursorCorrupt,
    /// `5xx`: transient, back off and retry.
    Transient,
}

/// Everything a cycle asks of Graph: a token and the two delta streams. Nothing
/// else in this crate speaks to the tenant.
///
/// [`GraphClient`] is the only implementation a deployment runs. The trait is
/// earned by testability alone -- the cycle's cursor recovery is otherwise
/// observable only against a live tenant. It is not a `DirectorySource`: that
/// boundary produces a desired state, this one produces the bytes one is built
/// from.
pub trait GraphReader {
    async fn acquire_token(&self) -> Result<String, TokenError>;

    /// Read the users stream. `cursor` is a stored `@odata.deltaLink`; `None`
    /// starts a fresh delta, whose first read returns the full user set.
    async fn read_users(&self, token: &str, cursor: Option<&str>) -> Result<StreamResult<RawUser>>;

    /// Read the groups stream, `members` included so membership edges arrive
    /// with the group. Group selection is filtered client-side afterwards.
    async fn read_groups(
        &self,
        token: &str,
        cursor: Option<&str>,
    ) -> Result<StreamResult<RawGroup>>;
}

impl GraphReader for GraphClient {
    /// Acquire an app-only access token by client credentials. A shared secret is
    /// the degraded option -- a bearer string with an expiry the operator has to
    /// track by hand; the preferred certificate path is not built yet.
    async fn acquire_token(&self) -> Result<String, TokenError> {
        let url = format!("https://login.microsoftonline.com/{}/oauth2/v2.0/token", self.tenant);
        let params = [
            ("client_id", self.client_id.as_str()),
            ("scope", "https://graph.microsoft.com/.default"),
            ("client_secret", self.secret.expose()),
            ("grant_type", "client_credentials"),
        ];
        let resp = self
            .http
            .post(&url)
            .form(&params)
            .send()
            .await
            .map_err(|e| TokenError::Other(e.into()))?;
        let status = resp.status();
        let bytes = resp.bytes().await.map_err(|e| TokenError::Other(e.into()))?;
        if status.is_success() {
            #[derive(Deserialize)]
            struct Resp {
                access_token: String,
            }
            let t: Resp = serde_json::from_slice(&bytes)
                .map_err(|e| TokenError::Other(anyhow!("parsing token response: {e}")))?;
            return Ok(t.access_token);
        }
        let desc = aadsts_description(&bytes);
        if desc.contains("AADSTS7000222") {
            Err(TokenError::Expired(desc))
        } else if desc.contains("AADSTS7000215") {
            Err(TokenError::Invalid(desc))
        } else {
            Err(TokenError::Other(anyhow!("token endpoint returned {status}: {desc}")))
        }
    }

    async fn read_users(&self, token: &str, cursor: Option<&str>) -> Result<StreamResult<RawUser>> {
        let start = cursor
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{GRAPH}/users/delta?$select={USER_SELECT}"));
        self.read_stream(token, &start).await
    }

    async fn read_groups(
        &self,
        token: &str,
        cursor: Option<&str>,
    ) -> Result<StreamResult<RawGroup>> {
        let start = cursor
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{GRAPH}/groups/delta?$select={GROUP_SELECT}"));
        self.read_stream(token, &start).await
    }
}

impl GraphClient {
    pub fn new(tenant: String, client_id: String, secret: Secret) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if same_origin(attempt.previous(), attempt.url()) {
                    // Delegate every other decision, including the ten-hop
                    // bound, to reqwest's normal policy. A redirect that stays
                    // on the origin is one Microsoft is entitled to make.
                    reqwest::redirect::Policy::default().redirect(attempt)
                } else {
                    attempt.error("refusing a redirect off the origin the request started on")
                }
            }))
            .build()
            .context("building the Graph HTTP client")?;
        Ok(Self { http, tenant, client_id, secret })
    }

    async fn get_page<T: DeserializeOwned>(&self, token: &str, url: &str) -> Result<Outcome<T>> {
        assert_graph_url(url)?;
        let resp = self
            .http
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .with_context(|| format!("GET {}", redact(url)))?;
        let status = resp.status().as_u16();
        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<u64>().ok());
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let bytes = resp.bytes().await.context("reading Graph response body")?;
        classify(status, retry_after, location, &bytes, carries_cursor(url))
    }

    async fn read_stream<T: DeserializeOwned>(
        &self,
        token: &str,
        start: &str,
    ) -> Result<StreamResult<T>> {
        let mut url = start.to_owned();
        let mut items = Vec::new();
        let mut backoff = 1u64;
        let mut last_page = Instant::now();
        loop {
            if last_page.elapsed() >= STALL_LIMIT {
                return Ok(StreamResult::Stalled);
            }
            match self.get_page::<T>(token, &url).await? {
                Outcome::Page(p) => {
                    items.extend(p.value);
                    match p.next_link {
                        Some(next) => {
                            url = next;
                            backoff = 1;
                            last_page = Instant::now();
                        }
                        // Only a deltaLink (or a plain list's end) terminates.
                        None => {
                            return Ok(StreamResult::Complete { items, delta_link: p.delta_link });
                        }
                    }
                }
                // Capped like the computed backoff, and for the same reason: this
                // is a number the server chose. Honoring an hour of it would sit
                // unresponsive for an hour, and the stall check above only runs
                // between sleeps.
                Outcome::Throttled(Some(secs)) => {
                    tokio::time::sleep(Duration::from_secs(secs.min(BACKOFF_CAP_SECS))).await;
                }
                Outcome::Throttled(None) | Outcome::Transient => {
                    tokio::time::sleep(Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(BACKOFF_CAP_SECS);
                }
                Outcome::Resync => return Ok(StreamResult::Resync),
                Outcome::CursorCorrupt => return Ok(StreamResult::CursorCorrupt),
            }
        }
    }
}

/// The scheme, host and path prefix every request must be under.
const GRAPH_HOST: &str = "graph.microsoft.com";
const GRAPH_PATH: &str = "/v1.0";

/// Refuse to send the Graph token anywhere but Graph.
///
/// Only the first URL of a stream is this crate's own; every one after it is
/// `@odata.nextLink` as the server wrote it, and the stored cursor a later cycle
/// resumes from is the same string read back from disk. The request carries a
/// bearer token issued for Graph and for the whole tenant's IdP directory, so a URL
/// pointing elsewhere is that token handed to whoever is there -- and the read
/// would then look like an ordinary empty page. Checked on every request rather
/// than where links are parsed, so a new call site cannot skip it.
///
/// Parsed rather than prefix-matched. A string comparison has to defend its own
/// boundary -- `https://graph.microsoft.com/v1.0.example/` shares the prefix
/// without being under it -- and the host has to be the whole host, not a suffix
/// of `graph.microsoft.com.example.test`. `Url` decides both, and it also
/// normalizes the case and any percent-encoding in the authority before the
/// comparison, which a `starts_with` never sees.
fn assert_graph_url(raw: &str) -> Result<()> {
    let refuse =
        || anyhow!("refusing to send the Graph token to {}, which is not Graph", redact(raw));
    let url = Url::parse(raw).map_err(|_| refuse())?;
    let ok = url.scheme() == "https"
        && url.host_str() == Some(GRAPH_HOST)
        && url.port().is_none()
        && (url.path() == GRAPH_PATH || url.path().starts_with(&format!("{GRAPH_PATH}/")));
    if ok { Ok(()) } else { Err(refuse()) }
}

/// Neither endpoint this client speaks to needs a redirect that leaves its own
/// origin, and [`assert_graph_url`] cannot see one: it runs before `send`, and
/// the hops `send` takes internally are never re-checked.
///
/// `reqwest` strips `Authorization` when the host or the effective port changes,
/// so a redirect to another host costs no token. The scheme is not part of that
/// comparison: `https://graph.microsoft.com` -> `http://graph.microsoft.com:443`
/// keeps host and effective port, so the token would travel in clear. And only
/// *headers* are stripped -- a 307 off the token endpoint re-posts the body,
/// which is the client secret. `Url::origin` compares scheme, host and effective
/// port together, which is the one rule both cases need.
fn same_origin(previous: &[Url], next: &Url) -> bool {
    previous.last().is_some_and(|url| url.origin() == next.origin())
}

/// A Graph URL with its cursor values elided, for anything that reaches a log.
///
/// A delta token is not a credential -- it is a resumption cursor -- but it is
/// tenant state, it is long enough to bury the part of the line that matters,
/// and error paths are the one place these URLs are printed at all. The endpoint
/// and the parameter names survive, which is the whole diagnostic; the opaque
/// blob does not. Applied to the refusal in `assert_graph_url` as well, where
/// the URL came from the *server* and is being printed precisely because it is
/// not trusted -- so this must also cope with a string that is not a URL at all.
///
/// Every parameter whose name ends in `token` is elided, not the two that are
/// known today: this runs on a URL the server chose, and a cursor arriving under
/// a name nobody anticipated should still not reach the log.
fn redact(raw: &str) -> String {
    let Ok(mut url) = Url::parse(raw) else {
        // Not parsable, so there is no query to walk. Printing it whole is the
        // point -- it is being logged precisely because it is not a Graph URL.
        return raw.to_owned();
    };
    let Some(query) = url.query() else {
        return raw.to_owned();
    };
    // Rebuilt from the raw query rather than through `query_pairs_mut`, which
    // form-encodes and would render every `$select` as `%24select`. What makes
    // this line worth printing is that a human can read the endpoint and the
    // parameter names off it, and it is never parsed again.
    let cleaned = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((k, _)) if k.to_ascii_lowercase().ends_with("token") => format!("{k}=..."),
            _ => pair.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("&");
    url.set_query(Some(&cleaned));
    url.into()
}

/// Does this URL carry a cursor there would be any point in discarding?
///
/// `$deltatoken` is a stored cursor from a previous cycle; `$skiptoken` is a
/// `nextLink` mid-stream. Either makes "the token is bad, throw it away" a
/// remedy. Neither present means the request was this crate's own first URL,
/// built from constants -- and a 400 on one of those is a fault to surface, not a
/// cursor to throw away, so this must not answer yes for the wrong reason. Read
/// off parsed parameter *names*, so a delta token whose opaque value happens to
/// contain the text `$skiptoken=` does not count as carrying one.
fn carries_cursor(url: &str) -> bool {
    let Ok(url) = Url::parse(url) else {
        return false;
    };
    url.query_pairs().any(|(k, _)| k == "$deltatoken" || k == "$skiptoken")
}

/// Graph refused the request itself, not the transport. `401` is an access token
/// Graph no longer accepts -- normally one that aged out during a long read, which
/// the next cycle's own token clears. `403` is a IdP directory permission the
/// application never had, which no retry fixes.
#[derive(Debug)]
pub(super) struct AuthRefused {
    status: u16,
    detail: String,
}

impl std::fmt::Display for AuthRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let why = if self.status == 401 {
            "Graph rejected the access token; a token is short-lived, so the next cycle's own \
             token normally clears this"
        } else {
            "Graph refused the read; grant the application User.Read.All and Group.Read.All, \
             then give admin consent"
        };
        write!(f, "{why} (HTTP {}: {})", self.status, self.detail)
    }
}

impl std::error::Error for AuthRefused {}

fn classify<T: DeserializeOwned>(
    status: u16,
    retry_after: Option<u64>,
    location: Option<String>,
    body: &[u8],
    carries_cursor: bool,
) -> Result<Outcome<T>> {
    match status {
        200 => Ok(Outcome::Page(serde_json::from_slice(body).context("parsing Graph page")?)),
        429 => Ok(Outcome::Throttled(retry_after)),
        410 => match location {
            // The Location's empty $deltatoken makes a fresh /delta equivalent,
            // so only its presence matters -- a 410 without one is malformed.
            Some(_) => Ok(Outcome::Resync),
            None => bail!("410 Gone without a Location header"),
        },
        // Only a request that *had* a cursor can have a corrupt one. The spike
        // measured this status against a garbage and a mutated `$deltatoken`
        // (research spike `entra-directory-sync` @1.2), and the remedy it prescribes is
        // to discard the stored cursor -- which does nothing for a 400 on a URL
        // built here from constants. Treating those alike hid the real cause: a
        // rejected `$select`, a permission Graph now answers differently, a
        // mistyped admission-group filter. The cycle would discard a cursor it did not
        // have, alert, resync, and be refused identically forever. Discriminated
        // on the request rather than on the error message, because the message
        // is Microsoft's prose and this must not turn on their wording.
        400 if carries_cursor => Ok(Outcome::CursorCorrupt),
        // Not a transport fault, so this must not read as one: the operator is
        // sent to the firewall for a consent they never gave.
        401 | 403 => {
            Err(AuthRefused { status, detail: String::from_utf8_lossy(body).into_owned() }.into())
        }
        s if (500..=599).contains(&s) => Ok(Outcome::Transient),
        s => bail!("unexpected Graph status {s}: {}", String::from_utf8_lossy(body)),
    }
}

/// The `error_description` from a token-endpoint error body, which is where the
/// `AADSTS` code lives.
fn aadsts_description(body: &[u8]) -> String {
    #[derive(Deserialize)]
    struct Err {
        #[serde(default)]
        error: String,
        #[serde(default)]
        error_description: String,
    }
    match serde_json::from_slice::<Err>(body) {
        Ok(e) if !e.error_description.is_empty() => e.error_description,
        Ok(e) => e.error,
        _ => String::from_utf8_lossy(body).into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> serde_json::Value {
        let path = format!(
            "{}/../../testbench/fixtures/graph-sync/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
    }

    fn is_page<T>(o: &Outcome<T>) -> bool {
        matches!(o, Outcome::Page(_))
    }

    #[test]
    fn the_token_only_ever_goes_to_graph() {
        assert!(assert_graph_url(&format!("{GRAPH}/users/delta?$skiptoken=x")).is_ok());
        assert!(assert_graph_url(GRAPH).is_ok());
        assert!(assert_graph_url(&format!("{GRAPH}?$top=1")).is_ok());
        for bad in [
            "https://graph.microsoft.com.example.test/v1.0/users",
            // The boundary a bare starts_with would let through.
            "https://graph.microsoft.com/v1.0.example.test/users",
            "http://graph.microsoft.com/v1.0/users",
            "https://evil.test/v1.0/users",
            "/v1.0/users",
            "",
            "not a url at all",
        ] {
            assert!(assert_graph_url(bad).is_err(), "{bad}");
        }
    }

    /// What parsing buys over a prefix comparison. Each of these is a string
    /// whose relationship to `GRAPH` a `starts_with` gets wrong in one direction
    /// or the other, and every one arrives as a `nextLink` the server wrote.
    #[test]
    fn the_authority_is_compared_as_an_authority_and_not_as_text() {
        // Userinfo: everything up to the `@` is credentials, not the host.
        assert!(assert_graph_url("https://graph.microsoft.com@evil.test/v1.0/users").is_err());
        // A port is a different endpoint even on the right host.
        assert!(assert_graph_url("https://graph.microsoft.com:8443/v1.0/users").is_err());
        // Percent-encoded separators do not smuggle a path past the check.
        assert!(assert_graph_url("https://evil.test/%2Fgraph.microsoft.com/v1.0/x").is_err());
        // A trailing dot is a distinct host to a resolver.
        assert!(assert_graph_url("https://graph.microsoft.com./v1.0/users").is_err());
        // Host case is not significant, and rejecting these would break a
        // perfectly good nextLink.
        assert!(assert_graph_url("https://GRAPH.MICROSOFT.COM/v1.0/users").is_ok());
    }

    /// The pairs that decide whether a redirect keeps the credential. Measured
    /// against reqwest 0.12: a host or effective-port change strips
    /// `Authorization`, and nothing else does.
    #[test]
    fn a_redirect_may_not_leave_the_origin_it_started_on() {
        let url = |s: &str| Url::parse(s).unwrap();
        let follows = |from: &str, to: &str| same_origin(&[url(from)], &url(to));

        assert!(follows(GRAPH, "https://graph.microsoft.com/beta/users/delta"));
        // The downgrade reqwest does not strip for: same host, and 443 either way.
        assert!(!follows(GRAPH, "http://graph.microsoft.com:443/v1.0/users"));
        assert!(!follows(GRAPH, "http://graph.microsoft.com/v1.0/users"));
        assert!(!follows(GRAPH, "https://graph.microsoft.com:8443/v1.0/users"));
        assert!(!follows(GRAPH, "https://evil.test/v1.0/users"));
        // The token POST: a 307 elsewhere would re-post the client secret.
        assert!(!follows("https://login.microsoftonline.com/t/oauth2/v2.0/token", GRAPH));
        assert!(!same_origin(&[], &url(GRAPH)));
    }

    /// The policy is on the client the rest of this file uses, not only in the
    /// predicate. Loopback, because `assert_graph_url` keeps every URL this
    /// client *chooses* off a test server -- only a redirect gets it there.
    #[tokio::test]
    async fn the_built_client_refuses_a_redirect_off_the_origin() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = axum::Router::new()
            .route(
                "/off",
                axum::routing::get(move || async move {
                    // Same address, same port, different host spelling.
                    redirect(&format!("http://localhost:{port}/hop"))
                }),
            )
            .route("/on", axum::routing::get(move || async move { redirect("/hop") }))
            .route("/hop", axum::routing::get(|| async { "{}" }));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = GraphClient::new("t".into(), "c".into(), Secret::new("s")).unwrap().http;
        let err = client
            .get(format!("http://127.0.0.1:{port}/off"))
            .send()
            .await
            .expect_err("a redirect off the origin was followed");
        assert!(err.is_redirect(), "{err}");

        let ok = client.get(format!("http://127.0.0.1:{port}/on")).send().await.unwrap();
        assert_eq!(ok.status(), 200);
    }

    fn redirect(to: &str) -> axum::response::Response {
        use axum::response::IntoResponse;
        (axum::http::StatusCode::FOUND, [(axum::http::header::LOCATION, to.to_owned())])
            .into_response()
    }

    #[test]
    fn a_page_is_parsed_and_terminates_only_on_delta_link() {
        let body =
            serde_json::to_vec(&fixture("groups_delta_init_page2")["response"]["body"]).unwrap();
        let out = classify::<RawGroup>(200, None, None, &body, true).unwrap();
        match out {
            Outcome::Page(p) => {
                assert_eq!(p.value.len(), 4);
                assert!(p.next_link.is_none());
                assert!(p.delta_link.is_some(), "final page carries the deltaLink");
            }
            _ => panic!("expected a page"),
        }
    }

    #[test]
    fn throttling_carries_the_retry_after_seconds() {
        let fx = fixture("throttled_429");
        let secs: u64 = fx["response"]["headers"]["Retry-After"].as_str().unwrap().parse().unwrap();
        let body = serde_json::to_vec(&fx["response"]["body"]).unwrap();
        match classify::<RawGroup>(429, Some(secs), None, &body, true).unwrap() {
            Outcome::Throttled(Some(10)) => {}
            _ => panic!("expected Throttled(10)"),
        }
    }

    #[test]
    fn gone_resyncs_from_location_but_needs_one() {
        let fx = fixture("delta_410_gone");
        let loc = fx["response"]["headers"]["Location"].as_str().unwrap().to_owned();
        let body = serde_json::to_vec(&fx["response"]["body"]).unwrap();
        assert!(matches!(
            classify::<RawGroup>(410, None, Some(loc), &body, true).unwrap(),
            Outcome::Resync
        ));
        assert!(
            classify::<RawGroup>(410, None, None, &body, true).is_err(),
            "410 with no Location is an error"
        );
    }

    #[test]
    fn a_corrupt_cursor_is_distinct_from_an_expired_one() {
        // 400 (badly formed token) is discard-and-resync-from-fresh, not the
        // 410 follow-Location path.
        assert!(matches!(
            classify::<RawGroup>(400, None, None, b"{}", true).unwrap(),
            Outcome::CursorCorrupt
        ));
        assert!(matches!(
            classify::<RawGroup>(503, None, None, b"{}", true).unwrap(),
            Outcome::Transient
        ));
        assert!(!is_page(&classify::<RawGroup>(400, None, None, b"{}", true).unwrap()));
    }

    #[test]
    fn a_400_with_no_cursor_to_discard_is_an_error_and_not_a_corrupt_cursor() {
        // The endless-resync case: a fresh delta URL this crate built itself is
        // refused, and "throw the cursor away" is not a remedy for it. The body
        // has to reach the operator instead.
        let body = br#"{"error":{"code":"BadRequest","message":"Invalid $select"}}"#;
        let Err(e) = classify::<RawGroup>(400, None, None, body, false) else {
            panic!("a 400 with no cursor must not be swallowed as CursorCorrupt");
        };
        let e = e.to_string();
        assert!(e.contains("Invalid $select"), "{e}");
        assert!(e.contains("400"), "{e}");
    }

    /// A refused read is not an unreachable one. `Unreachable` sends the
    /// operator to the network; both of these are answered in the portal.
    #[test]
    fn graph_refusing_the_read_is_named_and_not_reported_as_a_transport_fault() {
        let body = br#"{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges"}}"#;
        for (status, expect) in [(401u16, "access token"), (403, "User.Read.All")] {
            let Err(e) = classify::<RawUser>(status, None, None, body, false) else {
                panic!("{status} must not parse as a page");
            };
            assert!(e.downcast_ref::<AuthRefused>().is_some(), "{status}: must stay downcastable");
            let msg = e.to_string();
            assert!(msg.contains(expect), "{status}: {msg}");
            assert!(msg.contains("Insufficient privileges"), "{status}: body must reach it");
        }
    }

    #[test]
    fn a_cursor_is_recognized_on_either_kind_of_link() {
        assert!(carries_cursor(&format!("{GRAPH}/users/delta?$deltatoken=abc")));
        assert!(carries_cursor(&format!("{GRAPH}/groups/delta?$select=id&$skiptoken=abc")));
        assert!(!carries_cursor(&format!("{GRAPH}/users/delta?$select=id,displayName")));
        assert!(!carries_cursor(&format!("{GRAPH}/groups/delta?$select=id,members")));
    }

    /// A cursor is a parameter, not a substring. A delta token whose opaque
    /// value happens to spell one must not make a 400 on a first URL look like a
    /// corrupt cursor -- that misreading is what turns a rejected `$select` into
    /// an endless resync.
    #[test]
    fn a_cursor_is_read_off_a_parameter_name_and_not_the_text() {
        assert!(!carries_cursor(&format!("{GRAPH}/users/delta?$filter=x eq '$skiptoken=y'")));
        assert!(!carries_cursor(&format!("{GRAPH}/users?$select=notadeltatoken")));
        assert!(!carries_cursor("not a url at all"));
    }

    #[test]
    fn cursor_values_do_not_reach_a_log_line() {
        let opaque = "AbCdEf0123456789_the-opaque-blob";
        for url in [
            format!("{GRAPH}/users/delta?$deltatoken={opaque}"),
            format!("{GRAPH}/groups/delta?$skiptoken={opaque}&$top=1"),
            format!("{GRAPH}/users/delta?$select=id&$deltatoken={opaque}&$top=1"),
        ] {
            let r = redact(&url);
            assert!(!r.contains(opaque), "{r}");
            // Everything that made the line worth printing survives.
            assert!(r.starts_with(GRAPH), "{r}");
            assert!(r.contains("token=..."), "{r}");
        }
        // A URL with nothing to hide keeps every parameter it had.
        let plain = format!("{GRAPH}/users/delta?$select=id,displayName");
        assert!(redact(&plain).contains("$select=id,displayName"), "{}", redact(&plain));
        // Including the one that is being printed because it is *not* Graph.
        assert_eq!(redact("https://evil.test/v1.0/users"), "https://evil.test/v1.0/users");
        // And a string that is not a URL is printed as it arrived, since that is
        // the whole reason it reached a log line.
        assert_eq!(redact("not a url at all"), "not a url at all");
    }

    /// The cursor names are the server's to choose, so the rule is the shape of
    /// the name rather than a list of the two seen so far.
    #[test]
    fn any_parameter_named_like_a_token_is_elided() {
        let out = redact(&format!("{GRAPH}/users/delta?$nexttoken=SECRETVALUE&$top=1"));
        assert!(!out.contains("SECRETVALUE"), "{out}");
        assert!(out.contains("$top=1"), "{out}");
        // A parameter that merely mentions one is not a cursor and survives.
        let out = redact(&format!("{GRAPH}/users?$select=tokenCount"));
        assert!(out.contains("tokenCount"), "{out}");
    }

    #[test]
    fn aadsts_codes_are_extracted_from_the_error_body() {
        let expired =
            br#"{"error":"invalid_client","error_description":"AADSTS7000222: secret expired"}"#;
        assert!(aadsts_description(expired).contains("AADSTS7000222"));
    }
}
