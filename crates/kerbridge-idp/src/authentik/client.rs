//! The live authentik IdP directory client: an API token, and a full page-by-page
//! read of `/core/users/` and `/core/groups/`.
//!
//! authentik has no cursor, delta, or server-selected next link. This client
//! builds each URL from the configured instance and a page number. It cannot
//! send the token to a host from a response.
//!
//! Runtime rules:
//! - authentik **never returns 401**. A dead or absent credential is a `403`,
//!   and the `detail` string is the whole discriminator -- only "Token
//!   invalid/expired" is a non-counting rejection; "no permission" is a loud
//!   failure. A missing grant must not read as an empty IdP directory.
//! - A `5xx` or an unparseable body is reachability, not a verdict: back off and
//!   retry, and give up as [`SourceError::Unreachable`] only once no page has
//!   arrived for [`STALL_LIMIT`]. This limit applies between pages, not to the
//!   complete read.
//! - No `429`: no throttle applies to an authenticated read.
//! - The page cursor is a number authentik computes, and nothing makes it
//!   advance. A `next` that does not is a not-whole read, never a page to fetch
//!   again -- see [`next_page`].

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::wire::Page;
use crate::sync::SourceError;

/// The whole users read: unfiltered (nothing narrows an account below the
/// admission closure), and `include_groups=false`/`include_roles=false` so the
/// object arrays come back null and the id arrays -- which the read consumes --
/// come back whole.
///
/// Measured on 2026.8.0: an `ordering` value the filter does not allow is
/// dropped rather than refused, and the read falls back to the model's default
/// -- `username` for users, `name` for groups. Both are mutable and neither is
/// append-only, so a typo in this one parameter is not a smaller version of the
/// right read; it is the least stable sort authentik has, and the response says
/// nothing. `pk` is honoured on both streams.
const USERS_QUERY: &str =
    "/api/v3/core/users/?ordering=pk&include_groups=false&include_roles=false&page_size=100";
/// The whole groups read: `include_users=false` for the same reason, keeping the
/// `users` and `children` id arrays.
const GROUPS_QUERY: &str = "/api/v3/core/groups/?ordering=pk&include_users=false&page_size=100";

/// Exponential-backoff ceiling for reachability trouble.
const BACKOFF_CAP: u64 = 300;
/// How long a read may make no progress before it is abandoned. Bounds the gap
/// between two pages, never the whole read, so it puts no limit on the directory
/// (IdP) size.
const STALL_LIMIT: Duration = Duration::from_secs(3 * BACKOFF_CAP);
/// How many pages one collection read may take before it is abandoned. At
/// `page_size=100` that is a million users, or a million groups -- past any real
/// IdP directory, and short of the unbounded walk a server whose `next` keeps rising
/// would otherwise get. [`STALL_LIMIT`] does not bound this: it measures the gap
/// between two pages, and every page that arrives resets it.
const MAX_PAGES: usize = 10_000;

pub struct AuthentikClient {
    http: reqwest::Client,
    /// The instance URL, scheme and host, trailing slash trimmed.
    base: String,
    token: String,
}

impl AuthentikClient {
    pub fn new(url: &str, token: String) -> Result<Self> {
        // The crate's shared client: rustls trusting native roots merged with the
        // webpki set, so `SSL_CERT_FILE` reaches an authentik behind an operator's
        // own CA -- the same trust the broker's JWKS fetch has. A bare builder here
        // would trust only whatever reqwest defaults to, and a private-CA authentik
        // would then read as unreachable, not untrusted.
        let http = crate::jwks::http_client(Duration::from_secs(30))
            .context("building the authentik HTTP client")?;
        Ok(Self { http, base: url.trim_end_matches('/').to_owned(), token })
    }

    pub async fn read_users(&self) -> Result<Vec<Page<super::wire::RawUser>>, SourceError> {
        self.read_all(USERS_QUERY, "users").await
    }

    pub async fn read_groups(&self) -> Result<Vec<Page<super::wire::RawGroup>>, SourceError> {
        self.read_all(GROUPS_QUERY, "groups").await
    }

    /// Read one whole collection, following the page-number cursor until it hits
    /// `0`. Reachability trouble is ridden out; a rejected or refused credential
    /// ends the read at once.
    async fn read_all<T: DeserializeOwned>(
        &self,
        query: &str,
        what: &str,
    ) -> Result<Vec<Page<T>>, SourceError> {
        let mut pages = Vec::new();
        let mut page_num: i64 = 1;
        let mut backoff = 1u64;
        let mut last_progress = Instant::now();
        loop {
            let url = format!("{}{}&page={}", self.base, query, page_num);
            let outcome = match self.get(&url).await {
                Ok((status, body)) => classify::<T>(status, &body),
                // A send or body error is reachability trouble, like a 5xx.
                Err(e) => PageOutcome::Retry(format!("GET {what} page {page_num}: {e:#}")),
            };
            match outcome {
                PageOutcome::Ready(page) => {
                    let next = page.pagination.next;
                    pages.push(page);
                    match next_page(page_num, next, pages.len(), what)
                        .map_err(SourceError::NotWhole)?
                    {
                        None => return Ok(pages),
                        Some(n) => page_num = n,
                    }
                    backoff = 1;
                    last_progress = Instant::now();
                }
                PageOutcome::Rejected(why) => return Err(SourceError::CredentialRejected(why)),
                PageOutcome::Refused(why) => return Err(SourceError::Credential(why)),
                PageOutcome::Retry(why) => {
                    if last_progress.elapsed() >= STALL_LIMIT {
                        return Err(SourceError::Unreachable(format!(
                            "{what} read abandoned: no page arrived for long enough to call the \
                             read stalled -- {why}"
                        )));
                    }
                    tokio::time::sleep(Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(BACKOFF_CAP);
                }
            }
        }
    }

    /// Best-effort headroom on the sync credential, in days, from the
    /// self-scoped `/core/tokens/` read. Advisory only: any trouble -- a refused
    /// read, a non-expiring token, an unreadable body -- answers `None`, because
    /// a countdown that could not be measured must never disturb the cycle that
    /// carries the actual IdP directory read.
    pub async fn measure_expiry(&self, now: u64) -> Option<i64> {
        let url = format!("{}/api/v3/core/tokens/?intent=api&page_size=100", self.base);
        let (status, body) = self.get(&url).await.ok()?;
        if status != 200 {
            return None;
        }
        super::measured_days(std::str::from_utf8(&body).ok()?, now)
    }

    async fn get(&self, url: &str) -> Result<(u16, Vec<u8>)> {
        let resp = self
            .http
            .get(url)
            .bearer_auth(&self.token)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        let status = resp.status().as_u16();
        let body = resp.bytes().await.context("reading the authentik response body")?;
        Ok((status, body.to_vec()))
    }
}

/// The page to ask for after the one just read, `None` once the read is whole,
/// or the reason it is not.
///
/// authentik is deployed behind a reverse proxy by design. A cache there that
/// ignores the query string answers every request with page 1's body, so `next`
/// comes back `2` for a page-2 request and stays `2`. Following it is an
/// unbounded loop with no sleep in it -- the stall clock is reset by every page
/// that arrives, and [`super::wire::assemble`]'s pk check would catch the
/// repeated rows but is never reached. So a cursor that does not advance ends
/// the read here rather than being fetched again.
fn next_page(page_num: i64, next: i64, read: usize, what: &str) -> Result<Option<i64>, String> {
    if next == 0 {
        return Ok(None);
    }
    if next <= page_num {
        return Err(format!(
            "torn {what} read: page {page_num} points at page {next}, which does not advance --              following it would ask for the same page forever"
        ));
    }
    if read >= MAX_PAGES {
        return Err(format!(
            "torn {what} read: {read} pages in and the cursor still advances, past the              {MAX_PAGES}-page ceiling a read is bounded by"
        ));
    }
    Ok(Some(next))
}

/// One page's outcome.
enum PageOutcome<T> {
    Ready(Page<T>),
    /// Reachability trouble: warn and retry. Never a verdict on the data.
    Retry(String),
    /// The credential was rejected. Reported on its own channel and never
    /// counted: the server is healthy, the fix is a rotation.
    Rejected(String),
    /// The read was refused for a reason that must be loud -- no permission, or
    /// no credential presented -- and so counts as a failure.
    Refused(String),
}

/// Map one HTTP response to a [`PageOutcome`].
///
/// The `detail` string distinguishes a dead credential from a missing grant.
/// authentik uses `403` for both and does not return `401`.
fn classify<T: DeserializeOwned>(status: u16, body: &[u8]) -> PageOutcome<T> {
    if status == 200 {
        return match serde_json::from_slice::<Page<T>>(body) {
            Ok(page) => PageOutcome::Ready(page),
            // An invalid 200 body can be a proxy error or truncation. Retry it;
            // do not parse it as an empty IdP directory.
            Err(e) => {
                PageOutcome::Retry(format!("a 200 whose body is not a IdP directory page: {e}"))
            }
        };
    }
    if status == 403 {
        let detail = detail_of(body);
        return if detail == "Token invalid/expired" {
            PageOutcome::Rejected(format!(
                "authentik rejected the sync credential (403 {detail:?}): the token is dead and \
                 rotates on expiry, so this will not heal until it is replaced"
            ))
        } else {
            // "You do not have permission ..." and "Authentication credentials
            // were not provided." both land here: a valid token with no grant,
            // or no token at all. Either way the read is refused, not emptied,
            // and total loss must be loud.
            PageOutcome::Refused(format!(
                "authentik refused the IdP directory read (403 {detail:?}): the read is refused, \
                 not emptied, so this is a failure rather than an empty IdP directory"
            ))
        };
    }
    if status >= 500 {
        return PageOutcome::Retry(format!(
            "authentik answered {status}: a 5xx is reachability, not a verdict on the credential \
             or the data"
        ));
    }
    // Treat an unexpected status as a refusal, not an empty IdP directory.
    PageOutcome::Refused(format!("authentik answered an unexpected {status}"))
}

/// The `detail` string of an authentik error body, or empty when there is none.
fn detail_of(body: &[u8]) -> String {
    #[derive(Deserialize)]
    struct Detail {
        detail: String,
    }
    serde_json::from_slice::<Detail>(body).map(|d| d.detail).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::authentik::wire::RawUser;
    use crate::sync::conformance;

    fn corpus(name: &str) -> Value {
        let path = format!(
            "{}/../../testbench/fixtures/authentik-directory/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
    }

    /// A response's status and body bytes, from a corpus file. The body is an
    /// object for the JSON shapes and a raw string for the non-JSON one, so the
    /// bytes are taken as authentik would have sent them.
    fn response(name: &str) -> (u16, Vec<u8>) {
        let file = corpus(name);
        let status = file["response"]["status"].as_u64().unwrap() as u16;
        let bytes = match &file["response"]["body"] {
            Value::String(html) => html.clone().into_bytes(),
            other => serde_json::to_vec(other).unwrap(),
        };
        (status, bytes)
    }

    /// The five error shapes, classified by status and `detail` alone, and a real
    /// page for contrast. The rejection is the one that must not count.
    #[test]
    fn the_error_shapes_classify_by_status_and_detail() {
        let (s, b) = response("err_403_token_invalid");
        assert!(matches!(classify::<RawUser>(s, &b), PageOutcome::Rejected(_)));

        for name in ["err_403_no_permission", "err_403_not_provided"] {
            let (s, b) = response(name);
            assert!(matches!(classify::<RawUser>(s, &b), PageOutcome::Refused(_)), "{name}");
        }

        for name in ["err_503_starting", "err_non_json_body"] {
            let (s, b) = response(name);
            assert!(matches!(classify::<RawUser>(s, &b), PageOutcome::Retry(_)), "{name}");
        }

        let (s, b) = response("users_page1");
        assert!(matches!(classify::<RawUser>(s, &b), PageOutcome::Ready(_)));
    }

    /// Only a rejected credential does not count as a source failure. The shared
    /// conformance test applies the same rule to Entra.
    #[test]
    fn only_a_rejected_credential_is_spared_from_counting() {
        for name in ["err_403_token_invalid", "err_403_no_permission", "err_403_not_provided"] {
            conformance::credential_rejection_is_the_only_non_failure(&classified(name));
        }
    }

    /// A cursor that does not advance ends the read instead of spinning on it,
    /// and a cursor that never stops advancing meets the ceiling.
    #[test]
    fn a_cursor_that_does_not_advance_ends_the_read() {
        assert!(matches!(next_page(1, 2, 1, "users"), Ok(Some(2))), "a cursor that advances");
        assert!(matches!(next_page(3, 0, 3, "users"), Ok(None)), "the terminating page");
        // A cache that ignores the query string: page 1's body answers a page-2
        // request, so `next` is 2 however many times it is asked.
        for (page_num, next) in [(2, 2), (2, 1), (2, -1)] {
            assert!(next_page(page_num, next, 2, "users").is_err(), "page {page_num} -> {next}");
        }
        assert!(next_page(1, 2, MAX_PAGES, "users").is_err(), "the page ceiling");
    }

    /// The [`SourceError`] the read builds from a classified 403, mapping each
    /// terminal [`PageOutcome`] onto its seam class the way [`AuthentikClient`]'s
    /// own read does.
    fn classified(name: &str) -> SourceError {
        let (s, b) = response(name);
        match classify::<RawUser>(s, &b) {
            PageOutcome::Rejected(why) => SourceError::CredentialRejected(why),
            PageOutcome::Refused(why) => SourceError::Credential(why),
            _ => panic!("{name} did not classify as a terminal error"),
        }
    }
}
