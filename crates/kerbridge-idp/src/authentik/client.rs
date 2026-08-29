//! The live authentik directory client: an API token, and a full page-by-page
//! read of `/core/users/` and `/core/groups/`.
//!
//! Simpler than the Graph client, and deliberately: there is no cursor, no
//! delta and no server-chosen next link. Every URL is built here from the
//! instance URL and a page number, so the token is only ever sent to the
//! instance the operator configured -- there is nothing to guard the way Graph's
//! `@odata.nextLink` has to be guarded.
//!
//! Runtime rules that are not cosmetic:
//! - authentik **never returns 401**. A dead or absent credential is a `403`,
//!   and the `detail` string is the whole discriminator -- only "Token
//!   invalid/expired" is a non-counting rejection; "no permission" is a loud
//!   failure, because total loss of the grant must not read as an empty
//!   directory.
//! - A `5xx` or an unparseable body is reachability, not a verdict: back off and
//!   retry, and give up as [`SourceError::Unreachable`] only once no page has
//!   arrived for [`STALL_LIMIT`]. A large directory is not a fault and has no
//!   time bound.
//! - No `429`: no throttle applies to an authenticated read.

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
const USERS_QUERY: &str =
    "/api/v3/core/users/?ordering=pk&include_groups=false&include_roles=false&page_size=100";
/// The whole groups read: `include_users=false` for the same reason, keeping the
/// `users` and `children` id arrays.
const GROUPS_QUERY: &str = "/api/v3/core/groups/?ordering=pk&include_users=false&page_size=100";

/// Exponential-backoff ceiling for reachability trouble.
const BACKOFF_CAP: u64 = 300;
/// How long a read may make no progress before it is abandoned. Bounds the gap
/// between two pages, never the whole read, so it puts no limit on directory
/// size.
const STALL_LIMIT: Duration = Duration::from_secs(3 * BACKOFF_CAP);

pub struct AuthentikClient {
    http: reqwest::Client,
    /// The instance URL, scheme and host, trailing slash trimmed.
    base: String,
    token: String,
}

impl AuthentikClient {
    pub fn new(url: &str, token: String) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
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
                // A send or body error is the world being unreachable, not a
                // verdict -- treated exactly like a 5xx.
                Err(e) => PageOutcome::Retry(format!("GET {what} page {page_num}: {e:#}")),
            };
            match outcome {
                PageOutcome::Ready(page) => {
                    let next = page.pagination.next;
                    pages.push(page);
                    if next == 0 {
                        return Ok(pages);
                    }
                    page_num = next;
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
    /// carries the actual directory read.
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

/// One page's outcome, before the read decides whether to continue, retry or
/// stop.
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
/// Split out and pure so the corpus's five error shapes are exercised without a
/// server. The `detail` string is the whole discriminator among the 403s,
/// because authentik has no 401 to tell a dead credential from a missing grant.
fn classify<T: DeserializeOwned>(status: u16, body: &[u8]) -> PageOutcome<T> {
    if status == 200 {
        return match serde_json::from_slice::<Page<T>>(body) {
            Ok(page) => PageOutcome::Ready(page),
            // A 200 whose body is not a page is a proxy or a truncation, not a
            // directory: reachability, retried rather than parsed as empty.
            Err(e) => PageOutcome::Retry(format!("a 200 whose body is not a directory page: {e}")),
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
                "authentik refused the directory read (403 {detail:?}): the read is refused, not \
                 emptied, so this is a failure rather than an empty directory"
            ))
        };
    }
    if status >= 500 {
        return PageOutcome::Retry(format!(
            "authentik answered {status}: a 5xx is reachability, not a verdict on the credential \
             or the data"
        ));
    }
    // Nothing else is expected of an authenticated read; treat an unforeseen
    // status as a loud refusal rather than an empty directory.
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

    /// The class the seam draws from each outcome: only the rejection is spared
    /// from counting against the source. Driven through the shared conformance,
    /// which holds Entra's own classified errors to the same biconditional.
    #[test]
    fn only_a_rejected_credential_is_spared_from_counting() {
        // token_invalid rejects the credential (spared); no_permission and
        // not_provided refuse the read (counted) -- both sides of the rule.
        for name in ["err_403_token_invalid", "err_403_no_permission", "err_403_not_provided"] {
            conformance::credential_rejection_is_the_only_non_failure(&classified(name));
        }
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
