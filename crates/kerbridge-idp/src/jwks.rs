//! The signing keys the verifier trusts, and how they are refreshed.
//!
//! A token never selects its own key source: the source is configuration, and
//! the only thing a token contributes is a `kid` to look up. An unknown `kid`
//! may trigger one refresh -- that is how key rollover is survived -- but the
//! refresh is rate-limited, so a stream of tokens carrying invented `kid`s
//! cannot turn into a stream of outbound requests.
//!
//! The IdP is remote and outside the deployment, so a fetch of its document is
//! the one operation here that can be made to take forever by someone else.
//! It is bounded in both directions -- in time by the request timeout, in size
//! by [`MAX_DOCUMENT_BYTES`] -- and, just as important, no lock is held while it
//! runs: a stalled fetch must not be able to wedge `POST /ticket`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use kerbridge_core::Source;
use kerbridge_notify::{Event, Notifier, Severity};
use serde::Deserialize;
use tokio::sync::RwLock;

/// How old a cached document may be before a request tries to refresh it first.
/// Refreshed early only on an unknown `kid`, so a scheduled rollover costs no
/// polling and an unscheduled one still resolves within a request.
///
/// **A refresh trigger, not an expiry.** If that refresh fails, the keys already
/// held keep verifying -- see [`Jwks::with_key`].
const MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);
/// Floor between unknown-`kid` refreshes after a *successful* fetch. Without it
/// the refresh is a free outbound request for anyone who can reach `POST /ticket`.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Floor after a *failed* one, doubled per consecutive failure up to
/// `MIN_REFRESH_INTERVAL`. Deliberately much shorter, because a failure is not a
/// rate-limit signal: the case that produces one is a key rollover, where the
/// cache is guaranteed to miss and every `POST /ticket` fails until the next
/// attempt is allowed. Charging a one-second blip the full success interval turns
/// it into five minutes of refusing every login.
const FAILED_REFRESH_INTERVAL: Duration = Duration::from_secs(15);
/// How long [`Jwks::load`] keeps retrying a startup fetch that cannot connect
/// before it gives up. A reverse proxy that fronts the IdP and shares the
/// broker's network namespace cannot bind its listener until the broker process
/// is up, so the very first fetch can be refused through no fault of the
/// configuration -- and a process that exits on it takes that shared namespace
/// down before the proxy can bind. Long enough for the proxy to come up, short
/// enough that a genuinely unreachable IdP still surfaces as the crash loop the
/// eventual exit becomes under `restart: unless-stopped`.
pub(crate) const STARTUP_RETRY_BUDGET: Duration = Duration::from_secs(90);
/// Between startup retries. Short, so a proxy binding its listener is noticed
/// within a second or two.
const STARTUP_RETRY_INTERVAL: Duration = Duration::from_secs(2);
/// Ceiling on a fetched document. A tenant's real one is a few kilobytes; this
/// is the point past which the response is no longer a JWKS but a way to spend
/// the broker's memory.
const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

/// One RSA public key, already decoded from its base64url components.
pub struct RsaKey {
    pub modulus: Vec<u8>,
    pub exponent: Vec<u8>,
    /// The JWK's own `alg`, when it stated one. See [`RsaKey::pins`].
    pub alg: Option<String>,
}

impl RsaKey {
    /// Is this key published for something other than `alg`?
    ///
    /// RFC 7517 §4.4 makes `alg` on a JWK the algorithm the key is intended for.
    /// Honouring it is what keeps widening [`ALGORITHMS`] from also widening
    /// what any one already-published key may be used with.
    pub fn pins(&self, alg: &str) -> bool {
        self.alg.as_deref().is_some_and(|published| published != alg)
    }
}

/// Every signature algorithm this crate will verify with, and the `ring`
/// primitive each one names.
///
/// **Asymmetric by construction** -- see the crate doc for why that rule, and
/// not "RS256 only", is the thing being held. Every row is an RSA algorithm, so
/// every row is served by the one key type above and the one verification
/// routine in `entra.rs`. An algorithm over a different key type (`ES*`,
/// `EdDSA`) is a second key type and a second routine, not a row here.
///
/// The `RsaParameters` element type holds that rule at compile time: nothing
/// symmetric and nothing over another key type can be written into this table.
/// Widening it to `dyn VerificationAlgorithm` would give the rule back to
/// convention.
const ALGORITHMS: [(&str, &ring::signature::RsaParameters); 6] = [
    ("RS256", &ring::signature::RSA_PKCS1_2048_8192_SHA256),
    ("RS384", &ring::signature::RSA_PKCS1_2048_8192_SHA384),
    ("RS512", &ring::signature::RSA_PKCS1_2048_8192_SHA512),
    ("PS256", &ring::signature::RSA_PSS_2048_8192_SHA256),
    ("PS384", &ring::signature::RSA_PSS_2048_8192_SHA384),
    ("PS512", &ring::signature::RSA_PSS_2048_8192_SHA512),
];

/// The allowlist, in the only form anything may consult it: a caller cannot ask
/// whether an algorithm is permitted without being handed the very thing it
/// would verify with, so nothing can pass the check and then reach a different
/// primitive.
pub fn algorithm(alg: &str) -> Option<&'static ring::signature::RsaParameters> {
    ALGORITHMS.iter().find(|(name, _)| *name == alg).map(|&(_, primitive)| primitive)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwksSource {
    /// A local document. Used by the bench, and a legitimate deployment choice
    /// where the broker has no outbound path to the IdP.
    File(PathBuf),
    Url(String),
}

#[derive(Deserialize)]
struct JwksDocument {
    keys: Vec<JwkEntry>,
}

#[derive(Deserialize)]
struct JwkEntry {
    kty: String,
    kid: Option<String>,
    #[serde(rename = "use")]
    use_: Option<String>,
    alg: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

/// Consecutive failed refreshes before an operator hears about it. A single blip
/// is not news -- the backoff is short precisely because one is expected -- but a
/// run of them means the cached keys are all that is serving logins, and the IdP
/// rotating its signing key at that point breaks every one of them.
const ALERT_AFTER_FAILURES: u32 = 3;

pub struct Jwks {
    source: JwksSource,
    /// Which configured IdP these keys are for, and the subject both events
    /// below are keyed on. There is one `Jwks` per adapter instance, so a
    /// deployment listing two sources holds two of these.
    idp: Source,
    timeout: Duration,
    keys: RwLock<Keys>,
    /// Shared with `AppState` rather than threaded through `verify`, which has no
    /// business carrying a notification concern through it just to reach here.
    notifier: Arc<Notifier>,
}

struct Keys {
    by_kid: HashMap<String, RsaKey>,
    fetched_at: Instant,
    /// No refresh is attempted before this. Claimed pessimistically when one
    /// starts, then set from its outcome -- see `refresh`.
    retry_after: Instant,
    consecutive_failures: u32,
}

impl Jwks {
    /// The startup fetch. A connection failure is retried for up to
    /// `startup_retry`: the process stays up so a reverse proxy that shares its
    /// network namespace can bind the listener the fetch needs. A failure a wait
    /// cannot clear -- a missing file, an HTTP error status, a malformed document
    /// -- is fatal at once, and a connection failure becomes fatal once the budget
    /// is spent. A fatal return exits the process, which under
    /// `restart: unless-stopped` is a crash loop -- so it is also the one an
    /// operator is least likely to be told about by anything else, and it raises
    /// before it returns. The durable problem record is what keeps that loop from
    /// becoming an event flood: the second start finds the condition already
    /// reported and says nothing.
    pub async fn load(
        source: JwksSource,
        idp: &Source,
        timeout: Duration,
        startup_retry: Duration,
        notifier: Arc<Notifier>,
    ) -> Result<Self> {
        let deadline = Instant::now() + startup_retry;
        let by_kid = loop {
            match fetch(&source, timeout).await {
                Ok(keys) => break keys,
                Err(e) => {
                    if is_transient(&e) && Instant::now() + STARTUP_RETRY_INTERVAL <= deadline {
                        tokio::time::sleep(STARTUP_RETRY_INTERVAL).await;
                        continue;
                    }
                    notifier
                        .send(idp_failure(&e, idp, Severity::Error, "no signing keys at startup"))
                        .await;
                    return Err(e);
                }
            }
        };
        resolve_idp_failures(&notifier, idp).await;
        let now = Instant::now();
        Ok(Self {
            source,
            idp: idp.clone(),
            timeout,
            keys: RwLock::new(Keys {
                by_kid,
                fetched_at: now,
                retry_after: now + MIN_REFRESH_INTERVAL,
                consecutive_failures: 0,
            }),
            notifier,
        })
    }

    /// Run `f` against the key for `kid`, refreshing once if it is unknown or
    /// the document is older than [`MAX_AGE`].
    ///
    /// **A failed refresh does not withdraw the keys.** Whatever is cached still
    /// verifies, however old it is. Failing closed would stop every login in the
    /// realm whenever the IdP is unreachable, and an aged key is not an
    /// attacker's key: only the IdP ever held the private half, so a token
    /// signed with a retired key was issued while that key was live.
    /// `SECURITY.md`, "The token verifier is hand-written", records the choice.
    ///
    /// Takes a closure rather than handing out the key because the key lives
    /// behind the lock; cloning a modulus per request to avoid that would be
    /// pure waste.
    pub async fn with_key<T>(&self, kid: &str, f: impl FnOnce(&RsaKey) -> T) -> Option<T> {
        {
            let keys = self.keys.read().await;
            if let Some(key) = keys.by_kid.get(kid)
                && keys.fetched_at.elapsed() < MAX_AGE
            {
                return Some(f(key));
            }
        }
        self.refresh().await;
        let keys = self.keys.read().await;
        keys.by_kid.get(kid).map(f)
    }

    /// Best-effort. A failed refresh keeps the keys already held: an IdP
    /// metadata outage must not invalidate tokens the broker can still verify.
    ///
    /// The three phases are separate on purpose. Pushing `retry_after` out under
    /// the write lock is what *claims* the refresh, and it happens before the
    /// fetch so that the fetch itself can run with no lock held. A request that
    /// arrives while one is in flight therefore sees the claim, returns at once,
    /// and is denied on the `kid` it could not find -- rather than queueing
    /// behind a write lock held across a network call, which is how one stalled
    /// IdP connection used to become every `POST /ticket` stalling with it. The
    /// unknown-`kid` path is a key rollover, so the request that loses this race
    /// succeeds on its retry.
    ///
    /// The claim is pessimistic -- a full `MIN_REFRESH_INTERVAL`, because at that
    /// point the outcome is unknown -- and the outcome then *shortens* it again if
    /// the fetch failed. Setting it only from the outcome would leave the in-flight
    /// window unclaimed and bring the stall back; leaving it at the claim, as this
    /// used to, charged a transient failure the whole success interval.
    async fn refresh(&self) {
        {
            let keys = self.keys.read().await;
            if Instant::now() < keys.retry_after {
                return;
            }
        }
        {
            let mut keys = self.keys.write().await;
            if Instant::now() < keys.retry_after {
                return;
            }
            keys.retry_after = Instant::now() + MIN_REFRESH_INTERVAL;
        }
        match fetch(&self.source, self.timeout).await {
            Ok(fresh) => {
                {
                    let mut keys = self.keys.write().await;
                    keys.by_kid = fresh;
                    keys.fetched_at = Instant::now();
                    keys.retry_after = Instant::now() + MIN_REFRESH_INTERVAL;
                    keys.consecutive_failures = 0;
                }
                // Outside the guard: the whole point of this module is that no
                // lock is held across an await.
                resolve_idp_failures(&self.notifier, &self.idp).await;
            }
            Err(e) => {
                let (failures, backoff, stale) = {
                    let mut keys = self.keys.write().await;
                    keys.consecutive_failures = keys.consecutive_failures.saturating_add(1);
                    let backoff = failure_backoff(keys.consecutive_failures);
                    keys.retry_after = Instant::now() + backoff;
                    (keys.consecutive_failures, backoff, keys.fetched_at.elapsed() >= MAX_AGE)
                };
                eprintln!(
                    "[broker] JWKS refresh failed, keeping cached keys, next attempt in {}s: {e:#}",
                    backoff.as_secs()
                );
                if failures >= ALERT_AFTER_FAILURES {
                    // Logins work in both cases -- `with_key` does not withdraw
                    // an aged key. What escalates is how long the deployment has
                    // been authenticating on keys nothing could confirm. Neither
                    // sentence may say "expired" or "failing": an operator who
                    // reads that goes hunting an outage that is not happening.
                    let (severity, what) = if stale {
                        (Severity::Error, "serving signing keys long past the refresh limit")
                    } else {
                        (Severity::Warning, "serving cached signing keys")
                    };
                    self.notifier.send(idp_failure(&e, &self.idp, severity, what)).await;
                }
            }
        }
    }
}

/// Which of the two IdP conditions this failure is, as one event ready to send.
///
/// They are separate because the fixes are: a trust failure is a stale root
/// bundle or something terminating the connection, and no amount of waiting
/// clears it; an unreachable IdP is a network problem that may clear itself.
///
/// The source is the subject and is also spelled into the message: the webhook
/// template has `%MESSAGE%` and no `%SUBJECT%`, so the sentence is the only
/// place an operator learns which IdP stopped answering.
fn idp_failure(error: &anyhow::Error, idp: &Source, severity: Severity, what: &str) -> Event {
    let slug = if looks_like_a_trust_failure(error) {
        "idp-trust-failure"
    } else {
        "idp-keys-unavailable"
    };
    Event::new(slug, severity, format!("cannot fetch the signing keys for source {idp}: {what}"))
        .subject(idp.name())
        .detail(format!("{error:#}"))
}

/// Both conditions cleared for one source, and for no other.
///
/// `resolve` would clear every subject the event holds, which is right for a
/// condition whose subject describes the symptom and wrong here: a fetch proves
/// only the IdP it fetched from reachable.
async fn resolve_idp_failures(notifier: &Notifier, idp: &Source) {
    notifier.resolve_subject("idp-keys-unavailable", idp.name()).await;
    notifier.resolve_subject("idp-trust-failure", idp.name()).await;
}

/// Does this look like a trust decision rather than a network one?
///
/// There is no typed answer to ask for: `reqwest` reports a failed TLS handshake
/// as a connect error like any other, and the certificate detail survives only as
/// text in the source chain. So this reads that chain, and is a heuristic on
/// purpose -- both outcomes raise an event, and all that rides on it is which of
/// the two sentences an operator gets.
fn looks_like_a_trust_failure(error: &anyhow::Error) -> bool {
    const MARKERS: [&str; 5] =
        ["certificate", "tls handshake", "unknownissuer", "self-signed", "notvalidforname"];
    error.chain().any(|cause| {
        let text = cause.to_string().to_ascii_lowercase();
        MARKERS.iter().any(|marker| text.contains(marker))
    })
}

/// Whether a fetch failure is one a short wait can clear: the connection was
/// refused or the request timed out. A missing file, an HTTP error status, or a
/// malformed document will not fix itself on a retry, so those stay fatal at
/// once -- only [`Jwks::load`]'s startup retry consults this.
fn is_transient(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<reqwest::Error>())
        .any(|e| e.is_connect() || e.is_timeout())
}

/// `FAILED_REFRESH_INTERVAL` doubled per consecutive failure, capped at
/// `MIN_REFRESH_INTERVAL`: a blip costs seconds, while an IdP that is genuinely
/// down settles at the same one-attempt-per-five-minutes the success path allows.
fn failure_backoff(consecutive_failures: u32) -> Duration {
    let doublings = consecutive_failures.saturating_sub(1).min(5);
    FAILED_REFRESH_INTERVAL.saturating_mul(1 << doublings).min(MIN_REFRESH_INTERVAL)
}

/// The IdP is the one trust anchor outside the deployment, so its roots are
/// taken from the OS trust store (the image's `ca-certificates` bundle, which
/// an operator updates with `apk` without recompiling this binary) rather than
/// frozen into the binary. `webpki` stays compiled in as the fallback for a
/// host with no bundle; enabling both merges the two root sets.
///
/// The timeout covers the whole exchange -- connect, TLS, headers and body --
/// because every one of those is a place a remote host can simply stop
/// answering, and only a deadline that spans all of them bounds a fetch.
pub(crate) fn http_client(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_native_certs(true)
        .tls_built_in_webpki_certs(true)
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if is_https_downgrade(attempt.previous(), attempt.url()) {
                attempt.error("refusing HTTPS to HTTP redirect")
            } else {
                // Delegate every other decision, including the ten-hop bound,
                // to reqwest's normal policy. HTTPS redirects remain useful for
                // IdP migrations; only the transport downgrade is forbidden.
                reqwest::redirect::Policy::default().redirect(attempt)
            }
        }))
        .timeout(timeout)
        .build()
        .context("building the JWKS HTTP client")
}

/// A chain that has established TLS must never hand the next request (and, for
/// the directory client, its bearer credential) to plaintext HTTP.
fn is_https_downgrade(previous: &[reqwest::Url], next: &reqwest::Url) -> bool {
    previous.last().is_some_and(|url| url.scheme() == "https") && next.scheme() == "http"
}

async fn fetch(source: &JwksSource, timeout: Duration) -> Result<HashMap<String, RsaKey>> {
    let body = match source {
        JwksSource::File(path) => std::fs::read_to_string(path)
            .with_context(|| format!("reading JWKS from {}", path.display()))?,
        JwksSource::Url(url) => {
            let response = http_client(timeout)?
                .get(url)
                .send()
                .await
                .with_context(|| format!("fetching JWKS from {url}"))?
                .error_for_status()?;
            bounded_body(response).await.with_context(|| format!("reading JWKS from {url}"))?
        }
    };
    parse(&body)
}

/// Read a response body, refusing one that grows past [`MAX_DOCUMENT_BYTES`].
///
/// Accumulated chunk by chunk rather than through `text()`, which would buffer
/// whatever arrives: `Content-Length` is the sender's claim about the body, not
/// a limit on it, so a cap that trusted the header would not be a cap.
pub(crate) async fn bounded_body(mut response: reqwest::Response) -> Result<String> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > MAX_DOCUMENT_BYTES {
            bail!("document is larger than the {MAX_DOCUMENT_BYTES} byte limit");
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).context("document is not UTF-8")
}

pub fn parse(body: &str) -> Result<HashMap<String, RsaKey>> {
    let doc: JwksDocument = serde_json::from_str(body).context("parsing JWKS document")?;
    let mut out = HashMap::new();
    for entry in doc.keys {
        // A key this verifier could never select is dropped here rather than
        // carried and rejected later.
        if entry.kty != "RSA" || entry.use_.as_deref().unwrap_or("sig") != "sig" {
            continue;
        }
        if entry.alg.as_deref().is_some_and(|a| algorithm(a).is_none()) {
            continue;
        }
        let (Some(kid), Some(n), Some(e)) = (entry.kid, entry.n, entry.e) else {
            continue;
        };
        let key = RsaKey {
            modulus: crate::b64url(&n).context("JWKS modulus is not base64url")?,
            exponent: crate::b64url(&e).context("JWKS exponent is not base64url")?,
            alg: entry.alg,
        };
        // Two usable entries under one kid make the token's own `kid` ambiguous,
        // and a map would resolve it by document order. Which key verified a
        // token must never depend on that, so the document is refused whole
        // rather than one of the pair being picked. Entries dropped above do not
        // collide: they were never selectable.
        if out.insert(kid.clone(), key).is_some() {
            bail!("JWKS document publishes two usable keys under kid {kid:?}");
        }
    }
    if out.is_empty() {
        bail!("JWKS document contains no signing key this build can verify with");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_policy_refuses_only_a_tls_downgrade() {
        let https = reqwest::Url::parse("https://idp.example/old").unwrap();
        let next_https = reqwest::Url::parse("https://idp.example/new").unwrap();
        let plaintext = reqwest::Url::parse("http://idp.example/new").unwrap();
        let initial_http = reqwest::Url::parse("http://127.0.0.1/old").unwrap();

        assert!(is_https_downgrade(std::slice::from_ref(&https), &plaintext));
        assert!(!is_https_downgrade(std::slice::from_ref(&https), &next_https));
        assert!(!is_https_downgrade(&[initial_http], &plaintext));
    }

    /// The two IdP conditions are told apart by reading the error chain, because
    /// nothing types the answer. A stale root bundle and an unplugged network
    /// have different fixes, so the classification is the whole value of raising
    /// two events instead of one.
    #[test]
    fn a_certificate_failure_is_told_apart_from_an_unreachable_idp() {
        let trust = [
            anyhow::anyhow!("invalid peer certificate: UnknownIssuer"),
            anyhow::anyhow!("tls handshake eof"),
            anyhow::anyhow!("invalid peer certificate: NotValidForName"),
            // The shape it actually arrives in: wrapped, with the useful part
            // several levels down the chain rather than in the top message.
            anyhow::anyhow!("boom")
                .context("invalid peer certificate: Expired")
                .context("fetching"),
        ];
        for e in &trust {
            assert!(looks_like_a_trust_failure(e), "{e:#}");
        }

        let reachability = [
            anyhow::anyhow!("tcp connect error: Network unreachable (os error 101)"),
            anyhow::anyhow!("operation timed out"),
            anyhow::anyhow!("dns error: failed to lookup address information"),
            anyhow::anyhow!("the JWKS document is 2 MiB"),
        ];
        for e in &reachability {
            assert!(!looks_like_a_trust_failure(e), "{e:#}");
        }
    }

    /// The point of splitting the two intervals: a failed refresh must not buy
    /// the quiet period a successful one does. A key rollover is exactly when the
    /// cache misses, so the interval a failure charges is the length of the
    /// outage it causes -- and it still has to converge on the success interval,
    /// or an IdP that is genuinely down gets hammered.
    #[test]
    fn a_failed_refresh_backs_off_from_seconds_to_the_success_interval() {
        assert_eq!(failure_backoff(1), FAILED_REFRESH_INTERVAL, "one blip costs seconds");
        assert_eq!(failure_backoff(2), FAILED_REFRESH_INTERVAL * 2);
        assert_eq!(failure_backoff(3), FAILED_REFRESH_INTERVAL * 4);
        // Doubling stops at the success interval and stays there, however long
        // the IdP is down -- and `0` cannot underflow into a huge shift.
        assert_eq!(failure_backoff(0), FAILED_REFRESH_INTERVAL);
        for failures in 5..1000 {
            assert!(failure_backoff(failures) <= MIN_REFRESH_INTERVAL, "{failures}");
        }
        assert_eq!(failure_backoff(999), MIN_REFRESH_INTERVAL);
    }

    /// The startup retry waits only on a failure a wait can clear. A missing file
    /// is permanent, so it must fall straight through -- retrying it would turn a
    /// mistyped path into a full-budget hang before the same error.
    #[tokio::test]
    async fn a_missing_file_is_not_a_transient_failure() {
        let missing =
            fetch(&JwksSource::File("/nonexistent/jwks.json".into()), Duration::from_secs(1))
                .await
                .err()
                .expect("a missing file must fail to fetch");
        assert!(!is_transient(&missing));
        assert!(!is_transient(&anyhow::anyhow!("a plain error carries no reqwest cause")));
    }

    /// The fail-open `with_key` documents: a document past `MAX_AGE` whose
    /// refresh cannot succeed still verifies. Asserting it is what stops a later
    /// reading of `MAX_AGE` as an expiry from quietly becoming one -- that change
    /// would break this test rather than every login in a deployment whose IdP
    /// went unreachable for a day.
    #[tokio::test]
    async fn an_aged_document_still_verifies_when_the_refresh_fails() {
        // A host booted less than MAX_AGE ago cannot express the instant, and
        // the property does not depend on the wall clock. Nothing to assert.
        let Some(aged) = Instant::now().checked_sub(MAX_AGE + Duration::from_secs(1)) else {
            return;
        };
        let body =
            std::fs::read_to_string(crate::entra::tests::fixture_dir().join("jwks.json")).unwrap();
        let jwks = Jwks {
            // Unreadable, so the refresh `with_key` triggers is certain to fail.
            source: JwksSource::File("/nonexistent/jwks.json".into()),
            idp: crate::entra::tests::source(),
            timeout: Duration::from_secs(1),
            keys: RwLock::new(Keys {
                by_kid: parse(&body).unwrap(),
                fetched_at: aged,
                // In the past, so `retry_after` does not skip the attempt.
                retry_after: aged,
                consecutive_failures: 0,
            }),
            notifier: Arc::new(kerbridge_notify::Notifier::disabled("broker")),
        };

        assert_eq!(
            jwks.with_key("fixture-key-2026-07", |key| key.modulus.len()).await,
            Some(256),
            "an aged document was withdrawn -- MAX_AGE is a refresh trigger, not an expiry"
        );
    }

    /// Two sources are two conditions. One `Jwks` per adapter instance means an
    /// unkeyed `resolve` on the second source's startup fetch announces a
    /// recovery for the first source's outage while that outage still runs.
    #[tokio::test]
    async fn a_second_source_does_not_resolve_the_first_one_s_outage() {
        let dir = std::env::temp_dir().join(format!("kb-jwks-subject-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let cfg =
            kerbridge_core::config::Notify { state_dir: Some(dir.clone()), ..Default::default() };
        let notifier = Arc::new(Notifier::from_config("broker", &cfg, "EXAMPLE.SITE").unwrap());

        let missing = JwksSource::File("/nonexistent/jwks.json".into());
        let fixture = JwksSource::File(crate::entra::tests::fixture_dir().join("jwks.json"));
        let second = Duration::from_secs(1);
        let broken = Source::new("broken").unwrap();
        let working = Source::new("working").unwrap();
        assert!(
            Jwks::load(missing, &broken, second, Duration::ZERO, notifier.clone()).await.is_err()
        );
        Jwks::load(fixture, &working, second, Duration::ZERO, notifier.clone()).await.unwrap();

        let open: Vec<serde_json::Value> = std::fs::read_dir(dir.join("broker"))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("problem-"))
            .map(|e| serde_json::from_str(&std::fs::read_to_string(e.path()).unwrap()).unwrap())
            .collect();
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(open.len(), 1, "{open:?}");
        assert_eq!(open[0]["event"], "idp-keys-unavailable");
        assert_eq!(open[0]["subject"], "broken", "the outage is still the broken source's");
    }

    #[test]
    fn parses_the_fixture_document() {
        let body =
            std::fs::read_to_string(crate::entra::tests::fixture_dir().join("jwks.json")).unwrap();
        let keys = parse(&body).unwrap();
        let key = &keys["fixture-key-2026-07"];
        assert_eq!(key.exponent, vec![0x01, 0x00, 0x01]);
        assert_eq!(key.modulus.len(), 256, "2048-bit modulus");
        assert_eq!(key.alg.as_deref(), Some("RS256"));
    }

    #[test]
    fn drops_keys_that_could_never_be_selected() {
        let doc = r#"{"keys":[
            {"kty":"oct","kid":"symmetric","k":"AAAA"},
            {"kty":"RSA","kid":"encryption","use":"enc","n":"AQAB","e":"AQAB"},
            {"kty":"EC","kid":"elliptic","alg":"ES256","x":"AQAB","y":"AQAB"},
            {"kty":"RSA","kid":"wrong-alg","alg":"RS1","n":"AQAB","e":"AQAB"},
            {"kty":"RSA","kid":"keeper","alg":"PS256","n":"AQAB","e":"AQAB"}
        ]}"#;
        let keys = parse(doc).unwrap();
        assert_eq!(keys.keys().collect::<Vec<_>>(), vec!["keeper"]);
    }

    /// A duplicate kid is refused, and only a duplicate the verifier could
    /// select: an entry this build drops was never a candidate, so a kid it
    /// shares with a usable key is not ambiguous.
    #[test]
    fn refuses_two_usable_keys_under_one_kid() {
        let doc = |second: &str| {
            format!(
                r#"{{"keys":[
                    {{"kty":"RSA","kid":"shared","alg":"RS256","n":"AQAB","e":"AQAB"}},
                    {second}
                ]}}"#
            )
        };
        let dup = r#"{"kty":"RSA","kid":"shared","alg":"RS256","n":"AQAB","e":"AQAB"}"#;
        let Err(why) = parse(&doc(dup)) else { panic!("a duplicate kid was accepted") };
        assert!(why.to_string().contains("two usable keys under kid \"shared\""), "{why}");

        for harmless in [
            r#"{"kty":"RSA","kid":"shared","use":"enc","n":"AQAB","e":"AQAB"}"#,
            r#"{"kty":"EC","kid":"shared","alg":"ES256","x":"AQAB","y":"AQAB"}"#,
            r#"{"kty":"RSA","kid":"shared","alg":"RS1","n":"AQAB","e":"AQAB"}"#,
        ] {
            let keys = parse(&doc(harmless)).unwrap_or_else(|e| panic!("{harmless}: {e}"));
            assert_eq!(keys.len(), 1);
        }
    }

    /// The allowlist is asymmetric-only and that is the rule, not its current
    /// length -- so this asserts what may never appear rather than pinning the
    /// set. A symmetric entry here would be an authentication bypass.
    #[test]
    fn the_allowlist_admits_no_symmetric_algorithm() {
        for (name, _) in ALGORITHMS {
            assert!(!name.starts_with("HS"), "{name} is symmetric");
        }
        for refused in ["HS256", "HS384", "HS512", "none", "", "rs256"] {
            assert!(algorithm(refused).is_none(), "{refused} resolved to a primitive");
        }
    }

    /// A key that names no `alg` is available to every allowlisted algorithm;
    /// one that names an `alg` is available only to that one.
    #[test]
    fn a_key_is_pinned_by_the_alg_it_was_published_for() {
        let doc = r#"{"keys":[
            {"kty":"RSA","kid":"pinned","alg":"RS256","n":"AQAB","e":"AQAB"},
            {"kty":"RSA","kid":"open","n":"AQAB","e":"AQAB"}
        ]}"#;
        let keys = parse(doc).unwrap();
        assert!(keys["pinned"].pins("RS384"));
        assert!(!keys["pinned"].pins("RS256"));
        assert!(!keys["open"].pins("RS384"));
    }

    #[test]
    fn refuses_a_document_with_nothing_usable() {
        assert!(parse(r#"{"keys":[]}"#).is_err());
    }

    /// Built from an `http::Response` rather than served over a socket: the
    /// limit is about what the body is allowed to be, and a real server would
    /// only add a way for the test to be flaky.
    fn response(body: &str) -> reqwest::Response {
        reqwest::Response::from(http::Response::new(body.to_owned()))
    }

    #[tokio::test]
    async fn reads_a_body_that_is_within_the_limit() {
        assert_eq!(bounded_body(response(r#"{"keys":[]}"#)).await.unwrap(), r#"{"keys":[]}"#);
    }

    #[tokio::test]
    async fn refuses_a_body_past_the_limit() {
        let err = bounded_body(response(&"x".repeat(MAX_DOCUMENT_BYTES + 1))).await.unwrap_err();
        assert!(format!("{err:#}").contains("larger than"), "{err:#}");
    }

    /// The failure this is really about is the one where nothing fails: a host
    /// that completes the connection and then never answers. Without a deadline
    /// spanning the whole exchange, this call does not return.
    #[tokio::test]
    async fn a_host_that_stops_answering_does_not_hang_the_fetch() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/keys", listener.local_addr().unwrap());
        // Accepted connections are held, not dropped -- a closed socket is an
        // error the client would return on its own, which is not the case here.
        tokio::spawn(async move {
            let mut open = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                open.push(socket);
            }
        });

        let started = Instant::now();
        let Err(err) = fetch(&JwksSource::Url(url), Duration::from_millis(250)).await else {
            panic!("a host that never answered produced keys");
        };
        assert!(started.elapsed() < Duration::from_secs(5), "waited {:?}", started.elapsed());
        assert!(format!("{err:#}").contains("fetching JWKS"), "{err:#}");
    }
}
