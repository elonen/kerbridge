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
use kerbridge_notify::{Event, Notifier, Severity};
use serde::Deserialize;
use tokio::sync::RwLock;

/// How long a fetched document is trusted. Refreshed early only on an unknown
/// `kid`, so a scheduled rollover costs no polling and an unscheduled one still
/// resolves within a request.
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
const ALGORITHMS: [(&str, &dyn ring::signature::VerificationAlgorithm); 6] = [
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
pub fn algorithm(alg: &str) -> Option<&'static dyn ring::signature::VerificationAlgorithm> {
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
    /// The startup fetch. A failure here is fatal and the process exits, which
    /// under `restart: unless-stopped` is a crash loop -- so it is also the one an
    /// operator is least likely to be told about by anything else, and it raises
    /// before it returns. The durable problem record is what keeps that loop from
    /// becoming an event flood: the second start finds the condition already
    /// reported and says nothing.
    pub async fn load(
        source: JwksSource,
        timeout: Duration,
        notifier: Arc<Notifier>,
    ) -> Result<Self> {
        let by_kid = match fetch(&source, timeout).await {
            Ok(keys) => keys,
            Err(e) => {
                notifier.send(idp_failure(&e, Severity::Error, "no signing keys at startup")).await;
                return Err(e);
            }
        };
        notifier.resolve("idp-keys-unavailable").await;
        notifier.resolve("idp-trust-failure").await;
        let now = Instant::now();
        Ok(Self {
            source,
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

    /// Run `f` against the key for `kid`, refreshing once if it is unknown.
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
                self.notifier.resolve("idp-keys-unavailable").await;
                self.notifier.resolve("idp-trust-failure").await;
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
                    // Still-valid cached keys mean logins work and this is a
                    // warning; past `MAX_AGE` they are no longer trusted and
                    // every login is failing, which is a different sentence.
                    let (severity, what) = if stale {
                        (Severity::Error, "the cached signing keys have expired")
                    } else {
                        (Severity::Warning, "serving cached signing keys")
                    };
                    self.notifier.send(idp_failure(&e, severity, what)).await;
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
fn idp_failure(error: &anyhow::Error, severity: Severity, what: &str) -> Event {
    let slug = if looks_like_a_trust_failure(error) {
        "idp-trust-failure"
    } else {
        "idp-keys-unavailable"
    };
    Event::new(slug, severity, format!("cannot fetch the IdP signing keys: {what}"))
        .detail(format!("{error:#}"))
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
        .timeout(timeout)
        .build()
        .context("building the JWKS HTTP client")
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
        out.insert(
            kid,
            RsaKey {
                modulus: crate::b64url(&n).context("JWKS modulus is not base64url")?,
                exponent: crate::b64url(&e).context("JWKS exponent is not base64url")?,
                alg: entry.alg,
            },
        );
    }
    if out.is_empty() {
        bail!("JWKS document contains no signing key this build can verify with");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

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
