//! authentik's token face: an access token reduced to an [`ExternalIdentity`].
//!
//! The policy below is the one `testbench/authentik/authcode.sh` measured
//! against a live 2026.8.0 provider, claim by claim. Where it differs from
//! Entra's it is because authentik differs, not because a second adapter had a
//! second opinion:
//!
//! - **`azp` is the strong claim, and it is an access-token check.**
//!   `to_dict()` ends in a blind `id_dict.update(self.claims)`
//!   (`id_token.py:155-165`), so a scope mapping on this provider can rewrite
//!   every claim in the token -- `aud` and `sub` included. `azp` and `uid` are
//!   written *after* that merge, and `azp` only in `to_access_token()`. So it is
//!   the one claim a mapping cannot forge, and an honest ID token carries none
//!   at all.
//! - **`nbf` is validated only if present.** authentik emits none, ever, so
//!   requiring one would refuse every token this provider issues.
//! - **No scope is checked.** On authentik a scope selects which mappings run;
//!   it is not an authorization decision, and there is no `api://` analogue to
//!   ask for. Admission is the group closure sync mirrors, as it is for every
//!   source.
//!
//! Structure, the algorithm allowlist, the key and the signature are
//! `crate::jwt`'s, shared with the Entra adapter: that half is the same
//! wherever a JWT arrives, and it is the half where a mistake is an
//! authentication bypass. The clock is a parameter, not configuration.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use kerbridge_core::{ExternalIdentity, Source};
use kerbridge_notify::Notifier;
use serde::Deserialize;

use super::{Settings, identity};
use crate::jwks::{Jwks, JwksSource};
use crate::jwt::{self, Audience};
use crate::{IdentityProvider, OidcDiscovery, Reject, reject};

/// Clock skew allowed on `exp` and on an `nbf` that is there to allow.
///
/// The same 300 s the Entra adapter allows, and for the same reason: skew is a
/// property of the two clocks rather than of the IdP, and an operator reading a
/// window in one broker log should not find a different one in the next.
/// authentik publishes no number of its own to follow instead.
const LEEWAY_SECONDS: i64 = 300;

/// What the agent asks for. `offline_access` is what makes authentik issue a
/// refresh token -- and it is dropped in silence unless the mapping is also
/// attached to the provider, which is why `check --online` asks about it.
/// `email` is deliberately absent: on authentik it adds `email_verified`,
/// hardcoded `False`, and nothing here reads either.
const SCOPES: [&str; 3] = ["openid", "profile", "offline_access"];

/// Everything about a configured authentik application that verification
/// compares against.
struct Policy {
    /// The one issuer this source accepts, exact -- **trailing slash
    /// included**. A stored string rather than something derived at comparison
    /// time, so a deployment behind a rewriting proxy can state its own.
    issuer: String,
    /// The one `aud` accepted. [`Settings`] defaults it to the client id.
    audience: String,
    /// The Provider's client id, which every access token must name in `azp`.
    /// Separate from [`Self::audience`] even though authentik makes them equal:
    /// the audience is what a mapping may rewrite, and this is what it may not.
    client_id: String,
    leeway_seconds: i64,
}

pub struct Authentik {
    source: Source,
    policy: Policy,
    jwks: Jwks,
    discovery: OidcDiscovery,
}

impl Authentik {
    pub(crate) async fn connect(
        settings: &Settings,
        source: &Source,
        notifier: Arc<Notifier>,
        timeout: Duration,
    ) -> Result<Self> {
        // Always the application's own live document. authentik publishes one,
        // so there is no `jwks_file` to fall back to and nothing to verify
        // against whatever happened to be on disk.
        let jwks =
            Jwks::load(JwksSource::Url(settings.jwks_url.clone()), source, timeout, notifier)
                .await
                .context("loading signing keys")?;
        Ok(Self {
            source: source.clone(),
            jwks,
            discovery: OidcDiscovery {
                authority: settings.authority.clone(),
                display_name: settings.display_name.clone(),
                client_id: settings.client_id.clone(),
                scopes: SCOPES.iter().map(|scope| (*scope).to_owned()).collect(),
                // authentik asks for a refresh token by scope, the way Entra
                // does, so the authorization request needs nothing added to it.
                extra_auth_params: Default::default(),
            },
            policy: Policy {
                issuer: settings.issuer.clone(),
                audience: settings.audience.clone(),
                client_id: settings.client_id.clone(),
                leeway_seconds: LEEWAY_SECONDS,
            },
        })
    }
}

#[async_trait::async_trait]
impl IdentityProvider for Authentik {
    fn client_config(&self) -> OidcDiscovery {
        self.discovery.clone()
    }

    async fn identify(&self, bearer: &str, now: i64) -> Result<ExternalIdentity, Reject> {
        verify(bearer, &self.source, &self.policy, &self.jwks, now).await
    }
}

#[derive(Deserialize)]
struct Claims {
    iss: Option<String>,
    aud: Option<Audience>,
    exp: Option<i64>,
    nbf: Option<i64>,
    azp: Option<String>,
    sub: Option<String>,
}

/// Verify a bearer token and reduce it to a provider-neutral identity.
///
/// `now` is unix seconds. Nothing downstream of this function ever sees an
/// authentik-specific claim.
async fn verify(
    token: &str,
    source: &Source,
    policy: &Policy,
    jwks: &Jwks,
    now: i64,
) -> Result<ExternalIdentity, Reject> {
    // Structure, the algorithm allowlist, the key and the signature are
    // `crate::jwt`'s, and the claims are not read until they hold. Everything
    // below is policy against a payload whose authenticity is established.
    let claims: Claims = jwt::verified_claims(token, jwks).await?;

    let exp = claims.exp.ok_or_else(|| reject("no exp"))?;
    if now > exp + policy.leeway_seconds {
        return Err(reject("token has expired"));
    }
    if not_yet_valid(claims.nbf, now, policy.leeway_seconds) {
        return Err(reject("token is not valid yet"));
    }

    // The audience before the issuer, because the neighbouring application's
    // token differs in both and the audience is what is wrong with it: under
    // the default per-provider issuer mode a token minted next door carries its
    // own `iss`, its own `aud` and its own `azp`, and "addressed to another
    // application" is the sentence an operator can act on.
    let aud = claims.aud.ok_or_else(|| reject("no aud"))?;
    if !aud.accepts(&policy.audience) {
        return Err(reject("aud is not this application"));
    }
    // Compared byte for byte, trailing slash and all: `get_issuer()` is
    // `reverse()` over a pattern that ends in one. What this catches on its own
    // is the "same identifier for all providers" issuer mode, which publishes
    // the bare instance root and stops telling one application from another.
    let iss = claims.iss.ok_or_else(|| reject("no iss"))?;
    if iss != policy.issuer {
        return Err(reject("iss is not the configured issuer"));
    }

    // The claim a scope mapping cannot reach, and the reason the two checks
    // above are not the whole audience story. Absent means an ID token: honest,
    // correctly signed, and not an authorization to act as anyone -- so the
    // words say which token was sent rather than that a claim is missing.
    match claims.azp.as_deref() {
        None => return Err(reject("no azp: an ID token is not an access token")),
        Some(azp) if azp != policy.client_id => {
            return Err(reject("azp is not this source's client"));
        }
        Some(_) => {}
    }

    // Presence is this function's, shape is `identity`'s -- sync goes through it
    // too. The cause is interpolated, so a `sub` refused for the provider's
    // subject mode says so rather than saying "not a subject".
    let sub = claims.sub.ok_or_else(|| reject("no sub"))?;
    identity(source, &sub).map_err(|e| reject(format!("sub is not a usable subject: {e}")))
}

/// `nbf`, honoured only when the token carries one.
///
/// authentik emits none, on any token, in any version, so requiring one would
/// refuse every token this provider issues -- and the corpus therefore has no
/// future-`nbf` fixture to state the other half with, because fabricating a
/// shape the IdP cannot produce would pin the fabrication. "Not emitted" is
/// still not "not honoured": a token that does carry one is held to it, which
/// is what this reads as a predicate rather than an `if let` in the middle of
/// `verify`.
fn not_yet_valid(nbf: Option<i64>, now: i64, leeway_seconds: i64) -> bool {
    nbf.is_some_and(|nbf| now + leeway_seconds < nbf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use crate::authentik::tests::{CLIENT_ID, SLUG, URL, USER_UUID, source};
    use crate::conformance;

    /// The positive fixture's own window. The corpus is expired by design -- a
    /// verifier that could only be tested while its fixtures were fresh would be
    /// untestable -- so the clock is supplied rather than read.
    ///
    /// Regenerating the corpus
    /// (`testbench/fixtures/authentik-token/make_fixtures.py`, which stamps
    /// `iat` and `exp` from the wall clock) moves these. Read the new values off
    /// `positive.jwt` and update them here; nothing else in this file hardcodes
    /// a timestamp.
    const FIXTURE_IAT: i64 = 1_787_953_108;
    const FIXTURE_EXP: i64 = 1_787_956_768;
    const VALID_AT: i64 = (FIXTURE_IAT + FIXTURE_EXP) / 2;

    /// Its own directory rather than a second application inside `entra-token`:
    /// `ci-stack.sh` regenerates that corpus live, into the tree it runs from,
    /// and would overwrite anything else that lived there.
    fn fixture_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testbench/fixtures/authentik-token")
    }

    fn policy() -> Policy {
        Policy {
            issuer: format!("{URL}/application/o/{SLUG}/"),
            audience: CLIENT_ID.into(),
            client_id: CLIENT_ID.into(),
            leeway_seconds: LEEWAY_SECONDS,
        }
    }

    async fn jwks_from(document: &str) -> Result<Jwks> {
        // The timeout is the network fetch's; a file source never reaches it.
        Jwks::load(
            JwksSource::File(fixture_dir().join(document)),
            &source(),
            Duration::from_secs(30),
            Arc::new(kerbridge_notify::Notifier::disabled("broker")),
        )
        .await
    }

    /// The adapter as the broker holds it, without the environment `connect`
    /// would read: the discovery document is the one `connect` builds, so the
    /// conformance suite exercises the same object `POST /ticket` does.
    async fn authentik() -> Authentik {
        Authentik {
            source: source(),
            policy: policy(),
            jwks: jwks_from("jwks.json").await.unwrap(),
            discovery: OidcDiscovery {
                authority: format!("{URL}/application/o/{SLUG}"),
                display_name: "authentik".into(),
                client_id: CLIENT_ID.into(),
                scopes: SCOPES.iter().map(|scope| (*scope).to_owned()).collect(),
                extra_auth_params: Default::default(),
            },
        }
    }

    fn token(name: &str) -> String {
        std::fs::read_to_string(fixture_dir().join(name)).unwrap().trim().to_owned()
    }

    /// One claim of a fixture, unverified. A test that rests on what a token
    /// does *not* carry reads the corpus here rather than asserting the shape it
    /// assumed.
    fn claim(name: &str, key: &str) -> Option<serde_json::Value> {
        let jwt = token(name);
        let payload = jwt.split('.').nth(1).expect("a three-part JWT");
        let claims: serde_json::Value =
            serde_json::from_slice(&crate::b64url(payload).unwrap()).unwrap();
        claims.get(key).cloned()
    }

    async fn check(name: &str, now: i64) -> Result<ExternalIdentity, Reject> {
        authentik().await.identify(&token(name), now).await
    }

    #[tokio::test]
    async fn accepts_the_access_token_and_reduces_it_to_an_identity() {
        let id = check("positive.jwt", VALID_AT).await.unwrap();
        assert_eq!(id.subject(), USER_UUID);
        assert_eq!(id.source(), &source());
        // The exact bytes the broker will search Samba for, and the exact bytes
        // sync writes. A divergence here breaks every login.
        assert_eq!(id.encode(), format!("kb1|authentik|{USER_UUID}"));
    }

    /// The two faces of the adapter, held against each other on a token this
    /// verifier actually accepted: the broker builds an identity from a verified
    /// token, sync from a directory `uuid`. `mod.rs` holds the same rule against
    /// itself on a bare string; this is it reached the way the broker reaches it.
    #[tokio::test]
    async fn the_token_face_and_the_directory_face_agree_byte_for_byte() {
        let from_token = check("positive.jwt", VALID_AT).await.unwrap();
        let from_directory =
            crate::encode_identity(crate::Provider::Authentik, &source(), USER_UUID).unwrap();
        assert_eq!(from_token.encode(), from_directory.encode());
        assert_eq!(from_token, from_directory);
    }

    #[tokio::test]
    async fn meets_the_shared_conformance_suite() {
        conformance::run(
            &authentik().await,
            &conformance::Forged {
                alg_none: &token("neg_alg_none.jwt"),
                alg_none_unknown_kid: &token("neg_alg_none_unknown_kid.jwt"),
                alg_hs256: &token("neg_alg_hs256.jwt"),
                alg_confusion: &token("neg_alg_confusion.jwt"),
                alg_unknown: &token("neg_alg_unknown.jwt"),
                unknown_kid: &token("neg_unknown_kid.jwt"),
                expired: &token("neg_expired.jwt"),
                wrong_audience: &token("neg_wrong_audience.jwt"),
                tampered: &tampered_positive(),
            },
            VALID_AT,
        )
        .await;
    }

    /// The positive fixture with one claim substituted and the payload
    /// re-encoded: everything about it is well-formed except the signature,
    /// which is over the bytes that used to be there.
    fn tampered_positive() -> String {
        let original = token("positive.jwt");
        let mut parts: Vec<&str> = original.split('.').collect();
        let claims = String::from_utf8(crate::b64url(parts[1]).unwrap()).unwrap();
        let swapped = claims.replace(USER_UUID, "00000000-0000-0000-0000-000000000000");
        assert_ne!(swapped, claims, "the sub must actually have been substituted");
        use base64::Engine as _;
        let reencoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(swapped.as_bytes());
        parts[1] = &reencoded;
        parts.join(".")
    }

    /// Every negative in the corpus, each with the rejection it must produce.
    /// Named individually rather than globbed so that a fixture appearing
    /// without a matching expectation fails the suite instead of being skipped.
    #[tokio::test]
    async fn rejects_every_negative_fixture() {
        let cases = [
            ("neg_alg_none.jwt", "disallowed alg"),
            ("neg_alg_none_unknown_kid.jwt", "disallowed alg"),
            // The provider a deployment gets by leaving the Signing Key unset:
            // `jwt_key` falls back to the client secret and HS256, and the JWKS
            // published beside it is the empty document below.
            ("neg_alg_hs256.jwt", "disallowed alg"),
            ("neg_alg_confusion.jwt", "disallowed alg"),
            ("neg_alg_unknown.jwt", "disallowed alg"),
            // The other end of the same setting: an Ed25519 Signing Key, whose
            // JWK the corpus publishes. Correctly signed by a key the document
            // carries, and refused for the algorithm before any key is looked
            // up -- which is the ordering the whole defense rests on.
            ("neg_alg_eddsa.jwt", "disallowed alg"),
            ("neg_unknown_kid.jwt", "unknown kid"),
            // Correctly signed with the right key material: only the key's
            // published `alg` refuses it.
            ("neg_alg_not_published_for_key.jwt", "is not published for alg"),
            ("neg_garbage.jwt", "not a three-part JWT"),
            ("neg_expired.jwt", "token has expired"),
            // The neighbouring application's own honest token. It differs in
            // `iss`, `aud` and `azp`, and what is wrong with it here is that it
            // was minted for somebody else.
            ("neg_wrong_audience.jwt", "aud is not this application"),
            // The "same identifier for all providers" issuer mode: the audience
            // is still this application's, and only the issuer says otherwise.
            ("neg_wrong_issuer.jwt", "iss is not the configured issuer"),
            // The claim a scope mapping cannot forge, disagreeing with the one
            // it can.
            ("neg_azp_mismatch.jwt", "azp is not this source's client"),
            // The ID token from the same sign-in: no `azp`, because authentik
            // writes it in `to_access_token()` only.
            ("neg_id_token.jwt", "an ID token is not an access token"),
            // `sub_mode` left at its default, whose whole symptom otherwise is
            // that nobody in the realm can sign in.
            ("neg_sub_hashed.jwt", "sub_mode"),
        ];
        let mut present: Vec<String> = std::fs::read_dir(fixture_dir())
            .unwrap()
            .filter_map(|e| {
                let name = e.unwrap().file_name().to_string_lossy().into_owned();
                name.starts_with("neg_").then_some(name)
            })
            .collect();
        present.sort();
        let mut covered: Vec<String> = cases.iter().map(|(n, _)| (*n).to_owned()).collect();
        covered.sort();
        assert_eq!(present, covered, "every negative fixture must have an expectation");

        for (name, expected) in cases {
            match check(name, VALID_AT).await {
                Ok(id) => panic!("{name} was accepted, yielding {id:?}"),
                Err(Reject(why)) => assert!(
                    why.contains(expected),
                    "{name}: expected a rejection mentioning {expected:?}, got {why:?}"
                ),
            }
        }
    }

    /// The signature is checked before any claim is read, so a token that is
    /// merely stale still has to be authentic.
    ///
    /// An authentik token carries no `nbf`, so `exp` is the *whole* window it
    /// has: a clock behind the IdP's accepts it, and only a clock past its
    /// expiry refuses it. That is the visible consequence of the rule below, and
    /// it is why the Entra suite's matching test has an assertion this one
    /// cannot.
    #[tokio::test]
    async fn expiry_is_enforced_against_the_supplied_clock() {
        assert_eq!(claim("positive.jwt", "nbf"), None, "authentik emits none, ever");
        assert!(check("positive.jwt", FIXTURE_IAT).await.is_ok());
        assert!(check("positive.jwt", FIXTURE_IAT - 10_000).await.is_ok());
        assert!(check("positive.jwt", VALID_AT + 10_000).await.is_err());
        // Inside the 300 s skew allowance.
        assert!(check("positive.jwt", FIXTURE_EXP + 299).await.is_ok());
        assert!(check("positive.jwt", FIXTURE_EXP + 301).await.is_err());
    }

    /// The other half of that rule, which no fixture can state: a token that
    /// does carry an `nbf` is held to it, and an absent one is not a future one.
    #[test]
    fn an_absent_nbf_is_not_a_future_one() {
        let now = 1_000_000;
        assert!(!not_yet_valid(None, now, LEEWAY_SECONDS));
        assert!(!not_yet_valid(Some(now - 1), now, LEEWAY_SECONDS));
        assert!(!not_yet_valid(Some(now + LEEWAY_SECONDS), now, LEEWAY_SECONDS));
        assert!(not_yet_valid(Some(now + LEEWAY_SECONDS + 1), now, LEEWAY_SECONDS));
    }

    /// `azp` is an access-token check, and the ID token is what proves it has to
    /// be: the same sign-in produces one with this application's `aud` and this
    /// person's `sub`, and no `azp` at all. An adapter that asked for `azp` on
    /// every token would refuse every honest ID token; one that did not ask for
    /// it at all would accept this in place of an authorization to act.
    #[tokio::test]
    async fn the_azp_check_is_an_access_token_check() {
        assert_eq!(claim("neg_id_token.jwt", "azp"), None);
        assert_eq!(claim("neg_id_token.jwt", "aud"), claim("positive.jwt", "aud"));
        assert_eq!(claim("neg_id_token.jwt", "sub"), claim("positive.jwt", "sub"));
        assert_eq!(claim("neg_id_token.jwt", "iss"), claim("positive.jwt", "iss"));

        let why = check("neg_id_token.jwt", VALID_AT).await.unwrap_err().to_string();
        assert!(why.contains("ID token"), "{why}");
    }

    /// `audience` and `issuer` are keys in the file; `azp` is pinned to the
    /// client id and is nobody's to state. So a file pointed at the neighbouring
    /// application -- its slug, its audience, this source's client id -- gets
    /// every claim it names to agree, and is still refused.
    ///
    /// That is the whole reason both `aud` and `azp` are checked: a scope
    /// mapping can put any audience on a token, and `azp` is written after the
    /// merge that would have to carry it.
    #[tokio::test]
    async fn azp_is_pinned_to_the_client_id_whatever_the_file_states() {
        let mut idp = authentik().await;
        idp.policy.audience = "wiki".into();
        idp.policy.issuer = format!("{URL}/application/o/wiki/");

        let why = idp.identify(&token("neg_wrong_audience.jwt"), VALID_AT).await.unwrap_err();
        assert!(why.to_string().contains("azp"), "{why}");
        // And this source's own token now fails, on the audience the file moved.
        let why = idp.identify(&token("positive.jwt"), VALID_AT).await.unwrap_err();
        assert!(why.to_string().contains("aud"), "{why}");
    }

    /// A provider with no Signing Key publishes `{}` -- no `keys` member at all
    /// -- and signs HS256 with the client secret. Both halves are in the corpus,
    /// and this is the one an operator meets first: the broker refuses to come
    /// up rather than starting with nothing to verify against.
    #[tokio::test]
    async fn a_provider_with_no_signing_key_publishes_a_document_that_will_not_load() {
        // `map` because a loaded document is not `Debug` and never reaches here.
        let refused =
            jwks_from("jwks_empty.json").await.map(|_| ()).expect_err("nothing to verify with");
        assert!(format!("{refused:#}").contains("JWKS"), "{refused:#}");
    }

    /// What the agent is told. No `api://` spelling, because authentik has no
    /// counterpart to it, and no extra authorization parameters, because the
    /// refresh token is asked for by scope.
    #[tokio::test]
    async fn the_discovery_document_carries_the_three_scopes_and_nothing_else() {
        let oidc = authentik().await.client_config();
        assert_eq!(oidc.scopes, ["openid", "profile", "offline_access"]);
        assert_eq!(oidc.client_id, CLIENT_ID);
        assert_eq!(oidc.authority, format!("{URL}/application/o/{SLUG}"));
        assert!(oidc.extra_auth_params.is_empty());
    }
}
