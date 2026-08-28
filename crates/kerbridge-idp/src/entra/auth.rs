//! Entra's token face: an access token reduced to an [`ExternalIdentity`].
//!
//! The verification policy is the one measured in research spike
//! `entra-token-validation`, whose ordering of the checks below is the one this
//! reproduces.
//!
//! Two properties are structural rather than checked, and both are held in
//! `crate::jwt` rather than here: the algorithm is never chosen by the token --
//! `alg` is resolved against the allowlist before any key is loaded, and the
//! only verification routine that half can reach is RSA, so the classic
//! confusions have no code path rather than merely a guard in front of them;
//! see the crate doc for why that rule is asymmetric-only rather than
//! RS256-only. And the clock is a parameter, not configuration.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use kerbridge_core::{ExternalIdentity, Source, is_guid};
use kerbridge_notify::Notifier;
use serde::Deserialize;

use super::{DEFAULT_LEEWAY_SECONDS, Settings, identity};
use crate::jwks::Jwks;
use crate::jwt::{self, Audience};
use crate::{IdentityProvider, OidcDiscovery, Reject, reject};

/// Everything about a configured Entra tenant that verification compares
/// against.
struct Policy {
    tenant_id: String,
    /// The one issuer this broker accepts, exact and tenant-specific -- the
    /// common `/common` and `/organizations` forms are a different tenant's
    /// tokens as far as this broker is concerned.
    ///
    /// A stored string, like any other adapter's, rather than something derived
    /// at comparison time. [`Settings::parse`] fills it in from the tenant when
    /// the file leaves `issuer` unset, because the form is fixed and
    /// live-verified: `https://login.microsoftonline.com/{tid}/v2.0`, research
    /// spike `entra-token-validation`.
    issuer: String,
    broker_api_client_id: String,
    public_client_id: String,
    required_scope: String,
    leeway_seconds: i64,
}

pub struct Entra {
    source: Source,
    policy: Policy,
    jwks: Jwks,
    discovery: OidcDiscovery,
}

impl Entra {
    pub(crate) async fn connect(
        settings: &Settings,
        source: &Source,
        notifier: Arc<Notifier>,
        timeout: Duration,
    ) -> Result<Self> {
        let jwks = Jwks::load(settings.jwks.clone(), source, timeout, notifier)
            .await
            .context("loading signing keys")?;
        Ok(Self {
            source: source.clone(),
            jwks,
            discovery: OidcDiscovery {
                authority: settings.authority.clone(),
                display_name: settings.display_name.clone(),
                client_id: settings.public_client_id.clone(),
                scopes: vec![
                    // Entra spells a delegated API permission this way; nothing
                    // outside this adapter knows that syntax.
                    format!("api://{}/{}", settings.broker_api_client_id, settings.scope),
                    "openid".into(),
                    "profile".into(),
                    // Silent re-injection needs a refresh token; the helper
                    // keeps it in memory only.
                    "offline_access".into(),
                ],
                extra_auth_params: Default::default(),
            },
            policy: Policy {
                issuer: settings.issuer.clone(),
                tenant_id: settings.tenant_id.clone(),
                broker_api_client_id: settings.broker_api_client_id.clone(),
                public_client_id: settings.public_client_id.clone(),
                required_scope: settings.scope.clone(),
                leeway_seconds: DEFAULT_LEEWAY_SECONDS,
            },
        })
    }
}

#[async_trait::async_trait]
impl IdentityProvider for Entra {
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
    iat: Option<i64>,
    ver: Option<String>,
    tid: Option<String>,
    oid: Option<String>,
    azp: Option<String>,
    scp: Option<String>,
    idtyp: Option<String>,
}

/// Verify a bearer token and reduce it to a provider-neutral identity.
///
/// `now` is unix seconds. Nothing downstream of this function ever sees an
/// Entra-specific claim.
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

    let iss = claims.iss.ok_or_else(|| reject("no iss"))?;
    let aud = claims.aud.ok_or_else(|| reject("no aud"))?;
    let exp = claims.exp.ok_or_else(|| reject("no exp"))?;
    let nbf = claims.nbf.ok_or_else(|| reject("no nbf"))?;
    if claims.iat.is_none() {
        return Err(reject("no iat"));
    }

    if now > exp + policy.leeway_seconds {
        return Err(reject("token has expired"));
    }
    if now + policy.leeway_seconds < nbf {
        return Err(reject("token is not valid yet"));
    }
    if !aud.accepts(&policy.broker_api_client_id) {
        return Err(reject("aud is not this broker"));
    }

    let tid = claims.tid.ok_or_else(|| reject("no tid"))?;
    if !is_guid(&tid) {
        return Err(reject("tid is not a GUID"));
    }
    if tid != policy.tenant_id {
        return Err(reject("tid is not the configured tenant"));
    }
    // A token states its tenant twice and both are pinned, because the issuer is
    // a configured string: an operator who moved `provider_config.issuer` off
    // its default has said which issuer this deployment trusts, and `tid` does
    // not imply it.
    if iss != policy.issuer {
        return Err(reject("iss is not the configured issuer"));
    }

    // v1 tokens carry a different issuer form and a different subject model.
    // The API app must set `requestedAccessTokenVersion: 2`; this is what
    // catches a deployment where it was left at the null default.
    if claims.ver.as_deref() != Some("2.0") {
        return Err(reject(format!("token version {:?} is not 2.0", claims.ver)));
    }

    // Real access control, not defense in depth: Entra issues app-only tokens with
    // this broker's audience to any confidential client in the tenant, with no
    // app role, consent or grant required. `scp` presence and `idtyp` are what
    // separate a user's delegated token from that.
    if claims.idtyp.as_deref() == Some("app") {
        return Err(reject("app-only token (idtyp=app)"));
    }
    let scp = claims.scp.ok_or_else(|| reject("no scp: not a delegated token"))?;
    if !scp.split(' ').any(|s| s == policy.required_scope) {
        return Err(reject("required delegated scope missing"));
    }

    if claims.azp.as_deref() != Some(policy.public_client_id.as_str()) {
        return Err(reject("azp is not the authorized public client"));
    }

    // Presence is this function's, shape is `identity`'s -- sync goes through it
    // too. The cause is interpolated, so an `oid` refused for its case says so.
    let oid = claims.oid.ok_or_else(|| reject("no oid"))?;
    identity(source, &oid).map_err(|e| reject(format!("oid is not a usable subject: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::JwksSource;
    use crate::conformance;
    use crate::entra::tests::{TENANT, USER_OID, fixture_dir, source};
    /// The positive fixture's own window. The corpus is expired by design -- a
    /// verifier that could only be tested while its fixtures were fresh would be
    /// untestable -- so the clock is supplied rather than read.
    ///
    /// Regenerating the corpus (`testbench/fixtures/entra-token/make_fixtures.py`,
    /// which stamps `iat`/`nbf`/`exp` from the wall clock) moves these. Read the
    /// new values off `positive_delegated.jwt` and update them here; nothing else
    /// in the suite hardcodes a timestamp.
    const FIXTURE_NBF: i64 = 1_786_350_604;
    const FIXTURE_EXP: i64 = 1_786_354_264;
    pub const VALID_AT: i64 = (FIXTURE_NBF + FIXTURE_EXP) / 2;

    fn policy() -> Policy {
        Policy {
            tenant_id: TENANT.into(),
            issuer: format!("https://login.microsoftonline.com/{TENANT}/v2.0"),
            broker_api_client_id: "11112222-bbbb-3333-cccc-4444dddd5555".into(),
            public_client_id: "22223333-cccc-4444-dddd-5555eeee6666".into(),
            required_scope: "access_as_user".into(),
            leeway_seconds: DEFAULT_LEEWAY_SECONDS,
        }
    }

    async fn jwks() -> Jwks {
        // The timeout is the network fetch's; a file source never reaches it.
        Jwks::load(
            JwksSource::File(fixture_dir().join("jwks.json")),
            &source(),
            std::time::Duration::from_secs(30),
            std::sync::Arc::new(kerbridge_notify::Notifier::disabled("broker")),
        )
        .await
        .unwrap()
    }

    /// The adapter as the broker holds it, without the environment `connect`
    /// would read: the discovery document is the one `connect` builds, so the
    /// conformance suite exercises the same object `POST /ticket` does.
    async fn entra() -> Entra {
        Entra {
            source: source(),
            policy: policy(),
            jwks: jwks().await,
            discovery: OidcDiscovery {
                authority: format!("https://login.microsoftonline.com/{TENANT}/v2.0"),
                display_name: "Entra".into(),
                client_id: policy().public_client_id,
                scopes: vec![
                    format!("api://{}/access_as_user", policy().broker_api_client_id),
                    "openid".into(),
                    "profile".into(),
                    "offline_access".into(),
                ],
                extra_auth_params: Default::default(),
            },
        }
    }

    pub fn token(name: &str) -> String {
        std::fs::read_to_string(fixture_dir().join(name)).unwrap().trim().to_owned()
    }

    async fn check(name: &str, now: i64) -> Result<ExternalIdentity, Reject> {
        entra().await.identify(&token(name), now).await
    }

    #[tokio::test]
    async fn accepts_the_delegated_token_and_reduces_it_to_an_identity() {
        let id = check("positive_delegated.jwt", VALID_AT).await.unwrap();
        assert_eq!(id.subject(), USER_OID);
        assert_eq!(id.source(), &source());
        // The exact bytes the broker will search Samba for, and the exact bytes
        // sync writes. A divergence here breaks every login.
        assert_eq!(id.encode(), format!("kb1|entra|{USER_OID}"));
    }

    /// The rest of the allowlist. Entra signs RS256, so nothing else in the
    /// suite would ever reach the other primitives -- and an algorithm nobody
    /// verifies a real signature with is an algorithm whose padding and digest
    /// pairing nobody has checked. This covers the workspace-wide allowlist.
    #[tokio::test]
    async fn accepts_every_allowlisted_algorithm() {
        for name in [
            "positive_rs384.jwt",
            "positive_rs512.jwt",
            "positive_ps256.jwt",
            "positive_ps384.jwt",
            "positive_ps512.jwt",
        ] {
            let id = check(name, VALID_AT).await.unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(id.subject(), USER_OID);
        }
    }

    /// The two faces of the adapter, held against each other. The broker builds
    /// an identity from a verified token; sync builds one from a Graph object
    /// id. They run in different processes with no channel between them, and
    /// nothing else in the workspace compares their output.
    #[tokio::test]
    async fn the_token_face_and_the_directory_face_agree_byte_for_byte() {
        let from_token = check("positive_delegated.jwt", VALID_AT).await.unwrap();
        let from_graph =
            crate::encode_identity(crate::Provider::Entra, &source(), USER_OID).unwrap();
        assert_eq!(from_token.encode(), from_graph.encode());
        assert_eq!(from_token, from_graph);
    }

    #[tokio::test]
    async fn meets_the_shared_conformance_suite() {
        conformance::run(
            &entra().await,
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
        let original = token("positive_delegated.jwt");
        let mut parts: Vec<&str> = original.split('.').collect();
        let claims = String::from_utf8(crate::b64url(parts[1]).unwrap()).unwrap();
        let swapped = claims.replace(USER_OID, "00000000-0000-0000-0000-000000000000");
        assert_ne!(swapped, claims, "the oid must actually have been substituted");
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
            ("neg_alg_hs256.jwt", "disallowed alg"),
            ("neg_alg_confusion.jwt", "disallowed alg"),
            ("neg_alg_unknown.jwt", "disallowed alg"),
            ("neg_unknown_kid.jwt", "unknown kid"),
            // Correctly signed with the right key material: only the key's
            // published `alg` refuses it.
            ("neg_alg_not_published_for_key.jwt", "is not published for alg"),
            ("neg_garbage.jwt", "not a three-part JWT"),
            ("neg_expired.jwt", "token has expired"),
            ("neg_future_nbf.jwt", "token is not valid yet"),
            ("neg_wrong_audience.jwt", "aud is not this broker"),
            ("neg_wrong_tenant.jwt", "tid is not the configured tenant"),
            // A v1 token addresses the API by its App ID URI rather than the
            // client GUID, so it fails on audience before version is reached.
            // That is the deployment symptom of `requestedAccessTokenVersion`
            // left at its null default.
            ("neg_v1_token.jwt", "aud is not this broker"),
            // Correct issuer, foreign tid: the tenant claims disagree.
            ("neg_iss_tid_mismatch.jwt", "tid is not the configured tenant"),
            ("neg_malformed_tid.jwt", "tid is not a GUID"),
            ("neg_app_only.jwt", "app-only token"),
            ("neg_missing_scope.jwt", "no scp"),
            ("neg_wrong_scope_value.jwt", "required delegated scope missing"),
            ("neg_wrong_azp.jwt", "azp is not the authorized public client"),
            ("neg_missing_oid.jwt", "no oid"),
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
    #[tokio::test]
    async fn expiry_is_enforced_against_the_supplied_clock() {
        let past = VALID_AT - 10_000;
        let future = VALID_AT + 10_000;
        assert!(check("positive_delegated.jwt", past).await.is_err());
        assert!(check("positive_delegated.jwt", future).await.is_err());
        // Inside the 300 s skew allowance on either side.
        assert!(check("positive_delegated.jwt", FIXTURE_EXP + 299).await.is_ok());
        assert!(check("positive_delegated.jwt", FIXTURE_NBF - 299).await.is_ok());
    }

    /// The discovery document names Entra's scope syntax, which nothing outside
    /// this adapter knows.
    #[tokio::test]
    async fn the_discovery_document_carries_the_delegated_scope() {
        let oidc = entra().await.client_config();
        assert!(
            oidc.scopes
                .contains(&"api://11112222-bbbb-3333-cccc-4444dddd5555/access_as_user".to_owned()),
            "{:?}",
            oidc.scopes
        );
        assert!(oidc.scopes.contains(&"offline_access".to_owned()), "refresh tokens");
        // Entra asks for a refresh token by scope, so it needs no request
        // parameters -- and an empty map is omitted from `GET /config`.
        assert!(oidc.extra_auth_params.is_empty());
    }
}
