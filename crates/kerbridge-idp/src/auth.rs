//! The token face: what a bearer credential is reduced to, and what a client
//! must be told to obtain one.
//!
//! The other face is [`encode_identity`](crate::encode_identity): the same
//! [`ExternalIdentity`], built from a directory object instead of a token. See
//! the crate doc for what a disagreement between the two costs.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use kerbridge_core::{ExternalIdentity, Source};
use kerbridge_notify::Notifier;
use serde::Serialize;

use crate::{IdpSettings, entra};

/// Bring up one source's adapter. The settings variant names the adapter, so a
/// caller cannot hand one provider's block to another's constructor.
///
/// Signing keys are fetched here, and a failure raises an operator notification
/// and then fails the process: nothing serves a request against keys it has not
/// got.
pub async fn connect(
    settings: &IdpSettings,
    source: &Source,
    notifier: Arc<Notifier>,
    timeout: Duration,
) -> Result<Box<dyn IdentityProvider>> {
    match settings {
        IdpSettings::Entra(settings) => {
            Ok(Box::new(entra::Entra::connect(settings, source, notifier, timeout).await?))
        }
        // A broker that came up without a token face would answer every
        // sign-in for this source with a 401 and say why nowhere.
        IdpSettings::Authentik(_) => bail!(
            "the authentik adapter cannot verify a token in this build -- remove {:?} from \
             main.sources, or run a build that carries its token face",
            source.name()
        ),
    }
}

/// What a client must be told to obtain a credential this provider accepts.
///
/// Served verbatim as the `oidc` half of the broker's `GET /config`, so a helper
/// bootstraps from a broker URL alone and stays ignorant of which IdP is behind
/// it.
#[derive(Debug, Clone, Serialize)]
pub struct OidcDiscovery {
    pub authority: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    /// What to call this IdP on screen, in the agent's own UI text.
    ///
    /// Published rather than compiled into the client, which knows no provider
    /// names: "Sign out of {idp}" has to read right beside whatever the user's
    /// browser just showed them. An adapter's product name is only the default --
    /// `provider_config.display_name` wins, because the name a workforce
    /// recognises is the one on their sign-in page, not the vendor's.
    pub display_name: String,
    /// Extra query parameters the client must put on the authorization request.
    ///
    /// Entra asks for a refresh token through the `offline_access` *scope*, and
    /// not every IdP takes it that way -- some want it as a parameter on the
    /// authorization request. One field here beats an IdP branch in the client.
    /// Omitted from the wire when empty, which is every Entra deployment.
    ///
    /// Never name a parameter the flow sets itself -- `client_id`,
    /// `response_type`, `redirect_uri`, `response_mode`, `scope`, `state`,
    /// `code_challenge`, `code_challenge_method`. The client appends its own
    /// after these, so a duplicate here costs a sign-in on any authority that
    /// reads the first of the two.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub extra_auth_params: BTreeMap<String, String>,
}

/// Why an identity proof was refused.
///
/// Carried to the log, never to the client: every variant collapses to 401 on
/// the wire, because telling a caller *which* check failed is telling them how
/// to pass it.
#[derive(Debug, PartialEq, Eq)]
pub struct Reject(pub String);

impl std::fmt::Display for Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub(crate) fn reject(msg: impl Into<String>) -> Reject {
    Reject(msg.into())
}

/// One cloud IdP, reduced to what the rest of KerBridge needs of it.
///
/// INVARIANT: the subject an adapter derives must be stable for the lifetime of
/// the account. It is encoded into `msDS-ExternalDirectoryObjectId`; a changed
/// subject orphans the AD object and detaches every file whose owner
/// `idmap_rid` derived from its SID. Unrecoverable, and silent. This is why
/// subject selection is never configurable -- it is compiled into the adapter.
///
/// INVARIANT: the [`Source`] an adapter builds identities against must be the
/// one this IdP's sync writes. Separate processes, no channel between them; a
/// disagreement breaks every login for that IdP and nothing reports it.
///
/// INVARIANT: the credential [`IdentityProvider::identify`] receives is opaque.
/// Nothing in this trait requires a JWT, nor a JWKS or an OIDC discovery
/// document behind it. An adapter verifies its IdP's credential however that
/// IdP works, and establishes trust in the key however that IdP publishes one
/// -- the seam is "prove an identity", not "validate a token". Only the `&str`
/// in the signature holds that open.
///
/// A helper two adapters come to share therefore stays private to this crate.
/// A public type is a contract: it makes every future adapter's protocol a
/// commitment this trait never asked for. ([`b64url`] is public for the
/// broker's device grant, which is no IdP adapter.)
#[async_trait::async_trait]
pub trait IdentityProvider: Send + Sync {
    fn client_config(&self) -> OidcDiscovery;

    /// Reduce a bearer credential to a provider-neutral identity.
    ///
    /// `now` is unix seconds -- always a parameter, never read from the clock.
    /// Tests pass a fixed instant because the committed fixtures are
    /// deliberately expired; a verifier that could only be tested while its
    /// fixtures were fresh would be untestable. There is no deployment in which
    /// a clock override is readable from the environment.
    async fn identify(&self, bearer: &str, now: i64) -> Result<ExternalIdentity, Reject>;
}

/// Base64url without padding, as every JOSE field is encoded.
pub fn b64url(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
}
