//! The Entra adapter: access-token verification, the discovery document a
//! client needs, and the subject encoding sync shares.
//!
//! The verification policy is the one measured in research spike
//! `entra-token-validation`, whose ordering of the checks below is the one this
//! reproduces.
//!
//! Two properties are structural rather than checked. The algorithm is never
//! chosen by the token -- `alg` is resolved against the allowlist before any key
//! is loaded, and the only verification routine in this file is RSA, so the
//! classic confusions have no code path to reach rather than merely a guard in
//! front of them; see the crate doc for why that rule is asymmetric-only rather
//! than RS256-only. And the clock is a parameter, not configuration.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use kerbridge_core::{ExternalIdentity, IdentityError, Source, is_guid};
use kerbridge_notify::Notifier;
use serde::Deserialize;

use crate::jwks::{self, Jwks, JwksSource, RsaKey};
use crate::{IdentityProvider, OidcDiscovery, Probe, Reject, Verdict, b64url, reject};

/// Per Microsoft.IdentityModel's `DefaultClockSkew`.
pub const DEFAULT_LEEWAY_SECONDS: i64 = 300;

/// The identity this adapter stores for an Entra object id.
///
/// **Bare `oid`.** The tenant is a property of the source, not of the object,
/// and shorter is strictly safer against the attribute's 256-character ceiling.
/// Changing this encoding later orphans every object in this source, so it is
/// not a knob: it was decided once, deliberately, and moving it is a migration
/// and not an edit.
///
/// **The subject rule lives here.** Both faces reach it -- the broker through
/// [`verify`], sync from a Graph object -- so one rule holds for both. `oid`
/// must be a canonical GUID: the two are compared byte for byte, and Entra
/// emitting one object id in two spellings orphans the account.
pub fn identity(source: &Source, oid: &str) -> Result<ExternalIdentity, IdentityError> {
    if !is_guid(oid) {
        return Err(IdentityError::SubjectShape("a GUID in canonical lowercase form"));
    }
    ExternalIdentity::new(source, oid)
}

/// Entra's product name: what the agent says on screen unless the deployment
/// renames it.
const PRODUCT_NAME: &str = "Entra";

/// The delegated scope the Broker API exposes unless the operator named it
/// something else.
const DEFAULT_SCOPE: &str = "access_as_user";

/// The tenant-specific v2 endpoint -- both the authority a client signs in
/// against and the `iss` its tokens carry. The form is fixed and live-verified:
/// research spike `entra-token-validation`.
fn v2_endpoint(tenant_id: &str) -> String {
    format!("https://login.microsoftonline.com/{tenant_id}/v2.0")
}

/// The tenant's live signing-key document.
fn tenant_jwks_url(tenant_id: &str) -> String {
    format!("https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys")
}

/// One Entra tenant, as a source file's `[provider_config]` states it.
///
/// Both faces are here because one file serves both binaries: the policy the
/// broker verifies tokens against, and the Graph credential sync reads with.
/// Split across `broker.toml` and `sync.toml` they could name different
/// tenants, and that disagreement retires every account and recreates it with a
/// fresh SID.
#[derive(Debug, PartialEq)]
pub struct Settings {
    pub tenant_id: String,
    /// The Broker API app, whose id is the audience of every token this source
    /// accepts. It holds no credential -- it only validates.
    pub broker_api_client_id: String,
    /// The native app the agent signs in with. Public, so it has no secret.
    pub public_client_id: String,
    /// The delegated scope, bare: the `api://<broker_api_client_id>/` prefix is
    /// Entra's spelling and is added where the discovery document is built.
    pub scope: String,
    /// The one `iss` accepted, compared exactly.
    pub issuer: String,
    /// What the agent is told to sign in against.
    pub authority: String,
    /// Unset in the file means the tenant's live document, because a silent
    /// fallback to a local file would verify against whatever is on disk.
    pub jwks: JwksSource,
    pub display_name: String,
    pub sync_client_id: String,
    pub sync_credential_file: PathBuf,
    /// The operator's assertion of that credential's expiry, `YYYY-MM-DD`.
    /// Absent means no advance warning, not a refusal to run.
    pub sync_credential_expires: Option<String>,
    /// Who may hold Kerberos tickets, by object id. Required: with no admission
    /// group sync mirrors nobody and every sign-in is a 403.
    pub admission_group_id: String,
    /// Who may activate a device grant, by object id. `None` is a deployment
    /// with no device-grant group and therefore no working grants -- the broker
    /// finds the group by its marker.
    pub device_grant_group_id: Option<String>,
    /// Groups to mirror beyond those reachable from the admission group.
    pub extra_group_ids: Vec<String>,
}

/// The file's own shape, before the exactly-one rules and the derived defaults.
///
/// Unknown keys are refused, as in every struct `kerbridge-core` parses: a typo
/// that silently keeps a default is the failure mode the whole config set exists
/// to end.
/// Every `example` here is borrowed rather than written bare. The derive
/// re-lexes a bare string literal to see whether it names a function, and a GUID
/// is exactly the string that trips that: `...-5555eeee6666` reads there as a
/// numeric exponent with no digits. One spelling throughout, so that a field
/// added later cannot pick the one that happens to break.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
struct Raw {
    #[cfg_attr(feature = "schema", schemars(example = &"aaaabbbb-0000-cccc-1111-dddd2222eeee"))]
    tenant_id: String,
    #[cfg_attr(feature = "schema", schemars(example = &"11112222-bbbb-3333-cccc-4444dddd5555"))]
    broker_api_client_id: String,
    #[cfg_attr(feature = "schema", schemars(example = &"22223333-cccc-4444-dddd-5555eeee6666"))]
    public_client_id: String,
    #[serde(default = "default_scope")]
    scope: String,
    #[cfg_attr(
        feature = "schema",
        schemars(
            example = &"https://login.microsoftonline.com/aaaabbbb-0000-cccc-1111-dddd2222eeee/v2.0"
        )
    )]
    issuer: Option<String>,
    #[cfg_attr(
        feature = "schema",
        schemars(
            example = &"https://login.microsoftonline.com/aaaabbbb-0000-cccc-1111-dddd2222eeee/v2.0"
        )
    )]
    authority: Option<String>,
    #[cfg_attr(
        feature = "schema",
        schemars(
            example = &"https://login.microsoftonline.com/aaaabbbb-0000-cccc-1111-dddd2222eeee/discovery/v2.0/keys"
        )
    )]
    jwks_url: Option<String>,
    #[cfg_attr(feature = "schema", schemars(example = &"/etc/kerbridge/entra-jwks.json"))]
    jwks_file: Option<PathBuf>,
    #[serde(default = "default_display_name")]
    display_name: String,
    #[cfg_attr(feature = "schema", schemars(example = &"66667777-aaaa-8888-bbbb-9999cccc0000"))]
    sync_client_id: String,
    #[cfg_attr(feature = "schema", schemars(example = &"/etc/kerbridge.secrets/idp/entra/credential"))]
    sync_credential_file: PathBuf,
    #[cfg_attr(feature = "schema", schemars(example = &"2027-01-31"))]
    sync_credential_expires: Option<String>,
    #[cfg_attr(feature = "schema", schemars(example = &"77778888-bbbb-9999-cccc-0000dddd1111"))]
    admission_group_id: String,
    #[cfg_attr(feature = "schema", schemars(example = &"88889999-cccc-0000-dddd-1111eeee2222"))]
    device_grant_group_id: Option<String>,
    #[serde(default)]
    extra_group_ids: Vec<String>,
}

/// What [`Raw`] says about its own shape, as JSON Schema.
///
/// `Raw` stays private -- which keys this block has is the adapter's business,
/// and its description is the only part of that the renderer needs.
#[cfg(feature = "schema")]
pub(crate) fn schema() -> Result<serde_json::Value, String> {
    serde_json::to_value(schemars::schema_for!(Raw))
        .map_err(|e| format!("the schema is not JSON: {e}"))
}

fn default_scope() -> String {
    DEFAULT_SCOPE.to_owned()
}
fn default_display_name() -> String {
    PRODUCT_NAME.to_owned()
}

impl Settings {
    /// The `[provider_config]` table `kerbridge-core` captured verbatim.
    pub fn parse(table: &toml::Table) -> Result<Self> {
        let raw: Raw = toml::Value::Table(table.clone())
            .try_into()
            .context("[provider_config], for an entra source")?;

        let jwks = match (raw.jwks_url, raw.jwks_file) {
            (Some(_), Some(_)) => bail!(
                "[provider_config]: jwks_url and jwks_file both say where this source's token \
                 signing keys come from -- remove one"
            ),
            (Some(url), None) => JwksSource::Url(url),
            (None, Some(path)) => JwksSource::File(path),
            (None, None) => JwksSource::Url(tenant_jwks_url(&raw.tenant_id)),
        };

        let admission_group_id = group_id(raw.admission_group_id, "admission_group_id")?;
        let device_grant_group_id = raw
            .device_grant_group_id
            .map(|id| group_id(id, "device_grant_group_id"))
            .transpose()?;

        Ok(Self {
            issuer: raw.issuer.unwrap_or_else(|| v2_endpoint(&raw.tenant_id)),
            authority: raw.authority.unwrap_or_else(|| v2_endpoint(&raw.tenant_id)),
            jwks,
            admission_group_id,
            device_grant_group_id,
            tenant_id: raw.tenant_id,
            broker_api_client_id: raw.broker_api_client_id,
            public_client_id: raw.public_client_id,
            scope: raw.scope,
            display_name: raw.display_name,
            sync_client_id: raw.sync_client_id,
            sync_credential_file: raw.sync_credential_file,
            sync_credential_expires: raw.sync_credential_expires,
            extra_group_ids: raw.extra_group_ids,
        })
    }
}

/// This source's settings as `kbconfig get` answers them, keyed by the file's
/// own key names.
///
/// Hand-written, unlike the envelope's generated half, because [`Settings`] is
/// *resolved* rather than a copy of the file: `jwks` is an enum with no one
/// obvious rendering, and prints as the pair of keys a file would state, the one
/// it is not bound by empty.
/// `a_settings_key_answers_by_the_name_the_file_gives_it` holds the set to the
/// adapter's own schema, so a key added to the block and forgotten here fails
/// the build.
pub(crate) fn paths(settings: &Settings) -> BTreeMap<String, String> {
    let (jwks_url, jwks_file) = match &settings.jwks {
        JwksSource::Url(url) => (url.clone(), String::new()),
        JwksSource::File(path) => (String::new(), path.display().to_string()),
    };
    [
        ("tenant_id", settings.tenant_id.clone()),
        ("broker_api_client_id", settings.broker_api_client_id.clone()),
        ("public_client_id", settings.public_client_id.clone()),
        ("scope", settings.scope.clone()),
        ("issuer", settings.issuer.clone()),
        ("authority", settings.authority.clone()),
        ("jwks_url", jwks_url),
        ("jwks_file", jwks_file),
        ("display_name", settings.display_name.clone()),
        ("sync_client_id", settings.sync_client_id.clone()),
        ("sync_credential_file", settings.sync_credential_file.display().to_string()),
        ("sync_credential_expires", settings.sync_credential_expires.clone().unwrap_or_default()),
        ("admission_group_id", settings.admission_group_id.clone()),
        ("device_grant_group_id", settings.device_grant_group_id.clone().unwrap_or_default()),
        ("extra_group_ids", settings.extra_group_ids.join("\n")),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}

/// Check a group object id's shape. The likely mistake in one of these keys is
/// the display name pasted into it, which would otherwise surface only as a
/// realm that admits nobody.
fn group_id(id: String, key: &str) -> Result<String> {
    // Folded first, because `is_guid` takes only the canonical lowercase form:
    // an uppercase Object Id is still an Object Id, and this refuses a mistake
    // rather than a spelling.
    if !is_guid(&id.to_ascii_lowercase()) {
        bail!(
            "[provider_config]: {key} is not a group object id (GUID): {id:?} -- the portal \
             shows it on the group's Overview page, as Object Id"
        );
    }
    Ok(id)
}

/// The three checks, named as `kbconfig` prints them.
const DISCOVERY: &str = "discovery document";
const ISSUER: &str = "issuer";
const KEYS: &str = "signing keys";

/// OIDC fixes the suffix. Hung off the authority rather than assembled from the
/// tenant, so the document fetched is the one a client signing in here would
/// find.
fn discovery_url(authority: &str) -> String {
    format!("{}/.well-known/openid-configuration", authority.trim_end_matches('/'))
}

/// The two claims a probe compares. Everything else the document carries is a
/// client's business rather than this deployment's.
#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}

/// What the tenant says about itself, against what this file derived.
pub(crate) async fn probe(settings: &Settings, timeout: Duration) -> Vec<Probe> {
    let url = discovery_url(&settings.authority);
    let body = match get(&url, timeout).await {
        Ok(body) => body,
        Err(trouble) => return vec![trouble.at(DISCOVERY)],
    };
    let Ok(document) = serde_json::from_str::<Discovery>(&body) else {
        return vec![Probe::fail(DISCOVERY, format!("{url} is not an OpenID discovery document"))];
    };

    let keys = match get(&document.jwks_uri, timeout).await {
        // A source verifying against a local `jwks_file` is probed here too: the
        // question is whether the tenant is publishing keys at all, which its
        // own document is the only authority on.
        Ok(body) => match crate::jwks::parse(&body) {
            Ok(keys) => Probe::pass(KEYS, format!("{} at {}", keys.len(), document.jwks_uri)),
            Err(e) => Probe::fail(KEYS, format!("{}: {e:#}", document.jwks_uri)),
        },
        Err(trouble) => trouble.at(KEYS),
    };
    vec![Probe::pass(DISCOVERY, url), issuer_probe(&settings.issuer, &document.issuer), keys]
}

/// The check that earns the whole feature.
///
/// The issuer and every stored subject are both downstream of `tenant_id`, so a
/// wrong one does not fail loudly: sync mirrors a different tenant's people
/// under this source's name, each under a storage key that cannot be corrected
/// without retiring and recreating all of them. One HTTP GET catches it.
fn issuer_probe(derived: &str, published: &str) -> Probe {
    if derived == published {
        Probe::pass(ISSUER, derived)
    } else {
        Probe::fail(
            ISSUER,
            format!("the tenant publishes {published:?}, this file derives {derived:?}"),
        )
    }
}

/// A failed GET, sorted into the two kinds but not yet attached to a question.
struct Trouble(Verdict, String);

impl Trouble {
    fn at(self, check: &'static str) -> Probe {
        Probe { check, verdict: self.0, detail: self.1 }
    }
}

/// One GET, bounded the same way the signing-key fetch is -- the IdP is remote
/// and outside the deployment either way.
///
/// **Only the status is classified here.** Anything that stopped the exchange
/// from completing is the world; a document that arrived and does not say what
/// it should is the caller's to judge, because only the caller knows what it was
/// reading for.
async fn get(url: &str, timeout: Duration) -> Result<String, Trouble> {
    let response = crate::jwks::http_client(timeout)
        .map_err(|e| Trouble(Verdict::Warn, format!("{e:#}")))?
        .get(url)
        .send()
        .await
        .map_err(|e| Trouble(Verdict::Warn, format!("{url} did not answer: {}", root_cause(&e))))?;
    let status = response.status();
    if !status.is_success() {
        return Err(Trouble(status_verdict(status.as_u16()), format!("{url} answered {status}")));
    }
    crate::jwks::bounded_body(response)
        .await
        .map_err(|e| Trouble(Verdict::Warn, format!("{url} answered, the body did not: {e:#}")))
}

/// The bottom of an error chain. `reqwest`'s own `Display` repeats the URL the
/// line already names and says nothing about why; the DNS or connect failure is
/// the last link.
fn root_cause(error: &dyn std::error::Error) -> String {
    let mut cause = error;
    while let Some(next) = cause.source() {
        cause = next;
    }
    cause.to_string()
}

/// Which side of the line a status falls on. A 4xx is the server answering
/// *about the request*, which settles the question against the configuration; a
/// 5xx is the server failing to answer it at all.
fn status_verdict(status: u16) -> Verdict {
    if (500..600).contains(&status) { Verdict::Warn } else { Verdict::Fail }
}

/// The template source for the `[provider_config]` half of
/// `idp_<name>.toml.example`, rendered by `kerbridge-core`'s `render` and
/// appended to the envelope that crate emits.
///
/// It lives beside the parser above because the renderer reads [`Raw`]'s own
/// schema for every value it writes: a source that showed a value the code does
/// not use, named a key the parser dropped or missed one it gained fails the
/// build rather than misleading an operator.
#[cfg(feature = "schema")]
pub(crate) const ENTRA_SRC: &str = r#"# Entra: the three app registrations from SETUP.md step 2, the sync app's Graph
# credential, and the group that admits a user to the realm. What each value is,
# and the four Entra defaults that are wrong for KerBridge: docs/setup/entra.md.
# `terraform apply` in deploy/terraform/entra/ creates all three and prints
# the ids.
[provider_config]

# The tenant, and the two app registrations the sign-in path uses. Each id is on
# its app's Overview blade in the portal.
#
#   broker_api_client_id  the Broker API: the audience of every token this
#                         source accepts, and the app that exposes `scope`
#                         below. It holds no credential -- it only validates.
#   public_client_id      the native app the agent signs in with, auth-code plus
#                         PKCE. Public, so it has no secret.
#
# A typing error in any of them denies every login, and none of them looks wrong
# afterwards.
{{tenant_id}}
{{broker_api_client_id}}
{{public_client_id}}

# The delegated scope the Broker API exposes. Change it only if you exposed the
# API under another name. State the bare name: the agent asks for
# `api://<broker_api_client_id>/<scope>`, which is Entra's spelling, and that is
# assembled here.
{{scope}}

# What the agent calls this IdP on screen -- "Sign out of Entra", and the note
# after a device grant. Set it to whatever your sign-in page says: the name has
# to match what the user just saw in the browser, not what the vendor calls
# itself. Cosmetic, and safe to change at any time.
{{display_name}}

# Both derived from tenant_id, and stated only for a cloud whose host name is
# not the commercial one.
#
#   issuer     the one `iss` this source accepts, compared exactly. The
#              `/common` and `/organizations` forms are another tenant's tokens
#              as far as this deployment is concerned.
#   authority  what the agent is told to sign in against.
#
{{issuer}}
{{authority}}

# Where this source's token signing keys come from. Neither one set means the
# tenant's own live document, which is what you want: a broker that silently
# fell back to a local file would verify tokens against whatever happened to be
# on disk. Set at most one.
#
# jwks_file is for a broker with no outbound path to the IdP. Refreshing it
# whenever Entra rolls a signing key is then yours to do, and every token is
# refused until you have.
{{jwks_url}}
{{jwks_file}}

# The directory sync app: app-only, read-only Graph, and the only one of the
# three holding a credential. Without admin consent on its permissions its token
# carries no roles and every read is a 403.
{{sync_client_id}}

# The file holding that credential's *Value*, never the value itself. Copy the
# Value and not the Secret ID beside it: the Secret ID is a GUID, it stays
# visible after the Value is masked, and it is the one usually copied later.
# Sync refuses a GUID here for exactly that reason.
#
# Under this source's own /etc/kerbridge.secrets/idp/<name>/ -- beside
# bind_password_file's directory and deliberately not in it, because you write
# this one and `kbsetup directory` writes that one. Paste the portal value into
# deploy/secrets/idp/entra/credential on the host. Empty means the app
# registration does not exist yet: that source is skipped with a warning, and
# every other source still mirrors.
{{sync_credential_file}}

# What the portal shows in that credential's Expires field, YYYY-MM-DD. An
# assertion rather than a measurement: rotate the secret without editing this
# and the warning it drives reports headroom that is not there. Unset means no
# advance warning, not a refusal to run. How far ahead to warn is local policy
# -- sync.toml's credential_warn_before_days.
{{sync_credential_expires}}

# The Entra security group whose members may hold Kerberos tickets, by object
# id -- the portal shows it on the group's Overview page. Nothing works without
# one: with no admission group sync mirrors no users and every sign-in is a 403.
#
# The id, and not the display name: a group that is renamed or recreated keeps
# its id, and a name can come to answer for a group you did not choose.
# Repointing at a different group retires every user the new one does not admit.
{{admission_group_id}}

# Object ids of further groups to mirror, beyond those reachable from the
# admission group.
{{extra_group_ids}}

# The Entra group whose members may activate a device grant, by object id as
# above. Unset is a deployment with no device-grant group and therefore no
# working grants, whatever main.toml's device_grant_days says: the broker finds
# the group by its marker. docs/setup/device-grants.md.
{{device_grant_group_id}}
"#;

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
        let jwks = Jwks::load(settings.jwks.clone(), timeout, notifier)
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
struct Header {
    alg: String,
    kid: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn accepts(&self, want: &str) -> bool {
        match self {
            Self::One(a) => a == want,
            Self::Many(all) => all.iter().any(|a| a == want),
        }
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
    // 1. Structure, before anything is decoded or fetched.
    let mut parts = token.split('.');
    let (Some(header_b64), Some(claims_b64), Some(sig_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(reject("not a three-part JWT"));
    };

    let header: Header =
        serde_json::from_slice(&b64url(header_b64).map_err(|_| reject("header is not base64url"))?)
            .map_err(|_| reject("header is not JSON"))?;

    // 2. Algorithm allowlist, before a key is selected. Entra signs v2 access
    //    tokens with RS256; the rest of the list is crate-wide.
    let Some(primitive) = jwks::algorithm(&header.alg) else {
        return Err(reject(format!("disallowed alg {:?}", header.alg)));
    };
    let kid = header.kid.ok_or_else(|| reject("header carries no kid"))?;

    // 3. Signature over the exact bytes presented, not over anything re-encoded.
    let signature = b64url(sig_b64).map_err(|_| reject("signature is not base64url"))?;
    let signed_len = header_b64.len() + 1 + claims_b64.len();
    let signed = &token.as_bytes()[..signed_len];
    let outcome = jwks
        .with_key(&kid, |key| {
            // Refused on the key's published `alg` before the signature is
            // computed at all, so a correct signature does not reach a key the
            // IdP published for something else.
            (!key.pins(&header.alg)).then(|| verify_rsa(key, primitive, signed, &signature))
        })
        .await
        .ok_or_else(|| reject(format!("unknown kid {kid:?}")))?;
    let Some(verified) = outcome else {
        return Err(reject(format!("key {kid:?} is not published for alg {:?}", header.alg)));
    };
    if !verified {
        return Err(reject("signature does not verify"));
    }

    // 4. Claims. Everything from here is policy against a payload whose
    //    authenticity is already established.
    let claims: Claims = serde_json::from_slice(
        &b64url(claims_b64).map_err(|_| reject("claims are not base64url"))?,
    )
    .map_err(|_| reject("claims are not JSON"))?;

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

/// The one verification routine in this file, and it is RSA. `primitive` came
/// from [`jwks::algorithm`], so it is an allowlisted algorithm by construction
/// rather than by a check somewhere above.
///
/// ring takes the two components as JWKS states them, so no key encoding is
/// written here. Do not reintroduce one: hand-built ASN.1 in this routine is
/// the single defect that would forge any identity.
fn verify_rsa(
    key: &RsaKey,
    primitive: &'static ring::signature::RsaParameters,
    signed: &[u8],
    signature: &[u8],
) -> bool {
    ring::signature::RsaPublicKeyComponents {
        n: trim_leading_zeros(&key.modulus),
        e: trim_leading_zeros(&key.exponent),
    }
    .verify(primitive, signed, signature)
    .is_ok()
}

/// ring wants each component big-endian with no leading zero. RFC 7517 does not
/// forbid an IdP from publishing one, so this does not assume it away.
fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_significant = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first_significant..]
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::conformance;
    use std::path::PathBuf;

    pub fn fixture_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testbench/fixtures/entra-token")
    }

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

    pub const TENANT: &str = "aaaabbbb-0000-cccc-1111-dddd2222eeee";
    pub const USER_OID: &str = "33334444-dddd-5555-eeee-6666ffff7777";
    /// The commented `admission_group_id` the template offers.
    const GROUP_ID: &str = "77778888-bbbb-9999-cccc-0000dddd1111";

    fn source() -> Source {
        Source::new("entra").unwrap()
    }

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
    /// pairing nobody has checked.
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

    /// One rule at both faces: the directory face is `encode_identity`, the
    /// token face is the reduction `verify` ends on. No fixture reaches the
    /// token face -- the corpus signing key is not committed, so one new token
    /// means regenerating all of them. The words are asserted because `verify`
    /// wraps them.
    #[test]
    fn an_uppercase_oid_is_refused_on_both_faces() {
        assert!(identity(&source(), USER_OID).is_ok(), "the canonical form still passes");
        let uppercase = USER_OID.to_ascii_uppercase();

        let from_graph = crate::encode_identity(crate::Provider::Entra, &source(), &uppercase)
            .expect_err("the directory face refuses it");
        let from_token = identity(&source(), &uppercase).expect_err("the token face refuses it");
        assert_eq!(from_graph, from_token, "one rule, so one refusal");

        let why = from_token.to_string();
        assert!(why.contains("GUID") && why.contains("lowercase"), "{why}");
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
        let claims = String::from_utf8(b64url(parts[1]).unwrap()).unwrap();
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

    /// A `[provider_config]` table, out of a document that carries one.
    fn block(document: &str) -> toml::Table {
        let doc: toml::Table = toml::from_str(document).expect("the document parses");
        doc["provider_config"].as_table().expect("[provider_config]").clone()
    }

    /// The same required values the template states, and nothing else: the
    /// difference between this and the template is exactly the optional half.
    const REQUIRED_ONLY: &str = r#"
        [provider_config]
        tenant_id = "aaaabbbb-0000-cccc-1111-dddd2222eeee"
        broker_api_client_id = "11112222-bbbb-3333-cccc-4444dddd5555"
        public_client_id = "22223333-cccc-4444-dddd-5555eeee6666"
        sync_client_id = "66667777-aaaa-8888-bbbb-9999cccc0000"
        sync_credential_file = "/etc/kerbridge.secrets/idp/entra/credential"
        admission_group_id = "77778888-bbbb-9999-cccc-0000dddd1111"
    "#;

    fn required() -> toml::Table {
        block(REQUIRED_ONLY)
    }

    /// Every value the template states must *be* the default, or the file
    /// documents a number the code does not use. Parsing the template and the
    /// required-fields-only document must therefore give the same settings.
    #[test]
    fn the_template_states_the_defaults_it_claims() {
        let rendered = crate::Provider::Entra.template().expect("the source renders");
        let shown = block(&rendered);
        let stated = Settings::parse(&shown).expect("the template parses");
        let defaults = Settings::parse(&required()).expect("the minimal document parses");
        assert_eq!(stated, defaults);
        // And the derivations the file leaves out, spelled once here so a
        // changed default is visible rather than merely consistent.
        assert_eq!(defaults.scope, DEFAULT_SCOPE);
        assert_eq!(defaults.display_name, PRODUCT_NAME);
        assert_eq!(defaults.issuer, v2_endpoint(TENANT));
        assert_eq!(defaults.authority, v2_endpoint(TENANT));
        assert_eq!(defaults.jwks, JwksSource::Url(tenant_jwks_url(TENANT)));
        assert_eq!(defaults.device_grant_group_id, None);
        assert!(defaults.extra_group_ids.is_empty());
    }

    /// The typo that silently keeps a default is what the whole config set
    /// exists to end, and the provider block is not exempt from it.
    #[test]
    fn an_unknown_key_in_the_block_is_an_error() {
        let mut typo = required();
        typo.insert("tennant_id".into(), "x".into());
        let err = Settings::parse(&typo).unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"), "{err:#}");
    }

    /// Required, and an object id: a realm with no admission group admits
    /// nobody, and a display name pasted into the key selects nothing.
    #[test]
    fn the_admission_group_is_bound_by_object_id() {
        let mut absent = required();
        absent.remove("admission_group_id");
        let err = format!("{:#}", Settings::parse(&absent).unwrap_err());
        assert!(err.contains("admission_group_id"), "{err}");

        assert_eq!(Settings::parse(&required()).unwrap().admission_group_id, GROUP_ID);

        let mut misplaced = required();
        misplaced.insert("admission_group_id".into(), "onprem-realm-users".into());
        let err = Settings::parse(&misplaced).unwrap_err().to_string();
        assert!(err.contains("not a group object id"), "{err}");

        let mut named = required();
        named.insert("admission_group".into(), "onprem-realm-users".into());
        let err = format!("{:#}", Settings::parse(&named).unwrap_err());
        assert!(err.contains("unknown field"), "{err}");
    }

    /// Optional, unlike the admission group -- and held to the same shape.
    #[test]
    fn a_device_grant_group_is_optional_and_bound_by_object_id() {
        assert_eq!(Settings::parse(&required()).unwrap().device_grant_group_id, None);

        let mut misplaced = required();
        misplaced.insert("device_grant_group_id".into(), "onprem-device-grants".into());
        let err = Settings::parse(&misplaced).unwrap_err().to_string();
        assert!(err.contains("device_grant_group_id"), "{err}");
    }

    /// Neither is the tenant's live document; both is two answers to one
    /// question.
    #[test]
    fn the_signing_keys_come_from_at_most_one_place() {
        let derived = Settings::parse(&required()).unwrap().jwks;
        assert_eq!(derived, JwksSource::Url(tenant_jwks_url(TENANT)));

        let mut file_only = required();
        file_only.insert("jwks_file".into(), "/etc/kerbridge/entra-jwks.json".into());
        let parsed = Settings::parse(&file_only).unwrap().jwks;
        assert_eq!(parsed, JwksSource::File("/etc/kerbridge/entra-jwks.json".into()));

        let mut both = required();
        both.insert("jwks_url".into(), tenant_jwks_url(TENANT).into());
        both.insert("jwks_file".into(), "/etc/kerbridge/entra-jwks.json".into());
        let err = Settings::parse(&both).unwrap_err().to_string();
        assert!(err.contains("jwks_url") && err.contains("jwks_file"), "{err}");
    }

    /// The distinction the verdict table rests on, and nothing here touches the
    /// network: an answer about the request settles it against the file, and no
    /// answer settles nothing.
    #[test]
    fn a_4xx_names_the_config_and_a_5xx_names_the_world() {
        for definitive in [400, 401, 403, 404, 410] {
            assert_eq!(status_verdict(definitive), Verdict::Fail, "{definitive}");
        }
        for transient in [500, 502, 503, 504] {
            assert_eq!(status_verdict(transient), Verdict::Warn, "{transient}");
        }
    }

    #[test]
    fn a_published_issuer_that_disagrees_is_a_hard_fail() {
        let derived = v2_endpoint(TENANT);
        assert_eq!(issuer_probe(&derived, &derived).verdict, Verdict::Pass);

        let elsewhere = v2_endpoint("00000000-0000-0000-0000-000000000000");
        let probe = issuer_probe(&derived, &elsewhere);
        assert_eq!(probe.verdict, Verdict::Fail);
        // Both spellings, because the operator has to see which of the two ids
        // is the typo.
        assert!(probe.detail.contains(&derived), "{}", probe.detail);
        assert!(probe.detail.contains(&elsewhere), "{}", probe.detail);
    }

    /// A document missing either claim is one this probe cannot read, which the
    /// caller turns into a hard fail rather than a transport problem.
    #[test]
    fn a_discovery_document_needs_both_claims_and_tolerates_the_rest() {
        let full = r#"{"issuer":"https://idp.example.site/t/v2.0",
                       "jwks_uri":"https://idp.example.site/t/keys",
                       "response_modes_supported":["query"]}"#;
        assert!(serde_json::from_str::<Discovery>(full).is_ok());
        assert!(
            serde_json::from_str::<Discovery>(r#"{"issuer":"https://idp.example.site/t/v2.0"}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<Discovery>("<html>sign in</html>").is_err());
    }

    #[test]
    fn the_discovery_url_hangs_off_the_authority() {
        let want = "https://idp.example.site/tenant/.well-known/openid-configuration";
        assert_eq!(discovery_url("https://idp.example.site/tenant"), want);
        assert_eq!(discovery_url("https://idp.example.site/tenant/"), want);
    }

    #[test]
    fn a_component_is_trimmed_to_what_ring_accepts() {
        assert_eq!(trim_leading_zeros(&[0x00, 0x00, 0x7f]), &[0x7f]);
        assert_eq!(trim_leading_zeros(&[0x01, 0x00, 0x01]), &[0x01, 0x00, 0x01]);
        // No significant byte at all: an empty slice, not a panic.
        assert_eq!(trim_leading_zeros(&[0x00, 0x00]), &[] as &[u8]);
        assert_eq!(trim_leading_zeros(&[]), &[] as &[u8]);
    }

    /// The same key and signature, with the modulus stated both ways: bare, and
    /// with the leading zero RFC 7517 permits. A verifier that handed the padded
    /// form straight to ring would refuse a token the IdP signed correctly.
    #[test]
    fn a_modulus_published_with_a_leading_zero_still_verifies() {
        let body = std::fs::read_to_string(fixture_dir().join("jwks.json")).unwrap();
        let mut key = crate::jwks::parse(&body).unwrap().remove("fixture-key-2026-07").unwrap();
        let jwt = token("positive_delegated.jwt");
        let (signed, sig) = jwt.rsplit_once('.').unwrap();
        let signature = crate::b64url(sig).unwrap();
        let primitive = crate::jwks::algorithm("RS256").unwrap();

        assert!(verify_rsa(&key, primitive, signed.as_bytes(), &signature), "bare modulus");
        key.modulus.insert(0, 0x00);
        assert!(verify_rsa(&key, primitive, signed.as_bytes(), &signature), "padded modulus");
    }
}
