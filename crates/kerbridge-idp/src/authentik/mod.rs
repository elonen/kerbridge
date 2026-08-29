//! The authentik adapter: the application a source file names, and the subject
//! encoding both faces share.
//!
//! Each source uses one authentik OAuth2 provider and one application. The
//! provider supplies the protocol. The application supplies access control.
//!
//! The application slug identifies all application-specific URLs. It derives
//! the issuer, authority, and JWKS URL. The other OAuth endpoints are global to
//! the instance. The agent reads them from the discovery document.
//!
//! `auth` is the token face. [`identity`] is the shared subject rule.

mod auth;
#[cfg(feature = "sync")]
mod client;
#[cfg(feature = "sync")]
pub(crate) mod sync;
#[cfg(feature = "sync")]
mod wire;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use kerbridge_core::time::{days_from_ymd, now_unix};
use kerbridge_core::{ExternalIdentity, IdentityError, Source, is_guid};
use serde::Deserialize;

use crate::{Probe, Verdict, discovery_url, get, jwks, status_verdict};

pub(crate) use auth::Authentik;

/// authentik's product name, in its own lower-case styling: what the agent says
/// on screen unless the deployment renames it.
const PRODUCT_NAME: &str = "authentik";

/// A value that is not UUID-shaped at all means the provider is on the wrong
/// subject mode. `models.py:309` defaults it to `hashed_user_id`, so this is a
/// setting an operator must change rather than one they can leave.
///
/// The words are the operator's only channel: a rejection never reaches the
/// client, so the broker log is where this is read.
const NOT_A_UUID: &str = "a UUID: this provider is on the wrong subject mode -- set the OAuth2 \
                          provider's sub_mode to user_uuid, which is not authentik's default";

/// The other cause, and not the operator's to fix: `_resolve_sub()` ends in
/// `str(user.uuid)`, Python's canonical lower-case form, so a UUID spelled any
/// other way means authentik's serialization changed. Naming `sub_mode` here
/// would send an operator to a setting that is already correct.
const NOT_CANONICAL: &str = "a UUID in canonical lowercase form: authentik serializes a user uuid with Python's str(), \
     so a differently-spelled one is a change in authentik's output rather than a setting of \
     yours -- nothing here normalizes it, because a transformation over a stored subject would \
     become a second thing that may never change";

/// Store the user's canonical lowercase `uuid` with `sub_mode: user_uuid`.
///
/// The UUID is the only user identifier that `/core/users/` can filter on. The
/// token face and directory (IdP) face therefore use the same rule. The adapter
/// rejects, and does not normalize, a noncanonical value. Normalization could
/// silently change a permanent stored subject.
pub fn identity(source: &Source, uuid: &str) -> Result<ExternalIdentity, IdentityError> {
    // Distinguish a wrong subject mode from noncanonical UUID spelling.
    if !is_guid(&uuid.to_ascii_lowercase()) {
        return Err(IdentityError::SubjectShape(NOT_A_UUID));
    }
    if !is_guid(uuid) {
        return Err(IdentityError::SubjectShape(NOT_CANONICAL));
    }
    ExternalIdentity::new(source, uuid)
}

/// Build the base for application-specific URLs. Ignore a trailing instance
/// slash so both accepted forms produce the same URLs.
fn application_base(url: &str, slug: &str) -> String {
    format!("{}/application/o/{slug}", url.trim_end_matches('/'))
}

/// The one `iss` this source accepts.
///
/// The final slash is required. Authentik's reversed URL pattern includes it,
/// and `iss` comparison is exact.
fn issuer(url: &str, slug: &str) -> String {
    format!("{}/", application_base(url, slug))
}

/// What the agent is told to sign in against, and what the discovery document
/// hangs off.
fn authority(url: &str, slug: &str) -> String {
    application_base(url, slug)
}

/// The application's live signing-key document.
fn jwks_url(url: &str, slug: &str) -> String {
    format!("{}/jwks/", application_base(url, slug))
}

/// One authentik application, as a source file's `[provider_config]` states it.
///
/// One settings value serves both adapter faces. Different applications would
/// map every account to a new identity and SID.
#[derive(Debug, PartialEq)]
pub struct Settings {
    /// The authentik instance, scheme and host, with no path of its own.
    pub url: String,
    /// The Application's slug. Every per-application URL is keyed by it.
    pub application_slug: String,
    /// The Provider's client id: what the agent signs in as, and the value
    /// `azp` must carry on every access token.
    pub client_id: String,
    /// The one `aud` accepted. Defaults to [`Self::client_id`], because on
    /// authentik the two coincide -- but only coincidentally, so the key exists
    /// rather than being conflated away.
    pub audience: String,
    /// The one `iss` accepted, compared exactly. Keeps its trailing slash.
    pub issuer: String,
    /// What the agent is told to sign in against.
    pub authority: String,
    /// Where this source's token signing keys come from. Always the
    /// application's own live document: authentik publishes one, and a broker
    /// that silently fell back to a local file would verify tokens against
    /// whatever happened to be on disk.
    pub jwks_url: String,
    pub display_name: String,
    /// The file holding the API token sync reads the directory with.
    ///
    /// There is deliberately no `sync_credential_expires` beside it: authentik
    /// reports an API token's own expiry to the bearer, so the adapter measures
    /// it rather than asking the operator to assert it.
    pub sync_credential_file: PathBuf,
    /// Who may hold Kerberos tickets, by the group's pk (a uuid). Required: with
    /// no admission group sync mirrors nobody and every sign-in is a 403. The
    /// operator reads the pk back after the blueprint creates the group.
    pub admission_group_id: String,
    /// Who may activate a device grant, by the group's pk. `None` is a
    /// deployment with no device-grant group and therefore no working grants --
    /// the broker finds the group by its marker.
    pub device_grant_group_id: Option<String>,
    /// Groups to mirror beyond those reachable from the admission group, by pk.
    pub extra_group_ids: Vec<String>,
}

/// The file's own shape, before the derived defaults.
///
/// Unknown keys are refused so a typo cannot silently select a default.
///
/// Borrow each `example`. The derive re-parses a bare string as a possible
/// function name.
#[derive(Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
struct Raw {
    #[cfg_attr(feature = "schema", schemars(example = &"https://authentik.example.site"))]
    url: String,
    #[cfg_attr(feature = "schema", schemars(example = &"kerbridge"))]
    application_slug: String,
    #[cfg_attr(feature = "schema", schemars(example = &"kerbridge"))]
    client_id: String,
    #[cfg_attr(feature = "schema", schemars(example = &"kerbridge"))]
    audience: Option<String>,
    #[serde(default = "default_display_name")]
    display_name: String,
    #[cfg_attr(
        feature = "schema",
        schemars(example = &"https://authentik.example.site/application/o/kerbridge/")
    )]
    issuer: Option<String>,
    #[cfg_attr(
        feature = "schema",
        schemars(example = &"https://authentik.example.site/application/o/kerbridge")
    )]
    authority: Option<String>,
    #[cfg_attr(
        feature = "schema",
        schemars(example = &"https://authentik.example.site/application/o/kerbridge/jwks/")
    )]
    jwks_url: Option<String>,
    #[cfg_attr(feature = "schema", schemars(example = &"/etc/kerbridge.secrets/idp/authentik/credential"))]
    sync_credential_file: PathBuf,
    #[cfg_attr(feature = "schema", schemars(example = &"0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d"))]
    admission_group_id: String,
    #[cfg_attr(feature = "schema", schemars(example = &"1b2c3d4e-5f6a-7b8c-9d0e-1f2a3b4c5d6e"))]
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

fn default_display_name() -> String {
    PRODUCT_NAME.to_owned()
}

impl Settings {
    /// The `[provider_config]` table `kerbridge-core` captured verbatim.
    pub fn parse(table: &toml::Table) -> Result<Self> {
        let raw: Raw = toml::Value::Table(table.clone())
            .try_into()
            .context("[provider_config], for an authentik source")?;

        let admission_group_id = group_id(raw.admission_group_id, "admission_group_id")?;
        let device_grant_group_id = raw
            .device_grant_group_id
            .map(|id| group_id(id, "device_grant_group_id"))
            .transpose()?;

        Ok(Self {
            issuer: raw.issuer.unwrap_or_else(|| issuer(&raw.url, &raw.application_slug)),
            authority: raw.authority.unwrap_or_else(|| authority(&raw.url, &raw.application_slug)),
            jwks_url: raw.jwks_url.unwrap_or_else(|| jwks_url(&raw.url, &raw.application_slug)),
            audience: raw.audience.unwrap_or_else(|| raw.client_id.clone()),
            url: raw.url,
            application_slug: raw.application_slug,
            client_id: raw.client_id,
            display_name: raw.display_name,
            sync_credential_file: raw.sync_credential_file,
            admission_group_id,
            device_grant_group_id,
            extra_group_ids: raw.extra_group_ids,
        })
    }
}

/// Reject a group name pasted in place of the UUID primary key.
fn group_id(id: String, key: &str) -> Result<String> {
    // Accept uppercase spelling because this value selects an existing group;
    // it is not a stored subject.
    if !is_guid(&id.to_ascii_lowercase()) {
        bail!(
            "[provider_config]: {key} is not a group pk (a uuid): {id:?} -- authentik shows it on \
             the group's page, and the blueprint reports it after it creates the group"
        );
    }
    Ok(id)
}

/// This source's settings as `kbconfig get` answers them, keyed by the file's
/// own key names.
///
/// [`Settings`] contains resolved values, including operator overrides. Return
/// those values so callers do not derive them again.
pub(crate) fn paths(settings: &Settings) -> BTreeMap<String, String> {
    [
        ("url", settings.url.clone()),
        ("application_slug", settings.application_slug.clone()),
        ("client_id", settings.client_id.clone()),
        ("audience", settings.audience.clone()),
        ("issuer", settings.issuer.clone()),
        ("authority", settings.authority.clone()),
        ("jwks_url", settings.jwks_url.clone()),
        ("display_name", settings.display_name.clone()),
        ("sync_credential_file", settings.sync_credential_file.display().to_string()),
        ("admission_group_id", settings.admission_group_id.clone()),
        ("device_grant_group_id", settings.device_grant_group_id.clone().unwrap_or_default()),
        ("extra_group_ids", settings.extra_group_ids.join("\n")),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}

/// Probe labels shown by `kbconfig`. Separate labels identify separate fixes.
const DISCOVERY: &str = "discovery document";
const ISSUER: &str = "issuer";
const SIGNING: &str = "signing algorithm";
const REFRESH: &str = "offline_access";
const CREDENTIAL: &str = "sync credential";
const GRANT: &str = "directory grant";
const EXPIRY: &str = "credential expiry";

/// The claims that the configuration probe reads.
///
/// Only `issuer` is structural. An absent algorithm or scope list means that the
/// provider publishes no matching value.
#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    #[serde(default)]
    id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    scopes_supported: Vec<String>,
}

/// Compare the public provider metadata and test the sync credential. The
/// authenticated probes test the token, directory grant, and expiry.
pub(crate) async fn probe(
    settings: &Settings,
    credential: Option<&str>,
    timeout: Duration,
) -> Vec<Probe> {
    let mut probes = public_probes(settings, timeout).await;
    probes.extend(authenticated_probes(settings, credential, timeout).await);
    probes
}

/// Check issuer, signing algorithm, and the `offline_access` mapping.
async fn public_probes(settings: &Settings, timeout: Duration) -> Vec<Probe> {
    let url = discovery_url(&settings.authority);
    let body = match get(&url, timeout).await {
        Ok(body) => body,
        Err(trouble) => return vec![trouble.at(DISCOVERY)],
    };
    let Ok(document) = serde_json::from_str::<Discovery>(&body) else {
        return vec![Probe::fail(DISCOVERY, format!("{url} is not an OpenID discovery document"))];
    };
    vec![
        Probe::pass(DISCOVERY, url),
        issuer_probe(&settings.issuer, &document.issuer),
        signing_probe(&document.id_token_signing_alg_values_supported),
        offline_access_probe(&document.scopes_supported),
    ]
}

/// Check the sync credential as a bearer token.
///
/// An absent credential warns because setup is incomplete. It does not fail the
/// source configuration.
async fn authenticated_probes(
    settings: &Settings,
    credential: Option<&str>,
    timeout: Duration,
) -> Vec<Probe> {
    let Some(token) = credential.map(str::trim).filter(|t| !t.is_empty()) else {
        let why = format!(
            "no sync credential in {} yet -- paste the read-only service account's API token in \
             and re-run; the three authenticated legs are skipped until then",
            settings.sync_credential_file.display()
        );
        return [CREDENTIAL, GRANT, EXPIRY]
            .into_iter()
            .map(|check| Probe { check, verdict: Verdict::Warn, detail: why.clone() })
            .collect();
    };
    vec![
        credential_probe(&settings.url, token, timeout).await,
        grant_probe(&settings.url, token, timeout).await,
        expiry_probe(&settings.url, token, now_unix(), timeout).await,
    ]
}

/// `GET /core/users/me/`: does the token authenticate at all?
///
/// The self endpoint needs no grants. A `403` therefore identifies a credential
/// failure, not a missing permission.
async fn credential_probe(base: &str, token: &str, timeout: Duration) -> Probe {
    let url = format!("{}/api/v3/core/users/me/", base.trim_end_matches('/'));
    credential_verdict(get_authed(&url, token, timeout).await)
}

/// Authentik returns `403`, not `401`, for an expired, revoked, or wrong token
/// and for a deactivated service account. This condition cannot heal without a
/// credential change.
fn credential_verdict(fetched: Fetched) -> Probe {
    match fetched {
        Fetched::Body(_) => Probe::pass(CREDENTIAL, "the service account authenticates"),
        Fetched::Status(403) => Probe::fail(
            CREDENTIAL,
            "authentik refused the sync credential (403): expired, revoked, wrong, and a \
             deactivated service account all answer one 403 here -- authentik emits no 401 -- and \
             an expired token rotates on lapse, so this will not heal on its own. Replace the \
             token on the read-only service account (Intent: API).",
        ),
        Fetched::Status(status) => at(CREDENTIAL, status),
        Fetched::World(why) => Probe { check: CREDENTIAL, verdict: Verdict::Warn, detail: why },
    }
}

/// `GET /core/groups/?page_size=1`: does the grant let the directory be read?
async fn grant_probe(base: &str, token: &str, timeout: Duration) -> Probe {
    let url = format!("{}/api/v3/core/groups/?page_size=1", base.trim_end_matches('/'));
    grant_verdict(get_authed(&url, token, timeout).await)
}

/// A list needs `view_group`. If the credential probe passes, a `403` identifies
/// a missing grant. An object-scoped grant can return a silently shorter list,
/// so the permission must be global.
fn grant_verdict(fetched: Fetched) -> Probe {
    match fetched {
        Fetched::Body(_) => Probe::pass(GRANT, "the service account may list the directory"),
        Fetched::Status(403) => Probe::fail(
            GRANT,
            "authentik refused the directory read (403): with the sync-credential leg green this \
             is a missing grant -- give the service account view_user and view_group globally \
             through a Role. A per-object grant answers 200 with a silently truncated list, which \
             reconciles the people it left out as departures.",
        ),
        Fetched::Status(status) => at(GRANT, status),
        Fetched::World(why) => Probe { check: GRANT, verdict: Verdict::Warn, detail: why },
    }
}

/// `GET /core/tokens/?intent=api`: measure credential headroom.
///
/// `TokenViewSet.owner_field = "user"` makes this endpoint self-scoped. The
/// serializer omits `key`, so the endpoint cannot disclose the secret. The
/// `intent=api` filter excludes an `app_password` token.
async fn expiry_probe(base: &str, token: &str, now: u64, timeout: Duration) -> Probe {
    let url =
        format!("{}/api/v3/core/tokens/?intent=api&page_size=100", base.trim_end_matches('/'));
    expiry_verdict(get_authed(&url, token, timeout).await, now)
}

fn expiry_verdict(fetched: Fetched, now: u64) -> Probe {
    match fetched {
        Fetched::Body(body) => match read_expiry(&body, now) {
            Ok(Expiry::Days(days)) => Probe::pass(EXPIRY, format!("{days} days of headroom")),
            Ok(Expiry::NonExpiring) => {
                Probe::pass(EXPIRY, "the sync credential is set never to expire")
            }
            // Authentication passed, but no API token is visible to measure.
            Ok(Expiry::Absent) => Probe {
                check: EXPIRY,
                verdict: Verdict::Warn,
                detail: "no api-intent token is visible to measure the credential's headroom"
                    .to_owned(),
            },
            Err(e) => Probe {
                check: EXPIRY,
                verdict: Verdict::Warn,
                detail: format!("the token read answered, but not with a token list: {e}"),
            },
        },
        Fetched::Status(403) => Probe::fail(
            EXPIRY,
            "authentik refused the token read (403): the sync credential is not an API token -- an \
             app_password token authenticates nothing here and fails byte-identically to a wrong \
             or expired one. Create the token with Intent: API.",
        ),
        Fetched::Status(status) => at(EXPIRY, status),
        Fetched::World(why) => Probe { check: EXPIRY, verdict: Verdict::Warn, detail: why },
    }
}

/// A `5xx` is reachability trouble. Other unexpected statuses reject the
/// request.
fn at(check: &'static str, status: u16) -> Probe {
    Probe { check, verdict: status_verdict(status), detail: format!("authentik answered {status}") }
}

/// Detect a wrong application slug, global issuer mode, or rewritten `Host`.
fn issuer_probe(derived: &str, published: &str) -> Probe {
    if derived == published {
        Probe::pass(ISSUER, derived)
    } else {
        Probe::fail(
            ISSUER,
            format!("the provider publishes {published:?}, this file derives {derived:?}"),
        )
    }
}

/// A new authentik provider has no Signing Key. There is no algorithm selector:
/// the algorithm follows the key type, and with no key the provider signs
/// HS256 with its client secret and publishes an empty JWKS. KerBridge permits
/// asymmetric algorithms only.
fn signing_probe(published: &[String]) -> Probe {
    if published.iter().any(|alg| crate::jwks::algorithm(alg).is_some()) {
        Probe::pass(SIGNING, published.join(", "))
    } else {
        Probe::fail(
            SIGNING,
            format!(
                "the provider signs with {published:?}, none of which this build will verify -- \
                 select a Signing Key on the OAuth2 provider, or it signs symmetrically with the \
                 client secret and publishes an empty JWKS"
            ),
        )
    }
}

/// A refresh token needs the `offline_access` scope mapping **attached to the
/// provider** and requested by the agent. The authorize view silently drops an
/// unattached scope. The discovery document lists attached mappings, so this
/// check can detect the missing mapping.
fn offline_access_probe(scopes: &[String]) -> Probe {
    if scopes.iter().any(|scope| scope == "offline_access") {
        Probe::pass(REFRESH, "attached")
    } else {
        Probe::fail(
            REFRESH,
            format!(
                "the provider offers {scopes:?} -- attach the offline_access scope mapping to it, \
                 or the agent is issued no refresh token and nothing says so"
            ),
        )
    }
}

/// One authenticated GET, classified for a provider-specific probe.
///
/// [`crate::get`] has no bearer and combines all non-2xx responses. These probes
/// must distinguish a `403` from a `5xx`.
enum Fetched {
    /// A 2xx, body in hand.
    Body(String),
    /// A non-2xx the server chose to answer with. The status is the whole of it.
    Status(u16),
    /// The exchange never completed, or a 2xx body would not read: the world,
    /// which says nothing about whether the file is right.
    World(String),
}

async fn get_authed(url: &str, token: &str, timeout: Duration) -> Fetched {
    let client = match jwks::http_client(timeout) {
        Ok(client) => client,
        Err(e) => return Fetched::World(format!("{e:#}")),
    };
    let response = match client.get(url).bearer_auth(token).send().await {
        Ok(response) => response,
        Err(e) => return Fetched::World(format!("{url} did not answer: {e}")),
    };
    let status = response.status();
    if !status.is_success() {
        return Fetched::Status(status.as_u16());
    }
    match jwks::bounded_body(response).await {
        Ok(body) => Fetched::Body(body),
        Err(e) => Fetched::World(format!("{url} answered, the body did not: {e:#}")),
    }
}

/// What the self-scoped `/core/tokens/?intent=api` read says about the sync
/// credential's headroom.
enum Expiry {
    /// Days until the soonest API token expires. Can be negative.
    Days(i64),
    /// An API token has `expiring=false`. Its `expires` value is invalid.
    NonExpiring,
    /// No API-intent token is visible to the bearer at all.
    Absent,
}

/// One `/core/tokens/` row, cut to the two fields that decide expiry.
///
/// The serializer does not contain `key`. Unknown response fields are ignored.
#[derive(Deserialize)]
struct TokenRow {
    /// The datetime the token lapses, RFC 3339. **Junk whenever `expiring` is
    /// false** -- authentik leaves a stale or default value in the field rather
    /// than nulling it -- so it is read only when `expiring` is true.
    #[serde(default)]
    expires: Option<String>,
    /// Whether the token expires at all. The gate on `expires`.
    expiring: bool,
}

#[derive(Deserialize)]
struct TokenList {
    results: Vec<TokenRow>,
}

/// Read credential headroom from a self-scoped token list. The supplied clock
/// makes day-boundary tests deterministic.
///
/// The soonest expiry binds. Only a list of non-expiring tokens has no
/// countdown. An empty list is [`Expiry::Absent`].
fn read_expiry(body: &str, now: u64) -> Result<Expiry, serde_json::Error> {
    let list: TokenList = serde_json::from_str(body)?;
    if list.results.is_empty() {
        return Ok(Expiry::Absent);
    }
    let today = (now / 86_400) as i64;
    let soonest = list
        .results
        .iter()
        .filter(|row| row.expiring)
        // Use the date only. The notification countdown has day granularity.
        .filter_map(|row| row.expires.as_deref())
        .filter_map(|expires| expires.split('T').next())
        .filter_map(days_from_ymd)
        .map(|day| day - today)
        .min();
    Ok(soonest.map_or(Expiry::NonExpiring, Expiry::Days))
}

/// The self-scoped token read, for the sync loop's own measurement. Same shape
/// as the probe's [`expiry_probe`], reduced to the days the countdown needs:
/// [`Expiry::Days`] becomes a number, and everything else -- non-expiring,
/// absent, unparseable -- is no countdown.
#[cfg(feature = "sync")]
pub(crate) fn measured_days(body: &str, now: u64) -> Option<i64> {
    match read_expiry(body, now) {
        Ok(Expiry::Days(days)) => Some(days),
        _ => None,
    }
}

/// The template source for the `[provider_config]` half of
/// `idp_authentik.toml.example`, rendered by `kerbridge-core`'s `render` and
/// appended to the envelope that crate emits.
///
/// It lives beside the parser above because the renderer reads [`Raw`]'s own
/// schema for every value it writes: a source that showed a value the code does
/// not use, named a key the parser dropped or missed one it gained fails the
/// build rather than misleading an operator.
#[cfg(feature = "schema")]
pub(crate) const AUTHENTIK_SRC: &str = r#"# authentik: one OAuth2 provider and one application, plus the API token sync
# reads the directory with. authentik splits the protocol (the Provider) from
# the access control (the Application), so there is one of each and no third
# object. The provider settings KerBridge needs are mandatory and none of them
# shows up in a token: sub_mode, a Signing Key, the offline_access mapping and a
# regular-expression loopback redirect URI. The blueprint that sets them:
# docs/setup/authentik.md.
[provider_config]

# The authentik instance, and the Application's slug. Every per-application URL
# is keyed by that slug -- the issuer this deployment accepts, the discovery
# document the agent bootstraps from, and the signing keys. The slug is on the
# Application, not on the Provider, and it is yours to choose: some words are
# reserved (authorize, token, device, userinfo, introspect, revoke).
#
# State the instance as scheme and host with no path. Everything below is
# derived from these two.
{{url}}
{{application_slug}}

# The Provider's Client ID, from its OAuth2/OpenID Provider page. The agent
# signs in with it -- a public client on authorization code plus PKCE, with no
# secret -- and every access token this source accepts must name it in `azp`.
#
# Unlike Entra's, this is a string you may write yourself rather than a
# generated identifier; whatever it says there is what goes here.
{{client_id}}

# The one `aud` this source accepts. Unset means client_id, which is what
# authentik issues.
#
# It exists as its own key because the two are the same thing only by
# coincidence here: another IdP has a genuinely separate audience, and a lone
# client_id would conflate the client that signs a person in with the resource
# the token is for. Set it only if a scope mapping on this provider rewrites
# `aud`. `azp` is checked against client_id either way, and a scope mapping
# cannot reach `azp`.
{{audience}}

# What the agent calls this IdP on screen -- "Sign out of authentik", and the
# note after a device grant. Set it to whatever your sign-in page says: the name
# has to match what the user just saw in the browser, not what the vendor calls
# itself. Cosmetic, and safe to change at any time.
{{display_name}}

# All three derived from url and application_slug, and stated only for a
# deployment whose published URLs are not the ones this instance derives -- a
# reverse proxy that rewrites the Host header is the case that needs them.
#
#   issuer     the one `iss` this source accepts, compared exactly. Note the
#              trailing slash: authentik's own issuer carries one, `iss` is
#              compared byte for byte, and a value without it refuses every
#              token.
#   authority  what the agent is told to sign in against.
#   jwks_url   this application's live signing-key document.
#
# `kbconfig check --online` compares the issuer against what the provider
# publishes, which is what finds a wrong slug or a rewriting proxy.
{{issuer}}
{{authority}}
{{jwks_url}}

# The file holding the API token that sync reads users and groups with, never
# the token itself. Create it on a dedicated service account with Intent "API"
# -- an App password token authenticates nothing here and fails exactly the way
# a wrong one does -- and grant that account view_user and view_group through a
# Role, globally. A per-object grant answers 200 with a silently shorter list,
# which reconciles the people it left out as departures.
#
# Under this source's own /etc/kerbridge.secrets/idp/<name>/ -- beside
# bind_password_file's directory and deliberately not in it, because you write
# this one and `kbsetup directory` writes that one. Paste the token into
# deploy/secrets/idp/authentik/credential on the host. Empty means the token
# does not exist yet: that source is skipped with a warning, and every other
# source still mirrors.
#
# There is no expiry to state beside it. authentik reports an API token's own
# expiry to the bearer that holds it, so KerBridge measures the headroom rather
# than asking you to assert it -- but only if you left "Expiring" on when you
# created the token.
{{sync_credential_file}}

# The group whose members may hold Kerberos tickets, by the group's pk (a uuid).
# Nothing works without one: with no admission group sync mirrors no users and
# every sign-in is a 403. The blueprint reports the pk after it creates the
# group, and authentik shows it on the group's page.
#
# The pk, and not the name: a group that is renamed keeps its pk, while a name
# can come to answer for a group you did not choose. Repointing at a different
# group retires every user the new one does not admit.
{{admission_group_id}}

# Pks of further groups to mirror, beyond those reachable from the admission
# group.
{{extra_group_ids}}

# The group whose members may activate a device grant, by pk as above. Unset is
# a deployment with no device-grant group and therefore no working grants,
# whatever main.toml's device_grant_days says: the broker finds the group by its
# marker. docs/setup/device-grants.md.
{{device_grant_group_id}}
"#;

#[cfg(test)]
pub mod tests {
    use super::*;

    use crate::Verdict;

    /// The commented `application_slug` and `client_id` the template offers,
    /// which are also what the token corpus was forged for.
    pub const SLUG: &str = "kerbridge";
    pub const CLIENT_ID: &str = "kerbridge";
    pub const URL: &str = "https://authentik.example.site";
    /// The admission group's pk, as the template's example states it.
    pub const GROUP_ID: &str = "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d";
    /// One authentik `uuid`, in the form `str(user.uuid)` produces.
    pub const USER_UUID: &str = "6d1b9c4a-2f3e-4a7b-8c5d-0e1f2a3b4c5d";

    pub fn source() -> Source {
        Source::new("authentik").unwrap()
    }

    /// The two faces, on one value, byte for byte. Nothing else compares them:
    /// they run in separate processes with no channel between them, so this
    /// test is where a divergence is caught or not at all.
    #[test]
    fn both_faces_derive_the_same_bytes_from_one_uuid() {
        let directory = crate::encode_identity(crate::Provider::Authentik, &source(), USER_UUID)
            .expect("the directory face encodes a uuid");
        let token = identity(&source(), USER_UUID).expect("the token face encodes the same uuid");
        assert_eq!(directory, token, "one rule, so one identity");
        assert_eq!(directory.encode(), format!("kb1|authentik|{USER_UUID}"));
        assert_eq!(directory.encode(), token.encode());
    }

    /// Two rejects, because there are two causes, and the operator's next move
    /// is different for each. Nothing normalizes on the way.
    #[test]
    fn a_non_canonical_subject_is_refused_on_both_faces_and_names_its_cause() {
        let uppercase = USER_UUID.to_ascii_uppercase();
        let from_directory =
            crate::encode_identity(crate::Provider::Authentik, &source(), &uppercase)
                .expect_err("the directory face refuses it");
        let from_token = identity(&source(), &uppercase).expect_err("the token face refuses it");
        assert_eq!(from_directory, from_token, "one rule, so one refusal");

        // Upper case: authentik's serialization changed. Sending the operator
        // to `sub_mode` here would send them to a setting that is right.
        let why = from_token.to_string();
        assert!(why.contains("canonical lowercase"), "{why}");
        assert!(!why.contains("sub_mode"), "an upper-case uuid is not a sub_mode error: {why}");

        // Not a UUID at all: the provider is on the wrong subject mode, and the
        // reject names the setting rather than the symptom.
        for wrong_mode in [
            // `hashed_user_id`, the default: sha256 hex, and unfilterable.
            "b9dcd6a9d1f0e2b6c0f7a2d3e4b5c6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3",
            // `user_id`, the integer pk.
            "17",
            "benchuser",
            "benchuser@bench.invalid",
            "",
        ] {
            let why = identity(&source(), wrong_mode).unwrap_err().to_string();
            assert!(why.contains("sub_mode") && why.contains("user_uuid"), "{wrong_mode:?}: {why}");
        }
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
        url = "https://authentik.example.site"
        application_slug = "kerbridge"
        client_id = "kerbridge"
        sync_credential_file = "/etc/kerbridge.secrets/idp/authentik/credential"
        admission_group_id = "0a1b2c3d-4e5f-6a7b-8c9d-0e1f2a3b4c5d"
    "#;

    fn required() -> toml::Table {
        block(REQUIRED_ONLY)
    }

    /// Every value the template shows against a commented key must *be* the
    /// default, or the file documents a value the code does not use. Parsing the
    /// template and the required-fields-only document must therefore give the
    /// same settings.
    #[test]
    fn the_template_states_the_defaults_it_claims() {
        let rendered = crate::Provider::Authentik.source_template().expect("the source renders");
        let schema = crate::Provider::Authentik.source_schema().expect("the schema composes");
        let rendered = kerbridge_core::config::decisions::completed(&rendered, &schema)
            .expect("the template completes");
        let shown = block(&rendered);
        let stated = Settings::parse(&shown).expect("the template parses");
        let defaults = Settings::parse(&required()).expect("the minimal document parses");
        assert_eq!(stated, defaults);
        // Assert derived values separately from template consistency.
        assert_eq!(defaults.display_name, PRODUCT_NAME);
        assert_eq!(defaults.audience, CLIENT_ID);
        assert_eq!(defaults.issuer, issuer(URL, SLUG));
        assert_eq!(defaults.authority, authority(URL, SLUG));
        assert_eq!(defaults.jwks_url, jwks_url(URL, SLUG));
        assert_eq!(defaults.admission_group_id, GROUP_ID);
        assert_eq!(defaults.device_grant_group_id, None);
        assert!(defaults.extra_group_ids.is_empty());
    }

    /// The trailing slash, which is not decoration.
    ///
    /// `get_issuer()` is `reverse()` plus `build_absolute_uri()` over a URL
    /// pattern that ends in a slash, and `iss` is compared byte for byte -- so a
    /// derivation that dropped it would refuse every token this provider issues,
    /// with nothing in the file looking wrong. The authority is the same string
    /// without it, because the discovery URL is hung off the authority and
    /// authentik serves it at `<authority>/.well-known/openid-configuration`.
    #[test]
    fn the_issuer_keeps_its_trailing_slash_and_the_authority_does_not() {
        let settings = Settings::parse(&required()).unwrap();
        assert_eq!(settings.issuer, "https://authentik.example.site/application/o/kerbridge/");
        assert_eq!(settings.authority, "https://authentik.example.site/application/o/kerbridge");
        assert_eq!(
            settings.jwks_url,
            "https://authentik.example.site/application/o/kerbridge/jwks/"
        );
        assert!(settings.issuer.ends_with('/'), "{}", settings.issuer);
        assert_eq!(settings.issuer, format!("{}/", settings.authority));
        assert_eq!(
            discovery_url(&settings.authority),
            "https://authentik.example.site/application/o/kerbridge/.well-known/openid-configuration"
        );
        // An instance URL copied with a trailing slash must not double the slash
        // in the exact issuer value.
        let mut trailing = required();
        trailing.insert("url".into(), format!("{URL}/").into());
        assert_eq!(Settings::parse(&trailing).unwrap().issuer, settings.issuer);
    }

    /// The six protocol endpoints are instance-global -- they carry no slug, and
    /// the Provider is identified by `client_id`. Nothing in the block derives
    /// one, and the agent reads them out of the discovery document instead.
    #[test]
    fn only_the_per_application_urls_carry_the_slug() {
        let answered = paths(&Settings::parse(&required()).unwrap());
        // No endpoint is derived as a URL of this file's. Only the derived URL
        // keys are in scope: `device_grant_group_id` names the device-grant
        // group, not the device-authorization endpoint, and shares only the word.
        let url_keys = answered.keys().filter(|key| key.ends_with("_url") || *key == "issuer");
        let url_keys: Vec<&String> = url_keys.collect();
        for endpoint in ["authorize", "token", "userinfo", "introspect", "revoke", "device"] {
            assert!(
                !url_keys.iter().any(|key| key.contains(endpoint)),
                "{endpoint} is instance-global and is not this file's to state"
            );
        }
        for derived in ["issuer", "authority", "jwks_url"] {
            assert!(answered[derived].contains(SLUG), "{derived} does not carry the slug");
        }
    }

    /// The typo that silently keeps a default is what the whole config set
    /// exists to end, and the provider block is not exempt from it.
    #[test]
    fn an_unknown_key_in_the_block_is_an_error() {
        let mut typo = required();
        typo.insert("aplication_slug".into(), "kerbridge".into());
        let err = Settings::parse(&typo).unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"), "{err:#}");
    }

    /// Two keys the block deliberately does not have.
    ///
    /// `scope` because Entra's `api://<id>/<scope>` spelling has no authentik
    /// counterpart and the adapter checks no scope: on authentik a scope selects
    /// which mappings run, and is not an authorization decision.
    /// `sync_credential_expires` because authentik reports the token's own
    /// expiry to the bearer, so the adapter measures it -- an operator's
    /// assertion here would be a number that goes stale the first time the token
    /// is rotated.
    #[test]
    fn the_block_has_no_scope_and_no_asserted_credential_expiry() {
        for absent in ["scope", "sync_credential_expires"] {
            let mut stated = required();
            stated.insert(absent.into(), "whatever".into());
            let err = format!("{:#}", Settings::parse(&stated).unwrap_err());
            assert!(err.contains("unknown field"), "{absent}: {err}");
        }
    }

    /// The required keys, each of them the whole deployment: a source with any
    /// one of them missing serves nobody, and serde reports one per file. The
    /// admission group joins the token-face four for the directory face -- with
    /// no admission group sync mirrors nobody.
    #[test]
    fn the_block_requires_the_values_only_the_operator_has() {
        for key in
            ["url", "application_slug", "client_id", "sync_credential_file", "admission_group_id"]
        {
            let mut absent = required();
            absent.remove(key);
            let err = format!("{:#}", Settings::parse(&absent).unwrap_err());
            assert!(err.contains(key), "{key}: {err}");
        }
    }

    /// The admission group is bound by pk, a uuid, and the likely mistake is the
    /// group's name pasted where its pk goes -- refused with the key named, not
    /// left to surface as a realm that admits nobody.
    #[test]
    fn a_group_id_that_is_not_a_uuid_is_refused_by_name() {
        let mut named = required();
        named.insert("admission_group_id".into(), "kb-admission".into());
        let err = format!("{:#}", Settings::parse(&named).unwrap_err());
        assert!(err.contains("admission_group_id") && err.contains("uuid"), "{err}");
    }

    /// The audience exists as a key and defaults to the client id, and `azp` is
    /// pinned to the client id whatever it is set to -- so setting one does not
    /// move the other.
    #[test]
    fn the_audience_defaults_to_the_client_id_and_is_still_a_key() {
        assert_eq!(Settings::parse(&required()).unwrap().audience, CLIENT_ID);
        let mut stated = required();
        stated.insert("audience".into(), "some-other-application".into());
        let settings = Settings::parse(&stated).unwrap();
        assert_eq!(settings.audience, "some-other-application");
        assert_eq!(settings.client_id, CLIENT_ID);
    }

    #[test]
    fn a_published_issuer_that_disagrees_is_a_hard_fail() {
        let derived = issuer(URL, SLUG);
        assert_eq!(issuer_probe(&derived, &derived).verdict, Verdict::Pass);

        // The slash, again: the one difference an operator would never see.
        let probe = issuer_probe(derived.trim_end_matches('/'), &derived);
        assert_eq!(probe.verdict, Verdict::Fail);
        assert!(probe.detail.contains(&derived), "{}", probe.detail);

        // And the "same identifier for all providers" issuer mode, which
        // publishes the bare root and stops distinguishing applications.
        let global = issuer_probe(&derived, "https://authentik.example.site/");
        assert_eq!(global.verdict, Verdict::Fail);
    }

    /// The default that is wrong: no Signing Key means HS256, which this build
    /// will not verify, and the algorithm list is where that says so.
    #[test]
    fn a_provider_with_no_signing_key_fails_on_the_algorithm_it_advertises() {
        assert_eq!(signing_probe(&["RS256".to_owned()]).verdict, Verdict::Pass);
        assert_eq!(
            signing_probe(&["HS256".to_owned(), "RS256".to_owned()]).verdict,
            Verdict::Pass,
            "one asymmetric algorithm is enough: the JWK's own alg narrows it further"
        );
        let hs = signing_probe(&["HS256".to_owned()]);
        assert_eq!(hs.verdict, Verdict::Fail);
        assert!(hs.detail.contains("Signing Key"), "{}", hs.detail);
        // A document that names no algorithm at all is the same provider,
        // answering the same question.
        assert_eq!(signing_probe(&[]).verdict, Verdict::Fail);
    }

    /// A hard fail, not a warning: an unattached mapping costs the agent its
    /// refresh token and nothing at run time reports it.
    #[test]
    fn an_unattached_offline_access_mapping_is_a_hard_fail() {
        let attached = [
            "openid".to_owned(),
            "profile".to_owned(),
            "offline_access".to_owned(),
            "email".into(),
        ];
        assert_eq!(offline_access_probe(&attached).verdict, Verdict::Pass);

        let without = ["openid".to_owned(), "profile".to_owned()];
        let probe = offline_access_probe(&without);
        assert_eq!(probe.verdict, Verdict::Fail);
        assert!(probe.detail.contains("offline_access"), "{}", probe.detail);
    }

    /// A document missing the one claim that makes it a discovery document is
    /// one this probe cannot read; the two lists it also reads are answers
    /// rather than structure, so their absence is a verdict and not a parse
    /// error.
    #[test]
    fn a_discovery_document_needs_its_issuer_and_tolerates_the_rest() {
        let full = r#"{"issuer":"https://authentik.example.site/application/o/kerbridge/",
                       "id_token_signing_alg_values_supported":["RS256"],
                       "scopes_supported":["openid","offline_access"],
                       "response_modes_supported":["query"]}"#;
        let document: Discovery = serde_json::from_str(full).expect("it parses");
        assert_eq!(document.id_token_signing_alg_values_supported, ["RS256"]);
        assert!(document.scopes_supported.iter().any(|s| s == "offline_access"));

        let bare: Discovery =
            serde_json::from_str(r#"{"issuer":"https://x/"}"#).expect("it parses");
        assert!(bare.id_token_signing_alg_values_supported.is_empty());
        assert!(bare.scopes_supported.is_empty());

        assert!(serde_json::from_str::<Discovery>(r#"{"jwks_uri":"https://x/jwks/"}"#).is_err());
        assert!(serde_json::from_str::<Discovery>("<html>sign in</html>").is_err());
    }

    /// The `body` half of one of the corpus's response envelopes -- the bytes
    /// authentik would have put on the wire, which is what the reads above parse.
    fn token_body(name: &str) -> String {
        let path = format!(
            "{}/../../testbench/fixtures/authentik-directory/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let file: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        serde_json::to_string(&file["response"]["body"]).unwrap()
    }

    /// Midnight, Unix seconds, for a `YYYY-MM-DD` date.
    fn day(date: &str) -> u64 {
        (days_from_ymd(date).unwrap() as u64) * 86_400
    }

    /// The measurement that lets `sync_credential_expires` stop being an operator
    /// assertion. Two api tokens, and the soonest binds -- a surplus token
    /// further out cannot mask a nearer deadline. The clock is read at midday to
    /// prove only the date part counts.
    #[test]
    fn the_soonest_expiring_token_binds_the_measured_headroom() {
        let body = token_body("tokens_self_api");
        let now = day("2027-05-02") + 45_000;
        assert!(matches!(read_expiry(&body, now), Ok(Expiry::Days(30))), "30 days to 2027-06-01");
        assert_eq!(measured_days(&body, now), Some(30));
    }

    /// The trap: `expires` is junk whenever `expiring` is false. The fixture's
    /// junk value is years in the past, and a reader that trusted it would
    /// report a live credential as long expired. The right reading is no
    /// countdown, on both faces.
    #[test]
    fn a_non_expiring_token_is_not_read_as_expired() {
        let body = token_body("tokens_self_nonexpiring");
        // `now` well after the junk 2020 `expires`, so a bug would surface as a
        // large negative headroom rather than as `NonExpiring`.
        let now = day("2026-08-29");
        assert!(matches!(read_expiry(&body, now), Ok(Expiry::NonExpiring)));
        assert_eq!(measured_days(&body, now), None, "no countdown for a non-expiring token");
    }

    /// A 200 with no api token to read, and a 200 that is not a token list at
    /// all: neither is a headroom and neither is the file being wrong.
    #[test]
    fn an_empty_or_unreadable_token_list_measures_nothing() {
        let empty = r#"{"pagination":{"next":0,"count":0},"results":[]}"#;
        assert!(matches!(read_expiry(empty, 0), Ok(Expiry::Absent)));
        assert_eq!(measured_days(empty, 0), None);
        assert!(read_expiry("<html>not a token list</html>", 0).is_err());
        assert_eq!(measured_days("<html>", 0), None);
    }

    /// The credential leg, keyed on the 403 authentik actually emits rather than
    /// on a 401 it never does. Expired/revoked/wrong/deactivated all collapse to
    /// that one 403, and it is a permanent `Fail` because the token rotates on
    /// lapse. A 5xx is the world, not the credential.
    #[test]
    fn the_credential_leg_fails_on_the_403_and_never_keys_on_401() {
        assert_eq!(credential_verdict(Fetched::Body("{}".into())).verdict, Verdict::Pass);
        let dead = credential_verdict(Fetched::Status(403));
        assert_eq!(dead.verdict, Verdict::Fail);
        assert_eq!(dead.check, CREDENTIAL);
        assert!(dead.detail.contains("no 401"), "{}", dead.detail);
        // A 5xx is reachability; a stray other 4xx still settles against the request.
        assert_eq!(credential_verdict(Fetched::Status(503)).verdict, Verdict::Warn);
        assert_eq!(credential_verdict(Fetched::Status(404)).verdict, Verdict::Fail);
        assert_eq!(credential_verdict(Fetched::World("dns".into())).verdict, Verdict::Warn);
    }

    /// The grant leg, named apart from the credential leg: its 403 is a missing
    /// view_group, and it says so in its own words.
    #[test]
    fn the_grant_leg_names_the_missing_grant() {
        assert_eq!(grant_verdict(Fetched::Body("{}".into())).verdict, Verdict::Pass);
        let refused = grant_verdict(Fetched::Status(403));
        assert_eq!(refused.verdict, Verdict::Fail);
        assert_eq!(refused.check, GRANT);
        assert!(refused.detail.contains("view_group"), "{}", refused.detail);
    }

    /// The expiry leg over the corpus: a 200 measures the headroom, a 403 names
    /// the app_password trap, and a non-expiring token passes with no countdown.
    #[test]
    fn the_expiry_leg_measures_or_names_the_app_password_trap() {
        let now = day("2027-05-02");
        let ok = expiry_verdict(Fetched::Body(token_body("tokens_self_api")), now);
        assert_eq!(ok.verdict, Verdict::Pass);
        assert_eq!(ok.check, EXPIRY);
        assert!(ok.detail.contains("30 days"), "{}", ok.detail);

        let never = expiry_verdict(Fetched::Body(token_body("tokens_self_nonexpiring")), now);
        assert_eq!(never.verdict, Verdict::Pass);
        assert!(never.detail.contains("never to expire"), "{}", never.detail);

        let app_password = expiry_verdict(Fetched::Status(403), now);
        assert_eq!(app_password.verdict, Verdict::Fail);
        assert!(app_password.detail.contains("app_password"), "{}", app_password.detail);

        let empty = r#"{"pagination":{"next":0,"count":0},"results":[]}"#;
        assert_eq!(expiry_verdict(Fetched::Body(empty.into()), now).verdict, Verdict::Warn);
    }

    /// The three 403s are named apart: three distinct labels and three distinct
    /// details, so which leg failed is the diagnosis.
    #[test]
    fn the_three_authenticated_403s_are_named_apart() {
        let legs = [
            credential_verdict(Fetched::Status(403)),
            grant_verdict(Fetched::Status(403)),
            expiry_verdict(Fetched::Status(403), 0),
        ];
        let checks: std::collections::BTreeSet<_> = legs.iter().map(|p| p.check).collect();
        assert_eq!(checks.len(), 3, "each leg carries its own label");
        let details: std::collections::BTreeSet<_> =
            legs.iter().map(|p| p.detail.as_str()).collect();
        assert_eq!(details.len(), 3, "each 403 explains its own leg");
        for leg in &legs {
            assert_eq!(leg.verdict, Verdict::Fail);
        }
    }

    /// With no credential yet the five-leg shape still holds: the three
    /// authenticated legs warn rather than fail, because an empty credential file
    /// is a deployment mid-bootstrap, not a wrong one. No network is touched.
    #[test]
    fn no_credential_yet_warns_on_the_authenticated_legs() {
        let settings = Settings::parse(&required()).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let probes = runtime.block_on(authenticated_probes(
            &settings,
            None,
            std::time::Duration::from_secs(1),
        ));
        assert_eq!(probes.iter().map(|p| p.check).collect::<Vec<_>>(), [CREDENTIAL, GRANT, EXPIRY]);
        for probe in &probes {
            assert_eq!(probe.verdict, Verdict::Warn, "{}", probe.check);
            assert!(probe.detail.contains("no sync credential"), "{}", probe.detail);
        }
    }
}
