//! The authentik adapter: the application a source file names, and the subject
//! encoding both faces share.
//!
//! One authentik **OAuth2 provider** plus one **application**, per source. The
//! provider is the protocol and the application is the access control, so
//! Entra's three app registrations have no counterpart to copy here.
//!
//! **Every per-application URL is keyed by the application slug**, so one string
//! in the file derives the issuer the broker compares, the authority the agent
//! signs in against and the document its signing keys come from. The authorize,
//! token, userinfo, introspect, revoke and device endpoints are
//! instance-global -- they carry no slug, the provider is identified by
//! `client_id`, and the agent reads them out of the discovery document rather
//! than out of this file.
//!
//! `auth` is the token face. [`identity`] is what makes the two faces agree --
//! see the crate doc for what a divergence costs.

mod auth;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use kerbridge_core::{ExternalIdentity, IdentityError, Source, is_guid};
use serde::Deserialize;

use crate::{Probe, discovery_url, get};

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

/// The identity this adapter stores for an authentik account.
///
/// **The user's `uuid`**, canonical lower-case hyphenated, bare, with the
/// provider set to `sub_mode: user_uuid`. The decisive argument is
/// **filterability** rather than stability: `uuid` is the only identifier
/// `/core/users/` can be filtered on, and under any other mode the broker's
/// `sub` could not be looked up in the directory at all, so the two faces could
/// never be made to agree. Stability only ranks the rest -- the default
/// `hashed_user_id` is salted per provider, `pk` is a reused integer, and
/// username, email and UPN are mutable.
///
/// **The subject rule lives here**, so one rule serves both faces and sync's
/// conflict machinery reports a bad value with no new code.
///
/// **Nothing normalizes.** A non-canonical value is refused rather than
/// lower-cased: a stored subject is unrecoverable if wrong, so a transformation
/// over it becomes a second thing that may never change. Storing either case
/// verbatim is worse still, because the two are different subjects and an
/// upstream serialization change would then orphan every account in silence.
pub fn identity(source: &Source, uuid: &str) -> Result<ExternalIdentity, IdentityError> {
    // The shape case-insensitively first, so the second branch can name itself:
    // a value that is a UUID in the wrong case has a different cause, and a
    // different reader, from one that is no UUID at all.
    if !is_guid(&uuid.to_ascii_lowercase()) {
        return Err(IdentityError::SubjectShape(NOT_A_UUID));
    }
    if !is_guid(uuid) {
        return Err(IdentityError::SubjectShape(NOT_CANONICAL));
    }
    ExternalIdentity::new(source, uuid)
}

/// Everything an application's own URLs hang off: the instance and the
/// application's slug, with the trailing slash of the instance URL dropped so
/// that one stated with or without it derives the same strings.
fn application_base(url: &str, slug: &str) -> String {
    format!("{}/application/o/{slug}", url.trim_end_matches('/'))
}

/// The one `iss` this source accepts.
///
/// **The trailing slash is load-bearing.** `get_issuer()` is `reverse()` plus
/// `build_absolute_uri()`, and the URL pattern it reverses ends with a slash.
/// `iss` is compared byte for byte, so a derivation without the slash refuses
/// every token this provider will ever issue.
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
/// Both faces are here because one file serves both binaries: the policy the
/// broker verifies tokens against, and the API token sync reads the directory
/// with. Split across two files they could name different applications, and
/// that disagreement retires every account and recreates it with a fresh SID.
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
}

/// The file's own shape, before the derived defaults.
///
/// Unknown keys are refused, as in every struct `kerbridge-core` parses: a typo
/// that silently keeps a default is the failure mode the whole config set exists
/// to end.
///
/// Every `example` is borrowed rather than written bare, as in the Entra block:
/// the derive re-lexes a bare string literal to see whether it names a
/// function, and some placeholder values do not survive that.
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
        })
    }
}

/// This source's settings as `kbconfig get` answers them, keyed by the file's
/// own key names.
///
/// Hand-written, because [`Settings`] is *resolved* rather than a copy of the
/// file: a deploy script that could not ask for `issuer` would rebuild it out
/// of `url` and the slug, and be wrong the day a deployment states one of its
/// own. `a_settings_key_answers_by_the_name_the_file_gives_it` holds the set to
/// the adapter's schema, so a key added to the block and forgotten here fails
/// the build.
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
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}

/// The checks, named as `kbconfig` prints them. Three questions about the
/// provider, and the fetch that answers all three at once.
const DISCOVERY: &str = "discovery document";
const ISSUER: &str = "issuer";
const SIGNING: &str = "signing algorithm";
const REFRESH: &str = "offline_access";

/// The three claims the probe reads. Everything else the document carries is a
/// client's business rather than this deployment's.
///
/// Only `issuer` is required, because it is what makes the document a discovery
/// document. The other two are answers rather than structure, and a document
/// that omits one has answered it: no algorithm list is a provider publishing
/// no key, and no scope list is a provider with no mapping attached.
#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    #[serde(default)]
    id_token_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    scopes_supported: Vec<String>,
}

/// What the provider says about itself, against what this file derived.
///
/// One fetch, three verdicts, each of them a hard fail.
pub(crate) async fn probe(settings: &Settings, timeout: Duration) -> Vec<Probe> {
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

/// The check that earns the whole feature.
///
/// Three unrelated mistakes reach a deployment as one symptom -- every token
/// refused, with the issuer the only clue: a wrong application slug, the "same
/// identifier for all providers" issuer mode, and a reverse proxy that rewrites
/// the `Host` header. One HTTP GET catches all three.
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

/// The default that is wrong, read where it names its own cause.
///
/// A new authentik provider has no Signing Key. There is no algorithm selector:
/// the algorithm follows the key type, and with no key the provider signs
/// **HS256 with its own client secret** and publishes a JWKS of `{}` with no
/// `keys` array. This crate's allowlist is asymmetric-only and compiled in, so
/// that deployment's whole symptom is a 401 and one log line. An empty JWKS
/// shows only the symptom.
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

/// A hard fail rather than a warning, because its runtime failure is silent by
/// construction.
///
/// A refresh token needs the `offline_access` scope mapping **attached to the
/// provider** as well as requested by the agent, and a new provider does not
/// get it. Unattached, the authorize view drops the scope with no error and the
/// sign-in still succeeds; the agent cannot report it either, because a missing
/// refresh token is a legitimate state. On authentik that token is the agent's
/// only silent supply, so every re-injection becomes a browser sign-in instead.
///
/// The document lists the mappings attached to this provider, which is what
/// makes an unattached one visible at all.
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
        // And the derivations the file leaves out, spelled once here so a
        // changed default is visible rather than merely consistent.
        assert_eq!(defaults.display_name, PRODUCT_NAME);
        assert_eq!(defaults.audience, CLIENT_ID);
        assert_eq!(defaults.issuer, issuer(URL, SLUG));
        assert_eq!(defaults.authority, authority(URL, SLUG));
        assert_eq!(defaults.jwks_url, jwks_url(URL, SLUG));
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
        // A instance URL stated with a trailing slash derives the same strings:
        // an operator who pastes the address bar must not get a doubled slash
        // in the one value that is compared byte for byte.
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
        for endpoint in ["authorize", "token", "userinfo", "introspect", "revoke", "device"] {
            assert!(
                !answered.keys().any(|key| key.contains(endpoint)),
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

    /// The four required keys, each of them the whole deployment: a source with
    /// any one of them missing serves nobody, and serde reports one per file.
    #[test]
    fn the_block_requires_the_four_values_only_the_operator_has() {
        for key in ["url", "application_slug", "client_id", "sync_credential_file"] {
            let mut absent = required();
            absent.remove(key);
            let err = format!("{:#}", Settings::parse(&absent).unwrap_err());
            assert!(err.contains(key), "{key}: {err}");
        }
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
}
