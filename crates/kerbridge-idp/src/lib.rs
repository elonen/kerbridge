//! Every provider-specific fact, behind one interface.
//!
//! An adapter has **two faces**, and they are here together because they have to
//! agree byte for byte. The broker turns a bearer credential into an
//! [`ExternalIdentity`]; sync turns a directory (IdP) object from the same IdP into
//! one. Nothing connects the two processes -- separate containers, separate
//! credentials, no channel -- so a disagreement about what the stored value
//! should be breaks every login for that source, and neither program looks
//! wrong. Worse, the value is also the join key of sync's reconciliation loop:
//! the desired set is keyed by the IdP's subject and the current set by what was
//! read back out of AD, so a divergence retires and recreates every account,
//! with a fresh SID each, which strands every file its owner held.
//!
//! [`Provider`] is the **only** place a provider is chosen. `connect` and
//! [`encode_identity`] both dispatch on it, so adding an adapter is one arm in
//! one match rather than switch-cases threaded through two binaries.
//!
//! `issuerd` deliberately does not link this crate: it holds KDC authority, and
//! all it needs of an identity is that the stored value parses, which
//! `kerbridge-core` answers on its own.
//!
//! # The algorithm allowlist
//!
//! **Asymmetric-only, compiled in, never configuration.** Every symmetric
//! algorithm (`HS*`) and `none` are permanently excluded. The RSA families
//! `RS*` and `PS*` are allowed today; ES256 is an expected future addition and
//! not a violation of the rule -- the length of the list is not itself the
//! rule.
//!
//! A JWK that states its own `alg` narrows this further, to that one algorithm
//! for that one key. So widening the list widens what an IdP *may* publish, not
//! what any key it already published may be used with.
//!
//! Two reasons, and the second is the one specific to this deployment:
//!
//! 1. *Algorithm confusion.* The IdP publishes an RSA public key. A verifier
//!    that dispatches on the token's own `alg` lets anyone use those published
//!    bytes as an HMAC secret, forge a token asserting any identity, and have it
//!    verify. Full authentication bypass.
//! 2. *Blast radius.* With an asymmetric algorithm the broker holds only public
//!    key material and cannot forge a token even if it is fully compromised. A
//!    symmetric algorithm makes the verification key the signing key, so the
//!    broker would hold something that mints identities -- which undoes the
//!    reason KDC authority sits in `issuerd` behind a peer-uid-authorized socket
//!    in the first place.
//!
//! The guard is structural rather than checked: the allowlist is resolved
//! before any key is loaded, *and* no adapter contains a symmetric verification
//! routine at all. The check stands in front of a door that does not exist. Do
//! not add an HMAC code path for completeness. Resolving rather than comparing
//! is what keeps that true as the list grows -- the lookup hands back the
//! primitive to verify with, so an algorithm cannot pass the check and then be
//! verified by something else.
//!
//! An operator can arrive with symmetric signing configured, because some IdPs
//! offer it as an ordinary option, and their whole symptom is a 401 and one log
//! line. Every page documenting an IdP's configuration says to use an asymmetric
//! signing key.

#![forbid(unsafe_code)]

mod auth;
pub mod authentik;
pub mod entra;
mod jwks;
mod jwt;
#[cfg(feature = "sync")]
pub mod sync;

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{Result, bail};
use kerbridge_core::{ExternalIdentity, IdentityError, Source};

pub(crate) use auth::reject;
pub use auth::{IdentityProvider, OidcDiscovery, Reject, b64url, connect};
pub use jwks::JwksSource;

/// Which adapter a deployment configured, from a source file's `provider`.
///
/// The single point of variance. Every provider-specific decision is reached
/// through one of the functions below, so an adapter cannot be half-wired: a new
/// arm here is a compile error until every face exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Entra,
    Authentik,
}

impl Provider {
    /// Every adapter this build carries. A caller that writes or checks one file
    /// per provider iterates this rather than naming the arms, which is what
    /// keeps a second adapter to one arm in one match.
    pub const ALL: [Self; 2] = [Self::Entra, Self::Authentik];

    /// From a source file's `provider = "..."`. The caller names the file; this
    /// knows only the word it was handed.
    pub fn from_name(name: &str) -> Result<Self> {
        match name {
            "entra" => Ok(Self::Entra),
            "authentik" => Ok(Self::Authentik),
            other => bail!("{other:?} is not an adapter this build carries"),
        }
    }

    /// What a source file spells to select this adapter, and the stem of its
    /// committed example -- `idp_<name>.toml.example`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Entra => "entra",
            Self::Authentik => "authentik",
        }
    }

    /// This provider's commented `[provider_config]` block, rendered from the
    /// adapter's template source against the adapter's own schema.
    #[cfg(feature = "schema")]
    pub fn template(self) -> Result<String, String> {
        match self {
            Self::Entra => kerbridge_core::config::render(
                "provider_config",
                entra::ENTRA_SRC,
                &entra::schema()?,
            ),
            Self::Authentik => kerbridge_core::config::render(
                "provider_config",
                authentik::AUTHENTIK_SRC,
                &authentik::schema()?,
            ),
        }
    }

    /// A whole `idp_<name>.toml.example`. The envelope half belongs to
    /// `kerbridge-core` and the block to the adapter, and this crate is the only
    /// one that links both.
    ///
    /// The example source is named after the adapter, which is the name a first
    /// deployment gives it. A realm running two of one provider names the second
    /// something else and the derived values follow.
    #[cfg(feature = "schema")]
    pub fn source_template(self) -> Result<String, String> {
        let name = self.name();
        Ok(format!("{}{}", kerbridge_core::config::source_envelope(name, name)?, self.template()?))
    }

    /// A whole `idp_<name>.toml` as JSON Schema: the envelope, with this
    /// provider's block put where core leaves a hole.
    ///
    /// Core skips `provider_config`, and `deny_unknown_fields` makes the
    /// emitted schema close the document -- so the envelope on its own tells a
    /// reader that `[provider_config]` is not allowed at all. Only this crate
    /// holds both halves, so only this crate can say otherwise.
    #[cfg(feature = "schema")]
    pub fn source_schema(self) -> Result<serde_json::Value, String> {
        let mut block = match self {
            Self::Entra => entra::schema()?,
            Self::Authentik => authentik::schema()?,
        };
        // `$schema` names a document's own dialect, and this one stops being a
        // document here. `title` is the private struct's name, which is
        // nobody's business outside this crate.
        let block_object = block.as_object_mut().ok_or("the provider schema is not an object")?;
        block_object.remove("$schema");
        block_object.remove("title");

        let mut schema = kerbridge_core::config::source_schema()?;
        schema
            .get_mut("properties")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or("the envelope schema states no properties")?
            .insert("provider_config".into(), block);
        Ok(schema)
    }
}

/// One source's `[provider_config]`, parsed.
///
/// `kerbridge-core` captures that table and hands it here without looking
/// inside. That is the confinement this crate exists for: parsed anywhere else,
/// core -- and therefore `issuerd`, which holds KDC authority -- would carry a
/// struct describing what an Entra deployment needs.
#[derive(Debug, PartialEq)]
pub enum IdpSettings {
    Entra(entra::Settings),
    Authentik(authentik::Settings),
}

impl IdpSettings {
    pub fn parse(provider: Provider, table: &toml::Table) -> Result<Self> {
        match provider {
            Provider::Entra => Ok(Self::Entra(entra::Settings::parse(table)?)),
            Provider::Authentik => Ok(Self::Authentik(authentik::Settings::parse(table)?)),
        }
    }

    /// This source's settings as `kbconfig get` answers them, relative to
    /// `sources.<name>.`: the *resolved* value of each key, not the line the
    /// file holds.
    ///
    /// The third face keyed off the adapter, beside [`Provider::source_template`]
    /// and [`Provider::source_schema`]: the adapter stays the only thing that
    /// interprets its own block, and `get` is its mouthpiece rather than a
    /// competitor. Do not withhold it again -- a deploy script that cannot ask
    /// for `issuer` rebuilds it out of `tenant_id`, and is silently wrong on the
    /// first deployment that states an `authority` of its own.
    pub fn paths(&self) -> BTreeMap<String, String> {
        match self {
            Self::Entra(settings) => entra::paths(settings),
            Self::Authentik(settings) => authentik::paths(settings),
        }
    }

    /// The sync credential file. Callers can supply its content to [`probe`]
    /// without knowing the adapter type.
    pub fn sync_credential_file(&self) -> &Path {
        match self {
            Self::Entra(settings) => &settings.sync_credential_file,
            Self::Authentik(settings) => &settings.sync_credential_file,
        }
    }
}

/// One `check --online` question, and the answer the IdP gave it.
///
/// A verdict per question rather than one per source: which of the three failed
/// is the whole diagnosis, and they fail for unrelated reasons.
#[derive(Debug, PartialEq, Eq)]
pub struct Probe {
    /// What was asked, as the label `kbconfig` prints.
    pub check: &'static str,
    pub verdict: Verdict,
    /// What was found, or why nothing was. One line.
    pub detail: String,
}

/// A configuration error and a world error deserve different verdicts, and
/// separating them is the reason to probe at all: an operator whose host cannot
/// reach the IdP must still be able to finish validating the file.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Verdict {
    Pass,
    /// Definitively the configuration: a 4xx, a document that does not parse, a
    /// published claim that disagrees with what the adapter derived.
    Fail,
    /// The world rather than the configuration: DNS, a refused connection, a
    /// timeout, a 5xx. Says nothing about whether the file is right.
    Warn,
}

impl Probe {
    pub(crate) fn pass(check: &'static str, detail: impl Into<String>) -> Self {
        Self { check, verdict: Verdict::Pass, detail: detail.into() }
    }

    pub(crate) fn fail(check: &'static str, detail: impl Into<String>) -> Self {
        Self { check, verdict: Verdict::Fail, detail: detail.into() }
    }
}

/// Append the standard OIDC discovery suffix to the configured authority.
pub(crate) fn discovery_url(authority: &str) -> String {
    format!("{}/.well-known/openid-configuration", authority.trim_end_matches('/'))
}

/// A failed GET, sorted into the two kinds but not yet attached to a question.
pub(crate) struct Trouble(Verdict, String);

impl Trouble {
    pub(crate) fn at(self, check: &'static str) -> Probe {
        Probe { check, verdict: self.0, detail: self.1 }
    }
}

/// One GET with the signing-key fetch limits.
///
/// Classify only transport and status. The adapter decides what the response
/// document means.
pub(crate) async fn get(url: &str, timeout: Duration) -> Result<String, Trouble> {
    let response = jwks::http_client(timeout)
        .map_err(|e| Trouble(Verdict::Warn, format!("{e:#}")))?
        .get(url)
        .send()
        .await
        .map_err(|e| Trouble(Verdict::Warn, format!("{url} did not answer: {}", root_cause(&e))))?;
    let status = response.status();
    if !status.is_success() {
        return Err(Trouble(status_verdict(status.as_u16()), format!("{url} answered {status}")));
    }
    jwks::bounded_body(response)
        .await
        .map_err(|e| Trouble(Verdict::Warn, format!("{url} answered, the body did not: {e:#}")))
}

/// The DNS or connection cause at the bottom of an error chain.
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
pub(crate) fn status_verdict(status: u16) -> Verdict {
    if (500..600).contains(&status) { Verdict::Warn } else { Verdict::Fail }
}

/// Ask this source's IdP the questions only it can answer.
///
/// Which document to fetch and which claim to compare are provider facts, so
/// this dispatches and the adapter implements -- beside `from_config` and
/// `template`, whose derivations are what the probe is checking.
///
/// Never called at startup or on the bootstrap path. A transient IdP outage must
/// not become a local one, which is why every verdict here is advisory to a
/// caller that already validated the file offline.
///
/// `credential` is the source's sync credential, read from
/// [`IdpSettings::sync_credential_file`] by the caller, or `None` when the
/// operator has yet to paste one in. Entra's probe reads only public documents
/// and ignores it; authentik's uses it for the three authenticated legs that a
/// public document cannot answer. Passing it rather than reading the file here
/// keeps the one secret read on the caller's side of the seam.
pub async fn probe(
    settings: &IdpSettings,
    credential: Option<&str>,
    timeout: Duration,
) -> Vec<Probe> {
    match settings {
        IdpSettings::Entra(settings) => entra::probe(settings, timeout).await,
        IdpSettings::Authentik(settings) => authentik::probe(settings, credential, timeout).await,
    }
}

/// The other face of [`IdentityProvider::identify`]: what this provider stores
/// for an account it already knows the subject of.
///
/// Sync calls this from the Graph side, the adapter calls it from the token
/// side, and they are the same function on purpose -- see the crate doc for what
/// a divergence costs.
pub fn encode_identity(
    provider: Provider,
    source: &Source,
    subject: &str,
) -> Result<ExternalIdentity, IdentityError> {
    match provider {
        Provider::Entra => entra::identity(source, subject),
        Provider::Authentik => authentik::identity(source, subject),
    }
}

#[cfg(test)]
mod conformance;

#[cfg(test)]
mod tests {
    use super::*;

    /// The same seam, in the schema rather than in the document: an editor
    /// validating a real source file against the envelope alone would mark
    /// every deployment wrong.
    #[test]
    fn a_source_schema_admits_the_block_the_envelope_leaves_out() {
        for provider in Provider::ALL {
            let name = provider.name();
            let schema = provider.source_schema().expect("the source schema composes");
            assert_eq!(schema["additionalProperties"], serde_json::json!(false), "{name}");

            let block = &schema["properties"]["provider_config"];
            assert!(block["properties"].is_object(), "{name}: the block states no properties");
            assert!(block["required"].is_array(), "{name}: the block requires nothing");
            // A published document must not carry the private struct's name,
            // nor claim a dialect of its own from inside another document.
            assert!(block.get("title").is_none(), "{name}: the block kept its Rust type name");
            assert!(block.get("$schema").is_none(), "{name}: a subschema named a dialect");
        }
    }

    /// The seam between the two halves of a source file, which nothing else
    /// exercises: core's envelope parser and this crate's block parser see the
    /// same bytes here, and an assembly that does not fit together fails as a
    /// whole document rather than as either half.
    #[test]
    fn every_assembled_source_file_parses_as_both_halves() {
        for provider in Provider::ALL {
            let text = completed(provider);
            let envelope: kerbridge_core::config::SourceFile =
                toml::from_str(&text).expect("the assembled file parses as a source file");
            assert_eq!(envelope.provider, provider.name(), "the envelope names another adapter");
            assert_eq!(envelope.name, provider.name(), "the envelope names another source");
            template_settings(provider, envelope.provider_config);
        }
    }

    /// The block this provider's own template carries, parsed.
    fn template_settings(provider: Provider, block: toml::Table) -> IdpSettings {
        IdpSettings::parse(provider, &block).expect("the block the envelope carried")
    }

    /// One provider's whole source file with its lines to complete filled in
    /// from their own examples -- the document a deployment holds. A template
    /// answers nothing the parser requires, so nothing here parses one.
    fn completed(provider: Provider) -> String {
        let body = provider.source_template().expect("the source template renders");
        let schema = provider.source_schema().expect("the source schema composes");
        kerbridge_core::config::decisions::completed(&body, &schema)
            .expect("the template completes")
    }

    /// What holds the hand-written half to the adapter: every key the block
    /// states answers, under the name the file gives it, and nothing else does.
    /// A key added to an adapter and forgotten in `paths()` fails the build
    /// rather than a deployment.
    #[test]
    fn a_settings_key_answers_by_the_name_the_file_gives_it() {
        for provider in Provider::ALL {
            let name = provider.name();
            let schema = provider.source_schema().expect("the source schema composes");
            let described: Vec<&String> = schema["properties"]["provider_config"]["properties"]
                .as_object()
                .expect("the block states properties")
                .keys()
                .collect();

            let block = toml::from_str::<kerbridge_core::config::SourceFile>(&completed(provider))
                .expect("the assembled file parses")
                .provider_config;
            let answered = template_settings(provider, block).paths();

            let missed: Vec<&&String> =
                described.iter().filter(|key| !answered.contains_key(**key)).collect();
            assert!(
                missed.is_empty(),
                "{name}: the block states {missed:?} and `paths()` does not answer it -- \
                 `kbconfig get sources.<name>.<key>` has to reach every key the file has."
            );
            let invented: Vec<&String> =
                answered.keys().filter(|key| !described.contains(key)).collect();
            assert!(
                invented.is_empty(),
                "{name}: `paths()` answers {invented:?} and the block has no such key -- a path \
                 is spelled the way the file spells it."
            );
        }
    }

    /// The committed copies are what a reader evaluating the project sees on
    /// GitHub, which is half the point of committing a generated file. Same
    /// guarantee as `cargo fmt --check`, same regeneration step.
    #[test]
    fn the_committed_source_templates_are_current() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/configs");
        let write = std::env::var_os("KB_WRITE_CONFIG_TEMPLATES").is_some();
        for provider in Provider::ALL {
            let name = format!("idp_{}.toml.example", provider.name());
            let body = provider.source_template().expect("the source template renders");
            let path = dir.join(&name);
            if write {
                std::fs::write(&path, &body).expect("writing the template");
                continue;
            }
            // Absent is not a failure: see the note on kerbridge-core's
            // `the_committed_templates_are_current`.
            let committed = match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => panic!("reading deploy/configs/{name}: {e}"),
            };
            // Not assert_eq!: the bodies are kilobytes and the dump buries the
            // one line that says how to fix it.
            assert!(
                committed == body,
                "deploy/configs/{name} is stale. Regenerate with \
                 `KB_WRITE_CONFIG_TEMPLATES=1 cargo test -p kerbridge-idp`."
            );
        }
    }

    /// A 4xx rejects the request. A 5xx gives no configuration verdict.
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
    fn the_discovery_url_hangs_off_the_authority() {
        let want = "https://idp.example.site/tenant/.well-known/openid-configuration";
        assert_eq!(discovery_url("https://idp.example.site/tenant"), want);
        assert_eq!(discovery_url("https://idp.example.site/tenant/"), want);
    }

    #[test]
    fn a_provider_name_round_trips_and_an_unknown_one_is_refused() {
        for provider in Provider::ALL {
            assert_eq!(Provider::from_name(provider.name()).unwrap(), provider);
        }
        let err = Provider::from_name("google").unwrap_err().to_string();
        assert!(err.contains("google"), "{err}");
    }
}
