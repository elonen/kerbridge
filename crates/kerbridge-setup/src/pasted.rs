//! The credentials an operator pastes in, as opposed to the ones KerBridge
//! generates.
//!
//! The secrets tree is split by *who writes the file*: `kbsetup realm` and
//! `kbsetup directory` write everything under `generated/`, and everything
//! under `idp/` comes from somewhere KerBridge cannot reach -- a portal, a
//! chat webhook. Nothing generates those, so a deployment that never had them
//! pasted in sits there looking installed and serves no sign-in.
//!
//! This module answers *which ones does this config set call for, and are they
//! there yet*. `secrets::run` asks the operator for the ones that are not, and
//! `status` counts them.
//!
//! **Found by convention, worded by table.** A source's `[provider_config]`
//! arrives from `kerbridge-core` as an opaque `toml::Table` -- deliberately, so
//! that nothing outside `kerbridge-idp` carries a struct describing what an
//! Entra deployment needs. Rather than parse it, this takes every key whose
//! name ends in `_credential_file` as a pasted credential, and looks the
//! operator-facing sentence up in [`PROMPTS`].
//!
//! **Why the sentence is not asked of `kerbridge-idp`.** That crate owns what
//! the option means and would be the natural home for how to word it, but it
//! carries `reqwest` and `tokio` for fetching signing keys, and `kbsetup` ships
//! in the same package as `issuerd`, which links no HTTP client at all. So the
//! two are held in step by a test instead: `kerbridge-idp` is a dev-dependency,
//! and `every_declared_credential_has_a_prompt` fails the build if an adapter's
//! template declares a credential this table has no words for.

use std::path::{Path, PathBuf};

use anyhow::Result;
use kerbridge_core::config::Config;

/// The key suffix that marks a pasted credential in a `[provider_config]`.
///
/// A convention rather than a list of key names, so that an adapter added later
/// is found here without editing this file. `every_declared_credential_has_a_prompt`
/// is what keeps an adapter from choosing a different spelling.
pub const SUFFIX: &str = "_credential_file";

/// What each pasted credential is, in the words to show at the prompt.
///
/// Keyed by provider *and* option, not by option alone: two adapters may spell
/// the same key and mean different credentials.
const PROMPTS: &[Words] = &[Words {
    provider: "entra",
    option: "sync_credential_file",
    what: "The client secret of the Entra app registration for synchronization,\n\
           usually named \"KerBridge sync\". Entra shows it once, when it is created:\n\
           Certificates & secrets -> Client secrets on that app's blade.",
    caution: Some(
        "Copy the secret's Value, not the Secret ID beside it. The Secret ID is a GUID,\n\
         and it is the one still readable after the Value has been masked.",
    ),
}];

struct Words {
    provider: &'static str,
    option: &'static str,
    what: &'static str,
    caution: Option<&'static str>,
}

/// One credential the config set names and KerBridge cannot produce.
pub struct Pasted {
    /// The source that calls for it, or `None` for one that belongs to the
    /// deployment rather than to a source.
    pub source: Option<String>,
    /// The option that names the path, as `kbconfig get` spells it.
    pub option: String,
    pub path: PathBuf,
    /// What to fetch and where from. Shown above the prompt.
    pub what: String,
    /// The mistake worth naming before it is made, if there is one.
    pub caution: Option<String>,
    /// Whether the deployment still works with this one left empty.
    pub optional: bool,
}

impl Pasted {
    /// How the credential is named in a report: `entra.sync_credential_file`.
    pub fn named(&self) -> String {
        match &self.source {
            Some(source) => format!("{source}.{}", self.option),
            None => self.option.clone(),
        }
    }

    /// Is the file there and non-empty. Empty is absent -- the rule the whole
    /// secrets tree is written to; see the [`crate::secrets`] module comment.
    pub fn present(&self) -> Result<bool> {
        crate::secrets::existing(&self.path).map(|value| value.is_some())
    }
}

/// Every pasted credential this config set calls for, in the order to ask for
/// them: each source's own first, and the deployment-wide optional ones last.
pub fn wanted(config: &Config) -> Vec<Pasted> {
    let mut out = Vec::new();
    for source in &config.sources {
        for (option, value) in &source.provider_config {
            if !option.ends_with(SUFFIX) {
                continue;
            }
            // A key of the right shape whose value is not a path is the
            // adapter's own error to report, in its own words, when it parses
            // the block. Skipping it here is what keeps that the only report.
            let Some(path) = value.as_str() else { continue };
            let words = PROMPTS
                .iter()
                .find(|words| words.provider == source.provider && words.option == option);
            out.push(Pasted {
                source: Some(source.name.clone()),
                option: option.clone(),
                path: PathBuf::from(path),
                what: words.map_or_else(
                    || {
                        format!(
                            "The credential {option} names, for the {} source. This version of \
                             kbsetup has no description of it -- see the comment above {option} \
                             in idp_{}.toml.",
                            source.name, source.name
                        )
                    },
                    |words| words.what.to_owned(),
                ),
                caution: words.and_then(|words| words.caution).map(str::to_owned),
                // A source with no credential mirrors nothing and admits
                // nobody, so every one of these is required.
                optional: false,
            });
        }
    }

    // The webhook URL is a secret for the same reason and by the same rule --
    // for Slack, Teams and the rest the URL is the receiver's whole
    // authentication -- and it is the only one outside a source. Asked for only
    // when the set names a file for it: with no `url_file` the deployment has
    // chosen to keep operator events in the log, which is supported.
    if let Some(path) = &config.main.notify.url_file {
        out.push(Pasted {
            source: None,
            option: "notify.url_file".to_owned(),
            path: path.clone(),
            what: "The webhook URL that operator notifications are posted to -- the Incoming \
                   Webhook of a Slack, Teams, Mattermost or Rocket.Chat channel.\n\
                   https:// only."
                .to_owned(),
            caution: Some(
                "This URL is a secret: for every one of those receivers it is the whole of \
                 the\nauthentication, so anyone holding it can post as your deployment."
                    .to_owned(),
            ),
            optional: true,
        });
    }
    out
}

/// The pasted credentials that are still missing, which is what both `status`
/// and `secrets` act on.
pub fn missing(config: &Config) -> Result<Vec<Pasted>> {
    let mut out = Vec::new();
    for want in wanted(config) {
        if !want.present()? {
            out.push(want);
        }
    }
    Ok(out)
}

/// Why this text cannot be the credential, if it cannot be.
///
/// Checked here rather than left to the daemon that reads the file, because the
/// operator is standing at the prompt with the portal still open. `kbsetup`
/// refusing the Secret ID costs them one retry; sync refusing it costs them a
/// failed cycle and a journal to read.
pub fn refuse(value: &str, path: &Path) -> Option<String> {
    if value.is_empty() {
        return Some("nothing was typed".to_owned());
    }
    // Folded: `is_guid` is canonical-only, and an uppercase Secret ID is still
    // a Secret ID.
    if kerbridge_core::is_guid(&value.to_ascii_lowercase()) {
        return Some(format!(
            "that is a GUID. For an Entra client secret it is the Secret ID rather than the \
             Value -- the Value is the longer string beside it, and the portal masks it as soon \
             as you leave the blade. {} is refused with the same words by the daemon that reads \
             it, so writing it would only move the failure.",
            path.display()
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{SOURCE_WITH_CREDENTIAL, set_with};

    /// The convention the module comment states, exercised through a real
    /// config set rather than a hand-built table.
    #[test]
    fn a_sources_credential_file_key_is_found_and_worded() {
        let set = set_with(&[("idp_entra.toml", SOURCE_WITH_CREDENTIAL)]);
        let config = Config::load(set.dir()).unwrap();
        let wanted = wanted(&config);
        let entra = wanted.iter().find(|w| w.option == "sync_credential_file").unwrap();
        assert_eq!(entra.source.as_deref(), Some("entra"));
        assert!(entra.what.contains("KerBridge sync"), "{}", entra.what);
        assert!(entra.caution.as_ref().unwrap().contains("Secret ID"));
        assert!(!entra.optional);
    }

    /// The two halves the module comment names, held in step: `kerbridge-idp`
    /// owns what a credential *is*, this owns how to word it. An adapter added
    /// without a sentence here would prompt with a paragraph saying nothing,
    /// and an adapter that spells its key some other way would not be found at
    /// all.
    #[test]
    fn every_declared_credential_has_a_prompt() {
        for provider in kerbridge_idp::Provider::ALL {
            let template = provider.source_template().expect("the source template renders");
            let declared: Vec<&str> = template
                .lines()
                .filter_map(|line| line.split_once('=').map(|(key, _)| key))
                .map(|key| key.trim().trim_start_matches('#').trim())
                .filter(|key| key.ends_with(SUFFIX))
                .collect();
            assert!(
                !declared.is_empty(),
                "the {} template declares no *{SUFFIX} option, so kbsetup secrets would never \
                 ask for that source's credential",
                provider.name()
            );
            for option in declared {
                assert!(
                    PROMPTS.iter().any(|w| w.provider == provider.name() && w.option == option),
                    "{}.{option} has no entry in PROMPTS",
                    provider.name()
                );
            }
        }
    }

    /// The trap the Entra prompt warns about, refused at the prompt rather than
    /// three hours later in sync's journal.
    #[test]
    fn a_secret_id_is_refused_and_the_value_is_not() {
        let path = Path::new("/etc/kerbridge.secrets/idp/entra/credential");
        let guid = "77778888-bbbb-9999-cccc-0000dddd1111";
        assert!(refuse(guid, path).unwrap().contains("Secret ID"));
        assert!(refuse(&guid.to_ascii_uppercase(), path).unwrap().contains("Secret ID"));
        assert!(refuse("", path).is_some());
        assert!(refuse("aB3~qX9.some-real-looking-secret-value-Zz0", path).is_none());
    }
}
