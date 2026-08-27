//! Sync configuration: the config set reduced to what the mirror does, and to
//! the sources it does it for.
//!
//! Secrets are the files this names, never values in it -- a credential in a
//! config file is a credential in every backup of it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use kerbridge_core::Source;
use kerbridge_core::config::SourceFile;
use kerbridge_idp::sync::Subject;
use kerbridge_idp::{IdpSettings, Provider};

/// What one process does, and for whom.
///
/// Everything here is deployment-wide; anything that could differ between two
/// cloud IdPs is in [`SourceConfig`]. The split is not cosmetic: the fields
/// below are read once and shared, and a value that belongs per source but sat
/// here would silently make the second source a copy of the first.
pub struct Config {
    /// The pause between cycles, not the rate of them.
    pub interval: Duration,
    /// Compute and log the plan but apply nothing. A safe way to watch a new
    /// deployment before letting it write.
    pub dry_run: bool,
    /// Whether a live account's login name follows its cloud display name.
    /// Default on. Off freezes every live name where it is.
    pub automatic_sam_renames: bool,
    /// `main.toml`'s value, read here only to work out which grants are near
    /// their *effective* deadline for the expiry notification. Sync neither
    /// enforces nor writes it.
    pub device_grant_days: u32,
    /// How many days ahead of a grant's effective deadline to open the
    /// aggregate expiry problem, or `None` for not notifying.
    pub device_grant_notify_days: Option<u32>,
    pub warn_before_days: i64,
    pub realm: String,
    /// Passed to `kerbridge-notify` verbatim. Read from `main.toml` rather than
    /// per component, because an operator wiring up a channel is wiring up one.
    pub notify: kerbridge_core::config::Notify,
    pub ldap_url: String,
    pub base_dn: String,
    /// The AD DNS domain, used as the UPN suffix for created users.
    pub upn_suffix: String,
    pub ldap_ca_file: PathBuf,
    /// Where the record of what this process wrote to the directory is kept, or
    /// `None` when the deployment said `none` and keeps the console copy alone.
    pub audit_log_file: Option<PathBuf>,
    /// Every source, in the order `main.toml` lists them. May be empty: a realm
    /// mid-bootstrap has nothing to mirror yet, which is not a fault.
    pub sources: Vec<SourceConfig>,
}

/// One source, as the mirror sees it: an identity to bind as, an OU to own, and
/// a cloud IdP to read.
pub struct SourceConfig {
    pub source: Source,
    provider: Provider,
    /// The one OU this source owns, one level under the IdP parent OU -- e.g.
    /// `OU=Entra,OU=CloudIdP,<base_dn>`. Never shared: it is the scope of this
    /// identity's write ACE and of the realm-admission marker's exactly-one
    /// rule, so two sources in one OU would give the broker two admission
    /// groups and freeze every login.
    pub idp_ou: String,
    /// What every synchronized group's `sAMAccountName` ends with. Empty only
    /// when the source file wrote `none`.
    pub group_suffix: String,
    pub bind_dn: String,
    pub bind_password: String,
    /// The adapter's half of the source file: the IdP, its credential and
    /// its group ids. Handed to [`kerbridge_idp::sync::connect`] and never read
    /// above the seam.
    pub settings: IdpSettings,
}

impl Config {
    /// The whole config set, reduced to what this process serves.
    ///
    /// Every source's `[provider_config]` is parsed here rather than at first
    /// use: a typo in one would otherwise surface as one source's people
    /// quietly not appearing, long after the operator stopped watching.
    pub fn load(dir: &Path) -> Result<(Self, Vec<String>)> {
        let set = kerbridge_core::config::Config::load(dir)?;
        let (realm, sync) = (set.realm, set.sync);

        let parent_ou = realm.idp_parent_ou();
        let mut sources = Vec::with_capacity(set.sources.len());
        for file in &set.sources {
            sources.push(SourceConfig::load(file, &parent_ou)?);
        }

        let config = Self {
            interval: interval(sync.interval_seconds)?,
            dry_run: sync.dry_run,
            automatic_sam_renames: sync.automatic_sam_renames,
            device_grant_days: set.main.device_grant_days,
            device_grant_notify_days: notify_days(&sync.device_grant_notify)?,
            warn_before_days: sync.credential_warn_before_days.into(),
            notify: set.main.notify,
            base_dn: realm.base_dn(),
            upn_suffix: realm.ad_dns_domain(),
            ldap_url: realm.ldap_url,
            ldap_ca_file: realm.ldap_ca_file,
            realm: realm.realm,
            audit_log_file: sync.audit_log_file,
            sources,
        };
        Ok((config, set.warnings))
    }
}

impl SourceConfig {
    fn load(file: &SourceFile, parent_ou: &str) -> Result<Self> {
        let named = format!("idp_{}.toml", file.name);
        let provider =
            Provider::from_name(&file.provider).with_context(|| format!("{named}: provider"))?;
        let settings = IdpSettings::parse(provider, &file.provider_config)
            .with_context(|| format!("in {named}"))?;
        Ok(Self {
            source: Source::new(file.name.clone()).with_context(|| format!("{named}: name"))?,
            provider,
            idp_ou: file.ou(parent_ou),
            group_suffix: group_suffix(&file.group_suffix, &named)?,
            bind_dn: file.bind_dn.clone(),
            bind_password: kerbridge_core::secret::read(&file.bind_password_file)
                .with_context(|| format!("{named}: bind_password_file"))?,
            settings,
        })
    }

    pub fn name(&self) -> &str {
        self.source.name()
    }

    /// How this source's subjects become stored identity values, for the
    /// planner. The adapter's own encoder, never a copy of it -- the broker's
    /// verifier emits the same bytes from the token side.
    pub fn identity(&self) -> impl Fn(&Subject) -> Result<String, kerbridge_core::IdentityError> {
        let (provider, source) = (self.provider, self.source.clone());
        move |subject| {
            kerbridge_idp::encode_identity(provider, &source, subject.as_str())
                .map(|id| id.encode())
        }
    }
}

/// `sync.toml`'s `interval_seconds`, which is the pause between cycles.
///
/// Zero is refused: it asks for no pause at all, which spends the IdP's request
/// quota and the directory's write capacity on a loop that never rests.
/// Nothing above zero is refused. Where a floor belongs is policy, and no
/// measurement says where to put it.
fn interval(seconds: u32) -> Result<Duration> {
    if seconds == 0 {
        bail!("sync.toml: interval_seconds is the pause between cycles; 0 is not a pause");
    }
    Ok(Duration::from_secs(seconds.into()))
}

/// `sync.toml`'s `device_grant_notify`: `off`, or a number of days ahead of a
/// grant's deadline to start warning.
///
/// Off by default because the event names machine labels, and an operator should
/// choose to send those to whatever channel they wired up rather than discover
/// afterwards that they did. An unrecognized value is refused rather than
/// treated as `off`: silently not notifying is the failure mode this setting
/// exists to prevent.
fn notify_days(raw: &str) -> Result<Option<u32>> {
    match raw {
        "off" | "0" => Ok(None),
        raw => raw.parse().map(Some).map_err(|_| {
            anyhow::anyhow!(
                "sync.toml: device_grant_notify expects `off` or a number of days; got {raw:?}"
            )
        }),
    }
}

/// A source's group `sAMAccountName` suffix, or the literal `none` for none at
/// all.
///
/// Both answers are consequential and only the operator knows which applies,
/// which is why `kerbridge-core` takes the key without a default and leaves the
/// rule here, beside the planner that would hit the collision:
/// `planner::PlanError::NameCollision` is what an unsuffixed second source
/// costs.
fn group_suffix(raw: &str, named: &str) -> Result<String> {
    if raw == "none" {
        return Ok(String::new());
    }
    if let Some(why) = crate::planner::group_suffix_rejection(raw) {
        bail!("{named}: group_suffix {raw:?} {why}; or `none` for no suffix");
    }
    Ok(raw.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `none` is the spelling for no suffix at all, and a value the planner
    /// would refuse is refused here instead -- where the file that carries it
    /// can be named.
    #[test]
    fn a_group_suffix_is_none_or_a_name_the_planner_accepts() {
        assert_eq!(group_suffix("none", "idp_entra.toml").unwrap(), "");
        assert_eq!(group_suffix("-entra", "idp_entra.toml").unwrap(), "-entra");
        let err = group_suffix("a b", "idp_entra.toml").unwrap_err().to_string();
        assert!(err.contains("idp_entra.toml") && err.contains("none"), "{err}");
    }

    /// An unrecognized value is a refusal, not a silent default -- and `off` is
    /// spelled, so a deployment that wants no notification says so.
    #[test]
    fn the_notify_setting_refuses_what_it_does_not_recognize() {
        assert_eq!(notify_days("off").unwrap(), None);
        assert_eq!(notify_days("14").unwrap(), Some(14));
        assert!(notify_days("yes").is_err());
    }

    /// A pause of nothing is the one interval that is refused, and the refusal
    /// stops there: every other value is the operator's to choose.
    #[test]
    fn the_interval_refuses_zero_and_nothing_above_it() {
        assert!(interval(0).is_err());
        assert_eq!(interval(1).unwrap(), Duration::from_secs(1));
        assert_eq!(interval(300).unwrap(), Duration::from_secs(300));
    }
}
