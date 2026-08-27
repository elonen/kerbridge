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
use kerbridge_core::is_guid;
use kerbridge_core::time::days_from_ymd;
use kerbridge_idp::{IdpSettings, Provider};

use crate::planner::SamSource;

/// What one process does, and for whom.
///
/// Everything here is deployment-wide; anything that could differ between two
/// cloud tenants is in [`SourceConfig`]. The split is not cosmetic: the fields
/// below are read once and shared, and a value that belongs per source but sat
/// here would silently make the second source a copy of the first.
pub struct Config {
    /// The pause between cycles, not the rate of them.
    pub interval: Duration,
    /// Compute and log the plan but apply nothing. A safe way to watch a new
    /// deployment before letting it write.
    pub dry_run: bool,
    /// Which cloud attribute a *newly created* account's `sAMAccountName` is
    /// derived from. Existing accounts are never renamed by it.
    pub sam_source: SamSource,
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
/// a cloud tenant to read.
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
    pub tenant_id: String,
    pub graph_client_id: String,
    /// Read at the start of a cycle rather than here: it arrives from the portal
    /// after the deployment is running, and a source still waiting for one must
    /// not stop the others from mirroring.
    pub credential_file: PathBuf,
    /// Operator-asserted expiry of a *secret* credential (`YYYY-MM-DD`).
    /// Absent means no advance warning, not a refusal to run.
    pub credential_expires: Option<String>,
    /// Who may hold Kerberos tickets, by object id.
    pub admission_group_id: String,
    /// Who may activate a device grant, by object id. `None` is a source with no
    /// device-grant group and therefore no working grants -- the broker finds
    /// the group by its marker.
    pub grant_group_id: Option<String>,
    /// Extra group ids to synchronize beyond the admission-group-reachable
    /// closure.
    pub allowlist: Vec<String>,
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
            sam_source: sam_source(&sync.sam_source)?,
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
        // The match rather than a field access: a second adapter arrives here as
        // a compile error, which is the only way this crate's Graph client
        // cannot end up pointed at a tenant that does not speak Graph.
        let IdpSettings::Entra(entra) = settings;

        Ok(Self {
            source: Source::new(file.name.clone()).with_context(|| format!("{named}: name"))?,
            provider,
            idp_ou: file.ou(parent_ou),
            group_suffix: group_suffix(&file.group_suffix, &named)?,
            bind_dn: file.bind_dn.clone(),
            bind_password: kerbridge_core::secret::read(&file.bind_password_file)
                .with_context(|| format!("{named}: bind_password_file"))?,
            tenant_id: entra.tenant_id,
            graph_client_id: entra.sync_client_id,
            credential_file: entra.sync_credential_file,
            credential_expires: entra.sync_credential_expires,
            admission_group_id: entra.admission_group_id,
            grant_group_id: entra.device_grant_group_id,
            allowlist: entra.extra_group_ids,
        })
    }

    pub fn name(&self) -> &str {
        self.source.name()
    }

    /// How this source's subjects become stored identity values, for the
    /// planner. The adapter's own encoder, never a copy of it -- the broker's
    /// verifier emits the same bytes from the token side.
    pub fn identity(&self) -> impl Fn(&str) -> Result<String, kerbridge_core::IdentityError> {
        let (provider, source) = (self.provider, self.source.clone());
        move |subject| {
            kerbridge_idp::encode_identity(provider, &source, subject).map(|id| id.encode())
        }
    }

    /// This source's Graph credential, or `None` while the operator has yet to
    /// paste one in.
    ///
    /// A compose secret is a bind mount, so the file has to exist before the
    /// container starts and `prepare-state` creates it empty. Empty means
    /// the Graph app registration has not happened yet -- a deployment that has
    /// not got there, not a fault. So the source is skipped and re-checked next
    /// cycle rather than refused, and an operator who drops the secret in starts
    /// mirroring with nothing to restart.
    ///
    /// Only emptiness is treated this way. A credential that is present and
    /// wrong -- the *Secret ID* GUID, say -- is an error, and so is one this
    /// process is not allowed to read.
    ///
    /// `EACCES` in particular must not read as "not yet": it is the *likely*
    /// failure on Linux, where a compose secret is a bind mount and the host
    /// file's mode reaches the container unchanged. Sync runs unprivileged and
    /// reaches its secret through `BROKER_GID`, so a credential written `0600`
    /// owned by the root that wrote it is unreadable to it. Docker Desktop
    /// remaps the ownership and hides this, which is why the bench never saw it
    /// -- the same reason [`kerbridge_core::secret::read`] records.
    pub fn credential(&self) -> Result<Option<String>> {
        let shown = self.credential_file.display();
        match std::fs::read_to_string(&self.credential_file) {
            Ok(raw) if raw.trim().is_empty() => Ok(None),
            Ok(_) => {
                let value = kerbridge_core::secret::read(&self.credential_file)?;
                // Folded: `is_guid` is canonical-only, and an uppercase Secret
                // ID is still a Secret ID. Losing the fold is fail-open.
                if is_guid(&value.to_ascii_lowercase()) {
                    bail!(
                        "secret file {shown} contains a GUID: that is the credential's Secret ID, \
                         not its Value"
                    );
                }
                Ok(Some(value))
            }
            // This arm never reaches `secret::read`, so the diagnosis is asked
            // for by name -- and it prints the group the file actually has,
            // where a message written here could only name `$BROKER_GID`.
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                bail!("{}", kerbridge_core::secret::denial(&self.credential_file))
            }
            // Absent is the fresh-deployment case `prepare-state` creates,
            // and anything else here is a path that is not there either.
            Err(_) => Ok(None),
        }
    }

    /// Days until the operator-asserted credential expiry, if one is set. `None`
    /// when unset; negative once past. The value is an assertion, not a
    /// measurement -- a rotated secret with a stale date reports false headroom.
    ///
    /// `now` is unix seconds, supplied rather than read, for the reason the
    /// broker's verifier gives: a function that reads the clock itself can only
    /// be tested against the clock, and this one straddles a day boundary that
    /// would otherwise make the test flake once every 86 400 runs.
    pub fn credential_days_remaining(&self, now: u64) -> Option<i64> {
        let expiry = days_from_ymd(self.credential_expires.as_deref()?)?;
        Some(expiry - (now / 86_400) as i64)
    }

    /// One source with nothing behind it, for a test driving a cycle without a
    /// config set. Lives here because `provider` is this module's own.
    #[cfg(test)]
    pub fn for_test() -> Self {
        Self {
            source: Source::new("entra").expect("a source name"),
            provider: Provider::Entra,
            idp_ou: "OU=Entra,OU=CloudIdP,DC=example,DC=site".to_owned(),
            group_suffix: "-kb".to_owned(),
            bind_dn: "CN=svc-sync,DC=example,DC=site".to_owned(),
            bind_password: "unused".to_owned(),
            tenant_id: "00000000-0000-0000-0000-000000000000".to_owned(),
            graph_client_id: "11111111-1111-1111-1111-111111111111".to_owned(),
            credential_file: PathBuf::from("/nonexistent/credential"),
            credential_expires: None,
            admission_group_id: "77778888-bbbb-9999-cccc-0000dddd1111".to_owned(),
            grant_group_id: None,
            allowlist: Vec::new(),
        }
    }
}

/// `sync.toml`'s `interval_seconds`, which is the pause between cycles.
///
/// Zero is refused: it asks for no pause at all, which spends the tenant's
/// Graph quota and the directory's write capacity on a loop that never rests.
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

/// `sync.toml`'s `sam_source`. An unrecognized value is refused rather than
/// defaulted: it is a name policy for every account the deployment will ever
/// create, and a typo that silently picks the default is discovered only when
/// someone reads a login name in Explorer.
fn sam_source(raw: &str) -> Result<SamSource> {
    raw.parse().map_err(|()| {
        anyhow::anyhow!(
            "sync.toml: sam_source expects one of {}; got {raw:?}",
            SamSource::SPELLINGS
        )
    })
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

    /// The trap itself, rather than the shape check behind it -- that lives with
    /// `is_guid`'s own tests, and the LDAP bind password deliberately does not
    /// get this treatment: it has no Secret ID to be confused with, and a
    /// generated password could legitimately come out GUID-shaped.
    #[test]
    fn a_secret_id_is_refused_where_a_secret_value_is_not() {
        let refused = |value: &str| is_guid(&value.to_ascii_lowercase());
        let secret_id = "0a94cc71-1a92-4730-a2d9-8213912b4e6d";
        assert!(refused(secret_id), "a Secret ID is GUID-shaped");
        assert!(refused(&secret_id.to_ascii_uppercase()), "in uppercase too");
        assert!(!refused("aB3~qX9.some-real-looking-secret-value-Zz0"));
    }

    /// The expiry is an operator's assertion in a file, so the whole range
    /// matters: a date that has passed must read as negative headroom, not as a
    /// parse failure that reports nothing -- `report_credential` distinguishes
    /// "expires in 5 days" from "expired 5 days ago" only by the sign.
    #[test]
    fn credential_headroom_is_signed() {
        // 2026-07-25T12:00:00Z, midday so the assertions do not sit on a day
        // boundary the way a wall clock would.
        const NOW: u64 = 1_784_980_800;
        let cfg = |expires: Option<&str>| SourceConfig {
            credential_expires: expires.map(str::to_owned),
            ..blank()
        };
        assert_eq!(cfg(None).credential_days_remaining(NOW), None);
        assert_eq!(cfg(Some("not-a-date")).credential_days_remaining(NOW), None);
        assert_eq!(cfg(Some("2026-07-25")).credential_days_remaining(NOW), Some(0));
        assert_eq!(cfg(Some("2026-08-24")).credential_days_remaining(NOW), Some(30));
        assert_eq!(cfg(Some("2026-07-20")).credential_days_remaining(NOW), Some(-5));
    }

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

    /// An unrecognized value is a refusal, not a silent default, in both
    /// directions -- and `off` is spelled, so a deployment that wants no
    /// notification says so.
    #[test]
    fn the_two_spelled_settings_refuse_what_they_do_not_recognize() {
        assert_eq!(notify_days("off").unwrap(), None);
        assert_eq!(notify_days("14").unwrap(), Some(14));
        assert!(notify_days("yes").is_err());
        assert_eq!(sam_source("upn").unwrap(), SamSource::Upn);
        assert!(sam_source("").is_err());
    }

    /// A pause of nothing is the one interval that is refused, and the refusal
    /// stops there: every other value is the operator's to choose.
    #[test]
    fn the_interval_refuses_zero_and_nothing_above_it() {
        assert!(interval(0).is_err());
        assert_eq!(interval(1).unwrap(), Duration::from_secs(1));
        assert_eq!(interval(300).unwrap(), Duration::from_secs(300));
    }

    fn blank() -> SourceConfig {
        SourceConfig {
            source: Source::new("entra").unwrap(),
            provider: Provider::Entra,
            idp_ou: String::new(),
            group_suffix: String::new(),
            bind_dn: String::new(),
            bind_password: String::new(),
            tenant_id: String::new(),
            graph_client_id: String::new(),
            credential_file: PathBuf::new(),
            credential_expires: None,
            admission_group_id: String::new(),
            grant_group_id: None,
            allowlist: Vec::new(),
        }
    }
}
