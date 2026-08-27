//! Which deployment `kbmanage` acts on, and what it takes out of it.
//!
//! Precedence, highest first: a command-line flag, the deployment's config set,
//! a derived default. `--config` names the set's directory outright; without it
//! the set is the one [`kerbridge_core::config::discover`] finds among its two
//! fixed locations.
//!
//! Only `bind_dn` and the bind password file have no answer outside
//! `kbmanage.toml`. Everything else falls back to `realm.toml`, so on a host
//! without that file `--bind-dn` and `--password-file` are a complete
//! configuration.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};

#[derive(Debug, Clone)]
pub struct Config {
    pub url: String,
    pub base_dn: String,
    pub cloud_idp_ou: String,
    pub resource_ou: String,
    pub bind_dn: String,
    /// The file the credential was read from, so `kbmanage config` can name it.
    pub password_file: PathBuf,
    /// The credential, or why it could not be read.
    ///
    /// Deferred rather than fatal at load, because two of this tool's verbs
    /// bind nothing. `config` exists to be answerable when connecting is what
    /// fails, and `doctor` promises to walk a chain and name the first broken
    /// link -- neither can keep its promise if an unreadable credential ends
    /// the program before either has said a word. A host that has installed the
    /// packages and not yet run `kbsetup directory` has no credential, and that
    /// is exactly the host whose configuration someone needs printed. Every
    /// verb that does bind takes it through `Directory::new`, which turns this
    /// Err back into the same message it would have carried.
    pub bind_password: Result<String, String>,
    pub ca_file: PathBuf,
    /// The parent of the per-service problem directories, as `main.toml` states
    /// it. `None` is `notify.state_dir = "none"`, where the open problems exist
    /// in each service's memory and nowhere a reader can reach.
    pub notify_state_dir: Option<PathBuf>,
    pub timeout: Duration,
    /// The config set that answered, for `kbmanage config` and for error
    /// messages that would otherwise leave an operator guessing which
    /// deployment was read.
    pub source: PathBuf,
    /// Non-fatal remarks about the set, said out loud by the caller at startup.
    pub warnings: Vec<String>,
}

/// What the CLI may override. Every field is optional: a flag wins, and anything
/// left unset comes from the config set.
#[derive(Debug, Default, Clone)]
pub struct Overrides {
    pub config: Option<PathBuf>,
    pub url: Option<String>,
    pub base_dn: Option<String>,
    pub resource_ou: Option<String>,
    pub bind_dn: Option<String>,
    pub password_file: Option<PathBuf>,
    pub ca_file: Option<PathBuf>,
}

impl Config {
    pub fn load(over: &Overrides) -> Result<Self> {
        let source = match &over.config {
            Some(path) => path.clone(),
            None => kerbridge_core::config::discover()?,
        };
        let set = kerbridge_core::config::Config::load(&source)?;
        let (main, realm, kbmanage, warnings) = (set.main, set.realm, set.kbmanage, set.warnings);

        // The two values `realm.toml` cannot answer, so the two a deployment
        // with no `kbmanage.toml` has to be given on the command line.
        let missing = |field: &str, flag: &str, example: &str| {
            anyhow!(
                "{field} is not set: {} does not exist. Pass {flag} {example}, or run \
                 `make kbmanage-config` in deploy/ to write it.",
                source.join("kbmanage.toml").display()
            )
        };

        let url = match (&over.url, &kbmanage) {
            (Some(url), _) => url.clone(),
            (None, Some(k)) => k.ldap_url(&realm).to_owned(),
            (None, None) => realm.ldap_url.clone(),
        };
        // Checked after `--url` has had its say, not before: this tool is run by
        // hand and the flag is the likeliest place the mistake is made.
        kerbridge_core::require_ldaps(&url).context("--url")?;

        let ca_file = match (&over.ca_file, &kbmanage) {
            (Some(path), _) => path.clone(),
            (None, Some(k)) => k.ldap_ca_file(&realm).to_owned(),
            (None, None) => realm.ldap_ca_file.clone(),
        };
        let bind_dn = match (&over.bind_dn, &kbmanage) {
            (Some(dn), _) => dn.clone(),
            (None, Some(k)) => k.bind_dn.clone(),
            (None, None) => {
                return Err(missing(
                    "bind_dn",
                    "--bind-dn",
                    "CN=svc-kerbridge-manage,CN=Users,DC=example,DC=site",
                ));
            }
        };
        let password_file = match (&over.password_file, &kbmanage) {
            (Some(path), _) => path.clone(),
            (None, Some(k)) => k.bind_password_file.clone(),
            (None, None) => {
                return Err(missing("bind_password_file", "--password-file", "<path>"));
            }
        };

        // The one password file no script gets to look at: this tool runs on the
        // operator's own host against a file they placed themselves, so
        // check-secrets.sh never sees it and the permission check has to be here.
        let bind_password = kerbridge_core::secret::read(&password_file)
            .with_context(|| {
                format!(
                    "reading the bind password from {}. `kbsetup directory` generates it \
                             with the svc-kerbridge-manage account",
                    password_file.display()
                )
            })
            .map_err(|e| format!("{e:#}"));

        Ok(Self {
            url,
            base_dn: over.base_dn.clone().unwrap_or_else(|| realm.base_dn()),
            // The parent of every IdP-specific OU, not one of them. This tool is
            // realm-wide: its containment checks ask "is this DN sync-owned", which
            // must stay true however many cloud IdPs the realm ends up with.
            cloud_idp_ou: realm.idp_parent_ou(),
            resource_ou: over.resource_ou.clone().unwrap_or_else(|| realm.resource_ou()),
            bind_dn,
            password_file,
            bind_password,
            ca_file,
            notify_state_dir: main.notify.state_dir,
            timeout: Duration::from_secs(30),
            source,
            warnings,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use kerbridge_core::config::{decisions, schemas, source_envelope, source_schema, templates};

    use super::*;

    /// A config set on disk, from the emitted templates with every line to
    /// complete filled in from its own example, plus the two things a template
    /// cannot supply: a readable password file, and a `kbmanage.toml` naming
    /// it. Every test names it with `--config`, so nothing here depends on what
    /// the host running the tests has installed.
    ///
    /// Completed rather than copied: a template does not load, and that rule is
    /// `kbconfig`'s to hold, not this crate's.
    struct Dir(PathBuf);

    impl Dir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("kbmanage-config-{}-{label}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            for ((name, body), (described, schema)) in
                templates().expect("the sources render").into_iter().zip(schemas().unwrap())
            {
                assert_eq!(name, described, "a template and a schema fell out of order");
                let body = decisions::completed(&body, &schema).expect("it completes");
                std::fs::write(path.join(name), body).unwrap();
            }
            let dir = Self(path);
            let envelope = source_envelope("entra", "entra").expect("it renders");
            let envelope = decisions::completed(&envelope, &source_schema().unwrap())
                .expect("the envelope completes");
            dir.write("idp_entra.toml", &envelope);
            dir.write("password", "s3cret\n");
            std::fs::set_permissions(dir.0.join("password"), PermissionsExt::from_mode(0o600))
                .unwrap();
            dir.write(
                "kbmanage.toml",
                &format!(
                    "bind_dn = \"CN=svc-kerbridge-manage,CN=Users,DC=example,DC=site\"\n\
                     bind_password_file = {:?}\n",
                    dir.0.join("password").display().to_string()
                ),
            );
            dir
        }

        fn write(&self, name: &str, body: &str) {
            std::fs::write(self.0.join(name), body).unwrap();
        }

        fn overrides(&self) -> Overrides {
            Overrides { config: Some(self.0.clone()), ..Overrides::default() }
        }

        fn load(&self) -> Result<Config> {
            Config::load(&self.overrides())
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `kbmanage.toml` states neither of the two it may override, so the realm's
    /// own answers stand -- as they do for everything the file cannot hold.
    #[test]
    fn the_realm_answers_everything_kbmanage_toml_leaves_out() {
        let dir = Dir::new("realm");
        let cfg = dir.load().unwrap();
        assert_eq!(cfg.url, "ldaps://kerbridge.example.site:636");
        assert_eq!(cfg.ca_file, PathBuf::from("/run/kerbridge/realm-ca.pem"));
        assert_eq!(cfg.base_dn, "DC=example,DC=site");
        assert_eq!(cfg.cloud_idp_ou, "OU=CloudIdP,DC=example,DC=site");
        assert_eq!(cfg.resource_ou, "OU=Resources,DC=example,DC=site");
        assert_eq!(cfg.bind_dn, "CN=svc-kerbridge-manage,CN=Users,DC=example,DC=site");
        assert_eq!(cfg.bind_password.as_deref(), Ok("s3cret"));
        assert_eq!(cfg.source, dir.0);
        assert!(cfg.warnings.is_empty(), "{:?}", cfg.warnings);
    }

    /// The host `debian-deployment.md` produces at its "Check it" step if
    /// `kbsetup directory` has not run yet: a complete config set and no
    /// credential. `config` and `doctor` are the two verbs whose whole purpose
    /// is to answer there, so loading has to survive it and carry the reason.
    #[test]
    fn a_credential_that_cannot_be_read_is_carried_rather_than_fatal() {
        let dir = Dir::new("no-credential");
        std::fs::remove_file(dir.0.join("password")).unwrap();
        let cfg = dir.load().expect("the set still loads");
        assert_eq!(cfg.password_file, dir.0.join("password"));
        let why = cfg.bind_password.expect_err("there is no file to read");
        assert!(why.contains("kbsetup directory"), "{why}");
        assert!(why.contains(&dir.0.join("password").display().to_string()), "{why}");
    }

    /// The precedence the module doc promises: a one-off override on the command
    /// line beats a configured host.
    #[test]
    fn a_flag_beats_the_config_set() {
        let dir = Dir::new("flag");
        let cfg = Config::load(&Overrides {
            url: Some("ldaps://other.example.site:636".to_owned()),
            base_dn: Some("DC=other,DC=site".to_owned()),
            resource_ou: Some("OU=Elsewhere,DC=other,DC=site".to_owned()),
            ca_file: Some(PathBuf::from("/tmp/other-ca.pem")),
            ..dir.overrides()
        })
        .unwrap();
        assert_eq!(cfg.url, "ldaps://other.example.site:636");
        assert_eq!(cfg.base_dn, "DC=other,DC=site");
        assert_eq!(cfg.resource_ou, "OU=Elsewhere,DC=other,DC=site");
        assert_eq!(cfg.ca_file, PathBuf::from("/tmp/other-ca.pem"));
    }

    /// The absent-tolerant file: what it alone can answer has to be named, and
    /// the flags that answer instead have to be in the message.
    #[test]
    fn a_missing_kbmanage_toml_names_the_flags_that_replace_it() {
        let dir = Dir::new("no-kbmanage");
        std::fs::remove_file(dir.0.join("kbmanage.toml")).unwrap();
        let err = format!("{:#}", dir.load().unwrap_err());
        assert!(err.contains("bind_dn is not set"), "{err}");
        assert!(err.contains("kbmanage.toml does not exist"), "{err}");
        assert!(err.contains("--bind-dn"), "{err}");

        let with_dn = Overrides { bind_dn: Some("CN=a".to_owned()), ..dir.overrides() };
        let err = format!("{:#}", Config::load(&with_dn).unwrap_err());
        assert!(err.contains("--password-file"), "{err}");

        let cfg = Config::load(&Overrides {
            password_file: Some(dir.0.join("password")),
            ..with_dn.clone()
        })
        .unwrap();
        assert_eq!(cfg.bind_dn, "CN=a");
        assert_eq!(cfg.url, "ldaps://kerbridge.example.site:636");
    }

    /// The flag is the one place a plain URL can still get in: the set's own were
    /// checked as they were read.
    #[test]
    fn a_plain_ldap_url_is_refused() {
        let dir = Dir::new("plain-ldap");
        let over =
            Overrides { url: Some("ldap://dc.example.site:389".to_owned()), ..dir.overrides() };
        let err = format!("{:#}", Config::load(&over).unwrap_err());
        assert!(err.contains("--url"), "{err}");
        assert!(err.contains("is not ldaps://"), "{err}");
    }

    /// A source file nobody listed is the set's own warning, and this tool is
    /// what says it out loud on an operator's host.
    #[test]
    fn the_sets_warnings_are_carried_to_the_caller() {
        let dir = Dir::new("warnings");
        dir.write("idp_google.toml", &source_envelope("google", "entra").expect("it renders"));
        assert_eq!(
            dir.load().unwrap().warnings,
            ["idp_google.toml present, not listed in main.sources -- ignored"]
        );
    }
}
