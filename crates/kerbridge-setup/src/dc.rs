//! The domain controller, as the four command-line tools that can act on it.
//!
//! There is no Rust binding for `ldb` or `samdb` -- crates.io has SMB *client*
//! crates only -- so the directory work drives `samba-tool`, `ldbsearch` and
//! `ldbmodify`, and the durable-state comparison drives `testparm`. That is not
//! a compromise: two of the behaviours this depends on were *measured* against
//! the pinned baseline rather than reasoned about, and re-deriving them in
//! hand-rolled descriptor code would buy nothing and lose the measurement.
//!
//! Both also hold on Samba **4.23.6**, not just the pinned 4.22.10, measured on
//! a realm `kbsetup realm` provisioned: `dsacl set` prepends its ACE and, over
//! four runs of `kbsetup directory`, leaves exactly one copy of each. Holding
//! across a major version is what the idempotency and the ordering of the deny
//! both rest on.
//!
//! **Every call names the database with `-H`.** The scripts this replaces leave
//! it off, which works inside the realm container because `smb.conf`'s private
//! directory and the configured `sam_db` are the same place. Off Compose they
//! need not be, and a bootstrap that wrote the accounts to one store and the
//! delegation to another would look like it worked. `issuerd.sam_db` is the one
//! answer, and it is also the mode both measurements were taken in -- straight
//! at `sam.ldb`, with the DC not running.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::ldif::{self, Entry};
use crate::run;

/// The file a finished `kbsetup realm` leaves beside the database.
const STAMP: &str = "kerbridge-provisioned";

/// What durable state is, as far as two file tests can tell.
///
/// Three states rather than two, because a boolean gets the middle one wrong:
/// `samba-tool domain provision` leaves a `sam.ldb` behind when it exits
/// partway, and everything downstream then compares the config set against a
/// domain that has no machine account -- and agrees with it.
pub enum State {
    /// No database at the configured path.
    Absent,
    /// A database, and the stamp saying the run that made it finished.
    Provisioned,
    /// A database with no stamp beside it.
    Unfinished,
}

pub struct Dc {
    sam_db: PathBuf,
}

impl Dc {
    pub fn at(sam_db: &Path) -> Self {
        Self { sam_db: sam_db.to_owned() }
    }

    pub fn state(&self) -> State {
        match (self.sam_db.exists(), self.stamp().exists()) {
            (false, _) => State::Absent,
            (true, true) => State::Provisioned,
            (true, false) => State::Unfinished,
        }
    }

    /// The stamp's own path, derived from the database for the reason the
    /// certificate is: a deployment that moved its private directory must not
    /// end up with the stamp in one place and the database in another.
    pub fn stamp(&self) -> PathBuf {
        self.sam_db.with_file_name(STAMP)
    }

    /// Say that provisioning finished.
    ///
    /// Written last -- after the Administrator password and the annotation --
    /// so its presence means the whole of it and not the part that reached the
    /// database.
    pub fn stamp_provisioned(&self, realm: &str) -> Result<()> {
        let path = self.stamp();
        std::fs::write(
            &path,
            format!(
                "kbsetup provisioned {realm} here, and finished.\n\
                 Delete this file only together with the Samba state beside it: kbsetup reads \
                 its absence next to a sam.ldb as a provision that died partway.\n"
            ),
        )
        .with_context(|| format!("writing {}", path.display()))
    }

    /// What to tell an operator holding a [`State::Unfinished`] realm.
    ///
    /// One text for the three verbs, because it is one state and the way out of
    /// it does not depend on which command met it.
    ///
    /// **Both readings, and neither may be dropped.** A database with no stamp
    /// is either a provision that died partway, which is unrepairable, or a
    /// working domain controller this program did not provision -- built by
    /// hand, or made before the stamp existed. Nothing here can tell them
    /// apart, and an operator who acts on the wrong one destroys a DC that
    /// serves its realm.
    pub fn unfinished(&self) -> String {
        let stamp = self.stamp().display().to_string();
        format!(
            "the Samba database at {} has no {stamp} beside it, so no `kbsetup realm` has \
             finished here. Two situations look like this, and they want opposite \
             answers:\n\n  \
             A provision that stopped partway, which is the usual one. `samba-tool domain \
             provision` leaves its database behind when it exits, and the domain it left has \
             no machine account: Samba starts on it and reports \
             NT_STATUS_CANT_ACCESS_DOMAIN_INFO, which names nothing about provisioning. \
             Nothing repairs that from outside -- destroy the Samba state and run `kbsetup \
             realm` again.\n\n  \
             A domain controller kbsetup did not provision -- built by hand, or provisioned \
             before kbsetup wrote this file. Nothing is wrong with it, and nothing above \
             applies. Once you are sure this DC serves the realm the config set names, adopt \
             it: `touch {stamp}`.",
            self.sam_db.display()
        )
    }

    fn h(&self) -> String {
        self.sam_db.display().to_string()
    }

    /// An `ldbsearch`, as entries. `extra` carries the scope, the base, any
    /// filter, the attribute list and any control.
    pub fn search(&self, extra: &[&str]) -> Result<Vec<Entry>> {
        let h = self.h();
        let mut argv = vec!["ldbsearch", "-H", h.as_str()];
        argv.extend_from_slice(extra);
        Ok(ldif::entries(&run::plain(&argv)?))
    }

    /// Whether one object is there. A failed search is "no": `ldbsearch` exits
    /// non-zero on a base search for a DN that does not exist, and every caller
    /// here is asking in order to decide whether to create it.
    pub fn exists(&self, dn: &str) -> Result<bool> {
        let h = self.h();
        let done = run::attempt(&["ldbsearch", "-H", &h, "-s", "base", "-b", dn, "dn"], None)?;
        Ok(done.ok() && !ldif::entries(&done.stdout).is_empty())
    }

    /// Create an OU, or report that it was already there.
    ///
    /// Idempotent **by construction** rather than by tolerating a failure: the
    /// script this replaces ran `ou create ... || true`, which also swallows a
    /// refusal that matters -- a parent OU that does not exist, a typo in a DN,
    /// a database opened read-only. Asking first means the only failure left is
    /// a real one.
    pub fn ou_create(&self, dn: &str) -> Result<bool> {
        if self.exists(dn)? {
            return Ok(false);
        }
        run::plain(&["samba-tool", "ou", "create", dn, "-H", &self.h()])
            .with_context(|| format!("creating {dn}"))?;
        Ok(true)
    }

    /// Every account name the directory holds.
    pub fn users(&self) -> Result<Vec<String>> {
        Ok(run::plain(&["samba-tool", "user", "list", "-H", &self.h()])?
            .lines()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect())
    }

    /// Create a service account with its password over stdin, never on argv.
    pub fn user_create(&self, name: &str, description: &str, password: &str) -> Result<String> {
        let said = run::piped(
            &[
                "samba-tool",
                "user",
                "create",
                name,
                &format!("--description={description}"),
                "-H",
                &self.h(),
            ],
            &twice(password),
        )
        .with_context(|| format!("creating {name}"))?;
        Ok(run::without_password_prompts(&said))
    }

    /// Set an existing account's password, the same way.
    pub fn set_password(&self, name: &str, password: &str) -> Result<String> {
        let said = run::piped(
            &["samba-tool", "user", "setpassword", name, "-H", &self.h()],
            &twice(password),
        )
        .with_context(|| format!("setting {name}'s password"))?;
        Ok(run::without_password_prompts(&said))
    }

    /// One account's SID, out of the directory rather than out of winbind.
    ///
    /// The accounts were created moments earlier by `samba-tool` against this
    /// same database, so the objects are there by the time this reads them --
    /// whereas `wbinfo` answers from a cache that can still hold the negative
    /// entry from before they existed. Nothing in between is asynchronous, so
    /// there is nothing to wait for either.
    pub fn sid_of(&self, dn: &str) -> Result<Option<String>> {
        let found = self.search(&["-s", "base", "-b", dn, "objectSid"])?;
        Ok(found
            .first()
            .and_then(|entry| ldif::first(entry, "objectSid"))
            .filter(|sid| sid.starts_with("S-1-5-21-"))
            .cloned())
    }

    /// An LDIF modify, read from stdin.
    ///
    /// `options` is `--option=` and nothing else. **`-o` is not a short form of
    /// it**: `ldbmodify --help` lists `-o` as an `ldb_connect` option, and using
    /// it fails with the same LDAP 53 as passing no option at all. Nothing in
    /// the tree recorded that, and it costs an afternoon.
    pub fn modify(&self, ldif: &str, options: &[&str]) -> Result<String> {
        let h = self.h();
        let mut argv = vec!["ldbmodify", "-H", h.as_str()];
        argv.extend_from_slice(options);
        run::piped(&argv, ldif)
    }

    /// One SDDL ACE applied to one object.
    ///
    /// Two measured behaviours ride on this call. It **re-applies cleanly** --
    /// the ACE is not duplicated and the exit is 0 -- which is what keeps the
    /// bootstrap idempotent now that its failure path is fatal. And it
    /// **prepends**: an allow added third sat above two denies added first and
    /// second, which is not canonical order, so it is a plain prepend whatever
    /// the ACE type. Measured on this command line only -- whether the Python
    /// `samba.dsacl` binding orders them the same way was not.
    pub fn dsacl_set(&self, dn: &str, sddl: &str) -> Result<()> {
        run::plain(&[
            "samba-tool",
            "dsacl",
            "set",
            &format!("--objectdn={dn}"),
            &format!("--sddl={sddl}"),
            "-H",
            &self.h(),
        ])?;
        Ok(())
    }

    /// The schema partition's DN, from the rootDSE.
    pub fn schema_dn(&self) -> Result<String> {
        let found = self.search(&["-s", "base", "-b", "", "schemaNamingContext"])?;
        found
            .first()
            .and_then(|entry| ldif::first(entry, "schemaNamingContext"))
            .cloned()
            .context("the rootDSE names no schemaNamingContext")
    }
}

/// The one parameter `testparm` cannot answer for.
pub const LOG_LEVEL: &str = "log level";

/// One `settings` value as Samba itself resolves it.
///
/// Normalized through `testparm` rather than read out of `smb.conf`, because the
/// question is what the *running* configuration says: a value can arrive from an
/// include, from a default, or in different case and spacing than it was written
/// in. `smb.conf` is not the answer; it is one of the inputs.
pub fn parameter(name: &str) -> Result<String> {
    if name == LOG_LEVEL {
        return log_level();
    }
    let done = run::attempt(&["testparm", "-s", &format!("--parameter-name={name}")], None)?;
    if !done.ok() {
        bail!("testparm could not read `{name}`: {}", done.reason());
    }
    // testparm puts its progress on stderr and the value alone on stdout. The
    // whitespace goes because `netbios name` comes back padded.
    Ok(done.stdout.trim().to_owned())
}

/// `log level`, out of the file, because `testparm` **drops the debug classes**.
///
/// Measured on Samba 4.23.6 against a realm provisioned by this very command,
/// with `log level = 1 auth_audit:3` sitting in `smb.conf`:
///
/// ```text
/// $ testparm -s --parameter-name="log level"
/// 1
/// $ testparm -s | grep -i 'log level'          # nothing at all
/// ```
///
/// The base level comes back and the class list does not, in every spelling of
/// the invocation tried -- and `testparm -s` omits the key entirely, having
/// decided the effective value equals the default. So a check for `auth_audit:3`
/// run through `testparm` would warn on every correctly provisioned realm, on
/// every start of the issuer daemon, forever. That is worse than no check.
///
/// This is the one place `smb.conf` is read directly, and the file is the one
/// Samba itself was built to read -- `smbd -b` reports the compiled-in path, so
/// this does not assume `/etc/samba/smb.conf` on a distribution that moved it.
fn log_level() -> Result<String> {
    let path = config_file()?;
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {} for the log level", path.display()))?;
    Ok(log_level_in(&text))
}

/// The path Samba was built to read, from `smbd -b`'s build report.
fn config_file() -> Result<PathBuf> {
    let done = run::attempt(&["smbd", "-b"], None)?;
    if !done.ok() {
        bail!("smbd -b could not report its paths: {}", done.reason());
    }
    done.stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("CONFIGFILE:"))
        .map(|path| PathBuf::from(path.trim()))
        .context("smbd -b reported no CONFIGFILE")
}

/// The last `log level` a configuration states, which is the one Samba's own
/// parser keeps. Absent is `0`, Samba's default -- and a level with no
/// `auth_audit` class, which is what the caller is asking about.
fn log_level_in(smb_conf: &str) -> String {
    smb_conf
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#') && !line.starts_with(';'))
        .filter_map(|line| line.split_once('='))
        .filter(|(key, _)| key.trim().eq_ignore_ascii_case(LOG_LEVEL))
        .map(|(_, value)| value.trim().to_owned())
        .next_back()
        .unwrap_or_else(|| "0".to_owned())
}

/// A password answered to `getpass`'s two prompts. `samba-tool` asks twice
/// whenever the positional password is absent, and with no tty it reads both
/// from stdin -- measured on the pinned baseline (Samba 4.22.10).
fn twice(password: &str) -> String {
    format!("{password}\n{password}\n")
}

/// The account name out of the DN the config set states.
///
/// Taken from the DN the component actually binds with, never from anywhere
/// else: an account created under a name nothing looks for is a bind that fails
/// at start, with the cause in a file nobody is reading.
pub fn cn_of(dn: &str) -> &str {
    let after = dn.strip_prefix("CN=").unwrap_or(dn);
    after.split_once(',').map_or(after, |(cn, _)| cn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cn_is_the_first_rdn() {
        assert_eq!(
            cn_of("CN=svc-kerbridge-broker,CN=Users,DC=example,DC=site"),
            "svc-kerbridge-broker"
        );
        assert_eq!(cn_of("CN=only"), "only");
        assert_eq!(cn_of("svc-plain,CN=Users,DC=example,DC=site"), "svc-plain");
    }

    /// The line the whole exception exists for, and the two ways a file can
    /// fail to hold it. The annotation `kbsetup realm` prepends to `smb.conf`
    /// mentions `log level` in prose, so a reader that did not skip comments
    /// would find the wrong one.
    #[test]
    fn the_log_level_comes_out_of_the_file_with_its_classes_intact() {
        let smb_conf = "# log level     the auth_audit:3 class is the KDC\'s record\n                        [global]\n\tlog level = 1 auth_audit:3\n\trealm = KERB.TEST\n";
        assert_eq!(log_level_in(smb_conf), "1 auth_audit:3");
        assert_eq!(log_level_in("[global]\n\trealm = KERB.TEST\n"), "0");
        assert_eq!(log_level_in("\tLog Level = 3\n"), "3", "the key is case-insensitive");
    }

    /// Samba keeps the last statement of a key, and so does this.
    #[test]
    fn the_last_log_level_wins() {
        assert_eq!(log_level_in("log level = 0\nlog level = 1 auth_audit:3\n"), "1 auth_audit:3");
    }

    /// The stamp sits beside the database, so a moved private directory takes
    /// it along rather than leaving it behind as a claim about another realm.
    #[test]
    fn the_stamp_lives_beside_the_database() {
        let dc = Dc::at(Path::new("/srv/dc/private/sam.ldb"));
        assert_eq!(dc.stamp(), Path::new("/srv/dc/private/kerbridge-provisioned"));
    }

    /// The three states, and the one that matters: a database with no stamp is
    /// what `samba-tool domain provision` leaves when it exits partway, and it
    /// must not read as a realm.
    #[test]
    fn a_database_without_a_stamp_is_unfinished() {
        let dir = std::env::temp_dir().join(format!("kbsetup-dc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dc = Dc::at(&dir.join("sam.ldb"));
        assert!(matches!(dc.state(), State::Absent));

        std::fs::write(dir.join("sam.ldb"), "half a domain").unwrap();
        assert!(matches!(dc.state(), State::Unfinished));

        // Both readings, in this order: the wrong one destroys a working DC.
        let said = dc.unfinished();
        assert!(said.contains("kerbridge-provisioned"));
        assert!(said.find("destroy") < said.find("touch"), "{said}");

        dc.stamp_provisioned("KERB.TEST").unwrap();
        assert!(matches!(dc.state(), State::Provisioned));
        assert!(std::fs::read_to_string(dc.stamp()).unwrap().contains("KERB.TEST"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_password_answers_both_prompts() {
        assert_eq!(twice("Kb1-abc"), "Kb1-abc\nKb1-abc\n");
    }
}
