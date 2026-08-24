//! Writing a credential into the secrets tree, and telling the truth about
//! whether the write landed the way it was meant to.
//!
//! Both kinds pass through here. `realm` and `directory` write what they
//! generated; `kbsetup secrets` -- [`run`], at the end of this file -- writes
//! what only an operator can fetch, and [`crate::pasted`] is what says which
//! those are.
//!
//! Measured facts shape every function here.
//!
//! **Empty means absent.** Generate-iff-absent tests `-s`, never `-e`. A
//! single-file bind mount cannot be created by the container that writes it: with
//! the host path missing, the daemon creates a **directory** there and mounts it
//! as one, and the write then fails with `Is a directory` -- on Docker Desktop
//! *and* on a native daemon, so this is dockerd's behaviour rather than a Desktop
//! quirk. Worse, that stray directory is created root-owned on the host, so a
//! first run that misses the file leaves something an unprivileged operator
//! cannot clean up. A pre-existing zero-byte regular file is what works, with
//! emptiness as the container-visible "not generated yet" signal.
//! `deploy/scripts/check-secrets.sh` and the placeholders `prepare-state`
//! leaves spell it `-s` for this reason.
//!
//! **The write is in place.** Never write-and-rename: the target may be a bind
//! mount of a single file, where a rename over it is a different inode and the
//! host never sees the value.
//!
//! **Mode is not a witness that ownership was set.** On a FUSE-backed bind source
//! `chgrp` exits 0 and does nothing while `chmod` sticks, and the remap applies
//! on read as well, so an in-container `stat` cannot detect it either. A check
//! that infers "ownership was set" from "the mode is right" is wrong on exactly
//! the hosts where it matters. So this re-reads the owner it just set and says
//! what it found -- and says it as a warning rather than a refusal, because the
//! condition is unfixable from where this runs and a fatal check would break
//! every deployment on such a host at the moment it is least recoverable.
//!
//! **Group read is the access control.** An unprivileged daemon reaches its own
//! secret through the group and nothing else, which is why `0640 root:<group>`
//! is the shape and why `kerbridge_core::secret` accepts group read and refuses
//! everything wider.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result, bail};
use kerbridge_core::config::Issuerd;

use crate::units;

/// The unix group through which an unprivileged daemon reads its own credential,
/// and which owns the directories those credentials sit in.
///
/// A stated name wins over the number beside it and never falls back to it --
/// the policy `issuerd` states at `crates/kerbridge-issuerd/src/identity.rs`, which is the
/// process that has to agree with what is written here. It is restated rather
/// than shared because `issuerd` is a binary crate with no library to link, and
/// because the two need different halves of it: `issuerd` resolves both
/// identities and refuses to start, this resolves the group alone.
pub fn daemon_group(issuerd: &Issuerd) -> Result<u32> {
    let Some(name) = &issuerd.socket_group else {
        return Ok(issuerd.socket_gid);
    };
    let group = nix::unistd::Group::from_name(name)
        .with_context(|| format!("looking up the unix group {name:?}"))?;
    match group {
        Some(group) => Ok(group.gid.as_raw()),
        None => bail!(
            "issuerd.toml says socket_group = {name:?} and this host has no unix group of that \
             name. The credentials written here are read through that group, so a wrong one is a \
             daemon that cannot start. Create the group, or state socket_gid instead."
        ),
    }
}

/// Why an unprivileged daemon in `gid` cannot read this file, or `None` when it
/// can.
///
/// **The one fault every root-run tool is blind to.** The permission bits do not
/// stop uid 0, so `kbsetup`, `kbmanage doctor` and a hand `cat` all read a
/// credential the daemons are refused, and each reports the deployment healthy.
/// The daemon meets it at startup, exits, and latches -- with the diagnosis in
/// the journal, where the operator who wrote the file by hand is not looking.
///
/// A stat, not a privilege drop: the numbers the kernel would compare are all in
/// the inode. The rule and the fix line are [`kerbridge_core::secret::read`]'s,
/// restated over somebody else's identity -- the operator meets the two in
/// either order, so they may not come to word it differently.
///
/// A file that is not there is not this function's answer: absent is
/// [`Pasted::present`](crate::pasted::Pasted::present)'s question.
pub fn unreadable_by(path: &Path, gid: u32) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    let mode = meta.mode() & 0o7777;
    let fix = format!("chgrp {gid} {0} && chmod 0640 {0}", path.display());
    if mode & 0o027 != 0 {
        let bad = if mode & 0o007 != 0 { "readable by other" } else { "writable by group" };
        return Some(format!("mode {mode:04o}, {bad} -- fix: {fix}"));
    }
    if meta.gid() == gid && mode & 0o040 != 0 {
        return None;
    }
    Some(format!(
        "group {}, mode {mode:04o}: the daemons read it as group {gid} and are refused -- fix: {fix}",
        meta.gid()
    ))
}

/// Who has to be able to read the file, which decides both numbers.
#[derive(Debug, Clone, Copy)]
pub enum Reader {
    /// `0600 root:root`. A stated exception to the `0640` the rest of
    /// `/etc/kerbridge.secrets/` takes, and stated as an exception rather than
    /// left as a contradiction between two decisions: the realm Administrator's
    /// password has no unprivileged consumer at all -- provisioning sets it, a
    /// member server joins with it, and a human reads it for break-glass -- and
    /// the stricter of two modes is the one that wins.
    RootOnly,
    /// `0640 root:<gid>`, for a credential a daemon running as an unprivileged
    /// uid in that group must read.
    Group(u32),
}

impl Reader {
    fn mode(self) -> u32 {
        match self {
            Reader::RootOnly => 0o600,
            Reader::Group(_) => 0o640,
        }
    }

    fn gid(self) -> Option<u32> {
        match self {
            Reader::RootOnly => None,
            Reader::Group(gid) => Some(gid),
        }
    }
}

/// The value already there, or `None` for a file that is absent or empty.
pub fn existing(path: &Path) -> Result<Option<String>> {
    let Ok(meta) = std::fs::metadata(path) else { return Ok(None) };
    if meta.is_dir() {
        bail!(
            "{} is a directory, not a file. Docker creates one at a bind mount's target when \
             the host path is missing, and it is created root-owned -- so removing it needs \
             root, and the deployment that was meant to hold a credential there holds nothing. \
             Remove the directory, put an empty file at the host path, and run this again.",
            path.display()
        );
    }
    if meta.len() == 0 {
        return Ok(None);
    }
    kerbridge_core::secret::read(path).map(Some)
}

/// Write a generated credential, and report anything about the result an
/// operator has to know.
///
/// The returned lines are warnings, not failures. Each one names a state the
/// deployment can still start in and a consequence it will meet later.
pub fn write(path: &Path, value: &str, group: u32, reader: Reader) -> Result<Vec<String>> {
    if let Some(parent) = path.parent() {
        ensure_directory(parent, group)?;
    }

    // Created 0600 and widened afterwards, never the other way round: between
    // `create` and `set_permissions` the file already holds the credential, and
    // a umask that left it 0644 for those microseconds is a race nobody would
    // ever see fail.
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("writing {}", path.display()))?;
    // The bare value with no trailing newline -- the convention every reader in
    // this repository expects (`deploy/README.md` @ Secrets).
    file.write_all(value.as_bytes()).with_context(|| format!("writing {}", path.display()))?;
    file.sync_all().with_context(|| format!("writing {}", path.display()))?;
    drop(file);

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(reader.mode()))
        .with_context(|| format!("setting the mode of {}", path.display()))?;
    if let Some(gid) = reader.gid() {
        std::os::unix::fs::chown(path, None, Some(gid))
            .with_context(|| format!("setting the group of {}", path.display()))?;
    }
    Ok(witness(path, reader))
}

/// Create the directories a secret lives under, as `0750 root:<group>`.
///
/// **Every level, not just the last one.** `create_dir_all` gives an
/// intermediate directory the process umask, and the intermediate here is
/// `/etc/kerbridge.secrets/generated/idp/` -- which at `0755` lets any account on
/// the host enumerate the source names, and at `0700` would stop the daemon from
/// traversing to its own credential. Measured on a real run before this was
/// fixed: the leaf came out `0750 root:_kerbridge` and the directory holding it
/// `0755 root:root`.
///
/// The group is the deployment's daemon group even when the file itself is
/// root-only, because the directory is shared: the realm Administrator's
/// password is written first, and if it created these directories root-only the
/// broker could never traverse them to reach the credential written next.
///
/// Normally a no-op. `/etc/kerbridge.secrets` is package-owned and its
/// maintainer script creates it; this is what a deployment gets when the
/// bootstrap ran before the package did, or when the config set points the
/// secrets somewhere the package never heard of.
pub fn ensure_directory(dir: &Path, group: u32) -> Result<()> {
    let missing: Vec<&Path> =
        dir.ancestors().take_while(|level| !level.exists()).collect::<Vec<_>>();
    for level in missing.into_iter().rev() {
        std::fs::create_dir(level).with_context(|| format!("creating {}", level.display()))?;
        std::fs::set_permissions(level, std::fs::Permissions::from_mode(0o750))
            .with_context(|| format!("setting the mode of {}", level.display()))?;
        // Best effort, and warned about at the file below rather than here: on a
        // FUSE-backed bind source this reports success and does nothing.
        let _ = std::os::unix::fs::chown(level, None, Some(group));
    }
    Ok(())
}

/// Did the ownership actually take? See the module comment: neither the exit
/// status nor the mode answers this.
fn witness(path: &Path, reader: Reader) -> Vec<String> {
    let Ok(meta) = std::fs::metadata(path) else { return Vec::new() };
    let shown = path.display();
    match reader {
        Reader::Group(want) if meta.gid() != want => vec![format!(
            "{shown} is group {} and had to become group {want}. The chgrp reported success and \
             did nothing, which is what a FUSE-backed bind source does -- the mode stuck and the \
             ownership did not. The daemon that reads this file will fail at start with \
             \"Permission denied (os error 13)\". Set the group from the host side, or put the \
             secrets directory on a filesystem that is not FUSE-backed.",
            meta.gid()
        )],
        Reader::RootOnly if meta.uid() != 0 => vec![format!(
            "{shown} is owned by uid {}, not by root. A deployment's secrets must be root-owned: \
             the realm container is root with no DAC_OVERRIDE, so it can read only what it owns.",
            meta.uid()
        )],
        _ => Vec::new(),
    }
}

/// `kbsetup secrets` -- ask for every credential the config set names, KerBridge
/// cannot generate, and the deployment does not have yet.
///
/// The whole point is the path the value takes: terminal -> this process ->
/// the file, at the mode its reader needs. Never through debconf, which copies
/// what passes through it to a world-readable file -- [`crate::ask`] carries
/// that reasoning.
pub fn run(dir: &Path, replace: bool) -> Result<()> {
    let config = crate::load(dir)?;
    let wanted = crate::pasted::wanted(&config);
    if wanted.is_empty() {
        println!(
            "[kbsetup] this config set names no credential for you to supply. Every secret it \
             uses is one `kbsetup realm` or `kbsetup directory` generates."
        );
        return Ok(());
    }

    let mut todo = Vec::new();
    for want in wanted {
        if want.present()? && !replace {
            println!("[kbsetup] {} is already set -- left alone", want.named());
            continue;
        }
        todo.push(want);
    }
    if todo.is_empty() {
        println!(
            "[kbsetup] every credential this config set names is in place. `kbsetup secrets \
             --replace` asks about them again; `kbsetup status` says what is still outstanding."
        );
        return Ok(());
    }

    let group = daemon_group(&config.issuerd)?;
    // No terminal first, and whatever the uid is: a configuration-management run
    // reaches this, and what it needs is the file, the mode and the owner rather
    // than advice about sudo.
    if !crate::ask::interactive() {
        // The group by the name the config set states, falling back to the
        // number: it is pasted into an `install -g` line, and `_kerbridge`
        // survives a host whose gid allocation differs where a number does not.
        let named = config.issuerd.socket_group.clone().unwrap_or_else(|| group.to_string());
        bail!("{}", by_hand(&todo, &named));
    }
    for want in &todo {
        reserve(&want.path, group).with_context(|| {
            format!(
                "reserving {}. These are root-owned files under the deployment's secrets \
                 directory -- run this with sudo",
                want.path.display()
            )
        })?;
    }

    let mut written = 0;
    let mut skipped = Vec::new();
    for want in &todo {
        match one(want, group, replace)? {
            true => written += 1,
            false => skipped.push(want.named()),
        }
    }

    println!();
    println!("[kbsetup] {written} written, {} left unset", skipped.len());
    for name in &skipped {
        println!("[kbsetup]   {name}");
    }
    if written > 0 {
        units::resume_failed();
    }
    println!("[kbsetup] `kbsetup status` says what is outstanding now.");
    Ok(())
}

/// Create the file empty, at its final mode and owner, before anything is
/// typed.
///
/// Not simply a permission test. It fails *here* rather than after the
/// credential has been pasted -- the one late failure in this program that
/// costs the operator something the portal will not show them twice. What it
/// leaves behind is the placeholder the whole secrets tree is written around:
/// empty is absent, so a reserved file is the state the deployment was already
/// in, and `ls -l` names the path and the mode instead of a config file.
///
/// Never over an existing file. `--replace` reaches here with a credential
/// already in place, and truncating it before asking whether to replace it
/// would destroy a working deployment's secret at the prompt.
fn reserve(path: &Path, group: u32) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    write(path, "", group, Reader::Group(group)).map(|_| ())
}

/// One credential: show what it is, ask, check, write. `Ok(false)` is a
/// deliberate skip, which is a legal outcome for every one of them -- an
/// operator who does not have the value to hand must be able to leave the
/// prompt without losing the ones already answered.
fn one(want: &crate::pasted::Pasted, group: u32, replace: bool) -> Result<bool> {
    println!();
    println!("--- {} ---", want.named());
    println!("{}", want.what);
    if let Some(caution) = &want.caution {
        println!();
        println!("{caution}");
    }
    println!();
    println!("  file:  {}", want.path.display());
    println!("  mode:  0640 root:<the daemon group>, set by this command");

    if replace && want.present()? {
        println!();
        if !crate::ask::confirm("A credential is already there. Replace it?", false)? {
            return Ok(false);
        }
    }

    println!();
    loop {
        let value = crate::ask::secret("  Value (not echoed): ")?;
        let value = value.trim();
        if value.is_empty() {
            let question = if want.optional {
                "Nothing typed. Leave this one unset?"
            } else {
                "Nothing typed. Leave it unset for now, and finish the rest?"
            };
            if crate::ask::confirm(&format!("  {question}"), true)? {
                return Ok(false);
            }
            continue;
        }
        if let Some(why) = crate::pasted::refuse(value, &want.path) {
            println!("  Refused: {why}");
            println!();
            continue;
        }
        for warning in write(&want.path, value, group, Reader::Group(group))? {
            eprintln!("[kbsetup] warning: {warning}");
        }
        // The length and nothing else. It is what tells a mis-paste -- a
        // truncated value, a stray quote -- from a good one, and it discloses
        // nothing about the credential itself.
        println!("  Written: {} bytes into {}", value.len(), want.path.display());
        return Ok(true);
    }
}

/// What to do instead, for a caller with no terminal to answer at.
///
/// A configuration-management run reaches this, and the useful answer is the
/// exact file, mode and owner rather than a refusal. `0600` is named as a
/// mistake on purpose: it is the one an operator makes by instinct, and it
/// leaves a daemon that cannot read its own credential.
fn by_hand(todo: &[crate::pasted::Pasted], group: &str) -> String {
    let mut out = String::from(
        "there is no terminal to ask at, and a credential must never be taken from an argument \
         or an environment variable -- both are readable by every account on the host. Write \
         each file yourself instead, with the bare value and no trailing newline:\n",
    );
    for want in todo {
        out.push_str(&format!("\n  {}\n    {}\n", want.named(), want.path.display()));
    }
    out.push_str(&format!(
        "\n  install -o root -g {group} -m 0640 /dev/null <file>, then write the value into it.\n  \
         Not 0600: the daemon runs unprivileged and reads through the group.",
    ));
    out
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("kbsetup-secrets-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The `-s` rule, both ways round. A zero-byte file is the signal that a
    /// bind mount is in place and nothing has generated into it yet.
    #[test]
    fn an_empty_file_reads_as_absent_and_a_written_one_does_not() {
        let dir = scratch("empty");
        let path = dir.join("realm_admin_password");
        assert!(existing(&path).unwrap().is_none(), "a missing file is absent");

        File::create(&path).unwrap();
        assert!(existing(&path).unwrap().is_none(), "an empty file is absent");

        write(&path, "Kb1abc", 0, Reader::RootOnly).unwrap();
        assert_eq!(existing(&path).unwrap().as_deref(), Some("Kb1abc"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The failure a root-run check cannot feel: a credential every privileged
    /// reader opens and no daemon can. The group asked about is this process's
    /// own, which is the one gid a test can be sure a file may carry.
    #[test]
    fn a_file_the_daemon_group_cannot_read_is_named_with_its_fix() {
        let dir = scratch("readable");
        let mine = nix::unistd::getgid().as_raw();
        let path = dir.join("notify_url");
        write(&path, "https://hooks.example.site/x", mine, Reader::Group(mine)).unwrap();
        assert_eq!(unreadable_by(&path, mine), None, "0640 in the reader's own group");

        // The same file, offered to a group this process is not in: the case
        // that arrives as `chown root:root` on a hand-written secret.
        let other = mine + 1;
        let said = unreadable_by(&path, other).expect("a foreign group is refused");
        assert!(said.contains(&format!("the daemons read it as group {other}")), "{said}");
        assert!(said.contains(&format!("chgrp {other}")), "the fix names the gid: {said}");

        std::fs::set_permissions(&path, PermissionsExt::from_mode(0o644)).unwrap();
        let said = unreadable_by(&path, mine).expect("world-readable is refused");
        assert!(said.contains("readable by other"), "{said}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The hazard that would otherwise be reported as `Is a directory` from
    /// three layers down, with nothing saying who created it or how to remove it.
    #[test]
    fn a_directory_at_the_secret_path_is_named_for_what_it_is() {
        let dir = scratch("isdir");
        let path = dir.join("bind_password");
        std::fs::create_dir(&path).unwrap();
        let err = existing(&path).unwrap_err().to_string();
        assert!(err.contains("is a directory"), "{err}");
        assert!(err.contains("root-owned"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The value lands byte-exact, and the mode is the one the reader needs.
    /// `kerbridge_core::secret::read` refuses anything wider, so a wrong mode
    /// here is a daemon that will not start.
    #[test]
    fn the_written_file_is_the_bare_value_at_the_stated_mode() {
        let dir = scratch("mode");
        let path = dir.join("svc_password");
        write(&path, "Kb1-value", 0, Reader::RootOnly).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "Kb1-value");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{mode:o}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A rewrite must not leave the tail of a longer previous value behind.
    #[test]
    fn a_rewrite_truncates() {
        let dir = scratch("truncate");
        let path = dir.join("svc_password");
        write(&path, "Kb1-a-very-long-previous-value", 0, Reader::RootOnly).unwrap();
        write(&path, "Kb1-short", 0, Reader::RootOnly).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "Kb1-short");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
