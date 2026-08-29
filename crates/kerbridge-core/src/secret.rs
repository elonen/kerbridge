//! Reading a credential off disk, the same way in every component.
//!
//! `deploy/scripts/check-secrets.sh` already enforces this rule on the host, and
//! refuses to start the stack when it is broken -- but it only sees the files
//! compose mounts. `kbmanage` runs on an operator's own host against a password
//! file they placed by hand, and nothing checked that one at all. So the rule
//! lives here, at the read, where every caller gets it whether or not a script
//! ran first.
//!
//! And where the *diagnosis* lives too. A denied read is the one failure whose
//! cause is two numbers the reader already holds -- the file's group and its own
//! groups -- so every message here names both sides of the comparison the kernel
//! made and the `chgrp`/`chmod` that fixes it. The process that was refused
//! reports the identity it has; nothing here resolves a name like `_kerbridge`
//! to a number, which is what keeps the lookup the config structs decline
//! (`config/mod.rs`) out of this crate as well.

use anyhow::{Context, Result, bail};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Read a secret file, refusing one whose permissions hand it to somebody else.
///
/// The rule is check-secrets.sh's rule 1, restated so the two cannot drift: not
/// readable by other, not writable by group. Group *read* is deliberately
/// allowed -- it is how an unprivileged container reaches its own secret, and how
/// an operator shares a key with the system group that already owns it.
///
/// Fatal rather than a warning. A warning at startup is a line in a log nobody
/// reads, and the file then stays wrong for the life of the deployment.
///
/// Measured on the bench (2026-07-28): Docker Desktop presents a bind-mounted
/// compose secret as `0600` owned by the container's own uid whatever the host
/// file says, so this does not fire on the macOS bench. On Linux the host's
/// `0640 root:BROKER_GID` reaches the container unchanged and passes, for the
/// same reason check-secrets.sh accepts it there.
///
/// `metadata` follows symlinks, which is the point: a hand-placed secret is
/// often a symlink into a path the host already manages, and a symlink is always
/// `lrwxrwxrwx`. The target's mode is what the reader actually gets.
pub fn read(path: &Path) -> Result<String> {
    let shown = path.display();
    let reader = Reader::current();
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        // A refused `stat` is never the file's own mode -- see [`path_denial`].
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            bail!(path_denial(path, &reader))
        }
        Err(e) => return Err(e).with_context(|| format!("reading secret {shown}")),
    };
    let file = Owned::of(&meta);
    judge(file, path, &reader)?;
    match std::fs::read_to_string(path) {
        Ok(raw) => clean(&raw, path),
        // The errno is dropped rather than chained: "Permission denied (os error
        // 13)" is what this message exists to replace, and it says nothing the
        // lines below do not say with numbers.
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            bail!(file_denial(path, file, &reader))
        }
        Err(e) => Err(e).with_context(|| format!("reading secret {shown}")),
    }
}

/// The same read, for a secret the deployment is allowed not to have yet.
///
/// A compose secret is a bind mount, so the file exists before its container
/// starts and starts empty. Empty and absent therefore both mean the operator
/// has not pasted one in, which is a state and not a fault -- the reader waits
/// and looks again. Everything else is a fault, `EACCES` above all: that one
/// arrives at the peek below rather than inside [`read`], and answering it with
/// `None` would disable a credential that is present behind a message saying
/// none was configured.
pub fn read_optional(path: &Path) -> Result<Option<String>> {
    let shown = path.display();
    match std::fs::read_to_string(path) {
        Ok(raw) if raw.trim().is_empty() => Ok(None),
        // Read again through `read`, which is where the permission rule lives.
        Ok(_) => read(path).map(Some),
        // This arm never reaches `read`, so the diagnosis is asked for by name.
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => bail!("{}", denial(path)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading secret {shown}")),
    }
}

/// The same diagnosis, for the denial [`read_optional`] meets at its own peek
/// rather than inside [`read`].
///
/// That peek exists to tell a secret that is empty from one that is absent, and
/// `EACCES` arrives there instead. It is the same failure with the same
/// audience, so it gets the same words, from the same numbers, instead of a
/// hand-written guess at which group the deployment meant.
fn denial(path: &Path) -> String {
    let reader = Reader::current();
    match std::fs::metadata(path) {
        Ok(meta) => file_denial(path, Owned::of(&meta), &reader),
        Err(_) => path_denial(path, &reader),
    }
}

/// Split out from the read so the rule is testable without writing a file with
/// each mode: the I/O is `metadata`, and that is not what could be wrong here.
///
/// `reader` is passed in rather than read here for the same reason -- the rule
/// does not consult it, only the message does, and a message built from whoever
/// happens to run `cargo test` is a message no test can assert on.
fn judge(file: Owned, path: &Path, reader: &Reader) -> Result<()> {
    let shown = path.display();
    let bad = file.mode & 0o027;
    if bad != 0 {
        bail!(
            "secret file {shown} is mode {:04o}: {}.\n{}  Fix:    {}",
            file.mode & 0o7777,
            if bad & 0o007 != 0 { "readable by other" } else { "writable by group" },
            facts("File:", file, reader),
            fix(path, file, reader)
        );
    }
    Ok(())
}

/// Why the kernel refused the open, in terms of the bits it actually compared.
///
/// The mode has already passed [`judge`] by the time this is reached from
/// [`read`], so the usual answer is not the mode at all: it is a `0640` file
/// owned by the group that wrote it rather than the group that reads it -- the
/// case check-secrets.sh called rule 2, and the one no mode check can see.
fn file_denial(path: &Path, file: Owned, reader: &Reader) -> String {
    let shown = path.display();
    // Root bypasses the mode entirely, so a refusal here was never about it;
    // neither was one against a mode that grants us the read. Both mean the
    // obstacle is outside this file, and a `chmod` would be a wrong answer
    // confidently given.
    let (why, cmd) = if reader.uid == 0 {
        ("this process is root, which the permission bits do not stop", None)
    } else if file.grants(READ, reader) {
        ("its own mode and group grant this process the read", None)
    } else if reader.uid == file.uid {
        ("this process owns it, and the owner bits carry no read", Some(fix(path, file, reader)))
    } else if reader.in_group(file.gid) {
        (
            "this process is in its group, and the group bits carry no read",
            Some(fix(path, file, reader)),
        )
    } else {
        ("this process is not its owner and not in its group", Some(fix(path, file, reader)))
    };
    let advice = cmd.unwrap_or_else(|| {
        format!(
            "not this file -- check the directories leading to {shown}, and any SELinux or \
             AppArmor policy"
        )
    });
    format!(
        "cannot read secret file {shown}: {why}.\n{}  Fix:    {advice}",
        facts("File:", file, reader)
    )
}

/// A refused `stat` is a directory on the way in, not the file: reaching a path
/// costs search on every directory above it, and the file's own mode is not
/// consulted until they are all passed.
///
/// The *shallowest* unsearchable one is named, since it is the one to fix and
/// everything below it is invisible from here anyway -- a directory this process
/// cannot search is one whose contents it cannot even stat.
fn path_denial(path: &Path, reader: &Reader) -> String {
    let shown = path.display();
    let blocker = path
        .ancestors()
        .skip(1)
        .filter_map(|dir| {
            let file = Owned::of(&std::fs::metadata(dir).ok()?);
            (!file.grants(SEARCH, reader)).then_some((dir, file))
        })
        .last();
    let head = format!(
        "cannot reach secret file {shown}: a directory on the path is not searchable by this process"
    );
    match blocker {
        Some((dir, file)) => format!(
            "{head} -- {}.\n{}  Fix:    {}",
            dir.display(),
            facts("Dir:", file, reader),
            if reader.in_group(file.gid) {
                format!("chmod 0750 {}", dir.display())
            } else {
                format!("chgrp {} {} && chmod 0750 {}", reader.gid, dir.display(), dir.display())
            }
        ),
        // Every directory we can see grants us search, so the one that does not
        // is above the first we cannot stat. Say what we know rather than
        // inventing a path to blame.
        None => format!("{head}.\n  Reader: uid {}, groups {}", reader.uid, reader.groups_shown()),
    }
}

/// The commands that leave the file both closed to others and readable by this
/// process. `chmod 0640` on its own, against a file whose group this process is
/// not in, only trades one denial for another -- and the operator learns that at
/// the next restart. So the `chgrp` that makes the mode mean something is named
/// with it, and first.
///
/// The group named is the reader's own primary one, which is the only group it
/// is certain to be in. It is also what both deployments already use: the broker
/// and sync run `user: "<uid>:${BROKER_GID}"`, so this prints the `chgrp $GID`
/// check-secrets.sh printed, without needing to know the variable's name.
fn fix(path: &Path, file: Owned, reader: &Reader) -> String {
    let shown = path.display();
    if reader.uid == file.uid {
        format!("chmod 0640 {shown} (or 0600 if nothing else needs to read it)")
    } else if reader.in_group(file.gid) {
        format!("chmod 0640 {shown}")
    } else {
        format!("chgrp {} {shown} && chmod 0640 {shown}", reader.gid)
    }
}

/// The two sides of the comparison the kernel made, stated in the same order and
/// the same shape by every message here. `what` is the noun the first line
/// describes -- the secret in most of them, a directory above it in one -- and
/// is padded to keep the two labels and the `Fix:` below them in one column.
fn facts(what: &str, file: Owned, reader: &Reader) -> String {
    format!(
        "  {what:<7} mode {:04o}, owner uid {}, group {}\n  Reader: uid {}, groups {}\n",
        file.mode & 0o7777,
        file.uid,
        file.gid,
        reader.uid,
        reader.groups_shown()
    )
}

const READ: u32 = 0o4;
const SEARCH: u32 = 0o1;

/// The file's side of the decision: the three facts a denial turns on.
#[derive(Clone, Copy)]
struct Owned {
    mode: u32,
    uid: u32,
    gid: u32,
}

impl Owned {
    fn of(meta: &std::fs::Metadata) -> Self {
        Self { mode: meta.mode(), uid: meta.uid(), gid: meta.gid() }
    }

    /// Whether the permission triple the kernel would pick for `reader` carries
    /// `bit`. One triple, not the union of the three: the kernel stops at the
    /// first that applies, which is why a `0604` file owned by you is *less*
    /// readable to you than to a stranger.
    fn grants(self, bit: u32, reader: &Reader) -> bool {
        let triple = if reader.uid == self.uid {
            self.mode >> 6
        } else if reader.in_group(self.gid) {
            self.mode >> 3
        } else {
            self.mode
        };
        triple & bit != 0
    }
}

/// The reading process's side of it.
///
/// *Effective*, not real: the effective ids are what the kernel weighs against a
/// file's (Linux's fsuid follows euid), so a process that dropped privileges
/// reports the identity it actually reads as.
struct Reader {
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
}

impl Reader {
    fn current() -> Self {
        let (uid, gid) = (rustix::process::geteuid(), rustix::process::getegid());
        Self { uid: uid.as_raw(), gid: gid.as_raw(), groups: supplementary() }
    }

    fn in_group(&self, gid: u32) -> bool {
        self.gid == gid || self.groups.contains(&gid)
    }

    /// Primary first, then the rest -- the order `id` prints them in, and the
    /// order that makes the `chgrp` above read as one of the numbers on the line
    /// before it.
    fn groups_shown(&self) -> String {
        std::iter::once(self.gid)
            .chain(self.groups.iter().copied().filter(|g| *g != self.gid))
            .map(|g| g.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// This process's supplementary groups, which std does not expose.
///
/// A failure returns none rather than propagating: this runs only to explain a
/// denial that has already happened, and an error here must not replace that
/// explanation with one about itself. A short group list makes the diagnosis say
/// less; it never makes it say something untrue, because the `chgrp` is aimed at
/// the primary group either way.
fn supplementary() -> Vec<u32> {
    rustix::process::getgroups()
        .map(|gs| gs.iter().map(|g| g.as_raw()).collect())
        .unwrap_or_default()
}

/// Trailing newlines are what a file-based secret always has and never means.
fn clean(raw: &str, path: &Path) -> Result<String> {
    let value = raw.trim_end_matches(['\n', '\r']).to_owned();
    if value.is_empty() {
        bail!("secret file {} is empty", path.display());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_TEMP_DIR: AtomicUsize = AtomicUsize::new(0);

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new() -> Self {
            let serial = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("kerbridge-secret-test-{}-{serial}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn write(&self, name: &str, value: &[u8]) -> std::path::PathBuf {
            let path = self.0.join(name);
            std::fs::write(&path, value).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    /// The deployment's own numbers: sync at `10003:10002`, its credential
    /// written `0640 root:root` by a root that never chgrp'd it. Fixed rather
    /// than read from the host, so the assertions below mean the same thing
    /// under `cargo test`, in CI, and in a root container.
    fn sync() -> Reader {
        Reader { uid: 10003, gid: 10002, groups: vec![10002] }
    }

    fn file(mode: u32, uid: u32, gid: u32) -> Owned {
        Owned { mode, uid, gid }
    }

    #[test]
    fn strips_the_trailing_newline_a_secret_file_always_has() {
        assert_eq!(clean("s3cret\n", Path::new("p")).unwrap(), "s3cret");
        assert_eq!(clean("s3cret\r\n", Path::new("p")).unwrap(), "s3cret");
        assert_eq!(clean("s3cret", Path::new("p")).unwrap(), "s3cret");
        assert!(clean("\n", Path::new("p")).is_err());
        assert!(clean("", Path::new("p")).is_err());
    }

    #[test]
    fn optional_secret_treats_only_absence_as_unconfigured() {
        let dir = TempDir::new();
        assert_eq!(read_optional(&dir.path().join("absent")).unwrap(), None);
    }

    #[test]
    fn optional_secret_treats_empty_and_whitespace_only_as_unconfigured() {
        let dir = TempDir::new();
        for (name, value) in [("empty", b"".as_slice()), ("whitespace", b" \t\r\n".as_slice())] {
            assert_eq!(read_optional(&dir.write(name, value)).unwrap(), None);
        }
    }

    #[test]
    fn optional_secret_cleans_line_endings_without_trimming_the_secret() {
        let dir = TempDir::new();
        let path = dir.write("credential", b"  secret value  \r\n");
        assert_eq!(read_optional(&path).unwrap().as_deref(), Some("  secret value  "));
    }

    #[test]
    fn optional_secret_reports_a_directory_instead_of_calling_it_absent() {
        let dir = TempDir::new();
        let error = read_optional(dir.path()).unwrap_err();
        assert!(error.to_string().contains("reading secret"), "{error:#}");
        assert!(
            error.chain().any(|cause| cause.downcast_ref::<std::io::Error>().is_some()),
            "{error:#}"
        );
    }

    #[test]
    fn optional_secret_reports_invalid_utf8_instead_of_calling_it_absent() {
        let dir = TempDir::new();
        let path = dir.write("binary", &[0xff, 0xfe]);
        let error = read_optional(&path).unwrap_err();
        assert!(error.to_string().contains("reading secret"), "{error:#}");
        assert_eq!(
            error
                .chain()
                .find_map(|cause| cause.downcast_ref::<std::io::Error>())
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::InvalidData),
            "{error:#}"
        );
    }

    #[test]
    fn optional_secret_reports_other_io_errors_instead_of_calling_them_absent() {
        let path = std::path::PathBuf::from(std::ffi::OsString::from_vec(b"bad\0path".to_vec()));
        let error = read_optional(&path).unwrap_err();
        assert!(error.to_string().contains("reading secret"), "{error:#}");
        assert_eq!(
            error
                .chain()
                .find_map(|cause| cause.downcast_ref::<std::io::Error>())
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::InvalidInput),
            "{error:#}"
        );
    }

    #[test]
    fn optional_secret_keeps_the_bespoke_permission_diagnosis() {
        if rustix::process::geteuid().is_root() {
            return;
        }
        let dir = TempDir::new();
        let path = dir.write("unreadable", b"secret");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let error = read_optional(&path).unwrap_err().to_string();
        assert!(error.contains("cannot read secret file"), "{error}");
        assert!(error.contains("Fix:    chmod 0640"), "{error}");
        assert!(!error.contains("reading secret"), "{error}");
    }

    #[test]
    fn accepts_group_read_and_refuses_the_rest() {
        // What the scripts actually produce, and what Docker Desktop shows.
        assert!(judge(file(0o100640, 0, 10002), Path::new("p"), &sync()).is_ok());
        assert!(judge(file(0o100600, 0, 10002), Path::new("p"), &sync()).is_ok());
        assert!(judge(file(0o100400, 0, 10002), Path::new("p"), &sync()).is_ok());
        // The two failures, each named by the message.
        for mode in [0o100644, 0o100604, 0o100777, 0o100666] {
            let e = judge(file(mode, 0, 10002), Path::new("p"), &sync()).unwrap_err().to_string();
            assert!(e.contains("readable by other"), "{mode:o}: {e}");
        }
        for mode in [0o100660, 0o100620] {
            let e = judge(file(mode, 0, 10002), Path::new("p"), &sync()).unwrap_err().to_string();
            assert!(e.contains("writable by group"), "{mode:o}: {e}");
        }
    }

    #[test]
    fn the_message_quotes_the_permission_bits_and_not_the_file_type() {
        let e = judge(file(0o100644, 0, 10002), Path::new("/etc/kerbridge.secrets/x"), &sync())
            .unwrap_err()
            .to_string();
        assert!(e.contains("mode 0644"), "{e}");
        assert!(e.contains("/etc/kerbridge.secrets/x"), "{e}");
    }

    /// The wrong-mode case: a `0644` an editor or an scp left behind. The mode is
    /// the fault, and the group is already right, so the fix is one command.
    #[test]
    fn a_loose_mode_names_both_identities_and_the_chmod() {
        let e = judge(file(0o100644, 0, 10002), Path::new("/etc/kerbridge.secrets/x"), &sync())
            .unwrap_err()
            .to_string();
        assert!(e.contains("File:   mode 0644, owner uid 0, group 10002"), "{e}");
        assert!(e.contains("Reader: uid 10003, groups 10002"), "{e}");
        assert!(e.contains("Fix:    chmod 0640 /etc/kerbridge.secrets/x"), "{e}");
        assert!(!e.contains("chgrp"), "the group is already right: {e}");
    }

    /// Closing a file this process cannot reach anyway is half a fix, and the
    /// other half is only visible from here -- the mode check cannot see it.
    #[test]
    fn a_loose_mode_on_a_foreign_group_names_the_chgrp_too() {
        let e = judge(file(0o100644, 0, 0), Path::new("/etc/kerbridge.secrets/x"), &sync())
            .unwrap_err()
            .to_string();
        assert!(
            e.contains(
                "Fix:    chgrp 10002 /etc/kerbridge.secrets/x && chmod 0640 \
                 /etc/kerbridge.secrets/x"
            ),
            "{e}"
        );
    }

    /// The wrong-group case, which is the one this exists for: `0640 root:root`
    /// passes [`judge`] and is unreadable to the uid that was meant to read it.
    #[test]
    fn a_foreign_group_names_the_group_it_is_and_the_group_to_give_it() {
        let path = Path::new("/etc/kerbridge.secrets/idp/entra/credential");
        assert!(judge(file(0o100640, 0, 0), path, &sync()).is_ok(), "the mode is not the fault");
        let e = file_denial(path, file(0o100640, 0, 0), &sync());
        assert!(e.contains("not its owner and not in its group"), "{e}");
        assert!(e.contains("File:   mode 0640, owner uid 0, group 0"), "{e}");
        assert!(e.contains("Reader: uid 10003, groups 10002"), "{e}");
        assert!(
            e.contains(
                "Fix:    chgrp 10002 /etc/kerbridge.secrets/idp/entra/credential && chmod 0640 \
                 /etc/kerbridge.secrets/idp/entra/credential"
            ),
            "{e}"
        );
    }

    /// The other two denials the mode can survive: in the group but without the
    /// read bit, and owning a file whose owner bits do not carry one.
    #[test]
    fn a_missing_read_bit_names_the_chmod_for_whichever_triple_applies() {
        let group = file_denial(Path::new("/s"), file(0o100600, 0, 10002), &sync());
        assert!(group.contains("in its group, and the group bits carry no read"), "{group}");
        assert!(group.contains("Fix:    chmod 0640 /s"), "{group}");

        let owner = file_denial(Path::new("/s"), file(0o100000, 10003, 10002), &sync());
        assert!(owner.contains("owns it, and the owner bits carry no read"), "{owner}");
        assert!(owner.contains("Fix:    chmod 0640 /s (or 0600"), "{owner}");
    }

    /// A denial the permission bits do not explain must not be answered with a
    /// `chmod`: the operator would run it, see the same failure, and stop
    /// trusting the message.
    #[test]
    fn a_denial_the_bits_do_not_explain_says_so_instead_of_guessing() {
        for (file, reader) in [
            (file(0o100640, 0, 10002), sync()),
            (file(0o100600, 0, 0), Reader { uid: 0, gid: 0, groups: vec![] }),
        ] {
            let e = file_denial(Path::new("/s"), file, &reader);
            assert!(e.contains("Fix:    not this file"), "{e}");
            assert!(!e.contains("chmod"), "{e}");
        }
    }

    /// The kernel stops at the first triple that applies, so an owner can be
    /// denied a read that "other" is granted. A diagnosis that ORs the three
    /// would call this file readable and blame something else.
    #[test]
    fn the_triple_is_the_one_the_kernel_would_pick_not_the_union() {
        let odd = file(0o100004, 10003, 10002);
        assert!(!odd.grants(READ, &sync()), "owner triple is 0, whatever `other` says");
        assert!(
            odd.grants(READ, &Reader { uid: 1, gid: 1, groups: vec![] }),
            "a stranger reads it"
        );
    }

    #[test]
    fn the_primary_group_leads_the_list_and_appears_once() {
        let r = Reader { uid: 10003, gid: 10002, groups: vec![10002, 44, 27] };
        assert_eq!(r.groups_shown(), "10002, 44, 27");
        assert!(r.in_group(44) && r.in_group(10002) && !r.in_group(0));
    }

    /// Whatever the host running the tests is, the process asking is the process
    /// that would be denied -- which is the whole reason no name lookup is
    /// needed here.
    #[test]
    fn the_reader_is_this_process() {
        let me = Reader::current();
        assert_eq!(me.uid, rustix::process::geteuid().as_raw());
        assert!(me.in_group(me.gid));
        assert!(me.groups_shown().starts_with(&me.gid.to_string()));
    }
}
