//! Which unix group owns the socket and which unix user may speak on it, out of
//! a name or out of a number.
//!
//! Here rather than in `kerbridge-core` because the broker and sync link that
//! same parser and have no business gaining a libc name lookup; the numeric
//! fields are all core needs in order to describe the file. The consequence,
//! stated so nobody reads it as an oversight: `kbconfig check` verifies the
//! *keys*, never that a name exists on the host, and `issuerd` is the only thing
//! that ever resolves one.
//!
//! **musl has no NSS**, and this binary links static
//! against musl, which ignores `/etc/nsswitch.conf` entirely and
//! parses `/etc/passwd` and `/etc/group` itself -- so a unix user or group that
//! exists only in LDAP, SSSD or winbind never resolves in this process, however
//! well `getent` answers on the same host. A Samba AD DC is precisely where
//! someone expects otherwise, which is why it is written down here. It is
//! correct for this design: these are local unix users a package creates. Static
//! linking removes a hazard rather than adding one -- with no `dlopen` there is
//! no NSS module to be missing at runtime -- and it was measured before the
//! decision was taken, on trixie and noble: both calls resolve, and both return
//! a clean NULL for a name that is not there.

use std::path::Path;

use anyhow::{Context, Result};
use kerbridge_core::config::{ISSUERD_FILE, Issuerd};
use nix::unistd::{Group, User};

/// `(socket_gid, broker_uid)`, however each of the two was spelled.
///
/// A stated name wins over the number beside it; a file stating both is
/// `kbconfig check`'s to refuse, because serde cannot tell a written `10002`
/// from an absent line and this cannot either.
///
/// A name that does not resolve is fatal and never falls back to the number.
/// The fallback would be a silent disagreement about who may speak to the KDC --
/// it costs every login and reports nothing, which is the failure this whole
/// contract exists to prevent.
pub fn resolve(issuerd: &Issuerd, config_dir: &Path) -> Result<(u32, u32)> {
    let file = config_dir.join(ISSUERD_FILE);
    let gid = match &issuerd.socket_group {
        Some(name) => id("socket_group", "group", name, &file, group_gid)?,
        None => issuerd.socket_gid,
    };
    let uid = match &issuerd.broker_user {
        Some(name) => id("broker_user", "user", name, &file, user_uid)?,
        None => issuerd.broker_uid,
    };
    Ok((gid, uid))
}

/// One name resolved, or the refusal an operator has to act on -- which key,
/// which name, and which file the two came out of. Nothing else on the host says
/// where that line is: a package's config directory is not the one a container
/// bind-mounts.
fn id(
    key: &str,
    kind: &str,
    name: &str,
    file: &Path,
    lookup: fn(&str) -> nix::Result<Option<u32>>,
) -> Result<u32> {
    let at = || format!("{key} = {name:?} in {}", file.display());
    lookup(name).with_context(at)?.with_context(|| {
        format!(
            "{}: this host has no unix {kind} of that name. Only /etc/passwd and \
             /etc/group are read -- issuerd is a static musl binary and consults no \
             nsswitch.conf, so an LDAP, SSSD or winbind {kind} is not one of them.",
            at()
        )
    })
}

/// `getgrnam_r` and `getpwnam_r`. `Ok(None)` is the clean "no such name", which
/// `id` reports differently from a lookup that failed; a name holding a NUL byte
/// is `Ok(None)` too, since `nix` cannot pass one to libc.
fn group_gid(name: &str) -> nix::Result<Option<u32>> {
    Ok(Group::from_name(name)?.map(|group| group.gid.as_raw()))
}

fn user_uid(name: &str) -> nix::Result<Option<u32>> {
    Ok(User::from_name(name)?.map(|user| user.uid.as_raw()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Somewhere no config set is: these tests read the path out of the error,
    /// and nothing here opens the file.
    const CONFIG_DIR: &str = "/etc/kerbridge";

    /// A name this host really has, read out of the file the lookup itself
    /// reads. What the tests need is a name that resolves, not a particular one,
    /// and naming `root` would assume a passwd file they do not control.
    fn first(file: &str) -> Option<(String, u32)> {
        std::fs::read_to_string(file).ok()?.lines().find_map(|line| {
            let mut columns = line.split(':');
            let name = columns.next().filter(|n| !n.is_empty() && !n.starts_with('#'))?;
            let id = columns.nth(1)?.parse().ok()?;
            Some((name.to_owned(), id))
        })
    }

    fn stating(group: Option<&str>, user: Option<&str>) -> Issuerd {
        Issuerd {
            socket_group: group.map(str::to_owned),
            broker_user: user.map(str::to_owned),
            ..Issuerd::default()
        }
    }

    /// Each key accepts a name, a numeric ID, or its documented default.
    /// `provision.sh` exercises the defaults with an empty `issuerd.toml`.
    #[test]
    fn a_name_resolves_a_number_stands_and_a_file_stating_neither_gets_the_default() {
        let dir = Path::new(CONFIG_DIR);
        let (group, gid) = first("/etc/group").expect("this host has a group file");
        let (user, uid) = first("/etc/passwd").expect("this host has a passwd file");

        assert_eq!(resolve(&stating(Some(&group), Some(&user)), dir).unwrap(), (gid, uid));

        let mut numbers = stating(None, None);
        (numbers.socket_gid, numbers.broker_uid) = (4242, 4243);
        assert_eq!(resolve(&numbers, dir).unwrap(), (4242, 4243));

        assert_eq!(resolve(&Issuerd::default(), dir).unwrap(), (10002, 10001));
    }

    /// An unresolvable name stops the process, and the refusal carries the whole
    /// of what fixing it needs: which key, which name, which file. It never
    /// falls back to the number sitting beside it.
    #[test]
    fn an_unresolvable_name_is_fatal_and_names_the_key_the_name_and_the_file() {
        let dir = Path::new(CONFIG_DIR);
        let missing = "_kerbridge-no-such-account";
        for (issuerd, key) in [
            (stating(Some(missing), None), "socket_group"),
            (stating(None, Some(missing)), "broker_user"),
        ] {
            let err = format!("{:#}", resolve(&issuerd, dir).unwrap_err());
            assert!(err.contains(key), "{err}");
            assert!(err.contains(missing), "{err}");
            assert!(err.contains("/etc/kerbridge/issuerd.toml"), "{err}");
            assert!(!err.contains("10002") && !err.contains("10001"), "{err}");
        }
    }
}
