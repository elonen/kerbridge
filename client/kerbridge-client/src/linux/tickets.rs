//! The Linux arm of [`super`]: MIT krb5's own `FILE:` cache, written directly.
//! Part of the CI-only Linux arm -- see [`crate::os`] for what that is and is not.
//!
//! The least machinery of the three arms, because the wire format was already
//! shaped for it. The broker emits `mit-ccache-v4`; a `FILE:` cache *is* that
//! format, so [`inject`] is a file write and nothing is repackaged -- the same
//! bargain macOS gets from Heimdal, one step plainer, because there the bytes go
//! through a library and here they go to a path the caller names.
//!
//! # Which file, and what happens when nobody says
//!
//! `KRB5CCNAME` names the cache, and this arm honours it: `FILE:/path`, or a
//! bare `/path`, which MIT also accepts. When it is **unset**, the ticket goes to
//! `/tmp/krb5cc_<euid>` -- MIT's own built-in default, and therefore where an
//! unconfigured `smbclient` or `cifs.upcall` on the same machine will look -- and
//! [`inject`] logs the path it chose.
//!
//! It is logged rather than assumed silently because a ccache written where
//! nothing looks for it is *the* failure mode of this arm, and it does not
//! present as one: the injection succeeds, and something else later reports that
//! it has no credentials and asks for a password. `/etc/krb5.conf`'s
//! `default_ccache_name` is the case this arm cannot see -- it moves MIT's
//! default without touching the environment, and nothing here parses it. A
//! deployment that sets it must set `KRB5CCNAME` too, and the log line is what
//! makes the disagreement visible instead of mysterious.
//!
//! A cache type this arm cannot write -- `DIR:`, `KEYRING:`, `KCM:` -- is refused
//! by name rather than written to the wrong place. `FILE:` is what the bench
//! drives `smbclient` with; a second cache type is a real Linux client's problem.
//!
//! # What it does not do
//!
//! Not merge. [`inject`] replaces the named cache, which is what the broker's
//! bytes are: a complete cache for one principal, freshly issued. That takes any
//! stale `cifs/<nas>` service ticket in it with it, which is the point and the
//! same reason the other two arms empty before they write -- an old PAC
//! otherwise keeps serving after a group change. If the named cache belonged to
//! somebody else, this arm says so in the log before overwriting it, because on
//! Linux -- unlike the macOS collection -- there is one file and no second place
//! for the other identity to go.

use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use super::CachedTgt;
use crate::krbcred::{CachedCred, Tgt};
use crate::log;

/// MIT's compiled-in default when nothing else names a cache.
fn default_path() -> PathBuf {
    PathBuf::from(format!("/tmp/krb5cc_{}", crate::os::euid()))
}

/// The cache this arm reads and writes, and whether the environment named it.
///
/// Returned as a pair so [`inject`] can say which of the two it is: only one of
/// them is a guess, and only the guess is worth a log line every time.
fn cache_path() -> Result<(PathBuf, bool)> {
    let Some(name) = crate::os::env("KRB5CCNAME") else {
        return Ok((default_path(), false));
    };
    match name.split_once(':') {
        Some(("FILE", path)) => Ok((PathBuf::from(path), true)),
        // A bare path, which MIT reads as FILE:.
        None if name.starts_with('/') => Ok((PathBuf::from(name), true)),
        _ => bail!(
            "KRB5CCNAME is {name}: this client writes only a FILE: credential cache. \
             Set KRB5CCNAME=FILE:/path (or an absolute path) and try again."
        ),
    }
}

/// Write the broker's ccache bytes to the named `FILE:` cache.
///
/// `tgt` is unused: it carries the DER KRB-CRED the Windows arm submits, and
/// this arm -- like macOS -- consumes the ccache the broker already sent. Parsing
/// still happens once, in the caller, for the lifetime the schedule runs off.
pub fn inject(ccache: &[u8], _tgt: &Tgt) -> Result<()> {
    let (path, named) = cache_path()?;
    if !named {
        log::info(&format!(
            "KRB5CCNAME is unset; writing the ticket to {} -- MIT's default. \
             If krb5.conf sets default_ccache_name, set KRB5CCNAME to match it.",
            path.display()
        ));
    }
    // Whose cache is being replaced, said before it is gone rather than after.
    // Only a *different* identity is worth a warning: overwriting this user's
    // own cache is what every re-injection does.
    if let Some(held) = client_of(&std::fs::read(&path).unwrap_or_default())
        && client_of(ccache).is_some_and(|fresh| fresh != held)
    {
        log::warn(&format!(
            "{} held {held}'s tickets; replacing it with the ticket just issued",
            path.display()
        ));
    }

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    // Written beside the cache and renamed over it, so a reader never sees half
    // a cache and a failed write never destroys a working ticket. Same
    // directory, because a rename is only atomic within one filesystem.
    let temp = path.with_extension(format!("kb{}", std::process::id()));
    let written = write_private(&temp, ccache).and_then(|()| {
        std::fs::rename(&temp, &path).with_context(|| format!("replacing {}", path.display()))
    });
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    written
}

/// The identity a cache's credentials belong to, or `None` for a cache that is
/// absent, empty or not one.
fn client_of(ccache: &[u8]) -> Option<String> {
    crate::krbcred::read_cache(ccache).ok()?.into_iter().next().map(|c| c.client)
}

/// Create `path` readable by this user alone and write `bytes` to it.
///
/// 0600 is not housekeeping: a ccache holds a session key, and MIT and Heimdal
/// both *ignore* a cache any other user can read rather than warning about it --
/// which then presents as "no credentials" and a password prompt. `create_new`
/// so this refuses to write through a symlink somebody left in `/tmp`, which is
/// the ordinary home of the default cache and a world-writable directory.
fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let _ = std::fs::remove_file(path);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(bytes).with_context(|| format!("writing {}", path.display()))?;
    f.sync_all().with_context(|| format!("flushing {}", path.display()))
}

pub fn realm_tgt(realm: &str) -> Result<Option<CachedTgt>> {
    let want = format!("krbtgt/{realm}@{realm}");
    Ok(read()?.into_iter().find(|c| c.is_tgt && c.server.eq_ignore_ascii_case(&want)).map(|c| {
        CachedTgt { principal: c.client, start: c.start, end: c.end, renew_till: c.renew_till }
    }))
}

/// Drop this realm's tickets by removing the cache that holds them.
///
/// Whole-file, because a `FILE:` cache is already partitioned the way this needs:
/// it names one client principal, so a cache belonging to `user@REALM` holds that
/// identity's tickets and nobody else's -- the same argument the macOS arm makes
/// about its collection, where the Windows arm has to filter ticket by ticket
/// because one flat cache per logon session holds every realm at once.
///
/// Removed rather than emptied: MIT recreates the file on the next write, and an
/// empty cache carrying only a header is a shape some readers report as an error
/// rather than as no tickets.
pub fn purge_realm(realm: &str) -> Result<usize> {
    let creds = read()?;
    if !creds.iter().any(|c| in_realm(&c.client, realm)) {
        return Ok(0);
    }
    let (path, _) = cache_path()?;
    std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    Ok(creds.len())
}

/// The named cache's credentials. An absent cache reads as no credentials, which
/// is what a machine that has never held a ticket looks like and is not an
/// error; an unreadable or malformed one is.
fn read() -> Result<Vec<CachedCred>> {
    let (path, _) = cache_path()?;
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    crate::krbcred::read_cache(&bytes).with_context(|| format!("parsing {}", path.display()))
}

/// True when `principal` ("user@REALM") belongs to `realm`. Realms are ASCII and
/// conventionally upper-case, but a broker may spell one either way.
fn in_realm(principal: &str, realm: &str) -> bool {
    principal.rsplit_once('@').is_some_and(|(_, r)| r.eq_ignore_ascii_case(realm))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole arm, against a cache of its own: inject the golden ccache, read
    /// the TGT back, purge it, and find nothing.
    ///
    /// `KRB5CCNAME` points at a throwaway path, so unlike the macOS arm's
    /// equivalent this touches no real ticket cache and does not have to be
    /// `#[ignore]`d -- which is the point of the arm existing, since this is the
    /// test that runs in CI.
    #[test]
    fn injects_reads_back_and_purges() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("krb5cc_test");
        // SAFETY: `KRB5CCNAME` is process-wide, and this is the only test in the
        // crate that reads or writes it.
        unsafe { std::env::set_var("KRB5CCNAME", format!("FILE:{}", path.display())) };

        let ccache = include_bytes!("../../../../testbench/fixtures/kerberos/golden.ccache");
        let tgt = crate::krbcred::ccache_to_tgt(ccache).expect("the golden ccache holds a TGT");

        assert!(realm_tgt("EXAMPLE.SITE").unwrap().is_none(), "nothing there yet");
        inject(ccache, &tgt).unwrap();

        // The bytes go in unchanged -- that is the whole claim of this arm.
        assert_eq!(std::fs::read(&path).unwrap(), ccache);

        let found = realm_tgt("EXAMPLE.SITE").unwrap().expect("the TGT just injected");
        assert_eq!(found.principal, "alice@EXAMPLE.SITE");
        assert_eq!((found.start, found.end), (tgt.start, tgt.end));
        // Case-insensitive, because a broker may spell the realm either way.
        assert!(realm_tgt("example.site").unwrap().is_some());
        assert!(realm_tgt("OTHER.SITE").unwrap().is_none());

        // Readable by this user alone: MIT and Heimdal both ignore a cache that
        // is not, and report it as having no credentials.
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);

        assert_eq!(purge_realm("OTHER.SITE").unwrap(), 0, "another realm is not ours to drop");
        assert!(path.exists());
        assert!(purge_realm("EXAMPLE.SITE").unwrap() >= 1);
        assert!(!path.exists());
        assert!(realm_tgt("EXAMPLE.SITE").unwrap().is_none());

        // A re-injection over a live cache is the ordinary case, not a special
        // one: the schedule does it every few hours.
        inject(ccache, &tgt).unwrap();
        inject(ccache, &tgt).unwrap();
        assert!(realm_tgt("EXAMPLE.SITE").unwrap().is_some());

        // A bare absolute path is the other spelling MIT accepts.
        let bare = dir.path().join("bare_cache");
        unsafe { std::env::set_var("KRB5CCNAME", bare.display().to_string()) };
        inject(ccache, &tgt).unwrap();
        assert!(bare.exists());
        assert!(realm_tgt("EXAMPLE.SITE").unwrap().is_some());

        // A cache type this arm cannot write is refused *by name*, because the
        // alternative -- writing a FILE: cache anyway -- lands the ticket where
        // nothing is looking and reports success.
        for name in ["KEYRING:persistent:1000", "KCM:1000", "DIR:/run/user/1000/krb5cc"] {
            unsafe { std::env::set_var("KRB5CCNAME", name) };
            let e = inject(ccache, &tgt).expect_err("this arm writes only FILE: caches");
            assert!(e.to_string().contains(name), "the refusal has to name what it refused: {e}");
            assert!(realm_tgt("EXAMPLE.SITE").is_err());
            assert!(purge_realm("EXAMPLE.SITE").is_err());
        }

        // With nothing set at all, the cache is MIT's own default -- so an
        // unconfigured `smbclient` beside this process finds the ticket.
        unsafe { std::env::remove_var("KRB5CCNAME") };
        let (path, named) = cache_path().unwrap();
        assert!(!named);
        assert_eq!(path, PathBuf::from(format!("/tmp/krb5cc_{}", crate::os::euid())));
    }

    /// A cache holding somebody else's ticket is still replaced -- there is one
    /// file and no second place for the other identity to go -- but the log says
    /// so first. This asserts the fact the log line is derived from.
    #[test]
    fn a_cache_names_the_identity_whose_tickets_it_holds() {
        let ccache = include_bytes!("../../../../testbench/fixtures/kerberos/golden.ccache");
        assert_eq!(client_of(ccache).as_deref(), Some("alice@EXAMPLE.SITE"));
        // The three shapes that are not a cache, none of which may panic.
        assert_eq!(client_of(&[]), None);
        assert_eq!(client_of(b"not a ccache at all"), None);
        assert_eq!(client_of(&ccache[..12]), None);
    }
}
