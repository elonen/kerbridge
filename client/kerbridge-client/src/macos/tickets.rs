//! The macOS arm of [`super`]: Heimdal, through Kerberos.framework.
//!
//! Far less work than the Windows arm, because the broker already speaks the
//! right format. Heimdal reads an MIT ccache v4 natively, so the bytes the broker
//! returns go in unchanged -- no KRB-CRED repackaging, no configuration file, and
//! no elevation. The whole chain was measured before any of this was written:
//! research spike `macos-ticket-injection`.
//!
//! **Which cache gets written.** The `API:` collection holds one cache per client
//! principal, and one of them is the default that `gssd` -- and so Finder and
//! `mount_smbfs` -- reaches for. Writing the default is what the spike proved
//! works, so that is the first choice. It is *not* the choice when the default
//! belongs to somebody else: initializing a cache empties it, and a Mac holding a
//! second realm's credentials would lose them. In that case an existing cache for
//! our own principal is reused, and failing that a new one is created. There is
//! no `krb5_cc_switch` in the framework's export list, so that last case leaves a
//! cache that is not the default -- logged, because it is the one shape of machine
//! where a mount may still ask for a password.
//!
//! **`krb5_cc_copy_creds` is not used.** It would replace the whole store loop
//! in [`inject`], and it is broken in Apple's MIT-compatibility layer: it fails
//! with `KRB5_CC_NOMEM` on a cache Heimdal's own `klist` reads without
//! complaint. Measured from plain C as well as from here, so it is the framework
//! rather than this binding.
//!
//! Emptying our own cache on the way in is deliberate, not incidental: it takes
//! the stale `cifs/<nas>` service ticket with it, which is what makes a group
//! change take effect. It is the same reason the Windows arm purges the realm
//! before it submits.
//!
//! The API is the MIT-compatibility layer Apple ships over Heimdal, and its
//! headers mark it deprecated in favor of GSS.framework. GSS cannot accept a
//! ticket issued elsewhere, which is the only thing this module does, so the
//! deprecation has nowhere to lead. The symbols are what `kinit` and `klist`
//! themselves call.

use std::ffi::{CStr, CString, c_char, c_void};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use anyhow::{Context as _, Result, anyhow, bail};

use super::CachedTgt;
use crate::krbcred::Tgt;
use crate::log;

// ---- FFI -------------------------------------------------------------------

type Ctx = *mut c_void;
type Ccache = *mut c_void;
type Principal = *mut c_void;
type Cursor = *mut c_void;
type ColCursor = *mut c_void;
type Code = i32;

/// End of a cache or collection enumeration -- a sentinel, not a failure.
const KRB5_CC_END: Code = -1_765_328_242;
/// No cache in the collection holds that principal.
const KRB5_CC_NOTFOUND: Code = -1_765_328_243;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TicketTimes {
    authtime: i32,
    starttime: i32,
    endtime: i32,
    renew_till: i32,
}

/// `krb5_creds` as Kerberos.framework lays it out. Only `server` and `times` are
/// read; the rest is named to pin the offsets and never touched. The assertions
/// below are the guard -- measured on macOS 26.4.1, and a silent ABI change here
/// would otherwise read lifetimes out of a keyblock.
#[repr(C)]
struct Creds {
    magic: i32,
    _pad: u32,
    client: Principal,
    server: Principal,
    keyblock: [u8; 24],
    times: TicketTimes,
    is_skey: i32,
    ticket_flags: i32,
    addresses: *mut c_void,
    ticket: [u8; 16],
    second_ticket: [u8; 16],
    authdata: *mut c_void,
}

const _: () = {
    assert!(size_of::<Creds>() == 120);
    assert!(std::mem::offset_of!(Creds, client) == 8);
    assert!(std::mem::offset_of!(Creds, server) == 16);
    assert!(std::mem::offset_of!(Creds, times) == 48);
    assert!(size_of::<TicketTimes>() == 16);
};

#[link(name = "Kerberos", kind = "framework")]
unsafe extern "C" {
    fn krb5_init_context(ctx: *mut Ctx) -> Code;
    fn krb5_free_context(ctx: Ctx);
    fn krb5_get_error_message(ctx: Ctx, code: Code) -> *const c_char;
    fn krb5_free_error_message(ctx: Ctx, msg: *const c_char);

    fn krb5_cc_default(ctx: Ctx, cc: *mut Ccache) -> Code;
    fn krb5_cc_resolve(ctx: Ctx, name: *const c_char, cc: *mut Ccache) -> Code;
    fn krb5_cc_new_unique(
        ctx: Ctx,
        ty: *const c_char,
        hint: *const c_char,
        cc: *mut Ccache,
    ) -> Code;
    fn krb5_cc_close(ctx: Ctx, cc: Ccache) -> Code;
    fn krb5_cc_initialize(ctx: Ctx, cc: Ccache, princ: Principal) -> Code;
    fn krb5_cc_get_principal(ctx: Ctx, cc: Ccache, princ: *mut Principal) -> Code;
    fn krb5_cc_get_name(ctx: Ctx, cc: Ccache) -> *const c_char;
    fn krb5_cc_get_type(ctx: Ctx, cc: Ccache) -> *const c_char;
    fn krb5_cc_cache_match(ctx: Ctx, princ: Principal, cc: *mut Ccache) -> Code;

    fn krb5_cc_start_seq_get(ctx: Ctx, cc: Ccache, cur: *mut Cursor) -> Code;
    fn krb5_cc_next_cred(ctx: Ctx, cc: Ccache, cur: *mut Cursor, creds: *mut Creds) -> Code;
    fn krb5_cc_end_seq_get(ctx: Ctx, cc: Ccache, cur: *mut Cursor) -> Code;
    fn krb5_cc_store_cred(ctx: Ctx, cc: Ccache, creds: *mut Creds) -> Code;
    fn krb5_free_cred_contents(ctx: Ctx, creds: *mut Creds);

    fn krb5_cccol_cursor_new(ctx: Ctx, cur: *mut ColCursor) -> Code;
    fn krb5_cccol_cursor_next(ctx: Ctx, cur: ColCursor, cc: *mut Ccache) -> Code;
    fn krb5_cccol_cursor_free(ctx: Ctx, cur: *mut ColCursor) -> Code;

    fn krb5_free_principal(ctx: Ctx, princ: Principal);
    fn krb5_principal_compare(ctx: Ctx, a: Principal, b: Principal) -> i32;
    fn krb5_unparse_name(ctx: Ctx, princ: Principal, name: *mut *mut c_char) -> Code;
    fn krb5_free_unparsed_name(ctx: Ctx, name: *mut c_char);
}

// ---- the three operations --------------------------------------------------

pub fn inject(ccache: &[u8], _tgt: &Tgt) -> Result<()> {
    let k = Krb5::new()?;
    let spool = Spool::write(ccache)?;

    let src = k.resolve(&format!("FILE:{}", spool.path.display()))?;
    // The source cache names its own client, so nothing here has to trust a
    // principal spelled somewhere else and risk the two disagreeing.
    let principal =
        src.principal()?.ok_or_else(|| anyhow!("the broker's ccache names no client principal"))?;

    let dst = k.destination(&principal)?;
    k.check(unsafe { krb5_cc_initialize(k.ctx, dst.cc, principal.raw) }, "initializing the cache")?;

    let mut stored = 0usize;
    src.for_each_cred(|cred| {
        stored += 1;
        k.check(unsafe { krb5_cc_store_cred(k.ctx, dst.cc, cred) }, "storing a credential")
    })?;
    if stored == 0 {
        bail!("the broker's ccache held no credentials");
    }
    Ok(())
}

pub fn realm_tgt(realm: &str) -> Result<Option<CachedTgt>> {
    let k = Krb5::new()?;
    let want = format!("krbtgt/{realm}@{realm}");
    for cc in k.collection()? {
        let Some(principal) = cc.principal()? else {
            continue;
        };
        let name = k.unparse(&principal)?;
        if !in_realm(&name, realm) {
            continue;
        }
        for cred in cc.credentials()? {
            if cred.server.eq_ignore_ascii_case(&want) {
                return Ok(Some(CachedTgt {
                    principal: name,
                    start: cred.start,
                    end: cred.end,
                    renew_till: cred.renew_till,
                }));
            }
        }
    }
    Ok(None)
}

/// Empty every cache whose client principal belongs to `realm`.
///
/// Cache-level rather than ticket-level, because the collection is already
/// partitioned the way this needs: one cache per client principal, so a cache
/// belonging to `user@REALM` holds that identity's tickets and no one else's.
/// The Windows arm filters on each ticket's *server* realm instead, for the
/// opposite reason -- one flat cache per logon session, with every realm in it.
pub fn purge_realm(realm: &str) -> Result<usize> {
    let k = Krb5::new()?;
    let mut purged = 0usize;
    for cc in k.collection()? {
        let Some(principal) = cc.principal()? else {
            continue;
        };
        if !in_realm(&k.unparse(&principal)?, realm) {
            continue;
        }
        purged += cc.credentials()?.len();
        // Re-initialized rather than destroyed, so the cache keeps whatever
        // standing it has in the collection. Destroying the default cache would
        // leave the collection pointing at a name that no longer resolves.
        k.check(unsafe { krb5_cc_initialize(k.ctx, cc.cc, principal.raw) }, "emptying the cache")?;
    }
    Ok(purged)
}

/// True when `principal` ("user@REALM") belongs to `realm`. Realms are ASCII and
/// conventionally upper-case, but a broker may spell one either way.
fn in_realm(principal: &str, realm: &str) -> bool {
    principal.rsplit_once('@').is_some_and(|(_, r)| r.eq_ignore_ascii_case(realm))
}

// ---- the broker's cache, briefly on disk ------------------------------------

/// The broker's ccache bytes in a file only this user can read, for exactly as
/// long as it takes Heimdal to read them.
///
/// There is no API that takes a cache as a buffer, so this is the one point where
/// a live TGT touches the filesystem -- the Windows arm hands LSA the bytes
/// directly and never does. It is bounded on both sides: mode 0600 inside the
/// app's own directory, and unlinked by [`Drop`] whatever happens above.
struct Spool {
    path: PathBuf,
}

impl Spool {
    fn write(bytes: &[u8]) -> Result<Spool> {
        use std::io::Write;

        let dir = crate::config::app_dir().context("locating the application directory")?;
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        // Unique per attempt so a stale file from a killed process can never be
        // picked up, and `create_new` so this refuses to write through a symlink
        // somebody left behind.
        let path = dir.join(format!("inject-{}.ccache", std::process::id()));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .or_else(|_| {
                let _ = std::fs::remove_file(&path);
                std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)
            })
            .with_context(|| format!("creating {}", path.display()))?;
        f.write_all(bytes).with_context(|| format!("writing {}", path.display()))?;
        Ok(Spool { path })
    }
}

impl Drop for Spool {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

// ---- krb5 handles ----------------------------------------------------------

struct Krb5 {
    ctx: Ctx,
}

impl Krb5 {
    fn new() -> Result<Krb5> {
        let mut ctx: Ctx = std::ptr::null_mut();
        let code = unsafe { krb5_init_context(&mut ctx) };
        if code != 0 || ctx.is_null() {
            bail!("krb5_init_context failed ({code})");
        }
        Ok(Krb5 { ctx })
    }

    /// Turn a non-zero return into an error carrying Heimdal's own message,
    /// which names things like clock skew and unsupported enctypes far better
    /// than a numeric code would.
    fn check(&self, code: Code, what: &str) -> Result<()> {
        if code == 0 {
            return Ok(());
        }
        Err(anyhow!("{what}: {}", self.message(code)))
    }

    fn message(&self, code: Code) -> String {
        unsafe {
            let raw = krb5_get_error_message(self.ctx, code);
            if raw.is_null() {
                return format!("krb5 error {code}");
            }
            let msg = CStr::from_ptr(raw).to_string_lossy().into_owned();
            krb5_free_error_message(self.ctx, raw);
            msg
        }
    }

    fn resolve(&self, name: &str) -> Result<Cache<'_>> {
        let c = CString::new(name).context("cache name")?;
        let mut cc: Ccache = std::ptr::null_mut();
        self.check(unsafe { krb5_cc_resolve(self.ctx, c.as_ptr(), &mut cc) }, "opening the cache")?;
        Ok(Cache { k: self, cc })
    }

    fn unparse(&self, p: &Princ<'_>) -> Result<String> {
        let mut raw: *mut c_char = std::ptr::null_mut();
        self.check(
            unsafe { krb5_unparse_name(self.ctx, p.raw, &mut raw) },
            "reading a principal name",
        )?;
        let name = unsafe { CStr::from_ptr(raw) }.to_string_lossy().into_owned();
        unsafe { krb5_free_unparsed_name(self.ctx, raw) };
        Ok(name)
    }

    /// Every cache in the collection.
    fn collection(&self) -> Result<Vec<Cache<'_>>> {
        let mut cursor: ColCursor = std::ptr::null_mut();
        self.check(
            unsafe { krb5_cccol_cursor_new(self.ctx, &mut cursor) },
            "opening the cache collection",
        )?;
        let mut out = Vec::new();
        loop {
            let mut cc: Ccache = std::ptr::null_mut();
            let code = unsafe { krb5_cccol_cursor_next(self.ctx, cursor, &mut cc) };
            if code != 0 || cc.is_null() {
                break;
            }
            out.push(Cache { k: self, cc });
        }
        unsafe { krb5_cccol_cursor_free(self.ctx, &mut cursor) };
        Ok(out)
    }

    /// The cache to inject into -- see this module's header for why it is not
    /// simply the default one.
    fn destination(&self, principal: &Princ<'_>) -> Result<Cache<'_>> {
        let mut cc: Ccache = std::ptr::null_mut();
        self.check(unsafe { krb5_cc_default(self.ctx, &mut cc) }, "opening the default cache")?;
        let default = Cache { k: self, cc };

        match default.principal()? {
            // Nothing there yet, or it is already ours. Either way this is the
            // cache gssd reaches for, so it is the one to write.
            None => return Ok(default),
            Some(held) if self.same(&held, principal) => return Ok(default),
            Some(_) => {}
        }

        let mut mine: Ccache = std::ptr::null_mut();
        let code = unsafe { krb5_cc_cache_match(self.ctx, principal.raw, &mut mine) };
        if code == 0 && !mine.is_null() {
            return Ok(Cache { k: self, cc: mine });
        }
        if code != KRB5_CC_NOTFOUND {
            self.check(code, "looking for this principal's cache")?;
        }

        let ty = CString::new("API").expect("literal");
        let mut fresh: Ccache = std::ptr::null_mut();
        self.check(
            unsafe { krb5_cc_new_unique(self.ctx, ty.as_ptr(), std::ptr::null(), &mut fresh) },
            "creating a cache",
        )?;
        let fresh = Cache { k: self, cc: fresh };
        log::warn(&format!(
            "the default cache belongs to another identity, so the ticket went to \
             {} instead; a mount may still ask for a password until `kswitch` selects it",
            fresh.full_name()
        ));
        Ok(fresh)
    }

    fn same(&self, a: &Princ<'_>, b: &Princ<'_>) -> bool {
        unsafe { krb5_principal_compare(self.ctx, a.raw, b.raw) != 0 }
    }
}

impl Drop for Krb5 {
    fn drop(&mut self) {
        unsafe { krb5_free_context(self.ctx) };
    }
}

struct Cache<'a> {
    k: &'a Krb5,
    cc: Ccache,
}

/// One credential, reduced to what the caller can use. Extracted while the
/// enumeration holds it so no krb5 allocation outlives the loop.
struct Cred {
    server: String,
    start: i64,
    end: i64,
    renew_till: i64,
}

impl<'a> Cache<'a> {
    /// The cache's client principal, or `None` when the cache does not exist
    /// yet -- which is what a Mac that has never held a ticket looks like, and is
    /// not an error.
    fn principal(&self) -> Result<Option<Princ<'a>>> {
        let mut raw: Principal = std::ptr::null_mut();
        let code = unsafe { krb5_cc_get_principal(self.k.ctx, self.cc, &mut raw) };
        if code != 0 || raw.is_null() {
            return Ok(None);
        }
        Ok(Some(Princ { k: self.k, raw }))
    }

    /// Walk the cache, handing each credential to `f` and freeing it after.
    ///
    /// This loop is why `krb5_cc_copy_creds` is not used to inject, which would
    /// otherwise be one call instead of all of it: in Apple's MIT-compatibility
    /// layer that function fails with `KRB5_CC_NOMEM` on a cache Heimdal's own
    /// `klist` reads happily. Reproduced from plain C against the golden ccache
    /// in `krbcred`'s tests, so it is the framework and not this binding --
    /// `start_seq_get`/`next_cred`/`store_cred` over the same cache works.
    fn for_each_cred(&self, mut f: impl FnMut(&mut Creds) -> Result<()>) -> Result<()> {
        let mut cursor: Cursor = std::ptr::null_mut();
        // An absent cache enumerates as nothing, like an empty one.
        if unsafe { krb5_cc_start_seq_get(self.k.ctx, self.cc, &mut cursor) } != 0 {
            return Ok(());
        }
        let mut result = Ok(());
        loop {
            // SAFETY: krb5_cc_next_cred fills the struct on success and leaves it
            // untouched otherwise; the zeroed value is a valid empty `krb5_creds`.
            let mut creds: Creds = unsafe { std::mem::zeroed() };
            let code = unsafe { krb5_cc_next_cred(self.k.ctx, self.cc, &mut cursor, &mut creds) };
            if code != 0 {
                if code != KRB5_CC_END {
                    log::warn(&format!(
                        "stopped reading {}: {}",
                        self.full_name(),
                        self.k.message(code)
                    ));
                }
                break;
            }
            result = f(&mut creds);
            unsafe { krb5_free_cred_contents(self.k.ctx, &mut creds) };
            if result.is_err() {
                break;
            }
        }
        unsafe { krb5_cc_end_seq_get(self.k.ctx, self.cc, &mut cursor) };
        result
    }

    fn credentials(&self) -> Result<Vec<Cred>> {
        let mut out = Vec::new();
        self.for_each_cred(|creds| {
            // Borrowed from the credential, which `for_each_cred` frees; forgotten
            // below so it is never freed twice.
            let server = Princ { k: self.k, raw: creds.server };
            out.push(Cred {
                server: self.k.unparse(&server).unwrap_or_default(),
                // Heimdal reports 0 for a start time the KDC omitted; the ticket
                // is valid from `authtime` then, and treating 0 as an instant in
                // 1970 would make it look 56 years old.
                start: if creds.times.starttime != 0 {
                    creds.times.starttime as i64
                } else {
                    creds.times.authtime as i64
                },
                end: creds.times.endtime as i64,
                renew_till: creds.times.renew_till as i64,
            });
            std::mem::forget(server);
            Ok(())
        })?;
        Ok(out)
    }

    /// `API:1234ABCD-…`, for a log line that says which cache was meant.
    fn full_name(&self) -> String {
        unsafe {
            let ty = krb5_cc_get_type(self.k.ctx, self.cc);
            let name = krb5_cc_get_name(self.k.ctx, self.cc);
            let part = |p: *const c_char| {
                if p.is_null() {
                    String::new()
                } else {
                    CStr::from_ptr(p).to_string_lossy().into_owned()
                }
            };
            format!("{}:{}", part(ty), part(name))
        }
    }
}

impl Drop for Cache<'_> {
    fn drop(&mut self) {
        unsafe { krb5_cc_close(self.k.ctx, self.cc) };
    }
}

struct Princ<'a> {
    k: &'a Krb5,
    raw: Principal,
}

impl Drop for Princ<'_> {
    fn drop(&mut self) {
        unsafe { krb5_free_principal(self.k.ctx, self.raw) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Injects the golden ccache from [`crate::krbcred`]'s tests and reads it
    /// back through the collection -- the whole macOS path except the broker.
    ///
    /// Ignored by default because it writes this user's real ticket cache.
    /// `cargo test -- --ignored injects_and_reads_back` on a Mac with no
    /// EXAMPLE.SITE tickets of its own.
    #[test]
    #[ignore]
    fn injects_and_reads_back() {
        let ccache = include_bytes!("../../../../testbench/fixtures/kerberos/golden.ccache");
        let tgt = crate::krbcred::ccache_to_tgt(ccache).unwrap();
        inject(ccache, &tgt).unwrap();

        let found = realm_tgt("EXAMPLE.SITE").unwrap().expect("the TGT just injected");
        assert_eq!(found.principal, "alice@EXAMPLE.SITE");
        assert_eq!((found.start, found.end), (tgt.start, tgt.end));

        assert_eq!(purge_realm("EXAMPLE.SITE").unwrap(), 1);
        assert!(realm_tgt("EXAMPLE.SITE").unwrap().is_none());
    }
}
