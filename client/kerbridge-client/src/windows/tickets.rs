//! The Windows arm of [`super`]: LSA, not a file cache.
//!
//! Windows keeps no ccache on disk, so the broker's cache is repackaged as a DER
//! KRB-CRED ([`crate::krbcred`]) and handed to the Kerberos security package with
//! `KerbSubmitTicketMessage`, after which the native SMB redirector obtains its
//! own `cifs/nas` service ticket and connects transparently. Submitting into the
//! caller's *own* logon session (LogonId = 0) needs no privilege; targeting
//! another session's LUID would need SeTcbPrivilege.
//!
//! Every ticket-cache operation goes through the LSA API directly, never
//! `klist`: `klist purge` has no realm filter and would destroy the user's own
//! cloud TGT on an Entra-joined machine, and `klist get`
//! (`KerbRetrieveTicket`) **destroys** an injected TGT when acquisition fails
//! (measured 2/2 -- `client/DESIGN.md` @ principles), so it is never called here.
//!
//! Reference implementations: Rubeus `ptt`, Mimikatz `kerberos::ptt`.

use anyhow::{Result, anyhow};
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::{NonNull, null_mut};

use windows_sys::Win32::Foundation::{HANDLE, LUID, NTSTATUS};
use windows_sys::Win32::Security::Authentication::Identity::{
    KERB_CRYPTO_KEY32, KERB_PURGE_TKT_CACHE_EX_REQUEST, KERB_QUERY_TKT_CACHE_EX_RESPONSE,
    KERB_QUERY_TKT_CACHE_REQUEST, KERB_SUBMIT_TKT_REQUEST, KerbPurgeTicketCacheExMessage,
    KerbQueryTicketCacheExMessage, KerbSubmitTicketMessage, LSA_STRING, LSA_UNICODE_STRING,
    LsaCallAuthenticationPackage, LsaConnectUntrusted, LsaDeregisterLogonProcess,
    LsaFreeReturnBuffer, LsaLookupAuthenticationPackage,
};

use super::CachedTgt;
use crate::krbcred::Tgt;

const STATUS_SUCCESS: NTSTATUS = 0;

/// One cached ticket, copied out of the LSA response so the response buffer can
/// be freed immediately. The names are kept as UTF-16 because that is what the
/// purge template wants back -- which is also why this stays private and
/// [`CachedTgt`] is what leaves the module.
struct CachedTicket {
    client_name: Vec<u16>,
    client_realm: Vec<u16>,
    server_name: Vec<u16>,
    server_realm: Vec<u16>,
    /// Unix seconds, converted from the FILETIME the package reports.
    start: i64,
    end: i64,
    renew_till: i64,
}

impl CachedTicket {
    fn client(&self) -> String {
        format!(
            "{}@{}",
            String::from_utf16_lossy(&self.client_name),
            String::from_utf16_lossy(&self.client_realm)
        )
    }

    fn server(&self) -> String {
        String::from_utf16_lossy(&self.server_name)
    }

    /// True for *this* realm's own TGT -- `krbtgt/REALM`, matched whole. A prefix
    /// test would also accept `krbtgt/OTHER.REALM`, which is a cross-realm referral
    /// ticket with a different lifetime, not the ticket we injected.
    fn is_tgt_for(&self, realm: &str) -> bool {
        String::from_utf16_lossy(&self.server_name).eq_ignore_ascii_case(&format!("krbtgt/{realm}"))
    }
}

pub fn inject(_ccache: &[u8], tgt: &Tgt) -> Result<()> {
    with_kerberos(|lsa, pkg| submit_with_handle(lsa, pkg, &tgt.krbcred))
}

pub fn realm_tgt(realm: &str) -> Result<Option<CachedTgt>> {
    with_kerberos(|lsa, pkg| {
        let realm_u16: Vec<u16> = realm.encode_utf16().collect();
        Ok(query_cache(lsa, pkg)?
            .into_iter()
            .find(|t| t.is_tgt_for(realm) && eq_ascii_ci(&t.server_realm, &realm_u16))
            .map(|t| CachedTgt {
                principal: t.client(),
                start: t.start,
                end: t.end,
                renew_till: t.renew_till,
            }))
    })
}

/// Enumerate the cache, then purge each matching ticket by name. A realm-only
/// *purge* template is rejected (STATUS_INVALID_PARAMETER); purging each ticket
/// by its exact server name is what the EX purge accepts.
pub fn purge_realm(realm: &str) -> Result<usize> {
    with_kerberos(|lsa, pkg| {
        let realm_u16: Vec<u16> = realm.encode_utf16().collect();
        let mut purged = 0usize;
        let mut failures: Vec<String> = Vec::new();
        for t in query_cache(lsa, pkg)? {
            if !eq_ascii_ci(&t.server_realm, &realm_u16) {
                continue;
            }
            match purge_one(lsa, pkg, &t) {
                Ok(()) => purged += 1,
                Err(e) => failures.push(e.to_string()),
            }
        }
        if !failures.is_empty() {
            return Err(anyhow!(
                "purged {purged} ticket(s) for {realm}; {} refused: {}",
                failures.len(),
                failures.join("; ")
            ));
        }
        Ok(purged)
    })
}

/// Open an untrusted LSA connection, resolve the Kerberos package, run `f`, and
/// always deregister. Untrusted is sufficient for operating on our own session.
fn with_kerberos<T>(f: impl FnOnce(HANDLE, u32) -> Result<T>) -> Result<T> {
    let mut lsa_handle: HANDLE = null_mut();
    let st = unsafe { LsaConnectUntrusted(&mut lsa_handle) };
    if st != STATUS_SUCCESS {
        return Err(anyhow!("LsaConnectUntrusted failed (NTSTATUS {:#010x})", st as u32));
    }
    let result = lookup_kerberos(lsa_handle).and_then(|pkg| f(lsa_handle, pkg));
    unsafe { LsaDeregisterLogonProcess(lsa_handle) };
    result
}

/// Resolve the Kerberos authentication package id ("Kerberos",
/// MICROSOFT_KERBEROS_NAME_A).
fn lookup_kerberos(lsa_handle: HANDLE) -> Result<u32> {
    let pkg = b"Kerberos\0";
    let lsa_name = LSA_STRING {
        Length: 8,        // bytes, excluding the NUL
        MaximumLength: 9, // bytes, including the NUL
        Buffer: pkg.as_ptr() as *mut u8,
    };
    let mut auth_pkg: u32 = 0;
    let st = unsafe { LsaLookupAuthenticationPackage(lsa_handle, &lsa_name, &mut auth_pkg) };
    if st != STATUS_SUCCESS {
        return Err(anyhow!(
            "LsaLookupAuthenticationPackage(Kerberos) failed (NTSTATUS {:#010x})",
            st as u32
        ));
    }
    Ok(auth_pkg)
}

fn submit_with_handle(lsa_handle: HANDLE, auth_pkg: u32, krbcred: &[u8]) -> Result<()> {
    // Build one contiguous submit buffer: the fixed request header immediately
    // followed by the KRB-CRED bytes, with KerbCredOffset pointing at them.
    let header_size = size_of::<KERB_SUBMIT_TKT_REQUEST>();
    let total = header_size + krbcred.len();
    let mut buf = vec![0u8; total];

    let req = KERB_SUBMIT_TKT_REQUEST {
        MessageType: KerbSubmitTicketMessage,
        LogonId: LUID { LowPart: 0, HighPart: 0 }, // 0 = current logon session
        Flags: 0,
        Key: KERB_CRYPTO_KEY32 { KeyType: 0, Length: 0, Offset: 0 }, // no extra key
        KerbCredSize: krbcred.len() as u32,
        KerbCredOffset: header_size as u32,
    };
    // SAFETY: KERB_SUBMIT_TKT_REQUEST is repr(C) POD; `buf` holds `header_size` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(
            &req as *const KERB_SUBMIT_TKT_REQUEST as *const u8,
            buf.as_mut_ptr(),
            header_size,
        );
    }
    buf[header_size..].copy_from_slice(krbcred);

    let (_, protocol_status) = call_package(lsa_handle, auth_pkg, &buf)?;
    if protocol_status != STATUS_SUCCESS {
        return Err(anyhow!(
            "Kerberos package rejected the ticket (protocol status {:#010x}) -- \
             often a clock skew or unsupported enctype",
            protocol_status as u32
        ));
    }
    Ok(())
}

/// Enumerate the logon session's ticket cache into owned entries.
fn query_cache(lsa_handle: HANDLE, auth_pkg: u32) -> Result<Vec<CachedTicket>> {
    let query = KERB_QUERY_TKT_CACHE_REQUEST {
        MessageType: KerbQueryTicketCacheExMessage,
        LogonId: LUID { LowPart: 0, HighPart: 0 },
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(
            &query as *const KERB_QUERY_TKT_CACHE_REQUEST as *const u8,
            size_of::<KERB_QUERY_TKT_CACHE_REQUEST>(),
        )
    };

    let mut ret_buf: *mut c_void = null_mut();
    let mut ret_len: u32 = 0;
    let mut protocol_status: NTSTATUS = 0;
    let st = unsafe {
        LsaCallAuthenticationPackage(
            lsa_handle,
            auth_pkg,
            bytes.as_ptr() as *const c_void,
            bytes.len() as u32,
            &mut ret_buf,
            &mut ret_len,
            &mut protocol_status,
        )
    };
    if st != STATUS_SUCCESS {
        return Err(anyhow!("KerbQueryTicketCacheEx call failed (NTSTATUS {:#010x})", st as u32));
    }
    if protocol_status != STATUS_SUCCESS {
        if !ret_buf.is_null() {
            unsafe { LsaFreeReturnBuffer(ret_buf) };
        }
        return Err(anyhow!(
            "Kerberos package refused the cache query (protocol status {:#010x})",
            protocol_status as u32
        ));
    }
    let Some(resp) = NonNull::new(ret_buf) else {
        return Ok(Vec::new()); // empty cache
    };

    // SAFETY: on success the package returns a KERB_QUERY_TKT_CACHE_EX_RESPONSE
    // followed by CountOfTickets entries; every UNICODE_STRING Buffer points inside
    // this buffer, valid until LsaFreeReturnBuffer below. Everything is copied out
    // before the free, so no borrowed pointer escapes.
    let mut out = Vec::new();
    unsafe {
        let resp = resp.cast::<KERB_QUERY_TKT_CACHE_EX_RESPONSE>().as_ref();
        let tickets =
            std::slice::from_raw_parts(resp.Tickets.as_ptr(), resp.CountOfTickets as usize);
        for t in tickets {
            out.push(CachedTicket {
                client_name: ustr_vec(&t.ClientName),
                client_realm: ustr_vec(&t.ClientRealm),
                server_name: ustr_vec(&t.ServerName),
                server_realm: ustr_vec(&t.ServerRealm),
                start: filetime_to_unix(t.StartTime),
                end: filetime_to_unix(t.EndTime),
                renew_till: filetime_to_unix(t.RenewTime),
            });
        }
        LsaFreeReturnBuffer(ret_buf);
    }
    Ok(out)
}

/// Purge one ticket, named by its full client+server identity, using a
/// self-contained submit buffer: the four names are appended after the request
/// and the template's UNICODE_STRING buffers point *inside* it. LSA relocates
/// pointers that lie within the submit buffer (the same mechanism `KerbCredOffset`
/// relies on for submit); a template pointing at a separate allocation is rejected
/// with STATUS_INVALID_PARAMETER, which is why response-buffer pointers fail.
fn purge_one(lsa_handle: HANDLE, auth_pkg: u32, t: &CachedTicket) -> Result<()> {
    let struct_size = size_of::<KERB_PURGE_TKT_CACHE_EX_REQUEST>();
    let (cn, cr) = (struct_size, struct_size + t.client_name.len() * 2);
    let sn = cr + t.client_realm.len() * 2;
    let sr = sn + t.server_name.len() * 2;
    let total = sr + t.server_realm.len() * 2;
    let mut buf = vec![0u8; total];
    let base = buf.as_mut_ptr();

    let ustr = |off: usize, s: &[u16]| LSA_UNICODE_STRING {
        Length: (s.len() * 2) as u16,
        MaximumLength: (s.len() * 2) as u16,
        Buffer: unsafe { base.add(off) } as *mut u16,
    };
    let mut req: KERB_PURGE_TKT_CACHE_EX_REQUEST = unsafe { std::mem::zeroed() };
    req.MessageType = KerbPurgeTicketCacheExMessage;
    // LogonId {0,0} = current session; Flags 0 = match the template.
    req.TicketTemplate.ClientName = ustr(cn, &t.client_name);
    req.TicketTemplate.ClientRealm = ustr(cr, &t.client_realm);
    req.TicketTemplate.ServerName = ustr(sn, &t.server_name);
    req.TicketTemplate.ServerRealm = ustr(sr, &t.server_realm);

    // SAFETY: `buf` holds `total` bytes; each copy stays within its slice, and the
    // request header exactly fills the first `struct_size` bytes.
    unsafe {
        let copy = |off: usize, s: &[u16]| {
            std::ptr::copy_nonoverlapping(s.as_ptr() as *const u8, base.add(off), s.len() * 2)
        };
        copy(cn, &t.client_name);
        copy(cr, &t.client_realm);
        copy(sn, &t.server_name);
        copy(sr, &t.server_realm);
        std::ptr::copy_nonoverlapping(
            &req as *const KERB_PURGE_TKT_CACHE_EX_REQUEST as *const u8,
            base,
            struct_size,
        );
    }

    let (_, protocol_status) = call_package(lsa_handle, auth_pkg, &buf)?;
    if protocol_status != STATUS_SUCCESS {
        return Err(anyhow!(
            "purge of {} refused (protocol status {:#010x})",
            t.server(),
            protocol_status as u32
        ));
    }
    Ok(())
}

/// `LsaCallAuthenticationPackage` with the return buffer freed. Returns the call
/// status (checked) and the package's protocol status (the caller's to interpret).
fn call_package(lsa_handle: HANDLE, auth_pkg: u32, submit: &[u8]) -> Result<(NTSTATUS, NTSTATUS)> {
    let mut ret_buf: *mut c_void = null_mut();
    let mut ret_len: u32 = 0;
    let mut protocol_status: NTSTATUS = 0;
    let st = unsafe {
        LsaCallAuthenticationPackage(
            lsa_handle,
            auth_pkg,
            submit.as_ptr() as *const c_void,
            submit.len() as u32,
            &mut ret_buf,
            &mut ret_len,
            &mut protocol_status,
        )
    };
    if !ret_buf.is_null() {
        unsafe { LsaFreeReturnBuffer(ret_buf) };
    }
    if st != STATUS_SUCCESS {
        return Err(anyhow!("LsaCallAuthenticationPackage failed (NTSTATUS {:#010x})", st as u32));
    }
    Ok((st, protocol_status))
}

/// Copy an `LSA_UNICODE_STRING`'s buffer into an owned `u16` vector.
fn ustr_vec(s: &LSA_UNICODE_STRING) -> Vec<u16> {
    if s.Buffer.is_null() || s.Length == 0 {
        return Vec::new();
    }
    unsafe { std::slice::from_raw_parts(s.Buffer, s.Length as usize / 2) }.to_vec()
}

/// ASCII case-insensitive compare. Kerberos realms are ASCII; the cache stores
/// the realm upper-cased, but a broker could spell it either way.
fn eq_ascii_ci(have: &[u16], want: &[u16]) -> bool {
    have.len() == want.len()
        && have.iter().zip(want).all(|(&a, &b)| ascii_lower_u16(a) == ascii_lower_u16(b))
}

fn ascii_lower_u16(c: u16) -> u16 {
    if (0x41..=0x5A).contains(&c) { c + 0x20 } else { c }
}

/// Windows FILETIME (100 ns ticks since 1601-01-01) → Unix seconds. A zero or
/// negative-looking FILETIME (the package uses these for "not applicable", e.g.
/// RenewTime on a non-renewable ticket) maps to 0.
fn filetime_to_unix(ft: i64) -> i64 {
    const EPOCH_DIFF: i64 = 11_644_473_600; // seconds between 1601 and 1970
    if ft <= 0 {
        return 0;
    }
    (ft / 10_000_000) - EPOCH_DIFF
}
