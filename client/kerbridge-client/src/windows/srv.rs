//! The Windows arm of [`super`]: `DnsQuery_W`, and the registry for the suffixes
//! no API hands over.

use std::ffi::c_void;

use windows_sys::Win32::NetworkManagement::Dns::{
    DNS_QUERY_STANDARD, DNS_RECORDW, DNS_TYPE_SRV, DnsFree, DnsFreeRecordList, DnsQuery_W,
};
use windows_sys::Win32::System::SystemInformation::{ComputerNameDnsDomain, GetComputerNameExW};

use super::Srv;
use crate::reg::{self, Root};

/// Where Windows keeps the DNS suffixes, for the ones no API hands over directly.
const TCPIP: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";

/// One subkey per adapter, each holding the connection-specific suffix that
/// `ipconfig` prints. This is where a DHCP-supplied domain actually lands; the
/// global `DhcpDomain` above is set only for whichever adapter Windows considered
/// primary, and on a machine with a VPN, a hypervisor switch or WSL it is
/// routinely absent.
const INTERFACES: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";

/// The DNS domains this machine is actually in: the primary suffix, the global
/// DHCP domain, every adapter's connection-specific suffix, then the resolver
/// search list.
///
/// The per-adapter keys matter more than their position here suggests. A machine
/// that is not AD-joined has no primary suffix at all -- `GetComputerNameExW` is
/// empty, and a DHCP-supplied suffix does not set it -- which is every KerBridge
/// client, since the whole point is that nothing is joined to the realm.
pub fn own_domains() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    out.extend(primary_dns_suffix());
    out.extend(reg::read_string(Root::Machine, TCPIP, "DhcpDomain"));
    for adapter in reg::subkeys(Root::Machine, INTERFACES) {
        let key = format!(r"{INTERFACES}\{adapter}");
        out.extend(reg::read_string(Root::Machine, &key, "Domain"));
        out.extend(reg::read_string(Root::Machine, &key, "DhcpDomain"));
    }
    out.extend(reg::read_string(Root::Machine, TCPIP, "SearchList"));
    out
}

fn primary_dns_suffix() -> Option<String> {
    let mut len: u32 = 0;
    // First call sizes the buffer; it fails with ERROR_MORE_DATA by design.
    unsafe { GetComputerNameExW(ComputerNameDnsDomain, std::ptr::null_mut(), &mut len) };
    if len == 0 {
        return None;
    }
    let mut buf = vec![0u16; len as usize];
    let ok = unsafe { GetComputerNameExW(ComputerNameDnsDomain, buf.as_mut_ptr(), &mut len) };
    (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
}

/// One SRV query. Anything other than a successful answer -- NXDOMAIN, no
/// resolver, a timeout -- is an empty result: this is a lookup that is *expected*
/// to find nothing on most networks.
pub fn lookup_srv(name: &str) -> Vec<Srv> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut head: *mut DNS_RECORDW = std::ptr::null_mut();
    let rc = unsafe {
        DnsQuery_W(
            wide.as_ptr(),
            DNS_TYPE_SRV,
            DNS_QUERY_STANDARD,
            std::ptr::null_mut(),
            (&mut head as *mut *mut DNS_RECORDW).cast(),
            std::ptr::null_mut(),
        )
    };
    if rc != 0 || head.is_null() {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        let record = unsafe { &*cur };
        // The answer can carry the additional section too (the target's A
        // records), so the type has to be checked rather than assumed.
        if record.wType == DNS_TYPE_SRV {
            let srv = unsafe { record.Data.Srv };
            out.push(Srv {
                target: unsafe { from_wide(srv.pNameTarget) },
                port: srv.wPort,
                priority: srv.wPriority,
                weight: srv.wWeight,
            });
        }
        cur = record.pNext;
    }
    unsafe { DnsFree(head.cast::<c_void>(), DnsFreeRecordList) };
    out
}

/// # Safety
/// `p` must be a NUL-terminated UTF-16 string owned by the caller's record list.
unsafe fn from_wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0;
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}
