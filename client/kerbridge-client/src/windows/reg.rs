//! The few registry reads and writes the helper needs, as safe functions.
//!
//! Three unrelated callers want the registry and none of them wants the FFI:
//! `config` (per-user settings, the autostart `Run` value, the HKLM policy
//! override), `enroll` (Windows' own LSA Kerberos realm state, which is the
//! ground truth for "is this machine enrolled"), and the tray's theme lookup.
//! Absent keys and values are `None`, never errors -- "not configured" is the
//! normal case for every one of them.

use std::ffi::c_void;

use anyhow::{Result, anyhow};
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE, REG_DWORD, REG_SZ,
    RRF_RT_REG_DWORD, RRF_RT_REG_MULTI_SZ, RRF_RT_REG_SZ, RegCloseKey, RegCreateKeyExW,
    RegDeleteTreeW, RegDeleteValueW, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, RegSetValueExW,
};

/// Which hive. An enum rather than a raw `HKEY` so callers never handle a
/// pointer, and so "machine policy" and "this user's preference" stay visibly
/// different things at every call site.
#[derive(Clone, Copy)]
pub enum Root {
    /// `HKLM` -- machine-wide: IT policy, and Windows' own LSA realm state.
    Machine,
    /// `HKCU` -- this user: preferences and the autostart `Run` value.
    User,
}

impl Root {
    fn hkey(self) -> HKEY {
        match self {
            Root::Machine => HKEY_LOCAL_MACHINE,
            Root::User => HKEY_CURRENT_USER,
        }
    }
}

/// UTF-16, NUL-terminated.
fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Raw `RegGetValueW` into a byte buffer, sized by the two-call idiom.
fn get_raw(root: Root, subkey: &str, value: &str, flags: u32) -> Option<Vec<u8>> {
    let hkey = root.hkey();
    let (sk, v) = (w(subkey), w(value));
    let mut size: u32 = 0;
    unsafe {
        let rc = RegGetValueW(
            hkey,
            sk.as_ptr(),
            v.as_ptr(),
            flags,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        );
        if rc != ERROR_SUCCESS || size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        let rc = RegGetValueW(
            hkey,
            sk.as_ptr(),
            v.as_ptr(),
            flags,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut c_void,
            &mut size,
        );
        (rc == ERROR_SUCCESS).then(|| {
            buf.truncate(size as usize);
            buf
        })
    }
}

/// Reinterpret a byte buffer as UTF-16 code units.
fn as_u16(bytes: &[u8]) -> Vec<u16> {
    bytes.as_chunks::<2>().0.iter().map(|&c| u16::from_le_bytes(c)).collect()
}

pub fn read_string(root: Root, subkey: &str, value: &str) -> Option<String> {
    let units = as_u16(&get_raw(root, subkey, value, RRF_RT_REG_SZ)?);
    let end = units.iter().position(|&c| c == 0).unwrap_or(units.len());
    Some(String::from_utf16_lossy(&units[..end]))
}

/// REG_MULTI_SZ → the non-empty strings in it (`KdcNames`, `SpnMappings`).
pub fn read_multi_string(root: Root, subkey: &str, value: &str) -> Option<Vec<String>> {
    let units = as_u16(&get_raw(root, subkey, value, RRF_RT_REG_MULTI_SZ)?);
    Some(units.split(|&c| c == 0).filter(|s| !s.is_empty()).map(String::from_utf16_lossy).collect())
}

pub fn read_dword(root: Root, subkey: &str, value: &str) -> Option<u32> {
    let b = get_raw(root, subkey, value, RRF_RT_REG_DWORD)?;
    (b.len() >= 4).then(|| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// True when the key itself exists, regardless of its values.
///
/// Must be an *open*, not a value read. `RegGetValueW` with a null value name
/// asks for the key's **default value**, and a key with no default value returns
/// `ERROR_FILE_NOT_FOUND` exactly like a missing key -- which is every key we care
/// about, since `ksetup` creates `…\Domains\<REALM>` with `KdcNames`/`RealmFlags`
/// and no default. Reading it that way reports every enrolled machine as
/// unenrolled.
pub fn key_exists(root: Root, subkey: &str) -> bool {
    let sk = w(subkey);
    unsafe {
        let mut key: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(root.hkey(), sk.as_ptr(), 0, KEY_READ, &mut key) != ERROR_SUCCESS {
            return false;
        }
        RegCloseKey(key);
        true
    }
}

/// The names of a key's immediate subkeys; empty for a key that is not there.
///
/// One caller: the per-adapter TCP/IP settings, which are one key per interface
/// GUID and so cannot be read without first asking what the GUIDs are.
pub fn subkeys(root: Root, subkey: &str) -> Vec<String> {
    let sk = w(subkey);
    let mut out = Vec::new();
    unsafe {
        let mut key: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(root.hkey(), sk.as_ptr(), 0, KEY_READ, &mut key) != ERROR_SUCCESS {
            return out;
        }
        // 255 characters is the documented maximum key-name length, plus the NUL.
        let mut buf = [0u16; 256];
        let mut index = 0u32;
        loop {
            let mut len = buf.len() as u32;
            let rc = RegEnumKeyExW(
                key,
                index,
                buf.as_mut_ptr(),
                &mut len,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            // ERROR_NO_MORE_ITEMS ends it; anything else is a key we cannot read,
            // and stopping is the same answer as an empty list to every caller.
            if rc != ERROR_SUCCESS {
                break;
            }
            out.push(String::from_utf16_lossy(&buf[..len as usize]));
            index += 1;
        }
        RegCloseKey(key);
    }
    out
}

pub fn write_string(root: Root, subkey: &str, value: &str, data: &str) -> Result<()> {
    let bytes = w(data);
    write_value(root, subkey, value, REG_SZ, unsafe {
        std::slice::from_raw_parts(bytes.as_ptr() as *const u8, bytes.len() * 2)
    })
}

pub fn write_dword(root: Root, subkey: &str, value: &str, data: u32) -> Result<()> {
    write_value(root, subkey, value, REG_DWORD, &data.to_le_bytes())
}

fn write_value(root: Root, subkey: &str, value: &str, kind: u32, data: &[u8]) -> Result<()> {
    let (sk, v) = (w(subkey), w(value));
    unsafe {
        let mut key: HKEY = std::ptr::null_mut();
        let rc = RegCreateKeyExW(
            root.hkey(),
            sk.as_ptr(),
            0,
            std::ptr::null(),
            0,
            KEY_SET_VALUE,
            std::ptr::null(),
            &mut key,
            std::ptr::null_mut(),
        );
        if rc != ERROR_SUCCESS {
            return Err(anyhow!("opening HKEY..\\{subkey} for write failed (error {rc})"));
        }
        let rc = RegSetValueExW(key, v.as_ptr(), 0, kind, data.as_ptr(), data.len() as u32);
        RegCloseKey(key);
        if rc != ERROR_SUCCESS {
            return Err(anyhow!("writing {subkey}\\{value} failed (error {rc})"));
        }
    }
    Ok(())
}

/// Remove a key and everything under it. A key that is already absent is success --
/// unenrollment must be idempotent, so re-running it on an already-clean machine is
/// not an error. This is the inverse of what `ksetup /addkdc` builds.
pub fn delete_tree(root: Root, subkey: &str) -> Result<()> {
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    let sk = w(subkey);
    let rc = unsafe { RegDeleteTreeW(root.hkey(), sk.as_ptr()) };
    if rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND {
        return Err(anyhow!("deleting HKEY..\\{subkey} failed (error {rc})"));
    }
    Ok(())
}

/// Remove a value. A value that is already absent is success.
pub fn delete_value(root: Root, subkey: &str, value: &str) -> Result<()> {
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    let (sk, v) = (w(subkey), w(value));
    unsafe {
        let mut key: HKEY = std::ptr::null_mut();
        let rc = RegCreateKeyExW(
            root.hkey(),
            sk.as_ptr(),
            0,
            std::ptr::null(),
            0,
            KEY_SET_VALUE,
            std::ptr::null(),
            &mut key,
            std::ptr::null_mut(),
        );
        if rc != ERROR_SUCCESS {
            return Err(anyhow!("opening HKEY..\\{subkey} for write failed (error {rc})"));
        }
        let rc = RegDeleteValueW(key, v.as_ptr());
        RegCloseKey(key);
        if rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND {
            return Err(anyhow!("deleting {subkey}\\{value} failed (error {rc})"));
        }
    }
    Ok(())
}
