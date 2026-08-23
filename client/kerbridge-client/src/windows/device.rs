//! The Windows arm of [`super`]: a non-exportable ECDSA P-256 key in this
//! machine's TPM, through CNG.
//!
//! **`MS_PLATFORM_CRYPTO_PROVIDER`** is the TPM-backed provider. Nothing here
//! attests that it really was a TPM, and the server deliberately does not try to
//! tell: attestation would need a verification chain rooted in TPM vendor EK
//! certificates, and it would cost the property that the entire server side is
//! testable with a software key. What bounds the residual risk instead is the
//! grant's duration and the group that gates who may create one.
//!
//! **User scope** -- no `NCRYPT_MACHINE_KEY_FLAG` -- so creating one needs no
//! elevation and the key dies with the profile.
//!
//! The private key never leaves the provider: it is created with an export
//! policy of nothing, so even this process cannot read it out.

use anyhow::{Context, Result, anyhow, bail};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ECCPUBLIC_BLOB, BCRYPT_ECDSA_P256_ALGORITHM, MS_PLATFORM_CRYPTO_PROVIDER,
    NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_KEY_HANDLE, NCRYPT_PROV_HANDLE, NCryptCreatePersistedKey,
    NCryptDeleteKey, NCryptExportKey, NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey,
    NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash,
};

/// This platform can hold a grant, so a grants-enabled deployment may offer one.
pub const AVAILABLE: bool = true;

/// A P-256 coordinate, and half a fixed-form signature.
const COORD: usize = 32;

/// The key container name. One per install, because the tray is single-account
/// and single-broker by design; a second grant on this machine would be a second
/// installation.
const CONTAINER: &str = "KerBridge device grant";

/// An open handle to the device key, with its provider.
pub struct DeviceKey {
    provider: NCRYPT_PROV_HANDLE,
    key: NCRYPT_KEY_HANDLE,
}

impl Drop for DeviceKey {
    fn drop(&mut self) {
        unsafe {
            if self.key != 0 {
                NCryptFreeObject(self.key);
            }
            NCryptFreeObject(self.provider);
        }
    }
}

/// NUL-terminated UTF-16, for the CNG string arguments.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// CNG returns an `HRESULT`-shaped `SECURITY_STATUS`; anything non-zero failed.
fn check(status: i32, what: &str) -> Result<()> {
    if status == 0 {
        return Ok(());
    }
    bail!("{what} failed (0x{:08x})", status as u32)
}

fn open_provider() -> Result<NCRYPT_PROV_HANDLE> {
    let mut provider: NCRYPT_PROV_HANDLE = 0;
    // The one call that fails on a machine with no usable TPM, which is why the
    // tray offers the button unconditionally and reports here: a TPM can be
    // absent, unprepared, locked out or blocked by policy, and all four are the
    // same answer to the person who just clicked.
    check(
        unsafe { NCryptOpenStorageProvider(&mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) },
        "opening the platform crypto provider",
    )
    .context(
        "this machine has no usable TPM-backed key store. A TPM that is absent, not prepared, \
         locked out, or blocked by policy all look like this",
    )?;
    Ok(provider)
}

/// Create the device key, replacing any key already in the container.
///
/// The pre-delete is required and not defensive: `NCryptCreatePersistedKey` on
/// an occupied container fails with `NTE_EXISTS`, measured on a firmware TPM
/// (research spike `device-grant-tpm-key`). It also leaves the path
/// idempotent after a failure that created a key and never registered it.
///
/// Whether to make a new key at all is the caller's decision, not this one's:
/// `session::create_grant` opens the key already here when there is one, so that
/// re-authorizing replaces a row on the account instead of orphaning it.
pub fn create() -> Result<DeviceKey> {
    // Best-effort, and its failure is not this call's failure: there may be no
    // key to delete, which is the common case.
    let _ = delete();

    let provider = open_provider()?;
    let mut key: NCRYPT_KEY_HANDLE = 0;
    let container = wide(CONTAINER);
    let created = unsafe {
        NCryptCreatePersistedKey(
            provider,
            &mut key,
            BCRYPT_ECDSA_P256_ALGORITHM,
            container.as_ptr(),
            // No legacy key spec, and **no `NCRYPT_MACHINE_KEY_FLAG`**: user
            // scope is what keeps this off the UAC path and ties the key's life
            // to the profile.
            0,
            0,
        )
    };
    if created != 0 {
        unsafe { NCryptFreeObject(provider) };
        check(created, "creating the device key")?;
    }
    let this = DeviceKey { provider, key };

    // Export policy of nothing, set before finalize so it is part of the key
    // rather than a property of this handle. The TPM would refuse to export the
    // private key anyway; this is what makes the same code refuse it when the
    // provider underneath is a software one.
    let policy = 0u32.to_le_bytes();
    check(
        unsafe {
            NCryptSetProperty(
                this.key,
                NCRYPT_EXPORT_POLICY_PROPERTY,
                policy.as_ptr(),
                policy.len() as u32,
                0,
            )
        },
        "setting the export policy",
    )?;
    check(unsafe { NCryptFinalizeKey(this.key, 0) }, "finalizing the device key")?;
    Ok(this)
}

/// Open the existing device key, or `None` if this machine holds none.
pub fn open() -> Result<Option<DeviceKey>> {
    let provider = open_provider()?;
    let mut key: NCRYPT_KEY_HANDLE = 0;
    let container = wide(CONTAINER);
    let status = unsafe { NCryptOpenKey(provider, &mut key, container.as_ptr(), 0, 0) };
    if status != 0 {
        unsafe { NCryptFreeObject(provider) };
        // Every failure here reads as "no key": the container is gone, the
        // profile was rebuilt, the TPM was cleared. The caller's answer to all
        // of them is to sign in through the browser again.
        return Ok(None);
    }
    Ok(Some(DeviceKey { provider, key }))
}

/// Destroy the device key.
///
/// Unconditional and local: it works offline and kills the grant on this machine
/// whatever the directory says. Sign-out calls this *before* it tries to tell the
/// broker, so a failed self-revocation leaves a directory entry that is stale but
/// dead -- the key it names no longer exists.
pub fn delete() -> Result<()> {
    let Some(mut held) = open()? else {
        return Ok(());
    };
    let key = std::mem::replace(&mut held.key, 0);
    check(unsafe { NCryptDeleteKey(key, 0) }, "deleting the device key")
}

impl DeviceKey {
    /// The public key as a raw uncompressed point, `0x04 || X || Y`.
    ///
    /// Not SPKI: this is the form CNG hands out and the form `ring` verifies
    /// against, so no DER encoding sits between the two ends to disagree about.
    pub fn public_point(&self) -> Result<Vec<u8>> {
        let mut needed = 0u32;
        check(
            unsafe {
                NCryptExportKey(
                    self.key,
                    0,
                    BCRYPT_ECCPUBLIC_BLOB,
                    null(),
                    null_mut(),
                    0,
                    &mut needed,
                    0,
                )
            },
            "sizing the public key blob",
        )?;
        let mut blob = vec![0u8; needed as usize];
        check(
            unsafe {
                NCryptExportKey(
                    self.key,
                    0,
                    BCRYPT_ECCPUBLIC_BLOB,
                    null(),
                    blob.as_mut_ptr(),
                    needed,
                    &mut needed,
                    0,
                )
            },
            "exporting the public key",
        )?;
        point_from_ecc_blob(&blob)
    }

    /// Sign a message: SHA-256, then ECDSA P-256, returning the fixed `r || s`
    /// form the broker verifies.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(message);
        let mut signature = vec![0u8; 2 * COORD];
        let mut written = 0u32;
        check(
            unsafe {
                NCryptSignHash(
                    self.key,
                    null(),
                    hash.as_ptr(),
                    hash.len() as u32,
                    signature.as_mut_ptr(),
                    signature.len() as u32,
                    &mut written,
                    0,
                )
            },
            "signing with the device key",
        )?;
        if written as usize != signature.len() {
            bail!("device key produced a {written}-byte signature, expected {}", signature.len());
        }
        Ok(signature)
    }
}

/// Pull `X || Y` out of a `BCRYPT_ECCKEY_BLOB` and prepend the uncompressed tag.
///
/// The blob is a fixed 8-byte header -- a magic and the coordinate length -- then
/// the two coordinates. Parsed rather than assumed, because a provider that
/// answered with a different curve would otherwise produce a point that verifies
/// against nothing, and the failure would surface as an unexplained 401 days
/// later.
fn point_from_ecc_blob(blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 8 {
        bail!("public key blob is {} bytes, shorter than its own header", blob.len());
    }
    let cb_key = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
    if cb_key != COORD {
        bail!("public key has {cb_key}-byte coordinates, expected {COORD} (P-256)");
    }
    let body = blob.get(8..8 + 2 * COORD).ok_or_else(|| {
        anyhow!("public key blob is {} bytes, too short for two coordinates", blob.len())
    })?;
    Ok(std::iter::once(0x04).chain(body.iter().copied()).collect())
}

/// What this device calls itself: `<computer>\<local-account>`.
///
/// The user's own name is deliberately absent -- the record hangs off their
/// directory object, so it would be redundant -- and the machine plus the local
/// account it ran as are what actually distinguish `BUILD01\unreal-builder` from
/// `BUILD01\jarno`. Each component is clamped to the limit Windows already
/// enforces on it, so the escaped label cannot approach the directory's
/// per-value ceiling.
pub fn default_label() -> String {
    let clamp = |var: &str, limit: usize| -> String {
        std::env::var(var).unwrap_or_default().chars().take(limit).collect()
    };
    // NetBIOS names are at most 15 characters, local account names at most 20.
    format!("{}\\{}", clamp("COMPUTERNAME", 15), clamp("USERNAME", 20))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The blob layout, which is the one place a silent provider change would
    /// produce a key that verifies against nothing.
    #[test]
    fn a_p256_blob_becomes_an_uncompressed_point() {
        let mut blob = vec![0u8; 8];
        blob[4..8].copy_from_slice(&(COORD as u32).to_le_bytes());
        blob.extend(0..COORD as u8); // X
        blob.extend((0..COORD as u8).map(|b| b.wrapping_add(100))); // Y
        let point = point_from_ecc_blob(&blob).unwrap();
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 0x04);
        assert_eq!(&point[1..33], &blob[8..40]);
        assert_eq!(&point[33..], &blob[40..]);
    }

    #[test]
    fn a_blob_that_is_not_p256_is_refused_rather_than_truncated() {
        let mut p384 = vec![0u8; 8 + 96];
        p384[4..8].copy_from_slice(&48u32.to_le_bytes());
        assert!(point_from_ecc_blob(&p384).is_err());
        let mut truncated = vec![0u8; 8 + 40];
        truncated[4..8].copy_from_slice(&(COORD as u32).to_le_bytes());
        assert!(point_from_ecc_blob(&truncated).is_err());
        assert!(point_from_ecc_blob(&[0u8; 4]).is_err());
    }

    /// Both halves are already bounded by Windows, so the label can never reach
    /// the directory's per-value ceiling however hostile the environment is.
    #[test]
    fn the_default_label_is_clamped_to_what_windows_allows() {
        // SAFETY: single-threaded test, and the variables are read back at once.
        unsafe {
            std::env::set_var("COMPUTERNAME", "A".repeat(200));
            std::env::set_var("USERNAME", "b".repeat(200));
        }
        let label = default_label();
        assert_eq!(label, format!("{}\\{}", "A".repeat(15), "b".repeat(20)));
        // 36 characters at most, so `issuerd`'s own clamp never has to bite and
        // the escaped value stays far inside the directory's 255-byte ceiling.
        assert!(label.len() <= 36, "{label}");
    }
}
