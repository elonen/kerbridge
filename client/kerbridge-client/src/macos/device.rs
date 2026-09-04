//! macOS device key: a Secure Enclave P-256 key persisted as a `0600` wrapped blob.
//!
//! The Enclave stores no transient key across boot. `kSecAttrTokenOID` persists a
//! Mac-bound wrapped key outside Keychain, without an entitlement or Developer ID.
//! Measured on two Macs (research spike `device-grant-enclave-key`).
//!
//! Only signing proves a blob belongs to this Enclave; its public point is clear
//! text.
//!
//! **File mode is the user boundary.** Any local account can use a readable blob.
//! [`delete`] unlinks only this copy.
//!
//! **No usable Enclave.** [`AVAILABLE`] remains `true` so grants-enabled
//! deployments offer authorization. Unsupported hardware is untested.

use std::ffi::c_void;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use core_foundation_sys::base::{
    Boolean, CFAllocatorRef, CFIndex, CFOptionFlags, CFTypeRef, kCFAllocatorDefault,
};
use core_foundation_sys::data::{CFDataCreate, CFDataGetBytePtr, CFDataGetLength, CFDataRef};
use core_foundation_sys::dictionary::{
    CFDictionaryCreate, CFDictionaryGetValue, CFDictionaryRef, kCFTypeDictionaryKeyCallBacks,
    kCFTypeDictionaryValueCallBacks,
};
use core_foundation_sys::error::{CFErrorCopyDescription, CFErrorGetCode, CFErrorRef};
use core_foundation_sys::number::{CFNumberCreate, kCFBooleanFalse, kCFNumberSInt32Type};
use core_foundation_sys::string::CFStringRef;

use crate::cf::{self, Owned};

/// macOS supports device grants.
pub const AVAILABLE: bool = true;

/// Wrapped key beside `config.toml`. One grant per installation.
const BLOB_FILE: &str = "device-grant.key";

/// A P-256 coordinate, and half a fixed-form signature.
const COORD: usize = 32;

/// An uncompressed point: `0x04 || X || Y`.
const POINT: usize = 1 + 2 * COORD;

/// Signing this value proves that this Enclave can use the private scalar;
/// importing a foreign blob does not.
const PROOF: &[u8] = b"kerbridge device key self-test";

/// Private-key usage without user presence or biometry; grants must work
/// unattended. This `CF_OPTIONS` member has no exported symbol.
const PRIVATE_KEY_USAGE: CFOptionFlags = 1 << 30;

/// Private `kSecAttrTokenOID` attribute `toid` stores the wrapped key. Inline its
/// `SecItemPriv.h` value to avoid private-API linkage.
const TOKEN_OID: &str = "toid";

type SecKeyRef = *const c_void;
type SecAccessControlRef = *const c_void;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecAttrKeyType: CFStringRef;
    static kSecAttrKeyTypeECSECPrimeRandom: CFStringRef;
    static kSecAttrKeySizeInBits: CFStringRef;
    static kSecAttrKeyClass: CFStringRef;
    static kSecAttrKeyClassPrivate: CFStringRef;
    static kSecAttrKeyClassPublic: CFStringRef;
    static kSecAttrTokenID: CFStringRef;
    static kSecAttrTokenIDSecureEnclave: CFStringRef;
    static kSecPrivateKeyAttrs: CFStringRef;
    static kSecAttrIsPermanent: CFStringRef;
    static kSecAttrAccessControl: CFStringRef;
    static kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly: CFStringRef;
    /// The fixed 64-byte `r || s` form `ring`'s `ECDSA_P256_SHA256_FIXED`
    /// verifies. Not the X9.62 variant, which returns DER.
    static kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA256: CFStringRef;

    fn SecAccessControlCreateWithFlags(
        allocator: CFAllocatorRef,
        protection: CFTypeRef,
        flags: CFOptionFlags,
        error: *mut CFErrorRef,
    ) -> SecAccessControlRef;
    fn SecKeyCreateRandomKey(parameters: CFDictionaryRef, error: *mut CFErrorRef) -> SecKeyRef;
    fn SecKeyCreateWithData(
        data: CFDataRef,
        attributes: CFDictionaryRef,
        error: *mut CFErrorRef,
    ) -> SecKeyRef;
    fn SecKeyCopyAttributes(key: SecKeyRef) -> CFDictionaryRef;
    fn SecKeyCopyPublicKey(key: SecKeyRef) -> SecKeyRef;
    fn SecKeyCopyExternalRepresentation(key: SecKeyRef, error: *mut CFErrorRef) -> CFDataRef;
    fn SecKeyCreateSignature(
        key: SecKeyRef,
        algorithm: CFStringRef,
        data: CFDataRef,
        error: *mut CFErrorRef,
    ) -> CFDataRef;
    fn SecKeyVerifySignature(
        key: SecKeyRef,
        algorithm: CFStringRef,
        signed_data: CFDataRef,
        signature: CFDataRef,
        error: *mut CFErrorRef,
    ) -> Boolean;
}

/// An open handle to the device key. The Enclave holds the scalar; this is a
/// `SecKey` naming it.
pub struct DeviceKey(Owned);

impl DeviceKey {
    /// The public key as a raw uncompressed point, `0x04 || X || Y`.
    ///
    /// Security.framework returns the raw 65-byte point. Reject another form before
    /// registration.
    pub fn public_point(&self) -> Result<Vec<u8>> {
        let public = Owned::adopt(unsafe { SecKeyCopyPublicKey(self.0.as_ref()) })
            .context("reading the device key's public half")?;
        let mut err: CFErrorRef = std::ptr::null_mut();
        let exported =
            Owned::adopt(unsafe { SecKeyCopyExternalRepresentation(public.as_ref(), &mut err) })
                .ok_or_else(|| sec_error(err, "exporting the public key"))?;
        // SAFETY: a live `CFData` this call owns.
        let point = unsafe { bytes(exported.as_ref()) };
        if point.len() != POINT || point[0] != 0x04 {
            bail!("public key is {} bytes, expected {POINT} of uncompressed point", point.len());
        }
        Ok(point)
    }

    /// Sign a SHA-256 digest with ECDSA P-256; return fixed `r || s`. [`open`]
    /// owns cleanup because signing refusal can be transient.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(message);
        let digest = data(&hash).context("wrapping the digest")?;
        let mut err: CFErrorRef = std::ptr::null_mut();
        // SAFETY: framework constant, live for the process.
        let algorithm = unsafe { kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA256 };
        let signature = Owned::adopt(unsafe {
            SecKeyCreateSignature(self.0.as_ref(), algorithm, digest.as_ref(), &mut err)
        })
        .ok_or_else(|| sec_error(err, "signing with the device key"))?;
        // SAFETY: a live `CFData` this call owns.
        let signature = unsafe { bytes(signature.as_ref()) };
        if signature.len() != 2 * COORD {
            bail!(
                "device key produced a {}-byte signature, expected {}",
                signature.len(),
                2 * COORD
            );
        }
        Ok(signature)
    }

    /// Sign [`PROOF`] and verify it with this key's public point.
    ///
    /// Import and a matching public point do not prove that this Enclave can use
    /// the key because the blob stores the point in clear text.
    fn self_test(&self) -> Result<()> {
        let signature = self.sign(PROOF)?;
        verify(&self.public_point()?, PROOF, &signature)
    }
}

/// Create and verify the stored wrapped key before registration. Otherwise a
/// grant can fail after restart.
pub fn create() -> Result<DeviceKey> {
    create_at(&blob_path()?)
}

fn create_at(path: &Path) -> Result<DeviceKey> {
    let key = DeviceKey(new_enclave_key()?);
    let point = key.public_point()?;
    write_blob(path, &wrapped_blob(&key.0)?)?;
    if let Err(e) = stored_key_matches(path, &point) {
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(key)
}

/// Open the device key. Return `None` if no key is available.
///
/// Unlink the blob only after a Security.framework refusal. Preserve it for other
/// failures. Imported keys are test-signed.
pub fn open() -> Result<Option<DeviceKey>> {
    let Ok(path) = blob_path() else {
        return Ok(None);
    };
    open_at(&path)
}

fn open_at(path: &Path) -> Result<Option<DeviceKey>> {
    let Ok(blob) = std::fs::read(path) else {
        return Ok(None);
    };
    match import(&blob).map(DeviceKey).and_then(|key| key.self_test().map(|()| key)) {
        Ok(key) => Ok(Some(key)),
        Err(why) if refused(&why) => {
            crate::log::warn(&format!(
                "this Mac's Secure Enclave will not use the stored device key, so {} is \
                 removed and the next sign-in goes through the browser: {why:#}",
                path.display()
            ));
            let _ = std::fs::remove_file(path);
            Ok(None)
        }
        Err(why) => {
            crate::log::warn(&format!("the stored device key could not be checked: {why:#}"));
            Ok(None)
        }
    }
}

fn refused(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.is::<Refusal>())
}

/// Unlink the local wrapped blob; copies remain usable on this Mac.
pub fn delete() -> Result<()> {
    let path = blob_path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).context(format!("deleting {}", path.display())),
    }
}

pub fn default_label() -> String {
    let host = std::process::Command::new("/bin/hostname")
        .arg("-s")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    label(&host, &std::env::var("USER").unwrap_or_default())
}

fn label(host: &str, user: &str) -> String {
    let clamp = |s: &str, limit: usize| -> String { s.chars().take(limit).collect() };
    // Match Windows: 15-character host and 20-character account.
    format!("{}\\{}", clamp(host, 15), clamp(user, 20))
}

fn blob_path() -> Result<PathBuf> {
    Ok(crate::config::app_dir().context("this account has no home directory")?.join(BLOB_FILE))
}

/// `kSecAttrIsPermanent: false` avoids the Keychain entitlement. The protection
/// class only satisfies the transient-key API.
fn new_enclave_key() -> Result<Owned> {
    let mut err: CFErrorRef = std::ptr::null_mut();
    // SAFETY: framework constants, live for the process.
    let access = Owned::adopt(unsafe {
        SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as CFTypeRef,
            PRIVATE_KEY_USAGE,
            &mut err,
        )
    })
    .ok_or_else(|| sec_error(err, "creating the key's access control"))?;

    let bits: i32 = 8 * COORD as i32;
    let bits = Owned::adopt(unsafe {
        CFNumberCreate(
            kCFAllocatorDefault,
            kCFNumberSInt32Type,
            &bits as *const i32 as *const c_void,
        )
    })
    .context("wrapping the key size")?;

    // SAFETY: framework constants, live for the process.
    let params = unsafe {
        let private = dict(&[
            (kSecAttrIsPermanent, kCFBooleanFalse as CFTypeRef),
            (kSecAttrAccessControl, access.as_ref()),
        ])
        .context("building the private-key attributes")?;
        dict(&[
            (kSecAttrTokenID, kSecAttrTokenIDSecureEnclave as CFTypeRef),
            (kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom as CFTypeRef),
            (kSecAttrKeySizeInBits, bits.as_ref()),
            (kSecPrivateKeyAttrs, private.as_ref()),
        ])
        .context("building the key parameters")?
    };

    let mut err: CFErrorRef = std::ptr::null_mut();
    Owned::adopt(unsafe { SecKeyCreateRandomKey(params.as_ref(), &mut err) })
        .ok_or_else(|| sec_error(err, "creating the Secure Enclave key"))
        .context("this machine has no usable hardware key store")
}

fn wrapped_blob(key: &Owned) -> Result<Vec<u8>> {
    let oid = cf::string(TOKEN_OID).context("naming the wrapped-key attribute")?;
    let attributes = Owned::adopt(unsafe { SecKeyCopyAttributes(key.as_ref()) })
        .context("reading the key's attributes")?;
    let blob = unsafe { CFDictionaryGetValue(attributes.as_ref(), oid.as_ref()) } as CFDataRef;
    if blob.is_null() {
        bail!("the Secure Enclave key carries no wrapped-key blob");
    }
    // SAFETY: a live `CFData` the attribute dictionary owns, and it outlives this.
    Ok(unsafe { bytes(blob) })
}

/// Import a wrapped blob through `kSecAttrTokenOID` with empty key data. Using it
/// as key data silently creates a new key.
fn import(blob: &[u8]) -> Result<Owned> {
    let oid = cf::string(TOKEN_OID).context("naming the wrapped-key attribute")?;
    let blob = data(blob).context("wrapping the stored blob")?;
    let empty = data(&[]).context("building the empty key data")?;
    // SAFETY: framework constants, live for the process.
    let attributes = unsafe {
        dict(&[
            (kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom as CFTypeRef),
            (kSecAttrKeyClass, kSecAttrKeyClassPrivate as CFTypeRef),
            (kSecAttrTokenID, kSecAttrTokenIDSecureEnclave as CFTypeRef),
            (oid.as_ref(), blob.as_ref()),
        ])
        .context("building the import attributes")?
    };
    let mut err: CFErrorRef = std::ptr::null_mut();
    Owned::adopt(unsafe { SecKeyCreateWithData(empty.as_ref(), attributes.as_ref(), &mut err) })
        .ok_or_else(|| sec_error(err, "importing the stored key"))
}

/// Verify the fixed-form signature against a raw point with the Enclave-free path
/// that matches broker `ring`.
fn verify(point: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    use sha2::{Digest, Sha256};
    let point = data(point).context("wrapping the public point")?;
    // SAFETY: framework constants, live for the process.
    let attributes = unsafe {
        dict(&[
            (kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom as CFTypeRef),
            (kSecAttrKeyClass, kSecAttrKeyClassPublic as CFTypeRef),
        ])
        .context("building the public-key attributes")?
    };
    let mut err: CFErrorRef = std::ptr::null_mut();
    let public = Owned::adopt(unsafe {
        SecKeyCreateWithData(point.as_ref(), attributes.as_ref(), &mut err)
    })
    .ok_or_else(|| sec_error(err, "reading back the public key"))?;

    let hash = Sha256::digest(message);
    let digest = data(&hash).context("wrapping the digest")?;
    let signature = data(signature).context("wrapping the signature")?;
    let mut err: CFErrorRef = std::ptr::null_mut();
    // SAFETY: framework constant, live for the process.
    let algorithm = unsafe { kSecKeyAlgorithmECDSASignatureDigestRFC4754SHA256 };
    let ok = unsafe {
        SecKeyVerifySignature(
            public.as_ref(),
            algorithm,
            digest.as_ref(),
            signature.as_ref(),
            &mut err,
        )
    };
    if ok == 0 {
        return Err(sec_error(err, "verifying the device key's own signature"));
    }
    Ok(())
}

fn stored_key_matches(path: &Path, point: &[u8]) -> Result<()> {
    let blob = std::fs::read(path).context("reading back the key file just written")?;
    let stored = DeviceKey(import(&blob).context("the stored key could not be re-imported")?);
    if stored.public_point()? != point {
        bail!("the stored key is not the key just created");
    }
    stored.self_test().context("the stored key could not sign")
}

/// Write the blob at `0600` through a temporary file and rename. Set the mode
/// before writing; `chmod` after creation can expose the credential.
fn write_blob(path: &Path, blob: &[u8]) -> Result<()> {
    let dir = path.parent().context("the key file has no directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let tmp = path.with_extension("new");
    let _ = std::fs::remove_file(&tmp);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    file.write_all(blob).and_then(|()| file.sync_all()).context("writing the device key")?;
    drop(file);
    std::fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))
}

fn data(b: &[u8]) -> Option<Owned> {
    Owned::adopt(unsafe { CFDataCreate(kCFAllocatorDefault, b.as_ptr(), b.len() as CFIndex) })
}

/// A `CFData`'s contents.
///
/// # Safety
/// `d` must be a live `CFData`.
unsafe fn bytes(d: CFDataRef) -> Vec<u8> {
    unsafe {
        let len = CFDataGetLength(d) as usize;
        std::slice::from_raw_parts(CFDataGetBytePtr(d), len).to_vec()
    }
}

/// Create a `CFDictionary` that retains keys and values.
fn dict(pairs: &[(CFStringRef, CFTypeRef)]) -> Option<Owned> {
    let keys: Vec<*const c_void> = pairs.iter().map(|(k, _)| *k as *const c_void).collect();
    let values: Vec<*const c_void> = pairs.iter().map(|(_, v)| *v).collect();
    Owned::adopt(unsafe {
        CFDictionaryCreate(
            kCFAllocatorDefault,
            keys.as_ptr(),
            values.as_ptr(),
            pairs.len() as CFIndex,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        )
    })
}

/// A Security.framework refusal. Only this permits [`open_at`] to unlink the
/// blob.
#[derive(Debug)]
struct Refusal(String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refusal {}

/// Do not interpret CryptoTokenKit error codes: `-3` covers foreign blobs,
/// selectors, and corruption.
fn sec_error(err: CFErrorRef, what: &str) -> anyhow::Error {
    let Some(owned) = Owned::adopt(err) else {
        return anyhow::Error::new(Refusal(format!("{what} failed")));
    };
    let err: CFErrorRef = owned.as_mut();
    let code = unsafe { CFErrorGetCode(err) };
    let described = Owned::adopt(unsafe { CFErrorCopyDescription(err) })
        // SAFETY: a live `CFString` this call owns.
        .and_then(|d| unsafe { cf::to_string(d.as_ref()) });
    anyhow::Error::new(Refusal(match described {
        Some(text) => format!("{what} failed ({code}: {text})"),
        None => format!("{what} failed ({code})"),
    }))
}

#[cfg(test)]
const MODE: u32 = 0o600;

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    /// Use a private temporary directory: native tests can run with a live device
    /// grant.
    fn scratch() -> tempfile::TempDir {
        tempfile::tempdir().expect("a temporary directory")
    }

    /// Key-data import silently creates a new key; attribute import retains the
    /// point.
    #[test]
    fn a_stored_key_re_imports_as_the_same_key() {
        let dir = scratch();
        let path = dir.path().join(BLOB_FILE);
        let key = create_at(&path).expect("a Secure Enclave key");
        let point = key.public_point().unwrap();
        assert_eq!(point.len(), POINT);

        let reopened = open_at(&path).unwrap().expect("the stored key");
        assert_eq!(reopened.public_point().unwrap(), point);
    }

    /// Verify the fixed signature form accepted by broker `ring`.
    #[test]
    fn a_stored_key_signs_what_its_public_point_verifies() {
        let dir = scratch();
        let path = dir.path().join(BLOB_FILE);
        let key = create_at(&path).expect("a Secure Enclave key");

        let signature = key.sign(b"a message").unwrap();
        assert_eq!(signature.len(), 2 * COORD);
        verify(&key.public_point().unwrap(), b"a message", &signature).expect("it verifies");
        assert!(verify(&key.public_point().unwrap(), b"another message", &signature).is_err());
    }

    /// A refused blob is removed.
    #[test]
    fn a_corrupted_blob_is_refused_and_removed() {
        let dir = scratch();
        let path = dir.path().join(BLOB_FILE);
        create_at(&path).expect("a Secure Enclave key");

        let mut blob = std::fs::read(&path).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        std::fs::write(&path, &blob).unwrap();

        assert!(open_at(&path).unwrap().is_none());
        assert!(!path.exists(), "a blob that cannot sign is not left behind");
    }

    #[test]
    fn no_file_means_no_key() {
        let dir = scratch();
        assert!(open_at(&dir.path().join(BLOB_FILE)).unwrap().is_none());
    }

    /// Set mode to `0600` at creation; `chmod` after can expose the credential.
    #[test]
    fn the_blob_is_created_unreadable_to_other_accounts() {
        let dir = scratch();
        let path = dir.path().join(BLOB_FILE);
        write_blob(&path, b"not a real blob").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, MODE, "{mode:o}");
        write_blob(&path, b"nor is this").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"nor is this");
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, MODE);
    }

    #[test]
    fn the_default_label_is_clamped() {
        let long = label(&"A".repeat(200), &"b".repeat(200));
        assert_eq!(long, format!("{}\\{}", "A".repeat(15), "b".repeat(20)));
        // The platform label is at most 36 characters; `issuerd` separately limits
        // escaped bytes.
        assert!(long.chars().count() <= 36, "{long}");
        assert!(default_label().contains('\\'));
    }
}
