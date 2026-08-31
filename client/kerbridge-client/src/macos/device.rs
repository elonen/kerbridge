//! The macOS arm of [`super`]: no device grant yet.
//!
//! The Secure Enclave is the counterpart of the TPM the Windows arm uses. A P-256
//! key in it is non-exportable in the same way. It needs no entitlement and no
//! Developer ID. A transient key persists as the Enclave-wrapped blob that the key
//! carries. The broker's own verifier accepts what it signs. Measured on two Macs:
//! research spike `device-grant-enclave-key`.
//!
//! Signing gates the user boundary, not the key. The Enclave imposes no user
//! boundary of its own. Any local account that can read a stored blob can use the
//! key it names. A file mode is the only barrier.
//!
//! This arm is not written yet, so it reports that the machine holds no key.
//!
//! [`open`] returning `None` is the ordinary answer, not an error: it is exactly
//! what a Windows machine that has never been authorized reports, and every
//! caller already handles it. Nothing offers to create a grant on macOS, so
//! [`create`] is reached only if something is wired up wrongly, and it says so.

use anyhow::{Result, bail};

/// Nothing may offer to authorize this machine. Read where the action is
/// derived, so the button is absent rather than present and doomed: without it a
/// Mac talking to a grants-enabled broker offers *Authorize access…* and answers
/// the click with [`create`]'s refusal.
pub const AVAILABLE: bool = false;

/// No key can exist on this arm, so neither can a handle to one. Uninhabited
/// rather than a unit struct: the methods below are then unreachable by
/// construction instead of by convention.
pub enum DeviceKey {}

impl DeviceKey {
    pub fn public_point(&self) -> Result<Vec<u8>> {
        match *self {}
    }

    pub fn sign(&self, _message: &[u8]) -> Result<Vec<u8>> {
        match *self {}
    }
}

pub fn create() -> Result<DeviceKey> {
    bail!("device grants are not available on macOS yet; sign in through the browser")
}

pub fn open() -> Result<Option<DeviceKey>> {
    Ok(None)
}

pub fn delete() -> Result<()> {
    Ok(())
}

/// What this device calls itself: `<host>\<login>`, matching the Windows arm's
/// shape so one directory holds both and an operator reads them the same way.
pub fn default_label() -> String {
    let clamp = |s: String, limit: usize| -> String { s.chars().take(limit).collect() };
    let host = std::process::Command::new("/bin/hostname")
        .arg("-s")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    // The same ceilings the Windows arm clamps to, so `issuerd`'s own limit
    // never has to bite whichever platform the record came from.
    format!("{}\\{}", clamp(host, 15), clamp(std::env::var("USER").unwrap_or_default(), 20))
}
