//! The macOS arm of [`super`]: no device grant yet.
//!
//! The Secure Enclave is the counterpart of the TPM the Windows arm uses, and a
//! P-256 key in it would be non-exportable in the same way. What is not yet
//! settled is everything around it: an Enclave key needs the app to be signed
//! with a keychain-access-group entitlement, which means the signing and
//! notarization story has to exist first. Until it does, this arm reports that
//! the machine holds no key -- which is the truth -- and refuses to invent one.
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
