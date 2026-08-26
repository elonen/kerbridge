//! The Linux arm of [`super`]: no device grant, and no prospect of one here.
//! Part of the CI-only Linux arm -- see [`crate::os`] for what that is and is not.
//!
//! A device grant is only ever worth offering when the key behind it cannot be
//! copied off the machine: that is what makes "keep issuing tickets to this box
//! for a fortnight, with no browser" a bounded thing to authorize. Windows has
//! CNG over the TPM, macOS has the Secure Enclave. Linux has neither as anything
//! this arm could reach without a story it does not have -- a TPM is not present
//! on every machine, `/dev/tpmrm0` is not readable by an ordinary user on most
//! of the ones that do have it, and the alternative of a key in a file is
//! precisely the copyable credential the feature exists to avoid.
//!
//! So this arm reports that the machine holds no key, which is the truth, and
//! refuses to invent one. [`AVAILABLE`] being `false` is what keeps the offer
//! off every surface, so nothing gets a button that is present and doomed;
//! [`create`] is reached only if something is wired up wrongly, and it says so.
//!
//! The same shape as the macOS arm, uninhabited enum included, because it is the
//! same situation. Two arms that answer one question alike should read alike.

use anyhow::{Result, bail};

/// Nothing may offer to authorize this machine. Read where the action is
/// derived, so the button is absent rather than present and doomed.
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
    bail!("device grants are not available on Linux; sign in through the browser")
}

pub fn open() -> Result<Option<DeviceKey>> {
    Ok(None)
}

pub fn delete() -> Result<()> {
    Ok(())
}

/// What this device calls itself: `<host>\<login>`, matching the other two arms'
/// shape so one directory holds all three and an operator reads them the same
/// way -- and clamped to the same ceilings, so `issuerd`'s own limit never has to
/// bite whichever platform the record came from.
pub fn default_label() -> String {
    let clamp = |s: String, limit: usize| -> String { s.chars().take(limit).collect() };
    // `/etc/hostname` rather than the `hostname` command: the file is what the
    // command reads on a systemd machine, and it is there in a container that
    // ships no such binary. Short form, like the other two arms.
    let host = std::fs::read_to_string("/etc/hostname")
        .map(|h| h.trim().split('.').next().unwrap_or_default().to_owned())
        .unwrap_or_default();
    let user = crate::os::env("USER").or_else(|| crate::os::env("LOGNAME")).unwrap_or_default();
    format!("{}\\{}", clamp(host, 15), clamp(user, 20))
}
