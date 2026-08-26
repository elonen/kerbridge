//! Linux has no boundary to cross for anything this client does. Part of the
//! CI-only Linux arm -- see [`crate::os`] for what that is and is not.
//!
//! There is no realm to register with the OS (`enroll.rs`), and no redirector to
//! restart (`repair.rs`), so nothing here ever asks for privilege. That leaves
//! [`is_elevated`] as a plain fact about the process and [`run_elevated`] with
//! nothing to raise -- reported as [`Elevated::Unavailable`], which already means
//! "this machine cannot elevate" and is the truth rather than a failure. `sudo`
//! is deliberately not reached for: it is interactive, it is not present on
//! every machine, and no caller here has anything for it to run.

use anyhow::Result;

use super::Elevated;

/// Whether the process happens to be running as root. Nothing asks it to be,
/// and nothing offers to make it so.
pub fn is_elevated() -> bool {
    crate::os::euid() == 0
}

pub fn run_elevated(_args: &[&str], _started: &dyn Fn()) -> Result<Elevated> {
    Ok(Elevated::Unavailable)
}
