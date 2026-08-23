//! macOS never crosses the boundary. Nothing the Mac agent does needs privilege:
//! the realm is resolved from DNS with no file to write, and there is no NTLM
//! fallback to repair (measured in research spike `macos-ticket-injection`).
//! So this arm answers "not elevated, and no way to become so", which is the
//! truth rather than a stub waiting to be filled in.

use anyhow::{Result, bail};

/// Whether the process happens to be running as root. Nothing asks it to be,
/// and nothing offers to make it so.
pub fn is_elevated() -> bool {
    // SAFETY: geteuid is a plain syscall wrapper with no failure mode.
    unsafe { geteuid() == 0 }
}

pub fn run_elevated(_args: &[&str], _started: &dyn Fn()) -> Result<super::Elevated> {
    bail!("nothing on macOS needs administrator rights")
}

unsafe extern "C" {
    fn geteuid() -> u32;
}
