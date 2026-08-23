//! Realm enrollment: telling the OS that `EXAMPLE.SITE` is a Kerberos realm, and
//! checking whether it already knows.
//!
//! **Only Windows needs any of this.** A Mac that had never been told the realm
//! existed resolved it from DNS and was issued a `cifs/` service ticket with no
//! configuration file and no elevation (measured --
//! research spike `macos-ticket-injection` Q4), so its arm answers
//! [`State::Enrolled`] and there is nothing to apply. The question stays shared
//! because the agent asks it on both, and one of the two answers is "no".
//!
//! On Windows this is the one thing the helper does that needs administrator
//! rights, and the one thing it does that outlives the user's session -- it
//! writes machine LSA state. So it is a separate elevated one-shot
//! (`--enroll <broker>`), not something the agent does behind the user's back,
//! and it shows the literal `ksetup` commands for confirmation before running
//! them. The broker is trusted over TLS to name the realm's KDCs, and that
//! confirmation is the backstop against a rogue one.

use crate::discovery::KerberosConfig;

#[cfg_attr(windows, path = "windows/enroll.rs")]
#[cfg_attr(target_os = "macos", path = "macos/enroll.rs")]
mod imp;

/// The OS's view of the realm, compared against the broker's.
#[derive(PartialEq, Eq, Debug)]
pub enum State {
    Enrolled,
    /// The realm is unknown to the OS.
    NotEnrolled,
    /// Registered, but not as the broker describes it. Each string is a
    /// human-readable difference, shown in the enrollment confirmation.
    Stale(Vec<String>),
}

impl State {
    pub fn needs_action(&self) -> bool {
        !matches!(self, State::Enrolled)
    }
}

/// Compare the OS's realm state to the broker's `kerberos` block.
pub fn state(k: &KerberosConfig) -> State {
    imp::state(k)
}

/// True when applying the plan needs a reboot to take effect.
pub fn needs_reboot(before: &State) -> bool {
    imp::needs_reboot(before)
}

/// Applying an enrollment exists only where there is one to apply. The macOS
/// agent never offers it, so the functions are not there to be called by
/// accident.
#[cfg(windows)]
pub use imp::{apply, plan, plan_text, unenroll, unenroll_plan_text};
