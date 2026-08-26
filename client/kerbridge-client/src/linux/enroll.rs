//! The Linux arm of [`super`]: there is nothing to enroll. Part of the CI-only
//! Linux arm -- see [`crate::os`] for what that is and is not.
//!
//! The same answer as macOS, for the same reason and one step further: MIT krb5
//! finds a realm's KDCs from the `_kerberos._udp` SRV records the deployment
//! already publishes, and maps a host to a realm by upper-casing its DNS domain
//! when no `[domain_realm]` says otherwise. There is no OS-level realm registry
//! for a state to be *stale* against -- `/etc/krb5.conf` is a file, not machine
//! state, and writing one would only be a second place for the realm to be
//! described wrongly.
//!
//! So [`State::Enrolled`] is not a stub standing in for work not done: it is the
//! answer. `apply`/`plan` do not exist on this arm at all, exactly as on macOS,
//! so nothing can call them by accident.

use super::State;
use crate::discovery::KerberosConfig;

pub fn state(_k: &KerberosConfig) -> State {
    State::Enrolled
}

pub fn needs_reboot(_before: &State) -> bool {
    false
}
