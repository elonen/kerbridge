//! The macOS arm of [`super`]: there is nothing to enroll.
//!
//! Heimdal finds the realm's KDCs through the `_kerberos._udp` SRV record the
//! deployment already publishes, and maps a host to a realm by upper-casing its
//! DNS domain when no `[domain_realm]` says otherwise. The spike mounted a share
//! on a Mac with no `/etc/krb5.conf` at all, so writing one would only be a
//! second place for the realm to be described wrongly.
//!
//! If a deployment ever does need a mapping -- a realm whose name is not the
//! upper-cased DNS domain is the case to watch, and it is on the open list in
//! research spike `macos-ticket-injection` -- this is where it goes, and
//! [`State::Stale`] is how it gets reported.

use super::State;
use crate::discovery::KerberosConfig;

pub fn state(_k: &KerberosConfig) -> State {
    State::Enrolled
}

pub fn needs_reboot(_before: &State) -> bool {
    false
}
