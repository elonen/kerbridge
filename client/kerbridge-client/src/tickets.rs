//! This user's Kerberos ticket cache: put a broker-issued TGT in it, read
//! what is there, take a realm's tickets out again.
//!
//! Three operations, one meaning on every platform, three very different
//! mechanisms behind them. Windows has no file cache at all -- the ticket is
//! handed to the LSA Kerberos package as a DER KRB-CRED and lives inside the
//! logon session. macOS has Heimdal, whose `API:` cache reads the broker's MIT
//! ccache bytes natively, so nothing is repackaged
//! (research spike `macos-ticket-injection` Q2).
//!
//! Linux reads those same bytes natively too: the broker's `mit-ccache-v4` *is*
//! the format MIT krb5 keeps on disk, so the arm writes a file and no library
//! sees the bytes. That leaves one question the other two never face -- *which*
//! file, since a library knows where the caller's cache is and a path does not.
//! `KRB5CCNAME` is the answer, `/tmp/krb5cc_<uid>` is MIT's fallback when it is
//! unset, and the arm logs which it used: a ccache written where nothing looks
//! for it presents as a password prompt somewhere else entirely. See
//! `linux/tickets.rs`.
//!
//! What the three arms owe each other is only the contract below: after
//! [`inject`] returns, the platform's own SMB client can obtain a service ticket
//! for the realm without asking anyone for a password. Everything above this
//! module -- the schedule, the state machine, the CLI -- is written once against
//! that.
//!
//! A `#[cfg]` seam, like [`crate::sys`] and for the same reason: the choice is
//! made when the binary is built, and a trait object would only add dispatch.

use anyhow::Result;

use crate::krbcred::Tgt;

#[cfg_attr(windows, path = "windows/tickets.rs")]
#[cfg_attr(target_os = "macos", path = "macos/tickets.rs")]
#[cfg_attr(target_os = "linux", path = "linux/tickets.rs")]
mod imp;

/// A TGT the ticket cache currently holds.
///
/// Display and startup adoption only. **Ticket presence is not liveness**: an
/// expired ticket lingers in the cache, and a local failure can evict a valid one
/// (measured -- `client/DESIGN.md` @ ticket lifecycle), so the re-injection
/// schedule runs off what the agent itself injected. It is however the right
/// source at startup, when the agent has no metadata of its own and a previous
/// run's ticket may still be live.
pub struct CachedTgt {
    /// `user@REALM`, as the cache spells it.
    pub principal: String,
    /// Unix seconds. `renew_till` is 0 for a non-renewable ticket.
    pub start: i64,
    pub end: i64,
    pub renew_till: i64,
}

/// Land a broker-issued TGT in this user's ticket cache.
///
/// Both forms of the same ticket are passed because the platforms consume
/// different ones: Windows submits the DER KRB-CRED that [`crate::krbcred`]
/// repackages, while macOS and Linux take the broker's ccache bytes unchanged.
/// Parsing happens once, in the caller, either way.
pub fn inject(ccache: &[u8], tgt: &Tgt) -> Result<()> {
    imp::inject(ccache, tgt)
}

/// The realm's own TGT as the cache currently holds it, if any.
pub fn realm_tgt(realm: &str) -> Result<Option<CachedTgt>> {
    imp::realm_tgt(realm)
}

/// Drop every ticket for `realm` from this user's cache, so a fresh injection's
/// PAC is what future access derives from.
///
/// Realm-scoped, never a blanket purge: on Windows a cloud/AzureAD TGT on an
/// Entra-joined machine has to survive (measured:
/// research spike `windows-tgt-followup-entra-joined` Q8), and on macOS and
/// Linux another realm's credentials have to. It takes the stale `cifs/<nas>`
/// service ticket
/// with it, which is the point -- its old PAC otherwise keeps serving after a
/// group change (research spike `windows-tgt-renewal` row 7).
///
/// An already-open SMB session outlives this on every platform, deliberately:
/// this module owns the ticket cache, not anyone's mounts.
///
/// Returns the number of tickets removed.
pub fn purge_realm(realm: &str) -> Result<usize> {
    imp::purge_realm(realm)
}
