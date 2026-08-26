//! # The Linux arm, and what a green run here means
//!
//! **This arm exists so that CI can run the real client.** CI is Linux, and
//! without an arm here the crate does not compile there -- which leaves the
//! platform-neutral majority untested anywhere automated: `/config` parsing,
//! authorization-code + PKCE, the loopback redirect and its state check, the
//! token exchange, the broker exchange, `krbcred`, the re-injection schedule,
//! error classification, configuration precedence, and the CLI's orchestration.
//! A stack test that re-implements the client in shell cannot catch the client
//! being wrong.
//!
//! **A green Linux run is not a statement about Windows or macOS.** It does not
//! exercise LSA ticket submission, Heimdal's `API:` cache, WAM, CNG device keys,
//! or realm registration. Those are measured where they live, on the Windows and
//! macOS benches, and nothing here substitutes for that.
//!
//! **This is not a supported Linux desktop client.** There is no tray, no
//! packaging, no login item and no notification surface, and the arms below say
//! so one subject at a time: where Linux genuinely has the thing, the arm is
//! real (`tickets`, `srv`, `time`, `config`'s state directory); where it does
//! not, the arm *refuses with a reason* rather than panicking, because a stub
//! that panics is a crash waiting for a caller and a stub that refuses is an
//! answer. Should a real Linux client ever be wanted, these files are where it
//! starts -- but nothing here should be read as it having started.
//!
//! ---
//!
//! The rest of this file is the platform's toolbox, in the same sense as
//! `windows/reg.rs` and `macos/cf.rs`: the calls `std` does not expose that more
//! than one arm needs. Both are plain syscall wrappers with no failure mode, and
//! keeping them here is what keeps `unsafe` out of the arms themselves.

/// This process's effective user id.
pub fn euid() -> u32 {
    // SAFETY: `geteuid` is a plain syscall wrapper. POSIX gives it no failure
    // mode and no error return -- there is nothing to check.
    unsafe { geteuid() }
}

/// The environment variable the caller named, ignoring an empty value.
///
/// Empty and unset mean the same thing everywhere this is used: `LANG=` names
/// no locale, and `KRB5CCNAME=` names no cache.
pub fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

unsafe extern "C" {
    fn geteuid() -> u32;
}
