//! Linux has no redirector to restart, and needs none. Part of the CI-only
//! Linux arm -- see [`crate::os`] for what that is and is not.
//!
//! The failure [`super`] exists for is a Windows one: an SMB session whose TGT
//! expired falls back to NTLM and stays there. `cifs.ko` and `smbclient` have no
//! such fallback to be stuck in against this realm -- there is no password for
//! them to fall back *to* -- and neither runs behind a system service whose
//! restart would be the remedy. Nothing has to be restarted, so nothing here is
//! reachable: the episode machinery is switched off by
//! [`crate::config::Settings::ntlm_fallback_recovery`], the same as on macOS.
//!
//! It refuses with that reason rather than panicking, so a caller wired up
//! wrongly gets an answer it can show instead of a crash.

pub fn restart_workstation() -> anyhow::Result<Vec<String>> {
    anyhow::bail!("Linux has no SMB redirector service to restart; nothing falls back to NTLM here")
}

pub fn running_dependents() -> Vec<String> {
    Vec::new()
}
