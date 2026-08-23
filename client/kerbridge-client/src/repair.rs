//! NTLM-fallback recovery: restart the Workstation service (`LanmanWorkstation`).
//!
//! The measured failure this exists for is a Windows one: when an injected TGT
//! expires while an SMB session is open, the redirector falls back to NTLM and
//! stays there -- and NTLM cannot succeed against this realm, since no cloud
//! identity has a password the KDC knows. Neither re-injection nor a ticket purge
//! clears it -- only an elevated restart of the redirector service does. Which is
//! why proactive re-injection (landing well before End Time) is the real fix and
//! this is the ladder's last rung.

#[cfg_attr(windows, path = "windows/repair.rs")]
#[cfg_attr(target_os = "macos", path = "macos/repair.rs")]
mod imp;

/// Stop and restart the Workstation service, taking its running dependents with
/// it. Returns a human-readable transcript for the log and the result dialog.
pub fn restart_workstation() -> anyhow::Result<Vec<String>> {
    imp::restart_workstation()
}

/// Which services would be stopped and restarted along with the redirector.
///
/// The confirmation names its casualties, so the *unprivileged* parent has to be
/// able to find them -- and it can: enumerating dependents needs only
/// `SERVICE_ENUMERATE_DEPENDENTS`, measured to succeed in the same session where
/// `SERVICE_STOP` is refused with error 5. Empty on any failure, and on macOS,
/// because a list that cannot be produced is a paragraph the dialog omits rather
/// than a reason to refuse the operation.
pub fn running_dependents() -> Vec<String> {
    imp::running_dependents()
}
