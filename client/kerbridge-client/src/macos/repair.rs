//! macOS has no equivalent, and needs none. The same expiry here drops the mount
//! with a visible "server disconnected" and wedges any in-flight I/O, but the
//! wedge clears itself on a client-side timeout of about ten minutes and a
//! reconnect works immediately (measured --
//! research spike `macos-ticket-injection` Q9). Nothing has to be
//! restarted, so nothing here is reachable: the whole episode machinery is
//! switched off by [`crate::config::Settings::ntlm_fallback_recovery`].

pub fn restart_workstation() -> anyhow::Result<Vec<String>> {
    anyhow::bail!("macOS recovers from an expired ticket on its own; nothing to restart")
}

pub fn running_dependents() -> Vec<String> {
    Vec::new()
}
