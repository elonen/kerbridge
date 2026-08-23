//! State in `%APPDATA%`, policy under `HKLM`, autostart as a `Run` value.

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::reg::{self, Root};

const POLICY_KEY: &str = r"Software\KerBridge";
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
/// Value name under `Run`. User-visible in Task Manager's Startup tab.
const RUN_VALUE: &str = "KerBridge NAS Access";

pub fn app_dir() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join(super::APP_DIR))
}

pub fn policy_string(name: &str) -> Option<String> {
    reg::read_string(Root::Machine, POLICY_KEY, name)
}

pub fn policy_bool(name: &str) -> Option<bool> {
    reg::read_dword(Root::Machine, POLICY_KEY, name).map(|v| v != 0)
}

pub fn autostart_enabled() -> bool {
    reg::read_string(Root::User, RUN_KEY, RUN_VALUE).is_some()
}

/// A machine-wide `Run` value under the same name -- what the MSI writes when a
/// deployment installs with `AUTOSTART=1`. It starts the agent in the
/// interactive user's session whatever the per-user value says, and removing it
/// takes an administrator.
pub fn autostart_locked() -> bool {
    reg::read_string(Root::Machine, RUN_KEY, RUN_VALUE).is_some()
}

pub fn set_autostart(on: bool) -> Result<()> {
    if !on {
        return reg::delete_value(Root::User, RUN_KEY, RUN_VALUE);
    }
    let exe = std::env::current_exe().context("locating this executable")?;
    // Quoted: the path can contain spaces, and Run values are parsed as commands.
    reg::write_string(Root::User, RUN_KEY, RUN_VALUE, &format!("\"{}\"", exe.display()))
}
