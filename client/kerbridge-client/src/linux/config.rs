//! State under `$XDG_CONFIG_HOME`, no policy channel, and no autostart. Part of
//! the CI-only Linux arm -- see [`crate::os`] for what that is and is not.
//!
//! Only [`super`]'s state directory is answered here. The refusals below carry
//! the reasoning.
//!
//! **There is no policy layer.** Windows has `HKLM\Software\Policies` and macOS
//! has forced managed preferences: both are channels an existing management
//! system *already owns*, which is what makes a value read out of one mean "IT
//! decided". Linux has no such channel -- and inventing one, say a file under
//! `/etc`, would create a fourth layer that no management system writes and that
//! any local administrator can forge, while presenting to the rest of the client
//! as the layer that outranks the user. [`policy_string`] and [`policy_bool`]
//! answer `None`, so the policy layer is empty and every setting falls through
//! to `config.toml` and the broker's defaults, which is the correct precedence
//! for a machine no management system owns.
//!
//! **There is no autostart.** systemd user units, XDG autostart desktop entries
//! and half a dozen session managers are all plausible answers, and picking one
//! is a decision about a supported Linux desktop client that this arm explicitly
//! is not. [`set_autostart`] refuses with that reason rather than writing a file
//! into a session that may not read it.

use std::path::PathBuf;

use anyhow::{Result, bail};

/// `$XDG_CONFIG_HOME/KerBridge`, or `~/.config/KerBridge` when it is unset --
/// the fallback the XDG base directory specification names, and the one every
/// other program on the machine uses, so the state lands where a person looking
/// for it would look.
///
/// A relative `XDG_CONFIG_HOME` is ignored: the specification says it must be an
/// absolute path, and honouring a relative one would put this user's state
/// wherever the process happened to be started from.
pub fn app_dir() -> Option<PathBuf> {
    let base = crate::os::env("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| crate::os::env("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join(super::APP_DIR))
}

/// Never. See this module's header: there is no policy channel on this platform
/// and this arm does not invent one.
pub fn policy_string(_name: &str) -> Option<String> {
    None
}

/// Never, for the same reason as [`policy_string`].
pub fn policy_bool(_name: &str) -> Option<bool> {
    None
}

pub fn autostart_enabled() -> bool {
    false
}

/// Never: with no autostart mechanism at all there is nothing machine-wide for a
/// per-user setting to be unable to countermand.
pub fn autostart_machine_wide() -> bool {
    false
}

pub fn set_autostart(_on: bool) -> Result<()> {
    bail!("starting at login is not supported on Linux; run `kerbridge` when you need a ticket")
}
