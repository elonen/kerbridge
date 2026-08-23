//! The elevation boundary: whether this process is over it, and how to run one
//! step on the far side. Only Windows has one to cross.

#[cfg_attr(windows, path = "windows/elevate.rs")]
#[cfg_attr(target_os = "macos", path = "macos/elevate.rs")]
mod imp;

/// What a relaunch came to.
///
/// A decline is a value rather than an error, and rather than an exit code,
/// because it is neither: nothing failed, and no child ever ran to have a code.
/// Folding it into either one is what makes a surface announce a decision as a
/// fault.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Elevated {
    /// The child ran and exited with this code.
    Ran(u32),
    /// The user said no at the administrator prompt.
    Declined,
    /// This machine cannot elevate at all: UAC is off, so the `runas` verb is
    /// inert and hands back a copy on the caller's own token. Distinct from a
    /// failure because nothing went wrong -- the machine is configured this way,
    /// and only an administrator can act on it.
    Unavailable,
}

/// Is this process running with an elevated token?
pub fn is_elevated() -> bool {
    imp::is_elevated()
}

/// Relaunch this executable elevated with `args` and wait for it. Blocking --
/// callers use a worker thread, never the UI loop.
///
/// `started` fires once the elevated child exists, which is the only observable
/// moment between "the prompt is up" and "the work is running": the secure
/// desktop is the system's and nothing reports back from it.
pub fn run_elevated(args: &[&str], started: &dyn Fn()) -> anyhow::Result<Elevated> {
    imp::run_elevated(args, started)
}
