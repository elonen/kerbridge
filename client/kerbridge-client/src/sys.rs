//! The per-platform seam: one function per thing the core needs from the host
//! operating system that has no portable spelling.
//!
//! Selected by `#[cfg]` rather than by a trait, because the choice is made when
//! the binary is built and a trait object would only add dispatch to it. Every
//! arm exposes the same signatures; a caller never says which one it is on.
//!
//! Distinct from [`crate::agent::Host`], which is the *other* kind of seam -- that
//! one is injected at runtime because it reaches back into a UI the core cannot
//! name. This one reaches down.
//!
//! The same `#[cfg]` split runs through [`crate::tickets`], [`crate::srv`],
//! [`crate::time`], [`crate::config`] and the rest, each a subject in its own
//! right. What lands here is what belongs to no subject: one fact about the host,
//! needed once.

#[cfg_attr(windows, path = "windows/sys.rs")]
#[cfg_attr(target_os = "macos", path = "macos/sys.rs")]
#[cfg_attr(target_os = "linux", path = "linux/sys.rs")]
mod imp;

/// The operating system's UI language as a BCP-47 tag ("fi-FI", "zh-Hans-CN"),
/// or an empty string when the platform has no answer.
///
/// A tag rather than an OS-native language id so that
/// [`crate::strings`] can hold the mapping -- which table serves which language is
/// the string catalog's business, not any one platform's, and as a tag it is
/// testable off the platform that produced it.
pub fn ui_language() -> String {
    imp::ui_language()
}

/// How long since the user last touched this machine, in seconds, or `None`
/// where the platform will not say.
///
/// One notification has slack -- the device-grant deadline is days away -- so it
/// is the one that waits for somebody to be at the keyboard rather than firing
/// at 03:00 into an empty room. `None` counts as present, so a platform with no
/// answer gets the toast on time rather than never.
pub fn seconds_since_input() -> Option<i64> {
    imp::seconds_since_input()
}
