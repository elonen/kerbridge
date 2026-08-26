//! The Linux arm of [`super`]. Part of the CI-only Linux arm -- see [`crate::os`]
//! for what that is and is not.
//!
//! The UI language is POSIX locale environment, in the precedence the C library
//! itself applies: `LC_ALL` overrides everything, then `LC_MESSAGES` for the
//! category this actually is -- which strings a program shows -- and `LANG` as
//! the fallback for every unset category. `LC_CTYPE` is deliberately not
//! consulted: it is the *regional format*, which is the same distinction the
//! Windows and macOS arms make between display language and format.

/// A POSIX locale name as a BCP-47 tag: `fi_FI.UTF-8@euro` becomes `fi-FI`.
///
/// The codeset and the modifier are dropped -- neither is a language subtag, and
/// [`crate::strings`] matches on language and region. `C` and `POSIX` name no
/// language at all, so they answer the empty string, which is what the seam
/// documents for a platform with no answer.
pub fn ui_language() -> String {
    ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .find_map(|n| crate::os::env(n))
        .map(|locale| tag(&locale))
        .unwrap_or_default()
}

/// Split out so the parsing is testable without setting a process-wide variable
/// that every other test in the run would then see.
fn tag(locale: &str) -> String {
    match locale.split(['.', '@']).next().unwrap_or_default() {
        "C" | "POSIX" => String::new(),
        name => name.replace('_', "-"),
    }
}

/// Not answered here, and for the same reason the macOS arm gives: this gates
/// one notification, about a device grant, and this platform never holds one --
/// [`crate::device::AVAILABLE`] is `false`. The call site is unreachable rather
/// than unimplemented. Answering `None` also counts as "somebody is here", so a
/// caller that did reach it is early rather than never.
pub fn seconds_since_input() -> Option<i64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shapes a real `LANG` arrives in. Parsed rather than passed through,
    /// because `fi_FI.UTF-8` is not a language tag and the catalog looks one up.
    #[test]
    fn a_posix_locale_becomes_a_language_tag() {
        assert_eq!(tag("fi_FI.UTF-8"), "fi-FI");
        assert_eq!(tag("fi_FI.UTF-8@euro"), "fi-FI");
        assert_eq!(tag("en_US"), "en-US");
        assert_eq!(tag("de"), "de");
        // The two that name no language, and are what a container ships with.
        assert_eq!(tag("C"), "");
        assert_eq!(tag("POSIX"), "");
        assert_eq!(tag("C.UTF-8"), "");
    }
}
