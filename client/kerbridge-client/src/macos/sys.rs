//! macOS states the answer as a tag already: `CFLocaleCopyPreferredLanguages`
//! returns the user's ordered display languages ("en-FI", "fi-FI"), the first of
//! which is what the desktop is drawn in. That is the display language and not
//! the regional format, which is the same distinction the Windows arm makes.

pub fn ui_language() -> String {
    use core_foundation_sys::array::{CFArrayGetCount, CFArrayGetValueAtIndex};
    use core_foundation_sys::locale::CFLocaleCopyPreferredLanguages;
    use core_foundation_sys::string::CFStringRef;

    use crate::cf::{self, Owned};

    let Some(langs) = Owned::adopt(unsafe { CFLocaleCopyPreferredLanguages() }) else {
        return String::new();
    };
    unsafe {
        if CFArrayGetCount(langs.as_ref()) == 0 {
            return String::new();
        }
        cf::to_string(CFArrayGetValueAtIndex(langs.as_ref(), 0) as CFStringRef).unwrap_or_default()
    }
}

/// Not answered here. The Mac has `CGEventSourceSecondsSinceLastEventType`, but
/// it is the notification's own gate and nothing on this platform sends that
/// notification: device grants are a Windows feature and the Mac never holds
/// one, so the call site is unreachable rather than unimplemented.
pub fn seconds_since_input() -> Option<i64> {
    None
}
