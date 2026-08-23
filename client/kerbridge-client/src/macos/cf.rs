//! The three CoreFoundation chores every macOS arm needs: own a reference,
//! make a `CFString`, read one back.
//!
//! Not a platform seam of its own -- it is the macOS side of several
//! ([`crate::sys`], [`crate::time`], [`crate::config`]), factored out so the
//! release rules are written once. CoreFoundation's ownership convention is the
//! part worth centralizing: anything from a `Create` or `Copy` function is the
//! caller's to release, anything else is not.

use core_foundation_sys::base::{CFRange, CFRelease, CFTypeRef};
use core_foundation_sys::string::{
    CFStringCreateWithBytes, CFStringGetBytes, CFStringGetLength, CFStringRef,
    kCFStringEncodingUTF8,
};

/// A CoreFoundation object this code has to release.
pub struct Owned(CFTypeRef);

impl Owned {
    /// Adopt the result of a `Create`/`Copy` call. `None` for the null those
    /// functions return on failure, so a caller cannot forget to check.
    pub fn adopt<T>(r: *const T) -> Option<Owned> {
        (!r.is_null()).then(|| Owned(r as CFTypeRef))
    }

    /// Borrow it as whichever `CF…Ref` the callee wants. Sound only because
    /// every one of them is a pointer to an opaque type and CoreFoundation
    /// checks the real type itself.
    pub fn as_ref<T>(&self) -> *const T {
        self.0 as *const T
    }

    /// The same, for the handful of `CF…Ref` aliases that are spelled `*mut` --
    /// mutable-looking but no more mutable in practice.
    pub fn as_mut<T>(&self) -> *mut T {
        self.0 as *mut T
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0) };
    }
}

/// A `CFString` holding `s`.
pub fn string(s: &str) -> Option<Owned> {
    Owned::adopt(unsafe {
        CFStringCreateWithBytes(
            std::ptr::null(),
            s.as_ptr(),
            s.len() as isize,
            kCFStringEncodingUTF8,
            false as u8,
        )
    })
}

/// A `CFString`'s contents. Borrows: the caller still owns `s`.
///
/// `CFStringGetBytes` rather than `CFStringGetCString`, because it reports the
/// exact byte count and so needs no guess about how far UTF-8 expands the UTF-16
/// the string is stored as.
///
/// # Safety
/// `s` must be null or a live `CFString`.
pub unsafe fn to_string(s: CFStringRef) -> Option<String> {
    if s.is_null() {
        return None;
    }
    unsafe {
        let range = CFRange { location: 0, length: CFStringGetLength(s) };
        let mut needed: isize = 0;
        CFStringGetBytes(
            s,
            range,
            kCFStringEncodingUTF8,
            0,
            false as u8,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
        let mut buf = vec![0u8; needed as usize];
        CFStringGetBytes(
            s,
            range,
            kCFStringEncodingUTF8,
            0,
            false as u8,
            buf.as_mut_ptr(),
            needed,
            std::ptr::null_mut(),
        );
        String::from_utf8(buf).ok()
    }
}
