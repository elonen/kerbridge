//! `CFDateFormatter`, which is the same mechanism the rest of the desktop
//! formats times with -- including the user's 24-hour override, which a
//! `strftime` of our own would not see.

use core_foundation_sys::date::kCFAbsoluteTimeIntervalSince1970;
use core_foundation_sys::date_formatter::{
    CFDateFormatterCreate, CFDateFormatterCreateStringWithAbsoluteTime, CFDateFormatterSetFormat,
    CFDateFormatterStyle, kCFDateFormatterNoStyle, kCFDateFormatterShortStyle,
};
use core_foundation_sys::locale::{CFLocaleCopyCurrent, CFLocaleCreate, CFLocaleRef};

use crate::cf::{self, Owned};

pub fn local_time_string(unix: i64) -> String {
    let Some(locale) = Owned::adopt(unsafe { CFLocaleCopyCurrent() }) else {
        return String::new();
    };
    format(unix, &locale, kCFDateFormatterNoStyle, kCFDateFormatterShortStyle, None)
        .unwrap_or_default()
}

pub fn local_date_string(unix: i64) -> String {
    let Some(locale) = Owned::adopt(unsafe { CFLocaleCopyCurrent() }) else {
        return String::new();
    };
    format(unix, &locale, kCFDateFormatterShortStyle, kCFDateFormatterNoStyle, None)
        .unwrap_or_default()
}

pub fn local_stamp(unix: i64) -> String {
    // en_US_POSIX, so the pattern below means what it says whatever calendar
    // and numbering system the user's own locale prefers -- a log line has to
    // stay sortable and machine-readable.
    let locale = cf::string("en_US_POSIX")
        .and_then(|name| Owned::adopt(unsafe { CFLocaleCreate(std::ptr::null(), name.as_ref()) }))
        .and_then(|l| {
            format(
                unix,
                &l,
                kCFDateFormatterNoStyle,
                kCFDateFormatterNoStyle,
                Some("yyyy-MM-dd HH:mm:ss"),
            )
        });
    locale.unwrap_or_else(|| super::UNKNOWN_STAMP.into())
}

/// One formatter, used once. Cheap enough at the rate this is called (a log
/// line, a status repaint), and it means a time-zone or locale change during
/// a long-running agent is picked up rather than cached past its truth.
fn format(
    unix: i64,
    locale: &Owned,
    date_style: CFDateFormatterStyle,
    time_style: CFDateFormatterStyle,
    pattern: Option<&str>,
) -> Option<String> {
    unsafe {
        let locale: CFLocaleRef = locale.as_ref();
        let fmt =
            Owned::adopt(CFDateFormatterCreate(std::ptr::null(), locale, date_style, time_style))?;
        if let Some(pattern) = pattern {
            CFDateFormatterSetFormat(fmt.as_mut(), cf::string(pattern)?.as_ref());
        }
        let s = Owned::adopt(CFDateFormatterCreateStringWithAbsoluteTime(
            std::ptr::null(),
            fmt.as_mut(),
            unix as f64 - kCFAbsoluteTimeIntervalSince1970,
        ))?;
        cf::to_string(s.as_ref())
    }
}
