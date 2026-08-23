//! Unix seconds ↔ the user's local clock.
//!
//! Kerberos speaks Unix seconds and so does everything upstream of the UI; the
//! user reads clock time in their own locale and time zone. Rather than carry a
//! date library for two conversions, this leans on the OS on both platforms --
//! which also gets 12- vs 24-hour right without a policy of our own.

use std::time::{SystemTime, UNIX_EPOCH};

#[cfg_attr(windows, path = "windows/time.rs")]
#[cfg_attr(target_os = "macos", path = "macos/time.rs")]
mod imp;

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Local wall-clock time of a Unix instant, formatted for the user's locale
/// ("14:32" / "2:32 PM"). Empty on the impossible conversion failure -- callers
/// render it inline, so an empty string degrades to a missing time, not a panic.
pub fn local_time_string(unix: i64) -> String {
    imp::local_time_string(unix)
}

/// Local calendar date of a Unix instant, in the user's short format
/// ("24/07/2026" / "7/24/2026"). For a deadline days away, where the wall clock
/// says nothing and the date is what someone puts in a calendar.
pub fn local_date_string(unix: i64) -> String {
    imp::local_date_string(unix)
}

/// Sortable local timestamp for log lines: `2026-07-24 14:32:07`.
pub fn local_stamp(unix: i64) -> String {
    imp::local_stamp(unix)
}

/// What a failed conversion leaves in a log line. Same width as a real stamp, so
/// the column does not move.
const UNKNOWN_STAMP: &str = "????-??-?? ??:??:??";
