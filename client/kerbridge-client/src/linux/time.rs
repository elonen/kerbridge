//! The Linux arm of [`super`]: `localtime_r`, and nothing above it. Part of the
//! CI-only Linux arm -- see [`crate::os`] for what that is and is not.
//!
//! **Not locale-aware, deliberately.** The other two arms reach for
//! `GetDateFormatEx` and `CFDateFormatter` because a human reads these strings
//! in a tray menu, and 12- versus 24-hour is that human's setting rather than
//! ours. Nothing reads a Linux tray menu -- there is no Linux agent -- so every
//! caller here is a log line, and a log line wants to be sortable and
//! unambiguous more than it wants to be local convention. So: ISO-8601 field
//! order and 24-hour in all three functions. Pulling a date-formatting crate
//! into the shared tree to render a timestamp no person reads would be a poor
//! trade, and the seam above already tolerates a plainer answer -- it documents
//! the empty string as what a platform with nothing to say returns.
//!
//! **Local, though, and not UTC.** `localtime_r` is what applies `TZ` and
//! `/etc/localtime`, so a stamp here means the same wall clock as every other
//! log on the machine. It is declared here rather than taken from `libc`: this
//! is one function, the client crate has no `libc` dependency on any platform,
//! and the two arms beside this one declare their own externs for the same
//! reason.

/// `time_t`. 64-bit on every target this arm is built for, and on 32-bit musl
/// too; a 32-bit glibc without `_TIME_BITS=64` is the one shape that would
/// disagree, and nothing builds this client there.
type TimeT = i64;

/// `struct tm`, cut off after the fields that are read.
///
/// The six below are the first six members on every C library -- POSIX fixes
/// their order, and glibc, musl and the BSDs all agree -- so a `#[repr(C)]`
/// struct puts them where the library expects them. `_rest` stands for
/// `tm_wday`, `tm_yday`, `tm_isdst`, `tm_gmtoff` and `tm_zone`, which
/// `localtime_r` fills in and this arm never reads: it is here so the library
/// writes inside the allocation rather than past it, and the assertion below is
/// what keeps that true.
#[repr(C)]
#[derive(Default)]
struct Tm {
    sec: i32,
    min: i32,
    hour: i32,
    mday: i32,
    /// Months since January: 0..=11.
    mon: i32,
    /// Years since 1900.
    year: i32,
    _rest: [u64; 5],
}

// `struct tm` is 56 bytes on 64-bit glibc and musl: nine `int`s, padded, then a
// `long` and a pointer. Larger is safe here and smaller is memory corruption, so
// the direction of this assertion is the direction that matters.
const _: () = assert!(size_of::<Tm>() >= 56);

unsafe extern "C" {
    fn localtime_r(t: *const TimeT, tm: *mut Tm) -> *mut Tm;
}

/// Broken-down local time, or `None` when the C library refuses the instant --
/// which it does for a year outside `int` range, and for nothing a Kerberos
/// ticket will ever carry.
fn local(unix: i64) -> Option<Tm> {
    let t: TimeT = unix;
    let mut tm = Tm::default();
    // SAFETY: `t` and `tm` are both live for the call, and `tm` is at least as
    // large as the `struct tm` the library writes -- see the assertion above.
    let out = unsafe { localtime_r(&t, &mut tm) };
    (!out.is_null()).then_some(tm)
}

/// 24-hour, `14:32`. See this module's header for why not the user's own format.
pub fn local_time_string(unix: i64) -> String {
    local(unix).map(|t| format!("{:02}:{:02}", t.hour, t.min)).unwrap_or_default()
}

/// ISO-8601, `2026-07-24`. Ordered so it cannot be read as the other arms'
/// short date with its day and month swapped, which is the whole risk there.
pub fn local_date_string(unix: i64) -> String {
    local(unix).map(|t| date(&t)).unwrap_or_default()
}

pub fn local_stamp(unix: i64) -> String {
    local(unix).map_or_else(|| super::UNKNOWN_STAMP.into(), |t| stamp(&t))
}

fn date(t: &Tm) -> String {
    format!("{:04}-{:02}-{:02}", t.year + 1900, t.mon + 1, t.mday)
}

/// Split from [`local_stamp`] so the arithmetic -- the 1900 and the 0-based
/// month, which are the two things a `struct tm` gets wrong quietly -- is
/// testable without a time zone.
fn stamp(t: &Tm) -> String {
    format!("{} {:02}:{:02}:{:02}", date(t), t.hour, t.min, t.sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two offsets `struct tm` carries that nothing else does: years since
    /// 1900 and a zero-based month. Both are silent when wrong -- a stamp still
    /// looks like a stamp -- so they are asserted rather than eyeballed.
    #[test]
    fn a_stamp_undoes_struct_tms_two_offsets() {
        let t = Tm { sec: 7, min: 32, hour: 14, mday: 24, mon: 6, year: 126, _rest: [0; 5] };
        assert_eq!(stamp(&t), "2026-07-24 14:32:07");
        assert_eq!(date(&t), "2026-07-24");
        assert_eq!(stamp(&t).len(), super::super::UNKNOWN_STAMP.len());

        // January of a single-digit day and hour, where the padding shows.
        let t = Tm { sec: 0, min: 5, hour: 3, mday: 1, mon: 0, year: 100, _rest: [0; 5] };
        assert_eq!(stamp(&t), "2000-01-01 03:05:00");
    }

    /// The FFI itself, and with it the field offsets: a wrong layout reads a
    /// year out of `tm_min` and cannot land in the window below.
    ///
    /// No `TZ` is set -- the whole point is that this holds on any machine. The
    /// instant is 2026-07-24T11:32:07Z and no real zone is more than 14 hours
    /// from UTC, so the local date is the 23rd, 24th or 25th of July 2026
    /// wherever the test runs.
    #[test]
    fn localtime_r_fills_the_fields_this_struct_names() {
        let t = local(1_784_892_727).expect("an instant every C library accepts");
        assert_eq!(t.year, 126, "years since 1900");
        assert_eq!(t.mon, 6, "July, zero-based");
        assert!((23..=25).contains(&t.mday), "day was {}", t.mday);
        assert!((0..24).contains(&t.hour) && (0..60).contains(&t.min));
        assert_eq!(t.sec, 7, "seconds are the same in every whole-minute zone");
    }
}
