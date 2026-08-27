//! The one calendar in the workspace.
//!
//! Four components stamp and read the same timestamps: `issuerd` renders a
//! ticket's validity window, sync stamps a retire or quarantine marker, the
//! broker and `kbmanage` read those markers back days or months later. The
//! format is fixed -- `YYYY-MM-DDTHH:MM:SSZ`, UTC, no offsets and no fractional
//! seconds -- because every string parsed here was written by [`rfc3339`] and
//! guessing at anything else would be inventing a second format.
//!
//! Hand-rolled rather than pulled from a date library, and deliberately so: this
//! is the whole of the workspace's date arithmetic, `kerbridge-core` is what
//! `issuerd` links, and `issuerd` holds KDC authority -- the same argument
//! `DESIGN.md` makes for keeping the notifier out of this crate. What a date
//! crate would buy is timezones, locales and leap seconds, none of which appear
//! here.
//!
//! Both directions are Howard Hinnant's `civil_from_days` / `days_from_civil`,
//! one implementation each. The era begins on 0000-03-01 so leap days fall at
//! the end of a year and need no special case. There were four copies of these
//! twenty lines before this module existed, and two of them disagreed about
//! whether a bad date was `None` or a silently wrong answer.

/// Seconds since the Unix epoch, now.
///
/// A clock before the epoch reads as `0` rather than failing: every caller is
/// stamping a marker or an age, and none of them has anything better to do with
/// a broken clock than record the earliest time it can name.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Render a Unix timestamp as RFC 3339 UTC.
///
/// `u32` is the range this commits to -- it runs out in 2106, and every caller is
/// stamping either a Kerberos time (which is `u32` on the wire) or a marker.
pub fn rfc3339(epoch: u32) -> String {
    let (days, secs) = (i64::from(epoch / 86_400), epoch % 86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// Parse the form [`rfc3339`] emits, and nothing else.
///
/// Offsets, fractional seconds and a lowercase `t` are rejected rather than
/// guessed at. `None` for anything that is not exactly `YYYY-MM-DDTHH:MM:SSZ`
/// with a real date in it.
pub fn epoch_from_rfc3339(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let num = |from: usize, to: usize| -> Option<i64> { s[from..to].parse().ok() };
    let days = days_from_civil(num(0, 4)?, num(5, 7)?, num(8, 10)?)?;
    let (h, mi, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    // 60 is allowed: a leap second is a real value to have written down, and
    // rounding it into the next minute is a worse answer than accepting it.
    if h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    u64::try_from(days * 86_400 + h * 3600 + mi * 60 + sec).ok()
}

/// Days from the Unix epoch for a bare `YYYY-MM-DD` date, or `None` if that is
/// not what it is. Negative before 1970.
///
/// This one is an operator's assertion rather than something this workspace
/// wrote -- the sync credential's expiry, typed into a `.env` -- so the whole
/// string has to be validated rather than trusted.
pub fn days_from_ymd(date: &str) -> Option<i64> {
    let mut parts = date.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: i64 = parts.next()?.parse().ok()?;
    let d: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    days_from_civil(y, m, d)
}

/// Hinnant's `days_from_civil`, with the range check folded in so no caller can
/// forget it. `None` for a month or day outside the calendar.
///
/// The day bound is 31 for every month: rejecting the 31st of February would
/// need a month-length table, and nothing here is validating operator input
/// closely enough to be worth one. A date that does not exist maps to a real day
/// a little further on, which is the behavior every caller already had.
fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = y - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// Hinnant's `civil_from_days`: the exact inverse of [`days_from_civil`].
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_timestamps() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_000_000_000), "2001-09-09T01:46:40Z");
        // A leap day, and the last second of a leap year.
        assert_eq!(rfc3339(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_735_689_599), "2024-12-31T23:59:59Z");
        assert_eq!(rfc3339(u32::MAX), "2106-02-07T06:28:15Z");
    }

    #[test]
    fn epoch_parsing_inverts_the_renderer() {
        for epoch in [0u32, 1, 951_782_400, 1_753_444_800, 2_000_000_000, u32::MAX] {
            assert_eq!(epoch_from_rfc3339(&rfc3339(epoch)), Some(u64::from(epoch)), "{epoch}");
        }
    }

    #[test]
    fn epoch_parsing_rejects_anything_it_did_not_write() {
        for bad in [
            "",
            "2026-07-21",
            "2026-07-21T12:00:00",       // no zone
            "2026-07-21T12:00:00+02:00", // an offset, not UTC
            "2026-07-21t12:00:00Z",      // lowercase separator
            "2026-07-21T12:00:00.5Z",    // fractional seconds
            "2026-13-21T12:00:00Z",      // month 13
            "2026-07-21T24:00:00Z",      // hour 24
            "not-a-date-at-all!!!",
        ] {
            assert_eq!(epoch_from_rfc3339(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn day_math_matches_known_anchors() {
        assert_eq!(days_from_ymd("1970-01-01"), Some(0));
        assert_eq!(days_from_ymd("2000-01-01"), Some(10_957));
        assert_eq!(days_from_ymd("2026-07-23"), Some(20_657));
        assert_eq!(days_from_ymd("not-a-date"), None);
        assert_eq!(days_from_ymd("2026-13-01"), None);
        // Trailing junk is not a date, however parsable its front is.
        assert_eq!(days_from_ymd("2026-07-23-01"), None);
    }

    /// The two kernels are inverses, which is the property every caller leans on
    /// and the one a transcription error would break. Checked across the era
    /// boundaries the algorithm actually branches on rather than at a few dates.
    #[test]
    fn the_two_kernels_invert_each_other() {
        for days in [-719_468i64, -1, 0, 1, 10_957, 20_657, 49_673, 146_097] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), Some(days), "{days} -> {y}-{m}-{d}");
        }
    }

    /// Pre-epoch dates go negative rather than wrapping, which is what makes
    /// `credential_days_remaining` read as "expired" instead of "millennia left".
    #[test]
    fn dates_before_the_epoch_are_negative() {
        assert_eq!(days_from_ymd("1969-12-31"), Some(-1));
        assert_eq!(days_from_ymd("1900-01-01"), Some(-25_567));
        // And they have no `u32` timestamp, so the parser refuses rather than
        // wrapping into the far future.
        assert_eq!(epoch_from_rfc3339("1969-12-31T23:59:59Z"), None);
    }
}
