//! `SYSTEMTIME` for the arithmetic and `GetTimeFormatEx` for the presentation.

use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows_sys::Win32::Globalization::{GetDateFormatEx, GetTimeFormatEx};
use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};

/// Seconds between the FILETIME epoch (1601-01-01) and the Unix epoch.
const EPOCH_DIFF: i64 = 11_644_473_600;

/// `TIME_NOSECONDS` -- "14:32", not "14:32:07".
const TIME_NOSECONDS: u32 = 0x0000_0002;
/// `DATE_SHORTDATE` -- the locale's short date, not its long one.
const DATE_SHORTDATE: u32 = 0x0000_0001;

pub fn local_time_string(unix: i64) -> String {
    let Some(local) = local_systemtime(unix) else {
        return String::new();
    };
    let mut buf = [0u16; 64];
    let n = unsafe {
        GetTimeFormatEx(
            std::ptr::null(), // LOCALE_NAME_USER_DEFAULT
            TIME_NOSECONDS,
            &local,
            std::ptr::null(),
            buf.as_mut_ptr(),
            buf.len() as i32,
        )
    };
    if n <= 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buf[..(n as usize - 1)]) // n counts the NUL
}

pub fn local_date_string(unix: i64) -> String {
    let Some(local) = local_systemtime(unix) else {
        return String::new();
    };
    let mut buf = [0u16; 64];
    let n = unsafe {
        GetDateFormatEx(
            std::ptr::null(), // LOCALE_NAME_USER_DEFAULT
            DATE_SHORTDATE,
            &local,
            std::ptr::null(),
            buf.as_mut_ptr(),
            buf.len() as i32,
            std::ptr::null(),
        )
    };
    if n <= 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buf[..(n as usize - 1)]) // n counts the NUL
}

pub fn local_stamp(unix: i64) -> String {
    let Some(t) = local_systemtime(unix) else {
        return super::UNKNOWN_STAMP.into();
    };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond
    )
}

fn local_systemtime(unix: i64) -> Option<SYSTEMTIME> {
    let ticks = (unix + EPOCH_DIFF).checked_mul(10_000_000)?;
    if ticks < 0 {
        return None;
    }
    let ft = FILETIME {
        dwLowDateTime: (ticks as u64 & 0xffff_ffff) as u32,
        dwHighDateTime: ((ticks as u64) >> 32) as u32,
    };
    unsafe {
        let mut utc: SYSTEMTIME = std::mem::zeroed();
        if FileTimeToSystemTime(&ft, &mut utc) == 0 {
            return None;
        }
        let mut local: SYSTEMTIME = std::mem::zeroed();
        // Null time zone = the machine's current one, DST included.
        if SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc, &mut local) == 0 {
            return None;
        }
        Some(local)
    }
}
