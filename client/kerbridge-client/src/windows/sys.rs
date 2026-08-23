//! `GetUserDefaultUILanguage` gives a LANGID; `LCIDToLocaleName` turns it into
//! the BCP-47 tag the caller wants.

pub fn ui_language() -> String {
    use windows_sys::Win32::Globalization::{GetUserDefaultUILanguage, LCIDToLocaleName};

    // The *display* language, not the regional format: someone running English
    // Windows with Finnish dates is reading English.
    let langid = unsafe { GetUserDefaultUILanguage() } as u32;
    // LOCALE_NAME_MAX_LENGTH. LCIDToLocaleName returns the count including the
    // terminating null, or 0 on failure -- which leaves English, as it should.
    let mut buf = [0u16; 85];
    let n = unsafe { LCIDToLocaleName(langid, buf.as_mut_ptr(), buf.len() as i32, 0) };
    if n <= 1 {
        return String::new();
    }
    String::from_utf16_lossy(&buf[..n as usize - 1])
}

pub fn seconds_since_input() -> Option<i64> {
    use windows_sys::Win32::System::SystemInformation::GetTickCount;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

    let mut info = LASTINPUTINFO { cbSize: size_of::<LASTINPUTINFO>() as u32, dwTime: 0 };
    if unsafe { GetLastInputInfo(&mut info) } == 0 {
        return None;
    }
    // Both counters are milliseconds since boot and both wrap at 2^32, so the
    // wrapping difference is right across the wrap as well as before it.
    let elapsed = unsafe { GetTickCount() }.wrapping_sub(info.dwTime);
    Some(i64::from(elapsed) / 1000)
}
