//! OS light/dark theming for stock Win32 controls.
//!
//! Windows gives no supported "make my controls dark" switch, so this is the
//! well-trodden mix the ecosystem (Explorer, Terminal, Notepad++) uses:
//!   * dark title bar via the documented DWM attribute,
//!   * dark menus/scrollbars via **undocumented** uxtheme ordinals + SetWindowTheme,
//!   * dark control faces via our own `WM_CTLCOLOR*` brushes.
//!
//! The ordinal calls have been stable since Win10 1809 but are not a supported
//! contract; if Microsoft ever breaks them we lose *dark menus*, not correctness.

use std::ffi::c_void;
use std::mem::transmute;

use windows_sys::Win32::Foundation::HWND;

// windows-sys models Win32 BOOL as a plain i32. Spelled the Win32 way on purpose:
// these are FFI signatures, and matching the SDK's names is what makes them checkable.
#[allow(clippy::upper_case_acronyms)]
type BOOL = i32;
use windows_sys::Win32::Graphics::Dwm::DwmSetWindowAttribute;
use windows_sys::Win32::Graphics::Gdi::{CreateSolidBrush, DeleteObject, HBRUSH};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RegGetValueW};
use windows_sys::Win32::UI::Controls::SetWindowTheme;

use crate::sys::wide;

const DWMWA_USE_IMMERSIVE_DARK_MODE: u32 = 20;
const DWMWA_WINDOW_CORNER_PREFERENCE: u32 = 33;
const DWMWCP_ROUND: i32 = 2;

fn rgb(r: u8, g: u8, b: u8) -> u32 {
    (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
}

/// Resolved palette + GDI brushes for the current mode. Copyable so window procs can
/// snapshot it without borrowing; brushes are owned by `App` and freed on mode change.
#[derive(Clone, Copy)]
pub struct Theme {
    pub dark: bool,
    pub bg: u32,      // window background
    pub surface: u32, // read-only field / detail backgrounds
    pub text: u32,
    pub subtext: u32,
    pub accent: u32,
    pub warn: u32,
    pub ok: u32,
    pub danger: u32,
    pub sep: u32, // hairline separator
    pub bg_brush: HBRUSH,
    pub surface_brush: HBRUSH,
    pub sep_brush: HBRUSH,
    // The explanation block's rule, at the three severities it draws in. Solid
    // fills rather than text colors, because the rule is an empty STATIC.
    pub warn_brush: HBRUSH,
    pub danger_brush: HBRUSH,
    pub sub_brush: HBRUSH,
}

impl Theme {
    /// Build the palette for the OS's current apps-mode, allocating its brushes.
    pub fn current() -> Theme {
        let dark = os_prefers_dark();
        let (bg, surface, text, subtext) = if dark {
            (
                rgb(0x2b, 0x2b, 0x2b),
                rgb(0x3a, 0x3a, 0x3a),
                rgb(0xff, 0xff, 0xff),
                rgb(0xb0, 0xb0, 0xb0),
            )
        } else {
            (
                rgb(0xf3, 0xf3, 0xf3),
                rgb(0xff, 0xff, 0xff),
                rgb(0x1a, 0x1a, 0x1a),
                rgb(0x60, 0x60, 0x66),
            )
        };
        Theme {
            dark,
            bg,
            surface,
            text,
            subtext,
            accent: if dark { rgb(0x4c, 0xc2, 0xff) } else { rgb(0x00, 0x67, 0xc0) },
            warn: warn(dark),
            ok: if dark { rgb(0x57, 0xc9, 0x8a) } else { rgb(0x1a, 0x7f, 0x4f) },
            danger: danger(dark),
            sep: if dark { rgb(0x50, 0x50, 0x50) } else { rgb(0xdc, 0xdc, 0xe0) },
            bg_brush: unsafe { CreateSolidBrush(bg) },
            surface_brush: unsafe { CreateSolidBrush(surface) },
            sep_brush: unsafe {
                CreateSolidBrush(if dark { rgb(0x50, 0x50, 0x50) } else { rgb(0xdc, 0xdc, 0xe0) })
            },
            warn_brush: unsafe { CreateSolidBrush(warn(dark)) },
            danger_brush: unsafe { CreateSolidBrush(danger(dark)) },
            sub_brush: unsafe { CreateSolidBrush(subtext) },
        }
    }

    /// Free the brushes. Call before replacing a `Theme` on a mode change.
    pub fn free(&self) {
        unsafe {
            DeleteObject(self.bg_brush as _);
            DeleteObject(self.surface_brush as _);
            DeleteObject(self.sep_brush as _);
            DeleteObject(self.warn_brush as _);
            DeleteObject(self.danger_brush as _);
            DeleteObject(self.sub_brush as _);
        }
    }
}

fn warn(dark: bool) -> u32 {
    if dark { rgb(0xfc, 0xb7, 0x43) } else { rgb(0x9a, 0x63, 0x00) }
}

fn danger(dark: bool) -> u32 {
    if dark { rgb(0xf5, 0x62, 0x62) } else { rgb(0xc4, 0x2b, 0x1c) }
}

/// The icon badge's two colors, for a given surface ink.
///
/// Separate from [`Theme`] because the badge follows [`taskbar_dark`] and every
/// other role follows the app theme -- two different settings, which
/// Personalization > Colors > Custom lets differ. Same two values either way, so
/// the badge and the flyout's explanation rule cannot drift apart.
pub fn badge_colors(dark: bool) -> (u32, u32) {
    (warn(dark), danger(dark))
}

/// True when the *taskbar* is dark, which is what a notification-area icon has to
/// contrast against.
///
/// Deliberately not [`Theme::dark`]: `AppsUseLightTheme` and `SystemUsesLightTheme`
/// are separate settings, and Settings ▸ Personalization ▸ Colors ▸ Custom lets
/// one be light while the other is dark.
pub fn taskbar_dark() -> bool {
    personalize_dark("SystemUsesLightTheme")
}

/// Read `AppsUseLightTheme` (0 == dark). Defaults to light if the value is absent.
fn os_prefers_dark() -> bool {
    personalize_dark("AppsUseLightTheme")
}

/// One of the Personalize DWORDs, where 0 means dark. Absent means light, which
/// is what Windows itself assumes.
fn personalize_dark(value: &str) -> bool {
    let subkey = wide("Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize");
    let value = wide(value);
    let mut data: u32 = 1;
    let mut size = size_of::<u32>() as u32;
    let ok = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            &mut data as *mut u32 as *mut c_void,
            &mut size,
        )
    };
    ok == 0 && data == 0
}

/// Apply the dark/light title bar + rounded corners to a top-level window.
pub fn apply_frame(hwnd: HWND, dark: bool) {
    let on: BOOL = if dark { 1 } else { 0 };
    unsafe {
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_USE_IMMERSIVE_DARK_MODE,
            &on as *const _ as *const c_void,
            size_of::<BOOL>() as u32,
        );
        let corner = DWMWCP_ROUND;
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_WINDOW_CORNER_PREFERENCE,
            &corner as *const _ as *const c_void,
            size_of::<i32>() as u32,
        );
    }
}

/// Route a control through the light/dark visual-style set (scrollbars, edit frame,
/// etc.). `dark` picks Explorer's dark theme atom.
pub fn apply_control_theme(hwnd: HWND, dark: bool) {
    let name = wide(if dark { "DarkMode_Explorer" } else { "Explorer" });
    unsafe { SetWindowTheme(hwnd, name.as_ptr(), std::ptr::null()) };
}

/// Strip a control's visual style so our own colors apply -- a themed progress bar
/// ignores PBM_SETBARCOLOR otherwise (it always draws the theme's green).
pub fn disable_visual_style(hwnd: HWND) {
    let empty = wide("");
    unsafe { SetWindowTheme(hwnd, empty.as_ptr(), empty.as_ptr()) };
}

// ---- undocumented uxtheme ordinals (dark menus / global app mode) ----------------

#[repr(C)]
#[allow(dead_code)]
enum PreferredAppMode {
    Default = 0,
    AllowDark = 1,
    ForceDark = 2,
    ForceLight = 3,
}

type FnSetPreferredAppMode = unsafe extern "system" fn(i32) -> i32;
type FnAllowDarkModeForWindow = unsafe extern "system" fn(HWND, BOOL) -> BOOL;
type FnFlushMenuThemes = unsafe extern "system" fn();

/// Opt the whole process into dark mode for the bits only reachable via uxtheme's
/// ordinal-only exports (notably `TrackPopupMenu`). Best-effort: a build that no
/// longer exports these leaves menus light but everything else intact. Call once at
/// startup with the resolved mode.
pub fn init_app_dark_mode(dark: bool) {
    unsafe {
        let lib = LoadLibraryW(wide("uxtheme.dll").as_ptr());
        if lib.is_null() {
            return;
        }
        // Ordinal 135: SetPreferredAppMode (build >= 18334); 136: FlushMenuThemes.
        if let Some(p) = GetProcAddress(lib, 135 as *const u8) {
            let set: FnSetPreferredAppMode = transmute(p);
            let mode =
                if dark { PreferredAppMode::AllowDark } else { PreferredAppMode::ForceLight };
            set(mode as i32);
        }
        if let Some(p) = GetProcAddress(lib, 136 as *const u8) {
            let flush: FnFlushMenuThemes = transmute(p);
            flush();
        }
    }
}

/// Let this specific window (menu owner) render its non-client menu bits dark.
/// Ordinal 133: AllowDarkModeForWindow.
pub fn allow_dark_for_window(hwnd: HWND, dark: bool) {
    unsafe {
        let lib = LoadLibraryW(wide("uxtheme.dll").as_ptr());
        if lib.is_null() {
            return;
        }
        if let Some(p) = GetProcAddress(lib, 133 as *const u8) {
            let allow: FnAllowDarkModeForWindow = transmute(p);
            allow(hwnd, if dark { 1 } else { 0 });
        }
    }
}
