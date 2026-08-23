//! The state every surface reads, and the one pointer that publishes it to the
//! window procedures.

use std::cell::{Cell, RefCell};
use std::time::Instant;

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::Graphics::Gdi::HFONT;
use windows_sys::Win32::UI::HiDpi::{GetDpiForWindow, GetSystemMetricsForDpi};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    HICON, IDC_ARROW, LoadCursorW, RegisterClassW, WNDCLASSW,
};

use kerbridge_client::describe::{Action, Condition};

use crate::sys::{svg_to_hicon, wide};
use crate::theme::Theme;
use crate::{modal, settings};

pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

/// `SM_CXSMICON`: the size the shell actually asks a notification-area icon for.
pub(crate) const SM_CXSMICON: u32 = 49;
/// `SM_CXICON`: the large-icon metric, what a title bar's `ICON_BIG` is scaled to.
pub(crate) const SM_CXICON: u32 = 11;

// The logo, single source of truth for every icon (tray, header, title bar) and
// shared with every other platform's packaging.
pub(crate) const LOGO_SVG: &str = include_str!("../../assets/app-icon.svg");

/// Windows and shared UI state. Single-threaded (the message loop), so interior
/// mutability via `Cell` is enough and lets window procs take `&App` without the
/// reentrancy hazard a `RefCell` would carry through `SendMessage`. Everything
/// that is not a window handle lives in `agent`.
pub(crate) struct App {
    pub(crate) hinstance: HWND,
    pub(crate) font: HFONT,
    pub(crate) font_bold: HFONT,
    pub(crate) font_title: HFONT, // larger semibold, for the condition headline
    pub(crate) font_icon: HFONT,  // Segoe MDL2 Assets, for the gear glyph
    pub(crate) font_mono: HFONT,  // the literal command plans inside the modal
    /// The plain logo, one `HICON` per pixel size, rendered on demand and kept
    /// for the process's life.
    ///
    /// Keyed by size because its consumers ask for different ones and every one
    /// of them moves with the monitor. A single raster leaves all but one of them
    /// resampling a finished bitmap -- `SS_REALSIZECONTROL` stretching it to the
    /// control, or the shell halving it for a title bar -- which is point-sampled
    /// rather than re-rendered. Measured 2026-08-05: a 32 px raster drawn at 34
    /// left exactly-duplicated ink rows at regular intervals, the nearest-
    /// neighbor signature, visible as a doubled line through the paw.
    pub(crate) logos: RefCell<Vec<(u32, HICON)>>,
    pub(crate) theme: Cell<Theme>,
    pub(crate) owner: HWND,
    pub(crate) flyout: HWND,
    /// Kerberos details start collapsed in the flyout; toggled by its disclosure.
    pub(crate) details_expanded: Cell<bool>,
    pub(crate) flyout_visible: Cell<bool>,
    pub(crate) tray_cur: Cell<HICON>, // current tray icon (logo + badge); freed on each swap
    /// Last rendered whole minute of ticket life, so the 1 Hz timer only rebuilds
    /// the flyout when the text it shows would actually change.
    pub(crate) shown_minute: Cell<i64>,
    /// Last rendered condition, so the icon and infotip follow a change the clock
    /// caused rather than an event.
    pub(crate) shown_condition: Cell<Option<Condition>>,
    /// When the flyout last hid itself because it lost activation. A tray click
    /// deactivates it *before* the shell delivers the click, so without this the
    /// click that closes the flyout immediately reopens it.
    ///
    /// `None` until it first happens, rather than a time far enough in the past
    /// to have expired: `Instant` is anchored at boot on Windows, so subtracting
    /// from `now()` panics for as long as the machine has been up less than the
    /// amount subtracted. An agent that starts with the session hits exactly that.
    pub(crate) auto_hidden_at: Cell<Option<Instant>>,
    /// Which flyout button each command id stands for, rebuilt with the buttons.
    /// The id carries the action, never the wording: labels are chosen by state,
    /// and an id keyed on a label is how one control ends up wearing another's
    /// sentence.
    pub(crate) buttons: RefCell<Vec<Action>>,
    /// Same, for the tray menu.
    pub(crate) menu_actions: RefCell<Vec<Action>>,
    pub(crate) settings: settings::State,
    pub(crate) modal: modal::State,
}

impl App {
    /// The logo rasterized at exactly `size` pixels, rendered on the first ask and
    /// cached after. Callers pass the size they are about to draw at, so nothing
    /// downstream has to stretch.
    pub(crate) fn logo_at(&self, size: u32) -> HICON {
        let size = size.max(1);
        // The borrow is released before the return in both arms: callers reach
        // `SendMessageW` with this handle, and a live borrow across that is how a
        // re-entrant paint would panic.
        if let Some(&(_, h)) = self.logos.borrow().iter().find(|&&(s, _)| s == size) {
            return h;
        }
        let h = svg_to_hicon(LOGO_SVG, size);
        self.logos.borrow_mut().push((size, h));
        h
    }

    /// The logo at the size this window's title bar will ask for. `WM_SETICON`
    /// stores whatever it is handed and the shell scales it to the metric, so the
    /// two icons want different renders, not one icon sent twice.
    pub(crate) fn title_icons(&self, hwnd: HWND) -> (HICON, HICON) {
        let dpi = unsafe { GetDpiForWindow(hwnd) }.max(96);
        let sm = unsafe { GetSystemMetricsForDpi(SM_CXSMICON as i32, dpi) }.max(16) as u32;
        let big = unsafe { GetSystemMetricsForDpi(SM_CXICON as i32, dpi) }.max(16) as u32;
        (self.logo_at(sm), self.logo_at(big))
    }
}

thread_local! {
    static APP: Cell<*const App> = const { Cell::new(std::ptr::null()) };
}

pub(crate) fn publish(app: &'static App) {
    APP.with(|c| c.set(app as *const App));
}

pub(crate) fn app() -> &'static App {
    app_opt().expect("App initialized before any window message is handled")
}

/// `App` is only published after the windows exist, so a message dispatched
/// during `CreateWindowExW` would reach a window procedure with nothing behind it.
/// Nothing pumps in that window today; the window procedures check anyway, because
/// the alternative failure is a null dereference at startup with no diagnostic.
pub(crate) fn app_opt() -> Option<&'static App> {
    let p = APP.with(|c| c.get());
    (!p.is_null()).then(|| unsafe { &*p })
}

pub(crate) fn register_class(
    name: &str,
    proc: windows_sys::Win32::UI::WindowsAndMessaging::WNDPROC,
    hinstance: HWND,
) {
    // Bind the class name so it outlives RegisterClassW -- an inline `wide(name).as_ptr()`
    // in the struct would drop the Vec before the call reads it.
    let name_w = wide(name);
    unsafe {
        let wc = WNDCLASSW {
            style: 0,
            lpfnWndProc: proc,
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinstance,
            hIcon: std::ptr::null_mut(),
            hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: name_w.as_ptr(),
        };
        RegisterClassW(&wc);
    }
}
