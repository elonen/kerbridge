//! The presentation vocabulary every window here shares: the color roles, the
//! stock-control factories, the vertical layout cursor, and the `WM_CTLCOLOR*`
//! and owner-draw handlers that turn a role into ink.
//!
//! Nothing in here knows what it is showing. The rows that do -- the ones that
//! read a `Status` or carry a command id -- live with the surface that owns them.

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    DrawFocusRect, DrawTextW, FillRect, HFONT, SelectObject, SetBkColor, SetBkMode, SetTextColor,
    TRANSPARENT,
};
use windows_sys::Win32::UI::Controls::DRAWITEMSTRUCT;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DestroyWindow, EnumChildWindows, GWLP_USERDATA, GetWindowLongPtrW,
    GetWindowTextW, SendMessageW, SetWindowLongPtrW, WM_SETFONT, WS_CHILD, WS_TABSTOP, WS_VISIBLE,
};

use crate::app::app;
use crate::sys::{dip, measure_text, wide};
use crate::theme::{apply_control_theme, disable_visual_style};

// STATIC text color roles, stashed per-control in GWLP_USERDATA and read in WM_CTLCOLOR.
pub(crate) const ROLE_TEXT: isize = 0;
pub(crate) const ROLE_SUB: isize = 1;
pub(crate) const ROLE_ACCENT: isize = 2;
pub(crate) const ROLE_WARN: isize = 3;
pub(crate) const ROLE_DANGER: isize = 4;
pub(crate) const ROLE_OK: isize = 5;
pub(crate) const ROLE_FIELD: isize = 6; // EDIT with a field background
pub(crate) const ROLE_FLAT_SUB: isize = 7; // read-only EDIT: window background, subtext color
pub(crate) const ROLE_FLAT_TEXT: isize = 8; // read-only EDIT: window background, primary color
pub(crate) const ROLE_SEP: isize = 9; // empty STATIC filled with the separator brush (hairline)
pub(crate) const ROLE_GEAR: isize = 10; // owner-draw flat button: centered icon glyph
pub(crate) const ROLE_DISCLOSURE: isize = 11; // owner-draw flat button: left chevron + label
// The explanation block's vertical rule: the same empty STATIC as the hairline,
// with its width and height swapped, and the severity of the whole block in its
// fill. One color signal per fact -- the lines inside stay plain text.
pub(crate) const ROLE_RULE_WARN: isize = 12;
pub(crate) const ROLE_RULE_DANGER: isize = 13;
pub(crate) const ROLE_RULE_SUB: isize = 14;

/// A button's notification code, in the high word of its `WM_COMMAND`.
pub(crate) const BN_CLICKED: u16 = 0;

// Misc window messages / style bits used inline (numeric -- small and version-stable).
pub(crate) const WM_SETICON: u32 = 0x0080;
pub(crate) const ICON_SMALL: usize = 0;
pub(crate) const ICON_BIG: usize = 1;
const BM_GETCHECK: u32 = 0x00F0;
const BM_SETCHECK: u32 = 0x00F1;
pub(crate) const WM_DRAWITEM: u32 = 0x002B;
const WM_GETFONT: u32 = 0x0031;
const ODS_SELECTED: u32 = 0x0001; // owner-draw item is pressed
const ODS_FOCUS: u32 = 0x0010; // owner-draw item has keyboard focus
pub(crate) const EM_SETCUEBANNER: u32 = 0x1501; // EDIT placeholder text
pub(crate) const SWP_NOMOVE: u32 = 0x0002;
pub(crate) const SWP_NOZORDER: u32 = 0x0004;
pub(crate) const SWP_NOACTIVATE: u32 = 0x0010;

// Progress-bar messages (numeric to avoid feature-name churn across windows-sys).
pub(crate) const PBM_SETRANGE32: u32 = 0x0406;
pub(crate) const PBM_SETPOS: u32 = 0x0402;
pub(crate) const PBM_SETBARCOLOR: u32 = 0x0409;
pub(crate) const PBM_SETBKCOLOR: u32 = 0x2001;
pub(crate) const PBM_SETMARQUEE: u32 = 0x040A;
pub(crate) const PBS_MARQUEE: u32 = 0x0008;

// STATIC / EDIT / BUTTON style bits (numeric -- small and version-stable).
pub(crate) const SS_LEFT: u32 = 0x0000;
pub(crate) const SS_RIGHT: u32 = 0x0002;
pub(crate) const SS_ICON: u32 = 0x0003;
pub(crate) const SS_REALSIZECONTROL: u32 = 0x0040;
pub(crate) const ES_RIGHT: u32 = 0x0001;
pub(crate) const ES_MULTILINE: u32 = 0x0004;
pub(crate) const ES_AUTOHSCROLL: u32 = 0x0080;
pub(crate) const ES_READONLY: u32 = 0x0800;
pub(crate) const BS_PUSHBUTTON: u32 = 0x0000;
pub(crate) const BS_DEFPUSHBUTTON: u32 = 0x0001;
pub(crate) const BS_AUTOCHECKBOX: u32 = 0x0003;
pub(crate) const BS_OWNERDRAW: u32 = 0x0000_000B;
pub(crate) const WS_EX_CLIENTEDGE: u32 = 0x0000_0200;

// DrawText format flags (numeric -- small and version-stable).
pub(crate) const DT_LEFT: u32 = 0x0000;
pub(crate) const DT_CENTER: u32 = 0x0001;
pub(crate) const DT_SINGLELINE: u32 = 0x0020;
pub(crate) const DT_VCENTER: u32 = 0x0004;

// ---- layout builder --------------------------------------------------------

/// A running vertical cursor that creates child controls and advances `y`. All sizes
/// are given in logical px and scaled to the window DPI.
pub(crate) struct Col {
    pub(crate) hwnd: HWND,
    pub(crate) dpi: u32,
    pub(crate) x: i32,
    pub(crate) y: i32,
    pub(crate) w: i32,
}

impl Col {
    pub(crate) fn d(&self, v: i32) -> i32 {
        dip(v, self.dpi)
    }

    pub(crate) fn gap(&mut self, v: i32) {
        self.y += self.d(v);
    }

    /// Full-width hairline separator with breathing room above and below (an empty
    /// STATIC filled via the separator brush in WM_CTLCOLORSTATIC).
    pub(crate) fn separator(&mut self) {
        self.gap(12);
        let h = self.d(1).max(1);
        make_static(
            self.hwnd,
            "",
            self.x,
            self.y,
            self.w,
            h,
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            ROLE_SEP,
            false,
        );
        self.y += h;
        self.gap(12);
    }

    /// A full-width, keyboard-focusable disclosure header: a chevron + label that
    /// toggles a collapsible section. Owner-drawn (see [`on_drawitem`]) so it stays
    /// flat like a heading yet is reachable by Tab and fired by Space/Enter.
    pub(crate) fn disclosure(&mut self, label: &str, expanded: bool, id: u16) {
        let h = self.d(22);
        let chevron = if expanded { "\u{25BE}" } else { "\u{25B8}" }; // ▾ expanded / ▸ collapsed
        let text = format!("{chevron}  {label}");
        make_flat_button(
            self.hwnd,
            &text,
            self.x,
            self.y,
            self.w,
            h,
            id,
            ROLE_DISCLOSURE,
            font_for(false),
        );
        self.y += h;
    }

    /// Single-line label.
    pub(crate) fn line(&mut self, text: &str, role: isize) {
        let h = self.d(18);
        make_static(
            self.hwnd,
            text,
            self.x,
            self.y,
            self.w,
            h,
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            role,
            false,
        );
        self.y += h;
    }

    /// Word-wrapped paragraph, height measured so nothing clips.
    pub(crate) fn wrap(&mut self, text: &str, role: isize) {
        let font = font_for(false);
        let h = measure_text(font, text, self.w).max(self.d(16));
        make_static(
            self.hwnd,
            text,
            self.x,
            self.y,
            self.w,
            h,
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            role,
            false,
        );
        self.y += h;
    }

    /// A bold section heading.
    pub(crate) fn heading(&mut self, text: &str) {
        let h = self.d(20);
        make_static(
            self.hwnd,
            text,
            self.x,
            self.y,
            self.w,
            h,
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            ROLE_TEXT,
            true,
        );
        self.y += h;
    }

    /// The literal plan a confirmation is made of, in a copyable monospace field.
    pub(crate) fn mono(&mut self, text: &str) {
        let a = app();
        let h = measure_text(a.font_mono, text, self.w) + self.d(4);
        let style = WS_CHILD | WS_VISIBLE | ES_READONLY | ES_MULTILINE;
        unsafe {
            let hwnd = CreateWindowExW(
                0,
                wide("EDIT").as_ptr(),
                wide(text).as_ptr(),
                style,
                self.x,
                self.y,
                self.w,
                h,
                self.hwnd,
                std::ptr::null_mut(),
                a.hinstance,
                std::ptr::null(),
            );
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, ROLE_FLAT_TEXT);
            SendMessageW(hwnd, WM_SETFONT, a.font_mono as WPARAM, 1);
        }
        self.y += h;
    }

    /// Larger semibold headline so the (color-coded) condition reads at a glance.
    /// Height is measured so a long or translated headline wraps instead of clipping.
    pub(crate) fn title(&mut self, text: &str, role: isize) {
        let font = app().font_title;
        let h = measure_text(font, text, self.w).max(self.d(24));
        let hwnd = make_static(
            self.hwnd,
            text,
            self.x,
            self.y,
            self.w,
            h,
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            role,
            true,
        );
        unsafe { SendMessageW(hwnd, WM_SETFONT, font as WPARAM, 1) };
        self.y += h;
    }

    /// Read-only EDIT whose background matches the window -- reads as plain text but is
    /// selectable/copyable. `right` right-aligns (for detail values).
    pub(crate) fn flat_field(&mut self, text: &str, role: isize, right: bool) {
        let h = self.d(20);
        make_flat_edit(self.hwnd, text, self.x, self.y, self.w, h, role, right);
        self.y += h;
    }

    /// A single-line EDIT with a field background. Returns the handle so Settings
    /// can read it back. `editable` false = read-only (policy-managed value).
    pub(crate) fn edit(&mut self, text: &str, editable: bool, id: u16) -> HWND {
        let h = self.d(24);
        let style = WS_CHILD
            | WS_VISIBLE
            | WS_TABSTOP
            | ES_AUTOHSCROLL
            | if editable { 0 } else { ES_READONLY };
        let hwnd = unsafe {
            let hwnd = CreateWindowExW(
                WS_EX_CLIENTEDGE,
                wide("EDIT").as_ptr(),
                wide(text).as_ptr(),
                style,
                self.x,
                self.y,
                self.w,
                h,
                self.hwnd,
                id as isize as _,
                app().hinstance,
                std::ptr::null(),
            );
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, ROLE_FIELD);
            SendMessageW(hwnd, WM_SETFONT, font_for(false) as WPARAM, 1);
            apply_control_theme(hwnd, app().theme.get().dark);
            hwnd
        };
        self.y += h;
        hwnd
    }

    pub(crate) fn progress_bar(&mut self, h: i32, style: u32) -> HWND {
        unsafe {
            let pb = CreateWindowExW(
                0,
                wide("msctls_progress32").as_ptr(),
                std::ptr::null(),
                WS_CHILD | WS_VISIBLE | style,
                self.x,
                self.y,
                self.w,
                h,
                self.hwnd,
                std::ptr::null_mut(),
                app().hinstance,
                std::ptr::null(),
            );
            disable_visual_style(pb); // let PBM_SETBARCOLOR take effect
            pb
        }
    }
}

pub(crate) fn font_for(bold: bool) -> HFONT {
    let a = app();
    if bold { a.font_bold } else { a.font }
}

// ---- control factories -----------------------------------------------------

/// Create a STATIC label, stash its color role, set its font.
#[allow(clippy::too_many_arguments)]
pub(crate) fn make_static(
    parent: HWND,
    text: &str,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    style: u32,
    role: isize,
    bold: bool,
) -> HWND {
    unsafe {
        let hwnd = CreateWindowExW(
            0,
            wide("STATIC").as_ptr(),
            wide(text).as_ptr(),
            style,
            x,
            y,
            w,
            h,
            parent,
            std::ptr::null_mut(),
            app().hinstance,
            std::ptr::null(),
        );
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, role);
        SendMessageW(hwnd, WM_SETFONT, font_for(bold) as WPARAM, 1);
        hwnd
    }
}

/// Create a read-only, borderless EDIT that blends into the window background (so it
/// reads as plain text) yet is selectable/copyable. `role` sets its text color.
#[allow(clippy::too_many_arguments)]
pub(crate) fn make_flat_edit(
    parent: HWND,
    text: &str,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    role: isize,
    right: bool,
) -> HWND {
    let style =
        WS_CHILD | WS_VISIBLE | ES_READONLY | ES_AUTOHSCROLL | if right { ES_RIGHT } else { 0 };
    unsafe {
        let hwnd = CreateWindowExW(
            0,
            wide("EDIT").as_ptr(),
            wide(text).as_ptr(),
            style,
            x,
            y,
            w,
            h,
            parent,
            std::ptr::null_mut(),
            app().hinstance,
            std::ptr::null(),
        );
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, role);
        SendMessageW(hwnd, WM_SETFONT, font_for(false) as WPARAM, 1);
        hwnd
    }
}

/// An ordinary push button.
#[allow(clippy::too_many_arguments)]
pub(crate) fn make_button(
    parent: HWND,
    label: &str,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: u16,
    primary: bool,
) -> HWND {
    let style =
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | if primary { BS_DEFPUSHBUTTON } else { BS_PUSHBUTTON };
    unsafe {
        let b = CreateWindowExW(
            0,
            wide("BUTTON").as_ptr(),
            wide(label).as_ptr(),
            style,
            x,
            y,
            w,
            h,
            parent,
            id as isize as _,
            app().hinstance,
            std::ptr::null(),
        );
        SendMessageW(b, WM_SETFONT, font_for(false) as WPARAM, 1);
        apply_control_theme(b, app().theme.get().dark);
        b
    }
}

/// Create a flat, borderless owner-draw BUTTON, painted by [`on_drawitem`]. Unlike
/// an SS_NOTIFY static (which the dialog manager skips) it is a real control, so
/// Tab reaches it and Space/Enter fire it -- the gear and the disclosure rows use
/// this so they are keyboard-reachable, not just clickable.
#[allow(clippy::too_many_arguments)]
pub(crate) fn make_flat_button(
    parent: HWND,
    text: &str,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: u16,
    role: isize,
    font: HFONT,
) -> HWND {
    unsafe {
        let hwnd = CreateWindowExW(
            0,
            wide("BUTTON").as_ptr(),
            wide(text).as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            x,
            y,
            w,
            h,
            parent,
            id as isize as _,
            app().hinstance,
            std::ptr::null(),
        );
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, role);
        SendMessageW(hwnd, WM_SETFONT, font as WPARAM, 1);
        hwnd
    }
}

/// Paint a flat owner-draw button (the header gear, the disclosure rows): the
/// control's caption in the subtext color on the window background, plus a focus
/// rectangle when it holds keyboard focus and a pressed tint while held down.
pub(crate) fn on_drawitem(lparam: LPARAM) -> LRESULT {
    let dis = unsafe { &*(lparam as *const DRAWITEMSTRUCT) };
    // Settings' tab strip owns its own items; everything else here is one of ours.
    if app().settings.draw_tab_item(dis) {
        return 1;
    }
    let t = app().theme.get();
    let role = unsafe { GetWindowLongPtrW(dis.hwndItem, GWLP_USERDATA) };
    unsafe {
        let brush = if dis.itemState & ODS_SELECTED != 0 { t.surface_brush } else { t.bg_brush };
        FillRect(dis.hDC, &dis.rcItem, brush);

        // The system does not reliably pre-select the button's font for owner draw,
        // so select it ourselves -- otherwise the Segoe MDL2 gear glyph renders as a
        // box in the default font.
        let font = SendMessageW(dis.hwndItem, WM_GETFONT, 0, 0);
        let old = (font != 0).then(|| SelectObject(dis.hDC, font as _));

        SetBkMode(dis.hDC, TRANSPARENT as i32);
        SetTextColor(dis.hDC, t.subtext);
        let mut text = [0u16; 128];
        let n = GetWindowTextW(dis.hwndItem, text.as_mut_ptr(), text.len() as i32);
        let mut rc = dis.rcItem;
        let align = if role == ROLE_GEAR { DT_CENTER } else { DT_LEFT };
        DrawTextW(dis.hDC, text.as_ptr(), n, &mut rc, align | DT_VCENTER | DT_SINGLELINE);

        if let Some(old) = old {
            SelectObject(dis.hDC, old);
        }
        if dis.itemState & ODS_FOCUS != 0 {
            DrawFocusRect(dis.hDC, &dis.rcItem);
        }
    }
    1
}

// ---- shared control coloring ----------------------------------------------

/// Handle WM_CTLCOLOR* for a themed child: set text + background from its role and
/// return the matching brush. `wparam` is the HDC, `lparam` the child HWND.
pub(crate) fn ctl_color(wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let a = app();
    let t = a.theme.get();
    let child = lparam as HWND;
    let role = unsafe { GetWindowLongPtrW(child, GWLP_USERDATA) };
    let text = match role {
        ROLE_SUB | ROLE_FLAT_SUB => t.subtext,
        ROLE_ACCENT => t.accent,
        ROLE_WARN => t.warn,
        ROLE_DANGER => t.danger,
        ROLE_OK => t.ok,
        _ => t.text,
    };
    let (bg, brush) = match role {
        ROLE_SEP => (t.sep, t.sep_brush), // hairline separator: fill solid
        ROLE_RULE_WARN => (t.warn, t.warn_brush),
        ROLE_RULE_DANGER => (t.danger, t.danger_brush),
        ROLE_RULE_SUB => (t.subtext, t.sub_brush),
        ROLE_FIELD => (t.surface, t.surface_brush), // editable field look
        _ => (t.bg, t.bg_brush),                    // everything else incl. flat fields
    };
    unsafe {
        let hdc = wparam as _;
        SetTextColor(hdc, text);
        SetBkColor(hdc, bg);
        SetBkMode(hdc, TRANSPARENT as i32);
    }
    brush as LRESULT
}

pub(crate) fn destroy_children(parent: HWND) {
    unsafe extern "system" fn collect(hwnd: HWND, lparam: LPARAM) -> i32 {
        let v = unsafe { &mut *(lparam as *mut Vec<HWND>) };
        v.push(hwnd);
        1
    }
    let mut v: Vec<HWND> = Vec::new();
    unsafe {
        EnumChildWindows(parent, Some(collect), &mut v as *mut _ as LPARAM);
        for h in v {
            DestroyWindow(h);
        }
    }
}

pub(crate) fn retheme_children(parent: HWND, dark: bool) {
    unsafe extern "system" fn each(hwnd: HWND, lparam: LPARAM) -> i32 {
        let dark = lparam != 0;
        apply_control_theme(hwnd, dark);
        1
    }
    unsafe { EnumChildWindows(parent, Some(each), dark as LPARAM) };
}

pub(crate) fn window_text(hwnd: HWND) -> String {
    if hwnd.is_null() {
        return String::new();
    }
    let mut buf = [0u16; 1024];
    let n = unsafe { GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32) };
    String::from_utf16_lossy(&buf[..n.max(0) as usize])
}

pub(crate) fn is_checked(hwnd: HWND) -> bool {
    !hwnd.is_null() && unsafe { SendMessageW(hwnd, BM_GETCHECK, 0, 0) } == 1
}

pub(crate) fn set_checked(hwnd: HWND, on: bool) {
    unsafe { SendMessageW(hwnd, BM_SETCHECK, usize::from(on), 0) };
}
