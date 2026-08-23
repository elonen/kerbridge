//! Settings: three tabs, sorted by subject, routine to rare, destructive last.
//!
//! ```text
//! ┌ Basic ┬ Advanced ┬ About ┐
//! │ Connection      broker address · sub or managed cue · [Save]
//! │ Sign-in         ☑ Start at login
//! │                 ☑ Use Windows sign-in when possible
//! ┌ Advanced
//! │ Authorization   state line · "Authorize this device for" · [Authorize…] [Remove…]
//! │ Windows setup   enrollment state line · 🛡[Set up again…] 🛡[Forget {realm}…]
//! │ Troubleshoot    [Open log folder]
//! ┌ About           logo · name · version · copyright · license · URL
//! ```
//!
//! **Instant-apply, and no OK/Cancel.** The one-shots are confirmed in the
//! parent and fire on click, so a Cancel beside them could not undo any of them
//! -- it would teach a rule the same window immediately breaks.
//!
//! **The two text fields keep an explicit Save**, disabled until changed. They
//! cannot commit on blur, because both are consequential: a broker change purges
//! the realm, gives up the grant and drops the refresh token, so a half-typed
//! address landing on focus-loss would wipe the session; and the target field
//! writes what this device is expected to be working as. The cost is stated: a
//! user who types an address and closes the window without committing loses it,
//! which is cheaper than a Cancel the rest of the window contradicts.
//!
//! **`SysTabControl32` is owner-drawn, because it will not take a dark theme.**
//! Measured: `SetWindowTheme(hwnd, L"DarkMode_Explorer", NULL)` returns `S_OK`
//! and changes not one pixel -- byte-identical across four conditions, with an
//! `EDIT` in the same window going dark as the positive control. So
//! `TCS_OWNERDRAWFIXED` + `WM_DRAWITEM` draws the items, a subclassed
//! `WM_ERASEBKGND` draws the strip behind and beside them, and a page child over
//! `TCM_ADJUSTRECT`'s rect covers the display area *and* the light border around
//! it. Selected, hot and focus rendering become ours -- the exact affordance the
//! theme was giving away free, and an unhoverable strip is worse than a light one.

use std::cell::{Cell, RefCell};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    DrawFocusRect, DrawTextW, FillRect, InvalidateRect, SelectObject, SetBkMode, SetTextColor,
    TRANSPARENT,
};
use windows_sys::Win32::UI::Controls::{BCM_SETSHIELD, DRAWITEMSTRUCT, NMHDR, TCITEMW};
use windows_sys::Win32::UI::HiDpi::{AdjustWindowRectExForDpi, GetDpiForWindow};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
    EnableWindow, TRACKMOUSEEVENT, TrackMouseEvent,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CallWindowProcW, CreateWindowExW, DefWindowProcW, GWLP_WNDPROC, GetWindowRect, IsWindowVisible,
    SW_HIDE, SW_SHOW, SendMessageW, SetForegroundWindow, SetWindowLongPtrW, SetWindowPos,
    ShowWindow, WM_CLOSE, WM_COMMAND, WM_CTLCOLORBTN, WM_CTLCOLOREDIT, WM_CTLCOLORSTATIC,
    WM_ERASEBKGND, WM_GETFONT, WM_MOUSEMOVE, WM_NOTIFY, WM_SETFONT, WNDPROC, WS_CAPTION, WS_CHILD,
    WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
};

use kerbridge_client::agent;
use kerbridge_client::describe::Action;
use kerbridge_client::strings::{fill, tr};

use crate::app::{App, VERSION, app, register_class};
use crate::sys::{center_on_work_area, client_size, dip, hiword, loword, measure_width, wide};
use crate::theme::{apply_control_theme, apply_frame};
use crate::ui::{
    BN_CLICKED, BS_AUTOCHECKBOX, Col, DT_CENTER, DT_SINGLELINE, DT_VCENTER, ICON_BIG, ICON_SMALL,
    ROLE_SUB, ROLE_TEXT, SS_ICON, SS_LEFT, SS_REALSIZECONTROL, SWP_NOACTIVATE, SWP_NOMOVE,
    SWP_NOZORDER, WM_SETICON, ctl_color, destroy_children, font_for, is_checked, make_button,
    make_static, retheme_children, set_checked, window_text,
};

const SETTINGS_CLASS: &str = "NasAuthSettings";
const PAGE_CLASS: &str = "NasAuthSettingsPage";
const STM_SETICON: u32 = 0x0170;

const WEBSITE: &str = "https://kerbridge.org/";
// Shown verbatim on the About tab, every locale.
const COPYRIGHT: &str = "© 2026 Jarno Elonen";

// Tab-control messages and styles (numeric -- small and version-stable).
const TCS_OWNERDRAWFIXED: u32 = 0x2000;
const TCM_INSERTITEMW: u32 = 0x133E;
const TCM_ADJUSTRECT: u32 = 0x1328;
const TCM_GETITEMRECT: u32 = 0x130A;
const TCM_GETCURSEL: u32 = 0x130B;
const TCM_HITTEST: u32 = 0x130D;
const TCIF_TEXT: u32 = 0x0001;
/// `TCN_SELCHANGE` = `TCN_FIRST - 1`, and `TCN_FIRST` is -550.
const TCN_SELCHANGE: u32 = (0u32).wrapping_sub(551);
const TME_LEAVE: u32 = 0x0000_0002;
/// `WM_MOUSELEAVE`, which windows-sys does not export.
const WM_MOUSELEAVE: u32 = 0x02A3;
const ODS_SELECTED: u32 = 0x0001;
const ODS_FOCUS: u32 = 0x0010;

// Command ids.
const CMD_SAVE: u16 = 400;
const CMD_AUTOSTART: u16 = 401;
const CMD_WAM: u16 = 402;
const CMD_BROKER: u16 = 403;
const CMD_GRANT_FOR: u16 = 404;
const CMD_AUTHORIZE: u16 = 405;
const CMD_GIVE_UP: u16 = 406;
const CMD_REENROLL: u16 = 407;
const CMD_UNENROLL: u16 = 408;
const CMD_OPEN_LOG: u16 = 409;
/// `EN_CHANGE`, in the high word of a WM_COMMAND from an EDIT.
const EN_CHANGE: u16 = 0x0300;

#[repr(C)]
struct TcHitTestInfo {
    pt: POINT,
    flags: u32,
}

/// Settings' own state. Lives in [`crate::app::App`], like every other window here.
pub(crate) struct State {
    hwnd: Cell<HWND>,
    tabs: Cell<HWND>,
    /// All three pages exist from the first open, so the window can be sized to
    /// the tallest of them once and never resize under a tab click.
    pages: RefCell<Vec<HWND>>,
    /// The tab-strip's original window procedure, kept for the subclass.
    tab_proc: Cell<isize>,
    hot_tab: Cell<i32>,
    broker: Cell<HWND>,
    grant_for: Cell<HWND>,
    save: Cell<HWND>,
    autostart: Cell<HWND>,
    wam: Cell<HWND>,
    /// What the two text fields held when the page was built. Save is what turns
    /// an edit into a change, so it stays disabled until one differs.
    committed: RefCell<(String, String)>,
}

impl Default for State {
    fn default() -> Self {
        let null = || Cell::new(std::ptr::null_mut());
        Self {
            hwnd: null(),
            tabs: null(),
            pages: RefCell::new(Vec::new()),
            tab_proc: Cell::new(0),
            hot_tab: Cell::new(-1),
            broker: null(),
            grant_for: null(),
            save: null(),
            autostart: null(),
            wam: null(),
            committed: RefCell::new((String::new(), String::new())),
        }
    }
}

impl State {
    pub(crate) fn window(&self) -> HWND {
        self.hwnd.get()
    }

    /// Paint one tab item, and say whether this `WM_DRAWITEM` was the strip's.
    ///
    /// Selected, hot and focus are all ours here: `WM_DRAWITEM` hands over items
    /// only, and the theme that renders those states is the one this control
    /// will not take.
    pub(crate) fn draw_tab_item(&self, dis: &DRAWITEMSTRUCT) -> bool {
        if dis.hwndItem != self.tabs.get() || self.tabs.get().is_null() {
            return false;
        }
        let a = app();
        let t = a.theme.get();
        let selected = dis.itemState & ODS_SELECTED != 0;
        let hot = self.hot_tab.get() == dis.itemID as i32;
        unsafe {
            let brush = if selected {
                t.bg_brush
            } else if hot {
                t.surface_brush
            } else {
                t.sep_brush
            };
            FillRect(dis.hDC, &dis.rcItem, brush);
            let font = SendMessageW(dis.hwndItem, WM_GETFONT, 0, 0);
            let old = (font != 0).then(|| SelectObject(dis.hDC, font as _));
            SetBkMode(dis.hDC, TRANSPARENT as i32);
            SetTextColor(dis.hDC, if selected { t.text } else { t.subtext });
            let label = tab_label(dis.itemID as usize);
            let w = wide(label);
            let mut rc = dis.rcItem;
            DrawTextW(dis.hDC, w.as_ptr(), -1, &mut rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            if let Some(old) = old {
                SelectObject(dis.hDC, old);
            }
            if dis.itemState & ODS_FOCUS != 0 {
                DrawFocusRect(dis.hDC, &dis.rcItem);
            }
        }
        true
    }
}

fn tab_label(i: usize) -> &'static str {
    let s = tr();
    match i {
        0 => s.tab_basic,
        1 => s.tab_advanced,
        _ => s.tab_about,
    }
}

pub(crate) fn register(hinstance: HWND) {
    register_class(SETTINGS_CLASS, Some(wndproc), hinstance);
    register_class(PAGE_CLASS, Some(page_wndproc), hinstance);
}

pub(crate) fn open() {
    let a = app();
    if a.settings.hwnd.get().is_null() {
        create();
    } else {
        // A changed broker, realm or policy since the last open, and any edit
        // left uncommitted: reopening Settings is a fresh start.
        layout_pages();
    }
    let hwnd = a.settings.hwnd.get();
    let mut r = RECT { left: 0, top: 0, right: 0, bottom: 0 };
    unsafe { GetWindowRect(hwnd, &mut r) };
    let (x, y) = center_on_work_area(r.right - r.left, r.bottom - r.top);
    unsafe {
        SetWindowPos(
            hwnd,
            std::ptr::null_mut(),
            x,
            y,
            0,
            0,
            SWP_NOZORDER | SWP_NOACTIVATE | 0x0001,
        );
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
    }
}

/// Rebuild the pages if the window is up, so an action taken from the flyout or
/// the tray is reflected here too.
pub(crate) fn refresh() {
    let a = app();
    if !a.settings.hwnd.get().is_null() && unsafe { IsWindowVisible(a.settings.hwnd.get()) } != 0 {
        layout_pages();
    }
}

pub(crate) fn retheme(dark: bool) {
    let hwnd = app().settings.hwnd.get();
    if !hwnd.is_null() {
        apply_frame(hwnd, dark);
        retheme_children(hwnd, dark);
        unsafe { InvalidateRect(hwnd, std::ptr::null(), 1) };
    }
}

fn create() {
    let a = app();
    let s = tr();
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            wide(SETTINGS_CLASS).as_ptr(),
            wide(s.settings_title).as_ptr(),
            WS_CAPTION | WS_SYSMENU,
            0,
            0,
            10,
            10,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            a.hinstance,
            std::ptr::null(),
        )
    };
    a.settings.hwnd.set(hwnd);
    apply_frame(hwnd, a.theme.get().dark);
    unsafe {
        let (small, big) = a.title_icons(hwnd);
        SendMessageW(hwnd, WM_SETICON, ICON_SMALL, small as LPARAM);
        SendMessageW(hwnd, WM_SETICON, ICON_BIG, big as LPARAM);
    }

    let dpi = unsafe { GetDpiForWindow(hwnd) }.max(96);
    let tabs = unsafe {
        let tabs = CreateWindowExW(
            0,
            wide("SysTabControl32").as_ptr(),
            std::ptr::null(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | TCS_OWNERDRAWFIXED,
            0,
            0,
            dip(460, dpi),
            dip(520, dpi),
            hwnd,
            std::ptr::null_mut(),
            a.hinstance,
            std::ptr::null(),
        );
        SendMessageW(tabs, WM_SETFONT, font_for(false) as WPARAM, 1);
        for i in 0..3 {
            let mut label = wide(tab_label(i));
            let mut item: TCITEMW = std::mem::zeroed();
            item.mask = TCIF_TEXT;
            item.pszText = label.as_mut_ptr();
            SendMessageW(tabs, TCM_INSERTITEMW, i, &item as *const _ as LPARAM);
        }
        // The strip's background is the one part `WM_DRAWITEM` never reaches.
        let old =
            SetWindowLongPtrW(tabs, GWLP_WNDPROC, tab_subclass as *const () as usize as isize);
        a.settings.tab_proc.set(old);
        tabs
    };
    a.settings.tabs.set(tabs);

    let mut pages = Vec::new();
    for _ in 0..3 {
        pages.push(unsafe {
            CreateWindowExW(
                0,
                wide(PAGE_CLASS).as_ptr(),
                std::ptr::null(),
                WS_CHILD,
                0,
                0,
                10,
                10,
                hwnd,
                std::ptr::null_mut(),
                a.hinstance,
                std::ptr::null(),
            )
        });
    }
    *a.settings.pages.borrow_mut() = pages;
    layout_pages();
}

/// Build all three pages, size the window to the tallest, and show the selected
/// one. A tab control sizes to its tallest page, so About costs nothing and the
/// window never floors to it.
fn layout_pages() {
    let a = app();
    let hwnd = a.settings.hwnd.get();
    let dpi = unsafe { GetDpiForWindow(hwnd) }.max(96);
    let pad = dip(14, dpi);
    let width = dip(460, dpi);
    // Where the display area starts, which is the strip's own height plus the
    // border it draws. `TCM_ADJUSTRECT` answers it from any rect, because it
    // depends on the strip and nothing else.
    let mut probe = RECT { left: 0, top: 0, right: width, bottom: width };
    unsafe {
        SendMessageW(a.settings.tabs.get(), TCM_ADJUSTRECT, 0, &mut probe as *mut _ as LPARAM);
    }
    let strip = probe.top;
    let inner = width - pad * 2;

    let view = agent::settings_view();
    let status = agent::status();
    *a.settings.committed.borrow_mut() = (view.broker_url.clone(), view.grant_for.clone());

    let pages = a.settings.pages.borrow().clone();
    let mut tallest = 0;
    for (i, page) in pages.iter().enumerate() {
        destroy_children(*page);
        let mut col = Col { hwnd: *page, dpi, x: pad, y: pad, w: inner };
        match i {
            0 => page_basic(&mut col, &view),
            1 => page_advanced(&mut col, &view, &status),
            _ => page_about(&mut col),
        }
        tallest = tallest.max(col.y + pad);
    }

    // The tab control's own height is the strip plus the tallest page, and the
    // page child covers the display area *and* the light border around it --
    // which is the residual cost of owner-drawing a control that will not theme.
    let tab_h = strip + tallest;
    unsafe {
        SetWindowPos(a.settings.tabs.get(), std::ptr::null_mut(), 0, 0, width, tab_h, SWP_NOZORDER);
    }
    // The page starts at the items' own bottom edge rather than at
    // `TCM_ADJUSTRECT`'s display area, because between the two the control draws
    // a border in `COLOR_3DHILIGHT` -- pure white, and Windows keeps the classic
    // 3D palette light on a dark desktop. Measured 2026-08-05 on Windows 11
    // 26200: a full-width #FFFFFF rule on #2B2B2B, the brightest object in the
    // window. Covering it is the only way to reach it; owner-draw gets the item
    // interiors and `WM_ERASEBKGND` the strip, and this is drawn outside both.
    let mut item = RECT { left: 0, top: 0, right: 0, bottom: 0 };
    unsafe {
        SendMessageW(a.settings.tabs.get(), TCM_GETITEMRECT, 0, &mut item as *mut _ as LPARAM);
    }
    let page_top = if item.bottom > 0 { item.bottom } else { strip };
    let current =
        unsafe { SendMessageW(a.settings.tabs.get(), TCM_GETCURSEL, 0, 0) }.max(0) as usize;
    for (i, page) in pages.iter().enumerate() {
        unsafe {
            SetWindowPos(
                *page,
                std::ptr::null_mut(),
                0,
                page_top,
                width,
                tab_h - page_top,
                SWP_NOZORDER,
            );
            ShowWindow(*page, if i == current { SW_SHOW } else { SW_HIDE });
        }
    }

    let mut r = RECT { left: 0, top: 0, right: width, bottom: tab_h };
    unsafe {
        AdjustWindowRectExForDpi(&mut r, WS_CAPTION | WS_SYSMENU, 0, 0, dpi);
        SetWindowPos(
            hwnd,
            std::ptr::null_mut(),
            0,
            0,
            r.right - r.left,
            r.bottom - r.top,
            SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE,
        );
        InvalidateRect(hwnd, std::ptr::null(), 1);
    }
}

fn page_basic(col: &mut Col, view: &agent::SettingsView) {
    let a = app();
    let s = tr();
    col.heading(s.settings_section_connection);
    col.gap(4);
    col.line(s.settings_broker_label, ROLE_TEXT);
    col.wrap(
        if view.broker_locked { s.settings_broker_managed } else { s.settings_broker_sub },
        ROLE_SUB,
    );
    col.gap(4);
    let broker = col.edit(&view.broker_url, !view.broker_locked, CMD_BROKER);
    // Gray placeholder shown when the field is empty; the app prepends https:// on
    // save, so the example is bare like what the user should type.
    unsafe {
        SendMessageW(
            broker,
            crate::ui::EM_SETCUEBANNER,
            1,
            wide("kerbridge.example.site").as_ptr() as LPARAM,
        );
    }
    a.settings.broker.set(broker);

    col.gap(8);
    let bw = col.d(96);
    let bh = col.d(28);
    let save =
        make_button(col.hwnd, s.settings_save, col.x + col.w - bw, col.y, bw, bh, CMD_SAVE, false);
    unsafe { EnableWindow(save, 0) };
    a.settings.save.set(save);
    col.y += bh;

    col.separator();
    col.heading(s.settings_section_signin);
    col.gap(4);
    let autostart = checkbox(col, s.settings_startup_label, CMD_AUTOSTART);
    set_checked(autostart, view.autostart);
    if view.autostart_locked {
        unsafe { EnableWindow(autostart, 0) };
        col.wrap(s.settings_startup_managed, ROLE_SUB);
    }
    a.settings.autostart.set(autostart);
    col.gap(6);
    let wam = checkbox(col, s.settings_wam_label, CMD_WAM);
    set_checked(wam, view.windows_sign_in);
    a.settings.wam.set(wam);
    col.wrap(s.settings_wam_sub, ROLE_SUB);
}

/// **Presence rules, no text branches.** No broker or no realm yet →
/// Authorization and Windows setup are absent and the gate line stands where the
/// absence it explains is. Grants off → Authorization is absent *silently*: a
/// deployment that turned the feature off does not want a row explaining what its
/// users cannot have. Not enrolled → Windows setup keeps its state line and loses
/// its buttons, which kills the standing false claim that the realm is registered
/// directly above a button offering to remove it.
fn page_advanced(col: &mut Col, view: &agent::SettingsView, status: &agent::Status) {
    let s = tr();
    if view.realm.is_empty() {
        app().settings.grant_for.set(std::ptr::null_mut());
        col.wrap(s.settings_gate, ROLE_SUB);
    } else {
        advanced_realm_sections(col, view, status);
    }

    // Outside the gate: the gate is about *this realm's* authorization and
    // enrollment, and the log is what someone reaches for when there is no realm
    // -- which is the state the gate line describes.
    col.separator();
    col.heading(s.settings_section_troubleshoot);
    col.gap(4);
    col.wrap(s.settings_troubleshoot_sub, ROLE_SUB);
    col.gap(8);
    let bh = col.d(28);
    let w = (measure_width(font_for(false), s.act_open_log) + col.d(16)).max(col.d(160));
    make_button(col.hwnd, s.act_open_log, col.x, col.y, w, bh, CMD_OPEN_LOG, false);
    col.y += bh;
}

/// Authorization and Windows setup, both of which name a realm.
fn advanced_realm_sections(col: &mut Col, view: &agent::SettingsView, status: &agent::Status) {
    let a = app();
    let s = tr();
    a.settings.grant_for.set(std::ptr::null_mut());

    if view.grant_days > 0 {
        col.heading(s.settings_section_authorization);
        col.gap(4);
        // Past tense, and from the held grant, so it cannot be edited into a lie.
        if !status.principal.is_empty() && status.holds_grant {
            col.wrap(&fill(s.settings_grant_state, &[("account", &status.principal)]), ROLE_TEXT);
            col.gap(6);
        }
        col.line(s.settings_grant_for_label, ROLE_TEXT);
        // The managed cue is the broker field's, verbatim: the sentence is about
        // who decided, not about which setting it was.
        col.wrap(
            if view.grant_for_locked {
                s.settings_broker_managed
            } else {
                s.settings_grant_for_sub
            },
            ROLE_SUB,
        );
        col.gap(4);
        a.settings.grant_for.set(col.edit(&view.grant_for, !view.grant_for_locked, CMD_GRANT_FOR));
        col.gap(8);

        let label = if status.holds_grant { s.act_create_grant_again } else { s.act_create_grant };
        let bh = col.d(28);
        // Measured, like the enrollment pair below. These are verb phrases in
        // eleven languages -- German's "Autorisierung entfernen…" alone is
        // twenty-four glyphs -- and a fixed width clips whichever is longest
        // wherever nobody happened to look.
        let mut buttons = vec![(label.to_owned(), CMD_AUTHORIZE)];
        if status.holds_grant {
            buttons.push((s.act_give_up_grant.to_owned(), CMD_GIVE_UP));
        }
        let widths: Vec<i32> = buttons
            .iter()
            .map(|(l, _)| (measure_width(font_for(false), l) + col.d(16)).max(col.d(150)))
            .collect();
        let stack = widths.iter().sum::<i32>() + col.d(8) * (widths.len() as i32 - 1) > col.w;
        let mut x = col.x;
        for (i, ((l, id), bw)) in buttons.iter().zip(&widths).enumerate() {
            if stack && i > 0 {
                col.y += bh + col.d(6);
            }
            make_button(col.hwnd, l, x, col.y, *bw, bh, *id, false);
            if !stack {
                x += bw + col.d(8);
            }
        }
        col.y += bh;
        col.separator();
    }

    col.heading(s.settings_section_windows);
    col.gap(4);
    // `usable` is the realm being known *and* Windows registered for it, and
    // this group only renders once the realm is known.
    let enrolled = status.usable;
    col.wrap(
        &fill(
            if enrolled { s.settings_enrolled } else { s.settings_not_enrolled },
            &[("realm", &view.realm)],
        ),
        ROLE_TEXT,
    );
    if enrolled {
        col.gap(8);
        let bh = col.d(28);
        // Both of these confirm before changing anything, hence the ellipses; the
        // shield carries "needs administrator approval" and goes on regardless of
        // whether this account happens to have it.
        let labels = [
            (s.act_reenroll.to_owned(), CMD_REENROLL),
            (fill(s.act_unenroll, &[("realm", &view.realm)]), CMD_UNENROLL),
        ];
        // Sized to the text, never to a fixed width: one of these interpolates the
        // realm, so any width that suits EXAMPLE.SITE clips a longer one. The
        // shield's 18 is space the label never gets.
        let extra = col.d(16) + col.d(18);
        let widths: Vec<i32> =
            labels.iter().map(|(label, _)| measure_width(font_for(false), label) + extra).collect();
        let stack = widths.iter().sum::<i32>() + col.d(8) > col.w;
        let mut x = col.x;
        for (i, ((label, id), bw)) in labels.iter().zip(&widths).enumerate() {
            if stack && i > 0 {
                col.y += bh + col.d(6);
            }
            let b = make_button(col.hwnd, label, x, col.y, *bw, bh, *id, false);
            unsafe { SendMessageW(b, BCM_SETSHIELD, 0, 1) };
            if !stack {
                x += bw + col.d(8);
            }
        }
        col.y += bh;
    }
}

fn page_about(col: &mut Col) {
    let a = app();
    let s = tr();
    let icon = col.d(40);
    unsafe {
        let lg = CreateWindowExW(
            0,
            wide("STATIC").as_ptr(),
            std::ptr::null(),
            WS_CHILD | WS_VISIBLE | SS_ICON | SS_REALSIZECONTROL,
            col.x,
            col.y,
            icon,
            icon,
            col.hwnd,
            std::ptr::null_mut(),
            a.hinstance,
            std::ptr::null(),
        );
        SendMessageW(lg, STM_SETICON, a.logo_at(icon.max(1) as u32) as WPARAM, 0);
    }
    let text_x = col.x + icon + col.d(12);
    let text_w = col.w - icon - col.d(12);
    let name = make_static(
        col.hwnd,
        s.app_name,
        text_x,
        col.y,
        text_w,
        col.d(22),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        ROLE_TEXT,
        true,
    );
    unsafe { SendMessageW(name, WM_SETFONT, a.font_title as WPARAM, 1) };
    make_static(
        col.hwnd,
        &format!("{VERSION} · {}", s.tagline),
        text_x,
        col.y + col.d(22),
        text_w,
        col.d(16),
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        ROLE_SUB,
        false,
    );
    col.y += icon.max(col.d(38));

    col.gap(14);
    col.line(COPYRIGHT, ROLE_TEXT);
    col.gap(8);
    col.wrap(s.about_license, ROLE_SUB);
    col.gap(8);
    col.wrap(WEBSITE, ROLE_SUB);
}

fn checkbox(col: &mut Col, label: &str, id: u16) -> HWND {
    let a = app();
    let h = col.d(22);
    let cb = unsafe {
        let cb = CreateWindowExW(
            0,
            wide("BUTTON").as_ptr(),
            wide(label).as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX,
            col.x,
            col.y,
            col.w,
            h,
            col.hwnd,
            id as isize as _,
            a.hinstance,
            std::ptr::null(),
        );
        SendMessageW(cb, WM_SETFONT, font_for(false) as WPARAM, 1);
        apply_control_theme(cb, a.theme.get().dark);
        cb
    };
    col.y += h;
    cb
}

/// What the two text fields hold, and whether either differs from what is stored.
fn dirty(a: &App) -> bool {
    let (broker, grant_for) = a.settings.committed.borrow().clone();
    window_text(a.settings.broker.get()) != broker
        || (!a.settings.grant_for.get().is_null()
            && window_text(a.settings.grant_for.get()) != grant_for)
}

/// Commit the two text fields. Checkboxes never come through here: they apply the
/// moment they are clicked.
fn save() {
    let a = app();
    let broker = window_text(a.settings.broker.get());
    // Never an empty string standing in for "absent": the field lives on a tab
    // that may not have been built, and reading a null one as empty would clear
    // the target every time somebody pressed Save.
    let grant_for = if a.settings.grant_for.get().is_null() {
        agent::settings_view().grant_for
    } else {
        window_text(a.settings.grant_for.get())
    };
    agent::apply_settings(
        Some(&broker),
        is_checked(a.settings.autostart.get()),
        is_checked(a.settings.wam.get()),
        &grant_for,
    );
    crate::refresh_ui();
    layout_pages();
}

/// Apply the checkboxes on the spot, leaving the text fields to their Save.
fn apply_toggles() {
    let a = app();
    let view = agent::settings_view();
    // The broker field is not part of a toggle. Passing the value back would
    // write the DNS-discovered address into `config.toml` and pin a machine that
    // was meant to keep following the SRV record.
    agent::apply_settings(
        None,
        is_checked(a.settings.autostart.get()),
        is_checked(a.settings.wam.get()),
        &view.grant_for,
    );
    crate::refresh_ui();
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_CTLCOLORSTATIC | WM_CTLCOLOREDIT | WM_CTLCOLORBTN => ctl_color(wparam, lparam),
        crate::ui::WM_DRAWITEM => crate::ui::on_drawitem(lparam),
        WM_ERASEBKGND => {
            let (w, h) = client_size(hwnd);
            let r = RECT { left: 0, top: 0, right: w, bottom: h };
            unsafe { FillRect(wparam as _, &r, app().theme.get().bg_brush) };
            1
        }
        WM_COMMAND => {
            on_command(wparam);
            0
        }
        WM_NOTIFY => {
            let nm = unsafe { &*(lparam as *const NMHDR) };
            if nm.code == TCN_SELCHANGE {
                show_current_page();
            }
            0
        }
        WM_CLOSE => {
            // Leaving Settings lands the user back on the status flyout, not on
            // an empty desktop with the agent only in the tray.
            unsafe { ShowWindow(hwnd, SW_HIDE) };
            crate::flyout::show();
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

fn on_command(wparam: WPARAM) {
    let a = app();
    let id = loword(wparam) as u16;
    let notify = hiword(wparam);
    match (id, notify) {
        (CMD_SAVE, BN_CLICKED) => save(),
        (CMD_AUTOSTART | CMD_WAM, BN_CLICKED) => apply_toggles(),
        (CMD_BROKER | CMD_GRANT_FOR, EN_CHANGE) => {
            let save = a.settings.save.get();
            if !save.is_null() {
                unsafe { EnableWindow(save, i32::from(dirty(a))) };
            }
        }
        // Pressing an authorize button commits a pending edit in the target field
        // first, then confirms with the committed value -- the confirmation names
        // its target, which is where the disagreement resolves.
        (CMD_AUTHORIZE, BN_CLICKED) => {
            if dirty(a) {
                save();
            }
            crate::start_action(Action::CreateGrant);
        }
        (CMD_GIVE_UP, BN_CLICKED) => crate::start_action(Action::GiveUpGrant),
        (CMD_REENROLL, BN_CLICKED) => crate::start_action(Action::Reenroll),
        (CMD_UNENROLL, BN_CLICKED) => crate::start_action(Action::Unenroll),
        (CMD_OPEN_LOG, BN_CLICKED) => agent::open_log_folder(),
        _ => {}
    }
}

fn show_current_page() {
    let a = app();
    let current =
        unsafe { SendMessageW(a.settings.tabs.get(), TCM_GETCURSEL, 0, 0) }.max(0) as usize;
    // The borrow is held across `ShowWindow`, which re-enters `page_wndproc`.
    // Safe only because nothing on a paint or create path takes `pages` mutably
    // -- see `app.rs`. A `borrow_mut` reachable from a window message panics
    // here, and does it on the user's machine rather than in a test.
    for (i, page) in a.settings.pages.borrow().iter().enumerate() {
        unsafe { ShowWindow(*page, if i == current { SW_SHOW } else { SW_HIDE }) };
    }
}

/// The pages are plain child containers: they carry the theme, and hand every
/// control message back to the window that knows what the controls mean.
unsafe extern "system" fn page_wndproc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_CTLCOLORSTATIC | WM_CTLCOLOREDIT | WM_CTLCOLORBTN => ctl_color(wparam, lparam),
        crate::ui::WM_DRAWITEM => crate::ui::on_drawitem(lparam),
        WM_ERASEBKGND => {
            let (w, h) = client_size(hwnd);
            let r = RECT { left: 0, top: 0, right: w, bottom: h };
            unsafe { FillRect(wparam as _, &r, app().theme.get().bg_brush) };
            1
        }
        WM_COMMAND => {
            on_command(wparam);
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

/// The tab strip's subclass: the background behind and beside the items, which
/// `WM_DRAWITEM` never reaches, plus the hot tracking that comes with it.
unsafe extern "system" fn tab_subclass(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let a = app();
    let old: WNDPROC = unsafe { std::mem::transmute(a.settings.tab_proc.get()) };
    match msg {
        WM_ERASEBKGND => {
            let (w, h) = client_size(hwnd);
            let r = RECT { left: 0, top: 0, right: w, bottom: h };
            unsafe { FillRect(wparam as _, &r, a.theme.get().bg_brush) };
            1
        }
        WM_MOUSEMOVE => {
            let mut hit = TcHitTestInfo {
                pt: POINT {
                    x: (lparam & 0xffff) as i16 as i32,
                    y: ((lparam >> 16) & 0xffff) as i16 as i32,
                },
                flags: 0,
            };
            let over =
                unsafe { SendMessageW(hwnd, TCM_HITTEST, 0, &mut hit as *mut _ as LPARAM) } as i32;
            let was = a.settings.hot_tab.replace(over);
            if was != over {
                invalidate_tab(hwnd, was);
                invalidate_tab(hwnd, over);
            }
            let mut tme = TRACKMOUSEEVENT {
                cbSize: size_of::<TRACKMOUSEEVENT>() as u32,
                dwFlags: TME_LEAVE,
                hwndTrack: hwnd,
                dwHoverTime: 0,
            };
            unsafe { TrackMouseEvent(&mut tme) };
            unsafe { CallWindowProcW(old, hwnd, msg, wparam, lparam) }
        }
        WM_MOUSELEAVE => {
            let was = a.settings.hot_tab.replace(-1);
            invalidate_tab(hwnd, was);
            unsafe { CallWindowProcW(old, hwnd, msg, wparam, lparam) }
        }
        _ => unsafe { CallWindowProcW(old, hwnd, msg, wparam, lparam) },
    }
}

/// Repaint one tab item, and only that one.
///
/// Invalidating the whole control instead routes through the `WM_ERASEBKGND`
/// above, which flattens the entire strip to the background for a change that
/// touches at most two items -- and an erase whose repaint does not follow is a
/// blank strip. `bErase` is false because `WM_DRAWITEM` fills the item rect
/// itself. A negative index is "no tab", which is what leaving the strip means.
fn invalidate_tab(hwnd: HWND, index: i32) {
    if index < 0 {
        return;
    }
    let mut r = RECT { left: 0, top: 0, right: 0, bottom: 0 };
    unsafe {
        if SendMessageW(hwnd, TCM_GETITEMRECT, index as WPARAM, &mut r as *mut _ as LPARAM) != 0 {
            InvalidateRect(hwnd, &r, 0);
        }
    }
}
