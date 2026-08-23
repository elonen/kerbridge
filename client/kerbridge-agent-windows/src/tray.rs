//! The notification-area icon and the hidden window behind it: the tray
//! callbacks, the context menu, the balloon notifications, and the 1 Hz tick
//! that drives the countdown and the re-injection schedule.

use std::sync::atomic::{AtomicU32, Ordering};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows_sys::Win32::UI::HiDpi::{GetDpiForWindow, GetSystemMetricsForDpi};
use windows_sys::Win32::UI::Shell::{
    NIF_GUID, NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY,
    NOTIFYICONDATAW, Shell_NotifyIconW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, DefWindowProcW, DestroyIcon, DestroyMenu, DestroyWindow,
    GetCursorPos, MF_SEPARATOR, MF_STRING, PostMessageW, PostQuitMessage, RegisterWindowMessageW,
    SetForegroundWindow, TPM_RETURNCMD, TPM_RIGHTBUTTON, TrackPopupMenu, WM_CONTEXTMENU,
    WM_DESTROY, WM_ENDSESSION, WM_LBUTTONUP, WM_RBUTTONUP, WM_SETTINGCHANGE, WM_TIMER,
};
use windows_sys::core::GUID;

use kerbridge_client::agent::{self, Severity, Status};
use kerbridge_client::describe::Action;
use kerbridge_client::present::action_label;
use kerbridge_client::strings::tr;

use crate::app::{LOGO_SVG, SM_CXSMICON, app, app_opt};
use crate::present::infotip;
use crate::sys::{loword, status_icon, wide};
use crate::theme::{allow_dark_for_window, taskbar_dark};
use crate::{flyout, settings, start_action};

pub(crate) const OWNER_CLASS: &str = "NasAuthOwner";

const TRAY_UID: u32 = 1;
/// This icon's identity, as far as the shell is concerned.
///
/// A GUID rather than the `(hWnd, uID)` pair, because that pair is not an
/// identity the shell can keep across runs: with no GUID it falls back to the
/// executable's path, and `Control Panel\NotifyIconSettings` grows a fresh row
/// -- with a fresh hidden-by-default promotion -- for every path this has ever
/// run from.
///
/// Generated once and frozen. It is the name of the row the user's "show this
/// icon" choice lives under, so changing it silently discards that choice.
const TRAY_GUID: GUID = GUID::from_u128(0xaa109b1c_a0d2_4900_894e_d07aaea5ce31);
pub(crate) const WM_TRAY: u32 = 0x0400 + 1; // WM_APP + 1
/// Posted by a worker thread that has queued an agent event -- this is
/// [`agent::Host::wake`] on Windows.
pub(crate) const WM_AGENT: u32 = 0x0400 + 2;
/// Posted by a second instance to bring this one's flyout up.
pub(crate) const WM_SHOW_FLYOUT: u32 = 0x0400 + 3;
/// The shell broadcasts this registered message after Explorer restarts; every tray
/// icon must be added again or the agent silently loses its only UI.
static TASKBAR_CREATED: AtomicU32 = AtomicU32::new(0);

/// One-second heartbeat: drives the countdown and the re-injection schedule.
pub(crate) const TIMER_TICK: usize = 1;
pub(crate) const TIMER_TICK_MS: u32 = 1000;

const WM_DPICHANGED: u32 = 0x02E0;

// Menu command ids.
const MENU_OPEN_STATUS: usize = 200;
const MENU_SETTINGS: usize = 201;
const MENU_HELP: usize = 202;
const MENU_QUIT: usize = 203;
/// Actions occupy `MENU_ACTION_BASE + <action index>`.
const MENU_ACTION_BASE: usize = 210;

// Balloon flags. `NIIF_INFO` is deliberately absent: severity follows the
// condition, and quiet time is respected on every one of them.
const NIIF_NONE: u32 = 0x0000;
const NIIF_WARNING: u32 = 0x0002;
const NIIF_ERROR: u32 = 0x0003;
const NIIF_RESPECT_QUIET_TIME: u32 = 0x0080;
/// A click on the balloon itself. Measured to arrive at notify-icon version 0,
/// in `LOWORD(lParam)` where the tray callback already looks -- so `NIM_SETVERSION`
/// stays uncalled: raising it fires the context menu twice per right-click and,
/// at v4, suppresses the `szTip` tooltip.
const NIN_BALLOONUSERCLICK: u32 = 0x0405;

pub(crate) unsafe extern "system" fn wndproc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if app_opt().is_none() {
        return unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) };
    }
    // Registered message ids are assigned at runtime, so they cannot be match arms.
    if msg != 0 && msg == TASKBAR_CREATED.load(Ordering::Relaxed) {
        kerbridge_client::log::info("Explorer restarted; re-adding the tray icon");
        add_icon();
        return 0;
    }
    match msg {
        WM_TRAY => {
            match loword(lparam as usize) {
                WM_LBUTTONUP => flyout::toggle(),
                WM_RBUTTONUP | WM_CONTEXTMENU => show_menu(),
                // A click on a toast should always open, never toggle.
                NIN_BALLOONUSERCLICK => flyout::show(),
                _ => {}
            }
            0
        }
        WM_SHOW_FLYOUT => {
            flyout::show();
            0
        }
        WM_AGENT => {
            if agent::drain() {
                crate::refresh_ui();
            }
            0
        }
        WM_TIMER => {
            on_tick();
            0
        }
        WM_SETTINGCHANGE => {
            // Re-read on any broadcast; cheap, and covers the theme toggle reliably.
            crate::on_theme_changed();
            unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
        }
        // The badge's glyph threshold sits at 150 %, so both sides of it are
        // reachable on one machine only if the icon is drawn again when the
        // scale moves.
        WM_DPICHANGED => {
            update(&agent::status());
            0
        }
        // Restart Manager closes us so an upgrade can replace the exe, and a
        // logoff ends us the same way. Both arrive here as a session end, and
        // both want the ordinary quit path: it is what removes the tray icon, so
        // skipping it leaves a dead icon in the notification area until the shell
        // next sweeps. Not answering at all is worse than answering slowly --
        // Restart Manager waits out its timeout and then terminates us.
        //
        // WM_QUERYENDSESSION is left to DefWindowProc, which consents. There is
        // no unsaved state to lose and nothing this agent could ask about.
        WM_ENDSESSION if wparam != 0 => {
            kerbridge_client::log::info("closing: the session is ending");
            unsafe { DestroyWindow(app().owner) };
            0
        }
        WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

/// The identity every `Shell_NotifyIcon` call has to carry.
///
/// All four sites, not just the add: once an icon is registered by GUID, a call
/// that names only `uID` addresses nothing and fails quietly.
fn tray_id(owner: HWND) -> NOTIFYICONDATAW {
    let mut nid: NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    nid.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = owner;
    nid.uID = TRAY_UID;
    nid.guidItem = TRAY_GUID;
    nid.uFlags = NIF_GUID;
    nid
}

/// Subscribe to the shell's Explorer-restart broadcast, then put the icon up.
pub(crate) fn install() {
    TASKBAR_CREATED.store(
        unsafe { RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()) },
        Ordering::Relaxed,
    );
    add_icon();
}

/// Add (or re-add) our notification-area icon and paint the current state on it.
fn add_icon() {
    let a = app();
    unsafe {
        let mut nid = tray_id(a.owner);
        nid.uFlags |= NIF_ICON | NIF_MESSAGE | NIF_TIP;
        nid.uCallbackMessage = WM_TRAY;
        // Only up until the `update` below paints the condition on it, but the
        // shell scales whatever `NIM_ADD` carries, so hand it the metric's size.
        let dpi = GetDpiForWindow(a.owner).max(96);
        nid.hIcon = a.logo_at(GetSystemMetricsForDpi(SM_CXSMICON as i32, dpi).max(16) as u32);
        // The name Windows keeps for its own notification-area list. It records
        // that once, at `NIM_ADD`: the state-carrying tip written by every later
        // `NIM_MODIFY` never reaches the settings list.
        copy_into(&mut nid.szTip, tr().app_name);
        if Shell_NotifyIconW(NIM_ADD, &nid) == 0 {
            // A GUID is bound to the path of the executable that registered it,
            // and an add from a different path fails outright. That is this
            // build's ordinary case -- the same agent runs from the share, from
            // a local copy and from the installed location -- so take the
            // registration over rather than leaving no icon at all.
            Shell_NotifyIconW(NIM_DELETE, &nid);
            if Shell_NotifyIconW(NIM_ADD, &nid) == 0 {
                // The one way to learn the icon never landed. Windows 11 also
                // demotes new icons to an overflow the taskbar may not show, so
                // an invisible tray icon is not on its own evidence of a failure
                // here.
                kerbridge_client::log::error("tray: Shell_NotifyIcon(NIM_ADD) failed");
            }
        }
    }
    update(&agent::status());
}

/// Take the icon down on the way out, so the notification area does not keep a
/// dead one until the shell next sweeps.
pub(crate) fn remove_icon() {
    let nid = tray_id(app().owner);
    unsafe { Shell_NotifyIconW(NIM_DELETE, &nid) };
}

/// One second of housekeeping: let the agent run its schedule, then repaint only
/// what has actually changed -- the icon on a condition change, the flyout on
/// either that or the countdown ticking over a minute.
fn on_tick() {
    let a = app();
    let scheduled_change = agent::tick();
    let status = agent::status();
    let condition_changed =
        a.shown_condition.replace(Some(status.condition)) != Some(status.condition);
    let minute = status.ticket.as_ref().map_or(-1, |t| t.remaining / 60);
    let minute_changed = a.shown_minute.replace(minute) != minute;

    if scheduled_change || condition_changed {
        update(&status);
    }
    if a.flyout_visible.get() && (scheduled_change || condition_changed || minute_changed) {
        flyout::rebuild();
    }
}

fn show_menu() {
    let a = app();
    let t = a.theme.get();
    let status = agent::status();
    unsafe {
        let menu = CreatePopupMenu();
        let s = tr();
        // "Open status" first -- a discoverable path for anyone who misses left-click.
        AppendMenuW(menu, MF_STRING, MENU_OPEN_STATUS, wide(s.menu_open_status).as_ptr());

        // The flyout's superset, in the flyout's order: width is free here and
        // rarity is not a cost, so everything the front page had to gate away
        // still has one home.
        let mut offered = Vec::new();
        let group = |menu, offered: &mut Vec<Action>, of: &[Action]| {
            let mut any = false;
            for act in of.iter().filter(|act| status.actions.contains(act)) {
                if !any {
                    AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
                    any = true;
                }
                let label = action_label(*act, &status);
                AppendMenuW(
                    menu,
                    MF_STRING,
                    MENU_ACTION_BASE + offered.len(),
                    wide(&label).as_ptr(),
                );
                offered.push(*act);
            }
        };
        group(
            menu,
            &mut offered,
            &[
                Action::CreateGrant,
                Action::ReinjectTicket,
                Action::SignIn,
                Action::DropKrbTicket,
                Action::SignOutIdp,
            ],
        );
        // The two shielded ones, and the repair unconditionally: broken drives
        // are what someone reaches for this with, and the agent only sometimes
        // knows why.
        group(menu, &mut offered, &[Action::Enroll, Action::RestartWorkstation]);
        *a.menu_actions.borrow_mut() = offered;

        AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
        AppendMenuW(menu, MF_STRING, MENU_SETTINGS, wide(s.menu_settings).as_ptr());
        AppendMenuW(menu, MF_STRING, MENU_HELP, wide(s.menu_help).as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
        AppendMenuW(menu, MF_STRING, MENU_QUIT, wide(s.menu_quit).as_ptr());

        allow_dark_for_window(a.owner, t.dark);

        let mut pt = POINT { x: 0, y: 0 };
        GetCursorPos(&mut pt);
        // MSDN dance: foreground the owner so the menu dismisses on outside click,
        // then post a null message afterwards to flush it.
        SetForegroundWindow(a.owner);
        let cmd = TrackPopupMenu(
            menu,
            TPM_RETURNCMD | TPM_RIGHTBUTTON,
            pt.x,
            pt.y,
            0,
            a.owner,
            std::ptr::null(),
        );
        PostMessageW(a.owner, 0, 0, 0);
        DestroyMenu(menu);

        match cmd as usize {
            MENU_OPEN_STATUS => flyout::show(),
            MENU_SETTINGS => settings::open(),
            MENU_HELP => crate::sys::shell_open(&kerbridge_client::help_url_for(
                if status.help_url.is_empty() {
                    kerbridge_client::HELP_URL
                } else {
                    &status.help_url
                },
                "win",
            )),
            MENU_QUIT => {
                kerbridge_client::log::info("quit from the tray menu");
                DestroyWindow(a.owner);
            }
            id if id >= MENU_ACTION_BASE => {
                let act = a.menu_actions.borrow().get(id - MENU_ACTION_BASE).copied();
                if let Some(act) = act {
                    start_action(act);
                }
            }
            _ => {}
        }
    }
}

/// Balloon notification through the tray icon. Reached through `WinHost`, which
/// has already decided that no surface of ours is carrying this.
pub(crate) fn notify(title: &str, body: &str, severity: Severity) {
    let a = app();
    unsafe {
        let mut nid = tray_id(a.owner);
        nid.uFlags |= NIF_INFO;
        // Quiet time on every one of them, unconditionally: none of these is
        // urgent enough to talk over a presentation.
        nid.dwInfoFlags = NIIF_RESPECT_QUIET_TIME
            | match severity {
                Severity::Info => NIIF_NONE,
                Severity::Warning => NIIF_WARNING,
                Severity::Error => NIIF_ERROR,
            };
        copy_into(&mut nid.szInfoTitle, title);
        copy_into(&mut nid.szInfo, body);
        Shell_NotifyIconW(NIM_MODIFY, &nid);
    }
}

/// Swap the tray icon to the current condition's variant and rebuild the infotip.
pub(crate) fn update(status: &Status) {
    let a = app();
    // The shell asks for `SM_CXSMICON`, and the badge's glyph threshold is a
    // pixel count -- so a hardcoded 32 would hand every 100 % machine a glyph
    // squashed to 16 and leave the threshold nothing to act on.
    let dpi = unsafe { GetDpiForWindow(a.owner) }.max(96);
    let size = unsafe { GetSystemMetricsForDpi(SM_CXSMICON as i32, dpi) }.max(16) as u32;
    let icon = status_icon(LOGO_SVG, size, taskbar_dark(), status.condition);
    let old = a.tray_cur.replace(icon);

    unsafe {
        let mut nid = tray_id(a.owner);
        nid.uFlags |= NIF_ICON | NIF_TIP;
        nid.hIcon = icon;
        copy_into(&mut nid.szTip, &infotip(status));
        Shell_NotifyIconW(NIM_MODIFY, &nid);
        if !old.is_null() {
            DestroyIcon(old);
        }
    }
}

/// Copy a string into a fixed `[u16; N]` Win32 field, NUL-terminated and truncated.
fn copy_into(dst: &mut [u16], src: &str) {
    let w = wide(src);
    let n = w.len().min(dst.len());
    dst[..n].copy_from_slice(&w[..n]);
    if let Some(last) = dst.get_mut(n.saturating_sub(1)) {
        *last = 0;
    }
}
