//! The status flyout: a borderless popup that opens from the tray icon and
//! dismisses on blur. It is torn down and re-laid on every change, so what is on
//! screen is always the current `Status` and never a patched-up older one.
//!
//! The rows here are the ones that know what they are showing -- the header's
//! gear command, the severity-carrying explanation rule, the two-button row and
//! its stacking rule. The stock-control vocabulary underneath them is `ui`.

use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{FillRect, InvalidateRect};
use windows_sys::Win32::UI::Controls::BCM_SETSHIELD;
use windows_sys::Win32::UI::HiDpi::GetDpiForWindow;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, SW_HIDE, SW_SHOW, SendMessageW, SetForegroundWindow,
    SetWindowPos, ShowWindow, WM_ACTIVATE, WM_COMMAND, WM_CTLCOLORBTN, WM_CTLCOLOREDIT,
    WM_CTLCOLORSTATIC, WM_ERASEBKGND, WS_CHILD, WS_VISIBLE,
};

use kerbridge_client::agent::{self, Status};
use kerbridge_client::describe::{Action, Blocker, Condition, Supply};
use kerbridge_client::strings::{days, duration, fill, tr};

use kerbridge_client::present::{action_label, blocker_line, days_until, headline, identity};

use crate::app::app;
use crate::present::{condition_role, ranked, rule_role};
use crate::sys::{anchor_pos, client_size, dip, hiword, loword, measure_text, measure_width, wide};
use crate::ui::{
    BN_CLICKED, Col, PBM_SETBARCOLOR, PBM_SETBKCOLOR, PBM_SETMARQUEE, PBM_SETPOS, PBM_SETRANGE32,
    PBS_MARQUEE, ROLE_FLAT_SUB, ROLE_FLAT_TEXT, ROLE_GEAR, ROLE_OK, ROLE_SUB, ROLE_TEXT, ROLE_WARN,
    SS_ICON, SS_LEFT, SS_REALSIZECONTROL, SS_RIGHT, WM_DRAWITEM, ctl_color, destroy_children,
    font_for, make_button, make_flat_button, make_flat_edit, make_static, on_drawitem,
};
use crate::{settings, start_action};

pub(crate) const FLYOUT_CLASS: &str = "NasAuthFlyout";

const MARGIN: i32 = 12; // logical px between popup and work-area edge

// Flyout command ids. One per action rather than per control: the label is
// chosen by state and the command is what the action *is*, so no two controls
// can reach the same verb under different names again.
const CMD_ACTION_BASE: u16 = 100;
const CMD_OPEN_LOG: u16 = 120;
const CMD_SETTINGS_GEAR: u16 = 121;
const CMD_TOGGLE_DETAILS: u16 = 122;
/// What the dialog manager posts when Escape is pressed.
const IDCANCEL: u16 = 2;

const STM_SETICON: u32 = 0x0170;
const SW_SHOWNA: i32 = 8; // show, without taking activation
const WA_INACTIVE: usize = 0;

pub(crate) unsafe extern "system" fn wndproc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if crate::app::app_opt().is_none() {
        return unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) };
    }
    match msg {
        WM_CTLCOLORSTATIC | WM_CTLCOLOREDIT | WM_CTLCOLORBTN => ctl_color(wparam, lparam),
        WM_DRAWITEM => on_drawitem(lparam),
        WM_ERASEBKGND => {
            let (w, h) = client_size(hwnd);
            let r = RECT { left: 0, top: 0, right: w, bottom: h };
            unsafe { FillRect(wparam as _, &r, app().theme.get().bg_brush) };
            1
        }
        // Buttons only. A control notification carries its HWND in `lparam` and
        // its code in the high word, so a read-only EDIT's `EN_UPDATE` is a
        // `WM_COMMAND` too -- and one arrives inside `CreateWindowExW`, before
        // the detail row it belongs to is even built. The dialog manager's
        // Escape has `lparam` 0, which is how it stays reachable.
        WM_COMMAND if lparam == 0 || hiword(wparam) == BN_CLICKED => {
            on_command(loword(wparam) as u16);
            0
        }
        WM_ACTIVATE => {
            // Dismiss-on-blur: low word of wParam is the activation state. Not
            // while one of our own modals has the foreground -- the confirmation
            // it opened came from a button in here.
            if (wparam & 0xffff) == WA_INACTIVE && !app().modal.is_open() {
                app().auto_hidden_at.set(Some(Instant::now()));
                hide();
            }
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

fn on_command(id: u16) {
    match id {
        IDCANCEL => return hide(),
        CMD_OPEN_LOG => agent::open_log_folder(),
        CMD_SETTINGS_GEAR => {
            hide();
            settings::open();
            return;
        }
        CMD_TOGGLE_DETAILS => {
            let a = app();
            a.details_expanded.set(!a.details_expanded.get());
            return rebuild();
        }
        // An id below the action base is not an action button. Unchecked, the
        // subtraction wraps and indexes far off the end.
        _ => {
            let act = id
                .checked_sub(CMD_ACTION_BASE)
                .and_then(|i| app().buttons.borrow().get(i as usize).copied());
            match act {
                Some(act) => start_action(act),
                None => return,
            }
        }
    }
    crate::refresh_ui();
}

/// How long after an activation-loss hide a tray click is treated as "that was the
/// click that closed it", not "open it again".
const REOPEN_SUPPRESSION: Duration = Duration::from_millis(300);

pub(crate) fn toggle() {
    let a = app();
    if a.flyout_visible.get() {
        hide();
    } else if a.auto_hidden_at.get().is_none_or(|t| t.elapsed() >= REOPEN_SUPPRESSION) {
        show();
    }
}

pub(crate) fn show() {
    let a = app();
    a.flyout_visible.set(true);
    rebuild();
    unsafe {
        ShowWindow(a.flyout, SW_SHOW);
        SetForegroundWindow(a.flyout);
        SetFocus(a.flyout);
    }
}

/// Raise the flyout without taking activation.
///
/// The tray opens it by itself when it has detected an NTLM fallback it could not
/// clear. Broken network drives justify an interruption; they do not justify
/// pulling the foreground out from under a full-screen build or game, which is
/// exactly the machine this is most likely to happen on.
pub(crate) fn show_unfocused() {
    let a = app();
    a.flyout_visible.set(true);
    rebuild();
    unsafe { ShowWindow(a.flyout, SW_SHOWNA) };
}

fn hide() {
    let a = app();
    unsafe { ShowWindow(a.flyout, SW_HIDE) };
    a.flyout_visible.set(false);
    // The only thing that outlives a repaint is the promotion a fresh grant
    // earns, and closing the surface is what spends it.
    agent::status_closed();
}

/// Tear down and re-lay the flyout's controls for the current state, then size and
/// anchor the borderless window to its content.
pub(crate) fn rebuild() {
    let a = app();
    let hwnd = a.flyout;
    let st = agent::status();
    destroy_children(hwnd);
    a.buttons.borrow_mut().clear();

    let dpi = unsafe { GetDpiForWindow(hwnd) }.max(96);
    let pad = dip(14, dpi);
    let inner = dip(340, dpi) - pad * 2;
    let mut col = Col { hwnd, dpi, x: pad, y: pad, w: inner };
    let s = tr();

    col.header(s.app_name, s.tagline, CMD_SETTINGS_GEAR);
    col.gap(10);

    // Anything for me to do? first, identity beneath, then the clocks, then the
    // explanation.
    if let Some(headline) = headline(&st) {
        col.title(headline, condition_role(st.condition));
    }
    if let Some(identity) = identity(&st) {
        col.flat_field(&identity, ROLE_FLAT_SUB, false);
    }
    // The ticket clock is promoted to the front page exactly when it is a
    // deadline rather than a countdown to an automatic renewal. On `Working` the
    // supply is intact and End Time is a number nobody is waiting on.
    if matches!(st.condition, Condition::Flaky | Condition::WillStop)
        && let Some(t) = &st.ticket
    {
        col.line(&fill(s.access_ends_in, &[("duration", &duration(t.remaining))]), ROLE_WARN);
    }
    if let Some(deadline) = st.grant_expiry {
        let left = days_until(deadline);
        let role = if left <= agent::GRANT_DUE_SOON_SECS / 86_400 { ROLE_WARN } else { ROLE_SUB };
        col.line(&fill(s.grant_expires_in, &[("days", &days(left))]), role);
    }

    // The explanation block. `NoSupply` is suppressed here and only here: with
    // the headline above it and the button below it, it is the third statement of
    // one fact.
    let lines: Vec<String> = st
        .blockers
        .iter()
        .filter(|b| **b != Blocker::NoSupply)
        .map(|b| blocker_line(*b, &st))
        .collect();
    if !lines.is_empty() || !st.message.is_empty() {
        col.gap(6);
        col.explanation(&lines, &st.message, rule_role(&st));
    }
    col.gap(12);

    // At most two, by the surface's own priority, and the second slot is spoken
    // for whenever a browser leg is cancellable or something has failed.
    let offer = ranked(&st);
    let mut slots: Vec<Action> = offer.iter().take(1).copied().collect();
    let mut extra = None;
    if st.actions.contains(&Action::Cancel) {
        slots.push(Action::Cancel);
    } else if (!lines.is_empty() || st.fault) && !st.message.is_empty() {
        // The one conditional route to the log, which is what keeps the
        // permanent one in Settings the only permanent one.
        extra = Some((s.act_open_log, CMD_OPEN_LOG));
    } else {
        slots.extend(offer.iter().skip(1).take(1).copied());
    }
    if slots.is_empty() && extra.is_none() {
        col.wrap(s.no_action, ROLE_SUB);
    } else {
        col.action_buttons(&slots, &st, extra);
    }
    finish(&mut col, &st, dpi, pad);
}

/// The marquee, the details drawer, and the window's own size. Shared by the two
/// ways the button row can end.
fn finish(col: &mut Col, st: &Status, dpi: u32, pad: i32) {
    let a = app();
    // A shape, not a word: the Win32 idiom for *something is running*, owing no
    // string in eleven languages.
    if !st.in_flight.is_empty() {
        col.gap(6);
        col.marquee();
    }
    // Every row of the drawer would otherwise describe a ticket nothing can use.
    if st.usable {
        col.gap(10);
        let open = a.details_expanded.get();
        col.disclosure(tr().details_heading, open, CMD_TOGGLE_DETAILS);
        if open {
            col.gap(4);
            details(col, st);
        }
    }

    let total_h = col.y + pad;
    let (w, h) = (dip(340, dpi), total_h);
    let (x, y) = anchor_pos(w, h, dip(MARGIN, dpi));
    unsafe {
        SetWindowPos(col.hwnd, std::ptr::null_mut(), x, y, w, h, 0);
        InvalidateRect(col.hwnd, std::ptr::null(), 1);
    }
}

/// What moves, plus the realm. Row order is fixed; three shapes are reachable.
fn details(col: &mut Col, st: &Status) {
    let s = tr();
    if let Some(t) = &st.ticket {
        col.meter(
            &duration(t.remaining),
            if st.condition == Condition::Working { ROLE_OK } else { ROLE_WARN },
            t.fraction,
        );
        col.gap(8);
    }
    // Constant per machine, and it names the subject every other row is about --
    // which is why it leads and why a drawer of constants is not what this is.
    col.detail(s.d_realm, &st.realm);
    if !st.source.is_empty() {
        col.detail(s.d_source, &st.source);
    }
    if let Some(t) = &st.ticket {
        let value = if t.renewable { s.d_ticket_value } else { s.d_ticket_value_norenew };
        col.detail(
            s.d_ticket,
            &fill(value, &[("time", &kerbridge_client::time::local_time_string(t.end))]),
        );
    }
    col.detail(
        s.d_supply,
        match st.supply {
            Supply::Grant => s.d_supply_grant,
            Supply::WindowsSignIn => s.d_supply_wam,
            Supply::BrowserSignIn => s.d_supply_browser,
            Supply::None => s.d_supply_none,
        },
    );
    if let Some(next) = st.next_attempt_at_earliest {
        col.detail(s.d_next, &kerbridge_client::time::local_time_string(next));
    }
}

/// The rendered width of a label in the UI font, in physical px. Half of the
/// stacking test; the other half is the shield allowance.
fn text_width(text: &str) -> i32 {
    // Measured against a width nothing can wrap at, so the answer is the label's
    // own width rather than the column's.
    measure_width(font_for(false), text)
}

// ---- the rows that know what they are showing ------------------------------

impl Col {
    /// The explanation block: a 2 dip vertical rule, a 10 dip indent, blocker
    /// lines and then `message` in subtext. The rule carries the severity, which
    /// is why nothing inside it is colored.
    fn explanation(&mut self, lines: &[String], message: &str, rule_role: isize) {
        let rule_w = self.d(2).max(1);
        let indent = self.d(10);
        let text_x = self.x + rule_w + indent;
        let text_w = self.w - rule_w - indent;
        let font = font_for(false);
        let top = self.y;

        for line in lines {
            let h = measure_text(font, line, text_w).max(self.d(16));
            make_static(
                self.hwnd,
                line,
                text_x,
                self.y,
                text_w,
                h,
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                ROLE_TEXT,
                false,
            );
            self.y += h;
        }
        if !message.is_empty() {
            let h = measure_text(font, message, text_w).max(self.d(16));
            make_static(
                self.hwnd,
                message,
                text_x,
                self.y,
                text_w,
                h,
                WS_CHILD | WS_VISIBLE | SS_LEFT,
                ROLE_SUB,
                false,
            );
            self.y += h;
        }
        // Last, now that its height is known: the same empty STATIC the hairline
        // uses, with its width and height swapped.
        make_static(
            self.hwnd,
            "",
            self.x,
            top,
            rule_w,
            self.y - top,
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            rule_role,
            false,
        );
    }

    /// Header row: logo on the left, app name + tagline, and a gear on the right that
    /// opens Settings (a discoverable path for anyone who misses right-click on the tray).
    fn header(&mut self, title: &str, tagline: &str, gear_id: u16) {
        let icon_sz = self.d(34);
        let gear_sz = self.d(30);
        let a = app();
        // Rendered at the control's own size. `SS_REALSIZECONTROL` still scales the
        // icon to the control, but with nothing left to scale it is a no-op rather
        // than a resampler.
        let logo = a.logo_at(icon_sz.max(1) as u32);
        unsafe {
            let lg = CreateWindowExW(
                0,
                wide("STATIC").as_ptr(),
                std::ptr::null(),
                WS_CHILD | WS_VISIBLE | SS_ICON | SS_REALSIZECONTROL,
                self.x,
                self.y,
                icon_sz,
                icon_sz,
                self.hwnd,
                std::ptr::null_mut(),
                a.hinstance,
                std::ptr::null(),
            );
            SendMessageW(lg, STM_SETICON, logo as WPARAM, 0);
        }
        // Gear as a flat owner-draw BUTTON (not an SS_NOTIFY static) so it is a real
        // control in the Tab order and Space/Enter open Settings -- clicking still works.
        make_flat_button(
            self.hwnd,
            "\u{E713}",
            self.x + self.w - gear_sz,
            self.y + (icon_sz - gear_sz) / 2,
            gear_sz,
            gear_sz,
            gear_id,
            ROLE_GEAR,
            a.font_icon,
        );
        let text_x = self.x + icon_sz + self.d(10);
        let text_w = self.w - icon_sz - self.d(10) - gear_sz - self.d(6);
        make_static(
            self.hwnd,
            title,
            text_x,
            self.y,
            text_w,
            self.d(18),
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            ROLE_TEXT,
            true,
        );
        make_static(
            self.hwnd,
            tagline,
            text_x,
            self.y + self.d(18),
            text_w,
            self.d(15),
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            ROLE_SUB,
            false,
        );
        self.y += icon_sz.max(self.d(33));
    }

    /// "Access valid for" row and its bar.
    fn meter(&mut self, value: &str, value_role: isize, frac: f32) {
        let s = tr();
        let row_h = self.d(16);
        make_static(
            self.hwnd,
            s.meter_label,
            self.x,
            self.y,
            self.w / 2,
            row_h,
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            ROLE_SUB,
            false,
        );
        make_static(
            self.hwnd,
            value,
            self.x + self.w / 2,
            self.y,
            self.w / 2,
            row_h,
            WS_CHILD | WS_VISIBLE | SS_RIGHT,
            value_role,
            true,
        );
        self.y += row_h + self.d(4);

        let bar_h = self.d(6);
        let t = app().theme.get();
        let bar_color = if value_role == ROLE_WARN { t.warn } else { t.ok };
        let pb = self.progress_bar(bar_h, 0);
        unsafe {
            SendMessageW(pb, PBM_SETRANGE32, 0, 1000);
            SendMessageW(pb, PBM_SETBARCOLOR, 0, bar_color as LPARAM);
            SendMessageW(pb, PBM_SETBKCOLOR, 0, t.surface as LPARAM);
            SendMessageW(pb, PBM_SETPOS, (frac * 1000.0) as WPARAM, 0);
        }
        self.y += bar_h;
    }

    /// The `in_flight` marquee: a hairline under the button row that says
    /// something is running, and nothing about what.
    fn marquee(&mut self) {
        let h = self.d(4);
        let t = app().theme.get();
        let pb = self.progress_bar(h, PBS_MARQUEE);
        unsafe {
            SendMessageW(pb, PBM_SETBARCOLOR, 0, t.accent as LPARAM);
            SendMessageW(pb, PBM_SETBKCOLOR, 0, t.bg as LPARAM);
            SendMessageW(pb, PBM_SETMARQUEE, 1, 30);
        }
        self.y += h;
    }

    /// A label:value detail row. The value is a copyable flat field (right-aligned).
    fn detail(&mut self, label: &str, value: &str) {
        let h = self.d(20);
        make_static(
            self.hwnd,
            label,
            self.x,
            self.y,
            self.w / 2,
            h,
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            ROLE_SUB,
            false,
        );
        make_flat_edit(
            self.hwnd,
            value,
            self.x + self.w / 2,
            self.y,
            self.w / 2,
            h,
            ROLE_FLAT_TEXT,
            true,
        );
        self.y += h;
    }

    /// The flyout's button row: at most two, paired when both labels fit at half
    /// width and stacked when they do not.
    ///
    /// **The rule is what matters, not the widths.** Six labels in the
    /// whole product cross the line and every one of them stacks; the narrowest
    /// margin in the swept set is two tenths of a dip, so any change to the
    /// shield's 18, the 16 of padding or the 312 of inner width flips one
    /// silently.
    fn action_buttons(&mut self, acts: &[Action], st: &Status, extra: Option<(&str, u16)>) {
        let a = app();
        let mut defs: Vec<(String, u16, bool)> = Vec::new();
        for act in acts {
            let id = CMD_ACTION_BASE + a.buttons.borrow().len() as u16;
            a.buttons.borrow_mut().push(*act);
            // Disabled rather than hidden while it runs: the control stays where
            // the user last saw it.
            let running = st.in_flight.contains(act);
            defs.push((action_label(*act, st), id, !running));
        }
        if let Some((label, id)) = extra {
            defs.push((label.to_owned(), id, true));
        }
        let shielded: Vec<bool> = acts
            .iter()
            .map(|act| {
                matches!(
                    act,
                    Action::Enroll
                        | Action::Reenroll
                        | Action::Unenroll
                        | Action::RestartWorkstation
                )
            })
            .chain(std::iter::once(false))
            .collect();

        let half = (self.w - self.d(8)) / 2;
        // A label needs its own width, plus the shield's allowance where one is
        // drawn, plus the button's horizontal padding, against half the row.
        let fits = |i: usize, label: &str| {
            let shield = if shielded.get(i).copied().unwrap_or(false) { self.d(18) } else { 0 };
            text_width(label) + shield + self.d(16) <= half
        };
        let pair = defs.len() == 2 && defs.iter().enumerate().all(|(i, (l, ..))| fits(i, l));

        let h = self.d(30);
        let rows: Vec<Vec<usize>> =
            if pair { vec![vec![0, 1]] } else { (0..defs.len()).map(|i| vec![i]).collect() };
        for (r, row) in rows.iter().enumerate() {
            if r > 0 {
                self.gap(6);
            }
            let n = row.len() as i32;
            let spacing = self.d(8);
            let bw = (self.w - spacing * (n - 1)) / n;
            for (slot, &i) in row.iter().enumerate() {
                let (label, id, enabled) = &defs[i];
                // The first pick is the default button unless `in_flight` has
                // disabled it.
                let primary = i == 0 && *enabled;
                let b = make_button(
                    self.hwnd,
                    label,
                    self.x + slot as i32 * (bw + spacing),
                    self.y,
                    bw,
                    h,
                    *id,
                    primary,
                );
                unsafe {
                    if shielded.get(i).copied().unwrap_or(false) {
                        SendMessageW(b, BCM_SETSHIELD, 0, 1);
                    }
                    if !*enabled {
                        EnableWindow(b, 0);
                    }
                }
            }
            self.y += h;
        }
    }
}
