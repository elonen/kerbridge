//! One dialog, four phases, six operations.
//!
//! ```text
//! confirm ──commit──▶ waiting ──▶ working ──▶ result
//!    ▲                   │           │
//!    └────decline────────┘           └──Close──▶ detached, outcome → notification
//! ```
//!
//! **Confirm in the parent, then elevate**, never the other way round. Nothing
//! about the confirmation needs privilege: `plan_text`, `needs_reboot` and
//! `running_dependents` are all computable here, and the last is measured to
//! succeed unelevated in the same session where `SERVICE_STOP` is refused with
//! error 5 -- which makes the split necessary rather than tidy.
//!
//! The flyout can host none of this: it hides on blur and the UAC secure desktop
//! takes focus, so the surface would vanish exactly when it is meant to say
//! *waiting*.
//!
//! **No Cancel and no Stop**, which is the one deliberate departure from the
//! platform guidance. Cancel is impossible because none of these operations is
//! reversible, and Stop is worse than useless: its own definition -- *leaves the
//! partially completed operation intact* -- is precisely the outcome that must
//! not be offered, which here means `Netlogon` left stopped. **Close detaches
//! instead**: the window goes, the work continues, and the outcome arrives as a
//! notification.

use std::cell::{Cell, RefCell};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{FillRect, InvalidateRect};
use windows_sys::Win32::UI::Controls::BCM_SETSHIELD;
use windows_sys::Win32::UI::HiDpi::{AdjustWindowRectExForDpi, GetDpiForWindow};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, GetWindowRect, KillTimer, SW_HIDE, SW_SHOW, SendMessageW,
    SetForegroundWindow, SetTimer, SetWindowPos, ShowWindow, WM_CLOSE, WM_COMMAND, WM_CTLCOLORBTN,
    WM_CTLCOLOREDIT, WM_CTLCOLORSTATIC, WM_ERASEBKGND, WM_TIMER, WS_CAPTION, WS_SYSMENU,
};

use kerbridge_client::agent::{self, Outcome};
use kerbridge_client::describe::Action;
use kerbridge_client::present::days_until;
use kerbridge_client::strings::{days, duration, fill, tr};
use kerbridge_client::{enroll, repair};

use crate::app::{app, register_class};
use crate::sys::{center_on_work_area, client_size, dip, loword, measure_width, wide};
use crate::theme::apply_frame;
use crate::ui::{
    Col, ICON_BIG, ICON_SMALL, ROLE_SUB, ROLE_TEXT, ROLE_WARN, SWP_NOACTIVATE, SWP_NOMOVE,
    SWP_NOZORDER, WM_SETICON, ctl_color, destroy_children, font_for, make_button, retheme_children,
};

const MODAL_CLASS: &str = "NasAuthModal";
const CMD_COMMIT: u16 = 300;
const CMD_CLOSE: u16 = 301;
const IDCANCEL: u16 = 2;
/// Ticks the working phase, so the bar appears only once the wait is long enough
/// to be worth a shape.
const TIMER_WORKING: usize = 7;
/// A busy indicator first, an **indeterminate** bar only after this long.
/// Determinate is impossible: progress through an opaque elevated child is not
/// observable.
///
/// **It will look dead on a healthy machine, and that is the point — do not
/// delete it on a fast measurement.** Measured 2026-08-05: a Workstation restart
/// on a bench box with nothing mounted finished in about a second, four seconds
/// short of ever starting this. But stopping `LanmanWorkstation` blocks on
/// outstanding I/O, and this repair only runs *after* an NTLM fallback — a
/// redirector already holding a session it cannot authenticate. The condition
/// that triggers the repair is the condition that makes the stop slow, so one
/// second is the floor, not the typical case.
const BAR_AFTER_SECS: u32 = 5;
/// `SWP_NOSIZE` -- move without touching the size the layout just chose.
const SWP_NOSIZE: u32 = 0x0001;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Confirm,
    /// The secure desktop is up and nothing is running yet, and the dimmed
    /// desktop proves it. Shielded operations only.
    Waiting,
    Working,
    Result,
}

/// The modal's own state. Lives in [`crate::app::App`], like every other window here.
pub(crate) struct State {
    hwnd: Cell<HWND>,
    /// Which of the six is on screen. `None` when the window is not up -- which
    /// is also what makes a later outcome *detached*.
    op: Cell<Option<Action>>,
    phase: Cell<Option<Phase>>,
    /// Seconds the working phase has been on screen.
    elapsed: Cell<u32>,
    result: RefCell<Option<(bool, String, Option<String>)>>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            hwnd: Cell::new(std::ptr::null_mut()),
            op: Cell::new(None),
            phase: Cell::new(None),
            elapsed: Cell::new(0),
            result: RefCell::new(None),
        }
    }
}

impl State {
    pub(crate) fn window(&self) -> HWND {
        self.hwnd.get()
    }

    pub(crate) fn is_open(&self) -> bool {
        self.op.get().is_some()
    }
}

pub(crate) fn register(hinstance: HWND) {
    register_class(MODAL_CLASS, Some(wndproc), hinstance);
}

/// Open the dialog on its confirmation. Nothing has happened yet and nothing will
/// until the commit.
pub(crate) fn open(op: Action) {
    let a = app();
    if a.modal.hwnd.get().is_null() {
        let hwnd = unsafe {
            CreateWindowExW(
                0,
                wide(MODAL_CLASS).as_ptr(),
                wide(tr().app_name).as_ptr(),
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
        a.modal.hwnd.set(hwnd);
        apply_frame(hwnd, a.theme.get().dark);
        unsafe {
            let (small, big) = a.title_icons(hwnd);
            SendMessageW(hwnd, WM_SETICON, ICON_SMALL, small as LPARAM);
            SendMessageW(hwnd, WM_SETICON, ICON_BIG, big as LPARAM);
        }
    }
    a.modal.op.set(Some(op));
    *a.modal.result.borrow_mut() = None;
    to_phase(Phase::Confirm);
    let hwnd = a.modal.hwnd.get();
    let mut r = RECT { left: 0, top: 0, right: 0, bottom: 0 };
    unsafe { GetWindowRect(hwnd, &mut r) };
    let (x, y) = center_on_work_area(r.right - r.left, r.bottom - r.top);
    unsafe {
        SetWindowPos(hwnd, std::ptr::null_mut(), x, y, 0, 0, SWP_NOZORDER | SWP_NOSIZE);
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
    }
}

/// One of the six finished. Rendered here while the window is up and about this
/// operation; otherwise it detached, and the notification is what it becomes.
pub(crate) fn finished(action: Action, outcome: Outcome) {
    let a = app();
    let mine = a.modal.op.get() == Some(action) && !a.modal.hwnd.get().is_null();
    match outcome {
        // A decision, not a fault: back to the question, unchanged and silent.
        Outcome::Declined if mine => to_phase(Phase::Confirm),
        Outcome::Declined => {}
        Outcome::Done { message, detail } => {
            report(mine, action, true, message, detail);
        }
        Outcome::Failed { message } => {
            report(mine, action, false, message, None);
        }
    }
    crate::refresh_ui();
}

fn report(mine: bool, action: Action, ok: bool, message: String, detail: Option<String>) {
    let a = app();
    if mine {
        *a.modal.result.borrow_mut() = Some((ok, message, detail));
        to_phase(Phase::Result);
        return;
    }
    // Detached, or never had a dialog. The title names the operation, because
    // there is no per-failure headline anywhere else in the product.
    let s = tr();
    let realm = agent::status().realm;
    let title = if ok {
        s.app_name.to_owned()
    } else {
        match action {
            Action::Enroll | Action::Reenroll => fill(s.fail_title_enroll, &[("realm", &realm)]),
            Action::Unenroll => fill(s.fail_title_unenroll, &[("realm", &realm)]),
            Action::RestartWorkstation => s.fail_title_repair.to_owned(),
            _ => s.settings_section_authorization.to_owned(),
        }
    };
    let body = match detail {
        Some(detail) => format!("{message} {detail}"),
        None => message,
    };
    crate::tray::notify(
        &title,
        &body,
        if ok { agent::Severity::Info } else { agent::Severity::Error },
    );
}

/// The prompt has been answered and the child is running.
pub(crate) fn elevation_granted(action: Action) {
    let a = app();
    if a.modal.op.get() == Some(action) && a.modal.phase.get() == Some(Phase::Waiting) {
        to_phase(Phase::Working);
    }
}

pub(crate) fn retheme(dark: bool) {
    let hwnd = app().modal.hwnd.get();
    if !hwnd.is_null() {
        apply_frame(hwnd, dark);
        retheme_children(hwnd, dark);
        unsafe { InvalidateRect(hwnd, std::ptr::null(), 1) };
    }
}

fn close() {
    let a = app();
    unsafe {
        KillTimer(a.modal.hwnd.get(), TIMER_WORKING);
        ShowWindow(a.modal.hwnd.get(), SW_HIDE);
    }
    a.modal.op.set(None);
    a.modal.phase.set(None);
}

fn to_phase(phase: Phase) {
    let a = app();
    a.modal.phase.set(Some(phase));
    a.modal.elapsed.set(0);
    unsafe { KillTimer(a.modal.hwnd.get(), TIMER_WORKING) };
    if phase == Phase::Working {
        unsafe { SetTimer(a.modal.hwnd.get(), TIMER_WORKING, 1000, None) };
    }
    layout();
}

/// The commit, and the only place any of the six starts.
fn commit() {
    let Some(op) = app().modal.op.get() else { return };
    let started = match op {
        Action::Enroll => agent::begin_enroll(),
        Action::Reenroll => agent::begin_reenroll(),
        Action::Unenroll => agent::begin_unenroll(),
        Action::RestartWorkstation => agent::begin_repair(),
        Action::CreateGrant => agent::create_grant(),
        Action::GiveUpGrant => agent::give_up_grant_now(),
        _ => false,
    };
    // Advanced only on something that actually started. Every one of these
    // refuses silently when the agent's single busy slot is taken, and the
    // dialog used to move regardless -- into `Waiting`, which disables Close,
    // for work that would never post an outcome. The confirm button is disabled
    // in that state, so this is the race between drawing it and pressing it.
    if started {
        // Only the shielded ones have a permission to wait for; the grant key is
        // user-scope and a browser sign-in is not an elevation.
        to_phase(if shielded(op) { Phase::Waiting } else { Phase::Working });
    }
    crate::refresh_ui();
}

/// **The shield goes on unconditionally**, even where UAC is off or the user is
/// the built-in Administrator, and it never reflects state. *Remove
/// authorization…* carries none: the grant key is user-scope, so destroying it
/// needs no elevation. Irreversible and privileged are independent properties and
/// only the second is the shield's business.
fn shielded(op: Action) -> bool {
    matches!(op, Action::Enroll | Action::Reenroll | Action::Unenroll | Action::RestartWorkstation)
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_CTLCOLORSTATIC | WM_CTLCOLOREDIT | WM_CTLCOLORBTN => ctl_color(wparam, lparam),
        WM_ERASEBKGND => {
            let (w, h) = client_size(hwnd);
            let r = RECT { left: 0, top: 0, right: w, bottom: h };
            unsafe { FillRect(wparam as _, &r, app().theme.get().bg_brush) };
            1
        }
        WM_COMMAND => {
            match loword(wparam) as u16 {
                CMD_COMMIT => commit(),
                // Close in the working phase detaches; anywhere else it is the
                // ordinary dismissal. Escape reaches here too, which is right:
                // in the confirm it is the Cancel that is already the default.
                CMD_CLOSE | IDCANCEL => close(),
                _ => {}
            }
            0
        }
        WM_TIMER => {
            let a = app();
            let elapsed = a.modal.elapsed.get() + 1;
            a.modal.elapsed.set(elapsed);
            if elapsed == BAR_AFTER_SECS {
                layout();
            }
            0
        }
        WM_CLOSE => {
            close();
            0
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

/// What each operation states before the click: what it does in system terms, who
/// else pays *named*, and what to do first.
struct Prompt {
    question: String,
    /// Prose paragraphs, in order.
    body: Vec<String>,
    /// The literal plan, where the plan *is* the confirmation.
    plan: Option<String>,
    commit: String,
    working: String,
}

fn prompt_for(op: Action) -> Prompt {
    let s = tr();
    let st = agent::status();
    let realm = st.realm.clone();
    match op {
        Action::RestartWorkstation => {
            let mut body = vec![fill(s.dlg_repair_body, &[("realm", &realm)])];
            // Generated rather than warned about generically, and omitted when
            // there is nothing to name.
            let deps = repair::running_dependents();
            if !deps.is_empty() {
                body.push(fill(s.dlg_repair_dependents, &[("services", &deps.join(", "))]));
            }
            body.push(s.dlg_repair_save.into());
            Prompt {
                question: s.dlg_repair_question.into(),
                body,
                plan: None,
                commit: s.dlg_repair_commit.into(),
                working: s.dlg_repair_working.into(),
            }
        }
        Action::Enroll | Action::Reenroll => Prompt {
            question: fill(s.dlg_enroll_question, &[("realm", &realm)]),
            body: vec![s.dlg_enroll_body.into(), s.dlg_enroll_reboot.into()],
            plan: Some(enroll::plan_text(&agent::kerberos_config())),
            commit: s.dlg_enroll_commit.into(),
            working: s.dlg_enroll_working.into(),
        },
        Action::Unenroll => Prompt {
            question: fill(s.dlg_unenroll_question, &[("realm", &realm)]),
            body: vec![s.dlg_unenroll_body.into(), fill(s.dlg_unenroll_note, &[("realm", &realm)])],
            plan: Some(enroll::unenroll_plan_text(&realm)),
            commit: fill(s.dlg_unenroll_commit, &[("realm", &realm)]),
            working: fill(s.dlg_unenroll_working, &[("realm", &realm)]),
        },
        Action::GiveUpGrant => {
            let mut body = vec![fill(s.dlg_grant_off_body, &[("broker", &st.broker_host)])];
            // Two bodies, keyed on the delegation -- the same value the exchange
            // guard keys on, so the sentence and the machine cannot disagree.
            if st.grant_target.is_empty() {
                body.push(fill(s.dlg_grant_off_body_own, &[("realm", &realm)]));
            } else {
                // The *ticket's* remaining life, not the grant's days: after
                // removal no renewal can land, so access stops at ticket end.
                // The affirming clause renders only while one is live.
                if let Some(t) = st.ticket.as_ref().filter(|t| t.remaining > 0) {
                    body.push(fill(
                        s.dlg_grant_off_body_delegated,
                        &[
                            ("target", &st.grant_target),
                            ("realm", &realm),
                            ("remaining", &duration(t.remaining)),
                        ],
                    ));
                }
            }
            Prompt {
                question: s.dlg_grant_off_question.into(),
                body,
                plan: None,
                commit: s.dlg_grant_off_commit.into(),
                working: s.dlg_grant_off_working.into(),
            }
        }
        _ => {
            let left = st.grant_expiry.map_or_else(
                || days(i64::from(agent::settings_view().grant_days)),
                |d| days(days_until(d)),
            );
            Prompt {
                question: String::new(),
                body: vec![fill(s.grant_confirm, &[("days", &left)])],
                plan: None,
                commit: s.dlg_grant_commit.into(),
                working: s.dlg_grant_working.into(),
            }
        }
    }
}

fn layout() {
    let a = app();
    let hwnd = a.modal.hwnd.get();
    let Some(op) = a.modal.op.get() else { return };
    let Some(phase) = a.modal.phase.get() else { return };
    destroy_children(hwnd);

    let s = tr();
    let dpi = unsafe { GetDpiForWindow(hwnd) }.max(96);
    let pad = dip(16, dpi);
    let inner = dip(420, dpi) - pad * 2;
    let mut col = Col { hwnd, dpi, x: pad, y: pad, w: inner };
    let prompt = prompt_for(op);

    match phase {
        Phase::Confirm => {
            if !prompt.question.is_empty() {
                col.title(&prompt.question, ROLE_WARN);
                col.gap(8);
            }
            for (i, para) in prompt.body.iter().enumerate() {
                if i > 0 {
                    col.gap(8);
                }
                col.wrap(para, ROLE_TEXT);
            }
            if let Some(plan) = &prompt.plan {
                col.gap(8);
                col.mono(plan);
            }
        }
        Phase::Waiting => col.wrap(s.dlg_waiting, ROLE_TEXT),
        Phase::Working => {
            col.wrap(&prompt.working, ROLE_TEXT);
            if a.modal.elapsed.get() >= BAR_AFTER_SECS {
                col.gap(10);
                let bar = col.progress_bar(col.d(6), crate::ui::PBS_MARQUEE);
                unsafe { SendMessageW(bar, crate::ui::PBM_SETMARQUEE, 1, 30) };
                col.y += col.d(6);
            }
        }
        Phase::Result => {
            // Held across `col.wrap`, which creates windows and sends messages,
            // both of which re-enter this window's procedure. The same rule as
            // `settings::show_current_page`: no `borrow_mut` of `result` may
            // become reachable from a window message.
            let result = a.modal.result.borrow();
            let (ok, message, detail) = result.as_ref().expect("the result phase has a result");
            col.wrap(message, if *ok { ROLE_TEXT } else { ROLE_WARN });
            if let Some(detail) = detail {
                col.gap(6);
                col.wrap(detail, ROLE_SUB);
            }
        }
    }

    // Footer: 12/16 padding, buttons at least 110 dip.
    col.gap(16);
    let bw = col.d(110);
    let bh = col.d(30);
    let gap = col.d(8);
    match phase {
        Phase::Confirm => {
            // 110 is a floor, not the width. Every commit label here is a verb
            // phrase rather than a word -- and one of them interpolates the realm
            // -- so a fixed width clips whichever is longest in whichever of the
            // eleven languages, which is not a set anyone can eyeball.
            let cw = (measure_width(font_for(false), &prompt.commit)
                + col.d(16)
                + if shielded(op) { col.d(18) } else { 0 })
            .max(bw);
            // Cancel is the default: this is the one place where the safe answer
            // is the one Enter gives.
            let commit = make_button(
                hwnd,
                &prompt.commit,
                col.x + col.w - cw - gap - bw,
                col.y,
                cw,
                bh,
                CMD_COMMIT,
                false,
            );
            if shielded(op) {
                unsafe { SendMessageW(commit, BCM_SETSHIELD, 0, 1) };
            }
            // Disabled rather than hidden, like every other control here: the
            // agent runs one of these at a time, and a commit into an occupied
            // slot starts nothing. `in_flight` is the faithful proxy -- the slot
            // is claimed and `started` recorded in the same breath.
            let busy = agent::status().in_flight.iter().any(|a| !a.outside_busy_slot());
            if busy && !op.outside_busy_slot() {
                unsafe { EnableWindow(commit, 0) };
            }
            make_button(hwnd, s.btn_cancel, col.x + col.w - bw, col.y, bw, bh, CMD_CLOSE, true);
        }
        _ => {
            let close = make_button(
                hwnd,
                s.dlg_close,
                col.x + col.w - bw,
                col.y,
                bw,
                bh,
                CMD_CLOSE,
                phase == Phase::Result,
            );
            // Nothing is running yet and the secure desktop owns the screen, so
            // there is nothing here to dismiss.
            if phase == Phase::Waiting {
                unsafe { EnableWindow(close, 0) };
            }
        }
    }
    col.y += bh;

    let mut r = RECT { left: 0, top: 0, right: dip(420, dpi), bottom: col.y + pad };
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
