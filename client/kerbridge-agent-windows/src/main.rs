//! NAS Access systray agent -- the KerBridge client as a per-user background agent
//! on Windows (see `client/DESIGN.md`).
//!
//! It signs the user in to the cloud IdP in the system browser, exchanges the token
//! with the broker for a real KDC-signed TGT, injects it into this logon session,
//! and then keeps re-injecting at ~50 % of ticket lifetime so the ticket never
//! lapses under an open SMB session. All of that is the `kerbridge-client`
//! library; this crate is the window -- it draws and dispatches, and decides
//! nothing about the protocol.
//!
//! Native Win32 on stock controls (no UI toolkit) so it looks and behaves like a
//! normal Windows tray app and follows the OS light/dark theme:
//!   * left-click tray  -> toggle the status flyout (borderless popup, dismiss-on-blur)
//!   * right-click tray -> native context menu (TrackPopupMenu -- never a taskbar window)
//!   * Settings          -> a normal tabbed window with a real title bar (dark via DWM)
//!   * anything privileged or irreversible -> the four-phase modal in [`modal`]
//!
//! Text fields are real EDIT/STATIC controls, so selection + copy work natively.
//! User-visible text comes from `kerbridge_client::strings`.
//!
//! | module | what |
//! |---|---|
//! | `app.rs` | the window handles and shared state, and the pointer that publishes them |
//! | `present.rs` | `Status` -> words and color roles, and the one ranking in the product |
//! | `ui.rs` | the shared control vocabulary: roles, factories, the layout cursor |
//! | `tray.rs` · `flyout.rs` · `settings.rs` · `modal.rs` | one surface each |
//! | `theme.rs` · `sys.rs` | light/dark for stock controls; Win32 plumbing |
//! | `wam.rs` · `elevated.rs` | the Windows-sign-in token source; the elevated one-shots |
//!
//! This file is what is left: the process, and the three fan-outs that no single
//! surface owns. [`WinHost`] is the whole of what the core asks this crate for.
#![windows_subsystem = "windows"]

mod app;
mod elevated;
mod flyout;
mod modal;
mod present;
mod settings;
mod sys;
mod theme;
mod tray;
mod ui;
mod wam;

use std::cell::{Cell, RefCell};
use std::ffi::c_void;

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::Graphics::Gdi::{CreateFontIndirectW, HFONT, LOGFONTW};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::{INITCOMMONCONTROLSEX, InitCommonControlsEx};
use windows_sys::Win32::UI::HiDpi::{
    DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DispatchMessageW, GA_ROOT, GetAncestor, GetMessageW, IsDialogMessageW,
    KillTimer, MSG, NONCLIENTMETRICSW, PostMessageW, SPI_GETNONCLIENTMETRICS, SetTimer,
    SystemParametersInfoW, TranslateMessage, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_POPUP,
};

use kerbridge_client::agent::{self, NativeToken, Outcome, Raise, Severity};
use kerbridge_client::describe::{Action, Blocker};
use kerbridge_client::discovery::OidcConfig;
use kerbridge_client::present::action_label;
use kerbridge_client::strings::tr;

use app::{App, VERSION, app, register_class};
use present::ranked;
use sys::wide;
use theme::{Theme, allow_dark_for_window, init_app_dark_mode};
use tray::{OWNER_CLASS, TIMER_TICK, TIMER_TICK_MS, WM_AGENT, WM_SHOW_FLYOUT};

// ---- the core's view of us -------------------------------------------------

/// The Win32 half of [`agent::Host`] -- everything the state machine cannot do
/// without a window, and the only thing the core knows about this crate.
///
/// The owner window is kept as a `usize` because an `HWND` is a raw pointer and
/// this is shared with worker threads.
struct WinHost {
    owner: usize,
}

impl agent::Host for WinHost {
    /// A posted message, so the worker returns immediately and the drain happens
    /// on the UI thread in `tray::wndproc`. A failed post means the window is
    /// already gone and the process is on its way out; the queued event dies with
    /// it, which is what should happen to it.
    fn wake(&self) {
        unsafe { PostMessageW(self.owner as HWND, WM_AGENT, 0, 0) };
    }

    /// Gate 2: an outcome is announced by whatever surface is on screen, and a
    /// notification is what happens when none is. The core has already logged
    /// this, so silence here costs the record nothing.
    fn notify(&self, title: &str, body: &str, severity: Severity) {
        if app().flyout_visible.get() || app().modal.is_open() {
            return;
        }
        tray::notify(title, body, severity);
    }

    fn finished(&self, action: Action, outcome: Outcome) {
        modal::finished(action, outcome);
    }

    fn elevating(&self, action: Action) {
        modal::elevation_granted(action);
    }

    fn primary_action_label(&self) -> String {
        let st = agent::status();
        ranked(&st).first().map(|a| action_label(*a, &st)).unwrap_or_else(|| tr().no_action.into())
    }

    fn raise(&self, _target: Raise) {
        // One surface answers both targets: the flyout draws the `NtlmFallback`
        // blocker and the repair button from the same status it always did, so
        // there is nothing for a repair-shaped raise to open instead.
        flyout::show_unfocused();
    }

    fn open_path(&self, path: &str) {
        sys::shell_open(path);
    }

    fn native_token(&self, oidc: &OidcConfig) -> NativeToken {
        match wam::acquire(oidc) {
            wam::Outcome::Token(t) => NativeToken::Token(t),
            wam::Outcome::Unavailable => NativeToken::Unavailable,
        }
    }
}

// ---- entry -----------------------------------------------------------------

/// What a one-shot invocation asked for: the verb, the broker to run it against,
/// and where to leave the sentence the parent will read.
///
/// Two binaries reach the same verbs and they were spelled differently: this one
/// took the broker positionally (`--enroll <url>`), the CLI takes it as a flag
/// (`--broker <url> --enroll`). Handing this binary the CLI's spelling used to
/// match no arm at all and fall through to starting a tray -- an enrollment that
/// silently did not happen, and looked like one that had. So accept either, and
/// treat an unrecognized leading flag as the mistake it is rather than as a
/// reason to open a tray.
fn one_shot(args: &[String]) -> Result<(Option<&str>, &str, &str), String> {
    let (mut mode, mut broker, mut result) = (None, "", "");
    let mut rest = args.iter().map(String::as_str);
    while let Some(arg) = rest.next() {
        match arg {
            "--enroll" | "--reenroll" | "--unenroll" | "--repair" => mode = Some(arg),
            "--broker" => broker = rest.next().unwrap_or_default(),
            "--result" => result = rest.next().unwrap_or_default(),
            // The positional spelling, valid only straight after the mode.
            _ if mode.is_some() && broker.is_empty() && !arg.starts_with('-') => broker = arg,
            _ => return Err(format!("unrecognized argument {arg:?}")),
        }
    }
    Ok((mode, broker, result))
}

fn main() {
    install_panic_hook();

    // Mode dispatch before any UI. These are the elevated one-shots the tray
    // relaunches itself for; they render nothing and report through a file.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (mode, broker, result) = match one_shot(&args) {
        Ok(parsed) => parsed,
        Err(e) => {
            // No console to print to -- this is a windows-subsystem binary -- so
            // the exit code is the whole report unless someone is watching a log.
            kerbridge_client::log::warn(&format!(
                "{e}. Usage: kerbridge-agent [--enroll|--reenroll|--unenroll <broker>] \
                 [--repair] [--result <path>]"
            ));
            std::process::exit(2);
        }
    };
    if let Some(mode) = mode {
        std::process::exit(elevated::run(mode, broker, result) as i32);
    }

    // One agent per user session. A second launch just raises the first one's
    // flyout -- which is also what makes the autostart entry safe to double-fire.
    if !sys::claim_single_instance("Local\\KerBridgeNasAuthTray") {
        let existing = sys::find_window(OWNER_CLASS);
        if !existing.is_null() {
            unsafe { PostMessageW(existing, WM_SHOW_FLYOUT, 0, 0) };
        }
        return;
    }

    unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        let icce = INITCOMMONCONTROLSEX {
            dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: 0x0000_FFFF, // ICC_ALL: standard + progress + tab + link classes
        };
        InitCommonControlsEx(&icce);

        let hinstance = GetModuleHandleW(std::ptr::null()) as HWND;
        let theme = Theme::current();
        init_app_dark_mode(theme.dark);

        let (font, font_bold, font_title, font_icon, font_mono) = create_fonts();

        register_class(OWNER_CLASS, Some(tray::wndproc), hinstance);
        register_class(flyout::FLYOUT_CLASS, Some(flyout::wndproc), hinstance);
        settings::register(hinstance);
        modal::register(hinstance);

        // Hidden owner window: holds the tray icon, receives its callbacks, the
        // timer, the worker events and theme-change broadcasts. Never shown.
        let owner = CreateWindowExW(
            WS_EX_TOOLWINDOW,
            wide(OWNER_CLASS).as_ptr(),
            wide("NAS Access").as_ptr(),
            WS_POPUP,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinstance,
            std::ptr::null(),
        );

        let flyout_hwnd = CreateWindowExW(
            WS_EX_TOOLWINDOW | WS_EX_TOPMOST,
            wide(flyout::FLYOUT_CLASS).as_ptr(),
            wide("NAS Access").as_ptr(),
            WS_POPUP,
            0,
            0,
            10,
            10,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinstance,
            std::ptr::null(),
        );

        app::publish(Box::leak(Box::new(App {
            hinstance,
            font,
            font_bold,
            font_title,
            font_icon,
            font_mono,
            logos: RefCell::new(Vec::new()),
            theme: Cell::new(theme),
            owner,
            flyout: flyout_hwnd,
            details_expanded: Cell::new(false),
            flyout_visible: Cell::new(false),
            tray_cur: Cell::new(std::ptr::null_mut()),
            shown_minute: Cell::new(i64::MIN),
            shown_condition: Cell::new(None),
            auto_hidden_at: Cell::new(None),
            buttons: RefCell::new(Vec::new()),
            menu_actions: RefCell::new(Vec::new()),
            settings: settings::State::default(),
            modal: modal::State::default(),
        })));

        allow_dark_for_window(owner, theme.dark);
        sys::register_for_restart();
        agent::init(Box::leak(Box::new(WinHost { owner: owner as usize })));
        kerbridge_client::log::info(&format!("NAS Access {VERSION} started"));

        tray::install();

        // The single heartbeat behind the re-injection schedule, the expiry
        // transition and the fallback poll. A zero return is a tray that paints
        // on events and never renews -- the failure this product exists to
        // prevent -- with nothing anywhere to say so.
        if SetTimer(owner, TIMER_TICK, TIMER_TICK_MS, None) == 0 {
            kerbridge_client::log::error("could not start the 1 Hz timer: nothing will re-inject");
        }

        // A machine with nothing configured, or one Windows does not know the
        // realm for, has something to be told; the flyout is the only affordance
        // that says what. Anything else starts quietly in the tray, which is what
        // an autostarted agent should do.
        let status = agent::status();
        if status
            .blockers
            .iter()
            .any(|b| matches!(b, Blocker::NoBrokerUrl | Blocker::RealmNotRegistered))
        {
            flyout::show();
        } else {
            // …and "quietly" includes signing in, when Windows can serve the
            // credential without asking. Nothing opens if it cannot.
            agent::autostart_sign_in();
        }

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            // The flyout, Settings and the modal are ordinary windows, not dialog
            // boxes, so Tab/Enter/Esc only work if we run their messages through
            // the dialog manager ourselves. Guarded by the message's root window,
            // because IsDialogMessage does not check that the message is even ours.
            if !dialog_handled(&mut msg) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }

        KillTimer(owner, TIMER_TICK);
        tray::remove_icon();
    }
}

/// Send panics to the log, because nothing else will.
///
/// This is a windows-subsystem binary: it has no stderr, so the default hook
/// writes the one useful sentence about a crash to a handle that does not exist,
/// and the only symptom a user gets is the tray icon disappearing. A panic
/// inside a window procedure is worse still -- `extern "system"` makes it
/// non-unwinding, so it aborts rather than returning an error -- which is
/// exactly the case where the message has to have been recorded already.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let at = info.location().map_or_else(String::new, |l| format!(" at {l}"));
        kerbridge_client::log::error(&format!(
            "panic{at}: {}",
            info.payload_as_str().unwrap_or("(no message)")
        ));
    }));
}

/// Give the dialog manager first refusal on a message aimed at one of our
/// windows: keyboard navigation, the default button, and Escape.
fn dialog_handled(msg: &mut MSG) -> bool {
    let a = app();
    let root = unsafe { GetAncestor(msg.hwnd, GA_ROOT) };
    if root.is_null() {
        return false;
    }
    let ours = root == a.flyout || root == a.settings.window() || root == a.modal.window();
    ours && unsafe { IsDialogMessageW(root, msg) != 0 }
}

fn create_fonts() -> (HFONT, HFONT, HFONT, HFONT, HFONT) {
    unsafe {
        let mut ncm: NONCLIENTMETRICSW = std::mem::zeroed();
        ncm.cbSize = size_of::<NONCLIENTMETRICSW>() as u32;
        SystemParametersInfoW(
            SPI_GETNONCLIENTMETRICS,
            ncm.cbSize,
            &mut ncm as *mut _ as *mut c_void,
            0,
        );
        let font = CreateFontIndirectW(&ncm.lfMessageFont);

        let mut bold: LOGFONTW = ncm.lfMessageFont;
        bold.lfWeight = 600;
        let font_bold = CreateFontIndirectW(&bold);

        // The condition headline: semibold and ~30% larger so the state reads at
        // a glance.
        let mut title: LOGFONTW = ncm.lfMessageFont;
        title.lfWeight = 600;
        title.lfHeight = (title.lfHeight as f32 * 1.3) as i32; // lfHeight is negative
        let font_title = CreateFontIndirectW(&title);

        // Gear glyph: Segoe MDL2 Assets (present since Win10) has the settings icon.
        // Sized up a touch so it reads as an affordance, not a tiny mark.
        let mut icon: LOGFONTW = ncm.lfMessageFont;
        set_face(&mut icon, "Segoe MDL2 Assets");
        icon.lfHeight = (icon.lfHeight as f32 * 1.4) as i32;
        let font_icon = CreateFontIndirectW(&icon);

        // The `ksetup` plan and the registry keys. Monospace because the plan
        // *is* the confirmation: it has to be readable as the literal commands
        // that run, not as prose about them.
        let mut mono: LOGFONTW = ncm.lfMessageFont;
        set_face(&mut mono, "Consolas");
        mono.lfHeight = (mono.lfHeight as f32 * 0.92) as i32;
        let font_mono = CreateFontIndirectW(&mono);

        (font, font_bold, font_title, font_icon, font_mono)
    }
}

/// Overwrite a LOGFONTW's face name (fixed [u16; 32] field), NUL-padded.
fn set_face(lf: &mut LOGFONTW, name: &str) {
    lf.lfFaceName = [0u16; 32];
    for (i, ch) in name.encode_utf16().enumerate().take(31) {
        lf.lfFaceName[i] = ch;
    }
}

// ---- what no single surface owns -------------------------------------------

/// Repaint everything that shows state.
pub(crate) fn refresh_ui() {
    let a = app();
    let status = agent::status();
    a.shown_condition.set(Some(status.condition));
    tray::update(&status);
    if a.flyout_visible.get() {
        flyout::rebuild();
    }
    settings::refresh();
}

/// Start one action, or open the dialog that has to come before it.
///
/// The six that change something irreversibly or need administrator rights go
/// through [`modal`]; everything else is a verb the core already owns.
pub(crate) fn start_action(act: Action) {
    match act {
        Action::SignIn => agent::sign_in(),
        Action::ReinjectTicket => agent::renew_now(),
        Action::Cancel => agent::cancel_sign_in(),
        Action::DropKrbTicket => agent::drop_ticket(),
        Action::SignOutIdp => agent::sign_out_idp(),
        Action::OpenSettings => settings::open(),
        Action::CreateGrant
        | Action::GiveUpGrant
        | Action::Enroll
        | Action::Reenroll
        | Action::Unenroll
        | Action::RestartWorkstation => modal::open(act),
    }
    refresh_ui();
}

pub(crate) fn on_theme_changed() {
    let a = app();
    let old = a.theme.get();
    let new = Theme::current();
    a.theme.set(new);
    old.free();
    init_app_dark_mode(new.dark);
    allow_dark_for_window(a.owner, new.dark);

    // The tray icon is drawn in the taskbar's own ink, so it is now a function of
    // the theme and not only of the state. Nothing else would redraw it: the tick
    // repaints only when the condition or the displayed minute changes.
    tray::update(&agent::status());

    if a.flyout_visible.get() {
        flyout::rebuild();
    }
    settings::retheme(new.dark);
    modal::retheme(new.dark);
}

#[cfg(test)]
mod tests {
    use super::one_shot;

    fn parse(argv: &[&str]) -> Result<(Option<String>, String, String), String> {
        let owned: Vec<String> = argv.iter().map(|s| (*s).to_owned()).collect();
        one_shot(&owned).map(|(m, b, r)| (m.map(str::to_owned), b.to_owned(), r.to_owned()))
    }

    #[test]
    fn accepts_both_spellings_of_the_same_verb() {
        let positional = parse(&["--enroll", "https://b.example"]).unwrap();
        let flagged = parse(&["--broker", "https://b.example", "--enroll"]).unwrap();
        assert_eq!(positional, flagged);
        assert_eq!(
            positional,
            (Some("--enroll".into()), "https://b.example".into(), String::new())
        );
    }

    #[test]
    fn no_arguments_means_run_the_tray() {
        assert_eq!(parse(&[]).unwrap(), (None, String::new(), String::new()));
    }

    #[test]
    fn repair_takes_no_broker() {
        assert_eq!(
            parse(&["--repair"]).unwrap(),
            (Some("--repair".into()), String::new(), String::new())
        );
    }

    /// The child reports through a file the parent names, so the path has to
    /// survive alongside either spelling of the verb.
    #[test]
    fn the_result_path_is_carried_with_either_spelling() {
        let path = r"C:\Users\x\AppData\Local\Temp\kerbridge-elevated-42.txt";
        assert_eq!(parse(&["--repair", "--result", path]).unwrap().2, path);
        assert_eq!(
            parse(&["--enroll", "https://b.example", "--result", path]).unwrap(),
            (Some("--enroll".into()), "https://b.example".into(), path.into())
        );
    }

    /// The regression: an unknown flag must not fall through to starting a tray,
    /// which read as an enrollment that had happened.
    #[test]
    fn an_unrecognized_flag_is_refused() {
        assert!(parse(&["--enrol", "https://b.example"]).is_err());
        assert!(parse(&["--enroll", "https://b.example", "--wat"]).is_err());
    }
}
