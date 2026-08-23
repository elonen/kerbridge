//! macOS menu-bar agent. Uses `kerbridge_client::agent`.
//!
//! **Division of responsibility**: The core library makes decisions. This crate
//! draws the UI.
//!
//! **Status display**: The menu shows status. macOS menu-bar items can display
//! state in disabled menu items.
//!
//! **Threading model**: Same as Windows agent. Sign-in is slow (browser + two
//! network calls). It runs on a worker thread. The worker thread queues events
//! and wakes the UI thread.
//!
//! **Modules**:
//! - [`menu`]: converts `Status` to menu items
//! - [`icon`]: draws the logo
//! - [`ui`]: AppKit integration code
//!
//! **Unsupported features**: Not currently available on macOS:
//!
//! 1. Enrollment: Heimdal resolves the realm from DNS.
//! 2. NTLM-fallback repair: The mount recovers automatically.
//! 3. Device grant: Requires Secure Enclave key. Needs entitlement and
//!    signing identity.
//!
//! The core library excludes these features from the model. See
//! `kerbridge_client::describe::Facts`.

use std::cell::RefCell;

use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2::{MainThreadMarker, msg_send};
use objc2_app_kit::{
    NSApplication, NSApplicationActivationPolicy, NSStatusBar, NSStatusItem,
    NSVariableStatusItemLength,
};
use objc2_foundation::NSString;

use kerbridge_client::agent::{self, NativeToken, Outcome, Raise, Severity, Status};
use kerbridge_client::describe::{Action, Blocker, Condition};
use kerbridge_client::discovery::OidcConfig;
use kerbridge_client::log;
use kerbridge_client::present::headline;
use kerbridge_client::strings::tr;

mod icon;
mod menu;
mod ui;

/// How often the core's clock-driven work runs. One second, like the Windows
/// agent's timer: the status text counts down in minutes, and everything with a
/// deadline is checked against the clock rather than scheduled precisely.
const TICK_SECONDS: f64 = 1.0;

thread_local! {
    /// The menu-bar item, which only the main thread ever touches.
    static STATUS_ITEM: RefCell<Option<Retained<NSStatusItem>>> = const { RefCell::new(None) };
    /// What was last drawn, so a tick that changes nothing repaints nothing.
    static SHOWN: RefCell<Option<Shown>> = const { RefCell::new(None) };
}

/// The three things the menu bar shows, each repainted only when it moves.
struct Shown {
    condition: Condition,
    tooltip: String,
    plan: menu::Plan,
}

fn main() {
    log::info(&format!("kerbridge-agent {} starting", env!("CARGO_PKG_VERSION")));

    let mtm = MainThreadMarker::new().expect("main() runs on the main thread");
    let app = NSApplication::sharedApplication(mtm);
    // Accessory, not Regular: no Dock icon and no menu bar of its own. This is
    // what makes it a background agent rather than an application someone has to
    // keep out of their way.
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);

    agent::init(Box::leak(Box::new(MacHost)));

    let item = NSStatusBar::systemStatusBar().statusItemWithLength(NSVariableStatusItemLength);
    if let Some(button) = item.button(mtm) {
        button.setImage(Some(&icon::template()));
        button.setToolTip(Some(&NSString::from_str(tr().app_name)));
    }
    STATUS_ITEM.with(|s| *s.borrow_mut() = Some(item));

    ui::request_notification_permission();
    refresh();

    // A machine with nothing configured has something to be told, and the menu is
    // the only affordance that says what. Anything else starts quietly, which is
    // what an agent launched at login should do -- including signing in, on the
    // same terms as Windows: it may use a credential already held, and it may not
    // open a window.
    if agent::status().blockers.contains(&Blocker::NoBrokerUrl) {
        // Not here: there is no run loop yet to track a menu in.
        ui::show_status_later();
    } else {
        agent::autostart_sign_in();
    }

    ui::every(mtm, TICK_SECONDS, || {
        agent::tick();
        refresh();
    });

    app.run();
}

/// Redraw the menu bar from the core's current [`Status`].
///
/// Called after every event the core applies and on every tick. Cheap when
/// nothing moved: building a plan is a handful of strings, and each of the three
/// things on screen is replaced only when its own part of that plan changes.
fn refresh() {
    let mtm = MainThreadMarker::new().expect("refresh runs on the main thread");
    let status = agent::status();
    let shown =
        Shown { condition: status.condition, tooltip: tooltip(&status), plan: menu::plan(&status) };

    STATUS_ITEM.with(|item| {
        let item = item.borrow();
        let Some(item) = item.as_ref() else { return };
        SHOWN.with(|s| {
            let mut s = s.borrow_mut();
            let was = s.as_ref();
            if let Some(button) = item.button(mtm) {
                if was.is_none_or(|w| w.condition != shown.condition) {
                    button.setImage(Some(&icon::state_image(shown.condition)));
                }
                if was.is_none_or(|w| w.tooltip != shown.tooltip) {
                    button.setToolTip(Some(&NSString::from_str(&shown.tooltip)));
                }
            }
            // Never while it is being tracked: replacing an open menu releases
            // it under AppKit. What was missed is redrawn when it closes.
            if was.is_none_or(|w| w.plan != shown.plan) && !menu::is_open() {
                item.setMenu(Some(&menu::build(mtm, &shown.plan)));
            }
            *s = Some(shown);
        });
    });
}

/// Draw everything again, whatever was last shown. What a closing menu needs,
/// since [`refresh`] deliberately drew nothing into it while it was open.
pub fn redraw() {
    SHOWN.with(|s| *s.borrow_mut() = None);
    refresh();
}

/// The hover text: the app, and what it would say if you opened it.
fn tooltip(status: &Status) -> String {
    match headline(status) {
        Some(headline) => format!("{} — {headline}", tr().app_name),
        None => tr().app_name.to_owned(),
    }
}

// ---- the UI half of the core ------------------------------------------------

/// The eight things [`agent::Host`] needs from a platform. Everything else the
/// agent does is the core's.
struct MacHost;

impl agent::Host for MacHost {
    /// Called from worker threads. `performSelectorOnMainThread:` is the whole
    /// mechanism -- it queues onto the main run loop and returns, which is exactly
    /// the contract (must not block, must not drain here).
    fn wake(&self) {
        ui::wake();
    }

    /// Gate 2: an outcome is announced by whatever surface is on screen, and a
    /// notification is what happens when none is. The core has already logged
    /// this, so silence here costs the record nothing.
    fn notify(&self, title: &str, body: &str, severity: Severity) {
        if menu::is_open() {
            return;
        }
        ui::notify(title, body, severity);
    }

    fn finished(&self, action: Action, outcome: Outcome) {
        ui::finished(action, outcome);
    }

    /// Nothing on this platform elevates -- there is no `ksetup` counterpart and
    /// no service to restart -- so there is no waiting-for-permission phase to
    /// leave. `macos/elevate.rs` is the arm that says so.
    fn elevating(&self, _action: Action) {}

    fn primary_action_label(&self) -> String {
        menu::plan(&agent::status()).primary_label()
    }

    /// One surface answers both targets, and only one of them is reachable: the
    /// NTLM-fallback episode that raises `Repair` is switched off on macOS.
    fn raise(&self, _target: Raise) {
        ui::show_status_later();
    }

    fn open_path(&self, path: &str) {
        ui::open_path(path);
    }

    /// No native token source yet.
    ///
    /// The Windows arm asks WAM, which can issue a broker token from the sign-in
    /// the machine already holds. The Mac counterpart is the Company Portal SSO
    /// extension, which is a deployment dependency and a spike of its own; until
    /// that is measured, saying so and letting the browser handle it is the
    /// honest answer. `Unavailable` is what the core already does the right thing
    /// with -- it falls back -- and it is not an error.
    fn native_token(&self, _oidc: &OidcConfig) -> NativeToken {
        NativeToken::Unavailable
    }
}

/// Drop the menu open, as if the menu-bar item had been clicked.
pub fn show_status() {
    let mtm = MainThreadMarker::new().expect("show_status runs on the main thread");
    STATUS_ITEM.with(|item| {
        if let Some(item) = item.borrow().as_ref()
            && let Some(button) = item.button(mtm)
        {
            unsafe {
                let _: () = msg_send![&*button, performClick: std::ptr::null::<AnyObject>()];
            }
        }
    });
}

/// Menu commands, dispatched from [`menu`] by tag.
pub fn perform(command: menu::Command) {
    use menu::Command::*;
    match command {
        Offer(i) => {
            if let Some(act) = SHOWN.with(|s| s.borrow().as_ref().and_then(|s| s.plan.action(i))) {
                start_action(act);
            }
        }
        Details => ui::details_sheet(),
        Log => agent::open_log_folder(),
        Settings => ui::settings_sheet(),
        Help => {
            let published = agent::status().help_url;
            ui::open_url(&kerbridge_client::help_url_for(
                if published.is_empty() { kerbridge_client::HELP_URL } else { &published },
                "mac",
            ));
        }
        About => ui::about(),
        Quit => {
            log::info("quitting at the user's request");
            let mtm = MainThreadMarker::new().expect("a menu command runs on the main thread");
            NSApplication::sharedApplication(mtm).terminate(None);
        }
    }
    refresh();
}

/// Start one action. Every one of these is a verb the core already owns: nothing
/// here needs a confirmation, because the six operations that do are the ones
/// this platform has no arm for.
fn start_action(act: Action) {
    match act {
        Action::SignIn => agent::sign_in(),
        Action::ReinjectTicket => agent::renew_now(),
        Action::Cancel => agent::cancel_sign_in(),
        Action::DropKrbTicket => agent::drop_ticket(),
        Action::SignOutIdp => agent::sign_out_idp(),
        Action::OpenSettings => ui::settings_sheet(),
        Action::CreateGrant
        | Action::GiveUpGrant
        | Action::Enroll
        | Action::Reenroll
        | Action::Unenroll
        | Action::RestartWorkstation => {
            log::warn(&format!("{act:?} has no macOS arm; nothing to start"));
        }
    }
}
