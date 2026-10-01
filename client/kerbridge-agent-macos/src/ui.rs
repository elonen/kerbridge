//! AppKit plumbing with no better home: tick timer, getting onto the main
//! thread, alerts, Notification Center, opening a path, and the sheets.
//!
//! The core decides what to announce. This file applies macOS delivery gates and
//! owns AppKit and UserNotifications integration.

use std::cell::RefCell;
use std::sync::Mutex;

use objc2::rc::Retained;
use objc2::runtime::{NSObject, NSObjectProtocol};
use objc2::{ClassType, MainThreadMarker, MainThreadOnly, define_class, msg_send, sel};
use objc2_app_kit::{
    NSAlert, NSAlertStyle, NSApplication, NSButton, NSControlStateValueOff, NSControlStateValueOn,
    NSTextField, NSView, NSWorkspace,
};
use objc2_foundation::{
    NSPoint, NSRect, NSRunLoop, NSRunLoopCommonModes, NSSize, NSString, NSTimer, NSURL,
};

use kerbridge_client::agent::{self, Outcome, Severity};
use kerbridge_client::describe::{Action, Supply};
use kerbridge_client::log;
use kerbridge_client::present::action_label;
use kerbridge_client::strings::{duration, fill, tr};
use kerbridge_client::time;

// Shown verbatim in About, every locale -- the same two the Windows agent shows.
const COPYRIGHT: &str = "© 2026 Jarno Elonen";
const WEBSITE: &str = "https://kerbridge.org/";

/// Work queued for the main thread. A queue rather than a boxed closure per
/// call, because the wake-up selector below carries no argument -- the same shape
/// as the Windows agent's `PostMessageW`, which also carries nothing and reads
/// the state on arrival.
static MAIN_QUEUE: Mutex<Vec<Job>> = Mutex::new(Vec::new());
static NOTIFICATIONS: Mutex<AuthorizationCoordinator> = Mutex::new(AuthorizationCoordinator::new());

#[derive(Clone, Debug, PartialEq, Eq)]
struct Notice {
    title: String,
    body: String,
    severity: Severity,
}

impl Notice {
    fn new(title: &str, body: &str, severity: Severity) -> Self {
        Self { title: title.to_owned(), body: body.to_owned(), severity }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum AuthorizationState {
    Unasked,
    Requesting(Notice),
    Granted,
    Denied,
}

#[derive(Debug, PartialEq, Eq)]
struct AuthorizationCoordinator {
    state: AuthorizationState,
}

#[derive(Clone, Copy)]
struct NotificationEligibility {
    /// `None` until policy, user settings, or a broker snapshot resolves silence.
    /// `Some(true)` permits an interruption.
    configuration_allows: Option<bool>,
    menu_open: bool,
    bundled: bool,
}

impl NotificationEligibility {
    fn allows(self, severity: Severity) -> bool {
        self.configuration_allows == Some(true)
            && !self.menu_open
            && self.bundled
            && matches!(severity, Severity::Warning | Severity::Error)
    }

    fn allows_pending(self) -> bool {
        self.configuration_allows == Some(true) && !self.menu_open
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthorizationResult {
    Granted,
    Denied,
    Error,
}

#[derive(Debug, PartialEq, Eq)]
enum AuthorizationEffect {
    Request,
    Deliver(Notice),
}

impl AuthorizationCoordinator {
    const fn new() -> Self {
        Self { state: AuthorizationState::Unasked }
    }

    fn submit(
        &mut self,
        notice: Notice,
        eligibility: NotificationEligibility,
    ) -> Option<AuthorizationEffect> {
        if !eligibility.allows(notice.severity) {
            return None;
        }
        match &self.state {
            AuthorizationState::Unasked => {
                self.state = AuthorizationState::Requesting(notice);
                Some(AuthorizationEffect::Request)
            }
            AuthorizationState::Requesting(_) | AuthorizationState::Denied => None,
            AuthorizationState::Granted => Some(AuthorizationEffect::Deliver(notice)),
        }
    }

    fn complete(
        &mut self,
        result: AuthorizationResult,
        pending_eligible: bool,
    ) -> Option<AuthorizationEffect> {
        let state = std::mem::replace(&mut self.state, AuthorizationState::Denied);
        let AuthorizationState::Requesting(pending) = state else {
            self.state = state;
            return None;
        };
        match result {
            AuthorizationResult::Granted => {
                self.state = AuthorizationState::Granted;
                pending_eligible.then_some(AuthorizationEffect::Deliver(pending))
            }
            AuthorizationResult::Denied | AuthorizationResult::Error => None,
        }
    }
}

enum Job {
    /// Drain the core's event queue and repaint.
    Drain,
    /// Draw everything again, whatever was last shown.
    Redraw,
    /// Finish the UserNotifications callback on the UI thread.
    AuthorizationCompleted(AuthorizationResult),
    Alert {
        caption: String,
        body: String,
        ok: bool,
    },
}

thread_local! {
    static TICKER: RefCell<Option<Retained<NSTimer>>> = const { RefCell::new(None) };
    static TICK_FN: RefCell<Option<Box<dyn Fn()>>> = const { RefCell::new(None) };
}

define_class!(
    // SAFETY: NSObject has no subclassing requirements; no Drop, no ivars.
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "KerBridgeRunner"]
    struct Runner;

    impl Runner {
        /// The tick timer's target.
        #[unsafe(method(tick:))]
        fn tick(&self, _timer: &NSTimer) {
            TICK_FN.with(|f| {
                if let Some(f) = f.borrow().as_ref() {
                    f();
                }
            });
        }

        /// What `performSelectorOnMainThread:` lands on. Drains everything a
        /// worker queued, so several wake-ups collapsing into one is harmless.
        #[unsafe(method(runQueued:))]
        fn run_queued(&self, _arg: *mut NSObject) {
            let jobs = std::mem::take(&mut *MAIN_QUEUE.lock().unwrap());
            for job in jobs {
                match job {
                    Job::Drain => {
                        if agent::drain() {
                            crate::redraw();
                        }
                    }
                    Job::Redraw => crate::redraw(),
                    Job::AuthorizationCompleted(result) => complete_notification_authorization(result),
                    Job::Alert { caption, body, ok } => alert(&caption, &body, ok),
                }
            }
        }
    }

    unsafe impl NSObjectProtocol for Runner {}
);

impl Runner {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        unsafe { msg_send![Self::alloc(mtm), init] }
    }
}

/// Run `f` every `seconds` on the main run loop, forever.
///
/// **Common modes, not the default one.** This is the single heartbeat behind the
/// re-injection schedule, and menu tracking runs the run loop in
/// `NSEventTrackingRunLoopMode` -- so a timer left in the default mode stops
/// while the menu is open, which is exactly when someone is looking at a
/// countdown.
pub fn every(mtm: MainThreadMarker, seconds: f64, f: impl Fn() + 'static) {
    TICK_FN.with(|slot| *slot.borrow_mut() = Some(Box::new(f)));
    let runner = Runner::new(mtm);
    // SAFETY: `tick:` is the selector `Runner` above implements, and the target
    // is the object that implements it. The timer retains its target, and the
    // run loop retains the timer.
    let timer = unsafe {
        NSTimer::timerWithTimeInterval_target_selector_userInfo_repeats(
            seconds,
            &runner,
            sel!(tick:),
            None,
            true,
        )
    };
    unsafe { NSRunLoop::currentRunLoop().addTimer_forMode(&timer, NSRunLoopCommonModes) };
    TICKER.with(|slot| *slot.borrow_mut() = Some(timer));
}

/// Drain the core's events and repaint, on the main thread. Called from worker
/// threads; must not block and must not drain here.
pub fn wake() {
    queue(Job::Drain);
}

/// A modal box, on the main thread. Same reason as [`wake`]: AppKit belongs to
/// the main thread and the caller may be a worker.
pub fn alert_later(caption: &str, body: &str, ok: bool) {
    queue(Job::Alert { caption: caption.to_owned(), body: body.to_owned(), ok });
}

/// Redraw the menu bar, on the next pass of the run loop.
pub fn redraw_later() {
    next_pass(Job::Redraw);
}

fn queue(job: Job) {
    // A fresh Runner each time: it holds nothing, and the alternative is a
    // static that would have to be main-thread-only to construct.
    let Some(mtm) = MainThreadMarker::new() else {
        // Off the main thread, which is the ordinary case for a worker.
        return next_pass(job);
    };
    // Already on the main thread: run it now rather than round-tripping.
    MAIN_QUEUE.lock().unwrap().push(job);
    let runner = Runner::new(mtm);
    unsafe {
        let _: () = msg_send![&*runner, runQueued: std::ptr::null_mut::<NSObject>()];
    }
}

/// Queue for the *next* pass of the run loop, whichever thread asks.
///
/// A menu-delegate callback needs this, though it is on the main thread: its
/// menu is still on AppKit's stack, and to replace the status item's menu
/// inside the callback releases that menu under AppKit.
fn next_pass(job: Job) {
    MAIN_QUEUE.lock().unwrap().push(job);
    // `class()` registers the class on first use; `define_class!` alone does
    // not. A wake-up can arrive before the main thread builds its first `Runner`.
    unsafe {
        let obj: *mut NSObject = msg_send![Runner::class(), new];
        // Owned, so it is released once the message has been delivered; left
        // raw it would leak one object per wake-up. `performSelectorOnMainThread`
        // retains the receiver until then, so the drop below is not a race.
        let obj = Retained::from_raw(obj).expect("+new returns an object");
        let _: () = msg_send![
            &*obj,
            performSelectorOnMainThread: sel!(runQueued:),
            withObject: std::ptr::null_mut::<NSObject>(),
            waitUntilDone: false,
        ];
    }
}

/// A modal box the user has to dismiss.
pub fn alert(caption: &str, body: &str, ok: bool) {
    let Some(mtm) = MainThreadMarker::new() else {
        queue(Job::Alert { caption: caption.to_owned(), body: body.to_owned(), ok });
        return;
    };
    // An agent with no Dock icon puts its alert behind whatever is in front
    // unless it asks; the alert is an answer to something the user did, so it
    // has to be where they are looking.
    NSApplication::sharedApplication(mtm).activate();
    let alert = NSAlert::new(mtm);
    alert.setMessageText(&NSString::from_str(caption));
    alert.setInformativeText(&NSString::from_str(body));
    alert.setAlertStyle(if ok { NSAlertStyle::Informational } else { NSAlertStyle::Warning });
    alert.runModal();
}

/// Show a blocking main-thread confirmation. Off-thread calls cancel. Report
/// progress after it closes.
pub fn confirm(caption: &str, body: &str, commit: &str) -> bool {
    let Some(mtm) = MainThreadMarker::new() else {
        log::warn("a confirmation was asked for off the main thread; treating it as cancelled");
        return false;
    };
    NSApplication::sharedApplication(mtm).activate();
    let alert = NSAlert::new(mtm);
    alert.setMessageText(&NSString::from_str(caption));
    alert.setInformativeText(&NSString::from_str(body));
    alert.setAlertStyle(NSAlertStyle::Warning);
    // AppKit makes the first button default. Escape selects the second.
    alert.addButtonWithTitle(&NSString::from_str(commit));
    alert.addButtonWithTitle(&NSString::from_str(tr().btn_cancel));
    // `NSAlertFirstButtonReturn`.
    alert.runModal() == 1000
}

/// Submit one interruption to the process-local authorization coordinator.
/// Information stays in the log and menu; it neither prompts nor posts.
pub fn notify(title: &str, body: &str, severity: Severity) {
    let notice = Notice::new(title, body, severity);
    let effect = NOTIFICATIONS.lock().unwrap().submit(notice, notification_eligibility());
    apply_notification_effect(effect);
}

fn notification_eligibility() -> NotificationEligibility {
    NotificationEligibility {
        configuration_allows: agent::notification_authorization_eligible(),
        menu_open: crate::menu::is_open(),
        bundled: bundled(),
    }
}

fn apply_notification_effect(effect: Option<AuthorizationEffect>) {
    match effect {
        Some(AuthorizationEffect::Request) => request_notification_authorization(),
        Some(AuthorizationEffect::Deliver(notice)) => deliver_notification(notice),
        None => {}
    }
}

/// Ask only in response to the first eligible interruption. Existing OS state
/// comes back through the same callback as a new decision.
fn request_notification_authorization() {
    use objc2_user_notifications::{UNAuthorizationOptions, UNUserNotificationCenter};

    let center = UNUserNotificationCenter::currentNotificationCenter();
    let options = UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound;
    let handler = block2::StackBlock::new(
        |granted: objc2::runtime::Bool, error: *mut objc2_foundation::NSError| {
            let result = if !error.is_null() {
                AuthorizationResult::Error
            } else if granted.as_bool() {
                AuthorizationResult::Granted
            } else {
                AuthorizationResult::Denied
            };
            next_pass(Job::AuthorizationCompleted(result));
        },
    );
    center.requestAuthorizationWithOptions_completionHandler(options, &handler);
}

/// Apply the callback on the UI thread. Configuration or menu visibility can
/// change while the system prompt is open, so the pending notice is checked
/// again before delivery.
fn complete_notification_authorization(result: AuthorizationResult) {
    match result {
        AuthorizationResult::Granted => {}
        AuthorizationResult::Denied => {
            log::info("notifications were declined; the menu bar still shows the state");
        }
        AuthorizationResult::Error => {
            log::warn("notification authorization failed; the menu bar still shows the state");
        }
    }
    let pending_eligible = notification_eligibility().allows_pending();
    let effect = NOTIFICATIONS.lock().unwrap().complete(result, pending_eligible);
    apply_notification_effect(effect);
}

/// Create Objective-C notification objects only when delivery is permitted.
fn deliver_notification(notice: Notice) {
    use objc2_user_notifications::{
        UNMutableNotificationContent, UNNotificationInterruptionLevel, UNNotificationRequest,
        UNUserNotificationCenter,
    };

    let interruption = match notice.severity {
        Severity::Info => return,
        Severity::Warning | Severity::Error => UNNotificationInterruptionLevel::Active,
    };
    let content = UNMutableNotificationContent::new();
    content.setTitle(&NSString::from_str(&notice.title));
    content.setBody(&NSString::from_str(&notice.body));
    content.setInterruptionLevel(interruption);
    // A stable identifier would replace the previous notification; a fresh one
    // each time keeps a sequence readable.
    let id = NSString::from_str(&format!("kerbridge-{}", time::now()));
    let request = UNNotificationRequest::requestWithIdentifier_content_trigger(&id, &content, None);
    let center = UNUserNotificationCenter::currentNotificationCenter();
    center.addNotificationRequest_withCompletionHandler(&request, None);
}

/// Show this result as an alert because it answers user input.
///
/// On macOS, only grant actions reach this callback.
pub fn finished(action: Action, outcome: Outcome) {
    let (body, ok) = match outcome {
        // A decision rather than a fault: it returns in silence.
        Outcome::Declined => return,
        Outcome::Done { message, detail } => {
            (detail.map_or(message.clone(), |d| format!("{message}\n\n{d}")), true)
        }
        Outcome::Failed { message } => (message, false),
    };
    alert_later(&action_label(action, &agent::status()), &body, ok);
}

/// True when this process is running from an `.app`, which several AppKit
/// facilities require and which a `cargo run` build is not.
fn bundled() -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.ends_with("MacOS")))
        .unwrap_or(false)
}

/// Hand a file or folder to the Finder.
pub fn open_path(path: &str) {
    let url = NSURL::fileURLWithPath(&NSString::from_str(path));
    NSWorkspace::sharedWorkspace().openURL(&url);
}

/// Open an address in the user's browser.
pub fn open_url(url: &str) {
    let Some(url) = NSURL::URLWithString(&NSString::from_str(url)) else {
        log::warn(&format!("not a URL: {url}"));
        return;
    };
    NSWorkspace::sharedWorkspace().openURL(&url);
}

/// Show Settings in a delayed-commit `NSAlert`.
///
/// Three settings fit in its accessory view, avoiding another surface to keep
/// in sync. Unlike the Windows Settings window, this sheet commits on OK.
pub fn settings_sheet() {
    let Some(mtm) = MainThreadMarker::new() else {
        return;
    };
    let view = agent::settings_view();
    let s = tr();

    // Bottom-left origin, so the field sits above the checkboxes.
    let accessory = NSView::initWithFrame(
        NSView::alloc(mtm),
        NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(320.0, 76.0)),
    );
    let field = NSTextField::initWithFrame(
        NSTextField::alloc(mtm),
        NSRect::new(NSPoint::new(0.0, 52.0), NSSize::new(320.0, 24.0)),
    );
    field.setStringValue(&NSString::from_str(&view.broker_url));
    // Policy wins over anything typed here, and saying so beats letting someone
    // type into a field whose value is discarded.
    field.setEditable(!view.broker_locked);
    accessory.addSubview(&field);

    // SAFETY: no target and no action, so there is no selector to get wrong --
    // the state is read below rather than acted on as it changes.
    let autostart = unsafe {
        NSButton::checkboxWithTitle_target_action(
            &NSString::from_str(s.settings_startup_label),
            None,
            None,
            mtm,
        )
    };
    autostart.setFrame(NSRect::new(NSPoint::new(0.0, 28.0), NSSize::new(320.0, 20.0)));
    autostart.setState(if view.autostart { NSControlStateValueOn } else { NSControlStateValueOff });
    autostart.setToolTip(Some(&NSString::from_str(if view.autostart_locked {
        s.settings_broker_managed
    } else {
        s.settings_startup_sub
    })));
    autostart.setEnabled(!view.autostart_locked);
    accessory.addSubview(&autostart);

    let silent = unsafe {
        NSButton::checkboxWithTitle_target_action(
            &NSString::from_str(s.settings_silent_label),
            None,
            None,
            mtm,
        )
    };
    silent.setFrame(NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(320.0, 20.0)));
    silent.setState(if view.silent { NSControlStateValueOn } else { NSControlStateValueOff });
    silent.setToolTip(Some(&NSString::from_str(if view.silent_locked {
        s.settings_broker_managed
    } else {
        s.settings_silent_sub
    })));
    silent.setEnabled(!view.silent_locked);
    accessory.addSubview(&silent);

    NSApplication::sharedApplication(mtm).activate();
    let alert = NSAlert::new(mtm);
    alert.setMessageText(&NSString::from_str(s.settings_broker_label));
    alert.setInformativeText(&NSString::from_str(if view.broker_locked {
        s.settings_broker_managed
    } else {
        s.settings_broker_sub
    }));
    alert.setAccessoryView(Some(&accessory));
    alert.addButtonWithTitle(&NSString::from_str(s.settings_ok));
    alert.addButtonWithTitle(&NSString::from_str(s.settings_cancel));

    // NSAlertFirstButtonReturn.
    if alert.runModal() != 1000 {
        return;
    }
    let broker = field.stringValue().to_string();
    let autostart_on = autostart.state() == NSControlStateValueOn;
    let silent_on = silent.state() == NSControlStateValueOn;
    agent::apply_settings(agent::SettingsChange {
        broker_url: (broker != view.broker_url).then_some(broker.as_str()),
        autostart: (autostart_on != view.autostart).then_some(autostart_on),
        silent: (silent_on != view.silent).then_some(silent_on),
        ..agent::SettingsChange::default()
    });
}

/// The Kerberos details, read-only. Behind a menu item rather than in the menu --
/// see [`crate::menu`] -- and in the row order the Windows drawer uses.
pub fn details_sheet() {
    let s = tr();
    let st = agent::status();
    let mut lines = Vec::new();
    if let Some(t) = &st.ticket {
        lines.push(format!("{}: {}", s.meter_label, duration(t.remaining)));
    }
    // Constant per machine, and it names the subject every other row is about.
    lines.push(format!("{}: {}", s.d_realm, st.realm));
    if !st.source.is_empty() {
        lines.push(format!("{}: {}", s.d_source, st.source));
    }
    if let Some(t) = &st.ticket {
        let value = if t.renewable { s.d_ticket_value } else { s.d_ticket_value_norenew };
        lines.push(format!(
            "{}: {}",
            s.d_ticket,
            fill(value, &[("time", &time::local_time_string(t.end))])
        ));
    }
    lines.push(format!(
        "{}: {}",
        s.d_supply,
        match st.supply {
            Supply::Grant => s.d_supply_grant,
            Supply::WindowsSignIn => s.d_supply_wam,
            Supply::BrowserSignIn => s.d_supply_browser,
            Supply::None => s.d_supply_none,
        }
    ));
    if let Some(next) = st.next_attempt_at_earliest {
        lines.push(format!("{}: {}", s.d_next, time::local_time_string(next)));
    }
    alert(s.details_heading, &lines.join("\n"), true);
}

/// The About box: what this is, whose it is, where it lives, and the license it
/// is under.
///
/// The address is an accessory text field rather than a line of the body,
/// because an alert's own text cannot be selected and an address nobody can copy
/// is decoration.
pub fn about() {
    let Some(mtm) = MainThreadMarker::new() else {
        return;
    };
    let s = tr();

    NSApplication::sharedApplication(mtm).activate();
    let alert = NSAlert::new(mtm);
    alert.setMessageText(&NSString::from_str(&format!(
        "{} {} · {}",
        s.app_name,
        env!("CARGO_PKG_VERSION"),
        s.tagline
    )));
    alert.setInformativeText(&NSString::from_str(&format!("{COPYRIGHT}\n\n{}", s.about_license)));
    let address = NSTextField::labelWithString(&NSString::from_str(WEBSITE), mtm);
    address.setSelectable(true);
    address.setFrame(NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(320.0, 20.0)));
    alert.setAccessoryView(Some(&address));
    alert.addButtonWithTitle(&NSString::from_str(s.settings_ok));
    alert.runModal();
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;

    fn notice(title: &str, severity: Severity) -> Notice {
        Notice::new(title, "body", severity)
    }

    fn eligible() -> NotificationEligibility {
        NotificationEligibility {
            configuration_allows: Some(true),
            menu_open: false,
            bundled: true,
        }
    }

    #[test]
    fn coordinator_starts_unasked_without_an_effect() {
        assert_eq!(AuthorizationCoordinator::new().state, AuthorizationState::Unasked);
    }

    #[test]
    fn first_eligible_notice_requests_authorization_and_becomes_pending() {
        let mut coordinator = AuthorizationCoordinator::new();
        let first = notice("first", Severity::Warning);

        assert_eq!(
            coordinator.submit(first.clone(), eligible()),
            Some(AuthorizationEffect::Request)
        );
        assert_eq!(coordinator.state, AuthorizationState::Requesting(first));
    }

    #[test]
    fn concurrent_submissions_make_one_request_and_keep_one_notice() {
        let coordinator = Arc::new(Mutex::new(AuthorizationCoordinator::new()));
        let barrier = Arc::new(Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let coordinator = Arc::clone(&coordinator);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    coordinator
                        .lock()
                        .unwrap()
                        .submit(notice(&format!("notice {i}"), Severity::Error), eligible())
                })
            })
            .collect();
        let effects: Vec<_> =
            threads.into_iter().map(|thread| thread.join().expect("submission thread")).collect();

        assert_eq!(
            effects
                .iter()
                .filter(|effect| matches!(effect, Some(AuthorizationEffect::Request)))
                .count(),
            1
        );
        let mut coordinator = coordinator.lock().unwrap();
        assert!(matches!(&coordinator.state, AuthorizationState::Requesting(_)));
        assert!(matches!(
            coordinator.complete(AuthorizationResult::Granted, true),
            Some(AuthorizationEffect::Deliver(_))
        ));
    }

    #[test]
    fn grant_delivers_the_pending_notice_and_later_notices_without_a_request() {
        let mut coordinator = AuthorizationCoordinator::new();
        let first = notice("first", Severity::Warning);
        let dropped = notice("dropped", Severity::Error);
        let later = notice("later", Severity::Error);

        assert_eq!(
            coordinator.submit(first.clone(), eligible()),
            Some(AuthorizationEffect::Request)
        );
        assert_eq!(coordinator.submit(dropped, eligible()), None);
        assert_eq!(
            coordinator.complete(AuthorizationResult::Granted, true),
            Some(AuthorizationEffect::Deliver(first))
        );
        assert_eq!(coordinator.state, AuthorizationState::Granted);
        assert_eq!(
            coordinator.submit(later.clone(), eligible()),
            Some(AuthorizationEffect::Deliver(later))
        );
    }

    #[test]
    fn denial_and_error_are_terminal() {
        for result in [AuthorizationResult::Denied, AuthorizationResult::Error] {
            let mut coordinator = AuthorizationCoordinator::new();
            assert_eq!(
                coordinator.submit(notice("first", Severity::Warning), eligible()),
                Some(AuthorizationEffect::Request)
            );
            assert_eq!(coordinator.complete(result, true), None);
            assert_eq!(coordinator.state, AuthorizationState::Denied);
            assert_eq!(coordinator.submit(notice("later", Severity::Error), eligible()), None);
        }
    }

    #[test]
    fn ineligible_notices_leave_authorization_unasked() {
        let cases = [
            (
                NotificationEligibility { configuration_allows: None, ..eligible() },
                Severity::Warning,
            ),
            (
                NotificationEligibility { configuration_allows: Some(false), ..eligible() },
                Severity::Warning,
            ),
            (NotificationEligibility { menu_open: true, ..eligible() }, Severity::Warning),
            (NotificationEligibility { bundled: false, ..eligible() }, Severity::Error),
            (eligible(), Severity::Info),
        ];

        for (eligibility, severity) in cases {
            let mut coordinator = AuthorizationCoordinator::new();
            assert_eq!(coordinator.submit(notice("ignored", severity), eligibility), None);
            assert_eq!(coordinator.state, AuthorizationState::Unasked);
        }
    }

    #[test]
    fn turning_silent_off_without_a_notice_is_inert() {
        let mut coordinator = AuthorizationCoordinator::new();
        let mut current =
            NotificationEligibility { configuration_allows: Some(false), ..eligible() };
        assert_eq!(coordinator.submit(notice("silent", Severity::Warning), current), None);

        current.configuration_allows = Some(true);
        assert!(current.allows(Severity::Warning));
        assert_eq!(coordinator.state, AuthorizationState::Unasked);
    }

    #[test]
    fn grant_rechecks_silence_and_menu_before_releasing_pending() {
        let changed = [
            NotificationEligibility { configuration_allows: None, ..eligible() },
            NotificationEligibility { configuration_allows: Some(false), ..eligible() },
            NotificationEligibility { menu_open: true, ..eligible() },
        ];

        for eligibility in changed {
            let mut coordinator = AuthorizationCoordinator::new();
            assert_eq!(
                coordinator.submit(notice("pending", Severity::Warning), eligible()),
                Some(AuthorizationEffect::Request)
            );
            let pending_eligible = eligibility.allows_pending();
            assert_eq!(coordinator.complete(AuthorizationResult::Granted, pending_eligible), None);
            assert_eq!(coordinator.state, AuthorizationState::Granted);
        }
    }
}
