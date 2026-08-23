//! AppKit plumbing with no better home: tick timer, getting onto the main
//! thread, alerts, Notification Center, opening a path, and the sheets.
//!
//! Nothing here decides anything. Every function is a verb the core asked for
//! through [`kerbridge_client::agent::Host`], or the loop that drives it.

use std::cell::RefCell;
use std::sync::Mutex;

use objc2::rc::Retained;
use objc2::runtime::{NSObject, NSObjectProtocol};
use objc2::{MainThreadMarker, MainThreadOnly, define_class, msg_send, sel};
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

enum Job {
    /// Drain the core's event queue and repaint.
    Drain,
    /// Draw everything again, whatever was last shown.
    Redraw,
    /// Show the status menu.
    ShowStatus,
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
                    Job::ShowStatus => crate::show_status(),
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

/// Open the status menu, on the next pass of the run loop.
pub fn show_status_later() {
    next_pass(Job::ShowStatus);
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
/// Two callers need that even though they are already on the main thread. A
/// menu-delegate callback is one: the menu it is telling us about is still on
/// AppKit's stack, and replacing the status item's menu from inside the callback
/// would release it under them. Opening the menu before `NSApplication::run` is
/// the other -- there is no run loop yet to track it in.
fn next_pass(job: Job) {
    MAIN_QUEUE.lock().unwrap().push(job);
    unsafe {
        let cls = objc2::runtime::AnyClass::get(c"KerBridgeRunner")
            .expect("KerBridgeRunner is defined by define_class! above");
        let obj: *mut NSObject = msg_send![cls, new];
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

/// Ask for permission to post notifications, once, at startup.
///
/// Only a bundled application can: `UNUserNotificationCenter.current` throws for
/// a bare executable, which is why the Makefile builds an `.app` and ad-hoc
/// signs it. A refusal is not an error -- the state is always in the menu bar,
/// and a notification is the extra.
pub fn request_notification_permission() {
    use objc2_user_notifications::{UNAuthorizationOptions, UNUserNotificationCenter};

    if !bundled() {
        log::warn("not running from an .app bundle; notifications are unavailable");
        return;
    }
    let center = UNUserNotificationCenter::currentNotificationCenter();
    let options = UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound;
    let handler = block2::StackBlock::new(
        |granted: objc2::runtime::Bool, _err: *mut objc2_foundation::NSError| {
            if !granted.as_bool() {
                log::info("notifications were declined; the menu bar still shows the state");
            }
        },
    );
    center.requestAuthorizationWithOptions_completionHandler(options, &handler);
}

/// A passive notification.
///
/// Severity is an **interruption level** here rather than an icon: a banner has
/// no icon slot of ours to carry it, and the level is what decides whether this
/// may light a dark screen. Nothing the agent says is time-sensitive in the sense
/// the system means -- that level needs an entitlement, and it is for things that
/// cannot wait for the user to look -- so the loud end is `Active` and the quiet
/// end is `Passive`.
/// No `MainThreadMarker`, unlike every other entry point here. UserNotifications
/// is not AppKit: `UNUserNotificationCenter` is thread-safe and this touches
/// nothing else. The marker its neighbors take is for `NSAlert` and for window
/// and sheet work, which AppKit does confine to the main thread.
pub fn notify(title: &str, body: &str, severity: Severity) {
    use objc2_user_notifications::{
        UNMutableNotificationContent, UNNotificationInterruptionLevel, UNNotificationRequest,
        UNUserNotificationCenter,
    };

    if !bundled() {
        return;
    }
    let content = UNMutableNotificationContent::new();
    content.setTitle(&NSString::from_str(title));
    content.setBody(&NSString::from_str(body));
    content.setInterruptionLevel(match severity {
        Severity::Info => UNNotificationInterruptionLevel::Passive,
        Severity::Warning | Severity::Error => UNNotificationInterruptionLevel::Active,
    });
    // A stable identifier would replace the previous notification; a fresh one
    // each time keeps a sequence readable.
    let id = NSString::from_str(&format!("kerbridge-{}", time::now()));
    let request = UNNotificationRequest::requestWithIdentifier_content_trigger(&id, &content, None);
    let center = UNUserNotificationCenter::currentNotificationCenter();
    center.addNotificationRequest_withCompletionHandler(&request, None);
}

/// One of the core's hosted operations finished.
///
/// Unreachable as this platform stands: all six need an arm macOS does not have
/// (`macos/elevate.rs`, `macos/repair.rs`, `macos/device.rs`), and nothing here
/// derives an action that starts one. An alert rather than a notification, so
/// that if one ever does arrive it lands in front of the person who asked for it
/// instead of in a corner they have to notice.
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

/// The Settings sheet: the broker URL and whether to start at login.
///
/// An alert with an accessory view rather than a window of its own. There are two
/// settings; a window would be mostly empty, and this way there is no second
/// surface to keep in sync with the core. An `NSAlert` is delayed-commit by
/// construction, which is why this has OK and Cancel where the Windows Settings
/// window is instant-apply.
pub fn settings_sheet() {
    let Some(mtm) = MainThreadMarker::new() else {
        return;
    };
    let view = agent::settings_view();
    let s = tr();

    // Bottom-left origin, so the field sits above the checkbox.
    let accessory = NSView::initWithFrame(
        NSView::alloc(mtm),
        NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(320.0, 52.0)),
    );
    let field = NSTextField::initWithFrame(
        NSTextField::alloc(mtm),
        NSRect::new(NSPoint::new(0.0, 28.0), NSSize::new(320.0, 24.0)),
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
    autostart.setFrame(NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(320.0, 20.0)));
    autostart.setState(if view.autostart { NSControlStateValueOn } else { NSControlStateValueOff });
    autostart.setToolTip(Some(&NSString::from_str(s.settings_startup_sub)));
    accessory.addSubview(&autostart);

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
    agent::apply_settings(
        Some(&field.stringValue().to_string()),
        autostart.state() == NSControlStateValueOn,
        view.windows_sign_in,
        // Both handed straight back: neither has a control on this sheet, and a
        // Windows sign-in this platform never had is not something a Mac may
        // clear. The pin is machine policy or nothing here.
        &view.grant_for,
    );
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
