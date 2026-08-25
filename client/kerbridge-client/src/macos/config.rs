//! State in `~/Library/Application Support`, policy as a *forced* managed
//! preference, autostart as an `SMAppService` login item.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use core_foundation_sys::base::CFTypeRef;
use core_foundation_sys::number::{CFBooleanGetValue, CFBooleanRef, CFNumberRef};
use core_foundation_sys::preferences::{CFPreferencesAppValueIsForced, CFPreferencesCopyAppValue};
use core_foundation_sys::string::CFStringRef;
use objc2::msg_send;
use objc2::rc::Retained;
use objc2::runtime::{AnyClass, AnyObject, Bool};

use crate::cf::{self, Owned};

/// The bundle identifier, which on macOS is the name of everything: the
/// managed-preferences domain read below, the login-item registration, and
/// the app's own identity to the system. `org.` because `kerbridge.org` is
/// the registered domain and reverse-DNS reverses the TLD too.
pub const BUNDLE_ID: &str = "org.kerbridge.agent";

pub fn app_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join("Library/Application Support").join(super::APP_DIR))
}

/// A *forced* managed preference, and nothing else.
///
/// `CFPreferencesCopyAppValue` would also return the user's own value for the
/// same key, which would quietly promote a `defaults write` into policy and
/// lock the Settings field against the person who set it. The forced check is
/// what restricts this to what an MDM profile put in
/// `/Library/Managed Preferences/`.
fn forced(name: &str) -> Option<Owned> {
    let key = cf::string(name)?;
    let app = cf::string(BUNDLE_ID)?;
    let (key, app): (CFStringRef, CFStringRef) = (key.as_ref(), app.as_ref());
    // Both pointers stay alive for the two calls below: `key` and `app` own
    // them until the end of this function.
    if unsafe { CFPreferencesAppValueIsForced(key, app) } == 0 {
        return None;
    }
    Owned::adopt(unsafe { CFPreferencesCopyAppValue(key, app) })
}

pub fn policy_string(name: &str) -> Option<String> {
    // SAFETY: `forced` returns a live CoreFoundation object.
    unsafe { cf::to_string(forced(name)?.as_ref()) }
}

/// A boolean managed preference. `<true/>` is the natural spelling in a
/// profile; a number is accepted too, because a profile written by hand
/// often carries `<integer>0</integer>`.
pub fn policy_bool(name: &str) -> Option<bool> {
    let value = forced(name)?;
    let raw: CFTypeRef = value.as_ref();
    unsafe {
        if type_id(raw) == core_foundation_sys::number::CFBooleanGetTypeID() {
            return Some(CFBooleanGetValue(raw as CFBooleanRef));
        }
        if type_id(raw) == core_foundation_sys::number::CFNumberGetTypeID() {
            let mut n: i64 = 0;
            let ok = core_foundation_sys::number::CFNumberGetValue(
                raw as CFNumberRef,
                core_foundation_sys::number::kCFNumberSInt64Type,
                (&mut n as *mut i64).cast(),
            );
            return ok.then_some(n != 0);
        }
    }
    None
}

unsafe fn type_id(r: CFTypeRef) -> core_foundation_sys::base::CFTypeID {
    unsafe { core_foundation_sys::base::CFGetTypeID(r) }
}

// Autostart is `SMAppService`: the app registering *itself* as a login item.
//
// A `RunAtLoad` plist in `~/Library/LaunchAgents` also starts the agent, and
// is what this did first. What it does not do is say whose it is -- macOS
// records a plist there as a bare launchd job, so System Settings > Login
// Items lists it by the executable's file name under a generic icon.
// Registering the app puts the bundle's name and icon there instead, and login
// then starts the *app*, so LSUIElement and the rest of Info.plist are in
// force from the first frame rather than from the first line of main().
//
// Only a bundled build can do this: a bare `cargo run` has no app to register
// and every call below fails. That is the honest answer; a second mechanism
// for the development loop would be a second thing to keep working.
//
// macOS 13 and later, which is what LSMinimumSystemVersion says.
#[link(name = "ServiceManagement", kind = "framework")]
unsafe extern "C" {}

/// `SMAppServiceStatusEnabled`. The other three -- not registered, waiting for
/// the user to allow it in System Settings, and a registration whose app has
/// gone -- all mean the agent will not be started at login.
const ENABLED: isize = 1;

fn app_service() -> Option<Retained<AnyObject>> {
    let class = AnyClass::get(c"SMAppService")?;
    // SAFETY: `mainAppService` is a class property returning an SMAppService
    // for the running app, autoreleased.
    Some(unsafe { msg_send![class, mainAppService] })
}

pub fn autostart_enabled() -> bool {
    let Some(service) = app_service() else {
        return false;
    };
    // SAFETY: `status` is an SMAppService property returning SMAppServiceStatus.
    let status: isize = unsafe { msg_send![&service, status] };
    status == ENABLED
}

/// Never: `SMAppService` registers this app for this user alone, so there is no
/// machine-wide login item the checkbox would be unable to countermand.
pub fn autostart_machine_wide() -> bool {
    false
}

/// Register, or unregister, this app as a login item.
///
/// Takes effect at the next login rather than immediately -- the same as the
/// Windows `Run` value, and for the same reason: starting it now would mean a
/// second copy of an agent that is already running.
pub fn set_autostart(on: bool) -> Result<()> {
    let service = app_service().context("SMAppService is unavailable")?;
    // SAFETY: both take an `NSError **` out-parameter, which is documented as
    // optional; the status below says more about a refusal than the error
    // does, and needs no Foundation to read.
    let ok: Bool = unsafe {
        let err = std::ptr::null_mut::<*mut AnyObject>();
        if on {
            msg_send![&service, registerAndReturnError: err]
        } else {
            msg_send![&service, unregisterAndReturnError: err]
        }
    };
    if !ok.as_bool() {
        let status: isize = unsafe { msg_send![&service, status] };
        let verb = if on { "register" } else { "unregister" };
        bail!("SMAppService would not {verb} this app as a login item (status {status})");
    }
    Ok(())
}
