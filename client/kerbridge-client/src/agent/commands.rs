//! What the host may ask for: the verbs behind a menu item or a button, and the
//! settings sheet's read and write.
//!
//! Each one runs on the UI thread and returns at once. Anything that blocks is
//! only *started* here and finished in [`super::worker`], so a command's whole
//! job is to decide whether the ask is legal now, change what the user sees, and
//! hand the rest over.

use std::sync::atomic::Ordering;

use crate::describe::Fault;
use crate::strings::tr;
use crate::{config, log, time};

use super::worker::{self, Trigger};
use super::{
    Agent, BUSY, CANCEL, GRANT_CLEANUP, InterruptionGate, Phase, STARTUP_RETRIES, host,
    purge_realm, retarget, with,
};

/// Start a sign-in the user asked for. No-op while another worker is running.
///
/// On a machine with a pinned target this is an *authorization* instead, and the
/// button says so. The sign-in it runs proves the person at the keyboard, not
/// the account this machine works as, so turning it into a ticket would have the
/// machine publish under their name for up to a ticket lifetime -- with no error
/// anywhere and, on a build share, an ACL that probably permits it. What the
/// sign-in buys is a grant for the pinned account; the ticket comes from that.
///
/// Where the pin names the signed-in account itself, this is today's behavior
/// with one extra step: the same person ends up with the same ticket.
pub fn sign_in() {
    // Their click supersedes anything autostart still had queued or awaited.
    with(|a| {
        a.startup_retry_at = None;
        a.autostart_awaits_broker = false;
    });
    // Only when there is nothing to re-inject with. A pinned machine holding a
    // live grant has a free, browser-less way to recover from the transient
    // failure that put this button in front of someone, and diverting to
    // authorization unconditionally would take it away on exactly the machines
    // the pin exists for. `run_sign_in` is what holds decision 18: it tries the
    // grant, and its pin guard refuses to fall through to a token either way. A
    // grant refused as expired or revoked is forgotten as this event is applied,
    // so the next press lands here with nothing held and authorizes.
    if with(|a| a.settings.grant_for().is_some() && a.settings.grant().is_none()) {
        worker::create_grant();
        return;
    }
    worker::start_worker(Trigger::User);
}

/// Re-inject now, silently if a credential is available.
pub fn renew_now() {
    worker::start_worker(Trigger::Renewal);
}

/// Sign in at logon, without being asked and without showing anything.
///
/// Autostart means "be a working background agent", and the checkbox says as much
/// ("Sign in automatically after you log in") -- so with a credential Windows can
/// serve silently, a logon should end in a live ticket and no click. Every
/// condition here is a reason the attempt could only annoy: no broker, no way to
/// be silent, a realm Windows does not know yet, or a ticket already adopted from
/// the logon session.
///
/// There are two ways to be silent, not one. Windows sign-in is the old one -- the
/// refresh token is memory-only, so on a fresh process nothing else could be. A
/// device grant is the other, and needs neither a browser nor a Windows
/// credential, so requiring the checkbox here left an unattended machine holding
/// a good grant sitting at "not signed in" after every logon, for no reason but
/// that its operator preferred the browser.
///
/// [`config::autostart_active`] and not `autostart_enabled`: a fleet deployed with
/// the MSI's `AUTOSTART=1` is Entra-joined and wants exactly this, and reading only
/// the per-user value skipped the attempt on every one of those machines. Nothing
/// widens here -- the silent-supply condition above still holds, and
/// [`worker::start_worker`] never reaches a browser on its own.
pub fn autostart_sign_in() {
    let go = with(|a| {
        let eligible = autostart_eligible(a);
        // DNS can name the broker later; the SRV answer then starts this.
        a.autostart_awaits_broker = eligible && a.settings.broker_url().is_none();
        let go = eligible && a.settings.broker_url().is_some() && !a.enroll_state.needs_action();
        if go {
            a.startup_retries = STARTUP_RETRIES;
        }
        go
    });
    if go {
        log::info("autostart: trying a silent sign-in");
        worker::start_worker(Trigger::Startup);
    }
}

/// The autostart conditions that do not depend on the broker. The OS read is
/// last, so a machine that fails the others does not make it.
fn autostart_eligible(a: &Agent) -> bool {
    a.phase == Phase::SignedOut
        && (a.settings.windows_sign_in() || a.settings.grant().is_some())
        && config::autostart_active()
}

pub fn cancel_sign_in() {
    CANCEL.store(true, Ordering::Relaxed);
    log::info("sign-in cancel requested");
}

/// Sign off: purge this realm's Kerberos tickets, and stop expecting this
/// machine to be working. The cloud session is untouched -- the browser SSO
/// cookie survives, so signing back in needs no fresh credential prompt.
///
/// Ticket-cache only, and the label stops exactly where the mechanism does: a
/// purge takes the TGT and the CIFS tickets, and an SMB session already open
/// in Explorer keeps serving files off an empty cache with no Kerberos traffic at all.
/// Which clients hold one open is theirs to decide, so the note that follows says *may*.
pub fn drop_ticket() {
    with(|a| {
        let realm = a.kerberos.realm.clone();
        let purged = purge_realm(&realm);
        a.reset_session();
        a.expect(false);
        // After the reset, which clears it.
        if purged {
            a.note(tr().signed_off_note);
        } else {
            // The tickets are still in the cache and the shares still open, so
            // the icon must not fade to Off over a sign-off that did not happen.
            a.record(Some(Fault::Other), tr().err_sign_off_failed.to_string());
        }
    });
}

/// Sign out of the cloud: forget the in-memory refresh token and end the browser
/// session this agent put at the authority. The Kerberos tickets stay.
///
/// **The OS's own account is not touched.** A browser sign-in leaves an SSO
/// cookie of ours, which outlives this process and is a real leak on a machine
/// somebody walks away from; a WAM sign-in leaves no cookie of ours at all, and
/// the most this process could do there is force the next acquisition to prompt.
/// That retires no session -- the Windows account was there before and stays
/// after -- so it buys nothing for the silent renewal it spends.
pub fn sign_out_idp() {
    worker::begin_cloud_sign_out();
}

/// Give up the grant this machine holds, at the broker that issued it.
pub fn give_up_grant_now() -> bool {
    with(|a| {
        let broker = a.settings.broker_url().map(str::to_owned);
        worker::give_up_grant(a, broker)
    })
}

/// The status surface has gone away. The only thing that outlives a repaint is
/// the promotion a fresh grant earns, and closing the surface is what spends it.
pub fn status_closed() {
    with(|a| a.just_authorized = false);
}

pub fn open_log() {
    let Some(path) = config::log_path() else {
        return;
    };
    // Create it if this is the first run, so "Open log" never dead-ends.
    if !path.exists() {
        log::info("log opened from the menu");
    }
    host().open_path(&path.to_string_lossy());
}

pub fn open_log_folder() {
    if let Some(dir) = config::app_dir() {
        let _ = std::fs::create_dir_all(&dir);
        host().open_path(&dir.to_string_lossy());
    }
}

/// What the Settings window shows. Autostart is read from the registry each
/// time, because the user can also change it in Task Manager.
pub struct SettingsView {
    pub broker_url: String,
    pub broker_locked: bool,
    pub autostart: bool,
    /// True when a machine-wide entry or machine policy decides it. The checkbox
    /// then reads the decided value and does not move: a per-user setting cannot
    /// countermand either, and a box beside an app that ignores it is a lie.
    pub autostart_locked: bool,
    pub windows_sign_in: bool,
    /// True when machine policy decides the Windows sign-in, same rule.
    pub windows_sign_in_locked: bool,
    pub silent: bool,
    pub silent_locked: bool,
    /// The realm the Advanced actions target; empty until it has been discovered.
    pub realm: String,
    /// How many days a device grant would last here. 0 means the deployment has
    /// the feature off, and the button does not exist at all.
    pub grant_days: u32,
    /// The deadline on the grant this machine already holds, or 0 for none. Its
    /// presence is what turns the action into "Extend".
    pub grant_deadline: i64,
    /// Whom this machine authorizes itself for; empty is "whoever signs in".
    pub grant_for: String,
    /// True when that came from machine policy, so it is shown rather than
    /// offered for editing. Not a security control either way -- the broker
    /// checks the delegate group whatever this asks for -- but a field that lies
    /// about being editable is worse than one that does not offer.
    pub grant_for_locked: bool,
}

pub fn settings_view() -> SettingsView {
    let machine_wide = config::autostart_machine_wide();
    with(|a| SettingsView {
        broker_url: a.settings.broker_url().unwrap_or_default().to_string(),
        broker_locked: a.settings.broker_url_locked(),
        autostart: config::autostart_active(),
        autostart_locked: machine_wide || a.settings.autostart_managed(),
        windows_sign_in: a.settings.windows_sign_in(),
        windows_sign_in_locked: a.settings.windows_sign_in_locked(),
        silent: a.settings.silent(),
        silent_locked: a.settings.silent_locked(),
        realm: a.kerberos.realm.clone(),
        grant_days: if a.device_grant.enabled() { a.device_grant.days } else { 0 },
        grant_deadline: a.settings.grant().map_or(0, |g| g.sign_in_required_by),
        grant_for: a.settings.grant_for().unwrap_or_default().to_string(),
        grant_for_locked: a.settings.grant_for_locked(),
    })
}

/// Effective silent mode, with the built-in `false` while it is unresolved. For
/// a surface that follows user input; an unsolicited one asks
/// [`interruption_gate`].
pub fn silent() -> bool {
    with(|a| a.settings.silent())
}

/// Whether an unsolicited interruption may reach the user now. The host asks
/// before it raises a status surface on its own, and before it asks the OS for
/// notification permission.
pub fn interruption_gate() -> InterruptionGate {
    with(|a| a.interruption_gate())
}

/// `None` leaves a setting unchanged and does not persist its effective value.
#[derive(Default)]
pub struct SettingsChange<'a> {
    pub broker_url: Option<&'a str>,
    pub autostart: Option<bool>,
    pub windows_sign_in: Option<bool>,
    pub silent: Option<bool>,
    pub grant_for: Option<&'a str>,
}

/// Apply and persist settings changes. A changed broker URL invalidates all
/// outstanding discovery and clears the old broker snapshot.
///
/// A changed pin invalidates nothing. It decides who the *next* authorization
/// names and does not touch the grant this machine already holds, which keeps
/// working as the account it was issued for until somebody authorizes the
/// machine again -- at which point a human is at the keyboard anyway.
pub fn apply_settings(change: SettingsChange<'_>) {
    with(|a| {
        let before = a.settings.broker_url().unwrap_or_default().to_string();
        let before_user = a.settings.user_broker_url();
        let old_broker = (!before.is_empty()).then(|| before.clone());
        // `None` is "the user did not touch the field", which is not the same as
        // an empty one. It matters because `broker_url()` resolves *through* the
        // address DNS volunteered, which `config.rs` keeps deliberately in memory
        // only -- so a caller that read the field back and handed it here would
        // pin a machine that was following DNS, and the `before != after` guard
        // below would compare equal and say nothing happened.
        let broker_change_blocked = change.broker_url.is_some()
            && (BUSY.load(Ordering::Relaxed)
                || GRANT_CLEANUP.load(Ordering::Relaxed)
                || a.cloud_sign_out.is_some());
        if broker_change_blocked {
            log::warn("broker URL change ignored while agent work is in progress");
        }
        if let Some(url) = change.broker_url
            && !broker_change_blocked
            && !a.settings.broker_url_locked()
        {
            a.settings.set_broker_url(url);
        }
        if a.settings.broker_url().unwrap_or_default() != before {
            log::info("broker URL changed; ending the previous realm's session");
            if retarget(a, old_broker) {
                // Try the new address at once, silently. The old broker payload
                // and every old fault are already gone.
                a.startup_retry_at = Some(time::now());
                // A cleared address returns to DNS, and autostart waits for
                // its answer as it does at logon.
                a.autostart_awaits_broker =
                    a.settings.broker_url().is_none() && autostart_eligible(a);
            } else {
                a.settings.restore_user_broker_url(before_user);
                log::warn("broker URL change cancelled because old realm tickets remain");
            }
        }
        if let Some(target) = change.grant_for
            && !a.settings.grant_for_locked()
        {
            a.settings.set_grant_for(target);
        }
        if let Some(on) = change.windows_sign_in
            && !a.settings.windows_sign_in_locked()
        {
            a.settings.set_windows_sign_in(on);
        }
        if let Some(on) = change.silent
            && !a.settings.silent_locked()
        {
            a.settings.set_silent(on);
        }
        // Under a machine-wide entry or a policy value the checkbox is disabled
        // and reads the decided value, so what comes back here is not a choice
        // anyone made: writing it back would leave a per-user entry that
        // outlives the deployment's, and a `config.toml` line that outlives the
        // policy.
        if let Some(on) = change.autostart
            && !config::autostart_machine_wide()
            && !a.settings.autostart_managed()
        {
            a.settings.set_autostart_choice(on);
            if let Err(e) = config::set_autostart(on) {
                log::warn(&format!("could not update the autostart entry: {e:#}"));
            }
        }
        if let Err(e) = a.settings.save() {
            log::warn(&format!("could not save config.toml: {e:#}"));
        }
    })
}
