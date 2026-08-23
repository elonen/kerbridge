//! Operations that run with administrator rights:
//! - Register the realm with Windows (`--enroll`, `--reenroll`)
//! - Remove registration (`--unenroll`)
//! - Restart the redirector to clear NTLM fallback (`--repair`)
//!
//! These operations run as a separate elevated process, not as an elevated tray.
//! Reason: An elevated process has a different LUID and ticket cache. Windows
//! cannot see a ticket that you inject into the elevated cache. The Windows SMB
//! redirector cannot use it. (Evidence: spike `windows-tgt-followup-entra-joined`
//! @5). The tray relaunches itself for this step only. It stays unprivileged for
//! all other operations.
//!
//! **This process shows no UI.**
//! UIPI permits the child to write down to the medium-IL tray. UIPI prevents the
//! tray from controlling the child UI. The parent shows confirmation before the
//! UAC prompt. The child writes an exit code and one sentence to the path the
//! parent gave. If the parent finds nothing at that path, it shows "couldn't
//! confirm", not a fabricated success.
//!
//! This process reads the enrollment plan from `/config`. It does not take the
//! plan from the tray. Only a URL crosses the privilege boundary. The plan the
//! parent showed is confirmation, not instruction.

use kerbridge_client::strings::{fill, tr};
use kerbridge_client::{discovery, elevate, enroll, log, repair};

/// What the child owes back: whether it worked, and the one sentence saying so.
struct Report {
    ok: bool,
    message: String,
}

impl Report {
    fn ok(message: String) -> Self {
        Self { ok: true, message }
    }

    fn failed(message: &str) -> Self {
        Self { ok: false, message: message.to_owned() }
    }
}

/// Run one privileged verb and leave its sentence where the parent will look.
/// Returns the process exit code: 0 means the sentence is a success.
pub fn run(mode: &str, broker: &str, result: &str) -> u32 {
    // A person running this exe from a shell has not been through UAC. The
    // relaunch keeps the same result path, so whichever copy does the work is
    // the one that writes the sentence.
    if !elevate::is_elevated() {
        let args = if broker.is_empty() {
            vec![mode, "--result", result]
        } else {
            vec![mode, broker, "--result", result]
        };
        return match elevate::run_elevated(&args, &|| {}) {
            Ok(elevate::Elevated::Ran(code)) => code,
            // Both leave the result file untouched, which the parent reads as
            // "nothing to confirm" -- and a decline it already knows about from
            // the return of its own `run_elevated`.
            Ok(_) => 1,
            Err(e) => {
                log::error(&format!("could not elevate: {e:#}"));
                1
            }
        };
    }

    let report = match mode {
        "--enroll" => run_enroll(broker, false),
        "--reenroll" => run_enroll(broker, true),
        "--unenroll" => run_unenroll(broker),
        _ => run_repair(),
    };
    if let Err(e) = std::fs::write(result, &report.message) {
        // The work is done either way; what is lost is the parent's ability to
        // say what happened, which is exactly what it reports.
        log::error(&format!("could not write the result file {result}: {e:#}"));
    }
    u32::from(!report.ok)
}

fn run_enroll(broker_url: &str, force: bool) -> Report {
    let s = tr();
    let kerberos = match discovery::discover(broker_url) {
        Ok(c) => c.kerberos,
        Err(e) => {
            log::error(&format!("enrollment discovery failed: {e:#}"));
            return Report::failed(s.enroll_discovery_failed);
        }
    };

    let state = enroll::state(&kerberos);
    if !state.needs_action() && !force {
        return Report::ok(fill(s.enroll_already, &[("realm", &kerberos.realm)]));
    }

    for line in enroll::apply(&kerberos) {
        log::info(&format!("enroll: {}", line.replace('\n', " ")));
    }
    if enroll::state(&kerberos).needs_action() {
        return Report::failed(s.enroll_incomplete);
    }
    Report::ok(fill(s.dlg_enroll_result, &[("realm", &kerberos.realm)]))
}

fn run_unenroll(broker_url: &str) -> Report {
    let s = tr();
    let kerberos = match discovery::discover(broker_url) {
        Ok(c) => c.kerberos,
        Err(e) => {
            log::error(&format!("unenrollment discovery failed: {e:#}"));
            return Report::failed(s.enroll_discovery_failed);
        }
    };
    let realm = &kerberos.realm;

    if matches!(enroll::state(&kerberos), enroll::State::NotEnrolled) {
        return Report::ok(fill(s.unenroll_already, &[("realm", realm)]));
    }

    for line in enroll::unenroll(realm) {
        log::info(&format!("unenroll: {}", line.replace('\n', " ")));
    }
    if !matches!(enroll::state(&kerberos), enroll::State::NotEnrolled) {
        return Report::failed(s.unenroll_incomplete);
    }
    Report::ok(fill(s.dlg_unenroll_result, &[("realm", realm)]))
}

fn run_repair() -> Report {
    let s = tr();
    match repair::restart_workstation() {
        Ok(steps) => {
            log::info(&format!("repair: {}", steps.join("; ")));
            Report::ok(s.dlg_repair_result.to_owned())
        }
        Err(e) => {
            log::error(&format!("repair failed: {e:#}"));
            Report::failed(s.repair_incomplete)
        }
    }
}
