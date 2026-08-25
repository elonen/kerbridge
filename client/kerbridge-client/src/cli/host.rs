//! The subcommands that change this machine rather than this user's tickets:
//! realm registration and the NTLM-fallback repair. Windows only -- macOS
//! resolves its realm from DNS with no file to write, and recovers from an
//! expired ticket on its own, so none of these flags exist there.
//!
//! Every one of them elevates, and each relaunches a second copy for exactly the
//! privileged step rather than running the whole CLI elevated. See
//! [`kerbridge_client::elevate`] for why that boundary is where it is.

use anyhow::{Context, Result, bail};
use kerbridge_client::{config, discovery, elevate, enroll, repair};

use super::resolve::{resolve_broker, resolve_realm};
use crate::Args;

/// Print what Windows believes about `kerberos`, and hand back the state so a
/// caller that intends to act can decide whether there is anything to do.
fn report_enroll_state(kerberos: &discovery::KerberosConfig) -> enroll::State {
    let state = enroll::state(kerberos);
    match &state {
        enroll::State::Enrolled => println!("[kerbridge] {} is enrolled", kerberos.realm),
        enroll::State::NotEnrolled => {
            println!("[kerbridge] {} is not registered with Windows", kerberos.realm)
        }
        enroll::State::Stale(diffs) => {
            println!("[kerbridge] {} needs attention:", kerberos.realm);
            for d in diffs {
                println!("  - {d}");
            }
        }
    }
    state
}

/// `--enroll-status`: what Windows believes, and nothing else.
///
/// Answered against the broker when there is one, so the report includes drift
/// from what the broker describes. Without one it falls back to the realm this
/// machine has already cached, because the question is about the local registry
/// and refusing to answer it strands whoever is diagnosing a half-configured
/// machine -- they would have to supply the very thing they are asking about.
/// Only the *comparison* needs the broker, so say when it was not made.
pub(crate) fn do_enroll_status(args: &Args) -> Result<()> {
    let kerberos = match resolve_broker(args) {
        Ok(broker) => discovery::discover(&broker).context("discovering the realm")?.kerberos,
        Err(no_broker) => {
            let realm = config::Settings::load().cache().realm.clone();
            if realm.is_empty() {
                return Err(no_broker);
            }
            println!(
                "[kerbridge] no broker configured -- reporting {realm} from this machine alone"
            );
            discovery::KerberosConfig { realm, ..Default::default() }
        }
    };
    report_enroll_state(&kerberos);
    Ok(())
}

/// What an elevated relaunch came to, as a CLI exit. A decline is a decision and
/// leaves with nothing to say; a non-zero code is the child's own, and it has
/// already printed why.
fn report_elevated(outcome: elevate::Elevated, step: &str) -> Result<()> {
    match outcome {
        elevate::Elevated::Ran(0) => Ok(()),
        // The child did the work and wants a restart. The code has to pass
        // out rather than read as a failed step: a deployment tool reads it
        // from the process it launched, not from the elevated child it cannot
        // see.
        elevate::Elevated::Ran(code) if code as i32 == crate::EXIT_REBOOT_REQUIRED => {
            exit_reboot_required()
        }
        elevate::Elevated::Ran(code) => bail!("the elevated {step} exited with code {code}"),
        elevate::Elevated::Declined => {
            println!("[kerbridge] declined at the administrator prompt; nothing was changed.");
            Ok(())
        }
        elevate::Elevated::Unavailable => {
            bail!(
                "UAC is disabled here (EnableLUA=0), so the {step} cannot elevate itself; run it from an already-elevated shell"
            )
        }
    }
}

/// The tray's dialog uses this to leave its "waiting for permission" phase. A
/// console has nothing to move on.
fn ignore_start() {}

/// Report Windows' realm state and bring it in line. `force` re-applies the plan
/// even when Windows already looks set up (`--reenroll`).
pub(crate) fn do_enroll(broker: &str, force: bool, yes: bool) -> Result<()> {
    let kerberos = discovery::discover(broker).context("discovering the realm")?.kerberos;
    let state = report_enroll_state(&kerberos);
    if !state.needs_action() && !force {
        return Ok(());
    }

    // Relaunch just this step through UAC -- never the whole process. The
    // elevated copy re-reads /config and asks for confirmation itself, so the
    // confirmation always happens in the process that will do the writing.
    if !elevate::is_elevated() {
        println!("\n[kerbridge] elevating to apply...");
        let mut relaunch = vec!["--broker", broker, if force { "--reenroll" } else { "--enroll" }];
        if yes {
            relaunch.push("--yes");
        }
        report_elevated(elevate::run_elevated(&relaunch, &ignore_start)?, "enrollment")?;
        return Ok(());
    }

    println!("\n[kerbridge] about to run:\n");
    for line in enroll::plan_text(&kerberos).lines() {
        println!("  {line}");
    }
    if !agreed(yes, "\nRun them now? [y/N] ")? {
        bail!("enrollment declined");
    }
    for line in enroll::apply(&kerberos) {
        println!("{line}");
    }
    if enroll::needs_reboot(&state) {
        println!("\n[kerbridge] reboot required: Windows caches realm state at boot.");
        if yes {
            return exit_reboot_required();
        }
    }
    Ok(())
}

/// Remove the realm's registration from Windows (`--unenroll`). The inverse of
/// enrollment: it deletes the LSA keys `ksetup` built, and a reboot finishes it.
pub(crate) fn do_unenroll(args: &Args, yes: bool) -> Result<()> {
    let realm = resolve_realm(args)?;

    if !elevate::is_elevated() {
        println!("\n[kerbridge] elevating to unregister {realm}...");
        let mut relaunch = vec!["--unenroll"];
        if let Some(b) = &args.broker {
            relaunch.extend_from_slice(&["--broker", b]);
        }
        if yes {
            relaunch.push("--yes");
        }
        report_elevated(elevate::run_elevated(&relaunch, &ignore_start)?, "unenrollment")?;
        return Ok(());
    }

    println!("\n[kerbridge] about to remove from Windows:\n");
    for line in enroll::unenroll_plan_text(&realm).lines() {
        println!("  {line}");
    }
    if !agreed(yes, "\nRemove them now? [y/N] ")? {
        bail!("unenrollment declined");
    }
    for line in enroll::unenroll(&realm) {
        println!("{line}");
    }
    println!("\n[kerbridge] reboot required: Windows caches realm state at boot.");
    Ok(())
}

pub(crate) fn do_repair(yes: bool) -> Result<()> {
    if !elevate::is_elevated() {
        let mut relaunch = vec!["--repair"];
        if yes {
            relaunch.push("--yes");
        }
        report_elevated(elevate::run_elevated(&relaunch, &ignore_start)?, "repair")?;
        return Ok(());
    }
    println!("[kerbridge] restarting the Workstation service -- every SMB session drops.");
    if !agreed(yes, "Continue? [y/N] ")? {
        bail!("repair declined");
    }
    for step in repair::restart_workstation()? {
        println!("  {step}");
    }
    Ok(())
}

/// Only the elevated one-shots ask, and they exist only on Windows.
/// Leave with the restart still owed. `std::process::exit` rather than a return
/// value: nothing above here can carry an exit code, and the one caller that
/// matters is a deployment tool reading the code off this process.
fn exit_reboot_required() -> Result<()> {
    use std::io::Write;
    std::io::stdout().flush().ok();
    std::process::exit(crate::EXIT_REBOOT_REQUIRED);
}

/// The confirmation, or `--yes` standing in for it. The plan is printed either
/// way, so an unattended run still leaves in the log exactly what it ran --
/// what `--yes` removes is the wait, not the record.
fn agreed(yes: bool, prompt: &str) -> Result<bool> {
    if yes {
        println!("{}yes (--yes)", prompt.trim_start_matches('\n'));
        return Ok(true);
    }
    confirm(prompt)
}

fn confirm(prompt: &str) -> Result<bool> {
    use std::io::Write;
    print!("{prompt}");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}
