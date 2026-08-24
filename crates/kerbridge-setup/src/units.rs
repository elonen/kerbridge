//! The KerBridge units: what `kbsetup` asks systemd about them, and the one
//! thing it does to them.
//!
//! **Why anything has to.** A daemon whose input is missing exits, and the start
//! limiter in `debian/kerbridge-issuerd.service` then latches the unit into
//! `failed` rather than let it loop. That is deliberate: installed and not yet
//! configured is a state, not a fault. But the retry budget is spent at
//! *install* time, long before the operator reaches `kbsetup directory`, which
//! is what writes the bind passwords the broker and sync exit without. Nothing
//! else on the host clears the latch afterwards, and the setup verbs are the
//! only thing that knows the wait is over.

use std::path::Path;

use crate::run;

/// The units a Debian deployment installs, in start order.
pub const UNITS: [&str; 3] = ["kerbridge-issuerd", "kerbridge-broker", "kerbridge-sync"];

/// Clear the latch and start the units that are in `failed`, after a verb that
/// wrote what one of them was waiting for.
///
/// **Only `failed`.** A unit an operator stopped is `inactive` and is left
/// alone, and one that is already running is not restarted -- both are
/// decisions this has no business overruling. Only the state systemd reaches on
/// its own, for a reason that may no longer hold, is acted on.
///
/// **Called after the write, never before.** A verb that has not yet supplied
/// what the unit lacks would only spend the retry budget again and latch it a
/// second time.
///
/// Never fatal: the unit may still be missing something else, and the verb that
/// called this did its own work.
///
/// A no-op where systemd does not run, which is every Compose deployment.
pub fn resume_failed() {
    if !Path::new("/run/systemd/system").exists() {
        return;
    }
    for unit in UNITS.into_iter().filter(is_failed) {
        // `reset-failed` first: within the 60-second window a plain `start` is
        // refused without even running ExecStartPre=, and each refusal pushes
        // the window out another minute.
        if let Err(e) = run::attempt(&["systemctl", "reset-failed", unit], None) {
            eprintln!("[kbsetup] warning: clearing the failed state of {unit}: {e:#}");
            continue;
        }
        match run::attempt(&["systemctl", "start", unit], None) {
            Ok(done) if done.ok() => {
                println!("[kbsetup] started {unit}, which had failed before this was in place");
            }
            Ok(done) => {
                eprintln!(
                    "[kbsetup] warning: {unit} had failed and still does not start: {}",
                    done.reason()
                );
                if let Some(said) = last_line(unit) {
                    eprintln!("[kbsetup] warning:   its own last line: {said}");
                }
                eprintln!("[kbsetup] warning:   `{}` has the rest", reader(unit));
            }
            Err(e) => eprintln!("[kbsetup] warning: starting {unit}: {e:#}"),
        }
    }
}

/// Whether systemd holds this unit in `failed`.
pub fn is_failed(unit: &&str) -> bool {
    run::attempt(&["systemctl", "is-failed", unit], None).is_ok_and(|done| done.ok())
}

/// The last line the daemon itself wrote, for a unit that is not running.
///
/// **Why this is not `systemctl status`.** That shows ten lines, and a unit
/// that spent its restart budget has ten lines of systemd's own -- `Scheduled
/// restart job`, `Start request repeated too quickly` -- with the sentence that
/// says *why* pushed off the top.
///
/// `_SYSTEMD_UNIT=` rather than `-u`: `-u` adds systemd's messages *about* the
/// unit to the unit's own, which is exactly the noise to be rid of here. What
/// is left is what the daemon printed before it exited.
///
/// `None` where the journal has nothing to offer, so a caller cannot print an
/// empty quotation.
pub fn last_line(unit: &str) -> Option<String> {
    let done = run::attempt(
        &["journalctl", &format!("_SYSTEMD_UNIT={unit}.service"), "-n", "1", "-o", "cat", "-q"],
        None,
    )
    .ok()?;
    let line = done.stdout.trim();
    (done.ok() && !line.is_empty()).then(|| line.to_owned())
}

/// What to read for the whole of it, once [`last_line`] has given the end.
pub fn reader(unit: &str) -> String {
    format!("journalctl _SYSTEMD_UNIT={unit}.service -n 30")
}
