//! The Windows arm of [`super`]: `ksetup`, and the LSA registry state it writes.
//!
//! Ground truth for "is this machine enrolled" is Windows' own registry state,
//! not our config file (measured -- `ksetup` prints a misleading "machine is not
//! configured to log on to an external KDC" banner even when the mapping is
//! correct, so its *output* is not evidence):
//!
//! ```text
//! HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Domains\<REALM>\KdcNames    (MULTI_SZ)
//! HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Domains\<REALM>\RealmFlags  (DWORD)
//! HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\HostToRealm\<REALM>\SpnMappings (MULTI_SZ)
//! ```

use std::os::windows::process::CommandExt;

use anyhow::{Context, Result, anyhow};

use super::State;
use crate::discovery::KerberosConfig;
use crate::reg::{self, Root};

const DOMAINS: &str = r"SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Domains";
const HOST_TO_REALM: &str = r"SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\HostToRealm";

/// `RealmFlags` bit for `tcpsupported`. Mandatory, not optional: without it a
/// PAC-bearing TGS fails `KRB-ERROR 52` and Windows abandons the TCP retry with
/// `STATUS_INVALID_BUFFER_SIZE` -- measured, and the single knob that made
/// passwordless SMB work.
const REALM_FLAG_TCP_SUPPORTED: u32 = 0x2;

/// The one difference that `ksetup /setrealmflags` fixes without a reboot.
const TCP_DIFF: &str = "Kerberos over TCP is not enabled for the realm";

/// Compare Windows' LSA realm state to the broker's `kerberos` block.
pub fn state(k: &KerberosConfig) -> State {
    if k.realm.is_empty() {
        return State::NotEnrolled;
    }
    let domain_key = format!(r"{DOMAINS}\{}", k.realm);
    if !reg::key_exists(Root::Machine, &domain_key) {
        return State::NotEnrolled;
    }

    let mut diffs = Vec::new();

    let flags = reg::read_dword(Root::Machine, &domain_key, "RealmFlags").unwrap_or(0);
    if flags & REALM_FLAG_TCP_SUPPORTED == 0 {
        diffs.push(TCP_DIFF.into());
    }

    // An empty `kdcs` means "locate the KDC by SRV" -- then whatever KdcNames
    // holds is not a mismatch, so it is deliberately not compared.
    if !k.kdcs.is_empty() {
        let have =
            reg::read_multi_string(Root::Machine, &domain_key, "KdcNames").unwrap_or_default();
        for kdc in &k.kdcs {
            if !contains_ci(&have, kdc) {
                diffs.push(format!("KDC {kdc} is not registered"));
            }
        }
    }

    if !k.services.is_empty() {
        let key = format!(r"{HOST_TO_REALM}\{}", k.realm);
        let have = reg::read_multi_string(Root::Machine, &key, "SpnMappings").unwrap_or_default();
        for svc in &k.services {
            if !contains_ci(&have, svc) {
                diffs.push(format!("host mapping for {svc} is missing"));
            }
        }
    }

    if diffs.is_empty() { State::Enrolled } else { State::Stale(diffs) }
}

/// `RealmFlags` applies live; `KdcNames` and the host→realm mappings are cached
/// by LSASS at boot (measured). So a run that only flips the transport flag is
/// immediately effective, and saying "reboot required" there would be a lie.
pub fn needs_reboot(before: &State) -> bool {
    match before {
        State::Enrolled => false,
        State::NotEnrolled => true,
        // The transport flag is the one live change; anything else in the plan
        // writes boot-cached state.
        State::Stale(diffs) => diffs.iter().any(|d| d != TCP_DIFF),
    }
}

/// The exact `ksetup` command batch enrollment will run -- this list *is* the
/// confirmation prompt, so it must be literally what gets executed.
pub fn plan(k: &KerberosConfig) -> Vec<Vec<String>> {
    let realm = &k.realm;
    let mut cmds: Vec<Vec<String>> = Vec::new();

    if k.kdcs.is_empty() {
        // No KDC name: the realm is registered and the KDC located through the
        // published `_kerberos._udp.<realm>` SRV record -- measured: with SRV
        // published, a `KdcNames` value is unnecessary
        // (research spike `windows-tgt-followup-entra-joined`).
        cmds.push(vec!["ksetup".into(), "/addkdc".into(), realm.clone()]);
    } else {
        for kdc in &k.kdcs {
            cmds.push(vec!["ksetup".into(), "/addkdc".into(), realm.clone(), kdc.clone()]);
        }
    }

    // `/setrealmflags`, not `/addrealmflags`: the latter fails 0xc0000034 when
    // RealmFlags does not exist yet, and /setrealmflags creates it.
    cmds.push(vec!["ksetup".into(), "/setrealmflags".into(), realm.clone(), "tcpsupported".into()]);

    // Only for the escape-hatch foreign-zone services. Same-DNS-zone hosts are
    // covered by Windows' suffix heuristic and need no mapping, which is why
    // adding such a service never triggers re-enrollment.
    for svc in &k.services {
        cmds.push(vec!["ksetup".into(), "/addhosttorealmmap".into(), svc.clone(), realm.clone()]);
    }
    cmds
}

/// Render the plan the way the confirmation dialog shows it.
pub fn plan_text(k: &KerberosConfig) -> String {
    plan(k).iter().map(|c| c.join(" ")).collect::<Vec<_>>().join("\r\n")
}

/// Run the plan. Returns one line per command; an empty `Vec` cannot happen.
/// Errors are per-command so a partial batch is still reported honestly.
pub fn apply(k: &KerberosConfig) -> Vec<String> {
    plan(k)
        .into_iter()
        .map(|cmd| {
            let line = cmd.join(" ");
            match run(&cmd) {
                Ok(out) if out.trim().is_empty() => format!("OK   {line}"),
                Ok(out) => format!("OK   {line}\n     {}", out.trim().replace('\n', "\n     ")),
                Err(e) => format!("FAIL {line}\n     {e:#}"),
            }
        })
        .collect()
}

/// The two LSA keys that hold a realm's registration -- everything `apply` writes.
/// `Domains\<REALM>` carries `KdcNames`/`RealmFlags`; `HostToRealm\<REALM>` the
/// escape-hatch `SpnMappings`. Removing both is a complete unenrollment.
fn realm_keys(realm: &str) -> [String; 2] {
    [format!(r"{DOMAINS}\{realm}"), format!(r"{HOST_TO_REALM}\{realm}")]
}

/// The registry keys unenrollment will delete -- this list *is* the confirmation
/// prompt, the same contract `plan_text` has for enrollment.
pub fn unenroll_plan_text(realm: &str) -> String {
    realm_keys(realm).map(|k| format!(r"HKLM\{k}")).join("\r\n")
}

/// Remove the realm's LSA registration -- the inverse of `apply`. Idempotent (an
/// already-absent key is not an error), so it doubles as "make sure Windows has
/// forgotten this realm". Returns one line per key for the log and result dialog.
///
/// Like `KdcNames`, the removal is boot-cached: LSASS keeps the realm until the
/// next restart, so the caller should say a reboot is needed (see `needs_reboot`).
pub fn unenroll(realm: &str) -> Vec<String> {
    realm_keys(realm)
        .into_iter()
        .map(|key| match reg::delete_tree(Root::Machine, &key) {
            Ok(()) => format!(r"OK   removed HKLM\{key}"),
            Err(e) => format!("FAIL HKLM\\{key}\n     {e:#}"),
        })
        .collect()
}

/// `CREATE_NO_WINDOW` -- a GUI process must not flash a console per command.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn run(cmd: &[String]) -> Result<String> {
    let mut command = std::process::Command::new(&cmd[0]);
    command.args(&cmd[1..]);
    command.creation_flags(CREATE_NO_WINDOW);
    let out = command.output().with_context(|| format!("running {}", cmd.join(" ")))?;
    let text =
        format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    if out.status.success() {
        Ok(text)
    } else {
        Err(anyhow!("exit code {}: {}", out.status.code().unwrap_or(-1), text.trim()))
    }
}

fn contains_ci(haystack: &[String], needle: &str) -> bool {
    haystack.iter().any(|h| h.eq_ignore_ascii_case(needle))
}
