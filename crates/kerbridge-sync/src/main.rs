//! `kerbridge-sync` -- IdP-to-realm synchronization.
//!
//! Reads configured users and groups from each cloud IdP and reconciles them
//! into dedicated Samba AD OUs over delegated LDAPS, stamping each object with
//! its [`ExternalIdentity`](kerbridge_core::ExternalIdentity). Separate from the
//! broker so sync credentials and realm directory write privileges stay out of the
//! interactive authentication path.
//!
//! Samba AD is the single source of truth for external-to-realm mappings; this
//! service persists nothing of its own. What a read has to carry across cycles
//! is the adapter's, below the seam.
//!
//! One process serves every source the config set lists, one after another. A
//! cycle per source: ask that source's adapter to advance, diff the snapshot it
//! returns against the current realm directory with the [`planner`], and apply the
//! plan over delegated LDAPS as that source's own account. How an IdP is read
//! is the adapter's own business, behind
//! [`kerbridge_idp::sync::DirectorySource`]; a cycle that produced no whole
//! enumeration is discarded rather than planned from, so
//! it can never delete or disable anything.
//!
//! Sequential rather than concurrent, which is what makes the realm
//! single-writer: two sources allocating a `sAMAccountName` at once would each
//! see the other's name as free.
//!
//! Contract: `DESIGN.md` @ Directory ownership and synchronization.
//! Measured behavior: research spike `entra-directory-sync`.

#![forbid(unsafe_code)]

mod config;
mod directory;
mod planner;

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use kerbridge_core::audit::AuditLog;
use kerbridge_core::grant::DeviceGrant;
use kerbridge_core::time::{now_unix, rfc3339};
use kerbridge_notify::{Event, Notifier, Severity};

use crate::config::{Config, SourceConfig};
use crate::directory::{Directory, marker_index};
use kerbridge_idp::sync::{
    CredentialState, DirectorySource, Progress, SourceError, SourceSnapshot, connect,
};

use crate::planner::{AlertKind, Current, PlanCtx, PlanError, plan_sync};

/// Consecutive discarded cycles before an operator is alerted.
const FAIL_THRESHOLD: u32 = 3;
/// Connect/bind timeout for the delegated LDAPS writes.
const LDAP_TIMEOUT: Duration = Duration::from_secs(30);

const DEFAULT_CONFIG_DIR: &str = "/etc/kerbridge";

/// The durable half of what [`audit`] writes. A process-wide sink, set once
/// before the first cycle, for the reason `issuerd` gives: the reconcile path is
/// four calls below `main` and would otherwise carry a logger down to reach it.
static AUDIT: OnceLock<AuditLog> = OnceLock::new();

/// A line that is also the record: an object this process created, renamed,
/// disabled or emptied, and the writes the realm directory refused. Anything else is a
/// plain `eprintln!`, which the console keeps and the file does not.
///
/// One string for both, as the broker does it, so the console copy and the
/// durable one cannot come to say different things.
fn audit(line: &str) {
    eprintln!("{line}");
    if let Some(sink) = AUDIT.get() {
        sink.append(line);
    }
}

/// One source's whole world: the account it binds as, the OU it owns, and the
/// IdP directory it mirrors.
///
/// The realm directory client is owned here rather than shared. With one process
/// serving several sources, "apply this source's plan over that source's
/// connection" would retire every object the bind identity did not recognize,
/// and owning it is what makes the sentence unspellable.
struct SourceSync {
    cfg: SourceConfig,
    dir: Directory,
    source: Box<dyn DirectorySource>,
    consecutive_failures: u32,
}

impl SourceSync {
    fn new(cfg: SourceConfig, shared: &Config, notifier: Arc<Notifier>) -> Result<Self> {
        let dir = Directory::new(
            shared.ldap_url.clone(),
            shared.base_dn.clone(),
            cfg.idp_ou.clone(),
            cfg.bind_dn.clone(),
            cfg.bind_password.clone(),
            &shared.ldap_ca_file,
            LDAP_TIMEOUT,
        )
        .with_context(|| format!("configuring the realm directory client for {}", cfg.name()))?;
        let source = connect(&cfg.settings, cfg.name(), notifier)
            .with_context(|| format!("connecting to the IdP directory for {}", cfg.name()))?;
        Ok(Self { cfg, dir, source, consecutive_failures: 0 })
    }

    /// This source's turn. Never returns `Err`: one source's failure is counted
    /// against that source and the next one still runs.
    async fn tick(&mut self, shared: &Config, notifier: &Notifier) {
        let name = self.cfg.name().to_owned();
        // Before the read and whatever it concludes: a source whose cycles keep
        // failing is exactly the one whose credential may be why.
        report_credential(self.source.as_ref(), &name, shared, notifier).await;

        let progress = self.source.advance().await;
        // Anything that got as far as holding a credential disproves "there is
        // none yet". A credential that could not be read neither proves nor
        // disproves it, so that one outcome leaves the record alone.
        if !matches!(progress, Ok(Progress::Idle(_)) | Err(SourceError::Credential(_))) {
            notifier.resolve_subject("sync-not-configured", &name).await;
        }
        match progress {
            Ok(Progress::Idle(why)) => {
                notifier
                    .send(Event::new("sync-not-configured", Severity::Warning, why).subject(&name))
                    .await;
            }
            Ok(Progress::Complete(snapshot)) => {
                let applied = self.reconcile(shared, snapshot, notifier).await;
                match applied {
                    Ok(()) => {
                        // Cleared once the whole cycle has concluded, not on the read
                        // above. A cycle that reads the IdP perfectly and then cannot
                        // write to the realm directory has not succeeded, and clearing it there
                        // makes a standing LDAP outage alternate 1, 0, 1, 0 -- never
                        // reaching the threshold, however long it lasts.
                        if self.consecutive_failures >= FAIL_THRESHOLD {
                            audit(&format!(
                                "[sync/{name}] RESUMED after {} discarded cycles",
                                self.consecutive_failures
                            ));
                        }
                        self.consecutive_failures = 0;
                        notifier.resolve_subject("sync-cycle-failing", &name).await;
                    }
                    Err(e) => cycle_failed(self, notifier, format!("cycle error: {e:#}")).await,
                }
            }
            Err(e) if e.counts_as_failure() => cycle_failed(self, notifier, e.to_string()).await,
            // Reported precisely on its own channel already.
            Err(_) => {}
        }
    }

    /// Diff a whole reading of the IdP directory against the current directory
    /// (realm), and apply. Returns `Err` only on an infrastructure failure -- the
    /// realm directory out of reach -- which the caller counts. Policy outcomes such as a frozen
    /// admission group are handled in-band and count as a cycle that reached a
    /// conclusion.
    async fn reconcile(
        &self,
        shared: &Config,
        snapshot: SourceSnapshot,
        notifier: &Notifier,
    ) -> Result<()> {
        let SourceSnapshot { desired, admission, grant, refused } = snapshot;
        let cfg = &self.cfg;
        let name = cfg.name();
        // The syncable rule narrows the admission-group closure, and silence about that is the
        // failure an operator cannot debug: they nominated a group or a person, nothing
        // appeared, and the plan they read is simply smaller than they expected. Logged
        // every cycle rather than on change, because this is the state of the IdP and
        // there is no cheap way to know which cycle the operator is reading.
        for why in &refused {
            eprintln!("[sync/{name}] refused: {why}");
        }
        let current = self
            .dir
            .read_current(&cfg.source)
            .await
            .context("reading current realm directory state")?;

        let now = now_rfc3339();
        let identity = cfg.identity();
        let ctx = PlanCtx {
            idp_ou: &cfg.idp_ou,
            admission: &admission,
            grant: grant.as_ref(),
            upn_suffix: &shared.upn_suffix,
            group_suffix: &cfg.group_suffix,
            now: &now,
            automatic_sam_renames: shared.automatic_sam_renames,
            identity: &identity,
        };
        let plan = match plan_sync(&desired, &current, &ctx) {
            Ok(p) => p,
            Err(PlanError::NameCollision(names)) => {
                notifier
                    .send(
                        Event::new(
                            "sync-name-collision",
                            Severity::Error,
                            format!(
                                "sAMAccountName collision blocks the whole cycle for source \
                                 {name}; nothing applied: {}",
                                names.join(", ")
                            ),
                        )
                        .subject(name),
                    )
                    .await;
                return Ok(());
            }
        };

        // A plan was built at all, so no collision blocked this cycle: whatever names
        // were colliding when one last did are no longer doing so.
        notifier.resolve_subject("sync-name-collision", name).await;

        let mut admission_alerted = false;
        let mut grant_alerted = false;
        for a in &plan.alerts {
            match a.kind {
                AlertKind::AdmissionGroup => {
                    notifier
                        .send(
                            Event::new(ADMISSION_MISSING, Severity::Error, a.message.clone())
                                .subject(name),
                        )
                        .await;
                    admission_alerted = true;
                }
                AlertKind::DeviceGrantGroup => {
                    notifier.send(grant_group_wrong(name, &a.message)).await;
                    grant_alerted = true;
                }
                AlertKind::Note => eprintln!("[sync/{name}] ALERT: {}", a.message),
            }
        }
        if !grant_alerted {
            // Same reasoning as the admission clear below: the configured group and
            // the marker agree again, so whichever way they disagreed has stopped.
            notifier.resolve_subject("grant-group-misconfigured", name).await;
        }
        if !admission_alerted {
            // A plan that built is the evidence: the planner found the configured
            // admission group in the desired state, so it is no longer missing.
            notifier.resolve_subject(ADMISSION_MISSING, name).await;
        }
        for c in &plan.conflicts {
            eprintln!("[sync/{name}] CONFLICT: {c}");
        }
        eprintln!(
            "[sync/{name}] plan: {} ops, {} conflicts, {} alerts (users desired={}, groups \
             desired={})",
            plan.ops.len(),
            plan.conflicts.len(),
            plan.alerts.len(),
            desired.users.len(),
            desired.groups.len(),
        );

        report_expiring_grants(cfg, shared, &current, notifier).await;

        if shared.dry_run {
            for op in &plan.ops {
                eprintln!(
                    "[sync/{name}] would apply: {}",
                    serde_json::to_string(op).unwrap_or_default()
                );
            }
            eprintln!("[sync/{name}] dry-run: not applying");
            return Ok(());
        }
        let report =
            self.dir.apply(&plan, &marker_index(&current)).await.context("applying plan")?;
        let tally = format!(
            "[sync/{name}] applied {} ops, {} failures",
            report.applied.len(),
            report.failures.len()
        );
        // A cycle that changed nothing is a heartbeat, and heartbeats stay on
        // the console: the file answers who was given an account and when, and a
        // line every interval saying nobody was is what would bury the answer.
        if report.applied.is_empty() && report.failures.is_empty() {
            eprintln!("{tally}");
        } else {
            audit(&tally);
            for change in &report.applied {
                audit(&format!("[sync/{name}] APPLY {change}"));
            }
        }
        for f in &report.failures {
            audit(&format!("[sync/{name}] APPLY-FAIL {f}"));
        }
        // A cycle that reads and plans perfectly and then cannot write is silent
        // everywhere else: it returns `Ok`, so it does not count as a discarded cycle
        // either. The usual cause is a delegation ACE that was never granted or has
        // been removed, which no amount of waiting fixes.
        if report.failures.is_empty() {
            notifier.resolve_subject("sync-apply-failing", name).await;
        } else {
            notifier
                .send(
                    Event::new(
                        "sync-apply-failing",
                        Severity::Error,
                        format!(
                            "the realm directory rejected {} of {} writes for source {name} this cycle",
                            report.failures.len(),
                            report.applied.len() + report.failures.len()
                        ),
                    )
                    .subject(name)
                    .detail(report.failures.join("\n")),
                )
                .await;
        }
        Ok(())
    }
}

/// What `--help` prints, and the one place the argument surface is written out.
///
/// A hand-rolled parser has no `--help` unless somebody writes one. The list
/// lives here rather than in `kerbridge-sync.8` because that page is
/// hand-written: it names `--help` and nothing else, precisely so that there is
/// no second copy of this to go stale.
const HELP: &str = "\
kerbridge-sync -- the KerBridge IdP-to-realm synchronization daemon

usage: kerbridge-sync [--config <dir>] [--test-notification]

  --config <dir>        the configuration set to read (default: /etc/kerbridge)
  --test-notification   send one test operator notification, then exit
  -h, --help            print this and exit

Mirrors the admitted cloud users into this realm. See kerbridge-sync(8).
";

/// `kerbridge-sync [--config <dir>] [--test-notification]`, or [`None`] when
/// `-h` or `--help` was asked for.
///
/// Hand-rolled rather than clap: three optional flags do not earn a dependency.
/// An unrecognized argument is refused rather than ignored -- a typo in
/// `--test-notifcation` must not start a service that then looks like it is
/// running normally. `--help` returns `None` rather than printing here, so that
/// the test covering this function does not write to the harness's stdout.
fn usage(args: &[String]) -> Result<Option<(PathBuf, bool)>> {
    let (mut dir, mut test_only) = (None, false);
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--config" => dir = Some(PathBuf::from(args.next().context("--config <dir>")?)),
            kerbridge_notify::TEST_NOTIFICATION_FLAG => test_only = true,
            other => bail!(
                "unexpected argument {other:?} -- usage: kerbridge-sync [--config <dir>] \
                 [--test-notification]. `kerbridge-sync --help` prints the whole set."
            ),
        }
    }
    Ok(Some((dir.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_DIR)), test_only)))
}

#[tokio::main]
async fn main() -> Result<()> {
    let Some((dir, test_only)) = usage(&std::env::args().skip(1).collect::<Vec<_>>())? else {
        print!("{HELP}");
        return Ok(());
    };
    let (mut shared, warnings) = Config::load(&dir)
        .with_context(|| format!("reading the configuration under {}", dir.display()))?;
    // Built before the IdP and the realm directory: it is what reports a deployment
    // that has no sync credential yet, and `--test-notification` must work on
    // exactly that deployment -- proving the channel is a step of installing,
    // not of running.
    let notifier = Arc::new(
        Notifier::from_config("sync", &shared.notify, &shared.realm)
            .context("configuring notification")?,
    );
    if test_only {
        return notifier.test_notification().await;
    }
    for warning in &warnings {
        eprintln!("[sync] warning: {warning}");
    }

    // Before the first cycle, and fatal if it cannot be opened: a deployment
    // that asked for a durable record of what was done to its realm directory must not
    // get a running service that silently keeps none. After
    // `--test-notification`, which is a step of installing and runs on a
    // deployment whose audit directory may not exist yet.
    let sink = AuditLog::open(shared.audit_log_file.as_deref()).context("opening the audit log")?;
    let trail = match sink.path() {
        Some(path) => format!("audit {}", path.display()),
        None => "no audit file".to_owned(),
    };
    let _ = AUDIT.set(sink);
    reopen_audit_on_sigusr1()?;

    // Moved out rather than borrowed from: each source's config belongs to the
    // context that owns its connection, and what is left in `shared` is exactly
    // the deployment-wide half every source is handed.
    let mut sources = Vec::with_capacity(shared.sources.len());
    for cfg in std::mem::take(&mut shared.sources) {
        sources.push(SourceSync::new(cfg, &shared, notifier.clone())?);
    }

    eprintln!(
        "[sync] starting; interval {}s, dry_run={}, {}, {trail}",
        shared.interval.as_secs(),
        shared.dry_run,
        listed(&sources),
    );
    for s in &sources {
        if matches!(s.source.credential_state(), CredentialState::Unknown) {
            eprintln!(
                "[sync/{}] no credential expiry stated: no advance warning is possible; relying \
                 on whatever notice the IdP itself sends",
                s.cfg.name()
            );
        }
    }

    loop {
        for source in &mut sources {
            source.tick(&shared, &notifier).await;
        }
        tokio::select! {
            _ = tokio::time::sleep(shared.interval) => {}
            _ = tokio::signal::ctrl_c() => {
                eprintln!("[sync] shutting down");
                return Ok(());
            }
        }
    }
}

/// The startup line's source list. A deployment mid-bootstrap has none, and says
/// so rather than printing an empty list that reads as a truncated message.
fn listed(sources: &[SourceSync]) -> String {
    if sources.is_empty() {
        return "no sources yet".to_owned();
    }
    let names: Vec<&str> = sources.iter().map(|s| s.cfg.name()).collect();
    format!("sources {}", names.join(", "))
}

/// Reopen the audit file whenever `SIGUSR1` arrives.
///
/// `logrotate` sends it from `postrotate`, after renaming the file aside; see
/// [`AuditLog::reopen`]. `SIGUSR1` rather than `SIGHUP`, which conventionally
/// means "reload configuration" and would promise something this does not do.
///
/// Tokio's handler is process-wide and hands the signal to this task whichever
/// thread it arrives on, so nothing here depends on the runtime's thread count.
/// Installing it is what makes the signal harmless: unhandled, `SIGUSR1` ends
/// the process -- and a mirror killed mid-cycle by the operator's own log
/// rotation is a worse failure than the one this exists to prevent.
fn reopen_audit_on_sigusr1() -> Result<()> {
    let mut usr1 = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
        .context("listening for SIGUSR1")?;
    tokio::spawn(async move {
        while usr1.recv().await.is_some() {
            let Some(sink) = AUDIT.get() else { continue };
            match (sink.reopen(), sink.path()) {
                // Through `audit`, so the successor's first line says the trail
                // continues here and the console copy says the rotation was
                // seen. A failure is the console's alone: it is a diagnosis, and
                // the file it would go in is the one we could not open.
                (Ok(()), Some(path)) => audit(&format!("[sync] REOPEN {}", path.display())),
                (Ok(()), None) => eprintln!("[sync] SIGUSR1: no audit file to reopen"),
                (Err(e), _) => {
                    eprintln!("[sync] SIGUSR1: {e:#} -- still writing to the old file");
                }
            }
        }
    });
    Ok(())
}

/// Count a cycle that produced nothing, and raise once the run of them is long
/// enough to be an outage rather than a blip.
///
/// Every path that discards a cycle comes through here, which is the whole point
/// of it existing. A counter on the incomplete-read arm alone would miss the
/// failures an operator most needs to hear about -- no route to the IdP, a rejected
/// LDAP bind, a rotated secret -- which return `Err` straight past that arm and
/// would repeat forever behind nothing but a log line.
///
/// `why` is deliberately not part of the subject. It stays the source alone so
/// this reads as one standing condition per source, and a cause that flaps
/// between two error strings cannot defeat the rate limit by looking like a new
/// problem each time; the first event still names the cause, because the message
/// is free to vary.
async fn cycle_failed(source: &mut SourceSync, notifier: &Notifier, why: String) {
    let name = source.cfg.name().to_owned();
    source.consecutive_failures += 1;
    eprintln!("[sync/{name}] {why}; failures={}", source.consecutive_failures);
    // The crossing itself, once: a discarded cycle changes nothing and is not an
    // audit line, but a run of them long enough to be an outage dates a stretch
    // during which this source stopped mirroring. Paired with `RESUMED` -- a
    // beginning with no end reads as an outage still running.
    if source.consecutive_failures == FAIL_THRESHOLD {
        audit(&format!("[sync/{name}] STALLED after {FAIL_THRESHOLD} discarded cycles: {why}"));
    }
    if source.consecutive_failures >= FAIL_THRESHOLD {
        notifier
            .send(
                Event::new(
                    "sync-cycle-failing",
                    Severity::Error,
                    format!(
                        "{} cycles discarded in a row for source {name}: {why}",
                        source.consecutive_failures
                    ),
                )
                .subject(&name),
            )
            .await;
    }
}

/// The credential-expiry surface. The value is an operator assertion, so a
/// missing one is silent (already logged once at startup) rather than alarming.
///
/// A countdown rather than a standing condition: an expiry on the 24 h repeat
/// interval would send an event a day for a month, which is the flood the
/// rate limit exists to prevent. It is delivered as it crosses 30, 14, 7, 3 and
/// 1 days remaining, and is silent between those.
async fn report_credential(
    source: &dyn DirectorySource,
    name: &str,
    shared: &Config,
    notifier: &Notifier,
) {
    let subject = source.credential_subject();
    let expiring = |days: i64, severity| {
        Event::new(
            "sync-credential-expiring",
            severity,
            format!("sync credential for source {name} expires in {days} days"),
        )
        .subject(&subject)
        .countdown(days)
    };
    let days = match source.credential_state() {
        CredentialState::Measured { days } | CredentialState::Asserted { days } => days,
        CredentialState::Unknown => return,
    };
    match days {
        days if days < 7 => notifier.send(expiring(days, Severity::Error)).await,
        days if days <= shared.warn_before_days => {
            notifier.send(expiring(days, Severity::Warning)).await;
        }
        days => {
            eprintln!("[sync/{name}] sync credential: {days} days remaining");
            // Rotated: the deadline moved back out of every warning band, so the
            // condition an operator was told about is over. The countdown itself
            // re-arms on its own, but the open problem has to be closed by hand
            // or it stands until the *next* credential expires.
            notifier.resolve_subject("sync-credential-expiring", &subject).await;
        }
    }
}

/// One aggregate for every device grant coming up on its deadline.
///
/// Aggregate rather than per-device on purpose. A problem per device is fine for
/// three build machines and unusable for a laptop fleet, and the per-user channel
/// already exists -- it is the tray, on the machine, in front of the person who
/// has to click the button. This one is for the operator, who wants to know that
/// *some* number of devices are about to start costing tickets.
///
/// Sync raises it because sync is the only component that reads every object on
/// a schedule; the broker is request-driven and would only ever see the device
/// that just asked. The deadline compared against is the *effective* one, so
/// lowering `main.toml`'s `device_grant_days` shows up here as well as on the
/// exchange path.
///
/// Off unless `sync.toml` names a threshold, which also keeps machine labels out
/// of whatever channel the operator wired up until they ask.
async fn report_expiring_grants(
    cfg: &SourceConfig,
    shared: &Config,
    current: &Current,
    notifier: &Notifier,
) {
    let name = cfg.name();
    let Some(within_days) = shared.device_grant_notify_days else {
        return;
    };
    let now = now_unix();
    let horizon = now + u64::from(within_days) * 86_400;
    let expiring = current
        .users
        .iter()
        .flat_map(|(_, u)| u.markers.iter())
        .filter_map(|m| DeviceGrant::decode(m).ok())
        .filter(|g| g.effective_end(shared.device_grant_days) <= horizon)
        .count();
    if expiring == 0 {
        notifier.resolve_subject("device-grants-expiring", name).await;
        return;
    }
    notifier
        .send(
            Event::new(
                "device-grants-expiring",
                Severity::Warning,
                format!(
                    "{expiring} device grants under source {name} expire within {within_days} days"
                ),
            )
            .subject(name)
            .detail("`kbmanage device list` shows which, and who has to sign in".to_owned()),
        )
        .await;
}

/// The configured device-grant group and the marker in the realm directory disagree.
///
/// `Error`, not a warning, and in both directions: one leaves grants working on
/// machines after the operator believes the feature is off, the other leaves no
/// machine able to authorize at all. Neither is visible from the broker, which
/// sees exactly one marked group and nothing wrong.
fn grant_group_wrong(source: &str, why: &str) -> Event {
    Event::new("grant-group-misconfigured", Severity::Error, why.to_owned()).subject(source)
}

/// Sync's one reading of the admission state: the configured group is absent
/// from the desired state, or expands to nobody. A marker found on any other
/// group is repointed rather than reported, because the file binds by object id
/// and so which group admits is never in doubt.
const ADMISSION_MISSING: &str = "admission-group-missing";

/// The stamp on retire and quarantine markers, which `kbmanage` and the broker
/// read back through the same module.
fn now_rfc3339() -> String {
    rfc3339(now_unix() as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An unrecognized argument is refused rather than ignored.
    #[test]
    fn the_arguments_are_a_config_directory_and_the_test_flag() {
        let args = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(usage(&args(&[])).unwrap(), Some((PathBuf::from(DEFAULT_CONFIG_DIR), false)));
        assert_eq!(
            usage(&args(&["--config", "/tmp/set", "--test-notification"])).unwrap(),
            Some((PathBuf::from("/tmp/set"), true))
        );
        // `--help` parses and asks for nothing to be run.
        for help in [vec!["-h"], vec!["--help"]] {
            assert_eq!(usage(&args(&help)).unwrap(), None, "{help:?} is answered, not refused");
        }
        assert!(HELP.contains("--config") && HELP.contains("--test-notification"));
        for bad in [vec!["--test-notifcation"], vec!["-help"], vec!["--config"]] {
            assert!(usage(&args(&bad)).is_err(), "{bad:?}");
        }
    }
}
