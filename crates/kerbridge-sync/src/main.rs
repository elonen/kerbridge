//! `kerbridge-sync` -- cloud directory synchronization.
//!
//! Reads configured users and groups from Microsoft Graph and reconciles them
//! into dedicated Samba AD OUs over delegated LDAPS, stamping each object with
//! its [`ExternalIdentity`](kerbridge_core::ExternalIdentity). Separate from the
//! broker so Graph credentials and directory write privileges stay out of the
//! interactive authentication path.
//!
//! Samba AD is the single source of truth for external-to-realm mappings; this
//! service persists only sync cursors and reconciliation state.
//!
//! One process serves every source the config set lists, one after another. A
//! cycle per source: acquire an app-only token, read the users and groups delta
//! streams into a [`graph::Shadow`], turn that into a desired state, diff it
//! against the current directory with the [`planner`], and apply the plan over
//! delegated LDAPS as that source's own account. A read that does not assert
//! `complete read` is discarded rather than planned from, so it can never
//! delete or disable anything.
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
mod graph;
mod graphclient;
mod planner;

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use kerbridge_core::audit::AuditLog;
use kerbridge_core::grant::DeviceGrant;
use kerbridge_core::time::{now_unix, rfc3339};
use kerbridge_idp::entra::GroupBinding;
use kerbridge_notify::{Event, Notifier, Severity};

use crate::config::{Config, SourceConfig};
use crate::directory::{Directory, marker_index};
use crate::graph::{Shadow, build_desired};
use crate::graphclient::{GraphClient, GraphReader, StreamResult, TokenError};
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
/// disabled or emptied, and the writes the directory refused. Anything else is a
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

#[derive(Default)]
struct SyncState {
    shadow: Shadow,
    users_cursor: Option<String>,
    groups_cursor: Option<String>,
    /// What a display-name binding last resolved to. A group the file pinned by
    /// id is never in here: it needs no lookup, so it needs no cache.
    admission_oid: Option<String>,
    grant_oid: Option<String>,
    consecutive_failures: u32,
}

/// One source's whole world: the account it binds as, the OU it owns, the tenant
/// it reads, and the cursors it carries between cycles.
///
/// The directory client is owned here rather than shared. With one process
/// serving several sources, "apply this source's plan over that source's
/// connection" would retire every object the bind identity did not recognize,
/// and owning it is what makes the sentence unspellable.
struct SourceSync {
    cfg: SourceConfig,
    dir: Directory,
    state: SyncState,
}

impl SourceSync {
    fn new(cfg: SourceConfig, shared: &Config) -> Result<Self> {
        let dir = Directory::new(
            shared.ldap_url.clone(),
            shared.base_dn.clone(),
            cfg.idp_ou.clone(),
            cfg.bind_dn.clone(),
            cfg.bind_password.clone(),
            &shared.ldap_ca_file,
            LDAP_TIMEOUT,
        )
        .with_context(|| format!("configuring the directory client for {}", cfg.name()))?;
        Ok(Self { cfg, dir, state: SyncState::default() })
    }

    /// The admission group's object id: the one the file pinned, or the one its
    /// display name resolved to and is remembered as.
    ///
    /// Which of the two it is comes off the binding rather than off the cache,
    /// so a pinned id is never looked up -- the pin exists precisely to stop a
    /// renamed or recreated group from resolving to a different one.
    async fn admission_oid(&mut self, graph: &impl GraphReader, token: &str) -> Result<String> {
        let name = match &self.cfg.admission_group {
            GroupBinding::Id(id) => return Ok(id.clone()),
            GroupBinding::Name(name) => name.clone(),
        };
        if let Some(g) = &self.state.admission_oid {
            return Ok(g.clone());
        }
        let g = graph.resolve_group(token, &name, "admission_group_id").await?;
        eprintln!("[sync/{}] resolved admission group {name:?} -> {g}", self.cfg.name());
        self.state.admission_oid = Some(g.clone());
        Ok(g)
    }

    /// The device-grant group's object id, or `None` when this source names no
    /// such group and can therefore create no grants.
    ///
    /// Unlike the admission group, a name that resolves to nothing is not fatal:
    /// it stops device grants and leaves everything else synchronizing, where
    /// failing the cycle would make an unrelated typo a full outage.
    async fn grant_oid(&mut self, graph: &impl GraphReader, token: &str) -> Option<String> {
        let name = match self.cfg.grant_group.as_ref()? {
            GroupBinding::Id(id) => return Some(id.clone()),
            GroupBinding::Name(name) => name.clone(),
        };
        if self.state.grant_oid.is_none() {
            match graph.resolve_group(token, &name, "device_grant_group_id").await {
                Ok(g) => {
                    eprintln!(
                        "[sync/{}] resolved device-grant group {name:?} -> {g}",
                        self.cfg.name()
                    );
                    self.state.grant_oid = Some(g);
                }
                Err(e) => eprintln!(
                    "[sync/{}] ALERT: device-grant group {name:?} unresolved: {e:#}",
                    self.cfg.name()
                ),
            }
        }
        self.state.grant_oid.clone()
    }

    /// This source's turn. Never returns `Err`: one source's failure is counted
    /// against that source and the next one still runs.
    async fn tick(&mut self, shared: &Config, notifier: &Notifier) {
        let name = self.cfg.name().to_owned();
        let credential = match self.cfg.credential() {
            Ok(Some(secret)) => {
                notifier.resolve_subject("sync-not-configured", &name).await;
                secret
            }
            Ok(None) => {
                notifier
                    .send(
                        Event::new(
                            "sync-not-configured",
                            Severity::Warning,
                            format!(
                                "no Graph credential in {}: source {name} is idle until one \
                                 appears",
                                self.cfg.credential_file.display()
                            ),
                        )
                        .subject(&name),
                    )
                    .await;
                return;
            }
            Err(e) => {
                cycle_failed(self, notifier, format!("credential unreadable: {e:#}")).await;
                return;
            }
        };
        // Rebuilt every cycle rather than cached, so a rotated secret is picked
        // up by the next cycle with nothing to restart. The connection pool it
        // drops matters within a cycle, not across one.
        let graph = match GraphClient::new(
            self.cfg.tenant_id.clone(),
            self.cfg.graph_client_id.clone(),
            credential,
        ) {
            Ok(graph) => graph,
            Err(e) => {
                cycle_failed(self, notifier, format!("Graph client: {e:#}")).await;
                return;
            }
        };
        if let Err(e) = self.run_cycle(shared, &graph, notifier).await {
            cycle_failed(self, notifier, format!("cycle error: {e:#}")).await;
        }
    }

    /// One read/plan/apply cycle. Returns `Err` only on an infrastructure failure (LDAP or
    /// Graph transport), which the caller counts through [`cycle_failed`]; policy outcomes
    /// such as a frozen admission group or a discarded partial read are handled in-band and
    /// count as a cycle that reached a conclusion.
    async fn run_cycle(
        &mut self,
        shared: &Config,
        graph: &impl GraphReader,
        notifier: &Notifier,
    ) -> Result<()> {
        let name = self.cfg.name().to_owned();
        let credential_subject = credential_subject(&self.cfg);
        let token = match graph.acquire_token().await {
            Ok(token) => {
                // A token came back, so the credential the operator was told
                // about has been rotated or was never the problem.
                notifier.resolve_subject("graph-credential-expired", &credential_subject).await;
                token
            }
            Err(e @ (TokenError::Expired(_) | TokenError::Invalid(_))) => {
                notifier
                    .send(
                        Event::new("graph-credential-expired", Severity::Error, e.to_string())
                            .subject(&credential_subject),
                    )
                    .await;
                return Ok(());
            }
            Err(TokenError::Other(e)) => return Err(e.context("acquiring Graph token")),
        };

        let admission_oid = self.admission_oid(graph, &token).await?;
        let grant_oid = self.grant_oid(graph, &token).await;

        // A resync (410) or corrupt cursor (400) on either stream forces a fresh full
        // read of both this cycle, from an empty shadow. At most one retry.
        let mut users_cursor = self.state.users_cursor.clone();
        let mut groups_cursor = self.state.groups_cursor.clone();
        for attempt in 0..2 {
            let users = outcome(graph.read_users(&token, users_cursor.as_deref()).await?);
            let groups = outcome(graph.read_groups(&token, groups_cursor.as_deref()).await?);
            use Outcome::*;
            // Read before the match consumes them: the discard arm has to name
            // which cause it met.
            let stalled = matches!(users, Stalled) || matches!(groups, Stalled);
            match (users, groups) {
                (Ready(uv, ucur), Ready(gv, gcur)) => {
                    self.state.shadow.apply_users(uv);
                    self.state.shadow.apply_groups(gv);
                    self.state.users_cursor = ucur;
                    self.state.groups_cursor = gcur;
                    self.reconcile(shared, &admission_oid, grant_oid.as_deref(), notifier).await?;
                    // Cleared once the whole cycle has concluded, not on the read
                    // above. A cycle that reads Entra perfectly and then cannot write
                    // to the directory has not succeeded, and clearing it there makes
                    // a standing LDAP outage alternate 1, 0, 1, 0 -- never reaching
                    // the threshold, however long it lasts.
                    if self.state.consecutive_failures >= FAIL_THRESHOLD {
                        audit(&format!(
                            "[sync/{name}] RESUMED after {} discarded cycles",
                            self.state.consecutive_failures
                        ));
                    }
                    self.state.consecutive_failures = 0;
                    notifier.resolve_subject("sync-cycle-failing", &name).await;
                    return Ok(());
                }
                (Corrupt, _) | (_, Corrupt) if attempt == 0 => {
                    notifier
                        .send(
                            Event::new(
                                "sync-cursor-corrupt",
                                Severity::Warning,
                                format!(
                                    "a stored delta cursor for source {name} was rejected (400); \
                                     resyncing from a fresh read"
                                ),
                            )
                            .subject(&name)
                            // Already healed by the time it is reported -- the resync
                            // is happening. Listing it as an open problem would leave
                            // an entry nothing could ever clear.
                            .incident(),
                        )
                        .await;
                    self.state.shadow = Shadow::default();
                    users_cursor = None;
                    groups_cursor = None;
                }
                (Resync, _) | (_, Resync) if attempt == 0 => {
                    eprintln!("[sync/{name}] delta cursor expired (410); full resync");
                    self.state.shadow = Shadow::default();
                    users_cursor = None;
                    groups_cursor = None;
                }
                _ => {
                    let why = if stalled {
                        "cycle discarded (stalled read): no page arrived from the cloud IdP for \
                         long enough to call the read abandoned"
                    } else {
                        "cycle discarded: a delta cursor was still refused after a full resync"
                    };
                    cycle_failed(self, notifier, why.to_owned()).await;
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    /// Build desired from the shadow, diff against current, and apply.
    async fn reconcile(
        &self,
        shared: &Config,
        admission_oid: &str,
        grant_oid: Option<&str>,
        notifier: &Notifier,
    ) -> Result<()> {
        let cfg = &self.cfg;
        let name = cfg.name();
        // The device-grant group joins the closure roots the way an allowlist entry
        // does, so it synchronizes whether or not the operator nested it inside the
        // admission group. The consequence is the allowlist's own, and is documented
        // with it: someone held only by this group gets a directory object and no
        // admission, so no ticket -- the two groups are additive, never alternatives.
        let mut roots = cfg.allowlist.clone();
        roots.extend(grant_oid.map(str::to_owned));
        let (mut desired, refused) = build_desired(&self.state.shadow, true, admission_oid, &roots);
        desired.grant_subject = grant_oid.map(str::to_owned);
        // The syncable rule narrows the admission-group closure, and silence about that is the
        // failure an operator cannot debug: they nominated a group or a person, nothing
        // appeared, and the plan they read is simply smaller than they expected. Logged
        // every cycle rather than on change, because this is the state of the tenant and
        // there is no cheap way to know which cycle the operator is reading.
        for why in &refused {
            eprintln!("[sync/{name}] refused: {why}");
        }
        let current =
            self.dir.read_current(&cfg.source).await.context("reading current directory state")?;

        let now = now_rfc3339();
        let identity = cfg.identity();
        let ctx = PlanCtx {
            idp_ou: &cfg.idp_ou,
            upn_suffix: &shared.upn_suffix,
            group_suffix: &cfg.group_suffix,
            now: &now,
            sam_source: shared.sam_source,
            automatic_sam_renames: shared.automatic_sam_renames,
            admission_bound_by_id: matches!(cfg.admission_group, GroupBinding::Id(_)),
            identity: &identity,
        };
        let plan = match plan_sync(&desired, &current, &ctx) {
            Ok(p) => p,
            Err(PlanError::PartialRead) => {
                eprintln!(
                    "[sync/{name}] planner refused a partial read (should not happen on a full \
                     cycle)"
                );
                return Ok(());
            }
            Err(PlanError::AdmissionAmbiguous(why)) => {
                admission_state(notifier, name, Some((ADMISSION_AMBIGUOUS, &why))).await;
                return Ok(());
            }
            Err(PlanError::AdmissionMisconfigured(why)) => {
                admission_state(notifier, name, Some((ADMISSION_MISCONFIGURED, &why))).await;
                return Ok(());
            }
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
                    // Every alert of this kind is the same reading: the configured
                    // admission group is not in the desired state, or expands to
                    // nobody. The other two readings never reach a built plan --
                    // they are `PlanError`s above.
                    admission_state(notifier, name, Some((ADMISSION_MISSING, &a.message))).await;
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
            // The planner accepted the admission group and nothing alerted on it, so
            // none of the three readings holds.
            admission_state(notifier, name, None).await;
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

        report_credential(cfg, shared, notifier).await;
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
                            "the directory rejected {} of {} writes for source {name} this cycle",
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

/// Every operator problem this component raises is keyed by the source it
/// belongs to, because with one process serving several that is the only thing
/// making two instances of one condition two problems -- and the only key a
/// later cycle can compute again in order to clear exactly what it disproved.
///
/// The credential conditions carry the app registration as well: rotating to a
/// different one is a new problem rather than the same standing condition
/// reworded.
fn credential_subject(cfg: &SourceConfig) -> String {
    format!("{}/{}", cfg.name(), cfg.graph_client_id)
}

/// What `--help` prints, and the one place the argument surface is written out.
///
/// A hand-rolled parser has no `--help` unless somebody writes one. The list
/// lives here rather than in `kerbridge-sync.8` because that page is
/// hand-written: it names `--help` and nothing else, precisely so that there is
/// no second copy of this to go stale.
const HELP: &str = "\
kerbridge-sync -- the KerBridge directory synchronisation daemon

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
    // Built before the tenant and the directory: it is what reports a deployment
    // that has no Graph credential yet, and `--test-notification` must work on
    // exactly that deployment -- proving the channel is a step of installing,
    // not of running.
    let notifier = Notifier::from_config("sync", &shared.notify, &shared.realm)
        .context("configuring notification")?;
    if test_only {
        return notifier.test_notification().await;
    }
    for warning in &warnings {
        eprintln!("[sync] warning: {warning}");
    }

    // Before the first cycle, and fatal if it cannot be opened: a deployment
    // that asked for a durable record of what was done to its directory must not
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
        sources.push(SourceSync::new(cfg, &shared)?);
    }

    eprintln!(
        "[sync] starting; interval {}s, dry_run={}, {}, {trail}",
        shared.interval.as_secs(),
        shared.dry_run,
        listed(&sources),
    );
    for s in &sources {
        if s.cfg.credential_expires.is_none() {
            eprintln!(
                "[sync/{}] no credential expiry stated: no advance warning is possible; relying \
                 on the tenant's owner email",
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
/// failures an operator most needs to hear about -- no route to Entra, a rejected
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
    source.state.consecutive_failures += 1;
    eprintln!("[sync/{name}] {why}; failures={}", source.state.consecutive_failures);
    // The crossing itself, once: a discarded cycle changes nothing and is not an
    // audit line, but a run of them long enough to be an outage dates a stretch
    // during which this source stopped mirroring. Paired with `RESUMED` -- a
    // beginning with no end reads as an outage still running.
    if source.state.consecutive_failures == FAIL_THRESHOLD {
        audit(&format!("[sync/{name}] STALLED after {FAIL_THRESHOLD} discarded cycles: {why}"));
    }
    if source.state.consecutive_failures >= FAIL_THRESHOLD {
        notifier
            .send(
                Event::new(
                    "sync-cycle-failing",
                    Severity::Error,
                    format!(
                        "{} cycles discarded in a row for source {name}: {why}",
                        source.state.consecutive_failures
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
async fn report_credential(cfg: &SourceConfig, shared: &Config, notifier: &Notifier) {
    let subject = credential_subject(cfg);
    let expiring = |days: i64, severity| {
        Event::new(
            "graph-credential-expiring",
            severity,
            format!("Graph credential for source {} expires in {days} days", cfg.name()),
        )
        .subject(&subject)
        .countdown(days)
    };
    match cfg.credential_days_remaining(now_unix()) {
        None => {}
        Some(days) if days < 7 => notifier.send(expiring(days, Severity::Error)).await,
        Some(days) if days <= shared.warn_before_days => {
            notifier.send(expiring(days, Severity::Warning)).await;
        }
        Some(days) => {
            eprintln!("[sync/{}] Graph credential: {days} days remaining", cfg.name());
            // Rotated: the deadline moved back out of every warning band, so the
            // condition an operator was told about is over. The countdown itself
            // re-arms on its own, but the open problem has to be closed by hand
            // or it stands until the *next* credential expires.
            notifier.resolve_subject("graph-credential-expiring", &subject).await;
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

/// The configured device-grant group and the directory's marker disagree.
///
/// `Error`, not a warning, and in both directions: one leaves grants working on
/// machines after the operator believes the feature is off, the other leaves no
/// machine able to authorize at all. Neither is visible from the broker, which
/// sees exactly one marked group and nothing wrong.
fn grant_group_wrong(source: &str, why: &str) -> Event {
    Event::new("grant-group-misconfigured", Severity::Error, why.to_owned()).subject(source)
}

const ADMISSION_MISSING: &str = "admission-group-missing";
const ADMISSION_AMBIGUOUS: &str = "admission-group-ambiguous";
const ADMISSION_MISCONFIGURED: &str = "admission-group-misconfigured";

/// The three readings of the admission role-marker state -- no group carries it,
/// two or more do, one does but not the configured group.
const ADMISSION_PROBLEMS: [&str; 3] =
    [ADMISSION_MISSING, ADMISSION_AMBIGUOUS, ADMISSION_MISCONFIGURED];

/// Raise one reading of this source's admission marker state and clear the other
/// two; `None` clears all three.
///
/// The state changes arity -- a source with no marked group can acquire two
/// without ever being healthy in between -- so a cycle that concludes one
/// reading must say what the state is *not* as well, or the earlier one stays
/// open for as long as the deployment lives. Call only where the cycle actually
/// learned the state; a read that never got that far leaves all three alone.
async fn admission_state(notifier: &Notifier, source: &str, open: Option<(&'static str, &str)>) {
    if let Some((problem, why)) = open {
        notifier.send(Event::new(problem, Severity::Error, why.to_owned()).subject(source)).await;
    }
    for problem in admission_siblings(open.map(|(p, _)| p)) {
        notifier.resolve_subject(problem, source).await;
    }
}

/// The readings `open` is not -- exactly what a cycle that concluded `open` has
/// disproved, and `None` disproves all three.
fn admission_siblings(open: Option<&'static str>) -> impl Iterator<Item = &'static str> {
    ADMISSION_PROBLEMS.into_iter().filter(move |p| Some(*p) != open)
}

/// One stream's outcome, flattened so `run_cycle` can match users and groups
/// together regardless of element type.
enum Outcome<T> {
    Ready(Vec<T>, Option<String>),
    Resync,
    Corrupt,
    Stalled,
}

fn outcome<T>(r: StreamResult<T>) -> Outcome<T> {
    match r {
        StreamResult::Complete { items, delta_link } => Outcome::Ready(items, delta_link),
        StreamResult::Resync => Outcome::Resync,
        StreamResult::CursorCorrupt => Outcome::Corrupt,
        StreamResult::Stalled => Outcome::Stalled,
    }
}

/// The stamp on retire and quarantine markers, which `kbmanage` and the broker
/// read back through the same module.
fn now_rfc3339() -> String {
    rfc3339(now_unix() as u32)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::graph::{RawGroup, RawUser};

    /// Whichever reading a cycle concludes, it clears the other two. The state
    /// changes arity -- no marked group becomes two -- so a raise that cleared
    /// only itself would leave the earlier reading open forever.
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

    #[test]
    fn every_admission_reading_clears_the_other_two() {
        for open in ADMISSION_PROBLEMS {
            let cleared: Vec<_> = admission_siblings(Some(open)).collect();
            assert!(!cleared.contains(&open), "{open} cleared the problem it just raised");
            assert_eq!(cleared.len(), ADMISSION_PROBLEMS.len() - 1, "{open} left a sibling open");
        }
        assert_eq!(admission_siblings(None).count(), ADMISSION_PROBLEMS.len());
    }

    const STORED_CURSOR: &str = "https://graph.microsoft.com/v1.0/users/delta?$deltatoken=stored";
    const STALE_USER: &str = "user-from-the-last-cycle";
    const FRESH_USER: &str = "user-from-the-retry";
    const USERS_RETRY_CURSOR: &str = "users-cursor-from-the-retry";
    const GROUPS_RETRY_CURSOR: &str = "groups-cursor-from-the-retry";

    /// A reader that refuses the stored cursor once, then reads cleanly.
    ///
    /// It records the cursor each stream was handed, which is the only place the
    /// discard is observable: a cursor that was not cleared arrives again.
    #[derive(Default)]
    struct CorruptThenComplete {
        users_seen: Mutex<Vec<Option<String>>>,
        groups_seen: Mutex<Vec<Option<String>>>,
    }

    impl GraphReader for CorruptThenComplete {
        async fn acquire_token(&self) -> Result<String, TokenError> {
            Ok("bearer".to_owned())
        }

        async fn read_users(
            &self,
            _token: &str,
            cursor: Option<&str>,
        ) -> Result<StreamResult<RawUser>> {
            let mut seen = self.users_seen.lock().unwrap();
            seen.push(cursor.map(str::to_owned));
            Ok(if seen.len() == 1 {
                StreamResult::CursorCorrupt
            } else {
                StreamResult::Complete {
                    items: vec![raw(FRESH_USER)],
                    delta_link: Some(USERS_RETRY_CURSOR.to_owned()),
                }
            })
        }

        /// Never corrupt: the groups cursor has to be discarded because the
        /// *users* one was, and a stream that failed too could not show that.
        ///
        /// A different link per attempt, so the cursor left behind names the
        /// read it came from.
        async fn read_groups(
            &self,
            _token: &str,
            cursor: Option<&str>,
        ) -> Result<StreamResult<RawGroup>> {
            let mut seen = self.groups_seen.lock().unwrap();
            seen.push(cursor.map(str::to_owned));
            let delta_link = match seen.len() {
                1 => "groups-cursor-from-the-discarded-attempt",
                _ => GROUPS_RETRY_CURSOR,
            };
            Ok(StreamResult::Complete {
                items: Vec::new(),
                delta_link: Some(delta_link.to_owned()),
            })
        }

        async fn resolve_group(&self, _t: &str, _name: &str, _setting: &str) -> Result<String> {
            Ok("admission-group-oid".to_owned())
        }
    }

    fn raw<T: serde::de::DeserializeOwned>(id: &str) -> T {
        serde_json::from_value(serde_json::json!({ "id": id, "displayName": id })).unwrap()
    }

    /// A loopback webhook keeping every body posted to it, so "once" is a count.
    async fn receiver() -> (String, Arc<Mutex<Vec<String>>>, tokio::task::JoinHandle<()>) {
        let posted: Arc<Mutex<Vec<String>>> = Arc::default();
        let captured = posted.clone();
        let app = axum::Router::new().route(
            "/hook",
            axum::routing::post(move |body: String| {
                let captured = captured.clone();
                async move {
                    captured.lock().unwrap().push(body);
                    axum::http::StatusCode::OK
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/hook", listener.local_addr().unwrap());
        let served = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (url, posted, served)
    }

    /// A corrupt cursor on one stream discards both -- including the stream that
    /// answered normally -- and the shadow they patched.
    ///
    /// The `Ready` arm sets all of that before it calls `reconcile`, so the read
    /// half is observable with no directory behind it. Nothing listens on the
    /// LDAP port here, which is what confines this to the read half.
    #[tokio::test]
    async fn a_corrupt_cursor_empties_the_shadow_resyncs_both_streams_and_reports_once() {
        let dir = std::env::temp_dir().join(format!("kb-sync-corrupt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (url, posted, _served) = receiver().await;
        let url_file = dir.join("notify_url");
        std::fs::write(&url_file, &url).unwrap();
        std::fs::set_permissions(&url_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let notifier = Notifier::from_config(
            "sync",
            &kerbridge_core::config::Notify {
                url_file: Some(url_file),
                insecure_host: Some("127.0.0.1".to_owned()),
                state_dir: Some(dir.clone()),
                ..Default::default()
            },
            "EXAMPLE.SITE",
        )
        .unwrap();

        let shared = Config {
            interval: Duration::from_secs(300),
            dry_run: false,
            sam_source: crate::planner::SamSource::default(),
            automatic_sam_renames: true,
            device_grant_days: 30,
            device_grant_notify_days: None,
            warn_before_days: 30,
            realm: "EXAMPLE.SITE".to_owned(),
            notify: kerbridge_core::config::Notify::default(),
            ldap_url: "ldaps://127.0.0.1:1".to_owned(),
            base_dn: "DC=example,DC=site".to_owned(),
            upn_suffix: "example.site".to_owned(),
            // Parsed by `Directory::new` and never used: the bind is refused
            // before any certificate is judged.
            ldap_ca_file: PathBuf::from(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../kerbridge-core/testdata/test-ca.pem"
            )),
            audit_log_file: None,
            sources: Vec::new(),
        };
        let mut sync = SourceSync::new(SourceConfig::for_test(), &shared).unwrap();
        sync.state.shadow.apply_users(vec![raw(STALE_USER)]);
        sync.state.shadow.apply_groups(vec![raw("group-from-the-last-cycle")]);
        sync.state.users_cursor = Some(STORED_CURSOR.to_owned());
        sync.state.groups_cursor = Some(STORED_CURSOR.to_owned());

        let graph = CorruptThenComplete::default();
        let stopped_at_ldap = sync.run_cycle(&shared, &graph, &notifier).await;
        assert!(stopped_at_ldap.is_err(), "the retry did not reach the directory");

        let users: Vec<&str> = sync.state.shadow.users.keys().map(String::as_str).collect();
        assert_eq!(users, [FRESH_USER], "the shadow kept what the corrupt cursor patched");
        assert!(sync.state.shadow.groups.is_empty(), "a group survived the reset");

        let stored = || Some(STORED_CURSOR.to_owned());
        assert_eq!(*graph.users_seen.lock().unwrap(), [stored(), None], "users cursor");
        assert_eq!(*graph.groups_seen.lock().unwrap(), [stored(), None], "groups cursor");
        assert_eq!(sync.state.users_cursor.as_deref(), Some(USERS_RETRY_CURSOR));
        assert_eq!(sync.state.groups_cursor.as_deref(), Some(GROUPS_RETRY_CURSOR));

        let posted = posted.lock().unwrap();
        let announced = posted.iter().filter(|b| b.contains("sync-cursor-corrupt")).count();
        assert_eq!(announced, 1, "announced {announced} times: {posted:?}");
        // Recorded as healed rather than open: an open problem the next cycle
        // could never clear is one an operator would have to clear by hand.
        let state: Vec<String> = std::fs::read_dir(dir.join("sync"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        let named = |class: &str| {
            let prefix = format!("{class}-sync-cursor-corrupt");
            state.iter().any(|n| n.starts_with(&prefix))
        };
        assert!(named("recent"), "the incident was not recorded: {state:?}");
        assert!(!named("problem"), "the incident was listed as an open problem: {state:?}");

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
