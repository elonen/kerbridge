//! `issuerd` -- the privileged local ticket issuer.
//!
//! Runs inside the realm container alongside Samba, because issuance needs
//! local access to the Samba databases and is effectively KDC-administrator
//! authority. Listens on a Unix socket only; there is no TCP listener, so it
//! cannot be exposed as a network service by a configuration mistake.
//!
//! Per request: resolve a SID to one enabled, synchronized user, export that
//! account's existing key to a request-scoped tmpfs keytab, `kinit -k -r`,
//! validate that the resulting ccache holds a TGT for exactly that account, and
//! destroy the temporary material.
//!
//! Contract: `DESIGN.md` @ Ticket issuer, @ Ticket policy.
//! Cleanup and failure-path evidence: research spike `samba-tgt-issuance`
//! @ Security analysis.

// The peer-credential and name lookups that would otherwise need FFI go through
// `nix`'s safe wrappers instead.
#![forbid(unsafe_code)]

mod ccache;
mod grant;
mod identity;
mod issue;
mod peer;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use nix::sys::signal::{SigSet, Signal};

use issue::Config;
use kerbridge_core::audit::AuditLog;
use kerbridge_core::config::DEFAULT_CONFIG_DIR;
use kerbridge_core::issuer::{self as wire, Request, Response};
use kerbridge_core::time::{now_unix, rfc3339};

/// A peer that connects and then says nothing holds a thread and a slot. Both
/// halves are bounded: the request is one small frame and the reply is written
/// straight after it.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// The durable half of what [`audit`] writes. A process-wide output like
/// [`log`], and set once before the listener exists, so the request path is not
/// asked to carry a logger through three call layers to reach two call sites.
static AUDIT: OnceLock<AuditLog> = OnceLock::new();

fn log(msg: &str) {
    println!("{} [issuerd] {msg}", rfc3339(now_unix() as u32));
}

/// A line that is also the record: a ticket issued, a grant written or removed.
/// Anything else is [`log`], which the console keeps and the file does not.
fn audit(msg: &str) {
    log(msg);
    if let Some(sink) = AUDIT.get() {
        sink.append(&format!("[issuerd] {msg}"));
    }
}

/// What `--help` prints, and the one place the argument surface is written out.
///
/// A hand-rolled parser has no `--help` unless somebody writes one. The list
/// lives here rather than in `issuerd.8` because that page is
/// hand-written: it names `--help` and nothing else, precisely so that there is
/// no second copy of this to go stale.
const HELP: &str = "\
issuerd -- the KerBridge issuer daemon

usage: issuerd [--config <dir>] [ping]

  --config <dir>  the configuration set to read (default: /etc/kerbridge)
  ping            ask a running issuerd whether it answers, then exit
  -h, --help      print this and exit

Runs as root on the domain controller. See issuerd(8).
";

/// `issuerd [--config <dir>] [ping]`, or [`None`] when `-h` or `--help` was asked for.
///
/// `ping` is the container healthcheck's client. Shipping it in the same
/// binary keeps the framing in one place -- a healthcheck that disagreed with
/// the server about the wire format would report a healthy container that no
/// broker can talk to -- and reading the same config keeps it pointed at the
/// same socket without shell having to parse TOML.
///
/// Help returns `None` rather than printing here, so that the one test
/// covering this function does not write to the harness's stdout to prove it.
fn usage(args: &[String]) -> Result<Option<(bool, PathBuf)>> {
    let (mut ping, mut config) = (false, None);
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "ping" => ping = true,
            "--config" => config = Some(PathBuf::from(args.next().context("--config <path>")?)),
            other => {
                bail!(
                    "unexpected argument {other:?} -- usage: issuerd [--config <dir>] [ping]. \
                     `issuerd --help` prints the whole set."
                )
            }
        }
    }
    Ok(Some((ping, config.unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_DIR)))))
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((ping_only, config_dir)) = usage(&args)? else {
        print!("{HELP}");
        return Ok(());
    };
    let deployment = kerbridge_core::config::Config::load(&config_dir)?;
    if ping_only {
        return ping(&deployment.issuerd.socket);
    }

    let (realm, issuerd) = (&deployment.realm, &deployment.issuerd);
    let cfg = Config {
        realm: realm.realm.clone(),
        base_dn: realm.base_dn(),
        cloud_idp_ou: realm.idp_parent_ou(),
        // Spelled out on a `samba-tool` command line, so it has to be a `str`.
        sam_db: issuerd.sam_db.to_str().context("issuerd.sam_db is not UTF-8")?.to_owned(),
        tmp_dir: issuerd.tmp_dir.clone(),
        // Samba's own domain policy caps these again. Asking for more than the
        // KDC allows does not get more; it just gets what the KDC grants.
        max_lifetime: realm.max_lifetime_seconds,
        max_renewable: realm.max_renewable_seconds,
        cmd_timeout: issuerd.command_timeout_seconds,
        max_grants: deployment.main.device_grant_max_per_user as usize,
    };
    // Before anything is created or opened: a name that does not resolve is a
    // refusal to start, and the process has nothing to undo at this point.
    let (gid, broker_uid) = identity::resolve(issuerd, &config_dir)?;
    let (socket, max_inflight) = (issuerd.socket.clone(), issuerd.max_inflight);

    for warning in &deployment.warnings {
        log(warning);
    }

    std::fs::create_dir_all(&cfg.tmp_dir)
        .with_context(|| format!("creating {}", cfg.tmp_dir.display()))?;
    std::fs::set_permissions(&cfg.tmp_dir, std::fs::Permissions::from_mode(0o700))?;

    let audit = AuditLog::open(issuerd.audit_log_file.as_deref())?;
    let trail = match audit.path() {
        Some(path) => format!("audit {}", path.display()),
        None => "no audit file".to_owned(),
    };
    let _ = AUDIT.set(audit);
    // Before the first connection thread exists: the SIGUSR1 block it installs
    // is inherited, so every thread this process ever has carries it.
    reopen_audit_on_sigusr1()?;

    let listener = bind(&socket, gid)?;
    log(&format!(
        "listening on {} (realm {}, base {}, policy {}s/{}s, peer uid {} or root, {} in flight, {}, via {})",
        socket.display(),
        cfg.realm,
        cfg.base_dn,
        cfg.max_lifetime,
        cfg.max_renewable,
        broker_uid,
        max_inflight,
        trail,
        issue::kinit_program()
    ));

    let inflight = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for stream in listener.incoming() {
            let stream = match stream {
                Ok(stream) => stream,
                Err(e) => {
                    log(&format!("accept failed: {e}"));
                    continue;
                }
            };
            if let Err(why) = peer::authorized(&stream, broker_uid) {
                log(&format!("REFUSE connection: {why}"));
                continue;
            }
            // Bounded before the thread exists, so a flood costs an accept and
            // a close rather than a thread and three forks.
            let Some(slot) = Slot::claim(&inflight, max_inflight) else {
                log("REFUSE connection: too many requests in flight");
                continue;
            };
            // One thread per connection. Requests are short and the KDC
            // serializes the expensive part anyway.
            scope.spawn(|| {
                let _slot = slot;
                handle(&cfg, stream);
            });
        }
    });
    Ok(())
}

/// One of the bounded in-flight slots, released when the handler thread ends
/// however it ends.
struct Slot<'a>(&'a AtomicUsize);

impl<'a> Slot<'a> {
    fn claim(counter: &'a AtomicUsize, max: usize) -> Option<Self> {
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < max).then_some(n + 1))
            .ok()
            .map(|_| Self(counter))
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The request id is the caller's own string and it lands in the audit log, one
/// line per request. Unfiltered, a newline in it writes log lines of the
/// caller's choosing -- including a convincing `ISSUE` for someone else.
fn safe_id(id: &str) -> String {
    let clean: String =
        id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').take(64).collect();
    if clean.is_empty() { "-".into() } else { clean }
}

/// The reply and the audit line for a directory write.
///
/// `subject` is the grant's operator handle where there is one -- the same short
/// id `kbmanage device list` prints, so an audit line and a revocation join up.
/// A `TouchGrant` has none worth printing: it fires about once per device per
/// day and says nothing an operator acts on, so only its failures are logged.
fn written(
    verb: &str,
    request_id: &str,
    outcome: issue::Result<()>,
    subject: Option<&str>,
) -> Response {
    match outcome {
        Ok(()) => {
            if let Some(thumbprint) = subject {
                let handle =
                    kerbridge_core::grant::short_id(thumbprint).unwrap_or_else(|| "-".into());
                audit(&format!("{verb} {} {handle}", safe_id(request_id)));
            }
            Response::Done { request_id: request_id.to_owned() }
        }
        Err(e) => {
            log(&format!(
                "DENY   {} [{}] {}: {}",
                safe_id(request_id),
                e.client,
                verb.trim(),
                e.detail
            ));
            Response::Error { request_id: request_id.to_owned(), error: e.client.into() }
        }
    }
}

fn ping(socket: &Path) -> Result<()> {
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("connecting to {}", socket.display()))?;
    // Encoded from the enum rather than written as a literal, so the probe
    // cannot drift from the protocol it is probing.
    wire::write_frame(&mut stream, &serde_json::to_vec(&Request::Ping)?)?;
    let reply = wire::read_frame(&mut stream)?;
    anyhow::ensure!(
        matches!(serde_json::from_slice(&reply), Ok(Response::Pong { ok: true })),
        "unexpected reply: {:?}",
        String::from_utf8_lossy(&reply)
    );
    Ok(())
}

/// Reopen the audit file whenever `SIGUSR1` arrives, and return the thread that
/// waits for it.
///
/// `logrotate` sends it from `postrotate`, after renaming the file aside; see
/// [`AuditLog::reopen`]. `SIGUSR1` rather than `SIGHUP`, which conventionally
/// means "reload configuration" and would promise something this does not do.
///
/// Blocked and waited for rather than handled: a handler runs on whichever
/// thread the kernel picks, may use only async-signal-safe calls, and could
/// therefore not open a file. Blocking here -- before any other thread exists,
/// so every thread inherits it -- makes this thread the one place the signal is
/// ever delivered, and it then does the work as ordinary code.
///
/// The handle is what lets a test aim a signal at this thread rather than at the
/// process. Nothing joins it: it lives as long as the process does.
fn reopen_audit_on_sigusr1() -> Result<std::thread::JoinHandle<()>> {
    let mut usr1 = SigSet::empty();
    usr1.add(Signal::SIGUSR1);
    usr1.thread_block().context("blocking SIGUSR1")?;
    std::thread::Builder::new()
        .name("audit-rotate".to_owned())
        .spawn(move || {
            loop {
                if let Err(e) = usr1.wait() {
                    // Nothing left to wait on, so say so once and stop rather
                    // than spin: the process still serves tickets, and its audit
                    // file is simply no longer rotatable without a restart.
                    log(&format!("SIGUSR1: no longer waiting for it: {e}"));
                    return;
                }
                let Some(sink) = AUDIT.get() else { continue };
                match (sink.reopen(), sink.path()) {
                    // Into the new file, as its first line: an append-only
                    // record says where it continues, and the console copy says
                    // the rotation was seen.
                    (Ok(()), Some(path)) => audit(&format!("REOPEN {}", path.display())),
                    (Ok(()), None) => log("SIGUSR1: no audit file to reopen"),
                    (Err(e), _) => log(&format!("SIGUSR1: {e:#} -- still writing to the old file")),
                }
            }
        })
        .context("starting the audit-rotate thread")
}

/// An unclean stop leaves the socket file behind and `bind` would fail on it.
/// Ownership and mode are applied after binding, so the window in which the
/// socket exists with default permissions is the two syscalls in between.
fn bind(socket: &Path, gid: u32) -> Result<UnixListener> {
    let dir = socket.parent().context("socket path has no parent directory")?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;

    match std::fs::remove_file(socket) {
        Ok(()) => log("removed a stale socket"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context("removing stale socket"),
    }

    let listener =
        UnixListener::bind(socket).with_context(|| format!("binding {}", socket.display()))?;
    std::os::unix::fs::chown(dir, Some(0), Some(gid))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o710))?;
    std::os::unix::fs::chown(socket, Some(0), Some(gid))?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

fn handle(cfg: &Config, mut stream: UnixStream) {
    // A peer that connects and then stalls must not hold its slot forever.
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));

    let response = match wire::read_frame(&mut stream) {
        Err(e) => {
            log(&format!("framing error: {e}"));
            return;
        }
        Ok(frame) => match serde_json::from_slice::<Request>(&frame) {
            Err(e) => {
                log(&format!("undecodable request: {e}"));
                Response::Error { request_id: "-".into(), error: "bad request".into() }
            }
            Ok(Request::Ping) => Response::Pong { ok: true },
            Ok(Request::Issue(req)) => match issue::issue(cfg, &req) {
                Ok(ticket) => {
                    audit(&format!(
                        "ISSUE {} {} expires {}",
                        safe_id(&req.request_id),
                        ticket.principal,
                        ticket.expires_at
                    ));
                    Response::Ok(ticket)
                }
                Err(e) => {
                    // The detail names accounts and quotes command failures;
                    // only the category crosses the socket.
                    log(&format!("DENY  {} [{}] {}", safe_id(&req.request_id), e.client, e.detail));
                    Response::Error { request_id: req.request_id, error: e.client.into() }
                }
            },
            // The three grant verbs answer alike: a write that happened, or a
            // category. `TouchGrant` passes no subject, so only its failures
            // are logged -- `written` says why.
            Ok(Request::GrantDevice(req)) => {
                written("GRANT ", &req.request_id, grant::grant(cfg, &req), Some(&req.thumbprint))
            }
            Ok(Request::RevokeGrant(req)) => {
                written("REVOKE", &req.request_id, grant::revoke(cfg, &req), Some(&req.thumbprint))
            }
            Ok(Request::TouchGrant(req)) => {
                written("TOUCH ", &req.request_id, grant::touch(cfg, &req), None)
            }
        },
    };

    let body = match serde_json::to_vec(&response) {
        Ok(body) => body,
        Err(e) => {
            log(&format!("could not serialize response: {e}"));
            return;
        }
    };
    if let Err(e) = wire::write_frame(&mut stream, &body) {
        log(&format!("could not write response: {e}"));
    }
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    use std::os::unix::thread::JoinHandleExt;
    use std::time::{Duration, Instant};

    use super::*;

    /// The argument surface, and the one flag a shipped man page points at.
    ///
    /// `issuerd.8` is hand-written and names no flag; what it does say is that
    /// `issuerd --help` prints the current set. That sentence was false when
    /// the page was written -- every unrecognised argument was refused,
    /// `--help` among them -- so this asserts the sentence is true now, and
    /// `make test` asserts the page still points here.
    #[test]
    fn the_arguments_are_a_config_directory_and_ping_and_help() {
        let args = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(usage(&args(&[])).unwrap(), Some((false, PathBuf::from(DEFAULT_CONFIG_DIR))));
        assert_eq!(
            usage(&args(&["--config", "/tmp/set", "ping"])).unwrap(),
            Some((true, PathBuf::from("/tmp/set")))
        );
        for help in [vec!["-h"], vec!["--help"]] {
            assert_eq!(usage(&args(&help)).unwrap(), None, "{help:?} is answered, not refused");
        }
        assert!(HELP.contains("--config") && HELP.contains("ping"));
        for bad in [vec!["help"], vec!["--ping"], vec!["--config"]] {
            assert!(usage(&args(&bad)).is_err(), "{bad:?}");
        }
    }

    /// The whole rotation, end to end and with a real signal: a record, the
    /// rename `logrotate` performs, `SIGUSR1`, and a second record.
    ///
    /// The signal is aimed at the waiting thread with `pthread_kill` rather than
    /// at the process. A process-directed one is delivered to any thread that
    /// does not block it, and under the test harness that is every thread but
    /// this one -- where the default action for `SIGUSR1` would end the run.
    #[test]
    fn sigusr1_moves_the_record_to_the_file_logrotate_created() {
        let path =
            std::env::temp_dir().join(format!("kb-issuerd-rotate-{}.log", std::process::id()));
        let rotated = path.with_extension("log.1");
        let (_, _) = (std::fs::remove_file(&path), std::fs::remove_file(&rotated));

        AUDIT.set(AuditLog::open(Some(&path)).expect("open")).ok().expect("the only test using it");
        let waiter = reopen_audit_on_sigusr1().expect("the waiting thread");

        audit("ISSUE req-1 alice@EXAMPLE.TEST expires 2026-08-16T12:00:00Z");
        std::fs::rename(&path, &rotated).expect("rotate");
        nix::sys::pthread::pthread_kill(waiter.as_pthread_t(), Signal::SIGUSR1).expect("SIGUSR1");

        // The `REOPEN` line is the reopen itself, so seeing it is what says the
        // successor is now the file being written to.
        let deadline = Instant::now() + Duration::from_secs(10);
        let reopened = loop {
            match std::fs::read_to_string(&path) {
                Ok(text) if text.contains("REOPEN") => break text,
                _ if Instant::now() > deadline => panic!("no reopen within ten seconds"),
                _ => std::thread::sleep(Duration::from_millis(10)),
            }
        };
        assert!(
            reopened.trim_end().ends_with(&format!("REOPEN {}", path.display())),
            "{reopened:?}"
        );

        audit("ISSUE req-2 bob@EXAMPLE.TEST expires 2026-08-16T13:00:00Z");

        let rolled = std::fs::read_to_string(&rotated).expect("the rotated file");
        let current = std::fs::read_to_string(&path).expect("its successor");
        assert_eq!(rolled.lines().count(), 1, "{rolled:?}");
        assert!(
            rolled
                .trim_end()
                .ends_with("ISSUE req-1 alice@EXAMPLE.TEST expires 2026-08-16T12:00:00Z"),
            "{rolled:?}"
        );
        assert_eq!(current.lines().count(), 2, "{current:?}");
        assert!(
            current
                .trim_end()
                .ends_with("ISSUE req-2 bob@EXAMPLE.TEST expires 2026-08-16T13:00:00Z"),
            "{current:?}"
        );
        std::fs::remove_file(&path).expect("cleanup");
        std::fs::remove_file(&rotated).expect("cleanup");
    }
}
