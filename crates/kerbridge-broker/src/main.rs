//! `kerbridge-broker` -- the public ticket API.
//!
//! Serves `GET /{source}/config` and `POST /{source}/ticket` on a loopback-only
//! listener behind Caddy. Validates the external identity proof, converts
//! provider claims to an [`ExternalIdentity`](kerbridge_core::ExternalIdentity),
//! resolves that to exactly one enabled and admitted Samba AD user over LDAP,
//! asks `issuerd` for a TGT over its Unix socket, and returns the ccache.
//!
//! **One process serves every source**, and the leading path segment says which
//! one. What that segment selects is an adapter and an OU, never a weaker check:
//! each source resolves against its own admission group, and an identity minted
//! under one may not be spent under another ([`http::same_source`]).
//!
//! `POST /{source}/ticket` takes either identity proof -- a cloud IdP bearer
//! token or a device-grant assertion ([`device`]) -- and the two meet at the same
//! directory lookup, so the admission path is one path by construction rather
//! than by discipline. The rest of the device-grant surface (`GET
//! /{source}/nonce`, `/{source}/devices`) only ever registers, lists or removes
//! a key; it decides no admission of its own, and every write it implies goes
//! through `issuerd`, so the broker's LDAP identity stays read-only.
//!
//! Which cloud IdP is behind it is not knowledge this crate holds: `kerbridge-idp`
//! answers that, and nothing here reads a provider claim or names a provider
//! environment key.
//!
//! Holds no KDC database, Samba administrative credential, or user keytab, and
//! cannot execute Samba tools.
//!
//! # The modules
//!
//! One per route family -- [`discovery`], [`ticket`], [`devices`] -- over one
//! per step a request passes through, in the order it meets them:
//! `kerbridge-idp` or [`device`], [`directory`], [`issuer`]. The two neighbours
//! are not the same thing: [`device`] verifies an assertion and holds the nonce
//! store, [`devices`] serves the routes that manage the grants.
//!
//! What every route speaks is [`http`]; what they are answered from is
//! [`state`]; what a failure becomes, and who hears about it out of band, is
//! [`problems`].
//!
//! Contract: `DESIGN.md` @ Public broker API, @ Entra validation, @ Device
//! grants.

#![forbid(unsafe_code)]

mod config;
mod device;
mod devices;
mod directory;
mod discovery;
mod http;
mod issuer;
mod problems;
mod state;
mod ticket;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use axum::Router;
use axum::routing::{delete, get, post};
use kerbridge_notify::Notifier;

use crate::config::Config;
use crate::state::AppState;

/// The config set this deployment installed, unless an argument names another.
const DEFAULT_CONFIG_DIR: &str = "/etc/kerbridge";

/// What `--help` prints, and the one place the argument surface is written out.
///
/// A hand-rolled parser has no `--help` unless somebody writes one. The list
/// lives here rather than in `kerbridge-broker.8` because that page is
/// hand-written: it names `--help` and nothing else, precisely so that there is
/// no second copy of this to go stale.
const HELP: &str = "\
kerbridge-broker -- the KerBridge broker daemon

usage: kerbridge-broker [--config <dir>] [--test-notification]

  --config <dir>        the configuration set to read (default: /etc/kerbridge)
  --test-notification   send one test operator notification, then exit
  -h, --help            print this and exit

Listens on loopback only; put a TLS terminator in front of it on the same host.
See kerbridge-broker(8).
";

/// `kerbridge-broker [--config <dir>] [--test-notification]`, or [`None`] when
/// `-h` or `--help` was asked for.
///
/// Hand-rolled rather than clap: three optional flags do not earn a dependency
/// in a process on the token path. An unrecognized argument is refused rather
/// than ignored -- a typo in `--test-notifcation` must not start a broker that
/// then looks like it is running normally. `--help` returns `None` rather than printing here, so that
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
                "unexpected argument {other:?} -- usage: kerbridge-broker [--config <dir>] \
                 [--test-notification]. `kerbridge-broker --help` prints the whole set."
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
    let (config, warnings) = Config::load(&dir)
        .with_context(|| format!("reading the configuration under {}", dir.display()))?;
    let notifier = Notifier::from_config("broker", &config.notify, &config.realm)
        .context("configuring notification")?;
    // Before the directory and the IdP: proving the channel is a step of
    // installing, and an installation that cannot reach either yet is exactly
    // when an operator wants to know the alarm works.
    if test_only {
        return notifier.test_notification().await;
    }
    let notifier = Arc::new(notifier);
    for warning in &warnings {
        eprintln!("[broker] warning: {warning}");
    }

    let state = Arc::new(AppState::build(config, notifier).await?);
    let app = Router::new()
        // Discovery alone answers without a source segment: an SRV record
        // carries a host and a port and has nowhere to put a path. The routes
        // that issue or revoke stay prefixed -- the client re-bases on the
        // `base_url` in this reply before it asks for a ticket.
        .route("/config", get(discovery::sole_discovery))
        .route("/{source}/config", get(discovery::discovery))
        .route("/{source}/ticket", post(ticket::ticket))
        .route("/{source}/nonce", get(devices::nonce))
        .route("/{source}/devices", post(devices::register_device).get(devices::list_devices))
        .route("/{source}/devices/{id}", delete(devices::revoke_device))
        .with_state(state.clone());

    reopen_audit_on_sigusr1(state.clone())?;

    let listener = tokio::net::TcpListener::bind(&state.config.listen)
        .await
        .with_context(|| format!("binding {}", state.config.listen))?;
    eprintln!("[broker] {}", state.startup_line());
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .context("serving")
}

/// Reopen the audit file whenever `SIGUSR1` arrives.
///
/// `logrotate` sends it from `postrotate`, after renaming the file aside; see
/// [`AuditLog::reopen`](kerbridge_core::audit::AuditLog::reopen). `SIGUSR1`
/// rather than `SIGHUP`, which conventionally means "reload configuration" and
/// would promise something this does not do.
///
/// Tokio's handler is process-wide and hands the signal to this task whichever
/// thread it arrives on, so nothing here depends on the runtime's thread count
/// or on when the workers were started. Installing it is what makes the signal
/// harmless: unhandled, `SIGUSR1` ends the process.
fn reopen_audit_on_sigusr1(state: Arc<AppState>) -> Result<()> {
    let mut usr1 = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
        .context("listening for SIGUSR1")?;
    tokio::spawn(async move {
        while usr1.recv().await.is_some() {
            match (state.audit.reopen(), state.audit.path()) {
                // Through `record`, so the successor's first line says the trail
                // continues here and the console copy says the rotation was
                // seen. A failure is the console's alone: it is a diagnosis, and
                // the file it would go in is the one we could not open.
                (Ok(()), Some(path)) => {
                    let line = format!("[broker] REOPEN {}", path.display());
                    state.record(line);
                }
                (Ok(()), None) => eprintln!("[broker] SIGUSR1: no audit file to reopen"),
                (Err(e), _) => {
                    eprintln!("[broker] SIGUSR1: {e:#} -- still writing to the old file");
                }
            }
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An unrecognized argument is refused rather than ignored: a typo in
    /// `--test-notifcation` must not start a broker that then looks like it is
    /// running normally.
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
