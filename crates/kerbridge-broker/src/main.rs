//! Public ticket API.
//!
//! - Serves HTTP to clients.
//! - Validates access tokens of the cloud IdP.
//! - Resolves the user identity in that token to an enabled and admitted Samba
//!   AD account.
//! - Asks `issuerd` for the TGT of that account.
//!
//! # The modules
//!
//! [`discovery`], [`ticket`] and [`devices`] hold one route family each. Under
//! them is one module per step of a request, in the order that a request meets
//! them: `kerbridge-idp` or [`device`], then [`directory`], then [`issuer`].
//!
//! The two device names are close and the jobs are not: [`device`] verifies an
//! assertion and holds the nonce store, [`devices`] serves the routes that
//! manage the grants.
//!
//! [`http`] holds the vocabulary that every route speaks. [`state`] holds what
//! answers a request. [`problems`] turns a failure into a status, and tells an
//! operator out of band.
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

/// Default config directory, unless an argument names another.
const DEFAULT_CONFIG_DIR: &str = "/etc/kerbridge";

const HELP: &str = "\
kerbridge-broker -- the KerBridge broker daemon

usage: kerbridge-broker [--config <dir>] [--test-notification]

  --config <dir>        the configuration set to read (default: /etc/kerbridge)
  --test-notification   send one test operator notification, then exit
  -h, --help            print this and exit

Listens on loopback only; put a TLS terminator in front of it on the same host.
See kerbridge-broker(8).
";

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
    if test_only {
        return notifier.test_notification().await;
    }
    let notifier = Arc::new(notifier);
    for warning in &warnings {
        eprintln!("[broker] warning: {warning}");
    }

    let state = Arc::new(AppState::build(config, notifier).await?);
    let app = Router::new()
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

/// Reopen the log on `SIGUSR1`, for logrotate. Unhandled, `SIGUSR1` ends the
/// process.
fn reopen_audit_on_sigusr1(state: Arc<AppState>) -> Result<()> {
    let mut usr1 = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
        .context("listening for SIGUSR1")?;
    tokio::spawn(async move {
        while usr1.recv().await.is_some() {
            match (state.audit.reopen(), state.audit.path()) {
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

    /// Unrecognized arguments must be refused, not ignored.
    #[test]
    fn the_arguments_are_a_config_directory_and_the_test_flag() {
        let args = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(usage(&args(&[])).unwrap(), Some((PathBuf::from(DEFAULT_CONFIG_DIR), false)));
        assert_eq!(
            usage(&args(&["--config", "/tmp/set", "--test-notification"])).unwrap(),
            Some((PathBuf::from("/tmp/set"), true))
        );
        for help in [vec!["-h"], vec!["--help"]] {
            assert_eq!(usage(&args(&help)).unwrap(), None, "{help:?} is answered, not refused");
        }
        assert!(HELP.contains("--config") && HELP.contains("--test-notification"));
        for bad in [vec!["--test-notifcation"], vec!["-help"], vec!["--config"]] {
            assert!(usage(&args(&bad)).is_err(), "{bad:?}");
        }
    }
}
