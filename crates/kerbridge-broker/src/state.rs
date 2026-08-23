//! What a request is answered with: one wired-up adapter and directory per
//! source, and the process-wide resources shared behind all of them.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::http::StatusCode;
use kerbridge_core::Source;
use kerbridge_core::audit::AuditLog;
use kerbridge_idp::IdentityProvider;
use kerbridge_notify::Notifier;

use crate::config::Config;
use crate::device::Nonces;
use crate::directory::Directory;
use crate::http::Failure;
use crate::issuer::Issuer;

/// How long a nonce stays spendable. Long enough for a TPM signature and a
/// round trip on a slow link; short enough that the store stays small.
const NONCE_TTL: Duration = Duration::from_secs(120);

/// Nonces outstanding at once. Past this `GET /{source}/nonce` refuses rather
/// than evicting -- evicting would let a flood invalidate the nonce a
/// legitimate device is about to spend.
const MAX_NONCES: usize = 4096;

/// One source, wired up: everything a request that arrived on its path segment
/// is answered with.
///
/// It **owns** its directory client rather than sharing one, so resolving a
/// request against another source's admission group is not something a caller
/// can spell.
pub struct SourceState {
    /// What this adapter stamps into every identity it mints, and what
    /// [`crate::http::same_source`] compares an assertion's identity against.
    pub source: Source,
    /// The cloud IdP behind this source, and the only thing here that knows
    /// which one it is. Everything downstream sees an `ExternalIdentity`.
    pub idp: Box<dyn IdentityProvider>,
    pub directory: Directory,
}

pub struct AppState {
    pub config: Config,
    /// By source name -- the path segment. Ordered so the startup line lists
    /// them the same way twice running.
    pub sources: BTreeMap<String, SourceState>,
    pub issuer: Issuer,
    /// Shared with the adapter, which raises the two IdP conditions from its own
    /// key-refresh path. The admission problems in [`crate::problems::ROLE_PROBLEMS`]
    /// are raised here *and* by sync, from the other side of the same directory --
    /// either may be the only one running when it happens.
    pub notifier: Arc<Notifier>,
    /// The grant lifecycle, on a path that survives this container. Written
    /// through [`AppState::record`], never on its own, so the console copy and
    /// the durable one cannot say different things.
    pub audit: AuditLog,
    pub rng: ring::rand::SystemRandom,
    /// The device-grant replay window. In memory: a restart invalidates every
    /// outstanding nonce, and a client that finds one refused asks for another.
    pub nonces: Nonces,
    /// Ticket requests in flight at once. A valid token is not a budget: one
    /// holder can replay `POST /{source}/ticket` as fast as the network allows, and each
    /// one that passes costs an RSA verification, a fresh LDAPS bind, and three
    /// forked root subprocesses inside the realm container. `issuerd` caps the
    /// last of those from its own side; this is what keeps the flood from
    /// reaching the directory in the first place.
    ///
    /// `GET /{source}/config` is deliberately outside it. That route serializes a struct
    /// that is already in memory and touches nothing else, so capping it would
    /// only be a way to refuse discovery to a client that has not asked for
    /// anything yet; what bounds it is Caddy, ahead of both routes.
    pub inflight: tokio::sync::Semaphore,
}

impl AppState {
    /// Wire one config set up into the thing that answers requests.
    pub async fn build(config: Config, notifier: Arc<Notifier>) -> Result<Self> {
        let mut sources = BTreeMap::new();
        for source in &config.sources {
            let name = source.source.name();
            let idp = kerbridge_idp::connect(
                &source.settings,
                &source.source,
                notifier.clone(),
                config.timeout,
            )
            .await
            .with_context(|| format!("connecting to the cloud IdP for source {name}"))?;
            let directory = Directory::new(
                config.ldap_url.clone(),
                config.ldap_base_dn.clone(),
                source.ou.clone(),
                config.ldap_bind_dn.clone(),
                config.ldap_bind_password.clone(),
                Some(&config.ldap_ca_file),
                config.timeout,
            )
            .with_context(|| format!("configuring the directory client for source {name}"))?;
            sources.insert(
                name.to_owned(),
                SourceState { source: source.source.clone(), idp, directory },
            );
        }

        let issuer = Issuer::new(config.issuer_socket.clone(), config.timeout);
        let audit =
            AuditLog::open(config.audit_log_file.as_deref()).context("opening the audit log")?;
        let inflight = tokio::sync::Semaphore::new(config.max_inflight);

        Ok(Self {
            config,
            sources,
            issuer,
            notifier,
            audit,
            rng: ring::rand::SystemRandom::new(),
            nonces: Nonces::new(NONCE_TTL, MAX_NONCES),
            inflight,
        })
    }

    pub fn record(&self, line: String) {
        eprintln!("{line}");
        self.audit.append(&line);
    }

    /// The source a path segment names.
    ///
    /// 404 rather than 403: a name this deployment does not serve is not a
    /// resource that exists, and the set of source names is public -- the tray
    /// is handed one in the URL it was configured with.
    pub fn source(&self, name: &str) -> Result<&SourceState, Failure> {
        self.sources.get(name).ok_or_else(|| {
            Failure::new(
                StatusCode::NOT_FOUND,
                "no such source",
                format!("no source named {name:?} is configured"),
            )
        })
    }

    /// What a restart says it came up as. Every knob here is one an operator
    /// changes and then wants confirmation of.
    pub fn startup_line(&self) -> String {
        let grants = if self.config.device_grants.enabled() {
            format!("device grants {} days", self.config.device_grants.days)
        } else {
            "device grants off".to_owned()
        };
        let trail = match self.audit.path() {
            Some(path) => format!("audit {}", path.display()),
            None => "no audit file".to_owned(),
        };
        format!(
            "listening on {} ({}, {} tickets in flight, {grants}, {trail})",
            self.config.listen,
            self.listed(),
            self.config.max_inflight,
        )
    }

    /// The startup line's source list. Named rather than counted: which sources
    /// a restart came up with is the question after an operator edits
    /// `main.toml`, and a number cannot answer it.
    fn listed(&self) -> String {
        match self.sources.keys().cloned().collect::<Vec<_>>().join(", ") {
            names if names.is_empty() => "no sources yet".to_owned(),
            names => format!("sources {names}"),
        }
    }
}
