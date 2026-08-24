//! The state that answers a request: one IdP adapter and one directory client
//! per source, plus the resources that every source shares.

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

/// One source: everything that answers a request which arrived on its path
/// segment.
///
/// Each source **owns** its directory client and does not share one. Thus a
/// caller cannot spell a request that resolves against the admission group of a
/// different source.
pub struct SourceState {
    /// The adapter stamps this into every identity it mints.
    /// [`crate::http::same_source`] compares an assertion's identity against it.
    pub source: Source,
    /// The cloud IdP behind this source. The only field here that knows which
    /// IdP it is; everything downstream sees an `ExternalIdentity`.
    pub idp: Box<dyn IdentityProvider>,
    pub directory: Directory,
}

pub struct AppState {
    pub config: Config,
    /// Keyed by source name, which is the path segment. Ordered, so that two
    /// runs print the same startup line.
    pub sources: BTreeMap<String, SourceState>,
    pub issuer: Issuer,
    /// Shared with the adapter, which raises the two IdP conditions from its own
    /// key-refresh path. The broker raises the admission problems in
    /// [`crate::problems::ROLE_PROBLEMS`], and so does sync, from the other side
    /// of the same directory: either one may be the only one running at the
    /// time.
    pub notifier: Arc<Notifier>,
    /// The grant lifecycle, on a path that outlives this container. Written
    /// through [`AppState::record`] only, so that the console copy and the
    /// durable copy cannot differ.
    pub audit: AuditLog,
    pub rng: ring::rand::SystemRandom,
    /// The device-grant replay window. In memory: a restart invalidates every
    /// outstanding nonce, and a client whose nonce is refused asks for another.
    pub nonces: Nonces,
    /// The cap on ticket requests in flight at once. A valid token is not a
    /// budget: one holder can replay `POST /{source}/ticket` as fast as the
    /// network allows, and each request that passes costs an RSA verification, a
    /// fresh LDAPS bind, and three forked root subprocesses in the realm
    /// container.
    ///
    /// Discovery is outside the cap on purpose: it serializes a struct already
    /// in memory. Caddy bounds both routes.
    pub inflight: tokio::sync::Semaphore,
}

impl AppState {
    /// Build the state that answers requests, from one config set.
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

    /// The source that a path segment names.
    ///
    /// 404 and not 403: a name that this deployment does not serve is not a
    /// resource that exists, and the set of source names is public. The tray
    /// gets one in the URL that it was configured with.
    pub fn source(&self, name: &str) -> Result<&SourceState, Failure> {
        self.sources.get(name).ok_or_else(|| {
            Failure::new(
                StatusCode::NOT_FOUND,
                "no such source",
                format!("no source named {name:?} is configured"),
            )
        })
    }

    /// The line a restart prints. Every value here is one that an operator
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

    /// The source list for the startup line. Named and not counted: after an
    /// operator edits `main.toml`, the question is which sources came up, and a
    /// number cannot answer it.
    fn listed(&self) -> String {
        match self.sources.keys().cloned().collect::<Vec<_>>().join(", ") {
            names if names.is_empty() => "no sources yet".to_owned(),
            names => format!("sources {names}"),
        }
    }
}
