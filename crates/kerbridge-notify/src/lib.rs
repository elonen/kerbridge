//! `kerbridge-notify` -- telling an operator about the things only they can fix.
//!
//! Some conditions are invisible in a log nobody reads and actionable by nobody
//! else: an expiring Graph credential, a deleted admission group, a sync cycle
//! that keeps failing. This is the one channel they leave by.
//!
//! **The only delivery method is an HTTP webhook**, enabled by the presence of
//! the URL secret file and disabled by its absence. There is no method selector,
//! because with one method a selector is a second way to say the same thing and a
//! second way to be misconfigured. Every event is also written to the component's
//! own log as a `NOTIFY <severity> <event>: <message>` line whether or not a
//! webhook is configured, so the log stays the fallback it has always been.
//!
//! Three rules keep the channel trustworthy, and each has its own module or
//! section here:
//!
//! - **Nothing a tenant can name may reshape the payload.** [`template`] renders
//!   one JSON body with every substituted value escaped as a JSON string.
//! - **Nothing may flood it.** [`problems`] holds a durable last-notified stamp,
//!   keyed on event and subject, with a different repeat policy for a condition
//!   that persists and one that counts down.
//! - **Nothing may fail because of it.** A send is one attempt with a deadline,
//!   and every failure is logged rather than returned. Notification cannot fail a
//!   sync cycle or a ticket request.
//!
//! The webhook is not the only exit. [`problems`] keeps what is currently wrong
//! as one JSON file per condition in a directory, which a monitoring agent can
//! read without this crate's cooperation, and which is written whether or not a
//! webhook is configured. A condition that clears is announced as a recovery and
//! its file stops being an open problem, so the directory is a live answer to
//! "what is wrong right now" rather than a log of things that once were.
//!
//! It is a crate of its own rather than a module of `kerbridge-core` because
//! `issuerd` links that crate and holds KDC authority; an HTTP and TLS dependency
//! tree has no business inside that process. `DESIGN.md` @ Operator notification
//! is authoritative.

#![forbid(unsafe_code)]

mod problems;
mod template;

use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use kerbridge_core::config::Notify;
use kerbridge_core::time::{now_unix, rfc3339};
use serde::{Deserialize, Serialize};
use url::Url;

pub use crate::problems::{Kind, Repeat};
use crate::problems::{Problem, Problems};
use crate::template::{Template, Values};

/// What most receivers accept unchanged -- Slack, Mattermost, Rocket.Chat and
/// Teams all read a bare `text`. Anything else is `notify.template`.
const DEFAULT_TEMPLATE: &str = r#"{"text":"KerBridge %COMPONENT% on %REALM%\n%SEVERITY% %EVENT% at %TIMESTAMP%\n%MESSAGE%\n%DETAIL%"}"#;

/// How loud an event is. Ordered, because `notify.min_severity` suppresses
/// everything below the configured level.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    const SPELLINGS: &'static str = "info, warning, error";

    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "info" => Some(Self::Info),
            "warning" => Some(Self::Warning),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

/// One operator-actionable thing that happened.
pub struct Event {
    /// Stable slug, e.g. `graph-credential-expiring`. `DESIGN.md` lists the set.
    pub event: &'static str,
    pub severity: Severity,
    /// What *this instance* is about -- the credential, the group, the account.
    /// Keys the rate-limit record together with `event`, so two instances of one
    /// event class do not suppress each other. Empty when the event is about the
    /// deployment as a whole.
    pub subject: String,
    /// One-line human summary.
    pub message: String,
    /// Event specifics; may be empty.
    pub detail: String,
    pub repeat: Repeat,
    /// Whether this opens a condition that stays true until something clears it.
    pub kind: Kind,
}

impl Event {
    /// A persisting condition with no subject and no detail -- what most of them
    /// are.
    pub fn new(event: &'static str, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            event,
            severity,
            subject: String::new(),
            message: message.into(),
            detail: String::new(),
            repeat: Repeat::Persisting,
            kind: Kind::Condition,
        }
    }

    /// Report something that is already over -- so it is announced once, but never
    /// listed as an open problem, since nothing could ever resolve it.
    pub fn incident(mut self) -> Self {
        self.kind = Kind::Incident;
        self
    }

    pub fn subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = subject.into();
        self
    }

    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    /// Turn this into a countdown: notified as it crosses 30, 14, 7, 3 and 1
    /// days remaining, and silent between those.
    pub fn countdown(mut self, days_remaining: i64) -> Self {
        self.repeat = Repeat::Countdown { days_remaining };
        self
    }
}

/// The configured channel. Absent from a [`Notifier`] whose deployment has no
/// webhook URL, which is a supported state and not an error.
struct Channel {
    http: reqwest::Client,
    /// A credential -- for common chat receivers the *only* authentication. Never
    /// logged, which is also why every `reqwest` error below is stripped of its
    /// URL before it reaches a log line.
    url: String,
    template: Template,
}

pub struct Notifier {
    component: &'static str,
    realm: String,
    /// Policy, not channel: the floor and the interval govern the durable state
    /// too, and that state is kept whether or not anything is delivered.
    min_severity: Severity,
    repeat_interval: Duration,
    problems: Mutex<Problems>,
    channel: Option<Channel>,
}

impl Notifier {
    /// One component's view of `main.toml`'s `[notify]`. `component` is the
    /// emitting service: the log prefix, `%COMPONENT%`, and the directory it
    /// takes under `notify.state_dir`.
    ///
    /// Configuration errors are fatal here -- an unknown placeholder, a template
    /// that is not JSON, an unreadable secret -- because the alternative is a
    /// deployment that believes it has a notification channel. Having *no* URL
    /// is not one of them: it warns and runs, since the log lines still go out
    /// and a bench has nowhere to send anything.
    pub fn from_config(component: &'static str, cfg: &Notify, realm: &str) -> Result<Self> {
        let min_severity = Severity::parse(&cfg.min_severity).with_context(|| {
            format!(
                "main.toml: notify.min_severity expects one of {}; got {:?}",
                Severity::SPELLINGS,
                cfg.min_severity
            )
        })?;
        let repeat_interval = Duration::from_secs(u64::from(cfg.repeat_interval_hours) * 3_600);

        // Loaded before the URL is even looked at: the problem directory is the
        // integration surface for a deployment that wants a monitoring agent
        // rather than a chat channel, so it has to work with no webhook at all.
        if cfg.state_dir.is_none() {
            eprintln!(
                "[{component}] no notify.state_dir: open problems are tracked in memory only, so \
                 nothing outside this process can read them and a restart re-sends whatever is \
                 still outstanding"
            );
        }
        // `notify.state_dir` is one key every daemon reads, so the configured
        // path is the parent and the component's name is the directory. Compose
        // hides the need for this by binding a different host directory into
        // each container; a Debian deployment has three services writing
        // `problem-<event>.json` into one place under three different uids.
        let problems = Mutex::new(Problems::load(
            cfg.state_dir.as_ref().map(|dir| dir.join(component)),
            component,
            repeat_interval.as_secs(),
            now_unix(),
        ));

        let channel = match webhook_url(cfg.url_file.as_deref())? {
            None => {
                eprintln!(
                    "[{component}] no webhook URL: operator events go to this log and the problem \
                     directory only. Point notify.url_file at a file holding one to have them \
                     delivered"
                );
                None
            }
            Some(url) => {
                let insecure = insecure_opt_in(&url, component, cfg.insecure_host.as_deref())?;
                Some(Channel {
                    http: http_client(
                        Duration::from_secs(cfg.timeout_seconds.into()),
                        cfg.ca_file.as_deref(),
                        insecure,
                    )?,
                    url,
                    template: Template::parse(cfg.template.as_deref().unwrap_or(DEFAULT_TEMPLATE))?,
                })
            }
        };

        Ok(Self {
            component,
            realm: realm.to_owned(),
            min_severity,
            repeat_interval,
            problems,
            channel,
        })
    }

    /// A notifier with no channel and no durable state: every event becomes its
    /// log line and stops there.
    ///
    /// What [`Notifier::from_config`] produces for a deployment that has
    /// configured nothing, but reached directly -- for a caller that needs a `Notifier` to satisfy a
    /// signature and has no environment to read, which in practice means tests.
    pub fn disabled(component: &'static str) -> Self {
        Self {
            component,
            realm: String::new(),
            min_severity: Severity::Info,
            repeat_interval: Duration::from_secs(0),
            problems: Mutex::new(Problems::load(None, component, 0, 0)),
            channel: None,
        }
    }

    /// Log the event, and deliver it if it is configured, loud enough and due.
    ///
    /// Returns nothing: a notification failure is never a caller's problem, and
    /// a `Result` here would eventually be one that somebody propagated into a
    /// sync cycle or a ticket request.
    pub async fn send(&self, mut event: Event) {
        eprintln!(
            "[{}] NOTIFY {} {}: {}",
            self.component,
            event.severity.as_str(),
            event.event,
            event.message
        );
        let now = now_unix();
        // Deliverable and due are separate questions. The state is recorded
        // either way -- an operator watching the directory must see a problem
        // that the severity floor happens to mute -- but an event that was never
        // going to be sent must not consume the rate limit of one that would be.
        let deliverable = self.channel.is_some() && event.severity >= self.min_severity;
        let (due, summary) = {
            // Scoped so the guard is dropped before the await below: deciding
            // and marking happen together, delivery happens outside the lock.
            let mut problems = self.problems.lock().unwrap_or_else(|p| p.into_inner());
            let due = problems.raise(
                &event,
                self.component,
                now,
                self.repeat_interval.as_secs(),
                deliverable,
            );
            (due, problems.open_summary())
        };
        let Some(channel) = &self.channel else { return };
        if !due {
            return;
        }
        event.detail = aggregate(&event.detail, &summary);
        if let Err(e) = self.post(channel, &event, now).await {
            eprintln!("[{}] NOTIFY-FAIL {}: {e:#}", self.component, event.event);
        }
    }

    /// Mark `event` no longer true, and say so if it was.
    ///
    /// Called from wherever the condition is *disproved* -- the point that would
    /// have raised it and did not. Only a component that re-evaluates on a
    /// schedule can do this honestly, which is why sync clears most of them on a
    /// completed cycle while the broker clears its one on a successful lookup.
    ///
    /// Every open subject of the event goes at once; see [`Problems::resolve`]
    /// for why resolving by subject would not work. Costs nothing when there is
    /// nothing open, so a per-request caller may call it unconditionally.
    pub async fn resolve(&self, event: &'static str) {
        let (resolved, summary) = {
            let mut problems = self.problems.lock().unwrap_or_else(|p| p.into_inner());
            let resolved = problems.resolve(event, self.component);
            (resolved, problems.open_summary())
        };
        self.announce_recovery(event, resolved, &summary).await;
    }

    /// Clear one subject of an event, for a condition that only *that* subject
    /// succeeding can disprove -- one account the issuer refuses, one identity two
    /// directory objects claim. Clearing the whole event there would announce a
    /// recovery for a second broken account because the first one was fixed.
    pub async fn resolve_subject(&self, event: &'static str, subject: &str) {
        let (resolved, summary) = {
            let mut problems = self.problems.lock().unwrap_or_else(|p| p.into_inner());
            let resolved = problems.resolve_one(event, subject, self.component);
            (resolved, problems.open_summary())
        };
        self.announce_recovery(event, resolved.into_iter().collect(), &summary).await;
    }

    async fn announce_recovery(&self, event: &'static str, resolved: Vec<Problem>, summary: &str) {
        let now = now_unix();
        for problem in resolved {
            eprintln!("[{}] NOTIFY info {event}: recovered", self.component);
            let Some(channel) = &self.channel else {
                continue;
            };
            // Judged against the floor the *event* passed, not against `info`,
            // so raising the floor cannot leave an operator with alarms and no
            // all-clears. Announced as `info` regardless: it is good news, and
            // rendering it at the original severity would put ERROR on it.
            if problem.severity < self.min_severity {
                continue;
            }
            let recovered = Event::new(
                event,
                Severity::Info,
                format!("recovered after {}", problem.lasted(now)),
            )
            .subject(problem.subject.clone())
            .detail(aggregate(&format!("was: {}", problem.message), summary));
            if let Err(e) = self.post(channel, &recovered, now).await {
                eprintln!("[{}] NOTIFY-FAIL {event}: {e:#}", self.component);
            }
        }
    }

    /// One synthetic `info` event, bypassing both the severity floor and the
    /// rate limit. A notification channel can fail as silently as the conditions
    /// it reports, so an installation is not finished until this has been seen
    /// to arrive.
    pub async fn test_notification(&self) -> Result<()> {
        let Some(channel) = &self.channel else {
            bail!(
                "no webhook URL is configured, so there is nothing to test. Put one in the file \
                 notify.url_file names"
            );
        };
        if self.min_severity > Severity::Info {
            eprintln!(
                "[{}] note: notify.min_severity={} would suppress a real info event; this test \
                 is sent regardless",
                self.component,
                self.min_severity.as_str()
            );
        }
        let event = Event::new(
            "test-notification",
            Severity::Info,
            format!("test notification from kerbridge-{}", self.component),
        )
        .detail("Sent by --test-notification. Nothing is wrong.");
        self.post(channel, &event, now_unix()).await?;
        eprintln!("[{}] test notification accepted by the receiver", self.component);
        Ok(())
    }

    /// One attempt, bounded by the configured timeout. No retry: a retry against
    /// a receiver that is down is the same failure again, and against one that is
    /// rate-limiting it is a flood.
    async fn post(&self, channel: &Channel, event: &Event, now: u64) -> Result<()> {
        let body = channel.template.render(&Values {
            event: event.event,
            severity: event.severity.as_str(),
            component: self.component,
            realm: &self.realm,
            timestamp: &rfc3339(now as u32),
            message: &event.message,
            detail: &event.detail,
        });
        let response = channel
            .http
            .post(&channel.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            // `reqwest` puts the request URL in its Display, and this one is a
            // credential. Every error out of here is stripped of it, so a
            // transport failure cannot post the webhook secret into the log.
            .map_err(|e| anyhow::anyhow!("{}", e.without_url()))
            .context("posting the notification")?;
        let status = response.status();
        if !status.is_success() {
            bail!("the receiver answered {status}");
        }
        Ok(())
    }
}

/// An event's own detail, followed by the census of everything still open.
///
/// The aggregate rides on `%DETAIL%` rather than a placeholder of its own, so an
/// operator who has already written a custom template gets "and here is the rest
/// of the problem list" without editing it.
fn aggregate(detail: &str, summary: &str) -> String {
    if detail.is_empty() {
        return summary.to_owned();
    }
    format!("{detail}\n{summary}")
}

/// The one-shot flag a service takes to prove its channel works, spelled once
/// so the two services cannot disagree about it. Each parses its own arguments,
/// because each also takes `--config`.
pub const TEST_NOTIFICATION_FLAG: &str = "--test-notification";

/// The webhook URL, or `None` when the deployment has not configured one.
///
/// Present-but-empty reads as unconfigured, the same way sync treats its Entra
/// credential: a Compose secret is a bind mount, so the file has to exist before
/// the container starts and is created empty. `EACCES` is the one error that does
/// not mean "not yet" -- the file exists and the deployment meant this process to
/// have it, so treating it as absent would silently disable notification behind a
/// message saying none was configured.
fn webhook_url(path: Option<&Path>) -> Result<Option<String>> {
    let Some(path) = path else {
        return Ok(None);
    };
    match std::fs::read_to_string(path) {
        Ok(raw) if raw.trim().is_empty() => Ok(None),
        // Re-read through `secret::read`, which is where the permission rule
        // lives: this file is a credential and must not be world-readable.
        Ok(_) => Ok(Some(kerbridge_core::secret::read(path)?)),
        // This arm never reaches `secret::read`, so the diagnosis is asked for
        // by name: one sentence for this credential, whichever read was refused.
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            bail!("{}", kerbridge_core::secret::denial(path))
        }
        Err(_) => Ok(None),
    }
}

/// Whether TLS validation is turned off for this URL, and the checks that make
/// that a deliberate act rather than a default.
///
/// The URL is the channel's only authentication for common receivers, so a
/// connection that does not authenticate its peer lets a network attacker
/// capture it -- posting forged `info` events into the operator's channel, which
/// mutes the alarm, and reading the directory-derived text in every event body.
/// The opt-in is therefore keyed on the *host*: a lab receiver can be named, and
/// pointing the deployment at a different one turns validation back on rather
/// than silently carrying the exemption over.
fn insecure_opt_in(url: &str, component: &str, named: Option<&str>) -> Result<bool> {
    let parsed = Url::parse(url).context("the webhook URL file does not contain a URL")?;
    let host = parsed.host_str().unwrap_or_default().to_owned();
    let insecure = !host.is_empty() && named == Some(host.as_str());

    match parsed.scheme() {
        "https" => {}
        // Plaintext is strictly worse than an unvalidated certificate -- it hands
        // the URL to anyone on the path -- so it takes the same explicit opt-in.
        "http" if insecure => {}
        "http" => bail!(
            "the webhook URL is http://: the URL is the channel's only authentication and this \
             would publish it to the network. Use https://, or name {host} in \
             notify.insecure_host if this is a lab"
        ),
        scheme => bail!("the webhook URL scheme is {scheme}://; only https:// is a webhook"),
    }

    if insecure {
        eprintln!(
            "[{component}] WARNING: notify.insecure_host={host} -- the notification channel \
             does not authenticate its receiver. Anyone on the path can capture the webhook URL \
             and post forged events with it"
        );
    } else if let Some(named) = named {
        eprintln!(
            "[{component}] notify.insecure_host={named} does not name the webhook's host, so \
             TLS validation stays on"
        );
    }
    Ok(insecure)
}

/// Public roots by default, from the image's `ca-certificates` bundle so they
/// refresh with the base rather than with a recompile -- the same argument the
/// broker's JWKS client makes.
///
/// An operator CA is *added* to those rather than replacing them: a self-hosted
/// receiver behind a private CA is the case it exists for, and making it
/// exclusive would break a public receiver the moment someone also has a private
/// one. That is unlike `kerbridge-core::tls`, which refuses public roots outright
/// -- an LDAPS bind has exactly one legitimate peer and this does not.
///
/// The timeout spans connect, TLS, headers and body, because every one of those
/// is a place a receiver can simply stop answering.
fn http_client(
    timeout: Duration,
    ca_file: Option<&Path>,
    insecure: bool,
) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_native_certs(true)
        .tls_built_in_webpki_certs(true)
        .timeout(timeout);
    if let Some(path) = ca_file {
        let pem = std::fs::read(path)
            .with_context(|| format!("reading notify.ca_file from {}", path.display()))?;
        let certs = reqwest::Certificate::from_pem_bundle(&pem)
            .with_context(|| format!("parsing notify.ca_file from {}", path.display()))?;
        // An empty store here would leave the public roots in place and look
        // entirely healthy, so a file carrying no certificate is refused for the
        // same reason `kerbridge-core::tls` refuses one.
        if certs.is_empty() {
            bail!("notify.ca_file {} contains no certificate", path.display());
        }
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }
    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder.build().context("building the notification HTTP client")
}

#[cfg(test)]
mod tests;
