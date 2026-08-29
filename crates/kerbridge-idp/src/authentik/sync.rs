//! The authentik adapter: the REST directory, behind the directory seam.
//!
//! Owns what one instance costs a cycle -- the API token, and a full read of
//! every user and group -- and hands the mirror a whole enumeration or nothing
//! at all. There is no cursor and no shadow: authentik has no delta, no
//! group-side change filter and invisible deletions, so every cycle is a full
//! read and absence in it is the only deletion channel. The seam takes no event
//! input, not even a wake-up: an authentik event is absent exactly for a
//! blueprint or worker change, so a push feed would miss the changes that matter.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use kerbridge_notify::{Event, Notifier, Severity};

use super::Settings;
use super::client::AuthentikClient;
use super::wire::assemble;
use crate::sync::{
    CredentialState, DirectorySource, Progress, SourceError, SourceSnapshot, Subject, build_desired,
};

/// One authentik instance, read over its REST API.
///
/// Nothing about the directory this feeds -- no bind identity, no OU -- is
/// reachable from here: the fields below are the whole of what crosses the seam.
pub struct AuthentikSource {
    /// This source's name, the subject of every problem raised below the seam.
    source: String,
    url: String,
    credential_file: PathBuf,
    /// The admission group's pk (a uuid): who may hold Kerberos tickets. Required.
    admission_group_id: String,
    /// The device-grant group's pk, if the deployment names one.
    grant_group_id: Option<String>,
    /// Group pks to mirror beyond the admission-group closure.
    allowlist: Vec<String>,
    /// Days of headroom the last cycle measured on the sync credential, from the
    /// self-scoped `/core/tokens/` read. `None` until a cycle has measured it, or
    /// whenever the token is set never to expire -- either way there is no
    /// countdown to run. Refreshed each cycle rather than at startup, so a
    /// rotated token's new deadline is picked up with nothing to restart.
    measured_days: Option<i64>,
    notifier: Arc<Notifier>,
}

impl AuthentikSource {
    pub fn new(settings: &Settings, source: &str, notifier: Arc<Notifier>) -> Self {
        Self {
            source: source.to_owned(),
            url: settings.url.clone(),
            credential_file: settings.sync_credential_file.clone(),
            admission_group_id: settings.admission_group_id.clone(),
            grant_group_id: settings.device_grant_group_id.clone(),
            allowlist: settings.extra_group_ids.clone(),
            measured_days: None,
            notifier,
        }
    }

    /// This source's sync credential -- the API token the directory is read with
    /// -- or `None` while the operator has yet to paste one in.
    ///
    /// Empty means the token does not exist yet: a deployment that has not got
    /// there, not a fault, so the source is skipped and re-checked next cycle.
    ///
    /// Unlike Entra's, there is **no shape to refuse locally**: an authentik API
    /// token is an opaque string, so the prompt's words are the only local
    /// defence and a wrong token fails identically to a right one until the read.
    /// `EACCES` is still an error rather than "not yet", for
    /// the reason [`kerbridge_core::secret::denial`] records: a compose secret is
    /// a bind mount whose host mode reaches the container unchanged.
    fn credential(&self) -> Result<Option<String>> {
        match std::fs::read_to_string(&self.credential_file) {
            Ok(raw) if raw.trim().is_empty() => Ok(None),
            Ok(_) => Ok(Some(kerbridge_core::secret::read(&self.credential_file)?)),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                anyhow::bail!("{}", kerbridge_core::secret::denial(&self.credential_file))
            }
            // Absent is the fresh-deployment case, and anything else here is a
            // path that is not there either.
            Err(_) => Ok(None),
        }
    }

    /// The enumeration, narrowed to the population the realm should hold.
    fn snapshot(&self, read: crate::sync::Enumeration) -> SourceSnapshot {
        // The device-grant group joins the closure roots the way an allowlist
        // entry does: someone held only by it gets a directory object and no
        // admission, so the two groups are additive, never alternatives.
        let mut roots: Vec<Subject> = self.allowlist.iter().cloned().map(Subject::new).collect();
        let grant = self.grant_group_id.clone().map(Subject::new);
        roots.extend(grant.clone());
        let admission = Subject::new(self.admission_group_id.clone());
        let (desired, refused) = build_desired(read, &admission, &roots);
        SourceSnapshot { desired, admission, grant, refused }
    }
}

#[async_trait::async_trait]
impl DirectorySource for AuthentikSource {
    async fn advance(&mut self) -> Result<Progress, SourceError> {
        let credential = match self.credential() {
            Ok(Some(token)) => token,
            Ok(None) => {
                return Ok(Progress::Idle(format!(
                    "no sync credential in {}: source {} is idle until one appears",
                    self.credential_file.display(),
                    self.source
                )));
            }
            Err(e) => return Err(SourceError::Credential(format!("credential unreadable: {e:#}"))),
        };
        // Rebuilt every cycle rather than cached, so a rotated token is picked up
        // by the next cycle with nothing to restart.
        let client = AuthentikClient::new(&self.url, credential)
            .map_err(|e| SourceError::Unreachable(format!("authentik client: {e:#}")))?;

        // Measured before the read, best-effort: the self-scoped token read is a
        // different endpoint from the directory, and its headroom feeds
        // `credential_state`, which the loop consults on the *next* cycle. A
        // failure to measure leaves the last good reading standing rather than
        // clobbering it, so a transient blip does not blank the countdown.
        if let Some(days) = client.measure_expiry(kerbridge_core::time::now_unix()).await {
            self.measured_days = Some(days);
        }

        let subject = self.credential_subject();
        let read = async {
            let users = client.read_users().await?;
            let groups = client.read_groups().await?;
            Ok::<_, SourceError>((users, groups))
        }
        .await;
        let (users, groups) = match read {
            Ok(pages) => {
                // A read got through, so the token the operator was warned about
                // has been rotated or was never the problem.
                self.notifier.resolve_subject("sync-credential-expired", &subject).await;
                pages
            }
            Err(e @ SourceError::CredentialRejected(_)) => {
                // Reported on its own channel, which is why the seam does not
                // count it: a second, vaguer alarm for one condition is noise.
                self.notifier
                    .send(
                        Event::new("sync-credential-expired", Severity::Error, e.to_string())
                            .subject(&subject),
                    )
                    .await;
                return Err(e);
            }
            Err(e) => return Err(e),
        };

        let read = assemble(&users, &groups).map_err(SourceError::NotWhole)?;
        Ok(Progress::Complete(self.snapshot(read)))
    }

    /// authentik reports an API token's own expiry to the bearer through the
    /// self-scoped `/core/tokens/` read, so the last cycle's measurement is the
    /// answer -- no operator assertion, which would go stale the first time the
    /// token is rotated. `Unknown` until a cycle has measured it, and for a token
    /// set never to expire: neither has a countdown to run.
    fn credential_state(&self) -> CredentialState {
        match self.measured_days {
            Some(days) => CredentialState::Measured { days },
            None => CredentialState::Unknown,
        }
    }

    /// The sync credential is an API token on a dedicated service account, not a
    /// registration with an id this file holds, so the source name is the whole
    /// of what its problems are keyed by.
    fn credential_subject(&self) -> String {
        self.source.clone()
    }
}
