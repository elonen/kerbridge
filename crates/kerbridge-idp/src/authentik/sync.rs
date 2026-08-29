//! The authentik directory (IdP) adapter, behind the directory-source seam.
//!
//! Each cycle reads all users and groups with an API token. It returns a complete
//! enumeration or no enumeration. authentik has no delta API or group change
//! filter. A push feed is insufficient because blueprint and worker changes do
//! not produce an authentik event.

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

/// Narrow one complete enumeration only when every configured root that lacks
/// the admission root's planner freeze is visible.
fn complete_snapshot(
    read: crate::sync::Enumeration,
    admission: Subject,
    grant: Option<Subject>,
    roots: Vec<Subject>,
) -> Result<SourceSnapshot, String> {
    let missing: Vec<&str> =
        roots.iter().filter(|root| !read.groups.contains_key(*root)).map(Subject::as_str).collect();
    if !missing.is_empty() {
        return Err(format!(
            "configured authentik group root(s) absent from the read: {}; the credential may have \
             returned a coherent object-filtered subset, so no snapshot was published",
            missing.join(", ")
        ));
    }
    let (desired, refused) = build_desired(read, &admission, &roots);
    Ok(SourceSnapshot { desired, admission, grant, refused })
}

/// One authentik instance, read over its REST API.
///
/// Directory (realm) details such as the bind identity and OU do not cross the
/// directory-source seam.
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

    /// This source's sync credential -- the API token used to read the directory (IdP)
    /// -- or `None` while the operator has yet to paste one in, which is the
    /// state [`kerbridge_core::secret::read_optional`] defines: setup is
    /// incomplete, the source has not failed, and the next cycle looks again.
    ///
    /// Unlike Entra's, there is **no shape to refuse locally**: an authentik API
    /// token is an opaque string, so the prompt's words are the only local
    /// defence and a wrong token fails identically to a right one until the read.
    fn credential(&self) -> Result<Option<String>> {
        kerbridge_core::secret::read_optional(&self.credential_file)
    }

    /// The enumeration, narrowed to the population the realm should hold, once
    /// every configured non-admission root is visible.
    ///
    /// authentik applies object permissions before pagination and its count. A
    /// credential can therefore return a self-consistent `200` that hides a
    /// complete, disconnected subgraph. Dangling-id checks catch a permissions
    /// cut through a visible membership edge, but not a configured extra or
    /// device-grant root hidden together with everything it reaches. Publishing
    /// that subset would retire the missing objects. The admission root already
    /// has the planner's no-operations freeze; these roots need the equivalent
    /// invariant here, before a snapshot exists.
    fn snapshot(&self, read: crate::sync::Enumeration) -> Result<SourceSnapshot, String> {
        // The device-grant group joins the closure roots the way an allowlist
        // entry does: someone held only by it gets a directory (realm) object and no
        // admission, so the two groups are additive, never alternatives.
        let mut roots: Vec<Subject> = self.allowlist.iter().cloned().map(Subject::new).collect();
        let grant = self.grant_group_id.clone().map(Subject::new);
        roots.extend(grant.clone());
        let admission = Subject::new(self.admission_group_id.clone());
        complete_snapshot(read, admission, grant, roots)
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
        // Rebuild the client to use a rotated token without a restart.
        let client = AuthentikClient::new(&self.url, credential)
            .map_err(|e| SourceError::Unreachable(format!("authentik client: {e:#}")))?;

        // Expiry measurement is advisory and uses a separate endpoint. Keep the
        // last value if this read fails, so a transient error does not remove the
        // countdown.
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
                // A successful read proves that the credential works.
                self.notifier.resolve_subject("sync-credential-expired", &subject).await;
                pages
            }
            Err(e @ SourceError::CredentialRejected(_)) => {
                // Use the credential event only. A second source-failure event
                // would report the same condition.
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
        self.snapshot(read).map(Progress::Complete).map_err(SourceError::NotWhole)
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::sync::{DesiredGroup, DesiredUser, Enumeration, Membership};

    const ADMISSION: &str = "9665b31a-b1e6-42e6-9204-45e14bb0eb21";
    const EXTRA: &str = "0af8e7f1-82d8-4265-9f16-844061421ae4";
    const USER: &str = "19427827-69e8-4d8f-9db4-b90bd5ff364e";

    /// A coherent visible subgraph: one non-empty admission group and its user.
    /// The configured EXTRA root and everything reachable only from it have been
    /// hidden together, so no visible membership id dangles.
    fn coherent_filtered_read() -> Enumeration {
        let admission = Subject::new(ADMISSION);
        let user = Subject::new(USER);
        Enumeration {
            users: BTreeMap::from([(
                user.clone(),
                DesiredUser {
                    display_name: "Ada Lovelace".to_owned(),
                    name_candidates: vec![],
                    enabled: true,
                },
            )]),
            groups: BTreeMap::from([(
                admission.clone(),
                DesiredGroup { display_name: "kb-admission".to_owned() },
            )]),
            membership: BTreeMap::from([(admission, vec![Membership::User(user)])]),
            refused: BTreeMap::new(),
        }
    }

    fn snapshot(
        read: Enumeration,
        grant: Option<&str>,
        allowlist: &[&str],
    ) -> Result<SourceSnapshot, String> {
        let mut roots: Vec<Subject> = allowlist.iter().copied().map(Subject::new).collect();
        let grant = grant.map(Subject::new);
        roots.extend(grant.clone());
        complete_snapshot(read, Subject::new(ADMISSION), grant, roots)
    }

    #[test]
    fn a_coherent_hidden_extra_root_yields_no_snapshot() {
        let why = snapshot(coherent_filtered_read(), None, &[EXTRA])
            .err()
            .expect("a hidden configured root is not a snapshot");
        assert!(why.contains(EXTRA), "{why}");
    }

    #[test]
    fn a_coherent_hidden_device_grant_root_yields_no_snapshot() {
        let why = snapshot(coherent_filtered_read(), Some(EXTRA), &[])
            .err()
            .expect("a hidden configured root is not a snapshot");
        assert!(why.contains(EXTRA), "{why}");
    }

    #[test]
    fn a_visible_configured_root_preserves_the_snapshot() {
        let mut read = coherent_filtered_read();
        read.groups.insert(
            Subject::new(EXTRA),
            DesiredGroup { display_name: "authentik Admins".to_owned() },
        );
        read.membership.insert(Subject::new(EXTRA), vec![]);
        let snapshot = snapshot(read, Some(EXTRA), &[EXTRA]).expect("every root is visible");
        assert!(snapshot.desired.groups.contains_key(&Subject::new(EXTRA)));
    }
}
