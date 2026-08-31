//! The authentik IdP directory adapter, behind the directory-source seam.
//!
//! Each cycle reads all users and groups with an API token. It returns a complete
//! enumeration or no enumeration. authentik has no delta API or group change
//! filter. A push feed is insufficient because blueprint and worker changes do
//! not produce an authentik event.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use kerbridge_core::secret::Secret;
use kerbridge_notify::Notifier;

use super::Settings;
use super::client::AuthentikClient;
use super::wire::assemble;
use crate::sync::{
    Credential, CredentialAlarm, CredentialState, DirectorySource, Progress, Roots, SourceError,
    SourceSnapshot, Subject, credential_or_idle,
};

/// Narrow one complete enumeration only when every configured root that lacks
/// the admission root's planner freeze is visible.
fn complete_snapshot(
    read: crate::sync::Enumeration,
    roots: Roots,
) -> Result<SourceSnapshot, String> {
    let missing: Vec<&str> = roots
        .extra
        .iter()
        .filter(|root| !read.groups.contains_key(*root))
        .map(Subject::as_str)
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "configured authentik group root(s) absent from the read: {}; the credential may have \
             returned a coherent object-filtered subset, so no snapshot was published",
            missing.join(", ")
        ));
    }
    Ok(roots.narrow(read))
}

/// One authentik instance, read over its REST API.
///
/// Realm directory details such as the bind identity and OU do not cross the
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

    /// This source's sync credential -- the API token used to read the IdP directory
    /// -- or `None` while the operator has yet to paste one in, which is the
    /// state [`kerbridge_core::secret::read_optional`] defines: setup is
    /// incomplete, the source has not failed, and the next cycle looks again.
    ///
    /// Unlike Entra's, there is **no shape to refuse locally**: an authentik API
    /// token is an opaque string, so the prompt's words are the only local
    /// defence and a wrong token fails identically to a right one until the read.
    fn credential(&self) -> Result<Option<Secret>> {
        Ok(kerbridge_core::secret::read_optional(&self.credential_file)?.map(Secret::new))
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
        let roots = Roots::new(
            self.admission_group_id.clone(),
            self.grant_group_id.clone(),
            self.allowlist.iter().cloned(),
        );
        complete_snapshot(read, roots)
    }
}

#[async_trait::async_trait]
impl DirectorySource for AuthentikSource {
    async fn advance(&mut self) -> Result<Progress, SourceError> {
        let credential =
            match credential_or_idle(self.credential(), &self.credential_file, &self.source)? {
                Credential::Ready(token) => token,
                Credential::Missing(idle) => return Ok(idle),
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

        let alarm = CredentialAlarm::new(self.notifier.clone(), self.credential_subject());
        let read = async {
            let users = client.read_users().await?;
            let groups = client.read_groups().await?;
            Ok::<_, SourceError>((users, groups))
        }
        .await;
        let (users, groups) = match read {
            Ok(pages) => {
                // A successful read proves that the credential works.
                alarm.resolved().await;
                pages
            }
            Err(e @ SourceError::CredentialRejected(_)) => {
                return Err(alarm.rejected(e.to_string()).await);
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
        complete_snapshot(read, Roots::new(ADMISSION, grant, allowlist.iter().copied()))
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

    /// A visible configured root that holds nobody publishes. An empty group is
    /// legitimate, and it is not what a permission filter makes: the filter
    /// narrows the user list but leaves the hidden member's id in the root's
    /// `users`, so a *filtered* root is refused at `assemble` and never reaches
    /// here. Recorded in `testbench/authentik/captured/groups_partial_grant_page1.json`
    /// and pinned by `wire::tests::a_recorded_partial_grant_is_refused_as_a_dangling_id`.
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
