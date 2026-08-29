//! The Entra adapter: Microsoft Graph, behind the directory seam.
//!
//! Owns everything one tenant costs -- the credential, the app-only token, the
//! two delta cursors and the [`Shadow`] they patch -- and hands the mirror a
//! whole enumeration or nothing at all.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, bail};
use kerbridge_core::is_guid;
use kerbridge_core::time::{days_from_ymd, now_unix};
use kerbridge_notify::{Event, Notifier, Severity};

use super::client::{AuthRefused, GraphClient, GraphReader, StreamResult, TokenError};
use super::wire::Shadow;
use super::{SamSource, Settings};
use crate::sync::{
    CredentialState, DirectorySource, Progress, SourceError, SourceSnapshot, Subject, build_desired,
};

/// One Entra tenant, read over Graph.
///
/// Nothing about the directory this feeds -- no bind identity, no OU -- is
/// reachable from here: the fields below are the whole of what crosses the seam.
pub struct EntraSource {
    /// This source's name, the subject of every problem raised below the seam.
    source: String,
    tenant_id: String,
    client_id: String,
    credential_file: PathBuf,
    credential_expires: Option<String>,
    admission_group_id: String,
    grant_group_id: Option<String>,
    /// Group ids to mirror beyond the admission-group closure.
    allowlist: Vec<String>,
    sam_source: SamSource,
    notifier: Arc<Notifier>,
    shadow: Shadow,
    users_cursor: Option<String>,
    groups_cursor: Option<String>,
}

impl EntraSource {
    pub fn new(settings: &Settings, source: &str, notifier: Arc<Notifier>) -> Self {
        Self {
            source: source.to_owned(),
            tenant_id: settings.tenant_id.clone(),
            client_id: settings.sync_client_id.clone(),
            credential_file: settings.sync_credential_file.clone(),
            credential_expires: settings.sync_credential_expires.clone(),
            admission_group_id: settings.admission_group_id.clone(),
            grant_group_id: settings.device_grant_group_id.clone(),
            allowlist: settings.extra_group_ids.clone(),
            sam_source: settings.sam_source,
            notifier,
            shadow: Shadow::default(),
            users_cursor: None,
            groups_cursor: None,
        }
    }

    /// This source's sync credential -- the app-only client secret Graph is read
    /// with -- or `None` while the operator has yet to paste one in.
    ///
    /// A compose secret is a bind mount, so the file has to exist before the
    /// container starts and `prepare-state` creates it empty. Empty means
    /// the Graph app registration has not happened yet -- a deployment that has
    /// not got there, not a fault. So the source is skipped and re-checked next
    /// cycle rather than refused, and an operator who drops the secret in starts
    /// mirroring with nothing to restart.
    ///
    /// Only emptiness is treated this way. A credential that is present and
    /// wrong -- the *Secret ID* GUID, say -- is an error, and so is one this
    /// process is not allowed to read.
    ///
    /// `EACCES` in particular must not read as "not yet": it is the *likely*
    /// failure on Linux, where a compose secret is a bind mount and the host
    /// file's mode reaches the container unchanged. Sync runs unprivileged and
    /// reaches its secret through `BROKER_GID`, so a credential written `0600`
    /// owned by the root that wrote it is unreadable to it. Docker Desktop
    /// remaps the ownership and hides this, which is why the bench never saw it
    /// -- the same reason [`kerbridge_core::secret::read`] records.
    fn credential(&self) -> Result<Option<String>> {
        let shown = self.credential_file.display();
        match std::fs::read_to_string(&self.credential_file) {
            Ok(raw) if raw.trim().is_empty() => Ok(None),
            Ok(_) => {
                let value = kerbridge_core::secret::read(&self.credential_file)?;
                // Folded: `is_guid` is canonical-only, and an uppercase Secret
                // ID is still a Secret ID. Losing the fold is fail-open.
                if is_guid(&value.to_ascii_lowercase()) {
                    bail!(
                        "secret file {shown} contains a GUID: that is the credential's Secret ID, \
                         not its Value"
                    );
                }
                Ok(Some(value))
            }
            // This arm never reaches `secret::read`, so the diagnosis is asked
            // for by name -- and it prints the group the file actually has,
            // where a message written here could only name `$BROKER_GID`.
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                bail!("{}", kerbridge_core::secret::denial(&self.credential_file))
            }
            // Absent is the fresh-deployment case `prepare-state` creates,
            // and anything else here is a path that is not there either.
            Err(_) => Ok(None),
        }
    }

    /// One read of both delta streams, into the shadow they patch.
    ///
    /// Split from [`DirectorySource::advance`] so a test can drive the cursor
    /// recovery against a stubbed reader: the live client is built from a
    /// credential, and the recovery is otherwise observable only against a real
    /// tenant.
    async fn read(&mut self, graph: &impl GraphReader) -> Result<Progress, SourceError> {
        let subject = self.credential_subject();
        let token = match graph.acquire_token().await {
            Ok(token) => {
                // A token came back, so the credential the operator was told
                // about has been rotated or was never the problem.
                self.notifier.resolve_subject("sync-credential-expired", &subject).await;
                token
            }
            Err(e @ (TokenError::Expired(_) | TokenError::Invalid(_))) => {
                let why = e.to_string();
                self.notifier
                    .send(
                        Event::new("sync-credential-expired", Severity::Error, why.clone())
                            .subject(&subject),
                    )
                    .await;
                return Err(SourceError::CredentialRejected(why));
            }
            Err(TokenError::Other(e)) => {
                return Err(transport(e.context("acquiring Graph token")));
            }
        };

        let name = &self.source;
        // A resync (410) or corrupt cursor (400) on either stream forces a fresh full
        // read of both this cycle, from an empty shadow. At most one retry.
        let mut users_cursor = self.users_cursor.clone();
        let mut groups_cursor = self.groups_cursor.clone();
        let mut retried = false;
        loop {
            let users = outcome(
                graph.read_users(&token, users_cursor.as_deref()).await.map_err(transport)?,
            );
            let groups = outcome(
                graph.read_groups(&token, groups_cursor.as_deref()).await.map_err(transport)?,
            );
            use Outcome::*;
            // Read before the match consumes them: the discard arm has to name
            // which cause it met.
            let stalled = matches!(users, Stalled) || matches!(groups, Stalled);
            match (users, groups) {
                (Ready(uv, ucur), Ready(gv, gcur)) => {
                    self.shadow.apply_users(uv);
                    self.shadow.apply_groups(gv);
                    self.users_cursor = ucur;
                    self.groups_cursor = gcur;
                    return Ok(Progress::Complete(self.snapshot()));
                }
                (Corrupt, _) | (_, Corrupt) if !retried => {
                    self.notifier
                        .send(
                            Event::new(
                                "sync-cursor-corrupt",
                                Severity::Warning,
                                format!(
                                    "a stored delta cursor for source {name} was rejected (400); \
                                     resyncing from a fresh read"
                                ),
                            )
                            .subject(name)
                            // Already healed by the time it is reported -- the resync
                            // is happening. Listing it as an open problem would leave
                            // an entry nothing could ever clear.
                            .incident(),
                        )
                        .await;
                    self.shadow = Shadow::default();
                    users_cursor = None;
                    groups_cursor = None;
                }
                (Resync, _) | (_, Resync) if !retried => {
                    eprintln!("[sync/{name}] delta cursor expired (410); full resync");
                    self.shadow = Shadow::default();
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
                    return Err(SourceError::NotWhole(why.to_owned()));
                }
            }
            retried = true;
        }
    }

    /// The shadow, as the population the realm should hold.
    fn snapshot(&self) -> SourceSnapshot {
        // The device-grant group joins the closure roots the way an allowlist entry
        // does, so it synchronizes whether or not the operator nested it inside the
        // admission group. Someone held only by this group gets a directory object
        // and no admission, so no ticket -- the two groups are additive, never
        // alternatives.
        let mut roots: Vec<Subject> = self.allowlist.iter().cloned().map(Subject::new).collect();
        let grant = self.grant_group_id.clone().map(Subject::new);
        roots.extend(grant.clone());
        let admission = Subject::new(self.admission_group_id.clone());
        let (desired, refused) =
            build_desired(self.shadow.enumerate(self.sam_source), &admission, &roots);
        SourceSnapshot { desired, admission, grant, refused }
    }
}

#[async_trait::async_trait]
impl DirectorySource for EntraSource {
    async fn advance(&mut self) -> Result<Progress, SourceError> {
        let credential = match self.credential() {
            Ok(Some(secret)) => secret,
            Ok(None) => {
                return Ok(Progress::Idle(format!(
                    "no sync credential in {}: source {} is idle until one appears",
                    self.credential_file.display(),
                    self.source
                )));
            }
            Err(e) => return Err(SourceError::Credential(format!("credential unreadable: {e:#}"))),
        };
        // Rebuilt every cycle rather than cached, so a rotated secret is picked
        // up by the next cycle with nothing to restart. The connection pool it
        // drops matters within a cycle, not across one.
        let graph = GraphClient::new(self.tenant_id.clone(), self.client_id.clone(), credential)
            .map_err(|e| SourceError::Unreachable(format!("Graph client: {e:#}")))?;
        self.read(&graph).await
    }

    /// Entra's app-registration secret carries no expiry a read can see, so the
    /// answer is whatever the operator asserted.
    fn credential_state(&self) -> CredentialState {
        match days_remaining(self.credential_expires.as_deref(), now_unix()) {
            Some(days) => CredentialState::Asserted { days },
            None => CredentialState::Unknown,
        }
    }

    fn credential_subject(&self) -> String {
        format!("{}/{}", self.source, self.client_id)
    }
}

/// Days until an operator-asserted credential expiry. `None` when unset or
/// unparseable; negative once past.
///
/// `now` is unix seconds, supplied rather than read, for the reason the broker's
/// verifier gives: a function that reads the clock itself can only be tested
/// against the clock, and this one straddles a day boundary that would otherwise
/// make the test flake once every 86 400 runs.
fn days_remaining(expires: Option<&str>, now: u64) -> Option<i64> {
    let expiry = days_from_ymd(expires?)?;
    Some(expiry - (now / 86_400) as i64)
}

/// Anything Graph did not answer: the tenant is out of reach this cycle.
fn transport(e: anyhow::Error) -> SourceError {
    match e.downcast_ref::<AuthRefused>() {
        Some(refused) => SourceError::Credential(refused.to_string()),
        None => SourceError::Unreachable(format!("cycle error: {e:#}")),
    }
}

/// One stream's outcome, flattened so [`EntraSource::read`] can match users and
/// groups together regardless of element type.
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

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    use super::*;
    use crate::entra::wire::{RawGroup, RawUser};
    use crate::sync::conformance;

    const STORED_CURSOR: &str = "https://graph.microsoft.com/v1.0/users/delta?$deltatoken=stored";
    const STALE_USER: &str = "user-from-the-last-cycle";
    const FRESH_USER: &str = "user-from-the-retry";
    const USERS_RETRY_CURSOR: &str = "users-cursor-from-the-retry";
    const GROUPS_RETRY_CURSOR: &str = "groups-cursor-from-the-retry";

    /// The trap itself, rather than the shape check behind it -- that lives with
    /// `is_guid`'s own tests, and the LDAP bind password deliberately does not
    /// get this treatment: it has no Secret ID to be confused with, and a
    /// generated password could legitimately come out GUID-shaped.
    #[test]
    fn a_secret_id_is_refused_where_a_secret_value_is_not() {
        let refused = |value: &str| is_guid(&value.to_ascii_lowercase());
        let secret_id = "0a94cc71-1a92-4730-a2d9-8213912b4e6d";
        assert!(refused(secret_id), "a Secret ID is GUID-shaped");
        assert!(refused(&secret_id.to_ascii_uppercase()), "in uppercase too");
        assert!(!refused("aB3~qX9.some-real-looking-secret-value-Zz0"));
    }

    /// The expiry is an operator's assertion in a file, so the whole range
    /// matters: a date that has passed must read as negative headroom, not as a
    /// parse failure that reports nothing -- `report_credential` distinguishes
    /// "expires in 5 days" from "expired 5 days ago" only by the sign.
    #[test]
    fn credential_headroom_is_signed() {
        // 2026-07-25T12:00:00Z, midday so the assertions do not sit on a day
        // boundary the way a wall clock would.
        const NOW: u64 = 1_784_980_800;
        assert_eq!(days_remaining(None, NOW), None);
        assert_eq!(days_remaining(Some("not-a-date"), NOW), None);
        assert_eq!(days_remaining(Some("2026-07-25"), NOW), Some(0));
        assert_eq!(days_remaining(Some("2026-08-24"), NOW), Some(30));
        assert_eq!(days_remaining(Some("2026-07-20"), NOW), Some(-5));
    }

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
    }

    fn raw<T: serde::de::DeserializeOwned>(id: &str) -> T {
        serde_json::from_value(serde_json::json!({ "id": id, "displayName": id })).unwrap()
    }

    /// A reader whose user cursor stays corrupt after a full resync.
    struct CursorNeverRecovers;

    impl GraphReader for CursorNeverRecovers {
        async fn acquire_token(&self) -> Result<String, TokenError> {
            Ok("bearer".to_owned())
        }

        async fn read_users(
            &self,
            _token: &str,
            _cursor: Option<&str>,
        ) -> Result<StreamResult<RawUser>> {
            Ok(StreamResult::CursorCorrupt)
        }

        async fn read_groups(
            &self,
            _token: &str,
            _cursor: Option<&str>,
        ) -> Result<StreamResult<RawGroup>> {
            Ok(StreamResult::Complete { items: Vec::new(), delta_link: Some("g".to_owned()) })
        }
    }

    /// A source for direct [`EntraSource::read`] tests. Notifications are off.
    fn bare_source() -> EntraSource {
        EntraSource {
            source: "entra".to_owned(),
            tenant_id: String::new(),
            client_id: "11111111-1111-1111-1111-111111111111".to_owned(),
            credential_file: PathBuf::from("/nonexistent/credential"),
            credential_expires: None,
            admission_group_id: "77778888-bbbb-9999-cccc-0000dddd1111".to_owned(),
            grant_group_id: None,
            allowlist: Vec::new(),
            sam_source: SamSource::default(),
            notifier: Arc::new(Notifier::disabled("sync")),
            shadow: Shadow::default(),
            users_cursor: Some(STORED_CURSOR.to_owned()),
            groups_cursor: Some(STORED_CURSOR.to_owned()),
        }
    }

    /// A cursor that stays corrupt after full resync yields no snapshot.
    #[tokio::test]
    async fn a_read_that_never_recovers_yields_no_snapshot() {
        let mut source = bare_source();
        let verdict = match source.read(&CursorNeverRecovers).await {
            Ok(Progress::Complete(_)) => conformance::Verdict::Snapshot,
            Ok(Progress::Idle(why)) => panic!("idle is not a torn read: {why}"),
            Err(e) => conformance::Verdict::Refused(e.to_string()),
        };
        let why = conformance::a_torn_read_yields_no_snapshot(verdict);
        assert!(why.contains("still refused after a full resync"), "{why}");
    }

    /// Only a rejected credential does not count as a source failure.
    #[test]
    fn only_a_rejected_credential_is_spared_from_counting() {
        let errs = [
            SourceError::CredentialRejected("the app secret expired".to_owned()),
            transport(anyhow::anyhow!("the tenant did not answer")),
            SourceError::NotWhole(
                "a delta cursor was still refused after a full resync".to_owned(),
            ),
        ];
        for err in &errs {
            conformance::credential_rejection_is_the_only_non_failure(err);
        }
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

        let mut source = EntraSource {
            source: "entra".to_owned(),
            tenant_id: String::new(),
            client_id: "11111111-1111-1111-1111-111111111111".to_owned(),
            credential_file: PathBuf::from("/nonexistent/credential"),
            credential_expires: None,
            admission_group_id: "77778888-bbbb-9999-cccc-0000dddd1111".to_owned(),
            grant_group_id: None,
            allowlist: Vec::new(),
            sam_source: SamSource::default(),
            notifier: Arc::new(notifier),
            shadow: Shadow::default(),
            users_cursor: Some(STORED_CURSOR.to_owned()),
            groups_cursor: Some(STORED_CURSOR.to_owned()),
        };
        source.shadow.apply_users(vec![raw(STALE_USER)]);
        source.shadow.apply_groups(vec![raw("group-from-the-last-cycle")]);

        let graph = CorruptThenComplete::default();
        let progress = source.read(&graph).await;
        assert!(
            matches!(progress, Ok(Progress::Complete(_))),
            "the retry did not conclude a whole read"
        );

        let users: Vec<&str> = source.shadow.users.keys().map(String::as_str).collect();
        assert_eq!(users, [FRESH_USER], "the shadow kept what the corrupt cursor patched");
        assert!(source.shadow.groups.is_empty(), "a group survived the reset");

        let stored = || Some(STORED_CURSOR.to_owned());
        assert_eq!(*graph.users_seen.lock().unwrap(), [stored(), None], "users cursor");
        assert_eq!(*graph.groups_seen.lock().unwrap(), [stored(), None], "groups cursor");
        assert_eq!(source.users_cursor.as_deref(), Some(USERS_RETRY_CURSOR));
        assert_eq!(source.groups_cursor.as_deref(), Some(GROUPS_RETRY_CURSOR));

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
