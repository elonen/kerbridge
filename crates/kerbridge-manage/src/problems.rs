//! What is wrong right now, read off the host rather than out of the directory.
//!
//! Each service writes `problem-<event>.json` into its own subdirectory of
//! `notify.state_dir`, whether or not a webhook is configured. This reads that
//! set and judges nothing: it is the same answer a monitoring agent counting
//! the files gets, which is what makes it worth printing at all.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use anyhow::{Result, anyhow};
use kerbridge_core::problem::Problem;

pub struct Scan {
    /// Loudest first, and the oldest of an equal severity first.
    pub open: Vec<Problem>,
    /// What could not be read. One service's records are not another's, so a
    /// directory or a file this cannot read costs that record and not the
    /// listing.
    pub warnings: Vec<String>,
}

/// Every open problem under `state_dir`, one subdirectory per service.
///
/// Fails only when `state_dir` itself cannot be read, which is the one case
/// where an empty listing would be a lie. An absent directory is a deployment
/// that has raised nothing yet.
pub fn scan(state_dir: &Path) -> Result<Scan> {
    let mut scan = Scan { open: Vec::new(), warnings: Vec::new() };
    let services = match fs::read_dir(state_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            scan.warnings.push(format!(
                "{} does not exist: no service has written a problem record on this host",
                state_dir.display()
            ));
            return Ok(scan);
        }
        Err(e) => return Err(anyhow!(unreadable(state_dir, &e))),
    };
    for service in services.flatten().filter(|e| e.path().is_dir()) {
        let dir = service.path();
        let files = match fs::read_dir(&dir) {
            Ok(files) => files,
            Err(e) => {
                scan.warnings.push(unreadable(&dir, &e));
                continue;
            }
        };
        for path in files.flatten().map(|f| f.path()).filter(|p| is_open_record(p)) {
            let parsed =
                fs::read_to_string(&path).map_err(|e| unreadable(&path, &e)).and_then(|raw| {
                    serde_json::from_str::<Problem>(&raw)
                        .map_err(|e| format!("{} is not a problem record: {e}", path.display()))
                });
            match parsed {
                Ok(problem) => scan.open.push(problem),
                Err(why) => scan.warnings.push(why),
            }
        }
    }
    scan.open.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.since.cmp(&b.since)));
    Ok(scan)
}

/// `problem-*.json` and nothing else. A `recent-*.json` beside it is a
/// condition that has already cleared, and anything else in the directory is
/// the operator's.
fn is_open_record(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with("problem-") && n.ends_with(".json"))
}

/// The records are `0640` and owned by the service that wrote them, so a denial
/// here is a reader outside their group rather than a broken deployment.
fn unreadable(path: &Path, e: &std::io::Error) -> String {
    match e.kind() {
        ErrorKind::PermissionDenied => format!(
            "cannot read {}: {e}. The records are 0640 and owned by the service that wrote \
             them -- read them as root, or as their group",
            path.display()
        ),
        _ => format!("cannot read {}: {e}", path.display()),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use super::*;

    /// A `notify.state_dir` on disk, written the way the daemons write it: one
    /// subdirectory per service, named after the service.
    struct Dir(PathBuf);

    impl Dir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("kbmanage-problems-{}-{label}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn write(&self, service: &str, name: &str, body: &str) {
            let dir = self.0.join(service);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(name), body).unwrap();
        }

        /// One record as `kerbridge-notify` serializes it.
        fn record(&self, service: &str, event: &str, severity: &str, since: u64) {
            self.write(
                service,
                &format!("problem-{event}.json"),
                &format!(
                    r#"{{"event":"{event}","component":"{service}","severity":"{severity}",
                        "message":"{event} is true","open":true,"since":{since}}}"#
                ),
            );
        }

        fn scan(&self) -> Scan {
            scan(&self.0).unwrap()
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The host an operator runs this on before anything has gone wrong, and the
    /// one it is easiest to misread: nothing to read is not the same answer as
    /// nothing wrong, so it says which directory it looked in.
    #[test]
    fn a_directory_nothing_has_written_yet_is_not_a_failure() {
        let dir = Dir::new("absent");
        let missing = dir.0.join("never-created");
        let scan = scan(&missing).expect("an absent directory is a fresh deployment");
        assert!(scan.open.is_empty());
        assert!(scan.warnings[0].contains(&missing.display().to_string()), "{:?}", scan.warnings);
    }

    /// The file class is the whole integration for a monitoring agent, and it is
    /// the whole selector here: `recent-` has cleared, and everything else in the
    /// directory belongs to whoever put it there.
    #[test]
    fn only_the_open_records_are_listed_loudest_first() {
        let dir = Dir::new("classes");
        dir.record("sync", "sync-cycle-failing", "error", 1_000);
        dir.record("broker", "admission-group-missing", "warning", 500);
        dir.write("sync", "recent-sync-credential-expiring.json", r#"{"open":false}"#);
        dir.write("sync", "notes.txt", "the operator's own");
        let scan = dir.scan();
        assert!(scan.warnings.is_empty(), "{:?}", scan.warnings);
        let events: Vec<&str> = scan.open.iter().map(|p| p.event.as_str()).collect();
        assert_eq!(events, ["sync-cycle-failing", "admission-group-missing"]);
        assert_eq!(scan.open[0].component, "sync");
    }

    /// A record that cannot be parsed is one record. The listing exists to be
    /// read when something is already wrong, so it must not be the thing that
    /// hides the rest.
    #[test]
    fn a_corrupt_record_costs_that_record_and_no_other() {
        let dir = Dir::new("corrupt");
        dir.record("sync", "sync-cycle-failing", "error", 1_000);
        dir.write("sync", "problem-truncated.json", "{\"event\":");
        let scan = dir.scan();
        assert_eq!(scan.open.len(), 1);
        assert!(scan.warnings[0].contains("problem-truncated.json"), "{:?}", scan.warnings);
    }

    /// Each service owns its own directory and its own uid, so a reader the
    /// broker's group does not include still has a complete answer about sync.
    #[test]
    fn a_directory_that_cannot_be_read_costs_that_service_alone() {
        let dir = Dir::new("denied");
        dir.record("sync", "sync-cycle-failing", "error", 1_000);
        dir.record("broker", "admission-group-missing", "warning", 500);
        let locked = dir.0.join("broker");
        fs::set_permissions(&locked, PermissionsExt::from_mode(0o000)).unwrap();
        let denied = fs::read_dir(&locked).is_err();
        let scan = dir.scan();
        fs::set_permissions(&locked, PermissionsExt::from_mode(0o700)).unwrap();
        // Root reads a 0000 directory whatever the mode says, and there is
        // nothing to assert on a host where the denial cannot happen.
        if !denied {
            return;
        }
        assert_eq!(scan.open.len(), 1, "sync's records are still readable");
        assert!(scan.warnings[0].contains("0640"), "{:?}", scan.warnings);
    }

    /// `notify.state_dir` pointed at something that is not a directory. Nothing
    /// can be listed and an empty listing would read as "nothing is wrong", so
    /// this is the one shape that fails.
    #[test]
    fn a_state_dir_that_is_not_a_directory_fails_rather_than_lists_nothing() {
        let dir = Dir::new("not-a-directory");
        let file = dir.0.join("main.toml");
        fs::write(&file, "").unwrap();
        let Err(e) = scan(&file) else { panic!("a file is not a directory") };
        let err = format!("{e:#}");
        assert!(err.contains(&file.display().to_string()), "{err}");
    }
}
