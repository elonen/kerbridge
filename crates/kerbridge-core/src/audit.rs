//! The audit file: the record that outlives the container that wrote it.
//!
//! Every line written here is also on the writer's own console, and that copy is
//! the one that does not survive. Docker's json-file log belongs to a *container
//! instance*, so any recreate -- an image bump, every iteration of a dev loop --
//! starts a new container with an empty log and takes the old one's history with
//! it. A compose `logging:` block buys rotation and no more: the driver has no
//! path option, and no block survives a recreate. So a durable trail has to be a
//! file the process writes itself, onto a bind mount the operator keeps.
//!
//! What belongs in it is what *happened*: a ticket issued, a device grant made or
//! revoked. Refusals stay on the console with the rest of the diagnosis -- this
//! file answers "who got what, and when", not "why did that fail".
//!
//! Append-only, and rotated only by halves: retention is the operator's
//! `logrotate` or their log shipper, and this file's half of it is
//! [`AuditLog::reopen`]. `logrotate` renames the file aside and creates the
//! successor; until somebody reopens the path, every later record still lands in
//! the renamed inode, where nobody reads it again. The daemons call `reopen` on
//! `SIGUSR1`, which is what the `postrotate` line sends.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};

use crate::time::{now_unix, rfc3339};

/// An append-only record, or nothing at all.
pub struct AuditLog {
    /// Behind a lock only so that [`AuditLog::reopen`] can replace it: a record
    /// is written to whichever file was open when the write began, never to a
    /// handle being swapped out from under it.
    sink: Option<Mutex<File>>,
    path: Option<PathBuf>,
}

impl AuditLog {
    /// The file at `path`, or a sink that keeps nothing when there is none.
    ///
    /// A path that cannot be opened is an error, and every service treats it as
    /// fatal: the deployment asked for a durable record, and one that is
    /// silently absent is the failure this file exists to prevent. The
    /// permissions it needs are settled by the bind mount at `up`, so this fails
    /// at startup or not at all.
    pub fn open(path: Option<&Path>) -> Result<Self> {
        let Some(path) = path else { return Ok(Self::disabled()) };
        let sink = open_appending(path)?;
        Ok(Self { sink: Some(Mutex::new(sink)), path: Some(path.to_owned()) })
    }

    /// Open the path again, so that records stop landing in a file `logrotate`
    /// has already moved aside. Nothing at all when there is no path.
    ///
    /// The successor is opened before the lock is taken and swapped in under it,
    /// so a concurrent [`append`](Self::append) never sees a half-replaced
    /// handle: a record either precedes the swap and is in the rotated file, or
    /// follows it and is in the new one.
    ///
    /// A failure keeps the handle we have. Writing on into a rotated file loses
    /// less than dropping the record, and the caller says so on the console.
    pub fn reopen(&self) -> Result<()> {
        let (Some(sink), Some(path)) = (self.sink.as_ref(), self.path.as_ref()) else {
            return Ok(());
        };
        let fresh = open_appending(path)?;
        *sink.lock().unwrap_or_else(|held| held.into_inner()) = fresh;
        Ok(())
    }

    fn disabled() -> Self {
        Self { sink: None, path: None }
    }

    /// Where the record is kept, for the line a service prints at startup. An
    /// operator has no other way to tell a configured sink from an absent one.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Append one line, timestamped.
    ///
    /// The timestamp is this file's own. The console copy is dated by the log
    /// driver (or, in `issuerd`, by its own prefix); a file we write is dated by
    /// nobody.
    ///
    /// A failed write says so on the console and is otherwise ignored: an audit
    /// sink that could fail a request would be a way to stop issuance by filling
    /// a disk.
    pub fn append(&self, line: &str) {
        let Some(sink) = self.sink.as_ref() else { return };
        // Unbuffered, so no tail is held back at a crash: the file is O_APPEND,
        // and one small write per line lands whole and at the end however many
        // writers hold it open. The lock is held for that one write and is
        // `reopen`'s alone -- it buys nothing between writers, which O_APPEND
        // already orders.
        let record = format!("{} {line}\n", rfc3339(now_unix() as u32));
        let mut sink = sink.lock().unwrap_or_else(|held| held.into_inner());
        if let Err(e) = sink.write_all(record.as_bytes()) {
            eprintln!("[audit] LOST {}: {e}", record.trim_end());
        }
    }
}

/// The one way this file is ever opened. Startup and rotation open it the same
/// way, so a reopened sink cannot be a truncating one.
fn open_appending(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("audit log {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::epoch_from_rfc3339;

    fn scratch(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("kb-audit-{tag}-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    /// The acceptance criterion: a line an operator can date without the log
    /// driver's help.
    #[test]
    fn appends_a_well_formed_timestamped_line() {
        let path = scratch("wellformed");
        let audit = AuditLog::open(Some(&path)).expect("open");
        audit.append("[broker] GRANT req-1 alice ab12cd34");

        let written = std::fs::read_to_string(&path).expect("read");
        let line = written.strip_suffix('\n').expect("one terminated line");
        let (stamp, message) = line.split_once(' ').expect("stamp then message");
        assert_eq!(message, "[broker] GRANT req-1 alice ab12cd34");
        let stamped = epoch_from_rfc3339(stamp).expect("the stamp parses as our own format");
        assert!(stamped.abs_diff(now_unix()) < 60, "{stamp} is not about now");
        std::fs::remove_file(&path).expect("cleanup");
    }

    /// The whole point of the file: a restart adds to the history rather than
    /// replacing it.
    #[test]
    fn a_reopened_sink_appends_rather_than_truncates() {
        let path = scratch("append");
        AuditLog::open(Some(&path)).expect("open").append("[broker] GRANT req-1 alice ab12cd34");
        AuditLog::open(Some(&path)).expect("reopen").append("[broker] REVOKE req-2 alice ab12cd34");

        let written = std::fs::read_to_string(&path).expect("read");
        let lines: Vec<&str> = written.lines().collect();
        assert_eq!(lines.len(), 2, "got {written:?}");
        assert!(lines[0].ends_with("GRANT req-1 alice ab12cd34"));
        assert!(lines[1].ends_with("REVOKE req-2 alice ab12cd34"));
        std::fs::remove_file(&path).expect("cleanup");
    }

    /// Rotation, minus the signal that asks for it -- `issuerd`'s own test
    /// covers that half.
    #[test]
    fn a_reopen_writes_to_the_successor_and_leaves_the_rotated_file_alone() {
        let path = scratch("reopen");
        let rotated = path.with_extension("log.1");
        let _ = std::fs::remove_file(&rotated);

        let audit = AuditLog::open(Some(&path)).expect("open");
        audit.append("[broker] GRANT req-1 alice ab12cd34");
        // What `logrotate` does with `create`, in the order it does it.
        std::fs::rename(&path, &rotated).expect("rotate");
        audit.reopen().expect("reopen");
        audit.append("[broker] REVOKE req-2 alice ab12cd34");

        let rolled = std::fs::read_to_string(&rotated).expect("the rotated file");
        let current = std::fs::read_to_string(&path).expect("its successor");
        assert_eq!(rolled.lines().count(), 1, "{rolled:?}");
        assert!(rolled.trim_end().ends_with("GRANT req-1 alice ab12cd34"), "{rolled:?}");
        assert_eq!(current.lines().count(), 1, "{current:?}");
        assert!(current.trim_end().ends_with("REVOKE req-2 alice ab12cd34"), "{current:?}");
        std::fs::remove_file(&path).expect("cleanup");
        std::fs::remove_file(&rotated).expect("cleanup");
    }

    /// Unset is today's behavior: console only, and nothing to go wrong -- a
    /// rotation signal included, since a service gets one whether it keeps a
    /// file or not.
    #[test]
    fn without_a_path_it_keeps_nothing() {
        let audit = AuditLog::disabled();
        assert_eq!(audit.path(), None);
        audit.append("[broker] GRANT req-1 alice ab12cd34");
        audit.reopen().expect("a sink with no path has nothing to reopen");
    }
}
