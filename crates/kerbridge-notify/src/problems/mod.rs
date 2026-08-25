//! What is currently wrong, as files an operator can point anything at.
//!
//! One JSON file per condition, in a directory. The webhook is then one consumer
//! of this state rather than the only way out of the process: a deployment that
//! does not want a chat channel can point a Zabbix agent, a cron script or a
//! human at the same directory and get the same information. That inversion is
//! the reason this is a directory of files and not a private record -- a private
//! record makes the notifier the only exit.
//!
//! Two file classes, told apart by their name so a monitoring agent can count
//! one without parsing the other:
//!
//! - `problem-*.json` -- a condition that is still true. This set *is* the
//!   deployment's problem list.
//! - `recent-*.json` -- a condition that has been resolved, or an incident that
//!   had already healed when it was reported. Kept only because its last-notified
//!   stamp is still needed, and pruned once it is not.
//!
//! Keeping the stamp after a condition resolves is what makes flapping cheap to
//! handle: a condition that clears and comes back within the repeat interval is
//! not announced again, because the rate limit outlived the problem. No separate
//! flap mechanism is needed, and in particular none that a restart would forget --
//! a crash loop is exactly when conditions are raised and cleared repeatedly.
//!
//! Nothing here fails a caller. An unwritable directory costs the durability of
//! the rate limit and the integration surface, and is reported once; it does not
//! stop a service from running, and it does not stop the webhook from working.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use kerbridge_core::problem::Problem;

use crate::Event;

/// How a condition repeats, and therefore what makes it due again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Repeat {
    /// It is simply still true. Repeats on the configured interval.
    Persisting,
    /// It has a deadline. Notifies only as `days_remaining` crosses into a new
    /// step of [`BANDS`], and is silent between them however long that is.
    Countdown { days_remaining: i64 },
}

/// Whether an event opens something, or merely reports something.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Stays true until something clears it, and is listed as an open problem
    /// until then. Almost everything is one of these.
    Condition,
    /// Already over by the time it is reported -- a cursor that was rejected and
    /// resynced, say. Worth telling an operator once, but listing it as an open
    /// problem would leave a permanent entry that nothing can ever resolve.
    Incident,
}

/// The escalating schedule a countdown notifies on, ascending. Anything further
/// out than the last step is not yet worth an operator's attention.
const BANDS: [i64; 5] = [1, 3, 7, 14, 30];

/// Which step `days` falls in, or `None` when the deadline is beyond the last
/// one. Ascending order makes this the first step the value fits inside, so 8
/// days and 14 days share a band and only the crossing is notified.
fn band(days: i64) -> Option<i64> {
    BANDS.iter().copied().find(|step| days <= *step)
}

pub struct Problems {
    /// `None` keeps everything in memory, which is what a deployment that
    /// configures no directory gets -- and what it is told at startup.
    dir: Option<PathBuf>,
    /// event -> subject -> record. Nested rather than a joined key, so no
    /// separator character has to be forbidden in a subject.
    records: BTreeMap<String, BTreeMap<String, Problem>>,
}

impl Problems {
    /// Never fails. A missing directory is a fresh deployment; an unreadable or
    /// corrupt file is reported and skipped, because the alternative is a service
    /// that will not run until an operator repairs a rate limiter.
    ///
    /// The directory is created if it is absent but **never** re-permissioned if
    /// it is present. An operator who has set it group-`zabbix` and setgid so a
    /// monitoring agent can read it must not have that undone by a restart.
    pub fn load(dir: Option<PathBuf>, component: &str, interval_secs: u64, now: u64) -> Self {
        let mut records: BTreeMap<String, BTreeMap<String, Problem>> = BTreeMap::new();
        let Some(dir) = dir else {
            return Self { dir: None, records };
        };
        if !dir.exists()
            && let Err(e) = fs::create_dir_all(&dir)
        {
            eprintln!(
                "[{component}] cannot create the notification state directory {}: {e}. Problems \
                 are tracked in memory only, so a restart re-sends whatever is still outstanding",
                dir.display()
            );
            return Self { dir: None, records };
        }
        match fs::read_dir(&dir) {
            Err(e) => eprintln!(
                "[{component}] cannot read the notification state directory {}: {e}. Starting from \
                 an empty problem list -- outstanding events may be sent once more",
                dir.display()
            ),
            Ok(entries) => {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !is_state_file(&path) {
                        continue;
                    }
                    let parsed = fs::read_to_string(&path)
                        .ok()
                        .and_then(|raw| serde_json::from_str::<Problem>(&raw).ok());
                    let Some(problem) = parsed else {
                        eprintln!(
                            "[{component}] notification state file {} is unreadable; ignoring it",
                            path.display()
                        );
                        continue;
                    };
                    // A closed record exists only for its rate limit, so once the
                    // interval has passed it is telling nobody anything -- and a
                    // closed one that was never sent has none to preserve.
                    if !problem.open
                        && problem
                            .attempted_at
                            .is_none_or(|at| now.saturating_sub(at) > interval_secs)
                    {
                        let _ = fs::remove_file(&path);
                        continue;
                    }
                    records
                        .entry(problem.event.clone())
                        .or_default()
                        .insert(problem.subject.clone(), problem);
                }
            }
        }
        Self { dir: Some(dir), records }
    }

    /// Record that `event` is true, and answer whether to announce it.
    ///
    /// Deciding and marking together is deliberate: they must not be separated by
    /// an await, or two concurrent requests raising the same event both pass the
    /// check before either records it.
    ///
    /// `deliverable` is whether an announcement is possible at all -- a configured
    /// channel, and a severity at or above the floor. It gates the *stamp* as well
    /// as the answer, because an event that was never going to be sent must not
    /// consume the rate limit of one that would be.
    pub fn raise(
        &mut self,
        event: &Event,
        component: &str,
        now: u64,
        interval_secs: u64,
        deliverable: bool,
    ) -> bool {
        let existing = self.records.get(event.event).and_then(|s| s.get(&event.subject));
        let due = deliverable
            && match event.repeat {
                Repeat::Persisting => existing.is_none_or(|p| {
                    p.attempted_at.is_none_or(|at| now.saturating_sub(at) >= interval_secs)
                }),
                // A countdown is due only on entering a nearer band, so it is
                // silent for the weeks between two of them.
                Repeat::Countdown { days_remaining } => match band(days_remaining) {
                    None => false,
                    Some(step) => existing.is_none_or(|p| p.band.is_none_or(|had| step < had)),
                },
            };
        let problem = Problem {
            event: event.event.to_owned(),
            subject: event.subject.clone(),
            component: component.to_owned(),
            severity: event.severity,
            message: event.message.clone(),
            detail: event.detail.clone(),
            open: event.kind == Kind::Condition,
            since: existing.map_or(now, |p| p.since),
            attempted_at: if due { Some(now) } else { existing.and_then(|p| p.attempted_at) },
            // Always the band the deadline is in *now*, not only when something
            // was sent. A rotated credential moves the deadline back past the
            // last step, and that has to disarm the schedule -- otherwise the
            // next credential is silent at every step the previous one used up.
            band: match event.repeat {
                Repeat::Persisting => None,
                Repeat::Countdown { days_remaining } => band(days_remaining),
            },
        };
        self.store(problem, component);
        due
    }

    /// Mark every open record for `event` resolved, whatever subject it was
    /// raised under, and hand back the ones that were open.
    ///
    /// Resolving by event rather than by `(event, subject)` is what makes this
    /// usable at all. Several subjects describe the *symptom* -- the reason an
    /// admission-group lookup failed, the set of colliding names -- so a caller
    /// that has just proven the condition false has no way to name the subject it
    /// was raised under, and a reworded reason would strand the old record forever.
    ///
    /// Cheap when nothing is open: the in-memory mirror answers, and no syscall
    /// happens. The broker calls this on every successful directory lookup.
    pub fn resolve(&mut self, event: &str, component: &str) -> Vec<Problem> {
        let Some(subjects) = self.records.get_mut(event) else {
            return Vec::new();
        };
        let mut resolved = Vec::new();
        for problem in subjects.values_mut().filter(|p| p.open) {
            problem.open = false;
            resolved.push(problem.clone());
        }
        // Re-stored rather than deleted: the last-notified stamp is what stops a
        // condition that comes straight back from being announced again.
        for problem in &resolved {
            self.store(problem.clone(), component);
        }
        resolved
    }

    /// Resolve one subject of an event.
    ///
    /// For a condition that is about a specific thing and is disproved only by
    /// *that* thing succeeding -- one account the issuer refuses, one identity two
    /// directory objects claim. Clearing the whole event there would announce a
    /// recovery for a second broken account because the first one was fixed.
    pub fn resolve_one(&mut self, event: &str, subject: &str, component: &str) -> Option<Problem> {
        let resolved = {
            let problem = self.records.get_mut(event)?.get_mut(subject)?;
            if !problem.open {
                return None;
            }
            problem.open = false;
            problem.clone()
        };
        self.store(resolved.clone(), component);
        Some(resolved)
    }

    /// A one-line census of what is still true, for the aggregate half of every
    /// announcement -- so one event says both what just changed and what the
    /// deployment's whole problem list now is.
    pub fn open_summary(&self) -> String {
        let open: Vec<&Problem> =
            self.records.values().flat_map(|s| s.values()).filter(|p| p.open).collect();
        if open.is_empty() {
            return "no problems open".to_owned();
        }
        // Grouped by event already, so equal slugs are adjacent and no sort is
        // needed to collapse two subjects of one event into one name.
        let mut slugs: Vec<&str> = open.iter().map(|p| p.event.as_str()).collect();
        slugs.dedup();
        format!("{} open: {}", open.len(), slugs.join(", "))
    }

    /// Write one record, moving it between the two file classes if its openness
    /// changed. The stale name is removed first, so a resolved condition cannot
    /// leave a `problem-` file behind claiming it is still true.
    fn store(&mut self, problem: Problem, component: &str) {
        if let Some(dir) = &self.dir {
            let name = file_name(problem.open, &problem.event, &problem.subject);
            let stale = file_name(!problem.open, &problem.event, &problem.subject);
            let _ = fs::remove_file(dir.join(&stale));
            if let Err(e) = write_atomically(dir, &name, &problem) {
                eprintln!(
                    "[{component}] cannot write the notification state file {}: {e:#}. The rate \
                     limit is degraded to this process's memory",
                    dir.join(&name).display()
                );
            }
        }
        self.records
            .entry(problem.event.clone())
            .or_default()
            .insert(problem.subject.clone(), problem);
    }
}

/// Ours to read? Anything else in the directory is left strictly alone -- an
/// operator may well have put something there.
fn is_state_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name.ends_with(".json") && (name.starts_with("problem-") || name.starts_with("recent-"))
}

/// `problem-<event>.json`, or `problem-<event>__<hash>.json` when the event has a
/// subject. Subjects are arbitrary text -- a UPN, a list of names, a sentence -- so
/// they are hashed rather than spelled: a name has to be a legal, bounded, single
/// path component, and the real subject is in the body anyway.
fn file_name(open: bool, event: &str, subject: &str) -> String {
    let class = if open { "problem" } else { "recent" };
    if subject.is_empty() {
        format!("{class}-{event}.json")
    } else {
        format!("{class}-{event}__{:016x}.json", fnv1a(subject))
    }
}

/// FNV-1a, written out rather than taken from `std`, because `DefaultHasher` is
/// documented as not stable across releases and these names have to survive an
/// upgrade. Nothing here is security -- it only has to be a function.
fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in s.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// Written to a temporary name and renamed, so a reader never sees half a file.
///
/// Created `0640` explicitly rather than by umask, and the group is never set
/// here: that is what lets an operator `chgrp` the directory to their monitoring
/// agent's group and set the setgid bit, after which every file this writes is
/// group-owned by the agent and readable by it. Setting a group here would fight
/// that, and world-readable would publish account names and error text to every
/// uid on the host.
fn write_atomically(dir: &Path, name: &str, problem: &Problem) -> anyhow::Result<()> {
    let body = serde_json::to_string_pretty(problem)?;
    // Leading dot, so a half-written file is not one `is_state_file` will read.
    let tmp = dir.join(format!(".{name}.tmp"));
    let mut file =
        fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o640).open(&tmp)?;
    file.write_all(body.as_bytes())?;
    file.write_all(b"\n")?;
    drop(file);
    // Set again rather than trusted from `mode` above, which the process umask
    // masks: under `umask 077` the file would be created 0600 and the operator's
    // monitoring group -- the entire reason these files exist -- could not read
    // it. `set_permissions` is not masked, so this is the mode that holds.
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o640))?;
    fs::rename(&tmp, dir.join(name))?;
    Ok(())
}

#[cfg(test)]
mod tests;
