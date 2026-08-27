use super::*;
use crate::Severity;

const DAY: u64 = 86_400;

fn problems() -> Problems {
    Problems::load(None, "test", DAY, 0)
}

/// A scratch directory of this test's own, removed when it returns.
fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kb-notify-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn event(slug: &'static str, subject: &str, repeat: Repeat) -> Event {
    let mut e = Event::new(slug, Severity::Error, "m").subject(subject);
    e.repeat = repeat;
    e
}

fn due(p: &mut Problems, subject: &str, repeat: Repeat, now: u64) -> bool {
    p.raise(&event("e", subject, repeat), "test", now, DAY, true)
}

#[test]
fn a_persisting_condition_repeats_on_the_interval_and_not_before() {
    let mut p = problems();
    assert!(due(&mut p, "", Repeat::Persisting, 0));
    assert!(!due(&mut p, "", Repeat::Persisting, DAY - 1));
    assert!(due(&mut p, "", Repeat::Persisting, DAY));
    assert!(!due(&mut p, "", Repeat::Persisting, DAY + 1));
    assert!(due(&mut p, "", Repeat::Persisting, 2 * DAY));
}

/// The flood the two policies exist to keep apart: thirty days of daily
/// cycles produce five events, not thirty.
#[test]
fn a_countdown_notifies_once_per_step_and_five_times_in_all() {
    let mut p = problems();
    let sent: Vec<i64> = (0..=40)
        .rev()
        .filter(|days| due(&mut p, "", Repeat::Countdown { days_remaining: *days }, 0))
        .collect();
    assert_eq!(sent, vec![30, 14, 7, 3, 1]);
}

/// Time passing is not what makes a countdown due -- only the step moving
/// is. Otherwise the interval would leak back in and undo the whole split.
#[test]
fn a_countdown_stays_silent_between_steps_however_long_it_takes() {
    let mut p = problems();
    assert!(due(&mut p, "", Repeat::Countdown { days_remaining: 30 }, 0));
    for day in 1..16 {
        assert!(
            !due(&mut p, "", Repeat::Countdown { days_remaining: 30 - day }, day as u64 * DAY),
            "day {day}"
        );
    }
    assert!(due(&mut p, "", Repeat::Countdown { days_remaining: 14 }, 16 * DAY));
}

/// Beyond the last step there is nothing to report: a credential with a year
/// left is not news, and reporting it once would consume the 30-day step.
#[test]
fn a_deadline_past_the_last_step_is_silent() {
    let mut p = problems();
    assert!(!due(&mut p, "", Repeat::Countdown { days_remaining: 31 }, 0));
    assert!(!due(&mut p, "", Repeat::Countdown { days_remaining: 365 }, 0));
    assert!(due(&mut p, "", Repeat::Countdown { days_remaining: 30 }, 0));
}

/// An expiry that has already passed is in the last step, not out of the
/// schedule: `sync-credential-expiring` is raised with negative headroom.
#[test]
fn a_deadline_already_passed_lands_in_the_last_step() {
    let mut p = problems();
    assert!(due(&mut p, "", Repeat::Countdown { days_remaining: 0 }, 0));
    assert!(!due(&mut p, "", Repeat::Countdown { days_remaining: -5 }, 30 * DAY));
}

/// A rotated credential moves the deadline back out, and the next one
/// deserves its own five warnings rather than silence at every step it has
/// already been through.
#[test]
fn a_deadline_that_moves_back_out_re_arms_the_schedule() {
    let mut p = problems();
    assert!(due(&mut p, "", Repeat::Countdown { days_remaining: 3 }, 0));
    assert!(!due(&mut p, "", Repeat::Countdown { days_remaining: 100 }, DAY));
    assert!(due(&mut p, "", Repeat::Countdown { days_remaining: 30 }, 2 * DAY));
}

/// Two groups carrying the admission marker are two problems. Keying on the
/// event alone would report the first and hide the second for a day.
#[test]
fn subjects_do_not_suppress_each_other() {
    let mut p = problems();
    assert!(due(&mut p, "CN=one", Repeat::Persisting, 0));
    assert!(due(&mut p, "CN=two", Repeat::Persisting, 0));
    assert!(!due(&mut p, "CN=one", Repeat::Persisting, 1));
    assert!(!due(&mut p, "CN=two", Repeat::Persisting, 1));
}

/// Different events are independent for the same reason, and a subject
/// carrying the character a joined key would have used is not special.
#[test]
fn events_do_not_suppress_each_other_and_a_subject_may_hold_anything() {
    let mut p = problems();
    let raise = |p: &mut Problems, slug, subject| {
        p.raise(&event(slug, subject, Repeat::Persisting), "test", 0, DAY, true)
    };
    assert!(raise(&mut p, "a", "x|y"));
    assert!(raise(&mut p, "b", "x|y"));
    assert!(raise(&mut p, "a", "x"));
    assert!(!raise(&mut p, "a", "x|y"));
}

/// An event that was never going to be delivered -- below the severity floor,
/// or no channel at all -- must not consume the rate limit of one that would
/// have been. It is still recorded, so the directory shows it either way.
#[test]
fn an_undeliverable_event_is_recorded_without_spending_the_rate_limit() {
    let mut p = problems();
    assert!(!p.raise(&event("e", "", Repeat::Persisting), "test", 0, DAY, false));
    assert!(p.open_summary().starts_with("1 open"));
    assert!(p.raise(&event("e", "", Repeat::Persisting), "test", 1, DAY, true));
}

/// The reason it is durable at all: a restart must not re-send everything
/// outstanding, which is what a crash loop turns into a flood.
#[test]
fn the_state_survives_a_restart() {
    let dir = scratch("restart");
    let load = |now| Problems::load(Some(dir.clone()), "test", DAY, now);

    let mut first = load(0);
    assert!(first.raise(&event("e", "s", Repeat::Persisting), "test", 1_000, DAY, true));
    let counting = event("c", "s", Repeat::Countdown { days_remaining: 9 });
    assert!(first.raise(&counting, "test", 1_000, DAY, true));

    let mut restarted = load(1_001);
    assert!(!restarted.raise(&event("e", "s", Repeat::Persisting), "test", 1_001, DAY, true));
    let closer = event("c", "s", Repeat::Countdown { days_remaining: 8 });
    assert!(!restarted.raise(&closer, "test", 1_001, DAY, true));
    let closer = event("c", "s", Repeat::Countdown { days_remaining: 7 });
    assert!(restarted.raise(&closer, "test", 1_001, DAY, true));

    fs::remove_dir_all(&dir).unwrap();
}

/// A corrupt file must not stop the service. It costs one round of repeated
/// events, which is strictly better than a broker that will not start because
/// its rate limiter has a typo in it.
#[test]
fn a_corrupt_file_is_skipped_rather_than_failing() {
    let dir = scratch("corrupt");
    fs::write(dir.join("problem-e.json"), b"{ not json").unwrap();

    let mut p = Problems::load(Some(dir.clone()), "test", DAY, 0);
    assert!(p.raise(&event("e", "", Repeat::Persisting), "test", 0, DAY, true));
    // And it overwrote the unreadable file on the way past, rather than
    // leaving the next restart to make the same discovery.
    let mut restarted = Problems::load(Some(dir.clone()), "test", DAY, 1);
    assert!(!restarted.raise(&event("e", "", Repeat::Persisting), "test", 1, DAY, true));

    fs::remove_dir_all(&dir).unwrap();
}

/// An unwritable directory is a degraded rate limiter, not a failure: the
/// event still goes out, and only the memory of it is lost on restart.
#[test]
fn an_unwritable_directory_still_notifies() {
    let mut p = Problems::load(Some(PathBuf::from("/proc/nonexistent-dir")), "test", DAY, 0);
    assert!(p.raise(&event("e", "s", Repeat::Persisting), "test", 0, DAY, true));
    assert!(!p.raise(&event("e", "s", Repeat::Persisting), "test", 1, DAY, true));
}

/// The integration surface: an open condition is a `problem-` file, and
/// resolving it moves it out of that class so a monitoring agent counting
/// them sees it go.
#[test]
fn an_open_condition_is_a_problem_file_and_resolving_moves_it() {
    let dir = scratch("files");
    let mut p = Problems::load(Some(dir.clone()), "test", DAY, 0);
    p.raise(&event("admission-group-missing", "", Repeat::Persisting), "test", 0, DAY, true);
    assert!(dir.join("problem-admission-group-missing.json").exists());

    let resolved = p.resolve("admission-group-missing", "test");
    assert_eq!(resolved.len(), 1);
    assert!(!dir.join("problem-admission-group-missing.json").exists());
    assert!(dir.join("recent-admission-group-missing.json").exists());
    assert_eq!(p.open_summary(), "no problems open");

    fs::remove_dir_all(&dir).unwrap();
}

/// Flap control, and the reason the stamp outlives the problem: a condition
/// that clears and comes straight back is not announced a second time.
/// Without this, one flapping condition is noisier than a standing one.
#[test]
fn a_condition_that_comes_straight_back_is_not_announced_again() {
    let mut p = problems();
    assert!(due(&mut p, "", Repeat::Persisting, 0));
    assert_eq!(p.resolve("e", "test").len(), 1);
    assert!(!due(&mut p, "", Repeat::Persisting, 60), "a flap was announced twice");
    // ...but it is announced again once the interval has genuinely passed.
    assert!(due(&mut p, "", Repeat::Persisting, DAY));
}

/// Resolving reports only what was actually open, so a caller that clears
/// unconditionally on every success does not announce a recovery per request.
#[test]
fn resolving_what_is_not_open_reports_nothing() {
    let mut p = problems();
    assert!(p.resolve("e", "test").is_empty());
    assert!(due(&mut p, "", Repeat::Persisting, 0));
    assert_eq!(p.resolve("e", "test").len(), 1);
    assert!(p.resolve("e", "test").is_empty());
}

/// Resolving takes every subject at once. A caller that has just proven the
/// condition false cannot name the subject it was raised under -- several of
/// them describe the symptom, not a stable thing.
#[test]
fn resolving_clears_every_subject_of_the_event() {
    let mut p = problems();
    assert!(due(&mut p, "CN=one", Repeat::Persisting, 0));
    assert!(due(&mut p, "CN=two", Repeat::Persisting, 0));
    assert!(p.open_summary().starts_with("2 open"));
    assert_eq!(p.resolve("e", "test").len(), 2);
    assert_eq!(p.open_summary(), "no problems open");
}

/// A condition about one account is cleared only by *that* account working
/// again. Clearing the whole event would announce a recovery for a second
/// broken account because the first one was fixed.
#[test]
fn resolving_one_subject_leaves_its_siblings_open() {
    let mut p = problems();
    assert!(due(&mut p, "alice", Repeat::Persisting, 0));
    assert!(due(&mut p, "bob", Repeat::Persisting, 0));

    let resolved = p.resolve_one("e", "alice", "test").expect("alice was open");
    assert_eq!(resolved.subject, "alice");
    assert!(p.open_summary().starts_with("1 open"), "{}", p.open_summary());

    // Idempotent, so a per-request caller may clear unconditionally.
    assert!(p.resolve_one("e", "alice", "test").is_none());
    assert!(p.resolve_one("e", "nobody", "test").is_none());
    assert!(p.resolve_one("absent", "alice", "test").is_none());
}

/// An incident has already healed, so listing it as open would leave an entry
/// nothing could ever resolve -- a permanent problem on the operator's board.
#[test]
fn an_incident_is_reported_but_never_open() {
    let dir = scratch("incident");
    let mut p = Problems::load(Some(dir.clone()), "test", DAY, 0);
    let incident = Event::new("sync-cursor-corrupt", Severity::Warning, "resynced").incident();
    assert!(p.raise(&incident, "test", 0, DAY, true));
    assert_eq!(p.open_summary(), "no problems open");
    assert!(dir.join("recent-sync-cursor-corrupt.json").exists());

    fs::remove_dir_all(&dir).unwrap();
}

/// A closed record is kept only for its rate limit, so once that has expired
/// it is pruned -- otherwise the directory grows for the life of the
/// deployment. An open one is never pruned, however old.
#[test]
fn a_closed_record_is_pruned_once_its_rate_limit_expires() {
    let dir = scratch("prune");
    let mut p = Problems::load(Some(dir.clone()), "test", DAY, 0);
    p.raise(&event("gone", "", Repeat::Persisting), "test", 1_000, DAY, true);
    p.raise(&event("still-here", "", Repeat::Persisting), "test", 1_000, DAY, true);
    p.resolve("gone", "test");

    let reloaded = Problems::load(Some(dir.clone()), "test", DAY, 1_000 + DAY + 1);
    assert!(!dir.join("recent-gone.json").exists(), "a stale record was kept");
    assert!(dir.join("problem-still-here.json").exists(), "an open problem was pruned");
    assert!(reloaded.open_summary().starts_with("1 open"));

    fs::remove_dir_all(&dir).unwrap();
}

/// Group-readable so an operator can `chgrp` the directory to their
/// monitoring agent's group and have it work, and not world-readable because
/// these files carry account names and error text.
#[test]
fn state_files_are_group_readable_and_never_world_readable() {
    let dir = scratch("mode");
    let mut p = Problems::load(Some(dir.clone()), "test", DAY, 0);
    p.raise(&event("e", "", Repeat::Persisting), "test", 0, DAY, true);

    let mode = fs::metadata(dir.join("problem-e.json")).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o640, "{mode:o}");

    fs::remove_dir_all(&dir).unwrap();
}

/// A subject may be any text at all, so it is hashed into the file name --
/// and two subjects of one event must not land on the same file.
#[test]
fn a_subject_becomes_a_bounded_distinct_file_name() {
    let awkward = "CN=Ünïcode/../..\0 name with spaces";
    assert_eq!(file_name(true, "e", awkward), format!("problem-e__{:016x}.json", fnv1a(awkward)));
    assert_ne!(file_name(true, "e", "one"), file_name(true, "e", "two"));
    // Openness is what the class prefix says, and nothing else changes.
    assert_eq!(file_name(false, "e", ""), "recent-e.json");
}
