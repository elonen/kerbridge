//! The helper's log file: `%APPDATA%\KerBridge\kerbridge.log`.
//!
//! A tray agent has no console, and its most interesting failures happen while
//! nobody is watching, so the log is the diagnostic surface -- "Open log" in the
//! menu points here. Deliberately tiny: append one line per event, open and
//! close per line so the unprivileged tray, the elevated `--enroll` one-shot and
//! the CLI can all write the same file without a lock protocol.
//!
//! Size is bounded by rotation and never by truncation: a machine in a
//! sustained fault writes continuously, and emptying the file at the cap would
//! destroy the onset of the fault exactly when somebody is asking for it. Past
//! [`MAX_BYTES`] the log moves aside into `kerbridge.log.1.gz`, [`KEEP`]
//! generations deep.
//!
//! Rotation runs once per process, before its first line: the writers share the
//! file with no lock, and a process's own start is the only moment it can speak
//! for.
//!
//! **Never log a token, a ticket, or a refresh token.** Call sites pass reasons
//! and identities, never credentials.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Once;

use flate2::Compression;
use flate2::write::GzEncoder;

use crate::config;

/// Rotate a log larger than this, at the next start. Re-injection is floored at
/// one a minute (`agent::MIN_REFRESH_DELAY`), so ten megabytes is weeks of a
/// machine failing every cycle and a lifetime of a healthy one.
const MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Compressed generations kept behind the live log.
const KEEP: u32 = 3;

pub fn info(msg: &str) {
    write("INFO", msg);
}

pub fn warn(msg: &str) {
    write("WARN", msg);
}

pub fn error(msg: &str) {
    write("ERROR", msg);
}

/// Append `[stamp] LEVEL message`. Silent on failure: logging must never be the
/// reason an operation fails.
pub fn write(level: &str, msg: &str) {
    let Some(path) = config::log_path() else {
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    static ROTATED: Once = Once::new();
    ROTATED.call_once(|| rotate(&path));
    // Format first, write once. `File` is unbuffered, so `writeln!` would issue
    // one `write_all` per format fragment; append mode makes each of those atomic
    // but not the group, and concurrent writers then interleave *inside* a record
    // rather than between records. One write per line is what makes the lock-free
    // sharing above true.
    let line = format!("{} {level:<5} {msg}\n", crate::time::local_stamp(crate::time::now()));
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = f.write_all(line.as_bytes());
    }
}

/// Move an oversized log aside, compressed, keeping [`KEEP`] generations.
///
/// Every step is best-effort: a rotation that cannot finish leaves a log that
/// is still written to, which matters more than its size, and the next start
/// tries again.
fn rotate(path: &Path) {
    if !std::fs::metadata(path).is_ok_and(|m| m.len() > MAX_BYTES) {
        return;
    }
    // Rename first, so every writer -- including this one -- carries on into a
    // fresh file while the old one is read at leisure. The rename is also the
    // lock test: on Windows it fails against a handle opened without sharing
    // delete, and a rotation skipped for that is simply retried at the next
    // start.
    let staged = suffixed(path, ".rotating");
    if std::fs::rename(path, &staged).is_err() {
        return;
    }
    // Compress before shifting the generations, so a failure here does not
    // spend the oldest one on nothing. A `.rotating` left behind stays readable
    // and the next rotation renames over it.
    let packed = suffixed(path, ".rotating.gz");
    if gzip(&staged, &packed).is_err() {
        return;
    }
    let _ = std::fs::remove_file(&staged);
    let _ = std::fs::remove_file(suffixed(path, &format!(".{KEEP}.gz")));
    for n in (1..KEEP).rev() {
        let _ = std::fs::rename(
            suffixed(path, &format!(".{n}.gz")),
            suffixed(path, &format!(".{}.gz", n + 1)),
        );
    }
    let _ = std::fs::rename(&packed, suffixed(path, ".1.gz"));
}

/// Appended to the whole name: `Path::with_extension` would eat the `.log`.
fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn gzip(src: &Path, dst: &Path) -> std::io::Result<()> {
    let mut input = std::fs::File::open(src)?;
    let mut out = GzEncoder::new(std::fs::File::create(dst)?, Compression::default());
    std::io::copy(&mut input, &mut out)?;
    out.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    fn oversized(dir: &Path) -> PathBuf {
        let path = dir.join("kerbridge.log");
        let mut text = String::from("the onset of the fault\n");
        text.push_str(&"x".repeat(MAX_BYTES as usize));
        std::fs::write(&path, text).expect("writes the log");
        path
    }

    fn unpack(path: &Path) -> String {
        let mut text = String::new();
        flate2::read::GzDecoder::new(std::fs::File::open(path).expect("the generation exists"))
            .read_to_string(&mut text)
            .expect("it is gzip");
        text
    }

    /// The common case by far: rotation must not disturb a log nobody is
    /// filling, or a healthy machine loses its history for no reason.
    #[test]
    fn a_log_under_the_cap_is_left_alone() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("kerbridge.log");
        std::fs::write(&path, b"one line\n").expect("writes the log");
        rotate(&path);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one line\n");
        assert!(!suffixed(&path, ".1.gz").exists());
    }

    /// The point of the whole module: the history survives the cap, and the
    /// live log is gone rather than emptied so the next line starts a new one.
    #[test]
    fn an_oversized_log_becomes_a_compressed_generation() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = oversized(dir.path());
        rotate(&path);
        assert!(!path.exists(), "the live log moved aside");
        assert!(unpack(&suffixed(&path, ".1.gz")).starts_with("the onset of the fault\n"));
        assert!(!suffixed(&path, ".rotating").exists(), "no staging left behind");
        assert!(!suffixed(&path, ".rotating.gz").exists());
    }

    /// Three generations, then the oldest goes -- otherwise the cap is not a cap.
    #[test]
    fn generations_shift_down_and_the_oldest_is_dropped() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("kerbridge.log");
        for n in 1..=KEEP {
            let generation = suffixed(&path, &format!(".{n}.gz"));
            gzip(
                &{
                    let raw = dir.path().join(format!("raw{n}"));
                    std::fs::write(&raw, format!("generation {n}")).expect("writes");
                    raw
                },
                &generation,
            )
            .expect("packs");
        }
        oversized(dir.path());
        rotate(&path);
        assert!(unpack(&suffixed(&path, ".1.gz")).starts_with("the onset of the fault\n"));
        assert_eq!(unpack(&suffixed(&path, ".2.gz")), "generation 1");
        assert_eq!(unpack(&suffixed(&path, ".3.gz")), "generation 2");
        assert!(!suffixed(&path, ".4.gz").exists(), "generation 3 is dropped, not kept");
    }

    /// A first run has no log at all, and rotation is the first thing that
    /// touches one.
    #[test]
    fn a_missing_log_rotates_to_nothing() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("kerbridge.log");
        rotate(&path);
        assert!(!path.exists());
        assert!(!suffixed(&path, ".1.gz").exists());
    }
}
