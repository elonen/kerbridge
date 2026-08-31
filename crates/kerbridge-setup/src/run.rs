//! Running the Samba tools, and the two rules that are not negotiable.
//!
//! **Nothing secret ever reaches argv.** Container argv is in the *host's*
//! process table -- there are no user namespaces in this deployment -- so
//! `--adminpass="$(cat ...)"` published the domain Administrator's password to
//! every local `ps` for the length of a provision. `samba-tool` prompts twice
//! when a password is absent from the command line and answers both prompts from
//! stdin when there is no tty -- so [`piped`] gives it none. Any caller
//! holding a credential uses it; [`plain`] takes `&[&str]` and is only ever
//! given values that may be read by anyone.
//!
//! **The environment is built, never inherited.** These run as root on a domain
//! controller, and `KRB5_CONFIG`, `KRB5CCNAME`, `PYTHONPATH` and `LD_PRELOAD`
//! all change where a Samba tool looks for things. `issuerd` states the same
//! rule at `crates/kerbridge-issuerd/src/issue.rs:491-495`; this is the second process
//! that forks these tools, and it agrees with the first rather than filtering.
//!
//! There is deliberately **no `timeout(1)`** here, which is where this parts
//! company with `issuerd`. That process is on the token path and a subprocess
//! that hangs is a request that never answers; this one is an operator standing
//! at a console watching a realm being created, and `samba-tool domain provision`
//! legitimately takes minutes. A deadline would abandon a half-provisioned
//! database, which is the one outcome the whole design exists to avoid.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use kerbridge_core::secret::Secret;

/// The `PATH` every subprocess gets. The same list `issuerd` compiles in, for
/// the same reason: `samba-tool` and the `ldb` tools live in `/usr/bin` on a
/// Debian DC, and a `PATH` inherited from an operator's shell is a path this
/// process did not choose.
///
/// `/usr/local` is not on it: these run as root against the live directory, so
/// a hand-built `samba-tool` or `ldbmodify` there would be the one that ran.
const SUBPROCESS_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// What a finished subprocess said, whatever it exited with.
pub struct Done {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Done {
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }

    /// The line to show an operator. Samba's tools put the useful sentence last
    /// and a stack trace above it, so the last non-empty line of stderr is the
    /// one worth carrying into an error; stdout answers for the tools that
    /// report a refusal there instead.
    pub fn reason(&self) -> &str {
        [&self.stderr, &self.stdout]
            .into_iter()
            .find_map(|s| last_sentence(s))
            .unwrap_or("no output")
    }
}

/// The last line of one captured stream that is worth showing.
///
/// "Last non-empty" is right until the tool crashes. `smb_panic` prints its
/// sentence, then a backtrace, then its own fault handler's trailer, so the
/// last line of a Samba panic is "Can not dump core: corepath not set up".
/// That line is true and it names nothing. Measured against samba-tool 4.22.10
/// failing to provision: the trailer was the whole of what kbsetup said, and
/// the sentence naming the fault was thirty lines above it. So a panic reports
/// its own line, and everything else keeps the old rule.
fn last_sentence(s: &str) -> Option<&str> {
    s.lines()
        .rev()
        .find(|l| l.starts_with("PANIC (pid ") || l.starts_with("INTERNAL ERROR: "))
        .or_else(|| s.lines().rev().find(|l| !l.trim().is_empty()))
}

/// Run a command whose failure the caller wants to inspect rather than inherit.
///
/// `Err` here means the program could not be started at all -- which on this
/// host means it is not installed, and is worth saying differently from "it ran
/// and refused".
pub fn attempt(argv: &[&str], stdin: Option<&str>) -> Result<Done> {
    let mut cmd = Command::new(argv[0]);
    cmd.args(&argv[1..])
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("PATH", SUBPROCESS_PATH);

    let mut child = cmd
        .spawn()
        .with_context(|| format!("running {}: is the package that ships it installed?", argv[0]))?;
    if let Some(text) = stdin {
        child
            .stdin
            .take()
            .expect("stdin was piped")
            .write_all(text.as_bytes())
            .with_context(|| format!("writing to {}'s stdin", argv[0]))?;
    }
    let out = child.wait_with_output().with_context(|| format!("waiting for {}", argv[0]))?;
    Ok(Done {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Run a command that has to succeed, and hand back its stdout.
pub fn plain(argv: &[&str]) -> Result<String> {
    finish(argv, attempt(argv, None)?)
}

/// The same, with a credential written to the process rather than shown to the
/// host. See the module comment.
pub fn piped(argv: &[&str], stdin: &str) -> Result<String> {
    finish(argv, attempt(&detached(argv), Some(stdin))?)
}

/// `argv`, to run in a session of its own -- which is what makes the credential
/// written to its stdin the one it reads.
///
/// `samba-tool` asks Python's `getpass`, and `getpass` opens /dev/tty in
/// preference to stdin: it falls back only when that open fails. A controlling
/// terminal is exactly what an operator running `kbsetup` at a console has, and
/// what `docker compose run` allocates unless told `-T` -- so without this the
/// password here is ignored and the run stops at a "New Password:" prompt no
/// one can answer. A new session has no controlling terminal, so the open
/// fails. `-w`, or `setsid` returns before the tool it started does, and its
/// exit status is the tool's.
///
/// Measured, samba-tool 4.22 in a container with a tty: `user create` with the
/// password on stdin blocked until it was killed, and the same line under
/// `setsid -w` read the password and reached the directory.
///
/// Only the credential path takes this. `plain` keeps the operator's session,
/// so a Ctrl-C at the console still reaches `samba-tool domain provision` --
/// the one call here that runs for minutes.
fn detached<'a>(argv: &[&'a str]) -> Vec<&'a str> {
    let mut out = vec!["setsid", "-w"];
    out.extend_from_slice(argv);
    out
}

fn finish(argv: &[&str], done: Done) -> Result<String> {
    if done.ok() {
        return Ok(done.stdout);
    }
    bail!("{} exited {:?}: {}", argv[0], done.code, done.reason())
}

/// `samba-tool` prompts on the same stream it reports on, and its prompts carry
/// no trailing newline -- so whatever it says next arrives glued to one. This
/// strips the three fragments rather than whole lines, for that reason, and
/// leaves everything else it said intact.
///
/// The "input may be echoed" warning describes `getpass`'s fallback for a
/// terminal it could not put into no-echo mode. It is not true of a pipe, and
/// showing it to an operator would only alarm them about a leak that is not
/// happening.
///
/// `password` is redacted from what is returned. Measured behaviour is that
/// `samba-tool` never echoes a piped credential, so this catches nothing today;
/// it is here because the result is printed, and the caller cannot see whether a
/// future tool version starts quoting what it was given.
pub fn without_password_prompts(text: &str, password: &Secret) -> String {
    let mut out = text.to_owned();
    for fragment in
        ["Warning: Password input may be echoed.", "New Password: ", "Retype Password: "]
    {
        out = out.replace(fragment, "");
    }
    // An empty needle matches at every boundary, which would splice the marker
    // between every character.
    if !password.expose().is_empty() {
        out = out.replace(password.expose(), "<redacted>");
    }
    out.lines().filter(|l| !l.trim().is_empty()).collect::<Vec<_>>().join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The prompts are answered from stdin only where /dev/tty cannot be opened.
    #[test]
    fn a_piped_credential_runs_in_a_session_of_its_own() {
        assert_eq!(
            detached(&["samba-tool", "user", "create", "svc-kerbridge-broker"]),
            ["setsid", "-w", "samba-tool", "user", "create", "svc-kerbridge-broker"]
        );
    }

    #[test]
    fn subprocess_path_never_searches_usr_local() {
        // A hand-built samba-tool or ldbmodify there would run as root against
        // the live directory.
        assert!(
            !SUBPROCESS_PATH.split(':').any(|dir| dir.starts_with("/usr/local")),
            "{SUBPROCESS_PATH} searches /usr/local"
        );
    }

    /// The measured shape of what `samba-tool user create` says over a pipe: two
    /// prompts with no newline of their own, the echo warning, and the one line
    /// that actually reports the outcome.
    #[test]
    fn the_prompt_filter_keeps_the_sentence_and_drops_the_prompts() {
        let raw = "New Password: Retype Password: Warning: Password input may be echoed.\n\
                   User 'svc-kerbridge-broker' created successfully\n";
        assert_eq!(
            without_password_prompts(raw, &Secret::new("Kb1-abc")),
            "User 'svc-kerbridge-broker' created successfully"
        );
    }

    /// A refusal must survive the filter -- it is the whole reason the output is
    /// read rather than discarded.
    #[test]
    fn a_refusal_survives_the_prompt_filter() {
        let raw = "New Password: Retype Password: \nERROR: Bad password\n";
        assert_eq!(without_password_prompts(raw, &Secret::new("Kb1-abc")), "ERROR: Bad password");
    }

    /// The result is printed, so a credential quoted back by a future
    /// `samba-tool` must not survive the filter.
    #[test]
    fn the_password_does_not_survive_the_filter() {
        let raw = "New Password: ERROR: password 'Kb1-abc' is too short\n";
        let said = without_password_prompts(raw, &Secret::new("Kb1-abc"));
        assert!(!said.contains("Kb1-abc"), "{said}");
        assert_eq!(said, "ERROR: password '<redacted>' is too short");
    }

    /// An empty needle matches at every boundary. `reserve` writes an empty
    /// credential to claim a path, so this is reachable rather than theoretical.
    #[test]
    fn an_empty_password_redacts_nothing() {
        let raw = "User 'svc' created successfully\n";
        assert_eq!(
            without_password_prompts(raw, &Secret::new("")),
            "User 'svc' created successfully"
        );
    }

    /// The measured shape of a Samba crash: the sentence, a backtrace, and the
    /// fault handler's own last line about a core file nobody asked for.
    #[test]
    fn a_panic_reports_its_own_sentence_and_not_the_core_dump_trailer() {
        let done = Done {
            code: Some(1),
            stdout: String::new(),
            stderr: "Setting up self join\n\
                     INTERNAL ERROR: Security context active token stack underflow! in  () () \
                     pid 6141 (4.22.10-Debian)\n\
                     PANIC (pid 6141): Security context active token stack underflow! in \
                     4.22.10-Debian\n\
                     BACKTRACE: 28 stack frames:\n \
                     #0 /usr/lib/x86_64-linux-gnu/samba/libgenrand-private-samba.so.0() [0x7f00]\n\
                     Can not dump core: corepath not set up\n"
                .to_owned(),
        };
        assert_eq!(
            done.reason(),
            "PANIC (pid 6141): Security context active token stack underflow! in 4.22.10-Debian"
        );
    }

    #[test]
    fn the_reason_is_the_last_thing_said() {
        let done = Done {
            code: Some(1),
            stdout: String::new(),
            stderr: "Traceback...\nERROR(ldb): the real reason\n\n".to_owned(),
        };
        assert_eq!(done.reason(), "ERROR(ldb): the real reason");
    }

    /// A tool that refused on stdout and said nothing on stderr still has a
    /// reason worth carrying.
    #[test]
    fn stdout_answers_when_stderr_is_silent() {
        let done = Done {
            code: Some(2),
            stdout: "refused: no such object\n".to_owned(),
            stderr: String::new(),
        };
        assert_eq!(done.reason(), "refused: no such object");
    }
}
