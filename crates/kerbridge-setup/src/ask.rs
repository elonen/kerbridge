//! Asking the operator for a credential, at a terminal, with the echo off.
//!
//! **Why this exists at all.** The alternative is debconf, and a value that
//! transits debconf is written to `/var/cache/debconf/config.dat` and again to
//! the world-readable `config.dat-old`. That is why the install questions ask
//! for a realm, a URL and public identifiers and never for a secret, and why
//! the secret has to be collected somewhere else. Here the value goes from the
//! terminal into the file and nowhere in between: no argument list, no
//! environment, no shell history, no temporary file.
//!
//! **The echo is turned off through termios and restored by a guard**, so an
//! error on any path between the two puts it back. A `SIGINT` at the prompt is
//! the one case it does not cover -- the process dies with the terminal still
//! in no-echo mode, and the way out is `reset`. Restoring on a signal needs a
//! handler, and a handler needs `unsafe`, which this crate forbids.

use std::io::{BufRead, IsTerminal, Write};

use anyhow::{Context, Result, bail};
use nix::sys::termios::{LocalFlags, SetArg, tcgetattr, tcsetattr};

/// Is there an operator to ask?
///
/// Both streams, not just stdin: the prompt goes to stderr, and a run whose
/// prompts are being captured is one whose operator never sees the question.
pub fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

/// One line, with the echo off while it is typed.
///
/// The prompt goes to stderr so that it stays visible when stdout is being
/// read, and the trailing newline the terminal did not echo is supplied here --
/// without it whatever is printed next lands on the prompt's own line.
pub fn secret(prompt: &str) -> Result<String> {
    let mut stderr = std::io::stderr();
    write!(stderr, "{prompt}").context("writing the prompt")?;
    stderr.flush().context("writing the prompt")?;

    let value = {
        let _quiet = Echo::off()?;
        read_line()?
    };
    writeln!(stderr).context("writing the prompt")?;
    Ok(value)
}

/// One line, echoed. For an answer that is not a secret.
pub fn line(prompt: &str) -> Result<String> {
    let mut stderr = std::io::stderr();
    write!(stderr, "{prompt}").context("writing the prompt")?;
    stderr.flush().context("writing the prompt")?;
    read_line()
}

/// A yes-or-no whose default is taken by pressing return.
pub fn confirm(prompt: &str, default: bool) -> Result<bool> {
    let shown = if default { "[Y/n]" } else { "[y/N]" };
    loop {
        match line(&format!("{prompt} {shown} "))?.trim().to_ascii_lowercase().as_str() {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => eprintln!("  Answer y or n."),
        }
    }
}

/// Read to the end of the line, and treat end-of-input as an abort rather than
/// as an empty answer: a closed stdin cannot answer the next question either.
fn read_line() -> Result<String> {
    let mut buffer = String::new();
    let read = std::io::stdin().lock().read_line(&mut buffer).context("reading the answer")?;
    if read == 0 {
        bail!("stdin ended before the answer did; nothing was written");
    }
    Ok(buffer.trim_end_matches(['\r', '\n']).to_owned())
}

/// The terminal's echo, off for as long as this is alive.
struct Echo(nix::sys::termios::Termios);

impl Echo {
    fn off() -> Result<Self> {
        let stdin = std::io::stdin();
        let restore = tcgetattr(&stdin).context("reading the terminal mode")?;
        let mut quiet = restore.clone();
        quiet.local_flags.remove(LocalFlags::ECHO);
        // TCSAFLUSH, so that anything typed ahead of the prompt is discarded
        // rather than taken as the start of the credential and echoed.
        tcsetattr(&stdin, SetArg::TCSAFLUSH, &quiet).context("turning the terminal echo off")?;
        Ok(Self(restore))
    }
}

impl Drop for Echo {
    fn drop(&mut self) {
        let _ = tcsetattr(std::io::stdin(), SetArg::TCSAFLUSH, &self.0);
    }
}
