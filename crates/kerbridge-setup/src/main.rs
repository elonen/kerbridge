//! `kbsetup` -- the realm, the directory, the credentials only an operator has,
//! and the two questions about all of it: what is left, and does it still match.
//!
//! **setup -> config -> manage.** This brings a deployment into existence,
//! `kbconfig` owns the config set, `kbmanage` runs it day to day. Three tools,
//! three lifecycle phases.
//!
//! One binary with a verb each rather than one merged command that skips
//! whatever is already done. *Provisioning* is pinned to `samba-tool domain
//! provision` and stops at a provisioned DC; adding a cloud IdP source is a
//! day-2 act that re-runs the directory half alone; `secrets` asks for what no
//! program can generate; and `verify` sits on the daemon start path where the
//! others must never be. Nothing orders them mechanically -- `samba-tool`
//! without `-H` opens `sam.ldb` directly, so the directory half does not need
//! Samba running -- so the verbs keep them straight instead.
//!
//! `status` is the way in. It reads the others' answers and reports how far
//! through the procedure this host is, which is the question an operator has at
//! the terminal the packages left them at. It decides nothing of its own.
//!
//! It reads the config set **in process**, through `kerbridge-core` -- not
//! through `kbconfig get`, which the shell it replaces needs only because shell
//! cannot parse TOML, at a subprocess per value.

#![forbid(unsafe_code)]

use std::path::Path;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use kerbridge_core::config::Config;

mod ask;
mod cli;
mod dc;
mod directory;
mod krb5;
mod ldif;
mod pasted;
mod realm;
mod run;
mod secrets;
mod status;
#[cfg(test)]
mod testing;
mod verify;

fn main() -> ExitCode {
    match dispatch() {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("kbsetup: {e:#}");
            ExitCode::from(verify::ERROR)
        }
    }
}

fn dispatch() -> Result<u8> {
    let cli = cli::Cli::parse();
    let dir = match &cli.config {
        Some(path) => path.clone(),
        None => kerbridge_core::config::discover()?,
    };
    // Only `verify` has an exit code that is not "ran or failed", and it has one
    // because a maintainer script and a systemd unit both read it.
    match cli.command {
        cli::Command::Status => status::run(&dir),
        cli::Command::Realm { allow_example_realm } => {
            realm::run(&dir, allow_example_realm).map(|()| verify::MATCHES)
        }
        cli::Command::Directory => directory::run(&dir).map(|()| verify::MATCHES),
        cli::Command::Secrets { replace } => secrets::run(&dir, replace).map(|()| verify::MATCHES),
        cli::Command::Verify => verify::run(&dir),
    }
}

/// The config set, with the directory it came from named in any failure.
///
/// Every verb starts here. Loading is the same parse and the same cross-checks a
/// daemon does at startup, so a set this refuses is one no daemon would have
/// started on either.
pub(crate) fn load(dir: &Path) -> Result<Config> {
    Config::load(dir).with_context(|| format!("reading the config set in {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    /// The verbs, and no others. `kbsetup provision` in particular is not one of
    /// them -- the verb is `realm`, because provisioning is what it does when
    /// there is no realm and verifying is what it does when there is.
    /// GLOSSARY.md lists the spelling under `avoid`.
    #[test]
    fn the_command_surface_is_exactly_these_verbs() {
        let command = super::cli::Cli::command();
        let mut verbs: Vec<&str> = command.get_subcommands().map(|s| s.get_name()).collect();
        verbs.sort_unstable();
        assert_eq!(verbs, ["directory", "realm", "secrets", "status", "verify"]);
    }

    /// The escape hatch is a flag, not an environment variable: this is a
    /// shipped `/usr/sbin` program, and an env-var-only escape hatch is a poor
    /// interface for one. A Compose entrypoint translates its own variable into
    /// this flag.
    #[test]
    fn the_example_realm_escape_hatch_is_a_flag_on_realm() {
        let command = super::cli::Cli::command();
        let realm = command.get_subcommands().find(|s| s.get_name() == "realm").unwrap();
        assert!(realm.get_arguments().any(|a| a.get_id() == "allow_example_realm"));
    }

    /// `--config` reaches every verb, so `kbsetup --config DIR verify` and
    /// `kbsetup verify --config DIR` are the same command.
    #[test]
    fn the_config_directory_is_global() {
        let command = super::cli::Cli::command();
        let config = command.get_arguments().find(|a| a.get_id() == "config").unwrap();
        assert!(config.is_global_set());
    }

    /// clap panics on a malformed command definition, and only at runtime.
    #[test]
    fn the_command_definition_is_well_formed() {
        super::cli::Cli::command().debug_assert();
    }
}
