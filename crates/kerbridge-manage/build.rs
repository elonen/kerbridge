//! Generate `kbmanage.1` from the command definition, at build time.
//!
//! **No committed copy**, for the reason `kerbridge-setup/build.rs` states: a
//! page listing subcommands and options goes stale the first time one changes
//! and nothing fails when it does. This one is rendered from `src/cli.rs` --
//! the same definition `--help` prints.
//!
//! Section **1**, not 8: `kbmanage` installs to `/usr/bin` because a human runs
//! it off-host as themselves.
//!
//! One page per verb as well as the top-level one, as `kbsetup` does: `group`,
//! `cloud`, `device` and `doctor` each carry their own arguments and their own
//! warnings, and `clap_mangen` renders a subcommand's long help only on its own
//! page. The nested verbs (`kbmanage group member add`) get no page: their
//! parent's SUBCOMMANDS section cross references them -- `kbmanage-group-list(1)`
//! and sixteen more -- and nothing generates or installs those, so their
//! arguments are documented nowhere.
//!
//! The pages land in `OUT_DIR`. `cargo build -p kerbridge-manage
//! --message-format=json` names the directory, which is how the packaging rule
//! finds it without knowing cargo's hash layout.

use std::path::Path;

// `Args`, `Parser`, `Subcommand` and `PathBuf` arrive with the include below,
// which is the whole command definition verbatim.
use clap::CommandFactory;

include!("src/cli.rs");

fn main() -> std::io::Result<()> {
    println!("cargo::rerun-if-changed=src/cli.rs");
    println!("cargo::rerun-if-changed=build.rs");
    let out = std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR");
    let dir = Path::new(&out);

    let command = Cli::command();
    write(dir, "kbmanage.1", &command)?;
    for sub in command.get_subcommands() {
        if sub.get_name() == "help" {
            continue;
        }
        // Rendered under its full name so the page's own header says
        // `kbmanage-group` rather than `group`. `Command::name` wants something
        // with a static lifetime and this process exits in a moment, so the one
        // string per verb is leaked rather than threaded through an arena.
        let full: &'static str = Box::leak(format!("kbmanage-{}", sub.get_name()).into_boxed_str());
        write(dir, &format!("{full}.1"), &sub.clone().name(full))?;
    }
    Ok(())
}

fn write(dir: &Path, name: &str, command: &clap::Command) -> std::io::Result<()> {
    let mut page = Vec::new();
    clap_mangen::Man::new(command.clone()).section("1").render(&mut page)?;
    std::fs::write(dir.join(name), page)
}
