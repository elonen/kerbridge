//! Generate `kbsetup.8` from the command definition, at build time.
//!
//! **No committed copy**, which is the whole point: a man page listing
//! subcommands and options is a page that goes stale the first time one changes,
//! and nothing fails when it does. This one is rendered from `src/cli.rs` -- the
//! same definition `--help` prints -- so staleness is impossible rather than
//! merely discouraged.
//!
//! Section **8**, not 1: `kbsetup` installs to `/usr/sbin` and is root-only, which
//! is FHS 3.0 §4.10's own test for that directory. `kbconfig.1` and `kbmanage.1`
//! are the other half of the same rule -- an operator runs those, and `/usr/sbin`
//! is not on a non-root `PATH` on any Debian release.
//!
//! The pages land in `OUT_DIR`. Nothing installs them yet -- the package manifest
//! that will is a separate work order -- and generating them now is what makes
//! that a copy step rather than an authoring job. `cargo build -p kerbridge-setup
//! --message-format=json` names the directory, which is how a packaging rule
//! finds it without knowing cargo's hash layout. Deliberately *not* announced
//! with `cargo::warning=`: that prints on every build of the workspace, and a
//! build that always warns is a build nobody reads warnings from.

use std::path::Path;

// `Parser`, `Subcommand` and `PathBuf` arrive with the include below, which is the
// whole command definition verbatim.
use clap::CommandFactory;

include!("src/cli.rs");

fn main() -> std::io::Result<()> {
    println!("cargo::rerun-if-changed=src/cli.rs");
    println!("cargo::rerun-if-changed=build.rs");
    let out = std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR");
    let dir = Path::new(&out);

    let command = Cli::command();
    // The top-level page, and one per verb. `clap_mangen` renders a subcommand's
    // own options and long help only on its own page, so a single page would
    // reduce every verb to one line -- which is the summary a hand-written page
    // would have given.
    //
    // Two lists elsewhere name these pages by hand and do not derive them:
    // `debian/stage-prebuilt` and `debian/kerbridge-issuerd.install`. A verb
    // added here ships no page until both grow; `dh_missing --fail-missing` is
    // what says so.
    write(dir, "kbsetup.8", &command)?;
    for sub in command.get_subcommands() {
        if sub.get_name() == "help" {
            continue;
        }
        // Rendered under its full name so the page's own header says
        // `kbsetup-realm` rather than `realm`. `Command::name` wants something
        // with a static lifetime and this process exits in a moment, so the one
        // string per verb is leaked rather than threaded through an arena.
        let full: &'static str = Box::leak(format!("kbsetup-{}", sub.get_name()).into_boxed_str());
        write(dir, &format!("{full}.8"), &sub.clone().name(full))?;
    }
    Ok(())
}

fn write(dir: &Path, name: &str, command: &clap::Command) -> std::io::Result<()> {
    let mut page = Vec::new();
    clap_mangen::Man::new(command.clone()).section("8").render(&mut page)?;
    std::fs::write(dir.join(name), page)
}
