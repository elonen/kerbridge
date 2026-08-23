//! Generate `kbconfig.1` from the command definition, at build time.
//!
//! **No committed copy**, for the reason `kerbridge-setup/build.rs` states: a
//! page listing subcommands and options goes stale the first time one changes
//! and nothing fails when it does. This one is rendered from `src/cli.rs` --
//! the same definition `--help` prints.
//!
//! Section **1**, not 8: `kbconfig` installs to `/usr/bin` because an operator
//! runs it on an admin host, and `/usr/sbin` is not on a non-root `PATH` on any
//! Debian release.
//!
//! One page, not one per verb, unlike `kbsetup` and `kbmanage`.
//!
//! The cost is that `clap_mangen` renders a SUBCOMMANDS entry as a cross
//! reference whether or not the page exists, so this one points at
//! `kbconfig-check(1)` and seven more that are neither generated nor installed.
//! Generating them is what makes those resolve; nothing else does.
//!
//! The page lands in `OUT_DIR`. `cargo build -p kerbridge-config
//! --message-format=json` names the directory, which is how the packaging rule
//! finds it without knowing cargo's hash layout.

use std::path::Path;

// `Parser`, `Subcommand` and `PathBuf` arrive with the include below, which is
// the whole command definition verbatim.
use clap::CommandFactory;

include!("src/cli.rs");

fn main() -> std::io::Result<()> {
    println!("cargo::rerun-if-changed=src/cli.rs");
    println!("cargo::rerun-if-changed=build.rs");
    let out = std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR");
    let dir = Path::new(&out);

    let mut page = Vec::new();
    clap_mangen::Man::new(Cli::command()).section("1").render(&mut page)?;
    std::fs::write(dir.join("kbconfig.1"), page)
}
