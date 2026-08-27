// The command surface, in the one file `build.rs` also reads.
//
// Nothing but `clap` is used here, and nothing from the rest of the crate,
// because `build.rs` `include!`s this file in order to generate the man page
// from it. That is what makes `kbconfig.1` impossible to leave stale: there is
// no committed copy to forget, and the page is the source of truth's own
// account of itself. Same shape as `kerbridge-setup/src/cli.rs`, for the same
// reason.
//
// Plain comments rather than `//!` for the same reason as there: an inner doc
// comment is only legal at the top of the file it ends up in, and this one ends
// up in the middle of `build.rs`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "kbconfig",
    version,
    about = "Validate the config set, read one value out of it, write a new set and the schema",
    long_about = "KerBridge's configuration CLI, usable before the realm exists.\n\n\
                  It reads and writes files and may reach the cloud IdP; it links no LDAP\n\
                  client and can never touch the directory. Everything that needs a live\n\
                  directory is in kbmanage, which is useless until bootstrap has finished."
)]
pub struct Cli {
    /// The config set's directory; every file in it is read
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Parse and cross-check every file. Offline, and exactly what a daemon
    /// does at startup.
    Check {
        /// Also probe the IdP: its discovery document, the issuer it publishes,
        /// and its signing keys. Operator-invoked, never on a startup or
        /// bootstrap path.
        #[arg(long)]
        online: bool,
    },
    /// One value, by dotted path -- realm.base_dn, sources.entra.ou.
    Get { path: String },
    /// The active source names, one per line.
    Sources,
    /// Every option this deployment sets, with the value it would use if it
    /// set none.
    Decisions,
    /// Carry the config set to this version: replay every recorded change, then
    /// write each file from this version's template with your answers in it.
    Upgrade {
        /// Say what would change and write nothing.
        ///
        /// Exits 0 when the set is already this version's shape and 2 when it
        /// is not, so a script can probe a set without writing to it.
        #[arg(long)]
        dry_run: bool,
    },
    /// Write the config set into a directory, with your answers already in it.
    Init {
        dir: PathBuf,
        /// One cloud IdP source, as `<name>[=<provider>]` -- `entra`, or
        /// `staff=entra` for a second source of the same provider under a name
        /// of its own. Repeatable. The provider defaults to the name.
        ///
        /// Each writes an idp_<name>.toml and adds <name> to main.sources.
        /// With none, the set names no source: a realm mid-bootstrap, not a
        /// broken one. Only this flag writes those three values, so --set may
        /// not name them.
        #[arg(long = "source", value_name = "NAME[=PROVIDER]")]
        sources: Vec<String>,
        /// One answer, as `<file>.<option>=<value>` --
        /// `realm.realm=EXAMPLE.SITE`,
        /// `idp_entra.provider_config.tenant_id=<uuid>`. Repeatable, and the
        /// paths are the ones `kbconfig decisions` prints under each file.
        ///
        /// An empty answer for an option the parser requires stops the whole
        /// write; an empty answer for any other option is left at its default.
        #[arg(long = "set", value_name = "PATH=VALUE")]
        set: Vec<String>,
        /// Overwrite files that are already there.
        #[arg(long)]
        force: bool,
    },
    /// Write the config schema into a directory, one document per file.
    Schema {
        dir: PathBuf,
        /// Overwrite files that are already there.
        #[arg(long)]
        force: bool,
    },
}
