// The command surface, in the one file `build.rs` also reads.
//
// Nothing but `clap` is used here, and nothing from the rest of the crate,
// because `build.rs` `include!`s this file in order to generate the man page
// from it. That is what makes `kbmanage.1` impossible to leave stale: there is
// no committed copy to forget, and the page is the source of truth's own
// account of itself. Same shape as `kerbridge-setup/src/cli.rs`, for the same
// reason.
//
// Plain comments rather than `//!` for the same reason as there: an inner doc
// comment is only legal at the top of the file it ends up in, and this one ends
// up in the middle of `build.rs`.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "kbmanage",
    version,
    about = "Resource groups, their membership, and why an identity does or does not reach a share",
    long_about = "KerBridge owns the IdP-specific OUs; you own the resource groups that gate\n\
                  your services. This manages the second and diagnoses the chain between them.\n\n\
                  Inside an IdP-specific OU this reads, deletes, renames a login name, and revokes a\n\
                  device grant -- nothing else. A kerbridge-sync owns each of them, and a second\n\
                  writer racing the reconciliation loop is the failure this tool exists to avoid.\n\
                  The two write verbs are exceptions because neither has a race to lose: sync\n\
                  derives a login name once, at creation, and never recomputes it for a live\n\
                  account; and a device grant is only ever written by issuerd, so revoking one\n\
                  here deletes a value nothing else is about to rewrite."
)]
pub struct Cli {
    #[command(flatten)]
    pub conn: ConnArgs,
    /// Machine-readable output, for scripting.
    #[arg(long, global = true)]
    pub json: bool,
    /// Do not prompt. Without a terminal and without this, destructive verbs refuse.
    #[arg(long, short = 'y', global = true)]
    pub yes: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Args, Clone, Default)]
pub struct ConnArgs {
    /// The deployment to act on: the directory its config set lives in
    #[arg(long, global = true, value_name = "DIR")]
    pub config: Option<PathBuf>,
    /// The directory to bind to, ldaps://dc.example.site
    #[arg(long, global = true)]
    pub url: Option<String>,
    /// The domain root every search starts from
    #[arg(long, global = true)]
    pub base_dn: Option<String>,
    /// The account to bind as
    #[arg(long, global = true)]
    pub bind_dn: Option<String>,
    /// The file holding that account's password
    #[arg(long, global = true)]
    pub password_file: Option<PathBuf>,
    /// The realm's own CA, the only one an LDAPS bind trusts
    #[arg(long, global = true)]
    pub ca_file: Option<PathBuf>,
    /// Where resource groups live
    #[arg(long, global = true)]
    pub resource_ou: Option<String>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Resource groups: the domain-local groups that gate your services.
    #[command(subcommand)]
    Group(GroupCmd),
    /// The sync-owned IdP-specific OUs. Read and delete only.
    #[command(subcommand)]
    Cloud(CloudCmd),
    /// Device grants: which machines may obtain tickets without a browser.
    #[command(subcommand)]
    Device(DeviceCmd),
    /// Diagnose the authorization chain.
    Doctor {
        /// One user, by sAMAccountName, UPN, DN or external identity. Omit for
        /// a whole-directory sweep.
        #[arg(long)]
        user: Option<String>,
        /// Also ask the public endpoint for `/config`: the URL a client is
        /// enrolled against, https://kerbridge.example.site. Not in the config
        /// set -- it belongs to whatever fronts the broker, and in a Docker
        /// Compose deployment it is BROKER_FQDN in deploy/.env.
        #[arg(long, value_name = "URL")]
        endpoint: Option<String>,
    },
    /// Whether the broker answers GET /config at a URL, and which of the two
    /// 404s came back.
    ///
    /// Prints one line -- the diagnosis -- for a poll loop to put in its own
    /// report. --json carries every link, and `doctor --endpoint` walks the same
    /// ones and shows each.
    ///
    /// Reads no config set and binds nothing: a deployment's own readiness
    /// script runs this while the stack is still coming up, and a Debian
    /// deployment runs it with nothing installed but this binary.
    ///
    /// Exits 0 when the endpoint serves that path, 2 when nothing is wrong that
    /// waiting could not fix, 3 when the port is open and no TLS session came of
    /// it -- an ACME issuance still in flight, or a certificate file that did
    /// not load, which are the same symptom and opposite verdicts -- and 1 when
    /// it answered and the answer was wrong.
    Endpoint {
        /// The base a client is given: https://kerbridge.example.site, with an
        /// optional port and an optional /<source> segment. /config is appended.
        url: String,
        /// Connect to this address instead of resolving the URL's host, as
        /// `curl --resolve` does: 127.0.0.1, or 127.0.0.1:8443. The certificate
        /// is still judged against the name in the URL.
        #[arg(long, value_name = "ADDR")]
        resolve: Option<String>,
        /// Judge the certificate against this CA rather than the public roots.
        #[arg(long, value_name = "FILE")]
        ca_file: Option<PathBuf>,
        /// Complete the handshake whatever certificate is presented, and report
        /// what was wrong with it rather than stopping there. For a deployment
        /// whose certificate is the operator's own business.
        #[arg(long)]
        any_cert: bool,
        /// Seconds any one step may take.
        #[arg(long, default_value_t = 10, value_name = "SECS")]
        timeout: u64,
    },
    /// Where the configuration came from and what it resolved to. Connects to
    /// nothing, so it answers "why is it talking to that DC" on a broken host.
    Config,
}

#[derive(Subcommand)]
pub enum GroupCmd {
    /// List resource groups and what is nested in each.
    List,
    /// Create a domain-local security group.
    New { name: String },
    /// What is nested inside a resource group -- the authorization model.
    #[command(subcommand)]
    Member(MemberCmd),
    /// Delete a resource group. Destroys its SID.
    Delete { name: String },
    /// Rename a resource group, CN and sAMAccountName together.
    Rename { old: String, new: String },
}

/// The edited object comes first, as it does in `group rename` and `cloud
/// rename`. `group nest` put it second; a script converted by changing the verb
/// alone is caught by [`assert_argument_order`], not by the directory.
#[derive(Subcommand)]
pub enum MemberCmd {
    /// Nest a synced group into a resource group.
    Add { target_group: String, new_member: String },
    /// Remove that nesting.
    Remove { target_group: String, old_member: String },
    /// What one resource group contains.
    List { target_group: String },
}

#[derive(Subcommand)]
pub enum CloudCmd {
    /// Managed objects, their state and how long they have been held.
    List {
        /// users | groups. Both by default.
        kind: Option<String>,
    },
    /// Everything about one managed object.
    Show { name: String },
    /// Destroy a managed object. Read the warning.
    Delete { name: String },
    /// Hand a login name back to sync, so it follows the cloud IdP display name again.
    Unpin { name: String },
    /// Change a user's login name, and pin it. Read the warning.
    Rename {
        /// The account now, by sAMAccountName or DN.
        name: String,
        /// The login name it should carry instead.
        #[arg(long)]
        to: String,
    },
}

#[derive(Subcommand)]
pub enum DeviceCmd {
    /// Every authorized device, or just one user's.
    List {
        /// One user, by sAMAccountName, UPN, DN or external identity.
        user: Option<String>,
    },
    /// Stop one device. It stops at its next ticket exchange, like every other
    /// revocation lever.
    Revoke {
        /// The eight-character id `device list` prints, not the machine label --
        /// the label is whatever the machine said it was.
        id: String,
    },
    /// Who may authorize a machine on someone else's behalf.
    #[command(subcommand)]
    Delegate(DelegateCmd),
}

#[derive(Subcommand)]
pub enum DelegateCmd {
    /// Name the group whose members may authorize a machine as this user.
    /// Replaces: one delegate group per account.
    Set {
        /// The account whose device grants are being lent out, by
        /// sAMAccountName, UPN, DN or external identity.
        user: String,
        /// A resource group. Nest the engineers' synced group into it.
        delegate_group: String,
    },
    /// Take the delegation away. Revokes no machine that already holds a grant.
    Clear { user: String },
    /// The chain: account, the group that may authorize for it, and who is in
    /// that group.
    List { user: Option<String> },
}
