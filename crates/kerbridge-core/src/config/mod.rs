//! What a deployment is: five files under one directory, plus one per cloud IdP.
//!
//! A binary is told the directory; `main.toml` is the entry point and the rest
//! are found beside it under fixed names. Splitting them is not
//! tidiness -- the cut is *would this still be true if a different tool fronted
//! the same realm?* Yes goes in [`Realm`], no goes in [`Main`]. So the ticket
//! ceilings are realm facts expressed in Kerberos terms, while device grants,
//! which no other tool has a notion of, are not.
//!
//! One `idp_<name>.toml` per [`crate::Source`], and `main.sources` lists them by
//! name rather than a glob. A source that vanished by glob would orphan every
//! object it owns -- SIDs, memberships, file ownership -- with nothing
//! reporting it, and the list doubles as the enable switch: drop a name, keep
//! the file, and that source stops being served without anything being
//! destroyed.
//!
//! **Every validation failure here is fatal.** That is only safe because
//! `kbconfig check` runs the same checks as a pre-flight, so a typo is caught
//! before a restart rather than during one. For the same reason nothing here
//! looks at deployment state: confirming an OU exists would deadlock bootstrap,
//! which cannot create the OU without first reading this config.
//!
//! Secrets do not appear in any of these files. They are named as paths and
//! read through [`crate::secret`].
//!
//! **The `Serialize` half is [`field_paths`]'s alone.** These structs are read,
//! never written: an upgrade writes a file from this version's template with
//! the operator's decisions put back into it, and never from a struct. The
//! derive is there so that the dotted path of every plain field is generated
//! rather than typed out a second time, and it rides the `schema` feature
//! because that is the one that means *the parser describes itself*.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::dn::dn_equals;

#[cfg(feature = "schema")]
pub mod decisions;
pub mod migrations;
#[cfg(feature = "schema")]
mod paths;
mod template;

#[cfg(feature = "schema")]
pub use paths::field_paths;
pub use template::TEMPLATE_SOURCES;
#[cfg(feature = "schema")]
pub use template::{REQUIRED_NOTE, render, schemas, source_envelope, source_schema, templates};

/// Where the binaries look when nothing says otherwise. One compiled-in path,
/// so a container bind-mounting its `deploy/configs/` here and a package
/// installing here need no conditional between them.
pub const DEFAULT_CONFIG_DIR: &str = "/etc/kerbridge";

/// The entry point, inside the directory a binary is given.
pub const MAIN_FILE: &str = "main.toml";

const REALM_FILE: &str = "realm.toml";
/// Named outside this crate as well: `issuerd` says which file a unix name it
/// could not resolve came from, and `kbconfig check` says which file states one
/// identity twice.
pub const ISSUERD_FILE: &str = "issuerd.toml";
const BROKER_FILE: &str = "broker.toml";
const SYNC_FILE: &str = "sync.toml";
const KBMANAGE_FILE: &str = "kbmanage.toml";

/// Where a host-run tool looks for a deployment when no `--config` names one.
/// A symlink `make kbmanage-config` writes, so a checkout's `deploy/configs/`
/// answers for the tools without either end knowing the other's path.
const USER_CONFIG_DIR: &str = "kerbridge/configs";

/// Both ends of the issuer socket default to this, and they have to agree: a
/// broker looking at another path finds no issuer at all.
const ISSUER_SOCKET: &str = "/run/kerbridge/issuer.sock";

/// One deployment's whole configuration, loaded and cross-checked.
#[derive(Debug)]
pub struct Config {
    pub main: Main,
    pub realm: Realm,
    pub issuerd: Issuerd,
    pub broker: Broker,
    pub sync: Sync,
    /// `None` when the deployment has no `kbmanage.toml`, which is the normal
    /// state of a container: the operator CLI runs on a host, and nothing else
    /// reads this.
    pub kbmanage: Option<Kbmanage>,
    /// Listed sources, in `main.sources` order. Deterministic iteration is the
    /// point: a singleton sync walks them in turn, and an order that moved
    /// between restarts would move which source wins a `sAMAccountName` race.
    pub sources: Vec<SourceFile>,
    /// Non-fatal remarks, said out loud by the caller at startup.
    pub warnings: Vec<String>,
}

/// The one array a template shows. schemars parses `example = ...` with a
/// restricted expression grammar, which takes a path but not a literal array.
#[cfg(feature = "schema")]
const SOURCES_EXAMPLE: [&str; 1] = ["entra"];

/// `main.toml`: the things that would not exist without this tool.
#[derive(Debug, Deserialize, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema, serde::Serialize))]
#[serde(deny_unknown_fields)]
pub struct Main {
    /// One name per `idp_<name>.toml`. Required, and may be empty -- a realm
    /// with no source yet is a deployment mid-bootstrap, not a broken one.
    #[cfg_attr(feature = "schema", schemars(example = SOURCES_EXAMPLE))]
    pub sources: Vec<String>,
    #[serde(default)]
    pub device_grant_days: u32,
    #[serde(default = "default_grants_per_user")]
    pub device_grant_max_per_user: u32,
    #[serde(default)]
    pub client_defaults: ClientDefaults,
    #[serde(default)]
    pub notify: Notify,
}

/// `[client_defaults]`: what a workstation agent should do here, where nobody
/// at that end has said otherwise.
///
/// Served in `GET /{source}/config` and layered *under* both the machine policy
/// (`HKLM` or an MDM profile) and the user's own `config.toml`. It exists for
/// the machines no management system owns: policy reaches a managed fleet, and
/// this reaches the rest over the one channel they already trust for the realm
/// and the KDCs.
///
/// Every value is optional, and unset means "no opinion", not "off" -- an
/// unset option leaves the agent's own built-in answer standing, which is what
/// lets a later client version change one. See `client/DESIGN.md`
/// @ Configuration and storage for the resolution order.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema, serde::Serialize))]
#[serde(deny_unknown_fields, default)]
pub struct ClientDefaults {
    /// Start the agent when the user logs in. The agent applies this to the
    /// real login-item entry -- the `Run` value on Windows, the login item on
    /// macOS -- once, on a machine whose user has never decided either way.
    #[cfg_attr(feature = "schema", schemars(example = true))]
    pub autostart: Option<bool>,
    /// Let Windows' own token store (WAM) issue the broker token before the
    /// browser is tried. `false` forces the browser flow. Nothing on macOS.
    #[cfg_attr(feature = "schema", schemars(example = true))]
    pub windows_sign_in: Option<bool>,
    /// Offer the elevated `LanmanWorkstation` restart that clears a stuck NTLM
    /// fallback. `false` gives that up: the fallback is then recoverable only
    /// by a reboot or by IT. Windows only, macOS clears it by itself.
    #[cfg_attr(feature = "schema", schemars(example = true))]
    pub ntlm_fallback_recovery: Option<bool>,
}

/// `[notify]`: where the conditions only a human can fix are sent.
#[derive(Debug, Deserialize, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema, serde::Serialize))]
#[serde(deny_unknown_fields, default)]
pub struct Notify {
    /// No URL is log-only, not off: every event is still a `NOTIFY` line in the
    /// service log and a file in `state_dir`. No default, unlike the paths
    /// below -- there is no address a deployment can be assumed to have.
    #[cfg_attr(feature = "schema", schemars(example = "/etc/kerbridge.secrets/notify_url"))]
    pub url_file: Option<PathBuf>,
    #[cfg_attr(feature = "schema", schemars(example = "/etc/kerbridge/notify-ca.pem"))]
    pub ca_file: Option<PathBuf>,
    #[cfg_attr(feature = "schema", schemars(example = "hooks.lab.example.site"))]
    pub insecure_host: Option<String>,
    pub min_severity: String,
    pub repeat_interval_hours: u32,
    /// Every service that raises a condition mounts this, so the default holds
    /// for all of them -- and each appends its own name to it rather than
    /// sharing the directory, so an operator who sets `/srv/kb` gives the broker
    /// `/srv/kb/broker`. One key, three directories, and no daemon can be made
    /// to collide with another by setting it. `none` gives up durable problem
    /// state: nothing outside the process can read what is open, and a restart
    /// re-sends it.
    // A string, never a nullable one -- see `switchable_path`.
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    #[serde(deserialize_with = "switchable_path")]
    pub state_dir: Option<PathBuf>,
    /// `None` is `kerbridge-notify`'s built-in body, which this crate cannot
    /// name: it does not link the notifier, and must not -- `issuerd` links
    /// this crate and may not acquire an HTTP and TLS dependency tree.
    #[cfg_attr(
        feature = "schema",
        schemars(
            example = "{\"text\":\"%COMPONENT% on %REALM%: %SEVERITY% %EVENT% -- %MESSAGE%\"}"
        )
    )]
    pub template: Option<String>,
    pub timeout_seconds: u32,
}

impl Default for Notify {
    fn default() -> Self {
        Self {
            url_file: None,
            ca_file: None,
            insecure_host: None,
            min_severity: "info".to_owned(),
            repeat_interval_hours: 24,
            state_dir: default_notify_state_dir(),
            template: None,
            timeout_seconds: 5,
        }
    }
}

/// `realm.toml`: what is true of the realm whichever tool fronts it.
///
/// Six values are derived rather than stated, and are read back through the
/// accessors rather than as fields -- a caller deriving its own would be the
/// divergence this crate exists to end.
///
/// `[provision]` is the one group here that is Samba's rather than the realm's,
/// and it stays in this file because a table is cheaper than a seventh one.
#[derive(Debug, Deserialize, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema, serde::Serialize))]
#[serde(deny_unknown_fields)]
pub struct Realm {
    /// Baked into the Samba database at provisioning; startup fails if it later
    /// disagrees.
    #[cfg_attr(feature = "schema", schemars(example = "EXAMPLE.SITE"))]
    pub realm: String,
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(example = "DC=example,DC=site"))]
    base_dn: Option<String>,
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(example = "example.site"))]
    ad_dns_domain: Option<String>,
    #[serde(default)]
    // `&` on both examples because schemars refuses a bare string literal that
    // could be read as a function path, which a one-word name can.
    #[cfg_attr(feature = "schema", schemars(example = &"EXAMPLE"))]
    netbios_domain: Option<String>,
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(example = &"kerbridge"))]
    dc_hostname: Option<String>,
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(example = "OU=CloudIdP,DC=example,DC=site"))]
    idp_parent_ou: Option<String>,
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(example = "OU=Resources,DC=example,DC=site"))]
    resource_ou: Option<String>,
    #[cfg_attr(feature = "schema", schemars(example = "ldaps://kerbridge.example.site:636"))]
    pub ldap_url: String,
    #[cfg_attr(feature = "schema", schemars(example = "/run/kerbridge/realm-ca.pem"))]
    pub ldap_ca_file: PathBuf,
    #[serde(default)]
    pub kdcs: Vec<String>,
    #[serde(default)]
    pub services: Vec<String>,
    #[serde(default = "default_ten_hours")]
    pub ticket_lifetime_seconds: u32,
    #[serde(default = "default_seven_days")]
    pub ticket_renewable_seconds: u32,
    /// The ceiling `issuerd` enforces, against which the two above are a
    /// request. Samba's own domain policy caps both again.
    #[serde(default = "default_ten_hours")]
    pub max_lifetime_seconds: u32,
    #[serde(default = "default_seven_days")]
    pub max_renewable_seconds: u32,
    #[serde(default)]
    pub provision: Provision,
}

impl Realm {
    /// The domain root, derived from [`Realm::realm`] unless the file states one.
    pub fn base_dn(&self) -> String {
        self.base_dn.clone().unwrap_or_else(|| crate::dn::base_dn_for(&self.realm))
    }

    /// The UPN suffix created users get. The realm lowercased, not a separate
    /// choice.
    pub fn ad_dns_domain(&self) -> String {
        self.ad_dns_domain.clone().unwrap_or_else(|| self.realm.to_lowercase())
    }

    /// The OU holding one IdP-specific OU per source and nothing else.
    /// `kbmanage` and `issuerd` test containment against this one, because
    /// "is this DN sync-owned" must stay a single question however many cloud
    /// IdPs a realm gains.
    pub fn idp_parent_ou(&self) -> String {
        self.idp_parent_ou.clone().unwrap_or_else(|| crate::dn::idp_parent_ou_for(&self.base_dn()))
    }

    /// Where the operator's own resource groups live -- outside every
    /// IdP-specific OU, since sync does not own them.
    pub fn resource_ou(&self) -> String {
        self.resource_ou.clone().unwrap_or_else(|| format!("OU=Resources,{}", self.base_dn()))
    }

    /// The flat NT4 name of the domain, conventionally the realm's first label
    /// uppercased -- which is what `samba-tool domain provision` picks when it is
    /// given a realm and no workgroup.
    ///
    /// Never cut to the 15-character limit a flat name has: a realm whose first
    /// label is longer needs a name of its own, and a silently truncated one
    /// would be a fourth spelling of the domain that nothing else agrees with.
    pub fn netbios_domain(&self) -> String {
        self.netbios_domain
            .clone()
            .unwrap_or_else(|| self.realm.split('.').next().unwrap_or_default().to_uppercase())
    }

    /// The DC's own short name, which [`Realm::ldap_url`] already carries: its
    /// host's first label. Stating it turns a cross-check into a derivation --
    /// the two cannot disagree if only one of them is written down.
    ///
    /// State it where `ldap_url` names an address rather than a name, which is
    /// the one case the derivation has no answer for.
    pub fn dc_hostname(&self) -> String {
        self.dc_hostname
            .clone()
            .unwrap_or_else(|| self.ldap_host().split('.').next().unwrap_or_default().to_owned())
    }

    /// The host [`Realm::ldap_url`] names, with the scheme, the port and an
    /// IPv6 literal's brackets off. Borrowed from the URL rather than parsed
    /// into one: a URL type would have to decide what an unparseable string
    /// means, and every caller here is comparing a name.
    pub fn ldap_host(&self) -> &str {
        let after_scheme = self.ldap_url.split_once("//").map_or(&*self.ldap_url, |(_, r)| r);
        let authority = after_scheme.split('/').next().unwrap_or_default();
        match authority.strip_prefix('[') {
            Some(v6) => v6.split(']').next().unwrap_or_default(),
            None => authority.split(':').next().unwrap_or_default(),
        }
    }
}

/// `[provision]`: what Samba is told the once, when the realm is created.
///
/// Read by `kbsetup realm` and by nothing on a start, which is why these
/// three are a table down here rather than keys beside `realm` -- and a table
/// rather than a seventh file, which three keys do not earn. It is also the one
/// group in `realm.toml` that a different AD implementation would fill in
/// differently, the rest of the file being true of the realm however it was
/// made.
#[derive(Debug, Deserialize, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema, serde::Serialize))]
#[serde(deny_unknown_fields, default)]
pub struct Provision {
    /// Upstream resolver for whatever uses the DC as its own -- the DC itself, and
    /// any member pointed at it. Empty is no forwarder at all, which leaves those
    /// able to resolve the AD zone and nothing else: normally right, since clients
    /// here use the site resolver and an off-host member forwards the AD zone only.
    pub dns_forwarder: String,
    /// Samba's dynamic RPC ports. Narrow it where the range has to be published
    /// through a firewall, which is what an off-host member needs.
    pub rpc_port_range: String,
    /// The realm Administrator's password, which is also the credential a file
    /// server joins with.
    ///
    /// WRITTEN, not read -- the one key in the whole config set naming a file
    /// KerBridge creates rather than one it opens. Provisioning generates the
    /// password and puts it here, and never overwrites a file already there. It is
    /// a key at all, rather than the fixed path the rest of the secrets directory
    /// is reached by, because a secrets directory on separate or encrypted storage
    /// is the one thing an operator cannot otherwise route around.
    pub admin_password_file: PathBuf,
}

impl Default for Provision {
    fn default() -> Self {
        Self {
            dns_forwarder: String::new(),
            rpc_port_range: "49152-49251".to_owned(),
            admin_password_file: "/etc/kerbridge.secrets/generated/realm_admin_password".into(),
        }
    }
}

/// `issuerd.toml`: the one Unix socket, and the bounds on what crosses it.
///
/// The uid and gid are a contract with the secret bootstrap and the broker
/// container rather than a preference: the socket directory is
/// `0710 root:socket_gid`, so that gid is the whole of the broker's reach.
/// `compose.yaml` states the same two numbers again, as the broker's `user:`;
/// a disagreement is a refused peer on every ticket.
///
/// Each identity is spelled twice over, and the name wins where it is stated.
/// A package cannot state a number -- `adduser --system` allocates one -- and
/// the Docker Compose deployment cannot state a name, its host having no such account.
/// Resolving a name is `issuerd`'s, not this crate's: the broker and sync link
/// the same parser and have no business gaining a libc name lookup.
///
/// `max_inflight` sits below [`Broker::max_inflight`] on purpose: each request
/// here forks three root subprocesses on the DC, and one that reached the
/// issuer has already spent its LDAPS bind.
#[derive(Debug, Deserialize, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema, serde::Serialize))]
#[serde(deny_unknown_fields, default)]
pub struct Issuerd {
    pub socket: PathBuf,
    pub socket_gid: u32,
    /// The unix group owning the socket directory, resolved to its gid at startup
    /// and used in place of socket_gid. State a name where the number is allocated
    /// rather than chosen: a package's `adduser --system` takes whatever is free, so
    /// nothing can write the number down in advance. It is read out of /etc/group
    /// alone -- issuerd is a static musl binary, which consults no nsswitch.conf, so
    /// a group that exists only in LDAP, SSSD or winbind will not resolve. One that
    /// does not resolve stops issuerd; it never falls back to the number.
    // `&` on both examples because schemars refuses a bare string literal that
    // could be read as a function path, which `_kerbridge` can.
    #[cfg_attr(feature = "schema", schemars(example = &"_kerbridge"))]
    pub socket_group: Option<String>,
    pub broker_uid: u32,
    /// The unix user the broker runs as, resolved to its uid at startup and used in
    /// place of broker_uid. Same terms as socket_group, and read the same way.
    #[cfg_attr(feature = "schema", schemars(example = &"_kerbridge-broker"))]
    pub broker_user: Option<String>,
    pub tmp_dir: PathBuf,
    pub max_inflight: usize,
    pub sam_db: PathBuf,
    /// Deadline on one samba-tool or kinit subprocess.
    pub command_timeout_seconds: u32,
    /// Every ticket this process issued, appended. A file rather than the container
    /// log, which lasts only until the next recreate. Its own directory under
    /// `/var/log/kerbridge`, never the broker's: one directory per writing service,
    /// owned by that service, is what keeps a compromised broker from unlinking the
    /// issuer's record -- and what still lets `logrotate` create the successor file.
    /// `none` keeps the console line and nothing else, which survives only until the
    /// next recreate.
    // A string, never a nullable one -- see `switchable_path`.
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    #[serde(deserialize_with = "switchable_path")]
    pub audit_log_file: Option<PathBuf>,
}

impl Default for Issuerd {
    fn default() -> Self {
        Self {
            socket: ISSUER_SOCKET.into(),
            socket_gid: 10002,
            socket_group: None,
            broker_uid: 10001,
            broker_user: None,
            tmp_dir: "/run/issuer".into(),
            max_inflight: 8,
            sam_db: "/var/lib/samba/private/sam.ldb".into(),
            command_timeout_seconds: 20,
            audit_log_file: default_issuer_audit(),
        }
    }
}

/// `broker.toml`: the internet-facing half.
///
/// There is no search base here. `realm.toml` holds the *IdP-specific OU* as
/// [`Realm::base_dn`], derived from `realm`; a singleton broker serves every
/// source, so each one's OU is derived from [`Realm::idp_parent_ou`] and the
/// source name instead. A reader comparing this against `realm.toml` will
/// otherwise think a field went missing.
#[derive(Debug, Deserialize, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema, serde::Serialize))]
#[serde(deny_unknown_fields)]
pub struct Broker {
    /// Loopback only, and a wider address is refused where the listener is
    /// opened: this process speaks plain HTTP, and Caddy terminates TLS in the
    /// network namespace they share.
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_broker_inflight")]
    pub max_inflight: usize,
    #[cfg_attr(
        feature = "schema",
        schemars(example = "CN=svc-kerbridge-broker,CN=Users,DC=example,DC=site")
    )]
    pub bind_dn: String,
    #[cfg_attr(
        feature = "schema",
        schemars(example = "/etc/kerbridge.secrets/generated/svc_kerbridge_broker_password")
    )]
    pub bind_password_file: PathBuf,
    #[serde(default = "default_issuer_socket")]
    pub issuer_socket: PathBuf,
    #[serde(default = "default_broker_timeout")]
    pub timeout_seconds: u32,
    /// Separate from `issuerd.audit_log_file`, and on a separate mount --
    /// see the reason there.
    // A string, never a nullable one -- see `switchable_path`.
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    #[serde(default = "default_broker_audit", deserialize_with = "switchable_path")]
    pub audit_log_file: Option<PathBuf>,
}

/// `sync.toml`: what the mirror does. Which cloud IdP it reads, and which of
/// that IdP's attributes names an account, is per source and not here.
///
/// `device_grant_notify` stays a string. Its parser lives in `kerbridge-sync`,
/// and a value is best refused where it is interpreted -- this crate would only
/// be able to repeat the spelling list, which is the way two checks come to
/// disagree.
#[derive(Debug, Deserialize, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema, serde::Serialize))]
#[serde(deny_unknown_fields, default)]
pub struct Sync {
    /// The pause between cycles, not the rate of them. One cycle reads every
    /// source in turn, so the time between two reads of one source is that
    /// cycle plus this pause.
    pub interval_seconds: u32,
    pub automatic_sam_renames: bool,
    pub dry_run: bool,
    pub device_grant_notify: String,
    pub credential_warn_before_days: u32,
    /// What each cycle changed in the directory, appended: the tally, and the
    /// object every applied write touched. Its own path on its own mount, never
    /// the broker's and never the issuer's -- see the reason at
    /// [`Issuerd::audit_log_file`]. `none` keeps the console line and nothing
    /// else, which survives only until the next recreate.
    // A string, never a nullable one -- see `switchable_path`.
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    #[serde(deserialize_with = "switchable_path")]
    pub audit_log_file: Option<PathBuf>,
}

impl Default for Sync {
    fn default() -> Self {
        Self {
            interval_seconds: 300,
            automatic_sam_renames: true,
            dry_run: false,
            device_grant_notify: "off".to_owned(),
            credential_warn_before_days: 30,
            audit_log_file: default_sync_audit(),
        }
    }
}

/// `kbmanage.toml`: the operator CLI's own identity, and the two paths that
/// differ because it is the one component running outside the containers.
///
/// Optional, and read by nothing else. A deployment that is only ever
/// administered from inside never has this file; `make kbmanage-config` writes
/// it, alongside the symlink that lets the CLI find the set at all.
#[derive(Debug, Deserialize, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema, serde::Serialize))]
#[serde(deny_unknown_fields)]
pub struct Kbmanage {
    #[cfg_attr(
        feature = "schema",
        schemars(example = "CN=svc-kerbridge-manage,CN=Users,DC=example,DC=site")
    )]
    pub bind_dn: String,
    #[cfg_attr(
        feature = "schema",
        schemars(example = "/home/you/.config/kerbridge/svc_kerbridge_manage_password")
    )]
    pub bind_password_file: PathBuf,
    /// Defaults to [`Realm::ldap_url`], which names the DC on the container
    /// network. The realm's certificate carries `localhost` in its SAN
    /// alongside the DC's own names, so a host binary reaching LDAPS on
    /// loopback needs no resolver entry and no split horizon.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(example = "ldaps://localhost:636"))]
    ldap_url: Option<String>,
    /// Defaults to [`Realm::ldap_ca_file`], which is a path inside the realm
    /// container. `make kbmanage-config` copies the CA out to a host path.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(example = "/home/you/.config/kerbridge/realm-ca.pem"))]
    ldap_ca_file: Option<PathBuf>,
}

impl Kbmanage {
    pub fn ldap_url<'a>(&'a self, realm: &'a Realm) -> &'a str {
        self.ldap_url.as_deref().unwrap_or(&realm.ldap_url)
    }

    pub fn ldap_ca_file<'a>(&'a self, realm: &'a Realm) -> &'a Path {
        self.ldap_ca_file.as_deref().unwrap_or(&realm.ldap_ca_file)
    }
}

/// `idp_<name>.toml`: one source, as a neutral envelope around an opaque
/// provider block.
///
/// The membership test is *whose fact is it*: anything about the cloud IdP goes
/// in `[provider_config]`, anything about our directory or our naming policy
/// goes here. So `bind_dn` is an envelope field -- it names an AD account, ours
/// -- while an admission group is not, because only the adapter knows whether
/// its identifier is a GUID, an address or a slug.
///
/// `name`, `provider` and the OU are here rather than in `broker.toml` and
/// `sync.toml` for one reason: both binaries must read the *same* value of each,
/// and a disagreement retires every account and recreates it with a fresh SID,
/// stranding every file whose owner came from the old one.
#[derive(Debug, Deserialize, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema, serde::Serialize))]
#[serde(deny_unknown_fields)]
pub struct SourceFile {
    /// Must equal the filename stem after `idp_`, checked at load. This is the
    /// frozen storage key in every synchronized object's identity, so a
    /// half-edited copy of another source's file has to fail rather than create
    /// a phantom source.
    #[cfg_attr(feature = "schema", schemars(example = "{name}"))]
    pub name: String,
    /// Selects the `kerbridge-idp` adapter.
    #[cfg_attr(feature = "schema", schemars(example = "{provider}"))]
    pub provider: String,
    /// What this source's group login names end with; the literal `none` means
    /// no suffix. Unset derives `-<name>`, which is the answer that cannot
    /// collide with another source. Not validated here -- the rule is
    /// `kerbridge-sync`'s, next to the planner that would hit the collision.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(example = "-{name}"))]
    group_suffix: Option<String>,
    #[cfg_attr(
        feature = "schema",
        schemars(example = "CN=svc-kerbridge-sync-{name},CN=Users,DC=example,DC=site")
    )]
    pub bind_dn: String,
    #[cfg_attr(
        feature = "schema",
        schemars(example = "/etc/kerbridge.secrets/generated/idp/{name}/bind_password")
    )]
    pub bind_password_file: PathBuf,
    #[cfg_attr(feature = "schema", schemars(example = "OU={Name},OU=CloudIdP,DC=example,DC=site"))]
    #[serde(default)]
    ou: Option<String>,
    /// Handed to the adapter verbatim and never read here. Keeping it opaque is
    /// what stops `issuerd`, which links this crate and holds KDC authority,
    /// from carrying a struct describing what an Entra deployment needs.
    // Out of the schema for the same reason it is a `toml::Table` above:
    // describing an adapter's keys here is what the paragraph forbids. The
    // adapter describes its own half. (`toml::Table` has no `JsonSchema` impl
    // either, so the two reasons agree.)
    #[cfg_attr(feature = "schema", schemars(skip))]
    // Out of `field_paths` too: `kbconfig get` answers a provider path with the
    // adapter's *resolved* settings, which only `kerbridge-idp` can produce, so
    // the raw table would be a second and disagreeing answer.
    #[cfg_attr(feature = "schema", serde(skip_serializing))]
    #[serde(default)]
    pub provider_config: toml::Table,
}

impl SourceFile {
    /// This source's IdP-specific OU: `OU=<Name>,<idp_parent_ou>`, with the
    /// source name's first character uppercased, unless the file overrides it.
    /// The override is for a directory whose existing layout collides.
    pub fn ou(&self, idp_parent_ou: &str) -> String {
        self.ou.clone().unwrap_or_else(|| format!("OU={},{idp_parent_ou}", title_case(&self.name)))
    }

    /// The derived answer is `-<name>`, never `none`: a suffix costs nothing
    /// while there is one source and is the only thing that keeps two apart,
    /// and it cannot be adopted later without renaming groups already in use.
    pub fn group_suffix(&self) -> String {
        self.group_suffix.clone().unwrap_or_else(|| format!("-{}", self.name))
    }
}

impl Config {
    /// Read and cross-check the whole set. Offline: no network, no LDAP, and
    /// nothing that asks whether a directory object exists.
    ///
    /// The *directory*, never one file in it: every caller reads all of them, so
    /// a path to `main.toml` would be a filename this immediately discarded and
    /// an invitation to point a binary at `realm.toml` and wonder why nothing
    /// changed.
    pub fn load(dir: &Path) -> Result<Self> {
        let main_toml = dir.join(MAIN_FILE);

        let main: Main = read(&main_toml)?;
        let realm_path = dir.join(REALM_FILE);
        let realm: Realm = read(&realm_path)?;
        crate::require_ldaps(&realm.ldap_url)
            .with_context(|| format!("{}: ldap_url", realm_path.display()))?;
        realm_shape(&realm_path, &realm)?;

        let issuerd = read(&dir.join(ISSUERD_FILE))?;
        let broker = read(&dir.join(BROKER_FILE))?;
        let sync = read(&dir.join(SYNC_FILE))?;

        let kbmanage_path = dir.join(KBMANAGE_FILE);
        let kbmanage: Option<Kbmanage> =
            kbmanage_path.is_file().then(|| read(&kbmanage_path)).transpose()?;
        if let Some(k) = &kbmanage {
            crate::require_ldaps(k.ldap_url(&realm))
                .with_context(|| format!("{}: ldap_url", kbmanage_path.display()))?;
        }

        let mut seen = BTreeSet::new();
        let mut sources = Vec::with_capacity(main.sources.len());
        for name in &main.sources {
            if !seen.insert(name) {
                bail!("{}: sources lists {name:?} twice", main_toml.display());
            }
            if !is_source_name(name) {
                bail!(
                    "{}: {name:?} is not a source name. The name is a path segment in this \
                     source's broker URL, a filename stem and an OU: letters, digits, '.', \
                     '-' and '_', starting with a letter or a digit.",
                    main_toml.display()
                );
            }
            let path = dir.join(source_file(name));
            let source: SourceFile = read(&path)?;
            if source.name != *name {
                bail!(
                    "{}: name = {:?}, but the filename says {name:?}. The source name is the \
                     frozen storage key in every object this source owns -- rename the file or \
                     the key, whichever one is the copy.",
                    path.display(),
                    source.name
                );
            }
            sources.push(source);
        }

        // One OU per source, and the check exists because `ou` is an override:
        // two files copied from one another keep the same stated value, and
        // nothing downstream would say so. Both sources then write into one OU,
        // which puts two realm-admission markers in the search base a broker
        // resolves exactly one in -- so every login fails, for both sources, on
        // a directory neither file describes wrongly on its own.
        //
        // Compared as DNs rather than as strings: AD ignores case and the space
        // after a separator, so `ou=entra, dc=…` is the same container.
        let parent_ou = realm.idp_parent_ou();
        for (i, source) in sources.iter().enumerate() {
            let ou = source.ou(&parent_ou);
            if let Some(other) = sources[..i].iter().find(|s| dn_equals(&s.ou(&parent_ou), &ou)) {
                bail!(
                    "{} and {} both own {ou}. A source owns its OU alone: two \
                     realm-admission markers in one OU freeze every login for both. Give one of \
                     them its own `ou`, or drop the override and let it derive from the name.",
                    source_file(&other.name),
                    source_file(&source.name),
                );
            }
        }

        let warnings = unlisted(dir, &main.sources)?;
        Ok(Self { main, realm, issuerd, broker, sync, kbmanage, sources, warnings })
    }
}

/// The four things about a realm identity that are decidable from `realm.toml`
/// alone, before there is a realm to ask.
///
/// Each of them is otherwise answered by `samba-tool domain provision`, at the
/// one moment where the answer stops being correctable: the realm, the flat
/// name and the DC's own name go into the Samba database and come back out only
/// with the domain SID and every filesystem ACL carrying it. So they are judged
/// here, where a hand-edited file and `kbconfig check` both pass through, and
/// where `Config::load` makes them fatal at startup as well.
///
/// They lived in `deploy/scripts/config/check-env.sh` until now. That file is
/// Compose-only and reads `.env`, so a package install had no check on realm
/// shape at all -- which is the whole of why they moved rather than being
/// copied.
fn realm_shape(path: &Path, realm: &Realm) -> Result<()> {
    let file = path.display();

    // Upper case is not decoration. `ad_dns_domain` derives as the realm
    // lowercased, so a lower-case realm derives a DNS domain identical to
    // itself and every later cross-check compares a value with a copy of
    // itself: the set reads self-consistent the whole way down, and
    // `samba-tool` accepts it.
    let upper = realm.realm.to_uppercase();
    if realm.realm != upper {
        bail!(
            "{file}: realm = {:?} is not upper case. A Kerberos realm name is, and this one is \
             written into the Samba database at provisioning where nothing corrects it \
             afterwards -- `ad_dns_domain` is the lower-case spelling, derived from this. \
             Write realm = {upper:?}.",
            realm.realm
        );
    }

    // The flat NT4 name. Checked as the *effective* value, so a realm whose
    // first label carries a space is caught along with a stated name that does,
    // and refused rather than repaired: a name this cannot read is a name the
    // operator has to choose.
    let netbios = realm.netbios_domain();
    let stated = realm.netbios_domain.is_some();
    if netbios.contains('.') || netbios.contains(' ') {
        bail!(
            "{file}: netbios_domain resolves to {netbios:?}, which is not a flat name. This is \
             the domain's NT4-era short name -- what `{}\\alice` means and what a Windows client \
             shows -- so it is one label, with no dots and no spaces.",
            netbios.split(['.', ' ']).next().unwrap_or_default()
        );
    }
    if netbios.chars().count() > NETBIOS_LIMIT {
        // Two ways to arrive here and two different mistakes. A stated name is
        // simply too long. A derived one means the realm's first label is, and
        // the answer is never to cut it down: a truncated flat name would be a
        // fourth spelling of the domain that nothing else agrees with, so the
        // realm needs a name of its own and the key to state it in is named
        // here.
        let count = netbios.chars().count();
        if stated {
            bail!(
                "{file}: netbios_domain = {netbios:?} is {count} characters; a flat name holds \
                 {NETBIOS_LIMIT}. It is baked into the database at provisioning, so this is not \
                 correctable later."
            );
        }
        bail!(
            "{file}: realm = {:?} has a first label of {count} characters, and the flat name \
             derived from it holds {NETBIOS_LIMIT}. State one: netbios_domain = \"...\", up to \
             {NETBIOS_LIMIT} characters. Not this name cut short -- a truncated flat name is a \
             fourth spelling of the domain that nothing else agrees with, and provisioning bakes \
             it in.",
            realm.realm
        );
    }

    // Reachable only on a stated value: the derivation takes `ldap_url`'s first
    // label and has no dot left to find.
    let dc = realm.dc_hostname();
    if dc.contains('.') {
        bail!(
            "{file}: dc_hostname = {dc:?} is a fully qualified name; it is the short one. The \
             FQDN is this plus ad_dns_domain, which is what the LDAPS certificate is issued for \
             and what `kbsetup realm` names the host -- so this would resolve as {dc}.{}. Write \
             dc_hostname = {:?}.",
            realm.ad_dns_domain(),
            dc.split('.').next().unwrap_or_default()
        );
    }

    // The DC's name, stated a third time by `ldap_url`. What this accepts is
    // the set of names the realm's LDAPS certificate carries -- the FQDN, the
    // short name and loopback, signed in
    // `crates/kerbridge-setup/src/realm.rs` @ `make_tls`; widen that and widen
    // this. A host outside it fails the TLS handshake rather than the lookup,
    // with every file reading correctly on its own.
    //
    // Derived from the config set rather than read out of `ldap_ca_file`, and
    // that is not a shortcut: that file is the *CA*, whose certificate carries
    // no `subjectAltName` at all, and it does not exist until provisioning has
    // published it -- which is after everything this function is for. The names
    // are `dc_hostname` and `ad_dns_domain`, and they are here.
    let host = realm.ldap_host().to_lowercase();
    let fqdn = format!("{dc}.{}", realm.ad_dns_domain()).to_lowercase();
    let covered = [fqdn.as_str(), &dc.to_lowercase(), "localhost", "127.0.0.1", "::1"]
        .iter()
        .any(|name| *name == host);
    if !covered {
        bail!(
            "{file}: ldap_url names the host {host:?}, which the realm's LDAPS certificate does \
             not cover. Provisioning signs it for {fqdn}, {dc} and loopback, from the realm CA \
             that ldap_ca_file names as the only trust root -- so every bind would fail the TLS \
             handshake. Use ldaps://{fqdn}:636, or state dc_hostname if it is this file that \
             names the wrong host."
        );
    }

    Ok(())
}

/// What a flat NT4 name holds. Not a KerBridge choice: `samba-tool domain
/// provision` refuses a longer `--domain`, and Windows has always shown these
/// names truncated to it.
const NETBIOS_LIMIT: usize = 15;

/// The config set a host-run tool uses when nothing names one: the user's own
/// deployment link first, then the packaged path.
///
/// Two locations, both fixed, and no walk up the tree. A tool that searched
/// would answer "why is it talking to *that* DC" with a list, leaving the
/// operator to work out which entry won -- so `kbmanage config` prints the
/// path that answered, and there are few enough candidates to name them all
/// when none does.
pub fn discover() -> Result<PathBuf> {
    let candidates: Vec<PathBuf> =
        user_config_dir().into_iter().chain([PathBuf::from(DEFAULT_CONFIG_DIR)]).collect();
    if let Some(found) = candidates.iter().find(|dir| dir.join(MAIN_FILE).is_file()) {
        return Ok(found.clone());
    }
    // The file rather than the directory, because a directory that exists and
    // holds no main.toml is the likelier mistake of the two.
    let looked: Vec<String> =
        candidates.iter().map(|d| format!("  {}", d.join(MAIN_FILE).display())).collect();
    bail!(
        "no KerBridge configuration found. Looked at:\n{}\nRun `make kbmanage-config` in \
         deploy/ to link this host to a deployment, or pass --config <directory>.",
        looked.join("\n")
    )
}

/// `$XDG_CONFIG_HOME/kerbridge/configs`, or `~/.config/kerbridge/configs`.
/// `None` on a host with neither variable set, where `--config` is the only way
/// to name a deployment.
fn user_config_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .map(|base| base.join(USER_CONFIG_DIR))
}

/// One file, parsed -- and where the parse fails, whatever the migration list
/// knows about the shape this file is in.
///
/// `unknown field` on its own tells an operator that they are wrong and nothing
/// else. Almost every way to reach it on a set that once worked is a rename,
/// and the list is where a rename is recorded, so this is where the two meet.
fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&text).map_err(|e| {
        let file = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        let mut message = format!("in {}: {e}", path.display());
        let instructions = migrations::explain(file, &text);
        for instruction in &instructions {
            message.push_str("\n  this version of KerBridge moved it -- ");
            message.push_str(instruction);
        }
        if !instructions.is_empty() {
            message.push_str(UPGRADE_NOTE);
        }
        anyhow::anyhow!(message)
    })
}

/// Where an operator goes next, said only where the migration list had
/// something to say. A set the list knows nothing about is one `upgrade` cannot
/// help with either, and sending an operator to a command that will change
/// nothing is worse than saying nothing at all.
const UPGRADE_NOTE: &str = "\n\n== How to fix this?\n\n\
     Try the `kbconfig upgrade` command. Use --dry-run first to see what would\n\
     change.";

/// Non-empty, and nothing that would have to be escaped in a URL path, a
/// filename or an LDAP filter. A name enters the deployment in two places --
/// loading a set, and `kbconfig init --source` writing one -- and both check
/// here, so `..` never reaches a filename. Every later consumer takes a name as
/// already safe.
pub fn is_source_name(name: &str) -> bool {
    // Leading alphanumeric so no name is a relative path segment.
    name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

/// `idp_<name>.toml`, spelled in the one place, because the filename is also
/// the source name's second home: `Config::load` refuses a file whose `name`
/// disagrees with its stem.
pub fn source_file(name: &str) -> String {
    format!("idp_{name}.toml")
}

/// Source files nobody listed. A warning rather than an error: an operator who
/// disabled a source by dropping its name meant it, and wedging the deployment
/// over a file that is being ignored helps nobody. Said out loud all the same,
/// because a silently ignored source file looks finished.
fn unlisted(dir: &Path, listed: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))?;
    for entry in entries {
        let file_name = entry.with_context(|| format!("reading {}", dir.display()))?.file_name();
        let Some(file_name) = file_name.to_str() else { continue };
        // `.toml` exactly, so the committed `.toml.example` set is not a source.
        let Some(stem) = file_name.strip_suffix(".toml").and_then(|s| s.strip_prefix("idp_"))
        else {
            continue;
        };
        if !listed.iter().any(|name| name == stem) {
            out.push(format!("{file_name} present, not listed in main.sources -- ignored"));
        }
    }
    out.sort();
    Ok(out)
}

fn title_case(name: &str) -> String {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

// serde wants a function per default. The values are the ones the binaries
// carry today; the config schema reads them from here, and each template shows
// one beside its commented-out key.
fn default_grants_per_user() -> u32 {
    10
}
fn default_ten_hours() -> u32 {
    36_000
}
fn default_seven_days() -> u32 {
    604_800
}
/// A path whose default is on, and which the literal `none` switches off --
/// following `group_suffix`, the other key here where both answers are the
/// operator's to make and one of them is not a path.
///
/// `none` rather than an empty string: a path that silently means "off" when a
/// substitution leaves it blank is how a deployment loses its audit trail
/// without anyone typing the decision.
///
/// Either answer is a **string**: the `None` is this function's reading of
/// `"none"`, not a TOML null. Which is why every field using this also carries
/// `#[schemars(with = "String")]` -- schemars describes the Rust type and
/// ignores `deserialize_with`, so left alone it would advertise the
/// `Option<PathBuf>`, a string *or* a null, and the null is the one value this
/// refuses.
fn switchable_path<'de, D>(d: D) -> Result<Option<PathBuf>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(d)?;
    Ok((raw != "none").then(|| PathBuf::from(raw)))
}

/// `/var/log` rather than `/var/lib` because these are logs, and `auditd` is the
/// precedent for audit records specifically. One directory per daemon, owned by
/// the daemon that writes it -- see [`Issuerd::audit_log_file`].
fn default_issuer_audit() -> Option<PathBuf> {
    Some("/var/log/kerbridge/issuerd/audit.log".into())
}
fn default_broker_audit() -> Option<PathBuf> {
    Some("/var/log/kerbridge/broker/audit.log".into())
}
fn default_sync_audit() -> Option<PathBuf> {
    Some("/var/log/kerbridge/sync/audit.log".into())
}
/// The *parent*, and the one key all three daemons read. Each appends its own
/// name to it, so `/var/lib/kerbridge/broker` is what the broker writes -- see
/// [`Notify::state_dir`].
fn default_notify_state_dir() -> Option<PathBuf> {
    Some("/var/lib/kerbridge".into())
}
fn default_listen() -> String {
    "127.0.0.1:8080".to_owned()
}
fn default_broker_inflight() -> usize {
    16
}
fn default_issuer_socket() -> PathBuf {
    ISSUER_SOCKET.into()
}
fn default_broker_timeout() -> u32 {
    30
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rendered envelope with its lines to complete filled in -- a source
    /// file as a deployment holds one. A failure here is a source that
    /// disagrees with the parser, which
    /// `the_committed_source_templates_are_current` reports properly; these
    /// tests only need the document.
    fn envelope(name: &str, provider: &str) -> String {
        let body = source_envelope(name, provider).expect("the envelope renders");
        decisions::completed(&body, &source_schema().expect("the envelope schema renders"))
            .expect("the envelope completes")
    }

    /// A directory holding the emitted templates with every line to complete
    /// filled in by `decisions::completed`, and the source file's provider
    /// block left off -- core neither writes nor reads one. Completed rather
    /// than copied: a template on its own does not load, so these tests would
    /// otherwise exercise nothing but that rule.
    struct Dir(PathBuf);

    impl Dir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("kerbridge-config-{}-{label}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            for ((name, body), (described, schema)) in template::templates()
                .expect("the sources render")
                .into_iter()
                .zip(schemas().unwrap())
            {
                assert_eq!(name, described, "a template and a schema fell out of order");
                let body = decisions::completed(&body, &schema).expect("the template completes");
                std::fs::write(path.join(name), body).unwrap();
            }
            let dir = Self(path);
            dir.write("idp_entra.toml", &envelope("entra", "entra"));
            dir
        }

        fn write(&self, name: &str, body: &str) {
            std::fs::write(self.0.join(name), body).unwrap();
        }

        fn load(&self) -> Result<Config> {
            Config::load(&self.0)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_template_set_loads_and_derives_what_it_leaves_out() {
        let dir = Dir::new("happy");
        let config = dir.load().unwrap();
        assert_eq!(config.main.sources, ["entra"]);
        assert_eq!(config.realm.base_dn(), "DC=example,DC=site");
        assert_eq!(config.realm.ad_dns_domain(), "example.site");
        assert_eq!(config.realm.idp_parent_ou(), "OU=CloudIdP,DC=example,DC=site");
        assert_eq!(config.realm.resource_ou(), "OU=Resources,DC=example,DC=site");
        assert_eq!(config.realm.netbios_domain(), "EXAMPLE");
        assert_eq!(config.realm.dc_hostname(), "kerbridge");
        assert_eq!(
            config.sources[0].ou(&config.realm.idp_parent_ou()),
            "OU=Entra,OU=CloudIdP,DC=example,DC=site"
        );
        assert!(config.warnings.is_empty(), "{:?}", config.warnings);
    }

    /// The five keys `realm.toml` gained for the realm's own identity and for
    /// provisioning: stated, each is taken as written; absent, each derives or
    /// falls to its documented default. `kbsetup` is their consumer -- it bakes
    /// three of them into a Samba database that cannot be told otherwise
    /// afterwards -- so this is what holds them to what the file promises before
    /// anything irreversible reads them.
    #[test]
    fn the_identity_and_provisioning_keys_derive_unless_the_file_states_them() {
        let stated: Realm = realm_stating(
            "netbios_domain = \"FLAT\"\n\
             dc_hostname = \"dc1\"\n\
             \n\
             [provision]\n\
             dns_forwarder = \"192.0.2.53\"\n\
             rpc_port_range = \"49152-49161\"\n\
             admin_password_file = \"/srv/keys/realm_admin\"\n",
        );
        assert_eq!(stated.netbios_domain(), "FLAT");
        assert_eq!(stated.dc_hostname(), "dc1");
        assert_eq!(stated.provision.dns_forwarder, "192.0.2.53");
        assert_eq!(stated.provision.rpc_port_range, "49152-49161");
        assert_eq!(stated.provision.admin_password_file, Path::new("/srv/keys/realm_admin"));

        // The defaults an operator reads off the template, held here so the
        // template cannot be the only thing that says what they are.
        let absent = realm_stating("");
        assert_eq!(absent.provision.dns_forwarder, "");
        assert_eq!(absent.provision.rpc_port_range, "49152-49251");
        assert_eq!(
            absent.provision.admin_password_file,
            Path::new("/etc/kerbridge.secrets/generated/realm_admin_password")
        );

        // Both derivations follow the key they are derived from rather than the
        // documented realm, which is what makes them derivations and not a
        // second spelling of `EXAMPLE`.
        let mut moved = realm_stating("");
        moved.realm = "ad.corp.example".to_owned();
        moved.ldap_url = "ldaps://dc1.ad.corp.example:636".to_owned();
        assert_eq!(moved.netbios_domain(), "AD");
        assert_eq!(moved.dc_hostname(), "dc1");
    }

    /// A `realm.toml` stating the three required keys and whatever else the
    /// caller is testing. Parsed on its own rather than through [`Config`]: the
    /// question is what one file's parser does with a line, and a set-wide
    /// cross-check would answer a different one.
    fn realm_stating(body: &str) -> Realm {
        toml::from_str(&format!(
            "realm = \"EXAMPLE.SITE\"\n\
             ldap_url = \"ldaps://kerbridge.example.site:636\"\n\
             ldap_ca_file = \"/run/kerbridge/realm-ca.pem\"\n\
             {body}"
        ))
        .expect("the document parses")
    }

    /// The one optional file, and the two values it leaves to `realm.toml`
    /// unless this host reaches the DC differently from the containers.
    #[test]
    fn kbmanage_is_optional_and_falls_back_to_the_realm() {
        let dir = Dir::new("kbmanage");
        let config = dir.load().unwrap();
        let k = config.kbmanage.as_ref().expect("the template set writes one");
        assert_eq!(k.ldap_url(&config.realm), config.realm.ldap_url);
        assert_eq!(k.ldap_ca_file(&config.realm), config.realm.ldap_ca_file);

        dir.write("kbmanage.toml", "bind_dn = \"CN=a\"\nbind_password_file = \"/p\"\nldap_url = \"ldaps://localhost:636\"\n");
        let config = dir.load().unwrap();
        assert_eq!(config.kbmanage.unwrap().ldap_url(&config.realm), "ldaps://localhost:636");

        std::fs::remove_file(dir.0.join(KBMANAGE_FILE)).unwrap();
        assert!(dir.load().unwrap().kbmanage.is_none());
    }

    /// Both halves of the rule: what [`is_source_name`] accepts, and that
    /// `load` is where a set carrying anything else is refused.
    #[test]
    fn a_source_name_is_refused_where_a_url_or_a_filename_could_not_carry_it() {
        for ok in ["entra", "entra-eu", "tenant.2", "a_b", "e0"] {
            assert!(is_source_name(ok), "{ok}");
        }
        for bad in ["", "../etc", ".hidden", "-lead", "two words", "a/b", "a%b", "ä"] {
            assert!(!is_source_name(bad), "{bad}");
        }

        let dir = Dir::new("source-name");
        dir.write(MAIN_FILE, "sources = [\"a/b\"]\n");
        let err = format!("{:#}", dir.load().unwrap_err());
        assert!(err.contains("not a source name"), "{err}");
    }

    /// Rule 1: a missing file names its path, not just the directory.
    #[test]
    fn a_missing_sibling_names_the_file_it_wanted() {
        let dir = Dir::new("missing-sibling");
        std::fs::remove_file(dir.0.join(SYNC_FILE)).unwrap();
        let err = format!("{:#}", dir.load().unwrap_err());
        assert!(err.contains("sync.toml"), "{err}");
    }

    /// Rule 2. The typo that silently keeps a default is the failure mode this
    /// whole file exists to end, so it is an error in every one of the structs.
    #[test]
    fn an_unknown_key_is_an_error_in_every_file() {
        for (file, body) in [
            (MAIN_FILE, "sources = []\ndevice_grant_dayz = 3\n"),
            (
                REALM_FILE,
                "realm = \"EXAMPLE.SITE\"\n\
                 ldap_url = \"ldaps://kerbridge.example.site:636\"\n\
                 ldap_ca_file = \"/run/kerbridge/realm-ca.pem\"\n\
                 base_bn = \"DC=example,DC=site\"\n",
            ),
            (ISSUERD_FILE, "sock = \"/run/kerbridge/issuer.sock\"\n"),
            (
                BROKER_FILE,
                "bind_dn = \"CN=b\"\n\
                 bind_password_file = \"/p\"\n\
                 lissen = \"127.0.0.1:8080\"\n",
            ),
            (SYNC_FILE, "dryrun = true\n"),
            (
                "idp_entra.toml",
                "name = \"entra\"\nprovider = \"entra\"\ngroup_suffix = \"none\"\n\
                 bind_dn = \"CN=s\"\nbind_password_file = \"/p\"\ntennant_id = \"x\"\n",
            ),
        ] {
            let dir = Dir::new("unknown-key");
            dir.write(file, body);
            let err = format!("{:#}", dir.load().unwrap_err());
            assert!(err.contains("unknown field"), "{file}: {err}");
            assert!(err.contains(file), "{file}: {err}");
        }
        // And the nested table, which is a struct of its own.
        let dir = Dir::new("unknown-key-notify");
        dir.write(MAIN_FILE, "sources = []\n\n[notify]\nmin_severty = \"error\"\n");
        let err = format!("{:#}", dir.load().unwrap_err());
        assert!(err.contains("unknown field"), "{err}");
    }

    /// Rule 3. Refusing to start beats serving a realm with a source silently
    /// absent: the objects that source owns are still there and still nobody's.
    #[test]
    fn a_listed_source_with_no_file_refuses_to_start() {
        let dir = Dir::new("listed-missing");
        dir.write(MAIN_FILE, "sources = [\"entra\", \"google\"]\n");
        let err = format!("{:#}", dir.load().unwrap_err());
        assert!(err.contains("idp_google.toml"), "{err}");
    }

    /// Rule 4: the half-edited `cp idp_entra.toml idp_google.toml`.
    #[test]
    fn a_source_whose_name_disagrees_with_its_filename_is_refused() {
        let dir = Dir::new("name-mismatch");
        dir.write(MAIN_FILE, "sources = [\"google\"]\n");
        dir.write("idp_google.toml", &envelope("entra", "entra"));
        let err = format!("{:#}", dir.load().unwrap_err());
        assert!(err.contains("idp_google.toml"), "{err}");
        assert!(err.contains("\"entra\""), "{err}");
    }

    /// Rule 5. Deduplicating silently would mean the file said one thing and
    /// the process did another.
    #[test]
    fn a_duplicated_source_name_is_refused_rather_than_deduplicated() {
        let dir = Dir::new("duplicate");
        dir.write(MAIN_FILE, "sources = [\"entra\", \"entra\"]\n");
        let err = format!("{:#}", dir.load().unwrap_err());
        assert!(err.contains("\"entra\"") && err.contains("twice"), "{err}");
    }

    /// The paths a deployment gets without asking, and the one word that gives
    /// each of them up. An operator who deletes the line keeps the audit trail;
    /// only `none` drops it.
    #[test]
    fn a_switchable_path_defaults_on_and_only_none_turns_it_off() {
        let issuerd = |body: &str| toml::from_str::<Issuerd>(body).unwrap().audit_log_file;
        assert_eq!(issuerd("").unwrap(), PathBuf::from("/var/log/kerbridge/issuerd/audit.log"));
        assert_eq!(issuerd("audit_log_file = \"none\""), None);
        assert_eq!(
            issuerd("audit_log_file = \"/srv/audit.log\"").unwrap(),
            PathBuf::from("/srv/audit.log")
        );

        let sync = |body: &str| toml::from_str::<Sync>(body).unwrap().audit_log_file;
        assert_eq!(sync("").unwrap(), PathBuf::from("/var/log/kerbridge/sync/audit.log"));
        assert_eq!(sync("audit_log_file = \"none\""), None);
        assert_eq!(
            sync("audit_log_file = \"/srv/sync.log\"").unwrap(),
            PathBuf::from("/srv/sync.log")
        );

        let notify = |body: &str| toml::from_str::<Notify>(body).unwrap().state_dir;
        assert_eq!(notify("").unwrap(), PathBuf::from("/var/lib/kerbridge"));
        assert_eq!(notify("state_dir = \"none\""), None);

        // No default: there is no webhook a deployment can be assumed to have,
        // and absence here is a working state rather than a switched-off one.
        assert_eq!(toml::from_str::<Notify>("").unwrap().url_file, None);
    }

    /// Two names, one container. Reachable only through the `ou` override, and
    /// the whitespace and case are the point: AD would treat these as one OU,
    /// so a comparison that did not would let the pair through.
    #[test]
    fn two_sources_may_not_own_one_ou() {
        let dir = Dir::new("shared-ou");
        dir.write(MAIN_FILE, "sources = [\"entra\", \"google\"]\n");
        dir.write(
            "idp_entra.toml",
            &format!(
                "{}\nou = \"OU=Entra,OU=CloudIdP,DC=example,DC=site\"\n",
                envelope("entra", "entra")
            ),
        );
        dir.write(
            "idp_google.toml",
            &format!(
                "{}\nou = \"ou=entra, ou=cloudidp, dc=example, dc=site\"\n",
                envelope("google", "entra")
            ),
        );
        let err = format!("{:#}", dir.load().unwrap_err());
        assert!(err.contains("idp_entra.toml") && err.contains("idp_google.toml"), "{err}");

        // The derivation gives each its own, so the default set is not caught by
        // this: the check has to refuse the override and nothing else.
        let dir = Dir::new("derived-ou");
        dir.write(MAIN_FILE, "sources = [\"entra\", \"google\"]\n");
        dir.write("idp_google.toml", &envelope("google", "entra"));
        assert_eq!(dir.load().unwrap().sources.len(), 2);
    }

    /// Rule 6, the one deliberate non-error.
    #[test]
    fn an_unlisted_source_file_is_a_warning_and_not_a_refusal() {
        let dir = Dir::new("unlisted");
        dir.write("idp_google.toml", &envelope("google", "entra"));
        let config = dir.load().unwrap();
        assert_eq!(config.sources.len(), 1);
        assert_eq!(
            config.warnings,
            ["idp_google.toml present, not listed in main.sources -- ignored"]
        );
        // The committed templates sit in the same directory in a live
        // deployment and are not sources.
        let dir = Dir::new("unlisted-example");
        dir.write("idp_google.toml.example", &envelope("google", "entra"));
        assert!(dir.load().unwrap().warnings.is_empty());
    }

    /// Rule 7. The bind password, and every password sync writes, would
    /// otherwise cross the network in the clear.
    #[test]
    fn a_plain_ldap_url_is_refused() {
        let dir = Dir::new("plain-ldap");
        dir.write(
            REALM_FILE,
            "realm = \"EXAMPLE.SITE\"\n\
             ldap_url = \"ldap://kerbridge.example.site:636\"\n\
             ldap_ca_file = \"/run/kerbridge/realm-ca.pem\"\n",
        );
        let err = format!("{:#}", dir.load().unwrap_err());
        assert!(err.contains("realm.toml: ldap_url"), "{err}");
    }

    /// A `realm.toml` body written into a whole set, so the refusal comes from
    /// `load` and not from a parser called on one file: these four rules are
    /// what every binary meets at startup, and a test that bypassed `load`
    /// would not say so.
    fn refused(label: &str, body: &str) -> String {
        let dir = Dir::new(label);
        dir.write(
            REALM_FILE,
            &format!(
                "ldap_ca_file = \"/run/kerbridge/realm-ca.pem\"\n\
                 {body}"
            ),
        );
        format!("{:#}", dir.load().unwrap_err())
    }

    /// #40's fourth rule, added from #77: nothing anywhere judged the realm's
    /// case. `ad_dns_domain` derives as the realm lowercased, so a lower-case
    /// realm derives a DNS domain identical to itself, and the set that results
    /// agrees with itself at every later cross-check.
    #[test]
    fn a_lower_case_realm_is_refused() {
        let err = refused(
            "lowercase-realm",
            "realm = \"example.site\"\n\
             ldap_url = \"ldaps://kerbridge.example.site:636\"\n",
        );
        assert!(err.contains("not upper case"), "{err}");
        assert!(err.contains("EXAMPLE.SITE"), "{err}");

        // The one that made it invisible: derived and stated agree, because the
        // derivation is the lower-casing.
        let mut realm = realm_stating("");
        realm.realm = "example.site".to_owned();
        assert_eq!(realm.ad_dns_domain(), realm.realm);
    }

    /// #40's flat-name rule. Judged on the effective value, so the derivation
    /// is covered as well as a stated name -- and the over-long derived one
    /// names the key to state instead of being cut to fit, which would be a
    /// fourth spelling of the domain.
    #[test]
    fn a_flat_name_that_is_not_flat_or_will_not_fit_is_refused() {
        for (label, body) in [
            ("netbios-dotted", "netbios_domain = \"EXAMPLE.SITE\"\n"),
            ("netbios-spaced", "netbios_domain = \"EXAMPLE SITE\"\n"),
        ] {
            let err = refused(
                label,
                &format!(
                    "realm = \"EXAMPLE.SITE\"\n\
                     ldap_url = \"ldaps://kerbridge.example.site:636\"\n\
                     {body}"
                ),
            );
            assert!(err.contains("not a flat name"), "{label}: {err}");
        }

        // Stated and too long: the operator's own value, and nothing to derive.
        let err = refused(
            "netbios-long",
            "realm = \"EXAMPLE.SITE\"\n\
             ldap_url = \"ldaps://kerbridge.example.site:636\"\n\
             netbios_domain = \"SIXTEENCHARSXXXX\"\n",
        );
        assert!(err.contains("16 characters"), "{err}");

        // Derived and too long: the realm's first label is, and the message has
        // to hand over the key rather than a shortened name.
        let err = refused(
            "netbios-derived-long",
            "realm = \"VERYLONGFIRSTLABEL.SITE\"\n\
             ldap_url = \"ldaps://kerbridge.verylongfirstlabel.site:636\"\n",
        );
        assert!(err.contains("netbios_domain"), "{err}");
        assert!(err.contains("18 characters"), "{err}");
        assert!(!err.contains("VERYLONGFIRSTLA\""), "truncation offered: {err}");

        // Fifteen is inside it, and the whole set still loads with one stated.
        let dir = Dir::new("netbios-fifteen");
        dir.write(
            REALM_FILE,
            "realm = \"EXAMPLE.SITE\"\n\
             ldap_url = \"ldaps://kerbridge.example.site:636\"\n\
             ldap_ca_file = \"/run/kerbridge/realm-ca.pem\"\n\
             netbios_domain = \"FIFTEENCHARSXXX\"\n",
        );
        assert_eq!(dir.load().unwrap().realm.netbios_domain(), "FIFTEENCHARSXXX");
    }

    /// #40's short-name rule. It bites on a stated value alone -- the
    /// derivation takes `ldap_url`'s first label and has no dot left to find --
    /// which is exactly why nothing caught it once the value moved out of
    /// `.env`.
    #[test]
    fn a_fully_qualified_dc_hostname_is_refused() {
        let err = refused(
            "dc-hostname-fqdn",
            "realm = \"EXAMPLE.SITE\"\n\
             ldap_url = \"ldaps://kerbridge.example.site:636\"\n\
             dc_hostname = \"kerbridge.example.site\"\n",
        );
        assert!(err.contains("fully qualified"), "{err}");
        assert!(err.contains("\"kerbridge\""), "{err}");

        // The derivation cannot reach it, so the rule must not fire on the
        // shipped set that states nothing.
        assert_eq!(realm_stating("").dc_hostname(), "kerbridge");
    }

    /// #40's SAN rule. The names come from the config set rather than from
    /// `ldap_ca_file`, which is the CA and carries no `subjectAltName` -- see
    /// [`realm_shape`]. Loopback is in the set because `make_tls` signs it, for
    /// host-run tooling reaching the published port.
    #[test]
    fn an_ldap_url_the_realm_certificate_would_not_cover_is_refused() {
        let err = refused(
            "ldap-host-uncovered",
            "realm = \"EXAMPLE.SITE\"\n\
             ldap_url = \"ldaps://dc1.corp.example:636\"\n",
        );
        assert!(err.contains("does not cover"), "{err}");
        assert!(err.contains("dc1.example.site"), "{err}");

        // Every name make_tls signs, and the IPv6 literal that the host parser
        // has to unwrap before any of them can match.
        for url in [
            "ldaps://kerbridge.example.site:636",
            "ldaps://kerbridge:636",
            "ldaps://localhost:636",
            "ldaps://127.0.0.1:636",
            "ldaps://[::1]:636",
        ] {
            let dir = Dir::new("ldap-host-covered");
            dir.write(
                REALM_FILE,
                &format!(
                    "realm = \"EXAMPLE.SITE\"\n\
                     ldap_url = \"{url}\"\n\
                     ldap_ca_file = \"/run/kerbridge/realm-ca.pem\"\n\
                     dc_hostname = \"kerbridge\"\n"
                ),
            );
            dir.load().unwrap_or_else(|e| panic!("{url}: {e:#}"));
        }
    }

    #[test]
    fn the_child_ou_uppercases_only_the_first_character() {
        assert_eq!(title_case("entra"), "Entra");
        assert_eq!(title_case("authentik"), "Authentik");
        assert_eq!(title_case("okta-eu"), "Okta-eu");
        assert_eq!(title_case(""), "");
    }
}
