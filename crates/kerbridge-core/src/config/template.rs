//! The commented `*.toml.example` set, held next to the structs it describes.
//!
//! These are documentation as much as templates -- `deploy/.env.example` was,
//! and this is where its prose went. Keeping them here rather than as files
//! under `deploy/` is what a test can hold to the parser: every shown value is
//! uncommented, parsed back and compared against the struct default, so a
//! template that documents a number the code does not use fails the build
//! rather than misleading an operator.
//!
//! **A template states the required options and comments out every other one.**
//! A live file then holds the operator's configuration decisions and nothing
//! else, which is what lets a later version change a default and reach a
//! deployment that never decided anything about that option. A stated default
//! could not be told apart from a configuration decision, so it would pin every
//! deployment to the value shipped on the day it was installed. The terms:
//! `crates/kerbridge-config/GLOSSARY.md`.
//!
//! The realm is the documented one throughout (`EXAMPLE.SITE`), and every
//! identifier is a placeholder. An operator copies these and edits them; a
//! reader on GitHub gets the whole settings surface without cloning.

use super::{BROKER_FILE, ISSUERD_FILE, KBMANAGE_FILE, MAIN_FILE, REALM_FILE, SYNC_FILE};

/// The files this crate owns, as `(filename, source)`. A source names its keys
/// with `{{key}}` rather than spelling them; [`render`] turns one into the
/// document an operator reads, and [`templates`] does that for all six.
///
/// An `idp_<name>.toml` is not here: half of it comes from the adapter, so
/// `kerbridge-idp` guards that one.
pub const TEMPLATE_SOURCES: [(&str, &str); 6] = [
    (MAIN_FILE, MAIN_SRC),
    (REALM_FILE, REALM_SRC),
    (ISSUERD_FILE, ISSUERD_SRC),
    (BROKER_FILE, BROKER_SRC),
    (SYNC_FILE, SYNC_SRC),
    (KBMANAGE_FILE, KBMANAGE_SRC),
];

/// The six files as an operator reads them, in [`TEMPLATE_SOURCES`] order.
///
/// The committed `deploy/configs/*.toml.example` set is this, and a test holds
/// the two together. Behind the `schema` feature because rendering needs the
/// parser's description of itself, and `issuerd` must compile no schemars.
#[cfg(feature = "schema")]
pub fn templates() -> Result<Vec<(&'static str, String)>, String> {
    described()?
        .into_iter()
        .map(|(file, source, schema)| Ok((file, render(file, source, &schema)?)))
        .collect()
}

/// The six files as JSON Schema, in [`TEMPLATE_SOURCES`] order.
///
/// The same description [`templates`] renders from, handed to a caller that
/// wants it as a document rather than as a rendered file. `kbconfig schema`
/// writes these out for an editor to validate a live file against.
#[cfg(feature = "schema")]
pub fn schemas() -> Result<Vec<(&'static str, serde_json::Value)>, String> {
    Ok(described()?.into_iter().map(|(file, _, schema)| (file, schema)).collect())
}

/// The envelope half of an `idp_<name>.toml` as JSON Schema.
///
/// Without `provider_config`, which is `schemars(skip)` for the reason stated
/// where [`super::SourceFile`] declares it. A caller that wants the whole
/// document asks `kerbridge-idp`, which is the one crate holding both halves.
#[cfg(feature = "schema")]
pub fn source_schema() -> Result<serde_json::Value, String> {
    json_schema::<super::SourceFile>()
}

/// Each file, its source and its schema, so that the two public views cannot
/// fall into different orders or disagree about which schema describes which
/// file.
#[cfg(feature = "schema")]
fn described() -> Result<Vec<(&'static str, &'static str, serde_json::Value)>, String> {
    use crate::config::{Broker, Issuerd, Kbmanage, Main, Realm, Sync};

    Ok(vec![
        (MAIN_FILE, MAIN_SRC, json_schema::<Main>()?),
        (REALM_FILE, REALM_SRC, json_schema::<Realm>()?),
        (ISSUERD_FILE, ISSUERD_SRC, json_schema::<Issuerd>()?),
        (BROKER_FILE, BROKER_SRC, json_schema::<Broker>()?),
        (SYNC_FILE, SYNC_SRC, json_schema::<Sync>()?),
        (KBMANAGE_FILE, KBMANAGE_SRC, json_schema::<Kbmanage>()?),
    ])
}

#[cfg(feature = "schema")]
fn json_schema<T: schemars::JsonSchema>() -> Result<serde_json::Value, String> {
    serde_json::to_value(schemars::schema_for!(T))
        .map_err(|e| format!("the schema is not JSON: {e}"))
}

/// The envelope half of an `idp_<name>.toml` for a source of this name and
/// provider, ending in a blank line: the adapter's `[provider_config]` block is
/// appended to this, and only `kerbridge-idp` holds both halves.
///
/// The envelope is the one template that is a *function*, because a source
/// names itself in five of its own values. `{name}`, `{Name}` and `{provider}`
/// are its parameters, and they stand in the prose and in the examples alike --
/// so the substitution runs once, over the rendered document. That is what lets
/// a second adapter emit its own example file with no edit here, which is the
/// property the provider interface exists for.
#[cfg(feature = "schema")]
pub fn source_envelope(name: &str, provider: &str) -> Result<String, String> {
    let schema = source_schema()?;
    let title = super::title_case(name);
    Ok(render(SOURCE_FILE_LABEL, SOURCE_ENVELOPE_SRC, &schema)?
        .replace("{name}", name)
        .replace("{Name}", &title)
        .replace("{provider}", provider))
}

/// What an error names, there being no one filename: a source file is
/// `idp_<name>.toml` for whichever name the deployment chose.
#[cfg(feature = "schema")]
const SOURCE_FILE_LABEL: &str = "idp_<name>.toml";

/// Render a template source into the document an operator reads.
///
/// A `{{key}}` line becomes that key's line, in the form the schema decides:
/// stated for a required key, `#key = <default>` where there is a default, and
/// a bare `#key =` under an `# Example:` line where there is neither. The value
/// is therefore never typed twice, so it cannot drift from the parser.
///
/// Prose comes from one of two places and never both. A comment block directly
/// above the placeholder is the template's, and is used as written -- that is
/// what carries the section banners, the aligned option tables and the blank
/// lines that group. A placeholder with nothing above it takes the field's own
/// doc comment instead, one `# ` line per doc line. A field that has a doc
/// comment *and* prose above it in the template is refused: two descriptions of
/// one key are how the pair comes to disagree.
#[cfg(feature = "schema")]
pub fn render(file: &str, source: &str, schema: &serde_json::Value) -> Result<String, String> {
    let lines: Vec<&str> = source.lines().collect();
    let mut out = String::with_capacity(source.len());
    // One file can hold more than one struct: `[notify]` inside `main.toml` is
    // its own. A table header switches which struct the keys below it belong
    // to, and each is held to its own key set.
    let mut table = Table::root(file, schema)?;
    // A `[name]` header names a table of the *file*, never of the table above
    // it: `[notify]` after `[client_defaults]` in main.toml is a sibling, not a
    // descent. Resolve from the open table and the second header is an error.
    let root = Table::root(file, schema)?;
    let mut done: Vec<Table> = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            // A header naming the table already open writes it and changes
            // nothing: an adapter's block is `[provider_config]` at the root of
            // its own schema, so the line that opens it is not a descent.
            if name != table.name {
                let next = root.child(name, schema)?;
                done.push(std::mem::replace(&mut table, next));
            }
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let Some(key) = line.strip_prefix("{{").and_then(|l| l.strip_suffix("}}")) else {
            out.push_str(line);
            out.push('\n');
            continue;
        };
        let property = table
            .properties
            .get(key)
            .ok_or_else(|| format!("{{{{{key}}}}}: {} has no such key", table.name))?;
        table.seen.push(key.to_owned());

        // A comment above means the template owns the prose, and the field's
        // own doc is left to rustdoc. The two answer different questions where
        // both exist -- `Main::sources` documents that an empty list is a
        // deployment mid-bootstrap, which is the parser's business, while the
        // template explains the enable switch, which is the operator's. A key
        // with nothing above it takes the doc instead.
        if !prose_above(&lines, i) {
            let doc = property.get("description").and_then(serde_json::Value::as_str);
            for line in doc.unwrap_or_default().lines() {
                out.push_str(if line.is_empty() { "#" } else { "# " });
                out.push_str(line);
                out.push('\n');
            }
        }

        let example = property.get("examples").and_then(|e| e.get(0));
        let default = property.get("default").filter(|d| !d.is_null());
        match (table.required.iter().any(|r| r == key), default, example) {
            (true, _, Some(value)) => out.push_str(&format!("{key} = {}\n", toml_value(value)?)),
            (true, _, None) => {
                return Err(format!("{key} is required, so it needs a schemars(example = ...)"));
            }
            (false, Some(value), _) => out.push_str(&format!("#{key} = {}\n", toml_value(value)?)),
            (false, None, Some(value)) => {
                out.push_str(&format!("# Example: {}\n#{key} =\n", toml_value(value)?));
            }
            (false, None, None) => {
                return Err(format!(
                    "{key} has no default, so it needs a schemars(example = ...) to show a shape"
                ));
            }
        }
    }

    done.push(table);
    for table in &done {
        let missed: Vec<&str> = table
            .properties
            .keys()
            .map(String::as_str)
            .filter(|k| !table.seen.iter().any(|s| s == k))
            // A table has its own placeholder-free line, the header.
            .filter(|k| !done.iter().any(|t| t.name == **k))
            .collect();
        if !missed.is_empty() {
            return Err(format!("{} names none of: {}", table.name, missed.join(", ")));
        }
    }
    Ok(out)
}

/// Whether a comment block covers this key. The walk crosses the placeholders
/// above it, because one prose block routinely covers a run of keys -- the four
/// ticket ceilings in `realm.toml` are one paragraph and four lines.
#[cfg(feature = "schema")]
fn prose_above(lines: &[&str], i: usize) -> bool {
    lines[..i].iter().rev().find(|l| !l.starts_with("{{")).is_some_and(|l| l.starts_with('#'))
}

/// One struct's key set, while the lines belonging to it are rendered.
#[cfg(feature = "schema")]
pub(super) struct Table {
    pub(super) name: String,
    pub(super) properties: serde_json::Map<String, serde_json::Value>,
    pub(super) required: Vec<String>,
    seen: Vec<String>,
}

#[cfg(feature = "schema")]
impl Table {
    pub(super) fn root(file: &str, schema: &serde_json::Value) -> Result<Self, String> {
        Self::of(file, schema, schema)
    }

    /// The struct a `[name]` header opens, found as a property of the file's
    /// root table and followed through its `$ref` into `$defs`.
    pub(super) fn child(&self, name: &str, root: &serde_json::Value) -> Result<Self, String> {
        let property = self
            .properties
            .get(name)
            .ok_or_else(|| format!("[{name}]: {} has no such table", self.name))?;
        let target = match property.get("$ref").and_then(serde_json::Value::as_str) {
            Some(reference) => {
                let key = reference.rsplit('/').next().unwrap_or_default();
                root.get("$defs")
                    .and_then(|defs| defs.get(key))
                    .ok_or_else(|| format!("[{name}]: the schema defines no {key}"))?
            }
            None => property,
        };
        Self::of(name, target, root)
    }

    fn of(
        name: &str,
        schema: &serde_json::Value,
        _root: &serde_json::Value,
    ) -> Result<Self, String> {
        Ok(Self {
            name: name.to_owned(),
            properties: schema
                .get("properties")
                .and_then(serde_json::Value::as_object)
                .cloned()
                .ok_or_else(|| format!("{name}: the schema states no properties"))?,
            required: schema
                .get("required")
                .and_then(serde_json::Value::as_array)
                .map(|a| {
                    a.iter().filter_map(serde_json::Value::as_str).map(str::to_owned).collect()
                })
                .unwrap_or_default(),
            seen: Vec::new(),
        })
    }
}

/// A JSON value as TOML. Single-quoted where the string holds a `"`, which is
/// what `notify.template`'s JSON body needs.
#[cfg(feature = "schema")]
fn toml_value(value: &serde_json::Value) -> Result<String, String> {
    Ok(match value {
        serde_json::Value::String(s) if s.contains('"') => format!("'{s}'"),
        serde_json::Value::String(s) => format!("{s:?}"),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Array(items) => {
            let rendered: Result<Vec<String>, String> = items.iter().map(toml_value).collect();
            format!("[{}]", rendered?.join(", "))
        }
        other => return Err(format!("{other} is not a value a template can show")),
    })
}

#[cfg(feature = "schema")]
const SOURCE_ENVELOPE_SRC: &str = r#"# One cloud IdP, as this realm stores it.
#
# The filename stem after `idp_` is the source name, and `name` below repeats
# it. Everything above [provider_config] is about *our* directory and *our*
# naming policy and is read by KerBridge itself; everything inside that block is
# about the cloud IdP and is read only by that provider's adapter.
#
# Add the file's name to `sources` in main.toml. That list is the enable switch:
# a file no name lists is ignored, with a line in the log saying so.
#
# A commented-out line sets nothing. `#some_option = 8` means that KerBridge
# uses 8, the default for that option. `#some_option =`, with no value, means
# that the option has no default: the comment above the line says what
# KerBridge does instead, and shows an example. main.toml gives the full rule.

# !! FROZEN AT FIRST PROVISIONING !!
#
# The source name goes into every synchronized object's identity value, which is
# what the broker searches for on every login. Change it afterwards and every
# one of those values is rewritten: sync sees the old objects as gone, retires
# each account and creates a replacement with a NEW SID, and every file whose
# owner was resolved from the old SID loses its owner. Silent, and not
# recoverable without a directory restore.
#
# Pointing an existing name at a different tenant costs the same. That one is at
# least loud -- the new tenant's subjects share none of the old ones, so sync
# retires every account and creates a replacement rather than confusing two
# people -- but every SID is still new. A new tenant gets a new name and its own
# file. Detail: docs/setup/names-and-decisions.md.
{{name}}

# Which adapter verifies this source's tokens and reads its directory.
{{provider}}

# What this source's group login names end with, which is what keeps them out of
# every other source's. A sAMAccountName is unique across the whole realm, so
# two cloud IdPs that each hold a `payroll` group collide -- and the second one
# to reach the name refuses every sync cycle, mirroring no users either, until
# one of them is renamed in its own IdP.
#
#   -entra, _goog, ...  appended to every synchronized group's login name, so
#                       `payroll` becomes `payroll-entra`. Up to 20 characters,
#                       none of them whitespace or anything AD or a DN rejects.
#   none                no suffix. The right answer while this is your only
#                       cloud IdP and you accept renaming its groups if you ever
#                       add a second.
#
# Choose it before a second source exists. Chosen afterwards it renames groups
# that are already in use, and a share ACL refers to the old name.
{{group_suffix}}

# This source's own directory account, and the file holding its password. One
# account per source, never a shared one: AD enforces the write delegation
# against the bound identity, and the directory's own audit is how you tell
# which source's cycle wrote what.
#
# Under /etc/kerbridge.secrets/generated/idp/<name>/, which is one mounted
# directory rather than a Docker secret each -- so a second source needs no edit
# to compose.yaml. The host side is deploy/secrets/generated/idp/{name}/, and
# `kbsetup directory` writes this one with the account. The credential you paste
# in yourself sits apart, under idp/: the two have different writers.
{{bind_dn}}
{{bind_password_file}}

# The IdP-specific OU this source owns, derived from `name` and
# realm.idp_parent_ou. State it only for a directory whose existing layout
# collides with the derived name.
#
{{ou}}

"#;

const MAIN_SRC: &str = r#"# KerBridge, entry point.
#
# The other files are found beside this one under fixed names -- realm.toml,
# issuerd.toml, broker.toml, sync.toml, the optional kbmanage.toml, and one
# idp_<source>.toml per cloud IdP. A binary is given this *directory*, never one
# file in it, so --config <dir> relocates the whole set.
#
# Copy the *.toml.example set to *.toml and edit. Secrets are files under
# deploy/secrets/ and are named here as paths, never written here as values.
# Procedure: SETUP.md.
#
# HOW TO READ THESE FILES
#
# Each configuration option is one line: its key, `=`, and its value. A line
# that starts with `#` is commented out and sets nothing. Two forms:
#
#   #some_option = 8    KerBridge uses 8. That is the default.
#   #some_option =      This option has no default. KerBridge derives the value
#                       from another option, or leaves it unset. The comment
#                       above the line says which, and shows an example.
#
# To set an option, remove the `#` and write the value. For the second form you
# must also supply a value: `some_option =` alone is not valid TOML.
#
# Leave every other line commented out. A default can change when you install a
# new version, and an option you left alone then uses the new value. An option
# you set keeps your value, even where the new default is better.
#
# `kbconfig get <path>` prints the value in use, and `kbconfig decisions` lists
# every option this deployment sets.
#
# This file holds what would not exist without KerBridge. Anything that would
# still be true of the realm if a different tool fronted it is in realm.toml.

# The cloud IdPs this deployment serves, one per idp_<name>.toml beside this
# file. The list is the enable switch: drop a name and keep the file, and sync
# stops mirroring that source and the broker stops serving its path, with
# nothing already in the directory touched.
#
# Never a wildcard, deliberately. A source that disappeared by glob would orphan
# every object it owns -- SIDs, memberships, file ownership -- with nothing
# reporting it. A listed name with no file refuses to start; a file no name
# lists is ignored, with a line in the log saying so.
{{sources}}


# --- Device grants: let a machine skip the browser sign-in ---
# Read docs/setup/device-grants.md before turning this on.

# How long a machine may go without a human proving the identity to the cloud
# IdP again. 0 is off, and off is the default: an operator who does nothing gets
# nothing.
#
# NOT a revocation window. Every lever in DESIGN.md @ Ticket policy still takes
# at most one ticket lifetime, because each is re-checked on the exchange path.
# Lowering this clamps every outstanding grant at its next exchange; raising it
# stretches none.
{{device_grant_days}}

# Grants one account may hold. A safety bound rather than policy -- what stops a
# compromised broker from looping the grant verb until the object will not load.
# Configurable because one service account across twenty build machines is the
# economical shape, cloud IdPs licensing per user.
{{device_grant_max_per_user}}


# --- Client defaults: what a workstation agent does where nobody has said ---
# Served in the broker's /config document, which every agent already reads for
# the realm and the KDCs. It reaches the machines no management system owns.
#
# Below the machine policy (HKLM\Software\Policies\KerBridge on Windows, an MDM
# profile on macOS) and below the user's own choice, both of which win. Leave an
# option unset and the agent keeps its own built-in answer -- which is also what
# lets a later client version change that answer.
[client_defaults]

{{autostart}}

{{windows_sign_in}}

{{ntlm_fallback_recovery}}


# --- Operator notification ---
# For conditions only a human can fix and nothing else will report: an expiring
# Graph credential, a deleted admission group, a sync cycle that keeps failing.
#
# With no url_file every event is still a `NOTIFY <severity> <event>:` line in
# the service log, and state_dir keeps the currently-true conditions for your
# own monitoring. The full story, including the monitoring-agent recipe:
# deploy/README.md @ Operator notification. Verify delivery end to end with
# `make test-notification`, from deploy/.
[notify]

# The webhook URL is a secret, not a setting: for Slack, Teams and the rest the
# URL is the receiver's only authentication. https:// only.
#
{{url_file}}

# One JSON file per currently-true condition, which a monitoring agent can read
# without KerBridge's cooperation and which is written whether or not a webhook
# is configured.
#
# This is the parent. Each service takes the directory named after itself under
# it -- broker/, sync/, issuerd/ -- so three services never write over one
# another. Point a monitoring agent at the parent and it sees all three.
#
# `none` gives that up: open problems are then tracked in memory only, so
# nothing outside the process can read them and a restart re-sends whatever is
# still outstanding.
{{state_dir}}

# The JSON body. Unset uses a default that Slack, Teams, Mattermost and
# Rocket.Chat all render. Placeholders: %EVENT% %SEVERITY% %COMPONENT% %REALM%
# %TIMESTAMP% %MESSAGE% %DETAIL% %ICON%. Every substituted value is escaped as a JSON
# string, so each placeholder must sit inside one; an unknown placeholder, or a
# template that does not render as JSON, refuses to start.
#
{{template}}

# Suppress anything below this: info, warning or error.
{{min_severity}}

# How long a *standing* condition waits before it is reported again. An expiry
# does not use this -- it is reported at 30, 14, 7, 3 and 1 days remaining and
# is silent between those. Also the flap damper: a condition that clears and
# comes straight back is not announced twice within this window, though the
# state files still record every transition.
{{repeat_interval_hours}}

# The whole delivery attempt -- connect, TLS, request, response.
{{timeout_seconds}}

# A CA bundle for a self-hosted receiver behind a private CA, added to the
# public roots rather than replacing them. Must be a path the service can read;
# mount it yourself if it is not already there.
#
{{ca_file}}

# LAST RESORT, LAB ONLY. Names the one host whose certificate is not validated,
# and permits http:// to that host. Anyone on the path to it can then capture
# the webhook URL and post forged alerts with it -- which mutes the alarm rather
# than triggering it. Logs a warning for as long as it is set, and does nothing
# if it does not name the host the webhook URL actually points at.
#
{{insecure_host}}
"#;

const REALM_SRC: &str = r#"# The realm, as anything fronting it would see it. Nothing here is specific to
# KerBridge; what is, is in main.toml. The one exception is the [provision]
# table at the end, which is specific to Samba -- a different axis: it says how
# this realm was made, not what it is.
#
# A commented-out line sets nothing. `#some_option = 8` means that KerBridge
# uses 8, the default for that option. `#some_option =`, with no value, means
# that the option has no default: the comment above the line says what
# KerBridge does instead, and shows an example. main.toml gives the full rule.

# SET ONCE, BEFORE THE FIRST PROVISIONING. Baked into the Samba database, and
# startup fails if this later disagrees with it.
#
# UPPER CASE, and refused otherwise. ad_dns_domain below is this lowercased, so
# a lower-case realm here derives a DNS domain identical to itself and looks
# self-consistent everywhere -- samba-tool would provision it, and nothing after
# that can correct the name.
{{realm}}

# Derived from `realm` -- the domain root the same way AD derives it, and the
# UPN suffix as the realm lowercased. State either only if this realm was
# provisioned with something else.
#
{{base_dn}}
#
{{ad_dns_domain}}

# The domain's flat NT4-era name: what `EXAMPLE\alice` means and what a Windows
# client shows. One label, no dots and no spaces, 15 characters at most. Derived
# as the realm's first label uppercased, which is the answer samba-tool itself
# picks -- state it only for a realm provisioned with a different one.
#
{{netbios_domain}}

# The DC's own short name, never its FQDN: that is this plus ad_dns_domain, and
# is what the LDAPS certificate is issued for. Derived from ldap_url's host,
# which already carries it -- state it only where ldap_url names an address
# rather than a name, which is the one case there is nothing to derive from.
#
{{dc_hostname}}

# The OU holding one IdP-specific OU per cloud IdP, and nothing else. kbmanage
# and issuerd test containment against this one: their question is "is this DN
# sync-owned", which has to stay a single question however many cloud IdPs you
# add. Each source's own OU is derived from it and the source name -- see
# idp_<source>.toml.
#
{{idp_parent_ou}}

# Where your own resource groups live: outside every IdP-specific OU, because
# sync does not own them and must not reconcile them away.
#
{{resource_ou}}

# ldaps:// only. Plain ldap:// is refused where it is read, and StartTLS is not
# negotiated either: the bind password, and every password sync writes, would
# otherwise cross the network in the clear.
{{ldap_url}}

# The realm's own CA, and only it -- there is no fallback to the OS trust store.
# Samba's certificate has no SAN, so provisioning creates one from a CA that
# exists only in the realm container and publishes it at this path.
{{ldap_ca_file}}

# What enrollment publishes to a client. Empty is the normal answer for both:
# the realm is located through its _kerberos._udp SRV record, so enrollment pins
# no KDC hostname and survives a DC being replaced. `services` is the escape
# hatch for a service outside the realm's DNS zone, which the client's
# DNS-suffix heuristic would not map.
{{kdcs}}
{{services}}

# Kerberos ticket policy: 10 hours, renewable for 7 days.
#
# The first pair is what the broker asks for. The second is what issuerd is
# willing to issue whatever it is asked -- Samba's own domain policy then caps
# both again, so asking for more than the KDC allows gets what the KDC grants
# rather than an error.
{{ticket_lifetime_seconds}}
{{ticket_renewable_seconds}}
{{max_lifetime_seconds}}
{{max_renewable_seconds}}


# --- Provisioning: read once, when the realm is created ---
# What Samba is told the day the realm is made, and the one group in this file
# that is Samba's rather than the realm's. `kbsetup realm` reads these and
# nothing reads them again: changing one afterwards reaches the realm only by
# reprovisioning it, or by editing smb.conf in the volume by hand.
[provision]

{{dns_forwarder}}

{{rpc_port_range}}

{{admin_password_file}}
"#;

/// `issuerd.toml`, before the key lines are filled in. The prose blocks that
/// cover more than one key stay here; a key documented on its own field takes
/// its comment from there. See [`render`].
const ISSUERD_SRC: &str = r#"# issuerd: the only process holding KDC authority. It binds no network socket
# and reads sam.ldb locally, so all of this is about the one Unix socket the
# broker reaches it on.
#
# A commented-out line sets nothing. `#some_option = 8` means that KerBridge
# uses 8, the default for that option. `#some_option =`, with no value, means
# that the option has no default: the comment above the line says what
# KerBridge does instead, and shows an example. main.toml gives the full rule.

# Which unix group owns the socket and which unix user may speak on it, not a
# preference either way. The socket directory is 0710 root:<group> and the
# socket 0660, so that group is the whole of the broker's access to the issuer.
#
# The numbers are the Docker Compose deployment's contract: compose.yaml states the
# same two again as the broker's user:, and a disagreement is a refused peer on
# every ticket. The names below are what a package uses, where adduser
# allocates the numbers and nobody can write them down in advance. State one
# form or the other for an identity, never both -- `kbconfig check` refuses a
# file that states both, because only one of the two would be read.
{{socket}}
{{socket_gid}}
{{broker_uid}}

{{socket_group}}

{{broker_user}}

# Request-scoped keytabs and ccaches, 0700 and removed with the request. Put it
# on tmpfs: key material written here must not reach a disk.
{{tmp_dir}}

# Requests admitted at once; the rest are refused immediately rather than
# queued. Each one costs three forked root subprocesses on the DC, whose ceiling
# is what this defends -- and it sits below the broker's, because a request that
# reached the issuer has already spent its LDAPS bind.
#
# Raise it only if legitimate sign-ins are being refused. A morning where
# everyone arrives at once is a few requests a second, not tens in flight.
{{max_inflight}}

{{sam_db}}

{{command_timeout_seconds}}

{{audit_log_file}}
"#;

const BROKER_SRC: &str = r#"# The broker: the internet-facing half, and the only part a client talks to.
#
# A commented-out line sets nothing. `#some_option = 8` means that KerBridge
# uses 8, the default for that option. `#some_option =`, with no value, means
# that the option has no default: the comment above the line says what
# KerBridge does instead, and shows an example. main.toml gives the full rule.

# Loopback, and a non-loopback address is refused. This process speaks plain
# HTTP and Caddy terminates TLS in the network namespace they share, so binding
# wider serves POST /ticket in the clear on every interface of the host. The
# port is free to move; nothing publishes it.
{{listen}}

# Ticket exchanges in flight at once; the rest get 429 without touching the
# directory, and the client backs off. A valid token is not a budget -- each
# ticket costs an LDAPS bind plus three forked root subprocesses on the DC.
# Above issuerd's cap on purpose: this number also has to cover the requests
# still in verification.
{{max_inflight}}

# The broker's own directory identity, read-only. It resolves identities and
# reads the admission group; every write goes through issuerd, so there is
# nothing here to confine and one account serves every source.
#
# There is no search base setting. Each source's OU is derived from
# realm.idp_parent_ou and the source name, so the broker searches the OU
# belonging to whichever source the request arrived for.
{{bind_dn}}
{{bind_password_file}}

{{issuer_socket}}

# Deadline on one issuer request.
{{timeout_seconds}}

# Who was granted which machine, and when it was taken back. A separate file on
# a separate mount from issuerd.audit_log_file -- see the reason there. `none`
# keeps the console line and nothing else.
{{audit_log_file}}
"#;

const KBMANAGE_SRC: &str = r#"# kbmanage: the operator CLI, and the only component that runs on a host rather
# than in a container. Optional -- a deployment nobody administers from outside
# never needs this file, and nothing else reads it.
#
# `make kbmanage-config` in deploy/ writes this and the ~/.config/kerbridge/
# symlink that lets the CLI find the set at all. It holds an identity and two
# paths, because everything else it needs is already in realm.toml and is the
# same answer from either side of the container boundary.
#
# A commented-out line sets nothing. `#some_option = 8` means that KerBridge
# uses 8, the default for that option. `#some_option =`, with no value, means
# that the option has no default: the comment above the line says what
# KerBridge does instead, and shows an example. main.toml gives the full rule.

# Its own directory identity, created by `kbsetup directory`. Not the
# broker's and not a source's sync account: this one may write in the resource
# OU, which neither of those may, and may not write inside an IdP-specific OU,
# which a sync account must.
{{bind_dn}}

# A host path, unlike every other password file in the set: no container mounts
# this one. `kbsetup directory` generates it under deploy/secrets/generated/.
{{bind_password_file}}

# Both default to realm.toml's, and both are stated here when this host reaches
# the DC differently from the way the containers do.
#
# The realm's certificate carries localhost in its SAN alongside the DC's own
# names, and compose publishes LDAPS on loopback only, so a binary on the DC's
# own host needs no resolver entry and no split horizon to bind. Administering
# from another host means ldaps://<the DC's name>:636, LDAPS_BIND widened, and a
# firewall rule.
#
{{ldap_url}}

# realm.ldap_ca_file names a path inside the realm container. This is the copy
# `make kbmanage-config` takes out of it.
#
{{ldap_ca_file}}
"#;

const SYNC_SRC: &str = r#"# Sync: what the mirror does, and how it names what it creates. Which cloud IdP
# it reads, and with which credentials, is per source -- idp_<source>.toml.
#
# A commented-out line sets nothing. `#some_option = 8` means that KerBridge
# uses 8, the default for that option. `#some_option =`, with no value, means
# that the option has no default: the comment above the line says what
# KerBridge does instead, and shows an example. main.toml gives the full rule.

# interval_seconds is the pause between cycles, not the rate of them. One cycle
# reads every source in turn, so the time between two reads of one source is
# that cycle plus this pause.
#
# A read from the cloud IdP runs until it is done, however long that takes. A
# read that stops making progress is abandoned, and the cycle is discarded.
{{interval_seconds}}

# Which cloud-IdP attribute a *newly created* account's login name
# (sAMAccountName) is minted from. Existing accounts are never renamed by a
# change here.
#
#   displayname     every whitespace token of the display name, joined by dots
#                   ("Jane Doe" -> jane.doe) -- what users see as
#                   REALM\jane.doe in Explorer, on file ownership and in ACL
#                   dialogs. Not unique, so colliding names get a short
#                   object-id suffix. Supports Unicode names.
#
#   email_username  the part of the mail address before the @. Usually
#                   hand-made, already ASCII, and what the person answers to.
#                   Reads Email, then Other emails, then the UPN -- an account
#                   invited from another tenant has its address in Other emails,
#                   not Email.
#
#   upn             the part of the UPN before the @. Unique tenant-wide, so it
#                   collides least. Least readable, and see the caveat below.
#
# Each falls back to the others when its attribute yields no usable name --
# absent, or holding nothing a sAMAccountName may keep ("...", "!!!").
#
# Why displayname and not upn by default? An invited Entra account's UPN carries
# the source domain in its local part (alice.anderson_gmail.com#EXT#@...). The
# #EXT# is stripped, but nothing distinguishes anderson_gmail.com from a
# surname, so that account becomes EXAMPLE\alice.anderson_gmail.
{{sam_source}}

# Whether a live account's login name follows a rename in the cloud IdP.
#
#   true (default)  a rename there renames the account here on the next cycle,
#                   so someone who changes their name stops finding the old one
#                   on their files. The cost: the login name is their Kerberos
#                   principal, so the renamed user signs out and back in once.
#
#   false           login names are set once, at creation, and never move again.
#                   Rename by hand with `kbmanage cloud rename`, which lets you
#                   choose when it happens.
#
# `kbmanage cloud rename <user> --to <name>` pins a name against either setting,
# for the case where the derived name is legal but wrong; `kbmanage cloud unpin
# <user>` hands it back. More: docs/setup/rough-edges.md.
{{automatic_sam_renames}}

# Log the plan every cycle and apply nothing. The safe way to watch a new
# deployment before letting it write the directory.
{{dry_run}}

# How far ahead of a device grant's effective deadline to warn: `off`, or a
# number of days. Off by default because the event names machine labels, and an
# operator should choose to send those to whatever channel they wired up rather
# than discover afterwards that they did.
{{device_grant_notify}}

# How far ahead of a source's stated Graph credential expiry to start warning.
# Local policy, not a portal value -- the expiry date itself is per source, in
# idp_<source>.toml.
{{credential_warn_before_days}}

# What each cycle changed in the directory: the tally, and the object every
# applied write touched. A separate file on a separate mount from the other two
# audit logs -- see the reason in issuerd.toml. An account created here outlives
# any ticket or grant, and nothing else says who was given one. `none` keeps the
# console line and nothing else.
{{audit_log_file}}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    /// The rendered envelope. A failure here is a source that disagrees with
    /// the parser, which `the_committed_source_templates_are_current` reports
    /// properly; these tests only need the document.
    fn envelope(name: &str, provider: &str) -> String {
        source_envelope(name, provider).expect("the envelope renders")
    }
    use crate::config::{
        Broker, Issuerd, Kbmanage, Main, Notify, Provision, Realm, SourceFile, Sync,
    };

    /// The convention every template follows, held key by key: an option the
    /// parser requires is stated, every other one is commented out. The module
    /// doc says why; `crates/kerbridge-config/GLOSSARY.md` @ configuration
    /// decision names the terms.
    ///
    /// Exactly once, too. The upgrade path rewrites a template line in place,
    /// and a key appearing twice would leave one of the two behind.
    #[test]
    fn a_template_states_what_is_required_and_comments_out_the_rest() {
        fn check<T: schemars::JsonSchema>(template: &str, file: &str) {
            let lines: Vec<&str> = template.lines().collect();
            let required = required::<T>();
            for (key, property) in properties::<T>() {
                let stated = lines.iter().filter(|l| l.starts_with(&format!("{key} = "))).count();
                let shown = lines.iter().filter(|l| l.starts_with(&format!("#{key} = "))).count();
                let bare: Vec<usize> = lines
                    .iter()
                    .enumerate()
                    .filter(|(_, l)| **l == format!("#{key} ="))
                    .map(|(i, _)| i)
                    .collect();
                // A table opens a section rather than taking a value.
                let header = lines.iter().filter(|l| **l == format!("[{key}]")).count();
                let total = stated + shown + bare.len() + header;
                assert_eq!(
                    total, 1,
                    "{file}: {key} appears {total} times. A key belongs in its template exactly \
                     once -- an upgrade rewrites the line in place, and a second one is left behind."
                );

                if header == 1 {
                    continue;
                }
                if required.iter().any(|r| r == &key) {
                    assert_eq!(
                        stated, 1,
                        "{file}: {key} is required, so the template must state it rather than \
                         comment it out."
                    );
                    continue;
                }
                assert_eq!(
                    stated, 0,
                    "{file}: {key} is not required, so the template must comment it out. A stated \
                     value cannot be told apart from a configuration decision, and an upgrade \
                     would keep it forever."
                );
                match property.get("default").filter(|d| !d.is_null()) {
                    // A default to show: `#key = value`, and the value is
                    // checked against the parser by the next test.
                    Some(_) => assert_eq!(
                        shown, 1,
                        "{file}: {key} has a default, so its line must show it as `#{key} = ...`."
                    ),
                    // Nothing to show. The line stays bare so that no reader
                    // mistakes an example for the value in use, and the example
                    // moves into the comment above it.
                    None => {
                        assert_eq!(
                            bare.len(),
                            1,
                            "{file}: {key} has no default, so its line must be bare -- `#{key} =` \
                             with the example value moved into the comment above it."
                        );
                        assert!(
                            example_above(&lines, bare[0]),
                            "{file}: {key} is bare, so the comment above it must carry an \
                             `# Example: <value>` line. Nothing else shows the operator a shape."
                        );
                    }
                }
            }
        }

        // `Notify` shares `main.toml` with `Main`, being `[notify]` inside it.
        check::<Main>(&rendered("main.toml"), "main.toml");
        check::<Notify>(&rendered("main.toml"), "main.toml [notify]");
        check::<Realm>(&rendered("realm.toml"), "realm.toml");
        // As does `Provision`, being `[provision]` inside `realm.toml`.
        check::<Provision>(&rendered("realm.toml"), "realm.toml [provision]");
        check::<Issuerd>(&rendered("issuerd.toml"), "issuerd.toml");
        check::<Broker>(&rendered("broker.toml"), "broker.toml");
        check::<Sync>(&rendered("sync.toml"), "sync.toml");
        check::<Kbmanage>(&rendered("kbmanage.toml"), "kbmanage.toml");
        // Against the envelope rather than a committed file: half of
        // `idp_entra.toml` is the adapter's, and `provider_config` is out of
        // this schema for the reason stated where it is declared.
        check::<SourceFile>(&envelope("entra", "entra"), "idp_<name>.toml");
    }

    /// Every value shown against a commented key must *be* the default the
    /// parser holds, so uncommenting them all changes nothing. A template
    /// documenting a number the code does not use fails the build.
    #[test]
    fn every_shown_default_is_the_one_the_parser_holds() {
        fn same<T>(template: &str, required_only: &str, defaulted: &[String])
        where
            T: serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
        {
            let shown: T =
                toml::from_str(&uncomment(template, defaulted)).expect("template parses");
            let defaults: T = toml::from_str(required_only).expect("minimal document parses");
            assert_eq!(shown, defaults);
        }

        // `main.toml` carries two structs, so it carries both key sets.
        let mut main_keys = defaulted::<Main>();
        main_keys.extend(defaulted::<Notify>());
        same::<Main>(&rendered("main.toml"), r#"sources = ["entra"]"#, &main_keys);
        // `realm.toml` carries two as well, `[provision]` being the second.
        let mut realm_keys = defaulted::<Realm>();
        realm_keys.extend(defaulted::<Provision>());
        same::<Realm>(
            &rendered("realm.toml"),
            r#"
            realm = "EXAMPLE.SITE"
            ldap_url = "ldaps://kerbridge.example.site:636"
            ldap_ca_file = "/run/kerbridge/realm-ca.pem"
            "#,
            &realm_keys,
        );
        same::<Issuerd>(&rendered("issuerd.toml"), "", &defaulted::<Issuerd>());
        same::<Broker>(
            &rendered("broker.toml"),
            r#"
            bind_dn = "CN=svc-kerbridge-broker,CN=Users,DC=example,DC=site"
            bind_password_file = "/etc/kerbridge.secrets/generated/svc_kerbridge_broker_password"
            "#,
            &defaulted::<Broker>(),
        );
        same::<Sync>(&rendered("sync.toml"), "", &defaulted::<Sync>());
        same::<Kbmanage>(
            &rendered("kbmanage.toml"),
            r#"
            bind_dn = "CN=svc-kerbridge-manage,CN=Users,DC=example,DC=site"
            bind_password_file = "/home/you/.config/kerbridge/svc_kerbridge_manage_password"
            "#,
            &defaulted::<Kbmanage>(),
        );
        same::<SourceFile>(
            &envelope("entra", "entra"),
            r#"
            name = "entra"
            provider = "entra"
            group_suffix = "-entra"
            bind_dn = "CN=svc-kerbridge-sync-entra,CN=Users,DC=example,DC=site"
            bind_password_file = "/etc/kerbridge.secrets/generated/idp/entra/bind_password"
            "#,
            &defaulted::<SourceFile>(),
        );
    }

    /// The committed copies are what a reader evaluating the project sees on
    /// GitHub, which is half the point of committing a generated file. Same
    /// guarantee as `cargo fmt --check`, same regeneration step.
    ///
    /// Only a file that is *there* is judged. These sit in the directory a
    /// deployment fills in, and an operator may clear them out once they have
    /// their own `*.toml`; `kbconfig init` writes the same bodies as a live set.
    #[test]
    fn the_committed_templates_are_current() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../deploy/configs");
        let write = std::env::var_os("KB_WRITE_CONFIG_TEMPLATES").is_some();
        for (name, body) in templates().expect("the sources render") {
            let path = dir.join(format!("{name}.example"));
            if write {
                std::fs::write(&path, &body).expect("writing the template");
                continue;
            }
            let committed = match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => panic!("reading deploy/configs/{name}.example: {e}"),
            };
            // Not assert_eq!: the bodies are kilobytes and the dump buries the
            // one line that says how to fix it.
            assert!(
                committed == body,
                "deploy/configs/{name}.example is stale. Regenerate with \
                 `KB_WRITE_CONFIG_TEMPLATES=1 cargo test -p kerbridge-core`."
            );
        }
    }

    /// One rendered file, by name. The convention tests judge the document an
    /// operator reads, which is the rendered one -- a source states no values.
    fn rendered(file: &str) -> String {
        templates()
            .expect("the sources render")
            .into_iter()
            .find(|(name, _)| *name == file)
            .map(|(_, body)| body)
            .unwrap_or_else(|| panic!("no template named {file}"))
    }

    fn schema<T: schemars::JsonSchema>() -> serde_json::Value {
        serde_json::to_value(schemars::schema_for!(T)).expect("a schema is JSON")
    }

    fn properties<T: schemars::JsonSchema>() -> serde_json::Map<String, serde_json::Value> {
        schema::<T>()
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .cloned()
            .expect("the schema states properties")
    }

    fn required<T: schemars::JsonSchema>() -> Vec<String> {
        schema::<T>()
            .get("required")
            .and_then(serde_json::Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
            .unwrap_or_default()
    }

    /// The keys whose default is a value rather than nothing. `null` is what
    /// schemars writes for a field the parser derives or leaves unset, and
    /// those carry an example instead.
    fn defaulted<T: schemars::JsonSchema>() -> Vec<String> {
        properties::<T>()
            .iter()
            .filter(|(_, v)| v.get("default").is_some_and(|d| !d.is_null()))
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Drop the comment mark from the `#key = value` lines these keys name.
    /// A prose line is never one: what precedes ` = ` must be one of the keys.
    fn uncomment(template: &str, keys: &[String]) -> String {
        let mut out = String::with_capacity(template.len());
        for line in template.lines() {
            let shown = line.strip_prefix('#').filter(|rest| {
                rest.split_once(" = ").is_some_and(|(key, _)| keys.iter().any(|k| k == key))
            });
            out.push_str(shown.unwrap_or(line));
            out.push('\n');
        }
        out
    }

    /// Whether the run of comment lines above `i` carries an example. The walk
    /// stops at the previous key, so a key cannot borrow its neighbour's.
    fn example_above(lines: &[&str], i: usize) -> bool {
        lines[..i]
            .iter()
            .rev()
            .take_while(|l| l.starts_with('#') && !is_assignment(l))
            .any(|l| l.starts_with("# Example: "))
    }

    fn is_assignment(line: &str) -> bool {
        let body = line.strip_prefix('#').unwrap_or(line);
        let Some(key) = body.strip_suffix(" =").or_else(|| body.split_once(" = ").map(|(k, _)| k))
        else {
            return false;
        };
        !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    }

    /// What the renderer refuses. Each of these is a way the two halves come
    /// apart, and each fails the build rather than reaching an operator.
    #[test]
    fn the_renderer_refuses_a_source_that_disagrees_with_the_parser() {
        let schema = serde_json::to_value(schemars::schema_for!(Issuerd)).unwrap();
        let err = |source: &str| super::render(ISSUERD_FILE, source, &schema).unwrap_err();

        assert!(err("{{sam_dbb}}").contains("no such key"), "a key the parser dropped");
        assert!(err("{{socket}}").contains("names none of"), "a key the template forgot");
    }
}
