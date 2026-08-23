//! The LDAP half. Reads produce a [`Snapshot`]; writes take DNs the pure half
//! has already blessed.
//!
//! Async `ldap3` on `tokio`, awaited one call at a time. Concurrency is not a
//! goal here -- the verbs are sequential by nature -- and the async choice buys
//! workspace consistency: this is `kerbridge-sync/src/directory.rs` copied
//! pattern for pattern rather than translated.

use std::collections::HashSet;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use kerbridge_core::dn::{dn_equals, parent_of};
use kerbridge_core::state::ROLE_DELEGATES;
use kerbridge_core::{decode_sid_attr, escape_ldap_filter_value};
use ldap3::{LdapConnAsync, LdapConnSettings, Mod, Scope, SearchEntry};

use crate::config::Config;
use crate::model::{
    CertFault, CloudObject, IdpOu, Kind, ManagedGroup, Reach, ResourceGroup, Snapshot,
};

pub struct Directory {
    url: String,
    base_dn: String,
    cloud_idp_ou: String,
    resource_ou: String,
    bind_dn: String,
    bind_password: String,
    ca_file: std::path::PathBuf,
    tls: Arc<rustls::ClientConfig>,
    timeout: Duration,
}

const CLOUD_ATTRS: [&str; 11] = [
    "distinguishedName",
    "sAMAccountName",
    "objectClass",
    "displayName",
    "userPrincipalName",
    "msDS-ExternalDirectoryObjectId",
    "extensionName",
    "userAccountControl",
    "objectSid",
    "member",
    // Not for anything under an IdP-specific OU: `resolve` shares this list, and a
    // delegation that repoints an existing link has to say what it replaced.
    "managedBy",
];

const GROUP_ATTRS: [&str; 7] = [
    "distinguishedName",
    "sAMAccountName",
    "groupType",
    "objectSid",
    "member",
    // A resource group is also where a delegation lives: `managedBy` names the
    // account, the marker in `extensionName` says the link was meant as one.
    "managedBy",
    "extensionName",
];

impl Directory {
    pub fn new(cfg: &Config) -> Result<Self> {
        Ok(Self {
            url: cfg.url.clone(),
            base_dn: cfg.base_dn.clone(),
            cloud_idp_ou: cfg.cloud_idp_ou.clone(),
            resource_ou: cfg.resource_ou.clone(),
            bind_dn: cfg.bind_dn.clone(),
            // Where a deferred credential becomes fatal, and the only place it
            // does: everything downstream of here binds.
            bind_password: cfg.bind_password.clone().map_err(anyhow::Error::msg)?,
            ca_file: cfg.ca_file.clone(),
            // The advice is added here rather than carried into the shared
            // helper: it is true for an operator running this by hand on their
            // own host, and misleading inside a container that never had a
            // `make kbmanage-config` to run.
            tls: kerbridge_core::tls::client_config(Some(&cfg.ca_file)).with_context(|| {
                format!(
                    "reading the directory CA from {}. The realm creates its own CA at \
                     provisioning, so a rebuilt realm means a new one: `make kbmanage-config` \
                     in deploy/ copies the current one out",
                    cfg.ca_file.display()
                )
            })?,
            timeout: cfg.timeout,
        })
    }

    pub async fn connect(&self) -> Result<ldap3::Ldap> {
        let settings =
            LdapConnSettings::new().set_config(self.tls.clone()).set_conn_timeout(self.timeout);
        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &self.url)
            .await
            .with_context(|| self.connect_advice())?;
        ldap3::drive!(conn);
        ldap.simple_bind(&self.bind_dn, &self.bind_password)
            .await
            .context("binding to the directory")?
            .success()
            .with_context(|| format!("binding as {}", self.bind_dn))?;
        Ok(ldap)
    }

    /// What the ways this connection fails have in common, because `ldap3`'s own
    /// errors do not distinguish them usefully: an unresolvable host times out
    /// rather than saying so, and a name outside the certificate says
    /// `NotValidForName` without saying which name would have worked. Both read
    /// as "the DC is down" and neither is.
    fn connect_advice(&self) -> String {
        format!(
            "connecting to {url}\n\
             Three things have to line up, and the error above usually names only one:\n\
             - the host in that URL must resolve from *this* machine. An unresolvable \
               name surfaces as a timeout, not as a lookup failure.\n\
             - it must be a name in the certificate. The realm's SAN carries the DC's \
               FQDN, its short name, and the loopback addresses -- so \
               ldaps://localhost:636 works against a loopback-published port, and \
               anything else does not.\n\
             - {ca} must be the CA that signed it. A rebuilt realm creates a new one; \
               `make kbmanage-config` in deploy/ copies the current one out.",
            url = self.url,
            ca = self.ca_file.display(),
        )
    }

    /// One read of everything the pure half is allowed to reason about.
    ///
    /// Three searches, sequentially: the sync-owned OU, the resource OU,
    /// and then -- by DN -- any group elsewhere that a managed object turned out
    /// to be nested into. `docs/setup/file-server.md` promises resource groups may
    /// live anywhere outside the IdP parent OU, so a diagnosis that only looked in the
    /// configured OU would report a working chain as broken.
    pub async fn snapshot(&self, ldap: &mut ldap3::Ldap, now: u64) -> Result<Snapshot> {
        let cloud = self
            .search(
                ldap,
                &self.cloud_idp_ou,
                Scope::Subtree,
                "(|(objectClass=user)(objectClass=group))",
                &CLOUD_ATTRS,
            )
            .await
            .with_context(|| format!("reading {}", self.cloud_idp_ou))?;
        let cloud: Vec<CloudObject> = cloud.into_iter().map(cloud_object).collect();

        // The resource OU is allowed not to exist yet: a fresh deployment that
        // has never created a resource group is diagnosable, not an error.
        let mut resources: Vec<ResourceGroup> = self
            .search(ldap, &self.resource_ou, Scope::Subtree, "(objectClass=group)", &GROUP_ATTRS)
            .await
            .unwrap_or_default()
            .into_iter()
            .map(resource_group)
            .collect();

        let mut wanted: Vec<String> = Vec::new();
        for obj in &cloud {
            for parent in self.parents_of(ldap, &obj.dn).await? {
                let known = resources.iter().any(|g| g.dn.eq_ignore_ascii_case(&parent))
                    || cloud.iter().any(|o| o.dn.eq_ignore_ascii_case(&parent))
                    || wanted.iter().any(|d: &String| d.eq_ignore_ascii_case(&parent));
                if !known {
                    wanted.push(parent);
                }
            }
        }
        for dn in wanted {
            if let Ok(found) =
                self.search(ldap, &dn, Scope::Base, "(objectClass=group)", &GROUP_ATTRS).await
            {
                resources.extend(found.into_iter().map(resource_group));
            }
        }

        // One level, not a subtree: an IdP-specific OU is by definition a direct
        // child of the IdP parent OU, which is also what `Snapshot::idp_ou_of`
        // counts, and a sub-OU carrying a stray marker is not one.
        let idp_ous = self
            .search(
                ldap,
                &self.cloud_idp_ou,
                Scope::OneLevel,
                "(objectClass=organizationalUnit)",
                &["distinguishedName"],
            )
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|e| IdpOu { dn: e.dn.clone() })
            .collect();

        Ok(Snapshot {
            base_dn: self.base_dn.clone(),
            cloud_idp_ou: self.cloud_idp_ou.clone(),
            resource_ou: self.resource_ou.clone(),
            netbios: self.netbios(ldap).await,
            now,
            cloud,
            resources,
            idp_ous,
        })
    }

    /// Groups this object is directly inside, from its own `memberOf`. Read per
    /// object rather than as one subtree search, because the answer may name a
    /// group in a part of the tree this tool never searches.
    async fn parents_of(&self, ldap: &mut ldap3::Ldap, dn: &str) -> Result<Vec<String>> {
        let entries = self.search(ldap, dn, Scope::Base, "(objectClass=*)", &["memberOf"]).await?;
        Ok(entries
            .into_iter()
            .flat_map(|e| e.attrs.get("memberOf").cloned().unwrap_or_default())
            .collect())
    }

    /// The domain's NetBIOS name from the Partitions container. Best effort:
    /// it decorates a message, and a bind that cannot read the configuration
    /// naming context should still be able to run every verb.
    async fn netbios(&self, ldap: &mut ldap3::Ldap) -> Option<String> {
        let base = format!("CN=Partitions,CN=Configuration,{}", self.base_dn);
        let filter = format!("(nCName={})", escape_ldap_filter_value(&self.base_dn));
        let entries =
            self.search(ldap, &base, Scope::Subtree, &filter, &["nETBIOSName"]).await.ok()?;
        entries.into_iter().find_map(|e| first(&e, "nETBIOSName"))
    }

    async fn search(
        &self,
        ldap: &mut ldap3::Ldap,
        base: &str,
        scope: Scope,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<SearchEntry>> {
        let (entries, _) = ldap
            .search(base, scope, filter, attrs.to_vec())
            .await
            .with_context(|| format!("searching {base}"))?
            .success()
            .with_context(|| format!("search of {base} was refused"))?;
        Ok(entries.into_iter().map(SearchEntry::construct).collect())
    }

    /// Exactly one object, by whatever the operator typed. Ambiguity is a
    /// refusal: this tool deletes things, and picking one of two would be
    /// picking which one.
    pub async fn resolve(&self, ldap: &mut ldap3::Ldap, name: &str) -> Result<SearchEntry> {
        let e = escape_ldap_filter_value(name);
        let filter = format!(
            "(&(|(objectClass=user)(objectClass=group))\
              (|(sAMAccountName={e})(userPrincipalName={e})(distinguishedName={e})\
                (msDS-ExternalDirectoryObjectId={e})(cn={e})))"
        );
        let (entries, _) = ldap
            .search(&self.base_dn, Scope::Subtree, &filter, CLOUD_ATTRS.to_vec())
            .await
            .context("resolving the name")?
            .success()
            .context("the name search was refused")?;
        let mut entries: Vec<SearchEntry> =
            entries.into_iter().map(SearchEntry::construct).collect();
        match entries.len() {
            1 => Ok(entries.remove(0)),
            0 => bail!("nothing under {} is named {name:?}", self.base_dn),
            n => bail!(
                "{n} objects match {name:?}: {}. Give a full DN instead",
                entries.iter().map(|e| e.dn.as_str()).collect::<Vec<_>>().join(", ")
            ),
        }
    }

    pub async fn create_group(
        &self,
        ldap: &mut ldap3::Ldap,
        dn: &str,
        sam: &str,
        group_type: &str,
    ) -> Result<()> {
        ldap.add(
            dn,
            vec![
                ("objectClass", HashSet::from(["group"])),
                ("sAMAccountName", HashSet::from([sam])),
                ("groupType", HashSet::from([group_type])),
            ],
        )
        .await
        .context("creating the group")?
        .success()
        .context("the directory refused the group")?;
        Ok(())
    }

    pub async fn add_member(
        &self,
        ldap: &mut ldap3::Ldap,
        group: &str,
        member: &str,
    ) -> Result<()> {
        self.modify(ldap, group, vec![Mod::Add(b("member"), one(member))]).await
    }

    pub async fn remove_member(
        &self,
        ldap: &mut ldap3::Ldap,
        group: &str,
        member: &str,
    ) -> Result<()> {
        self.modify(ldap, group, vec![Mod::Delete(b("member"), one(member))]).await
    }

    /// Both halves of a name, as `kerbridge-sync`'s own rename does: a member
    /// server matches `valid users` against `sAMAccountName`, so moving only
    /// the CN would leave the two disagreeing.
    pub async fn rename(
        &self,
        ldap: &mut ldap3::Ldap,
        dn: &str,
        new_cn: &str,
        new_sam: &str,
    ) -> Result<String> {
        let rdn = format!("CN={new_cn}");
        ldap.modifydn(dn, &rdn, true, None)
            .await
            .context("renaming")?
            .success()
            .context("the directory refused the rename")?;
        // No `newsuperior`, so the object keeps its parent.
        let new_dn = format!("{rdn},{}", parent_of(dn));
        self.modify(ldap, &new_dn, vec![Mod::Replace(b("sAMAccountName"), one(new_sam))]).await?;
        Ok(new_dn)
    }

    /// Remove state markers by exact value -- what `unpin` hands back with.
    pub async fn clear_markers(
        &self,
        ldap: &mut ldap3::Ldap,
        dn: &str,
        values: &[String],
    ) -> Result<()> {
        let set: HashSet<Vec<u8>> = values.iter().map(|v| v.as_bytes().to_vec()).collect();
        self.modify(ldap, dn, vec![Mod::Delete(b("extensionName"), set)]).await
    }

    /// Every group naming this account in `managedBy`, and whether the link
    /// carries the delegates marker.
    ///
    /// The forward search, not the account's own `managedObjects` back-link the
    /// broker reads: both were measured to work, and this one brings the marker
    /// back from the same search -- which is what tells a delegation apart from
    /// an admin's conventional ownership record, the one thing this tool must
    /// not rewrite.
    pub async fn groups_managed_by(
        &self,
        ldap: &mut ldap3::Ldap,
        user_dn: &str,
    ) -> Result<Vec<ManagedGroup>> {
        let filter =
            format!("(&(objectClass=group)(managedBy={}))", escape_ldap_filter_value(user_dn));
        let found = self
            .search(
                ldap,
                &self.base_dn,
                Scope::Subtree,
                &filter,
                &["distinguishedName", "extensionName"],
            )
            .await
            .context("looking for groups that already name this account")?;
        Ok(found
            .into_iter()
            .map(|e| ManagedGroup {
                is_delegate: all(&e, "extensionName").iter().any(|m| m == ROLE_DELEGATES),
                dn: e.dn,
            })
            .collect())
    }

    /// Point a group at the account whose device grants its members may
    /// authorize.
    ///
    /// One modify, because neither half means anything alone: a `managedBy`
    /// without the marker is the conventional "who owns this group" the broker
    /// deliberately ignores, and the marker without a link names nobody.
    /// `add_marker` is false when the group already carries it -- adding a
    /// value twice is a constraint violation, not a no-op.
    pub async fn set_delegate_link(
        &self,
        ldap: &mut ldap3::Ldap,
        group_dn: &str,
        user_dn: &str,
        add_marker: bool,
    ) -> Result<()> {
        let mut mods = vec![Mod::Replace(b("managedBy"), one(user_dn))];
        if add_marker {
            mods.push(Mod::Add(b("extensionName"), one(ROLE_DELEGATES)));
        }
        self.modify(ldap, group_dn, mods).await
    }

    /// Undo [`Self::set_delegate_link`], both halves for the reason they were
    /// written together. Only ever called on a group known to carry the marker:
    /// deleting a value that is not there is an error, not a no-op.
    pub async fn clear_delegate_link(&self, ldap: &mut ldap3::Ldap, group_dn: &str) -> Result<()> {
        self.modify(
            ldap,
            group_dn,
            vec![
                Mod::Delete(b("managedBy"), HashSet::new()),
                Mod::Delete(b("extensionName"), one(ROLE_DELEGATES)),
            ],
        )
        .await
    }

    /// Move an account's login name: `sAMAccountName` and `userPrincipalName`
    /// together, leaving the CN where it is.
    ///
    /// Both, because `samldb` enforces uniqueness on the UPN as well -- moving
    /// only the sam leaves the old name held one attribute over, and the next
    /// account that wants it fails on a constraint nobody can see. The CN stays
    /// because sync owns it: it follows `displayName` from the cloud IdP, and a CN moved
    /// from here would be moved back on the next cycle.
    /// The pin marker goes in the *same* modify: sync recomputes a login name on
    /// its own cycle, so a rename that landed without its pin would be undone
    /// before anyone could add one.
    pub async fn set_login_name(
        &self,
        ldap: &mut ldap3::Ldap,
        dn: &str,
        sam: &str,
        upn: &str,
        pin: &str,
    ) -> Result<()> {
        self.modify(
            ldap,
            dn,
            vec![
                Mod::Replace(b("sAMAccountName"), one(sam)),
                Mod::Replace(b("userPrincipalName"), one(upn)),
                Mod::Add(b("extensionName"), one(pin)),
            ],
        )
        .await
    }

    /// Anything in the realm already answering to this account name, other than
    /// `renaming` itself. The namespace is shared by users and groups, so both
    /// count.
    ///
    /// AD would refuse a duplicate anyway; this exists so the refusal names the
    /// object holding it instead of surfacing as a constraint violation.
    ///
    /// `renaming` is excluded because AD matches these attributes
    /// case-insensitively while the caller's "is this a no-op?" test is a Rust
    /// `==`. Changing only the case of a name -- `mcdonald` to `McDonald`, which
    /// Samba accepts, measured 2026-07-30 -- therefore slips past that test and
    /// then matches *itself* here, and the operator is told the name they asked
    /// for is taken by the account they are renaming.
    pub async fn holder_of_name(
        &self,
        ldap: &mut ldap3::Ldap,
        name: &str,
        upn: &str,
        renaming: &str,
    ) -> Result<Option<String>> {
        let filter = format!("(|(sAMAccountName={name})(userPrincipalName={upn}))");
        let found = self
            .search(ldap, &self.base_dn, Scope::Subtree, &filter, &["distinguishedName"])
            .await?;
        // Filtered rather than taking the first hit and comparing: a second object
        // really holding the name must still be reported when this one matches too.
        Ok(found.into_iter().map(|e| e.dn).find(|dn| !dn_equals(dn, renaming)))
    }

    pub async fn delete(&self, ldap: &mut ldap3::Ldap, dn: &str) -> Result<()> {
        ldap.delete(dn)
            .await
            .context("deleting")?
            .success()
            .with_context(|| format!("the directory refused to delete {dn}"))?;
        Ok(())
    }

    async fn modify(
        &self,
        ldap: &mut ldap3::Ldap,
        dn: &str,
        mods: Vec<Mod<Vec<u8>>>,
    ) -> Result<()> {
        ldap.modify(dn, mods)
            .await
            .context("modifying")?
            .success()
            .with_context(|| format!("the directory refused the change to {dn}"))?;
        Ok(())
    }
}

/// `ldaps://` with no port, as `ldap3` resolves it (`ldap3 0.12`,
/// `src/conn.rs:476-492`): the preflight has to probe the port the bind would
/// have used, not a different one.
const LDAPS_PORT: u16 = 636;

/// The connectivity preflight: can this host reach that directory at all, and
/// which link is broken if not.
///
/// A free function rather than a method, because [`Directory::new`] is itself
/// one of the links -- it loads the realm CA, and a CA this walk exists to
/// report on must not be a constructor error that ends the run first.
///
/// The first three links use blocking sockets inside an `async fn` on purpose.
/// The walk is strictly sequential, nothing else is on this runtime -- the
/// first `ldap3` connection appears at link 5 -- and rustls' own blocking API
/// needs no crate beside the one that already builds the trust config, so an
/// async handshake would buy a second TLS path to keep in step with
/// [`Directory::connect`] and nothing else.
pub async fn probe(cfg: &Config) -> Reach {
    let (host, port) = host_port(&cfg.url);
    let mut reach = Reach {
        source: cfg.source.clone(),
        url: cfg.url.clone(),
        host: host.clone().unwrap_or_default(),
        port,
        ca_file: cfg.ca_file.clone(),
        bind_dn: cfg.bind_dn.clone(),
        resolve: None,
        tcp: None,
        tls: None,
        bind: None,
    };

    let Some(host) = host else {
        reach.resolve = Some(Err(format!("{} names no host to look up", cfg.url)));
        return reach;
    };

    // The resolver this machine has, which is the point of the link: the name
    // is the DC's and it is this host that has to know it.
    let addrs: Vec<SocketAddr> = match (host.as_str(), port).to_socket_addrs() {
        Ok(found) => found.collect(),
        Err(e) => {
            reach.resolve = Some(Err(e.to_string()));
            return reach;
        }
    };
    if addrs.is_empty() {
        reach.resolve = Some(Err("the resolver answered with no address".to_owned()));
        return reach;
    }
    reach.resolve = Some(Ok(addrs.iter().map(SocketAddr::ip).collect()));

    // Every address it resolved to, not just the first: a DC with an AAAA
    // record on a host with no IPv6 route is reachable, and stopping at that
    // first refusal would report a working directory as down.
    let mut opened = None;
    let mut refused = String::new();
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, cfg.timeout) {
            Ok(sock) => {
                opened = Some((*addr, sock));
                break;
            }
            Err(e) => refused = format!("{addr}: {e}"),
        }
    }
    let Some((addr, mut sock)) = opened else {
        reach.tcp = Some(Err(refused));
        return reach;
    };
    reach.tcp = Some(Ok(addr));

    if let Err(fault) = handshake(&mut sock, &host, &cfg.ca_file, cfg.timeout) {
        reach.tls = Some(Err(fault));
        return reach;
    }
    reach.tls = Some(Ok(()));

    // The real bind rather than a second implementation of one: whatever
    // `connect()` does here is what every verb does, so a preflight that passes
    // cannot be passing something the snapshot fetch behind it does not. The
    // connection is dropped again -- this link answers a question, it does not
    // hand a connection onward, which keeps `run()` with one connect path.
    reach.bind = Some(match Directory::new(cfg) {
        Ok(dir) => match dir.connect().await {
            Ok(mut ldap) => {
                let _ = ldap.unbind().await;
                Ok(())
            }
            Err(e) => Err(format!("{e:#}")),
        },
        Err(e) => Err(format!("{e:#}")),
    });
    reach
}

/// Link 4, and the one that actually fails in the field. The handshake is run
/// for its verdict alone: nothing is sent over it, and the LDAP bind that
/// follows opens its own.
fn handshake(
    sock: &mut TcpStream,
    host: &str,
    ca_file: &std::path::Path,
    timeout: Duration,
) -> std::result::Result<(), CertFault> {
    let tls = kerbridge_core::tls::client_config(Some(ca_file))
        .map_err(|e| CertFault::NoCa(format!("{e:#}")))?;
    let name = rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|e| {
        CertFault::Other(format!("{host} is not a name a certificate can carry: {e}"))
    })?;
    let mut conn =
        rustls::ClientConnection::new(tls, name).map_err(|e| CertFault::Other(e.to_string()))?;
    // Without these the handshake inherits the socket's block-forever default,
    // so a peer that accepts a connection and then says nothing -- a middlebox,
    // a plain-LDAP port -- hangs the preflight instead of diagnosing it.
    let _ = sock.set_read_timeout(Some(timeout));
    let _ = sock.set_write_timeout(Some(timeout));
    // An unknown issuer and a name outside the SAN both read as "TLS failed"
    // and send an operator to opposite files, so the verdict is asked for by
    // type -- and by the same classifier the endpoint probe uses.
    conn.complete_io(sock).map_err(|e| crate::certificate::of_io(&e))?;
    Ok(())
}

/// The host and port an LDAPS URL names, parsed the way `ldap3` parses it so
/// the preflight probes the endpoint the bind would have used.
///
/// `None` for a URL that names no host at all -- `ldaps://` alone passes
/// [`kerbridge_core::require_ldaps`], which reads the scheme and nothing else.
/// That is a link-2 failure to report rather than a reason to end the run:
/// `--url` is where this mistake gets made.
fn host_port(url: &str) -> (Option<String>, u16) {
    let Ok(parsed) = url::Url::parse(url) else {
        return (None, LDAPS_PORT);
    };
    let host = match parsed.host() {
        Some(url::Host::Domain(name)) => Some(name.to_owned()),
        // Unbracketed: `to_socket_addrs` and rustls' `ServerName` both want the
        // address, and `host_str` would hand them the URL's brackets.
        Some(url::Host::Ipv4(addr)) => Some(addr.to_string()),
        Some(url::Host::Ipv6(addr)) => Some(addr.to_string()),
        None => None,
    };
    (host, parsed.port().unwrap_or(LDAPS_PORT))
}

fn b(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

fn one(value: &str) -> HashSet<Vec<u8>> {
    HashSet::from([b(value)])
}

fn first(entry: &SearchEntry, attr: &str) -> Option<String> {
    entry.attrs.get(attr).and_then(|v| v.first()).cloned()
}

fn all(entry: &SearchEntry, attr: &str) -> Vec<String> {
    entry.attrs.get(attr).cloned().unwrap_or_default()
}

fn sid_of(entry: &SearchEntry) -> Option<String> {
    decode_sid_attr(
        entry.bin_attrs.get("objectSid").map(|v| &v[..]),
        entry.attrs.get("objectSid").map(|v| &v[..]),
    )
}

fn cloud_object(e: SearchEntry) -> CloudObject {
    let kind = if all(&e, "objectClass").iter().any(|c| c.eq_ignore_ascii_case("group")) {
        Kind::Group
    } else {
        Kind::User
    };
    CloudObject {
        sam: first(&e, "sAMAccountName").unwrap_or_default(),
        kind,
        display_name: first(&e, "displayName"),
        upn: first(&e, "userPrincipalName"),
        identity: first(&e, "msDS-ExternalDirectoryObjectId"),
        markers: all(&e, "extensionName"),
        uac: first(&e, "userAccountControl").and_then(|v| v.parse().ok()),
        sid: sid_of(&e),
        members: all(&e, "member"),
        member_of: all(&e, "memberOf"),
        dn: e.dn,
    }
}

fn resource_group(e: SearchEntry) -> ResourceGroup {
    ResourceGroup {
        sam: first(&e, "sAMAccountName").unwrap_or_default(),
        group_type: first(&e, "groupType"),
        sid: sid_of(&e),
        members: all(&e, "member"),
        managed_by: first(&e, "managedBy"),
        markers: all(&e, "extensionName"),
        dn: e.dn,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The endpoint the preflight probes has to be the endpoint the bind would
    /// have used, or a link can fail against something no verb ever contacts.
    #[test]
    fn an_ldaps_url_yields_the_endpoint_ldap3_would_have_used() {
        let cases = [
            ("ldaps://kerbridge.example.site:636", Some("kerbridge.example.site"), 636),
            ("ldaps://kerbridge.example.site", Some("kerbridge.example.site"), 636),
            ("ldaps://dc.example.site:6636", Some("dc.example.site"), 6636),
            ("ldaps://127.0.0.1:636", Some("127.0.0.1"), 636),
            // Unbracketed on the way out: the brackets are the URL's, and
            // neither `to_socket_addrs` nor `ServerName` wants them.
            ("ldaps://[::1]:636", Some("::1"), 636),
            ("not a url", None, 636),
            // `require_ldaps` reads the scheme and stops, so this reaches here.
            ("ldaps://", None, 636),
        ];
        for (url, host, port) in cases {
            assert_eq!(host_port(url), (host.map(str::to_owned), port), "{url}");
        }
    }
}
