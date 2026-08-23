//! Plain data at the seam between LDAP I/O and the pure logic over it.
//!
//! `directory.rs` fills a [`Snapshot`] in; `validate.rs` and `doctor/mod.rs` are
//! functions over one. Nothing here knows how to reach a directory, which is
//! what lets the interesting half be tested from fixtures with nothing running.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use kerbridge_core::ExternalIdentity;
use kerbridge_core::dn::{dn_equals, dn_is_at_or_within, parent_of};
use kerbridge_core::grant::DeviceGrant;
use kerbridge_core::state::{
    GROUP_TYPE_DOMAIN_LOCAL_SECURITY, ROLE_ADMISSION, ROLE_DELEGATES, ROLE_DEVICE_GRANT, ST_QUAR,
    ST_RETIRED, retention_age_days,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    User,
    Group,
}

/// What a state marker says about an object sync no longer sees in the cloud IdP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Live,
    /// A user, disabled and held for its SID.
    Retired,
    /// A group, members cleared and held for its SID.
    Quarantined,
}

/// An object under an IdP-specific OU: sync's to own, this tool's only to read and, in
/// an emergency, to destroy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudObject {
    pub dn: String,
    pub sam: String,
    pub kind: Kind,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub upn: Option<String>,
    /// Raw `msDS-ExternalDirectoryObjectId`, undecoded: a malformed value is
    /// something `doctor` must be able to report, so it cannot be parsed away
    /// at read time.
    #[serde(default)]
    pub identity: Option<String>,
    /// `extensionName` values: the role marker, the state markers and any device
    /// grants. Raw and undecoded, because a revocation deletes one by its exact
    /// stored bytes.
    #[serde(default)]
    pub markers: Vec<String>,
    #[serde(default)]
    pub uac: Option<u32>,
    #[serde(default)]
    pub sid: Option<String>,
    /// `member` -- for a group, what it contains.
    #[serde(default)]
    pub members: Vec<String>,
    /// `memberOf` -- what contains it, including groups outside the IdP parent OU.
    #[serde(default)]
    pub member_of: Vec<String>,
}

/// `ADS_UF_ACCOUNTDISABLE`, the bit the broker refuses on.
const UF_ACCOUNTDISABLE: u32 = 0x0002;

impl CloudObject {
    pub fn is_admission_group(&self) -> bool {
        self.markers.iter().any(|m| m == ROLE_ADMISSION)
    }

    pub fn is_grant_group(&self) -> bool {
        self.markers.iter().any(|m| m == ROLE_DEVICE_GRANT)
    }

    /// Every device grant on this object, paired with the exact stored value it
    /// came from -- that value is what a revocation has to delete, byte for byte.
    ///
    /// A `kbkey1|` value that does not parse is dropped rather than reported as a
    /// grant: the broker cannot authenticate on it either, so it is not one.
    pub fn grants(&self) -> Vec<(&str, DeviceGrant)> {
        self.markers
            .iter()
            .filter_map(|m| DeviceGrant::decode(m).ok().map(|g| (m.as_str(), g)))
            .collect()
    }

    pub fn state(&self) -> State {
        if self.markers.iter().any(|m| m.starts_with(ST_RETIRED)) {
            State::Retired
        } else if self.markers.iter().any(|m| m.starts_with(ST_QUAR)) {
            State::Quarantined
        } else {
            State::Live
        }
    }

    /// Whole days since the state marker was stamped, or `None` when the object
    /// is live or the marker carries no parsable timestamp.
    pub fn held_days(&self, now: u64) -> Option<u64> {
        self.markers.iter().find_map(|m| retention_age_days(m, now))
    }

    pub fn enabled(&self) -> Option<bool> {
        self.uac.map(|u| u & UF_ACCOUNTDISABLE == 0)
    }

    pub fn identity(&self) -> Option<Result<ExternalIdentity, kerbridge_core::IdentityError>> {
        self.identity.as_deref().map(ExternalIdentity::decode)
    }
}

/// A group outside the IdP parent OU that gates a resource. Yours, not sync's.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceGroup {
    pub dn: String,
    pub sam: String,
    /// The raw `groupType` string, so an unexpected value can be reported as
    /// what it actually is rather than as a failed parse.
    #[serde(default)]
    pub group_type: Option<String>,
    #[serde(default)]
    pub sid: Option<String>,
    #[serde(default)]
    pub members: Vec<String>,
    /// `managedBy` -- the account this group's members may authorize a device
    /// for, if the group also carries [`ROLE_DELEGATES`]. AD rewrites this DN
    /// when either object is renamed, which is what makes a DN acceptable here.
    #[serde(default)]
    pub managed_by: Option<String>,
    /// `extensionName`, for the delegates marker.
    #[serde(default)]
    pub markers: Vec<String>,
}

impl ResourceGroup {
    pub fn is_domain_local(&self) -> bool {
        self.group_type.as_deref() == Some(GROUP_TYPE_DOMAIN_LOCAL_SECURITY)
    }

    /// The account whose device grants this group's members may authorize.
    ///
    /// `managedBy` without the marker is not one: the attribute has a live
    /// conventional meaning -- who owns this group -- and an admin who set it
    /// for ADUC reasons must not thereby have handed that group's members an
    /// authorization right. The broker reads the pair the same way.
    pub fn delegates_for(&self) -> Option<&str> {
        if self.markers.iter().any(|m| m == ROLE_DELEGATES) {
            self.managed_by.as_deref()
        } else {
            None
        }
    }
}

/// A group naming an account in `managedBy`, as the write path finds them.
///
/// Carries only what the decision to clear one needs. Not a [`ResourceGroup`]:
/// the search behind it is realm-wide, so it reaches groups no snapshot read.
#[derive(Debug, Clone)]
pub struct ManagedGroup {
    pub dn: String,
    /// Whether the link carries [`ROLE_DELEGATES`] and is therefore a
    /// delegation rather than an ownership record.
    pub is_delegate: bool,
}

/// What the connectivity preflight found, link by link.
///
/// The same seam as [`Snapshot`], one phase earlier: `directory.rs` runs the
/// probes, `doctor/mod.rs` words them, so the wording is testable with nothing
/// listening. A link the walk never reached is `None` -- the walk stops at the
/// first break, and rows saying "not tried" would bury the one line that
/// matters.
#[derive(Debug, Clone)]
pub struct Reach {
    /// The config set that answered. Every value below came out of it, so a
    /// `--config` naming another deployment moves all of them at once, and
    /// which set answered is the first thing a chain walk has to say.
    pub source: PathBuf,
    pub url: String,
    /// The host and port taken out of `url` -- what was probed, which is not
    /// always what the operator thinks they typed.
    pub host: String,
    pub port: u16,
    pub ca_file: PathBuf,
    pub bind_dn: String,
    /// The addresses `host` resolved to on *this* machine, or why it did not.
    pub resolve: Option<Result<Vec<IpAddr>, String>>,
    /// The address that accepted a connection, or why none did.
    pub tcp: Option<Result<SocketAddr, String>>,
    pub tls: Option<Result<(), CertFault>>,
    pub bind: Option<Result<(), String>>,
}

/// Why the certificate the server presented did not validate.
///
/// The distinction is the whole point of the link. Trust here is CA-exclusive
/// by design -- [`kerbridge_core::tls::client_config`] refuses `None` and never
/// falls back to the OS store -- so a realm re-provisioned under a copied CA
/// presents a certificate nothing on this host vouches for, and that reads as a
/// generic TLS error unless something separates it from the other four ways a
/// handshake fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertFault {
    /// The configured CA could not be used at all: missing, unreadable, or
    /// carrying no certificate.
    NoCa(String),
    /// It loaded, and does not vouch for what the server presented.
    Untrusted,
    /// It vouches for the certificate, which does not carry the name in the
    /// URL. `presented` is what the certificate does carry, in rustls' own
    /// shape -- `DnsName("dc.example.site")` -- which is left alone because the
    /// kind of name is half the answer: a SAN of IP addresses and a URL of
    /// hostnames never match, however right both look.
    WrongName { presented: Vec<String> },
    /// Signed by the configured CA, and past its own validity window.
    Expired,
    /// Anything else the handshake failed on.
    Other(String),
}

/// What the public path answered, link by link.
///
/// [`Reach`] one service outward: that one is the directory this tool binds,
/// this is the endpoint a *client* reaches -- TLS terminates, the route matches,
/// and the broker is behind it. The same seam again, for the same reason:
/// `endpoint.rs` runs the probes and `doctor/mod.rs` words them, so every
/// verdict below is testable with nothing listening.
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// The URL that was requested: the base the caller gave, plus `/config`.
    pub asked: String,
    pub host: String,
    pub port: u16,
    /// `false` for a plain `http://` base -- a broker reached directly on its
    /// own `listen` address, where there is no certificate to judge.
    pub tls: bool,
    /// The address connected to instead of resolving `host`, when the caller
    /// named one. The certificate is still judged against `host`, exactly as
    /// `curl --resolve` does it: the published port is on loopback and the name
    /// in the URL is the one a client uses.
    pub via: Option<SocketAddr>,
    pub anchor: TrustAnchor,
    /// Whether a certificate the anchor does not vouch for was allowed to be a
    /// remark rather than the end of the walk.
    pub any_cert: bool,
    pub resolve: Option<Result<Vec<IpAddr>, String>>,
    pub tcp: Option<Result<SocketAddr, String>>,
    /// The certificate's verdict, recorded whether or not it was fatal.
    pub cert: Option<Result<(), CertFault>>,
    /// The session itself. `Err` is *no TLS at all* -- an endpoint listening
    /// with no certificate to present, which under an ACME strategy is issuance
    /// still in flight and under a supplied one is a certificate that did not
    /// load.
    pub session: Option<Result<(), String>>,
    pub answer: Option<Result<Answer, String>>,
}

/// What the certificate was judged against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustAnchor {
    /// The compiled-in public roots -- what a client's own store would say, and
    /// the only question worth asking of a certificate an ACME strategy went and
    /// got.
    Public,
    /// One CA file, and only it: a private CA, or the bench's own.
    Ca(PathBuf),
}

/// The `GET /config` exchange itself.
#[derive(Debug, Clone)]
pub struct Answer {
    pub status: u16,
    /// The source names a broker lists when it refuses an unprefixed `/config`
    /// because several sources make the answer ambiguous. `None` when the body
    /// carried no such list -- which is what a path nothing routed returns, and
    /// the distinction this link exists for: both are 404.
    pub sources: Option<Vec<String>>,
}

/// One read of the directory. Everything the pure half is allowed to know.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub base_dn: String,
    pub cloud_idp_ou: String,
    pub resource_ou: String,
    /// The domain's NetBIOS name, read from the Partitions container rather
    /// than guessed from the first `DC=` component: it is the prefix of the
    /// `DOMAIN\name` this tool tells the operator to run `id` on, and a wrong
    /// one sends them chasing a lookup that was never going to work.
    #[serde(default)]
    pub netbios: Option<String>,
    /// Seconds since the Unix epoch, for the held-age arithmetic. Carried
    /// rather than read from the clock, so a fixture pins it.
    pub now: u64,
    #[serde(default)]
    pub cloud: Vec<CloudObject>,
    /// Groups from the resource OU, plus any group outside the IdP parent OU that a
    /// managed object is nested into wherever it lives.
    #[serde(default)]
    pub resources: Vec<ResourceGroup>,
    /// The IdP-specific OUs themselves -- one per cloud IdP.
    #[serde(default)]
    pub idp_ous: Vec<IdpOu>,
}

/// One cloud IdP's own OU, as an object rather than as a DN prefix.
///
/// The identities under it name a source name and nothing else; the OU's own
/// name is what says which source that is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdpOu {
    pub dn: String,
}

impl Snapshot {
    /// The IdP-specific OU holding `dn`: the child of the IdP parent OU that
    /// contains it, however deep below that the object actually sits.
    ///
    /// `None` for a DN outside the IdP parent OU, and for the IdP parent OU itself.
    ///
    /// The unit every once-per-source rule counts within: it is the search base
    /// one broker resolves a role marker in.
    pub fn idp_ou_of(&self, dn: &str) -> Option<String> {
        let mut cur = dn.to_owned();
        loop {
            let parent = parent_of(&cur).to_owned();
            if parent.is_empty() {
                return None;
            }
            if dn_equals(&parent, &self.cloud_idp_ou) {
                // Only a strict ancestor counts. An object sitting directly in
                // the IdP parent OU would otherwise be reported as its own source
                // OU, which reads as healthy and is the opposite: no broker's
                // search base contains it.
                return (cur != dn).then_some(cur);
            }
            cur = parent;
        }
    }

    /// The realm-admission group in one IdP-specific OU, which is the only one that
    /// admits that source's users. Another source's is a different group and
    /// says nothing about them.
    pub fn admission_group_in(&self, source_ou: &str) -> Option<&CloudObject> {
        self.role_group_in(source_ou, |o| o.is_admission_group())
    }

    pub fn grant_group_in(&self, source_ou: &str) -> Option<&CloudObject> {
        self.role_group_in(source_ou, |o| o.is_grant_group())
    }

    fn role_group_in(
        &self,
        source_ou: &str,
        marked: impl Fn(&CloudObject) -> bool,
    ) -> Option<&CloudObject> {
        self.cloud.iter().find(|o| marked(o) && dn_is_at_or_within(&o.dn, source_ou))
    }

    /// The object holding the device this handle names, and the grant itself.
    ///
    /// Keyed on the handle rather than on the label because the label is client
    /// data: two machines claiming one name would otherwise revoke the wrong one,
    /// or fail ambiguously at precisely the wrong moment.
    pub fn find_device(&self, id: &str) -> Option<(&CloudObject, &str, DeviceGrant)> {
        self.cloud.iter().find_map(|o| {
            o.grants().into_iter().find(|(_, g)| g.short_id() == id).map(|(raw, g)| (o, raw, g))
        })
    }

    /// The delegate groups naming this account: whose members may authorize a
    /// device on its behalf.
    ///
    /// A list because the directory permits several -- `managedObjects` is
    /// multi-valued -- and not because the tool makes them: `device delegate
    /// set` replaces, so more than one means someone wrote the link by hand.
    pub fn delegates_of(&self, user_dn: &str) -> Vec<&ResourceGroup> {
        self.resources
            .iter()
            .filter(|g| g.delegates_for().is_some_and(|dn| dn.eq_ignore_ascii_case(user_dn)))
            .collect()
    }

    pub fn find_cloud(&self, dn: &str) -> Option<&CloudObject> {
        self.cloud.iter().find(|o| o.dn.eq_ignore_ascii_case(dn))
    }

    pub fn find_resource(&self, dn: &str) -> Option<&ResourceGroup> {
        self.resources.iter().find(|g| g.dn.eq_ignore_ascii_case(dn))
    }

    /// Every group, at any depth, that `dn` ends up inside. Follows `member`
    /// links across both OUs and tolerates cycles, which the directory
    /// permits and the sync fixtures actually contain.
    pub fn closure_of(&self, dn: &str) -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        let mut queue = vec![dn.to_owned()];
        while let Some(current) = queue.pop() {
            let parents = self
                .cloud
                .iter()
                .filter(|o| o.members.iter().any(|m| m.eq_ignore_ascii_case(&current)))
                .map(|o| o.dn.clone())
                .chain(
                    self.resources
                        .iter()
                        .filter(|g| g.members.iter().any(|m| m.eq_ignore_ascii_case(&current)))
                        .map(|g| g.dn.clone()),
                );
            for p in parents {
                if !seen.iter().any(|s| s.eq_ignore_ascii_case(&p)) {
                    seen.push(p.clone());
                    queue.push(p);
                }
            }
        }
        seen
    }
}
