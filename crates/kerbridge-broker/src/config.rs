//! Broker configuration, and the document it publishes to helpers.
//!
//! The whole of it comes from the config set; secrets arrive as the files it
//! names, never as values -- a password in a config file is a password in every
//! backup of it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use kerbridge_core::Source;
use kerbridge_idp::{IdpSettings, OidcDiscovery, Provider};
use serde::Serialize;

pub struct Config {
    pub listen: String,
    pub realm: String,
    pub kdcs: Vec<String>,
    pub services: Vec<String>,
    pub ldap_url: String,
    /// The domain root. Accounts are searched from here whatever source they
    /// belong to: the identity filter already names the source, and searching
    /// per-source subtrees would make two objects claiming one identity across
    /// two OUs invisible rather than [`crate::directory::Denied::Ambiguous`].
    pub ldap_base_dn: String,
    pub ldap_bind_dn: String,
    pub ldap_bind_password: String,
    pub ldap_ca_file: PathBuf,
    pub issuer_socket: PathBuf,
    pub ticket_lifetime_seconds: u32,
    pub ticket_renewable_seconds: u32,
    pub timeout: Duration,
    pub max_inflight: usize,
    pub audit_log_file: Option<PathBuf>,
    /// Passed to `kerbridge-notify` verbatim. Read from `main.toml` rather than
    /// per component, because an operator wiring up a channel is wiring up one.
    pub notify: kerbridge_core::config::Notify,
    pub device_grants: DeviceGrantConfig,
    /// Every source this process serves, in the order `main.toml` lists them.
    /// May be empty: a realm mid-bootstrap has no source yet, and a broker that
    /// refused to start would take the deployment's only running service with
    /// it.
    pub sources: Vec<SourceConfig>,
}

/// One source, as this process serves it.
///
/// The name is three things at once -- the URL segment a request arrives on, the
/// source field of every identity this adapter mints, and the OU those accounts
/// live in -- which is exactly why it is stated once, in the config set, and
/// derived everywhere else.
pub struct SourceConfig {
    pub source: Source,
    pub settings: IdpSettings,
    /// This source's IdP-specific OU, and the subtree its role groups are
    /// searched in.
    pub ou: String,
}

/// The device-grant options, off by default so an operator who does nothing gets
/// nothing -- the way the rest of the stack fails closed.
pub struct DeviceGrantConfig {
    /// How long a device may go without a human proving the identity to Entra
    /// again. **Not** the revocation window: every lever in `DESIGN.md`
    /// @ Ticket policy still takes at most one ticket lifetime, because each is
    /// re-checked on the exchange path. `0` turns the feature off, and turns off
    /// every outstanding grant with it -- the clamp in
    /// [`kerbridge_core::grant::DeviceGrant::effective_end`] is evaluated on
    /// every exchange, so "I disabled it and it stayed on" cannot happen.
    pub days: u32,
    /// A safety bound rather than policy: what stops a compromised broker from
    /// looping `GrantDevice` and ballooning an object. Configurable because one
    /// service account across twenty build machines is the economical shape --
    /// Entra licenses per user -- and a small constant would break the exact
    /// deployment this feature exists for. `issuerd` enforces it; this copy is
    /// what the tray is told.
    pub max_per_user: usize,
    /// What an assertion must name to be accepted here, so one captured against
    /// this deployment cannot be presented to another.
    ///
    /// Derived from the realm rather than configured. The broker has no
    /// knowledge of its own public URL -- Caddy terminates TLS and `listen` is
    /// loopback -- and a separate setting would be a string the tray's copy has
    /// to match exactly. The realm is already the deployment's identity, and the
    /// tray reads this value straight out of `GET /{source}/config`.
    ///
    /// Deployment-wide rather than per source, because that is what it names.
    /// What keeps a grant minted under one source from being spent under
    /// another is [`crate::same_source`], which compares the identity the
    /// assertion decodes to against the source the request arrived on.
    pub audience: String,
}

impl DeviceGrantConfig {
    pub fn enabled(&self) -> bool {
        self.days > 0
    }
}

/// The `GET /{source}/config` body. The helper bootstraps from a broker URL
/// alone and discovers everything else here, which is what keeps it ignorant of
/// whether the realm behind this broker is Samba, MIT, or anything else.
#[derive(Serialize)]
pub struct Discovery {
    /// Where this source's other routes are, as a reference to resolve against
    /// the URL this document was fetched from -- `/entra`, not an absolute URL.
    ///
    /// Relative because nothing here knows the deployment's public address: the
    /// broker listens on loopback behind Caddy, so an absolute answer could only
    /// be rebuilt from the `Host` header, and whoever sets that header could then
    /// re-base the client onto another origin.
    pub base_url: String,
    pub oidc: OidcDiscovery,
    pub kerberos: KerberosDiscovery,
    pub ticket_format: &'static str,
    pub device_grant: DeviceGrantDiscovery,
}

/// What a helper needs to know about device grants before offering one. `days`
/// of 0 is the whole answer for a deployment with the feature off: the tray
/// hides the button, and takes the duration in its own strings from this value
/// rather than hardcoding one.
#[derive(Serialize)]
pub struct DeviceGrantDiscovery {
    pub days: u32,
    pub max_per_user: usize,
    pub audience: String,
}

#[derive(Serialize)]
pub struct KerberosDiscovery {
    pub realm: String,
    /// May be empty: with `_kerberos._udp.<realm>` published, enrollment
    /// registers the realm without pinning a KDC, which is the shape that
    /// survives a DC being replaced.
    pub kdcs: Vec<String>,
    /// Escape hatch: plain host/suffix entries for `ksetup /addhosttorealmmap`
    /// when a service lives outside the realm's DNS zone. Empty in the common
    /// layout, where the DNS-suffix heuristic maps same-zone hosts unmapped.
    pub services: Vec<String>,
}

impl Config {
    /// The `GET /{source}/config` body. The `oidc` half comes from the adapter
    /// verbatim: which scopes to ask for, and in what syntax, is a provider fact
    /// and not one this file is allowed to have an opinion about.
    pub fn discovery(&self, oidc: OidcDiscovery, source: &str) -> Discovery {
        Discovery {
            base_url: format!("/{source}"),
            oidc,
            kerberos: KerberosDiscovery {
                realm: self.realm.clone(),
                kdcs: self.kdcs.clone(),
                services: self.services.clone(),
            },
            ticket_format: kerbridge_core::issuer::TICKET_FORMAT,
            device_grant: DeviceGrantDiscovery {
                days: self.device_grants.days,
                max_per_user: self.device_grants.max_per_user,
                audience: self.device_grants.audience.clone(),
            },
        }
    }

    /// The whole config set, reduced to what this process serves.
    ///
    /// Every source's `[provider_config]` is parsed here rather than at first
    /// use: a typo in one would otherwise surface as one source's logins
    /// failing, long after the operator stopped watching the deploy.
    pub fn load(dir: &Path) -> Result<(Self, Vec<String>)> {
        let set = kerbridge_core::config::Config::load(dir)?;
        let (main, realm, broker) = (set.main, set.realm, set.broker);

        require_loopback(&broker.listen)?;

        let parent_ou = realm.idp_parent_ou();
        let mut sources = Vec::with_capacity(set.sources.len());
        for source in &set.sources {
            let file = format!("idp_{}.toml", source.name);
            let provider = Provider::from_name(&source.provider)
                .with_context(|| format!("{file}: provider"))?;
            sources.push(SourceConfig {
                source: Source::new(source.name.clone())
                    .with_context(|| format!("{file}: name"))?,
                settings: IdpSettings::parse(provider, &source.provider_config)
                    .with_context(|| format!("in {file}"))?,
                ou: source.ou(&parent_ou),
            });
        }

        let config = Self {
            listen: broker.listen,
            device_grants: DeviceGrantConfig {
                days: main.device_grant_days,
                max_per_user: main.device_grant_max_per_user as usize,
                audience: device_grant_audience(&realm.realm),
            },
            ldap_base_dn: realm.base_dn(),
            ldap_url: realm.ldap_url,
            ldap_bind_dn: broker.bind_dn,
            ldap_bind_password: kerbridge_core::secret::read(&broker.bind_password_file)?,
            ldap_ca_file: realm.ldap_ca_file,
            issuer_socket: broker.issuer_socket,
            ticket_lifetime_seconds: realm.ticket_lifetime_seconds,
            ticket_renewable_seconds: realm.ticket_renewable_seconds,
            timeout: Duration::from_secs(broker.timeout_seconds.into()),
            max_inflight: broker.max_inflight,
            audit_log_file: broker.audit_log_file,
            notify: main.notify,
            realm: realm.realm,
            kdcs: realm.kdcs,
            services: realm.services,
            sources,
        };
        Ok((config, set.warnings))
    }
}

/// The audience a device assertion must name. Opaque to both ends and compared
/// byte for byte; its only job is to keep an assertion captured against one
/// deployment from being presented to another.
fn device_grant_audience(realm: &str) -> String {
    format!("kerbridge://{realm}")
}

/// Refuse a listen address outside loopback.
///
/// This process speaks plain HTTP; Caddy terminates TLS and reaches it over the
/// loopback the two share by living in one network namespace. A non-loopback
/// bind therefore serves `POST /{source}/ticket` in the clear -- on the bench to
/// the bridge, and under production host networking to every interface on the
/// box. `DESIGN.md` @ Security boundaries: "The broker accepts traffic only on
/// host loopback."
///
/// `deploy/scripts/config/check-env.sh` refuses the same thing before the
/// container starts, and this is deliberately the same rule rather than a
/// stricter one: the script cannot help anyone who runs the binary directly,
/// and two checks that disagreed would be worse than either alone. The port is
/// free to move -- nothing publishes it; the address is not.
fn require_loopback(listen: &str) -> Result<()> {
    // Split at the *last* colon: an IPv6 literal is full of the others.
    let host = listen.rsplit_once(':').map_or(listen, |(host, _)| host);
    let ok = match host.trim_start_matches('[').trim_end_matches(']') {
        "localhost" => true,
        host => host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()),
    };
    if ok {
        return Ok(());
    }
    bail!(
        "broker.toml: listen = {listen:?} binds outside loopback. The broker serves plain HTTP \
         and Caddy is the only TLS listener, so this would put the ticket API on the network \
         unencrypted. Change the port if you must; the address is not a setting"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_listener_stays_on_loopback() {
        for ok in ["127.0.0.1:8080", "127.0.0.53:1", "localhost:8080", "[::1]:8080"] {
            assert!(require_loopback(ok).is_ok(), "{ok}");
        }
        for bad in ["0.0.0.0:8080", "192.0.2.10:8080", "[::]:8080", "broker.example.site:8080"] {
            assert!(require_loopback(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_plaintext_directory_url_is_refused() {
        assert!(kerbridge_core::require_ldaps("ldaps://dc.example.site:636").is_ok());
        for bad in ["ldap://dc.example.site:389", "ldap://dc.example.site:636", "dc.example.site"] {
            assert!(kerbridge_core::require_ldaps(bad).is_err(), "{bad}");
        }
    }
}
