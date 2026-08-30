//! Broker configuration, and the document it publishes to helpers.
//!
//! All of it comes from the config set. Secrets arrive as the files that the
//! set names, never as values: a password in a config file is a password in
//! every backup of that file.

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
    /// The domain root. Every account search starts here, whatever source the
    /// account belongs to: the identity filter already names the source. A
    /// search of per-source subtrees would hide two objects that claim one
    /// identity across two OUs, instead of
    /// [`crate::directory::Denied::Ambiguous`].
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
    /// Passed to `kerbridge-notify` verbatim. Read from `main.toml` and not per
    /// component: an operator who sets up a channel sets up one channel.
    pub notify: kerbridge_core::config::Notify,
    pub device_grants: DeviceGrantConfig,
    /// What a workstation agent should do where nobody at that end has said.
    /// Read from `main.toml` and republished verbatim: this process holds no
    /// opinion about any of it, and the agent is the one that resolves it
    /// against its own policy layer and its user's file.
    pub client_defaults: kerbridge_core::config::ClientDefaults,
    /// Every source that this process serves, in the order that `main.toml`
    /// lists them. May be empty: a realm part-way through bootstrap has no
    /// source yet, and a broker that refused to start would take down the only
    /// running service of the deployment.
    pub sources: Vec<SourceConfig>,
}

/// One source, as this process serves it.
///
/// The name is three things at once: the URL segment that a request arrives on,
/// the source field of every identity that this adapter mints, and the OU that
/// those accounts live in. It is thus stated once, in the config set, and
/// derived everywhere else.
pub struct SourceConfig {
    pub source: Source,
    pub settings: IdpSettings,
    /// This source's IdP-specific OU, and the subtree its role groups are
    /// searched in.
    pub ou: String,
}

/// The device-grant options. Off by default: an operator who does nothing gets
/// nothing, the way the rest of the stack fails closed.
pub struct DeviceGrantConfig {
    /// How long a device may go before a human proves the identity to Entra
    /// again. **Not** the revocation window: every lever in `DESIGN.md`
    /// @ Ticket policy still takes at most one ticket lifetime, because the
    /// exchange path re-checks each one. `0` turns the feature off, and turns
    /// off every outstanding grant with it. Every exchange evaluates the clamp
    /// in [`kerbridge_core::grant::DeviceGrant::effective_end`], thus "I
    /// disabled it and it stayed on" cannot happen.
    pub days: u32,
    /// A safety bound and not policy: it stops a compromised broker from a loop
    /// of `GrantDevice` calls that inflates an object. Configurable because one
    /// service account across twenty build machines is the economical shape --
    /// Entra licenses per user -- and a small constant would break the exact
    /// deployment that this feature exists for. `issuerd` enforces the bound;
    /// this copy is what the tray hears.
    pub max_per_user: usize,
    /// An assertion must name this value to be accepted here. An assertion
    /// captured against this deployment thus cannot be presented to another.
    ///
    /// Derived from the realm, not configured. The broker does not know its own
    /// public URL -- Caddy terminates TLS and `listen` is loopback -- and a
    /// separate setting would be a string that the tray's copy must match
    /// exactly. The realm is already the identity of the deployment, and the
    /// tray reads this value straight out of `GET /{source}/config`.
    ///
    /// Deployment-wide and not per source, because that is what it names.
    /// [`crate::http::same_source`] is what stops a grant minted under one
    /// source from being spent under another: it compares the identity that the
    /// assertion decodes to against the source that the request arrived on.
    pub audience: String,
}

impl DeviceGrantConfig {
    pub fn enabled(&self) -> bool {
        self.days > 0
    }
}

/// The `GET /{source}/config` body. The helper bootstraps from a broker URL
/// alone and discovers everything else here. That keeps the helper ignorant of
/// whether the realm behind this broker is Samba, MIT, or anything else.
#[derive(Serialize)]
pub struct Discovery {
    /// Where the other routes of this source are. A reference to resolve
    /// against the URL that this document came from -- `/entra`, not an absolute
    /// URL.
    ///
    /// Relative, because nothing here knows the public address of the
    /// deployment: the broker listens on loopback behind Caddy. An absolute
    /// answer could only come from the `Host` header, and whoever sets that
    /// header could then move the client to another origin.
    pub base_url: String,
    pub oidc: OidcDiscovery,
    pub kerberos: KerberosDiscovery,
    pub ticket_format: &'static str,
    pub device_grant: DeviceGrantDiscovery,
    /// Absent where the deployment expressed no preference, which reads to a
    /// client as "no opinion" -- the same answer a client too old to look gets.
    #[serde(skip_serializing_if = "ClientDefaultsDiscovery::is_empty")]
    pub client_defaults: ClientDefaultsDiscovery,
}

/// The deployment's preferences, as a client reads them. Each absent value is
/// one the operator left unset, and a client that finds none keeps its own
/// built-in answer.
#[derive(Serialize, Default)]
pub struct ClientDefaultsDiscovery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub autostart: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows_sign_in: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ntlm_fallback_recovery: Option<bool>,
}

impl ClientDefaultsDiscovery {
    fn is_empty(&self) -> bool {
        self.autostart.is_none()
            && self.windows_sign_in.is_none()
            && self.ntlm_fallback_recovery.is_none()
    }
}

/// The device-grant facts a helper needs before it offers one. `days` of 0 is
/// the whole answer for a deployment with the feature off: the tray hides the
/// button. The tray also takes the duration in its own strings from this value,
/// instead of a hardcoded one.
#[derive(Serialize)]
pub struct DeviceGrantDiscovery {
    pub days: u32,
    pub max_per_user: usize,
    pub audience: String,
}

#[derive(Serialize)]
pub struct KerberosDiscovery {
    pub realm: String,
    /// May be empty. With `_kerberos._udp.<realm>` published, enrollment
    /// registers the realm and pins no KDC, which is the shape that survives a
    /// replaced DC.
    pub kdcs: Vec<String>,
    /// Escape hatch: plain host or suffix entries for
    /// `ksetup /addhosttorealmmap`, for a service outside the realm's DNS zone.
    /// Empty in the common layout, where the DNS-suffix heuristic maps
    /// same-zone hosts with no entry.
    pub services: Vec<String>,
}

impl Config {
    /// Build the `GET /{source}/config` body. The `oidc` half comes from the
    /// adapter verbatim: which scopes to ask for, and in what syntax, is a fact
    /// about the provider, and this file may hold no opinion about it.
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
            client_defaults: ClientDefaultsDiscovery {
                autostart: self.client_defaults.autostart,
                windows_sign_in: self.client_defaults.windows_sign_in,
                ntlm_fallback_recovery: self.client_defaults.ntlm_fallback_recovery,
            },
        }
    }

    /// Read the whole config set, and reduce it to what this process serves.
    ///
    /// Every `[provider_config]` parses here and not at first use. A typo in one
    /// would otherwise show up as the failed logins of one source, long after
    /// the operator stopped watching the deploy.
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
                settings: IdpSettings::parse(provider, &source.name, &source.provider_config)
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
            client_defaults: main.client_defaults,
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

/// The audience that a device assertion must name. Opaque to both ends and
/// compared byte for byte. Its only job: an assertion captured against one
/// deployment cannot be presented to another.
fn device_grant_audience(realm: &str) -> String {
    format!("kerbridge://{realm}")
}

/// Refuse a listen address outside loopback.
///
/// This process speaks plain HTTP. Caddy terminates TLS and reaches the broker
/// over the loopback that the two share, because they live in one network
/// namespace. A bind outside loopback thus serves `POST /{source}/ticket` in the
/// clear: on the bench to the bridge, and under production host networking to
/// every interface on the box. `DESIGN.md` @ Security boundaries: "The broker
/// accepts traffic on host loopback only."
///
/// `deploy/scripts/config/check-env.sh` refuses the same thing before the
/// container starts. The rule here is the same one and not a stricter one: the
/// script cannot help anyone who runs the binary directly, and two checks that
/// disagreed would be worse than either alone. The port is free to move --
/// nothing publishes it. The address is not.
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
