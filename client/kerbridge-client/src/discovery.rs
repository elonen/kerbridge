//! Broker and OIDC discovery.
//!
//! The helper is given only a broker URL and derives everything else, so it
//! stays agnostic to the realm and IdP behind that broker. `GET {broker}/config`
//! yields the OIDC authority, public client id and scopes plus the Kerberos
//! realm the client should register; standard OIDC discovery against the
//! authority yields the authorize and token endpoints.
//!
//! TLS is mandatory (`client/DESIGN.md` @ security model): the broker is trusted
//! to name the realm's KDCs, which is a decision about who may authenticate this
//! machine, so a plaintext answer is refused outright rather than warned about.

use anyhow::{Context, Result, anyhow, bail};
use url::Url;

use crate::log;

/// Everything `oidc::login` needs, resolved from the broker URL alone.
#[derive(Clone)]
pub struct OidcConfig {
    pub client_id: String,
    /// What the UI calls the IdP ("Entra", or whatever the operator renamed it
    /// to). Required: the client has no provider name of its own to fall back on.
    pub display_name: String,
    /// The authority the broker named, verbatim (e.g.
    /// `https://login.microsoftonline.com/<tenant>/v2.0`). The endpoints below
    /// are what the browser flow uses; this is kept because WAM asks for the
    /// authority itself, not for an endpoint.
    pub authority: String,
    pub scopes: Vec<String>,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    /// The authority's RP-initiated logout endpoint, when it advertises one. Used
    /// by the tray's "sign out of the cloud too" path; `None` means the IdP does
    /// not offer a logout URL and only the local session can be dropped.
    pub end_session_endpoint: Option<String>,
}

/// The realm state the client is expected to register with Windows.
///
/// `kdcs` may legitimately be empty: the default deployment publishes
/// `_kerberos._udp.<realm>` and enrollment then registers the realm without
/// pinning a KDC name. `services` is the escape hatch for service hosts that
/// live *outside* the realm's DNS zone -- same-zone hosts are covered by
/// Windows' DNS-suffix heuristic and need no mapping.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct KerberosConfig {
    pub realm: String,
    pub kdcs: Vec<String>,
    pub services: Vec<String>,
}

/// What this deployment allows in the way of device grants.
///
/// `days` of 0 means the feature is off, and it is the whole answer: the tray
/// never offers the button, and it takes the duration in its own strings from
/// this value rather than hardcoding one. A broker too old to publish the block
/// reads the same way.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct DeviceGrantConfig {
    pub days: u32,
    /// What an assertion must name to be accepted. Copied from the broker rather
    /// than derived here, so the two ends cannot disagree about spelling.
    pub audience: String,
}

impl DeviceGrantConfig {
    pub fn enabled(&self) -> bool {
        self.days > 0 && !self.audience.is_empty()
    }
}

/// What this deployment prefers a client here to do, in the cases the user and
/// IT have both left open.
///
/// Every field is `None` on a broker that publishes no `client_defaults` block,
/// which is the ordinary case and reads as "no opinion" rather than as "off".
/// The block exists for the machines a management system does not own: policy
/// covers a managed fleet, and this covers the rest without asking DNS -- which
/// is unauthenticated -- to carry a decision about how this machine behaves.
///
/// A default never overrides a choice; it decides where there is none.
/// `config::Settings` holds the resolution order.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Defaults {
    /// Start the agent at login. Applied to the real login-item entry rather
    /// than only remembered -- `config::Settings::enforce_autostart`.
    pub autostart: Option<bool>,
    pub windows_sign_in: Option<bool>,
    pub ntlm_fallback_recovery: Option<bool>,
}

/// The whole `/config` document, as the helper uses it.
#[derive(Clone)]
pub struct BrokerConfig {
    /// Where this run's `/ticket`, `/nonce` and `/devices` are: the broker's
    /// answer to which source the address reached, resolved to an absolute URL.
    /// Equal to the address asked when that already named a source; it differs
    /// only for a client that found the broker in DNS.
    ///
    /// Never stored. Writing it to `config.toml` would pin a machine following
    /// DNS to whichever source answers today, and the pin would keep working
    /// after the realm added a second one -- silently, which is the outcome the
    /// segment exists to prevent.
    pub base_url: String,
    pub oidc: OidcConfig,
    pub kerberos: KerberosConfig,
    pub device_grant: DeviceGrantConfig,
    pub defaults: Defaults,
    /// Where the tray menu's *Help* goes, when the deployment publishes one.
    /// `None` on every broker that does not, which is what an older one reads
    /// as -- the client falls back to its own page.
    pub help_url: Option<String>,
}

/// Reject anything that is not an `https://` URL.
///
/// Called on the broker URL before every request, and on every URL the broker or
/// the IdP hands back -- the caller's `context` names which one.
///
/// Parsed rather than prefix-matched, following `assert_graph_url` in sync: a
/// scheme is a parsed property and `starts_with` only looks like one. It is wrong
/// in both directions -- `HTTPS://broker/` is a perfectly good https URL that the
/// prefix test refuses, and `https://` alone, or any other string that is not a
/// URL at all, is one it accepts and then fails on much later, at the request,
/// with an error naming the wrong thing.
pub fn require_https(url: &str) -> Result<()> {
    let parsed = Url::parse(url).map_err(|e| anyhow!("not a URL: `{url}` ({e})"))?;
    if parsed.scheme() != "https" {
        bail!("must be https:// (refusing to trust `{url}` over plaintext)");
    }
    Ok(())
}

/// The `/config` document and the base it resolves to, in one request.
fn fetch_config_and_base(broker_url: &str) -> Result<(serde_json::Value, String)> {
    require_https(broker_url)?;
    // Logged before the request, not after: every later line in a support log --
    // the realm, the authority, the failure -- is downstream of this URL, and
    // when the request is what fails there is otherwise nothing to say which
    // address was tried.
    let url = format!("{}/config", broker_url.trim_end_matches('/'));
    log::info(&format!("discovery: GET {url}"));
    let config = fetch_broker_config(&url).context("fetching broker /config")?;
    let base_url = resolve_base_url(&url, &config)?;
    Ok((config, base_url))
}

/// Which source this address reaches, and nothing else: no OIDC metadata,
/// unlike [`discover`]. The device-grant paths need that -- a machine proving
/// itself with its TPM key must reach a ticket with the IdP unreachable.
pub fn source_base(broker_url: &str) -> Result<String> {
    Ok(fetch_config_and_base(broker_url)?.1)
}

pub fn discover(broker_url: &str) -> Result<BrokerConfig> {
    let (config, base_url) = fetch_config_and_base(broker_url)?;

    let oidc_block = config.get("oidc").ok_or_else(|| anyhow!("/config has no `oidc` block"))?;
    let client_id = str_field(oidc_block, "client_id").context("/config oidc")?;
    let display_name = str_field(oidc_block, "display_name").context("/config oidc")?;
    let authority = str_field(oidc_block, "authority").context("/config oidc")?;
    let scopes = str_array(oidc_block, "scopes").context("/config oidc")?;
    if scopes.is_empty() {
        return Err(anyhow!("/config oidc.scopes is empty"));
    }

    let krb_block =
        config.get("kerberos").ok_or_else(|| anyhow!("/config has no `kerberos` block"))?;
    let kerberos = KerberosConfig {
        realm: str_field(krb_block, "realm").context("/config kerberos")?.to_uppercase(),
        // Both lists are optional: absent means "none", which is the common layout.
        kdcs: str_array(krb_block, "kdcs").unwrap_or_default(),
        services: str_array(krb_block, "services").unwrap_or_default(),
    };

    // The helper does not trust the broker to name the token endpoints; it runs
    // standard discovery against the authority itself.
    require_https(&authority).context("/config oidc.authority")?;
    // Named separately because this is the one call in the pair that reaches the
    // IdP rather than the broker. A reader who sees only "discovery failed" will
    // go and check the broker, which is up.
    let metadata_url =
        format!("{}/.well-known/openid-configuration", authority.trim_end_matches('/'));
    log::info(&format!("discovery: GET {metadata_url}"));
    let metadata = fetch_json(&metadata_url).context("fetching OIDC discovery document")?;

    let authorization_endpoint =
        str_field(&metadata, "authorization_endpoint").context("OIDC metadata")?;
    let token_endpoint = str_field(&metadata, "token_endpoint").context("OIDC metadata")?;
    // Optional in the spec; Entra publishes it. Absent = no cloud logout URL.
    let end_session_endpoint = str_field(&metadata, "end_session_endpoint").ok();

    // The endpoints are checked too, and this is the half that was missing. The
    // broker URL is the one an operator typed and can see; these three arrive from
    // the network, and they are where the secrets go -- the browser carries the
    // user's credentials to the authorization endpoint, and the authorization code
    // is exchanged at the token endpoint. A plaintext one is the whole login handed
    // to whoever is on the path, and the discovery document that named it was
    // itself only as trustworthy as the authority that served it.
    require_https(&authorization_endpoint).context("OIDC metadata authorization_endpoint")?;
    require_https(&token_endpoint).context("OIDC metadata token_endpoint")?;
    if let Some(logout) = &end_session_endpoint {
        // Refused rather than dropped to `None`. This one carries no token, so the
        // downgrade is smaller, but an authority publishing a plaintext endpoint is
        // broken in a way worth stopping on, and silently disabling cloud logout
        // would leave the tray offering a sign-out that no longer signs out.
        require_https(logout).context("OIDC metadata end_session_endpoint")?;
    }

    // Absent entirely on a broker predating device grants, which reads as off --
    // the same answer as a broker that has the feature and leaves it disabled.
    let device_grant = config
        .get("device_grant")
        .map(|block| DeviceGrantConfig {
            days: block.get("days").and_then(serde_json::Value::as_u64).unwrap_or(0) as u32,
            audience: str_field(block, "audience").unwrap_or_default(),
        })
        .unwrap_or_default();

    // Absent on a broker that expresses no preference, which is every one that
    // does not configure the block. A field of the wrong type reads as absent
    // for the same reason: this decides convenience, never access, so a typo in
    // it may not be what stops a machine signing in.
    let defaults = config
        .get("client_defaults")
        .map(|block| Defaults {
            autostart: bool_field(block, "autostart"),
            windows_sign_in: bool_field(block, "windows_sign_in"),
            ntlm_fallback_recovery: bool_field(block, "ntlm_fallback_recovery"),
        })
        .unwrap_or_default();

    // Optional, and a plaintext one is refused rather than used: a broker
    // already trusted to name the realm's KDCs is not made more dangerous by
    // naming a help page, but it does not get to send a user to one over http.
    // Refusing the *URL* rather than the whole document, unlike the endpoints
    // above -- a mistyped help link must not stop this machine signing in.
    let help_url = config.get("help_url").and_then(|v| v.as_str()).filter(|url| {
        require_https(url)
            .inspect_err(|e| log::warn(&format!("ignoring /config help_url: {e}")))
            .is_ok()
    });

    Ok(BrokerConfig {
        base_url,
        oidc: OidcConfig {
            client_id,
            display_name,
            authority,
            scopes,
            authorization_endpoint,
            token_endpoint,
            end_session_endpoint,
        },
        kerberos,
        device_grant,
        defaults,
        help_url: help_url.map(str::to_owned),
    })
}

/// The base the rest of this run's broker calls hang off, from the `base_url` in
/// the document and the address it was fetched from.
///
/// Resolved as a reference against that address, so a broker that answers a
/// bare `/config` can say "you reached `entra`" without knowing the deployment's
/// public name -- it sits on loopback behind a reverse proxy and does not have
/// one.
///
/// Absent on a broker predating source routing, which reads as "the address you
/// asked is the base".
fn resolve_base_url(config_url: &str, config: &serde_json::Value) -> Result<String> {
    let asked = Url::parse(config_url).map_err(|e| anyhow!("not a URL: `{config_url}` ({e})"))?;
    let base = asked.join(".").map_err(|e| anyhow!("no base for `{config_url}` ({e})"))?;
    let Some(reference) = config.get("base_url").and_then(|v| v.as_str()) else {
        return Ok(base.as_str().trim_end_matches('/').to_owned());
    };
    let resolved = base
        .join(reference)
        .map_err(|e| anyhow!("/config base_url `{reference}` is not a URL reference ({e})"))?;
    if resolved.origin() != asked.origin() {
        bail!(
            "/config base_url `{reference}` points off `{}`",
            asked.origin().ascii_serialization()
        );
    }
    Ok(resolved.as_str().trim_end_matches('/').to_owned())
}

/// Which source a [`BrokerConfig::base_url`] names: its last path segment.
///
/// Empty where the base carries no segment -- a broker predating source routing,
/// which names one source and does not say which.
pub fn source_name(base_url: &str) -> String {
    let Ok(url) = Url::parse(base_url) else {
        return String::new();
    };
    url.path_segments()
        .and_then(|mut segments| segments.rfind(|s| !s.is_empty()))
        .unwrap_or_default()
        .to_owned()
}

fn get_text(url: &str) -> Result<(u16, String)> {
    let mut resp = crate::http::agent().get(url).call().map_err(|e| {
        let failure = crate::http::describe(url, &e);
        // Typed rather than a message, because the tray has to tell this apart
        // from an unreachable broker and everything above here is `anyhow`.
        if failure.untrusted {
            anyhow::Error::new(crate::http::Untrusted::new(url, failure.message))
        } else {
            anyhow!("GET {}", failure.message)
        }
    })?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().context("reading response body")?;
    Ok((status, text))
}

fn fetch_json(url: &str) -> Result<serde_json::Value> {
    let (status, text) = get_text(url)?;
    if status != 200 {
        return Err(anyhow!("GET {url} returned {status}: {}", text.trim()));
    }
    serde_json::from_str(&text).with_context(|| format!("parsing JSON from {url}"))
}

/// The broker names more than one source, and this address named none of them.
///
/// Typed for the same reason [`crate::http::Untrusted`] is: the tray and the CLI
/// both have to say something other than "not found" here.
#[derive(Debug)]
pub struct AmbiguousSource {
    pub sources: Vec<String>,
}

impl std::fmt::Display for AmbiguousSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "this broker serves several sources and the address names none of them ({}); the \
             broker URL has to end in one of them",
            self.sources.join(", ")
        )
    }
}

impl std::error::Error for AmbiguousSource {}

/// `GET /config`, telling the ambiguous 404 apart from every other one.
///
/// The list in the body decides it, not the status: a 404 is also what a bare
/// web server, a stale reverse proxy, or a wrong hostname returns, and those are
/// not this.
fn fetch_broker_config(url: &str) -> Result<serde_json::Value> {
    let (status, text) = get_text(url)?;
    if let Some(ambiguous) = ambiguous_source(status, &text) {
        return Err(anyhow::Error::new(ambiguous));
    }
    if status != 200 {
        return Err(anyhow!("GET {url} returned {status}: {}", text.trim()));
    }
    serde_json::from_str(&text).with_context(|| format!("parsing JSON from {url}"))
}

fn ambiguous_source(status: u16, body: &str) -> Option<AmbiguousSource> {
    if status != 404 {
        return None;
    }
    let parsed = serde_json::from_str::<serde_json::Value>(body).ok()?;
    let sources = str_array(&parsed, "sources").ok().filter(|s| !s.is_empty())?;
    Some(AmbiguousSource { sources })
}

fn str_field(value: &serde_json::Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("missing string field `{key}`"))
}

fn bool_field(value: &serde_json::Value, key: &str) -> Option<bool> {
    value.get(key).and_then(serde_json::Value::as_bool)
}

fn str_array(value: &serde_json::Value, key: &str) -> Result<Vec<String>> {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
        .ok_or_else(|| anyhow!("`{key}` is missing or not an array"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn plaintext_and_non_urls_are_refused() {
        for bad in [
            "http://broker.example.site/",
            "ftp://broker.example.site/",
            // Parses, but names no host and is not a transport.
            "javascript:alert(1)//https://broker.example.site",
            // Prefix-shaped and not a URL: the old check accepted both of these and
            // failed later, at the request, complaining about the wrong thing.
            "https://",
            "https://[bad",
            "not a url",
            "",
        ] {
            assert!(require_https(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn a_base_url_may_not_move_the_client_off_the_origin_it_reached() {
        let asked = "https://kerbridge.example.site/config";
        let base = |v: serde_json::Value| resolve_base_url(asked, &v);

        assert_eq!(
            base(json!({"base_url": "/entra"})).unwrap(),
            "https://kerbridge.example.site/entra"
        );
        // No field: the address asked is the base, which is what a broker
        // predating source routing leaves the client with.
        assert_eq!(base(json!({})).unwrap(), "https://kerbridge.example.site");

        for off in ["https://elsewhere.example/entra", "//elsewhere.example/entra"] {
            assert!(base(json!({"base_url": off})).is_err(), "{off} must be refused");
        }
    }

    #[test]
    fn a_source_name_is_the_last_segment_or_nothing() {
        assert_eq!(source_name("https://kerbridge.example.site/entra"), "entra");
        assert_eq!(source_name("https://kerbridge.example.site/entra/"), "entra");
        for none in
            ["https://kerbridge.example.site", "https://kerbridge.example.site/", "nonsense"]
        {
            assert_eq!(source_name(none), "", "{none} names no source");
        }
    }

    #[test]
    fn only_a_404_naming_sources_is_ambiguous() {
        let body = r#"{"error": "which source?", "sources": ["entra", "entra-legacy"]}"#;
        let found = ambiguous_source(404, body).expect("a sources list makes it ambiguous");
        assert_eq!(found.sources, ["entra", "entra-legacy"]);

        for (status, body) in [
            // The 404s that are a bare web server, a stale proxy or a wrong host.
            (404, ""),
            (404, "<html>Not Found</html>"),
            (404, r#"{"error": "no such source"}"#),
            (404, r#"{"sources": []}"#),
            // The list read off any other status is not this.
            (200, body),
        ] {
            assert!(ambiguous_source(status, body).is_none(), "{status} {body:?}");
        }
    }

    /// The false negatives, which is the half a prefix test got wrong in the
    /// direction that breaks a working deployment rather than admitting a bad one.
    /// Measured against `url` 2.x (2026-07-30): each of these is a valid https URL
    /// naming `broker.example.site`, and each fails `starts_with("https://")`.
    #[test]
    fn valid_https_urls_a_prefix_test_would_have_refused() {
        for good in [
            "https://broker.example.site/config",
            // An operator who typed the scheme in caps. `with_https` in `config.rs`
            // leaves it alone because it already carries a scheme, so the refusal
            // used to land here.
            "HTTPS://broker.example.site/",
            "HttpS://broker.example.site/",
            // Leading space out of a hand-edited config.toml. WHATWG strips it.
            "  https://broker.example.site/",
            // No path, which is what `with_https` produces from a bare hostname.
            "https://broker.example.site",
        ] {
            assert!(
                require_https(good).is_ok(),
                "{good:?} must be accepted: {:?}",
                require_https(good)
            );
        }
    }
}
