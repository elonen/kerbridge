//! What this run acts on: which broker, which account, which realm, and the
//! access token that proves the caller. Every subcommand starts here.

use std::sync::atomic::AtomicBool;

use anyhow::{Context, Result, anyhow};
use kerbridge_client::secret::Secret;
use kerbridge_client::{config, discovery, oidc};

use crate::Args;

/// Whom this machine authorizes itself for, when that is pinned at all.
pub(crate) fn pinned_target() -> Option<String> {
    config::Settings::load().grant_for().map(str::to_owned)
}

/// Whether persisted agent state can be used for this CLI run. A DNS-selected
/// broker has no stored URL, so absence of an explicit override is the proof.
pub(crate) fn stored_state_applies(
    explicit_broker: Option<&str>,
    requested_broker: &str,
    configured_broker: Option<&str>,
) -> bool {
    match (explicit_broker, configured_broker) {
        (Some(_), None) => false,
        (_, Some(configured)) => configured == requested_broker,
        (None, None) => true,
    }
}

/// Which account a `--grant*` run acts on: `--for` if given, else the pin.
///
/// The UPN check happens here rather than only at the broker because the round
/// trip in between is a browser sign-in, and the end of one is the worst place
/// to be told the name was never going to work.
pub(crate) fn resolve_target(args: &Args) -> Result<Option<String>> {
    // Named, because the two come from different people: `--for` is this
    // command line and the pin is whatever the machine was set up with, and
    // being told "--for" about a value nobody typed is a wild goose chase.
    let (target, whence) = match &args.target {
        Some(t) => (t.clone(), "--for"),
        None => match pinned_target() {
            Some(t) => (t, "the account this machine gets tickets as"),
            None => return Ok(None),
        },
    };
    kerbridge_client::broker::check_target(&target).map_err(|why| anyhow!("{whence}: {why}"))?;
    Ok(Some(target))
}

/// `--broker` > configured value (policy, then `config.toml`) > the
/// `_kerbridge._tcp.<domain>` SRV record. No built-in default: guessing a broker
/// URL is guessing who may authenticate this machine, and DNS is only asked
/// about the machine's own domain.
pub(crate) fn resolve_broker(args: &Args) -> Result<String> {
    if let Some(b) = &args.broker {
        return Ok(b.clone());
    }
    let mut settings = config::Settings::load();
    if settings.broker_url().is_none()
        && let Some(url) = kerbridge_client::srv::discover_broker()
    {
        println!("[kerbridge] found {url} in DNS");
        settings.set_discovered(url);
    }
    settings
        .broker_url()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("no broker configured -- pass --broker <url>, publish a _kerbridge._tcp.<domain> SRV record, or set it in the agent's Settings window"))
}

/// Obtain an access token: use the one supplied, or run the browser sign-in.
///
/// Hands back the base this run's broker calls hang off alongside it: the
/// address asked, plus the source segment the broker confirmed. Unchanged where
/// no discovery ran, which is `--token-file`.
pub(crate) fn obtain_token(args: &Args, broker: &str) -> Result<(String, Secret)> {
    if let Some(path) = &args.token_file {
        let token = std::fs::read_to_string(path)
            .with_context(|| format!("reading an access token from {}", path.display()))?;
        return Ok((broker.to_owned(), Secret::new(token.trim())));
    }
    let config = discovery::discover(broker).context("discovering OIDC configuration")?;
    // Share the realm with the agent only when this run follows its effective
    // broker. An explicit override must not replace the agent's cached realm.
    let mut settings = config::Settings::load();
    if stored_state_applies(args.broker.as_deref(), broker, settings.broker_url())
        && settings.set_cache(&config.kerberos)
    {
        let _ = settings.save();
    }
    let tokens = oidc::login(&config.oidc, &AtomicBool::new(false))
        .context("browser sign-in")?
        .ok_or_else(|| anyhow!("sign-in cancelled"))?;
    if tokens.refresh_token.is_some() {
        // Held in memory only; the tray agent uses it for silent re-injection.
        eprintln!("[kerbridge] refresh token acquired (held in memory, never written)");
    }
    Ok((config.base_url, tokens.access_token))
}

/// The realm's name, offline-first: the cached copy the tray/CLI last discovered,
/// falling back to a live broker lookup only when nothing is cached -- so removing
/// or purging a realm works even when the broker is unreachable.
pub(crate) fn resolve_realm(args: &Args) -> Result<String> {
    let settings = config::Settings::load();
    let requested = args.broker.as_deref().or_else(|| settings.broker_url()).unwrap_or_default();
    if stored_state_applies(args.broker.as_deref(), requested, settings.broker_url()) {
        let cached = settings.cache().realm.clone();
        if !cached.is_empty() {
            return Ok(cached);
        }
    }
    Ok(discovery::discover(&resolve_broker(args)?)?.kerberos.realm)
}

#[cfg(test)]
mod tests {
    use super::stored_state_applies;

    #[test]
    fn dns_run_uses_the_stored_grant_without_a_persisted_broker_url() {
        assert!(stored_state_applies(None, "https://kerbridge.example.site", None));
    }

    #[test]
    fn configured_run_uses_state_only_for_its_effective_broker() {
        let broker = "https://kerbridge.example.site";
        assert!(stored_state_applies(None, broker, Some(broker)));
        assert!(!stored_state_applies(None, broker, Some("https://other.example.site")));
    }

    #[test]
    fn explicit_broker_uses_state_only_when_it_matches_configuration() {
        let broker = "https://kerbridge.example.site";
        assert!(stored_state_applies(Some(broker), broker, Some(broker)));
        assert!(!stored_state_applies(Some(broker), broker, None));
        assert!(!stored_state_applies(Some(broker), broker, Some("https://other.example.site")));
    }
}
