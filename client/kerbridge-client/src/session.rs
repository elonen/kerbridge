//! One sign-in's worth of work: token in, injected TGT out.
//!
//! This is the single implementation of the pipeline's business end, so the
//! CLI's one-shot and the tray's silent re-injection cannot drift. Everything
//! upstream (how the token was obtained) and downstream (when to do it again) is
//! the caller's.

use base64::Engine;

use crate::broker::{self, AuthScheme, BrokerError};
use crate::config::Grant;
use crate::{device, krbcred, log, tickets};

/// A TGT now sitting in the caller's ticket cache.
#[derive(Clone)]
pub struct Injected {
    pub principal: String,
    /// Unix seconds. `renew_till` is 0 for a non-renewable ticket.
    pub start: i64,
    pub end: i64,
    pub renew_till: i64,
}

/// Why an injection failed. The split matters to the tray: a broker error is
/// classified (and some classes must *not* be retried), while a local error is
/// this machine's problem.
#[derive(Debug)]
pub enum InjectError {
    Broker(BrokerError),
    Local(anyhow::Error),
}

impl std::fmt::Display for InjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Broker(e) => write!(f, "{e}"),
            Self::Local(e) => write!(f, "{e:#}"),
        }
    }
}

/// Why authorizing this device failed. Split for the same reason
/// [`InjectError`] is: a broker refusal is classified and some classes are the
/// user's to clear, while a local failure is this machine's TPM.
#[derive(Debug)]
pub enum GrantError {
    Broker(BrokerError),
    Local(anyhow::Error),
}

impl std::fmt::Display for GrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Broker(e) => write!(f, "{e}"),
            Self::Local(e) => write!(f, "{e:#}"),
        }
    }
}

/// Exchange an access token for a TGT and land it in this user's ticket cache.
pub fn inject(broker_url: &str, access_token: &str) -> Result<Injected, InjectError> {
    inject_with(broker_url, AuthScheme::Bearer(access_token))
}

/// The same exchange, proved by this machine's device grant instead of a token.
///
/// Only the auth scheme differs: from here on the path is byte-identical, which
/// is the point -- the broker meets both proofs at the same directory lookup, so
/// nothing downstream can tell them apart or treat one more leniently.
pub fn inject_with_grant(broker_url: &str, grant: &Grant) -> Result<Injected, InjectError> {
    crate::discovery::require_https(broker_url).map_err(InjectError::Local)?;
    let key = device::open()
        .map_err(InjectError::Local)?
        // The key is gone but `config.toml` still names a grant: a rebuilt
        // profile, a cleared TPM, or a give-up that did not finish writing.
        // Reported as an identity problem because the fix is the same one -- sign
        // in through the browser.
        .ok_or_else(|| {
            InjectError::Broker(BrokerError::InvalidProof(
                "this machine no longer holds the device key".into(),
            ))
        })?;
    let nonce = broker::fetch_nonce(broker_url).map_err(InjectError::Broker)?;
    let assertion =
        device::assertion(&key, &grant.identity, &grant.audience, &nonce, crate::time::now())
            .map_err(InjectError::Local)?;
    inject_with(broker_url, AuthScheme::DeviceGrant(&assertion))
}

fn inject_with(broker_url: &str, scheme: AuthScheme<'_>) -> Result<Injected, InjectError> {
    crate::discovery::require_https(broker_url).map_err(InjectError::Local)?;

    let ticket = broker::fetch_ticket(broker_url, scheme).map_err(InjectError::Broker)?;
    let tgt = krbcred::ccache_to_tgt(&ticket.ccache).map_err(InjectError::Local)?;
    let realm = ticket
        .principal
        .rsplit('@')
        .next()
        .filter(|r| !r.is_empty())
        .unwrap_or_default()
        .to_owned();

    // Evict our realm's stale tickets before injecting the fresh TGT. Re-injecting
    // alone leaves the cached cifs/<nas> service ticket in place, so the OS keeps
    // serving the old PAC and a group/ACL change never takes effect (measured:
    // research spike `windows-tgt-renewal` row 7). Realm-scoped, so another realm's
    // credentials survive. Non-fatal: a fresh TGT is still worth injecting even if
    // the purge is refused.
    if !realm.is_empty() {
        match tickets::purge_realm(&realm) {
            Ok(n) if n > 0 => log::info(&format!("purged {n} stale {realm} ticket(s)")),
            Ok(_) => {}
            Err(e) => log::warn(&format!("realm ticket purge failed ({e:#}); injecting anyway")),
        }
    }

    tickets::inject(&ticket.ccache, &tgt).map_err(InjectError::Local)?;
    log::info(&format!(
        "injected TGT for {} (ends {})",
        ticket.principal,
        crate::time::local_stamp(tgt.end)
    ));

    Ok(Injected {
        principal: ticket.principal,
        start: tgt.start,
        end: tgt.end,
        renew_till: tgt.renew_till,
    })
}

/// Authorize this machine: make the key, register it, and hand back the grant to
/// store.
///
/// The access token *is* the authorization -- the broker registers the key on a
/// token it has just validated for an account it has just confirmed is
/// synchronized, enabled, admitted and permitted to hold grants -- so the caller
/// must have obtained one non-silently, and nothing here decides anything of its
/// own.
///
/// **The key this machine already has is reused.** `issuerd` replaces a grant
/// whose thumbprint it already holds, and counts such a re-grant against no cap,
/// so re-authorizing stays one row on the account. Making a fresh key each time
/// left the old grant in the directory instead -- unusable, its key destroyed,
/// and still occupying one of `device_grant_max_per_user` -- so a single machine
/// renewing on schedule locked its own account out after that many renewals.
///
/// The id is derived from the key, so it survives a re-authorization too; `added`
/// is what moves.
///
/// `target` authorizes the key for *somebody else's* account -- a service
/// account an unattended machine builds as -- which the broker allows only to
/// that account's delegates. The ticket this machine later obtains is then the
/// target's, and no ticket is issued for whoever signed in here.
pub fn create_grant(
    broker_url: &str,
    access_token: &str,
    audience: &str,
    target: Option<&str>,
) -> Result<Grant, GrantError> {
    crate::discovery::require_https(broker_url).map_err(GrantError::Local)?;
    let (key, fresh) = match device::open().map_err(GrantError::Local)? {
        Some(key) => (key, false),
        None => (device::create().map_err(GrantError::Local)?, true),
    };
    let point = key.public_point().map_err(GrantError::Local)?;
    let label = match target {
        Some(_) => delegated_label(access_token),
        None => device::default_label(),
    };
    let registered = broker::register_device(
        broker_url,
        access_token,
        device::ALG,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&point),
        &label,
        target,
    );
    let device = match registered {
        Ok(device) => device,
        Err(e) => {
            // Only a key this call made. A key that was already here still backs
            // whatever grant the account holds, and a refused re-grant -- at the
            // cap, outside the device-grant group, a broker that went away
            // mid-call -- must not take a working device down with it. A key the
            // broker never accepted is different: an assertion signed by it names
            // a thumbprint on no object, so it is cheaper to drop here than to
            // reason about later.
            if fresh {
                let _ = device::delete();
            }
            return Err(GrantError::Broker(e));
        }
    };

    Ok(Grant {
        grant_id: device.grant_id,
        // Server-stated, both of them. The `kb1|` encoding has exactly one
        // implementation and the audience one spelling; deriving either here
        // would let the two ends disagree, and a disagreement refuses every
        // later exchange with nothing to point at. Under delegation the identity
        // is also the *only* thing that names the target: the caller presented
        // their own token and never spelled it.
        identity: device.identity,
        // Unknown until the grant is used; the exchange is what teaches it.
        principal: None,
        audience: audience.to_owned(),
        sign_in_required_by: device.sign_in_required_by,
    })
}

/// The default label for a grant authorized on another account's behalf: this
/// machine, and who was standing at it.
///
/// Best-effort and cosmetic. The label is client-supplied and the broker
/// sanitizes it; the durable record of who authorized what is the broker's own
/// grant log. What this buys is that `kbmanage device list <target>` and that log
/// read the same at a glance, instead of one naming a machine and the other a
/// person. A machine's own name says nothing about who set it up, and on a
/// delegated grant that is the question being asked of the listing.
fn delegated_label(access_token: &str) -> String {
    let machine = device::default_label();
    match crate::oidc::token_account(access_token) {
        // Clamped, so the appended half cannot push the escaped label past the
        // directory's ceiling and take the machine's own name with it.
        Some(who) => format!("{machine} by {}", who.chars().take(30).collect::<String>()),
        None => machine,
    }
}

/// Give this machine's device grant back: destroy the key, then tell the broker.
///
/// **The order is the whole design.** Telling the broker first makes giving the
/// grant back conditional on reaching the broker, and a device that cannot give
/// its grant back while offline is one an unreachable network keeps authorized.
/// So the local key goes first, unconditionally -- it works offline and kills the
/// grant on this machine whatever the directory says -- and only then is the
/// broker told. A failed revocation therefore leaves a directory entry that is
/// stale but dead, because the key it names no longer exists.
///
/// Best-effort by construction, and it returns whether the broker was actually
/// told: a teardown that refused to finish because the broker was unreachable
/// would be one that does not work offline.
pub fn revoke_this_device(broker_url: Option<&str>, grant: &Grant) -> bool {
    let base = broker_url.and_then(|url| crate::discovery::source_base(url).ok());
    // Built before the key is destroyed, because it is signed with it.
    let assertion = base.as_deref().and_then(|url| self_revocation(url, grant).ok());
    if let Err(e) = device::delete() {
        log::warn(&format!("could not delete the device key ({e:#}); continuing"));
    }
    match (base, assertion) {
        (Some(url), Some(assertion)) => {
            // No target: a machine may name only its own identity, and the
            // broker refuses an assertion that names another account outright.
            match broker::revoke_device(
                &url,
                AuthScheme::DeviceGrant(&assertion),
                &grant.grant_id,
                None,
            ) {
                Ok(()) => {
                    log::info(&format!("revoked device grant {}", grant.grant_id));
                    true
                }
                Err(e) => {
                    log::warn(&format!(
                        "device grant {} not revoked at the broker ({e}); the key it names is \
                         gone, so it is already dead",
                        grant.grant_id
                    ));
                    false
                }
            }
        }
        _ => {
            log::warn(&format!(
                "device grant {} not revoked at the broker (offline); the key it names is gone, \
                 so it is already dead",
                grant.grant_id
            ));
            false
        }
    }
}

/// Sign off: drop every ticket for `realm` from this user's ticket cache.
///
/// The device grant survives, here as in the tray: giving it up is
/// [`revoke_this_device`], asked for by name.
///
/// Ticket-cache only, by design. An SMB session already open keeps serving until
/// the OS drops it; revocation is enforced at *ticket* granularity, and forcing a
/// live session closed risks open-handle data loss.
///
/// Returns the tickets purged.
pub fn sign_off(realm: &str) -> anyhow::Result<usize> {
    let n = tickets::purge_realm(realm)?;
    log::info(&format!("signed out of {realm} ({n} ticket(s) purged)"));
    Ok(n)
}

/// An assertion naming this device, for the one revocation that needs no IdP
/// token. Fallible and its failure is not fatal -- see [`revoke_this_device`].
fn self_revocation(broker_url: &str, grant: &Grant) -> anyhow::Result<String> {
    let key = device::open()?.ok_or_else(|| anyhow::anyhow!("no device key to revoke with"))?;
    let nonce = broker::fetch_nonce(broker_url)?;
    device::assertion(&key, &grant.identity, &grant.audience, &nonce, crate::time::now())
}
