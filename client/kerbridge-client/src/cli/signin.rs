//! The default run: prove an identity, exchange the proof for a TGT, put it in
//! this user's cache. `--sign-off` is its inverse and lives here for that reason.

use anyhow::{Context, Result, anyhow};
use kerbridge_client::broker::BrokerError;
use kerbridge_client::session::{InjectError, Injected};
use kerbridge_client::{config, session};

use super::resolve::resolve_realm;
use crate::Args;

/// What this run proves its identity with. The two are interchangeable
/// downstream -- the broker meets both at the same directory lookup -- so the only
/// thing that varies here is which one the renew loop keeps re-presenting.
pub(crate) enum Proof {
    Grant(config::Grant),
    Token(String),
}

pub(crate) fn inject(broker: &str, proof: &Proof) -> Result<Injected, InjectError> {
    match proof {
        Proof::Grant(grant) => session::inject_with_grant(broker, grant),
        Proof::Token(token) => session::inject(broker, token),
    }
}

/// Use this machine's device grant, when it holds one and this run allows it.
///
/// `None` means fall through to a sign-in: either there is no grant, or the one
/// there is was refused in a way a sign-in fixes. Every other failure stops the
/// run -- falling back on those would open a browser to paper over a broker that
/// is answering perfectly well.
///
/// Which refusals those are is not the status code. Two of the 403s -- the
/// deployment switching the feature off, and this account leaving the
/// device-grant group -- say the grant is finished while the person at the
/// keyboard can still sign in that minute, and in both the operator's intent
/// *is* "use a browser from now on". Treating them as hard stops did not send a
/// machine back to the browser, it locked it out: measured at
/// `DEVICE_GRANT_DAYS=0`, where every granted machine refused to get a ticket at
/// all. The other three 403s stay hard, because nothing the user does helps.
///
/// The base it hands back is the one the exchange used, for the rest of the run
/// to keep re-presenting the grant against.
pub(crate) fn granted_injection(
    args: &Args,
    broker: &str,
) -> Result<Option<(Proof, Injected, String)>> {
    // `--token-file` names a credential outright, and an explicit one beats a
    // stored one; without it a granted machine could not be given a token at all.
    if args.no_grant || args.token_file.is_some() {
        if args.no_grant {
            warn_ticket_is_yours();
        }
        return Ok(None);
    }
    let Some(grant) = config::Settings::load().grant().cloned() else {
        return Ok(None);
    };

    println!(
        "[kerbridge] this device holds grant {}; proving it with the TPM key instead of \
         signing in (--no-grant to sign in anyway)",
        grant.grant_id
    );
    // Not `discover`: a granted machine must reach a ticket with the IdP down.
    let broker = kerbridge_client::discovery::source_base(broker)
        .context("asking the broker which source this address reaches")?;
    match session::inject_with_grant(&broker, &grant) {
        Ok(injected) => {
            record_grant_principal(&injected.principal);
            Ok(Some((Proof::Grant(grant), injected, broker)))
        }
        // Expired, clamped, revoked, or the key is gone. All four are the same
        // answer to the person at the keyboard, and it is the browser.
        Err(InjectError::Broker(BrokerError::InvalidProof(why))) => {
            println!("[kerbridge] the grant was refused ({why}); signing in instead");
            Ok(None)
        }
        // Kept in `config.toml`, not discarded: both of these are reversible by
        // the operator, and a grant put back in the group works again untouched.
        Err(InjectError::Broker(BrokerError::NotAdmitted(why)))
            if why == kerbridge_client::broker::REFUSED_GRANTS_DISABLED
                || why == kerbridge_client::broker::REFUSED_NOT_GRANTED =>
        {
            println!(
                "[kerbridge] this device's grant is no longer accepted ({why}); signing in instead"
            );
            Ok(None)
        }
        Err(e) => Err(anyhow!("injecting a TGT with this device's grant: {e}")),
    }
}

/// Say what a `--no-grant` run costs, on a machine where it costs something.
///
/// The ticket this run injects is the caller's, so anything written with it is
/// owned by them and not by the account the machine works as -- which is
/// invisible until somebody reads a Security tab weeks later. And it does not
/// last: the tray re-injects from the grant at its next cycle.
fn warn_ticket_is_yours() {
    let settings = config::Settings::load();
    let Some(target) = settings
        .grant()
        .and_then(|g| g.principal.clone())
        .or_else(|| settings.grant_for().map(str::to_owned))
    else {
        return;
    };
    println!(
        "[kerbridge] --no-grant: the ticket this injects is YOURS, not {target}'s. Files written \
         with it are owned by you, and the tray re-injects as {target} at its next cycle."
    );
}

/// Remember what the grant just worked as, so a later run -- and the tray's
/// startup -- can tell this machine's own ticket from anybody else's.
fn record_grant_principal(principal: &str) {
    let mut settings = config::Settings::load();
    if settings.set_grant_principal(principal)
        && let Err(e) = settings.save()
    {
        eprintln!("[kerbridge] could not record what the grant works as: {e:#}");
    }
}

/// Purge the realm's tickets. The device grant survives, as it does in the tray.
///
/// Uses the cached realm name so it works offline -- the point of signing off is
/// that it works when nothing else does. The grant is the account this machine
/// works *as*, which somebody -- possibly somebody else -- authorized it for;
/// giving it up is `--grant-give-up`, asked for by name.
pub(crate) fn do_sign_off(args: &Args) -> Result<()> {
    let realm = resolve_realm(args)?;
    let n = session::sign_off(&realm)?;
    println!("[kerbridge] purged {n} ticket(s) for {realm}");
    Ok(())
}
