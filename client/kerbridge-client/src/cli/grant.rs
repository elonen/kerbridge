//! `--grant*`: authorize this machine to get tickets without a browser, and
//! read or stop what is authorized.

use anyhow::{Context, Result, anyhow, bail};
use kerbridge_client::broker::{AuthScheme, BrokerError};
use kerbridge_client::{config, device, discovery, session};

use super::resolve::{obtain_token, resolve_broker, resolve_target};
use crate::Args;

/// Authorize this machine to obtain tickets without a browser sign-in.
///
/// The sign-in *is* the authorization: the broker records the key against an
/// account it has just confirmed is admitted and allowed to hold grants. Nothing
/// here decides anything of its own, which is why there is no confirmation
/// prompt and no elevation -- the key is user-scoped.
///
/// With a target it authorizes the machine for *that* account, and the broker
/// additionally requires the signer to be one of its delegates. The ticket this
/// machine later obtains is then the target's; this run gets none at all.
pub(crate) fn do_grant(args: &Args, broker: &str) -> Result<()> {
    let target = resolve_target(args)?;
    let config = discovery::discover(broker).context("discovering the broker's grant policy")?;
    // The registration below goes to the source the broker confirmed, which a
    // URL found in DNS does not name.
    let broker = config.base_url.as_str();
    // Refused here rather than at registration so the user is not sent through a
    // browser to be turned away afterwards.
    if !config.device_grant.enabled() {
        bail!("this deployment does not offer device grants (DEVICE_GRANT_DAYS is 0)");
    }
    if let Some(existing) = config::Settings::load().grant().cloned() {
        // Says "renewing" because the key stays and the id with it. This used to
        // warn that the key went at once, which was true then and is a promise
        // worth not breaking quietly: a refused renewal now leaves the grant
        // below exactly as it was.
        println!(
            "[kerbridge] renewing grant {} -- the same key, so the id does not change",
            existing.grant_id
        );
    }

    if let Some(target) = &target {
        println!("[kerbridge] authorizing this device for {target}, not for you");
    }

    let (broker, token) = obtain_token(args, broker)?;
    let grant = session::create_grant(
        &broker,
        &token,
        &config.device_grant.audience,
        target.as_deref(),
    )
    .map_err(|e| match &e {
        // The sign-in above worked and this account is admitted; what is missing
        // is membership of a group on the *target*, which only somebody else can
        // fix. Naming it here saves the reader deducing it from a 403 reason.
        session::GrantError::Broker(BrokerError::NotAdmitted(why))
            if why == kerbridge_client::broker::REFUSED_NOT_DELEGATE =>
        {
            anyhow!(
                "authorizing this device: {e}. You are signed in and admitted -- someone has to \
                 add you to that account's delegate group; signing in again will not help"
            )
        }
        _ => anyhow!("authorizing this device: {e}"),
    })?;
    println!(
        "[kerbridge] this device is authorized as grant {}; it needs a browser sign-in again by {}",
        grant.grant_id,
        kerbridge_client::time::local_stamp(grant.sign_in_required_by)
    );
    // The broker's word for whose grant this is, and the only place a delegated
    // run learns it: the caller presented their own token and never spelled it.
    println!("  identity  {}", grant.identity);

    // Loaded after the sign-in, never before: `obtain_token` saves the realm it
    // discovered, and a copy read earlier would write that back out stale.
    let mut settings = config::Settings::load();
    settings.set_grant(Some(grant));
    settings.save().context("recording the device grant in config.toml")?;
    println!("[kerbridge] the tray uses it too -- both read the same config.toml");
    Ok(())
}

/// What this machine holds, from `config.toml` and the TPM alone.
///
/// Deliberately offline. The states worth diagnosing are the two halves
/// disagreeing -- a grant the file names whose key the TPM no longer holds (a
/// rebuilt profile, a cleared TPM, a give-up that did not finish writing), or a
/// key no grant names -- and no broker can be asked about either.
pub(crate) fn do_grant_status() -> Result<()> {
    let settings = config::Settings::load();
    let key = device::open();
    let held = matches!(key, Ok(Some(_)));

    match settings.grant() {
        Some(grant) => {
            println!("[kerbridge] this device holds device grant {}", grant.grant_id);
            println!("  identity             {}", grant.identity);
            println!(
                "  works as             {}",
                grant.principal.as_deref().unwrap_or("not yet known -- no exchange has run yet")
            );
            println!("  audience             {}", grant.audience);
            println!(
                "  sign-in required by  {} ({})",
                kerbridge_client::time::local_stamp(grant.sign_in_required_by),
                remaining(grant.sign_in_required_by)
            );
        }
        None => println!(
            "[kerbridge] this device holds no device grant; every ticket costs a browser sign-in"
        ),
    }
    // Beside the grant, because this is the only place the two are visible
    // together and they are allowed to disagree: the pin decides who the *next*
    // authorization names and nothing else, ever. A machine holding a grant for
    // one account keeps working as that account whatever the pin says.
    println!("  authorizes for       {}", settings.grant_for().unwrap_or("whoever authorizes it"));

    match &key {
        Ok(Some(_)) => println!("  TPM key              present"),
        Ok(None) => println!("  TPM key              absent"),
        // Not a failure of this command: a machine with no usable TPM cannot hold
        // a grant, and saying so is the answer the caller came for.
        Err(e) => println!("  TPM key              unreadable ({e:#})"),
    }

    match (settings.grant().is_some(), held) {
        (true, false) => println!(
            "\n[kerbridge] the grant names a key this machine no longer has, so the next ticket \
             needs a browser sign-in. --grant authorizes this device again."
        ),
        (false, true) => println!(
            "\n[kerbridge] a device key is left over with no grant naming it. It authorizes \
             nothing; --grant replaces it, --grant-give-up removes it."
        ),
        (false, false) => {
            println!("\n[kerbridge] --grant authorizes this device, if the deployment allows it.")
        }
        (true, true) => {}
    }

    // Stated rather than judged. The two lines above are allowed to name
    // different accounts, and the machine is not broken when they do -- it keeps
    // working as the grant it holds and migrates by itself the next time
    // somebody authorizes it, when a human is at the keyboard anyway.
    if settings.grant().is_some() && settings.grant_for().is_some() {
        println!(
            "\n[kerbridge] the pin decides only who the next authorization names; this machine \
             keeps working as the grant above until --grant is run again."
        );
    }
    Ok(())
}

/// How long until a deadline, in whole days -- the unit the operator set it in.
fn remaining(deadline: i64) -> String {
    let days = (deadline - kerbridge_client::time::now()) / 86_400;
    match days {
        d if d < 0 => "overdue".into(),
        0 => "today".into(),
        1 => "in 1 day".into(),
        d => format!("in {d} days"),
    }
}

/// Every device on this account, as the broker sees it. The same view
/// `kbmanage device list` gives an operator, asked for with the user's own
/// sign-in -- so a user can audit their own machines without one.
pub(crate) fn do_grant_list(args: &Args, broker: &str) -> Result<()> {
    let target = resolve_target(args)?;
    let whose = target.clone().unwrap_or_else(|| "this account".to_owned());
    let mine = config::Settings::load().grant().map(|g| g.grant_id.clone());
    let (broker, token) = obtain_token(args, broker)?;
    let devices = kerbridge_client::broker::list_devices(&broker, &token, target.as_deref())
        .map_err(|e| anyhow!("listing {whose}'s devices: {e}"))?;

    if devices.is_empty() {
        println!("[kerbridge] no device authorized for {whose}");
        return Ok(());
    }
    println!("[kerbridge] devices authorized for {whose}:");
    for d in &devices {
        // The id leads because it is what a revocation takes: the label is
        // whatever the machine called itself and two machines can claim the same
        // one, while the id is derived from the key and cannot be.
        let this =
            if mine.as_deref() == Some(d.grant_id.as_str()) { "  <- this device" } else { "" };
        println!("  {}  {}{}", d.grant_id, d.label, this);
        println!(
            "    sign-in required by  {} ({}){}",
            kerbridge_client::time::local_stamp(d.sign_in_required_by),
            remaining(d.sign_in_required_by),
            if d.clamped { ", clamped by the current setting" } else { "" }
        );
        println!(
            "    added {}, {}",
            kerbridge_client::time::local_stamp(d.added),
            match d.last_seen {
                // Day-granular by construction, so it answers one question: is
                // this device dead wood.
                Some(seen) => format!("last used {}", kerbridge_client::time::local_stamp(seen)),
                None => "never used".to_owned(),
            }
        );
    }
    println!("\n[kerbridge] --grant-revoke <id> stops one of them");
    Ok(())
}

/// Give up this machine's own device grant.
///
/// The key goes first and the broker is told after -- see
/// [`session::revoke_this_device`] -- so this works offline: leaving is not an
/// attack, and it has to work when nothing else does. Needs no sign-in for the
/// same reason.
pub(crate) fn do_grant_give_up(args: &Args) -> Result<()> {
    let mut settings = config::Settings::load();
    let Some(grant) = settings.grant().cloned() else {
        println!("[kerbridge] this device holds no device grant to give up");
        return Ok(());
    };
    let told = session::revoke_this_device(resolve_broker(args).ok().as_deref(), &grant);
    settings.set_grant(None);
    settings.save().context("forgetting the device grant in config.toml")?;
    println!("[kerbridge] gave up this machine's device grant {}", grant.grant_id);
    if !told {
        println!(
            "[kerbridge] the broker was not told (see the log); the key it names is gone, so the \
             grant is already dead"
        );
    }
    println!("[kerbridge] tickets already in this logon session stand -- --sign-off purges them");
    Ok(())
}

/// Stop one device, named by id.
///
/// This machine's own is [`do_grant_give_up`] under another name, and keeps
/// working for an operator who reaches for the id. Any other device needs a
/// sign-in, so a compromised machine cannot knock the rest of the account
/// offline.
pub(crate) fn do_grant_revoke(args: &Args, id: &str) -> Result<()> {
    let target = resolve_target(args)?;
    // Only when the id really is this machine's *and* nothing else was named: a
    // `--for` here says "one of that account's other devices", and the offline
    // path cannot serve it -- an assertion may name no account but its own.
    if args.target.is_none() && config::Settings::load().grant().is_some_and(|g| g.grant_id == id) {
        return do_grant_give_up(args);
    }

    let broker = resolve_broker(args)?;
    let (broker, token) = obtain_token(args, &broker)?;
    kerbridge_client::broker::revoke_device(
        &broker,
        AuthScheme::Bearer(&token),
        id,
        target.as_deref(),
    )
    .map_err(|e| anyhow!("revoking device {id}: {e}"))?;
    println!("[kerbridge] revoked device grant {id}");
    Ok(())
}
