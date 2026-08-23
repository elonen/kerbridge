//! `kerbridge` -- cloud identity -> Kerberos NAS SSO, CLI form.
//!
//! Signs in to the cloud IdP in the system browser, exchanges the resulting
//! access token with the KerBridge broker for a real KDC-signed TGT, and puts
//! that TGT in this user's ticket cache. The platform's own SMB client then
//! reaches the file server transparently -- no custom SMB client, no forged tickets, no
//! password.
//!
//! Pipeline:  browser OIDC  ->  broker /ticket  ->  MIT ccache  ->  the OS cache.
//!
//! Every step lives in the library (`lib.rs`), which each platform's agent links
//! too, so this binary is orchestration and console output only. It ships
//! alongside the agent: same capabilities, one shot at a time, visible output --
//! which is what makes it the tool to reach for when something is wrong.

mod cli;

use anyhow::{Result, anyhow, bail};
use clap::Parser;

use cli::grant::{do_grant, do_grant_give_up, do_grant_list, do_grant_revoke, do_grant_status};
#[cfg(windows)]
use cli::host::{do_enroll, do_enroll_status, do_repair, do_unenroll};
use cli::resolve::{obtain_token, pinned_target, resolve_broker};
use cli::signin::{Proof, do_sign_off, granted_injection, inject};
use cli::verify::verify_share;

#[derive(Parser)]
#[command(
    name = "kerbridge",
    about = "Sign in to the cloud IdP and put a broker-issued Kerberos TGT in this user's ticket cache, for passwordless NAS access"
)]
struct Args {
    /// Broker base URL. TLS is required; the certificate is validated against
    /// the OS certificate store. Everything else -- IdP authority, client id,
    /// scopes, realm -- is discovered from the broker. Defaults to the configured
    /// one (`config.toml`, or the machine policy value) so the CLI and the agent
    /// agree without being told.
    #[arg(long)]
    broker: Option<String>,

    /// Skip the browser and use the access token (aud = broker) held in this
    /// file, e.g. one obtained from testbench/entra-tenant/pkce.py. A file rather
    /// than a value: an argument is visible in the process list to anyone on the
    /// machine, and this is a live bearer credential. Mainly for debugging.
    #[arg(long, value_name = "PATH")]
    token_file: Option<std::path::PathBuf>,

    /// After injecting, prove it end to end against this share: read README.txt
    /// and write a stamp file over it through the platform's own SMB client.
    /// Takes the UNC path on Windows (`--verify \\nas.example.site\share`) and a
    /// mount point on macOS (`--verify /Volumes/share`) -- there is no default,
    /// because the share is whatever you joined to the realm.
    #[arg(long, value_name = "UNC")]
    verify: Option<String>,

    /// Keep the session alive by re-injecting every N minutes (0 = one-shot).
    /// Silent refresh is the tray's job; here the same proof is reused, so a run
    /// on an access token lasts no longer than that token -- a run on this
    /// device's grant lasts as long as the grant.
    #[arg(long, default_value_t = 0)]
    renew: u64,

    /// Register the realm with Windows (elevated; `ksetup`). Prints the exact
    /// command batch and asks before running it.
    #[cfg(windows)]
    #[arg(long)]
    enroll: bool,

    /// Show what Windows currently believes about the broker's realm and exit.
    #[cfg(windows)]
    #[arg(long)]
    enroll_status: bool,

    /// Force re-apply the realm registration even if Windows already looks set up
    /// (elevated; `ksetup`). Use when the registration is partial or stale.
    #[cfg(windows)]
    #[arg(long)]
    reenroll: bool,

    /// Remove the realm's registration from Windows (elevated). The inverse of
    /// --enroll; a reboot finishes it.
    #[cfg(windows)]
    #[arg(long)]
    unenroll: bool,

    /// Restart the Workstation service to clear an NTLM fallback (elevated).
    /// Drops every SMB session on this machine.
    #[cfg(windows)]
    #[arg(long)]
    repair: bool,

    /// Drop this realm's tickets from the ticket cache and exit. This
    /// machine's device grant survives -- it is the account the machine works as,
    /// not the session you are leaving; --grant-give-up hands that back.
    #[arg(long)]
    sign_off: bool,

    /// Authorize this machine to obtain tickets without a browser sign-in, for
    /// as long as this deployment allows. Signs in first -- that sign-in is the
    /// authorization -- and the key it makes cannot be copied off this machine.
    /// Run again to replace an existing grant.
    #[arg(long)]
    grant: bool,

    /// Show this machine's device grant: what config.toml names, and whether this
    /// machine still holds the key it names. Offline -- it asks no broker, which
    /// is the point when the broker is what you suspect.
    #[arg(long)]
    grant_status: bool,

    /// List every device authorized on this account. Signs in first: this reads
    /// the whole account, not just this machine.
    #[arg(long)]
    grant_list: bool,

    /// Hand this machine's own device grant back: it goes to a browser sign-in
    /// for every ticket from now on. Needs no sign-in and works offline. Tickets
    /// already in the cache stand -- --sign-off purges those.
    #[arg(long)]
    grant_give_up: bool,

    /// Stop another device, by the id --grant-list prints. Signs in first, so a
    /// compromised machine cannot knock the others offline. For this machine's
    /// own, --grant-give-up.
    #[arg(long, value_name = "ID")]
    grant_revoke: Option<String>,

    /// Ignore this machine's device grant for this run and sign in through the
    /// browser instead -- the way to tell a refused grant from a broken broker.
    /// --token-file implies it.
    #[arg(long)]
    no_grant: bool,

    /// Act on this account instead of your own: --grant authorizes this machine
    /// for it, --grant-list and --grant-revoke read and edit its devices. Takes
    /// a login name or a literal kb1| identity, never a UPN. Needs you to be one
    /// of that account's delegates; without it, "Get tickets as" from the tray's
    /// Settings supplies the default.
    #[arg(long = "for", value_name = "NAME")]
    target: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Repair touches no broker at all, sign-off only needs the realm's name, and
    // grant status is read out of this machine alone, so none of them may be
    // blocked by an unconfigured broker URL. Neither may giving up this device's
    // own grant, which resolves its own broker and works without one. Nor may
    // enrollment *status*, which asks what Windows believes -- a machine with no
    // broker yet is exactly the machine someone is asking that about.
    #[cfg(windows)]
    if args.repair {
        return do_repair();
    }
    #[cfg(windows)]
    if args.enroll_status {
        return do_enroll_status(&args);
    }
    if args.sign_off {
        return do_sign_off(&args);
    }
    #[cfg(windows)]
    if args.unenroll {
        return do_unenroll(&args);
    }
    if args.grant_status {
        return do_grant_status();
    }
    if args.grant_give_up {
        return do_grant_give_up(&args);
    }
    if let Some(id) = &args.grant_revoke {
        return do_grant_revoke(&args, id);
    }

    let mut broker = resolve_broker(&args)?;
    #[cfg(windows)]
    if args.enroll || args.reenroll {
        return do_enroll(&broker, args.reenroll);
    }
    if args.grant {
        return do_grant(&args, &broker);
    }
    if args.grant_list {
        return do_grant_list(&args, &broker);
    }

    let (proof, injected) = match granted_injection(&args, &broker)? {
        Some((proof, injected, base)) => {
            broker = base;
            (proof, injected)
        }
        None => {
            // Nothing left to prove this run with but a sign-in, and on a machine
            // that works as somebody else a sign-in proves the wrong identity:
            // the ticket would be the caller's, and every file written with it
            // theirs. --no-grant is the deliberate way to do that anyway.
            if let Some(target) = pinned_target()
                && !args.no_grant
            {
                bail!(
                    "this machine gets its tickets as {target} and holds no device grant to \
                     prove it with. Run --grant to authorize it again, or --no-grant to sign in \
                     as yourself"
                );
            }
            // The token is a live bearer credential; it is never printed or logged.
            // The exchange goes to the source the sign-in's discovery confirmed,
            // which a URL found in DNS does not name.
            let (base, token) = obtain_token(&args, &broker)?;
            broker = base;
            let proof = Proof::Token(token);
            let injected = inject(&broker, &proof).map_err(|e| anyhow!("injecting a TGT: {e}"))?;
            (proof, injected)
        }
    };
    println!(
        "[kerbridge] injected TGT for {} into this user's ticket cache (no password); \
         valid until {}",
        injected.principal,
        kerbridge_client::time::local_stamp(injected.end)
    );

    if let Some(share) = args.verify.as_deref() {
        verify_share(share, &injected.principal)?;
    }

    if args.renew > 0 {
        let interval = std::time::Duration::from_secs(args.renew * 60);
        println!("[kerbridge] renew mode: re-injecting every {} min (Ctrl+C to stop)", args.renew);
        loop {
            std::thread::sleep(interval);
            match inject(&broker, &proof) {
                Ok(i) => println!("[kerbridge] refreshed TGT for {}", i.principal),
                Err(e) => eprintln!("[kerbridge] refresh failed: {e}"),
            }
        }
    }

    Ok(())
}
