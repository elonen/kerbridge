//! `kbmanage` -- the operator CLI over `kerbridge_manage`.
//!
//! Everything a human sees is here. The library never prints, never prompts and
//! never reads a terminal, so a GUI could link it and render the same data
//! differently.

#![forbid(unsafe_code)]

mod cli;

use std::io::{IsTerminal, Write};

use anyhow::{Context, Result, bail};
use clap::Parser;
use kerbridge_core::state::{
    GROUP_TYPE_DOMAIN_LOCAL_SECURITY, ROLE_ADMISSION, ROLE_DELEGATES, ST_NAME_PINNED,
};
use kerbridge_core::time::{now_unix as now, rfc3339};
use kerbridge_manage::directory::probe;
use kerbridge_manage::doctor::{self, Reachable, Status};
use kerbridge_manage::model::{Kind, Snapshot, State, TrustAnchor};
use kerbridge_manage::validate::{
    Arg, assert_argument_order, assert_inside_cloud_idp, assert_is_group, assert_is_user,
    assert_outside_cloud_idp, assert_within_resource_ou, check_group_name, check_login_name,
    delegate_links_to_clear, dn_equals, dn_is_at_or_within,
};
use kerbridge_manage::{Config, Directory, Overrides};

use crate::cli::{Cli, CloudCmd, Command, DelegateCmd, DeviceCmd, GroupCmd, MemberCmd};

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("kbmanage: {e:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    // Before the config set is even looked for: this verb is given everything it
    // needs on the command line, and the hosts that run it are a CI job with no
    // `kbmanage.toml` and a deployment whose stack is still coming up. Loading a
    // set first would make a readiness probe fail for the one reason readiness
    // has nothing to do with.
    if let Command::Endpoint { url, resolve, ca_file, any_cert, timeout } = &cli.command {
        let request = kerbridge_manage::endpoint::Request {
            base: url.clone(),
            via: resolve.clone(),
            anchor: match ca_file {
                Some(path) => TrustAnchor::Ca(path.clone()),
                None => TrustAnchor::Public,
            },
            any_cert: *any_cert,
            timeout: std::time::Duration::from_secs(*timeout),
        };
        let report = doctor::diagnose_endpoint(&kerbridge_manage::endpoint::probe(&request)?);
        Renderer { json: cli.json, yes: cli.yes }.endpoint_line(&report);
        std::process::exit(match report.verdict {
            Reachable::Serving => 0,
            Reachable::Broken => 1,
            Reachable::Settling => 2,
            Reachable::NoSession => 3,
        });
    }

    let cfg = Config::load(&Overrides {
        config: cli.conn.config.clone(),
        url: cli.conn.url.clone(),
        base_dn: cli.conn.base_dn.clone(),
        resource_ou: cli.conn.resource_ou.clone(),
        bind_dn: cli.conn.bind_dn.clone(),
        password_file: cli.conn.password_file.clone(),
        ca_file: cli.conn.ca_file.clone(),
    })?;
    for warning in &cfg.warnings {
        eprintln!("kbmanage: warning: {warning}");
    }

    // Before connecting, because its whole purpose is to be answerable when
    // connecting is what fails.
    if matches!(cli.command, Command::Config) {
        Renderer { json: cli.json, yes: cli.yes }.config(&cfg);
        return Ok(());
    }

    let out = Renderer { json: cli.json, yes: cli.yes };

    // The connectivity preflight, before the connection it diagnoses. `doctor`
    // promises to walk a chain and name the broken link, but until this ran its
    // first link was a snapshot -- which is to say a bind that had already
    // succeeded. On a host that is not the DC that is the half that breaks, and
    // a stale realm CA surfaced as an `ldap3` TLS error naming nothing.
    if let Command::Doctor { endpoint, .. } = &cli.command {
        let reach = doctor::diagnose_reach(&probe(&cfg).await);
        out.reach(&reach);
        let mut broken = reach.worst() == Status::Fail;
        // The other direction, and it is asked whether or not the directory
        // answered: an endpoint that is down is down for reasons of its own, and
        // a report that stopped at the first chain would hide the second.
        if let Some(url) = endpoint {
            let request = kerbridge_manage::endpoint::Request {
                base: url.clone(),
                via: None,
                anchor: TrustAnchor::Public,
                // Said rather than judged. Whether a certificate the public
                // roots reject is a fault depends on the TLS strategy, which
                // lives in the deployment's own ingress and not in the config
                // set this reads -- `kbmanage endpoint` is where a readiness
                // gate makes that call.
                any_cert: true,
                timeout: cfg.timeout,
            };
            let report = doctor::diagnose_endpoint(&kerbridge_manage::endpoint::probe(&request)?);
            out.endpoint(&report);
            // The status, not the verdict: `Reachable` exists for a poll loop,
            // and this is the one-shot diagnosis whose rule is already written
            // -- `Fail` exits non-zero, `Warn` means working and not as
            // designed.
            broken |= report.worst() == Status::Fail;
        }
        if broken {
            bail!("doctor found a broken link (see FAIL above)")
        }
    }

    let dir = Directory::new(&cfg)?;
    let mut ldap = dir.connect().await?;

    let result = match &cli.command {
        Command::Group(cmd) => group(&dir, &mut ldap, &cfg, &out, cmd).await,
        Command::Cloud(cmd) => cloud(&dir, &mut ldap, &cfg, &out, cmd).await,
        Command::Device(cmd) => device(&dir, &mut ldap, &cfg, &out, cmd).await,
        Command::Doctor { user, .. } => {
            let snap = dir.snapshot(&mut ldap, now()).await?;
            let failed = match user {
                Some(subject) => {
                    let report = doctor::diagnose_user(&snap, subject);
                    out.user_report(&report);
                    report.worst() == doctor::Status::Fail
                }
                None => {
                    let findings = doctor::sweep(&snap);
                    out.sweep(&snap, &findings);
                    findings.iter().any(|f| f.status == doctor::Status::Fail)
                }
            };
            // A verdict nothing can act on is half a diagnosis. This is the
            // first thing SETUP.md tells an operator to run, so it is also what
            // a cron check or a monitoring agent reads -- and printing FAIL
            // while exiting 0 tells anything reading `$?` that the realm is
            // healthy. `Warn` deliberately still exits 0: it means working, but
            // not as designed.
            if failed {
                bail!("doctor found a broken link (see FAIL above)")
            }
            Ok(())
        }
        Command::Config | Command::Endpoint { .. } => {
            unreachable!("handled before connecting")
        }
    };
    let _ = ldap.unbind().await;
    result
}

/// A resolved entry's `objectClass` chain. Empty if the directory returned none,
/// which the guard treats as "not a group" rather than as "unknown".
fn object_classes(entry: &ldap3::SearchEntry) -> &[String] {
    entry.attrs.get("objectClass").map_or(&[], |v| &v[..])
}

/// A resolved entry's `extensionName` values: role and state markers, and any
/// device grant.
fn markers_of(entry: &ldap3::SearchEntry) -> &[String] {
    entry.attrs.get("extensionName").map_or(&[], |v| &v[..])
}

/// The resolved object's own `sAMAccountName`, for the confirmation prompt.
///
/// Deliberately not the string the operator typed: they will type that again
/// without reading it, which is the one thing the prompt exists to prevent. The
/// DN is the fallback because an object with no `sAMAccountName` still has to be
/// confirmable, and by then the operator has seen it on the DESTROYING line.
fn resolved_name(entry: &ldap3::SearchEntry) -> &str {
    entry
        .attrs
        .get("sAMAccountName")
        .and_then(|v| v.first())
        .map_or(entry.dn.as_str(), String::as_str)
}

async fn group(
    dir: &Directory,
    ldap: &mut ldap3::Ldap,
    cfg: &Config,
    out: &Renderer,
    cmd: &GroupCmd,
) -> Result<()> {
    match cmd {
        GroupCmd::List => {
            let snap = dir.snapshot(ldap, now()).await?;
            out.group_list(&snap);
        }
        GroupCmd::New { name } => {
            check_group_name(name)?;
            let dn = format!("CN={name},{}", cfg.resource_ou);
            assert_outside_cloud_idp(&dn, &cfg.cloud_idp_ou)?;
            assert_within_resource_ou(&dn, &cfg.resource_ou)?;
            dir.create_group(ldap, &dn, name, GROUP_TYPE_DOMAIN_LOCAL_SECURITY).await?;
            out.done(format!("created {dn} (domain-local security)"));
        }
        GroupCmd::Member(cmd) => member(dir, ldap, cfg, out, cmd).await?,
        GroupCmd::Delete { name } => {
            let entry = dir.resolve(ldap, name).await?;
            // The same three the create verb applies, in the order that gives the
            // most useful refusal: whose object it is, what kind of object it is,
            // then whether this tool is delegated on it at all.
            assert_outside_cloud_idp(&entry.dn, &cfg.cloud_idp_ou)?;
            assert_is_group(&entry.dn, object_classes(&entry))?;
            assert_within_resource_ou(&entry.dn, &cfg.resource_ou)?;
            let sid = kerbridge_core::decode_sid_attr(
                entry.bin_attrs.get("objectSid").map(|v| &v[..]),
                entry.attrs.get("objectSid").map(|v| &v[..]),
            );
            out.confirm_destroying(
                &entry.dn,
                resolved_name(&entry),
                &[
                    format!(
                        "{} is what your filesystem ACLs are keyed to. Deleting the group \
                         does not remove those ACEs -- it strands them.",
                        sid.as_deref().unwrap_or("Its SID")
                    ),
                    "Every file server derives its gid from that SID under idmap_rid. \
                     A recreated group with the same name gets a different SID, a different \
                     gid, and authorizes nobody the old one authorized."
                        .to_owned(),
                    "There is no undo. Restoring means restoring the directory.".to_owned(),
                ],
            )?;
            dir.delete(ldap, &entry.dn).await?;
            out.done(format!("deleted {}", entry.dn));
        }
        GroupCmd::Rename { old, new } => {
            check_group_name(new)?;
            let entry = dir.resolve(ldap, old).await?;
            assert_outside_cloud_idp(&entry.dn, &cfg.cloud_idp_ou)?;
            assert_is_group(&entry.dn, object_classes(&entry))?;
            assert_within_resource_ou(&entry.dn, &cfg.resource_ou)?;
            let new_dn = dir.rename(ldap, &entry.dn, new, new).await?;
            out.done(format!(
                "renamed to {new_dn}\n\
                 The SID is unchanged, so filesystem ACLs still match. What may now deny \
                 everyone is name-based matching on the file server: `valid users = @\"DOMAIN\\{old}\"` \
                 matches the sAMAccountName, which just moved. This tool does not go looking \
                 for those; update them where you keep them.",
            ));
        }
    }
    Ok(())
}

/// Membership of a resource group: the nesting that is the authorization model.
async fn member(
    dir: &Directory,
    ldap: &mut ldap3::Ldap,
    cfg: &Config,
    out: &Renderer,
    cmd: &MemberCmd,
) -> Result<()> {
    // Anything can be nested -- a synced group, a person, another resource
    // group -- so the second position rules nothing out and the only reversal
    // there is to catch is the one that matters: a resource group named as the
    // member by a script that kept `group nest`'s order.
    let resource = |e: &ldap3::SearchEntry| {
        assert_is_group(&e.dn, object_classes(e)).is_ok()
            && assert_outside_cloud_idp(&e.dn, &cfg.cloud_idp_ou).is_ok()
    };
    let order = |verb, group: (&str, &ldap3::SearchEntry), other: (&str, &ldap3::SearchEntry)| {
        assert_argument_order(
            verb,
            "resource group",
            Arg { given: group.0, fits_first: resource(group.1), fits_second: true },
            Arg { given: other.0, fits_first: resource(other.1), fits_second: true },
        )
    };
    match cmd {
        MemberCmd::Add { target_group, new_member } => {
            let group = dir.resolve(ldap, target_group).await?;
            let member = dir.resolve(ldap, new_member).await?;
            order("group member add", (target_group, &group), (new_member, &member))?;
            assert_is_group(&group.dn, object_classes(&group))?;
            assert_outside_cloud_idp(&group.dn, &cfg.cloud_idp_ou)?;
            dir.add_member(ldap, &group.dn, &member.dn).await?;
            out.done(format!("{} is now a member of {}", member.dn, group.dn));
        }
        MemberCmd::Remove { target_group, old_member } => {
            let group = dir.resolve(ldap, target_group).await?;
            let member = dir.resolve(ldap, old_member).await?;
            order("group member remove", (target_group, &group), (old_member, &member))?;
            assert_is_group(&group.dn, object_classes(&group))?;
            assert_outside_cloud_idp(&group.dn, &cfg.cloud_idp_ou)?;
            dir.remove_member(ldap, &group.dn, &member.dn).await?;
            out.done(format!(
                "{} is no longer a member of {}.\n\
                 This bites at the next service ticket, not now: a ticket already issued \
                 carries the old group list in its PAC until it expires.",
                member.dn, group.dn
            ));
        }
        MemberCmd::List { target_group } => {
            let group = dir.resolve(ldap, target_group).await?;
            assert_is_group(&group.dn, object_classes(&group))?;
            let members = group.attrs.get("member").cloned().unwrap_or_default();
            let snap = dir.snapshot(ldap, now()).await?;
            out.member_list(&snap, &group.dn, &members);
        }
    }
    Ok(())
}

async fn cloud(
    dir: &Directory,
    ldap: &mut ldap3::Ldap,
    cfg: &Config,
    out: &Renderer,
    cmd: &CloudCmd,
) -> Result<()> {
    match cmd {
        CloudCmd::List { kind } => {
            let want = match kind.as_deref() {
                None | Some("all") => None,
                Some("users") | Some("user") => Some(Kind::User),
                Some("groups") | Some("group") => Some(Kind::Group),
                Some(other) => bail!("{other:?} is not `users` or `groups`"),
            };
            let snap = dir.snapshot(ldap, now()).await?;
            out.cloud_list(&snap, want);
        }
        CloudCmd::Show { name } => {
            let snap = dir.snapshot(ldap, now()).await?;
            let entry = dir.resolve(ldap, name).await?;
            let Some(obj) = snap.find_cloud(&entry.dn) else {
                bail!("{} is not under {}", entry.dn, cfg.cloud_idp_ou);
            };
            out.cloud_show(&snap, obj);
        }
        CloudCmd::Delete { name } => {
            let snap = dir.snapshot(ldap, now()).await?;
            let entry = dir.resolve(ldap, name).await?;
            assert_inside_cloud_idp(&entry.dn, &cfg.cloud_idp_ou)?;
            let obj = snap
                .find_cloud(&entry.dn)
                .with_context(|| format!("{} was not in the snapshot", entry.dn))?;

            // The admission group is not an object like the others: deleting it stops
            // issuance realm-wide, and DESIGN says freeze and alert, never
            // auto-recreate. Typing a name back is not enough signal for that.
            if obj.is_admission_group() {
                bail!(
                    "{} carries the {ROLE_ADMISSION} marker: it is the realm-admission group.\n\
                     Deleting it stops the broker issuing tickets for anyone, and it cannot be \
                     restored -- a recreated group has a new SID, and sync will not recreate it \
                     on its own (it freezes and alerts instead).\n\
                     If you genuinely mean to retire the realm's admission group, do it on the \
                     DC with samba-tool, deliberately and with a backup.",
                    obj.sam
                );
            }

            let mut consequences = vec![
                format!(
                    "{} is what durable filesystem ACLs hold and what every file server \
                     derives a uid or gid from under idmap_rid. Deleting this object strands \
                     every ACE naming it, on every server, silently until someone opens a \
                     folder.",
                    obj.sid.as_deref().unwrap_or("Its SID")
                ),
                "This is not how objects are meant to leave. Sync retires them: disabled, \
                 renamed out of the live namespace, and held with the SID intact so a \
                 returning identity comes back to their own files. Deleting throws that away."
                    .to_owned(),
                "There is no undo, and sync will not recreate it: to sync, this object \
                 simply no longer exists."
                    .to_owned(),
            ];
            if obj.state() == State::Live {
                consequences.push(
                    "This object is LIVE -- sync still sees it in the cloud IdP, and will create a \
                     replacement on the next cycle, with a new SID. You are not removing an \
                     identity here, you are giving it new numbers."
                        .to_owned(),
                );
            } else if let Some(days) = obj.held_days(snap.now) {
                consequences.push(format!(
                    "Held for {days} days. However long that is, it is not permission: a \
                     returning employee is no cheaper to break on day 400 than on day 4."
                ));
            }
            out.confirm_destroying(&entry.dn, &obj.sam, &consequences)?;
            dir.delete(ldap, &entry.dn).await?;
            out.done(format!("deleted {}", entry.dn));
        }

        CloudCmd::Unpin { name } => {
            let snap = dir.snapshot(ldap, now()).await?;
            let entry = dir.resolve(ldap, name).await?;
            assert_inside_cloud_idp(&entry.dn, &cfg.cloud_idp_ou)?;
            let obj = snap
                .find_cloud(&entry.dn)
                .with_context(|| format!("{} was not in the snapshot", entry.dn))?;

            let pins: Vec<String> =
                obj.markers.iter().filter(|m| m.starts_with(ST_NAME_PINNED)).cloned().collect();
            if pins.is_empty() {
                out.done(format!("{} is not pinned; nothing to hand back", obj.sam));
                return Ok(());
            }
            dir.clear_markers(ldap, &entry.dn, &pins).await?;
            out.done(format!(
                "{} unpinned. If sync.toml's automatic_sam_renames is on, the next cycle derives \
                 the name from the cloud IdP display name again and may rename this account -- \
                 which \
                 signs the user out once.",
                obj.sam
            ));
        }

        // The one update this tool makes inside an IdP-specific OU, and it is safe for a
        // specific reason: sync allocates a sAMAccountName once, at creation,
        // and never recomputes it for a live account -- its only rename of a
        // live object moves the CN and displayName and carries no sam at all.
        // So there is no reconciliation to race here; the new name stands.
        //
        // It exists because the login name is not an internal key. It is what
        // Windows shows as the file owner and in the Security pane, so it can be
        // wrong -- a typo, or a person whose name has changed -- and "we cannot
        // fix that" is a worse answer than a signed-out session.
        CloudCmd::Rename { name, to } => {
            let snap = dir.snapshot(ldap, now()).await?;
            let entry = dir.resolve(ldap, name).await?;
            assert_inside_cloud_idp(&entry.dn, &cfg.cloud_idp_ou)?;
            let obj = snap
                .find_cloud(&entry.dn)
                .with_context(|| format!("{} was not in the snapshot", entry.dn))?;

            if obj.kind != Kind::User {
                bail!(
                    "{} is a group. This renames a person's login name; a group's name comes \
                     from its cloud IdP displayName and sync rewrites it on the next cycle.",
                    obj.sam
                );
            }
            if obj.state() != State::Live {
                bail!(
                    "{} is not live -- it is held in retention as {}. Renaming it would move it \
                     out of the namespace sync reads as retired, and sync would then see an \
                     account it has no record of retiring.\n\
                     If this identity is back in the cloud IdP, put it back in the admission group and \
                     let a cycle reinstate it; that restores the name too.",
                    obj.sam,
                    obj.sam
                );
            }
            check_login_name(to)?;

            // Keep the realm suffix the account already carries rather than
            // rebuilding it: this tool is not told what the realm is called.
            let suffix = obj
                .upn
                .as_deref()
                .and_then(|u| u.split_once('@'))
                .map(|(_, s)| s.to_owned())
                .with_context(|| {
                    format!("{} has no userPrincipalName to take a realm suffix from", obj.sam)
                })?;
            let new_upn = format!("{to}@{suffix}");

            if *to == obj.sam {
                out.done(format!("{} already carries that name; nothing to do", obj.sam));
                return Ok(());
            }
            if let Some(held) = dir.holder_of_name(ldap, to, &new_upn, &entry.dn).await? {
                bail!(
                    "{to} is already taken, by {held}. Account names are one namespace shared by \
                     users and groups, and the directory enforces it on the UPN as well."
                );
            }

            out.confirm_destroying(
                &entry.dn,
                &obj.sam,
                &[
                    format!(
                        "{} is this account's Kerberos principal. Every ticket already issued \
                         names the old one, so they stop working the moment this lands: the user \
                         signs out and back in, or purges and re-injects.",
                        obj.upn.as_deref().unwrap_or(&obj.sam)
                    ),
                    "Filesystem ACLs are unaffected -- they hold the SID, which does not move. \
                     Anything keyed to the *name*, though, does not follow: shares that name it, \
                     scripts, and logs written before today."
                        .to_owned(),
                    "Sync will not revert this and will not repeat it: it derives a login name \
                     once, at creation. Should this account ever be retired and reinstated, the \
                     name is derived again from the display name, and this edit is lost."
                        .to_owned(),
                ],
            )?;
            let pin = format!("{ST_NAME_PINNED}{}", rfc3339(now() as u32));
            dir.set_login_name(ldap, &entry.dn, to, &new_upn, &pin).await?;
            out.done(format!(
                "{} is now {to} ({new_upn}), and pinned: sync will not recompute it from the \
                 cloud IdP display name. `kbmanage cloud unpin {to}` hands it back.",
                obj.sam
            ));
        }
    }
    Ok(())
}

/// Device grants.
///
/// Deleting a grant value is the one write here that is not a resource-group
/// edit, and it needs no new delegation: `svc-kerbridge-manage` already holds
/// per-attribute `WP` on `extensionName` inside the IdP parent OU
/// (`kbsetup directory`). It also only ever *deletes* whole
/// values, which preserves the single-writer invariant -- `issuerd` is the one
/// thing that emits a `kbkey1|` value, and a second emitter could silently drop
/// a key it did not understand.
async fn device(
    dir: &Directory,
    ldap: &mut ldap3::Ldap,
    cfg: &Config,
    out: &Renderer,
    cmd: &DeviceCmd,
) -> Result<()> {
    match cmd {
        DeviceCmd::Delegate(cmd) => return delegate(dir, ldap, cfg, out, cmd).await,
        DeviceCmd::List { user } => {
            let only = match user {
                Some(name) => Some(dir.resolve(ldap, name).await?.dn),
                None => None,
            };
            let snap = dir.snapshot(ldap, now()).await?;
            out.device_list(&snap, only.as_deref());
        }
        DeviceCmd::Revoke { id } => {
            let snap = dir.snapshot(ldap, now()).await?;
            let (obj, raw, grant) = snap.find_device(id).with_context(|| {
                format!("no device grant with id {id}. `kbmanage device list` shows them")
            })?;
            // Confirmed by the typed id and not by the label, for the same
            // reason the id is the selector: the label is whatever the machine
            // said it was, and `BUILD01  (revoked)` must not be able to read as
            // a status column.
            out.confirm_destroying(
                &obj.dn,
                id,
                &[
                    format!(
                        "{} loses its authorization to obtain tickets without a browser sign-in. \
                     Label as recorded by the machine: {:?}.",
                        obj.sam, grant.label
                    ),
                    "It stops at its next ticket exchange, not now: a ticket already issued stays \
                 valid until it expires, exactly like every other revocation lever."
                        .to_owned(),
                    "The key stays on that machine. Someone signing in there through the browser \
                 authorizes it again -- remove the user from the device-grant group to stop \
                 that too."
                        .to_owned(),
                ],
            )?;
            dir.clear_markers(ldap, &obj.dn, std::slice::from_ref(&raw.to_owned())).await?;
            out.done(format!("revoked {id} on {}", obj.sam));
        }
    }
    Ok(())
}

/// Delegated device grants: a group whose members may authorize a machine to
/// obtain tickets as somebody else, without ever holding that account's
/// credentials.
///
/// The link is `managedBy` on a resource group plus the [`ROLE_DELEGATES`]
/// marker. Both are inside the blanket write `svc-kerbridge-manage` already holds on
/// the resource OU, so none of this needs a delegation of its own.
///
/// `set` is the one verb here that writes an object the operator did not name,
/// so every verb prints what it changed at the directory, by DN.
async fn delegate(
    dir: &Directory,
    ldap: &mut ldap3::Ldap,
    cfg: &Config,
    out: &Renderer,
    cmd: &DelegateCmd,
) -> Result<()> {
    match cmd {
        DelegateCmd::Set { user, delegate_group } => {
            let target = dir.resolve(ldap, user).await?;
            let group = dir.resolve(ldap, delegate_group).await?;
            let fits_user =
                |e: &ldap3::SearchEntry| assert_is_user(&e.dn, object_classes(e)).is_ok();
            let fits_group = |e: &ldap3::SearchEntry| {
                assert_is_group(&e.dn, object_classes(e)).is_ok()
                    && assert_outside_cloud_idp(&e.dn, &cfg.cloud_idp_ou).is_ok()
                    && assert_within_resource_ou(&e.dn, &cfg.resource_ou).is_ok()
            };
            // The account first, which is the one place this tool does not put
            // the edited object first: the operator's model is "lend this
            // user's device grants to that group", and `managedBy` living on
            // the group is an LDAP detail that should not drive the grammar.
            assert_argument_order(
                "device delegate set",
                "user",
                Arg {
                    given: user,
                    fits_first: fits_user(&target),
                    fits_second: fits_group(&target),
                },
                Arg {
                    given: delegate_group,
                    fits_first: fits_user(&group),
                    fits_second: fits_group(&group),
                },
            )?;
            assert_is_user(&target.dn, object_classes(&target))?;
            assert_is_group(&group.dn, object_classes(&group))?;
            assert_outside_cloud_idp(&group.dn, &cfg.cloud_idp_ou)?;
            assert_within_resource_ou(&group.dn, &cfg.resource_ou)?;

            let managed = dir.groups_managed_by(ldap, &target.dn).await?;
            let mut changed = Vec::new();
            // Cleared before the new link is written, never after: a failure
            // between the two then leaves nobody able to authorize a machine
            // for this account, rather than two groups that can.
            for dn in delegate_links_to_clear(&managed, Some(&group.dn)) {
                dir.clear_delegate_link(ldap, dn).await?;
                changed.push(format!("cleared managedBy and {ROLE_DELEGATES} on {dn}"));
            }
            let marked = markers_of(&group).iter().any(|m| m == ROLE_DELEGATES);
            dir.set_delegate_link(ldap, &group.dn, &target.dn, !marked).await?;
            // Naming what the link was is the whole of D16 in one line: this
            // group may have been somebody else's delegate group, and taking
            // that right away is a change to an account nobody typed.
            changed.push(match group.attrs.get("managedBy").and_then(|v| v.first()) {
                Some(prev) if !dn_equals(prev, &target.dn) => {
                    format!("set managedBy on {} to {} (was {prev})", group.dn, target.dn)
                }
                _ => format!("set managedBy on {} to {}", group.dn, target.dn),
            });
            if !marked {
                changed.push(format!("added {ROLE_DELEGATES} to {}", group.dn));
            }
            let owners: Vec<&str> =
                managed.iter().filter(|g| !g.is_delegate).map(|g| g.dn.as_str()).collect();
            if !owners.is_empty() {
                changed.push(format!(
                    "left alone: {} also names this account in managedBy, without the marker \
                     -- an ownership record, which delegates nothing",
                    owners.join(", ")
                ));
            }
            out.done(format!(
                "{}\n\
                 Everyone in {} may now authorize a machine to obtain tickets as {}. They are \
                 each still admitted to the realm in their own right: the delegate group is \
                 additional to admission, never instead of it.\n\
                 To let a second team do the same, nest their synced group into this one. One \
                 delegate group per account is deliberate -- a second would be a right nobody \
                 remembers granting.",
                changed.join("\n"),
                resolved_name(&group),
                resolved_name(&target),
            ));
        }
        DelegateCmd::Clear { user } => {
            let target = dir.resolve(ldap, user).await?;
            let managed = dir.groups_managed_by(ldap, &target.dn).await?;
            let links = delegate_links_to_clear(&managed, None);
            if links.is_empty() {
                out.done(format!(
                    "no delegate group names {}; there is nothing to clear",
                    resolved_name(&target)
                ));
                return Ok(());
            }
            let mut changed = Vec::new();
            for dn in links {
                dir.clear_delegate_link(ldap, dn).await?;
                changed.push(format!("cleared managedBy and {ROLE_DELEGATES} on {dn}"));
            }
            let sam = resolved_name(&target);
            out.done(format!(
                "{}\n\
                 This revokes nothing. A grant lives on {sam} and is checked against {sam}'s own \
                 membership, so the machines those delegates already authorized keep working to \
                 their deadline: `kbmanage device list {sam}` lists them and `kbmanage device \
                 revoke <id>` stops one.",
                changed.join("\n"),
            ));
        }
        DelegateCmd::List { user } => {
            let only = match user {
                Some(name) => Some(dir.resolve(ldap, name).await?.dn),
                None => None,
            };
            let snap = dir.snapshot(ldap, now()).await?;
            out.delegate_list(&snap, only.as_deref());
        }
    }
    Ok(())
}

struct Renderer {
    json: bool,
    yes: bool,
}

impl Renderer {
    fn done(&self, message: String) {
        if self.json {
            println!("{}", serde_json::json!({ "ok": true, "message": message }));
        } else {
            println!("{message}");
        }
    }

    /// The one prompt in the tool. Every destructive verb goes through it, and
    /// it always says what is lost -- there is no "routine" deletion here.
    fn confirm_destroying(&self, dn: &str, name: &str, consequences: &[String]) -> Result<()> {
        if self.yes {
            return Ok(());
        }
        if !std::io::stdin().is_terminal() {
            bail!(
                "refusing to delete {dn} with no terminal to confirm at.\n\
                 A script that meant this passes --yes; one that did not just avoided \
                 deleting something irreplaceable."
            );
        }
        eprintln!("\n  DESTROYING {dn}\n");
        for line in consequences {
            eprintln!("  - {}", wrap(line, 74, "    "));
        }
        eprint!("\n  Type the object's name ({name}) to confirm: ");
        std::io::stderr().flush().ok();
        let mut typed = String::new();
        std::io::stdin().read_line(&mut typed).context("reading confirmation")?;
        if typed.trim() != name {
            bail!("that is not {name:?} -- nothing was deleted");
        }
        Ok(())
    }

    /// Never the password, and never the password *file's contents* -- only the
    /// path, which is what an operator needs to check.
    fn config(&self, cfg: &kerbridge_manage::Config) {
        if self.json {
            return print_json(&serde_json::json!({
                "source": cfg.source.display().to_string(),
                "url": cfg.url,
                "base_dn": cfg.base_dn,
                "cloud_idp_ou": cfg.cloud_idp_ou,
                "resource_ou": cfg.resource_ou,
                "bind_dn": cfg.bind_dn,
                "password_file": cfg.password_file.display().to_string(),
                "credential_readable": cfg.bind_password.is_ok(),
                "ca_file": cfg.ca_file.display().to_string(),
            }));
        }
        println!("config set       {}", cfg.source.display());
        println!("directory        {}", cfg.url);
        println!("base             {}", cfg.base_dn);
        println!("sync-owned       {}", cfg.cloud_idp_ou);
        println!("resource OU      {}", cfg.resource_ou);
        println!("binding as       {}", cfg.bind_dn);
        println!("credential       {}", cfg.password_file.display());
        // Said, not judged: on a host that has installed the packages and not
        // yet run `kbsetup directory` this file is legitimately absent, and
        // this verb is the one that has to keep answering there.
        if let Err(why) = &cfg.bind_password {
            println!("                 cannot be read: {why}");
        }
        println!("realm CA         {}", cfg.ca_file.display());
    }

    fn group_list(&self, snap: &Snapshot) {
        if self.json {
            return print_json(&snap.resources);
        }
        if snap.resources.is_empty() {
            println!("no resource groups under {}", snap.resource_ou);
            return;
        }
        for g in &snap.resources {
            let scope = if g.is_domain_local() {
                "domain-local".to_owned()
            } else {
                format!("groupType {} -- NOT domain-local", g.group_type.as_deref().unwrap_or("?"))
            };
            println!("{}  [{scope}]", g.sam);
            println!("    {}", g.dn);
            if let Some(sid) = &g.sid {
                println!("    {sid}");
            }
            for m in &g.members {
                println!("    contains {}", member_line(snap, m));
            }
        }
    }

    /// One group's membership, for the group the operator asked about. `group
    /// list` answers "what groups are there"; this answers "who is in this
    /// one", which is the question a broken authorization actually raises.
    fn member_list(&self, snap: &Snapshot, dn: &str, members: &[String]) {
        if self.json {
            return print_json(&serde_json::json!({ "group": dn, "members": members }));
        }
        println!("{dn}");
        if members.is_empty() {
            println!("    contains nothing");
            return;
        }
        for m in members {
            println!("    contains {}", member_line(snap, m));
        }
    }

    /// The delegation chain, account first: who the grants are for, the group
    /// that may authorize a machine as them, and who is in it. The directory
    /// holds it the other way round -- the link lives on the group -- and that
    /// is not the question anyone asks.
    fn delegate_list(&self, snap: &Snapshot, only: Option<&str>) {
        let rows: Vec<_> = snap
            .resources
            .iter()
            .filter_map(|g| g.delegates_for().map(|dn| (g, dn)))
            .filter(|(_, dn)| only.is_none_or(|want| dn.eq_ignore_ascii_case(want)))
            .collect();
        if self.json {
            return print_json(
                &rows
                    .iter()
                    .map(|(g, dn)| {
                        serde_json::json!({
                            "user": snap.find_cloud(dn).map(|o| o.sam.clone()),
                            "dn": dn,
                            "group": g.sam,
                            "group_dn": g.dn,
                            "members": g.members,
                        })
                    })
                    .collect::<Vec<_>>(),
            );
        }
        if rows.is_empty() {
            println!("no delegate groups");
            return;
        }
        for (g, dn) in rows {
            match snap.find_cloud(dn) {
                Some(o) => println!("{}  ({dn})", o.sam),
                None => println!("{dn}"),
            }
            println!("    device grants may be authorized by {}", g.dn);
            if g.members.is_empty() {
                println!("        contains nothing -- so nobody but this account can");
            }
            for m in &g.members {
                println!("        contains {}", member_line(snap, m));
            }
        }
    }

    fn cloud_list(&self, snap: &Snapshot, want: Option<Kind>) {
        let objects: Vec<_> =
            snap.cloud.iter().filter(|o| want.is_none_or(|k| o.kind == k)).collect();
        if self.json {
            return print_json(&objects);
        }
        for o in objects {
            let state = match o.state() {
                State::Live => "live".to_owned(),
                s => match o.held_days(snap.now) {
                    Some(d) => format!("{s:?} {d}d, holding its SID"),
                    None => format!("{s:?}, timestamp unreadable"),
                },
            };
            let mut role = String::new();
            if o.is_admission_group() {
                role.push_str("  [admission group]");
            }
            if o.is_grant_group() {
                role.push_str("  [device-grant group]");
            }
            println!("{:<24} {:<6} {state}{role}", o.sam, format!("{:?}", o.kind).to_lowercase());
        }
    }

    /// The device table.
    ///
    /// The deadline column is **"sign-in required by"** and not "expires",
    /// because that is what the date costs whoever holds the machine: someone
    /// has to be at it, in a browser, by then.
    ///
    /// It is the date *stamped in the directory*, which is the only one this
    /// tool can see. The broker clamps it to `start + device_grant_days` on
    /// the exchange path, so the enforced date can be earlier than this and
    /// never later -- and that setting belongs to the deployment, not to a
    /// directory client. Copying it here is what made this column report every
    /// grant as long dead on a host whose copy had gone stale.
    fn device_list(&self, snap: &Snapshot, only: Option<&str>) {
        let rows: Vec<_> = snap
            .cloud
            .iter()
            .filter(|o| only.is_none_or(|dn| o.dn.eq_ignore_ascii_case(dn)))
            .flat_map(|o| o.grants().into_iter().map(move |(_, g)| (o, g)))
            .collect();
        if self.json {
            return print_json(
                &rows
                    .iter()
                    .map(|(o, g)| {
                        serde_json::json!({
                            "id": g.short_id(),
                            "user": o.sam,
                            "dn": o.dn,
                            "label": g.label,
                            "added": rfc3339(g.start as u32),
                            "last_seen": g.seen.map(|s| rfc3339(s as u32)),
                            "sign_in_required_by": rfc3339(g.end as u32),
                        })
                    })
                    .collect::<Vec<_>>(),
            );
        }
        if rows.is_empty() {
            println!("no device grants");
            return;
        }
        println!(
            "{:<10} {:<20} {:<26} {:<12} SIGN-IN REQUIRED BY",
            "ID", "USER", "DEVICE", "LAST SEEN"
        );
        for (o, g) in rows {
            // Days, never hours: `seen` is stamped at day granularity, so an
            // hour figure would be precision the stored value does not carry.
            let seen = match kerbridge_core::grant::seen_days_ago(g.seen, snap.now) {
                None => "never".to_owned(),
                Some(0) => "today".to_owned(),
                Some(1) => "1 day ago".to_owned(),
                Some(d) => format!("{d} days ago"),
            };
            println!(
                "{:<10} {:<20} {:<26} {:<12} {}",
                g.short_id(),
                o.sam,
                g.label,
                seen,
                rfc3339(g.end as u32)
            );
        }
    }

    fn cloud_show(&self, snap: &Snapshot, obj: &kerbridge_manage::CloudObject) {
        if self.json {
            return print_json(obj);
        }
        println!("{}", obj.dn);
        println!("  sAMAccountName  {}", obj.sam);
        if let Some(upn) = &obj.upn {
            println!("  userPrincipalName {upn}");
        }
        if let Some(name) = &obj.display_name {
            println!("  displayName     {name}");
        }
        println!("  objectSid       {}", obj.sid.as_deref().unwrap_or("(unreadable)"));
        match obj.identity() {
            Some(Ok(id)) => println!("  cloud identity  {id}", id = id.label()),
            Some(Err(e)) => println!("  cloud identity  MALFORMED: {e}"),
            None => println!("  cloud identity  (none -- not managed by sync)"),
        }
        if let Some(enabled) = obj.enabled() {
            println!("  account         {}", if enabled { "enabled" } else { "DISABLED" });
        }
        println!("  state           {:?}", obj.state());
        for m in &obj.markers {
            println!("  marker          {m}");
        }
        for dn in &obj.members {
            println!("  contains        {dn}");
        }
        for dn in snap.closure_of(&obj.dn) {
            let where_ =
                if dn_is_at_or_within(&dn, &snap.cloud_idp_ou) { "synced" } else { "resource" };
            println!("  inside          {dn}  ({where_})");
        }
    }

    /// The connectivity chain, in the same shape as a user report: one line per
    /// link, and the walk visibly stopping at the broken one.
    ///
    /// In JSON only when it broke. A healthy `doctor --json` prints one document
    /// and scripts read that document; a second one ahead of it, on every run,
    /// to say nothing is wrong would change the shape for every reader.
    fn reach(&self, report: &doctor::ReachReport) {
        if self.json {
            if report.worst() == Status::Fail {
                print_json(report);
            }
            return;
        }
        println!("{}", report.target);
        for c in &report.checks {
            let indent = " ".repeat(26);
            println!("  {} {:<18} {}", mark(c.status), c.label, wrap(&c.detail, 54, &indent));
        }
        println!();
    }

    /// One line: what the walk reached, and why it stopped there.
    ///
    /// The whole output of the verb, because the thing running it is a poll loop
    /// printing a line per service, and a chain landing inside that table would
    /// have to be re-worded by every script that calls this. The chain is still
    /// there under --json, and `doctor --endpoint` renders it link by link.
    fn endpoint_line(&self, report: &doctor::EndpointReport) {
        if self.json {
            return print_json(report);
        }
        println!("{}", report.summary());
    }

    /// The endpoint chain, in the same shape as the reach one.
    fn endpoint(&self, report: &doctor::EndpointReport) {
        if self.json {
            return print_json(report);
        }
        println!("{}", report.target);
        for c in &report.checks {
            let indent = " ".repeat(26);
            println!("  {} {:<18} {}", mark(c.status), c.label, wrap(&c.detail, 54, &indent));
        }
        println!();
    }

    fn user_report(&self, report: &doctor::UserReport) {
        if self.json {
            return print_json(report);
        }
        println!("{}", report.dn.as_deref().unwrap_or(&report.subject));
        for c in &report.checks {
            let indent = " ".repeat(26);
            println!("  {} {:<18} {}", mark(c.status), c.label, wrap(&c.detail, 54, &indent));
        }
        if let Some(next) = &report.next_step {
            println!("\n  {}", wrap(next, 74, "  "));
        }
        if report.worst() == Status::Ok {
            println!("\n  Every link this tool can see is intact.");
        }
    }

    fn sweep(&self, snap: &Snapshot, findings: &[doctor::Finding]) {
        if self.json {
            return print_json(findings);
        }
        let order = |s: Status| match s {
            Status::Fail => 0,
            Status::Warn => 1,
            Status::Info => 2,
            Status::Ok => 3,
        };
        let mut sorted: Vec<&doctor::Finding> = findings.iter().collect();
        sorted.sort_by_key(|f| order(f.status));
        for f in sorted {
            println!("{} {:<20} {}", mark(f.status), f.kind, f.subject);
            println!("       {}", wrap(&f.detail, 70, "       "));
        }
        let plural = |n: usize, one: &str| {
            if n == 1 { one.to_owned() } else { format!("{one}s") }
        };
        println!(
            "\n{} managed {} under {}, {} resource {}.",
            snap.cloud.len(),
            plural(snap.cloud.len(), "object"),
            snap.cloud_idp_ou,
            snap.resources.len(),
            plural(snap.resources.len(), "group")
        );
    }
}

/// One member of a group, annotated with the two things that make a nesting
/// read as working when it is not: whose object it is, and whether it is being
/// held for its SID and therefore grants nothing.
fn member_line(snap: &Snapshot, dn: &str) -> String {
    let held = snap
        .find_cloud(dn)
        .filter(|o| o.state() != State::Live)
        .map(|o| format!("  <- {:?}, grants nothing", o.state()))
        .unwrap_or_default();
    let synced = if dn_is_at_or_within(dn, &snap.cloud_idp_ou) { "  (synced)" } else { "" };
    format!("{dn}{synced}{held}")
}

fn mark(s: Status) -> &'static str {
    match s {
        Status::Ok => "ok  ",
        Status::Warn => "warn",
        Status::Fail => "FAIL",
        Status::Info => "note",
    }
}

fn print_json<T: serde::Serialize + ?Sized>(value: &T) {
    match serde_json::to_string_pretty(value) {
        Ok(s) => println!("{s}"),
        Err(e) => eprintln!("kbmanage: rendering JSON: {e}"),
    }
}

/// Greedy wrap at `width`, continuation lines indented by `indent`. Long
/// consequences are the point of this tool's prompts; an unwrapped one is a
/// wall the operator skips.
fn wrap(text: &str, width: usize, indent: &str) -> String {
    let mut out = String::new();
    let mut column = 0;
    for word in text.split_whitespace() {
        if column > 0 && column + 1 + word.len() > width {
            out.push('\n');
            out.push_str(indent);
            column = 0;
        } else if column > 0 {
            out.push(' ');
            column += 1;
        }
        out.push_str(word);
        column += word.len();
    }
    out
}
