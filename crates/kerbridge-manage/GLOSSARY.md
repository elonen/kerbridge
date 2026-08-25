# kerbridge-manage glossary

The operator CLI: the resource side of the directory, `doctor` diagnostics, and
the destructive-verb confirmation machinery.

Part of the repo-wide vocabulary in [`GLOSSARY.md`](../../GLOSSARY.md) — a term
means the same thing there and here. It lives in this file, closest to where
it's used, rather than in the root file, because the root file would be
unreadably long if it carried every term at once.

### authorization chain

The path from a cloud identity to a file: external identity → the synced group
it is in → the resource group that nests it → the share and filesystem ACL.
`kbmanage doctor` walks it as far as LDAP reaches and then names the link it
cannot see — winbind's idmap on the file server, where `id 'DOMAIN\name'` is
the operator's next step.
<!-- refs: `kerbridge_manage::doctor::diagnose_user` -->
<!-- avoid: the chain, delegation chain, authorization model, auth chain -->

### check

One named line of a report, with a status and a detail: in `kbmanage doctor`,
one test on a user's `authorization chain`; in the deployment's readiness
report, one service line — `realm`, `nas1`, `broker`, `endpoint`, `sync`. There
`realm`, `broker` and `endpoint` are always required; `nas1` and `sync` are
checked only when the container exists.
<!-- refs: `kerbridge_manage::doctor::Check` -->
<!-- avoid: test, probe, service check -->

### confinement

The DN containment rule deciding which side of the IdP parent OU a target is on,
written to survive case, whitespace, and a DN that merely contains the
OU's text. It is not "no writes inside the IdP parent OU": resource-group
writes must be outside, and the verbs that do reach in — `entra delete`,
`entra rename`, `entra unpin`, `device revoke` — must be inside, and nothing
else may be.
<!-- refs: `kerbridge_manage::validate::assert_outside_entra`, `assert_inside_entra`, `kerbridge_core::dn::dn_is_at_or_within` -->
<!-- avoid: dn confinement, containment check, dn guard -->

### delegation (device grants)

`managedBy` plus `kbrole1|delegates` on one `resource group`: the right for
that group's members to authorize a machine as the named account, without ever
holding that account's credentials. Additional to `admission`, never instead of
it.
<!-- avoid: device delegation, delegated device grants, managedby link -->

### destructive verb

A `kbmanage` verb that loses something no restore brings back, and so always
goes through the `typed-name confirmation`: `group delete`, `entra delete`,
`entra rename` and `device revoke`. `entra unpin` is not one — it hands a login
name back to sync and prompts for nothing.
<!-- refs: `crates/kerbridge-manage/src/main.rs` -->
<!-- avoid: dangerous verb -->

### endpoint link

The one readiness question that is not about a deployment's containers: does the
broker answer `GET /config` over the path a client uses, and — when it answers
404 — which 404 it is. A broker serving several sources refuses an unprefixed
`/config` and lists them; a path nothing routed refuses it with an empty body.
`kbmanage endpoint` asks it and nothing else, `kbmanage doctor --endpoint` walks
it beside the reach chain, and the deployment's readiness script reports what it
said.
<!-- refs: `kerbridge_manage::endpoint::probe`, `kerbridge_manage::doctor::diagnose_endpoint` -->
<!-- avoid: config probe, health check, readiness check -->

### finding

One named observation from a `doctor` `sweep`: its kind, the object it is
about, a status and a detail. A `check` is the per-user equivalent.
<!-- refs: `kerbridge_manage::doctor::Finding` -->
<!-- avoid: `kind` -->

### group name

A `resource group`'s CN and `sAMAccountName` together, which must survive
becoming an RDN and a `valid users` entry on a file server. `kbmanage` refuses
one past 64 characters, the same bound sync's own group names are cut to.

### guard

A pure `kbmanage` check standing between an operator's argument and a directory
write: is this a group, is it a person, is it inside the delegated OU, is it on
the right side of the IdP parent OU, is the argument pair the right way round. Guards
never print — they return a `refusal` the caller renders.
<!-- refs: `crates/kerbridge-manage/src/validate.rs` -->
<!-- avoid: validation, precondition -->

### handle

`kbmanage`'s and `issuerd`'s word for the `grant handle`: the eight hex
characters `device list` prints and `device revoke` takes, derived from the
grant key's thumbprint. Never the machine `label`, which the client chooses and
two devices can share.
<!-- refs: `kerbridge_core::grant::short_id` -->
<!-- avoid: id, eight-character id, operator handle -->

### link

One step of the authorization chain `kbmanage doctor` walks — does the identity
resolve, is the account usable, is it admitted, is it nested into the resource
group — and the unit the report calls broken.
<!-- avoid: hop, step, stage -->

### live

A managed object carrying neither the retired nor the quarantined state marker:
sync still sees it in Entra. A name pin is a state marker too and leaves an
object live.
<!-- refs: `kerbridge_manage::model::CloudObject::state` -->
<!-- avoid: active, current -->

### ownership record

`managedBy` on a group without the `kbrole1|delegates` marker: the attribute's
conventional ADUC meaning, *who owns this group*, which delegates nothing.
`device delegate set` and `clear` leave these alone deliberately.
<!-- refs: `kerbridge_manage::validate::delegate_links_to_clear` -->
<!-- avoid: bare managedby, managed group -->

### reachable

The verdict on the `endpoint link`, in the shapes a caller acts on
differently — serving, settling, no session, broken — which `kbmanage endpoint`
carries out as exit 0, 2, 3 and 1. Not a `status (kbmanage)`: a poll loop has to
tell "not yet" from "broken", and a TLS session that never formed is an issuance
still in flight under one `TLS_STRATEGY` and a certificate that did not load
under another, so only the caller can judge it.
<!-- refs: `kerbridge_manage::doctor::Reachable` -->
<!-- avoid: readiness state, health, endpoint status -->

### refusal

A policy answer that says no and says why: not provisioned, disabled, not
admitted, not in the device-grant group, not a delegate, or a `guard` that
rejected an argument. Distinct from an infrastructure failure, which becomes a
502 and says nothing about policy. In `kbmanage` it is a named value the
library returns and the caller renders; the library never prints.
<!-- refs: `kerbridge_manage::validate::Refusal` -->
<!-- avoid: denial, rejection, drop, exclusion -->

### resource group

A domain-local security group the operator creates in the `resource OU` to gate
a service (such as a file share): the ACL points at its `SID`, and `synced group`s are nested into it.
Sync does not own it, and it is the operator's only revocation control faster
than the ticket lifetime.
<!-- avoid: authorization group, access group, nas access group, nas authorization group, nas-policy group, local nas group, domain-local security group -->

### revocation lever

One of the ranked ways to cut an identity's access: account disable (immediate
at AS and TGS), a global group removed from the domain-local group (next
service ticket), the user removed from the global group (next TGT), and
`kbmanage device revoke`. Rotating the user's Samba key is not one — measured
to have no effect at any layer, and the operator documentation has to say so.
<!-- avoid: kill switch, revocation method -->

### revocation window

The time between an operator's revoking act and its taking effect, bounded by
the ticket lifetime in every case. The device-grant duration is deliberately
not one: `configs/main.toml`'s `device_grant_days` bounds how long a machine
runs before a person must prove the identity again, and an operator who reads
it as a revocation window sets it far too low.
<!-- refs: `configs/main.toml` `device_grant_days` -->
<!-- avoid: grace period, retention window, grant duration -->

### sign-in required by

The date stamped on a device grant, past which someone has to sign in at that
machine through the browser again. It is the stamped bound and not the enforced
one: `kbmanage device list` prints what the directory holds, and the broker
serves `min(stamped, start + device_grant_days)`, so the knob may bring the
date in and never push it out. Shown to users as *SIGN-IN REQUIRED BY*.
<!-- refs: `DeviceGrant::effective_end`, `configs/main.toml` `device_grant_days` -->
<!-- avoid: expires, expiry, deadline -->

### snapshot

One read of the directory, and the whole of what the pure part of `kbmanage` is
allowed to reason about, so diagnosis is a function over plain data that a
fixture can pin.
<!-- refs: `kerbridge_manage::model::Snapshot` -->
<!-- avoid: directory read -->

### stamped deadline

The `end=` epoch written into a device grant when it was created, and the only
date a directory client can see; it is what `kbmanage device list` prints in
its "sign-in required by" column. The enforced date can be earlier and never
later, because `device_grant_days` lives on the broker — so this and the
`sign-in deadline` are two different facts and copying one into the other's
place is a measured bug.
<!-- refs: `configs/main.toml` `device_grant_days` -->

### status (kbmanage)

The verdict on one `doctor` check or finding: `Ok`, `Warn`, `Fail`,
`Info`. Only `Fail` makes the command exit non-zero; `Warn` means working, but
not as designed.
<!-- refs: `kerbridge_manage::doctor::Status` -->
<!-- avoid: verdict, mark, level -->

### sweep

A whole-directory `doctor` run, reporting a `finding` on every managed object
and resource group rather than on one user.
<!-- refs: `kerbridge_manage::doctor::sweep` -->
<!-- avoid: scan, audit, whole-directory sweep -->

### two-name verb

A `kbmanage` verb taking two object names. Most put the edited object first
(`group member add`, `group rename`, `entra rename`); `device delegate set`
deliberately names the user first, because the operator's model is "lend this
user's grants to that group" and `managedBy` living on the group is an LDAP
detail. A reversed pair is refused by naming which argument is wrong and
printing the command that would have worked.
<!-- refs: `assert_argument_order` -->
<!-- avoid: argument order, two-argument verb, paired verb -->

### typed-name confirmation

The single prompt in `kbmanage`: it names what is lost, then requires the
object's resolved `sAMAccountName` — the grant `handle` for `device revoke` —
typed back on a real terminal. Deliberately not the string the operator typed,
which they would retype without reading; `--yes` skips it, and no terminal
without `--yes` refuses outright.
<!-- refs: `Renderer::confirm_destroying` -->
<!-- avoid: confirmation prompt, destroying prompt, are-you-sure -->

### verb (kbmanage)

One `kbmanage` subcommand that changes the directory, as against the read-only
ones (`list`, `show`, `doctor`, `config`, `problems`). Every write verb runs its `guard`s
before the write; a `destructive verb` also takes a `typed-name confirmation`.
<!-- avoid: command, operation -->
