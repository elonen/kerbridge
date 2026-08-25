# kerbridge-manage — the operator-owned part of the directory

 `kbmanage` CLI and a library it uses. KerBridge sync owns the IdP-specific OUs; the
operator owns the domain-local resource groups in `OU=Resources` that your file server is supposed to use.

This tool manages the second, and its  `doctor` sub-command walks the chain between them —
cloud identity → synced global group → resource group → share ACL — and names the
broken link.

## Why it exists

- **RSAT/ADUC is the alternative, and it is worse for this.** It is a Windows
  install for a few group operations, and it authenticates as the realm
  `Administrator` with a password. `kbmanage` runs from a shell as `svc-kerbridge-manage`
  over LDAPS, delegated to write `OU=Resources` and to do nothing in the IdP parent OU
  but read and delete-child.
- **The IdP parent OU is read and delete only, by design.** Everything under it is sync-owned, and a
  second writer racing the reconciliation loop is a failure this tool
  exists to avoid. The two exceptions are a pinned login name and a revoked
  device grant, and neither has a race to lose: sync derives a login name once
  and never recomputes it for a live account, and only `issuerd` ever writes a
  grant value, so deleting one removes something nothing is about to rewrite.
- **Deleting is never recovery.** The recreated object gets a new SID, and under
  `idmap_rid` every file server derives `uid` from it, so files stay owned by
  ids that no longer resolve. This was tested: a synced user destroyed through
  this tool came back from the next sync cycle at RID 1107 → 1122.
- **The library never prints** — every interaction with a human is in the CLI, so
  a GUI could link the same code later.

## How

- `group new` / `rename` and `group member add` / `remove` / `list` — domain-local
  security groups in `OU=Resources`, and putting synced Entra groups inside them.
  That nesting is the authorization model; ACLs on the file server reference the
  resource group's SID, never a name. `group list` answers "what groups are
  there"; `group member list` answers "who is in this one", which is the question
  a denied folder actually raises.
- `doctor [--user …]` — reads one snapshot, then diagnoses it as a pure function
  over plain data. It also names the one link it cannot see rather than
  pretending to have checked it.
- `problems` — what the services on **this host** have recorded as still wrong:
  severity, component, event, subject, how long it has been open, and the
  message, out of the `problem-*.json` files each service writes under
  `notify.state_dir`. It reads files and binds nothing, so it answers when the
  directory does not, and it is a listing and not a check — it exits 0 whether
  or not something is open, because what an open problem is worth belongs to
  the operator's monitoring. A record it cannot read costs that record and is
  said out loud; the rest of the listing stands.
- `entra delete` — the untangler. One object at a time, hard, with a typed-name
  confirmation on a real TTY and a warning every time. There is no retention
  window to be past, because a lost SID does not become cheap with age.
- `device list` / `device revoke` — which machines may obtain tickets without a
  browser, and stopping one. Keyed on the eight-character id derived from the
  key, never on the machine label: the label is client data, and two machines
  claiming one name would revoke the wrong one at precisely the wrong moment.
  The deadline shown is the one *stamped in the directory*, which is the only one
  this tool can see: the broker clamps to `start + device_grant_days` (`configs/main.toml`) on the
  exchange path, and that setting belongs to the deployment rather than to a
  directory client. Read it as an upper bound — the enforced date is never later,
  and can be earlier. Keeping a copy of the setting here is what once reported
  every live grant as long expired on a host whose copy had gone stale.
- `device delegate set <user> <delegate-group>` — the group whose members may
  authorize a machine to obtain tickets **as** `<user>`, without anyone learning
  that account's credentials. The link is `managedBy` on the group plus a
  `kbrole1|delegates` marker in `extensionName`, both of them inside the blanket
  write `svc-kerbridge-manage` already holds on the resource OU: **no ACL change, no new
  delegation.** `managedBy` alone is deliberately not enough — it has a live
  conventional meaning, *who owns this group*, and an admin who set it for ADUC
  reasons must not thereby have handed that group's members the right to
  authorize devices as the account it names.
  - **One delegate group per account, on purpose.** `set` replaces: it clears the
    link on any other group naming that account and says which one it cleared.
    The directory would allow several — `managedObjects` is multi-valued — but
    then an operator moving a service account between teams reads "set" as
    replace and leaves team A a right nobody remembers granting. To let two
    populations authorize one account, **nest both their Entra groups into the
    one delegate group**; that is the ordinary authorization model above, not a
    second delegate group.
  - `clear` and `list` — `list` shows the chain account-first: who the grants are
    for, the group that may authorize as them, and who is in it. **Removing a
    delegate revokes nothing:** a grant lives on the target and is checked
    against the *target's* membership, so it stops new machines being authorized
    and touches none of the ones already running. Those are found in the broker's
    grant log and stopped with `device revoke`.
- `doctor` and `config` find their own configuration: the deployment's config
  set, found where `--config` points or in the two fixed locations
  `kerbridge_core::config::discover` looks. `make kbmanage-config` in `deploy/`
  writes the `kbmanage.toml` and the link a host-run binary needs.

## Argument order

Two-name verbs put the **edited object first** — `group member add
<resource-group> <member>`, `group rename <old> <new>`. `device delegate set
<user> <delegate-group>` breaks that deliberately: the operator's model is
"lend this user's device grants to that group", and `managedBy` living on the
group is an LDAP detail that should not drive the grammar.

A reversed pair is refused by naming which argument is wrong and printing the
command that would have worked, rather than with a generic "outside the IdP parent OU".
That matters most where it is easiest to get wrong: `group nest <synced>
<resource>` became `group member add <resource> <synced>`, so a script converted
by changing the verb alone has its arguments the other way round and the verb
name no longer catches it.

Day-2 usage, including where RSAT still fits:
[`docs/rsat-and-kerbridge-management.md`](../../docs/rsat-and-kerbridge-management.md).
Directory layout and the delegation model:
`DESIGN.md` § [Directory ownership and synchronization](../../docs/design/identity-and-directory.md#directory-ownership-and-synchronization).
