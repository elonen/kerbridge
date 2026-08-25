# Device grants: letting a machine skip the cloud sign-in

This feature is off by default. Read this page before you turn it on.

The design is in [Device grants (`DESIGN.md`)](../../docs/design/tickets.md#device-grants).

## What it is

Usually KerBridge needs a browser or Windows sign-in before it issues a Kerberos
ticket. A **device grant** replaces that sign-in. One person signs in one time at
the machine and authorizes it. The machine then gets tickets for a number of days
that you choose. The authorization is a key in the **TPM** of that machine. The
key cannot be exported.

Two reasons to use it:

- **An unattended machine.** An example is a build server that signs in
  automatically at boot and publishes artifacts to a file server over SMB. With no
  person at the keyboard, such a machine cannot hold a Kerberos identity.
- **Ordinary users** who do not want to sign in again each ticket lifetime.

## Who goes in which group

A grant has two accounts. They do not need the same groups.

| | What it is | Admission group | Device-grant group | Delegate group of the grantee |
|---|---|---|---|---|
| **Grantee** | The account the machine gets tickets as | Yes | **Yes** | — |
| **Authorizer** | The person who signs in at the machine to make the grant | Yes | No | Yes, when the two are different accounts |

**The device-grant group does not replace the admission group.** Its members
must also have admission. Put the grantee in the device-grant group, **not the
authorizer**: the broker tests the grant against the grantee at each ticket
exchange.

Without delegation, the two are one account. A person authorizes the machine for
themselves, thus that person needs both groups. With delegation, the two are
different accounts, and the machine gets tickets as a service account.

For example, `alice` is a build engineer, and the build machine must publish as
`svc-builder`:

| Account | Admission group | Device-grant group | `svc-builder-delegates` |
|---|---|---|---|
| `svc-builder`, the grantee | Yes | **Yes** | — |
| `alice`, the authorizer | Yes | No | Yes |

`alice` signs in at the machine one time. The machine then gets tickets as
`svc-builder`. [Machines that publish as a service
account](#machines-that-publish-as-a-service-account) gives the full
procedure.

## Turning it on

Two settings turn the feature on. Then run `make up`.

```toml
# configs/main.toml
device_grant_days = 30                 # 0 is off, and 0 is the default

# configs/idp_entra.toml, inside [provider_config]
device_grant_group = "KerBridge Device Grant Users"
#device_grant_group_id =               # alternative to the name
```

Two more settings change how the feature operates. Each is already at the value
that suits most deployments: `device_grant_max_per_user` is 10, and
`device_grant_notify` is `"off"`. Leave both lines commented out until you want a
different value.

| Setting | Lives in |
|---|---|
| `device_grant_days` | `configs/main.toml` |
| `device_grant_max_per_user` | `configs/main.toml` |
| `device_grant_notify` | `configs/sync.toml` |
| `device_grant_group`, `device_grant_group_id` | `configs/idp_entra.toml`, `[provider_config]` |
| `admission_group`, `admission_group_id` | `configs/idp_entra.toml`, `[provider_config]` |

### The device-grant group

Create it in Entra adjacent to `admission_group`. Sync synchronizes the group
whether you nest it in the admission group or not.

To give the feature to all users, put all users in the group. A shortcut: add the
admission group itself as a member. With delegation, that shortcut has a second
effect: **each member of this group is a possible delegation target**. You can
then appoint a delegate for each person in the company. This can be what you want.
It is how you let a person operate for a colleague who is on leave. But make it a
decision, not an accident.

Set the group name *or* `device_grant_group_id`, never both. If you set both, sync
refuses to start. The ID stays correct when you rename the group in Entra. If you
set neither, no device grant can be made or used. `device_grant_days` does not
change this: the broker looks up the group, finds none, and denies each
device-grant request.

If you point `device_grant_group` at a different group, the change applies at the
next sync cycle. A user who is not in the new group loses each device they hold.
Sync does not apply one change: when you unset the name, sync writes a message in
its log and continues with the group stored in LDAP. Unsetting the name is not how
you turn the feature off — see [Revocation](#revocation).

### `device_grant_max_per_user`

A safety limit, not a policy. The limit stops a compromised broker before it makes
a directory object too large. With delegation, the limit applies to a **fleet**,
not to one person, and that is the normal case: twenty build machines that are
authorized for one `svc-builder` account make twenty device grants on that one
object. Set the value for the size of the fleet.

## Revocation

Each method takes effect in at most one **ticket** lifetime, the same as with
regular user sign-in. The broker examines all of them again each time a device
asks for a ticket.

- Remove the grantee from the device-grant group.
- Disable the account.
- `kbmanage device revoke <id>`.
- Set `device_grant_days = 0`.

`device_grant_days` limits a different thing: the time that a machine can operate
before a person must prove the identity to Entra again. **It is not a revocation
window.** Operators who use it as a revocation window set the number much too low.
Then a person must go to the build machine each week.

## What a user does

On the machine, open the tray agent and go to **Settings → Advanced →
Authorization**. The group shows only when the feature is on. It operates only for
a user who is in the device-grant group. When the machine holds a grant, the same
location shows *Access authorized as &lt;account&gt;* and a **Remove
authorization…** button. The tray shows a warning when seven days or less remain
before the deadline. If a TPM cannot store a key for the grant, the feature fails.

**A sign-out does not give up the grant.** When grants are on, the tray divides
sign-out in two actions. *Sign out of Entra* removes the SSO cookie and the
in-memory refresh token. *Sign off* removes the Kerberos tickets. Neither action
changes the grant. On a delegated machine, the person who signs out does not own
the grant: it belongs to the grantee. **Remove authorization…** is the action that
ends the grant. It first deletes the key from the TPM, which works offline. It
then tells the broker.

### Without the GUI

The CLI client is installed adjacent to the tray in `%ProgramFiles%\KerBridge\`:

```sh
kerbridge --grant                # authorize this machine; signs in first
kerbridge --grant-status         # what this machine holds, and its pin. Offline
kerbridge --grant-list           # list every device on the account
kerbridge --grant-give-up        # hand this machine's own grant back. Offline
kerbridge --grant-revoke <id>    # stop another device; signs in first
kerbridge --no-grant             # ignore the grant for one run; the browser instead
kerbridge --grant --for svc-x    # authorize this machine for another account
```

The tray and the CLI read the same `config.toml`. Thus both tools use a grant that
you make with one of them. `--grant-status` gives one answer that the tray and the
server-side `kbmanage` cannot give: it compares the claims in the file with the
keys that the TPM holds. When the two do not agree, the cause is a rebuilt profile
or a cleared TPM.

## Machines that publish as a service account

This is the full procedure for the `alice` and `svc-builder` example in
[Who goes in which group](#who-goes-in-which-group).

No person is permitted to know the password of `svc-builder`. Thus no person can
sign in as that account at the machine, and a device grant normally needs that
sign-in. **Delegation** is the solution. You name a group of people who can
authorize machines *for that account*.

### In Entra

The service account is an **ordinary Entra user**. Create it the same as any
other user, with the memberships in the table in [Who goes in which
group](#who-goes-in-which-group). Keep it enabled: sync
mirrors `accountEnabled`, and a disabled account gets nothing.

**Put a Conditional Access policy on the account.** KerBridge does not require this
policy, and the feature works without it. But without it, each person who can
*reset the password of that account* can sign in as the account and get a ticket
directly, with no TPM and no grant. The roles that can do this — Helpdesk
Administrator, Password Administrator — are usually given much more widely than
admission-group membership. A policy that blocks interactive sign-in for the
account removes this risk.

### On the server

The delegate group is a resource group that you own, outside `OU=CloudIdP`:

```sh
kbmanage group new svc-builder-delegates
kbmanage device delegate set svc-builder svc-builder-delegates
kbmanage group member add svc-builder-delegates build-engineers
```

The last line nests your synced Entra group into the delegate group. Each member
of `build-engineers`, at each level of nesting, can now authorize a machine for
`svc-builder`.

**Each account has one delegate group. This is intentional.** `delegate set`
replaces the link: it removes the link from each other group that points at that
account, and it reports which group it changed. To let *two* populations authorize
the same account, nest both of their Entra groups into the one delegate group. Do
not make a second delegate group. Then `kbmanage doctor` shows one chain, and no
group is partially delegated.

A delegate does not need a device grant of their own and does not join the
device-grant group. But a delegate **must** be admitted to the realm: the delegate
group is examined in addition to admission, never instead of it.

### At the machine

Point the machine at the account one time. Use `--for` on the command line, or use
a pin that stays through reinstalls:

```sh
kerbridge --grant --for svc-builder
kerbridge --grant-status                     # the pin and what is actually held
```

The pin is stored in `HKLM` or in the user's `config.toml`. The machine-wide value
is `GrantFor` under `HKLM\Software\Policies\KerBridge`. Group Policy, Intune or an
imaging script writes it — see
[windows-client.md](windows-client.md#preconfiguring-a-fleet). The MSI does not
write it. The machine-wide value has priority, and the tray shows it read-only.

On a pinned machine, the button in the tray shows **Authorize access…**, not *Sign
in…*, because that is the only thing that it does. The pinned account is above it,
in the *Authorize this device for* field. The sign-in of the engineer authorizes
the key and then stops. It never injects the ticket of the engineer. `--no-grant`
is the exception, and it shows this clearly: it signs in and injects a ticket **as
you**, for that one run. The tray then gets a ticket as the service account again
at its next cycle.

The pin is an input at authorization time, not a switch. A machine that already
holds a grant for one account continues to get tickets as that account. A change
to the pin applies at the next re-authorization, when a person is at the keyboard.

There is no interactive method to test the share access of the service account,
and no run-as function. This is intentional. Debug from the machine that holds the
grant.

### When a delegate leaves

**When you remove a person from a delegate group, this revokes nothing.** Grants
are stored on the target account, and the broker tests them against the membership
of the *target*. Thus the engineer cannot authorize **new** machines, but the
machines that they authorized before continue. Those machines operate until their
`device_grant_days` deadline, and each delegate who remains can renew them.

To stop the machines that the person enrolled:

```sh
grep 'GRANT .* by=alice' deploy/state/broker-audit/audit.log
kbmanage device revoke <id>          # for each one you find
```

You must keep that file — see [Day 2](#day-2). To stop all access from the
machines of that account at one time, remove the **service account** from the
device-grant group. That stops each device on the account, delegated or not.

## Day 2

Use these commands on the server:

```sh
kbmanage device list                # every authorized device
kbmanage device list alice          # just one user's
kbmanage device revoke 1a2b3c4d     # stop one, by the id `list` prints
kbmanage device delegate list       # every delegation chain
kbmanage doctor --user alice        # includes a device-grant line if they hold any
```

The **"sign-in required by"** column does not mean "expires". It means that a
person must be at that machine, in a browser, before that date. The value is the
date stamped in the directory, which is the data that `kbmanage` can see:
`kbmanage` talks to the DC, and it does not see your `device_grant_days` value.
When you decrease that setting, the enforced date becomes earlier, but this column
does not change. Thus use the column as an upper limit: the enforced date is
`min(this, added + device_grant_days)`, never later.

Revocation uses the eight-character id, not the machine label. The label is the
text that the machine reported, so two machines can report the same label. The id
is derived from the TPM key and is always unique. The id also stays the same
through a re-authorization: the machine keeps its row and its id, its "added" date
changes, and its "last seen" value starts again. Thus two rows with the same
machine label are two machines, or one machine whose previous key was lost (a
rebuilt profile, or a cleared TPM). They are never one machine that only signed in
again.

**The history is in `deploy/state/broker-audit/audit.log`, and you must keep that
file.** `kbmanage device list` shows the grants that exist *now*, and a revoked
grant leaves no trace in the directory. Each action writes one timestamped `GRANT`
or `REVOKE` line, with the account and the same eight-character id. A delegated
action has a second name, `by=<login>`. **That is the only permanent record of who
authorized a machine for a different person.** The file is append-only, and
nothing rotates it for you. Point `logrotate` at it with `create` and a
`postrotate` line that runs `docker compose kill -s SIGUSR1 broker`. That command
makes the broker write to the new file. Back the file up.
[Audit trail (`deploy/README.md`)](../../deploy/README.md#audit-trail) gives the
full description, which includes the issuer-side copy.

Remove the `#` from `#device_grant_notify = "off"` in `configs/sync.toml` and set
it to `7` to notify the KerBridge operator when a device grant is in the last
seven days before its deadline. That default also keeps machine labels out of
your notification channel until you ask for them.
A grant that is past its deadline stays in the count until its row is revoked.
Thus, when the number becomes zero, the grants are removed, not only lapsed. The
value must be `off` or a number. With a different value, sync stops at startup; it
does not guess.

## Lowering or turning it off

The effective deadline is the `min()` in [Day 2](#day-2). Thus:

- **A decrease takes effect quickly**: in at most one ticket lifetime, the same as
  each other control here.
- **The value 0 stops every device**, not only new ones. Those machines change
  back to a browser or Windows sign-in and continue to work. They also keep the
  grant that they hold. Thus, when you turn the feature on again, each grant that
  the `min()` above keeps alive becomes active again. A grant that is older than
  the new number stays dead until it is authorized again. The same applies when
  you remove a user from the group.
- **An increase does not extend** a grant that a user authorized before. The user
  authorizes the machine again, or the grant ends at its original deadline.

While the feature is off, the tray has no Authorization group, thus no method to
release a grant. The broker also refuses a *revoke*. Access does not change,
because the broker refuses each device-grant request. But the grants remain as
unwanted data: each one continues to hold a `device_grant_max_per_user` slot if
you turn the feature on again. Remove them with `kbmanage device revoke`, which
writes to the directory directly and works when the feature is on or off.
`kerbridge --grant-give-up` on the machine destroys the local key, but the broker
refuses the revocation in that window, so the directory row stays.

## Security implications

The server cannot know the difference between a TPM key and a software key, and
the server does not do attestation. Do not turn on the feature if malicious
clients are a risk for you.

With a TPM key, malware that runs as that user can *use* the key while the key is
on that machine, but the malware cannot move the key to a different location. With
a software key, an attacker can copy the key from the machine and get tickets as
that user, from anywhere, with no browser and no Entra, until the grant ends. The
normal refresh token of the tray is only in memory. Compared with that, the
feature makes the exfiltration window longer: from hours to `device_grant_days`.
Two things limit this: that number, and the device-grant group. If you cannot
accept the window, decrease the duration.

## Unattended machines: the counter-intuitive part

[Ticket policy (`DESIGN.md`)](../../docs/design/tickets.md#ticket-policy) gives
**shorter** ticket lifetimes as a hardening option. On an unattended build machine
you usually want a **longer** one instead.

This is the reason. The tray injects a new ticket at approximately half of a
ticket lifetime. A broker outage or a stopped tray can prevent this. If the ticket
then lapses under an open SMB session, the Windows redirector changes to NTLM.
NTLM does not succeed, and the redirector stays in that state until the
Workstation service is restarted. Your tolerance for an outage before this occurs
is approximately *half of a ticket lifetime*: five hours at the 10-hour default,
thirty minutes at one hour. When you make the lifetime shorter to harden a build
farm, you make the farm fail more easily.

The tray tries to repair this condition itself. When the tray finds the NTLM
fallback, it restarts the connection service without a prompt. This succeeds
immediately if that account is a local administrator. The tray makes one attempt
for each episode, and no more attempts until a ticket exchange succeeds. Retries
without a limit during a broker outage would overload the machine.

An unattended machine needs two more things. The feature does not supply them
automatically:

- The tray must run in the auto-login interactive session. A service that injects
  into the session of a different user is not supported. The ticket must go into
  the user's own (non-elevated) logon session, or the Windows SMB redirector
  cannot see it.
- The tray needs restart-on-failure. If the tray stops at 03:00, the ticket
  lapses, and a lapse while a build holds a share open is the worst case above.

Nothing reports an NTLM-degraded machine to you. If the automatic repair fails, a
build system usually finds the problem when a publish fails. KerBridge does not
report the condition remotely.
