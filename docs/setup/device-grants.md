# Device grants: letting a machine skip the user sign-in

This feature is off by default. Read this page before you turn it on. One of
the settings below has a meaning that is different from what its name suggests.

The design is in [Device grants (`DESIGN.md`)](../../docs/design/tickets.md#device-grants).

## What it is

Usually, KerBridge requires a browser or Windows sign-in from the user before
it issues a Kerberos ticket. A **device grant** changes this. After one normal
Entra sign-in, the user can authorize *this machine* to continue to get
tickets with their account, without a browser. The grant is valid for a number
of days that you choose. The authorization is a key in the **TPM** of that
machine. The key cannot be exported from the machine.

There are two reasons to use the feature:

- **An unattended machine.** An example is a build server that signs in
  automatically at boot and publishes artifacts to a file server over SMB. Without a
  person at the keyboard, such a machine cannot hold a Kerberos identity.
- **Ordinary users** who do not want to sign in again each ticket lifetime.

By default, the machine gets tickets as the person who authorized it. For an
unattended machine, this is usually not what you want. The build must publish
as a service account, not as the person who installed the machine.
**Delegation** makes this possible: see
[Machines that publish as a service account](#machines-that-publish-as-a-service-account).

## The thing to read twice

> **Note:** You can revoke access before the grant ends.

Each method that removes access takes effect in at most one **ticket**
lifetime. This is the same as with regular user sign-in. The methods are:

- Remove the user from a group.
- Disable the account.
- Run `kbmanage device revoke`.
- Turn the feature off fully.

The broker examines all of these again each time a device asks for a ticket.

`device_grant_days` limits a different thing: the time that a machine can
operate before a person must prove the identity to Entra again. Choose the
number for *that* reason. It is not a revocation window. Operators who use it
as a revocation window set the number much too low. Then a person must go to
the build machine each week.

## Turning it on

Two settings turn the feature on. Then run `make up`.

```toml
# configs/main.toml
device_grant_days = 30                 # 0 is off, and 0 is the default

# configs/idp_entra.toml, inside [provider_config]
device_grant_group = "KerBridge Device Grant Users"
#device_grant_group_id =               # alternative to the name
```

Two more settings change how the feature behaves. Each is already at the value
that suits most deployments: `device_grant_max_per_user` is 10, and
`device_grant_notify` is `"off"`. Leave both lines commented out until you want
a different value.

| Setting | Lives in |
|---|---|
| `device_grant_days` | `configs/main.toml` |
| `device_grant_max_per_user` | `configs/main.toml` |
| `device_grant_notify` | `configs/sync.toml` |
| `device_grant_group`, `device_grant_group_id` | `configs/idp_entra.toml`, `[provider_config]` |
| `admission_group`, `admission_group_id` | `configs/idp_entra.toml`, `[provider_config]` |

**The grant group is a second gate, not a bypass for the admission group.**
A user must be in the admission group *and* in this group. Create the group in
Entra, adjacent to `admission_group`. Sync will synchronize the group
whether you nest it in the admission group or not. The broker examines the
membership again at each ticket exchange. Thus, when you remove a user from
the group, each device that the user holds stops. To give the feature to all
users, put all users in the group. A shortcut: add the admission group itself
as a member.

If you use delegation, this shortcut has an extra effect: **each member of
this group is a possible delegation target**. If you put the full company in
the group, a delegate can be appointed for each person in it. This can be what
you want. It is how you let a person operate for a colleague who is on leave.
But make this a decision, not an accident.

You can also identify the group when you set `device_grant_group_id` to
its Object ID. Then you can rename the group in Entra, and the configuration
continues to work. Set the group name _or_ the ID, never both. If you set
both, sync refuses to start.

If neither the group name nor the ID is set, no device grant can be created or
used. The value of `device_grant_days` does not change this. This is
intentional: the broker looks up the group, and when the broker does not find
one, it denies all device-grant requests.

If you point `device_grant_group` at a different Entra group, the change
applies at the next sync cycle. A user who is not in the new group loses each
device that they hold, at the device's next ticket exchange. There is one
change that sync will not apply: when you unset the name. Sync then writes a
message in its log and continues with the current group, which is stored in
LDAP. To disable grants fully, leave `#device_grant_days = 0` commented out
in `configs/main.toml`, or comment it back — `0` is already the default.

`device_grant_max_per_user` (`configs/main.toml`) is a safety limit, not a policy. The limit stops a
compromised broker before it makes a directory object too large. With
delegation, the limit applies to a **fleet**, not to one person, and that is
the normal case: twenty build machines that are authorized for one
`svc-unreal-builder` account make twenty device grants on that one object.
Set the value for the size of the fleet.

## What a user does

On the machine, open the tray agent and go to **Settings → Advanced →
Authorization**. The group shows only when the feature is on. The group
operates only for a user who is in the device-grant group. When the machine
holds a grant, the same location shows a status row: *Access authorized as
&lt;account&gt;*. A **Remove authorization…** button is adjacent to the row.
The tray shows a warning when seven days or less remain before the deadline. If
a TPM cannot store a key for the grant, the feature fails.

**A sign-out does not give up the grant.** When grants are on, the tray
divides sign-out in two actions. *Sign out of Entra* removes the SSO cookie
and the in-memory refresh token. *Sign off* removes the Kerberos tickets.
Neither action changes the grant. On a delegated machine, the person who signs
out does not own the grant. The grant belongs to the target account and to the
person who authorized it. **Remove authorization…** is the action that ends the
grant. It first deletes the key from the TPM, which works offline. It then
tells the broker.

This division has a consequence when you **turn the feature off** while
machines still hold grants. The Authorization group is part of the grants-on
UI, so the group also goes away, and sign-out does not give up a grant. Thus
the tray has no method to release a grant. This does not change access: the
broker refuses each device-grant request while `device_grant_days` is 0, so
those grants authorize nothing. But the grants remain as unwanted data: each
one continues to hold a `device_grant_max_per_user` slot if you turn the
feature on again. Remove them from the server with `kbmanage device revoke`.
That command writes to the directory directly, so it works when the feature is
on or off. `kerbridge --grant-give-up` on the machine is different: it destroys
the local key, but the broker refuses the revocation in that window, the same as
each other device-grant request, so the directory entry stays.

### Without the GUI

The CLI client is installed adjacent to the tray in
`%ProgramFiles%\KerBridge\`. You can use it to manage device grants
programmatically:

```sh
kerbridge --grant                # authorize this machine; signs in first
kerbridge --grant-status         # what this machine holds, and its pin. Offline
kerbridge --grant-list           # list every device on the account
kerbridge --grant-give-up        # hand this machine's own grant back. Offline
kerbridge --grant-revoke <id>    # stop another device; signs in first
kerbridge --no-grant             # ignore the grant for one run; the browser instead
kerbridge --grant --for svc-x    # authorize this machine for another account
```

The tray and the CLI read the same `config.toml`. Thus a grant that you make
with one tool is used by both tools. `--grant-status` gives one answer that
the tray and the server-side `kbmanage` cannot give: it compares the claims in
the file with the keys that the TPM holds. When the two do not agree, the
cause is a rebuilt profile or a cleared TPM.

## Machines that publish as a service account

A build machine must publish as `svc-unreal-builder`, not as the engineer who
installed it. But no person is permitted to know the password of that account.
Thus no person can sign in as that account at the machine. A device grant
normally needs that sign-in.

**Delegation** is the solution. You name a group of people who can authorize
machines *for that account*. One of them signs in at the machine as
themselves, and the machine then holds a grant for the service account. After
that, the identity of the engineer is not used. No ticket of the engineer is
injected on that machine, and the machine does not use the credentials of the
engineer.

### In Entra

The service account is an **ordinary Entra user**.

- Create it the same as any other user.
- Put it in the admission group and in the device-grant group.
- Keep it enabled.

Sync mirrors `accountEnabled`, and a disabled account gets nothing.

**Put a Conditional Access policy on the account.** KerBridge does not require
this policy, and the feature works without it. But the policy gives this exact
protection: without it, each person who can *reset the password of that
account* can sign in as the account and get a ticket directly, with no TPM and
no grant. The roles that can do this — Helpdesk Administrator, Password
Administrator — are usually given much more widely than admission-group
membership. A policy that blocks interactive sign-in for the account removes
this risk.

### On the server

The delegate group is a resource group that you own, outside `OU=CloudIdP`:

```sh
kbmanage group new svc-unreal-builder-delegates
kbmanage device delegate set svc-unreal-builder svc-unreal-builder-delegates
kbmanage group member add svc-unreal-builder-delegates build-engineers
```

The last line nests your synced Entra group into the delegate group. This is
the usual method to authorize anything here. Each member of `build-engineers`,
at each level of nesting, can now authorize a machine for
`svc-unreal-builder`.

**Each account has one delegate group. This is intentional.** `delegate set`
replaces the link: it removes the link from each other group that points at
that account, and it reports which group it changed. To let *two* populations
authorize the same account, nest both of their Entra groups into the one
delegate group. Do not make a second delegate group. Then `kbmanage doctor`
shows one chain, and there is no unclear state with more than one partially
delegated group.

A delegate does not need a device grant of their own and does not join the
device-grant group. But a delegate **must** be admitted to the realm: the
delegate group is examined in addition to admission, never instead of it.

### At the machine

Point the machine at the account one time. Use `--for` on the command line, or
use a pin that stays through reinstalls:

```sh
kerbridge --grant --for svc-unreal-builder
kerbridge --grant-status                     # the pin and what is actually held
```

The pin is stored in `HKLM` or in the user's `config.toml`. The machine-wide
value is `GrantFor` under `HKLM\Software\Policies\KerBridge`, which Group
Policy, Intune or an imaging script writes — see
[windows-client.md](windows-client.md#preconfiguring-a-fleet). The MSI does not
write it. The machine-wide value has priority.
The tray shows the machine-wide pin as read-only. The tray does not show it as
a value that you can edit.

On a pinned machine, the button in the tray shows **Authorize access…**, not
*Sign in…*, because that is the only thing that it does. The pinned account is
above it, in the *Authorize this device for* field. The sign-in of the engineer authorizes the key and then stops. It never
injects the ticket of the engineer. `--no-grant` is the exception, and it
shows this clearly: it signs in and injects a ticket **as you**, for that one
run. The tray then gets a ticket as the service account again at its next
cycle.

The pin is an input at authorization time, not a switch. A machine that
already holds a grant for one account continues to get tickets as that
account. The pin does not change this. A change to the pin applies at the next
re-authorization, when a person is at the keyboard. `--grant-status` is the
only place that shows the pin and the held grant together.

### What you give up

There is no interactive method to test the share access of the service
account. There is no run-as function. This is intentional. Debug from the
machine that holds the grant.

### When a delegate leaves

**When you remove a person from a delegate group, this revokes nothing.**
Grants are stored on the target account, and the broker tests them against the
membership of the *target*. Thus, when you remove an engineer, the engineer
cannot authorize **new** machines, but the machines that they authorized
before continue. Those machines operate until their `device_grant_days`
deadline, and each delegate who remains can renew them.

To stop the machines that the person enrolled:

```sh
grep 'GRANT .* by=alice' deploy/state/broker-audit/audit.log
kbmanage device revoke <id>          # for each one you find
```

The audit file is the only record of who authorized what. That is why you must
keep it (see [Day 2](#day-2)). If you want to stop all access from the
machines of that account at one time, remove the **service account** from the
device-grant group. That stops each device on the account, delegated or not,
at the next ticket exchange.

## Day 2

Use these commands on the server:

```sh
kbmanage device list                # every authorized device
kbmanage device list alice          # just one user's
kbmanage device revoke 1a2b3c4d     # stop one, by the id `list` prints
kbmanage device delegate list       # every delegation chain
kbmanage doctor --user alice        # includes a device-grant line if she holds any
```

The **"sign-in required by"** column does not mean "expires". It means that a
person must be at that machine, in a browser, before that date. The value is
the date stamped in the directory, which is the data that `kbmanage` can see:
`kbmanage` talks to the DC. `kbmanage` does not see your `device_grant_days`
value. When you decrease that setting, the enforced date becomes earlier, but
this column does not change. Thus use the column as an upper limit: the
enforced date is `min(this, added + device_grant_days)`, never later.

Revocation uses the eight-character id, not the machine label. The label is
the text that the machine reported, so two machines can report the same label.
The id is derived from the TPM key and is always unique.

Because the id comes from the key, the id also stays the same through a
re-authorization. A machine that is authorized again keeps its row and its id.
Its "added" date changes, and its "last seen" value starts again. Thus two
rows with the same machine label are two machines, or one machine whose
previous key was lost (a rebuilt profile, or a cleared TPM). They are never
one machine that only signed in again.

**The history is in `deploy/state/broker-audit/audit.log`, and you must keep
that file.** `kbmanage device list` shows the grants that exist *now*. A
revoked grant leaves no trace in the directory. The audit file is the location
where a grant that is gone continues to appear. Each action writes one
timestamped `GRANT` or `REVOKE` line, with the account and the same
eight-character id. A delegated action has a second name, `by=<login>`.
**That is the only permanent record of who authorized a machine for a
different person.** Thus, when you use delegation, this file is necessary, not
optional. The file is append-only, and nothing rotates it for you. Point
`logrotate` at it with `create` and a `postrotate` line that runs
`docker compose kill -s SIGUSR1 broker`, which is what makes the broker start
writing to the new file, and back it up. [Audit trail (`deploy/README.md`)](../../deploy/README.md#audit-trail)
gives the full description, which includes the issuer-side copy.

Remove the `#` from `#device_grant_notify = "off"` in `configs/sync.toml` and
set it to `7` to notify the KerBridge
operator when a device grant is in the last seven days before its deadline.
The notification is off
by default. This default also keeps machine labels out of your notification
channel until you ask for them. A grant that is past its deadline stays in the
count until its row is revoked. Thus, when the number becomes zero, the grants
are removed, not only lapsed. The value must be `off` or a number. With a
different value, sync stops at startup; it does not guess.

## Lowering or turning it off

The effective deadline is `min(what was stamped, start + device_grant_days)`.
The broker calculates this each time a device asks for a ticket. Thus:

- **A decrease takes effect quickly**: in at most one ticket lifetime, the
  same as each other control here.
- **The value 0 stops every device**, not only new ones. Those machines
  change back to a browser or Windows sign-in and continue to work. They also
  keep the grant that they hold. Thus, when you turn the feature on again,
  each grant that the `min()` above keeps alive becomes active again. A grant
  that is older than the new number stays dead until it is authorized again.
  The same applies when you remove a user from the group.
- **An increase does not extend** a grant that a user authorized before. The
  user authorizes the machine again, or the grant ends at its original
  deadline.

There is one asymmetry while the feature is off: the broker also refuses a
*revoke*. Thus a machine that gives up its grant in that window keeps its
directory row. The row is dead, because the key is destroyed locally. But the
row uses a `device_grant_max_per_user` slot when the feature comes back, until
`kbmanage device revoke` removes it.

## What this costs you, stated plainly

The server cannot know the difference between a TPM key and a software key,
and the server does not do attestation. Do not turn on the feature if
malicious clients are a risk for you.

With a TPM key, malware that runs as that user can *use* the key while the key
is on that machine, but the malware cannot move the key to a different
location. With a software key, an attacker can copy the key from the machine
and use it to get tickets as that user, from anywhere, with no browser and no
Entra, until the grant ends. The normal refresh token of the tray is only in
memory. Compared with that, the feature makes the exfiltration window longer:
from hours to `device_grant_days`.

Two things limit this: that number, and the device-grant group. If you cannot
accept the window, decrease the duration.

## Unattended machines: the counter-intuitive part

[Ticket policy (`DESIGN.md`)](../../docs/design/tickets.md#ticket-policy) gives **shorter**
ticket lifetimes as a hardening option. On an unattended build machine, you usually want a **longer** one
instead.

This is the reason. The tray injects a new ticket at approximately half of a
ticket lifetime. A broker outage or a stopped tray can prevent this. If the
ticket then lapses under an open SMB session, the Windows redirector changes
to NTLM. NTLM does not succeed, and the redirector stays in that state until
the Workstation service is restarted. Your tolerance for an outage before this
occurs is approximately *half of a ticket lifetime*: five hours at the 10-hour
default, thirty minutes at one hour. When you make the lifetime shorter to
harden a build farm, you make the farm fail more easily.

The tray tries to repair this condition itself. When the tray finds the NTLM
fallback, it restarts the connection service without a prompt. This succeeds
immediately if that account is a local administrator. The tray makes one
attempt for each episode, and no more attempts until a ticket exchange
succeeds. Retries without a limit during a broker outage would overload the
machine.

An unattended machine needs two more things. The feature does not supply them
automatically:

- The tray must run in the auto-login interactive session. A service that
  injects into the session of a different user is not supported. The ticket
  must go into the user's own (non-elevated) logon session, or the Windows SMB
  redirector cannot see it.
- The tray needs restart-on-failure. If the tray stops at 03:00, the ticket
  lapses, and a lapse while a build holds a share open is the worst case
  above.

Nothing reports an NTLM-degraded machine to you. If the automatic repair
fails, a build system usually finds the problem when a publish fails.
KerBridge does not report the condition remotely.
