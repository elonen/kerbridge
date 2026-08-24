# Known rough edges

An honest list of the parts that are not finished. The items are in the order
in which you meet them when you follow [`SETUP.md`](../../SETUP.md). No item
here is theoretical. Each one comes from a real run.

Each item states the limit, then what it costs you. The measurement behind it,
where there is one, is in the collapsed block.

## The DC advertises an address that only its host can reach

This applies to a Docker Compose deployment. Provisioning registers the DC's A
record with its container address, and a member that joins registers its own A
record the same way. So what Samba's own DNS says about the realm is true
inside the bridge only.

**What to do:** resolve the realm from your site's own resolver, as
[dns-and-firewall.md](dns-and-firewall.md) describes. The defect that stays is
that Samba's zone and the site's zone do not agree, and only one of them is
correct.

Host networking removes the problem. But then you cannot run `nas1` on the same
machine — see
[Host networking and DNS (`DESIGN.md`)](../../docs/design/api-and-network.md#host-networking-and-dns).
`KERBRIDGE_SUBNET` and `REALM_IPV4` stay in `.env` for the same reason.

## Sync authenticates with a client secret

A certificate credential is the intended default, and it is not built.

**What to do:** set `sync_credential_expires` in
`configs/idp_<source>.toml`'s `[provider_config]`, so that sync warns you
before the secret expires. Update the value each time that you rotate the
credential. If you do not, sync reports months of remaining time on a dead
credential.

## A rename in Entra signs that user out one time

Login names follow the Entra display name (`automatic_sam_renames` in
`configs/sync.toml`, default on). The login name is also the user's Kerberos
principal, so a rename invalidates the tickets that were issued under the old
name.

**What to do:** at the next cycle after the change, the user must sign out and
sign in again, or purge the tickets and inject them again. No other user is
affected, and nothing on the disk moves, because the ACLs hold the SID.

`kbmanage cloud rename <account> --to <name>` sets a name manually and pins it
against all of the above. Use it when the derived name is legal but wrong.
`kbmanage cloud unpin <account>` returns the name to automatic control.

<details>
<summary>Why the name follows the display name, and two surprises</summary>

Windows shows the login name as the file owner and in the *Security* tab. If
the files of a person who is now called Jane Doe show `EXAMPLE\jane.smith`,
then the directory fails at its job.

First surprise: if you change `sam_source` in `configs/sync.toml` while renames
are on, one cycle renames *each* user whose name derives differently under the
new source. To stage that change, set `automatic_sam_renames` to `false` first.

Second surprise: the retire/return path derives the name again, and this
setting has no effect on it. An account that leaves the admission group and
comes back can return with a different name than the name it left with. That
path loses the name by design: retirement truncates the held name to 11
characters, and to remove the prefix would bring back the truncated name.

</details>

## Operator notification is off until you give it a URL

`secrets/notify_url` ships empty, and `url_file` ships commented out. Until you
set both, the only channels are the sync log and the problem directory.

**What to do:** follow
[Operator notification (`broker-host.md`)](broker-host.md#operator-notification).

<details>
<summary>What was measured, and what was not</summary>

The webhook notifier works: on 2026-07-30 a `make test-notification` message
arrived in a real Slack channel. These events were **not** seen on a live
deployment:

- a real event, not the synthetic test, that arrives in a channel;
- a recovery after such an event;
- suppression over real time, by the repeat interval and by the
  30/14/7/3/1-day expiry schedule.

Unit tests cover all of these, but none was seen in the field. So the first
month of a pilot is where you find out that an event repeats more frequently
than you want.

</details>

## No code signing, and no ADMX

The MSI is unsigned, so SmartScreen shows a warning and each UAC prompt says
"unknown publisher". There is no Group Policy template either.

**What to do:** accept it for a pilot. A fleet needs a signature, and that is a
release-time act by the publisher.

<details>
<summary>Why signing also needs a build change</summary>

`make installer` compiles and packages in one Docker build, so there is no
point at which you can sign the *exes* before they are embedded. A signature on
the package alone leaves the binary that autostarts and elevates through UAC —
the one that SmartScreen judges — unsigned. A release must split the stages:
build the exes → sign them → package → sign the MSI.

</details>

## Windows 11 hides the tray icon the first time

The agent registers correctly and runs. Windows 11 puts a notification-area
icon that it has not seen before into an overflow area, and the taskbar can
show no chevron for that area. Users read a hidden tray icon as a failed
installation.

**What to do:** tell pilot users where the switch is — *Settings →
Personalization → Taskbar → Other system tray icons*. If you do not, the first
report that you get says that nothing happened.

<details>
<summary>Why the agent does not set the switch itself</summary>

The agent intentionally does not write `IsPromoted`: an application that
promotes itself decides its own importance on the taskbar of another person.

Measured on Windows 11, 2026-08-05. The icon now carries a fixed identity, and
it is not keyed by the path that it runs from, so the switch stays set through
an upgrade. But the first build that carries the fixed identity is itself a new
identity, so each user who already runs the agent must set the switch one more
time.

</details>

## The Mac has no installer, and its bundle is ad-hoc signed

`make macos` writes `dist/NAS Access.app`, and you copy it to `/Applications`
yourself. There is no `.pkg`, no `.dmg` and no MDM payload.

**What it costs you:** System Settings ▸ Login Items lists the agent as *Item
from unidentified developer*, and a bundle that arrives from a different
machine is quarantined until a person permits it in Privacy & Security. Ad-hoc
signing also blocks the Secure Enclave device grant, which needs a
keychain-access-group entitlement, which needs a real signing identity.

The repair is a Developer ID signature and notarization. Like the MSI, that is
a release-time act by the publisher.

## On a machine with no PRT, one dialog decided if renewal would ever work

Windows asks *"Sign in to all apps and websites on this device?"*. The answer
*"No, this app only"* keeps the account out of the Windows account manager,
WAM then has no account for renewal, and silent re-injection fails with
`0xcaa10001 Need user interaction to continue`.

**What to do:** nothing, on a current build. The client no longer asks the
question: a failed silent attempt goes directly to the browser. **On a build
made before this change, answer *Yes*.**

**What it still costs you:** the first sign-in after a restart is a real
interactive sign-in, with credentials and MFA if your policy asks for them. A
machine with a PRT signs in at logon with no prompt.

<details>
<summary>The measurements behind this</summary>

Measured on a non-Entra-joined client, 2026-07-30: *"No, this app only"* let
the ticket expire, and *"Yes"* re-injected on schedule with no user action. An
expiry with an open SMB session is also the path to the stuck NTLM fallback.
Nothing warned the operator at the time: the choice was in a Microsoft dialog
that you do not control, and the effect appeared about half a ticket lifetime
later.

The same day, on a client whose device registration was removed
(`dsregcmd /leave`), the silent attempt failed with that same `0xcaa10001` and
the browser opened in the same second, with no Windows dialog between the two.
This happened at the sign-in, and again at the unattended renewal 27 minutes
later. That renewal used the refresh token, with no browser at all. Three
consecutive re-injections ran with no browser and no user, and the end time of
the injected ticket matched what the broker issued.

The Entra-joined machine — where the silent attempt is the one that *succeeds*
— was tested again the same evening and showed no change: after a reboot the
tray autostarted and had a TGT two seconds later, through WAM, with no window
shown.

The cost comes at startup, not during a session. The in-memory refresh token
dies with the tray, and the browser's Entra session dies with the browser, so a
reboot leaves neither. Only the forced re-authentication after a sign-out still
opens the dialog, and only on a machine where the first sign-in was through
WAM.

</details>

## Device grants were tested one time, carefully

The feature is off by default.

**What to do:** read [`device-grants.md`](device-grants.md) before you turn it
on, and pilot it on one machine.

**The edge that remains:** the broker refuses a *revoke* while the feature is
off. So a device that is given up in that window keeps its dead directory row
and one `device_grant_max_per_user` slot, until `kbmanage device revoke` clears
them.

<details>
<summary>What was measured, and the two gaps beside it</summary>

The full path was measured end to end on 2026-08-01, on one machine with a real
firmware TPM: the machine was authorized with `kerbridge --grant`, it got a
ticket with no browser, and from that ticket it got a `cifs/` service ticket
and read a file over SMB. The tray's own menu path and each CLI verb followed
on 2026-08-02, revocation included. That sweep found and fixed six defects.

This is still one machine, one TPM, one deployment, debugged immediately before
the test. A second TPM implementation is unmeasured.

Two smaller gaps exist in the same area. Nothing reports a device whose Windows
connection fell back to NTLM: the tray tries to repair the connection and tells
the person at the machine, but on an unattended build machine that toast goes
nowhere, and the build system is what finds the failure. And one configuration
is untested: such a machine running as a local administrator with UAC disabled,
so that the tray can inject a ticket and restart the connection service in one
logon session. The measured fact is only this: an elevated process under
split-token UAC has a different logon session, and the redirector cannot see
the tickets of that session.

</details>

## Delegated grants: renewal-time recovery with nobody present is unmeasured

The CLI path and the tray are measured on Windows, and `make test-stack` covers
the full server path. What is not measured is recovery **at renewal time**
after an outage, with no person at the keyboard. Every recovery that was
measured came after a button press.

**What it costs you:** if injection ever breaks on an unattended machine, the
symptom is artifacts that a person owns instead of the service account. Nothing
reports this, and nobody sees it until they open a *Security* tab. So after you
change the injection path, measure again with `klist`.

**Two known display faults:** the tray calls a grant-backed machine "Not signed
in", and it offers *Authorize* as the remedy for an outage that no human can
fix. No behavior is wrong. But both show the normal state of an unattended
machine as a fault.

<details>
<summary>What was measured</summary>

`make test-stack` covers, end to end: an engineer's token that authorizes a
machine for a service account; a ticket that comes back as the *service
account*, not as the caller; a list operation and a revoke operation with a
target; and a 403 refusal for an admitted user who is outside the delegate
group.

The client path was measured on Windows 11 25H2 (build 26200) on 2026-08-03,
against a bench realm, with `RunAsPPL=2` and Credential Guard off. A machine
pinned to `svc-builder` was authorized by a browser sign-in as an engineer who
holds no credential for it. It produced:

```
#0  Client: svc-builder@EXAMPLE.SITE  Server: krbtgt/EXAMPLE.SITE
#1  Client: svc-builder@EXAMPLE.SITE  Server: cifs/nas1.example.site
```

The engineer is nowhere in the cache. The file that was written over SMB is
owned by `EXAMPLE\svc-builder`, resolved uid → SID → name through winbind and
not read from a display string. So the identity also survives the TGS exchange,
not only the injected TGT.

The tray was measured the same night, on the same machine, and every path
holds: at startup the tray refuses a ticket that is not the grant's own and
gets a new one instead of adopting it; a transport outage is reported as an
outage, and the tray recovers when it re-injects from the grant, with no
browser; a sign-out drops the tickets and does not change the grant; and *Give
up* destroys the TPM key **and** revokes at the broker, so afterwards the grant
is gone from the directory, not only flagged.

The two display faults have one shared cause: the tray shows a
signed-in/signed-out binary for a machine whose state is at least four
independent things. So the repair is a design pass, not more conditional
wording.

To measure the unattended case, use a short-lived ticket (`-l 10m -r 30m`, see
[`../windows-testbench.md`](../windows-testbench.md)). Do not wait for a
multi-hour ticket.

</details>

## Each person who shares a pinned machine's logon session runs as the service account

Injection applies to one logon session, and the tray runs for one user. So this
is not "each person who logs in inherits the account". The exposure is the one
autologin session that the tray injects into.

On an unattended machine this is intended. It is a surprise if a person sits
down at that session, or if the machine gets a new purpose. The software cannot
detect "interactive", and a build service is itself a logon session, so this
risk is documented and not guarded.

## Untested combinations

- tenants with Entra Cloud Kerberos enabled — ticket cache selection was never
  measured against a contested cache;
- workstations with Credential Guard on — injection was proven with Credential
  Guard off;
- consumer NAS appliances: Synology, QNAP, TrueNAS
  ([`file-server.md`](file-server.md) says what is known);
- clients joined to a different on-prem AD domain — out of scope by design.
  Nothing blocks it. It is simply unknown.

## No procedure yet

- **Upgrade and password rotation.** Both are absent.
- **Backup is a script, not a schedule.** `backup.sh` captures the state, and
  `restore.sh` puts it back. Both were tested in a wipe-and-restore of the
  volumes. You must arrange when they run, and where the tarballs go.
