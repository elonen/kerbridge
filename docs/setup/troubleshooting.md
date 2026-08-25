# When it does not work

Companion to
[step 8 (*Verify end to end*) in SETUP.md](../../SETUP.md#8-verify-end-to-end).

Read the first section *before* you debug a ticket problem. Some commands that
look harmless destroy a correct ticket. You then search for a fault that you
caused yourself.

## Commands that will ruin your test

- **`klist get <spn>`** destroys a valid injected TGT. This was measured, and
  it happens each time.
- **`klist purge`** has no realm filter. It also removes the user's own Entra
  tickets. Use `kerbridge.exe --sign-off`, which is realm-scoped.
- **`klist tgt`** crashes on Entra-joined builds.

Run `klist` from a **non-elevated** prompt. An elevated shell is a different
logon session with a different ticket cache, and it shows you nothing.

## SMB stops working after a ticket expires

When a TGT expires while an SMB session is open, Windows changes to NTLM and
stays there. Re-injection does not clear this condition, and a purge does not
clear it. The NTLM fallback can never succeed, because the realm has no
password for a cloud identity. So the drive stays unserviceable until you
restart the redirector.

- **Repair:** use **menu → *Repair …***, or `kerbridge.exe --repair`. This
  restarts the Workstation service.
- **Warn the user first.** The repair disconnects every network drive on the
  machine.
- Automatic detection of this condition is not implemented. The user must
  identify the symptom "my network drives stopped working" without help.

## Symptom to cause

| Symptom | Cause |
|---|---|
| `make ready` says that `endpoint` failed on the certificate | Issuance can be slow — wait, then run it again. If it fails again, the cause is the strategy's material: [`compose-deployment.md`](compose-deployment.md#supply-the-certificate) |
| Every sign-in is rejected, and nothing in the config set looks wrong | The broker API issues v1 tokens. This is the most common setup failure: [`entra.md`](entra.md#entra-defaults-that-are-wrong-for-kerbridge) |
| A token request fails with `AADSTS500011` | The broker API has no Application ID URI |
| Windows sign-in fails with a redirect-URI mismatch | The public client does not have the WAM redirect URI |
| Sync logs 403 on every Graph read | Admin consent was not given for `User.Read.All` / `Group.Read.All` |
| `sync` stays `idle` | There is no credential file. [Enable synchronization (`broker-host.md`)](broker-host.md#enable-synchronization) |
| Every sync write is denied; `kbmanage` group verbs say `insufficientAccessRights` | The `svc-kerbridge-sync-entra` / `svc-kerbridge-manage` delegations are missing. A refusal during the bootstrap is fatal and names itself, so they were removed afterwards or never applied. Run the directory step again — it is idempotent |
| Sync logs `reconciliation FROZEN` and applies nothing, every cycle | The Graph read returned no users, but the directory contains some. The usual cause is a Graph or permissions fault. Sometimes a person emptied the admission group intentionally. Sync will not empty the directory because of one empty read. Put a member back, or remove the accounts one at a time with `kbmanage cloud delete` |
| `samba-ad-dc` dies at every start with `winbindd daemon died with exit status 1` | A standalone `winbind.service` (or `smbd`/`nmbd`) still runs. The DC runs both daemons itself, as children of `samba`, and the child cannot have the socket the old one holds. `systemctl disable --now winbind smbd nmbd`, then start `samba-ad-dc`. `kbsetup realm` does this for you; a unit re-enabled afterwards comes back |
| `samba_dnsupdate` logs `WERR_DNS_ERROR_RECORD_ALREADY_EXISTS` every ten minutes, and `Failed DNS update with exit code 29` | The DC's own `/etc/resolv.conf` does not name the DC, so no record in the realm zone verifies and every one is rewritten. [`dns-and-firewall.md`](dns-and-firewall.md#the-dcs-own-resolver) |
| A KerBridge unit is `failed` and `systemctl status` gives no reason for it | Five restarts fill the ten lines that `status` prints with systemd's own, and the daemon's last words are above them. `kbsetup status` quotes that line per failed unit; `journalctl _SYSTEMD_UNIT=<unit>.service -n 30` is the same thing by hand. `-u <unit>` is what puts systemd's messages back in |
| A service refuses to start and names `ldap_url` (`realm.toml`) or `listen` (`broker.toml`) | The binary itself validates both values, not only `kbconfig check`. `ldap://` would put the bind password on the wire. A non-loopback listener would put the ticket API there without encryption |
| The Windows client stops responding and shows no error | An AAAA record is in the answer. [`dns-and-firewall.md`](dns-and-firewall.md#the-records) |
| NAS Access installs and starts, but there is no tray icon | Windows 11 hides an icon that it did not see before. [First run (`windows-client.md`)](windows-client.md#first-run) |
| The client says `TLS error` | The client reports the certificate that the host really supplied — subject, the names that it covers, issuer, validity — in the elevated dialog and in its log. Those four fields identify the three causes: a name that the certificate does not include, a date that has passed, or an issuer that this machine does not trust. For a trust failure at the *elevated* step only, see [`windows-client.md`](windows-client.md#installer-contents) |
| Only the macOS client says `TLS error`; Windows clients are fine | The certificate is valid for more than 398 days. macOS refuses this, even when the root is trusted. Issue a shorter certificate — [TLS strategy (`names-and-decisions.md`)](names-and-decisions.md#tls-strategy) |
| Every request is reset after a broker restart | Caddy was orphaned. Run `docker compose restart caddy` |
| The agent says that the broker is rate limiting; the log shows `too many requests in flight` | Either real concurrency above `max_inflight` (`configs/broker.toml`), or a client that retries in a loop. Find out which one first. Only then uncomment `#max_inflight = 16`, raise the value, and restart the broker — [What bounds a flood (`deploy/README.md`)](../../deploy/README.md#what-bounds-a-flood) |
| Sign-in succeeds, but the user can open nothing | This is the correct behavior. Realm admission is not authorization — [step 6 in SETUP.md](../../SETUP.md#6-authorize-cloud-identities-on-smb-share) |
| The share opens, but `klist` names no KDC for the `cifs/` ticket | NTLM fallback happened. Usually the share was opened by IP address, which gives no SPN |
| The agent never offers *Device grant* | Device grants are off in the deployment, or the agent signed in before they were turned on — sign out, then sign in again. [`device-grants.md`](device-grants.md#what-a-user-does) |
| A device grant is refused with `account may not authorize a device` | The user is in the admission group, but not in the device-grant group. That group is the second gate. [`device-grants.md`](device-grants.md#turning-it-on) |
| `--grant --for` is refused with `you may not authorize a device for that account` | The sign-in was correct, but the delegate group of that account does not contain this person. A new sign-in will not correct this. [`device-grants.md`](device-grants.md#on-the-server) |
| A build machine publishes artifacts owned by the engineer who set it up | The machine holds a self-grant, not a delegated grant. `kerbridge --grant-status` shows which one. Authorize it again with `--for`, or set the pin. [`device-grants.md`](device-grants.md#at-the-machine) |
| `--grant` is refused with `too many devices` | The `device_grant_max_per_user` limit (`configs/main.toml`) was reached. Frequently the rows come from machines that were discarded while the feature was off. Run `kbmanage device list`, then revoke the dead rows |
| Sync stops at startup and names `device_grant_notify` | The value must be `off` or a number of days. With a different value, sync does not start, and it does not guess |
| Anything on the file server itself | [Troubleshooting (`file-server.md`)](file-server.md#troubleshooting) — a table by symptom, which includes idmap and `nsswitch.conf` faults |

## Before the diagnostics: is the deployment finished?

On the server, when nothing works yet and you are not sure how far you got:

```sh
sudo kbsetup status
```

It marks each step of the procedure done or outstanding, and prints the command
for the next one. Most of what looks like a fault on a new host is a step that
was never run — a realm that was never provisioned, or a cloud IdP credential
that was never pasted in. `status` changes nothing, so it is safe to run at any
point.

It answers some steps with `[?]` rather than a verdict, because they cannot be
seen from that host: the TLS terminator is a program KerBridge does not ship,
and a unit's state is a sentence in its own journal.

## The diagnostic that walks the whole chain

`doctor` starts where `status` finishes: `status` asks whether the server was
built, `doctor` asks whether an identity can reach a file server through it.

```sh
kbmanage doctor --user alice
```

The command names the first broken link, with the command that repairs it. It
checks that:

- the object exists;
- the external identity decodes;
- the account is enabled;
- the admission group is reachable;
- the resource group is nested;
- the group is domain-local.

With no arguments, `doctor` examines the directory for structural problems:

- duplicate identities;
- a missing or duplicated admission group;
- live groups that are nested into nothing;
- retired objects that still hold a name.

`--endpoint <url>` adds the public URL that a workstation enrolls against.

`doctor` cannot see the filesystem. At the end it prints the
`id 'EXAMPLE\<user>'` command. Run that command on the file server yourself.
