# When it does not work

Companion to [step 8 (*Verify end to end*) in SETUP.md](../../SETUP.md#8-verify-end-to-end).
Read the first section *before* you start to debug a ticket problem. Three commands
that look harmless will destroy a correct ticket. Then you will search for a
fault that you caused yourself.

## Three commands that will ruin your test

- **`klist get <spn>`** destroys a valid injected TGT. This was measured, and
  it occurs each time.
- **`klist purge`** has no realm filter. It also removes the user's own Entra
  tickets. Use `kerbridge.exe --sign-off`, which is realm-scoped.
- **`klist tgt`** crashes on Entra-joined builds.

Also: run `klist` from a **non-elevated** prompt. An elevated shell is a
different logon session with a different ticket cache. It will show nothing.

## SMB stops working after a ticket expires

When a TGT expires while an SMB session is open, Windows changes to NTLM and
stays there. Re-injection does not clear this condition. A purge does not
clear it. The NTLM fallback can never succeed, because the realm has no
password for a cloud identity. Thus the drive stays unserviceable until you
restart the redirector.

- Repair: use **menu → *Repair …*** (or `kerbridge.exe --repair`). This
  restarts the Workstation service.
- This **disconnects every network drive on the machine**. Give the user a
  warning before you do it.
- Automatic detection of this condition is not implemented. The user must
  identify the symptom "my network drives stopped working" without help.

## Symptom to cause

| Symptom | Cause |
|---|---|
| `make ready` says `endpoint` failed on the certificate | The cause can be slow issuance only — wait, then run it again. If not, the cause is the strategy's material: [`compose-deployment.md`](compose-deployment.md#supply-the-certificate) |
| Every sign-in is rejected, and nothing in the config set looks wrong | The broker API issues v1 tokens. This is the most common setup failure: [`entra.md`](entra.md#four-defaults-that-are-wrong-for-kerbridge) |
| A token request fails with `AADSTS500011` | The broker API has no Application ID URI |
| Windows sign-in fails with a redirect-URI mismatch | The public client does not have the WAM redirect URI |
| Sync logs 403 on every Graph read | Admin consent was not given for `User.Read.All` / `Group.Read.All` |
| `sync` stays `idle` | There is no credential file. [Enable synchronization (`broker-host.md`)](broker-host.md#enable-synchronization) |
| Every sync write is denied; `kbmanage` group verbs say `insufficientAccessRights` | The `svc-kerbridge-sync-entra` / `svc-kerbridge-manage` delegations are missing. A refusal during `make up` is fatal and names itself, so they were removed afterwards or never applied — re-run `make directory`, which is idempotent |
| Sync logs `reconciliation FROZEN` and applies nothing, every cycle | The Graph read returned no users, but the directory contains some. Usually the cause is a Graph or permissions fault. Sometimes a person emptied the admission group intentionally. Sync will not empty the directory because of one empty read. Put a member back, or remove the accounts one at a time with `kbmanage cloud delete` |
| A container refuses to start and names `ldap_url` (`realm.toml`) or `listen` (`broker.toml`) | The binary itself makes sure that both values are safe, not only `make check`. `ldap://` would put the bind password on the wire. A non-loopback listener would put the ticket API there without encryption |
| The Windows client stops responding and shows no error | An AAAA record is in the answer. [`dns-and-firewall.md`](dns-and-firewall.md#the-records) |
| NAS Access installs and starts, but there is no tray icon | Windows 11 hides an icon that it did not see before. [First run (`windows-client.md`)](windows-client.md#first-run) |
| The client says `TLS error` | The client reports the certificate that the host really supplied — subject, the names that it is valid for, issuer, validity — in the elevated dialog and in its log. These four fields identify the three causes: a name that the certificate does not include, a date that has passed, or an issuer that this machine does not trust. For a trust failure at the *elevated* step only, see [`windows-client.md`](windows-client.md#what-ships) |
| Only the macOS client says `TLS error`; Windows clients are fine | The certificate is valid for more than 398 days. macOS refuses this, even when the root is trusted. Issue a shorter certificate — [TLS strategy (`names-and-decisions.md`)](names-and-decisions.md#tls-strategy) |
| Every request is reset after a broker restart | Caddy was orphaned. Run `docker compose restart caddy` |
| The tray says the broker is rate limiting; the log shows `too many requests in flight` | The cause is real concurrency above `max_inflight` (`configs/broker.toml`), or a client that retries in a loop. First make sure which cause applies. Only then uncomment `#max_inflight = 16`, raise the value, and restart the broker — [What bounds a flood (`deploy/README.md`)](../../deploy/README.md#what-bounds-a-flood) |
| Sign-in succeeds, but the user can open nothing | This is the correct behavior — realm admission is not authorization. [step 6 (*Authorize cloud identities on SMB share*) in SETUP.md](../../SETUP.md#6-authorize-cloud-identities-on-smb-share) |
| The share opens, but `klist` names no KDC for the `cifs/` ticket | NTLM fallback occurred. Usually the share was opened by IP address, which gives no SPN |
| The tray never offers *Device grant* | Device grants are off in the deployment, or the tray signed in before they were set to on — sign out, then sign in again. [`device-grants.md`](device-grants.md#what-a-user-does) |
| A device grant is refused with `account may not authorize a device` | The user is in the admission group, but not in the device-grant group. This group is the second gate. [`device-grants.md`](device-grants.md#turning-it-on) |
| `--grant --for` is refused with `you may not authorize a device for that account` | The sign-in was correct, but the delegate group of that account does not contain this person. A new sign-in will not correct this. [`device-grants.md`](device-grants.md#on-the-server) |
| A build machine publishes artifacts owned by the engineer who set it up | The machine holds a self-grant, not a delegated grant — `kerbridge --grant-status` shows which one. Authorize it again with `--for`, or set the pin. [`device-grants.md`](device-grants.md#at-the-machine) |
| `--grant` is refused with `too many devices` | The `device_grant_max_per_user` limit (`configs/main.toml`) was reached. Frequently the rows come from machines that were discarded while the feature was off. Run `kbmanage device list`, then revoke the dead rows |
| Sync stops at startup and names `device_grant_notify` | The value must be `off` or a number of days. With a different value, sync does not start, and it does not guess |
| Anything on the file server itself | [Troubleshooting (`file-server.md`)](file-server.md#troubleshooting) — a table by symptom, which includes idmap and `nsswitch.conf` faults |

## The diagnostic that walks the whole chain

```sh
dist/kbmanage doctor --user alice
```

The command names the first broken link, with the command that repairs it. It
makes sure that:

- the object exists
- the external identity decodes
- the account is enabled
- the admission group is reachable
- the resource group is nested
- the group is domain-local

When you run `doctor` with no arguments, it examines the directory for
structural problems:

- duplicate identities
- a missing or duplicated admission group
- live groups that are nested into nothing
- retired objects that still hold a name

It cannot see the filesystem. At the end, it prints the `id 'EXAMPLE\<user>'`
command. Run that command on the file server yourself.
