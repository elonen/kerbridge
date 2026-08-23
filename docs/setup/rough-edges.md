# Known rough edges

This page is an honest list of the parts that are not finished. The items are
in the order in which you will meet them when you follow
[`SETUP.md`](../../SETUP.md). No item here is theoretical — each item comes
from a real run.

- **The DC is on a Docker bridge, so it advertises an address that only the
  host can reach.** Provisioning registers the DC's A record with its container
  address. A member that joins registers its own A record automatically, in the
  same way. Thus what Samba's own DNS says about the realm is true only inside
  the bridge. Deployments avoid this problem when they resolve the realm from
  the site's own resolver. The split-horizon setup in
  [`dns-and-firewall.md`](dns-and-firewall.md) describes this method. The defect
  is that Samba's zone and the site's zone then do not agree, and only one of
  them is correct. `KERBRIDGE_SUBNET` and `REALM_IPV4` stay in `.env` for the
  same reason. Host networking removes all of these problems. But then you
  cannot run `nas1` on the same machine — see
  [Host networking and DNS (`DESIGN.md`)](../../docs/design/api-and-network.md#host-networking-and-dns).
- **Sync authenticates with a client secret.** A certificate credential is the
  intended default and is not built. Set `sync_credential_expires` (in
  `configs/idp_<source>.toml`'s `[provider_config]`) so
  that sync warns you before the secret expires. Update the value each time
  that you rotate the credential. If you do not, sync reports months of
  remaining time on a dead credential.
- **A rename in Entra signs that user out once.** Login names follow the Entra
  display name (`automatic_sam_renames` in `configs/sync.toml`, default on).
  The reason: Windows shows the login name as the file owner and in the
  *Security* tab. If the files of a person who is now called Jane Doe show
  `EXAMPLE\jane.smith`, then the directory fails at its job. But the login
  name is also that user's Kerberos principal. Thus tickets that were issued
  under the old name become invalid. At the next cycle after the change, the
  user must sign out and sign in again, or purge the tickets and inject them
  again. No other user is affected, and nothing on the disk moves — the ACLs
  hold the SID.

  Know these two facts before they surprise you. First: if you change
  `sam_source` in `configs/sync.toml` while renames are on, one cycle renames
  *each* user whose name derives differently under the new source. To stage
  that change, set `automatic_sam_renames` to `false` first. Second: the
  retire/return path
  derives the name again, and this setting has no effect on it. An account
  that leaves the admission group and comes back can return with a different
  name than the name it left with. That path loses the name by design:
  retirement truncates the held name to 11 characters, and removal of the
  prefix would bring back the truncated name.

  `kbmanage cloud rename <account> --to <name>` sets a name manually and pins
  it against all of the above. Use it when the derived name is legal but
  wrong. `kbmanage cloud unpin <account>` returns the name to automatic
  control.

- **Operator notification is off until you give it a URL.** The webhook
  notifier works: on 2026-07-30, a `make test-notification` message arrived in
  a real Slack channel. But `secrets/notify_url` ships empty, and `url_file`
  ships commented out. If a deployment does not set both, its only channels are
  `docker compose logs sync` and the problem directory. To enable notification:

  1. Put a URL in `secrets/notify_url`.
  2. In the `[notify]` table of `configs/main.toml`, remove the `#` from
     `url_file` and point it at that file.
  3. Restart `broker` and `sync`.
  4. Run `make test-notification` from `deploy/` to make sure that the message
     arrives.

  The default template renders on Slack, Teams, Mattermost, and Rocket.Chat.
  Each other service needs `notify.template` in `configs/main.toml`. A template that names an unknown
  `%PLACEHOLDER%`, or that does not produce JSON, stops the service at
  startup, not at the first event.

  `state/broker/` and `state/sync/` hold one `problem-<event>.json` file for
  each condition that is currently true. They do this whether a webhook is
  configured or not. Thus a deployment that prefers its own monitoring can
  skip the URL — see [`deploy/README.md`](../../deploy/README.md).

  These events were not seen on a live deployment:

  - a real event (not the synthetic test) that arrives in a channel
  - a recovery after such an event
  - suppression over real time by the repeat interval and by the
    30/14/7/3/1-day expiry schedule

  Unit tests cover all of these, but none was seen in the field. Thus the
  first month of a pilot is where you find out that an event repeats more
  frequently than you want.
- **No code signing, no ADMX.** An MSI exists
  ([`windows-client.md`](windows-client.md)), and it can do silent installs
  and fleet installs. But the MSI is unsigned. Thus SmartScreen shows a
  warning, and each UAC prompt says "unknown publisher". There is also no
  Group Policy template. This is acceptable for a pilot. A fleet needs a
  signature. Correct signing also needs a build change. `make installer`
  compiles and packages in one Docker build. Thus there is no point at which
  you can sign the *exes* before they are embedded. A signature on the package
  alone leaves the binary that autostarts and elevates through UAC — the one
  that SmartScreen judges — unsigned. A release must split the stages: build
  the exes → sign them → package → sign the MSI.
- **Windows 11 hides the tray icon the first time that it appears, and users
  read a hidden tray icon as a failed installation.** The agent registers
  correctly and runs. Windows 11 puts a notification-area icon that it did not
  see before into an overflow area, and the taskbar can show no chevron for
  that area. One switch makes the icon appear: *Settings → Personalization →
  Taskbar → Other system tray icons*. Only the user can set that switch. The
  agent intentionally does not write `IsPromoted` itself: an application that
  promotes itself decides its own importance on the taskbar of another person.
  Tell pilot users where the switch is. If you do not, the first report that
  you get says that nothing occurred. This was measured on Windows 11
  (2026-08-05). The icon now carries a fixed identity; it is not keyed by the
  path that it runs from. Thus the switch stays set through an upgrade. But
  the first build that carries the fixed identity is itself a new identity.
  Thus each user who already runs the agent must set the switch one more time.
- **The Mac has no installer, and its bundle is ad-hoc signed.** `make macos`
  writes `dist/NAS Access.app`, and you copy it to `/Applications` yourself
  ([`macos-client.md`](macos-client.md)). There is no `.pkg`, no `.dmg`, and
  no MDM payload. The ad-hoc signature is sufficient to run and sufficient for
  Notification Center. But it carries no team identity: System Settings ▸
  Login Items lists the agent as *Item from unidentified developer*, and a
  bundle that arrives from a different machine is quarantined until a person
  permits it in Privacy & Security. The fix is a Developer ID signature plus
  notarization. Like the MSI, this is a release-time task for the publisher;
  this repository cannot do it for you. Ad-hoc signing also blocks the Secure
  Enclave device grant: that grant needs a keychain-access-group entitlement,
  and that entitlement needs a real identity for the signature.
- **On a machine with no PRT, one click during the first sign-in decided if
  renewal would ever work — and the fix for it is newer than the evidence.**
  Windows asks: *"Sign in to all apps and websites on this device?"*. The
  answer *"No, this app only"* keeps the account out of the Windows account
  manager. Then WAM has no account for renewal. Silent re-injection fails with
  `0xcaa10001 Need user interaction to continue`, and Windows asks the user to
  sign in again. There is no fallback, because a WAM sign-in also leaves no
  browser refresh token. This was measured on a non-Entra-joined client on
  2026-07-30: *"No, this app only"* let the ticket expire; *"Yes"*
  re-injected on schedule, with no user action. An expiry with an open SMB session is
  also the path to the stuck NTLM fallback.

  Nothing warned you at the time. The choice was in a Microsoft dialog that
  you do not control, and the effect appeared approximately half a ticket
  lifetime later. Thus the client no longer asks the question. A failed silent
  attempt goes directly to the browser; it does not escalate into that dialog.
  Only the forced re-authentication after a sign-out still opens the dialog,
  and only on a machine where the first sign-in was through WAM.

  This behavior was measured on 2026-07-30, on a client whose device
  registration was removed (`dsregcmd /leave`). The silent attempt failed with
  that same `0xcaa10001`, and the browser opened in the same second, with no
  Windows dialog between the two. This occurred at the sign-in, and again at
  the unattended renewal 27 minutes later. That renewal used the refresh
  token, with no browser at all. The Entra-joined machine — where the silent
  attempt is the one that *succeeds* — was tested again the same evening and
  showed no change: after a reboot, the tray autostarted and had a TGT two
  seconds later, through WAM, with no window shown. Builds made before this
  change still escalate; for those builds, answer **Yes** to the dialog.

  The browser path that the client falls to renews unattended. Three
  consecutive re-injections on 2026-07-30 ran with no browser and no user;
  the in-memory refresh token carried them, and the end time of the injected
  ticket matched what the broker issued. The cost comes at startup, not
  during a session. That token dies with the tray, and the browser's Entra
  session dies with the browser, so a reboot leaves neither.

  Thus the first sign-in after a reboot is a real interactive sign-in, with
  credentials and MFA if your policy asks for them. A machine with a PRT
  signs in at logon, with no prompts. In a session, this is invisible; after a
  reboot, it is a prompt.
- **Device grants were tested once, carefully — not over a long period.** The
  full path was measured end to end on 2026-08-01, on one machine with a real
  firmware TPM:

  1. The machine was authorized with `kerbridge --grant`.
  2. It got a ticket with no browser.
  3. From that ticket, it got a `cifs/` service ticket and read a file over
     SMB.

  The tray's own menu path and each CLI verb followed on 2026-08-02. This
  included revocation, done by removal of the user from the device-grant
  group. That sweep found and fixed six defects. This is still one machine,
  one TPM, one deployment, debugged immediately before the test. A second TPM
  implementation is unmeasured.

  One edge remains: the broker refuses a *revoke* while the feature is off.
  Thus a device that is given up in that window keeps its (dead) directory
  row and one `device_grant_max_per_user` slot. They stay until
  `kbmanage device revoke` clears them. The feature is off by default. See
  [`device-grants.md`](device-grants.md) before you turn it on, and pilot it
  on one machine.

  Two smaller gaps exist in the same area. Nothing reports a device whose
  Windows connection fell back to NTLM. The tray tries to repair the
  connection and tells the person at the machine. But on an unattended build
  machine, that toast goes nowhere, and the build system is what finds the
  failure. Also, one configuration is untested: such a machine that runs as a
  local administrator with UAC disabled, so that the tray can inject a ticket
  and restart the connection service in one logon session. The measured fact
  is only this: an elevated process under split-token UAC has a different
  logon session, and the redirector cannot see the tickets of that session.
- **Delegated grants: the CLI path and the tray are measured on Windows;
  renewal-time recovery with no person present is not.**
  `make test-stack` covers the full server path end to end:

  - an engineer's token that authorizes a machine for a service account
  - a ticket that comes back as the *service account*, not as the caller
  - a list operation and a revoke operation with a target
  - a 403 refusal for an admitted user who is outside the delegate group

  The client path was measured on Windows 11 25H2 (build 26200) on
  2026-08-03, against a bench realm, with `RunAsPPL=2` and Credential Guard
  off. A machine pinned to `svc-builder` was authorized by a browser sign-in
  as an engineer who holds no credential for it. It produced:

  ```
  #0  Client: svc-builder@EXAMPLE.SITE  Server: krbtgt/EXAMPLE.SITE
  #1  Client: svc-builder@EXAMPLE.SITE  Server: cifs/nas1.example.site
  ```

  The engineer is nowhere in the cache. The file that was written over SMB is
  owned by `EXAMPLE\svc-builder` (resolved uid → SID → name through winbind,
  not read from a display string). Thus the identity also survives the TGS
  exchange, not only the injected TGT.

  The tray was measured the same night, on the same machine, and all four
  paths hold:

  - At startup, the tray refuses a ticket that is not the grant's own, and
    gets a new one instead of adopting it.
  - A transport outage is reported as an outage, and the tray recovers when
    it re-injects from the grant, with no browser.
  - A sign-out drops the tickets and does not change the grant.
  - *Give up* destroys the TPM key **and** revokes at the broker; afterwards
    the grant is gone from the directory, not only flagged.

  The test showed two faults in wording and state display. The tray calls a
  grant-backed machine "Not signed in", and it offers *Authorize* as the
  remedy for an outage that no human can fix (issues #8 and #9). Both are
  cosmetic in the sense that no behavior is wrong. Neither is cosmetic in the
  sense that matters: they show the normal state of an unattended machine as
  a fault. They have one shared cause: the tray shows a signed-in/signed-out
  binary for a machine whose state is at least four independent things. Thus
  the fix is a design pass (#10), not more conditional wording.

  One measurement remains, and it is the one to do next: recovery **at
  renewal time** after an outage, with no person at the keyboard. Each
  recovery that was measured came after a button press. To reach the
  unattended case, use a short-lived ticket (`-l 10m -r 30m`, see
  [`../windows-testbench.md`](../windows-testbench.md)); do not wait for a
  multi-hour ticket. If injection ever breaks, the symptom is
  artifacts that a person owns instead of the account. Nothing reports this,
  and nobody sees it until they open a *Security* tab. Thus, after you change
  the injection path, measure again with `klist`.
- **Each person who shares the pinned machine's logon session runs as the
  service account.** Injection applies to one logon session, and the tray runs
  for one user. Thus this is not "each person who logs in inherits the
  account". The exposure is the one autologin session that the tray injects
  into. On an unattended machine, this is intended. It is a surprise if a
  person sits down at that session, or if the machine gets a new purpose.
  This is new with delegation only in one way: the holder of a self-grant
  *was* the identity of that session. This risk is documented, not guarded:
  the software cannot detect "interactive", and a build service is itself a
  logon session.
- **Untested combinations:**
  - tenants with Entra Cloud Kerberos enabled (ticket cache selection was
    never measured against a contested cache)
  - workstations with Credential Guard on (injection was proven with
    Credential Guard off)
  - consumer NAS appliances — Synology, QNAP, TrueNAS
    ([`file-server.md`](file-server.md) says what is known and what is not
    known)
  - clients joined to a different on-prem AD domain (out of scope by design;
    nothing blocks it — it is simply unknown)
- **Upgrade and password rotation have no procedure.** Both are absent.
- **Backup is a script, not a schedule.** `backup.sh` captures the state, and
  `restore.sh` puts it back. Both were tested in a wipe-and-restore of the
  volumes. You must arrange when they run and where the tarballs go.
