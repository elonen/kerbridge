# The Windows client

This page gives the detail for
[step 7 (*Set up a workstation*) in SETUP.md](../../SETUP.md#7-set-up-a-workstation).

## What ships

The package installs two executables:

- `kerbridge-agent.exe` — the product. It is a per-user background agent in the
  system tray. Users see it as **NAS Access**.
- `kerbridge.exe` — the same core as a console tool. It does one operation at a
  time and shows its output. Use it when you think that the tray itself has a
  fault.

Neither executable is a service. Neither runs elevated, except for the two
one-shot operations that must run elevated: realm registration, and the
NTLM-fallback repair.

This division was measured end to end on 2026-08-04, by a **standard user**.
This was not an administrator that ran unelevated. It was an account with no
membership in the Administrators group at all, at Medium integrity. The test
made sure of this before and after each step. One administrator action
registers the realm. After that action, no other step asks for privilege:

- browser sign-in
- ticket injection into the caller's own logon session
- the `cifs/` TGS
- mounting the share
- a file write, where the file gets the correct directory object as its owner
- a re-injection
- creation and revocation of a device grant with its TPM key
- the tray
- the user's own autostart entry

The result has two limits. Keep them attached to it. The machine had UAC
disabled, so the account had a single token. This makes the test cleaner,
because no elevated token existed that could do the work without detection.
But it leaves the split-token case untested, and the differing-LUID hazard
applies to that case. Also, the result says nothing about the state display of
the tray, which has its own open issues.

Know one consequence of this division before you meet it. The elevated
enrollment step gets `/config` over TLS again **itself**, so that only a URL
crosses the privilege boundary. The step therefore runs as a different user,
and it cannot see a CA that you installed for yourself. A user-scoped CA is
sufficient for all other steps and fails only here. Thus the broker's CA must
be trusted machine-wide. A fleet pushes the CA by policy and does not see the
problem. A small deployment that installed the CA by hand meets the problem at
this one step, and this step cannot be skipped.

The failure identifies itself. A TLS failure prints the certificate that the
host presented: the subject, the names that it covers, the issuer, and the
validity. This output goes below the dialog and into the log. In this case,
the issuer shows the cause: it names a CA that the elevated user has no copy
of.

## Build it

```sh
make installer     # -> dist/kerbridge-nas-access.msi
```

The build needs Docker and nothing else. Packaging uses wixl and msitools,
which stay in a container, not on your machine. The build is `x86_64`
intentionally. The production client is an amd64 workstation, and an ARM64 dev
VM runs these exact bytes under emulation. A native ARM64 build would never
ship.

<details>
<summary>Without the MSI: only the two executables</summary>

```sh
make windows      # from the repo root -- writes both exes above to dist/
```

Copy both executables to the workstation, to a location where the user can
execute them, and run the tray. All the steps below work the same. You supply
the Start-menu shortcut and the autostart entry yourself. The *Start at login*
checkbox in Settings supplies the autostart entry.

</details>

## Install it

```
msiexec /i kerbridge-nas-access.msi                  # interactive
msiexec /i kerbridge-nas-access.msi AUTOSTART=1 /qn  # silent, fleet push, autostart
```

- The MSI installs to `%ProgramFiles%\KerBridge\` and adds a Start-menu
  shortcut.
- The installer writes the machine-wide autostart entry **only** when you pass
  `AUTOSTART=1`. An interactive install leaves autostart to the *Start at
  login* checkbox in Settings. Where the entry exists, that checkbox reads
  checked and is disabled, with a line saying that IT turned it on: a per-user
  setting cannot countermand a machine-wide one.
- An uninstall keeps the per-user settings.
  `msiexec /x kerbridge-nas-access.msi REMOVESETTINGS=1` also removes
  `%APPDATA%\KerBridge\`.
- **To upgrade, install the newer MSI over the old one.** Do not uninstall
  first, even when the two MSIs have the same version. Settings survive the
  upgrade; `AUTOSTART=1` does not. Thus a fleet's upgrade command must pass
  `AUTOSTART=1` again. If the tray runs, the interactive install offers to
  close and restart it, and `/qn` does that without a question.

> **Note:** The MSI is unsigned. SmartScreen will show a warning at the first
> install, and each UAC prompt will say "unknown publisher". A signature is a
> release-time task for the publisher of this product. There is no ADMX
> template either. See [rough-edges.md](rough-edges.md).

The source of the installer is
[`client/kerbridge-agent-windows/installer/nas-access.wxs`](../../client/kerbridge-agent-windows/installer/nas-access.wxs).

## First run

1. **If you used `TLS_STRATEGY=external`:** first install your CA root into the
   Windows certificate store. The agent validates against the OS trust store.
   Without the CA root, it will not speak to the broker.
2. **Run NAS Access.** When no configuration exists, it opens the flyout on
   *Setup needed*. If your `_kerbridge._tcp` SRV record is in place, the broker
   address field already shows the value that the agent found. If not, type
   `kerbridge.example.site` in Settings. The agent adds `https://` for you, and
   it refuses plaintext `http://`.

   A realm with **more than one source** has to say which one: the address ends
   in the source name, `kerbridge.example.site/entra`. The bare host is enough
   for the single-source realm this guide builds, and a realm that later adds a
   second source tells these clients so — they refuse with the names to choose
   from rather than picking one.

   **If no tray icon appears, the icon is hidden, not missing.** Windows 11
   puts an icon that it has not seen before into an overflow area, and the
   taskbar can show no chevron for that area. Turn the icon on under *Settings
   → Personalization → Taskbar → Other system tray icons*. Windows keeps this
   choice for each icon. The agent will not change that setting for you;
   [`rough-edges.md`](rough-edges.md) gives the reason.
3. **Sign in.** The browser opens; complete the sign-in there. On an
   Entra-joined machine, the agent signs in through the Windows broker, with no
   browser and no user action.
4. **Register the realm with Windows.** If Windows does not know the realm, the
   tray offers *Set up now*. This is an elevated one-shot operation. It shows
   the literal commands, runs them, and asks for a reboot when Windows needs
   one:

   ```
   ksetup /addkdc EXAMPLE.SITE
   ksetup /setrealmflags EXAMPLE.SITE tcpsupported
   ```

   `tcpsupported` is not optional. A PAC-bearing ticket is larger than the UDP
   reply limit, and without this flag Windows does not retry over TCP. A reboot
   is necessary the first time.

   To undo the registration, run `kerbridge.exe --unenroll`, or use Settings →
   Advanced.
5. **Tick *Start at login*** in Settings. Autostart must be per-user. A ticket
   that an elevated or service context injects goes into the wrong logon
   session, and the SMB redirector never sees it.

The agent then signs in, injects a TGT, and injects again at half of the
remaining ticket lifetime.

[`client/kerbridge-agent-windows/README.md`](../../client/kerbridge-agent-windows/README.md)
describes the state machine behind the tray icon, and the meaning of each
state.

## Preconfiguring a fleet

Two registry values under `HKLM\Software\KerBridge` override the per-user
config file:

| Value | Type | Effect |
|---|---|---|
| `BrokerUrl` | REG_SZ | Has priority over all sources below it; the Settings field becomes read-only |
| `NtlmFallbackRecovery` | REG_DWORD | `0` disables the SMB repair mechanism |

Broker URL resolution order:

1. `--broker` flag
2. HKLM policy
3. `config.toml`
4. `_kerbridge._tcp` SRV
5. first-run prompt

**If you publish the SRV record, you push nothing at all.** This is the
intended deployment.

## Config and logs

These files are per-user, at `%APPDATA%\KerBridge\`:

- `config.toml` — the broker URL and two toggles. It holds no secret: the
  refresh token never touches the disk.
- `kerbridge.log`, plus `kerbridge.log.1.gz` … `.3.gz` after rotation. Send the
  rotated files together with the log, because the fault usually started before
  the last 10 MB.
