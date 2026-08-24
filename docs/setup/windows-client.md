# The Windows client

This page is the Windows half of
[step 7 (*Set up a workstation*) in SETUP.md](../../SETUP.md#7-set-up-a-workstation).
The facts that apply to both platforms are in that step. This page holds what
is different on Windows.

## What ships

The package installs two executables:

- `kerbridge-agent.exe` — the product. It is a per-user background agent in the
  system tray, and users see it as **NAS Access**.
- `kerbridge.exe` — the same core as a console tool. It does one operation at a
  time and shows its output. Use it when you think that the tray itself has a
  fault.

Neither executable is a service, and neither runs elevated. There are two
exceptions, and both are one-shot operations: realm registration, and the
NTLM-fallback repair.

> **CAUTION: Trust the broker's CA machine-wide.** The elevated enrollment step
> gets `/config` over TLS again itself, so that only a URL crosses the
> privilege boundary. That step therefore runs as a different user, and it
> cannot see a CA that you installed for yourself only. A user-scoped CA is
> sufficient for every other step, and it fails at this one step, which you
> cannot skip. A fleet that pushes the CA by policy never meets this.

The failure identifies itself. A TLS failure prints the certificate that the
host presented — the subject, the names that it covers, the issuer and the
validity — below the dialog and in the log. The issuer names the CA that the
elevated user has no copy of.

<details>
<summary>The privilege split was measured by a standard user</summary>

The division was measured end to end on 2026-08-04, by a **standard user**.
This was not an administrator that ran unelevated. It was an account with no
membership in the Administrators group at all, at Medium integrity. The test
checked this before and after each step. One administrator action registers the
realm. After that action, no other step asks for privilege:

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
disabled, so the account had a single token. That makes the test cleaner,
because no elevated token existed that could do the work undetected. But it
leaves the split-token case untested, and the differing-LUID hazard applies to
that case. The result also says nothing about the state display of the tray,
which has its own open issues.

</details>

## Build it

```sh
make installer     # -> dist/kerbridge-nas-access.msi
```

The build needs Docker and nothing else. Packaging uses wixl and msitools,
which stay in a container. The build is `x86_64` intentionally: the production
client is an amd64 workstation, and an ARM64 development VM runs these exact
bytes under emulation.

<details>
<summary>Without the MSI: the two executables only</summary>

```sh
make windows      # from the repo root -- writes both exes to dist/
```

Copy both executables to the workstation, to a location where the user can
execute them, and run the tray. Every step below works the same. You supply the
Start-menu shortcut yourself. The *Start at login* checkbox in Settings
supplies the autostart entry.

</details>

## Install it

```
msiexec /i kerbridge-nas-access.msi                  # interactive
msiexec /i kerbridge-nas-access.msi AUTOSTART=1 /qn  # silent, fleet push, autostart
```

- The MSI installs to `%ProgramFiles%\KerBridge\`, and it adds a Start-menu
  shortcut.
- The installer writes the machine-wide autostart entry **only** when you pass
  `AUTOSTART=1`. An interactive install leaves autostart to the *Start at
  login* checkbox in Settings. Where the machine-wide entry exists, that
  checkbox reads checked and is disabled, with a line that says that IT turned
  it on: a per-user setting cannot countermand a machine-wide one.
- An uninstall keeps the per-user settings.
  `msiexec /x kerbridge-nas-access.msi REMOVESETTINGS=1` also removes
  `%APPDATA%\KerBridge\`.
- **To upgrade, install the newer MSI over the old one.** Do not uninstall
  first, even when the two MSIs have the same version. The settings survive the
  upgrade. `AUTOSTART=1` does not, so a fleet's upgrade command must pass it
  again. If the tray runs, the interactive install offers to close and restart
  it, and `/qn` does that with no question.

> **Note: The MSI is unsigned.** SmartScreen shows a warning at the first
> install, and each UAC prompt says "unknown publisher". There is also no ADMX
> template. See [rough-edges.md](rough-edges.md).

The source of the installer is
[`client/kerbridge-agent-windows/installer/nas-access.wxs`](../../client/kerbridge-agent-windows/installer/nas-access.wxs).

## First run

1. **Run NAS Access.** With no configuration, it opens the flyout on *Setup
   needed*.
2. **Sign in.** The browser opens. Complete the sign-in there. On an
   Entra-joined machine, the agent signs in through the Windows broker, with no
   browser and no user action.
3. **Register the realm with Windows.** If Windows does not know the realm, the
   tray offers *Set up now*. This is an elevated one-shot operation. It shows
   the commands, runs them, and asks for a restart when Windows needs one:

   ```
   ksetup /addkdc EXAMPLE.SITE
   ksetup /setrealmflags EXAMPLE.SITE tcpsupported
   ```

   `tcpsupported` is mandatory. A ticket that carries a PAC is larger than the
   UDP reply limit, and without this flag Windows does not retry over TCP. A
   restart is necessary the first time.

   To undo the registration, run `kerbridge.exe --unenroll`, or use
   Settings → Advanced.
4. **Tick *Start at login*** in Settings.

> **Note: If no tray icon appears, the icon is hidden, not missing.** Windows
> 11 puts an icon that it has not seen before into an overflow area, and the
> taskbar can show no chevron for that area. Turn the icon on under *Settings →
> Personalization → Taskbar → Other system tray icons*. Windows keeps this
> choice for each icon. The agent will not change the setting for you —
> [`rough-edges.md`](rough-edges.md) gives the reason.

[`client/kerbridge-agent-windows/README.md`](../../client/kerbridge-agent-windows/README.md)
describes the state machine behind the tray icon, and the meaning of each
state.

## Preconfiguring a fleet

Two registry values under `HKLM\Software\KerBridge` override the per-user
config file. They are the *platform policy value* in the broker URL resolution
order of [step 7](../../SETUP.md#7-set-up-a-workstation):

| Value | Type | Effect |
|---|---|---|
| `BrokerUrl` | REG_SZ | Takes priority over every source below it; the Settings field becomes read-only |
| `NtlmFallbackRecovery` | REG_DWORD | `0` disables the SMB repair mechanism |

## Config and logs

These files are per-user, at `%APPDATA%\KerBridge\`:

- `config.toml` — the broker URL and two toggles.
- `kerbridge.log`, and `kerbridge.log.1.gz` … `.3.gz` after rotation.
