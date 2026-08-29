# The Windows client

This page the Windows-part of [step 7 (*Set up a workstation*) in SETUP.md](../../SETUP.md#7-set-up-a-workstation).
The facts that apply to both Windows are Mac platforms are in that step.

## Installer contents

The package installs two executables:

- `kerbridge-agent.exe` — the GUI product. It is a per-user background agent in the
  system tray, and users see it as **NAS Access**.
- `kerbridge.exe` — the same core as a console tool. It does one operation at a
  time and shows its output. Useful for scripting and debugging.

Neither executable is a service, and neither runs elevated. There are two
exceptions, and both are one-shot operations: realm registration, and the
NTLM-fallback repair.

## Building it

```sh
make installer     # -> dist/windows-kerbridge-nas-access-gui-amd64.msi
```

The build needs Docker and nothing else. Packaging uses wixl and msitools,
which stay in a container. The build is `x86_64`, but it was also tested on an
ARM64 development VM: it ran the AMD64 version  under emulation just fine.

<details>
<summary>Without the MSI: the two executables only</summary>

```sh
make windows      # from the repo root -- writes both exes to dist/
```

You can copy both executables to the workstation, to a location where the user can
execute them, and run the tray. Every step below works the same. You supply the
Start-menu shortcut yourself. The *Start at login* checkbox in Settings
supplies the autostart entry.

</details>

## Install it

```
msiexec /i windows-kerbridge-nas-access-gui-amd64.msi                  # interactive
msiexec /i windows-kerbridge-nas-access-gui-amd64.msi AUTOSTART=1 /qn  # silent, fleet push, autostart
```

To push it from Intune, go to **→ [mdm-intune.md](mdm-intune.md)**.

- The MSI installs to `%ProgramFiles%\KerBridge\`, and it adds a Start-menu
  shortcut.
- The installer writes the machine-wide autostart entry **only** when you pass
  `AUTOSTART=1`. An interactive install leaves autostart to the *Start at
  login* checkbox in Settings. Where the machine-wide entry exists, that
  checkbox reads checked and is disabled, with a line that says that IT turned
  it on: a per-user setting cannot countermand a machine-wide one.
- An uninstall keeps the per-user settings.
  `msiexec /x windows-kerbridge-nas-access-gui-amd64.msi REMOVESETTINGS=1`
  also removes `%APPDATA%\KerBridge\`.
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
2. **Sign in.** With an Entra source on an Entra-joined machine, the agent can
   use Windows sign-in, with no browser or user action. Otherwise, the browser
   opens; complete the sign-in there. authentik always uses browser sign-in.
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

> **Note: If no tray icon appears, the icon is likely hidden, not missing.** Windows
> 11 puts an icon that it has not seen before into an overflow area, and the
> taskbar can show no chevron for that area. Turn the icon on under *Settings →
> Personalization → Taskbar → Other system tray icons*. Windows keeps this
> choice for each icon. The agent will not change the setting for you —
> [`rough-edges.md`](rough-edges.md) gives the reason.

[`client/kerbridge-agent-windows/README.md`](../../client/kerbridge-agent-windows/README.md)
describes the state machine behind the tray icon, and the meaning of each
state.

## Preconfiguring a fleet

Registry values override the per-user config file. They are the *platform
policy value* in the resolution order of
[step 7](../../SETUP.md#7-set-up-a-workstation), and each one makes its control
in the Settings window show the managed value instead of offering to change it.

The agent reads `HKLM\Software\Policies\KerBridge` first. That is the branch
Group Policy and Intune write, and the only one Windows removes again when the
policy stops applying to a machine. `HKLM\Software\KerBridge` holds the same
names for a deployment with no management system — an imaging script can write
it — and nothing cleans that one up.

| Value | Type | Effect |
|---|---|---|
| `BrokerUrl` | REG_SZ | Takes priority over every source below it |
| `Autostart` | REG_DWORD | `1` starts the agent at sign-in, `0` forbids it |
| `WindowsSignIn` | REG_DWORD | `0` forces the browser flow instead of WAM |
| `NtlmFallbackRecovery` | REG_DWORD | `0` disables the SMB repair mechanism |
| `GrantFor` | REG_SZ | The account a device grant works as — [device-grants.md](device-grants.md) |

`Autostart` is applied, not only recorded: the login entry is per-user, so the
agent writes one to match the policy every time it starts. That means it takes
effect from the **first run** on each account — nothing can write a per-user
entry for a user who has never run the agent. Install with `AUTOSTART=1` where
the very first logon has to start it: that writes a *machine-wide* entry, which
no per-user setting can countermand and which the agent cannot remove.

### Over Group Policy

[`client/kerbridge-agent-windows/policy/`](../../client/kerbridge-agent-windows/policy/)
holds `KerBridge.admx` and `en-US\KerBridge.adml`. Copy both into the central
store (`\\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions\`, the `.adml`
into its `en-US\` subfolder). The settings appear under *Computer Configuration
→ Administrative Templates → NAS Access by KerBridge*.

Each setting is *Not Configured*, *Enabled* or *Disabled*, and Disabled is a
real third state: it forces the setting **off** and locks the control, where
Not Configured leaves the choice to the user and to the deployment's own
defaults.

### Over Intune

The same template, imported into the tenant — and the installer push with it.
**→ [mdm-intune.md](mdm-intune.md)**.

### Without a management system

A deployment can publish the same defaults from the broker instead. `main.toml`
`[client_defaults]` is served in `GET /config`, which every agent already reads
for the realm and the KDCs, so it reaches the machines no management system
owns:

```toml
[client_defaults]
autostart = true
windows_sign_in = true
```

These are defaults and not policy: they decide a machine whose user has never
chosen, and a user's own choice — and any of the registry values above — wins
over them. `autostart` is applied once, to the real login entry.

## Config and logs

These files are per-user, at `%APPDATA%\KerBridge\`:

- `config.toml` — the broker URL, and each toggle the user has changed.
- `kerbridge.log`, and `kerbridge.log.1.gz` … `.3.gz` after rotation.
