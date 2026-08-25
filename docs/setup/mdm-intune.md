# Deploying the Windows client with Intune

Intune does two independent jobs here, and neither needs the other:

| Phase | What it delivers | How |
|---|---|---|
| Settings | the broker address and switches | an imported ADMX, as an administrative template |
| The app | the agent itself | a Win32 app wrapping the MSI |

Deliver the settings first where you can. The install can then find its broker
on a machine with nobody signed in, which is what makes
[step 4](#4-register-the-realm-during-the-push-optional) possible.

## 1. Import the ADMX

[`client/kerbridge-agent-windows/policy/`](../../client/kerbridge-agent-windows/policy/)
holds `KerBridge.admx` and `en-US\KerBridge.adml`.

*Devices → Manage devices → Configuration → **Import ADMX** tab → Import.*
Upload both, then refresh until **Status: Available**.

- **Upload the `en-US` ADML** whatever the tenant's display language is. Intune
  supports no other.
- **Nothing is configured yet.** This page is a library; the settings are
  assigned in step 2.

**Updating it later:** a new version will not upload over the one already
there. Delete every profile that uses it, delete the template, then import the
new pair.

## 2. Create the settings profile

Do this after you have uploaded the ADMX template (above).

*Devices → Manage devices → Configuration → Create → New policy*, platform
**Windows 10 and later**, profile type **Templates → Imported Administrative
templates**. The five settings are under *Configuration settings*, in a **NAS
Access by KerBridge** category.

Two profile types look right and are not:

- **Administrative Templates** holds the settings built into Windows.
- The **Settings Catalog** does NOT list an imported ADMX.

Each setting is *Not Configured*, *Enabled* or *Disabled*. Disabled is a real
third state: it forces the setting **off** and locks the control, where Not
Configured leaves the choice to the user and to the deployment's own defaults.

**Reverting to Not Configured needs the *Device configurations → Delete*
permission.** The built-in **Policy and Profile Manager** role has it; a
narrower custom role may not, and without it the value stays on the device
after you clear it in the console.

## 3. Push the app install

Package it as a **Win32 app**, not Line-of-Business.

<details><summary>Why now LOB?</summary>

Line-of-business (LOB) is the tempting shortcut — one
upload, no tooling — but it detects the app by the MSI product code and nothing
else, and this installer is built with `Product Id="*"`, so every build carries
a fresh one. A LOB app therefore stops matching at the first upgrade. Usable
for a one-shot pilot, for nothing after that.
</details>

Next, you need a `.intunewin` file that packages the installer.
You can create them with the `IntuneWinAppUtil.exe` tool ([download here](https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/)).

Move the NAS Access MSI installer (.msi) to some `<folder>` and then run:

```sh
IntuneWinAppUtil.exe -c <folder> -s windows-kerbridge-nas-access-gui-amd64.msi -o <out-folder>
```

The `<folder>` must contain the MSI (plus an install script only if you choose the
scripted variant in step 4), **and nothing else** — the tool packages everything
in it, and all of it is downloaded to every device.

Upload the resulting file from `<out-folder` to Intune:

*Apps → Windows → Add → Windows app (Win32)*, upload the `.intunewin`, then:

| Field | Value |
|---|---|
| Install command | `msiexec /i "windows-kerbridge-nas-access-gui-amd64.msi" /qn` |
| Uninstall command | see below |
| Install behavior | **System** — the MSI is `perMachine` |
| Detection rule | **File**, `%ProgramFiles%\KerBridge`, `kerbridge-agent.exe`, *String (version)*, ≥ the version you are shipping (four parts, e.g. `0.9.2.0`) |

That is the whole install. Every setting comes from step 2 above, and the installer decides nothing.

**Do not use an MSI product-code detection rule**, for the reason above. The
`UpgradeCode` is permanent, but Intune's MSI rule does not take one. The
file-version rule has neither problem.

The same fact makes the uninstall command awkward, because `msiexec /x` wants
the product code. Resolve it on the device instead:

```
powershell -NoProfile -ExecutionPolicy Bypass -Command "$k = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' | Where-Object { $_.GetValue('DisplayName') -eq 'NAS Access' }; if ($k) { Start-Process msiexec -ArgumentList '/x', $k.PSChildName, '/qn' -Wait }"
```

To upgrade, deploy the newer package with the same install command. Do not add
an uninstall step first. The MSI is unsigned, which does not stop a
SYSTEM-context install — see [rough-edges.md](rough-edges.md) — and Restart
Manager closes and revives a running agent, so `/qn` needs no reboot.

## 4. Register the realm during the push (optional)

Windows has to be told the realm exists before an injected ticket means
anything, and that is a machine-wide, elevated, reboot-once step. The tray
offers it at first run, but the push can do it instead — it runs as SYSTEM,
which is already elevated, and Intune already knows how to reboot.

Add it to the install command:

```
cmd /c msiexec /i "windows-kerbridge-nas-access-gui-amd64.msi" /qn && "%ProgramFiles%\KerBridge\kerbridge.exe" --enroll --yes
```

`cmd` returns the last command's code, so the enrollment's is the one Intune
reads, and a failed `msiexec` short-circuits and returns its own.

`--yes` prints the `ksetup` plan and runs it without waiting for anybody. An
already-registered machine exits 0 and changes nothing, so this is safe to
re-run on every upgrade.

Two things it needs:

- **A broker the machine can find with nobody signed in.** Assign the
  `BrokerUrl` setting from step 2 before the app, or publish the
  `_kerbridge._tcp` SRV record. With neither, this step has nothing to discover
  and exits non-zero; the tray still offers enrollment at first run.
- **A deliberate decision.** Enrollment normally shows the realm and the KDCs
  and waits for the user to agree, and that confirmation is the backstop
  against a broker naming KDCs it should not. `--yes` moves the judgement to
  you, at the moment you write this command. Naming the broker in the template
  rather than leaving it to DNS is the tighter of the two configurations.

### The restart

Exit code **3010** means the registration is written and a restart finishes it.
In Intune, leave *Device restart behavior* on **Determine behavior based on return
codes**; 3010 is a soft reboot in Intune's built-in table and needs no entry of
your own.

**A soft reboot is a notification, not a restart.** Outside Autopilot the user
can ignore it, and a machine that has been enrolled but not restarted is one
the agent cannot describe: the registry says enrolled, so the agent signs in
and injects a ticket, but Windows caches the realm at boot and the ticket is
valid and unusable until then. The drives do not work and the tray says nothing
is wrong.

- **Under Autopilot this does not arise.** A 3010 reboots the device at the end
  of the enrollment status phase, batched with every other app that asked, and
  the realm is live before anyone signs in.
- **On an existing fleet, force it** if you would rather not field the support
  call: use the scripted variant below and turn the code into a hard reboot,
  which Intune acts on with a countdown and your grace period.

  ```powershell
  if ($e.ExitCode -eq 3010) { exit 1641 }
  ```

  Do not reach for *Intune will force a mandatory device restart* instead. That
  restarts every targeted machine, including the ones that were already
  enrolled and needed nothing.

### When the one-liner is not enough

`&&` reads *any* non-zero code as failure, including `msiexec`'s own 3010. That
would skip the enrollment, reboot, and then detect the app as installed — so
the machine would never get enrolled. This installer closes and revives a
running agent rather than asking for a reboot, so that code is unlikely here;
where a fleet is large enough for "unlikely" to mean "a few of them", use a
script and make the install command
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File install.ps1`:

```powershell
$msi = Join-Path $PSScriptRoot 'windows-kerbridge-nas-access-gui-amd64.msi'
$m = Start-Process msiexec -ArgumentList '/i', "\"$msi\"", '/qn' -Wait -PassThru
if ($m.ExitCode -ne 0 -and $m.ExitCode -ne 3010) { exit $m.ExitCode }

$exe = Join-Path $env:ProgramFiles 'KerBridge\kerbridge.exe'
$e = Start-Process $exe -ArgumentList '--enroll', '--yes' -Wait -PassThru -NoNewWindow
if ($e.ExitCode -eq 3010 -or $m.ExitCode -eq 3010) { exit 3010 }
exit $e.ExitCode
```

## Starting the agent without a first run

A plain install leaves one manual step: **each user has to start NAS Access
once**, from the Start menu. The `Autostart` setting cannot do it for them, and
this is structural — the login entry is per-user, so only the agent, running as
that user, can write one. From that first launch onward every sign-in starts
the agent by itself.

To remove even that step, add `AUTOSTART=1` to the install command:

```
msiexec /i "windows-kerbridge-nas-access-gui-amd64.msi" AUTOSTART=1 /qn
```

That writes the *machine-wide* `Run` entry, which starts the agent for every
user at their next sign-in with nobody launching anything — and on an
Entra-joined machine the agent then signs in through WAM and injects a ticket
with no user action at all. It also makes the `Autostart` template setting
redundant on those machines, and the Settings checkbox reads on and greys out.

The property is not remembered across an upgrade, so an upgrade command that
omits it removes the entry. That is the cost of the zero-touch path: the
autostart decision lives in the deployment command rather than in the template
with everything else.

## What you cannot target per user

Nothing here scopes to a user. `AUTOSTART=1` writes `HKLM`, and every setting
in the template is a machine setting, so both apply to whoever signs in to the
device. Assigning either to a user group picks which *devices* receive them,
never which users obey them.

What you can scope is the device: assign the app and the settings profile to
different device groups, or use assignment filters. "Installed everywhere,
starts automatically on the shared machines only" is expressible; "starts only
for one person on this machine" is not.

An unentitled user who gets the agent started for them does not gain access.
The broker checks admission-group membership on the exchange, so they get a
refusal, not a ticket.
