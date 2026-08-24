# The Windows agent — design

This crate owns the Win32 surfaces and nothing else. Common logic is
in shared `kerbridge-client` module.

| Subject | Where |
|---|---|
| The mode dispatch, the message loop, and `WinHost` | `main.rs` |
| The notification icon, its menu, and the balloons | `tray.rs` |
| The status popup | `flyout.rs` |
| The tabbed settings window | `settings.rs` |
| The confirmation dialog | `modal.rs` |
| The elevated one-shots | `elevated.rs` |
| What this surface ranks and colors for itself | `present.rs` |
| The shared window state and the control vocabulary | `app.rs`, `ui.rs` |
| Light and dark for stock controls | `theme.rs` |
| Win32 plumbing, DPI, and the icon raster | `sys.rs` |
| The WAM token source | `wam.rs` |

## Realm enrollment

Enrollment is an elevated one-shot. It runs one time per machine, and it is what
makes an injected ticket mean anything: with the realm absent from
`…\Lsa\Kerberos\Domains`, the injection still succeeds and the TGT is then valid
and unusable.

**Detection.** At startup, and before a sign-in, the agent reads
`HKLM\…\Lsa\Kerberos\Domains\<REALM>` — whether it is present, whether
`RealmFlags` includes `tcpsupported`, and how `KdcNames` compares to the
discovered configuration — and the `HostToRealm` mappings. A missing or
mismatched state gives the `RealmNotRegistered` blocker.

**The trigger** is the *Set up Windows…* action. It relaunches the binary
elevated, with `ShellExecute("runas", "kerbridge --enroll <broker-url>")`.

**The elevated run fetches `/config` over TLS itself.** It does not trust data
that the unprivileged process hands it. It then does this:

- `ksetup /addkdc REALM kdc` for each configured KDC, or a bare
  `ksetup /addkdc REALM` when `kdcs` is empty. In the second case Windows locates
  the KDC through the published `_kerberos._udp` SRV record.
- `ksetup /setrealmflags REALM tcpsupported`. **This is mandatory.** Without it a
  TGS that carries a PAC fails with `KRB-ERROR 52`, and Windows never retries
  over TCP.
- `ksetup /addhosttorealmmap <entry> REALM`, **only** for the escape-hatch
  `services` entries, which are hosts or suffixes in a foreign DNS zone. A
  service host in the realm's own DNS zone needs no mapping, because the
  DNS-suffix heuristic covers it. So to add such a service never triggers a
  re-enrollment. Prefer a leading-dot suffix over one entry per host, so that a
  whole foreign zone is one mapping.

A reboot is then required, because Windows caches the realm registration at boot.
`RealmFlags` alone applies immediately.

**The one-time IdP sign-in is not part of enrollment.** Enrollment is a machine
fact and it belongs to an administrator. The sign-in is a user fact and it
belongs to the signed-in user. They are deliberately independent, because the
elevated process can run as a *different* account, and a sign-in there would bind
the wrong user.

## The repair of the NTLM fallback

How the fallback is detected, and why the agent never restarts the service by
itself, is in [`../DESIGN.md`](../DESIGN.md). What is left here is the mechanism.

When the agent detects the fallback, it opens the status window directly on the
repair explanation, and the user consents to the elevated `--repair`. **The
confirmation warns that every network drive and shared folder on the device
disconnects, and not only the realm's.**

The agent does **not** try a re-injection first. Into a redirector that is stuck
on NTLM, that is the attempt the research measured going nowhere.

The elevated child restarts `LanmanWorkstation` through the SCM, stopping and
restarting its running dependents. The list of dependents is computed in the
unprivileged parent: an unelevated caller can enumerate them in the same session
where `SERVICE_STOP` is refused with error 5. That is what makes the split
between the parent and the elevated child necessary and not merely tidy.

## The WAM token source

The mechanism was measured end to end on an Entra-joined box
(research spike `windows-wam-whfb-silent-token`):
WAM issues a token for the *existing* public client, the token passes the
broker's locked validator, it yields a TGT, and it survives a reboot.

`wam.rs` uses `WebAuthenticationCoreManager` through the `windows` WinRT crate.
This is the one place where a heavier dependency enters.

**There is no `TokenSource` trait.** One call site in one function does not need
one. `agent::acquire_token` calls `wam::acquire` first, unless the
`windows_sign_in` toggle is off, and it falls through on anything but a token.

**The call is silent on every ordinary path.** A silent success *is* the test for
a usable PRT. A silent failure means that Windows would have shown the Workplace
Join prompt instead of a sign-in, and that is the browser's case. The silent leg
also runs on the re-injection timer, which is the point of it: an unattended
renewal with no refresh token in this process at all.

- **One-time registration.** `ms-appx-web://microsoft.aad.brokerplugin/<client id>`
  must be a redirect URI on the public client. Without it the interactive call
  fails with a redirect-URI mismatch. Nothing in the client can fix this.
- **The first acquisition can prompt.** Conditional Access can demand an MFA that
  the PRT cannot satisfy silently. That is one native dialog instead of one
  browser window, and every re-injection after it is silent.
- **Default on, and never a dependency.** Every failure falls through to the
  browser, so a machine that cannot do WAM behaves as it did before. To turn the
  toggle off forces the browser.
- **A full sign-out forces the next WAM prompt.** The credential belongs to
  Windows and not to this process, so *sign out of the cloud too* would otherwise
  be undone by the very next silent acquisition.

## The flyout

The flyout is a borderless popup, that the tray icon opens. It is
one page: there is no view axis, and what the state makes irrelevant is simply
not drawn. It dismisses on "blur" (click outside the window).

The order of its lines, the identity rules and the severity of the explanation
block are the core's, and they are in [`../DESIGN.md`](../DESIGN.md). What this
surface decides for itself is in `present.rs`: the ranking, the tooltip and the
color roles.

**At most two buttons, by a fixed priority:**

```
OpenSettings → SignOutEntra → Enroll → RestartWorkstation
             → CreateGrant → ReinjectTicket → SignIn → DropKrbTicket
```

Gates apply. `RestartWorkstation` appears only while the `NtlmFallback`
blocker is present, because the menu already offers the repair to a user who
suspects the fault. `CreateGrant` appears only when the machine is delegated and
grantless, or when the grant is due soon. `SignIn` never appears on `Working`.
`SignOutEntra` appears only while `just_authorized` is set, which is the one
moment the agent knows that it put a session in a browser and that the machine no
longer needs one.

While a browser leg runs, the second slot is *Cancel*. When something has failed,
it is *Open log folder*.

**`in_flight` is a shape and not a word** — a marquee hairline under the button
row, which is the Win32 idiom for *something is running*. It owes no string in
any language. That state is rarely on screen at all, because a sign-in opens
a browser and the flyout dismisses on blur.

**Pair the buttons only when both fit, otherwise stack them.** Half width is
152 dip, plus 18 dip where a shield is drawn. A label that needs more puts the
pair on two rows, and the Settings button rows wrap for the same reason. This is
a *layout* answer to a *vocabulary* problem, and it is what lets the labels stay
as chosen. **Keep the rule, and do not rely on the individual widths**: the
narrowest margin in the set is two tenths of a dip, so any change to the shield
width, the padding or the inner width changes the outcome with no other sign.

**The details drawer holds what moves, plus the realm.** A drawer of constants
teaches the reader to stop opening it. `Realm` is the deliberate exception and it
leads: it is constant per machine, it names the subject that every other row is
about, and it is the first thing asked for when somebody helps over a phone. The
drawer as a whole is gated on `usable`, because on an unenrolled machine every
row would describe a ticket that the OS cannot use.

## The tray menu

The menu is the flyout's superset, in the flyout's order. It carries the paths
that width and rarity make free there — the cloud sign-out, *Repair network
drives…* whether or not the fault is diagnosed, Settings, Help and Quit.

**`Open log folder` is not in the menu.** A technical record was a permanent
offer, one row above *Quit*, to a reader with no use for it. Its one permanent
home is Settings ▸ Advanced ▸ Troubleshoot. Its menu slot goes to *Help*, which
can teach the Kerberos-versus-OIDC distinction that a menu verb cannot. The help
URL defaults to the client's own, and `help_url` in `GET /config` replaces it —
through the same `require_https` rule as every other URL the broker returns. **The
flyout's fault slot keeps the log**, because it is conditional and not permanent,
and on a fault it is the only thing that advances a support conversation.

**About is not in the menu.** It is a Settings tab, and one route beats two.

**The infotip is a bounded status list.** `szTip` holds 128 characters including
the NUL, and the worst reachable combination reaches 230. So the agent writes the
condition first, then adds blocker lines one at a time while the whole stays
within the bound, and stops cleanly instead of truncating mid-word. The flyout
holds whatever did not fit, which is where a user looks anyway.

## Confirmation, elevation and the modal

**Confirm in the parent, then elevate** — never the other way round. Nothing is
lost by it: the plan text, the reboot flag and the running dependents are all
computable in the parent.

| Action | Home | Shield |
|---|---|---|
| Set up Windows… | flyout primary while `RealmNotRegistered`, plus the tray menu | ✔ |
| Repair network drives… | flyout while the `NtlmFallback` blocker is present; tray menu always | ✔ |
| Set up Windows again… | Settings ▸ Advanced ▸ Windows setup | ✔ |
| Forget {realm}… | Settings ▸ Advanced ▸ Windows setup | ✔ |
| Authorize access… | Settings ▸ Advanced ▸ Authorization, beside the *Authorize this device for* field; reads *Authorize again…* once a grant is held | ✘ |
| Remove authorization… | Settings ▸ Advanced ▸ Authorization, and nowhere else | ✘ |

**The shield goes on unconditionally**, even where UAC is off or the user is the
built-in Administrator, and it never reflects state. **The two authorization
actions carry none**, because the grant key is user-scope and neither creating
nor destroying it needs elevation. Irreversible and privileged are independent
properties, and only the second is the shield's business.

**Repair stays out of Settings.** It answers *my drives are broken right now*,
which is a flyout question. Settings is where you go when nothing is wrong.

### One modal, and its phases

Every operation takes the same dialog. The flyout can host none of it: it
hides on blur, and the UAC secure desktop takes focus, so the surface would
vanish exactly when it is meant to say *waiting*.

```
confirm ──commit──▶ waiting ──▶ working ──▶ result
   ▲                   │           │
   └────decline────────┘           └──Close──▶ detached, outcome → notification
```

1. **Confirm** — a warning icon, the casualties named, and **Cancel as the
   default**.
2. **Waiting for permission…** — the secure desktop is up, nothing runs yet, and
   the dimmed desktop proves it. Shielded operations only.
3. **Working** — the operation verb-first with an ellipsis. A busy indicator
   first, and an **indeterminate** bar only after five seconds. Determinate is
   impossible, because progress through an opaque elevated child is not
   observable.
4. **Result** — one sentence, and Close.

**A decline returns to phase 1, unchanged and silent.** A decline is a decision
and not a fault.

**There is no Cancel and no Stop, and that is the one deliberate departure from
the guidance.** Cancel is impossible, because none of these operations is
reversible. Stop is worse: its own definition — *leaves the partially completed
operation intact* — is precisely the outcome that must not be offered, which
here means `Netlogon` left stopped. **Close detaches instead**: it
dismisses the window and leaves the work running, and the outcome then arrives as
a notification. That is also what makes the outcome asynchronous, which is the
only thing that licenses a notification about a button the user has just pressed.
**Close is not Stop**, and the label states the difference.

**What each confirmation states before the click** is: what the operation does in
system terms, who else pays, named, and what to do first.

- **Repair network drives?** names `LanmanWorkstation`, and states that every
  network drive and shared folder on the device disconnects, that programs with
  open files can lose unsaved work, and — generated from the dependent list, and
  omitted when it is empty — that `Netlogon` stops and starts with it. The commit
  button is **Repair anyway** and not a mirror of the label that opened the
  dialog: this is an *unintended consequence* confirmation, and *anyway* is the
  guide's own way to slow the user down. The label and the commit button differ
  here and nowhere else, because this dialog exists to add what the label could
  not carry.
- **Set up Windows for {realm}?** shows the literal `ksetup` lines that will run,
  and states that a restart is needed afterwards. **The plan text is the
  confirmation prompt, so it must be literally what gets executed.**
- **Remove {realm} from Windows?** shows the two registry keys that are deleted.
- **Remove this device's authorization?** has **two bodies, keyed on the
  delegation**. Both open with the key being deleted and revoked, and with *can't
  be undone — authorizing again creates a new key*. The undelegated body then
  affirms the access: it is not affected, and the device signs in the way it did
  before. The delegated body states that access keeps working until the
  **ticket** expires, in hours, and then stops.

**That result reports two independent facts**: the key on this device, and the
record at the broker. The revoke destroys the key first and unconditionally, so
the action works offline by design, and the broker call is the second fact. A key
gone while the broker was not told is not cosmetic: the directory row survives
holding a `device_grant_max_per_user` slot, and the cost arrives later as *Device
cap reached* on a machine that has forgotten why. **The revoke must leave the UI
thread**, because with the broker unreachable — exactly the case that produces
the two-fact result — an HTTP round trip on the message loop freezes the flyout
for the timeout, and dismiss-on-blur then discards the outcome.

**The elevated child renders nothing at all** — no confirmation, no summary, no
reboot prompt. UIPI runs the right way for this: the child can report *down* to
the medium-IL agent, and the agent could never drive the child's user interface.
The child owes back an outcome class and, where an exit code cannot carry it, one
sentence through a result file whose path the parent passes. An absent or
unreadable file is **"couldn't confirm"** and never a fabricated success, and a
declined prompt is **silence**.

## Settings

**Instant-apply. There is no OK and no Cancel.** Once the one-shots are confirmed
in the parent, a Cancel cannot undo them, and a control that does not do what it
says is worse than no control.

**The two text fields keep an explicit Save**, disabled until the value changes.
They cannot commit on blur, because both are consequential: a change of broker
purges the realm, releases the grant and drops the refresh token, so a half-typed
address landing on focus loss would wipe the session; and the target field writes
`expected_working_as`. The cost is stated: a user who types an address and closes
the window without a commit loses it, which is cheaper than a Cancel the rest of
the window contradicts.

**Tabs sorted by subject, routine to rare, destructive last.**

```
┌ Basic ┬ Advanced ┬ About ┐
│ Connection                 broker address · sub or managed cue · [Save]
│ Sign-in                    ☑ Start at login
│                            ☑ Use Windows sign-in when possible
└
┌ Advanced
│ Authorization              state line (grant held only)
│                            "Authorize this device for" [        ]
│                            [Authorize access… | Authorize again…]
│                            [Remove authorization…]      (grant held only)
│ Windows setup              enrollment state line
│                            🛡[Set up Windows again…] 🛡[Forget {realm}…]
│ Troubleshoot               [Open log folder]
└
┌ About                      logo · name · version · copyright · license · URL
└
```

**Kind is a *commit* axis, not a layout one.** To sort by it would separate the
authorization state from its own buttons, and that state is the reason the
group is opened. So the window sorts by subject, and the constraint — **routine
and destructive never share a door** — stands as a rule with nothing here to
apply to: the two controls behind *Advanced* are both rare for almost every user,
which is what an Advanced door is for.

**`SysTabControl32` is owner-drawn, because it will not take a dark theme.**
`SetWindowTheme` returns `S_OK` and changes not one pixel; an `EDIT` in the same
window goes dark as the positive control. So `TCS_OWNERDRAWFIXED` with
`WM_DRAWITEM` draws the items, a subclassed `WM_ERASEBKGND` draws the strip
behind them, and the page child over the `TCM_ADJUSTRECT` rect covers the display
area. **Two residual costs are the work and not footnotes**: the display area's
border still draws light and has to be covered, and `WM_DRAWITEM` hands you the
items only, so the selected, hot and focus rendering become ours. An unhoverable
tab strip is worse than a light one. To draw only in dark mode was rejected,
because it costs *more*: that rendering has to be written either way, and two
paths mean two sets of metrics to keep true.

**The delegated-user field stays in Settings and must not disagree with the
machine.** It cannot move into the *Authorize access…* dialog, because
`grant_for()` is read in many places and must be persisted before any of them run.
It is standing machine policy, not an argument to one dialog. A changed target
invalidates nothing, because the machine keeps working as the old one. So the
group reads **what is true now, then what the next authorization will do, then
the buttons**:

- **The state line comes from the held grant**, in the past tense, so it cannot
  be edited into a lie and cannot be confused with the flyout's *Working as*,
  which means something else.
- **The field is labeled for the future it controls** — *Authorize this device
  for* — and not for the present that it does not govern.
- **When the two differ, nothing branches and no warning appears.** The
  disagreement resolves where it is committed, inside the confirmation, which
  names its target.
- **The authorize button commits a pending edit in that field first**, then
  confirms with the committed value.

Policy-locked means read-only plus the managed cue, and never hidden. That is the
one place where a locked machine with no grant yet states its target.

**Presence rules, and no text branches.** With no broker address or no realm, the
Authorization and Windows setup groups are absent and the second tab carries a
gate line instead, which is where the absence it explains actually is. With
grants off, Authorization is absent *silently*: a deployment that turned the
feature off does not want a row that explains what its users cannot have. When
the machine is not enrolled, Windows setup keeps its state line and loses its
buttons.

**There is no clock in Settings.** The grant deadline renders in the status
surface and nowhere else. Two numbers about one authorization in two windows is
the duplication that one clock was meant to end.

## Notification mechanics

The policy — the two gates and the event table — is in
[`../DESIGN.md`](../DESIGN.md). What is Windows' own:

- **A `Shell_NotifyIcon` balloon never reaches Notification Center**, in any
  configuration, even with the per-app box checked. Measured. That is part of why
  a notification is an interruption and never a record.
- **Severity follows `condition`**: `NIIF_NONE` for a recovery, `NIIF_WARNING`
  for an escalation or a deadline, and `NIIF_ERROR` for an expiry or a failure.
- **`NIIF_RESPECT_QUIET_TIME` belongs on all of them**, unconditionally.
- **A click opens the status window.** `NIN_BALLOONUSERCLICK` arrives at version
  0, and `NIM_SETVERSION` stays uncalled: to raise the version would fire the
  menu twice per right-click and, at v4, suppress the tooltip. The handler calls
  `show_flyout()` and never `toggle_flyout()`, because a click on a toast must
  always open.
- **The presence gate for the grant deadline is `GetLastInputInfo`**, per session
  and capped at once a day.
- **No AUMID of ours.** The agent already appears in Settings ▸ System ▸
  Notifications under a synthesized `NotifyIconGeneratedAumid_<hash>` with a full
  user off-switch. The process call alone is a regression, because it replaces
  the product name in the header with a raw AUMID string. If an AUMID is ever
  added, the shortcut property and the process call go in together.

## Icon rendering

The mapping, the geometry, the halo and the glyph threshold are
`kerbridge_client::icon`'s and are shared with macOS. `sys.rs` rasterizes the SVG
and composites the badge. Two Windows-only requirements:

- **The badge takes color**, from `theme.rs`'s own `warn` and `danger`, keyed on
  `taskbar_dark()` and not on the app theme, because the taskbar is the surface
  it is drawn on. The mark itself stays taskbar ink. Monochrome cannot separate
  `Working` from `Flaky` at 16 px.
- **Render at `GetSystemMetrics(SM_CXSMICON)`, never at a hardcoded size.**
  Otherwise a 100 % DPI machine gets the glyph version squashed to 16 px and the
  glyph threshold has nothing to act on. The metric is 16 × scale, so the
  threshold turns on at 150 %. The icon must re-render on `WM_DPICHANGED` as well
  as on a theme change, which is what makes both sides reachable.

## Known limits

- **The bare `ksetup /addkdc REALM` command.** The end state is proven — the
  `Domains\<REALM>` key present, `KdcNames` absent, and the KDC located through
  the `_kerberos._udp` SRV record — but the measurement reached that state by a
  registry edit. If the bare command turns out not to create the key, create
  `Domains\<REALM>` and the flags directly. **The failure would be silent**: only
  a non-zero exit becomes `FAIL`, so a command that exits 0 without creating the
  key logs `OK` and detection then reports `NotEnrolled` for ever.
- **The host-to-realm mapping strategy**, which decides whether a new service
  ever needs a re-enrollment. Two parts are unverified here: whether
  `/addhosttorealmmap` is droppable when the realm equals the uppercased DNS
  suffix, isolated with `SpnMappings` absent and with the parent-domain walk
  checked; and whether the leading-dot suffix map covers nested subdomains
  independently of the heuristic, whether it needs a reboot, and how it ranks
  against explicit host maps.
- **Whether a stuck NTLM fallback clears itself after about 20 minutes idle**
  (`SpnCacheTimeout`). Not reached in the measurements.
</content>
