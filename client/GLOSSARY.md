# client glossary

The workstation software: the agent state machine, sign-in and enrollment, ticket
injection, and what a surface shows the person at the keyboard.

Part of the repo-wide vocabulary in [`GLOSSARY.md`](../GLOSSARY.md) — a term
means the same thing there and here. It lives in this file, closest to where
it's used, rather than in the root file, because the root file would be
unreadably long if it carried every term at once.

### action

Something the user may start, from `SignIn` to `OpenSettings`.
The list is flat and unordered by construction, so each `surface` picks its own
primary, and the list never offers one that provably cannot help — nothing that
gets or spends a ticket is offered while the machine is not `usable`.
<!-- refs: `kerbridge_client::describe::Action` -->
<!-- avoid: command, offer, operation, button, verb, task -->

### arm

One platform's implementation of a module that differs by OS, selected from the
shared module by a conditional path attribute.
<!-- refs: `#[cfg_attr(…, path = …)]`; `windows/enroll.rs` is the Windows arm of `enroll` -->
<!-- avoid: platform module, impl, backend, `imp` -->

### assertion

The bare form of `device assertion`, used inside the client's device-grant code
where nothing else could be meant. Prefer the full term anywhere an access token
could also be in scope.
<!-- refs: `kerbridge_client::device::assertion` -->
<!-- avoid: jwt, token, device token, signed proof -->

### auth scheme

Which proof a broker request carries, as the `Authorization` header names it:
`Bearer` for an access token or `DeviceGrant` for a signed device assertion,
exactly one per request and chosen by the caller. The scheme words are the
broker's wire strings; client and broker each name the choice in code, and the
broker parses the same two words into a proof.
<!-- refs: `AuthScheme` in `client/kerbridge-client/src/broker.rs`, broker's `Proof` -->
<!-- avoid: credential, proof type, auth type, token type -->

### authority

The IdP's OIDC issuer URL, named by the broker in its `discovery document` and
then asked verbatim for its own `.well-known/openid-configuration`. The
authorize and token endpoints are never taken from the broker.
<!-- refs: `kerbridge_client::discovery` -->
<!-- avoid: idp, the cloud, identity provider -->

### autostart

Registration to start at login, per-user on both platforms because the ticket
has to land in the interactive user's own session. It is the registration, not
the silent sign-in that follows it; a separate locked flag covers the
machine-wide `Run` value the MSI can write, which no per-user toggle
countermands.
<!-- refs: `kerbridge_client::config::autostart_enabled`, `autostart_locked`, `SMAppService` on macOS -->
<!-- avoid: startup, login item, start at login, start with windows, run at startup, run value, runatload -->

### badge

The mark composited into the bottom-right of the faded `logo`: a triangle for
warn, a disc for stop. It is keyed on `condition`, not on `fault` — `Flaky` and
`WillStop` draw the triangle, `Stopped` the disc, `Working` and `NotStarted`
none — and the glyph inside it (bang or cross) appears only at 24 px and above.
Mapping, geometry and thresholds are the core's; only the ink treatment is each
platform's.
<!-- refs: `kerbridge_client::icon::Badge` (`Badge::Warn`, `Badge::Stop`), mapped by `icon::mark`, `GLYPH_MIN` -->
<!-- avoid: indicator, corner mark, icon variant -->

### blocker

What is missing right now, immediate and unentailed: from
`NoBrokerUrl` to `NtlmFallback`. Blockers explain, `action`s resolve; they are
not parallel lists and nothing lines up between them. `NoBrokerUrl` swallows
everything downstream of it, so a first-run machine emits one entry rather than
that entry and its consequences.
<!-- refs: `kerbridge_client::describe::Blocker` -->
<!-- avoid: reason, error -->

### broker URL

The `https://` base address of the broker and the client's only bootstrap input,
resolved in precedence order: machine policy, then the user's config file, then
a DNS SRV answer. A policy-supplied value locks the field in the UI.
<!-- refs: `config.toml`, `kerbridge_client::config::Settings::broker_url` -->
<!-- avoid: broker address, endpoint -->

### condition (client)

The single rung a machine is on, derived from local facts and no network
term: `Working`, `Flaky`, `WillStop`, `Stopped`, `NotStarted`. It drives the
`headline`, the icon and the notification `severity`; a broker outage never
moves it, but appears as a `blocker` and, if it persists, as `Flaky`. Shown to
users as *Access OK*, *Renewal uncertain*, *Access expiring*, *No access* and
*Off*.
<!-- refs: `kerbridge_client::describe::Condition` -->
<!-- avoid: health, mode -->

### delegated

Of a workstation: it has a `grant_for` target configured, so only a device grant
can obtain a ticket there and the tickets are the target's rather than whoever
signed in.
<!-- avoid: unattended, service machine, pinned -->

### device key

The non-exportable ECDSA P-256 key a device grant stands on: Windows holds it in
the TPM through CNG's platform crypto provider, user-scoped, so creating one
needs no elevation and it dies with the profile. macOS has none — its device
module reports unavailable, so nothing there offers to authorize the machine.
<!-- refs: `MS_PLATFORM_CRYPTO_PROVIDER`; `client/kerbridge-client/src/macos/device.rs` reports `AVAILABLE = false` -->
<!-- avoid: TPM key, protected key, platform key, enclave key -->

### elevation

Relaunching one privileged step as administrator and waiting for it; Windows
only, answering `Ran`, `Declined` or `Unavailable`. Only enrollment,
unenrollment and `repair` ever cross it — nothing that touches a ticket may,
because an elevated token has its own ticket cache.
<!-- refs: `kerbridge_client::elevate::run_elevated` -->
<!-- avoid: uac, runas, admin, root, privilege escalation -->

### end time

The Unix second at which the injected ticket stops being valid, read back out of
what the KDC actually granted rather than out of what was asked for. The whole
client schedule is measured against it: `re-injection` is clamped to land before
it, and reaching it without a renewal landing is its own agent phase.
<!-- avoid: expiry, expiration, endtime -->

### episode

One run of an `NTLM fallback`, opened when the injected TGT vanishes before its
End Time and closed by a landed exchange or a restart; it is the whole rate
limit on raising the status surface, one raised window per episode. A successful
elevated repair deliberately leaves it open, because the evicted TGT is still
gone.
<!-- refs: `agent::NtlmFallback` -->
<!-- avoid: incident, event, occurrence -->

### expectation

Whether this machine is supposed to be working here: a `realm|target` scope
stored in settings and compared at load, so retargeting the broker or changing
the target voids it with no event.
<!-- refs: stored as `expected_working_as`; `Agent::expect`, `Agent::scope` -->
<!-- avoid: `expected`, scope, supposed-to-work flag -->

### fault

The class of the last failure — `Network`, `Refused`, `GrantRefused`, `Other` —
which decides which `blocker` the message sentence stands behind. `Other` has no
blocker of its own but still counts as something being wrong, which is what a
surface keys its fault ink and its offer of the log on. Distinct from the
status's fault flag, a bool that separates something being *wrong* from
something merely being said.
<!-- refs: `kerbridge_client::describe::Fault`, `agent::Status::fault` -->
<!-- avoid: error class, failure kind -->

### grant target

The account this machine authorizes itself *for*: configured per machine, also
settable by machine-wide policy. Standing machine policy rather than an argument
to one dialog — it decides who the *next* authorization names and changes
nothing about the grant already held. Shown to users as *Authorize this device
for*.
<!-- refs: `grant_for` in the client's config -->
<!-- avoid: delegated user, the target field -->

### halo

The transparent ring cleared along the `badge`'s own silhouette, so the badge
keeps an edge where the logo behind it is the same ink. Along the silhouette and
not as a disc around it: a disc that fits the box leaves the triangle's lower
corners touching the mark.
<!-- refs: `kerbridge_client::icon::KNOCKOUT`, 1.2× the badge radius -->
<!-- avoid: knockout, ring -->

### headline

The one line naming the current `condition`, drawn larger and color-coded, and
the only place a condition is spelled out. It is absent for `NotStarted` on a
machine with no identity yet, so a machine that never worked here gets no
headline at all.
<!-- refs: `kerbridge_client::present::headline` -->
<!-- avoid: title, status line, condition line, bold line -->

### `Host`

The seam for everything the agent needs a UI for, installed at
runtime by the platform's agent binary. Not the platform seam for non-UI work.
<!-- refs: methods `wake`, `notify`, `finished`, `elevating`, `primary_action_label`, `raise`, `open_path`, `native_token`; non-UI seam is `sys` -->
<!-- avoid: ui seam, platform seam, backend, the host app -->

### `kerbridge-agent`

The agent binary's name, identical on Windows and macOS. Neither it nor the
crate name ever reaches a user.
<!-- refs: `[[bin]]` in both agent crates, `CFBundleExecutable` in the macOS bundle -->
<!-- avoid: kerbridge-agent-windows, kerbridge-agent-macos, the tray exe, agent.exe -->

### KRB-CRED

The DER-encoded RFC 4120 §5.8.1 message the broker's MIT ccache is repackaged
into for Windows' ticket-submission message. A pure repackaging with no crypto
of our own: same ticket, same session key, `enc-part` etype 0. macOS needs none
of it, because Heimdal reads the ccache bytes natively.
<!-- refs: Windows `KerbSubmitTicketMessage`, `kerbridge_client::krbcred` -->
<!-- avoid: krbcred blob, ticket blob -->

### logo

The single committed artwork file that every icon in the product is rasterized
from: both agents' status icons, the `.ico`, the `.icns`, the title bar and the
installer. There is no second artwork file to keep in sync with it.
<!-- refs: `client/assets/app-icon.svg` -->
<!-- avoid: app icon, the mark, artwork, brand mark -->

### notification

The client's out-of-surface announcement of an `outcome` or a state change, at
one of the `severity` levels — a tray balloon on Windows, a Notification
Center banner on macOS. The core emits and logs unconditionally and each
platform host decides whether to suppress one because a surface is already on
screen saying it. Never a parallel record of state.
<!-- refs: `agent::Host::notify` -->
<!-- avoid: balloon, toast, notification bubble -->

### outcome

What one of the hosted operations came to, in the words its surface renders:
`Declined`, `Done { message, detail }`, `Failed { message }`. A decline is a
decision and not a fault — it returns the dialog to its question, unchanged and
silent.
<!-- refs: `kerbridge_client::agent::Outcome` -->
<!-- avoid: result, exit -->

### phase (agent)

The agent's internal machinery: `SignedOut`, `SigningIn`, `Connected`,
`Expired`, `Error`. Deliberately not what any surface says — `condition` is
derived from facts instead, so a phase never reaches a user.
<!-- refs: private to `kerbridge_client::agent` -->
<!-- avoid: step, stage, mode -->

### phase (confirmation)

One of the states of the Windows confirmation modal: `Confirm`, `Waiting`,
`Working`, `Result`. `Waiting` is the moment the secure desktop is up and
nothing is running yet, so it exists for shielded operations only.
<!-- refs: `kerbridge-agent-windows/src/modal.rs` -->
<!-- avoid: step, stage, mode -->

### plan (client)

The literal command batch or registry key list an elevated step will execute,
shown in monospace for confirmation first. What is shown must be exactly what
runs — the plan *is* the confirmation, and that is the backstop against a rogue
broker. Windows only, since macOS has nothing to enroll.
<!-- refs: `ksetup`, `kerbridge_client::enroll::plan`, `plan_text`, `unenroll_plan_text` -->
<!-- avoid: script, batch, commands, preview, plan text -->

### policy

The machine-managed configuration layer IT decides: a machine-wide registry hive
on Windows and a *forced* managed preference on macOS. Read-only to the client
and it beats the user's own configuration file, which is why the corresponding
Settings field goes read-only rather than merely losing.
<!-- refs: `HKLM\Software\KerBridge` on Windows, `config.toml`, `kerbridge_client::config::Policy` -->
<!-- avoid: hklm, gpo, mdm, machine policy, managed settings, admin policy -->

### purge

Removing every ticket for one realm from this user's ticket cache. Realm-scoped,
never blanket, and it deliberately leaves an already-open SMB session serving.
<!-- refs: `kerbridge_client::tickets::purge_realm` -->
<!-- avoid: `klist purge`, clear, flush, empty, evict, wipe -->

### re-enrollment

Applying the `enrollment` again over a partial or stale one.
<!-- avoid: reenroll, force enroll -->

### re-injection

Running the `exchange` again and injecting the result, scheduled at roughly half
the remaining ticket lifetime and clamped to land before `end time`. Not renewal
and not a convenience: Windows never installs a renewed injected TGT, so this is
what prevents the stuck NTLM fallback.
<!-- refs: `client/kerbridge-client/src/agent/mod.rs` -->
<!-- avoid: renewal, silent renewal, silent refresh, refresh, re-mint, re-inject, reinjection -->

### refresh token

The `offline_access` token an agent keeps in process memory so re-injection
needs no browser. It dies with the process by design; `cloud sign-out`, not
`sign off`, is what forgets it early.
<!-- refs: `agent::REFRESH_TOKEN` -->
<!-- avoid: silent credential, stored token -->

### role

In the Windows agent, the paint semantic a control is stamped with, stashed per
control in the window's user-data field and read back when the control is
colored. The surface picks the role and the message handler turns it into a
color. Unrelated to a `role group` or a role marker.
<!-- refs: `ROLE_*` constants in `kerbridge-agent-windows/src/ui.rs`, `GWLP_USERDATA`, `WM_CTLCOLOR` -->
<!-- avoid: colour role, style, class, variant -->

### settings

Both the window or sheet where the user changes what is theirs to change, and
the resolved view the client acts on behind it: the user's config file with
`policy` layered over it and a DNS answer underneath both. No secret is stored
in any layer — the refresh token lives in process memory and dies with it.
<!-- refs: `config.toml`, `kerbridge_client::config::Settings` -->
<!-- avoid: config, preferences, options -->

### severity

How loud an announcement is, on the ordered scale `Info` < `Warning`
< `Error`. On the client it is keyed on the `condition` being announced rather
than on the code path that emitted it; on the server it is stamped on the record
at the moment of raising, so the configured minimum severity judges a later
announcement against the same bar.
<!-- refs: `kerbridge_client::agent::Severity`, `kerbridge_notify::Severity`, `notify.min_severity` -->
<!-- avoid: level, priority, urgency, loudness, interruption level -->

### sign-in deadline

The moment a device grant stops working and somebody must sign in at that
machine through a browser again. Always the current cap's answer and never what
was stamped: the broker serves the `stamped deadline` clamped by the configured
day count, so lowering that number bites every outstanding grant and raising it
stretches none. Shown to users as *Authorization expires in …*.
<!-- refs: `DeviceGrant::effective_end`, `configs/main.toml` `device_grant_days` -->
<!-- avoid: browser-sign-in deadline, grant deadline, grant expiry, effective end, expiry, expires at, deadline (bare) -->

### status (client)

The immutable snapshot a surface repaints from, computed once on the UI thread.
Every judgment in it is already made — it carries the description's values
and adds the clocks, the identity and the in-flight actions — and a surface that
re-derived one would be a second place the lifecycle is settled.
<!-- refs: `kerbridge_client::agent::status`, `describe::Description` -->
<!-- avoid: view model -->

### supply

Which silent path stands behind the *next* renewal: `Grant`, `WindowsSignIn`,
`BrowserSignIn` or `None`, named in the order the sign-in worker actually tries
them. Possession, never a prediction, and never where the current ticket came
from — a delegated machine with no valid grant reports `None` even while holding
a ticket.
<!-- refs: `kerbridge_client::describe::Supply` -->
<!-- avoid: source, provenance, origin, credential source, renewal path -->

### surface

Anything that draws the client's state: a flyout, a status menu, a sheet, a
`notification`, a console line. Surfaces choose what is primary and what fits;
they never derive a fact.
<!-- avoid: view, ui, window, front end -->

### target

The account a machine or a `/devices` request acts *for*, named by login name or
a literal `kb1|` identity and never by UPN. Set per machine on the client,
carried on the wire as `for`, and absent meaning the caller themselves. It is an
authorization-time input rather than runtime state.
<!-- refs: `RegisterRequest::target` in the broker -->
<!-- avoid: pinned target, delegated user, target account, subject account -->

### TGT injection

The documentation's spelling of `injection`; the same operation, not a narrower
one.
<!-- avoid: ticket injection, submitting a ticket -->

### ticket cache

The OS-held store this user's Kerberos tickets live in: the LSA logon session on
Windows, the `API:` collection on macOS. Never a file the client owns and never
the OS token store; on Windows it is per-LUID, so an elevated shell is a
different cache and an `ACCESS_DENIED` is meaningless without the logon-session
id.
<!-- avoid: credential cache, ticket store, kerberos cache, the lsa cache, cache -->

### trigger

Why a sign-in worker is running — `User`, `Renewal`, `Startup` or `Granted` —
which decides whether a window may open and what a failure means to the person
at the keyboard.
<!-- refs: `agent::worker::Trigger` -->
<!-- avoid: reason, cause, source, mode -->

### unenrollment

Removing the realm's registration from the OS; a reboot finishes it, and it
exists only on Windows. Surfaced only in Settings ▸ Advanced ▸ Windows setup.
<!-- avoid: unenrolment, unenroll, unregister, deregister, deregistration, remove realm -->

### usable

The property of a machine where a ticket could actually be spent: the realm is
known *and* the OS is enrolled for it. A valid TGT that fails this is not access
— measured: with the realm absent from the OS's Kerberos domain table the
exchange succeeds and the TGT injects, then sits valid and unusable.
<!-- refs: `kerbridge_client::describe::Facts::usable`, `…\Lsa\Kerberos\Domains` -->
<!-- avoid: ready, working, valid, enrolled -->
