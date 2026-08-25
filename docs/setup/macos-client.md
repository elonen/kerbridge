# The macOS client

This page is the macOS half of
[step 7 (*Set up a workstation*) in SETUP.md](../../SETUP.md#7-set-up-a-workstation).
The facts that apply to both platforms are in that step. This page holds what
is different on a Mac.

A Mac needs the agent only. This platform has **no realm registration, no
administrator prompt and no repair path**. Heimdal resolves the realm from the
DNS records that step 3 published. A Mac that did not know the realm received a
`cifs/` ticket with no configuration file of any kind. This was measured:
research spike `macos-ticket-injection`.

## What ships

- `NAS Access.app` — the product. It is a per-user menu-bar agent,
  `LSUIElement`, with no Dock tile. The binary inside is `kerbridge-agent`, the
  same name that it has on every platform.
- `kerbridge` — the same core as a console tool. It does one operation at a
  time and shows its output. It is not part of the bundle. Build it when you
  think that the agent itself has a fault.

Neither executable runs as root at any time.

## Download it

Each release attaches `macos-kerbridge-nas-access-gui-arm64.app.zip`. Unzip
it to get `NAS Access.app`. The bundle is **arm64 only**, because that is the
architecture of the runner that builds it. On an Intel Mac, build it.

## Build it

```sh
make macos          # from the repo root -- writes dist/NAS Access.app
```

The build is native only. A Mac assembles the `.app`, and no container can do
this instead. The build needs a Rust toolchain and the Xcode command-line
tools, nothing else. Every framework that the app links ships with the OS.

To build the CLI:

```sh
cd client/kerbridge-client && cargo build --release   # -> client/target/release/kerbridge
```

> **Note: The bundle is ad-hoc signed and not notarized.** If you build it on
> the machine that runs it, it opens with no message. If it arrives from
> another location — a download, an AirDrop transfer or a copy from a share —
> it carries a quarantine flag, and Gatekeeper refuses it until you allow it in
> System Settings ▸ Privacy & Security. In both cases, Login Items lists it
> under *Item from unidentified developer*. See
> [rough-edges.md](rough-edges.md).

## Install it

There is no installer. Copy `NAS Access.app` to `/Applications` and open it.

Copy the app **before** you turn on *Start at login*. The registration records
the location of the app. If you move the app afterwards, macOS points to a path
that holds no app.

## First run

1. **Open NAS Access.** The menu-bar icon appears and opens its menu, which
   says *Broker URL not configured*.
2. **Sign in.** The browser opens. Complete the sign-in there.
3. **Tick *Start at login*** in Settings. On this platform the ticket goes into
   the login session's own credential cache, and that cache is the only one
   that `gssd`, and thus Finder, looks in.

Then, in Finder, use **Go ▸ Connect to Server** and enter
`smb://nas.example.site`. No password prompt appears.

Nothing on macOS renews an injected TGT. A mount continues after the end time
of its ticket *only* when a fresh TGT is already in the cache. The agent's
re-injection schedule exists to guarantee that condition.

> **Note: Expect one sign-in for each login.** The agent tries a sign-in with
> no prompt when it starts, and on this platform it has no credentials for the
> attempt: the refresh token is memory-only by design, there is no native token
> source yet, and the ticket cache belongs to the login session, so a fresh
> session starts empty. The attempt fails with no visible error, and the
> failure goes to the log only. The menu says *Needs a browser sign-in* until
> someone clicks. A restart of the agent *inside* a session is different: the
> agent adopts the ticket that is already in the cache, and it starts in a
> working state.

## What the menu bar shows

The icon is monochrome in every state, because a menu bar reserves color for
itself. The icon shows two independent things:

| Icon | Means |
|---|---|
| the logo, at full strength | a ticket that this Mac can spend — the shares open now |
| faded | no such ticket |
| a triangle in the corner | renewal is uncertain, or access will stop at a known time |
| a disc in the corner | access stopped |

So a faded logo with no badge shows a Mac that never worked here. A full logo
*with* a badge shows a Mac whose shares open at this minute but will stop
later. The badge is a warning about the ticket supply, never about the current
state.

Click the icon to open the menu, which is also the status window. The menu
shows the state in one line, the identity that you are signed in as, and any
deadline. Then it shows the actions that the state offers, and the reasons.
*Kerberos details…* shows the realm, the ticket's own terms, what the next
renewal would use, and when that renewal is due.

## Config and logs

These files are per-user, at `~/Library/Application Support/KerBridge/`:

- `config.toml` — the broker URL and two toggles.
- `kerbridge.log` — also reachable from the menu. When it is larger than 10 MB,
  it rotates at the next start into `kerbridge.log.1.gz` … `.3.gz`.

The ticket goes into the Heimdal `API:` ticket cache of this login session.
That cache is memory in the user's session, not a file. `klist` shows the
ticket. `kdestroy` discards it, and the agent puts it back at the next
re-injection.

## Preconfiguring a fleet

A *forced* managed preference in the `org.kerbridge.agent` domain overrides the
per-user config file. It is the *platform policy value* in the broker URL
resolution order of [step 7](../../SETUP.md#7-set-up-a-workstation). An MDM
profile writes it to
`/Library/Managed Preferences/org.kerbridge.agent.plist`:

| Key | Type | Effect |
|---|---|---|
| `BrokerUrl` | string | Takes priority over every source below it; the Settings field becomes read-only |

Only *forced* values count. A `defaults write` by the user is intentionally not
policy. If it were policy, it would lock the Settings field against the person
who set the value.

## Not here yet

- **No native token source.** The Windows agent asks WAM, and WAM can issue a
  broker token from the sign-in that the machine already holds. The Mac
  counterpart is the Company Portal SSO extension. That extension is a
  deployment dependency and a spike of its own. Until that spike is measured,
  every sign-in goes through the browser.
- **No device grant.** The Secure Enclave is the counterpart of the Windows TPM
  key. But an Enclave key needs a keychain-access-group entitlement, and that
  entitlement needs the signature work above.

The state machine, the schedule and every user-visible string come from the
core, not from this agent:
[`client/kerbridge-agent-macos/README.md`](../../client/kerbridge-agent-macos/README.md).
