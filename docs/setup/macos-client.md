# The macOS client

This page gives the detail for
[step 7 (*Set up a workstation*) in SETUP.md](../../SETUP.md#7-set-up-a-workstation).

A Mac needs only the agent. This platform has **no realm registration, no
administrator prompt and no repair path**. Heimdal resolves the realm from the
DNS records that the deployment already publishes. A Mac that did not know the
realm received a `cifs/` ticket with no configuration file of any kind. This
was measured before this page was written:
research spike `macos-ticket-injection`.

## What ships

- `NAS Access.app` — the product. It is a per-user menu-bar agent, `LSUIElement`,
  with no Dock tile. The binary inside is `kerbridge-agent`, the same name that
  it has on every platform.
- `kerbridge` — the same core as a console tool. It does one operation at a
  time and shows its output. It is not part of the bundle. Build it when you
  think that the agent itself has a fault.

Neither executable runs as root at any time.

## Download it

Each release attaches `kerbridge-nas-access-arm64.app.zip`. Unzip it to get
`NAS Access.app`. The bundle is **arm64 only**, because that is the
architecture of the runner that builds it. On an Intel Mac, build it.

## Build it

```sh
make macos          # from the repo root -- writes dist/NAS Access.app
```

The build is native only. A Mac assembles the `.app`, and unlike the Windows
agent, no container can do this instead. The build needs a Rust toolchain and
the Xcode command-line tools, nothing else. Every framework that the app links
ships with the OS.

To build the CLI:

```sh
cd client/kerbridge-client && cargo build --release   # -> client/target/release/kerbridge
```

> **Note:** The bundle is ad-hoc signed and not notarized. If you build it on
> the machine that runs it, it opens with no message. If it arrives from
> another location — a download, an AirDrop transfer, or a copy from a share —
> it carries a quarantine flag, and Gatekeeper refuses it until you allow it
> in System Settings ▸ Privacy & Security. In both cases, Login Items lists it
> under *Item from unidentified developer*. A Developer ID signature and a
> notarization pass are release-time tasks for the publisher. See
> [rough-edges.md](rough-edges.md).

## Install it

There is no installer. Copy `NAS Access.app` to `/Applications` and open it.

Copy the app **before** you turn on *Start at login*. The registration records
the location of the app. If you move the app after registration, macOS points
to a path that no longer holds an app.

## First run

1. **If you used `TLS_STRATEGY=external`:** install your CA root into the
   System keychain and mark it trusted. The agent validates against the OS
   trust store. Without the CA root, it will not speak to the broker.
2. **Open NAS Access.** The menu-bar icon appears and opens its menu, which says
   *Broker URL not configured*. If your `_kerbridge._tcp` SRV record is in
   place, the broker URL field already shows the value that the agent
   found. If not, type `kerbridge.example.site` in Settings. The agent adds
   `https://` for you, and it refuses plaintext `http://`.

   A realm with **more than one source** has to say which one: the address ends
   in the source name, `kerbridge.example.site/entra`. The bare host is enough
   for the single-source realm this guide builds, and a realm that later adds a
   second source tells these clients so — they refuse with the names to choose
   from rather than picking one.
3. **Sign in.** The browser opens; complete the sign-in there.
4. **Tick *Start at login*** in Settings. Autostart is per-user by
   construction. The ticket goes into the login session's own credential
   cache. That cache is the only one that `gssd`, and thus Finder, will look
   in.

The agent then injects a TGT, and injects again at half of the remaining
ticket lifetime. Nothing on macOS renews an injected TGT. A mount continues
after the end time of its ticket *only* when a fresh TGT is already in the
cache. The schedule exists to guarantee that condition.

**Expect one sign-in for each login.** The agent tries a sign-in with no
prompt when it starts. On this platform, it has no credentials for the
attempt:

- The refresh token is memory-only by design.
- There is no native token source yet.
- The ticket cache belongs to the login session, so a fresh session starts
  empty.

The attempt fails with no visible error; the failure goes only to the log. The
menu says *Needs a browser sign-in* until someone clicks. A restart of the
agent inside a session is different: the agent adopts the ticket that is
already in the cache and starts in a working state.

Then, in Finder, use **Go ▸ Connect to Server** and enter
`smb://nas.example.site`. No password prompt appears.

## What the menu bar shows

The icon is monochrome in every state, because a menu bar reserves color for
itself. The icon shows two independent things:

| Icon | Means |
|---|---|
| the logo, at full strength | a ticket that this Mac can spend — the shares open now |
| faded | no such ticket |
| a triangle in the corner | renewal is uncertain, or access will stop at a known time |
| a disc in the corner | access stopped |

Thus a faded logo with no badge shows a Mac that never worked here. A full
logo *with* a badge shows a Mac whose shares open at this minute but will stop
later. The badge is a warning about the ticket supply, never about the current
state.

Click the icon to open the menu, which is also the status window. The menu
shows the state in one line, the identity that you are signed in as, and any
deadline. Then it shows the actions that the state offers, and the reasons.
*Kerberos details…* shows the realm, the ticket's own terms, what the next
renewal would use, and when that renewal is due.

## Config and logs

These files are per-user, at `~/Library/Application Support/KerBridge/`:

- `config.toml` — the broker URL and two toggles. It holds no secret: the
  refresh token never touches the disk.
- `kerbridge.log` — also reachable from the menu. When the log is larger than
  10 MB, it rotates at the next start into `kerbridge.log.1.gz` … `.3.gz`.
  Send the rotated files together with the log.

The ticket goes into the Heimdal `API:` ticket cache of this login
session. That cache is memory in the user's session, not a file. `klist`
shows the ticket. `kdestroy` discards it, and the agent will put it back at
the next re-injection.

## Preconfiguring a fleet

A *forced* managed preference in the `org.kerbridge.agent` domain overrides
the per-user config file. This preference is what an MDM profile writes to
`/Library/Managed Preferences/org.kerbridge.agent.plist`:

| Key | Type | Effect |
|---|---|---|
| `BrokerUrl` | string | Has priority over all sources below it; the Settings field becomes read-only |

Only *forced* values count. A `defaults write` by the user is intentionally
not policy. If it were policy, it would lock the Settings field against the
person who set the value.

Broker URL resolution order:

1. `--broker` flag
2. managed preference
3. `config.toml`
4. `_kerbridge._tcp` SRV
5. first-run prompt

**If you publish the SRV record, you push nothing at all.** This is the
intended deployment.

## Not here yet

- **No native token source.** The Windows agent asks WAM, and WAM can issue a
  broker token from the sign-in that the machine already holds. The Mac
  counterpart is the Company Portal SSO extension. That extension is a
  deployment dependency and a spike of its own. Until that spike is measured,
  every sign-in goes through the browser.
- **No device grant.** The Secure Enclave is the counterpart of the Windows
  TPM key. But an Enclave key needs a keychain-access-group entitlement, and
  that entitlement needs the signature work above to exist first.

The state machine, the schedule and every user-visible string come from the
core, not from this agent:
[`client/kerbridge-agent-macos/README.md`](../../client/kerbridge-agent-macos/README.md).
