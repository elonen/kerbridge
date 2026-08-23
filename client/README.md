# client — the workstation software

Client is what end-user installs. It signs them in to the cloud IdP in the system browser,
exchanges the token with the KerBridge broker for a real KDC-signed TGT, and puts
that ticket where the operating system's own Kerberos stack will find it — after
which the stock SMB client reaches the realm's shares with no password and no
custom software in the data path.

Users know it as **NAS Access by KerBridge**. That is the product name and it is on
every surface a non-technical person sees. The names below are what an
administrator or a developer sees, and they are the same on every platform.

| | What | Where |
|---|---|---|
| `kerbridge-client` | The core: every protocol decision, the agent's state machine and copy, plus the `kerbridge` CLI over it | [`kerbridge-client/`](kerbridge-client/) |
| `kerbridge-agent` | The background agent — systray on Windows, menu bar on macOS. One crate per platform, one binary name | [`kerbridge-agent-windows/`](kerbridge-agent-windows/), [`kerbridge-agent-macos/`](kerbridge-agent-macos/) |

[`DESIGN.md`](DESIGN.md) is the client design, authoritative for all of it: the
broker contract, the ticket lifecycle, the status model and the words. What one
platform does alone is in that agent's own document —
[`kerbridge-agent-windows/DESIGN.md`](kerbridge-agent-windows/DESIGN.md) and
[`kerbridge-agent-macos/README.md`](kerbridge-agent-macos/README.md).

## Why it is shaped this way

**One core, one agent per platform.** An agent crate owns its platform's UI and
nothing else — no discovery, no token handling, no injection, and no decision
about *when* to do any of it. What that buys is that the shipping agent and the
CLI you debug with cannot disagree about what the broker said, and that two
platforms cannot disagree with each other about what keeps a ticket alive.

**The line runs through the window, not through the platform.** The re-injection
schedule is what stops the worst measured failure mode, and the eleven translated
string tables are the product's voice; neither is Windows' business, so both are
in the core. A platform supplies the eight methods behind `agent::Host` — wake
the UI thread, notify, report an outcome, say that an elevation has started, name
the primary action, raise the status window, open a path, ask the OS for a token
— and that is the whole of what the core knows about it.

The other seams go the other way: `#[cfg]`-selected calls *down* into an OS that
has no portable spelling for what we want. There is one per subject rather than
one big `platform.rs` — `tickets`, `srv`, `enroll`, `device`, `time`, `config`,
`elevate`, `repair`, `sys` — so the reason a thing differs is written next to the
thing. Some of those differences are that a platform needs *nothing*: macOS has
no realm to enroll and no NTLM fallback to repair, and both arms say so in a
sentence rather than by omission.

The arms themselves are gathered in `src/windows/` and `src/macos/`, one file per
subject, so reading what the client does on one platform does not mean visiting
nine directories. Neither folder is a module — each file is reached by `#[path]`
from the subject that owns it — so the grouping costs the module tree nothing.

**The CLI ships too.** `kerbridge` is not a development tool that escaped; it is
installed next to the agent, because when the agent is the thing under suspicion
you need the same code path with visible output and one shot at a time.

**Its own Cargo workspace**, excluded from the repository root's. The server
crates target x86_64-musl; everything here targets a workstation. The core builds
for the host, so `cargo test` on a Mac runs the real Kerberos and DNS code rather
than stubs; Windows is reached with an explicit `--target x86_64-pc-windows-gnu`
and the MinGW linker named in `.cargo/config.toml`. One lockfile for the client,
so the platform agents cannot resolve the core's dependencies differently from
each other.

**`assets/` holds the logo, once.** Each platform's packaging rasterizes it into
whatever that platform wants; the derived file is committed next to the packaging
that consumes it.

## Building

```sh
cd kerbridge-agent-windows && make check   # cross-build both binaries + clippy
cd kerbridge-agent-macos   && make check   # native build + clippy (macOS host)
cd kerbridge-client        && cargo test   # the core, on this host
```

From the repository root, `make windows` cross-builds in a container and
`make installer` packages the MSI there too, so a host with only Docker needs no
Rust and no MinGW. The macOS agent is the exception: an `.app` has to be built on
a Mac, with Xcode's command-line tools. Each crate's `README.md` has the rest.
