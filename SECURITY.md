# Security

KerBridge gives cloud identities, such as Entra ID, access to an on-premises
Kerberos realm. That realm usually controls access to a file server (NAS).
It replaces an open or a password-protected Samba domain.

All security software has risks as well as benefits. This document is for the
person who must decide if the risks are acceptable.

## Contents

- [Read this first](#read-this-first) — maturity, and the two limits that hold everywhere.
- [What a breach can expose](#what-a-breach-can-expose) — the scope, and one row per part.
- [What you control](#what-you-control) — your levers, in order of effect.
- [What holds authority](#what-holds-authority) — which part holds what.
- [Software design, and LLM-written code](#software-design-and-llm-written-code)
- [The risks in detail](#the-risks-in-detail):
  1. [The realm host is the whole realm](#1-the-realm-host-is-the-whole-realm)
  2. [A broker compromise issues tickets for any synchronized user](#2-a-broker-compromise-issues-tickets-for-any-synchronized-user)
  3. [The token verifier is hand-written](#3-the-token-verifier-is-hand-written)
  4. [The reply carries the session key](#4-the-reply-carries-the-session-key)
  5. [Revocation is slow, and one lever does nothing](#5-revocation-is-slow-and-one-lever-does-nothing)
  6. [The sync credential](#6-the-sync-credential)
  7. [The `kbmanage` credential is impersonation-grade](#7-the-kbmanage-credential-is-impersonation-grade)
  8. [Device grants remove the browser from the loop](#8-device-grants-remove-the-browser-from-the-loop)
  9. [The workstation](#9-the-workstation)
  10. [One backup file holds the whole deployment](#10-one-backup-file-holds-the-whole-deployment)
  11. [Exposed realm ports](#11-exposed-realm-ports)
  12. [A compromised file server](#12-a-compromised-file-server)
  13. [Dependencies and artifacts](#13-dependencies-and-artifacts)
- [What no test covers](#what-no-test-covers) — the gaps in the test suite.
- [Deliberate limits](#deliberate-limits) — decisions, not oversights.
- [Glossary](#glossary)
- [Report a vulnerability](#report-a-vulnerability)

## Read this first

KerBridge is experimental software. One person wrote it, with much help from
LLM agents. That person is a sysadmin and a programmer with long experience.
Use it at your own risk. See
[Status and disclaimers](README.md#status-and-disclaimers).

The design is conservative where it matters. The implementation is young.

Two properties limit every risk in this document:

- KerBridge holds **no write authority in your cloud IdP**. Authority moves one
  way: from Entra to KerBridge. An attacker who owns the KerBridge host gets
  read access to your Entra users and groups. The attacker gets nothing more.
- The broker holds **no signing key**. It cannot forge a cloud
  [identity proof](GLOSSARY.md#identity-proof), and it cannot invent a new
  identity. An attacker who owns the broker is confined to the accounts that
  sync already admitted. `issuerd` enforces that limit — see
  [risk 2](#2-a-broker-compromise-issues-tickets-for-any-synchronized-user).
  Inside that set, the attacker gets a real Kerberos ticket for any account.

## What a breach can expose

KerBridge touches two systems:

- **Entra ID**, your IdP. KerBridge only reads it.
- **A Samba domain controller** that you install for KerBridge. It controls the
  file server and the other services that you join to it. It controls nothing
  else.

Assume that you run a correct KerBridge on an otherwise secure LAN, and that you
give an Entra group access to a local file server. A defect in KerBridge can
then do two things:

- Give a person on your LAN administrator access to the file server, and to
  every other service that KerBridge protects.
- Show a person on your LAN the Entra users in the
  [admission group](GLOSSARY.md#admission-group). That group controls who can
  use KerBridge to reach the file server.

The table shows what each part protects. Each row links to the full risk.

| If this fails | An attacker gets |
|---|---|
| [The realm host](#1-the-realm-host-is-the-whole-realm) | The whole realm. Every ticket, every file on every joined file server. |
| [The broker](#2-a-broker-compromise-issues-tickets-for-any-synchronized-user) | A Kerberos ticket for any synchronized user, on demand. |
| [The token verifier](#3-the-token-verifier-is-hand-written) | The same, from the internet, with no host access. |
| [The TLS certificate chain](#4-the-reply-carries-the-session-key) | Every ticket that passes over the wire, for one ticket lifetime. |
| [The sync credential](#6-the-sync-credential) | Read access to your whole Entra directory, plus a way to admit an account into the realm. |
| [The `kbmanage` credential](#7-the-kbmanage-credential-is-impersonation-grade) | The ability to act as any user in the device-grant group. |
| [A device grant, on Windows](#8-device-grants-remove-the-browser-from-the-loop) | Tickets as one account, from that machine, until the grant expires. |
| [A backup tarball](#10-one-backup-file-holds-the-whole-deployment) | All of the above, in one file. |

One more threat is credible, but it is not specific to KerBridge. A supply-chain
attack puts unrelated malware into a KerBridge release. The release then carries
that malware to every workstation and every server that installs it. This
applies to all software.

## What you control

These are the levers that change your own risk, in order of effect.

1. **Protect the VM.** Risk 1 below has no software mitigation. Host compromise is
   realm compromise.
2. **Apply the firewall.** Never expose port 88 broadly. Expose port 443 only if
   you must. See [`docs/setup/dns-and-firewall.md`](docs/setup/dns-and-firewall.md).
3. **Shorten the ticket lifetime.** `ticket_lifetime_seconds` in
   `configs/realm.toml`. One hour cuts every revocation window to one hour, and
   costs one extra re-injection per hour.
4. **Leave device grants off** unless an unattended machine needs one. If you
   turn them on, keep `device_grant_days` short, and keep the device-grant group
   small.
5. **Encrypt every backup.** Pipe `backup.sh -` into  `gpg` or such.
6. **Guard the `kbmanage` credential** like a domain admin password. You shouldn't need to remove it from the realm host (or even to view it).
7. **Scope the DNS-01 ACME API token** to a dedicated `_acme-challenge` record or a
   CNAME'd zone. A token that can rewrite your organization's zone is a far
   larger blast radius than a web server needs. Note also where this token sits:
   in the Caddy container's environment. `docker inspect` and `/proc` expose it
   to anyone with root or docker-group access on the host.
8. **Turn operator notification on/off.** Put a URL in `secrets/notify_url` and
   uncomment `url_file`. Without it, the only channels are the container logs and
   the problem directory. Alternatively, keep it off if you are concerned information might leak through it.
9. **Read the audit log after any incident.** Every exchange has a random
   correlation ID. Grants name both parties. Tokens, ccaches, session keys,
   keytabs and credentials are never logged.
10. **Never point Entra Connect or Entra Cloud Sync at this AD.** Both use
    `msDS-ExternalDirectoryObjectId` as their own join key, and would collide
    with KerBridge's identity mapping. It's also completely useless.

## What holds authority

These parts hold something an attacker wants:

| Part | What it holds |
|---|---|
| `issuerd` and the realm | Complete Samba domain and KDC authority. |
| Caddy | The public TLS private key, and the DNS update credential. |
| Broker | The power to ask `issuerd` for a ticket. Read-only directory access. |
| Sync | Graph read authority, and write authority inside one directory OU. |
| `svc-kerbridge-manage` | Delete authority in the IdP parent OU, and full authority in the resource OU. |

The parts are separate on purpose. The broker faces the internet and holds no
key. `issuerd` holds every key and faces no network. Each boundary below is the
thing that keeps those two apart.

## Software design, and LLM-written code

LLM agents, mostly Claude Code, wrote much of this project. The project would not
have been possible without them, given the amount of research and implementation it required.
The result is not "vibe coded", however, but specifically engineered to the shape it is.
Some quality principles:

- **Measurement, not assumed.** Many research spikes measured the
  behaviour that the design rests on, on real Samba, a real Entra tenant, and a
  real TPM. Several plausible designs died on evidence. See
  [`docs/research/INDEX.md`](docs/research/INDEX.md). **So: if you like the idea but don't trust the implementation, feel free to reimplement based on the research**.
- **Extensive unit and integration tests** across the workspaces.
- **One end-to-end test that proves the whole chain.** `make test-stack`
  provisions an empty realm and syncs a directory. It then issues an OIDC token
  and exchanges it for a KDC-signed TGT. With that ticket, and with no password,
  it reads a file over SMB. It also asserts refusals: a replayed device
  assertion gets a 401, and a user who is not a delegate cannot get a service
  account's ticket.
- **Structural defences.** Where a check could be forgotten,
  the design removes the option instead. For example:
  - No symmetric verification routine
    exists in any adapter, so a `HS256` token cannot be verified even if a check
    fails open.
  -  `issuerd` has no TCP listener, so no forgotten firewall rule could expose it.
- **Rust, with no `unsafe` on the server.** The server code set
  `#![forbid(unsafe_code)]`, so the compiler refuses one.  Platform calls go
  through `rustix`'s safe wrappers. Client code (agents) do contain `unsafe` blocks
  due to their native library dependencies, but they are inherently limited to
  the running Windows/MacOS user's privileges.
- **Fail closed by construction.** Every refusal path in the broker's admission
  code returns a denial or a 502. There is no default-allow branch.

## The risks in detail

Each risk states what can go wrong, what limits it, and what the
worst case is.

### 1. The realm host is the whole realm

**Risk.** `issuerd` runs as root and never drops privileges. It reads the Samba
private databases directly. That is full KDC authority: the domain SID, the
`krbtgt` key, and every account key. The realm container and the issuer container
share the same volume.

**What limits it.**

- `issuerd` has no TCP listener. It answers only on a Unix socket.
- It authorizes its caller by peer UID from the kernel (`SO_PEERCRED`), not by
  socket group ownership. It accepts UID 0 and the configured broker UID only.
  It makes this check before it reads the request.
- Every subprocess runs from an argv vector, never a shell string. It clears the
  environment and rebuilds `PATH` without `/usr/local`.
- Keytabs and ccaches go to a per-request directory on **tmpfs**, mode `0700`.
  A `Drop` handler removes the directory on every path, including every error
  path.
- The containers run with `no-new-privileges`, read-only root filesystems, and
  `cap_drop: ALL`. The realm container adds back only the capabilities that measurements showed
  necessary. The issuer
  container adds one (`CHOWN`).

**Worst case.** An attacker with code execution on the realm host owns the realm.
They mint a ticket for any principal, including `Administrator`. They read and
write every file on every joined file server. No KerBridge control stops this,
and none is designed to. Protect the VM.

### 2. A broker compromise issues tickets for any synchronized user

**Risk.** `issuerd` does not re-check the identity proof. It cannot: it never
sees one. It checks only that the SID the broker names resolves to an account
that is eligible. An attacker who reaches the broker's UID asks for any ticket
they want.

**What limits it.** `issuerd` applies its own eligibility gate, and that gate is
an **allowlist, not a deny list**:

- Exactly one directory object must match the SID.
- The `objectClass` set must be exactly `{top, person, organizationalPerson, user}`.
- The account must not be disabled, and must carry no machine-account bit.
- The object must carry a decodable KerBridge external identity marker.

The built-in `Administrator` fails the last check, because sync never created it.
Machine accounts fail the second and third.

**Worst case.** An attacker who controls the broker process gets a Kerberos TGT
for **any human account that sync created**. They get it at any time, with no
token and with no Entra involvement.

They can also plant a device grant on any such account, up to
`device_grant_max_per_user` (default 10). That grant keeps their access after
you close the original hole.

They cannot get a ticket for `Administrator`, for a machine account, or for a
locally-created account.

The audit log records every issue. Read it after any broker incident, and revoke
every device grant you did not create.

### 3. The token verifier is hand-written

**Risk.** KerBridge uses **no JWT library**.
`crates/kerbridge-idp/src/entra/auth.rs` splits the token, resolves the algorithm,
and applies every claim rule itself, calling `ring` for the signature. This is
the single most security-critical routine in the project, and it is bespoke
code in a project whose code is mostly agent-written.

**What limits it.**

- **The algorithm allowlist is structural.** The code resolves `alg` to the
  verification primitive *before* it loads any key. Only `RS*` and `PS*` are
  in the list. `none` and every `HS*` algorithm are absent, and **no symmetric
  verification routine exists anywhere in the crate**. An algorithm-confusion
  attack has nothing to call. The allowlist is typed as ring's `RsaParameters`,
  so a symmetric entry does not compile.
- **No key parsing is written here.** The verifier hands ring the two JWKS
  integers as `RsaPublicKeyComponents`. There is no hand-built ASN.1.
- The code verifies the signature over the exact bytes that arrived, sliced
  from the raw token. It does not re-encode the header or the claims.
- If a JWK states its own `alg`, a token that names a different `alg` for that
  key is refused.
- The verifier checks the structure, the algorithm, the signature, the issuer,
  the audience, the lifetime, the tenant, the token version, the token type, the
  delegated scope, the authorized client and the shape of the subject. It
  refuses the token if one fails. Each check, claim by claim, is in
  [`crates/kerbridge-idp/entra.md`](crates/kerbridge-idp/entra.md).
- The `scp` and `idtyp` checks are the real access control, not defence in
  depth. Entra issues app-only tokens with the broker audience to **any**
  confidential client in the tenant. The spike `entra-token-validation` measured
  this against a live tenant.
- The JWKS handling has these bounds:
  - a 24 h cache;
  - a refresh rate limit of 5 min after a success;
  - a 1 MiB document cap, applied chunk by chunk;
  - a fatal failure at startup, rather than a silent one.
- **The 24 h cache is a refresh trigger, not an expiry.** Past it, the broker
  tries to fetch a new document before it serves a request. If that fetch
  fails, the keys it already holds keep verifying tokens, for as long as the IdP
  stays unreachable. The operator gets an error-level notification after three
  consecutive failures.

  This is a deliberate choice of availability over freshness. Failing closed
  would mean an IdP outage stops every login in the realm, and an aged key buys
  an attacker nothing: the IdP is the only party that ever held the private
  half, so a token signed with a retired key still had to be issued while that
  key was live. The lever against a *stolen* identity is the account, not the
  signing key — see risk 5.

**Known gap.** The JOSE header `typ` claim is **not checked**. The header parser
reads only `alg` and `kid`. No attack is known through this, because `aud`,
`iss`, `azp`, `scp` and `idtyp` together pin the token to one purpose. It is
still a check the standard expects.

**Worst case.** A defect in this routine lets anyone on the internet assert any
identity. They then receive a Kerberos ticket for it. They need no host access
and no credential.

This is the highest-value target in the codebase. If you audit one file, audit
this one.

### 4. The reply carries the session key

**Risk.** `POST /ticket` returns an MIT ccache. A ccache holds the session key
next to the ticket. The request carries a bearer token, which has no channel
binding. TLS is the only thing that protects either one.

**What limits it.**

- Caddy terminates TLS. There is no HTTP listener at all, on any strategy. The
  client refuses a plain-HTTP broker URL, and refuses a plain-HTTP OIDC
  authority.
- Caddy caps the request body at 16 KB and applies header, body and idle
  deadlines.
- Caddy proxies only the documented routes. Everything else gets a 404 at the
  edge. `make test` fails if the allowlist and the broker's router disagree.
- Caddy creates no trusted identity headers. Proxy header configuration is
  never an authorization boundary here.

**Worst case.** A party who can read the traffic gets service tickets for the
whole realm, for one ticket lifetime. These parties can do this: a rogue CA in
the client's trust store, a corporate TLS interception proxy, and a compromised
Caddy. A rotation of the user's key does **not** stop this. See risk 5.

`DESIGN.md` records the construction that would remove the risk: a
sender-constrained token plus a PKINIT hand-off. Entra implements neither DPoP
nor mTLS-bound tokens as of 2026-07, so it is not buildable today.

### 5. Revocation is slow, and one lever does nothing

**Risk.** A Kerberos ticket is a bearer credential with a fixed lifetime. Nothing
recalls one. An open SMB session and a cached service ticket both survive an
account disable until the ticket expires.

**What limits it.** Every KerBridge admission check runs on the exchange path,
so no revocation is slower than one ticket lifetime. The default lifetime is 10
hours. **A shorter lifetime shrinks the worst case in proportion, at negligible
cost.** One hour is a supported hardening option.

Levers, by measured speed:

| Lever | Speed |
|---|---|
| Disable the account | Cuts AS and TGS at once. |
| Remove the global group from the domain-local group | Cuts at the next service ticket. |
| Remove the user from the global group | Cuts at the next TGT. |
| **Rotate the user's Samba key** | **No effect at any layer.** |

**Worst case.** You disable a compromised account and the attacker keeps file
access for up to one ticket lifetime. On an Entra-joined client, the cached
`cifs/` service ticket opens **new** sessions during that window, because the
file server never asks the DC again.

The key rotation row is the dangerous one. It is the reflex action, and it does
nothing. Do not use it as a kill switch.

### 6. The sync credential

**Risk.** Sync holds two credentials: a Microsoft Graph application credential,
and an LDAPS bind password for its own Samba account.

**What limits it, on the Graph side.**

- Exactly two application permissions: `User.Read.All` and `Group.Read.All`.
  Both are read-only. `Directory.Read.All` was rejected on least-privilege
  grounds.
- The app registration has no redirect URI and no exposed API scope. It cannot
  be used interactively.

**What limits it, on the Samba side.** Each source's bind account holds one ACE,
`(A;CI;CCDCWP;...)`, on its own IdP-specific OU and nowhere else. The AD ACL
enforces the boundary at the protocol level. A stolen credential for one source
cannot touch another source's OU, cannot touch `OU=Resources`, and cannot touch
`Domain Admins` or anything else in the directory.

**Sync's own planner cannot delete.** The plan type has no delete operation, so
no plan — however wrong — destroys an object. Leavers are disabled, renamed with
a `_retired-` prefix, and keep their SID. Removed groups are quarantined, not
deleted. A Graph read that does not finish produces no plan at all. A whole read
that describes zero users, while Samba holds synchronized users, freezes the
cycle and raises an alert.

**Precision worth stating.** "Sync cannot delete" is a property of the
**program**, not of the **credential**. The ACE grants delete-child. A person who
steals the bind password file and uses a raw LDAP client can delete any user or
group object inside that source's OU. The planner is not in the path.

**There is no percentage brake.** Only a complete wipe to zero triggers the
freeze. If 40 % of your admitted users disappear from a *complete* Graph read in
one cycle, sync retires 40 % of your directory that cycle.

**Worst case.** A stolen Graph credential reads every user and every group in
your tenant, including the ones that KerBridge never syncs. It writes nothing.

A stolen Samba bind password is worse. An attacker creates an account inside the
source OU. They stamp any external identity on it. They add it to the local
admission group mirror. That admits them to every Kerberos-protected service in
the realm. `DESIGN.md` names this accepted risk directly.

The Graph credential is a **client secret**, not a certificate. A certificate
credential is the intended default and is not built. Set
`sync_credential_expires` so that sync warns you before the secret lapses, and
update the value each time you rotate.

### 7. The `kbmanage` credential is impersonation-grade

**Risk.** `svc-kerbridge-manage` looks like a low-privilege management account.
It is not. It holds a per-attribute `extensionName` write in the IdP parent OU.
An operator needs that write to pin a login name. It also lets the holder
hand-write a device grant. That grant does not go through `issuerd`, so
`issuerd`'s per-request checks never run.

**What limits it.**

- `device_grant_days` in `configs/main.toml` must be non-zero.
- The target account must already be in the device-grant group.

Delegation does not widen this. The credential could already do it.

**Worst case.** A person who holds this credential file gets Kerberos tickets as
any member of the device-grant group. They can also delete any object under the
IdP parent OU. A deleted object that you recreate gets a **new SID**. That breaks
every file ACL that named the old one.

The file lives on the server as `0600 root:root`, and the operator copies it to
their own workstation. That second copy has no expiry, no rotation path, and
whatever protection the workstation has. Treat it like a domain admin password.

### 8. Device grants remove the browser from the loop

Device grants are **off by default** (`device_grant_days = 0`). Read
[`docs/setup/device-grants.md`](docs/setup/device-grants.md) before you turn them
on.

**Risk.** A grant lets a machine obtain Kerberos tickets with no browser and no
Entra sign-in, for a bounded number of days. The authorization is an ECDSA P-256
key held in the machine's TPM.

**What limits it.**

- The Entra sign-in *is* the authorization. No second admission decision is
  invented. The broker validates the token exactly as for a ticket, and
  additionally requires device-grant group membership.
- The assertion binds a server-issued nonce, an audience, an expiry and the
  public key. The nonce is 16 random bytes, single-use, and held under a lock.
  The store has a hard ceiling of 4096 and **refuses rather than evicts**, so a
  flood cannot push out a legitimate nonce. The broker checks the signature
  *before* it spends the nonce.
- The assertion has its own 300 s ceiling on top of the nonce.
- The broker re-runs **every** admission check on the grant path, and
  additionally requires that the presented thumbprint belongs to *that* object.
  A claim on another user's identity fails.
- A machine cannot enroll another machine, and cannot revoke another device.
- On Windows the key uses the platform TPM provider with an export policy of
  nothing. The owning process cannot read the private key out.
- The grant end is **absolute**, stamped at creation. It never slides on use.
  Lowering `device_grant_days` clamps every outstanding grant on the next
  exchange. Setting it to 0 stops every device.

**Stated honestly, in the design: there is no attestation.** The server cannot
tell a TPM key from a software key, and deliberately does not try.

**Things to weigh.**

1. **macOS has no device grants.** The key creation path is not implemented. The
   TPM-binding property is Windows-only today.
2. **Removal of a person from a delegate group stops no existing grant.** It
   stops only new authorizations. Every machine that person already authorized
   runs to its absolute expiry. Any remaining delegate can renew it. Find those
   machines in the broker's audit log, by the `GRANT ... by=` field. Revoke them
   by ID.
3. **Everyone in the device-grant group is a potential delegation target.** Add
   a person to that group for their own convenience, and you also make them an
   account that any delegate can authorize a machine as.

**Worst case.** Malware runs as the user on a granted Windows machine. It gets
Kerberos tickets as the grant's target account, for as long as it stays
resident, with no browser and no Entra. With delegation, that account may not be
the logged-in user. The malware cannot take the key anywhere.

A software key would be worse. An attacker copies it off the machine. They then
use it from anywhere, for the full `device_grant_days`. That widens the
exfiltration window from hours to days.

Two settings bound this: the duration, and the group. If you cannot accept the
window, shorten the duration.

### 9. The workstation

**Risk.** The workstation holds a live Kerberos ticket. Whoever controls the
workstation controls what that ticket reaches.

**What limits it.**

- On Windows there is **no ccache file at all**. The ticket goes from the HTTP
  response, through memory, into the LSA, scoped to the caller's own logon
  session. Another interactive user's session cannot see it.
- The agent runs unprivileged. Only `--enroll` and `--repair` elevate, and
  neither touches a ticket. There is no LocalSystem service and no standing IPC
  endpoint.
- The OIDC flow uses authorization code with PKCE (S256), a `state` nonce, and
  an OS-assigned loopback port bound before the browser opens. Another local
  process that steals the code cannot redeem it without the verifier, which
  never leaves the process.
- TLS verification uses the OS trust store and **cannot be disabled** in the
  production path.
- A `_kerbridge._tcp` SRV answer can only name a host inside a domain the client
  already trusts. The client holds the answer in memory only. It never writes it
  to the config file.
- The refresh token is never persisted. It dies with the process.

**Known gaps.**

- **macOS writes the ccache to disk once.** Heimdal needs a path. The file is
  mode `0600`, created with `create_new` so it refuses to follow a pre-planted
  symlink, and unlinked on every exit path. It exists for the duration of one
  injection.
- **Neither platform zeroes the session key in memory** after use. There is no
  `zeroize`. The bytes live in ordinary buffers until they drop.
- **The config file is user-writable.** It lives in the user's own profile. A
  user can point their own agent at any broker. That leaks only their own future
  credentials, because a broker retarget purges tickets, releases the grant and
  drops the refresh token. An attacker who can write it is already that user.
- **Sign-off is a ticket purge, not a session teardown.** It does not close open
  SMB sessions. There is no lock or logoff hook.
- The client's `unsafe` surface is large and unavoidable: 291 sites, all Win32
  and Objective-C FFI. Ticket injection and TPM key handling are inside it.

**Worst case.** An attacker with the user's session gets that user's realm
access for as long as the ticket lives. They also get the device grant, if one
exists. An attacker with local admin gets the same. They can additionally
install a CA, and so defeat risk 4's protection on that machine.

### 10. One backup file holds the whole deployment

**Risk.** `deploy/scripts/compose/backup.sh` collects `.env`, every config, **all
of `secrets/`**, the audit logs, and the raw Samba volumes. That is the domain
administrator password, the KDC keys, the TLS private key, every bind password,
and the Graph credential, in one file.

**What limits it.** The script sets `umask 077` *before* it creates the file, not
after. It refuses to run while the stack is up: a live Samba database would go
into the archive in a torn state. Give the script `-` and it sends the archive to
stdout. A pipe into `age` or `gpg` then needs no plaintext copy on disk.

**Worst case.** One readable tarball is a total compromise of the deployment,
with no exploit required. **Encrypt it at rest, and treat the key as you would
treat a domain admin password.**

The docs state the matching rule: nothing in `secrets/` should exist anywhere
else on disk, and a backup tarball is the one sanctioned second copy.

### 11. Exposed realm ports

**Risk.** The stack publishes Kerberos, LDAP, SMB, RPC and DNS. Samba AD DC
ports must never face the internet indiscriminately. The host firewall is part
of the required deployment, and Compose does not manage it.

**What limits it.** Each of LDAPS, member and KDC ports has a `*_BIND` variable
in `.env`. `LDAPS_BIND` is loopback-only by default. Binding selects which of
the host's addresses answer. **It does not control which hosts can reach them.**
Only the firewall does that.

**Worst case.** An exposed AS endpoint on port 88 lets anyone use the
failed-password counter to lock out synchronized accounts. Those accounts hold
random, undisclosed passwords, so nobody can unlock them by signing in. Issuance
then fails for those users with `KDC_ERR_CLIENT_REVOKED`. This is standard AD
behaviour, and it makes the lockout policy a denial-of-service lever.

Port 443 is the only endpoint permitted to face the internet, and only when it
must. See
[`docs/setup/dns-and-firewall.md`](docs/setup/dns-and-firewall.md).

### 12. A compromised file server

**Risk.** A joined file server is an ordinary Samba AD member. KerBridge does not
install it and does not manage it. It holds a machine account, a keytab and a
secure channel.

**What limits it.** Nothing KerBridge-specific is delegated to it. It is a member,
not a DC.

**Worst case.** An attacker who owns the file-server host reads every file on it,
holds its machine keytab, and can impersonate its own service principals. They
do not thereby get realm authority.

Two operational notes matter here:

- A DC outage does **not** interrupt SMB for a client that holds a cached
  service ticket. The file server authenticates from its own keytab
  indefinitely. Combined with a cold winbind cache, a name-based `valid users`
  line then denies a correctly authenticated user. **Use SID-based ACLs.** The
  ACL is the control; `valid users` is defence in depth.
- The `nas1` container in this repository is a **test fixture, not a deployment
  pattern**. It rewrites `nsswitch.conf` with an unguarded `sed` and joins the
  domain non-interactively with a password from a file. Do not run a production
  file server that way.

### 13. Dependencies and artifacts

**Risk.** The server workspace locks 267 packages. The client workspace locks
255. 385 are unique across the two. Any of them can carry a defect.

**What limits it.**

- Both lockfiles are committed.
- `make test` gates on exactly one major version each of `rustls`, `ring` and
  `rustls-webpki`, and fails if `aws-lc-rs` enters the tree.
- Every Docker base image is pinned by digest, except the packaging stage in
  `debian/Dockerfile`, which is tag-only.
- Security-relevant versions are visible in the lockfile: `ring 0.17.14`,
  `rustls 0.23.42`, `ldap3 0.12.1`, `axum 0.8.9`.

**What does not limit it.** No `cargo-deny`. No `cargo-vet`. No Dependabot. As
stated above, `cargo audit` runs only by hand. `forbid(unsafe_code)` binds the
server crates and nothing below them: the packages they pull contain `unsafe`,
as every Rust program's do, and nothing here audits it.

**Artifact integrity.**

- **The Windows MSI is unsigned.** SmartScreen warns. Signing is the publisher's
  step, and the build process does not do it.
- **The macOS app is ad-hoc signed only.** There is no Developer ID. This also
  blocks Secure Enclave use.
- Release artifacts carry a `SHA256SUMS` file and **no cryptographic signature**.
  A hash proves integrity against corruption, not against a substituted release.
- Nothing is published to crates.io.

**Worst case.** You cannot verify, from the artifact alone, that a release came
from this repository. Build from source if that matters to you. Every shipping
artifact builds in Docker with `make`.

## What no test covers

The repository states this itself, and it is worth repeating in one place:

- **The live Entra tenant.** No automated test reaches Graph, delta sync, or
  real token issuance. `make test-stack` uses a mock IdP with a throwaway key.
- **The ACME TLS strategies.** Neither DNS-01 nor HTTP-01 is exercised.
- **What Windows does with a ticket after it holds one.** The LSA injection path
  has no automated coverage.
- **systemd units.** `make test-deb` verifies them with `systemd-analyze verify`.
  It never starts one.
- **Rootless Docker.** Not tested, and not supported.
- **macOS code signing.** Neither the ad-hoc path nor the Developer ID path is
  tested.
- **Operator notification against a real event.** A synthetic test message
  reached a real channel. A real event, a real recovery, and real suppression
  over time did not.
- **Most hostile input.** The 543 tests cover correct behaviour far more than
  they cover attacks. Tests for injection and malformed input exist in
  `issuerd` and `kerbridge-core`. They are thinner elsewhere.

Three further scope limits:

- **The bearer path has no replay defence in the broker.** A captured, still-valid
  Entra access token works against `/ticket` until it expires. This is the
  ordinary OAuth bearer model. TLS and the token lifetime are the protection.
  Device-grant assertions, which *do* have nonce protection, are the exception.
- **The nonce store is per process and in memory.** A broker restart invalidates
  every outstanding nonce, by design. Two broker replicas do not share one, and
  a multi-replica deployment is not supported.
- **Only `POST /ticket` is concurrency-capped.** `max_inflight` protects the
  directory and `issuerd`. The `/nonce` and `/devices` routes are not under that
  cap. They are gated instead: `/nonce` touches no directory and self-bounds at
  4096; the `/devices` routes require a valid credential before any LDAP work.
  A caller who holds one valid token can still drive uncapped concurrent
  directory reads through them.

## Deliberate limits

These are decisions, not oversights. Each is recorded with its reasoning in
[`DESIGN.md`](DESIGN.md).

- **No attestation for device grants.** The cost is vendor EK certificate chains
  to ship and maintain, and the loss of a server side that is testable with a
  software key. An unverified claim is worth nothing, so there is no cheap
  middle. See [Device grants (`DESIGN.md`)](docs/design/tickets.md#device-grants).
- **A TGT, not a service ticket.** The tighter variant was built and works. But a
  bare service ticket is not usable by stock Linux `smbclient`, and it buys one
  service per exchange. A TGT lets the KDC, not the broker, decide what an
  identity may reach.
- **Sync holds a coarse write ACE.** A minimal 16-ACE set was measured
  sufficient. The coarser grant ships anyway, for two reasons. A stolen sync
  credential already grants realm access under either scheme. And an attribute
  list has to be re-derived each time sync writes a new attribute.
- **No multi-DC replication and no application HA.** One VM, one realm.
- **No backup scheduling, retention or off-site copy.** KerBridge collects its
  state into one tarball and puts it back. Everything else is yours.

## Glossary

This document uses the project's terms exactly. Some words look ordinary but are
pinned to one meaning here: *admission*, *fail closed*, *identity proof*,
*retired prefix*, *quarantined group*, *delegate*. Their definitions are in
[`GLOSSARY.md`](GLOSSARY.md).

## Report a vulnerability

If it's something that could be readily exploited, send a mail to maintainer. Write `KerBridge security` in the subject. Do not open a public issue for a vulnerability. Open a public issue for everything else.

**There is no bounty**, no service level, and no guaranteed answer time. One person
maintains this project. A fix arrives when that person can make one, if at all. You are invited to provide a patch if you can.
