# Design » API and network

The wire contract that a client depends on, and the ports, resolvers and
firewall zones that carry it. [`DESIGN.md`](../../DESIGN.md) is the index.

## Public broker API

Each route carries the source name as its first segment: `/{source}/config`,
`/{source}/ticket`, `/{source}/nonce`, `/{source}/devices` and
`/{source}/devices/{id}`. A segment that names no configured source gets a 404.
Discovery is the one exception, below. Caddy's allowlist
(`deploy/caddy/routes.caddyfile`) passes exactly this set and the bare `/config`.
Each other path gets a 404 at the edge.

### `GET /{source}/config`

Unauthenticated, and served over HTTPS only. It returns the configuration
document that a helper needs to bootstrap from a broker URL alone:

```json
{
  "base_url": "/entra",
  "oidc":     { "authority": "...", "client_id": "...", "scopes": ["..."], "display_name": "Entra" },
  "kerberos": { "realm": "EXAMPLE.SITE", "kdcs": [], "services": [] },
  "ticket_format": "mit-ccache-v4",
  "device_grant": { "days": 0, "max_per_user": 10, "audience": "kerbridge://EXAMPLE.SITE" },
  "client_defaults": { "autostart": true }
}
```

- `client_defaults` is `main.toml`'s `[client_defaults]` republished verbatim,
  and the block and every key in it are omitted where the operator set none.
  The broker holds no opinion about any of it: the agent resolves it against its
  own machine policy and its user's file, both of which win. It exists for the
  workstations no management system owns — see `client/DESIGN.md`
  @ Configuration and storage.

- `base_url` says where this source's other routes are. It is a reference that
  the client resolves against the address that the document came from — `/entra`,
  and never an absolute URL. It is relative because the broker does not know the
  deployment's public name. An absolute answer could only be rebuilt from the
  `Host` header, and a client that trusted that header could be re-based onto
  another origin by whoever set it. The client sends that run's `/ticket`,
  `/nonce` and `/devices` to the resolved base, and stores none of it. A stored
  copy pins a machine that follows DNS to whichever source answered on the day
  that the machine was set up.
- `kdcs` is normally empty. With `_kerberos._udp.<realm>` published, client
  enrollment registers the realm and pins no KDC hostname. That is the shape that
  survives a replacement of a DC.
- `services` is the escape hatch. It holds plain host or suffix entries for
  `ksetup /addhosttorealmmap`, for a service that lives outside the realm's DNS
  zone. It is empty in the common layout, where the DNS-suffix heuristic maps
  same-zone hosts without help.
- `device_grant.days` of 0 is the whole answer for a deployment that has the
  feature off. The tray never offers the feature, and takes the duration in its
  own strings from this value instead of a hardcoded one.
- `device_grant.audience` is what a device assertion must name. The broker states
  it, and the client does not derive it, and thus the two ends cannot disagree
  about the spelling. It is derived from the realm, because the broker knows
  nothing about its own public URL: Caddy ends TLS, and `broker.toml`'s `listen`
  is loopback.

The client still does standard OIDC discovery against the authority.

#### `GET /config`, without a segment

Discovery alone is also served unprefixed. It is the only route that a client
can reach before it knows a source name: `_kerbridge._tcp.<domain>` carries a
host and a port, and has nowhere to put a path. Thus a client that found its
broker in DNS has nothing else to ask for. The route answers the prefixed
document, `base_url` included, and the client re-bases on that.

It is answered **only where exactly one source is configured**. With two sources
there is no correct answer, and to guess one is what the segment exists to
prevent: the client would authenticate against whichever source sorted first,
successfully, forever. Instead the reply is a 404 with

```json
{ "error": "which source?", "sources": ["entra", "entra-legacy"] }
```

It lists the names, and does not only refuse, because the operator who reads it
must put one name in a URL and this is where they find out which. A client tells
this 404 from each other 404 by the body, and not by the status.

The routes that issue or revoke stay prefixed-only. By the time that a client
asks for a ticket, it has read a discovery document and names the source that it
asks about.

### `POST /{source}/ticket`

The request carries **exactly one** of:

```http
Authorization: Bearer <access-token>
Authorization: DeviceGrant <assertion>
```

The scheme is parsed first, and exactly one must match. Anything else is refused
outright, and does not fall through to a weaker check. Both schemes end at the
same directory lookup and the same `issuerd` call. Thus the admission path is one
path by construction, and not by discipline. Both contend for the one
`max_inflight` cap (`configs/broker.toml`).

An assertion is `<base64url(payload)>.<base64url(signature)>` — two parts, and
not three, because there is no header for anything to negotiate. The stored grant
names the algorithm, and the client does not choose it. The payload binds the
public key, the claimed `kb1|` identity, a single-use nonce from `GET /nonce`,
the audience and a short expiry.

Success:

```json
{
  "principal": "alice@EXAMPLE.SITE",
  "ccache_b64": "..."
}
```

The response can gain start, expiry and renewal timestamps in a
backward-compatible version of the contract. `issuerd` already returns them, and
the broker logs them. The response never returns user keys, temporary
certificates or refresh tokens.

Status classes:

| Status | Meaning |
|---|---|
| 400 | Malformed request |
| 401 | Invalid or expired identity proof — including a device grant that has expired, been clamped or been revoked |
| 403 | Valid identity not synchronized, disabled, outside the admission group, outside the device-grant group, or outside the delegate group of an account it named |
| 429 | In-flight cap reached (`max_inflight` in `configs/broker.toml`); refused, never queued |
| 500 | The issuer refused a request the broker had already admitted — the two disagree, which is a server fault |
| 502/503 | Directory (502) or issuer (503) temporarily unavailable |

A failure body is `{"error": "<short reason>", "request_id": "..."}`. The 401
says only "invalid identity proof", however the proof failed. The 403
distinguishes not provisioned, disabled, not admitted, and not permitted to
authorize a device. Only a caller whose token has already verified reaches a 403,
and the reason is what the tray shows them. Internal command errors are
correlated through the request ID and logged on the server. They are never
surfaced verbatim.

Usually the reason is about the caller's own account. A `for` on `/devices` is
the exception. An admitted caller who names another account learns from the 403
whether that login name exists, whether it is enabled, and whether it is in the
device-grant group. This is accepted, because each one of those facts is already
one authenticated LDAP read away. That same read is how the broker's own
unprivileged bind evaluates the delegate link. Thus the alternative would be a
uniform refusal that tells a legitimate delegate nothing, and an attacker nothing
new. The caller is resolved *before* the target, and thus someone who is not
admitted at all still learns nothing.

The tray branches on the 403 reasons, and thus they are contract and not prose.
Verbatim:

| `error` | Cause |
|---|---|
| `identity is not provisioned` | sync has not created the object yet |
| `account is disabled` | `UF_ACCOUNTDISABLE` |
| `account is not admitted to the realm` | outside the admission group |
| `account may not authorize a device` | outside the device-grant group |
| `you may not authorize a device for that account` | outside the delegate group of the account a `for` named |
| `device grants are not enabled` | `device_grant_days` is 0 |

The client shares no crate with the broker, because it cross-compiles to Windows
on its own. Thus these strings are spelled on both sides of the wire. `make test`
holds the two sources and this table to the same list, because a reword on the
broker side would otherwise silently change what a user is told, in each locale
at once.

**The status code does not decide whether the client falls back.** A 401 always
falls back, and so do the last two 403s above. Those two say that the device
grant is finished while the person at the keyboard can still sign in that minute,
and in both the operator's intent *is* "use a browser from now on". The rest
stay hard, because no browser helps an account that is unprovisioned,
disabled or outside the realm. To treat them all as hard stops did not send
granted machines back to the browser. At `device_grant_days` = 0 it stopped them
getting a ticket at all, measured 2026-08-02. Neither of the two discards the
stored grant: both are the operator's to undo, and a grant that is put back in
the group works again, untouched.

**An expired or clamped grant is a 401, and not a 403.** The client's correct
response is a browser sign-in, which is what 401 means to the tray. A 403 means
that the identity is fine and that to authenticate again will not help. That is
true of "not in the device-grant group", and false of an expired grant.

### `GET /{source}/nonce`, `/{source}/devices`

These routes are present only when `device_grant_days` is non-zero. Each route
below answers 403 otherwise.

| Route | Credential | Purpose |
|---|---|---|
| `GET /{source}/nonce` | none | A single-use nonce for a device assertion. Unauthenticated like discovery: sixteen random bytes tell a caller nothing and let nobody in, and the store's own ceiling bounds it |
| `POST /{source}/devices` | Bearer | Authorize this device. Returns the grant handle, the deadline and the account's `kb1|` identity |
| `GET /{source}/devices` | Bearer | The devices this user has authorized |
| `DELETE /{source}/devices/{id}` | Bearer, **or** DeviceGrant naming itself | Stop one device |

To create a grant, to list grants, or to revoke *another* device needs a
delegated Entra token. A machine must not be able to enroll more machines, and a
compromised machine must not be able to knock the user's other devices offline.
A DeviceGrant assertion that names any other id is refused 403
`a device may only remove itself`.

To revoke *itself* needs no such thing, because to leave is not an attack. The
rule enforces itself, because the grant path never produces an Entra token.

Every route takes an optional **target**: a `for` field on the `POST` body,
and a `for` query parameter on the other two. It names the account that the grant
belongs to. If it is absent, the target is the caller themselves, which is each
self-service request. If it is present, this is the delegation path of
[Delegating the authorization](tickets.md#delegating-the-authorization): the
caller must be in that account's delegate group, and the `kb1|` identity that
comes back is the target's. A `for` on a `DELETE` that is presented with a
DeviceGrant assertion is a 400 and not a 403, because a machine may name its own
identity only. That is the same rule that already binds it to its own thumbprint.

A target is a `sAMAccountName` or a literal `kb1|` value. **A UPN is refused
400.** A login name is domain-unique, and thus resolution is exactly-one-or-
refuse. A `kb1|` value needs no lookup at all. A UPN would be a second mutable
spelling that arrives as end-user input and travels in an assertion. `kbmanage`
keeps the wider resolution that its other verbs offer, because there the audience
is an operator and the string reaches nothing that an attacker does.

## Host networking and DNS

These rules hold, whatever the network shape:

- Caddy binds the public HTTPS port.
- The broker binds loopback only, and refuses to start on any other address.
- Samba binds its DC ports.
- `issuerd` binds a Unix socket only.

**The shipped `deploy/compose.yaml` is the supported shape:** a bridge network,
with published ports and named volumes. It is what each deployment has run, the
development bench included. That covers a Linux host that serves a real public
domain, with a separate file server that is joined across the LAN, and a publicly
trusted certificate.

Host networking is a documented alternative, and not the target. It suits an
operator who wants the DC to own the host's network identity, and it removes the
static subnet, the published-port list and the shared network namespace with it.
What it costs is a bench. Docker Desktop has no host networking to give, because
`--network host` there attaches to the hidden desktop VM and not to a LAN. Thus a
macOS developer cannot run it at all, and `nas1` in `compose.nas.yaml` cannot
coexist with a DC that holds `:445` on the host. Research spike
`host-networking-and-dns` §14 is its verification checklist, and stays unrun.

Little of consequence rides on the choice. Nothing in the stack addresses another
service by container name: the two LDAPS clients use the DC's FQDN, Caddy reaches
the broker on loopback, and the broker reaches `issuerd` through a Unix socket.
Thus the same configuration describes both shapes. Two differences are worth
knowing:

- Under the bridge shape, Caddy shares the broker's network namespace, and
  nothing else can reach the broker's loopback listener. Under host networking it
  is the *host's* loopback, and thus each process on the box can reach it. The
  host becomes the trust boundary.
- Under the bridge shape, the address that a port is published on narrows a
  listener (`LDAPS_BIND`, `MEMBER_BIND`, `KDC_BIND`). Under host networking that
  job belongs to Samba's `interfaces` and `bind interfaces only`, which is per
  listener set and not per port. Thus to narrow one port and not another becomes
  a firewall rule instead — §10's `nftables` matrix.

Samba internal DNS owns `example.site` in the documented setup. What must reach
it depends on the client:

- Unjoined helper clients need `kerbridge.example.site` and the `_kerberos._udp`
  and `_kerberos._tcp` SRV records only. They can also use
  `_kerbridge._tcp.<domain> SRV 0 100 443 kerbridge.<domain>.`, which is how a
  client with no configured broker address finds one. Thus no registry value must
  be pushed to a workstation. Where the realm reuses an existing zone, publish
  those records statically in the site resolver, and never point a workstation at
  Samba DNS at all.
- File servers need the full DC-locator record set. Thus they either use the
  Samba DC as their resolver, or the existing resolvers delegate `example.site`
  to it or forward `example.site` to it conditionally.

`kerbridge.example.site` is both the DC name and the broker name. Provisioning
creates it in Samba DNS, and it resolves to the KerBridge VM. DNS-01 ACME updates
the TXT records of the public DNS provider, and does not need the Samba DNS
service to be exposed to the Internet. This is a split-horizon arrangement, and
it needs ownership of the public domain.

The proven port set and rules (research spike `host-networking-and-dns`):

- Ports: DNS 53, Kerberos 88, RPC 135 with the pinned dynamic range, LDAP and
  CLDAP 389, SMB 445, kpasswd 464, LDAPS 636, and Global Catalog 3268 and 3269.
  There is no port 123: `ntp_signd` is Unix-socket-only, and the VM runs chrony
  with `ntpsigndsocket`.
- NetBIOS 137-139 is removed completely: `disable netbios = yes` and
  `smb ports = 445`. A member join was proven without it.
- Dynamic RPC is pinned with `rpc server dynamic port range = 49152-49251`.
- Kerberos 88 is restricted to LAN zones. An exposed AS endpoint lets an attacker
  lock out a synced account, which also breaks issuance.
- Clients must reach the KDC over **TCP/88**, and Windows clients need the realm
  flagged as TCP-capable. A PAC-bearing TGS-REP exceeds the UDP reply limit
  (`KRB-ERROR 52 RESPONSE_TOO_BIG`), and stateful firewalls drop the fragmented
  UDP reply in any case.
  - Client knob: `ksetup /addrealmflags <REALM> tcpsupported`. It is read live,
    and needs no reboot.
  - `MaxPacketSize` is inert, *and* it suppresses Windows' own RFC-4120 TCP
    retry. Never use it.
  - Publish the `_kerberos._udp.<realm>` SRV record, so that clients need no
    per-client KDC hostname. Windows consults the `_udp` name only, and to
    publish both names is the safe default. The `ksetup` realm registration stays
    mandatory per client. `KdcNames` does not (research spike
    `windows-tgt-followup-entra-joined`, which supersedes the phase-5 §3.1
    fragment-drop rationale, an artifact of the Docker publish path).
- Firewall rules live in the VM boot configuration, and not in a container. A
  recreation of the network namespace wipes runtime rules.
- Upstream DNS integration is conditional forwarding, and not NS delegation.
  DNSSEC-validating resolvers need `domain-insecure` or `validate-except` for the
  AD zone. Caddy DNS-01 must use external `resolvers` (1.1.1.1, for example)
  under split-horizon DNS, or the propagation checks stall.
- Host preparation: turn the systemd-resolved stub off; mask the conflicting
  smbd, nmbd, winbind, krb5-kdc and slapd units; and put `/etc/samba` on a
  durable bind mount.

The host firewall must distinguish at least:

- HTTPS access from helper clients.
- DNS and Kerberos access from helper clients and file servers.
- LDAP, SMB, RPC and Global Catalog access from member and admin networks.
- Administrative SSH access.
- No inbound Internet access to the Samba DC ports.
