# Design » API and network

This page describes the broker wire contract and the network paths that carry it.
[`DESIGN.md`](../../DESIGN.md) is the design index.

## Public broker API

Each source route starts with `/{source}`. The broker returns 404 `no such
source` if the segment does not name a configured source.

The public TLS proxy forwards only route-shaped paths from this section. The
broker validates the exact method and path. For the Docker Compose deployment,
[`deploy/caddy/routes.caddyfile`](../../deploy/caddy/routes.caddyfile) contains
the allowlist. `make test` verifies that the allowlist does not block a broker
route.

### `GET /{source}/config`

This route is unauthenticated and requires valid HTTPS. It returns the discovery
document that a client needs to start from a broker URL. Example with Entra as an IdP:

```json
{
  "base_url": "/entra",
  "oidc": {
    "authority": "...",
    "client_id": "...",
    "scopes": ["..."],
    "display_name": "Entra",
    "extra_auth_params": { "key": "value" }
  },
  "kerberos": {
    "realm": "EXAMPLE.SITE",
    "kdcs": [],
    "services": []
  },
  "ticket_format": "mit-ccache-v4",
  "device_grant": {
    "days": 0,
    "max_per_user": 10,
    "audience": "kerbridge://EXAMPLE.SITE"
  },
  "client_defaults": {
    "autostart": true,
    "windows_sign_in": true,
    "ntlm_fallback_recovery": true
  }
}
```

The broker omits `oidc.extra_auth_params` when it is empty. It omits each unset
`client_defaults` key and omits the block when all three keys are unset. The
`device_grant` block is always present. A `days` value of 0 disables device
grants.

The fields have these rules:

- `base_url` is a path such as `/entra`, not an absolute URL. The client resolves
  it against the URL that returned the document. The broker cannot know its
  public origin behind the TLS proxy. It also must not construct an origin from
  an untrusted `Host` header. The client keeps the result for the current run
  and does not store it.
- `oidc` comes from the configured source adapter. The client performs OIDC
  discovery against `authority`. It also adds each `extra_auth_params` entry to
  the authorization request.
- `kerberos.kdcs` and `kerberos.services` control Windows enrollment. An empty
  `kdcs` list lets DNS select a replacement KDC. `services` contains host or
  suffix mappings for services outside the realm DNS zone. macOS ignores both
  lists and uses DNS.
- `device_grant.audience` is the exact value that each device assertion must
  contain. The broker derives it from the realm. The client does not derive it.
- `client_defaults` contains deployment defaults. Policy has first priority. The
  user settings have second priority. A deployment default applies only when
  neither layer has a value.

#### `GET /config`, without a segment

A `_kerbridge._tcp` SRV record contains a host and port, but no source path. A
client that uses this record first requests `/config`.

The broker returns a source discovery document only when exactly one source is
configured. With zero sources or more than one source, it returns 404:

```json
{ "error": "which source?", "sources": ["entra", "entra-legacy"] }
```

The `sources` list gives the valid URL segments. All ticket and device routes
remain source-prefixed.

### `POST /{source}/ticket`

A ticket exchange uses one of these recognized authorization schemes:

```http
Authorization: Bearer <access-token>
Authorization: DeviceGrant <device-assertion>
```

The broker rejects an absent or unknown scheme as 400 `malformed request`. It
does not try a second scheme after a verification failure.

The two proof paths use different checks:

- An access token resolves an external identity.
- A device assertion carries an external identity, which the directory resolves.
  The broker matches the asserted key thumbprint to a stored device grant and
  verifies its effective deadline.

Both paths check current admission. Both use the same issuer path and the same
broker in-flight cap from `broker.toml`.

A device assertion has two base64url parts:

```text
base64url(payload).base64url(signature)
```

It has no JOSE header. A registration request names the `es256` algorithm, and
the broker accepts only a supported algorithm. The payload contains `identity`,
`key`, `nonce`, `aud`, and `exp`. The broker accepts an expiry no more than 300
seconds in the future.

A successful exchange returns:

```json
{
  "principal": "user@EXAMPLE.SITE",
  "ccache_b64": "..."
}
```

These are the only success fields.

The ticket route uses these status classes:

| Status | Result |
|---|---|
| 400 | Absent or unknown authorization scheme, or malformed authorization header |
| 401 | Invalid identity proof, or an absent, expired, clamped, or revoked stored device grant |
| 403 | A ticket policy error from an applicable row in the table below |
| 404 | Unknown source |
| 429 | The broker in-flight cap is full; the request is not queued |
| 500 | Server clock failure, or issuer refusal after broker admission |
| 502 | LDAP failure, or an absent or ambiguous required role marker |
| 503 | issuerd unavailable |

Explicit handler failures use this body:

```json
{ "error": "<short reason>", "request_id": "..." }
```

Every identity-proof failure returns 401 `invalid identity proof`. The broker
logs the internal reason with the request ID. It does not return command output.
Caddy errors, router errors, request-extractor errors, and the bare `/config`
error use their own response shapes.

These policy strings are part of the wire contract:

| `error` | Routes | Cause |
|---|---|---|
| `identity is not provisioned` | Ticket and device | No unique synchronized identity, or a named target has no external identity |
| `account is disabled` | Ticket and device | `UF_ACCOUNTDISABLE` is set |
| `account is not admitted to the realm` | Ticket and device | Account is outside the admission group |
| `account may not authorize a device` | Ticket and device | Account is outside the device-grant group |
| `you may not authorize a device for that account` | Device | Caller is outside the target's delegate group |
| `device grants are not enabled` | Ticket and device | `device_grant_days` is 0 |
| `a device may only remove itself` | Device delete | URL `{id}` differs from the device ID derived from the assertion key |

The agent branches on exact text for selected errors. When it tries a stored
device grant, 401, `account may not authorize a device`, and `device grants are not
enabled` let a workstation with no grant target try its next sign-in method.
A workstation with a configured grant target reports that it needs
reauthorization instead. `you may not authorize a device for that account`
identifies a delegate denial. Other 403 errors stop the attempt. A 401 from an
access-token exchange remains an error.

A target request can reveal whether an account is provisioned, enabled, in the
device-grant group, and authorized for the caller. The broker reveals these
results only after it resolves and admits the caller.

### `GET /{source}/nonce`, `/{source}/devices`

The broker always mounts the device routes. Each route returns 403 `device
grants are not enabled` when `device_grant_days` is 0.

| Route | Identity proof | Success |
|---|---|---|
| `GET /{source}/nonce` | None | 200 with `nonce` and `expires_in` |
| `POST /{source}/devices` | Access token | 201 with the device grant |
| `GET /{source}/devices` | Access token | 200 with `devices` |
| `DELETE /{source}/devices/{id}` | Access token, or the device assertion for `{id}` | 204 with no body |

The nonce response is:

```json
{ "nonce": "...", "expires_in": 120 }
```

The nonce contains 16 random bytes. It is single-use. The broker limits the
nonce store. A full store returns 503 `too many requests in flight`.

Device registration accepts this shape:

```json
{
  "alg": "es256",
  "key": "<base64url-public-key>",
  "label": "...",
  "for": "<optional-target>"
}
```

A device grant contains `grant_id`, `identity`, `label`, `added`, optional
`last_seen`, `sign_in_required_by`, and `clamped`. A list response contains the
same objects under `devices`.

Only an access token from the configured source can register or list device
grants. It is also required to remove a different device. A device assertion can
remove only its own grant. It cannot add another device or remove another grant.

The three `/devices` routes accept an optional target:

- `POST /devices` uses the `for` body field.
- `GET /devices` and `DELETE /devices/{id}` use the `for` query parameter.

An absent target means the caller. A present target that resolves to the caller
also uses the self-service path. A different target requires the caller to be in
the target's delegate group. Registration and list responses contain the target
identity. A DELETE response has no body. A DELETE authenticated by a device
assertion cannot contain `for`; the broker returns 400.
[Device authorization delegation](tickets.md#delegating-the-authorization) defines
the authorization model.

A target is a `sAMAccountName` or a literal `kb1|` identity. A UPN returns 400.
A literal identity avoids login-name resolution, but the broker still looks up
and authorizes the realm directory account that has the identity.

## Host networking and DNS

The supported deployment methods use different network boundaries:

| Deployment | Public TLS | Service network |
|---|---|---|
| Docker Compose | Caddy | A bridge network with published host ports |
| Debian | An operator-supplied same-host proxy; Caddy and nginx examples ship | Host network |

KerBridge does not ship or test a host-network Docker Compose configuration.

These listener rules apply to both methods:

- The TLS proxy binds the public HTTPS port.
- The broker binds loopback only and refuses any other address.
- Samba binds the DC ports.
- issuerd binds only a Unix socket.

In Docker Compose, Caddy shares the broker network namespace and can reach the
broker loopback address. Other containers cannot reach that listener. In a
Debian deployment, each host process can reach the broker loopback address. The
host is the trust boundary.

Compose publish addresses can narrow one port at a time. A Debian Samba service
binds its service set by interface, not by port. The host or upstream firewall
must restrict source networks in both deployments.

### DNS views

Samba internal DNS owns the DC's view of `example.site`. The LAN resolver owns
the view that workstations use. Publish these records in the LAN view, not in
Samba DNS. Each SRV record uses priority 0 and weight 100:

| Record | Port and target | Use |
|---|---|---|
| `kerbridge.example.site A` | KerBridge server LAN address | Broker and DC host |
| `_kerbridge._tcp.example.site SRV` | `443 kerbridge.example.site.` | Broker discovery |
| `_kerberos._udp.example.site SRV` | `88 kerbridge.example.site.` | Kerberos discovery |
| `_kerberos._tcp.example.site SRV` | `88 kerbridge.example.site.` | Kerberos discovery |
| `_ldap._tcp.example.site SRV` | `389 kerbridge.example.site.` | DC locator |
| `_ldap._tcp.dc._msdcs.example.site SRV` | `389 kerbridge.example.site.` | DC locator |

Do not publish an AAAA record for these names. The Compose path publishes Samba
on IPv4 only. A measured Windows workstation waited without an error when DNS
also returned IPv6.

The DC must use its own Samba DNS service for the realm zone. An off-host file
server must also resolve the full realm zone from the DC. Point the file server
to the DC, or configure a conditional forward for the zone. Do not use NS
delegation. Mark the unsigned realm zone as insecure in a resolver that validates
DNSSEC.

`kerbridge.example.site` is both the broker name and the DC name. The LAN and
Samba views can return different addresses. This is necessary for the Compose
bridge network.

The `acme` and `acme-dns` TLS strategies require control of public DNS. The
`external` strategy can use an operator CA and LAN-only DNS. DNS-01 updates only
TXT records at the public provider; it does not expose Samba DNS. With `acme-dns` and split-horizon DNS,
Caddy must use external resolvers for the DNS-01 propagation check.

[DNS records and firewall](../setup/dns-and-firewall.md) contains the record
recipes and operator steps.

### Firewall zones

The base network contract is:

| Source | Destination ports | Purpose |
|---|---|---|
| Workstations and file servers | 88/tcp, 88/udp | Kerberos |
| Workstations | 443/tcp | Broker HTTPS |
| File servers | 389/tcp, 389/udp, 445/tcp | DC location, join, and secure channel |
| File servers or conditional resolvers | 53/tcp, 53/udp | Samba DNS, only when they query it directly |
| Remote `kbmanage` hosts | 636/tcp | LDAPS |
| RSAT hosts | 389/tcp, 389/udp, 445/tcp, 3268/tcp | Directory administration |
| RSAT hosts | 135/tcp and the configured dynamic RPC range | Operations that use RPC |
| Administrative hosts | 22/tcp | Server administration |

A file server join does not need dynamic RPC. RSAT does. The default dynamic RPC
range is `49152-49251`, but `rpc_port_range` can set a smaller range before the
realm is provisioned.

NetBIOS is disabled with `disable netbios = yes` and `smb ports = 445`. Do not
open ports 137-139. KerBridge does not supply NTP. Workstations, the server, and
file servers must use another time source, so the KerBridge firewall contract
has no port 123.

Keep port 88 on LAN networks. A public AS endpoint lets an attacker use failed
passwords to lock a synchronized account. This also stops ticket issuance for
that account. Port 443 is the only KerBridge port that can face the Internet.

Apply firewall rules on the host or upstream network, not inside a container
network namespace. A container recreation removes namespace-local rules. Bind
addresses restrict which server interfaces answer; they do not restrict source
hosts.

### Windows Kerberos transport

Workstations must reach the KDC on TCP port 88. A reply with a PAC can exceed the
UDP reply limit. Windows enrollment sets the realm flag with:

```console
ksetup /setrealmflags <REALM> tcpsupported
```

Windows reads this flag without a restart. Publish both `_kerberos._udp` and
`_kerberos._tcp`. The measured Windows 11 workstation queried the UDP record, but this
does not prove that every Windows build ignores the TCP record. Enrollment is
still required. A pinned `KdcNames` value is not required.

Do not set `MaxPacketSize` for the supported Windows 11 external-realm path. In
measurement, the value had no effect and suppressed the RFC 4120 TCP retry. See
[Windows Kerberos findings](../windows-kerberos-findings.md#what-made-kerberos-transport-work-reliably-for-a-ksetup-realm).
