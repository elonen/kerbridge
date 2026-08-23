# kerbridge-broker — the public ticket API

The one service a client talks to. It serves `GET /config` and `POST /ticket`,
validates the cloud IdP's access token, resolves the identity in that token to
exactly one enabled and admitted Samba AD account, and asks `issuerd` for that
account's TGT. Static musl binary, installed from its own `.deb` on a minimal
Debian base.

Where a deployment turns on device grants it also serves `GET /nonce` and
`/devices`, and `POST /ticket` then accepts a signed device assertion in place of
a token. That is the only shape change; the two proofs meet at the same directory
lookup, so nothing downstream can tell them apart.

Every `/devices` route additionally takes an optional target — which account the
grant is *for*. Absent is the caller themselves; present, the caller must be in
that account's delegate group, and it is the target's identity and grants that
come back. The reads either side of that check are ordinary ones: the broker still
cannot write the directory.

## Why it is shaped this way

- **It holds nothing.** No KDC database, no Samba administrative credential, no
  user keytab, no ability to run `samba-tool`. Everything privileged is on the
  far side of the `issuerd` socket, so compromising the broker
  yields the ability to *ask* for a ticket, not to issue one.
- **It binds loopback only.** Caddy terminates TLS and reverse-proxies the two
  documented routes; the broker itself speaks plain HTTP, so any non-loopback
  bind puts the API on the network in the clear. Caddy validates no token and
  creates no trusted identity header — authentication stays here, so proxy header
  configuration is never an authorization boundary.
- **Provider specifics stop at `kerbridge-idp`.** The mapper and `issuerd` see an
  `ExternalIdentity`, never a provider claim; this crate's own configuration
  names no Entra key at all, and a later IdP is one arm in one match there. A
  distribution base rather than `scratch` for the same kind of reason — CA roots
  refresh with `apt` instead of only being what was frozen in at build time;
  `webpki-roots` stays compiled in beside them for a host with no bundle.

## How a request goes through

- Verification happens in `kerbridge-idp`, never here: signature against cached
  issuer JWKS, then algorithm, exact issuer, audience, `exp`/`nbf`, tenant,
  `scp`, and `azp`. `alg` is checked against an **asymmetric-only** allowlist
  before any key loads — see that crate's README for why it is not a setting —
  and an app-only token shape is rejected, which is the real access control
  rather than defense in depth.
- Claims normalize to an `ExternalIdentity` — a source name and an opaque
  subject — encoded by `kerbridge-core` and looked up over LDAPS with a
  read-only bind: exactly one match, enabled, effectively inside the
  realm-admission group. Ambiguity is a refusal, never a choice.
- The SID and ticket policy go to `issuerd` over its Unix socket; an MIT ccache
  v4 comes back and is returned verbatim. A ticket, a refusal and an unreachable
  issuer stay three distinct outcomes all the way out.
- `max_inflight` (`configs/broker.toml`) refuses past the cap with 429 before
  any directory traffic happens. A valid token is not a budget.

## The second identity proof

A device assertion is verified in `device/` and reduced to the same
`ExternalIdentity` a token produces — the seam `DESIGN.md` § External identity
model already names. The differences are all before that point: a one-shot nonce
this process issued, an audience naming this deployment, a signature over the
exact bytes presented, and a directory lookup that additionally requires
device-grant group membership and the presented key's thumbprint on the object
claimed.

Registering, listing and revoking a device are the only routes here that cause a
write, and none of them writes the directory: they go through `issuerd`, which
already has the local access. The broker's LDAP identity stays read-only, because
a broker that could write the directory could grant itself admission.

`DESIGN.md` § [Public broker API](../../docs/design/api-and-network.md#public-broker-api),
§ [Entra validation](../../docs/design/identity-and-directory.md#entra-validation) and
§ [Device grants](../../docs/design/tickets.md#device-grants). Operator configuration is the
config set — `deploy/configs/broker.toml`, `idp_<source>.toml` for the tenant and
its admission group, and `main.toml` for device grants — and
[`SETUP.md`](../../SETUP.md) step 4.
