# kerbridge-broker — the public ticket API

This is the only service that a client speaks to. It does these tasks:

- Serves `GET /{source}/config` and `POST /{source}/ticket`.
- Validates the access token of the cloud IdP.
- Resolves the identity in that token to an enabled and admitted Samba AD
  account.
- Asks `issuerd` for the TGT of that account.

The `{source}` variable is name of the IdP, like `entra`.

The binary is static musl. It installs from its own `.deb` on a minimal Debian
base.

One process serves every source, and the first path segment names which one.
That segment selects an adapter and an OU, never a weaker test: each source
resolves against its own admission group, and an identity from one source is not
valid under another. A segment that names no configured source gets a 404. The
bare `GET /config` is the one route without a segment, because a client that
found the broker in DNS has no source name yet. The broker answers it only when
the config set has one source; the reply gives a `base_url`, and the client
re-bases on that before it asks for a ticket.

If a deployment enables device grants, the broker also serves `GET
/{source}/nonce`, `/{source}/devices` and `DELETE /{source}/devices/{id}`. In
that case, `POST /{source}/ticket` accepts a signed device assertion in place of
a user token. This is the only change to the shape of the API. The two proofs
meet at the same directory lookup, thus `issuerd` cannot tell them apart.

Each `/{source}/devices` route also accepts an optional target user. The target
is the account that the grant applies to.

- If the target is absent, the grant applies to the caller.
- If the target is present, the caller must be a member of the delegate group of
  that account. The reply then holds the identity and the grants of the target.

The lookups on the two sides of that test are usual reads. The broker still
cannot write to the directory.

## Why the design is like this

- **The broker holds nothing.** It has no KDC database, no Samba administrative
  credential, no user keytab, and no permission to run `samba-tool`. All
  privileged operations are on the far side of the `issuerd` socket. Thus an
  attacker who gets the broker can *ask* for a ticket, but cannot issue one.
- **The broker binds to loopback only.** Caddy terminates TLS and sends the two
  documented routes to the broker. The broker itself speaks plain HTTP. Thus a
  bind to a different address puts the API on the network without encryption.
  Caddy validates no token and makes no trusted identity header. Authentication
  stays in the broker, thus the configuration of the proxy headers is never an
  authorization boundary.
- **Provider details stop at `kerbridge-idp`.** The mapper and `issuerd` see an
  `ExternalIdentity`, never a claim of the provider. The configuration of this
  crate names no Entra key. To add a different IdP, add one arm to one match in
  that crate. The image uses a distribution base and not `scratch` for a related
  reason: `apt` refreshes the CA roots, but a build can only freeze them in.
  `webpki-roots` stays compiled in beside them, for a host that has no bundle.

## How a request goes through

- `kerbridge-idp` does the verification, not this crate. It checks the signature
  against the cached issuer JWKS. Then it checks the algorithm, the exact issuer,
  the audience, `exp`/`nbf`, the tenant, `scp` and `azp`. It compares `alg` to an
  **asymmetric-only** allowlist before it loads a key — the README of that crate
  tells why this is not a setting. It also refuses a token with an app-only
  shape. That refusal is the true access control, not an added protection.
- The claims become an `ExternalIdentity`: a source name and an opaque subject.
  `kerbridge-core` encodes it, and the broker looks it up over LDAPS with a
  read-only bind. The account must match one time only, must be enabled, and
  must be effectively in the realm-admission group. An ambiguous result is a
  refusal, never a choice.
- The broker sends the SID and the ticket policy to `issuerd` over its Unix
  socket. An MIT ccache v4 comes back, and the broker returns it without a
  change. A ticket, a refusal and an unreachable issuer stay different results
  to the client.
- `max_inflight` (`configs/broker.toml`) gives a cap. Above the cap, the broker
  refuses with 429 before it makes directory traffic. A valid token is not a
  budget.

## The second identity proof

The code in `device/` verifies a device assertion and reduces it to the same
`ExternalIdentity` that a token gives (`DESIGN.md` gives the external identity
model). All the differences occur before that point:

- a one-shot nonce that this process made,
- an audience that names this deployment,
- a signature over the exact bytes of the request, and
- a directory lookup that also requires membership of the device-grant group,
  and the thumbprint of the presented key on the object in the claim.

The routes that register, list and revoke a device are the only routes here that
cause a write. None of them writes to the directory. They go through `issuerd`,
which already has the local access. The LDAP identity of the broker stays
read-only, because a broker that could write to the directory could give itself
admission.

`DESIGN.md` § [Public broker API](../../docs/design/api-and-network.md#public-broker-api),
§ [Entra validation](../../docs/design/identity-and-directory.md#entra-validation) and
§ [Device grants](../../docs/design/tickets.md#device-grants). Operator configuration is the
config set — `deploy/configs/broker.toml`, `idp_<source>.toml` for the tenant and
its admission group, and `main.toml` for device grants — and
[`SETUP.md`](../../SETUP.md) step 4.
