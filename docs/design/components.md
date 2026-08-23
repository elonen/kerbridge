# Design » Components

The four containers of the KerBridge stack, and what each one is denied.
[`DESIGN.md`](../../DESIGN.md) is the index and holds the goal, the deployment
assumptions and the security boundaries.

## Containers

### `caddy`

Caddy is the only public HTTP service.

Responsibilities:

- Get the broker certificate and renew it. `TLS_STRATEGY` selects the source:
  - `acme-dns` — DNS-01. This is the recommended source.
  - `acme` — an inbound challenge.
  - `external` — a certificate that the operator supplies.
- End TLS. There is no HTTP listener. Each strategy disables the `:80` redirect
  vhost, nothing publishes port 80, and `kerbridge-client` refuses plain HTTP.
- Apply a limit of 16 KB to the request body. Apply header, body and idle
  deadlines to each connection. The broker and `issuerd` limit the number of
  parallel requests.
- Send only the documented broker routes
  (see [Public broker API](api-and-network.md#public-broker-api)) to a
  loopback broker listener. Each other path gets a 404 and does not reach the
  broker. The allowlist and the broker's router move together: `make test`
  refuses a route that the broker serves and Caddy does not.
- Serve one static page at `/`, from a read-only mount. It is for the person who
  points a browser at the broker, because a 404 there reads as an outage. The
  page reaches no component and knows no identity. Each path other than `/`
  still gives a 404.
- Set the forwarding headers. Discard the client's own versions, which are not
  trusted.

Constraints:

- Caddy validates no Entra token and creates no trusted identity headers.
  Authentication stays in the broker. Thus the proxy header configuration is
  never an authorization boundary.
- DNS-01 usually needs a Caddy image that contains the selected DNS provider
  module. HTTP-01 is an alternative that the operator selects. It is not the
  default.

<details>
<summary>What TLS is necessary for, and the future construction that would remove it</summary>

Examined 2026-07-27. Not built. This text is here because the question "does the
broker need a certificate at all" comes back often, and the answer is not
obvious.

**TLS is not for the OIDC proof.** The authorization-code exchange goes between
`kerbridge-client` and the IdP. It uses the *IdP's* certificate and a loopback
redirect. The broker takes no part in it, and the client needs no broker
certificate to get the token. This agrees with a deliberate property of
KerBridge: nothing must reach it from the Internet. ACME defaults to DNS-01 for
the same reason.

The exchange carries three things that need confidentiality:

- **The request** is a bearer token with no channel binding. An attacker who
  reads it in flight can replay it until `exp` and get a TGT.
- **The response is worse.** `POST /ticket` returns an MIT ccache, and a ccache
  holds the session key together with the ticket
  (`client/kerbridge-client/src/krbcred.rs`). Thus a passive observer gets
  service tickets for the whole realm, for the full ticket lifetime. To rotate
  the user's key does not stop this — see
  [Ticket policy](tickets.md#ticket-policy).
- **`GET /config`** is unauthenticated and names the authority that the client
  will trust. Only TLS gives it integrity.

One construction removes all three risks: a **sender-constrained token with a
PKINIT hand-off**. It works as follows:

- The IdP binds an ephemeral key, which the client made, into the token as
  `cnf`.
- The broker registers *that* key as the caller's PKINIT credential. It does not
  use a key read from the request body, because a MITM could replace such a key.
- The broker answers with no secret at all.
- The client's own AS-REQ then makes the session key by Diffie-Hellman, against
  a private key that never leaves the machine. By design, this is confidential
  over plain port 88.

A MITM cannot substitute a key without the user's credentials, and gets nothing
from a replay. The broker then needs no authentication, because it holds nothing
that the client depends on.

**It is not buildable as of 2026-07:**

- Entra implements neither DPoP (RFC 9449) nor mTLS-bound tokens (RFC 8705).
  Microsoft documents the second as "being investigated" for confidential
  clients.
- Microsoft's proprietary Signed HTTP Request PoP is enabled per resource, on
  Microsoft's own APIs. A tenant cannot turn it on for its own app registration.
  Microsoft documents its confidential-client form as experimental and likely to
  be removed.
- Entra token encryption (JWE to the resource key) stops a passive observer but
  not an active relay. It is also a premium provider-specific feature, of
  exactly the kind that the
  [external identity model](identity-and-directory.md#external-identity-model)
  exists to avoid.
- Anonymous PKINIT with FAST armoring still needs a KDC trust anchor on the
  client.
- The broker holds no Entra credential today (`config.rs` — tenant id, JWKS
  source, two client ids for `aud`/`azp`). Thus any scheme in which the broker
  proves itself *to* the client must start by giving it one, with the renewal
  problem of
  [Graph credential lifetime](identity-and-directory.md#graph-credential-lifetime).

The general result: **a bearer token authenticates one direction only.** To
authenticate the broker, you need one of two things — key material that the
client trusts in advance, whatever its name, or an IdP that binds a client-held
key into the token.

If a sender-constrained token becomes available, two costs stay real. The PKINIT
branch was never spiked ([`INDEX.md`](../research/INDEX.md) spike 1 — local key
export got GO, and the conditional fallback was skipped). And the broker would
write a PKINIT credential for each login, which is a much larger privilege than
`issuerd`'s present one-SID-one-ticket socket.

</details>

### `kerbridge-broker`

A static musl-linked Rust executable. It is installed from the
`kerbridge-broker` package onto a minimal Debian base. This is the same artifact
that a Debian host installs, not a second build of the same source.

Trust anchors:

- The broker needs the public CA roots for outbound TLS to Entra, and the realm
  CA for LDAPS to Samba.
- The Entra roots come from Debian's `ca-certificates` package, read as the OS
  trust store (`rustls-tls-native-roots`). Thus the roots refresh with `apt`, or
  with a base-image rebump, and KerBridge is not recompiled. The image names the
  package explicitly, because the image takes no `Recommends`.
- `webpki-roots` stays compiled in as a fallback for a host that has no bundle.
  If both are enabled, the two root sets merge.
- A TLS trust failure on the Entra path is a categorized failure and an operator
  notification (see [Operator notification](operations.md#operator-notification)).
  It is never a silent verification error: a verifier that cannot get keys must
  say so, and must not fail closed in silence.

<details>
<summary>Why not <code>scratch</code> with compiled-in roots</summary>

`webpki-roots` freezes the trust store at build time. Thus the roots of a
long-lived deployment become as old as its binary, and a root that is retired or
newly added breaks JWKS retrieval. The break is invisible, because the root
store is a build artifact.

The static binary does not depend on the base, because it links its own musl. A
package manager is a larger surface than `scratch`, and that is the deliberate
trade: a frozen root store is a scheduled outage, and an updatable one is a
routine patch.

</details>

Responsibilities:

- Serve `GET /{source}/config` and `POST /{source}/ticket` on a loopback-only
  host listener, for each source that `main.toml` lists. One process serves any
  number of sources, and each request acts on the one source that its path
  names.
- Validate the external identity proof.
- Convert the provider claims to a canonical external identity.
- Resolve that identity to exactly one Samba AD user over LDAP.
- Make sure that the user is enabled and admitted to the realm.
- Ask `issuerd` for a TGT over a Unix domain socket.
- Return the ccache in the stable helper wire format.
- Produce security audit events, but log no token and no ticket material.

The broker has none of:

- a KDC database
- a Samba administrative credential
- a user keytab
- the ability to run Samba tools

### `kerbridge-sync`

A separate static musl-linked Rust service. The separation keeps the Graph
credentials and the Samba write privileges out of the interactive
authentication path. One process serves each source and reconciles one source at
a time, under that source's own OU and bind account.

Responsibilities:

- Read the configured users and groups from Microsoft Graph.
- Resolve the configured Entra realm-admission group. It defaults to
  `KerBridge Allowed On-prem Users`.
- Reconcile the IdP-controlled users and groups into dedicated Samba AD OUs.
- Store the immutable external identity mapping on each Samba AD object.
- Create user accounts with random, undisclosed key-generating passwords.
- Disable the users that it can no longer synchronize. Quarantine the groups
  that are removed and clear their sync-owned membership, as the configured
  policy specifies.
- Keep the locally managed Samba objects and the local group memberships.
- Hold only its own synchronization cursors and reconciliation state, in memory.
- Monitor the expiry of its own Graph credential and give a warning well before
  the credential lapses.

Samba AD is the single source of truth for the external-to-realm mappings. There
is no second mapping database in the broker. A full reconciliation can rebuild
the cursors, and thus the cursors need no durable home. The directory mapping is
part of the Samba database and cannot be discarded.

### `realm`

Contents:

- The Samba AD DC with its standard command-line tools, and the Kerberos client
  tools that produce a ccache. Both come from `kerbridge-issuerd`'s own
  `Depends`. Thus the image is a test of that list, and not a second copy of it.
- A static musl-linked `issuerd` and `kbsetup`, installed from the
  `kerbridge-issuerd` package.
- One process, not two. `issuerd` has its own container — the same image with
  its own entrypoint — because a Debian deployment has two units for these two
  programs. Nothing supervises anything: each program is restarted and reported
  on separately. The healthcheck of the realm is TCP 389, and the issuer answers
  its own healthcheck with `issuerd ping`.

Provisioning rules:

- Provision a domain only when no Samba database exists.
- After provisioning, the container must refuse a configuration whose realm, DNS
  domain, NetBIOS name or DC hostname disagrees with the durable state. It must
  never reprovision an existing bind mount in silence.
- `/var/lib/samba` must be on a volume that supports extended attributes. Writes
  of the `security.NTACL` extended attribute fail on overlayfs and on macOS bind
  mounts.
- Provisioning must create a TLS certificate with a SAN, through a local CA, and
  set `tls certfile`, `tls keyfile` and `tls cafile`. Samba's autogenerated
  certificate has no SAN, and rustls-based LDAPS clients refuse it.
- The realm host must use Samba DNS as its own resolver, so that the issuer path
  resolves the realm locally.

<details>
<summary>Why Samba and <code>issuerd</code> stay on one host</summary>

`issuerd` needs local access to the Samba databases and is in effect a KDC
administrator. On another host, that state would cross a network boundary. Thus
`issuerd` does not move.

They are two processes, and each deployment runs them as two. A Debian
deployment has `samba-ad-dc.service` and `kerbridge-issuerd.service`. Compose has
the `realm` and `issuer` services, from one image, which share the directory
volumes and one network namespace. Thus a restart stops one program only, and a
failure names the program that failed.

</details>
