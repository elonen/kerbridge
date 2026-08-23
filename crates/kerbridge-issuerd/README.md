# kerbridge-issuerd — `issuerd`, the privileged local ticket issuer

This is the only thing in KerBridge that can issue a Kerberos ticket. It takes a
Samba account SID and a requested ticket policy over a Unix socket, and returns
a validated MIT ccache v4 holding a renewable TGT for exactly that account. It
runs inside the `realm` container, next to Samba.

It is also the only thing that writes a device grant onto a directory object,
for the same reason it can issue a ticket: it already has local Samba database
access, so the broker never needs a writable LDAP identity.

## Why it is separate, and why it is behind a socket

- **It is effectively a KDC administrator.** Issuance needs local access to the
  Samba databases and root to export a key, so this authority exists whatever
  shape it takes. Keeping it in its own process is what lets the internet-facing
  broker hold none of it.
- **Same container as Samba.** A separate one would either be
  cosmetic or, worse, a way of exposing the same highly privileged state across a
  container boundary.
- **A Unix socket, so there is no TCP listener to expose by accident.** The
  socket rides a runtime-only volume mounted read-only into the broker.
- **Permissions are a group check, and a group is not an identity.** The peer's
  uid is read from the kernel (`SO_PEERCRED`) and compared against the broker's,
  so anything that merely acquires the socket's gid still cannot ask. Its own
  checks are independent of the broker's on purpose: the `broker` decides who may
  ask, `issuerd` decides what it is willing to issue.

## How a ticket is made

- Resolve the SID through local `ldbsearch` — the SID is the stable,
  rename-surviving key — and require one enabled user carrying the synchronized
  marker, in the configured domain.
- Export that account's **existing** key to a request-scoped keytab on tmpfs with
  `samba-tool domain exportkeytab`, then `kinit -k -r`. Export changes neither the
  key nor the kvno, so issuing a ticket is a read of the KDC database; nothing
  about the account changes.
- Parse the resulting cache rather than trusting an exit status: it must hold a
  TGT for exactly the resolved client, from the configured realm, with the
  expected flags and within realm lifetime policy.
- Destroy the temporary material, always. Commands are an argv vector with
  bounded time and output; errors never carry key material outward.
  `issuerd.toml`'s `max_inflight` refuses past the cap before the thread and
  the three forked root subprocesses exist.
- **Which `kinit`, and which `samba-tool`.** The environment those subprocesses
  get is built here rather than filtered, and its `PATH` is
  `/usr/sbin:/usr/bin:/sbin:/bin`. `/usr/local` is left out: on a host rather
  than in a container it is exactly where an operator's hand-built `samba-tool`
  or `kinit` lands, and searching it first would run that copy as root against
  the live directory. `kinit` itself is probed once at startup, because the
  cache parser reads MIT's format and no single spelling means MIT on every
  release — `kinit.mit` where Heimdal is packaged beside it and an alternatives
  link could be pointed away from MIT, which is both supported releases, and the
  bare name as a fallback where that spelling does not exist. The startup line
  names the one that was resolved.

## How a device grant is recorded

Three more verbs — `GrantDevice`, `RevokeGrant`, `TouchGrant` — and their
narrowness is the point. What makes it safe to put an internet-facing broker in
front of a domain administrator is not this process's privilege, which is
unavoidable, but that every verb names one account by SID and one attribute
value, and none of them takes a DN, a filter or an attribute name.

- The object is resolved from the SID here, never from a caller-supplied DN, and
  must be a live, non-retired user inside the IdP parent OU.
- The algorithm is checked against an allow-list and the thumbprint against its
  exact length and charset; the stored value is *constructed* here rather than
  taken verbatim, and the client-chosen label is sanitized.
- Grants per object are capped by `main.toml`'s `device_grant_max_per_user`, refusing rather
  than evicting — evicting the oldest would let one device push out the others.
  The cap lives here, not in the broker, because what it defends against is a
  compromised broker.
- The write goes out as one LDIF modify with base64 values. Base64 is not
  decoration: the label is client data, and a value able to carry a newline into
  an LDIF would be a second modification of the caller's choosing.

`DESIGN.md` § [Ticket issuer](../../docs/design/tickets.md#ticket-issuer),
§ [Ticket policy](../../docs/design/tickets.md#ticket-policy) and
§ [Device grants](../../docs/design/tickets.md#device-grants). Operator-visible options are the
ticket policy in `realm.toml` and everything else in `issuerd.toml`; the
socket ownership contract (uid 10001, gid 10002) is in [`deploy/README.md`](../../deploy/README.md)
§ Secrets.
