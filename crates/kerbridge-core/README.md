# kerbridge-core — what the components agree on

These kinds of thing, in descending order of how loudly a disagreement would
fail.

**Formats**, which must match byte for byte: the provider-neutral
`ExternalIdentity` that sync writes into Samba AD and the broker reads back, the
directory state and role markers, the `kbkey1|` device grant (`grant`), and the
broker↔`issuerd` wire protocol.

**Decisions**, which are not wire formats but must still be identical in every
component: what permissions a credential file may have (`secret`), and what an
LDAPS bind trusts (`tls`). `secret` also holds `Secret`, the type a credential
travels in once it is in memory, whose `Debug` prints `<redacted>` and which
gives its value up only to `expose`.

**Vocabulary**, which is ordinary shared code, here only because the copies had
started to disagree: the calendar (`time`), DN splitting (`dn`), and the GUID
shape check.

**Configuration** (`config`) belongs to the first kind: it parses the
`main.toml` set every binary reads, so a shared number cannot mean one thing to
the broker and another to `issuerd`.

## Why it is a crate of its own

The readers and the writers are separate programs that never talk to each other.
`kerbridge-sync` stamps an identity value into `msDS-ExternalDirectoryObjectId`,
`kerbridge-broker` looks it up minutes later, `kbmanage` reads the same markers a
month after that. A second spelling anywhere does not raise an error — it makes
the account unfindable or the admission group unrecognized, silently, and only for
some of the readers. One implementation, linked by every reader, is the whole point;
a private copy on either side is a divergence waiting to happen.

That argument is strongest for the formats and weakest for the vocabulary, and
the vocabulary is here because the weak version came true anyway: there were four
transcriptions of the same twenty lines of calendar arithmetic, two of which
disagreed about whether an unparsable date was an error or a silently wrong
answer.

## What may be added

One rule, and it is `DESIGN.md`'s: `issuerd` links this crate and holds KDC
authority, so nothing here may widen its dependency surface. Anything needing a
dependency goes behind a feature `issuerd` does not enable — `tls` and `schema`
are the two today, and `cargo tree -p kerbridge-issuerd` shows neither rustls
nor schemars. `schema` is what makes the `config` structs describe themselves,
for `kbconfig` and for the test holding every key the parser accepts to the
template that documents it; `issuerd` reads this config but never asks it its
own shape. Everything else is dependency-free beyond `anyhow`, `serde` and
`toml`; `toml` is unconditional because `issuerd` reads the same config files
as the broker, and it is small and pure Rust. The same rule is why the notifier
is [its own crate](../kerbridge-notify/README.md) rather than a module here: it
needs an HTTP and TLS dependency tree, and `issuerd` must not link one. The
problem record and its severity (`problem`) stay here for the same reason from
the other side — they are a format that `kbmanage` and an operator's monitoring
agent read, and parsing one must not cost the reader that tree.

**Licensed `MIT OR Apache-2.0`**, not the repository's GPL-3.0. This
crate is protocol, and a third party implementing the other end of it — another
IdP adapter, another issuer, a client — should not have to take the GPL to do so.

## How

- **Identity**: `kb1|<source name>|<subject>`, with only `%` and `|`
  percent-escaped, so canonical values stay readable in `ldbsearch` output. The
  matching LDAP filter escaping ships with it, because the encoder and the query
  must agree about the same characters. Private fields and a validating
  constructor: the length ceiling is the attribute's, and with an adapter-defined
  subject this crate can no longer bound it by reasoning about content.
- **Source**: the name an identity is stored under. It carries nothing else —
  an issuer URL is an authentication input and operator-mutable, a source name
  is a storage key and frozen, and the two must not be conflated.
- **Markers**: the admission group's `kbrole1|realm-admission` role, the retired and
  quarantined state values with their `_retired-` name namespace, and the UAC and
  group-type constants a synced object is expected to carry. `kbrole1|delegates`
  is the odd one out and says so where it is defined: many groups carry it, one
  per delegated account, so a reader that resolves it the way it resolves the
  realm-wide role groups — exactly one or freeze — has it exactly backwards.
- **Issuer protocol**: a 4-byte big-endian length followed by that many bytes of
  JSON, capped at 64 KiB — the length is read before anything is allocated. Every
  type derives both directions, so each process uses one direction and keeps the other
  honest.
- **Time**: `YYYY-MM-DDTHH:MM:SSZ`, UTC, no offsets and no fractional seconds.
  Both directions are Howard Hinnant's civil-day algorithms, one implementation
  each; a marker this cannot parse reads as "timestamp unreadable" rather than as
  an age nobody wrote.

`DESIGN.md` § [External identity model](../../docs/design/identity-and-directory.md#external-identity-model)
and § [Ticket issuer](../../docs/design/tickets.md#ticket-issuer) are authoritative for both
formats. Nothing here is operator-configurable.
