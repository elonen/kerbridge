# kerbridge-core glossary

The formats and decisions every other component must agree on: identity
encoding, `sAMAccountName` rules, DN handling, markers, device-grant encoding,
ccache and audit primitives.

Part of the repo-wide vocabulary in [`GLOSSARY.md`](../../GLOSSARY.md) — a term
means the same thing there and here. It lives in this file, closest to where
it's used, rather than in the root file, because the root file would be
unreadably long if it carried every term at once.

### account

The one directory object a request resolves to: for the broker, the single
enabled Samba AD user carrying the presented `external identity`; for `issuerd`,
the object found by `(objectSid=…)` and the only DN any write in the process
addresses. The directory is the sole source of truth for the mapping — there is
no parallel broker database — and `issuerd` never takes the object from its
caller.
<!-- avoid: directory object, the object, user, ad account, entry, person -->

### account SID

The field every `issuer protocol` verb carries: which account `issuerd` is to
act on, named by `SID` rather than by name so it survives a rename and is not a
string the issuer must defend against.
<!-- refs: `account_sid`, `kerbridge_core::issuer::IssueRequest` -->
<!-- avoid: account name -->

### alg

The signature algorithm a device grant names, checked against a one-entry
allow-list (`es256`) before any key material is touched; the implementation
returns the borrowed static, so the stored value is never the caller's bytes. A
`device assertion` carries no JOSE header, so the algorithm is never the
client's to choose.
<!-- refs: `kerbridge_core::grant::algorithm` -->
<!-- avoid: algorithm -->

### algorithm key

The field of a device grant whose key *name* is the signature algorithm and
whose value is the `thumbprint` — `es256=` today. Exactly one recognized
algorithm key must be present, so a value naming a future algorithm reads as
key-less and is refused rather than ignored.
<!-- refs: `kerbridge_core::grant::ALG_ES256` -->
<!-- avoid: alg field, algorithm name -->

### ambiguous identity

Two or more directory objects carrying one `external identity`: a
directory-integrity fault, not a policy answer. The broker fails closed
because picking one would be picking whose tickets an attacker gets; sync
excludes both objects from reconciliation and freezes their memberships rather
than touching either.
<!-- refs: `Denied::Ambiguous`, notification `identity-ambiguous` -->
<!-- avoid: duplicate identity, identity collision, multiple match, dupe, conflicted object, identity clash -->

### audit line

One durable record of something that happened: a ticket issued, a device grant
written or removed, an account created or renamed or disabled. It goes to the
writer's console and to the `audit log` as one string so the two cannot say
different things; refusals are not in it, and for a delegated grant this line
*is* the record of who authorized what. A quiet sync cycle is not one: the file
answers who was given something, and a heartbeat every interval saying nobody
was is what would bury the answer.
<!-- avoid: audit entry, audit record, the trail, log line, the record -->

### audit log

The append-only file a service writes its `audit line`s into, named by that
service's own configuration and kept on a bind mount so it outlives the
container that wrote it. One per writing service — three of them, each on its
own mount on purpose, so a compromised broker cannot unlink the issuer's record
of what it asked for or sync's record of who was given an account.
<!-- refs: `audit_log_file` in `configs/issuerd.toml`, `configs/broker.toml` and `configs/sync.toml`, `kerbridge_core::audit::AuditLog`, `state/broker-audit/audit.log`, `state/issuer-audit/audit.log`, `state/sync-audit/audit.log` -->
<!-- avoid: audit trail, audit file, the record, log, logging, the console log -->

### cap

A configured maximum: grants per account, exchanges in flight, ticket lifetime.
*Clamp* is pulling a stored value in to the current cap; *floor* is the
mirror-image configured minimum.
<!-- avoid: ceiling, knob, slot, budget, bound, safety bound, maximum (as a noun) -->

### clamped

Of a device grant whose `sign-in deadline` the current device-grant day count
has pulled in below the `stamped deadline`, decided per grant and reported per
device by the broker. Lowering the day count turns every outstanding grant down
with it, evaluated on the exchange; raising it stretches none.
<!-- refs: `configs/main.toml` `device_grant_days`, `kerbridge_core::grant::DeviceGrant::clamped` -->
<!-- avoid: shortened, capped, truncated -->

### collision

A `sAMAccountName` a new object needs that already belongs to a different
object, compared case-folded because AD's account-name namespace is
case-insensitive and a byte-exact check plans a rename AD will refuse forever.
A new user's name takes an object-id suffix instead; a group's name is its
display name verbatim, so a group collision refuses the whole cycle rather than
half-applying it.
<!-- refs: `kerbridge_core::sam::fold` -->
<!-- avoid: name collision, namecollision, name clash, duplicate name -->

### combining mark

A Unicode mark in an account name that either a script genuinely needs
(accepted, because Unicode counts it as alphabetic) or that NFC would have
composed away (refused, with a hint saying so). The implementation recognizes
only the blocks that can reach that rejection, which is all the hint needs.
<!-- refs: `kerbridge_core::sam::is_combining_mark` -->

### component

One of the KerBridge server programs that links `kerbridge-core` — the broker,
sync, `issuerd`, `kbmanage`. The unit across which a disagreement about a
format is possible.
<!-- avoid: service, program, part -->

### directory CA

The single certificate authority an LDAPS bind trusts: the realm's own, created
by provisioning. No CA configured is refused outright rather than falling back
to the OS trust store.
<!-- refs: `kerbridge_core::tls::client_config` -->
<!-- avoid: trust anchor, root ca, ca bundle, ca_pem -->

### distinguished name

An object's full directory path. Split, compared and contained component-wise
everywhere here, never by string suffix.
<!-- refs: `kerbridge_core::dn` -->
<!-- avoid: dn path, ldap path -->

### DN component

One normalized `attr=value` element of a DN: attribute lowercased, value
case-folded and trimmed, backslash escapes honored. A malformed DN yields none
at all, which makes it outside every OU rather than inside one.
<!-- refs: `kerbridge_core::dn::dn_components` -->
<!-- avoid: dn part -->

### effective end

When a device grant actually stops working: its stamped `end=` clamped to
`start` plus the device-grant day count. Lowering the setting bites outstanding
grants immediately and raising it never stretches one, so `kbmanage` prints the
stamped deadline while the broker serves this clamped one.
<!-- refs: `configs/main.toml` `device_grant_days`, `kerbridge_core::grant::DeviceGrant::effective_end` -->
<!-- avoid: expiry, deadline -->

### emitter

The one component permitted to write a given format; device grants have exactly
one, `issuerd`. Everyone else may only delete whole values, which is what makes
"unknown keys are ignored" safe.
<!-- avoid: writer, producer -->

### external identity

The provider-neutral pair `source` / `subject` naming a `cloud identity`
independently of which IdP produced it; for Entra, the configured `source name`
and the `oid`. Never a UPN, email, display name or group name — all of those are
mutable, and a mutable attribute is never a mapping key. It carries no third
field and never will: every field added becomes a mapping key someone comes to
depend on, so the type has no extension point at all. Sync is its only writer and
every other component reads it.
<!-- refs: `kerbridge_core::ExternalIdentity` -->
<!-- avoid: externalidentity, canonical identity, the identity triple, identity value, kb1 value, the mapping -->

### fallback name

`kbuser`, the `login name` derived when nothing of the source string survives
sanitizing. Public so a caller choosing between several `sam source`s can tell
"this attribute yielded a real name" from "this one yielded nothing" — `...`
is three allowed characters and no name.
<!-- refs: `kerbridge_core::sam::FALLBACK` -->
<!-- avoid: default name, placeholder name -->

### field escaping

The one escaping rule shared by the `kb1|` and `kbkey1|` encodings: only `%`
(the escape introducer) and `|` (the delimiter) are percent-escaped, as `%25`
and `%7C`. Canonical Entra values contain neither, so stored values stay
readable in `ldbsearch` output and audit lines.
<!-- refs: `kerbridge_core::escape_field` -->
<!-- avoid: percent-encoding, url escaping -->

### filter escaping

RFC 4515 escaping of an LDAP filter assertion value, applied unconditionally to
an encoded identity so a malformed or hostile issuer cannot inject filter
syntax.
<!-- refs: `kerbridge_core::escape_ldap_filter_value` -->
<!-- avoid: ldap escaping -->

### frame

One message on the broker-to-`issuerd` socket: a 4-byte big-endian length
followed by that many bytes, capped at 64 KiB because the length is read before
anything is allocated.
<!-- refs: `kerbridge_core::issuer::MAX_FRAME` -->

### grant handle

The eight hex digits derived from a device grant's thumbprint — the only safe
way to name one device to an operator or in a URL path, because it is a
function of the key and not of the client-chosen label. On the wire and in the
client's stored settings it is `grant_id`, which the client keeps as the broker
returned it rather than deriving.
<!-- refs: `kerbridge_core::grant::short_id` -->
<!-- avoid: short id, operator handle, device id, key id, thumbprint, `{id}`, `device=` -->

### group type

The `groupType` value distinguishing a `synced group` (global security,
`-2147483646`) from a `resource group` (domain-local security, `-2147483644`).
<!-- refs: `kerbridge_core::state` -->

### GUID shape

The `8-4-4-4-12` hex form. A shape check and deliberately not a parse: the
broker requires it of a token's `tid` and `oid`, sync refuses a credential file
that *has* it (that is a `secret ID`), and the braced and URN forms a UUID
parser would accept are neither.
<!-- refs: `kerbridge_core::is_guid` -->
<!-- avoid: uuid -->

### issuer protocol

The broker-to-`issuerd` wire protocol: length-prefixed JSON over a Unix socket,
with every type deriving both directions so each process keeps the other
honest. Every verb names exactly one account by `account SID` and none takes a
DN, a filter or an attribute name — that narrowness is what makes it safe to
put an internet-facing service in front of a domain administrator.
<!-- refs: `kerbridge_core::issuer` -->
<!-- avoid: issuerd protocol, broker-issuerd protocol, the wire protocol -->

### `kb1|` identity

An `external identity` as encoded into `msDS-ExternalDirectoryObjectId`:
`kb1|<source name>|<subject>`, each field escaping only `%` and `|`, and never
longer than the attribute's 256 characters. One implementation — a disagreement
here breaks every login silently, with nothing in either program looking wrong.
The broker hands the stored string back verbatim and a client passes it on
unaltered, because a copy spelled differently would be refused on every exchange
with nothing to point at.

Two fields, because two are what every consumer uses: which `source` owns the
object, and which account within it. The `subject` is the adapter's, opaque to
everything else, and the format never grows a third — an added field becomes a
mapping key someone comes to depend on.
<!-- refs: `kerbridge_core::ExternalIdentity::encode`/`decode` -->
<!-- avoid: external directory object id, the identity attribute, identity value, kb1 value, identity attr -->

### last seen

The day-granular stamp of a device grant's most recent use, rewritten at most
about once a day. A display stamp and not data: a failed stamp never fails a
ticket exchange.
<!-- refs: `kerbridge_core::grant::needs_touch` -->
<!-- avoid: seen, touch, last use, last-use day -->

### LDAPS

The only directory transport this project accepts over the network: `ldap://`
is refused where the URL is read, and StartTLS is not negotiated either.
`issuerd` is not an exception to the rule but outside it — it opens no LDAP
connection at all, reading and writing `sam.ldb` locally instead.
<!-- refs: `kerbridge_core::require_ldaps` -->

### login name

An account's `sAMAccountName`, which is also its Kerberos `principal` name and
what winbind resolves a `SID` back to; users and groups share one namespace for
it. To the broker it is the `sAMAccountName` alone — a `/devices` target
containing `@` is refused as a UPN — while `kbmanage` moves the
`sAMAccountName` and its matching `userPrincipalName` together, because
`samldb` enforces uniqueness on both. Sync derives both at creation and leaves
the CN to follow `displayName`.
<!-- refs: `Directory::set_login_name` -->
<!-- avoid: sam, logon name, account name, username -->

### marker format rule

Which shape a stored value takes, decided by how it is consumed rather than by
taste. **Searched by exact match** → positional, fixed arity, one canonical
encoding. **Parsed after retrieval** → `key=value`, extensible.

| Format | Shape | Consumed how |
|---|---|---|
| `kb1\|` identity | positional | exact-match LDAP filter |
| `kbrole1\|` role markers | positional constants | exact-match filter |
| `kbkey1\|` device grant | `key=value` | fetched with the account, then parsed |

Causal, not stylistic: LDAP compares the whole value as one token, so every byte
is part of the primary key. A format admitting two encodings of one identity
does not return a wrong answer — it returns **no** answer, which reads as "user
not synchronized". `key=value` admits reordering and optional fields; positional
with fixed arity has one encoding by construction.
<!-- avoid: encoding convention, marker style -->

### NFC normalization

Composing a name to a single Unicode spelling before an account name is derived
from it. The caller's job and not optional: `kerbridge-core` carries no Unicode
tables by design, so `validate` refuses the decomposed form and a decomposed
name — which renders identically to the composed one and is a different
principal — never becomes a second account.
<!-- avoid: normalize, unicode fold -->

### object id

The Entra GUID of the user object a token was issued for, the `oid` claim,
which *is* the `subject` field once encoded — the Entra adapter stores it bare.
A directory coordinate, and safe to log: a coordinate is not a credential.
<!-- avoid: oid, the sub -->

### RDN

A DN's leading component: the object's own name within its OU.

### role group

A realm-wide policy group found by the marker it carries rather than by name,
so a rename keeps working: the `admission group` and the device-grant group,
and only those two. Exactly one must carry each marker — none is **missing**,
two or more is **ambiguous**, and they are two errors rather than one because
the way out of each is the opposite of the other's and a realm goes from one to
the other without passing through health. A `delegate group` is deliberately
not resolved this way.
<!-- avoid: policy group, well-known group, marker group -->

### role marker

The `kbrole1|<role>` marker saying what a group is for — `realm-admission`,
`device-grant`, `delegates` — so a reader matches on the marker and a rename or
a lost cursor changes nothing. Exactly one group may carry each of the two
realm-wide roles, and sync names the three ways that can be untrue apart:
**missing** (no group carries it), **ambiguous** (two or more do) and
**misconfigured** (one does, but not the configured group). `kbrole1|delegates`
is the exception — non-singleton, one group per delegated account, so
exactly-one-or-freeze must never be applied to it.
<!-- refs: `kerbridge_core::state` -->
<!-- avoid: role tag, role value, group marker -->

### sanitize

Fold an arbitrary source string into a name `validate` will accept: lowercased,
allowed characters only, both the character and byte budgets enforced,
separators trimmed, never empty (falling back to `kbuser`). Its output always
satisfies `validate` — that invariant is the module's reason to exist.
<!-- refs: `kerbridge_core::sam::sanitize` -->
<!-- avoid: sanitize_sam, safe_name, slugify -->

### seen stamp

The `seen=<epoch>` field on a device grant recording its last use, written at
most once a day and read in whole days. A display stamp and not data — a failed
stamp never fails a ticket exchange — and *touch* is the act of writing it.
Shown to users as *last seen*.
<!-- refs: `kerbridge_core::grant::needs_touch`, `seen_days_ago` -->
<!-- avoid: last use, last-use day, last-use stamp, touch stamp -->

### short id

The operator's handle for a device: the first four bytes of its key thumbprint
in hex, eight characters. A function of the key and not of the client-chosen
label, so it cannot be forged into revoking the wrong device.
<!-- refs: `kerbridge_core::grant::short_id` -->
<!-- avoid: device id, handle, operator handle, key id -->

### state marker

The `kbstate1|<state>|<RFC3339>` marker recording where an object is in its
lifecycle — `retired`, `quarantined`, `namepinned` — and when it entered that
state. Nothing gates on the timestamp: the retention-age helper exists only so
operator tooling can say how long an object has been held, and there is
deliberately no configured window for it to be past. Only `retired` and
`quarantined` mean sync stopped seeing the object; a `name pin` sits on a live
account.
<!-- refs: `kerbridge_core::state::retention_age_days` -->
<!-- avoid: status marker, lifecycle marker, retention marker, lifecycle flag, state value, state stamp, st marker -->

### subject (identity)

The immutable per-principal field of an `external identity`; for Entra the
`oid` claim, which is the `object id` on the provider side. A mutable attribute
is never a mapping key, and the word is not free for a notification key or a
grant handle.
<!-- avoid: oid, sub, the subject claim -->

### thumbprint

Base64url-unpadded SHA-256 over a device's raw uncompressed P-256 public point
(`0x04 || X || Y`), exactly 43 characters: the identity of a device grant.
Derived by the broker from the key presented and never taken from the client,
and checked against that exact length and charset before anything is stored.
<!-- refs: `kerbridge_core::grant::is_thumbprint` -->
<!-- avoid: fingerprint, key digest, key hash, key id, digest, hash -->

### ticket (credential)

The KDC-signed TGT a `ticket exchange` returns, and the word for it in every
fixed compound: `POST /ticket`, ticket lifetime, `ticket exchange`, `ticket
policy`. Every ticket KerBridge handles is a TGT, so the plain word is safe in
prose; it is never a helpdesk ticket and never a unit of rate limiting.
<!-- avoid: creds, helpdesk ticket -->

### ticket format

The named shape of the credential the broker returns and the client injects,
`mit-ccache-v4`, pinned by name and published in the `discovery document` so
neither end infers it.
<!-- refs: `kerbridge_core::issuer::TICKET_FORMAT` -->

### UAC value

A `userAccountControl` value a synced object is expected to carry, stored as a
decimal string. The no-expire bit is mandatory, because an expired password
breaks keytab-based issuance for that account.
<!-- refs: `kerbridge_core::state::UAC_ENABLED`, `UAC_DISABLED` -->
<!-- avoid: useraccountcontrol, account flags -->

### validate

Decide whether an account name read back out of the directory may be used:
non-empty, at most 64 bytes, no leading `-`, and letters, digits, `.`, `-`, `_`
only. The admitting half of the one rule `sanitize` derives under.
<!-- refs: `kerbridge_core::sam::validate` -->

### verb (issuer)

One request kind `issuerd` answers, tagged `op` on the wire: `issue`,
`grant_device`, `revoke_grant`, `touch_grant`, plus `ping` for liveness. Each
names exactly one account by SID and at most one attribute value.
<!-- refs: `kerbridge_core::issuer::Request` -->
<!-- avoid: operation, command, method -->

### version tag

The leading `kb1` / `kbrole1` / `kbstate1` / `kbkey1` token that says which
encoding a stored value is in. Bumped only for a structural change; the tags
themselves are on-disk contracts, not rename targets.
<!-- avoid: format version, prefix -->

### width of the verbs

The security property `issuerd` defends in place of reducing its own privilege:
no verb accepts a DN, a filter or an attribute name, so a compromised caller
cannot widen what a privileged process will do. It is what makes fronting a
domain administrator with an internet-facing broker safe.
