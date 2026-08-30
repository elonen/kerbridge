# kerbridge-idp — every provider-specific fact, in one place

A library, not a service. It is what the broker and sync both link so that the
two of them cannot disagree about a cloud IdP, and it is where a second or third
IdP is added.

## Why it is its own crate

An adapter has **two faces**, and they have to agree byte for byte:

- the broker turns a bearer credential into an `ExternalIdentity`;
- sync turns a directory (IdP) object from the same IdP into one.

Nothing connects those two processes. Separate containers, separate credentials,
no channel between them. If they emit different bytes for the same account:

- the broker's exact-match LDAP search finds nothing, so every login for that
  source fails with "identity is not provisioned"; and
- the stored value is also the **join key of sync's reconciliation loop** — the
  desired set is keyed by the IdP's subject, the current set by what came back
  out of AD — so sync sees every account as gone and every account as new. It
  retires each one and creates a replacement with a fresh SID, which strands
  every file the old SID owned under `idmap_rid`.

Neither program looks wrong while that happens. Putting both faces behind one
`Provider` and one encoder is what makes the agreement structural instead of a
convention two crates are trusted to keep. `crates/kerbridge-idp/src/entra/auth.rs`'s
tests hold them against each other directly.

`issuerd` deliberately does **not** link this crate. It holds KDC authority, and
all it needs of an identity is that the stored value parses — which
`kerbridge-core` answers on its own, with no dependencies.

The directory (IdP) face is behind the `sync` feature, which only `kerbridge-sync`
turns on: the broker, `kbconfig` and `kbsetup` link this crate for the token face
alone and compile no reader at all. One directory per provider holds both —
`src/entra/{mod,auth}.rs` is the token face, `src/entra/{sync,client,wire}.rs`
the directory (IdP) face — and `src/sync/` is the seam they meet the mirror at.

## The adapters this build carries

**Entra** is complete on both faces, and is the one measured against a live
tenant.

**authentik** carries **both faces**. The **token face** is the source
file's `[provider_config]`, the derivations every URL hangs off, the subject
rule and the verifier: `kbconfig` loads and checks a source, `kbconfig check
--online` asks the provider the three questions that catch the settings a token
never shows, and the broker verifies an access token against the shared
conformance suite and the forged corpus at
`testbench/fixtures/authentik-token/`. The **directory (IdP) face**
(`src/authentik/{sync,client,wire}.rs`) is a full REST read every cycle —
authentik has no delta, no group-side change filter and invisible deletions, so
a torn read is refused rather than mirrored short a person, a dangling id refuses
the whole read, and nothing filters an account below the admission closure. It
is validated with no container against `testbench/fixtures/authentik-directory/`,
golden included.

## What is provider-specific, and therefore lives here

- Token verification: which algorithm, which issuer, which audience, which claim
  is the subject, and in which order those are checked. Entra's is written out
  claim by claim in [`entra.md`](entra.md).
- Key acquisition. JWKS is one IdP's answer, not the only one, so the cache
  sits inside the adapter rather than beside it: an adapter whose IdP does not
  publish keys establishes trust some other way, and nothing outside it should
  have to care which.
- The discovery document a client bootstraps from, including
  `extra_auth_params`: Entra asks for a refresh token through the
  `offline_access` scope, and an IdP that instead wants parameters on the
  authorization request puts them there. One field beats an IdP branch in the
  client.
- The **subject encoding** — what goes in field 3 of `kb1|<name>|<subject>`.
  Opaque to everything else. Entra's is the bare `oid`; authentik's is the
  user's `uuid`, chosen for being the only identifier its REST API can *filter*
  on — a subject the directory (IdP) cannot be queried by makes the two faces
  impossible to hold together, whatever else recommends it.
- **Whether a subject not in that shape is refused, and in whose words.** Nothing
  normalizes: a transformation over a value that is unrecoverable if wrong
  becomes a second thing that may never change. An adapter that can tell two
  causes apart says which — authentik's separates "the provider is on the
  wrong subject mode", which an operator fixes, from "the IdP changed how it
  spells a uuid", which is not theirs to fix.
- Reading the directory (IdP): the protocol, the credential, the cursors, and which
  accounts the IdP's own rules accept. What comes back is a `SourceSnapshot`, and
  reconciliation never enters an adapter. The realm's own rules — the group
  closure, the held-narrowing, the refusal list — are `sync::build_desired`, and
  an adapter uses them or fills a `Desired` its own way.
- Which strings a login name may be minted from, and in what order. The adapter
  offers `name_candidates`, best first; the realm decides which of them a name
  may actually *be*, because that needs a domain-wide view no adapter has. One
  rule reduces a candidate to what AD accepts — `sync::name_candidate` — so no
  adapter carries a character set of its own. Entra's choice is `sam_source`.
- A source file's `[provider_config]`, both the parser and the commented example
  block. `kerbridge-core` reads the envelope around it, captures that table and
  hands it here without looking inside — parsed anywhere else, core, and
  therefore `issuerd`, would carry a struct describing what an Entra deployment
  needs. The example block is provider prose ("from the app registration's
  Overview blade"), so the second adapter's
  `deploy/configs/idp_<name>.toml.example` appeared with no change outside this
  crate.
- **What the block derives, and from what.** Entra hangs its issuer, authority
  and key document off `tenant_id`; authentik hangs them off an instance URL plus
  the *application slug*. Each derived value stays overridable, because the
  deployment that has to state one is the deployment behind a proxy that rewrites
  what the IdP publishes about itself.
- The `kbconfig check --online` probe: which document to fetch, and which claims
  in it to compare against what the adapter derived. Entra's compares the
  published `issuer`, because that and every stored subject both come from
  `tenant_id` — a wrong one misfiles every account rather than failing loudly.
  authentik's compares the issuer for the same reason, and reads two more claims
  out of the same document because two of its provider defaults are wrong for
  KerBridge and neither is visible in a token: with no Signing Key it signs
  symmetrically, and without the `offline_access` mapping attached it drops the
  scope in silence and issues no refresh token. An answer *about* the request
  (4xx, an unreadable document, a mismatch) is a hard fail; no answer at all
  (DNS, a refused connection, a timeout, 5xx) is a warning about the world. The
  fetch itself is shared: what a document *means* is provider-specific and what a
  refused connection means is not.

## Two rules that are not negotiable

**The subject must be stable for the lifetime of the account.** It is the
primary key of the AD object; a changed subject orphans that object and detaches
every file whose owner `idmap_rid` derived from its SID. Silent, and
unrecoverable. This is why subject selection is compiled into the adapter and is
never configuration.

**The algorithm allowlist is asymmetric-only**, compiled in, never
configuration. Every symmetric algorithm (`HS*`) and `none` are permanently
excluded; the RSA families `RS*` and `PS*` are allowed today and ES256 is
an expected future addition. A JWK that states its own `alg` narrows this to that
one algorithm for that one key, so the list bounds what an IdP may publish rather
than what an already-published key may be used with. Two reasons: an RSA public
key is published, so a verifier that dispatched on the token's own `alg` would
let anyone HMAC-sign a forgery with those bytes; and with an asymmetric algorithm
the broker holds only public key material and cannot forge a token *even if fully
compromised*, which is the same reason KDC authority sits in `issuerd` behind a
peer-uid-authorized socket.

The guard is structural: the allowlist is resolved before any key is loaded — the
lookup hands back the primitive to verify with, so nothing can pass the check and
then be verified by something else — and no adapter contains a symmetric
verification routine at all. Do not add an HMAC code path for completeness. Some
IdPs offer symmetric signing as an ordinary option, so an operator can
legitimately arrive with it configured — every page documenting an IdP's setup
says to use an asymmetric signing key.

## Adding an adapter

Add one arm to `Provider`, and the compiler names every place it has to be
wired: `name`, `template`, `connect`, `encode_identity`, `IdpSettings::parse`,
`probe` and `sync::connect`.
Then run the shared conformance suite
(`src/conformance.rs`) against it with tokens forged against that IdP — an
adapter that does not run it is one whose algorithm handling nobody has checked,
and the failure mode there is a silent authentication bypass.

Two things follow from the arms being a match rather than a registry. An adapter
can land face by face, with the faces it has not got refusing by name in their
own arm; and a helper two adapters come to share moves to a private module here
— `src/jwt.rs` for the JOSE shapes and for the structure, algorithm and
signature in front of every claim rule, `src/lib.rs` for the probe's HTTP —
rather than becoming a public type, which would make every future adapter's
protocol a commitment the trait never asked for. That first one is shared
because it is where a mistake is an authentication bypass rather than a wrong
answer; what the claims then have to *say* is never shared, and is why
`identify` still receives an opaque credential.

Read the IdP's own documentation rather than assuming it resembles Entra's or
authentik's. The interface is
shaped so that the likely differences are absorbable inside your arm of the
match:

- **The credential need not be a JWT.** `identify` takes a bearer credential, not
  a token, so an adapter whose access tokens are opaque can verify something else
  or introspect instead.
- **A claim need not have the type or spelling Entra uses.** Parse what your IdP
  documents; `src/entra/auth.rs` is one example, not a template.
- **The issuer may be a setting rather than a constant**, which is the whole
  reason the stored identity carries a source name and not an issuer URL.

`DESIGN.md` § [External identity model](../../docs/design/identity-and-directory.md#external-identity-model)
and § [Entra validation](../../docs/design/identity-and-directory.md#entra-validation).
