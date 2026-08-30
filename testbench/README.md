# Test bench

Nothing here is production code, for testing only.

## `fixtures/` — test corpora, loaded by `cargo test`

| Path | What | Read by |
|---|---|---|
| `entra-token/` | signed JWTs + `jwks.json`: a positive delegated token, an RS/PS algorithm sweep, and the negatives (wrong tenant/audience/`azp`/scope, missing `scp` or `oid`, `idtyp=app`, expired, future `nbf`, unknown kid, `alg:none`, `alg:none` under an unknown kid, HS256, HS256 confusion, unknown alg, an alg the key does not publish, malformed tid, iss/tid mismatch, v1 shape, non-JWT garbage). The script also generates a second positive for a different `oid`, which only the live run below uses — see the note there. | `kerbridge-idp/src/entra/auth.rs`, and `deploy/scripts/bench/ci-stack.sh` |
| `authentik-token/` | signed JWTs + `jwks.json`: one positive access token and the negatives (the neighbouring application's own token, the all-providers issuer mode, an `azp` that disagrees with `aud`, the ID token from the same sign-in, the default `sub_mode`, expired, unknown kid, an alg the key does not publish, `alg:none`, `alg:none` under an unknown kid, HS256, HS256 confusion, unknown alg, the EdDSA an Ed25519 signing key produces, non-JWT garbage). Plus `jwks_empty.json`, the document a provider with no Signing Key publishes. | `kerbridge-idp/src/authentik/auth.rs` |
| `graph-sync/` | recorded-shape Graph exchanges — delta init/incremental/paging, soft and hard delete, 410 Gone, 429 throttle, transitive members, syncable-rule cases. | `kerbridge-idp/src/entra/wire.rs`, `client.rs` |
| `authentik-directory/` | recorded-shape authentik IdP directory pages — four read pages carrying the structural cases as rows, a corpus-local golden desired state, torn-read and bad-value negatives, and the error shapes (three 403 bodies, a 503 and a non-JSON body; no 401, no 429). Derived and trimmed from `../authentik/captured/`, with a `README.md` indexing every file. | `kerbridge-idp/src/authentik/{wire,client,mod}.rs` |
| `planner/` | golden files, each `{admission, desired, current, plan}` — retention, quarantine, admission-group-deleted freeze, ambiguous-identity conflict, role-marker restamp. | `kerbridge-sync/src/planner/mod.rs`, `kerbridge-idp/src/entra/wire.rs` |
| `tls/` | Two certificates, covering both arms of every branch the client's X.509 reader has: private-CA-issued vs self-signed, subjectAltName vs none, UTCTime vs GeneralizedTime, ASCII vs UTF8String. Nothing presents or trusts these — they are bytes to parse. | `kerbridge-client/src/tls.rs` |

The `make_fixtures` scripts stay because they are the only way to regenerate
their corpus. The two token generators share `tokenforge.py`, which owns the
signing key, the JWKS and the negatives `conformance::Forged` demands, so a
third IdP inherits `neg_alg_confusion`'s assert instead of copying
it; each corpus forks only its own claim shape and its own claim-level
negatives. `entra-token` and `graph-sync` take `--out` and default to the corpus
they live in:

- `entra-token/make_fixtures.py` is **run live** by `make test-stack`:
  `deploy/scripts/bench/ci-stack.sh` runs it in place with `--out` pointing at a
  scratch directory, so the broker under test verifies a token inside its own
  validity window against a locally generated `jwks.json`. It creates a fresh
  throwaway RSA key on every run; that key is gitignored, never committed, and
  follows `--out`, because `compose.ci-entra.yaml` mounts it into mockidp from
  there.
  `positive_other_user.jwt` exists only in that live corpus: the delegation
  checks need two admitted callers to distinguish "refused for not being a
  delegate" from "refused for not being admitted", and committing a second
  positive would mean regenerating the whole corpus and moving the validity
  window `verify.rs` pins. A future regeneration picks it up; nothing reads it
  from here.
- `authentik-token/make_fixtures.py` has **no** `--out`: nothing runs this corpus
  live, because the tier that exercises authentik signs a real user in against a
  real provider. It carries no algorithm sweep either — that belongs to the
  shared allowlist rather than to either IdP, and `entra-token` already covers
  it.
- `graph-sync/make_fixtures.py` writes the recorded-shape corpus, with the Graph
  documentation each shape follows cited at the top.
- `tls/make_fixtures.sh` sets literal `notBefore`/`notAfter` values rather than
  `-days N`, so the tests can assert the dates they parse. Its keys go to
  `.local-tmp/` and are deleted on the way out.

The committed JWTs are time-bound and already expired, so the verifier tests
inject a fixed clock — each corpus's window is pinned in the adapter that reads
it — which is the right shape for a verifier test anyway. All identifiers in the
fixtures are synthetic.

### Where each corpus comes from, and what a green test therefore proves

A fixture is worth what its origin is worth, and the origins are not the same.

- **Synthesized** — `entra-token/`, `authentik-token/`, `tls/`. `tokenforge.py`
  and `make_fixtures.sh` sign every one of these with a key they own. A green
  test says the reader accepts and refuses the shapes *this repository chose to
  write*. It says nothing about what the IdP issues. The claim shapes are held
  to the providers' documentation by hand. `make test-authentik` is the one
  thing that puts a provider-issued token through the same verifier, and it does
  so for authentik only.
- **Documentation-derived** — `graph-sync/`. Written from Microsoft's published
  Graph shapes; no tenant produced a byte of it. `make test` cannot detect a
  shape that is wrong, because it reads the same corpus and so agrees with
  itself. [`entra-tenant/conformance.py`](entra-tenant/conformance.py) is the
  only thing that compares it with a live tenant, and it is run by hand.
- **Recorded** — `authentik/captured/`, taken from a live
  `ghcr.io/goauthentik/server:2026.8.0` by `authentik/capture_directory.py`. The
  server, not this repository, decided what these bytes are.
- **Derived from a recording** — `authentik-directory/`, trimmed and pinned from
  those recordings. The trim is stated, and `check_derivation.py` holds the
  corpus to it on every `make test`, together with a provenance table naming the
  recording each file came from.
- **Hand-written golden** — `planner/`. Each file states an intended decision.
  It is a specification the planner is held to, not evidence of anything outside
  this repository.

So one provider's wire shapes reached the tests from that provider, and it is
authentik. Nothing in `graph-sync/` did; `conformance.py` closes that by hand,
and [`entra-tenant/README.md`](entra-tenant/README.md) is the procedure.

## `authentik/` — live blueprint proof

`authcode.sh` is the standalone provider proof. It starts this directory's pinned
three-container authentik stack, waits for its default blueprints, applies the
KerBridge bench blueprint, and completes an authorization-code flow. It checks
the discovery document, the provider settings and the issued tokens, and runs no
KerBridge container or Rust code.

`make test-authentik` instead runs `deploy/scripts/bench/ci-authentik.sh`: a
disposable KerBridge stack with live authentik behind its Caddy. It exercises the
adapter from OIDC sign-in and a full IdP directory read through TGT issuance and an
SMB file read. The default run removes the stack and its volumes. Use `make
test-authentik ARGS=--keep` to preserve them.

For manual iteration:

```sh
testbench/authentik/authcode.sh up
testbench/authentik/authcode.sh flow
testbench/authentik/authcode.sh down
```

Both stacks hold their passwords and API tokens as constants in the tracked
files — the compose file, the blueprints and the scripts. An authentik API token
cannot be read back after it is created, so a constant is the only way the two
ends can agree on one. Each value carries the word `bench`: `benchpass`,
`kerbridge-bench-bootstrap-token`, `bench-user-password`,
`bench-only-secret-key-not-for-anything-real`. The CI tier keeps its own copies
under `deploy/`, by the same rule — see
[Development bench versus production](../deploy/README.md#development-bench-versus-production).

## `deploy/bench.env` — the bench's own fixtures, and why they are not here

The development bench also uses seeded accounts, object IDs, the `mockidp`
tenant ID, and the example file server's name and address. These values are in
[`../deploy/bench.env`](../deploy/bench.env). All identifiers are synthetic and
production does not read this file. Keeping them together prevents duplicate
defaults in `deploy/.env.example` and `seed-demo.sh`.

They are in `deploy/` rather than under `testbench/` for two mechanical reasons:

- Each stack tier stages a disposable tree from the *tracked* files (`git
  ls-files` → its own directory under `.local-tmp/`) and works only there, so a
  fixture the deploy scripts need has to be committed to exist inside that tree
  at all.
- Compose and those scripts read it beside `.env`, relative to the compose
  project directory: `COMPOSE_ENV_FILES=bench.env,.env`, and the scripts source
  the same pair in the same order.

An override does not require an edit to the tracked file. The last file read
wins: `deploy/.env` overrides `bench.env`, and an environment variable overrides
both. The stack test uses this order to set an isolated subnet and test accounts.
A live-tenant bench must set `SEED_USER_OID` to the `oid` in that tenant's token.
Otherwise, the broker refuses each sign-in.

## `entra-tenant/` — operating a live tenant

Some tools for *acquiring* evidence from a real Entra tenant. They do not implement anything KerBridge
ships.

The app registrations themselves are **not** here — `deploy/terraform/entra/` creates
them, and [`../docs/setup/entra-manual.md`](../docs/setup/entra-manual.md) is the portal walk for the same thing.

| File | What |
|---|---|
| `conformance.py` | Reads a live tenant and compares it with the `graph-sync` corpus, so the corpus stops being documentation-derived. Read-only, run by hand, never a tier. [`entra-tenant/README.md`](entra-tenant/README.md) is the whole procedure, including how to build a tenant for it. |
| `graph.py` | Thin Graph client the rest call. Reads the tenant id from `ENTRA_TENANT_ID` or a local `config.json`; credentials from a gitignored `secrets/`. |
| `devicecode.py` | Device-code flow for a delegated admin Graph token. |
| `pkce.py` | Auth code + PKCE for a *user* token, loopback redirect. `client/kerbridge-client/src/oidc.rs` is the port of this, and `kerbridge.exe --token-file` still takes the `access_token` it writes. |
| `setup_directory.py`, `setup_directory2.py` | Build the user, group and membership zoo the sync follow-ups need. The disposable tenant was deleted; a new one has to be rebuilt before any `exp_*` script runs. |
| `exp_delta.py`, `exp_delta2.py`, `exp_misc.py` | Pointed at the Graph items still open: the 410 `Location` shape, real throttling values, and the delta propagation-lag bound. |
| `exp_final.py`, `exp_graph_reads.py`, `exp_xstream.py` | The read-shape, guest-claim and cross-stream-cursor instruments, kept as the worked examples of driving `graph.py` against a tenant. |

Every `exp_*` script loads `config.json` and `directory.json`, which the previous
tenant's identifiers are gone from. Recreate both.

## `wire.py` — decoding a capture without tshark

Reads rotating `tcpdump` captures and prints a decoded, UTC-stamped ladder:
Kerberos message types, error codes and transport on port 88; SMB2 command and
NTStatus on 445. Set `WIRE_EVIDENCE_DIR`.

[`../docs/windows-testbench.md`](../docs/windows-testbench.md) tells you to
capture packets on both the DC and the file server from the start of a Windows
session, and the bench VM has no tshark. This is what reads the result.
