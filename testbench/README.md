# Test bench

Nothing here is production code, for testing only.

## `fixtures/` — test corpora, loaded by `cargo test`

| Path | What | Read by |
|---|---|---|
| `entra-token/` | signed JWTs + `jwks.json`: a positive delegated token, an RS/PS algorithm sweep, and the negatives (wrong tenant/audience/`azp`/scope, missing `scp` or `oid`, `idtyp=app`, expired, future `nbf`, unknown kid, `alg:none`, `alg:none` under an unknown kid, HS256, HS256 confusion, unknown alg, an alg the key does not publish, malformed tid, iss/tid mismatch, v1 shape, non-JWT garbage). The script also generates a second positive for a different `oid`, which only the live run below uses — see the note there. | `kerbridge-idp/src/entra/auth.rs`, and `deploy/scripts/bench/ci-stack.sh` |
| `authentik-token/` | signed JWTs + `jwks.json`: one positive access token and the negatives (the neighbouring application's own token, the all-providers issuer mode, an `azp` that disagrees with `aud`, the ID token from the same sign-in, the default `sub_mode`, expired, unknown kid, an alg the key does not publish, `alg:none`, `alg:none` under an unknown kid, HS256, HS256 confusion, unknown alg, the EdDSA an Ed25519 signing key produces, non-JWT garbage). Plus `jwks_empty.json`, the document a provider with no Signing Key publishes. | `kerbridge-idp/src/authentik/auth.rs` |
| `graph-sync/` | recorded-shape Graph exchanges — delta init/incremental/paging, soft and hard delete, 410 Gone, 429 throttle, transitive members, syncable-rule cases. | `kerbridge-idp/src/entra/wire.rs`, `client.rs` |
| `authentik-directory/` | recorded-shape Authentik directory pages — four read pages carrying the structural cases as rows, a corpus-local golden desired state, torn-read and bad-value negatives, and the error shapes (three 403 bodies, a 503 and a non-JSON body; no 401, no 429). Derived and trimmed from `../authentik/captured/`, with a `README.md` indexing every file. | the authentik directory read (`advance`); reader lands next |
| `planner/` | golden files, each `{admission, desired, current, plan}` — retention, quarantine, admission-group-deleted freeze, ambiguous-identity conflict, role-marker restamp. | `kerbridge-sync/src/planner/mod.rs`, `kerbridge-idp/src/entra/wire.rs` |
| `tls/` | Two certificates, covering both arms of every branch the client's X.509 reader has: private-CA-issued vs self-signed, subjectAltName vs none, UTCTime vs GeneralizedTime, ASCII vs UTF8String. Nothing presents or trusts these — they are bytes to parse. | `kerbridge-client/src/tls.rs` |

The `make_fixtures` scripts stay because they are the only way to regenerate
their corpus. The two token generators share `tokenforge.py`, which owns the
signing key, the JWKS and the negatives `conformance::Forged` demands, so a
third IdP inherits `neg_alg_confusion`'s load-bearing assert instead of copying
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

## `authentik/` — live blueprint proof

`make test-authentik` starts the pinned three-container Authentik stack, waits for
its default blueprints, applies the KerBridge bench blueprint, and completes an
authorization-code flow. It checks the discovery document, the provider settings,
and the issued tokens. It tests Authentik fixture data and runs no KerBridge
container or Rust code. The default run removes the stack and its volume. Use
`make test-authentik ARGS=--keep` to preserve them.

For manual iteration:

```sh
testbench/authentik/authcode.sh up
testbench/authentik/authcode.sh flow
testbench/authentik/authcode.sh down
```

## `deploy/bench.env` — the bench's own fixtures, and why they are not here

The development bench also uses seeded accounts, object IDs, the `mockidp`
tenant ID, and the example file server's name and address. These values are in
[`../deploy/bench.env`](../deploy/bench.env). All identifiers are synthetic and
production does not read this file. Keeping them together prevents duplicate
defaults in `deploy/.env.example` and `seed-demo.sh`.

They are in `deploy/` rather than under `testbench/` for two mechanical reasons:

- `make test-stack` stages a disposable tree from the *tracked* files
  (`git ls-files` → `.local-tmp/ci-tree`) and works only there, so a fixture the
  deploy scripts need has to be committed to exist inside that tree at all.
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
