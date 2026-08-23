# Test bench

Nothing here is production code, for testing only.

## `fixtures/` — test corpora, loaded by `cargo test`

| Path | What | Read by |
|---|---|---|
| `entra-token/` | 17 signed JWTs + `jwks.json`: one positive delegated token and 16 negatives (wrong tenant/audience/`azp`/scope, missing `scp` or `oid`, `idtyp=app`, expired, future `nbf`, unknown kid, `alg:none`, HS256 confusion, malformed tid, iss/tid mismatch, v1 shape, non-JWT garbage). The script also generates a second positive for a different `oid`, which only the live run below uses — see the note there. | `kerbridge-idp/src/entra.rs`, and `deploy/scripts/bench/ci-stack.sh` |
| `graph-sync/` | 20 recorded-shape Graph exchanges — delta init/incremental/paging, soft and hard delete, 410 Gone, 429 throttle, transitive members, admission-group ambiguity, syncable-rule cases. | `kerbridge-sync/src/graph/mod.rs`, `graphclient.rs` |
| `planner/` | 13 golden files, each `{desired, current, plan, error}` — retention, quarantine, admission-group-deleted freeze, partial-read refusal, ambiguous-identity conflict, role-marker restamp. | `kerbridge-sync/src/planner/mod.rs`, `graph/mod.rs` |
| `tls/` | Two certificates, covering both arms of every branch the client's X.509 reader has: private-CA-issued vs self-signed, subjectAltName vs none, UTCTime vs GeneralizedTime, ASCII vs UTF8String. Nothing presents or trusts these — they are bytes to parse. | `kerbridge-client/src/tls.rs` |

The three `make_fixtures` scripts stay because they are the only way to
regenerate their corpus:

- `entra-token/make_fixtures.py` is **run live** by `make test-stack`:
  `deploy/scripts/bench/ci-stack.sh` copies it into a scratch directory and runs
  it, so the broker under test verifies a token inside its own validity window
  against a locally generated `jwks.json`. It creates a fresh throwaway RSA key
  on every run; that key is gitignored and never committed.
  `positive_other_user.jwt` exists only in that live corpus: the delegation
  checks need two admitted callers to distinguish "refused for not being a
  delegate" from "refused for not being admitted", and committing a second
  positive would mean regenerating the whole corpus and moving the validity
  window `verify.rs` pins. A future regeneration picks it up; nothing reads it
  from here.
- `graph-sync/make_fixtures.py` writes the recorded-shape corpus, with the Graph
  documentation each shape follows cited at the top.
- `tls/make_fixtures.sh` sets literal `notBefore`/`notAfter` values rather than
  `-days N`, so the tests can assert the dates they parse. Its keys go to
  `.local-tmp/` and are deleted on the way out.

The committed JWTs are time-bound and already expired, so the verifier tests
inject a fixed clock — which is the right shape for a verifier test anyway. All
identifiers in the fixtures are synthetic.

## `deploy/bench.env` — the bench's own fixtures, and why they are not here

The development bench has a cast too — three seeded accounts with their object
ids, `mockidp`'s tenant id, and the example file server's name and address — and
it is tracked, in [`../deploy/bench.env`](../deploy/bench.env). Fixtures in this
directory's sense: every identifier synthetic, the same on every bench that has
ever run, and read by nothing production runs. Until they had a file of their own
they were split between `deploy/.env.example` and defaults inside
`seed-demo.sh` — values nobody chooses, sitting in a gitignored per-operator file
in front of everyone deploying a real realm, and defaulted a second time wherever
a script happened to need one.

They are in `deploy/` rather than under `testbench/` for two mechanical reasons:

- `make test-stack` stages a disposable tree from the *tracked* files
  (`git ls-files` → `.local-tmp/ci-tree`) and works only there, so a fixture the
  deploy scripts need has to be committed to exist inside that tree at all.
- Compose and those scripts read it beside `.env`, relative to the compose
  project directory: `COMPOSE_ENV_FILES=bench.env,.env`, and the scripts source
  the same pair in the same order.

Overriding one needs no edit to the tracked file. The last file read wins, so a
line in `deploy/.env` beats it, and a variable in the environment beats both —
which is how `ci-stack.sh` hands its throwaway realm a different subnet and a
different cast without touching the fixtures. `SEED_USER_OID` is the value a
bench against a live tenant has to override: it must be the `oid` that tenant's
token actually carries, or the broker refuses every login.

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
| `exp_delta.py`, `exp_delta2.py`, `exp_misc.py` | Pointed at the three Graph items still open: the 410 `Location` shape, real throttling values, and the delta propagation-lag bound. |
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
