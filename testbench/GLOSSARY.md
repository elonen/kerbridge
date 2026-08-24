# testbench glossary

Test fixture corpora, live-tenant tooling, and the capture decoder — what a
corpus, a case, and a fixture mean here.

Part of the repo-wide vocabulary in [`GLOSSARY.md`](../GLOSSARY.md) — a term
means the same thing there and here. It lives in this file, closest to where
it's used, rather than in the root file, because the root file would be
unreadably long if it carried every term at once.

### capture

One rotating tcpdump file set that the capture decoder reads, named for where
it was taken.
<!-- refs: `testbench/wire.py`; names `frag88`, `ws`, `member`, `dc` -->
<!-- avoid: cap, pcap -->

### case

One named situation a [fixture](#fixture-test-corpus) pins. Planner cases are
numbered `S1` through `S12` (plus `S2b`); token cases are named for the single
thing wrong with them.
<!-- avoid: scenario, work-order item -->

### corpus

One directory under the fixtures root that its reader loads as a set and that
is regenerated whole or not at all.
<!-- refs: path `testbench/fixtures/`; corpora `entra-token`, `graph-sync`, `planner`, `tls` -->
<!-- avoid: test corpora, fixture set, golden files -->

### evidence

The text output an [instrument](#instrument) or the capture decoder writes; the
artifact a research spike is judged on.
<!-- refs: kept under `docs/research/` -->
<!-- avoid: results, output, findings -->

### fixture (test corpus)

One committed file inside a [corpus](#corpus): a signed token, a
[recorded-shape exchange](#recorded-shape-exchange), a planner case, a
certificate. Every identifier in one is synthetic, and the committed tokens are
expired on purpose.
<!-- avoid: golden file -->

### generator

A script, the only sanctioned way to change the [corpus](#corpus) it owns.
One per generated corpus; the planner corpus has none, its cases being
hand-written golden files.
<!-- refs: `make_fixtures.py` / `make_fixtures.sh`, one per generated corpus: `entra-token`, `graph-sync`, `tls` -->
<!-- avoid: script -->

### instrument

A script in the live-tenant tooling, pointed at a live tenant to settle one
open question and kept as a worked example of driving the shared Graph helper.
<!-- refs: `exp_*.py` under `testbench/entra-tenant/`; drives `graph.py` -->
<!-- avoid: tool, script, experiment, probe -->

### live corpus

The token [corpus](#corpus) the stack test generates, so the broker under test
verifies a token inside its own [validity window](#validity-window). It carries
a second [positive](#positive), which the committed corpus does not.
<!-- refs: `ci-stack.sh` generates it into `.local-tmp/ci-fixtures` at `make test-stack` time; carries `positive_other_user.jwt` -->
<!-- avoid: ci fixtures, scratch corpus -->

### negative

A token [fixture](#fixture-test-corpus) that must be refused, named for the
single defect it carries.
<!-- refs: names `neg_wrong_tenant`, `neg_expired`, `neg_alg_none`, … -->
<!-- avoid: bad token, invalid token -->

### note

The prose field at the top of a [recorded-shape
exchange](#recorded-shape-exchange) stating what the shape proves and what a
reader must not conclude from it; the corpus's own documentation channel.
<!-- avoid: comment, header -->

### positive

A token [fixture](#fixture-test-corpus) that must verify. Exactly one is
committed; the second exists only in the [live corpus](#live-corpus), because
committing it would mean regenerating the whole corpus and moving the
[validity window](#validity-window) the broker's verifier pins.
<!-- refs: the pinned window lives in `kerbridge-idp/src/entra.rs` -->
<!-- avoid: good token, happy path -->

### recorded-shape exchange

A [fixture](#fixture-test-corpus) of the sync [corpus](#corpus): one
`{note, request, response{status, headers, body}}` object holding a complete
HTTP exchange for replay, with the Graph documentation it follows cited in the
[generator](#generator).
<!-- refs: corpus `graph-sync` -->
<!-- avoid: recorded-style, recording, replay fixture, canned response -->

### selected user

Which bench identity the [stand-in authority](#stand-in-authority) will issue
for next. Sticky once set; a login hint overrides it for a single exchange.
<!-- refs: set via `POST /select`; override field `login_hint` -->
<!-- avoid: current user, active user, default user -->

### stand-in authority

Serves discovery, JWKS, authorize and token, verifies PKCE, and issues tokens
the broker's verifier accepts unmodified. It is not an authorization server —
the authorize endpoint approves everyone, with no credential of any kind — so
it belongs on bench networks only.
<!-- refs: `testbench/mock-idp`; endpoint `/authorize` -->
<!-- avoid: the mock, idp, standing-in oidc authority -->

### validity window

The `nbf`..`exp` span baked into a committed test token. The committed
[corpus](#corpus) is expired on purpose, so the verifier tests pin a fixed
clock; the [live corpus](#live-corpus) gets a fresh window instead.
<!-- avoid: token lifetime, expiry window -->

### zoo

A deliberately exhaustive cast of directory objects assembled so that every
claimed member type or name case appears at least once.
<!-- avoid: object zoo, cast, menagerie -->
