# The authentik directory (IdP) fixture corpus

Sixteen pinned files that let `cargo test` exercise the authentik directory
(IdP) read -- the `advance()` face -- and the sync credential's own expiry measurement,
with no container. It is the directory (IdP) companion to
`../authentik-token/`, and it is loaded as a set: the reader points
at this directory the way the Entra reader points at `../graph-sync/`.

**Derived, not recorded.** Every file here is trimmed and pinned from the live
recordings at `../../authentik/captured/`, which were taken against
`ghcr.io/goauthentik/server:2026.8.0`. The recordings carry a full response
header block with per-request noise and identifiers that change run to run; this
corpus keeps the response body's shape and pins the identifiers, so a test can
assert exact bytes. The trim is deliberate and the same on every read page:

- response headers reduced to `content-type` alone,
- the `autocomplete` UI-hint block dropped from every page body -- the
  directory (IdP) read never looks at it,
- object rows cut to the fields the read consumes plus the ones that carry a
  structural case: users keep `pk`, `username`, `name`, `is_active`, `groups`,
  `groups_obj`, `email`, `type`, `uuid`; groups keep `pk`, `num_pk`, `name`,
  `parents`, `parents_obj`, `users`, `users_obj`, `children`, `children_obj`.

The `*_obj` keys are kept at their recorded `null`: under `include_users=false`
and `include_groups=false` authentik nulls the object arrays but keeps the id
arrays, so a reader that follows `children_obj`/`groups_obj` instead of
`children`/`groups` reads an empty directory (IdP), and this corpus is a test of that.

There is no generator. The corpus is hand-derived and edited in place, like
`../planner/`; regenerating it would mean re-recording, which is
`../../authentik/capture_directory.py`'s job, not this directory's.

So the derivation cannot be replayed, and a byte comparison against a
re-recording proves nothing: a re-record keeps the shapes and none of the
identifiers. [`check_derivation.py`](check_derivation.py) checks the part that
*is* invariant, and `make test` runs it — the trim above, the `*_obj` nulls, the
status each recording returned, and that no row carries a field its recording
never returned. It also holds a provenance table naming where every file here
came from, so a fixture cannot enter the corpus without saying what it is
derived from.

## The read pages

Four pages, `?ordering=pk`, `page_size` forced to a two-page boundary. Together
they are one whole read of a 13-user, 11-group directory (IdP). The structural cases
ride as rows, never as files of their own.

| File | What it pins |
|---|---|
| `users_page1.json` | First user page, `pagination.next` the integer 2. Carries a service account (`kb-svc-sync`, `type` `service_account`) and a disabled account (`kb-svc-retired`, `is_active` false), plus authentik's own accounts the read does not filter out. |
| `users_page2.json` | The terminating user page, `pagination.next` the integer `0`. Carries the cycle member `carol.cycle` and two degenerate display names (`nomad`, empty; and one whose username and name are both `...`). |
| `groups_page1.json` | First group page, `pagination.next` 2. `pk` is a uuid, `num_pk` the integer beside it. Carries the `kb-cyc-a` / `kb-cyc-b` cycle. |
| `groups_page2.json` | Terminating group page. Carries `kb-two-parents` (two entries in `parents`), and `kb-admission`, whose closure the golden derives. |

## The golden

`golden.json` is the desired state those four pages yield, corpus-local because
deriving it is IdP-agnostic work the planner already owns. Subjects are user
uuids; the population is the admission closure from `kb-admission`, so five of
the thirteen users and six of the eleven groups survive -- and every structural
case is among them (a held service account, a held disabled account, two-level
nesting, a two-parent group, a cycle).

## The negatives

Two break the read's structure; two carry a bad value in a perfect envelope.
All four must yield a not-whole read and no snapshot.

| File | Class | The defect |
|---|---|---|
| `neg_torn_read_user_delete.json` | structural | A user page 2 to read against `users_page1`: `count` fell 13 to 12 because a page-1 user was deleted mid-read, and one row falls into neither page. The lower count is the detector. |
| `neg_torn_read_group_insert.json` | structural | A group page 2 to read against `groups_page1`: an insert with a lower-sorting uuid pushed `kb-filler-2` onto page 2, which the reader already held. `count` went **up**, so only the duplicate `pk` catches it. |
| `neg_uuid_noncanonical.json` | value | A perfect page-1 user read with one upper-cased uuid. `UUIDField` serializes uniformly, so this is a whole-population serialization change, not one bad user -- the cycle fails, no account is singled out. |
| `neg_dangling_member.json` | value | A perfect group page naming member `pk` 900, which no user page returns. A complete read has no races, so a dangling id is a signal. It can dangle in a group's `users` (here), a group's `children`, or a user's own `groups`. |

The partial-grant truncation is **not** here on purpose: a silently truncated
200 and an honest smaller 200 are the same bytes, so no fixture can express it.

## The error shapes

Five, and no 429 -- no throttle applies to an authenticated read. authentik
never returns 401, so a 403's `detail` string is the whole discriminator; the
three 403 bodies are byte-faithful to the recordings.

| File | Status | Meaning |
|---|---|---|
| `err_403_not_provided.json` | 403 | No `Authorization` header. |
| `err_403_token_invalid.json` | 403 | A bearer token naming no `Token` row -- a rejected credential, which must not count the cycle as a failure. |
| `err_403_no_permission.json` | 403 | A real token with no grant. The read is refused, not emptied: total loss is loud. |
| `err_503_starting.json` | 503 | Hand-authored -- unrecordable on this stack, which runs no reverse proxy. Reachability, not a verdict. |
| `err_non_json_body.json` | 502 | Hand-authored -- a reverse proxy's HTML error page, `text/html`, body unparseable as JSON. Reachability, not a malformed directory (IdP). |

Every identifier here is synthetic.

## The self-scoped token reads

Two, for the sync credential's own expiry -- the `credential_state` measurement
and the `check --online` `credential expiry` leg. `GET /core/tokens/?intent=api`
is self-scoped through `TokenViewSet.owner_field = "user"` with zero grants, and
`key` is absent from the serializer, so the read measures the expiry while being
structurally unable to read the secret. The soonest expiring token binds the
headroom.

| File | What it pins |
|---|---|
| `tokens_self_api.json` | 200, two api-intent tokens, both `expiring`. The soonest deadline binds, so a surplus token further out cannot mask a nearer expiry. |
| `tokens_self_nonexpiring.json` | 200, one api-intent token, `expiring` false and `expires` a **junk** already-past value. A reader that trusted `expires` regardless of `expiring` would report a live credential as expired; the correct reading is no countdown. |

A refused token read is not a file of its own: it is the same 403 the directory
(IdP) read already pins -- authentik has no 401, so an expired, revoked, wrong or
app_password credential all answer one status, and the `check --online` legs name
that collapse apart in their own words.
