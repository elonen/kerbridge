# A recorded authentik directory read

Bytes, recorded against `ghcr.io/goauthentik/server:2026.8.0` — the image
`../compose.authentik.yaml` pins — by `../capture_directory.py` on 2026-08-27.

**These are recordings, not the corpus.** Every file is one HTTP exchange the
way `testbench/fixtures/graph-sync/` already writes them —
`{note, request, response{status, headers, body}}` — so the readers at
`entra/wire/tests.rs:8-13` and `entra/client.rs:438-444` parse them unchanged.
They are not `testbench/fixtures/authentik-directory/`: they carry the full
response header block including per-request noise (`date`, `x-authentik-id`),
they are re-recorded whole on every run, and their uuids and integer ids differ
run to run. `testbench/fixtures/authentik-directory/` is *derived* from these,
trimmed and pinned; this directory is the evidence it is derived from.

Re-record with the stack up:

    cd testbench/authentik && ./authcode.sh up && python3 capture_directory.py

The script wipes and re-seeds every object it owns, so a second run reproduces
the *shapes* below and none of the identifiers.

## What is here

| File | Status | What it is evidence of |
|---|---|---|
| `users_page1.json` | 200 | First page of the full user read. The cast, as rows. |
| `users_page2.json` | 200 | The terminating page. `pagination.next` is the integer `0`. |
| `groups_page1.json` | 200 | First group page: `pk`, `num_pk`, `parents`, `users`, `children`. |
| `groups_page2.json` | 200 | Terminating group page, and the `cyc-a` ↔ `cyc-b` cycle. |
| `users_torn_page2.json` | 200 | Page 2 after a page-1 user was deleted mid-read: lower `count`, one row in neither page. |
| `users_insert_mid_read_page2.json` | 200 | Page 2 after a user was created mid-read. No row repeats. |
| `groups_insert_mid_read_page2.json` | 200 | Page 2 after a group was created mid-read. **A row repeats.** |
| `users_partial_grant_page1.json` | 200 | The read a partial object-permission grant returns. |
| `groups_partial_grant_page1.json` | 200 | The same credential's group read, dangling member ids and all. |
| `err_403_not_provided.json` | 403 | No `Authorization` header. |
| `err_403_token_invalid.json` | 403 | A bearer token naming no `Token` row. |
| `err_403_no_permission.json` | 403 | A real account with a real token and no permission. |
| `findings.json` | — | The measurements below, as data, from the run that wrote these files. |

The cast rides in the rows rather than in files of its own: a
`service_account` held by the admission group, a disabled (`is_active: false`)
service account, `kb-admission` → `kb-mid` → `kb-inner`, a `kb-two-parents`
group with two entries in `parents`, the `kb-cyc-a` ↔ `kb-cyc-b` cycle, a user
whose `name` and `email` are both empty, and a user whose username, name and
email are `"..."`, `"..."` and `""` — all three of which `name_candidate`
(`sync/mod.rs:234-238`) answers `None` for, since `sam::FALLBACK`'s own doc note
says `...` trims to nothing.

## Question 1 — what `?ordering=pk` sorts by

**It sorts by a different kind of key on each of the two streams, and the
parameter name hides that.**

| Stream | `pk` in the row | `?ordering=pk` sorts by | Append-only |
|---|---|---|---|
| `/core/users/` | integer (`2`, `4`, `6`, …) | that integer | **yes** |
| `/core/groups/` | uuid | that uuid, lexicographically | **no** |

A group carries an integer beside its uuid — `num_pk` — but it is not a
sequence: in `findings.json` the values arrive unordered and unrelated to
creation order, and `?ordering=num_pk` is not honoured anyway (below). So **the
group stream exposes no append-only sort key at all**.

Both answers are recorded rather than reasoned: `findings.json` holds the full
sorted sequence for each stream with the integer and the uuid beside every row,
and `ordering=-pk` reverses each one row-for-row.

### The consequence, measured rather than argued

`users_insert_mid_read_page2.json` and `groups_insert_mid_read_page2.json` are
the same experiment on the two streams: read page 1, create an object, read
page 2.

- **Users: no row repeats.** An integer pk only grows, the new row appends past
  the last page, and every row the reader already holds keeps its index.
- **Groups: a row repeats.** The recorded run created groups until one drew a
  uuid sorting before page 1's last row; that insert pushed a group the reader
  already had onto page 2, and the recording holds it twice.

So the torn-read case is **not symmetric**, and the derived corpus carries both
halves of it. The insert is also worse than the skip it sits beside: a delete
lowers `count`, which is the signal a count comparison keys on, while **an
insert raises it — so the count comparison passes while the reader's membership
set is wrong.**

### And a hazard neither question asked about

`?ordering=` fails **silently**. A value the filter does not allow is not a 400;
it is dropped, and the read falls back to the model's own default ordering —
`username` for users, `name` for groups. Both are mutable and neither is
append-only, so a typo in this one parameter downgrades the read to the least
stable sort available and nothing in the response says so.

| Stream | Honoured | Silently ignored |
|---|---|---|
| `/core/users/` | `pk`, `uuid`, `username`, `name`, `date_joined`, `last_updated` | — |
| `/core/groups/` | `pk`, `name` | `num_pk`, `group_uuid` |

(`email`, `is_active`, `type` and `is_superuser` sort with ties, so reversing
them does not settle whether the parameter was honoured. `findings.json` records
them as inconclusive rather than guessing.)

## Question 2 — is `pagination.count` computed before or after object filtering

**After. A count cross-check is structurally blind to a partial grant, and the
corpus must not carry a case pretending otherwise.**

`users_partial_grant_page1.json` is the read a credential holding
`authentik_core.view_user` on exactly two user objects — and nothing globally —
gets back. The directory holds 13 users. The response:

```
"pagination": {"next": 0, "previous": 0, "count": 2,
               "current": 1, "total_pages": 1, "start_index": 1, "end_index": 2}
```

`count` is the size of the filtered set. The envelope is internally perfect:
`count` matches the row count, `total_pages` is 1, `next` is `0`. Byte for byte
it is an honest read of a two-person directory. So a count cross-check cannot
tell a partial grant from a small directory, and the derived corpus carries no
case that pretends otherwise.

### Two things found while settling it, both worth more than the answer

**The total-loss case is loud.** `err_403_no_permission.json` was recorded as a
real service account with a real, valid api-intent token and not one permission
granted: the read comes back **403**, not a well-formed 200 holding zero users.
Truncation is quiet only once the credential has *some* grant. A credential that
loses its role entirely fails the read rather than retiring the population — the
freeze at `planner/mod.rs:412` is not the only thing standing between a revoked
grant and a wipe.

**The dangling id dangles in three places, not one.** With the same partial
credential granted `view_group` on the admission group only,
`groups_partial_grant_page1.json` shows the admission group naming both of its
members in `users`, one of which (`kb-svc-sync`) the credential's own user read
will not return, and naming three groups in `children` that it cannot read. The
object filter touches neither array. Nor does it touch the third: in
`users_partial_grant_page1.json` the *visible* users' own `groups` arrays name a
group uuid the credential cannot read. So the rule — any dangling id in a full
read is `NotWhole` — is confirmed against real bytes, and it has three
independent detectors rather than one.

## What could not be recorded, and why that is in this file

- **`err_503_starting`** — measured, not assumed: `docker compose restart server`
  was raced with a tight poll and every attempt came back with a **refused
  connection**, never a 503. On 2026.8.0 nothing answers on `:9000` until the
  server is up, so `{"error": "authentik starting"}` belongs to a deployment
  with a reverse proxy in front of it.
- **`err_non_json_body`** — needs the operator's reverse proxy, which is exactly
  the component this stack does not run.

Both stay hand-authored in `testbench/fixtures/authentik-directory/`, and the
`note` on each says so. The recorder writes no file it did not receive; a
recorder that quietly authored these two would be a generator wearing the wrong
name.
