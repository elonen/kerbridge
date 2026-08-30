#!/usr/bin/env python3
"""Record a real authentik IdP directory read, and settle the two ordering questions.

    cd testbench/authentik && ./authcode.sh up      # the stack, once
    python3 capture_directory.py                    # seed, measure, record

This is a RECORDER, not a generator. Every file it writes under `captured/` is
bytes an authentik answered on this machine -- status line, response headers and
body verbatim -- in the recorded-shape envelope
`{note, request, response{status, headers, body}}` that
`testbench/fixtures/graph-sync/make_fixtures.py:57-64` defines and
`entra/wire/tests.rs:8-13` and `entra/client.rs:438-444` already read. Nothing
here is authored to a documented shape. Where a shape could not be produced
against a real server, the run says so and writes no file rather than inventing
one.

MEASURED against ghcr.io/goauthentik/server:2026.8.0, the same image
`compose.authentik.yaml` pins. It seeds its own cast, so it wipes and re-creates
every object it owns on each run. What a re-record reproduces is the
MEASUREMENTS, not the pages: the group stream sorts by a server-generated uuid,
so which group lands on which page is a fresh draw, and the group-insert probe
may take any number of tries or none that work.
`testbench/authentik/captured/README.md` states the invariants that do hold.

The cast includes a service account held by the admission group, a disabled
service account, a two-level nesting, a group
with two parents, a `cyc-a`/`cyc-b` cycle, and users whose display names are
degenerate. It also seeds fillers, so that a page size well below the measured
`page_size=100` splits the read in two and the terminating page is recorded
rather than described.
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("AK_BASE", "http://127.0.0.1:9000")
ADMIN_TOKEN = os.environ.get("AK_BOOTSTRAP_TOKEN", "kerbridge-bench-bootstrap-token")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captured")

# Below the measured page size of 100, and the only parameter that
# differs from the real read: 13 users and 11 groups will not split at 100, and
# a corpus that never records the terminating page cannot pin `next: 0`.
USER_PAGE_SIZE = 10
GROUP_PAGE_SIZE = 8

# The production read, without its page size. `include_groups`/`include_users`
# default to TRUE in the schema, so both must be passed explicitly or every row
# carries an embedded object graph the adapter does not read.
USER_QUERY = "ordering=pk&include_groups=false&include_roles=false"
GROUP_QUERY = "ordering=pk&include_users=false"

# The proxy in this sandbox does not reach the sandbox's own loopback, and
# urllib honours the environment's proxy variables where curl was already
# bypassing them.
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


# --- transport --------------------------------------------------------------


def call(method, path, token=ADMIN_TOKEN, body=None, headers=None):
    """One HTTP exchange, returned whole: status, every response header, body.

    Errors are values here, not exceptions: a 403 is the point of half these
    calls, and `urlopen` raising on one would put the bytes this script exists
    to record inside an exception's `read()`.
    """
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if token is not None:
        req.add_header("Authorization", "Bearer " + token)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        r = OPENER.open(req)
        status, hdrs, raw = r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        status, hdrs, raw = e.code, e.headers, e.read()
    text = raw.decode("utf-8", "replace")
    try:
        parsed = json.loads(text) if text else None
    except json.JSONDecodeError:
        parsed = None
    return {
        "url": url,
        "method": method,
        "status": status,
        "headers": {k: v for k, v in hdrs.items()},
        "body": parsed,
        "text": text,
    }


def ok(ex, want=(200, 201, 204)):
    if ex["status"] not in want:
        sys.exit("FAIL: %s %s -> %s\n%s" % (ex["method"], ex["url"], ex["status"], ex["text"][:400]))
    return ex["body"]


def ok_ex(ex, want=(200, 201, 204)):
    ok(ex, want)
    return ex


def record(name, note, ex):
    """Write one exchange in the recorded shape the Rust readers already parse.

    `body` is the parsed JSON where the server sent JSON, and the raw string
    where it did not -- a reverse proxy's HTML page is a case the corpus wants,
    and stringifying it is the only way a JSON fixture can carry it.
    """
    obj = {
        "note": note,
        "request": {"method": ex["method"], "url": ex["url"]},
        "response": {
            "status": ex["status"],
            "headers": ex["headers"],
            "body": ex["body"] if ex["body"] is not None else ex["text"],
        },
    }
    with open(os.path.join(OUT, name + ".json"), "w") as f:
        json.dump(obj, f, indent=2, sort_keys=False)
        f.write("\n")
    print("  wrote captured/%s.json  (%s, %d bytes)" % (name, ex["status"], len(ex["text"])))


def say(msg):
    print("\n== %s" % msg)


# --- the cast ---------------------------------------------------------------

# Fillers first, so the seeded cast straddles the page boundary: with
# USER_PAGE_SIZE=10 and authentik's own three accounts already there, page 1
# ends inside the cast and page 2 carries the degenerate names. The torn-read
# experiment below needs an expendable row on PAGE 1, and only this ordering
# puts one there.
FILLERS = ["dave.filler", "erin.filler", "frank.filler"]

USERS = [
    # (username, name, email, type, is_active)
    ("dave.filler", "Dave Filler", "dave.filler@bench.invalid", "internal", True),
    ("erin.filler", "Erin Filler", "erin.filler@bench.invalid", "internal", True),
    ("frank.filler", "Frank Filler", "frank.filler@bench.invalid", "internal", True),
    ("ada.lovelace", "Ada Lovelace", "ada.lovelace@bench.invalid", "internal", True),
    # authentik account type does not control admission. This service account is
    # admitted because the admission group holds it.
    ("kb-svc-sync", "Kerbridge Sync Collector", "", "service_account", True),
    # `is_active` is independent of type: a disabled service account still
    # arrives in the read rather than disappearing from it.
    ("kb-svc-retired", "Retired Collector", "", "service_account", False),
    ("bob.nested", "Bob Nested", "bob.nested@bench.invalid", "internal", True),
    ("carol.cycle", "Carol Cycle", "carol.cycle@bench.invalid", "internal", True),
    # name and email empty, so the candidate list is [username] alone.
    ("nomad", "", "", "internal", True),
    # Everything sanitizes to nothing: `name_candidate` (sync/mod.rs:234-238)
    # answers None for all three, and the realm must name the account itself.
    ("...", "...", "", "internal", True),
]

# (name, parent names, member usernames)
GROUPS = [
    ("kb-admission", [], ["kb-svc-sync", "ada.lovelace"]),
    ("kb-mid", ["kb-admission"], []),
    ("kb-inner", ["kb-mid"], ["bob.nested"]),
    # The DAG case: one group, two selected parents, and it must appear once.
    ("kb-two-parents", ["kb-admission", "kb-mid"], ["kb-svc-retired"]),
    ("kb-cyc-a", ["kb-admission"], ["carol.cycle"]),
    ("kb-cyc-b", ["kb-cyc-a"], []),
    ("kb-filler-1", [], []),
    ("kb-filler-2", [], []),
]

# Every ordering value worth asking about on each stream, honoured or not.
FIELDS = {
    "users": ["pk", "uuid", "username", "name", "email", "date_joined",
              "last_updated", "is_active", "type"],
    "groups": ["pk", "num_pk", "group_uuid", "name", "is_superuser"],
}

CAST_USERNAMES = [u[0] for u in USERS]
CAST_GROUPNAMES = [g[0] for g in GROUPS]


# The one host `wipe` may run against. Every other object it removes is named
# `kb-*` or `zz-*`, but the cast is not: the corpus records the names a real
# IdP directory carries, degenerate ones included, so those users are deleted by
# exact username. `AK_BASE` exists to point this recorder at another instance,
# and pointing it at one that has an `ada.lovelace` would delete them.
WIPEABLE = ("http://127.0.0.1:9000", "http://localhost:9000")


def wipe():
    if BASE not in WIPEABLE:
        sys.exit(
            "FAIL: AK_BASE is %s, and this run would delete users by exact username\n"
            "      (%s) there. Point it at %s, the stack `authcode.sh up` starts."
            % (BASE, ", ".join(CAST_USERNAMES[:3]) + ", ...", WIPEABLE[0])
        )
    say("removing anything a previous run left behind")
    for name in list_all("/core/groups/", "name"):
        if name.startswith("kb-") or name.startswith("zz-"):
            pk = find("/core/groups/", "name", name)["pk"]
            ok(call("DELETE", "/api/v3/core/groups/%s/" % pk))
    for username in list_all("/core/users/", "username"):
        if username in CAST_USERNAMES or username.startswith("zz-") or username.startswith("kb-"):
            pk = find("/core/users/", "username", username)["pk"]
            ok(call("DELETE", "/api/v3/core/users/%d/" % pk))
    for role in ok(call("GET", "/api/v3/rbac/roles/?page_size=100"))["results"]:
        if role["name"].startswith("kb-"):
            ok(call("DELETE", "/api/v3/rbac/roles/%s/" % role["pk"]))
    for tok in ok(call("GET", "/api/v3/core/tokens/?page_size=100"))["results"]:
        if tok["identifier"].startswith("kb-"):
            ok(call("DELETE", "/api/v3/core/tokens/%s/" % tok["identifier"]))


def list_all(path, field):
    out, page = [], 1
    while page:
        body = ok(call("GET", "/api/v3%s?page_size=100&page=%d" % (path, page)))
        out += [r[field] for r in body["results"]]
        page = body["pagination"]["next"]
    return out


def find(path, field, value):
    body = ok(call("GET", "/api/v3%s?%s=%s" % (path, field, urllib.parse.quote(str(value)))))
    hits = [r for r in body["results"] if str(r[field]) == str(value)]
    return hits[0] if hits else None


def seed():
    say("seeding the cast")
    upk = {}
    for username, name, email, utype, active in USERS:
        body = {"username": username, "name": name, "email": email,
                "type": utype, "is_active": active, "path": "users"}
        ex = call("POST", "/api/v3/core/users/", body=body)
        if ex["status"] != 201:
            sys.exit("FAIL: authentik refused user %r: %s %s" % (username, ex["status"], ex["text"][:300]))
        upk[username] = ex["body"]["pk"]
        print("  user %-16s pk=%-4s uuid=%s" % (username, ex["body"]["pk"], ex["body"]["uuid"]))

    gpk = {}
    for name, parents, members in GROUPS:
        body = {"name": name,
                "parents": [gpk[p] for p in parents],
                "users": [upk[m] for m in members]}
        ex = call("POST", "/api/v3/core/groups/", body=body)
        if ex["status"] != 201:
            sys.exit("FAIL: authentik refused group %r: %s %s" % (name, ex["status"], ex["text"][:300]))
        gpk[name] = ex["body"]["pk"]
        print("  group %-16s pk=%s" % (name, ex["body"]["pk"]))

    # The cycle closes here and not in GROUPS, because kb-cyc-b does not exist
    # yet when kb-cyc-a is created. MEASURED: authentik accepts it. There is no
    # acyclicity check on `parents` at 2026.8.0 -- the mutual edge is written
    # and both groups list the other under `children`.
    ex = call("PATCH", "/api/v3/core/groups/%s/" % gpk["kb-cyc-a"],
              body={"parents": [gpk["kb-admission"], gpk["kb-cyc-b"]]})
    ok(ex)
    print("  cycle kb-cyc-a <-> kb-cyc-b accepted: parents=%s" % (ex["body"]["parents"],))
    return upk, gpk


# --- the read ---------------------------------------------------------------


def read_page(stream, page, page_size, query):
    return call("GET", "/api/v3/core/%s/?%s&page_size=%d&page=%d" % (stream, query, page_size, page))


def rows(ex, key):
    return [r[key] for r in ex["body"]["results"]]


def main():
    os.makedirs(OUT, exist_ok=True)

    version = ok(call("GET", "/api/v3/admin/version/"))
    say("authentik %s at %s" % (version["version_current"], BASE))

    wipe()
    upk, gpk = seed()

    # -----------------------------------------------------------------------
    # 1. the base read, both streams, both pages
    # -----------------------------------------------------------------------
    say("recording the base read")
    u1 = ok_ex(read_page("users", 1, USER_PAGE_SIZE, USER_QUERY))
    u2 = ok_ex(read_page("users", 2, USER_PAGE_SIZE, USER_QUERY))
    assert u1["body"]["pagination"]["next"] == 2, u1["body"]["pagination"]
    assert u2["body"]["pagination"]["next"] == 0, u2["body"]["pagination"]

    record("users_page1", "RECORDED. First page of the full user read. "
           "page_size is %d rather than the production value 100 to force a boundary. "
           "The rows are the cast: a service account, a disabled service account, an "
           "ordinary person, and (on page 2) the degenerate display names. "
           "authentik's own three accounts are here because they are: /core/users/ has "
           "no server-side filter the adapter asks for. Note `groups`: with "
           "include_groups=false the `groups_obj` OBJECTS go away but the uuid list "
           "stays, so the membership edge is readable from the user side as well as "
           "from the group's `users` array." % USER_PAGE_SIZE, u1)
    record("users_page2", "RECORDED. The TERMINATING page: pagination.next is the "
           "integer 0 -- not null, not a URL, not an absent key. This is the whole "
           "reason the page exists as a fixture, and it is the role "
           "groups_delta_init_page2 plays at entra/client.rs:488. `count` equals page "
           "1's; the torn recording below is the same read with a lower one.", u2)

    g1 = ok_ex(read_page("groups", 1, GROUP_PAGE_SIZE, GROUP_QUERY))
    g2 = ok_ex(read_page("groups", 2, GROUP_PAGE_SIZE, GROUP_QUERY))
    assert g1["body"]["pagination"]["next"] == 2, g1["body"]["pagination"]
    assert g2["body"]["pagination"]["next"] == 0, g2["body"]["pagination"]

    record("groups_page1", "RECORDED. First page of the full group read. Each row "
           "carries `pk` (a uuid), `num_pk` (an integer authentik keeps beside it), "
           "`name`, `parents`, `users` and `children`. With include_users=false the "
           "`*_obj` keys are present and NULL rather than absent -- the adapter must "
           "read `users`/`children`, never `users_obj`/`children_obj`.", g1)
    record("groups_page2", "RECORDED. Terminating group page, pagination.next: 0. "
           "Note kb-two-parents: two entries in `parents`, and the same edge readable "
           "from the other side as `children` on kb-admission and kb-mid. The DAG is "
           "recorded, not inferred.", g2)

    # -----------------------------------------------------------------------
    # 2. Q1 -- what does ?ordering=pk sort by, on each stream
    # -----------------------------------------------------------------------
    say("Q1: what ?ordering=pk sorts by")
    q1 = {}

    ua = ok(call("GET", "/api/v3/core/users/?%s&page_size=100" % USER_QUERY))["results"]
    ud = ok(call("GET", "/api/v3/core/users/?ordering=-pk&include_groups=false"
                        "&include_roles=false&page_size=100"))["results"]
    by_int = [r["pk"] for r in ua]
    by_uuid = [r["uuid"] for r in ua]
    q1["users"] = {
        "ordering_applies": [r["pk"] for r in ud] == list(reversed(by_int)),
        "sorted_by_integer_pk": by_int == sorted(by_int),
        "sorted_by_uuid": by_uuid == sorted(by_uuid),
        "sequence": [{"pk": r["pk"], "uuid": r["uuid"], "username": r["username"]} for r in ua],
    }

    ga = ok(call("GET", "/api/v3/core/groups/?%s&page_size=100" % GROUP_QUERY))["results"]
    gd = ok(call("GET", "/api/v3/core/groups/?ordering=-pk&include_users=false&page_size=100"))["results"]
    g_uuid = [r["pk"] for r in ga]
    g_int = [r["num_pk"] for r in ga]
    q1["groups"] = {
        "ordering_applies": [r["pk"] for r in gd] == list(reversed(g_uuid)),
        "sorted_by_uuid_pk": g_uuid == sorted(g_uuid),
        "sorted_by_num_pk": g_int == sorted(g_int),
        "sequence": [{"pk": r["pk"], "num_pk": r["num_pk"], "name": r["name"]} for r in ga],
    }
    for stream, m in q1.items():
        print("  %-7s ordering applies=%s  ascending-by-integer=%s  ascending-by-uuid=%s"
              % (stream, m["ordering_applies"],
                 m.get("sorted_by_integer_pk", m.get("sorted_by_num_pk")),
                 m.get("sorted_by_uuid", m.get("sorted_by_uuid_pk"))))

    # AND WHICH `ordering` VALUES THE SERVER ACTUALLY HONOURS, because it never
    # says. A field the filter does not allow is not a 400 -- it is SILENTLY
    # IGNORED, and the read falls back to the model's own Meta.ordering, which is
    # `username` for users and `name` for groups. Both are mutable and neither is
    # append-only, so a typo in this parameter downgrades the read to the least
    # stable sort there is and nothing in the response says so.
    def honoured(stream, key, query):
        base = [r[key] for r in ok(call("GET", "/api/v3/core/%s/?%s&page_size=100"
                                        % (stream, query)))["results"]]
        out = {}
        for field in FIELDS[stream]:
            asc = [r[key] for r in ok(call("GET", "/api/v3/core/%s/?%s&page_size=100&ordering=%s"
                                           % (stream, query, field)))["results"]]
            desc = [r[key] for r in ok(call("GET", "/api/v3/core/%s/?%s&page_size=100&ordering=-%s"
                                            % (stream, query, field)))["results"]]
            # Reversing is the only honest test: `ordering=name` on a stream
            # already defaulting to name is indistinguishable from being ignored.
            honoured = desc == list(reversed(asc)) and asc != desc
            ignored = asc == base and desc == base
            # A field with ties -- `type`, `is_active`, an empty `email` -- sorts
            # into an order the server does not reverse row-for-row, so neither
            # test settles it. Say inconclusive rather than pick one.
            out[field] = {"honoured": honoured, "ignored_falls_back_to_default": ignored,
                          "inconclusive_ties": not honoured and not ignored}
        return {"default_ordering": base, "fields": out}

    q1["users"]["ordering_param"] = honoured("users", "username", USER_QUERY.replace("ordering=pk&", ""))
    q1["groups"]["ordering_param"] = honoured("groups", "name", GROUP_QUERY.replace("ordering=pk&", ""))
    for stream in ("users", "groups"):
        fields = q1[stream]["ordering_param"]["fields"]
        print("  %-7s honoured: %s" % (stream, [f for f, v in fields.items() if v["honoured"]]))
        print("  %-7s ignored : %s" % (stream, [f for f, v in fields.items()
                                                if v["ignored_falls_back_to_default"]]))
        print("  %-7s ties     : %s" % (stream, [f for f, v in fields.items()
                                                 if v["inconclusive_ties"]]))

    # -----------------------------------------------------------------------
    # 3. what a mid-read INSERT does to each stream
    # -----------------------------------------------------------------------
    # The consequence Q1 exists for. A sort key that only ever grows cannot move
    # a row backwards across a boundary a reader has already passed, so an
    # insert is invisible to the rest of the read. A random sort key can land
    # anywhere, and a row that lands before the boundary pushes one that the
    # reader already has onto the next page -- a DUPLICATE, which is a different
    # fixture from the skip a delete produces.
    say("Q1's consequence: a user inserted between page 1 and page 2")
    page1_before = rows(u1, "pk")
    ok(call("POST", "/api/v3/core/users/",
            body={"username": "zz-inserted-mid-read", "name": "Zed Inserted",
                  "email": "", "type": "internal", "path": "users"}))
    u2_after_insert = read_page("users", 2, USER_PAGE_SIZE, USER_QUERY)
    ok(u2_after_insert)
    dup_users = sorted(set(page1_before) & set(rows(u2_after_insert, "pk")))
    print("  rows repeated across the boundary: %s" % (dup_users or "none"))
    record("users_insert_mid_read_page2",
           "RECORDED. Page 2 of the same read, after one user was created between "
           "the two requests. Rows repeated from page 1: %s. An integer pk only ever "
           "grows, so the new row appends and every earlier row keeps its index: an "
           "insert cannot produce a duplicate on this stream. `count` rises by one, "
           "which is the only trace." % (dup_users or "none"), u2_after_insert)

    zed = find("/core/users/", "username", "zz-inserted-mid-read")
    ok(call("DELETE", "/api/v3/core/users/%d/" % zed["pk"]))

    say("Q1's consequence: a group inserted between page 1 and page 2")
    # This experiment requires the random UUID sort key. Refuse a future
    # authentik version that sorts groups by `num_pk`.
    assert q1["groups"]["sorted_by_uuid_pk"], "groups are not ordered by their uuid pk"
    boundary = g1["body"]["results"][-1]["pk"]
    g_page1_before = rows(g1, "pk")
    made, landed_early = [], None
    # A group's pk is a server-generated random uuid, so where an insert lands
    # is a coin flip weighted by the boundary's position. Create until one lands
    # before it; every group made here is deleted below.
    for i in range(1, 25):
        ex = ok_ex(call("POST", "/api/v3/core/groups/", body={"name": "zz-insert-probe-%d" % i}))
        made.append(ex["body"]["pk"])
        if ex["body"]["pk"] < boundary:
            landed_early = ex["body"]["pk"]
            break
    g2_after_insert = ok_ex(read_page("groups", 2, GROUP_PAGE_SIZE, GROUP_QUERY))
    dup_groups = sorted(set(g_page1_before) & set(rows(g2_after_insert, "pk")))
    print("  inserted %d group(s); one sorted before the boundary: %s" % (len(made), landed_early))
    print("  rows repeated across the boundary: %s" % (dup_groups or "none"))
    if landed_early is None:
        print("  NO file written: %d inserts and none landed before the boundary" % len(made))
    else:
        record("groups_insert_mid_read_page2",
               "RECORDED, AND THIS IS THE ASYMMETRY. Page 2 of the group read after "
               "%d group(s) were created between the two requests, one of which (%s) "
               "sorts BEFORE page 1's last row (%s). A group's pk IS its uuid -- "
               "random, not append-only -- so ?ordering=pk on /core/groups/ reorders "
               "on insert, and row(s) %s that the reader already holds come back on "
               "page 2. A count comparison does not catch this: `count` went UP, so "
               "the torn-read check that catches a delete passes here while the "
               "membership set the reader assembled is wrong."
               % (len(made), landed_early, boundary, dup_groups or "none"), g2_after_insert)
    for pk in made:
        ok(call("DELETE", "/api/v3/core/groups/%s/" % pk))

    # -----------------------------------------------------------------------
    # 4. the torn read that a DELETE produces
    # -----------------------------------------------------------------------
    say("a user deleted between page 1 and page 2")
    doomed = find("/core/users/", "username", "frank.filler")
    assert doomed["pk"] in page1_before, "the expendable row must be on page 1"
    ok(call("DELETE", "/api/v3/core/users/%d/" % doomed["pk"]))
    u2_torn = read_page("users", 2, USER_PAGE_SIZE, USER_QUERY)
    ok(u2_torn)
    skipped = sorted(set(rows(u2, "pk")) - set(rows(u2_torn, "pk")) - {doomed["pk"]})
    print("  count %d -> %d; rows on the first page 2 that this one never shows: %s"
          % (u2["body"]["pagination"]["count"], u2_torn["body"]["pagination"]["count"], skipped))
    record("users_torn_page2",
           "RECORDED. Page 2 after user %d (frank.filler) was deleted between the two "
           "requests. `count` is %d against page 1's %d, and rows %s are in NEITHER "
           "page the reader holds: every row after the deleted one shifted back by "
           "one index, so the boundary moved past them. The lower count is the "
           "detectable half, and the skipped row "
           "is what it protects against. Expect SourceError::NotWhole, never a "
           "snapshot missing a user."
           % (doomed["pk"], u2_torn["body"]["pagination"]["count"],
              u2["body"]["pagination"]["count"], skipped), u2_torn)

    # -----------------------------------------------------------------------
    # 5. the three 403 bodies, and the fourth answer that is not a 403
    # -----------------------------------------------------------------------
    say("the refusals")
    no_header = call("GET", "/api/v3/core/users/?page_size=1", token=None)
    record("err_403_not_provided",
           "RECORDED with no Authorization header at all. 403, not 401 -- authentik "
           "has no 401 anywhere in its schema, and the schema for "
           "/core/users/ documents exactly two failures, 400 and 403. A classifier "
           "keyed on the status collapses this with the two below; the `detail` "
           "string is the entire discriminator.", no_header)

    bad_token = call("GET", "/api/v3/core/users/?page_size=1", token="not-a-real-token-at-all")
    record("err_403_token_invalid",
           "RECORDED with a syntactically fine bearer token that names no Token row. "
           "Same status, same content type, different `detail`. This is the one that "
           "must map to SourceError::CredentialRejected so it does not count against "
           "the source (sync/mod.rs:96-100): the credential is dead, the server is "
           "healthy, and the operator's problem is a rotation, not an outage.", bad_token)

    # A real account with a real, valid token and no permission of any kind. The
    # third body, and the one that cannot be produced by fiddling with headers.
    unpriv = ok(call("POST", "/api/v3/core/users/",
                     body={"username": "kb-svc-unprivileged", "name": "Unprivileged Collector",
                           "email": "", "type": "service_account", "path": "users"}))
    ok(call("POST", "/api/v3/core/tokens/",
            body={"identifier": "kb-unprivileged-token", "intent": "api",
                  "user": unpriv["pk"], "description": "IdP directory capture", "expiring": False}))
    unpriv_key = ok(call("GET", "/api/v3/core/tokens/kb-unprivileged-token/view_key/"))["key"]
    no_perm = call("GET", "/api/v3/core/users/?%s&page_size=%d&page=1" % (USER_QUERY, USER_PAGE_SIZE),
                   token=unpriv_key)
    record("err_403_no_permission",
           "RECORDED as a real service account holding a real, valid api-intent token "
           "and not one permission. THE READ IS REFUSED, NOT EMPTIED: a credential "
           "with nothing granted gets this 403 rather than a well-formed 200 holding "
           "zero users. That is worth more than the body string -- it means the "
           "total-loss case is loud. The partial case below is the quiet one.", no_perm)

    # -----------------------------------------------------------------------
    # 6. Q2 -- is pagination.count computed before or after object filtering
    # -----------------------------------------------------------------------
    say("Q2: pagination.count against a partial object-permission grant")
    role = ok(call("POST", "/api/v3/rbac/roles/", body={"name": "kb-partial-reader"}))
    ok(call("POST", "/api/v3/rbac/roles/%s/add_user/" % role["pk"], body={"pk": unpriv["pk"]}))
    granted = [upk["ada.lovelace"], upk["bob.nested"]]
    for pk in granted:
        ok(call("POST", "/api/v3/rbac/permissions/assigned_by_roles/%s/assign/" % role["pk"],
                body={"permissions": ["authentik_core.view_user"],
                      "model": "authentik_core.user", "object_pk": str(pk)}))
    partial = call("GET", "/api/v3/core/users/?%s&page_size=100" % USER_QUERY, token=unpriv_key)
    ok(partial)
    pag = partial["body"]["pagination"]
    whole = ok(call("GET", "/api/v3/core/users/?%s&page_size=100" % USER_QUERY))["pagination"]
    q2 = {
        "granted_object_pks": granted,
        "rows_returned": len(partial["body"]["results"]),
        "pagination_count_seen_by_the_grantee": pag["count"],
        "pagination_count_seen_by_an_admin": whole["count"],
        "counted_after_filtering": pag["count"] == len(partial["body"]["results"]),
        "self_consistent": pag["count"] == len(partial["body"]["results"]) and pag["next"] == 0,
    }
    print("  admin sees count=%d; the grantee sees count=%d over %d rows, next=%s"
          % (whole["count"], pag["count"], len(partial["body"]["results"]), pag["next"]))
    record("users_partial_grant_page1",
           "RECORDED against a credential granted authentik_core.view_user on exactly "
           "two user objects and nothing globally. 200. pagination.count is %d -- the "
           "size of the FILTERED set, not of the IdP directory (%d). The envelope is "
           "internally perfect: count matches the row count, total_pages is 1, next is "
           "0. Byte for byte this is indistinguishable from an honest read of a "
           "two-person IdP directory. A count cross-check is "
           "STRUCTURALLY BLIND to a partial grant and the corpus must not carry a case "
           "pretending otherwise." % (pag["count"], whole["count"]), partial)

    # The one detectable shadow: the grantee can still read the groups, whose
    # `users` arrays name people the user read will not return.
    ok(call("POST", "/api/v3/rbac/permissions/assigned_by_roles/%s/assign/" % role["pk"],
            body={"permissions": ["authentik_core.view_group"],
                  "model": "authentik_core.group", "object_pk": str(gpk["kb-admission"])}))
    groups_seen = ok_ex(call("GET", "/api/v3/core/groups/?%s&page_size=100" % GROUP_QUERY,
                             token=unpriv_key))
    visible_users = {r["pk"] for r in partial["body"]["results"]}
    dangling = sorted({m for g in groups_seen["body"]["results"]
                       for m in g["users"] if m not in visible_users})
    q2["dangling_member_ids_visible_to_the_grantee"] = dangling
    # The same edge from the other side, and it is NOT object-filtered: a row
    # the grantee may read names groups the grantee may not.
    readable_groups = {g["pk"] for g in groups_seen["body"]["results"]}
    q2["unreadable_group_ids_named_by_visible_users"] = sorted(
        {g for r in partial["body"]["results"] for g in r["groups"] if g not in readable_groups})
    record("groups_partial_grant_page1",
           "RECORDED with the same partially-granted credential, after granting "
           "view_group on the admission group only. The group rows name member ids "
           "(%s) that the user read above will not return. On a read that is complete "
           "by construction a dangling id cannot be ordering, so this -- not the count "
           "-- is the one detectable shadow of a partial grant, and it only shows where "
           "the grant cuts across a membership edge. It dangles in three places at "
           "once: `users`, `children`, and (in the user recording above) the visible "
           "users' own `groups` arrays, none of which the object filter touches."
           % (dangling or "none"), groups_seen)

    # -----------------------------------------------------------------------
    # 7. what could not be recorded
    # -----------------------------------------------------------------------
    say("shapes this run could not produce against a real server")
    unrecorded = []
    # A 503 with Retry-After is a startup/deployment shape, not something a
    # healthy stack will answer; a reverse proxy's HTML page needs a proxy this
    # compose file does not run. Both stay hand-authored, and saying so is the
    # point -- a recorder that quietly authored them would be a generator.
    # MEASURED, not assumed: `docker compose restart server` was raced with a
    # tight poll of /api/v3/core/users/ and every attempt came back with a
    # REFUSED CONNECTION, never a 503. Nothing listens on :9000 until the whole
    # server is up, so the `{"error": "authentik starting"}` body belongs to a
    # deployment with something else in front -- which is the same missing
    # component as the line below.
    unrecorded.append("err_503_starting: restarting the server container yields a "
                      "refused connection, never a 503. Measured, not assumed. On "
                      "2026.8.0 nothing answers on :9000 until the server is up, so "
                      "this shape needs the reverse proxy this stack does not run.")
    unrecorded.append("err_non_json_body: needs the operator's reverse proxy, which is "
                      "exactly the component this stack does not have.")
    for line in unrecorded:
        print("  - %s" % line)

    findings = {
        "authentik_version": version["version_current"],
        "base": BASE,
        "user_page_size": USER_PAGE_SIZE,
        "group_page_size": GROUP_PAGE_SIZE,
        "q1_ordering_pk": q1,
        "q1_insert_repeats_a_row": {"users": dup_users, "groups": dup_groups},
        "q2_pagination_count": q2,
        "not_recorded": unrecorded,
    }
    with open(os.path.join(OUT, "findings.json"), "w") as f:
        json.dump(findings, f, indent=2)
        f.write("\n")
    print("\n  wrote captured/findings.json")

    say("done")


if __name__ == "__main__":
    main()
