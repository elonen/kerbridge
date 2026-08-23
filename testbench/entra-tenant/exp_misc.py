#!/usr/bin/env python3
"""Remaining sync checks: SP membership after restore, delta paging, throttling."""
import json
import time

import graph

d = json.load(open("directory.json"))
PROJX = d["groups"]["proj-x"]
GSEL = "id,displayName,securityEnabled,mailEnabled,groupTypes,members"
out = []


def rec(title, body):
    print("\n=== %s ===" % title)
    print(body)
    out.append("=== %s ===\n%s\n" % (title, body))


def app_get(path):
    st, h, raw = graph.call("GET", path, use_app=True)
    try:
        return st, h, json.loads(raw)
    except json.JSONDecodeError:
        return st, h, raw


# M1: is the servicePrincipal still a member after soft-delete + restore?
st, h, j = app_get("/v1.0/groups/%s/members/microsoft.graph.servicePrincipal?$select=id,appDisplayName" % PROJX)
rec("M1 proj-x servicePrincipal members after restore (cast query)",
    "HTTP %s\ncount: %s\n%s" % (st, len(j.get("value", [])), json.dumps(j.get("value", j), indent=2)))

st, h, j = app_get("/v1.0/groups/%s/members?$select=id,displayName" % PROJX)
rec("M1b proj-x plain /members after restore",
    "HTTP %s\ncount: %s" % (st, len(j.get("value", []))))

# M2: delta paging with a small $top -- does one group's members split across pages?
st, h, j = app_get("/v1.0/groups/delta?$select=%s&$top=1" % GSEL)
pages, groups_seen, ids = 0, 0, []
url = "/v1.0/groups/delta?$select=%s&$top=1" % GSEL
while True:
    st, h, j = app_get(url)
    if st != 200:
        rec("M2 delta paging error", "HTTP %s %s" % (st, json.dumps(j)[:200]))
        break
    pages += 1
    for v in j.get("value", []):
        groups_seen += 1
        ids.append((v.get("id"), len(v.get("members@delta", []))))
    if "@odata.nextLink" in j and pages < 25:
        url = j["@odata.nextLink"]
        continue
    break
dupes = [i for i in set(x[0] for x in ids) if sum(1 for y in ids if y[0] == i) > 1]
rec("M2 initial groups delta with $top=1",
    "pages: %d\nobject entries: %d\nper-entry (id, members@delta count): %s\nids appearing on >1 page: %s"
    % (pages, groups_seen, json.dumps(ids, indent=2), dupes or "none"))

# M3: throttling -- bounded burst, look for 429 + Retry-After
codes = {}
retry_after = None
t0 = time.time()
N = 400
for i in range(N):
    st, h, raw = graph.call("GET", "/v1.0/groups/%s?$select=id" % PROJX, use_app=True)
    codes[st] = codes.get(st, 0) + 1
    if st == 429:
        retry_after = h.get("Retry-After")
        break
el = time.time() - t0
rec("M3 throttling burst",
    "requests issued: %d in %.1fs (%.1f req/s)\nstatus counts: %s\n429 seen: %s\nRetry-After: %s"
    % (sum(codes.values()), el, sum(codes.values()) / el, codes, 429 in codes, retry_after or "n/a"))

open("evidence/misc.txt", "w").write("\n".join(out))
print("\nwrote evidence/misc.txt")
