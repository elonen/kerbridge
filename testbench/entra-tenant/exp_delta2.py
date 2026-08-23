#!/usr/bin/env python3
"""Deletion lifecycle, 410 hunting, member-object-deletion caveat, throttling."""
import base64
import json
import time
import urllib.parse

import graph

cfg = json.load(open("config.json"))
d = json.load(open("directory.json"))
cur = json.load(open("cursors.json"))
ADMISSION, ENG, PROJX = d["admission_group_id"], d["groups"]["eng-team"], d["groups"]["proj-x"]
U = d["users"]
out = []
GSEL = "id,displayName,securityEnabled,mailEnabled,groupTypes,members"
USEL = "id,displayName,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled"


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


def admin(method, path, body=None):
    st, h, raw = graph.call(method, path, body)
    if st >= 400:
        print("  mutation failed", method, path, st, raw[:200])
    return st, raw


def drain(url):
    vals, pages = [], 0
    while True:
        st, h, j = app_get(url)
        pages += 1
        if st != 200:
            return vals, None, pages, (st, h, j)
        vals.extend(j.get("value", []))
        if "@odata.nextLink" in j:
            url = j["@odata.nextLink"]
            continue
        return vals, j.get("@odata.deltaLink"), pages, None


# ---------------------------------------------------- 410 hunting
tok = urllib.parse.parse_qs(urllib.parse.urlparse(cur["groups_cursor"]).query).get("$deltatoken", [""])[0]
rec("D6 real deltatoken shape", "length: %d\nprefix: %s…" % (len(tok), tok[:24]))

# (a) a well-formed groups token replayed against /users/delta
st, h, j = app_get("/v1.0/users/delta?$deltatoken=" + urllib.parse.quote(tok))
rec("D6a groups token used on /users/delta",
    "HTTP %s\nLocation: %s\nbody: %s" % (st, h.get("Location", "(none)"), json.dumps(j)[:300]))

# (b) structurally valid but mutated token (flip characters inside the blob)
mut = tok[:-8] + ("AAAAAAAA" if not tok.endswith("AAAAAAAA") else "BBBBBBBB")
st, h, j = app_get("/v1.0/groups/delta?$deltatoken=" + urllib.parse.quote(mut))
rec("D6b mutated (well-formed) deltatoken",
    "HTTP %s\nLocation: %s\nbody: %s" % (st, h.get("Location", "(none)"), json.dumps(j)[:300]))

# ---------------------------------------------------- member-object deletion caveat
# proj-x members: kb-bob, kb-dave-disabled(+SP). Delete kb-dave and see whether the
# membership removal shows up in proj-x members@delta (docs say it does NOT).
_, hh, jj = app_get("/v1.0/groups/delta?$select=%s&$deltatoken=latest" % GSEL)
gcur2 = jj.get("@odata.deltaLink")
_, hh, jj = app_get("/v1.0/users/delta?$select=%s&$deltatoken=latest" % USEL)
ucur2 = jj.get("@odata.deltaLink")

admin("DELETE", "/v1.0/users/%s" % U["kb-dave-disabled"])
print("deleted kb-dave-disabled; waiting")
time.sleep(45)

gv, gnew, _, _ = drain(gcur2)
uv, unew, _, _ = drain(ucur2)
rec("D7 user deletion -> users delta",
    json.dumps(uv, indent=2))
rec("D7b user deletion -> groups delta (does proj-x report the membership loss?)",
    "groups reported: %d\n%s" % (len(gv), json.dumps(gv, indent=2)))

st, h, j = app_get("/v1.0/directory/deletedItems/microsoft.graph.user?$select=id,displayName,userPrincipalName,accountEnabled,deletedDateTime")
rec("D7c deletedItems/user", "HTTP %s\n%s" % (st, json.dumps(j.get("value", j), indent=2)))

# ---------------------------------------------------- group soft delete + restore
_, hh, jj = app_get("/v1.0/groups/delta?$select=%s&$deltatoken=latest" % GSEL)
gcur3 = jj.get("@odata.deltaLink")
admin("DELETE", "/v1.0/groups/%s" % PROJX)
print("soft-deleted proj-x; waiting")
time.sleep(45)

gv, gnew3, _, _ = drain(gcur3)
rec("D8 group soft delete -> groups delta @removed reason", json.dumps(gv, indent=2))

st, h, j = app_get("/v1.0/directory/deletedItems/microsoft.graph.group?$select=id,displayName,securityEnabled,mailEnabled,groupTypes,deletedDateTime")
rec("D8b deletedItems/group (securityEnabled gotcha check)", "HTTP %s\n%s" % (st, json.dumps(j.get("value", j), indent=2)))

# restore
_, hh, jj = app_get("/v1.0/groups/delta?$select=%s&$deltatoken=latest" % GSEL)
gcur4 = jj.get("@odata.deltaLink")
st, raw = admin("POST", "/v1.0/directory/deletedItems/%s/restore" % PROJX)
print("restore:", st)
time.sleep(45)
gv, gnew4, _, _ = drain(gcur4)
rec("D8c group restore -> groups delta", json.dumps(gv, indent=2))

st, h, j = app_get("/v1.0/groups/%s/members?$select=id,displayName" % PROJX)
rec("D8d proj-x members after restore", "HTTP %s\n%s" % (st, json.dumps(j.get("value", j), indent=2)))

open("evidence/delta_part2.txt", "w").write("\n".join(out))
json.dump({"groups_cursor": gnew4, "users_cursor": unew}, open("cursors.json", "w"), indent=2)
print("\nwrote evidence/delta_part2.txt")
