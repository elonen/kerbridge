#!/usr/bin/env python3
"""Delta-cycle experiments: cursor establishment, members@delta shapes,
soft/hard delete reasons, 410 handling, replay.

Reads use the app-only sync token; mutations use the delegated admin token.
"""
import json
import sys
import time

import graph

cfg = json.load(open("config.json"))
d = json.load(open("directory.json"))
ADMISSION = d["admission_group_id"]
ENG = d["groups"]["eng-team"]
PROJX = d["groups"]["proj-x"]
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
        print("  mutation failed", method, path, st, raw[:300])
    return st, raw


def drain(url, label, show_pages=False):
    """Follow nextLinks to the deltaLink; return (all_values, deltaLink, pages)."""
    vals, pages = [], 0
    while True:
        st, h, j = app_get(url)
        pages += 1
        if st != 200:
            return vals, None, pages, (st, j)
        vals.extend(j.get("value", []))
        if show_pages:
            print("   %s page %d: %d objects, next=%s delta=%s"
                  % (label, pages, len(j.get("value", [])),
                     "@odata.nextLink" in j, "@odata.deltaLink" in j))
        if "@odata.nextLink" in j:
            url = j["@odata.nextLink"]
            continue
        return vals, j.get("@odata.deltaLink"), pages, None


# ---------------------------------------------------------------- cursors
st, h, j = app_get("/v1.0/groups/delta?$select=%s&$deltatoken=latest" % GSEL)
gcursor = j.get("@odata.deltaLink")
rec("D1 groups delta cursor via $deltatoken=latest",
    "HTTP %s\nobjects returned: %d\ndeltaLink present: %s" % (st, len(j.get("value", [])), bool(gcursor)))

st, h, j = app_get("/v1.0/users/delta?$select=%s&$deltatoken=latest" % USEL)
ucursor = j.get("@odata.deltaLink")

# ---------------------------------------------------------------- mutations
admin("POST", "/v1.0/groups/%s/members/$ref" % ENG,
      {"@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/%s" % U["kb-bob"]})
admin("DELETE", "/v1.0/groups/%s/members/%s/$ref" % (ADMISSION, U["kb-alice"]))
admin("PATCH", "/v1.0/groups/%s" % ADMISSION, {"displayName": "KerBridge Allowed On-prem Users (renamed)"})
admin("PATCH", "/v1.0/users/%s" % U["kb-carol"], {"accountEnabled": False})
print("mutations applied; waiting for delta propagation")
time.sleep(45)

# ---------------------------------------------------------------- read delta
vals, newg, pages, err = drain(gcursor, "groups", show_pages=True)
rec("D2 groups delta after add/remove/rename",
    "pages: %d\nobjects: %d\n%s" % (pages, len(vals), json.dumps(vals, indent=2)))

vals_u, newu, pagesu, err = drain(ucursor, "users", show_pages=True)
rec("D3 users delta after disable",
    "pages: %d\n%s" % (pagesu, json.dumps(vals_u, indent=2)))

# ---------------------------------------------------------------- replay
vals2, _, _, _ = drain(gcursor, "groups-replay")
rec("D4 replay of the SAME deltaLink (idempotency)",
    "objects on replay: %d\nsame ids as first read: %s"
    % (len(vals2), sorted(v.get("id", "") for v in vals2) == sorted(v.get("id", "") for v in vals)))

# ---------------------------------------------------------------- 410 paths
st, h, j = app_get("/v1.0/groups/delta?$deltatoken=GARBAGE_TOKEN_VALUE")
loc = h.get("Location", "")
rec("D5 invalid $deltatoken",
    "HTTP %s\nLocation header: %s\nbody: %s" % (st, loc or "(none)", json.dumps(j)[:400]))

open("evidence/delta_part1.txt", "w").write("\n".join(out))
json.dump({"groups_cursor": newg, "users_cursor": newu}, open("cursors.json", "w"), indent=2)
print("\nwrote evidence/delta_part1.txt + cursors.json")
