#!/usr/bin/env python3
"""Groups + membership for the live follow-ups (users already exist).

Kept deliberately small: 6 groups, no new users. The existing tenant guest
(userType=Guest, #EXT# UPN) is reused instead of inviting one, since guest
invitations are blocked tenant-wide here.
"""
import json
import sys

import graph

cfg = json.load(open("config.json"))
state = json.load(open("directory.json")) if __import__("os").path.exists("directory.json") else {"users": {}, "groups": {}}
state.setdefault("groups", {})

# An object id names a real directory, so none is written here. directory.json
# (setup_directory.py wrote it) and config.json are both gitignored.
try:
    USERS = {n: state["users"][n] for n in
             ("kb-alice", "kb-bob", "kb-carol", "kb-dave-disabled")}
    GUEST_EXISTING = cfg["existing_guest_id"]  # userType=Guest, #EXT# UPN
    MEMBER_EXT = cfg["existing_member_ext_id"]  # Member with an #EXT# UPN
except KeyError as missing:
    sys.exit("%s absent -- run setup_directory.py first" % missing)
state["users"]["existing-guest"] = GUEST_EXISTING
state["users"]["existing-member-ext"] = MEMBER_EXT


def g(method, path, body=None, tolerate=False):
    st, h, raw = graph.call(method, path, body)
    if st >= 400:
        if tolerate:
            return {"__error__": json.loads(raw) if raw.strip() else {}, "__status__": st}
        print("FAIL", method, path, st, raw[:800])
        sys.exit(1)
    return json.loads(raw) if raw.strip() else {}


def mkgroup(nick, display, unified=False):
    gr = g(
        "POST",
        "/v1.0/groups",
        {
            "displayName": display,
            "mailNickname": nick,
            "mailEnabled": unified,
            "securityEnabled": not unified,
            "groupTypes": ["Unified"] if unified else [],
        },
    )
    state["groups"][nick] = gr["id"]
    print("group %-20s %s" % (nick, gr["id"]))
    return gr


def add_member(group_id, obj_id):
    r = g(
        "POST",
        "/v1.0/groups/%s/members/$ref" % group_id,
        {"@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/%s" % obj_id},
        tolerate=True,
    )
    if "__error__" in r:
        print("   add_member failed:", r["__error__"].get("error", {}).get("message", "")[:160])
    return r


admission = mkgroup("kb-admission", "KerBridge Allowed On-prem Users")
eng = mkgroup("eng-team", "eng-team")
projx = mkgroup("proj-x", "proj-x")
dup1 = mkgroup("kb-dup-a", "kb-duplicate-name")
dup2 = mkgroup("kb-dup-b", "kb-duplicate-name")
m365 = mkgroup("kb-collab", "kb-collab", unified=True)

# admission group <- alice, eng-team, existing guest ; eng-team <- carol  (2-level nesting)
add_member(admission["id"], USERS["kb-alice"])
add_member(admission["id"], eng["id"])
add_member(admission["id"], GUEST_EXISTING)
add_member(eng["id"], USERS["kb-carol"])
# proj-x: outside the admission group (allowlist case) + disabled user + a service principal
add_member(projx["id"], USERS["kb-bob"])
add_member(projx["id"], USERS["kb-dave-disabled"])
add_member(projx["id"], cfg["sync_sp_id"])

state["admission_group_id"] = admission["id"]
json.dump(state, open("directory.json", "w"), indent=2)
print("\nwrote directory.json")
