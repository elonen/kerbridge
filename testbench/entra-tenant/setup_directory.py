#!/usr/bin/env python3
"""Build the Entra object zoo the sync spike's live follow-ups need.

Admission group + nesting + allowlist group + duplicate-name pair + M365 group +
member users + a guest (no invitation mail is sent) + an SP group member.
Object ids land in directory.json; generated passwords in secrets/users.json.
"""
import json
import os
import secrets as pysecrets
import string
import sys

import graph

cfg = json.load(open("config.json"))
DOM = cfg["primary_domain"]
state = {"users": {}, "groups": {}}


def g(method, path, body=None, tolerate=False):
    st, h, raw = graph.call(method, path, body)
    if st >= 400:
        if tolerate:
            return {"__error__": json.loads(raw) if raw.strip() else {}, "__status__": st}
        print("FAIL", method, path, st, raw[:800])
        sys.exit(1)
    return json.loads(raw) if raw.strip() else {}


# Entra accepts a password carrying three of its four character categories, and
# a 24-character draw over this alphabet met that by chance rather than by
# construction: 144 of 200 000 simulated draws hold only two, about one in 1400,
# and a run creates four users. Rare enough that the rejection would arrive as a
# Graph error nobody reads as a generator fault. The affix carries all four
# categories itself, so the draw cannot fail the rule; it costs no strength,
# because the random half is the whole of the entropy either way. Same rule as
# kerbridge_core::password, arrived at separately -- this is a tenant's policy,
# not the realm's, and nothing here can reach that crate.
def pw():
    alpha = string.ascii_letters + string.digits + "!@#$%^&*"
    return "Kb1!" + "".join(pysecrets.choice(alpha) for _ in range(24))


passwords = {}


def mkuser(nick, display, enabled=True):
    p = pw()
    u = g(
        "POST",
        "/v1.0/users",
        {
            "accountEnabled": enabled,
            "displayName": display,
            "mailNickname": nick,
            "userPrincipalName": "%s@%s" % (nick, DOM),
            "passwordProfile": {"forceChangePasswordNextSignIn": False, "password": p},
        },
    )
    passwords[u["userPrincipalName"]] = p
    state["users"][nick] = u["id"]
    print("user  %-14s %s" % (nick, u["id"]))
    return u


def mkgroup(nick, display, unified=False, security=True):
    body = {
        "displayName": display,
        "mailNickname": nick,
        "mailEnabled": unified,
        "securityEnabled": security,
        "groupTypes": ["Unified"] if unified else [],
    }
    gr = g("POST", "/v1.0/groups", body)
    state["groups"].setdefault(nick, []).append(gr["id"])
    print("group %-14s %s%s" % (nick, gr["id"], " (unified)" if unified else ""))
    return gr


def add_member(group_id, obj_id):
    g(
        "POST",
        "/v1.0/groups/%s/members/$ref" % group_id,
        {"@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/%s" % obj_id},
    )


# --- users -------------------------------------------------------------
u1 = mkuser("kb-alice", "KB Alice")
u2 = mkuser("kb-bob", "KB Bob")
u3 = mkuser("kb-carol", "KB Carol")
u4 = mkuser("kb-dave-disabled", "KB Dave (disabled)", enabled=False)

# guest: sendInvitationMessage defaults to false -> no mail leaves the tenant
inv = g(
    "POST",
    "/v1.0/invitations",
    {
        "invitedUserEmailAddress": "kb-guest@example.com",
        "invitedUserDisplayName": "KB Guest",
        "inviteRedirectUrl": "https://example.com/",
        "sendInvitationMessage": False,
    },
)
state["users"]["kb-guest"] = inv["invitedUser"]["id"]
print("guest %-14s %s" % ("kb-guest", inv["invitedUser"]["id"]))

# --- groups ------------------------------------------------------------
admission = mkgroup("onprem-realm-users", "onprem-realm-users")
eng = mkgroup("eng-team", "eng-team")
sub = mkgroup("eng-backend", "eng-backend")
projx = mkgroup("proj-x", "proj-x")
dup1 = mkgroup("kb-dup-a", "kb-duplicate-name")
dup2 = mkgroup("kb-dup-b", "kb-duplicate-name")
m365 = mkgroup("kb-collab", "kb-collab", unified=True)

# nesting: admission group <- eng-team <- eng-backend ; users spread across levels
add_member(admission["id"], u1["id"])
add_member(admission["id"], eng["id"])
add_member(eng["id"], u2["id"])
add_member(eng["id"], sub["id"])
add_member(sub["id"], u3["id"])
add_member(admission["id"], state["users"]["kb-guest"])
add_member(projx["id"], u1["id"])
add_member(projx["id"], u4["id"])

# service principal as a group member (v1.0 /members omission check)
add_member(projx["id"], cfg["sync_sp_id"])
print("added sync SP as member of proj-x")

# distribution list / dynamic group: expected to fail on this tenant
dl = g(
    "POST",
    "/v1.0/groups",
    {"displayName": "kb-distlist", "mailNickname": "kb-distlist", "mailEnabled": True, "securityEnabled": False},
    tolerate=True,
)
print("distribution list attempt:", json.dumps(dl.get("__error__", {}).get("error", {}).get("message", "CREATED"))[:200])

dyn = g(
    "POST",
    "/v1.0/groups",
    {
        "displayName": "kb-dynamic",
        "mailNickname": "kb-dynamic",
        "mailEnabled": False,
        "securityEnabled": True,
        "groupTypes": ["DynamicMembership"],
        "membershipRule": '(user.department -eq "eng")',
        "membershipRuleProcessingState": "On",
    },
    tolerate=True,
)
if "__error__" in dyn:
    print("dynamic group attempt:", json.dumps(dyn["__error__"].get("error", {}).get("message", ""))[:300])
else:
    state["groups"]["kb-dynamic"] = [dyn["id"]]
    print("dynamic group CREATED", dyn["id"])

state["admission_group_id"] = admission["id"]
json.dump(state, open("directory.json", "w"), indent=2)
with open(os.path.join("secrets", "users.json"), "w") as f:
    json.dump(passwords, f, indent=2)
os.chmod(os.path.join("secrets", "users.json"), 0o600)
print("\nwrote directory.json + secrets/users.json")
