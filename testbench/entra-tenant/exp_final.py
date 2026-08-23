#!/usr/bin/env python3
"""Member-vs-guest claim diff + device @odata.type confirmation."""
import base64
import json
import time
import uuid

import graph

cfg = json.load(open("config.json"))
d = json.load(open("directory.json"))
PROJX = d["groups"]["proj-x"]
out = []


def rec(title, body):
    print("\n=== %s ===" % title)
    print(body)
    out.append("=== %s ===\n%s\n" % (title, body))


def claims(path):
    t = json.load(open(path))["access_token"]
    p = t.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


g = claims("secrets/user_token_guest-admin.json")
m = claims("secrets/user_token_member.json")

keys = sorted(set(g) | set(m))
VOLATILE = {"aio", "rh", "uti", "sid", "exp", "iat", "nbf", "sub", "xms_ftd"}
IDENTIFYING = {"name", "preferred_username"}
rows = []
for k in keys:
    gv, mv = g.get(k, "(absent)"), m.get(k, "(absent)")
    if k in VOLATILE:
        gv = mv = "(volatile, omitted)"
    elif k in IDENTIFYING:
        gv = "(redacted)" if k in g else "(absent)"
        mv = "(redacted)" if k in m else "(absent)"
    rows.append("%-20s guest=%-58s member=%s" % (k, gv, mv))
rec("T3 member vs guest claim diff (sanitized)", "\n".join(rows))

rec(
    "T3b discriminator check",
    "same tid                : %s\n"
    "oid == resource-tenant object id: guest=%s member=%s\n"
    "acct claim present      : guest=%s member=%s\n"
    "email/upn claim present : guest=%s member=%s\n"
    "idp == iss              : guest=%s member=%s"
    % (
        g["tid"] == m["tid"],
        g["oid"] == d["users"]["existing-guest"],
        m["oid"] == d["users"]["existing-member-ext"],
        "acct" in g,
        "acct" in m,
        any(k in g for k in ("email", "upn")),
        any(k in m for k in ("email", "upn")),
        g.get("idp") == g["iss"],
        m.get("idp") == m["iss"],
    ),
)

# userType of each token subject, straight from the directory
for label, oid in [("guest token subject", g["oid"]), ("member token subject", m["oid"])]:
    st, h, raw = graph.call("GET", "/v1.0/users/%s?$select=id,userType,accountEnabled" % oid, use_app=True)
    j = json.loads(raw)
    rec("T3c %s directory lookup" % label,
        "userType=%s accountEnabled=%s" % (j.get("userType"), j.get("accountEnabled")))

# ---- device object type string -----------------------------------------
dev_id = str(uuid.uuid4())
st, h, raw = graph.call(
    "POST",
    "/v1.0/devices",
    {
        "accountEnabled": True,
        "displayName": "kb-test-device",
        "deviceId": dev_id,
        "operatingSystem": "Windows",
        "operatingSystemVersion": "10.0.22631",
        "alternativeSecurityIds": [{"type": 2, "key": base64.b64encode(b"kb-spike-test-device").decode()}],
    },
)
if st < 400:
    dev = json.loads(raw)
    graph.call(
        "POST",
        "/v1.0/groups/%s/members/$ref" % PROJX,
        {"@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/%s" % dev["id"]},
    )
    time.sleep(5)
    st2, h2, raw2 = graph.call("GET", "/v1.0/groups/%s/members" % PROJX, use_app=True)
    types = [(x.get("@odata.type"), x.get("displayName")) for x in json.loads(raw2).get("value", [])]
    st3, h3, raw3 = graph.call(
        "GET", "/v1.0/groups/%s/members/microsoft.graph.device?$select=id,displayName" % PROJX, use_app=True
    )
    rec("T4 device as group member",
        "device created: HTTP %s\nplain /members: %s\ndevice cast: HTTP %s %s"
        % (st, json.dumps(types), st3, raw3[:200]))
    graph.call("DELETE", "/v1.0/devices/%s" % dev["id"])
    print("device deleted")
else:
    rec("T4 device creation", "HTTP %s\n%s" % (st, raw[:400]))

open("evidence/final.txt", "w").write("\n".join(out))
print("\nwrote evidence/final.txt")
