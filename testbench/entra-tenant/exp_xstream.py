#!/usr/bin/env python3
"""Decisive test: is a cross-stream delta cursor silently accepted, and does it
hide changes that the correct cursor reports?

Control = the correct users cursor. Only if the control reports the change and
the crossed cursor does not is the "silent no-op" claim justified.
"""
import json
import time
import urllib.parse

import graph

GSEL = "id,displayName,securityEnabled,mailEnabled,groupTypes,members"
USEL = "id,displayName,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled"
d = json.load(open("directory.json"))


def tok_of(link):
    return urllib.parse.parse_qs(urllib.parse.urlparse(link).query)["$deltatoken"][0]


def cursor(path, sel):
    st, h, raw = graph.call("GET", "%s?$select=%s&$deltatoken=latest" % (path, sel), use_app=True)
    return tok_of(json.loads(raw)["@odata.deltaLink"])


def poll(path, tok):
    st, h, raw = graph.call("GET", "%s?$deltatoken=%s" % (path, urllib.parse.quote(tok)), use_app=True)
    j = json.loads(raw)
    return st, [v.get("id") for v in j.get("value", [])]


gtok = cursor("/v1.0/groups/delta", GSEL)
utok = cursor("/v1.0/users/delta", USEL)
print("groups token == users token:", gtok == utok)

graph.call("PATCH", "/v1.0/users/%s" % d["users"]["kb-bob"], {"jobTitle": "xstream-probe-2"})
graph.call("PATCH", "/v1.0/groups/%s" % d["groups"]["eng-team"], {"description": "xstream-probe-2"})
print("mutations applied at", time.strftime("%H:%M:%S"))

for attempt in range(10):
    time.sleep(45)
    st_c, ids_c = poll("/v1.0/users/delta", utok)          # control: correct cursor
    st_x, ids_x = poll("/v1.0/users/delta", gtok)          # crossed: groups cursor
    st_g, ids_g = poll("/v1.0/groups/delta", gtok)         # groups stream, correct cursor
    print("t+%3ds | users/correct: HTTP %s %s | users/crossed: HTTP %s %s | groups/correct: HTTP %s %s"
          % ((attempt + 1) * 45, st_c, ids_c, st_x, ids_x, st_g, ids_g))
    if ids_c:
        break

print("\nkb-bob   =", d["users"]["kb-bob"])
print("eng-team =", d["groups"]["eng-team"])
print("\nVERDICT: control reported change = %s ; crossed cursor reported change = %s"
      % (bool(ids_c), bool(ids_x)))
