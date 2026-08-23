#!/usr/bin/env python3
"""Read-shape experiments against the live tenant.

All reads use the app-only kerbridge-sync token (User.Read.All +
Group.Read.All only) so the least-privilege decision is proven at the same time.
"""
import json

import graph

cfg = json.load(open("config.json"))
d = json.load(open("directory.json"))
ADMISSION = d["admission_group_id"]
PROJX = d["groups"]["proj-x"]
out = []


def rec(title, body):
    print("\n=== %s ===" % title)
    print(body)
    out.append("=== %s ===\n%s\n" % (title, body))


def app_get(path, headers=None):
    st, h, raw = graph.call("GET", path, use_app=True, headers=headers)
    try:
        return st, h, json.loads(raw)
    except json.JSONDecodeError:
        return st, h, raw


# E1: are accountEnabled/userType/onPremisesSyncEnabled returned without $select?
st, h, j = app_get("/v1.0/users?$top=3")
keys = sorted(j["value"][0].keys()) if st == 200 else j
rec(
    "E1 default /users projection (no $select)",
    "HTTP %s\nkeys returned: %s\naccountEnabled present: %s\nuserType present: %s\nonPremisesSyncEnabled present: %s"
    % (
        st,
        keys,
        "accountEnabled" in keys,
        "userType" in keys,
        "onPremisesSyncEnabled" in keys,
    ),
)

st, h, j = app_get(
    "/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled"
)
rec(
    "E1b /users WITH $select",
    "HTTP %s\n%s" % (st, json.dumps(j.get("value", j), indent=2)),
)

# E2: pagination shape
st, h, j = app_get("/v1.0/users?$select=id,displayName&$top=2")
nl = j.get("@odata.nextLink", "")
rec(
    "E2 pagination",
    "HTTP %s\npage size: %d\nhas @odata.nextLink: %s\nnextLink param: %s"
    % (st, len(j.get("value", [])), bool(nl), "$skiptoken" if "$skiptoken" in nl else nl[:120]),
)

# E3: $deltatoken=latest returns no resource data?
st, h, j = app_get("/v1.0/users/delta?$deltatoken=latest")
rec(
    "E3 users/delta?$deltatoken=latest",
    "HTTP %s\nvalue length: %s\nhas @odata.deltaLink: %s\nhas @odata.nextLink: %s"
    % (st, len(j.get("value", [])), "@odata.deltaLink" in j, "@odata.nextLink" in j),
)

# E10: transitive members of the admission group
st, h, j = app_get("/v1.0/groups/%s/transitiveMembers?$select=id,displayName,userType" % ADMISSION)
rec(
    "E10 admission-group transitiveMembers",
    "HTTP %s\n%s"
    % (st, json.dumps([{k: v for k, v in m.items() if k != "@odata.context"} for m in j.get("value", [])], indent=2)),
)

st, h, j = app_get("/v1.0/groups/%s/members?$select=id,displayName" % ADMISSION)
rec("E10b admission-group direct members", "HTTP %s\n%s" % (st, json.dumps(j.get("value", []), indent=2)))

# E11: display-name admission-group resolution + ambiguity, no ConsistencyLevel header
st, h, j = app_get("/v1.0/groups?$filter=displayName eq 'onprem-realm-users'&$select=id,displayName")
rec("E11 admission-group resolve by displayName (plain eq, no ConsistencyLevel)", "HTTP %s\n%s" % (st, json.dumps(j.get("value", j), indent=2)))

st, h, j = app_get("/v1.0/groups?$filter=displayName eq 'kb-duplicate-name'&$select=id,displayName")
rec(
    "E11b ambiguous displayName",
    "HTTP %s\nmatches: %d\n%s" % (st, len(j.get("value", [])), json.dumps(j.get("value", []), indent=2)),
)

# E12: does v1.0 /members list the service principal member?
st, h, j = app_get("/v1.0/groups/%s/members" % PROJX)
types = [(m.get("@odata.type"), m.get("id"), m.get("displayName")) for m in j.get("value", [])]
rec(
    "E12 proj-x /members (contains a servicePrincipal member)",
    "HTTP %s\nmembers returned: %d\n%s" % (st, len(types), json.dumps(types, indent=2)),
)

st, h, j = app_get("/v1.0/groups/%s/members/microsoft.graph.servicePrincipal" % PROJX)
rec("E12b /members/microsoft.graph.servicePrincipal cast", "HTTP %s\n%s" % (st, json.dumps(j, indent=2)[:600]))

st, h, j = app_get("/v1.0/groups/%s/transitiveMembers" % PROJX)
rec(
    "E12c proj-x /transitiveMembers @odata.type values",
    "HTTP %s\n%s"
    % (st, json.dumps([(m.get("@odata.type"), m.get("displayName")) for m in j.get("value", [])], indent=2)),
)

# E13: group object shape incl. the fields the planner reads
st, h, j = app_get(
    "/v1.0/groups?$select=id,displayName,securityEnabled,mailEnabled,groupTypes,membershipRule,membershipRuleProcessingState,onPremisesSyncEnabled"
)
rec("E13 group projection", "HTTP %s\n%s" % (st, json.dumps(j.get("value", j), indent=2)))

# E14: deleted-items read with Group.Read.All (permission boundary check)
st, h, j = app_get("/v1.0/directory/deletedItems/microsoft.graph.group")
rec("E14 deletedItems/group with Group.Read.All", "HTTP %s\n%s" % (st, json.dumps(j, indent=2)[:400]))

st, h, j = app_get("/v1.0/directory/deletedItems/microsoft.graph.user")
rec("E14b deletedItems/user with User.Read.All", "HTTP %s\n%s" % (st, json.dumps(j, indent=2)[:400]))

# E15: a write must be refused (proves read-only grant)
st, h, raw = graph.call(
    "PATCH", "/v1.0/groups/%s" % PROJX, {"description": "should not work"}, use_app=True
)
rec("E15 write attempt with read-only grant", "HTTP %s\n%s" % (st, raw[:300]))

open("evidence/graph_reads.txt", "w").write("\n".join(out))
print("\nwrote evidence/graph_reads.txt")
