#!/usr/bin/env python3
"""Generate recorded-style Microsoft Graph HTTP fixtures for kerbridge-sync tests.

Shapes follow current Graph v1.0 documentation (fetched 2026-07-21):
- delta:      https://learn.microsoft.com/en-us/graph/delta-query-overview
              https://learn.microsoft.com/en-us/graph/api/group-delta?view=graph-rest-1.0
              https://learn.microsoft.com/en-us/graph/delta-query-groups
- users:      https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0
- members:    https://learn.microsoft.com/en-us/graph/api/group-list-transitivemembers?view=graph-rest-1.0
- throttling: https://learn.microsoft.com/en-us/graph/throttling
- deleted:    https://learn.microsoft.com/en-us/graph/api/directory-deleteditems-list?view=graph-rest-1.0
Every fixture is a JSON object: {"request": {...}, "response": {"status": n, "headers": {...}, "body": {...}}}
so tests can replay complete HTTP exchanges. IDs match the objects provisioned in the
sync-spike Samba directory (tenant aaaabbbb-..., admission group 4e8a1c9d-...).
"""
import json, os

T = "aaaabbbb-0000-cccc-1111-dddd2222eeee"  # tenant id
G = "https://graph.microsoft.com/v1.0"
ADMISSION = "4e8a1c9d-5f6b-4d7e-b8a9-001122334455"
U_ALICE = "33334444-dddd-5555-eeee-6666ffff7777"
U_JDOE = "9f3a0002-aaaa-bbbb-cccc-000000000002"
U_JDOE2 = "8b210003-aaaa-bbbb-cccc-000000000003"
U_BOB = "b0b00004-aaaa-bbbb-cccc-000000000004"
U_CAROL = "ca201005-aaaa-bbbb-cccc-000000000005"
G_INNER = "61000006-aaaa-bbbb-cccc-000000000006"
G_MID = "a1d00007-aaaa-bbbb-cccc-000000000007"
G_CYCA = "c1c00008-aaaa-bbbb-cccc-000000000008"
G_CYCB = "c1c00009-aaaa-bbbb-cccc-000000000009"
G_PROJX = "77770001-aaaa-bbbb-cccc-000000000001"
U_GUEST = "9e570010-aaaa-bbbb-cccc-000000000010"
G_M365 = "0365aa11-aaaa-bbbb-cccc-000000000011"
G_DYN = "d1a2bb12-aaaa-bbbb-cccc-000000000012"
G_ONPREM = "0b9e4c13-aaaa-bbbb-cccc-000000000013"
DEV_1 = "de71ce14-aaaa-bbbb-cccc-000000000014"
SP_1 = "5e9f1015-aaaa-bbbb-cccc-000000000015"

USER_SELECT = "id,displayName,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled"
GROUP_SELECT = ("id,displayName,securityEnabled,mailEnabled,groupTypes,membershipRule,"
                "membershipRuleProcessingState,onPremisesSyncEnabled,members")

def user(oid, dn, upn, enabled=True, utype="Member", onprem=None):
    return {"id": oid, "displayName": dn, "userPrincipalName": upn,
            "accountEnabled": enabled, "userType": utype, "onPremisesSyncEnabled": onprem}

def group(gid, dn, sec=True, mail=False, gtypes=None, rule=None, rulestate=None, onprem=None):
    return {"id": gid, "displayName": dn, "securityEnabled": sec, "mailEnabled": mail,
            "groupTypes": gtypes or [], "membershipRule": rule,
            "membershipRuleProcessingState": rulestate, "onPremisesSyncEnabled": onprem}

def mref(t, oid, removed=False):
    d = {"@odata.type": f"#microsoft.graph.{t}", "id": oid}
    if removed:
        d["@removed"] = {"reason": "deleted"}   # membership removal reason per delta-query-groups
    return d

def fx(name, method, url, status, body, headers=None, note=None):
    hdrs = {"Content-Type": "application/json"} if body is not None else {}
    hdrs.update(headers or {})
    obj = {"note": note, "request": {"method": method, "url": url},
           "response": {"status": status, "headers": hdrs, "body": body}}
    with open(name + ".json", "w") as f:
        json.dump(obj, f, indent=2)
    print("wrote", name + ".json")

os.chdir(os.path.dirname(os.path.abspath(__file__)))

ALICE = user(U_ALICE, "Alice Anderson", "alice.anderson@contoso.example")
JDOE = user(U_JDOE, "John Doe", "jdoe@contoso.example")
JDOE2 = user(U_JDOE2, "John Doe", "john.doe2@contoso.example")
BOB = user(U_BOB, "Bob Nested", "bob.nested@contoso.example")
CAROL = user(U_CAROL, "Carol Cycle", "carol.cycle@contoso.example")
GUEST = user(U_GUEST, "Gary Guest", "gary_partner.example#EXT#@contoso.onmicrosoft.com", utype="Guest")

# --- 1. admission-group resolution by display name (bootstrap): exactly one --------------------
fx("admission_resolve_by_name", "GET",
   f"{G}/groups?$filter=displayName eq 'onprem-realm-users'&$select={GROUP_SELECT.replace(',members','')}",
   200,
   {"@odata.context": f"{G}/$metadata#groups", "value": [group(ADMISSION, "onprem-realm-users")]},
   note="Bootstrap-only display-name lookup. Plain eq filter needs no ConsistencyLevel header "
        "(group-list docs). Sync must require exactly one result.")

# --- 1b. ambiguous admission-group name: two results -> fail closed ----------------------------
fx("admission_resolve_ambiguous", "GET",
   f"{G}/groups?$filter=displayName eq 'onprem-realm-users'",
   200,
   {"@odata.context": f"{G}/$metadata#groups",
    "value": [group(ADMISSION, "onprem-realm-users"),
              group("dup1f0f0-aaaa-bbbb-cccc-0000000000ff", "onprem-realm-users")]},
   note="Two groups share the configured display name. Sync MUST abort bootstrap (fail closed).")

# --- 2. full user read, paginated ---------------------------------------------------
fx("full_users_page1", "GET", f"{G}/users?$select={USER_SELECT}", 200,
   {"@odata.context": f"{G}/$metadata#users({USER_SELECT})",
    "@odata.nextLink": f"{G}/users?$select={USER_SELECT}&$skiptoken=RFDU-page2-opaque",
    "value": [ALICE, JDOE, JDOE2]},
   note="accountEnabled/userType/onPremisesSyncEnabled require explicit $select (user resource docs).")
fx("full_users_page2", "GET", f"{G}/users?$select={USER_SELECT}&$skiptoken=RFDU-page2-opaque", 200,
   {"@odata.context": f"{G}/$metadata#users({USER_SELECT})",
    "value": [BOB, CAROL, GUEST]},
   note="Final page: no @odata.nextLink. A read is COMPLETE only when the last page arrived.")

# --- 3. groups delta: initial sync, paginated, members@delta ------------------------
fx("groups_delta_init_page1", "GET",
   f"{G}/groups/delta?$select={GROUP_SELECT}", 200,
   {"@odata.context": f"{G}/$metadata#groups", "@odata.nextLink":
    f"{G}/groups/delta?$skiptoken=ppqq-init-2",
    "value": [
      dict(group(ADMISSION, "onprem-realm-users"),
           **{"members@delta": [mref("user", U_ALICE), mref("user", U_JDOE), mref("user", U_JDOE2),
                                mref("group", G_MID), mref("group", G_CYCA)]}),
      dict(group(G_MID, "mid-group"), **{"members@delta": [mref("group", G_INNER)]}),
    ]},
   note="Initial delta page 1. members@delta carries only {@odata.type,id} per docs. "
        "The two John Does are admission-group members because an account exists only for a user a "
        "selected group holds; they are the colliding-display-name pair, and holding them "
        "is what keeps that collision in the corpus. Gary Guest is deliberately in no "
        "group at all: he is the eligible-but-unheld case.")
fx("groups_delta_init_page2", "GET", f"{G}/groups/delta?$skiptoken=ppqq-init-2", 200,
   {"@odata.context": f"{G}/$metadata#groups", "@odata.deltaLink":
    f"{G}/groups/delta?$deltatoken=tok-AAA1",
    "value": [
      dict(group(G_INNER, "inner-devs"), **{"members@delta": [mref("user", U_BOB)]}),
      dict(group(G_CYCA, "cyc-a"), **{"members@delta": [mref("group", G_CYCB)]}),
      dict(group(G_CYCB, "cyc-b"), **{"members@delta": [mref("group", G_CYCA), mref("user", U_CAROL)]}),
      dict(group(G_PROJX, "proj-x"), **{"members@delta": [mref("user", U_ALICE)]}),
    ]},
   note="Final init page: deltaLink replaces nextLink; a page never carries both.")

# --- 3b. same group split across two pages (documented large-group pattern) ---------
fx("groups_delta_split_group_p1", "GET", f"{G}/groups/delta?$select={GROUP_SELECT}", 200,
   {"@odata.nextLink": f"{G}/groups/delta?$skiptoken=split-2",
    "value": [dict(group(ADMISSION, "onprem-realm-users"),
                   **{"members@delta": [mref("user", U_ALICE)]})]},
   note="Large group slice 1 of 2: same group id repeats on the next page with more members. "
        "Merge locally; never treat one slice as the full member set.")
fx("groups_delta_split_group_p2", "GET", f"{G}/groups/delta?$skiptoken=split-2", 200,
   {"@odata.deltaLink": f"{G}/groups/delta?$deltatoken=tok-SPLIT",
    "value": [dict(group(ADMISSION, "onprem-realm-users"),
                   **{"members@delta": [mref("group", G_MID), mref("group", G_CYCA)]})]},
   note="Large group slice 2 of 2.")

# --- 4. steady-state delta: member add + member remove ------------------------------
fx("groups_delta_incr_add_remove", "GET", f"{G}/groups/delta?$deltatoken=tok-AAA1", 200,
   {"@odata.context": f"{G}/$metadata#groups", "@odata.deltaLink":
    f"{G}/groups/delta?$deltatoken=tok-AAA2",
    "value": [
      dict(group(ADMISSION, "onprem-realm-users"), **{"members@delta": [
          mref("user", U_JDOE),                 # added member: no annotation
          mref("user", U_ALICE, removed=True),  # removed member: @removed reason deleted
      ]})]},
   note='Removed membership uses "@removed":{"reason":"deleted"} INSIDE members@delta even though '
        'the user object still exists (delta-query-groups doc). Caveat: removal via deletion of the '
        'member object itself is NOT reported here - track user deletions from users delta.')

# --- 5. admission group renamed ----------------------------------------------------------------
fx("groups_delta_admission_group_renamed", "GET", f"{G}/groups/delta?$deltatoken=tok-AAA2", 200,
   {"@odata.deltaLink": f"{G}/groups/delta?$deltatoken=tok-AAA3",
    "value": [group(ADMISSION, "corp-realm-gate")]},
   note="Same immutable id, new displayName. Sync matches on id (identity attr), renames Samba "
        "object, role marker + SID unchanged.")

# --- 6. group deleted: soft (changed) and hard (deleted) ----------------------------
fx("groups_delta_group_softdeleted", "GET", f"{G}/groups/delta?$deltatoken=tok-AAA3", 200,
   {"@odata.deltaLink": f"{G}/groups/delta?$deltatoken=tok-AAA4",
    "value": [{"id": G_PROJX, "@removed": {"reason": "changed"}}]},
   note='reason "changed" = soft-deleted, restorable from /directory/deletedItems for 30 days. '
        'Cloud security group soft delete is in preview (groups-restore-deleted doc); sync must '
        'treat BOTH reasons as: quarantine now.')
fx("groups_delta_group_harddeleted", "GET", f"{G}/groups/delta?$deltatoken=tok-AAA4", 200,
   {"@odata.deltaLink": f"{G}/groups/delta?$deltatoken=tok-AAA5",
    "value": [{"id": G_PROJX, "@removed": {"reason": "deleted"}}]},
   note='reason "deleted" = permanently deleted, not restorable.')

# --- 7. user disabled / user deleted (users delta) ----------------------------------
fx("users_delta_user_disabled", "GET",
   f"{G}/users/delta?$select={USER_SELECT}&$deltatoken=tok-U1", 200,
   {"@odata.deltaLink": f"{G}/users/delta?$deltatoken=tok-U2",
    "value": [user(U_BOB, "Bob Nested", "bob.nested@contoso.example", enabled=False)]},
   note="accountEnabled:false -> sync disables the Samba account (UAC |= 0x2).")
fx("users_delta_user_deleted", "GET", f"{G}/users/delta?$deltatoken=tok-U2", 200,
   {"@odata.deltaLink": f"{G}/users/delta?$deltatoken=tok-U3",
    "value": [{"id": U_CAROL, "@removed": {"reason": "changed"}}]},
   note='User soft-deleted in Entra (30-day recycle bin). Sync: disable + retention marker. '
        'Permanent purge arrives later as reason "deleted".')

# --- 8. throttled 429 ---------------------------------------------------------------
fx("throttled_429", "GET", f"{G}/groups/delta?$deltatoken=tok-AAA1", 429,
   {"error": {"code": "TooManyRequests",
              "message": "Too many requests. Please retry after some time.",
              "innerError": {"date": "2026-07-21T12:00:00", "request-id": "0f9a-fixture",
                             "client-request-id": "0f9a-fixture"}}},
   headers={"Retry-After": "10"},
   note="Honor Retry-After seconds, then retry SAME request (throttling doc). The interrupted read "
        "is INCOMPLETE until it finishes; no plan may be produced from it.")

# --- 9. delta token invalidated: 410 Gone ------------------------------------------
fx("delta_410_gone", "GET", f"{G}/groups/delta?$deltatoken=tok-EXPIRED", 410,
   {"error": {"code": "syncStateNotFound",
              "message": "The sync state generation is not found; a full read is required.",
              "innerError": {"date": "2026-07-21T12:00:00", "request-id": "0f9b-fixture"}}},
   headers={"Location": f"{G}/groups/delta?$deltatoken="},
   note="410 Gone + Location with empty $deltatoken -> restart FULL sync from the Location URL "
        "(delta-query-overview). Directory delta tokens last max 7 days.")

# --- 10. transitive members of the admission group (admission read) ----------------------------
fx("transitive_members_admission_group", "GET",
   f"{G}/groups/{ADMISSION}/transitiveMembers?$select=id,displayName,userPrincipalName,accountEnabled,userType",
   200,
   {"@odata.context": f"{G}/$metadata#directoryObjects", "value": [
      dict(mref("user", U_ALICE), **{"displayName": "Alice Anderson",
           "userPrincipalName": "alice.anderson@contoso.example", "accountEnabled": True, "userType": "Member"}),
      dict(mref("user", U_BOB), **{"displayName": "Bob Nested",
           "userPrincipalName": "bob.nested@contoso.example", "accountEnabled": True, "userType": "Member"}),
      dict(mref("user", U_CAROL), **{"displayName": "Carol Cycle",
           "userPrincipalName": "carol.cycle@contoso.example", "accountEnabled": True, "userType": "Member"}),
      dict(mref("group", G_MID), **{"displayName": "mid-group"}),
      dict(mref("group", G_INNER), **{"displayName": "inner-devs"}),
      dict(mref("group", G_CYCA), **{"displayName": "cyc-a"}),
      dict(mref("group", G_CYCB), **{"displayName": "cyc-b"}),
   ]},
   note="transitiveMembers returns nested groups AS OBJECTS plus flattened users. Used as the "
        "admission cross-check; costs 5 resource units vs 3 for /members (throttling-limits).")

# --- 11. eligibility zoo: every claimed member type on one admission group ---------------------
fx("eligibility_zoo_members", "GET", f"{G}/groups/{ADMISSION}/members", 200,
   {"@odata.context": f"{G}/$metadata#directoryObjects", "value": [
      dict(mref("user", U_ALICE), **{"displayName": "Alice Anderson", "userType": "Member"}),
      dict(mref("user", U_GUEST), **{"displayName": "Gary Guest", "userType": "Guest",
           "userPrincipalName": "gary_partner.example#EXT#@contoso.onmicrosoft.com"}),
      dict(mref("group", G_MID), **{"displayName": "mid-group", "securityEnabled": True,
           "mailEnabled": False, "groupTypes": [], "onPremisesSyncEnabled": None}),
      dict(mref("group", G_M365), **{"displayName": "marketing-m365", "securityEnabled": False,
           "mailEnabled": True, "groupTypes": ["Unified"]}),
      dict(mref("group", G_DYN), **{"displayName": "all-fte-dynamic", "securityEnabled": True,
           "mailEnabled": False, "groupTypes": ["DynamicMembership"],
           "membershipRule": 'user.userType -eq "Member"', "membershipRuleProcessingState": "On"}),
      dict(mref("group", G_ONPREM), **{"displayName": "legacy-ad-synced", "securityEnabled": True,
           "mailEnabled": False, "groupTypes": [], "onPremisesSyncEnabled": True}),
      dict(mref("device", DEV_1), **{"displayName": "LAPTOP-0042", "deviceId": "4d0042aa-0000-0000-0000-00000000dead"}),
      dict(mref("servicePrincipal", SP_1), **{"displayName": "ci-automation", "appId": "ap9f0000-0000-0000-0000-0000000000aa"}),
   ]},
   note="Eligibility fixture. KNOWN ISSUE (group-list-members doc): v1.0 /members omits "
        "servicePrincipals; included here deliberately so the eligibility filter is exercised - "
        "implementation must reject SPs whether or not Graph returns them. "
        "@odata.type strings for device/servicePrincipal are pattern-inferred (live-tenant TODO).")

# --- 12. deleted items listing (recycle bin) ----------------------------------------
fx("deleted_items_groups", "GET",
   f"{G}/directory/deletedItems/microsoft.graph.group?$select=id,displayName,securityEnabled,groupTypes,deletedDateTime",
   200,
   {"@odata.context": f"{G}/$metadata#groups", "value": [
      {"id": G_PROJX, "displayName": "proj-x", "securityEnabled": False, "groupTypes": [],
       "deletedDateTime": "2026-07-20T09:00:00Z"}]},
   note="GOTCHA (deleteditems-list doc): soft-deleted SECURITY groups report securityEnabled:false; "
        "distinguish by groupTypes ([] = security). OData cast segment is mandatory. "
        "App perms: group cast needs Group.Read.All; user cast needs User.Read.All.")

# --- 13. admission group deleted ---------------------------------------------------------------
fx("groups_delta_admission_group_deleted", "GET", f"{G}/groups/delta?$deltatoken=tok-AAA5", 200,
   {"@odata.deltaLink": f"{G}/groups/delta?$deltatoken=tok-AAA6",
    "value": [{"id": ADMISSION, "@removed": {"reason": "changed"}}]},
   note="THE ADMISSION ITSELF deleted -> sync freezes admission changes + alerts; broker fails closed "
        "via role-marker count 0 after quarantine. NEVER auto-recreate (SID would change).")

print("done")
