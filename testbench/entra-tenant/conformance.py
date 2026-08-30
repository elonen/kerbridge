#!/usr/bin/env python3
"""Check a live Entra tenant against the directory the graph-sync corpus assumes.

The corpus under `testbench/fixtures/graph-sync/` is written from Graph
documentation, not from a tenant, so every claim in it is documentation-derived.
This reads a live tenant and reports where the two disagree.

Run it by hand. It is not a test tier: it goes red when Microsoft changes
something, not when a commit does, so it must not gate a merge.

  python3 conformance.py            # prompt, then check
  python3 conformance.py --list     # print the expected directory and exit

Credentials come from the environment, and nothing is written to disk:

  ENTRA_TENANT_ID        the directory (tenant) ID
  ENTRA_SYNC_APP_ID      the sync application's application (client) ID
  ENTRA_SYNC_APP_SECRET  a client secret for that application

Every one that is missing or malformed is named at once, so a first run
reports all of them rather than one per attempt.

The application needs `User.Read.All` and `Group.Read.All`, with admin consent.
It writes nothing.

Output carries no id, no UPN and no tenant GUID, so a run pastes into a
public issue unedited. `label()` is what enforces it: a message names an object
by a constant from this file, or by `<unknown>`. Property values are printed
beside them, and those are the small enumerations Graph uses (`Member`,
`Unified`), never an identifier.
"""

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "..", "fixtures", "graph-sync")
GRAPH = "https://graph.microsoft.com"
GUID = re.compile(r"^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")

# --- the expected directory --------------------------------------------
# Stated in the words the portal uses, because that is where an operator
# builds it. Terraform creates the admission group and the applications; every
# other object here is made by hand. `--list` prints this block, so it is also
# the reproduction instructions.

ADMISSION = "KerBridge Allowed On-prem Users"
DUPLICATE = "kb-duplicate-name"

# username -> "Blocked sign in" is No. The username is what goes before the `@`
# in the portal's User principal name. A display name is not a handle: it is
# free text an operator may write in any script, and holding a non-ASCII one is
# a case this corpus wants covered rather than one that breaks the lookup.
EXPECTED_USERS = {
    "kb-alice": True,
    "kb-bob": True,
    "kb-carol": True,
    "kb-dave-disabled": False,
}

# The guest has neither an expected username nor an expected display name: an
# invitation writes both from the address it invited, and that address is not
# ours to choose. It is found by the `#EXT#` in its UPN, and among the
# admission group's members rather than the whole tenant -- the account that
# created the tenant carries an `#EXT#` UPN too.
GUEST = "<guest>"
SP = "<service principal>"
UNKNOWN = "<unknown>"

# Group name -> the portal's "Group type". Membership type is Assigned for
# every one of them: Dynamic needs Entra ID P1 and is the separate `kb-dynamic`.
SECURITY = "Security"
MICROSOFT_365 = "Microsoft 365"

EXPECTED_GROUPS = {
    ADMISSION: SECURITY,
    "eng-team": SECURITY,
    "eng-backend": SECURITY,
    "proj-x": SECURITY,
    "kb-collab": MICROSOFT_365,
}

# What each portal choice is on the wire. `groupTypes` is the discriminator:
# `securityEnabled` does not separate the two, because a Microsoft 365 group can
# carry it as well. The word `Unified` appears nowhere in the portal, which is
# why it is confined to this table.
GROUP_TYPE_WIRE = {
    SECURITY: {"securityEnabled": True, "groupTypes": []},
    MICROSOFT_365: {"groupTypes": ["Unified"]},
}

# Direct members, by label. The service principal is deliberately absent from
# proj-x: v1.0 `/members` omits it, and `check_sp_omission` checks that.
EXPECTED_MEMBERS = {
    ADMISSION: {"kb-alice", "eng-team", GUEST},
    "eng-team": {"kb-bob", "eng-backend"},
    "eng-backend": {"kb-carol"},
    "proj-x": {"kb-alice", "kb-dave-disabled"},
}

# Users reachable through nesting from the admission group. Dave is absent: it
# is in proj-x only, which is the pair that proves admission is by membership
# and not by existing.
EXPECTED_TRANSITIVE_USERS = {"kb-alice", "kb-bob", "kb-carol", GUEST}

# Present only on a licensed or permitting tenant. Reported, never failed.
OPTIONAL_GROUPS = ("kb-distlist", "kb-dynamic")


def username(obj):
    """The UPN local part, lowered. Entra compares a UPN without case."""
    return (obj.get("userPrincipalName") or "").split("@")[0].lower()


def is_guest(obj):
    """A `#EXT#` UPN. The spike measured that this does not imply
    `userType == "Guest"`, so the two are checked apart: this finds the object,
    and `check_guest` judges what Entra calls it."""
    return "#EXT#" in (obj.get("userPrincipalName") or "")


def label(obj):
    """One Graph object as a name this file already contains.

    Every object named in a message goes through here, which is what keeps a
    live id, UPN or display name out of the output.
    """
    kind = obj.get("@odata.type", "")
    if kind.endswith("servicePrincipal"):
        return SP
    if kind.endswith("group") or "groupTypes" in obj:
        name = obj.get("displayName")
        return name if name in EXPECTED_GROUPS or name == DUPLICATE else UNKNOWN
    if is_guest(obj):
        return GUEST
    name = username(obj)
    return name if name in EXPECTED_USERS else UNKNOWN


def labels(objects):
    return sorted(label(o) for o in objects)


# --- the checks, over parsed JSON only ---------------------------------
# Each returns a list of failure strings. Empty means the check passed.


def check_users(users):
    """Every expected user is present once, and enabled as expected."""
    bad = []
    for name, enabled in sorted(EXPECTED_USERS.items()):
        found = [u for u in users if username(u) == name]
        if len(found) != 1:
            bad.append("expected 1 user %r, found %d" % (name, len(found)))
            continue
        got = found[0].get("accountEnabled")
        if got is not enabled:
            bad.append("user %r: accountEnabled is %r, expected %r" % (name, got, enabled))
    return bad


def check_guest(admission_members, users):
    """One guest in the admission group, found by its UPN.

    Looked for among the members rather than the whole tenant: an account that
    created the tenant from a Microsoft account carries an `#EXT#` UPN as well,
    and it is not the guest this corpus means.

    `userType` is read back from `users`, not from the member object. A
    `/members` read carries the default property set, and that set has no
    `userType` -- which is the second half of the same measurement.
    """
    guests = [m for m in admission_members if is_guest(m)]
    if len(guests) != 1:
        return ["expected 1 admission-group member with #EXT# in its UPN, found %d" % len(guests)]
    known = {username(u): u for u in users}
    full = known.get(username(guests[0]))
    if full is None:
        return ["the admission group's #EXT# member is not in the tenant's user list"]
    kind = full.get("userType")
    if kind != "Guest":
        return ["the #EXT# member has userType %r, expected 'Guest'" % kind]
    return []


def check_groups(groups):
    """Every expected group is present once and carries its properties."""
    bad = []
    for name, kind in sorted(EXPECTED_GROUPS.items()):
        found = [g for g in groups if g.get("displayName") == name]
        if len(found) != 1:
            bad.append("expected 1 %s group %r, found %d" % (kind, name, len(found)))
            continue
        for key, want in sorted(GROUP_TYPE_WIRE[kind].items()):
            got = found[0].get(key)
            if got != want:
                bad.append(
                    "group %r should be a %s group, but %s is %r and not %r"
                    % (name, kind, key, got, want)
                )
    return bad


def check_duplicate_pair(groups):
    """(failures, notes) for the display-name ambiguity pair.

    Two groups under one name settle whether a name resolves to one object, and
    the corpus records that it does not. Only Graph can build it: the portal
    offers a group a name and a description, refuses a second group under a name
    it already holds, and derives the mail nickname itself, so a tenant built by
    hand has no pair. Absent is therefore allowed, and half a pair is not -- that
    is a tenant somebody started building and could not finish.
    """
    found = [g for g in groups if g.get("displayName") == DUPLICATE]
    if len(found) == 2:
        return [], []
    if not found:
        return [], ["no %r pair, so name ambiguity stays unmeasured" % DUPLICATE]
    return ["found %d groups named %r, expected 2 or none" % (len(found), DUPLICATE)], []


def check_members(name, members):
    got = set(labels(members))
    want = EXPECTED_MEMBERS[name]
    if got == want:
        return []
    return [
        "group %r members: missing %s, unexpected %s"
        % (name, sorted(want - got) or "nothing", sorted(got - want) or "nothing")
    ]


def check_transitive_users(members):
    """Admission is by membership, so the users reachable through nesting are
    the claim. Nested groups also appear in this collection and are ignored."""
    got = {lb for lb in labels(members) if lb in EXPECTED_USERS or lb == GUEST}
    if got == EXPECTED_TRANSITIVE_USERS:
        return []
    return [
        "admission group transitive users: missing %s, unexpected %s"
        % (
            sorted(EXPECTED_TRANSITIVE_USERS - got) or "nothing",
            sorted(got - EXPECTED_TRANSITIVE_USERS) or "nothing",
        )
    ]


def check_sp_omission(plain_members, cast_members):
    """v1.0 omits a service principal from `/members` and shows it only under
    the type cast. The corpus records this; a tenant that stopped doing it would
    silently widen every membership read."""
    bad = []
    if SP in labels(plain_members):
        bad.append("proj-x /members listed a service principal; v1.0 omits it")
    if len(cast_members) != 1:
        bad.append(
            "proj-x /members/microsoft.graph.servicePrincipal returned %d, expected 1"
            % len(cast_members)
        )
    return bad


# --- shape comparison against the corpus -------------------------------


def replay_url(fixture, admission_id):
    """The fixture's request as a live URL, or None if it cannot be replayed.

    A cursor is opaque and tenant-specific, so an exchange that carries one
    describes a state this run cannot reach. An exchange addressed to the
    corpus's own admission group is replayed against the live one.
    """
    url = fixture["request"]["url"]
    if "$deltatoken=" in url or "$skiptoken=" in url:
        return None
    found = re.search(r"/groups/([0-9a-fA-F-]{36})/", url)
    if found:
        url = url.replace(found.group(1), admission_id)
    return url


def keys_by_type(page, common=False):
    """Field names each object carries, grouped by `@odata.type`.

    `common` keeps only the fields every object of a kind carries. A field on
    one object and not on the next is conditional -- `membershipRule` belongs to
    a dynamic group alone -- so it cannot be required of a tenant that holds no
    such object.
    """
    out = {}
    for obj in page.get("value", []):
        kind = obj.get("@odata.type", "")
        fields = {k for k in obj if not k.startswith("@odata.")}
        if common and kind in out:
            out[kind] &= fields
        else:
            out.setdefault(kind, set()).update(fields)
    return out


def shape_diff(fixture_page, live_page):
    """(missing, added, absent) per `@odata.type`.

    Only missing is a failure: an object of a kind the tenant does hold has lost
    a field the corpus records on every object of that kind. The other two are
    reported -- a new field breaks nothing, and a kind the tenant holds none of
    can show no fields at all, which is a smaller tenant rather than drift.
    """
    required = keys_by_type(fixture_page, common=True)
    recorded = keys_by_type(fixture_page)
    live = keys_by_type(live_page)
    missing, added, absent = {}, {}, []
    for kind, fields in sorted(required.items()):
        if kind not in live:
            absent.append(kind)
        elif fields - live[kind]:
            missing[kind] = sorted(fields - live[kind])
    for kind, fields in sorted(live.items()):
        if fields - recorded.get(kind, set()):
            added[kind] = sorted(fields - recorded.get(kind, set()))
    return missing, added, absent


# --- the live half -----------------------------------------------------


def post_form(url, fields):
    body = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def token(tenant, client_id, secret):
    return post_form(
        "https://login.microsoftonline.com/%s/oauth2/v2.0/token" % tenant,
        {
            "client_id": client_id,
            "scope": GRAPH + "/.default",
            "client_secret": secret,
            "grant_type": "client_credentials",
        },
    )["access_token"]


def get(access_token, url):
    req = urllib.request.Request(url)
    req.add_header("Authorization", "Bearer " + access_token)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, {}


def get_all(access_token, url):
    """Follow `@odata.nextLink` to the end. The tenant is a bench tenant, so the
    whole collection fits in memory."""
    out, page = [], None
    while url:
        status, page = get(access_token, url)
        if status != 200:
            raise SystemExit("GET returned HTTP %d; check the permissions and the consent" % status)
        out.extend(page.get("value", []))
        url = page.get("@odata.nextLink")
    return out, page


# Variable, what it holds, and whether it must be a GUID.
ENV = (
    ("ENTRA_TENANT_ID", "the directory (tenant) ID", True),
    ("ENTRA_SYNC_APP_ID", "the sync application's application (client) ID", True),
    ("ENTRA_SYNC_APP_SECRET", "a client secret for that application", False),
)


def credentials(env):
    """(values, problems) from the environment.

    Every problem is collected rather than raised at the first one: the three
    are usually set together, and a run that reports one missing variable per
    attempt costs three runs to learn the same thing.
    """
    values, problems = [], []
    for name, what, is_guid in ENV:
        value = (env.get(name) or "").strip()
        values.append(value)
        if not value:
            problems.append("%s is not set -- it holds %s" % (name, what))
        elif is_guid and not GUID.match(value):
            problems.append("%s is not a GUID" % name)
    return tuple(values), problems


def print_expected():
    print("Users, by username (the UPN local part). Any display name, in any script:")
    for name, enabled in sorted(EXPECTED_USERS.items()):
        print("  %-22s Account enabled: %s" % (name, "yes" if enabled else "no"))
    print("  %-22s an invited external user, in the admission group; User type: Guest" % GUEST)
    print("\nGroups, by name. Membership type is Assigned for every one:")
    for name, kind in sorted(EXPECTED_GROUPS.items()):
        print("  %-34s Group type: %s" % (name, kind))
    print("  %-34s two groups under one name; Graph only, the portal refuses it" % DUPLICATE)
    for name in OPTIONAL_GROUPS:
        print("  %-34s optional; absent on a tenant that refuses it" % name)
    print("\nDirect members:")
    for name in sorted(EXPECTED_MEMBERS):
        print("  %-34s %s" % (name, ", ".join(sorted(EXPECTED_MEMBERS[name]))))
    print("\nUsers reachable from %s: %s" % (ADMISSION, ", ".join(sorted(EXPECTED_TRANSITIVE_USERS))))
    print("proj-x also holds the sync service principal, which v1.0 /members omits.")


def report(name, failures):
    print("%-46s %s" % (name, "PASS" if not failures else "FAIL"))
    for line in failures:
        print("    " + line)
    return not failures


def main():
    if "--list" in sys.argv:
        print_expected()
        return 0

    (tenant, client_id, secret), problems = credentials(os.environ)
    if problems:
        for problem in problems:
            print("error: " + problem, file=sys.stderr)
        return 2

    print_expected()
    print()
    access = token(tenant, client_id, secret)
    print()

    user_select = "id,displayName,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled"
    group_select = "id,displayName,securityEnabled,mailEnabled,groupTypes"
    users, _ = get_all(access, "%s/v1.0/users?$select=%s" % (GRAPH, user_select))
    groups, _ = get_all(access, "%s/v1.0/groups?$select=%s" % (GRAPH, group_select))

    ok = True
    ok &= report("users present and enabled as expected", check_users(users))
    ok &= report("groups present with their properties", check_groups(groups))

    by_name = {}
    for group in groups:
        by_name.setdefault(group.get("displayName"), []).append(group)

    for name in sorted(EXPECTED_MEMBERS):
        if len(by_name.get(name, [])) != 1:
            ok &= report("%s direct members" % name, ["group %r is not present once" % name])
            continue
        members, _ = get_all(access, "%s/v1.0/groups/%s/members" % (GRAPH, by_name[name][0]["id"]))
        ok &= report("%s direct members" % name, check_members(name, members))
        if name == ADMISSION:
            ok &= report("one #EXT# member, typed Guest", check_guest(members, users))

    admission_id = by_name[ADMISSION][0]["id"] if len(by_name.get(ADMISSION, [])) == 1 else None
    if admission_id:
        members, _ = get_all(
            access, "%s/v1.0/groups/%s/transitiveMembers" % (GRAPH, admission_id)
        )
        ok &= report("admission group reaches the expected users", check_transitive_users(members))

    if len(by_name.get("proj-x", [])) == 1:
        projx = by_name["proj-x"][0]["id"]
        plain, _ = get_all(access, "%s/v1.0/groups/%s/members" % (GRAPH, projx))
        cast, _ = get_all(
            access,
            "%s/v1.0/groups/%s/members/microsoft.graph.servicePrincipal" % (GRAPH, projx),
        )
        ok &= report("service principal only under the type cast", check_sp_omission(plain, cast))

    failures, notes = check_duplicate_pair(groups)
    ok &= report("the display-name ambiguity pair", failures)
    for note in notes:
        print("    note: " + note)

    for name in OPTIONAL_GROUPS:
        print("%-46s %s" % ("optional group %s" % name, "present" if by_name.get(name) else "absent"))

    if admission_id:
        print()
        ok &= shape_report(access, admission_id)

    print("\n%s" % ("all checks passed" if ok else "some checks failed"))
    return 0 if ok else 1


def shape_verdict(fixture, status, live):
    """(failures, notes) for one replayed exchange.

    Two answers are not drift and must not fail the run: a read this consent
    does not cover, and a collection the tenant has nothing in. An empty
    collection carries no fields, so every field the corpus records would
    otherwise read as removed.
    """
    want = fixture["response"]["status"]
    if status == 403 and want == 200:
        return [], ["not permitted by this consent, so nothing was compared"]
    if status != want:
        return ["HTTP %d, the corpus records %d" % (status, want)], []
    if not live.get("value"):
        return [], ["the tenant holds no such object, so nothing was compared"]
    missing, added, absent = shape_diff(fixture["response"]["body"], live)
    notes = ["the tenant holds no %s, so its fields were not compared" % (kind or "object")
             for kind in absent]
    notes += ["%s also returns %s" % (kind or "the object", fields)
              for kind, fields in sorted(added.items())]
    return (
        ["%s no longer returns %s" % (kind or "the object", fields)
         for kind, fields in sorted(missing.items())],
        notes,
    )


def shape_report(access, admission_id):
    """Replay each replayable exchange and compare the field names."""
    ok = True
    for name in sorted(os.listdir(CORPUS)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(CORPUS, name)) as handle:
            fixture = json.load(handle)
        url = replay_url(fixture, admission_id)
        if url is None:
            continue
        status, live = get(access, url)
        failures, notes = shape_verdict(fixture, status, live)
        ok &= report("shape %s" % name, failures)
        for note in notes:
            print("    note: " + note)
    return ok


if __name__ == "__main__":
    sys.exit(main())
