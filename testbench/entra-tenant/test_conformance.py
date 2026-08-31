#!/usr/bin/env python3
"""Hermetic tests for conformance.py's checks. No tenant, no network.

The instrument itself cannot run without a tenant, so this is what holds its
judgement to what it claims: each check is driven over a correct directory and
over a directory broken in one named way.

  python3 test_conformance.py
"""

import contextlib
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import conformance as c


_SEQ = iter(range(1, 10 ** 6))


def oid(prefix):
    """A distinct id per object. A group is looked up by id in `Driver`, so a
    collision there would answer for the wrong group."""
    return "%s-0000-0000-0000-%012d" % (prefix, next(_SEQ))


def user(name, enabled=True, upn=None, kind="Member", display=None):
    return {
        "id": oid("00000000"),
        # Free text, and deliberately not what the checks match on.
        "displayName": display or ("Display %s" % name),
        "userPrincipalName": upn or ("%s@tenant.example" % name),
        "accountEnabled": enabled,
        "userType": kind,
    }


GUEST_UPN = "someone_partner.example#EXT#@tenant.example"


def guest(name="someone_partner.example#EXT#"):
    return user(name, upn=GUEST_UPN, kind="Guest")


def group(name, **props):
    body = {
        "id": oid("10000000"),
        "displayName": name,
        "securityEnabled": True,
        "mailEnabled": False,
        "groupTypes": [],
    }
    body.update(props)
    return body


def member(obj, kind):
    out = dict(obj)
    out["@odata.type"] = "#microsoft.graph." + kind
    return out


def good_users():
    return [user(n, e) for n, e in c.EXPECTED_USERS.items()] + [guest()]


def good_groups(pair=True):
    out = [group(n, **c.GROUP_TYPE_WIRE[k]) for n, k in c.EXPECTED_GROUPS.items()]
    if pair:
        out += [group(c.DUPLICATE), group(c.DUPLICATE)]
    return out


class Users(unittest.TestCase):
    def test_a_correct_roster_passes(self):
        self.assertEqual(c.check_users(good_users()), [])

    def test_a_missing_user_fails(self):
        roster = [u for u in good_users() if c.username(u) != "kb-bob"]
        self.assertIn("kb-bob", " ".join(c.check_users(roster)))

    def test_a_duplicated_user_fails(self):
        self.assertIn("found 2", " ".join(c.check_users(good_users() + [user("kb-alice")])))

    def test_an_enabled_dave_fails(self):
        roster = [u for u in good_users() if c.username(u) != "kb-dave-disabled"]
        roster.append(user("kb-dave-disabled", enabled=True))
        self.assertIn("accountEnabled", " ".join(c.check_users(roster)))


class Guest(unittest.TestCase):
    def check(self, members, users=None):
        return " ".join(c.check_guest(members, users if users is not None else members))

    def test_any_display_name_is_accepted(self):
        for display in ("kb-guest", "Carol \u9ad8\u6a4b", "Whoever The Invitation Named"):
            g = guest()
            g["displayName"] = display
            self.assertEqual(self.check([user("kb-alice"), g]), "", display)

    def test_the_upn_is_what_identifies_the_guest(self):
        # Named like the guest but with an ordinary UPN: not the guest.
        self.assertIn("found 0", self.check([user("kb-guest", kind="Guest")]))

    def test_the_tenant_creator_outside_the_group_is_not_counted(self):
        # A tenant made from a Microsoft account holds an #EXT# user of its own.
        creator = user("someone_outlook.com#EXT#", upn="someone_outlook.com#EXT#@t.example")
        members = [user("kb-alice"), guest()]
        self.assertEqual(self.check(members, members + [creator]), "")

    def test_an_ext_upn_that_is_not_typed_guest_fails(self):
        # The spike measured that #EXT# does not imply userType Guest.
        odd = user("whoever", upn=GUEST_UPN, kind="Member")
        self.assertIn("userType", self.check([odd]))

    def test_the_type_is_read_from_the_user_list_not_the_member(self):
        # A /members read carries the default property set, which has no
        # userType, so judging the member object would judge nothing.
        member_view = {k: v for k, v in guest().items() if k != "userType"}
        self.assertEqual(self.check([member_view], [guest()]), "")

    def test_two_guests_in_the_group_fail(self):
        self.assertIn("found 2", self.check([guest("a#EXT#"), guest("b#EXT#")]))


class Groups(unittest.TestCase):
    def test_a_correct_directory_passes(self):
        self.assertEqual(c.check_groups(good_groups()), [])

    def test_a_missing_group_fails(self):
        groups = [g for g in good_groups() if g["displayName"] != "eng-backend"]
        self.assertIn("eng-backend", " ".join(c.check_groups(groups)))

    def test_the_pair_is_not_required_by_the_group_check(self):
        # The portal cannot build it, so check_duplicate_pair judges it apart.
        self.assertEqual(c.check_groups(good_groups(pair=False)), [])

    def test_a_security_group_where_microsoft_365_is_expected_fails(self):
        groups = [g for g in good_groups() if g["displayName"] != "kb-collab"]
        groups.append(group("kb-collab", **c.GROUP_TYPE_WIRE[c.SECURITY]))
        failure = " ".join(c.check_groups(groups))
        self.assertIn(c.MICROSOFT_365, failure)
        self.assertIn("groupTypes", failure)

    def test_the_portal_words_reach_the_message(self):
        # An operator reads these, and picks from them in the New group dialog.
        failure = " ".join(c.check_groups([]))
        self.assertIn(c.SECURITY, failure)
        self.assertIn(c.MICROSOFT_365, failure)


class DuplicatePair(unittest.TestCase):
    def test_a_pair_passes_silently(self):
        self.assertEqual(c.check_duplicate_pair(good_groups()), ([], []))

    def test_no_pair_is_a_note_not_a_failure(self):
        failures, notes = c.check_duplicate_pair(good_groups(pair=False))
        self.assertEqual(failures, [])
        self.assertIn("unmeasured", notes[0])

    def test_half_a_pair_fails(self):
        groups = good_groups(pair=False) + [group(c.DUPLICATE)]
        failures, _ = c.check_duplicate_pair(groups)
        self.assertIn("found 1", failures[0])

    def test_three_fail(self):
        groups = good_groups() + [group(c.DUPLICATE)]
        failures, _ = c.check_duplicate_pair(groups)
        self.assertIn("found 3", failures[0])


class Members(unittest.TestCase):
    def admission(self):
        return [
            member(user("kb-alice"), "user"),
            member(group("eng-team"), "group"),
            member(guest(), "user"),
        ]

    def test_the_expected_members_pass(self):
        self.assertEqual(c.check_members(c.ADMISSION, self.admission()), [])

    def test_the_guest_counts_as_a_member_under_any_name(self):
        members = [
            member(user("kb-alice"), "user"),
            member(group("eng-team"), "group"),
            member(guest("An Entirely Different Name"), "user"),
        ]
        self.assertEqual(c.check_members(c.ADMISSION, members), [])

    def test_a_dropped_member_is_named(self):
        failures = " ".join(c.check_members(c.ADMISSION, self.admission()[:-1]))
        self.assertIn(c.GUEST, failures)

    def test_an_extra_member_is_reported_as_unknown(self):
        extra = self.admission() + [member(user("Somebody Else"), "user")]
        self.assertIn(c.UNKNOWN, " ".join(c.check_members(c.ADMISSION, extra)))


class Transitive(unittest.TestCase):
    def reachable(self):
        return [
            member(user("kb-alice"), "user"),
            member(user("kb-bob"), "user"),
            member(user("kb-carol"), "user"),
            member(guest(), "user"),
            member(group("eng-team"), "group"),
            member(group("eng-backend"), "group"),
        ]

    def test_nested_groups_are_ignored(self):
        self.assertEqual(c.check_transitive_users(self.reachable()), [])

    def test_a_disabled_user_reaching_admission_fails(self):
        extra = self.reachable() + [member(user("kb-dave-disabled", False), "user")]
        self.assertIn("kb-dave-disabled", " ".join(c.check_transitive_users(extra)))


class ServicePrincipal(unittest.TestCase):
    def test_the_omission_holds(self):
        plain = [member(user("kb-alice"), "user")]
        cast = [member({"displayName": "sync"}, "servicePrincipal")]
        self.assertEqual(c.check_sp_omission(plain, cast), [])

    def test_a_service_principal_in_plain_members_fails(self):
        plain = [member({"displayName": "sync"}, "servicePrincipal")]
        cast = list(plain)
        self.assertIn("omits it", " ".join(c.check_sp_omission(plain, cast)))

    def test_an_empty_cast_fails(self):
        self.assertIn("expected 1", " ".join(c.check_sp_omission([], [])))


class Shape(unittest.TestCase):
    def page(self, *objects):
        return {"@odata.context": "irrelevant", "value": list(objects)}

    def test_an_identical_shape_has_no_difference(self):
        page = self.page(user("kb-alice"))
        self.assertEqual(c.shape_diff(page, page), ({}, {}, []))

    def test_a_dropped_field_is_missing(self):
        live = self.page({k: v for k, v in user("kb-alice").items() if k != "userType"})
        missing, added, absent = c.shape_diff(self.page(user("kb-alice")), live)
        self.assertEqual(missing, {"": ["userType"]})
        self.assertEqual((added, absent), ({}, []))

    def test_a_new_field_is_added_not_missing(self):
        richer = dict(user("kb-alice"), employeeId="x")
        missing, added, _ = c.shape_diff(self.page(user("kb-alice")), self.page(richer))
        self.assertEqual(missing, {})
        self.assertEqual(added, {"": ["employeeId"]})

    def test_a_kind_the_tenant_lacks_is_absent_not_missing(self):
        fixture = self.page(member(user("kb-alice"), "user"),
                            member(group("eng-team"), "group"))
        live = self.page(member(user("kb-alice"), "user"))
        missing, _, absent = c.shape_diff(fixture, live)
        self.assertEqual(missing, {})
        self.assertEqual(absent, ["#microsoft.graph.group"])

    def test_a_field_only_one_object_carries_is_not_required(self):
        # membershipRule belongs to a dynamic group alone. A tenant with no
        # dynamic group must not be told the field went away.
        fixture = self.page(group("eng-team"), dict(group("kb-dynamic"), membershipRule="x"))
        missing, _, _ = c.shape_diff(fixture, self.page(group("eng-team")))
        self.assertEqual(missing, {})


class Verdict(unittest.TestCase):
    """A replayed exchange judged without a network."""

    FIXTURE = {"response": {"status": 200, "body": {"value": [{"id": "x", "displayName": "y"}]}}}

    def test_a_matching_shape_passes_with_no_notes(self):
        live = {"value": [{"id": "1", "displayName": "2"}]}
        self.assertEqual(c.shape_verdict(self.FIXTURE, 200, live), ([], []))

    def test_a_refused_read_is_a_note_not_a_failure(self):
        failures, notes = c.shape_verdict(self.FIXTURE, 403, {})
        self.assertEqual(failures, [])
        self.assertIn("consent", notes[0])

    def test_an_empty_collection_is_a_note_not_a_failure(self):
        # Otherwise every field the corpus records reads as removed.
        failures, notes = c.shape_verdict(self.FIXTURE, 200, {"value": []})
        self.assertEqual(failures, [])
        self.assertIn("nothing was compared", notes[0])

    def test_another_status_is_a_failure(self):
        failures, _ = c.shape_verdict(self.FIXTURE, 404, {})
        self.assertIn("404", failures[0])

    def test_a_dropped_field_is_a_failure(self):
        failures, _ = c.shape_verdict(self.FIXTURE, 200, {"value": [{"id": "1"}]})
        self.assertIn("displayName", failures[0])


class Replay(unittest.TestCase):
    LIVE = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    def test_a_cursor_exchange_is_not_replayable(self):
        fixture = {"request": {"url": "https://graph.microsoft.com/v1.0/groups/delta?$deltatoken=x"}}
        self.assertIsNone(c.replay_url(fixture, self.LIVE))

    def test_the_corpus_group_id_is_replaced_with_the_live_one(self):
        url = "https://graph.microsoft.com/v1.0/groups/4e8a1c9d-5f6b-4d7e-b8a9-001122334455/members"
        got = c.replay_url({"request": {"url": url}}, self.LIVE)
        self.assertIn(self.LIVE, got)
        self.assertNotIn("4e8a1c9d", got)

    def test_a_plain_read_is_replayed_unchanged(self):
        url = "https://graph.microsoft.com/v1.0/users?$select=id,displayName"
        self.assertEqual(c.replay_url({"request": {"url": url}}, self.LIVE), url)

    def test_the_committed_corpus_yields_replayable_exchanges(self):
        replayable = []
        for name in sorted(os.listdir(c.CORPUS)):
            if not name.endswith(".json"):
                continue
            with open(os.path.join(c.CORPUS, name)) as handle:
                fixture = json.load(handle)
            if "request" in fixture and c.replay_url(fixture, self.LIVE):
                replayable.append(name)
        self.assertIn("full_users_page1.json", replayable)
        self.assertIn("transitive_members_admission_group.json", replayable)


class Redaction(unittest.TestCase):
    """No live identifier may reach the output. `label` is the only channel by
    which an object names itself, so a failure can name one only by a constant."""

    # `#EXT#` is deliberately absent: it is a constant in conformance.py, and
    # naming it in a message is how a reader learns what was looked for.
    SECRETS = ("tenant.example", "00000000-", "10000000-", "Somebody Else")

    def messages(self):
        users = good_users() + [user("Somebody Else")]
        out = []
        out += c.check_users(users)
        out += c.check_guest([guest(), guest("second#EXT#")], users)
        out += c.check_groups(good_groups()[1:])
        out += c.check_members(c.ADMISSION, [member(user("Somebody Else"), "user")])
        out += c.check_transitive_users([member(user("Somebody Else"), "user")])
        out += c.check_sp_omission([member({"displayName": "sync"}, "servicePrincipal")], [])
        return " ".join(out)

    def test_no_live_value_appears_in_a_failure(self):
        text = self.messages()
        self.assertTrue(text, "the broken directory produced no failures to inspect")
        for secret in self.SECRETS:
            self.assertNotIn(secret, text, "a live value reached the output: %r" % secret)


class Credentials(unittest.TestCase):
    GOOD = {
        "ENTRA_TENANT_ID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "ENTRA_SYNC_APP_ID": "11111111-2222-3333-4444-555555555555",
        "ENTRA_SYNC_APP_SECRET": "a-secret",
    }

    def test_a_complete_environment_has_no_problems(self):
        values, problems = c.credentials(self.GOOD)
        self.assertEqual(problems, [])
        self.assertEqual(values, tuple(self.GOOD[n] for n, _, _ in c.ENV))

    def test_every_missing_variable_is_named_at_once(self):
        _, problems = c.credentials({})
        self.assertEqual(len(problems), 3)
        for name, _, _ in c.ENV:
            self.assertTrue(any(name in p for p in problems), name)

    def test_an_empty_value_counts_as_missing(self):
        _, problems = c.credentials(dict(self.GOOD, ENTRA_SYNC_APP_SECRET="  "))
        self.assertEqual(len(problems), 1)
        self.assertIn("ENTRA_SYNC_APP_SECRET", problems[0])

    def test_a_value_that_is_not_a_guid_is_named(self):
        _, problems = c.credentials(dict(self.GOOD, ENTRA_TENANT_ID="krbtesting"))
        self.assertIn("not a GUID", problems[0])

    def test_the_secret_is_not_required_to_be_a_guid(self):
        self.assertEqual(c.credentials(dict(self.GOOD, ENTRA_SYNC_APP_SECRET="~q7Q"))[1], [])

    def test_a_value_is_stripped(self):
        values, _ = c.credentials(dict(self.GOOD, ENTRA_SYNC_APP_SECRET=" s "))
        self.assertEqual(values[2], "s")

    def test_no_secret_reaches_a_problem_message(self):
        _, problems = c.credentials({"ENTRA_SYNC_APP_SECRET": "hunter2"})
        self.assertNotIn("hunter2", " ".join(problems))


class Driver(unittest.TestCase):
    """`main` over a stubbed tenant.

    Everything below the checks -- the ordering, the group lookups, the two
    reads proj-x needs -- runs only against a tenant, so this is the one place
    it runs at all. Only the four network calls are replaced.
    """

    def tenant(self, users, groups):
        """A `get_all` that answers from a directory held in memory."""
        by_id = {g["id"]: g for g in groups}

        def members_of(group_id):
            name = by_id[group_id]["displayName"]
            if name not in c.EXPECTED_MEMBERS:
                return []
            out = []
            for lb in sorted(c.EXPECTED_MEMBERS[name]):
                if lb == c.GUEST:
                    out.append(member(guest(), "user"))
                elif lb in c.EXPECTED_USERS:
                    out.append(member(user(lb), "user"))
                else:
                    out.append(member(group(lb), "group"))
            return out

        def get_all(_access, url):
            if "/users?" in url:
                return list(users), {}
            if "/groups?" in url:
                return list(groups), {}
            group_id = url.split("/groups/")[1].split("/")[0]
            if url.endswith("microsoft.graph.servicePrincipal"):
                return [member({"displayName": "sync"}, "servicePrincipal")], {}
            if url.endswith("transitiveMembers"):
                return [
                    member(user("kb-alice"), "user"),
                    member(user("kb-bob"), "user"),
                    member(user("kb-carol"), "user"),
                    member(guest(), "user"),
                    member(group("eng-team"), "group"),
                ], {}
            return members_of(group_id), {}

        return get_all

    def run_main(self, users, groups):
        saved = (c.credentials, c.token, c.get_all, c.get)
        c.credentials = lambda _env: (("t", "c", "s"), [])
        c.token = lambda *a: "access"
        c.get_all = self.tenant(users, groups)
        # Every replayed exchange answers 403, which shape_verdict reports as a
        # note. The shapes themselves are covered by the Verdict cases.
        c.get = lambda *a: (403, {})
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                code = c.main()
        finally:
            c.credentials, c.token, c.get_all, c.get = saved
        return code, out.getvalue()

    def test_a_correct_tenant_passes(self):
        code, text = self.run_main(good_users(), good_groups())
        self.assertEqual(code, 0, text)
        self.assertIn("all checks passed", text)
        self.assertNotIn("FAIL", text)

    def test_a_broken_tenant_fails_and_names_what_broke(self):
        users = [u for u in good_users() if c.username(u) != "kb-bob"]
        code, text = self.run_main(users, good_groups())
        self.assertEqual(code, 1, text)
        self.assertIn("kb-bob", text)

    def test_a_missing_group_does_not_stop_the_run(self):
        groups = [g for g in good_groups() if g["displayName"] != "proj-x"]
        code, text = self.run_main(good_users(), groups)
        self.assertEqual(code, 1, text)
        self.assertIn("is not present once", text)
        # The checks after it still ran.
        self.assertIn("ambiguity pair", text)

    def test_no_live_identifier_reaches_a_whole_run(self):
        _, text = self.run_main(good_users() + [user("Somebody Else")], good_groups())
        for secret in Redaction.SECRETS:
            self.assertNotIn(secret, text, secret)


if __name__ == "__main__":
    # One summary line on success, like the other checks make test runs; the
    # captured report is what a failure needs.
    report = io.StringIO()
    runner = unittest.TextTestRunner(stream=report, verbosity=1)
    result = unittest.main(exit=False, testRunner=runner).result
    if not result.wasSuccessful():
        sys.stderr.write(report.getvalue())
        sys.exit(1)
    print(f"entra conformance: {result.testsRun} cases hold")
