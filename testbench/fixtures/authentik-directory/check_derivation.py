#!/usr/bin/env python3
"""Hold this corpus to the derivation its README states.

The corpus has no generator: it is trimmed and pinned by hand from the
recordings at `../../authentik/captured/`. So the derivation cannot be replayed,
and a byte comparison against a re-recording is worthless -- a re-record keeps
the shapes and none of the identifiers.

This checks the part that *is* invariant. Every rule below is one the README
states in prose, and the provenance table names where each file came from. A
file with no entry fails, so a fixture cannot enter the corpus without saying
what it is derived from.
"""
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
RECORDED = HERE.parent.parent / "authentik" / "captured"

# Where each file comes from: a recording basename, or the reason there is none.
# A reason means no recording can exist, not that nobody made one.
PROVENANCE = {
    "users_page1": "users_page1",
    "users_page2": "users_page2",
    "groups_page1": "groups_page1",
    "groups_page2": "groups_page2",
    "err_403_no_permission": "err_403_no_permission",
    "err_403_not_provided": "err_403_not_provided",
    "err_403_token_invalid": "err_403_token_invalid",
    "neg_torn_read_user_delete": "users_torn_page2",
    "neg_torn_read_group_insert": "groups_insert_mid_read_page2",
    "neg_dangling_member": "edited from the group pages: authentik cannot be asked for a "
    "dangling id, only for a grant that leaves one",
    "neg_uuid_noncanonical": "edited from the user pages: UUIDField never emits upper case",
    "err_503_starting": "authentik answers this before it can be asked for it",
    "err_non_json_body": "the proxy in front of authentik writes it, not authentik",
    "tokens_self_api": "probe against a live instance, recorded straight into this corpus",
    "tokens_self_nonexpiring": "probe against a live instance, recorded straight into this corpus",
    "golden": "the desired state the four read pages yield, derived by hand from them",
}

# The fields a row keeps. The README lists both sets; this is the same list.
USER_KEYS = {"pk", "username", "name", "is_active", "groups", "groups_obj", "email", "type", "uuid"}
GROUP_KEYS = {"pk", "num_pk", "name", "parents", "parents_obj", "users", "users_obj", "children",
              "children_obj"}


def load(path):
    return json.loads(path.read_text())


def rows(doc):
    body = doc.get("response", {}).get("body")
    return body.get("results", []) if isinstance(body, dict) else []


def kind(row):
    if "username" in row:
        return "user", USER_KEYS
    if "num_pk" in row:
        return "group", GROUP_KEYS
    return None, None


def has_key(node, name):
    if isinstance(node, dict):
        return name in node or any(has_key(v, name) for v in node.values())
    if isinstance(node, list):
        return any(has_key(v, name) for v in node)
    return False


def main():
    problems = []
    present = {p.stem for p in HERE.glob("*.json")}
    for name in sorted(present - set(PROVENANCE)):
        problems.append("%s.json states no provenance: add it to PROVENANCE" % name)
    for name in sorted(set(PROVENANCE) - present):
        problems.append("PROVENANCE names %s.json, which is not here" % name)

    checked = 0
    for name in sorted(present & set(PROVENANCE)):
        where = "%s.json" % name
        doc = load(HERE / where)
        if "response" not in doc:
            continue  # golden.json is a desired state, not an exchange
        checked += 1

        headers = set(doc["response"].get("headers", {}))
        if headers != {"content-type"}:
            problems.append("%s keeps headers %s; the trim keeps content-type alone"
                            % (where, sorted(headers)))
        if has_key(doc["response"]["body"], "autocomplete"):
            problems.append("%s keeps the autocomplete block, which the read never looks at"
                            % where)

        for row in rows(doc):
            what, expected = kind(row)
            if what is None:
                continue
            if set(row) != expected:
                problems.append("%s: a %s row carries %s, not the derived field set (%s)"
                                % (where, what, sorted(set(row)), sorted(expected)))
                break
            for key in (k for k in row if k.endswith("_obj")):
                if row[key] is not None:
                    problems.append("%s: %s is %r, not null -- the corpus tests a reader that "
                                    "follows the id arrays" % (where, key, row[key]))

        source = PROVENANCE[name]
        recording = RECORDED / ("%s.json" % source)
        if not recording.exists():
            continue  # the entry is a reason, not a recording
        rec = load(recording)
        if doc["response"]["status"] != rec["response"]["status"]:
            problems.append("%s answers %s; %s.json recorded %s"
                            % (where, doc["response"]["status"], source,
                               rec["response"]["status"]))
        rec_rows = {k for row in rows(rec) for k in row}
        for row in rows(doc):
            invented = set(row) - rec_rows
            if invented and rec_rows:
                problems.append("%s: a row carries %s, which %s.json never returned"
                                % (where, sorted(invented), source))
                break
        here, there = doc["response"]["body"], rec["response"]["body"]
        if isinstance(here, dict) and isinstance(there, dict):
            a, b = here.get("pagination"), there.get("pagination")
            if isinstance(a, dict) and isinstance(b, dict) and set(a) != set(b):
                problems.append("%s: pagination carries %s; %s.json returned %s"
                                % (where, sorted(a), source, sorted(b)))

    for line in problems:
        print("authentik corpus: %s" % line, file=sys.stderr)
    if problems:
        return 1
    print("authentik corpus: %d files state their provenance, %d exchanges hold the derivation"
          % (len(present), checked))
    return 0


if __name__ == "__main__":
    sys.exit(main())
