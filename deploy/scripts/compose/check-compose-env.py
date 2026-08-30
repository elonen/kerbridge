#!/usr/bin/env python3
"""The `.env` -> process environment translation `compose.yaml` performs is what
it claims, and no component reads a `KB_*` variable at all.

Two environment namespaces used to meet here. `.env` classifies by *where the
operator gets the value* -- `AD_*` from the realm they are creating, `ENTRA_*`
from the portal, `LDAP_*` from the directory, unprefixed for what the operator
decides here rather than reads off something else. `KB_*` classified by *which
component consumes it*, and the `environment:` blocks were the whole of the
translation between them.

Every component's own configuration is in the [config set](../configs), one
cross-checked whole with its defaults held to the committed templates by
`kerbridge_core::config::template`'s tests. So the second namespace is empty,
and the first check below is what keeps it empty: a `KB_*` key reappearing in
`compose.yaml` is a setting that a binary reads from two places, or from a place
`kbconfig check` cannot validate.

One decision does still have to travel, and travels as argv instead:
`KB_ALLOW_EXAMPLE_REALM` becomes `kbsetup realm`'s `--allow-example-realm`, the
flag a native DC's operator types. That is not a component reading its
configuration from the environment, and it is checked here too -- unset must
reach the binary as no argument at all.

What is left needing this file at all is the overlays, which do still translate:
`compose.mockidp.yaml` hands the mock IdP an address `.env` states unprefixed,
and a tenant id that has to be the one its source file states -- compose cannot
read TOML, so that pair is two copies of one value with nothing but this holding
them together.

`docker compose config` would do the interpolation for us and is exactly what we
must not depend on: this runs in `make test-fast`, which is deliberately
Docker-free, and a check that only runs where Docker does is a check that does
not run. The subset of the interpolation grammar compose actually uses is small
enough to implement here (`interpolate`, below), and the file is
held to that subset by parsing it strictly and refusing what it does not
understand.

Exit 0 and print a count, or list every disagreement and exit 1.
"""

import os
import re
import sys

# --- Compose variable interpolation -----------------------------------------
#
# `${VAR}`, `${VAR:-default}`, `${VAR-default}`, `${VAR:+alt}`, `${VAR+alt}`,
# `${VAR:?msg}`, `${VAR?msg}`, `$VAR` and `$$`. Defaults nest
# (`${A:-https://${B}:8443}`), which is why this scans rather than substitutes by
# regex. Anything outside that grammar fails here loudly rather than being
# interpolated wrongly.

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_BODY = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(?::?[-+?])?", re.S)


class ComposeError(Exception):
    pass


def _braced(raw, i, where):
    """Scan from just past `${` to the matching `}`. Returns (body, index after)."""
    depth, start = 1, i
    while i < len(raw):
        if raw.startswith("${", i):
            depth += 1
            i += 2
        elif raw[i] == "}":
            depth -= 1
            if depth == 0:
                return raw[start:i], i + 1
            i += 1
        else:
            i += 1
    raise ComposeError(f"{where}: unterminated ${{ in {raw!r}")


def _expand(body, env, where):
    m = _BODY.match(body)
    name = m.group(1) if m else ""
    op = body[len(name) : m.end()] if m else ""
    arg = body[m.end() :] if m else ""
    # No operator, yet something followed the name.
    if not op and len(body) != len(name):
        raise ComposeError(f"{where}: ${{{body}}} uses syntax this checker does not implement")
    value = env.get(name)
    # `:-` and `:+` treat empty as unset; `-` and `+` treat it as set.
    present = value != "" if (op.startswith(":") and value is not None) else value is not None
    if not op:
        return value or ""
    if op.endswith("-"):
        return value if present else interpolate(arg, env, where)
    # `?` states that the deployment must supply the value. Compose aborts on an
    # unset one; here it is what the value would have been, so the checks below
    # judge a configured deployment rather than the abort.
    if op.endswith("?"):
        if present:
            return value
        raise ComposeError(f"{where}: ${{{body}}} is unset -- {arg}")
    return interpolate(arg, env, where) if present else ""


def interpolate(raw, env, where):
    out, i = [], 0
    while i < len(raw):
        if raw[i] != "$":
            out.append(raw[i])
            i += 1
        elif raw.startswith("$$", i):
            out.append("$")
            i += 2
        elif raw.startswith("${", i):
            body, i = _braced(raw, i + 2, where)
            out.append(_expand(body, env, where))
        elif m := _NAME.match(raw, i + 1):
            out.append(env.get(m.group(0), ""))
            i = m.end()
        else:
            out.append("$")
            i += 1
    return "".join(out)


# --- Reading the `environment:` blocks ---------------------------------------
#
# A mapping key alone or anchored (`authentik-server: &authentik`), and a merge
# of one (`<<: *authentik`). `compose.authentik.yaml` gives one image's
# environment to three services that way, so a walk that reads neither reads
# none of the largest block in the file.

_KEY = re.compile(r"([A-Za-z0-9_.-]+):(?:\s+&([A-Za-z0-9_.-]+))?$")
_MERGE = re.compile(r"<<:\s*\*([A-Za-z0-9_.-]+)$")


def environments(path):
    """{service: {key: uninterpolated value}} from one compose file.

    Indentation-driven rather than YAML-parsed: PyYAML is not in the standard
    library and `make test-fast` takes no dependencies. The shape it accepts is
    narrow on purpose -- two-space service keys, four-space `environment:`,
    six-space `KEY: value`, either mapping key optionally anchored, and a
    four-space `<<:` merging one service into another.

    Every departure from that shape is refused rather than read past: reading
    past one is how a service goes uncovered while the checks below still
    report success.
    """
    services, anchors, merges, declared = {}, {}, [], []
    service, in_services, in_env = None, False, False
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            body = line.strip()
            if not body or body.startswith("#"):
                continue
            indent = len(line) - len(line.lstrip(" "))
            if indent == 0:
                in_services, service, in_env = body == "services:", None, False
            elif not in_services:
                continue
            elif indent == 2:
                # A key this does not recognize -- quoted, or trailing a comment
                # -- would leave `service` on the one before it, and hand that
                # service the next one's keys.
                if not (m := _KEY.match(body)):
                    raise ComposeError(f"{path}: {body!r} is not a service key this reads")
                service, in_env = m.group(1), False
                services.setdefault(service, {})
                if m.group(2):
                    anchors[m.group(2)] = service
            elif service is None:
                continue
            elif indent == 4 and body.startswith("<<:"):
                # Only a merge of one anchor. A sequence (`<<: [*a, *b]`, or `<<:`
                # over indented `- *a` lines) is YAML this does not implement, and
                # reading past it drops every key the service merged.
                if not (m := _MERGE.match(body)):
                    raise ComposeError(f"{path}: {service} merges {body!r}, not <<: *anchor")
                merges.append((service, m.group(1)))
                in_env = False
            elif indent == 4:
                m = _KEY.match(body)
                in_env = bool(m) and m.group(1) == "environment"
                if in_env:
                    declared.append(service)
                elif body.startswith("environment:"):
                    raise ComposeError(f"{path}: {service} opens environment as {body!r}")
            elif in_env and indent == 6:
                key, sep, value = body.partition(":")
                if not sep or not _NAME.fullmatch(key):
                    raise ComposeError(f"{path}: {service} passes {body!r}, which is not KEY: value")
                services[service][key] = value.strip().strip("\"'")
            elif in_env:
                # Deeper than six: a block scalar or a nested value, whose key
                # above it was read as if the whole value were on that line.
                raise ComposeError(f"{path}: {service} passes {body!r}, indented past KEY: value")

    # A merged key yields to one the service states itself, as YAML's does. In
    # file order, so a service merged from is already resolved when merged.
    for target, alias in merges:
        if alias not in anchors:
            raise ComposeError(f"{path}: <<: *{alias} names no service anchor in this file")
        for key, value in services[anchors[alias]].items():
            services[target].setdefault(key, value)

    for service in declared:
        if not services[service]:
            raise ComposeError(f"{path}: {service} states environment: and this reads no key from it")
    # Reading no service at all is the shape drift with no symptom: every check
    # below still passes, over nothing.
    if not services:
        raise ComposeError(f"{path}: this reads no service from it")
    return services


def translate(root, files, dotenv):
    """The process environment each service ends up with, for one `.env`."""
    merged = {}
    for name in files:
        path = os.path.join(root, "deploy", name)
        for service, raw in environments(path).items():
            into = merged.setdefault(service, {})
            for key, value in raw.items():
                into[key] = interpolate(value, dotenv, f"{name} @ {service}.{key}")
    return merged


# --- The table ---------------------------------------------------------------
#
# Each case is (what it pins, .env, {(service, KB_* key): expected}).

BASE = ["compose.yaml"]
MOCK = ["compose.yaml", "compose.mockidp.yaml"]

CASES = [
    (
        "the mock IdP is told its sign-in address and the tenant id whose issuer "
        "the broker accepts, both unprefixed in .env and prefixed at the process",
        MOCK,
        {
            ("mockidp", "IDP_EXTERNAL_URL"): "https://kerbridge.example.site:8443",
            ("mockidp", "IDP_TENANT_ID"): "aaaabbbb-0000-cccc-1111-dddd2222eeee",
        },
        {
            "OIDC_AUTHORITY": "https://kerbridge.example.site:8443",
            "MOCK_IDP_TENANT_ID": "aaaabbbb-0000-cccc-1111-dddd2222eeee",
        },
    ),
]


def run_table(root):
    broken = []
    for case in CASES:
        what, files, expected = case[0], case[1], case[2]
        dotenv = case[3] if len(case) > 3 else {}
        actual = translate(root, files, dotenv)
        for (service, key), want in expected.items():
            got = actual.get(service, {}).get(key)
            if got is None:
                broken.append(f"{what}: {service} is passed no {key} at all")
            elif got != want:
                broken.append(f"{what}: {service} {key} is {got!r}, expected {want!r}")
    return len(CASES), broken


# --- The one value stated on both sides of the namespace ----------------------
#
# Caddy cannot read TOML, so the address the broker binds is stated twice: as
# `listen` in the config set, and as what compose hands Caddy to proxy to. Two
# independent defaults for one address, and a disagreement is a 502 on every
# ticket with nothing in either file looking wrong.


def run_broker_upstream(root):
    compose = translate(root, BASE, {})
    proxied = compose.get("caddy", {}).get("BROKER_UPSTREAM")
    template = os.path.join(root, "deploy", "configs", "broker.toml.example")
    # `#?`: the template comments the line out, and the value it shows there is
    # the default -- what the broker binds unless the operator sets the option.
    with open(template, encoding="utf-8") as fh:
        m = re.search(r'^#?listen\s*=\s*"([^"]+)"', fh.read(), re.M)
    bound = m.group(1) if m else None
    if bound is None:
        return ["broker.toml.example shows no listen address"]
    if proxied != bound:
        return [
            f"caddy proxies to {proxied!r} and the broker binds {bound!r}: a deployment "
            "that sets neither gets a 502 on every ticket"
        ]
    return []


# --- The one KB_* key that does reach a component, and does so as argv ---------
#
# The example-realm decision is the operator's, and `kbsetup realm` is what acts
# on it, so it has to travel. As an `environment:` key it would be exactly what
# the rule below refuses; as a flag it is what an operator types on a native DC.
# Two properties matter and neither is visible by reading the line: unset must
# interpolate to no argument at all, and set must produce the flag kbsetup
# accepts. Held here rather than by `docker compose config`, which needs Docker.


def service_field(path, service, field):
    """One four-space scalar field of one service, uninterpolated.

    The same narrow indentation walk `environments` uses, and narrow for the
    same reason: a file that drifts out of the shape makes this return None,
    which the caller reports, rather than reading something else.
    """
    want, cur, in_services = f"{field}:", None, False
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            body = line.strip()
            if not body or body.startswith("#"):
                continue
            indent = len(line) - len(line.lstrip(" "))
            if indent == 0:
                in_services, cur = body == "services:", None
            elif not in_services:
                continue
            elif indent == 2 and (m := _KEY.match(body)):
                cur = m.group(1)
            elif indent == 4 and cur == service and body.startswith(want):
                return body[len(want) :].strip()
    return None


def run_example_realm_flag(root):
    where = "compose.yaml @ realm.command"
    raw = service_field(os.path.join(root, "deploy", "compose.yaml"), "realm", "command")
    if raw is None:
        return [f"{where} is absent: kbsetup realm is never told the example-realm decision"]
    off = interpolate(raw, {}, where)
    on = interpolate(raw, {"KB_ALLOW_EXAMPLE_REALM": "1"}, where)
    broken = []
    if off:
        broken.append(
            f"{where} interpolates to {off!r} with KB_ALLOW_EXAMPLE_REALM unset: the "
            "gate would be disarmed on deployments that never asked for it"
        )
    if on != "--allow-example-realm":
        broken.append(
            f"{where} interpolates to {on!r} with KB_ALLOW_EXAMPLE_REALM=1, expected "
            "'--allow-example-realm'"
        )
    return broken


# --- No component is configured through the environment -----------------------

FILES = [
    "compose.yaml",
    "compose.ci.yaml",
    "compose.ci-entra.yaml",
    "compose.authentik.yaml",
    "compose.mockidp.yaml",
    "compose.nas.yaml",
]


def run_no_kb_keys(root):
    """Every `KB_*` key any compose file passes, which must be none of them."""
    # The keys as written, uninterpolated: this asks what a service is *passed*,
    # and a value that cannot be expanded without a .env is still a key. The
    # total is printed because reading nothing also passes.
    written, total = set(), 0
    for name in FILES:
        for service, env in environments(os.path.join(root, "deploy", name)).items():
            total += len(env)
            written |= {(service, key) for key in env if key.startswith("KB_")}
    broken = [
        f"{service} is passed {key}: a component's configuration belongs in the config "
        "set, where kbconfig check validates it"
        for service, key in sorted(written)
    ]
    return len(FILES), total, broken


def main(root):
    cases, broken = run_table(root)
    files, keys, more = run_no_kb_keys(root)
    broken += more
    broken += run_broker_upstream(root)
    broken += run_example_realm_flag(root)

    if broken:
        print(f"{len(broken)} disagreement(s) in the compose environment:", file=sys.stderr)
        for b in broken:
            print(f"  {b}", file=sys.stderr)
        return 1

    print(f"compose env: {cases} translation case(s) hold")
    print(f"compose env: {keys} key(s) in {files} compose file(s), none of them KB_*")
    print("compose env: caddy's upstream is the address broker.toml binds")
    print("compose env: the example-realm decision reaches kbsetup as argv, and only when made")
    return 0


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    deploy = os.path.dirname(os.path.dirname(os.path.dirname(here)))
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else deploy))
