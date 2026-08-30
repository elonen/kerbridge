#!/usr/bin/env python3
"""Every reverse proxy in front of the broker passes exactly the broker's routes.

The proxy allows a route list and 404s the rest, so a route the broker gained
and a proxy did not is a 404 at the edge. Nothing reaching the broker directly
can see that, which is why this reads the router itself rather than comparing
the proxy files with each other alone.

`crates/kerbridge-broker/src/main.rs` is the source: its `.route()` calls are
what the program answers. Each proxy is then held to two things -- it accepts
every one of those paths, and it still refuses a path that is not one.

The three proxy files also carry one regexp between them, because they are one
routing decision written three times. A difference is drift whichever file it
is in.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROUTER = ROOT / "crates/kerbridge-broker/src/main.rs"

# Each proxy file, and how its route regexp is spelled there.
PROXIES = {
    "deploy/caddy/routes.caddyfile": re.compile(r"^@api path_regexp (\S+)$", re.M),
    "debian/examples/broker/kerbridge.caddyfile": re.compile(
        r"^\s*@api path_regexp (\S+)$", re.M
    ),
    "debian/examples/broker/kerbridge-nginx.conf": re.compile(
        r"^\s*location ~ (\S+) \{$", re.M
    ),
}

ROUTE = re.compile(r'\.route\(\s*"([^"]+)"')

# What a path parameter is worth when the pattern is tried. A source name is the
# one the documented realm uses; an id stands for a device handle.
SAMPLE = {"{source}": "entra", "{id}": "a1b2c3d4"}

# Paths the proxy must keep away from the broker: `/`, which is served as a
# static page instead, a route that does not exist, a plural that looks like
# one, and two segments past a real route.
#
# One segment past a real route is deliberately *not* here. The pattern carries
# a trailing optional segment for `DELETE /{source}/devices/{id}` and does not
# spell out which route may take it, so `/{source}/ticket/x` is proxied and the
# broker refuses it. That is stated where the pattern is.
REFUSED = ["/", "/admin", "/entra/tickets", "/entra/devices/a/b"]


def sample(route):
    """One concrete path for a route template."""
    for name, value in SAMPLE.items():
        route = route.replace(name, value)
    return route


def main():
    routes = ROUTE.findall(ROUTER.read_text())
    if not routes:
        print(f"FAIL: no .route() calls in {ROUTER.relative_to(ROOT)}")
        return 1
    paths = [sample(route) for route in routes]

    patterns = {}
    bad = []
    for name, spelling in PROXIES.items():
        text = (ROOT / name).read_text()
        found = spelling.search(text)
        if not found:
            bad.append(f"{name}: no route regexp -- the spelling this script knows changed")
            continue
        patterns[name] = found.group(1)
        allowed = re.compile(found.group(1))
        for route, path in zip(routes, paths):
            if not allowed.fullmatch(path):
                bad.append(f"{name}: 404s {path}, which the broker routes as {route}")
        for path in REFUSED:
            if allowed.fullmatch(path):
                bad.append(f"{name}: proxies {path}, which is not a broker route")

    stated = set(patterns.values())
    if len(stated) > 1:
        bad.append("the proxies stand on different regexps: " + ", ".join(sorted(stated)))

    if bad:
        print("FAIL: the edge and the broker's router disagree:")
        print("\n".join(f"       {b}" for b in bad))
        return 1
    print(f"broker routes: {len(routes)} routes, {len(PROXIES)} proxies, all agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
