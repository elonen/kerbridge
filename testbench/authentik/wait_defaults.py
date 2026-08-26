#!/usr/bin/env python3
"""Exit 0 once every object `kerbridge-bench.yaml` !Finds actually exists.

Separate from authcode.sh only because a heredoc inside a heredoc is a trap of
its own. See the `wait_for_defaults` comment there for why this gate exists:
/-/health/ready/ goes 200 before the worker has finished applying authentik's
own shipped blueprints, and a blueprint applied into that window fails with a
serializer error that names the wrong thing.
"""

import json
import sys
import urllib.request

NEEDED = [
    "/api/v3/flows/instances/?slug=default-provider-authorization-implicit-consent",
    "/api/v3/flows/instances/?slug=default-provider-invalidation-flow",
    "/api/v3/flows/instances/?slug=default-authentication-flow",
    "/api/v3/crypto/certificatekeypairs/?name=authentik%20Self-signed%20Certificate",
    # The one a new provider does not get on its own, and without which there is
    # no refresh token no matter what the client asks for.
    "/api/v3/propertymappings/provider/scope/"
    "?managed=goauthentik.io%2Fproviders%2Foauth2%2Fscope-offline_access",
]


def count(base: str, token: str, path: str) -> int:
    req = urllib.request.Request(base + path, headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.load(resp)["pagination"]["count"]


def main() -> int:
    base, token = sys.argv[1], sys.argv[2]
    missing = [p for p in NEEDED if count(base, token, p) != 1]
    for path in missing:
        print("still missing: %s" % path, file=sys.stderr)
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
