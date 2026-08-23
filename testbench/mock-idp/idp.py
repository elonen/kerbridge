#!/usr/bin/env python3
"""A standing-in OIDC authority for bench runs, so the client's real sign-in
path can be exercised without a tenant.

`ci-stack.sh` posts pre-issued fixture JWTs straight at the broker with curl, so
nothing today drives `kerbridge-client`'s authorization-code + PKCE flow. This
serves the three endpoints that flow needs and issues tokens the broker's own
verifier accepts, unmodified.

What it is not: an authorization server. `/authorize` approves everyone who
asks, immediately. It belongs on a bench network and nowhere else.

Two details that are not free choices:

- `iss` stays the `login.microsoftonline.com/<tenant>/v2.0` form whatever host
  this is served from, because `verify.rs::Policy::expected_issuer` builds that
  string from the tenant id and compares it exactly. The address the client
  talks to and the issuer it ends up trusting are separate strings here.
- The signing key is generated at startup and written out as a JWKS for the
  broker to load with `KB_JWKS_FILE`. It deliberately does not reuse
  `testbench/fixtures/entra-token/` -- that corpus's private key is gitignored
  and unavailable, and its `jwks.json` is what `cargo test` verifies the
  committed fixtures against, so writing there would break the unit tests.
"""

import base64
import hashlib
import json
import os
import secrets
import ssl
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# ---- configuration ---------------------------------------------------------
# Defaults mirror testbench/fixtures/entra-token/make_fixtures.py and
# deploy/scripts/bench/seed-demo.sh: the identities the broker is seeded to know.

TENANT_ID = os.environ.get("IDP_TENANT_ID", "aaaabbbb-0000-cccc-1111-dddd2222eeee")
BROKER_API_CLIENT_ID = os.environ.get(
    "IDP_BROKER_API_CLIENT_ID", "11112222-bbbb-3333-cccc-4444dddd5555"
)
PUBLIC_CLIENT_ID = os.environ.get("IDP_PUBLIC_CLIENT_ID", "22223333-cccc-4444-dddd-5555eeee6666")
SCOPE = os.environ.get("IDP_SCOPE", "access_as_user")
ISSUER = os.environ.get("IDP_ISSUER", f"https://login.microsoftonline.com/{TENANT_ID}/v2.0")

# The address the *client* reaches this on -- it goes into the discovery
# document, so it must be the externally valid one, not the bind address.
EXTERNAL = os.environ.get("IDP_EXTERNAL_URL", "https://kerbridge.example.site:8443").rstrip("/")
PORT = int(os.environ.get("IDP_PORT", "8443"))
BIND = os.environ.get("IDP_BIND", "0.0.0.0")

HERE = Path(__file__).parent
STATE = Path(os.environ.get("IDP_STATE_DIR", HERE / ".." / ".." / ".local-tmp" / "mock-idp"))
CERT = os.environ.get("IDP_TLS_CERT")
KEY = os.environ.get("IDP_TLS_KEY")

# Signing. With IDP_SIGNING_KEY set, this adopts an existing corpus key instead
# of generating one -- point it at the `signing-key.pem` that ci-stack.sh's
# make_fixtures.py run leaves in .local-tmp/ci-fixtures/ and a stack already
# mounting that corpus's jwks.json accepts these tokens with no further wiring.
# Unset, it generates its own and you must hand the broker the JWKS it writes.
KEY_FILE = os.environ.get("IDP_SIGNING_KEY")
KID = os.environ.get("IDP_KID", "fixture-key-2026-07" if KEY_FILE else "mock-idp-key")
TOKEN_TTL = int(os.environ.get("IDP_TOKEN_TTL", "3600"))

# name -> (oid, display name, upn). Everyone here must exist in the directory
# with a matching msDS-ExternalDirectoryObjectId or the broker will refuse them,
# which is a seeding problem and not this program's to solve.
USERS = {
    "alice": ("33334444-dddd-5555-eeee-6666ffff7777", "Alice Example", "alice@example.site"),
    "bob": ("44445555-eeee-6666-ffff-7777aaaa8888", "Bob Example", "bob@example.site"),
    "svc-builder": (
        "55556666-ffff-7777-aaaa-8888bbbb9999",
        "Build Service",
        "svc-builder@example.site",
    ),
}
for spec in filter(None, os.environ.get("IDP_EXTRA_USERS", "").split(",")):
    name, oid = spec.split("=", 1)
    USERS[name] = (oid, name, f"{name}@example.site")

# Who the next /authorize issues for. Mutable at runtime because the interesting
# bench cases are "alice authorizes" and "bob is refused", and restarting the
# authority between them would cost the client's whole discovery state.
CURRENT = os.environ.get("IDP_DEFAULT_USER", "alice")

CODES = {}       # code -> {user, challenge, redirect, at}
REFRESH = {}     # refresh token -> user
LOCK = threading.Lock()


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


# ---- signing ---------------------------------------------------------------

if KEY_FILE:
    SIGNING_KEY = serialization.load_pem_private_key(Path(KEY_FILE).read_bytes(), password=None)
else:
    SIGNING_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwks() -> dict:
    j = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(SIGNING_KEY.public_key()))
    j.update({"kid": KID, "use": "sig", "alg": "RS256"})
    return {"keys": [j]}


def issue(user: str) -> str:
    oid, name, upn = USERS[user]
    now = int(time.time())
    claims = {
        "aud": BROKER_API_CLIENT_ID,
        "iss": ISSUER,
        "iat": now - 60,
        "nbf": now - 60,
        "exp": now + TOKEN_TTL,
        "azp": PUBLIC_CLIENT_ID,
        "azpacr": "0",
        "name": name,
        "oid": oid,
        "preferred_username": upn,
        "rh": "I",
        "scp": SCOPE,
        # Pairwise in Entra, and the broker does not key on it -- the identity is
        # built from tid+oid. Stable per user so a capture is readable.
        "sub": b64url(hashlib.sha256(f"{TENANT_ID}:{oid}".encode()).digest())[:22],
        "tid": TENANT_ID,
        "uti": str(uuid.uuid4())[:22],
        "ver": "2.0",
    }
    return jwt.encode(claims, SIGNING_KEY, algorithm="RS256", headers={"typ": "JWT", "kid": KID})


# ---- endpoints -------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("  idp: " + (fmt % args) + "\n")

    def _json(self, code, payload):
        raw = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        url = urlparse(self.path)
        query = {k: v[0] for k, v in parse_qs(url.query).items()}

        if url.path in ("/.well-known/openid-configuration", "/v2.0/.well-known/openid-configuration"):
            self._json(
                200,
                {
                    "issuer": ISSUER,
                    "authorization_endpoint": f"{EXTERNAL}/authorize",
                    "token_endpoint": f"{EXTERNAL}/token",
                    "jwks_uri": f"{EXTERNAL}/keys",
                    "end_session_endpoint": f"{EXTERNAL}/logout",
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                    "subject_types_supported": ["pairwise"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "code_challenge_methods_supported": ["S256"],
                    "scopes_supported": ["openid", "profile", "offline_access", SCOPE],
                },
            )
            return

        if url.path == "/keys":
            self._json(200, jwks())
            return

        if url.path == "/authorize":
            self._authorize(query)
            return

        if url.path == "/logout":
            # RP-initiated logout. Nothing is kept, so this only has to exist and
            # bounce the browser back where it was told to.
            back = query.get("post_logout_redirect_uri")
            if back:
                self.send_response(302)
                self.send_header("Location", back)
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self._json(200, {"ok": True})
            return

        if url.path == "/whoami":
            with LOCK:
                self._json(200, {"current": CURRENT, "known": sorted(USERS)})
            return

        self._json(404, {"error": "no such endpoint"})

    def _authorize(self, query):
        global CURRENT
        missing = [k for k in ("client_id", "redirect_uri", "state", "code_challenge") if k not in query]
        if missing:
            self._json(400, {"error": "invalid_request", "missing": missing})
            return
        if query["client_id"] != PUBLIC_CLIENT_ID:
            self._json(400, {"error": "unauthorized_client", "got": query["client_id"]})
            return
        if query.get("code_challenge_method") != "S256":
            self._json(400, {"error": "invalid_request", "detail": "S256 only"})
            return

        # `login_hint` wins over the selected user, so one bench can drive two
        # identities without a control call in between.
        user = query.get("login_hint", "").split("@")[0]
        with LOCK:
            if user not in USERS:
                user = CURRENT
            code = secrets.token_urlsafe(24)
            CODES[code] = {
                "user": user,
                "challenge": query["code_challenge"],
                "redirect": query["redirect_uri"],
                "at": time.time(),
            }

        target = query["redirect_uri"] + "?" + urlencode({"code": code, "state": query["state"]})
        sys.stderr.write(f"  idp: approving {user} -> {query['redirect_uri']}\n")
        self.send_response(302)
        self.send_header("Location", target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        url = urlparse(self.path)
        if url.path == "/select":
            self._select(url)
            return
        if url.path != "/token":
            self._json(404, {"error": "no such endpoint"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}
        grant = form.get("grant_type")

        if grant == "refresh_token":
            with LOCK:
                user = REFRESH.get(form.get("refresh_token", ""))
            if not user:
                self._json(400, {"error": "invalid_grant"})
                return
            self._issue(user)
            return

        if grant != "authorization_code":
            self._json(400, {"error": "unsupported_grant_type", "got": grant})
            return

        with LOCK:
            entry = CODES.pop(form.get("code", ""), None)
        if not entry:
            self._json(400, {"error": "invalid_grant", "detail": "unknown or spent code"})
            return
        # PKCE is verified rather than waved through: it is the one part of this
        # exchange the client actually implements, so a bench that skipped it
        # would not be testing the client.
        expected = b64url(hashlib.sha256(form.get("code_verifier", "").encode()).digest())
        if expected != entry["challenge"]:
            self._json(400, {"error": "invalid_grant", "detail": "PKCE verifier mismatch"})
            return
        if form.get("redirect_uri") != entry["redirect"]:
            self._json(400, {"error": "invalid_grant", "detail": "redirect_uri mismatch"})
            return

        self._issue(entry["user"])

    def _issue(self, user):
        refresh = secrets.token_urlsafe(32)
        with LOCK:
            REFRESH[refresh] = user
        sys.stderr.write(f"  idp: issued an access token for {user}\n")
        self._json(
            200,
            {
                "token_type": "Bearer",
                "expires_in": TOKEN_TTL,
                "scope": SCOPE,
                "access_token": issue(user),
                "refresh_token": refresh,
            },
        )

    def _select(self, url):
        global CURRENT
        who = {k: v[0] for k, v in parse_qs(url.query).items()}.get("user", "")
        if who not in USERS:
            self._json(400, {"error": "unknown user", "known": sorted(USERS)})
            return
        with LOCK:
            CURRENT = who
        sys.stderr.write(f"  idp: next sign-in will be {who}\n")
        self._json(200, {"current": who})


def main():
    STATE.mkdir(parents=True, exist_ok=True)
    out = STATE / "jwks.json"
    out.write_text(json.dumps(jwks(), indent=2))

    if not (CERT and KEY):
        sys.exit(
            "set IDP_TLS_CERT and IDP_TLS_KEY -- the client requires https and verifies the\n"
            "certificate, so there is no plaintext fallback worth having here"
        )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)

    server = ThreadingHTTPServer((BIND, PORT), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)

    print(f"mock idp on https://{BIND}:{PORT}, advertising {EXTERNAL}", file=sys.stderr)
    print(f"  issuer   {ISSUER}", file=sys.stderr)
    print(f"  jwks     {out}  (point the broker at this with KB_JWKS_FILE)", file=sys.stderr)
    print(f"  users    {', '.join(sorted(USERS))}   (current: {CURRENT})", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    main()
