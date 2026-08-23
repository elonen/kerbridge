#!/usr/bin/env python3
"""Auth-code + PKCE against the live tenant, loopback redirect.

Mirrors what kerbridge-client will do: public client, no secret, 127.0.0.1 redirect on
an ephemeral port (tests the documented "port is ignored for loopback" rule).

  python3 pkce.py <label> [port]

Writes secrets/user_token_<label>.json and prints sanitized claims.
"""
import base64
import hashlib
import http.server
import json
import os
import secrets
import sys
import threading
import urllib.parse
import urllib.request

cfg = json.load(open("config.json"))
LABEL = sys.argv[1] if len(sys.argv) > 1 else "member"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 53682
AUTHORITY = "https://login.microsoftonline.com/%s" % cfg["tenant_id"]
SCOPE = "api://%s/%s openid profile offline_access" % (cfg["broker_app_id"], cfg["scope_value"])
REDIRECT = "http://127.0.0.1:%d" % PORT

verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).decode().rstrip("=")
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
state = secrets.token_urlsafe(16)
result = {}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        result.update({k: v[0] for k, v in q.items()})
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h2>KerBridge spike: you can close this tab.</h2></body></html>")

    def log_message(self, *a):
        pass


auth_url = AUTHORITY + "/oauth2/v2.0/authorize?" + urllib.parse.urlencode(
    {
        "client_id": cfg["helper_app_id"],
        "response_type": "code",
        "redirect_uri": REDIRECT,
        "response_mode": "query",
        "scope": SCOPE,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
)
with open("authorize_url.txt", "w") as f:
    f.write(auth_url)
print("AUTHORIZE_URL_WRITTEN redirect=%s" % REDIRECT, flush=True)

srv = http.server.HTTPServer(("127.0.0.1", PORT), Handler)
t = threading.Thread(target=srv.serve_forever, daemon=True)
t.start()

import time

deadline = time.time() + 300
while time.time() < deadline and "code" not in result and "error" not in result:
    time.sleep(1)
srv.shutdown()

if "code" not in result:
    print("NO_CODE", json.dumps(result))
    sys.exit(1)
if result.get("state") != state:
    print("STATE_MISMATCH")
    sys.exit(1)

body = urllib.parse.urlencode(
    {
        "client_id": cfg["helper_app_id"],
        "grant_type": "authorization_code",
        "code": result["code"],
        "redirect_uri": REDIRECT,
        "code_verifier": verifier,
        "scope": SCOPE,
    }
).encode()
req = urllib.request.Request(AUTHORITY + "/oauth2/v2.0/token", data=body, method="POST")
req.add_header("Content-Type", "application/x-www-form-urlencoded")
try:
    tok = json.load(urllib.request.urlopen(req))
except urllib.error.HTTPError as e:
    print("TOKEN_ERROR", e.read().decode()[:800])
    sys.exit(1)

path = os.path.join("secrets", "user_token_%s.json" % LABEL)
with open(path, "w") as f:
    json.dump(tok, f, indent=2)
os.chmod(path, 0o600)

at = tok["access_token"]
hdr = json.loads(base64.urlsafe_b64decode(at.split(".")[0] + "=="))
p = at.split(".")[1]
claims = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
print("HEADER:", json.dumps(hdr))
print("CLAIM_KEYS:", sorted(claims.keys()))
for k in ["ver", "iss", "aud", "azp", "azpacr", "scp", "tid", "oid", "idtyp", "acct", "idp", "roles", "sub"]:
    if k in claims:
        print("  %-8s = %s" % (k, claims[k]))
print("token_type:", tok.get("token_type"), "| granted scope:", tok.get("scope"))
print("SAVED", path)
