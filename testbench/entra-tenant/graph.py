#!/usr/bin/env python3
"""Thin Microsoft Graph client for the live-tenant spike.

Usage:
  python3 graph.py GET /v1.0/organization
  python3 graph.py POST /v1.0/groups '<json>'
  python3 graph.py PATCH /v1.0/applications/{id} '<json>'
  python3 graph.py DELETE /v1.0/groups/{id}
  python3 graph.py RAW GET <absolute-url>          # e.g. follow a deltaLink

Credentials come from secrets/admin_token.json (delegated admin, device code) or,
with --app, from secrets/sync_app.json (client credentials, least-privilege app).
Adds --headers to dump response headers. Never commit this directory.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SEC = os.path.join(HERE, "secrets")
GRAPH = "https://graph.microsoft.com"
CLI_CLIENT = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
TENANT_ID = os.environ.get("ENTRA_TENANT_ID") or json.load(
    open(os.path.join(os.path.dirname(__file__), "config.json"))
)["tenant_id"]


def _http(method, url, token, body=None, extra_headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "Bearer " + token)
    if data:
        req.add_header("Content-Type", "application/json")
    for k, v in (extra_headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read().decode() or "{}"
            return r.status, dict(r.headers), raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode() or "{}"
        return e.code, dict(e.headers), raw


def _refresh_delegated(tok):
    body = urllib.parse.urlencode(
        {
            "grant_type": "refresh_token",
            "client_id": CLI_CLIENT,
            "refresh_token": tok["refresh_token"],
            "scope": "https://graph.microsoft.com/.default offline_access openid profile",
        }
    ).encode()
    req = urllib.request.Request(
        "https://login.microsoftonline.com/" + TENANT_ID + "/oauth2/v2.0/token", data=body, method="POST"
    )
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req) as r:
        new = json.load(r)
    new["obtained_at"] = int(time.time())
    with open(os.path.join(SEC, "admin_token.json"), "w") as f:
        json.dump(new, f, indent=2)
    return new


def delegated_token():
    with open(os.path.join(SEC, "admin_token.json")) as f:
        tok = json.load(f)
    if tok["obtained_at"] + tok.get("expires_in", 3600) - 300 < time.time():
        tok = _refresh_delegated(tok)
    return tok["access_token"]


def app_token(cfg_name="sync_app.json", scope=GRAPH + "/.default"):
    """Client-credentials token for a registered confidential app."""
    with open(os.path.join(SEC, cfg_name)) as f:
        cfg = json.load(f)
    cache_key = os.path.join(SEC, "cache_" + cfg_name.replace(".json", "") + "_" + str(abs(hash(scope))) + ".json")
    if os.path.exists(cache_key):
        with open(cache_key) as f:
            c = json.load(f)
        if c["obtained_at"] + c.get("expires_in", 3600) - 300 > time.time():
            return c["access_token"]
    body = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": cfg["client_id"],
            "client_secret": cfg["client_secret"],
            "scope": scope,
        }
    ).encode()
    req = urllib.request.Request(
        "https://login.microsoftonline.com/%s/oauth2/v2.0/token" % cfg["tenant_id"], data=body, method="POST"
    )
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req) as r:
            tok = json.load(r)
    except urllib.error.HTTPError as e:
        print(e.read().decode())
        sys.exit(1)
    tok["obtained_at"] = int(time.time())
    with open(cache_key, "w") as f:
        json.dump(tok, f, indent=2)
    os.chmod(cache_key, 0o600)
    return tok["access_token"]


def call(method, path, body=None, use_app=False, headers=None):
    token = app_token() if use_app else delegated_token()
    url = path if path.startswith("http") else GRAPH + path
    return _http(method, url.replace(" ", "%20"), token, body, headers)


def main():
    argv = [a for a in sys.argv[1:]]
    use_app = "--app" in argv
    show_headers = "--headers" in argv
    argv = [a for a in argv if not a.startswith("--")]
    if argv[0] == "RAW":
        method, path = argv[1], argv[2]
        body = json.loads(argv[3]) if len(argv) > 3 else None
    else:
        method, path = argv[0], argv[1]
        body = json.loads(argv[2]) if len(argv) > 2 else None
    status, hdrs, raw = call(method, path, body, use_app)
    if show_headers:
        print("HTTP", status)
        for k in ("Cache-Control", "Retry-After", "Location", "request-id", "client-request-id", "Date"):
            if k in hdrs:
                print("%s: %s" % (k, hdrs[k]))
        print("---")
    else:
        print("HTTP", status)
    try:
        print(json.dumps(json.loads(raw), indent=2))
    except json.JSONDecodeError:
        print(raw)
    sys.exit(0 if status < 400 else 1)


if __name__ == "__main__":
    main()
