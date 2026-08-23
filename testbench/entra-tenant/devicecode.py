#!/usr/bin/env python3
"""Device-code flow to obtain a delegated admin Microsoft Graph token.

Uses the well-known Azure CLI public client (same mechanism as
`az login --use-device-code`). Token cached in secrets/admin_token.json.
Never commit anything from this directory.
"""
import json
import os
import sys
import time
import urllib.parse
import urllib.request

CLI_CLIENT = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Microsoft Azure CLI
AUTHORITY = "https://login.microsoftonline.com/organizations"
# First-party clients only accept .default against Graph (AADSTS65002 otherwise);
# the preauthorized set is what `az` itself uses.
SCOPES = "https://graph.microsoft.com/.default offline_access openid profile"

HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN_FILE = os.path.join(HERE, "secrets", "admin_token.json")


def post(url, data):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def save(tok):
    tok["obtained_at"] = int(time.time())
    with open(TOKEN_FILE, "w") as f:
        json.dump(tok, f, indent=2)
    os.chmod(TOKEN_FILE, 0o600)


def start():
    status, dc = post(AUTHORITY + "/oauth2/v2.0/devicecode", {"client_id": CLI_CLIENT, "scope": SCOPES})
    if status != 200:
        print(json.dumps(dc, indent=2))
        sys.exit(1)
    print("USER_CODE:", dc["user_code"])
    print("VERIFY_URL:", dc["verification_uri"])
    with open(os.path.join(HERE, "secrets", "devicecode.json"), "w") as f:
        json.dump(dc, f, indent=2)
    return dc


def poll(dc):
    deadline = time.time() + dc.get("expires_in", 900)
    interval = dc.get("interval", 5)
    while time.time() < deadline:
        status, tok = post(
            AUTHORITY + "/oauth2/v2.0/token",
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": CLI_CLIENT,
                "device_code": dc["device_code"],
            },
        )
        if status == 200:
            save(tok)
            print("TOKEN_OK scopes=", tok.get("scope", "")[:400])
            return tok
        err = tok.get("error")
        if err == "authorization_pending":
            time.sleep(interval)
            continue
        if err == "slow_down":
            interval += 5
            time.sleep(interval)
            continue
        print("ERROR", json.dumps(tok, indent=2))
        sys.exit(1)
    print("TIMEOUT")
    sys.exit(1)


def refresh():
    with open(TOKEN_FILE) as f:
        tok = json.load(f)
    status, new = post(
        AUTHORITY + "/oauth2/v2.0/token",
        {
            "grant_type": "refresh_token",
            "client_id": CLI_CLIENT,
            "refresh_token": tok["refresh_token"],
            "scope": SCOPES,
        },
    )
    if status != 200:
        print("ERROR", json.dumps(new, indent=2))
        sys.exit(1)
    save(new)
    print("REFRESHED")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "login"
    if cmd == "login":
        poll(start())
    elif cmd == "start":
        start()
    elif cmd == "poll":
        with open(os.path.join(HERE, "secrets", "devicecode.json")) as f:
            poll(json.load(f))
    elif cmd == "refresh":
        refresh()
