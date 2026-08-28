#!/usr/bin/env python3
"""Generate local signed Entra v2-format access-token fixtures for the
kerbridge-broker verifier. Throwaway RSA key, never committed.

Claim shapes follow the v2.0 access-token examples and claim reference:
- https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens
- https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference
"""
import argparse
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tokenforge import TokenForge

# The corpus directory by default: this is where the broker's tests read it from.
# A wrong destination fails silently -- the regeneration lands elsewhere and the
# stale corpus keeps passing.
#
# --out is for the live run (deploy/scripts/bench/ci-stack.sh), which needs a
# corpus inside its own validity window without touching the committed one. The
# signing key follows it: compose.ci.yaml mounts the key into mockidp from the
# same directory.
_cli = argparse.ArgumentParser(description=__doc__)
_cli.add_argument("--out", type=Path, default=Path(__file__).parent,
                  help="directory to write the corpus into")
FIX = _cli.parse_args().out
FIX.mkdir(parents=True, exist_ok=True)

# ---- Configured broker policy (mirrors .env keys in DESIGN.md) ----
TENANT_ID = "aaaabbbb-0000-cccc-1111-dddd2222eeee"          # configured tenant
BROKER_API_CLIENT_ID = "11112222-bbbb-3333-cccc-4444dddd5555"  # kerbridge-broker API app
PUBLIC_CLIENT_ID = "22223333-cccc-4444-dddd-5555eeee6666"      # the client public-client app
SCOPE = "access_as_user"
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"

WRONG_TENANT = "99998888-ffff-7777-eeee-666655554444"
USER_OID = "33334444-dddd-5555-eeee-6666ffff7777"
# A second ordinary person in the same tenant. The delegation path needs two
# admitted callers to say anything: one who is in an account's delegate group and
# one who is not, so that a refusal can be shown to be about delegation rather
# than about admission.
OTHER_USER_OID = "44445555-eeee-6666-ffff-7777aaaa8888"
SP_OID = "aaaa1111-2222-3333-4444-bbbbcccc0000"  # service principal oid (app-only case)

KID_GOOD = "fixture-key-2026-07"
KID_UNKNOWN = "fixture-key-unknown"
# One published key per non-Entra algorithm the verifier accepts. Separate kids
# rather than one unpinned key, because a JWK's `alg` pins it: the verifier must
# refuse KID_GOOD used with RS384, and that refusal is only visible if the
# corpus has a key for which RS384 *is* right.
KID_BY_ALG = {"RS384": "fixture-key-rs384", "RS512": "fixture-key-rs512",
              "PS256": "fixture-key-ps256", "PS384": "fixture-key-ps384",
              "PS512": "fixture-key-ps512"}

# The per-key issuer member mirrors the live Entra v2 keys document. Other
# providers do not carry it, so it remains with Entra's provider-specific data.
forge = TokenForge(
    FIX,
    KID_GOOD,
    KID_UNKNOWN,
    jwk_fields={"issuer": "https://login.microsoftonline.com/{tenantid}/v2.0"},
)
# JWKS the verifier trusts: the same key material under every kid, differing
# only in the `alg` each is published for.
forge.write_jwks((kid, alg) for alg, kid in KID_BY_ALG.items())
NOW = forge.now
issue = forge.issue

def base_claims():
    return {
        "aud": BROKER_API_CLIENT_ID,
        "iss": ISSUER,
        "iat": NOW - 60,
        "nbf": NOW - 60,
        "exp": NOW + 3600,
        "aio": "AXQAi/fixtureopaque==",
        "azp": PUBLIC_CLIENT_ID,
        "azpacr": "0",
        "name": "Alice Example",
        "oid": USER_OID,
        "preferred_username": "alice@example.site",
        "rh": "I",
        "scp": SCOPE,
        "sub": "HKZpfaHyWadeOouYlitjrI-fixture-pairwise",
        "tid": TENANT_ID,
        "uti": str(uuid.uuid4())[:22],
        "ver": "2.0",
    }

def algorithm_confusion_claims():
    claims = base_claims()
    claims["oid"] = OTHER_USER_OID
    return claims

def wrong_audience_claims():
    claims = base_claims()
    claims["aud"] = "00000003-0000-0000-c000-000000000000"  # Graph's own resource id
    return claims

# ---- Positive fixtures ----
issue("positive_delegated", base_claims())

# Entra signs RS256, so these are the corpus's only exercise of the rest of the
# allowlist.
for alg, kid in KID_BY_ALG.items():
    issue("positive_%s" % alg.lower(), base_claims(), kid=kid, alg=alg)

# The same token for a different person: only the subject claims move. Generated
# but not committed -- the delegation path it exists for is exercised live.
c = base_claims()
c.update({"oid": OTHER_USER_OID, "sub": "Rp2vKdXqYweTcnBoiljsuA-fixture-pairwise",
          "name": "Bob Example", "preferred_username": "bob@example.site"})
issue("positive_other_user", c)

# ---- Negative fixtures (every case in the work order) ----
c = base_claims(); c["tid"] = WRONG_TENANT
c["iss"] = f"https://login.microsoftonline.com/{WRONG_TENANT}/v2.0"
issue("neg_wrong_tenant", c)

forge.conformance_set(
    base_claims,
    wrong_audience_claims=wrong_audience_claims,
    algorithm_confusion_claims=algorithm_confusion_claims,
)

c = base_claims(); del c["scp"]
issue("neg_missing_scope", c)

c = base_claims(); c["scp"] = "some_other_scope openid"
issue("neg_wrong_scope_value", c)

# App-only (client credentials) shape: no scp, roles + idtyp=app, oid = SP oid,
# azp = the confidential client itself, azpacr = "1".
c = base_claims()
for k in ("scp", "name", "preferred_username"):
    del c[k]
c.update({"roles": ["Ticket.Issue.All"], "idtyp": "app", "oid": SP_OID,
          "sub": SP_OID, "azpacr": "1"})
issue("neg_app_only", c)

c = base_claims(); c["azp"] = "33334444-dddd-5555-eeee-6666ffff7777"
issue("neg_wrong_azp", c)

c = base_claims()
c["nbf"] = NOW + 3600; c["iat"] = NOW + 3600; c["exp"] = NOW + 7200
issue("neg_future_nbf", c)

# An allowlisted algorithm over a key published for a different one. Correctly
# signed with the right key material, so only the JWK's own `alg` refuses it:
# widening the allowlist must not widen what an already-published key covers.
issue("neg_alg_not_published_for_key", base_claims(), kid=KID_GOOD, alg="RS384")

# Malformed claims
c = base_claims(); c["tid"] = "not-a-guid"
issue("neg_malformed_tid", c)

c = base_claims(); del c["oid"]
issue("neg_missing_oid", c)

c = base_claims()  # iss/tid mismatch: correct-looking issuer, foreign tid
c["tid"] = WRONG_TENANT
issue("neg_iss_tid_mismatch", c)

# v1.0-format token for the same API (requestedAccessTokenVersion=1 shape):
# iss = sts.windows.net, appid instead of azp, ver 1.0.
c = base_claims()
c["iss"] = f"https://sts.windows.net/{TENANT_ID}/"
c["ver"] = "1.0"
c["appid"] = c.pop("azp"); c["appidacr"] = c.pop("azpacr")
c["aud"] = f"api://{BROKER_API_CLIENT_ID}"
c["unique_name"] = c.pop("preferred_username")
issue("neg_v1_token", c, headers={"x5t": KID_GOOD})

# Not a JWT at all
(FIX / "neg_garbage.jwt").write_text("this-is-not.a-jwt")

print("wrote", len(list(FIX.glob("*.jwt"))), "token fixtures +", "jwks.json to", FIX)
