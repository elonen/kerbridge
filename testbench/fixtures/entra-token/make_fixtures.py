#!/usr/bin/env python3
"""Generate local signed Entra v2-format access-token fixtures for the
kerbridge-broker verifier. Throwaway RSA key, never committed.

Claim shapes follow the v2.0 access-token examples and claim reference:
- https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens
- https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference
"""
import base64
import hashlib
import hmac
import json
import time
import uuid
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = Path(__file__).parent
# Write in place. This used to be HERE/"fixtures", one level below where the
# corpus actually lives and where the broker's tests read it from, so a
# regeneration silently landed nowhere and the stale corpus kept passing.
FIX = HERE

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

# ---- Keys ----
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rogue = rsa.generate_private_key(public_exponent=65537, key_size=2048)

(HERE / "signing-key.pem").write_bytes(
    key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
)

def to_jwk(k, kid, alg="RS256"):
    j = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(k.public_key()))
    j.update({"kid": kid, "use": "sig", "alg": alg,
              # mirror the per-key issuer property of the live v2 keys document
              "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0"})
    return j

# JWKS the verifier trusts: the same key material under every kid, differing
# only in the `alg` each is published for.
(FIX / "jwks.json").write_text(json.dumps(
    {"keys": [to_jwk(key, KID_GOOD)] +
             [to_jwk(key, kid, alg) for alg, kid in KID_BY_ALG.items()]}, indent=1))

NOW = int(time.time())

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

def issue(name, claims, *, kid=KID_GOOD, alg="RS256", signer=None, headers=None):
    hdr = {"typ": "JWT", "kid": kid}
    if headers:
        hdr.update(headers)
    if alg == "none":
        tok = jwt.encode(claims, None, algorithm="none", headers=hdr)
    elif alg == "HS256":
        tok = jwt.encode(claims, "shared-secret", algorithm="HS256", headers=hdr)
    else:
        tok = jwt.encode(claims, signer or key, algorithm=alg, headers=hdr)
    (FIX / f"{name}.jwt").write_text(tok)
    return tok

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

c = base_claims(); c["aud"] = "00000003-0000-0000-c000-000000000000"  # Graph aud
issue("neg_wrong_audience", c)

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
c["iat"] = NOW - 7200; c["nbf"] = NOW - 7200; c["exp"] = NOW - 3600
issue("neg_expired", c)

c = base_claims()
c["nbf"] = NOW + 3600; c["iat"] = NOW + 3600; c["exp"] = NOW + 7200
issue("neg_future_nbf", c)

# Unknown kid: validly signed but with a key the JWKS does not publish.
issue("neg_unknown_kid", base_claims(), kid=KID_UNKNOWN, signer=rogue)

# An allowlisted algorithm over a key published for a different one. Correctly
# signed with the right key material, so only the JWK's own `alg` refuses it:
# widening the allowlist must not widen what an already-published key covers.
issue("neg_alg_not_published_for_key", base_claims(), kid=KID_GOOD, alg="RS384")

issue("neg_alg_none", base_claims(), alg="none")
issue("neg_alg_hs256", base_claims(), alg="HS256")

# The allowlist has to be compared *before* a key is selected, so this one is
# `alg: none` over a kid the JWKS does not publish: a verifier that looked the
# key up first would refuse it for the kid and the ordering would go unnoticed.
issue("neg_alg_none_unknown_kid", base_claims(), kid=KID_UNKNOWN, alg="none")

# The remaining two are assembled by hand: PyJWT will not name an algorithm it
# does not implement, and will not take a public key as an HMAC secret. Both
# refusals are correct, and both are the thing under test -- the corpus needs the
# tokens a library declines to produce.
def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

def hmac_signed(name, header, claims, secret):
    signing_input = "%s.%s" % (
        b64u(json.dumps(header, separators=(",", ":")).encode()),
        b64u(json.dumps(claims, separators=(",", ":")).encode()),
    )
    sig = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    (FIX / ("%s.jwt" % name)).write_text("%s.%s" % (signing_input, b64u(sig)))
    return signing_input, sig

# An allowlist, not a denylist of the algorithms known to be bad.
hmac_signed("neg_alg_unknown", {"typ": "JWT", "alg": "XS999", "kid": KID_GOOD},
            base_claims(), b"whatever")

# Algorithm confusion, for real rather than as a string comparison: HMAC keyed
# with the IdP's *own published public key*, asserting somebody else's identity.
# Anyone can fetch those bytes, so a verifier that dispatched on the token's own
# `alg` would find this signature perfectly valid.
PUBLIC_PEM = key.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
)
c = base_claims(); c["oid"] = OTHER_USER_OID
signing_input, sig = hmac_signed(
    "neg_alg_confusion", {"typ": "JWT", "alg": "HS256", "kid": KID_GOOD}, c, PUBLIC_PEM)
# The fixture is only worth anything if it really would pass a naive verifier --
# one that took `alg` from the token and the key from the published document.
assert hmac.compare_digest(
    sig, hmac.new(PUBLIC_PEM, signing_input.encode(), hashlib.sha256).digest())

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
