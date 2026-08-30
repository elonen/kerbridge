#!/usr/bin/env python3
"""Generate local signed authentik access-token fixtures for the kerbridge-broker
verifier. Throwaway RSA key, never committed.

An authentik access token is the ID token's dataclass re-encoded, so
`authentik/providers/oauth2/id_token.py` at `version/2026.8.0` is the whole wire
contract these claims follow. What is authentik's rather than Entra's:

- `iss` carries the application slug and ends in a slash;
- `aud` and `azp` are both the client id, and `azp` is written after the scope
  mappings are merged, so it is the one claim a mapping cannot rewrite;
- `sub` is the bare lowercase hyphenated user uuid, under `sub_mode: user_uuid`;
- there is **no `nbf`**, on any token, in any version -- so there is no
  future-`nbf` negative here, and none is fabricated;
- `uid` is a fresh 40-character random string per token and is not a user id.

The JWK is emitted without `x5c`/`x5t`, which authentik does publish: `jwks::parse`
reads none of them, and minting a self-signed X.509 to carry them would buy no
coverage.
"""
import base64
import hashlib
import secrets
import string
import sys
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import ed25519

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tokenforge import TokenForge

# The corpus directory: this is where the broker's tests read it from. There is
# no --out here, unlike the two other generators -- nothing runs this corpus live,
# because the tier that exercises authentik signs a real user in.
FIX = Path(__file__).parent

# ---- The configured application, as `[provider_config]` states it ----
URL = "https://authentik.example.site"
SLUG = "kerbridge"
CLIENT_ID = "kerbridge"
ISSUER = f"{URL}/application/o/{SLUG}/"

# A second OAuth2 provider and application on the same instance. Two providers
# sharing one Signing Key receive the same JWK -- `get_jwk_for_key` is keyed on
# the key pair alone -- so a token minted here verifies against our JWKS and its
# kid resolves. That is what makes the wrong-audience negative a real token
# rather than a forgery.
NEIGHBOUR_SLUG = "wiki"
NEIGHBOUR_CLIENT_ID = "wiki"

USER_UUID = "6d1b9c4a-2f3e-4a7b-8c5d-0e1f2a3b4c5d"
OTHER_USER_UUID = "8e2c7b5d-3a4f-4b6c-9d0e-1f2a3b4c5d6e"
# What `sub_mode: hashed_user_id`, authentik's default, puts there instead:
# sha256 of the user id and the install id, which no directory read can filter on.
HASHED_SUB = "b9dcd6a9d1f0e2b6c0f7a2d3e4b5c6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3"


def authentik_kid(pem):
    """The key id authentik computes for a key pair, from the key pair alone.

    A `pre_save` receiver sets it to `base64url(sha512(the PEM text))` with the
    padding stripped -- 86 characters, where every other IdP in this bench names
    its keys. Reproducing the derivation is what makes the corpus catch a
    verifier that assumed a kid is short. authentik writes PKCS#1 where
    `tokenforge` writes PKCS#8 and the hash is over the PEM text, so this is the
    same derivation over different bytes rather than the same string.
    """
    return base64.urlsafe_b64encode(hashlib.sha512(pem).digest()).rstrip(b"=").decode()


def generate_id(length=40):
    """`authentik.lib.generators.generate_id`: `[A-Za-z0-9]` of that length."""
    return "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))


KID_UNKNOWN = "fixture-key-unknown"
KID_EDDSA = "fixture-key-ed25519"

forge = TokenForge(FIX, authentik_kid, KID_UNKNOWN)
NOW = forge.now
issue = forge.issue

# An Ed25519 key beside the RSA one, published and unusable. authentik derives
# the signing algorithm from the key type, so an operator who selects an Ed25519
# certificate gets EdDSA on every token -- an algorithm the compiled allowlist
# does not carry. `jwks::parse` drops the JWK for its key type; the token is
# refused for its algorithm before any key is looked up, which is the ordering
# the negative below exists to hold.
eddsa = ed25519.Ed25519PrivateKey.generate()
eddsa_jwk = jwt.algorithms.OKPAlgorithm.to_jwk(eddsa.public_key(), as_dict=True)
eddsa_jwk.update({"kid": KID_EDDSA, "use": "sig", "alg": "EdDSA"})
forge.write_jwks(foreign=[eddsa_jwk])

# A provider with no Signing Key publishes this and nothing else: `keys` is
# created lazily and only for a truthy JWK, so the document has no `keys` member
# at all. It is the single most likely operator error on this IdP, and it is the
# default. `neg_alg_hs256` below is the other half of the same provider -- with
# `signing_key` null, `jwt_key` falls back to the client secret and HS256.
(FIX / "jwks_empty.json").write_text("{}\n")


def base_claims():
    return {
        "iss": ISSUER,
        "sub": USER_UUID,
        "aud": CLIENT_ID,
        "exp": NOW + 3600,
        "iat": NOW - 60,
        "auth_time": NOW - 60,
        "acr": "goauthentik.io/providers/oauth2/default",
        "name": "Bench User",
        "given_name": "Bench User",
        "preferred_username": "benchuser",
        "nickname": "benchuser",
        "groups": ["KerBridge Users"],
        "azp": CLIENT_ID,
        "uid": generate_id(),
        "scope": "openid profile offline_access",
    }


def id_token_claims():
    """The same sign-in's ID token: `to_jwt()` writes nothing after the merge."""
    claims = base_claims()
    for access_token_only in ("azp", "uid", "scope"):
        del claims[access_token_only]
    return claims


def neighbour_claims():
    """An honest token, minted by the neighbouring application for the same person."""
    claims = base_claims()
    claims.update(
        {
            "iss": f"{URL}/application/o/{NEIGHBOUR_SLUG}/",
            "aud": NEIGHBOUR_CLIENT_ID,
            "azp": NEIGHBOUR_CLIENT_ID,
        }
    )
    return claims


def algorithm_confusion_claims():
    claims = base_claims()
    claims["sub"] = OTHER_USER_UUID
    return claims


# ---- The positive ----
#
# One, and RS256. authentik signs RS256 -- the self-signed certificate every
# install creates is RSA-4096 -- and the RS/PS sweep in `entra-token/` already
# exercises the rest of the shared allowlist, which is a property of the verifier
# rather than of either IdP.
issue("positive", base_claims())

# ---- The shared conformance set ----
forge.conformance_set(
    base_claims,
    wrong_audience_claims=neighbour_claims,
    algorithm_confusion_claims=algorithm_confusion_claims,
)

# ---- authentik's own negatives ----
#
# The "same identifier is used for all providers" issuer mode, which publishes
# the bare instance root and stops telling one application from another. It is
# not the default, and it fails loudly on every token rather than misfiling one.
c = base_claims(); c["iss"] = f"{URL}/"
issue("neg_wrong_issuer", c)

# `aud` says this application, `azp` says another. No real authentik emits it:
# `azp` is written unconditionally after the scope mappings merge, so it is the
# claim a mapping cannot forge and `aud` is the one it can. This fixture is the
# only one that fails if the `azp` half of that rule is dropped.
c = base_claims(); c["azp"] = NEIGHBOUR_CLIENT_ID
issue("neg_azp_mismatch", c)

# The ID token from the same sign-in, carrying no `azp` at all. An adapter that
# read the ID token instead of the access token would refuse every honest
# authentik token, so the access-token half of the rule is a fixture too.
issue("neg_id_token", id_token_claims())

# `sub_mode` left at its default: the broker's subject is then a value the
# directory cannot be filtered on, and the two faces could never agree.
c = base_claims(); c["sub"] = HASHED_SUB
issue("neg_sub_hashed", c)

# An allowlisted algorithm over a key published for a different one. Correctly
# signed with the right key material, so only the JWK's own `alg` refuses it.
issue("neg_alg_not_published_for_key", base_claims(), alg="RS384")

# The algorithm an Ed25519 Signing Key produces, published in the JWKS above.
issue("neg_alg_eddsa", base_claims(), kid=KID_EDDSA, alg="EdDSA", signer=eddsa)

# Not a JWT at all
(FIX / "neg_garbage.jwt").write_text("this-is-not.a-jwt")

print("wrote", len(list(FIX.glob("*.jwt"))), "token fixtures +", "jwks.json to", FIX)
