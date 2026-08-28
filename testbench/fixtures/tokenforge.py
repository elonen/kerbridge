"""Shared machinery for the signed token-fixture corpora.

An adapter owns its honest claim shape and its claim-level negatives.  This
module owns the signing key, JWKS, and the negatives every adapter must supply
to ``conformance::Forged``.
"""

import base64
import hashlib
import hmac
import json
import time

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class TokenForge:
    """Write one token corpus and the shared conformance cases."""

    def __init__(self, out, kid_good, kid_unknown, *, jwk_fields=None):
        self.out = out
        self.kid_good = kid_good
        self.kid_unknown = kid_unknown
        self.jwk_fields = jwk_fields or {}
        self.now = int(time.time())
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.rogue = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        (self.out / "signing-key.pem").write_bytes(
            self.key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

    def to_jwk(self, key, kid, alg="RS256"):
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        jwk.update({"kid": kid, "use": "sig", "alg": alg, **self.jwk_fields})
        return jwk

    def write_jwks(self, additional_keys=()):
        """Publish the default RS256 key plus ``(kid, alg)`` key aliases."""
        keys = [self.to_jwk(self.key, self.kid_good)]
        keys.extend(self.to_jwk(self.key, kid, alg) for kid, alg in additional_keys)
        (self.out / "jwks.json").write_text(json.dumps({"keys": keys}, indent=1))

    def issue(self, name, claims, *, kid=None, alg="RS256", signer=None, headers=None):
        header = {"typ": "JWT", "kid": kid or self.kid_good}
        if headers:
            header.update(headers)
        if alg == "none":
            token = jwt.encode(claims, None, algorithm="none", headers=header)
        elif alg == "HS256":
            token = jwt.encode(claims, "shared-secret", algorithm="HS256", headers=header)
        else:
            token = jwt.encode(claims, signer or self.key, algorithm=alg, headers=header)
        (self.out / f"{name}.jwt").write_text(token)
        return token

    def conformance_set(self, base_claims, *, wrong_audience, algorithm_confusion_claims=None):
        """Emit the file-backed cases required by ``conformance::Forged``."""
        claims = base_claims()
        claims["aud"] = wrong_audience
        self.issue("neg_wrong_audience", claims)

        claims = base_claims()
        claims["iat"] = self.now - 7200
        claims["nbf"] = self.now - 7200
        claims["exp"] = self.now - 3600
        self.issue("neg_expired", claims)

        self.issue("neg_unknown_kid", base_claims(), kid=self.kid_unknown, signer=self.rogue)
        self.issue("neg_alg_none", base_claims(), alg="none")
        self.issue("neg_alg_hs256", base_claims(), alg="HS256")
        self.issue("neg_alg_none_unknown_kid", base_claims(), kid=self.kid_unknown, alg="none")

        # PyJWT will not name an algorithm it does not implement, and will not
        # take a public key as an HMAC secret.  These are the tokens a library
        # declines to produce, and the refusals are what the suite exercises.
        self._hmac_signed(
            "neg_alg_unknown",
            {"typ": "JWT", "alg": "XS999", "kid": self.kid_good},
            base_claims(),
            b"whatever",
        )

        # This must stay a real algorithm-confusion forgery, not a header-only
        # check: anybody can fetch an IdP's published public key and use it as
        # an HMAC secret to assert an identity of their choosing.
        public_pem = self.key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        confusion_claims = algorithm_confusion_claims or base_claims
        signing_input, signature = self._hmac_signed(
            "neg_alg_confusion",
            {"typ": "JWT", "alg": "HS256", "kid": self.kid_good},
            confusion_claims(),
            public_pem,
        )
        assert hmac.compare_digest(
            signature,
            hmac.new(public_pem, signing_input.encode(), hashlib.sha256).digest(),
        )

    def _hmac_signed(self, name, header, claims, secret):
        signing_input = "%s.%s" % (
            self._b64u(json.dumps(header, separators=(",", ":")).encode()),
            self._b64u(json.dumps(claims, separators=(",", ":")).encode()),
        )
        signature = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
        (self.out / f"{name}.jwt").write_text(f"{signing_input}.{self._b64u(signature)}")
        return signing_input, signature

    @staticmethod
    def _b64u(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
