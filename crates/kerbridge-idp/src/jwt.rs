//! The JOSE shapes and the one signature check more than one adapter needs,
//! kept where neither owns them.
//!
//! `pub(crate)` and nothing else. A public type here would commit every future
//! adapter to a protocol [`IdentityProvider`](crate::IdentityProvider) never
//! asked for: the credential it takes is opaque, and need not be a JWT.

use serde::Deserialize;
use serde::de::DeserializeOwned;

use crate::jwks::{self, Jwks, RsaKey};
use crate::{Reject, b64url, reject};

/// `aud`. RFC 7519 §4.1.3 allows both forms: one string, or an array of them.
#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    pub(crate) fn accepts(&self, want: &str) -> bool {
        match self {
            Self::One(a) => a == want,
            Self::Many(all) => all.iter().any(|a| a == want),
        }
    }
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
}

/// Everything an adapter does with a JWT *before* policy: structure, the
/// algorithm allowlist, the key, and the signature over the exact bytes
/// presented. What the claims then have to say is the adapter's own, and stays
/// there.
///
/// A defect in these shared checks is an authentication bypass. The algorithm
/// is allowlisted before key lookup. RSA is the only reachable verification
/// routine, so symmetric algorithm confusion has no code path.
///
/// The claims are deserialized only after the signature holds, which is what
/// makes every check an adapter writes afterwards a check against a payload
/// whose authenticity is already established.
pub(crate) async fn verified_claims<C: DeserializeOwned>(
    token: &str,
    jwks: &Jwks,
) -> Result<C, Reject> {
    // Validate structure before decoding or fetching a key.
    let mut parts = token.split('.');
    let (Some(header_b64), Some(claims_b64), Some(sig_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(reject("not a three-part JWT"));
    };

    let header: Header =
        serde_json::from_slice(&b64url(header_b64).map_err(|_| reject("header is not base64url"))?)
            .map_err(|_| reject("header is not JSON"))?;

    // Apply the crate-wide algorithm allowlist before key selection. A JWK can
    // narrow this choice with its own `alg`.
    let Some(primitive) = jwks::algorithm(&header.alg) else {
        return Err(reject(format!("disallowed alg {:?}", header.alg)));
    };
    let kid = header.kid.ok_or_else(|| reject("header carries no kid"))?;

    // Verify the exact encoded bytes, not a reconstructed token.
    let signature = b64url(sig_b64).map_err(|_| reject("signature is not base64url"))?;
    let signed_len = header_b64.len() + 1 + claims_b64.len();
    let signed = &token.as_bytes()[..signed_len];
    let outcome = jwks
        .with_key(&kid, |key| {
            // Refused on the key's published `alg` before the signature is
            // computed at all, so a correct signature does not reach a key the
            // IdP published for something else.
            (!key.pins(&header.alg)).then(|| verify_rsa(key, primitive, signed, &signature))
        })
        .await
        .ok_or_else(|| reject(format!("unknown kid {kid:?}")))?;
    let Some(verified) = outcome else {
        return Err(reject(format!("key {kid:?} is not published for alg {:?}", header.alg)));
    };
    if !verified {
        return Err(reject("signature does not verify"));
    }

    // Read claims only after signature verification.
    serde_json::from_slice(&b64url(claims_b64).map_err(|_| reject("claims are not base64url"))?)
        .map_err(|_| reject("claims are not JSON"))
}

/// The one verification routine this crate has, and it is RSA. `primitive` came
/// from [`jwks::algorithm`], so it is an allowlisted algorithm by construction
/// rather than by a check somewhere above.
///
/// ring takes the two components as JWKS states them, so no key encoding is
/// written here. Do not reintroduce one: hand-built ASN.1 in this routine is
/// the single defect that would forge any identity.
fn verify_rsa(
    key: &RsaKey,
    primitive: &'static ring::signature::RsaParameters,
    signed: &[u8],
    signature: &[u8],
) -> bool {
    ring::signature::RsaPublicKeyComponents {
        n: trim_leading_zeros(&key.modulus),
        e: trim_leading_zeros(&key.exponent),
    }
    .verify(primitive, signed, signature)
    .is_ok()
}

/// ring wants each component big-endian with no leading zero. RFC 7517 does not
/// forbid an IdP from publishing one, so this does not assume it away.
fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_significant = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first_significant..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_component_is_trimmed_to_what_ring_accepts() {
        assert_eq!(trim_leading_zeros(&[0x00, 0x00, 0x7f]), &[0x7f]);
        assert_eq!(trim_leading_zeros(&[0x01, 0x00, 0x01]), &[0x01, 0x00, 0x01]);
        // No significant byte at all: an empty slice, not a panic.
        assert_eq!(trim_leading_zeros(&[0x00, 0x00]), &[] as &[u8]);
        assert_eq!(trim_leading_zeros(&[]), &[] as &[u8]);
    }

    /// The same key and signature, with the modulus stated both ways: bare, and
    /// with the leading zero RFC 7517 permits. A verifier that handed the padded
    /// form straight to ring would refuse a token the IdP signed correctly.
    #[test]
    fn a_modulus_published_with_a_leading_zero_still_verifies() {
        let dir = crate::entra::tests::fixture_dir();
        let body = std::fs::read_to_string(dir.join("jwks.json")).unwrap();
        let mut key = jwks::parse(&body).unwrap().remove("fixture-key-2026-07").unwrap();
        let jwt = std::fs::read_to_string(dir.join("positive_delegated.jwt")).unwrap();
        let (signed, sig) = jwt.trim().rsplit_once('.').unwrap();
        let signature = b64url(sig).unwrap();
        let primitive = jwks::algorithm("RS256").unwrap();

        assert!(verify_rsa(&key, primitive, signed.as_bytes(), &signature), "bare modulus");
        key.modulus.insert(0, 0x00);
        assert!(verify_rsa(&key, primitive, signed.as_bytes(), &signature), "padded modulus");
    }
}
