//! Device-grant assertions: the second identity proof `POST /ticket` accepts.
//!
//! A granted device proves that it holds a key, instead of a cloud IdP token.
//! This module does exactly that much: it turns a signed assertion into a
//! claimed [`ExternalIdentity`] and the thumbprint of the key that signed it. It
//! decides nothing about admission. The directory answers all of that, on every
//! exchange, thus revocation behaves as it does on the browser path.
//!
//! `DESIGN.md` @ External identity model names this seam -- "a direct provider
//! adapter can emit the same `ExternalIdentity`" -- thus nothing downstream of
//! here can tell the two proofs apart.
//!
//! # The wire format
//!
//! ```text
//! <base64url(payload JSON)>.<base64url(signature)>
//! ```
//!
//! There is no header, because a header has nothing to negotiate.
//! The client does not choose the algorithm: the stored grant names
//! it, one entry today, and an algorithm that this build cannot verify has no
//! key material as far as this build knows. A JOSE header would only bring back
//! the `alg` confusion that the token verifier makes unreachable.
//!
//! The signature is ECDSA P-256 with SHA-256, in the fixed `r || s` form that
//! CNG's `NCryptSignHash` produces. It covers the ASCII bytes of the encoded
//! payload exactly as presented, never a re-encoding of them.
//!
//! # What the payload binds
//!
//! - `key` -- the raw uncompressed public point. The broker stores only a
//!   thumbprint, thus the key itself must arrive with the assertion.
//! - `identity` -- the `kb1|` value that the client claims to be. A claim on
//!   someone else's identity fails, because the thumbprint must also be on the
//!   object claimed. See `DESIGN.md` @ Device grants.
//! - `nonce` -- a one-shot value that this broker issued. The replay window.
//! - `aud` -- this deployment, thus an assertion captured here cannot be
//!   presented to another broker.
//! - `exp` -- a short ceiling on top of the nonce, thus a stockpiled assertion
//!   is stale as well as spent.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use kerbridge_core::ExternalIdentity;
use kerbridge_idp::{Reject, b64url};
use ring::rand::SecureRandom;
use serde::Deserialize;

/// An uncompressed P-256 point: the `0x04` tag and two 32-byte coordinates.
const P256_POINT_LEN: usize = 65;

/// Fixed-form ECDSA P-256: `r || s`, 32 bytes each.
const P256_SIGNATURE_LEN: usize = 64;

/// How far ahead of now an assertion may claim to be valid, in seconds. The
/// nonce already makes each assertion single-use. This stops a device from a
/// stockpile of a year's assertions over nonces it collected in an afternoon.
const MAX_ASSERTION_LIFETIME: i64 = 300;

fn reject(msg: impl Into<String>) -> Reject {
    Reject(msg.into())
}

#[derive(Deserialize)]
struct Payload {
    identity: String,
    key: String,
    nonce: String,
    aud: String,
    exp: i64,
}

/// A verified assertion, reduced to two things: who the client says it is, and
/// which key said so. The directory must still check both.
#[derive(Debug)]
pub struct DeviceProof {
    pub identity: ExternalIdentity,
    pub thumbprint: String,
}

/// Verify an assertion and spend its nonce.
///
/// The signature is checked before the nonce is spent, thus an unsigned flood
/// cannot empty the store. A *replayed* valid assertion still fails, because its
/// nonce is already gone.
pub fn verify(
    assertion: &str,
    audience: &str,
    nonces: &Nonces,
    now: i64,
) -> Result<DeviceProof, Reject> {
    let mut parts = assertion.split('.');
    let (Some(payload_b64), Some(sig_b64), None) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(reject("not a two-part device assertion"));
    };

    let payload: Payload = serde_json::from_slice(
        &b64url(payload_b64).map_err(|_| reject("payload is not base64url"))?,
    )
    .map_err(|_| reject("payload is not JSON"))?;

    if payload.aud != audience {
        return Err(reject("aud is not this deployment"));
    }
    if now >= payload.exp {
        return Err(reject("assertion has expired"));
    }
    if payload.exp - now > MAX_ASSERTION_LIFETIME {
        return Err(reject(format!("assertion is valid for more than {MAX_ASSERTION_LIFETIME}s")));
    }

    let key = b64url(&payload.key).map_err(|_| reject("key is not base64url"))?;
    if key.len() != P256_POINT_LEN || key[0] != 0x04 {
        return Err(reject(format!("key is not a {P256_POINT_LEN}-byte uncompressed point")));
    }
    let signature = b64url(sig_b64).map_err(|_| reject("signature is not base64url"))?;
    if signature.len() != P256_SIGNATURE_LEN {
        return Err(reject("signature is not fixed-form ECDSA P-256"));
    }
    ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, &key)
        .verify(payload_b64.as_bytes(), &signature)
        .map_err(|_| reject("signature does not verify"))?;

    if !nonces.consume(&payload.nonce, now) {
        return Err(reject("nonce is unknown, expired or already spent"));
    }

    let identity = ExternalIdentity::decode(&payload.identity)
        .map_err(|e| reject(format!("claimed identity does not decode: {e}")))?;
    Ok(DeviceProof { identity, thumbprint: thumbprint(&key) })
}

/// The stored form of a public key: unpadded base64url of SHA-256 over the raw
/// uncompressed point. One derivation, here, because the tray computes the same
/// value before it registers, and a disagreement would deny every granted login.
pub fn thumbprint(key: &[u8]) -> String {
    b64url_encode(ring::digest::digest(&ring::digest::SHA256, key).as_ref())
}

fn b64url_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// The nonces that this broker issued and has not seen spent.
///
/// One-shot and short-lived, which is the whole replay defense: an assertion is
/// bound to a value that only this process handed out, and a spend removes it.
/// In memory on purpose -- a restart invalidates every outstanding nonce, and a
/// client that finds one refused asks for another.
pub struct Nonces {
    ttl: Duration,
    /// The ceiling on outstanding nonces. Above it, `GET /nonce` refuses and
    /// does not evict: eviction would let a flood of requests invalidate the
    /// nonce that a legitimate device is about to use.
    max: usize,
    inner: Mutex<HashMap<String, i64>>,
}

impl Nonces {
    pub fn new(ttl: Duration, max: usize) -> Self {
        Self { ttl, max, inner: Mutex::new(HashMap::new()) }
    }

    /// A fresh nonce, or `None` when too many are outstanding.
    pub fn issue(&self, rng: &ring::rand::SystemRandom, now: i64) -> Option<String> {
        let mut bytes = [0u8; 16];
        rng.fill(&mut bytes).ok()?;
        let nonce = b64url_encode(&bytes);
        let expiry = now + self.ttl.as_secs() as i64;

        let mut inner = self.inner.lock().expect("nonce store");
        inner.retain(|_, &mut exp| exp > now);
        if inner.len() >= self.max {
            return None;
        }
        inner.insert(nonce.clone(), expiry);
        Some(nonce)
    }

    /// Spend a nonce. `false` when it was never issued, has expired, or was
    /// already spent -- the client hears one answer for all three.
    fn consume(&self, nonce: &str, now: i64) -> bool {
        let mut inner = self.inner.lock().expect("nonce store");
        inner.remove(nonce).is_some_and(|expiry| expiry > now)
    }

    pub fn ttl_seconds(&self) -> u64 {
        self.ttl.as_secs()
    }
}

/// Is this an operator-typed grant handle: eight hex digits, as
/// `kerbridge_core::grant::short_id` renders one?
///
/// The handle reaches a comparison and a log line, never a filter. But it
/// arrives in a URL path, and a permissive test here would put arbitrary client
/// text in both.
pub fn is_grant_handle(id: &str) -> bool {
    id.len() == 8 && id.bytes().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
pub mod tests;
