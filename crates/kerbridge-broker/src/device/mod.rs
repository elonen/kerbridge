//! Device-grant assertions: the second identity proof `POST /ticket` accepts.
//!
//! A granted device proves possession of a key instead of presenting a cloud
//! IdP token. This module does exactly that much -- it turns a signed assertion into
//! a claimed [`ExternalIdentity`] and the thumbprint of the key that signed it.
//! It decides nothing about admission: the directory still answers all of that,
//! on every exchange, which is why revocation semantics are unchanged from the
//! browser path.
//!
//! That seam is the one `DESIGN.md` @ External identity model already names --
//! "a direct provider adapter can emit the same `ExternalIdentity`" -- so nothing
//! downstream of here can tell the two proofs apart.
//!
//! # The wire format
//!
//! ```text
//! <base64url(payload JSON)>.<base64url(signature)>
//! ```
//!
//! Two parts, not three: there is no header, because there is nothing for a
//! header to negotiate. The algorithm is not the client's to choose -- the stored
//! grant names it, one entry today, and a value naming an algorithm this build
//! cannot verify has no key material as far as this build is concerned. A JOSE
//! header would only reintroduce the `alg` confusion the token verifier is
//! structured to make unreachable.
//!
//! The signature is ECDSA P-256 with SHA-256 in the fixed `r || s` form -- what
//! CNG's `NCryptSignHash` produces -- over the ASCII bytes of the encoded
//! payload, exactly as presented rather than over anything re-encoded.
//!
//! # What the payload binds
//!
//! - `key` -- the raw uncompressed public point. The broker stores only a
//!   thumbprint, so the key itself has to arrive with the assertion.
//! - `identity` -- the `kb1|` value the client claims to be. Claiming someone
//!   else's fails, because the thumbprint must be present on the object claimed;
//!   see `DESIGN.md` @ Device grants.
//! - `nonce` -- a one-shot value this broker issued. The replay window.
//! - `aud` -- this deployment, so an assertion captured here cannot be presented
//!   to another broker.
//! - `exp` -- a short ceiling on top of the nonce, so a stockpiled assertion is
//!   stale as well as spent.

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

/// How far ahead of now an assertion may claim to be valid. The nonce already
/// makes each one single-use; this stops a device from stockpiling a year's supply
/// against nonces it collected in an afternoon.
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

/// What a verified assertion establishes: who the client says it is, and which
/// key said so. Both still have to be checked against the directory.
#[derive(Debug)]
pub struct DeviceProof {
    pub identity: ExternalIdentity,
    pub thumbprint: String,
}

/// Verify an assertion, consuming its nonce.
///
/// The signature is checked before the nonce is spent, so an unsigned flood
/// cannot exhaust the store -- and a *replayed* valid assertion still fails,
/// because its nonce is already gone.
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

/// The stored form of a public key: base64url-unpadded SHA-256 over the raw
/// uncompressed point. One derivation, here, because the tray computes the same
/// thing before registering and a disagreement would deny every granted login.
pub fn thumbprint(key: &[u8]) -> String {
    b64url_encode(ring::digest::digest(&ring::digest::SHA256, key).as_ref())
}

fn b64url_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Nonces this broker has issued and not yet seen used.
///
/// One-shot and short-lived, which is the whole replay defense: an assertion is
/// bound to a value only this process handed out, and spending it removes it.
/// Held in memory on purpose -- a restart invalidates every outstanding nonce,
/// and a client that finds one refused asks for another.
pub struct Nonces {
    ttl: Duration,
    /// Outstanding nonces, bounded. Past the ceiling `GET /nonce` refuses rather
    /// than evicting: evicting would let a flood of requests invalidate the
    /// nonce a legitimate device is about to use.
    max: usize,
    inner: Mutex<HashMap<String, i64>>,
}

impl Nonces {
    pub fn new(ttl: Duration, max: usize) -> Self {
        Self { ttl, max, inner: Mutex::new(HashMap::new()) }
    }

    /// A fresh nonce, or `None` if too many are outstanding.
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

    /// Spend a nonce. `false` if it was never issued, has expired, or has
    /// already been used -- all three are one answer to the client.
    fn consume(&self, nonce: &str, now: i64) -> bool {
        let mut inner = self.inner.lock().expect("nonce store");
        inner.remove(nonce).is_some_and(|expiry| expiry > now)
    }

    pub fn ttl_seconds(&self) -> u64 {
        self.ttl.as_secs()
    }
}

/// Is this an operator-typed grant handle -- eight hex digits, as
/// `kerbridge_core::grant::short_id` renders one?
///
/// The handle reaches a comparison and a log line, never a filter, but it
/// arrives in a URL path and a permissive check here would put arbitrary client
/// text in both.
pub fn is_grant_handle(id: &str) -> bool {
    id.len() == 8 && id.bytes().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
pub mod tests;
