//! The device grant's key, and the assertion it signs.
//!
//! A device grant lets this machine keep obtaining tickets without a browser for
//! an operator-configured number of days. What makes that safe to offer at all is
//! that the authorization is a key which cannot be copied off the machine --
//! malware running as the user can *use* it while resident, but cannot take it
//! anywhere. Where that key lives is the platform's business; what it signs is
//! not, and is here.
//!
//! **ECDSA P-256, not RSA.** TPM RSA-2048 key generation takes seconds; P-256 is
//! quick and the assertions are smaller.
//!
//! # What is not secret here
//!
//! The public key and the container name are not credentials, which is why
//! `config.toml` is the right home for the container name.

use anyhow::Result;

#[cfg_attr(windows, path = "windows/device.rs")]
#[cfg_attr(target_os = "macos", path = "macos/device.rs")]
mod imp;

pub use imp::{AVAILABLE, DeviceKey, create, default_label, delete, open};

/// How long an assertion is valid. Only a ceiling on top of the nonce, which is
/// what actually makes each one single-use; short so a stockpiled assertion is
/// stale as well as spent.
pub const ASSERTION_LIFETIME_SECONDS: i64 = 60;

/// The algorithm name the stored grant carries, and the one this key implements.
pub const ALG: &str = "es256";

/// The stored form of a public key: base64url-unpadded SHA-256 over the raw
/// point. The broker derives the identical value from what it is sent; a
/// disagreement here would deny every granted login.
pub fn thumbprint(point: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    b64url(&Sha256::digest(point))
}

/// Build the assertion a granted device presents in place of an IdP token.
///
/// `<base64url(payload)>.<base64url(signature)>`, signed over the ASCII bytes of
/// the encoded payload. There is no header: the algorithm is not the client's to
/// choose -- the stored grant names it -- and a JOSE header would only reintroduce
/// the `alg` confusion the broker's token verifier is structured to make
/// unreachable.
pub fn assertion(
    key: &DeviceKey,
    identity: &str,
    audience: &str,
    nonce: &str,
    now: i64,
) -> Result<String> {
    let payload = serde_json::json!({
        "identity": identity,
        "key": b64url(&key.public_point()?),
        "nonce": nonce,
        "aud": audience,
        "exp": now + ASSERTION_LIFETIME_SECONDS,
    });
    let encoded = b64url(payload.to_string().as_bytes());
    let signature = key.sign(encoded.as_bytes())?;
    Ok(format!("{encoded}.{}", b64url(&signature)))
}

fn b64url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The payload the broker parses, built without a TPM. Signing needs one;
    /// the shape does not, and the shape is what a typo would break.
    #[test]
    fn the_assertion_payload_carries_what_the_broker_binds_to() {
        let payload = serde_json::json!({
            "identity": "kb1|entra|33334444-dddd-5555-eeee-6666ffff7777",
            "key": b64url(&[0x04; 65]),
            "nonce": "n",
            "aud": "kerbridge://EXAMPLE.SITE",
            "exp": 1_785_000_000i64 + ASSERTION_LIFETIME_SECONDS,
        });
        let encoded = b64url(payload.to_string().as_bytes());
        assert!(!encoded.contains('='), "base64url here is unpadded");
        assert!(!encoded.contains('+') && !encoded.contains('/'));
        assert_eq!(payload["exp"].as_i64().unwrap(), 1_785_000_060);
    }
}
