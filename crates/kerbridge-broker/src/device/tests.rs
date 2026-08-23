use super::*;

const AUD: &str = "kerbridge://EXAMPLE.SITE";
const NOW: i64 = 1_785_000_000;
const OID: &str = "33334444-dddd-5555-eeee-6666ffff7777";
const IDENTITY: &str = "kb1|entra|33334444-dddd-5555-eeee-6666ffff7777";

/// A software key. There is no attestation, so this exercises every check
/// the server makes -- which is what keeps the whole server side testable
/// without a TPM. Do not write hermetic tests that need one.
pub struct SoftKey {
    pair: ring::signature::EcdsaKeyPair,
    pub point: Vec<u8>,
}

impl SoftKey {
    pub fn new() -> Self {
        let rng = ring::rand::SystemRandom::new();
        let doc = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            doc.as_ref(),
            &rng,
        )
        .unwrap();
        let point = {
            use ring::signature::KeyPair;
            pair.public_key().as_ref().to_vec()
        };
        Self { pair, point }
    }

    pub fn thumbprint(&self) -> String {
        thumbprint(&self.point)
    }

    pub fn assertion(&self, payload: &serde_json::Value) -> String {
        let encoded = b64url_encode(payload.to_string().as_bytes());
        let rng = ring::rand::SystemRandom::new();
        let sig = self.pair.sign(&rng, encoded.as_bytes()).unwrap();
        format!("{encoded}.{}", b64url_encode(sig.as_ref()))
    }
}

fn payload(key: &SoftKey, nonce: &str) -> serde_json::Value {
    serde_json::json!({
        "identity": IDENTITY,
        "key": b64url_encode(&key.point),
        "nonce": nonce,
        "aud": AUD,
        "exp": NOW + 60,
    })
}

fn nonces() -> (Nonces, ring::rand::SystemRandom) {
    (Nonces::new(Duration::from_secs(120), 16), ring::rand::SystemRandom::new())
}

#[test]
fn accepts_a_signed_assertion_and_reduces_it_to_an_identity_and_a_key() {
    let (store, rng) = nonces();
    let key = SoftKey::new();
    let nonce = store.issue(&rng, NOW).unwrap();
    let proof = verify(&key.assertion(&payload(&key, &nonce)), AUD, &store, NOW).unwrap();
    assert_eq!(proof.identity.subject(), OID);
    assert_eq!(proof.thumbprint, key.thumbprint());
    assert!(kerbridge_core::grant::is_thumbprint(&proof.thumbprint));
}

/// An assertion a real TPM signed, recorded once and checked from then on
/// without one -- `MS_PLATFORM_CRYPTO_PROVIDER` on Windows 11 build 10.0.26200
/// aarch64, 2026-08-09, through the same `NCryptExportKey`/`NCryptSignHash`
/// calls `kerbridge_client::device` makes. Everything else here signs with
/// `ring`, so nothing else would notice if CNG's fixed `r || s` and this
/// verifier stopped agreeing -- they would agree with themselves and be wrong
/// together.
#[test]
fn an_assertion_a_tpm_signed_verifies() {
    const RECORDED: &str = "eyJhdWQiOiJrZXJicmlkZ2U6Ly9FWEFNUExFLlNJVEUiLCJleHAiOjE3ODUwMDAwNjAsImlkZW50aXR5Ijoia2IxfGVudHJhfDMzMzM0NDQ0LWRkZGQtNTU1NS1lZWVlLTY2NjZmZmZmNzc3NyIsImtleSI6IkJMRG13OEVjbGFNa280VFNwR2psZUFPYTlzZThDMnJmSHJlaC1EejdXSmZ2aXBPQWljMWJzVF9sa3M2eTEtWjhVeUVSWC1OLWFFQk1uVHJYVjdHZ3R0cyIsIm5vbmNlIjoiY21WamIzSmtaV1F0YjI0dFlTMVVVRTAifQ.o9TH9pkQTd4O68CYUbJFhn2W_A2OGiioGs8jT2drOquPasnvrGs45dHCLq79oI5G6wmsfa4Tq1OlO3XALlbTxA";
    const NONCE: &str = "cmVjb3JkZWQtb24tYS1UUE0";

    // Planted rather than issued: the assertion was signed over this nonce
    // on the day it was recorded, and no store since has issued that value.
    let store = Nonces::new(Duration::from_secs(120), 16);
    store.inner.lock().unwrap().insert(NONCE.to_string(), NOW + 60);
    let proof = verify(RECORDED, AUD, &store, NOW).unwrap();
    assert_eq!(proof.identity.subject(), OID);
    assert_eq!(proof.thumbprint, "HYb-SxqU7LiAGuhVIzxiXWAI9YjNJiFtONrKFO8VGTU");
}

/// The replay defense itself. A captured assertion is complete and correctly
/// signed; what stops it is that its nonce is gone.
#[test]
fn a_replayed_assertion_is_refused() {
    let (store, rng) = nonces();
    let key = SoftKey::new();
    let nonce = store.issue(&rng, NOW).unwrap();
    let assertion = key.assertion(&payload(&key, &nonce));
    assert!(verify(&assertion, AUD, &store, NOW).is_ok());
    assert_eq!(
        verify(&assertion, AUD, &store, NOW).unwrap_err().0,
        "nonce is unknown, expired or already spent"
    );
}

/// An invalid signature must not spend a nonce, or an unauthenticated flood
/// could invalidate the one a real device is about to use.
#[test]
fn a_bad_signature_leaves_the_nonce_alone() {
    let (store, rng) = nonces();
    let key = SoftKey::new();
    let nonce = store.issue(&rng, NOW).unwrap();
    let other = SoftKey::new();
    // Signed by a different key than the one the payload names.
    let forged = {
        let p = payload(&key, &nonce);
        let encoded = b64url_encode(p.to_string().as_bytes());
        let sig = other.assertion(&p);
        let (_, sig) = sig.split_once('.').unwrap();
        format!("{encoded}.{sig}")
    };
    assert_eq!(verify(&forged, AUD, &store, NOW).unwrap_err().0, "signature does not verify");
    // Still spendable by its rightful holder.
    assert!(verify(&key.assertion(&payload(&key, &nonce)), AUD, &store, NOW).is_ok());
}

fn refused(assertion: &str, store: &Nonces, expected: &str, name: &str) {
    match verify(assertion, AUD, store, NOW) {
        Ok(_) => panic!("{name} was accepted"),
        Err(Reject(why)) => {
            assert!(why.contains(expected), "{name}: got {why:?}, wanted {expected:?}")
        }
    }
}

#[test]
fn refuses_everything_that_is_not_a_current_assertion_for_this_deployment() {
    let (store, rng) = nonces();
    let key = SoftKey::new();
    // Each case is an otherwise-valid assertion with one thing wrong, over a
    // nonce that has not been spent -- so what refuses it is the named
    // defect and not a leftover from the case before.
    let tampered = |field: &str, value: serde_json::Value, expected: &str| {
        let nonce = store.issue(&rng, NOW).unwrap();
        let mut payload = payload(&key, &nonce);
        payload[field] = value;
        refused(&key.assertion(&payload), &store, expected, field);
    };
    tampered("aud", "kerbridge://OTHER.SITE".into(), "aud is not this deployment");
    tampered("exp", (NOW - 1).into(), "assertion has expired");
    tampered("exp", (NOW + 31_536_000).into(), "valid for more than");
    tampered("key", b64url_encode(&[0u8; 65]).into(), "uncompressed point");
    tampered("identity", "kb9|a|b|c".into(), "claimed identity does not decode");

    refused(
        &key.assertion(&payload(&key, "made-up")),
        &store,
        "nonce is unknown",
        "a nonce nobody issued",
    );
    refused("junk", &store, "two-part", "not an assertion at all");
}

#[test]
fn nonces_expire_and_the_store_is_bounded() {
    let store = Nonces::new(Duration::from_secs(120), 2);
    let rng = ring::rand::SystemRandom::new();
    let old = store.issue(&rng, NOW).unwrap();
    assert!(store.issue(&rng, NOW).is_some());
    assert!(store.issue(&rng, NOW).is_none(), "the ceiling refuses rather than evicting");
    // Past its lifetime it is neither spendable nor occupying a slot.
    assert!(!store.consume(&old, NOW + 121));
    assert!(store.issue(&rng, NOW + 121).is_some());
}

#[test]
fn a_grant_handle_is_eight_hex_digits_and_nothing_else() {
    assert!(is_grant_handle("1ac34f00"));
    for bad in ["1ac34f0", "1ac34f000", "../etc", "1ac34f0g", ""] {
        assert!(!is_grant_handle(bad), "accepted {bad:?}");
    }
}
