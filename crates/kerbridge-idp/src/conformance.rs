//! What every adapter must refuse, whatever else it accepts.
//!
//! Run against each adapter from that adapter's own test module, with tokens
//! forged against *its* IdP. An adapter that does not run it is an adapter whose
//! algorithm handling nobody has checked -- and the failure mode of getting this
//! wrong is not a broken login but a silent authentication bypass, which no
//! deployment would notice.

use crate::{IdentityProvider, Reject};

/// One forged credential per thing the suite asserts. Every field is a token
/// that is otherwise well-formed for the adapter under test, with one thing
/// wrong, so what refuses it is the named defect and not an accident.
pub(crate) struct Forged<'a> {
    pub alg_none: &'a str,
    /// `alg: none` *and* a `kid` the IdP does not publish. Refusing this for the
    /// algorithm rather than the key is what proves the allowlist is compared
    /// before any key is looked up -- the ordering the whole defense rests on.
    pub alg_none_unknown_kid: &'a str,
    /// `alg: HS256` with an arbitrary secret.
    pub alg_hs256: &'a str,
    /// `alg: HS256` HMAC-keyed with the IdP's **own published public key**. This
    /// is the actual algorithm-confusion attack rather than a string comparison:
    /// anyone can fetch that key, so a verifier that dispatched on the token's
    /// `alg` would find this signature perfectly valid and admit whatever
    /// identity it asserts.
    pub alg_confusion: &'a str,
    /// A header naming an algorithm nothing has heard of. The allowlist must be
    /// an allowlist, not a denylist of the ones known to be bad.
    pub alg_unknown: &'a str,
    /// Correctly signed, by a key the IdP does not publish.
    pub unknown_kid: &'a str,
    /// Correctly signed, and past its expiry at `now`.
    pub expired: &'a str,
    /// Correctly signed, for a different audience.
    pub wrong_audience: &'a str,
    /// A genuine token whose payload was edited and re-encoded, leaving a
    /// signature over the bytes that used to be there.
    pub tampered: &'a str,
}

pub(crate) async fn run(idp: &dyn IdentityProvider, forged: &Forged<'_>, now: i64) {
    // The four algorithm cases must all be refused *for the algorithm*. That
    // they name it is the observable part of "before any key is loaded": a
    // verifier that selected a key first would refuse the unknown-kid one on the
    // key instead.
    for (name, token) in [
        ("alg: none", forged.alg_none),
        ("alg: none with an unpublished kid", forged.alg_none_unknown_kid),
        ("alg: HS256", forged.alg_hs256),
        ("alg: HS256 keyed with the IdP public key", forged.alg_confusion),
        ("an unrecognized alg", forged.alg_unknown),
    ] {
        refused(idp, token, now, "disallowed alg", name).await;
    }

    refused(idp, forged.unknown_kid, now, "unknown kid", "an unpublished signing key").await;
    refused(idp, forged.expired, now, "expired", "an expired token").await;
    refused(idp, forged.wrong_audience, now, "aud", "another audience").await;
    refused(idp, forged.tampered, now, "signature does not verify", "an edited payload").await;
}

/// A negative fixture proves nothing about the defect its name claims unless
/// that defect is the only one it carries. A fixture that is *also* expired is
/// refused whatever else is wrong with it, so it would satisfy its own
/// expectation while saying nothing -- and check order hides the second defect
/// rather than reporting it. The corpus, not the verifier, is what has to be
/// held to one defect per file.
///
/// `dimensions` names the header members and claims that may differ from the
/// positive. The two namespaces share one set of names, which no corpus makes
/// ambiguous: none of them carries a claim called `alg`, `kid` or `x5t`.
/// `nonce` is the one claim excluded, because the forge writes a fresh value
/// into every token it issues and no fixture differs by intent.
pub(crate) fn differs_only_where_named(
    positive: &str,
    nonce: &str,
    name: &str,
    token: &str,
    dimensions: &[&str],
) {
    let (want_header, want_claims) = decode(positive, "the positive fixture");
    let (header, claims) = decode(token, name);
    let mut changed = moved(&header, &want_header, nonce);
    changed.append(&mut moved(&claims, &want_claims, nonce));
    let named: std::collections::BTreeSet<String> =
        dimensions.iter().map(|d| (*d).to_owned()).collect();
    assert_eq!(
        changed, named,
        "{name} differs from the positive in {changed:?}, and its name claims {named:?}"
    );
}

/// The members whose value moved, in either direction: a member the fixture
/// dropped is as much a difference as one it edited.
fn moved(
    doc: &serde_json::Map<String, serde_json::Value>,
    from: &serde_json::Map<String, serde_json::Value>,
    nonce: &str,
) -> std::collections::BTreeSet<String> {
    doc.keys()
        .chain(from.keys())
        .filter(|k| k.as_str() != nonce && doc.get(*k) != from.get(*k))
        .cloned()
        .collect()
}

type Parts =
    (serde_json::Map<String, serde_json::Value>, serde_json::Map<String, serde_json::Value>);

fn decode(token: &str, what: &str) -> Parts {
    let member = |part: Option<&str>| -> serde_json::Map<String, serde_json::Value> {
        let raw = crate::b64url(part.unwrap_or_else(|| panic!("{what} is not a three-part JWT")))
            .unwrap_or_else(|e| panic!("{what} is not base64url: {e}"));
        serde_json::from_slice(&raw).unwrap_or_else(|e| panic!("{what} is not JSON: {e}"))
    };
    let mut parts = token.split('.');
    (member(parts.next()), member(parts.next()))
}

async fn refused(idp: &dyn IdentityProvider, token: &str, now: i64, expected: &str, what: &str) {
    match idp.identify(token, now).await {
        Ok(id) => panic!("{what} was accepted, yielding {id:?}"),
        Err(Reject(why)) => {
            assert!(why.contains(expected), "{what}: expected {expected:?}, got {why:?}")
        }
    }
}
