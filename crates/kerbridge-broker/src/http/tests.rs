use super::*;
use axum::http::header::AUTHORIZATION;

fn with(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, value.parse().unwrap());
    headers
}

#[test]
fn extracts_either_credential_whatever_the_case() {
    for spelling in ["Bearer", "bearer", "BEARER"] {
        let headers = with(&format!("{spelling} abc.def.ghi"));
        assert!(matches!(proof(&headers), Some(Proof::Bearer("abc.def.ghi"))), "{spelling}");
    }
    for spelling in ["DeviceGrant", "devicegrant", "DEVICEGRANT"] {
        let headers = with(&format!("{spelling} payload.sig"));
        assert!(matches!(proof(&headers), Some(Proof::DeviceGrant("payload.sig"))), "{spelling}");
    }
}

/// Exactly one scheme must match. An unrecognized one is refused outright
/// rather than falling through to a weaker check -- which is the whole reason
/// this is a parse and not a pair of prefix tests.
#[test]
fn rejects_anything_that_is_not_one_of_the_two_schemes() {
    assert!(proof(&HeaderMap::new()).is_none());
    for bad in [
        "Basic dXNlcjpwYXNz",
        "Bearer ",
        "DeviceGrant ",
        "abc.def.ghi",
        // Neither scheme is a prefix of a longer one that also passes.
        "DeviceGrantX payload.sig",
        "Bearer2 abc.def.ghi",
    ] {
        assert!(proof(&with(bad)).is_none(), "accepted {bad:?}");
    }
}

/// A singleton broker serves several sources behind one audience and one
/// nonce store, so this is the whole of what keeps an identity minted under
/// one from being spent under another. 401, because a client holding a proof
/// the wrong path cannot use has an identity problem, not a policy one.
#[test]
fn an_identity_is_refused_at_another_sources_path() {
    let entra = Source::new("entra").unwrap();
    let okta = Source::new("okta").unwrap();
    let identity = ExternalIdentity::new(&entra, "user-oid").unwrap();

    assert!(same_source(&entra, &identity).is_ok());
    let failure = same_source(&okta, &identity).unwrap_err();
    assert_eq!(failure.status, StatusCode::UNAUTHORIZED);
    // Both names, because "invalid identity proof" is all the client is
    // told and the log line is the only place the mismatch is visible.
    assert!(
        failure.detail.contains("entra") && failure.detail.contains("okta"),
        "{}",
        failure.detail
    );
}

#[test]
fn request_ids_are_hex_and_do_not_repeat() {
    let rng = ring::rand::SystemRandom::new();
    let a = request_id(&rng);
    let b = request_id(&rng);
    assert_eq!(a.len(), 16);
    assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(a, b);
}
