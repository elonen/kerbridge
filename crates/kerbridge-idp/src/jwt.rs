//! The JOSE shapes more than one adapter needs, kept where neither owns them.
//!
//! `pub(crate)` and nothing else. A public type here would commit every future
//! adapter to a protocol [`IdentityProvider`](crate::IdentityProvider) never
//! asked for: the credential it takes is opaque, and need not be a JWT.

use serde::Deserialize;

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
