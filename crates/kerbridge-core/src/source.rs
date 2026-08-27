//! Which cloud IdP an object came from.
//!
//! A source name is a **storage key**: it is written into
//! [`crate::ExternalIdentity`], which is the primary key of every synchronized
//! object. An issuer URL is an **authentication input**: the adapter compares a
//! token's `iss` against it on every exchange, and at a self-hosted IdP it is
//! ordinarily a setting rather than a constant.
//!
//! Keeping the two apart is the whole point. Conflating them puts a value
//! someone can edit into permanent storage, and changing it there orphans every
//! AD object, which detaches every file whose owner `idmap_rid` derived from
//! that object's SID. Silent and unrecoverable.

use std::fmt;

use crate::IdentityError;

/// Which cloud IdP an identity came from: everything about it except *who*.
///
/// One realm can hold several, each mirrored by its own sync into its own
/// IdP-specific OU. This is the key deciding which of them owns a given object:
/// sync reconciles only its own source and leaves the rest untouched.
///
/// The name is the operator's configured name for the source -- the same string
/// as the IdP-specific OU (`entra`, `google`). Unique *by construction*, because
/// a name is assigned per configured source within one realm: it needs no
/// second field to separate two deployments that both call themselves `acme`.
///
/// **Frozen at first provisioning.** Changing it rewrites every identity this
/// realm has stored -- see the module doc for what that costs, and
/// `docs/setup/names-and-decisions.md` for where an operator is told.
///
/// The name-to-source binding is a configuration invariant the stored value does
/// not enforce on its own, so pointing an existing name at a *different* IdP is
/// a second way to pay the same bill. That one is at least loud -- the new IdP's
/// subjects share none of the old ones, so sync retires every account and
/// creates a replacement rather than confusing two people -- but every SID is
/// still new. A new IdP gets a new name and its own OU.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Source(String);

impl Source {
    pub fn new(name: impl Into<String>) -> Result<Self, IdentityError> {
        let name = name.into();
        if name.is_empty() {
            return Err(IdentityError::EmptyField("source name"));
        }
        Ok(Self(name))
    }

    pub fn name(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_name_is_not_a_source() {
        assert_eq!(Source::new(""), Err(IdentityError::EmptyField("source name")));
        assert_eq!(Source::new("entra").unwrap().name(), "entra");
    }
}
