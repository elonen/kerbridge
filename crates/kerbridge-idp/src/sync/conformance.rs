//! What every [`DirectorySource`](super::DirectorySource) must hold, whatever
//! else its IdP's wire looks like.
//!
//! Each adapter runs these checks with its own fixtures. An unchecked seam can
//! cause a silent mass retirement because an absent snapshot object means that
//! the object departed.
//!
//! The adapters cannot share a wire corpus. authentik assembles full pages;
//! Entra patches a shadow with sparse deltas. Each adapter converts its fixtures
//! to the seam types. These checks validate the seam contract.

use serde_json::Value;

use crate::sync::{Enumeration, SourceError, Subject, build_desired};

/// What one deliberately-broken read produced, reduced to the single distinction
/// the seam's contract turns on: a population, or a refusal.
///
/// An adapter maps its provider-specific read outcome to this seam verdict.
pub(crate) enum Verdict {
    Snapshot,
    Refused(String),
}

/// A whole read, narrowed to the population the realm should hold, is the golden
/// desired state byte for byte.
///
/// Each adapter supplies a provider-specific golden result. [`build_desired`]
/// supplies the shared narrowing rule.
pub(crate) fn whole_read_reproduces_golden(
    read: Enumeration,
    admission: &Subject,
    allowlist: &[Subject],
    golden_desired: &Value,
) {
    let (desired, _) = build_desired(read, admission, allowlist);
    let got = serde_json::to_value(&desired).expect("the desired state serializes");
    assert_eq!(&got, golden_desired, "a whole read did not reproduce the golden desired state");
}

/// A read that is not whole yields no snapshot, and says why.
///
/// An incomplete read must produce no snapshot because an absent snapshot object
/// is treated as a departure. Returns the refusal for provider-specific checks.
pub(crate) fn a_torn_read_yields_no_snapshot(verdict: Verdict) -> String {
    match verdict {
        Verdict::Refused(why) => why,
        Verdict::Snapshot => panic!(
            "a torn read produced a snapshot: absence in a snapshot is a departure, so a read \
             that did not finish must retire nobody"
        ),
    }
}

/// A rejected credential is the one failure the seam does not count -- and the
/// only one.
///
/// A rejected credential has its own event. Counting it again would raise a
/// second, less specific alarm. Every other error class counts.
pub(crate) fn credential_rejection_is_the_only_non_failure(err: &SourceError) {
    let rejected = matches!(err, SourceError::CredentialRejected(_));
    assert_eq!(
        err.counts_as_failure(),
        !rejected,
        "{err}: only a rejected credential is spared from counting against the source"
    );
}
