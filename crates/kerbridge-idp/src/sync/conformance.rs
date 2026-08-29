//! What every [`DirectorySource`](super::DirectorySource) must hold, whatever
//! else its IdP's wire looks like.
//!
//! The directory-face analogue of [`crate::conformance`]: run against each
//! adapter from that adapter's own test module, with reads produced from *its*
//! own fixtures. An adapter that does not run it is one whose seam contract
//! nobody has checked -- and getting this wrong is not a broken cycle but a
//! silent mass retirement, because absence in a snapshot is how this design
//! spells a departure.
//!
//! Unlike the token face there is no shared corpus and no `Forged` list of
//! inputs. The two IdPs read their directories in shapes that do not line up --
//! authentik proves a set of pages is one whole read, Entra patches a shadow
//! from sparse deltas -- so each adapter turns its own fixtures into the seam's
//! own types and drives *those* through here. What generalizes is the contract
//! on the seam types, not the wire that produced them.

use serde_json::Value;

use crate::sync::{Enumeration, SourceError, Subject, build_desired};

/// What one deliberately-broken read produced, reduced to the single distinction
/// the seam's contract turns on: a population, or a refusal.
///
/// An adapter maps its own outcome onto this -- authentik a `Result` from its
/// page assembler, Entra a `Result<Progress, _>` from its reader -- so the two
/// meet at the seam rather than at their wire.
pub(crate) enum Verdict {
    Snapshot,
    Refused(String),
}

/// A whole read, narrowed to the population the realm should hold, is the golden
/// desired state byte for byte.
///
/// [`build_desired`] is the shared narrowing both adapters feed, so this asserts
/// the adapter handed it the enumeration the golden was derived from. Each
/// adapter supplies its own golden -- authentik's `golden.json`, Entra's planner
/// `S1` -- because the population is the IdP's, but the rule that shapes it is
/// not.
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
/// The load-bearing rule of the seam: absence in a snapshot is a departure, so a
/// read that did not finish must produce no snapshot at all rather than a
/// population short whoever fell in the gap. Each adapter supplies its own torn
/// read -- authentik a page set that fails assembly, Entra a reader whose cursor
/// never recovers -- and both must refuse. Returns the refusal so the caller can
/// assert its own IdP-specific wording.
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
/// [`SourceError::counts_as_failure`] is the whole of it: a rejected credential
/// is reported on its own channel, so counting it a second time would raise a
/// vaguer alarm for one condition. Every other class counts. Each adapter drives
/// its own classified errors through this -- authentik its 403 shapes, Entra its
/// token and transport errors -- because the biconditional binds them both.
pub(crate) fn credential_rejection_is_the_only_non_failure(err: &SourceError) {
    let rejected = matches!(err, SourceError::CredentialRejected(_));
    assert_eq!(
        err.counts_as_failure(),
        !rejected,
        "{err}: only a rejected credential is spared from counting against the source"
    );
}
