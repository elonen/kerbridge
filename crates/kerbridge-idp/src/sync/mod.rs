//! The IdP directory face: what an adapter reads out of its IdP, and the shape it
//! hands over.
//!
//! This isolates IdP-specific things from LDAP types. The mirror receives a
//! [`SourceSnapshot`] and makes realm directory changes from it; nothing about the
//! realm directory -- no bind identity, no OU, no `sAMAccountName` -- is reachable
//! from below the seam.
//!
//! Behind the crate's `sync` feature, so the broker's binary carries none of it.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use kerbridge_core::sam;
use kerbridge_notify::Notifier;
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::IdpSettings;
use crate::authentik::sync::AuthentikSource;
use crate::entra::sync::EntraSource;

/// Directory-source conformance checks, compiled for adapter tests only.
#[cfg(test)]
pub(crate) mod conformance;

// ---- the seam ----------------------------------------------------------

/// What one [`DirectorySource::advance`] concluded.
pub enum Progress {
    /// A whole IdP directory enumeration, observed in one uninterrupted read.
    Complete(SourceSnapshot),
    /// No credential yet. Not a fault, and never counted.
    Idle(String),
}

/// One cycle's whole reading of a tenant.
///
/// Its existence is the assertion: an adapter that cannot enumerate returns
/// [`SourceError::NotWhole`], and then there is no snapshot to plan from. So a
/// read that did not finish can never delete or disable anything.
pub struct SourceSnapshot {
    pub desired: Desired,
    /// The group that admits people to the realm.
    pub admission: Subject,
    /// The device-grant group, if the deployment names one. Absent is ordinary:
    /// a deployment with device grants off has no such group, and one with them
    /// on but no group configured simply admits nobody to them -- the broker
    /// looks the group up by its marker and fails closed when it is missing.
    pub grant: Option<Subject>,
    /// Who the adapter's own rules left out, and why -- prose for the operator,
    /// not a fault.
    pub refused: Vec<String>,
}

/// One IdP's own key for an account or a group, as its adapter hands it over.
///
/// Opaque above the seam. It is compared for equality against the keys of the
/// enumeration it arrived in, and nothing else is done with it; whether it is a
/// UUID, a slug or a DN is the adapter's choice and the adapter's to document.
///
/// The planner wants the admission subject among the keys of `desired.groups`
/// and freezes the cycle when it is absent, so an adapter whose key does not
/// survive a rename freezes rather than repointing onto the wrong group. A key
/// that moves reads as a different account: the stored identity is built from
/// it, so the old object retires and a new one is created with a new SID.
///
/// `Ord` is derived for deterministic iteration, which the recorded fixtures
/// depend on. It means nothing else; subjects have no order.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Subject(String);

impl Subject {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why a cycle produced no snapshot.
///
/// Each variant carries the sentence the operator sees, in the adapter's own
/// words. The seam fixes only the *class*, which is what decides whether the
/// cycle counts against this source.
pub enum SourceError {
    /// The credential is present and unusable, or cannot be read at all.
    Credential(String),
    /// The IdP refused the credential. The adapter reports it on its own
    /// channel, so this never counts: a second, vaguer alarm for one condition
    /// is noise.
    CredentialRejected(String),
    Unreachable(String),
    /// A whole enumeration was not possible this cycle.
    NotWhole(String),
}

impl SourceError {
    pub fn counts_as_failure(&self) -> bool {
        !matches!(self, SourceError::CredentialRejected(_))
    }
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (SourceError::Credential(why)
        | SourceError::CredentialRejected(why)
        | SourceError::Unreachable(why)
        | SourceError::NotWhole(why)) = self;
        f.write_str(why)
    }
}

/// Headroom on the credential a source reads with, and where the number came
/// from. An IdP that reports its own credential's expiry needs no operator
/// assertion; one that does not gets whatever the config set states.
pub enum CredentialState {
    /// Read from the IdP. authentik reports API-token expiry to the bearer.
    Measured { days: i64 },

    /// Stated reminder from the operator.
    Asserted { days: i64 },

    /// No expiry known.
    Unknown,
}

/// One IdP directory, reduced to what the mirror needs of it.
///
/// INVARIANT: cursors do not survive a restart. An adapter must be correct when
/// its first cycle after start is a full read.
///
/// INVARIANT: long-lived, and carries state between cycles, but the credential
/// should be re-read at the start of every [`Self::advance`], so a rotated secret
/// needs no restart.
#[async_trait::async_trait]
pub trait DirectorySource: Send {
    async fn advance(&mut self) -> Result<Progress, SourceError>;

    fn credential_state(&self) -> CredentialState;

    /// What this source's credential problems are keyed by. Names the
    /// registration the credential belongs to as well as the source, so
    /// rotating to a different one opens a new problem rather than rewording
    /// the standing one.
    fn credential_subject(&self) -> String;
}

/// The one place a configured source becomes an adapter.
///
/// Connect a configured IdP directory. A failure stops sync because silently
/// skipping a source would treat its complete population as departed.
pub fn connect(
    settings: &IdpSettings,
    source: &str,
    notifier: Arc<Notifier>,
) -> anyhow::Result<Box<dyn DirectorySource>> {
    match settings {
        IdpSettings::Entra(entra) => Ok(Box::new(EntraSource::new(entra, source, notifier))),
        IdpSettings::Authentik(authentik) => {
            Ok(Box::new(AuthentikSource::new(authentik, source, notifier)))
        }
    }
}

// ---- the population ----------------------------------------------------

/// The population the realm should hold, keyed by the adapter's own subjects.
/// `BTreeMap` because the reference planner iterates every desired collection
/// in subject order, and this makes that ordering automatic and total.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Desired {
    pub users: BTreeMap<Subject, DesiredUser>,
    pub groups: BTreeMap<Subject, DesiredGroup>,
    pub membership: BTreeMap<Subject, Vec<Subject>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DesiredUser {
    /// What the IdP directory shows: `displayName`, and the CN built from it.
    pub display_name: String,
    /// What the login name may be minted from, best first.
    ///
    /// The adapter owns which strings are worth trying and in what order; the
    /// realm owns which of them a name may actually be. Empty is legal and
    /// means "nothing usable", which derives `kbuser` plus a collision suffix.
    pub name_candidates: Vec<NameCandidate>,
    pub enabled: bool,
}

/// One string an account's `sAMAccountName` may be minted from, already reduced
/// to what AD accepts.
///
/// Constructible only through [`name_candidate`], on the wire as in Rust: the
/// rule has one home, so an adapter cannot inline a charset of its own and a
/// fixture cannot state a name the realm would never derive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct NameCandidate(String);

impl NameCandidate {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for NameCandidate {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        // Idempotent on a value this rule already produced, so a fixture that
        // states the derived form round-trips and one that states anything else
        // is refused rather than quietly rewritten.
        name_candidate(&raw)
            .filter(|c| c.as_str() == raw)
            .ok_or_else(|| serde::de::Error::custom(format!("{raw:?} is not a name candidate")))
    }
}

/// The character budget a candidate is cut to: AD's documented user limit. The
/// byte ceiling [`sam::MAX_BYTES`] binds independently.
const CANDIDATE_CHARS: usize = 20;

/// `s` as a login name, or `None` when nothing usable survives.
///
/// NFC first, and this is the only place a read-path name is normalized:
/// Unicode spells `å` as either `U+00E5` or `a` + `U+030A`, the two render
/// identically, and deriving both would put two accounts in the realm directory that
/// no human can tell apart.
///
/// The budget is not a parameter. An adapter that can pass a length can pass
/// the wrong one.
///
/// `None` rather than the string, because [`sam::sanitize`] answers
/// [`sam::FALLBACK`] -- the literal `kbuser` -- where nothing survives. Handed
/// back raw, an adapter filtering on `!is_empty()` would offer `kbuser` as a
/// real candidate for every user whose display name is `"..."`.
pub fn name_candidate(s: &str) -> Option<NameCandidate> {
    let nfc: String = s.nfc().collect();
    let sanitized = sam::sanitize(&nfc, CANDIDATE_CHARS, sam::MAX_BYTES);
    (sanitized != sam::FALLBACK).then_some(NameCandidate(sanitized))
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DesiredGroup {
    pub display_name: String,
}

// ---- the opt-in helpers ------------------------------------------------

/// One adapter's whole reading of its IdP, before the realm's rules narrow it.
///
/// The realm's rules are the closure walk, the held-narrowing and the refusal
/// list, and they live once, in [`build_desired`]. Filling this in is how an
/// adapter opts into them. An adapter whose IdP expands nesting server-side, or
/// that reads a flat list, fills a [`Desired`] its own way instead; nothing
/// requires this shape.
#[derive(Debug, Default)]
pub struct Enumeration {
    /// Every account the adapter's own rules accept. Which those are rests on
    /// wire facts about one IdP, so the decision is the adapter's.
    pub users: BTreeMap<Subject, DesiredUser>,
    pub groups: BTreeMap<Subject, DesiredGroup>,
    pub membership: BTreeMap<Subject, Vec<Membership>>,
    /// The accounts the adapter turned away. Reported only where a selected
    /// group holds one -- an unheld account was never going to get an object, so
    /// naming it would be noise.
    pub refused: BTreeMap<Subject, Refusal>,
}

/// `"Jane Doe" -> "jane.doe"`: every whitespace-separated token of a display
/// name, joined by `.`. Casing and illegal characters are [`name_candidate`]'s.
///
/// Every token rather than first-and-last. First-and-last assumes a name is
/// *given* then *family*, and that assumption is wrong in both directions: it
/// drops middle tokens everywhere, and on a Spanish double surname it keeps the
/// last token -- the maternal surname -- while dropping the paternal one that
/// actually identifies the person (`Gabriel García Márquez` ->
/// `gabriel.márquez`, not `gabriel.garcía`). Joining every token imposes no
/// ordering of its own, which is the only defensible reading of a display name:
/// `山田 太郎` is family-first in the source and stays family-first here.
pub fn dotted(display_name: &str) -> String {
    display_name.split_whitespace().collect::<Vec<_>>().join(".")
}

/// The part of an address before the `@`. Empty when there is nothing there.
///
/// Only the `@`. Whatever else one IdP writes into a local part is that
/// adapter's to strip, before or after this.
pub fn local_part(address: &str) -> &str {
    address.split('@').next().unwrap_or("")
}

/// A group edge, as the two classes the realm mirrors. Anything else an IdP
/// permits in a group -- a device, a service principal -- the adapter drops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Membership {
    User(Subject),
    Group(Subject),
}

/// An account an adapter's own rules turned away, ready to report if a selected
/// group turns out to hold it.
#[derive(Debug, Clone)]
pub struct Refusal {
    /// How to name the account on screen. The subject alone rarely means
    /// anything to the operator reading it.
    pub who: String,
    pub why: String,
}

/// Turn one adapter's reading into the desired state.
///
/// Group selection is the closure reachable from the admission group through
/// nested group membership, plus the configured allowlist. Direct edges are
/// mirrored as-is; nesting is resolved by Samba, not flattened here.
///
/// Returns the desired state and the refusals that shaped it -- every account a
/// selected group holds that the adapter's own rules turned away.
pub fn build_desired(
    read: Enumeration,
    admission: &Subject,
    allowlist: &[Subject],
) -> (Desired, Vec<String>) {
    let Enumeration { users: accepted, groups: all_groups, membership: edges, refused: refusals } =
        read;

    // Admission-group-reachable closure + allowlist, following only group-typed edges.
    //
    // `selected` breaks nesting cycles: Entra permits mutual nesting, and the
    // recorded fixtures contain `cyc-a` -> `cyc-b` -> `cyc-a` reachable from the
    // admission group. A group is expanded once; the second arrival at it is a no-op.
    //
    // Inserted only *after* the group lookup succeeds, so `selected` never names a
    // group the read has no object for -- the loop below unwraps that lookup and
    // would panic. A subject absent from the read is therefore re-examined on each
    // arrival, which costs nothing and still terminates, because an absent group
    // contributes no edges.
    let mut selected: HashSet<Subject> = HashSet::new();
    let mut refused: Vec<String> = Vec::new();
    let mut todo: Vec<Subject> =
        std::iter::once(admission.clone()).chain(allowlist.iter().cloned()).collect();
    while let Some(gid) = todo.pop() {
        if selected.contains(&gid) || !all_groups.contains_key(&gid) {
            continue;
        }
        for m in edges.get(&gid).into_iter().flatten() {
            if let Membership::Group(sub) = m {
                todo.push(sub.clone());
            }
        }
        selected.insert(gid);
    }

    let mut groups = BTreeMap::new();
    let mut membership = BTreeMap::new();
    // Users a selected group actually holds. Everyone else the adapter accepted is
    // unheld, and gets no account at all -- see the narrowing below.
    let mut held: HashSet<Subject> = HashSet::new();
    let mut order: Vec<&Subject> = selected.iter().collect();
    order.sort();
    for gid in order {
        let mut mm = Vec::new();
        for m in edges.get(gid).into_iter().flatten() {
            match m {
                Membership::User(sub) if accepted.contains_key(sub) => {
                    held.insert(sub.clone());
                    mm.push(sub.clone());
                }
                // `selected`, not `groups`: a member group the read has but the
                // closure did not select has no realm directory object, so naming it
                // here would put a member in `membership` that is absent from
                // `groups`. The planner drops such a reference silently when it
                // fails to resolve a DN for it, which makes this an invariant held
                // by accident two files away rather than stated here.
                Membership::Group(sub) if selected.contains(sub) => mm.push(sub.clone()),
                // A held account the adapter refuses is the confusing case worth
                // naming: the operator put them in the admission group and no
                // account appeared. An *absent* member is not reported -- that is
                // ordinary delta ordering, not a decision.
                Membership::User(sub) => {
                    if let Some(Refusal { who, why }) = refusals.get(sub) {
                        refused.push(format!(
                            "user {who} is held by a selected group but gets no account: {why}"
                        ));
                    }
                }
                Membership::Group(_) => {}
            }
        }
        let g = all_groups.get(gid).expect("selected implies a group in the read");
        groups.insert(gid.clone(), g.clone());
        membership.insert(gid.clone(), mm);
    }

    // A realm directory object exists for someone a selected group holds, and for
    // nobody else. The admission group and the allowlist are therefore the whole
    // answer to "who has an account here", not merely "who may get a ticket":
    // an operator reading the IdP-specific OU in ADUC sees the admitted set and
    // nothing else, which is the same thing the `_retired-` prefix is for.
    //
    // The consequence is deliberate: leaving the admission-group closure retires the
    // account rather than only dropping its group memberships. Retention keeps
    // the SID, so file ACLs survive and a returning user takes their name back.
    let users: BTreeMap<Subject, DesiredUser> =
        accepted.into_iter().filter(|(sub, _)| held.contains(sub)).collect();

    refused.sort();
    (Desired { users, groups, membership }, refused)
}
