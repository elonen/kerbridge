//! The directory face: what an adapter reads out of its IdP, and the shape it
//! hands over.
//!
//! This isolates IdP-specific things from LDAP types. The mirror receives a
//! [`SourceSnapshot`] and makes AD directory changes from it; nothing about the
//! directory -- no bind identity, no OU, no `sAMAccountName` -- is reachable
//! from below the seam.
//!
//! Behind the crate's `sync` feature, so the broker's binary carries none of it.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use kerbridge_notify::Notifier;
use serde::{Deserialize, Serialize};

use crate::IdpSettings;
use crate::entra::sync::EntraSource;

// ---- the seam ----------------------------------------------------------

/// What one [`DirectorySource::advance`] concluded.
pub enum Progress {
    /// A whole-directory enumeration, observed in one uninterrupted read.
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
    /// Read from the IdP. Unconstructed while Entra is the only adapter: an
    /// app-registration secret carries no expiry a Graph read can see.
    #[allow(dead_code)]
    Measured { days: i64 },

    /// Stated reminder from the operator.
    Asserted { days: i64 },

    /// No expiry known.
    Unknown,
}

/// One cloud directory, reduced to what the mirror needs of it.
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
/// Destructured rather than passed whole: a second `IdpSettings` variant makes
/// this line refutable, so adapter #2 arrives as a compile error here instead of
/// as a Graph client pointed at a tenant that does not speak Graph.
pub fn connect(
    settings: &IdpSettings,
    source: &str,
    notifier: Arc<Notifier>,
) -> Box<dyn DirectorySource> {
    let IdpSettings::Entra(entra) = settings;
    Box::new(EntraSource::new(entra, source, notifier))
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
    pub display_name: String,
    pub upn: String,
    /// The mail address, empty when the account has none -- a user with no
    /// mailbox is normal. Absent on both sides of the wire rather than present
    /// and empty, which keeps the S1–S11 planner fixtures byte-stable.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mail: String,
    /// Entra's `otherMails` -- the portal's "Other emails". A guest usually has
    /// this and no `mail` at all: it holds the address they were invited by.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub other_mails: Vec<String>,
    pub enabled: bool,
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
                // closure did not select has no directory object, so naming it
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

    // A directory object exists for someone a selected group holds, and for
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
