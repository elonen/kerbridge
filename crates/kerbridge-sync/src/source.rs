//! Directory interface that adapters implement to read their IdP and
//! hand back a snapshot of the realm's population.
//!
//! This isolates IdP-specific things from LDAP types. The planner and
//! reconciler receive a [`SourceSnapshot`] and make AD directory changes from it.

use std::sync::Arc;

use kerbridge_idp::IdpSettings;
use kerbridge_notify::Notifier;
use serde::{Deserialize, Serialize};

use crate::entra::EntraSource;
use crate::planner::Desired;

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
/// [`crate::planner::plan_sync`] wants the admission subject among the keys of
/// `desired.groups` and freezes the cycle when it is absent, so an adapter whose
/// key does not survive a rename freezes rather than repointing onto the wrong
/// group. A key that moves reads as a different account: the stored identity is
/// built from it, so the old object retires and a new one is created with a new
/// SID.
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
