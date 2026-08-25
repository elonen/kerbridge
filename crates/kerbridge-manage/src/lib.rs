//! The on-prem directory work KerBridge leaves to the operator: resource
//! groups, their membership, and diagnosing why a cloud identity does or does
//! not reach a share.
//!
//! Two halves, split the way `kerbridge-sync` is split. [`directory`] does
//! LDAP and [`endpoint`] does one HTTP request, and neither judges what it
//! finds; [`validate`] and [`doctor`] are pure functions over the plain data in
//! [`model`]. The seam is data, not traits -- there is nothing to mock, and the
//! interesting half tests from fixtures with nothing running.
//!
//! Nothing in this library prints. `main.rs` owns every interaction with a
//! human, so a GUI could link this later and render it differently.
//!
//! Two rules are functional rather than stylistic:
//!
//! - **An IdP-specific OU is read and delete only.** It is sync-owned, and a second
//!   writer racing the reconciliation loop is the failure this tool exists to
//!   avoid. [`validate::assert_outside_cloud_idp`] is where that is enforced.
//! - **Deleting is never recovery.** The recreated object gets a new SID; under
//!   `idmap_rid` every file server derives `uid = RID + range base`, so files
//!   stay owned by ids that no longer resolve. Retention protects the SID, and
//!   the SID does not become cheap with age -- which is why no verb here treats
//!   an elapsed window as permission.

#![forbid(unsafe_code)]

pub mod certificate;
pub mod config;
pub mod directory;
pub mod doctor;
pub mod endpoint;
pub mod model;
pub mod problems;
pub mod validate;

pub use config::{Config, Overrides};
pub use directory::Directory;
pub use model::{CloudObject, Kind, ResourceGroup, Snapshot, State};
