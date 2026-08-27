//! The markers and directory constants every KerBridge component agrees on.
//!
//! These are a wire format between processes that never talk to each other:
//! sync stamps a marker, the broker reads it minutes later, and an operator tool
//! reads it again a month after that. A second spelling anywhere means the
//! admission group stops being found or a retired object stops being
//! recognized -- silently, and
//! only for some of the readers. Same argument as [`crate::ExternalIdentity`],
//! for the same reason: one implementation.

/// The role marker sync stamps on the admission group. Recovers it after a
/// rename or a lost cursor; the broker matches on it rather than on a name.
pub const ROLE_ADMISSION: &str = "kbrole1|realm-admission";
/// The role marker sync stamps on the device-grant group -- who may authorize a
/// device to skip the browser sign-in.
///
/// **Additional to** [`ROLE_ADMISSION`], never an alternative to it: a device
/// grant holder must satisfy both, and because membership is re-checked on every
/// exchange, removing someone from this group is also the revocation lever for
/// every device they hold. An operator who wants the feature for everyone puts
/// everyone in it.
pub const ROLE_DEVICE_GRANT: &str = "kbrole1|device-grant";
/// The marker on a delegate group: the people who may authorize a device on
/// behalf of the user the group's `managedBy` names.
///
/// **Non-singleton**, unlike [`ROLE_ADMISSION`] and [`ROLE_DEVICE_GRANT`]: one
/// group carries it per delegated account, so a reader must never resolve it the
/// way those two are resolved -- exactly-one-or-freeze is right for a realm-wide
/// policy group and wrong here, where two of these is the ordinary state. What
/// picks the right one is the target's own `managedObjects` back-link; the
/// marker only says the link was meant as a delegation and is not an admin's
/// conventional "who owns this group".
pub const ROLE_DELEGATES: &str = "kbrole1|delegates";
/// State marker prefix for a disabled-for-deletion user whose retention is
/// counting down. The timestamp is appended.
pub const ST_RETIRED: &str = "kbstate1|retired|";
/// State marker prefix for a deleted group held through its retention window.
pub const ST_QUAR: &str = "kbstate1|quarantined|";
/// State marker prefix for an account whose login name an operator has set by
/// hand. The timestamp is appended.
///
/// Sync recomputes a live account's `sAMAccountName` when
/// `automatic_sam_renames` is on, and would otherwise undo that edit on
/// the next cycle. This says the operator's choice wins until they say
/// otherwise -- `kbmanage cloud unpin` removes it and hands the name back.
pub const ST_NAME_PINNED: &str = "kbstate1|namepinned|";

/// Name prefix for an object kept only for its SID. `sAMAccountName` is what
/// winbind resolves a SID back to, so this is what `id`, `getent` and Explorer's
/// *Security* tab show on a file server long after the cloud object is gone.
///
/// The leading underscore marks the namespace but does not reserve it:
/// [`crate::sam::allowed`] permits `_`, so a display name can sanitize to a live
/// name that begins with one. What keeps a retired object from shadowing a live
/// one is the planner's `sam_keys` pre-check, which suffixes the derived name or
/// refuses the cycle.
pub const RETIRED_PREFIX: &str = "_retired-";

/// `NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD`. The no-expire bit is mandatory: an
/// expired password breaks keytab-based issuance for that account.
pub const UAC_ENABLED: &str = "66048";
/// The above plus `ACCOUNTDISABLE`.
pub const UAC_DISABLED: &str = "66050";
/// `GLOBAL | SECURITY_ENABLED` -- what sync creates for a synchronized group.
pub const GROUP_TYPE_GLOBAL_SECURITY: &str = "-2147483646";
/// `DOMAIN_LOCAL | SECURITY_ENABLED` -- what a resource group is. Verified to
/// apply over LDAPS against Samba 4.22.10 as a delegated (non-admin) account.
pub const GROUP_TYPE_DOMAIN_LOCAL_SECURITY: &str = "-2147483644";

/// How long a retired or quarantined object has been held, in whole days, or
/// `None` if `marker` is not a state marker with a parsable timestamp.
///
/// Nothing gates on this, and there is deliberately no configured window for it
/// to be compared against: sync never deletes, and `kbmanage`'s delete is
/// destructive at any age because the SID is what retention protects and the SID
/// does not become cheap with time. A threshold would imply that crossing it
/// makes deletion safe. This exists only so operator tooling can say how long an
/// object has been held.
///
/// `now` is seconds since the Unix epoch, the same clock [`crate::time`] renders
/// from -- and a marker this cannot parse reads as `None` rather than as an age,
/// so a hand-edited value degrades to "held, timestamp unreadable" instead of to
/// a number nobody wrote.
pub fn retention_age_days(marker: &str, now: u64) -> Option<u64> {
    let stamp = marker.strip_prefix(ST_RETIRED).or_else(|| marker.strip_prefix(ST_QUAR))?;
    let stamped = crate::time::epoch_from_rfc3339(stamp)?;
    Some(now.saturating_sub(stamped) / 86_400)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::rfc3339;

    #[test]
    fn age_counts_whole_days_since_the_marker_was_stamped() {
        let stamped = 1_784_980_800;
        // Pinned both ways: a round-trip alone would pass just as happily with
        // the epoch and the date a year apart.
        assert_eq!(rfc3339(stamped), "2026-07-25T12:00:00Z");
        let marker = format!("{ST_RETIRED}{}", rfc3339(stamped));
        assert_eq!(retention_age_days(&marker, u64::from(stamped)), Some(0));
        assert_eq!(retention_age_days(&marker, u64::from(stamped) + 86_399), Some(0));
        assert_eq!(retention_age_days(&marker, u64::from(stamped) + 86_400), Some(1));
        assert_eq!(retention_age_days(&marker, u64::from(stamped) + 30 * 86_400), Some(30));
        // A clock that went backwards reads as freshly stamped, never as elapsed.
        assert_eq!(retention_age_days(&marker, 0), Some(0));
    }

    #[test]
    fn age_reads_both_state_markers_and_nothing_else() {
        let ts = "2026-07-25T12:00:00Z";
        assert!(retention_age_days(&format!("{ST_RETIRED}{ts}"), 1_784_980_800).is_some());
        assert!(retention_age_days(&format!("{ST_QUAR}{ts}"), 1_784_980_800).is_some());
        assert_eq!(retention_age_days(ROLE_ADMISSION, 1_784_980_800), None);
        assert_eq!(retention_age_days(&format!("{ST_RETIRED}whenever"), 1_784_980_800), None);
        assert_eq!(retention_age_days("", 1_784_980_800), None);
    }
}
