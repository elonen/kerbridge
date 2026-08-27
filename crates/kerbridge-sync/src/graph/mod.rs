//! Microsoft Graph: reading users and groups into the desired state the planner
//! consumes.
//!
//! The read model is a **shadow** -- a locally accumulated copy of the directory
//! that delta cycles patch. Graph delta entries are *sparse*: a change carries
//! only the properties that changed and only the membership edges that changed,
//! so a slice is merged into the shadow, never treated as a whole object. A user
//! object deletion arrives on the *users* stream and must be scrubbed from group
//! edges too, because Graph does not report it on the groups stream
//! (research spike `entra-directory-sync` @1.2).
//!
//! [`build_desired`] then applies the syncable rule and the admission
//! group's reachable closure to turn the shadow into a
//! [`crate::planner::Desired`]. It is pure and validated against the recorded
//! Graph fixtures: replaying the fixtures through the shadow reproduces, byte
//! for byte, the `desired` blocks the planner scenarios were generated from.

use std::collections::{BTreeMap, HashSet};

use serde::Deserialize;

use crate::planner::{Desired, DesiredGroup, DesiredUser};
use crate::source::Subject;

/// A directory-object membership edge's object class, taken from `@odata.type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberKind {
    User,
    Group,
    Device,
    ServicePrincipal,
    Other,
}

impl MemberKind {
    fn from_odata(t: &str) -> Self {
        match t.rsplit('.').next().unwrap_or("") {
            "user" => MemberKind::User,
            "group" => MemberKind::Group,
            "device" => MemberKind::Device,
            "servicePrincipal" => MemberKind::ServicePrincipal,
            _ => MemberKind::Other,
        }
    }
}

// ---- raw Graph wire shapes ----

/// A `delta` or list page. `@odata.nextLink` continues the read; only
/// `@odata.deltaLink` terminates it. A page never carries both, and an empty
/// `value` with a `nextLink` is *not* the last page.
#[derive(Debug, Deserialize)]
pub struct Page<T> {
    #[serde(rename = "@odata.nextLink")]
    pub next_link: Option<String>,
    #[serde(rename = "@odata.deltaLink")]
    pub delta_link: Option<String>,
    #[serde(default = "Vec::new")]
    pub value: Vec<T>,
}

#[derive(Debug, Deserialize)]
pub struct RawUser {
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "userPrincipalName")]
    pub upn: Option<String>,
    pub mail: Option<String>,
    #[serde(rename = "otherMails")]
    pub other_mails: Option<Vec<String>>,
    #[serde(rename = "accountEnabled")]
    pub account_enabled: Option<bool>,
    #[serde(rename = "userType")]
    pub user_type: Option<String>,
    #[serde(rename = "@removed")]
    pub removed: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct RawGroup {
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    // Absent (`None`) means "membership unchanged"; `Some([])` would mean an
    // empty slice. Distinguishing them is why this is an `Option`, not a
    // defaulted `Vec` -- a rename entry carries no `members@delta` and must not
    // clear the shadow's edges.
    #[serde(rename = "members@delta")]
    pub members_delta: Option<Vec<RawMember>>,
    #[serde(rename = "@removed")]
    pub removed: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct RawMember {
    #[serde(rename = "@odata.type")]
    pub odata_type: String,
    pub id: String,
    #[serde(rename = "@removed")]
    pub removed: Option<serde_json::Value>,
}

// ---- shadow ----

#[derive(Debug, Default, Clone)]
pub struct ShadowUser {
    pub display_name: Option<String>,
    pub upn: Option<String>,
    pub mail: Option<String>,
    pub other_mails: Option<Vec<String>>,
    pub account_enabled: Option<bool>,
    pub user_type: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct ShadowGroup {
    pub display_name: Option<String>,
    pub members: Vec<Member>,
}

#[derive(Debug, Clone)]
pub struct Member {
    pub kind: MemberKind,
    pub id: String,
}

/// The accumulated directory copy. Delta cycles mutate it; a full read starts
/// from an empty one.
#[derive(Debug, Default)]
pub struct Shadow {
    pub users: BTreeMap<String, ShadowUser>,
    pub groups: BTreeMap<String, ShadowGroup>,
}

impl Shadow {
    /// Merge a users delta/list slice. A removed user is dropped and scrubbed
    /// from every group edge, since Graph reports that deletion only here.
    pub fn apply_users(&mut self, entries: Vec<RawUser>) {
        for e in entries {
            if e.removed.is_some() {
                self.users.remove(&e.id);
                for g in self.groups.values_mut() {
                    g.members.retain(|m| m.id != e.id);
                }
                continue;
            }
            let u = self.users.entry(e.id).or_default();
            if e.display_name.is_some() {
                u.display_name = e.display_name;
            }
            if e.upn.is_some() {
                u.upn = e.upn;
            }
            if e.mail.is_some() {
                u.mail = e.mail;
            }
            if e.other_mails.is_some() {
                u.other_mails = e.other_mails;
            }
            if e.account_enabled.is_some() {
                u.account_enabled = e.account_enabled;
            }
            if e.user_type.is_some() {
                u.user_type = e.user_type;
            }
        }
    }

    /// Merge a groups delta/list slice. Property fields patch in place; a
    /// present `members@delta` merges edge by edge (add is deduplicated, remove
    /// drops the edge); an absent one leaves edges untouched.
    pub fn apply_groups(&mut self, entries: Vec<RawGroup>) {
        for e in entries {
            if e.removed.is_some() {
                self.groups.remove(&e.id);
                continue;
            }
            let g = self.groups.entry(e.id).or_default();
            if e.display_name.is_some() {
                g.display_name = e.display_name;
            }
            if let Some(md) = e.members_delta {
                for m in md {
                    if m.removed.is_some() {
                        g.members.retain(|x| x.id != m.id);
                    } else if !g.members.iter().any(|x| x.id == m.id) {
                        g.members
                            .push(Member { kind: MemberKind::from_odata(&m.odata_type), id: m.id });
                    }
                }
            }
        }
    }
}

/// Why an object is not synchronized. Returned so a cycle can log every rejection
/// without inventing the reason twice.
fn user_syncable(u: &ShadowUser) -> Result<(), &'static str> {
    // Members and guests both. A guest is authenticated by another tenant, but
    // that is not what grants access here: an account exists only for someone a
    // selected group holds, so admitting a guest is an operator's deliberate
    // act, and if their home tenant disables them they can no longer get a
    // token -- and without a token there is no ticket.
    //
    // Both carry a resource-tenant `oid`, measured, so the identity the broker
    // validates is the one sync writes (`docs/windows-kerberos-findings.md`
    // @ "Which claims reliably identify members and guests?"). An unknown or
    // absent `userType` is still refused: that fails closed on a shape nobody
    // has looked at.
    if !matches!(u.user_type.as_deref(), Some("Member" | "Guest")) {
        return Err("userType is neither Member nor Guest (or absent) - fails closed");
    }
    Ok(())
}

/// Turn the shadow into the planner's desired state.
///
/// Group selection is the closure reachable from the admission group through
/// nested group membership, plus the configured allowlist. Direct edges are
/// mirrored as-is; nesting is resolved by Samba, not flattened here.
///
/// Returns the desired state and the refusals that shaped it -- every user a
/// selected group holds that the syncable rule turned away.
pub fn build_desired(
    shadow: &Shadow,
    admission_oid: &str,
    allowlist: &[String],
) -> (Desired, Vec<String>) {
    let mut syncable = BTreeMap::new();
    for (oid, u) in &shadow.users {
        if user_syncable(u).is_ok() {
            syncable.insert(
                oid.clone(),
                DesiredUser {
                    display_name: u.display_name.clone().unwrap_or_default(),
                    upn: u.upn.clone().unwrap_or_default(),
                    mail: u.mail.clone().unwrap_or_default(),
                    other_mails: u.other_mails.clone().unwrap_or_default(),
                    enabled: u.account_enabled.unwrap_or(false),
                },
            );
        }
    }

    // Admission-group-reachable closure + allowlist, following only group-typed edges.
    //
    // `selected` breaks nesting cycles: Entra permits mutual nesting, and the
    // recorded fixtures contain `cyc-a` -> `cyc-b` -> `cyc-a` reachable from the
    // admission group. A group is expanded once; the second arrival at it is a no-op.
    //
    // Inserted only *after* the shadow lookup succeeds, so `selected` never names a
    // group with no `ShadowGroup` -- the loop below unwraps its `shadow.groups`
    // lookup and would panic. An id absent from the shadow is therefore re-examined
    // on each arrival, which costs nothing and still terminates, because an absent
    // group contributes no edges.
    let mut selected: HashSet<String> = HashSet::new();
    let mut refused: Vec<String> = Vec::new();
    let mut todo: Vec<String> =
        std::iter::once(admission_oid.to_owned()).chain(allowlist.iter().cloned()).collect();
    while let Some(gid) = todo.pop() {
        if selected.contains(&gid) {
            continue;
        }
        let Some(g) = shadow.groups.get(&gid) else {
            continue;
        };
        selected.insert(gid);
        for m in &g.members {
            if m.kind == MemberKind::Group {
                todo.push(m.id.clone());
            }
        }
    }

    let mut groups = BTreeMap::new();
    let mut membership = BTreeMap::new();
    // Users a selected group actually holds. Everyone else in the tenant is
    // syncable but unheld, and gets no account at all -- see the narrowing below.
    let mut held: HashSet<String> = HashSet::new();
    let mut order: Vec<&String> = selected.iter().collect();
    order.sort();
    for gid in order {
        let g = shadow.groups.get(gid).expect("selected implies a shadow group");
        let mut mm = Vec::new();
        for m in &g.members {
            match m.kind {
                MemberKind::User if syncable.contains_key(&m.id) => {
                    held.insert(m.id.clone());
                    mm.push(Subject::new(m.id.clone()));
                }
                // `selected`, not `shadow.groups`: a member group that exists in the
                // tenant but was not selected has no directory object, so naming it
                // here would put a member in `membership` that is absent from
                // `groups`. The planner drops such a reference silently when it
                // fails to resolve a DN for it, which makes this an invariant held
                // by accident two files away rather than stated here.
                MemberKind::Group if selected.contains(&m.id) => {
                    mm.push(Subject::new(m.id.clone()))
                }
                // A held user the tenant has but the syncable rule refuses is the confusing
                // case worth naming: the operator put them in the admission group and
                // no account appeared. An *absent* member is not reported -- that is
                // ordinary delta ordering, not a decision.
                MemberKind::User => {
                    if let Some(u) = shadow.users.get(&m.id)
                        && let Err(why) = user_syncable(u)
                    {
                        refused.push(format!(
                            "user {} ({}) is held by a selected group but gets no account: {why}",
                            m.id,
                            u.upn.as_deref().unwrap_or("no UPN")
                        ));
                    }
                }
                _ => {} // device/servicePrincipal, or an absent object: dropped
            }
        }
        groups.insert(
            Subject::new(gid.clone()),
            DesiredGroup { display_name: g.display_name.clone().unwrap_or_default() },
        );
        membership.insert(Subject::new(gid.clone()), mm);
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
    let users: BTreeMap<Subject, DesiredUser> = syncable
        .into_iter()
        .filter(|(oid, _)| held.contains(oid))
        .map(|(oid, u)| (Subject::new(oid), u))
        .collect();

    refused.sort();
    (Desired { users, groups, membership }, refused)
}

#[cfg(test)]
mod tests;
