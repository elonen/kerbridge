//! Microsoft Graph's wire shapes, and the shadow they patch.
//!
//! The read model is a **shadow** -- a locally accumulated copy of the directory
//! that delta cycles patch. Graph delta entries are *sparse*: a change carries
//! only the properties that changed and only the membership edges that changed,
//! so a slice is merged into the shadow, never treated as a whole object. A user
//! object deletion arrives on the *users* stream and must be scrubbed from group
//! edges too, because Graph does not report it on the groups stream
//! (research spike `entra-directory-sync` @1.2).
//!
//! [`Shadow::enumerate`] then applies the syncable rule to turn the shadow into
//! an [`Enumeration`], which the realm's own rules narrow to a
//! [`Desired`](crate::sync::Desired). Both steps are pure and validated against
//! the recorded Graph fixtures: replaying the fixtures through the shadow
//! reproduces, byte for byte, the `desired` blocks the planner scenarios were
//! generated from.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::sync::{DesiredGroup, DesiredUser, Enumeration, Membership, Refusal, Subject};

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

impl Shadow {
    /// The shadow as a whole-directory enumeration, with the syncable rule
    /// applied and every edge Samba cannot mirror dropped.
    ///
    /// The rule is Entra's own: `userType` is a wire fact about this IdP, so
    /// which accounts are acceptable is decided here and the closure walk that
    /// narrows them further is not.
    pub fn enumerate(&self) -> Enumeration {
        let mut read = Enumeration::default();
        for (oid, u) in &self.users {
            let subject = Subject::new(oid.clone());
            match user_syncable(u) {
                Ok(()) => {
                    read.users.insert(
                        subject,
                        DesiredUser {
                            display_name: u.display_name.clone().unwrap_or_default(),
                            upn: u.upn.clone().unwrap_or_default(),
                            mail: u.mail.clone().unwrap_or_default(),
                            other_mails: u.other_mails.clone().unwrap_or_default(),
                            enabled: u.account_enabled.unwrap_or(false),
                        },
                    );
                }
                Err(why) => {
                    read.refused.insert(
                        subject,
                        Refusal {
                            who: format!("{oid} ({})", u.upn.as_deref().unwrap_or("no UPN")),
                            why: why.to_owned(),
                        },
                    );
                }
            }
        }
        for (gid, g) in &self.groups {
            let subject = Subject::new(gid.clone());
            read.groups.insert(
                subject.clone(),
                DesiredGroup { display_name: g.display_name.clone().unwrap_or_default() },
            );
            let edges = g
                .members
                .iter()
                .filter_map(|m| match m.kind {
                    MemberKind::User => Some(Membership::User(Subject::new(m.id.clone()))),
                    MemberKind::Group => Some(Membership::Group(Subject::new(m.id.clone()))),
                    // device/servicePrincipal: nothing the realm mirrors.
                    _ => None,
                })
                .collect();
            read.membership.insert(subject, edges);
        }
        read
    }
}

#[cfg(test)]
mod tests;
