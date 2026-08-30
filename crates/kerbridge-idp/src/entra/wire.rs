//! Microsoft Graph's wire shapes, and the shadow they patch.
//!
//! The read model is a **shadow** -- a locally accumulated copy of the directory
//! (IdP) that delta cycles patch. Graph delta entries are *sparse*: a change carries
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

use super::SamSource;
use crate::sync::{
    DesiredGroup, DesiredUser, Enumeration, Membership, NameCandidate, Refusal, Subject, dotted,
    local_part, name_candidate,
};

/// An object's class on a directory (IdP) membership edge, from `@odata.type`.
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

/// The accumulated directory (IdP) copy. Delta cycles mutate it; a full read starts
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

/// The address the account answers to: `mail`, or the first of `otherMails`
/// where it has none.
///
/// An account with no mailbox in this tenant has no `mail` at all, while
/// `otherMails` still holds an address the person actually uses. An account
/// invited from another tenant has that shape -- guest or member alike -- and
/// theirs is the UPN [`upn_local_part`] describes. Without `otherMails`,
/// `email_username` would fall through to it for exactly those accounts.
fn email_address(u: &ShadowUser) -> &str {
    match u.mail.as_deref() {
        Some(mail) if !mail.trim().is_empty() => mail,
        _ => u.other_mails.as_ref().and_then(|m| m.first()).map_or("", String::as_str),
    }
}

/// A UPN's local part, with Entra's `#EXT#` guest marker stripped.
///
/// `alice.anderson_gmail.com#EXT#@example.onmicrosoft.com` leaves
/// `alice.anderson_gmail.com`. That is not a local part: it is Entra's
/// flattening of the external address `alice.anderson@gmail.com` with the `@`
/// rewritten to `_`, and `.` and `_` are both legal in a login name, so the
/// domain riding along cannot be told from a surname. Both kinds of invited
/// account carry it -- a guest, and a member invited from another tenant.
fn upn_local_part(upn: &str) -> &str {
    local_part(upn).split('#').next().unwrap_or("")
}

/// What this account's login name may be minted from: **one candidate, or
/// none**.
///
/// The seam takes a list, and Entra offers at most one entry of it. The three
/// attributes below are a fallback order and not a set of alternatives: each
/// can be absent on a real account -- a user with no mailbox has no mail, a
/// display name is not enforced, and only the UPN is guaranteed to exist -- so
/// the configured one leads and the other two stand in where it yields nothing.
///
/// Offering the losers as further candidates would let a taken name fall to
/// another attribute instead of to the realm's `-<oid4>` suffix. That renames
/// live accounts that hold a suffixed name today, and a login name is a
/// Kerberos principal, so each such rename signs one user out. An adapter that
/// wants that behaviour returns more than one entry here; this one does not.
fn name_candidates(u: &ShadowUser, sam_source: SamSource) -> Vec<NameCandidate> {
    let display = dotted(u.display_name.as_deref().unwrap_or_default());
    let email = local_part(email_address(u));
    let upn = upn_local_part(u.upn.as_deref().unwrap_or_default());
    let order: [&str; 3] = match sam_source {
        SamSource::DisplayName => [&display, email, upn],
        // The UPN before the display name here, not after it: someone who asked
        // for an address-shaped name is better served by another address.
        SamSource::EmailUsername => [email, upn, &display],
        SamSource::Upn => [upn, &display, email],
    };
    // An attribute is spent only where it *yields* a candidate: a display name
    // of `...` is three allowed characters and no name, so testing the raw
    // string for blankness would spend the turn and leave a good mail address
    // unread.
    order.into_iter().find_map(name_candidate).into_iter().collect()
}

impl Shadow {
    /// The shadow as a whole directory (IdP) enumeration, with the syncable rule
    /// applied and every edge Samba cannot mirror dropped.
    ///
    /// The rule is Entra's own: `userType` is a wire fact about this IdP, so
    /// which accounts are acceptable is decided here and the closure walk that
    /// narrows them further is not. So is the naming: `sam_source` names Entra's
    /// own attributes, and the realm sees only the strings it produced.
    pub fn enumerate(&self, sam_source: SamSource) -> Enumeration {
        let mut read = Enumeration::default();
        for (oid, u) in &self.users {
            let subject = Subject::new(oid.clone());
            match user_syncable(u) {
                Ok(()) => {
                    read.users.insert(
                        subject,
                        DesiredUser {
                            display_name: u.display_name.clone().unwrap_or_default(),
                            name_candidates: name_candidates(u, sam_source),
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
