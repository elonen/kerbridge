//! authentik's REST wire shapes, and the assembly that turns a whole read into
//! an [`Enumeration`].
//!
//! There is no shadow and no delta here, because authentik has neither: every
//! cycle is a full read of `/core/users/` and `/core/groups/`, page by page,
//! `?ordering=pk`. So this module's job is not to patch an accumulated copy but
//! to prove a set of pages is one whole reading and refuse it when it is not.
//!
//! Completeness is **by construction, not by proof**: page-number pagination
//! over a pk-ordered stream, so a
//! `count` that falls between pages betrays a deletion mid-read and a pk that
//! does not sort strictly after the last betrays an insertion or a repeat. A
//! truncated 200 and an honest smaller 200 are the same bytes, so that hazard is
//! not expressible here; what *is* expressible is the asymmetry it leaves --
//! authentik's read has no races, so a **dangling id is a signal**, and any one
//! makes the read not whole rather than dropping a single row.
//!
//! [`assemble`] produces the neutral [`Enumeration`]; the realm's own rules
//! ([`build_desired`](crate::sync::build_desired)) narrow it to a desired state.
//! Both are pure and validated against `testbench/fixtures/authentik-directory/`.

use std::collections::{BTreeMap, HashSet};

use kerbridge_core::is_guid;
use serde::Deserialize;

use crate::sync::{
    DesiredGroup, DesiredUser, Enumeration, Membership, NameCandidate, Subject, dotted, local_part,
    name_candidate,
};

/// One page of a `?ordering=pk` list read.
///
/// Unknown fields are tolerated: a live page carries far more than the read
/// consumes, and the corpus keeps only what the read reads plus what carries a
/// structural case.
#[derive(Debug, Deserialize)]
pub struct Page<T> {
    pub pagination: Pagination,
    pub results: Vec<T>,
}

/// The page-number cursor authentik returns beside every list.
#[derive(Debug, Deserialize)]
pub struct Pagination {
    /// The next page number, or the integer `0` on the terminating page -- not
    /// null, not a URL, not an absent key.
    pub next: i64,
    /// authentik's own count of the whole collection, repeated on every page.
    /// A later page reporting fewer is the detectable half of a torn read.
    pub count: i64,
}

/// A `/core/users/` row, cut to what the read consumes.
///
/// `type` is deliberately absent: **nothing filters an account**. authentik puts
/// people and service accounts in one collection, so a `?type=` gate or a
/// `Member`-only rule would overrule the operator rather than protect them. The
/// admission closure is the only gate, and it lives above this module.
#[derive(Debug, Deserialize)]
pub struct RawUser {
    /// The integer primary key. A group names its members by this, and it is the
    /// key `?ordering=pk` sorts users by.
    pub pk: i64,
    pub username: String,
    /// authentik's display name field. Empty on an account that never set one.
    pub name: String,
    /// Django's `is_active`, orthogonal to type: a disabled account is still a
    /// person, and `/core/users/` returns it by default.
    pub is_active: bool,
    /// The uuid of every group this user is a direct member of. Read from
    /// `groups`, never `groups_obj`: under `include_groups=false` authentik nulls
    /// the object array and keeps this id array.
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub email: String,
    /// The stored subject, canonical lowercase hyphenated under `sub_mode:
    /// user_uuid`. The one identifier the REST API can be filtered on, which is
    /// why both faces key on it.
    pub uuid: String,
}

/// A `/core/groups/` row, cut to what the read consumes.
///
/// `parents` and `num_pk` are not read. Groups are a DAG, but `children` alone
/// is the parent-keyed edge list [`build_desired`] walks, so mirroring `parents`
/// too would double every edge.
#[derive(Debug, Deserialize)]
pub struct RawGroup {
    /// The group's uuid, its stable key and the value an admission binding names.
    pub pk: String,
    pub name: String,
    /// The integer pks of this group's direct member users. Read from `users`,
    /// never `users_obj`.
    #[serde(default)]
    pub users: Vec<i64>,
    /// The uuids of this group's direct child groups: the parent-keyed edge list.
    /// Read from `children`, never `children_obj`.
    #[serde(default)]
    pub children: Vec<String>,
}

/// The strings this account's login name may be minted from, best first.
///
/// **Three spellings, `username` first**, each reduced by the shared name rule
/// and dropped when nothing survives, deduplicated first-wins. `username` leads
/// because it is authentik's stable login handle; the dotted display name and
/// the address local part stand in where it collapses to nothing (a display name
/// of `...` is three allowed characters and no name). The display name earns its
/// place only to dodge a flattened external address like `alice.anderson_gmail`,
/// a shape authentik cannot produce -- but it costs nothing to keep as a
/// fallback, and the realm suffixes a collision either way.
fn name_candidates(u: &RawUser) -> Vec<NameCandidate> {
    let display = dotted(&u.name);
    let email = local_part(&u.email);
    let mut out: Vec<NameCandidate> = Vec::new();
    for raw in [u.username.as_str(), display.as_str(), email] {
        if let Some(candidate) = name_candidate(raw)
            && !out.iter().any(|held| held.as_str() == candidate.as_str())
        {
            out.push(candidate);
        }
    }
    out
}

/// Turn one whole read -- every user page and every group page, in the order
/// `?ordering=pk` returned them -- into an [`Enumeration`], or say why the read
/// is not whole.
///
/// The four ways it refuses, each a whole-read verdict rather than a per-row one:
///
/// - a `count` that falls between pages (a delete mid-read),
/// - a pk that does not sort strictly after the last (an insert or a repeat),
/// - a uuid that is not canonical lowercase (authentik serializes every uuid the
///   same way, so one bad spelling is a whole-population change, and a per-user
///   refusal would retire everyone at once through `encoded_identity`),
/// - a member, child or membership id that resolves to nothing (a dangling id).
pub fn assemble(users: &[Page<RawUser>], groups: &[Page<RawGroup>]) -> Result<Enumeration, String> {
    let user_rows = ordered(users, |u| u.pk, "user")?;
    let group_rows = ordered(groups, |g| g.pk.clone(), "group")?;

    let group_ids: HashSet<&str> = group_rows.iter().map(|g| g.pk.as_str()).collect();

    // pk -> subject, refusing the whole cycle on the first non-canonical uuid.
    let mut by_pk: BTreeMap<i64, Subject> = BTreeMap::new();
    let mut read = Enumeration::default();
    for u in &user_rows {
        if !is_guid(&u.uuid) {
            return Err(format!(
                "user {:?} (pk {}) carries a uuid that is not canonical lowercase ({:?}): \
                 UUIDField serializes every row the same way, so this is a whole-population \
                 serialization change, and refusing one account would retire the rest in silence",
                u.username, u.pk, u.uuid
            ));
        }
        let subject = Subject::new(u.uuid.clone());
        by_pk.insert(u.pk, subject.clone());
        read.users.insert(
            subject,
            DesiredUser {
                display_name: u.name.clone(),
                name_candidates: name_candidates(u),
                enabled: u.is_active,
            },
        );
    }

    // A visible user naming a group no page returned is a dangling id too, even
    // though this edge is read from the group side: the read is meant to have no
    // races, so any unresolved reference refuses it.
    for u in &user_rows {
        for gid in &u.groups {
            if !group_ids.contains(gid.as_str()) {
                return Err(format!(
                    "user {:?} names group {gid:?}, which no group page returned: a complete read \
                     has no dangling ids",
                    u.username
                ));
            }
        }
    }

    for g in &group_rows {
        let subject = Subject::new(g.pk.clone());
        read.groups.insert(subject.clone(), DesiredGroup { display_name: g.name.clone() });

        // Members first, in wire order, then child groups: the order
        // `build_desired` preserves into the mirrored membership.
        let mut edges: Vec<Membership> = Vec::new();
        for member in &g.users {
            match by_pk.get(member) {
                Some(user) => edges.push(Membership::User(user.clone())),
                None => {
                    return Err(format!(
                        "group {:?} names member user pk {member}, which no user page returned: a \
                         complete read has no dangling ids",
                        g.name
                    ));
                }
            }
        }
        for child in &g.children {
            if !group_ids.contains(child.as_str()) {
                return Err(format!(
                    "group {:?} names child group {child:?}, which no group page returned: a \
                     complete read has no dangling ids",
                    g.name
                ));
            }
            edges.push(Membership::Group(Subject::new(child.clone())));
        }
        read.membership.insert(subject, edges);
    }

    Ok(read)
}

/// Collect a collection's rows across its pages, refusing a torn read.
///
/// Two checks, each catching a torn read the other misses: the `count` must not
/// fall from one page to the next (a
/// deletion lowers it and slips a row between the pages), and each row's pk must
/// sort strictly after the last (an insertion into a pk-ordered stream reorders
/// it and repeats a row a falling count would not catch, because an insert
/// *raises* the count).
fn ordered<'a, T, K, F>(pages: &'a [Page<T>], key: F, what: &str) -> Result<Vec<&'a T>, String>
where
    K: PartialOrd + std::fmt::Debug,
    F: Fn(&T) -> K,
{
    let mut rows = Vec::new();
    let mut prev_count: Option<i64> = None;
    let mut last_key: Option<K> = None;
    for page in pages {
        if let Some(prev) = prev_count
            && page.pagination.count < prev
        {
            return Err(format!(
                "torn {what} read: a page counts {} where an earlier page counted {prev}, so an \
                 object was deleted mid-read and a row can fall between the pages",
                page.pagination.count
            ));
        }
        prev_count = Some(page.pagination.count);
        for row in &page.results {
            let this = key(row);
            if let Some(last) = &last_key
                && this <= *last
            {
                return Err(format!(
                    "torn {what} read: pk {this:?} does not sort after {last:?} under ?ordering=pk, \
                     so a row was inserted or repeated between pages"
                ));
            }
            last_key = Some(this);
            rows.push(row);
        }
    }
    Ok(rows)
}

#[cfg(test)]
mod tests;
