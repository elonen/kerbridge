//! The reconciliation planner: a pure desired-versus-current comparison that
//! emits an ordered op list, conflicts, and alerts. No I/O, no side effects.
//!
//! Four safety properties are structural, not incidental:
//!
//! - A read that did not finish yields no
//!   [`kerbridge_idp::sync::SourceSnapshot`], so there is nothing to plan from
//!   and nothing can be deleted or disabled.
//! - Every op targets a DN inside the IdP-specific OU; [`Builder::add`] asserts it, so a
//!   bug cannot make the applier write outside this source's own OU.
//! - A `sAMAccountName` collision on any new group refuses the whole cycle rather
//!   than applying the rest, so a first deploy against a directory (realm) that already
//!   holds a same-named object never half-applies.
//! - There is no delete op. [`Op`] cannot express one, so no plan -- however
//!   wrong -- can destroy an object. Deletion is the operator's, through
//!   `kbmanage`, which says what a lost SID costs. Adding an `Op::Delete` here
//!   would weaken this deliberately.
//!
//! Validated op for op against the recorded scenarios in
//! `testbench/fixtures/planner/`, which `tests::corpus` replays and whose module
//! doc records where the planner diverges from them deliberately.
//!
//! The external-identity value is built by the configured adapter, through
//! [`PlanCtx::identity`], so sync writes exactly the bytes the broker's verifier
//! emits; the markers come from [`kerbridge_core::state`] for the same reason.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::marker::PhantomData;

// `Op::Rename` calls `modifydn` with no `newsuperior`, so AD keeps the parent and
// the post-rename DN has to be rebuilt from where the object actually is --
// rebuilding it from `idp_ou` names a non-existent object for anything in a
// sub-OU.
// Containment is component-wise, never `ends_with`: the two membership decisions
// below are "did sync put this member here, or did an operator", and an escaped
// comma puts a DN outside the OU that still ends with the base as a string.
use kerbridge_core::dn::{dn_is_at_or_within, parent_of};
// The markers are a wire format between processes that never talk to each
// other: sync stamps one, the broker reads it minutes later, an operator tool a
// month after that. One implementation, in kerbridge-core.
use kerbridge_core::grant::GRANT_PREFIX;
use kerbridge_core::sam;
use kerbridge_core::state::{
    RETIRED_PREFIX, ROLE_ADMISSION, ROLE_DEVICE_GRANT, ST_NAME_PINNED, ST_QUAR, ST_RETIRED,
};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use kerbridge_idp::sync::{Desired, DesiredUser, Subject};

mod names;

pub(crate) use names::group_suffix_rejection;
use names::*;

/// An order-preserving map deserialized straight from a JSON object in document
/// order. `current` comes from LDAP in receipt order, and the duplicate-identity
/// scan reports objects in that order; a `BTreeMap` would silently re-sort it.
#[derive(Debug, Clone, Default)]
pub struct OrderedMap<T>(pub Vec<(String, T)>);

impl<T> OrderedMap<T> {
    pub fn iter(&self) -> impl Iterator<Item = (&String, &T)> {
        self.0.iter().map(|(k, v)| (k, v))
    }
    fn lookup(&self) -> HashMap<&str, &T> {
        self.0.iter().map(|(k, v)| (k.as_str(), v)).collect()
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for OrderedMap<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for V<T> {
            type Value = OrderedMap<T>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a map")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut m: M) -> Result<OrderedMap<T>, M::Error> {
                let mut out = Vec::new();
                while let Some((k, v)) = m.next_entry::<String, T>()? {
                    out.push((k, v));
                }
                Ok(OrderedMap(out))
            }
        }
        deserializer.deserialize_map(V(PhantomData))
    }
}

/// Current state, read from Samba. Only objects carrying a `kb1` identity for
/// this instance's own source reach `users`/`groups`; everything else in the OU
/// lands in `unmanaged_dns` and is reported but never touched.
#[derive(Debug, Clone, Deserialize)]
pub struct Current {
    pub users: OrderedMap<CurrentUser>,
    pub groups: OrderedMap<CurrentGroup>,
    #[serde(default)]
    pub foreign_sams: Vec<String>,
    #[serde(default)]
    pub unmanaged_dns: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CurrentUser {
    pub dn: String,
    pub sam: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub enabled: bool,
    #[serde(default)]
    pub markers: Vec<String>,
    pub identity: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CurrentGroup {
    pub dn: String,
    pub sam: String,
    pub display_name: String,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub markers: Vec<String>,
    pub identity: String,
}

/// One reconciliation action. Serializes to the exact `{op, dn, ...}` shape the
/// applier consumes and the fixtures record; optional fields are omitted when
/// absent so a user rename and a group rename produce distinct payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    CreateUser {
        dn: String,
        sam: String,
        upn: String,
        display_name: String,
        enabled: bool,
        identity: String,
    },
    CreateGroup {
        dn: String,
        sam: String,
        identity: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        role_marker: Option<String>,
    },
    AddMember {
        dn: String,
        member: String,
    },
    RemoveMember {
        dn: String,
        member: String,
    },
    EnableUser {
        dn: String,
    },
    DisableUser {
        dn: String,
    },
    Rename {
        dn: String,
        new_cn: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        set_display_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        set_sam: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        set_upn: Option<String>,
    },
    SetAttr {
        dn: String,
        attr: String,
        value: String,
    },
    SetMarker {
        dn: String,
        value: String,
    },
    SetRoleMarker {
        dn: String,
        value: String,
    },
    ClearMarker {
        dn: String,
        prefix: String,
    },
    ClearMembers {
        dn: String,
        /// The members that must survive: everything on the group that sync does
        /// not own. Named as a keep-set rather than a remove-set because the
        /// members sync is dropping may have been renamed earlier in this same
        /// plan -- a retiring user is renamed before the group holding it is
        /// quarantined -- and a keep-set names none of them. Omitted from the
        /// serialized op when empty, which is the common case.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        keep: Vec<String>,
    },
}

impl Op {
    /// The DN this op targets -- the one thing that must be inside the IdP-specific OU.
    pub fn dn(&self) -> &str {
        match self {
            Op::CreateUser { dn, .. }
            | Op::CreateGroup { dn, .. }
            | Op::AddMember { dn, .. }
            | Op::RemoveMember { dn, .. }
            | Op::EnableUser { dn }
            | Op::DisableUser { dn }
            | Op::Rename { dn, .. }
            | Op::SetAttr { dn, .. }
            | Op::SetMarker { dn, .. }
            | Op::SetRoleMarker { dn, .. }
            | Op::ClearMarker { dn, .. }
            | Op::ClearMembers { dn, .. } => dn,
        }
    }

    /// The `op` tag this serializes under, for the one line the audit file keeps
    /// per applied write. A second spelling of the `rename_all = "snake_case"`
    /// names above, held to them by `the_audited_op_name_is_the_serialized_op_tag`
    /// -- drifting apart would leave the record ungreppable against the plan that
    /// caused it.
    pub fn kind(&self) -> &'static str {
        match self {
            Op::CreateUser { .. } => "create_user",
            Op::CreateGroup { .. } => "create_group",
            Op::AddMember { .. } => "add_member",
            Op::RemoveMember { .. } => "remove_member",
            Op::EnableUser { .. } => "enable_user",
            Op::DisableUser { .. } => "disable_user",
            Op::Rename { .. } => "rename",
            Op::SetAttr { .. } => "set_attr",
            Op::SetMarker { .. } => "set_marker",
            Op::SetRoleMarker { .. } => "set_role_marker",
            Op::ClearMarker { .. } => "clear_marker",
            Op::ClearMembers { .. } => "clear_members",
        }
    }
}

/// Which operator channel an alert belongs on.
///
/// The planner knows what it has found. Deriving the class back out of the
/// sentence at the notification boundary is how both device-grant alerts reached
/// the console and nothing else, while a reworded message would have silently
/// unrouted the admission one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    /// Reconciliation is frozen and the broker fails closed.
    AdmissionGroup,
    /// Device grants are not in the state the configuration describes.
    DeviceGrantGroup,
    /// Worth the log and nothing louder.
    Note,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Alert {
    pub kind: AlertKind,
    pub message: String,
}

impl Alert {
    fn admission(message: String) -> Self {
        Self { kind: AlertKind::AdmissionGroup, message }
    }
    fn device_grant(message: String) -> Self {
        Self { kind: AlertKind::DeviceGrantGroup, message }
    }
    fn note(message: String) -> Self {
        Self { kind: AlertKind::Note, message }
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Plan {
    pub ops: Vec<Op>,
    pub conflicts: Vec<String>,
    pub alerts: Vec<Alert>,
}

/// A refusal to plan at all: the input is in a state where any reconciliation
/// would risk the wrong thing, so the caller must stop rather than proceed with
/// a partial plan.
///
/// A variant per case, never one blocked-with-a-sentence: the caller routes each
/// to its own operator problem, and deriving the class back out of the sentence
/// is how a reworded message silently unroutes itself.
#[derive(Debug)]
pub enum PlanError {
    /// One or more desired objects need a `sAMAccountName` that already belongs to
    /// a different object. The whole cycle is refused -- nothing is touched -- so
    /// a first deploy against a directory (realm) that already holds a same-named object
    /// never half-applies. The operator resolves the listed collisions.
    ///
    /// Two cloud IdPs that both hold, say, a `payroll` group reach this without
    /// anyone having done anything wrong: a name is unique per source, and the
    /// directory (realm) gives them one namespace. Distinct `group_suffix` values
    /// are what keep them apart.
    NameCollision(Vec<String>),
}

/// The parts of the deployment the planner needs to form DNs and stamp markers.
pub struct PlanCtx<'a> {
    /// `OU=Entra,OU=CloudIdP,<base_dn>` -- the one OU the planner may write.
    pub idp_ou: &'a str,
    /// The group that admits people to the realm. Absent from `desired.groups`
    /// freezes the cycle: no ops at all.
    pub admission: &'a Subject,
    /// The device-grant group, if the deployment names one.
    pub grant: Option<&'a Subject>,
    /// The AD DNS domain, used as the UPN suffix for created users.
    pub upn_suffix: &'a str,
    /// What every group's `sAMAccountName` ends with, keeping this source's
    /// group names out of every other source's. Empty is one deployment's
    /// deliberate choice (`group_suffix = "none"`) and only safe while this
    /// is the only cloud IdP -- see [`PlanError::NameCollision`] for what two
    /// unsuffixed sources cost.
    pub group_suffix: &'a str,
    /// RFC 3339 timestamp stamped into retire/quarantine markers.
    pub now: &'a str,
    /// Whether a live account's login name follows its cloud display name after
    /// creation. Off means it is set once and never moves again.
    pub automatic_sam_renames: bool,
    /// How this source's subjects become stored identity values.
    ///
    /// Adapter-owned, and reached through it rather than reimplemented here:
    /// the broker's verifier emits this same value from the token side, and its
    /// LDAP search is an exact match, so a byte of difference means "user not
    /// synchronized" for everyone. `Err` for a subject the format cannot hold --
    /// a value past the attribute's ceiling -- which is reported and the object
    /// left alone, exactly like an identity this tool cannot read.
    pub identity: &'a dyn Fn(&Subject) -> Result<String, kerbridge_core::IdentityError>,
}

/// Accumulates ops while enforcing the source-OU invariant on every one.
struct Builder<'a> {
    plan: Plan,
    idp_ou: &'a str,
}

/// The stored identity for a subject, or `None` with a conflict recorded.
///
/// Here because the subject is the adapter's to shape, so the next one is not
/// this crate's to reason about. Reported rather than skipped silently: an
/// account that quietly never appears is the failure an operator cannot debug.
///
/// For Entra the length never binds -- a GUID is 36 characters and the format
/// holds 256 -- but the shape does: the adapter refuses an `oid` that is not a
/// canonical GUID, here as at the broker.
fn encoded_identity(b: &mut Builder<'_>, ctx: &PlanCtx<'_>, oid: &Subject) -> Option<String> {
    match (ctx.identity)(oid) {
        Ok(value) => Some(value),
        Err(why) => {
            b.plan.conflicts.push(format!(
                "{} has no encodable identity ({why}) - nothing created",
                oid.as_str()
            ));
            None
        }
    }
}

impl Builder<'_> {
    fn add(&mut self, op: Op) {
        assert!(
            dn_is_at_or_within(op.dn(), self.idp_ou),
            "structural violation: op outside the IdP-specific OU: {}",
            op.dn()
        );
        self.plan.ops.push(op);
    }
}

/// Compare desired against current and produce the ordered plan.
pub fn plan_sync(
    desired: &Desired,
    current: &Current,
    ctx: &PlanCtx<'_>,
) -> Result<Plan, PlanError> {
    let mut b = Builder { plan: Plan::default(), idp_ou: ctx.idp_ou };

    // ---- admission-group invariants (fail closed) ----
    let admission_oid = ctx.admission;
    if !desired.groups.contains_key(admission_oid) {
        b.plan.alerts.push(Alert::admission(
            "ADMISSION GROUP missing from desired state: reconciliation FROZEN; broker will fail \
             closed via role marker; operator escalation required"
                .to_owned(),
        ));
        return Ok(b.plan); // conservative freeze: no ops at all
    }

    let cur_users = current.users.lookup();
    let cur_groups = current.groups.lookup();

    // ---- a whole read describing nobody is a fault, not an empty IdP ----
    // A read that did not finish never gets here: it yields no snapshot. This
    // covers the one that did finish: a 200 with an empty page, an admission
    // group whose membership came back empty, a permissions change that quietly stopped
    // expanding it. Every one of those is indistinguishable from "the IdP has
    // no users", and acting on it retires every account in a single cycle --
    // recoverable only by restoring the directory (realm), and a total outage until
    // someone does. The first deployment is unaffected: nothing is synchronized
    // yet, so there is nothing to lose.
    if desired.users.is_empty() && !cur_users.is_empty() {
        b.plan.alerts.push(Alert::admission(format!(
            "ADMISSION GROUP expansion yields no users at all while {} are synchronized: \
             reconciliation FROZEN, operator escalation required. If this is deliberate, the \
             accounts are removed one at a time with `kbmanage cloud delete` -- or stop the \
             broker to cut access immediately; sync will not empty the directory (realm) in one \
             cycle on the strength of an empty read",
            cur_users.len()
        )));
        return Ok(b.plan); // conservative freeze: no ops at all
    }

    let mut marked: Vec<&str> = current
        .groups
        .iter()
        .filter(|(_, g)| g.markers.iter().any(|m| m == ROLE_ADMISSION))
        .map(|(oid, _)| oid.as_str())
        .collect();
    // A marker on a group other than the configured one is moved to obey the
    // configuration. The configured group is stated by object id, which is an
    // identity -- the vocabulary the role marker itself speaks -- so "the
    // operator repointed the realm" is the only reading, exactly as for the
    // device-grant marker below.
    //
    // The move is clear-then-stamp across the plan, so any partial apply
    // leaves too few markers rather than too many: the broker refuses logins
    // either way, but a shortfall is re-stamped by the next cycle unaided,
    // while a surplus would read as ambiguous. Emptying `marked` is what hands
    // the stamping to the same code that marks a fresh deployment.
    for stale in marked.iter().filter(|m| **m != admission_oid.as_str()) {
        b.add(Op::ClearMarker {
            dn: cur_groups[*stale].dn.clone(),
            prefix: ROLE_ADMISSION.to_owned(),
        });
    }
    marked.retain(|m| *m == admission_oid.as_str());

    // ---- ambiguous external identity in current -> conflict, never touch ----
    // Iterated in receipt order (users then groups); an oid never spans kinds,
    // so the same-kind dn lookup is always the right one.
    let mut seen: HashMap<&str, &str> = HashMap::new();
    let mut dupes: HashSet<&str> = HashSet::new();
    for (oid, u) in current.users.iter() {
        if let Some(&prev) = seen.get(u.identity.as_str()) {
            dupes.insert(oid.as_str());
            dupes.insert(prev);
            b.plan.conflicts.push(format!(
                "ambiguous identity value on {} and {} - both excluded",
                u.dn, cur_users[prev].dn
            ));
        }
        seen.insert(u.identity.as_str(), oid.as_str());
    }
    for (oid, g) in current.groups.iter() {
        if let Some(&prev) = seen.get(g.identity.as_str()) {
            dupes.insert(oid.as_str());
            dupes.insert(prev);
            b.plan.conflicts.push(format!(
                "ambiguous identity value on {} and {} - both excluded",
                g.dn, cur_groups[prev].dn
            ));
        }
        seen.insert(g.identity.as_str(), oid.as_str());
    }
    let dupe_dns: HashSet<&str> = current
        .users
        .iter()
        .filter(|(oid, _)| dupes.contains(oid.as_str()))
        .map(|(_, u)| u.dn.as_str())
        .chain(
            current
                .groups
                .iter()
                .filter(|(oid, _)| dupes.contains(oid.as_str()))
                .map(|(_, g)| g.dn.as_str()),
        )
        .collect();

    // ---- objects in the OU this source does not own: report, never touch ----
    // Two different situations under one heading, deliberately: an object with no
    // readable kb1 identity, and one carrying another source's. Both mean the same
    // thing to this cycle -- not mine, do not reconcile -- and the DN is what an
    // operator needs either way.
    for dn in &current.unmanaged_dns {
        b.plan.conflicts.push(format!(
            "object in the OU with no kb1 identity for this source: {dn} - left untouched"
        ));
    }

    let mut dn_of: HashMap<&Subject, String> = HashMap::new();
    let mut taken_dns: HashSet<String> = current
        .users
        .iter()
        .map(|(_, u)| u.dn.clone())
        .chain(current.groups.iter().map(|(_, g)| g.dn.clone()))
        .chain(current.unmanaged_dns.iter().cloned())
        .collect();

    // ---- users ----
    // AD's account-name namespace is shared by users and groups, so both kinds of
    // managed sam belong here: one is what a new name must not collide with.
    //
    // `sam::fold` keys, not names: AD is case-insensitive here and Rust `String`
    // is not. Everything that touches this set folds first -- see `sam::fold` for
    // what a byte-exact check costs.
    let mut sam_keys: HashSet<String> = current.foreign_sams.iter().map(|s| sam::fold(s)).collect();
    for (_, u) in current.users.iter() {
        sam_keys.insert(sam::fold(&u.sam));
    }
    for (_, g) in current.groups.iter() {
        sam_keys.insert(sam::fold(&g.sam));
    }
    for (oid, du) in desired.users.iter() {
        if dupes.contains(oid.as_str()) {
            continue;
        }
        match cur_users.get(oid.as_str()) {
            None => {
                // Before any name is allocated: a subject that cannot be
                // encoded must not consume the sam this account would have had.
                let Some(identity) = encoded_identity(&mut b, ctx, oid) else {
                    continue;
                };
                let (sam, upn, cn) = alloc_names(du, oid.as_str(), &sam_keys, ctx.upn_suffix)?;
                sam_keys.insert(sam::fold(&sam));
                let dn = fresh_dn(&cn, oid.as_str(), ctx.idp_ou, &mut taken_dns);
                dn_of.insert(oid, dn.clone());
                b.add(Op::CreateUser {
                    dn,
                    sam,
                    upn,
                    display_name: du.display_name.clone(),
                    enabled: du.enabled,
                    identity,
                });
            }
            Some(cu) => {
                dn_of.insert(oid, cu.dn.clone());
                let retired = cu.markers.iter().any(|m| m.starts_with(ST_RETIRED));
                let mut restored = false;
                if retired {
                    // reappearance during retention
                    b.add(Op::ClearMarker { dn: cu.dn.clone(), prefix: ST_RETIRED.to_owned() });
                    if du.enabled && !cu.enabled {
                        b.add(Op::EnableUser { dn: cu.dn.clone() });
                    }
                    // Take the name retirement freed back -- through `alloc_names`,
                    // not from what is stored, because someone else may hold it by
                    // now and the `-<oid4>` fallback is the right answer when they
                    // do. Her own held name must read as free to her.
                    sam_keys.remove(&sam::fold(&cu.sam));
                    let (sam, upn, mut cn) =
                        alloc_names(du, oid.as_str(), &sam_keys, ctx.upn_suffix)?;
                    sam_keys.insert(sam::fold(&sam));
                    let parent = parent_of(&cu.dn);
                    let mut newdn = format!("CN={cn},{parent}");
                    if newdn != cu.dn && taken_dns.contains(&newdn) {
                        cn = format!("{cn} ({})", oid4(oid.as_str()));
                        newdn = format!("CN={cn},{parent}");
                    }
                    // Silent when nothing moved: an uncontested reappearance of a
                    // user who never lost the name plans no rename at all.
                    if sam != cu.sam || newdn != cu.dn {
                        taken_dns.insert(newdn.clone());
                        let want = du.display_name.as_str();
                        b.add(Op::Rename {
                            dn: cu.dn.clone(),
                            new_cn: cn,
                            set_display_name: (cu.display_name.as_deref() != Some(want))
                                .then(|| du.display_name.clone()),
                            set_sam: Some(sam),
                            set_upn: Some(upn),
                        });
                        dn_of.insert(oid, newdn);
                        restored = true;
                    }
                } else if du.enabled != cu.enabled {
                    b.add(if du.enabled {
                        Op::EnableUser { dn: cu.dn.clone() }
                    } else {
                        Op::DisableUser { dn: cu.dn.clone() }
                    });
                }

                // A live account's login name follows its display name, unless
                // an operator has pinned it. The name is not an internal key --
                // Windows shows it as the file owner and in the *Security* tab
                // -- so an old name on their files means the directory (realm) is stale.
                //
                // It costs the user a sign-out: the sam is their Kerberos
                // principal, and tickets already issued name the old one.
                // `automatic_sam_renames = false` trades that away and freezes
                // every live name instead.
                let pinned = cu.markers.iter().any(|m| m.starts_with(ST_NAME_PINNED));
                if !restored && ctx.automatic_sam_renames && !pinned {
                    // Her own name must read as free to her, exactly as at
                    // reappearance: otherwise every account collides with itself
                    // and drifts into the `-<oid4>` fallback.
                    sam_keys.remove(&sam::fold(&cu.sam));
                    let (sam, upn, _) = alloc_names(du, oid.as_str(), &sam_keys, ctx.upn_suffix)?;
                    sam_keys.insert(sam::fold(&sam));
                    if sam != cu.sam {
                        // The DN is left where it is: the CN follows the display
                        // name on its own path below, and moving it from here
                        // would race that.
                        b.add(Op::SetAttr {
                            dn: cu.dn.clone(),
                            attr: "sAMAccountName".to_owned(),
                            value: sam,
                        });
                        b.add(Op::SetAttr {
                            dn: cu.dn.clone(),
                            attr: "userPrincipalName".to_owned(),
                            value: upn,
                        });
                    }
                }
                if !restored && cu.display_name.as_deref() != Some(du.display_name.as_str()) {
                    // Falls back to the account's own sam: a display name that
                    // sanitizes to nothing would build `CN=,OU=Entra,…`.
                    let newcn = safe_name(&du.display_name).unwrap_or_else(|| cu.sam.clone());
                    let newdn = format!("CN={newcn},{}", parent_of(&cu.dn));
                    if newdn == cu.dn {
                        b.add(Op::SetAttr {
                            dn: cu.dn.clone(),
                            attr: "displayName".to_owned(),
                            value: du.display_name.clone(),
                        });
                    } else if taken_dns.contains(&newdn) {
                        let sufdn =
                            format!("CN={newcn} ({}),{}", oid4(oid.as_str()), parent_of(&cu.dn));
                        if sufdn == cu.dn {
                            b.add(Op::SetAttr {
                                dn: cu.dn.clone(),
                                attr: "displayName".to_owned(),
                                value: du.display_name.clone(),
                            });
                        } else {
                            taken_dns.insert(sufdn.clone());
                            b.add(Op::Rename {
                                dn: cu.dn.clone(),
                                new_cn: format!("{newcn} ({})", oid4(oid.as_str())),
                                set_display_name: Some(du.display_name.clone()),
                                set_sam: None,
                                set_upn: None,
                            });
                            dn_of.insert(oid, sufdn);
                        }
                    } else {
                        taken_dns.insert(newdn.clone());
                        b.add(Op::Rename {
                            dn: cu.dn.clone(),
                            new_cn: newcn,
                            set_display_name: Some(du.display_name.clone()),
                            set_sam: None,
                            set_upn: None,
                        });
                        dn_of.insert(oid, newdn);
                    }
                }
            }
        }
    }
    // users present in Samba but gone from the IdP: disable and start retention.
    //
    // `current` is keyed by the subject parsed back out of the stored identity,
    // so the comparison is against text. Same in the group loop below.
    let desired_users: HashSet<&str> = desired.users.keys().map(Subject::as_str).collect();
    let mut cur_user_oids: Vec<&str> = current.users.iter().map(|(oid, _)| oid.as_str()).collect();
    cur_user_oids.sort_unstable();
    for oid in cur_user_oids {
        if desired_users.contains(oid) || dupes.contains(oid) {
            continue;
        }
        let cu = cur_users[oid];
        if !cu.markers.iter().any(|m| m.starts_with(ST_RETIRED)) {
            b.add(Op::DisableUser { dn: cu.dn.clone() });
            b.add(Op::SetMarker { dn: cu.dn.clone(), value: format!("{ST_RETIRED}{}", ctx.now) });
        }
        // Retirement is a revocation, and a revocation that undoes itself on
        // re-adoption is not one: a rehire whose machine still holds the key
        // would otherwise resume getting tickets with nobody re-authorizing it,
        // bounded only by the grant's own deadline -- which a builder-style
        // duration outlives easily. Disable deliberately does *not* do this: a
        // disabled account's grants are already inert via the enabled check, and
        // disable/re-enable is an ordinary admin action where restoring access
        // is usually the intent.
        //
        // Gated on presence rather than on the marker above, so it is idempotent
        // and so an object retired before this shipped is cleaned up too. Before
        // the rename, because the ops after it address the post-rename DN.
        if cu.markers.iter().any(|m| m.starts_with(GRANT_PREFIX)) {
            b.add(Op::ClearMarker { dn: cu.dn.clone(), prefix: GRANT_PREFIX.to_owned() });
        }
        // Nothing durable on a file server is keyed to the name -- only to the
        // SID -- so holding it through retention buys nothing while a returning
        // object may urgently need it. Gated on the name and not on the marker
        // above: idempotent by construction, and it migrates objects that were
        // already retired when this shipped instead of holding them forever.
        // Last, because the ops before it address the pre-rename DN.
        if !cu.sam.starts_with(RETIRED_PREFIX) {
            let label = cu.display_name.as_deref().unwrap_or(&cu.sam);
            let (sam, new_cn) =
                retired_names(&cu.dn, &cu.sam, label, oid, &mut sam_keys, &mut taken_dns);
            // `samldb` enforces uniqueness on the UPN too, so leaving it behind
            // would reproduce this failure one attribute over.
            let upn = format!("{sam}@{}", ctx.upn_suffix);
            b.add(Op::Rename {
                dn: cu.dn.clone(),
                new_cn,
                set_display_name: None,
                set_sam: Some(sam),
                set_upn: Some(upn),
            });
        }
    }

    // ---- fail closed on any sAMAccountName collision: refuse the whole cycle ----
    // A new group's sAMAccountName is its display name, and AD's account-name
    // namespace -- shared by users and groups -- must be unique. If a name a new
    // group needs is already taken (a foreign on-prem object, or another managed
    // or newly-created one), refuse to plan at all rather than sync the rest and
    // skip the collider: a half-applied cycle is worse than none, and a group is
    // referenced by name in resource ACLs, so it must never be silently renamed.
    // The operator resolves the collision, then sync proceeds. `sam_keys` already
    // holds every foreign sam and every managed/created user and group sam --
    // including another cloud IdP's, since the scan behind it is domain-wide.
    // `ctx.group_suffix` is what keeps two sources out of each other's names.
    //
    // Case-folded, and that is what makes this gate work at all. A group sam is the
    // display name verbatim -- `group_names` does not run it through `sanitize_sam`
    // -- so `Sales` and `sales` are two different `String`s, and a byte-exact check
    // plans both: AD takes the first, refuses the second, and the apply failure
    // repeats silently on every cycle forever.
    let mut collisions = Vec::new();
    let mut new_group_keys: HashSet<String> = HashSet::new();
    for (oid, dg) in desired.groups.iter() {
        if dupes.contains(oid.as_str()) || cur_groups.contains_key(oid.as_str()) {
            continue;
        }
        let (_, sam) = group_names(&dg.display_name, oid.as_str(), ctx.group_suffix);
        let key = sam::fold(&sam);
        if sam_keys.contains(&key) || !new_group_keys.insert(key) {
            collisions.push(format!("{:?} (group {})", dg.display_name, oid.as_str()));
        }
    }
    if !collisions.is_empty() {
        return Err(PlanError::NameCollision(collisions));
    }

    // ---- groups ----
    for (oid, dg) in desired.groups.iter() {
        if dupes.contains(oid.as_str()) {
            continue;
        }
        match cur_groups.get(oid.as_str()) {
            None => {
                let Some(identity) = encoded_identity(&mut b, ctx, oid) else {
                    continue;
                };
                let (cn, sam) = group_names(&dg.display_name, oid.as_str(), ctx.group_suffix);
                let dn = fresh_dn(&cn, oid.as_str(), ctx.idp_ou, &mut taken_dns);
                dn_of.insert(oid, dn.clone());
                let role_marker = if oid == admission_oid {
                    if marked.is_empty() {
                        // The re-check this names is real: Directory::apply_one
                        // re-reads the marker before stamping one. Wording frozen
                        // by the S1 fixture, which asserts this string.
                        b.plan.alerts.push(Alert::note(
                            "admission group must be created and marked; requires empty-marker \
                             precondition re-check at apply time"
                                .to_owned(),
                        ));
                    }
                    Some(ROLE_ADMISSION.to_owned())
                } else {
                    None
                };
                b.add(Op::CreateGroup { dn, sam, identity, role_marker });
            }
            Some(cg) => {
                dn_of.insert(oid, cg.dn.clone());
                if cg.markers.iter().any(|m| m.starts_with(ST_QUAR)) {
                    // group reappearance during retention
                    b.add(Op::ClearMarker { dn: cg.dn.clone(), prefix: ST_QUAR.to_owned() });
                }
                if dg.display_name != cg.display_name {
                    let (cn, sam) = group_names(&dg.display_name, oid.as_str(), ctx.group_suffix);
                    let parent = parent_of(&cg.dn);
                    let mut newdn = format!("CN={cn},{parent}");
                    if newdn != cg.dn && taken_dns.contains(&newdn) {
                        newdn = format!("CN={cn} ({}),{parent}", oid4(oid.as_str()));
                    }
                    if newdn != cg.dn {
                        taken_dns.insert(newdn.clone());
                        let new_cn = newdn.split(',').next().unwrap()[3..].to_owned();
                        b.add(Op::Rename {
                            dn: cg.dn.clone(),
                            new_cn,
                            set_display_name: None,
                            set_sam: Some(sam),
                            set_upn: None,
                        });
                        dn_of.insert(oid, newdn);
                    }
                }
                if oid == admission_oid && marked.is_empty() {
                    b.add(Op::SetRoleMarker {
                        dn: cg.dn.clone(),
                        value: ROLE_ADMISSION.to_owned(),
                    });
                }
            }
        }
    }
    // groups present in Samba but gone from the IdP: quarantine (or freeze if admission
    // group).
    let desired_groups: HashSet<&str> = desired.groups.keys().map(Subject::as_str).collect();
    let mut cur_group_oids: Vec<&str> =
        current.groups.iter().map(|(oid, _)| oid.as_str()).collect();
    cur_group_oids.sort_unstable();
    for oid in cur_group_oids {
        if desired_groups.contains(oid) || dupes.contains(oid) {
            continue;
        }
        let cg = cur_groups[oid];
        // A marker on any other group is cleared this cycle, so it no longer
        // means "this is the admission group" and its carrier is an ordinary
        // leaver, quarantined below like any other.
        if oid == admission_oid.as_str() {
            b.plan.alerts.push(Alert::admission(format!(
                "ADMISSION GROUP {} vanished from desired state: FROZEN, operator escalation",
                cg.dn
            )));
            continue;
        }
        if !cg.markers.iter().any(|m| m.starts_with(ST_QUAR)) {
            // IdP-owned direct membership only, exactly as on the reconcile path
            // below: a member nested from outside the IdP-specific OU was put
            // there by an operator, and quarantining a group is not license to
            // undo that.
            let mut keep: Vec<String> =
                cg.members.iter().filter(|m| !dn_is_at_or_within(m, ctx.idp_ou)).cloned().collect();
            keep.sort_unstable();
            for m in &keep {
                b.plan.conflicts.push(format!(
                    "foreign member {m} in quarantined group {} - left in place, reported",
                    cg.dn
                ));
            }
            b.add(Op::ClearMembers { dn: cg.dn.clone(), keep });
            b.add(Op::SetMarker { dn: cg.dn.clone(), value: format!("{ST_QUAR}{}", ctx.now) });
        }
        // Same release as at retirement, and the same name gate. A group needs no
        // UPN move; on reappearance the branch above renames it back unaided,
        // because `CreateGroup` writes no `displayName` and the CN it falls back
        // to now differs from the desired one.
        if !cg.sam.starts_with(RETIRED_PREFIX) {
            let (sam, new_cn) = retired_names(
                &cg.dn,
                &cg.sam,
                &cg.display_name,
                oid,
                &mut sam_keys,
                &mut taken_dns,
            );
            b.add(Op::Rename {
                dn: cg.dn.clone(),
                new_cn,
                set_display_name: None,
                set_sam: Some(sam),
                set_upn: None,
            });
        }
    }

    // ---- device-grant group role marker ----
    // Mirrors the admission group's marker, with two deliberate differences.
    // Nothing here freezes the cycle: admission decides whether anyone gets a
    // ticket at all, so an ambiguous marker there has to stop everything, while
    // device grants are an optional convenience that already fails closed on its
    // own -- the broker looks the group up by marker and refuses every grant when
    // it cannot find exactly one. And a marker on the wrong group is moved, not
    // frozen on: the configured group is an object id, which is as explicit as an
    // operator statement gets, and an id naming no synchronized group is alerted
    // on below instead.
    let grant_marked: Vec<&str> = current
        .groups
        .iter()
        .filter(|(_, g)| g.markers.iter().any(|m| m == ROLE_DEVICE_GRANT))
        .map(|(oid, _)| oid.as_str())
        .collect();
    match ctx.grant {
        // Nothing configured, but a group still carries the marker: the operator
        // has unset the group without unmarking it, so device grants keep
        // working for whoever is in it. Reported, never undone -- sync removing a
        // marker on the strength of an absent setting is how a typo becomes an
        // outage.
        None if !grant_marked.is_empty() => b.plan.alerts.push(Alert::device_grant(format!(
            "DEVICE-GRANT GROUP unset while {grant_marked:?} still carries {ROLE_DEVICE_GRANT}: \
             device grants remain available to its members"
        ))),
        None => {}
        Some(oid) if !desired.groups.contains_key(oid) => {
            b.plan.alerts.push(Alert::device_grant(format!(
                "DEVICE-GRANT GROUP {} is not in the synchronized set: no device grant can be \
                 created or used until it is",
                oid.as_str()
            )))
        }
        // Exactly the configured group carries the marker when this converges.
        // Clear-then-set means a mid-apply failure leaves zero markers, not two:
        // grants refused, which is the fail-closed side, until the next cycle
        // completes the move. The `if let` skips an identity-conflicted target
        // the group loop refused to manage -- markers then stay where they are.
        Some(oid) => {
            if let Some(dn) = dn_of.get(oid) {
                for marked in &grant_marked {
                    if *marked != oid.as_str() {
                        b.add(Op::ClearMarker {
                            dn: cur_groups[*marked].dn.clone(),
                            prefix: ROLE_DEVICE_GRANT.to_owned(),
                        });
                    }
                }
                if !grant_marked.contains(&oid.as_str()) {
                    b.add(Op::SetRoleMarker {
                        dn: dn.clone(),
                        value: ROLE_DEVICE_GRANT.to_owned(),
                    });
                }
            }
        }
    }

    // ---- IdP-owned direct membership (groups in the IdP-specific OU, by construction) ----
    // Samba rewrites DN-valued member links when a member is renamed, so compare
    // against post-rename DNs: a planned rename is membership-invariant.
    // Owned keys so the map does not borrow `b` across the mutating loop below.
    let rename_map: HashMap<String, String> = b
        .plan
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::Rename { dn, new_cn, .. } => {
                Some((dn.clone(), format!("CN={new_cn},{}", parent_of(dn))))
            }
            _ => None,
        })
        .collect();
    for (goid, want_oids) in desired.membership.iter() {
        if dupes.contains(goid.as_str()) || !desired.groups.contains_key(goid) {
            continue;
        }
        let Some(gdn) = dn_of.get(goid).cloned() else {
            continue;
        };
        let want: HashSet<String> =
            want_oids.iter().filter_map(|m| dn_of.get(m).cloned()).collect();
        let have: HashSet<String> = match cur_groups.get(goid.as_str()) {
            Some(cg) => cg
                .members
                .iter()
                .map(|m| rename_map.get(m).cloned().unwrap_or_else(|| m.clone()))
                .collect(),
            None => HashSet::new(),
        };
        // Nesting into a resource group is structurally safe: `have` is the
        // member list of a group in the IdP-specific OU; this group's membership
        // in a resource group lives on that group's own object, which no op can
        // address (Builder::add asserts the IdP-specific OU).
        let mut to_add: Vec<&String> = want.difference(&have).collect();
        to_add.sort_unstable();
        for m in to_add {
            b.add(Op::AddMember { dn: gdn.clone(), member: m.clone() });
        }
        let mut to_remove: Vec<&String> = have.difference(&want).collect();
        to_remove.sort_unstable();
        for m in to_remove {
            if dupe_dns.contains(m.as_str()) {
                b.plan
                    .conflicts
                    .push(format!("membership of conflicted object {m} in {gdn} frozen"));
            } else if dn_is_at_or_within(m, ctx.idp_ou) {
                b.add(Op::RemoveMember { dn: gdn.clone(), member: m.clone() });
            } else {
                b.plan.conflicts.push(format!(
                    "foreign member {m} in managed group {gdn} - left in place, reported"
                ));
            }
        }
    }

    Ok(b.plan)
}

#[cfg(test)]
mod tests;
