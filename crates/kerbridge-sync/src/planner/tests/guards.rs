//! The structural refusals: OU containment, quarantined membership sync never
//! owned, and the empty-desired-state freeze.

use super::*;

/// Quarantine drops what sync put in the group and nothing else. A member an
/// operator nested by hand outlives the quarantine, because sync never owned
/// it -- the same rule the reconcile path applies to a live group.
#[test]
fn quarantine_keeps_the_members_sync_never_owned() {
    let proj = "77770001-0000";
    let local = "CN=Contractors,CN=Users,DC=example,DC=site".to_owned();
    let mine = format!("CN=Alice Anderson,{BASE}");
    let des = desired(vec![], vec![]);
    let cur = current(
        vec![],
        vec![(
            proj,
            CurrentGroup { members: vec![mine, local.clone()], ..cur_group("proj-x", "proj-x") },
        )],
    );
    let plan = plan_sync(&des, &cur, &ctx()).unwrap();
    assert_eq!(
        plan.ops,
        vec![
            Op::ClearMembers { dn: format!("CN=proj-x,{BASE}"), keep: vec![local.clone()] },
            Op::SetMarker {
                dn: format!("CN=proj-x,{BASE}"),
                value: format!("{ST_QUAR}2026-07-21T12:00:00Z"),
            },
            Op::Rename {
                dn: format!("CN=proj-x,{BASE}"),
                new_cn: "proj-x (retired)".to_owned(),
                set_display_name: None,
                set_sam: Some("_retired-proj-x".to_owned()),
                set_upn: None,
            },
        ]
    );
    assert_eq!(
        plan.conflicts,
        vec![format!(
            "foreign member {local} in quarantined group CN=proj-x,{BASE} - left in place, reported"
        )]
    );
}

/// The base string can land in the *middle* of a component, and a suffix match
/// cannot tell. An escaped comma is the reachable way there: `CN=Bob\,OU=Entra,
/// DC=example,DC=site` is one RDN named `Bob,OU=Entra` sitting in `DC=example,
/// DC=site`, and it ends with the base as a string while being nowhere near the
/// OU. Sync then read an operator's object as its own -- quarantine stripped it
/// out of the group and the reconcile path planned `RemoveMember` on it, both
/// silently, because a member it believes it owns is not a conflict to report.
///
/// Contrived to arrive at by accident, trivial to arrive at on purpose, and the
/// same escape `parent_of` is careful about one module over.
#[test]
fn the_base_landing_mid_component_is_not_containment() {
    let proj = "77770002-0000";
    let forged = "CN=Bob\\,OU=Entra,DC=example,DC=site".to_owned();
    assert!(forged.ends_with(BASE), "the case is only interesting if the suffix matches");
    let cur = current(
        vec![],
        vec![(
            proj,
            CurrentGroup { members: vec![forged.clone()], ..cur_group("proj-y", "proj-y") },
        )],
    );
    let plan = plan_sync(&desired(vec![], vec![]), &cur, &ctx()).unwrap();
    assert!(
        plan.ops.contains(&Op::ClearMembers {
            dn: format!("CN=proj-y,{BASE}"),
            keep: vec![forged.clone()],
        }),
        "the member must survive quarantine: {:?}",
        plan.ops
    );
    assert_eq!(
        plan.conflicts,
        vec![format!(
            "foreign member {forged} in quarantined group CN=proj-y,{BASE} \
         - left in place, reported"
        )]
    );
}

/// The read finished, so a snapshot did reach the planner -- and every
/// synchronized user is then absent from the desired state, which the
/// retention path reads as "retire all of them".
#[test]
fn an_empty_desired_state_freezes_rather_than_retiring_everyone() {
    let plan = plan_sync(
        &desired(vec![], vec![]),
        &current(vec![("3a1c0b8e-7777-8888-9999-aaaabbbbcccc", cur_user("ada", "Ada"))], vec![]),
        &ctx(),
    )
    .unwrap();
    assert!(plan.ops.is_empty(), "not one op: {:?}", plan.ops);
    assert_eq!(plan.alerts.len(), 1);
    assert_eq!(plan.alerts[0].kind, AlertKind::AdmissionGroup);
    assert!(plan.alerts[0].message.contains("FROZEN"), "{}", plan.alerts[0].message);
}

/// The guard must not fire on a first deployment, where an empty desired
/// state and an empty directory (realm) are the same ordinary thing.
#[test]
fn an_empty_realm_directory_is_not_frozen_by_the_same_guard() {
    let plan = plan_sync(&desired(vec![], vec![]), &current(vec![], vec![]), &ctx()).unwrap();
    assert!(plan.alerts.is_empty(), "{:?}", plan.alerts);
}

/// A subject the identity format cannot hold is reported, not skipped.
#[test]
fn a_subject_with_no_encodable_identity_is_a_conflict_and_creates_nothing() {
    let long = "s".repeat(kerbridge_core::MAX_IDENTITY_LEN);
    let des = desired(vec![(&long, des_user("Too Long"))], vec![]);
    let cur = current(vec![], vec![]);
    let refuse: &dyn Fn(&Subject) -> Result<String, kerbridge_core::IdentityError> = &|subject| {
        ExternalIdentity::new(&kerbridge_core::Source::new("entra").unwrap(), subject.as_str())
            .map(|id| id.encode())
    };
    let plan = plan_sync(&des, &cur, &PlanCtx { identity: refuse, ..ctx() }).unwrap();
    assert!(plan.ops.is_empty(), "{:?}", plan.ops);
    assert_eq!(plan.conflicts.len(), 1, "{:?}", plan.conflicts);
    assert!(plan.conflicts[0].contains("no encodable identity"), "{}", plan.conflicts[0]);
}

/// `Op::kind` names each op the way the serialized payload does. Two spellings
/// of one operation -- `create_user` in a fixture and `CreateUser` in the audit
/// file -- would make the record of what happened ungreppable against the plan
/// that caused it, and nothing else compares the two.
#[test]
fn the_audited_op_name_is_the_serialized_op_tag() {
    let dn = format!("CN=Alice Anderson,{BASE}");
    let every = vec![
        Op::CreateUser {
            dn: dn.clone(),
            sam: "alice.anderson".to_owned(),
            upn: "alice.anderson@example.site".to_owned(),
            display_name: "Alice Anderson".to_owned(),
            enabled: true,
            identity: "kb1|entra|oid".to_owned(),
        },
        Op::CreateGroup {
            dn: dn.clone(),
            sam: "proj-x".to_owned(),
            identity: "kb1|entra|oid".to_owned(),
            role_marker: None,
        },
        Op::AddMember { dn: dn.clone(), member: dn.clone() },
        Op::RemoveMember { dn: dn.clone(), member: dn.clone() },
        Op::EnableUser { dn: dn.clone() },
        Op::DisableUser { dn: dn.clone() },
        Op::Rename {
            dn: dn.clone(),
            new_cn: "Alice Andersson".to_owned(),
            set_display_name: None,
            set_sam: None,
            set_upn: None,
        },
        Op::SetAttr {
            dn: dn.clone(),
            attr: "displayName".to_owned(),
            value: "Alice Andersson".to_owned(),
        },
        Op::SetMarker { dn: dn.clone(), value: retired_marker() },
        Op::SetRoleMarker { dn: dn.clone(), value: ROLE_ADMISSION.to_owned() },
        Op::ClearMarker { dn: dn.clone(), prefix: ST_RETIRED.to_owned() },
        Op::ClearMembers { dn, keep: vec![] },
    ];
    for op in &every {
        let payload: serde_json::Value = serde_json::to_value(op).expect("an op serializes");
        assert_eq!(payload["op"], op.kind(), "{op:?}");
    }
}
