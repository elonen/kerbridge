//! Device grants, retirement, and the admission-group marker -- the state sync
//! writes for the broker to read back.

use super::*;

/// A device grant is a stored `extensionName` value on a live user, and
/// nothing in reconciliation may touch it. Two facts hold it there and both
/// are pinned here, because either one silently failing revokes or
/// resurrects every device in the deployment.
///
/// The first is that no op replaces the whole attribute. `SetAttr` is the
/// only whole-attribute `Mod::Replace` taking an arbitrary attribute name,
/// and one aimed at `extensionName` would wipe every marker and every grant
/// on the object. That path does not exist today; this is what stops it
/// appearing.
///
/// The second is that a steady cycle plans nothing at all for an object
/// carrying grants -- they are not markers sync owns, so they must not read
/// as drift.
#[test]
fn reconciliation_never_touches_a_stored_device_grant() {
    let grant = format!(
        "{GRANT_PREFIX}label=BUILD01\\svc|es256=GsNH2NUyRXY46_dTvTB1SIf7hkZ8LYlOKPT-ODdVUgo\
         |start=1785000000|end=1787592000"
    );
    let holder = (
        "bu11d0001-0000",
        CurrentUser { markers: vec![grant], ..cur_user("service.builder", "Service Builder") },
    );
    let want = desired(
        [vec![("bu11d0001-0000", des_user("Service Builder"))], steady_desired()].concat(),
        vec![],
    );
    let cur = current([vec![holder], steady_current()].concat(), vec![]);
    let ops = plan_sync(&want, &cur, &ctx()).unwrap().ops;
    assert!(ops.is_empty(), "a grant must not read as drift: {ops:?}");

    // And on the path that does emit `SetAttr`, it names only attributes the
    // applier will accept -- `directory::SETTABLE_ATTRS`, which refuses the
    // rest outright rather than trusting this to stay true.
    let mut renamed = want.clone();
    renamed.users.get_mut("bu11d0001-0000").unwrap().display_name = "Renamed Builder".to_owned();
    let ops = plan_sync(&renamed, &cur, &ctx()).unwrap().ops;
    assert!(ops.iter().any(|o| matches!(o, Op::SetAttr { .. })), "{ops:?}");
    for op in &ops {
        if let Op::SetAttr { attr, .. } = op {
            assert!(
                ["sAMAccountName", "userPrincipalName", "displayName"].contains(&attr.as_str()),
                "SetAttr on {attr} would clobber a whole multi-valued attribute"
            );
        }
    }
}

/// Retirement is a revocation, and one that undid itself on re-adoption
/// would not be one: a rehire whose machine still holds the key would
/// otherwise resume getting tickets with nobody re-authorizing it. Disable
/// deliberately does not do this -- a disabled account's grants are already
/// inert, and disable/re-enable is an ordinary admin action.
#[test]
fn retirement_clears_every_grant_on_the_object() {
    let live = format!("CN=Carol Cycle,{BASE}");
    let grant = format!(
        "{GRANT_PREFIX}label=LAPTOP|es256=GsNH2NUyRXY46_dTvTB1SIf7hkZ8LYlOKPT-ODdVUgo\
         |start=1785000000|end=1787592000"
    );
    let gone = desired(steady_desired(), vec![]);
    let cur = current(
        [
            vec![(
                "ca201005-0000",
                CurrentUser { markers: vec![grant], ..cur_user("carol.cycle", "Carol Cycle") },
            )],
            steady_current(),
        ]
        .concat(),
        vec![],
    );
    let ops = plan_sync(&gone, &cur, &ctx()).unwrap().ops;
    let clear = Op::ClearMarker { dn: live.clone(), prefix: GRANT_PREFIX.to_owned() };
    assert!(ops.contains(&clear), "{ops:?}");
    // Before the rename, because the ops after it address the post-rename DN.
    let at = |want: &Op| ops.iter().position(|o| o == want).expect("planned");
    assert!(at(&clear) < ops.iter().position(|o| matches!(o, Op::Rename { .. })).unwrap());

    // A disabled-but-still-desired account keeps its grants: the enabled
    // check already makes them inert, and restoring access is usually the
    // intent.
    let mut disabled = desired(steady_desired(), vec![]);
    disabled.users.insert(
        "ca201005-0000".to_owned(),
        DesiredUser { enabled: false, ..des_user("Carol Cycle") },
    );
    let ops = plan_sync(&disabled, &cur, &ctx()).unwrap().ops;
    assert_eq!(ops, vec![Op::DisableUser { dn: live }], "{ops:?}");
}

/// The grant group is marked the way the admission group is -- by role marker,
/// so a rename or a lost cursor cannot lose it -- but a problem with it never
/// freezes the cycle, and unlike the admission marker it follows the setting:
/// repointing the configured group moves the marker. Only an absent setting
/// moves nothing, because absence is the one shape a typo takes.
#[test]
fn the_device_grant_marker_follows_the_setting_and_its_troubles_stay_local() {
    const GRANT: &str = "9c1d2e3f-4444-5555-6666-777788889999";
    let with_grant_group = |grant_oid: Option<&str>| {
        let mut d = desired(
            steady_desired(),
            vec![(GRANT, DesiredGroup { display_name: "onprem-device-grants".to_owned() })],
        );
        d.grant_subject = grant_oid.map(str::to_owned);
        d
    };
    let unmarked = current(
        steady_current(),
        vec![(GRANT, cur_group("onprem-device-grants", "onprem-device-grants"))],
    );

    let plan = plan_sync(&with_grant_group(Some(GRANT)), &unmarked, &ctx()).unwrap();
    assert_eq!(
        plan.ops,
        vec![Op::SetRoleMarker {
            dn: format!("CN=onprem-device-grants,{BASE}"),
            value: ROLE_DEVICE_GRANT.to_owned(),
        }]
    );
    assert!(plan.alerts.is_empty(), "{:?}", plan.alerts);

    // Already marked: nothing to do, and no second marker.
    let marked = current(
        steady_current(),
        vec![(
            GRANT,
            CurrentGroup {
                markers: vec![ROLE_DEVICE_GRANT.to_owned()],
                ..cur_group("onprem-device-grants", "onprem-device-grants")
            },
        )],
    );
    assert!(plan_sync(&with_grant_group(Some(GRANT)), &marked, &ctx()).unwrap().ops.is_empty());

    // A marker on a group that is not the configured one: moved -- cleared
    // there, stamped here -- with nothing alerted, because the plan is the fix.
    const OTHER: &str = "0000dead-4444-5555-6666-777788889999";
    let mut repointed = with_grant_group(Some(GRANT));
    repointed
        .groups
        .insert(OTHER.to_owned(), DesiredGroup { display_name: "stale-grants".to_owned() });
    let foreign = current(
        steady_current(),
        vec![
            (GRANT, cur_group("onprem-device-grants", "onprem-device-grants")),
            (
                OTHER,
                CurrentGroup {
                    markers: vec![ROLE_DEVICE_GRANT.to_owned()],
                    ..cur_group("stale-grants", "stale-grants")
                },
            ),
        ],
    );
    let plan = plan_sync(&repointed, &foreign, &ctx()).unwrap();
    assert_eq!(
        plan.ops,
        vec![
            Op::ClearMarker {
                dn: format!("CN=stale-grants,{BASE}"),
                prefix: ROLE_DEVICE_GRANT.to_owned(),
            },
            Op::SetRoleMarker {
                dn: format!("CN=onprem-device-grants,{BASE}"),
                value: ROLE_DEVICE_GRANT.to_owned(),
            },
        ]
    );
    assert!(plan.alerts.is_empty(), "{:?}", plan.alerts);

    // Two markers, one of them on the configured group: only the foreign one
    // is cleared.
    let both = current(
        steady_current(),
        vec![
            (
                GRANT,
                CurrentGroup {
                    markers: vec![ROLE_DEVICE_GRANT.to_owned()],
                    ..cur_group("onprem-device-grants", "onprem-device-grants")
                },
            ),
            (
                OTHER,
                CurrentGroup {
                    markers: vec![ROLE_DEVICE_GRANT.to_owned()],
                    ..cur_group("stale-grants", "stale-grants")
                },
            ),
        ],
    );
    let plan = plan_sync(&repointed, &both, &ctx()).unwrap();
    assert_eq!(
        plan.ops,
        vec![Op::ClearMarker {
            dn: format!("CN=stale-grants,{BASE}"),
            prefix: ROLE_DEVICE_GRANT.to_owned(),
        }]
    );

    // Unconfigured with a marker still out there: reported, never undone.
    let plan = plan_sync(&with_grant_group(None), &marked, &ctx()).unwrap();
    assert!(plan.ops.is_empty());
    // The class, not the wording: routing to the operator's channel is what this
    // alert is for, and a reworded message used to unroute it silently.
    assert!(
        plan.alerts
            .iter()
            .any(|a| a.kind == AlertKind::DeviceGrantGroup && a.message.contains("unset")),
        "{:?}",
        plan.alerts
    );
}

/// Repointing the realm forks on how the admission group was stated. An
/// object id it is bound by is an identity, so the marker moves to obey it
/// -- and the abandoned group, if it also left Entra, is an ordinary leaver,
/// not a vanished-admission freeze. A resolved display name moves nothing:
/// the cycle freezes, and the refusal names binding by id as the way out.
#[test]
fn an_admission_group_bound_by_id_moves_the_marker_where_a_name_only_freezes() {
    const OLD: &str = "0dd00000-1111-2222-3333-444455556666";
    let ident = |oid: &str| format!("kb1|entra|{oid}");
    let cur = || Current {
        users: OrderedMap(vec![]),
        groups: OrderedMap(vec![
            (
                ADMISSION.to_owned(),
                CurrentGroup {
                    identity: ident(ADMISSION),
                    ..cur_group("onprem-realm-users", "onprem-realm-users")
                },
            ),
            (
                OLD.to_owned(),
                CurrentGroup {
                    markers: vec![ROLE_ADMISSION.to_owned()],
                    identity: ident(OLD),
                    ..cur_group("old-realm-users", "old-realm-users")
                },
            ),
        ]),
        foreign_sams: vec![],
        unmanaged_dns: vec![],
    };

    match plan_sync(&desired(vec![], vec![]), &cur(), &ctx()) {
        Err(PlanError::AdmissionMisconfigured(why)) => {
            assert!(why.contains("ENTRA_ADMISSION_GROUP_ID"), "names the exit: {why}");
        }
        other => panic!("expected a misconfigured-marker freeze, got {other:?}"),
    }

    let bound = PlanCtx { admission_bound_by_id: true, ..ctx() };

    // Old group still synchronized: exactly the move, cleared before stamped.
    let mut d = desired(vec![], vec![]);
    d.groups.insert(OLD.to_owned(), DesiredGroup { display_name: "old-realm-users".to_owned() });
    let plan = plan_sync(&d, &cur(), &bound).unwrap();
    assert_eq!(
        plan.ops,
        vec![
            Op::ClearMarker {
                dn: format!("CN=old-realm-users,{BASE}"),
                prefix: ROLE_ADMISSION.to_owned(),
            },
            Op::SetRoleMarker {
                dn: format!("CN=onprem-realm-users,{BASE}"),
                value: ROLE_ADMISSION.to_owned(),
            },
        ]
    );
    assert!(plan.alerts.is_empty(), "{:?}", plan.alerts);

    // Old group gone from Entra in the same breath: quarantined like any
    // other leaver, with no vanished-admission freeze.
    let plan = plan_sync(&desired(vec![], vec![]), &cur(), &bound).unwrap();
    assert!(plan.alerts.is_empty(), "{:?}", plan.alerts);
    assert!(
        plan.ops
            .iter()
            .any(|o| matches!(o, Op::SetMarker { value, .. } if value.starts_with(ST_QUAR))),
        "old group is quarantined: {:?}",
        plan.ops
    );
    assert!(
        plan.ops
            .iter()
            .any(|o| matches!(o, Op::SetRoleMarker { value, .. } if value == ROLE_ADMISSION)),
        "new group is stamped: {:?}",
        plan.ops
    );
}

/// Retirement holds the SID -- durable filesystem ACLs and every `idmap_rid`
/// uid depend on it -- but releases the name, which nothing durable is keyed
/// to. Having released it, the next cycle finds nothing left to do.
#[test]
fn retirement_frees_the_name_once_and_then_plans_nothing() {
    let live = format!("CN=Carol Cycle,{BASE}");
    let gone = desired(steady_desired(), vec![]);
    let cur = current(
        [vec![("ca201005-0000", cur_user("carol.cycle", "Carol Cycle"))], steady_current()]
            .concat(),
        vec![],
    );
    assert_eq!(
        plan_sync(&gone, &cur, &ctx()).unwrap().ops,
        vec![
            Op::DisableUser { dn: live.clone() },
            Op::SetMarker { dn: live.clone(), value: format!("{ST_RETIRED}2026-07-21T12:00:00Z") },
            Op::Rename {
                dn: live,
                new_cn: "Carol Cycle (retired)".to_owned(),
                set_display_name: None,
                // 9 + 11: the whole 20-char budget, exactly.
                set_sam: Some("_retired-carol.cycle".to_owned()),
                // `samldb` enforces uniqueness here too, so it has to move as well.
                set_upn: Some("_retired-carol.cycle@example.site".to_owned()),
            },
        ]
    );
    let settled = current(
        [
            vec![(
                "ca201005-0000",
                CurrentUser {
                    dn: format!("CN=Carol Cycle (retired),{BASE}"),
                    enabled: false,
                    markers: vec![retired_marker()],
                    ..cur_user("_retired-carol.cycle", "Carol Cycle")
                },
            )],
            steady_current(),
        ]
        .concat(),
        vec![],
    );
    assert!(
        plan_sync(&gone, &settled, &ctx()).unwrap().ops.is_empty(),
        "the state the rename leaves behind is a fixed point"
    );
}

/// The rename is gated on the name and not on the retirement marker. That
/// guard is already false for anything retired before this shipped, which
/// would leave every such object holding its name forever.
#[test]
fn an_object_retired_before_this_shipped_is_migrated_next_cycle() {
    let cur = current(
        [
            vec![(
                "ca201005-0000",
                CurrentUser {
                    enabled: false,
                    markers: vec![retired_marker()],
                    ..cur_user("carol.cycle", "Carol Cycle")
                },
            )],
            steady_current(),
        ]
        .concat(),
        vec![],
    );
    assert_eq!(
        plan_sync(&desired(steady_desired(), vec![]), &cur, &ctx()).unwrap().ops,
        vec![Op::Rename {
            dn: format!("CN=Carol Cycle,{BASE}"),
            new_cn: "Carol Cycle (retired)".to_owned(),
            set_display_name: None,
            set_sam: Some("_retired-carol.cycle".to_owned()),
            set_upn: Some("_retired-carol.cycle@example.site".to_owned()),
        }],
        "no second disable and no second marker -- retention is already running"
    );
}
