//! A name already taken. Every case here refuses the whole cycle rather than
//! applying the rest, so a first deploy against a populated directory never
//! half-applies.

use super::*;

/// Two groups, told apart only by which one the test names first.
const GROUP_A: &str = "aaaa0001-0000-0000-0000-000000000001";
const GROUP_B: &str = "bbbb0002-0000-0000-0000-000000000002";

/// One group's sAMAccountName colliding with an existing object refuses the
/// *whole* cycle -- no partial sync -- so deploying against a directory that
/// already holds a same-named object never half-applies. Here the admission
/// group itself collides; the name it collides on is this fixture's own, chosen
/// to match what the bench seeds and standing for no documented default. A
/// second, perfectly-createable group proves nothing else is planned either.
#[test]
fn a_group_sam_collision_refuses_the_whole_cycle() {
    let admission = Subject::new("8689e2c1-3268-4744-a647-30d05e5c7b90");
    let mut groups = BTreeMap::new();
    groups
        .insert(admission.clone(), DesiredGroup { display_name: "onprem-realm-users".to_owned() });
    // Fine on its own -- must still not be created, because the cycle is refused.
    groups.insert(
        Subject::new("47c8e0b4-c5e0-4c20-96a6-25f4c4632f18"),
        DesiredGroup { display_name: "proj-x-staff".to_owned() },
    );
    let desired = Desired { users: BTreeMap::new(), groups, membership: BTreeMap::new() };
    // The admission group's name is already occupied by an unmanaged/foreign
    // object.
    let current = Current {
        users: OrderedMap(vec![]),
        groups: OrderedMap(vec![]),
        foreign_sams: vec!["onprem-realm-users".to_owned()],
        unmanaged_dns: vec![],
    };
    let ctx = PlanCtx {
        idp_ou: "OU=Entra,DC=example,DC=site",
        admission: &admission,
        grant: None,
        upn_suffix: "example.site",
        group_suffix: "",
        now: "2026-07-21T12:00:00Z",
        automatic_sam_renames: true,
        identity: ENCODE,
    };
    match plan_sync(&desired, &current, &ctx) {
        Err(PlanError::NameCollision(names)) => {
            assert_eq!(names.len(), 1, "exactly the one real collision");
            assert!(names[0].contains("onprem-realm-users"), "names the collision");
        }
        other => panic!("expected a whole-cycle NameCollision refusal, got {other:?}"),
    }
}

/// A managed group's own `sAMAccountName` is part of the namespace a new
/// group's name must avoid. Delete-and-recreate in Entra hits this: the old
/// object is still in the directory holding the name for its retention window,
/// so the recreated group would be planned as an unappliable `CreateGroup` --
/// AD rejects the duplicate name domain-wide, on every cycle, forever.
#[test]
fn a_new_group_reusing_a_managed_group_sam_refuses_the_cycle() {
    let admission = Subject::new("8689e2c1-3268-4744-a647-30d05e5c7b90");
    let mut groups = BTreeMap::new();
    groups
        .insert(admission.clone(), DesiredGroup { display_name: "onprem-realm-users".to_owned() });
    // Recreated in Entra under a fresh oid, with the same name as before.
    groups.insert(
        Subject::new("47c8e0b4-c5e0-4c20-96a6-25f4c4632f18"),
        DesiredGroup { display_name: "proj-x".to_owned() },
    );
    let desired = Desired { users: BTreeMap::new(), groups, membership: BTreeMap::new() };
    // The predecessor: gone from Entra, still held here, still owning the name.
    let current = Current {
        users: OrderedMap(vec![]),
        groups: OrderedMap(vec![
            (
                admission.as_str().to_owned(),
                CurrentGroup {
                    dn: "CN=onprem-realm-users,OU=Entra,DC=example,DC=site".to_owned(),
                    sam: "onprem-realm-users".to_owned(),
                    display_name: "onprem-realm-users".to_owned(),
                    members: vec![],
                    markers: vec![ROLE_ADMISSION.to_owned()],
                    identity: "kb1|entra|8689e2c1-3268-4744-a647-30d05e5c7b90".to_owned(),
                },
            ),
            (
                "11110000-aaaa-bbbb-cccc-000000000001".to_owned(),
                CurrentGroup {
                    dn: "CN=proj-x,OU=Entra,DC=example,DC=site".to_owned(),
                    sam: "proj-x".to_owned(),
                    display_name: "proj-x".to_owned(),
                    members: vec![],
                    markers: vec![],
                    identity: "kb1|entra|11110000-aaaa-bbbb-cccc-000000000001".to_owned(),
                },
            ),
        ]),
        foreign_sams: vec![],
        unmanaged_dns: vec![],
    };
    let ctx = PlanCtx {
        idp_ou: "OU=Entra,DC=example,DC=site",
        admission: &admission,
        grant: None,
        upn_suffix: "example.site",
        group_suffix: "",
        now: "2026-07-21T12:00:00Z",
        automatic_sam_renames: true,
        identity: ENCODE,
    };
    match plan_sync(&desired, &current, &ctx) {
        Err(PlanError::NameCollision(names)) => {
            assert_eq!(names.len(), 1, "exactly the one real collision");
            assert!(names[0].contains("proj-x"), "names the collision");
        }
        other => panic!("expected a whole-cycle NameCollision refusal, got {other:?}"),
    }
}

/// Two Entra names that reduce to one directory name are a collision like any
/// other, and the pre-check must see the sanitized form -- comparing raw
/// display names would let both through to fail at apply time instead.
#[test]
fn group_names_that_sanitize_together_refuse_the_cycle() {
    let result = plan_sync(
        &desired(
            vec![],
            vec![
                (
                    "47c8e0b4-c5e0-4c20-96a6-25f4c4632f18",
                    DesiredGroup { display_name: "Sales, EU".to_owned() },
                ),
                (
                    "9f1d0f4a-1111-2222-3333-444455556666",
                    DesiredGroup { display_name: "Sales  EU".to_owned() },
                ),
            ],
        ),
        &current(vec![], vec![]),
        &ctx(),
    );
    assert!(
        matches!(result, Err(PlanError::NameCollision(_))),
        "expected a whole-cycle refusal, got {result:?}"
    );
}

/// A group sam is the display name verbatim, so `Sales`/`sales` are two
/// different `String`s and one directory name. Byte-exact, this planned both:
/// AD took the first, refused the second, and `apply` recorded the failure and
/// carried on -- so the group never existed, silently, on every cycle forever.
///
/// One conflict, not two, and not two `CreateGroup` ops.
#[test]
fn groups_differing_only_in_case_are_one_collision() {
    let result = plan_sync(
        &desired(
            vec![],
            vec![
                (GROUP_A, DesiredGroup { display_name: "Sales".to_owned() }),
                (GROUP_B, DesiredGroup { display_name: "sales".to_owned() }),
            ],
        ),
        &current(vec![], vec![]),
        &ctx(),
    );
    match result {
        Err(PlanError::NameCollision(c)) => assert_eq!(c.len(), 1, "one collision: {c:?}"),
        other => panic!("expected a whole-cycle refusal, got {other:?}"),
    }
}

/// The whole point of `group_suffix`. A second cloud IdP's `payroll` is
/// a foreign name to this source -- the scan behind `foreign_sams` is
/// domain-wide -- and unsuffixed it refuses this cycle and every one after it,
/// mirroring no users either.
#[test]
fn a_group_suffix_keeps_another_sources_group_name_out_of_the_way() {
    let mut cur = current(vec![], vec![]);
    cur.foreign_sams = vec!["payroll".to_owned()];
    let group = vec![(GROUP_A, DesiredGroup { display_name: "payroll".to_owned() })];

    let unsuffixed = plan_sync(&desired(vec![], group.clone()), &cur, &ctx());
    assert!(
        matches!(unsuffixed, Err(PlanError::NameCollision(_))),
        "without a suffix the shared name refuses the cycle, got {unsuffixed:?}"
    );

    let ops = plan_sync(&desired(vec![], group), &cur, &PlanCtx { group_suffix: "-goog", ..ctx() })
        .expect("a suffixed name does not collide")
        .ops;
    assert!(
        ops.iter().any(|op| matches!(op, Op::CreateGroup { sam, .. } if sam == "payroll-goog")),
        "{ops:?}"
    );
}

/// The same fold on the other side: a *foreign* on-prem object the operator
/// already owns must block a managed group that differs from it only in case,
/// or sync plans a name AD will refuse.
#[test]
fn a_foreign_name_blocks_a_case_only_variant() {
    let mut cur = current(vec![], vec![]);
    cur.foreign_sams = vec!["Payroll".to_owned()];
    let result = plan_sync(
        &desired(vec![], vec![(GROUP_A, DesiredGroup { display_name: "payroll".to_owned() })]),
        &cur,
        &ctx(),
    );
    assert!(
        matches!(result, Err(PlanError::NameCollision(_))),
        "expected a refusal against the foreign name, got {result:?}"
    );
}
