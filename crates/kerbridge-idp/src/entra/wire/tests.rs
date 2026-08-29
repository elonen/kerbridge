use super::*;
use crate::sync::{Desired, build_desired, conformance};

const ADMISSION: &str = "4e8a1c9d-5f6b-4d7e-b8a9-001122334455";
const PROJX: &str = "77770001-aaaa-bbbb-cccc-000000000001";
const GARY: &str = "9e570010-aaaa-bbbb-cccc-000000000010";

fn fixture(name: &str) -> serde_json::Value {
    let path =
        format!("{}/../../testbench/fixtures/graph-sync/{name}.json", env!("CARGO_MANIFEST_DIR"));
    let raw: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    raw["response"]["body"].clone()
}

fn users_of(name: &str) -> Vec<RawUser> {
    serde_json::from_value::<Page<RawUser>>(fixture(name)).unwrap().value
}

fn groups_of(name: &str) -> Vec<RawGroup> {
    serde_json::from_value::<Page<RawGroup>>(fixture(name)).unwrap().value
}

/// The initial full read: two user pages and two groups-delta pages, exactly
/// as the sync spike captured them.
fn initial_shadow() -> Shadow {
    let mut s = Shadow::default();
    s.apply_users(users_of("full_users_page1"));
    s.apply_users(users_of("full_users_page2"));
    s.apply_groups(groups_of("groups_delta_init_page1"));
    s.apply_groups(groups_of("groups_delta_init_page2"));
    s
}

fn desired_fixture(name: &str) -> serde_json::Value {
    let path =
        format!("{}/../../testbench/fixtures/planner/{name}.json", env!("CARGO_MANIFEST_DIR"));
    let raw: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    raw["desired"].clone()
}

fn built(shadow: &Shadow) -> serde_json::Value {
    serde_json::to_value(narrow(shadow, ADMISSION, &[sub(PROJX)]).0).unwrap()
}

/// `SamSource::Upn`, because that is the mode the planner fixtures were
/// recorded in and `corpus.rs` replays them under.
fn narrow(shadow: &Shadow, admission: &str, allowlist: &[Subject]) -> (Desired, Vec<String>) {
    build_desired(shadow.enumerate(SamSource::Upn), &sub(admission), allowlist)
}

fn sub(id: &str) -> Subject {
    Subject::new(id)
}

/// The admission rule, both halves. An account exists for someone a selected
/// group holds and for nobody else -- so the admission-group closure and the
/// allowlist answer "who exists here", not merely "who may get a ticket", and an
/// operator reading the IdP-specific OU sees the admitted set and nothing more.
///
/// Gary Guest carries both halves at once: a guest, so syncable, and in no
/// group in the corpus, so unheld.
#[test]
fn an_account_exists_only_for_a_user_a_selected_group_holds() {
    let shadow = initial_shadow();
    assert!(shadow.users.contains_key(GARY), "the tenant read did see him");
    assert!(user_syncable(&shadow.users[GARY]).is_ok(), "and he is syncable");

    let d = built(&shadow);
    assert!(
        d["users"].as_object().unwrap().get(GARY).is_none(),
        "syncable but held by no selected group: no account"
    );

    // Held by the admission group, and he gets one -- nothing about being a guest
    // keeps him out, only being unheld did.
    let d = built(&shadow_holding_gary());
    assert!(d["users"].as_object().unwrap().contains_key(GARY), "held guest gets an account");
    assert!(
        d["membership"][ADMISSION].as_array().unwrap().iter().any(|m| m == GARY),
        "and is an admission-group member"
    );
}

/// The recorded initial read with the admission group holding Gary as well.
/// Adding the edge here rather than to the corpus keeps him unheld in S1-S7,
/// which is what `an_account_exists_only_for_a_user_a_selected_group_holds`
/// reads him for.
fn shadow_holding_gary() -> Shadow {
    let mut held = initial_shadow();
    held.apply_groups(
        serde_json::from_value::<Page<RawGroup>>(serde_json::json!({
            "value": [{
                "id": ADMISSION,
                "members@delta": [{"@odata.type": "#microsoft.graph.user", "id": GARY}],
            }]
        }))
        .unwrap()
        .value,
    );
    held
}

/// An invited account's UPN is reduced to a login name here, `#EXT#` and all,
/// and only the result crosses the seam. S13 pins what that result is.
#[test]
fn held_guest_reproduces_the_s13_desired_state() {
    let d = built(&shadow_holding_gary());
    assert_eq!(
        d["users"][GARY]["name_candidates"][0], "gary_partner.example",
        "the marker is stripped here and the source domain is not"
    );
    assert_eq!(d, desired_fixture("S13_held_guest_upn_name"));
}

/// The initial full read, narrowed to the population, is the S1 desired state --
/// driven through the shared conformance, which holds authentik's corpus to the
/// same assertion. Entra reaches [`build_desired`] from a shadow rather than a
/// page set, so this is where the seam is checked against a second shape.
#[test]
fn initial_read_reproduces_the_s1_desired_state() {
    conformance::whole_read_reproduces_golden(
        initial_shadow().enumerate(SamSource::Upn),
        &sub(ADMISSION),
        &[sub(PROJX)],
        &desired_fixture("S1_initial_full_sync"),
    );
}

#[test]
fn user_disable_delta_reproduces_s3_desired() {
    let mut s = initial_shadow();
    s.apply_users(users_of("users_delta_user_disabled"));
    assert_eq!(built(&s), desired_fixture("S3_user_disabled"));
}

#[test]
fn membership_delta_reproduces_s4_desired() {
    let mut s = initial_shadow();
    s.apply_groups(groups_of("groups_delta_incr_add_remove"));
    assert_eq!(built(&s), desired_fixture("S4_membership_add_remove"));
}

#[test]
fn user_delete_delta_reproduces_s5_desired() {
    let mut s = initial_shadow();
    s.apply_users(users_of("users_delta_user_deleted"));
    assert_eq!(built(&s), desired_fixture("S5_user_deleted_retention"));
}

#[test]
fn group_softdelete_delta_reproduces_s6_desired() {
    let mut s = initial_shadow();
    s.apply_groups(groups_of("groups_delta_group_softdeleted"));
    assert_eq!(built(&s), desired_fixture("S6_group_deleted_quarantine"));
}

#[test]
fn admission_group_rename_delta_reproduces_s7_desired() {
    let mut s = initial_shadow();
    s.apply_groups(groups_of("groups_delta_admission_group_renamed"));
    assert_eq!(built(&s), desired_fixture("S7_admission_group_renamed"));
}

/// A group split across delta pages must accumulate, not replace: naively
/// overwriting on the second page would lose the first page's member.
#[test]
fn split_group_pages_merge_rather_than_replace() {
    let mut s = Shadow::default();
    s.apply_groups(groups_of("groups_delta_split_group_p1"));
    s.apply_groups(groups_of("groups_delta_split_group_p2"));
    let ids: Vec<&str> = s.groups[ADMISSION].members.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "33334444-dddd-5555-eeee-6666ffff7777",
            "a1d00007-aaaa-bbbb-cccc-000000000007",
            "c1c00008-aaaa-bbbb-cccc-000000000008",
        ]
    );
}

/// Every member type Entra can put in a group, on one admission group.
///
/// The group half is a **parse** test: a recorded page carries group properties
/// the wire structs no longer declare -- `securityEnabled`, `groupTypes`,
/// `onPremisesSyncEnabled` -- and this fails if they ever stop being tolerated.
/// The user half is the policy, which is `userType` and nothing else.
#[test]
fn every_member_type_parses_and_only_user_type_refuses() {
    let members = fixture("syncable_zoo_members");
    let mut users = Shadow::default();
    let mut groups = Shadow::default();
    let mut kinds: BTreeMap<String, MemberKind> = BTreeMap::new();
    for m in members["value"].as_array().unwrap() {
        let kind = MemberKind::from_odata(m["@odata.type"].as_str().unwrap());
        let id = m["id"].as_str().unwrap().to_owned();
        kinds.insert(id, kind);
        match kind {
            MemberKind::User => users.apply_users(vec![serde_json::from_value(m.clone()).unwrap()]),
            MemberKind::Group => {
                groups.apply_groups(vec![serde_json::from_value(m.clone()).unwrap()])
            }
            _ => {}
        }
    }
    let u = |id: &str| user_syncable(&users.users[id]).is_ok();

    assert!(u("33334444-dddd-5555-eeee-6666ffff7777"), "member user syncable");
    assert!(u("9e570010-aaaa-bbbb-cccc-000000000010"), "guest syncable");
    // Security, Unified, dynamic and on-prem-synced: all four reach the shadow.
    for gid in [
        "a1d00007-aaaa-bbbb-cccc-000000000007",
        "0365aa11-aaaa-bbbb-cccc-000000000011",
        "d1a2bb12-aaaa-bbbb-cccc-000000000012",
        "0b9e4c13-aaaa-bbbb-cccc-000000000013",
    ] {
        assert!(groups.groups.contains_key(gid), "{gid} must parse into the shadow");
    }
    assert_eq!(kinds["de71ce14-aaaa-bbbb-cccc-000000000014"], MemberKind::Device);
    assert_eq!(kinds["5e9f1015-aaaa-bbbb-cccc-000000000015"], MemberKind::ServicePrincipal);
}

/// A member user, enabled and cloud-only.
fn a_user(name: &str) -> ShadowUser {
    ShadowUser {
        display_name: Some(name.to_owned()),
        upn: Some(format!("{name}@example.onmicrosoft.com")),
        mail: None,
        other_mails: None,
        account_enabled: Some(true),
        user_type: Some("Member".to_owned()),
    }
}

/// A plain cloud security group holding `members`.
fn a_group(name: &str, members: Vec<Member>) -> ShadowGroup {
    ShadowGroup { display_name: Some(name.to_owned()), members }
}

fn user_member(id: &str) -> Member {
    Member { kind: MemberKind::User, id: id.to_owned() }
}

fn group_member(id: &str) -> Member {
    Member { kind: MemberKind::Group, id: id.to_owned() }
}

/// Mutual nesting terminates, and each group is expanded exactly once.
///
/// Entra permits `a -> b -> a`, and the recorded fixtures contain one reachable
/// from the admission group, so the walk has to break the cycle.
///
/// Deliberately asserts membership too, not just termination: breaking the
/// recursion must not lose an edge. `dana`, held only by the far side of the
/// cycle, still gets an account.
#[test]
fn mutual_nesting_terminates_and_expands_each_group_once() {
    let mut sh = Shadow::default();
    sh.users.insert("u-dana".into(), a_user("dana"));
    sh.groups
        .insert("g-admission".into(), a_group("onprem-realm-users", vec![group_member("g-a")]));
    sh.groups.insert("g-a".into(), a_group("cyc-a", vec![group_member("g-b")]));
    // Back to g-a, and on to the admission group itself, which is the tighter loop.
    sh.groups.insert(
        "g-b".into(),
        a_group(
            "cyc-b",
            vec![group_member("g-a"), group_member("g-admission"), user_member("u-dana")],
        ),
    );

    let (d, _) = narrow(&sh, "g-admission", &[]);

    assert_eq!(d.groups.len(), 3, "each group once: {:?}", d.groups.keys().collect::<Vec<_>>());
    assert!(d.users.contains_key(&sub("u-dana")), "an edge behind the cycle is still followed");
    assert_eq!(
        d.membership[&sub("g-b")],
        vec![sub("g-a"), sub("g-admission"), sub("u-dana")],
        "edges preserved"
    );
}

/// Every group named in `membership` has an object in `groups`.
///
/// Asserted here because downstream it holds only by accident: the planner drops
/// a member whose DN it cannot resolve, so a violation is silent in another file.
/// The reachable way in is a member group the read has not got to yet -- ordinary
/// delta ordering, not a decision.
#[test]
fn membership_never_names_a_group_with_no_object() {
    let mut sh = Shadow::default();
    sh.users.insert("u-direct".into(), a_user("direct"));
    sh.groups.insert(
        "g-admission".into(),
        a_group("onprem-realm-users", vec![user_member("u-direct"), group_member("g-unread")]),
    );
    // Named as a member, not yet in the shadow: no object, so no membership edge.

    let (d, _) = narrow(&sh, "g-admission", &[]);
    assert!(!d.groups.contains_key(&sub("g-unread")));
    for (gid, members) in &d.membership {
        for m in members {
            assert!(
                d.users.contains_key(m) || d.groups.contains_key(m),
                "{} names {}, which has no object in the desired state",
                gid.as_str(),
                m.as_str()
            );
        }
    }
}

/// A person the operator put in the admission group who still gets nothing is the
/// one not-syncable outcome they cannot debug from the outside, so it is named.
#[test]
fn a_held_but_unsyncable_user_is_reported() {
    let mut sh = Shadow::default();
    sh.users.insert(
        "u-device-ish".into(),
        ShadowUser { user_type: Some("Unknown".to_owned()), ..a_user("shapeunknown") },
    );
    sh.users.insert("u-absent-type".into(), ShadowUser { user_type: None, ..a_user("shapeless") });
    sh.groups.insert(
        "g-admission".into(),
        a_group(
            "onprem-realm-users",
            vec![
                user_member("u-device-ish"),
                user_member("u-absent-type"),
                // Never read this cycle: ordinary delta ordering, not a decision.
                user_member("u-not-in-shadow"),
            ],
        ),
    );

    let (d, refused) = narrow(&sh, "g-admission", &[]);
    assert!(d.users.is_empty(), "neither is syncable");
    assert!(
        refused.iter().any(|r| r.contains("u-device-ish") && r.contains("userType")),
        "{refused:?}"
    );
    assert!(
        refused.iter().any(|r| r.contains("u-absent-type") && r.contains("userType")),
        "{refused:?}"
    );
    assert!(
        !refused.iter().any(|r| r.contains("u-not-in-shadow")),
        "an unread member is not a refusal: {refused:?}"
    );
}

// ---- login names ----

/// The candidate list, as strings, so a test reads like the file it produces.
fn names(u: &ShadowUser, sam_source: SamSource) -> Vec<String> {
    name_candidates(u, sam_source).iter().map(|c| c.as_str().to_owned()).collect()
}

/// The first candidate: what the account is named unless the realm finds it
/// taken.
fn first(u: &ShadowUser, sam_source: SamSource) -> String {
    names(u, sam_source).first().cloned().unwrap_or_default()
}

/// A user carrying all three attributes, so each setting has something of its
/// own to pick.
fn three_ways() -> ShadowUser {
    ShadowUser {
        display_name: Some("Jane Doe".to_owned()),
        upn: Some("jane.doe.longcontractor@example.onmicrosoft.com".to_owned()),
        mail: Some("jdoe@example.site".to_owned()),
        other_mails: None,
        account_enabled: Some(true),
        user_type: Some("Member".to_owned()),
    }
}

/// Each setting names an account from its own attribute, and offers that one
/// name alone. The losing attributes are a fallback order, not alternatives the
/// realm may pick from -- `name_candidates` says what offering them would cost.
#[test]
fn each_sam_source_offers_its_own_attribute_and_nothing_else() {
    let u = three_ways();
    assert_eq!(names(&u, SamSource::DisplayName), ["jane.doe"]);
    assert_eq!(names(&u, SamSource::EmailUsername), ["jdoe"]);
    // Truncated to 20 characters, which is `name_candidate`'s budget.
    assert_eq!(names(&u, SamSource::Upn), ["jane.doe.longcontrac"]);

    // A one-word display name still yields a usable name.
    let one = ShadowUser { display_name: Some("Prince".to_owned()), ..three_ways() };
    assert_eq!(first(&one, SamSource::DisplayName), "prince");
}

/// The display name keeps *every* token, because first-and-last mangles names
/// that are not `given family`.
#[test]
fn the_display_name_keeps_every_token() {
    let u = ShadowUser {
        display_name: Some("Gabriel García Márquez".to_owned()),
        mail: None,
        upn: Some("gabo@example.onmicrosoft.com".to_owned()),
        ..three_ways()
    };
    // First-and-last would have given `gabriel.márquez`, keeping the maternal
    // surname and dropping the paternal one that identifies him.
    assert_eq!(first(&u, SamSource::DisplayName), "gabriel.garcía.márqu");

    // No ordering is imposed: a family-first display name stays family-first.
    let jp = ShadowUser { display_name: Some("山田 太郎".to_owned()), ..u.clone() };
    assert_eq!(first(&jp, SamSource::DisplayName), "山田.太郎");
}

/// Why `upn` is the last resort: a UPN local part can carry a *domain*, and the
/// other two attributes cannot.
///
/// `alice.anderson_gmail.com#EXT#@tenant.onmicrosoft.com` has its `#EXT#`
/// stripped but not its domain -- that is not separable from a name, since `.`
/// and `_` are both legal in a sam -- so the login name concatenates a domain
/// and is then cut mid-domain by the character budget.
///
/// Both kinds of invited account reach sync: a guest is syncable as soon as a
/// selected group holds them, and a *member* invited from another tenant keeps
/// the same UPN. `S13_held_guest_upn_name` carries a recorded one from the
/// Graph read all the way to the login name; this is the three-way comparison
/// that fixture cannot make.
#[test]
fn a_upn_local_part_can_carry_a_domain_where_the_others_cannot() {
    // No `mail` at all, because the mailbox is not in this tenant; the address
    // the person uses is in `otherMails`.
    let guest = ShadowUser {
        display_name: Some("Alice Anderson".to_owned()),
        upn: Some("alice.anderson_gmail.com#EXT#@example.onmicrosoft.com".to_owned()),
        mail: None,
        other_mails: Some(vec!["alice.anderson@gmail.example".to_owned()]),
        ..three_ways()
    };
    let name = first(&guest, SamSource::Upn);
    assert_eq!(name, "alice.anderson_gmail", "guest UPN drags the source domain in");
    assert!(name.contains("gmail"), "and it is a domain, not a name");

    assert_eq!(first(&guest, SamSource::DisplayName), "alice.anderson");
    // The whole point of reading otherMails: without it this would have fallen
    // through to the polluted UPN above.
    assert_eq!(first(&guest, SamSource::EmailUsername), "alice.anderson");

    // `mail` wins when the account has both.
    let member = ShadowUser { mail: Some("a.anderson@example.site".to_owned()), ..guest.clone() };
    assert_eq!(first(&member, SamSource::EmailUsername), "a.anderson");
}

/// Any attribute can be absent on a real account, so each falls back to the
/// others rather than deriving `kbuser`.
#[test]
fn an_absent_attribute_falls_back_to_the_others() {
    let no_mail = ShadowUser {
        display_name: Some("Bob Bobson".to_owned()),
        upn: Some("bbobson@example.onmicrosoft.com".to_owned()),
        mail: None,
        other_mails: None,
        ..three_ways()
    };
    // No mail and no otherMails: an address-shaped choice falls to the UPN,
    // which is address-shaped too, rather than to the display name.
    assert_eq!(first(&no_mail, SamSource::EmailUsername), "bbobson");

    let only_upn = ShadowUser { display_name: None, ..no_mail.clone() };
    assert_eq!(first(&only_upn, SamSource::EmailUsername), "bbobson");
    assert_eq!(first(&only_upn, SamSource::DisplayName), "bbobson");

    // otherMails alone is enough.
    let other_only = ShadowUser {
        other_mails: Some(vec!["bob@elsewhere.example".to_owned()]),
        ..no_mail.clone()
    };
    assert_eq!(first(&other_only, SamSource::EmailUsername), "bob");

    // Nothing usable at all offers nothing at all, and the realm names the
    // account itself.
    let nothing = ShadowUser { upn: None, ..only_upn.clone() };
    assert!(name_candidates(&nothing, SamSource::DisplayName).is_empty());
}

/// An attribute that is present but sanitizes to nothing is dropped like an
/// absent one. `...` is three characters `sam::allowed` accepts and no name,
/// because the trim takes them all -- so a candidate list filtered on
/// "non-blank" would offer `kbuser` while a perfectly good mail address went
/// unread.
#[test]
fn an_attribute_that_sanitizes_to_nothing_is_dropped_like_an_absent_one() {
    let punctuation = ShadowUser {
        display_name: Some("...".to_owned()),
        mail: Some("jane.doe@example.site".to_owned()),
        upn: Some("jdoe@example.onmicrosoft.com".to_owned()),
        other_mails: None,
        ..three_ways()
    };
    assert_eq!(names(&punctuation, SamSource::DisplayName), ["jane.doe"]);
    assert_eq!(names(&punctuation, SamSource::Upn), ["jdoe"]);

    // Every attribute unusable offers nothing, rather than offering `kbuser` as
    // if it were a real name.
    let none =
        ShadowUser { mail: None, upn: Some("@example.site".to_owned()), ..punctuation.clone() };
    assert!(name_candidates(&none, SamSource::DisplayName).is_empty());
}

/// The seam takes a list, and this adapter never fills a second entry of it.
/// The realm reads a second entry as "this account may hold that name instead",
/// and moves a live account onto it rather than onto the `-<oid4>` suffix --
/// which costs that user a sign-out, because a login name is their Kerberos
/// principal.
#[test]
fn no_account_is_ever_offered_a_second_candidate() {
    let shapes = [
        three_ways(),
        // Nothing in this tenant beyond the UPN.
        ShadowUser { display_name: None, mail: None, other_mails: None, ..three_ways() },
        // Invited from another tenant: no mailbox here, an address in otherMails.
        ShadowUser {
            mail: None,
            other_mails: Some(vec!["alice.anderson@gmail.example".to_owned()]),
            ..three_ways()
        },
    ];
    for u in &shapes {
        for source in [SamSource::DisplayName, SamSource::EmailUsername, SamSource::Upn] {
            let offered = names(u, source);
            assert!(offered.len() <= 1, "{source:?} offered {offered:?}");
        }
    }
}
