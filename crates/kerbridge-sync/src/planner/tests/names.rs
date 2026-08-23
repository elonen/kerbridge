//! Login names: how a `sAMAccountName` is derived from a source attribute,
//! when a live one is allowed to move, and what a name has to survive to become
//! a DN.

use super::*;

/// A live account's login name follows a display-name change. It is what
/// Windows shows as the file owner and in the *Security* tab, so leaving a
/// renamed person's old name on their files is a directory failing at its
/// job. The cost is one sign-out, because the sam is a Kerberos principal.
#[test]
fn a_live_login_name_follows_the_display_name() {
    let cur = current(vec![("oid-jane", cur_user("jane.smith", "Jane Smith"))], vec![]);
    let des = desired(vec![("oid-jane", des_user("Jane Doe"))], vec![]);
    let ops = plan_sync(&des, &cur, &ctx()).unwrap().ops;

    assert!(
        ops.contains(&Op::SetAttr {
            dn: format!("CN=Jane Smith,{BASE}"),
            attr: "sAMAccountName".to_owned(),
            value: "jane.doe".to_owned(),
        }),
        "{ops:?}"
    );
    // The UPN moves with it: samldb enforces uniqueness there too, so a sam
    // that moved alone would leave the old name held one attribute over.
    assert!(
        ops.contains(&Op::SetAttr {
            dn: format!("CN=Jane Smith,{BASE}"),
            attr: "userPrincipalName".to_owned(),
            value: "jane.doe@example.site".to_owned(),
        }),
        "{ops:?}"
    );
}

/// Off, nothing moves -- the setting exists for deployments that would rather
/// have a stale login name than a sign-out.
#[test]
fn automatic_renames_off_freezes_a_live_login_name() {
    let cur = current(vec![("oid-jane", cur_user("jane.smith", "Jane Smith"))], vec![]);
    let des = desired(vec![("oid-jane", des_user("Jane Doe"))], vec![]);
    let ctx = PlanCtx { automatic_sam_renames: false, ..ctx() };
    let ops = plan_sync(&des, &cur, &ctx).unwrap().ops;

    assert!(
        !ops.iter().any(|o| matches!(o, Op::SetAttr { attr, .. } if attr == "sAMAccountName")),
        "no sam moves with the setting off: {ops:?}"
    );
    // The CN still follows, as it always did. Only the login name is frozen.
    assert!(
        ops.iter().any(|o| matches!(o, Op::Rename { new_cn, .. } if new_cn == "Jane Doe")),
        "{ops:?}"
    );
}

/// An operator's `kbmanage cloud rename` outranks the display name. Without
/// this the two fight every cycle and the operator always loses.
#[test]
fn a_pinned_login_name_outranks_the_display_name() {
    let cur = current(
        vec![(
            "oid-jane",
            CurrentUser {
                markers: vec![format!("{ST_NAME_PINNED}2026-07-29T10:00:00Z")],
                ..cur_user("jd", "Jane Smith")
            },
        )],
        vec![],
    );
    let des = desired(vec![("oid-jane", des_user("Jane Doe"))], vec![]);
    let ops = plan_sync(&des, &cur, &ctx()).unwrap().ops;

    assert!(
        !ops.iter().any(|o| matches!(o, Op::SetAttr { attr, .. } if attr == "sAMAccountName")),
        "a pinned name is not recomputed: {ops:?}"
    );
}

/// A name that has not drifted plans nothing, so a steady state stays empty
/// and nobody is signed out by a cycle that had no news.
#[test]
fn an_unchanged_display_name_plans_no_rename() {
    let cur = current(vec![("oid-jane", cur_user("jane.doe", "Jane Doe"))], vec![]);
    let des = desired(vec![("oid-jane", des_user("Jane Doe"))], vec![]);
    assert_eq!(plan_sync(&des, &cur, &ctx()).unwrap().ops, vec![]);
}

/// What retention is for: a returning employee keeps the original SID, so her
/// uid and her files still resolve to her -- and the name comes back too, with
/// no `_retired-` residue and no disambiguating suffix.
#[test]
fn a_reappearing_user_takes_her_name_back() {
    let held = format!("CN=Carol Cycle (retired),{BASE}");
    let cur = current(
        vec![(
            "ca201005-0000",
            CurrentUser {
                dn: held.clone(),
                enabled: false,
                markers: vec![retired_marker()],
                ..cur_user("_retired-carol.cycle", "Carol Cycle")
            },
        )],
        vec![],
    );
    let des = desired(vec![("ca201005-0000", des_user("Carol Cycle"))], vec![]);
    assert_eq!(
        plan_sync(&des, &cur, &ctx()).unwrap().ops,
        vec![
            Op::ClearMarker { dn: held.clone(), prefix: ST_RETIRED.to_owned() },
            Op::EnableUser { dn: held.clone() },
            Op::Rename {
                dn: held,
                new_cn: "Carol Cycle".to_owned(),
                set_display_name: None,
                set_sam: Some("carol.cycle".to_owned()),
                set_upn: Some("carol.cycle@example.site".to_owned()),
            },
        ]
    );
}

/// Restoration goes through `alloc_names` rather than reusing the stored name,
/// because someone else may hold it by the time she returns. They keep it; she
/// takes the suffixed form, and nothing about their object is touched.
#[test]
fn a_reappearing_user_whose_name_was_taken_gets_the_suffixed_one() {
    let held = format!("CN=Carol Cycle (retired),{BASE}");
    let cur = current(
        vec![
            (
                "ca201005-0000",
                CurrentUser {
                    dn: held.clone(),
                    enabled: false,
                    markers: vec![retired_marker()],
                    ..cur_user("_retired-carol.cycle", "Carol Cycle")
                },
            ),
            ("d0ff1006-0000", cur_user("carol.cycle", "Carol Cycle")),
        ],
        vec![],
    );
    let des = desired(
        vec![
            ("ca201005-0000", des_user("Carol Cycle")),
            ("d0ff1006-0000", des_user("Carol Cycle")),
        ],
        vec![],
    );
    assert_eq!(
        plan_sync(&des, &cur, &ctx()).unwrap().ops,
        vec![
            Op::ClearMarker { dn: held.clone(), prefix: ST_RETIRED.to_owned() },
            Op::EnableUser { dn: held.clone() },
            Op::Rename {
                dn: held,
                new_cn: "Carol Cycle (ca20)".to_owned(),
                set_display_name: None,
                set_sam: Some("carol.cycle-ca20".to_owned()),
                set_upn: Some("carol.cycle-ca20@example.site".to_owned()),
            },
        ]
    );
}

/// `_retired-` spends 9 of `sanitize_sam`'s 20-char budget, so a sam that is
/// itself 20 long cannot simply be prefixed. Both forms land exactly on 20.
#[test]
fn a_full_length_sam_retires_within_the_twenty_char_budget() {
    let cur = current(
        [
            vec![
                ("aaaa0001-0000", cur_user("jane.doe.contractor1", "Jane Doe One")),
                ("bbbb0002-0000", cur_user("jane.doe.contractor2", "Jane Doe Two")),
            ],
            steady_current(),
        ]
        .concat(),
        vec![],
    );
    let plan = plan_sync(&desired(steady_desired(), vec![]), &cur, &ctx()).unwrap();
    let sams: Vec<&str> = plan
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::Rename { set_sam: Some(s), .. } => Some(s.as_str()),
            _ => None,
        })
        .collect();
    // Both truncate to the same 11, so the second falls back to 6 + `-<oid4>`.
    assert_eq!(sams, ["_retired-jane.doe.co", "_retired-jane.d-bbbb"]);
    assert!(sams.iter().all(|s| s.len() == 20), "exactly on the budget, never over");
}

/// `Op::Rename` passes no `newsuperior`, so AD keeps the object's parent. Every
/// post-rename DN the planner forms has to come from that parent rather than
/// from `idp_ou`, or a future `OU=Retired,OU=Entra` breaks silently -- here
/// the group's member link is what would be left pointing at nothing.
#[test]
fn a_sub_ou_object_is_renamed_inside_its_own_ou() {
    let sub = format!("CN=Sub User,OU=Retired,{BASE}");
    let proj = "77770001-0000";
    let mut des =
        desired(steady_desired(), vec![(proj, DesiredGroup { display_name: "proj-x".to_owned() })]);
    des.membership.insert(proj.to_owned(), vec![]);
    let cur = current(
        [
            vec![(
                "ca201005-0000",
                CurrentUser { dn: sub.clone(), ..cur_user("sub.user", "Sub User") },
            )],
            steady_current(),
        ]
        .concat(),
        vec![(proj, CurrentGroup { members: vec![sub.clone()], ..cur_group("proj-x", "proj-x") })],
    );
    assert_eq!(
        plan_sync(&des, &cur, &ctx()).unwrap().ops,
        vec![
            Op::DisableUser { dn: sub.clone() },
            Op::SetMarker { dn: sub.clone(), value: format!("{ST_RETIRED}2026-07-21T12:00:00Z") },
            Op::Rename {
                dn: sub,
                new_cn: "Sub User (retired)".to_owned(),
                set_display_name: None,
                set_sam: Some("_retired-sub.user".to_owned()),
                set_upn: Some("_retired-sub.user@example.site".to_owned()),
            },
            Op::RemoveMember {
                dn: format!("CN=proj-x,{BASE}"),
                member: format!("CN=Sub User (retired),OU=Retired,{BASE}"),
            },
        ]
    );
}

/// `oid4` byte-sliced a `&str`, and an object id is remote input. Four ASCII
/// characters are four bytes and the GUIDs Graph returns never exercised the
/// difference; a non-ASCII id would have panicked mid-codepoint and taken the
/// cycle with it.
#[test]
fn oid4_counts_characters_not_bytes() {
    assert_eq!(oid4("abcdef"), "abcd");
    assert_eq!(oid4("ab"), "ab");
    assert_eq!(oid4(""), "");
    // Two bytes per character: a byte slice at 4 would cut the third in half.
    assert_eq!(oid4("Ωμέγα"), "Ωμέγ");
    // Three and four bytes per character, the same way.
    assert_eq!(oid4("日本語テスト"), "日本語テ");
    assert_eq!(oid4("🙂🙃🙂🙃🙂"), "🙂🙃🙂🙃");
}

/// One helper, three sources, so the difference between them is readable
/// in one place.
fn alloc(du: &DesiredUser, src: SamSource) -> String {
    alloc_names(du, "oid1", &HashSet::new(), "example.site", src).unwrap().0
}

#[test]
fn each_sam_source_derives_from_its_own_attribute() {
    let du = DesiredUser {
        display_name: "Jane Doe".to_owned(),
        mail: "jdoe@example.site".to_owned(),
        other_mails: Vec::new(),
        upn: "jane.doe.longcontractor@example.onmicrosoft.com".to_owned(),
        enabled: true,
    };
    assert_eq!(alloc(&du, SamSource::DisplayName), "jane.doe");
    assert_eq!(alloc(&du, SamSource::EmailUsername), "jdoe");
    // Truncated to 20 characters by sanitize_sam.
    assert_eq!(alloc(&du, SamSource::Upn), "jane.doe.longcontrac");

    let (sam, upn, cn) =
        alloc_names(&du, "oid1", &HashSet::new(), "example.site", SamSource::DisplayName).unwrap();
    assert_eq!((upn, cn), ("jane.doe@example.site".to_owned(), "Jane Doe".to_owned()));
    assert_eq!(sam, "jane.doe");

    // A one-word display name still yields a usable name.
    let one = DesiredUser { display_name: "Prince".to_owned(), ..du.clone() };
    assert_eq!(alloc(&one, SamSource::DisplayName), "prince");
}

/// The display name keeps *every* token, because first-and-last mangles
/// names that are not `given family`.
#[test]
fn the_display_name_source_keeps_every_token() {
    let du = DesiredUser {
        display_name: "Gabriel García Márquez".to_owned(),
        mail: String::new(),
        other_mails: Vec::new(),
        upn: "gabo@example.onmicrosoft.com".to_owned(),
        enabled: true,
    };
    // First-and-last would have given `gabriel.márquez`, keeping the
    // maternal surname and dropping the paternal one that identifies him.
    assert_eq!(alloc(&du, SamSource::DisplayName), "gabriel.garcía.márqu");

    // No ordering is imposed: a family-first display name stays family-first.
    let jp = DesiredUser { display_name: "山田 太郎".to_owned(), ..du.clone() };
    assert_eq!(alloc(&jp, SamSource::DisplayName), "山田.太郎");
}

/// Why `upn` is the last resort: a UPN local part can carry a *domain*,
/// and the other two sources cannot.
///
/// `alice.anderson_gmail.com#EXT#@tenant.onmicrosoft.com` has its `#EXT#`
/// stripped but not its domain -- that is not separable from a name, since
/// `.` and `_` are both legal in a sam -- so the login name concatenates a
/// domain and is then cut mid-domain by the character budget.
///
/// This is the UPN of an invited account. Sync rejects guests today, but a
/// *member* invited from another tenant keeps exactly this UPN, so the shape
/// is reachable -- and it is the clearest case of the difference between the
/// three sources.
#[test]
fn a_upn_local_part_can_carry_a_domain_where_the_others_cannot() {
    // No `mail` at all, because the mailbox is not in this tenant; the
    // address the person uses is in `otherMails`.
    let guest = DesiredUser {
        display_name: "Alice Anderson".to_owned(),
        mail: String::new(),
        other_mails: vec!["alice.anderson@gmail.example".to_owned()],
        upn: "alice.anderson_gmail.com#EXT#@example.onmicrosoft.com".to_owned(),
        enabled: true,
    };
    let sam = alloc(&guest, SamSource::Upn);
    assert_eq!(sam, "alice.anderson_gmail", "guest UPN drags the source domain in");
    assert!(sam.contains("gmail"), "and it is a domain, not a name");

    assert_eq!(alloc(&guest, SamSource::DisplayName), "alice.anderson");
    // The whole point of reading otherMails: without it this would have
    // fallen through to the polluted UPN above.
    assert_eq!(alloc(&guest, SamSource::EmailUsername), "alice.anderson");

    // `mail` wins when the account has both.
    let member = DesiredUser { mail: "a.anderson@example.site".to_owned(), ..guest.clone() };
    assert_eq!(alloc(&member, SamSource::EmailUsername), "a.anderson");
}

/// Any source can be absent on a real account, so each falls back to the
/// others rather than deriving `kbuser`.
#[test]
fn an_absent_source_falls_back_to_the_others() {
    let no_mail = DesiredUser {
        display_name: "Bob Bobson".to_owned(),
        mail: String::new(),
        other_mails: Vec::new(),
        upn: "bbobson@example.onmicrosoft.com".to_owned(),
        enabled: true,
    };
    // No mail and no otherMails: an address-shaped choice falls to the UPN,
    // which is address-shaped too, rather than to the display name.
    assert_eq!(alloc(&no_mail, SamSource::EmailUsername), "bbobson");

    let only_upn = DesiredUser { display_name: String::new(), ..no_mail.clone() };
    assert_eq!(alloc(&only_upn, SamSource::EmailUsername), "bbobson");
    assert_eq!(alloc(&only_upn, SamSource::DisplayName), "bbobson");

    // otherMails alone is enough.
    let other_only =
        DesiredUser { other_mails: vec!["bob@elsewhere.example".to_owned()], ..no_mail.clone() };
    assert_eq!(alloc(&other_only, SamSource::EmailUsername), "bob");

    // Nothing usable at all still yields a legal name, never an empty one.
    let nothing = DesiredUser { upn: String::new(), ..only_upn.clone() };
    assert_eq!(alloc(&nothing, SamSource::DisplayName), "kbuser");
}

/// A source that is present but sanitizes to nothing is spent like an absent
/// one. `...` is three characters `sam::allowed` accepts and no name, because
/// the trim takes them all -- so testing the raw string for blankness derives
/// `sam::FALLBACK` while a perfectly good mail address goes unread.
#[test]
fn a_source_that_sanitizes_to_nothing_falls_through_like_an_absent_one() {
    let punctuation = DesiredUser {
        display_name: "...".to_owned(),
        mail: "jane.doe@example.site".to_owned(),
        other_mails: Vec::new(),
        upn: "jdoe@example.onmicrosoft.com".to_owned(),
        enabled: true,
    };
    assert_eq!(alloc(&punctuation, SamSource::DisplayName), "jane.doe");
    assert_eq!(alloc(&punctuation, SamSource::Upn), "jdoe");

    // Every source unusable is still the fallback, not an empty name.
    let none = DesiredUser { mail: String::new(), upn: "@example.site".to_owned(), ..punctuation };
    assert_eq!(alloc(&none, SamSource::DisplayName), sam::FALLBACK);
}

#[test]
fn sam_source_parses_only_the_documented_spellings() {
    use std::str::FromStr;
    assert_eq!(SamSource::from_str("displayname"), Ok(SamSource::DisplayName));
    assert_eq!(SamSource::from_str(" EMAIL_Username "), Ok(SamSource::EmailUsername));
    assert_eq!(SamSource::from_str("upn"), Ok(SamSource::Upn));
    assert_eq!(SamSource::default(), SamSource::DisplayName);
    // Near-misses are refused, not silently defaulted.
    for bad in ["", "email", "mail", "1", "true", "display_name", "userPrincipalName"] {
        assert!(SamSource::from_str(bad).is_err(), "{bad:?} must not parse");
    }
}

#[test]
fn sanitize_is_lowercase_bounded_and_never_empty() {
    assert_eq!(sanitize_sam("Alice.Anderson", 20), "alice.anderson");
    assert_eq!(sanitize_sam("a b c!!!", 20), "abc");
    assert_eq!(sanitize_sam("trailing--", 20), "trailing");
    assert_eq!(sanitize_sam("!!!", 20), "kbuser");
    assert_eq!(sanitize_sam("abcdefghij", 4), "abcd");
}

#[test]
fn a_name_keeps_nothing_a_dn_or_a_sam_would_choke_on() {
    assert_eq!(safe_name("Doe, Jane").as_deref(), Some("Doe  Jane"));
    assert_eq!(safe_name("Ada Lovelace").as_deref(), Some("Ada Lovelace"));
    // The whole reserved set, a control character, and the DN parser's
    // hex-value marker.
    assert_eq!(safe_name("a+b\"c\\d<e>f;g=h").as_deref(), Some("a b c d e f g h"));
    assert_eq!(safe_name("a/b[c]d:e|f*g?h").as_deref(), Some("a b c d e f g h"));
    assert_eq!(safe_name("Bad\r\nISSUE forged").as_deref(), Some("Bad  ISSUE forged"));
    assert_eq!(safe_name("#hashed").as_deref(), Some("hashed"));
    // Nothing usable left: the caller substitutes, rather than this building
    // `CN=,OU=Entra,…`.
    assert_eq!(safe_name("  "), None);
    assert_eq!(safe_name(",,,"), None);
    assert_eq!(safe_name(""), None);
}

/// The suffix comes out of the 64-character sam budget rather than being added
/// past it -- appended after truncation, a long group name would build a sam AD
/// refuses, on every cycle, forever. The CN does not carry it: it only has to be
/// unique inside this source's own OU.
#[test]
fn a_group_suffix_is_spent_from_the_sam_budget_not_added_past_it() {
    let long = "G".repeat(80);
    let (cn, sam) = group_names(&long, "aaaa0001-0000", "-goog");
    assert_eq!(cn, long, "the CN keeps the whole display name and the suffix stays off it");
    assert_eq!(sam.chars().count(), 64, "{sam}");
    assert!(sam.ends_with("-goog"), "{sam}");

    // The ordinary case, and the trailing-space trim still happening before the
    // suffix rather than after it.
    assert_eq!(group_names("payroll", "aaaa0001-0000", "-goog").1, "payroll-goog");
    assert_eq!(group_names("payroll ", "aaaa0001-0000", "-goog").1, "payroll-goog");
    assert_eq!(group_names("payroll", "aaaa0001-0000", "").1, "payroll");
}

/// Refused, not sanitized: this one is an operator's, and it lands in every
/// group name the source ever creates.
#[test]
fn a_group_suffix_is_refused_rather_than_sanitized() {
    assert_eq!(group_suffix_rejection("-goog"), None);
    assert_eq!(group_suffix_rejection("_authentik"), None);
    assert_eq!(group_suffix_rejection(""), None);
    for bad in ["-a b", "-a,b", "-a\tb", "-a*b"] {
        assert!(group_suffix_rejection(bad).is_some(), "{bad:?} must be refused");
    }
    assert!(group_suffix_rejection(&"x".repeat(MAX_GROUP_SUFFIX)).is_none());
    assert!(group_suffix_rejection(&"x".repeat(MAX_GROUP_SUFFIX + 1)).is_some());
}

/// An Entra **group owner** is an ordinary user and picks this string. Before
/// it was sanitized, the comma ended the RDN and the rest of the name became
/// DN components the planner never intended.
#[test]
fn a_hostile_group_display_name_cannot_shape_the_dn() {
    let plan = plan_sync(
        &desired(
            vec![],
            vec![(
                "47c8e0b4-c5e0-4c20-96a6-25f4c4632f18",
                DesiredGroup { display_name: "x,OU=Resources,DC=example,DC=site".to_owned() },
            )],
        ),
        &current(vec![], vec![]),
        &ctx(),
    )
    .unwrap();

    let created = plan
        .ops
        .iter()
        .find_map(|op| match op {
            Op::CreateGroup { dn, sam, .. } => Some((dn.clone(), sam.clone())),
            _ => None,
        })
        .expect("the group is created");
    assert_eq!(created.0, format!("CN=x OU Resources DC example DC site,{BASE}"));
    assert_eq!(created.1, "x OU Resources DC example DC site");
    // The DN has exactly the components it should: one RDN plus OU=Entra's three.
    assert_eq!(created.0.matches(',').count(), 3, "{}", created.0);
}

/// A display name with nothing usable in it would build `CN=,OU=Entra,…`, so
/// the CN falls back to the sam.
#[test]
fn a_user_whose_display_name_survives_nothing_still_gets_a_dn() {
    let created_dn = |du: DesiredUser| {
        plan_sync(
            &desired(vec![("3a1c0b8e-7777-8888-9999-aaaabbbbcccc", du)], vec![]),
            &current(vec![], vec![]),
            &ctx(),
        )
        .unwrap()
        .ops
        .iter()
        .find_map(|op| match op {
            Op::CreateUser { dn, .. } => Some(dn.clone()),
            _ => None,
        })
        .expect("the user is created")
    };
    // `,,,` sanitizes to nothing, so the UPN local part is spent instead.
    assert_eq!(created_dn(des_user(" ,,, ")), format!("CN=someone,{BASE}"));
    // With no source left, the sam is itself `sanitize_sam`'s never-empty
    // fallback, so the two substitutions chain rather than leaving a hole.
    let nothing = DesiredUser { upn: String::new(), ..des_user(" ,,, ") };
    assert_eq!(created_dn(nothing), format!("CN=kbuser,{BASE}"));
}
