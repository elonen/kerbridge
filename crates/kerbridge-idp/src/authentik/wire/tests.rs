use serde_json::Value;

use super::*;
use crate::sync::{build_desired, conformance};

/// The one group the corpus admits people through -- the pk the golden's closure
/// starts from.
const ADMISSION: &str = "9665b31a-b1e6-42e6-9204-45e14bb0eb21";

fn corpus(name: &str) -> Value {
    let path = format!(
        "{}/../../testbench/fixtures/authentik-directory/{name}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
}

fn body(name: &str) -> Value {
    corpus(name)["response"]["body"].clone()
}

fn user_page(name: &str) -> Page<RawUser> {
    serde_json::from_value(body(name)).unwrap()
}

fn group_page(name: &str) -> Page<RawGroup> {
    serde_json::from_value(body(name)).unwrap()
}

/// Assemble a set of named pages into the seam's [`Verdict`](conformance::Verdict):
/// a whole read is a snapshot, a refused one carries its reason.
fn verdict(users: &[&str], groups: &[&str]) -> conformance::Verdict {
    let u: Vec<Page<RawUser>> = users.iter().map(|n| user_page(n)).collect();
    let g: Vec<Page<RawGroup>> = groups.iter().map(|n| group_page(n)).collect();
    match assemble(&u, &g) {
        Ok(_) => conformance::Verdict::Snapshot,
        Err(why) => conformance::Verdict::Refused(why),
    }
}

/// The crux: the four pages, narrowed to the admission closure, are the golden
/// desired state byte for byte -- driven through the shared conformance so the
/// same assertion holds Entra's corpus too.
///
/// The golden is an independent hand-derivation, so this is where it and the
/// reader cross-check each other. Five of thirteen users and six of eleven
/// groups survive, and every structural case is among them -- a held service
/// account, a held disabled account, two-level nesting, a two-parent group, and
/// a cycle whose two nodes name each other.
#[test]
fn the_four_pages_reproduce_the_golden_desired_state() {
    let read = assemble(
        &[user_page("users_page1"), user_page("users_page2")],
        &[group_page("groups_page1"), group_page("groups_page2")],
    )
    .expect("a whole read");
    conformance::whole_read_reproduces_golden(
        read,
        &Subject::new(ADMISSION),
        &[],
        &corpus("golden")["desired"],
    );
}

/// Nothing filters an account, so the refusal list is empty and the population
/// is exactly who a selected group holds -- including the service account and
/// the disabled account the admission closure reaches.
#[test]
fn nothing_is_refused_and_a_held_service_account_is_kept() {
    let read = assemble(
        &[user_page("users_page1"), user_page("users_page2")],
        &[group_page("groups_page1"), group_page("groups_page2")],
    )
    .unwrap();
    assert!(read.refused.is_empty(), "an authentik account is never turned away by the adapter");
    let (desired, refused) = build_desired(read, &Subject::new(ADMISSION), &[]);
    assert!(refused.is_empty());
    // kb-svc-sync's uuid: a service account, held by kb-admission, kept.
    assert!(desired.users.contains_key(&Subject::new("10931101-8391-40c4-9554-4ea40f3d24d5")));
    // kb-svc-retired's uuid: a disabled account, held by kb-two-parents, kept.
    let retired = &desired.users[&Subject::new("68c9a109-235c-48c3-a721-e98b23869457")];
    assert!(!retired.enabled, "a disabled account is mirrored, disabled");
}

/// A user deleted between two page reads lowers the count, and the row after it
/// falls between the pages. The falling count is the detector; the read is
/// refused with no snapshot rather than a population quietly short one person.
#[test]
fn a_deleted_user_lowers_the_count_and_refuses_the_read() {
    let why = conformance::a_torn_read_yields_no_snapshot(verdict(
        &["users_page1", "neg_torn_read_user_delete"],
        &["groups_page1", "groups_page2"],
    ));
    assert!(why.contains("deleted mid-read"), "{why}");
}

/// A read that stops a page early is short of its own count. Every row it lost
/// that the closure could reach dangles, so this mostly restates the dangling-id
/// checks -- but it names the length rather than one row, and it holds for rows
/// bound for nothing.
#[test]
fn a_read_short_of_its_own_count_is_refused_as_truncated() {
    let why = conformance::a_torn_read_yields_no_snapshot(verdict(
        &["users_page1"],
        &["groups_page1", "groups_page2"],
    ));
    assert!(why.contains("truncated user read") && why.contains("counts 13"), "{why}");
}

/// A group inserted between two reads reorders a uuid-sorted stream and repeats a
/// row the reader already held. The count went *up*, so only the repeated pk
/// catches it -- the detector the delete case cannot exercise.
#[test]
fn an_inserted_group_repeats_a_pk_and_refuses_the_read() {
    let why = conformance::a_torn_read_yields_no_snapshot(verdict(
        &["users_page1", "users_page2"],
        &["groups_page1", "neg_torn_read_group_insert"],
    ));
    assert!(why.contains("inserted or repeated"), "{why}");
}

/// One upper-cased uuid refuses the whole cycle, not one account: UUIDField
/// serializes uniformly, so a per-user refusal would retire the population at
/// once. The page is otherwise structurally perfect.
#[test]
fn a_non_canonical_uuid_refuses_the_whole_cycle() {
    let why = conformance::a_torn_read_yields_no_snapshot(verdict(
        &["neg_uuid_noncanonical", "users_page2"],
        &["groups_page1", "groups_page2"],
    ));
    assert!(why.contains("not canonical lowercase"), "{why}");
}

/// A member id no user page returns is a signal in a read that is complete by
/// construction, so it refuses the whole read.
#[test]
fn a_dangling_member_id_refuses_the_read() {
    let why = conformance::a_torn_read_yields_no_snapshot(verdict(
        &["users_page1", "users_page2"],
        &["groups_page1", "neg_dangling_member"],
    ));
    assert!(why.contains("member user pk 900"), "{why}");
}

/// The same rule against the bytes a real partial grant returned, rather than
/// against a hand-made row.
///
/// This is the one case asserted on a recording instead of on the derived
/// corpus, because being recorded is its whole content: it settles what an
/// object-permission grant *does* to a read. authentik's object filter narrows
/// the user list and `pagination.count` with it -- the envelope is internally
/// perfect and a count cross-check sees nothing -- but it does not touch a
/// group's `users` array, a group's `children`, or a visible user's own
/// `groups`. Whatever the grant hides therefore survives as an id in at least
/// one of those three, and the read is refused whole. This recording trips the
/// user-side detector first, because users are resolved before groups.
///
/// The recording's ids change on every re-record, so only the refusal is
/// asserted, never a pk.
#[test]
fn a_recorded_partial_grant_is_refused_as_a_dangling_id() {
    let recording = |name: &str| {
        let path = format!(
            "{}/../../testbench/authentik/captured/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        v["response"]["body"].clone()
    };
    let users: Page<RawUser> =
        serde_json::from_value(recording("users_partial_grant_page1")).unwrap();
    let groups: Page<RawGroup> =
        serde_json::from_value(recording("groups_partial_grant_page1")).unwrap();

    let why = conformance::a_torn_read_yields_no_snapshot(match assemble(&[users], &[groups]) {
        Ok(_) => conformance::Verdict::Snapshot,
        Err(why) => conformance::Verdict::Refused(why),
    });
    assert!(why.contains("a complete read has no dangling ids"), "{why}");
}

/// The name rule, spelled out on the two accounts that exercise it. `username`
/// leads; the dotted display name follows, cut to the budget; the three spellings
/// deduplicate first-wins so an account whose spellings collapse keeps one.
#[test]
fn name_candidates_are_username_then_display_then_email_deduplicated() {
    let read = assemble(
        &[user_page("users_page1"), user_page("users_page2")],
        &[group_page("groups_page1"), group_page("groups_page2")],
    )
    .unwrap();

    // kb-svc-sync: username, then "Kerbridge Sync Collector" dotted and cut to 20;
    // the empty address contributes nothing.
    let sync = &read.users[&Subject::new("10931101-8391-40c4-9554-4ea40f3d24d5")];
    let sync: Vec<&str> = sync.name_candidates.iter().map(NameCandidate::as_str).collect();
    assert_eq!(sync, ["kb-svc-sync", "kerbridge.sync.colle"]);

    // ada.lovelace: username, display and email all reduce to the same string,
    // so first-wins leaves one.
    let ada = &read.users[&Subject::new("19427827-69e8-4d8f-9db4-b90bd5ff364e")];
    let ada: Vec<&str> = ada.name_candidates.iter().map(NameCandidate::as_str).collect();
    assert_eq!(ada, ["ada.lovelace"]);
}
