use serde_json::{Value, json};

use super::*;
use crate::sync::build_desired;

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

/// The whole read the four recorded pages make, as the snapshot the mirror
/// receives -- serialized the way `golden.json` records it.
fn snapshot(users: &[Page<RawUser>], groups: &[Page<RawGroup>]) -> Value {
    let read = assemble(users, groups).expect("a whole read");
    let admission = Subject::new(ADMISSION);
    let (desired, refused) = build_desired(read, &admission, &[]);
    json!({
        "admission": admission,
        "grant": Option::<Subject>::None,
        "refused": refused,
        "desired": desired,
    })
}

/// The crux: the four pages, narrowed to the admission closure, are the golden
/// desired state byte for byte.
///
/// The golden is an independent hand-derivation, so this is where it and the
/// reader cross-check each other. Five of thirteen users and six of eleven
/// groups survive, and every structural case is among them -- a held service
/// account, a held disabled account, two-level nesting, a two-parent group, and
/// a cycle whose two nodes name each other.
#[test]
fn the_four_pages_reproduce_the_golden_desired_state() {
    let users = [user_page("users_page1"), user_page("users_page2")];
    let groups = [group_page("groups_page1"), group_page("groups_page2")];
    let got = snapshot(&users, &groups);

    let golden = corpus("golden");
    let want = json!({
        "admission": golden["admission"],
        "grant": golden["grant"],
        "refused": golden["refused"],
        "desired": golden["desired"],
    });
    assert_eq!(got, want);
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
    let users = [user_page("users_page1"), user_page("neg_torn_read_user_delete")];
    let groups = [group_page("groups_page1"), group_page("groups_page2")];
    let why = assemble(&users, &groups).expect_err("the count fell");
    assert!(why.contains("deleted mid-read"), "{why}");
}

/// A group inserted between two reads reorders a uuid-sorted stream and repeats a
/// row the reader already held. The count went *up*, so only the repeated pk
/// catches it -- the detector the delete case cannot exercise.
#[test]
fn an_inserted_group_repeats_a_pk_and_refuses_the_read() {
    let users = [user_page("users_page1"), user_page("users_page2")];
    let groups = [group_page("groups_page1"), group_page("neg_torn_read_group_insert")];
    let why = assemble(&users, &groups).expect_err("a pk repeated");
    assert!(why.contains("inserted or repeated"), "{why}");
}

/// One upper-cased uuid refuses the whole cycle, not one account: UUIDField
/// serializes uniformly, so a per-user refusal would retire the population at
/// once. The page is otherwise structurally perfect.
#[test]
fn a_non_canonical_uuid_refuses_the_whole_cycle() {
    let users = [user_page("neg_uuid_noncanonical"), user_page("users_page2")];
    let groups = [group_page("groups_page1"), group_page("groups_page2")];
    let why = assemble(&users, &groups).expect_err("a uuid was not canonical");
    assert!(why.contains("not canonical lowercase"), "{why}");
}

/// A member id no user page returns is a signal in a read that is complete by
/// construction, so it refuses the whole read.
#[test]
fn a_dangling_member_id_refuses_the_read() {
    let users = [user_page("users_page1"), user_page("users_page2")];
    let groups = [group_page("groups_page1"), group_page("neg_dangling_member")];
    let why = assemble(&users, &groups).expect_err("a member id dangled");
    assert!(why.contains("member user pk 900"), "{why}");
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
