//! The recorded scenarios in `testbench/fixtures/planner`, replayed op for op.
//! The captured ones came off a live disposable Samba, recorded by the
//! directory-sync spike, so a match there is a match against measured directory
//! behavior.
//!
//! Two deliberate divergences from the behavior the fixtures were captured
//! against. The planner refuses a whole cycle on a group `sAMAccountName`
//! collision where the captured run emitted the create; and it frees a retired
//! object's name and UPN, which the captured run did not -- so the `plan` halves
//! of S5 and S6 are hand-authored. Their `desired` and `current` halves are
//! still the captured evidence, and the other captured scenarios are untouched.
//!
//! S12 is hand-authored throughout: the converged S2b realm with both role
//! markers stripped off, as a restore or a bulk `extensionName` edit leaves it.
//! The next cycle re-stamps both and does nothing else -- marker loss is
//! self-healing and does not cascade.

use super::*;

#[test]
fn matches_every_recorded_planner_fixture() {
    #[derive(Deserialize)]
    struct Fixture {
        admission: Subject,
        #[serde(default)]
        grant: Option<Subject>,
        desired: Desired,
        current: Current,
        plan: ExpectedPlan,
    }
    #[derive(Deserialize)]
    struct ExpectedPlan {
        ops: Vec<serde_json::Value>,
        conflicts: Vec<String>,
        alerts: Vec<ExpectedAlert>,
    }
    // The kind is what the notification boundary branches on, so a swapped
    // variant is a routing regression the message alone cannot catch.
    #[derive(Deserialize)]
    struct ExpectedAlert {
        kind: AlertKind,
        message: String,
    }

    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testbench/fixtures/planner");
    let mut count = 0;
    for entry in std::fs::read_dir(dir).expect("fixtures dir") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = path.file_stem().unwrap().to_string_lossy().to_string();
        let fx: Fixture = serde_json::from_slice(&std::fs::read(&path).unwrap()).expect(&name);
        // The stamp the fixtures were generated with, and the naming mode they
        // were generated in -- the sam derived from the UPN. Replay needs both.
        let ctx = PlanCtx {
            idp_ou: "OU=Entra,DC=example,DC=site",
            admission: &fx.admission,
            grant: fx.grant.as_ref(),
            upn_suffix: "example.site",
            group_suffix: "",
            now: "2026-07-21T12:00:00Z",
            sam_source: SamSource::Upn,
            // Off for the recorded scenarios. Their `current` blocks were authored when
            // a login name never moved, so every one of them would otherwise gain
            // rename ops and stop being about the thing it was recorded for --
            // retention, quarantine, the admission-group freeze, the duplicate-identity
            // conflict. Automatic renaming has its own tests below, where the before
            // and after are the point.
            automatic_sam_renames: false,
            identity: ENCODE,
        };
        let plan = plan_sync(&fx.desired, &fx.current, &ctx)
            .unwrap_or_else(|e| panic!("{name}: refused to plan: {e:?}"));
        let got: Vec<serde_json::Value> =
            plan.ops.iter().map(|o| serde_json::to_value(o).unwrap()).collect();
        assert_eq!(got, fx.plan.ops, "{name}: ops");
        assert_eq!(plan.conflicts, fx.plan.conflicts, "{name}: conflicts");
        assert_eq!(plan.alerts.len(), fx.plan.alerts.len(), "{name}: alert count");
        for (got, want) in plan.alerts.iter().zip(&fx.plan.alerts) {
            assert_eq!(got.message, want.message, "{name}: alert message");
            assert_eq!(got.kind, want.kind, "{name}: kind of alert {:?}", want.message);
        }
        count += 1;
    }
    assert_eq!(count, 12, "expected all twelve planner fixtures");
}
