//! DarkStar campaign CLI contract: the safe offline plan, the approved MySQL
//! opt-in enumeration, strict argument rejection and the explicit repeated
//! `--suite` subset selection.
//!
//! Everything here is local and offline by construction: only `--list`
//! (full plan and explicit subsets) and argument matrices that fail during
//! parsing or plan selection are exercised, so no database is started, no
//! cargo dispatch happens and no artifact directory is created.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const MYSQL_PAPER_SUITE: &str = "paper-usenix-mysql";

/// Catalog cases gated behind the approved run-scoped MySQL fixture.
const MYSQL_CASES: [&str; 5] = [
    "darkstar-mysql-apply",
    "darkstar-mysql-cold-install",
    "darkstar-mysql-recovery-curve",
    "darkstar-mysql-binary-e2e",
    "darkstar-mysql-transport-recovery",
];
const HOUR_SOAK: &str = "darkstar-synthetic-soak-hour";

/// Offline catalog cases: core smoke plus performance and loopback opt-ins.
const OFFLINE_CASES: [&str; 26] = [
    "darkstar-types",
    "darkstar-database-offline",
    "darkstar-identity",
    "darkstar-gateway",
    "darkstar-trustgraph",
    "darkstar-trustgraph-governance-parity",
    "darkstar-single-node-library",
    "darkstar-single-node-binary",
    "darkstar-process-refusals",
    "darkstar-fence-and-session-controls",
    "darkstar-binding-history",
    "darkstar-digest-capacity-and-scheduler",
    "darkstar-reverse-target-scale",
    "darkstar-session-contention",
    "darkstar-candidate-bench",
    "darkstar-confirmation-read-scale",
    "darkstar-mixed-unrelated",
    "darkstar-mixed-target",
    "darkstar-mixed-alternating",
    "darkstar-journal-and-checkpoint-load",
    "darkstar-recheck-cost",
    "darkstar-http-login-matrix",
    "darkstar-synthetic-paper-warm-governance",
    "darkstar-synthetic-binary-lifecycle",
    "darkstar-synthetic-writer-contention",
    "darkstar-synthetic-soak-smoke",
];

/// Paper-cut suites the offline plan must keep disclosing.
const PAPER_DISCLOSURE: [&str; 8] = [
    "paper-admission-depth2",
    "paper-composed-mediation",
    "paper-journal-witnesses",
    "paper-runner-contracts",
    "scale-memory-v1-500k",
    "paper-current-root-controls",
    "memory-v1-request-chain-candidate",
    "trustgraph-memory-v1-permission-chain",
];

fn darkstar(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_test-campaign"))
        .current_dir(std::env::temp_dir())
        .arg("--darkstar")
        .args(args)
        .output()
        .unwrap()
}

fn list(args: &[&str]) -> Value {
    let output = darkstar(args);
    assert!(output.status.success(), "{args:?}: {:?}", output);
    serde_json::from_slice(&output.stdout).unwrap()
}

fn launch(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_test-campaign"))
        .current_dir(std::env::temp_dir())
        .env_clear()
        .arg("--darkstar")
        .args(args)
        .output()
        .unwrap()
}

fn item_ids(plan: &Value) -> Vec<&str> {
    plan["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap())
        .collect()
}

fn excluded(plan: &Value) -> &[Value] {
    plan["excluded"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn selects_mysql(item: &Value) -> bool {
    item["test_services"]
        .as_array()
        .is_some_and(|services| services.iter().any(|service| service == "mysql"))
}

/// Run-scoped scratch artifact root; removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("darkstar-cli-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn empty(&self) -> bool {
        std::fs::read_dir(&self.0)
            .map(|mut entries| entries.next().is_none())
            .unwrap_or(false)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn offline_plan_lists_all_smoke_paper_and_opt_in_cases_without_mysql() {
    let plan = list(&["--list"]);
    assert!(plan["scope"]
        .as_str()
        .unwrap()
        .contains("DarkStar current-source Rust suites"));
    let items = plan["items"].as_array().unwrap();
    let ids = item_ids(&plan);
    assert_eq!(ids.len(), 54, "offline plan item count drifted");

    // Every offline catalog case is listed: core smoke plus the performance
    // and loopback opt-ins, including the bench lane.
    for id in OFFLINE_CASES {
        assert!(
            ids.contains(&id),
            "offline plan is missing DarkStar case {id}"
        );
    }
    let bench = items
        .iter()
        .find(|item| item["id"] == "darkstar-candidate-bench")
        .unwrap();
    assert_eq!(bench["argv"][1], "bench");

    // The paper cut stays disclosed.
    for id in PAPER_DISCLOSURE {
        assert!(
            ids.contains(&id),
            "offline plan is missing paper suite {id}"
        );
    }
    let root_controls = items
        .iter()
        .find(|item| item["id"] == "paper-current-root-controls")
        .unwrap();
    let argv = root_controls["argv"].as_array().unwrap();
    assert_eq!(
        &argv[argv.len() - 2..],
        ["--skip", "login_contention_at_live_session_scale"]
    );

    // Catalog cases always dispatch cargo offline and locked.
    for item in items
        .iter()
        .filter(|item| item["id"].as_str().unwrap().starts_with("darkstar-"))
    {
        let id = item["id"].as_str().unwrap();
        let argv = item["argv"].as_array().unwrap();
        assert_eq!(argv[0], "cargo", "{id}");
        assert!(
            matches!(argv[1].as_str().unwrap(), "test" | "bench"),
            "{id}"
        );
        assert_eq!(argv[2], "--offline", "{id} must not fetch from the network");
        assert_eq!(argv[3], "--locked", "{id}");
    }

    // No MySQL suite is selected offline.
    for id in MYSQL_CASES {
        assert!(!ids.contains(&id), "offline plan selected MySQL case {id}");
        let entry = excluded(&plan)
            .iter()
            .find(|entry| entry["id"].as_str() == Some(id))
            .unwrap_or_else(|| panic!("offline plan must disclose the skipped MySQL case {id}"));
        assert_eq!(entry["status"], "SKIP");
        assert_eq!(entry["reason"], "requires --mysql");
    }
    assert!(
        !ids.contains(&MYSQL_PAPER_SUITE),
        "offline plan selected the MySQL paper suite"
    );
    assert!(
        excluded(&plan)
            .iter()
            .any(|entry| entry["id"].as_str() == Some(MYSQL_PAPER_SUITE)),
        "offline plan must disclose the skipped MySQL paper suite"
    );
    for entry in excluded(&plan) {
        let id = entry["id"].as_str().unwrap();
        assert!(
            id == MYSQL_PAPER_SUITE || MYSQL_CASES.contains(&id) || id == HOUR_SOAK,
            "unexpected offline exclusion {id}"
        );
    }
    for item in items {
        assert!(
            !selects_mysql(item),
            "offline plan selected MySQL services for {}",
            item["id"]
        );
    }

    // The scope disclosure names what is not part of the current campaign.
    assert!(!plan["not_current_darkstar"].as_array().unwrap().is_empty());
    assert!(plan["historical_boundaries"].is_array());
}

#[test]
fn synthetic_suites_select_exact_loopback_tests_without_replacing_mysql() {
    let warm = "darkstar-synthetic-paper-warm-governance";
    let lifecycle = "darkstar-synthetic-binary-lifecycle";
    let plan = list(&["--list", "--suite", lifecycle, "--suite", warm]);
    assert_eq!(item_ids(&plan), [warm, lifecycle]);
    for (item, test, original) in [
        (
            &plan["items"][0],
            "memory_v1_service::lifecycle_tests::synthetic_scenarios::paper_warm_governance_with_synthetic_snapshot",
            MYSQL_PAPER_SUITE,
        ),
        (
            &plan["items"][1],
            "memory_v1_service::lifecycle_tests::synthetic_scenarios::binary_lifecycle_with_synthetic_snapshot",
            "darkstar-mysql-binary-e2e",
        ),
    ] {
        assert!(item["test_services"].as_array().unwrap().is_empty());
        assert!(item["boundary"].as_str().unwrap().contains(original));
        let argv = item["argv"].as_array().unwrap();
        let separator = argv.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(
            &argv[separator + 1..],
            ["--ignored", "--exact", test, "--nocapture", "--test-threads=1"]
        );
    }
}

#[test]
fn hour_soak_is_explicit_and_requires_no_database() {
    let default = list(&["--list"]);
    assert!(!item_ids(&default).contains(&HOUR_SOAK));
    assert!(excluded(&default).iter().any(|entry| {
        entry["id"] == HOUR_SOAK && entry["reason"] == "requires explicit --suite"
    }));
    let selected = list(&["--list", "--suite", HOUR_SOAK]);
    assert_eq!(item_ids(&selected), [HOUR_SOAK]);
    assert!(!selects_mysql(&selected["items"][0]));
}

#[test]
fn mysql_opt_in_enumerates_exactly_six_approved_suites() {
    for args in [
        vec!["--list", "--mysql"],
        vec!["--list", "--mysql", "--run-id", "contract_01"],
    ] {
        let plan = list(&args);
        let items = plan["items"].as_array().unwrap();
        assert_eq!(item_ids(&plan).len(), 60, "{args:?} item count drifted");
        let mysql: Vec<&Value> = items.iter().filter(|item| selects_mysql(item)).collect();
        assert_eq!(
            mysql.len(),
            6,
            "{args:?} must enumerate exactly six MySQL suites"
        );
        let mysql_ids: Vec<&str> = mysql
            .iter()
            .map(|item| item["id"].as_str().unwrap())
            .collect();
        for id in [MYSQL_PAPER_SUITE].into_iter().chain(MYSQL_CASES) {
            assert!(
                mysql_ids.contains(&id),
                "{args:?} is missing MySQL suite {id}"
            );
        }

        // The MySQL opt-in is additive: the offline cut stays selected.
        let ids = item_ids(&plan);
        for id in OFFLINE_CASES {
            assert!(ids.contains(&id), "{args:?} dropped offline case {id}");
        }
        assert_eq!(excluded(&plan).len(), 1, "{args:?}");
        assert_eq!(excluded(&plan)[0]["id"], HOUR_SOAK);

        // MySQL fixtures disclose their rehearsal-only boundary and never run
        // before the offline cut; the exploratory model stays absolutely last.
        for item in &mysql {
            assert!(
                item["boundary"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("MySQL"),
                "{} must disclose its MySQL boundary",
                item["id"]
            );
            let id = item["id"].as_str().unwrap();
            if MYSQL_CASES.contains(&id) {
                let argv = item["argv"].as_array().unwrap();
                assert_eq!(argv[2], "--offline", "{id} must stay offline-locked");
                assert_eq!(argv[3], "--locked", "{id} must stay offline-locked");
            }
        }
        assert_eq!(items.last().unwrap()["id"], "paper-repair-full-bounds");
        let next_to_last: Vec<&str> = items[items.len() - 6..items.len() - 1]
            .iter()
            .map(|item| item["id"].as_str().unwrap())
            .collect();
        assert_eq!(next_to_last.len(), 5);
        for id in MYSQL_CASES {
            assert!(
                next_to_last.contains(&id),
                "{args:?} reordered MySQL suites"
            );
        }
    }
}

#[test]
fn strict_arguments_reject_invalid_or_run_id_usage_without_dispatching() {
    let too_long = "a".repeat(33);
    for (args, expected) in [
        (&["--bogus"][..], "unknown DarkStar option: --bogus"),
        (&["--mysql"], "--mysql requires an explicit --run-id"),
        (&["--mysql", "--run-id", "Not_A_Run"], "lowercase"),
        (&["--mysql", "--run-id", too_long.as_str()], "lowercase"),
        (&["--run-id", "bad/id"], "invalid DarkStar run id"),
        (&["--run-id"], "missing value for --run-id"),
        (&["--artifact-root"], "missing value for --artifact-root"),
    ] {
        let output = launch(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{args:?}: {stderr}");
        assert!(
            stderr.contains("Usage:"),
            "{args:?} must echo the DarkStar usage: {stderr}"
        );
    }
}

#[test]
fn help_prints_usage_without_starting_a_campaign() {
    let output = darkstar(&["--help"]);
    assert!(output.status.success(), "{:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "{stdout}");
    assert!(stdout.contains("--mysql"), "{stdout}");
    assert!(stdout.contains("--run-id"), "{stdout}");
    assert!(
        stdout.contains("never provisions or targets production"),
        "{stdout}"
    );
}

#[test]
fn listing_never_creates_an_artifact_directory() {
    // A successful listing leaves even a missing artifact root untouched.
    let missing =
        std::env::temp_dir().join(format!("darkstar-cli-missing-{}", uuid::Uuid::new_v4()));
    let plan = list(&["--list", "--artifact-root", missing.to_str().unwrap()]);
    assert!(!item_ids(&plan).is_empty());
    assert!(
        !missing.exists(),
        "--list must not create the artifact root"
    );

    // The same holds for an existing empty root and for rejected run-shaped
    // arguments: nothing is dispatched, nothing is created.
    let scratch = Scratch::new("list");
    let base = scratch.path().to_str().unwrap().to_owned();
    let plan = list(&["--list", "--artifact-root", &base]);
    assert!(!item_ids(&plan).is_empty());
    assert!(
        scratch.empty(),
        "--list must not create artifact directories"
    );
    for args in [
        vec!["--artifact-root", base.as_str(), "--mysql"],
        vec![
            "--artifact-root",
            base.as_str(),
            "--mysql",
            "--run-id",
            "Not_A_Run",
        ],
    ] {
        let output = launch(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(
            scratch.empty(),
            "rejected arguments created artifacts: {args:?}"
        );
    }
}

#[test]
fn explicit_suite_selection_keeps_canonical_order_and_full_item_contracts() {
    let full = list(&["--list"]);
    let full_items = full["items"].as_array().unwrap();
    let item_of = |id: &str| {
        full_items
            .iter()
            .find(|item| item["id"] == id)
            .unwrap()
            .clone()
    };

    // The subset deliberately spans manifest-derived suites, catalog core,
    // performance, loopback and the trailing repair model, and is given in a
    // non-canonical argument order.
    let wanted = [
        "paper-repair-full-bounds",
        "darkstar-http-login-matrix",
        "darkstar-binding-history",
        "darkstar-types",
        "paper-admission-depth2",
    ];
    let scratch = Scratch::new("select");
    let plan = list(&[
        "--list",
        "--artifact-root",
        scratch.path().to_str().unwrap(),
        "--suite",
        "darkstar-types",
        "--suite",
        "paper-repair-full-bounds",
        "--suite",
        "paper-admission-depth2",
        "--suite",
        "darkstar-binding-history",
        "--suite",
        "darkstar-http-login-matrix",
    ]);

    // The listing is exactly the canonical plan order restricted to the
    // selection; the argument order above must not leak into the plan.
    let ids = item_ids(&full);
    let expected: Vec<&str> = ids
        .iter()
        .copied()
        .filter(|id| wanted.contains(id))
        .collect();
    assert_eq!(item_ids(&plan), expected);
    assert_eq!(
        plan["explicit_selection"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>(),
        [
            "darkstar-types",
            "paper-repair-full-bounds",
            "paper-admission-depth2",
            "darkstar-binding-history",
            "darkstar-http-login-matrix",
        ]
    );

    // Listing an explicit subset dispatches nothing and creates no artifacts.
    assert!(scratch.empty());

    // Every selected item is identical to its full-plan counterpart: argv,
    // test services and boundary are untouched, so no scope changes.
    let selected_items = plan["items"].as_array().unwrap();
    assert_eq!(selected_items.len(), expected.len());
    for id in &expected {
        let selected = selected_items
            .iter()
            .find(|item| item["id"] == *id)
            .unwrap();
        assert_eq!(
            selected,
            &item_of(id),
            "{id} must keep its exact full-plan contract"
        );
    }

    // The repair model override is pinned by explicit Cargo config pairs ahead
    // of the libtest separator; cargo consumes them, libtest never sees them.
    let repair_item = item_of("paper-repair-full-bounds");
    let argv = repair_item["argv"]
        .as_array()
        .unwrap()
        .iter()
        .map(|arg| arg.as_str().unwrap())
        .collect::<Vec<_>>();
    let separator = argv.iter().position(|arg| *arg == "--").unwrap();
    assert_eq!(
        argv[separator - 6..separator],
        [
            "--config",
            "profile.dev.package.test-harness.opt-level=2",
            "--config",
            "profile.dev.package.test-harness.debug-assertions=true",
            "--config",
            "profile.dev.package.test-harness.overflow-checks=true",
        ]
    );
    assert_eq!(argv[..4], ["cargo", "test", "--locked", "--offline"]);
}

#[test]
fn explicit_selection_rejects_unknown_duplicate_and_ungated_mysql_ids() {
    for (args, expected) in [
        // Unknown: neither an enabled plan item nor a disclosed MySQL gate.
        (
            vec!["--list", "--suite", "darkstar-not-a-case"],
            "unknown DarkStar suite",
        ),
        // A real manifest suite outside the DarkStar plan is equally unknown.
        (
            vec!["--list", "--suite", "campaign-contracts"],
            "unknown DarkStar suite",
        ),
        // Known but gated behind the approved MySQL opt-in, in list and
        // dispatch mode, with and without a run id.
        (
            vec!["--list", "--suite", "darkstar-mysql-apply"],
            "requires --mysql",
        ),
        (vec!["--suite", "darkstar-mysql-apply"], "requires --mysql"),
        (
            vec!["--list", "--suite", "paper-usenix-mysql"],
            "requires --mysql",
        ),
        (
            vec!["--suite", "darkstar-mysql-apply", "--run-id", "contract_01"],
            "requires --mysql",
        ),
        // Duplicates are refused even for otherwise valid ids.
        (
            vec![
                "--list",
                "--suite",
                "darkstar-types",
                "--suite",
                "darkstar-types",
            ],
            "duplicate DarkStar suite selection",
        ),
        // Malformed ids never reach plan matching.
        (
            vec!["--list", "--suite", "not a suite"],
            "invalid DarkStar suite id",
        ),
        (vec!["--list", "--suite"], "missing value for --suite"),
        // The approved opt-in itself still requires its run id when dispatching.
        (
            vec!["--suite", "darkstar-mysql-apply", "--mysql"],
            "--mysql requires an explicit --run-id",
        ),
    ] {
        let output = launch(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{args:?}: {stderr}");
        assert!(
            stderr.contains("Usage:"),
            "{args:?} must echo the DarkStar usage: {stderr}"
        );
    }
}

#[test]
fn mysql_opt_in_selection_lists_exactly_the_approved_suite() {
    for (id, mysql) in [
        ("darkstar-mysql-apply", true),
        ("darkstar-types", false),
        ("paper-usenix-mysql", true),
    ] {
        let plan = list(&["--list", "--mysql", "--suite", id]);
        let items = plan["items"].as_array().unwrap();
        assert_eq!(item_ids(&plan), [id], "{id} must be the only listed item");
        assert_eq!(selects_mysql(&items[0]), mysql, "{id} service binding");
        if mysql {
            assert_eq!(
                items[0]["test_services"],
                serde_json::json!(["mysql"]),
                "{id} must keep its MySQL service binding"
            );
            assert!(
                items[0]["boundary"].as_str().unwrap().contains("MySQL"),
                "{id} must disclose its MySQL boundary"
            );
        }
        assert_eq!(excluded(&plan).len(), 1, "{id} with --mysql opt-in");
        assert_eq!(excluded(&plan)[0]["id"], HOUR_SOAK);
    }
}
