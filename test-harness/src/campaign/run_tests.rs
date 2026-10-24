use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

static RUN_TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct RunDirectory(PathBuf);

impl RunDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        for _ in 0..32 {
            let sequence = RUN_TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "astrallight-campaign-run-{}-{nonce}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create isolated campaign directory: {error}"),
            }
        }
        panic!("could not allocate isolated campaign directory after bounded attempts");
    }
}

impl Drop for RunDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn synthetic_manifest(root: &Path) -> Manifest {
    let series = BTreeMap::from([(
        "E4".to_owned(),
        toml::from_str("boundary='synthetic offline contract only'").unwrap(),
    )]);
    Manifest {
        raw: TomlValue::Table(toml::map::Map::new()),
        profiles: BTreeMap::new(),
        series,
        suites: Vec::new(),
        root: root.to_path_buf(),
    }
}

fn synthetic_suite(id: &str, argv: &[&str], required_output: &str) -> TomlValue {
    let argv = argv
        .iter()
        .map(|argument| {
            format!(
                "\"{}\"",
                argument.replace('\\', "\\\\").replace('\"', "\\\"")
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    toml::from_str(&format!(
        "id = \"{id}\"\nprofile = \"native-kernel\"\ntest_services = []\nseries = [\"E4\"]\nscope = \"component\"\nowner = \"campaign-contract-tests\"\nboundary = \"synthetic local subprocess only\"\nsources = []\nargv = [{argv}]\nacceptance = \"command\"\nrequired_output = \"{required_output}\"\ntimeout_seconds = 5\n"
    ))
    .unwrap()
}

fn read_report(directory: &Path, run_id: &str) -> Value {
    serde_json::from_slice(&fs::read(directory.join(run_id).join("result.json")).unwrap()).unwrap()
}

fn test_runtime<F, E>(snapshot: F, execute_command: E) -> SelectedRuntime<'static, F, E>
where
    F: FnMut(&Path) -> Result<String, String>,
    E: FnMut(&TomlValue, &BTreeMap<OsString, OsString>, &Path, &Path) -> Result<Value, String>,
{
    SelectedRuntime {
        environment: &[],
        snapshot,
        execute_command,
    }
}

fn integration_suite(id: &str) -> TomlValue {
    toml::from_str(&format!(
        "id = \"{id}\"\nprofile = \"native-single-node\"\ntest_services = [\"mysql\"]\nseries = [\"E4\"]\nscope = \"integration\"\nowner = \"campaign-contract-tests\"\nboundary = \"preflight contract only; no database access\"\nsources = []\nargv = [\"/bin/sh\", \"-c\", \"printf proof\"]\nacceptance = \"command\"\nrequired_output = \"proof\"\ntimeout_seconds = 5\n"
    ))
    .unwrap()
}

#[test]
fn run_selected_publishes_owned_report_and_executes_only_local_contract_commands() {
    let artifacts = RunDirectory::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let manifest = synthetic_manifest(root);
    let suite = synthetic_suite("local", &["/bin/sh", "-c", "printf proof"], "proof");

    assert_eq!(
        run_selected(
            &manifest,
            &[suite],
            "run-report-contract",
            &artifacts.0,
            false
        )
        .unwrap(),
        0
    );
    let report = read_report(&artifacts.0, "run-report-contract");
    assert_eq!(report["schema_version"], 2);
    assert_eq!(report["taskId"], "run-report-contract");
    assert_eq!(report["responsible_agent"], "test-harness");
    assert_eq!(report["status"], "PASS");
    assert_eq!(report["retries"], 0);
    assert_eq!(report["preflight"]["status"], "PASS");
    assert_eq!(report["selection"], json!(["local"]));
    assert_eq!(report["results"].as_array().unwrap().len(), 1);
    assert_eq!(report["results"][0]["status"], "PASS");
    assert_eq!(
        report["results"][0]["actual_postcondition"],
        "scoped command completed; see its component proof boundary"
    );
    assert_eq!(report["results"][0]["exit_code"], 0);
    assert_eq!(
        fs::read_to_string(report["results"][0]["stdout"].as_str().unwrap()).unwrap(),
        "proof"
    );
    assert!(report["finished_at"].as_str().unwrap().starts_with("unix:"));
    assert!(report["phase_timing_seconds"][0]["finished_at_monotonic_offset"].is_number());
    assert!(report["outside_selection"].is_array());
    assert!(artifacts
        .0
        .join("run-report-contract/collection/local.stdout.log")
        .is_file());
}

#[test]
fn run_selected_preflight_blocks_every_suite_before_any_dispatch() {
    let artifacts = RunDirectory::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let manifest = synthetic_manifest(root);
    let unavailable = synthetic_suite(
        "unavailable",
        &["astrallight-command-that-does-not-exist"],
        "proof",
    );
    let later = synthetic_suite("later", &["/bin/sh", "-c", "printf proof"], "proof");

    assert_eq!(
        run_selected(
            &manifest,
            &[unavailable, later],
            "run-preflight-contract",
            &artifacts.0,
            false
        )
        .unwrap(),
        1
    );
    let report = read_report(&artifacts.0, "run-preflight-contract");
    assert_eq!(report["status"], "BLOCKED");
    assert_eq!(report["preflight"]["status"], "BLOCKED");
    assert_eq!(report["results"].as_array().unwrap().len(), 2);
    assert_eq!(report["results"][0]["status"], "BLOCKED");
    assert_eq!(report["results"][1]["status"], "BLOCKED");
    assert_eq!(report["results"][1]["log_integrity"], "not started");
    assert!(!artifacts
        .0
        .join("run-preflight-contract/collection/later.stdout.log")
        .exists());
}

#[test]
fn run_selected_stops_after_nonpass_and_records_the_stopped_phase() {
    let artifacts = RunDirectory::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let manifest = synthetic_manifest(root);
    let first = synthetic_suite(
        "first",
        &["/bin/sh", "-c", "printf no-proof; exit 3"],
        "proof",
    );
    let later = synthetic_suite("later", &["/bin/sh", "-c", "printf proof"], "proof");

    assert_eq!(
        run_selected(
            &manifest,
            &[first, later],
            "run-fail-stop-contract",
            &artifacts.0,
            false
        )
        .unwrap(),
        1
    );
    let report = read_report(&artifacts.0, "run-fail-stop-contract");
    assert_eq!(report["status"], "FAIL");
    assert_eq!(report["results"][0]["status"], "FAIL");
    assert_eq!(report["results"][1]["status"], "BLOCKED");
    assert_eq!(report["stopped_at"]["id"], "first");
    assert_eq!(report["stopped_at"]["status"], "FAIL");
    assert_eq!(report["stopped_at"]["phase"], "collection");
    assert!(!artifacts
        .0
        .join("run-fail-stop-contract/collection/later.stdout.log")
        .exists());
}

#[test]
fn run_selected_verify_items_reexecutes_in_fresh_phase_directories() {
    let artifacts = RunDirectory::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let manifest = synthetic_manifest(root);
    let suites = vec![
        synthetic_suite("one", &["/bin/sh", "-c", "printf proof"], "proof"),
        synthetic_suite("two", &["/bin/sh", "-c", "printf proof"], "proof"),
    ];

    assert_eq!(
        run_selected(
            &manifest,
            &suites,
            "run-two-phase-contract",
            &artifacts.0,
            true
        )
        .unwrap(),
        0
    );
    let report = read_report(&artifacts.0, "run-two-phase-contract");
    assert_eq!(report["status"], "PASS");
    assert_eq!(report["verify_items"], true);
    assert_eq!(report["item_results"].as_array().unwrap().len(), 2);
    assert_eq!(report["results"].as_array().unwrap().len(), 2);
    assert_eq!(report["item_results"][0]["phase"], "items");
    assert_eq!(report["results"][0]["phase"], "collection");
    assert_ne!(
        report["item_results"][0]["stdout"],
        report["results"][0]["stdout"]
    );
    assert_eq!(report["item_results"][0]["status"], "PASS");
    assert_eq!(report["results"][1]["status"], "PASS");
    assert!(artifacts
        .0
        .join("run-two-phase-contract/items/one.stdout.log")
        .is_file());
    assert!(artifacts
        .0
        .join("run-two-phase-contract/collection/one.stdout.log")
        .is_file());
}

#[test]
fn run_selected_collection_preflight_blocks_every_suite_for_missing_database() {
    let artifacts = RunDirectory::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let manifest = synthetic_manifest(root);
    let offline = synthetic_suite("offline", &["/bin/sh", "-c", "printf proof"], "proof");
    let integration = integration_suite("integration");
    let calls = std::cell::Cell::new(0usize);

    assert_eq!(
        run_selected_with_runtime(
            &manifest,
            &[offline, integration],
            "run-missing-db-preflight",
            &artifacts.0,
            false,
            test_runtime(
                |_| Ok("frozen".into()),
                |_, _, _, _| {
                    calls.set(calls.get() + 1);
                    Ok(json!({"status":"PASS","reason":"local synthetic command"}))
                },
            ),
        )
        .unwrap(),
        1
    );
    let report = read_report(&artifacts.0, "run-missing-db-preflight");
    assert_eq!(calls.get(), 0);
    assert_eq!(report["preflight"]["status"], "BLOCKED");
    assert_eq!(report["results"][0]["status"], "BLOCKED");
    assert_eq!(report["results"][1]["status"], "BLOCKED");
}

#[test]
fn run_selected_marks_source_changes_before_or_during_dispatch_unknown() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let manifest = synthetic_manifest(root);
    let suite = synthetic_suite("local", &["/bin/sh", "-c", "printf proof"], "proof");

    for (run_id, snapshots, expected_calls) in [
        ("changed-before-dispatch", vec!["initial", "changed"], 0),
        (
            "changed-during-dispatch",
            vec!["initial", "initial", "changed"],
            1,
        ),
    ] {
        let artifacts = RunDirectory::new();
        let mut remaining = snapshots.into_iter();
        let calls = std::cell::Cell::new(0usize);
        assert_eq!(
            run_selected_with_runtime(
                &manifest,
                std::slice::from_ref(&suite),
                run_id,
                &artifacts.0,
                false,
                test_runtime(
                    |_| Ok(remaining.next().unwrap_or("changed").into()),
                    |_, _, _, _| {
                        calls.set(calls.get() + 1);
                        Ok(json!({"status":"PASS","reason":"local synthetic command"}))
                    },
                ),
            )
            .unwrap(),
            1
        );
        let report = read_report(&artifacts.0, run_id);
        assert_eq!(calls.get(), expected_calls);
        assert_eq!(report["results"][0]["status"], "UNKNOWN");
        assert_eq!(report["status"], "UNKNOWN");
    }
}

#[test]
fn run_selected_keeps_report_pending_until_every_phase_finishes() {
    let artifacts = RunDirectory::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let manifest = synthetic_manifest(root);
    let suites = vec![
        synthetic_suite("one", &["/bin/sh", "-c", "printf proof"], "proof"),
        synthetic_suite("two", &["/bin/sh", "-c", "printf proof"], "proof"),
    ];
    let dispatch_snapshots = std::cell::RefCell::new(Vec::new());

    assert_eq!(
        run_selected_with_runtime(
            &manifest,
            &suites,
            "run-pending-publication-contract",
            &artifacts.0,
            true,
            test_runtime(
                |_| Ok("frozen".into()),
                |_, _, _, _| {
                    dispatch_snapshots.borrow_mut().push(read_report(
                        &artifacts.0,
                        "run-pending-publication-contract",
                    ));
                    Ok(json!({"status":"PASS","reason":"local synthetic command"}))
                },
            ),
        )
        .unwrap(),
        0
    );

    let snapshots = dispatch_snapshots.into_inner();
    assert_eq!(snapshots.len(), 4);
    for (index, report) in snapshots.iter().enumerate() {
        assert_eq!(report["status"], "PENDING");
        assert!(report.get("finished_at").is_none());
        let (records, expected_len, phase) = if index < 2 {
            (&report["item_results"], index + 1, "items")
        } else {
            (&report["results"], index - 1, "collection")
        };
        assert_eq!(records.as_array().unwrap().len(), expected_len);
        let active = records.as_array().unwrap().last().unwrap();
        assert_eq!(active["phase"], phase);
        assert_eq!(active["status"], "PENDING");
        assert!(active["stdout"].as_str().unwrap().ends_with(".stdout.log"));
        assert!(active["stderr"].as_str().unwrap().ends_with(".stderr.log"));
        assert!(active["log_integrity"]
            .as_str()
            .unwrap()
            .contains("in progress"));
    }
    assert_eq!(
        read_report(&artifacts.0, "run-pending-publication-contract")["status"],
        "PASS"
    );
}

#[test]
fn run_selected_fail_stops_on_every_nonpass_in_either_phase() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let manifest = synthetic_manifest(root);
    let suites = vec![
        synthetic_suite("one", &["/bin/sh", "-c", "printf proof"], "proof"),
        synthetic_suite("two", &["/bin/sh", "-c", "printf proof"], "proof"),
    ];

    for status in ["FAIL", "UNKNOWN", "BLOCKED", "PENDING", "SKIP"] {
        for verify_items in [false, true] {
            let artifacts = RunDirectory::new();
            let calls = std::cell::Cell::new(0usize);
            let run_id = format!("nonpass-{status}-{verify_items}");
            assert_eq!(
                run_selected_with_runtime(
                    &manifest,
                    &suites,
                    &run_id,
                    &artifacts.0,
                    verify_items,
                    test_runtime(
                        |_| Ok("frozen".into()),
                        |_, _, _, _| {
                            calls.set(calls.get() + 1);
                            Ok(json!({"status":status,"reason":"synthetic non-pass"}))
                        },
                    ),
                )
                .unwrap(),
                1
            );
            let report = read_report(&artifacts.0, &run_id);
            assert_eq!(calls.get(), 1, "{status}, verify_items={verify_items}");
            assert_eq!(report["status"], status);
            if verify_items {
                assert_eq!(report["item_results"][0]["status"], status);
                assert_eq!(report["item_results"][1]["status"], "BLOCKED");
                assert_eq!(report["results"][0]["status"], "BLOCKED");
                assert_eq!(report["results"][1]["status"], "BLOCKED");
                assert_eq!(report["stopped_at"]["phase"], "items");
            } else {
                assert_eq!(report["results"][0]["status"], status);
                assert_eq!(report["results"][1]["status"], "BLOCKED");
                assert_eq!(report["stopped_at"]["phase"], "collection");
            }
        }
    }
}

#[test]
fn run_selected_pending_output_stops_both_phases_without_retry() {
    let artifacts = RunDirectory::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let manifest = synthetic_manifest(root);
    let pending = synthetic_suite(
        "pending",
        &["/bin/sh", "-c", "printf '[PENDING] result not proven\\n'"],
        "proof",
    );
    let later = synthetic_suite("later", &["/bin/sh", "-c", "printf proof"], "proof");

    assert_eq!(
        run_selected(
            &manifest,
            &[pending, later],
            "run-pending-command-contract",
            &artifacts.0,
            true,
        )
        .unwrap(),
        1
    );
    let report = read_report(&artifacts.0, "run-pending-command-contract");
    assert_eq!(report["status"], "PENDING");
    assert_eq!(report["retries"], 0);
    assert_eq!(report["item_results"][0]["status"], "PENDING");
    assert_eq!(report["item_results"][1]["status"], "BLOCKED");
    assert_eq!(report["results"][0]["status"], "BLOCKED");
    assert_eq!(report["results"][1]["status"], "BLOCKED");
    assert_eq!(report["stopped_at"]["phase"], "items");
}

#[test]
fn run_selected_collection_failure_blocks_later_targets_after_items_pass() {
    let artifacts = RunDirectory::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let manifest = synthetic_manifest(root);
    let suites = vec![
        synthetic_suite("one", &["/bin/sh", "-c", "printf proof"], "proof"),
        synthetic_suite("two", &["/bin/sh", "-c", "printf proof"], "proof"),
    ];
    let calls = std::cell::Cell::new(0usize);

    assert_eq!(
        run_selected_with_runtime(
            &manifest,
            &suites,
            "run-collection-failure-contract",
            &artifacts.0,
            true,
            test_runtime(
                |_| Ok("frozen".into()),
                |_, _, _, _| {
                    let call = calls.get();
                    calls.set(call + 1);
                    let status = if call == 2 { "FAIL" } else { "PASS" };
                    Ok(json!({"status":status,"reason":"synthetic phase result"}))
                },
            ),
        )
        .unwrap(),
        1
    );

    let report = read_report(&artifacts.0, "run-collection-failure-contract");
    assert_eq!(calls.get(), 3);
    assert_eq!(report["item_results"][0]["status"], "PASS");
    assert_eq!(report["item_results"][1]["status"], "PASS");
    assert_eq!(report["results"][0]["status"], "FAIL");
    assert_eq!(report["results"][1]["status"], "BLOCKED");
    assert_eq!(report["stopped_at"]["phase"], "collection");
}

#[test]
fn run_selected_fresh_run_reexecutes_the_original_full_selection() {
    let artifacts = RunDirectory::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let manifest = synthetic_manifest(root);
    let suites = vec![
        synthetic_suite("one", &["/bin/sh", "-c", "printf proof"], "proof"),
        synthetic_suite("two", &["/bin/sh", "-c", "printf proof"], "proof"),
    ];
    let first_calls = std::cell::Cell::new(0usize);
    assert_eq!(
        run_selected_with_runtime(
            &manifest,
            &suites,
            "first-full-run",
            &artifacts.0,
            false,
            test_runtime(
                |_| Ok("frozen".into()),
                |_, _, _, _| {
                    first_calls.set(first_calls.get() + 1);
                    Ok(json!({"status":"FAIL","reason":"synthetic first-run failure"}))
                },
            ),
        )
        .unwrap(),
        1
    );
    assert_eq!(first_calls.get(), 1);

    let second_targets = std::cell::RefCell::new(Vec::new());
    assert_eq!(
        run_selected_with_runtime(
            &manifest,
            &suites,
            "fresh-full-run",
            &artifacts.0,
            false,
            test_runtime(
                |_| Ok("frozen".into()),
                |suite, _, _, _| {
                    second_targets.borrow_mut().push(suite_id(suite));
                    Ok(json!({"status":"PASS","reason":"synthetic reconciled result"}))
                },
            ),
        )
        .unwrap(),
        0
    );
    assert_eq!(second_targets.into_inner(), vec!["one", "two"]);
    assert_eq!(
        read_report(&artifacts.0, "first-full-run")["results"][1]["status"],
        "BLOCKED"
    );
    assert_eq!(
        read_report(&artifacts.0, "fresh-full-run")["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|record| record["status"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec!["PASS", "PASS"]
    );
}

#[test]
fn run_selected_refuses_run_id_collision_and_invalid_artifact_scope() {
    let artifacts = RunDirectory::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let manifest = synthetic_manifest(root);
    let suite = synthetic_suite("local", &["/bin/sh", "-c", "printf proof"], "proof");
    fs::create_dir(artifacts.0.join("existing-run")).unwrap();
    assert!(run_selected(
        &manifest,
        std::slice::from_ref(&suite),
        "existing-run",
        &artifacts.0,
        false
    )
    .is_err());
    assert!(run_selected(
        &manifest,
        std::slice::from_ref(&suite),
        "../escape",
        &artifacts.0,
        false
    )
    .is_err());
    assert!(run_selected(&manifest, &[suite], "workspace-artifacts", root, false).is_err());
    assert!(!root.join("workspace-artifacts").exists());
}
