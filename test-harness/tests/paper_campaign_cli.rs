use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output};
use test_harness::campaign::{
    classify_output, prepare_environment, read_manifest, scrub_log, select_suites,
};

#[path = "../../tests-suite/src/paper_mysql_scope.rs"]
mod mysql_scope;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
}

fn list(args: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_test-campaign"))
        .current_dir(std::env::temp_dir())
        .args(["--paper", "--list"])
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    serde_json::from_slice(&output.stdout).unwrap()
}

fn selected(plan: &Value) -> Vec<&Value> {
    plan["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|item| item["selected"] == true)
        .collect()
}

#[test]
fn default_paper_plan_is_offline_core_and_discloses_missing_evidence() {
    let plan = list(&[]);
    let suites = selected(&plan);
    assert_eq!(suites.len(), 11);
    assert!(suites.iter().all(|item| item["lane"] == "core"));
    assert!(suites
        .iter()
        .any(|item| item["id"] == "paper-composed-mediation"));
    assert!(suites
        .iter()
        .any(|item| item["id"] == "paper-journal-witnesses"));
    assert!(plan["unavailable"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["id"] == "historical-http-ab" && item["status"] == "BLOCKED"));
}

#[test]
fn opt_ins_are_scoped_by_track_and_full_repair_is_separate() {
    let plan = list(&["--track", "usenix", "--all-local"]);
    let suites = selected(&plan);
    assert!(suites.iter().all(|item| item["track"] != "cose"));
    assert!(suites.iter().all(|item| item["lane"] != "mysql"));
    for lane in ["controls", "heavy", "performance", "loopback"] {
        assert!(suites.iter().any(|item| item["lane"] == lane));
    }
    let plan = list(&["--track", "cose", "--all-local"]);
    let suites = selected(&plan);
    assert!(suites.iter().all(|item| item["track"] != "usenix"));
    assert!(suites.iter().all(|item| item["lane"] != "repair"));
    let plan = list(&["--track", "cose", "--repair-full"]);
    assert!(selected(&plan).iter().any(|item| item["lane"] == "repair"));
}

#[test]
fn broad_campaigns_do_not_dispatch_paper_opt_ins() {
    let manifest = read_manifest(root()).unwrap();
    for all_profiles in [false, true] {
        let suites = select_suites(&manifest, &[], &[], &[], true, all_profiles).unwrap();
        assert!(suites.iter().all(|suite| suite.get("paper_lane").is_none()));
    }
}

#[test]
fn paper_environment_and_result_gate_fail_closed() {
    let manifest = read_manifest(root()).unwrap();
    let suite = manifest
        .suites
        .iter()
        .find(|suite| {
            suite.get("id").and_then(toml::Value::as_str) == Some("paper-http-expanded-registry")
        })
        .unwrap();
    let (env, problem) = prepare_environment(
        suite,
        &[
            ("PATH".into(), "toolchain".into()),
            ("DATABASE_URL".into(), "not forwarded".into()),
            ("RUST_INTEGRATION_REQUIRED".into(), "1".into()),
            ("ASTRAL_MEMORY_V1_STRESS_CHILD".into(), "1".into()),
            ("ASTRAL_MEMORY_V1_ALLOW_CURVE".into(), "0".into()),
        ],
    );
    assert!(problem.is_none(), "{problem:?}");
    for name in [
        "DATABASE_URL",
        "RUST_INTEGRATION_REQUIRED",
        "ASTRAL_MEMORY_V1_STRESS_CHILD",
    ] {
        assert!(!env.contains_key(std::ffi::OsStr::new(name)));
    }
    assert_eq!(
        env[std::ffi::OsStr::new("ASTRAL_MEMORY_V1_ALLOW_CURVE")],
        "128"
    );
    let summary = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 18 filtered out";
    assert_eq!(
        classify_output(suite, 0, summary, "", false)["status"],
        "FAIL"
    );
    let rows = (0..3).flat_map(|round| {
        [false, true].into_iter().flat_map(move |keep_alive| {
            [1, 4, 16].into_iter().map(move |workers| format!(
                "allow_read extra_resources=128 keep_alive={keep_alive} workers={workers} round={round}\n"
            ))
        })
    }).collect::<String>();
    let rows = format!("test paper_fixture ... {rows}");
    let duplicate = "allow_read extra_resources=128 keep_alive=true workers=1 round=0\n".repeat(18);
    assert_eq!(
        classify_output(suite, 0, summary, &duplicate, false)["status"],
        "FAIL"
    );
    assert_eq!(
        classify_output(suite, 0, summary, &rows, false)["status"],
        "PASS"
    );
    assert_eq!(
        classify_output(suite, 0, summary, "[SKIP] no listener", false)["status"],
        "SKIP"
    );
    assert_eq!(
        classify_output(suite, 0, summary, &rows, true)["status"],
        "UNKNOWN"
    );
}

fn launch(args: &[&str], env: &[(&str, &str)]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_test-campaign"))
        .current_dir(std::env::temp_dir())
        .env_clear()
        .envs(env.iter().copied())
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn mysql_lane_has_an_explicit_plan_and_rejects_incompatible_options() {
    let plan = list(&["--mysql"]);
    let suites = selected(&plan);
    assert_eq!(suites.len(), 1);
    assert_eq!(suites[0]["id"], "paper-usenix-mysql");
    assert_eq!(suites[0]["track"], "usenix");
    for (args, expected) in [
        (&["--paper", "--mysql"][..], "explicit --run-id"),
        (
            &["--paper", "--mysql", "--run-id", "Not_A_Run"][..],
            "lowercase",
        ),
        (
            &["--paper", "--mysql", "--all-local"][..],
            "separate USENIX-only",
        ),
        (
            &["--paper", "--mysql", "--track", "cose"][..],
            "separate USENIX-only",
        ),
    ] {
        let output = launch(args, &[]);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains(expected));
    }
}

#[test]
fn mysql_scope_accepts_only_the_literal_same_run_target() {
    let id = "contract_01";
    let schema = mysql_scope::schema_name(id).unwrap();
    let host = std::net::Ipv4Addr::LOCALHOST;
    let address = format!("{host}:{}", mysql_scope::PORT);
    let valid = format!("mysql://paper_fixture@{address}/{schema}");
    let validate = |raw: &str, approved: &str| {
        mysql_scope::validate(&url::Url::parse(raw).unwrap(), id, approved)
    };
    assert_eq!(validate(&valid, id), Ok(schema.clone()));
    assert!(validate(&valid, "wrong_run").is_err());
    for bad in [
        format!(
            "mysql://paper_fixture@localhost:{}/{schema}",
            mysql_scope::PORT
        ),
        format!("mysql://paper_fixture@{host}:3306/{schema}"),
        format!("mysql://root@{address}/{schema}"),
        format!("mysql://%72oot@{address}/{schema}"),
        format!("mysql://paper_fixture@{address}/astral_rehearsal_paper_wrong_run"),
        format!("{valid}?socket=other"),
        format!("{valid}#fragment"),
    ] {
        assert!(validate(&bad, id).is_err());
    }
    for id in [
        "",
        "1run",
        "Up",
        "hy-phen",
        "name/part",
        "超过",
        "a12345678901234567890123456789012",
    ] {
        assert!(mysql_scope::schema_name(id).is_err());
    }
}

#[test]
fn mysql_dispatch_is_blocked_before_cargo_without_dedicated_approval() {
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let scratch = Scratch(
        std::env::temp_dir().join(format!("paper-mysql-contract-{}", uuid::Uuid::new_v4())),
    );
    std::fs::create_dir(&scratch.0).unwrap();
    let base = scratch.0.to_str().unwrap();
    let address = format!("{}:{}", std::net::Ipv4Addr::LOCALHOST, mysql_scope::PORT);
    let raw = format!(
        "mysql://paper_fixture:private_fixture_value@{address}/astral_rehearsal_paper_wrong_scope"
    );
    for (id, generic, env, reason) in [
        (
            "no_approval",
            false,
            vec![
                ("DATABASE_URL", raw.as_str()),
                ("ASTRAL_MEMORY_V1_E2E_ADMIN_URL", raw.as_str()),
                (mysql_scope::RUN_ENV, "no_approval"),
            ],
            "missing operator approval",
        ),
        (
            "no_url",
            false,
            vec![
                (mysql_scope::APPROVAL_ENV, "no_url"),
                ("DATABASE_URL", raw.as_str()),
            ],
            "missing dedicated paper MySQL fixture URL",
        ),
        (
            "wrong_scope",
            false,
            vec![
                (mysql_scope::APPROVAL_ENV, "different_run"),
                (mysql_scope::URL_ENV, raw.as_str()),
            ],
            "operator approval must match",
        ),
        (
            "wrong_schema",
            false,
            vec![
                (mysql_scope::APPROVAL_ENV, "wrong_schema"),
                (mysql_scope::URL_ENV, raw.as_str()),
            ],
            "name exactly the run-scoped schema",
        ),
        (
            "generic",
            true,
            vec![
                (mysql_scope::APPROVAL_ENV, "generic"),
                (mysql_scope::URL_ENV, raw.as_str()),
            ],
            "not a generic suite run",
        ),
    ] {
        let mut args = if generic {
            vec!["--run", "--suite", "paper-usenix-mysql"]
        } else {
            vec!["--paper", "--mysql"]
        };
        args.extend(["--run-id", id, "--artifact-root", base]);
        // Git is needed for source freeze; Cargo must not be dispatched.
        let path = std::env::var("PATH").unwrap();
        let mut env = env;
        env.push(("PATH", &path));
        let output = launch(&args, &env);
        assert!(!output.status.success(), "unexpected successful dispatch");
        let evidence = std::fs::read_to_string(scratch.0.join(id).join("result.json")).unwrap();
        assert!(!evidence.contains("private_fixture_value"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("private_fixture_value"));
        let evidence: Value = serde_json::from_str(&evidence).unwrap();
        assert_eq!(evidence["status"], "BLOCKED");
        assert_eq!(evidence["preflight"]["status"], "BLOCKED");
        let result = &evidence["results"][0];
        let reason = if cfg!(unix) || generic {
            reason
        } else {
            "requires Unix"
        };
        assert!(result["reason"].as_str().unwrap().contains(reason));
        for field in ["exit_code", "started_at", "stdout", "stderr"] {
            assert!(result[field].is_null());
        }
    }
    assert_eq!(
        scrub_log(&raw, &[(mysql_scope::URL_ENV.into(), raw.clone().into())]),
        "[redacted]"
    );
}

#[test]
fn mysql_result_requires_ordered_postconditions_in_addition_to_libtest_pass() {
    let manifest = read_manifest(root()).unwrap();
    let suite = manifest
        .suites
        .iter()
        .find(|suite| suite["id"].as_str() == Some("paper-usenix-mysql"))
        .unwrap();
    let supplied = [
        (mysql_scope::URL_ENV.into(), "ambient URL".into()),
        (mysql_scope::APPROVAL_ENV.into(), "ambient approval".into()),
        (mysql_scope::RUN_ENV.into(), "ambient run".into()),
        (mysql_scope::BUNDLE_ENV.into(), "ambient directory".into()),
        (
            mysql_scope::PREPARE_ENV.into(),
            "ambient preparation".into(),
        ),
    ];
    for suite in [suite, &manifest.suites[0]] {
        let (env, _) = prepare_environment(suite, &supplied);
        for name in [
            mysql_scope::URL_ENV,
            mysql_scope::APPROVAL_ENV,
            mysql_scope::RUN_ENV,
            mysql_scope::BUNDLE_ENV,
            mysql_scope::PREPARE_ENV,
        ] {
            assert!(!env.contains_key(std::ffi::OsStr::new(name)));
        }
    }
    let summary = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out";
    let verdict = |code, markers: &str, stderr, interrupt| {
        classify_output(
            suite,
            code,
            &format!("{markers}\n{summary}"),
            stderr,
            interrupt,
        )
    };
    let snapshot = "test paper_mysql::cold_snapshot_and_warm_governance ... paper-mysql: snapshot_exact rows=23\n";
    let cold = "paper-mysql: cold_release\n";
    let warm = "paper-mysql: warm_publications\n";
    let retained = "paper-mysql: retained_unchanged\n";
    assert_eq!(verdict(0, "", "", false)["status"], "FAIL");
    assert_eq!(
        verdict(0, &format!("{snapshot}{warm}{cold}{retained}"), "", false)["status"],
        "FAIL"
    );
    let markers = format!("{snapshot}{cold}{warm}{retained}");
    assert_eq!(verdict(0, &markers, "", false)["status"], "PASS");
    assert_eq!(
        verdict(0, &format!("{markers}{retained}"), "", false)["status"],
        "FAIL"
    );
    assert_eq!(
        verdict(1, snapshot, "[UNKNOWN] commit not acknowledged", false)["status"],
        "UNKNOWN"
    );
    assert_eq!(verdict(0, &markers, "", true)["status"], "UNKNOWN");
}
