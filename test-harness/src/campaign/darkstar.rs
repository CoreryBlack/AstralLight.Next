//! Unified DarkStar inventory and evidence bundle; reuses the native campaign runner.

use super::{
    env, json, paper, read_manifest, run_selected_with_runtime, safe_id, snapshot_hash,
    string_array, suite_id, validate_artifact_root, Manifest, Options, SelectedRuntime, TomlValue,
    Value,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SERIES: &str = "DarkStar-Papers";
const APPROVAL: &str = "ASTRAL_DARKSTAR_MYSQL_APPROVED_RUN";
const APPLY_URL: &str = "ASTRAL_MEMORY_V1_APPLY_TEST_MYSQL_URL";
const COLD_URL: &str = "ASTRAL_DARKSTAR_COLD_MYSQL_URL";
const E2E_URL: &str = "ASTRAL_MEMORY_V1_E2E_ADMIN_URL";
const REQUIRED: &str = "RUST_INTEGRATION_REQUIRED";
const RUN: &str = "ASTRAL_DARKSTAR_INTERNAL_RUN";
const ENV_SETTINGS: &[&str] = &[
    "ASTRAL_MEMORY_V1_LOGIN_CURVE",
    "ASTRAL_MEMORY_V1_LOGIN_CURVE_ROUNDS",
    "ASTRAL_MEMORY_V1_SOAK_HOURS",
    "MEMORY_V1_MIXED_LOAD_FENCE_MODE",
];
const CATALOG: &str = include_str!("darkstar.toml");

pub const DARKSTAR_USAGE: &str = "DarkStar current-source campaign\n\
Usage: bash scripts/run-darkstar-tests.sh [--list] [--mysql] [--run-id ID] [--artifact-root PATH] [--suite ID]...\n\
Default: all registered offline, loopback and performance checks. --mysql adds the approved\n\
run-scoped MySQL fixtures, including the binary E2E; never provisions or targets production.\n\
--suite ID repeats to select an explicit subset of the enabled plan; ids are exact and unique,\n\
unknown, duplicate or MySQL ids without --mysql are rejected, and the canonical plan order is\n\
kept regardless of argument order. --list never dispatches.\n\
Logs, result.json and a .tar.gz with SHA-256 are written outside the working tree.\n";

struct Settings {
    run_id: String,
    artifact_root: PathBuf,
    list: bool,
    mysql: bool,
    // Explicit repeated --suite ids; parse-time shape and duplicate checks, with
    // plan membership validated once the enabled plan is built.
    suites: Vec<String>,
}

impl Settings {
    fn parse(args: &[String]) -> Result<Self, String> {
        let common = Options::default();
        let mut settings = Self {
            run_id: common.run_id.replacen("test-campaign", "darkstar", 1),
            artifact_root: common.artifact_root,
            list: false,
            mysql: false,
            suites: Vec::new(),
        };
        let mut explicit_run = false;
        let mut args = args.iter();
        while let Some(arg) = args.next() {
            let mut value = || {
                args.next()
                    .ok_or_else(|| format!("missing value for {arg}"))
            };
            match arg.as_str() {
                "--list" => settings.list = true,
                "--mysql" => settings.mysql = true,
                "--run-id" => {
                    settings.run_id = value()?.clone();
                    explicit_run = true;
                }
                "--artifact-root" => settings.artifact_root = value()?.into(),
                "--suite" => {
                    let id = value()?.clone();
                    if !safe_id(&id) {
                        return Err(format!("invalid DarkStar suite id: {id}"));
                    }
                    if settings.suites.contains(&id) {
                        return Err(format!("duplicate DarkStar suite selection: {id}"));
                    }
                    settings.suites.push(id);
                }
                _ => return Err(format!("unknown DarkStar option: {arg}")),
            }
        }
        if !safe_id(&settings.run_id) {
            return Err("invalid DarkStar run id".into());
        }
        if settings.mysql && (explicit_run || !settings.list) {
            if !explicit_run {
                return Err("--mysql requires an explicit --run-id".into());
            }
            paper::mysql_scope::schema_name(&settings.run_id)?;
        }
        Ok(settings)
    }
}

pub(super) fn is_suite(suite: &TomlValue) -> bool {
    suite.get("darkstar_lane").is_some()
}

fn lane(suite: &TomlValue) -> &str {
    suite
        .get("darkstar_lane")
        .and_then(TomlValue::as_str)
        .unwrap_or("")
}

fn provisioned_environment(
    lane: &str,
    run: &str,
    original: &[(OsString, OsString)],
) -> Result<(String, String), String> {
    let lookup = |key: &str| {
        original
            .iter()
            .find(|(name, _)| name == key)
            .and_then(|(_, val)| val.to_str())
    };
    paper::mysql_scope::schema_name(run)?;
    if lookup(APPROVAL) != Some(run) {
        return Err("missing same-run approval for the isolated DarkStar MySQL fixture".into());
    }
    let (key, child_key, username, schema) = match lane {
        "mysql-e2e" => (E2E_URL, E2E_URL, "darkstar_e2e", None),
        "mysql-cold" => (COLD_URL, APPLY_URL, "darkstar_cold", Some("cold")),
        "mysql-apply" => (APPLY_URL, APPLY_URL, "darkstar_apply", Some("apply")),
        _ => return Err("unknown DarkStar MySQL lane".into()),
    };
    let raw = lookup(key).ok_or_else(|| format!("missing {key} for the isolated fixture"))?;
    let url = url::Url::parse(raw).map_err(|_| format!("invalid {key}"))?;
    let exact_path = match schema {
        Some(schema) => url.path() == format!("/astral_rehearsal_{schema}_{run}"),
        None => matches!(url.path(), "" | "/"),
    };
    if url.scheme() != "mysql"
        || url.host_str().and_then(|host| host.parse().ok()) != Some(Ipv4Addr::LOCALHOST)
        || url.port() != Some(paper::mysql_scope::PORT)
        || url.password().is_none_or(str::is_empty)
        || url.query().is_some()
        || url.fragment().is_some()
        || url.username() != username
        || !exact_path
    {
        return Err(format!(
            "{key} does not name the approved loopback test account and schema"
        ));
    }
    Ok((child_key.to_owned(), raw.to_owned()))
}

pub(super) fn environment(
    suite: &TomlValue,
    original: &[(OsString, OsString)],
) -> (BTreeMap<OsString, OsString>, Option<String>) {
    let mut child = paper::clean_environment(original);
    if let Some(settings) = suite.get("darkstar_env").and_then(TomlValue::as_table) {
        for (key, value) in settings {
            if !ENV_SETTINGS.contains(&key.as_str()) || value.as_str().is_none() {
                return (child, Some("unexpected DarkStar fixture setting".into()));
            }
            child.insert(key.into(), value.as_str().unwrap().into());
        }
    }
    if lane(suite).starts_with("mysql-") {
        let Some(run) = original
            .iter()
            .find(|(name, _)| name == RUN)
            .and_then(|(_, value)| value.to_str())
        else {
            return (
                child,
                Some("MySQL requires explicit DarkStar --mysql selection".into()),
            );
        };
        match provisioned_environment(lane(suite), run, original) {
            Ok((key, value)) => {
                child.insert(key.into(), value.into());
                child.insert(REQUIRED.into(), "1".into());
            }
            Err(error) => return (child, Some(error)),
        }
    }
    (child, None)
}

pub(super) fn fixture_settings(
    child: &BTreeMap<OsString, OsString>,
) -> BTreeMap<&'static str, String> {
    ENV_SETTINGS
        .iter()
        .filter_map(|&key| {
            child
                .get(std::ffi::OsStr::new(key))?
                .to_str()
                .map(|value| (key, value.to_owned()))
        })
        .collect()
}

pub(super) fn loopback_preflight(suite: &TomlValue) -> Option<String> {
    if !is_suite(suite) || !(lane(suite) == "loopback" || lane(suite).starts_with("mysql-")) {
        return None;
    }
    if !cfg!(unix) {
        return Some("DarkStar process fixtures require Unix file modes and signals".into());
    }
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .err()
        .map(|error| format!("loopback TCP preflight: {error}"))
}

pub(super) fn check_evidence(suite: &TomlValue, output: &str, result: &Value) -> Option<Value> {
    // Only an already proven PASS is auditable. UNKNOWN, BLOCKED and PENDING
    // stay unproven, and FAIL and SKIP keep their verdict, so an inner
    // `outcome=SKIP...` line can never rescue a failing or interrupted suite,
    // while a bare PASS can never hide skipped measurement sizes.
    if !is_suite(suite) || result["status"] != "PASS" {
        return None;
    }
    if output.lines().any(|line| line.contains("outcome=SKIP")) {
        let mut result = result.clone();
        result["status"] = json!("SKIP");
        result["reason"] = json!("one or more DarkStar measurement sizes were skipped");
        return Some(result);
    }
    if let Some(required) = suite
        .get("darkstar_postcondition")
        .and_then(TomlValue::as_str)
    {
        if output
            .lines()
            .filter(|line| line.contains(required))
            .count()
            != 1
        {
            let mut result = result.clone();
            result["status"] = json!("FAIL");
            result["reason"] = json!("missing or duplicate DarkStar postcondition output");
            return Some(result);
        }
    }
    let contract = suite.get("darkstar_evidence")?.as_str()?;
    let scenario = match contract {
        "synthetic-paper-warm-governance" => Some("paper-warm-governance"),
        "synthetic-binary-lifecycle" => Some("binary-lifecycle"),
        "synthetic-writer-contention" => Some("writer-contention"),
        _ => None,
    };
    if let Some(scenario) = scenario {
        let markers = output
            .lines()
            .filter_map(|line| line.trim().strip_prefix("synthetic_evidence scenario="))
            .collect::<Vec<_>>();
        let mut result = result.clone();
        if markers.as_slice() == [scenario] {
            result["synthetic_evidence"] = json!({"scenario":scenario});
        } else {
            result["status"] = json!("FAIL");
            result["reason"] = json!("missing, unexpected or duplicate synthetic evidence marker");
        }
        return Some(result);
    }
    let expected = match contract {
        "mixed" => ("memory—v1 mixed_load fence_mode=", 1),
        "login" => ("login_curve ", 52),
        "contention" => ("session_contention live=", 6),
        "recovery" => ("[perf-summary] size=", 3),
        _ => return Some(json!({"status":"FAIL", "reason":"unknown DarkStar evidence contract"})),
    };
    let rows = output
        .lines()
        .filter_map(|line| line.split_once(expected.0))
        .map(|(_, row)| row)
        .collect::<Vec<_>>();
    let unique = match contract {
        "login" => rows
            .iter()
            .filter_map(|row| {
                let value = serde_json::from_str::<Value>(row).ok()?;
                Some(format!(
                    "{}:{}:{}:{}",
                    value["round"].as_u64()?,
                    value["readers"].as_u64()?,
                    value["logins"].as_u64()?,
                    value["class"].as_str()?
                ))
            })
            .collect::<BTreeSet<_>>()
            .len(),
        "contention" => rows
            .iter()
            .filter_map(|row| {
                row.split_whitespace()
                    .take(2)
                    .collect::<Vec<_>>()
                    .get(..2)
                    .map(|key| key.join(" "))
            })
            .collect::<BTreeSet<_>>()
            .len(),
        _ => rows
            .iter()
            .filter_map(|row| row.split_whitespace().next())
            .collect::<BTreeSet<_>>()
            .len(),
    };
    let mut result = result.clone();
    result["measurement"] =
        json!({"rows":rows.len(), "expected_rows":expected.1, "unique_cells":unique});
    if rows.len() != expected.1 || unique != expected.1 {
        result["status"] = json!("FAIL");
        result["reason"] = json!("incomplete or duplicate DarkStar measurement cells");
    }
    Some(result)
}

/// Restrict a fully built plan to the operator's explicit repeated `--suite`
/// ids. Every id must be an exact member of the enabled plan; a known
/// MySQL-gated id without the approved `--mysql` opt-in is rejected instead of
/// being silently skipped, and unknown ids (including manifest suites outside
/// the DarkStar plan) are rejected. The canonical plan order — offline cut,
/// MySQL suites, the exploratory repair model strictly last — is preserved
/// regardless of the order the ids were given, and the plan records the
/// explicit selection for evidence.
fn apply_explicit_selection(
    suites: &mut Vec<TomlValue>,
    plan: &mut Value,
    explicit: &[String],
) -> Result<(), String> {
    if explicit.is_empty() {
        return Ok(());
    }
    let gated = plan["excluded"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry["id"].as_str())
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let enabled = suites.iter().map(suite_id).collect::<BTreeSet<_>>();
    for id in explicit {
        if enabled.contains(id) {
            continue;
        }
        if gated.contains(id) {
            return Err(format!(
                "DarkStar suite {id} requires --mysql; the approved run-scoped opt-in is not selected"
            ));
        }
        return Err(format!("unknown DarkStar suite: {id}"));
    }
    let keep = explicit.iter().map(String::as_str).collect::<BTreeSet<_>>();
    suites.retain(|suite| keep.contains(suite_id(suite).as_str()));
    if let Some(items) = plan.get_mut("items").and_then(Value::as_array_mut) {
        items.retain(|item| keep.contains(item["id"].as_str().unwrap_or_default()));
    }
    plan["explicit_selection"] = json!(explicit);
    Ok(())
}

/// DarkStar-only build override for the unbounded full-bounds repair model: a
/// pure current-source exploration inside the `test-harness` crate that is
/// otherwise memory- and time-bound at opt-level 0. Cargo `--config` overrides
/// explicitly pin, per package, the optimization level plus debug assertions
/// and overflow checks, so the assertions stay enforced even if the workspace
/// dev profile later changes. The pairs are inserted ahead of the libtest `--`
/// separator so cargo consumes them, and the paper runner keeps the manifest
/// argv unchanged.
fn repair_model_build_override(suite: &mut TomlValue) -> Result<(), String> {
    const OVERRIDES: [&str; 3] = [
        "profile.dev.package.test-harness.opt-level=2",
        "profile.dev.package.test-harness.debug-assertions=true",
        "profile.dev.package.test-harness.overflow-checks=true",
    ];
    let argv = suite
        .get_mut("argv")
        .and_then(TomlValue::as_array_mut)
        .ok_or("missing repair model argv")?;
    if argv.iter().any(|arg| arg.as_str() == Some(OVERRIDES[0])) {
        return Err("duplicate DarkStar repair model build override".into());
    }
    let position = argv
        .iter()
        .position(|arg| arg.as_str() == Some("--"))
        .ok_or("missing libtest separator in repair model argv")?;
    let inserted = OVERRIDES
        .iter()
        .flat_map(|pair| ["--config".to_owned(), (*pair).to_owned()])
        .collect::<Vec<_>>()
        .into_iter()
        .map(TomlValue::String)
        .collect::<Vec<_>>();
    argv.splice(position..position, inserted);
    Ok(())
}

fn selection(
    manifest: &mut Manifest,
    include_mysql: bool,
    explicit: &[String],
) -> Result<(Vec<TomlValue>, Value), String> {
    let (paper_ids, paper_plan) = paper::all_darkstar_suites(manifest)?;
    let mut suites = Vec::new();
    let mut excluded = Vec::new();
    for suite in &manifest.suites {
        let id = suite_id(suite);
        if paper_ids.contains(&id)
            || matches!(
                id.as_str(),
                "paper-runner-contracts"
                    | "scale-memory-v1-500k"
                    | "memory-v1-request-chain-candidate"
                    | "trustgraph-memory-v1-permission-chain"
            )
        {
            if paper::is_mysql_suite(suite) && !include_mysql {
                excluded.push(json!({"id":id,"status":"SKIP","reason":"requires --mysql"}));
            } else {
                let mut suite = suite.clone();
                // Current-source controls can add tests, but cannot shrink below the paper cut.
                let current_controls = matches!(
                    id.as_str(),
                    "paper-current-root-controls"
                        | "paper-current-evaluator-controls"
                        | "paper-current-evaluator-integration-controls"
                        | "paper-ordinary-admission"
                        | "paper-journal-witnesses"
                        | "paper-journal-controls"
                );
                if current_controls {
                    let table = suite
                        .as_table_mut()
                        .ok_or("invalid current control suite")?;
                    let minimum = table
                        .remove("expected_tests")
                        .ok_or("missing control test count")?;
                    table.insert("minimum_tests".into(), minimum);
                    table.insert("darkstar_lane".into(), "core".into());
                }
                let extra_skip = match id.as_str() {
                    "paper-current-root-controls" => Some("login_contention_at_live_session_scale"),
                    "paper-journal-controls" => Some("local_release_checkpoint_curve"),
                    _ => None,
                };
                if let Some(extra_skip) = extra_skip {
                    let argv = suite
                        .get_mut("argv")
                        .and_then(TomlValue::as_array_mut)
                        .ok_or("missing paper control argv")?;
                    argv.extend(["--skip".into(), extra_skip.into()]);
                }
                if id == "paper-repair-full-bounds" {
                    repair_model_build_override(&mut suite)?;
                }
                if !paper::is_paper_suite(&suite) {
                    suite
                        .as_table_mut()
                        .ok_or("invalid reused DarkStar suite")?
                        .insert("darkstar_lane".into(), "core".into());
                }
                suites.push(suite);
            }
        }
    }
    let extra: TomlValue =
        toml::from_str(CATALOG).map_err(|error| format!("invalid DarkStar catalog: {error}"))?;
    let mut seen = manifest
        .suites
        .iter()
        .map(suite_id)
        .collect::<BTreeSet<_>>();
    for item in extra
        .get("case")
        .and_then(TomlValue::as_array)
        .ok_or("missing DarkStar cases")?
    {
        let id = suite_id(item);
        if !safe_id(&id)
            || !seen.insert(id.clone())
            || !matches!(
                lane(item),
                "core" | "performance" | "loopback" | "mysql-apply" | "mysql-cold" | "mysql-e2e"
            )
        {
            return Err(format!("invalid or duplicate DarkStar case: {id}"));
        }
        let mut suite = item.as_table().ok_or("invalid DarkStar case")?.clone();
        let cargo_args = string_array(item, "args")?;
        let Some(operation @ ("test" | "bench")) = cargo_args.first().map(String::as_str) else {
            return Err(format!("non-test operation in DarkStar case: {id}"));
        };
        if cargo_args
            .iter()
            .any(|arg| arg.contains("://") || arg == "--manifest-path")
        {
            return Err(format!("out-of-scope argv in DarkStar case: {id}"));
        }
        let mut argv = vec!["cargo", operation, "--offline", "--locked"];
        argv.extend(cargo_args[1..].iter().map(String::as_str));
        let mysql = lane(item).starts_with("mysql-");
        suite.remove("args");
        suite.insert(
            "argv".into(),
            TomlValue::try_from(argv).map_err(|error| error.to_string())?,
        );
        suite.insert(
            "owner".into(),
            cargo_args
                .windows(2)
                .find(|args| args[0] == "-p")
                .map(|args| args[1].clone())
                .ok_or("missing DarkStar package")?
                .into(),
        );
        suite.insert(
            "profile".into(),
            if mysql {
                "native-single-node"
            } else {
                "native-kernel"
            }
            .into(),
        );
        suite.insert(
            "scope".into(),
            if mysql || lane(item) == "loopback" {
                "integration"
            } else {
                "component"
            }
            .into(),
        );
        suite.insert(
            "series".into(),
            TomlValue::try_from([SERIES]).map_err(|error| error.to_string())?,
        );
        suite.insert(
            "test_services".into(),
            TomlValue::try_from(if mysql { vec!["mysql"] } else { vec![] })
                .map_err(|error| error.to_string())?,
        );
        suite.insert(
            "boundary".into(),
            item.get("boundary").cloned().unwrap_or_else(|| {
                "Current-source Rust fixture; not a production deployment proof.".into()
            }),
        );
        suite.entry("acceptance").or_insert_with(|| "rust".into());
        suite
            .entry("timeout_seconds")
            .or_insert(TomlValue::Integer(1200));
        let explicit_only = suite
            .remove("explicit_only")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        let suite = TomlValue::Table(suite);
        manifest.suites.push(suite.clone());
        if mysql && !include_mysql {
            excluded.push(json!({"id":id,"status":"SKIP","reason":"requires --mysql"}));
        } else if explicit_only && !explicit.contains(&id) {
            excluded.push(json!({"id":id,"status":"SKIP","reason":"requires explicit --suite"}));
        } else {
            suites.push(suite);
        }
    }
    // Run the unbounded-in-memory (but time-limited) exploratory model last.
    suites.sort_by_key(|suite| {
        if suite_id(suite) == "paper-repair-full-bounds" {
            2
        } else if paper::is_mysql_suite(suite) || lane(suite).starts_with("mysql-") {
            1
        } else {
            0
        }
    });
    let mut plan = json!({
        "scope":"DarkStar current-source Rust suites; no production or historical acceptance",
        "items":suites.iter().map(|suite| json!({"id":suite_id(suite),"argv":suite.get("argv"),"test_services":suite.get("test_services"),"boundary":suite.get("boundary")})).collect::<Vec<_>>(),
        "excluded":excluded,
        "not_current_darkstar":["standalone legacy MySQL/RabbitMQ and Redis profiles", "archived V6/V7/S15 and Docker legacy gates", "independent SDK examples and legacy HTTP/engine benchmarks", "external TLA+/TLC toolchain"],
        "historical_boundaries":paper_plan["unavailable"],
    });
    apply_explicit_selection(&mut suites, &mut plan, explicit)?;
    Ok((suites, plan))
}

fn hash(path: &Path) -> Result<String, String> {
    let mut input =
        File::open(path).map_err(|error| format!("open evidence for checksum: {error}"))?;
    let mut digest = Sha256::new();
    io::copy(&mut input, &mut digest)
        .map_err(|error| format!("read evidence for checksum: {error}"))?;
    Ok(format!("{:x}", digest.finalize()))
}

fn bundle(directory: &Path, run: &str) -> Result<PathBuf, String> {
    let parent = directory.parent().ok_or("missing artifact parent")?;
    let report_path = directory.join("result.json");
    let report: Value = serde_json::from_slice(
        &fs::read(&report_path).map_err(|error| format!("read DarkStar report: {error}"))?,
    )
    .map_err(|error| format!("parse DarkStar report: {error}"))?;
    let mut names = vec![PathBuf::from("result.json")];
    let mut withheld = Vec::new();
    for row in report["results"]
        .as_array()
        .ok_or("missing DarkStar results")?
    {
        if row["started_at"].is_null() {
            continue;
        }
        let id = row["id"]
            .as_str()
            .filter(|id| safe_id(id))
            .ok_or("invalid DarkStar evidence id")?;
        for stream in ["stdout", "stderr"] {
            let relative = PathBuf::from("collection").join(format!("{id}.{stream}.log"));
            let expected = row[format!("{stream}_sha256")].as_str();
            let path = directory.join(&relative);
            // A killed drainer may have left unsanitized log files and may still own them.
            if !fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_file())
                || expected.is_none()
                || expected != Some(hash(&path)?.as_str())
            {
                withheld.push(relative);
                continue;
            }
            names.push(relative);
        }
    }
    let inventory = json!({"withheld_unverified_logs":withheld,"included":names});
    super::write_report(&directory.join("bundle-index.json"), &inventory)?;
    names.push(PathBuf::from("bundle-index.json"));
    let mut checksums = String::new();
    for name in &names {
        checksums.push_str(&format!(
            "{}  {}\n",
            hash(&directory.join(name))?,
            name.display()
        ));
    }
    fs::write(directory.join("SHA256SUMS"), checksums)
        .map_err(|error| format!("write evidence checksums: {error}"))?;
    names.push(PathBuf::from("SHA256SUMS"));
    let archive = parent.join(format!("{run}.tar.gz"));
    let file = File::options()
        .write(true)
        .create_new(true)
        .open(&archive)
        .map_err(|error| format!("reserve DarkStar archive: {error}"))?;
    let status = Command::new("tar")
        .arg("-czf")
        .arg("-")
        .arg("-C")
        .arg(directory)
        .arg("--")
        .args(&names)
        .env_clear()
        .env("PATH", env::var_os("PATH").unwrap_or_default())
        .stdout(Stdio::from(file))
        .status()
        .map_err(|error| format!("start tar: {error}"))?;
    if !status.success() {
        return Err(format!(
            "tar did not complete ({status}); partial archive has no checksum"
        ));
    }
    let checksum = format!("{}  {run}.tar.gz\n", hash(&archive)?);
    use std::io::Write;
    File::options()
        .write(true)
        .create_new(true)
        .open(parent.join(format!("{run}.tar.gz.sha256")))
        .and_then(|mut file| file.write_all(checksum.as_bytes()))
        .map_err(|error| format!("write archive checksum: {error}"))?;
    println!("DarkStar evidence archive: {}", archive.display());
    if !withheld.is_empty() {
        return Err(format!(
            "archive withheld {} logs whose integrity was not proven",
            withheld.len()
        ));
    }
    Ok(archive)
}

pub fn run_darkstar_options(root: &Path, args: &[String]) -> Result<i32, String> {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        print!("{DARKSTAR_USAGE}");
        return Ok(0);
    }
    let settings = Settings::parse(args)?;
    let mut manifest = read_manifest(root)?;
    let (suites, plan) = selection(&mut manifest, settings.mysql, &settings.suites)?;
    if settings.list {
        println!(
            "{}",
            serde_json::to_string_pretty(&plan).map_err(|error| error.to_string())?
        );
        return Ok(0);
    }
    if super::resolve_executable("tar", &env::var("PATH").unwrap_or_default()).is_none() {
        return Err("[BLOCKED] tar is required to package DarkStar evidence".into());
    }
    let parent = validate_artifact_root(&manifest.root, &settings.artifact_root)?;
    let directory = parent.join(&settings.run_id);
    if directory.symlink_metadata().is_ok()
        || parent
            .join(format!("{}.tar.gz", settings.run_id))
            .symlink_metadata()
            .is_ok()
    {
        return Err(
            "[BLOCKED] the DarkStar run id already exists; never overwrite evidence".into(),
        );
    }
    let mut environment = env::vars_os()
        .filter(|(name, _)| {
            name != RUN
                && (settings.mysql
                    || ![
                        paper::mysql_scope::URL_ENV,
                        paper::mysql_scope::APPROVAL_ENV,
                        APPROVAL,
                        APPLY_URL,
                        COLD_URL,
                        E2E_URL,
                    ]
                    .iter()
                    .any(|key| name == *key))
        })
        .collect::<Vec<_>>();
    if settings.mysql {
        environment.push((RUN.into(), settings.run_id.clone().into()));
    }
    #[cfg(unix)]
    let _interrupts = paper::InterruptGuard::install()?;
    let result = run_selected_with_runtime(
        &manifest,
        &suites,
        &settings.run_id,
        &parent,
        false,
        SelectedRuntime {
            environment: &environment,
            snapshot: snapshot_hash,
            execute_command: super::execute,
            paper: None,
            darkstar: Some(plan),
        },
    );
    if directory.join("result.json").is_file() {
        bundle(&directory, &settings.run_id)?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_fixture_never_reuses_the_apply_schema_or_account() {
        let run = "ds_scope";
        let make_url = |user, schema| {
            let mut url = url::Url::parse("mysql://localhost").unwrap();
            url.set_host(Some(&Ipv4Addr::LOCALHOST.to_string()))
                .unwrap();
            url.set_port(Some(paper::mysql_scope::PORT)).unwrap();
            url.set_username(user).unwrap();
            url.set_password(Some("fixture-only")).unwrap();
            url.set_path(schema);
            url.to_string()
        };
        let cold = make_url("darkstar_cold", "/astral_rehearsal_cold_ds_scope");
        let apply = make_url("darkstar_apply", "/astral_rehearsal_apply_ds_scope");
        let mut original = vec![
            (APPROVAL.into(), run.into()),
            (APPLY_URL.into(), apply.clone().into()),
        ];
        assert!(provisioned_environment("mysql-cold", run, &original).is_err());
        original.push((COLD_URL.into(), apply.into()));
        assert!(provisioned_environment("mysql-cold", run, &original).is_err());
        original.last_mut().unwrap().1 = cold.clone().into();
        assert_eq!(
            provisioned_environment("mysql-cold", run, &original).unwrap(),
            (APPLY_URL.into(), cold)
        );
    }

    #[test]
    fn an_internal_measurement_skip_is_not_accepted_as_a_completed_matrix() {
        let suite = toml::from_str("darkstar_lane='performance'").unwrap();
        let verdict = check_evidence(
            &suite,
            "history=4000 outcome=SKIP_EXECUTION_TIME_LIMIT",
            &json!({"status":"PASS"}),
        )
        .unwrap();
        assert_eq!(verdict["status"], "SKIP");
        let unknown = json!({"status":"UNKNOWN"});
        assert!(check_evidence(&suite, "outcome=SKIP", &unknown).is_none());
        let generic = toml::from_str("id='generic'").unwrap();
        assert!(check_evidence(&generic, "outcome=SKIP", &verdict).is_none());
    }

    #[test]
    fn a_terminal_non_pass_verdict_is_never_demoted_by_an_inner_skip() {
        let suite = toml::from_str("darkstar_lane='performance'").unwrap();
        for status in ["FAIL", "UNKNOWN", "BLOCKED", "PENDING", "SKIP"] {
            let verdict = json!({"status":status,"reason":"terminal outcome"});
            assert!(
                check_evidence(
                    &suite,
                    "history=4000 outcome=SKIP_EXECUTION_TIME_LIMIT",
                    &verdict
                )
                .is_none(),
                "{status} must keep its verdict when an inner measurement skipped"
            );
        }
    }

    #[test]
    fn synthetic_evidence_requires_one_matching_marker_after_a_rust_pass() {
        for (contract, scenario, other) in [
            (
                "synthetic-paper-warm-governance",
                "paper-warm-governance",
                "binary-lifecycle",
            ),
            (
                "synthetic-binary-lifecycle",
                "binary-lifecycle",
                "paper-warm-governance",
            ),
        ] {
            let suite = toml::from_str(&format!(
                "darkstar_lane='loopback'\ndarkstar_evidence='{contract}'"
            ))
            .unwrap();
            let pass = json!({"status":"PASS", "passed":1});
            let marker = format!("synthetic_evidence scenario={scenario}");
            let verified = check_evidence(&suite, &marker, &pass).unwrap();
            assert_eq!(verified["status"], "PASS");
            assert_eq!(verified["passed"], 1);
            assert_eq!(verified["synthetic_evidence"]["scenario"], scenario);
            for output in [
                String::new(),
                format!("synthetic_evidence scenario={other}"),
                format!("{marker}\n{marker}"),
                format!("{marker}\nsynthetic_evidence scenario={other}"),
                format!("diagnostic: {marker}"),
            ] {
                let rejected = check_evidence(&suite, &output, &pass).unwrap();
                assert_eq!(rejected["status"], "FAIL", "{output:?}");
                assert!(rejected.get("synthetic_evidence").is_none());
            }
            for status in ["FAIL", "UNKNOWN", "BLOCKED", "PENDING", "SKIP"] {
                assert!(check_evidence(&suite, &marker, &json!({"status":status})).is_none());
            }
        }
    }

    #[test]
    fn a_rust_pass_requires_the_selected_measurement_postcondition() {
        let suite = toml::from_str(
            "darkstar_lane='loopback'\ndarkstar_evidence='synthetic-writer-contention'\ndarkstar_postcondition='writer_contention commit_phases'",
        )
        .unwrap();
        let pass = json!({"status":"PASS", "passed":1});
        let scenario = "synthetic_evidence scenario=writer-contention";
        let phases = "writer_contention commit_phases prepare=count:2";
        for (log, expected) in [
            (scenario.to_owned(), "FAIL"),
            (format!("{phases}\n{phases}\n{scenario}"), "FAIL"),
            (format!("{phases}\n{scenario}"), "PASS"),
        ] {
            assert_eq!(
                check_evidence(&suite, &log, &pass).unwrap()["status"],
                expected
            );
        }
    }

    #[test]
    fn the_repair_model_override_stays_a_valid_paper_dispatch() {
        let mut suite: TomlValue = toml::from_str(
            "id = 'paper-repair-full-bounds'\n\
             paper_track = 'cose'\n\
             paper_lane = 'repair'\n\
             profile = 'offline-validation'\n\
             test_services = []\n\
             selection_policy = 'explicit-suite'\n\
             acceptance = 'rust'\n\
             expected_tests = 1\n\
             argv = ['cargo', 'test', '--locked', '--offline', '-p', 'test-harness', '--test', 'memory_v1_journal_protocol_model', '--', '--ignored', '--exact', 'repair_abort_plus_ordered_publish_full_bounds_has_no_violation', '--nocapture', '--test-threads=1']",
        )
        .unwrap();
        repair_model_build_override(&mut suite).unwrap();
        let argv = suite
            .get("argv")
            .and_then(TomlValue::as_array)
            .unwrap()
            .iter()
            .map(|arg| arg.as_str().unwrap())
            .collect::<Vec<_>>();
        let separator = argv.iter().position(|arg| *arg == "--").unwrap();
        // The pinned cargo config pairs stay ahead of the libtest separator.
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
        // The paper dispatch validator accepts the overridden argv unchanged.
        assert!(paper::environment(&suite, &[]).1.is_none());
        // A second application is refused; the override never double-inserts.
        assert!(repair_model_build_override(&mut suite).is_err());
    }
}
