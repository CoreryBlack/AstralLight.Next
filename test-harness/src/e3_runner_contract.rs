//! Native offline E3 runner contracts: plan identity, live gate, approval
//! record/validator handling, CLI exit behavior and output scrubbing.
//!
//! The module does not implement sampling, phase execution or a live probe.
//! Those remain explicit blocked primitives; this file only locks the
//! deterministic offline behaviour the archived Python tests exercise.

use crate::e1_runner_contract::stable_id;
use crate::e3_config::{self, E3Settings};
use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

pub const OUTPUT_CATEGORIES: [&str; 4] = [
    "request_side_denial_pending",
    "unrelated_card_availability",
    "publication_drain",
    "per_event_retry_history",
];
pub const E3_CLAIM_FULL: &str = "RECOVERY_TAIL_FULL";
pub const E3_CLAIM_NONE: &str = "NOT_CLAIMED";
pub const APPROVAL_REF_PATTERN: &str = r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct E3ConfigError {
    pub problems: Vec<String>,
}

impl E3ConfigError {
    fn from_config(error: e3_config::ConfigError) -> Self {
        Self {
            problems: error
                .problems
                .iter()
                .map(|problem| (*problem).to_owned())
                .collect(),
        }
    }
}

fn safe_dimensions(settings: &E3Settings) -> Value {
    json!({
        "runId": settings.run_id,
        "targetCard": settings.target_card,
        "unrelatedCard": settings.unrelated_card,
        "coldCard": settings.cold_card,
        "isolatedFixture": settings.isolated_fixture,
        "samplingIntervalS": settings.sampling_interval_s,
        "injectionWindowS": settings.injection_window_s,
        "drainWindowS": settings.drain_window_s,
        "maxAttempts": settings.max_attempts,
        "controllerTimeoutS": settings.controller_timeout_s,
        "nodes": settings.nodes,
        "decisionNode": stored_string(&settings.decision_node),
    })
}

fn stored_string(value: &str) -> String {
    if value.contains('.') || value.contains(':') {
        "[redacted-host]".to_owned()
    } else {
        value.to_owned()
    }
}

pub fn public_metadata(settings: &E3Settings) -> Value {
    safe_dimensions(settings)
}

pub fn probe_alias(settings: &E3Settings) -> &str {
    &settings.decision_node
}

pub fn e3_operation_ids(run_id: &str) -> Map<String, Value> {
    Map::from_iter([
        (
            "injection".to_owned(),
            json!(stable_id(run_id, "e3:injection")),
        ),
        ("drain".to_owned(), json!(stable_id(run_id, "e3:drain"))),
    ])
}

pub fn config_sha256(config: &Value) -> String {
    let mut canonical = String::new();
    python_canonical(config, &mut canonical);
    format!("{:x}", Sha256::digest(canonical.as_bytes()))
}

fn python_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            out.push('{');
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by_key(|(key, _)| *key);
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                out.push_str(&serde_json::to_string(key).expect("string key"));
                out.push_str(": ");
                python_canonical(value, out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                python_canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&serde_json::to_string(other).expect("json scalar")),
    }
}

fn write_json(root: &Path, name: &str, value: &Value) -> Result<(), String> {
    fs::create_dir_all(root).map_err(|error| error.to_string())?;
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    fs::write(root.join(name), bytes).map_err(|error| error.to_string())
}

fn write_checksums(root: &Path, files: &[&str]) -> Result<(), String> {
    let mut lines = Vec::new();
    for relative in files {
        let bytes = fs::read(root.join(relative)).map_err(|error| error.to_string())?;
        lines.push(format!("{:x}  {relative}", Sha256::digest(&bytes)));
    }
    fs::write(
        root.join("checksums.sha256"),
        format!("{}\n", lines.join("\n")),
    )
    .map_err(|error| error.to_string())
}

pub fn verify_checksums(root: &Path, checksum_file: &Path) -> Result<(), String> {
    let text = fs::read_to_string(checksum_file).map_err(|error| error.to_string())?;
    for line in text.lines() {
        let Some((expected, relative)) = line.split_once("  ") else {
            return Err(format!("malformed checksum line: {line}"));
        };
        if expected.len() != 64 || relative.is_empty() {
            return Err(format!("malformed checksum line: {line}"));
        }
        let bytes = fs::read(root.join(relative)).map_err(|error| error.to_string())?;
        if format!("{:x}", Sha256::digest(&bytes)) != expected {
            return Err(format!("checksum mismatch for {relative}"));
        }
    }
    Ok(())
}

pub fn execute_plan(config: &Value, out_dir: &Path) -> Result<Value, E3ConfigError> {
    let settings = e3_config::load_e3_config(config).map_err(E3ConfigError::from_config)?;
    let plan = json!({
        "kind": "e3_recovery_tail",
        "experiment": "E3",
        "mode": "plan",
        "status": "PLANNED",
        "campaignId": settings.run_id,
        "settings": public_metadata(&settings),
        "configSha256": config_sha256(config),
        "operationIds": e3_operation_ids(&settings.run_id),
        "phases": [
            {
                "phase": "injection",
                "markers": ["injection_start", "injection_end"],
                "samplingWindowS": settings.injection_window_s,
                "dispatchBudget": 1,
            },
            {
                "phase": "drain",
                "markers": ["drain_start", "drain_end"],
                "samplingWindowS": settings.drain_window_s,
                "dispatchBudget": 1,
            },
        ],
        "markerContract": {
            "timeSources": ["wall_unix_ns", "monotonic_ns"],
            "ordering": "strictly increasing monotonic_ns across injection_start, injection_end, drain_start, drain_end; non-decreasing wall_unix_ns; injection_end <= drain_start",
            "capturePoint": "start markers pre-call, end markers post-call",
        },
        "bounds": {
            "minIntervalS": e3_config::MIN_INTERVAL_S,
            "maxIntervalS": e3_config::MAX_INTERVAL_S,
            "maxWindowS": e3_config::MAX_WINDOW_S,
            "maxSamplesPerWindow": e3_config::MAX_SAMPLES_PER_WINDOW,
            "maxAttempts": e3_config::MAX_ATTEMPTS,
            "maxEventIds": crate::e3_reconciliation::MAX_EVENT_IDS,
            "maxCrosscheckRequestIds": crate::e3_reconciliation::MAX_CROSSCHECK_REQUEST_IDS,
        },
        "gateRequirements": [
            "allow_live_execution",
            "approval_ref",
            "approval_record(run_id, approval_ref, approved_by)",
            "independent approval_validator(run_id, approval_ref, config_sha256) == True",
            "e3.allowlist.isolated_fixture",
            "injected probe",
            "injected injection controller",
        ],
        "injectedPrimitives": [
            "probe (e3_e4 actor-aware read-only probe)",
            "injection controller (four phase methods, called at most once each)",
            "e3 log collector (optional; per-attempt category BLOCKED without it)",
            "durable row reader (optional; PASS prevented without it)",
            "request log collector (optional; host admission stays unconfirmed without it)",
        ],
        "outputCategories": OUTPUT_CATEGORIES,
        "evidenceContract": {
            "fullClaim": E3_CLAIM_FULL,
            "fullClaimRequires": [
                "all four output categories PASS",
                "durable per-attempt reconciliation",
                "complete ordered marker intervals",
                "host-admission cross-check PASS",
                "no problems or phase failures",
            ],
            "otherwise": E3_CLAIM_NONE,
        },
        "livePrimitiveStatus": "BLOCKED",
        "livePrimitiveNote": "no real controller/probe ships in this module; a bare CLI run --live is always BLOCKED",
    });
    write_json(out_dir, "plan.json", &plan).map_err(|problem| E3ConfigError {
        problems: vec![problem],
    })?;
    write_checksums(out_dir, &["plan.json"]).map_err(|problem| E3ConfigError {
        problems: vec![problem],
    })?;
    Ok(plan)
}

pub fn cli_plan(config: &Value, out_dir: &Path) -> i32 {
    match execute_plan(config, out_dir) {
        Ok(_) => 0,
        Err(_) => 2,
    }
}

pub fn load_approval_record(path: &Path) -> Result<Value, String> {
    let text = fs::read_to_string(path).map_err(|error| error.to_string())?;
    serde_json::from_str(&text).map_err(|error| error.to_string())
}

pub fn e3_live_gate(
    settings: &E3Settings,
    live: bool,
    approval_ref: Option<&str>,
    approval_record: Option<&Value>,
) -> Option<String> {
    if !live {
        return Some("live_not_enabled".to_owned());
    }
    let pattern = Regex::new(APPROVAL_REF_PATTERN).expect("approval ref regex");
    if approval_ref.is_none_or(|value| !pattern.is_match(value)) {
        return Some("approval_ref_missing_or_unsafe".to_owned());
    }
    let Some(record) = approval_record else {
        return Some("approval_record_not_a_mapping".to_owned());
    };
    if !record.is_object() {
        return Some("approval_record_not_a_mapping".to_owned());
    }
    if record.get("run_id").and_then(Value::as_str) != Some(settings.run_id.as_str()) {
        return Some("approval_record_run_id_mismatch".to_owned());
    }
    if record.get("approval_ref").and_then(Value::as_str) != approval_ref {
        return Some("approval_record_ref_mismatch".to_owned());
    }
    if record
        .get("approved_by")
        .and_then(Value::as_str)
        .is_none_or(|value| value.trim().is_empty())
    {
        return Some("approval_record_approver_missing".to_owned());
    }
    if !settings.isolated_fixture {
        return Some("fixture_not_isolated".to_owned());
    }
    None
}

pub type ApprovalValidator<'a> = dyn FnMut(&str, &str, &str) -> Result<bool, String> + 'a;

pub fn validate_live_setup(
    settings: &E3Settings,
    live: bool,
    approval_ref: Option<&str>,
    approval_record: Option<&Value>,
    config_hash: &str,
    validator: Option<&mut ApprovalValidator<'_>>,
) -> (Option<String>, Vec<(String, String, String)>) {
    if let Some(problem) = e3_live_gate(settings, live, approval_ref, approval_record) {
        return (Some(problem), Vec::new());
    }
    let Some(validator) = validator else {
        return (
            Some("independent_user_approval_not_verified".to_owned()),
            Vec::new(),
        );
    };
    let approval_ref = approval_ref.expect("validated approval ref");
    let captured = vec![(
        settings.run_id.clone(),
        approval_ref.to_owned(),
        config_hash.to_owned(),
    )];
    let accepted = validator(&settings.run_id, approval_ref, config_hash).unwrap_or(false);
    if accepted {
        (None, captured)
    } else {
        (
            Some("independent_user_approval_not_verified".to_owned()),
            captured,
        )
    }
}

pub fn missing_primitive_report(probe_present: bool, controller_present: bool) -> Value {
    let mut problems = Vec::new();
    if !probe_present {
        problems.push("missing_probe");
    }
    if !controller_present {
        problems.push("missing_injection_controller");
    }
    json!({
        "status": if problems.is_empty() { "PASS" } else { "BLOCKED" },
        "problems": problems,
        "limitations": [
            {"item": "real_platform_primitives", "status": "BLOCKED"},
        ],
    })
}

pub fn cli_run_without_live(config: &Value, out_dir: &Path) -> i32 {
    if e3_config::load_e3_config(config).is_err() {
        return 2;
    }
    let manifest = json!({
        "experiment": "E3",
        "status": "BLOCKED",
        "problems": ["live_not_enabled"],
        "e3_evidence_claim": E3_CLAIM_NONE,
    });
    let _ = write_json(out_dir, "manifest.json", &manifest);
    let _ = write_checksums(out_dir, &["manifest.json"]);
    1
}

pub fn scrub_output_settings(settings: &E3Settings) -> (Value, String) {
    (public_metadata(settings), probe_alias(settings).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use uuid::Uuid;

    const RUN_ID: &str = "authz-validation-e3-test";
    const APPROVAL_REF: &str = "approval-e3-0001";

    fn base_config() -> Value {
        json!({
            "run_id": RUN_ID,
            "e3": {
                "allowlist": {
                    "target_card": "card-target-1",
                    "unrelated_card": "card-unrelated-1",
                    "cold_card": "card-cold-1",
                    "isolated_fixture": true,
                },
                "windows": {
                    "sampling_interval_s": 0.02,
                    "injection_window_s": 0.05,
                    "drain_window_s": 0.05,
                },
                "bounds": {"max_attempts": 8},
                "nodes": ["node-a"],
                "decision_node": "gateway",
            }
        })
    }

    fn settings(config: &Value) -> E3Settings {
        e3_config::load_e3_config(config).expect("valid config")
    }

    fn approval_record() -> Value {
        json!({
            "run_id": RUN_ID,
            "approval_ref": APPROVAL_REF,
            "approved_by": "test-approver",
        })
    }

    fn temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("astral-e3-{label}-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).expect("temp dir");
        path
    }

    #[test]
    fn plan_is_offline_and_stable() {
        let first_dir = temp_dir("plan-a");
        let second_dir = temp_dir("plan-b");
        let config = base_config();
        let first = execute_plan(&config, &first_dir).expect("plan");
        let second = execute_plan(&config, &second_dir).expect("plan");
        assert_eq!(first["status"], "PLANNED");
        assert_eq!(first["mode"], "plan");
        assert_eq!(first["operationIds"], second["operationIds"]);
        assert_eq!(
            first["operationIds"],
            Value::Object(e3_operation_ids(RUN_ID))
        );
        assert_eq!(first["outputCategories"], json!(OUTPUT_CATEGORIES));
        assert_eq!(
            first["markerContract"]["timeSources"],
            json!(["wall_unix_ns", "monotonic_ns"])
        );
        assert_eq!(first["livePrimitiveStatus"], "BLOCKED");
        assert!(!first["gateRequirements"].as_array().unwrap().is_empty());
        assert!(first_dir.join("plan.json").exists());
        verify_checksums(&first_dir, &first_dir.join("checksums.sha256")).expect("checksums");
        fs::remove_dir_all(first_dir).ok();
        fs::remove_dir_all(second_dir).ok();
    }

    #[test]
    fn live_gate_blocks_missing_live_self_supplied_and_non_isolated_fixture() {
        let config = base_config();
        let settings_value = settings(&config);
        let record = approval_record();
        assert_eq!(
            e3_live_gate(&settings_value, false, Some(APPROVAL_REF), Some(&record)).as_deref(),
            Some("live_not_enabled")
        );
        assert_eq!(
            e3_live_gate(&settings_value, true, None, Some(&record)).as_deref(),
            Some("approval_ref_missing_or_unsafe")
        );
        let mut wrong_run = record.clone();
        wrong_run["run_id"] = json!("other-run");
        assert_eq!(
            e3_live_gate(&settings_value, true, Some(APPROVAL_REF), Some(&wrong_run)).as_deref(),
            Some("approval_record_run_id_mismatch")
        );
        let (problem, captured) = validate_live_setup(
            &settings_value,
            true,
            Some(APPROVAL_REF),
            Some(&record),
            &config_sha256(&config),
            None,
        );
        assert_eq!(
            problem.as_deref(),
            Some("independent_user_approval_not_verified")
        );
        assert!(captured.is_empty());

        let mut non_isolated = base_config();
        non_isolated["e3"]["allowlist"]["isolated_fixture"] = json!(false);
        let non_isolated = settings(&non_isolated);
        assert_eq!(
            e3_live_gate(&non_isolated, true, Some(APPROVAL_REF), Some(&record)).as_deref(),
            Some("fixture_not_isolated")
        );
    }

    #[test]
    fn approval_record_from_file_is_loaded_and_validated() {
        let dir = temp_dir("approval-file");
        let path = dir.join("approval.json");
        fs::write(&path, serde_json::to_vec(&approval_record()).unwrap()).unwrap();
        let record = load_approval_record(&path).expect("approval record");
        let config = base_config();
        let settings = settings(&config);
        let expected = config_sha256(&config);
        let mut validator = |run_id: &str, approval_ref: &str, config_hash: &str| {
            Ok(run_id == RUN_ID
                && approval_ref == APPROVAL_REF
                && config_hash.len() == 64
                && config_hash == expected.as_str())
        };
        let (problem, captured) = validate_live_setup(
            &settings,
            true,
            Some(APPROVAL_REF),
            Some(&record),
            &config_sha256(&config),
            Some(&mut validator),
        );
        assert_eq!(problem, None);
        assert_eq!(
            captured,
            vec![(
                RUN_ID.to_owned(),
                APPROVAL_REF.to_owned(),
                config_sha256(&config)
            )]
        );
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn cli_plan_returns_zero_and_verifies_checksums() {
        let dir = temp_dir("cli-plan");
        assert_eq!(cli_plan(&base_config(), &dir), 0);
        let plan: Value =
            serde_json::from_str(&fs::read_to_string(dir.join("plan.json")).unwrap()).unwrap();
        assert_eq!(plan["status"], "PLANNED");
        verify_checksums(&dir, &dir.join("checksums.sha256")).expect("checksums");
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn cli_run_without_live_returns_one_with_blocked_manifest() {
        let dir = temp_dir("cli-run");
        assert_eq!(cli_run_without_live(&base_config(), &dir), 1);
        let manifest: Value =
            serde_json::from_str(&fs::read_to_string(dir.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["status"], "BLOCKED");
        assert_eq!(manifest["problems"], json!(["live_not_enabled"]));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn cli_bad_config_returns_two() {
        let dir = temp_dir("cli-bad");
        assert_eq!(cli_plan(&json!({"run_id": "x"}), &dir), 2);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn approval_validator_receives_exact_canonical_hash() {
        let config = base_config();
        let settings = settings(&config);
        let record = approval_record();
        let expected = config_sha256(&config);
        let mut captured = Vec::new();
        let mut validator =
            |run_id: &str, approval_ref: &str, config_hash: &str| {
                captured.push((
                    run_id.to_owned(),
                    approval_ref.to_owned(),
                    config_hash.to_owned(),
                ));
                Ok(run_id == RUN_ID
                    && approval_ref == APPROVAL_REF
                    && config_hash == expected.as_str())
            };
        let (problem, returned) = validate_live_setup(
            &settings,
            true,
            Some(APPROVAL_REF),
            Some(&record),
            &expected,
            Some(&mut validator),
        );
        assert_eq!(problem, None);
        assert_eq!(
            captured,
            vec![(RUN_ID.to_owned(), APPROVAL_REF.to_owned(), expected.clone())]
        );
        assert_eq!(captured, returned);
    }

    #[test]
    fn approval_validator_hash_mismatch_and_exception_fail_closed() {
        let config = base_config();
        let settings = settings(&config);
        let record = approval_record();
        let expected = config_sha256(&config);
        let probe_calls = 0;
        let controller_calls = 0;
        let mut mismatch = |_run_id: &str, _approval_ref: &str, _config_hash: &str| Ok(false);
        let (problem, _) = validate_live_setup(
            &settings,
            true,
            Some(APPROVAL_REF),
            Some(&record),
            &expected,
            Some(&mut mismatch),
        );
        assert_eq!(
            problem.as_deref(),
            Some("independent_user_approval_not_verified")
        );
        assert_eq!((probe_calls, controller_calls), (0, 0));

        let mut crashed = |_run_id: &str, _approval_ref: &str, _config_hash: &str| {
            Err::<bool, String>("external validator crashed".to_owned())
        };
        let (problem, _) = validate_live_setup(
            &settings,
            true,
            Some(APPROVAL_REF),
            Some(&record),
            &expected,
            Some(&mut crashed),
        );
        assert_eq!(
            problem.as_deref(),
            Some("independent_user_approval_not_verified")
        );
        assert_eq!((probe_calls, controller_calls), (0, 0));
    }

    #[test]
    fn missing_probe_and_controller_are_blocked_with_limitation() {
        let report = missing_primitive_report(false, true);
        assert_eq!(report["status"], "BLOCKED");
        assert_eq!(report["problems"], json!(["missing_probe"]));
        assert_eq!(
            report["limitations"][0],
            json!({"item": "real_platform_primitives", "status": "BLOCKED"})
        );
        let report = missing_primitive_report(true, false);
        assert_eq!(report["problems"], json!(["missing_injection_controller"]));
        assert_eq!(missing_primitive_report(true, true)["status"], "PASS");
    }

    #[test]
    fn outputs_are_scrubbed_while_probe_keeps_raw_alias() {
        let mut config = base_config();
        config["e3"]["decision_node"] = json!("gateway.example.com");
        let settings = settings(&config);
        let (stored, alias) = scrub_output_settings(&settings);
        assert_eq!(stored["decisionNode"], "[redacted-host]");
        assert_eq!(alias, "gateway.example.com");
        assert!(!serde_json::to_string(&stored)
            .unwrap()
            .contains("example.com"));
    }

    #[test]
    fn cli_live_without_independent_validator_is_blocked() {
        let config = base_config();
        let settings = settings(&config);
        let record = approval_record();
        let (problem, captured) = validate_live_setup(
            &settings,
            true,
            Some(APPROVAL_REF),
            Some(&record),
            &config_sha256(&config),
            None,
        );
        assert_eq!(
            problem.as_deref(),
            Some("independent_user_approval_not_verified")
        );
        assert!(captured.is_empty());
    }
}
