use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const CAMPAIGN_PREFIX: &str = "authz-validation-";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReadinessStatus {
    Fail,
    Unknown,
    Blocked,
    Pending,
    Skip,
    Pass,
    Planned,
}

impl ReadinessStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fail => "FAIL",
            Self::Unknown => "UNKNOWN",
            Self::Blocked => "BLOCKED",
            Self::Pending => "PENDING",
            Self::Skip => "SKIP",
            Self::Pass => "PASS",
            Self::Planned => "PLANNED",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractError {
    InvalidCampaignId,
    InvalidArtifactPath(String),
    DuplicateInventoryPath(String),
    MissingSource(String),
    MissingCommandResult(String),
    MalformedChecksum,
    DuplicateChecksumPath(String),
    MissingArtifact(String),
    ChecksumMismatch(String),
    InvalidJsonStatus,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommandExpectation {
    pub stdout_marker: Option<String>,
    pub stderr_marker: Option<String>,
    pub minimum_rust_tests: Option<u64>,
    pub require_full_contract_json: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandExecution {
    Completed {
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
    TimedOut {
        partial_stdout: String,
        partial_stderr: String,
    },
    SpawnError {
        error_class: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandResult {
    pub id: String,
    pub status: ReadinessStatus,
    pub exit_code: Option<i32>,
    pub assertion_passed: bool,
    pub log_complete: bool,
    pub stdout: String,
    pub stderr: String,
    pub abstract_model_status: Option<ReadinessStatus>,
    pub reason: Option<String>,
}

pub fn validate_campaign_id(value: &str) -> Result<(), ContractError> {
    let Some(suffix) = value.strip_prefix(CAMPAIGN_PREFIX) else {
        return Err(ContractError::InvalidCampaignId);
    };
    if suffix.is_empty()
        || suffix.len() > 64
        || !suffix.as_bytes()[0].is_ascii_alphanumeric()
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ContractError::InvalidCampaignId);
    }
    Ok(())
}

pub fn validate_artifact_path(path: &str) -> Result<(), ContractError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains('\0')
        || path.contains(':')
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(ContractError::InvalidArtifactPath(path.to_owned()));
    }
    Ok(())
}

pub fn missing_sources<'a>(
    inventory: &'a [String],
    available: &BTreeMap<String, Vec<u8>>,
) -> Result<Vec<&'a str>, ContractError> {
    let mut seen = BTreeSet::new();
    for path in inventory {
        validate_artifact_path(path)?;
        if !seen.insert(path.as_str()) {
            return Err(ContractError::DuplicateInventoryPath(path.clone()));
        }
    }
    Ok(inventory
        .iter()
        .filter(|path| !available.contains_key(*path))
        .map(String::as_str)
        .collect())
}

pub fn source_snapshot(
    inventory: &[String],
    available: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, String>, ContractError> {
    if let Some(path) = missing_sources(inventory, available)?.first() {
        return Err(ContractError::MissingSource((*path).to_owned()));
    }
    Ok(inventory
        .iter()
        .map(|path| (path.clone(), sha256(&available[path])))
        .collect())
}

pub fn source_drift(
    initial: &BTreeMap<String, String>,
    current: &BTreeMap<String, String>,
) -> Vec<String> {
    initial
        .keys()
        .chain(current.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|path| initial.get(*path) != current.get(*path))
        .cloned()
        .collect()
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn full_contract_status(stdout: &str) -> ReadinessStatus {
    let parsed = serde_json::from_str::<Value>(stdout).ok();
    let status = parsed
        .as_ref()
        .and_then(|value| value.get("fullContract"))
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str);
    match status {
        Some("PASS") => ReadinessStatus::Pass,
        Some("FAIL") => ReadinessStatus::Fail,
        Some("BLOCKED") => ReadinessStatus::Blocked,
        Some("PENDING") => ReadinessStatus::Pending,
        Some("SKIP") => ReadinessStatus::Skip,
        Some("UNKNOWN") | Some("PLANNED") | None => ReadinessStatus::Unknown,
        Some(_) => ReadinessStatus::Unknown,
    }
}

pub fn evaluate_command(
    id: &str,
    expectation: &CommandExpectation,
    execution: CommandExecution,
) -> CommandResult {
    let (exit_code, stdout, stderr, log_complete, mut status, reason) = match execution {
        CommandExecution::Completed {
            exit_code,
            stdout,
            stderr,
        } => (
            Some(exit_code),
            stdout,
            stderr,
            true,
            if exit_code == 0 {
                ReadinessStatus::Pass
            } else {
                ReadinessStatus::Fail
            },
            None,
        ),
        CommandExecution::TimedOut {
            partial_stdout,
            partial_stderr,
        } => (
            None,
            partial_stdout,
            partial_stderr,
            false,
            ReadinessStatus::Unknown,
            Some("command timed out; output is incomplete".to_owned()),
        ),
        CommandExecution::SpawnError { error_class } => (
            None,
            String::new(),
            error_class.clone(),
            true,
            ReadinessStatus::Blocked,
            Some(format!("command could not start: {error_class}")),
        ),
    };

    if expectation.minimum_rust_tests.is_some() && status == ReadinessStatus::Pass {
        let output_status =
            crate::acceptance::check_rust_output_with_policy(crate::acceptance::RustOutputPolicy {
                expected_tests: None,
                minimum_tests: usize::try_from(expectation.minimum_rust_tests.unwrap_or(1).max(1))
                    .unwrap_or(usize::MAX),
                performance_cases: None,
                stdout: &stdout,
                stderr: &stderr,
                exit_code: 0,
                interrupted: false,
                allow_outside_selection_ignored: false,
            });
        status = match output_status["status"].as_str() {
            Some("PASS") => ReadinessStatus::Pass,
            Some("SKIP") => ReadinessStatus::Skip,
            Some("UNKNOWN") => ReadinessStatus::Unknown,
            Some("PENDING") => ReadinessStatus::Pending,
            Some("BLOCKED") => ReadinessStatus::Blocked,
            Some("FAIL") => ReadinessStatus::Fail,
            _ => ReadinessStatus::Unknown,
        };
    }
    let output_assertion_failed = expectation
        .stdout_marker
        .as_ref()
        .is_some_and(|marker| !stdout.contains(marker))
        || expectation
            .stderr_marker
            .as_ref()
            .is_some_and(|marker| !stderr.contains(marker));
    let mut assertion_passed = status == ReadinessStatus::Pass;
    if assertion_passed && output_assertion_failed {
        status = ReadinessStatus::Fail;
        assertion_passed = false;
    }

    let abstract_model_status = if expectation.require_full_contract_json {
        let model_status = full_contract_status(&stdout);
        if status == ReadinessStatus::Pass && model_status != ReadinessStatus::Pass {
            status = model_status;
            assertion_passed = false;
        }
        Some(model_status)
    } else {
        None
    };

    let reason = if status == ReadinessStatus::Fail && reason.is_none() && !assertion_passed {
        Some("exit code or required output assertion failed".to_owned())
    } else if status == ReadinessStatus::Unknown
        && expectation.require_full_contract_json
        && reason.is_none()
    {
        Some("full-contract JSON is invalid, incomplete, or not PASS".to_owned())
    } else {
        reason
    };

    CommandResult {
        id: id.to_owned(),
        status,
        exit_code,
        assertion_passed,
        log_complete,
        stdout,
        stderr,
        abstract_model_status,
        reason,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandGate {
    pub id: String,
    pub required: bool,
    pub preblocked_reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchReport {
    pub completed: Vec<CommandResult>,
    pub invoked: Vec<String>,
    pub skipped: Vec<String>,
}

pub fn reduce_dispatch(
    gates: &[CommandGate],
    outcomes: &BTreeMap<String, CommandResult>,
) -> Result<DispatchReport, ContractError> {
    let mut completed = Vec::new();
    let mut invoked = Vec::new();
    let mut stopped = false;
    for gate in gates {
        if stopped {
            continue;
        }
        if let Some(reason) = &gate.preblocked_reason {
            completed.push(CommandResult {
                id: gate.id.clone(),
                status: ReadinessStatus::Blocked,
                exit_code: None,
                assertion_passed: false,
                log_complete: true,
                stdout: String::new(),
                stderr: String::new(),
                abstract_model_status: None,
                reason: Some(reason.clone()),
            });
            continue;
        }
        let Some(result) = outcomes.get(&gate.id) else {
            return Err(ContractError::MissingCommandResult(gate.id.clone()));
        };
        invoked.push(gate.id.clone());
        completed.push(result.clone());
        if gate.required && result.status != ReadinessStatus::Pass {
            stopped = true;
        }
    }
    let completed_ids = completed
        .iter()
        .map(|result| result.id.as_str())
        .collect::<BTreeSet<_>>();
    let skipped = gates
        .iter()
        .filter(|gate| !completed_ids.contains(gate.id.as_str()))
        .map(|gate| gate.id.clone())
        .collect();
    Ok(DispatchReport {
        completed,
        invoked,
        skipped,
    })
}

pub fn apply_source_drift(results: &mut [CommandResult], drift: &[String]) {
    if drift.is_empty() {
        return;
    }
    for result in results {
        if result.status == ReadinessStatus::Pass {
            result.status = ReadinessStatus::Unknown;
            result.assertion_passed = false;
            result.reason = Some("source snapshot changed during readiness execution".to_owned());
        }
    }
}

pub fn aggregate_status(
    statuses: &BTreeMap<String, ReadinessStatus>,
    required: &[String],
) -> ReadinessStatus {
    let observed = required
        .iter()
        .map(|id| statuses.get(id).copied().unwrap_or(ReadinessStatus::Skip))
        .collect::<Vec<_>>();
    for candidate in [
        ReadinessStatus::Fail,
        ReadinessStatus::Unknown,
        ReadinessStatus::Blocked,
        ReadinessStatus::Pending,
    ] {
        if observed.contains(&candidate) {
            return candidate;
        }
    }
    if observed
        .iter()
        .any(|status| *status != ReadinessStatus::Pass)
    {
        ReadinessStatus::Skip
    } else {
        ReadinessStatus::Pass
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadinessStatusReport {
    pub overall: ReadinessStatus,
    pub local_ready: ReadinessStatus,
    pub local_source_snapshot: ReadinessStatus,
    pub scenarios: BTreeMap<String, ReadinessStatus>,
    pub skipped_commands: Vec<String>,
    pub unknown: Vec<String>,
    pub blocked: Vec<String>,
    pub source_drift: Vec<String>,
}

pub fn summarize_readiness(
    commands: &[CommandResult],
    skipped_commands: Vec<String>,
    scenarios: BTreeMap<String, ReadinessStatus>,
    source_drift: Vec<String>,
) -> ReadinessStatusReport {
    let failed = commands
        .iter()
        .any(|command| command.status == ReadinessStatus::Fail);
    let mut unknown = commands
        .iter()
        .filter(|command| command.status == ReadinessStatus::Unknown)
        .map(|command| command.id.clone())
        .collect::<Vec<_>>();
    if !source_drift.is_empty() {
        unknown.push("source-drift".to_owned());
    }
    let blocked_commands = commands
        .iter()
        .filter(|command| command.status == ReadinessStatus::Blocked)
        .map(|command| command.id.clone())
        .collect::<Vec<_>>();
    let blocked_scenarios = scenarios
        .iter()
        .filter(|(_, status)| **status == ReadinessStatus::Blocked)
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    let mut blocked = blocked_commands.clone();
    blocked.extend(blocked_scenarios);
    let required_pass = source_drift.is_empty()
        && skipped_commands.is_empty()
        && commands
            .iter()
            .all(|command| command.status == ReadinessStatus::Pass);
    let local_ready = if required_pass {
        ReadinessStatus::Pass
    } else if failed {
        ReadinessStatus::Fail
    } else if !unknown.is_empty() {
        ReadinessStatus::Unknown
    } else if !blocked_commands.is_empty() {
        ReadinessStatus::Blocked
    } else {
        ReadinessStatus::Skip
    };
    ReadinessStatusReport {
        overall: if failed {
            ReadinessStatus::Fail
        } else if !unknown.is_empty() {
            ReadinessStatus::Unknown
        } else {
            ReadinessStatus::Blocked
        },
        local_ready,
        local_source_snapshot: if source_drift.is_empty() {
            ReadinessStatus::Pass
        } else {
            ReadinessStatus::Unknown
        },
        scenarios,
        skipped_commands,
        unknown,
        blocked,
        source_drift,
    }
}

pub fn readiness_manifest(
    campaign_id: &str,
    source_hashes: &BTreeMap<String, String>,
    final_source_hashes: &BTreeMap<String, String>,
    commands: &[CommandResult],
    skipped_commands: &[String],
    source_drift: &[String],
) -> Result<Value, ContractError> {
    validate_campaign_id(campaign_id)?;
    for path in source_hashes.keys().chain(final_source_hashes.keys()) {
        validate_artifact_path(path)?;
    }
    Ok(json!({
        "schemaVersion": 2,
        "campaignId": campaign_id,
        "sourceHashes": source_hashes,
        "finalSourceHashes": final_source_hashes,
        "sourceDrift": source_drift,
        "commands": commands,
        "skippedCommands": skipped_commands,
        "statisticsUnit": {
            "E1/E3/E4": "not run",
            "E5": "offline abstract contract only"
        }
    }))
}

pub fn checksum_manifest(files: &BTreeMap<String, Vec<u8>>) -> Result<String, ContractError> {
    let mut lines = Vec::with_capacity(files.len());
    for (path, bytes) in files {
        validate_artifact_path(path)?;
        lines.push(format!("{}  {path}", sha256(bytes)));
    }
    if lines.is_empty() {
        Ok(String::new())
    } else {
        Ok(format!("{}\n", lines.join("\n")))
    }
}

pub fn verify_checksum_manifest(
    files: &BTreeMap<String, Vec<u8>>,
    manifest: &str,
) -> Result<(), ContractError> {
    let mut seen = BTreeSet::new();
    for line in manifest.lines() {
        let Some((digest, path)) = line.split_once("  ") else {
            return Err(ContractError::MalformedChecksum);
        };
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ContractError::MalformedChecksum);
        }
        validate_artifact_path(path)?;
        if !seen.insert(path) {
            return Err(ContractError::DuplicateChecksumPath(path.to_owned()));
        }
        let Some(bytes) = files.get(path) else {
            return Err(ContractError::MissingArtifact(path.to_owned()));
        };
        if sha256(bytes) != digest {
            return Err(ContractError::ChecksumMismatch(path.to_owned()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passing(id: &str) -> CommandResult {
        evaluate_command(
            id,
            &CommandExpectation::default(),
            CommandExecution::Completed {
                exit_code: 0,
                stdout: "ok".to_owned(),
                stderr: String::new(),
            },
        )
    }

    #[test]
    fn campaign_ids_and_artifact_paths_reject_traversal_before_writes() {
        assert!(validate_campaign_id("authz-validation-good_1.2").is_ok());
        for value in [
            "old",
            "authz-validation-",
            "authz-validation-../escape",
            "authz-validation-bad id",
            &format!("authz-validation-{}", "x".repeat(65)),
        ] {
            assert_eq!(
                validate_campaign_id(value),
                Err(ContractError::InvalidCampaignId)
            );
        }
        for path in [
            "../outside",
            "/absolute",
            "a//b",
            "a/./b",
            "a\\b",
            "C:/outside",
        ] {
            assert!(matches!(
                validate_artifact_path(path),
                Err(ContractError::InvalidArtifactPath(_))
            ));
        }
        assert!(validate_artifact_path("logs/command.stdout.log").is_ok());
    }

    #[test]
    fn source_inventory_is_unique_complete_and_hashes_exact_bytes() {
        let inventory = vec!["Cargo.toml".to_owned(), "src/lib.rs".to_owned()];
        let available = BTreeMap::from([
            ("Cargo.toml".to_owned(), b"[workspace]\n".to_vec()),
            ("src/lib.rs".to_owned(), b"pub mod readiness;\n".to_vec()),
        ]);
        let snapshot = source_snapshot(&inventory, &available).unwrap();
        assert_eq!(snapshot["Cargo.toml"], sha256(b"[workspace]\n"));
        assert!(source_drift(&snapshot, &snapshot).is_empty());
        let changed = BTreeMap::from([
            ("Cargo.toml".to_owned(), snapshot["Cargo.toml"].clone()),
            ("src/lib.rs".to_owned(), sha256(b"changed")),
        ]);
        assert_eq!(source_drift(&snapshot, &changed), vec!["src/lib.rs"]);
        assert_eq!(
            missing_sources(&inventory, &BTreeMap::new()).unwrap(),
            vec!["Cargo.toml", "src/lib.rs"]
        );
        assert_eq!(
            source_snapshot(&inventory, &BTreeMap::new()),
            Err(ContractError::MissingSource("Cargo.toml".to_owned()))
        );
        assert!(matches!(
            missing_sources(&["x".to_owned(), "x".to_owned()], &available),
            Err(ContractError::DuplicateInventoryPath(_))
        ));
    }

    #[test]
    fn timeout_and_spawn_failures_preserve_their_distinct_evidence_states() {
        let timeout = evaluate_command(
            "timed-out",
            &CommandExpectation::default(),
            CommandExecution::TimedOut {
                partial_stdout: "partial stdout".to_owned(),
                partial_stderr: "partial stderr".to_owned(),
            },
        );
        assert_eq!(timeout.status, ReadinessStatus::Unknown);
        assert_eq!(timeout.exit_code, None);
        assert!(!timeout.log_complete);
        assert_eq!(timeout.stdout, "partial stdout");
        assert_eq!(timeout.stderr, "partial stderr");

        let spawn = evaluate_command(
            "spawn-error",
            &CommandExpectation::default(),
            CommandExecution::SpawnError {
                error_class: "OSError".to_owned(),
            },
        );
        assert_eq!(spawn.status, ReadinessStatus::Blocked);
        assert_eq!(spawn.exit_code, None);
        assert_eq!(spawn.stderr, "OSError");
    }

    #[test]
    fn exit_zero_needs_markers_and_minimum_rust_tests() {
        let expectation = CommandExpectation {
            stdout_marker: Some("1 passed; 0 failed".to_owned()),
            stderr_marker: Some("completed".to_owned()),
            minimum_rust_tests: Some(1),
            require_full_contract_json: false,
        };
        let empty = evaluate_command(
            "zero-tests",
            &expectation,
            CommandExecution::Completed {
                exit_code: 0,
                stdout: rust_test_summary(0, 0, 0, 1),
                stderr: "completed".to_owned(),
            },
        );
        assert_eq!(empty.status, ReadinessStatus::Fail);
        assert!(!empty.assertion_passed);
        let passing = evaluate_command(
            "one-test",
            &expectation,
            CommandExecution::Completed {
                exit_code: 0,
                stdout: rust_test_summary(1, 0, 0, 0),
                stderr: "completed".to_owned(),
            },
        );
        assert_eq!(passing.status, ReadinessStatus::Pass);
        let ignored = evaluate_command(
            "ignored-test",
            &expectation,
            CommandExecution::Completed {
                exit_code: 0,
                stdout: rust_test_summary(1, 0, 1, 0),
                stderr: "completed".to_owned(),
            },
        );
        assert_eq!(ignored.status, ReadinessStatus::Skip);
        assert!(!ignored.assertion_passed);
        let internal_skip = evaluate_command(
            "internal-skip",
            &expectation,
            CommandExecution::Completed {
                exit_code: 0,
                stdout: rust_test_summary(1, 0, 0, 0),
                stderr: "[SKIP] missing dependency\ncompleted".to_owned(),
            },
        );

        assert_eq!(internal_skip.status, ReadinessStatus::Skip);
        assert!(!internal_skip.assertion_passed);
        let failed = evaluate_command(
            "failed-test",
            &expectation,
            CommandExecution::Completed {
                exit_code: 0,
                stdout: rust_test_summary(1, 1, 0, 0),
                stderr: "completed".to_owned(),
            },
        );
        assert_eq!(failed.status, ReadinessStatus::Fail);
        assert!(!failed.assertion_passed);
    }

    fn rust_test_summary(passed: u64, failed: u64, ignored: u64, filtered: u64) -> String {
        format!(
            "test result: ok. {passed} passed; {failed} failed; {ignored} ignored; 0 measured; {filtered} filtered out; finished in 0.00s\n"
        )
    }

    #[test]
    fn minimum_rust_tests_reject_exit_zero_without_cargo_summary() {
        let expectation = CommandExpectation {
            minimum_rust_tests: Some(1),
            ..CommandExpectation::default()
        };
        let result = evaluate_command(
            "missing-summary",
            &expectation,
            CommandExecution::Completed {
                exit_code: 0,
                stdout: "process completed without a Rust test summary".to_owned(),
                stderr: String::new(),
            },
        );
        assert_eq!(result.status, ReadinessStatus::Fail);
        assert!(!result.assertion_passed);
    }

    #[test]
    fn minimum_rust_test_count_cannot_turn_an_empty_target_into_pass() {
        let expectation = CommandExpectation {
            minimum_rust_tests: Some(0),
            ..CommandExpectation::default()
        };
        let result = evaluate_command(
            "empty-target",
            &expectation,
            CommandExecution::Completed {
                exit_code: 0,
                stdout: rust_test_summary(0, 0, 0, 0),
                stderr: String::new(),
            },
        );
        assert_eq!(result.status, ReadinessStatus::Fail);
        assert!(!result.assertion_passed);
    }

    #[test]
    fn rust_test_acceptance_preserves_pending_unknown_and_blocked_statuses() {
        let expectation = CommandExpectation {
            minimum_rust_tests: Some(1),
            ..CommandExpectation::default()
        };
        for (marker, expected) in [
            (
                "[PENDING] reconciliation required",
                ReadinessStatus::Pending,
            ),
            ("[UNKNOWN] stream ended", ReadinessStatus::Unknown),
            (
                "[BLOCKED] integration prerequisite missing",
                ReadinessStatus::Blocked,
            ),
        ] {
            let result = evaluate_command(
                "non-pass-state",
                &expectation,
                CommandExecution::Completed {
                    exit_code: 0,
                    stdout: rust_test_summary(1, 0, 0, 0),
                    stderr: marker.to_owned(),
                },
            );
            assert_eq!(result.status, expected, "{marker}");
            assert!(!result.assertion_passed, "{marker}");
        }
    }

    #[test]
    fn full_contract_json_errors_and_incomplete_status_remain_unknown() {
        let expectation = CommandExpectation {
            require_full_contract_json: true,
            ..CommandExpectation::default()
        };
        for stdout in ["not-json", r#"{"unexpected":true}"#] {
            let result = evaluate_command(
                "bad-json",
                &expectation,
                CommandExecution::Completed {
                    exit_code: 0,
                    stdout: stdout.to_owned(),
                    stderr: String::new(),
                },
            );
            assert_eq!(result.status, ReadinessStatus::Unknown);
            assert!(!result.assertion_passed);
            assert_eq!(result.abstract_model_status, Some(ReadinessStatus::Unknown));
        }
        let incomplete = evaluate_command(
            "incomplete",
            &expectation,
            CommandExecution::Completed {
                exit_code: 0,
                stdout: r#"{"fullContract":{"status":"UNKNOWN","modes":{"bracket":{"explorationComplete":false}}}}"#.to_owned(),
                stderr: String::new(),
            },
        );
        assert_eq!(incomplete.status, ReadinessStatus::Unknown);
        assert_eq!(
            incomplete.abstract_model_status,
            Some(ReadinessStatus::Unknown)
        );
        let pass = evaluate_command(
            "complete",
            &expectation,
            CommandExecution::Completed {
                exit_code: 0,
                stdout: r#"{"fullContract":{"status":"PASS"}}"#.to_owned(),
                stderr: String::new(),
            },
        );
        assert_eq!(pass.status, ReadinessStatus::Pass);
    }

    #[test]
    fn required_failure_stops_later_commands_but_declared_blocks_do_not_run() {
        let gates = vec![
            CommandGate {
                id: "first".to_owned(),
                required: true,
                preblocked_reason: None,
            },
            CommandGate {
                id: "live-scenario".to_owned(),
                required: true,
                preblocked_reason: Some("offline-only boundary".to_owned()),
            },
            CommandGate {
                id: "last".to_owned(),
                required: true,
                preblocked_reason: None,
            },
        ];
        let failed = evaluate_command(
            "first",
            &CommandExpectation::default(),
            CommandExecution::Completed {
                exit_code: 1,
                stdout: "failed".to_owned(),
                stderr: String::new(),
            },
        );
        let report =
            reduce_dispatch(&gates, &BTreeMap::from([("first".to_owned(), failed)])).unwrap();
        assert_eq!(report.invoked, vec!["first"]);
        assert_eq!(report.skipped, vec!["live-scenario", "last"]);
        assert_eq!(report.completed[0].status, ReadinessStatus::Fail);
    }

    #[test]
    fn source_drift_invalidates_prior_passes_and_scenario_blocks_do_not_lower_local_ready() {
        let mut commands = vec![passing("local-gate")];
        apply_source_drift(&mut commands, &["src/lib.rs".to_owned()]);
        assert_eq!(commands[0].status, ReadinessStatus::Unknown);
        assert!(!commands[0].assertion_passed);

        let clean = vec![passing("local-gate")];
        let report = summarize_readiness(
            &clean,
            Vec::new(),
            BTreeMap::from([("E1-production-race".to_owned(), ReadinessStatus::Blocked)]),
            Vec::new(),
        );
        assert_eq!(report.local_ready, ReadinessStatus::Pass);
        assert_eq!(report.overall, ReadinessStatus::Blocked);
        assert_eq!(report.blocked, vec!["E1-production-race"]);
    }

    #[test]
    fn status_aggregation_is_fail_closed_for_missing_and_ambiguous_gates() {
        let ids = vec!["a".to_owned(), "b".to_owned()];
        assert_eq!(
            aggregate_status(&BTreeMap::new(), &ids),
            ReadinessStatus::Skip
        );
        assert_eq!(
            aggregate_status(
                &BTreeMap::from([
                    ("a".to_owned(), ReadinessStatus::Pass),
                    ("b".to_owned(), ReadinessStatus::Fail),
                ]),
                &ids
            ),
            ReadinessStatus::Fail
        );
        assert_eq!(
            aggregate_status(&BTreeMap::new(), &[]),
            ReadinessStatus::Pass
        );
    }

    #[test]
    fn manifest_records_snapshot_drift_and_refuses_unsafe_campaign_paths() {
        let source = BTreeMap::from([("Cargo.toml".to_owned(), sha256(b"source"))]);
        let manifest = readiness_manifest(
            "authz-validation-run-1",
            &source,
            &source,
            &[passing("check")],
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(manifest["schemaVersion"], 2);
        assert_eq!(manifest["campaignId"], "authz-validation-run-1");
        assert!(manifest["sourceDrift"].as_array().unwrap().is_empty());
        assert_eq!(
            readiness_manifest(
                "authz-validation-../escape",
                &source,
                &source,
                &[],
                &[],
                &[]
            ),
            Err(ContractError::InvalidCampaignId)
        );
    }

    #[test]
    fn checksum_manifest_detects_tampering_bad_lines_and_path_escape() {
        let files = BTreeMap::from([
            ("manifest.json".to_owned(), b"{\"sealed\":true}\n".to_vec()),
            ("logs/a.stdout.log".to_owned(), b"passed\n".to_vec()),
        ]);
        let checksums = checksum_manifest(&files).unwrap();
        assert!(verify_checksum_manifest(&files, &checksums).is_ok());
        let changed = BTreeMap::from([
            ("manifest.json".to_owned(), b"tampered".to_vec()),
            ("logs/a.stdout.log".to_owned(), b"passed\n".to_vec()),
        ]);
        assert!(matches!(
            verify_checksum_manifest(&changed, &checksums),
            Err(ContractError::ChecksumMismatch(_))
        ));
        assert_eq!(
            verify_checksum_manifest(&files, "bad-line\n"),
            Err(ContractError::MalformedChecksum)
        );
        let escaped = format!("{}  ../outside\n", sha256(b"outside"));
        assert!(matches!(
            verify_checksum_manifest(&files, &escaped),
            Err(ContractError::InvalidArtifactPath(_))
        ));
        assert!(matches!(
            checksum_manifest(&BTreeMap::from([("../outside".to_owned(), b"x".to_vec())])),
            Err(ContractError::InvalidArtifactPath(_))
        ));
    }

    #[test]
    fn checksum_writer_orders_entries_deterministically_and_rejects_duplicates() {
        let files = BTreeMap::from([
            ("z.txt".to_owned(), b"z".to_vec()),
            ("a.txt".to_owned(), b"a".to_vec()),
        ]);
        let manifest = checksum_manifest(&files).unwrap();
        assert!(manifest.starts_with(&format!("{}  a.txt\n", sha256(b"a"))));
        let line = format!("{}  a.txt\n", sha256(b"a"));
        assert_eq!(
            verify_checksum_manifest(
                &BTreeMap::from([("a.txt".to_owned(), b"a".to_vec())]),
                &(line.clone() + &line)
            ),
            Err(ContractError::DuplicateChecksumPath("a.txt".to_owned()))
        );
    }

    #[test]
    fn readiness_sources_have_no_import_time_io_or_process_capability() {
        let source = include_str!("readiness_contract.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for token in [
            "std::fs",
            "std::process",
            "std::net",
            "std::env",
            "Command::new",
            "reqwest",
            "hyper::",
        ] {
            assert!(!source.contains(token), "{token}");
        }
    }
}
