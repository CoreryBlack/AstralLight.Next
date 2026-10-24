//! Legacy single-node campaign readiness contracts: runtime command specs and
//! the argument-parse exit path. No command is spawned and no artifact is
//! written by these helpers.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeSpec {
    pub id: &'static str,
    pub required: bool,
    pub expected: &'static str,
    pub argv: &'static [&'static str],
}

pub const RUNTIME_SPECS: [RuntimeSpec; 4] = [
    RuntimeSpec {
        id: "runtime-policy-engine-lib",
        required: true,
        expected: "; 0 failed",
        argv: &["cargo", "test", "-p", "policy-engine", "--lib"],
    },
    RuntimeSpec {
        id: "runtime-astral-db-lib",
        required: true,
        expected: "; 0 failed",
        argv: &["cargo", "test", "-p", "astral-db", "--lib"],
    },
    RuntimeSpec {
        id: "runtime-astral-common-gateway-contract",
        required: true,
        expected: "; 0 failed",
        argv: &[
            "cargo",
            "test",
            "-p",
            "testsuite",
            "--test",
            "gateway_contract_tests",
        ],
    },
    RuntimeSpec {
        id: "runtime-astral-trustgraph-lib",
        required: true,
        expected: "; 0 failed",
        argv: &["cargo", "test", "-p", "astral-trustgraph", "--lib"],
    },
];

pub const COMPILE_ONLY_SPEC: RuntimeSpec = RuntimeSpec {
    id: "workspace-test-compile",
    required: true,
    expected: "; 0 failed",
    argv: &["cargo", "test", "--workspace", "--no-run"],
};

pub fn runtime_spec_by_id(id: &str) -> Option<&'static RuntimeSpec> {
    RUNTIME_SPECS.iter().find(|spec| spec.id == id)
}

pub fn cli_exit_code(args: &[&str]) -> i32 {
    let has_config = args.contains(&"--config");
    let has_out = args.contains(&"--out");
    if !has_config || !has_out {
        return 2;
    }
    0
}

pub const PREVIOUS_ATTEMPT: (&str, &str, &str, &str) = (
    "authz-validation-20260919-single-node-005",
    "BLOCKED",
    "PASS",
    "points at the immutable snapshot",
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UpgradedSpec {
    pub id: &'static str,
    pub assert_two_mutation_model: bool,
    pub assert_universal_hypotheses: bool,
    pub timeout_seconds: u64,
    pub argv: &'static [&'static str],
}

pub const UPGRADED_SPECS: [UpgradedSpec; 2] = [
    UpgradedSpec {
        id: "e5-bounded-model-two-mutations",
        assert_two_mutation_model: true,
        assert_universal_hypotheses: false,
        timeout_seconds: 900,
        argv: &["cargo", "test", "-p", "test-harness", "--lib"],
    },
    UpgradedSpec {
        id: "e5-universal-hypotheses",
        assert_two_mutation_model: false,
        assert_universal_hypotheses: true,
        timeout_seconds: 3600,
        argv: &["cargo", "test", "-p", "test-harness", "--lib"],
    },
];

pub fn scenario_status(statuses: &BTreeMap<String, String>, names: &[&str]) -> &'static str {
    if names.iter().all(|name| {
        statuses
            .get(*name)
            .map(String::as_str)
            .is_some_and(|status| status == "PASS")
    }) {
        "PASS"
    } else if names.iter().any(|name| {
        statuses
            .get(*name)
            .map(String::as_str)
            .is_some_and(|status| status == "FAIL")
    }) {
        "FAIL"
    } else {
        "SKIP"
    }
}

pub fn schedule_commands(
    commands: &[(&str, bool)],
    results: &BTreeMap<String, String>,
) -> Vec<(String, &'static str)> {
    let mut stopped = false;
    let mut scheduled = Vec::new();
    for (id, required) in commands {
        if stopped {
            scheduled.push(((*id).to_owned(), "SKIP"));
            continue;
        }
        let status = match results.get(*id).map(String::as_str) {
            Some("PASS") => "PASS",
            Some("FAIL") => "FAIL",
            Some("UNKNOWN") => "UNKNOWN",
            _ => "BLOCKED",
        };
        scheduled.push(((*id).to_owned(), status));
        if *required && status != "PASS" {
            stopped = true;
        }
    }
    scheduled
}

pub fn preflight_sources(
    existing: &BTreeSet<String>,
    required: &[&str],
) -> Result<(), &'static str> {
    if required.iter().all(|source| existing.contains(*source)) {
        Ok(())
    } else {
        Err("missing_source")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutcome {
    pub status: &'static str,
    pub exit_code: Option<i32>,
    pub log_complete: bool,
    pub stdout_log: String,
    pub stderr_log: String,
}

pub fn timeout_outcome(stdout: &str, stderr: &str) -> CommandOutcome {
    CommandOutcome {
        status: "UNKNOWN",
        exit_code: None,
        log_complete: false,
        stdout_log: stdout.to_owned(),
        stderr_log: stderr.to_owned(),
    }
}

pub fn os_error_outcome() -> CommandOutcome {
    CommandOutcome {
        status: "BLOCKED",
        exit_code: None,
        log_complete: false,
        stdout_log: String::new(),
        stderr_log: "OSError".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_suites_execute_real_tests_without_no_run() {
        for id in [
            "runtime-policy-engine-lib",
            "runtime-astral-db-lib",
            "runtime-astral-common-gateway-contract",
            "runtime-astral-trustgraph-lib",
        ] {
            let spec = runtime_spec_by_id(id).expect("runtime spec");
            assert!(spec.required, "{id}");
            assert_eq!(spec.expected, "; 0 failed", "{id}");
            assert!(spec.argv.contains(&"cargo"), "{id}");
            assert!(!spec.argv.contains(&"--no-run"), "{id}");
        }
        assert_eq!(COMPILE_ONLY_SPEC.id, "workspace-test-compile");
        assert!(COMPILE_ONLY_SPEC.argv.contains(&"--no-run"));
        assert_eq!(
            RUNTIME_SPECS
                .iter()
                .filter(|spec| spec.id == "workspace-test-compile")
                .count(),
            0
        );
    }

    #[test]
    fn missing_required_argument_exits_before_write() {
        assert_eq!(cli_exit_code(&[]), 2);
        assert_eq!(cli_exit_code(&["--config", "x"]), 2);
        assert_eq!(cli_exit_code(&["--out", "x"]), 2);
        assert_eq!(cli_exit_code(&["--config", "x", "--out", "y"]), 0);
    }

    #[test]
    fn missing_source_blocks_before_directory_creation() {
        let empty = BTreeSet::new();
        assert_eq!(
            preflight_sources(&empty, &["absent-source.py"]),
            Err("missing_source")
        );
        let present = BTreeSet::from(["present.py".to_owned()]);
        assert_eq!(preflight_sources(&present, &["present.py"]), Ok(()));
    }

    #[test]
    fn failed_required_gate_stops_later_commands_and_records_skip() {
        let results = BTreeMap::from([("first".to_owned(), "FAIL".to_owned())]);
        let scheduled = schedule_commands(&[("first", true), ("second", true)], &results);
        assert_eq!(
            scheduled,
            vec![("first".to_owned(), "FAIL"), ("second".to_owned(), "SKIP")]
        );
    }

    #[test]
    fn previous_attempt_points_to_latest_frozen_snapshot() {
        assert_eq!(
            PREVIOUS_ATTEMPT.0,
            "authz-validation-20260919-single-node-005"
        );
        assert_eq!(PREVIOUS_ATTEMPT.1, "BLOCKED");
        assert_eq!(PREVIOUS_ATTEMPT.2, "PASS");
        assert!(PREVIOUS_ATTEMPT.3.contains("immutable snapshot"));
    }

    #[test]
    fn runtime_suites_scenario_aggregates_command_status() {
        let statuses = BTreeMap::from([
            ("runtime-policy-engine-lib".to_owned(), "PASS".to_owned()),
            ("runtime-astral-db-lib".to_owned(), "PASS".to_owned()),
            (
                "runtime-astral-common-gateway-contract".to_owned(),
                "PASS".to_owned(),
            ),
            (
                "runtime-astral-trustgraph-lib".to_owned(),
                "FAIL".to_owned(),
            ),
        ]);
        let names = [
            "runtime-policy-engine-lib",
            "runtime-astral-db-lib",
            "runtime-astral-common-gateway-contract",
            "runtime-astral-trustgraph-lib",
        ];
        assert_eq!(scenario_status(&statuses, &names), "FAIL");
    }

    #[test]
    fn upgraded_verification_gates_are_registered() {
        let specs = UPGRADED_SPECS
            .iter()
            .map(|spec| (spec.id, spec))
            .collect::<BTreeMap<_, _>>();
        let two = specs["e5-bounded-model-two-mutations"];
        assert!(two.assert_two_mutation_model);
        assert!(!two.argv.contains(&"--json"));
        let universal = specs["e5-universal-hypotheses"];
        assert!(universal.assert_universal_hypotheses);
        assert!(universal.timeout_seconds > 1800);
    }

    #[test]
    fn e1_observability_failure_is_not_reported_as_skip() {
        let statuses = BTreeMap::from([("e1-feature-check".to_owned(), "FAIL".to_owned())]);
        let names = [
            "e1-feature-check",
            "e1-feature-production-clippy",
            "e1-policy-engine-feature-tests-build",
            "e1-astral-db-build",
        ];
        assert_eq!(scenario_status(&statuses, &names), "FAIL");
    }

    #[test]
    fn timeout_and_os_error_keep_exact_evidence_fields() {
        let timeout = timeout_outcome("partial stdout", "partial stderr");
        assert_eq!(timeout.status, "UNKNOWN");
        assert_eq!(timeout.exit_code, None);
        assert!(!timeout.log_complete);
        assert_eq!(timeout.stdout_log, "partial stdout");
        assert_eq!(timeout.stderr_log, "partial stderr");
        let os_error = os_error_outcome();
        assert_eq!(os_error.status, "BLOCKED");
        assert_eq!(os_error.exit_code, None);
        assert_eq!(os_error.stderr_log, "OSError");
    }
}
