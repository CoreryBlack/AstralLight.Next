//! Native offline E4 fault-driver contracts: plan construction, default live
//! gate, matrix gate and CLI shape.
//!
//! No controller is constructed or invoked. The live fault matrix remains
//! explicitly BLOCKED until a platform controller and an approved Exec-L3 run
//! exist.

use crate::dependency_profiles;
use crate::e4_protocol::{self, Authorization};
use serde_json::{json, Value};

pub const DEFAULT_PROFILE: &str = "native-single-node";
pub const LEGACY_PROFILE: &str = "redis-compat";
pub const MAX_ATTEMPTS: u8 = 1;
pub const LIVE_FAULT_MATRIX_INTEGRATION: &str = "BLOCKED";
pub const LIVE_INTEGRATION_REASON: &str = "No platform-specific fault controller exists in this repository: the TrustGraph test-control plane (astral-trustgraph/src/api/test_control.rs) exposes a read-only /internal/test-control/worker-id probe only, and no generic safe fault primitive exists. Live fault injection is Exec-L3 and requires a future user-approved campaign to inject a FaultController satisfying the documented contract; this module never applies faults.";

pub const HOOKS: [&str; 8] = [
    "capabilities",
    "preflight",
    "prepare",
    "apply",
    "observe",
    "restore",
    "reconcile",
    "verify_postcondition",
];

pub fn profile_faults(profile: &str) -> Result<&'static [&'static str], String> {
    dependency_profiles::profile_faults(profile)
        .ok_or_else(|| format!("unknown profile: {profile}"))
}

pub fn build_fault_plan(run_id: &str, campaign_id: &str, profile: &str) -> Result<Value, String> {
    let faults = profile_faults(profile)?;
    let cases = faults
        .iter()
        .map(|fault| json!({"fault_id": fault, "status": "PLANNED"}))
        .collect::<Vec<_>>();
    let hooks = HOOKS
        .iter()
        .enumerate()
        .map(|(index, hook)| {
            json!({
                "hook": hook,
                "returns": if index == 0 {
                    "mapping with supported_faults + run-scoped isolation + read_only_preflight"
                } else {
                    "mapping"
                },
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "kind": "e4_fault_plan",
        "runId": run_id,
        "campaignId": campaign_id,
        "profile": profile,
        "attempts": MAX_ATTEMPTS,
        "cases": cases,
        "controller_contract": {"hooks": hooks},
        "live_fault_matrix_integration": {
            "status": LIVE_FAULT_MATRIX_INTEGRATION,
            "reason": LIVE_INTEGRATION_REASON,
        },
    }))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CliOutcome {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn cli(argv: &[&str]) -> CliOutcome {
    if argv.is_empty() {
        let plan = build_fault_plan("offline-plan", "offline-plan", DEFAULT_PROFILE)
            .expect("default profile");
        return CliOutcome {
            exit_code: 0,
            stdout: format!(
                "live fault matrix: BLOCKED\n{}",
                serde_json::to_string_pretty(&plan).expect("plan json")
            ),
            stderr: String::new(),
        };
    }
    if argv.contains(&"--help") {
        return CliOutcome {
            exit_code: 0,
            stdout: "usage: e4_fault_driver [--plan] [--profile PROFILE]\nThis module ships no fault primitive and never executes faults.\n"
                .to_owned(),
            stderr: String::new(),
        };
    }
    if argv.contains(&"--run") {
        return CliOutcome {
            exit_code: 2,
            stdout: String::new(),
            stderr: "unrecognized arguments: --run\n".to_owned(),
        };
    }
    let profile = argv
        .iter()
        .position(|arg| *arg == "--profile")
        .and_then(|index| argv.get(index + 1))
        .copied()
        .unwrap_or(DEFAULT_PROFILE);
    let plan = match build_fault_plan("offline-plan", "offline-plan", profile) {
        Ok(plan) => plan,
        Err(error) => {
            return CliOutcome {
                exit_code: 2,
                stdout: String::new(),
                stderr: format!("{error}\n"),
            }
        }
    };
    CliOutcome {
        exit_code: 0,
        stdout: format!(
            "live fault matrix: BLOCKED\n{}",
            serde_json::to_string_pretty(&plan).expect("plan json")
        ),
        stderr: String::new(),
    }
}

fn blocked_with(reason: &str) -> Value {
    json!({
        "overall": "BLOCKED",
        "integration_claim": LIVE_FAULT_MATRIX_INTEGRATION,
        // Structural zero-contact: this driver holds no controller at all, so
        // no contact path exists to count — the number is not a measurement.
        "controller_contact": "none_possible",
        "stages": {
            "live_gate": {"detail": reason},
        },
    })
}

pub fn run_fault_case(
    authorization: &Authorization<'_>,
    fault_id: &str,
    allow_live_execution: bool,
    profile: &str,
) -> Value {
    let faults = profile_faults(profile).unwrap_or_default();
    let validation = e4_protocol::validate_authorization(authorization, fault_id, faults);
    if !allow_live_execution {
        return blocked_with("allow_live_execution_false");
    }
    if !validation.problems.is_empty() {
        return json!({
            "overall": "BLOCKED",
            "integration_claim": LIVE_FAULT_MATRIX_INTEGRATION,
            "controller_contact": "none_possible",
            "authorization_problems": validation.problems,
            "authorization": {"token_values_recorded": false},
            "stages": {"authorization": {"detail": "invalid_authorization"}},
        });
    }
    if profile == DEFAULT_PROFILE {
        return json!({
            "overall": "BLOCKED",
            "integration_claim": LIVE_FAULT_MATRIX_INTEGRATION,
            "controller_contact": "none_possible",
            "stages": {"profile_execution": {"detail": "native_fault_controller_not_implemented"}},
        });
    }
    // Legacy/offline profiles have no real controller either; never claim PASS.
    blocked_with("controller_not_injected")
}

pub fn run_fault_matrix(
    authorization: &Authorization<'_>,
    allow_live_execution: bool,
    profile: &str,
) -> Value {
    let faults = profile_faults(profile).unwrap_or_default();
    let validation = e4_protocol::validate_authorization(authorization, faults[0], faults);
    if !allow_live_execution {
        return blocked_with("allow_live_execution_false");
    }
    if !validation.problems.is_empty() {
        return json!({
            "overall": "BLOCKED",
            "integration_claim": LIVE_FAULT_MATRIX_INTEGRATION,
            "controller_contact": "none_possible",
            "authorization_problems": validation.problems,
            "authorization": {"token_values_recorded": false},
        });
    }
    json!({
        "overall": "BLOCKED",
        "integration_claim": LIVE_FAULT_MATRIX_INTEGRATION,
        "controller_contact": "none_possible",
        "stages": {"profile_execution": {"detail": "native_fault_controller_not_implemented"}},
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUN_ID: &str = "authz-validation-e4-test";
    const ISOLATE_TOKEN: &str = "isolate-authz-validation-e4-test-a";
    const APPROVAL_TOKEN: &str = "approve-authz-validation-e4-test-b";

    fn authorization<'a>(faults: &'a [&'a str]) -> Authorization<'a> {
        Authorization {
            run_id: RUN_ID,
            exec_level: "Exec-L3",
            isolate_token: ISOLATE_TOKEN,
            approval_token: APPROVAL_TOKEN,
            allowlist: faults,
            approved_by: "human-operator",
        }
    }

    #[test]
    fn plan_marks_every_case_planned_and_integration_blocked() {
        let plan = build_fault_plan(RUN_ID, "campaign-1", DEFAULT_PROFILE).expect("plan");
        assert_eq!(plan["kind"], "e4_fault_plan");
        assert_eq!(plan["profile"], DEFAULT_PROFILE);
        assert_eq!(plan["attempts"], 1);
        let expected = profile_faults(DEFAULT_PROFILE).unwrap();
        assert_eq!(
            plan["cases"]
                .as_array()
                .unwrap()
                .iter()
                .map(|case| case["fault_id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            expected.to_vec()
        );
        assert!(plan["cases"]
            .as_array()
            .unwrap()
            .iter()
            .all(|case| case["status"] == "PLANNED"));
        assert_eq!(plan["live_fault_matrix_integration"]["status"], "BLOCKED");
        assert!(plan["live_fault_matrix_integration"]["reason"]
            .as_str()
            .unwrap()
            .contains("test_control.rs"));
        assert_eq!(
            plan["controller_contract"]["hooks"]
                .as_array()
                .unwrap()
                .iter()
                .map(|hook| hook["hook"].as_str().unwrap())
                .collect::<Vec<_>>(),
            HOOKS
        );
        assert!(plan["controller_contract"]["hooks"][0]["returns"]
            .as_str()
            .unwrap()
            .contains("supported_faults"));
        assert!(plan.get("controller").is_none());
    }

    #[test]
    fn module_integration_claim_is_blocked() {
        assert_eq!(LIVE_FAULT_MATRIX_INTEGRATION, "BLOCKED");
        assert!(LIVE_INTEGRATION_REASON.contains("test_control.rs"));
    }

    #[test]
    fn default_cli_prints_plan_and_blocked() {
        let outcome = cli(&[]);
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.stdout.contains("BLOCKED"));
        assert!(outcome.stdout.contains("memory_channel_suspect"));
        assert!(!outcome.stdout.contains("redis_unavailable"));
        let plan: Value =
            serde_json::from_str(&outcome.stdout[outcome.stdout.find('{').unwrap()..]).unwrap();
        assert_eq!(plan["kind"], "e4_fault_plan");
        assert_eq!(plan["profile"], "native-single-node");
    }

    #[test]
    fn plan_flag_prints_the_same_plan() {
        let outcome = cli(&["--plan", "--profile", LEGACY_PROFILE]);
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.stdout.contains("live_fault_matrix_integration"));
        assert!(outcome.stdout.contains("\"status\": \"BLOCKED\""));
    }

    #[test]
    fn no_execution_flag_exists() {
        let outcome = cli(&["--run"]);
        assert_eq!(outcome.exit_code, 2);
        assert!(outcome.stdout.is_empty());
    }

    #[test]
    fn help_exits_zero_without_executing_anything() {
        let outcome = cli(&["--help"]);
        assert_eq!(outcome.exit_code, 0);
        assert!(outcome.stdout.contains("fault primitive"));
        assert!(outcome.stdout.contains("--plan"));
    }

    #[test]
    fn default_live_gate_blocks_without_controller_contact() {
        let faults = profile_faults(DEFAULT_PROFILE).unwrap();
        let auth = authorization(faults);
        let result = run_fault_case(&auth, "memory_channel_suspect", false, DEFAULT_PROFILE);
        assert_eq!(result["overall"], "BLOCKED");
        assert_eq!(
            result["stages"]["live_gate"]["detail"],
            "allow_live_execution_false"
        );
    }

    #[test]
    fn matrix_default_live_gate_blocks_without_controller_contact() {
        let faults = profile_faults(DEFAULT_PROFILE).unwrap();
        let auth = authorization(faults);
        let result = run_fault_matrix(&auth, false, DEFAULT_PROFILE);
        assert_eq!(result["overall"], "BLOCKED");
        assert_eq!(result["integration_claim"], "BLOCKED");
    }

    #[test]
    fn matrix_bad_authorization_blocked_before_contact() {
        let faults = profile_faults(DEFAULT_PROFILE).unwrap();
        let mut auth = authorization(faults);
        auth.run_id = "!!";
        let result = run_fault_matrix(&auth, true, DEFAULT_PROFILE);
        assert_eq!(result["overall"], "BLOCKED");
        assert!(result["authorization_problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "invalid:run_id"));
    }

    #[test]
    fn native_live_execution_is_explicitly_blocked_before_controller_contact() {
        let faults = profile_faults(DEFAULT_PROFILE).unwrap();
        let auth = authorization(faults);
        let result = run_fault_case(&auth, faults[0], true, DEFAULT_PROFILE);
        assert_eq!(result["overall"], "BLOCKED");
        assert_eq!(
            result["stages"]["profile_execution"]["detail"],
            "native_fault_controller_not_implemented"
        );
        assert_eq!(result["controller_contact"], "none_possible");
    }
}
