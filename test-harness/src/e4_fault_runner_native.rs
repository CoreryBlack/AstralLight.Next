//! Native E4 fault-controller invocation over an injected controller port.
//! Every hook is called at most once; context/authorization are passed without
//! storing token values; results are scrubbed and bounded.

use crate::dependency_profiles;
use crate::e4_fault_lifecycle::{stable_operation_id, HookContext};
use crate::e4_protocol::{Authorization, Decision};
use crate::node_adapter_contract::scrub_text;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub trait FaultController {
    fn capabilities(&mut self) -> Result<Value, String>;
    fn preflight(&mut self, context: &HookContext) -> Result<Value, String>;
    fn prepare(&mut self, context: &HookContext) -> Result<Value, String>;
    fn apply(&mut self, context: &HookContext) -> Result<Value, String>;
    fn observe(&mut self, context: &HookContext) -> Result<Value, String>;
    fn restore(&mut self, context: &HookContext) -> Result<Value, String>;
    fn reconcile(&mut self, context: &HookContext) -> Result<Value, String>;
    fn verify_postcondition(&mut self, context: &HookContext) -> Result<Value, String>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StageRecord {
    pub status: &'static str,
    pub detail: String,
    pub calls: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultRunResult {
    pub overall: &'static str,
    pub stages: BTreeMap<&'static str, StageRecord>,
    pub calls: Vec<(String, String)>,
    pub context: Vec<HookContext>,
    pub authorization_problems: Vec<&'static str>,
    pub token_values_recorded: bool,
    pub integration_claim: &'static str,
}

fn record(
    result: &mut FaultRunResult,
    stage: &'static str,
    status: &'static str,
    detail: impl Into<String>,
) {
    let detail = scrub_text(&detail.into(), 120);
    result.stages.insert(
        stage,
        StageRecord {
            status,
            detail,
            calls: 1,
        },
    );
}

fn skipped(result: &mut FaultRunResult, stage: &'static str) {
    result.stages.insert(
        stage,
        StageRecord {
            status: "SKIP",
            detail: "not_reached".to_owned(),
            calls: 0,
        },
    );
}

fn worst(statuses: impl IntoIterator<Item = &'static str>) -> &'static str {
    let mut values = statuses.into_iter().collect::<Vec<_>>();
    values.sort_unstable_by_key(|status| match *status {
        "FAIL" => 0,
        "BLOCKED" => 1,
        "UNKNOWN" => 2,
        "PENDING" => 3,
        "SKIP" => 4,
        "PASS" => 5,
        _ => 6,
    });
    values.first().copied().unwrap_or("BLOCKED")
}

/// Evaluates one hook outcome with stage-specific fail-closed checks: an
/// `Ok` payload still has to carry the evidence its stage owes — capabilities
/// must cover the fault, prepare must carry a durable ref before apply may
/// run, an ALLOW observed during a fault is a hard FAIL, and reconcile needs
/// durable proof.
fn stage_outcome(
    result: &mut FaultRunResult,
    stage: &'static str,
    outcome: Result<Value, String>,
    mutable: bool,
    fault_id: &str,
) -> bool {
    let value = match outcome {
        Ok(value) => value,
        Err(error) => {
            let status = if mutable { "UNKNOWN" } else { "BLOCKED" };
            record(result, stage, status, error);
            return false;
        }
    };
    let (status, detail) = match stage {
        "capabilities" => {
            let covers = value
                .get("supported_faults")
                .and_then(Value::as_array)
                .is_some_and(|list| list.iter().any(|item| item.as_str() == Some(fault_id)));
            let read_only = value.get("read_only_preflight").and_then(Value::as_bool) == Some(true);
            if covers && read_only {
                ("PASS", "ok".to_owned())
            } else {
                ("BLOCKED", "capabilities_do_not_cover_fault".to_owned())
            }
        }
        "prepare" => {
            let prepare_ref = value
                .get("prepare_ref")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if prepare_ref.is_empty() {
                ("UNKNOWN", "missing_durable_prepare_ref".to_owned())
            } else {
                ("PASS", prepare_ref.to_owned())
            }
        }
        "observe" => {
            let decision = value
                .get("decision")
                .and_then(Value::as_str)
                .or_else(|| value.get("observed").and_then(Value::as_str))
                .unwrap_or_default();
            match decision {
                "ALLOW" => ("FAIL", "observed_allow_during_fault".to_owned()),
                "PENDING" | "DENY" | "UNKNOWN" => ("PASS", decision.to_owned()),
                _ => ("UNKNOWN", "missing_observed_decision".to_owned()),
            }
        }
        "reconcile" => {
            let proof = value
                .get("proof")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if proof.is_empty() {
                ("UNKNOWN", "missing_durable_reconcile_proof".to_owned())
            } else {
                ("PASS", proof.to_owned())
            }
        }
        _ => {
            let detail = value
                .get("prepare_ref")
                .and_then(Value::as_str)
                .or_else(|| value.get("state").and_then(Value::as_str))
                .unwrap_or("ok")
                .to_owned();
            ("PASS", detail)
        }
    };
    record(result, stage, status, detail);
    status == "PASS"
}

pub fn run_fault_case(
    authorization: &Authorization<'_>,
    fault_id: &str,
    profile: &str,
    controller: &mut dyn FaultController,
) -> FaultRunResult {
    let faults = dependency_profiles::profile_faults(profile).unwrap_or_default();
    let validation = crate::e4_protocol::validate_authorization(authorization, fault_id, faults);
    let operation_label = format!("e4-fault:{fault_id}:attempt-1");
    let operation_id =
        stable_operation_id(authorization.run_id, &operation_label).unwrap_or_default();
    let mut result = FaultRunResult {
        overall: "PASS",
        stages: BTreeMap::new(),
        calls: Vec::new(),
        context: Vec::new(),
        authorization_problems: validation.problems.clone(),
        token_values_recorded: false,
        integration_claim: "BLOCKED",
    };
    if !validation.problems.is_empty() {
        result.authorization_problems = validation.problems;
        result.overall = "BLOCKED";
        record(
            &mut result,
            "authorization",
            "BLOCKED",
            "invalid_authorization",
        );
        return result;
    }
    let stages = [
        ("preflight", true),
        ("prepare", false),
        ("apply", true),
        ("observe", true),
        ("restore", true),
        ("reconcile", true),
        ("verify_postcondition", false),
    ];
    if !stage_outcome(
        &mut result,
        "capabilities",
        controller.capabilities(),
        false,
        fault_id,
    ) {
        result.overall = "BLOCKED";
        return result;
    }
    let mut context = HookContext {
        run_id: authorization.run_id.to_owned(),
        fault_id: fault_id.to_owned(),
        operation_id: operation_id.clone(),
        attempt: 1,
        stage: "preflight".to_owned(),
        authorization_run_id: authorization.run_id.to_owned(),
        token_values_recorded: false,
    };
    let mut apply_failed = false;
    // When preflight or prepare fails, apply and observe must never run, but
    // the recovery path (restore/reconcile/verify_postcondition) still runs
    // exactly once — an unproven prepare never leaves the system in an
    // unreconciled state.
    let mut recovery_only = false;
    for (stage, mutable) in stages {
        if recovery_only && matches!(stage, "apply" | "observe") {
            skipped(&mut result, stage);
            continue;
        }
        if stage == "observe" && apply_failed {
            skipped(&mut result, "observe");
            continue;
        }
        context.stage = stage.to_owned();
        result.context.push(context.clone());
        result.calls.push((stage.to_owned(), operation_id.clone()));
        let outcome = match stage {
            "preflight" => controller.preflight(&context),
            "prepare" => controller.prepare(&context),
            "apply" => controller.apply(&context),
            "observe" => controller.observe(&context),
            "restore" => controller.restore(&context),
            "reconcile" => controller.reconcile(&context),
            "verify_postcondition" => controller.verify_postcondition(&context),
            _ => unreachable!(),
        };
        let passed = stage_outcome(&mut result, stage, outcome, mutable, fault_id);
        if !passed && matches!(stage, "preflight" | "prepare") {
            recovery_only = true;
        }
        if !passed && stage == "apply" {
            apply_failed = true;
            skipped(&mut result, "observe");
        }
    }
    result.overall = worst(result.stages.values().map(|stage| stage.status));
    result
}

pub fn run_fault_matrix(
    authorization: &Authorization<'_>,
    profile: &str,
    controller: &mut dyn FaultController,
) -> Value {
    let faults = dependency_profiles::profile_faults(profile).unwrap_or_default();
    let mut cases = Vec::new();
    for fault in faults {
        let result = run_fault_case(authorization, fault, profile, controller);
        cases.push(json!({
            "faultId": fault,
            "status": result.overall,
            "stages": result.stages.iter().map(|(name, stage)| {
                (name.to_string(), json!({
                    "status": stage.status,
                    "detail": stage.detail,
                    "calls": stage.calls,
                }))
            }).collect::<BTreeMap<_, _>>(),
        }));
    }
    let overall = if cases.iter().any(|case| case["status"] == "FAIL") {
        "FAIL"
    } else if cases.iter().any(|case| case["status"] == "UNKNOWN") {
        "UNKNOWN"
    } else if cases.iter().any(|case| case["status"] == "BLOCKED") {
        "BLOCKED"
    } else if cases.iter().any(|case| case["status"] == "PENDING") {
        "PENDING"
    } else {
        "PASS"
    };
    json!({
        "overall": overall,
        "integration_claim": "BLOCKED",
        "cases": cases,
    })
}

pub fn decision_value(decision: Decision) -> Value {
    json!(match decision {
        Decision::Allow => "ALLOW",
        Decision::Deny => "DENY",
        Decision::Pending => "PENDING",
        Decision::Unknown => "UNKNOWN",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e4_fault_lifecycle::HookContext;
    use serde_json::json;

    struct FakeController {
        fail: Option<(&'static str, &'static str)>,
        calls: Vec<String>,
        contexts: Vec<HookContext>,
        prepare_ref: Option<String>,
    }

    impl FakeController {
        fn call(&mut self, stage: &'static str, context: &HookContext) -> Result<Value, String> {
            self.calls.push(stage.to_owned());
            self.contexts.push(context.clone());
            if let Some((target, kind)) = self.fail {
                if target == stage {
                    return Err(kind.to_owned());
                }
            }
            Ok(match stage {
                "prepare" => json!({
                    "state": "prepared",
                    "prepare_ref": self.prepare_ref,
                }),
                "apply" => json!({"state": "applied"}),
                "observe" => json!({"state": "observed", "decision": "PENDING"}),
                "restore" => json!({"state": "restored"}),
                "reconcile" => json!({"state": "reconciled", "proof": "durable"}),
                "verify_postcondition" => json!({"state": "verified"}),
                _ => json!({"state": "ok"}),
            })
        }
    }

    impl FaultController for FakeController {
        fn capabilities(&mut self) -> Result<Value, String> {
            self.calls.push("capabilities".to_owned());
            Ok(json!({
                "supported_faults": dependency_profiles::profile_faults("native-single-node").unwrap(),
                "read_only_preflight": true,
            }))
        }
        fn preflight(&mut self, context: &HookContext) -> Result<Value, String> {
            self.call("preflight", context)
        }
        fn prepare(&mut self, context: &HookContext) -> Result<Value, String> {
            self.call("prepare", context)
        }
        fn apply(&mut self, context: &HookContext) -> Result<Value, String> {
            self.call("apply", context)
        }
        fn observe(&mut self, context: &HookContext) -> Result<Value, String> {
            self.call("observe", context)
        }
        fn restore(&mut self, context: &HookContext) -> Result<Value, String> {
            self.call("restore", context)
        }
        fn reconcile(&mut self, context: &HookContext) -> Result<Value, String> {
            self.call("reconcile", context)
        }
        fn verify_postcondition(&mut self, context: &HookContext) -> Result<Value, String> {
            self.call("verify_postcondition", context)
        }
    }

    /// A controller whose observe hook reports an ALLOW during the fault —
    /// the one outcome the runner must never fold into PASS.
    #[derive(Default)]
    struct AllowingController {
        calls: Vec<String>,
    }

    impl FaultController for AllowingController {
        fn capabilities(&mut self) -> Result<Value, String> {
            Ok(json!({
                "supported_faults": dependency_profiles::profile_faults("native-single-node").unwrap(),
                "read_only_preflight": true,
            }))
        }
        fn preflight(&mut self, _context: &HookContext) -> Result<Value, String> {
            self.calls.push("preflight".to_owned());
            Ok(json!({"state": "ok"}))
        }
        fn prepare(&mut self, _context: &HookContext) -> Result<Value, String> {
            self.calls.push("prepare".to_owned());
            Ok(json!({"state": "prepared", "prepare_ref": "prepare-ref-1"}))
        }
        fn apply(&mut self, _context: &HookContext) -> Result<Value, String> {
            self.calls.push("apply".to_owned());
            Ok(json!({"state": "applied"}))
        }
        fn observe(&mut self, _context: &HookContext) -> Result<Value, String> {
            self.calls.push("observe".to_owned());
            Ok(json!({"state": "observed", "decision": "ALLOW"}))
        }
        fn restore(&mut self, _context: &HookContext) -> Result<Value, String> {
            self.calls.push("restore".to_owned());
            Ok(json!({"state": "restored"}))
        }
        fn reconcile(&mut self, _context: &HookContext) -> Result<Value, String> {
            self.calls.push("reconcile".to_owned());
            Ok(json!({"state": "reconciled", "proof": "durable"}))
        }
        fn verify_postcondition(&mut self, _context: &HookContext) -> Result<Value, String> {
            self.calls.push("verify_postcondition".to_owned());
            Ok(json!({"state": "verified"}))
        }
    }

    /// A controller whose reconcile hook returns no durable proof.
    #[derive(Default)]
    struct ProoflessReconcileController {
        calls: Vec<String>,
    }

    impl FaultController for ProoflessReconcileController {
        fn capabilities(&mut self) -> Result<Value, String> {
            Ok(json!({
                "supported_faults": dependency_profiles::profile_faults("native-single-node").unwrap(),
                "read_only_preflight": true,
            }))
        }
        fn preflight(&mut self, _context: &HookContext) -> Result<Value, String> {
            self.calls.push("preflight".to_owned());
            Ok(json!({"state": "ok"}))
        }
        fn prepare(&mut self, _context: &HookContext) -> Result<Value, String> {
            self.calls.push("prepare".to_owned());
            Ok(json!({"state": "prepared", "prepare_ref": "prepare-ref-1"}))
        }
        fn apply(&mut self, _context: &HookContext) -> Result<Value, String> {
            self.calls.push("apply".to_owned());
            Ok(json!({"state": "applied"}))
        }
        fn observe(&mut self, _context: &HookContext) -> Result<Value, String> {
            self.calls.push("observe".to_owned());
            Ok(json!({"state": "observed", "decision": "PENDING"}))
        }
        fn restore(&mut self, _context: &HookContext) -> Result<Value, String> {
            self.calls.push("restore".to_owned());
            Ok(json!({"state": "restored"}))
        }
        fn reconcile(&mut self, _context: &HookContext) -> Result<Value, String> {
            self.calls.push("reconcile".to_owned());
            Ok(json!({"state": "reconciled"}))
        }
        fn verify_postcondition(&mut self, _context: &HookContext) -> Result<Value, String> {
            self.calls.push("verify_postcondition".to_owned());
            Ok(json!({"state": "verified"}))
        }
    }

    fn authorization<'a>(faults: &'a [&'a str]) -> Authorization<'a> {
        Authorization {
            run_id: "authz-validation-e4-test",
            exec_level: "Exec-L3",
            isolate_token: "isolate-authz-validation-e4-test-a",
            approval_token: "approve-authz-validation-e4-test-b",
            allowlist: faults,
            approved_by: "human-operator",
        }
    }

    fn faults() -> &'static [&'static str] {
        dependency_profiles::profile_faults("native-single-node").unwrap()
    }

    #[test]
    fn full_fake_controller_lifecycle_passes_and_calls_each_hook_once() {
        let auth = authorization(faults());
        let original = auth.clone();
        let mut controller = FakeController {
            fail: None,
            calls: Vec::new(),
            contexts: Vec::new(),
            prepare_ref: Some("prepare-ref-1".to_owned()),
        };
        let result = run_fault_case(
            &auth,
            "memory_channel_suspect",
            "native-single-node",
            &mut controller,
        );
        assert_eq!(result.overall, "PASS");
        assert_eq!(
            controller.calls,
            [
                "capabilities",
                "preflight",
                "prepare",
                "apply",
                "observe",
                "restore",
                "reconcile",
                "verify_postcondition"
            ]
        );
        assert_eq!(controller.calls.len(), 8);
        assert_eq!(auth, original);
        assert!(!result.token_values_recorded);
        assert_eq!(result.context.len(), 7);
        assert_eq!(result.context[0].run_id, "authz-validation-e4-test");
        assert_eq!(result.context[0].fault_id, "memory_channel_suspect");
        assert_eq!(result.context[0].attempt, 1);
        assert_eq!(result.context[0].stage, "preflight");
        assert!(!result.context[0].operation_id.is_empty());
    }

    #[test]
    fn apply_timeout_is_unknown_and_does_not_retry() {
        let auth = authorization(faults());
        let mut controller = FakeController {
            fail: Some(("apply", "timeout")),
            calls: Vec::new(),
            contexts: Vec::new(),
            prepare_ref: Some("prepare-ref-1".to_owned()),
        };
        let result = run_fault_case(
            &auth,
            "memory_channel_suspect",
            "native-single-node",
            &mut controller,
        );
        assert_eq!(result.overall, "UNKNOWN");
        assert_eq!(result.stages["apply"].status, "UNKNOWN");
        assert_eq!(result.stages["observe"].status, "SKIP");
        assert_eq!(
            controller
                .calls
                .iter()
                .filter(|call| *call == "apply")
                .count(),
            1
        );
        assert_eq!(result.stages["restore"].calls, 1);
        assert_eq!(result.stages["reconcile"].calls, 1);
        assert_eq!(result.overall, "UNKNOWN");
    }

    #[test]
    fn prepare_error_skips_apply_but_runs_recovery_once() {
        let auth = authorization(faults());
        let mut controller = FakeController {
            fail: Some(("prepare", "controller_error")),
            calls: Vec::new(),
            contexts: Vec::new(),
            prepare_ref: Some("prepare-ref-1".to_owned()),
        };
        let result = run_fault_case(
            &auth,
            "memory_channel_suspect",
            "native-single-node",
            &mut controller,
        );
        assert_ne!(result.overall, "PASS");
        assert!(!controller.calls.contains(&"apply".to_owned()));
        assert_eq!(result.stages["apply"].status, "SKIP");
        assert_eq!(result.stages["observe"].status, "SKIP");
        // The recovery path still runs exactly once after a failed prepare.
        assert_eq!(result.stages["restore"].calls, 1);
        assert_eq!(result.stages["reconcile"].calls, 1);
        assert_eq!(result.stages["verify_postcondition"].calls, 1);
        assert_eq!(result.stages["prepare"].status, "BLOCKED");
    }

    #[test]
    fn prepare_without_durable_ref_never_applies() {
        let auth = authorization(faults());
        let mut controller = FakeController {
            fail: None,
            calls: Vec::new(),
            contexts: Vec::new(),
            prepare_ref: None,
        };
        let result = run_fault_case(
            &auth,
            "memory_channel_suspect",
            "native-single-node",
            &mut controller,
        );
        assert_eq!(result.stages["prepare"].status, "UNKNOWN");
        assert_eq!(
            result.stages["prepare"].detail,
            "missing_durable_prepare_ref"
        );
        assert_eq!(result.stages["apply"].status, "SKIP");
        assert!(!controller.calls.contains(&"apply".to_owned()));
        assert_eq!(result.stages["restore"].calls, 1);
    }

    #[test]
    fn observed_allow_during_a_fault_is_a_hard_fail() {
        let auth = authorization(faults());
        let mut controller = AllowingController::default();
        let result = run_fault_case(
            &auth,
            "memory_channel_suspect",
            "native-single-node",
            &mut controller,
        );
        assert_eq!(result.stages["observe"].status, "FAIL");
        assert_eq!(
            result.stages["observe"].detail,
            "observed_allow_during_fault"
        );
        assert_eq!(result.overall, "FAIL");
    }

    #[test]
    fn reconcile_without_durable_proof_stays_unknown() {
        let auth = authorization(faults());
        let mut controller = ProoflessReconcileController::default();
        let result = run_fault_case(
            &auth,
            "memory_channel_suspect",
            "native-single-node",
            &mut controller,
        );
        assert_eq!(result.stages["reconcile"].status, "UNKNOWN");
        assert_eq!(
            result.stages["reconcile"].detail,
            "missing_durable_reconcile_proof"
        );
        assert_ne!(result.overall, "PASS");
    }

    #[test]
    fn invalid_authorization_blocks_before_any_controller_call() {
        let auth = authorization(faults());
        let mut invalid = Authorization {
            run_id: "!!",
            ..auth.clone()
        };
        invalid.run_id = "!!";
        let mut controller = FakeController {
            fail: None,
            calls: Vec::new(),
            contexts: Vec::new(),
            prepare_ref: Some("prepare-ref-1".to_owned()),
        };
        let result = run_fault_case(
            &invalid,
            "memory_channel_suspect",
            "native-single-node",
            &mut controller,
        );
        assert_eq!(result.overall, "BLOCKED");
        assert!(result.authorization_problems.contains(&"invalid:run_id"));
        assert!(controller.calls.is_empty());
    }

    #[test]
    fn controller_derived_strings_are_scrubbed_and_bounded() {
        let auth = authorization(faults());
        let mut controller = FakeController {
            fail: None,
            calls: Vec::new(),
            contexts: Vec::new(),
            prepare_ref: Some(
                "ref at fault-node.example.invalid and https://secret.example.com/x".to_owned(),
            ),
        };
        let result = run_fault_case(
            &auth,
            "memory_channel_suspect",
            "native-single-node",
            &mut controller,
        );
        let detail = &result.stages["prepare"].detail;
        assert!(detail.contains("[redacted-host]"));
        assert!(!detail.contains("fault-node.example.invalid"));
        assert!(!detail.contains("example.com"));
        assert!(detail.len() <= 120);
    }

    #[test]
    fn profile_matrix_aggregates_cases_and_keeps_integration_blocked() {
        assert_eq!(
            faults(),
            dependency_profiles::profile_faults("native-single-node").unwrap()
        );
        assert!(dependency_profiles::profile_faults("redis-compat").is_none());
        let auth = authorization(faults());
        let mut controller = FakeController {
            fail: None,
            calls: Vec::new(),
            contexts: Vec::new(),
            prepare_ref: Some("prepare-ref-1".to_owned()),
        };
        let matrix = run_fault_matrix(&auth, "native-single-node", &mut controller);
        assert_eq!(matrix["overall"], "PASS");
        assert_eq!(matrix["integration_claim"], "BLOCKED");
        assert_eq!(matrix["cases"].as_array().unwrap().len(), faults().len());

        let mut failing = FakeController {
            fail: Some(("apply", "timeout")),
            calls: Vec::new(),
            contexts: Vec::new(),
            prepare_ref: Some("prepare-ref-1".to_owned()),
        };
        let matrix = run_fault_matrix(&auth, "native-single-node", &mut failing);
        assert_eq!(matrix["overall"], "UNKNOWN");
    }

    #[test]
    fn hook_context_keeps_run_fault_operation_and_stage_identity() {
        let auth = authorization(faults());
        let mut controller = FakeController {
            fail: None,
            calls: Vec::new(),
            contexts: Vec::new(),
            prepare_ref: Some("prepare-ref-1".to_owned()),
        };
        let result = run_fault_case(&auth, "hmac_failure", "native-single-node", &mut controller);
        assert_eq!(result.overall, "PASS");
        for (index, context) in result.context.iter().enumerate() {
            assert_eq!(context.run_id, auth.run_id);
            assert_eq!(context.fault_id, "hmac_failure");
            assert_eq!(context.attempt, 1);
            assert_eq!(context.authorization_run_id, auth.run_id);
            assert!(!context.token_values_recorded);
            if index > 0 {
                assert_ne!(context.stage, result.context[index - 1].stage);
            }
        }
    }
}
