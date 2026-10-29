use crate::e4_protocol::{Authorization, Decision, Status};
use std::collections::BTreeMap;
use uuid::Uuid;

pub const FAULTS: [&str; 11] = [
    "memory_channel_suspect",
    "memory_invalidation_omission",
    "local_bus_owner_loss",
    "local_bus_overflow",
    "local_bus_unknown_completion",
    "source_commit_unknown",
    "worker_death_sticky",
    "writer_lease_loss",
    "current_pointer_movement",
    "hmac_failure",
    "mysql_unavailable",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HookResult {
    Pass,
    Refused,
    Timeout,
    Disconnect,
    Error(&'static str),
    Missing,
    NonMapping,
    Unproven,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultEvidence {
    pub generation: bool,
    pub compare_and_swap: bool,
    pub audit: bool,
    pub durable_reconcile: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultOutcome {
    pub observed: Option<Decision>,
    pub reason_present: bool,
    pub host_admission: Option<Decision>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultCaseInput {
    pub fault_id: &'static str,
    pub capabilities: HookResult,
    pub fault_supported: bool,
    pub read_only_preflight: bool,
    pub run_scoped_isolation: bool,
    pub preflight: HookResult,
    pub preflight_ok: bool,
    pub authorization_ok: bool,
    pub prepare: HookResult,
    pub prepare_durable_ref: bool,
    pub apply: HookResult,
    pub apply_ref: bool,
    pub observe: HookResult,
    pub outcome: FaultOutcome,
    pub restore: HookResult,
    pub restoration_proven: bool,
    pub reconcile: HookResult,
    pub reconciliation_proven: bool,
    pub proof_ref: bool,
    pub durable_proof: bool,
    pub postcondition: HookResult,
    pub postcondition_ok: Option<bool>,
    pub evidence: FaultEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Stage {
    pub status: Status,
    pub detail: &'static str,
    pub calls: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultCaseReport {
    pub fault_id: &'static str,
    pub operation_id: String,
    pub attempt: u8,
    pub retries: u8,
    pub retry_permitted: bool,
    pub overall: Status,
    pub stages: BTreeMap<&'static str, Stage>,
}

fn stage(status: Status, detail: &'static str, calls: u8) -> Stage {
    Stage {
        status,
        detail,
        calls,
    }
}

fn call_status(result: HookResult, mutable: bool) -> (Status, &'static str) {
    match result {
        HookResult::Pass => (Status::Pass, "ok"),
        HookResult::Refused => (Status::Blocked, "controller_refused"),
        HookResult::Timeout => (Status::Unknown, "controller_timeout"),
        HookResult::Disconnect => (Status::Unknown, "controller_disconnect"),
        HookResult::Error(class) => (
            if mutable {
                Status::Unknown
            } else {
                Status::Blocked
            },
            class,
        ),
        HookResult::Missing => (Status::Blocked, "controller_hook_missing"),
        HookResult::NonMapping => (
            if mutable {
                Status::Unknown
            } else {
                Status::Blocked
            },
            "controller_returned_non_mapping",
        ),
        HookResult::Unproven => (Status::Unknown, "controller_result_unproven"),
    }
}

fn observation_status(hook: HookResult, outcome: FaultOutcome) -> (Status, &'static str) {
    if hook != HookResult::Pass {
        return call_status(hook, true);
    }
    match outcome.observed {
        None => (Status::Blocked, "missing:observed"),
        Some(Decision::Allow) => (Status::Fail, "allow_observed_fail_closed_violation"),
        Some(Decision::Unknown) => (Status::Unknown, "unproven_outcome"),
        Some(Decision::Pending | Decision::Deny) if !outcome.reason_present => {
            (Status::Blocked, "missing:reason_code")
        }
        Some(Decision::Pending | Decision::Deny) => match outcome.host_admission {
            None => (Status::Unknown, "host_admission_not_observed"),
            Some(Decision::Allow) => (Status::Fail, "host_admission_allow_violation"),
            Some(Decision::Unknown) => (Status::Unknown, "host_admission_unknown"),
            Some(Decision::Pending | Decision::Deny) => (Status::Pass, "ok"),
        },
    }
}

fn required_evidence(fault_id: &str) -> &'static [&'static str] {
    match fault_id {
        "current_pointer_movement" | "writer_lease_loss" => &["generation", "compare_and_swap"],
        "hmac_failure" => &["audit"],
        "source_commit_unknown" | "local_bus_unknown_completion" => &["durable_reconcile"],
        _ => &[],
    }
}

fn evidence_status(
    fault_id: &str,
    evidence: FaultEvidence,
    observation_exists: bool,
    reconciliation_proven: bool,
) -> (Status, &'static str) {
    let required = required_evidence(fault_id);
    if required.is_empty() {
        return (Status::Skip, "no_case_specific_evidence_required");
    }
    if !observation_exists && required.iter().all(|item| *item != "durable_reconcile") {
        return (Status::Skip, "no_observation_for_evidence");
    }
    if required.contains(&"durable_reconcile") && !reconciliation_proven {
        return (Status::Unknown, "durable_reconciliation_unproven");
    }
    if required.iter().any(|item| match *item {
        "generation" => !evidence.generation,
        "compare_and_swap" => !evidence.compare_and_swap,
        "audit" => !evidence.audit,
        "durable_reconcile" => !evidence.durable_reconcile,
        _ => true,
    }) {
        return (Status::Blocked, "required_fault_evidence_missing");
    }
    (Status::Pass, "required_fault_evidence_present")
}

pub const OUTCOME_FAULT_MATRIX_ITEMS: [&str; 11] = FAULTS;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultOutcomeVerdict {
    pub index: usize,
    pub fault_id: Option<String>,
    pub status: Status,
    pub reason: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultOutcomeValidation {
    pub kind: &'static str,
    pub fault_matrix_items: Vec<&'static str>,
    pub status: Status,
    pub total: usize,
    pub accepted_fault_ids: Vec<String>,
    pub rejections: Vec<FaultOutcomeVerdict>,
}

pub fn validate_fault_outcomes(outcomes: &[serde_json::Value]) -> FaultOutcomeValidation {
    let mut accepted_fault_ids = Vec::new();
    let mut rejections = Vec::new();
    let reject = |index, fault_id, status, reason| FaultOutcomeVerdict {
        index,
        fault_id,
        status,
        reason,
    };
    for (index, outcome) in outcomes.iter().enumerate() {
        let Some(outcome) = outcome.as_object() else {
            rejections.push(reject(
                index,
                None,
                Status::Blocked,
                "outcome_not_a_mapping",
            ));
            continue;
        };
        let fault_id = outcome
            .get("fault_id")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        let Some(fault_id_value) = fault_id.as_ref() else {
            rejections.push(reject(index, fault_id, Status::Blocked, "missing:fault_id"));
            continue;
        };
        let Some(observed_value) = outcome.get("observed").filter(|value| !value.is_null()) else {
            rejections.push(reject(
                index,
                Some(fault_id_value.clone()),
                Status::Blocked,
                "missing:observed",
            ));
            continue;
        };
        let Some(observed_raw) = observed_value.as_str() else {
            rejections.push(reject(
                index,
                Some(fault_id_value.clone()),
                Status::Blocked,
                "invalid:observed_type",
            ));
            continue;
        };
        let observed = observed_raw.trim().to_ascii_uppercase();
        if observed == "ALLOW" {
            rejections.push(reject(
                index,
                Some(fault_id_value.clone()),
                Status::Fail,
                "allow_observed_fail_closed_violation",
            ));
            continue;
        }
        if observed == "UNKNOWN" {
            rejections.push(reject(
                index,
                Some(fault_id_value.clone()),
                Status::Unknown,
                "unproven_outcome",
            ));
            continue;
        }
        if !matches!(observed.as_str(), "DENY" | "PENDING") {
            rejections.push(reject(
                index,
                Some(fault_id_value.clone()),
                Status::Blocked,
                "unrecognized_observed_value",
            ));
            continue;
        }
        if outcome
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .is_none_or(|reason| reason.trim().is_empty())
        {
            rejections.push(reject(
                index,
                Some(fault_id_value.clone()),
                Status::Blocked,
                "missing:reason_code",
            ));
            continue;
        }
        if let Some(expected_value) = outcome.get("expected").filter(|value| !value.is_null()) {
            let Some(expected_raw) = expected_value.as_str() else {
                rejections.push(reject(
                    index,
                    Some(fault_id_value.clone()),
                    Status::Blocked,
                    "invalid:expected_type",
                ));
                continue;
            };
            let expected = expected_raw.trim().to_ascii_uppercase();
            if expected == "ALLOW" {
                rejections.push(reject(
                    index,
                    Some(fault_id_value.clone()),
                    Status::Fail,
                    "expected_allow_rejected",
                ));
                continue;
            }
            if !matches!(expected.as_str(), "DENY" | "PENDING") {
                rejections.push(reject(
                    index,
                    Some(fault_id_value.clone()),
                    Status::Blocked,
                    "invalid:expected_value",
                ));
                continue;
            }
            if expected != observed {
                rejections.push(reject(
                    index,
                    Some(fault_id_value.clone()),
                    Status::Fail,
                    "expected_mismatch",
                ));
                continue;
            }
        }
        accepted_fault_ids.push(fault_id_value.clone());
    }
    let status = if outcomes.is_empty() {
        Status::Blocked
    } else if rejections.iter().any(|item| item.status == Status::Fail) {
        Status::Fail
    } else if rejections.is_empty() {
        Status::Pass
    } else {
        Status::Blocked
    };
    FaultOutcomeValidation {
        kind: "fault_outcome_validation",
        fault_matrix_items: OUTCOME_FAULT_MATRIX_ITEMS.to_vec(),
        status,
        total: outcomes.len(),
        accepted_fault_ids,
        rejections,
    }
}

fn status_rank(status: Status) -> u8 {
    match status {
        Status::Fail => 0,
        Status::Blocked => 1,
        Status::Unknown => 2,
        Status::Pending => 3,
        Status::Skip => 4,
        Status::Pass => 5,
    }
}

fn worst(statuses: impl IntoIterator<Item = Status>) -> Status {
    statuses
        .into_iter()
        .min_by_key(|status| status_rank(*status))
        .unwrap_or(Status::Blocked)
}

pub fn stable_operation_id(run_id: &str, fault_id: &str) -> Result<String, &'static str> {
    fn safe_id(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 128
            && value.as_bytes()[0].is_ascii_alphanumeric()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    }

    if !safe_id(run_id) || !safe_id(fault_id) {
        return Err("run_id and label must use the safe identifier alphabet");
    }
    let namespace = Uuid::NAMESPACE_URL;
    Ok(Uuid::new_v5(
        &namespace,
        format!("{run_id}:authorization-validation:{fault_id}").as_bytes(),
    )
    .to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HookContext {
    pub run_id: String,
    pub fault_id: String,
    pub operation_id: String,
    pub attempt: u8,
    pub stage: String,
    pub authorization_run_id: String,
    pub token_values_recorded: bool,
}

pub fn build_hook_context(
    run_id: &str,
    fault_id: &str,
    stage: &str,
    authorization: &Authorization<'_>,
) -> Result<HookContext, &'static str> {
    if authorization.run_id != run_id {
        return Err("authorization run_id mismatch");
    }
    let operation_id = stable_operation_id(run_id, &format!("e4-fault:{fault_id}:attempt-1"))?;
    Ok(HookContext {
        run_id: run_id.to_owned(),
        fault_id: fault_id.to_owned(),
        operation_id,
        attempt: 1,
        stage: stage.to_owned(),
        authorization_run_id: authorization.run_id.to_owned(),
        token_values_recorded: false,
    })
}

pub fn run_fault_case(input: &FaultCaseInput, run_id: &str) -> FaultCaseReport {
    let (operation_id, operation_id_status) =
        match stable_operation_id(run_id, &format!("e4-fault:{}:attempt-1", input.fault_id)) {
            Ok(operation_id) => (operation_id, Status::Pass),
            Err(_) => (String::new(), Status::Blocked),
        };
    let mut stages = BTreeMap::new();
    stages.insert(
        "authorization",
        stage(
            operation_id_status,
            if operation_id_status == Status::Pass {
                "operation_id_derived"
            } else {
                "operation_id_derivation_failed"
            },
            0,
        ),
    );
    let valid_fault = FAULTS.contains(&input.fault_id);
    stages.insert(
        "validation",
        stage(
            if valid_fault {
                Status::Pass
            } else {
                Status::Blocked
            },
            if valid_fault {
                "registered_fault"
            } else {
                "unknown_fault_id"
            },
            0,
        ),
    );
    if operation_id_status != Status::Pass {
        return finish(input, operation_id, stages, false);
    }
    if !valid_fault {
        return FaultCaseReport {
            fault_id: input.fault_id,
            operation_id,
            attempt: 1,
            retries: 0,
            retry_permitted: false,
            overall: Status::Blocked,
            stages,
        };
    }

    let (cap_call_status, cap_call_detail) = call_status(input.capabilities, false);
    let capability_status = if cap_call_status != Status::Pass {
        cap_call_status
    } else if !input.fault_supported || !input.read_only_preflight || !input.run_scoped_isolation {
        Status::Blocked
    } else {
        Status::Pass
    };
    let capability_detail = if cap_call_status != Status::Pass {
        cap_call_detail
    } else if !input.fault_supported {
        "fault_not_supported_by_controller"
    } else if !input.read_only_preflight {
        "controller_does_not_declare_read_only_preflight"
    } else if !input.run_scoped_isolation {
        "controller_isolation_not_run_scoped"
    } else {
        "ok"
    };
    stages.insert(
        "capabilities",
        stage(capability_status, capability_detail, 1),
    );
    if capability_status != Status::Pass {
        return finish(input, operation_id, stages, false);
    }

    let (preflight_call_status, preflight_call_detail) = call_status(input.preflight, false);
    let preflight_status = if preflight_call_status != Status::Pass {
        preflight_call_status
    } else if !input.preflight_ok || !input.authorization_ok {
        Status::Blocked
    } else {
        Status::Pass
    };
    let preflight_detail = if preflight_call_status != Status::Pass {
        preflight_call_detail
    } else if !input.preflight_ok {
        "preflight_failed"
    } else if !input.authorization_ok {
        "controller_rejected_authorization"
    } else {
        "ok"
    };
    stages.insert("preflight", stage(preflight_status, preflight_detail, 1));
    if preflight_status != Status::Pass {
        return finish(input, operation_id, stages, false);
    }

    let (prepare_call_status, prepare_call_detail) = call_status(input.prepare, true);
    let prepare_status = if prepare_call_status != Status::Pass {
        prepare_call_status
    } else if !input.prepare_durable_ref {
        Status::Unknown
    } else {
        Status::Pass
    };
    let prepare_detail = if prepare_call_status != Status::Pass {
        prepare_call_detail
    } else if !input.prepare_durable_ref {
        "prepare_durable_ref_missing"
    } else {
        "ok"
    };
    stages.insert("prepare", stage(prepare_status, prepare_detail, 1));
    if prepare_status == Status::Blocked {
        return finish(input, operation_id, stages, false);
    }

    if prepare_status == Status::Pass {
        let (apply_call_status, apply_call_detail) = call_status(input.apply, true);
        let apply_status = if apply_call_status != Status::Pass {
            apply_call_status
        } else if !input.apply_ref {
            Status::Unknown
        } else {
            Status::Pass
        };
        let apply_detail = if apply_call_status != Status::Pass {
            apply_call_detail
        } else if !input.apply_ref {
            "apply_ref_missing"
        } else {
            "ok"
        };
        stages.insert("apply", stage(apply_status, apply_detail, 1));
        if apply_status == Status::Pass {
            let (observe_status, observe_detail) = observation_status(input.observe, input.outcome);
            stages.insert("observe", stage(observe_status, observe_detail, 1));
        } else {
            stages.insert("observe", stage(Status::Skip, "apply_not_proven", 0));
        }
    } else {
        stages.insert(
            "apply",
            stage(Status::Skip, "prepare_unproven_apply_skipped", 0),
        );
        stages.insert("observe", stage(Status::Skip, "prepare_unproven", 0));
    }

    let (restore_call_status, restore_call_detail) = call_status(input.restore, true);
    let restore_status = if restore_call_status == Status::Pass && !input.restoration_proven {
        Status::Unknown
    } else {
        restore_call_status
    };
    stages.insert(
        "restore",
        stage(
            restore_status,
            if restore_call_status == Status::Pass && !input.restoration_proven {
                "restoration_unproven"
            } else {
                restore_call_detail
            },
            1,
        ),
    );

    let (reconcile_call_status, reconcile_call_detail) = call_status(input.reconcile, true);
    let reconciliation_proven = reconcile_call_status == Status::Pass
        && input.reconciliation_proven
        && input.proof_ref
        && input.durable_proof;
    let reconcile_status = if reconcile_call_status != Status::Pass {
        reconcile_call_status
    } else if !input.reconciliation_proven || !input.proof_ref || !input.durable_proof {
        Status::Unknown
    } else {
        Status::Pass
    };
    let reconcile_detail = if reconcile_call_status != Status::Pass {
        reconcile_call_detail
    } else if !input.reconciliation_proven {
        "reconciliation_unproven"
    } else if !input.proof_ref {
        "reconciliation_proof_ref_missing"
    } else if !input.durable_proof {
        "durable_reconciliation_proof_missing"
    } else {
        "ok"
    };
    stages.insert("reconcile", stage(reconcile_status, reconcile_detail, 1));

    let (postcondition_call_status, postcondition_call_detail) =
        call_status(input.postcondition, true);
    let postcondition_status = if postcondition_call_status != Status::Pass {
        postcondition_call_status
    } else {
        match input.postcondition_ok {
            Some(true) => Status::Pass,
            Some(false) => Status::Fail,
            None => Status::Unknown,
        }
    };
    stages.insert(
        "postcondition",
        stage(
            postcondition_status,
            if postcondition_call_status != Status::Pass {
                postcondition_call_detail
            } else {
                match input.postcondition_ok {
                    Some(false) => "postcondition_violation",
                    None => "postcondition_unproven",
                    Some(true) => "ok",
                }
            },
            1,
        ),
    );
    let observation_exists = stages
        .get("observe")
        .is_some_and(|observation| observation.calls > 0 && observation.status == Status::Pass);
    let (evidence_status, evidence_detail) = evidence_status(
        input.fault_id,
        input.evidence,
        observation_exists,
        reconciliation_proven,
    );
    stages.insert("evidence", stage(evidence_status, evidence_detail, 0));

    if observation_exists {
        let (cross_status, cross_detail) = match input.outcome.observed {
            Some(Decision::Allow) => (Status::Fail, "allow_observed_fail_closed_violation"),
            Some(Decision::Unknown) => (Status::Unknown, "unproven_outcome"),
            Some(Decision::Pending | Decision::Deny) if input.outcome.reason_present => {
                (Status::Pass, "reasoned_fail_closed_outcome")
            }
            Some(Decision::Pending | Decision::Deny) => (Status::Blocked, "missing:reason_code"),
            None => (Status::Blocked, "missing:observed"),
        };
        stages.insert("cross_check", stage(cross_status, cross_detail, 0));
    } else {
        stages.insert(
            "cross_check",
            stage(Status::Skip, "no_observation_to_cross_check", 0),
        );
    }

    finish(input, operation_id, stages, reconciliation_proven)
}

fn finish(
    input: &FaultCaseInput,
    operation_id: String,
    stages: BTreeMap<&'static str, Stage>,
    retry_permitted: bool,
) -> FaultCaseReport {
    let overall = worst(
        stages
            .values()
            .filter(|stage| stage.status != Status::Skip)
            .map(|stage| stage.status),
    );
    FaultCaseReport {
        fault_id: input.fault_id,
        operation_id,
        attempt: 1,
        retries: 0,
        retry_permitted,
        overall,
        stages,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatrixReport {
    pub status: Status,
    pub matrix_complete: bool,
    pub missing_faults: Vec<&'static str>,
    pub faults: Vec<FaultCaseReport>,
}

pub fn aggregate_matrix(faults: Vec<FaultCaseReport>, requested_faults: &[&str]) -> MatrixReport {
    let passed = faults
        .iter()
        .filter(|fault| fault.overall == Status::Pass)
        .map(|fault| fault.fault_id)
        .collect::<Vec<_>>();
    let missing_faults = FAULTS
        .iter()
        .copied()
        .filter(|fault| !requested_faults.contains(fault))
        .collect::<Vec<_>>();
    let status = worst(faults.iter().map(|fault| fault.overall));
    let matrix_complete = FAULTS.iter().all(|fault| passed.contains(fault));
    MatrixReport {
        status,
        matrix_complete,
        missing_faults,
        faults,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good(fault_id: &'static str) -> FaultCaseInput {
        FaultCaseInput {
            fault_id,
            capabilities: HookResult::Pass,
            fault_supported: true,
            read_only_preflight: true,
            run_scoped_isolation: true,
            preflight: HookResult::Pass,
            preflight_ok: true,
            authorization_ok: true,
            prepare: HookResult::Pass,
            prepare_durable_ref: true,
            apply: HookResult::Pass,
            apply_ref: true,
            observe: HookResult::Pass,
            outcome: FaultOutcome {
                observed: Some(Decision::Pending),
                reason_present: true,
                host_admission: Some(Decision::Deny),
            },
            restore: HookResult::Pass,
            restoration_proven: true,
            reconcile: HookResult::Pass,
            reconciliation_proven: true,
            proof_ref: true,
            durable_proof: true,
            postcondition: HookResult::Pass,
            postcondition_ok: Some(true),
            evidence: FaultEvidence {
                generation: true,
                compare_and_swap: true,
                audit: true,
                durable_reconcile: true,
            },
        }
    }

    #[test]
    fn prepare_is_a_hard_gate_and_unknown_prepare_runs_recovery_once() {
        let mut refused = good("local_bus_overflow");
        refused.prepare_durable_ref = false;
        refused.prepare = HookResult::Refused;
        let refused = run_fault_case(&refused, "run-1");
        assert_eq!(refused.overall, Status::Blocked);
        assert!(!refused.stages.contains_key("apply"));
        assert!(!refused.stages.contains_key("restore"));
        assert!(!refused.stages.contains_key("reconcile"));

        let mut unknown = good("local_bus_unknown_completion");
        unknown.prepare_durable_ref = false;
        let unknown = run_fault_case(&unknown, "run-1");
        assert_eq!(unknown.overall, Status::Unknown);
        assert_eq!(unknown.stages["apply"].status, Status::Skip);
        assert_eq!(unknown.stages["apply"].calls, 0);
        assert_eq!(unknown.stages["restore"].calls, 1);
        assert_eq!(unknown.stages["reconcile"].calls, 1);
        assert_eq!(unknown.retries, 0);
    }

    #[test]
    fn recovery_path_is_once_and_retry_requires_durable_reconciliation() {
        let mut input = good("source_commit_unknown");
        input.apply = HookResult::Timeout;
        let result = run_fault_case(&input, "run-1");
        assert_eq!(result.overall, Status::Unknown);
        assert_eq!(result.stages["apply"].status, Status::Unknown);
        assert_eq!(result.stages["apply"].calls, 1);
        assert_eq!(result.stages["observe"].status, Status::Skip);
        assert_eq!(result.stages["restore"].calls, 1);
        assert_eq!(result.stages["reconcile"].calls, 1);
        assert_eq!(result.stages["reconcile"].status, Status::Pass);
        assert_eq!(result.stages["postcondition"].calls, 1);
        assert_eq!(result.stages["evidence"].status, Status::Pass);
        assert!(result.retry_permitted);
        assert_eq!(result.retries, 0);

        let mut unproven = good("source_commit_unknown");
        unproven.apply = HookResult::Timeout;
        unproven.reconcile = HookResult::Disconnect;
        unproven.reconciliation_proven = false;
        let unproven = run_fault_case(&unproven, "run-1");
        assert_eq!(unproven.overall, Status::Unknown);
        assert_eq!(unproven.stages["apply"].status, Status::Unknown);
        assert_eq!(unproven.stages["apply"].calls, 1);
        assert_eq!(unproven.stages["reconcile"].status, Status::Unknown);
        assert_eq!(unproven.stages["restore"].calls, 1);
        assert_eq!(unproven.stages["reconcile"].calls, 1);
        assert_eq!(unproven.stages["evidence"].status, Status::Unknown);
        assert!(!unproven.retry_permitted);
        assert_eq!(unproven.retries, 0);

        let mut disconnect = good("local_bus_owner_loss");
        disconnect.observe = HookResult::Disconnect;
        let observed = run_fault_case(&disconnect, "run-1");
        assert_eq!(observed.overall, Status::Unknown);
        assert_eq!(observed.stages["observe"].detail, "controller_disconnect");
        assert_eq!(observed.stages["cross_check"].status, Status::Skip);
        assert_eq!(observed.stages["restore"].calls, 1);
        assert_eq!(observed.stages["reconcile"].calls, 1);

        let mut refused = good("worker_death_sticky");
        refused.apply = HookResult::Refused;
        let refused = run_fault_case(&refused, "run-1");
        assert_eq!(refused.overall, Status::Blocked);
        assert_eq!(refused.stages["apply"].status, Status::Blocked);
        assert_eq!(refused.stages["observe"].status, Status::Skip);
        assert_eq!(refused.stages["restore"].calls, 1);
        assert_eq!(refused.stages["reconcile"].calls, 1);
        assert_eq!(refused.retries, 0);
    }

    #[test]
    fn case_evidence_requirements_and_observation_fail_closed_are_distinct() {
        for fault in ["current_pointer_movement", "writer_lease_loss"] {
            let mut missing_generation = good(fault);
            missing_generation.evidence.generation = false;
            assert_eq!(
                run_fault_case(&missing_generation, "run-1").stages["evidence"].status,
                Status::Blocked,
                "{fault} requires generation evidence"
            );

            let mut missing_cas = good(fault);
            missing_cas.evidence.compare_and_swap = false;
            assert_eq!(
                run_fault_case(&missing_cas, "run-1").stages["evidence"].status,
                Status::Blocked,
                "{fault} requires compare-and-swap evidence"
            );
        }

        let mut hmac = good("hmac_failure");
        hmac.evidence.audit = false;
        assert_eq!(
            run_fault_case(&hmac, "run-1").stages["evidence"].status,
            Status::Blocked
        );
        let mut valid_hmac = good("hmac_failure");
        valid_hmac.evidence.audit = true;
        assert_eq!(
            run_fault_case(&valid_hmac, "run-1").stages["evidence"].status,
            Status::Pass
        );

        for fault in ["source_commit_unknown", "local_bus_unknown_completion"] {
            let mut unknown = good(fault);
            unknown.evidence.durable_reconcile = false;
            assert_eq!(
                run_fault_case(&unknown, "run-1").stages["evidence"].status,
                Status::Blocked,
                "{fault} requires durable reconciliation evidence"
            );
        }

        let mut allow = good("memory_channel_suspect");
        allow.outcome.observed = Some(Decision::Allow);
        assert_eq!(
            run_fault_case(&allow, "run-1").stages["observe"].status,
            Status::Fail
        );

        let mut host_allow = good("memory_invalidation_omission");
        host_allow.outcome.host_admission = Some(Decision::Allow);
        assert_eq!(
            run_fault_case(&host_allow, "run-1").stages["observe"].status,
            Status::Fail
        );
    }

    #[test]
    fn runtime_preconditions_gate_mutation_and_leave_audit_free_of_controller_values() {
        let mut unsupported = good("writer_lease_loss");
        unsupported.fault_supported = false;
        let report = run_fault_case(&unsupported, "run-1");
        assert_eq!(report.overall, Status::Blocked);
        assert_eq!(
            report.stages["capabilities"].detail,
            "fault_not_supported_by_controller"
        );
        assert!(!report.stages.contains_key("preflight"));
        assert!(!report.stages.contains_key("prepare"));

        let mut unsafe_preflight = good("local_bus_overflow");
        unsafe_preflight.read_only_preflight = false;
        let report = run_fault_case(&unsafe_preflight, "run-1");
        assert_eq!(report.stages["capabilities"].status, Status::Blocked);
        assert!(!report.stages.contains_key("prepare"));

        let mut wrong_isolation = good("local_bus_owner_loss");
        wrong_isolation.run_scoped_isolation = false;
        assert_eq!(
            run_fault_case(&wrong_isolation, "run-1").stages["capabilities"].detail,
            "controller_isolation_not_run_scoped"
        );

        let mut unauthorized = good("source_commit_unknown");
        unauthorized.authorization_ok = false;
        let report = run_fault_case(&unauthorized, "run-1");
        assert_eq!(
            report.stages["preflight"].detail,
            "controller_rejected_authorization"
        );
        assert!(!report.stages.contains_key("prepare"));

        for preflight in [
            HookResult::Error("controller_error"),
            HookResult::NonMapping,
        ] {
            let mut rejected = good("worker_death_sticky");
            rejected.preflight = preflight;
            let report = run_fault_case(&rejected, "run-1");
            assert_eq!(report.overall, Status::Blocked);
            assert_eq!(report.stages["preflight"].calls, 1);
            assert!(!report.stages.contains_key("prepare"));
            assert!(!report.stages.contains_key("apply"));
            assert!(!report.stages.contains_key("restore"));
            assert!(!report.stages.contains_key("reconcile"));
        }

        let malformed = validate_fault_outcomes(&[
            serde_json::json!({"fault_id":"a","observed":"ALLOW","reason":"r"}),
            serde_json::json!({"fault_id":"b","observed":"UNKNOWN","reason":"r"}),
            serde_json::json!({"fault_id":"c","reason":"r"}),
            serde_json::json!({"fault_id":"d","observed":"DENY"}),
        ]);
        assert_eq!(malformed.kind, "fault_outcome_validation");
        assert_eq!(malformed.fault_matrix_items, OUTCOME_FAULT_MATRIX_ITEMS);
        assert_eq!(malformed.status, Status::Fail);
        assert_eq!(malformed.total, 4);
        assert_eq!(
            malformed
                .rejections
                .iter()
                .map(|entry| entry.reason)
                .collect::<Vec<_>>(),
            [
                "allow_observed_fail_closed_violation",
                "unproven_outcome",
                "missing:observed",
                "missing:reason_code",
            ]
        );
    }

    #[test]
    fn restore_reconcile_postcondition_and_outcome_aggregation_fail_closed() {
        let mut restore = good("local_bus_owner_loss");
        restore.restore = HookResult::Error("controller_error");
        let restore_report = run_fault_case(&restore, "run-1");
        assert_eq!(restore_report.stages["restore"].status, Status::Unknown);

        let mut apply_error = good("worker_death_sticky");
        apply_error.apply = HookResult::Error("ValueError");
        let apply_error_report = run_fault_case(&apply_error, "run-1");
        assert_eq!(apply_error_report.overall, Status::Unknown);
        assert_eq!(apply_error_report.stages["apply"].detail, "ValueError");
        assert_eq!(apply_error_report.stages["observe"].status, Status::Skip);
        assert_eq!(apply_error_report.stages["restore"].calls, 1);
        assert_eq!(apply_error_report.stages["reconcile"].calls, 1);
        assert_eq!(apply_error_report.retries, 0);

        let mut missing_ref = good("local_bus_unknown_completion");
        missing_ref.proof_ref = false;
        let report = run_fault_case(&missing_ref, "run-1");
        assert_eq!(
            report.stages["reconcile"].detail,
            "reconciliation_proof_ref_missing"
        );
        assert!(!report.retry_permitted);

        let mut no_postcondition = good("mysql_unavailable");
        no_postcondition.postcondition_ok = None;
        assert_eq!(
            run_fault_case(&no_postcondition, "run-1").stages["postcondition"].detail,
            "postcondition_unproven"
        );

        let invalid_expected = validate_fault_outcomes(&[
            serde_json::json!({"fault_id":"x","observed":"DENY","reason":"r","expected":"ALLOW"}),
            serde_json::json!({"fault_id":"y","observed":"DENY","reason":"r","expected":"MAYBE"}),
            serde_json::json!({"fault_id":"z","observed":"DENY","reason":"r","expected":"PENDING"}),
        ]);
        assert_eq!(invalid_expected.status, Status::Fail);
        assert_eq!(invalid_expected.accepted_fault_ids, Vec::<String>::new());
        assert_eq!(
            invalid_expected
                .rejections
                .iter()
                .map(|entry| entry.reason)
                .collect::<Vec<_>>(),
            [
                "expected_allow_rejected",
                "invalid:expected_value",
                "expected_mismatch"
            ]
        );
        assert_eq!(validate_fault_outcomes(&[]).status, Status::Blocked);

        let non_mapping = validate_fault_outcomes(&[serde_json::json!("not-a-mapping")]);
        assert_eq!(non_mapping.status, Status::Blocked);
        assert_eq!(non_mapping.rejections[0].reason, "outcome_not_a_mapping");
        let invalid_types = validate_fault_outcomes(&[
            serde_json::json!({"fault_id":"typed","observed":false,"reason":"r"}),
            serde_json::json!({"fault_id":"expected","observed":"DENY","reason":"r","expected":false}),
            serde_json::json!({"observed":"DENY","reason":"r"}),
        ]);
        assert_eq!(invalid_types.status, Status::Blocked);
        assert_eq!(
            invalid_types
                .rejections
                .iter()
                .map(|entry| entry.reason)
                .collect::<Vec<_>>(),
            [
                "invalid:observed_type",
                "invalid:expected_type",
                "missing:fault_id"
            ]
        );
    }

    #[test]
    fn empty_fault_outcome_input_is_blocked() {
        let report = validate_fault_outcomes(&[]);
        assert_eq!(report.status, Status::Blocked);
        assert_eq!(report.total, 0);
        assert!(report.accepted_fault_ids.is_empty());
        assert!(report.rejections.is_empty());
    }

    #[test]
    fn outcome_validation_does_not_mutate_supplied_json() {
        let outcomes = vec![
            serde_json::json!({"fault_id":"a","observed":"PENDING","reason":"r"}),
            serde_json::json!({"fault_id":"b","observed":"ALLOW","reason":"r"}),
        ];
        let before = outcomes.clone();

        let report = validate_fault_outcomes(&outcomes);

        assert_eq!(outcomes, before);
        assert_eq!(report.status, Status::Fail);
        assert_eq!(report.total, 2);
        assert_eq!(report.accepted_fault_ids, ["a"]);
    }

    #[test]
    fn fault_matrix_is_complete_only_when_every_registered_case_passes() {
        let inputs = FAULTS.map(good);
        let reports = inputs
            .iter()
            .map(|input| run_fault_case(input, "run-1"))
            .collect::<Vec<_>>();
        let complete = aggregate_matrix(reports.clone(), &FAULTS);
        assert_eq!(complete.status, Status::Pass);
        assert!(complete.matrix_complete);
        assert!(complete.missing_faults.is_empty());

        let subset = aggregate_matrix(reports[..1].to_vec(), &[FAULTS[0]]);
        assert!(!subset.matrix_complete);
        assert_eq!(subset.missing_faults.len(), FAULTS.len() - 1);
        assert_eq!(subset.status, Status::Pass);

        let mut incomplete = good("source_commit_unknown");
        incomplete.apply = HookResult::Timeout;
        incomplete.reconcile = HookResult::Disconnect;
        incomplete.reconciliation_proven = false;
        let incomplete = run_fault_case(&incomplete, "run-1");
        assert_eq!(incomplete.overall, Status::Unknown);
        assert_eq!(incomplete.stages["apply"].status, Status::Unknown);
        assert_eq!(incomplete.stages["apply"].calls, 1);
        assert_eq!(incomplete.stages["reconcile"].status, Status::Unknown);
        assert_eq!(incomplete.stages["reconcile"].calls, 1);
        assert_eq!(incomplete.stages["evidence"].status, Status::Unknown);
        assert!(!incomplete.retry_permitted);
        let failed_matrix = aggregate_matrix(vec![incomplete], &FAULTS);
        assert_eq!(failed_matrix.status, Status::Unknown);
        assert!(!failed_matrix.matrix_complete);
        assert!(failed_matrix.missing_faults.is_empty());
        assert_eq!(
            stable_operation_id("run-1", "e4-fault:memory_channel_suspect:attempt-1"),
            Ok("4dc22a28-770a-5eb6-b4ab-6e5138cde29f".to_owned())
        );
        assert_eq!(
            stable_operation_id("run-1", "e4-fault:source_commit_unknown:attempt-1"),
            Ok("9144814f-668e-573f-9924-5e6e2c150fa9".to_owned())
        );
        let ids = FAULTS
            .iter()
            .map(|fault| {
                stable_operation_id("run-1", &format!("e4-fault:{fault}:attempt-1")).unwrap()
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(ids.len(), FAULTS.len());
        for (fault_id, evidence_key) in [
            ("current_pointer_movement", "generation"),
            ("current_pointer_movement", "compare_and_swap"),
            ("writer_lease_loss", "generation"),
            ("writer_lease_loss", "compare_and_swap"),
            ("hmac_failure", "audit"),
            ("source_commit_unknown", "durable_reconcile"),
            ("local_bus_unknown_completion", "durable_reconcile"),
        ] {
            assert!(
                required_evidence(fault_id).contains(&evidence_key),
                "{fault_id} requires {evidence_key}"
            );
        }
        assert_eq!(
            aggregate_matrix(reports.clone(), &FAULTS).missing_faults,
            Vec::<&str>::new()
        );
        assert!(
            stable_operation_id("run id", "e4-fault:memory_channel_suspect:attempt-1").is_err()
        );
    }

    #[test]
    fn prepare_timeout_skips_apply_and_runs_recovery_once() {
        let mut input = good("memory_channel_suspect");
        input.prepare = HookResult::Timeout;
        let result = run_fault_case(&input, "run-1");
        assert_eq!(result.overall, Status::Unknown);
        assert_eq!(result.stages["prepare"].detail, "controller_timeout");
        assert_eq!(result.stages["apply"].status, Status::Skip);
        assert_eq!(result.stages["apply"].calls, 0);
        assert_eq!(result.stages["restore"].calls, 1);
        assert_eq!(result.stages["reconcile"].calls, 1);
        assert_eq!(result.retries, 0);
    }

    #[test]
    fn apply_timeout_and_disconnect_are_unknown_without_retry() {
        for hook in [HookResult::Timeout, HookResult::Disconnect] {
            let mut input = good("memory_channel_suspect");
            input.apply = hook;
            let result = run_fault_case(&input, "run-1");
            assert_eq!(result.overall, Status::Unknown, "{hook:?}");
            assert_eq!(result.stages["apply"].calls, 1, "{hook:?}");
            assert_eq!(result.stages["observe"].status, Status::Skip, "{hook:?}");
            assert_eq!(result.stages["restore"].calls, 1, "{hook:?}");
            assert_eq!(result.stages["reconcile"].calls, 1, "{hook:?}");
            assert_eq!(result.retries, 0, "{hook:?}");
        }
    }

    #[test]
    fn hook_context_carries_identity_and_authorization_without_mutation() {
        let auth = Authorization {
            run_id: "run-1",
            exec_level: "Exec-L3",
            isolate_token: "isolate-run-1-a",
            approval_token: "approve-run-1-b",
            allowlist: &["memory_channel_suspect"],
            approved_by: "human-operator",
        };
        let original = auth.clone();
        let context =
            build_hook_context("run-1", "memory_channel_suspect", "apply", &auth).unwrap();
        assert_eq!(context.run_id, "run-1");
        assert_eq!(context.fault_id, "memory_channel_suspect");
        assert_eq!(context.stage, "apply");
        assert_eq!(context.attempt, 1);
        assert_eq!(
            context.operation_id,
            stable_operation_id("run-1", "e4-fault:memory_channel_suspect:attempt-1").unwrap()
        );
        assert_eq!(context.authorization_run_id, "run-1");
        assert!(!context.token_values_recorded);
        assert_eq!(auth, original);
        assert!(build_hook_context("other-run", "memory_channel_suspect", "apply", &auth).is_err());
    }
}
