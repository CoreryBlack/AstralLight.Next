use serde_json::{json, Value};

pub const MAX_ATTEMPTS: u8 = 1;
pub const MAX_STORED_STRING: usize = 120;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Status {
    Fail,
    Blocked,
    Unknown,
    Pending,
    Skip,
    Pass,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fail => "FAIL",
            Self::Blocked => "BLOCKED",
            Self::Unknown => "UNKNOWN",
            Self::Pending => "PENDING",
            Self::Skip => "SKIP",
            Self::Pass => "PASS",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Pending,
    Deny,
    Allow,
    Unknown,
}

impl Decision {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "PENDING" => Some(Self::Pending),
            "DENY" => Some(Self::Deny),
            "ALLOW" => Some(Self::Allow),
            "UNKNOWN" => Some(Self::Unknown),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation<'a> {
    pub observed: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub host_admission: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationVerdict {
    pub status: Status,
    pub detail: Option<&'static str>,
    pub observed: Option<Decision>,
    pub host_admission: Option<Decision>,
}

pub fn classify_observation(observation: Observation<'_>) -> ObservationVerdict {
    let Some(observed_raw) = observation.observed else {
        return ObservationVerdict {
            status: Status::Blocked,
            detail: Some("missing:observed"),
            observed: None,
            host_admission: None,
        };
    };
    let Some(observed) = Decision::parse(observed_raw) else {
        return ObservationVerdict {
            status: Status::Blocked,
            detail: Some("unrecognized_observed_value"),
            observed: None,
            host_admission: None,
        };
    };
    match observed {
        Decision::Allow => {
            return ObservationVerdict {
                status: Status::Fail,
                detail: Some("allow_observed_fail_closed_violation"),
                observed: Some(observed),
                host_admission: None,
            };
        }
        Decision::Unknown => {
            return ObservationVerdict {
                status: Status::Unknown,
                detail: Some("unproven_outcome"),
                observed: Some(observed),
                host_admission: None,
            };
        }
        Decision::Pending | Decision::Deny => {}
    }
    if observation
        .reason
        .is_none_or(|reason| reason.trim().is_empty())
    {
        return ObservationVerdict {
            status: Status::Blocked,
            detail: Some("missing:reason_code"),
            observed: Some(observed),
            host_admission: None,
        };
    }
    let Some(host_raw) = observation.host_admission else {
        return ObservationVerdict {
            status: Status::Unknown,
            detail: Some("host_admission_not_observed"),
            observed: Some(observed),
            host_admission: None,
        };
    };
    let Some(host_admission) = Decision::parse(host_raw) else {
        return ObservationVerdict {
            status: Status::Blocked,
            detail: Some("unrecognized_host_admission"),
            observed: Some(observed),
            host_admission: None,
        };
    };
    let (status, detail) = match host_admission {
        Decision::Allow => (Status::Fail, Some("host_admission_allow_violation")),
        Decision::Unknown => (Status::Unknown, Some("host_admission_unknown")),
        Decision::Pending | Decision::Deny => (Status::Pass, None),
    };
    ObservationVerdict {
        status,
        detail,
        observed: Some(observed),
        host_admission: Some(host_admission),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconcileEvidence<'a> {
    pub status: Status,
    pub reconciled: bool,
    pub proof_ref: Option<&'a str>,
    pub durable_proof: bool,
}

pub fn retry_permitted(evidence: ReconcileEvidence<'_>) -> bool {
    evidence.status == Status::Pass
        && evidence.reconciled
        && evidence.durable_proof
        && evidence
            .proof_ref
            .is_some_and(|value| !value.trim().is_empty())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyOutcome {
    ProvenApplied,
    Refused,
    Timeout,
    Disconnect,
    Error,
    Unproven,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryOutcome {
    pub status: Status,
    pub restoration_proven: bool,
    pub reconciliation_proven: bool,
    pub postcondition_proven: bool,
    pub retry_permitted: bool,
    pub apply_calls: u8,
    pub observe_calls: u8,
    pub restore_calls: u8,
    pub reconcile_calls: u8,
    pub postcondition_calls: u8,
}

pub fn execute_recovery_protocol(
    apply: ApplyOutcome,
    observation: Option<ObservationVerdict>,
    restore_proven: bool,
    reconcile: ReconcileEvidence<'_>,
    postcondition: Status,
) -> RecoveryOutcome {
    let apply_status = match apply {
        ApplyOutcome::ProvenApplied => Status::Pass,
        ApplyOutcome::Refused => Status::Blocked,
        ApplyOutcome::Timeout
        | ApplyOutcome::Disconnect
        | ApplyOutcome::Error
        | ApplyOutcome::Unproven => Status::Unknown,
    };
    let observation_status = observation
        .map(|value| value.status)
        .unwrap_or(Status::Skip);
    let restore_status = if restore_proven {
        Status::Pass
    } else {
        Status::Unknown
    };
    let reconcile_status = if retry_permitted(reconcile) {
        Status::Pass
    } else {
        Status::Unknown
    };
    let statuses = [
        apply_status,
        observation_status,
        restore_status,
        reconcile_status,
        postcondition,
    ];
    let status = statuses.into_iter().min().unwrap_or(Status::Blocked);
    RecoveryOutcome {
        status,
        restoration_proven: restore_status == Status::Pass,
        reconciliation_proven: reconcile_status == Status::Pass,
        postcondition_proven: postcondition == Status::Pass,
        retry_permitted: reconcile_status == Status::Pass,
        apply_calls: 1,
        observe_calls: u8::from(apply == ApplyOutcome::ProvenApplied),
        restore_calls: 1,
        reconcile_calls: 1,
        postcondition_calls: 1,
    }
}

pub fn scrub_and_bound(value: &str) -> String {
    let mut output = String::with_capacity(value.len().min(MAX_STORED_STRING));
    let chars = value.chars().collect::<Vec<_>>();
    let mut index = 0;
    while index < chars.len() && output.len() < MAX_STORED_STRING {
        if chars[index..].starts_with(&['h', 't', 't', 'p', ':', '/', '/'])
            || chars[index..].starts_with(&['h', 't', 't', 'p', 's', ':', '/', '/'])
        {
            output.push_str("[redacted-host]");
            while index < chars.len() && !chars[index].is_whitespace() {
                index += 1;
            }
            continue;
        }
        if chars[index].is_ascii_digit() {
            let mut end = index;
            while end < chars.len() && (chars[end].is_ascii_digit() || chars[end] == '.') {
                end += 1;
            }
            let candidate = chars[index..end].iter().collect::<String>();
            let segments = candidate.split('.').collect::<Vec<_>>();
            if segments.len() == 4
                && segments
                    .iter()
                    .all(|segment| !segment.is_empty() && segment.parse::<u8>().is_ok())
            {
                output.push_str("[redacted-host]");
                index = end;
                continue;
            }
        }
        if chars[index].is_ascii_alphanumeric() {
            let mut end = index;
            while end < chars.len()
                && (chars[end].is_ascii_alphanumeric() || chars[end] == '.' || chars[end] == '-')
            {
                end += 1;
            }
            let candidate = chars[index..end].iter().collect::<String>();
            if candidate.contains('.')
                && [
                    "com", "net", "org", "edu", "gov", "io", "dev", "app", "local", "internal",
                    "lan", "example", "test", "invalid",
                ]
                .iter()
                .any(|suffix| {
                    candidate
                        .to_ascii_lowercase()
                        .ends_with(&format!(".{suffix}"))
                })
            {
                output.push_str("[redacted-host]");
                index = end;
                continue;
            }
        }
        output.push(chars[index]);
        index += 1;
    }
    if output.len() > MAX_STORED_STRING {
        while !output.is_char_boundary(MAX_STORED_STRING) {
            output.pop();
        }
        output.truncate(MAX_STORED_STRING);
    }
    output
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authorization<'a> {
    pub run_id: &'a str,
    pub exec_level: &'a str,
    pub isolate_token: &'a str,
    pub approval_token: &'a str,
    pub allowlist: &'a [&'a str],
    pub approved_by: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationValidation {
    pub problems: Vec<&'static str>,
    pub token_values_recorded: bool,
}

fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

pub fn validate_authorization(
    auth: &Authorization<'_>,
    fault_id: &str,
    allowed_faults: &[&str],
) -> AuthorizationValidation {
    let mut problems = Vec::new();
    if !safe_id(auth.run_id) {
        problems.push("invalid:run_id");
    }
    if auth.exec_level != "Exec-L3" {
        problems.push("invalid:exec_level");
    }
    if auth.approved_by.trim().is_empty() || auth.approved_by.len() > 120 {
        problems.push("invalid:approved_by");
    }
    for (field, token) in [
        ("isolate_token", auth.isolate_token),
        ("approval_token", auth.approval_token),
    ] {
        if !safe_id(token) {
            problems.push(if field == "isolate_token" {
                "invalid:isolate_token"
            } else {
                "invalid:approval_token"
            });
        } else if !auth.run_id.is_empty() && !token.contains(auth.run_id) {
            problems.push(if field == "isolate_token" {
                "not_run_scoped:isolate_token"
            } else {
                "not_run_scoped:approval_token"
            });
        }
    }
    if auth.isolate_token == auth.approval_token && safe_id(auth.isolate_token) {
        problems.push("tokens_not_distinct");
    }
    if auth.allowlist.is_empty()
        || auth
            .allowlist
            .iter()
            .any(|item| !allowed_faults.contains(item))
    {
        problems.push("invalid:allowlist");
    }
    if !allowed_faults.contains(&fault_id) {
        problems.push("invalid:fault_id");
    } else if !auth.allowlist.contains(&fault_id) {
        problems.push("fault_not_in_allowlist");
    }
    AuthorizationValidation {
        problems,
        token_values_recorded: false,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerCapabilities<'a> {
    pub supported_faults: &'a [&'a str],
    pub isolation: &'a str,
    pub run_id: &'a str,
    pub read_only_preflight: bool,
}

pub fn preflight_allowed(
    fault_id: &str,
    capabilities: ControllerCapabilities<'_>,
    preflight_ok: Option<bool>,
    authorization_ok: Option<bool>,
) -> Result<(), &'static str> {
    if !capabilities.supported_faults.contains(&fault_id) {
        return Err("fault_not_supported_by_controller");
    }
    if !capabilities.read_only_preflight {
        return Err("controller_does_not_declare_read_only_preflight");
    }
    if !safe_id(capabilities.isolation) || !capabilities.isolation.contains(capabilities.run_id) {
        return Err("controller_isolation_not_run_scoped");
    }
    if preflight_ok != Some(true) {
        return Err("preflight_failed");
    }
    if authorization_ok != Some(true) {
        return Err("controller_rejected_authorization");
    }
    Ok(())
}

pub fn plan_is_blocked_by_default(profile: &str, execution_flag_present: bool) -> Value {
    json!({
        "profile": profile,
        "status": "PLANNED",
        "executionFlagPresent": execution_flag_present,
        "liveFaultMatrixIntegration": "BLOCKED",
        "attempts": MAX_ATTEMPTS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUN: &str = "authz-validation-e4-test";
    const FAULTS: [&str; 2] = ["redis_unavailable", "unknown_ack"];

    fn auth<'a>() -> Authorization<'a> {
        Authorization {
            run_id: RUN,
            exec_level: "Exec-L3",
            isolate_token: "isolate-authz-validation-e4-test-a1",
            approval_token: "approve-authz-validation-e4-test-b2",
            allowlist: &FAULTS,
            approved_by: "approved-offline-fixture",
        }
    }

    fn proven_reconcile() -> ReconcileEvidence<'static> {
        ReconcileEvidence {
            status: Status::Pass,
            reconciled: true,
            proof_ref: Some("proof-ref-1"),
            durable_proof: true,
        }
    }

    #[test]
    fn authorization_is_run_scoped_distinct_allowlisted_and_token_free() {
        let validation = validate_authorization(&auth(), "redis_unavailable", &FAULTS);
        assert!(validation.problems.is_empty());
        assert!(!validation.token_values_recorded);

        let mut bad = auth();
        bad.approval_token = "approve-other-run";
        let invalid = validate_authorization(&bad, "redis_unavailable", &FAULTS);
        assert!(invalid.problems.contains(&"not_run_scoped:approval_token"));
        assert!(validate_authorization(&auth(), "not-registered", &FAULTS)
            .problems
            .contains(&"invalid:fault_id"));
    }

    #[test]
    fn preflight_must_be_read_only_run_scoped_and_fault_specific() {
        let caps = ControllerCapabilities {
            supported_faults: &FAULTS,
            isolation: "isolate-authz-validation-e4-test-run-1",
            run_id: RUN,
            read_only_preflight: true,
        };
        assert_eq!(
            preflight_allowed("redis_unavailable", caps.clone(), Some(true), Some(true)),
            Ok(())
        );
        assert_eq!(
            preflight_allowed("disk_full", caps.clone(), Some(true), Some(true)),
            Err("fault_not_supported_by_controller")
        );
        assert_eq!(
            preflight_allowed(
                "redis_unavailable",
                ControllerCapabilities {
                    read_only_preflight: false,
                    ..caps.clone()
                },
                Some(true),
                Some(true)
            ),
            Err("controller_does_not_declare_read_only_preflight")
        );
        assert_eq!(
            preflight_allowed(
                "redis_unavailable",
                ControllerCapabilities {
                    isolation: "isolate-other-run",
                    ..caps
                },
                Some(true),
                Some(true)
            ),
            Err("controller_isolation_not_run_scoped")
        );
    }

    #[test]
    fn observations_are_fail_closed_and_preserve_the_reason_gate() {
        let pass = classify_observation(Observation {
            observed: Some("pending"),
            reason: Some("AUTHORIZATION_PENDING"),
            host_admission: Some("deny"),
        });
        assert_eq!(pass.status, Status::Pass);
        assert_eq!(pass.observed, Some(Decision::Pending));
        assert_eq!(
            classify_observation(Observation {
                observed: Some("ALLOW"),
                reason: Some("unexpected"),
                host_admission: Some("ALLOW"),
            })
            .status,
            Status::Fail
        );
        assert_eq!(
            classify_observation(Observation {
                observed: Some("DENY"),
                reason: Some("NO_MATCH"),
                host_admission: Some("ALLOW"),
            })
            .detail,
            Some("host_admission_allow_violation")
        );
        assert_eq!(
            classify_observation(Observation {
                observed: Some("UNKNOWN"),
                reason: None,
                host_admission: None,
            })
            .status,
            Status::Unknown
        );
        assert_eq!(
            classify_observation(Observation {
                observed: Some("MAYBE"),
                reason: Some("x"),
                host_admission: Some("DENY"),
            })
            .status,
            Status::Blocked
        );
    }

    #[test]
    fn apply_runs_once_recovery_runs_once_and_retry_requires_durable_proof() {
        let recovered = execute_recovery_protocol(
            ApplyOutcome::Timeout,
            None,
            true,
            proven_reconcile(),
            Status::Pass,
        );
        assert_eq!(recovered.status, Status::Unknown);
        assert_eq!(recovered.apply_calls, 1);
        assert_eq!(recovered.observe_calls, 0);
        assert_eq!(recovered.restore_calls, 1);
        assert_eq!(recovered.reconcile_calls, 1);
        assert_eq!(recovered.postcondition_calls, 1);
        assert!(recovered.retry_permitted);

        let unknown = execute_recovery_protocol(
            ApplyOutcome::Timeout,
            None,
            true,
            ReconcileEvidence {
                status: Status::Unknown,
                reconciled: false,
                proof_ref: None,
                durable_proof: false,
            },
            Status::Unknown,
        );
        assert_eq!(unknown.status, Status::Unknown);
        assert!(!unknown.retry_permitted);
        assert_eq!(unknown.apply_calls, 1);
    }

    #[test]
    fn unproven_apply_skips_observe_but_refusal_and_violations_remain_visible() {
        let apply_unknown = execute_recovery_protocol(
            ApplyOutcome::Unproven,
            None,
            false,
            ReconcileEvidence {
                status: Status::Unknown,
                reconciled: false,
                proof_ref: Some("ref"),
                durable_proof: false,
            },
            Status::Unknown,
        );
        assert_eq!(apply_unknown.observe_calls, 0);
        assert_eq!(apply_unknown.status, Status::Unknown);

        let refusal = execute_recovery_protocol(
            ApplyOutcome::Refused,
            None,
            true,
            proven_reconcile(),
            Status::Pass,
        );
        assert_eq!(refusal.status, Status::Blocked);

        let violation = execute_recovery_protocol(
            ApplyOutcome::ProvenApplied,
            Some(classify_observation(Observation {
                observed: Some("DENY"),
                reason: Some("NO_MATCH"),
                host_admission: Some("DENY"),
            })),
            true,
            proven_reconcile(),
            Status::Fail,
        );
        assert_eq!(violation.status, Status::Fail);
    }

    #[test]
    fn redaction_bounds_controller_text_and_plans_never_enable_execution() {
        let source = "fault on gateway.example.invalid and https://secret.example.invalid/x";
        let stored = scrub_and_bound(source);
        assert!(!stored.contains("gateway.example.invalid"));
        assert!(!stored.contains("secret.example.invalid"));
        assert!(stored.contains("[redacted-host]"));
        assert!(stored.len() <= MAX_STORED_STRING);
        let plan = plan_is_blocked_by_default("native-single-node", false);
        assert_eq!(plan["status"], "PLANNED");
        assert_eq!(plan["liveFaultMatrixIntegration"], "BLOCKED");
        assert_eq!(plan["attempts"], MAX_ATTEMPTS);
    }
}
