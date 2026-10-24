use crate::e3_reconciliation::EvidenceStatus;
use serde_json::Value;
use std::collections::BTreeMap;

pub const MARKER_NAMES: [&str; 4] = [
    "injection_start",
    "injection_end",
    "drain_start",
    "drain_end",
];
const EFFECT_STATES: [&str; 4] = ["ACTIVE", "INACTIVE", "DRAINING", "DRAINED"];
pub const CATEGORY_REQUEST_SIDE: &str = "request_side_denial_pending";
pub const CATEGORY_UNRELATED: &str = "unrelated_card_availability";
pub const CATEGORY_PUBLICATION: &str = "publication_drain";
pub const CATEGORY_PER_EVENT: &str = "per_event_retry_history";
pub const E3_CLAIM_NONE: &str = "NOT_CLAIMED";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectAck {
    pub operation_id: Option<String>,
    pub applied: Option<bool>,
    pub state: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PhaseMarker {
    pub marker: String,
    pub operation_id: String,
    pub monotonic_ns: u64,
    pub wall_unix_ns: u64,
    pub ack: EffectAck,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MarkerReport {
    pub complete: bool,
    pub valid: bool,
    pub missing: Vec<&'static str>,
    pub problems: Vec<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionSample {
    pub role: String,
    pub decision_status: String,
    pub classification: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DrainSample {
    pub publication_read_success: bool,
    pub publication_drain_proven: bool,
    pub section_statuses: Vec<EvidenceStatus>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CategoryInputs {
    pub injection_decisions: Vec<DecisionSample>,
    pub drain_decisions: Vec<DecisionSample>,
    pub drain_samples: Vec<DrainSample>,
    pub per_event_status: Option<EvidenceStatus>,
    pub per_event_count: Option<usize>,
    pub per_event_unknown_reasons: Vec<String>,
    pub host_crosscheck_status: Option<EvidenceStatus>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Category {
    pub status: EvidenceStatus,
    pub samples: usize,
    pub detail: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FourCategories {
    pub request_side_denial_pending: Category,
    pub unrelated_card_availability: Category,
    pub publication_drain: Category,
    pub per_event_retry_history: Category,
    pub cold_samples: usize,
    pub cold_allow_observed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct E3RunSummary {
    pub status: EvidenceStatus,
    pub output_categories: FourCategories,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowDispatch {
    Run,
    Skip,
}

pub fn window_dispatch(duration_s: f64) -> Result<WindowDispatch, &'static str> {
    if !duration_s.is_finite() || duration_s < 0.0 {
        return Err("sampling duration must be finite and non-negative");
    }
    if duration_s == 0.0 {
        Ok(WindowDispatch::Skip)
    } else {
        Ok(WindowDispatch::Run)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SamplingWindowOutcome {
    Ran(EvidenceStatus),
    Skipped,
    Failed,
}

impl SamplingWindowOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ran(_) => "ran",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CampaignStatusInputs<'a> {
    pub window_outcomes: [SamplingWindowOutcome; 2],
    pub categories: &'a FourCategories,
    pub marker_report_valid: bool,
    pub host_crosscheck_status: Option<EvidenceStatus>,
    pub abort_reason_present: bool,
    pub phase_failures_present: bool,
    pub problems_present: bool,
    pub request_log_collector_missing: bool,
}

pub const SNAPSHOT_LIMITATIONS: [(&str, &str); 5] = [
    (
        "per_attempt_decision_history",
        "SKIP: fixed-interval snapshots cannot reconstruct per-attempt per-delta event history",
    ),
    (
        "fault_injection",
        "SKIP: this report does not inject faults",
    ),
    ("response_bodies", "SKIP: response bodies are not captured"),
    (
        "host_admission_cross_check",
        "SKIP: host admission requires request-side event logs",
    ),
    (
        "worker_readiness",
        "SKIP: Redis liveness is not worker readiness",
    ),
];

pub fn snapshot_report_boundary() -> Value {
    serde_json::json!({
        "kind": "e3_sampling",
        "mode": "fixed_interval_snapshot",
        "e3_evidence_claim": "NOT_CLAIMED",
        "status_note": "fixed-interval snapshot sampling is not complete E3 evidence; the maximum supported claim is the weaker workload-level recovery-tail conclusion",
        "limitations": SNAPSHOT_LIMITATIONS.iter().map(|(item, note)| {
            serde_json::json!({"item": item, "status": "SKIP", "note": note})
        }).collect::<Vec<_>>(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerHealthReport {
    pub status: EvidenceStatus,
    pub healthy: bool,
    pub http_status: Option<Value>,
    pub error_class: Option<&'static str>,
}

fn integer_http_status(value: &Value) -> Option<(Value, i128)> {
    match value {
        Value::Number(number) => {
            let status = number
                .as_i64()
                .map(i128::from)
                .or_else(|| number.as_u64().map(i128::from))?;
            Some((value.clone(), status))
        }
        Value::Bool(status) => {
            let integer = if *status { 1i128 } else { 0i128 };
            Some((serde_json::json!(integer), integer))
        }
        _ => None,
    }
}

pub fn normalize_worker_health_response(parts: &[Value]) -> WorkerHealthReport {
    if !matches!(parts.len(), 2 | 3) {
        return WorkerHealthReport {
            status: EvidenceStatus::Unknown,
            healthy: false,
            http_status: None,
            error_class: Some("ValueError"),
        };
    }
    let parsed_status = integer_http_status(&parts[0]);
    let http_status = parsed_status.as_ref().map(|(value, _)| value.clone());
    let body_healthy = parts[1]
        .as_object()
        .and_then(|body| body.get("healthy"))
        .is_some_and(|healthy| healthy == true);
    let healthy =
        parsed_status.is_some_and(|(_, status)| (200..300).contains(&status)) && body_healthy;
    WorkerHealthReport {
        status: if healthy {
            EvidenceStatus::Pass
        } else {
            EvidenceStatus::Unknown
        },
        healthy,
        http_status,
        error_class: None,
    }
}

fn ack_proves(ack: &EffectAck, operation_id: &str, state: &str) -> bool {
    ack.applied == Some(true)
        && ack.operation_id.as_deref() == Some(operation_id)
        && ack
            .state
            .as_deref()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case(state))
}

pub fn validate_markers(
    markers: &[PhaseMarker],
    injection_operation_id: &str,
    drain_operation_id: &str,
) -> MarkerReport {
    let mut by_name = BTreeMap::<&str, &PhaseMarker>::new();
    let mut problems = Vec::new();
    for marker in markers {
        if !MARKER_NAMES.contains(&marker.marker.as_str()) {
            problems.push("marker_unrecognized");
            continue;
        }
        if by_name.insert(&marker.marker, marker).is_some() {
            problems.push("marker_duplicate");
        }
    }
    let missing = MARKER_NAMES
        .iter()
        .copied()
        .filter(|name| !by_name.contains_key(name))
        .collect::<Vec<_>>();
    let ordered = MARKER_NAMES
        .iter()
        .filter_map(|name| by_name.get(name).copied())
        .collect::<Vec<_>>();
    if ordered
        .windows(2)
        .any(|pair| pair[1].monotonic_ns <= pair[0].monotonic_ns)
    {
        problems.push("marker_monotonic_order_violation");
    }
    if ordered
        .windows(2)
        .any(|pair| pair[1].wall_unix_ns < pair[0].wall_unix_ns)
    {
        problems.push("marker_wall_order_violation");
    }
    if missing.is_empty()
        && by_name["drain_start"].monotonic_ns < by_name["injection_end"].monotonic_ns
    {
        problems.push("marker_interval_overlap_violation");
    }
    for (index, name) in MARKER_NAMES.iter().enumerate() {
        let Some(marker) = by_name.get(name) else {
            continue;
        };
        let expected_operation_id = if index < 2 {
            injection_operation_id
        } else {
            drain_operation_id
        };
        let operation_problem = if index < 2 {
            "marker_operation_id_mismatch_injection"
        } else {
            "marker_operation_id_mismatch_drain"
        };
        if marker.operation_id != expected_operation_id {
            problems.push(operation_problem);
        }
        if !ack_proves(&marker.ack, expected_operation_id, EFFECT_STATES[index]) {
            problems.push("marker_effect_unproven");
        }
    }
    problems.sort_unstable();
    problems.dedup();
    let complete = missing.is_empty();
    let valid = complete && problems.is_empty();
    MarkerReport {
        complete,
        valid,
        missing,
        problems,
    }
}

fn category(status: EvidenceStatus, samples: usize, detail: &'static str) -> Category {
    Category {
        status,
        samples,
        detail,
    }
}

fn status_rank(status: EvidenceStatus) -> u8 {
    match status {
        EvidenceStatus::Fail => 0,
        EvidenceStatus::Blocked => 1,
        EvidenceStatus::Unknown => 2,
        EvidenceStatus::Pending => 3,
        EvidenceStatus::Skip => 4,
        EvidenceStatus::Pass => 5,
    }
}

fn worst_status(statuses: impl IntoIterator<Item = EvidenceStatus>) -> EvidenceStatus {
    statuses
        .into_iter()
        .min_by_key(|status| status_rank(*status))
        .unwrap_or(EvidenceStatus::Blocked)
}

pub fn build_output_categories(inputs: &CategoryInputs) -> FourCategories {
    let decisions = inputs
        .injection_decisions
        .iter()
        .chain(&inputs.drain_decisions)
        .collect::<Vec<_>>();
    let targets = decisions
        .iter()
        .filter(|decision| decision.role == "target")
        .copied()
        .collect::<Vec<_>>();
    let unrelated = decisions
        .iter()
        .filter(|decision| decision.role == "unrelated")
        .copied()
        .collect::<Vec<_>>();
    let cold = decisions
        .iter()
        .filter(|decision| decision.role == "cold")
        .copied()
        .collect::<Vec<_>>();
    let target_crosschecked =
        !targets.is_empty() && inputs.host_crosscheck_status == Some(EvidenceStatus::Pass);
    let request_side = if targets.is_empty() {
        category(EvidenceStatus::Skip, 0, "no target-card decision samples")
    } else if targets
        .iter()
        .all(|decision| decision.decision_status == "BLOCKED")
    {
        category(
            EvidenceStatus::Blocked,
            targets.len(),
            "actor-aware target decision was not executed",
        )
    } else if targets
        .iter()
        .any(|decision| matches!(decision.classification.as_str(), "PENDING" | "DENY"))
    {
        category(
            if target_crosschecked {
                EvidenceStatus::Pass
            } else {
                EvidenceStatus::Unknown
            },
            targets.len(),
            "target pending/denial requires host-admission cross-check",
        )
    } else {
        category(
            EvidenceStatus::Skip,
            targets.len(),
            "target pending/denial trigger was not observed",
        )
    };

    let unrelated_category = if unrelated.is_empty() {
        category(EvidenceStatus::Skip, 0, "no unrelated-card samples")
    } else if unrelated
        .iter()
        .all(|decision| decision.decision_status == "BLOCKED")
    {
        category(
            EvidenceStatus::Blocked,
            unrelated.len(),
            "actor-aware unrelated decision was not executed",
        )
    } else if unrelated
        .iter()
        .any(|decision| decision.classification == "ALLOW")
    {
        category(
            EvidenceStatus::Pass,
            unrelated.len(),
            "probe-level unrelated-card ALLOW",
        )
    } else if unrelated
        .iter()
        .any(|decision| decision.classification == "UNKNOWN")
    {
        category(
            EvidenceStatus::Unknown,
            unrelated.len(),
            "unrelated-card availability is inconclusive",
        )
    } else {
        category(
            EvidenceStatus::Unknown,
            unrelated.len(),
            "unrelated-card ALLOW was not demonstrated",
        )
    };

    let publication = if inputs.drain_samples.is_empty() {
        category(EvidenceStatus::Skip, 0, "drain window has no samples")
    } else if inputs.per_event_status == Some(EvidenceStatus::Pass)
        && inputs
            .drain_samples
            .iter()
            .all(|sample| sample.publication_drain_proven)
    {
        category(
            EvidenceStatus::Pass,
            inputs.drain_samples.len(),
            "all drain samples and per-event history prove drain",
        )
    } else if inputs
        .drain_samples
        .iter()
        .any(|sample| sample.publication_read_success)
        || inputs.drain_samples.iter().any(|sample| {
            sample
                .section_statuses
                .iter()
                .any(|status| matches!(status, EvidenceStatus::Unknown | EvidenceStatus::Blocked))
        })
    {
        category(
            EvidenceStatus::Unknown,
            inputs.drain_samples.len(),
            "snapshot reads do not prove publication drain",
        )
    } else {
        category(
            EvidenceStatus::Skip,
            inputs.drain_samples.len(),
            "publication indicators were not observed",
        )
    };

    let per_event = match inputs.per_event_status {
        Some(status) => category(
            status,
            inputs.per_event_count.unwrap_or(0),
            "per-attempt durable history",
        ),
        None => category(EvidenceStatus::Blocked, 0, "per-event evidence is absent"),
    };

    FourCategories {
        request_side_denial_pending: request_side,
        unrelated_card_availability: unrelated_category,
        publication_drain: publication,
        per_event_retry_history: per_event,
        cold_samples: cold.len(),
        cold_allow_observed: cold
            .iter()
            .any(|decision| decision.classification == "ALLOW"),
    }
}

pub fn aggregate_status(categories: &FourCategories) -> EvidenceStatus {
    worst_status([
        categories.request_side_denial_pending.status,
        categories.unrelated_card_availability.status,
        categories.publication_drain.status,
        categories.per_event_retry_history.status,
    ])
}

pub fn aggregate_campaign_status(input: CampaignStatusInputs<'_>) -> EvidenceStatus {
    let mut statuses = input
        .window_outcomes
        .into_iter()
        .map(|outcome| match outcome {
            SamplingWindowOutcome::Ran(status) => status,
            SamplingWindowOutcome::Skipped if input.abort_reason_present => EvidenceStatus::Unknown,
            SamplingWindowOutcome::Skipped => EvidenceStatus::Skip,
            SamplingWindowOutcome::Failed => EvidenceStatus::Unknown,
        })
        .collect::<Vec<_>>();
    statuses.extend([
        input.categories.request_side_denial_pending.status,
        input.categories.unrelated_card_availability.status,
        input.categories.publication_drain.status,
        input.categories.per_event_retry_history.status,
    ]);
    statuses.push(
        input
            .host_crosscheck_status
            .unwrap_or(EvidenceStatus::Unknown),
    );
    if !input.marker_report_valid || input.phase_failures_present || input.problems_present {
        statuses.push(EvidenceStatus::Unknown);
    }
    if input.request_log_collector_missing
        && input.categories.request_side_denial_pending.status == EvidenceStatus::Skip
    {
        if let Some(index) = statuses
            .iter()
            .position(|status| *status == EvidenceStatus::Skip)
        {
            statuses.remove(index);
        }
        statuses.push(EvidenceStatus::Unknown);
    }
    worst_status(statuses)
}

pub fn evidence_claim(status: EvidenceStatus) -> &'static str {
    if status == EvidenceStatus::Pass {
        "RECOVERY_TAIL_FULL"
    } else {
        E3_CLAIM_NONE
    }
}

pub fn build_run_summary(inputs: &CategoryInputs) -> E3RunSummary {
    let output_categories = build_output_categories(inputs);
    E3RunSummary {
        status: aggregate_status(&output_categories),
        output_categories,
    }
}

pub fn abort_evidence(
    markers: &[PhaseMarker],
    injection_operation_id: &str,
    drain_operation_id: &str,
    drain_completed: bool,
) -> Value {
    let report = validate_markers(markers, injection_operation_id, drain_operation_id);
    let mut problems = report
        .missing
        .iter()
        .map(|missing| format!("markers_missing:{missing}"))
        .collect::<Vec<_>>();
    if !drain_completed {
        problems.push("drain_not_completed".to_owned());
    }
    let drain_may_still_be_active = !drain_completed || report.missing.contains(&"drain_end");
    let injection_may_still_be_active = report.missing.contains(&"injection_end");
    Value::Object(serde_json::Map::from_iter([
        ("status".to_owned(), Value::String("UNKNOWN".to_owned())),
        (
            "problems".to_owned(),
            Value::Array(problems.into_iter().map(Value::String).collect()),
        ),
        (
            "drain_may_still_be_active".to_owned(),
            Value::Bool(drain_may_still_be_active),
        ),
        (
            "injection_may_still_be_active".to_owned(),
            Value::Bool(injection_may_still_be_active),
        ),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marker(name: &str, index: usize, op: &str, state: &str) -> PhaseMarker {
        PhaseMarker {
            marker: name.to_owned(),
            operation_id: op.to_owned(),
            monotonic_ns: (index as u64 + 1) * 100,
            wall_unix_ns: (index as u64 + 1) * 1000,
            ack: EffectAck {
                operation_id: Some(op.to_owned()),
                applied: Some(true),
                state: Some(state.to_owned()),
            },
        }
    }

    fn all_markers() -> Vec<PhaseMarker> {
        ["ACTIVE", "INACTIVE", "DRAINING", "DRAINED"]
            .into_iter()
            .enumerate()
            .map(|(index, state)| {
                marker(
                    MARKER_NAMES[index],
                    index,
                    if index < 2 {
                        "op-injection"
                    } else {
                        "op-drain"
                    },
                    state,
                )
            })
            .collect()
    }

    fn empty_categories() -> FourCategories {
        build_output_categories(&CategoryInputs {
            injection_decisions: Vec::new(),
            drain_decisions: Vec::new(),
            drain_samples: Vec::new(),
            per_event_status: None,
            per_event_count: None,
            per_event_unknown_reasons: Vec::new(),
            host_crosscheck_status: None,
        })
    }

    #[test]
    fn markers_require_complete_order_and_effect_ack_identity() {
        let markers = all_markers();
        let report = validate_markers(&markers, "op-injection", "op-drain");
        assert!(report.complete);
        assert!(report.valid);
        assert!(!validate_markers(&markers[..3], "op-injection", "op-drain").complete);

        let mut duplicate = markers.clone();
        duplicate.push(markers[0].clone());
        let report = validate_markers(&duplicate, "op-injection", "op-drain");
        assert!(!report.valid);
        assert!(report.problems.contains(&"marker_duplicate"));

        let mut wrong_operation = markers.clone();
        wrong_operation[0].operation_id = "other".to_owned();
        assert!(
            validate_markers(&wrong_operation, "op-injection", "op-drain")
                .problems
                .contains(&"marker_operation_id_mismatch_injection")
        );

        let mut missing_ack_proof = markers;
        missing_ack_proof[2].ack.applied = Some(false);
        assert!(
            validate_markers(&missing_ack_proof, "op-injection", "op-drain")
                .problems
                .contains(&"marker_effect_unproven")
        );
    }

    #[test]
    fn markers_refuse_non_monotonic_wall_and_overlapping_windows() {
        let mut non_monotonic = all_markers();
        non_monotonic[2].monotonic_ns = non_monotonic[1].monotonic_ns;
        assert!(validate_markers(&non_monotonic, "op-injection", "op-drain")
            .problems
            .contains(&"marker_monotonic_order_violation"));

        let mut wall = all_markers();
        wall[3].wall_unix_ns = 1;
        assert!(validate_markers(&wall, "op-injection", "op-drain")
            .problems
            .contains(&"marker_wall_order_violation"));

        let mut overlap = all_markers();
        overlap[2].monotonic_ns = 150;
        assert!(validate_markers(&overlap, "op-injection", "op-drain")
            .problems
            .contains(&"marker_interval_overlap_violation"));
    }

    #[test]
    fn missing_markers_on_abort_reports_unknown_and_active_drain() {
        let markers = all_markers()[..3].to_vec();
        let report = abort_evidence(&markers, "op-injection", "op-drain", false);
        assert_eq!(report["status"], "UNKNOWN");
        let problems = report["problems"].as_array().unwrap();
        assert!(problems
            .iter()
            .any(|problem| problem == "markers_missing:drain_end"));
        assert!(problems
            .iter()
            .any(|problem| problem == "drain_not_completed"));
        assert_eq!(report["drain_may_still_be_active"], true);
        assert_eq!(report["injection_may_still_be_active"], false);
    }

    #[test]
    fn empty_attempt_history_blocks_the_campaign_without_a_claim() {
        let events: [crate::e3_reconciliation::E3Event; 0] = [];
        let durable_rows = std::collections::BTreeMap::new();
        let per_event =
            crate::e3_reconciliation::validate_attempt_history(&events, Some(&durable_rows), 8);
        let categories = build_output_categories(&CategoryInputs {
            injection_decisions: Vec::new(),
            drain_decisions: Vec::new(),
            drain_samples: Vec::new(),
            per_event_status: Some(per_event.status),
            per_event_count: Some(per_event.events),
            per_event_unknown_reasons: per_event.unknown,
            host_crosscheck_status: None,
        });
        let status = aggregate_campaign_status(CampaignStatusInputs {
            window_outcomes: [
                SamplingWindowOutcome::Ran(EvidenceStatus::Pass),
                SamplingWindowOutcome::Ran(EvidenceStatus::Pass),
            ],
            categories: &categories,
            marker_report_valid: true,
            host_crosscheck_status: None,
            abort_reason_present: false,
            phase_failures_present: false,
            problems_present: false,
            request_log_collector_missing: false,
        });

        assert_eq!(per_event.status, EvidenceStatus::Blocked);
        assert_eq!(
            categories.per_event_retry_history.status,
            EvidenceStatus::Blocked
        );
        assert_eq!(status, EvidenceStatus::Blocked);
        assert_ne!(status, EvidenceStatus::Pass);
        assert_eq!(evidence_claim(status), E3_CLAIM_NONE);
    }

    #[test]
    fn missing_durable_row_reader_blocks_the_campaign_without_a_claim() {
        let events = [
            crate::e3_reconciliation::E3Event {
                kind: crate::e3_reconciliation::E3EventKind::ClaimCommitted,
                node: "node-a".to_owned(),
                process_observation_id: "worker-a".to_owned(),
                sequence: 1,
                wall_unix_ns: 1_010,
                delta_event_id: 101,
                event_id: "evt-1".to_owned(),
                operation_id: Some("op-1".to_owned()),
                attempts: Some(1),
                durable: None,
                outcome: None,
            },
            crate::e3_reconciliation::E3Event {
                kind: crate::e3_reconciliation::E3EventKind::PublishCommitted,
                node: "node-a".to_owned(),
                process_observation_id: "worker-a".to_owned(),
                sequence: 2,
                wall_unix_ns: 1_020,
                delta_event_id: 101,
                event_id: "evt-1".to_owned(),
                operation_id: Some("op-1".to_owned()),
                attempts: Some(1),
                durable: Some(true),
                outcome: Some("succeeded".to_owned()),
            },
        ];
        let history = crate::e3_reconciliation::validate_attempt_history(&events, None, 8);
        let categories = build_output_categories(&CategoryInputs {
            injection_decisions: Vec::new(),
            drain_decisions: Vec::new(),
            drain_samples: Vec::new(),
            per_event_status: Some(history.status),
            per_event_count: Some(history.events),
            per_event_unknown_reasons: history.unknown.clone(),
            host_crosscheck_status: None,
        });
        let status = aggregate_campaign_status(CampaignStatusInputs {
            window_outcomes: [
                SamplingWindowOutcome::Ran(EvidenceStatus::Pass),
                SamplingWindowOutcome::Ran(EvidenceStatus::Pass),
            ],
            categories: &categories,
            marker_report_valid: true,
            host_crosscheck_status: None,
            abort_reason_present: false,
            phase_failures_present: false,
            problems_present: false,
            request_log_collector_missing: false,
        });

        assert_eq!(history.status, EvidenceStatus::Blocked);
        assert!(history
            .unknown
            .contains(&"durable_row_reconciliation_unavailable".to_owned()));
        assert_eq!(
            categories.per_event_retry_history.status,
            EvidenceStatus::Blocked
        );
        assert_eq!(status, EvidenceStatus::Blocked);
        assert_ne!(status, EvidenceStatus::Pass);
        assert_eq!(evidence_claim(status), E3_CLAIM_NONE);
    }

    #[test]
    fn publication_not_configured_is_skip_without_a_full_claim() {
        let summary = build_run_summary(&CategoryInputs {
            injection_decisions: vec![
                DecisionSample {
                    role: "target".to_owned(),
                    decision_status: "PASS".to_owned(),
                    classification: "PENDING".to_owned(),
                },
                DecisionSample {
                    role: "unrelated".to_owned(),
                    decision_status: "PASS".to_owned(),
                    classification: "ALLOW".to_owned(),
                },
            ],
            drain_decisions: Vec::new(),
            drain_samples: vec![DrainSample {
                publication_read_success: false,
                publication_drain_proven: false,
                section_statuses: vec![EvidenceStatus::Skip; 4],
            }],
            per_event_status: Some(EvidenceStatus::Pass),
            per_event_count: Some(1),
            per_event_unknown_reasons: Vec::new(),
            host_crosscheck_status: Some(EvidenceStatus::Pass),
        });
        let status = aggregate_campaign_status(CampaignStatusInputs {
            window_outcomes: [
                SamplingWindowOutcome::Ran(EvidenceStatus::Pass),
                SamplingWindowOutcome::Ran(EvidenceStatus::Pass),
            ],
            categories: &summary.output_categories,
            marker_report_valid: true,
            host_crosscheck_status: Some(EvidenceStatus::Pass),
            abort_reason_present: false,
            phase_failures_present: false,
            problems_present: false,
            request_log_collector_missing: false,
        });

        assert_eq!(
            summary.output_categories.publication_drain.status,
            EvidenceStatus::Skip
        );
        assert_eq!(status, EvidenceStatus::Skip);
        assert_eq!(evidence_claim(status), E3_CLAIM_NONE);
    }

    #[test]
    fn supplied_missing_collector_and_pending_target_stay_unknown_without_a_claim() {
        let summary = build_run_summary(&CategoryInputs {
            injection_decisions: vec![
                DecisionSample {
                    role: "target".to_owned(),
                    decision_status: "PASS".to_owned(),
                    classification: "PENDING".to_owned(),
                },
                DecisionSample {
                    role: "unrelated".to_owned(),
                    decision_status: "PASS".to_owned(),
                    classification: "ALLOW".to_owned(),
                },
            ],
            drain_decisions: Vec::new(),
            drain_samples: vec![DrainSample {
                publication_read_success: true,
                publication_drain_proven: true,
                section_statuses: vec![EvidenceStatus::Pass],
            }],
            per_event_status: Some(EvidenceStatus::Pass),
            per_event_count: Some(1),
            per_event_unknown_reasons: Vec::new(),
            host_crosscheck_status: Some(EvidenceStatus::Skip),
        });
        let status = aggregate_campaign_status(CampaignStatusInputs {
            window_outcomes: [
                SamplingWindowOutcome::Ran(EvidenceStatus::Pass),
                SamplingWindowOutcome::Ran(EvidenceStatus::Pass),
            ],
            categories: &summary.output_categories,
            marker_report_valid: true,
            host_crosscheck_status: Some(EvidenceStatus::Skip),
            abort_reason_present: false,
            phase_failures_present: false,
            problems_present: false,
            request_log_collector_missing: true,
        });

        assert_eq!(
            summary.output_categories.request_side_denial_pending.status,
            EvidenceStatus::Unknown
        );
        assert_eq!(
            summary.output_categories.unrelated_card_availability.status,
            EvidenceStatus::Pass
        );
        assert_eq!(
            summary.output_categories.publication_drain.status,
            EvidenceStatus::Pass
        );
        assert_eq!(
            summary.output_categories.per_event_retry_history.status,
            EvidenceStatus::Pass
        );
        assert_eq!(status, EvidenceStatus::Unknown);
        assert_ne!(status, EvidenceStatus::Pass);
        assert_eq!(evidence_claim(status), E3_CLAIM_NONE);
    }

    #[test]
    fn allowed_target_and_unrelated_decision_reduce_to_skip_without_a_claim() {
        let summary = build_run_summary(&CategoryInputs {
            injection_decisions: vec![
                DecisionSample {
                    role: "target".to_owned(),
                    decision_status: "PASS".to_owned(),
                    classification: "ALLOW".to_owned(),
                },
                DecisionSample {
                    role: "unrelated".to_owned(),
                    decision_status: "PASS".to_owned(),
                    classification: "ALLOW".to_owned(),
                },
            ],
            drain_decisions: Vec::new(),
            drain_samples: vec![DrainSample {
                publication_read_success: true,
                publication_drain_proven: true,
                section_statuses: vec![EvidenceStatus::Pass],
            }],
            per_event_status: Some(EvidenceStatus::Pass),
            per_event_count: Some(1),
            per_event_unknown_reasons: Vec::new(),
            host_crosscheck_status: Some(EvidenceStatus::Pass),
        });
        let status = aggregate_campaign_status(CampaignStatusInputs {
            window_outcomes: [
                SamplingWindowOutcome::Ran(EvidenceStatus::Pass),
                SamplingWindowOutcome::Ran(EvidenceStatus::Pass),
            ],
            categories: &summary.output_categories,
            marker_report_valid: true,
            host_crosscheck_status: Some(EvidenceStatus::Pass),
            abort_reason_present: false,
            phase_failures_present: false,
            problems_present: false,
            request_log_collector_missing: false,
        });

        assert_eq!(
            summary.output_categories.request_side_denial_pending.status,
            EvidenceStatus::Skip
        );
        assert_eq!(
            summary.output_categories.unrelated_card_availability.status,
            EvidenceStatus::Pass
        );
        assert_eq!(
            summary.output_categories.publication_drain.status,
            EvidenceStatus::Pass
        );
        assert_eq!(
            summary.output_categories.per_event_retry_history.status,
            EvidenceStatus::Pass
        );
        assert_eq!(status, EvidenceStatus::Skip);
        assert_eq!(evidence_claim(status), E3_CLAIM_NONE);
    }

    #[test]
    fn actor_aware_probe_unavailability_blocks_categories_and_campaign() {
        let summary = build_run_summary(&CategoryInputs {
            injection_decisions: vec![DecisionSample {
                role: "target".to_owned(),
                decision_status: "BLOCKED".to_owned(),
                classification: "PENDING".to_owned(),
            }],
            drain_decisions: vec![DecisionSample {
                role: "unrelated".to_owned(),
                decision_status: "BLOCKED".to_owned(),
                classification: "UNKNOWN".to_owned(),
            }],
            drain_samples: vec![DrainSample {
                publication_read_success: true,
                publication_drain_proven: true,
                section_statuses: vec![EvidenceStatus::Pass],
            }],
            per_event_status: Some(EvidenceStatus::Pass),
            per_event_count: Some(1),
            per_event_unknown_reasons: Vec::new(),
            host_crosscheck_status: Some(EvidenceStatus::Blocked),
        });
        let status = aggregate_campaign_status(CampaignStatusInputs {
            window_outcomes: [
                SamplingWindowOutcome::Ran(EvidenceStatus::Pass),
                SamplingWindowOutcome::Ran(EvidenceStatus::Pass),
            ],
            categories: &summary.output_categories,
            marker_report_valid: true,
            host_crosscheck_status: Some(EvidenceStatus::Blocked),
            abort_reason_present: false,
            phase_failures_present: false,
            problems_present: false,
            request_log_collector_missing: false,
        });

        assert_eq!(
            summary.output_categories.request_side_denial_pending.status,
            EvidenceStatus::Blocked
        );
        assert_eq!(
            summary.output_categories.unrelated_card_availability.status,
            EvidenceStatus::Blocked
        );
        assert_eq!(
            summary.output_categories.publication_drain.status,
            EvidenceStatus::Pass
        );
        assert_eq!(
            summary.output_categories.per_event_retry_history.status,
            EvidenceStatus::Pass
        );
        assert_eq!(status, EvidenceStatus::Blocked);
        assert_eq!(evidence_claim(status), E3_CLAIM_NONE);
    }

    #[test]
    fn unrelated_pending_decision_keeps_the_campaign_unknown() {
        let summary = build_run_summary(&CategoryInputs {
            injection_decisions: vec![
                DecisionSample {
                    role: "target".to_owned(),
                    decision_status: "PASS".to_owned(),
                    classification: "PENDING".to_owned(),
                },
                DecisionSample {
                    role: "unrelated".to_owned(),
                    decision_status: "PASS".to_owned(),
                    classification: "PENDING".to_owned(),
                },
            ],
            drain_decisions: Vec::new(),
            drain_samples: vec![DrainSample {
                publication_read_success: true,
                publication_drain_proven: true,
                section_statuses: vec![EvidenceStatus::Pass],
            }],
            per_event_status: Some(EvidenceStatus::Pass),
            per_event_count: Some(1),
            per_event_unknown_reasons: Vec::new(),
            host_crosscheck_status: Some(EvidenceStatus::Pass),
        });
        let status = aggregate_campaign_status(CampaignStatusInputs {
            window_outcomes: [
                SamplingWindowOutcome::Ran(EvidenceStatus::Pass),
                SamplingWindowOutcome::Ran(EvidenceStatus::Pass),
            ],
            categories: &summary.output_categories,
            marker_report_valid: true,
            host_crosscheck_status: Some(EvidenceStatus::Pass),
            abort_reason_present: false,
            phase_failures_present: false,
            problems_present: false,
            request_log_collector_missing: false,
        });

        assert_eq!(
            summary.output_categories.request_side_denial_pending.status,
            EvidenceStatus::Pass
        );
        assert_eq!(
            summary.output_categories.unrelated_card_availability.status,
            EvidenceStatus::Unknown
        );
        assert_eq!(
            summary.output_categories.publication_drain.status,
            EvidenceStatus::Pass
        );
        assert_eq!(
            summary.output_categories.per_event_retry_history.status,
            EvidenceStatus::Pass
        );
        assert_eq!(status, EvidenceStatus::Unknown);
        assert_ne!(status, EvidenceStatus::Pass);
        assert_eq!(evidence_claim(status), E3_CLAIM_NONE);
    }

    #[test]
    fn failed_publication_indicators_keep_the_campaign_unknown() {
        let summary = build_run_summary(&CategoryInputs {
            injection_decisions: vec![
                DecisionSample {
                    role: "target".to_owned(),
                    decision_status: "PASS".to_owned(),
                    classification: "PENDING".to_owned(),
                },
                DecisionSample {
                    role: "unrelated".to_owned(),
                    decision_status: "PASS".to_owned(),
                    classification: "ALLOW".to_owned(),
                },
            ],
            drain_decisions: Vec::new(),
            drain_samples: vec![DrainSample {
                publication_read_success: false,
                publication_drain_proven: false,
                section_statuses: vec![EvidenceStatus::Unknown],
            }],
            per_event_status: Some(EvidenceStatus::Pass),
            per_event_count: Some(1),
            per_event_unknown_reasons: Vec::new(),
            host_crosscheck_status: Some(EvidenceStatus::Pass),
        });
        let status = aggregate_campaign_status(CampaignStatusInputs {
            window_outcomes: [
                SamplingWindowOutcome::Ran(EvidenceStatus::Pass),
                SamplingWindowOutcome::Ran(EvidenceStatus::Pass),
            ],
            categories: &summary.output_categories,
            marker_report_valid: true,
            host_crosscheck_status: Some(EvidenceStatus::Pass),
            abort_reason_present: false,
            phase_failures_present: false,
            problems_present: false,
            request_log_collector_missing: false,
        });

        assert_eq!(
            summary.output_categories.request_side_denial_pending.status,
            EvidenceStatus::Pass
        );
        assert_eq!(
            summary.output_categories.unrelated_card_availability.status,
            EvidenceStatus::Pass
        );
        assert_eq!(
            summary.output_categories.publication_drain.status,
            EvidenceStatus::Unknown
        );
        assert_eq!(
            summary.output_categories.per_event_retry_history.status,
            EvidenceStatus::Pass
        );
        assert_eq!(status, EvidenceStatus::Unknown);
        assert_ne!(status, EvidenceStatus::Pass);
        assert_eq!(evidence_claim(status), E3_CLAIM_NONE);
    }

    #[test]
    fn zero_duration_windows_are_skipped_and_keep_the_campaign_blocked() {
        let windows = [
            window_dispatch(0.0).unwrap(),
            window_dispatch(-0.0).unwrap(),
        ];
        assert_eq!(windows, [WindowDispatch::Skip; 2]);
        assert_eq!(
            windows.map(|outcome| match outcome {
                WindowDispatch::Run => "ran",
                WindowDispatch::Skip => "skipped",
            }),
            ["skipped", "skipped"]
        );

        let categories = build_output_categories(&CategoryInputs {
            injection_decisions: Vec::new(),
            drain_decisions: Vec::new(),
            drain_samples: Vec::new(),
            per_event_status: Some(EvidenceStatus::Pass),
            per_event_count: Some(1),
            per_event_unknown_reasons: Vec::new(),
            host_crosscheck_status: Some(EvidenceStatus::Blocked),
        });
        let status = aggregate_campaign_status(CampaignStatusInputs {
            window_outcomes: [
                SamplingWindowOutcome::Skipped,
                SamplingWindowOutcome::Skipped,
            ],
            categories: &categories,
            marker_report_valid: true,
            host_crosscheck_status: Some(EvidenceStatus::Blocked),
            abort_reason_present: false,
            phase_failures_present: false,
            problems_present: false,
            request_log_collector_missing: false,
        });
        assert_eq!(status, EvidenceStatus::Blocked);
        assert_eq!(evidence_claim(status), E3_CLAIM_NONE);
        assert_eq!(window_dispatch(0.1), Ok(WindowDispatch::Run));
        assert!(window_dispatch(-1.0).is_err());
        assert!(window_dispatch(f64::INFINITY).is_err());
    }

    #[test]
    fn four_categories_preserve_skip_blocked_unknown_and_publication_proof() {
        let empty = empty_categories();
        assert_eq!(
            empty.request_side_denial_pending.status,
            EvidenceStatus::Skip
        );
        assert_eq!(
            empty.unrelated_card_availability.status,
            EvidenceStatus::Skip
        );
        assert_eq!(empty.publication_drain.status, EvidenceStatus::Skip);
        assert_eq!(
            empty.per_event_retry_history.status,
            EvidenceStatus::Blocked
        );
        assert_eq!(aggregate_status(&empty), EvidenceStatus::Blocked);

        let reads_only = build_output_categories(&CategoryInputs {
            injection_decisions: vec![DecisionSample {
                role: "target".to_owned(),
                decision_status: "DONE".to_owned(),
                classification: "PENDING".to_owned(),
            }],
            drain_decisions: vec![DecisionSample {
                role: "unrelated".to_owned(),
                decision_status: "DONE".to_owned(),
                classification: "ALLOW".to_owned(),
            }],
            drain_samples: vec![DrainSample {
                publication_read_success: true,
                publication_drain_proven: false,
                section_statuses: vec![EvidenceStatus::Pass],
            }],
            per_event_status: Some(EvidenceStatus::Pass),
            per_event_count: Some(3),
            per_event_unknown_reasons: Vec::new(),
            host_crosscheck_status: Some(EvidenceStatus::Pass),
        });
        assert_eq!(
            reads_only.request_side_denial_pending.status,
            EvidenceStatus::Pass
        );
        assert_eq!(
            reads_only.unrelated_card_availability.status,
            EvidenceStatus::Pass
        );
        assert_eq!(reads_only.publication_drain.status, EvidenceStatus::Unknown);
        assert_eq!(reads_only.per_event_retry_history.samples, 3);

        let proven_drain = build_output_categories(&CategoryInputs {
            injection_decisions: Vec::new(),
            drain_decisions: Vec::new(),
            drain_samples: vec![DrainSample {
                publication_read_success: true,
                publication_drain_proven: true,
                section_statuses: vec![EvidenceStatus::Pass],
            }],
            per_event_status: Some(EvidenceStatus::Pass),
            per_event_count: Some(1),
            per_event_unknown_reasons: Vec::new(),
            host_crosscheck_status: None,
        });
        assert_eq!(proven_drain.publication_drain.status, EvidenceStatus::Pass);
    }

    #[test]
    fn snapshot_report_keeps_evidence_limits_and_snapshot_only_status_note() {
        let report = snapshot_report_boundary();
        assert_eq!(report["kind"], "e3_sampling");
        assert_eq!(report["mode"], "fixed_interval_snapshot");
        assert_eq!(report["e3_evidence_claim"], "NOT_CLAIMED");
        let status_note = report["status_note"].as_str().unwrap();
        assert!(status_note.contains("snapshot"));
        assert!(status_note.contains("not complete E3 evidence"));

        let limitations = report["limitations"].as_array().unwrap();
        assert_eq!(limitations.len(), SNAPSHOT_LIMITATIONS.len());
        for (item, _) in SNAPSHOT_LIMITATIONS {
            let entry = limitations
                .iter()
                .find(|entry| entry["item"] == item)
                .unwrap_or_else(|| panic!("missing limitation {item}"));
            assert_eq!(entry["status"], "SKIP", "{item}");
        }
        assert!(report["limitations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["item"] == "per_attempt_decision_history")
            .unwrap()["note"]
            .as_str()
            .unwrap()
            .contains("per-attempt"));
    }

    #[test]
    fn e3_runner_source_contains_no_deployment_constants() {
        // Guard the native runner sources, not the archived Python reference:
        // a deployment constant leaking into the Rust runner is the
        // regression this test exists to catch.
        let source = concat!(
            include_str!("e3_runner_native.rs"),
            include_str!("e3_runner_contract.rs"),
        );
        let ipv4 = regex::Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}\b").unwrap();
        assert!(!ipv4.is_match(source));
        for token in [
            "http://",
            "https://",
            "mysql_root",
            "redis_password",
            "MYSQL_PWD",
            "REDISCLI_AUTH",
            "hmac_secret",
            "ssh ",
        ] {
            assert!(!source.contains(token), "deployment token present: {token}");
        }
    }

    #[test]
    fn worker_health_response_accepts_two_or_three_fields_and_fails_closed() {
        for parts in [
            vec![serde_json::json!(200), serde_json::json!({"healthy": true})],
            vec![
                serde_json::json!(204),
                serde_json::json!({"healthy": true}),
                serde_json::json!("req-health-1"),
            ],
        ] {
            let report = normalize_worker_health_response(&parts);
            assert_eq!(report.status, EvidenceStatus::Pass);
            assert!(report.healthy);
            assert_eq!(report.http_status, Some(parts[0].clone()));
            assert_eq!(report.error_class, None);
        }

        for parts in [
            Vec::new(),
            vec![serde_json::json!(200)],
            vec![
                serde_json::json!(200),
                serde_json::json!({"healthy": true}),
                serde_json::json!("req-health-1"),
                serde_json::json!("extra"),
            ],
        ] {
            let report = normalize_worker_health_response(&parts);
            assert_eq!(report.status, EvidenceStatus::Unknown);
            assert!(!report.healthy);
            assert_eq!(report.http_status, None);
            assert_eq!(report.error_class, Some("ValueError"));
        }

        for (status, body, expected_status) in [
            (
                serde_json::json!(503),
                serde_json::json!({"healthy": true}),
                Some(503),
            ),
            (
                serde_json::json!(200),
                serde_json::json!({"healthy": false}),
                Some(200),
            ),
            (
                serde_json::json!("200"),
                serde_json::json!({"healthy": true}),
                None,
            ),
            (
                serde_json::json!(200.0),
                serde_json::json!({"healthy": true}),
                None,
            ),
            (
                serde_json::json!(true),
                serde_json::json!({"healthy": true}),
                Some(1),
            ),
        ] {
            let report = normalize_worker_health_response(&[status, body]);
            assert_eq!(report.status, EvidenceStatus::Unknown);
            assert!(!report.healthy);
            assert_eq!(
                report.http_status,
                expected_status.map(|status| serde_json::json!(status))
            );
            assert_eq!(report.error_class, None);
        }
    }
}
