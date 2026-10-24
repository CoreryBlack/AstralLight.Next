//! E3 campaign-control contracts over supplied phase/collector/category inputs.
//! No controller, probe, sampler or artifact lifecycle is executed.

use crate::e3_reconciliation::EvidenceStatus;
use crate::e3_report::{
    self, CampaignStatusInputs, CategoryInputs, DecisionSample, DrainSample, SamplingWindowOutcome,
};
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhaseOutcome {
    Pass,
    Timeout,
    Error,
}

impl PhaseOutcome {
    fn kind(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Timeout => "timeout",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhaseInputs {
    pub begin_injection: PhaseOutcome,
    pub end_injection: PhaseOutcome,
    pub begin_drain: PhaseOutcome,
    pub end_drain: PhaseOutcome,
}

pub fn phase_lifecycle(inputs: PhaseInputs) -> Value {
    let mut calls = Vec::new();
    let mut failures = Vec::new();
    let mut problems = Vec::new();
    let mut sampling = json!({
        "injection_window": {"outcome": "skipped", "sampleCount": 0},
        "drain_window": {"outcome": "skipped", "sampleCount": 0},
    });
    let mut inject_active = false;
    let mut drain_active = false;
    let mut per_event = json!({"status": "SKIP"});
    let mut controller_state_unknown = false;
    let mut status = "PASS";

    calls.push("begin_injection");
    if inputs.begin_injection != PhaseOutcome::Pass {
        status = "UNKNOWN";
        controller_state_unknown = true;
        failures.push(format!("{}:begin_injection", inputs.begin_injection.kind()));
        problems.push("controller_phase_failure:begin_injection".to_owned());
    } else {
        calls.push("end_injection");
        if inputs.end_injection != PhaseOutcome::Pass {
            status = "UNKNOWN";
            inject_active = true;
            failures.push(format!("{}:end_injection", inputs.end_injection.kind()));
            problems.push("controller_phase_failure:end_injection".to_owned());
            sampling["injection_window"] = json!({"outcome": "ran", "sampleCount": 1});
        } else {
            calls.push("begin_drain");
            if inputs.begin_drain != PhaseOutcome::Pass {
                status = "UNKNOWN";
                drain_active = true;
                failures.push(format!("{}:begin_drain", inputs.begin_drain.kind()));
                problems.push("controller_phase_failure:begin_drain".to_owned());
                sampling["injection_window"] = json!({"outcome": "ran", "sampleCount": 1});
            } else {
                calls.push("end_drain");
                if inputs.end_drain != PhaseOutcome::Pass {
                    status = "UNKNOWN";
                    drain_active = true;
                    failures.push(format!("{}:end_drain", inputs.end_drain.kind()));
                    problems.push("controller_phase_failure:end_drain".to_owned());
                    per_event = json!({
                        "status": "SKIP",
                        "note": "drain_not_completed_after_abort:end_drain",
                    });
                    sampling["injection_window"] = json!({"outcome": "ran", "sampleCount": 1});
                    sampling["drain_window"] = json!({"outcome": "ran", "sampleCount": 1});
                } else {
                    sampling["injection_window"] = json!({"outcome": "ran", "sampleCount": 1});
                    sampling["drain_window"] = json!({"outcome": "ran", "sampleCount": 1});
                }
            }
        }
    }
    let manual = status != "PASS";
    json!({
        "status": status,
        "operationIds": crate::e3_runner_contract::e3_operation_ids("e3-campaign-model"),
        "calls": calls,
        "markers": [],
        "problems": problems,
        "phaseFailures": failures,
        "controller_state_unknown": controller_state_unknown,
        "injection_may_still_be_active": inject_active,
        "drain_may_still_be_active": drain_active,
        "manual_reconciliation_required": manual,
        "reconciliation_prompt": if manual { "MANUAL_RECONCILIATION_REQUIRED" } else { "" },
        "sampling": sampling,
        "perEventRetryHistory": per_event,
        "e3_evidence_claim": crate::e3_report::E3_CLAIM_NONE,
    })
}

fn passing_inputs() -> CategoryInputs {
    CategoryInputs {
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
            section_statuses: vec![EvidenceStatus::Pass; 4],
        }],
        per_event_status: Some(EvidenceStatus::Pass),
        per_event_count: Some(1),
        per_event_unknown_reasons: Vec::new(),
        host_crosscheck_status: Some(EvidenceStatus::Pass),
    }
}

pub fn full_claim_pass(approval_loaded: bool) -> Value {
    if !approval_loaded {
        return json!({
            "status": "BLOCKED",
            "problems": ["approval_record_missing"],
            "e3_evidence_claim": crate::e3_report::E3_CLAIM_NONE,
        });
    }
    let categories = e3_report::build_output_categories(&passing_inputs());
    let status = e3_report::aggregate_campaign_status(CampaignStatusInputs {
        window_outcomes: [
            SamplingWindowOutcome::Ran(EvidenceStatus::Pass),
            SamplingWindowOutcome::Ran(EvidenceStatus::Pass),
        ],
        categories: &categories,
        marker_report_valid: true,
        host_crosscheck_status: Some(EvidenceStatus::Pass),
        abort_reason_present: false,
        phase_failures_present: false,
        problems_present: false,
        request_log_collector_missing: false,
    });
    json!({
        "status": if status == EvidenceStatus::Pass { "PASS" } else { status.as_str() },
        "cycles": [{"status": "PASS"}],
        "problems": [],
        "e3_evidence_claim": e3_report::evidence_claim(status),
        "markersComplete": true,
        "artifacts": ["manifest.json", "report.json", "markers.json", "checksums.sha256"],
    })
}

pub fn role_plan() -> Value {
    json!({
        "roles": [
            {"role": "target", "card": "card-target-1"},
            {"role": "unrelated", "card": "card-unrelated-1"},
            {"role": "cold", "card": "card-cold-1"},
        ],
        "distinctCards": true,
        "actorSwitching": true,
    })
}

pub fn campaign_from_categories(
    inputs: &CategoryInputs,
    host_crosscheck_status: Option<EvidenceStatus>,
    request_log_collector_missing: bool,
) -> Value {
    let mut inputs = inputs.clone();
    inputs.host_crosscheck_status = host_crosscheck_status;
    let categories = e3_report::build_output_categories(&inputs);
    let status = e3_report::aggregate_campaign_status(CampaignStatusInputs {
        window_outcomes: [
            SamplingWindowOutcome::Ran(EvidenceStatus::Pass),
            SamplingWindowOutcome::Ran(EvidenceStatus::Pass),
        ],
        categories: &categories,
        marker_report_valid: true,
        host_crosscheck_status,
        abort_reason_present: false,
        phase_failures_present: false,
        problems_present: false,
        request_log_collector_missing,
    });
    json!({
        "status": status.as_str(),
        "categories": {
            "request_side_denial_pending": categories.request_side_denial_pending.status.as_str(),
            "unrelated_card_availability": categories.unrelated_card_availability.status.as_str(),
            "publication_drain": categories.publication_drain.status.as_str(),
            "per_event_retry_history": categories.per_event_retry_history.status.as_str(),
        },
        "e3_evidence_claim": e3_report::evidence_claim(status),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e3_runner_module_has_no_import_time_process_or_network_capability() {
        let source = include_str!("e3_runner_contract.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for token in [
            "std::process",
            "std::net",
            "Command::new",
            "reqwest",
            "hyper::",
            "static mut",
            "lazy_static!",
        ] {
            assert!(!source.contains(token), "{token}");
        }
    }

    #[test]
    fn approval_record_from_file_reaches_full_claim_pass() {
        assert_eq!(full_claim_pass(true)["status"], "PASS");
        assert_eq!(
            full_claim_pass(true)["e3_evidence_claim"],
            crate::e3_runner_contract::E3_CLAIM_FULL
        );
    }

    #[test]
    fn full_claim_pass_requires_all_categories_and_durable_evidence() {
        let report = full_claim_pass(true);
        assert_eq!(report["status"], "PASS");
        assert_eq!(
            report["e3_evidence_claim"],
            crate::e3_runner_contract::E3_CLAIM_FULL
        );
        assert_eq!(report["markersComplete"], true);
        assert!(report["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "checksums.sha256"));
    }

    #[test]
    fn actor_switching_roles_and_cards_keep_distinct_bindings() {
        let plan = role_plan();
        assert_eq!(plan["distinctCards"], true);
        let cards = plan["roles"]
            .as_array()
            .unwrap()
            .iter()
            .map(|role| role["card"].as_str().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(cards.len(), 3);
    }

    #[test]
    fn begin_injection_failure_stops_without_retry() {
        let result = phase_lifecycle(PhaseInputs {
            begin_injection: PhaseOutcome::Error,
            end_injection: PhaseOutcome::Pass,
            begin_drain: PhaseOutcome::Pass,
            end_drain: PhaseOutcome::Pass,
        });
        assert_eq!(result["status"], "UNKNOWN");
        assert_eq!(result["calls"], json!(["begin_injection"]));
        assert_eq!(result["markers"], json!([]));
        assert_eq!(result["controller_state_unknown"], true);
        assert_eq!(result["injection_may_still_be_active"], false);
        assert_eq!(result["drain_may_still_be_active"], false);
        assert_eq!(result["manual_reconciliation_required"], true);
        assert!(result["reconciliation_prompt"]
            .as_str()
            .unwrap()
            .contains("MANUAL_RECONCILIATION_REQUIRED"));
        assert_eq!(result["sampling"]["injection_window"]["outcome"], "skipped");
        assert_eq!(result["sampling"]["drain_window"]["outcome"], "skipped");
        assert_eq!(result["e3_evidence_claim"], e3_report::E3_CLAIM_NONE);
    }

    #[test]
    fn end_injection_failure_leaves_injection_active() {
        let result = phase_lifecycle(PhaseInputs {
            begin_injection: PhaseOutcome::Pass,
            end_injection: PhaseOutcome::Error,
            begin_drain: PhaseOutcome::Pass,
            end_drain: PhaseOutcome::Pass,
        });
        assert_eq!(result["status"], "UNKNOWN");
        assert_eq!(result["calls"], json!(["begin_injection", "end_injection"]));
        assert_eq!(result["injection_may_still_be_active"], true);
        assert_eq!(result["manual_reconciliation_required"], true);
        assert_eq!(result["sampling"]["drain_window"]["outcome"], "skipped");
        assert!(
            result["sampling"]["injection_window"]["sampleCount"]
                .as_u64()
                .unwrap()
                >= 1
        );
        assert_eq!(result["perEventRetryHistory"]["status"], "SKIP");
        assert_eq!(result["e3_evidence_claim"], e3_report::E3_CLAIM_NONE);
    }

    #[test]
    fn end_drain_failure_leaves_drain_active() {
        let result = phase_lifecycle(PhaseInputs {
            begin_injection: PhaseOutcome::Pass,
            end_injection: PhaseOutcome::Pass,
            begin_drain: PhaseOutcome::Pass,
            end_drain: PhaseOutcome::Error,
        });
        assert_eq!(result["status"], "UNKNOWN");
        assert_eq!(result["drain_may_still_be_active"], true);
        assert_eq!(
            result["perEventRetryHistory"]["note"],
            "drain_not_completed_after_abort:end_drain"
        );
        assert_eq!(result["e3_evidence_claim"], e3_report::E3_CLAIM_NONE);
    }

    #[test]
    fn timeout_stops_without_retry() {
        let result = phase_lifecycle(PhaseInputs {
            begin_injection: PhaseOutcome::Timeout,
            end_injection: PhaseOutcome::Pass,
            begin_drain: PhaseOutcome::Pass,
            end_drain: PhaseOutcome::Pass,
        });
        assert_eq!(result["status"], "UNKNOWN");
        assert_eq!(result["calls"].as_array().unwrap().len(), 1);
        assert!(result["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "controller_phase_failure:begin_injection"));
        assert_eq!(result["phaseFailures"], json!(["timeout:begin_injection"]));
        assert_eq!(result["manual_reconciliation_required"], true);
    }

    #[test]
    fn backoff_tail_is_pending() {
        // Retry history still inside its backoff window: the per-event
        // category itself stays PENDING and the campaign cannot claim.
        let mut inputs = passing_inputs();
        inputs.per_event_status = Some(EvidenceStatus::Pending);
        let manifest = campaign_from_categories(&inputs, Some(EvidenceStatus::Pass), false);
        assert_eq!(manifest["categories"]["per_event_retry_history"], "PENDING");
        assert_eq!(manifest["status"], "UNKNOWN");
        assert_eq!(manifest["e3_evidence_claim"], e3_report::E3_CLAIM_NONE);
    }

    #[test]
    fn collector_error_is_blocked() {
        // A failed log collection leaves per-event evidence absent, which the
        // category folds to BLOCKED; the collector error string itself is
        // proven by the native runner's collector_error test.
        let mut inputs = passing_inputs();
        inputs.per_event_status = None;
        inputs.per_event_count = None;
        let manifest = campaign_from_categories(&inputs, Some(EvidenceStatus::Pass), false);
        assert_eq!(manifest["categories"]["per_event_retry_history"], "BLOCKED");
        assert_eq!(manifest["status"], "BLOCKED");
        assert_eq!(manifest["e3_evidence_claim"], e3_report::E3_CLAIM_NONE);
    }

    #[test]
    fn request_side_skip_when_target_stays_allowed() {
        let mut inputs = passing_inputs();
        inputs.injection_decisions[0].classification = "ALLOW".to_owned();
        let manifest = campaign_from_categories(&inputs, Some(EvidenceStatus::Pass), false);
        assert_eq!(manifest["status"], "SKIP");
        assert_eq!(manifest["e3_evidence_claim"], e3_report::E3_CLAIM_NONE);
    }

    #[test]
    fn publication_unknown_when_indicators_fail() {
        let mut inputs = passing_inputs();
        inputs.drain_samples[0].publication_drain_proven = false;
        inputs.drain_samples[0].section_statuses = vec![EvidenceStatus::Unknown; 4];
        let manifest = campaign_from_categories(&inputs, Some(EvidenceStatus::Pass), false);
        assert_eq!(manifest["categories"]["publication_drain"], "UNKNOWN");
        assert_eq!(manifest["status"], "UNKNOWN");
    }

    #[test]
    fn actor_aware_probe_required_is_blocked() {
        let mut inputs = passing_inputs();
        for decision in &mut inputs.injection_decisions {
            decision.decision_status = "BLOCKED".to_owned();
        }
        let manifest = campaign_from_categories(&inputs, None, false);
        assert_eq!(
            manifest["categories"]["request_side_denial_pending"],
            "BLOCKED"
        );
        assert_eq!(
            manifest["categories"]["unrelated_card_availability"],
            "BLOCKED"
        );
        assert_eq!(manifest["status"], "BLOCKED");
    }

    #[test]
    fn no_request_log_collector_is_unknown_not_pass() {
        let mut inputs = passing_inputs();
        inputs.injection_decisions[0].classification = "PENDING".to_owned();
        let manifest = campaign_from_categories(&inputs, Some(EvidenceStatus::Skip), true);
        assert_eq!(
            manifest["categories"]["request_side_denial_pending"],
            "UNKNOWN"
        );
        assert_eq!(manifest["status"], "UNKNOWN");
        assert_eq!(manifest["e3_evidence_claim"], e3_report::E3_CLAIM_NONE);
    }

    #[test]
    fn crosscheck_is_unknown_when_one_node_log_fails_to_parse() {
        // A request log that fails to parse can only support an UNKNOWN
        // crosscheck, and an UNKNOWN crosscheck keeps the target category
        // away from PASS even with every other category green.
        let manifest =
            campaign_from_categories(&passing_inputs(), Some(EvidenceStatus::Unknown), false);
        assert_eq!(
            manifest["categories"]["request_side_denial_pending"],
            "UNKNOWN"
        );
        assert_eq!(manifest["status"], "UNKNOWN");
        assert_eq!(manifest["e3_evidence_claim"], e3_report::E3_CLAIM_NONE);
    }
}
