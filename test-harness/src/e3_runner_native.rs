//! Native E3 campaign phase orchestration over injected ports.
//!
//! The runner executes the four controller phases exactly once each, samples
//! the configured windows, collects E3 and request logs, reconciles durable
//! rows, folds the four report categories, writes markers/report/manifest
//! artifacts and checksums. It never opens a socket, subprocess or database.

use crate::e1_log::E1LogEvent;
use crate::e3_config::{self, E3Settings};
use crate::e3_e4_events::{parse_e1_events, parse_e3_events};
use crate::e3_reconciliation::{
    self, AttemptHistoryReport, CrosscheckQuality, DecisionClass, DurableRow, EvidenceStatus,
    RequestContext, RequestDecision, RequestEvent, RequestEventKind,
};
use crate::e3_report::{
    self, CampaignStatusInputs, CategoryInputs, DecisionSample, DrainSample, EffectAck,
    PhaseMarker, SamplingWindowOutcome,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

pub trait InjectionController {
    fn begin_injection(&mut self, operation_id: &str) -> Result<Value, String>;
    fn end_injection(&mut self, operation_id: &str) -> Result<Value, String>;
    fn begin_drain(&mut self, operation_id: &str) -> Result<Value, String>;
    fn end_drain(&mut self, operation_id: &str) -> Result<Value, String>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeDecision {
    pub decision_status: String,
    pub classification: String,
}

pub trait E3Probe {
    fn decide(
        &mut self,
        role: &str,
        node: &str,
        card: &str,
        request_id: &str,
    ) -> Result<ProbeDecision, String>;
}

pub trait E3LogCollector {
    fn collect_e3_lines(&mut self, node: &str) -> Result<Vec<String>, String>;
}

pub trait DurableRowReader {
    fn read_rows(&mut self, event_ids: &[String]) -> Result<BTreeMap<String, DurableRow>, String>;
}

pub trait RequestLogCollector {
    fn collect_request_lines(
        &mut self,
        node: &str,
        request_ids: &[String],
    ) -> Result<Vec<String>, String>;
}

pub struct CampaignPorts<'a> {
    pub controller: &'a mut dyn InjectionController,
    pub probe: &'a mut dyn E3Probe,
    pub collector: Option<&'a mut dyn E3LogCollector>,
    pub row_reader: Option<&'a mut dyn DurableRowReader>,
    pub request_logs: Option<&'a mut dyn RequestLogCollector>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CampaignError {
    pub problems: Vec<String>,
}

fn marker(name: &str, operation_id: &str, sequence: u64, ack: &Value) -> PhaseMarker {
    PhaseMarker {
        marker: name.to_owned(),
        operation_id: operation_id.to_owned(),
        monotonic_ns: sequence * 10,
        wall_unix_ns: 1_758_000_000_000_000_000 + sequence * 10,
        ack: EffectAck {
            operation_id: ack
                .get("operation_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
            applied: ack.get("applied").and_then(Value::as_bool),
            state: ack.get("state").and_then(Value::as_str).map(str::to_owned),
        },
    }
}

fn marker_value(value: &PhaseMarker) -> Value {
    json!({
        "marker": value.marker,
        "operation_id": value.operation_id,
        "sequence": value.monotonic_ns / 10,
        "wall_unix_ns": value.wall_unix_ns,
        "monotonic_ns": value.monotonic_ns,
        "ack": {
            "operation_id": value.ack.operation_id,
            "applied": value.ack.applied,
            "state": value.ack.state,
        },
    })
}

fn decision_class(value: &str) -> DecisionClass {
    match value {
        "ALLOW" => DecisionClass::Allow,
        "PENDING" => DecisionClass::Pending,
        "DENY" => DecisionClass::Deny,
        _ => DecisionClass::Unknown,
    }
}

/// Builds the request context from the event's own identity fields; an
/// incomplete context stays `None` so the crosscheck treats the admission as
/// unverified instead of trusting caller-side constants.
fn request_context_from_fields(fields: &serde_json::Map<String, Value>) -> Option<RequestContext> {
    let field = |name: &str| {
        fields
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    Some(RequestContext {
        user_id: field("user_id")?,
        tenant_id: field("tenant_id")?,
        card_id: field("card_id")?,
        resource: field("resource")?,
        action: field("action")?,
    })
}

fn request_events_from_e1(events: &[E1LogEvent]) -> Vec<RequestEvent> {
    events
        .iter()
        .filter(|event| event.event == "decision_return" || event.event == "host_admission")
        .map(|event| RequestEvent {
            request_id: event.request_id.clone(),
            kind: if event.event == "decision_return" {
                RequestEventKind::DecisionReturn
            } else {
                RequestEventKind::HostAdmission
            },
            node: event.node.clone(),
            process_observation_id: event.process_observation_id.clone(),
            sequence: event.sequence.max(0) as u64,
            allowed: event.fields.get("allowed").and_then(Value::as_bool),
            reason: event
                .fields
                .get("reason")
                .and_then(Value::as_str)
                .map(str::to_owned),
            context: request_context_from_fields(&event.fields),
        })
        .collect()
}

fn scheduled_samples(window_s: f64, interval_s: f64) -> usize {
    if window_s <= 0.0 {
        return 0;
    }
    (window_s / interval_s - 1e-9).ceil().max(0.0) as usize
}

struct PhaseAbort {
    phase: String,
    kind: String,
}

pub fn run_campaign(
    config: &Value,
    out_dir: &Path,
    ports: &mut CampaignPorts<'_>,
) -> Result<Value, CampaignError> {
    let settings = e3_config::load_e3_config(config).map_err(|error| CampaignError {
        problems: error
            .problems
            .iter()
            .map(|item| (*item).to_owned())
            .collect(),
    })?;
    let operation_ids = crate::e3_runner_contract::e3_operation_ids(&settings.run_id);
    let injection_op = operation_ids["injection"].as_str().unwrap_or_default();
    let drain_op = operation_ids["drain"].as_str().unwrap_or_default();
    let node = settings.nodes.first().cloned().unwrap_or_default();

    // The live gate runs before any controller or probe contact: without an
    // explicit allow_live_execution flag plus a matching approval record the
    // campaign must not touch the controller at all.
    let live = config
        .get("allow_live_execution")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let approval_ref = config.get("approval_ref").and_then(Value::as_str);
    let approval_record = config.get("approval_record");
    if let Some(problem) =
        crate::e3_runner_contract::e3_live_gate(&settings, live, approval_ref, approval_record)
    {
        let manifest = json!({
            "experiment": "E3",
            "campaignId": settings.run_id,
            "status": "BLOCKED",
            "problems": [format!("live_gate:{problem}")],
            "operationIds": operation_ids,
            "markers": [],
            "markersComplete": false,
            "phaseFailures": [],
            "controller_state_unknown": false,
            "injection_may_still_be_active": false,
            "drain_may_still_be_active": false,
            "manual_reconciliation_required": true,
            "reconciliation_prompt": "MANUAL_RECONCILIATION_REQUIRED",
            "sampling": {
                "injection_window": {"outcome": "skipped", "sampleCount": 0},
                "drain_window": {"outcome": "skipped", "sampleCount": 0},
            },
            "perEventRetryHistory": {
                "status": "BLOCKED",
                "problems": [format!("live_gate:{problem}")],
            },
            "outputCategories": {
                "request_side_denial_pending": "BLOCKED",
                "unrelated_card_availability": "BLOCKED",
                "publication_drain": "BLOCKED",
                "per_event_retry_history": "BLOCKED",
            },
            "e3_evidence_claim": e3_report::evidence_claim(EvidenceStatus::Blocked),
            "liveGate": problem,
        });
        let _ = write_artifacts(out_dir, &manifest, &[]);
        return Ok(manifest);
    }

    let mut markers = Vec::new();
    let mut phase_failures = Vec::new();
    let mut problems = Vec::new();
    let mut abort: Option<PhaseAbort> = None;
    let mut sequence = 1u64;
    let mut injection_samples = Vec::new();
    let mut drain_samples_raw = Vec::new();
    let mut injection_outcome = "skipped";
    let mut drain_outcome = "skipped";

    let begin = ports.controller.begin_injection(injection_op);
    match begin {
        Ok(ack) => {
            markers.push(marker("injection_start", injection_op, sequence, &ack));
            sequence += 1;
            match ports.controller.end_injection(injection_op) {
                Ok(ack) => {
                    markers.push(marker("injection_end", injection_op, sequence, &ack));
                    sequence += 1;
                    let count = scheduled_samples(
                        settings.injection_window_s,
                        settings.sampling_interval_s,
                    );
                    if count == 0 {
                        injection_outcome = "skipped";
                    } else {
                        injection_outcome = "ran";
                        for index in 0..count {
                            for (role, card) in [
                                ("target", settings.target_card.as_str()),
                                ("unrelated", settings.unrelated_card.as_str()),
                                ("cold", settings.cold_card.as_str()),
                            ] {
                                let request_id = crate::e1_runner_contract::stable_id(
                                    &settings.run_id,
                                    &format!("e3:c{role}:injection:{index}"),
                                );
                                match ports.probe.decide(role, &node, card, &request_id) {
                                    Ok(decision) => injection_samples.push((
                                        role.to_owned(),
                                        decision,
                                        request_id,
                                    )),
                                    Err(_) => {
                                        problems.push(format!("probe_failure:{role}"));
                                    }
                                }
                            }
                        }
                    }
                    match ports.controller.begin_drain(drain_op) {
                        Ok(ack) => {
                            markers.push(marker("drain_start", drain_op, sequence, &ack));
                            sequence += 1;
                            match ports.controller.end_drain(drain_op) {
                                Ok(ack) => {
                                    markers.push(marker("drain_end", drain_op, sequence, &ack));
                                    let count = scheduled_samples(
                                        settings.drain_window_s,
                                        settings.sampling_interval_s,
                                    );
                                    if count == 0 {
                                        drain_outcome = "skipped";
                                    } else {
                                        drain_outcome = "ran";
                                        for index in 0..count {
                                            let request_id = crate::e1_runner_contract::stable_id(
                                                &settings.run_id,
                                                &format!("e3:drain:{index}"),
                                            );
                                            match ports.probe.decide(
                                                "target",
                                                &node,
                                                &settings.target_card,
                                                &request_id,
                                            ) {
                                                Ok(decision) => {
                                                    drain_samples_raw.push((
                                                        "target".to_owned(),
                                                        decision,
                                                        request_id,
                                                    ));
                                                }
                                                Err(_) => {
                                                    problems.push("probe_failure:drain".to_owned());
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(error) => {
                                    abort = Some(PhaseAbort {
                                        phase: "end_drain".to_owned(),
                                        kind: error,
                                    });
                                }
                            }
                        }
                        Err(error) => {
                            abort = Some(PhaseAbort {
                                phase: "begin_drain".to_owned(),
                                kind: error,
                            });
                        }
                    }
                }
                Err(error) => {
                    abort = Some(PhaseAbort {
                        phase: "end_injection".to_owned(),
                        kind: error,
                    });
                    // The sampling window never opened: keep the outcome
                    // skipped instead of reporting an unsampled window as ran.
                }
            }
        }
        Err(error) => {
            abort = Some(PhaseAbort {
                phase: "begin_injection".to_owned(),
                kind: error,
            });
        }
    }
    if let Some(abort) = &abort {
        phase_failures.push(format!("{}:{}", abort.kind, abort.phase));
        problems.push(format!("controller_phase_failure:{}", abort.phase));
    }

    let markers_valid =
        markers.len() == 4 && e3_report::validate_markers(&markers, injection_op, drain_op).valid;
    let per_event = collect_per_event(settings.max_attempts as u32, &node, ports, &mut problems);
    let (host_status, request_log_missing) = crosscheck(
        &settings,
        &node,
        &injection_samples,
        ports.request_logs.take(),
        &mut problems,
    );
    let category_decisions = injection_samples
        .iter()
        .map(|(role, decision, _)| DecisionSample {
            role: role.clone(),
            decision_status: decision.decision_status.clone(),
            classification: decision.classification.clone(),
        })
        .collect::<Vec<_>>();
    let per_event_status = if abort.is_some() {
        Some(EvidenceStatus::Skip)
    } else {
        Some(
            per_event
                .as_ref()
                .map(|report| report.status)
                .unwrap_or(EvidenceStatus::Blocked),
        )
    };
    let per_event_count = if abort.is_some() {
        None
    } else {
        per_event.as_ref().map(|report| report.events)
    };
    let per_event_unknown = if abort.is_some() {
        Vec::new()
    } else {
        per_event
            .as_ref()
            .map(|report| report.unknown.clone())
            .unwrap_or_default()
    };
    let publication_proven = per_event_status == Some(EvidenceStatus::Pass)
        && markers_valid
        && !drain_samples_raw.is_empty()
        && drain_samples_raw
            .iter()
            .all(|(_, decision, _)| decision.decision_status == "PASS");
    let drain_decisions = drain_samples_raw
        .iter()
        .map(|(role, decision, _)| DecisionSample {
            role: role.clone(),
            decision_status: decision.decision_status.clone(),
            classification: decision.classification.clone(),
        })
        .collect::<Vec<_>>();
    let drain_probes_pass = !drain_samples_raw.is_empty()
        && drain_samples_raw
            .iter()
            .all(|(_, decision, _)| decision.decision_status == "PASS");
    let categories = e3_report::build_output_categories(&CategoryInputs {
        injection_decisions: category_decisions,
        drain_decisions,
        drain_samples: vec![DrainSample {
            publication_read_success: per_event_status == Some(EvidenceStatus::Pass),
            publication_drain_proven: publication_proven,
            section_statuses: vec![
                per_event_status.unwrap_or(EvidenceStatus::Unknown),
                if markers_valid {
                    EvidenceStatus::Pass
                } else {
                    EvidenceStatus::Unknown
                },
                if drain_probes_pass {
                    EvidenceStatus::Pass
                } else {
                    EvidenceStatus::Unknown
                },
                host_status.unwrap_or(EvidenceStatus::Unknown),
            ],
        }],
        per_event_status,
        per_event_count,
        per_event_unknown_reasons: per_event_unknown,
        host_crosscheck_status: host_status,
    });
    let status = e3_report::aggregate_campaign_status(CampaignStatusInputs {
        window_outcomes: [
            if injection_outcome == "ran" {
                SamplingWindowOutcome::Ran(
                    if injection_samples
                        .iter()
                        .all(|(_, decision, _)| decision.decision_status == "PASS")
                    {
                        EvidenceStatus::Pass
                    } else {
                        EvidenceStatus::Unknown
                    },
                )
            } else {
                SamplingWindowOutcome::Skipped
            },
            if drain_outcome == "ran" {
                SamplingWindowOutcome::Ran(if drain_probes_pass {
                    EvidenceStatus::Pass
                } else {
                    EvidenceStatus::Unknown
                })
            } else {
                SamplingWindowOutcome::Skipped
            },
        ],
        categories: &categories,
        marker_report_valid: markers_valid,
        host_crosscheck_status: host_status,
        abort_reason_present: abort.is_some(),
        phase_failures_present: !phase_failures.is_empty(),
        problems_present: !problems.is_empty(),
        request_log_collector_missing: request_log_missing,
    });
    let injection_active = abort
        .as_ref()
        .is_some_and(|abort| abort.phase == "end_injection");
    let drain_active = abort
        .as_ref()
        .is_some_and(|abort| abort.phase == "end_drain" || abort.phase == "begin_drain");
    let manual = abort.is_some() || status != EvidenceStatus::Pass;
    let per_event_json = if abort.is_some() {
        json!({
            "status": "SKIP",
            "note": if drain_active {
                "drain_not_completed_after_abort:end_drain"
            } else {
                "phase_aborted"
            },
        })
    } else {
        per_event
            .map(|report| {
                json!({
                    "status": report.status.as_str(),
                    "events": report.events,
                    "attempts": report.attempts,
                    "attemptBoundExceeded": report.attempt_bound_exceeded,
                    "unknown": report.unknown,
                })
            })
            .unwrap_or_else(|| {
                json!({
                    "status": "BLOCKED",
                    "problems": problems.clone(),
                })
            })
    };
    let markers_json = markers.iter().map(marker_value).collect::<Vec<_>>();
    let manifest = json!({
        "experiment": "E3",
        "campaignId": settings.run_id,
        "status": status.as_str(),
        "problems": problems,
        "operationIds": operation_ids,
        "markers": markers_json.clone(),
        "markersComplete": markers.len() == 4,
        "phaseFailures": phase_failures,
        "controller_state_unknown": abort.is_some(),
        "injection_may_still_be_active": injection_active,
        "drain_may_still_be_active": drain_active,
        "manual_reconciliation_required": manual,
        "reconciliation_prompt": if manual { "MANUAL_RECONCILIATION_REQUIRED" } else { "" },
        "sampling": {
            "injection_window": {
                "outcome": injection_outcome,
                "sampleCount": injection_samples.len(),
            },
            "drain_window": {
                "outcome": drain_outcome,
                "sampleCount": drain_samples_raw.len(),
            },
        },
        "perEventRetryHistory": per_event_json,
        "outputCategories": {
            "request_side_denial_pending": categories.request_side_denial_pending.status.as_str(),
            "unrelated_card_availability": categories.unrelated_card_availability.status.as_str(),
            "publication_drain": categories.publication_drain.status.as_str(),
            "per_event_retry_history": categories.per_event_retry_history.status.as_str(),
        },
        "e3_evidence_claim": e3_report::evidence_claim(status),
    });
    let _ = write_artifacts(out_dir, &manifest, &markers_json);
    Ok(manifest)
}

fn collect_per_event(
    max_attempts: u32,
    node: &str,
    ports: &mut CampaignPorts<'_>,
    problems: &mut Vec<String>,
) -> Option<AttemptHistoryReport> {
    let Some(collector) = ports.collector.take() else {
        problems.push("e3_log_collector_unavailable".to_owned());
        return None;
    };
    let lines = match collector.collect_e3_lines(node) {
        Ok(lines) => lines,
        Err(error) => {
            problems.push(format!("collect_e3_lines:{error}"));
            return None;
        }
    };
    let events = match parse_e3_events(lines.iter().map(String::as_str), node) {
        Ok(events) => events,
        Err(error) => {
            problems.push(format!("e3_log_parse_failed:{error}"));
            return None;
        }
    };
    let Some(reader) = ports.row_reader.take() else {
        problems.push("durable_row_reconciliation_unavailable".to_owned());
        return None;
    };
    let ids = events
        .iter()
        .map(|event| event.event_id.clone())
        .collect::<Vec<_>>();
    let rows = match reader.read_rows(&ids) {
        Ok(rows) => rows,
        Err(error) => {
            problems.push(format!("durable_row_read_failed:{error}"));
            return None;
        }
    };
    Some(e3_reconciliation::validate_attempt_history(
        &events,
        Some(&rows),
        max_attempts,
    ))
}

fn crosscheck(
    settings: &E3Settings,
    node: &str,
    samples: &[(String, ProbeDecision, String)],
    request_logs: Option<&mut dyn RequestLogCollector>,
    problems: &mut Vec<String>,
) -> (Option<EvidenceStatus>, bool) {
    let Some(collector) = request_logs else {
        return (Some(EvidenceStatus::Skip), true);
    };
    // The crosscheck covers requests with a determinate classification; a
    // cold card that was never provisioned answers UNKNOWN by design and is
    // folded as cold metadata instead of an unverified contradiction.
    let sampled = samples
        .iter()
        .filter(|(_, decision, _)| decision.classification != "UNKNOWN")
        .collect::<Vec<_>>();
    let request_ids = sampled
        .iter()
        .map(|(_, _, request_id)| request_id.clone())
        .collect::<Vec<_>>();
    if request_ids.is_empty() {
        return (Some(EvidenceStatus::Blocked), false);
    }
    let lines = match collector.collect_request_lines(node, &request_ids) {
        Ok(lines) => lines,
        Err(error) => {
            problems.push(format!("request_log_collector_failed:{error}"));
            return (Some(EvidenceStatus::Unknown), false);
        }
    };
    let parsed = match parse_e1_events(lines.iter().map(String::as_str), node) {
        Ok(events) => events,
        Err(error) => {
            problems.push(format!("request_log_parse_failed:{error}"));
            return (Some(EvidenceStatus::Unknown), false);
        }
    };
    let decisions = sampled
        .iter()
        .map(|(_, decision, request_id)| RequestDecision {
            request_id: request_id.clone(),
            classification: decision_class(&decision.classification),
        })
        .collect::<Vec<_>>();
    let events = request_events_from_e1(&parsed);
    let report = e3_reconciliation::crosscheck_host_admissions(
        &decisions,
        &events,
        &CrosscheckQuality {
            logs_parsed: true,
            ..CrosscheckQuality::default()
        },
    );
    let _ = settings;
    (Some(report.status), false)
}

fn write_artifacts(out_dir: &Path, manifest: &Value, markers: &[Value]) -> Result<(), String> {
    crate::experiment_common_contract::write_atomic_json(out_dir, "manifest.json", manifest)?;
    crate::experiment_common_contract::write_atomic_json(
        out_dir,
        "report.json",
        &json!({
            "status": manifest["status"],
            "outputCategories": manifest["outputCategories"],
        }),
    )?;
    crate::experiment_common_contract::write_atomic_json(out_dir, "markers.json", &json!(markers))?;
    crate::experiment_common_contract::write_checksums(
        out_dir,
        &["manifest.json", "report.json", "markers.json"],
    )?;
    crate::experiment_common_contract::verify_checksums(out_dir, &out_dir.join("checksums.sha256"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const RUN_ID: &str = "authz-validation-e3-test";

    fn config(injection_window: f64, drain_window: f64) -> Value {
        json!({
            "run_id": RUN_ID,
            "allow_live_execution": true,
            "approval_ref": "appr-2026-e3-0001",
            "approval_record": {
                "run_id": RUN_ID,
                "approval_ref": "appr-2026-e3-0001",
                "approved_by": "human-operator",
            },
            "e3": {
                "allowlist": {
                    "target_card": "card-target-1",
                    "unrelated_card": "card-unrelated-1",
                    "cold_card": "card-cold-1",
                    "isolated_fixture": true,
                },
                "windows": {
                    "sampling_interval_s": 0.01,
                    "injection_window_s": injection_window,
                    "drain_window_s": drain_window,
                },
                "bounds": {"max_attempts": 8},
                "nodes": ["node-a"],
                "decision_node": "gateway",
            }
        })
    }

    fn e3_pass_lines() -> Vec<String> {
        vec![
            json!({
                "message": "e3 projector observation",
                "event": "claim_committed",
                "event_sequence": 1,
                "wall_unix_ns": 1_758_000_000_000_000_001u64,
                "delta_event_id": 101,
                "event_id": "evt-1",
                "operation_id": "op-1",
                "process_observation_id": "proc-a",
                "attempts": 1,
            })
            .to_string(),
            json!({
                "message": "e3 projector observation",
                "event": "publish_committed",
                "event_sequence": 2,
                "wall_unix_ns": 1_758_000_000_000_000_002u64,
                "delta_event_id": 101,
                "event_id": "evt-1",
                "operation_id": "op-1",
                "process_observation_id": "proc-a",
                "attempts": 1,
                "durable": true,
                "outcome": "succeeded",
            })
            .to_string(),
        ]
    }

    fn durable_rows() -> BTreeMap<String, DurableRow> {
        BTreeMap::from([(
            "evt-1".to_owned(),
            DurableRow {
                attempts: 1,
                status: "SUCCEEDED".to_owned(),
            },
        )])
    }

    fn request_lines(target_id: &str, unrelated_id: &str, cold_id: &str) -> Vec<String> {
        vec![
            json!({
                "message": "e1 authorization observation",
                "event": "decision_return",
                "request_id": target_id,
                "event_sequence": 1,
                "wall_unix_ns": 1_758_000_000_000_000_101u64,
                "process_observation_id": "proc-a",
                "allowed": false,
                "reason": "AUTHORIZATION_PENDING",
                "user_id": "user-1",
                "tenant_id": "9001",
                "card_id": "card-target-1",
                "resource": "monitor",
                "action": "read",
            })
            .to_string(),
            json!({
                "message": "e1 authorization observation",
                "event": "decision_return",
                "request_id": unrelated_id,
                "event_sequence": 2,
                "wall_unix_ns": 1_758_000_000_000_000_102u64,
                "process_observation_id": "proc-a",
                "allowed": true,
                "reason": "RULE_MATCH",
                "user_id": "user-1",
                "tenant_id": "9001",
                "card_id": "card-unrelated-1",
                "resource": "monitor",
                "action": "read",
            })
            .to_string(),
            json!({
                "message": "e1 authorization observation",
                "event": "host_admission",
                "request_id": unrelated_id,
                "event_sequence": 3,
                "wall_unix_ns": 1_758_000_000_000_000_103u64,
                "process_observation_id": "proc-a",
                "user_id": "user-1",
                "tenant_id": "9001",
                "card_id": "card-unrelated-1",
                "resource": "monitor",
                "action": "read",
            })
            .to_string(),
            json!({
                "message": "e1 authorization observation",
                "event": "decision_return",
                "request_id": cold_id,
                "event_sequence": 4,
                "wall_unix_ns": 1_758_000_000_000_000_104u64,
                "process_observation_id": "proc-a",
                "allowed": false,
                "reason": "AUTHORIZATION_PENDING",
                "user_id": "user-1",
                "tenant_id": "9001",
                "card_id": "card-cold-1",
                "resource": "monitor",
                "action": "read",
            })
            .to_string(),
        ]
    }

    #[derive(Default)]
    struct FakeController {
        fail: Option<(&'static str, &'static str)>,
        calls: Vec<String>,
        wrong_ack_operation: bool,
    }

    impl FakeController {
        fn call(
            &mut self,
            phase: &'static str,
            operation_id: &str,
            state: &str,
        ) -> Result<Value, String> {
            self.calls.push(phase.to_owned());
            if let Some((target, kind)) = self.fail {
                if target == phase {
                    return Err(kind.to_owned());
                }
            }
            Ok(json!({
                "operation_id": if self.wrong_ack_operation { "wrong-operation" } else { operation_id },
                "applied": true,
                "state": state,
            }))
        }
    }

    impl InjectionController for FakeController {
        fn begin_injection(&mut self, operation_id: &str) -> Result<Value, String> {
            self.call("begin_injection", operation_id, "ACTIVE")
        }
        fn end_injection(&mut self, operation_id: &str) -> Result<Value, String> {
            self.call("end_injection", operation_id, "INACTIVE")
        }
        fn begin_drain(&mut self, operation_id: &str) -> Result<Value, String> {
            self.call("begin_drain", operation_id, "DRAINING")
        }
        fn end_drain(&mut self, operation_id: &str) -> Result<Value, String> {
            self.call("end_drain", operation_id, "DRAINED")
        }
    }

    struct FakeProbe;

    #[derive(Default)]
    struct RecordingProbe {
        calls: usize,
    }

    impl E3Probe for RecordingProbe {
        fn decide(
            &mut self,
            _role: &str,
            _node: &str,
            _card: &str,
            _request_id: &str,
        ) -> Result<ProbeDecision, String> {
            self.calls += 1;
            Ok(ProbeDecision {
                decision_status: "PASS".to_owned(),
                classification: "PENDING".to_owned(),
            })
        }
    }

    impl E3Probe for FakeProbe {
        fn decide(
            &mut self,
            role: &str,
            _node: &str,
            _card: &str,
            _request_id: &str,
        ) -> Result<ProbeDecision, String> {
            Ok(match role {
                "unrelated" => ProbeDecision {
                    decision_status: "PASS".to_owned(),
                    classification: "ALLOW".to_owned(),
                },
                "cold" => ProbeDecision {
                    // A cold card is outside the prepared fixture: the probe
                    // call itself succeeds but the classification stays
                    // inconclusive, never a clean ALLOW.
                    decision_status: "PASS".to_owned(),
                    classification: "UNKNOWN".to_owned(),
                },
                _ => ProbeDecision {
                    decision_status: "PASS".to_owned(),
                    classification: "PENDING".to_owned(),
                },
            })
        }
    }

    struct FakeCollector {
        error: Option<&'static str>,
        lines: Vec<String>,
    }

    impl E3LogCollector for FakeCollector {
        fn collect_e3_lines(&mut self, _node: &str) -> Result<Vec<String>, String> {
            match self.error {
                Some(error) => Err(error.to_owned()),
                None => Ok(self.lines.clone()),
            }
        }
    }

    struct FakeRows {
        rows: BTreeMap<String, DurableRow>,
    }

    impl DurableRowReader for FakeRows {
        fn read_rows(
            &mut self,
            _event_ids: &[String],
        ) -> Result<BTreeMap<String, DurableRow>, String> {
            Ok(self.rows.clone())
        }
    }

    struct FakeLogs {
        lines: Vec<String>,
    }

    impl RequestLogCollector for FakeLogs {
        fn collect_request_lines(
            &mut self,
            _node: &str,
            _request_ids: &[String],
        ) -> Result<Vec<String>, String> {
            Ok(self.lines.clone())
        }
    }

    fn temp_dir(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("astral-e3-native-{label}-{}", uuid::Uuid::new_v4()))
    }

    fn ids() -> (String, String, String) {
        (
            crate::e1_runner_contract::stable_id(RUN_ID, "e3:ctarget:injection:0"),
            crate::e1_runner_contract::stable_id(RUN_ID, "e3:cunrelated:injection:0"),
            crate::e1_runner_contract::stable_id(RUN_ID, "e3:ccold:injection:0"),
        )
    }

    fn run(
        config: &Value,
        out: &Path,
        controller: &mut FakeController,
        collector: Option<&mut FakeCollector>,
        rows: Option<&mut FakeRows>,
        logs: Option<&mut FakeLogs>,
    ) -> Value {
        let mut probe = FakeProbe;
        let mut ports = CampaignPorts {
            controller,
            probe: &mut probe,
            collector: collector.map(|value| value as &mut dyn E3LogCollector),
            row_reader: rows.map(|value| value as &mut dyn DurableRowReader),
            request_logs: logs.map(|value| value as &mut dyn RequestLogCollector),
        };
        run_campaign(config, out, &mut ports).unwrap()
    }

    #[test]
    fn full_campaign_executes_phases_sampling_and_writes_artifacts() {
        let out = temp_dir("full");
        let (target_id, unrelated_id, cold_id) = ids();
        let mut controller = FakeController::default();
        let mut collector = FakeCollector {
            error: None,
            lines: e3_pass_lines(),
        };
        let mut rows = FakeRows {
            rows: durable_rows(),
        };
        let mut logs = FakeLogs {
            lines: request_lines(&target_id, &unrelated_id, &cold_id),
        };
        let manifest = run(
            &config(0.01, 0.01),
            &out,
            &mut controller,
            Some(&mut collector),
            Some(&mut rows),
            Some(&mut logs),
        );
        assert_eq!(manifest["status"], "PASS", "{manifest}");
        assert_eq!(
            manifest["e3_evidence_claim"],
            crate::e3_runner_contract::E3_CLAIM_FULL
        );
        assert_eq!(manifest["markers"].as_array().unwrap().len(), 4);
        assert_eq!(manifest["markersComplete"], true);
        assert_eq!(manifest["sampling"]["injection_window"]["sampleCount"], 3);
        assert_eq!(
            manifest["sampling"]["drain_window"]["outcome"], "ran",
            "{manifest}"
        );
        assert_eq!(manifest["sampling"]["drain_window"]["sampleCount"], 1);
        for artifact in ["manifest.json", "report.json", "markers.json"] {
            assert!(out.join(artifact).exists(), "{artifact}");
        }
        crate::experiment_common_contract::verify_checksums(&out, &out.join("checksums.sha256"))
            .unwrap();
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn live_gate_blocks_before_any_controller_or_probe_contact() {
        let out = temp_dir("gate-block");
        let mut config = config(0.01, 0.01);
        config["allow_live_execution"] = json!(false);
        let mut controller = FakeController::default();
        let mut probe = RecordingProbe::default();
        let mut ports = CampaignPorts {
            controller: &mut controller,
            probe: &mut probe,
            collector: None,
            row_reader: None,
            request_logs: None,
        };
        let manifest = run_campaign(&config, &out, &mut ports).unwrap();
        assert_eq!(manifest["status"], "BLOCKED", "{manifest}");
        assert_eq!(
            manifest["e3_evidence_claim"],
            crate::e3_runner_contract::E3_CLAIM_NONE
        );
        assert!(manifest["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "live_gate:live_not_enabled"));
        // The zero-contact guarantee is a real counter, not a constant.
        assert!(controller.calls.is_empty());
        assert_eq!(probe.calls, 0);
        assert_eq!(manifest["markers"], json!([]));
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn approval_record_mismatch_blocks_the_live_gate() {
        let out = temp_dir("gate-ref");
        let mut config = config(0.01, 0.01);
        config["approval_record"]["approval_ref"] = json!("appr-from-another-run-0001");
        let mut controller = FakeController::default();
        let manifest = run(&config, &out, &mut controller, None, None, None);
        assert_eq!(manifest["status"], "BLOCKED");
        assert!(controller.calls.is_empty());
        assert!(manifest["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "live_gate:approval_record_ref_mismatch"));
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn host_admission_context_mismatch_cannot_pass_crosscheck() {
        let out = temp_dir("context-mismatch");
        let (target_id, unrelated_id, cold_id) = ids();
        let mut lines = request_lines(&target_id, &unrelated_id, &cold_id);
        // The unrelated host_admission now carries a different card than its
        // own decision_return: the identity-context contradiction must keep
        // the campaign away from PASS.
        lines[2] = json!({
            "message": "e1 authorization observation",
            "event": "host_admission",
            "request_id": unrelated_id,
            "event_sequence": 3,
            "wall_unix_ns": 1_758_000_000_000_000_103u64,
            "process_observation_id": "proc-a",
            "user_id": "user-1",
            "tenant_id": "9001",
            "card_id": "card-someone-else",
            "resource": "monitor",
            "action": "read",
        })
        .to_string();
        let mut controller = FakeController::default();
        let mut collector = FakeCollector {
            error: None,
            lines: e3_pass_lines(),
        };
        let mut rows = FakeRows {
            rows: durable_rows(),
        };
        let mut logs = FakeLogs { lines };
        let manifest = run(
            &config(0.01, 0.01),
            &out,
            &mut controller,
            Some(&mut collector),
            Some(&mut rows),
            Some(&mut logs),
        );
        assert_ne!(manifest["status"], "PASS", "{manifest}");
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn begin_injection_failure_stops_without_retry() {
        let out = temp_dir("begin-fail");
        let mut controller = FakeController {
            fail: Some(("begin_injection", "error")),
            ..FakeController::default()
        };
        let manifest = run(&config(0.01, 0.01), &out, &mut controller, None, None, None);
        assert_eq!(manifest["status"], "UNKNOWN");
        assert_eq!(controller.calls, ["begin_injection"]);
        assert_eq!(manifest["markers"], json!([]));
        assert_eq!(manifest["controller_state_unknown"], true);
        assert_eq!(manifest["injection_may_still_be_active"], false);
        assert_eq!(manifest["drain_may_still_be_active"], false);
        assert_eq!(manifest["manual_reconciliation_required"], true);
        assert!(manifest["reconciliation_prompt"]
            .as_str()
            .unwrap()
            .contains("MANUAL_RECONCILIATION_REQUIRED"));
        assert_eq!(
            manifest["sampling"]["injection_window"]["outcome"],
            "skipped"
        );
        assert_eq!(manifest["sampling"]["drain_window"]["outcome"], "skipped");
        assert_eq!(
            manifest["e3_evidence_claim"],
            crate::e3_runner_contract::E3_CLAIM_NONE
        );
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn end_injection_failure_leaves_injection_active() {
        let out = temp_dir("end-injection");
        let mut controller = FakeController {
            fail: Some(("end_injection", "error")),
            ..FakeController::default()
        };
        let manifest = run(&config(0.01, 0.01), &out, &mut controller, None, None, None);
        assert_eq!(manifest["status"], "UNKNOWN");
        assert_eq!(controller.calls, ["begin_injection", "end_injection"]);
        assert_eq!(manifest["injection_may_still_be_active"], true);
        assert_eq!(
            manifest["sampling"]["injection_window"]["outcome"],
            "skipped"
        );
        assert_eq!(manifest["sampling"]["injection_window"]["sampleCount"], 0);
        assert_eq!(manifest["sampling"]["drain_window"]["outcome"], "skipped");
        assert_eq!(manifest["perEventRetryHistory"]["status"], "SKIP");
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn end_drain_failure_leaves_drain_active() {
        let out = temp_dir("end-drain");
        let mut controller = FakeController {
            fail: Some(("end_drain", "error")),
            ..FakeController::default()
        };
        let manifest = run(&config(0.01, 0.01), &out, &mut controller, None, None, None);
        assert_eq!(manifest["status"], "UNKNOWN");
        assert_eq!(manifest["drain_may_still_be_active"], true);
        assert_eq!(
            manifest["perEventRetryHistory"]["note"],
            "drain_not_completed_after_abort:end_drain"
        );
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn controller_timeout_stops_without_retry() {
        let out = temp_dir("timeout");
        let mut controller = FakeController {
            fail: Some(("begin_injection", "timeout")),
            ..FakeController::default()
        };
        let manifest = run(&config(0.01, 0.01), &out, &mut controller, None, None, None);
        assert_eq!(manifest["status"], "UNKNOWN");
        assert_eq!(controller.calls.len(), 1);
        assert!(manifest["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "controller_phase_failure:begin_injection"));
        assert_eq!(
            manifest["phaseFailures"],
            json!(["timeout:begin_injection"])
        );
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn collector_error_blocks_per_event_evidence() {
        let out = temp_dir("collector-error");
        let mut controller = FakeController::default();
        let mut collector = FakeCollector {
            error: Some("log read failed"),
            lines: Vec::new(),
        };
        let mut rows = FakeRows {
            rows: durable_rows(),
        };
        let manifest = run(
            &config(0.01, 0.01),
            &out,
            &mut controller,
            Some(&mut collector),
            Some(&mut rows),
            None,
        );
        assert_eq!(manifest["status"], "BLOCKED");
        assert_eq!(manifest["perEventRetryHistory"]["status"], "BLOCKED");
        assert!(manifest["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem.as_str().unwrap().contains("collect_e3_lines")));
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn missing_row_reader_blocks_per_event_evidence() {
        let out = temp_dir("missing-rows");
        let mut controller = FakeController::default();
        let mut collector = FakeCollector {
            error: None,
            lines: e3_pass_lines(),
        };
        let manifest = run(
            &config(0.01, 0.01),
            &out,
            &mut controller,
            Some(&mut collector),
            None,
            None,
        );
        assert_eq!(manifest["status"], "BLOCKED");
        assert_eq!(manifest["perEventRetryHistory"]["status"], "BLOCKED");
        assert!(manifest["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "durable_row_reconciliation_unavailable"));
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn missing_request_log_collector_stays_unknown() {
        let out = temp_dir("missing-logs");
        let mut controller = FakeController::default();
        let mut collector = FakeCollector {
            error: None,
            lines: e3_pass_lines(),
        };
        let mut rows = FakeRows {
            rows: durable_rows(),
        };
        let manifest = run(
            &config(0.01, 0.01),
            &out,
            &mut controller,
            Some(&mut collector),
            Some(&mut rows),
            None,
        );
        assert_eq!(manifest["status"], "UNKNOWN");
        assert_eq!(
            manifest["outputCategories"]["request_side_denial_pending"],
            "UNKNOWN"
        );
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn zero_duration_windows_skip_sampling_and_block() {
        let out = temp_dir("zero-window");
        let mut controller = FakeController::default();
        let mut collector = FakeCollector {
            error: None,
            lines: e3_pass_lines(),
        };
        let mut rows = FakeRows {
            rows: durable_rows(),
        };
        let mut logs = FakeLogs { lines: Vec::new() };
        let manifest = run(
            &config(0.0, 0.0),
            &out,
            &mut controller,
            Some(&mut collector),
            Some(&mut rows),
            Some(&mut logs),
        );
        assert_eq!(
            manifest["sampling"]["injection_window"]["outcome"],
            "skipped"
        );
        assert_eq!(manifest["sampling"]["drain_window"]["outcome"], "skipped");
        assert_eq!(manifest["status"], "BLOCKED");
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn marker_operation_id_mismatch_is_reported() {
        let out = temp_dir("marker-mismatch");
        let mut controller = FakeController {
            wrong_ack_operation: true,
            ..FakeController::default()
        };
        let mut collector = FakeCollector {
            error: None,
            lines: e3_pass_lines(),
        };
        let mut rows = FakeRows {
            rows: durable_rows(),
        };
        let manifest = run(
            &config(0.01, 0.01),
            &out,
            &mut controller,
            Some(&mut collector),
            Some(&mut rows),
            None,
        );
        assert_eq!(manifest["markersComplete"], true);
        assert_ne!(manifest["status"], "PASS");
        std::fs::remove_dir_all(out).ok();
    }
}
