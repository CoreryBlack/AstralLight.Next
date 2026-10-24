//! Native E1 live-campaign orchestration over injected adapter, log collector
//! and independent approval validator. The runner performs the live gate,
//! preflight/campaign cycle, log collection/classification and final
//! report/checksum artifacts without opening a network or subprocess itself.

use crate::e1_log::parse_e1_events;
use crate::e1_runner_contract::{
    check_live_gate, config_sha256, execute_campaign_offline, load_settings, CampaignAdapter,
    E1Error, LiveGateInput,
};
use crate::e3_e4_events::{classify_reader_attempt, CandidateIdentity, ReaderClassification};
use crate::experiment_common_contract::{verify_checksums, write_atomic_json, write_checksums};
use serde_json::{json, Value};
use std::path::Path;

pub trait E1LogCollector {
    fn collect(&mut self, node: &str, request_ids: &[String]) -> Result<Vec<String>, String>;
}

pub type ApprovalValidator<'a> = dyn FnMut(&str, &str, &str) -> Result<bool, String> + 'a;

fn write_blocked(out_dir: &Path, run_id: &str, problem: &str) -> Result<Value, E1Error> {
    let manifest = json!({
        "campaignId": run_id,
        "experiment": "E1",
        "mode": "campaign",
        "status": "BLOCKED",
        "problems": [problem],
        "e1_evidence_claim": "NOT_CLAIMED",
    });
    write_atomic_json(out_dir, "manifest.json", &manifest).map_err(E1Error::Io)?;
    write_checksums(out_dir, &["manifest.json"]).map_err(E1Error::Io)?;
    Ok(manifest)
}

fn collect_request_ids(manifest: &Value) -> Vec<String> {
    manifest["cycles"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|cycle| {
            cycle["readerAttempts"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|attempt| attempt["requestId"].as_str().map(str::to_owned))
        })
        .collect()
}

fn classification_value(request_id: &str, result: ReaderClassification) -> Value {
    json!({
        "requestId": request_id,
        "decision": result.decision,
        "reason": result.reason,
        "httpStatus": result.http_status,
        "candidateMatchesE0": result.candidate_matches_e0,
        "problems": result.problems,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn run_live_campaign(
    config: &Value,
    out_dir: &Path,
    live: bool,
    approval_ref: Option<&str>,
    approval_record: Option<&Value>,
    confirm_exec_l3: bool,
    validator: Option<&mut ApprovalValidator<'_>>,
    expected_e0: Option<&CandidateIdentity>,
    adapter: &mut impl CampaignAdapter,
    collector: &mut impl E1LogCollector,
) -> Result<Value, E1Error> {
    let settings = load_settings(config)?;
    let gate = check_live_gate(
        &settings,
        &LiveGateInput {
            live,
            approval_ref,
            approval_record,
            confirm_exec_l3,
            independent_validator: true,
        },
    );
    if let Some(problem) = gate {
        return write_blocked(out_dir, &settings.run_id, &problem);
    }
    let Some(validator) = validator else {
        return write_blocked(
            out_dir,
            &settings.run_id,
            "independent_user_approval_not_verified",
        );
    };
    let approval_ref = approval_ref.expect("validated approval ref");
    let config_hash = config_sha256(config);
    if !validator(&settings.run_id, approval_ref, &config_hash).unwrap_or(false) {
        return write_blocked(
            out_dir,
            &settings.run_id,
            "independent_user_approval_not_verified",
        );
    }

    let mut manifest = execute_campaign_offline(config, out_dir, adapter)?;
    let node = settings.node_rotation[0].clone();
    let request_ids = collect_request_ids(&manifest);
    let mut collector_status = "PASS";
    let mut collector_problem: Option<String> = None;
    let lines = match collector.collect(&node, &request_ids) {
        Ok(lines) => lines,
        Err(error) => {
            collector_status = "BLOCKED";
            collector_problem = Some(format!("e1_log_collection_failed:{error}"));
            Vec::new()
        }
    };
    let events = match parse_e1_events(lines.iter().map(String::as_str), &node) {
        Ok(events) => events,
        Err(error) => {
            collector_status = "BLOCKED";
            collector_problem = Some(format!("e1_log_parse_failed:{error}"));
            Vec::new()
        }
    };
    let mut classifications = Vec::new();
    for cycle in manifest["cycles"].as_array().into_iter().flatten() {
        for attempt in cycle["readerAttempts"].as_array().into_iter().flatten() {
            let Some(request_id) = attempt["requestId"].as_str() else {
                continue;
            };
            let http_status = attempt["httpStatus"]
                .as_u64()
                .and_then(|value| u16::try_from(value).ok());
            let result = classify_reader_attempt(&events, request_id, http_status, expected_e0);
            classifications.push(classification_value(request_id, result));
        }
    }
    let classifications_ok = collector_problem.is_none()
        && !classifications.is_empty()
        && classifications.iter().all(|row| {
            row["decision"] == "ALLOW" && row["problems"].as_array().is_some_and(Vec::is_empty)
        });
    let base_status = manifest["status"].as_str().unwrap_or("UNKNOWN").to_owned();
    let status = if collector_problem.is_some() {
        "BLOCKED"
    } else if base_status != "PASS" {
        base_status.as_str()
    } else if classifications_ok {
        "PASS"
    } else {
        "UNKNOWN"
    };
    let claim = if status == "PASS" {
        "CLAIMED"
    } else {
        "NOT_CLAIMED"
    };
    manifest["status"] = json!(status);
    manifest["e1_evidence_claim"] = json!(claim);
    manifest["liveGate"] = json!({
        "independentValidator": true,
        "configSha256": config_hash,
        "approvalRef": approval_ref,
    });
    manifest["collector"] = json!({
        "status": collector_status,
        "events": events.len(),
        "requestIds": request_ids,
        "problem": collector_problem,
    });
    manifest["classifications"] = json!(classifications);
    manifest["problems"] = if let Some(problem) = &collector_problem {
        json!([problem])
    } else {
        json!([])
    };

    write_atomic_json(out_dir, "manifest.json", &manifest).map_err(E1Error::Io)?;
    write_atomic_json(
        out_dir,
        "report.json",
        &json!({
            "campaignId": settings.run_id,
            "status": status,
            "claim": claim,
            "collector": manifest["collector"],
            "classifications": manifest["classifications"],
            "cycles": manifest["cycles"],
        }),
    )
    .map_err(E1Error::Io)?;
    let mut artifacts = vec![
        "preflight.json".to_owned(),
        "manifest.json".to_owned(),
        "report.json".to_owned(),
    ];
    for cycle in 1..=settings.cycles {
        artifacts.push(format!("e1-cycle-{cycle}.json"));
        artifacts.push(format!("e1-cycle-{cycle}-cleanup.json"));
    }
    let references = artifacts.iter().map(String::as_str).collect::<Vec<_>>();
    write_checksums(out_dir, &references).map_err(E1Error::Io)?;
    verify_checksums(out_dir, &out_dir.join("checksums.sha256")).map_err(E1Error::Io)?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e1_runner_contract::reader_request_id;
    use crate::e1_runner_contract::tests::FakeWorld;
    use serde_json::json;

    const E1_CLAIM_NONE: &str = "NOT_CLAIMED";

    const RUN_ID: &str = "authz-validation-e1unittest-run-001";
    const APPROVAL_REF: &str = "appr-2026-e1-0001";

    fn raw_config() -> Value {
        json!({
            "run_id": RUN_ID,
            "e1": {
                "admin_actor": {
                    "user_id": "9031",
                    "icard": "9041",
                    "card": "9061",
                    "domain": "9011",
                    "tenant": "9001"
                },
                "allowlist": {
                    "card_id": 9061,
                    "rule_set_id": 9071,
                    "resource_type": "monitor",
                    "action_code": "read",
                    "ref_type": "BASE"
                },
                "node_rotation": ["node-a"],
                "cycles": 1,
                "readers": 2,
                "max_requests_per_reader": 2,
                "fixture_synthetic": true,
                "reconcile_polls": 3,
                "reconcile_interval_s": 0.0
            }
        })
    }

    fn expected_e0() -> CandidateIdentity {
        CandidateIdentity([
            json!(9001),
            json!(9061),
            json!("rs-9071"),
            json!(1),
            json!("f".repeat(64)),
        ])
    }

    fn reader_lines() -> Vec<String> {
        let identity = json!({
            "tenant_id": 9001,
            "card_id": 9061,
            "grant_id": "rs-9071",
            "grant_revision": 1,
            "grant_hash": "f".repeat(64),
        });
        let mut sequence = 0u64;
        let mut lines = Vec::new();
        for reader in 1..=2 {
            for request in 1..=2 {
                let request_id = reader_request_id(RUN_ID, 1, reader, request);
                for (event, extra) in [
                    ("signed_context_bound", json!({})),
                    ("candidate_match", identity.clone()),
                    (
                        "decision_return",
                        json!({"allowed": true, "reason": "RULE_MATCH"}),
                    ),
                    ("host_admission", json!({})),
                ] {
                    sequence += 1;
                    let mut record = json!({
                        "message": "e1 authorization observation",
                        "event": event,
                        "request_id": request_id,
                        "event_sequence": sequence,
                        "wall_unix_ns": 1_758_000_000_000_000_000u64 + sequence,
                        "process_observation_id": "proc-a",
                    });
                    for (key, value) in extra.as_object().unwrap() {
                        record[key.as_str()] = value.clone();
                    }
                    lines.push(record.to_string());
                }
            }
        }
        lines
    }

    struct FakeCollector {
        error: Option<&'static str>,
        lines: Vec<String>,
    }

    impl E1LogCollector for FakeCollector {
        fn collect(&mut self, _node: &str, _request_ids: &[String]) -> Result<Vec<String>, String> {
            match self.error {
                Some(error) => Err(error.to_owned()),
                None => Ok(self.lines.clone()),
            }
        }
    }

    fn temp_dir(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("astral-e1-live-{label}-{}", uuid::Uuid::new_v4()))
    }

    fn run(
        out: &Path,
        live: bool,
        validator: Option<&mut ApprovalValidator<'_>>,
        collector: &mut FakeCollector,
        world: &mut FakeWorld,
    ) -> Value {
        run_live_campaign(
            &raw_config(),
            out,
            live,
            Some(APPROVAL_REF),
            Some(&json!({
                "run_id": RUN_ID,
                "approval_ref": APPROVAL_REF,
                "approval_scope": "E1-LIVE-CAMPAIGN",
                "approved_by": "human-operator",
                "approved_at": "2026-09-19T12:00:00Z",
            })),
            true,
            validator,
            Some(&expected_e0()),
            world,
            collector,
        )
        .unwrap()
    }

    #[test]
    fn live_runner_executes_gate_phases_logs_and_report() {
        let out = temp_dir("pass");
        let mut world = FakeWorld::clean();
        let mut collector = FakeCollector {
            error: None,
            lines: reader_lines(),
        };
        let mut validator = |run_id: &str, approval_ref: &str, hash: &str| {
            Ok(run_id == RUN_ID && approval_ref == APPROVAL_REF && hash.len() == 64)
        };
        let manifest = run(&out, true, Some(&mut validator), &mut collector, &mut world);
        assert_eq!(manifest["status"], "PASS", "{manifest}");
        assert_eq!(manifest["e1_evidence_claim"], "CLAIMED");
        assert_eq!(manifest["collector"]["status"], "PASS");
        assert_eq!(manifest["classifications"].as_array().unwrap().len(), 4);
        assert!(manifest["classifications"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["decision"] == "ALLOW"));
        for artifact in [
            "manifest.json",
            "report.json",
            "preflight.json",
            "e1-cycle-1.json",
        ] {
            assert!(out.join(artifact).exists(), "{artifact}");
        }
        verify_checksums(&out, &out.join("checksums.sha256")).unwrap();
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn live_false_is_blocked_before_campaign() {
        let out = temp_dir("offline");
        let mut world = FakeWorld::clean();
        let mut collector = FakeCollector {
            error: None,
            lines: Vec::new(),
        };
        let manifest = run(&out, false, None, &mut collector, &mut world);
        assert_eq!(manifest["status"], "BLOCKED");
        assert_eq!(manifest["problems"], json!(["live_not_enabled"]));
        assert_eq!(manifest["e1_evidence_claim"], E1_CLAIM_NONE);
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn missing_or_rejecting_validator_blocks_before_campaign() {
        let out = temp_dir("validator");
        let mut world = FakeWorld::clean();
        let mut collector = FakeCollector {
            error: None,
            lines: Vec::new(),
        };
        let manifest = run(&out, true, None, &mut collector, &mut world);
        assert_eq!(manifest["status"], "BLOCKED");
        assert!(manifest["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "independent_user_approval_not_verified"));
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn collector_error_blocks_final_evidence() {
        let out = temp_dir("collector-error");
        let mut world = FakeWorld::clean();
        let mut collector = FakeCollector {
            error: Some("log read failed"),
            lines: Vec::new(),
        };
        let mut validator = |_run_id: &str, _approval_ref: &str, _hash: &str| Ok(true);
        let manifest = run(&out, true, Some(&mut validator), &mut collector, &mut world);
        assert_eq!(manifest["status"], "BLOCKED");
        assert_eq!(manifest["collector"]["status"], "BLOCKED");
        assert!(manifest["collector"]["problem"]
            .as_str()
            .unwrap()
            .contains("e1_log_collection_failed"));
        assert_eq!(manifest["e1_evidence_claim"], E1_CLAIM_NONE);
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn missing_logs_stay_unknown_without_a_claim() {
        let out = temp_dir("missing-logs");
        let mut world = FakeWorld::clean();
        let mut collector = FakeCollector {
            error: None,
            lines: Vec::new(),
        };
        let mut validator = |_run_id: &str, _approval_ref: &str, _hash: &str| Ok(true);
        let manifest = run(&out, true, Some(&mut validator), &mut collector, &mut world);
        assert_eq!(manifest["status"], "UNKNOWN");
        assert_eq!(manifest["e1_evidence_claim"], E1_CLAIM_NONE);
        assert!(manifest["classifications"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["decision"] == "UNKNOWN"));
        std::fs::remove_dir_all(out).ok();
    }
}
