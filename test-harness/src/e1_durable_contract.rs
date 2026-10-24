//! E1 durable reconciliation and reader-classification contracts over supplied
//! evidence rows. These reducers never contact a node; they pin the decision
//! labels the live runner must emit.

use serde_json::{json, Value};

pub const AGGREGATE_RULE_SET: &str = "RULE_SET";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditRow {
    pub change_type: String,
    pub rule_set_id: i64,
    pub entry_id: Option<i64>,
    pub aggregate_type: String,
    pub aggregate_id: i64,
    pub operation_id: String,
    pub event_id: String,
    pub generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeltaRow {
    pub event_type: String,
    pub operation_id: String,
    pub card_id: i64,
    pub target_version: u64,
    pub status: String,
    pub event_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PointerRow {
    pub card_id: i64,
    pub operation_id: String,
    pub event_id: String,
    pub generation: u64,
    pub status: String,
    pub revoke_fence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableEvidence {
    pub aggregate_type: String,
    pub tenant_id: i64,
    pub rule_set_id: i64,
    pub card_id: i64,
    pub entry_id: i64,
    pub delete_operation_id: String,
    pub deltas: Vec<DeltaRow>,
    pub pointer: Option<PointerRow>,
    pub audit: Vec<AuditRow>,
    pub source_row_present: bool,
    pub source_row_count: Option<usize>,
    pub malformed: bool,
}

pub fn e1_durable_queries(
    tenant_id: i64,
    rule_set_id: i64,
    _card_id: i64,
    entry_id: i64,
    operation_id: &str,
) -> Vec<String> {
    vec![
        format!(
            "SELECT event_id, event_type, status, card_id, operation_id, target_version \
             FROM authorization_delta_event \
             WHERE tenant_id={tenant_id} AND aggregate_type='RULE_SET' AND aggregate_id={rule_set_id}"
        ),
        format!(
            "SELECT card_id, operation_id, event_id, generation, status, revoke_fence \
             FROM authorization_projection_current \
             WHERE tenant_id={tenant_id} AND aggregate_type='RULE_SET' AND aggregate_id={rule_set_id}"
        ),
        format!(
            "SELECT change_type, rule_set_id, entry_id, aggregate_type, aggregate_id, operation_id, event_id, generation \
             FROM rule_set_projection_audit \
             WHERE tenant_id={tenant_id} AND operation_id='{operation_id}'"
        ),
        format!(
            "SELECT COUNT(*) FROM rule_set_entry rse \
             INNER JOIN rule_set rs ON rs.id = rse.rule_set_id \
             WHERE rs.tenant_id={tenant_id} AND rse.rule_set_id={rule_set_id} AND rse.entry_id={entry_id}"
        ),
    ]
}

/// Raw TSV rows returned by the [`e1_durable_queries`] result set, in the same
/// column order as the SELECT lists. `read_failed` marks a transport-level
/// read failure for any member query.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RawDurableRows {
    pub deltas: Vec<Vec<String>>,
    pub pointer: Vec<Vec<String>>,
    pub audit: Vec<Vec<String>>,
    pub source_row_count: Option<Vec<String>>,
    pub read_failed: bool,
}

fn cell_i64(cell: &str) -> Option<i64> {
    cell.parse::<i64>().ok()
}

/// Parses raw query rows into a [`DurableEvidence`]. Rows with the wrong
/// arity or unparseable numeric cells set `malformed` and are dropped instead
/// of silently defaulting, mirroring the archived projection-snapshot
/// reader's fail-closed handling; an empty `source_row_count` member marks
/// the count unknown rather than zero.
pub fn parse_durable_evidence(
    raw: &RawDurableRows,
    aggregate_type: &str,
    tenant_id: i64,
    rule_set_id: i64,
    card_id: i64,
    entry_id: i64,
    delete_operation_id: &str,
) -> DurableEvidence {
    let mut malformed = raw.read_failed;
    let mut deltas = Vec::new();
    for row in &raw.deltas {
        match row.as_slice() {
            [event_id, event_type, status, row_card_id, operation_id, target_version] => {
                let (Some(row_card_id), Some(target_version)) =
                    (cell_i64(row_card_id), target_version.parse::<u64>().ok())
                else {
                    malformed = true;
                    continue;
                };
                deltas.push(DeltaRow {
                    event_type: event_type.clone(),
                    operation_id: operation_id.clone(),
                    card_id: row_card_id,
                    target_version,
                    status: status.clone(),
                    event_id: event_id.clone(),
                });
            }
            _ => malformed = true,
        }
    }
    let mut pointer = None;
    for row in &raw.pointer {
        match row.as_slice() {
            [row_card_id, operation_id, event_id, generation, status, revoke_fence] => {
                let (Some(row_card_id), Some(generation), Some(revoke_fence)) = (
                    cell_i64(row_card_id),
                    generation.parse::<u64>().ok(),
                    revoke_fence.parse::<u64>().ok(),
                ) else {
                    malformed = true;
                    continue;
                };
                pointer = Some(PointerRow {
                    card_id: row_card_id,
                    operation_id: operation_id.clone(),
                    event_id: event_id.clone(),
                    generation,
                    status: status.clone(),
                    revoke_fence,
                });
            }
            _ => malformed = true,
        }
    }
    let mut audit = Vec::new();
    for row in &raw.audit {
        match row.as_slice() {
            [change_type, row_rule_set_id, row_entry_id, row_aggregate_type, aggregate_id, operation_id, event_id, generation] =>
            {
                let Some(row_rule_set_id) = cell_i64(row_rule_set_id) else {
                    malformed = true;
                    continue;
                };
                let row_entry_id = if row_entry_id.is_empty() {
                    None
                } else {
                    match cell_i64(row_entry_id) {
                        Some(value) => Some(value),
                        None => {
                            malformed = true;
                            continue;
                        }
                    }
                };
                let Some(generation) = generation.parse::<u64>().ok() else {
                    malformed = true;
                    continue;
                };
                audit.push(AuditRow {
                    change_type: change_type.clone(),
                    rule_set_id: row_rule_set_id,
                    entry_id: row_entry_id,
                    aggregate_type: row_aggregate_type.clone(),
                    aggregate_id: cell_i64(aggregate_id).unwrap_or_default(),
                    operation_id: operation_id.clone(),
                    event_id: event_id.clone(),
                    generation,
                });
            }
            _ => malformed = true,
        }
    }
    let source_row_count = raw
        .source_row_count
        .as_ref()
        .and_then(|rows| rows.first())
        .and_then(|cell| cell.parse::<usize>().ok());
    if raw.source_row_count.as_ref().is_some_and(|rows| {
        rows.first()
            .is_some_and(|cell| cell.parse::<usize>().is_err())
    }) {
        malformed = true;
    }
    DurableEvidence {
        aggregate_type: aggregate_type.to_owned(),
        tenant_id,
        rule_set_id,
        card_id,
        entry_id,
        delete_operation_id: delete_operation_id.to_owned(),
        deltas,
        pointer,
        audit,
        source_row_present: source_row_count.is_some_and(|count| count > 0),
        source_row_count,
        malformed,
    }
}

fn matching_audits(evidence: &DurableEvidence) -> Vec<&AuditRow> {
    evidence
        .audit
        .iter()
        .filter(|row| {
            row.change_type == "DELETE"
                && row.rule_set_id == evidence.rule_set_id
                && row.entry_id == Some(evidence.entry_id)
                && row.aggregate_type == AGGREGATE_RULE_SET
                && row.aggregate_id == evidence.rule_set_id
        })
        .collect()
}

pub fn validate_e1_durable_evidence(evidence: &DurableEvidence) -> Value {
    let mut problems = Vec::new();
    if evidence.aggregate_type != AGGREGATE_RULE_SET {
        problems.push("unexpected_aggregate_type");
    }
    if evidence.malformed {
        problems.push("malformed_durable_rows");
    }
    if evidence.source_row_count.is_none() {
        problems.push("unknown_source_row_count");
    }
    if evidence.source_row_present || evidence.source_row_count.is_some_and(|count| count > 0) {
        problems.push("source_row_present_prevents_operation_publication_claim");
    }
    let deltas = evidence
        .deltas
        .iter()
        .filter(|row| {
            row.event_type == "REMOVE"
                && row.operation_id == evidence.delete_operation_id
                && row.card_id == evidence.card_id
        })
        .collect::<Vec<_>>();
    if deltas.is_empty() {
        problems.push("missing_delete_delta");
    } else if deltas.len() > 1 {
        problems.push("duplicate_operation_deltas");
    } else if deltas[0].status != "SUCCEEDED" || deltas[0].target_version == 0 {
        problems.push("operation_delta_attribute_mismatch");
    }
    match &evidence.pointer {
        None => problems.push("missing_pointer"),
        Some(pointer) => {
            if deltas.len() == 1
                && (pointer.operation_id != evidence.delete_operation_id
                    || pointer.event_id != deltas[0].event_id)
            {
                problems.push("stale_pointer_after_delete_delta");
            }
            if pointer.card_id != evidence.card_id {
                problems.push("pointer_card_mismatch");
            }
            if pointer.status != "READY" {
                problems.push("pointer_not_ready");
            }
        }
    }
    let audits = matching_audits(evidence);
    if audits.is_empty() {
        if evidence.audit.is_empty() {
            problems.push("missing_delete_audit_correlation");
        } else {
            problems.push("delete_audit_scope_mismatch");
        }
    } else if audits.len() > 1 {
        problems.push("duplicate_matching_delete_audits");
    }
    problems.sort_unstable();
    problems.dedup();
    json!({
        "status": if problems.is_empty() { "PASS" } else { "UNKNOWN" },
        "problems": problems,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeleteReconcileInput {
    pub audit_rows: Option<Vec<AuditRow>>,
    pub source_row_count: Option<usize>,
    pub publication_applied: bool,
    pub rule_set_id: i64,
    pub entry_id: i64,
    pub operation_id: String,
}

pub fn reconcile_delete(input: &DeleteReconcileInput) -> Value {
    let (Some(audit_rows), Some(source_count)) = (&input.audit_rows, input.source_row_count) else {
        return json!({
            "state": "unknown",
            "reason": "reconciliation_read_failed",
        });
    };
    let matching = audit_rows
        .iter()
        .filter(|row| {
            row.change_type == "DELETE"
                && row.rule_set_id == input.rule_set_id
                && row.entry_id == Some(input.entry_id)
                && row.aggregate_type == AGGREGATE_RULE_SET
                && row.aggregate_id == input.rule_set_id
        })
        .count();
    if source_count == 0 && matching == 1 {
        if input.publication_applied {
            return json!({"state": "applied", "matchingDeleteAuditRows": 1});
        }
        return json!({
            "state": "unknown",
            "reason": "operation_publication_unproven_after_delete",
            "matchingDeleteAuditRows": 1,
        });
    }
    if source_count > 0 && audit_rows.is_empty() {
        return json!({"state": "not_applied", "matchingDeleteAuditRows": 0});
    }
    json!({
        "state": "unknown",
        "reason": "contradictory_or_missing_reconciliation_evidence",
        "matchingDeleteAuditRows": matching,
    })
}

pub fn corrective_delete_attempts(result: &Value) -> usize {
    usize::from(result["state"] == "not_applied")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionState {
    Ready,
    Quiescent,
    Unknown,
}

pub fn projection_convergence(samples: &[ProjectionState]) -> Value {
    let converged = samples
        .iter()
        .any(|state| matches!(state, ProjectionState::Ready | ProjectionState::Quiescent));
    json!({
        "status": if converged { "PASS" } else { "UNKNOWN" },
        "raceSkipped": !converged,
    })
}

#[derive(Clone, Debug, PartialEq)]
pub struct ReaderAttemptInput {
    pub request_id: String,
    pub http_status: Option<u16>,
    pub transport_error: Option<String>,
    pub has_server_events: bool,
    pub decision_allowed: Option<bool>,
    pub decision_reason: Option<String>,
    pub candidate_identity_matches_e0: Option<bool>,
    pub commit_interval: Option<(u64, u64)>,
    pub final_observation: Option<(u64, u64)>,
}

pub fn classify_reader_attempt(attempt: &ReaderAttemptInput) -> Value {
    let mut row = json!({
        "requestId": attempt.request_id,
        "httpStatus": attempt.http_status,
        "decision": Value::Null,
        "category": Value::Null,
        "theoremDomain": false,
        "staleAllowViolation": false,
        "problems": [],
    });
    let mut problems = Vec::new();
    if !attempt.has_server_events {
        problems.push("no_server_events_for_request");
        if let Some(error) = &attempt.transport_error {
            problems.push(error.as_str());
        }
        row["decision"] = json!("UNKNOWN");
        row["problems"] = json!(problems);
        return row;
    }
    match attempt.http_status {
        Some(200) => {
            row["decision"] = json!("ALLOW");
            let Some((commit_start, commit_end)) = attempt.commit_interval else {
                problems.push("missing_server_commit_interval");
                row["category"] = json!("unclassified-unknown");
                row["problems"] = json!(problems);
                return row;
            };
            if attempt.candidate_identity_matches_e0 != Some(true) {
                problems.push(if attempt.candidate_identity_matches_e0 == Some(false) {
                    "candidate_identity_does_not_match_e0"
                } else {
                    "e0_identity_unproven"
                });
                row["category"] = json!("unclassified-unknown");
                row["problems"] = json!(problems);
                return row;
            }
            let Some((observation_start, observation_end)) = attempt.final_observation else {
                problems.push("missing_final_observation_interval");
                row["category"] = json!("unclassified-unknown");
                row["problems"] = json!(problems);
                return row;
            };
            if commit_end < observation_start {
                row["category"] = json!("post-commit-before-final-observation");
                row["theoremDomain"] = json!(true);
                row["staleAllowViolation"] = json!(true);
            } else if observation_end < commit_start {
                row["category"] = json!("pre-commit");
            } else {
                row["category"] = json!("interval-overlap-unknown");
            }
        }
        Some(status) => {
            let reason = attempt.decision_reason.as_deref().unwrap_or_default();
            row["decision"] = json!(if matches!(status, 401 | 403 | 503)
                && reason.contains("AUTHORIZATION_PENDING")
            {
                "PENDING"
            } else if matches!(status, 401 | 403) && attempt.decision_allowed == Some(false) {
                "DENY"
            } else {
                "UNKNOWN"
            });
        }
        None => {
            row["decision"] = json!("UNKNOWN");
            if let Some(error) = &attempt.transport_error {
                problems.push(error.as_str());
            }
            row["problems"] = json!(problems);
        }
    }
    row
}

pub fn campaign_classification_status(rows: &[Value]) -> &'static str {
    if rows.iter().any(|row| row["staleAllowViolation"] == true) {
        "FAIL"
    } else if rows
        .iter()
        .any(|row| row["decision"] == "UNKNOWN" || row["category"] == "unclassified-unknown")
    {
        "UNKNOWN"
    } else {
        "PASS"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audit(change: &str, entry: Option<i64>, aggregate: &str) -> AuditRow {
        AuditRow {
            change_type: change.to_owned(),
            rule_set_id: 9071,
            entry_id: entry,
            aggregate_type: aggregate.to_owned(),
            aggregate_id: 9071,
            operation_id: "del-1".to_owned(),
            event_id: "evt-1".to_owned(),
            generation: 1,
        }
    }

    fn delta(event_type: &str, operation: &str, status: &str, event_id: &str) -> DeltaRow {
        DeltaRow {
            event_type: event_type.to_owned(),
            operation_id: operation.to_owned(),
            card_id: 9061,
            target_version: 1,
            status: status.to_owned(),
            event_id: event_id.to_owned(),
        }
    }

    fn pointer(card: i64, operation: &str, event_id: &str) -> PointerRow {
        PointerRow {
            card_id: card,
            operation_id: operation.to_owned(),
            event_id: event_id.to_owned(),
            generation: 1,
            status: "READY".to_owned(),
            revoke_fence: 0,
        }
    }

    fn happy_evidence() -> DurableEvidence {
        DurableEvidence {
            aggregate_type: AGGREGATE_RULE_SET.to_owned(),
            tenant_id: 9001,
            rule_set_id: 9071,
            card_id: 9061,
            entry_id: 4001,
            delete_operation_id: "del-1".to_owned(),
            deltas: vec![delta("REMOVE", "del-1", "SUCCEEDED", "evt-1")],
            pointer: Some(pointer(9061, "del-1", "evt-1")),
            audit: vec![audit("DELETE", Some(4001), AGGREGATE_RULE_SET)],
            source_row_present: false,
            source_row_count: Some(0),
            malformed: false,
        }
    }

    #[test]
    fn ruleset_campaign_uses_only_the_ruleset_delta_chain() {
        let queries = e1_durable_queries(9001, 9071, 9061, 4001, "del-1");
        // Every durable query, including the source-row count join, is tenant
        // scoped.
        assert!(queries.iter().all(|query| query.contains("tenant_id=9001")));
        assert!(queries
            .iter()
            .all(|query| !query.contains("aggregate_type='USER_CARD'")));
        assert!(queries
            .iter()
            .any(|query| query.contains("aggregate_type='RULE_SET'")));
        let mut evidence = happy_evidence();
        evidence.aggregate_type = "CARD".to_owned();
        assert!(validate_e1_durable_evidence(&evidence)["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "unexpected_aggregate_type"));
    }

    #[test]
    fn durable_queries_are_tenant_scoped() {
        let queries = e1_durable_queries(9002, 9071, 9061, 4001, "del-9");
        assert!(queries.iter().all(|query| query.contains("tenant_id=9002")));
        assert!(queries
            .iter()
            .any(|query| query.contains("operation_id='del-9'")));
        assert!(queries
            .iter()
            .any(|query| query.contains("rse.entry_id=4001")));
        assert!(queries
            .iter()
            .any(|query| query.contains("rse.rule_set_id=9071")));
    }

    #[test]
    fn unknown_delete_is_reconciled_then_corrected_once() {
        let unknown = reconcile_delete(&DeleteReconcileInput {
            audit_rows: None,
            source_row_count: Some(0),
            publication_applied: false,
            rule_set_id: 9071,
            entry_id: 4001,
            operation_id: "del-1".to_owned(),
        });
        assert_eq!(unknown["state"], "unknown");
        assert_eq!(corrective_delete_attempts(&unknown), 0);
        let not_applied = reconcile_delete(&DeleteReconcileInput {
            audit_rows: Some(Vec::new()),
            source_row_count: Some(1),
            publication_applied: false,
            rule_set_id: 9071,
            entry_id: 4001,
            operation_id: "del-1".to_owned(),
        });
        assert_eq!(not_applied["state"], "not_applied");
        assert_eq!(corrective_delete_attempts(&not_applied), 1);
    }

    #[test]
    fn missing_delete_delta_prevents_pass() {
        let mut evidence = happy_evidence();
        evidence.deltas.clear();
        assert!(validate_e1_durable_evidence(&evidence)["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "missing_delete_delta"));
    }

    #[test]
    fn stale_pointer_after_delete_delta_prevents_pass() {
        let mut evidence = happy_evidence();
        evidence.pointer = Some(pointer(9061, "other-op", "evt-1"));
        assert!(validate_e1_durable_evidence(&evidence)["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "stale_pointer_after_delete_delta"));
    }

    #[test]
    fn delete_audit_for_another_entry_cannot_prove_target_delete() {
        let mut evidence = happy_evidence();
        evidence.audit = vec![audit("DELETE", Some(9999), AGGREGATE_RULE_SET)];
        assert!(validate_e1_durable_evidence(&evidence)["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "delete_audit_scope_mismatch"));
        let reconcile = reconcile_delete(&DeleteReconcileInput {
            audit_rows: Some(evidence.audit),
            source_row_count: Some(0),
            publication_applied: true,
            rule_set_id: 9071,
            entry_id: 4001,
            operation_id: "del-1".to_owned(),
        });
        assert_eq!(reconcile["state"], "unknown");
    }

    #[test]
    fn delete_audit_with_wrong_aggregate_scope_cannot_prove_target_delete() {
        let mut evidence = happy_evidence();
        evidence.audit = vec![audit("DELETE", Some(4001), "USER_CARD")];
        assert!(validate_e1_durable_evidence(&evidence)["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "delete_audit_scope_mismatch"));
    }

    #[test]
    fn source_row_present_prevents_operation_publication_claim() {
        let mut evidence = happy_evidence();
        evidence.source_row_present = true;
        assert!(validate_e1_durable_evidence(&evidence)["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "source_row_present_prevents_operation_publication_claim"));
    }

    #[test]
    fn empty_count_result_is_unknown_not_source_absence() {
        let mut evidence = happy_evidence();
        evidence.source_row_count = None;
        assert!(validate_e1_durable_evidence(&evidence)["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "unknown_source_row_count"));
        let reconcile = reconcile_delete(&DeleteReconcileInput {
            audit_rows: Some(Vec::new()),
            source_row_count: None,
            publication_applied: false,
            rule_set_id: 9071,
            entry_id: 4001,
            operation_id: "del-1".to_owned(),
        });
        assert_eq!(reconcile["state"], "unknown");
        assert_eq!(reconcile["reason"], "reconciliation_read_failed");
    }

    #[test]
    fn duplicate_matching_delete_audits_prevent_pass() {
        let mut evidence = happy_evidence();
        evidence
            .audit
            .push(audit("DELETE", Some(4001), AGGREGATE_RULE_SET));
        assert!(validate_e1_durable_evidence(&evidence)["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "duplicate_matching_delete_audits"));
    }

    #[test]
    fn operation_delta_attribute_mismatches_prevent_pass() {
        let mut evidence = happy_evidence();
        evidence.deltas = vec![delta("REMOVE", "del-1", "FAILED", "evt-1")];
        assert!(validate_e1_durable_evidence(&evidence)["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "operation_delta_attribute_mismatch"));
    }

    #[test]
    fn duplicate_operation_deltas_prevent_pass() {
        let mut evidence = happy_evidence();
        evidence
            .deltas
            .push(delta("REMOVE", "del-1", "SUCCEEDED", "evt-2"));
        assert!(validate_e1_durable_evidence(&evidence)["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "duplicate_operation_deltas"));
    }

    #[test]
    fn pointer_card_mismatch_prevents_pass() {
        let mut evidence = happy_evidence();
        evidence.pointer = Some(pointer(9999, "del-1", "evt-1"));
        assert!(validate_e1_durable_evidence(&evidence)["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "pointer_card_mismatch"));
    }

    #[test]
    fn projection_snapshot_malformed_durable_rows_are_unknown() {
        let mut evidence = happy_evidence();
        evidence.malformed = true;
        assert!(validate_e1_durable_evidence(&evidence)["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "malformed_durable_rows"));
    }

    #[test]
    fn missing_delete_audit_correlation_prevents_pass() {
        let mut evidence = happy_evidence();
        evidence.audit.clear();
        assert!(validate_e1_durable_evidence(&evidence)["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "missing_delete_audit_correlation"));
    }

    #[test]
    fn projection_never_converging_is_unknown_and_skips_the_race() {
        let report = projection_convergence(&[ProjectionState::Unknown, ProjectionState::Unknown]);
        assert_eq!(report["status"], "UNKNOWN");
        assert_eq!(report["raceSkipped"], true);
        let converged = projection_convergence(&[ProjectionState::Quiescent]);
        assert_eq!(converged["status"], "PASS");
    }

    fn attempt(http_status: Option<u16>) -> ReaderAttemptInput {
        ReaderAttemptInput {
            request_id: "req-1".to_owned(),
            http_status,
            transport_error: None,
            has_server_events: true,
            decision_allowed: Some(true),
            decision_reason: Some("RULE_MATCH".to_owned()),
            candidate_identity_matches_e0: Some(true),
            commit_interval: Some((1, 2)),
            final_observation: Some((10, 20)),
        }
    }

    #[test]
    fn stale_allow_reader_is_classified_violation_and_fails_campaign() {
        let row = classify_reader_attempt(&attempt(Some(200)));
        assert_eq!(row["category"], "post-commit-before-final-observation");
        assert_eq!(row["staleAllowViolation"], true);
        assert_eq!(campaign_classification_status(&[row]), "FAIL");
    }

    #[test]
    fn classify_pending_and_transport_failures() {
        let mut pending = attempt(Some(403));
        pending.decision_allowed = Some(false);
        pending.decision_reason = Some("AUTHORIZATION_PENDING".to_owned());
        assert_eq!(classify_reader_attempt(&pending)["decision"], "PENDING");

        let mut lost = attempt(None);
        lost.has_server_events = false;
        lost.transport_error = Some("URLError".to_owned());
        let row = classify_reader_attempt(&lost);
        assert_eq!(row["decision"], "UNKNOWN");
        assert!(row["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "URLError"));
    }

    #[test]
    fn classify_incomplete_request_events_stays_unknown() {
        let mut incomplete = attempt(Some(200));
        incomplete.candidate_identity_matches_e0 = None;
        let row = classify_reader_attempt(&incomplete);
        assert_eq!(row["category"], "unclassified-unknown");
        assert!(row["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "e0_identity_unproven"));
    }

    #[test]
    fn successful_empty_post_race_log_slice_is_unknown() {
        let mut empty = attempt(Some(200));
        empty.has_server_events = false;
        let row = classify_reader_attempt(&empty);
        assert_eq!(row["decision"], "UNKNOWN");
        assert!(row["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "no_server_events_for_request"));
    }

    #[test]
    fn parse_durable_evidence_builds_rows_in_query_column_order() {
        let raw = RawDurableRows {
            deltas: vec![vec![
                "evt-del-1".to_owned(),
                "REMOVE".to_owned(),
                "SUCCEEDED".to_owned(),
                "9061".to_owned(),
                "del-1".to_owned(),
                "2".to_owned(),
            ]],
            pointer: vec![vec![
                "9061".to_owned(),
                "del-1".to_owned(),
                "evt-del-1".to_owned(),
                "2".to_owned(),
                "READY".to_owned(),
                "0".to_owned(),
            ]],
            audit: vec![vec![
                "DELETE".to_owned(),
                "9071".to_owned(),
                "4001".to_owned(),
                "RULE_SET".to_owned(),
                "9071".to_owned(),
                "del-1".to_owned(),
                "evt-del-1".to_owned(),
                "2".to_owned(),
            ]],
            source_row_count: Some(vec!["0".to_owned()]),
            read_failed: false,
        };
        let evidence =
            parse_durable_evidence(&raw, AGGREGATE_RULE_SET, 9001, 9071, 9061, 4001, "del-1");
        assert!(!evidence.malformed);
        assert_eq!(
            evidence.deltas,
            vec![DeltaRow {
                event_type: "REMOVE".to_owned(),
                operation_id: "del-1".to_owned(),
                card_id: 9061,
                target_version: 2,
                status: "SUCCEEDED".to_owned(),
                event_id: "evt-del-1".to_owned(),
            }]
        );
        assert_eq!(
            evidence.pointer.as_ref(),
            Some(&PointerRow {
                card_id: 9061,
                operation_id: "del-1".to_owned(),
                event_id: "evt-del-1".to_owned(),
                generation: 2,
                status: "READY".to_owned(),
                revoke_fence: 0,
            })
        );
        assert_eq!(evidence.audit.len(), 1);
        assert_eq!(evidence.audit[0].entry_id, Some(4001));
        assert_eq!(evidence.source_row_count, Some(0));
        assert!(!evidence.source_row_present);
        let validation = validate_e1_durable_evidence(&evidence);
        assert_eq!(validation["status"], "PASS", "{validation}");
    }

    #[test]
    fn parse_durable_evidence_fails_closed_on_malformed_rows() {
        let mut raw = RawDurableRows {
            deltas: vec![vec![
                "evt-del-1".to_owned(),
                "REMOVE".to_owned(),
                "SUCCEEDED".to_owned(),
                "not-a-card".to_owned(),
                "del-1".to_owned(),
                "2".to_owned(),
            ]],
            pointer: vec![],
            audit: vec![vec!["DELETE".to_owned(), "9071".to_owned()]],
            source_row_count: Some(vec!["not-a-number".to_owned()]),
            read_failed: false,
        };
        let evidence =
            parse_durable_evidence(&raw, AGGREGATE_RULE_SET, 9001, 9071, 9061, 4001, "del-1");
        assert!(evidence.malformed);
        assert!(evidence.deltas.is_empty());
        assert!(evidence.source_row_count.is_none());
        let validation = validate_e1_durable_evidence(&evidence);
        assert_eq!(validation["status"], "UNKNOWN");
        assert!(validation["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "malformed_durable_rows"));

        raw.read_failed = true;
        let evidence =
            parse_durable_evidence(&raw, AGGREGATE_RULE_SET, 9001, 9071, 9061, 4001, "del-1");
        assert!(evidence.malformed);
    }
}
