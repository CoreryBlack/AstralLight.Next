use crate::e1_log::{parse_e1_events as parse_e1_log_events, E1LogEvent};
use crate::e3_reconciliation::{E3Event, E3EventKind};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

#[cfg(test)]
const E1_MESSAGE: &str = "e1 authorization observation";
const E3_MESSAGE: &str = "e3 projector observation";
const E4_MESSAGE: &str = "e4 deployment precondition observation";
const IDENTITY_FIELDS: [&str; 5] = [
    "tenant_id",
    "card_id",
    "grant_id",
    "grant_revision",
    "grant_hash",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct E4Event {
    pub event: String,
    pub process_observation_id: String,
    pub sequence: u64,
    pub wall_unix_ns: u64,
    pub fields: Map<String, Value>,
    pub node: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateIdentity(pub [Value; 5]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReaderClassification {
    pub decision: &'static str,
    pub reason: String,
    pub http_status: Option<u16>,
    pub candidate_matches_e0: Option<bool>,
    pub problems: Vec<&'static str>,
}

fn flatten(record: &Map<String, Value>) -> Map<String, Value> {
    let mut flattened = record
        .get("fields")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for (key, value) in record {
        if key != "fields" {
            flattened
                .entry(key.clone())
                .or_insert_with(|| value.clone());
        }
    }
    flattened
}

fn safe_process_id(value: &str) -> bool {
    let normalized = value.replace('-', "_");
    let mut bytes = normalized.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && normalized.len() <= 128
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || b"._:".contains(&byte))
}

fn unsigned(value: Option<&Value>) -> Option<u64> {
    value.and_then(Value::as_u64).or_else(|| {
        value
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<u64>().ok())
    })
}

fn positive_u32(value: Option<&Value>) -> Result<Option<u32>, &'static str> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = unsigned(Some(value))
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or("invalid or non-positive E3 attempts")?;
    Ok(Some(value))
}

fn e3_kind(value: &str) -> Option<E3EventKind> {
    Some(match value {
        "enqueue_staged" => E3EventKind::EnqueueStaged,
        "claim_committed" => E3EventKind::ClaimCommitted,
        "publish_committed" => E3EventKind::PublishCommitted,
        "quarantine_committed" => E3EventKind::QuarantineCommitted,
        "terminal_unknown" => E3EventKind::TerminalUnknown,
        "backoff_committed" => E3EventKind::BackoffCommitted,
        "release_committed" => E3EventKind::ReleaseCommitted,
        "lease_left_to_expire" => E3EventKind::LeaseLeftToExpire,
        "retry_scheduled" => E3EventKind::RetryScheduled,
        "pointer_replan" => E3EventKind::PointerReplan,
        "release_requested" => E3EventKind::ReleaseRequested,
        _ => return None,
    })
}

pub fn parse_e3_events<I, S>(lines: I, node: &str) -> Result<Vec<E3Event>, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut events = Vec::new();
    for (index, raw) in lines.into_iter().enumerate() {
        let line_number = index + 1;
        let raw = raw.as_ref().trim();
        if raw.is_empty() {
            continue;
        }
        let Ok(record) = serde_json::from_str::<Value>(raw) else {
            continue;
        };
        let Some(record) = record.as_object() else {
            continue;
        };
        let fields = flatten(record);
        if fields.get("message").and_then(Value::as_str) != Some(E3_MESSAGE) {
            continue;
        }
        let event_name = fields
            .get("event")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("invalid E3 event name at line {line_number}"))?;
        let kind = e3_kind(event_name)
            .ok_or_else(|| format!("invalid E3 event name at line {line_number}"))?;
        let process_id = fields
            .get("process_observation_id")
            .and_then(Value::as_str)
            .filter(|value| safe_process_id(value))
            .ok_or_else(|| {
                format!("missing or unsafe E3 process observation id at line {line_number}")
            })?;
        let event_id = fields
            .get("event_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("missing E3 event_id at line {line_number}"))?;
        let sequence = unsigned(fields.get("event_sequence"))
            .filter(|value| *value > 0)
            .ok_or_else(|| format!("invalid E3 event number at line {line_number}"))?;
        let wall_unix_ns = unsigned(fields.get("wall_unix_ns"))
            .ok_or_else(|| format!("invalid E3 event number at line {line_number}"))?;
        let delta_event_id = unsigned(fields.get("delta_event_id"))
            .ok_or_else(|| format!("invalid E3 event number at line {line_number}"))?;
        let attempts = positive_u32(fields.get("attempts"))
            .map_err(|error| format!("{error} at line {line_number}"))?;
        let operation_id = match fields.get("operation_id") {
            None | Some(Value::Null) => None,
            Some(Value::String(value)) if !value.is_empty() => Some(value.clone()),
            _ => return Err(format!("invalid E3 operation_id at line {line_number}")),
        };
        let durable = fields.get("durable").and_then(Value::as_bool);
        let outcome = fields
            .get("outcome")
            .and_then(Value::as_str)
            .map(str::to_owned);
        events.push(E3Event {
            kind,
            node: node.to_owned(),
            process_observation_id: process_id.to_owned(),
            sequence,
            wall_unix_ns,
            delta_event_id,
            event_id: event_id.to_owned(),
            operation_id,
            attempts,
            durable,
            outcome,
        });
    }

    let mut seen = BTreeSet::new();
    for event in &events {
        if !seen.insert((
            event.node.as_str(),
            event.process_observation_id.as_str(),
            event.sequence,
        )) {
            return Err(format!(
                "duplicate E3 event_sequence {} in {}",
                event.sequence, event.process_observation_id
            ));
        }
    }
    events.sort_by(|left, right| {
        (&left.node, &left.process_observation_id, left.sequence).cmp(&(
            &right.node,
            &right.process_observation_id,
            right.sequence,
        ))
    });
    Ok(events)
}

pub fn parse_e4_events<I, S>(lines: I, node: &str) -> Result<Vec<E4Event>, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut events = Vec::new();
    for (index, raw) in lines.into_iter().enumerate() {
        let line_number = index + 1;
        let raw = raw.as_ref().trim();
        if raw.is_empty() {
            continue;
        }
        let Ok(record) = serde_json::from_str::<Value>(raw) else {
            continue;
        };
        let Some(record) = record.as_object() else {
            continue;
        };
        let fields = flatten(record);
        if fields.get("message").and_then(Value::as_str) != Some(E4_MESSAGE) {
            continue;
        }
        let event = fields
            .get("event")
            .and_then(Value::as_str)
            .filter(|value| {
                matches!(
                    *value,
                    "pool_connection_precondition" | "cache_epoch_observed"
                )
            })
            .ok_or_else(|| format!("invalid E4 event at line {line_number}"))?;
        let process_id = fields
            .get("process_observation_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("missing E4 process observation id at line {line_number}"))?;
        let sequence = unsigned(fields.get("event_sequence"))
            .filter(|value| *value > 0)
            .ok_or_else(|| format!("invalid E4 process event sequence at line {line_number}"))?;
        let wall_unix_ns = unsigned(fields.get("wall_unix_ns"))
            .ok_or_else(|| format!("invalid E4 event number at line {line_number}"))?;
        events.push(E4Event {
            event: event.to_owned(),
            process_observation_id: process_id.to_owned(),
            sequence,
            wall_unix_ns,
            fields,
            node: node.to_owned(),
        });
    }

    let mut seen = BTreeSet::new();
    for event in &events {
        if !seen.insert((
            event.node.as_str(),
            event.process_observation_id.as_str(),
            event.sequence,
        )) {
            return Err("invalid or duplicate E4 process event sequence".to_owned());
        }
    }
    events.sort_by(|left, right| {
        (&left.node, &left.process_observation_id, left.sequence).cmp(&(
            &right.node,
            &right.process_observation_id,
            right.sequence,
        ))
    });
    Ok(events)
}

pub fn events_for_request<'a>(events: &'a [E1LogEvent], request_id: &str) -> Vec<&'a E1LogEvent> {
    let mut selected = events
        .iter()
        .filter(|event| event.request_id == request_id)
        .collect::<Vec<_>>();
    selected.sort_by(|left, right| {
        (&left.node, &left.process_observation_id, left.sequence).cmp(&(
            &right.node,
            &right.process_observation_id,
            right.sequence,
        ))
    });
    selected
}

pub fn validate_request_terminal(
    request_events: &[&E1LogEvent],
    http_status: u16,
) -> Result<ReaderClassification, &'static str> {
    let decisions = request_events
        .iter()
        .filter(|event| event.event == "decision_return")
        .collect::<Vec<_>>();
    if decisions.len() != 1 {
        return Err("expected exactly one decision_return");
    }
    let allowed = decisions[0].fields.get("allowed").and_then(Value::as_bool);
    let reason = decisions[0]
        .fields
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let admissions = request_events
        .iter()
        .filter(|event| event.event == "host_admission")
        .count();
    let decision = if http_status == 200 {
        if allowed != Some(true) || admissions != 1 {
            return Err("HTTP 200 lacks one matching host_admission ALLOW");
        }
        "ALLOW"
    } else if matches!(http_status, 401 | 403 | 503) {
        if admissions != 0 {
            return Err("non-200 request crossed host admission");
        }
        if reason.contains("AUTHORIZATION_PENDING") {
            "PENDING"
        } else if matches!(http_status, 401 | 403) && allowed == Some(false) {
            "DENY"
        } else {
            "UNKNOWN"
        }
    } else {
        "UNKNOWN"
    };
    Ok(ReaderClassification {
        decision,
        reason,
        http_status: Some(http_status),
        candidate_matches_e0: None,
        problems: Vec::new(),
    })
}

pub fn candidate_identity(event: &E1LogEvent) -> Result<CandidateIdentity, &'static str> {
    let values = IDENTITY_FIELDS
        .iter()
        .map(|field| {
            event
                .fields
                .get(*field)
                .cloned()
                .ok_or("candidate event lacks exact grant identity")
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values
        .iter()
        .any(|value| value.is_null() || value.as_str() == Some(""))
    {
        return Err("candidate event lacks exact grant identity");
    }
    let values: [Value; 5] = values
        .try_into()
        .map_err(|_| "candidate event lacks exact grant identity")?;
    Ok(CandidateIdentity(values))
}

pub fn compare_candidate_to_e0(
    candidate: &E1LogEvent,
    expected_e0: Option<&CandidateIdentity>,
) -> Result<bool, &'static str> {
    let expected_e0 = expected_e0.ok_or("e0_identity_unproven")?;
    Ok(candidate_identity(candidate)? == *expected_e0)
}

pub fn classify_reader_attempt(
    events: &[E1LogEvent],
    request_id: &str,
    http_status: Option<u16>,
    expected_e0: Option<&CandidateIdentity>,
) -> ReaderClassification {
    let selected = events_for_request(events, request_id);
    if selected.is_empty() {
        return ReaderClassification {
            decision: "UNKNOWN",
            reason: String::new(),
            http_status,
            candidate_matches_e0: None,
            problems: vec!["no_server_events_for_request"],
        };
    }
    let Some(http_status) = http_status else {
        return ReaderClassification {
            decision: "UNKNOWN",
            reason: String::new(),
            http_status: None,
            candidate_matches_e0: None,
            problems: vec!["transport_error"],
        };
    };
    let mut result = match validate_request_terminal(&selected, http_status) {
        Ok(result) => result,
        Err(_) => {
            return ReaderClassification {
                decision: "UNKNOWN",
                reason: String::new(),
                http_status: Some(http_status),
                candidate_matches_e0: None,
                problems: vec!["invalid_request_terminal_evidence"],
            };
        }
    };
    if http_status == 200 {
        let candidates = selected
            .iter()
            .filter(|event| event.event == "candidate_match")
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            result.problems.push("candidate_match_missing_or_ambiguous");
        } else {
            match compare_candidate_to_e0(candidates[0], expected_e0) {
                Ok(matches) => {
                    result.candidate_matches_e0 = Some(matches);
                    if !matches {
                        result.problems.push("candidate_identity_does_not_match_e0");
                    }
                }
                Err("e0_identity_unproven") => result.problems.push("e0_identity_unproven"),
                Err(_) => result.problems.push("candidate_identity_incomplete"),
            }
        }
    }
    result
}

pub fn validate_status(value: &str) -> Result<&str, String> {
    match value {
        "PASS" | "FAIL" | "BLOCKED" | "UNKNOWN" | "PENDING" | "SKIP" | "PLANNED" => Ok(value),
        _ => Err(format!("invalid evidence status {value:?}")),
    }
}

pub fn parse_e1_events<I, S>(lines: I, node: &str) -> Result<Vec<E1LogEvent>, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    parse_e1_log_events(lines, node)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn e3_line(event: &str, sequence: Value, process: &str) -> String {
        json!({
            "fields": {
                "message": E3_MESSAGE,
                "event": event,
                "event_sequence": sequence,
                "wall_unix_ns": "1000",
                "delta_event_id": 7,
                "event_id": "event-7",
                "operation_id": "op-7",
                "attempts": 1,
                "durable": true,
                "outcome": "succeeded",
                "process_observation_id": process
            }
        })
        .to_string()
    }

    fn e4_line(event: &str, sequence: Value, process: &str) -> String {
        json!({
            "fields": {
                "message": E4_MESSAGE,
                "event": event,
                "event_sequence": sequence,
                "wall_unix_ns": 1000,
                "process_observation_id": process,
                "epoch_sha256": "c".repeat(64)
            }
        })
        .to_string()
    }

    fn e1_event(event: &str, sequence: u64, extra: Value) -> String {
        let mut fields = json!({
            "message": E1_MESSAGE,
            "event": event,
            "event_sequence": sequence,
            "wall_unix_ns": sequence * 1000,
            "request_id": "req-1",
            "process_observation_id": "proc-a"
        });
        for (key, value) in extra.as_object().unwrap() {
            fields[key] = value.clone();
        }
        json!({"fields":fields}).to_string()
    }

    fn identity_event(request: &str, event: &str, sequence: u64, revision: Value) -> String {
        json!({"fields":{
            "message":E1_MESSAGE,
            "event":event,
            "event_sequence":sequence,
            "wall_unix_ns":sequence * 1000,
            "request_id":request,
            "process_observation_id":"proc-a",
            "tenant_id":7,
            "card_id":17,
            "grant_id":"grant-17",
            "grant_revision":revision,
            "grant_hash":"a".repeat(64)
        }})
        .to_string()
    }

    #[test]
    fn e3_parser_filters_flattens_sorts_and_rejects_malformed_matching_records() {
        let parsed = parse_e3_events(
            [
                "not-json".to_owned(),
                r#"{"fields":{"message":"other"}}"#.to_owned(),
                e3_line("publish_committed", json!(2), "proc-b"),
                e3_line("claim_committed", json!(1), "proc-a"),
            ],
            "node-a",
        )
        .unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].kind, E3EventKind::ClaimCommitted);
        assert_eq!(parsed[0].sequence, 1);
        assert_eq!(parsed[1].durable, Some(true));
        assert_eq!(parsed[1].operation_id.as_deref(), Some("op-7"));
        assert_eq!(
            parse_e3_events([e3_line("other", json!(1), "proc-a")], "node-a").unwrap_err(),
            "invalid E3 event name at line 1"
        );
        assert!(
            parse_e3_events([e3_line("claim_committed", json!(0), "proc-a")], "node-a").is_err()
        );
        assert!(
            parse_e3_events([e3_line("claim_committed", json!(1), "bad id")], "node-a").is_err()
        );
        assert!(parse_e3_events(
            [
                e3_line("claim_committed", json!(1), "proc-a"),
                e3_line("claim_committed", json!(1), "proc-a")
            ],
            "node-a"
        )
        .unwrap_err()
        .starts_with("duplicate E3 event_sequence"));
    }

    #[test]
    fn e4_parser_accepts_only_known_observations_and_unique_positive_epoch_sequences() {
        let parsed = parse_e4_events(
            [
                e4_line("cache_epoch_observed", json!(2), "proc-b"),
                e4_line("pool_connection_precondition", json!(1), "proc-a"),
            ],
            "node-a",
        )
        .unwrap();
        assert_eq!(parsed[0].event, "pool_connection_precondition");
        assert_eq!(parsed[1].fields["epoch_sha256"], "c".repeat(64));
        assert!(parse_e4_events([e4_line("unknown", json!(1), "proc-a")], "node-a").is_err());
        assert!(parse_e4_events(
            [e4_line("cache_epoch_observed", json!(0), "proc-a")],
            "node-a"
        )
        .is_err());
        assert!(parse_e4_events(
            [
                e4_line("cache_epoch_observed", json!(1), "proc-a"),
                e4_line("cache_epoch_observed", json!(1), "proc-a")
            ],
            "node-a"
        )
        .is_err());
    }

    #[test]
    fn e1_request_selection_terminal_status_and_status_vocabulary_are_explicit() {
        let parsed = parse_e1_log_events(
            [e1_event(
                "decision_return",
                2,
                json!({"allowed":false,"reason":"AUTHORIZATION_PENDING"}),
            )],
            "node-a",
        )
        .unwrap();
        assert_eq!(events_for_request(&parsed, "missing").len(), 0);
        let selected = events_for_request(&parsed, "req-1");
        assert_eq!(selected.len(), 1);
        assert_eq!(
            validate_request_terminal(&selected, 503).unwrap().decision,
            "PENDING"
        );
        let with_admission = parse_e1_log_events(
            [
                e1_event(
                    "decision_return",
                    2,
                    json!({"allowed":false,"reason":"AUTHORIZATION_PENDING"}),
                ),
                e1_event("host_admission", 3, json!({})),
            ],
            "node-a",
        )
        .unwrap();
        assert_eq!(
            validate_request_terminal(&events_for_request(&with_admission, "req-1"), 403)
                .unwrap_err(),
            "non-200 request crossed host admission"
        );
        assert_eq!(validate_status("PLANNED").unwrap(), "PLANNED");
        assert_eq!(
            validate_status("SUCCESS").unwrap_err(),
            "invalid evidence status \"SUCCESS\""
        );

        let deny = parse_e1_events(
            [e1_event(
                "decision_return",
                4,
                json!({"allowed":false,"reason":"DEFAULT_DENY"}),
            )],
            "node-a",
        )
        .unwrap();
        assert_eq!(
            validate_request_terminal(&events_for_request(&deny, "req-1"), 403)
                .unwrap()
                .decision,
            "DENY"
        );
        assert_eq!(
            validate_request_terminal(&events_for_request(&deny, "req-1"), 503)
                .unwrap()
                .decision,
            "UNKNOWN"
        );
        assert_eq!(
            validate_request_terminal(&events_for_request(&deny, "req-1"), 200).unwrap_err(),
            "HTTP 200 lacks one matching host_admission ALLOW"
        );
    }

    #[test]
    fn terminal_decisions_require_unique_records_and_preserve_status_mapping() {
        let admitted = parse_e1_events(
            [
                e1_event("decision_return", 1, json!({"allowed":true,"reason":"ok"})),
                e1_event("host_admission", 2, json!({})),
            ],
            "node-a",
        )
        .unwrap();
        assert_eq!(
            validate_request_terminal(&events_for_request(&admitted, "req-1"), 200)
                .unwrap()
                .decision,
            "ALLOW"
        );

        let duplicate_admission = parse_e1_events(
            [
                e1_event("decision_return", 1, json!({"allowed":true,"reason":"ok"})),
                e1_event("host_admission", 2, json!({})),
                e1_event("host_admission", 3, json!({})),
            ],
            "node-a",
        )
        .unwrap();
        assert_eq!(
            validate_request_terminal(&events_for_request(&duplicate_admission, "req-1"), 200)
                .unwrap_err(),
            "HTTP 200 lacks one matching host_admission ALLOW"
        );

        let duplicate_decision = parse_e1_events(
            [
                e1_event("decision_return", 1, json!({"allowed":true,"reason":"ok"})),
                e1_event("decision_return", 2, json!({"allowed":true,"reason":"ok"})),
            ],
            "node-a",
        )
        .unwrap();
        assert_eq!(
            validate_request_terminal(&events_for_request(&duplicate_decision, "req-1"), 403)
                .unwrap_err(),
            "expected exactly one decision_return"
        );

        let pending = parse_e1_events(
            [e1_event(
                "decision_return",
                1,
                json!({"allowed":false,"reason":"AUTHORIZATION_PENDING: cold"}),
            )],
            "node-a",
        )
        .unwrap();
        for status in [403, 503] {
            assert_eq!(
                validate_request_terminal(&events_for_request(&pending, "req-1"), status)
                    .unwrap()
                    .decision,
                "PENDING"
            );
        }

        let denied = parse_e1_events(
            [e1_event(
                "decision_return",
                1,
                json!({"allowed":false,"reason":"DEFAULT_DENY"}),
            )],
            "node-a",
        )
        .unwrap();
        assert_eq!(
            validate_request_terminal(&events_for_request(&denied, "req-1"), 401)
                .unwrap()
                .decision,
            "DENY"
        );
        assert_eq!(
            validate_request_terminal(&events_for_request(&denied, "req-1"), 503)
                .unwrap()
                .decision,
            "UNKNOWN"
        );
        assert_eq!(
            validate_request_terminal(&events_for_request(&denied, "req-1"), 500)
                .unwrap()
                .decision,
            "UNKNOWN"
        );
    }

    #[test]
    fn e0_identity_is_exact_and_missing_or_changed_identity_stays_unproven() {
        let baseline = parse_e1_events(
            [identity_event("req-e0", "candidate_match", 1, json!(4))],
            "node-a",
        )
        .unwrap();
        let expected = candidate_identity(&baseline[0]).unwrap();
        assert_eq!(
            compare_candidate_to_e0(&baseline[0], Some(&expected)),
            Ok(true)
        );

        let changed = parse_e1_events(
            [identity_event("req-reader", "candidate_match", 2, json!(5))],
            "node-a",
        )
        .unwrap();
        assert_eq!(
            compare_candidate_to_e0(&changed[0], Some(&expected)),
            Ok(false)
        );
        assert_eq!(
            compare_candidate_to_e0(&baseline[0], None),
            Err("e0_identity_unproven")
        );

        let incomplete = parse_e1_events(
            [e1_event(
                "candidate_match",
                1,
                json!({"tenant_id":7,"card_id":17}),
            )],
            "node-a",
        )
        .unwrap();
        assert_eq!(
            candidate_identity(&incomplete[0]),
            Err("candidate event lacks exact grant identity")
        );
    }

    #[test]
    fn reader_classification_does_not_hide_missing_events_transport_or_e0_binding() {
        let events = parse_e1_events(
            [
                e1_event(
                    "decision_return",
                    1,
                    json!({"allowed":true,"reason":"PUBLISHED_EVIDENCE_ALLOW"}),
                ),
                identity_event("req-1", "candidate_match", 2, json!(4)),
                e1_event("host_admission", 3, json!({})),
            ],
            "node-a",
        )
        .unwrap();
        let candidate = events
            .iter()
            .find(|event| event.event == "candidate_match")
            .unwrap();
        let expected = candidate_identity(candidate).unwrap();
        let accepted = classify_reader_attempt(&events, "req-1", Some(200), Some(&expected));
        assert_eq!(accepted.decision, "ALLOW");
        assert_eq!(accepted.candidate_matches_e0, Some(true));
        let missing_identity = classify_reader_attempt(&events, "req-1", Some(200), None);
        assert_eq!(missing_identity.problems, ["e0_identity_unproven"]);
        let no_events = classify_reader_attempt(&events, "missing", Some(503), Some(&expected));
        assert_eq!(no_events.decision, "UNKNOWN");
        assert_eq!(no_events.problems, ["no_server_events_for_request"]);
        let transport = classify_reader_attempt(&events, "req-1", None, Some(&expected));
        assert_eq!(transport.problems, ["transport_error"]);
    }
}
