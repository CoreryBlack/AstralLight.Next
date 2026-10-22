use serde_json::{Map, Value};
use std::collections::BTreeSet;

const AUTHZ_MESSAGE: &str = "e1 authorization observation";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct E1LogEvent {
    pub event: String,
    pub request_id: String,
    pub sequence: i64,
    pub wall_unix_ns: i64,
    pub fields: Map<String, Value>,
    pub node: String,
    pub process_observation_id: String,
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

fn integer(value: Option<&Value>) -> Option<i64> {
    value.and_then(Value::as_i64).or_else(|| {
        value
            .and_then(Value::as_str)
            .and_then(|item| item.parse().ok())
    })
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

pub fn parse_e1_events<I, S>(lines: I, node: &str) -> Result<Vec<E1LogEvent>, String>
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
        if fields.get("message").and_then(Value::as_str) != Some(AUTHZ_MESSAGE) {
            continue;
        }
        let sequence = integer(fields.get("event_sequence"))
            .ok_or_else(|| format!("invalid authz event number at line {line_number}"))?;
        let wall_unix_ns = integer(fields.get("wall_unix_ns"))
            .ok_or_else(|| format!("invalid authz event number at line {line_number}"))?;
        let event = fields
            .get("event")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("missing authz event name at line {line_number}"))?;
        let request_id = fields
            .get("request_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("missing request_id at line {line_number}"))?;
        let process_observation_id = fields
            .get("process_observation_id")
            .and_then(Value::as_str)
            .filter(|value| safe_process_id(value))
            .ok_or_else(|| {
                format!("missing or unsafe E1 process observation id at line {line_number}")
            })?
            .to_owned();
        let event = event.to_owned();
        let request_id = request_id.to_owned();
        events.push(E1LogEvent {
            event,
            request_id,
            sequence,
            wall_unix_ns,
            fields,
            node: node.to_owned(),
            process_observation_id,
        });
    }

    events.sort_by(|left, right| {
        (&left.node, &left.process_observation_id, left.sequence).cmp(&(
            &right.node,
            &right.process_observation_id,
            right.sequence,
        ))
    });
    let mut seen = BTreeSet::new();
    for event in &events {
        let key = (
            event.node.as_str(),
            event.process_observation_id.as_str(),
            event.sequence,
        );
        if !seen.insert(key) {
            return Err(format!(
                "duplicate event_sequence {} in {} on {}",
                event.sequence,
                event.process_observation_id,
                if event.node.is_empty() {
                    "node"
                } else {
                    &event.node
                }
            ));
        }
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(sequence: Value, process: &str, request: &str) -> String {
        serde_json::json!({
            "target": "authz_e1",
            "fields": {
                "message": AUTHZ_MESSAGE,
                "event": "decision_return",
                "event_sequence": sequence,
                "wall_unix_ns": "1000",
                "request_id": request,
                "process_observation_id": process,
                "allowed": true
            }
        })
        .to_string()
    }

    #[test]
    fn parser_flattens_filters_sorts_and_keeps_process_epochs_distinct() {
        let nested = serde_json::json!({
            "message": AUTHZ_MESSAGE,
            "event": "nested_event",
            "event_sequence": 1,
            "wall_unix_ns": 1000,
            "request_id": "nested-request",
            "process_observation_id": "proc-d",
            "allowed": true,
            "extra": true
        });
        let mut outer = serde_json::json!({
            "message": "outer-message-must-not-win",
            "event": "outer_event",
            "event_sequence": 99,
            "wall_unix_ns": 99,
            "request_id": "outer-request",
            "process_observation_id": "proc-z",
            "fields": nested
        });
        outer["target"] = "authz_e1".into();
        let parsed = parse_e1_events(
            [
                "not-json".to_owned(),
                serde_json::json!({"message":"other event"}).to_string(),
                line(2.into(), "proc-b", "request-b"),
                line("1".into(), "proc-a", "request-a"),
                line(1.into(), "proc-c", "request-c"),
                outer.to_string(),
            ],
            "node-a",
        )
        .unwrap();
        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed[0].process_observation_id, "proc-a");
        assert_eq!(parsed[0].sequence, 1);
        assert_eq!(parsed[1].process_observation_id, "proc-b");
        assert_eq!(parsed[2].process_observation_id, "proc-c");
        assert_eq!(parsed[3].process_observation_id, "proc-d");
        assert_eq!(parsed[3].event, "nested_event");
        assert_eq!(parsed[3].request_id, "nested-request");
        assert_eq!(parsed[3].sequence, 1);
        assert_eq!(parsed[3].fields["extra"], true);
        assert_eq!(parsed[3].fields["message"], AUTHZ_MESSAGE);
        assert_eq!(parsed[0].fields["allowed"], true);
    }

    #[test]
    fn parser_rejects_malformed_matching_records_and_duplicate_epoch_sequences() {
        assert_eq!(
            parse_e1_events([line(Value::Null, "proc-a", "req")], "node-a").unwrap_err(),
            "invalid authz event number at line 1"
        );
        assert!(parse_e1_events([line(1.into(), "bad id", "req")], "node-a").is_err());
        assert!(parse_e1_events([line(1.into(), "proc-a", "")], "node-a").is_err());
        let duplicate = line(1.into(), "proc-a", "req");
        assert!(parse_e1_events([duplicate.clone(), duplicate], "node-a")
            .unwrap_err()
            .starts_with("duplicate event_sequence 1"));
        assert!(parse_e1_events(
            [
                line(1.into(), "proc-a", "req-1"),
                line(1.into(), "proc-a", "req-2")
            ],
            "node-a"
        )
        .is_err());
    }
}
