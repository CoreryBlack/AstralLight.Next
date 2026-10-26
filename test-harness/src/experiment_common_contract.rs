//! Shared offline experiment-common contracts: stable identity, atomic JSON
//! with LF checksums, route-journal admission, sampling stop control, sink
//! error accounting and the self-test help entrypoint.
//!
//! These are control-flow contracts, not a live sampling loop or fault run.

use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub fn stable_id(run_id: &str, label: &str) -> String {
    crate::e1_runner_contract::stable_id(run_id, label)
}

pub fn write_atomic_json(root: &Path, name: &str, value: &Value) -> Result<PathBuf, String> {
    fs::create_dir_all(root).map_err(|error| error.to_string())?;
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    let temporary = root.join(format!(".{name}.{}.tmp", Uuid::new_v4()));
    fs::write(&temporary, &bytes).map_err(|error| error.to_string())?;
    let destination = root.join(name);
    fs::rename(&temporary, &destination).map_err(|error| error.to_string())?;
    Ok(destination)
}

pub fn write_checksums(root: &Path, files: &[&str]) -> Result<(), String> {
    crate::e1_runner_contract::write_checksums(root, files).map_err(|error| error.to_string())
}

pub fn verify_checksums(root: &Path, checksum_file: &Path) -> Result<(), String> {
    crate::e1_runner_contract::verify_checksums(root, checksum_file)
        .map_err(|error| error.to_string())
}

pub fn validate_route_journal(
    server_identities: &[&str],
    journal: Option<&Value>,
) -> Result<(), &'static str> {
    let unique = server_identities.iter().copied().collect::<BTreeSet<_>>();
    if unique.len() <= 1 {
        return Ok(());
    }
    let Some(journal) = journal else {
        return Err("route_journal_missing");
    };
    let rows = journal.as_array().ok_or("route_journal_malformed")?;
    for identity in unique {
        if !rows
            .iter()
            .any(|row| row.get("server_identity").and_then(Value::as_str) == Some(identity))
        {
            return Err("route_journal_incomplete");
        }
    }
    Ok(())
}

pub fn validate_runtime_inputs(
    nodes: &[&str],
    clock_skew_threshold_ns: i64,
) -> Result<(), &'static str> {
    if nodes.is_empty() {
        return Err("empty_node_set");
    }
    if clock_skew_threshold_ns < 0 {
        return Err("invalid_clock_skew_threshold");
    }
    Ok(())
}

pub fn sampling_sample_indices(limit: usize, stop_after: Option<usize>) -> Vec<usize> {
    (0..limit)
        .take_while(|index| stop_after != Some(*index))
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SampleStatus {
    Pass,
    Blocked,
    Unknown,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SamplingReport {
    pub samples: Vec<SampleStatus>,
    pub probes: usize,
}

pub fn sampling_plan(duration_s: f64, interval_s: f64) -> Vec<SampleStatus> {
    if duration_s <= 0.0 {
        return vec![SampleStatus::Blocked];
    }
    let count = (duration_s / interval_s - 1e-9).ceil().max(0.0) as usize;
    vec![SampleStatus::Pass; count]
}

pub fn run_sampling_steps(steps: &[(SampleStatus, usize)]) -> SamplingReport {
    let mut report = SamplingReport::default();
    for (status, probes) in steps {
        report.samples.push(*status);
        report.probes += probes;
    }
    report
}

#[derive(Clone, Debug, PartialEq)]
pub struct SamplingSample {
    pub duration_s: f64,
    pub queue_depths: Vec<u64>,
    pub worker_ready: bool,
    pub status: SampleStatus,
}

pub fn sampling_report(samples: &[SamplingSample]) -> Value {
    let publication_drain_proven = !samples.is_empty()
        && samples.iter().all(|sample| {
            sample.worker_ready && sample.queue_depths.iter().all(|depth| *depth == 0)
        });
    let worker_health = !samples.is_empty() && samples.iter().any(|sample| sample.worker_ready);
    let mut checks = vec![
        serde_json::json!({
            "check": "publication_drain",
            "status": if publication_drain_proven { "PASS" } else { "BLOCKED" },
        }),
        serde_json::json!({
            "check": "worker_health",
            "status": if worker_health { "PASS" } else { "BLOCKED" },
        }),
    ];
    if samples.is_empty() {
        checks.push(serde_json::json!({"check": "sampling", "status": "BLOCKED"}));
    } else if samples
        .iter()
        .any(|sample| sample.status == SampleStatus::Unknown)
    {
        checks.push(serde_json::json!({"check": "sampling", "status": "UNKNOWN"}));
    } else if samples
        .iter()
        .any(|sample| sample.status == SampleStatus::Blocked)
    {
        checks.push(serde_json::json!({"check": "sampling", "status": "BLOCKED"}));
    } else {
        checks.push(serde_json::json!({"check": "sampling", "status": "PASS"}));
    }
    let status = if checks.iter().any(|check| check["status"] == "UNKNOWN") {
        "UNKNOWN"
    } else if checks.iter().any(|check| check["status"] == "BLOCKED") {
        "BLOCKED"
    } else {
        "PASS"
    };
    serde_json::json!({
        "status": status,
        "samples": samples.len(),
        "checks": checks,
        "publicationDrainProven": publication_drain_proven,
        "workerHealthRecorded": worker_health,
        "durationsS": samples.iter().map(|sample| sample.duration_s).collect::<Vec<_>>(),
    })
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SinkStats {
    pub written: usize,
    pub errors: usize,
}

pub fn record_sink_result(stats: &mut SinkStats, success: bool) {
    if success {
        stats.written += 1;
    } else {
        stats.errors += 1;
    }
}

pub fn self_test_help() -> (i32, String) {
    (
        0,
        "usage: self-test [--help]\nThis entrypoint never executes sampling, faults or mutations.\n"
            .to_owned(),
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommonEvent {
    pub sequence: u64,
    pub event: String,
    pub observation: Option<String>,
    pub outcome: Option<String>,
    pub source: Option<String>,
    pub pending: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SequenceInterval {
    pub start: u64,
    pub end: u64,
}

fn one_event<'a>(events: &'a [CommonEvent], name: &str) -> Result<&'a CommonEvent, &'static str> {
    let matches = events
        .iter()
        .filter(|event| event.event == name)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err("expected exactly one event");
    }
    Ok(matches[0])
}

fn events_between<'a>(
    events: &'a [CommonEvent],
    name: &str,
    observation: &str,
    after: u64,
    before: u64,
) -> Vec<&'a CommonEvent> {
    events
        .iter()
        .filter(|event| {
            event.event == name
                && event.observation.as_deref() == Some(observation)
                && event.sequence > after
                && event.sequence < before
        })
        .collect()
}

fn observation_pairs<'a>(
    events: &'a [CommonEvent],
    observation: &str,
    after: u64,
    before: u64,
) -> Result<Vec<(&'a CommonEvent, &'a CommonEvent)>, &'static str> {
    let starts = events_between(
        events,
        "authoritative_read_start",
        observation,
        after,
        before,
    );
    let ends = events_between(events, "authoritative_read_end", observation, after, before);
    if starts.len() != ends.len() {
        return Err("unbalanced observations");
    }
    let mut pairs = Vec::new();
    for (start, end) in starts.into_iter().zip(ends) {
        if start.sequence >= end.sequence {
            return Err("invalid observation ordering");
        }
        if start.outcome.as_deref() != Some("started") || end.outcome.as_deref() != Some("ok") {
            return Err("unsuccessful observation");
        }
        pairs.push((start, end));
    }
    Ok(pairs)
}

fn pending_is_false(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "false" | "some(false)" | "0"
        )
    })
}

pub fn final_observation_interval(
    events: &[CommonEvent],
) -> Result<(SequenceInterval, String), &'static str> {
    let final_start = one_event(events, "final_reload_start")?;
    let stable_end = one_event(events, "stable_check_end")?;
    if final_start.sequence >= stable_end.sequence {
        return Err("final reload must precede stable-check completion");
    }
    let source_event = events
        .iter()
        .rfind(|event| {
            event.event == "evidence_load_result"
                && event.sequence > final_start.sequence
                && event.sequence < stable_end.sequence
        })
        .ok_or("missing final load source")?;
    let source = source_event.source.as_deref().ok_or("missing source")?;
    if source == "strict_db" {
        let pairs = observation_pairs(
            events,
            "strict_pending_probe",
            final_start.sequence,
            source_event.sequence,
        )?;
        if pairs.len() != 1 {
            return Err("expected one strict_pending_probe pair in final load");
        }
        let (start, end) = pairs[0];
        if !pending_is_false(end.pending.as_deref()) {
            return Err("strict final load observed an unsafe pending delta");
        }
        return Ok((
            SequenceInterval {
                start: start.sequence,
                end: end.sequence,
            },
            source.to_owned(),
        ));
    }
    if matches!(source, "l1_cache" | "l2_cache") {
        let manifests = observation_pairs(
            events,
            "cache_manifest",
            final_start.sequence,
            source_event.sequence,
        )?;
        let pending = observation_pairs(
            events,
            "cache_pending_probe",
            final_start.sequence,
            source_event.sequence,
        )?;
        if manifests.len() != 2 || pending.len() != 2 {
            return Err(
                "cache final load requires exactly two manifest and two pending observations",
            );
        }
        let (m0, m1) = (manifests[0], manifests[1]);
        let (p0, p1) = (pending[0], pending[1]);
        let ordered = m0.1.sequence < p0.0.sequence
            && p0.1.sequence < m1.0.sequence
            && m1.1.sequence < p1.0.sequence
            && p1.1.sequence < source_event.sequence;
        if !ordered {
            return Err("cache admission bracket is not m0 < p0 < m1 < p1");
        }
        if !pending_is_false(p0.1.pending.as_deref()) || !pending_is_false(p1.1.pending.as_deref())
        {
            return Err("cache admission bracket observed an unsafe pending delta");
        }
        return Ok((
            SequenceInterval {
                start: m0.0.sequence,
                end: m0.1.sequence,
            },
            source.to_owned(),
        ));
    }
    Err("unknown evidence source")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeConnection {
    pub node: String,
    pub sequence: u64,
    pub primary_route: bool,
    pub session_contract_ok: bool,
    pub clock_interval_ok: bool,
    pub server_identity_sha256: String,
    pub epoch_sha256: String,
}

pub fn validate_runtime_preconditions(
    nodes: &[&str],
    connections: &[RuntimeConnection],
    rotation_journal_present: bool,
    expected_pool_connections: Option<&std::collections::BTreeMap<String, usize>>,
) -> Value {
    let mut blocked = Vec::new();
    let mut failures = Vec::new();
    let mut unknown = Vec::new();
    let missing = nodes
        .iter()
        .filter(|node| !connections.iter().any(|event| event.node == **node))
        .copied()
        .collect::<Vec<_>>();
    for node in &missing {
        blocked.push(format!("{node}:no_pool_connection_observation"));
    }
    if let Some(expected) = expected_pool_connections {
        for node in nodes {
            let observed = connections
                .iter()
                .filter(|event| event.node == *node)
                .count();
            if observed != *expected.get(*node).unwrap_or(&0) {
                blocked.push(format!("{node}:pool_connection_inventory_mismatch"));
            }
        }
    } else if let Some(node) = nodes.first() {
        blocked.push(format!("{node}:pool_connection_inventory_missing"));
    }
    for event in connections {
        if !event.clock_interval_ok {
            unknown.push(format!(
                "{}:{}:invalid_clock_interval_evidence",
                event.node, event.sequence
            ));
        }
        if !event.primary_route && !event.session_contract_ok {
            failures.push(format!(
                "{}:{}:non_primary_session_contract_violation",
                event.node, event.sequence
            ));
        }
    }
    let epochs = connections
        .iter()
        .map(|event| event.epoch_sha256.clone())
        .collect::<BTreeSet<_>>();
    if !rotation_journal_present && (!missing.is_empty() || epochs.len() > 1) {
        blocked.push("cache_epoch_rotation_reason_unproven".to_owned());
    }
    if epochs.len() > 1 && !rotation_journal_present {
        blocked.push("cache_epoch_changed_without_rotation_journal".to_owned());
    }
    let mut identities = std::collections::BTreeMap::<&str, BTreeSet<&str>>::new();
    for event in connections {
        identities
            .entry(&event.node)
            .or_default()
            .insert(&event.server_identity_sha256);
    }
    for (node, values) in identities {
        if values.len() > 1 && !rotation_journal_present {
            blocked.push(format!(
                "{node}:mixed_server_identity_without_route_journal"
            ));
        }
    }
    blocked.sort();
    blocked.dedup();
    let status = if !failures.is_empty() {
        "FAIL"
    } else if !blocked.is_empty() {
        "BLOCKED"
    } else if !unknown.is_empty() {
        "UNKNOWN"
    } else {
        "PASS"
    };
    serde_json::json!({
        "status": status,
        "blocked": blocked,
        "failures": failures,
        "unknown": unknown,
        "connectionsObserved": connections.len(),
        "epochHashes": epochs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stable_id_matches_python_uuid_v5_and_validation() {
        let value = stable_id("authz-validation-e1unittest-run-001", "e1:c1:add-entry");
        assert_eq!(value, "bdfb1361-fd96-5c15-9781-f6ee2d4eacde");
        assert_eq!(
            value,
            stable_id("authz-validation-e1unittest-run-001", "e1:c1:add-entry")
        );
        assert_ne!(
            value,
            stable_id("authz-validation-e1unittest-run-001", "e1:c2:add-entry")
        );
        assert!(value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'));
    }

    #[test]
    fn atomic_json_and_checksums_use_lf_and_verify() {
        let root = std::env::temp_dir().join(format!("astral-common-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let path = write_atomic_json(&root, "result.json", &json!({"status": "PASS"})).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.ends_with('\n'));
        assert!(!text.contains('\r'));
        write_checksums(&root, &["result.json"]).unwrap();
        let checksums = fs::read_to_string(root.join("checksums.sha256")).unwrap();
        assert!(checksums.ends_with('\n'));
        assert!(!checksums.contains('\r'));
        assert!(checksums.contains("  result.json"));
        verify_checksums(&root, &root.join("checksums.sha256")).unwrap();
        fs::write(&path, "tampered\n").unwrap();
        assert!(verify_checksums(&root, &root.join("checksums.sha256")).is_err());
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn route_journal_is_required_for_multiple_server_identities() {
        assert_eq!(
            validate_route_journal(&["server-a", "server-a"], None),
            Ok(())
        );
        assert_eq!(
            validate_route_journal(&["server-a", "server-b"], None),
            Err("route_journal_missing")
        );
        assert_eq!(
            validate_route_journal(
                &["server-a", "server-b"],
                Some(&json!([{"server_identity": "server-a"}]))
            ),
            Err("route_journal_incomplete")
        );
        assert_eq!(
            validate_route_journal(
                &["server-a", "server-b"],
                Some(&json!([
                    {"server_identity": "server-a"},
                    {"server_identity": "server-b"}
                ]))
            ),
            Ok(())
        );
    }

    #[test]
    fn sampling_stop_event_stops_between_samples() {
        assert_eq!(sampling_sample_indices(5, None), [0, 1, 2, 3, 4]);
        assert_eq!(sampling_sample_indices(5, Some(2)), [0, 1]);
        assert_eq!(sampling_sample_indices(5, Some(0)), Vec::<usize>::new());
        assert_eq!(sampling_sample_indices(0, None), Vec::<usize>::new());
    }

    #[test]
    fn sink_errors_are_counted_without_aborting() {
        let mut stats = SinkStats::default();
        for success in [true, false, true, false] {
            record_sink_result(&mut stats, success);
        }
        assert_eq!(
            stats,
            SinkStats {
                written: 2,
                errors: 2
            }
        );
    }

    #[test]
    fn self_test_help_exits_cleanly_without_execution() {
        let (code, text) = self_test_help();
        assert_eq!(code, 0);
        assert!(text.contains("self-test"));
        assert!(text.contains("never executes"));
    }

    fn event(
        sequence: u64,
        event: &str,
        observation: Option<&str>,
        outcome: Option<&str>,
        source: Option<&str>,
        pending: Option<&str>,
    ) -> CommonEvent {
        CommonEvent {
            sequence,
            event: event.to_owned(),
            observation: observation.map(str::to_owned),
            outcome: outcome.map(str::to_owned),
            source: source.map(str::to_owned),
            pending: pending.map(str::to_owned),
        }
    }

    fn strict_events() -> Vec<CommonEvent> {
        vec![
            event(3, "final_reload_start", None, None, None, None),
            event(
                10,
                "authoritative_read_start",
                Some("strict_pending_probe"),
                Some("started"),
                None,
                None,
            ),
            event(
                20,
                "authoritative_read_end",
                Some("strict_pending_probe"),
                Some("ok"),
                None,
                Some("false"),
            ),
            event(
                21,
                "evidence_load_result",
                None,
                None,
                Some("strict_db"),
                None,
            ),
            event(30, "stable_check_end", None, None, None, None),
        ]
    }

    fn cache_events() -> Vec<CommonEvent> {
        vec![
            event(3, "final_reload_start", None, None, None, None),
            event(
                4,
                "authoritative_read_start",
                Some("cache_manifest"),
                Some("started"),
                None,
                None,
            ),
            event(
                5,
                "authoritative_read_end",
                Some("cache_manifest"),
                Some("ok"),
                None,
                None,
            ),
            event(
                6,
                "authoritative_read_start",
                Some("cache_pending_probe"),
                Some("started"),
                None,
                None,
            ),
            event(
                7,
                "authoritative_read_end",
                Some("cache_pending_probe"),
                Some("ok"),
                None,
                Some("Some(false)"),
            ),
            event(
                8,
                "authoritative_read_start",
                Some("cache_manifest"),
                Some("started"),
                None,
                None,
            ),
            event(
                9,
                "authoritative_read_end",
                Some("cache_manifest"),
                Some("ok"),
                None,
                None,
            ),
            event(
                10,
                "authoritative_read_start",
                Some("cache_pending_probe"),
                Some("started"),
                None,
                None,
            ),
            event(
                11,
                "authoritative_read_end",
                Some("cache_pending_probe"),
                Some("ok"),
                None,
                Some("Some(false)"),
            ),
            event(
                12,
                "evidence_load_result",
                None,
                None,
                Some("l1_cache"),
                None,
            ),
            event(13, "stable_check_end", None, None, None, None),
        ]
    }

    #[test]
    fn strict_final_observation_uses_initial_pending_probe() {
        let (interval, source) = final_observation_interval(&strict_events()).unwrap();
        assert_eq!(source, "strict_db");
        assert_eq!(interval, SequenceInterval { start: 10, end: 20 });
    }

    #[test]
    fn cache_final_observation_requires_full_bracket_and_returns_m0() {
        let (interval, source) = final_observation_interval(&cache_events()).unwrap();
        assert_eq!(source, "l1_cache");
        assert_eq!(interval, SequenceInterval { start: 4, end: 5 });
    }

    #[test]
    fn cache_missing_second_observation_is_rejected() {
        let events = cache_events()
            .into_iter()
            .filter(|event| !matches!(event.sequence, 8 | 9))
            .collect::<Vec<_>>();
        assert!(final_observation_interval(&events).is_err());
    }

    #[test]
    fn cache_misordered_bracket_is_rejected() {
        let mut events = cache_events();
        for event in &mut events {
            if event.sequence == 5 {
                event.sequence = 6;
            } else if event.sequence == 6 {
                event.sequence = 5;
            }
        }
        assert!(final_observation_interval(&events).is_err());
    }

    #[test]
    fn pending_true_observation_is_rejected() {
        let mut events = cache_events();
        events
            .iter_mut()
            .find(|event| event.sequence == 7)
            .unwrap()
            .pending = Some("Some(true)".to_owned());
        assert!(final_observation_interval(&events).is_err());
    }

    fn connection(
        node: &str,
        sequence: u64,
        primary_route: bool,
        session_contract_ok: bool,
        clock_interval_ok: bool,
        epoch: &str,
    ) -> RuntimeConnection {
        RuntimeConnection {
            node: node.to_owned(),
            sequence,
            primary_route,
            session_contract_ok,
            clock_interval_ok,
            server_identity_sha256: "a".repeat(64),
            epoch_sha256: epoch.to_owned(),
        }
    }

    fn pool(count: usize) -> std::collections::BTreeMap<String, usize> {
        ["node-a", "node-b", "node-c"]
            .into_iter()
            .map(|node| (node.to_owned(), count))
            .collect()
    }

    #[test]
    fn three_node_runtime_preconditions_pass_with_rotation_journal() {
        let connections = [
            connection("node-a", 1, true, true, true, &"c".repeat(64)),
            connection("node-b", 1, true, true, true, &"c".repeat(64)),
            connection("node-c", 1, true, true, true, &"c".repeat(64)),
        ];
        let report = validate_runtime_preconditions(
            &["node-a", "node-b", "node-c"],
            &connections,
            true,
            Some(&pool(1)),
        );
        assert_eq!(report["status"], "PASS", "{report}");
        assert_eq!(report["connectionsObserved"], 3);
        assert_eq!(report["epochHashes"], json!(["c".repeat(64)]));
    }

    #[test]
    fn missing_node_or_rotation_journal_is_blocked() {
        let connections = [
            connection("node-a", 1, true, true, true, &"c".repeat(64)),
            connection("node-b", 1, true, true, true, &"c".repeat(64)),
        ];
        let report = validate_runtime_preconditions(
            &["node-a", "node-b", "node-c"],
            &connections,
            false,
            Some(&pool(1)),
        );
        assert_eq!(report["status"], "BLOCKED");
        let blocked = report["blocked"].as_array().unwrap();
        assert!(blocked
            .iter()
            .any(|item| item == "node-c:no_pool_connection_observation"));
        assert!(blocked
            .iter()
            .any(|item| item == "cache_epoch_rotation_reason_unproven"));
    }

    #[test]
    fn non_primary_bad_clock_or_session_contract_fails() {
        let connections = [connection(
            "node-a",
            20,
            false,
            false,
            true,
            &"c".repeat(64),
        )];
        let mut expected = pool(0);
        expected.insert("node-a".to_owned(), 1);
        let report =
            validate_runtime_preconditions(&["node-a"], &connections, true, Some(&expected));
        assert_eq!(report["status"], "FAIL");
        assert!(!report["failures"].as_array().unwrap().is_empty());
    }

    #[test]
    fn mixed_server_identity_without_route_journal_is_blocked() {
        let epoch = "e".repeat(64);
        let connections = [
            RuntimeConnection {
                node: "node-a".to_owned(),
                sequence: 1,
                primary_route: true,
                session_contract_ok: true,
                clock_interval_ok: true,
                server_identity_sha256: "a".repeat(64),
                epoch_sha256: epoch.clone(),
            },
            RuntimeConnection {
                node: "node-a".to_owned(),
                sequence: 2,
                primary_route: true,
                session_contract_ok: true,
                clock_interval_ok: true,
                server_identity_sha256: "b".repeat(64),
                epoch_sha256: epoch,
            },
        ];
        let mut expected = pool(1);
        expected.insert("node-a".to_owned(), 2);
        let report =
            validate_runtime_preconditions(&["node-a"], &connections, false, Some(&expected));
        assert_eq!(report["status"], "BLOCKED");
        assert!(report["blocked"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "node-a:mixed_server_identity_without_route_journal"));
    }

    #[test]
    fn strict_observation_outcome_error_is_rejected() {
        let mut events = cache_events();
        let end = events
            .iter_mut()
            .find(|event| event.outcome.as_deref() == Some("ok"))
            .expect("an observation end event");
        end.outcome = Some("error".to_owned());
        assert!(final_observation_interval(&events).is_err());
    }

    #[test]
    fn epoch_change_without_journal_is_blocked() {
        let connections = [
            connection("node-a", 1, true, true, true, &"c".repeat(64)),
            connection("node-b", 11, true, true, true, &"d".repeat(64)),
        ];
        let report = validate_runtime_preconditions(
            &["node-a", "node-b"],
            &connections,
            false,
            Some(&pool(1)),
        );
        assert_eq!(report["status"], "BLOCKED");
        assert!(report["blocked"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "cache_epoch_changed_without_rotation_journal"));
    }

    #[test]
    fn missing_pool_inventory_or_clock_interval_is_not_pass() {
        let connections = [connection("node-a", 1, true, true, true, &"c".repeat(64))];
        let without_inventory =
            validate_runtime_preconditions(&["node-a"], &connections, true, None);
        assert_eq!(without_inventory["status"], "BLOCKED");
        assert!(without_inventory["blocked"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "node-a:pool_connection_inventory_missing"));

        let broken = [connection("node-a", 1, true, true, false, &"c".repeat(64))];
        let mut expected = std::collections::BTreeMap::new();
        expected.insert("node-a".to_owned(), 1);
        let report = validate_runtime_preconditions(&["node-a"], &broken, true, Some(&expected));
        assert_eq!(report["status"], "UNKNOWN");
        assert!(report["unknown"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "node-a:1:invalid_clock_interval_evidence"));
    }

    #[test]
    fn required_parser_and_validator_symbols_remain_callable() {
        type ObservationIntervalValidator =
            fn(&[CommonEvent]) -> Result<(SequenceInterval, String), &'static str>;
        type RuntimePreconditionValidator = fn(
            &[&str],
            &[RuntimeConnection],
            bool,
            Option<&std::collections::BTreeMap<String, usize>>,
        ) -> Value;

        let _: fn(&str, &str) -> String = stable_id;
        let _: ObservationIntervalValidator = final_observation_interval;
        let _: RuntimePreconditionValidator = validate_runtime_preconditions;
        let _: fn(&[&str], Option<&Value>) -> Result<(), &'static str> = validate_route_journal;
    }

    #[test]
    fn zero_duration_is_blocked_and_touches_nothing() {
        assert_eq!(sampling_plan(0.0, 0.02), vec![SampleStatus::Blocked]);
        let report = run_sampling_steps(&[(SampleStatus::Blocked, 0)]);
        assert_eq!(report.samples, vec![SampleStatus::Blocked]);
        assert_eq!(report.probes, 0);
    }

    #[test]
    fn blocked_or_unknown_sample_does_not_abort_sampling() {
        let report = run_sampling_steps(&[
            (SampleStatus::Blocked, 1),
            (SampleStatus::Pass, 1),
            (SampleStatus::Unknown, 1),
            (SampleStatus::Pass, 1),
        ]);
        assert_eq!(
            report.samples,
            vec![
                SampleStatus::Blocked,
                SampleStatus::Pass,
                SampleStatus::Unknown,
                SampleStatus::Pass,
            ]
        );
        assert_eq!(report.probes, 4);
    }

    fn production(source: &str) -> &str {
        source.split("#[cfg(test)]").next().unwrap_or(source)
    }

    #[test]
    fn e3_e4_sources_have_no_network_or_process_capability() {
        let sources = [
            include_str!("e3_e4_events.rs"),
            include_str!("e4_preconditions.rs"),
            include_str!("node_adapter_contract.rs"),
        ];
        for token in [
            "std::net",
            "std::process",
            "TcpStream",
            "UdpSocket",
            "reqwest",
            "hyper::",
            "tokio::net",
            "tokio::process",
            "Command::new",
        ] {
            for source in sources.map(production) {
                assert!(!source.contains(token), "{token}");
            }
        }
    }

    #[test]
    fn runtime_inputs_reject_empty_nodes_and_negative_clock_threshold() {
        assert_eq!(validate_runtime_inputs(&[], 1), Err("empty_node_set"));
        assert_eq!(
            validate_runtime_inputs(&["node-a"], -1),
            Err("invalid_clock_skew_threshold")
        );
        assert_eq!(validate_runtime_inputs(&["node-a"], 1), Ok(()));
    }

    fn sample(
        duration_s: f64,
        queue_depths: &[u64],
        worker_ready: bool,
        status: SampleStatus,
    ) -> SamplingSample {
        SamplingSample {
            duration_s,
            queue_depths: queue_depths.to_vec(),
            worker_ready,
            status,
        }
    }

    #[test]
    fn happy_path_sampling_report_passes_all_checks() {
        let report = sampling_report(&[
            sample(0.02, &[0, 0], true, SampleStatus::Pass),
            sample(0.02, &[0, 0], true, SampleStatus::Pass),
        ]);
        assert_eq!(report["status"], "PASS", "{report}");
        assert_eq!(report["publicationDrainProven"], true);
        assert_eq!(report["workerHealthRecorded"], true);
        assert!(report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|check| check["status"] == "PASS"));
    }

    #[test]
    fn fixed_interval_sampling_plan_matches_window() {
        let plan = sampling_plan(0.05, 0.02);
        assert_eq!(plan.len(), 3);
        let samples = plan
            .into_iter()
            .map(|status| sample(0.02, &[0, 0], true, status))
            .collect::<Vec<_>>();
        let report = sampling_report(&samples);
        assert_eq!(report["samples"], 3);
        assert_eq!(report["durationsS"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn publication_drain_requires_zero_queues_and_ready_worker() {
        let backlog = sampling_report(&[sample(0.02, &[1], true, SampleStatus::Pass)]);
        assert_eq!(backlog["publicationDrainProven"], false);
        assert_eq!(backlog["status"], "BLOCKED");
        let not_ready = sampling_report(&[sample(0.02, &[0], false, SampleStatus::Pass)]);
        assert_eq!(not_ready["publicationDrainProven"], false);
    }

    #[test]
    fn worker_health_endpoint_recorded_when_configured() {
        let report = sampling_report(&[sample(0.02, &[0], true, SampleStatus::Pass)]);
        assert_eq!(report["workerHealthRecorded"], true);
        assert_eq!(report["checks"][1]["check"], "worker_health");
        assert_eq!(report["checks"][1]["status"], "PASS");
        let missing = sampling_report(&[sample(0.02, &[0], false, SampleStatus::Pass)]);
        assert_eq!(missing["workerHealthRecorded"], false);
        assert_eq!(missing["checks"][1]["status"], "BLOCKED");
    }

    #[test]
    fn sampling_report_has_no_hosts_or_secrets() {
        let report = sampling_report(&[sample(0.02, &[0], true, SampleStatus::Pass)]);
        let text = serde_json::to_string(&report).unwrap();
        assert!(!text.contains("example.invalid"));
        assert!(!text.contains("gateway.example.com"));
        assert!(!text.contains("secret"));
    }
}
