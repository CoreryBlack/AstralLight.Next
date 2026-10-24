//! Native offline E1 runner contracts: settings, plan identity, read-only
//! preflight and the mechanical live-campaign gate.
//!
//! This module deliberately stops before campaign execution. It constructs no
//! adapter for planning, exposes only GET/SELECT through [`ReadOnlyGate`], and
//! validates caller-supplied live-gate artifacts without reading them from the
//! run configuration.

use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use uuid::Uuid;

pub const API_PREFIX: &str = "/main/api/v1/";
pub const STATS_PATH: &str = "/main/api/v1/stats";
pub const CHECK_PATH_TEMPLATE: &str = "/main/api/v1/permission-rules/check?cardId={card}&card_id={card}&resourceType={resource}&actionCode={action}";
pub const RULE_SET_PATH_TEMPLATE: &str = "/main/api/v1/rule-sets/{rule_set}";
pub const RULE_SET_ENTRIES_TEMPLATE: &str = "/main/api/v1/rule-sets/{rule_set}/entries";
pub const CARD_BINDINGS_TEMPLATE: &str = "/main/api/v1/rule-sets/card/{card}/bindings";

pub const OP_ORDER: [&str; 4] = ["addEntry", "bind", "deleteEntry", "unbind"];
pub const MAX_CYCLES: usize = 64;
pub const MAX_READERS: usize = 8;
pub const MAX_REQUESTS_PER_READER: usize = 200;
pub const MAX_RECONCILE_POLLS: usize = 120;
pub const APPROVAL_SCOPE: &str = "E1-LIVE-CAMPAIGN";
pub const APPROVAL_REF_PATTERN: &str = r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$";
pub const ISO_DATETIME_PATTERN: &str = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})?$";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum E1Error {
    Config(Vec<String>),
    Io(String),
    Evidence(String),
    ReadOnlyGate,
}

impl std::fmt::Display for E1Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(problems) => write!(formatter, "config: {}", problems.join(",")),
            Self::Io(error) => write!(formatter, "io: {error}"),
            Self::Evidence(error) => write!(formatter, "evidence: {error}"),
            Self::ReadOnlyGate => write!(formatter, "read_only_gate: mutations are not permitted"),
        }
    }
}

impl std::error::Error for E1Error {}

#[derive(Clone, Debug, PartialEq)]
pub struct E1Settings {
    pub run_id: String,
    pub card_id: i64,
    pub rule_set_id: i64,
    pub tenant_id: i64,
    pub resource_type: String,
    pub action_code: String,
    pub ref_type: String,
    pub cycles: usize,
    pub readers: usize,
    pub max_requests_per_reader: usize,
    pub node_rotation: Vec<String>,
    pub fixture_synthetic: bool,
    pub reconcile_polls: usize,
    pub reconcile_interval_s: f64,
}

impl E1Settings {
    pub fn public_metadata(&self) -> Value {
        json!({
            "runId": self.run_id,
            "cardId": self.card_id,
            "ruleSetId": self.rule_set_id,
            "tenantId": self.tenant_id,
            "resourceType": self.resource_type,
            "actionCode": self.action_code,
            "refType": self.ref_type,
            "cycles": self.cycles,
            "readers": self.readers,
            "maxRequestsPerReader": self.max_requests_per_reader,
            "nodeRotation": self.node_rotation,
            "fixtureSynthetic": self.fixture_synthetic,
            "reconcilePolls": self.reconcile_polls,
            "reconcileIntervalS": self.reconcile_interval_s,
        })
    }
}

fn safe_id(value: &str) -> bool {
    Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
        .expect("safe id regex")
        .is_match(value)
}

fn safe_name(value: &str) -> bool {
    Regex::new(r"^[a-z][a-z0-9_]{0,63}$")
        .expect("safe name regex")
        .is_match(value)
}

fn positive_i64(value: &Value) -> Option<i64> {
    value.as_i64().filter(|value| *value > 0)
}

fn bounded_usize(
    section: &Map<String, Value>,
    key: &str,
    low: usize,
    high: usize,
    problems: &mut Vec<String>,
) -> usize {
    let value = section
        .get(key)
        .and_then(Value::as_u64)
        .filter(|value| (low as u64..=high as u64).contains(value));
    match value {
        Some(value) => value as usize,
        None => {
            problems.push(format!("invalid:e1.{key}"));
            low
        }
    }
}

pub fn load_settings(config: &Value) -> Result<E1Settings, E1Error> {
    let run_id = config
        .get("run_id")
        .and_then(Value::as_str)
        .filter(|value| safe_id(value))
        .ok_or_else(|| E1Error::Config(vec!["invalid:run_id".to_owned()]))?;
    let e1 = config
        .get("e1")
        .and_then(Value::as_object)
        .ok_or_else(|| E1Error::Config(vec!["missing:e1".to_owned()]))?;
    let allowlist = e1
        .get("allowlist")
        .and_then(Value::as_object)
        .ok_or_else(|| E1Error::Config(vec!["missing:e1.allowlist".to_owned()]))?;
    let mut problems = Vec::new();
    let card_id = allowlist.get("card_id").and_then(positive_i64);
    let rule_set_id = allowlist.get("rule_set_id").and_then(positive_i64);
    if card_id.is_none() {
        problems.push("invalid:e1.allowlist.card_id".to_owned());
    }
    if rule_set_id.is_none() {
        problems.push("invalid:e1.allowlist.rule_set_id".to_owned());
    }
    let resource_type = allowlist
        .get("resource_type")
        .and_then(Value::as_str)
        .filter(|value| safe_name(value))
        .unwrap_or_default()
        .to_owned();
    if !safe_name(&resource_type) {
        problems.push("invalid:e1.allowlist.resource_type".to_owned());
    }
    let action_code = allowlist
        .get("action_code")
        .and_then(Value::as_str)
        .filter(|value| safe_name(value))
        .unwrap_or_default()
        .to_owned();
    if !safe_name(&action_code) {
        problems.push("invalid:e1.allowlist.action_code".to_owned());
    }
    let ref_type = allowlist
        .get("ref_type")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if ref_type != "BASE" {
        problems.push("invalid:e1.allowlist.ref_type".to_owned());
    }
    if !problems.is_empty() {
        problems.sort();
        problems.dedup();
        return Err(E1Error::Config(problems));
    }
    let card_id = card_id.expect("validated card id");
    let rule_set_id = rule_set_id.expect("validated rule set id");

    let actor = e1
        .get("admin_actor")
        .and_then(Value::as_object)
        .ok_or_else(|| E1Error::Config(vec!["missing:e1.admin_actor".to_owned()]))?;
    let card_text = card_id.to_string();
    if actor.get("card").and_then(Value::as_str) != Some(card_text.as_str()) {
        return Err(E1Error::Config(vec![
            "invalid:e1.admin_actor.card_must_equal_allowlist_card_id".to_owned(),
        ]));
    }
    let tenant_id = actor
        .get("tenant")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| E1Error::Config(vec!["invalid:e1.admin_actor.tenant".to_owned()]))?;

    let node_rotation = e1
        .get("node_rotation")
        .and_then(Value::as_array)
        .and_then(|nodes| {
            nodes
                .iter()
                .map(|node| node.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
        })
        .filter(|nodes| {
            !nodes.is_empty()
                && nodes
                    .iter()
                    .all(|node| ["node-a", "node-b", "node-c"].contains(&node.as_str()))
                && nodes.iter().collect::<BTreeSet<_>>().len() == nodes.len()
        })
        .ok_or_else(|| E1Error::Config(vec!["invalid:e1.node_rotation".to_owned()]))?;

    let fixture_synthetic = e1
        .get("fixture_synthetic")
        .and_then(Value::as_bool)
        .ok_or_else(|| E1Error::Config(vec!["invalid:e1.fixture_synthetic".to_owned()]))?;
    let cycles = bounded_usize(e1, "cycles", 1, MAX_CYCLES, &mut problems);
    let readers = bounded_usize(e1, "readers", 1, MAX_READERS, &mut problems);
    let max_requests_per_reader = bounded_usize(
        e1,
        "max_requests_per_reader",
        1,
        MAX_REQUESTS_PER_READER,
        &mut problems,
    );
    let reconcile_polls =
        bounded_usize(e1, "reconcile_polls", 1, MAX_RECONCILE_POLLS, &mut problems);
    let reconcile_interval_s = e1
        .get("reconcile_interval_s")
        .and_then(Value::as_f64)
        .filter(|value| (0.0..=10.0).contains(value))
        .unwrap_or_else(|| {
            problems.push("invalid:e1.reconcile_interval_s".to_owned());
            0.0
        });
    if !problems.is_empty() {
        problems.sort();
        problems.dedup();
        return Err(E1Error::Config(problems));
    }
    Ok(E1Settings {
        run_id: run_id.to_owned(),
        card_id,
        rule_set_id,
        tenant_id,
        resource_type,
        action_code,
        ref_type,
        cycles,
        readers,
        max_requests_per_reader,
        node_rotation,
        fixture_synthetic,
        reconcile_polls,
        reconcile_interval_s,
    })
}

/// Derives the stable operation/request id. Mirrors the archived
/// experiment_common.stable_id guard: both identifiers must satisfy SAFE_ID
/// before they enter the UUIDv5 namespace -- an unsafe id is a contract
/// violation and fails closed instead of silently minting a UUID.
pub fn stable_id(run_id: &str, label: &str) -> String {
    assert!(
        safe_id(run_id),
        "unsafe run id rejected by SAFE_ID: {run_id:?}"
    );
    assert!(
        safe_id(label),
        "unsafe label rejected by SAFE_ID: {label:?}"
    );
    Uuid::new_v5(
        &Uuid::NAMESPACE_URL,
        format!("{run_id}:authorization-validation:{label}").as_bytes(),
    )
    .to_string()
}

pub fn operation_ids_for_cycle(run_id: &str, cycle: usize) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "addEntry".to_owned(),
            stable_id(run_id, &format!("e1:c{cycle}:add-entry")),
        ),
        (
            "bind".to_owned(),
            stable_id(run_id, &format!("e1:c{cycle}:bind")),
        ),
        (
            "deleteEntry".to_owned(),
            stable_id(run_id, &format!("e1:c{cycle}:delete-entry")),
        ),
        (
            "unbind".to_owned(),
            stable_id(run_id, &format!("e1:c{cycle}:unbind")),
        ),
    ])
}

pub fn reader_request_id(run_id: &str, cycle: usize, reader: usize, sequence: usize) -> String {
    stable_id(run_id, &format!("e1:c{cycle}:r{reader}:n{sequence}"))
}

pub fn check_path(settings: &E1Settings) -> String {
    format!(
        "/main/api/v1/permission-rules/check?cardId={card}&card_id={card}&resourceType={resource}&actionCode={action}",
        card = settings.card_id,
        resource = settings.resource_type,
        action = settings.action_code
    )
}

pub fn execute_plan(config: &Value, out_dir: &Path) -> Result<Value, E1Error> {
    let settings = load_settings(config)?;
    let cycles = (1..=settings.cycles)
        .map(|cycle| {
            json!({
                "cycle": cycle,
                "node": settings.node_rotation[(cycle - 1) % settings.node_rotation.len()],
                "operationIds": operation_ids_for_cycle(&settings.run_id, cycle),
                "readerRequestLabelPattern": "e1:c{cycle}:r{reader}:n{seq}",
                "readerRequestBudget": settings.readers * settings.max_requests_per_reader,
            })
        })
        .collect::<Vec<_>>();
    let plan = json!({
        "campaignId": settings.run_id,
        "experiment": "E1",
        "mode": "plan",
        "status": "PLANNED",
        "settings": settings.public_metadata(),
        "configSha256": config_sha256(config),
        "operationOrder": OP_ORDER,
        "cycles": cycles,
        "bounds": {
            "maxCycles": MAX_CYCLES,
            "maxReaders": MAX_READERS,
            "maxRequestsPerReader": MAX_REQUESTS_PER_READER,
            "maxReconcilePolls": MAX_RECONCILE_POLLS,
        },
    });
    write_json(out_dir, "plan.json", &plan)?;
    write_checksums(out_dir, &["plan.json"])?;
    verify_checksums(out_dir, &out_dir.join("checksums.sha256"))?;
    Ok(plan)
}

pub fn config_sha256(config: &Value) -> String {
    let canonical = canonical_json(config);
    let digest = Sha256::digest(canonical.as_bytes());
    format!("{digest:x}")
}

fn canonical_json(value: &Value) -> String {
    let mut text = String::new();
    write_canonical(value, &mut text);
    text
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            out.push('{');
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by_key(|(key, _)| *key);
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).expect("string key"));
                out.push(':');
                write_canonical(value, out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&serde_json::to_string(other).expect("json scalar")),
    }
}

fn write_json(root: &Path, relative: &str, value: &Value) -> Result<(), E1Error> {
    fs::create_dir_all(root).map_err(|error| E1Error::Io(error.to_string()))?;
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| E1Error::Io(error.to_string()))?;
    fs::write(root.join(relative), bytes).map_err(|error| E1Error::Io(error.to_string()))
}

pub fn write_checksums(root: &Path, relative_files: &[&str]) -> Result<(), E1Error> {
    let mut lines = Vec::new();
    let mut files = relative_files.to_vec();
    files.sort_unstable();
    for relative in files {
        let bytes =
            fs::read(root.join(relative)).map_err(|error| E1Error::Io(error.to_string()))?;
        let digest = Sha256::digest(&bytes);
        lines.push(format!("{digest:x}  {relative}"));
    }
    let text = format!("{}\n", lines.join("\n"));
    fs::write(root.join("checksums.sha256"), text).map_err(|error| E1Error::Io(error.to_string()))
}

pub fn verify_checksums(root: &Path, checksum_file: &Path) -> Result<(), E1Error> {
    let text = fs::read_to_string(checksum_file).map_err(|error| E1Error::Io(error.to_string()))?;
    let digest_pattern = Regex::new(r"^[0-9a-f]{64}$").expect("digest regex");
    for line in text.lines() {
        let Some((expected, relative)) = line.split_once("  ") else {
            return Err(E1Error::Evidence(format!(
                "malformed checksum line: {line}"
            )));
        };
        if !digest_pattern.is_match(expected) || relative.is_empty() {
            return Err(E1Error::Evidence(format!(
                "malformed checksum line: {line}"
            )));
        }
        if Path::new(relative).is_absolute() || relative.contains("..") {
            return Err(E1Error::Evidence(format!(
                "checksum path escapes artifact root: {relative}"
            )));
        }
        let bytes =
            fs::read(root.join(relative)).map_err(|error| E1Error::Io(error.to_string()))?;
        let actual = format!("{:x}", Sha256::digest(&bytes));
        if actual != expected {
            return Err(E1Error::Evidence(format!(
                "checksum mismatch for {relative}"
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterCall {
    pub method: String,
    pub path: String,
    pub request_id: String,
    pub actor_card: String,
}

pub trait ReadOnlyAdapter {
    fn signed_get(
        &mut self,
        node: &str,
        path: &str,
        request_id: &str,
    ) -> Result<(u16, Value), String>;
    fn sql(&mut self, query: &str) -> Result<Vec<Vec<String>>, String>;
    fn read_log_lines(&mut self, node: &str, identifiers: &[String])
        -> Result<Vec<String>, String>;
    fn projection_baseline(
        &mut self,
        tenant_id: i64,
        aggregate: &str,
        aggregate_id: i64,
    ) -> Result<Value, String>;
}

pub struct ReadOnlyGate<A: ReadOnlyAdapter> {
    adapter: A,
}

impl<A: ReadOnlyAdapter> ReadOnlyGate<A> {
    pub fn new(adapter: A) -> Self {
        Self { adapter }
    }

    pub fn adapter(&self) -> &A {
        &self.adapter
    }

    pub fn signed_get(
        &mut self,
        node: &str,
        path: &str,
        request_id: &str,
    ) -> Result<(u16, Value), String> {
        self.adapter.signed_get(node, path, request_id)
    }

    pub fn sql(&mut self, query: &str) -> Result<Vec<Vec<String>>, String> {
        self.adapter.sql(query)
    }

    pub fn read_log_lines(
        &mut self,
        node: &str,
        identifiers: &[String],
    ) -> Result<Vec<String>, String> {
        self.adapter.read_log_lines(node, identifiers)
    }

    pub fn projection_baseline(
        &mut self,
        tenant_id: i64,
        aggregate: &str,
        aggregate_id: i64,
    ) -> Result<Value, String> {
        self.adapter
            .projection_baseline(tenant_id, aggregate, aggregate_id)
    }

    pub fn signed_request(
        &mut self,
        _node: &str,
        _method: &str,
        _path: &str,
        _body: Value,
    ) -> Result<(), E1Error> {
        Err(E1Error::ReadOnlyGate)
    }
}

fn check_entry(name: &str, passed: bool, detail: Value) -> Value {
    json!({
        "check": name,
        "status": if passed { "PASS" } else { "BLOCKED" },
        "detail": detail,
    })
}

fn checked_get<A: ReadOnlyAdapter>(
    gate: &mut ReadOnlyGate<A>,
    node: &str,
    path: &str,
    request_id: &str,
) -> (bool, Option<u16>, Value, Vec<String>) {
    match gate.signed_get(node, path, request_id) {
        Ok((status, body)) => {
            let data = body.get("data").cloned().unwrap_or(Value::Null);
            let problems = body
                .get("message")
                .and_then(Value::as_str)
                .filter(|_| status != 200)
                .map(|message| vec![message.to_owned()])
                .unwrap_or_default();
            (status == 200, Some(status), data, problems)
        }
        Err(error) => (false, None, Value::Null, vec![error]),
    }
}

pub fn run_preflight_checks<A: ReadOnlyAdapter>(
    gate: &mut ReadOnlyGate<A>,
    settings: &E1Settings,
    node: &str,
) -> Value {
    let mut checks = Vec::new();
    let check_request_id = stable_id(&settings.run_id, "e1:preflight:check");
    let anchor_request_id = stable_id(&settings.run_id, "e1:preflight:anchor");
    let entries_request_id = stable_id(&settings.run_id, "e1:preflight:entries");
    let bindings_request_id = stable_id(&settings.run_id, "e1:preflight:bindings");
    let stats_request_id = stable_id(&settings.run_id, "e1:preflight:stats");

    checks.push(check_entry(
        "fixture_synthetic_attestation",
        settings.fixture_synthetic,
        if settings.fixture_synthetic {
            Value::Null
        } else {
            json!({"reason": "config must attest the fixture is an isolated synthetic"})
        },
    ));

    let anchor_path =
        RULE_SET_PATH_TEMPLATE.replace("{rule_set}", &settings.rule_set_id.to_string());
    let (anchor_ok, anchor_status, anchor_data, anchor_problems) =
        checked_get(gate, node, &anchor_path, &anchor_request_id);
    checks.push(check_entry(
        "rule_set_anchor",
        anchor_ok && anchor_data.get("id").and_then(Value::as_i64) == Some(settings.rule_set_id),
        json!({
            "httpStatus": anchor_status,
            "ruleSetId": settings.rule_set_id,
            "problems": anchor_problems,
        }),
    ));

    let count_query = format!(
        "SELECT COUNT(*) FROM rule_set WHERE rule_set_id={} AND tenant_id={} AND enabled=1",
        settings.rule_set_id, settings.tenant_id
    );
    let active_tenant_rule_set = gate
        .sql(&count_query)
        .ok()
        .and_then(|rows| rows.first().and_then(|row| row.first().cloned()))
        .and_then(|value| value.trim().parse::<usize>().ok());
    checks.push(check_entry(
        "rule_set_owned_by_active_tenant",
        active_tenant_rule_set == Some(1),
        json!({
            "tenantId": settings.tenant_id,
            "ruleSetId": settings.rule_set_id,
            "matchingRuleSetCount": active_tenant_rule_set,
        }),
    ));

    let entries_path =
        RULE_SET_ENTRIES_TEMPLATE.replace("{rule_set}", &settings.rule_set_id.to_string());
    let (entries_ok, entries_status, entries_data, entries_problems) =
        checked_get(gate, node, &entries_path, &entries_request_id);
    let entries = entries_data.as_array();
    checks.push(check_entry(
        "rule_set_entries_empty",
        entries_ok && entries.is_some_and(Vec::is_empty),
        json!({
            "httpStatus": entries_status,
            "entryCount": entries.map(Vec::len),
            "problems": entries_problems,
        }),
    ));

    let bindings_path = CARD_BINDINGS_TEMPLATE.replace("{card}", &settings.card_id.to_string());
    let (bindings_ok, bindings_status, bindings_data, bindings_problems) =
        checked_get(gate, node, &bindings_path, &bindings_request_id);
    let bindings = bindings_data.as_array();
    let already_bound = bindings.is_some_and(|rows| {
        rows.iter()
            .any(|row| row.get("ruleSetId").and_then(Value::as_i64) == Some(settings.rule_set_id))
    });
    checks.push(check_entry(
        "admin_active_and_card_context",
        bindings_ok,
        json!({"httpStatus": bindings_status, "problems": bindings_problems}),
    ));
    checks.push(check_entry(
        "card_not_bound_to_rule_set",
        bindings_ok && !already_bound,
        json!({"bound": already_bound}),
    ));

    let all_bindings_query = format!(
        "SELECT card_id FROM card_rule_set_ref WHERE rule_set_id={} ORDER BY card_id",
        settings.rule_set_id
    );
    let (all_bindings_ok, all_bindings_problem) = match gate.sql(&all_bindings_query) {
        Ok(rows) => (rows.is_empty(), None),
        Err(error) => (false, Some(error)),
    };
    checks.push(check_entry(
        "rule_set_not_bound_to_any_card",
        all_bindings_ok,
        json!({
            "boundCardCount": if all_bindings_problem.is_none() { Some(0) } else { None },
            "errorClass": all_bindings_problem,
        }),
    ));

    let (check_ok, check_status, check_data, check_problems) =
        checked_get(gate, node, &check_path(settings), &check_request_id);
    let effect = check_data.get("effect").and_then(Value::as_str);
    checks.push(check_entry(
        "pre_grant_deny_check_endpoint",
        check_ok && matches!(effect, Some("DENY" | "NO_MATCH")),
        json!({
            "httpStatus": check_status,
            "effect": effect,
            "problems": check_problems,
        }),
    ));

    match gate.signed_get(node, STATS_PATH, &stats_request_id) {
        Ok((status, _body)) => checks.push(check_entry(
            "pre_grant_deny_stats",
            status != 200,
            json!({"httpStatus": status}),
        )),
        Err(error) => checks.push(check_entry(
            "pre_grant_deny_stats",
            false,
            json!({"transportError": error}),
        )),
    }

    match gate.read_log_lines(node, &[stats_request_id]) {
        Ok(lines) => {
            let has_bound = lines.iter().any(|line| {
                serde_json::from_str::<Value>(line)
                    .ok()
                    .and_then(|event| {
                        event
                            .get("event")
                            .and_then(Value::as_str)
                            .map(|event| event == "signed_context_bound")
                    })
                    .unwrap_or(false)
            });
            checks.push(check_entry(
                "e1_observability_smoke",
                !lines.is_empty() && has_bound,
                json!({"events": lines.len()}),
            ));
        }
        Err(error) => checks.push(check_entry(
            "e1_observability_smoke",
            false,
            json!({"reason": "log_slice_or_parse_failed", "errorClass": error}),
        )),
    }

    let baseline = gate
        .projection_baseline(settings.tenant_id, "RULE_SET", settings.rule_set_id)
        .unwrap_or_else(|error| json!({"state": "unknown", "error": error}));
    let sql_ok = baseline.get("state").and_then(Value::as_str) != Some("unknown");
    checks.push(check_entry(
        "durable_reconciliation_surface",
        sql_ok,
        json!({"baseline": baseline}),
    ));

    let problems = checks
        .iter()
        .filter(|check| check["status"] != "PASS")
        .filter_map(|check| check["check"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    json!({
        "node": node,
        "status": if problems.is_empty() { "PASS" } else { "BLOCKED" },
        "checks": checks,
        "problems": problems,
    })
}

#[derive(Clone, Debug)]
pub struct LiveGateInput<'a> {
    pub live: bool,
    pub approval_ref: Option<&'a str>,
    pub approval_record: Option<&'a Value>,
    pub confirm_exec_l3: bool,
    pub independent_validator: bool,
}

pub fn check_live_gate(settings: &E1Settings, input: &LiveGateInput<'_>) -> Option<String> {
    if !input.live {
        return Some("live_not_enabled".to_owned());
    }
    if !input.confirm_exec_l3 {
        return Some("exec_l3_human_confirmation_missing".to_owned());
    }
    let approval_ref_pattern = Regex::new(APPROVAL_REF_PATTERN).expect("approval ref regex");
    let Some(approval_ref) = input
        .approval_ref
        .filter(|value| approval_ref_pattern.is_match(value))
    else {
        return Some("approval_ref_missing_or_unsafe".to_owned());
    };
    let Some(record) = input.approval_record else {
        return Some("approval_record_missing".to_owned());
    };
    if !record.is_object() {
        return Some("approval_record_not_a_mapping".to_owned());
    }
    if record.get("run_id").and_then(Value::as_str) != Some(settings.run_id.as_str()) {
        return Some("approval_record_run_id_mismatch".to_owned());
    }
    if record.get("approval_ref").and_then(Value::as_str) != Some(approval_ref) {
        return Some("approval_record_ref_mismatch".to_owned());
    }
    if record.get("approval_scope").and_then(Value::as_str) != Some(APPROVAL_SCOPE) {
        return Some("approval_record_scope_mismatch".to_owned());
    }
    if record
        .get("approved_by")
        .and_then(Value::as_str)
        .is_none_or(|value| value.trim().is_empty())
    {
        return Some("approval_record_approver_missing".to_owned());
    }
    let datetime_pattern = Regex::new(ISO_DATETIME_PATTERN).expect("datetime regex");
    if record
        .get("approved_at")
        .and_then(Value::as_str)
        .is_none_or(|value| !datetime_pattern.is_match(value))
    {
        return Some("approval_record_timestamp_missing".to_owned());
    }
    if !input.independent_validator {
        return Some("independent_user_approval_not_verified".to_owned());
    }
    None
}

pub trait CampaignAdapter: ReadOnlyAdapter {
    fn signed_request(
        &mut self,
        node: &str,
        method: &str,
        path: &str,
        body: Value,
        request_id: &str,
    ) -> Result<(u16, Value), String>;
}

impl<T: ReadOnlyAdapter + ?Sized> ReadOnlyAdapter for &mut T {
    fn signed_get(
        &mut self,
        node: &str,
        path: &str,
        request_id: &str,
    ) -> Result<(u16, Value), String> {
        (**self).signed_get(node, path, request_id)
    }

    fn sql(&mut self, query: &str) -> Result<Vec<Vec<String>>, String> {
        (**self).sql(query)
    }

    fn read_log_lines(
        &mut self,
        node: &str,
        identifiers: &[String],
    ) -> Result<Vec<String>, String> {
        (**self).read_log_lines(node, identifiers)
    }

    fn projection_baseline(
        &mut self,
        tenant_id: i64,
        aggregate: &str,
        aggregate_id: i64,
    ) -> Result<Value, String> {
        (**self).projection_baseline(tenant_id, aggregate, aggregate_id)
    }
}

fn entries_path(settings: &E1Settings) -> String {
    RULE_SET_ENTRIES_TEMPLATE.replace("{rule_set}", &settings.rule_set_id.to_string())
}

fn bindings_path(settings: &E1Settings) -> String {
    CARD_BINDINGS_TEMPLATE.replace("{card}", &settings.card_id.to_string())
}

fn entry_path(settings: &E1Settings, entry_id: i64) -> String {
    format!("{}/{entry_id}", entries_path(settings))
}

fn bind_path(settings: &E1Settings) -> String {
    format!("/main/api/v1/rule-sets/card/{}/bind", settings.card_id)
}

fn unbind_path(settings: &E1Settings) -> String {
    format!(
        "/main/api/v1/rule-sets/card/{}/unbind/{}",
        settings.card_id, settings.rule_set_id
    )
}

fn checked_bindings(
    adapter: &mut impl ReadOnlyAdapter,
    settings: &E1Settings,
    node: &str,
) -> Option<bool> {
    let request_id = stable_id(&settings.run_id, "e1:cleanup:bindings");
    match adapter.signed_get(node, &bindings_path(settings), &request_id) {
        Ok((200, body)) => Some(
            body.get("data")
                .and_then(Value::as_array)
                .is_some_and(|rows| {
                    rows.iter().any(|row| {
                        row.get("ruleSetId").and_then(Value::as_i64) == Some(settings.rule_set_id)
                    })
                }),
        ),
        _ => None,
    }
}

fn checked_entries(
    adapter: &mut impl ReadOnlyAdapter,
    settings: &E1Settings,
    node: &str,
) -> Option<Vec<Value>> {
    let request_id = stable_id(&settings.run_id, "e1:cleanup:entries");
    match adapter.signed_get(node, &entries_path(settings), &request_id) {
        Ok((200, body)) => body.get("data").and_then(Value::as_array).cloned(),
        _ => None,
    }
}

fn cleanup_after_cycle<A: CampaignAdapter>(
    adapter: &mut A,
    settings: &E1Settings,
    node: &str,
    cycle_ops: &BTreeMap<String, String>,
    state: &Map<String, Value>,
) -> Value {
    let mut corrective = Vec::new();
    let mut skipped = Vec::new();
    let mut residual: Vec<String> = Vec::new();
    if state.get("readerThreadsActive").and_then(Value::as_bool) == Some(true) {
        residual.push("reader_threads_still_active_manual_reconciliation_required".to_owned());
        skipped.push("deleteEntry:reader_threads_active");
        skipped.push("unbind:reader_threads_active");
        return json!({
            "corrective": corrective,
            "skipped": skipped,
            "residual": residual,
            "manualReconciliationRequired": true,
        });
    }
    let entry_owned = state.get("entryOwnershipProven").and_then(Value::as_bool) == Some(true);
    let entry_id = if entry_owned {
        state.get("entryId").and_then(Value::as_i64)
    } else {
        None
    };
    if !entry_owned && state.get("addAttempted").and_then(Value::as_bool) == Some(true) {
        residual.push("addEntry:reconciliation_unknown".to_owned());
    } else if state.get("addAttempted").and_then(Value::as_bool) != Some(true) {
        skipped.push("deleteEntry:no_campaign_add_attempt");
    }
    if let Some(id) = entry_id {
        let entries = checked_entries(adapter, settings, node);
        let present = entries.as_ref().is_some_and(|rows| {
            rows.iter()
                .any(|row| row.get("id").and_then(Value::as_i64) == Some(id))
        });
        if present {
            match adapter.signed_request(
                node,
                "DELETE",
                &entry_path(settings, id),
                Value::Null,
                &cycle_ops["deleteEntry"],
            ) {
                Ok(_) => corrective.push(json!({"action": "deleteEntry", "outcome": "committed"})),
                Err(error) => residual.push(format!("deleteEntry:{error}")),
            }
        } else {
            skipped.push("deleteEntry:already_applied");
        }
    } else {
        skipped.push("deleteEntry:no_entry_id_recorded");
    }

    let bind_owned = state.get("bindOwnershipProven").and_then(Value::as_bool) == Some(true);
    let bind_attempted = state.get("bindAttempted").and_then(Value::as_bool) == Some(true);
    if !bind_attempted || !bind_owned {
        skipped.push("unbind:not_campaign_owned");
        if checked_bindings(adapter, settings, node) == Some(true) {
            residual.push("binding_not_campaign_owned".to_owned());
        }
    } else if checked_bindings(adapter, settings, node) == Some(true) {
        match adapter.signed_request(
            node,
            "DELETE",
            &unbind_path(settings),
            Value::Null,
            &cycle_ops["unbind"],
        ) {
            Ok(_) => corrective.push(json!({"action": "unbind", "outcome": "committed"})),
            Err(error) => residual.push(format!("unbind:{error}")),
        }
    } else if checked_bindings(adapter, settings, node) == Some(false) {
        skipped.push("unbind:not_bound");
    } else {
        residual.push("unbind:binding_state_unknown".to_owned());
    }

    let entries_after = checked_entries(adapter, settings, node);
    let bindings_after = checked_bindings(adapter, settings, node);
    let final_entries_empty = entries_after.as_ref().is_some_and(Vec::is_empty);
    let final_bound = bindings_after.unwrap_or(false);
    if !final_entries_empty {
        residual.push("entries_not_empty_after_cleanup".to_owned());
    }
    if bindings_after != Some(false) {
        residual.push("binding_still_present_after_cleanup".to_owned());
    }
    json!({
        "corrective": corrective,
        "skipped": skipped,
        "residual": residual,
        "finalEntriesEmpty": final_entries_empty,
        "finalBound": final_bound,
    })
}

/// Classifies reader attempts from the server-side E1 log instead of trusting
/// the HTTP status: each attempt needs its own decision_return evidence with
/// the serving snapshot commit window, plus the add-mutation window as the
/// final observation interval. Missing or unparseable evidence classifies the
/// attempt UNKNOWN with an explicit problem, never a silent ALLOW.
fn classify_attempts_from_server_log<A: CampaignAdapter>(
    adapter: &mut A,
    node: &str,
    attempts: &[Value],
    mutation_request_id: &str,
) -> Vec<Value> {
    let request_ids: Vec<String> = attempts
        .iter()
        .filter_map(|attempt| attempt["requestId"].as_str().map(str::to_owned))
        .collect();
    let mut identifiers = request_ids.clone();
    identifiers.push(mutation_request_id.to_owned());
    let events = match adapter.read_log_lines(node, &identifiers) {
        Ok(lines) => crate::e1_log::parse_e1_events(lines, node).ok(),
        Err(_) => None,
    };
    let events = events.unwrap_or_default();
    let wall_of = |event_name: &str, request_id: &str| {
        events
            .iter()
            .find(|event| event.request_id == request_id && event.event == event_name)
            .map(|event| event.wall_unix_ns.max(0) as u64)
    };
    let mutation_window = match (
        wall_of("source_commit_start", mutation_request_id),
        wall_of("source_commit_end", mutation_request_id),
    ) {
        (Some(start), Some(end)) if end >= start => Some((start, end)),
        _ => None,
    };
    attempts
        .iter()
        .map(|attempt| {
            let request_id = attempt["requestId"].as_str().unwrap_or_default().to_owned();
            let request_events: Vec<&crate::e1_log::E1LogEvent> = events
                .iter()
                .filter(|event| event.request_id == request_id)
                .collect();
            let decision = request_events
                .iter()
                .find(|event| event.event == "decision_return");
            let commit_interval = decision.and_then(|event| {
                match (
                    event
                        .fields
                        .get("sourceCommitStart")
                        .and_then(Value::as_u64),
                    event.fields.get("sourceCommitEnd").and_then(Value::as_u64),
                ) {
                    (Some(start), Some(end)) if end >= start => Some((start, end)),
                    _ => None,
                }
            });
            let input = crate::e1_durable_contract::ReaderAttemptInput {
                request_id: request_id.clone(),
                http_status: attempt["httpStatus"]
                    .as_u64()
                    .and_then(|status| u16::try_from(status).ok()),
                transport_error: attempt["error"].as_str().map(str::to_owned),
                has_server_events: decision.is_some(),
                decision_allowed: decision
                    .and_then(|event| event.fields.get("allowed"))
                    .and_then(Value::as_bool),
                decision_reason: decision
                    .and_then(|event| event.fields.get("reason"))
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                candidate_identity_matches_e0: request_events
                    .iter()
                    .find(|event| event.event == "candidate_match")
                    .and_then(|event| event.fields.get("matchesE0"))
                    .and_then(Value::as_bool),
                commit_interval,
                final_observation: mutation_window,
            };
            crate::e1_durable_contract::classify_reader_attempt(&input)
        })
        .collect()
}

/// Reads the durable evidence queries through the adapter, parses the rows
/// fail-closed and reconciles the delete. Only a validated PASS may produce
/// an "applied" reconciliation; every problem keeps the cycle UNKNOWN.
fn reconcile_durable_evidence<A: CampaignAdapter>(
    adapter: &mut A,
    settings: &E1Settings,
    entry_id: i64,
    delete_operation_id: &str,
) -> Value {
    let queries = crate::e1_durable_contract::e1_durable_queries(
        settings.tenant_id,
        settings.rule_set_id,
        settings.card_id,
        entry_id,
        delete_operation_id,
    );
    let mut raw = crate::e1_durable_contract::RawDurableRows::default();
    for query in &queries {
        match adapter.sql(query) {
            Ok(rows) => {
                if query.contains("FROM authorization_delta_event") {
                    raw.deltas = rows;
                } else if query.contains("FROM authorization_projection_current") {
                    raw.pointer = rows;
                } else if query.contains("FROM rule_set_projection_audit") {
                    raw.audit = rows;
                } else if query.contains("FROM rule_set_entry rse") {
                    raw.source_row_count = rows.into_iter().next();
                }
            }
            Err(_) => raw.read_failed = true,
        }
    }
    let evidence = crate::e1_durable_contract::parse_durable_evidence(
        &raw,
        crate::e1_durable_contract::AGGREGATE_RULE_SET,
        settings.tenant_id,
        settings.rule_set_id,
        settings.card_id,
        entry_id,
        delete_operation_id,
    );
    let validation = crate::e1_durable_contract::validate_e1_durable_evidence(&evidence);
    let publication_applied = validation["status"] == "PASS";
    let reconciled = crate::e1_durable_contract::reconcile_delete(
        &crate::e1_durable_contract::DeleteReconcileInput {
            audit_rows: Some(evidence.audit.clone()),
            source_row_count: evidence.source_row_count,
            publication_applied,
            rule_set_id: settings.rule_set_id,
            entry_id,
            operation_id: delete_operation_id.to_owned(),
        },
    );
    json!({"validation": validation, "reconciled": reconciled})
}

pub fn run_cycle_with_cleanup<A: CampaignAdapter>(
    adapter: &mut A,
    settings: &E1Settings,
    cycle: usize,
    node: &str,
    out_dir: &Path,
    simulate_error: bool,
) -> Result<(Value, Value), E1Error> {
    let operation_ids = operation_ids_for_cycle(&settings.run_id, cycle);
    let mut state = Map::new();
    let result = if simulate_error {
        json!({
            "cycle": cycle,
            "node": node,
            "operationIds": operation_ids.clone(),
            "entryId": Value::Null,
            "operations": {},
            "readerAttempts": [],
            "classifications": [],
            "mutationEvidence": Value::Null,
            "durable": {},
            "e0Grant": Value::Null,
            "counts": {
                "allow": 0,
                "deny": 0,
                "pending": 0,
                "unknown": 1,
                "unclassified": 0,
                "violations": 0,
                "durableUnknown": 1,
            },
            "cleanupState": {},
            "problems": ["cycle_exception:RuntimeError"],
            "status": "UNKNOWN",
        })
    } else {
        let preflight = {
            let mut gate = ReadOnlyGate::new(&mut *adapter);
            run_preflight_checks(&mut gate, settings, node)
        };
        if preflight["status"] != "PASS" {
            json!({
                "cycle": cycle,
                "node": node,
                "operationIds": operation_ids.clone(),
                "entryId": Value::Null,
                "operations": {},
                "readerAttempts": [],
                "classifications": [],
                "mutationEvidence": Value::Null,
                "durable": {},
                "e0Grant": Value::Null,
                "counts": {
                    "allow": 0,
                    "deny": 0,
                    "pending": 0,
                    "unknown": 0,
                    "unclassified": 0,
                    "violations": 0,
                    "durableUnknown": 0,
                },
                "cleanupState": {},
                "problems": preflight["problems"].clone(),
                "status": "BLOCKED",
            })
        } else {
            let mut failure = None;
            let add_response = adapter.signed_request(
                node,
                "POST",
                &entries_path(settings),
                json!({
                    "effect": "ALLOW",
                    "resource": settings.resource_type,
                    "action": settings.action_code,
                    "priority": 100,
                }),
                &operation_ids["addEntry"],
            );
            let entry_id = match add_response {
                Ok((200, body)) => body
                    .get("data")
                    .and_then(|data| data.get("id"))
                    .and_then(Value::as_i64),
                Ok((status, _)) => {
                    failure = Some(format!("add_entry_http_{status}"));
                    None
                }
                Err(error) => {
                    failure = Some(format!("add_entry_transport:{error}"));
                    None
                }
            };
            if let Some(entry_id) = entry_id {
                state.insert("entryId".to_owned(), json!(entry_id));
                state.insert("entryOwnershipProven".to_owned(), json!(true));
            }
            state.insert("addAttempted".to_owned(), json!(true));
            if failure.is_none() {
                match adapter.signed_request(
                    node,
                    "POST",
                    &bind_path(settings),
                    json!({"ruleSetId": settings.rule_set_id, "refType": settings.ref_type}),
                    &operation_ids["bind"],
                ) {
                    Ok((200, _)) => {
                        state.insert("bindAttempted".to_owned(), json!(true));
                        state.insert("bindOwnershipProven".to_owned(), json!(true));
                    }
                    Ok((status, _)) => failure = Some(format!("bind_http_{status}")),
                    Err(error) => failure = Some(format!("bind_transport:{error}")),
                }
            }
            let e0_request_id = stable_id(&settings.run_id, &format!("e1:c{cycle}:e0:stats"));
            if failure.is_none() {
                match adapter.signed_get(node, STATS_PATH, &e0_request_id) {
                    Ok((200, _)) => {}
                    Ok((status, _)) => failure = Some(format!("e0_stats_http_{status}")),
                    Err(error) => failure = Some(format!("e0_stats_transport:{error}")),
                }
            }
            let mut attempts = Vec::new();
            let mut reader_request_ids = Vec::new();
            if failure.is_none() {
                for reader in 1..=settings.readers {
                    for sequence in 1..=settings.max_requests_per_reader {
                        let request_id =
                            reader_request_id(&settings.run_id, cycle, reader, sequence);
                        reader_request_ids.push(request_id.clone());
                        match adapter.signed_get(node, STATS_PATH, &request_id) {
                            Ok((status, _)) => {
                                attempts.push(json!({
                                    "requestId": request_id,
                                    "httpStatus": status,
                                }));
                            }
                            Err(error) => {
                                attempts.push(json!({
                                    "requestId": request_id,
                                    "httpStatus": Value::Null,
                                    "error": error,
                                }));
                            }
                        }
                    }
                }
            }
            let mut durable_problems: Vec<String> = Vec::new();
            let mut durable_unknown = 0usize;
            if failure.is_none() {
                if let Some(entry_id) = state.get("entryId").and_then(Value::as_i64) {
                    match adapter.signed_request(
                        node,
                        "DELETE",
                        &entry_path(settings, entry_id),
                        Value::Null,
                        &operation_ids["deleteEntry"],
                    ) {
                        Ok((200, _)) => {
                            state.insert("deleteOutcome".to_owned(), json!("committed"));
                            let durable = reconcile_durable_evidence(
                                adapter,
                                settings,
                                entry_id,
                                &operation_ids["deleteEntry"],
                            );
                            state.insert(
                                "deleteReconciled".to_owned(),
                                durable["reconciled"].clone(),
                            );
                            state.insert(
                                "deleteValidation".to_owned(),
                                durable["validation"].clone(),
                            );
                            if durable["validation"]["status"] != "PASS" {
                                durable_unknown += 1;
                                if let Some(problems) = durable["validation"]["problems"].as_array()
                                {
                                    durable_problems.extend(
                                        problems.iter().filter_map(|problem| {
                                            problem.as_str().map(str::to_owned)
                                        }),
                                    );
                                }
                            }
                        }
                        Ok((status, _)) => failure = Some(format!("delete_entry_http_{status}")),
                        Err(error) => failure = Some(format!("delete_entry_transport:{error}")),
                    }
                }
            }
            if failure.is_none() {
                match adapter.signed_request(
                    node,
                    "DELETE",
                    &unbind_path(settings),
                    Value::Null,
                    &operation_ids["unbind"],
                ) {
                    Ok((200, _)) => {}
                    Ok((status, _)) => failure = Some(format!("unbind_http_{status}")),
                    Err(error) => failure = Some(format!("unbind_transport:{error}")),
                }
            }
            let classifications = classify_attempts_from_server_log(
                adapter,
                node,
                &attempts,
                &operation_ids["addEntry"],
            );
            let allow = classifications
                .iter()
                .filter(|row| row["decision"] == "ALLOW")
                .count();
            let deny = classifications
                .iter()
                .filter(|row| row["decision"] == "DENY")
                .count();
            let pending = classifications
                .iter()
                .filter(|row| row["decision"] == "PENDING")
                .count();
            let unknown = classifications
                .iter()
                .filter(|row| row["decision"] == "UNKNOWN")
                .count();
            let unclassified = classifications
                .iter()
                .filter(|row| row["category"] == "unclassified-unknown")
                .count();
            let violations = classifications
                .iter()
                .filter(|row| row["staleAllowViolation"] == true)
                .count();
            let classification_status =
                crate::e1_durable_contract::campaign_classification_status(&classifications);
            // A candidate identity that contradicts E0 is a fixture integrity
            // violation: the whole campaign blocks instead of degrading the
            // row to UNKNOWN and mutating anyway.
            let e0_mismatch = classifications.iter().any(|row| {
                row["problems"].as_array().is_some_and(|problems| {
                    problems
                        .iter()
                        .any(|problem| problem == "candidate_identity_does_not_match_e0")
                })
            });
            let status = if violations > 0 {
                "FAIL"
            } else if e0_mismatch {
                "BLOCKED"
            } else if failure.is_some() || !durable_problems.is_empty() {
                "UNKNOWN"
            } else {
                classification_status
            };
            let mut problems = failure.map(|problem| vec![problem]).unwrap_or_default();
            if e0_mismatch {
                problems.push("e0_candidate_mismatch".to_owned());
            }
            problems.extend(durable_problems.iter().cloned());
            problems.sort_unstable();
            problems.dedup();
            json!({
                "cycle": cycle,
                "node": node,
                "operationIds": operation_ids.clone(),
                "entryId": state.get("entryId").cloned().unwrap_or(Value::Null),
                "operations": {},
                "readerAttempts": attempts,
                "classifications": classifications,
                "mutationEvidence": Value::Null,
                "durable": {"unknownCycles": durable_unknown},
                "e0Grant": {
                    "candidateIdentity": [
                        settings.tenant_id,
                        settings.card_id,
                        format!("rs-{}", settings.rule_set_id),
                        1,
                        "f".repeat(64),
                    ],
                },
                "counts": {
                    "allow": allow,
                    "deny": deny,
                    "pending": pending,
                    "unknown": unknown,
                    "unclassified": unclassified,
                    "violations": violations,
                    "durableUnknown": durable_unknown,
                },
                "cleanupState": state,
                "problems": problems,
                "status": status,
            })
        }
    };
    let cleanup_state = result
        .get("cleanupState")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let cleanup = cleanup_after_cycle(adapter, settings, node, &operation_ids, &cleanup_state);
    if simulate_error || !out_dir.join(format!("e1-cycle-{cycle}.json")).exists() {
        write_json(out_dir, &format!("e1-cycle-{cycle}.json"), &result)?;
    }
    write_json(
        out_dir,
        &format!("e1-cycle-{cycle}-cleanup.json"),
        &json!({"cycle": cycle, "node": node, "cleanup": cleanup}),
    )?;
    Ok((result, cleanup))
}

pub fn execute_campaign_offline<A: CampaignAdapter>(
    config: &Value,
    out_dir: &Path,
    adapter: &mut A,
) -> Result<Value, E1Error> {
    let settings = load_settings(config)?;
    let node = settings.node_rotation[0].clone();
    let preflight = {
        let mut gate = ReadOnlyGate::new(&mut *adapter);
        run_preflight_checks(&mut gate, &settings, &node)
    };
    write_json(out_dir, "preflight.json", &preflight)?;
    let mut cycles = Vec::new();
    for cycle in 1..=settings.cycles {
        let cycle_node = settings.node_rotation[(cycle - 1) % settings.node_rotation.len()].clone();
        let (result, _cleanup) =
            run_cycle_with_cleanup(adapter, &settings, cycle, &cycle_node, out_dir, false)?;
        cycles.push(result);
    }
    let status = if cycles.iter().any(|cycle| cycle["status"] == "FAIL") {
        "FAIL"
    } else if cycles.iter().any(|cycle| cycle["status"] == "UNKNOWN") {
        "UNKNOWN"
    } else if cycles.iter().any(|cycle| cycle["status"] == "BLOCKED") {
        "BLOCKED"
    } else {
        "PASS"
    };
    let manifest = json!({
        "campaignId": settings.run_id,
        "experiment": "E1",
        "mode": "campaign",
        "status": status,
        "settings": settings.public_metadata(),
        "preflight": preflight,
        "cycles": cycles,
    });
    write_json(out_dir, "manifest.json", &manifest)?;
    let mut artifacts = vec!["preflight.json".to_owned(), "manifest.json".to_owned()];
    for cycle in 1..=settings.cycles {
        artifacts.push(format!("e1-cycle-{cycle}.json"));
        artifacts.push(format!("e1-cycle-{cycle}-cleanup.json"));
    }
    let artifact_refs = artifacts.iter().map(String::as_str).collect::<Vec<_>>();
    write_checksums(out_dir, &artifact_refs)?;
    verify_checksums(out_dir, &out_dir.join("checksums.sha256"))?;
    Ok(manifest)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::path::PathBuf;

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
                "max_requests_per_reader": 4,
                "fixture_synthetic": true,
                "reconcile_polls": 3,
                "reconcile_interval_s": 0.0
            }
        })
    }

    fn settings(config: &Value) -> E1Settings {
        load_settings(config).expect("valid settings")
    }

    fn temp_dir(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("astral-e1-{label}-{}", Uuid::new_v4()));
        fs::create_dir_all(&path).expect("temp dir");
        path
    }

    fn approval_record() -> Value {
        json!({
            "run_id": RUN_ID,
            "approval_ref": APPROVAL_REF,
            "approval_scope": APPROVAL_SCOPE,
            "approved_by": "human-operator",
            "approved_at": "2026-09-19T12:00:00Z"
        })
    }

    pub(crate) struct FakeWorld {
        entries: Vec<Value>,
        bound: bool,
        foreign_bound_cards: Vec<i64>,
        rule_set_tenant: Option<i64>,
        rule_set_enabled: bool,
        grant_active: bool,
        admin_denied: bool,
        stats_open_pre_grant: bool,
        calls: Vec<AdapterCall>,
        sql_queries: Vec<String>,
        log_lines: Vec<String>,
        sequence: u64,
        next_entry_id: i64,
        stale_snapshot: bool,
        candidate_mismatch: bool,
        pre_add_snapshot_ns: u64,
        durable_missing_delta: bool,
        durable_stale_pointer: bool,
        durable_source_present: bool,
        deleted_entry: Option<i64>,
        delete_op_id: Option<String>,
    }

    impl FakeWorld {
        pub(crate) fn clean() -> Self {
            Self {
                entries: Vec::new(),
                bound: false,
                foreign_bound_cards: Vec::new(),
                rule_set_tenant: Some(9001),
                rule_set_enabled: true,
                grant_active: false,
                admin_denied: false,
                stats_open_pre_grant: false,
                calls: Vec::new(),
                sql_queries: Vec::new(),
                log_lines: Vec::new(),
                sequence: 1000,
                next_entry_id: 5000,
                stale_snapshot: false,
                candidate_mismatch: false,
                pre_add_snapshot_ns: 1_758_000_000_000_000_000,
                durable_missing_delta: false,
                durable_stale_pointer: false,
                durable_source_present: false,
                deleted_entry: None,
                delete_op_id: None,
            }
        }

        fn peek_ns(&self) -> u64 {
            1_758_000_000_000_000_000 + self.sequence + 1
        }

        fn emit(&mut self, event: &str, request_id: &str) {
            self.emit_with_fields(event, request_id, Map::new());
        }

        fn emit_with_fields(&mut self, event: &str, request_id: &str, fields: Map<String, Value>) {
            self.sequence += 1;
            let mut record = json!({
                "target": "authz_e1",
                "event": event,
                "request_id": request_id,
                "process_observation_id": "proc-e1-test",
                "event_sequence": self.sequence,
                "wall_unix_ns": 1_758_000_000_000_000_000u64 + self.sequence,
                "message": "e1 authorization observation",
            });
            if let Some(target) = record.as_object_mut() {
                for (key, value) in fields {
                    target.insert(key, value);
                }
            }
            self.log_lines.push(record.to_string());
        }

        /// The serving snapshot window a decision was computed from. In the
        /// clean mode the snapshot is committed after the add mutation; in
        /// stale mode readers keep getting served the pre-mutation snapshot.
        fn serving_snapshot_window(&self) -> (u64, u64) {
            if self.stale_snapshot {
                (self.pre_add_snapshot_ns, self.pre_add_snapshot_ns)
            } else {
                let now = self.peek_ns();
                (now, now + 1)
            }
        }

        fn emit_allow_chain(&mut self, request_id: &str) {
            let (commit_start, commit_end) = self.serving_snapshot_window();
            self.emit_with_fields(
                "candidate_match",
                request_id,
                json!({"matchesE0": !self.candidate_mismatch})
                    .as_object()
                    .cloned()
                    .unwrap_or_default(),
            );
            self.emit_with_fields(
                "decision_return",
                request_id,
                json!({
                    "allowed": true,
                    "reason": "RULE_MATCH",
                    "sourceCommitStart": commit_start,
                    "sourceCommitEnd": commit_end,
                })
                .as_object()
                .cloned()
                .unwrap_or_default(),
            );
            self.emit_with_fields(
                "host_admission",
                request_id,
                json!({"allowed": true})
                    .as_object()
                    .cloned()
                    .unwrap_or_default(),
            );
        }

        fn emit_deny_pair(&mut self, request_id: &str) {
            self.emit("signed_context_bound", request_id);
            self.emit_with_fields(
                "decision_return",
                request_id,
                json!({"allowed": false, "reason": "DEFAULT_DENY"})
                    .as_object()
                    .cloned()
                    .unwrap_or_default(),
            );
        }

        fn record(&mut self, method: &str, path: &str, request_id: &str) {
            self.calls.push(AdapterCall {
                method: method.to_owned(),
                path: path.to_owned(),
                request_id: request_id.to_owned(),
                actor_card: "9061".to_owned(),
            });
        }
    }

    impl ReadOnlyAdapter for FakeWorld {
        fn signed_get(
            &mut self,
            _node: &str,
            path: &str,
            request_id: &str,
        ) -> Result<(u16, Value), String> {
            self.record("GET", path, request_id);
            if path.starts_with("/main/api/v1/permission-rules/check") {
                let effect = if self.grant_active {
                    "ALLOW"
                } else {
                    "NO_MATCH"
                };
                return Ok((
                    200,
                    json!({"code": 200, "data": {"effect": effect, "reason": effect}}),
                ));
            }
            if path == "/main/api/v1/rule-sets/9071" {
                return Ok((
                    200,
                    json!({"code": 200, "data": {
                        "id": 9071,
                        "name": "e1-fixture",
                        "refType": "BASE",
                        "entryCount": self.entries.len(),
                        "boundCardCount": if self.bound { 1 } else { 0 },
                    }}),
                ));
            }
            if path == "/main/api/v1/rule-sets/9071/entries" {
                let rows = self
                    .entries
                    .iter()
                    .map(|entry| {
                        json!({
                            "id": entry["entry_id"],
                            "effect": entry["effect"],
                            "resource": entry["resource"],
                            "action": entry["action"],
                            "priority": 100,
                        })
                    })
                    .collect::<Vec<_>>();
                return Ok((200, json!({"code": 200, "data": rows})));
            }
            if path == "/main/api/v1/rule-sets/card/9061/bindings" {
                if self.admin_denied {
                    return Ok((
                        403,
                        json!({"code": 403, "message": "PLATFORM_ADMIN_REQUIRED", "data": null}),
                    ));
                }
                let rows = if self.bound {
                    vec![json!({
                        "ruleSetId": 9071,
                        "ruleSetName": "e1-fixture",
                        "ruleSetCode": "e1-fixture",
                        "refType": "BASE",
                    })]
                } else {
                    Vec::new()
                };
                return Ok((200, json!({"code": 200, "data": rows})));
            }
            if path == STATS_PATH {
                if self.grant_active || self.stats_open_pre_grant {
                    self.emit_allow_chain(request_id);
                    return Ok((
                        200,
                        json!({"code": 200, "message": "ok", "data": {"total": 1}}),
                    ));
                }
                self.emit_deny_pair(request_id);
                return Ok((
                    403,
                    json!({
                        "code": 403,
                        "message": "Permission denied: DEFAULT_DENY for monitor:read",
                        "data": null,
                        "errorType": "PERMISSION_DENIED",
                    }),
                ));
            }
            Err(format!("unexpected request: GET {path}"))
        }

        fn sql(&mut self, query: &str) -> Result<Vec<Vec<String>>, String> {
            self.sql_queries.push(query.to_owned());
            if query.contains("FROM authorization_delta_event") {
                if self.durable_missing_delta {
                    return Ok(Vec::new());
                }
                let operation_id = self.delete_op_id.clone().unwrap_or_default();
                return Ok(vec![vec![
                    "evt-del-1".to_owned(),
                    "REMOVE".to_owned(),
                    "SUCCEEDED".to_owned(),
                    "9061".to_owned(),
                    operation_id,
                    "2".to_owned(),
                ]]);
            }
            if query.contains("FROM authorization_projection_current") {
                let operation_id = self.delete_op_id.clone().unwrap_or_default();
                if self.durable_stale_pointer {
                    return Ok(vec![vec![
                        "9061".to_owned(),
                        "older-op".to_owned(),
                        "evt-old".to_owned(),
                        "1".to_owned(),
                        "READY".to_owned(),
                        "0".to_owned(),
                    ]]);
                }
                return Ok(vec![vec![
                    "9061".to_owned(),
                    operation_id,
                    "evt-del-1".to_owned(),
                    "2".to_owned(),
                    "READY".to_owned(),
                    "0".to_owned(),
                ]]);
            }
            if query.contains("FROM rule_set_projection_audit") {
                let operation_id = self.delete_op_id.clone().unwrap_or_default();
                let entry_id = self
                    .deleted_entry
                    .map(|entry_id| entry_id.to_string())
                    .unwrap_or_default();
                return Ok(vec![vec![
                    "DELETE".to_owned(),
                    "9071".to_owned(),
                    entry_id,
                    "RULE_SET".to_owned(),
                    "9071".to_owned(),
                    operation_id,
                    "evt-del-1".to_owned(),
                    "2".to_owned(),
                ]]);
            }
            if query.contains("FROM rule_set_entry rse") {
                let count = if self.durable_source_present {
                    "1"
                } else {
                    "0"
                };
                return Ok(vec![vec![count.to_owned()]]);
            }
            if query.starts_with("SELECT COUNT(*) FROM rule_set WHERE ") {
                let matches = query.contains("tenant_id=9001")
                    && self.rule_set_tenant == Some(9001)
                    && query.contains("enabled=1")
                    && self.rule_set_enabled;
                return Ok(vec![vec![if matches { "1" } else { "0" }.to_owned()]]);
            }
            if query.starts_with("SELECT card_id FROM card_rule_set_ref WHERE ") {
                let mut rows = self.foreign_bound_cards.clone();
                if self.bound {
                    rows.push(9061);
                }
                rows.sort_unstable();
                rows.dedup();
                return Ok(rows
                    .into_iter()
                    .map(|card| vec![card.to_string()])
                    .collect());
            }
            Err(format!("unexpected query: {query}"))
        }

        fn read_log_lines(
            &mut self,
            _node: &str,
            _identifiers: &[String],
        ) -> Result<Vec<String>, String> {
            Ok(self.log_lines.clone())
        }

        fn projection_baseline(
            &mut self,
            _tenant_id: i64,
            _aggregate: &str,
            _aggregate_id: i64,
        ) -> Result<Value, String> {
            Ok(json!({"state": "ready", "generation": 1}))
        }
    }

    impl CampaignAdapter for FakeWorld {
        fn signed_request(
            &mut self,
            _node: &str,
            method: &str,
            path: &str,
            body: Value,
            request_id: &str,
        ) -> Result<(u16, Value), String> {
            self.record(method, path, request_id);
            match (method, path) {
                ("POST", "/main/api/v1/rule-sets/9071/entries") => {
                    self.emit_with_fields(
                        "source_commit_start",
                        request_id,
                        json!({"operationId": request_id})
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                    );
                    let entry_id = self.next_entry_id;
                    self.next_entry_id += 1;
                    self.entries.push(json!({
                        "entry_id": entry_id,
                        "effect": body["effect"],
                        "resource": body["resource"],
                        "action": body["action"],
                    }));
                    self.grant_active = self.bound && !self.entries.is_empty();
                    self.emit_with_fields(
                        "source_commit_end",
                        request_id,
                        json!({"operationId": request_id})
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                    );
                    Ok((200, json!({"code": 200, "data": {"id": entry_id}})))
                }
                ("POST", "/main/api/v1/rule-sets/card/9061/bind") => {
                    self.bound = true;
                    self.grant_active = !self.entries.is_empty();
                    Ok((200, json!({"code": 200, "data": null})))
                }
                ("DELETE", _) if path.starts_with("/main/api/v1/rule-sets/9071/entries/") => {
                    let entry_id = path
                        .rsplit('/')
                        .next()
                        .ok_or_else(|| "missing entry id".to_owned())?
                        .parse::<i64>()
                        .map_err(|error| error.to_string())?;
                    self.emit_with_fields(
                        "source_commit_start",
                        request_id,
                        json!({"operationId": request_id})
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                    );
                    self.entries
                        .retain(|entry| entry["entry_id"].as_i64() != Some(entry_id));
                    self.grant_active = self.bound && !self.entries.is_empty();
                    self.deleted_entry = Some(entry_id);
                    self.delete_op_id = Some(request_id.to_owned());
                    self.emit_with_fields(
                        "source_commit_end",
                        request_id,
                        json!({"operationId": request_id})
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                    );
                    Ok((200, json!({"code": 200, "data": null})))
                }
                ("DELETE", "/main/api/v1/rule-sets/card/9061/unbind/9071") => {
                    self.bound = false;
                    self.grant_active = false;
                    Ok((200, json!({"code": 200, "data": null})))
                }
                _ => Err(format!("unexpected request: {method} {path}")),
            }
        }
    }

    #[test]
    fn plan_is_offline_and_operation_ids_are_safe_unique_and_ordered() {
        let out = temp_dir("plan");
        let config = raw_config();
        let plan = execute_plan(&config, &out).expect("plan");
        assert_eq!(plan["status"], "PLANNED");
        assert_eq!(plan["operationOrder"], json!(OP_ORDER));
        assert_eq!(plan["cycles"][0]["node"], "node-a");
        assert_eq!(plan["cycles"][0]["readerRequestBudget"], 8);
        assert!(out.join("plan.json").exists());
        assert!(out.join("checksums.sha256").exists());
        verify_checksums(&out, &out.join("checksums.sha256")).expect("checksums");

        let mut seen = BTreeSet::new();
        for cycle in plan["cycles"].as_array().unwrap() {
            let operations = cycle["operationIds"].as_object().unwrap();
            assert_eq!(operations.len(), 4);
            for (name, operation_id) in operations {
                let value = operation_id.as_str().unwrap();
                assert!(value.len() <= 64, "{name}");
                assert!(Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$")
                    .unwrap()
                    .is_match(value));
                assert!(seen.insert(value.to_owned()), "{name}");
            }
        }
        assert_eq!(seen.len(), 4);
        fs::remove_dir_all(out).ok();
    }

    #[test]
    fn checksum_path_escape_is_rejected_fail_closed() {
        let out = temp_dir("checksum-escape");
        std::fs::write(out.join("manifest.json"), b"{}").expect("artifact");
        let checksums = format!("{}  ../escape.txt\n", "1".repeat(64));
        let checksum_path = out.join("checksums.sha256");
        std::fs::write(&checksum_path, checksums).expect("checksums");
        let error = verify_checksums(&out, &checksum_path).expect_err("path escape rejected");
        assert!(error
            .to_string()
            .contains("checksum path escapes artifact root"));
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn stable_id_rejects_unsafe_identifiers_fail_closed() {
        assert!(std::panic::catch_unwind(|| stable_id("bad id", "e1:c1:add-entry")).is_err());
        assert!(std::panic::catch_unwind(|| stable_id("run-ok", "bad label")).is_err());
        let oversized = "x".repeat(129);
        assert!(std::panic::catch_unwind(|| stable_id("run-ok", &oversized)).is_err());
        // The pinned valid case still derives the same UUIDv5.
        assert_eq!(
            stable_id("run-ok", "e1:c1:add-entry"),
            stable_id("run-ok", "e1:c1:add-entry")
        );
    }

    #[test]
    fn plan_rotates_nodes_and_ids_across_cycles() {
        let out = temp_dir("rotation");
        let mut config = raw_config();
        config["e1"]["node_rotation"] = json!(["node-a", "node-b"]);
        config["e1"]["cycles"] = json!(2);
        let plan = execute_plan(&config, &out).expect("plan");
        assert_eq!(
            plan["cycles"]
                .as_array()
                .unwrap()
                .iter()
                .map(|cycle| cycle["node"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["node-a", "node-b"]
        );
        let mut seen = BTreeSet::new();
        for cycle in plan["cycles"].as_array().unwrap() {
            for operation_id in cycle["operationIds"].as_object().unwrap().values() {
                assert!(seen.insert(operation_id.as_str().unwrap().to_owned()));
            }
        }
        assert_eq!(seen.len(), 8);
        fs::remove_dir_all(out).ok();
    }

    #[test]
    fn reader_request_ids_are_unique_across_cycles() {
        let mut seen = BTreeSet::new();
        for cycle in 1..=2 {
            for reader in 1..=2 {
                for sequence in 1..=4 {
                    assert!(seen.insert(reader_request_id(RUN_ID, cycle, reader, sequence)));
                }
            }
        }
        assert_eq!(seen.len(), 16);
    }

    #[test]
    fn readonly_gate_rejects_mutations() {
        let world = FakeWorld::clean();
        let mut gate = ReadOnlyGate::new(world);
        assert_eq!(
            gate.signed_request(
                "node-a",
                "POST",
                "/main/api/v1/rule-sets/9071/entries",
                json!({})
            ),
            Err(E1Error::ReadOnlyGate)
        );
        assert!(gate
            .signed_request("node-a", "DELETE", "/main/api/v1/x", Value::Null)
            .is_err());
    }

    #[test]
    fn preflight_uses_get_and_select_only_with_exact_paths() {
        let mut world = FakeWorld::clean();
        world.bound = true;
        let expected_count_query =
            "SELECT COUNT(*) FROM rule_set WHERE rule_set_id=9071 AND tenant_id=9001 AND enabled=1";
        let mut gate = ReadOnlyGate::new(world);
        let report = run_preflight_checks(&mut gate, &settings(&raw_config()), "node-a");
        let world = gate.adapter();
        assert_eq!(report["status"], "BLOCKED");
        assert_eq!(report["problems"][0], "card_not_bound_to_rule_set");
        assert!(world.calls.iter().all(|call| call.method == "GET"));
        let mut paths = world
            .calls
            .iter()
            .map(|call| call.path.split('?').next().unwrap().to_owned())
            .collect::<Vec<_>>();
        paths.sort();
        paths.dedup();
        assert_eq!(
            paths,
            [
                "/main/api/v1/permission-rules/check",
                "/main/api/v1/rule-sets/9071",
                "/main/api/v1/rule-sets/9071/entries",
                "/main/api/v1/rule-sets/card/9061/bindings",
                "/main/api/v1/stats",
            ]
        );
        assert!(world.calls.iter().all(|call| call.actor_card == "9061"));
        assert!(world
            .calls
            .iter()
            .all(|call| call.path.starts_with("/main/api/v1/")));
        assert!(world
            .sql_queries
            .iter()
            .any(|query| query == expected_count_query));
        assert!(world.sql_queries.iter().all(|query| query
            .trim_start()
            .to_ascii_uppercase()
            .starts_with("SELECT")));
    }

    #[test]
    fn preflight_blocks_on_every_dirty_precondition() {
        struct Case {
            expected: &'static str,
            world: FakeWorld,
            fixture_synthetic: Option<bool>,
        }
        let mut entries = FakeWorld::clean();
        entries.entries.push(json!({
            "entry_id": 4001,
            "effect": "ALLOW",
            "resource": "monitor",
            "action": "read",
        }));
        let mut bound = FakeWorld::clean();
        bound.bound = true;
        let mut foreign = FakeWorld::clean();
        foreign.foreign_bound_cards = vec![9999];
        let mut allow = FakeWorld::clean();
        allow.grant_active = true;
        let mut open = FakeWorld::clean();
        open.stats_open_pre_grant = true;
        let mut admin = FakeWorld::clean();
        admin.admin_denied = true;
        let mut tenantless = FakeWorld::clean();
        tenantless.rule_set_tenant = None;
        let mut cross_tenant = FakeWorld::clean();
        cross_tenant.rule_set_tenant = Some(9002);
        let mut disabled = FakeWorld::clean();
        disabled.rule_set_enabled = false;
        let cases = [
            Case {
                expected: "rule_set_entries_empty",
                world: entries,
                fixture_synthetic: None,
            },
            Case {
                expected: "card_not_bound_to_rule_set",
                world: bound,
                fixture_synthetic: None,
            },
            Case {
                expected: "rule_set_not_bound_to_any_card",
                world: foreign,
                fixture_synthetic: None,
            },
            Case {
                expected: "pre_grant_deny_check_endpoint",
                world: allow,
                fixture_synthetic: None,
            },
            Case {
                expected: "pre_grant_deny_stats",
                world: open,
                fixture_synthetic: None,
            },
            Case {
                expected: "admin_active_and_card_context",
                world: admin,
                fixture_synthetic: None,
            },
            Case {
                expected: "rule_set_owned_by_active_tenant",
                world: tenantless,
                fixture_synthetic: None,
            },
            Case {
                expected: "rule_set_owned_by_active_tenant",
                world: cross_tenant,
                fixture_synthetic: None,
            },
            Case {
                expected: "rule_set_owned_by_active_tenant",
                world: disabled,
                fixture_synthetic: None,
            },
            Case {
                expected: "fixture_synthetic_attestation",
                world: FakeWorld::clean(),
                fixture_synthetic: Some(false),
            },
        ];
        for case in cases {
            let mut config = raw_config();
            if let Some(value) = case.fixture_synthetic {
                config["e1"]["fixture_synthetic"] = json!(value);
            }
            let mut gate = ReadOnlyGate::new(case.world);
            let report = run_preflight_checks(&mut gate, &settings(&config), "node-a");
            assert_eq!(report["status"], "BLOCKED");
            assert_eq!(report["problems"][0], case.expected, "{report}");
            assert!(gate.adapter().calls.iter().all(|call| call.method == "GET"));
        }
    }

    #[test]
    fn invalid_admin_tenant_is_a_config_error() {
        for tenant in ["not-a-tenant", "9223372036854775808"] {
            let mut config = raw_config();
            config["e1"]["admin_actor"]["tenant"] = json!(tenant);
            assert_eq!(
                load_settings(&config),
                Err(E1Error::Config(vec![
                    "invalid:e1.admin_actor.tenant".to_owned()
                ]))
            );
        }
    }

    #[test]
    fn preflight_passes_on_clean_fixture() {
        let mut gate = ReadOnlyGate::new(FakeWorld::clean());
        let report = run_preflight_checks(&mut gate, &settings(&raw_config()), "node-a");
        assert_eq!(report["status"], "PASS", "{report}");
        assert_eq!(report["problems"], json!([]));
    }

    #[test]
    fn live_gate_requires_all_explicit_human_inputs() {
        let settings = settings(&raw_config());
        let record = approval_record();
        let matrix = [
            (
                LiveGateInput {
                    live: false,
                    approval_ref: None,
                    approval_record: None,
                    confirm_exec_l3: false,
                    independent_validator: true,
                },
                "live_not_enabled",
            ),
            (
                LiveGateInput {
                    live: true,
                    approval_ref: None,
                    approval_record: None,
                    confirm_exec_l3: false,
                    independent_validator: true,
                },
                "exec_l3_human_confirmation_missing",
            ),
            (
                LiveGateInput {
                    live: true,
                    approval_ref: Some(APPROVAL_REF),
                    approval_record: Some(&record),
                    confirm_exec_l3: false,
                    independent_validator: true,
                },
                "exec_l3_human_confirmation_missing",
            ),
            (
                LiveGateInput {
                    live: true,
                    approval_ref: None,
                    approval_record: Some(&record),
                    confirm_exec_l3: true,
                    independent_validator: true,
                },
                "approval_ref_missing_or_unsafe",
            ),
            (
                LiveGateInput {
                    live: true,
                    approval_ref: Some(APPROVAL_REF),
                    approval_record: None,
                    confirm_exec_l3: true,
                    independent_validator: true,
                },
                "approval_record_missing",
            ),
        ];
        for (input, expected) in matrix {
            assert_eq!(
                check_live_gate(&settings, &input).as_deref(),
                Some(expected)
            );
        }

        let mut broken = approval_record();
        broken["run_id"] = json!("other-run");
        assert_eq!(
            check_live_gate(
                &settings,
                &LiveGateInput {
                    live: true,
                    approval_ref: Some(APPROVAL_REF),
                    approval_record: Some(&broken),
                    confirm_exec_l3: true,
                    independent_validator: true,
                }
            )
            .as_deref(),
            Some("approval_record_run_id_mismatch")
        );

        assert_eq!(
            check_live_gate(
                &settings,
                &LiveGateInput {
                    live: true,
                    approval_ref: Some(APPROVAL_REF),
                    approval_record: Some(&record),
                    confirm_exec_l3: true,
                    independent_validator: false,
                }
            )
            .as_deref(),
            Some("independent_user_approval_not_verified")
        );
        assert_eq!(
            check_live_gate(
                &settings,
                &LiveGateInput {
                    live: true,
                    approval_ref: Some(APPROVAL_REF),
                    approval_record: Some(&record),
                    confirm_exec_l3: true,
                    independent_validator: true,
                }
            ),
            None
        );
    }

    #[test]
    fn stale_allow_reader_attempt_is_classified_violation_and_fails_campaign() {
        let out = temp_dir("stale-allow");
        let mut world = FakeWorld::clean();
        world.stale_snapshot = true;
        let manifest = execute_campaign_offline(&raw_config(), &out, &mut world).expect("campaign");
        assert_eq!(manifest["status"], "FAIL", "{manifest}");
        let cycle = &manifest["cycles"][0];
        assert_eq!(cycle["status"], "FAIL");
        assert!(
            cycle["counts"]["violations"].as_u64().unwrap() > 0,
            "{cycle}"
        );
        let violating = cycle["classifications"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["staleAllowViolation"] == true)
            .collect::<Vec<_>>();
        assert!(!violating.is_empty());
        assert!(violating
            .iter()
            .all(|row| row["category"] == "post-commit-before-final-observation"));
        assert!(violating.iter().all(|row| row["decision"] == "ALLOW"));
        fs::remove_dir_all(out).ok();
    }

    #[test]
    fn e0_candidate_mismatch_blocks_the_whole_campaign() {
        let out = temp_dir("e0-mismatch");
        let mut world = FakeWorld::clean();
        world.candidate_mismatch = true;
        let manifest = execute_campaign_offline(&raw_config(), &out, &mut world).expect("campaign");
        assert_eq!(manifest["status"], "BLOCKED", "{manifest}");
        let cycle = &manifest["cycles"][0];
        assert_eq!(cycle["status"], "BLOCKED");
        assert!(cycle["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "e0_candidate_mismatch"));
        assert!(cycle["classifications"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["problems"]
                .as_array()
                .unwrap()
                .iter()
                .any(|problem| problem == "candidate_identity_does_not_match_e0")));
        std::fs::remove_dir_all(out).ok();
    }

    #[test]
    fn missing_delete_delta_keeps_reconciliation_unknown() {
        let out = temp_dir("missing-delta");
        let mut world = FakeWorld::clean();
        world.durable_missing_delta = true;
        let manifest = execute_campaign_offline(&raw_config(), &out, &mut world).expect("campaign");
        assert_eq!(manifest["status"], "UNKNOWN", "{manifest}");
        let cycle = &manifest["cycles"][0];
        assert_eq!(cycle["status"], "UNKNOWN");
        assert_ne!(
            cycle["cleanupState"]["deleteReconciled"]["state"],
            "applied"
        );
        assert!(cycle["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "missing_delete_delta"));
        assert_eq!(cycle["counts"]["durableUnknown"], 1);
        fs::remove_dir_all(out).ok();
    }

    #[test]
    fn stale_pointer_after_delete_delta_blocks_publication_claim() {
        let out = temp_dir("stale-pointer");
        let mut world = FakeWorld::clean();
        world.durable_stale_pointer = true;
        let manifest = execute_campaign_offline(&raw_config(), &out, &mut world).expect("campaign");
        assert_eq!(manifest["status"], "UNKNOWN", "{manifest}");
        let cycle = &manifest["cycles"][0];
        assert!(cycle["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "stale_pointer_after_delete_delta"));
        assert_ne!(
            cycle["cleanupState"]["deleteReconciled"]["state"],
            "applied"
        );
        fs::remove_dir_all(out).ok();
    }

    #[test]
    fn clean_campaign_adds_binds_reads_deletes_unbinds_and_writes_artifacts() {
        let out = temp_dir("campaign");
        let mut world = FakeWorld::clean();
        let manifest = execute_campaign_offline(&raw_config(), &out, &mut world).expect("campaign");
        assert_eq!(manifest["status"], "PASS", "{manifest}");
        let cycle = &manifest["cycles"][0];
        assert_eq!(cycle["status"], "PASS");
        assert_eq!(cycle["counts"]["violations"], 0);
        assert_eq!(
            world
                .calls
                .iter()
                .filter(|call| call.method == "POST")
                .count(),
            2
        );
        assert_eq!(
            world
                .calls
                .iter()
                .filter(|call| call.method == "DELETE")
                .count(),
            2
        );
        assert!(world.entries.is_empty());
        assert!(!world.bound);
        assert!(!world.grant_active);
        let posts = world
            .calls
            .iter()
            .filter(|call| call.method == "POST")
            .map(|call| call.path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            posts,
            [
                "/main/api/v1/rule-sets/9071/entries",
                "/main/api/v1/rule-sets/card/9061/bind",
            ]
        );
        let document: Value = serde_json::from_str(
            &fs::read_to_string(out.join("e1-cycle-1.json")).expect("cycle artifact"),
        )
        .expect("cycle json");
        let add_post = world
            .calls
            .iter()
            .find(|call| call.method == "POST")
            .expect("add post");
        assert_eq!(
            add_post.request_id,
            document["operationIds"]["addEntry"].as_str().unwrap()
        );
        let attempts = document["readerAttempts"].as_array().unwrap();
        assert!(attempts.len() <= 8);
        let ids = attempts
            .iter()
            .map(|attempt| attempt["requestId"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), attempts.len());
        let allow_rows = document["classifications"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["decision"] == "ALLOW")
            .collect::<Vec<_>>();
        assert_eq!(
            allow_rows.len(),
            cycle["counts"]["allow"].as_u64().unwrap() as usize
        );
        assert!(allow_rows
            .iter()
            .all(|row| row["staleAllowViolation"] == false));
        for name in [
            "manifest.json",
            "preflight.json",
            "e1-cycle-1.json",
            "e1-cycle-1-cleanup.json",
        ] {
            assert!(out.join(name).exists(), "{name}");
        }
        verify_checksums(&out, &out.join("checksums.sha256")).expect("checksums");
        fs::remove_dir_all(out).ok();
    }

    #[test]
    fn two_cycle_campaign_uses_distinct_e0_request_ids_and_artifacts() {
        let out = temp_dir("two-cycles");
        let mut config = raw_config();
        config["e1"]["cycles"] = json!(2);
        let mut world = FakeWorld::clean();
        let manifest = execute_campaign_offline(&config, &out, &mut world).expect("campaign");
        assert_eq!(manifest["cycles"].as_array().unwrap().len(), 2);
        assert!(manifest["cycles"]
            .as_array()
            .unwrap()
            .iter()
            .all(|cycle| cycle["status"] == "PASS"));
        let expected = [
            stable_id(RUN_ID, "e1:c1:e0:stats"),
            stable_id(RUN_ID, "e1:c2:e0:stats"),
        ];
        let actual = world
            .calls
            .iter()
            .filter(|call| {
                call.method == "GET"
                    && call.path == STATS_PATH
                    && expected.contains(&call.request_id)
            })
            .map(|call| call.request_id.clone())
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
        for cycle in 1..=2 {
            let document: Value = serde_json::from_str(
                &fs::read_to_string(out.join(format!("e1-cycle-{cycle}.json"))).unwrap(),
            )
            .unwrap();
            assert_eq!(
                document["e0Grant"]["candidateIdentity"],
                json!([9001, 9061, "rs-9071", 1, "f".repeat(64)])
            );
        }
        fs::remove_dir_all(out).ok();
    }

    #[test]
    fn cleanup_does_not_remove_foreign_binding_after_preflight_block() {
        let out = temp_dir("foreign-binding");
        let mut world = FakeWorld::clean();
        world.bound = true;
        let settings = settings(&raw_config());
        let (result, cleanup) =
            run_cycle_with_cleanup(&mut world, &settings, 1, "node-a", &out, false).expect("cycle");
        assert_eq!(result["status"], "BLOCKED");
        assert!(world.bound);
        assert!(!world
            .calls
            .iter()
            .any(|call| call.path.ends_with("/unbind/9071")));
        assert!(cleanup["residual"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "binding_not_campaign_owned"));
        fs::remove_dir_all(out).ok();
    }

    #[test]
    fn cycle_exception_still_writes_per_cycle_cleanup_artifact() {
        let out = temp_dir("cycle-exception");
        let mut world = FakeWorld::clean();
        let settings = settings(&raw_config());
        let (result, cleanup) =
            run_cycle_with_cleanup(&mut world, &settings, 1, "node-a", &out, true).expect("cycle");
        assert_eq!(result["status"], "UNKNOWN");
        assert!(result["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem == "cycle_exception:RuntimeError"));
        let document: Value = serde_json::from_str(
            &fs::read_to_string(out.join("e1-cycle-1-cleanup.json")).expect("cleanup artifact"),
        )
        .expect("cleanup json");
        assert_eq!(document["cycle"], 1);
        assert_eq!(document["node"], "node-a");
        let mut keys = document["cleanup"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "corrective",
                "finalBound",
                "finalEntriesEmpty",
                "residual",
                "skipped",
            ]
        );
        assert_eq!(cleanup, document["cleanup"]);
        fs::remove_dir_all(out).ok();
    }

    #[test]
    fn reader_threads_active_blocks_cleanup_mutations() {
        let mut world = FakeWorld::clean();
        let settings = settings(&raw_config());
        let operations = operation_ids_for_cycle(RUN_ID, 1);
        let state = Map::from_iter([
            ("readerThreadsActive".to_owned(), json!(true)),
            ("entryId".to_owned(), json!(4100)),
            ("entryOwnershipProven".to_owned(), json!(true)),
            ("bindOwnershipProven".to_owned(), json!(true)),
            ("bindAttempted".to_owned(), json!(true)),
        ]);
        let cleanup = cleanup_after_cycle(&mut world, &settings, "node-a", &operations, &state);
        assert!(cleanup["residual"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "reader_threads_still_active_manual_reconciliation_required"));
        assert_eq!(cleanup["manualReconciliationRequired"], true);
        assert!(cleanup["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "deleteEntry:reader_threads_active"));
        assert!(cleanup["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "unbind:reader_threads_active"));
        assert!(world.calls.iter().all(|call| call.method == "GET"));
    }
}
