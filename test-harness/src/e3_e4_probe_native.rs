//! Native read-only E3/E4 probe over the injected NodeAdapter runtime.
//! It performs actor-aware signed decisions, SELECT-only snapshots and worker
//! readiness checks; no network, SSH or subprocess is opened by the probe.

use crate::node_adapter_contract::{
    decision_path_for, CommandRunner, ContractError, HttpTransport,
};
use crate::node_adapter_native::NodeAdapter;
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProbeSample {
    pub role: String,
    pub decision_status: &'static str,
    pub classification: &'static str,
}

pub fn sample_decision<T: HttpTransport>(
    adapter: &NodeAdapter,
    transport: &mut T,
    node: &str,
    role: &str,
    card: &str,
    request_id: &str,
) -> Result<ProbeSample, ContractError> {
    let path = decision_path_for("/main/api/v1/permission-rules/check", card, "cardId");
    let (status, body, _) =
        adapter.signed_get(transport, node, &path, request_id, "1700000000000")?;
    let classification = classify_decision(status, &body);
    Ok(ProbeSample {
        role: role.to_owned(),
        decision_status: if status == 200 { "PASS" } else { "BLOCKED" },
        classification,
    })
}

/// Reads the native API envelope: `data.effect` overrides the legacy flat
/// `allowed` field, and unrecognized effects stay unknown rather than defaulting
/// to false.
fn decision_fields(body: &Value) -> (Option<bool>, String) {
    let data = body.get("data").unwrap_or(&Value::Null);
    let mut allowed = body.get("allowed").and_then(Value::as_bool);
    if let Some(effect) = data.get("effect").and_then(Value::as_str) {
        allowed = match effect.to_ascii_uppercase().as_str() {
            "ALLOW" => Some(true),
            "DENY" => Some(false),
            _ => None,
        };
    }
    let reason = [
        data.get("reason").and_then(Value::as_str),
        body.get("reasonCode").and_then(Value::as_str),
        body.get("reason").and_then(Value::as_str),
    ]
    .into_iter()
    .flatten()
    .find(|reason| !reason.is_empty())
    .unwrap_or_default()
    .to_owned();
    (allowed, reason)
}

/// An AUTHORIZATION_PENDING reason outranks every other signal (fail-safe),
/// matching is case-insensitive, and 401/403/503 keep a pending/DENY
/// classification instead of collapsing to UNKNOWN. `decision_status` above
/// stays the transport-level PASS/BLOCKED view, so a non-200 sample still
/// blocks the probe report even when its classification is PENDING or DENY.
pub fn classify_decision(status: u16, body: &Value) -> &'static str {
    let (allowed, reason) = decision_fields(body);
    let pending = reason
        .to_ascii_uppercase()
        .contains("AUTHORIZATION_PENDING");
    match status {
        200 => {
            if pending {
                "PENDING"
            } else if allowed == Some(true) {
                "ALLOW"
            } else if allowed == Some(false)
                || body
                    .get("data")
                    .and_then(|data| data.get("effect"))
                    .and_then(Value::as_str)
                    == Some("NO_MATCH")
            {
                "DENY"
            } else {
                "UNKNOWN"
            }
        }
        401 | 403 => {
            if pending {
                "PENDING"
            } else if allowed == Some(false)
                || body.get("errorType").and_then(Value::as_str) == Some("PERMISSION_DENIED")
            {
                "DENY"
            } else {
                "UNKNOWN"
            }
        }
        503 if pending => "PENDING",
        _ => "UNKNOWN",
    }
}

pub fn sample_snapshot<R: CommandRunner>(
    adapter: &NodeAdapter,
    runner: &mut R,
    queries: &[&str],
) -> Result<usize, crate::node_adapter_contract::RunnerError> {
    let mut rows = 0;
    for query in queries {
        rows += adapter.sql(runner, query)?.len();
    }
    Ok(rows)
}

pub fn worker_ready<T: HttpTransport>(
    adapter: &NodeAdapter,
    transport: &mut T,
    node: &str,
    request_id: &str,
) -> Result<bool, ContractError> {
    let (status, _body, _) = adapter.signed_get(
        transport,
        node,
        "/main/api/v1/health",
        request_id,
        "1700000000000",
    )?;
    Ok(status == 200)
}

pub fn build_probe_report(samples: &[ProbeSample], snapshot_rows: usize, ready: bool) -> Value {
    let blocked = samples
        .iter()
        .any(|sample| sample.decision_status == "BLOCKED");
    let status = if samples.is_empty() || blocked {
        "BLOCKED"
    } else if !ready {
        "UNKNOWN"
    } else {
        "PASS"
    };
    json!({
        "status": status,
        "samples": samples,
        "snapshotRows": snapshot_rows,
        "workerReady": ready,
        "checks": [
            {"check": "actor_aware_decisions", "status": if samples.is_empty() || blocked { "BLOCKED" } else { "PASS" }},
            {"check": "snapshot_read", "status": if snapshot_rows > 0 { "PASS" } else { "UNKNOWN" }},
            {"check": "worker_readiness", "status": if ready { "PASS" } else { "UNKNOWN" }},
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_adapter_contract::{
        CommandPlan, CommandResult, HttpResponse, SignedRequestPlan,
    };
    use serde_json::json;

    fn raw_config() -> Value {
        json!({
            "run_id": "authz-validation-20260919-single-node-002",
            "nodes": {
                "node-a": "http://node-a.example.invalid:8081",
                "node-b": "http://127.0.0.1:8082",
                "node-c": "http://node-c.example.invalid:8083",
            },
            "ssh": {
                "node-a": "ops@node-a.example.invalid",
                "node-c": "ops@node-c.example.invalid",
            },
            "base_dir": "~/authz-validation-20260919-single-node-002",
            "db": "astral_bench",
            "mysql_container": "astral_bench_mysql",
            "hmac_secret_file": "/run/secrets/hmac.txt",
            "mysql_root": "mysql-secret",
            "binary_sha256": "a".repeat(64),
            "source_snapshot_sha256": "b".repeat(64),
            "source_git_rev": "c".repeat(40),
            "source_dirty_patch_sha256": "d".repeat(64),
            "bootstrap_bin_sha256": "e".repeat(64),
            "source_dirty": true,
            "git_rev": "f".repeat(40),
            "ports": {"node-a": 8081, "node-b": 8082, "node-c": 8083},
        })
    }

    fn actor() -> Value {
        json!({
            "user_id": "9031",
            "icard": "9041",
            "card": "9061",
            "domain": "9011",
            "tenant": "9001",
        })
    }

    fn adapter() -> NodeAdapter {
        NodeAdapter::from_raw(&raw_config(), &actor(), b"probe-key".to_vec()).unwrap()
    }

    struct FakeTransport {
        responses: Vec<HttpResponse>,
        calls: Vec<SignedRequestPlan>,
    }

    impl HttpTransport for FakeTransport {
        fn request(
            &mut self,
            plan: &SignedRequestPlan,
        ) -> Result<HttpResponse, crate::node_adapter_contract::RunnerError> {
            self.calls.push(plan.clone());
            Ok(self.responses.remove(0))
        }
    }

    #[derive(Default)]
    struct FakeRunner {
        rows: Vec<Vec<String>>,
    }

    impl CommandRunner for FakeRunner {
        fn run(
            &mut self,
            _plan: &CommandPlan,
        ) -> Result<CommandResult, crate::node_adapter_contract::RunnerError> {
            Ok(CommandResult {
                exit_code: 0,
                stdout: self
                    .rows
                    .iter()
                    .map(|row| row.join("\t"))
                    .collect::<Vec<_>>()
                    .join("\n")
                    + "\n",
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn probe_samples_actor_aware_decisions_and_readiness() {
        let adapter = adapter();
        let mut transport = FakeTransport {
            responses: vec![
                HttpResponse {
                    status: 200,
                    body: r#"{"code":200,"data":{"effect":"ALLOW","reason":"RULE_MATCH"}}"#
                        .to_owned(),
                },
                HttpResponse {
                    status: 200,
                    body:
                        r#"{"code":200,"data":{"effect":"DENY","reason":"AUTHORIZATION_PENDING"}}"#
                            .to_owned(),
                },
                HttpResponse {
                    status: 200,
                    body: "{}".to_owned(),
                },
            ],
            calls: Vec::new(),
        };
        let target = sample_decision(
            &adapter,
            &mut transport,
            "node-a",
            "target",
            "card-target-1",
            "req-target",
        )
        .unwrap();
        let unrelated = sample_decision(
            &adapter,
            &mut transport,
            "node-a",
            "unrelated",
            "card-unrelated-1",
            "req-unrelated",
        )
        .unwrap();
        let ready = worker_ready(&adapter, &mut transport, "node-a", "req-health").unwrap();
        assert_eq!(target.classification, "ALLOW");
        assert_eq!(unrelated.classification, "PENDING");
        assert!(ready);
        let report = build_probe_report(&[target, unrelated], 2, ready);
        assert_eq!(report["status"], "PASS", "{report}");
        assert!(report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|check| check["status"] == "PASS"));
        assert!(transport
            .calls
            .iter()
            .all(|call| call.headers.values["x-user-card-id"] == "9061"));
    }

    #[test]
    fn probe_snapshot_is_select_only_and_counts_rows() {
        let adapter = adapter();
        let mut runner = FakeRunner {
            rows: vec![vec!["1".to_owned()]],
        };
        assert_eq!(
            sample_snapshot(&adapter, &mut runner, &["SELECT 1", "SELECT 2"]).unwrap(),
            2
        );
    }

    #[test]
    fn probe_classification_matches_the_pinned_effect_and_status_matrix() {
        let classify = |status: u16, body: Value| classify_decision(status, &body);
        assert_eq!(
            classify(
                200,
                json!({"data": {"effect": "ALLOW", "reason": "RULE_MATCH"}})
            ),
            "ALLOW"
        );
        assert_eq!(
            classify(
                200,
                json!({"data": {"effect": "DENY", "reason": "NO_MATCH"}})
            ),
            "DENY"
        );
        assert_eq!(
            classify(200, json!({"data": {"effect": "NO_MATCH"}})),
            "DENY"
        );
        assert_eq!(
            classify(200, json!({"data": {"effect": "MAYBE"}})),
            "UNKNOWN"
        );
        // A pending reason outranks the ALLOW effect (fail-safe).
        assert_eq!(
            classify(
                200,
                json!({"data": {"effect": "ALLOW", "reason": "AUTHORIZATION_PENDING"}})
            ),
            "PENDING"
        );
        assert_eq!(classify(200, json!({})), "UNKNOWN");
        assert_eq!(
            classify(
                403,
                json!({"data": {"effect": "DENY", "reason": "PERMISSION_DENIED"}})
            ),
            "DENY"
        );
        assert_eq!(
            classify(403, json!({"errorType": "PERMISSION_DENIED"})),
            "DENY"
        );
        assert_eq!(
            classify(
                403,
                json!({"allowed": false, "reason": "AUTHORIZATION_PENDING"})
            ),
            "PENDING"
        );
        assert_eq!(
            classify(503, json!({"reason": "AUTHORIZATION_PENDING"})),
            "PENDING"
        );
        assert_eq!(classify(503, json!({})), "UNKNOWN");
        // 503 never mints DENY from an allowed=false body; only 401/403 do.
        assert_eq!(classify(503, json!({"allowed": false})), "UNKNOWN");
        assert_eq!(classify(404, json!({"allowed": false})), "UNKNOWN");
    }

    #[test]
    fn pending_reason_outranks_allow_in_probe_samples() {
        let adapter = adapter();
        let mut transport = FakeTransport {
            responses: vec![HttpResponse {
                status: 200,
                body: r#"{"code":200,"data":{"allowed":true,"reason":"AUTHORIZATION_PENDING"}}"#
                    .to_owned(),
            }],
            calls: Vec::new(),
        };
        let sample = sample_decision(
            &adapter,
            &mut transport,
            "node-a",
            "target",
            "card-target-1",
            "req-1",
        )
        .unwrap();
        assert_eq!(sample.classification, "PENDING");
        // Transport-level status still reflects the 200, but the sample must
        // never be reported as ALLOW while the reason says pending.
        assert_ne!(sample.classification, "ALLOW");
    }

    #[test]
    fn blocked_decision_or_missing_readiness_cannot_pass() {
        let adapter = adapter();
        let mut transport = FakeTransport {
            responses: vec![HttpResponse {
                status: 403,
                body: r#"{"code":403,"message":"DENIED"}"#.to_owned(),
            }],
            calls: Vec::new(),
        };
        let blocked = sample_decision(
            &adapter,
            &mut transport,
            "node-a",
            "target",
            "card-target-1",
            "req-1",
        )
        .unwrap();
        assert_eq!(blocked.decision_status, "BLOCKED");
        assert_eq!(build_probe_report(&[blocked], 1, true)["status"], "BLOCKED");

        let allowed = ProbeSample {
            role: "target".to_owned(),
            decision_status: "PASS",
            classification: "ALLOW",
        };
        assert_eq!(
            build_probe_report(&[allowed], 1, false)["status"],
            "UNKNOWN"
        );
    }

    #[test]
    fn probe_report_does_not_include_hosts_or_secrets() {
        let report = build_probe_report(
            &[ProbeSample {
                role: "target".to_owned(),
                decision_status: "PASS",
                classification: "ALLOW",
            }],
            1,
            true,
        );
        let text = report.to_string();
        assert!(!text.contains("example.invalid"));
        assert!(!text.contains("mysql-secret"));
    }
}
