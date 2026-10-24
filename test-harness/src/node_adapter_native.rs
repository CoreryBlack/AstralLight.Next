//! Native NodeAdapter runtime composed over injected CommandRunner and
//! HttpTransport ports. It executes SQL/Redis/log-slice commands and signed
//! GETs without opening sockets, SSH or subprocesses itself.

use crate::e3_e4_events::{
    events_for_request, parse_e1_events, validate_request_terminal, ReaderClassification,
};
use crate::node_adapter_contract::{
    actor_from_mapping, execute_log_slice_with_detail, execute_redis_with_detail,
    execute_signed_request, execute_sql_with_detail, Actor, CommandRunner, ContractError,
    HttpTransport, NodeAdapterConfig, RunnerError, SignedRequestSpec,
};
use serde_json::Value;
use std::fmt;

pub struct NodeAdapter {
    config: NodeAdapterConfig,
    actor: Actor,
    key: Vec<u8>,
}

impl fmt::Debug for NodeAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodeAdapter")
            .field("config", &self.config)
            .field("actor", &self.actor)
            .finish_non_exhaustive()
    }
}

impl NodeAdapter {
    pub fn new(
        config: NodeAdapterConfig,
        actor: Actor,
        key: Vec<u8>,
    ) -> Result<Self, ContractError> {
        actor.validate()?;
        if key.is_empty() {
            return Err(ContractError {
                kind: "invalid_signing_key",
                problems: vec!["invalid_signing_key"],
            });
        }
        Ok(Self { config, actor, key })
    }

    pub fn from_raw(config: &Value, actor: &Value, key: Vec<u8>) -> Result<Self, ContractError> {
        Self::new(
            crate::node_adapter_contract::load_config(config)?,
            actor_from_mapping(actor)?,
            key,
        )
    }

    pub fn sql<R: CommandRunner>(
        &self,
        runner: &mut R,
        query: &str,
    ) -> Result<Vec<Vec<String>>, RunnerError> {
        execute_sql_with_detail(&self.config, runner, query, 60_000)
    }

    pub fn redis<R: CommandRunner>(
        &self,
        runner: &mut R,
        verb: &str,
        args: &[&str],
    ) -> Result<String, RunnerError> {
        execute_redis_with_detail(&self.config, runner, verb, args, 30_000)
    }

    pub fn read_log_lines<R: CommandRunner>(
        &self,
        runner: &mut R,
        node: &str,
        identifiers: &[&str],
        home_dir: &str,
    ) -> Result<Vec<String>, RunnerError> {
        execute_log_slice_with_detail(&self.config, runner, node, identifiers, home_dir, 120_000)
    }

    pub fn signed_get<T: HttpTransport>(
        &self,
        transport: &mut T,
        node: &str,
        path: &str,
        request_id: &str,
        timestamp_ms: &str,
    ) -> Result<(u16, Value, String), ContractError> {
        execute_signed_request(
            &self.config,
            transport,
            SignedRequestSpec {
                actor: &self.actor,
                node,
                method: "GET",
                path,
                body: None,
                request_id,
                timestamp_ms,
                key: &self.key,
                timeout_ms: 30_000,
            },
        )
    }

    pub fn request_terminal(
        &self,
        lines: &[String],
        node: &str,
        request_id: &str,
        http_status: u16,
    ) -> Result<ReaderClassification, String> {
        let events = parse_e1_events(lines.iter().map(String::as_str), node)?;
        let selected = events_for_request(&events, request_id);
        validate_request_terminal(&selected, http_status).map_err(str::to_owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_adapter_contract::{
        CommandPlan, CommandResult, HttpResponse, SignedRequestPlan,
    };
    use serde_json::json;

    const MYSQL_SECRET: &str = "mysql-root-secret-xyzzy";
    const REDIS_SECRET: &str = "redis-pass-secret-abcdef";
    const SIGNING_KEY: &[u8] = b"super-secret-signing-key";

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
            "redis_container": "astral_bench_redis",
            "hmac_secret_file": "/run/secrets/hmac.txt",
            "mysql_root": MYSQL_SECRET,
            "redis_password": REDIS_SECRET,
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
        NodeAdapter::from_raw(&raw_config(), &actor(), SIGNING_KEY.to_vec()).unwrap()
    }

    #[derive(Default)]
    struct FakeRunner {
        calls: Vec<CommandPlan>,
        results: Vec<CommandResult>,
    }

    impl CommandRunner for FakeRunner {
        fn run(&mut self, plan: &CommandPlan) -> Result<CommandResult, RunnerError> {
            self.calls.push(plan.clone());
            if self.results.is_empty() {
                Ok(CommandResult {
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            } else {
                Ok(self.results.remove(0))
            }
        }
    }

    struct FakeTransport {
        calls: Vec<SignedRequestPlan>,
        response: HttpResponse,
    }

    impl HttpTransport for FakeTransport {
        fn request(&mut self, plan: &SignedRequestPlan) -> Result<HttpResponse, RunnerError> {
            self.calls.push(plan.clone());
            Ok(self.response.clone())
        }
    }

    #[test]
    fn sql_redis_and_log_slice_use_injected_fixed_commands() {
        let adapter = adapter();
        let mut runner = FakeRunner {
            calls: Vec::new(),
            results: vec![
                CommandResult {
                    exit_code: 0,
                    stdout: "a\tb\n".to_owned(),
                    stderr: String::new(),
                },
                CommandResult {
                    exit_code: 0,
                    stdout: "PONG\n".to_owned(),
                    stderr: String::new(),
                },
                CommandResult {
                    exit_code: 0,
                    stdout: "line1\nline2\n".to_owned(),
                    stderr: String::new(),
                },
            ],
        };
        assert_eq!(
            adapter.sql(&mut runner, "SELECT a, b FROM t").unwrap(),
            vec![vec!["a".to_owned(), "b".to_owned()]]
        );
        assert_eq!(adapter.redis(&mut runner, "PING", &[]).unwrap(), "PONG");
        assert_eq!(
            adapter
                .read_log_lines(&mut runner, "node-a", &["req-1"], "/home/ops")
                .unwrap(),
            ["line1".to_owned(), "line2".to_owned()]
        );
        assert_eq!(runner.calls.len(), 3);
        assert_eq!(runner.calls[0].argv[0], "docker");
        assert!(runner.calls[0].stdin_is(MYSQL_SECRET));
        assert_eq!(runner.calls[1].argv[0], "docker");
        assert!(runner.calls[1].stdin_is(REDIS_SECRET));
        assert_eq!(runner.calls[2].argv[0], "ssh");
        assert!(runner.calls[2].stdin_is(crate::node_adapter_contract::LOG_GREP_SCRIPT));
    }

    #[test]
    fn signed_get_uses_actor_signature_and_parses_envelope() {
        let adapter = adapter();
        let mut transport = FakeTransport {
            calls: Vec::new(),
            response: HttpResponse {
                status: 200,
                body: r#"{"code":200,"message":"ok","data":{"allowed":true}}"#.to_owned(),
            },
        };
        let (status, body, request_id) = adapter
            .signed_get(
                &mut transport,
                "node-a",
                "/main/api/v1/permission-rules/check?cardId=9061&card_id=9061",
                "req-1",
                "1700000000000",
            )
            .unwrap();
        assert_eq!(status, 200);
        assert_eq!(request_id, "req-1");
        assert_eq!(body["data"]["allowed"], true);
        assert_eq!(transport.calls.len(), 1);
        let headers = &transport.calls[0].headers.values;
        assert_eq!(headers["x-user-card-id"], "9061");
        assert_eq!(headers["x-gateway-auth"], "verified");
        assert!(headers.contains_key("x-gateway-signature"));
    }

    #[test]
    fn request_terminal_classification_uses_injected_lines() {
        let adapter = adapter();
        let pending = vec![json!({
            "message": "e1 authorization observation",
            "event": "decision_return",
            "request_id": "req-1",
            "event_sequence": 1,
            "wall_unix_ns": 1_758_000_000_000_000_001u64,
            "process_observation_id": "proc-a",
            "allowed": false,
            "reason": "AUTHORIZATION_PENDING",
        })
        .to_string()];
        assert_eq!(
            adapter
                .request_terminal(&pending, "node-a", "req-1", 503)
                .unwrap()
                .decision,
            "PENDING"
        );

        let allowed = vec![
            json!({
                "message": "e1 authorization observation",
                "event": "decision_return",
                "request_id": "req-2",
                "event_sequence": 1,
                "wall_unix_ns": 1_758_000_000_000_000_002u64,
                "process_observation_id": "proc-a",
                "allowed": true,
                "reason": "RULE_MATCH",
            })
            .to_string(),
            json!({
                "message": "e1 authorization observation",
                "event": "host_admission",
                "request_id": "req-2",
                "event_sequence": 2,
                "wall_unix_ns": 1_758_000_000_000_000_003u64,
                "process_observation_id": "proc-a",
            })
            .to_string(),
        ];
        assert_eq!(
            adapter
                .request_terminal(&allowed, "node-a", "req-2", 200)
                .unwrap()
                .decision,
            "ALLOW"
        );
        assert!(adapter
            .request_terminal(&allowed, "node-a", "req-2", 403)
            .is_err());
    }

    #[test]
    fn missing_mysql_root_fails_before_runner() {
        let mut raw = raw_config();
        raw.as_object_mut().unwrap().remove("mysql_root");
        let adapter = NodeAdapter::from_raw(&raw, &actor(), SIGNING_KEY.to_vec()).unwrap();
        let mut runner = FakeRunner::default();
        assert_eq!(
            adapter.sql(&mut runner, "SELECT 1").unwrap_err().kind,
            "mysql_root_missing"
        );
        assert!(runner.calls.is_empty());
    }

    #[test]
    fn adapter_debug_does_not_reveal_signing_key_or_secrets() {
        let adapter = adapter();
        let text = format!("{adapter:?}");
        assert!(text.contains("NodeAdapter"));
        assert!(!text.contains("super-secret-signing-key"));
        assert!(!text.contains(MYSQL_SECRET));
        assert!(!text.contains(REDIS_SECRET));
    }
}
