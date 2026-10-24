use hmac::{Hmac, Mac};
use regex::Regex;
use serde_json::{Map, Value};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::OnceLock;

pub const GATEWAY_V3_PREFIX: &str = "astral-gateway-v3";
pub const PRINCIPAL_KIND_PLATFORM_USER: &str = "PLATFORM_USER";
pub const GATEWAY_AUTH_VERIFIED: &str = "verified";
pub const GATEWAY_PATH_PREFIX: &str = "/main/api/v1/";
pub const NODE_ALIASES: [&str; 3] = ["node-a", "node-b", "node-c"];
pub const SIGNED_HTTP_METHODS: [&str; 4] = ["GET", "POST", "PUT", "DELETE"];
pub const READONLY_REDIS_VERBS: [&str; 3] = ["GET", "LLEN", "PING"];
pub const MYSQL_STDIN_SCRIPT: &str = "MYSQL_PWD=\"$(cat)\" exec mysql -uroot -N -e \"$2\" \"$1\"";
pub const REDIS_STDIN_SCRIPT: &str = "REDISCLI_AUTH=\"$(cat)\" exec redis-cli \"$@\"";

const LOG_FILES: [&str; 3] = ["server_a.log", "server_b.log", "server_c.log"];
pub const LOG_GREP_SCRIPT: &str = r#"import base64, binascii, json, re, sys

_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


def main(argv):
    if len(argv) != 4:
        raise SystemExit(2)
    base, name, payload = argv[1], argv[2], argv[3]
    # The argv payload is base64(json(identifiers)) -- encoded by read_log_lines
    # so the identifier list never rides as raw shell-visible JSON.
    try:
        identifiers = json.loads(base64.b64decode(payload, validate=True))
    except (binascii.Error, ValueError, json.JSONDecodeError):
        raise SystemExit(2)
    if not isinstance(identifiers, list) or not identifiers:
        raise SystemExit(2)
    for item in identifiers:
        if not isinstance(item, str) or not _SAFE_ID.fullmatch(item):
            raise SystemExit(2)
    path = base.rstrip("/") + "/" + name
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if any(item in line for item in identifiers):
                sys.stdout.write(line)


main(sys.argv)
"#;
#[cfg(test)]
const MAX_SIGNED_I64: i64 = i64::MAX;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractError {
    pub kind: &'static str,
    pub problems: Vec<&'static str>,
}

impl ContractError {
    fn one(kind: &'static str) -> Self {
        Self {
            kind,
            problems: vec![kind],
        }
    }
}

#[derive(Clone)]
pub struct NodeAdapterConfig {
    run_id: String,
    binary_sha256: String,
    source_snapshot_sha256: String,
    source_git_rev: String,
    source_dirty_patch_sha256: String,
    bootstrap_bin_sha256: String,
    source_dirty: Option<bool>,
    nodes: BTreeMap<String, String>,
    ssh: BTreeMap<String, String>,
    base_dir: String,
    db: String,
    mysql_container: String,
    redis_container: String,
    hmac_secret_file: String,
    ports: BTreeMap<String, u16>,
    git_rev: Option<String>,
    redis_port: Option<u16>,
    mysql_root: Option<String>,
    redis_password: Option<String>,
}

impl fmt::Debug for NodeAdapterConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NodeAdapterConfig")
            .field("public_metadata", &self.public_metadata())
            .finish()
    }
}

impl NodeAdapterConfig {
    pub fn public_metadata(&self) -> Value {
        Value::Object(Map::from_iter([
            ("runId".to_owned(), Value::String(self.run_id.clone())),
            (
                "binarySha256".to_owned(),
                Value::String(self.binary_sha256.clone()),
            ),
            (
                "sourceSnapshotSha256".to_owned(),
                Value::String(self.source_snapshot_sha256.clone()),
            ),
            (
                "sourceGitRev".to_owned(),
                Value::String(self.source_git_rev.clone()),
            ),
            (
                "sourceDirty".to_owned(),
                self.source_dirty.map(Value::Bool).unwrap_or(Value::Null),
            ),
            (
                "sourceDirtyPatchSha256".to_owned(),
                Value::String(self.source_dirty_patch_sha256.clone()),
            ),
            (
                "bootstrapBinSha256".to_owned(),
                Value::String(self.bootstrap_bin_sha256.clone()),
            ),
            (
                "nodeLabels".to_owned(),
                Value::Array(
                    NODE_ALIASES
                        .iter()
                        .map(|alias| Value::String((*alias).to_owned()))
                        .collect(),
                ),
            ),
        ]))
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn mysql_root_present(&self) -> bool {
        self.mysql_root.is_some()
    }

    pub fn redis_password_present(&self) -> bool {
        self.redis_password.is_some()
    }

    pub fn private_config_is_stored_but_not_published(&self) -> bool {
        !self.hmac_secret_file.is_empty()
            && !self.mysql_container.is_empty()
            && !self.redis_container.is_empty()
            && !self.ports.is_empty()
            && self.git_rev.as_ref().is_none_or(|value| !value.is_empty())
            && self.redis_port.is_none_or(|value| value > 0)
    }
}

fn safe_id(value: &str, max_len: usize) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= max_len
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(byte))
}

fn safe_operation_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(byte))
}

fn hash64(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|value| {
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn safe_base_dir(value: &str) -> bool {
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return false;
    }
    let path = value.strip_prefix('~').unwrap_or(value);
    if path.contains("..") {
        return false;
    }
    path.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"._-/".contains(&byte))
}

fn valid_url_shape(value: &str) -> bool {
    (value.starts_with("http://") || value.starts_with("https://"))
        && !value.ends_with('/')
        && !value.contains('?')
        && !value.chars().any(char::is_whitespace)
}

fn container_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(byte))
}

fn add_problem(problems: &mut Vec<&'static str>, valid: bool, problem: &'static str) {
    if !valid {
        problems.push(problem);
    }
}

pub fn load_config(raw: &Value) -> Result<NodeAdapterConfig, ContractError> {
    let Some(raw) = raw.as_object() else {
        return Err(ContractError::one("config_not_a_mapping"));
    };
    let required = [
        "run_id",
        "nodes",
        "ssh",
        "base_dir",
        "db",
        "mysql_container",
        "redis_container",
        "hmac_secret_file",
        "binary_sha256",
        "source_snapshot_sha256",
        "source_git_rev",
        "source_dirty_patch_sha256",
        "bootstrap_bin_sha256",
    ];
    let mut problems = Vec::new();
    for name in required {
        if !raw.contains_key(name) {
            problems.push("missing_required_field");
        }
    }

    let run_id = raw
        .get("run_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    add_problem(&mut problems, safe_id(run_id, 128), "invalid_run_id");
    for field in [
        "binary_sha256",
        "source_snapshot_sha256",
        "source_dirty_patch_sha256",
        "bootstrap_bin_sha256",
    ] {
        add_problem(&mut problems, hash64(raw.get(field)), "invalid_sha256");
    }
    let source_git_rev = raw
        .get("source_git_rev")
        .and_then(Value::as_str)
        .unwrap_or_default();
    add_problem(
        &mut problems,
        source_git_rev.len() == 40 && source_git_rev.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid_source_git_rev",
    );

    let nodes_obj = raw.get("nodes").and_then(Value::as_object);
    let node_keys_valid = nodes_obj.is_some_and(|nodes| {
        nodes.len() == NODE_ALIASES.len()
            && NODE_ALIASES.iter().all(|alias| {
                nodes
                    .get(*alias)
                    .and_then(Value::as_str)
                    .is_some_and(valid_url_shape)
            })
    });
    add_problem(&mut problems, node_keys_valid, "invalid_nodes");

    let ssh_obj = raw.get("ssh").and_then(Value::as_object);
    let ssh_valid = ssh_obj.is_some_and(|ssh| {
        ["node-a", "node-c"].iter().all(|alias| {
            ssh.get(*alias)
                .and_then(Value::as_str)
                .is_some_and(|target| {
                    !target.is_empty() && !target.chars().any(char::is_whitespace)
                })
        })
    });
    add_problem(&mut problems, ssh_valid, "invalid_ssh");

    let base_dir = raw
        .get("base_dir")
        .and_then(Value::as_str)
        .unwrap_or_default();
    add_problem(&mut problems, safe_base_dir(base_dir), "invalid_base_dir");
    let db = raw.get("db").and_then(Value::as_str).unwrap_or_default();
    add_problem(
        &mut problems,
        !db.is_empty()
            && db.len() <= 64
            && db
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
        "invalid_database_name",
    );
    let mysql_container = raw
        .get("mysql_container")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let redis_container = raw
        .get("redis_container")
        .and_then(Value::as_str)
        .unwrap_or_default();
    add_problem(
        &mut problems,
        container_name(mysql_container),
        "invalid_mysql_container",
    );
    add_problem(
        &mut problems,
        container_name(redis_container),
        "invalid_redis_container",
    );
    let hmac_secret_file = raw
        .get("hmac_secret_file")
        .and_then(Value::as_str)
        .unwrap_or_default();
    add_problem(
        &mut problems,
        !hmac_secret_file.is_empty() && !hmac_secret_file.chars().any(char::is_whitespace),
        "invalid_hmac_secret_path",
    );

    let ports_obj = raw.get("ports").and_then(Value::as_object);
    if let Some(ports) = ports_obj {
        let ports_valid = ports.len() == NODE_ALIASES.len()
            && NODE_ALIASES.iter().all(|alias| {
                ports
                    .get(*alias)
                    .and_then(Value::as_u64)
                    .is_some_and(|port| (1..=65535).contains(&port))
            });
        add_problem(&mut problems, ports_valid, "invalid_ports");
    } else if raw.contains_key("ports") {
        problems.push("invalid_ports");
    }
    for (field, problem) in [
        ("mysql_root", "invalid_mysql_root"),
        ("redis_password", "invalid_redis_password"),
    ] {
        if let Some(value) = raw.get(field) {
            add_problem(
                &mut problems,
                value.as_str().is_some_and(|secret| !secret.is_empty()),
                problem,
            );
        }
    }
    if let Some(git_rev) = raw.get("git_rev") {
        add_problem(
            &mut problems,
            git_rev.as_str().is_some_and(|value| {
                value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
            }),
            "invalid_git_rev",
        );
    }
    if let Some(redis_port) = raw.get("redis_port") {
        add_problem(
            &mut problems,
            redis_port
                .as_u64()
                .is_some_and(|port| (1..=65535).contains(&port)),
            "invalid_redis_port",
        );
    }
    if problems.is_empty() {
        let nodes = nodes_obj.expect("validated node mapping");
        let ssh = ssh_obj.expect("validated SSH mapping");
        let ports = ports_obj;
        Ok(NodeAdapterConfig {
            run_id: run_id.to_owned(),
            binary_sha256: raw["binary_sha256"].as_str().unwrap().to_ascii_lowercase(),
            source_snapshot_sha256: raw["source_snapshot_sha256"]
                .as_str()
                .unwrap()
                .to_ascii_lowercase(),
            source_git_rev: source_git_rev.to_owned(),
            source_dirty_patch_sha256: raw["source_dirty_patch_sha256"]
                .as_str()
                .unwrap()
                .to_ascii_lowercase(),
            bootstrap_bin_sha256: raw["bootstrap_bin_sha256"]
                .as_str()
                .unwrap()
                .to_ascii_lowercase(),
            source_dirty: raw.get("source_dirty").and_then(Value::as_bool),
            nodes: nodes
                .iter()
                .map(|(alias, url)| (alias.clone(), url.as_str().unwrap().to_owned()))
                .collect(),
            ssh: ssh
                .iter()
                .filter_map(|(alias, target)| {
                    target
                        .as_str()
                        .map(|target| (alias.clone(), target.to_owned()))
                })
                .collect(),
            base_dir: base_dir.to_owned(),
            db: db.to_owned(),
            mysql_container: mysql_container.to_owned(),
            redis_container: redis_container.to_owned(),
            hmac_secret_file: hmac_secret_file.to_owned(),
            ports: ports
                .map(|ports| {
                    ports
                        .iter()
                        .map(|(alias, port)| {
                            (
                                alias.clone(),
                                u16::try_from(port.as_u64().unwrap()).unwrap(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default(),
            git_rev: raw
                .get("git_rev")
                .and_then(Value::as_str)
                .map(str::to_owned),
            redis_port: raw
                .get("redis_port")
                .and_then(Value::as_u64)
                .map(|port| u16::try_from(port).unwrap()),
            mysql_root: raw
                .get("mysql_root")
                .and_then(Value::as_str)
                .map(str::to_owned),
            redis_password: raw
                .get("redis_password")
                .and_then(Value::as_str)
                .map(str::to_owned),
        })
    } else {
        problems.sort_unstable();
        problems.dedup();
        Err(ContractError {
            kind: "invalid_config",
            problems,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Actor {
    pub user_id: String,
    pub identity_card: String,
    pub user_card: String,
    pub domain: String,
    pub tenant: String,
}

impl Actor {
    pub fn validate(&self) -> Result<(), ContractError> {
        let values = [
            (&self.user_id, "invalid_user_id"),
            (&self.identity_card, "invalid_identity_card"),
            (&self.user_card, "invalid_user_card"),
            (&self.domain, "invalid_domain"),
            (&self.tenant, "invalid_tenant"),
        ];
        for (value, kind) in values {
            if value.is_empty()
                || value.len() > 256
                || value.trim() != value
                || value.chars().any(|char| matches!(char, '\n' | '\r' | '\t'))
            {
                return Err(ContractError::one(kind));
            }
        }
        Ok(())
    }
}

pub fn actor_from_mapping(raw: &Value) -> Result<Actor, ContractError> {
    let Some(raw) = raw.as_object() else {
        return Err(ContractError::one("actor_not_a_mapping"));
    };
    let pick = |primary: &str, alias: Option<&str>| {
        raw.get(primary)
            .filter(|value| !value.is_null())
            .or_else(|| alias.and_then(|alias| raw.get(alias).filter(|value| !value.is_null())))
    };
    let string = |value: Option<&Value>| {
        value.and_then(|value| match value {
            Value::String(value) => Some(value.clone()),
            Value::Number(value) => Some(value.to_string()),
            _ => None,
        })
    };
    let actor = Actor {
        user_id: string(pick("user_id", None)).unwrap_or_default(),
        identity_card: string(pick("identity_card", Some("icard"))).unwrap_or_default(),
        user_card: string(pick("user_card", Some("card"))).unwrap_or_default(),
        domain: string(pick("domain", None)).unwrap_or_default(),
        tenant: string(pick("tenant", None)).unwrap_or_default(),
    };
    actor.validate()?;
    Ok(actor)
}

pub fn build_gateway_v3_payload(
    actor: &Actor,
    method: &str,
    path: &str,
    timestamp_ms: &str,
) -> String {
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    [
        GATEWAY_V3_PREFIX,
        method.trim(),
        path,
        &actor.user_id,
        PRINCIPAL_KIND_PLATFORM_USER,
        "",
        &actor.identity_card,
        &actor.user_card,
        &actor.domain,
        &actor.tenant,
        "",
        "",
        "",
        "",
        timestamp_ms,
    ]
    .join("\n")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedHeaders {
    pub values: BTreeMap<String, String>,
}

pub fn sign_headers(
    actor: &Actor,
    method: &str,
    path: &str,
    request_id: &str,
    timestamp_ms: &str,
    key: &[u8],
) -> Result<SignedHeaders, ContractError> {
    actor.validate()?;
    if method.trim().is_empty() || !method.trim().bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return Err(ContractError::one("invalid_method"));
    }
    if !path.starts_with('/') || path.chars().any(char::is_whitespace) {
        return Err(ContractError::one("invalid_path"));
    }
    if !safe_operation_id(request_id) {
        return Err(ContractError::one("invalid_request_id"));
    }
    if key.is_empty()
        || timestamp_ms.is_empty()
        || !timestamp_ms.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(ContractError::one("invalid_signing_input"));
    }
    let method = method.trim();
    let payload = build_gateway_v3_payload(actor, method, path, timestamp_ms);
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| ContractError::one("invalid_signing_key"))?;
    mac.update(payload.as_bytes());
    let signature = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let values = [
        ("x-request-id", request_id.to_owned()),
        ("x-user-id", actor.user_id.clone()),
        ("x-principal-kind", PRINCIPAL_KIND_PLATFORM_USER.to_owned()),
        ("x-identity-card-id", actor.identity_card.clone()),
        ("x-user-card-id", actor.user_card.clone()),
        ("x-user-card-domain-id", actor.domain.clone()),
        ("x-user-card-tenant-id", actor.tenant.clone()),
        ("x-gateway-ts", timestamp_ms.to_owned()),
        ("x-gateway-signature", signature),
        ("x-gateway-auth", GATEWAY_AUTH_VERIFIED.to_owned()),
        ("Content-Type", "application/json".to_owned()),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value))
    .collect();
    Ok(SignedHeaders { values })
}

#[derive(Clone, Eq, PartialEq)]
pub struct CommandPlan {
    pub argv: Vec<String>,
    stdin: String,
    pub timeout_ms: u64,
}

impl fmt::Debug for CommandPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandPlan")
            .field("argv", &self.argv)
            .field("stdin", &"[redacted]")
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

impl CommandPlan {
    pub fn stdin_is(&self, value: &str) -> bool {
        self.stdin == value
    }
}

pub fn require_select_only(query: &str) -> Result<(), ContractError> {
    if query.trim().is_empty() {
        return Err(ContractError::one("empty_sql"));
    }
    let stripped = line_comment_regex().replace_all(query, " ");
    let stripped = block_comment_regex().replace_all(&stripped, " ");
    let stripped = stripped.trim();
    if !stripped
        .get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("SELECT"))
    {
        return Err(ContractError::one("select_only_required"));
    }
    let body = stripped.strip_suffix(';').unwrap_or(stripped);
    if body.contains(';') {
        return Err(ContractError::one("multiple_sql_statements"));
    }
    let upper = body.to_ascii_uppercase();
    if forbidden_sql_regex().is_match(&upper) {
        return Err(ContractError::one("unsafe_select_statement"));
    }
    Ok(())
}

fn line_comment_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"--[^\n]*|#[^\n]*").expect("constant SQL comment regex"))
}

fn block_comment_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?s)/\*.*?\*/").expect("constant SQL comment regex"))
}

fn forbidden_sql_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"\bINTO\s+(?:OUTFILE|DUMPFILE)\b|\bFOR\s+(?:UPDATE|SHARE)\b|\bLOCK\s+IN\s+SHARE\s+MODE\b|\b(?:GET_LOCK|RELEASE_LOCK)\s*\(",
        )
        .expect("constant SQL safety regex")
    })
}

pub fn build_sql_command(
    config: &NodeAdapterConfig,
    query: &str,
    timeout_ms: u64,
) -> Result<CommandPlan, ContractError> {
    require_select_only(query)?;
    let password = config
        .mysql_root
        .as_ref()
        .ok_or_else(|| ContractError::one("mysql_root_missing"))?;
    Ok(CommandPlan {
        argv: vec![
            "docker".to_owned(),
            "exec".to_owned(),
            "-i".to_owned(),
            config.mysql_container.clone(),
            "sh".to_owned(),
            "-c".to_owned(),
            MYSQL_STDIN_SCRIPT.to_owned(),
            "sh".to_owned(),
            config.db.clone(),
            query.to_owned(),
        ],
        stdin: password.clone(),
        timeout_ms,
    })
}

pub fn parse_tsv(stdout: &str) -> Vec<Vec<String>> {
    stdout
        .replace("\r\n", "\n")
        .split('\n')
        .filter(|line| !line.is_empty())
        .map(|line| line.split('\t').map(str::to_owned).collect())
        .collect()
}

fn redis_key_is_safe(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 512
        && key.as_bytes()[0].is_ascii_alphanumeric()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:+*-".contains(&byte))
}

pub fn build_redis_command(
    config: &NodeAdapterConfig,
    verb: &str,
    args: &[&str],
    timeout_ms: u64,
) -> Result<CommandPlan, ContractError> {
    let verb = verb.to_ascii_uppercase();
    if !READONLY_REDIS_VERBS.contains(&verb.as_str()) {
        return Err(ContractError::one("redis_verb_not_allowlisted"));
    }
    match verb.as_str() {
        "PING" if !args.is_empty() => return Err(ContractError::one("redis_ping_arity")),
        "GET" | "LLEN" if args.len() != 1 => {
            return Err(ContractError::one("redis_key_arity"));
        }
        _ => {}
    }
    if args.len() == 1 && !redis_key_is_safe(args[0]) {
        return Err(ContractError::one("invalid_redis_key"));
    }
    let password = config
        .redis_password
        .as_ref()
        .ok_or_else(|| ContractError::one("redis_password_missing"))?;
    let mut argv = vec![
        "docker".to_owned(),
        "exec".to_owned(),
        "-i".to_owned(),
        config.redis_container.clone(),
        "sh".to_owned(),
        "-c".to_owned(),
        REDIS_STDIN_SCRIPT.to_owned(),
        "sh".to_owned(),
        verb,
    ];
    argv.extend(args.iter().map(|value| (*value).to_owned()));
    Ok(CommandPlan {
        argv,
        stdin: password.clone(),
        timeout_ms,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunnerError {
    pub kind: &'static str,
    pub detail: String,
}

pub trait CommandRunner {
    fn run(&mut self, plan: &CommandPlan) -> Result<CommandResult, RunnerError>;
}

pub fn execute_sql<R: CommandRunner>(
    config: &NodeAdapterConfig,
    runner: &mut R,
    query: &str,
    timeout_ms: u64,
) -> Result<Vec<Vec<String>>, ContractError> {
    let plan = build_sql_command(config, query, timeout_ms)?;
    let result = runner
        .run(&plan)
        .map_err(|error| ContractError::one(error.kind))?;
    if result.exit_code != 0 {
        return Err(ContractError::one("sql_failed"));
    }
    Ok(parse_tsv(&result.stdout))
}

pub fn execute_redis<R: CommandRunner>(
    config: &NodeAdapterConfig,
    runner: &mut R,
    verb: &str,
    args: &[&str],
    timeout_ms: u64,
) -> Result<String, ContractError> {
    let plan = build_redis_command(config, verb, args, timeout_ms)?;
    let result = runner
        .run(&plan)
        .map_err(|error| ContractError::one(error.kind))?;
    if result.exit_code != 0 {
        return Err(ContractError::one("redis_failed"));
    }
    Ok(result.stdout.trim().to_owned())
}

pub fn load_hmac_secret(path: &str) -> Result<Vec<u8>, ContractError> {
    let bytes = std::fs::read(path).map_err(|_| ContractError::one("hmac_secret_unreadable"))?;
    let text =
        String::from_utf8(bytes).map_err(|_| ContractError::one("hmac_secret_unreadable"))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(ContractError::one("hmac_secret_empty"));
    }
    Ok(trimmed.as_bytes().to_vec())
}

pub fn execute_sql_with_detail<R: CommandRunner>(
    config: &NodeAdapterConfig,
    runner: &mut R,
    query: &str,
    timeout_ms: u64,
) -> Result<Vec<Vec<String>>, RunnerError> {
    let plan = build_sql_command(config, query, timeout_ms).map_err(|error| RunnerError {
        kind: error.kind,
        detail: String::new(),
    })?;
    let result = runner.run(&plan).map_err(|mut error| {
        error.detail = scrub_text(&error.detail, 300);
        error
    })?;
    if result.exit_code != 0 {
        return Err(RunnerError {
            kind: "sql_failed",
            detail: scrub_text(&result.stderr, 300),
        });
    }
    Ok(parse_tsv(&result.stdout))
}

pub fn execute_redis_with_detail<R: CommandRunner>(
    config: &NodeAdapterConfig,
    runner: &mut R,
    verb: &str,
    args: &[&str],
    timeout_ms: u64,
) -> Result<String, RunnerError> {
    let plan =
        build_redis_command(config, verb, args, timeout_ms).map_err(|error| RunnerError {
            kind: error.kind,
            detail: String::new(),
        })?;
    let result = runner.run(&plan).map_err(|mut error| {
        error.detail = scrub_text(&error.detail, 300);
        error
    })?;
    if result.exit_code != 0 {
        return Err(RunnerError {
            kind: "redis_failed",
            detail: scrub_text(&result.stderr, 300),
        });
    }
    Ok(result.stdout.trim().to_owned())
}

pub fn execute_log_slice_with_detail<R: CommandRunner>(
    config: &NodeAdapterConfig,
    runner: &mut R,
    node: &str,
    identifiers: &[&str],
    home_dir: &str,
    timeout_ms: u64,
) -> Result<Vec<String>, RunnerError> {
    let plan = build_log_slice_command(config, node, identifiers, home_dir, timeout_ms).map_err(
        |error| RunnerError {
            kind: error.kind,
            detail: String::new(),
        },
    )?;
    let Some(plan) = plan else {
        return Ok(Vec::new());
    };
    let result = runner.run(&plan).map_err(|mut error| {
        error.detail = scrub_text(&error.detail, 300);
        error
    })?;
    if result.exit_code != 0 {
        return Err(RunnerError {
            kind: "log_slice_failed",
            detail: scrub_text(&result.stderr, 300),
        });
    }
    Ok(result.stdout.lines().map(str::to_owned).collect())
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DisabledSubprocessRunner;

impl DisabledSubprocessRunner {
    pub fn run(&self, _plan: &CommandPlan) -> Result<CommandResult, RunnerError> {
        Err(RunnerError {
            kind: "subprocess_execution_not_enabled",
            detail: String::new(),
        })
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SignedRequestPlan {
    pub method: String,
    pub url: String,
    pub headers: SignedHeaders,
    pub body: Option<Vec<u8>>,
    pub timeout_ms: u64,
}

impl fmt::Debug for SignedRequestPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedRequestPlan")
            .field("method", &self.method)
            .field("url", &"[redacted-host]")
            .field("headers", &self.headers)
            .field("body", &self.body.as_ref().map(|_| "[redacted]"))
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

pub struct SignedRequestSpec<'a> {
    pub actor: &'a Actor,
    pub node: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub body: Option<&'a Value>,
    pub request_id: &'a str,
    pub timestamp_ms: &'a str,
    pub key: &'a [u8],
    pub timeout_ms: u64,
}

pub fn build_signed_request(
    config: &NodeAdapterConfig,
    request: SignedRequestSpec<'_>,
) -> Result<SignedRequestPlan, ContractError> {
    if !NODE_ALIASES.contains(&request.node) {
        return Err(ContractError::one("invalid_node_alias"));
    }
    let method = request.method.trim().to_ascii_uppercase();
    if !SIGNED_HTTP_METHODS.contains(&method.as_str()) {
        return Err(ContractError::one("signed_http_method_not_allowlisted"));
    }
    if !request.path.starts_with(GATEWAY_PATH_PREFIX)
        || request.path.chars().any(char::is_whitespace)
    {
        return Err(ContractError::one("signed_http_path_not_allowlisted"));
    }
    if method == "GET" && request.body.is_some() {
        return Err(ContractError::one("get_body_not_allowed"));
    }
    let body = match request.body {
        None => None,
        Some(Value::Object(object)) => Some(Value::Object(object.clone()).to_string().into_bytes()),
        Some(_) => return Err(ContractError::one("request_body_not_object")),
    };
    let headers = sign_headers(
        request.actor,
        &method,
        request.path,
        request.request_id,
        request.timestamp_ms,
        request.key,
    )?;
    let base = config
        .nodes
        .get(request.node)
        .ok_or_else(|| ContractError::one("invalid_node_alias"))?;
    Ok(SignedRequestPlan {
        method,
        url: format!("{base}{}", request.path),
        headers,
        body,
        timeout_ms: request.timeout_ms,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

pub trait HttpTransport {
    fn request(&mut self, plan: &SignedRequestPlan) -> Result<HttpResponse, RunnerError>;
}

pub fn execute_signed_request<T: HttpTransport>(
    config: &NodeAdapterConfig,
    transport: &mut T,
    request: SignedRequestSpec<'_>,
) -> Result<(u16, Value, String), ContractError> {
    let plan = build_signed_request(config, request)?;
    let response = transport
        .request(&plan)
        .map_err(|error| ContractError::one(error.kind))?;
    let parsed: Value = serde_json::from_str(&response.body)
        .map_err(|_| ContractError::one("response_not_json"))?;
    if !parsed.is_object() {
        return Err(ContractError::one("response_not_object"));
    }
    Ok((
        response.status,
        parsed,
        plan.headers.values["x-request-id"].clone(),
    ))
}

pub fn percent_encode(value: &str) -> String {
    let mut output = String::new();
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~".contains(byte) {
            output.push(*byte as char);
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

pub fn decision_path_for(base_path: &str, card: &str, query_parameter: &str) -> String {
    let separator = if base_path.contains('?') { '&' } else { '?' };
    let card = percent_encode(card);
    format!("{base_path}{separator}{query_parameter}={card}&card_id={card}")
}

pub fn role_actor<'a>(
    actors: &'a BTreeMap<String, Actor>,
    role: &str,
    card: &str,
) -> Result<&'a Actor, ContractError> {
    if !["target", "unrelated", "cold"].contains(&role) {
        return Err(ContractError::one("unknown_decision_role"));
    }
    let actor = actors
        .get(role)
        .ok_or_else(|| ContractError::one("role_actor_missing"))?;
    if actor.user_card != card {
        return Err(ContractError::one("role_card_mismatch"));
    }
    Ok(actor)
}

fn safe_log_identifier(value: &str) -> bool {
    safe_id(value, 128)
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        out.push(TABLE[(a >> 2) as usize] as char);
        out.push(TABLE[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(((b & 0x0f) << 2) | (c >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(c & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&byte))
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn local_base_dir(base_dir: &str, home: &str) -> String {
    if base_dir == "~" {
        home.to_owned()
    } else if let Some(rest) = base_dir.strip_prefix("~/") {
        format!("{home}/{rest}")
    } else {
        base_dir.to_owned()
    }
}

pub fn build_log_slice_command(
    config: &NodeAdapterConfig,
    node: &str,
    identifiers: &[&str],
    home_dir: &str,
    timeout_ms: u64,
) -> Result<Option<CommandPlan>, ContractError> {
    if !NODE_ALIASES.contains(&node) {
        return Err(ContractError::one("invalid_node_alias"));
    }
    let mut unique = Vec::new();
    for identifier in identifiers {
        if !safe_log_identifier(identifier) {
            return Err(ContractError::one("invalid_log_identifier"));
        }
        if !unique.contains(identifier) {
            unique.push(*identifier);
        }
    }
    if unique.is_empty() {
        return Ok(None);
    }
    let payload = Value::Array(
        unique
            .iter()
            .map(|identifier| Value::String((*identifier).to_owned()))
            .collect(),
    )
    .to_string();
    let payload = base64_encode(payload.as_bytes());
    let file = LOG_FILES[NODE_ALIASES
        .iter()
        .position(|alias| *alias == node)
        .unwrap()];
    let argv = if node == "node-b" {
        vec![
            "python3".to_owned(),
            "-".to_owned(),
            local_base_dir(&config.base_dir, home_dir),
            file.to_owned(),
            payload,
        ]
    } else {
        let ssh = config
            .ssh
            .get(node)
            .ok_or_else(|| ContractError::one("ssh_target_missing"))?;
        let remote_base = if let Some(rest) = config.base_dir.strip_prefix('~') {
            format!("\"$HOME\"{rest}")
        } else {
            format!("'{}'", config.base_dir)
        };
        let remote = format!(
            "python3 - {remote_base} {} {}",
            shell_quote(file),
            shell_quote(&payload)
        );
        vec![
            "ssh".to_owned(),
            "-o".to_owned(),
            "BatchMode=yes".to_owned(),
            "-o".to_owned(),
            "ConnectTimeout=10".to_owned(),
            ssh.clone(),
            remote,
        ]
    };
    Ok(Some(CommandPlan {
        argv,
        stdin: LOG_GREP_SCRIPT.to_owned(),
        timeout_ms,
    }))
}

fn validate_aggregate_type(value: &str) -> Result<(), ContractError> {
    if !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_uppercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        Ok(())
    } else {
        Err(ContractError::one("invalid_aggregate_type"))
    }
}

fn positive_i64(value: i64) -> Result<(), ContractError> {
    if value > 0 {
        Ok(())
    } else {
        Err(ContractError::one("invalid_positive_id"))
    }
}

fn operation_id(value: &str) -> Result<(), ContractError> {
    if safe_id(value, 64) {
        Ok(())
    } else {
        Err(ContractError::one("invalid_operation_id"))
    }
}

pub fn head_state_query(aggregate_type: &str, aggregate_id: i64) -> Result<String, ContractError> {
    validate_aggregate_type(aggregate_type)?;
    positive_i64(aggregate_id)?;
    Ok(format!(
        "SELECT aggregate_type, aggregate_id, source_generation, revoke_fence FROM authorization_projection_head WHERE aggregate_type='{aggregate_type}' AND aggregate_id={aggregate_id}"
    ))
}

pub fn delta_states_query(
    tenant_id: i64,
    aggregate_type: &str,
    aggregate_id: i64,
) -> Result<String, ContractError> {
    positive_i64(tenant_id)?;
    validate_aggregate_type(aggregate_type)?;
    positive_i64(aggregate_id)?;
    Ok(format!(
        "SELECT status, target_version FROM authorization_delta_event WHERE tenant_id={tenant_id} AND aggregate_type='{aggregate_type}' AND aggregate_id={aggregate_id} ORDER BY target_version"
    ))
}

pub fn delta_rows_for_operation_query(
    tenant_id: i64,
    aggregate_type: &str,
    aggregate_id: i64,
    operation: &str,
) -> Result<String, ContractError> {
    positive_i64(tenant_id)?;
    validate_aggregate_type(aggregate_type)?;
    positive_i64(aggregate_id)?;
    operation_id(operation)?;
    Ok(format!(
        "SELECT event_id, event_type, status, target_version, IFNULL(card_id,0) FROM authorization_delta_event WHERE tenant_id={tenant_id} AND aggregate_type='{aggregate_type}' AND aggregate_id={aggregate_id} AND operation_id='{operation}' ORDER BY event_id"
    ))
}

pub fn outbox_rows_query(aggregate_type: &str, aggregate_id: i64) -> Result<String, ContractError> {
    validate_aggregate_type(aggregate_type)?;
    positive_i64(aggregate_id)?;
    Ok(format!(
        "SELECT outbox_id, source_generation, status, IFNULL(lease_owner,''), terminal_transitions, IFNULL(processed_by,''), IFNULL(attempts,0) FROM authorization_projection_outbox WHERE aggregate_type='{aggregate_type}' AND aggregate_id={aggregate_id} ORDER BY outbox_id"
    ))
}

pub fn projection_pointer_query(
    tenant_id: i64,
    aggregate_type: &str,
    aggregate_id: i64,
) -> Result<String, ContractError> {
    positive_i64(tenant_id)?;
    validate_aggregate_type(aggregate_type)?;
    positive_i64(aggregate_id)?;
    Ok(format!(
        "SELECT current_generation, status, revoke_fence, cas_version, event_id, operation_id, IFNULL(card_id,0) FROM authorization_projection_current WHERE tenant_id={tenant_id} AND aggregate_type='{aggregate_type}' AND aggregate_id={aggregate_id}"
    ))
}

pub fn scrub_text(value: &str, max_len: usize) -> String {
    let value = url_regex().replace_all(value, "[redacted-host]");
    let value = ipv4_regex().replace_all(&value, "[redacted-host]");
    hostname_regex()
        .replace_all(&value, "[redacted-host]")
        .chars()
        .take(max_len)
        .collect()
}

fn url_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[A-Za-z][A-Za-z0-9+.\-]*://\S+").expect("constant URL regex"))
}

fn ipv4_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}\b").expect("constant IPv4 regex"))
}

fn hostname_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?\.)+(?:com|net|org|edu|gov|io|dev|app|local|internal|lan|example|test|invalid)\b")
            .expect("constant hostname regex")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const MYSQL_SECRET: &str = "mysql-root-secret-xyzzy";
    const REDIS_SECRET: &str = "redis-pass-secret-abcdef";
    const HMAC_SECRET: &str = "unit-test-hmac-secret-0123456789abcdef";

    fn raw_config() -> Value {
        serde_json::json!({
            "run_id":"authz-validation-20260919-single-node-002",
            "nodes":{
                "node-a":"http://node-a.example.invalid:8081",
                "node-b":"http://127.0.0.1:8082",
                "node-c":"http://node-c.example.invalid:8083"
            },
            "ssh":{"node-a":"ops@node-a.example.invalid","node-c":"ops@node-c.example.invalid"},
            "base_dir":"~/authz-validation-20260919-single-node-002",
            "db":"astral_bench",
            "mysql_container":"astral_bench_mysql",
            "redis_container":"astral_bench_redis",
            "hmac_secret_file":"/run/secrets/hmac.txt",
            "mysql_root":MYSQL_SECRET,
            "redis_password":REDIS_SECRET,
            "binary_sha256":"a".repeat(64),
            "source_snapshot_sha256":"b".repeat(64),
            "source_git_rev":"c".repeat(40),
            "source_dirty_patch_sha256":"d".repeat(64),
            "bootstrap_bin_sha256":"e".repeat(64),
            "source_dirty":true,
            "git_rev":"f".repeat(40),
            "ports":{"node-a":8081,"node-b":8082,"node-c":8083}
        })
    }

    fn config() -> NodeAdapterConfig {
        load_config(&raw_config()).unwrap()
    }

    fn actor() -> Actor {
        Actor {
            user_id: "9031".to_owned(),
            identity_card: "9041".to_owned(),
            user_card: "9061".to_owned(),
            domain: "9011".to_owned(),
            tenant: "9001".to_owned(),
        }
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

    #[derive(Default)]
    struct FakeTransport {
        calls: Vec<SignedRequestPlan>,
        response: Option<HttpResponse>,
    }

    impl HttpTransport for FakeTransport {
        fn request(&mut self, plan: &SignedRequestPlan) -> Result<HttpResponse, RunnerError> {
            self.calls.push(plan.clone());
            Ok(self.response.clone().unwrap_or(HttpResponse {
                status: 200,
                body: r#"{"code":0,"data":{"allowed":true}}"#.to_owned(),
            }))
        }
    }

    #[test]
    fn config_is_validated_without_io_and_public_metadata_hides_private_topology() {
        let config = config();
        assert_eq!(config.run_id(), "authz-validation-20260919-single-node-002");
        assert!(config.mysql_root_present());
        assert!(config.redis_password_present());
        assert!(config.private_config_is_stored_but_not_published());
        assert_eq!(
            config.public_metadata(),
            serde_json::json!({
                "runId":"authz-validation-20260919-single-node-002",
                "binarySha256":"a".repeat(64),
                "sourceSnapshotSha256":"b".repeat(64),
                "sourceGitRev":"c".repeat(40),
                "sourceDirty":true,
                "sourceDirtyPatchSha256":"d".repeat(64),
                "bootstrapBinSha256":"e".repeat(64),
                "nodeLabels":["node-a","node-b","node-c"]
            })
        );
        let private = format!("{config:?}");
        for forbidden in [
            MYSQL_SECRET,
            REDIS_SECRET,
            "example.invalid",
            "127.0.0.1",
            "astral_bench",
            "/run/secrets/hmac.txt",
            "8081",
        ] {
            assert!(
                !private.contains(forbidden),
                "config Debug leaked {forbidden}"
            );
        }
    }

    #[test]
    fn config_shape_errors_are_constant_sorted_and_invalid_maps_fail_closed() {
        let err = load_config(&serde_json::json!("not-a-mapping")).unwrap_err();
        assert_eq!(err.problems, ["config_not_a_mapping"]);
        let mut raw = raw_config();
        raw.as_object_mut().unwrap().remove("db");
        raw["run_id"] = Value::String("../escape".to_owned());
        raw["binary_sha256"] = Value::String("short".to_owned());
        raw["nodes"]["node-b"] = Value::String("ftp://bad".to_owned());
        raw["base_dir"] = Value::String("../evil".to_owned());
        raw["ports"]["node-a"] = Value::Bool(true);
        let error = load_config(&raw).unwrap_err();
        assert!(error.problems.contains(&"missing_required_field"));
        assert!(error.problems.contains(&"invalid_run_id"));
        assert!(error.problems.contains(&"invalid_sha256"));
        assert!(error.problems.contains(&"invalid_nodes"));
        assert!(error.problems.contains(&"invalid_base_dir"));
        assert!(error.problems.contains(&"invalid_ports"));
        assert!(error.problems.windows(2).all(|pair| pair[0] <= pair[1]));
        assert!(!format!("{error:?}").contains("bad"));
    }

    #[test]
    fn actor_aliases_and_signed_payload_field_order_are_explicit() {
        let actor = actor_from_mapping(&serde_json::json!({
            "user_id":9031,"icard":9041,"card":9061,"domain":9011,"tenant":9001
        }))
        .unwrap();
        assert_eq!(
            actor,
            Actor {
                user_id: "9031".to_owned(),
                identity_card: "9041".to_owned(),
                user_card: "9061".to_owned(),
                domain: "9011".to_owned(),
                tenant: "9001".to_owned(),
            }
        );
        let payload = build_gateway_v3_payload(
            &actor,
            "GET",
            "/main/api/v1/simulation/evaluate?card=9061",
            "1700000000000",
        );
        assert_eq!(
            payload.split('\n').collect::<Vec<_>>(),
            [
                "astral-gateway-v3",
                "GET",
                "/main/api/v1/simulation/evaluate",
                "9031",
                "PLATFORM_USER",
                "",
                "9041",
                "9061",
                "9011",
                "9001",
                "",
                "",
                "",
                "",
                "1700000000000"
            ]
        );
        assert!(actor_from_mapping(&serde_json::json!({"user_id":"1","icard":"2"})).is_err());
        let mut invalid = actor;
        invalid.user_id = "9\n031".to_owned();
        assert_eq!(invalid.validate().unwrap_err().kind, "invalid_user_id");
    }

    #[test]
    fn gateway_v3_signature_matches_byte_exact_hmac_vector() {
        let headers = sign_headers(
            &actor(),
            "GET",
            "/main/api/v1/simulation/evaluate?card=9061",
            "req-fixed-1",
            "1700000000000",
            HMAC_SECRET.as_bytes(),
        )
        .unwrap();
        assert_eq!(headers.values.len(), 11);
        assert_eq!(headers.values["x-request-id"], "req-fixed-1");
        assert_eq!(headers.values["x-principal-kind"], "PLATFORM_USER");
        assert_eq!(headers.values["x-gateway-auth"], "verified");
        assert_eq!(headers.values["x-gateway-ts"], "1700000000000");
        assert_eq!(headers.values["Content-Type"], "application/json");
        assert_eq!(
            headers.values["x-gateway-signature"],
            "f92591b3e214bd79fa0674682686013e488242ae359ae5f392507610f7186900"
        );
        assert!(!format!("{headers:?}").contains(HMAC_SECRET));
        assert_ne!(
            build_gateway_v3_payload(
                &actor(),
                "GET",
                "/main/api/v1/simulation/evaluate?card=9061",
                "1700000000000"
            ),
            build_gateway_v3_payload(
                &Actor {
                    identity_card: "9061".to_owned(),
                    user_card: "9041".to_owned(),
                    ..actor()
                },
                "GET",
                "/main/api/v1/simulation/evaluate?card=9061",
                "1700000000000"
            )
        );
    }

    #[test]
    fn sql_guard_and_fixed_argv_are_read_only_and_secret_stays_off_argv() {
        for allowed in [
            "SELECT 1",
            "/* lead */ SELECT 1",
            "  select 1;  ",
            "-- comment\nSELECT 1",
        ] {
            assert!(require_select_only(allowed).is_ok(), "{allowed}");
        }
        for rejected in [
            "UPDATE t SET x=1",
            "DELETE FROM t",
            "SELECT 1; DROP TABLE t",
            "SELECT * FROM t WHERE c=';'",
            "WITH cte AS (SELECT 1) SELECT * FROM cte",
            "SELECT 1 INTO OUTFILE '/tmp/x'",
            "SELECT * FROM t FOR UPDATE",
            "SELECT * FROM t LOCK IN SHARE MODE",
            "SELECT GET_LOCK('a', 1)",
        ] {
            assert!(require_select_only(rejected).is_err(), "{rejected}");
        }
        let plan = build_sql_command(&config(), "SELECT col_a, col_b FROM t", 60_000).unwrap();
        assert_eq!(
            plan.argv,
            [
                "docker",
                "exec",
                "-i",
                "astral_bench_mysql",
                "sh",
                "-c",
                MYSQL_STDIN_SCRIPT,
                "sh",
                "astral_bench",
                "SELECT col_a, col_b FROM t"
            ]
        );
        assert!(plan.stdin_is(MYSQL_SECRET));
        assert!(plan.argv.iter().all(|part| !part.contains(MYSQL_SECRET)));
        let mut runner = FakeRunner::default();
        runner.results.push(CommandResult {
            exit_code: 0,
            stdout: "a\t\tb\r\nc\tval\n\n".to_owned(),
            stderr: String::new(),
        });
        assert_eq!(
            execute_sql(&config(), &mut runner, "SELECT 1", 60_000).unwrap(),
            vec![
                vec!["a".to_owned(), "".to_owned(), "b".to_owned()],
                vec!["c".to_owned(), "val".to_owned()],
            ]
        );
        let mut missing = raw_config();
        missing.as_object_mut().unwrap().remove("mysql_root");
        let missing = load_config(&missing).unwrap();
        assert_eq!(
            build_sql_command(&missing, "SELECT 1", 60_000)
                .unwrap_err()
                .kind,
            "mysql_root_missing"
        );
    }

    #[test]
    fn redis_allowlist_arity_and_key_validation_precede_command_creation() {
        let config = config();
        let get =
            build_redis_command(&config, "get", &["astral:auth:cache_epoch"], 30_000).unwrap();
        assert_eq!(
            get.argv[0..8],
            [
                "docker",
                "exec",
                "-i",
                "astral_bench_redis",
                "sh",
                "-c",
                REDIS_STDIN_SCRIPT,
                "sh"
            ]
        );
        assert_eq!(get.argv[8..], ["GET", "astral:auth:cache_epoch"]);
        assert!(get.stdin_is(REDIS_SECRET));
        assert!(get.argv.iter().all(|part| !part.contains(REDIS_SECRET)));
        let ping = build_redis_command(&config, "PING", &[], 30_000).unwrap();
        assert_eq!(ping.argv.last().map(String::as_str), Some("PING"));
        for verb in ["SET", "DEL", "CONFIG", "FLUSHALL", "get ", "SETEX"] {
            assert!(
                build_redis_command(&config, verb, &["k"], 30_000).is_err(),
                "{verb}"
            );
        }
        for (verb, args) in [
            ("GET", &[][..]),
            ("GET", &["k1", "k2"][..]),
            ("LLEN", &[][..]),
            ("PING", &["extra"][..]),
            ("GET", &["has space"][..]),
            ("GET", &["key;DEL x"][..]),
        ] {
            assert!(build_redis_command(&config, verb, args, 30_000).is_err());
        }
        let mut missing = raw_config();
        missing.as_object_mut().unwrap().remove("redis_password");
        assert_eq!(
            build_redis_command(&load_config(&missing).unwrap(), "PING", &[], 30_000)
                .unwrap_err()
                .kind,
            "redis_password_missing"
        );
    }

    #[test]
    fn signed_request_restricts_path_method_body_and_parses_object_responses() {
        let config = config();
        let plan = build_signed_request(
            &config,
            SignedRequestSpec {
                actor: &actor(),
                node: "node-b",
                method: "GET",
                path: "/main/api/v1/simulation/evaluate?card=9061",
                body: None,
                request_id: "req-stable-7",
                timestamp_ms: "1700000000000",
                key: HMAC_SECRET.as_bytes(),
                timeout_ms: 30_000,
            },
        )
        .unwrap();
        assert_eq!(
            plan.url,
            "http://127.0.0.1:8082/main/api/v1/simulation/evaluate?card=9061"
        );
        assert_eq!(plan.method, "GET");
        assert_eq!(plan.body, None);
        assert_eq!(plan.headers.values["x-request-id"], "req-stable-7");
        assert!(!format!("{plan:?}").contains(HMAC_SECRET));
        for (node, method, path, body) in [
            ("node-d", "GET", "/main/api/v1/x", None),
            ("node-b", "PATCH", "/main/api/v1/x", None),
            (
                "node-b",
                "GET",
                "/main/api/v1/x",
                Some(&serde_json::json!({})),
            ),
            ("node-b", "GET", "/main/api/v2/x", None),
            ("node-b", "GET", "/main/api/v1/x\ninjected", None),
        ] {
            assert!(build_signed_request(
                &config,
                SignedRequestSpec {
                    actor: &actor(),
                    node,
                    method,
                    path,
                    body,
                    request_id: "req-1",
                    timestamp_ms: "1700000000000",
                    key: HMAC_SECRET.as_bytes(),
                    timeout_ms: 30_000,
                },
            )
            .is_err());
        }
        let body = serde_json::json!({"resource":"monitor","effect":"ALLOW","action":"read"});
        let post = build_signed_request(
            &config,
            SignedRequestSpec {
                actor: &actor(),
                node: "node-b",
                method: "POST",
                path: "/main/api/v1/rule-sets/9071/entries",
                body: Some(&body),
                request_id: "op-entry-add",
                timestamp_ms: "1700000000000",
                key: HMAC_SECRET.as_bytes(),
                timeout_ms: 30_000,
            },
        )
        .unwrap();
        assert_eq!(
            post.body.as_deref(),
            Some(br#"{"action":"read","effect":"ALLOW","resource":"monitor"}"#.as_slice())
        );
        let mut transport = FakeTransport::default();
        let result = execute_signed_request(
            &config,
            &mut transport,
            SignedRequestSpec {
                actor: &actor(),
                node: "node-b",
                method: "GET",
                path: "/main/api/v1/x",
                body: None,
                request_id: "req-2",
                timestamp_ms: "1700000000000",
                key: HMAC_SECRET.as_bytes(),
                timeout_ms: 30_000,
            },
        )
        .unwrap();
        assert_eq!(result.0, 200);
        assert_eq!(result.2, "req-2");
        transport.response = Some(HttpResponse {
            status: 200,
            body: "[1,2,3]".to_owned(),
        });
        assert_eq!(
            execute_signed_request(
                &config,
                &mut transport,
                SignedRequestSpec {
                    actor: &actor(),
                    node: "node-b",
                    method: "GET",
                    path: "/main/api/v1/x",
                    body: None,
                    request_id: "req-3",
                    timestamp_ms: "1700000000000",
                    key: HMAC_SECRET.as_bytes(),
                    timeout_ms: 30_000,
                },
            )
            .unwrap_err()
            .kind,
            "response_not_object"
        );
    }

    #[test]
    fn role_actor_and_decision_path_keep_exact_card_binding() {
        let actors = [("target", "9061"), ("unrelated", "9062"), ("cold", "9063")]
            .into_iter()
            .map(|(role, card)| {
                (
                    role.to_owned(),
                    Actor {
                        user_card: card.to_owned(),
                        ..actor()
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            role_actor(&actors, "target", "9061").unwrap().user_card,
            "9061"
        );
        assert_eq!(
            role_actor(&actors, "target", "9062").unwrap_err().kind,
            "role_card_mismatch"
        );
        assert!(role_actor(&actors, "other", "9061").is_err());
        assert_eq!(
            decision_path_for("/main/api/v1/permission-rules/check", "card 1/2?a=b", "cardId"),
            "/main/api/v1/permission-rules/check?cardId=card%201%2F2%3Fa%3Db&card_id=card%201%2F2%3Fa%3Db"
        );
    }

    #[test]
    fn log_slice_validates_and_deduplicates_ids_before_runner_dispatch() {
        let config = config();
        assert!(
            build_log_slice_command(&config, "node-a", &[], "/home/test", 120_000)
                .unwrap()
                .is_none()
        );
        assert!(
            build_log_slice_command(&config, "node-a", &["bad id"], "/home/test", 120_000).is_err()
        );
        assert!(
            build_log_slice_command(&config, "node-z", &["req-1"], "/home/test", 120_000).is_err()
        );
        let local = build_log_slice_command(
            &config,
            "node-b",
            &["req-1", "req-1", "op-2"],
            "/home/test",
            120_000,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            local.argv[0..4],
            [
                "python3",
                "-",
                "/home/test/authz-validation-20260919-single-node-002",
                "server_b.log"
            ]
        );
        assert_eq!(local.argv[4], "WyJyZXEtMSIsIm9wLTIiXQ==");
        assert_eq!(local.timeout_ms, 120_000);
        let remote =
            build_log_slice_command(&config, "node-a", &["op-1", "req-2"], "/home/test", 120_000)
                .unwrap()
                .unwrap();
        assert_eq!(
            remote.argv[0..6],
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "ops@node-a.example.invalid"
            ]
        );
        assert!(remote.argv[6].contains("\"$HOME\"/authz-validation-20260919-single-node-002"));
        assert!(remote.argv[6].contains("server_a.log"));
        assert!(!remote.argv[6].contains("open("));
        assert_eq!(remote.stdin, LOG_GREP_SCRIPT);
    }

    #[test]
    fn durable_reconciliation_query_builders_are_select_only_and_reject_bad_inputs() {
        let queries = [
            head_state_query("RULE_SET", 1).unwrap(),
            delta_states_query(9001, "RULE_SET", 1).unwrap(),
            outbox_rows_query("RULE_SET", 1).unwrap(),
            delta_rows_for_operation_query(9001, "RULE_SET", 1, "op-delete-1").unwrap(),
            projection_pointer_query(9001, "CARD", 2).unwrap(),
        ];
        assert!(queries
            .iter()
            .all(|query| require_select_only(query).is_ok()));
        assert!(queries[0].contains("FROM authorization_projection_head"));
        assert!(
            queries[1].contains("tenant_id=9001 AND aggregate_type='RULE_SET' AND aggregate_id=1")
        );
        assert!(queries[2].contains("FROM authorization_projection_outbox"));
        assert!(queries[3].contains("operation_id='op-delete-1'"));
        assert!(queries[4].contains("tenant_id=9001 AND aggregate_type='CARD' AND aggregate_id=2"));
        assert!(head_state_query("RULE_SET; DROP TABLE x", 1).is_err());
        assert!(head_state_query("rule_set", 1).is_err());
        assert!(head_state_query("RULE_SET", 0).is_err());
        assert!(delta_states_query(0, "RULE_SET", 1).is_err());
        assert!(delta_rows_for_operation_query(9001, "RULE_SET", 1, "bad operation id").is_err());
        assert!(projection_pointer_query(0, "RULE_SET", MAX_SIGNED_I64).is_err());
    }

    #[test]
    fn scrubber_redacts_url_ipv4_hostname_and_bounds_strings() {
        let value = scrub_text(
            "see http://h.example.internal/a and 10.1.2.3 and db.host.example.org end",
            300,
        );
        assert!(!value.contains("http://"));
        assert!(!value.contains("10.1.2.3"));
        assert!(!value.contains("db.host.example.org"));
        assert_eq!(value.matches("[redacted-host]").count(), 3);
        assert_eq!(scrub_text(&"x".repeat(400), 300).len(), 300);
    }

    #[test]
    fn fixed_script_literals_and_hmac_secret_load_lazily() {
        assert_eq!(
            MYSQL_STDIN_SCRIPT,
            "MYSQL_PWD=\"$(cat)\" exec mysql -uroot -N -e \"$2\" \"$1\""
        );
        assert_eq!(
            REDIS_STDIN_SCRIPT,
            "REDISCLI_AUTH=\"$(cat)\" exec redis-cli \"$@\""
        );
        assert!(LOG_GREP_SCRIPT.contains("_SAFE_ID"));
        assert!(LOG_GREP_SCRIPT.contains("base64.b64decode"));
        let dir =
            std::env::temp_dir().join(format!("astral-node-adapter-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hmac.txt");
        std::fs::write(&path, format!("{HMAC_SECRET}\n")).unwrap();
        let secret = load_hmac_secret(path.to_str().unwrap()).unwrap();
        assert_eq!(secret, HMAC_SECRET.as_bytes());
        assert_eq!(
            load_hmac_secret("/nonexistent/hmac.txt").unwrap_err().kind,
            "hmac_secret_unreadable"
        );
        let empty = dir.join("empty.txt");
        std::fs::write(&empty, "   \n").unwrap();
        assert_eq!(
            load_hmac_secret(empty.to_str().unwrap()).unwrap_err().kind,
            "hmac_secret_empty"
        );
        let config = config();
        assert!(!format!("{config:?}").contains(HMAC_SECRET));
        let headers = sign_headers(
            &actor(),
            "GET",
            "/main/api/v1/x",
            "req-1",
            "1700000000000",
            &secret,
        )
        .unwrap();
        assert!(headers.values.contains_key("x-gateway-signature"));
        assert!(!format!("{config:?}").contains(HMAC_SECRET));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn sql_command_has_fixed_argv_stdin_tsv_and_missing_root_guard() {
        let config = config();
        let plan = build_sql_command(&config, "SELECT col_a, col_b, col_c FROM t", 60_000).unwrap();
        assert_eq!(
            plan.argv,
            vec![
                "docker".to_owned(),
                "exec".to_owned(),
                "-i".to_owned(),
                "astral_bench_mysql".to_owned(),
                "sh".to_owned(),
                "-c".to_owned(),
                MYSQL_STDIN_SCRIPT.to_owned(),
                "sh".to_owned(),
                "astral_bench".to_owned(),
                "SELECT col_a, col_b, col_c FROM t".to_owned(),
            ]
        );
        assert!(plan.stdin_is(MYSQL_SECRET));
        assert_eq!(plan.timeout_ms, 60_000);
        assert!(plan.argv.iter().all(|part| !part.contains(MYSQL_SECRET)));
        assert_eq!(
            parse_tsv("a\t\tb\nc\tval\n"),
            vec![
                vec!["a".to_owned(), String::new(), "b".to_owned()],
                vec!["c".to_owned(), "val".to_owned()],
            ]
        );

        let mut raw = raw_config();
        raw.as_object_mut().unwrap().remove("mysql_root");
        let missing = load_config(&raw).unwrap();
        let mut runner = FakeRunner::default();
        let error = execute_sql(&missing, &mut runner, "SELECT 1", 60_000).unwrap_err();
        assert_eq!(error.kind, "mysql_root_missing");
        assert!(runner.calls.is_empty());
    }

    #[test]
    fn redis_command_has_fixed_argv_and_missing_password_guard() {
        let config = config();
        let plan =
            build_redis_command(&config, "GET", &["astral:auth:cache_epoch"], 30_000).unwrap();
        assert_eq!(
            plan.argv,
            vec![
                "docker".to_owned(),
                "exec".to_owned(),
                "-i".to_owned(),
                "astral_bench_redis".to_owned(),
                "sh".to_owned(),
                "-c".to_owned(),
                REDIS_STDIN_SCRIPT.to_owned(),
                "sh".to_owned(),
                "GET".to_owned(),
                "astral:auth:cache_epoch".to_owned(),
            ]
        );
        assert!(plan.stdin_is(REDIS_SECRET));
        let mut raw = raw_config();
        raw.as_object_mut().unwrap().remove("redis_password");
        let missing = load_config(&raw).unwrap();
        assert_eq!(
            build_redis_command(&missing, "PING", &[], 30_000)
                .unwrap_err()
                .kind,
            "redis_password_missing"
        );
    }

    #[test]
    fn sql_redis_and_log_failures_are_scrubbed_and_bounded() {
        let config = config();
        let mut runner = FakeRunner::default();
        runner.results.push(CommandResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: "ERROR at http://db.example.invalid:3306/secret".to_owned(),
        });
        let error = execute_sql_with_detail(&config, &mut runner, "SELECT 1", 60_000).unwrap_err();
        assert_eq!(error.kind, "sql_failed");
        assert!(error.detail.contains("[redacted-host]"));
        assert!(!error.detail.contains("example.invalid"));
        assert!(!error.detail.contains(MYSQL_SECRET));
        assert!(error.detail.len() <= 300);

        let mut runner = FakeRunner::default();
        runner.results.push(CommandResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: "NOAUTH at redis://cache.example.invalid:6380".to_owned(),
        });
        let error =
            execute_redis_with_detail(&config, &mut runner, "GET", &["k1"], 30_000).unwrap_err();
        assert_eq!(error.kind, "redis_failed");
        assert!(error.detail.contains("[redacted-host]"));
        assert!(!error.detail.contains("example.invalid"));
        assert!(!error.detail.contains(REDIS_SECRET));

        let mut runner = FakeRunner::default();
        runner.results.push(CommandResult {
            exit_code: 255,
            stdout: String::new(),
            stderr: "ssh: connect to host ops@node-a.example.invalid port 22".to_owned(),
        });
        let error = execute_log_slice_with_detail(
            &config,
            &mut runner,
            "node-a",
            &["req-1"],
            "/home/ops",
            120_000,
        )
        .unwrap_err();
        assert_eq!(error.kind, "log_slice_failed");
        assert!(error.detail.contains("[redacted-host]"));
        assert!(!error.detail.contains("node-a.example.invalid"));
    }

    #[test]
    fn log_slice_commands_use_local_and_ssh_fixed_argv() {
        let config = config();
        let payload = base64_encode(json!(["req-1"]).to_string().as_bytes());
        let local = build_log_slice_command(&config, "node-b", &["req-1"], "/home/ops", 120_000)
            .unwrap()
            .unwrap();
        assert_eq!(
            local.argv[..3].to_vec(),
            vec![
                "python3".to_owned(),
                "-".to_owned(),
                "/home/ops/authz-validation-20260919-single-node-002".to_owned(),
            ]
        );
        assert_eq!(local.argv[3], "server_b.log");
        assert_eq!(local.argv[4], payload);
        assert!(local.stdin_is(LOG_GREP_SCRIPT));

        let remote =
            build_log_slice_command(&config, "node-a", &["op-1", "req-2"], "/home/ops", 120_000)
                .unwrap()
                .unwrap();
        assert_eq!(
            remote.argv[..6].to_vec(),
            vec![
                "ssh".to_owned(),
                "-o".to_owned(),
                "BatchMode=yes".to_owned(),
                "-o".to_owned(),
                "ConnectTimeout=10".to_owned(),
                "ops@node-a.example.invalid".to_owned(),
            ]
        );
        let command = &remote.argv[6];
        assert!(command.starts_with("python3 - "));
        assert!(command.contains("\"$HOME\"/authz-validation-20260919-single-node-002"));
        assert!(command.contains("server_a.log"));
        assert!(!command.contains("open("));
        assert!(remote.stdin_is(LOG_GREP_SCRIPT));
        assert_eq!(
            build_log_slice_command(&config, "node-z", &["req-1"], "/home/ops", 1)
                .unwrap_err()
                .kind,
            "invalid_node_alias"
        );
        assert!(
            build_log_slice_command(&config, "node-a", &[], "/home/ops", 1)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn command_result_shape_and_disabled_subprocess_runner() {
        let result = CommandResult {
            exit_code: 0,
            stdout: "out".to_owned(),
            stderr: "err".to_owned(),
        };
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, "out");
        assert_eq!(result.stderr, "err");
        let plan = build_sql_command(&config(), "SELECT 1", 1).unwrap();
        let error = DisabledSubprocessRunner.run(&plan).unwrap_err();
        assert_eq!(error.kind, "subprocess_execution_not_enabled");
    }

    #[test]
    fn node_alias_restrictions_apply_to_signed_requests() {
        let config = config();
        let key = [1u8, 2, 3];
        let actor = actor();
        let spec = SignedRequestSpec {
            actor: &actor,
            node: "node-a",
            method: "GET",
            path: "/main/api/v1/x",
            body: None,
            request_id: "req-1",
            timestamp_ms: "1700000000000",
            key: &key,
            timeout_ms: 60_000,
        };
        assert!(build_signed_request(&config, spec).is_ok());
        for node in ["gateway", "node-d", "NODE-A", "node_a", ""] {
            let spec = SignedRequestSpec {
                actor: &actor,
                node,
                method: "GET",
                path: "/main/api/v1/x",
                body: None,
                request_id: "req-1",
                timestamp_ms: "1700000000000",
                key: &key,
                timeout_ms: 60_000,
            };
            assert_eq!(
                build_signed_request(&config, spec).unwrap_err().kind,
                "invalid_node_alias",
                "{node}"
            );
        }
    }

    #[test]
    fn fake_runner_and_transport_satisfy_the_declared_traits() {
        fn uses_runner<R: CommandRunner>(runner: &mut R) -> Result<CommandResult, RunnerError> {
            let plan = build_sql_command(&config(), "SELECT 1", 1).unwrap();
            runner.run(&plan)
        }
        fn uses_transport<T: HttpTransport>(
            transport: &mut T,
        ) -> Result<HttpResponse, RunnerError> {
            let plan = build_signed_request(
                &config(),
                SignedRequestSpec {
                    actor: &actor(),
                    node: "node-a",
                    method: "GET",
                    path: "/main/api/v1/x",
                    body: None,
                    request_id: "req-1",
                    timestamp_ms: "1700000000000",
                    key: &[1, 2, 3],
                    timeout_ms: 60_000,
                },
            )
            .unwrap();
            transport.request(&plan)
        }
        let mut runner = FakeRunner::default();
        assert_eq!(uses_runner(&mut runner).unwrap().exit_code, 0);
        let mut transport = FakeTransport::default();
        assert_eq!(uses_transport(&mut transport).unwrap().status, 200);
    }

    #[test]
    fn flat_config_loads_without_io_and_public_metadata_is_exact() {
        let raw = raw_config();
        let config = load_config(&raw).unwrap();
        assert_eq!(config.run_id(), "authz-validation-20260919-single-node-002");
        assert!(config.mysql_root_present());
        assert!(config.redis_password_present());
        assert!(config.private_config_is_stored_but_not_published());
        let metadata = config.public_metadata();
        let object = metadata.as_object().unwrap();
        assert_eq!(object.len(), 8);
        assert_eq!(
            metadata["runId"],
            "authz-validation-20260919-single-node-002"
        );
        assert_eq!(metadata["binarySha256"], "a".repeat(64));
        assert_eq!(metadata["sourceDirty"], true);
        assert_eq!(
            metadata["nodeLabels"],
            json!(["node-a", "node-b", "node-c"])
        );
        let text = metadata.to_string();
        assert!(!text.contains(MYSQL_SECRET));
        assert!(!text.contains(REDIS_SECRET));
        assert!(!text.contains(HMAC_SECRET));
        assert!(!text.contains("node-a.example.invalid"));
        assert!(!text.contains("astral_bench_mysql"));

        let mut missing_hmac = raw.clone();
        missing_hmac["hmac_secret_file"] = json!("/nonexistent/hmac.txt");
        assert!(load_config(&missing_hmac).is_ok());
        let mut missing_nodes = raw.clone();
        missing_nodes.as_object_mut().unwrap().remove("nodes");
        assert!(load_config(&missing_nodes).is_err());
        let mut bad_hash = raw;
        bad_hash["binary_sha256"] = json!("bad");
        assert!(load_config(&bad_hash).is_err());
    }

    #[test]
    fn default_decision_path_is_the_real_route() {
        let path = decision_path_for("/main/api/v1/permission-rules/check", "9061", "cardId");
        assert_eq!(
            path,
            "/main/api/v1/permission-rules/check?cardId=9061&card_id=9061"
        );
        let mut transport = FakeTransport::default();
        let (status, _body, _request_id) = execute_signed_request(
            &config(),
            &mut transport,
            SignedRequestSpec {
                actor: &actor(),
                node: "node-a",
                method: "GET",
                path: &path,
                body: None,
                request_id: "req-1",
                timestamp_ms: "1700000000000",
                key: &[1, 2, 3],
                timeout_ms: 60_000,
            },
        )
        .unwrap();
        assert_eq!(status, 200);
    }

    #[test]
    fn api_response_envelope_is_preserved_end_to_end() {
        let mut transport = FakeTransport::default();
        transport.response = Some(HttpResponse {
            status: 200,
            body: r#"{"code":200,"message":"ok","data":{"allowed":true,"reason":"RULE_MATCH"}}"#
                .to_owned(),
        });
        let (status, body, request_id) = execute_signed_request(
            &config(),
            &mut transport,
            SignedRequestSpec {
                actor: &actor(),
                node: "node-a",
                method: "GET",
                path: "/main/api/v1/permission-rules/check?cardId=9061&card_id=9061",
                body: None,
                request_id: "req-1",
                timestamp_ms: "1700000000000",
                key: &[1, 2, 3],
                timeout_ms: 60_000,
            },
        )
        .unwrap();
        assert_eq!(status, 200);
        assert_eq!(request_id, "req-1");
        assert_eq!(body["code"], 200);
        assert_eq!(body["message"], "ok");
        assert_eq!(body["data"]["allowed"], true);
        assert_eq!(body["data"]["reason"], "RULE_MATCH");
    }
}
