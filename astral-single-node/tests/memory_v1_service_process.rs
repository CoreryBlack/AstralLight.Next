//! memory—v1: Process-level tests of the experimental real-service binary.
//!
//! Part A runs by default and needs no database: the real binary refuses every
//! unsafe or incomplete start before it serves anything.
//!
//! Part B (`--ignored`) is the database-backed end-to-end run. It creates its own
//! run-scoped database on an operator-supplied server, applies the reviewed candidate
//! DDL, seeds the fixture, starts the real binary against it, drives the real HTTP
//! lifecycle (login → authorized read → logout), stops the binary gracefully and
//! drops the database. It never touches any other database and refuses to start
//! unless the server address is loopback (an SSH tunnel, never a public address).
//!
//! No credential, address or connection string is stored in this repository: the
//! server comes from `ASTRAL_MEMORY_V1_E2E_ADMIN_URL` at run time.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use astral_authorization_root::memory_v1_adoption::AdoptionLimit;
use astral_authorization_root::memory_v1_db_rows::RuleSetVersionRow;
use astral_authorization_root::memory_v1_rules::canonical_version_bytes;
use astral_types::memory_v1::MemoryId;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use sqlx::{MySqlPool, Row};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::time::timeout;

const BIN: &str = env!("CARGO_BIN_EXE_astral-single-node");
const READY_PREFIX: &str = "ASTRAL_MEMORY_V1_READY";
const REGISTRY: &str = "/main/api/v1/permission-rules/registry";

const ALICE: [u8; 16] = [0x11; 16];
const BOB: [u8; 16] = [0x21; 16];
const TENANT: [u8; 16] = [0x13; 16];
const CARD_ALLOW: [u8; 16] = [0x31; 16];
const CARD_OVERLAY_DENY: [u8; 16] = [0x32; 16];
const CARD_UNBOUND: [u8; 16] = [0x33; 16];
const CARD_BOB: [u8; 16] = [0x34; 16];
const RULES_READ: [u8; 16] = [0x41; 16];
const RULES_DENY: [u8; 16] = [0x42; 16];

/// Databases that hold other people's data. Neither is ever read beyond table names
/// nor written; the end-to-end run proves their table lists did not change.
const PROTECTED_DATABASES: [&str; 2] = ["astral_light_rust", "platform_v4"];
const RUN_DATABASE_PREFIX: &str = "astral_rehearsal_mv1_";

// ───────────────────────────── shared helpers ─────────────────────────────

// memory—v1: A scratch directory removed on drop.
struct TempDir(PathBuf);

impl TempDir {
    // memory—v1: Create a unique, owner-only directory under the system temp dir.
    fn new(label: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("astral-mv1-{label}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    // memory—v1: Remove the directory and everything in it.
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// memory—v1: Write a credentials file for the two fixture users with the given mode.
fn write_credentials(dir: &Path, mode: u32) -> PathBuf {
    let entry = |identifier: &str, user: [u8; 16], password: &str| {
        json!({
            "identifier": identifier,
            "userId": MemoryId::from_bytes(user).to_string(),
            "passwordHash": astral_identity::auth::hash_password(password).unwrap(),
            "status": "active",
            "revision": 1,
        })
    };
    let text = json!({
        "version": 1,
        "credentials": [
            entry("alice", ALICE, "alice-secret"),
            entry("bob", BOB, "bob-secret"),
        ],
    })
    .to_string();
    let path = dir.join("credentials.json");
    std::fs::write(&path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = mode;
    path
}

// memory—v1: Every limit by name, as the operator acknowledges them.
fn all_limits() -> String {
    AdoptionLimit::EXPERIMENTAL
        .iter()
        .map(|limit| limit.name())
        .collect::<Vec<_>>()
        .join(",")
}

// memory—v1: The environment the service needs; nothing is inherited from the caller.
fn service_env(database_url: &str, credentials: &Path) -> Vec<(String, String)> {
    [
        ("SINGLE_NODE_GATEWAY_ADDR", "127.0.0.1:0"),
        (
            "ASTRAL_MEMORY_V1_CREDENTIALS_FILE",
            credentials.to_str().unwrap(),
        ),
        ("ASTRAL_MEMORY_V1_ACKNOWLEDGE_LIMITS", &all_limits()),
        // The local-database relaxations of the runtime-safety gate; the listener is
        // loopback-only regardless.
        ("APP_PROFILE", "test"),
        ("ASTRAL_MESSAGE_TRANSPORT", "local"),
        ("DATABASE_URL", database_url),
        (
            "JWT_ACCESS_SECRET",
            "e2e-access-secret-0123456789abcdef0123",
        ),
        (
            "JWT_REFRESH_SECRET",
            "e2e-refresh-secret-0123456789abcdef012",
        ),
        ("JWT_ACCESS_ISSUER", "e2e-access-issuer"),
        ("JWT_REFRESH_ISSUER", "e2e-refresh-issuer"),
        ("JWT_ACCESS_AUDIENCE", "e2e-astral-api"),
        ("JWT_REFRESH_AUDIENCE", "e2e-astral-session"),
        (
            "GATEWAY_HMAC_SECRET",
            "e2e-gateway-hmac-secret-0123456789abcdef",
        ),
        ("CORS_ALLOWED_ORIGINS", "https://console.example.invalid"),
        ("CORS_ALLOW_CREDENTIALS", "false"),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value.to_owned()))
    .collect()
}

// memory—v1: Replace or add one variable.
fn with_var(mut env: Vec<(String, String)>, name: &str, value: &str) -> Vec<(String, String)> {
    env.retain(|(existing, _)| existing != name);
    env.push((name.to_owned(), value.to_owned()));
    env
}

// memory—v1: A started service process with its output captured.
struct Running {
    child: Child,
    stdout: mpsc::UnboundedReceiver<String>,
    stderr: Arc<Mutex<String>>,
    seen_stdout: Vec<String>,
}

// memory—v1: Start the real binary with exactly `env`, in an empty working directory.
fn start(env: &[(String, String)], cwd: &Path) -> Running {
    let mut child = Command::new(BIN)
        .env_clear()
        .envs(env.iter().map(|(name, value)| (name, value)))
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("start the astral-single-node binary");
    let (tx, stdout) = mpsc::unbounded_channel();
    let out = child.stdout.take().unwrap();
    tokio::spawn(async move {
        let mut lines = BufReader::new(out).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let _ = tx.send(line);
        }
    });
    let stderr = Arc::new(Mutex::new(String::new()));
    let err = child.stderr.take().unwrap();
    let sink = Arc::clone(&stderr);
    tokio::spawn(async move {
        let mut lines = BufReader::new(err).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let mut sink = sink.lock().unwrap();
            sink.push_str(&line);
            sink.push('\n');
        }
    });
    Running {
        child,
        stdout,
        stderr,
        seen_stdout: Vec::new(),
    }
}

impl Running {
    // memory—v1: Everything the process wrote so far (stdout lines, then stderr).
    fn output(&mut self) -> String {
        while let Ok(line) = self.stdout.try_recv() {
            self.seen_stdout.push(line);
        }
        format!(
            "stdout:\n{}\nstderr:\n{}",
            self.seen_stdout.join("\n"),
            self.stderr.lock().unwrap()
        )
    }

    // memory—v1: Wait for the readiness line; a process that exits first is a failure.
    async fn wait_ready(&mut self, limit: Duration) -> Result<String, String> {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            tokio::select! {
                line = self.stdout.recv() => match line {
                    Some(line) if line.starts_with(READY_PREFIX) => {
                        self.seen_stdout.push(line.clone());
                        return Ok(line);
                    }
                    Some(line) => self.seen_stdout.push(line),
                    None => {
                        let status = self.child.wait().await.ok();
                        return Err(format!("exited ({status:?}) before readiness\n{}", self.output()));
                    }
                },
                _ = tokio::time::sleep_until(deadline) => {
                    return Err(format!("not ready within {limit:?}\n{}", self.output()));
                }
            }
        }
    }

    // memory—v1: Wait for the process to exit; kill it and fail if it outlives `limit`.
    async fn exit(&mut self, limit: Duration) -> std::process::ExitStatus {
        match timeout(limit, self.child.wait()).await {
            Ok(status) => status.expect("wait for the service process"),
            Err(_) => {
                let _ = self.child.kill().await;
                panic!("the service outlived {limit:?}\n{}", self.output());
            }
        }
    }
}

// memory—v1: Run a configuration that must be refused; return its combined output.
async fn refused(env: &[(String, String)]) -> String {
    let cwd = TempDir::new("cwd");
    let mut running = start(env, cwd.path());
    let status = running.exit(Duration::from_secs(60)).await;
    // Let the reader tasks flush their last lines.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let output = running.output();
    assert!(
        !status.success(),
        "the service must refuse to start\n{output}"
    );
    assert!(
        !output.contains(READY_PREFIX),
        "a refused start must never announce readiness\n{output}"
    );
    output
}

// ──────────────────────── Part A: refusals, no database ────────────────────────

const UNREACHABLE_DB: &str = "mysql://unused:unused@127.0.0.1:1/memory_v1_unreachable";

#[tokio::test]
// memory—v1: A non-loopback listener is refused before any file or database is touched.
async fn non_loopback_listener_is_refused() {
    let dir = TempDir::new("listen");
    let credentials = write_credentials(dir.path(), 0o600);
    for address in ["0.0.0.0:0", "[::]:0", "192.0.2.10:9001"] {
        let env = with_var(
            service_env(UNREACHABLE_DB, &credentials),
            "SINGLE_NODE_GATEWAY_ADDR",
            address,
        );
        let output = refused(&env).await;
        assert!(output.contains("loopback"), "{address}: {output}");
    }
}

#[tokio::test]
// memory—v1: The credentials file and every limit must be named explicitly.
async fn credentials_and_limits_are_required_and_checked() {
    let dir = TempDir::new("inputs");
    let credentials = write_credentials(dir.path(), 0o600);
    let mut env = service_env(UNREACHABLE_DB, &credentials);
    env.retain(|(name, _)| name != "ASTRAL_MEMORY_V1_CREDENTIALS_FILE");
    let output = refused(&env).await;
    assert!(
        output.contains("ASTRAL_MEMORY_V1_CREDENTIALS_FILE"),
        "{output}"
    );

    let env = with_var(
        service_env(UNREACHABLE_DB, &credentials),
        "ASTRAL_MEMORY_V1_ACKNOWLEDGE_LIMITS",
        "writer-coverage,everything",
    );
    let output = refused(&env).await;
    assert!(output.contains("everything"), "{output}");
}

#[tokio::test]
// memory—v1: A credentials file open to group or others is refused before the database. Where
// permissions cannot be verified at all, the file is refused for that reason instead.
async fn insecure_credentials_file_is_refused() {
    let dir = TempDir::new("insecure");
    let credentials = write_credentials(dir.path(), 0o644);
    let output = refused(&service_env(UNREACHABLE_DB, &credentials)).await;
    if cfg!(unix) {
        assert!(output.contains("0600"), "{output}");
    } else {
        assert!(output.contains("cannot be verified"), "{output}");
    }
    assert!(
        !output.contains("memory-v1 candidate database"),
        "the credentials gate precedes any database access\n{output}"
    );
}

#[tokio::test]
// memory—v1: An unreachable database stops the start; nothing is served from nothing. The candidate
// read follows the credentials gate, which refuses every file whose mode cannot be verified, so this
// case runs on Unix only.
async fn unreachable_database_is_refused() {
    if !cfg!(unix) {
        report_skip(
            "the candidate-database refusal needs Unix: the credentials gate refuses first on this platform",
        );
        return;
    }
    let dir = TempDir::new("unreachable");
    let credentials = write_credentials(dir.path(), 0o600);
    let output = refused(&service_env(UNREACHABLE_DB, &credentials)).await;
    assert!(output.contains("candidate database"), "{output}");
}

// ───────────────── Part B: database-backed end-to-end (ignored) ─────────────────

// memory—v1: The reviewed candidate DDL, extracted unchanged from its design document.
//
// The document keeps the DDL inside one block comment on purpose. This takes exactly
// the text inside that comment and accepts nothing but the nine expected
// `CREATE TABLE memory_*` statements.
fn candidate_ddl() -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../Docs/memory-v1/数据库结构候选.sql");
    let text = std::fs::read_to_string(&path).expect("read the candidate DDL document");
    let start = text
        .find("/* OFFLINE CANDIDATE")
        .expect("the candidate DDL block comment");
    let block = &text[start..];
    let body_start = block.find('\n').expect("the marker line ends") + 1;
    let body_end = block.rfind("*/").expect("the block comment closes");
    let sql = block[body_start..body_end]
        .lines()
        .filter(|line| !line.trim_start().starts_with("--"))
        .collect::<Vec<_>>()
        .join("\n");
    let statements: Vec<String> = sql
        .split(';')
        .map(str::trim)
        .filter(|statement| !statement.is_empty())
        .map(str::to_owned)
        .collect();
    let expected = [
        "memory_user",
        "memory_identity_card",
        "memory_tenant",
        "memory_user_card",
        "memory_rule_set",
        "memory_rule_set_version",
        "memory_card_rule_set_binding",
        "memory_binding_confirmation",
        "memory_rule_set_change_confirmation",
    ];
    assert_eq!(
        statements.len(),
        expected.len(),
        "unexpected DDL statements"
    );
    for (statement, table) in statements.iter().zip(expected) {
        assert!(
            statement.starts_with(&format!("CREATE TABLE {table} (")),
            "unexpected DDL statement for {table}: {statement}"
        );
        assert!(
            !statement.contains("/*") && !statement.contains("*/"),
            "unexpected comment marker in {table}"
        );
    }
    statements
}

// memory—v1: Only a generated run-scoped name may ever be created or dropped.
fn assert_run_database_name(name: &str) {
    let suffix = name
        .strip_prefix(RUN_DATABASE_PREFIX)
        .unwrap_or_else(|| panic!("not a run-scoped database name: {name}"));
    assert!(
        suffix.len() == 16
            && suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "not a run-scoped database name: {name}"
    );
    assert!(!PROTECTED_DATABASES.contains(&name));
}

// memory—v1: The server URL with the database replaced by `database`.
fn url_for_database(admin_url: &str, database: &str) -> String {
    let (base, query) = match admin_url.split_once('?') {
        Some((base, query)) => (base, Some(query)),
        None => (admin_url, None),
    };
    let (scheme, rest) = base.split_once("://").expect("a scheme://authority URL");
    let authority = rest.split('/').next().unwrap();
    let mut url = format!("{scheme}://{authority}/{database}");
    if let Some(query) = query {
        url.push('?');
        url.push_str(query);
    }
    url
}

// memory—v1: Table count and a hash of the sorted table names (metadata only, no row read).
async fn inventory(pool: &MySqlPool, schema: &str) -> (usize, String) {
    let rows = sqlx::query(
        "SELECT CAST(TABLE_NAME AS CHAR) AS n FROM information_schema.TABLES \
         WHERE TABLE_SCHEMA = ? ORDER BY TABLE_NAME",
    )
    .bind(schema)
    .fetch_all(pool)
    .await
    .expect("read table names");
    let mut hasher = Sha256::new();
    for row in &rows {
        let name: String = row.try_get("n").unwrap();
        hasher.update(name.as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    (
        rows.len(),
        digest.iter().map(|byte| format!("{byte:02x}")).collect(),
    )
}

// memory—v1: One hashed rule-set version of the closed rule grammar (version 1).
fn version_row(rule_set_id: [u8; 16], content: &[u8]) -> RuleSetVersionRow {
    let version = vec![1];
    let timestamp = vec![1];
    let hash_input_bytes = canonical_version_bytes(&version, content, &timestamp);
    let hash_bytes = Sha256::digest(&hash_input_bytes).to_vec();
    RuleSetVersionRow {
        rule_set_id,
        version_bytes: version,
        content_bytes: content.to_vec(),
        timestamp_bytes: timestamp,
        hash_input_bytes,
        hash_bytes,
    }
}

// memory—v1: Seed the fixture: two users with dual cards in one tenant, shared rule sets,
// every binding confirmed. Mirrors the in-process full-path fixture row for row.
async fn seed_fixture(pool: &MySqlPool) -> usize {
    let read = br#"{"rules":[{"ruleId":"R5","resource":"permission_rule","action":"read","effect":"ALLOW"}]}"#;
    let deny = br#"{"rules":[{"ruleId":"R6","resource":"permission_rule","action":"read","effect":"DENY"}]}"#;
    let mut rows = 0;
    let mut run = |sql: &'static str| {
        rows += 1;
        sqlx::query(sql)
    };
    for user in [ALICE, BOB] {
        run("INSERT INTO memory_user (user_id) VALUES (?)")
            .bind(user.to_vec())
            .execute(pool)
            .await
            .unwrap();
    }
    for (card, user) in [([0x12; 16], ALICE), ([0x22; 16], BOB)] {
        run("INSERT INTO memory_identity_card (identity_card_id, user_id) VALUES (?, ?)")
            .bind(card.to_vec())
            .bind(user.to_vec())
            .execute(pool)
            .await
            .unwrap();
    }
    run("INSERT INTO memory_tenant (tenant_id, parent_tenant_id) VALUES (?, NULL)")
        .bind(TENANT.to_vec())
        .execute(pool)
        .await
        .unwrap();
    for (card, user) in [
        (CARD_ALLOW, ALICE),
        (CARD_OVERLAY_DENY, ALICE),
        (CARD_UNBOUND, ALICE),
        (CARD_BOB, BOB),
    ] {
        run("INSERT INTO memory_user_card (user_card_id, user_id, tenant_id) VALUES (?, ?, ?)")
            .bind(card.to_vec())
            .bind(user.to_vec())
            .bind(TENANT.to_vec())
            .execute(pool)
            .await
            .unwrap();
    }
    for rule_set in [RULES_READ, RULES_DENY] {
        run("INSERT INTO memory_rule_set (rule_set_id, owner_tenant_id) VALUES (?, ?)")
            .bind(rule_set.to_vec())
            .bind(TENANT.to_vec())
            .execute(pool)
            .await
            .unwrap();
    }
    for (rule_set, content) in [(RULES_READ, &read[..]), (RULES_DENY, &deny[..])] {
        let row = version_row(rule_set, content);
        run("INSERT INTO memory_rule_set_version \
             (rule_set_id, version_bytes, content_bytes, timestamp_bytes, hash_input_bytes, hash_bytes) \
             VALUES (?, ?, ?, ?, ?, ?)")
            .bind(row.rule_set_id.to_vec())
            .bind(row.version_bytes)
            .bind(row.content_bytes)
            .bind(row.timestamp_bytes)
            .bind(row.hash_input_bytes)
            .bind(row.hash_bytes)
            .execute(pool)
            .await
            .unwrap();
    }
    let bindings = [
        ([0x51; 16], CARD_ALLOW, RULES_READ, "BASE"),
        ([0x52; 16], CARD_OVERLAY_DENY, RULES_READ, "BASE"),
        ([0x53; 16], CARD_OVERLAY_DENY, RULES_DENY, "OVERLAY"),
        ([0x54; 16], CARD_BOB, RULES_READ, "BASE"),
    ];
    for (binding, card, rule_set, layer) in bindings {
        run("INSERT INTO memory_card_rule_set_binding \
             (binding_id, user_card_id, rule_set_id, binding_layer) VALUES (?, ?, ?, ?)")
        .bind(binding.to_vec())
        .bind(card.to_vec())
        .bind(rule_set.to_vec())
        .bind(layer)
        .execute(pool)
        .await
        .unwrap();
    }
    for (binding, _, rule_set, _) in bindings {
        run("INSERT INTO memory_binding_confirmation \
             (confirmation_id, binding_id, rule_set_id, version_bytes, confirmer_user_id, \
              scope_bytes, operation_id, confirmed_at_bytes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
        .bind([binding[0] + 0x10; 16].to_vec())
        .bind(binding.to_vec())
        .bind(rule_set.to_vec())
        .bind(vec![1_u8])
        .bind(ALICE.to_vec())
        .bind(vec![1_u8])
        .bind(vec![1_u8])
        .bind(vec![1_u8])
        .execute(pool)
        .await
        .unwrap();
    }
    rows
}

// memory—v1: One HTTP reply.
struct Reply {
    status: u16,
    cache_control: Option<String>,
    body: Value,
}

// memory—v1: Send one request to the running service.
async fn call(
    client: &reqwest::Client,
    addr: SocketAddr,
    method: reqwest::Method,
    path: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> Reply {
    let label = format!("{method} {path}");
    let mut request = client.request(method, format!("http://{addr}{path}"));
    if let Some(token) = bearer {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.expect("the service answered");
    let status = response.status().as_u16();
    // The run record: method, path and status only, never a credential or a body.
    println!("memory-v1 e2e: {label} -> {status}");
    let cache_control = response
        .headers()
        .get("cache-control")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = response.json::<Value>().await.unwrap_or(Value::Null);
    Reply {
        status,
        cache_control,
        body,
    }
}

// memory—v1: Login and return the bearer credential, asserting success.
async fn login(client: &reqwest::Client, addr: SocketAddr, who: &str, card: [u8; 16]) -> String {
    let password = format!("{who}-secret");
    let reply = call(
        client,
        addr,
        reqwest::Method::POST,
        "/api/v1/auth/sessions",
        None,
        Some(json!({
            "identifier": who,
            "password": password,
            "userCardId": MemoryId::from_bytes(card).to_string(),
        })),
    )
    .await;
    assert_eq!(reply.status, 200, "login {who}: {}", reply.body);
    reply.body["data"]["accessToken"]
        .as_str()
        .unwrap()
        .to_owned()
}

// memory—v1: The lifecycle through the real binary and a real database cold load.
async fn lifecycle(running: &mut Running, expected_rows: usize) {
    let ready = running
        .wait_ready(Duration::from_secs(120))
        .await
        .unwrap_or_else(|failure| panic!("{failure}"));
    assert!(ready.contains("grade=Experimental"), "{ready}");
    assert!(ready.contains(&format!("rows={expected_rows} ")), "{ready}");
    for limit in AdoptionLimit::EXPERIMENTAL {
        assert!(
            ready.contains(limit.name()),
            "{limit:?} missing from {ready}"
        );
    }
    let addr: SocketAddr = ready
        .split_whitespace()
        .find_map(|part| part.strip_prefix("addr="))
        .expect("an addr= field")
        .parse()
        .unwrap();
    assert!(addr.ip().is_loopback(), "{ready}");
    println!("memory-v1 e2e: {ready}");

    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap();
    let get = reqwest::Method::GET;
    let post = reqwest::Method::POST;

    // Unauthenticated: refused at the Gateway.
    let reply = call(&client, addr, get.clone(), REGISTRY, None, None).await;
    assert_eq!(reply.status, 401, "{}", reply.body);

    // Login → authorized read.
    let alice = login(&client, addr, "alice", CARD_ALLOW).await;
    let reply = call(&client, addr, get.clone(), REGISTRY, Some(&alice), None).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.body["success"], true, "{}", reply.body);
    assert!(
        reply.body["data"].as_array().is_some_and(|entries| entries
            .iter()
            .any(|entry| entry["resourceType"] == "permission_rule")),
        "{}",
        reply.body
    );

    // The login response is never cached and carries the server lifetime.
    let reply = call(
        &client,
        addr,
        post.clone(),
        "/api/v1/auth/sessions",
        None,
        Some(json!({
            "identifier": "alice",
            "password": "alice-secret",
            "userCardId": MemoryId::from_bytes(CARD_ALLOW).to_string(),
        })),
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.cache_control.as_deref(), Some("no-store"));
    assert_eq!(reply.body["data"]["expiresIn"], 1_800);

    // Decisions come from the database rows loaded at startup, per session card.
    let overlay = login(&client, addr, "alice", CARD_OVERLAY_DENY).await;
    let reply = call(&client, addr, get.clone(), REGISTRY, Some(&overlay), None).await;
    assert_eq!(reply.status, 403, "{}", reply.body);
    assert_eq!(reply.body["reasonCode"], "AUTHORIZATION_RULE_DENIED");
    let unbound = login(&client, addr, "alice", CARD_UNBOUND).await;
    let reply = call(&client, addr, get.clone(), REGISTRY, Some(&unbound), None).await;
    assert_eq!(reply.status, 403, "{}", reply.body);
    let bob = login(&client, addr, "bob", CARD_BOB).await;
    let reply = call(&client, addr, get.clone(), REGISTRY, Some(&bob), None).await;
    assert_eq!(reply.status, 200, "{}", reply.body);

    // A route not adapted to memory—v1 stays pending.
    let reply = call(
        &client,
        addr,
        get.clone(),
        "/main/api/v1/permission-rules",
        Some(&bob),
        None,
    )
    .await;
    assert_eq!(reply.status, 503, "{}", reply.body);
    assert_eq!(reply.body["reasonCode"], "AUTHORIZATION_ROUTE_NOT_ADAPTED");

    // Logout revokes the session.
    let reply = call(
        &client,
        addr,
        post.clone(),
        "/api/v1/auth/sessions/logout",
        Some(&alice),
        None,
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let reply = call(&client, addr, get.clone(), REGISTRY, Some(&alice), None).await;
    assert_eq!(reply.status, 401, "{}", reply.body);
    let reply = call(&client, addr, get, REGISTRY, Some(&bob), None).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
}

// memory—v1: Ask the process to stop the way an operator would (SIGTERM). Unix only.
#[cfg(unix)]
fn terminate(running: &Running) {
    let pid = running.child.id().expect("the service is still running");
    let pid = libc::pid_t::try_from(pid).expect("a process id fits in pid_t");
    assert!(pid > 0, "a child process id is positive");
    // SAFETY: `pid` names this test's own child process, which is still running. SIGTERM
    // only asks it to drain and exit, and the result is checked below.
    let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
    assert_eq!(rc, 0, "send SIGTERM: {}", std::io::Error::last_os_error());
}

// memory—v1: Non-Unix runs return SKIP before they reach this stub.
#[cfg(not(unix))]
fn terminate(_running: &Running) {
    unreachable!("the SIGTERM scenario returns SKIP before it stops the service");
}

// memory—v1: Report a platform SKIP on stderr, where libtest's output capture cannot hide it.
fn report_skip(reason: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "[SKIP] {reason}");
}

// memory—v1: The end-to-end server must be loopback. The host is compared the way the production
// loopback gate compares it: IPv6 brackets are stripped and the name is case-insensitive.
fn is_loopback_admin_host(options: &MySqlConnectOptions) -> bool {
    let host = options
        .get_host()
        .trim_matches(|c: char| c == '[' || c == ']')
        .to_ascii_lowercase();
    matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1")
}

#[test]
// memory—v1: The loopback guard of the end-to-end run accepts bracketed IPv6 and refuses remote
// hosts. It parses URLs only: no socket, no database and no environment variable.
fn end_to_end_loopback_guard_accepts_ipv6_and_refuses_remote_hosts() {
    for (url, loopback) in [
        ("mysql://u:p@127.0.0.1:3306", true),
        ("mysql://u:p@localhost:3306", true),
        ("mysql://u:p@[::1]:3306", true),
        ("mysql://u:p@[2001:db8::1]:3306", false),
        ("mysql://u:p@db.example.com:3306", false),
    ] {
        let options: MySqlConnectOptions = url.parse().expect("a valid MySQL URL");
        assert_eq!(
            is_loopback_admin_host(&options),
            loopback,
            "{url} resolves to host {}",
            options.get_host()
        );
    }
}

#[tokio::test]
#[ignore = "needs ASTRAL_MEMORY_V1_E2E_ADMIN_URL: a loopback MySQL server URL; creates and drops one run-scoped database"]
// memory—v1: Cold-load a run-scoped database, serve the real lifecycle, stop, drop the database.
async fn real_service_end_to_end_against_a_run_scoped_database() {
    // Configuration is checked on every platform first: a missing or non-loopback server is an
    // error, never a silent skip.
    let admin_url = std::env::var("ASTRAL_MEMORY_V1_E2E_ADMIN_URL")
        .expect("ASTRAL_MEMORY_V1_E2E_ADMIN_URL must name a loopback MySQL server");
    let options: MySqlConnectOptions = admin_url.parse().expect("a valid MySQL URL");
    assert!(
        is_loopback_admin_host(&options),
        "the end-to-end server must be loopback (an SSH tunnel)"
    );
    if !cfg!(unix) {
        report_skip(
            "the end-to-end scenario needs a Unix host: the service refuses a credentials file whose 0600 mode cannot be verified here, and the SIGTERM drain needs a Unix signal; no database was created",
        );
        return;
    }
    let admin = MySqlPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(20))
        .connect(&admin_url)
        .await
        .expect("connect to the end-to-end server");

    // The protected databases are only ever listed by table name, before and after.
    let mut protected_before = Vec::new();
    for name in PROTECTED_DATABASES {
        protected_before.push((name, inventory(&admin, name).await));
    }

    let database = format!(
        "{RUN_DATABASE_PREFIX}{}",
        &uuid::Uuid::new_v4().simple().to_string()[..16]
    );
    assert_run_database_name(&database);
    sqlx::query(&format!(
        "CREATE DATABASE `{database}` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci"
    ))
    .execute(&admin)
    .await
    .expect("create the run-scoped database");

    // Everything after creation runs under a guard so the database is always dropped.
    let scenario_admin_url = admin_url.clone();
    let scenario_database = database.clone();
    let scenario = tokio::spawn(async move {
        let run_url = url_for_database(&scenario_admin_url, &scenario_database);
        let pool = MySqlPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(20))
            .connect(&run_url)
            .await
            .expect("connect to the run-scoped database");
        for statement in candidate_ddl() {
            sqlx::query(&statement)
                .execute(&pool)
                .await
                .unwrap_or_else(|error| panic!("apply candidate DDL: {error}\n{statement}"));
        }
        let rows = seed_fixture(&pool).await;
        pool.close().await;

        let dir = TempDir::new("e2e");
        let credentials = write_credentials(dir.path(), 0o600);
        let cwd = TempDir::new("e2e-cwd");
        let mut running = start(&service_env(&run_url, &credentials), cwd.path());
        lifecycle(&mut running, rows).await;

        // After the cold load the service holds no database connection.
        let observer = MySqlPoolOptions::new()
            .max_connections(1)
            .connect(&scenario_admin_url)
            .await
            .unwrap();
        let (connections,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE DB = ?")
                .bind(&scenario_database)
                .fetch_one(&observer)
                .await
                .unwrap();
        assert_eq!(
            connections, 0,
            "the service must not keep the database open"
        );
        observer.close().await;

        terminate(&running);
        let status = running.exit(Duration::from_secs(60)).await;
        assert!(
            status.success(),
            "graceful stop must exit 0: {status:?}\n{}",
            running.output()
        );
        let output = running.output();
        assert!(!output.contains("panicked"), "{output}");
    });
    let outcome = scenario.await;

    // Teardown runs whatever the scenario did.
    assert_run_database_name(&database);
    let dropped = sqlx::query(&format!("DROP DATABASE `{database}`"))
        .execute(&admin)
        .await;
    let (remaining,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?")
            .bind(&database)
            .fetch_one(&admin)
            .await
            .unwrap();
    let mut protected_unchanged = true;
    for (name, before) in &protected_before {
        protected_unchanged &= inventory(&admin, name).await == *before;
    }
    admin.close().await;

    dropped.expect("drop the run-scoped database");
    assert_eq!(remaining, 0, "the run-scoped database must be gone");
    assert!(
        protected_unchanged,
        "a protected database's table list changed"
    );
    if let Err(error) = outcome {
        std::panic::resume_unwind(error.into_panic());
    }
}
