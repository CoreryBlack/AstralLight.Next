//! memory—v1: The experimental real service, driven over real loopback TCP.
//!
//! These tests run the same `adopt_rows` → `assemble` → `serve` sequence as the
//! service entry point and talk to it through a real socket with plain HTTP/1.1,
//! so the Gateway, Identity, TrustGraph and the request-scoped reader are exercised
//! across a process-local network boundary rather than through `oneshot`.
//!
//! What is stood in for: the database. `adopt_rows` receives the fixture rows and the
//! cold-load facts the test itself attests (the adapter's real facts come from
//! `capture_unverified_candidate_rows` and are covered by its own tests and by the
//! database-backed end-to-end run). Nothing here proves database provenance,
//! production adoption or authorization of any real data.

use std::net::SocketAddr;
use std::time::Duration;

use astral_authorization_root::memory_v1_adoption::{AdoptionGrade, AdoptionLimit, ColdLoadFacts};
use astral_authorization_root::memory_v1_root::{process_root_handle, RootError, RootStatus};
use astral_common::config::AppConfig;
use astral_identity::memory_v1_service::MemoryV1FileCredentials;
use astral_types::memory_v1::MemoryId;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;

use super::{adopt_rows, assemble, readiness_line, serve};
use crate::memory_v1_composition::full_path_tests::{
    fixture, ALICE, BOB, CARD_ALLOW, CARD_BOB, CARD_OVERLAY_DENY, CARD_UNBOUND, REGISTRY,
};

const LOGIN: &str = "/api/v1/auth/sessions";
const LOGOUT: &str = "/api/v1/auth/sessions/logout";
const UNADAPTED: &str = "/main/api/v1/permission-rules";

// memory—v1: One decoded HTTP response.
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Value,
}

impl Reply {
    // memory—v1: A response header by case-insensitive name.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

// memory—v1: Decode a `Transfer-Encoding: chunked` body.
fn dechunk(mut raw: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    loop {
        let Some(line_end) = raw.windows(2).position(|pair| pair == b"\r\n") else {
            return decoded;
        };
        let size = usize::from_str_radix(
            std::str::from_utf8(&raw[..line_end])
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .trim(),
            16,
        )
        .unwrap();
        raw = &raw[line_end + 2..];
        if size == 0 || raw.len() < size {
            return decoded;
        }
        decoded.extend_from_slice(&raw[..size]);
        raw = raw.get(size + 2..).unwrap_or_default();
    }
}

// memory—v1: Send one HTTP/1.1 request over a fresh connection and decode the response.
async fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    json_body: Option<&Value>,
    extra_headers: &[(&str, &str)],
) -> Reply {
    let mut stream = TcpStream::connect(addr)
        .await
        .expect("connect to the service");
    let body = json_body.map(Value::to_string).unwrap_or_default();
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    if let Some(token) = bearer {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if json_body.is_some() {
        request.push_str("Content-Type: application/json\r\n");
    }
    for (name, value) in extra_headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
        .await
        .expect("the service answered within the deadline")
        .unwrap();
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("a complete HTTP response head");
    let head = std::str::from_utf8(&raw[..split]).unwrap();
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    let payload = &raw[split + 4..];
    let chunked = headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding") && value.eq_ignore_ascii_case("chunked")
    });
    let payload = if chunked {
        dechunk(payload)
    } else {
        payload.to_vec()
    };
    Reply {
        status,
        headers,
        body: serde_json::from_slice(&payload).unwrap_or(Value::Null),
    }
}

// memory—v1: The login body a client sends; the card is an explicit choice.
fn login_body(identifier: &str, password: &str, card: [u8; 16]) -> Value {
    json!({
        "identifier": identifier,
        "password": password,
        "userCardId": MemoryId::from_bytes(card).to_string(),
    })
}

// memory—v1: Login and return the issued bearer credential, asserting success.
async fn login(addr: SocketAddr, identifier: &str, password: &str, card: [u8; 16]) -> String {
    let reply = http(
        addr,
        "POST",
        LOGIN,
        None,
        Some(&login_body(identifier, password, card)),
        &[],
    )
    .await;
    assert_eq!(reply.status, 200, "login {identifier}: {}", reply.body);
    reply.body["data"]["accessToken"]
        .as_str()
        .expect("an access token")
        .to_owned()
}

// memory—v1: The trusted UTC clock used to attest the fixture's cold-load facts.
fn unix_now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

// memory—v1: The facts a database adapter would attest for these rows.
fn attested_facts(
    rows: &astral_authorization_root::memory_v1_db_rows::CandidateRows,
) -> ColdLoadFacts {
    let counts = rows.table_counts();
    ColdLoadFacts {
        schema_contract_version:
            astral_authorization_root::memory_v1_adoption::MEMORY_V1_CANDIDATE_SCHEMA_VERSION,
        schema_fingerprint: [7; 32],
        snapshot_counts: counts,
        scanned_counts: counts,
        captured_at_unix_seconds: unix_now(),
    }
}

// memory—v1: Run a test body in a child process, because the process root installs once
// per process. Returns `true` only in the child, which must then run the body; in the
// parent it spawns the child, asserts that it passed and returns `false`.
fn in_isolated_child(test_path: &str, child_env: &str) -> bool {
    if std::env::var_os(child_env).is_some() {
        return true;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test_path, "--nocapture"])
        .env(child_env, "1")
        .output()
        .expect("failed to start the isolated test process");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    false
}

// memory—v1: A private credentials file holding the two fixture users.
struct CredentialsFile {
    dir: std::path::PathBuf,
    path: std::path::PathBuf,
}

impl CredentialsFile {
    // memory—v1: Write the file with owner-only permissions.
    fn write() -> Self {
        let dir =
            std::env::temp_dir().join(format!("astral-memory-v1-service-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("credentials.json");
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
        std::fs::write(&path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        Self { dir, path }
    }
}

impl Drop for CredentialsFile {
    // memory—v1: Remove the credentials file and its directory.
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir(&self.dir);
    }
}

// memory—v1: Report a platform SKIP on stderr, where libtest's output capture cannot hide it.
fn report_skip(reason: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "[SKIP] {reason}");
}

// memory—v1: Archived bodies count towards cold capture coverage, not the
// live source-key count. Missing even one archived row invalidates adoption.
#[test]
fn cold_archive_coverage_is_distinct_from_live_digest_capacity() {
    use astral_authorization_root::memory_v1_digest::MAX_ROOT_DIGEST_KEYS;
    use astral_authorization_root::memory_v1_rules::{canonical_version_bytes, version_digest};

    if !in_isolated_child(
        "memory_v1_service::lifecycle_tests::cold_archive_coverage_is_distinct_from_live_digest_capacity",
        "ASTRAL_MEMORY_V1_ARCHIVE_COVERAGE_CHILD",
    ) {
        return;
    }
    let (mut rows, _) = fixture();
    let current = rows.rule_set_versions[0].clone();
    for n in 0..MAX_ROOT_DIGEST_KEYS {
        let mut archived = current.clone();
        archived.version_bytes = u64::try_from(n).unwrap().to_be_bytes().to_vec();
        archived.hash_input_bytes = canonical_version_bytes(
            &archived.version_bytes,
            &archived.content_bytes,
            &archived.timestamp_bytes,
        );
        archived.hash_bytes = version_digest(&archived.hash_input_bytes);
        rows.rule_set_versions.push(archived);
    }
    // The binding's original confirmation remains valid even though the
    // version it names is no longer the rule set's current source.
    rows.binding_confirmations[0].version_bytes =
        rows.rule_set_versions.last().unwrap().version_bytes.clone();
    let facts = attested_facts(&rows);
    let owner = super::install_rows(rows).unwrap();
    owner
        .install_registry(&super::registry_declarations())
        .unwrap();
    let mut short = facts;
    short.scanned_counts.rule_set_versions -= 1;
    short.snapshot_counts = short.scanned_counts;
    assert!(owner
        .adopt_experimental(&short, &AdoptionLimit::EXPERIMENTAL)
        .is_err());
    assert_eq!(
        owner.handle().metadata().unwrap().status,
        RootStatus::Candidate
    );
    let live = owner
        .adopt_experimental(&facts, &AdoptionLimit::EXPERIMENTAL)
        .unwrap();
    assert_eq!(live.status, RootStatus::Serving);
    let record = owner.handle().adoption_record().unwrap().unwrap();
    assert_eq!(record.counts, Some(facts.snapshot_counts));
}

// memory—v1: Active cards, bindings and confirmations coexist in one serving root.
#[test]
fn cold_install_serves_active_keys_above_the_old_digest_limit() {
    if !in_isolated_child(
        "memory_v1_service::lifecycle_tests::cold_install_serves_active_keys_above_the_old_digest_limit",
        "ASTRAL_MEMORY_V1_LIVE_CAPACITY_CHILD",
    ) {
        return;
    }
    let (mut rows, _) = fixture();
    let card = rows.user_cards[0].clone();
    let binding = rows.bindings[0].clone();
    let confirmation = rows.binding_confirmations[0].clone();
    for n in 1..=1500u128 {
        let id = n.to_be_bytes();
        let mut card = card.clone();
        card.user_card_id = id;
        rows.user_cards.push(card);
        let mut binding = binding.clone();
        binding.binding_id = id;
        binding.user_card_id = id;
        rows.bindings.push(binding);
        let mut confirmation = confirmation.clone();
        confirmation.confirmation_id = id;
        confirmation.binding_id = id;
        rows.binding_confirmations.push(confirmation);
    }
    let facts = attested_facts(&rows);
    let owner = adopt_rows(rows, &facts, &AdoptionLimit::EXPERIMENTAL).unwrap();
    let root = owner.handle();
    assert_eq!(
        Some(root.metadata().unwrap().row_count),
        facts.snapshot_counts.total()
    );
    let reader = root.begin_request(uuid::Uuid::new_v4()).unwrap();
    let impact = reader.read_impact(binding.rule_set_id).unwrap();
    assert_eq!(impact.binding_ids.len(), 1503);
    for n in 1..=1500u128 {
        assert!(impact.card_ids.contains(&n.to_be_bytes()));
    }
    for id in [1u128.to_be_bytes(), 1500u128.to_be_bytes()] {
        reader
            .read_card(id, |context| {
                assert_eq!(context.user.user_id, ALICE);
                assert_eq!(context.card.user_card_id, id);
                assert_eq!(context.bindings.len(), 1);
                let entry = &context.bindings[0];
                assert_eq!(entry.binding.binding_id, id);
                assert_eq!(entry.selected.unwrap().rule_set_id, binding.rule_set_id);
                assert_eq!(entry.confirmations.len(), 1);
                assert_eq!(entry.confirmations[0].binding_id, id);
            })
            .unwrap();
    }
}

// memory—v1: Adoption acknowledgements do not prove recovery or formal readiness.
#[test]
fn readiness_reports_unverified_recovery_without_opening_a_listener() {
    if in_isolated_child(
        "memory_v1_service::lifecycle_tests::readiness_reports_unverified_recovery_without_opening_a_listener",
        "ASTRAL_MEMORY_V1_READY_STATUS_CHILD",
    ) {
        let (rows, _) = fixture();
        let facts = attested_facts(&rows);
        let owner = adopt_rows(rows, &facts, &AdoptionLimit::EXPERIMENTAL).unwrap();
        let ready = readiness_line(&owner.handle(), "127.0.0.1:0".parse().unwrap()).unwrap();
        assert!(ready.contains("grade=Experimental"), "{ready}");
        assert!(ready.contains("persistence-recovery"), "{ready}");
        assert!(ready.contains("recovery=unverified"), "{ready}");
        assert!(ready.contains("formal_authorization=unverified"), "{ready}");
    }
}

#[test]
// memory—v1: Login → fail-closed authorization → logout over a real socket. The credentials gate
// refuses a file whose mode cannot be verified, so this run needs Unix.
fn real_service_lifecycle_over_loopback_tcp_isolated_process() {
    if !cfg!(unix) {
        report_skip(
            "the lifecycle run needs Unix: its credentials file cannot be verified on this platform",
        );
        return;
    }
    if in_isolated_child(
        "memory_v1_service::lifecycle_tests::real_service_lifecycle_over_loopback_tcp_isolated_process",
        "ASTRAL_MEMORY_V1_SERVICE_LIFECYCLE_CHILD",
    ) {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(real_service_lifecycle());
    }
}

// memory—v1: The acceptance scenario for the real service.
async fn real_service_lifecycle() {
    let credentials_file = CredentialsFile::write();
    let credentials = MemoryV1FileCredentials::load(&credentials_file.path).unwrap();
    let (rows, _selections) = fixture();
    let facts = attested_facts(&rows);

    // Adoption under the experimental grade records every unverified family.
    let owner = adopt_rows(rows, &facts, &AdoptionLimit::EXPERIMENTAL).unwrap();
    let root = owner.handle();
    assert_eq!(root.metadata().unwrap().status, RootStatus::Serving);
    let record = root.adoption_record().unwrap().expect("an adoption record");
    assert_eq!(record.grade, AdoptionGrade::Experimental);
    assert_eq!(record.unverified, AdoptionLimit::EXPERIMENTAL.to_vec());

    let mut config = AppConfig::default();
    config.gateway.hmac_secret = uuid::Uuid::new_v4().to_string();
    let composition = assemble(owner, config, credentials).unwrap();
    let budget = composition.request_scope_budget();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    assert!(addr.ip().is_loopback());
    let ready = readiness_line(&root, addr).unwrap();
    assert!(
        ready.starts_with("ASTRAL_MEMORY_V1_READY addr=127.0.0.1:"),
        "{ready}"
    );
    assert!(ready.contains("grade=Experimental"), "{ready}");
    for limit in AdoptionLimit::EXPERIMENTAL {
        assert!(
            ready.contains(limit.name()),
            "{limit:?} missing from: {ready}"
        );
    }

    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(serve(listener, composition.router(), async move {
        let _ = stop_rx.await;
    }));

    // 1. No credential: refused at the Gateway, even with forged internal identity.
    let reply = http(addr, "GET", REGISTRY, None, None, &[]).await;
    assert_eq!(reply.status, 401, "{}", reply.body);
    let reply = http(
        addr,
        "GET",
        REGISTRY,
        None,
        None,
        &[
            ("x-user-id", "999"),
            ("x-principal-kind", "PLATFORM_USER"),
            ("x-user-card-id", "999"),
            ("x-gateway-auth", "verified"),
        ],
    )
    .await;
    assert_eq!(
        reply.status, 401,
        "forged identity is never trusted: {}",
        reply.body
    );
    assert_eq!(budget.active(), 0);

    // 2. Login failures are mapped without leaking which part was wrong.
    let reply = http(
        addr,
        "POST",
        LOGIN,
        None,
        Some(&login_body("alice", "wrong", CARD_ALLOW)),
        &[],
    )
    .await;
    assert_eq!(reply.status, 401, "{}", reply.body);
    assert_eq!(reply.body["reasonCode"], "INVALID_CREDENTIALS");
    let reply = http(
        addr,
        "POST",
        LOGIN,
        None,
        Some(&login_body("bob", "bob-secret", CARD_ALLOW)),
        &[],
    )
    .await;
    assert_eq!(reply.status, 403, "{}", reply.body);
    assert_eq!(reply.body["reasonCode"], "CARD_NOT_OWNED");
    let reply = http(
        addr,
        "POST",
        LOGIN,
        None,
        Some(&json!({"identifier": "alice"})),
        &[],
    )
    .await;
    assert_eq!(reply.status, 400, "{}", reply.body);
    assert_eq!(reply.body["reasonCode"], "INVALID_REQUEST_BODY");

    // 3. A successful login issues a no-store bearer credential with the server lifetime.
    let reply = http(
        addr,
        "POST",
        LOGIN,
        None,
        Some(&login_body("alice", "alice-secret", CARD_ALLOW)),
        &[],
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert_eq!(reply.body["data"]["tokenType"], "Bearer");
    let expires_in = reply.body["data"]["expiresIn"]
        .as_i64()
        .expect("expiresIn is an integer");
    assert!(
        (1..=1_800).contains(&expires_in),
        "expiresIn must report positive remaining lifetime: {expires_in}"
    );
    let alice = reply.body["data"]["accessToken"]
        .as_str()
        .expect("an access token")
        .to_owned();

    // 4. An acknowledged experimental limit is not evidence of the confirmer's
    // authority or scope, so the lifecycle request stays pending.
    let reply = http(addr, "GET", REGISTRY, Some(&alice), None, &[]).await;
    assert_eq!(reply.status, 503, "{}", reply.body);
    assert_eq!(reply.body["reasonCode"], "AUTHORIZATION_CONTEXT_INVALID");
    // Forged internal headers on an authenticated request change nothing.
    let reply = http(
        addr,
        "GET",
        REGISTRY,
        Some(&alice),
        None,
        &[("x-user-id", "999"), ("x-user-card-id", "999")],
    )
    .await;
    assert_eq!(reply.status, 503, "{}", reply.body);
    assert_eq!(reply.body["reasonCode"], "AUTHORIZATION_CONTEXT_INVALID");
    assert_eq!(budget.active(), 0, "the request scope returned its slot");

    // 5. Unproven confirmation prevents rule ALLOW and DENY; an unbound card
    // remains a structural denial independent of confirmation rows. The missing
    // durable DENY audit and evidence proofs make its HTTP response a 503.
    let overlay = login(addr, "alice", "alice-secret", CARD_OVERLAY_DENY).await;
    let reply = http(addr, "GET", REGISTRY, Some(&overlay), None, &[]).await;
    assert_eq!(reply.status, 503, "{}", reply.body);
    assert_eq!(reply.body["reasonCode"], "AUTHORIZATION_CONTEXT_INVALID");
    let unbound = login(addr, "alice", "alice-secret", CARD_UNBOUND).await;
    let reply = http(addr, "GET", REGISTRY, Some(&unbound), None, &[]).await;
    assert_eq!(reply.status, 503, "{}", reply.body);
    assert_eq!(reply.body["decision"], "AUTHORIZATION_CARD_UNBOUND");
    assert_eq!(reply.body["reasonCode"], "AUTHORIZATION_AUDIT_UNAVAILABLE");
    let bob = login(addr, "bob", "bob-secret", CARD_BOB).await;
    let reply = http(addr, "GET", REGISTRY, Some(&bob), None, &[]).await;
    assert_eq!(reply.status, 503, "{}", reply.body);
    assert_eq!(reply.body["reasonCode"], "AUTHORIZATION_CONTEXT_INVALID");

    // 6. A route not adapted to memory—v1 stays pending; no legacy handler runs.
    let reply = http(addr, "GET", UNADAPTED, Some(&bob), None, &[]).await;
    assert_eq!(reply.status, 503, "{}", reply.body);
    assert_eq!(reply.body["reasonCode"], "AUTHORIZATION_ROUTE_NOT_ADAPTED");

    // 7. Logout revokes the session; the same credential is refused afterwards.
    let reply = http(addr, "POST", LOGOUT, Some(&alice), None, &[]).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.body["success"], true, "{}", reply.body);
    let reply = http(addr, "GET", REGISTRY, Some(&alice), None, &[]).await;
    assert_eq!(reply.status, 401, "{}", reply.body);
    let reply = http(addr, "POST", LOGOUT, Some(&alice), None, &[]).await;
    assert_eq!(reply.status, 401, "{}", reply.body);
    // Bob's independent session is unaffected and remains fail-closed.
    let reply = http(addr, "GET", REGISTRY, Some(&bob), None, &[]).await;
    assert_eq!(reply.status, 503, "{}", reply.body);
    assert_eq!(reply.body["reasonCode"], "AUTHORIZATION_CONTEXT_INVALID");
    assert_eq!(budget.active(), 0);

    // 8. Graceful stop: the server drains, then dropping the composition ends the root.
    stop_tx.send(()).unwrap();
    timeout(Duration::from_secs(10), server)
        .await
        .expect("the server stopped within the drain budget")
        .unwrap()
        .unwrap();
    assert_eq!(budget.active(), 0);
    drop(composition);
    assert!(matches!(root.metadata(), Err(RootError::OwnerGone)));
    assert!(
        TcpStream::connect(addr).await.is_err(),
        "the listener is gone"
    );
}

#[test]
// memory—v1: Adoption refuses to serve while any unverified family is unacknowledged.
fn unacknowledged_limits_refuse_adoption_isolated_process() {
    if in_isolated_child(
        "memory_v1_service::lifecycle_tests::unacknowledged_limits_refuse_adoption_isolated_process",
        "ASTRAL_MEMORY_V1_SERVICE_UNACK_CHILD",
    ) {
        let (rows, _selections) = fixture();
        let facts = attested_facts(&rows);
        // Naming only some limits leaves the rest unacknowledged: nothing serves.
        let partial = &AdoptionLimit::EXPERIMENTAL[..AdoptionLimit::EXPERIMENTAL.len() - 1];
        let error = match adopt_rows(rows, &facts, partial) {
            Ok(_) => panic!("a partial acknowledgement must not adopt"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("unacknowledged"),
            "unexpected refusal: {error:#}"
        );
        // The failed owner is gone and the root never served.
        assert!(matches!(process_root_handle(), Err(RootError::OwnerGone)));
    }
}

// memory—v1: A process-root refusal and the positive production-port control
// in the same binary. Only the isolated owner accepts synthetic evidence.
#[test]
fn production_service_opens_a_verified_journal_and_admits_a_listener_isolated_process() {
    if !cfg!(unix) {
        report_skip("the lifecycle run needs Unix for the credentials file mode");
        return;
    }
    if in_isolated_child(
        "memory_v1_service::lifecycle_tests::production_service_opens_a_verified_journal_and_admits_a_listener_isolated_process",
        "ASTRAL_MEMORY_V1_SERVICE_PRODUCTION_CHILD",
    ) {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(production_service_lifecycle());
    }
}

async fn production_service_lifecycle() {
    let credentials_file = CredentialsFile::write();
    let credentials = MemoryV1FileCredentials::load(&credentials_file.path).unwrap();
    let (rows, _selections) = fixture();
    let facts = attested_facts(&rows);

    // 1. Open (create) the durable journal in one private temp directory.
    let journal_dir =
        std::env::temp_dir().join(format!("astral-prod-journal-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&journal_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&journal_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    // Ordinary startup never creates genesis when an acknowledged journal
    // could have disappeared. The fixture bootstrap is separate and explicit.
    assert!(
        super::open_durable_journal(&journal_dir, super::production_fixture::INSTALLATION).is_err()
    );
    assert!(!journal_dir.join(super::JOURNAL_FILE_NAME).exists());
    let (journal, durability) = super::production_fixture::journal(&journal_dir);
    assert_eq!(journal.record_count(), 0);
    assert_eq!(journal.file_position(), 0);

    // 2. The same synthetic declarations must fail on the process root even
    // in a test-support build. A refusal cannot publish an adoption record.
    let input = super::production_fixture::input(facts.captured_at_unix_seconds);
    let process_owner = super::install_rows(rows.clone()).unwrap();
    process_owner
        .install_registry(&super::registry_declarations())
        .unwrap();
    assert!(matches!(
        process_owner.adopt_with_production_evidence(&facts, &input),
        Err(RootError::AdoptionEvidence(
            astral_authorization_root::memory_v1_adoption::AdoptionEvidenceError::Missing(
                "source provenance"
            )
        ))
    ));
    assert_eq!(
        process_owner.handle().metadata().unwrap().status,
        RootStatus::Candidate
    );
    assert_eq!(process_owner.handle().adoption_record().unwrap(), None);
    let owner = super::production_fixture::owner(rows);
    owner
        .install_registry(&super::registry_declarations())
        .unwrap();
    use std::sync::Arc;
    let (metadata, admission) = owner
        .adopt_with_production_evidence(&facts, &input)
        .expect("production adoption");
    assert_eq!(metadata.status, RootStatus::Serving);
    let root = owner.handle();
    let record = root.adoption_record().unwrap().unwrap();
    assert_eq!(record.grade, AdoptionGrade::Production);
    assert!(record.unverified.is_empty());
    // The capability validates against this exact root.
    assert_eq!(
        root.validate_production_admission(&admission).unwrap(),
        root.metadata().unwrap()
    );
    super::require_serving_root(&root).unwrap();

    // 3. Compose the production path with the durable commit owner.
    let mut config = AppConfig::default();
    config.gateway.hmac_secret = uuid::Uuid::new_v4().to_string();
    let composition = super::assemble_production(
        std::sync::Arc::new(owner),
        Arc::new(admission),
        (journal, durability),
        config,
        credentials,
    )
    .unwrap();
    let budget = composition.request_scope_budget();

    // 4. A real listener opens and the readiness line reports production.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ready = readiness_line(&root, addr).unwrap();
    assert!(ready.contains("grade=Production"), "{ready}");
    assert!(
        !ready.contains("persistence-recovery"),
        "no unverified limit may be listed: {ready}"
    );

    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let server = tokio::spawn(serve(listener, composition.router(), async move {
        let _ = stop_rx.await;
    }));

    // 5. Login works on the production listener; the registry request carries
    //    the full fail-closed chain. (The engine rules of the fixture are
    //    exercised in the composition contract tests.)
    let reply = http(
        addr,
        "POST",
        LOGIN,
        None,
        Some(&login_body("alice", "alice-secret", CARD_ALLOW)),
        &[],
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let alice = reply.body["data"]["accessToken"].as_str().unwrap();
    let allowed = http(addr, "GET", REGISTRY, Some(alice), None, &[]).await;
    assert_eq!(allowed.status, 200, "{}", allowed.body);
    let unbound = login(addr, "alice", "alice-secret", CARD_UNBOUND).await;
    let denied = http(addr, "GET", REGISTRY, Some(&unbound), None, &[]).await;
    assert_eq!(denied.status, 403, "{}", denied.body);
    assert_eq!(denied.body["decision"], "AUTHORIZATION_CARD_UNBOUND");
    let target = journal_dir.join(super::JOURNAL_FILE_NAME);
    let first_end = std::fs::metadata(&target).unwrap().len();
    assert!(first_end > 0);
    let second_deny = http(addr, "GET", REGISTRY, Some(&unbound), None, &[]).await;
    assert_eq!(second_deny.status, 403, "{}", second_deny.body);
    assert!(std::fs::metadata(&target).unwrap().len() > first_end);
    assert_eq!(budget.active(), 0);

    // 6. Graceful stop.
    stop_tx.send(()).unwrap();
    timeout(Duration::from_secs(10), server)
        .await
        .expect("the server stopped within the drain budget")
        .unwrap()
        .unwrap();
    drop(composition);
    assert!(matches!(root.metadata(), Err(RootError::OwnerGone)));
    assert!(super::open_durable_journal(&journal_dir, MemoryId::from_bytes([62; 16])).is_err());
    let (retained, sync) =
        super::open_durable_journal(&journal_dir, super::production_fixture::INSTALLATION).unwrap();
    assert_eq!(retained.record_count(), 2);
    for frame in retained.recovery_records() {
        use astral_trustgraph::service::memory_v1_mutation_coordinator::{
            decode_deny_journal_payload_with_origin, journal_producer_boot_id,
        };
        let (origin, observation) =
            decode_deny_journal_payload_with_origin(&frame.payload).unwrap();
        assert_eq!(origin, Some(journal_producer_boot_id()));
        assert_eq!(observation.operation_id(), frame.operation_id.as_bytes());
    }
    assert_eq!(retained.position().mutation_sequence(), 0);
    // The two valid, checkpointed frames alone cannot satisfy the recovery gate.
    let unavailable = sqlx::mysql::MySqlPoolOptions::new()
        .connect_lazy_with(sqlx::mysql::MySqlConnectOptions::new());
    unavailable.close().await;
    assert!(
        astral_single_node::memory_v1_recovery_owner::verify_applied_history(
            &unavailable,
            &retained,
            &sync,
        )
        .await
        .is_err()
    );
    drop((retained, sync));
    // Lose exactly the last acknowledged DENY. The remaining nonempty prefix
    // is internally valid, so only an independent tail can detect its loss.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&target)
        .unwrap();
    file.set_len(first_end).unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(
        super::open_durable_journal(&journal_dir, super::production_fixture::INSTALLATION).is_err()
    );
    assert_eq!(std::fs::metadata(&target).unwrap().len(), first_end);
    std::fs::remove_dir_all(&journal_dir).unwrap();
}

// memory—v1: Separate synthetic evidence from the real MySQL suites.
#[cfg(unix)]
#[path = "memory_v1_synthetic_scenarios.rs"]
mod synthetic_scenarios;

// memory—v1: Keep contention and soak measurements independently selectable.
#[cfg(unix)]
#[path = "memory_v1_writer_contention_tests.rs"]
mod writer_contention_tests;

#[cfg(unix)]
#[path = "memory_v1_soak_tests.rs"]
mod soak_tests;
