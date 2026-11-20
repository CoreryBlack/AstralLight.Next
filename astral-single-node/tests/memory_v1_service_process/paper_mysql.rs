//! memory—v1: Approved MySQL fixture, real child, private cutoff and warm governance.

#[path = "paper_mysql/expected.rs"]
mod expected;
#[path = "paper_mysql/relay.rs"]
mod relay;
#[path = "../../../tests-suite/src/paper_mysql_scope.rs"]
mod scope;

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use astral_authorization_root::memory_v1_db_rows::{CandidateRows, TableCounts};
use astral_db::memory_v1_candidate_loader::{
    capture_unverified_candidate_rows, CaptureBudget, UnverifiedCandidateRows,
};
use reqwest::{Client, Method};
use serde_json::{json, Value};
use sqlx::{ConnectOptions, Connection, Executor, MySqlConnection, MySqlPool, Row};
use url::Url;

use super::{
    call, login, seed_fixture, service_env, start, terminate, timeout, write_credentials, MemoryId,
    MySqlConnectOptions, MySqlPoolOptions, Running, TempDir, BOB, CARD_ALLOW, CARD_BOB,
    CARD_UNBOUND, REGISTRY, TENANT,
};
use relay::Relay;

const BUDGET: CaptureBudget = CaptureBudget {
    max_rows: 23,
    max_bytes: 16 * 1024,
};
const GOVERNANCE: &str = "/main/api/v1/governance";

fn fixture() -> (String, String, Url) {
    if !cfg!(unix) {
        panic!("the paper MySQL fixture requires Unix");
    }
    let run = std::env::var(scope::RUN_ENV).expect("missing fixture run id");
    let approved = std::env::var(scope::APPROVAL_ENV).expect("missing same-run operator approval");
    let url =
        Url::parse(&std::env::var(scope::URL_ENV).expect("missing dedicated paper MySQL URL"))
            .expect("invalid paper MySQL URL");
    let schema = scope::validate(&url, &run, &approved).unwrap_or_else(|error| panic!("{error}"));
    (run, schema, url)
}

fn options(url: &Url, schema: &str, port: u16) -> MySqlConnectOptions {
    let options: MySqlConnectOptions = url
        .as_str()
        .parse()
        .unwrap_or_else(|_| panic!("invalid MySQL connect options"));
    assert!(
        options.get_host().parse::<Ipv4Addr>().ok() == Some(Ipv4Addr::LOCALHOST)
            && options.get_port() == port
            && options.get_database() == Some(schema)
            && options.get_username() == url.username()
            && options.get_socket().is_none(),
        "SQLx and fixture scope disagree"
    );
    options.disable_statement_logging()
}

async fn pool(options: &MySqlConnectOptions) -> MySqlPool {
    MySqlPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(options.clone())
        .await
        .unwrap_or_else(|_| panic!("connect to approved MySQL fixture"))
}

async fn check_sql_scope(conn: &mut MySqlConnection, schema: &str, user: &str) {
    let (selected, version, account, roles): (String, String, String, String) =
        sqlx::query_as("SELECT DATABASE(), VERSION(), CURRENT_USER(), CURRENT_ROLE()")
            .fetch_one(&mut *conn)
            .await
            .unwrap_or_else(|_| panic!("read dedicated MySQL identity"));
    assert!(
        selected == schema
            && version.starts_with("8.0.")
            && roles == "NONE"
            && account
                .split_once('@')
                .is_some_and(|(name, _)| name == user),
        "fixture requires MySQL 8.0, selected run schema, exact account and no active roles"
    );
    // SHOW returns a server-dependent column name; read by ordinal on the text protocol.
    let grants = (&mut *conn)
        .fetch_all("SHOW GRANTS FOR CURRENT_USER()")
        .await
        .unwrap_or_else(|_| panic!("read fixture grants"));
    assert_eq!(
        grants.len(),
        2,
        "fixture account must not have extra grants"
    );
    let fixture_grant = format!("GRANT SELECT, INSERT ON `{schema}`.* TO ");
    let grant_text = |row: &sqlx::mysql::MySqlRow| {
        row.try_get::<String, _>(0)
            .unwrap_or_else(|_| panic!("decode fixture grant"))
    };
    let grants = [grant_text(&grants[0]), grant_text(&grants[1])];
    assert!(
        grants
            .iter()
            .any(|grant| grant.starts_with("GRANT USAGE ON *.* TO "))
            && grants.iter().any(|grant| grant.starts_with(&fixture_grant))
            && grants.iter().all(|grant| !grant.contains(" WITH ")),
        "fixture account must have only SELECT, INSERT on the exact run schema"
    );
    let (tables, triggers, cross_schema): (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()), \
         (SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE EVENT_OBJECT_SCHEMA = DATABASE()), \
         (SELECT COUNT(*) FROM information_schema.KEY_COLUMN_USAGE WHERE TABLE_SCHEMA = DATABASE() \
          AND REFERENCED_TABLE_SCHEMA <> DATABASE())",
    ).fetch_one(&mut *conn).await.unwrap_or_else(|_| panic!("check fixture metadata"));
    // Trigger visibility is privilege-dependent: the operator must also certify no triggers.
    assert_eq!(
        (tables, triggers, cross_schema),
        (9, 0, 0),
        "fixture metadata outside the allowlist"
    );
}

fn unknown(reason: &str) -> ! {
    eprintln!("[UNKNOWN] {reason}; reconcile the fixture and last proven phase before another run");
    panic!("paper MySQL evidence is incomplete");
}

async fn capture(
    pool: &MySqlPool,
    rows: &CandidateRows,
    counts: TableCounts,
) -> UnverifiedCandidateRows {
    let captured = capture_unverified_candidate_rows(pool, BUDGET)
        .await
        .unwrap_or_else(|_| panic!("bounded consistent snapshot failed; no receipt inferred"));
    assert!(
        captured.rows == *rows,
        "snapshot rows differ from the fixture oracle"
    );
    assert_eq!(Some(captured.row_count), counts.total());
    let report = captured.report.as_ref().expect("candidate capture report");
    assert!(
        !report.is_adoption_ready(),
        "SQL observation alone is not authority"
    );
    let facts = report
        .cold_load_facts()
        .expect("all nine table scans present");
    assert_eq!(facts.scanned_counts, counts);
    assert_eq!(facts.snapshot_counts, counts);
    captured
}

async fn seed(options: &MySqlConnectOptions, schema: &str) {
    // The lock belongs to this non-pooled connection and drops with it. It serializes
    // runner attempts; exclusive source DDL/writer ownership is an operator prerequisite.
    let mut conn = MySqlConnection::connect_with(options)
        .await
        .unwrap_or_else(|_| panic!("open dedicated fixture writer"));
    check_sql_scope(&mut conn, schema, options.get_username()).await;
    let lock: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(?, 0)")
        .bind(schema)
        .fetch_one(&mut conn)
        .await
        .unwrap_or_else(|_| panic!("acquire fixture ownership"));
    assert_eq!(lock, Some(1), "fixture already owned by another run");
    let observer = pool(options).await;
    capture(&observer, &CandidateRows::default(), TableCounts::default()).await;
    observer.close().await;
    let mut tx = conn
        .begin()
        .await
        .unwrap_or_else(|_| panic!("begin synthetic transaction"));
    if seed_fixture(&mut tx, true).await.ok() != Some(23) {
        if tx.rollback().await.is_err() {
            unknown("synthetic fixture rollback not acknowledged");
        }
        panic!("synthetic fixture insert failed; transaction rolled back");
    }
    if tx.commit().await.is_err() {
        unknown("synthetic fixture commit not acknowledged");
    }
    conn.close()
        .await
        .unwrap_or_else(|_| unknown("fixture writer close not confirmed"));
}

async fn ready(running: &mut Running) -> (SocketAddr, u64) {
    let ready = running
        .wait_ready(Duration::from_secs(90))
        .await
        .unwrap_or_else(|_| panic!("real service did not announce readiness"));
    let field = |key: &str| {
        ready
            .split_whitespace()
            .find_map(|part| part.strip_prefix(key))
            .unwrap()
    };
    assert_eq!(field("grade="), "Production");
    assert_eq!(field("rows="), "23");
    assert_eq!(field("unverified="), "");
    assert_eq!(field("recovery="), "unverified");
    assert_eq!(field("formal_authorization="), "unverified");
    let addr: SocketAddr = field("addr=").parse().unwrap();
    assert!(addr.ip().is_loopback());
    (addr, field("root_version=").parse().unwrap())
}

async fn publish(
    builder: reqwest::RequestBuilder,
    operation: &str,
    body: &Value,
    previous: u64,
) -> (u64, String) {
    println!("paper MySQL operation: dispatch {operation}");
    let response = builder
        .header("x-request-id", operation)
        .json(body)
        .send()
        .await
        .unwrap_or_else(|_| unknown("governance response not received"));
    let status = response.status();
    if status.is_server_error() {
        unknown("governance returned a server error without a publication receipt");
    }
    assert_eq!(
        status.as_u16(),
        200,
        "governance {operation} returned {status}"
    );
    let payload: Value = response
        .json()
        .await
        .unwrap_or_else(|_| unknown("governance receipt could not be read"));
    let data = &payload["data"];
    let version = data["rootVersion"].as_u64();
    let digest = data["rootDigest"].as_str().filter(|digest| {
        digest.len() == 64
            && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            && digest.bytes().any(|byte| byte != b'0')
    });
    match (data["operationId"].as_str(), version, digest) {
        (Some(id), Some(version), Some(digest))
            if id == operation && Some(version) == previous.checked_add(1) =>
        {
            println!("paper MySQL operation: receipt {operation} root={version} digest={digest}");
            (version, digest.to_owned())
        }
        _ => unknown("governance receipt did not bind to the expected operation and root"),
    }
}

async fn assert_registry(
    client: &Client,
    addr: SocketAddr,
    token: &str,
    status: u16,
    reason: Option<&str>,
) {
    let reply = call(client, addr, Method::GET, REGISTRY, Some(token), None).await;
    assert_eq!(reply.status, status, "unexpected registry decision");
    if let Some(reason) = reason {
        assert_eq!(reply.body["decision"], reason);
        assert!(
            reply.body["data"].is_null(),
            "denial must not disclose registry data"
        );
    } else {
        assert!(
            !reply.body["data"].is_null(),
            "admission must reach the registry handler"
        );
    }
}

async fn warm_governance(run: &str, addr: SocketAddr, initial_version: u64) {
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .timeout(Duration::from_secs(12))
        .build()
        .unwrap();
    let alice = login(&client, addr, "alice", CARD_ALLOW).await;
    let bob = login(&client, addr, "bob", CARD_BOB).await;
    let unbound = login(&client, addr, "alice", CARD_UNBOUND).await;
    assert_registry(&client, addr, &alice, 200, None).await;
    assert_registry(&client, addr, &bob, 200, None).await;
    assert_registry(
        &client,
        addr,
        &unbound,
        403,
        Some("AUTHORIZATION_CARD_UNBOUND"),
    )
    .await;

    // Each subject manages their own target under the binding's default self scope.
    let create = format!("{run}-card-create");
    let card_id = MemoryId::from_bytes([0x35; 16]);
    let (created, create_digest) = publish(
        client
            .post(format!("http://{addr}{GOVERNANCE}/user-cards"))
            .bearer_auth(&bob),
        &create,
        &json!({"user_card_id":card_id.to_string(), "user_id":MemoryId::from_bytes(BOB).to_string(),
            "tenant_id":MemoryId::from_bytes(TENANT).to_string()}),
        initial_version,
    )
    .await;
    let new_unbound = login(&client, addr, "bob", card_id.into_bytes()).await;
    assert_registry(
        &client,
        addr,
        &new_unbound,
        403,
        Some("AUTHORIZATION_CARD_UNBOUND"),
    )
    .await;
    assert_registry(&client, addr, &alice, 200, None).await;

    let revoke = format!("{run}-binding-remove");
    let (removed, remove_digest) = publish(
        client
            .delete(format!("http://{addr}{GOVERNANCE}/bindings"))
            .bearer_auth(&alice),
        &revoke,
        &json!({"binding_id":MemoryId::from_bytes([0x51; 16]).to_string()}),
        created,
    )
    .await;
    assert_ne!(
        create_digest, remove_digest,
        "the revocation must publish a different root"
    );
    assert_registry(&client, addr, &alice, 403, Some("AUTHORIZATION_NO_MATCH")).await;
    assert_registry(&client, addr, &bob, 200, None).await;
    println!("paper-mysql: warm_publications create={create} root={created} revoke={revoke} root={removed}");
}

async fn scenario(run: &str, schema: &str, mut url: Url) {
    let start_time = Instant::now();
    let direct = options(&url, schema, scope::PORT);
    seed(&direct, schema).await;
    let expected = expected::expected_rows();
    let observer = pool(&direct).await;
    let before = capture(&observer, &expected, expected::COUNTS).await;
    observer.close().await;
    println!(
        "paper-mysql: snapshot_exact schema={schema} tables=9 rows=23 elapsed_ms={}",
        start_time.elapsed().as_millis()
    );

    let relay = Relay::start(SocketAddr::from((Ipv4Addr::LOCALHOST, scope::PORT))).await;
    url.set_port(Some(relay.port()))
        .expect("set private relay port");
    let _ = options(&url, schema, relay.port());
    let files = TempDir::new("paper-mysql-credentials");
    let credentials = write_credentials(files.path(), 0o600);
    let cwd = TempDir::new("paper-mysql-cwd");
    let (env, _journal) = service_env(url.as_str(), &credentials);
    let mut running = start(&env, cwd.path());
    let (addr, version) = ready(&mut running).await;
    let (cutoff, closed) = relay.cut().await;
    println!("paper-mysql: cold_release root={version} closed_streams={closed} forwarding=off elapsed_ms={}", start_time.elapsed().as_millis());

    warm_governance(run, addr, version).await;
    terminate(&running);
    match timeout(Duration::from_secs(20), running.child.wait()).await {
        Ok(Ok(status)) => assert!(status.success(), "graceful child stop failed"),
        _ => unknown("graceful child exit was not confirmed"),
    }
    let observer = pool(&direct).await;
    let after = capture(&observer, &expected, expected::COUNTS).await;
    assert_eq!(before.field_bytes, after.field_bytes);
    let fingerprint =
        |capture: &UnverifiedCandidateRows| capture.report.as_ref().unwrap().schema.fingerprint;
    assert_eq!(fingerprint(&before), fingerprint(&after));
    observer.close().await;
    drop(cutoff);
    println!(
        "paper-mysql: retained_unchanged schema={schema} rows=23 elapsed_ms={}",
        start_time.elapsed().as_millis()
    );
}

#[tokio::test]
#[ignore = "requires an operator-approved isolated, pre-provisioned empty MySQL 8.0 fixture"]
async fn cold_snapshot_and_warm_governance() {
    let (run, schema, url) = fixture();
    if timeout(Duration::from_secs(300), scenario(&run, &schema, url))
        .await
        .is_err()
    {
        unknown("MySQL fixture deadline expired");
    }
}
