//! memory—v1: Test-only negative control for rule-set change-confirmation withdrawal.
//!
//! The CURRENT contract gives this service's HTTP admission routes no constructor
//! for `ManagementMutationV2::RuleSetChangeConfirmationRevoke`: the internal
//! governed publication path handles the value (§4.12 B-2.4), but no route
//! reaches it, so this test never presents itself as a governed write or a
//! replay. It owns a genuine child process and a run-scoped fixture database,
//! shows the warm baseline serving, then — after a graceful stop — seeds the
//! equivalent withdrawn facts with an explicit test-only mutator and shows the
//! real binary's fail-closed restart behavior. Envelope-absence and
//! invalid-signature refusal classes are owned by the Part A lane; this matrix
//! separates the two withdrawal-relevant causes: an envelope whose checkpoint
//! tail is stale is refused before any replay, an envelope whose candidate
//! digest is stale is refused only after the real recovery owner completes the
//! pending suffix, and a fully fresh subject then hits the withdrawal control
//! itself — the serving gate refusing a candidate whose current version lost
//! its change confirmation.

use super::*;
use astral_db::memory_v1_apply::read_memory_v1_apply_progress;
use astral_single_node::memory_v1_durable_journal::{
    CheckpointInstallId, DurableJournalLimits, MemoryV1DurableJournal,
};
use astral_types::memory_v1_journal::{JournalAnchor, RecordKind};
use sqlx::Connection;

// memory—v1: The seeded RULES_READ change confirmation and its current version.
const WITHDRAWN_CONFIRMATION: [u8; 16] = [0x90; 16];
const ACTIVE_SIBLING_CONFIRMATION: [u8; 16] = [0xa0; 16];
const CURRENT_VERSION: [u8; 1] = [1];

#[tokio::test]
#[ignore = "withdrawal negative control: requires the operator-provided loopback MySQL via ASTRAL_MEMORY_V1_E2E_ADMIN_URL; creates and drops one run-scoped database"]
// memory—v1: Warm baseline, test-only tombstone after a graceful stop, then a
// restart matrix that separates every refusal cause on the real binary.
async fn real_change_confirmation_withdrawal_negative_control() {
    // Configuration is checked on every platform first: a missing or non-loopback
    // server is an error, never a silent skip.
    let admin_url = std::env::var("ASTRAL_MEMORY_V1_E2E_ADMIN_URL")
        .expect("ASTRAL_MEMORY_V1_E2E_ADMIN_URL must name a loopback MySQL server");
    let options: MySqlConnectOptions = admin_url.parse().expect("a valid MySQL URL");
    assert!(
        is_loopback_admin_host(&options),
        "the withdrawal control server must be loopback"
    );
    let admin = MySqlPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(20))
        .connect(&admin_url)
        .await
        .expect("connect to the withdrawal control server");

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
    let scenario = tokio::spawn(withdrawal_scenario(admin_url.clone(), database.clone()));
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

// memory—v1: The owned scenario on one run-scoped database. The database is
// dropped by the caller whether this ends in a result or a panic.
async fn withdrawal_scenario(admin_url: String, database: String) {
    let run_url = url_for_database(&admin_url, &database);
    let pool = MySqlPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(20))
        .connect(&run_url)
        .await
        .expect("connect to the run-scoped database");
    for statement in candidate_ddl().into_iter().chain(apply_candidate_ddl()) {
        sqlx::query(&statement)
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("apply fixture DDL: {error}"));
    }
    let rows = {
        let mut connection = pool.acquire().await.expect("acquire fixture connection");
        let rows = seed_fixture(&mut connection, false)
            .await
            .expect("seed the withdrawal fixture");
        drop(connection);
        rows
    };
    assert_eq!(
        rows, 23,
        "the withdrawal fixture seeds the shared 23-row shape"
    );

    let dir = TempDir::new("withdraw-evidence");
    let credentials = write_credentials(dir.path(), 0o600);
    let cwd = TempDir::new("withdraw-cwd");
    let (env, journal_dir) = service_env(&run_url, &credentials);
    let (stream, epoch, genesis) = stage_e2e_bootstrap(&env, journal_dir.path(), &pool).await;
    let scope = {
        let mut connection = pool
            .acquire()
            .await
            .expect("fixture source identity connection");
        astral_db::memory_v1_candidate_loader::read_startup_database_scope(&mut connection)
            .await
            .expect("read fixture source identity")
    };
    let genesis_prefix = (0_u64, 0_u64, genesis);

    // Warm baseline: the inspected genesis subject, signed by the isolated
    // fixture issuer, produces a serving production root on the real binary.
    let subject = startup_issuer::inspect_fixture_subject(&env, cwd.path(), scope).await;
    assert_eq!(
        (subject.journal_sequence, subject.mutation_sequence),
        (0, 0)
    );
    let mut running = start(
        &startup_issuer::sign_fixture(env.clone(), dir.path(), subject.clone()),
        cwd.path(),
    );
    let addr = ready_address(&mut running, rows).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let alice = login(&client, addr, "alice", CARD_ALLOW).await;
    let bob = login(&client, addr, "bob", CARD_BOB).await;
    read_registry(&client, addr, &alice, 200, None).await;
    read_registry(&client, addr, &bob, 200, None).await;
    // The structural DENY writes the one journal record whose suffix the next
    // start must reconcile before it may capture anything.
    let unbound = login(&client, addr, "alice", CARD_UNBOUND).await;
    let reply = read_registry(
        &client,
        addr,
        &unbound,
        403,
        Some("AUTHORIZATION_CARD_UNBOUND"),
    )
    .await;
    let _ = reply;
    read_registry(&client, addr, &alice, 200, None).await;
    stop(&mut running).await;

    // The retained journal independently proves the DENY-only suffix: the frame
    // tail moved, the governance frontier did not.
    let (tail_sequence, tail_hash) = retained_tail(
        journal_dir.path(),
        subject.installation_id,
        stream,
        epoch,
        genesis,
    );
    assert_eq!(tail_sequence, 1, "exactly one retained DENY record");

    // memory—v1: TEST-ONLY withdrawal mutator. This is not a governed write and
    // not a replay: this service's HTTP admission routes have no constructor for
    // `RuleSetChangeConfirmationRevoke`, so the equivalent withdrawn fact is
    // seeded directly after a graceful stop, under one stable run-scoped
    // operation id. The `revoked_by` identity is fixture data and proves no
    // authority.
    let withdrawn_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let tombstone = {
        let mut connection = pool.acquire().await.expect("withdrawal mutator connection");
        seed_withdrawn_fact(
            &mut connection,
            WITHDRAWN_CONFIRMATION,
            RULES_READ,
            &CURRENT_VERSION,
            BOB,
            withdrawn_at,
            2,
        )
        .await
    };
    assert_eq!(
        applied_prefix(&pool, stream).await,
        genesis_prefix,
        "the mutator only touches the source fact table; the durable prefix is untouched"
    );

    // (a) The envelope bound to the pre-withdrawal genesis tail is adoption
    // freshness at the checkpoint gate. Envelope-absence and invalid-signature
    // classes share this pre-database gate and are owned by the Part A lane;
    // here the pinned prefix proves no replay moved before this refusal.
    let stale_tail = refused(&startup_issuer::sign_fixture(
        env.clone(),
        dir.path(),
        subject.clone(),
    ))
    .await;
    assert!(
        stale_tail.contains("does not bind the captured startup state"),
        "{stale_tail}"
    );
    assert_eq!(
        applied_prefix(&pool, stream).await,
        genesis_prefix,
        "a stale checkpoint tail must be refused before any replay"
    );

    // (b) An envelope with the advanced tail but the pre-withdrawal candidate
    // digest passes the checkpoint gate, so the real recovery owner completes
    // the pending DENY suffix first; the adoption bind then refuses the moved
    // candidate. The refusal is adoption freshness, not incomplete replay.
    let mut moved = subject.clone();
    moved.journal_sequence = tail_sequence;
    moved.journal_tail_hash = tail_hash;
    let stale_candidate = refused(&startup_issuer::sign_fixture(
        env.clone(),
        dir.path(),
        moved,
    ))
    .await;
    assert!(
        stale_candidate.contains("cold candidate installation failed"),
        "{stale_candidate}"
    );
    assert!(
        stale_candidate.contains("AdoptionEvidence(Startup(SubjectMismatch))"),
        "{stale_candidate}"
    );
    wait_prefix(&pool, stream, (tail_sequence, 0, tail_hash)).await;
    refusal_evidence("stale-candidate-after-complete-replay", &stale_candidate);

    // (c) The withdrawal control itself: a fresh envelope from the real issuer
    // path binds the post-withdrawal capture, and the serving gate refuses the
    // candidate because the current version no longer carries an active change
    // confirmation. The durable prefix is already complete, so the refusal is
    // the withdrawal, not the envelope and not the replay.
    let fresh_subject = startup_issuer::inspect_fixture_subject(&env, cwd.path(), scope).await;
    assert_eq!(
        (
            fresh_subject.journal_sequence,
            fresh_subject.mutation_sequence
        ),
        (tail_sequence, 0),
        "the inspected subject must describe exactly the reconciled tail"
    );
    let fresh_env = startup_issuer::sign_fixture(env, dir.path(), fresh_subject);
    let withdrawn_refusal = refused(&fresh_env).await;
    assert!(
        withdrawn_refusal.contains("cold candidate installation failed"),
        "{withdrawn_refusal}"
    );
    assert!(
        withdrawn_refusal.contains("MissingVersionReference"),
        "{withdrawn_refusal}"
    );
    assert!(
        withdrawn_refusal.contains("RuleSetChangeConfirmation"),
        "{withdrawn_refusal}"
    );
    assert_eq!(
        applied_prefix(&pool, stream).await,
        (tail_sequence, 0, tail_hash),
        "the withdrawal refusal is not caused by incomplete replay"
    );
    refusal_evidence("stale-tail-before-any-replay", &stale_tail);
    refusal_evidence("fresh-envelope-withdrawn-candidate", &withdrawn_refusal);
    pool.close().await;

    eprintln!(
        "withdrawal_negative_control warm_ready=1 warm_denies=1 tombstones=1 tombstone_op={tombstone} attempts=3 refused=(stale-tail,stale-candidate-despite-complete-prefix,fresh-envelope-withdrawn-candidate) replay_completions=1 governed_writes=0"
    );
}

// memory—v1: The durable applied prefix, the replay observable of every restart.
async fn applied_prefix(pool: &MySqlPool, stream: MemoryId) -> (u64, u64, [u8; 32]) {
    let progress = read_memory_v1_apply_progress(pool, stream)
        .await
        .expect("read the fixture apply progress")
        .expect("the fixture apply progress row");
    (
        progress.last_journal_sequence,
        progress.last_mutation_sequence,
        progress.last_frame_hash,
    )
}

// memory—v1: Bounded wait for the real recovery owner to converge the prefix.
async fn wait_prefix(pool: &MySqlPool, stream: MemoryId, expected: (u64, u64, [u8; 32])) {
    timeout(Duration::from_secs(30), async {
        loop {
            if applied_prefix(pool, stream).await == expected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("durable prefix convergence deadline");
}

#[tokio::test]
#[ignore = "withdrawal positive control: requires the operator-provided loopback MySQL via ASTRAL_MEMORY_V1_E2E_ADMIN_URL; creates and drops one run-scoped database"]
// memory—v1: Two legal current-version confirmations from different fixture
// identities prove that withdrawing one tombstones only that confirmation; the
// sibling active confirmation keeps the real cold-installed service serving.
async fn real_change_confirmation_withdrawal_positive_control() {
    let admin_url = std::env::var("ASTRAL_MEMORY_V1_E2E_ADMIN_URL")
        .expect("ASTRAL_MEMORY_V1_E2E_ADMIN_URL must name a loopback MySQL server");
    let options: MySqlConnectOptions = admin_url.parse().expect("a valid MySQL URL");
    assert!(
        is_loopback_admin_host(&options),
        "the withdrawal positive control server must be loopback"
    );
    let admin = MySqlPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(20))
        .connect(&admin_url)
        .await
        .expect("connect to the withdrawal positive-control server");

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
    .expect("create the positive-control run-scoped database");

    let scenario = tokio::spawn(withdrawal_positive_scenario(
        admin_url.clone(),
        database.clone(),
    ));
    let outcome = scenario.await;

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

    dropped.expect("drop the positive-control run-scoped database");
    assert_eq!(remaining, 0, "the positive-control database must be gone");
    assert!(
        protected_unchanged,
        "a protected database's table list changed"
    );
    if let Err(error) = outcome {
        std::panic::resume_unwind(error.into_panic());
    }
}

// memory—v1: A separate real-process lane. It deliberately shares the
// negative-control fixture shape but adds one legal sibling confirmation for
// the same current version. The SQL mutation remains a test-only source fact;
// this lane does not claim to exercise a missing online governance route.
async fn withdrawal_positive_scenario(admin_url: String, database: String) {
    let run_url = url_for_database(&admin_url, &database);
    let pool = MySqlPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(20))
        .connect(&run_url)
        .await
        .expect("connect to the positive-control run-scoped database");
    for statement in candidate_ddl().into_iter().chain(apply_candidate_ddl()) {
        sqlx::query(&statement)
            .execute(&pool)
            .await
            .unwrap_or_else(|error| panic!("apply positive-control fixture DDL: {error}"));
    }
    let rows = {
        let mut connection = pool
            .acquire()
            .await
            .expect("acquire positive-control fixture connection");
        let rows = seed_fixture(&mut connection, false)
            .await
            .expect("seed the positive-control fixture");
        seed_sibling_change_confirmation(&mut connection)
            .await
            .expect("seed the legal active sibling confirmation");
        drop(connection);
        rows + 1
    };
    assert_eq!(
        rows, 24,
        "the positive-control fixture adds exactly one current-version confirmation"
    );

    let dir = TempDir::new("withdraw-positive-evidence");
    let credentials = write_credentials(dir.path(), 0o600);
    let cwd = TempDir::new("withdraw-positive-cwd");
    let (env, journal_dir) = service_env(&run_url, &credentials);
    let (stream, epoch, genesis) = stage_e2e_bootstrap(&env, journal_dir.path(), &pool).await;
    let scope = {
        let mut connection = pool
            .acquire()
            .await
            .expect("positive-control source identity connection");
        astral_db::memory_v1_candidate_loader::read_startup_database_scope(&mut connection)
            .await
            .expect("read positive-control source identity")
    };
    let subject = startup_issuer::inspect_fixture_subject(&env, cwd.path(), scope).await;
    assert_eq!(
        (subject.journal_sequence, subject.mutation_sequence),
        (0, 0)
    );
    let mut running = start(
        &startup_issuer::sign_fixture(env.clone(), dir.path(), subject.clone()),
        cwd.path(),
    );
    let addr = ready_address(&mut running, rows).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let alice = login(&client, addr, "alice", CARD_ALLOW).await;
    let bob = login(&client, addr, "bob", CARD_BOB).await;
    read_registry(&client, addr, &alice, 200, None).await;
    read_registry(&client, addr, &bob, 200, None).await;
    let overlay = login(&client, addr, "alice", CARD_OVERLAY_DENY).await;
    let overlay_reply = call(
        &client,
        addr,
        reqwest::Method::GET,
        REGISTRY,
        Some(&overlay),
        None,
    )
    .await;
    assert_eq!(overlay_reply.status, 403, "{}", overlay_reply.body);
    assert_eq!(
        overlay_reply.body["reasonCode"],
        "AUTHORIZATION_RULE_DENIED"
    );
    stop(&mut running).await;

    let (tail_sequence, tail_hash) = retained_tail(
        journal_dir.path(),
        subject.installation_id,
        stream,
        epoch,
        genesis,
    );
    assert_eq!(
        tail_sequence, 1,
        "the overlay DENY is the only retained suffix"
    );
    let genesis_prefix = (0_u64, 0_u64, genesis);
    let current_prefix = (tail_sequence, 0, tail_hash);
    let mut stale_candidate_subject = subject.clone();
    stale_candidate_subject.journal_sequence = tail_sequence;
    stale_candidate_subject.journal_tail_hash = tail_hash;

    let withdrawn_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let tombstone = {
        let mut connection = pool
            .acquire()
            .await
            .expect("positive-control withdrawal mutator connection");
        let tombstone = seed_withdrawn_fact(
            &mut connection,
            WITHDRAWN_CONFIRMATION,
            RULES_READ,
            &CURRENT_VERSION,
            BOB,
            withdrawn_at,
            3,
        )
        .await;
        assert_current_confirmation_state(
            &mut connection,
            WITHDRAWN_CONFIRMATION,
            ACTIVE_SIBLING_CONFIRMATION,
            true,
        )
        .await;
        tombstone
    };
    assert_eq!(
        applied_prefix(&pool, stream).await,
        genesis_prefix,
        "the positive-control test-only mutator leaves the durable prefix unchanged"
    );

    let stale_refusal = refused(&startup_issuer::sign_fixture(
        env.clone(),
        dir.path(),
        stale_candidate_subject,
    ))
    .await;
    assert!(
        stale_refusal.contains("does not bind the captured startup state")
            || stale_refusal.contains("cold candidate installation failed"),
        "{stale_refusal}"
    );
    assert_eq!(
        applied_prefix(&pool, stream).await,
        current_prefix,
        "the stale pre-withdrawal envelope must not leave a new mutation prefix"
    );

    let fresh_subject = startup_issuer::inspect_fixture_subject(&env, cwd.path(), scope).await;
    assert_eq!(
        (
            fresh_subject.journal_sequence,
            fresh_subject.mutation_sequence
        ),
        (tail_sequence, 0),
        "fresh evidence must bind the already reconciled journal tail"
    );
    let fresh_env = startup_issuer::sign_fixture(env, dir.path(), fresh_subject);
    let mut restarted = start(&fresh_env, cwd.path());
    let restarted_addr = ready_address(&mut restarted, rows).await;
    let restarted_client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let alice_after = login(&restarted_client, restarted_addr, "alice", CARD_ALLOW).await;
    let bob_after = login(&restarted_client, restarted_addr, "bob", CARD_BOB).await;
    read_registry(&restarted_client, restarted_addr, &alice_after, 200, None).await;
    read_registry(&restarted_client, restarted_addr, &bob_after, 200, None).await;
    let overlay_after = login(
        &restarted_client,
        restarted_addr,
        "alice",
        CARD_OVERLAY_DENY,
    )
    .await;
    let overlay_reply = call(
        &restarted_client,
        restarted_addr,
        reqwest::Method::GET,
        REGISTRY,
        Some(&overlay_after),
        None,
    )
    .await;
    assert_eq!(overlay_reply.status, 403, "{}", overlay_reply.body);
    assert_eq!(
        overlay_reply.body["reasonCode"],
        "AUTHORIZATION_RULE_DENIED"
    );
    stop(&mut restarted).await;

    let mut connection = pool
        .acquire()
        .await
        .expect("re-open positive-control verification connection");
    assert_current_confirmation_state(
        &mut connection,
        WITHDRAWN_CONFIRMATION,
        ACTIVE_SIBLING_CONFIRMATION,
        true,
    )
    .await;
    let (revoked_at, revoked_by, row_count): (Option<i64>, Option<Vec<u8>>, i64) = sqlx::query_as(
        "SELECT revoked_at, revoked_by, \
             (SELECT CAST(COUNT(*) AS SIGNED) FROM memory_rule_set_change_confirmation) \
             FROM memory_rule_set_change_confirmation WHERE confirmation_id = ?",
    )
    .bind(WITHDRAWN_CONFIRMATION.to_vec())
    .fetch_one(&mut *connection)
    .await
    .expect("read back the withdrawn confirmation");
    assert_eq!(revoked_at, Some(withdrawn_at));
    assert_eq!(revoked_by.as_deref(), Some(BOB.as_slice()));
    assert_eq!(row_count, 3, "withdrawal preserves all confirmation rows");
    pool.close().await;

    eprintln!(
        "memory-v1 withdrawal positive control warm_ready=2 stale_old_candidate=1 restarted_ready=1 sibling_active=1 overlay_denies=2 tombstone_persisted=1 tombstone_op={tombstone} governed_writes=0"
    );
}

// memory—v1: DDL permits multiple current-version confirmations because the
// schema keys only confirmation_id and indexes (rule_set_id, version_bytes).
// The two confirmer identities are deliberately distinct fixture users.
async fn seed_sibling_change_confirmation(
    connection: &mut MySqlConnection,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO memory_rule_set_change_confirmation \
         (confirmation_id, rule_set_id, version_bytes, confirmer_user_id, \
          affected_scope_bytes, operation_id, confirmed_at_bytes) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(ACTIVE_SIBLING_CONFIRMATION.to_vec())
    .bind(RULES_READ.to_vec())
    .bind(CURRENT_VERSION.to_vec())
    .bind(ALICE.to_vec())
    .bind(vec![2_u8])
    .bind(b"positive-sibling-confirmation".to_vec())
    .bind(vec![2_u8])
    .execute(&mut *connection)
    .await
    .map(|_| ())
}

// memory—v1: Verify both current-version confirmations after the test-only
// source mutation. The sibling remains active and the withdrawn row remains a
// complete tombstone; no binding or overlay-deny row is touched.
async fn assert_current_confirmation_state(
    connection: &mut MySqlConnection,
    withdrawn: [u8; 16],
    sibling: [u8; 16],
    expect_withdrawn: bool,
) {
    let rows: Vec<(Vec<u8>, Option<i64>, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT confirmation_id, revoked_at, revoked_by \
         FROM memory_rule_set_change_confirmation \
         WHERE rule_set_id = ? AND version_bytes = ? ORDER BY confirmation_id",
    )
    .bind(RULES_READ.to_vec())
    .bind(CURRENT_VERSION.to_vec())
    .fetch_all(&mut *connection)
    .await
    .expect("read current-version confirmation state");
    assert_eq!(
        rows.len(),
        2,
        "two legal current-version confirmations remain"
    );
    let withdrawn_row = rows
        .iter()
        .find(|row| row.0 == withdrawn.to_vec())
        .expect("withdrawn confirmation row remains");
    let sibling_row = rows
        .iter()
        .find(|row| row.0 == sibling.to_vec())
        .expect("active sibling confirmation row remains");
    if expect_withdrawn {
        assert!(withdrawn_row.1.is_some() && withdrawn_row.2.is_some());
        assert!(sibling_row.1.is_none() && sibling_row.2.is_none());
    }
}

// memory—v1: One registry read through the real Gateway, with the expected
// decision when the answer must be a denial.
async fn read_registry(
    client: &reqwest::Client,
    addr: SocketAddr,
    token: &str,
    status: u16,
    decision: Option<&str>,
) -> Reply {
    let reply = call(
        client,
        addr,
        reqwest::Method::GET,
        REGISTRY,
        Some(token),
        None,
    )
    .await;
    assert_eq!(reply.status, status, "{}", reply.body);
    match decision {
        Some(expected) => {
            assert_eq!(reply.body["decision"], expected, "{}", reply.body);
            assert!(
                reply.body["data"].is_null(),
                "a denial must not disclose registry data"
            );
        }
        None => assert!(
            !reply.body["data"].is_null(),
            "admission must reach the registry handler"
        ),
    }
    reply
}

// memory—v1: Stop the way an operator would, and hold the diagnostics.
async fn stop(running: &mut Running) {
    terminate(running);
    assert!(
        running.exit(Duration::from_secs(30)).await.success(),
        "graceful stop must exit 0: {}",
        running.output()
    );
    running.drain(Duration::from_secs(2)).await;
}

// memory—v1: Re-open the retained journal and read the position the fixture
// independently knows: one DENY record, frame tail advanced, governance at zero.
fn retained_tail(
    journal_dir: &Path,
    installation: MemoryId,
    stream: MemoryId,
    epoch: MemoryId,
    genesis: [u8; 32],
) -> (u64, [u8; 32]) {
    let (journal, _durability) = MemoryV1DurableJournal::open_checkpointed(
        &journal_dir.join("memory-v1-durable.bin"),
        &journal_dir.join("memory-v1-durable"),
        CheckpointInstallId::from_install_uuid(installation.into_bytes()).unwrap(),
        stream,
        epoch,
        JournalAnchor::new(stream, 0, 0, genesis).unwrap(),
        DurableJournalLimits::conservative(),
    )
    .unwrap();
    let [record] = journal.recovery_records() else {
        panic!("expected exactly one checkpointed DENY record");
    };
    assert_eq!(
        (record.kind, record.mutation_sequence),
        (RecordKind::Deny, 0)
    );
    let position = journal.position();
    assert_eq!(position.journal_sequence(), record.journal_sequence);
    (position.journal_sequence(), *position.frame_hash())
}

// memory—v1: The test-only tombstone. It completes an existing active row with
// both revocation halves in one transaction, bound to one stable operation id,
// and reads the persisted withdrawal fact back before any restart is attempted.
async fn seed_withdrawn_fact(
    connection: &mut MySqlConnection,
    confirmation: [u8; 16],
    rule_set: [u8; 16],
    current_version: &[u8],
    withdrawn_by: [u8; 16],
    withdrawn_at: i64,
    expected_total_rows: i64,
) -> String {
    let operation_id = format!("withdraw-change-confirmation-{}", uuid::Uuid::new_v4());
    let (version, confirmer): (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT version_bytes, confirmer_user_id FROM memory_rule_set_change_confirmation \
         WHERE confirmation_id = ? AND rule_set_id = ? \
           AND revoked_at IS NULL AND revoked_by IS NULL",
    )
    .bind(confirmation.to_vec())
    .bind(rule_set.to_vec())
    .fetch_one(&mut *connection)
    .await
    .expect("exactly one active change confirmation to withdraw");
    assert_eq!(
        version,
        current_version.to_vec(),
        "the active confirmation must cover the current version"
    );
    assert_eq!(
        confirmer,
        withdrawn_by.to_vec(),
        "fixture withdrawal identity"
    );

    let mut tx = connection
        .begin()
        .await
        .expect("begin the withdrawal transaction");
    let updated = sqlx::query(
        "UPDATE memory_rule_set_change_confirmation \
         SET revoked_at = ?, revoked_by = ? \
         WHERE confirmation_id = ? AND rule_set_id = ? AND version_bytes = ? \
           AND revoked_at IS NULL AND revoked_by IS NULL",
    )
    .bind(withdrawn_at)
    .bind(withdrawn_by.to_vec())
    .bind(confirmation.to_vec())
    .bind(rule_set.to_vec())
    .bind(current_version.to_vec())
    .execute(&mut *tx)
    .await
    .expect("tombstone the change confirmation");
    assert_eq!(updated.rows_affected(), 1, "exactly one complete tombstone");
    tx.commit()
        .await
        .expect("commit the withdrawal transaction");

    // Persistence proof: a complete tombstone on the current version, and the
    // withdrawal is a state change, not a deletion.
    let (revoked_at, revoked_by, version, remaining): (Option<i64>, Option<Vec<u8>>, Vec<u8>, i64) =
        sqlx::query_as(
            "SELECT revoked_at, revoked_by, version_bytes, \
         (SELECT CAST(COUNT(*) AS SIGNED) FROM memory_rule_set_change_confirmation) \
         FROM memory_rule_set_change_confirmation WHERE confirmation_id = ?",
        )
        .bind(confirmation.to_vec())
        .fetch_one(&mut *connection)
        .await
        .expect("read back the tombstoned row");
    assert_eq!(
        remaining, expected_total_rows,
        "the withdrawal must not delete any row"
    );
    assert_eq!(
        (
            revoked_at,
            revoked_by.as_deref() == Some(withdrawn_by.as_slice()),
            version
        ),
        (Some(withdrawn_at), true, current_version.to_vec()),
        "the persisted withdrawal fact must be a complete tombstone on the current version"
    );
    println!(
        "memory-v1 withdrawal control: test-only tombstone op={operation_id} revoked_at={withdrawn_at} persisted=1 (fixture identity, not authority evidence)"
    );
    operation_id
}

// memory—v1: Emit the observed refusal chain for the run evidence; the text is
// already scrubbed of URL credentials and known secret values by `redact`.
fn refusal_evidence(label: &str, output: &str) {
    let chain = output
        .lines()
        .skip_while(|line| !line.starts_with("Error:") && !line.contains("Caused by"))
        .collect::<Vec<_>>()
        .join("\n");
    println!("memory-v1 withdrawal control: {label} refusal:\n{chain}");
}

// memory—v1: The warm baseline of every lane: production readiness on loopback.
async fn ready_address(running: &mut Running, rows: usize) -> SocketAddr {
    let ready = running
        .wait_ready(Duration::from_secs(60))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(
        ready.contains("grade=Production") && ready.contains(&format!("rows={rows} ")),
        "{ready}"
    );
    let addr: SocketAddr = ready
        .split_whitespace()
        .find_map(|part| part.strip_prefix("addr="))
        .expect("an addr= field")
        .parse()
        .unwrap();
    assert!(addr.ip().is_loopback(), "{ready}");
    println!("memory-v1 withdrawal control: warm baseline ready: {ready}");
    addr
}
