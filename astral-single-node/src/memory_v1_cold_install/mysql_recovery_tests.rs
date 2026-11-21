//! memory—v1: Real-MySQL recovery coverage for
//! `ReconciledColdInstall::capture_and_bind` (Rust 规范 §15.10.4, ignored
//! integration).
//!
//! One run-scoped stream journals three supported `UserCardCreate` mutations
//! plus one historical DENY that observed mutation sequence 1 while its
//! retained predecessor is 3. MySQL holds only the provisioned genesis
//! progress tail, so the first reopened `capture_and_bind` consumes the whole
//! ordered suffix into the candidate tables, captures the nine fact tables at
//! the exact applied prefix and binds the last mutation's own anchor. The raw
//! receipt, audit and progress rows are checked against the retained frames:
//! the ORIGINAL producer boot, the chained frame digests, the engine trusted
//! time on mutations and the read-start sample with a NULL trusted time on the
//! raw deny observation. A second reopen re-verifies the identical history
//! purely through receipts and proves the append-only audit trail is
//! unchanged, and the bound candidate keeps the adoption gate's own
//! independence: the fully reconciled database still refuses without the
//! gate's evidence families. The optional isolated Serving adoption is
//! deliberately out of scope here. The scan-count assertions are absolute, so
//! the fixture schema must hold ONLY the run's rows. Nothing in this module
//! executes DDL, SSH, or a service; all rows are run-scoped and written with
//! parameterized SQL only, and a real `PASS` is only the operator's explicit
//! run, never this file's claim.
//!
//! Run explicitly:
//! `RUST_INTEGRATION_REQUIRED=1 \
//!  ASTRAL_MEMORY_V1_APPLY_TEST_MYSQL_URL=mysql://... \
//!  cargo test -p astral-single-node --lib memory_v1_cold_install -- --ignored`

use astral_authorization_root::memory_v1_adoption::{
    AdoptionEvidenceError, ProductionEvidenceInput, MEMORY_V1_CANDIDATE_SCHEMA_VERSION,
};
use astral_authorization_root::memory_v1_db_rows::{UserCardRow, UserCardStatus};
use astral_authorization_root::memory_v1_root::{
    install_isolated_test_root_with_governance_prefix, ManagementMutationV2, RootOwner,
};
use astral_db::memory_v1_apply::{
    initialize_memory_v1_apply_progress, read_memory_v1_apply_progress, MemoryV1ApplyProgressInit,
};
use astral_trustgraph::service::memory_v1_mutation_coordinator::{
    journal_producer_boot_id, DenyJournalRequest, JournalIdentity, MutationAuditCandidate,
    MutationRequest, RootBinding, VerifiedRootAdmission,
};
use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use astral_types::memory_v1_audit::{
    MemoryV1AuditAction, MemoryV1AuditActor, MemoryV1AuditCardState, MemoryV1AuditChange,
    MemoryV1AuditConfirmations, MemoryV1AuditContext, MemoryV1AuditDecisionInput,
    MemoryV1AuditDenySource, MemoryV1AuditEvent, MemoryV1AuditObject, MemoryV1AuditObjectState,
    MemoryV1AuditOperation, MemoryV1AuditRootObservation, MemoryV1AuditRootStatus,
    MemoryV1AuditRootVersion, MemoryV1AuditSource, MemoryV1AuditT2SingleChangeCandidate,
    MemoryV1AuditTime,
};
use astral_types::memory_v1_deny_observation::{
    MemoryV1DenyAffectedBindingState, MemoryV1DenyObservation, MemoryV1DenyRootObservation,
};
use astral_types::memory_v1_journal::JournalAnchor;
use uuid::Uuid;

use super::{CaptureBudget, ReconciledColdInstall, RecordKind, RootError, RootStatus};
use crate::memory_v1_durable_journal::{
    CheckpointInstallId, DurableJournalLimits, LocalCheckpointCoverage, LocalCheckpointStore,
    MemoryV1DurableJournal,
};

/// The trusted engine time the journaled mutation audits carry (value layer).
const TRUSTED_TIME: i64 = 1_700_000_000;
/// The synthetic root digest every journaled observation reports.
const OBSERVED_DIGEST: [u8; 32] = [7; 32];
/// The nonzero genesis anchor hash the stream is installed with.
const GENESIS_HASH: [u8; 32] = [5; 32];

// memory—v1: Run-scoped identifier; every seeded row and journal identity is
// derived from fresh UUIDs, so reruns against the shared operator database
// never collide.
fn random_id() -> MemoryId {
    MemoryId::from_bytes(*Uuid::new_v4().as_bytes())
}

// memory—v1: Same dependency gate as the astral-db apply integration tests: a
// missing required dependency is a hard failure; an absent optional dependency
// is recorded as [SKIP], never as PASS.
async fn real_recovery_pool() -> Option<sqlx::MySqlPool> {
    let required = std::env::var("RUST_INTEGRATION_REQUIRED").as_deref() == Ok("1");
    let Ok(url) = std::env::var("ASTRAL_MEMORY_V1_APPLY_TEST_MYSQL_URL") else {
        assert!(
            !required,
            "required isolated memory-v1 apply MySQL dependency is missing"
        );
        eprintln!("[SKIP] isolated memory-v1 apply MySQL dependency is missing");
        return None;
    };
    Some(sqlx::MySqlPool::connect(&url).await.unwrap())
}

fn capture_budget() -> CaptureBudget {
    CaptureBudget {
        max_rows: 100_000,
        max_bytes: 16 * 1024 * 1024,
    }
}

// memory—v1: One journaled UserCardCreate — a mutation the apply plan supports
// end to end (one fact insert into memory_user_card).
#[allow(clippy::too_many_arguments)]
fn create_request(
    stream: MemoryId,
    epoch: MemoryId,
    instance: MemoryId,
    run: &str,
    sequence: u64,
    user: MemoryId,
    identity_card: MemoryId,
    tenant: MemoryId,
    card: MemoryId,
) -> MutationRequest {
    let operation_id = format!("{run}-mut-{sequence}");
    let mut fingerprint = [0; 32];
    fingerprint[..8].copy_from_slice(&sequence.to_be_bytes());
    let mutation = ManagementMutationV2::UserCardCreate {
        row: UserCardRow {
            user_card_id: card.into_bytes(),
            user_id: user.into_bytes(),
            tenant_id: tenant.into_bytes(),
            status: UserCardStatus::Active,
        },
    };
    let summary = MutationAuditCandidate::governance_mutation_summary(&mutation).unwrap();
    let context = MemoryV1AuditContext::new(
        MemoryV1AuditActor::new(user, identity_card),
        MemoryV1AuditTime::new(TRUSTED_TIME).unwrap(),
        MemoryV1AuditAction::new("user_card", "create").unwrap(),
        "GOVERNANCE_USER_CARD_CREATE",
        MemoryV1AuditOperation::new(&operation_id, fingerprint).unwrap(),
        MemoryV1AuditRootObservation::new(
            MemoryV1AuditRootVersion::new(instance, 7),
            OBSERVED_DIGEST,
            MemoryV1AuditRootStatus::Serving,
        ),
    )
    .unwrap();
    let change = MemoryV1AuditChange::new(
        Some(user),
        Some(MemoryV1AuditObject::UserCard(card)),
        Some(MemoryV1AuditObject::Tenant(tenant)),
        Some(summary),
        Some(MemoryV1AuditObjectState::Absent),
        Some(MemoryV1AuditObjectState::UserCard(
            MemoryV1AuditCardState::Active,
        )),
        Some(MemoryV1AuditConfirmations::not_applicable()),
        Some(MemoryV1AuditRootVersion::new(instance, 7)),
        Some(MemoryV1AuditRootVersion::new(instance, 8)),
        MemoryV1AuditSource::Ordinary,
    );
    MutationRequest::try_new(
        &operation_id,
        fingerprint,
        mutation,
        MutationAuditCandidate::Single(
            MemoryV1AuditT2SingleChangeCandidate::try_from(
                MemoryV1AuditEvent::change(context, MemoryV1AuditDecisionInput::Allow, change)
                    .unwrap(),
            )
            .unwrap(),
        ),
        VerifiedRootAdmission::mint_from_production_owner(RootBinding::from_metadata(
            astral_authorization_root::memory_v1_root::RootMetadata {
                instance_id: astral_authorization_root::memory_v1_root::RootInstanceId::from_uuid(
                    Uuid::from_bytes(*instance.as_bytes()),
                ),
                version: 7,
                digest: OBSERVED_DIGEST,
                budget: astral_authorization_root::memory_v1_hamt::CandidateBudget {
                    max_table_rows: 64,
                    max_bindings_per_read: 8,
                },
                row_count: 9,
                status: RootStatus::Serving,
            },
        )),
        JournalIdentity::new(
            stream,
            epoch,
            sequence,
            sequence,
            MemoryId::from_bytes((u128::from(sequence) + 20).to_be_bytes()),
        )
        .unwrap(),
    )
    .unwrap()
}

// memory—v1: One historical DENY: the observation read mutation sequence 1,
// but the frame is retained after mutation 3 (predecessor 3).
#[allow(clippy::too_many_arguments)]
fn historical_deny(
    stream: MemoryId,
    epoch: MemoryId,
    instance: MemoryId,
    run: &str,
    user: MemoryId,
    identity_card: MemoryId,
    tenant: MemoryId,
    card: MemoryId,
) -> DenyJournalRequest {
    let journal_sequence = 4_u64;
    let operation_id = format!("{run}-deny-{journal_sequence}");
    let root = MemoryV1DenyRootObservation::try_from_usize(
        instance,
        7,
        OBSERVED_DIGEST,
        MemoryV1AuditRootStatus::Serving,
        64,
        8,
        9,
    )
    .unwrap();
    let observation = MemoryV1DenyObservation::new(
        root,
        CandidateIdentity {
            user_id: user,
            identity_card_id: identity_card,
            user_card_id: card,
            tenant_id: tenant,
        },
        TRUSTED_TIME,
        "document",
        "read",
        None,
        None,
        None,
        MemoryV1DenyAffectedBindingState::inapplicable(),
        operation_id.into_bytes(),
        [0x9e; 32].to_vec(),
        MemoryV1AuditDenySource::RuleDeny,
        None,
    )
    .unwrap();
    DenyJournalRequest::try_new(
        observation,
        JournalIdentity::new_deny(
            stream,
            epoch,
            journal_sequence,
            1,
            MemoryId::from_bytes((u128::from(journal_sequence) + 20).to_be_bytes()),
        )
        .unwrap(),
    )
    .unwrap()
}

// memory—v1: Run-scoped temporary journal directory with its checkpoint
// sidecar; removed when the test ends.
struct RecoveryJournalDir(std::path::PathBuf);

impl RecoveryJournalDir {
    fn new(label: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("astral-cold-install-{label}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn path(&self) -> std::path::PathBuf {
        self.0.join("journal.bin")
    }
    fn checkpoint(&self) -> std::path::PathBuf {
        self.0.join("journal.ckpt")
    }
}

impl Drop for RecoveryJournalDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn count_scalar(pool: &sqlx::MySqlPool, sql: &str, id: &MemoryId) -> i64 {
    sqlx::query_scalar(sql)
        .bind(&id.as_bytes()[..])
        .fetch_one(pool)
        .await
        .unwrap()
}

// memory—v1: The real-MySQL cold-install recovery contract, in order: journal
// three mutations plus one historical deny, reopen over the checkpoint
// sidecar, let capture_and_bind backfill the empty progress tail through the
// ordered suffix, verify the bound anchor and the raw seam rows, reopen again
// and re-verify through receipts only.
#[tokio::test]
#[ignore = "requires isolated ASTRAL_MEMORY_V1_APPLY_TEST_MYSQL_URL with the 13 operator-provisioned memory-v1 candidate tables created"]
async fn real_mysql_cold_install_backfills_suffix_binds_and_reverifies() {
    let Some(pool) = real_recovery_pool().await else {
        return;
    };
    let run = format!("it-cold-install-{}", Uuid::new_v4().simple());
    let user = random_id();
    let identity_card = random_id();
    let tenant = random_id();
    let stream = random_id();
    let epoch = random_id();
    let instance = random_id();
    let genesis = JournalAnchor::new(stream, 0, 0, GENESIS_HASH).unwrap();
    let limits = DurableJournalLimits::conservative();
    let install = CheckpointInstallId::from_install_uuid(*Uuid::new_v4().as_bytes()).unwrap();
    let dir = RecoveryJournalDir::new("mysql-recovery");

    // Run-scoped reference facts, written with parameterized SQL only: the
    // parent rows a supported UserCardCreate fact insert requires.
    sqlx::query("INSERT INTO memory_user (user_id) VALUES (?)")
        .bind(&user.as_bytes()[..])
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO memory_identity_card (identity_card_id, user_id) VALUES (?, ?)")
        .bind(&identity_card.as_bytes()[..])
        .bind(&user.as_bytes()[..])
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO memory_tenant (tenant_id) VALUES (?)")
        .bind(&tenant.as_bytes()[..])
        .execute(&pool)
        .await
        .unwrap();

    // Writer phase: three supported mutations and one historical DENY, each
    // flushed through the checkpoint group commit so the sidecar covers the
    // exact journal tail.
    let mut cards = Vec::new();
    {
        let (mut journal, durability) =
            MemoryV1DurableJournal::create(&dir.path(), stream, epoch, genesis, limits).unwrap();
        let (store, _) = LocalCheckpointStore::bootstrap(
            &dir.checkpoint(),
            install,
            stream,
            epoch,
            genesis,
            LocalCheckpointCoverage::from_anchor(genesis, 0),
            limits,
        )
        .unwrap();
        journal.attach_checkpoint(&durability, store).unwrap();
        // The wiring-side provisioned durable tail: the genesis progress row.
        assert!(matches!(
            initialize_memory_v1_apply_progress(&pool, stream, epoch, GENESIS_HASH)
                .await
                .unwrap(),
            MemoryV1ApplyProgressInit::Initialized
        ));
        for sequence in 1..=3_u64 {
            let card = random_id();
            let request = create_request(
                stream,
                epoch,
                instance,
                &run,
                sequence,
                user,
                identity_card,
                tenant,
                card,
            );
            journal
                .prepare_mutation(&request, &durability)
                .unwrap()
                .into_durable_receipt(&durability)
                .unwrap();
            cards.push(card);
        }
        let deny = historical_deny(
            stream,
            epoch,
            instance,
            &run,
            user,
            identity_card,
            tenant,
            cards[0],
        );
        journal
            .prepare_deny(&deny, &durability)
            .unwrap()
            .into_durable_receipt(&durability)
            .unwrap();
    }

    // First reopen: the production recovery shape over the clean-cut sidecar.
    let (journal, durability) = MemoryV1DurableJournal::open_checkpointed(
        &dir.path(),
        &dir.checkpoint(),
        install,
        stream,
        epoch,
        genesis,
        limits,
    )
    .unwrap();
    let records = journal.recovery_records();
    assert_eq!(records.len(), 4);
    // The historical deny: observed mutation sequence 1, retained predecessor 3.
    assert_eq!(records[3].kind, RecordKind::Deny);
    assert_eq!(records[3].mutation_sequence, 1);
    assert_eq!(records[3].prev_mutation_sequence, 3);

    // Empty progress tail: the whole journal is an ordered suffix that
    // capture_and_bind consumes into MySQL before capturing at the prefix.
    let cold =
        ReconciledColdInstall::capture_and_bind(&pool, &journal, &durability, capture_budget())
            .await
            .unwrap();

    // The bound governance position is the last mutation's OWN anchor, not the
    // deny tail: (3, 3) with the mutation frame digest, epoch bound.
    let prefix = cold.prefix.expect("the reconciled prefix binds");
    assert_eq!(prefix.anchor().journal_sequence(), 3);
    assert_eq!(prefix.anchor().mutation_sequence(), 3);
    assert_eq!(prefix.anchor().frame_hash(), &records[2].frame_hash);
    assert_eq!(prefix.epoch(), epoch);
    assert_eq!(journal.position().journal_sequence(), 4);
    assert_eq!(journal.position().mutation_sequence(), 3);
    assert_ne!(
        prefix.anchor().frame_hash(),
        journal.position().frame_hash()
    );

    // The capture carries the exact real scan facts of the applied prefix.
    assert_eq!(
        cold.facts.schema_contract_version,
        MEMORY_V1_CANDIDATE_SCHEMA_VERSION
    );
    assert_ne!(cold.facts.schema_fingerprint, [0; 32]);
    assert!(cold.facts.captured_at_unix_seconds > 0);
    let counts = cold.rows.table_counts();
    assert_eq!(cold.facts.snapshot_counts, counts);
    assert_eq!(cold.facts.scanned_counts, counts);
    assert_eq!(counts.users, 1);
    assert_eq!(counts.identity_cards, 1);
    assert_eq!(counts.tenants, 1);
    assert_eq!(counts.user_cards, 3);
    assert_eq!(
        counts.rule_sets
            + counts.rule_set_versions
            + counts.bindings
            + counts.binding_confirmations
            + counts.rule_set_change_confirmations,
        0
    );
    let mut captured_cards: Vec<[u8; 16]> = cold
        .rows
        .user_cards
        .iter()
        .map(|row| row.user_card_id)
        .collect();
    captured_cards.sort_unstable();
    let mut expected_cards: Vec<[u8; 16]> = cards.iter().map(|card| *card.as_bytes()).collect();
    expected_cards.sort_unstable();
    assert_eq!(captured_cards, expected_cards);

    // The durable tail: the deny advanced only the journal sequence.
    let progress = read_memory_v1_apply_progress(&pool, stream)
        .await
        .unwrap()
        .expect("the provisioned progress tail");
    assert_eq!(progress.epoch_id, epoch);
    assert_eq!(progress.last_journal_sequence, 4);
    assert_eq!(progress.last_mutation_sequence, 3);
    assert_eq!(progress.last_frame_hash, records[3].frame_hash);

    // Every retained frame holds an ordered receipt that binds the ORIGINAL
    // producer boot and the exact frame digests, written by the startup
    // recovery worker; each frame chains to its predecessor's digest.
    type ReceiptRow = (
        u64,
        u64,
        Vec<u8>,
        String,
        Vec<u8>,
        Vec<u8>,
        String,
        String,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        u16,
    );
    let receipts = sqlx::query_as::<_, ReceiptRow>(
        "SELECT journal_sequence, mutation_sequence, message_id, \
         CONVERT(operation_id USING utf8mb4) AS operation_id, boot_id, \
         applied_by_boot_id, CONVERT(worker_id USING utf8mb4) AS worker_id, \
         CONVERT(outcome USING utf8mb4) AS outcome, prev_frame_hash, frame_digest, payload_digest, \
         fact_operation_count FROM mv1_apply_receipt WHERE stream_id = ? ORDER BY journal_sequence",
    )
    .bind(&stream.as_bytes()[..])
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(receipts.len(), 4);
    for (index, (record, row)) in records.iter().zip(receipts.iter()).enumerate() {
        assert_eq!(row.0, record.journal_sequence, "frame {index}");
        assert_eq!(row.1, record.mutation_sequence, "frame {index}");
        assert_eq!(
            row.2,
            record.message_id.as_bytes().to_vec(),
            "frame {index}"
        );
        assert_eq!(row.3, record.operation_id, "frame {index}");
        // The receipt binds the ORIGINAL producer boot recorded in the
        // retained frame, never an invented consumer identity.
        assert_eq!(
            row.4,
            record.origin_boot_id.unwrap().as_bytes().to_vec(),
            "frame {index}"
        );
        assert_eq!(
            row.5,
            journal_producer_boot_id().as_bytes().to_vec(),
            "frame {index}"
        );
        assert_eq!(row.6, "startup-recovery", "frame {index}");
        assert_eq!(
            row.7,
            if record.kind == RecordKind::Mutation {
                "APPLIED"
            } else {
                "DENY"
            },
            "frame {index}"
        );
        assert_eq!(row.8, record.prev_hash.to_vec(), "frame {index}");
        assert_eq!(row.9, record.frame_hash.to_vec(), "frame {index}");
        assert_eq!(row.10, record.payload_digest.to_vec(), "frame {index}");
        assert_eq!(
            row.11,
            if record.kind == RecordKind::Mutation {
                1
            } else {
                0
            },
            "frame {index}"
        );
    }

    // The append-only audit rows: mutations carry their engine trusted time,
    // root digest and actor; the raw deny observation carries its read-start
    // sample and NO trusted time, with the observed sequence 1.
    type AuditRow = (
        u64,
        u64,
        String,
        Option<i64>,
        Option<i64>,
        Vec<u8>,
        Vec<u8>,
        String,
        Vec<u8>,
    );
    let audit_rows = sqlx::query_as::<_, AuditRow>(
        "SELECT journal_sequence, mutation_sequence, CONVERT(decision USING utf8mb4) AS decision, \
         audit_time_unix, read_started_at_unix, root_content_hash, actor_user_id, \
         CONVERT(operation_id USING utf8mb4) AS operation_id, message_id \
         FROM mv1_apply_audit_event WHERE stream_id = ? ORDER BY journal_sequence",
    )
    .bind(&stream.as_bytes()[..])
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(audit_rows.len(), 4);
    for (index, row) in audit_rows.iter().enumerate() {
        let record = &records[index];
        assert_eq!(row.0, record.journal_sequence, "audit {index}");
        assert_eq!(row.7, record.operation_id, "audit {index}");
        assert_eq!(
            row.8,
            record.message_id.as_bytes().to_vec(),
            "audit {index}"
        );
        if record.kind == RecordKind::Mutation {
            assert_eq!(row.1, record.mutation_sequence, "audit {index}");
            assert_eq!(row.2, "ALLOW", "audit {index}");
            assert_eq!(row.3, Some(TRUSTED_TIME), "audit {index}");
            assert_eq!(row.4, None, "audit {index}");
            assert_eq!(row.5, OBSERVED_DIGEST.to_vec(), "audit {index}");
            assert_eq!(row.6, user.as_bytes().to_vec(), "audit {index}");
        } else {
            assert_eq!(row.1, 1, "audit {index}");
            assert!(row.2.starts_with("DENY:"), "audit {index}: {}", row.2);
            assert_eq!(row.3, None, "audit {index}");
            assert_eq!(row.4, Some(TRUSTED_TIME), "audit {index}");
            assert_eq!(row.5, OBSERVED_DIGEST.to_vec(), "audit {index}");
        }
    }

    // The backfilled suffix produced the real supported facts.
    let active_cards = count_scalar(
        &pool,
        "SELECT CAST(COUNT(*) AS SIGNED) FROM memory_user_card \
         WHERE user_id = ? AND status = 'ACTIVE'",
        &user,
    )
    .await;
    assert_eq!(active_cards, 3);
    let audit_total = count_scalar(
        &pool,
        "SELECT CAST(COUNT(*) AS SIGNED) FROM mv1_apply_audit_event WHERE stream_id = ?",
        &stream,
    )
    .await;
    assert_eq!(audit_total, 4);

    drop(cold);
    drop(journal);
    drop(durability);

    // Second reopen: the identical history must now verify purely through the
    // receipts — no suffix is applied again, and the append-only audit trail
    // is unchanged.
    let (journal, durability) = MemoryV1DurableJournal::open_checkpointed(
        &dir.path(),
        &dir.checkpoint(),
        install,
        stream,
        epoch,
        genesis,
        limits,
    )
    .unwrap();
    let records = journal.recovery_records();
    let cold =
        ReconciledColdInstall::capture_and_bind(&pool, &journal, &durability, capture_budget())
            .await
            .unwrap();
    let audit_total_now = count_scalar(
        &pool,
        "SELECT CAST(COUNT(*) AS SIGNED) FROM mv1_apply_audit_event WHERE stream_id = ?",
        &stream,
    )
    .await;
    let receipt_total_now = count_scalar(
        &pool,
        "SELECT CAST(COUNT(*) AS SIGNED) FROM mv1_apply_receipt WHERE stream_id = ?",
        &stream,
    )
    .await;
    assert_eq!(
        audit_total_now, audit_total,
        "re-verification appends nothing"
    );
    assert_eq!(receipt_total_now, 4);
    let prefix = cold.prefix.expect("the re-verified prefix binds");
    assert_eq!(prefix.anchor().journal_sequence(), 3);
    assert_eq!(prefix.anchor().mutation_sequence(), 3);
    assert_eq!(prefix.anchor().frame_hash(), &records[2].frame_hash);
    assert_eq!(prefix.epoch(), epoch);

    // The adoption gate stays independent of the completed reconciliation:
    // the same bound candidate still refuses on the gate's own missing family
    // even though the database is fully reconciled. (The optional isolated
    // Serving adoption is out of scope for this minimal case.)
    let refusal = owner_of(&cold, prefix)
        .adopt_with_production_evidence(&cold.facts, &ProductionEvidenceInput::default())
        .unwrap_err();
    assert!(
        matches!(
            refusal,
            RootError::AdoptionEvidence(AdoptionEvidenceError::Missing("source provenance"))
        ),
        "a reconciled database is not adoption evidence: {refusal:?}"
    );

    // Change only the retained audit JSON, leaving both digest columns and
    // the exact progress tail untouched. Startup must still refuse the row.
    let changed = sqlx::query(
        "UPDATE mv1_apply_audit_event \
         SET canonical_payload = JSON_SET(canonical_payload, '$.reason_code', ?) \
         WHERE stream_id = ? AND journal_sequence = ?",
    )
    .bind("TEST_MISMATCH")
    .bind(&stream.as_bytes()[..])
    .bind(2_u64)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(changed.rows_affected(), 1);
    println!("checking refusal of mismatched stored audit payload");
    let refused =
        ReconciledColdInstall::capture_and_bind(&pool, &journal, &durability, capture_budget())
            .await;
    assert!(
        matches!(refused, Err(super::ColdInstallError::AppliedHistory(ref detail))
        if detail.contains("retained frame 2"))
    );
    assert_eq!(
        read_memory_v1_apply_progress(&pool, stream).await.unwrap(),
        Some(progress)
    );
}

// memory—v1: Install the exact bound candidate into the isolated test registry
// (never the process one-shot slot) so the production evidence gate can judge
// the real captured facts on its own.
fn owner_of(cold: &ReconciledColdInstall, prefix: super::GovernancePrefix) -> RootOwner {
    let selections = cold.rows.current_version_selections().unwrap();
    assert!(
        selections.is_empty(),
        "the run-scoped candidate has no rule sets"
    );
    install_isolated_test_root_with_governance_prefix(
        cold.rows.clone(),
        selections,
        astral_authorization_root::memory_v1_hamt::CandidateBudget {
            max_table_rows: 64,
            max_bindings_per_read: 8,
        },
        Some(prefix),
    )
    .unwrap()
}

// memory—v1: The real-MySQL `verify_applied_history` performance fixture
// (ignored), wired as a child module so it reuses this module's run-scoped
// helpers, constants and dependency gate unchanged.
mod perf;
