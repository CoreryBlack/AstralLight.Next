//! memory—v1: Real-MySQL performance fixture for
//! `crate::memory_v1_recovery_owner::verify_applied_history` (ignored
//! integration; Rust 规范 §15.10.4 evidence, task `mv1-perf-history-fixture`).
//!
//! The fixture measures the recovery verification alone, in two separate
//! phases per workload size, and never captures, installs, or adopts a root:
//! the process registry, the one-shot slot and any root instance stay
//! untouched.
//!
//! - Ordered DB suffix catch-up: the provisioned progress tail is genesis, so
//!   the whole retained journal is one ordered suffix consumed under the
//!   startup consumer lease; the measured call is the whole
//!   `verify_applied_history` execution. This phase must finish within the
//!   startup lease TTL (45 s), exactly like the production startup shape.
//! - Already-applied prefix re-verification: after the suffix applied, the
//!   reopened journal re-verifies the identical history purely through the
//!   durable receipts; the measured call again covers the whole execution.
//!   The largest workload takes one unmeasured warmup pass and three warm
//!   samples.
//!
//! Workloads are bounded and run-scoped: sizes [128, 1024, 4096] mutations
//! plus three trailing historical DENY frames each (observing quarter-, half-
//! and current-tail lag, mirroring the parent contract's historical deny at
//! workload scale), written as ONE journal batch with exactly one durability
//! sync — one group-commit flush and one sidecar checkpoint. Every stream,
//! epoch and row identity is a fresh UUID, all SQL is parameterized, and
//! nothing here executes DDL, SSH, a service, a migration or a root mutation.
//! The journal lives in a private (mode 0700) temp directory, so a Linux
//! umask 002 never widens it and the durable journal's own parent validation
//! accepts it; the directory is removed when the fixture ends. Before any
//! phase duration is reported, the exact progress tail, receipt count, audit
//! count, applied fact count and an idle apply fence (no active lease) are
//! asserted. Phase durations come from the monotonic `Instant` clock, each
//! measured region contains exactly one `verify_applied_history` call and no
//! other statement, and every duration is asserted non-zero as a monotonic
//! clock sanity gate. The fixture runs unchanged against the current and any
//! later recovery implementation: it asserts the observable contract (counts,
//! tail, idle fence), never internals, and reports timings without judging
//! them. The isolated refusal checks stay with the parent contract test.
//!
//! Escalation behavior matches the parent module's gate: with
//! `RUST_INTEGRATION_REQUIRED=1` a missing MySQL dependency is a hard failure,
//! otherwise it is recorded as `[SKIP]` and never counted as a pass. The
//! MySQL URL travels only through the environment and is never logged or
//! stored; this source contains no secrets. Nothing in this file claims a
//! pass by itself: a real PASS is only the operator's explicit run with the
//! full evidence output below.
//!
//! Run explicitly:
//! `RUST_INTEGRATION_REQUIRED=1 \
//!  ASTRAL_MEMORY_V1_APPLY_TEST_MYSQL_URL=mysql://... \
//!  cargo test -p astral-single-node --lib real_mysql_recovery_history_curve \
//!  -- --ignored --nocapture`

use std::time::{Duration, Instant};

use astral_db::memory_v1_apply::{
    initialize_memory_v1_apply_progress, read_memory_v1_apply_progress, MemoryV1ApplyProgressInit,
};
use astral_trustgraph::service::memory_v1_mutation_coordinator::{
    DenyJournalRequest, JournalIdentity,
};
use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use astral_types::memory_v1_audit::{MemoryV1AuditDenySource, MemoryV1AuditRootStatus};
use astral_types::memory_v1_deny_observation::{
    MemoryV1DenyAffectedBindingState, MemoryV1DenyObservation, MemoryV1DenyRootObservation,
};
use astral_types::memory_v1_journal::{JournalAnchor, RecordKind};
use uuid::Uuid;

use super::{
    count_scalar, create_request, random_id, real_recovery_pool, GENESIS_HASH, OBSERVED_DIGEST,
    TRUSTED_TIME,
};
use crate::memory_v1_durable_journal::{
    CheckpointInstallId, DurableJournalLimits, LocalCheckpointCoverage, LocalCheckpointStore,
    MemoryV1DurableJournal,
};
use crate::memory_v1_recovery_owner::verify_applied_history;

/// The bounded workload sizes: one curve point per size.
const SIZES: [u64; 3] = [128, 1024, 4096];
/// The warm already-applied prefix re-verification samples at the top size.
const WARM_PREFIX_SAMPLES: usize = 3;
/// Historical DENY frames appended after the mutations of every workload.
const DENY_FRAMES: u64 = 3;

/// One measured curve point: the two separately measured phases of one
/// bounded workload.
struct CurvePoint {
    mutations: u64,
    frames: u64,
    /// The whole execution consumed the ordered DB suffix (progress tail at
    /// genesis) under the startup consumer lease.
    suffix: Duration,
    /// The whole execution re-verified the already-applied prefix through the
    /// durable receipts; one sample per pass, three warm at the top size.
    prefix_samples: Vec<Duration>,
}

// memory—v1: Run-scoped temporary journal directory, created PRIVATE (mode
// 0700) so a Linux umask 002 never widens it and the durable journal's own
// parent validation accepts it; removed when the fixture ends.
struct PerfJournalDir(std::path::PathBuf);

impl PerfJournalDir {
    fn new(label: &str) -> Self {
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let dir = base.join(format!("astral-perf-history-{label}-{}", Uuid::new_v4()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&dir).unwrap();
        Self(dir)
    }
    fn path(&self) -> std::path::PathBuf {
        self.0.join("journal.bin")
    }
    fn checkpoint(&self) -> std::path::PathBuf {
        self.0.join("journal.ckpt")
    }
}

impl Drop for PerfJournalDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// memory—v1: One historical DENY frame appended after the workload's
// mutations: it observed `observed_sequence` while its retained predecessor is
// the workload's last mutation, mirroring the parent contract's historical
// deny shape (observed 1, retained predecessor 3) at the workload's scale.
#[allow(clippy::too_many_arguments)]
fn deny_request(
    stream: MemoryId,
    epoch: MemoryId,
    instance: MemoryId,
    run: &str,
    journal_sequence: u64,
    observed_sequence: u64,
    user: MemoryId,
    identity_card: MemoryId,
    tenant: MemoryId,
    card: MemoryId,
) -> DenyJournalRequest {
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
            observed_sequence,
            MemoryId::from_bytes((u128::from(journal_sequence) + 20).to_be_bytes()),
        )
        .unwrap(),
    )
    .unwrap()
}

// memory—v1: The older root state each trailing deny observed: quarter, half
// and current-tail lag, so the applied history mixes stale and current
// observations.
fn observed_sequence(mutations: u64, deny_index: u64) -> u64 {
    match deny_index {
        1 => (mutations / 4).max(1),
        2 => (mutations / 2).max(1),
        _ => mutations,
    }
}

// memory—v1: The apply fence for the run-scoped stream holds no live lease:
// the released token expired it, and an absent row is idle by construction.
async fn lease_is_idle(pool: &sqlx::MySqlPool, stream: &MemoryId) -> bool {
    let valid: Option<i64> = sqlx::query_scalar(
        "SELECT CAST(lease_expires_at > UTC_TIMESTAMP(6) AS SIGNED) \
         FROM mv1_apply_fence WHERE stream_id = ?",
    )
    .bind(&stream.as_bytes()[..])
    .fetch_optional(pool)
    .await
    .unwrap();
    valid.unwrap_or(0) == 0
}

// memory—v1: One monotonic-clock timing of exactly one awaited call: the
// measured region contains no other statement, and the duration is asserted
// non-zero so a collapsed or non-monotonic measurement cannot pass silently.
async fn timed<T>(
    label: &'static str,
    call: impl std::future::Future<Output = T>,
) -> (T, Duration) {
    let start = Instant::now();
    let value = call.await;
    let elapsed = start.elapsed();
    assert!(
        elapsed > Duration::ZERO,
        "{label} measured a zero duration on the monotonic clock"
    );
    (value, elapsed)
}

// memory—v1: One bounded, run-scoped workload: write `mutations` supported
// UserCardCreate frames plus `DENY_FRAMES` trailing historical denies as ONE
// journal batch with exactly one durability sync, then measure the whole
// `verify_applied_history` execution for the ordered suffix catch-up and, on
// the production reopen, for the already-applied prefix re-verification.
// Exact progress/receipt/audit/fact counts and an idle apply fence gate every
// reported duration. No capture, no root install, no adoption: the recovery
// verification alone is the measured subject.
async fn run_workload(
    pool: &sqlx::MySqlPool,
    run: &str,
    mutations: u64,
    prefix_samples: usize,
) -> CurvePoint {
    // memory—v1: The operation identity is the global receipt/audit dedup
    // identity, so every workload derives its own run label; one shared label
    // across sizes would collide `{run}-mut-{sequence}` across streams.
    let run = format!("{run}-{mutations}");
    let frames = mutations + DENY_FRAMES;
    let stream = random_id();
    let epoch = random_id();
    let instance = random_id();
    let user = random_id();
    let identity_card = random_id();
    let tenant = random_id();
    let genesis = JournalAnchor::new(stream, 0, 0, GENESIS_HASH).unwrap();
    let limits = DurableJournalLimits::conservative();
    let install = CheckpointInstallId::from_install_uuid(*Uuid::new_v4().as_bytes()).unwrap();
    let dir = PerfJournalDir::new("perf-history");

    // Run-scoped reference parents, parameterized SQL only.
    sqlx::query("INSERT INTO memory_user (user_id) VALUES (?)")
        .bind(&user.as_bytes()[..])
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO memory_identity_card (identity_card_id, user_id) VALUES (?, ?)")
        .bind(&identity_card.as_bytes()[..])
        .bind(&user.as_bytes()[..])
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO memory_tenant (tenant_id) VALUES (?)")
        .bind(&tenant.as_bytes()[..])
        .execute(pool)
        .await
        .unwrap();

    // Writer phase: every frame is appended without a per-frame sync, then ONE
    // batch durability confirmation — one group-commit flush and one sidecar
    // checkpoint covering the whole tail.
    let mut cards = Vec::new();
    let mut final_end = 0_u64;
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
        assert!(matches!(
            initialize_memory_v1_apply_progress(pool, stream, epoch, GENESIS_HASH)
                .await
                .unwrap(),
            MemoryV1ApplyProgressInit::Initialized
        ));
        for sequence in 1..=mutations {
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
            final_end = journal
                .prepare_mutation(&request, &durability)
                .unwrap()
                .durable_end;
            cards.push(card);
        }
        for deny_index in 1..=DENY_FRAMES {
            let observed = observed_sequence(mutations, deny_index);
            let deny = deny_request(
                stream,
                epoch,
                instance,
                &run,
                mutations + deny_index,
                observed,
                user,
                identity_card,
                tenant,
                cards[(observed - 1) as usize],
            );
            final_end = journal
                .prepare_deny(&deny, &durability)
                .unwrap()
                .durable_end;
        }
        // memory—v1: the one batch journal write/sync of this fixture.
        durability.ensure_durable(final_end).unwrap();
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
    assert_eq!(records.len() as u64, frames, "retained frame count");
    for (index, record) in records[..mutations as usize].iter().enumerate() {
        assert_eq!(record.kind, RecordKind::Mutation, "frame {index}");
        assert_eq!(record.mutation_sequence, index as u64 + 1, "frame {index}");
    }
    for (index, record) in records[mutations as usize..].iter().enumerate() {
        assert_eq!(
            record.kind,
            RecordKind::Deny,
            "frame {}",
            mutations as usize + index
        );
        assert_eq!(
            record.journal_sequence,
            mutations + index as u64 + 1,
            "frame {}",
            mutations as usize + index
        );
        assert_eq!(
            record.prev_mutation_sequence, mutations,
            "the deny's retained predecessor"
        );
        // The lagging denies observe strictly historical states; the last deny
        // observes the current tail itself, which the journal accepts as
        // observed <= retained predecessor.
        let observed = observed_sequence(mutations, index as u64 + 1);
        assert_eq!(
            record.mutation_sequence, observed,
            "the deny's observed sequence"
        );
        assert!(
            record.mutation_sequence <= record.prev_mutation_sequence,
            "the deny observed a state ahead of its retained predecessor"
        );
    }

    // Phase one, measured: the ordered DB suffix catch-up (progress tail at
    // genesis, so the whole journal is the suffix).
    let (verified, suffix) = timed(
        "suffix catch-up",
        verify_applied_history(pool, &journal, &durability),
    )
    .await;
    verified.expect("the ordered suffix catch-up verifies");

    // Exact seam state before the suffix duration is reported.
    let progress = read_memory_v1_apply_progress(pool, stream)
        .await
        .unwrap()
        .expect("the provisioned progress tail");
    assert_eq!(progress.epoch_id, epoch, "progress epoch");
    assert_eq!(
        progress.last_journal_sequence, frames,
        "progress journal tail"
    );
    assert_eq!(
        progress.last_mutation_sequence, mutations,
        "progress mutation tail"
    );
    assert_eq!(
        progress.last_frame_hash,
        records.last().unwrap().frame_hash,
        "progress frame digest"
    );
    let receipt_total = count_scalar(
        pool,
        "SELECT CAST(COUNT(*) AS SIGNED) FROM mv1_apply_receipt WHERE stream_id = ?",
        &stream,
    )
    .await;
    assert_eq!(receipt_total, frames as i64, "receipt count");
    let audit_total = count_scalar(
        pool,
        "SELECT CAST(COUNT(*) AS SIGNED) FROM mv1_apply_audit_event WHERE stream_id = ?",
        &stream,
    )
    .await;
    assert_eq!(audit_total, frames as i64, "audit count");
    let active_cards = count_scalar(
        pool,
        "SELECT CAST(COUNT(*) AS SIGNED) FROM memory_user_card \
         WHERE user_id = ? AND status = 'ACTIVE'",
        &user,
    )
    .await;
    assert_eq!(active_cards, mutations as i64, "applied fact count");
    assert!(lease_is_idle(pool, &stream).await, "no active lease");
    assert_eq!(journal.position().journal_sequence(), frames);
    assert_eq!(journal.position().mutation_sequence(), mutations);

    // Phase two, measured on the production reopen: the identical history
    // re-verifies purely through the durable receipts. The largest workload
    // takes one unmeasured warmup pass and then its warm samples.
    drop(journal);
    drop(durability);
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
    if prefix_samples > 1 {
        verify_applied_history(pool, &journal, &durability)
            .await
            .expect("the prefix re-verification warmup passes");
    }
    let mut measured = Vec::new();
    for sample in 1..=prefix_samples {
        let (verified, elapsed) = timed(
            "prefix re-verification",
            verify_applied_history(pool, &journal, &durability),
        )
        .await;
        verified.expect("the prefix re-verification passes");
        eprintln!(
            "[perf] run={run} size={mutations} frames={frames} phase=prefix-re-verify \
             sample={sample} nanos={} per_frame_nanos={}",
            elapsed.as_nanos(),
            elapsed.as_nanos() / u128::from(frames),
        );
        measured.push(elapsed);
    }

    // The append-only trail and the reconciled tail are unchanged by
    // re-verification.
    let receipt_total_now = count_scalar(
        pool,
        "SELECT CAST(COUNT(*) AS SIGNED) FROM mv1_apply_receipt WHERE stream_id = ?",
        &stream,
    )
    .await;
    assert_eq!(
        receipt_total_now, receipt_total,
        "re-verification appends no receipt"
    );
    let audit_total_now = count_scalar(
        pool,
        "SELECT CAST(COUNT(*) AS SIGNED) FROM mv1_apply_audit_event WHERE stream_id = ?",
        &stream,
    )
    .await;
    assert_eq!(
        audit_total_now, audit_total,
        "re-verification appends no audit"
    );
    let progress_now = read_memory_v1_apply_progress(pool, stream)
        .await
        .unwrap()
        .expect("the reconciled progress tail");
    assert_eq!(
        progress_now, progress,
        "the exact progress tail is unchanged"
    );
    assert!(lease_is_idle(pool, &stream).await, "no active lease");

    drop(journal);
    drop(durability);

    CurvePoint {
        mutations,
        frames,
        suffix,
        prefix_samples: measured,
    }
}

// memory—v1: The real-MySQL recovery history curve (ignored). Fresh run-scoped
// identities per workload keep reruns against the shared operator database
// collision-free; the exact seam counts and the idle fence gate every reported
// duration, and the printed curve is evidence only, never a pass by itself.
#[tokio::test]
#[ignore = "requires isolated ASTRAL_MEMORY_V1_APPLY_TEST_MYSQL_URL with the operator-provisioned memory-v1 apply tables created"]
async fn real_mysql_recovery_history_curve() {
    let Some(pool) = real_recovery_pool().await else {
        return;
    };
    let run = format!("perf-history-{}", Uuid::new_v4().simple());
    let top = *SIZES.iter().max().unwrap();
    let mut points = Vec::new();
    for mutations in SIZES {
        let prefix_samples = if mutations == top {
            WARM_PREFIX_SAMPLES
        } else {
            1
        };
        let point = run_workload(&pool, &run, mutations, prefix_samples).await;
        eprintln!(
            "[perf] run={run} size={} frames={} phase=suffix-catch-up nanos={} \
             per_frame_nanos={}",
            point.mutations,
            point.frames,
            point.suffix.as_nanos(),
            point.suffix.as_nanos() / u128::from(point.frames),
        );
        points.push(point);
    }
    eprintln!(
        "[perf] run={run} task=mv1-perf-history-fixture sizes={SIZES:?} \
         top_prefix_warm_samples={WARM_PREFIX_SAMPLES}"
    );
    for point in &points {
        eprintln!(
            "[perf-summary] size={} frames={} suffix_nanos={} prefix_samples_nanos={:?}",
            point.mutations,
            point.frames,
            point.suffix.as_nanos(),
            point
                .prefix_samples
                .iter()
                .map(|sample| sample.as_nanos())
                .collect::<Vec<_>>(),
        );
    }
}
