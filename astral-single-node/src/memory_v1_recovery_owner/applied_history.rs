//! memory—v1: Recover the already-applied prefix from an installation-checked journal.

mod consume;
mod payload;

use payload::RetainedPayload;

use anyhow::{ensure, Context, Result};
use astral_db::memory_v1_apply::{
    read_memory_v1_apply_progress, reconcile_memory_v1_unknown_commit,
    verify_memory_v1_applied_prefix_batch, MemoryV1ApplyFrameKind, MemoryV1ApplyIdentity,
    MemoryV1ApplyPredecessor, MemoryV1ApplyProgressRow, MemoryV1ApplyReconciliation,
    MemoryV1ApplyReconciliationInput, MEMORY_V1_APPLY_PREFIX_BATCH,
};
use astral_types::memory_v1::MemoryId;
use astral_types::memory_v1_journal::{JournalAnchor, RecordKind};
use sqlx::MySqlPool;

use crate::memory_v1_durable_journal::{JournalDurability, MemoryV1DurableJournal, RecoveryRecord};

// memory—v1: Use the verifier's pre-frame position for DENY. Its observed state can be older.
fn frame_anchor(stream: MemoryId, record: &RecoveryRecord) -> Result<JournalAnchor> {
    JournalAnchor::new(
        stream,
        record.journal_sequence,
        record.applied_mutation_sequence(),
        record.frame_hash,
    )
    .map_err(|_| anyhow::anyhow!("invalid verified recovery anchor"))
}

// memory—v1: The caller holds the reopened journal throughout reconciliation and cold capture.
fn message_identity(
    stream_id: MemoryId,
    epoch_id: MemoryId,
    record: &RecoveryRecord,
) -> Result<MemoryV1ApplyIdentity> {
    Ok(MemoryV1ApplyIdentity {
        stream_id,
        epoch_id,
        journal_sequence: record.journal_sequence,
        mutation_sequence: record.mutation_sequence,
        message_id: record.message_id,
        operation_id: record.operation_id.clone(),
        origin_boot_id: record
            .origin_boot_id
            .context("retained journal frame lacks its producer boot identity")?,
        request_fingerprint: record.request_fingerprint,
        prev_frame_hash: record.prev_hash,
        frame_digest: record.frame_hash,
        payload_digest: record.payload_digest,
        frame_kind: match record.kind {
            RecordKind::Mutation => MemoryV1ApplyFrameKind::Mutation,
            RecordKind::Deny => MemoryV1ApplyFrameKind::Deny,
        },
    })
}

// memory—v1: Match the database tail to a specific retained anchor before processing any suffix.
fn applied_count(
    journal: &MemoryV1DurableJournal,
    baseline: JournalAnchor,
    progress: &MemoryV1ApplyProgressRow,
) -> Result<usize> {
    ensure!(
        progress.epoch_id == journal.epoch_id(),
        "foreign apply epoch"
    );
    let count = progress
        .last_journal_sequence
        .checked_sub(baseline.journal_sequence())
        .and_then(|n| usize::try_from(n).ok())
        .context("apply progress precedes the retained baseline")?;
    let expected = match count.checked_sub(1) {
        None => baseline,
        Some(index) => frame_anchor(
            journal.stream_id(),
            journal
                .recovery_records()
                .get(index)
                .context("apply progress exceeds the retained journal")?,
        )?,
    };
    ensure!(
        expected.journal_sequence() == progress.last_journal_sequence
            && expected.mutation_sequence() == progress.last_mutation_sequence
            && expected.frame_hash() == &progress.last_frame_hash,
        "apply progress conflicts with the retained journal"
    );
    Ok(count)
}

/// memory—v1: Verify existing receipts, then consume each remaining verified frame in order.
/// The caller enforces the startup deadline and compares the exact tail again inside the fact snapshot.
pub async fn verify_applied_history(
    pool: &MySqlPool,
    journal: &MemoryV1DurableJournal,
    durability: &JournalDurability,
) -> Result<()> {
    let checkpoint = durability
        .checkpoint_latest()
        .context("recovery requires the independent installation checkpoint")?;
    ensure!(
        checkpoint.epoch_id() == journal.epoch_id()
            && checkpoint.coverage_anchor() == Some(journal.position())
            && checkpoint.journal_offset() == journal.file_position(),
        "recovery checkpoint differs from the open journal"
    );
    let records = journal.recovery_records();
    ensure!(
        u64::try_from(records.len())? == journal.record_count(),
        "recovery requires the complete, reopened history"
    );
    let progress = read_memory_v1_apply_progress(pool, journal.stream_id())
        .await?
        .context("missing provisioned apply progress")?;
    let count = applied_count(journal, checkpoint.baseline(), &progress)?;
    let verify_started = std::time::Instant::now();
    let batches = verify_prefix(pool, journal, &progress, &records[..count]).await?;
    tracing::debug!(frames = count, batches, elapsed = ?verify_started.elapsed(), "verified memory-v1 apply prefix");
    let consume_started = std::time::Instant::now();
    consume::consume_suffix(pool, journal, &records[count..]).await?;
    tracing::debug!(frames = records.len() - count, elapsed = ?consume_started.elapsed(), "recovered memory-v1 apply suffix");
    Ok(())
}

// memory—v1: Bound decoded payload working memory separately from the SQL row limit.
async fn verify_prefix(
    pool: &MySqlPool,
    journal: &MemoryV1DurableJournal,
    progress: &MemoryV1ApplyProgressRow,
    mut records: &[RecoveryRecord],
) -> Result<usize> {
    const PAYLOAD_BUDGET: usize = 8 * astral_types::memory_v1_journal::MAX_PAYLOAD_BYTES;
    let mut batches = 0;
    while !records.is_empty() {
        let mut bytes = 0;
        let count = records
            .iter()
            .take(MEMORY_V1_APPLY_PREFIX_BATCH)
            .take_while(|record| {
                bytes += record.payload.len();
                bytes <= PAYLOAD_BUDGET
            })
            .count();
        ensure!(
            count != 0,
            "retained recovery frame exceeds the batch budget"
        );
        let (batch, next) = records.split_at(count);
        let decoded = batch
            .iter()
            .map(|record| {
                let identity = message_identity(journal.stream_id(), journal.epoch_id(), record)?;
                let payload = RetainedPayload::decode(record, &identity)?;
                Ok((identity, payload, record.prev_mutation_sequence))
            })
            .collect::<Result<Vec<_>>>()?;
        let inputs = decoded
            .iter()
            .map(|(identity, payload, predecessor)| {
                Ok(MemoryV1ApplyReconciliationInput {
                    identity: identity.clone(),
                    predecessor: Some(MemoryV1ApplyPredecessor {
                        mutation_sequence: *predecessor,
                    }),
                    verified_content: Some(payload.audit_content()?),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        verify_memory_v1_applied_prefix_batch(pool, progress, &inputs).await?;
        records = next;
        batches += 1;
    }
    Ok(batches)
}

// memory—v1: An existing receipt must prove the independent audit and the same ordered frame.
async fn verify_receipt(
    pool: &MySqlPool,
    identity: &MemoryV1ApplyIdentity,
    record: &RecoveryRecord,
    payload: &RetainedPayload,
) -> Result<()> {
    let input = MemoryV1ApplyReconciliationInput {
        identity: identity.clone(),
        predecessor: Some(MemoryV1ApplyPredecessor {
            mutation_sequence: record.prev_mutation_sequence,
        }),
        verified_content: Some(payload.audit_content()?),
    };
    let proof = reconcile_memory_v1_unknown_commit(pool, input).await?;
    ensure!(
        matches!(proof, MemoryV1ApplyReconciliation::ReceiptMatches(receipt) if receipt.identity == *identity),
        "receipt or audit reconciliation failed at retained frame {}",
        record.journal_sequence
    );
    Ok(())
}
