//! memory—v1: Bounded verification of an already-applied startup prefix.

use futures_util::TryStreamExt;
use thiserror::Error;

use crate::memory_v1_apply_records::{stream_verified_prefix_rows, ProgressTailRow};

use super::{
    reconcile_decision, validate_identity, MemoryV1ApplyProgressRow, MemoryV1ApplyReconciliation,
    MemoryV1ApplyReconciliationInput,
};

/// The maximum number of retained frames in one startup verification query.
pub const MEMORY_V1_APPLY_PREFIX_BATCH: usize = 128;

/// A startup batch is usable only if every expected frame was proved.
#[derive(Debug, Error)]
pub enum MemoryV1ApplyPrefixError {
    #[error("invalid memory-v1 startup prefix batch")]
    InvalidBatch,
    #[error("memory-v1 startup prefix batch could not be encoded: {0}")]
    Encoding(#[from] serde_json::Error),
    #[error("memory-v1 startup prefix database read failed: {0}")]
    MySql(#[from] sqlx::Error),
    #[error("receipt, audit or progress could not be proved for retained frame {0}")]
    UnprovedFrame(u64),
}

/// memory—v1: Re-verify a contiguous batch of already-applied local frames.
/// Both independent receipt lookups and the expected progress are read in one
/// locking statement. This path is read-only and cannot prove `NotApplied` or
/// replace the single-message unknown-commit reconciliation path.
pub async fn verify_memory_v1_applied_prefix_batch(
    pool: &sqlx::MySqlPool,
    progress: &MemoryV1ApplyProgressRow,
    frames: &[MemoryV1ApplyReconciliationInput<'_>],
) -> Result<(), MemoryV1ApplyPrefixError> {
    let keys = batch_keys(progress, frames)?;
    let keys_json = serde_json::to_string(&keys)?;
    let stream = frames[0].identity.stream_id;
    let tail = ProgressTailRow {
        epoch_id: progress.epoch_id.as_bytes().to_vec(),
        last_journal_sequence: progress.last_journal_sequence,
        last_mutation_sequence: progress.last_mutation_sequence,
        last_frame_hash: progress.last_frame_hash.to_vec(),
    };
    let mut tx = pool.begin().await?;
    {
        let mut rows = stream_verified_prefix_rows(&mut tx, &stream, progress, keys_json);
        let mut seen = [false; MEMORY_V1_APPLY_PREFIX_BATCH];
        while let Some(row) = rows.try_next().await? {
            let index = usize::try_from(row.ordinal)
                .ok()
                .and_then(|ordinal| ordinal.checked_sub(1))
                .filter(|&index| index < frames.len())
                .ok_or(MemoryV1ApplyPrefixError::InvalidBatch)?;
            let frame = &frames[index];
            let proof = reconcile_decision(
                std::slice::from_ref(&row.joined),
                Some(&tail),
                &frame.identity,
                frame.predecessor.as_ref(),
                frame.verified_content.as_ref(),
            );
            if seen[index]
                || !matches!(proof, MemoryV1ApplyReconciliation::ReceiptMatches(receipt)
                    if receipt.identity == frame.identity)
            {
                return Err(MemoryV1ApplyPrefixError::UnprovedFrame(
                    frame.identity.journal_sequence,
                ));
            }
            seen[index] = true;
        }
        if let Some(index) = seen[..frames.len()].iter().position(|matched| !matched) {
            return Err(MemoryV1ApplyPrefixError::UnprovedFrame(
                frames[index].identity.journal_sequence,
            ));
        }
    }
    tx.commit().await?;
    Ok(())
}

// memory—v1: The only values sent to JSON_TABLE are validated numeric positions
// and ASCII operation identities in one stream and epoch.
fn batch_keys<'a>(
    progress: &MemoryV1ApplyProgressRow,
    frames: &'a [MemoryV1ApplyReconciliationInput<'_>],
) -> Result<Vec<(u64, &'a str)>, MemoryV1ApplyPrefixError> {
    let Some(first) = frames
        .first()
        .filter(|_| frames.len() <= MEMORY_V1_APPLY_PREFIX_BATCH)
    else {
        return Err(MemoryV1ApplyPrefixError::InvalidBatch);
    };
    frames
        .iter()
        .enumerate()
        .map(|(index, frame)| {
            let identity = &frame.identity;
            if validate_identity(identity).is_err()
                || frame.verified_content.is_none()
                || frame.predecessor.is_none()
                || identity.stream_id != first.identity.stream_id
                || identity.epoch_id != progress.epoch_id
                || Some(identity.journal_sequence)
                    != first.identity.journal_sequence.checked_add(index as u64)
                || identity.journal_sequence > progress.last_journal_sequence
            {
                return Err(MemoryV1ApplyPrefixError::InvalidBatch);
            }
            Ok((identity.journal_sequence, identity.operation_id.as_str()))
        })
        .collect()
}
