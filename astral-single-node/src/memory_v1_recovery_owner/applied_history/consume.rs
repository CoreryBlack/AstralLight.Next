//! memory—v1: Apply only the next verified local frame under the startup consumer lease.

use anyhow::{bail, ensure, Context, Result};
use astral_db::memory_v1_apply::{
    apply_memory_v1_deny_observation, apply_memory_v1_mutation_message,
    claim_memory_v1_apply_lease, release_memory_v1_apply_lease,
    MemoryV1ApplyDenyObservationRequest, MemoryV1ApplyFenceToken, MemoryV1ApplyLease,
    MemoryV1ApplyLeaseClaim, MemoryV1ApplyOutcome, MemoryV1ApplyPredecessor, MemoryV1ApplyRequest,
};
use astral_db::memory_v1_apply_plan::{ApplyPlanInput, MemoryV1ApplyPlan};
use astral_trustgraph::service::memory_v1_mutation_coordinator::journal_producer_boot_id;
use sqlx::MySqlPool;

use super::{frame_anchor, message_identity, MemoryV1DurableJournal, RecoveryRecord};

// memory—v1: One attempt per retained identity. Cancellation leaves the lease to expire.
pub(super) async fn consume_suffix(
    pool: &MySqlPool,
    journal: &MemoryV1DurableJournal,
    suffix: &[RecoveryRecord],
) -> Result<()> {
    if suffix.is_empty() {
        return Ok(());
    }
    let stream = journal.stream_id();
    let lease = MemoryV1ApplyLease {
        boot_id: journal_producer_boot_id(),
        worker_id: "startup-recovery".to_owned(),
        lease_ttl_seconds: 45,
    };
    let MemoryV1ApplyLeaseClaim::Claimed { token } =
        claim_memory_v1_apply_lease(pool, &lease, stream).await?
    else {
        bail!("apply lease is busy during recovery");
    };
    let consumed = async {
        for record in suffix {
            consume_frame(pool, journal, record, &token)
                .await
                .with_context(|| format!("recover retained frame {}", record.journal_sequence))?;
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let released = release_memory_v1_apply_lease(pool, &token, stream).await;
    consumed?;
    ensure!(released? == 1, "startup lost the consumer lease");
    Ok(())
}

// memory—v1: Decode the original audit value and pass the original producer identity to the transaction.
async fn consume_frame(
    pool: &MySqlPool,
    journal: &MemoryV1DurableJournal,
    record: &RecoveryRecord,
    token: &MemoryV1ApplyFenceToken,
) -> Result<()> {
    let identity = message_identity(journal.stream_id(), journal.epoch_id(), record)?;
    let payload = super::RetainedPayload::decode(record, &identity)?;
    let result = match &payload {
        super::RetainedPayload::Deny(observation) => {
            apply_memory_v1_deny_observation(
                pool,
                MemoryV1ApplyDenyObservationRequest {
                    identity: identity.clone(),
                    observation,
                    fence: token.clone(),
                    predecessor: MemoryV1ApplyPredecessor {
                        mutation_sequence: record.prev_mutation_sequence,
                    },
                },
            )
            .await?
        }
        super::RetainedPayload::Mutation(decoded) => {
            let audit = super::payload::single_event(decoded)?;
            let plan = MemoryV1ApplyPlan::build(ApplyPlanInput {
                mutation: decoded.mutation(),
                audit: Some(audit),
                flow: Some(frame_anchor(identity.stream_id, record)?),
            });
            apply_memory_v1_mutation_message(
                pool,
                MemoryV1ApplyRequest {
                    identity: identity.clone(),
                    plan,
                    audit,
                    fence: token.clone(),
                },
            )
            .await?
        }
    };
    match result {
        MemoryV1ApplyOutcome::Applied(receipt) if receipt.identity == identity => Ok(()),
        MemoryV1ApplyOutcome::Duplicate(receipt) if receipt.identity == identity => {
            super::verify_receipt(pool, &identity, record, &payload).await
        }
        MemoryV1ApplyOutcome::Denied(refusal) => {
            bail!("database apply refused frame: {:?}", refusal.reason)
        }
        _ => bail!("apply receipt differs from the retained frame"),
    }
}
