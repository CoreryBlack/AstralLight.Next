//! Bounded read-only observation of worker-owned projection completion.
//!
//! Source writers call this only after COMMIT has been proven and pass the full
//! immutable receipt batch. The request path never claims, compiles, publishes,
//! releases, or otherwise mutates worker state. LocalBus admission, ACK, a lone
//! `SUCCEEDED` status, or the latest pointer are not completion proofs.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use sqlx::MySqlPool;

use crate::observability::{record_sync_publish, SyncPublishMetricOutcome};
use crate::repository::authorization_source_transaction::{
    CommittedProjectionReceipts, InvalidationReceipt, SourceProjectionReceipt,
};

/// Overall wall-clock budget for observing one complete source receipt batch.
const PROJECTION_COMPLETION_WAIT_BUDGET: Duration = Duration::from_secs(5);
/// Defensive maximum receipt batch size. An oversized batch is handed to the worker whole.
const PROJECTION_COMPLETION_MAX_EVENTS: usize = 64;
/// Defensive maximum distinct card scopes accepted by one request-side wait.
const PROJECTION_COMPLETION_MAX_CARDS: usize = 50;
/// Poll interval for exact durable completion proofs.
const OWNED_COMPLETION_POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompletionWaitOutcome {
    /// Every receipt in the batch has an exact historical durable completion proof.
    Published,
    /// The worker still owns at least one receipt, or the batch exceeds bounded limits.
    Delegated,
    /// An exact read failed; do not infer completion or alter worker ownership.
    Failed,
}

#[derive(Debug, Clone)]
enum CompletionProbe {
    Delta(astral_db::DeltaEventAppendRequest),
    Source(SourceProjectionReceipt),
    Invalidation(InvalidationReceipt),
}

/// Wait, within a fixed budget, for full durable completion proofs for every
/// commit-proven receipt family. Timeout and oversized batches are delegated
/// intact to the worker. This function is deliberately observation-only.
pub(crate) async fn after_commit_wait_for_projection(
    pool: &MySqlPool,
    receipts: &CommittedProjectionReceipts,
) -> bool {
    let started = Instant::now();
    let count = receipt_count(receipts);
    if count == 0 {
        record_sync_publish(SyncPublishMetricOutcome::SkippedEmpty, started.elapsed());
        return false;
    }

    let outcome =
        wait_for_committed_completion(pool, receipts, PROJECTION_COMPLETION_WAIT_BUDGET).await;
    record_sync_publish(
        match outcome {
            CompletionWaitOutcome::Published => SyncPublishMetricOutcome::Published,
            CompletionWaitOutcome::Delegated => SyncPublishMetricOutcome::Delegated,
            CompletionWaitOutcome::Failed => SyncPublishMetricOutcome::Failed,
        },
        started.elapsed(),
    );

    match outcome {
        CompletionWaitOutcome::Published => tracing::debug!(
            receipts = count,
            "worker-owned completion proven for every source receipt family"
        ),
        CompletionWaitOutcome::Delegated => tracing::debug!(
            receipts = count,
            "worker-owned completion remains delegated to the durable workers"
        ),
        CompletionWaitOutcome::Failed => tracing::warn!(
            receipts = count,
            "worker-owned completion proof read failed; durable workers retain ownership"
        ),
    }
    matches!(outcome, CompletionWaitOutcome::Published)
}

/// Wait for exact durable completion and fail closed when a non-empty batch is
/// not proven within the bounded observation window. A proven source commit is
/// never rolled back or replayed; callers receive `PENDING` while WorkerOwned
/// processing remains the recovery path.
pub(crate) async fn require_committed_receipts(
    pool: &MySqlPool,
    receipts: &CommittedProjectionReceipts,
) -> Result<(), astral_types::AstralError> {
    if receipt_count(receipts) == 0 || after_commit_wait_for_projection(pool, receipts).await {
        return Ok(());
    }
    Err(astral_types::AstralError::Pending(
        "source committed; projection completion remains pending".into(),
    ))
}

/// Public(crate) completion result for asynchronous mutation owners that must
/// persist `IN_DOUBT` instead of claiming tracker completion.
pub(crate) async fn wait_for_committed_receipts(
    pool: &MySqlPool,
    receipts: &CommittedProjectionReceipts,
) -> bool {
    if receipt_count(receipts) == 0 {
        return false;
    }
    matches!(
        wait_for_committed_completion(pool, receipts, PROJECTION_COMPLETION_WAIT_BUDGET).await,
        CompletionWaitOutcome::Published
    )
}

fn receipt_count(receipts: &CommittedProjectionReceipts) -> usize {
    receipts.requests.len()
        + receipts.source_projection_receipts.len()
        + receipts.invalidation_receipts.len()
}

fn completion_probes(receipts: &CommittedProjectionReceipts) -> Vec<CompletionProbe> {
    receipts
        .requests
        .iter()
        .cloned()
        .map(CompletionProbe::Delta)
        .chain(
            receipts
                .source_projection_receipts
                .iter()
                .cloned()
                .map(CompletionProbe::Source),
        )
        .chain(
            receipts
                .invalidation_receipts
                .iter()
                .cloned()
                .map(CompletionProbe::Invalidation),
        )
        .collect()
}

fn affected_card_count(probes: &[CompletionProbe]) -> usize {
    probes
        .iter()
        .filter_map(|probe| match probe {
            CompletionProbe::Delta(request) => {
                request.card_id.map(|card_id| (request.tenant_id, card_id))
            }
            CompletionProbe::Source(receipt)
                if receipt.aggregate_type == astral_types::ProjectionAggregate::CARD
                    || receipt.aggregate_type == astral_types::ProjectionAggregate::ELIGIBILITY =>
            {
                Some((receipt.tenant_id.unwrap_or_default(), receipt.aggregate_id))
            }
            CompletionProbe::Source(_) | CompletionProbe::Invalidation(_) => None,
        })
        .collect::<HashSet<_>>()
        .len()
}

fn invalidation_completion_identity(
    receipt: &InvalidationReceipt,
) -> Option<astral_db::LocalMessageCompletionIdentity<'_>> {
    if receipt.event_id != receipt.envelope.message_id
        || receipt.operation_id != receipt.envelope.operation_id
    {
        return None;
    }
    Some(astral_db::LocalMessageCompletionIdentity {
        message_id: &receipt.event_id,
        operation_id: &receipt.operation_id,
        message_type: &receipt.envelope.message_type,
        queue_name: astral_mq::invalidation::INVALIDATION_QUEUE,
        payload_sha256: &receipt.envelope.payload_sha256,
    })
}

/// Bounded read-only waiter. Every family is checked against its own exact
/// durable identity; no ACK, bus admission, source head, or latest pointer is
/// accepted as a substitute for the matching row's terminal proof.
async fn wait_for_committed_completion(
    pool: &MySqlPool,
    receipts: &CommittedProjectionReceipts,
    budget: Duration,
) -> CompletionWaitOutcome {
    let probes = completion_probes(receipts);
    if probes.is_empty() {
        return CompletionWaitOutcome::Delegated;
    }
    if probes.len() > PROJECTION_COMPLETION_MAX_EVENTS {
        return CompletionWaitOutcome::Delegated;
    }
    if affected_card_count(&probes) > PROJECTION_COMPLETION_MAX_CARDS {
        return CompletionWaitOutcome::Delegated;
    }

    wait_for_completion_probes_with(&probes, budget, |probe| async move {
        match probe {
            CompletionProbe::Delta(request) => {
                match astral_db::load_owned_delta_completion(pool, &request).await {
                    Ok(proof) => Ok(proof.is_some()),
                    Err(error) => {
                        tracing::warn!(event_id = %request.event_id, error = %error,
                            "exact projection completion proof unavailable; worker ownership unchanged");
                        Err(())
                    }
                }
            }
            CompletionProbe::Source(receipt) => {
                let identity = astral_db::SourceProjectionCompletionIdentity {
                    event_id: &receipt.event_id,
                    aggregate_type: &receipt.aggregate_type,
                    aggregate_id: receipt.aggregate_id,
                    tenant_id: receipt.tenant_id,
                    source_generation: receipt.source_generation,
                    revoke_fence: receipt.revoke_fence,
                };
                match astral_db::load_exact_processed_source_projection(pool, &identity).await {
                    Ok(proven) => Ok(proven),
                    Err(error) => {
                        tracing::warn!(event_id = %receipt.event_id, error = %error,
                            "exact source projection completion proof unavailable");
                        Err(())
                    }
                }
            }
            CompletionProbe::Invalidation(receipt) => {
                let Some(identity) = invalidation_completion_identity(&receipt) else {
                    return Ok(false);
                };
                match astral_db::load_exact_processed_local_message(pool, &identity).await {
                    Ok(proven) => Ok(proven),
                    Err(error) => {
                        tracing::warn!(event_id = %receipt.event_id, error = %error,
                            "exact invalidation completion proof unavailable");
                        Err(())
                    }
                }
            }
        }
    })
    .await
}

async fn wait_for_completion_probes_with<F, Fut>(
    probes: &[CompletionProbe],
    budget: Duration,
    exact_completion: F,
) -> CompletionWaitOutcome
where
    F: FnMut(CompletionProbe) -> Fut,
    Fut: std::future::Future<Output = Result<bool, ()>>,
{
    wait_for_family(
        probes,
        tokio::time::Instant::now() + budget,
        exact_completion,
    )
    .await
}
async fn wait_for_family<T, F, Fut>(
    receipts: &[T],
    deadline: tokio::time::Instant,
    mut exact_completion: F,
) -> CompletionWaitOutcome
where
    T: Clone,
    F: FnMut(T) -> Fut,
    Fut: std::future::Future<Output = Result<bool, ()>>,
{
    if receipts.is_empty() {
        return CompletionWaitOutcome::Published;
    }
    let mut proven = vec![false; receipts.len()];
    loop {
        for (index, receipt) in receipts.iter().enumerate() {
            if proven[index] {
                continue;
            }
            match tokio::time::timeout_at(deadline, exact_completion(receipt.clone())).await {
                Ok(Ok(true)) => proven[index] = true,
                Ok(Ok(false)) => {}
                Ok(Err(())) => return CompletionWaitOutcome::Failed,
                Err(_) => return CompletionWaitOutcome::Delegated,
            }
        }
        if proven.iter().all(|is_proven| *is_proven) {
            return CompletionWaitOutcome::Published;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return CompletionWaitOutcome::Delegated;
        }
        tokio::time::sleep(OWNED_COMPLETION_POLL_INTERVAL.min(deadline - now)).await;
    }
}

/// Compatibility wrapper used by the focused delta-only unit tests below.
#[cfg(test)]
async fn wait_for_owned_completion_with<F, Fut>(
    requests: &[astral_db::DeltaEventAppendRequest],
    budget: Duration,
    exact_completion: F,
) -> CompletionWaitOutcome
where
    F: FnMut(astral_db::DeltaEventAppendRequest) -> Fut,
    Fut: std::future::Future<Output = Result<bool, ()>>,
{
    if requests.is_empty() || requests.len() > PROJECTION_COMPLETION_MAX_EVENTS {
        return CompletionWaitOutcome::Delegated;
    }
    let affected_cards = requests
        .iter()
        .filter_map(|request| request.card_id.map(|card_id| (request.tenant_id, card_id)))
        .collect::<HashSet<_>>()
        .len();
    if affected_cards > PROJECTION_COMPLETION_MAX_CARDS {
        return CompletionWaitOutcome::Delegated;
    }
    wait_for_family(
        requests,
        tokio::time::Instant::now() + budget,
        exact_completion,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_db::DeltaEventType;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    const TENANT: i64 = 7;
    const CARD_A: i64 = 101;

    fn completion_request(
        event_id: &str,
        target_version: i64,
    ) -> astral_db::DeltaEventAppendRequest {
        astral_db::DeltaEventAppendRequest {
            tenant_id: TENANT,
            card_id: Some(CARD_A),
            aggregate_type: "USER_CARD".to_owned(),
            aggregate_id: CARD_A,
            grant_id: astral_types::GrantId::random(),
            event_id: event_id.to_owned(),
            operation_id: "op-shared".to_owned(),
            event_type: DeltaEventType::Add,
            base_version: target_version - 1,
            target_version,
            source_generation: target_version as u64,
            revoke_fence: 0,
            invalidates_published_evidence: false,
            before_image_json: None,
            before_digest_hex: None,
            delta_json: "{}".to_owned(),
            semantic_hash_hex: "a".repeat(64),
            dependency_hash_hex: "b".repeat(64),
            compiler_version: astral_types::AUTHORIZATION_COMPILER_VERSION.to_owned(),
            next_attempt_at: None,
        }
    }

    fn same_operation_requests() -> Vec<astral_db::DeltaEventAppendRequest> {
        vec![
            completion_request("evt-a", 1),
            completion_request("evt-b", 2),
        ]
    }

    fn source_receipt(event_id: &str, aggregate_type: &str) -> SourceProjectionReceipt {
        SourceProjectionReceipt {
            event_id: event_id.to_owned(),
            aggregate_type: aggregate_type.to_owned(),
            aggregate_id: CARD_A,
            tenant_id: Some(TENANT),
            source_generation: 2,
            revoke_fence: 0,
        }
    }

    fn invalidation_receipt(event_id: &str, operation_id: &str) -> InvalidationReceipt {
        let envelope = astral_mq::envelope::MessageEnvelope::new(
            event_id,
            operation_id,
            astral_mq::invalidation::ELIGIBILITY_INVALIDATED,
            1,
            "city-a",
            serde_json::json!({"cardId": CARD_A}),
        )
        .expect("valid invalidation envelope");
        InvalidationReceipt {
            event_id: event_id.to_owned(),
            operation_id: operation_id.to_owned(),
            envelope,
        }
    }

    fn complete_receipt_batch() -> CommittedProjectionReceipts {
        CommittedProjectionReceipts {
            requests: same_operation_requests(),
            source_projection_receipts: vec![source_receipt(
                "source-card",
                astral_types::ProjectionAggregate::CARD,
            )],
            invalidation_receipts: vec![invalidation_receipt("invalidate-1", "op-shared")],
        }
    }

    #[tokio::test]
    async fn complete_multi_receipt_batch_proves_every_family() {
        let receipts = complete_receipt_batch();
        let probes = completion_probes(&receipts);
        let outcome = wait_for_completion_probes_with(&probes, Duration::from_secs(1), |_| {
            std::future::ready(Ok(true))
        })
        .await;
        assert_eq!(outcome, CompletionWaitOutcome::Published);
        assert_eq!(receipt_count(&receipts), 4);
    }

    #[tokio::test]
    async fn missing_invalidation_delegates_without_publishing() {
        let receipts = complete_receipt_batch();
        let probes = completion_probes(&receipts);
        let outcome =
            wait_for_completion_probes_with(&probes, Duration::from_millis(20), |probe| {
                std::future::ready(match probe {
                    CompletionProbe::Invalidation(_) => Ok(false),
                    _ => Ok(true),
                })
            })
            .await;
        assert_eq!(outcome, CompletionWaitOutcome::Delegated);
    }

    #[tokio::test]
    async fn mismatched_or_pending_invalidation_never_publishes() {
        let mut receipts = complete_receipt_batch();
        receipts.invalidation_receipts[0].event_id = "wrong-event".to_owned();
        assert!(invalidation_completion_identity(&receipts.invalidation_receipts[0]).is_none());

        let probes = completion_probes(&receipts);
        let mismatch =
            wait_for_completion_probes_with(&probes, Duration::from_millis(20), |probe| {
                std::future::ready(match probe {
                    CompletionProbe::Invalidation(receipt) => {
                        Ok(invalidation_completion_identity(&receipt).is_some())
                    }
                    _ => Ok(true),
                })
            })
            .await;
        assert_eq!(mismatch, CompletionWaitOutcome::Delegated);

        receipts.invalidation_receipts[0] = invalidation_receipt("invalidate-1", "op-shared");
        let probes = completion_probes(&receipts);
        let pending =
            wait_for_completion_probes_with(&probes, Duration::from_millis(20), |probe| {
                std::future::ready(match probe {
                    CompletionProbe::Invalidation(_) => Ok(false),
                    _ => Ok(true),
                })
            })
            .await;
        assert_eq!(pending, CompletionWaitOutcome::Delegated);
    }

    #[tokio::test]
    async fn empty_committed_receipts_are_not_completion() {
        let receipts = CommittedProjectionReceipts::default();
        let pool = sqlx::MySqlPool::connect_lazy("mysql://invalid").expect("lazy pool");
        assert!(!wait_for_committed_receipts(&pool, &receipts).await);
        assert_eq!(receipt_count(&receipts), 0);
    }

    #[tokio::test]
    async fn completion_requires_every_receipt_and_does_not_reread_proven_events() {
        let requests = same_operation_requests();
        assert_eq!(requests[0].operation_id, requests[1].operation_id);
        let reads = Arc::new(Mutex::new(HashMap::<String, usize>::new()));
        let outcome = wait_for_owned_completion_with(&requests, Duration::from_secs(1), {
            let reads = Arc::clone(&reads);
            move |request| {
                let reads = Arc::clone(&reads);
                async move {
                    let count = {
                        let mut reads = reads.lock().unwrap();
                        let count = reads.entry(request.event_id.clone()).or_default();
                        *count += 1;
                        *count
                    };
                    Ok(request.event_id == "evt-a" || count >= 2)
                }
            }
        })
        .await;

        assert_eq!(outcome, CompletionWaitOutcome::Published);
        let reads = reads.lock().unwrap();
        assert_eq!(reads.get("evt-a"), Some(&1));
        assert_eq!(reads.get("evt-b"), Some(&2));
    }

    #[tokio::test]
    async fn completion_delegates_when_one_receipt_never_publishes() {
        let requests = same_operation_requests();
        let reads = Arc::new(Mutex::new(HashMap::<String, usize>::new()));
        let outcome = wait_for_owned_completion_with(&requests, Duration::from_millis(80), {
            let reads = Arc::clone(&reads);
            move |request| {
                let reads = Arc::clone(&reads);
                async move {
                    let mut reads = reads.lock().unwrap();
                    *reads.entry(request.event_id.clone()).or_default() += 1;
                    Ok(request.event_id == "evt-a")
                }
            }
        })
        .await;

        assert_eq!(outcome, CompletionWaitOutcome::Delegated);
        let reads = reads.lock().unwrap();
        assert_eq!(reads.get("evt-a"), Some(&1));
        assert!(reads.get("evt-b").copied().unwrap_or_default() > 0);
    }

    #[tokio::test]
    async fn empty_and_oversized_batches_do_not_read_any_receipt() {
        let reads = Arc::new(AtomicUsize::new(0));
        assert_eq!(
            wait_for_owned_completion_with(&[], Duration::from_millis(20), {
                let reads = Arc::clone(&reads);
                move |_| {
                    reads.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Ok(true))
                }
            })
            .await,
            CompletionWaitOutcome::Delegated
        );
        let oversized = (0..=PROJECTION_COMPLETION_MAX_EVENTS)
            .map(|index| completion_request(&format!("evt-{index}"), index as i64 + 1))
            .collect::<Vec<_>>();
        assert_eq!(
            wait_for_owned_completion_with(&oversized, Duration::from_millis(20), {
                let reads = Arc::clone(&reads);
                move |_| {
                    reads.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Ok(true))
                }
            })
            .await,
            CompletionWaitOutcome::Delegated
        );
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn card_scope_budget_delegates_the_whole_batch_without_reading() {
        let requests = (0..=PROJECTION_COMPLETION_MAX_CARDS)
            .map(|index| {
                let mut request = completion_request(&format!("evt-{index}"), index as i64 + 1);
                request.card_id = Some(index as i64 + 1);
                request
            })
            .collect::<Vec<_>>();
        let reads = AtomicUsize::new(0);
        let outcome = wait_for_owned_completion_with(&requests, Duration::from_millis(20), |_| {
            reads.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(true))
        })
        .await;
        assert_eq!(outcome, CompletionWaitOutcome::Delegated);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn exact_completion_read_error_fails_closed() {
        let reads = AtomicUsize::new(0);
        let outcome = wait_for_owned_completion_with(
            &same_operation_requests()[..1],
            Duration::from_secs(1),
            |_| {
                reads.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Err(()))
            },
        )
        .await;
        assert_eq!(outcome, CompletionWaitOutcome::Failed);
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn slow_exact_read_times_out_as_delegated() {
        let reads = AtomicUsize::new(0);
        let outcome = wait_for_owned_completion_with(
            &same_operation_requests()[..1],
            Duration::from_millis(10),
            |_| {
                reads.fetch_add(1, Ordering::SeqCst);
                async {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    Ok(true)
                }
            },
        )
        .await;
        assert_eq!(outcome, CompletionWaitOutcome::Delegated);
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }
}
