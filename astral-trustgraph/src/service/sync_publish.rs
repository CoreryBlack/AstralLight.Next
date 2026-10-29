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
use crate::repository::authorization_source_transaction::CommittedProjectionReceipts;

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

/// Wait, within a fixed budget, for full durable completion proofs for every
/// commit-proven receipt. Timeout and oversized batches are delegated intact to
/// the worker. This function is deliberately observation-only.
pub(crate) async fn after_commit_wait_for_projection(
    pool: &MySqlPool,
    receipts: &CommittedProjectionReceipts,
) {
    let started = Instant::now();
    let count = receipts.requests.len();
    if count == 0 {
        record_sync_publish(SyncPublishMetricOutcome::SkippedEmpty, started.elapsed());
        return;
    }

    let outcome =
        wait_for_owned_completion(pool, &receipts.requests, PROJECTION_COMPLETION_WAIT_BUDGET)
            .await;
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
            "worker-owned projection completion proven for the entire source receipt batch"
        ),
        CompletionWaitOutcome::Delegated => tracing::debug!(
            receipts = count,
            "worker-owned projection completion remains delegated to the durable worker"
        ),
        CompletionWaitOutcome::Failed => tracing::warn!(
            receipts = count,
            "worker-owned completion proof read failed; durable worker retains ownership"
        ),
    }
}

/// Bounded read-only waiter. `Some` is accepted only from astral-db's exact
/// request-bound historical completion proof; no bus admission or ACK is proof.
async fn wait_for_owned_completion(
    pool: &MySqlPool,
    requests: &[astral_db::DeltaEventAppendRequest],
    budget: Duration,
) -> CompletionWaitOutcome {
    wait_for_owned_completion_with(requests, budget, |request| async move {
        match astral_db::load_owned_delta_completion(pool, &request).await {
            Ok(proof) => Ok(proof.is_some()),
            Err(error) => {
                tracing::warn!(event_id = %request.event_id, error = %error,
                    "exact projection completion proof unavailable; worker ownership unchanged");
                Err(())
            }
        }
    })
    .await
}

async fn wait_for_owned_completion_with<F, Fut>(
    requests: &[astral_db::DeltaEventAppendRequest],
    budget: Duration,
    mut exact_completion: F,
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

    let deadline = tokio::time::Instant::now() + budget;
    let mut proven = vec![false; requests.len()];
    loop {
        for (index, request) in requests.iter().enumerate() {
            if proven[index] {
                continue;
            }
            match tokio::time::timeout_at(deadline, exact_completion(request.clone())).await {
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
