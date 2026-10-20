use std::sync::Arc;

use astral_db::DeltaLeaseIdentity;

use super::{
    worker::{budget_exhausted_error, clamp_backoff, event_backoff_secs},
    AuthorizationProjectorRuntime, DispositionKind, OwnedTransitionProof, WorkerRunSummary,
    BACKOFF_CAP_SECS, MAX_EVENT_ATTEMPTS,
};
use crate::observability::{record_projector_event, ProjectorEventOutcome};

pub(super) async fn schedule_owned_retry(
    runtime: &Arc<dyn AuthorizationProjectorRuntime>,
    identity: &DeltaLeaseIdentity,
    minimum_backoff_secs: i64,
    reason: &str,
    count_failure: bool,
    kind_for_summary: DispositionKind,
    summary: &mut WorkerRunSummary,
) {
    let Some(failures) = runtime.event_execution_failures(identity) else {
        summary.events_publication_unknown += 1;
        tracing::warn!(event_id = %identity.event_id, "execution accounting unavailable; no mutation");
        return;
    };
    let next_failures = i64::from(failures) + i64::from(count_failure);
    let exhausted = next_failures >= MAX_EVENT_ATTEMPTS;
    let backoff = if exhausted {
        clamp_backoff(BACKOFF_CAP_SECS)
    } else {
        event_backoff_secs(next_failures.max(1)).max(clamp_backoff(minimum_backoff_secs))
    };
    let reason = if exhausted {
        budget_exhausted_error(reason, next_failures)
    } else {
        reason.to_owned()
    };
    let proof = runtime
        .owned_fail_transition(
            identity,
            backoff,
            &reason,
            count_failure && i64::from(failures) < MAX_EVENT_ATTEMPTS,
        )
        .await;
    match proof {
        OwnedTransitionProof::Applied => {
            if exhausted {
                summary.events_budget_exhausted += 1;
                crate::observability::record_projector_event(
                    crate::observability::ProjectorEventOutcome::BudgetExhausted,
                );
            }
            summary.record(kind_for_summary);
        }
        OwnedTransitionProof::LeaseLost => {
            summary.record(DispositionKind::LeaseLost);
        }
        OwnedTransitionProof::Unknown => {
            summary.events_publication_unknown += 1;
            record_projector_event(ProjectorEventOutcome::PublicationUnknown);
            tracing::warn!(
                event_id = %identity.event_id,
                "owned retry transition unknown; no success disposition recorded"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicU32, Ordering},
        Mutex,
    };

    use astral_db::{
        ClaimedDeltaEvent, DeltaEventClaim, DeltaEventClaimScope, DeltaLeaseToken,
        DeltaProjectorPublishCommand, DeltaProjectorPublishOutcome, ProjectionAggregateIdentity,
        RawLedgerRow,
    };
    use async_trait::async_trait;

    use super::super::{PublicationContext, RuntimeAccessError};
    use super::*;

    struct TransitionRuntime {
        proof: OwnedTransitionProof,
        failures: AtomicU32,
        transitions: Mutex<Vec<(i64, String, bool)>>,
    }

    #[async_trait]
    impl AuthorizationProjectorRuntime for TransitionRuntime {
        fn worker_owned_execution(&self) -> bool {
            true
        }

        fn event_execution_failures(&self, _identity: &DeltaLeaseIdentity) -> Option<u32> {
            Some(self.failures.load(Ordering::SeqCst))
        }

        async fn owned_fail_transition(
            &self,
            _identity: &DeltaLeaseIdentity,
            backoff_seconds: i64,
            message: &str,
            count_failure: bool,
        ) -> OwnedTransitionProof {
            self.transitions.lock().unwrap().push((
                backoff_seconds,
                message.to_owned(),
                count_failure,
            ));
            if self.proof == OwnedTransitionProof::Applied && count_failure {
                self.failures.fetch_add(1, Ordering::SeqCst);
            }
            self.proof
        }

        async fn claim_next_event(
            &self,
            _scope: &DeltaEventClaimScope,
            _lease_owner: &str,
            _lease_seconds: i64,
        ) -> Result<Option<DeltaEventClaim>, RuntimeAccessError> {
            unreachable!()
        }

        async fn read_claimed_event(
            &self,
            _identity: &DeltaLeaseIdentity,
        ) -> Result<ClaimedDeltaEvent, RuntimeAccessError> {
            unreachable!()
        }

        async fn observe_publication_context(
            &self,
            _identity: &ProjectionAggregateIdentity,
        ) -> Result<Option<PublicationContext>, RuntimeAccessError> {
            unreachable!()
        }

        async fn load_scope_ledger(
            &self,
            _tenant_id: i64,
            _aggregate_type: &str,
            _aggregate_id: i64,
            _card_id: Option<i64>,
        ) -> Result<Vec<RawLedgerRow>, RuntimeAccessError> {
            unreachable!()
        }

        async fn execute_projection_publish(
            &self,
            _command: &DeltaProjectorPublishCommand,
        ) -> Result<DeltaProjectorPublishOutcome, RuntimeAccessError> {
            unreachable!()
        }

        async fn fail_event(&self, _identity: &DeltaLeaseIdentity, _backoff: i64, _message: &str) {
            panic!("owned scheduling must not use the void transition port")
        }

        async fn release_event(&self, _identity: &DeltaLeaseIdentity) {
            panic!("owned scheduling must not use the void release port")
        }

        async fn mark_event_quarantined(
            &self,
            _identity: &DeltaLeaseIdentity,
            _reason_code: &str,
            _reason_detail: &str,
        ) -> Result<(), RuntimeAccessError> {
            unreachable!()
        }
    }

    fn lease_identity() -> DeltaLeaseIdentity {
        DeltaLeaseIdentity {
            delta_event_id: 1,
            event_id: "owned-transition-budget".to_owned(),
            lease_owner: "owned-transition-test".to_owned(),
            lease_token: DeltaLeaseToken::new_run_scoped(),
        }
    }

    #[tokio::test]
    async fn final_failure_is_charged_only_with_applied_transition_proof() {
        for proof in [
            OwnedTransitionProof::Applied,
            OwnedTransitionProof::Unknown,
            OwnedTransitionProof::LeaseLost,
        ] {
            let initial_failures = u32::try_from(MAX_EVENT_ATTEMPTS - 1).unwrap();
            let fake = Arc::new(TransitionRuntime {
                proof,
                failures: AtomicU32::new(initial_failures),
                transitions: Mutex::new(Vec::new()),
            });
            let runtime: Arc<dyn AuthorizationProjectorRuntime> = fake.clone();
            let mut summary = WorkerRunSummary::default();
            schedule_owned_retry(
                &runtime,
                &lease_identity(),
                0,
                "proven publication failure",
                true,
                DispositionKind::ReleasedRetry,
                &mut summary,
            )
            .await;
            let transitions = fake.transitions.lock().unwrap();
            assert_eq!(transitions.len(), 1);
            assert_eq!(transitions[0].0, clamp_backoff(BACKOFF_CAP_SECS));
            assert!(transitions[0]
                .1
                .contains("code=auth_projector.attempt_budget_exhausted"));
            assert!(
                transitions[0].2,
                "the failure that reaches the cap must be charged"
            );
            let applied = u64::from(proof == OwnedTransitionProof::Applied);
            assert_eq!(summary.events_budget_exhausted, applied);
            assert_eq!(summary.events_released_retry, applied);
            assert_eq!(
                summary.events_publication_unknown,
                u64::from(proof == OwnedTransitionProof::Unknown)
            );
            assert_eq!(
                summary.events_lease_lost,
                u64::from(proof == OwnedTransitionProof::LeaseLost)
            );
            assert_eq!(
                fake.failures.load(Ordering::SeqCst),
                initial_failures + applied as u32
            );
        }
    }

    #[tokio::test]
    async fn exhausted_budget_and_dependency_wait_do_not_charge_another_failure() {
        for (failures, count_failure, expected_exhaustion) in [
            (u32::try_from(MAX_EVENT_ATTEMPTS).unwrap(), true, 1),
            (u32::try_from(MAX_EVENT_ATTEMPTS - 1).unwrap(), false, 0),
        ] {
            let fake = Arc::new(TransitionRuntime {
                proof: OwnedTransitionProof::Applied,
                failures: AtomicU32::new(failures),
                transitions: Mutex::new(Vec::new()),
            });
            let runtime: Arc<dyn AuthorizationProjectorRuntime> = fake.clone();
            let mut summary = WorkerRunSummary::default();
            schedule_owned_retry(
                &runtime,
                &lease_identity(),
                0,
                "dependency waiting",
                count_failure,
                DispositionKind::Blocked,
                &mut summary,
            )
            .await;
            let transitions = fake.transitions.lock().unwrap();
            assert_eq!(transitions.len(), 1);
            assert!(!transitions[0].2);
            assert_eq!(fake.failures.load(Ordering::SeqCst), failures);
            assert_eq!(summary.events_budget_exhausted, expected_exhaustion);
            assert_eq!(summary.events_blocked, 1);
            assert_eq!(summary.events_released_retry, 0);
            assert_eq!(summary.events_publication_unknown, 0);
        }
    }
}
