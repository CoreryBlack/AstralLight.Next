//! Source-bound authority-to-MySQL bridge for certified-memory family completion.
//!
//! No source-owned durable family completeness contract is currently available
//! at this boundary. Both new issuance and historical receipt adoption remain
//! pending until such evidence can be independently verified.

use astral_authority::client::{AuthorityClient, VerifiedFamilyReceipt};
use astral_authority::AuthorityClientError;
use astral_types::authority_protocol::AuthorityFamilyCompletionCandidate;
use astral_types::AuthorityMutationKind;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sqlx::MySqlPool;
use thiserror::Error;

use crate::authority_source_outcome::AuthoritySourceOutcomeRow;
use crate::certified_memory_completion_writer::{
    CertifiedMemoryCompletionWriteError, VerifiedCertifiedMemoryCompletionWriteRequest,
};
use crate::certified_memory_family_owner::decode_certified_memory_payload;
use crate::certified_memory_materializer::CertifiedMemoryMaterializerError;

const MAX_CANONICAL_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
const PREFLIGHT_RECEIPT_ID: &str = "certified-memory-family-reconciler-preflight";

/// Error boundary for the authority-to-certified-memory completion bridge.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CertifiedMemoryFamilyReconcilerError {
    #[error("certified-memory family completion is pending: {code}: {detail}")]
    Pending { code: String, detail: String },
    #[error("certified-memory family completion is unknown: {code}: {detail}")]
    Unknown { code: String, detail: String },
    #[error("certified-memory family completion conflicts with its contract: {0}")]
    Conflict(String),
    #[error("certified-memory family completion database failure: {0}")]
    Database(String),
}

/// Reconcile one terminal family candidate and return a proof-only write request.
///
/// All source-outcome reads and authority calls happen before the caller opens a
/// MySQL transaction. A reconciliation miss permits exactly one completion call;
/// an authority UNKNOWN is terminal for this invocation.
pub async fn reconcile_verified_certified_memory_family(
    pool: &MySqlPool,
    client: &AuthorityClient,
    database_id: impl Into<String>,
    candidate: AuthorityFamilyCompletionCandidate,
    canonical_payload: impl Into<String>,
) -> Result<VerifiedCertifiedMemoryCompletionWriteRequest, CertifiedMemoryFamilyReconcilerError> {
    let database_id = database_id.into();
    require_source_owned_completeness(&candidate)?;
    let canonical_payload = validate_candidate_and_payload(&candidate, &canonical_payload.into())?;
    verify_committed_source_identity(pool, client.service_id(), &database_id, &candidate).await?;

    let pool_for_recheck = pool;
    let service_id_for_recheck = client.service_id().to_owned();
    let database_id_for_recheck = database_id.clone();
    let candidate_for_recheck = candidate.clone();
    let receipt = reconcile_or_complete_guarded(
        client,
        database_id.clone(),
        candidate.clone(),
        canonical_payload.clone(),
        || async move {
            verify_committed_source_identity(
                pool_for_recheck,
                &service_id_for_recheck,
                &database_id_for_recheck,
                &candidate_for_recheck,
            )
            .await
        },
    )
    .await?;

    validate_verified_receipt(client, &database_id, &candidate, &receipt)?;
    VerifiedCertifiedMemoryCompletionWriteRequest::new(client, receipt, canonical_payload)
        .map_err(map_write_error)
}

fn require_source_owned_completeness(
    candidate: &AuthorityFamilyCompletionCandidate,
) -> Result<(), CertifiedMemoryFamilyReconcilerError> {
    // A source outcome binds the mutation, not a complete family selector,
    // its exact result, or an empty-set proof. No durable capture contract for
    // any of these six families is currently available to verify here.
    Err(CertifiedMemoryFamilyReconcilerError::Pending {
        code: "certified_memory.source_family_completeness_unverified".into(),
        detail: format!(
            "source-owned durable completeness evidence is unavailable for {:?}",
            candidate.family
        ),
    })
}

async fn verify_committed_source_identity(
    pool: &MySqlPool,
    service_id: &str,
    database_id: &str,
    candidate: &AuthorityFamilyCompletionCandidate,
) -> Result<(), CertifiedMemoryFamilyReconcilerError> {
    let row: Option<AuthoritySourceOutcomeRow> = sqlx::query_as(
        "SELECT reservation_id, operation_id, event_id, admission_proof_id, \
                request_binding_digest, mutation_kind, service_id, database_id, \
                source_commit_digest, before_image_digest, after_image_digest, source_receipts, \
                staged_evidence, status, attempts, generation, outcome_digest, committed_at \
         FROM authority_source_outcome WHERE reservation_id = ?",
    )
    .bind(&candidate.reservation_id)
    .fetch_optional(pool)
    .await
    .map_err(|error| CertifiedMemoryFamilyReconcilerError::Unknown {
        code: "certified_memory.source_outcome_read_unknown".into(),
        detail: error.to_string(),
    })?;
    let row = row.ok_or_else(|| CertifiedMemoryFamilyReconcilerError::Pending {
        code: "certified_memory.source_outcome_missing".into(),
        detail: "committed source outcome is not available".into(),
    })?;
    validate_source_identity(&row, service_id, database_id, candidate)
}

fn validate_source_identity(
    row: &AuthoritySourceOutcomeRow,
    service_id: &str,
    database_id: &str,
    candidate: &AuthorityFamilyCompletionCandidate,
) -> Result<(), CertifiedMemoryFamilyReconcilerError> {
    let record = row
        .to_verified_publication_record("COMMITTED")
        .map_err(|_| CertifiedMemoryFamilyReconcilerError::Unknown {
            code: "certified_memory.source_outcome_unverified".into(),
            detail: "source outcome is not an exact verified COMMITTED record".into(),
        })?;
    if record.mutation_kind != AuthorityMutationKind::AuthorizationSource
        || record.service_id != service_id
        || record.database_id != database_id
        || record.reservation_id != candidate.reservation_id
        || record.operation_id != candidate.operation_id
        || record.event_id != candidate.event_id
        || record.source_commit_digest != candidate.source_commit_digest
        || hex::encode(&row.outcome_digest) != candidate.source_outcome_digest
    {
        return Err(CertifiedMemoryFamilyReconcilerError::Conflict(
            "committed source outcome does not bind the requested identity".into(),
        ));
    }
    Ok(())
}

/// Narrow authority seam used by the state-machine tests. Production delegates
/// directly to the concrete `AuthorityClient` methods.
#[async_trait]
trait FamilyCompletionGateway {
    type Receipt;

    async fn reconcile_family_verified(
        &self,
        database_id: String,
        candidate: AuthorityFamilyCompletionCandidate,
    ) -> Result<Option<Self::Receipt>, AuthorityClientError>;

    async fn complete_family_verified(
        &self,
        database_id: String,
        candidate: AuthorityFamilyCompletionCandidate,
    ) -> Result<Self::Receipt, AuthorityClientError>;
}

#[async_trait]
impl FamilyCompletionGateway for AuthorityClient {
    type Receipt = VerifiedFamilyReceipt;

    async fn reconcile_family_verified(
        &self,
        database_id: String,
        candidate: AuthorityFamilyCompletionCandidate,
    ) -> Result<Option<Self::Receipt>, AuthorityClientError> {
        AuthorityClient::reconcile_family_verified(self, database_id, candidate).await
    }

    async fn complete_family_verified(
        &self,
        database_id: String,
        candidate: AuthorityFamilyCompletionCandidate,
    ) -> Result<Self::Receipt, AuthorityClientError> {
        AuthorityClient::complete_family_verified(self, database_id, candidate).await
    }
}

async fn reconcile_or_complete_guarded<G, F, Fut>(
    gateway: &G,
    database_id: String,
    candidate: AuthorityFamilyCompletionCandidate,
    canonical_payload: String,
    source_recheck: F,
) -> Result<G::Receipt, CertifiedMemoryFamilyReconcilerError>
where
    G: FamilyCompletionGateway,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), CertifiedMemoryFamilyReconcilerError>>,
{
    require_source_owned_completeness(&candidate)?;
    reconcile_or_complete_verified_with_source_recheck(
        gateway,
        database_id,
        candidate,
        canonical_payload,
        source_recheck,
    )
    .await
}

async fn reconcile_or_complete_verified_with_source_recheck<G, F, Fut>(
    gateway: &G,
    database_id: String,
    candidate: AuthorityFamilyCompletionCandidate,
    canonical_payload: String,
    source_recheck: F,
) -> Result<G::Receipt, CertifiedMemoryFamilyReconcilerError>
where
    G: FamilyCompletionGateway,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), CertifiedMemoryFamilyReconcilerError>>,
{
    let _ = validate_candidate_and_payload(&candidate, &canonical_payload)?;

    // Reconciliation is always first. There is no retry loop: only an explicit
    // absence of a receipt permits one durable source recheck and one completion
    // call. An authority UNKNOWN never falls through to completion.
    match gateway
        .reconcile_family_verified(database_id.clone(), candidate.clone())
        .await
    {
        Ok(Some(receipt)) => Ok(receipt),
        Ok(None) => {
            source_recheck().await?;
            gateway
                .complete_family_verified(database_id, candidate)
                .await
                .map_err(map_authority_error)
        }
        Err(error) => Err(map_authority_error(error)),
    }
}

fn validate_candidate_and_payload(
    candidate: &AuthorityFamilyCompletionCandidate,
    payload: &str,
) -> Result<String, CertifiedMemoryFamilyReconcilerError> {
    candidate
        .validate()
        .map_err(|error| CertifiedMemoryFamilyReconcilerError::Conflict(error.to_string()))?;

    if payload.len() > MAX_CANONICAL_PAYLOAD_BYTES {
        return Err(CertifiedMemoryFamilyReconcilerError::Conflict(
            "completion payload exceeds bounded size".into(),
        ));
    }
    let parsed: serde_json::Value = serde_json::from_str(payload).map_err(|error| {
        CertifiedMemoryFamilyReconcilerError::Conflict(format!(
            "completion payload is not valid JSON: {error}"
        ))
    })?;
    if !parsed.is_array() {
        return Err(CertifiedMemoryFamilyReconcilerError::Conflict(
            "completion payload must be a family inventory array".into(),
        ));
    }
    let canonical = serde_json::to_string(&parsed).map_err(|error| {
        CertifiedMemoryFamilyReconcilerError::Conflict(format!(
            "completion payload cannot be canonicalized: {error}"
        ))
    })?;
    if canonical != payload {
        return Err(CertifiedMemoryFamilyReconcilerError::Conflict(
            "completion payload is not canonical JSON".into(),
        ));
    }

    let expected_digest = candidate
        .complete_content_digest
        .as_deref()
        .ok_or_else(|| {
            CertifiedMemoryFamilyReconcilerError::Conflict(
                "terminal family completion requires complete_content_digest".into(),
            )
        })?;
    if hex::encode(Sha256::digest(canonical.as_bytes())) != expected_digest {
        return Err(CertifiedMemoryFamilyReconcilerError::Conflict(
            "completion payload digest does not match candidate".into(),
        ));
    }

    // Validate the family-specific inventory before any authority call. The
    // placeholder receipt id is local-only and is never sent or persisted.
    let completion = candidate
        .clone()
        .into_receipted_completion(PREFLIGHT_RECEIPT_ID.to_owned())
        .map_err(|error| CertifiedMemoryFamilyReconcilerError::Conflict(error.to_string()))?;
    let decoded = decode_certified_memory_payload(candidate.family, &canonical)
        .map_err(map_materializer_error)?;
    decoded
        .validate_inventory(&completion)
        .map_err(map_materializer_error)?;

    Ok(canonical)
}

fn validate_verified_receipt(
    client: &AuthorityClient,
    database_id: &str,
    candidate: &AuthorityFamilyCompletionCandidate,
    receipt: &VerifiedFamilyReceipt,
) -> Result<(), CertifiedMemoryFamilyReconcilerError> {
    validate_client_provenance(receipt.verified_by(client))?;
    if receipt.database_id() != database_id {
        return Err(CertifiedMemoryFamilyReconcilerError::Conflict(
            "verified receipt database_id differs from the requested database_id".into(),
        ));
    }
    if receipt.candidate() != candidate {
        return Err(CertifiedMemoryFamilyReconcilerError::Conflict(
            "authority receipt candidate differs from the requested candidate".into(),
        ));
    }
    Ok(())
}

fn validate_client_provenance(matches: bool) -> Result<(), CertifiedMemoryFamilyReconcilerError> {
    if matches {
        Ok(())
    } else {
        Err(CertifiedMemoryFamilyReconcilerError::Unknown {
            code: "certified_memory.authority_client_provenance_mismatch".into(),
            detail: "verified receipt was produced by another AuthorityClient".into(),
        })
    }
}

fn map_authority_error(error: AuthorityClientError) -> CertifiedMemoryFamilyReconcilerError {
    match error {
        AuthorityClientError::Rejected { code, message } => match code.as_str() {
            "ReadsBlocked" | "LeaseExpired" | "NotLeader" | "QuorumUnavailable" | "NotFound" => {
                CertifiedMemoryFamilyReconcilerError::Pending {
                    code: format!("authority.{code}"),
                    detail: message,
                }
            }
            "UnknownOutcome" => CertifiedMemoryFamilyReconcilerError::Unknown {
                code: "authority.unknown_outcome".into(),
                detail: message,
            },
            _ => CertifiedMemoryFamilyReconcilerError::Conflict(format!(
                "authority rejected family completion: {code}: {message}"
            )),
        },
        AuthorityClientError::UnknownOutcome { operation_hint } => {
            CertifiedMemoryFamilyReconcilerError::Unknown {
                code: "authority.unknown_outcome".into(),
                detail: operation_hint,
            }
        }
        AuthorityClientError::Transport(message) => CertifiedMemoryFamilyReconcilerError::Unknown {
            code: "authority.transport_unknown".into(),
            detail: message,
        },
        AuthorityClientError::Attestation(message) => {
            CertifiedMemoryFamilyReconcilerError::Unknown {
                code: "authority.attestation_unknown".into(),
                detail: message,
            }
        }
        AuthorityClientError::Protocol(message) => CertifiedMemoryFamilyReconcilerError::Unknown {
            code: "authority.protocol_unknown".into(),
            detail: message,
        },
        AuthorityClientError::ProtocolError(error) => {
            CertifiedMemoryFamilyReconcilerError::Unknown {
                code: "authority.protocol_unknown".into(),
                detail: error.to_string(),
            }
        }
        AuthorityClientError::InsecureEndpoint => CertifiedMemoryFamilyReconcilerError::Conflict(
            "authority client endpoint is not HTTPS".into(),
        ),
    }
}

fn map_materializer_error(
    error: CertifiedMemoryMaterializerError,
) -> CertifiedMemoryFamilyReconcilerError {
    match error {
        CertifiedMemoryMaterializerError::Pending { code, .. } => {
            CertifiedMemoryFamilyReconcilerError::Pending {
                code: code.into(),
                detail: "certified-memory payload owner is not ready".into(),
            }
        }
        CertifiedMemoryMaterializerError::Unknown { code, .. }
        | CertifiedMemoryMaterializerError::Quarantined { code, .. } => {
            CertifiedMemoryFamilyReconcilerError::Unknown {
                code: code.into(),
                detail: "certified-memory payload owner could not prove its inventory".into(),
            }
        }
        other => CertifiedMemoryFamilyReconcilerError::Conflict(other.to_string()),
    }
}

fn map_write_error(
    error: CertifiedMemoryCompletionWriteError,
) -> CertifiedMemoryFamilyReconcilerError {
    match error {
        CertifiedMemoryCompletionWriteError::Invalid(message)
        | CertifiedMemoryCompletionWriteError::Conflict(message) => {
            CertifiedMemoryFamilyReconcilerError::Conflict(message)
        }
        CertifiedMemoryCompletionWriteError::Unknown { code }
            if code.starts_with("certified_memory.completion_ledger_") =>
        {
            CertifiedMemoryFamilyReconcilerError::Database(code.into())
        }
        CertifiedMemoryCompletionWriteError::Unknown { code } => {
            CertifiedMemoryFamilyReconcilerError::Unknown {
                code: code.into(),
                detail: "certified-memory durable evidence is not proven".into(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use super::*;
    use astral_types::authority_protocol::{
        AuthorityCertifiedMemoryFamily, AuthorityFamilyCompletionState,
        AuthorityFamilyDependencyFrontier, AuthorityFamilyScope,
    };

    struct ScriptedGateway {
        reconcile_calls: AtomicUsize,
        complete_calls: AtomicUsize,
        reconcile_result: Mutex<Option<Result<Option<String>, AuthorityClientError>>>,
        complete_result: Mutex<Option<Result<String, AuthorityClientError>>>,
    }

    impl ScriptedGateway {
        fn new(
            reconcile_result: Result<Option<String>, AuthorityClientError>,
            complete_result: Result<String, AuthorityClientError>,
        ) -> Self {
            Self {
                reconcile_calls: AtomicUsize::new(0),
                complete_calls: AtomicUsize::new(0),
                reconcile_result: Mutex::new(Some(reconcile_result)),
                complete_result: Mutex::new(Some(complete_result)),
            }
        }
    }

    #[async_trait]
    impl FamilyCompletionGateway for ScriptedGateway {
        type Receipt = String;

        async fn reconcile_family_verified(
            &self,
            _database_id: String,
            _candidate: AuthorityFamilyCompletionCandidate,
        ) -> Result<Option<Self::Receipt>, AuthorityClientError> {
            self.reconcile_calls.fetch_add(1, Ordering::SeqCst);
            self.reconcile_result
                .lock()
                .expect("reconcile result lock")
                .take()
                .expect("one reconcile call")
        }

        async fn complete_family_verified(
            &self,
            _database_id: String,
            _candidate: AuthorityFamilyCompletionCandidate,
        ) -> Result<Self::Receipt, AuthorityClientError> {
            self.complete_calls.fetch_add(1, Ordering::SeqCst);
            self.complete_result
                .lock()
                .expect("complete result lock")
                .take()
                .expect("one complete call")
        }
    }

    fn candidate(payload: &str) -> AuthorityFamilyCompletionCandidate {
        AuthorityFamilyCompletionCandidate {
            family: AuthorityCertifiedMemoryFamily::CardContext,
            state: AuthorityFamilyCompletionState::CompleteEmpty,
            scope: AuthorityFamilyScope {
                tenant_id: Some(7),
                scope: "tenant:7".into(),
            },
            reservation_id: "reservation".into(),
            operation_id: "operation".into(),
            event_id: "event".into(),
            message_id: None,
            source_commit_digest: "11".repeat(32),
            source_outcome_digest: "22".repeat(32),
            before_content_digest: None,
            after_content_digest: None,
            complete_content_digest: Some(hex::encode(Sha256::digest(payload.as_bytes()))),
            audit_correlation_id: "audit".into(),
            inventory: Vec::new(),
            scope_generation: 3,
            revoke_watermark: 1,
            dependency_frontier: AuthorityFamilyDependencyFrontier {
                authority_term: 1,
                global_fence_sequence: 2,
                dependency_generation: 3,
            },
        }
    }

    #[tokio::test]
    async fn reconcile_hit_does_not_post_completion() {
        let gateway = ScriptedGateway::new(Ok(Some("receipt".into())), Ok("unused".into()));
        let result = reconcile_or_complete_verified_with_source_recheck(
            &gateway,
            "database-1".into(),
            candidate("[]"),
            "[]".into(),
            || async { Ok(()) },
        )
        .await
        .expect("reconciliation hit");

        assert_eq!(result, "receipt");
        assert_eq!(gateway.reconcile_calls.load(Ordering::SeqCst), 1);
        assert_eq!(gateway.complete_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn reconcile_miss_then_completes_once() {
        let gateway = ScriptedGateway::new(Ok(None), Ok("receipt".into()));
        let result = reconcile_or_complete_verified_with_source_recheck(
            &gateway,
            "database-1".into(),
            candidate("[]"),
            "[]".into(),
            || async { Ok(()) },
        )
        .await
        .expect("one completion after a miss");

        assert_eq!(result, "receipt");
        assert_eq!(gateway.reconcile_calls.load(Ordering::SeqCst), 1);
        assert_eq!(gateway.complete_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn source_mismatch_after_reconcile_miss_blocks_completion() {
        let gateway = ScriptedGateway::new(Ok(None), Ok("must-not-be-used".into()));
        let result = reconcile_or_complete_verified_with_source_recheck(
            &gateway,
            "database-1".into(),
            candidate("[]"),
            "[]".into(),
            || async {
                Err(CertifiedMemoryFamilyReconcilerError::Conflict(
                    "source outcome mismatch".into(),
                ))
            },
        )
        .await;

        assert!(matches!(
            result,
            Err(CertifiedMemoryFamilyReconcilerError::Conflict(message))
                if message == "source outcome mismatch"
        ));
        assert_eq!(gateway.reconcile_calls.load(Ordering::SeqCst), 1);
        assert_eq!(gateway.complete_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn authority_unknown_is_not_retried() {
        let gateway = ScriptedGateway::new(
            Ok(None),
            Err(AuthorityClientError::UnknownOutcome {
                operation_hint: "family-completion".into(),
            }),
        );
        let result = reconcile_or_complete_verified_with_source_recheck(
            &gateway,
            "database-1".into(),
            candidate("[]"),
            "[]".into(),
            || async { Ok(()) },
        )
        .await;

        assert!(matches!(
            result,
            Err(CertifiedMemoryFamilyReconcilerError::Unknown { ref code, .. })
                if code == "authority.unknown_outcome"
        ));
        assert_eq!(gateway.reconcile_calls.load(Ordering::SeqCst), 1);
        assert_eq!(gateway.complete_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn reconcile_unknown_does_not_fall_through_to_completion() {
        let gateway = ScriptedGateway::new(
            Err(AuthorityClientError::UnknownOutcome {
                operation_hint: "reconcile".into(),
            }),
            Ok("must-not-be-used".into()),
        );
        let result = reconcile_or_complete_verified_with_source_recheck(
            &gateway,
            "database-1".into(),
            candidate("[]"),
            "[]".into(),
            || async { Ok(()) },
        )
        .await;

        assert!(matches!(
            result,
            Err(CertifiedMemoryFamilyReconcilerError::Unknown { ref code, .. })
                if code == "authority.unknown_outcome"
        ));
        assert_eq!(gateway.reconcile_calls.load(Ordering::SeqCst), 1);
        assert_eq!(gateway.complete_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn invalid_candidate_fails_closed_before_authority_calls() {
        let gateway = ScriptedGateway::new(Ok(Some("unused".into())), Ok("unused".into()));
        let invalid = AuthorityFamilyCompletionCandidate {
            state: AuthorityFamilyCompletionState::Pending,
            ..candidate("[]")
        };
        let result = reconcile_or_complete_verified_with_source_recheck(
            &gateway,
            "database-1".into(),
            invalid,
            "[]".into(),
            || async { Ok(()) },
        )
        .await;

        assert!(matches!(
            result,
            Err(CertifiedMemoryFamilyReconcilerError::Conflict(_))
        ));
        assert_eq!(gateway.reconcile_calls.load(Ordering::SeqCst), 0);
        assert_eq!(gateway.complete_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn missing_completeness_blocks_even_historical_receipts_before_io() {
        for family in AuthorityCertifiedMemoryFamily::required() {
            for state in [
                AuthorityFamilyCompletionState::Complete,
                AuthorityFamilyCompletionState::CompleteEmpty,
            ] {
                let gateway = ScriptedGateway::new(Ok(Some("historical".into())), Ok("new".into()));
                let mut claim = candidate("[]");
                claim.family = family;
                claim.state = state;
                let result = reconcile_or_complete_guarded(
                    &gateway,
                    "database-1".into(),
                    claim,
                    "[]".into(),
                    || async { panic!("source read must not start") },
                )
                .await;
                assert!(matches!(result,
                    Err(CertifiedMemoryFamilyReconcilerError::Pending { ref code, .. })
                        if code == "certified_memory.source_family_completeness_unverified"));
                assert_eq!(gateway.reconcile_calls.load(Ordering::SeqCst), 0);
                assert_eq!(gateway.complete_calls.load(Ordering::SeqCst), 0);
            }
        }
    }

    #[test]
    fn caller_terminal_claims_never_establish_source_completeness() {
        for family in AuthorityCertifiedMemoryFamily::required() {
            for state in [
                AuthorityFamilyCompletionState::Complete,
                AuthorityFamilyCompletionState::CompleteEmpty,
            ] {
                let mut claim = candidate("[]");
                claim.family = family;
                claim.state = state;
                assert!(matches!(
                    require_source_owned_completeness(&claim),
                    Err(CertifiedMemoryFamilyReconcilerError::Pending { ref code, .. })
                        if code == "certified_memory.source_family_completeness_unverified"
                ));
            }
        }
    }

    #[test]
    fn client_provenance_fails_closed() {
        let result = validate_client_provenance(false);
        assert!(matches!(
            result,
            Err(CertifiedMemoryFamilyReconcilerError::Unknown { ref code, .. })
                if code == "certified_memory.authority_client_provenance_mismatch"
        ));
    }
}
