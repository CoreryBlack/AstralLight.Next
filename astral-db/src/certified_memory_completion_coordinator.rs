//! Post-commit CertifiedMemory family completion coordinator.
//!
//! This coordinator is the durable handoff between a source owner that already
//! has a complete, source-bound family candidate and the certified-memory
//! ledger. Candidate capture remains owned by each family source owner; this
//! module never queries source tables, invents an empty family, or treats a
//! projection ACK as completion.
//!
//! The authority reconciliation call always happens before a MySQL transaction.
//! Only an opaque, client-proven authority receipt crosses into the short
//! transaction, where the proof-only writer rechecks source outcome and audit
//! correlation before inserting the idempotent `PROVEN` row. An authority or
//! commit UNKNOWN result is returned as UNKNOWN and is never retried here.

use std::collections::BTreeSet;

use astral_authority::client::AuthorityClient;
use astral_types::authority_protocol::{
    AuthorityCertifiedMemoryFamily, AuthorityFamilyCompletionCandidate,
};
use sqlx::MySqlPool;
use thiserror::Error;

use crate::certified_memory_completion_writer::{
    CertifiedMemoryCompletionWriteError, CertifiedMemoryCompletionWriteResult,
};
use crate::certified_memory_family_reconciler::{
    reconcile_verified_certified_memory_family, CertifiedMemoryFamilyReconcilerError,
};

/// One post-commit completion coordinator bound to the same authority client
/// and database identity as the CertifiedMemory composition root.
#[derive(Clone)]
pub struct CertifiedMemoryCompletionCoordinator {
    pool: MySqlPool,
    client: AuthorityClient,
    database_id: String,
}

impl std::fmt::Debug for CertifiedMemoryCompletionCoordinator {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CertifiedMemoryCompletionCoordinator")
            .field("pool", &"<mysql-pool>")
            .field("service_id", &self.client.service_id())
            .field("database_id", &self.database_id)
            .finish()
    }
}

impl CertifiedMemoryCompletionCoordinator {
    /// Bind a coordinator to a verified authority client and a registered
    /// database identity. Empty identities are rejected before any I/O.
    pub fn new(
        pool: MySqlPool,
        client: AuthorityClient,
        database_id: impl Into<String>,
    ) -> Result<Self, CertifiedMemoryCompletionCoordinatorError> {
        let database_id = database_id.into();
        if database_id.trim().is_empty()
            || database_id.len() > 128
            || database_id != database_id.trim()
            || database_id
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(CertifiedMemoryCompletionCoordinatorError::Invalid(
                "database_id is not canonical bounded text".into(),
            ));
        }
        Ok(Self {
            pool,
            client,
            database_id,
        })
    }

    pub fn database_id(&self) -> &str {
        &self.database_id
    }

    /// Promote an explicitly complete source-owner draft, reconcile it against
    /// the authority, and persist the verified receipt after the authority call.
    /// No source query or completion state is inferred here.
    pub async fn reconcile_and_record_source_owner_draft(
        &self,
        draft: astral_types::authority_protocol::AuthorityFamilyCompletion,
        payload: impl Into<String>,
        complete_empty: bool,
    ) -> Result<CertifiedMemoryCompletionWriteResult, CertifiedMemoryCompletionCoordinatorError>
    {
        let (candidate, canonical_payload) =
            crate::certified_memory_source_owner_producer::finalize_source_owner_draft(
                draft,
                payload,
                complete_empty,
            )
            .map_err(|error| {
                CertifiedMemoryCompletionCoordinatorError::Invalid(error.to_string())
            })?;
        self.reconcile_and_record(candidate, canonical_payload)
            .await
    }

    /// Promote and reconcile all six explicitly complete source-owner drafts.
    /// The bundle validator runs before any authority call, so a missing family,
    /// duplicate family, or frontier mismatch cannot create a partial positive
    /// bundle accidentally.
    pub async fn reconcile_and_record_source_owner_bundle(
        &self,
        drafts: impl IntoIterator<
            Item = (
                astral_types::authority_protocol::AuthorityFamilyCompletion,
                String,
                bool,
            ),
        >,
    ) -> Result<Vec<CertifiedMemoryCompletionWriteResult>, CertifiedMemoryCompletionCoordinatorError>
    {
        let mut candidates = Vec::new();
        for (draft, payload, complete_empty) in drafts {
            let (candidate, canonical_payload) =
                crate::certified_memory_source_owner_producer::finalize_source_owner_draft(
                    draft,
                    payload,
                    complete_empty,
                )
                .map_err(|error| {
                    CertifiedMemoryCompletionCoordinatorError::Invalid(error.to_string())
                })?;
            candidates.push((candidate, canonical_payload));
        }
        self.reconcile_and_record_bundle(candidates).await
    }

    ///
    /// The candidate must already contain the exact source reservation,
    /// operation, event, source outcome, audit, inventory, generation, revoke
    /// watermark, and dependency frontier. Missing or non-terminal evidence is
    /// rejected before network I/O by the existing bridge.
    pub async fn reconcile_and_record(
        &self,
        candidate: AuthorityFamilyCompletionCandidate,
        canonical_payload: impl Into<String>,
    ) -> Result<CertifiedMemoryCompletionWriteResult, CertifiedMemoryCompletionCoordinatorError>
    {
        let request = reconcile_verified_certified_memory_family(
            &self.pool,
            &self.client,
            self.database_id.clone(),
            candidate,
            canonical_payload,
        )
        .await
        .map_err(CertifiedMemoryCompletionCoordinatorError::Reconciler)?;

        // The authority call is complete before this transaction starts. The
        // transaction contains only local read-back, idempotent write, and
        // commit; no network, MQ, cache, or projection work is allowed here.
        let mut tx = self.pool.begin().await.map_err(|error| {
            CertifiedMemoryCompletionCoordinatorError::Database {
                code: "certified_memory.completion_transaction_begin_unknown",
                detail: error.to_string(),
            }
        })?;
        let result = crate::record_verified_certified_memory_completion_in_tx(
            &mut tx,
            &self.client,
            request,
        )
        .await
        .map_err(CertifiedMemoryCompletionCoordinatorError::Writer)?;
        tx.commit()
            .await
            .map_err(|error| CertifiedMemoryCompletionCoordinatorError::Unknown {
                code: "certified_memory.completion_transaction_commit_unknown",
                detail: error.to_string(),
            })?;
        Ok(result)
    }

    /// Reconcile and record the complete six-family bundle for one durable
    /// source operation. Each family has its own idempotent ledger identity;
    /// a partial result remains durable and later calls reconcile it by the
    /// same stable candidate identities.
    pub async fn reconcile_and_record_bundle(
        &self,
        candidates: impl IntoIterator<Item = (AuthorityFamilyCompletionCandidate, String)>,
    ) -> Result<Vec<CertifiedMemoryCompletionWriteResult>, CertifiedMemoryCompletionCoordinatorError>
    {
        let candidates: Vec<_> = candidates.into_iter().collect();
        validate_bundle(&candidates)?;
        let mut results = Vec::with_capacity(candidates.len());
        for (candidate, payload) in candidates {
            results.push(self.reconcile_and_record(candidate, payload).await?);
        }
        Ok(results)
    }
}

fn validate_bundle(
    candidates: &[(AuthorityFamilyCompletionCandidate, String)],
) -> Result<(), CertifiedMemoryCompletionCoordinatorError> {
    let required = AuthorityCertifiedMemoryFamily::required();
    if candidates.len() != required.len() {
        return Err(CertifiedMemoryCompletionCoordinatorError::Pending {
            code: "certified_memory.family_bundle_incomplete",
            detail: format!(
                "expected {} family candidates, received {}",
                required.len(),
                candidates.len()
            ),
        });
    }

    let mut seen = BTreeSet::new();
    let mut common_scope: Option<&astral_types::authority_protocol::AuthorityFamilyScope> = None;
    let mut common_identity: Option<(&str, &str, &str, &str, &str, u64, u64)> = None;
    for (candidate, _) in candidates {
        candidate.validate().map_err(|error| {
            CertifiedMemoryCompletionCoordinatorError::Invalid(error.to_string())
        })?;
        if !common_scope.is_some_and(|scope| scope == &candidate.scope) {
            if common_scope.is_some() {
                return Err(CertifiedMemoryCompletionCoordinatorError::Conflict(
                    "family bundle candidates do not share one scope".into(),
                ));
            }
            common_scope = Some(&candidate.scope);
        }
        if !seen.insert(candidate.family.as_text()) {
            return Err(CertifiedMemoryCompletionCoordinatorError::Conflict(
                "family bundle contains a duplicate family".into(),
            ));
        }
        let identity = (
            candidate.reservation_id.as_str(),
            candidate.operation_id.as_str(),
            candidate.event_id.as_str(),
            candidate.source_commit_digest.as_str(),
            candidate.source_outcome_digest.as_str(),
            candidate.scope_generation,
            candidate.revoke_watermark,
        );
        if let Some(expected) = common_identity {
            if expected != identity {
                return Err(CertifiedMemoryCompletionCoordinatorError::Conflict(
                    "family bundle candidates do not share one source identity and frontier".into(),
                ));
            }
        } else {
            common_identity = Some(identity);
        }
    }
    if seen.len() != required.len()
        || required
            .iter()
            .any(|family| !seen.contains(family.as_text()))
    {
        return Err(CertifiedMemoryCompletionCoordinatorError::Pending {
            code: "certified_memory.family_bundle_incomplete",
            detail: "one or more required family identities are absent".into(),
        });
    }
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CertifiedMemoryCompletionCoordinatorError {
    #[error("certified-memory completion candidate is invalid: {0}")]
    Invalid(String),
    #[error("certified-memory completion bundle conflicts with its source identity: {0}")]
    Conflict(String),
    #[error("certified-memory completion remains pending: {code}: {detail}")]
    Pending { code: &'static str, detail: String },
    #[error("certified-memory completion authority reconciliation failed: {0}")]
    Reconciler(CertifiedMemoryFamilyReconcilerError),
    #[error("certified-memory completion writer failed: {0}")]
    Writer(CertifiedMemoryCompletionWriteError),
    #[error("certified-memory completion database failure ({code}): {detail}")]
    Database { code: &'static str, detail: String },
    #[error("certified-memory completion outcome is unknown ({code}): {detail}")]
    Unknown { code: &'static str, detail: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::authority_protocol::{
        AuthorityFamilyCompletionState, AuthorityFamilyDependencyFrontier, AuthorityFamilyScope,
    };
    use sha2::{Digest, Sha256};

    fn candidate(family: AuthorityCertifiedMemoryFamily) -> AuthorityFamilyCompletionCandidate {
        let payload = "[]";
        AuthorityFamilyCompletionCandidate {
            family,
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

    #[test]
    fn incomplete_bundle_stays_pending_before_authority_calls() {
        let error = validate_bundle(&[(
            candidate(AuthorityCertifiedMemoryFamily::CardContext),
            "[]".into(),
        )])
        .expect_err("a six-family bundle is required");
        assert!(matches!(
            error,
            CertifiedMemoryCompletionCoordinatorError::Pending {
                code: "certified_memory.family_bundle_incomplete",
                ..
            }
        ));
    }

    #[test]
    fn mixed_scope_bundle_is_rejected_before_authority_calls() {
        let mut different_scope = candidate(AuthorityCertifiedMemoryFamily::GlobalAdmin);
        different_scope.scope.scope = "tenant:8".into();
        let error = validate_bundle(&[
            (
                candidate(AuthorityCertifiedMemoryFamily::CardContext),
                "[]".into(),
            ),
            (different_scope, "[]".into()),
            (
                candidate(AuthorityCertifiedMemoryFamily::PublishedEvidence),
                "[]".into(),
            ),
            (
                candidate(AuthorityCertifiedMemoryFamily::OrgAuthorization),
                "[]".into(),
            ),
            (
                candidate(AuthorityCertifiedMemoryFamily::Ownership),
                "[]".into(),
            ),
            (
                candidate(AuthorityCertifiedMemoryFamily::SodPolicy),
                "[]".into(),
            ),
        ])
        .expect_err("mixed family scopes must fail before authority calls");
        assert!(matches!(
            error,
            CertifiedMemoryCompletionCoordinatorError::Conflict(message)
                if message == "family bundle candidates do not share one scope"
        ));
    }

    #[test]
    fn duplicate_family_is_rejected() {
        let item = (
            candidate(AuthorityCertifiedMemoryFamily::CardContext),
            "[]".into(),
        );
        let error = validate_bundle(&[
            item.clone(),
            item,
            (
                candidate(AuthorityCertifiedMemoryFamily::GlobalAdmin),
                "[]".into(),
            ),
            (
                candidate(AuthorityCertifiedMemoryFamily::PublishedEvidence),
                "[]".into(),
            ),
            (
                candidate(AuthorityCertifiedMemoryFamily::OrgAuthorization),
                "[]".into(),
            ),
            (
                candidate(AuthorityCertifiedMemoryFamily::Ownership),
                "[]".into(),
            ),
        ])
        .expect_err("duplicate family must fail closed");
        assert!(matches!(
            error,
            CertifiedMemoryCompletionCoordinatorError::Conflict(_)
        ));
    }
}
