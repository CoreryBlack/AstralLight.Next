//! Durable CertifiedMemory family-completion ledger.
//!
//! This module is a read boundary for source owners. It never derives a family
//! completion from an empty query, a current pointer, an ACK, or a cache hit.
//! A row's typed inventory, frontier, digests, audit identity, and receipt ID
//! can be parsed and checked locally, but they do not prove authority provenance.
//! Ledger-backed owners also require independently verified source-owned
//! completeness, which is not yet available for any of the six families.

use astral_authority::AuthorityClient;
use astral_types::authority_protocol::{
    AuthorityCertifiedMemoryFamily, AuthorityFamilyCompletion, AuthorityFamilyCompletionCandidate,
    AuthorityFamilyCompletionState, AuthorityFamilyDependencyFrontier,
    AuthorityFamilyInventoryItem, AuthorityFamilyScope,
};
use astral_types::GlobalAuthorityFrontier;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sqlx::MySqlPool;
use thiserror::Error;

use crate::certified_memory_materializer::CertifiedMemoryFamilyOwnerRequest;

const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// Historical issuance identity for diagnostics only. This is not evidence of
/// source-owned family completeness, current authorization, or a write permit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyCompletionHistoryDiagnostic {
    pub family: AuthorityCertifiedMemoryFamily,
    pub reservation_id: String,
    pub operation_id: String,
    pub receipt_id: String,
    pub historical_frontier: GlobalAuthorityFrontier,
}

/// Read one exact authority history entry without creating a completion, a
/// ledger write request, or a materializable record. `None` means no receipt was
/// found; an uncertain authority outcome is returned without a retry.
pub async fn diagnose_family_completion_history(
    client: &AuthorityClient,
    database_id: impl Into<String>,
    candidate: AuthorityFamilyCompletionCandidate,
) -> Result<Option<FamilyCompletionHistoryDiagnostic>, CertifiedMemoryCompletionError> {
    diagnose_family_completion_history_with(client, database_id.into(), candidate).await
}

#[async_trait]
trait FamilyHistoryReader {
    async fn read_history(
        &self,
        database_id: String,
        candidate: AuthorityFamilyCompletionCandidate,
    ) -> Result<Option<FamilyCompletionHistoryDiagnostic>, CertifiedMemoryCompletionError>;
}

#[async_trait]
impl FamilyHistoryReader for AuthorityClient {
    async fn read_history(
        &self,
        database_id: String,
        candidate: AuthorityFamilyCompletionCandidate,
    ) -> Result<Option<FamilyCompletionHistoryDiagnostic>, CertifiedMemoryCompletionError> {
        let verified = self
            .reconcile_family_verified(database_id.clone(), candidate.clone())
            .await
            .map_err(|_| CertifiedMemoryCompletionError::Unknown {
                code: "certified_memory.completion_authority_reconciliation_unknown",
            })?;
        let Some(verified) = verified else {
            return Ok(None);
        };
        if !verified.verified_by(self)
            || verified.database_id() != database_id
            || verified.candidate() != &candidate
            || verified.reconciliation_response().is_none()
        {
            return Err(CertifiedMemoryCompletionError::Unknown {
                code: "certified_memory.completion_authority_history_mismatch",
            });
        }
        let receipt = verified.receipt();
        let expected = candidate
            .clone()
            .into_receipted_completion(receipt.receipt_id.clone())
            .map_err(|error| CertifiedMemoryCompletionError::Invalid(error.to_string()))?;
        if receipt.completion != expected {
            return Err(CertifiedMemoryCompletionError::Unknown {
                code: "certified_memory.completion_authority_history_mismatch",
            });
        }
        Ok(Some(FamilyCompletionHistoryDiagnostic {
            family: candidate.family,
            reservation_id: candidate.reservation_id,
            operation_id: candidate.operation_id,
            receipt_id: receipt.receipt_id.clone(),
            historical_frontier: receipt.global_frontier.clone(),
        }))
    }
}

async fn diagnose_family_completion_history_with<R: FamilyHistoryReader>(
    reader: &R,
    database_id: String,
    candidate: AuthorityFamilyCompletionCandidate,
) -> Result<Option<FamilyCompletionHistoryDiagnostic>, CertifiedMemoryCompletionError> {
    candidate
        .validate()
        .map_err(|error| CertifiedMemoryCompletionError::Invalid(error.to_string()))?;
    let result = reader.read_history(database_id, candidate.clone()).await?;
    if result.as_ref().is_some_and(|history| {
        history.family != candidate.family
            || history.reservation_id != candidate.reservation_id
            || history.operation_id != candidate.operation_id
    }) {
        return Err(CertifiedMemoryCompletionError::Unknown {
            code: "certified_memory.completion_authority_history_mismatch",
        });
    }
    Ok(result)
}

/// Stable, bounded row read from the durable completion ledger.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct CertifiedMemoryCompletionRow {
    pub family: String,
    pub scope_key: String,
    pub tenant_id: Option<i64>,
    pub scope_generation: u64,
    pub revoke_watermark: u64,
    pub state: String,
    pub reconciliation_state: String,
    pub reservation_id: String,
    pub operation_id: String,
    pub event_id: String,
    pub message_id: Option<String>,
    pub source_commit_digest: Vec<u8>,
    pub source_outcome_digest: Vec<u8>,
    pub before_content_digest: Option<Vec<u8>>,
    pub after_content_digest: Option<Vec<u8>>,
    pub complete_content_digest: Option<Vec<u8>>,
    pub audit_correlation_id: String,
    pub inventory_json: String,
    pub payload_json: String,
    pub dependency_frontier_json: String,
    pub authority_completion_receipt_id: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Typed completion plus the family-specific payload retained by its owner.
/// Payload decoding remains owner-specific; this adapter never guesses a
/// payload type from a family string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedMemoryCompletionRecord {
    pub completion: AuthorityFamilyCompletion,
    pub payload_json: String,
}

impl CertifiedMemoryCompletionRow {
    /// Parse and locally validate a durable row without upgrading non-terminal
    /// or unreconciled states. This does not verify receipt provenance and must
    /// not be used as authority proof or directly materialized by a ledger owner.
    pub fn into_record(
        self,
        expected_scope: &AuthorityFamilyScope,
        expected_generation: u64,
        expected_revoke_watermark: u64,
    ) -> Result<CertifiedMemoryCompletionRecord, CertifiedMemoryCompletionError> {
        if self.scope_key != expected_scope.scope
            || self.tenant_id != expected_scope.tenant_id
            || self.scope_generation != expected_generation
            || self.revoke_watermark != expected_revoke_watermark
        {
            return Err(CertifiedMemoryCompletionError::ScopeMismatch);
        }
        if self.reconciliation_state != "PROVEN" {
            return Err(match self.reconciliation_state.as_str() {
                "UNKNOWN" => CertifiedMemoryCompletionError::Unknown {
                    code: "certified_memory.completion_reconciliation_unknown",
                },
                "QUARANTINED" => CertifiedMemoryCompletionError::Quarantined {
                    code: "certified_memory.completion_reconciliation_quarantined",
                },
                _ => CertifiedMemoryCompletionError::Pending {
                    code: "certified_memory.completion_reconciliation_pending",
                },
            });
        }
        if self.payload_json.len() > MAX_PAYLOAD_BYTES {
            return Err(CertifiedMemoryCompletionError::Invalid(
                "completion payload exceeds bounded size".into(),
            ));
        }

        let family = parse_family(&self.family)?;
        let state = parse_state(&self.state)?;
        let inventory: Vec<AuthorityFamilyInventoryItem> =
            serde_json::from_str(&self.inventory_json).map_err(|_| {
                CertifiedMemoryCompletionError::Invalid("invalid completion inventory".into())
            })?;
        let dependency_frontier: AuthorityFamilyDependencyFrontier =
            serde_json::from_str(&self.dependency_frontier_json).map_err(|_| {
                CertifiedMemoryCompletionError::Invalid(
                    "invalid completion dependency frontier".into(),
                )
            })?;
        let completion = AuthorityFamilyCompletion {
            family,
            state,
            scope: expected_scope.clone(),
            reservation_id: self.reservation_id,
            operation_id: self.operation_id,
            event_id: self.event_id,
            message_id: self.message_id,
            source_commit_digest: digest_hex(self.source_commit_digest, "source_commit_digest")?,
            source_outcome_digest: digest_hex(self.source_outcome_digest, "source_outcome_digest")?,
            before_content_digest: optional_digest(
                self.before_content_digest,
                "before_content_digest",
            )?,
            after_content_digest: optional_digest(
                self.after_content_digest,
                "after_content_digest",
            )?,
            complete_content_digest: optional_digest(
                self.complete_content_digest,
                "complete_content_digest",
            )?,
            audit_correlation_id: self.audit_correlation_id,
            inventory,
            scope_generation: self.scope_generation,
            revoke_watermark: self.revoke_watermark,
            dependency_frontier,
            authority_completion_receipt_id: self.authority_completion_receipt_id,
        };
        completion
            .validate()
            .map_err(|error| CertifiedMemoryCompletionError::Invalid(error.to_string()))?;
        if completion.state.is_terminal_complete() {
            let Some(expected_digest) = completion.complete_content_digest.as_deref() else {
                return Err(CertifiedMemoryCompletionError::Invalid(
                    "terminal completion lacks content digest".into(),
                ));
            };
            let canonical_payload = canonical_json(&self.payload_json)?;
            let actual_digest = hex::encode(Sha256::digest(canonical_payload.as_bytes()));
            if actual_digest != expected_digest {
                return Err(CertifiedMemoryCompletionError::Invalid(
                    "completion payload digest does not match terminal content digest".into(),
                ));
            }
        }
        Ok(CertifiedMemoryCompletionRecord {
            completion,
            payload_json: self.payload_json,
        })
    }
}

/// Narrow SQL reader used by future family owners.
#[derive(Clone)]
pub struct CertifiedMemoryDurableOwnerContext {
    pool: MySqlPool,
    authority_client: Option<AuthorityClient>,
    authority_database_id: Option<String>,
}

impl std::fmt::Debug for CertifiedMemoryDurableOwnerContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CertifiedMemoryDurableOwnerContext")
            .field("pool", &"<mysql-pool>")
            .field("authority_client", &self.authority_client.is_some())
            .field("authority_database_id", &self.authority_database_id)
            .finish()
    }
}

impl CertifiedMemoryDurableOwnerContext {
    pub fn new(pool: MySqlPool) -> Self {
        Self {
            pool,
            authority_client: None,
            authority_database_id: None,
        }
    }

    /// Bind the composition-root authority client and its registered database
    /// identity. Historical receipt reconciliation does not prove source-owned
    /// family completeness or make a ledger row materializable.
    pub fn with_authority_client(
        mut self,
        client: AuthorityClient,
        database_id: impl Into<String>,
    ) -> Self {
        self.authority_client = Some(client);
        self.authority_database_id = Some(database_id.into());
        self
    }

    pub fn pool(&self) -> &MySqlPool {
        &self.pool
    }

    /// Read one exact family/scope/generation row. No row is interpreted as
    /// `CompleteEmpty`; the source owner must write an explicit terminal row.
    pub async fn read_completion(
        &self,
        request: &CertifiedMemoryFamilyOwnerRequest,
        family: AuthorityCertifiedMemoryFamily,
    ) -> Result<CertifiedMemoryCompletionRecord, CertifiedMemoryCompletionError> {
        request
            .validate()
            .map_err(|error| CertifiedMemoryCompletionError::Invalid(error.to_string()))?;
        if self.authority_client.is_some() {
            return self.read_completion_with_authority(request, family).await;
        }
        let row = sqlx::query_as::<_, CertifiedMemoryCompletionRow>(
            "SELECT family, scope_key, tenant_id, scope_generation, revoke_watermark, \
                    state, reconciliation_state, reservation_id, operation_id, event_id, \
                    message_id, source_commit_digest, source_outcome_digest, \
                    before_content_digest, after_content_digest, complete_content_digest, \
                    audit_correlation_id, inventory_json, payload_json, dependency_frontier_json, \
                    authority_completion_receipt_id, created_at, updated_at \
             FROM authority_certified_memory_completion \
             WHERE family = ? AND scope_key = ? AND (tenant_id <=> ?) \
               AND scope_generation = ? \
             LIMIT 1",
        )
        .bind(family.as_text())
        .bind(&request.scope.scope)
        .bind(request.scope.tenant_id)
        .bind(request.generation)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| CertifiedMemoryCompletionError::Unknown {
            code: if error.to_string().contains("doesn't exist") {
                "certified_memory.completion_ledger_schema_unavailable"
            } else {
                "certified_memory.completion_ledger_read_failed"
            },
        })?
        .ok_or(CertifiedMemoryCompletionError::Pending {
            code: "certified_memory.completion_receipt_missing",
        })?;
        Self::reconcile_row_for_owner(row, request)
    }

    /// Read and reconcile one exact historical completion through the same
    /// authority client used by the composition root. No receipt id from SQL is
    /// trusted by itself: the candidate is rebuilt from the row, the authority
    /// returns its immutable historical receipt, and the verified client checks
    /// frontier/trust-root history before checking the separate source-owned
    /// completeness gate. Historical reconciliation alone cannot serve a row.
    pub async fn read_completion_with_authority(
        &self,
        request: &CertifiedMemoryFamilyOwnerRequest,
        family: AuthorityCertifiedMemoryFamily,
    ) -> Result<CertifiedMemoryCompletionRecord, CertifiedMemoryCompletionError> {
        request
            .validate()
            .map_err(|error| CertifiedMemoryCompletionError::Invalid(error.to_string()))?;
        let client =
            self.authority_client
                .as_ref()
                .ok_or(CertifiedMemoryCompletionError::Unknown {
                    code: "certified_memory.authority_client_unbound",
                })?;
        let database_id =
            self.authority_database_id
                .as_ref()
                .ok_or(CertifiedMemoryCompletionError::Unknown {
                    code: "certified_memory.authority_database_unbound",
                })?;
        let row = sqlx::query_as::<_, CertifiedMemoryCompletionRow>(
            "SELECT family, scope_key, tenant_id, scope_generation, revoke_watermark, \
                    state, reconciliation_state, reservation_id, operation_id, event_id, \
                    message_id, source_commit_digest, source_outcome_digest, \
                    before_content_digest, after_content_digest, complete_content_digest, \
                    audit_correlation_id, inventory_json, payload_json, dependency_frontier_json, \
                    authority_completion_receipt_id, created_at, updated_at \
             FROM authority_certified_memory_completion \
             WHERE family = ? AND scope_key = ? AND (tenant_id <=> ?) \
               AND scope_generation = ? \
             LIMIT 1",
        )
        .bind(family.as_text())
        .bind(&request.scope.scope)
        .bind(request.scope.tenant_id)
        .bind(request.generation)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| CertifiedMemoryCompletionError::Unknown {
            code: if error.to_string().contains("doesn't exist") {
                "certified_memory.completion_ledger_schema_unavailable"
            } else {
                "certified_memory.completion_ledger_read_failed"
            },
        })?
        .ok_or(CertifiedMemoryCompletionError::Pending {
            code: "certified_memory.completion_receipt_missing",
        })?;
        let record =
            row.into_record(&request.scope, request.generation, request.revoke_watermark)?;
        let candidate = AuthorityFamilyCompletionCandidate {
            family: record.completion.family,
            state: record.completion.state,
            scope: record.completion.scope.clone(),
            reservation_id: record.completion.reservation_id.clone(),
            operation_id: record.completion.operation_id.clone(),
            event_id: record.completion.event_id.clone(),
            message_id: record.completion.message_id.clone(),
            source_commit_digest: record.completion.source_commit_digest.clone(),
            source_outcome_digest: record.completion.source_outcome_digest.clone(),
            before_content_digest: record.completion.before_content_digest.clone(),
            after_content_digest: record.completion.after_content_digest.clone(),
            complete_content_digest: record.completion.complete_content_digest.clone(),
            audit_correlation_id: record.completion.audit_correlation_id.clone(),
            inventory: record.completion.inventory.clone(),
            scope_generation: record.completion.scope_generation,
            revoke_watermark: record.completion.revoke_watermark,
            dependency_frontier: record.completion.dependency_frontier,
        };
        candidate
            .validate()
            .map_err(|error| CertifiedMemoryCompletionError::Invalid(error.to_string()))?;
        let verified = client
            .reconcile_family_verified(database_id.clone(), candidate)
            .await
            .map_err(|_| CertifiedMemoryCompletionError::Unknown {
                code: "certified_memory.completion_authority_reconciliation_unknown",
            })?
            .ok_or(CertifiedMemoryCompletionError::Pending {
                code: "certified_memory.completion_authority_receipt_missing",
            })?;
        let receipt = verified.receipt();
        if !verified.verified_by(client)
            || receipt.completion.family != family
            || receipt.completion != record.completion
            || receipt.receipt_id != record.completion.authority_completion_receipt_id
            || verified.database_id() != database_id
        {
            return Err(CertifiedMemoryCompletionError::Unknown {
                code: "certified_memory.completion_authority_history_mismatch",
            });
        }
        require_owner_source_completeness(record)
    }

    /// Compatibility path intentionally remains non-positive when no authority
    /// client is bound to this context.
    fn reconcile_row_for_owner(
        row: CertifiedMemoryCompletionRow,
        request: &CertifiedMemoryFamilyOwnerRequest,
    ) -> Result<CertifiedMemoryCompletionRecord, CertifiedMemoryCompletionError> {
        let _record =
            row.into_record(&request.scope, request.generation, request.revoke_watermark)?;
        Err(CertifiedMemoryCompletionError::Unknown {
            code: "certified_memory.completion_authority_receipt_unverified",
        })
    }
}

fn require_owner_source_completeness(
    _record: CertifiedMemoryCompletionRecord,
) -> Result<CertifiedMemoryCompletionRecord, CertifiedMemoryCompletionError> {
    // Neither the ledger row nor an authority receipt proves a complete source
    // selector and its exact result. No family has a verifiable durable capture
    // contract at this boundary yet.
    Err(CertifiedMemoryCompletionError::Pending {
        code: "certified_memory.source_family_completeness_unverified",
    })
}

fn canonical_json(value: &str) -> Result<String, CertifiedMemoryCompletionError> {
    let parsed: serde_json::Value = serde_json::from_str(value).map_err(|_| {
        CertifiedMemoryCompletionError::Invalid("completion payload is not valid JSON".into())
    })?;
    serde_json::to_string(&parsed).map_err(|_| {
        CertifiedMemoryCompletionError::Invalid("completion payload cannot be canonicalized".into())
    })
}
fn parse_family(
    value: &str,
) -> Result<AuthorityCertifiedMemoryFamily, CertifiedMemoryCompletionError> {
    AuthorityCertifiedMemoryFamily::required()
        .into_iter()
        .find(|family| family.as_text() == value)
        .ok_or_else(|| CertifiedMemoryCompletionError::Invalid("unknown completion family".into()))
}

fn parse_state(
    value: &str,
) -> Result<AuthorityFamilyCompletionState, CertifiedMemoryCompletionError> {
    match value {
        "COMPLETE" => Ok(AuthorityFamilyCompletionState::Complete),
        "COMPLETE_EMPTY" => Ok(AuthorityFamilyCompletionState::CompleteEmpty),
        "PENDING" => Ok(AuthorityFamilyCompletionState::Pending),
        "UNKNOWN" => Ok(AuthorityFamilyCompletionState::Unknown),
        "QUARANTINED" => Ok(AuthorityFamilyCompletionState::Quarantined),
        _ => Err(CertifiedMemoryCompletionError::Invalid(
            "unknown completion state".into(),
        )),
    }
}

fn digest_hex(
    value: Vec<u8>,
    field: &'static str,
) -> Result<String, CertifiedMemoryCompletionError> {
    if value.len() != 32 {
        return Err(CertifiedMemoryCompletionError::Invalid(format!(
            "{field} must be a 32-byte digest"
        )));
    }
    Ok(hex::encode(value))
}

fn optional_digest(
    value: Option<Vec<u8>>,
    field: &'static str,
) -> Result<Option<String>, CertifiedMemoryCompletionError> {
    value.map(|value| digest_hex(value, field)).transpose()
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CertifiedMemoryCompletionError {
    #[error("certified-memory completion is pending: {code}")]
    Pending { code: &'static str },
    #[error("certified-memory completion is unknown: {code}")]
    Unknown { code: &'static str },
    #[error("certified-memory completion is quarantined: {code}")]
    Quarantined { code: &'static str },
    #[error("certified-memory completion scope does not match request")]
    ScopeMismatch,
    #[error("certified-memory completion is invalid: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    struct ScriptedHistory {
        calls: AtomicUsize,
        result: Mutex<
            Option<
                Result<Option<FamilyCompletionHistoryDiagnostic>, CertifiedMemoryCompletionError>,
            >,
        >,
    }

    #[async_trait]
    impl FamilyHistoryReader for ScriptedHistory {
        async fn read_history(
            &self,
            _database_id: String,
            _candidate: AuthorityFamilyCompletionCandidate,
        ) -> Result<Option<FamilyCompletionHistoryDiagnostic>, CertifiedMemoryCompletionError>
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result
                .lock()
                .unwrap()
                .take()
                .expect("history queried at most once")
        }
    }

    fn history_candidate() -> AuthorityFamilyCompletionCandidate {
        let record = row("COMPLETE", "PROVEN")
            .into_record(&request().scope, 3, 1)
            .unwrap();
        let c = record.completion;
        AuthorityFamilyCompletionCandidate {
            family: c.family,
            state: c.state,
            scope: c.scope,
            reservation_id: c.reservation_id,
            operation_id: c.operation_id,
            event_id: c.event_id,
            message_id: c.message_id,
            source_commit_digest: c.source_commit_digest,
            source_outcome_digest: c.source_outcome_digest,
            before_content_digest: c.before_content_digest,
            after_content_digest: c.after_content_digest,
            complete_content_digest: c.complete_content_digest,
            audit_correlation_id: c.audit_correlation_id,
            inventory: c.inventory,
            scope_generation: c.scope_generation,
            revoke_watermark: c.revoke_watermark,
            dependency_frontier: c.dependency_frontier,
        }
    }

    fn history_diagnostic() -> FamilyCompletionHistoryDiagnostic {
        FamilyCompletionHistoryDiagnostic {
            family: AuthorityCertifiedMemoryFamily::CardContext,
            reservation_id: "reservation".into(),
            operation_id: "operation".into(),
            receipt_id: "receipt".into(),
            historical_frontier: GlobalAuthorityFrontier::genesis(
                "authority",
                "root",
                &"33".repeat(32),
                "key",
                1,
                100,
            )
            .unwrap(),
        }
    }

    #[tokio::test]
    async fn history_lookup_is_diagnostic_only_and_never_retries() {
        for result in [
            Ok(Some(history_diagnostic())),
            Ok(None),
            Err(CertifiedMemoryCompletionError::Unknown {
                code: "certified_memory.completion_authority_reconciliation_unknown",
            }),
        ] {
            let expected = match &result {
                Ok(value) => Ok(value.clone()),
                Err(CertifiedMemoryCompletionError::Unknown { code }) => {
                    Err(CertifiedMemoryCompletionError::Unknown { code })
                }
                Err(_) => unreachable!("unexpected fixture error"),
            };
            let reader = ScriptedHistory {
                calls: AtomicUsize::new(0),
                result: Mutex::new(Some(result)),
            };
            assert_eq!(
                diagnose_family_completion_history_with(
                    &reader,
                    "database".into(),
                    history_candidate()
                )
                .await,
                expected
            );
            assert_eq!(reader.calls.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn history_lookup_rejects_mismatched_identity_and_invalid_candidate() {
        let mut mismatch = history_diagnostic();
        mismatch.operation_id = "other".into();
        let reader = ScriptedHistory {
            calls: AtomicUsize::new(0),
            result: Mutex::new(Some(Ok(Some(mismatch)))),
        };
        assert_eq!(
            diagnose_family_completion_history_with(
                &reader,
                "database".into(),
                history_candidate()
            )
            .await,
            Err(CertifiedMemoryCompletionError::Unknown {
                code: "certified_memory.completion_authority_history_mismatch"
            })
        );
        assert_eq!(reader.calls.load(Ordering::SeqCst), 1);
        let mut invalid = history_candidate();
        invalid.state = AuthorityFamilyCompletionState::Pending;
        assert!(matches!(
            diagnose_family_completion_history_with(&reader, "database".into(), invalid).await,
            Err(CertifiedMemoryCompletionError::Invalid(_))
        ));
        assert_eq!(reader.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn every_family_and_terminal_state_needs_source_completeness_after_reconciliation() {
        for family in AuthorityCertifiedMemoryFamily::required() {
            for state in ["COMPLETE", "COMPLETE_EMPTY"] {
                let mut historical = row(state, "PROVEN");
                historical.family = family.as_text().into();
                if state == "COMPLETE_EMPTY" {
                    historical.inventory_json = "[]".into();
                }
                let record = historical.into_record(&request().scope, 3, 1).unwrap();
                assert_eq!(
                    require_owner_source_completeness(record),
                    Err(CertifiedMemoryCompletionError::Pending {
                        code: "certified_memory.source_family_completeness_unverified",
                    })
                );
            }
        }
    }

    fn row(state: &str, reconciliation_state: &str) -> CertifiedMemoryCompletionRow {
        CertifiedMemoryCompletionRow {
            family: "CARD_CONTEXT".into(),
            scope_key: "tenant:7".into(),
            tenant_id: Some(7),
            scope_generation: 3,
            revoke_watermark: 1,
            state: state.into(),
            reconciliation_state: reconciliation_state.into(),
            reservation_id: "reservation".into(),
            operation_id: "operation".into(),
            event_id: "event".into(),
            message_id: Some("message".into()),
            source_commit_digest: vec![0x11; 32],
            source_outcome_digest: vec![0x22; 32],
            before_content_digest: None,
            after_content_digest: None,
            complete_content_digest: Some(Sha256::digest(b"{}").to_vec()),
            audit_correlation_id: "audit".into(),
            inventory_json: r#"[{"key":"card:9","tenantId":7,"contentDigest":"4444444444444444444444444444444444444444444444444444444444444444"}]"#.into(),
            payload_json: "{}".into(),
            dependency_frontier_json: r#"{"authorityTerm":1,"globalFenceSequence":2,"dependencyGeneration":3}"#.into(),
            authority_completion_receipt_id: "receipt".into(),
            created_at: 10,
            updated_at: 11,
        }
    }

    fn request() -> CertifiedMemoryFamilyOwnerRequest {
        CertifiedMemoryFamilyOwnerRequest {
            scope: AuthorityFamilyScope {
                tenant_id: Some(7),
                scope: "tenant:7".into(),
            },
            generation: 3,
            revoke_watermark: 1,
            now_unix: 100,
        }
    }

    #[test]
    fn only_proven_terminal_rows_convert() {
        let record = row("COMPLETE", "PROVEN")
            .into_record(&request().scope, 3, 1)
            .expect("complete row");
        assert_eq!(
            record.completion.family,
            AuthorityCertifiedMemoryFamily::CardContext
        );
    }

    #[test]
    fn missing_or_unknown_completion_never_becomes_empty() {
        assert!(matches!(
            row("COMPLETE_EMPTY", "PENDING").into_record(&request().scope, 3, 1),
            Err(CertifiedMemoryCompletionError::Pending { .. })
        ));
        assert!(matches!(
            row("COMPLETE", "UNKNOWN").into_record(&request().scope, 3, 1),
            Err(CertifiedMemoryCompletionError::Unknown { .. })
        ));
    }

    #[test]
    fn locally_valid_historical_rows_never_become_owner_evidence() {
        let request = request();
        for family in AuthorityCertifiedMemoryFamily::required() {
            for state in ["COMPLETE", "COMPLETE_EMPTY"] {
                let mut historical = row(state, "PROVEN");
                historical.family = family.as_text().into();
                if state == "COMPLETE_EMPTY" {
                    historical.inventory_json = "[]".into();
                }
                assert!(historical
                    .clone()
                    .into_record(&request.scope, request.generation, request.revoke_watermark)
                    .is_ok());
                assert_eq!(
                    CertifiedMemoryDurableOwnerContext::reconcile_row_for_owner(
                        historical, &request
                    ),
                    Err(CertifiedMemoryCompletionError::Unknown {
                        code: "certified_memory.completion_authority_receipt_unverified",
                    })
                );
            }
        }
    }

    #[test]
    fn owner_read_keeps_unreconciled_and_mismatched_rows_non_positive() {
        let request = request();
        for (state, expected) in [
            (
                "PENDING",
                CertifiedMemoryCompletionError::Pending {
                    code: "certified_memory.completion_reconciliation_pending",
                },
            ),
            (
                "UNKNOWN",
                CertifiedMemoryCompletionError::Unknown {
                    code: "certified_memory.completion_reconciliation_unknown",
                },
            ),
            (
                "QUARANTINED",
                CertifiedMemoryCompletionError::Quarantined {
                    code: "certified_memory.completion_reconciliation_quarantined",
                },
            ),
        ] {
            assert_eq!(
                CertifiedMemoryDurableOwnerContext::reconcile_row_for_owner(
                    row("COMPLETE", state),
                    &request
                ),
                Err(expected)
            );
        }
        let mut mismatch = row("COMPLETE", "PROVEN");
        mismatch.tenant_id = Some(8);
        assert_eq!(
            CertifiedMemoryDurableOwnerContext::reconcile_row_for_owner(mismatch, &request),
            Err(CertifiedMemoryCompletionError::ScopeMismatch)
        );
    }

    #[test]
    fn digest_and_scope_binding_are_strict() {
        let mut invalid = row("COMPLETE", "PROVEN");
        invalid.source_commit_digest.pop();
        assert!(matches!(
            invalid.into_record(&request().scope, 3, 1),
            Err(CertifiedMemoryCompletionError::Invalid(_))
        ));
        let mut mismatch = row("COMPLETE", "PROVEN");
        mismatch.scope_key = "tenant:8".into();
        assert_eq!(
            mismatch.into_record(&request().scope, 3, 1),
            Err(CertifiedMemoryCompletionError::ScopeMismatch)
        );
    }
}
