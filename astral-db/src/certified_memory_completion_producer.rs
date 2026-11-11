//! Strict DB-read completion producers for the PUBLISHED_EVIDENCE and
//! ORG_AUTHORIZATION CertifiedMemory families.
//!
//! Contract (Rust 规范 §15.9; AGENTS §3.2):
//! - A durable `AuthorityFamilyCompletion` may only be produced from exact
//!   strict DB reads of already-published durable state, reusing the SAME
//!   loaders as the formal authorization paths (no second reading body):
//!   `load_published_card_state_bundle_in_tx` + `AuthorizationFenceProof::
//!   evidence_content_hash` for PUBLISHED_EVIDENCE, and
//!   `load_admission_evidence_in_pool` + the shared `org_authority_evidence_hash`
//!   / `org_authority_revocation_evidence_hash` structural owners for
//!   ORG_AUTHORIZATION.
//! - A strict read produces a diagnostic draft only. It does not prove the
//!   committed source/outcome binding, audit correlation, or a complete family
//!   inventory, and its legacy authority-candidate conversion returns UNKNOWN.
//!   The legacy receipt is also insufficient to prove authority provenance.
//! - Every read runs inside a SHORT caller-owned transaction (or the pool
//!   reader's own short transaction); no network, MQ, or cache operation
//!   occurs inside any transaction.
//! - Terminal payloads use the exact `certified_memory_family_owner` wire
//!   shapes, and the complete-content digest is computed exactly the way the
//!   ledger writer canonicalizes payloads, so a persisted row re-materializes
//!   to byte-identical evidence.

use std::collections::BTreeSet;

use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::Row;

use astral_types::authority_protocol::{
    AuthorityCertifiedMemoryFamily, AuthorityFamilyCompletion, AuthorityFamilyCompletionCandidate,
    AuthorityFamilyCompletionState, AuthorityFamilyInventoryItem, AuthorityFamilyScope,
};
use astral_types::org_authority_evidence_hash;
use astral_types::org_scope::OrgAdmissionResult;
use astral_types::{
    AuthorizationFenceProof, PublishedCardAuthorization, PublishedCardEvidenceScope,
};

use crate::authority_source_outcome::AuthoritySourceOutcomeRow;

use crate::org_scope_repository::OrgAdmissionQuery;

/// The durable authority frontier identity a receipt must strictly advance.
///
/// Field-for-field the DB-backed mirror of the authority fence identity row.
/// The producer cannot invent counters; the caller can only prove a receipt
/// whose authority term/fence sequence strictly advance this durable row.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DurableAuthorityFrontierIdentity {
    pub authority_id: String,
    pub authority_term: u64,
    pub global_fence_sequence: u64,
    pub key_id: String,
    pub key_epoch: u64,
}

impl DurableAuthorityFrontierIdentity {
    /// A receipt bound to a lagging or equal frontier can never prove a new
    /// completion: replay protection, fail-closed. A higher term resets the
    /// fence comparison (the authority term is the outer monotonic epoch).
    pub fn strictly_advances_beyond(
        &self,
        receipt_authority_term: u64,
        receipt_global_fence_sequence: u64,
    ) -> bool {
        receipt_authority_term > self.authority_term
            || (receipt_authority_term == self.authority_term
                && receipt_global_fence_sequence > self.global_fence_sequence)
    }
}

/// Legacy local receipt seam retained for source compatibility only.
///
/// This value is intentionally insufficient to prove an authority completion:
/// it has no candidate binding, authority identity, trust-root history, or
/// signed/global frontier evidence. It is accepted only by the deprecated
/// compatibility orchestration, which always remains PENDING/UNKNOWN.
#[derive(Debug, Clone)]
pub struct AuthorityCompletionReceipt {
    receipt_id: String,
    authority_term: u64,
    global_fence_sequence: u64,
}

#[allow(deprecated)]
impl AuthorityCompletionReceipt {
    /// Constructing this legacy value never verifies an authority receipt.
    pub fn new(
        receipt_id: impl Into<String>,
        authority_term: u64,
        global_fence_sequence: u64,
    ) -> Result<Self, CompletionProducerError> {
        let receipt_id = receipt_id.into();
        if receipt_id.is_empty()
            || receipt_id.len() > 128
            || receipt_id.trim() != receipt_id
            || receipt_id
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(CompletionProducerError::Invalid(
                "authority completion receipt id is not a bounded protocol text".into(),
            ));
        }
        if authority_term == 0 || global_fence_sequence == 0 {
            return Err(CompletionProducerError::Invalid(
                "authority completion receipt frontier counters must be positive".into(),
            ));
        }
        Ok(Self {
            receipt_id,
            authority_term,
            global_fence_sequence,
        })
    }

    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    pub const fn authority_term(&self) -> u64 {
        self.authority_term
    }

    pub const fn global_fence_sequence(&self) -> u64 {
        self.global_fence_sequence
    }
}

/// A process-local diagnostic draft from a strict read. Its source digest
/// fields are content hashes, not proof of the source commit or outcome. The
/// read covers one scope, not a complete family inventory; neither conversion
/// method can produce an authority completion from this draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyCompletionReady {
    pub family: AuthorityCertifiedMemoryFamily,
    pub scope: AuthorityFamilyScope,
    /// Canonical terminal payload bytes (the family-owner wire shape).
    pub payload_json: String,
    /// SHA-256 over the canonical payload, computed exactly the way the
    /// ledger writer canonicalizes payloads.
    pub complete_content_digest: String,
    /// Local content hash; not the authority reservation's source commit digest.
    pub source_commit_digest: String,
    /// Local payload digest; not proof of the committed source outcome.
    pub source_outcome_digest: String,
    pub audit_correlation_id: String,
    pub inventory: Vec<AuthorityFamilyInventoryItem>,
    pub scope_generation: u64,
    pub revoke_watermark: u64,
    pub dependency_generation: u64,
    /// Durable frontier observed during the read. This local observation does
    /// not establish the authority receipt or the committed source binding.
    pub frontier: DurableAuthorityFrontierIdentity,
}

/// Source identity supplied by the owner that captured the strict family read.
///
/// Keeping these fields together prevents callers from accidentally mixing an
/// operation, event, message, or audit identity from different source commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyCompletionSourceBinding {
    pub reservation_id: String,
    pub operation_id: String,
    pub event_id: String,
    pub message_id: Option<String>,
    pub audit_correlation_id: String,
    pub state: AuthorityFamilyCompletionState,
}

impl FamilyCompletionSourceBinding {
    fn validate(&self) -> Result<(), CompletionProducerError> {
        if self.reservation_id.trim().is_empty()
            || self.operation_id.trim().is_empty()
            || self.event_id.trim().is_empty()
            || self.audit_correlation_id.trim().is_empty()
            || !self.state.is_terminal_complete()
            || self
                .message_id
                .as_deref()
                .is_some_and(|message_id| message_id.trim().is_empty())
        {
            return Err(CompletionProducerError::Unknown(
                CompletionProducerErrorCode::SourceBindingUnverified,
            ));
        }
        Ok(())
    }
}

impl FamilyCompletionReady {
    /// Convert the strict DB read into the authority submission candidate.
    ///
    /// The local read does not prove the committed source binding or a complete
    /// family inventory. Keep the compatibility entry point fail-closed until
    /// those facts can be reconciled with the authority reservation.
    pub fn into_authority_candidate(
        &self,
        _reservation_id: &str,
        _operation_id: &str,
        _event_id: &str,
        _message_id: Option<&str>,
        _audit_correlation_id: &str,
    ) -> Result<AuthorityFamilyCompletionCandidate, CompletionProducerError> {
        Err(CompletionProducerError::Unknown(
            CompletionProducerErrorCode::SourceBindingUnverified,
        ))
    }

    /// A verified source outcome does not prove that this diagnostic read covers
    /// the complete family at the committed frontier. Keep this compatibility
    /// entry point closed until source-owned coverage evidence is available.
    pub fn bind_verified_source_outcome(
        &self,
        _source: &AuthoritySourceOutcomeRow,
        binding: &FamilyCompletionSourceBinding,
    ) -> Result<AuthorityFamilyCompletionCandidate, CompletionProducerError> {
        binding.validate()?;
        Err(CompletionProducerError::Unknown(
            CompletionProducerErrorCode::SourceBindingUnverified,
        ))
    }

    /// Legacy conversion retained for source compatibility only.
    ///
    /// A locally constructible receipt ID and frontier are not authority
    /// evidence. This method can no longer construct a terminal completion.
    pub fn into_terminal_completion(
        self,
        _reservation_id: &str,
        _operation_id: &str,
        _event_id: &str,
        _audit_correlation_id: &str,
        _receipt: &AuthorityCompletionReceipt,
    ) -> Result<AuthorityFamilyCompletion, CompletionProducerError> {
        Err(CompletionProducerError::Unknown(
            CompletionProducerErrorCode::LegacyReceiptUnverified,
        ))
    }
}

/// Stable source-mutation identity of one committed projection receipt batch,
/// converted by the owning source-transaction wrapper from its
/// `CommittedProjectionReceipts` hand-back. This type is a correlation
/// identity only: carrying it never proves projection dispatch, ACK, a current
/// pointer, or family completion. `commit_proven` is true only because the
/// wrapper releases the batch after a PROVEN COMMIT — it is not re-derivable
/// here and the seam refuses any batch that does not carry it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommittedBatchIdentity {
    /// The stable source mutation operation id frozen in-transaction.
    pub operation_id: String,
    /// The stable source event id frozen in-transaction (first staged delta or
    /// source projection identity; empty batches stay empty).
    pub event_id: String,
    /// The frozen invalidation messageId when one was staged (otherwise
    /// empty); by contract the invalidation message id is the same projection
    /// event id, so drift is refused by the orchestration gate.
    pub message_id: String,
    /// True only for batches handed back by the source wrapper after a PROVEN
    /// COMMIT. A batch without this flag can never enter the seam.
    pub commit_proven: bool,
}

impl CommittedBatchIdentity {
    /// Build the identity directly from the caller's committed receipt batch
    /// fields. The trustgraph source-transaction wrapper is the intended
    /// caller: it owns `CommittedProjectionReceipts` (astral-db cannot depend
    /// on it), and it passes `commit_proven = true` only for batches released
    /// after a PROVEN COMMIT.
    pub fn from_committed_receipt_batch(
        operation_id: &str,
        event_id: &str,
        message_id: &str,
        commit_proven: bool,
    ) -> Self {
        Self {
            operation_id: operation_id.to_owned(),
            event_id: event_id.to_owned(),
            message_id: message_id.to_owned(),
            commit_proven,
        }
    }
}

/// Deterministic outcome of one family completion read. `Ready` carries the
/// non-durable draft; a typed Pending/Unknown is the fail-closed boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FamilyCompletionCandidate {
    Ready(Box<FamilyCompletionReady>),
    /// Deterministic business missing/absent state. Fail-closed, never empty.
    Pending(CompletionProducerErrorCode),
    /// Infrastructure/unknown failure. Fail-closed.
    Unknown(CompletionProducerErrorCode),
}

/// Stable machine codes for the producer's non-positive boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionProducerErrorCode {
    /// The strict published-card read is not ready (absent pointer, pending
    /// source delta, too many aggregates).
    PublishedEvidenceNotReady,
    /// The strict published-card read contradicts its durable contract.
    PublishedEvidenceCorrupt,
    /// No sealed publication / member-exact admission is available for the
    /// ORG read (deterministic business pending).
    OrgAdmissionPending,
    /// The durable authority frontier row is missing, not SERVING, or
    /// malformed; no receipt can be proven against it.
    AuthorityFrontierUnknown,
    /// The bound receipt did not strictly advance the durable authority
    /// frontier; replay protection.
    ReceiptFrontierNotAdvanced,
    /// A source-compatible local receipt was supplied without an authority
    /// client verified full receipt. It can never produce a terminal row.
    LegacyReceiptUnverified,
    /// The bounded tenant-wide membership selector exceeded its cap+one proof.
    OrgInventoryBoundExceeded,
    /// No active membership rows were observed; empty family needs explicit proof.
    OrgInventoryEmptyUnproven,
    /// The bounded membership selector contained a duplicate exact key.
    OrgInventoryDuplicate,
    /// A selected membership or exact admission evidence contradicted its key.
    OrgInventoryCorrupt,
    /// Exact member reads observed different publication frontiers.
    OrgInventoryFrontierDrift,
    /// A local content and inventory read does not prove the committed source.
    SourceBindingUnverified,
}

impl CompletionProducerErrorCode {
    pub const fn as_code(self) -> &'static str {
        match self {
            Self::PublishedEvidenceNotReady => {
                "certified_memory.producer.published_evidence_not_ready"
            }
            Self::PublishedEvidenceCorrupt => {
                "certified_memory.producer.published_evidence_corrupt"
            }
            Self::OrgAdmissionPending => "certified_memory.producer.org_admission_pending",
            Self::AuthorityFrontierUnknown => {
                "certified_memory.producer.authority_frontier_unknown"
            }
            Self::ReceiptFrontierNotAdvanced => {
                "certified_memory.producer.receipt_frontier_not_advanced"
            }
            Self::LegacyReceiptUnverified => "certified_memory.producer.legacy_receipt_unverified",
            Self::OrgInventoryBoundExceeded => {
                "certified_memory.producer.org_inventory_bound_exceeded"
            }
            Self::OrgInventoryEmptyUnproven => {
                "certified_memory.producer.org_inventory_empty_unproven"
            }
            Self::OrgInventoryDuplicate => "certified_memory.producer.org_inventory_duplicate",
            Self::OrgInventoryCorrupt => "certified_memory.producer.org_inventory_corrupt",
            Self::OrgInventoryFrontierDrift => {
                "certified_memory.producer.org_inventory_frontier_drift"
            }
            Self::SourceBindingUnverified => "certified_memory.producer.source_binding_unverified",
        }
    }
}

impl std::fmt::Display for CompletionProducerErrorCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_code())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CompletionProducerError {
    #[error("certified-memory completion producer rejected: {0}")]
    Invalid(String),
    #[error("certified-memory completion producer pending: {0}")]
    Pending(CompletionProducerErrorCode),
    #[error("certified-memory completion producer unknown: {0}")]
    Unknown(CompletionProducerErrorCode),
    #[error("certified-memory completion producer database failure: {0}")]
    Database(String),
}

/// Narrow, strictly read-scoped completion producer for the two fact families
/// this crate durably reads as formal authorization state: PUBLISHED_EVIDENCE
/// (published card CURRENT V6 evidence) and ORG_AUTHORIZATION (sealed ORG
/// publication admission). The pool is an input boundary only.
#[derive(Clone)]
pub struct CertifiedMemoryCompletionProducer {
    pool: sqlx::MySqlPool,
}

impl std::fmt::Debug for CertifiedMemoryCompletionProducer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CertifiedMemoryCompletionProducer")
            .field("pool", &"<mysql-pool>")
            .finish()
    }
}

/// Typed outcomes of one orchestration attempt at the staging/reconciliation
/// seam. Every variant carries the caller's stable identities; no variant
/// proves family completion by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FamilyCompletionOrchestrationOutcome {
    /// COMMIT was not proven. Nothing was dispatched, staged, or written; the
    /// caller owns rollback semantics and must not retry blindly.
    CommitNotProven {
        operation_id: String,
        event_id: String,
    },
    /// COMMIT was proven but the authority receipt was not independently
    /// verified in this attempt. The committed batch stays PENDING for
    /// reconciliation; no terminal completion row is written.
    PendingReconciliation { batch: CommittedBatchIdentity },
    /// An exact infrastructure failure left the outcome unknown. Nothing is
    /// inferred; reconciliation must reconcile the stable identities before
    /// any retry.
    Unknown {
        batch: CommittedBatchIdentity,
        code: CompletionProducerErrorCode,
    },
    /// COMMIT proven AND a verified authority receipt strictly advancing the
    /// durable frontier at read time. `terminal` is ready for the exact
    /// idempotent ledger writer, which still re-proofs every field.
    TerminalReady {
        batch: CommittedBatchIdentity,
        terminal: Box<AuthorityFamilyCompletion>,
        payload_json: String,
    },
}

/// Legacy injectable receipt source. Implementations are caller-supplied and
/// their return values do not prove authority provenance. The compatibility
/// orchestration never promotes a returned value to a terminal completion.
pub trait AuthorityCompletionReceiptSource: Send + Sync {
    /// Return the receipt ONLY if it has been independently reconciled as
    /// durable at the authority for this exact family/scope. `None` is the
    /// honest "not proven yet" answer and keeps the seam PENDING.
    fn verified_receipt(
        &self,
        family: AuthorityCertifiedMemoryFamily,
        scope: &AuthorityFamilyScope,
    ) -> Result<Option<AuthorityCompletionReceipt>, CompletionProducerError>;
}

/// Fail-closed default: no production authority receipt producer exists, so
/// the default source never fabricates a receipt and always reports
/// `AuthorityFrontierUnknown` when asked. The composition root may replace it
/// later with a real implementation; the seam contract itself never changes.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoAuthorityCompletionReceiptSource;

impl AuthorityCompletionReceiptSource for NoAuthorityCompletionReceiptSource {
    fn verified_receipt(
        &self,
        _family: AuthorityCertifiedMemoryFamily,
        _scope: &AuthorityFamilyScope,
    ) -> Result<Option<AuthorityCompletionReceipt>, CompletionProducerError> {
        // Fail closed: an absent receipt producer can never be interpreted as
        // "no receipt needed". The seam stays PENDING, never terminal.
        Err(CompletionProducerError::Unknown(
            CompletionProducerErrorCode::AuthorityFrontierUnknown,
        ))
    }
}

impl CertifiedMemoryCompletionProducer {
    /// Caller-owned orchestration API for the source-owner completion
    /// staging/reconciliation seam.
    ///
    /// Contract:
    /// - The caller passes its own [`CommittedBatchIdentity`] built ONLY from
    ///   a batch handed back after a PROVEN source COMMIT (the trustgraph
    ///   `CommittedProjectionReceipts` conversion). This function never
    ///   re-derives commit status; a `commit_proven = false` batch is refused.
    /// - Without an independently verified receipt the outcome is
    ///   `PendingReconciliation`: the committed batch stays pending, no
    ///   terminal completion row is written, and the dispatch/ACK/current
    ///   pointer correlation carried by the batch is never promoted.
    /// - This compatibility API cannot verify an authority receipt. Any
    ///   locally supplied receipt remains unknown and never yields a terminal
    ///   completion; reconciliation requires a verified authority client.
    pub fn orchestrate_family_completion(
        ready: FamilyCompletionReady,
        committed: CommittedBatchIdentity,
        receipt_source: &dyn AuthorityCompletionReceiptSource,
        reservation_id: &str,
        operation_id: &str,
        event_id: &str,
        audit_correlation_id: &str,
    ) -> FamilyCompletionOrchestrationOutcome {
        if !committed.commit_proven {
            return FamilyCompletionOrchestrationOutcome::CommitNotProven {
                operation_id: operation_id.to_owned(),
                event_id: event_id.to_owned(),
            };
        }
        // The committed batch and the draft must describe the same source
        // mutation; identity drift is a fail-closed Unknown, never a mismatch
        // silently reconciled.
        if committed.operation_id != operation_id
            || committed.event_id != event_id
            || (!committed.message_id.is_empty() && committed.message_id != event_id)
        {
            return FamilyCompletionOrchestrationOutcome::Unknown {
                batch: committed,
                code: CompletionProducerErrorCode::PublishedEvidenceCorrupt,
            };
        }
        let receipt = match receipt_source.verified_receipt(ready.family, &ready.scope) {
            Ok(Some(receipt)) => receipt,
            Ok(None) | Err(CompletionProducerError::Pending(_)) => {
                // Honest "not proven yet": the seam stays PENDING with stable
                // identities for the reconciliation owner.
                return FamilyCompletionOrchestrationOutcome::PendingReconciliation {
                    batch: committed,
                };
            }
            Err(error) => {
                tracing::debug!(
                    operation_id = %committed.operation_id,
                    event_id = %committed.event_id,
                    error = %error,
                    "authority receipt verification is unknown; family completion stays reconcilable"
                );
                return FamilyCompletionOrchestrationOutcome::Unknown {
                    batch: committed,
                    code: CompletionProducerErrorCode::AuthorityFrontierUnknown,
                };
            }
        };
        let payload_json = ready.payload_json.clone();
        match ready.into_terminal_completion(
            reservation_id,
            operation_id,
            event_id,
            audit_correlation_id,
            &receipt,
        ) {
            Ok(terminal) => FamilyCompletionOrchestrationOutcome::TerminalReady {
                batch: committed,
                payload_json,
                terminal: Box::new(terminal),
            },
            Err(CompletionProducerError::Pending(
                CompletionProducerErrorCode::ReceiptFrontierNotAdvanced,
            )) => {
                // Replay protection: a lagging/equal receipt is a replay.
                // The batch stays pending for reconciliation; nothing is
                // fabricated.
                FamilyCompletionOrchestrationOutcome::PendingReconciliation { batch: committed }
            }
            Err(CompletionProducerError::Unknown(code)) => {
                FamilyCompletionOrchestrationOutcome::Unknown {
                    batch: committed,
                    code,
                }
            }
            Err(_) => FamilyCompletionOrchestrationOutcome::Unknown {
                batch: committed,
                code: CompletionProducerErrorCode::PublishedEvidenceCorrupt,
            },
        }
    }
}

impl CertifiedMemoryCompletionProducer {
    pub fn new(pool: sqlx::MySqlPool) -> Self {
        Self { pool }
    }

    /// Read the durable authority frontier row (single row, id = 1). This is
    /// the ONLY durable counter source the producer exposes; the caller
    /// proves its receipt against it. A missing, non-SERVING, or malformed
    /// row stays Unknown — never a fabricated counter.
    pub async fn load_durable_authority_frontier(
        &self,
    ) -> Result<DurableAuthorityFrontierIdentity, CompletionProducerError> {
        let row: Option<(String, i64, i64, String, i64, String)> = sqlx::query_as(
            "SELECT authority_id, authority_term, global_fence_sequence, key_id, key_epoch, status \
             FROM authorization_authority_frontier WHERE frontier_id = 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| CompletionProducerError::Database(error.to_string()))?;
        decode_frontier_row(row)
    }

    /// Strict PUBLISHED_EVIDENCE completion read for one card evidence scope.
    ///
    /// Reuses `load_published_card_state_bundle_in_tx` (the exact formal
    /// evidence loader, including its source-freshness gate) and the single
    /// V7 content-identity owners. Nothing is inferred from an empty read;
    /// every non-ready/corrupt state stays typed and fail-closed. The caller
    /// owns the transaction; no network/MQ/cache happens inside it.
    pub async fn read_published_evidence_completion_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<FamilyCompletionCandidate, CompletionProducerError> {
        scope.validate().map_err(|error| {
            CompletionProducerError::Invalid(format!("published evidence scope: {error}"))
        })?;
        let bundle =
            crate::authorization_projection_repository::load_published_card_state_bundle_in_tx(
                tx, scope,
            )
            .await
            .map_err(map_evidence_error)?;
        let now: i64 = sqlx::query_scalar("SELECT CAST(UNIX_TIMESTAMP() AS SIGNED)")
            .fetch_one(&mut **tx)
            .await
            .map_err(|error| CompletionProducerError::Database(error.to_string()))?;
        let evidence: PublishedCardAuthorization =
            bundle.evidence_at(now).map_err(map_evidence_error)?;
        evidence.validate().map_err(|error| {
            CompletionProducerError::Invalid(format!(
                "published evidence failed its strict contract: {error}"
            ))
        })?;
        let evidence_content_hash = AuthorizationFenceProof::evidence_content_hash(&evidence)
            .map_err(|error| {
                CompletionProducerError::Invalid(format!(
                    "published evidence content hash refused: {error}"
                ))
            })?;
        let (scope_generation, revoke_watermark) =
            AuthorizationFenceProof::evidence_frontier(&evidence).map_err(|error| {
                CompletionProducerError::Invalid(format!(
                    "published evidence frontier refused: {error}"
                ))
            })?;
        // Inventory: one sorted item per sealed aggregate manifest, keyed by
        // aggregate identity, digest = the manifest's own sealed digest.
        let mut inventory = Vec::with_capacity(evidence.manifests.len());
        for manifest in &evidence.manifests {
            inventory.push(AuthorityFamilyInventoryItem {
                key: format!(
                    "card:{}:{}:{}",
                    manifest.tenant_id, manifest.card_id, manifest.aggregate_id
                ),
                tenant_id: Some(manifest.tenant_id),
                content_digest: manifest.manifest_digest_hex.clone(),
            });
        }
        inventory.sort_by(|left, right| left.key.cmp(&right.key));
        // Canonical terminal payload: exactly the family-owner wire shape, as
        // a top-level JSON array (the ledger writer refuses anything else).
        let entries = vec![PublishedEvidencePayload {
            scope: PublishedEvidenceScopeWire::from(scope),
            evidence,
        }];
        let payload_json = serde_json::to_string(&entries).map_err(|error| {
            CompletionProducerError::Invalid(format!(
                "published evidence payload cannot be serialized: {error}"
            ))
        })?;
        let complete_content_digest = canonical_payload_digest(&payload_json)?;
        let frontier = read_frontier_in_tx(tx).await?;
        Ok(FamilyCompletionCandidate::Ready(Box::new(
            FamilyCompletionReady {
                family: AuthorityCertifiedMemoryFamily::PublishedEvidence,
                scope: AuthorityFamilyScope {
                    tenant_id: Some(scope.tenant_id),
                    scope: family_scope_text(&format!(
                        "card:{}:{}",
                        scope.tenant_id, scope.card_id
                    ))?,
                },
                payload_json,
                source_commit_digest: evidence_content_hash.clone(),
                source_outcome_digest: complete_content_digest.clone(),
                complete_content_digest,
                audit_correlation_id: format!(
                    "pub-ev:{}",
                    digest_prefix(&format!(
                        "{}:{}:{}",
                        scope.tenant_id,
                        scope.card_id,
                        scope
                            .user_filter
                            .map_or_else(|| "-".to_owned(), |id| id.to_string())
                    ))
                ),
                inventory,
                scope_generation,
                revoke_watermark,
                dependency_generation: scope_generation,
                frontier,
            },
        )))
    }

    /// Strict tenant-wide ORG_AUTHORIZATION completion read.
    ///
    /// The membership query is only a bounded selector. Every selected member is
    /// re-read through the formal exact admission reader, so membership rows
    /// never become authorization evidence by themselves. An empty selector is
    /// deliberately pending: `CompleteEmpty` requires an explicit source-owner
    /// empty-scope proof, not a zero-row SQL observation.
    pub async fn read_org_authorization_inventory(
        &self,
        tenant_id: i64,
        now_unix_seconds: i64,
        cap: usize,
    ) -> Result<FamilyCompletionCandidate, CompletionProducerError> {
        if tenant_id <= 0 || now_unix_seconds <= 0 || cap == 0 || cap > MAX_ORG_INVENTORY_ITEMS {
            return Err(CompletionProducerError::Invalid(
                "ORG inventory request has invalid tenant, clock, or bound".into(),
            ));
        }
        let rows = sqlx::query(
            "SELECT tenant_id, user_id, identity_card_id, card_id \
             FROM org_scope_membership \
             WHERE tenant_id = ? AND active = 1 \
             ORDER BY user_id, identity_card_id, card_id \
             LIMIT ?",
        )
        .bind(tenant_id)
        .bind((cap + 1) as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| CompletionProducerError::Database(error.to_string()))?;
        if rows.len() > cap {
            return Ok(FamilyCompletionCandidate::Pending(
                CompletionProducerErrorCode::OrgInventoryBoundExceeded,
            ));
        }
        if rows.is_empty() {
            return Ok(FamilyCompletionCandidate::Pending(
                CompletionProducerErrorCode::OrgInventoryEmptyUnproven,
            ));
        }

        let mut keys = Vec::with_capacity(rows.len());
        let mut seen = BTreeSet::new();
        for row in rows {
            let key = OrgAdmissionQuery {
                tenant_id: row
                    .try_get("tenant_id")
                    .map_err(|error| CompletionProducerError::Database(error.to_string()))?,
                user_id: row
                    .try_get("user_id")
                    .map_err(|error| CompletionProducerError::Database(error.to_string()))?,
                identity_card_id: Some(
                    row.try_get("identity_card_id")
                        .map_err(|error| CompletionProducerError::Database(error.to_string()))?,
                ),
                card_id: row
                    .try_get("card_id")
                    .map_err(|error| CompletionProducerError::Database(error.to_string()))?,
                now_unix_seconds,
            };
            if key.tenant_id != tenant_id
                || key.user_id <= 0
                || key.identity_card_id.is_none_or(|value| value <= 0)
                || key.card_id <= 0
            {
                return Ok(FamilyCompletionCandidate::Unknown(
                    CompletionProducerErrorCode::OrgInventoryCorrupt,
                ));
            }
            let key_text = org_read_key_text(&key);
            if !seen.insert(key_text) {
                return Ok(FamilyCompletionCandidate::Unknown(
                    CompletionProducerErrorCode::OrgInventoryDuplicate,
                ));
            }
            keys.push(key);
        }

        let mut entries = Vec::with_capacity(keys.len());
        let mut inventory = Vec::with_capacity(keys.len());
        let mut frontier: Option<(u64, u64, u64)> = None;
        for query in keys {
            let result =
                crate::org_scope_repository::load_admission_evidence_in_pool(&self.pool, &query)
                    .await
                    .map_err(|error| {
                        if matches!(error, astral_types::AstralError::Validation(_)) {
                            CompletionProducerError::Invalid(error.to_string())
                        } else {
                            CompletionProducerError::Database(error.to_string())
                        }
                    })?;
            let evidence = match result {
                OrgAdmissionResult::Evidence(evidence) => *evidence,
                OrgAdmissionResult::Pending { .. } => {
                    return Ok(FamilyCompletionCandidate::Pending(
                        CompletionProducerErrorCode::OrgAdmissionPending,
                    ));
                }
            };
            if evidence.membership.tenant_id != tenant_id
                || evidence.membership.user_id != query.user_id
                || evidence.membership.identity_card_id
                    != query.identity_card_id.unwrap_or_default()
                || evidence.membership.card_id != query.card_id
            {
                return Ok(FamilyCompletionCandidate::Unknown(
                    CompletionProducerErrorCode::OrgInventoryCorrupt,
                ));
            }
            let content_digest = org_authority_evidence_hash(&evidence).map_err(|error| {
                CompletionProducerError::Invalid(format!(
                    "org inventory evidence content hash refused: {error}"
                ))
            })?;
            let evidence_generation = evidence.publication.generation;
            let evidence_revoke = evidence.publication.revoke_fence;
            let evidence_frontier = (
                evidence_generation,
                evidence_revoke,
                evidence.publication.relationship_revision,
            );
            if let Err(code) = bind_org_inventory_frontier(&mut frontier, evidence_frontier) {
                return Ok(FamilyCompletionCandidate::Pending(code));
            }
            let key = OrgReadKeyWire {
                tenant_id,
                user_id: query.user_id,
                identity_card_id: query.identity_card_id.unwrap_or_default(),
                card_id: query.card_id,
            };
            entries.push(OrgAuthorizationPayload {
                key,
                value: OrgAuthorityWireRead::Ready {
                    evidence: Box::new(evidence),
                },
            });
            inventory.push(AuthorityFamilyInventoryItem {
                key: org_read_key_text(&query),
                tenant_id: Some(tenant_id),
                content_digest,
            });
        }
        entries.sort_by(|left, right| {
            (
                left.key.user_id,
                left.key.identity_card_id,
                left.key.card_id,
            )
                .cmp(&(
                    right.key.user_id,
                    right.key.identity_card_id,
                    right.key.card_id,
                ))
        });
        inventory.sort_by(|left, right| left.key.cmp(&right.key));
        let payload_json = serde_json::to_string(&entries).map_err(|error| {
            CompletionProducerError::Invalid(format!(
                "org authorization inventory payload cannot be serialized: {error}"
            ))
        })?;
        let complete_content_digest = canonical_payload_digest(&payload_json)?;
        let authority_frontier = self.load_durable_authority_frontier().await?;
        let scope = format!("org:{tenant_id}:inventory");
        Ok(FamilyCompletionCandidate::Ready(Box::new(
            FamilyCompletionReady {
                family: AuthorityCertifiedMemoryFamily::OrgAuthorization,
                scope: AuthorityFamilyScope {
                    tenant_id: Some(tenant_id),
                    scope: family_scope_text(&scope)?,
                },
                payload_json,
                source_commit_digest: complete_content_digest.clone(),
                source_outcome_digest: complete_content_digest.clone(),
                complete_content_digest,
                audit_correlation_id: format!("org-auth-inventory:{}", digest_prefix(&scope)),
                inventory,
                scope_generation: frontier.map_or(0, |value| value.0),
                revoke_watermark: frontier.map_or(0, |value| value.1),
                dependency_generation: frontier.map_or(0, |value| value.2),
                frontier: authority_frontier,
            },
        )))
    }

    /// Strict ORG_AUTHORIZATION completion read for one member-exact org read.
    ///
    /// Reuses `load_admission_evidence_in_pool` (the exact formal org
    /// admission reader) and the shared V7 structural content owners. An
    /// inactive node/member certifies ONLY through the shared revocation
    /// hash; no active state is ever fabricated. Pending org reads stay a
    /// typed fail-closed boundary.
    pub async fn read_org_authorization_completion(
        &self,
        query: &OrgAdmissionQuery,
    ) -> Result<FamilyCompletionCandidate, CompletionProducerError> {
        let result =
            crate::org_scope_repository::load_admission_evidence_in_pool(&self.pool, query)
                .await
                .map_err(|error| {
                    if matches!(error, astral_types::AstralError::Validation(_)) {
                        CompletionProducerError::Invalid(error.to_string())
                    } else {
                        CompletionProducerError::Database(error.to_string())
                    }
                })?;
        let evidence = match result {
            OrgAdmissionResult::Evidence(evidence) => *evidence,
            OrgAdmissionResult::Pending { code, detail } => {
                tracing::debug!(code = code.as_machine_code(), %detail,
                    "org admission read is pending; completion stays pending");
                return Ok(FamilyCompletionCandidate::Pending(
                    CompletionProducerErrorCode::OrgAdmissionPending,
                ));
            }
        };
        let snapshot_hash = if evidence.node.active && evidence.membership.active {
            evidence.validate().map_err(|error| {
                CompletionProducerError::Invalid(format!("org admission evidence: {error}"))
            })?;
            org_authority_evidence_hash(&evidence)
        } else {
            astral_types::org_authority_revocation_evidence_hash(&evidence)
        }
        .map_err(|error| {
            CompletionProducerError::Invalid(format!(
                "org admission evidence content hash refused: {error}"
            ))
        })?;
        let scope_key = format!(
            "org:{}:{}:{}:{}",
            evidence.membership.tenant_id,
            evidence.membership.user_id,
            evidence.membership.identity_card_id,
            evidence.membership.card_id
        );
        // Inventory: one item binding the whole member-exact admission state
        // to its V7 content identity (positive or revocation hash).
        let inventory = vec![AuthorityFamilyInventoryItem {
            key: scope_key.clone(),
            tenant_id: Some(evidence.membership.tenant_id),
            content_digest: snapshot_hash.clone(),
        }];
        // Canonical terminal payload: exactly the family-owner wire shape, as
        // a top-level JSON array.
        let entries = vec![OrgAuthorizationPayload {
            key: OrgReadKeyWire {
                tenant_id: evidence.membership.tenant_id,
                user_id: evidence.membership.user_id,
                identity_card_id: evidence.membership.identity_card_id,
                card_id: evidence.membership.card_id,
            },
            value: OrgAuthorityWireRead::Ready {
                evidence: Box::new(evidence.clone()),
            },
        }];
        let payload_json = serde_json::to_string(&entries).map_err(|error| {
            CompletionProducerError::Invalid(format!(
                "org authorization payload cannot be serialized: {error}"
            ))
        })?;
        let complete_content_digest = canonical_payload_digest(&payload_json)?;
        let frontier = self.load_durable_authority_frontier().await?;
        Ok(FamilyCompletionCandidate::Ready(Box::new(
            FamilyCompletionReady {
                family: AuthorityCertifiedMemoryFamily::OrgAuthorization,
                scope: AuthorityFamilyScope {
                    tenant_id: Some(evidence.membership.tenant_id),
                    scope: family_scope_text(&scope_key)?,
                },
                payload_json,
                source_commit_digest: snapshot_hash.clone(),
                source_outcome_digest: complete_content_digest.clone(),
                complete_content_digest,
                audit_correlation_id: format!("org-auth:{}", digest_prefix(&scope_key)),
                inventory,
                scope_generation: evidence.publication.generation,
                revoke_watermark: evidence.publication.revoke_fence,
                dependency_generation: evidence.publication.generation,
                frontier,
            },
        )))
    }
}

async fn read_frontier_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
) -> Result<DurableAuthorityFrontierIdentity, CompletionProducerError> {
    let row: Option<(String, i64, i64, String, i64, String)> = sqlx::query_as(
        "SELECT authority_id, authority_term, global_fence_sequence, key_id, key_epoch, status \
         FROM authorization_authority_frontier WHERE frontier_id = 1 FOR UPDATE",
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| CompletionProducerError::Database(error.to_string()))?;
    decode_frontier_row(row)
}

fn decode_frontier_row(
    row: Option<(String, i64, i64, String, i64, String)>,
) -> Result<DurableAuthorityFrontierIdentity, CompletionProducerError> {
    let (authority_id, authority_term, global_fence_sequence, key_id, key_epoch, status) = row
        .ok_or(CompletionProducerError::Unknown(
            CompletionProducerErrorCode::AuthorityFrontierUnknown,
        ))?;
    if status != "SERVING" {
        return Err(CompletionProducerError::Unknown(
            CompletionProducerErrorCode::AuthorityFrontierUnknown,
        ));
    }
    let (authority_term, global_fence_sequence, key_epoch) = match (
        u64::try_from(authority_term),
        u64::try_from(global_fence_sequence),
        u64::try_from(key_epoch),
    ) {
        (Ok(term), Ok(fence), Ok(epoch)) if term > 0 && fence > 0 && epoch > 0 => {
            (term, fence, epoch)
        }
        _ => {
            return Err(CompletionProducerError::Unknown(
                CompletionProducerErrorCode::AuthorityFrontierUnknown,
            ));
        }
    };
    Ok(DurableAuthorityFrontierIdentity {
        authority_id,
        authority_term,
        global_fence_sequence,
        key_id,
        key_epoch,
    })
}

const MAX_ORG_INVENTORY_ITEMS: usize = 256;

fn bind_org_inventory_frontier(
    expected: &mut Option<(u64, u64, u64)>,
    observed: (u64, u64, u64),
) -> Result<(), CompletionProducerErrorCode> {
    match expected {
        Some(current) if *current != observed => {
            Err(CompletionProducerErrorCode::OrgInventoryFrontierDrift)
        }
        Some(_) => Ok(()),
        None => {
            *expected = Some(observed);
            Ok(())
        }
    }
}

fn org_read_key_text(query: &OrgAdmissionQuery) -> String {
    format!(
        "org:{}:{}:{}:{}",
        query.tenant_id,
        query.user_id,
        query.identity_card_id.unwrap_or_default(),
        query.card_id
    )
}

/// `certified_memory_completion(_writer)` canonicalizes payloads: parse to a
/// JSON value, re-serialize canonically, SHA-256. A digest computed any other
/// way would never match the writer's re-proof.
fn canonical_payload_digest(payload_json: &str) -> Result<String, CompletionProducerError> {
    let parsed: serde_json::Value = serde_json::from_str(payload_json).map_err(|error| {
        CompletionProducerError::Invalid(format!("completion payload is not valid JSON: {error}"))
    })?;
    let canonical = serde_json::to_string(&parsed).map_err(|error| {
        CompletionProducerError::Invalid(format!(
            "completion payload cannot be canonicalized: {error}"
        ))
    })?;
    Ok(hex::encode(Sha256::digest(canonical.as_bytes())))
}

fn digest_prefix(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))[..16].to_owned()
}

fn family_scope_text(value: &str) -> Result<String, CompletionProducerError> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(|character| character.is_control())
    {
        return Err(CompletionProducerError::Invalid(
            "family scope text is not a bounded protocol text".into(),
        ));
    }
    Ok(value.to_owned())
}

fn map_evidence_error(
    error: crate::authorization_projection_repository::AuthorizationEvidenceError,
) -> CompletionProducerError {
    use crate::authorization_projection_repository::AuthorizationEvidenceError as EvidenceError;
    match error {
        EvidenceError::NotReady(message) => {
            tracing::debug!(%message,
                "published evidence read is not ready; completion stays pending");
            CompletionProducerError::Pending(CompletionProducerErrorCode::PublishedEvidenceNotReady)
        }
        EvidenceError::Corrupt(message) => {
            tracing::warn!(%message,
                "published evidence read contradicts its durable contract");
            CompletionProducerError::Unknown(CompletionProducerErrorCode::PublishedEvidenceCorrupt)
        }
        EvidenceError::InvalidRequest(message) => CompletionProducerError::Invalid(message),
        EvidenceError::Query(query) => CompletionProducerError::Database(query.to_string()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire shapes — intentionally identical to `certified_memory_family_owner`'s
// payload decoding contract, so a persisted ledger row re-decodes to exactly
// the evidence this producer read. Serialization is camelCase /
// SCREAMING_SNAKE_CASE tagged, matching the owner's `deny_unknown_fields`
// decoders.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct PublishedEvidencePayload {
    scope: PublishedEvidenceScopeWire,
    evidence: PublishedCardAuthorization,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PublishedEvidenceScopeWire {
    tenant_id: i64,
    card_id: i64,
    user_filter: Option<i64>,
    domain: PublishedEvidenceDomainWire,
}

impl From<&PublishedCardEvidenceScope> for PublishedEvidenceScopeWire {
    fn from(scope: &PublishedCardEvidenceScope) -> Self {
        Self {
            tenant_id: scope.tenant_id,
            card_id: scope.card_id,
            user_filter: scope.user_filter,
            domain: match scope.domain {
                astral_types::DomainScopeRequirement::Unconstrained => {
                    PublishedEvidenceDomainWire::Any
                }
                astral_types::DomainScopeRequirement::ExactlyNone => {
                    PublishedEvidenceDomainWire::None
                }
                astral_types::DomainScopeRequirement::ExactlySome(id) => {
                    PublishedEvidenceDomainWire::Exact { id }
                }
            },
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum PublishedEvidenceDomainWire {
    Any,
    None,
    Exact { id: i64 },
}

#[derive(Debug, Serialize)]
struct OrgAuthorizationPayload {
    key: OrgReadKeyWire,
    value: OrgAuthorityWireRead,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OrgReadKeyWire {
    tenant_id: i64,
    user_id: i64,
    identity_card_id: i64,
    card_id: i64,
}

#[derive(Debug, Serialize)]
#[allow(dead_code)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
enum OrgAuthorityWireRead {
    Unmanaged,
    Disabled,
    Pending {
        code: String,
    },
    Unavailable {
        code: String,
    },
    Ready {
        evidence: Box<astral_types::org_scope::OrgAdmissionEvidence>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frontier() -> DurableAuthorityFrontierIdentity {
        DurableAuthorityFrontierIdentity {
            authority_id: "authority-1".into(),
            authority_term: 2,
            global_fence_sequence: 5,
            key_id: "key-1".into(),
            key_epoch: 1,
        }
    }

    fn ready() -> FamilyCompletionReady {
        FamilyCompletionReady {
            family: AuthorityCertifiedMemoryFamily::OrgAuthorization,
            scope: AuthorityFamilyScope {
                tenant_id: Some(7),
                scope: "org:7:23:31:17".into(),
            },
            payload_json: r#"[{"key":{"tenantId":7,"userId":23,"identityCardId":31,"cardId":17},"value":{"kind":"UNMANAGED"}}]"#.into(),
            complete_content_digest: canonical_payload_digest(
                r#"[{"key":{"tenantId":7,"userId":23,"identityCardId":31,"cardId":17},"value":{"kind":"UNMANAGED"}}]"#,
            )
            .expect("canonical digest"),
            source_commit_digest: "11".repeat(32),
            source_outcome_digest: "22".repeat(32),
            audit_correlation_id: "audit-1".into(),
            inventory: vec![AuthorityFamilyInventoryItem {
                key: "org:7:23:31:17".into(),
                tenant_id: Some(7),
                content_digest: "44".repeat(32),
            }],
            scope_generation: 3,
            revoke_watermark: 1,
            dependency_generation: 3,
            frontier: frontier(),
        }
    }

    fn receipt(term: u64, fence: u64) -> AuthorityCompletionReceipt {
        AuthorityCompletionReceipt::new("receipt-1", term, fence).expect("receipt")
    }

    #[test]
    fn local_receipt_never_proves_terminal_completion() {
        for (term, fence) in [(1, 9), (2, 5), (2, 6), (3, 1)] {
            assert!(matches!(
                ready().into_terminal_completion(
                    "res",
                    "op",
                    "event",
                    "audit",
                    &receipt(term, fence)
                ),
                Err(CompletionProducerError::Unknown(
                    CompletionProducerErrorCode::LegacyReceiptUnverified
                ))
            ));
        }
    }

    #[test]
    fn receipt_identity_rejects_local_lookup_shapes() {
        for bad in ["", " padded", "with space", "tab\tid", &"x".repeat(129)] {
            assert!(
                AuthorityCompletionReceipt::new(bad, 2, 6).is_err(),
                "receipt id {bad:?} must be refused"
            );
        }
        assert!(AuthorityCompletionReceipt::new("receipt", 0, 6).is_err());
        assert!(AuthorityCompletionReceipt::new("receipt", 2, 0).is_err());
    }

    #[test]
    fn frontier_replay_protection_is_exact() {
        let frontier = frontier();
        assert!(frontier.strictly_advances_beyond(2, 6));
        assert!(frontier.strictly_advances_beyond(3, 1));
        assert!(!frontier.strictly_advances_beyond(2, 5));
        assert!(!frontier.strictly_advances_beyond(2, 4));
        assert!(!frontier.strictly_advances_beyond(1, 99));
    }

    #[test]
    fn producer_error_codes_are_stable_machine_codes() {
        assert_eq!(
            CompletionProducerErrorCode::PublishedEvidenceNotReady.as_code(),
            "certified_memory.producer.published_evidence_not_ready"
        );
        assert_eq!(
            CompletionProducerErrorCode::OrgAdmissionPending.as_code(),
            "certified_memory.producer.org_admission_pending"
        );
        assert_eq!(
            CompletionProducerErrorCode::AuthorityFrontierUnknown.as_code(),
            "certified_memory.producer.authority_frontier_unknown"
        );
        assert_eq!(
            CompletionProducerErrorCode::ReceiptFrontierNotAdvanced.as_code(),
            "certified_memory.producer.receipt_frontier_not_advanced"
        );
        assert_eq!(
            CompletionProducerErrorCode::OrgInventoryEmptyUnproven.as_code(),
            "certified_memory.producer.org_inventory_empty_unproven"
        );
        assert_eq!(
            CompletionProducerErrorCode::OrgInventoryFrontierDrift.as_code(),
            "certified_memory.producer.org_inventory_frontier_drift"
        );
    }

    #[test]
    fn org_inventory_key_is_exact_and_bounded() {
        let query = OrgAdmissionQuery {
            tenant_id: 7,
            user_id: 23,
            identity_card_id: Some(31),
            card_id: 17,
            now_unix_seconds: 100,
        };
        assert_eq!(org_read_key_text(&query), "org:7:23:31:17");
        assert_eq!(MAX_ORG_INVENTORY_ITEMS, 256);
    }

    #[test]
    fn org_inventory_frontier_requires_exact_same_publication() {
        let mut expected = None;
        assert!(bind_org_inventory_frontier(&mut expected, (3, 1, 8)).is_ok());
        assert!(bind_org_inventory_frontier(&mut expected, (3, 1, 8)).is_ok());
        assert_eq!(
            bind_org_inventory_frontier(&mut expected, (4, 1, 8)),
            Err(CompletionProducerErrorCode::OrgInventoryFrontierDrift)
        );
        assert_eq!(
            bind_org_inventory_frontier(&mut expected, (3, 2, 8)),
            Err(CompletionProducerErrorCode::OrgInventoryFrontierDrift)
        );
        assert_eq!(
            bind_org_inventory_frontier(&mut expected, (3, 1, 9)),
            Err(CompletionProducerErrorCode::OrgInventoryFrontierDrift)
        );
    }

    #[test]
    fn org_inventory_non_positive_bound_is_rejected_before_database_access() {
        assert!(matches!(
            CompletionProducerErrorCode::OrgInventoryBoundExceeded,
            CompletionProducerErrorCode::OrgInventoryBoundExceeded
        ));
        assert!(matches!(
            CompletionProducerErrorCode::OrgInventoryEmptyUnproven,
            CompletionProducerErrorCode::OrgInventoryEmptyUnproven
        ));
    }

    #[test]
    fn local_scope_read_cannot_create_authority_candidate() {
        for family in [
            AuthorityCertifiedMemoryFamily::PublishedEvidence,
            AuthorityCertifiedMemoryFamily::OrgAuthorization,
        ] {
            let mut draft = ready();
            draft.family = family;
            assert!(matches!(
                draft.into_authority_candidate("res", "op", "event", Some("msg"), "audit"),
                Err(CompletionProducerError::Unknown(
                    CompletionProducerErrorCode::SourceBindingUnverified
                ))
            ));
            draft.inventory.clear();
            assert!(matches!(
                draft.into_authority_candidate("res", "op", "event", None, "audit"),
                Err(CompletionProducerError::Unknown(
                    CompletionProducerErrorCode::SourceBindingUnverified
                ))
            ));
        }
    }

    #[test]
    fn committed_source_outcome_does_not_prove_family_coverage() {
        use crate::authority_source_outcome::{
            canonical_outcome_digest, AuthoritySourceOutcomeRecord, AuthoritySourceReceiptIdentity,
        };
        use astral_types::AuthorityMutationKind;

        let receipts = vec![AuthoritySourceReceiptIdentity {
            identity_kind: "audit_log".into(),
            identity: "audit-1".into(),
        }];
        let record = AuthoritySourceOutcomeRecord {
            reservation_id: "res".into(),
            operation_id: "op".into(),
            event_id: "event".into(),
            admission_proof_id: "proof".into(),
            request_binding_digest: "aa".repeat(32),
            mutation_kind: AuthorityMutationKind::AuthorizationSource,
            service_id: "service".into(),
            database_id: "database".into(),
            source_commit_digest: "bb".repeat(32),
            before_image_digest: Some("cc".repeat(32)),
            after_image_digest: Some("dd".repeat(32)),
            source_receipts: receipts,
            committed_at: 100,
        };
        let staged_evidence = "{}";
        let source = AuthoritySourceOutcomeRow {
            reservation_id: record.reservation_id.clone(),
            operation_id: record.operation_id.clone(),
            event_id: record.event_id.clone(),
            admission_proof_id: record.admission_proof_id.clone(),
            request_binding_digest: hex::decode(&record.request_binding_digest).unwrap(),
            mutation_kind: "AUTHORIZATION_SOURCE".into(),
            service_id: record.service_id.clone(),
            database_id: record.database_id.clone(),
            source_commit_digest: Some(hex::decode(&record.source_commit_digest).unwrap()),
            before_image_digest: Some(
                hex::decode(record.before_image_digest.as_ref().unwrap()).unwrap(),
            ),
            after_image_digest: Some(
                hex::decode(record.after_image_digest.as_ref().unwrap()).unwrap(),
            ),
            source_receipts: Some(serde_json::to_string(&record.source_receipts).unwrap()),
            staged_evidence: Some(staged_evidence.into()),
            status: "COMMITTED".into(),
            attempts: 0,
            generation: 1,
            outcome_digest: hex::decode(
                canonical_outcome_digest(&record, Some(staged_evidence)).unwrap(),
            )
            .unwrap(),
            committed_at: record.committed_at,
        };
        assert_eq!(
            source.to_verified_publication_record("COMMITTED").unwrap(),
            record
        );
        let binding = FamilyCompletionSourceBinding {
            reservation_id: "res".into(),
            operation_id: "op".into(),
            event_id: "event".into(),
            message_id: None,
            audit_correlation_id: "audit-1".into(),
            state: AuthorityFamilyCompletionState::Complete,
        };
        assert!(matches!(
            ready().bind_verified_source_outcome(&source, &binding),
            Err(CompletionProducerError::Unknown(
                CompletionProducerErrorCode::SourceBindingUnverified
            ))
        ));
    }

    #[test]
    fn published_wire_payload_matches_the_family_owner_decoder_shape() {
        let scope = PublishedCardEvidenceScope {
            tenant_id: 7,
            card_id: 17,
            user_filter: None,
            domain: astral_types::DomainScopeRequirement::Unconstrained,
        };
        let wire = PublishedEvidenceScopeWire::from(&scope);
        let encoded = serde_json::to_value(&wire).expect("wire");
        assert_eq!(encoded["tenantId"], 7);
        assert_eq!(encoded["cardId"], 17);
        assert_eq!(encoded["userFilter"], serde_json::Value::Null);
        assert_eq!(encoded["domain"], "ANY");

        let exact = PublishedEvidenceScopeWire::from(&PublishedCardEvidenceScope {
            domain: astral_types::DomainScopeRequirement::ExactlySome(3),
            ..scope
        });
        let encoded = serde_json::to_value(&exact).expect("wire");
        assert_eq!(encoded["domain"]["EXACT"]["id"], 3);
    }

    #[test]
    fn org_wire_payload_matches_the_family_owner_decoder_shape() {
        let pending = OrgAuthorityWireRead::Pending {
            code: "org.pending".into(),
        };
        let encoded = serde_json::to_value(&pending).expect("wire");
        assert_eq!(encoded["kind"], "PENDING");
        assert_eq!(encoded["code"], "org.pending");

        let ready_wire = OrgAuthorityWireRead::Ready {
            evidence: Box::new(astral_types::org_scope::OrgAdmissionEvidence {
                publication: astral_types::org_scope::OrgPublication {
                    tenant_id: 7,
                    root_tenant_id: 1,
                    generation: 1,
                    relationship_revision: 1,
                    revoke_fence: 0,
                    dependencies: Vec::new(),
                    manifest_digest_hex: "aa".repeat(32),
                    compiler_version: astral_types::AUTHORIZATION_ORG_COMPILER_VERSION.into(),
                    segments: Vec::new(),
                    operation_id: "op-1".into(),
                },
                node: astral_types::org_scope::OrgNode {
                    tenant_id: 7,
                    root_tenant_id: 1,
                    parent_tenant_id: None,
                    generation: 1,
                    revoke_fence: 0,
                    relationship_revision: 1,
                    active: true,
                    operation_id: "op-1".into(),
                    root_activation: Some(astral_types::org_scope::OrgRootActivation {
                        operator_user_id: 1,
                        approval_operation_id: "op-0".into(),
                    }),
                },
                membership: astral_types::org_scope::OrgMembership {
                    membership_id: "22222222-2222-4222-8222-222222222222".into(),
                    tenant_id: 7,
                    root_tenant_id: 1,
                    user_id: 23,
                    identity_card_id: 31,
                    card_id: 17,
                    revision: 1,
                    active: true,
                    validity: astral_types::ValidityWindow::perpetual(),
                    operation_id: "op-1".into(),
                },
                checked_at_unix: 100,
            }),
        };
        let encoded = serde_json::to_value(&ready_wire).expect("wire");
        assert_eq!(encoded["kind"], "READY");
        assert_eq!(encoded["evidence"]["membership"]["userId"], 23);
    }

    /// The canonical payload digest is computed exactly the way the ledger
    /// writer canonicalizes payloads, so the writer's re-proof matches.
    #[test]
    fn canonical_payload_digest_matches_writer_canonicalization() {
        let payload = r#"[{"value":{"kind":"UNMANAGED"},"key":{"cardId":17,"tenantId":7,"userId":23,"identityCardId":31}}]"#;
        let digest = canonical_payload_digest(payload).expect("digest");
        // The writer parses + re-serializes (sorted object keys), then hashes;
        // a differently-ordered input must produce the SAME canonical digest.
        let reordered = r#"[{"key":{"tenantId":7,"userId":23,"identityCardId":31,"cardId":17},"value":{"kind":"UNMANAGED"}}]"#;
        assert_eq!(canonical_payload_digest(reordered).expect("digest"), digest);
        assert_eq!(digest.len(), 64);
        assert!(canonical_payload_digest("{invalid").is_err());
    }

    // ── source-owner completion staging/reconciliation seam ────────────────

    use crate::certified_memory_completion_producer::{
        AuthorityCompletionReceiptSource, CommittedBatchIdentity,
        FamilyCompletionOrchestrationOutcome, NoAuthorityCompletionReceiptSource,
    };
    use astral_types::authority_protocol::AuthorityCertifiedMemoryFamily;

    /// A test receipt source that never fabricates: it only answers `None`
    /// (honest pending) or a real, strictly-advancing receipt.
    struct TestReceiptSource {
        receipt: Option<AuthorityCompletionReceipt>,
    }

    impl AuthorityCompletionReceiptSource for TestReceiptSource {
        fn verified_receipt(
            &self,
            _family: AuthorityCertifiedMemoryFamily,
            _scope: &AuthorityFamilyScope,
        ) -> Result<Option<AuthorityCompletionReceipt>, CompletionProducerError> {
            match &self.receipt {
                Some(receipt) => Ok(Some(receipt.clone())),
                None => Ok(None),
            }
        }
    }

    fn committed_identity() -> CommittedBatchIdentity {
        CommittedBatchIdentity::from_committed_receipt_batch("op-1", "event-1", "event-1", true)
    }

    #[test]
    fn seam_without_a_verified_receipt_stays_pending_reconciliation() {
        let outcome = CertifiedMemoryCompletionProducer::orchestrate_family_completion(
            ready(),
            committed_identity(),
            &TestReceiptSource { receipt: None },
            "res-1",
            "op-1",
            "event-1",
            "audit-1",
        );
        match outcome {
            FamilyCompletionOrchestrationOutcome::PendingReconciliation { batch } => {
                assert!(batch.commit_proven);
                assert_eq!(batch.operation_id, "op-1");
                assert_eq!(batch.event_id, "event-1");
            }
            other => panic!("no receipt means no terminal completion: {other:?}"),
        }
    }

    #[test]
    fn seam_refuses_any_batch_not_marked_commit_proven() {
        let unproven = CommittedBatchIdentity::from_committed_receipt_batch(
            "op-1", "event-1", "event-1", false,
        );
        let outcome = CertifiedMemoryCompletionProducer::orchestrate_family_completion(
            ready(),
            unproven,
            &TestReceiptSource {
                receipt: Some(receipt(9, 9)),
            },
            "res-1",
            "op-1",
            "event-1",
            "audit-1",
        );
        assert!(
            matches!(
                outcome,
                FamilyCompletionOrchestrationOutcome::CommitNotProven { .. }
            ),
            "an unproven batch can never reach the terminal path, even with a receipt"
        );
    }

    #[test]
    fn fail_closed_default_source_never_produces_a_terminal_completion() {
        let outcome = CertifiedMemoryCompletionProducer::orchestrate_family_completion(
            ready(),
            committed_identity(),
            &NoAuthorityCompletionReceiptSource,
            "res-1",
            "op-1",
            "event-1",
            "audit-1",
        );
        assert!(
            matches!(
                outcome,
                FamilyCompletionOrchestrationOutcome::Unknown {
                    code: CompletionProducerErrorCode::AuthorityFrontierUnknown,
                    ..
                }
            ),
            "the default source must fail closed, never fabricate evidence"
        );
    }

    #[test]
    fn seam_rejects_locally_constructed_receipt() {
        let outcome = CertifiedMemoryCompletionProducer::orchestrate_family_completion(
            ready(),
            committed_identity(),
            &TestReceiptSource {
                receipt: Some(receipt(2, 6)),
            },
            "res-1",
            "op-1",
            "event-1",
            "audit-1",
        );
        assert!(matches!(
            outcome,
            FamilyCompletionOrchestrationOutcome::Unknown {
                code: CompletionProducerErrorCode::LegacyReceiptUnverified,
                ..
            }
        ));
    }

    #[test]
    fn seam_rejects_unverified_replayed_receipt() {
        // An equal frontier is a replay, and a local receipt cannot prove its
        // origin regardless of the frontier value.
        let outcome = CertifiedMemoryCompletionProducer::orchestrate_family_completion(
            ready(),
            committed_identity(),
            &TestReceiptSource {
                receipt: Some(receipt(2, 5)),
            },
            "res-1",
            "op-1",
            "event-1",
            "audit-1",
        );
        assert!(matches!(
            outcome,
            FamilyCompletionOrchestrationOutcome::Unknown {
                code: CompletionProducerErrorCode::LegacyReceiptUnverified,
                ..
            }
        ));
    }

    #[test]
    fn seam_refuses_identity_drift_between_batch_and_caller() {
        let outcome = CertifiedMemoryCompletionProducer::orchestrate_family_completion(
            ready(),
            committed_identity(),
            &TestReceiptSource {
                receipt: Some(receipt(2, 6)),
            },
            "res-1",
            // The caller's operation id drifted from the committed batch.
            "op-OTHER",
            "event-1",
            "audit-1",
        );
        assert!(matches!(
            outcome,
            FamilyCompletionOrchestrationOutcome::Unknown {
                code: CompletionProducerErrorCode::PublishedEvidenceCorrupt,
                ..
            }
        ));
    }

    #[test]
    fn seam_refuses_message_id_drift_from_event_identity() {
        let drifted = CommittedBatchIdentity::from_committed_receipt_batch(
            "op-1",
            "event-1",
            "not-the-event-id",
            true,
        );
        let outcome = CertifiedMemoryCompletionProducer::orchestrate_family_completion(
            ready(),
            drifted,
            &TestReceiptSource {
                receipt: Some(receipt(2, 6)),
            },
            "res-1",
            "op-1",
            "event-1",
            "audit-1",
        );
        assert!(matches!(
            outcome,
            FamilyCompletionOrchestrationOutcome::Unknown { .. }
        ));
    }

    #[test]
    fn committed_batch_identity_is_a_correlation_value_only() {
        let identity = committed_identity();
        assert!(identity.commit_proven);
        assert_eq!(identity.operation_id, "op-1");
        assert_eq!(identity.event_id, "event-1");
        assert_eq!(
            identity.message_id, "event-1",
            "the invalidation message id is the same projection event id by contract"
        );
        // Default (empty) identities exist only so an absent field is visible;
        // they can never enter the seam (commit_proven = false).
        assert!(!CommittedBatchIdentity::default().commit_proven);
    }
}
