//! Short, caller-owned persistence boundary for reconciled CertifiedMemory completions.
//!
//! A terminal row requires verified authority provenance, an exact committed
//! source outcome, its durable audit receipt, and independently verifiable
//! source-owned family completeness. No durable completeness contract is
//! currently available, so verified and legacy write entry points fail closed.
//! Historical rows remain available through the separate read path.

use astral_authority::client::{AuthorityClient, VerifiedFamilyReceipt};
use astral_types::authority_protocol::{
    AuthorityCertifiedMemoryFamily, AuthorityFamilyCompletion, AuthorityFamilyScope,
};
use astral_types::AuthorityMutationKind;
use sha2::{Digest, Sha256};
use sqlx::{MySql, Transaction};
use thiserror::Error;
use time::OffsetDateTime;

use crate::authority_source_outcome::AuthoritySourceOutcomeRow;
use crate::certified_memory_completion::{
    CertifiedMemoryCompletionError, CertifiedMemoryCompletionRecord, CertifiedMemoryCompletionRow,
};
use crate::certified_memory_family_owner::decode_certified_memory_payload;
use crate::certified_memory_materializer::CertifiedMemoryMaterializerError;

const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

/// A terminal completion whose authority provenance was verified by the
/// composition-root client. The receipt is opaque by design: callers cannot
/// construct this value or replace its candidate/frontier/trust-root evidence.
#[derive(Debug, Clone)]
pub struct VerifiedCertifiedMemoryCompletionWriteRequest {
    authority_receipt: VerifiedFamilyReceipt,
    payload_json: String,
}

impl VerifiedCertifiedMemoryCompletionWriteRequest {
    /// Bind the receipt to the exact composition-root client before any SQL is
    /// touched. `VerifiedFamilyReceipt::verified_by` is an in-process identity
    /// check; visible client configuration is not accepted as a substitute.
    pub fn new(
        client: &AuthorityClient,
        authority_receipt: VerifiedFamilyReceipt,
        payload_json: impl Into<String>,
    ) -> Result<Self, CertifiedMemoryCompletionWriteError> {
        if !authority_receipt.verified_by(client) {
            return Err(CertifiedMemoryCompletionWriteError::Unknown {
                code: "certified_memory.authority_client_provenance_mismatch",
            });
        }
        let payload_json = canonical_payload(&payload_json.into())?;
        let candidate = authority_receipt.candidate();
        candidate
            .validate()
            .map_err(|error| CertifiedMemoryCompletionWriteError::Invalid(error.to_string()))?;
        let receipt = authority_receipt.receipt();
        receipt
            .validate()
            .map_err(|error| CertifiedMemoryCompletionWriteError::Invalid(error.to_string()))?;
        let expected = candidate
            .clone()
            .into_receipted_completion(receipt.receipt_id.clone())
            .map_err(|error| CertifiedMemoryCompletionWriteError::Invalid(error.to_string()))?;
        if receipt.completion != expected {
            return Err(CertifiedMemoryCompletionWriteError::Conflict(
                "authority receipt does not bind the exact verified candidate".into(),
            ));
        }
        let Some(expected_digest) = receipt.completion.complete_content_digest.as_deref() else {
            return Err(CertifiedMemoryCompletionWriteError::Invalid(
                "terminal family completion requires complete_content_digest".into(),
            ));
        };
        let actual_digest = hex::encode(Sha256::digest(payload_json.as_bytes()));
        if actual_digest != expected_digest {
            return Err(CertifiedMemoryCompletionWriteError::Invalid(
                "completion payload digest does not match canonical payload".into(),
            ));
        }
        bind_payload_inventory(&receipt.completion, &payload_json)?;
        require_source_owned_family_completeness()?;
        Ok(Self {
            authority_receipt,
            payload_json,
        })
    }

    pub fn authority_receipt(&self) -> &VerifiedFamilyReceipt {
        &self.authority_receipt
    }

    pub fn completion(&self) -> &AuthorityFamilyCompletion {
        &self.authority_receipt.receipt().completion
    }

    pub fn payload_json(&self) -> &str {
        &self.payload_json
    }
}

/// Legacy caller-supplied family completion request.
///
/// The constructor retains its existing validation, but cannot verify authority
/// receipt provenance and therefore always returns an error for valid input.
#[derive(Debug, Clone)]
pub struct CertifiedMemoryCompletionWriteRequest {
    completion: AuthorityFamilyCompletion,
    payload_json: String,
}

impl CertifiedMemoryCompletionWriteRequest {
    pub fn new(
        completion: AuthorityFamilyCompletion,
        payload_json: impl Into<String>,
    ) -> Result<Self, CertifiedMemoryCompletionWriteError> {
        let payload_json = canonical_payload(&payload_json.into())?;
        completion
            .validate()
            .map_err(|error| CertifiedMemoryCompletionWriteError::Invalid(error.to_string()))?;
        if !completion.state.is_terminal_complete() {
            return Err(CertifiedMemoryCompletionWriteError::Invalid(
                "only terminal family completions may be persisted as PROVEN".into(),
            ));
        }
        let Some(expected_digest) = completion.complete_content_digest.as_deref() else {
            return Err(CertifiedMemoryCompletionWriteError::Invalid(
                "terminal family completion requires complete_content_digest".into(),
            ));
        };
        let actual_digest = hex::encode(Sha256::digest(payload_json.as_bytes()));
        if actual_digest != expected_digest {
            return Err(CertifiedMemoryCompletionWriteError::Invalid(
                "completion payload digest does not match canonical payload".into(),
            ));
        }
        bind_payload_inventory(&completion, &payload_json)?;
        Err(authority_receipt_unverified())
    }

    pub fn completion(&self) -> &AuthorityFamilyCompletion {
        &self.completion
    }

    pub fn payload_json(&self) -> &str {
        &self.payload_json
    }
}

/// Result of an idempotent completion write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedMemoryCompletionWriteResult {
    pub inserted: bool,
    pub record: CertifiedMemoryCompletionRecord,
}

/// authority receipt, the committed source outcome, and the durable audit row.
///
/// The authority call must happen before this caller-owned transaction. This
/// function performs only bounded DB reads/writes and never retries an unknown
/// authority result. A verified receipt is not evidence of complete source
/// coverage; until that evidence is verifiable this entry point fails closed.
pub async fn record_verified_certified_memory_completion_in_tx(
    tx: &mut Transaction<'_, MySql>,
    client: &AuthorityClient,
    request: VerifiedCertifiedMemoryCompletionWriteRequest,
) -> Result<CertifiedMemoryCompletionWriteResult, CertifiedMemoryCompletionWriteError> {
    let authority_receipt = request.authority_receipt().clone();
    let completion = request.completion().clone();
    let payload_json = request.payload_json().to_owned();
    let prepared = PreparedCompletion::from_request(CertifiedMemoryCompletionWriteRequest {
        completion,
        payload_json,
    })?;
    if !authority_receipt.verified_by(client) {
        return Err(CertifiedMemoryCompletionWriteError::Unknown {
            code: "certified_memory.authority_client_provenance_mismatch",
        });
    }
    require_source_owned_family_completeness()?;
    verify_source_outcome_and_audit(tx, &authority_receipt, &prepared.completion).await?;
    write_prepared_completion_in_tx(tx, prepared).await
}

async fn write_prepared_completion_in_tx(
    tx: &mut Transaction<'_, MySql>,
    prepared: PreparedCompletion,
) -> Result<CertifiedMemoryCompletionWriteResult, CertifiedMemoryCompletionWriteError> {
    let existing = sqlx::query_as::<_, CertifiedMemoryCompletionRow>(
        "SELECT family, scope_key, tenant_id, scope_generation, revoke_watermark, \
                state, reconciliation_state, reservation_id, operation_id, event_id, \
                message_id, source_commit_digest, source_outcome_digest, \
                before_content_digest, after_content_digest, complete_content_digest, \
                audit_correlation_id, inventory_json, payload_json, dependency_frontier_json, \
                authority_completion_receipt_id, created_at, updated_at \
         FROM authority_certified_memory_completion \
         WHERE family = ? AND scope_key = ? AND (tenant_id <=> ?) \
           AND scope_generation = ? \
         LIMIT 1 FOR UPDATE",
    )
    .bind(prepared.family.as_text())
    .bind(&prepared.scope.scope)
    .bind(prepared.scope.tenant_id)
    .bind(prepared.completion.scope_generation)
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sql_error("completion ledger identity read"))?;

    if let Some(row) = existing {
        if !row_matches(&row, &prepared) {
            return Err(CertifiedMemoryCompletionWriteError::Conflict(
                "existing completion row does not match the reconciled identity".into(),
            ));
        }
        let record = row
            .into_record(
                &prepared.scope,
                prepared.completion.scope_generation,
                prepared.completion.revoke_watermark,
            )
            .map_err(map_existing_row_error)?;
        return Ok(CertifiedMemoryCompletionWriteResult {
            inserted: false,
            record,
        });
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    sqlx::query(
        "INSERT INTO authority_certified_memory_completion (\
            family, scope_key, tenant_id, scope_generation, revoke_watermark,\
            state, reconciliation_state, reservation_id, operation_id, event_id,\
            message_id, source_commit_digest, source_outcome_digest,\
            before_content_digest, after_content_digest, complete_content_digest,\
            audit_correlation_id, inventory_json, payload_json, dependency_frontier_json,\
            authority_completion_receipt_id, created_at, updated_at\
         ) VALUES (?, ?, ?, ?, ?, ?, 'PROVEN', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(prepared.family.as_text())
    .bind(&prepared.scope.scope)
    .bind(prepared.scope.tenant_id)
    .bind(prepared.completion.scope_generation)
    .bind(prepared.completion.revoke_watermark)
    .bind(prepared.completion.state.as_text())
    .bind(&prepared.completion.reservation_id)
    .bind(&prepared.completion.operation_id)
    .bind(&prepared.completion.event_id)
    .bind(&prepared.completion.message_id)
    .bind(&prepared.source_commit_digest)
    .bind(&prepared.source_outcome_digest)
    .bind(&prepared.before_content_digest)
    .bind(&prepared.after_content_digest)
    .bind(&prepared.complete_content_digest)
    .bind(&prepared.completion.audit_correlation_id)
    .bind(&prepared.inventory_json)
    .bind(&prepared.payload_json)
    .bind(&prepared.dependency_frontier_json)
    .bind(&prepared.completion.authority_completion_receipt_id)
    .bind(now)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(map_sql_error("completion ledger insert"))?;

    Ok(CertifiedMemoryCompletionWriteResult {
        inserted: true,
        record: prepared.into_record(),
    })
}

async fn verify_source_outcome_and_audit(
    tx: &mut Transaction<'_, MySql>,
    authority_receipt: &VerifiedFamilyReceipt,
    completion: &AuthorityFamilyCompletion,
) -> Result<(), CertifiedMemoryCompletionWriteError> {
    let row: Option<AuthoritySourceOutcomeRow> = sqlx::query_as(
        "SELECT reservation_id, operation_id, event_id, admission_proof_id, \
                request_binding_digest, mutation_kind, service_id, database_id, \
                source_commit_digest, before_image_digest, after_image_digest, source_receipts, \
                staged_evidence, status, attempts, generation, outcome_digest, committed_at \
         FROM authority_source_outcome WHERE reservation_id = ? FOR UPDATE",
    )
    .bind(&completion.reservation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sql_error("source outcome readback"))?;
    let Some(row) = row else {
        return Err(CertifiedMemoryCompletionWriteError::Unknown {
            code: "certified_memory.source_outcome_missing",
        });
    };
    let record = row
        .to_verified_publication_record("COMMITTED")
        .map_err(|_| CertifiedMemoryCompletionWriteError::Unknown {
            code: "certified_memory.source_outcome_unverified",
        })?;
    if record.mutation_kind != AuthorityMutationKind::AuthorizationSource
        || record.reservation_id != completion.reservation_id
        || record.operation_id != completion.operation_id
        || record.event_id != completion.event_id
        || record.source_commit_digest != completion.source_commit_digest
        || hex::encode(&row.outcome_digest) != completion.source_outcome_digest
        || row.service_id != authority_receipt.service_id()
        || row.database_id != authority_receipt.database_id()
    {
        return Err(CertifiedMemoryCompletionWriteError::Conflict(
            "source outcome does not bind the verified authority completion".into(),
        ));
    }

    let mut audit_count = 0usize;
    for receipt in &record.source_receipts {
        if receipt.identity_kind != "audit_log" {
            continue;
        }
        let audit_id = receipt.identity.parse::<i64>().map_err(|_| {
            CertifiedMemoryCompletionWriteError::Unknown {
                code: "certified_memory.audit_receipt_identity_invalid",
            }
        })?;
        if audit_id <= 0 {
            return Err(CertifiedMemoryCompletionWriteError::Unknown {
                code: "certified_memory.audit_receipt_identity_invalid",
            });
        }
        type AuditCorrelationRow = (i64, Option<String>, Option<String>, Option<String>);
        let row: Option<AuditCorrelationRow> = sqlx::query_as(
            "SELECT id, event_type, request_id, detail FROM audit_log WHERE id = ? FOR UPDATE",
        )
        .bind(audit_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_sql_error("source audit readback"))?;
        let Some((id, event_type, request_id, detail)) = row else {
            return Err(CertifiedMemoryCompletionWriteError::Unknown {
                code: "certified_memory.audit_receipt_missing",
            });
        };
        if id != audit_id
            || event_type.as_deref().is_none_or(str::is_empty)
            || !audit_request_binds_operation(request_id.as_deref(), &completion.operation_id)
            || !audit_detail_binds_correlation(
                detail.as_deref(),
                &completion.operation_id,
                &completion.audit_correlation_id,
            )
        {
            return Err(CertifiedMemoryCompletionWriteError::Conflict(
                "source audit receipt does not bind the completion operation".into(),
            ));
        }
        audit_count += 1;
    }
    if audit_count == 0 {
        return Err(CertifiedMemoryCompletionWriteError::Unknown {
            code: "certified_memory.source_audit_receipt_missing",
        });
    }
    Ok(())
}

///
/// No verified authority receipt can be supplied through this API. It always
/// returns UNKNOWN before reading or writing the caller-owned transaction.
pub async fn record_proven_certified_memory_completion_in_tx(
    tx: &mut Transaction<'_, MySql>,
    request: CertifiedMemoryCompletionWriteRequest,
) -> Result<CertifiedMemoryCompletionWriteResult, CertifiedMemoryCompletionWriteError> {
    require_verified_authority_receipt()?;
    let prepared = PreparedCompletion::from_request(request)?;
    let existing = sqlx::query_as::<_, CertifiedMemoryCompletionRow>(
        "SELECT family, scope_key, tenant_id, scope_generation, revoke_watermark, \
                state, reconciliation_state, reservation_id, operation_id, event_id, \
                message_id, source_commit_digest, source_outcome_digest, \
                before_content_digest, after_content_digest, complete_content_digest, \
                audit_correlation_id, inventory_json, payload_json, dependency_frontier_json, \
                authority_completion_receipt_id, created_at, updated_at \
         FROM authority_certified_memory_completion \
         WHERE family = ? AND scope_key = ? AND (tenant_id <=> ?) \
           AND scope_generation = ? \
         LIMIT 1 FOR UPDATE",
    )
    .bind(prepared.family.as_text())
    .bind(&prepared.scope.scope)
    .bind(prepared.scope.tenant_id)
    .bind(prepared.completion.scope_generation)
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sql_error("completion ledger identity read"))?;

    if let Some(row) = existing {
        if !row_matches(&row, &prepared) {
            return Err(CertifiedMemoryCompletionWriteError::Conflict(
                "existing completion row does not match the reconciled identity".into(),
            ));
        }
        let record = row
            .into_record(
                &prepared.scope,
                prepared.completion.scope_generation,
                prepared.completion.revoke_watermark,
            )
            .map_err(map_existing_row_error)?;
        return Ok(CertifiedMemoryCompletionWriteResult {
            inserted: false,
            record,
        });
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    sqlx::query(
        "INSERT INTO authority_certified_memory_completion (\
            family, scope_key, tenant_id, scope_generation, revoke_watermark,\
            state, reconciliation_state, reservation_id, operation_id, event_id,\
            message_id, source_commit_digest, source_outcome_digest,\
            before_content_digest, after_content_digest, complete_content_digest,\
            audit_correlation_id, inventory_json, payload_json, dependency_frontier_json,\
            authority_completion_receipt_id, created_at, updated_at\
         ) VALUES (?, ?, ?, ?, ?, ?, 'PROVEN', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(prepared.family.as_text())
    .bind(&prepared.scope.scope)
    .bind(prepared.scope.tenant_id)
    .bind(prepared.completion.scope_generation)
    .bind(prepared.completion.revoke_watermark)
    .bind(prepared.completion.state.as_text())
    .bind(&prepared.completion.reservation_id)
    .bind(&prepared.completion.operation_id)
    .bind(&prepared.completion.event_id)
    .bind(&prepared.completion.message_id)
    .bind(&prepared.source_commit_digest)
    .bind(&prepared.source_outcome_digest)
    .bind(&prepared.before_content_digest)
    .bind(&prepared.after_content_digest)
    .bind(&prepared.complete_content_digest)
    .bind(&prepared.completion.audit_correlation_id)
    .bind(&prepared.inventory_json)
    .bind(&prepared.payload_json)
    .bind(&prepared.dependency_frontier_json)
    .bind(&prepared.completion.authority_completion_receipt_id)
    .bind(now)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(map_sql_error("completion ledger insert"))?;

    Ok(CertifiedMemoryCompletionWriteResult {
        inserted: true,
        record: prepared.into_record(),
    })
}

#[derive(Debug)]
struct PreparedCompletion {
    completion: AuthorityFamilyCompletion,
    payload_json: String,
    family: AuthorityCertifiedMemoryFamily,
    scope: AuthorityFamilyScope,
    source_commit_digest: Vec<u8>,
    source_outcome_digest: Vec<u8>,
    before_content_digest: Option<Vec<u8>>,
    after_content_digest: Option<Vec<u8>>,
    complete_content_digest: Option<Vec<u8>>,
    inventory_json: String,
    dependency_frontier_json: String,
}

impl PreparedCompletion {
    fn from_request(
        request: CertifiedMemoryCompletionWriteRequest,
    ) -> Result<Self, CertifiedMemoryCompletionWriteError> {
        let completion = request.completion;
        let family = completion.family;
        let scope = completion.scope.clone();
        Ok(Self {
            source_commit_digest: decode_digest(
                &completion.source_commit_digest,
                "source_commit_digest",
            )?,
            source_outcome_digest: decode_digest(
                &completion.source_outcome_digest,
                "source_outcome_digest",
            )?,
            before_content_digest: decode_optional_digest(
                completion.before_content_digest.as_deref(),
                "before_content_digest",
            )?,
            after_content_digest: decode_optional_digest(
                completion.after_content_digest.as_deref(),
                "after_content_digest",
            )?,
            complete_content_digest: decode_optional_digest(
                completion.complete_content_digest.as_deref(),
                "complete_content_digest",
            )?,
            inventory_json: serde_json::to_string(&completion.inventory).map_err(|error| {
                CertifiedMemoryCompletionWriteError::Invalid(format!(
                    "completion inventory cannot be serialized: {error}"
                ))
            })?,
            dependency_frontier_json: serde_json::to_string(&completion.dependency_frontier)
                .map_err(|error| {
                    CertifiedMemoryCompletionWriteError::Invalid(format!(
                        "completion dependency frontier cannot be serialized: {error}"
                    ))
                })?,
            completion,
            payload_json: request.payload_json,
            family,
            scope,
        })
        .and_then(|prepared| {
            bind_payload_inventory(&prepared.completion, &prepared.payload_json)?;
            Ok(prepared)
        })
    }
}

/// Reject a caller-supplied payload that does not enumerate the same items as
/// the completion inventory. This is the write-time copy of the snapshot
/// binding; it does not prove source coverage or authority provenance.
fn bind_payload_inventory(
    completion: &AuthorityFamilyCompletion,
    payload_json: &str,
) -> Result<(), CertifiedMemoryCompletionWriteError> {
    let payload =
        decode_certified_memory_payload(completion.family, payload_json).map_err(|error| {
            match error {
                CertifiedMemoryMaterializerError::Pending { code, .. } => {
                    CertifiedMemoryCompletionWriteError::Unknown { code }
                }
                CertifiedMemoryMaterializerError::Unknown { code, .. }
                | CertifiedMemoryMaterializerError::Quarantined { code, .. } => {
                    CertifiedMemoryCompletionWriteError::Unknown { code }
                }
                other => CertifiedMemoryCompletionWriteError::Invalid(other.to_string()),
            }
        })?;
    payload
        .validate_inventory(completion)
        .map_err(|error| match error {
            CertifiedMemoryMaterializerError::Pending { code, .. } => {
                CertifiedMemoryCompletionWriteError::Unknown { code }
            }
            CertifiedMemoryMaterializerError::Unknown { code, .. }
            | CertifiedMemoryMaterializerError::Quarantined { code, .. } => {
                CertifiedMemoryCompletionWriteError::Unknown { code }
            }
            other => CertifiedMemoryCompletionWriteError::Invalid(other.to_string()),
        })?;
    let payload_empty = payload.is_empty();
    match completion.state {
        astral_types::authority_protocol::AuthorityFamilyCompletionState::CompleteEmpty
            if !payload_empty =>
        {
            Err(CertifiedMemoryCompletionWriteError::Invalid(
                "family payload and completion state disagree".into(),
            ))
        }
        astral_types::authority_protocol::AuthorityFamilyCompletionState::Complete
            if payload_empty =>
        {
            Err(CertifiedMemoryCompletionWriteError::Invalid(
                "family payload and completion state disagree".into(),
            ))
        }
        _ => Ok(()),
    }
}

impl PreparedCompletion {
    fn into_record(self) -> CertifiedMemoryCompletionRecord {
        CertifiedMemoryCompletionRecord {
            completion: self.completion,
            payload_json: self.payload_json,
        }
    }
}

fn row_matches(row: &CertifiedMemoryCompletionRow, prepared: &PreparedCompletion) -> bool {
    row.family == prepared.family.as_text()
        && row.scope_key == prepared.scope.scope
        && row.tenant_id == prepared.scope.tenant_id
        && row.scope_generation == prepared.completion.scope_generation
        && row.revoke_watermark == prepared.completion.revoke_watermark
        && row.state == prepared.completion.state.as_text()
        && row.reconciliation_state == "PROVEN"
        && row.reservation_id == prepared.completion.reservation_id
        && row.operation_id == prepared.completion.operation_id
        && row.event_id == prepared.completion.event_id
        && row.message_id == prepared.completion.message_id
        && row.source_commit_digest == prepared.source_commit_digest
        && row.source_outcome_digest == prepared.source_outcome_digest
        && row.before_content_digest == prepared.before_content_digest
        && row.after_content_digest == prepared.after_content_digest
        && row.complete_content_digest == prepared.complete_content_digest
        && row.audit_correlation_id == prepared.completion.audit_correlation_id
        && json_values_equal(&row.inventory_json, &prepared.inventory_json)
        && json_values_equal(&row.payload_json, &prepared.payload_json)
        && json_values_equal(
            &row.dependency_frontier_json,
            &prepared.dependency_frontier_json,
        )
        && row.authority_completion_receipt_id
            == prepared.completion.authority_completion_receipt_id
}

fn json_values_equal(stored: &str, expected: &str) -> bool {
    match (
        serde_json::from_str::<serde_json::Value>(stored),
        serde_json::from_str::<serde_json::Value>(expected),
    ) {
        (Ok(stored), Ok(expected)) => stored == expected,
        _ => false,
    }
}

fn canonical_payload(value: &str) -> Result<String, CertifiedMemoryCompletionWriteError> {
    if value.len() > MAX_PAYLOAD_BYTES {
        return Err(CertifiedMemoryCompletionWriteError::Invalid(
            "completion payload exceeds bounded size".into(),
        ));
    }
    let parsed: serde_json::Value = serde_json::from_str(value).map_err(|error| {
        CertifiedMemoryCompletionWriteError::Invalid(format!(
            "completion payload is not valid JSON: {error}"
        ))
    })?;
    if !parsed.is_array() {
        return Err(CertifiedMemoryCompletionWriteError::Invalid(
            "completion payload must be a family inventory array".into(),
        ));
    }
    serde_json::to_string(&parsed).map_err(|error| {
        CertifiedMemoryCompletionWriteError::Invalid(format!(
            "completion payload cannot be canonicalized: {error}"
        ))
    })
}

fn decode_digest(
    value: &str,
    field: &'static str,
) -> Result<Vec<u8>, CertifiedMemoryCompletionWriteError> {
    let decoded = hex::decode(value).map_err(|_| {
        CertifiedMemoryCompletionWriteError::Invalid(format!("{field} is not hexadecimal"))
    })?;
    if decoded.len() != 32 {
        return Err(CertifiedMemoryCompletionWriteError::Invalid(format!(
            "{field} must be a 32-byte digest"
        )));
    }
    Ok(decoded)
}

fn decode_optional_digest(
    value: Option<&str>,
    field: &'static str,
) -> Result<Option<Vec<u8>>, CertifiedMemoryCompletionWriteError> {
    value.map(|value| decode_digest(value, field)).transpose()
}

fn map_existing_row_error(
    error: CertifiedMemoryCompletionError,
) -> CertifiedMemoryCompletionWriteError {
    match error {
        CertifiedMemoryCompletionError::Pending { .. }
        | CertifiedMemoryCompletionError::Unknown { .. }
        | CertifiedMemoryCompletionError::Quarantined { .. }
        | CertifiedMemoryCompletionError::ScopeMismatch => {
            CertifiedMemoryCompletionWriteError::Conflict(
                "existing completion row is not a proven terminal row".into(),
            )
        }
        CertifiedMemoryCompletionError::Invalid(message) => {
            CertifiedMemoryCompletionWriteError::Invalid(message)
        }
    }
}

fn map_sql_error(
    operation: &'static str,
) -> impl FnOnce(sqlx::Error) -> CertifiedMemoryCompletionWriteError {
    move |error| {
        let code = if error.to_string().contains("doesn't exist") {
            "certified_memory.completion_ledger_schema_unavailable"
        } else if operation.contains("commit") {
            "certified_memory.completion_ledger_commit_unknown"
        } else {
            "certified_memory.completion_ledger_write_failed"
        };
        CertifiedMemoryCompletionWriteError::Unknown { code }
    }
}

const AUDIT_REQUEST_ID_MAX_BYTES: usize = 64;

/// `audit_log.request_id` is only 64 bytes. A longer operation id cannot be
/// proven by that column, so equality with a truncated or absent value is not
/// accepted as correlation.
fn audit_request_binds_operation(request_id: Option<&str>, operation_id: &str) -> bool {
    request_id.is_some_and(|request_id| {
        request_id.len() <= AUDIT_REQUEST_ID_MAX_BYTES
            && operation_id.len() <= AUDIT_REQUEST_ID_MAX_BYTES
            && request_id == operation_id
    })
}

/// The ledger correlation must be present in the same audit row. The existing
/// `operationId` detail field is the only durable text wide enough for the
/// protocol identity; a matching column alone does not prove it.
fn audit_detail_binds_correlation(
    detail: Option<&str>,
    operation_id: &str,
    audit_correlation_id: &str,
) -> bool {
    let Some(detail) = detail else {
        return false;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(detail) else {
        return false;
    };
    value.get("operationId").and_then(serde_json::Value::as_str) == Some(operation_id)
        && (value
            .get("auditCorrelationId")
            .and_then(serde_json::Value::as_str)
            == Some(audit_correlation_id)
            || audit_correlation_id == operation_id)
}

/// Authority provenance and payload/inventory agreement do not prove that the
/// source owner captured the complete selector result, including an empty set.
/// Replace this gate only with independently verified durable source evidence.
fn require_source_owned_family_completeness() -> Result<(), CertifiedMemoryCompletionWriteError> {
    Err(CertifiedMemoryCompletionWriteError::Unknown {
        code: "certified_memory.source_family_completeness_unverified",
    })
}

fn authority_receipt_unverified() -> CertifiedMemoryCompletionWriteError {
    CertifiedMemoryCompletionWriteError::Unknown {
        code: "certified_memory.authority_receipt_unverified",
    }
}

fn require_verified_authority_receipt() -> Result<(), CertifiedMemoryCompletionWriteError> {
    Err(authority_receipt_unverified())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CertifiedMemoryCompletionWriteError {
    #[error("certified-memory completion write is invalid: {0}")]
    Invalid(String),
    #[error("certified-memory completion write conflicts with durable state: {0}")]
    Conflict(String),
    #[error("certified-memory completion write is unknown: {code}")]
    Unknown { code: &'static str },
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::authority_protocol::{
        AuthorityFamilyCompletionState, AuthorityFamilyInventoryItem,
    };

    fn completion(payload: &str) -> AuthorityFamilyCompletion {
        AuthorityFamilyCompletion {
            family: AuthorityCertifiedMemoryFamily::CardContext,
            state: AuthorityFamilyCompletionState::CompleteEmpty,
            scope: AuthorityFamilyScope {
                tenant_id: Some(7),
                scope: "tenant:7".into(),
            },
            reservation_id: "reservation".into(),
            operation_id: "operation".into(),
            event_id: "event".into(),
            message_id: Some("message".into()),
            source_commit_digest: "11".repeat(32),
            source_outcome_digest: "22".repeat(32),
            before_content_digest: None,
            after_content_digest: None,
            complete_content_digest: Some(hex::encode(Sha256::digest(payload.as_bytes()))),
            audit_correlation_id: "audit".into(),
            inventory: Vec::new(),
            scope_generation: 3,
            revoke_watermark: 1,
            dependency_frontier:
                astral_types::authority_protocol::AuthorityFamilyDependencyFrontier {
                    authority_term: 1,
                    global_fence_sequence: 2,
                    dependency_generation: 3,
                },
            authority_completion_receipt_id: "authority-receipt".into(),
        }
    }

    #[test]
    fn verified_public_entry_points_require_source_completeness() {
        // VerifiedFamilyReceipt is opaque outside astral-authority, so assert
        // the gates at both public entry points without fabricating a receipt.
        let production = include_str!("certified_memory_completion_writer.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let constructor = production
            .split("impl VerifiedCertifiedMemoryCompletionWriteRequest {")
            .nth(1)
            .unwrap()
            .split("    pub fn authority_receipt(")
            .next()
            .unwrap();
        let inventory = constructor.find("bind_payload_inventory(").unwrap();
        let constructor_gate = constructor
            .find("require_source_owned_family_completeness()?")
            .unwrap();
        let construction = constructor.find("Ok(Self {").unwrap();
        assert!(inventory < constructor_gate && constructor_gate < construction);

        let writer = production
            .split("pub async fn record_verified_certified_memory_completion_in_tx(")
            .nth(1)
            .unwrap()
            .split("async fn write_prepared_completion_in_tx(")
            .next()
            .unwrap();
        let provenance = writer
            .find("authority_receipt.verified_by(client)")
            .unwrap();
        let source_audit = writer.find("verify_source_outcome_and_audit(").unwrap();
        let writer_gate = writer
            .find("require_source_owned_family_completeness()?")
            .unwrap();
        let write = writer.find("write_prepared_completion_in_tx(").unwrap();
        assert!(provenance < writer_gate && writer_gate < source_audit && source_audit < write);
    }

    #[test]
    fn valid_inventory_and_authority_receipt_cannot_establish_source_completeness() {
        let empty = completion("[]");
        bind_payload_inventory(&empty, "[]").unwrap();
        assert_eq!(
            require_source_owned_family_completeness(),
            Err(CertifiedMemoryCompletionWriteError::Unknown {
                code: "certified_memory.source_family_completeness_unverified",
            })
        );
    }

    #[test]
    fn legacy_writer_rejects_unverified_authority_before_ledger_access() {
        assert_eq!(
            require_verified_authority_receipt(),
            Err(CertifiedMemoryCompletionWriteError::Unknown {
                code: "certified_memory.authority_receipt_unverified",
            })
        );
    }

    #[test]
    fn writer_requires_a_terminal_completion_and_canonical_payload_digest() {
        let pending = AuthorityFamilyCompletion {
            state: AuthorityFamilyCompletionState::Pending,
            ..completion("[]")
        };
        assert!(matches!(
            CertifiedMemoryCompletionWriteRequest::new(pending, "[]"),
            Err(CertifiedMemoryCompletionWriteError::Invalid(_))
        ));

        let mut invalid = completion("[]");
        invalid.complete_content_digest = Some("00".repeat(32));
        assert!(matches!(
            CertifiedMemoryCompletionWriteRequest::new(invalid, "[]"),
            Err(CertifiedMemoryCompletionWriteError::Invalid(_))
        ));
    }

    #[test]
    fn writer_canonicalizes_json_and_rejects_non_array_payloads() {
        assert_eq!(canonical_payload("[ ]").unwrap(), "[]");
        assert_eq!(
            CertifiedMemoryCompletionWriteRequest::new(completion("[]"), "[ ]").unwrap_err(),
            CertifiedMemoryCompletionWriteError::Unknown {
                code: "certified_memory.authority_receipt_unverified",
            }
        );

        assert!(matches!(
            CertifiedMemoryCompletionWriteRequest::new(completion("[]"), "{}"),
            Err(CertifiedMemoryCompletionWriteError::Invalid(_))
        ));
    }

    #[test]
    fn mysql_json_formatting_does_not_break_exact_reconciliation() {
        assert!(json_values_equal(
            r#"[{ "key": "card:9", "value": { "b": 2, "a": 1 } }]"#,
            r#"[{"key":"card:9","value":{"a":1,"b":2}}]"#,
        ));
        assert!(!json_values_equal(
            r#"[{"key":"card:9","value":1}]"#,
            r#"[{"key":"card:9","value":2}]"#,
        ));
        assert!(!json_values_equal("not-json", "not-json"));
        assert!(!json_values_equal("[1,2]", "[2,1]"));
    }

    #[test]
    fn audit_correlation_requires_the_operation_and_detail_binding() {
        let operation_id = "operation-1";
        let correlation_id = "audit-correlation-1";
        let detail = serde_json::json!({
            "operationId": operation_id,
            "auditCorrelationId": correlation_id
        })
        .to_string();
        assert!(audit_request_binds_operation(
            Some(operation_id),
            operation_id
        ));
        assert!(!audit_request_binds_operation(
            Some(operation_id),
            &"o".repeat(65)
        ));
        assert!(!audit_request_binds_operation(None, operation_id));
        assert!(audit_detail_binds_correlation(
            Some(&detail),
            operation_id,
            correlation_id
        ));
        assert!(audit_detail_binds_correlation(
            Some(&serde_json::json!({"operationId": operation_id}).to_string()),
            operation_id,
            operation_id
        ));
        assert!(!audit_detail_binds_correlation(
            Some(&detail),
            operation_id,
            "other-correlation"
        ));
        assert!(!audit_detail_binds_correlation(
            None,
            operation_id,
            operation_id
        ));
    }

    #[test]
    fn payload_must_bind_each_inventory_item_before_a_proven_write() {
        let mut complete = completion("[]");
        complete.state = AuthorityFamilyCompletionState::Complete;
        complete.inventory = vec![AuthorityFamilyInventoryItem {
            key: "user:5".into(),
            tenant_id: Some(7),
            content_digest: "44".repeat(32),
        }];
        let mismatched = r#"[{"userId":5,"status":"ACTIVE"}]"#;
        complete.complete_content_digest = Some(hex::encode(Sha256::digest(
            serde_json::to_string(&serde_json::from_str::<serde_json::Value>(mismatched).unwrap())
                .unwrap()
                .as_bytes(),
        )));
        let error = CertifiedMemoryCompletionWriteRequest::new(complete, mismatched).unwrap_err();
        assert!(
            matches!(error, CertifiedMemoryCompletionWriteError::Invalid(_)),
            "payload/inventory mismatch must fail before a proven write, got {error:?}"
        );
    }

    #[test]
    fn prepared_completion_requires_explicit_empty_state_for_empty_inventory() {
        let mut complete = completion("[]");
        complete.state = AuthorityFamilyCompletionState::Complete;
        let payload = r#"[{"key":{"userId":5,"identityCardId":6,"userCardId":9},"value":{"user_id":5,"eligibility":{"identityCardId":6,"userCardId":9,"userCardTenantId":7,"userCardDomainId":8,"effectiveExpiry":null}}}]"#;
        let inventory_value = serde_json::json!({
            "user_id": 5,
            "eligibility": {
                "identityCardId": 6,
                "userCardId": 9,
                "userCardTenantId": 7,
                "userCardDomainId": 8,
                "effectiveExpiry": null
            }
        });
        complete.inventory = vec![AuthorityFamilyInventoryItem {
            key: "user:5:identity-card:6:user-card:9".into(),
            tenant_id: Some(7),
            content_digest: hex::encode(Sha256::digest(
                serde_json::to_vec(&inventory_value).unwrap(),
            )),
        }];
        complete.complete_content_digest = Some(hex::encode(Sha256::digest(
            serde_json::to_string(&serde_json::from_str::<serde_json::Value>(payload).unwrap())
                .unwrap()
                .as_bytes(),
        )));
        assert_eq!(
            CertifiedMemoryCompletionWriteRequest::new(complete, payload).unwrap_err(),
            CertifiedMemoryCompletionWriteError::Unknown {
                code: "certified_memory.authority_receipt_unverified",
            }
        );

        let invalid = completion("[]");
        let invalid = AuthorityFamilyCompletion {
            state: AuthorityFamilyCompletionState::Complete,
            ..invalid
        };
        assert!(matches!(
            CertifiedMemoryCompletionWriteRequest::new(invalid, "[]"),
            Err(CertifiedMemoryCompletionWriteError::Invalid(_))
        ));
    }
}
