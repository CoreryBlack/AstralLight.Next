//! Durable, authority-completed proof that an empty card was created by a real source transaction.
//!
//! This row is only a source-origin association. A first-grant candidate may consume it only
//! after the current AuthorityClient reconciles the exact binding and immutable completion receipt.

use astral_authority::AuthorityClient;
use astral_types::{
    AuthorityCommitBinding, AuthorityEligibilityCompletionEvidence,
    AuthorityEligibilityCompletionResponse, AuthorityEligibilityEvidenceKind,
    AuthorityEligibilityStagedEvidence, AuthorityMutationKind, AuthorityProtocolScope,
    AuthorityRetainedStagedEvidence, AuthorizationAdmission, PolicyError,
};
use sha2::{Digest, Sha256};
use sqlx::{MySql, MySqlPool, Transaction};

use crate::authority_source_outcome::{
    canonical_outcome_digest, AuthoritySourceOutcomeRecord, AuthoritySourceReceiptIdentity,
};

use super::identity::{IdentityPresence, IdentityStagedEvidence};

const ORIGIN_TABLE: &str = "authority_empty_card_origin";
const ORIGIN_RECEIPT_DOMAIN: &[u8] = b"ASTRAL_EMPTY_CARD_ORIGIN_TERMINAL_RECEIPT_V1\0";

fn pending(message: impl std::fmt::Display) -> PolicyError {
    PolicyError::Repository(format!("empty-card origin pending: {message}"))
}

fn digest_hex(raw: &[u8], field: &str) -> Result<String, PolicyError> {
    if raw.len() != 32 {
        return Err(pending(format!("{field} digest is not 32 bytes")));
    }
    Ok(hex::encode(raw))
}

fn receipt_digest(
    receipt: &astral_types::AuthorityEligibilityCompletionReceipt,
) -> Result<String, PolicyError> {
    receipt.validate().map_err(pending)?;
    let json = serde_json::to_vec(receipt).map_err(pending)?;
    let mut hasher = Sha256::new();
    hasher.update(ORIGIN_RECEIPT_DOMAIN);
    hasher.update(json);
    Ok(hex::encode(hasher.finalize()))
}

fn completion_for_origin(
    tenant_id: i64,
    card_id: i64,
    completion: &AuthorityEligibilityCompletionEvidence,
) -> Result<(), PolicyError> {
    completion.validate().map_err(pending)?;
    if tenant_id <= 0 || card_id <= 0 || completion.zero_card_selection.is_some() {
        return Err(pending(
            "origin completion must name one positive tenant/card",
        ));
    }
    if completion.cards.len() != 1 {
        return Err(pending("origin completion must contain exactly one card"));
    }
    let expected = AuthorityProtocolScope::Card(astral_types::AuthorizationAuthorityScope {
        tenant_id,
        card_id,
        user_id: None,
        domain: astral_types::AuthorizationDomainScope::Any,
    });
    if completion.cards[0].scope != expected {
        return Err(pending("origin completion card/tenant scope differs"));
    }
    Ok(())
}

/// Validate the actual card creation probe and insert receipt retained by Identity.
fn validate_empty_card_insert_artifact(
    tenant_id: i64,
    card_id: i64,
    artifact: &IdentityStagedEvidence,
    completion: &AuthorityEligibilityCompletionEvidence,
) -> Result<(), PolicyError> {
    completion_for_origin(tenant_id, card_id, completion)?;
    if artifact.delta.is_some() {
        return Err(pending("empty-card origin cannot carry a grant delta"));
    }
    let affected = artifact.affected_cards()?;
    if affected.len() != 1
        || affected[0].card_id != card_id
        || affected[0].tenant_id != Some(tenant_id)
    {
        return Err(pending(
            "retained affected-card set differs from the origin",
        ));
    }
    if artifact
        .fanout
        .get("eligibilityEvents")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
    {
        return Err(pending("origin must retain exactly one eligibility event"));
    }
    let card_targets: Vec<_> = artifact
        .targets
        .iter()
        .filter(|target| target.entity == "user_card")
        .collect();
    if card_targets.len() != 1 {
        return Err(pending(
            "origin must retain exactly one user_card target probe",
        ));
    }
    let target = card_targets[0];
    if target.key.get("cardId").and_then(serde_json::Value::as_i64) != Some(card_id)
        || !matches!(target.before, IdentityPresence::Absent)
    {
        return Err(pending(
            "user_card probe does not prove a before-absent create",
        ));
    }
    let IdentityPresence::Present(after) = &target.after else {
        return Err(pending("user_card create probe has no actual after row"));
    };
    if after.get("cardId").and_then(serde_json::Value::as_i64) != Some(card_id)
        || after.get("tenantId").and_then(serde_json::Value::as_i64) != Some(tenant_id)
        || after.get("cardStatus").and_then(serde_json::Value::as_str) != Some("ACTIVE")
        || after
            .get("userId")
            .and_then(serde_json::Value::as_i64)
            .is_none_or(|id| id <= 0)
    {
        return Err(pending(
            "user_card after image does not bind the active card and tenant",
        ));
    }
    let inserts: Vec<_> = artifact
        .receipts
        .iter()
        .filter(|receipt| receipt.entity == "user_card")
        .collect();
    if inserts.len() != 1 {
        return Err(pending(
            "origin must retain exactly one user_card statement receipt",
        ));
    }
    let receipt = inserts[0];
    if !receipt.kind.eq_ignore_ascii_case("INSERT")
        || receipt.rows_affected != 1
        || receipt.durable_id != card_id.to_string()
        || receipt
            .key
            .get("cardId")
            .and_then(serde_json::Value::as_i64)
            != Some(card_id)
    {
        return Err(pending(
            "user_card INSERT receipt is not bound to this card",
        ));
    }
    Ok(())
}

fn parse_origin_evidence(
    staged_evidence: &str,
    tenant_id: i64,
    card_id: i64,
) -> Result<
    (
        AuthorityEligibilityCompletionEvidence,
        IdentityStagedEvidence,
    ),
    PolicyError,
> {
    let envelope: astral_types::AuthorityStagedSourceEvidence =
        serde_json::from_str(staged_evidence).map_err(pending)?;
    envelope.validate().map_err(pending)?;
    if envelope.coverage.is_some() {
        return Err(pending(
            "eligibility origin must not declare publication coverage",
        ));
    }
    let typed: AuthorityEligibilityStagedEvidence =
        serde_json::from_value(envelope.evidence.clone()).map_err(pending)?;
    typed.validate().map_err(pending)?;
    if typed.kind != AuthorityEligibilityEvidenceKind::EligibilityCompletion {
        return Err(pending(
            "origin evidence is not typed eligibility completion",
        ));
    }
    let artifact: IdentityStagedEvidence =
        serde_json::from_value(typed.source_evidence.clone()).map_err(pending)?;
    validate_empty_card_insert_artifact(tenant_id, card_id, &artifact, &typed.completion)?;
    Ok((typed.completion, artifact))
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct OriginSourceOutcomeRow {
    reservation_id: String,
    operation_id: String,
    event_id: String,
    admission_proof_id: String,
    request_binding_digest: Vec<u8>,
    mutation_kind: String,
    service_id: String,
    database_id: String,
    source_commit_digest: Vec<u8>,
    before_image_digest: Vec<u8>,
    after_image_digest: Vec<u8>,
    source_receipts: Option<String>,
    staged_evidence: Option<String>,
    status: String,
    outcome_digest: Vec<u8>,
    committed_at: i64,
}

const SOURCE_OUTCOME_COLUMNS: &str = "reservation_id, operation_id, event_id, admission_proof_id, \
    request_binding_digest, mutation_kind, service_id, database_id, source_commit_digest, \
    before_image_digest, after_image_digest, CAST(source_receipts AS CHAR) AS source_receipts, \
    CAST(staged_evidence AS CHAR) AS staged_evidence, status, outcome_digest, committed_at";

/// Stage the origin after Identity has staged/promoted the source outcome in this transaction.
/// It only reads and binds the real source proof; it does not consume or promote a second time.
pub async fn stage_empty_card_origin_in_tx(
    tx: &mut Transaction<'_, MySql>,
    admission: &AuthorizationAdmission,
    tenant_id: i64,
    card_id: i64,
) -> Result<(), PolicyError> {
    let proof = admission.proof();
    if tenant_id <= 0 || card_id <= 0 {
        return Err(pending("origin tenant/card identifiers must be positive"));
    }
    let request_digest = proof
        .request_binding_digest
        .as_deref()
        .ok_or_else(|| pending("source proof has no request binding"))?;
    let prepare_json: Option<String> = sqlx::query_scalar(
        "SELECT CAST(reservation_json AS CHAR) FROM authorization_source_reservation \
         WHERE operation_id = ? AND proof_id = ? AND request_digest = UNHEX(?) \
         AND disposition = 'RESERVED' FOR UPDATE",
    )
    .bind(&proof.operation_id)
    .bind(&proof.proof_id)
    .bind(request_digest)
    .fetch_optional(&mut **tx)
    .await
    .map_err(pending)?;
    let prepare: astral_types::AuthorityPrepareResponse = serde_json::from_str(
        &prepare_json.ok_or_else(|| pending("source reservation is missing"))?,
    )
    .map_err(pending)?;
    prepare.validate().map_err(pending)?;
    let reservation = &prepare.reservation;
    let query = format!(
        "SELECT {SOURCE_OUTCOME_COLUMNS} FROM authority_source_outcome \
         WHERE reservation_id = ? FOR UPDATE"
    );
    let source: OriginSourceOutcomeRow = sqlx::query_as(&query)
        .bind(&reservation.reservation_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(pending)?
        .ok_or_else(|| pending("promoted source outcome is missing"))?;
    if source.status != "PENDING"
        || source.operation_id != proof.operation_id
        || source.event_id != proof.event_id
        || source.admission_proof_id != proof.proof_id
        || source.mutation_kind != AuthorityMutationKind::AuthorizationSource.as_text()
        || reservation.intent.operation_id != source.operation_id
        || reservation.intent.event_id != source.event_id
        || reservation.intent.admission_proof_id != source.admission_proof_id
        || reservation.intent.request_digest != request_digest
        || reservation.intent.service_id != source.service_id
        || reservation.intent.mutation_kind != AuthorityMutationKind::AuthorizationSource
    {
        return Err(pending(
            "source outcome does not match the exact admitted create",
        ));
    }
    let staged_evidence = source
        .staged_evidence
        .as_deref()
        .ok_or_else(|| pending("promoted source outcome has no retained evidence"))?;
    let source_receipts: Vec<AuthoritySourceReceiptIdentity> = serde_json::from_str(
        source
            .source_receipts
            .as_deref()
            .ok_or_else(|| pending("promoted source outcome has no actual receipts"))?,
    )
    .map_err(pending)?;
    let record = AuthoritySourceOutcomeRecord {
        reservation_id: source.reservation_id.clone(),
        operation_id: source.operation_id.clone(),
        event_id: source.event_id.clone(),
        admission_proof_id: source.admission_proof_id.clone(),
        request_binding_digest: digest_hex(&source.request_binding_digest, "request binding")?,
        mutation_kind: AuthorityMutationKind::AuthorizationSource,
        service_id: source.service_id.clone(),
        database_id: source.database_id.clone(),
        source_commit_digest: digest_hex(&source.source_commit_digest, "source commit")?,
        before_image_digest: Some(digest_hex(&source.before_image_digest, "before image")?),
        after_image_digest: Some(digest_hex(&source.after_image_digest, "after image")?),
        source_receipts: source_receipts.clone(),
        committed_at: source.committed_at,
    };
    record.validate().map_err(pending)?;
    let expected_outcome_digest =
        hex::decode(canonical_outcome_digest(&record, Some(staged_evidence)).map_err(pending)?)
            .map_err(pending)?;
    if expected_outcome_digest != source.outcome_digest
        || record.request_binding_digest != request_digest
        || source.service_id != reservation.intent.service_id
        || source.database_id != reservation.intent.database_id
        || !source_receipts.iter().any(|receipt| {
            receipt.identity_kind == "user_card:INSERT" && receipt.identity == card_id.to_string()
        })
    {
        return Err(pending(
            "promoted source proof or card INSERT identity does not verify",
        ));
    }
    let (completion, _) = parse_origin_evidence(staged_evidence, tenant_id, card_id)?;
    let staged_digest = AuthorityRetainedStagedEvidence::new(staged_evidence.to_owned())
        .canonical_digest()
        .map_err(pending)?;
    let after_image_digest = record
        .after_image_digest
        .as_deref()
        .ok_or_else(|| pending("promoted source outcome has no after-image digest"))?;
    let binding = AuthorityCommitBinding {
        reservation_id: record.reservation_id.clone(),
        operation_id: record.operation_id.clone(),
        event_id: record.event_id.clone(),
        admission_proof_id: record.admission_proof_id.clone(),
        mutation_kind: record.mutation_kind,
        service_id: record.service_id.clone(),
        database_id: record.database_id.clone(),
        request_digest: record.request_binding_digest.clone(),
        source_commit_digest: record.source_commit_digest.clone(),
        before_image_digest: record.before_image_digest.clone(),
        after_image_digest: after_image_digest.to_owned(),
        source_outcome_digest: hex::encode(&source.outcome_digest),
        staged_evidence_digest: staged_digest.clone(),
    };
    binding.validate().map_err(pending)?;
    let now = record.committed_at;
    let inserted = sqlx::query(
        "INSERT INTO authority_empty_card_origin \
         (tenant_id, card_id, create_operation_id, reservation_id, event_id, admission_proof_id, \
          service_id, database_id, request_binding_digest, source_commit_digest, before_image_digest, \
          after_image_digest, source_outcome_digest, staged_evidence_digest, source_receipts, \
          staged_evidence, state, authority_terminal_receipt, authority_terminal_receipt_digest, \
          created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, UNHEX(?), UNHEX(?), UNHEX(?), UNHEX(?), UNHEX(?), \
          UNHEX(?), ?, ?, 'PENDING', NULL, NULL, ?, ?)",
    )
    .bind(tenant_id)
    .bind(card_id)
    .bind(&record.operation_id)
    .bind(&record.reservation_id)
    .bind(&record.event_id)
    .bind(&record.admission_proof_id)
    .bind(&record.service_id)
    .bind(&record.database_id)
    .bind(&record.request_binding_digest)
    .bind(&record.source_commit_digest)
    .bind(record.before_image_digest.as_deref().unwrap_or_default())
    .bind(record.after_image_digest.as_deref().unwrap_or_default())
    .bind(hex::encode(&source.outcome_digest))
    .bind(&staged_digest)
    .bind(serde_json::to_string(&source_receipts).map_err(pending)?)
    .bind(staged_evidence)
    .bind(now)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(pending)?;
    if inserted.rows_affected() != 1 {
        return Err(pending("origin association insert did not affect one row"));
    }
    completion_for_origin(tenant_id, card_id, &completion)?;
    Ok(())
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct OriginStoredRow {
    tenant_id: i64,
    card_id: i64,
    create_operation_id: String,
    reservation_id: String,
    event_id: String,
    admission_proof_id: String,
    service_id: String,
    database_id: String,
    request_binding_digest: Vec<u8>,
    source_commit_digest: Vec<u8>,
    before_image_digest: Vec<u8>,
    after_image_digest: Vec<u8>,
    source_outcome_digest: Vec<u8>,
    staged_evidence_digest: Vec<u8>,
    source_receipts: String,
    staged_evidence: String,
    state: String,
    authority_terminal_receipt: Option<String>,
    authority_terminal_receipt_digest: Option<Vec<u8>>,
    committed_at: i64,
}

const ORIGIN_COLUMNS: &str = "tenant_id, card_id, create_operation_id, reservation_id, event_id, \
    admission_proof_id, service_id, database_id, request_binding_digest, source_commit_digest, \
    before_image_digest, after_image_digest, source_outcome_digest, staged_evidence_digest, \
    CAST(source_receipts AS CHAR) AS source_receipts, CAST(staged_evidence AS CHAR) AS staged_evidence, \
    state, CAST(authority_terminal_receipt AS CHAR) AS authority_terminal_receipt, \
    authority_terminal_receipt_digest, created_at AS committed_at";

fn verify_origin_record(
    row: &OriginStoredRow,
) -> Result<
    (
        AuthorityCommitBinding,
        AuthorityEligibilityCompletionEvidence,
        AuthorityRetainedStagedEvidence,
        astral_types::AuthorityEligibilityCompletionReceipt,
    ),
    PolicyError,
> {
    if row.state != "COMPLETED" {
        return Err(pending("origin is not completed"));
    }
    let (completion, artifact) =
        parse_origin_evidence(&row.staged_evidence, row.tenant_id, row.card_id)?;
    let receipts: Vec<AuthoritySourceReceiptIdentity> =
        serde_json::from_str(&row.source_receipts).map_err(pending)?;
    if !receipts.iter().any(|receipt| {
        receipt.identity_kind == "user_card:INSERT" && receipt.identity == row.card_id.to_string()
    }) || artifact.delta.is_some()
    {
        return Err(pending(
            "origin does not retain its typed actual INSERT proof",
        ));
    }
    let retained = AuthorityRetainedStagedEvidence::new(row.staged_evidence.clone());
    let staged_digest = retained.canonical_digest().map_err(pending)?;
    if staged_digest != digest_hex(&row.staged_evidence_digest, "staged evidence")? {
        return Err(pending("origin retained staged digest does not verify"));
    }
    let record = AuthoritySourceOutcomeRecord {
        reservation_id: row.reservation_id.clone(),
        operation_id: row.create_operation_id.clone(),
        event_id: row.event_id.clone(),
        admission_proof_id: row.admission_proof_id.clone(),
        request_binding_digest: digest_hex(&row.request_binding_digest, "request binding")?,
        mutation_kind: AuthorityMutationKind::AuthorizationSource,
        service_id: row.service_id.clone(),
        database_id: row.database_id.clone(),
        source_commit_digest: digest_hex(&row.source_commit_digest, "source commit")?,
        before_image_digest: Some(digest_hex(&row.before_image_digest, "before image")?),
        after_image_digest: Some(digest_hex(&row.after_image_digest, "after image")?),
        source_receipts: receipts,
        committed_at: row.committed_at,
    };
    record.validate().map_err(pending)?;
    let expected_outcome_digest = hex::decode(
        canonical_outcome_digest(&record, Some(&row.staged_evidence)).map_err(pending)?,
    )
    .map_err(pending)?;
    if expected_outcome_digest
        != hex::decode(digest_hex(&row.source_outcome_digest, "source outcome")?)
            .map_err(pending)?
    {
        return Err(pending("origin source outcome digest does not verify"));
    }
    let binding = AuthorityCommitBinding {
        reservation_id: record.reservation_id.clone(),
        operation_id: record.operation_id.clone(),
        event_id: record.event_id.clone(),
        admission_proof_id: record.admission_proof_id.clone(),
        mutation_kind: record.mutation_kind,
        service_id: record.service_id.clone(),
        database_id: record.database_id.clone(),
        request_digest: record.request_binding_digest.clone(),
        source_commit_digest: record.source_commit_digest.clone(),
        before_image_digest: record.before_image_digest.clone(),
        after_image_digest: record.after_image_digest.clone().unwrap_or_default(),
        source_outcome_digest: digest_hex(&row.source_outcome_digest, "source outcome")?,
        staged_evidence_digest: staged_digest,
    };
    binding.validate().map_err(pending)?;
    let receipt: astral_types::AuthorityEligibilityCompletionReceipt = serde_json::from_str(
        row.authority_terminal_receipt
            .as_deref()
            .ok_or_else(|| pending("origin terminal receipt is missing"))?,
    )
    .map_err(pending)?;
    receipt.validate().map_err(pending)?;
    let receipt_digest = receipt_digest(&receipt)?;
    if receipt.binding != binding
        || receipt.completion != completion
        || receipt.reservation_id != row.reservation_id
        || receipt.operation_id != row.create_operation_id
        || receipt.event_id != row.event_id
        || receipt_digest
            != digest_hex(
                row.authority_terminal_receipt_digest
                    .as_deref()
                    .ok_or_else(|| pending("origin terminal receipt digest is missing"))?,
                "terminal receipt",
            )?
    {
        return Err(pending(
            "origin immutable terminal receipt differs from its exact source",
        ));
    }
    Ok((binding, completion, retained, receipt))
}

/// Persist the exact AuthorityClient-validated terminal receipt under a CAS.
/// The caller passes the same response validated by its authority-completion client.
pub async fn complete_empty_card_origin_in_tx(
    tx: &mut Transaction<'_, MySql>,
    response: &AuthorityEligibilityCompletionResponse,
) -> Result<(), PolicyError> {
    response.validate().map_err(pending)?;
    let row_query =
        format!("SELECT {ORIGIN_COLUMNS} FROM {ORIGIN_TABLE} WHERE reservation_id = ? FOR UPDATE");
    let row: OriginStoredRow = sqlx::query_as(&row_query)
        .bind(&response.receipt.reservation_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(pending)?
        .ok_or_else(|| pending("origin association is missing"))?;
    if row.state == "COMPLETED" {
        let (_, _, _, receipt) = verify_origin_record(&row)?;
        if receipt == response.receipt {
            return Ok(());
        }
        return Err(pending(
            "completed origin receipt is immutable and cannot be replaced",
        ));
    }
    if row.state != "PENDING" {
        return Err(pending("origin state is not pending"));
    }
    let (_, completion) = verify_pending_origin_record(&row)?;
    if response.receipt.binding.reservation_id != row.reservation_id
        || response.receipt.binding.operation_id != row.create_operation_id
        || response.receipt.binding.event_id != row.event_id
        || response.receipt.binding.admission_proof_id != row.admission_proof_id
        || response.receipt.binding.service_id != row.service_id
        || response.receipt.binding.database_id != row.database_id
        || response.receipt.binding.request_digest
            != digest_hex(&row.request_binding_digest, "request binding")?
        || response.receipt.completion != completion
    {
        return Err(pending(
            "authority terminal does not match exact pending origin binding",
        ));
    }
    let receipt_json = serde_json::to_string(&response.receipt).map_err(pending)?;
    let digest = receipt_digest(&response.receipt)?;
    let updated = sqlx::query(
        "UPDATE authority_empty_card_origin SET state = 'COMPLETED', authority_terminal_receipt = ?, \
         authority_terminal_receipt_digest = UNHEX(?), updated_at = ? \
         WHERE tenant_id = ? AND card_id = ? AND reservation_id = ? AND state = 'PENDING' \
         AND authority_terminal_receipt IS NULL AND authority_terminal_receipt_digest IS NULL",
    )
    .bind(receipt_json)
    .bind(digest)
    .bind(response.receipt.completed_at)
    .bind(row.tenant_id)
    .bind(row.card_id)
    .bind(&row.reservation_id)
    .execute(&mut **tx)
    .await
    .map_err(pending)?;
    if updated.rows_affected() != 1 {
        return Err(pending("origin terminal receipt CAS did not apply"));
    }
    Ok(())
}

fn verify_pending_origin_record(
    row: &OriginStoredRow,
) -> Result<
    (
        AuthorityCommitBinding,
        AuthorityEligibilityCompletionEvidence,
    ),
    PolicyError,
> {
    if row.state != "PENDING"
        || row.authority_terminal_receipt.is_some()
        || row.authority_terminal_receipt_digest.is_some()
    {
        return Err(pending("origin is not an uncompleted pending row"));
    }
    let (completion, artifact) =
        parse_origin_evidence(&row.staged_evidence, row.tenant_id, row.card_id)?;
    let receipts: Vec<AuthoritySourceReceiptIdentity> =
        serde_json::from_str(&row.source_receipts).map_err(pending)?;
    if !receipts.iter().any(|receipt| {
        receipt.identity_kind == "user_card:INSERT" && receipt.identity == row.card_id.to_string()
    }) || artifact.delta.is_some()
    {
        return Err(pending(
            "pending origin has no actual empty-card INSERT evidence",
        ));
    }
    let retained = AuthorityRetainedStagedEvidence::new(row.staged_evidence.clone());
    let staged_digest = retained.canonical_digest().map_err(pending)?;
    if staged_digest != digest_hex(&row.staged_evidence_digest, "staged evidence")? {
        return Err(pending("pending origin staged digest differs"));
    }
    let record = AuthoritySourceOutcomeRecord {
        reservation_id: row.reservation_id.clone(),
        operation_id: row.create_operation_id.clone(),
        event_id: row.event_id.clone(),
        admission_proof_id: row.admission_proof_id.clone(),
        request_binding_digest: digest_hex(&row.request_binding_digest, "request binding")?,
        mutation_kind: AuthorityMutationKind::AuthorizationSource,
        service_id: row.service_id.clone(),
        database_id: row.database_id.clone(),
        source_commit_digest: digest_hex(&row.source_commit_digest, "source commit")?,
        before_image_digest: Some(digest_hex(&row.before_image_digest, "before image")?),
        after_image_digest: Some(digest_hex(&row.after_image_digest, "after image")?),
        source_receipts: receipts,
        committed_at: row.committed_at,
    };
    record.validate().map_err(pending)?;
    let actual = hex::decode(
        canonical_outcome_digest(&record, Some(&row.staged_evidence)).map_err(pending)?,
    )
    .map_err(pending)?;
    if actual
        != hex::decode(digest_hex(&row.source_outcome_digest, "source outcome")?)
            .map_err(pending)?
    {
        return Err(pending(
            "pending origin source outcome digest does not verify",
        ));
    }
    let binding = AuthorityCommitBinding {
        reservation_id: record.reservation_id,
        operation_id: record.operation_id,
        event_id: record.event_id,
        admission_proof_id: record.admission_proof_id,
        mutation_kind: record.mutation_kind,
        service_id: record.service_id,
        database_id: record.database_id,
        request_digest: record.request_binding_digest,
        source_commit_digest: record.source_commit_digest,
        before_image_digest: record.before_image_digest,
        after_image_digest: record.after_image_digest.unwrap_or_default(),
        source_outcome_digest: digest_hex(&row.source_outcome_digest, "source outcome")?,
        staged_evidence_digest: staged_digest,
    };
    binding.validate().map_err(pending)?;
    Ok((binding, completion))
}

/// Opaque proof only constructed after a fresh AuthorityClient reconciliation verifies the
/// persisted immutable receipt and the full staged source binding.
#[derive(Debug)]
pub(super) struct VerifiedEmptyCardOrigin {
    tenant_id: i64,
    card_id: i64,
    receipt_digest: String,
}

impl VerifiedEmptyCardOrigin {
    pub(super) fn proves(&self, tenant_id: i64, card_id: i64) -> bool {
        self.tenant_id == tenant_id && self.card_id == card_id && self.receipt_digest.len() == 64
    }
}

/// Reconcile outside the DB transaction; network I/O is never performed while DB consistency
/// locks are held. Local COMPLETED alone is insufficient to construct this token.
pub(super) async fn reconcile_empty_card_origin(
    pool: &MySqlPool,
    client: &AuthorityClient,
    tenant_id: i64,
    card_id: i64,
) -> Result<Option<VerifiedEmptyCardOrigin>, PolicyError> {
    let mut tx = pool.begin().await.map_err(pending)?;
    let query =
        format!("SELECT {ORIGIN_COLUMNS} FROM {ORIGIN_TABLE} WHERE tenant_id = ? AND card_id = ?");
    let row: Option<OriginStoredRow> = sqlx::query_as(&query)
        .bind(tenant_id)
        .bind(card_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(pending)?;
    let Some(row) = row else {
        tx.rollback().await.map_err(pending)?;
        return Ok(None);
    };
    let (binding, completion, retained, local_receipt) = verify_origin_record(&row)?;
    tx.rollback().await.map_err(pending)?;
    let reconciled = client
        .reconcile_eligibility(binding.clone(), completion.clone(), retained)
        .await
        .map_err(pending)?;
    reconciled.validate().map_err(pending)?;
    if reconciled.receipt != local_receipt
        || reconciled.receipt.binding != binding
        || reconciled.receipt.completion != completion
        || reconciled.receipt.reservation_id != row.reservation_id
        || reconciled.receipt.operation_id != row.create_operation_id
        || reconciled.receipt.event_id != row.event_id
    {
        return Err(pending(
            "current authority reconciliation differs from the immutable origin receipt",
        ));
    }
    Ok(Some(VerifiedEmptyCardOrigin {
        tenant_id,
        card_id,
        receipt_digest: receipt_digest(&reconciled.receipt)?,
    }))
}
