//! Same-transaction binding of an admitted mutation to its actual source evidence.

use astral_types::{
    AuthorityMutationKind, AuthorityPrepareResponse, AuthorityStagedSourceEvidence,
    AuthorizationAdmission, PolicyError,
};
use sqlx::{MySql, Transaction};

use crate::authority_source_outcome::{
    promote_authority_source_outcome_tx, stage_authority_source_outcome_tx,
    AuthoritySourceOutcomeEvidence, AuthoritySourceOutcomeStaged,
};

/// Stage and promote only after the source owner has captured actual immutable
/// receipts and consumed the admission in this transaction. No network I/O occurs.
pub async fn stage_admitted_source_outcome_in_tx(
    tx: &mut Transaction<'_, MySql>,
    admission: &AuthorizationAdmission,
    expected_kind: AuthorityMutationKind,
    staged_evidence_json: String,
    evidence: &AuthoritySourceOutcomeEvidence,
) -> Result<(), PolicyError> {
    stage_admitted_source_outcome_with_coverage_in_tx(
        tx,
        admission,
        expected_kind,
        staged_evidence_json,
        evidence,
        None,
    )
    .await
}

/// The source owner may supply complete finite coverage captured in this same
/// transaction. The reservation remains GLOBAL until every declared publication
/// is certified; this declaration never narrows the in-flight barrier.
pub async fn stage_admitted_source_outcome_with_coverage_in_tx(
    tx: &mut Transaction<'_, MySql>,
    admission: &AuthorizationAdmission,
    expected_kind: AuthorityMutationKind,
    staged_evidence_json: String,
    evidence: &AuthoritySourceOutcomeEvidence,
    coverage: Option<astral_types::AuthorityStagedScopeCoverage>,
) -> Result<(), PolicyError> {
    if expected_kind == AuthorityMutationKind::ProtectedBusiness && coverage.is_some() {
        return Err(pending(
            "protected business outcomes cannot declare authorization coverage",
        ));
    }
    if let Some(coverage) = &coverage {
        coverage
            .validate()
            .map_err(|error| pending(error.to_string()))?;
    }
    let proof = admission.proof();
    let binding = proof
        .request_binding_digest
        .as_deref()
        .ok_or_else(|| pending("source proof has no request binding"))?;
    let row: Option<String> = sqlx::query_scalar(
        "SELECT CAST(reservation_json AS CHAR) FROM authorization_source_reservation \
         WHERE operation_id = ? AND proof_id = ? AND request_digest = UNHEX(?) \
         AND disposition = 'RESERVED' FOR UPDATE",
    )
    .bind(&proof.operation_id)
    .bind(&proof.proof_id)
    .bind(binding)
    .fetch_optional(&mut **tx)
    .await
    .map_err(database)?;
    let response: AuthorityPrepareResponse =
        serde_json::from_str(&row.ok_or_else(|| pending("source reservation is missing"))?)
            .map_err(|_| pending("source reservation cannot be decoded"))?;
    response
        .validate()
        .map_err(|error| pending(error.to_string()))?;
    let reservation = &response.reservation;
    let intent = &reservation.intent;
    if intent.operation_id != proof.operation_id
        || intent.event_id != proof.event_id
        || intent.admission_proof_id != proof.proof_id
        || intent.request_digest != binding
        || intent.mutation_kind != expected_kind
        || reservation.state != astral_types::AuthorityReservationState::Reserved
    {
        return Err(pending(
            "source outcome differs from its approved reservation",
        ));
    }
    let consumed: Option<i64> = sqlx::query_scalar(
        "SELECT consumed_at FROM authorization_admission_use \
         WHERE proof_id = ? AND request_nonce = ? AND operation_id = ? AND event_id = ? FOR UPDATE",
    )
    .bind(&proof.proof_id)
    .bind(&proof.request_nonce)
    .bind(&proof.operation_id)
    .bind(&proof.event_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(database)?;
    if consumed.is_none() {
        return Err(pending(
            "source outcome has no same-transaction admission consumption",
        ));
    }
    let source_evidence = AuthorityStagedSourceEvidence {
        coverage,
        evidence: serde_json::from_str(&staged_evidence_json)
            .map_err(|_| pending("source owner evidence cannot be decoded"))?,
    };
    source_evidence
        .validate()
        .map_err(|error| pending(error.to_string()))?;
    let staged_evidence_json = serde_json::to_string(&source_evidence)
        .map_err(|_| pending("source evidence envelope cannot be encoded"))?;
    let committed_at: i64 = sqlx::query_scalar("SELECT CAST(UNIX_TIMESTAMP() AS SIGNED)")
        .fetch_one(&mut **tx)
        .await
        .map_err(database)?;
    let staged = AuthoritySourceOutcomeStaged {
        reservation_id: reservation.reservation_id.clone(),
        operation_id: proof.operation_id.clone(),
        event_id: proof.event_id.clone(),
        admission_proof_id: proof.proof_id.clone(),
        request_binding_digest: binding.to_owned(),
        mutation_kind: expected_kind,
        service_id: intent.service_id.clone(),
        database_id: intent.database_id.clone(),
        staged_evidence_json,
        committed_at,
    };
    stage_authority_source_outcome_tx(tx, &staged).await?;
    promote_authority_source_outcome_tx(tx, &staged.reservation_id, evidence).await
}

fn pending(message: impl Into<String>) -> PolicyError {
    PolicyError::Repository(message.into())
}

fn database(error: sqlx::Error) -> PolicyError {
    pending(format!("source outcome binding failed: {error}"))
}
