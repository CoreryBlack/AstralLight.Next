//! Durable source-outcome owner for the external authority control plane.
//!
//! One row of [`authority_source_outcome`] is committed in the SAME source
//! transaction as the mutation it describes (via
//! [`enqueue_authority_source_outcome_tx`], the hook the shared admission-use
//! owner calls inside its transaction). The row is the exact binding between:
//! the stable authority reservation/proof/operation identity, the registered
//! service/database owner, the ACTUAL source receipt identities produced by
//! the transaction, and the real before/after image digests supplied by the
//! writer of the affected rows.
//!
//! Outside the transaction, [`AuthoritySourceOutcomeReconciler`] is a bounded
//! lease/CAS/generation reconciler: it leases pending rows, reads each row
//! back durably, and calls the authority client `commit` with exactly the
//! read-back values. Failure modes are fail-closed:
//! - An unknown commit outcome leaves the row PENDING (lease expires; the
//!   generation fence prevents lost updates). The source transaction is never
//!   replayed: the reconciler only re-reads this table and re-issues the
//!   idempotent authority commit, which the authority's own reservation state
//!   machine and one-use consume rules make safe.
//! - Digest or identity mismatches, unknown reservations, and expired-lease
//!   commits are quarantined for operators; they are never retried silently.
//! - Protected-business outcomes terminate on the proven source commit;
//!   authorization-source outcomes remain committed rows that the publisher
//!   certifies through the reservation lifecycle.
//!
//! This module never derives an after-image from an actor authorization
//! snapshot and never equates outbox events with the request event: digests
//! are supplied by the writer over the actual affected rows (see
//! [`source_image_digest`]) and receipt identities are the actual durable ids.

use std::sync::Arc;

use astral_authority::client::AuthorityClient;
use astral_types::{AuthorityMutationKind, AuthoritySourceCommitRecord, AUTHORIZATION_EDITION};
use sha2::{Digest, Sha256};
use sqlx::{MySql, Pool, Transaction};

use astral_types::PolicyError;

const OUTCOME_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_SOURCE_OUTCOME_V7\0";
const MAX_RECEIPTS: usize = 1024;
const MAX_TEXT_LEN: usize = 128;

/// One actual durable receipt identity produced by the source transaction.
///
/// `identity_kind` names the receipt class (for example the admission-use row
/// identity, an outbox/message identity, or a source head revision identity);
/// `identity` is the exact durable id. The authority never receives raw rows —
/// these identities bind the commit to what the source transaction actually
/// wrote, and are validated as canonical bounded text, not free prose.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySourceReceiptIdentity {
    pub identity_kind: String,
    pub identity: String,
}

impl AuthoritySourceReceiptIdentity {
    pub fn validate(&self) -> Result<(), PolicyError> {
        canonical_text(&self.identity_kind, "identity_kind")?;
        canonical_text(&self.identity, "identity")?;
        Ok(())
    }
}

/// The committed-in-transaction source outcome record.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySourceOutcomeRecord {
    pub reservation_id: String,
    pub operation_id: String,
    pub event_id: String,
    pub admission_proof_id: String,
    /// The immutable policy-request digest the admission proof was minted for.
    pub request_binding_digest: String,
    pub mutation_kind: AuthorityMutationKind,
    /// Registered trusted source process identity.
    pub service_id: String,
    /// Registered database identity that executed the transaction.
    pub database_id: String,
    /// SHA-256 over the durable source commit evidence supplied by the writer.
    pub source_commit_digest: String,
    /// SHA-256 over the actual before-image of the affected rows; absent only
    /// for first publications. Never derived from an authorization snapshot.
    pub before_image_digest: Option<String>,
    /// SHA-256 over the actual after-image of the affected rows. A NULL here
    /// can never be committed to the authority: the reconciler leaves such
    /// rows pending until the writer supplies the real digest.
    pub after_image_digest: Option<String>,
    /// The actual source receipt identities of this transaction.
    pub source_receipts: Vec<AuthoritySourceReceiptIdentity>,
    /// Wall clock recorded inside the source transaction.
    pub committed_at: i64,
}

impl AuthoritySourceOutcomeRecord {
    pub fn validate(&self) -> Result<(), PolicyError> {
        canonical_text(&self.reservation_id, "reservation_id")?;
        canonical_text(&self.operation_id, "operation_id")?;
        canonical_text(&self.event_id, "event_id")?;
        canonical_text(&self.admission_proof_id, "admission_proof_id")?;
        sha256_hex(&self.request_binding_digest, "request_binding_digest")?;
        canonical_text(&self.service_id, "service_id")?;
        canonical_text(&self.database_id, "database_id")?;
        sha256_hex(&self.source_commit_digest, "source_commit_digest")?;
        if let Some(before) = &self.before_image_digest {
            sha256_hex(before, "before_image_digest")?;
        }
        // The after-image digest is the actual content identity of the commit;
        // a missing digest can never reach the authority.
        if let Some(after) = &self.after_image_digest {
            sha256_hex(after, "after_image_digest")?;
        }
        if self.source_receipts.is_empty() || self.source_receipts.len() > MAX_RECEIPTS {
            return Err(PolicyError::InvalidContext(
                "source outcome requires one or more actual receipt identities".into(),
            ));
        }
        for receipt in &self.source_receipts {
            receipt.validate()?;
        }
        if self.committed_at <= 0 {
            return Err(PolicyError::InvalidContext(
                "source outcome committed_at must be a positive unix timestamp".into(),
            ));
        }
        Ok(())
    }

    /// Canonical, injective digest over the full record (no staged evidence
    /// attached). Stored with the row and re-derived on read-back so a
    /// corrupted row can never be committed.
    pub fn outcome_digest(&self) -> Result<String, PolicyError> {
        canonical_outcome_digest(self, None)
    }
}

fn canonical_staged_evidence(value: &str) -> Result<String, PolicyError> {
    if value.len() > 256 * 1024 {
        return Err(PolicyError::InvalidContext(
            "staged evidence exceeds its byte bound".into(),
        ));
    }
    let value: serde_json::Value = serde_json::from_str(value)
        .map_err(|_| PolicyError::InvalidContext("staged evidence is invalid JSON".into()))?;
    serde_json::to_string(&value)
        .map_err(|_| PolicyError::InvalidContext("staged evidence cannot be encoded".into()))
}

fn staged_evidence_digest(value: &str) -> Result<String, PolicyError> {
    Ok(hex::encode(Sha256::digest(
        canonical_staged_evidence(value)?.as_bytes(),
    )))
}

/// Canonical digest over one record plus the RETAINED typed staged evidence.
///
/// The durable source proof is the combination: the promoted record alone is
/// not sufficient evidence, so the read-back digest always covers both the
/// staged evidence (delta/source/invalidation identities the writer serialized
/// in the transaction) and the promoted commit evidence.
pub fn canonical_outcome_digest(
    record: &AuthoritySourceOutcomeRecord,
    staged_evidence_json: Option<&str>,
) -> Result<String, PolicyError> {
    fn field(bytes: &mut Vec<u8>, value: &str) {
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    record.validate()?;
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(OUTCOME_DOMAIN);
    field(&mut bytes, &AUTHORIZATION_EDITION.to_string());
    field(&mut bytes, &record.reservation_id);
    field(&mut bytes, &record.operation_id);
    field(&mut bytes, &record.event_id);
    field(&mut bytes, &record.admission_proof_id);
    field(&mut bytes, &record.request_binding_digest);
    field(&mut bytes, record.mutation_kind.as_text());
    field(&mut bytes, &record.service_id);
    field(&mut bytes, &record.database_id);
    field(&mut bytes, &record.source_commit_digest);
    field(
        &mut bytes,
        record.before_image_digest.as_deref().unwrap_or("-"),
    );
    field(
        &mut bytes,
        record.after_image_digest.as_deref().unwrap_or("-"),
    );
    field(&mut bytes, &record.source_receipts.len().to_string());
    for receipt in &record.source_receipts {
        field(&mut bytes, &receipt.identity_kind);
        field(&mut bytes, &receipt.identity);
    }
    field(&mut bytes, &record.committed_at.to_string());
    match staged_evidence_json {
        Some(value) => field(&mut bytes, &canonical_staged_evidence(value)?),
        None => field(&mut bytes, "-"),
    }
    Ok(hex::encode(Sha256::digest(&bytes)))
}

/// The explicit STAGED row: the binding and owners are written inside the
/// source transaction together with the writer's typed staged evidence (the
/// serialized delta/source/invalidation identities and hashes the owning
/// writer produced). A STAGED row is NOT eligible for reconciliation: it
/// carries no authority-commit evidence yet and must never be presented to
/// the control plane.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySourceOutcomeStaged {
    pub reservation_id: String,
    pub operation_id: String,
    pub event_id: String,
    pub admission_proof_id: String,
    /// The immutable policy-request digest the admission proof was minted for.
    pub request_binding_digest: String,
    pub mutation_kind: AuthorityMutationKind,
    pub service_id: String,
    pub database_id: String,
    /// Typed durable source proof supplied by the writer: the serialized
    /// staged delta/source/invalidation identity+hash set, bounded JSON.
    pub staged_evidence_json: String,
    /// Wall clock recorded inside the source transaction.
    pub committed_at: i64,
}

impl AuthoritySourceOutcomeStaged {
    pub fn validate(&self) -> Result<(), PolicyError> {
        canonical_text(&self.reservation_id, "reservation_id")?;
        canonical_text(&self.operation_id, "operation_id")?;
        canonical_text(&self.event_id, "event_id")?;
        canonical_text(&self.admission_proof_id, "admission_proof_id")?;
        sha256_hex(&self.request_binding_digest, "request_binding_digest")?;
        canonical_text(&self.service_id, "service_id")?;
        canonical_text(&self.database_id, "database_id")?;
        if self.staged_evidence_json.is_empty() || self.staged_evidence_json.len() > 256 * 1024 {
            return Err(PolicyError::InvalidContext(
                "staged evidence must be bounded canonical JSON".into(),
            ));
        }
        if self.committed_at <= 0 {
            return Err(PolicyError::InvalidContext(
                "staged outcome committed_at must be a positive unix timestamp".into(),
            ));
        }
        Ok(())
    }

    /// Canonical digest over the staged binding and evidence.
    pub fn staged_digest(&self) -> Result<String, PolicyError> {
        fn field(bytes: &mut Vec<u8>, value: &str) {
            bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
        self.validate()?;
        let mut bytes = Vec::with_capacity(384);
        bytes.extend_from_slice(OUTCOME_DOMAIN);
        bytes.extend_from_slice(b"STAGED\0");
        field(&mut bytes, &self.reservation_id);
        field(&mut bytes, &self.operation_id);
        field(&mut bytes, &self.event_id);
        field(&mut bytes, &self.admission_proof_id);
        field(&mut bytes, &self.request_binding_digest);
        field(&mut bytes, self.mutation_kind.as_text());
        field(&mut bytes, &self.service_id);
        field(&mut bytes, &self.database_id);
        field(
            &mut bytes,
            &canonical_staged_evidence(&self.staged_evidence_json)?,
        );
        field(&mut bytes, &self.committed_at.to_string());
        Ok(hex::encode(Sha256::digest(&bytes)))
    }
}

/// The complete, typed durable source proof required to promote a staged row
/// to reconcilable PENDING. Every field is an ACTUAL value: the commit digest
/// over the durable source evidence, the before/after image digests over the
/// ACTUAL affected rows read/written by the transaction, and the real durable
/// receipt identities. Promotion refuses empty receipts or missing digests:
/// no after-image may be manufactured from an actor authorization snapshot.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySourceOutcomeEvidence {
    pub source_commit_digest: String,
    pub before_image_digest: String,
    pub after_image_digest: String,
    pub source_receipts: Vec<AuthoritySourceReceiptIdentity>,
}

impl AuthoritySourceOutcomeEvidence {
    pub fn validate(&self) -> Result<(), PolicyError> {
        sha256_hex(&self.source_commit_digest, "source_commit_digest")?;
        sha256_hex(&self.before_image_digest, "before_image_digest")?;
        sha256_hex(&self.after_image_digest, "after_image_digest")?;
        if self.source_receipts.is_empty() || self.source_receipts.len() > MAX_RECEIPTS {
            return Err(PolicyError::InvalidContext(
                "source outcome promotion requires the actual receipt identities".into(),
            ));
        }
        for receipt in &self.source_receipts {
            receipt.validate()?;
        }
        Ok(())
    }
}

/// SHA-256 over the exact canonical bytes of one source image.
///
/// The caller serializes the ACTUAL affected source rows (before or after the
/// transaction) and passes those bytes here. The authority control plane never
/// sees actor authorization snapshots as a substitute for this digest.
pub fn source_image_digest(content: &[u8]) -> String {
    hex::encode(Sha256::digest(content))
}

/// Stage the source outcome row INSIDE the caller's source transaction.
///
/// Called by the source owner where the typed staged proof is available, so
/// the staged binding commits or rolls back atomically with the mutation.
/// The row lands in status `STAGED`: not reconcilable, not presented to the
/// authority. Unique keys on `reservation_id` and `admission_proof_id` make a
/// duplicate stage fail the transaction instead of widening the binding.
pub async fn stage_authority_source_outcome_tx(
    tx: &mut Transaction<'_, MySql>,
    staged: &AuthoritySourceOutcomeStaged,
) -> Result<(), PolicyError> {
    staged.validate()?;
    let staged_digest = staged.staged_digest()?;
    sqlx::query(
        "INSERT INTO authority_source_outcome \
         (reservation_id, operation_id, event_id, admission_proof_id, request_binding_digest, \
          mutation_kind, service_id, database_id, source_receipts, staged_evidence, status, \
          generation, outcome_digest, committed_at, created_at, updated_at) \
         VALUES (?, ?, ?, ?, UNHEX(?), ?, ?, ?, NULL, ?, 'STAGED', 0, UNHEX(?), ?, ?, ?)",
    )
    .bind(&staged.reservation_id)
    .bind(&staged.operation_id)
    .bind(&staged.event_id)
    .bind(&staged.admission_proof_id)
    .bind(&staged.request_binding_digest)
    .bind(staged.mutation_kind.as_text())
    .bind(&staged.service_id)
    .bind(&staged.database_id)
    .bind(&staged.staged_evidence_json)
    .bind(&staged_digest)
    .bind(staged.committed_at)
    .bind(staged.committed_at)
    .bind(staged.committed_at)
    .execute(&mut **tx)
    .await
    .map_err(|error| map_sqlx_error(error, "stage source outcome"))?;
    Ok(())
}

/// Promote one staged row to reconcilable PENDING with the complete typed
/// durable source proof. Call this from the writer once the transaction has
/// pinned the actual before/after image digests and the real receipt
/// identities (same transaction or a later one; the update is CAS-guarded on
/// the STAGED status so a row is promoted exactly once).
///
/// The resulting row's canonical self-digest covers the staged binding and
/// the promoted evidence, so the reconciler's exact read-back can verify both.
pub async fn promote_authority_source_outcome_tx(
    tx: &mut Transaction<'_, MySql>,
    reservation_id: &str,
    evidence: &AuthoritySourceOutcomeEvidence,
) -> Result<(), PolicyError> {
    evidence.validate()?;
    let row: AuthoritySourceOutcomeRow = sqlx::query_as(
        "SELECT reservation_id, operation_id, event_id, admission_proof_id, \
         request_binding_digest, mutation_kind, service_id, database_id, \
         source_commit_digest, before_image_digest, after_image_digest, source_receipts, \
         staged_evidence, status, attempts, generation, outcome_digest, committed_at \
         FROM authority_source_outcome WHERE reservation_id = ? FOR UPDATE",
    )
    .bind(reservation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| map_sqlx_error(error, "read staged source outcome"))?
    .ok_or_else(|| {
        PolicyError::InvalidContext("staged source outcome row does not exist".into())
    })?;
    if row.status != "STAGED" {
        return Err(PolicyError::InvalidContext(format!(
            "source outcome row is not staged (status {})",
            row.status
        )));
    }
    // Integrity check before promotion: the stored digest must be exactly the
    // staged digest of the durable binding + retained evidence, so a row that
    // was tampered with after staging can never be promoted.
    let staged = AuthoritySourceOutcomeStaged {
        reservation_id: row.reservation_id.clone(),
        operation_id: row.operation_id.clone(),
        event_id: row.event_id.clone(),
        admission_proof_id: row.admission_proof_id.clone(),
        request_binding_digest: hex::encode(&row.request_binding_digest),
        mutation_kind: parse_mutation_kind(&row.mutation_kind)?,
        service_id: row.service_id.clone(),
        database_id: row.database_id.clone(),
        staged_evidence_json: row.staged_evidence.clone().ok_or_else(|| {
            PolicyError::InvalidContext("staged outcome row lacks its typed evidence".into())
        })?,
        committed_at: row.committed_at,
    };
    let expected_staged_digest = hex::decode(staged.staged_digest()?)
        .map_err(|_| PolicyError::InvalidContext("staged digest encoding failed".into()))?;
    if row.outcome_digest != expected_staged_digest {
        return Err(PolicyError::InvalidContext(
            "staged source outcome row failed its staged digest".into(),
        ));
    }

    // Rebuild the promoted record from the durable staged binding (exact
    // read-back inside the tx) plus the complete evidence.
    let record = AuthoritySourceOutcomeRecord {
        reservation_id: row.reservation_id.clone(),
        operation_id: row.operation_id.clone(),
        event_id: row.event_id.clone(),
        admission_proof_id: row.admission_proof_id.clone(),
        request_binding_digest: hex::encode(&row.request_binding_digest),
        mutation_kind: parse_mutation_kind(&row.mutation_kind)?,
        service_id: row.service_id.clone(),
        database_id: row.database_id.clone(),
        source_commit_digest: evidence.source_commit_digest.clone(),
        before_image_digest: Some(evidence.before_image_digest.clone()),
        after_image_digest: Some(evidence.after_image_digest.clone()),
        source_receipts: evidence.source_receipts.clone(),
        committed_at: row.committed_at,
    };
    record.validate()?;
    // The promoted row keeps the typed staged evidence; its durable digest is
    // the COMBINED digest over record + retained evidence, so the exact
    // read-back covers both.
    let outcome_digest =
        canonical_outcome_digest(&record, Some(staged.staged_evidence_json.as_str()))?;
    let receipts_json = serde_json::to_string(&record.source_receipts).map_err(|_| {
        PolicyError::InvalidContext("source receipt identities cannot be encoded".into())
    })?;

    let promoted = sqlx::query(
        "UPDATE authority_source_outcome \
         SET source_commit_digest = UNHEX(?), before_image_digest = UNHEX(?), \
             after_image_digest = UNHEX(?), source_receipts = ?, status = 'PENDING', \
             outcome_digest = UNHEX(?), updated_at = ? \
         WHERE reservation_id = ? AND status = 'STAGED'",
    )
    .bind(&record.source_commit_digest)
    .bind(record.before_image_digest.clone().unwrap_or_default())
    .bind(record.after_image_digest.clone().unwrap_or_default())
    .bind(&receipts_json)
    .bind(&outcome_digest)
    .bind(record.committed_at)
    .bind(reservation_id)
    .execute(&mut **tx)
    .await
    .map_err(|error| map_sqlx_error(error, "promote source outcome"))?;
    if promoted.rows_affected() != 1 {
        return Err(PolicyError::InvalidContext(
            "source outcome row was promoted concurrently; refusing to widen the binding".into(),
        ));
    }
    Ok(())
}

/// Read back one outcome row exactly as it is durably stored. This is the ONLY
/// input the reconciler uses to build an authority commit.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct AuthoritySourceOutcomeRow {
    pub reservation_id: String,
    pub operation_id: String,
    pub event_id: String,
    pub admission_proof_id: String,
    pub request_binding_digest: Vec<u8>,
    pub mutation_kind: String,
    pub service_id: String,
    pub database_id: String,
    /// NULL while STAGED; set at promotion.
    pub source_commit_digest: Option<Vec<u8>>,
    pub before_image_digest: Option<Vec<u8>>,
    pub after_image_digest: Option<Vec<u8>>,
    /// NULL while STAGED; set at promotion.
    pub source_receipts: Option<String>,
    /// The typed staged evidence is RETAINED after promotion so the durable
    /// source proof stays auditable; the reconciler includes it in the
    /// read-back digest verification.
    pub staged_evidence: Option<String>,
    pub status: String,
    pub attempts: u32,
    pub generation: u64,
    /// Raw 32 bytes: the staged digest while STAGED, the combined
    /// record+evidence digest while PENDING/COMMITTED.
    pub outcome_digest: Vec<u8>,
    pub committed_at: i64,
}

impl AuthoritySourceOutcomeRow {
    /// Identity of the retained typed evidence, independent of JSON storage formatting.
    pub(crate) fn staged_digest(&self) -> Result<String, PolicyError> {
        staged_evidence_digest(self.staged_evidence.as_deref().ok_or_else(|| {
            PolicyError::InvalidContext("outcome row lacks retained source evidence".into())
        })?)
    }

    /// Rebuild the record from the durable row and verify its self-digest so
    /// a corrupted row is quarantined instead of committed to the authority.
    /// STAGED rows are refused: they carry no commit evidence yet.
    pub fn to_verified_record(&self) -> Result<AuthoritySourceOutcomeRecord, PolicyError> {
        if self.status != "PENDING" {
            return Err(PolicyError::InvalidContext(format!(
                "outcome row is not reconcilable (status {})",
                self.status
            )));
        }
        self.verify_promoted_record()
    }

    /// Publication workers accept only the exact acknowledged status of their
    /// current leg. Neither entry point admits PENDING source acknowledgement.
    pub(crate) fn to_verified_publication_record(
        &self,
        expected_status: &str,
    ) -> Result<AuthoritySourceOutcomeRecord, PolicyError> {
        if !matches!(expected_status, "COMMITTED" | "PUBLISHED") || self.status != expected_status {
            return Err(PolicyError::InvalidContext(
                "publication requires its exact acknowledged source outcome status".into(),
            ));
        }
        self.verify_promoted_record()
    }

    fn verify_promoted_record(&self) -> Result<AuthoritySourceOutcomeRecord, PolicyError> {
        // Every promoted row must carry the complete actual source evidence.
        let source_commit_digest = self.source_commit_digest.as_deref().ok_or_else(|| {
            PolicyError::InvalidContext("pending outcome row lacks the source commit digest".into())
        })?;
        let before_image_digest = self.before_image_digest.as_deref().ok_or_else(|| {
            PolicyError::InvalidContext(
                "pending outcome row lacks the actual before-image digest".into(),
            )
        })?;
        let after_image_digest = self.after_image_digest.as_deref().ok_or_else(|| {
            PolicyError::InvalidContext(
                "pending outcome row lacks the actual after-image digest".into(),
            )
        })?;
        let source_receipts = self.source_receipts.as_deref().ok_or_else(|| {
            PolicyError::InvalidContext(
                "pending outcome row lacks the actual receipt identities".into(),
            )
        })?;
        let record = AuthoritySourceOutcomeRecord {
            reservation_id: self.reservation_id.clone(),
            operation_id: self.operation_id.clone(),
            event_id: self.event_id.clone(),
            admission_proof_id: self.admission_proof_id.clone(),
            request_binding_digest: hex32(&self.request_binding_digest, "request_binding")?,
            mutation_kind: parse_mutation_kind(&self.mutation_kind)?,
            service_id: self.service_id.clone(),
            database_id: self.database_id.clone(),
            source_commit_digest: hex32(source_commit_digest, "source_commit")?,
            before_image_digest: Some(hex32(before_image_digest, "before_image")?),
            after_image_digest: Some(hex32(after_image_digest, "after_image")?),
            source_receipts: serde_json::from_str(source_receipts).map_err(|_| {
                PolicyError::InvalidContext("outcome row receipts are malformed".into())
            })?,
            committed_at: self.committed_at,
        };
        // The stored digest is the COMBINED digest over the promoted record
        // AND the retained typed staged evidence; the raw 32 bytes compare
        // directly against the recomputation.
        let actual = hex::decode(canonical_outcome_digest(
            &record,
            self.staged_evidence.as_deref(),
        )?)
        .map_err(|_| PolicyError::InvalidContext("outcome digest encoding failed".into()))?;
        if self.outcome_digest != actual {
            return Err(PolicyError::InvalidContext(
                "outcome row failed its canonical self-digest".into(),
            ));
        }
        Ok(record)
    }
}

/// Validate a 32-byte raw digest column and return its lowercase hex form.
fn hex32(bytes: &[u8], field: &'static str) -> Result<String, PolicyError> {
    if bytes.len() == 32 {
        Ok(hex::encode(bytes))
    } else {
        Err(PolicyError::InvalidContext(format!(
            "outcome row {field} digest is malformed"
        )))
    }
}

fn parse_mutation_kind(text: &str) -> Result<AuthorityMutationKind, PolicyError> {
    match text {
        "AUTHORIZATION_SOURCE" => Ok(AuthorityMutationKind::AuthorizationSource),
        "PROTECTED_BUSINESS" => Ok(AuthorityMutationKind::ProtectedBusiness),
        other => Err(PolicyError::InvalidContext(format!(
            "outcome row mutation kind is invalid: {other}"
        ))),
    }
}

/// Map sqlx failures onto the policy error taxonomy. A unique violation is a
/// durable-state signal (duplicate stage/promotion), never silently retried.
fn map_sqlx_error(error: sqlx::Error, context: &'static str) -> PolicyError {
    if let sqlx::Error::Database(database) = &error {
        if database.is_unique_violation() {
            return PolicyError::Repository(format!(
                "{context}: a durable source outcome row already exists; reconcile its identity"
            ));
        }
    }
    PolicyError::Repository(format!("{context}: {error}"))
}

fn canonical_text(value: &str, field: &'static str) -> Result<(), PolicyError> {
    if value.is_empty()
        || value.len() > MAX_TEXT_LEN
        || value.trim() != value
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(PolicyError::InvalidContext(format!(
            "source outcome {field} must be canonical bounded text"
        )));
    }
    Ok(())
}

fn sha256_hex(value: &str, field: &'static str) -> Result<(), PolicyError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PolicyError::InvalidContext(format!(
            "source outcome {field} must be a lowercase sha-256 digest"
        )));
    }
    Ok(())
}

/// Registered trusted service and database identities owned by one reconciler.
/// Other hosts' rows are excluded before leasing and are never quarantined here.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySourceOwnerEntry {
    pub service_id: String,
    pub database_ids: Vec<String>,
}

/// Hard-bounded reconciler configuration.
#[derive(Debug, Clone)]
pub struct AuthoritySourceOutcomeReconcilerConfig {
    /// Rows leased per `run_once` (1..=256).
    pub batch_size: u32,
    /// Lease duration in seconds (5..=3600), set from DB UTC time.
    pub lease_seconds: i64,
    /// Maximum attempts before a row is quarantined (1..=64).
    pub max_attempts: u32,
    /// Stable worker identity; the lease owner is `worker_id/run_instance`.
    pub worker_id: String,
    /// Run-scoped unique instance id (uuid); two live runs of one worker can
    /// never share a lease.
    pub run_instance_id: String,
    /// The ONE source owner pair this runtime instance is responsible for
    /// (multiple hosts share the DB; each host leases ONLY its own rows).
    /// Foreign-owner rows are never leased and never quarantined here.
    pub owned: AuthoritySourceOwnerEntry,
}

impl Default for AuthoritySourceOutcomeReconcilerConfig {
    /// Hard-bounded defaults; `owned` still requires explicit registration
    /// and `validate()` refuses an empty database list.
    fn default() -> Self {
        Self {
            batch_size: 16,
            lease_seconds: 30,
            max_attempts: 8,
            worker_id: "authority-source-outcome-reconciler".to_owned(),
            run_instance_id: String::new(),
            owned: AuthoritySourceOwnerEntry {
                service_id: String::new(),
                database_ids: Vec::new(),
            },
        }
    }
}

impl AuthoritySourceOutcomeReconcilerConfig {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if !(1..=256).contains(&self.batch_size) {
            return Err(PolicyError::InvalidContext(
                "reconciler batch_size must be within 1..=256".into(),
            ));
        }
        if !(5..=3600).contains(&self.lease_seconds) {
            return Err(PolicyError::InvalidContext(
                "reconciler lease_seconds must be within 5..=3600".into(),
            ));
        }
        if !(1..=64).contains(&self.max_attempts) {
            return Err(PolicyError::InvalidContext(
                "reconciler max_attempts must be within 1..=64".into(),
            ));
        }
        canonical_text(&self.worker_id, "worker_id")?;
        canonical_text(&self.run_instance_id, "run_instance_id")?;
        if self.worker_id.len() + self.run_instance_id.len() + 1 > 128 {
            return Err(PolicyError::InvalidContext(
                "worker_id/run_instance must fit the 128-character lease owner column".into(),
            ));
        }
        if self.owned.database_ids.is_empty() {
            return Err(PolicyError::InvalidContext(format!(
                "source owner {} must register at least one database id",
                self.owned.service_id
            )));
        }
        if self.owned.database_ids.len() > 64 {
            return Err(PolicyError::InvalidContext(
                "source owner must register at most 64 database ids".into(),
            ));
        }
        canonical_text(&self.owned.service_id, "service_id")?;
        for database_id in &self.owned.database_ids {
            canonical_text(database_id, "database_id")?;
        }
        Ok(())
    }

    fn lease_owner(&self) -> String {
        let owner = format!("{}/{}", self.worker_id, self.run_instance_id);
        debug_assert!(owner.len() <= 128, "lease owner must fit VARCHAR(128)");
        owner
    }

    /// Whether the row's owner binding is THIS instance's registered pair.
    /// Foreign-owner rows are never leased, committed, or quarantined here.
    fn owner_is_registered(&self, service_id: &str, database_id: &str) -> bool {
        self.owned.service_id == service_id
            && self.owned.database_ids.iter().any(|id| id == database_id)
    }
}

/// The authority-facing surface the reconciler drives. Implemented by the
/// real client; tests stub it. Unknown outcomes are never retried blindly:
/// the reconciler reconciles by stable identity first.
#[async_trait::async_trait]
pub trait AuthorityOutcomeGateway: Send + Sync {
    async fn commit(
        &self,
        commit: AuthoritySourceCommitRecord,
        database_id: String,
        declared_coverage: Option<astral_types::AuthorityStagedScopeCoverage>,
    ) -> Result<astral_types::AuthorityCommitResponse, astral_authority::AuthorityClientError>;
    async fn reconcile(
        &self,
        reservation_id: String,
        operation_id: String,
    ) -> Result<astral_types::AuthorityReconcileResponse, astral_authority::AuthorityClientError>;
}

#[async_trait::async_trait]
impl AuthorityOutcomeGateway for AuthorityClient {
    async fn commit(
        &self,
        commit: AuthoritySourceCommitRecord,
        database_id: String,
        declared_coverage: Option<astral_types::AuthorityStagedScopeCoverage>,
    ) -> Result<astral_types::AuthorityCommitResponse, astral_authority::AuthorityClientError> {
        AuthorityClient::commit(self, commit, database_id, declared_coverage).await
    }

    async fn reconcile(
        &self,
        reservation_id: String,
        operation_id: String,
    ) -> Result<astral_types::AuthorityReconcileResponse, astral_authority::AuthorityClientError>
    {
        AuthorityClient::reconcile(self, reservation_id, operation_id).await
    }
}

/// One `run_once` execution report. Committed/quarantined counts increment
/// ONLY when their CAS actually applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuthoritySourceOutcomeReconcileReport {
    pub leased: u64,
    pub marked_committed: u64,
    pub confirmed_committed: u64,
    pub retried_after_unknown: u64,
    pub stayed_pending: u64,
    pub quarantined: u64,
    pub skipped: u64,
}

/// Action after one unknown-or-conflicting commit outcome, resolved by
/// stable-identity reconciliation. Pure and unit-tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownOutcomeReconcileAction {
    /// The authority holds the commit (or a later state): finalize locally.
    ConfirmCommitted,
    /// The authority still holds RESERVED: the previous commit provably never
    /// applied; one internal idempotent re-issue is allowed this run.
    RetryCommitOnce,
    /// Reconciliation itself is unknown: stay pending under the lease.
    StayPending,
    /// Terminal operator quarantine.
    Quarantine(&'static str),
}

/// Pure mapping from a reconciliation disposition to the unknown-outcome
/// action. Unknown source commits stay pending; the source is never replayed.
pub fn unknown_outcome_action(
    disposition: Option<&astral_types::AuthorityReservationDisposition>,
) -> UnknownOutcomeReconcileAction {
    use astral_types::AuthorityReservationDisposition as D;
    match disposition {
        Some(D::Committed) | Some(D::Published) | Some(D::Certified) | Some(D::Completed) => {
            UnknownOutcomeReconcileAction::ConfirmCommitted
        }
        Some(D::Reserved) => UnknownOutcomeReconcileAction::RetryCommitOnce,
        Some(D::NotFound) => UnknownOutcomeReconcileAction::Quarantine(
            "authority has no reservation for the committed source outcome",
        ),
        Some(D::Quarantined) | Some(D::Aborted) => UnknownOutcomeReconcileAction::Quarantine(
            "authority reservation is in a terminal non-committed state",
        ),
        Some(D::Pending) | Some(D::Unknown) | None => UnknownOutcomeReconcileAction::StayPending,
    }
}

/// Decision after one authoritative commit attempt. Pure and unit-tested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthoritySourceOutcomeDecision {
    /// The authority acknowledged the commit with the exact read-back binding.
    MarkCommitted,
    /// The authority reports the reservation already progressed (or an
    /// unknown-but-possibly-applied outcome): reconcile by stable identity
    /// before any state change; never replay the source.
    ReconcileByStableIdentity,
    /// Stay pending: unknown transport outcome or still-provable-later state.
    StayPending,
    /// Terminal operator quarantine with the recorded reason.
    Quarantine(&'static str),
}

/// Pure mapping from an authority commit outcome to the reconciler decision.
pub fn commit_outcome_decision(
    outcome: &Result<astral_types::AuthorityCommitResponse, astral_authority::AuthorityClientError>,
) -> AuthoritySourceOutcomeDecision {
    match outcome {
        Ok(_) => AuthoritySourceOutcomeDecision::MarkCommitted,
        Err(error) => match error {
            astral_authority::AuthorityClientError::Rejected { code, .. } => match code.as_str() {
                "StateConflict" | "AlreadyExists" => {
                    AuthoritySourceOutcomeDecision::ReconcileByStableIdentity
                }
                "NotFound" => AuthoritySourceOutcomeDecision::Quarantine(
                    "authority has no reservation for the committed source outcome",
                ),
                "LeaseExpired" => AuthoritySourceOutcomeDecision::Quarantine(
                    "authority refused the commit: authorization lease expired",
                ),
                "CallerIdentityMismatch"
                | "DigestMismatch"
                | "TrustRootMismatch"
                | "EditionMismatch" => AuthoritySourceOutcomeDecision::Quarantine(
                    "authority rejected the commit binding",
                ),
                _ => AuthoritySourceOutcomeDecision::StayPending,
            },
            astral_authority::AuthorityClientError::UnknownOutcome { .. }
            | astral_authority::AuthorityClientError::Transport(_)
            | astral_authority::AuthorityClientError::Attestation(_)
            | astral_authority::AuthorityClientError::InsecureEndpoint
            | astral_authority::AuthorityClientError::Protocol(_)
            | astral_authority::AuthorityClientError::ProtocolError(_) => {
                AuthoritySourceOutcomeDecision::StayPending
            }
        },
    }
}

/// Bounded lease/CAS/generation reconciler over `authority_source_outcome`.
///
/// All lease and expiry comparisons use DB UTC (`UNIX_TIMESTAMP()`), never the
/// application clock. A crashed worker's expired lease is reclaimable by ANY
/// worker through the generation fence; finalization additionally requires the
/// live lease (owner + unexpired, attempt cap) so no stale worker can finalize
/// after losing ownership.
pub struct AuthoritySourceOutcomeReconciler<G: AuthorityOutcomeGateway> {
    pool: Pool<MySql>,
    gateway: Arc<G>,
    config: AuthoritySourceOutcomeReconcilerConfig,
}

const OUTCOME_ROW_COLUMNS: &str = "reservation_id, operation_id, event_id, admission_proof_id, \
     request_binding_digest, mutation_kind, service_id, database_id, \
     source_commit_digest, before_image_digest, after_image_digest, source_receipts, \
     staged_evidence, status, attempts, generation, outcome_digest, committed_at";

impl<G: AuthorityOutcomeGateway> AuthoritySourceOutcomeReconciler<G> {
    pub fn new(
        pool: Pool<MySql>,
        gateway: Arc<G>,
        config: AuthoritySourceOutcomeReconcilerConfig,
    ) -> Result<Self, PolicyError> {
        config.validate()?;
        Ok(Self {
            pool,
            gateway,
            config,
        })
    }

    fn push_owner_predicate(&self, query: &mut sqlx::QueryBuilder<'_, MySql>) {
        query
            .push(" AND service_id = ")
            .push_bind(self.config.owned.service_id.clone());
        query.push(" AND database_id IN (");
        let mut databases = query.separated(", ");
        for database_id in &self.config.owned.database_ids {
            databases.push_bind(database_id.clone());
        }
        databases.push_unseparated(")");
    }

    /// Bound selection, lease CAS and readback to this registered owner. Exhausted
    /// rows are quarantined only after their previous lease has expired.
    async fn lease_batch(&self) -> Result<(Vec<AuthoritySourceOutcomeRow>, u64, u64), PolicyError> {
        let mut selection = sqlx::QueryBuilder::<MySql>::new(
            "SELECT reservation_id, generation, attempts FROM authority_source_outcome \
             WHERE status = 'PENDING' \
             AND (lease_until IS NULL OR lease_until <= UNIX_TIMESTAMP())",
        );
        self.push_owner_predicate(&mut selection);
        selection
            .push(" ORDER BY reservation_id LIMIT ")
            .push_bind(self.config.batch_size);
        let candidates: Vec<(String, u64, u32)> = selection
            .build_query_as()
            .fetch_all(&self.pool)
            .await
            .map_err(|error| map_sqlx_error(error, "list pending source outcomes"))?;
        let mut leased = Vec::with_capacity(candidates.len());
        let mut skipped = 0;
        let mut exhausted = 0;
        for (reservation_id, observed_generation, attempts) in candidates {
            if attempts >= self.config.max_attempts {
                let mut quarantine = sqlx::QueryBuilder::<MySql>::new(
                    "UPDATE authority_source_outcome SET status = 'QUARANTINED', \
                     last_error = 'source outcome retry budget exhausted; reconcile before recovery', \
                     generation = generation + 1, lease_owner = NULL, lease_until = NULL, \
                     updated_at = UNIX_TIMESTAMP() WHERE status = 'PENDING' \
                     AND (lease_until IS NULL OR lease_until <= UNIX_TIMESTAMP()) AND reservation_id = ",
                );
                quarantine
                    .push_bind(reservation_id)
                    .push(" AND generation = ")
                    .push_bind(observed_generation)
                    .push(" AND attempts >= ")
                    .push_bind(self.config.max_attempts);
                self.push_owner_predicate(&mut quarantine);
                let result = quarantine
                    .build()
                    .execute(&self.pool)
                    .await
                    .map_err(|error| {
                        map_sqlx_error(error, "quarantine exhausted source outcome")
                    })?;
                if result.rows_affected() == 1 {
                    exhausted += 1;
                } else {
                    skipped += 1;
                }
                continue;
            }
            let Some(expected_generation) = observed_generation.checked_add(1) else {
                return Err(PolicyError::InvalidContext(
                    "source outcome generation exhausted".into(),
                ));
            };
            let mut claim = sqlx::QueryBuilder::<MySql>::new(
                "UPDATE authority_source_outcome SET lease_owner = ",
            );
            claim
                .push_bind(self.config.lease_owner())
                .push(", lease_until = UNIX_TIMESTAMP() + ")
                .push_bind(self.config.lease_seconds)
                .push(
                    ", generation = generation + 1, attempts = attempts + 1, \
                 updated_at = UNIX_TIMESTAMP() WHERE reservation_id = ",
                )
                .push_bind(reservation_id.clone())
                .push(" AND status = 'PENDING' AND generation = ")
                .push_bind(observed_generation)
                .push(
                    " AND (lease_until IS NULL OR lease_until <= UNIX_TIMESTAMP()) AND attempts < ",
                )
                .push_bind(self.config.max_attempts);
            self.push_owner_predicate(&mut claim);
            let result = claim
                .build()
                .execute(&self.pool)
                .await
                .map_err(|error| map_sqlx_error(error, "lease source outcome"))?;
            if result.rows_affected() != 1 {
                skipped += 1;
                continue;
            }
            let mut readback = sqlx::QueryBuilder::<MySql>::new(format!(
                "SELECT {OUTCOME_ROW_COLUMNS} FROM authority_source_outcome WHERE reservation_id = ",
            ));
            readback
                .push_bind(reservation_id)
                .push(" AND status = 'PENDING' AND lease_owner = ")
                .push_bind(self.config.lease_owner())
                .push(" AND lease_until > UNIX_TIMESTAMP() AND generation = ")
                .push_bind(expected_generation)
                .push(" AND attempts <= ")
                .push_bind(self.config.max_attempts);
            self.push_owner_predicate(&mut readback);
            let row: Option<AuthoritySourceOutcomeRow> = readback
                .build_query_as()
                .fetch_optional(&self.pool)
                .await
                .map_err(|error| map_sqlx_error(error, "reread leased source outcome"))?;
            match row {
                Some(row)
                    if self
                        .config
                        .owner_is_registered(&row.service_id, &row.database_id) =>
                {
                    leased.push(row)
                }
                _ => skipped += 1,
            }
        }
        Ok((leased, skipped, exhausted))
    }

    /// Finalize one leased row under the full fence: pending status, the
    /// post-lease generation, OUR lease owner, an unexpired DB-UTC lease, and
    /// the attempt cap. A worker that lost its lease can never finalize.
    async fn finalize(
        &self,
        reservation_id: &str,
        observed: &AuthoritySourceOutcomeRow,
        committed: bool,
        disposition: Option<&str>,
        reason: Option<&str>,
    ) -> Result<bool, PolicyError> {
        if !self
            .config
            .owner_is_registered(&observed.service_id, &observed.database_id)
        {
            return Ok(false);
        }
        let mut query = sqlx::QueryBuilder::<MySql>::new(if committed {
            "UPDATE authority_source_outcome SET status = 'COMMITTED', authority_disposition = "
        } else {
            "UPDATE authority_source_outcome SET status = 'QUARANTINED', last_error = "
        });
        query.push_bind(
            if committed {
                disposition.unwrap_or("-")
            } else {
                reason.unwrap_or("-")
            }
            .to_owned(),
        );
        query
            .push(
                ", generation = generation + 1, lease_owner = NULL, lease_until = NULL, \
             updated_at = UNIX_TIMESTAMP() WHERE reservation_id = ",
            )
            .push_bind(reservation_id.to_owned())
            .push(" AND status = 'PENDING' AND generation = ")
            .push_bind(observed.generation)
            .push(" AND lease_owner = ")
            .push_bind(self.config.lease_owner())
            .push(" AND lease_until > UNIX_TIMESTAMP() AND attempts <= ")
            .push_bind(self.config.max_attempts);
        self.push_owner_predicate(&mut query);
        let result = query
            .build()
            .execute(&self.pool)
            .await
            .map_err(|error| map_sqlx_error(error, "finalize source outcome"))?;
        Ok(result.rows_affected() == 1)
    }
}

mod reconciliation;

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt(kind: &str, id: &str) -> AuthoritySourceReceiptIdentity {
        AuthoritySourceReceiptIdentity {
            identity_kind: kind.to_owned(),
            identity: id.to_owned(),
        }
    }

    pub(super) fn record() -> AuthoritySourceOutcomeRecord {
        AuthoritySourceOutcomeRecord {
            reservation_id: "res-abc".to_owned(),
            operation_id: "operation-1".to_owned(),
            event_id: "event-1".to_owned(),
            admission_proof_id: "prf-1".to_owned(),
            request_binding_digest: "aa".repeat(32),
            mutation_kind: AuthorityMutationKind::AuthorizationSource,
            service_id: "source-svc".to_owned(),
            database_id: "db-1".to_owned(),
            source_commit_digest: "bb".repeat(32),
            before_image_digest: Some("cc".repeat(32)),
            after_image_digest: Some("dd".repeat(32)),
            source_receipts: vec![
                receipt("ADMISSION_USE_ROW", "42"),
                receipt("OUTBOX_MESSAGE", "msg-7"),
            ],
            committed_at: 1_790_000_000,
        }
    }

    #[test]
    fn record_validation_is_fail_closed() {
        assert!(record().validate().is_ok());

        let mut missing_receipts = record();
        missing_receipts.source_receipts.clear();
        assert!(missing_receipts.validate().is_err());

        let mut non_canonical = record();
        non_canonical.reservation_id = "res abc".to_owned();
        assert!(non_canonical.validate().is_err());

        let mut bad_digest = record();
        bad_digest.after_image_digest = Some("ZZ".repeat(32));
        assert!(bad_digest.validate().is_err());

        let mut no_after_image = record();
        no_after_image.after_image_digest = None;
        // Structurally allowed on the record: the reconciler refuses to
        // commit it, because the authority needs the actual digest.
        assert!(no_after_image.validate().is_ok());
    }

    #[test]
    fn outcome_digest_binds_every_field_including_receipts() {
        let base = record().outcome_digest().unwrap();
        assert_eq!(base, record().outcome_digest().unwrap());

        let mut variants = vec![record(); 6];
        variants[0].reservation_id = "res-other".to_owned();
        variants[1].operation_id = "operation-2".to_owned();
        variants[2].mutation_kind = AuthorityMutationKind::ProtectedBusiness;
        variants[3].after_image_digest = Some("ee".repeat(32));
        variants[4].source_receipts[0].identity = "43".to_owned();
        variants[5].committed_at += 1;
        for variant in &variants {
            assert_ne!(base, variant.outcome_digest().unwrap());
        }

        let mut removed_receipt = record();
        removed_receipt.source_receipts.remove(1);
        assert_ne!(base, removed_receipt.outcome_digest().unwrap());
    }

    #[test]
    fn staged_digests_survive_json_storage_normalization_and_reject_content_drift() {
        let original = r#"{"coverage":null,"evidence":{"z":2,"a":"literal { }"}}"#;
        let reordered = r#"{ "evidence": { "a": "literal { }", "z": 2 }, "coverage": null }"#;
        assert_eq!(
            staged_evidence_digest(original).unwrap(),
            staged_evidence_digest(reordered).unwrap()
        );
        assert_eq!(
            canonical_outcome_digest(&record(), Some(original)).unwrap(),
            canonical_outcome_digest(&record(), Some(reordered)).unwrap()
        );
        let drifted = reordered.replace("literal { }", "literal {}");
        assert_ne!(
            staged_evidence_digest(original).unwrap(),
            staged_evidence_digest(&drifted).unwrap()
        );
        assert_ne!(
            canonical_outcome_digest(&record(), Some(original)).unwrap(),
            canonical_outcome_digest(&record(), Some(&drifted)).unwrap()
        );
        assert!(staged_evidence_digest("{invalid").is_err());
    }

    #[test]
    fn source_image_digest_is_content_bound() {
        let first = source_image_digest(b"{\"grant\":1}");
        assert_eq!(first, source_image_digest(b"{\"grant\":1}"));
        assert_ne!(first, source_image_digest(b"{\"grant\":2}"));
        // An actor authorization snapshot marker is not a digest input.
        assert_ne!(first, source_image_digest(b"actor-snapshot"));
    }

    fn commit_response_stub(
    ) -> Result<astral_types::AuthorityCommitResponse, astral_authority::AuthorityClientError> {
        Err(astral_authority::AuthorityClientError::Rejected {
            code: "StateConflict".to_owned(),
            message: "already committed".to_owned(),
        })
    }

    #[test]
    fn decision_mapping_never_retries_unknown_and_quarantines_corruption() {
        assert_eq!(
            commit_outcome_decision(&commit_response_stub()),
            AuthoritySourceOutcomeDecision::ReconcileByStableIdentity
        );

        let unknown = Err(astral_authority::AuthorityClientError::UnknownOutcome {
            operation_hint: "res-abc".to_owned(),
        });
        assert_eq!(
            commit_outcome_decision(&unknown),
            AuthoritySourceOutcomeDecision::StayPending
        );

        let transport = Err(astral_authority::AuthorityClientError::Transport(
            "connection reset".to_owned(),
        ));
        assert_eq!(
            commit_outcome_decision(&transport),
            AuthoritySourceOutcomeDecision::StayPending
        );

        let not_found = Err(astral_authority::AuthorityClientError::Rejected {
            code: "NotFound".to_owned(),
            message: "reservation missing".to_owned(),
        });
        assert!(matches!(
            commit_outcome_decision(&not_found),
            AuthoritySourceOutcomeDecision::Quarantine(_)
        ));

        let lease_expired = Err(astral_authority::AuthorityClientError::Rejected {
            code: "LeaseExpired".to_owned(),
            message: "expired".to_owned(),
        });
        assert!(matches!(
            commit_outcome_decision(&lease_expired),
            AuthoritySourceOutcomeDecision::Quarantine(_)
        ));

        let mismatch = Err(astral_authority::AuthorityClientError::Rejected {
            code: "DigestMismatch".to_owned(),
            message: "digest".to_owned(),
        });
        assert!(matches!(
            commit_outcome_decision(&mismatch),
            AuthoritySourceOutcomeDecision::Quarantine(_)
        ));
    }

    #[test]
    fn unknown_outcome_action_reconciles_stable_identity_first() {
        use astral_types::AuthorityReservationDisposition as D;
        // The authority holds the commit: finalize locally.
        assert_eq!(
            unknown_outcome_action(Some(&D::Committed)),
            UnknownOutcomeReconcileAction::ConfirmCommitted
        );
        assert_eq!(
            unknown_outcome_action(Some(&D::Published)),
            UnknownOutcomeReconcileAction::ConfirmCommitted
        );
        // Provably not applied: exactly one bounded idempotent re-issue.
        assert_eq!(
            unknown_outcome_action(Some(&D::Reserved)),
            UnknownOutcomeReconcileAction::RetryCommitOnce
        );
        // Missing reservation is terminal quarantine, never a re-prepare.
        assert!(matches!(
            unknown_outcome_action(Some(&D::NotFound)),
            UnknownOutcomeReconcileAction::Quarantine(_)
        ));
        // Reconciliation itself unknown: stay pending under the lease.
        assert_eq!(
            unknown_outcome_action(Some(&D::Unknown)),
            UnknownOutcomeReconcileAction::StayPending
        );
        assert_eq!(
            unknown_outcome_action(None),
            UnknownOutcomeReconcileAction::StayPending
        );
    }

    #[test]
    fn reconciler_config_bounds_and_allowlist_fail_closed() {
        fn config() -> AuthoritySourceOutcomeReconcilerConfig {
            AuthoritySourceOutcomeReconcilerConfig {
                batch_size: 16,
                lease_seconds: 30,
                max_attempts: 8,
                worker_id: "worker-1".to_owned(),
                run_instance_id: "run-1".to_owned(),
                owned: AuthoritySourceOwnerEntry {
                    service_id: "source-svc".to_owned(),
                    database_ids: vec!["db-1".to_owned()],
                },
            }
        }
        assert!(config().validate().is_ok());

        let mut no_owners = config();
        no_owners.owned.database_ids.clear();
        assert!(no_owners.validate().is_err());

        let mut unbounded = config();
        unbounded.batch_size = 4096;
        assert!(unbounded.validate().is_err());
        let mut short_lease = config();
        short_lease.lease_seconds = 1;
        assert!(short_lease.validate().is_err());
        let mut no_instance = config();
        no_instance.run_instance_id = String::new();
        assert!(no_instance.validate().is_err());

        let config = config();
        assert!(config.owner_is_registered("source-svc", "db-1"));
        assert!(!config.owner_is_registered("source-svc", "db-other"));
        assert!(!config.owner_is_registered("other-svc", "db-1"));

        // The lease owner is run-scoped: two runs of one worker never share.
        assert_eq!(config.lease_owner(), "worker-1/run-1");
    }

    #[test]
    fn receipts_cap_is_extended_to_1024_with_bounded_json() {
        let mut evidence = AuthoritySourceOutcomeEvidence {
            source_commit_digest: "bb".repeat(32),
            before_image_digest: "cc".repeat(32),
            after_image_digest: "dd".repeat(32),
            source_receipts: (0..1024)
                .map(|index| receipt("OUTBOX_MESSAGE", &format!("msg-{index}")))
                .collect(),
        };
        assert!(evidence.validate().is_ok());
        evidence
            .source_receipts
            .push(receipt("OUTBOX_MESSAGE", "over"));
        assert!(evidence.validate().is_err());
    }

    #[tokio::test]
    #[ignore = "requires isolated ASTRAL_SOURCE_OUTCOME_TEST_MYSQL_URL with migration 20261107000006"]
    async fn live_lease_takeover_and_finalize_fences() {
        let required = std::env::var("RUST_INTEGRATION_REQUIRED").as_deref() == Ok("1");
        let Ok(url) = std::env::var("ASTRAL_SOURCE_OUTCOME_TEST_MYSQL_URL") else {
            assert!(!required, "required isolated MySQL dependency is missing");
            eprintln!("[SKIP] isolated source outcome MySQL dependency is missing");
            return;
        };
        let pool = sqlx::MySqlPool::connect(&url).await.unwrap();
        let run = uuid::Uuid::new_v4().simple().to_string();
        let reservation_id = format!("res-it-{run}");
        let staged = AuthoritySourceOutcomeStaged {
            reservation_id: reservation_id.clone(),
            operation_id: format!("operation-{run}"),
            event_id: format!("event-{run}"),
            admission_proof_id: format!("proof-{run}"),
            request_binding_digest: "aa".repeat(32),
            mutation_kind: AuthorityMutationKind::AuthorizationSource,
            service_id: format!("source-{run}"),
            database_id: format!("db-{run}"),
            staged_evidence_json: r#"{"coverage":null,"evidence":{"delta":"d1"}}"#.to_owned(),
            committed_at: 1_790_000_000,
        };
        {
            let mut tx = pool.begin().await.unwrap();
            stage_authority_source_outcome_tx(&mut tx, &staged)
                .await
                .unwrap();
            promote_authority_source_outcome_tx(
                &mut tx,
                &reservation_id,
                &AuthoritySourceOutcomeEvidence {
                    source_commit_digest: "bb".repeat(32),
                    before_image_digest: "cc".repeat(32),
                    after_image_digest: "dd".repeat(32),
                    source_receipts: vec![receipt("ADMISSION_USE_ROW", "1")],
                },
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }

        struct StubGateway;
        #[async_trait::async_trait]
        impl AuthorityOutcomeGateway for StubGateway {
            async fn commit(
                &self,
                _commit: AuthoritySourceCommitRecord,
                _database_id: String,
                _declared_coverage: Option<astral_types::AuthorityStagedScopeCoverage>,
            ) -> Result<astral_types::AuthorityCommitResponse, astral_authority::AuthorityClientError>
            {
                Err(astral_authority::AuthorityClientError::UnknownOutcome {
                    operation_hint: "stub".to_owned(),
                })
            }
            async fn reconcile(
                &self,
                _reservation_id: String,
                _operation_id: String,
            ) -> Result<
                astral_types::AuthorityReconcileResponse,
                astral_authority::AuthorityClientError,
            > {
                Err(astral_authority::AuthorityClientError::UnknownOutcome {
                    operation_hint: "stub".to_owned(),
                })
            }
        }

        // Run 1: unknown everywhere -> row stays PENDING, leased with owner+lease.
        let reconciler = AuthoritySourceOutcomeReconciler::new(
            pool.clone(),
            Arc::new(StubGateway),
            AuthoritySourceOutcomeReconcilerConfig {
                worker_id: "worker-1".to_owned(),
                run_instance_id: "run-1".to_owned(),
                owned: AuthoritySourceOwnerEntry {
                    service_id: staged.service_id.clone(),
                    database_ids: vec![staged.database_id.clone()],
                },
                max_attempts: 2,
                ..Default::default()
            },
        )
        .unwrap();
        let report = reconciler.run_once().await.unwrap();
        assert_eq!(report.leased, 1);
        assert_eq!(report.stayed_pending, 1);
        let leased: (String, String, i64, i64) = sqlx::query_as(
            "SELECT status, lease_owner, lease_until, attempts \
             FROM authority_source_outcome WHERE reservation_id = ?",
        )
        .bind(&reservation_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(leased.0, "PENDING");
        assert_eq!(leased.1, "worker-1/run-1");
        assert!(leased.2 > 0);
        assert_eq!(leased.3, 1);

        let first_snapshot: AuthoritySourceOutcomeRow = sqlx::query_as(&format!(
            "SELECT {OUTCOME_ROW_COLUMNS} FROM authority_source_outcome WHERE reservation_id = ?",
        ))
        .bind(&reservation_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(first_snapshot.attempts, 1);
        let foreign = AuthoritySourceOutcomeReconciler::new(
            pool.clone(),
            Arc::new(StubGateway),
            AuthoritySourceOutcomeReconcilerConfig {
                worker_id: "foreign".into(),
                run_instance_id: run.clone(),
                max_attempts: 2,
                owned: AuthoritySourceOwnerEntry {
                    service_id: format!("foreign-{run}"),
                    database_ids: vec![staged.database_id.clone()],
                },
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!foreign
            .finalize(
                &reservation_id,
                &first_snapshot,
                false,
                None,
                Some("foreign")
            )
            .await
            .unwrap());

        // Run 2 with a DIFFERENT worker while the lease is live: the lease is
        // not stealable; the row is skipped.
        let worker_two = AuthoritySourceOutcomeReconciler::new(
            pool.clone(),
            Arc::new(StubGateway),
            AuthoritySourceOutcomeReconcilerConfig {
                worker_id: "worker-2".to_owned(),
                run_instance_id: "run-1".to_owned(),
                owned: AuthoritySourceOwnerEntry {
                    service_id: staged.service_id.clone(),
                    database_ids: vec![staged.database_id.clone()],
                },
                max_attempts: 2,
                ..Default::default()
            },
        )
        .unwrap();
        let report = worker_two.run_once().await.unwrap();
        assert_eq!(report.leased, 0);
        assert_eq!(report.skipped, 0);

        // After DB-UTC expiry the other worker reclaims via generation CAS.
        sqlx::query("UPDATE authority_source_outcome SET lease_until = 1 WHERE reservation_id = ?")
            .bind(&reservation_id)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(foreign.run_once().await.unwrap().leased, 0);
        let report = worker_two.run_once().await.unwrap();
        assert_eq!(report.leased, 1);
        let owner: (String,) = sqlx::query_as(
            "SELECT lease_owner FROM authority_source_outcome WHERE reservation_id = ?",
        )
        .bind(&reservation_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(owner.0, "worker-2/run-1");
        let last_attempt: AuthoritySourceOutcomeRow = sqlx::query_as(&format!(
            "SELECT {OUTCOME_ROW_COLUMNS} FROM authority_source_outcome WHERE reservation_id = ?",
        ))
        .bind(&reservation_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(last_attempt.attempts, 2);
        assert!(last_attempt.generation > first_snapshot.generation);
        assert!(!reconciler
            .finalize(
                &reservation_id,
                &first_snapshot,
                true,
                Some("COMMITTED"),
                None
            )
            .await
            .unwrap());
        assert!(worker_two
            .finalize(
                &reservation_id,
                &last_attempt,
                true,
                Some("COMMITTED"),
                None
            )
            .await
            .unwrap());
        let terminal: (String, Option<String>, Option<String>) = sqlx::query_as(
            "SELECT status, authority_disposition, last_error FROM authority_source_outcome WHERE reservation_id = ?",
        ).bind(&reservation_id).fetch_one(&pool).await.unwrap();
        assert_eq!(
            terminal,
            ("COMMITTED".into(), Some("COMMITTED".into()), None)
        );
        sqlx::query("UPDATE authority_source_outcome SET status = 'PENDING', lease_until = 1 WHERE reservation_id = ?")
            .bind(&reservation_id).execute(&pool).await.unwrap();
        assert_eq!(worker_two.run_once().await.unwrap().quarantined, 1);
        let reason: (String, Option<String>) = sqlx::query_as(
            "SELECT status, last_error FROM authority_source_outcome WHERE reservation_id = ?",
        )
        .bind(&reservation_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(reason.0, "QUARANTINED");
        assert!(reason.1.unwrap().contains("retry budget exhausted"));

        // Cleanup best-effort: the test owns only its run-scoped row.
        sqlx::query("DELETE FROM authority_source_outcome WHERE reservation_id = ?")
            .bind(&reservation_id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
