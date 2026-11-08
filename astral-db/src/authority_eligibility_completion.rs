//! Durable ELIGIBILITY completion closure for identity source outcomes.
//!
//! User status / org status / card status mutations stage an
//! `AUTHORIZATION_SOURCE` outcome row whose staged evidence is the shared
//! `AuthorityStagedSourceEvidence` envelope, with `coverage: None` and the
//! shared `ELIGIBILITY_COMPLETION` typed contract around the full Identity artifact.
//! Those rows carry NO coverage and NO canonical grant delta, so the
//! publication leg (`authority_publication`) never selects them; this module
//! owns their finite closure instead:
//!
//! 1. The identity writer captures, IN the same source transaction and AFTER
//!    the actual mutation, one [`EligibilityCompletionCapture`] per affected
//!    card: the exact durable ELIGIBILITY head generation/revoke watermark,
//!    the projection outbox event id and the typed message intent id (all
//!    read back from the durable rows the same transaction wrote). More than
//!    [`ELIGIBILITY_COMPLETION_MAX_CARDS`] captures keep the row WITHOUT the
//!    envelope: it stays operator-owned, never truncated.
//! 2. This worker leases `COMMITTED` `AUTHORIZATION_SOURCE` rows whose staged
//!    evidence carries the strict typed tag, verifies — by exact byte
//!    identity against the durable rows — the complete scope set
//!    ([`AuthorityEligibilityCompletionEvidence`].cards vs the artifact's
//!    `affectedCards`), every declared head/outbox/intent row, and the
//!    ABSENCE of any actual `authorization_delta_event` for the operation.
//!    Only then does it call the authority completion endpoint through
//!    [`EligibilityCompletionGateway`].
//! 3. Local `COMPLETED` is terminal ONLY after an authoritative, field-exact
//!    matching [`AuthorityEligibilityCompletionTerminal`]. Unknown outcomes
//!    are reconciled by the stable reservation/operation identity; the source
//!    is never replayed, no grant current/history row is ever written here,
//!    and no certificate/manifest is fabricated.
//!
//! Selection disjointness (never widened):
//! - source acknowledgement owns `PENDING` rows;
//! - the publication leg owns `COMMITTED` rows with a `coverage` OBJECT;
//! - this leg owns `COMMITTED` `AUTHORIZATION_SOURCE` rows with NO coverage
//!   object AND the exact `$.evidence.kind == "EligibilityCompletion"` tag.
//!   Config/`PROTECTED_BUSINESS` rows and untagged rows are never selected.

use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use sqlx::{MySql, Pool, Transaction};

use astral_types::{
    AuthorityCommitBinding, AuthorityEligibilityCardCompletion,
    AuthorityEligibilityCompletionEvidence, AuthorityEligibilityCompletionResponse,
    AuthorityEligibilityEmptySelectionCompleteness, AuthorityEligibilityEmptySelectionEvidence,
    AuthorityEligibilityEmptySelectionKind, AuthorityEligibilityEmptySelectionSelector,
    AuthorityEligibilityEmptySelectionSubjectKind, AuthorityProtocolScope,
    AuthorityRetainedStagedEvidence, AuthorityStagedSourceEvidence, AuthorizationAdmission,
    PolicyError,
};

use crate::authority_publication::{
    identity_image_digests, IdentityPresence, IdentityReceipt, IdentityTargetImage,
};

use crate::authority_publication::empty_card_origin::complete_empty_card_origin_in_tx;
use crate::authority_source_outcome::{AuthoritySourceOutcomeRow, AuthoritySourceOwnerEntry};

mod card_rebind;
mod verification;

pub use card_rebind::CardRebindCapture;

use verification::verify_eligibility_completion_durable_facts;

fn map_completion_sqlx_error(error: sqlx::Error, context: &'static str) -> PolicyError {
    if let sqlx::Error::Database(database) = &error {
        if database.is_unique_violation() {
            return PolicyError::Repository(format!(
                "{context}: a durable source outcome row already exists; reconcile its identity"
            ));
        }
    }
    PolicyError::Repository(format!("{context}: {error}"))
}

/// Typed staged-evidence tag of this completion protocol.
pub const ELIGIBILITY_COMPLETION_KIND: &str = "ELIGIBILITY_COMPLETION";

/// Hard upper bound of one completion evidence card set. Beyond it the source
/// transaction must stage WITHOUT the envelope (operator-owned row); the set
/// is never truncated.
pub const ELIGIBILITY_COMPLETION_MAX_CARDS: usize = 256;

/// The durable ELIGIBILITY head/aggregate type this protocol verifies.
pub const ELIGIBILITY_AGGREGATE_TYPE: &str = astral_types::ProjectionAggregate::ELIGIBILITY;

// ─────────────────────────────────────────────────────────────────────────────
// Typed staged evidence (the single serde contract of this protocol)
// ─────────────────────────────────────────────────────────────────────────────

/// What the identity writer records per affected card while the source
/// transaction still holds its locks. Converted into the typed evidence only
/// at finalize; nothing here is ever guessed after the fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EligibilityCompletionCapture {
    pub card_id: i64,
    /// The locked scan's tenant; `None` fails staging closed (never guessed).
    pub tenant_id: Option<i64>,
    pub generation: u64,
    pub revoke_watermark: u64,
    pub outbox_event_id: String,
    pub message_id: String,
}

/// Typed inputs for a closed card creation capture. The capture owns the INSERT
/// and returns the generated primary key; callers cannot self-report a card id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardCreateInsertSpec {
    pub user_id: i64,
    pub tenant_id: i64,
    pub domain_id: Option<i64>,
    pub card_type: String,
    pub template_id: Option<i64>,
    pub level_id: Option<i64>,
    pub priority: i32,
    pub is_primary: bool,
}

impl CardCreateInsertSpec {
    fn validate(&self) -> Result<(), PolicyError> {
        if self.user_id <= 0 || self.tenant_id <= 0 {
            return Err(capture_invalid(
                "card create insert requires positive user and tenant identities",
            ));
        }
        if self.template_id.is_some_and(|id| id <= 0) || self.level_id.is_some_and(|id| id <= 0) {
            return Err(capture_invalid(
                "card create template and level identities must be positive when present",
            ));
        }
        if self.card_type.is_empty()
            || self.card_type.len() > 32
            || !self
                .card_type
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
        {
            return Err(capture_invalid(
                "card create requires a canonical card type",
            ));
        }
        if self.domain_id.is_some_and(|domain_id| domain_id <= 0) {
            return Err(capture_invalid(
                "card create insert domain identity must be positive when present",
            ));
        }
        Ok(())
    }
}

/// Why an identity capture set cannot become a typed completion evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EligibilityCompletionStagingError {
    /// More than [`ELIGIBILITY_COMPLETION_MAX_CARDS`] cards: the row must be
    /// staged WITHOUT the envelope and stays operator-owned. Never truncated.
    CapacityExceeded,
    Invalid(&'static str),
}

/// Build the shared completion contract from actual in-transaction captures.
/// More than 256 entries stay operator-owned and are never truncated.
pub fn build_eligibility_completion_evidence(
    captures: &[EligibilityCompletionCapture],
) -> Result<AuthorityEligibilityCompletionEvidence, EligibilityCompletionStagingError> {
    if captures.is_empty() {
        return Err(EligibilityCompletionStagingError::Invalid(
            "eligibility completion requires at least one affected card",
        ));
    }
    if captures.len() > ELIGIBILITY_COMPLETION_MAX_CARDS {
        return Err(EligibilityCompletionStagingError::CapacityExceeded);
    }
    let mut cards = Vec::with_capacity(captures.len());
    for capture in captures {
        let Some(tenant_id) = capture.tenant_id else {
            return Err(EligibilityCompletionStagingError::Invalid(
                "eligibility completion capture has no locked tenant identity",
            ));
        };
        if capture.card_id <= 0 || tenant_id <= 0 || capture.generation == 0 {
            return Err(EligibilityCompletionStagingError::Invalid(
                "eligibility completion capture has invalid durable card identity",
            ));
        }
        cards.push(AuthorityEligibilityCardCompletion {
            scope: AuthorityProtocolScope::Card(astral_types::AuthorizationAuthorityScope {
                tenant_id,
                card_id: capture.card_id,
                user_id: None,
                domain: astral_types::AuthorizationDomainScope::Any,
            }),
            generation: capture.generation,
            revoke_watermark: capture.revoke_watermark,
            outbox_event_id: capture.outbox_event_id.clone(),
            message_id: capture.message_id.clone(),
        });
    }
    cards.sort_by(|left, right| {
        left.scope
            .store_key_text()
            .unwrap_or_default()
            .cmp(&right.scope.store_key_text().unwrap_or_default())
    });
    let completion = AuthorityEligibilityCompletionEvidence {
        cards,
        zero_card_selection: None,
    };
    completion.validate().map_err(|_| {
        EligibilityCompletionStagingError::Invalid(
            "eligibility completion evidence failed shared validation",
        )
    })?;
    Ok(completion)
}

/// Build through the shared protocol helper, retaining one canonical serde contract.
pub fn build_eligibility_completion_envelope(
    captures: &[EligibilityCompletionCapture],
    source_evidence: serde_json::Value,
) -> Result<AuthorityStagedSourceEvidence, EligibilityCompletionStagingError> {
    let completion = build_eligibility_completion_evidence(captures)?;
    completion.to_staged_envelope(source_evidence).map_err(|_| {
        EligibilityCompletionStagingError::Invalid(
            "eligibility completion envelope failed shared validation",
        )
    })
}

/// Canonical compact JSON bytes of a staged evidence string (parse + compact
/// serialize through `serde_json::Value`). This is the exact canonicalization
/// the outcome row digest uses, so a stored JSON column's physical formatting
/// can never change the identity of the evidence.
pub(crate) fn canonical_staged_evidence_bytes(value: &str) -> Result<Vec<u8>, PolicyError> {
    if value.len() > 256 * 1024 {
        return Err(PolicyError::InvalidContext(
            "staged evidence exceeds its byte bound".into(),
        ));
    }
    let parsed: serde_json::Value = serde_json::from_str(value)
        .map_err(|_| PolicyError::InvalidContext("staged evidence is invalid JSON".into()))?;
    serde_json::to_vec(&parsed)
        .map_err(|_| PolicyError::InvalidContext("staged evidence cannot be encoded".into()))
}

/// Canonical staged-evidence digest: SHA-256 over the canonical compact Value
/// serialization. Byte-exact agreement with the control plane's
/// `AuthorityRetainedStagedEvidence::canonical_digest()`.
pub fn eligibility_retained_staged_evidence_digest(value: &str) -> Result<String, PolicyError> {
    Ok(hex::encode(Sha256::digest(
        canonical_staged_evidence_bytes(value)?,
    )))
}

// ─────────────────────────────────────────────────────────────────────────────
// Typed source-operation whitelist (never config, never a general SourceImage)
// ─────────────────────────────────────────────────────────────────────────────

/// The only source mutations this completion protocol may close. Everything
/// else — config, protected business, general source images — is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EligibilitySourceOperation {
    UserStatus,
    UserDelete,
    TenantStatus,
    TenantDelete,
    CardStatus,
    CardCreate,
    CardRebind,
}

/// Opaque receipt produced only by `EligibilitySourceCapture::finish_in_tx`.
/// It contains the actual before/after target, audit and projection/message receipts.
#[derive(Debug, Clone)]
pub struct EligibilitySourceEvidenceReceipt {
    completion: AuthorityEligibilityCompletionEvidence,
    source_evidence: serde_json::Value,
    source_target: IdentityTargetImage,
    source_receipts: Vec<IdentityReceipt>,
    before_image_digest: String,
    after_image_digest: String,
    operation: EligibilitySourceOperation,
    publication_origin: bool,
    card_rebind: Option<astral_types::AuthorityCardRebindEvidence>,
}

impl EligibilitySourceEvidenceReceipt {
    pub fn operation(&self) -> EligibilitySourceOperation {
        self.operation
    }

    pub fn is_publication_origin(&self) -> bool {
        self.publication_origin
    }

    pub fn before_image_digest(&self) -> &str {
        &self.before_image_digest
    }

    pub fn after_image_digest(&self) -> &str {
        &self.after_image_digest
    }

    pub fn source_target(&self) -> &IdentityTargetImage {
        &self.source_target
    }

    pub fn source_receipts(&self) -> &[IdentityReceipt] {
        &self.source_receipts
    }

    pub fn completion(&self) -> &AuthorityEligibilityCompletionEvidence {
        &self.completion
    }

    pub fn source_evidence(&self) -> &serde_json::Value {
        &self.source_evidence
    }

    pub fn into_staged_envelope(self) -> Result<AuthorityStagedSourceEvidence, PolicyError> {
        if self.publication_origin {
            return Err(capture_invalid(
                "publication card origin cannot enter independent eligibility completion",
            ));
        }
        self.completion
            .to_staged_envelope_with_card_rebind(self.source_evidence, self.card_rebind)
            .map_err(|error| PolicyError::InvalidContext(error.to_string()))
    }
}
/// Transaction-owned source capture. The mutable transaction borrow remains
/// held until `finish_in_tx`, so every before/after image and durable receipt
/// is read from the same source transaction that performed the mutation.
pub struct EligibilitySourceCapture<'tx, 'conn> {
    tx: Option<&'tx mut Transaction<'conn, MySql>>,
    admission: AuthorizationAdmission,
    subject: EligibilitySourceSubject,
    operation: EligibilitySourceOperation,
    target: IdentityTargetImage,
    selected_cards: Vec<(i64, Option<i64>)>,
    captured_receipts: Vec<IdentityReceipt>,
    created_card_spec: Option<CardCreateInsertSpec>,
}

/// A card status mutation locks an existing card; a card creation mutation
/// proves the target was absent before the INSERT and present after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EligibilitySourceSubject {
    UserStatus { user_id: i64 },
    UserDelete { user_id: i64 },
    TenantStatus { tenant_id: i64 },
    TenantDelete { tenant_id: i64 },
    CardStatus { card_id: i64 },
    CardCreate { card_id: i64 },
}

fn capture_db_error(error: sqlx::Error, context: &'static str) -> PolicyError {
    PolicyError::Repository(format!("{context}: {error}"))
}

fn capture_invalid(message: impl Into<String>) -> PolicyError {
    PolicyError::InvalidContext(message.into())
}

fn validate_card_create_admission(
    admission: &AuthorizationAdmission,
    spec: &CardCreateInsertSpec,
) -> Result<(), PolicyError> {
    let proof = admission.proof();
    if proof.request_binding_digest.is_none()
        || proof.operation_id.is_empty()
        || proof.event_id.is_empty()
        || proof.scope.tenant_id != spec.tenant_id
    {
        return Err(capture_invalid(
            "card create admission is not bound to the exact tenant and source identity",
        ));
    }
    let domain_matches = match proof.scope.domain {
        astral_types::AuthorizationDomainScope::Exact(id) => spec.domain_id == Some(id),
        astral_types::AuthorizationDomainScope::NoDomain => spec.domain_id.is_none(),
        astral_types::AuthorizationDomainScope::Any => false,
    };
    if proof.scope.user_id.is_none_or(|user_id| user_id <= 0) || !domain_matches {
        return Err(capture_invalid(
            "card create admission is not bound to an exact actor and domain scope",
        ));
    }
    Ok(())
}

fn subject_operation(subject: EligibilitySourceSubject) -> EligibilitySourceOperation {
    match subject {
        EligibilitySourceSubject::UserStatus { .. } => EligibilitySourceOperation::UserStatus,
        EligibilitySourceSubject::UserDelete { .. } => EligibilitySourceOperation::UserDelete,
        EligibilitySourceSubject::TenantStatus { .. } => EligibilitySourceOperation::TenantStatus,
        EligibilitySourceSubject::TenantDelete { .. } => EligibilitySourceOperation::TenantDelete,
        EligibilitySourceSubject::CardStatus { .. } => EligibilitySourceOperation::CardStatus,
        EligibilitySourceSubject::CardCreate { .. } => EligibilitySourceOperation::CardCreate,
    }
}

fn subject_id(subject: EligibilitySourceSubject) -> i64 {
    match subject {
        EligibilitySourceSubject::UserStatus { user_id }
        | EligibilitySourceSubject::UserDelete { user_id } => user_id,
        EligibilitySourceSubject::TenantStatus { tenant_id }
        | EligibilitySourceSubject::TenantDelete { tenant_id } => tenant_id,
        EligibilitySourceSubject::CardStatus { card_id }
        | EligibilitySourceSubject::CardCreate { card_id } => card_id,
    }
}

fn zero_subject_kind(
    operation: EligibilitySourceOperation,
) -> Option<AuthorityEligibilityEmptySelectionSubjectKind> {
    match operation {
        EligibilitySourceOperation::UserStatus => {
            Some(AuthorityEligibilityEmptySelectionSubjectKind::UserStatus)
        }
        EligibilitySourceOperation::UserDelete => {
            Some(AuthorityEligibilityEmptySelectionSubjectKind::UserDelete)
        }
        EligibilitySourceOperation::TenantStatus => {
            Some(AuthorityEligibilityEmptySelectionSubjectKind::TenantStatus)
        }
        EligibilitySourceOperation::TenantDelete => {
            Some(AuthorityEligibilityEmptySelectionSubjectKind::TenantDelete)
        }
        EligibilitySourceOperation::CardStatus | EligibilitySourceOperation::CardRebind => None,
        EligibilitySourceOperation::CardCreate => None,
    }
}

fn source_row_target(
    entity: &str,
    key: serde_json::Value,
    before: serde_json::Value,
) -> IdentityTargetImage {
    IdentityTargetImage {
        entity: entity.to_owned(),
        key,
        before: IdentityPresence::Present(before),
        after: IdentityPresence::Absent,
    }
}

fn captured_source_receipt(
    subject: EligibilitySourceSubject,
    target: &IdentityTargetImage,
) -> Result<IdentityReceipt, PolicyError> {
    let id = subject_id(subject);
    let (entity, id_field, kind) = match subject {
        EligibilitySourceSubject::UserStatus { .. }
        | EligibilitySourceSubject::UserDelete { .. } => ("platform_user", "userId", "UPDATE"),
        EligibilitySourceSubject::TenantStatus { .. } => ("tenant", "tenantId", "UPDATE"),
        EligibilitySourceSubject::TenantDelete { .. } => ("tenant", "tenantId", "DELETE"),
        EligibilitySourceSubject::CardStatus { .. } => ("user_card", "cardId", "UPDATE"),
        EligibilitySourceSubject::CardCreate { .. } => ("user_card", "cardId", "INSERT"),
    };
    let key = serde_json::json!({id_field: id});
    if id <= 0 || target.entity != entity || target.key != key {
        return Err(capture_invalid(
            "captured source target identity differs from its subject",
        ));
    }
    let before = match &target.before {
        IdentityPresence::Present(value) => Some(value),
        IdentityPresence::Absent => None,
    };
    let after = match &target.after {
        IdentityPresence::Present(value) => Some(value),
        IdentityPresence::Absent => None,
    };
    if [before, after].into_iter().flatten().any(|value| {
        !value.is_object() || value.get(id_field).and_then(serde_json::Value::as_i64) != Some(id)
    }) {
        return Err(capture_invalid(
            "captured source image has a conflicting row identity",
        ));
    }
    let status_changed = |field: &str| {
        before.zip(after).is_some_and(|(before, after)| {
            before
                .get(field)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| !value.is_empty())
                && after
                    .get(field)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| !value.is_empty())
                && before.get(field) != after.get(field)
        })
    };
    let valid_transition = match subject {
        EligibilitySourceSubject::UserStatus { .. } => {
            status_changed("status")
                && before.is_some_and(|value| {
                    value
                        .get("deletedAt")
                        .is_some_and(serde_json::Value::is_null)
                })
                && after.is_some_and(|value| {
                    value
                        .get("deletedAt")
                        .is_some_and(serde_json::Value::is_null)
                })
        }
        EligibilitySourceSubject::UserDelete { .. } => {
            before.is_some_and(|value| {
                value
                    .get("deletedAt")
                    .is_some_and(serde_json::Value::is_null)
            }) && after.is_some_and(|value| {
                value
                    .get("deletedAt")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| !value.is_empty())
            })
        }
        EligibilitySourceSubject::TenantStatus { .. } => status_changed("status"),
        EligibilitySourceSubject::TenantDelete { .. } => before.is_some() && after.is_none(),
        EligibilitySourceSubject::CardStatus { .. } => {
            before.zip(after).is_some_and(|(before, after)| {
                before.get("cardStatus").and_then(serde_json::Value::as_str) == Some("ACTIVE")
                    && status_changed("cardStatus")
                    && before
                        .get("tenantId")
                        .and_then(serde_json::Value::as_i64)
                        .is_some_and(|tenant| tenant > 0)
                    && before.get("tenantId") == after.get("tenantId")
            })
        }
        EligibilitySourceSubject::CardCreate { .. } => {
            before.is_none()
                && after.is_some_and(|value| {
                    value.get("cardStatus").and_then(serde_json::Value::as_str) == Some("ACTIVE")
                        && value
                            .get("tenantId")
                            .and_then(serde_json::Value::as_i64)
                            .is_some_and(|tenant| tenant > 0)
                })
        }
    };
    if !valid_transition {
        return Err(capture_invalid(
            "captured source images do not prove the declared eligibility mutation",
        ));
    }
    Ok(IdentityReceipt {
        entity: entity.to_owned(),
        key,
        kind: kind.to_owned(),
        rows_affected: 1,
        durable_id: id.to_string(),
    })
}

fn absent_card_target(card_id: i64) -> IdentityTargetImage {
    IdentityTargetImage {
        entity: "user_card".to_owned(),
        key: serde_json::json!({"cardId": card_id}),
        before: IdentityPresence::Absent,
        after: IdentityPresence::Absent,
    }
}

#[derive(Debug, sqlx::FromRow)]
struct UserEligibilityImageRow {
    user_id: i64,
    status: String,
    display_name: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    deleted_at: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct CardEligibilityBeforeRow {
    card_status: String,
    user_id: Option<i64>,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
    template_id: Option<i64>,
}

#[derive(Debug, sqlx::FromRow)]
struct CardEligibilityAfterImageRow {
    card_id: i64,
    card_status: String,
    user_id: Option<i64>,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
    template_id: Option<i64>,
}

async fn read_user_before(
    tx: &mut Transaction<'_, MySql>,
    user_id: i64,
) -> Result<IdentityTargetImage, PolicyError> {
    let row: Option<UserEligibilityImageRow> = sqlx::query_as(
        "SELECT user_id, status, display_name, email, phone, CAST(deleted_at AS CHAR) AS deleted_at \
         FROM platform_user WHERE user_id = ? AND deleted_at IS NULL FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| capture_db_error(error, "lock user eligibility subject"))?;
    let Some(UserEligibilityImageRow {
        user_id,
        status,
        display_name,
        email,
        phone,
        deleted_at,
    }) = row
    else {
        return Err(capture_invalid(
            "eligibility user subject is missing or deleted",
        ));
    };
    Ok(source_row_target(
        "platform_user",
        serde_json::json!({"userId": user_id}),
        serde_json::json!({
            "userId": user_id,
            "status": status,
            "displayName": display_name,
            "email": email,
            "phone": phone,
            "deletedAt": deleted_at,
        }),
    ))
}

async fn read_tenant_before(
    tx: &mut Transaction<'_, MySql>,
    tenant_id: i64,
) -> Result<IdentityTargetImage, PolicyError> {
    let row: Option<(i64, String, String, String)> = sqlx::query_as(
        "SELECT tenant_id, tenant_name, tenant_code, status FROM tenant \
         WHERE tenant_id = ? FOR UPDATE",
    )
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| capture_db_error(error, "lock tenant eligibility subject"))?;
    let Some((tenant_id, name, code, status)) = row else {
        return Err(capture_invalid("eligibility tenant subject is missing"));
    };
    Ok(source_row_target(
        "tenant",
        serde_json::json!({"tenantId": tenant_id}),
        serde_json::json!({
            "tenantId": tenant_id,
            "name": name,
            "code": code,
            "status": status,
        }),
    ))
}

async fn read_card_before(
    tx: &mut Transaction<'_, MySql>,
    card_id: i64,
) -> Result<IdentityTargetImage, PolicyError> {
    let row: Option<CardEligibilityBeforeRow> = sqlx::query_as(
        "SELECT card_status, user_id, tenant_id, domain_id, template_id \
             FROM user_card WHERE card_id = ? FOR UPDATE",
    )
    .bind(card_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| capture_db_error(error, "lock card eligibility subject"))?;
    let Some(CardEligibilityBeforeRow {
        card_status,
        user_id,
        tenant_id,
        domain_id,
        template_id,
    }) = row
    else {
        return Err(capture_invalid("eligibility card subject is missing"));
    };
    let tenant_id = tenant_id.filter(|value| *value > 0).ok_or_else(|| {
        capture_invalid("eligibility card subject has no positive tenant identity")
    })?;
    Ok(source_row_target(
        "user_card",
        serde_json::json!({"cardId": card_id}),
        serde_json::json!({
            "cardId": card_id,
            "cardStatus": card_status,
            "userId": user_id,
            "tenantId": tenant_id,
            "domainId": domain_id,
            "templateId": template_id,
        }),
    ))
}

async fn scan_active_cards(
    tx: &mut Transaction<'_, MySql>,
    subject: EligibilitySourceSubject,
) -> Result<Vec<(i64, Option<i64>)>, PolicyError> {
    let limit = i64::try_from(ELIGIBILITY_COMPLETION_MAX_CARDS + 1)
        .map_err(|_| capture_invalid("eligibility selector capacity overflow"))?;
    let rows: Vec<(i64, Option<i64>)> = match subject {
        EligibilitySourceSubject::UserStatus { user_id }
        | EligibilitySourceSubject::UserDelete { user_id } => sqlx::query_as(
            "SELECT card_id, tenant_id FROM user_card \
             WHERE user_id = ? AND card_status = 'ACTIVE' ORDER BY card_id LIMIT ? FOR UPDATE",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&mut **tx)
        .await
        .map_err(|error| capture_db_error(error, "lock active user eligibility selector"))?,
        EligibilitySourceSubject::TenantStatus { tenant_id }
        | EligibilitySourceSubject::TenantDelete { tenant_id } => sqlx::query_as(
            "SELECT card_id, tenant_id FROM user_card \
             WHERE tenant_id = ? AND card_status = 'ACTIVE' ORDER BY card_id LIMIT ? FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&mut **tx)
        .await
        .map_err(|error| capture_db_error(error, "lock active tenant eligibility selector"))?,
        EligibilitySourceSubject::CardStatus { card_id } => {
            let row: Option<(i64, Option<i64>)> = sqlx::query_as(
                "SELECT card_id, tenant_id FROM user_card WHERE card_id = ? FOR UPDATE",
            )
            .bind(card_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|error| capture_db_error(error, "lock card eligibility selector"))?;
            row.into_iter().collect()
        }
        EligibilitySourceSubject::CardCreate { card_id } => {
            let row: Option<(i64, Option<i64>)> = sqlx::query_as(
                "SELECT card_id, tenant_id FROM user_card WHERE card_id = ? FOR UPDATE",
            )
            .bind(card_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|error| capture_db_error(error, "lock created card eligibility selector"))?;
            row.into_iter().collect()
        }
    };
    if rows.len() > ELIGIBILITY_COMPLETION_MAX_CARDS {
        return Err(capture_invalid(format!(
            "eligibility selector returned more than {} ACTIVE cards; refusing before mutation",
            ELIGIBILITY_COMPLETION_MAX_CARDS
        )));
    }
    for (card_id, tenant_id) in &rows {
        if *card_id <= 0 || tenant_id.is_none_or(|value| value <= 0) {
            return Err(capture_invalid(
                "eligibility selector returned invalid card identity",
            ));
        }
        if matches!(subject, EligibilitySourceSubject::TenantStatus { tenant_id: expected }
            | EligibilitySourceSubject::TenantDelete { tenant_id: expected }
            if *tenant_id != Some(expected))
        {
            return Err(capture_invalid(
                "eligibility selector crossed tenant ownership",
            ));
        }
    }
    Ok(rows)
}

#[derive(Debug, serde::Serialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
struct CreatedCardImage {
    card_id: i64,
    card_status: String,
    user_id: Option<i64>,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
    template_id: Option<i64>,
    card_type: String,
    level_id: Option<i64>,
    priority: i32,
    is_primary: bool,
    valid_from: Option<String>,
    valid_until: Option<String>,
}

fn validate_created_card_image(
    target: &IdentityTargetImage,
    card_id: i64,
    spec: &CardCreateInsertSpec,
) -> Result<(), PolicyError> {
    let expected = serde_json::to_value(CreatedCardImage {
        card_id,
        card_status: "ACTIVE".to_owned(),
        user_id: Some(spec.user_id),
        tenant_id: Some(spec.tenant_id),
        domain_id: spec.domain_id,
        template_id: spec.template_id,
        card_type: spec.card_type.clone(),
        level_id: spec.level_id,
        priority: spec.priority,
        is_primary: spec.is_primary,
        valid_from: None,
        valid_until: None,
    })
    .map_err(|error| capture_invalid(format!("encode expected card image: {error}")))?;
    if target.entity != "user_card"
        || target.key != serde_json::json!({"cardId": card_id})
        || !matches!(&target.before, IdentityPresence::Absent)
        || !matches!(&target.after, IdentityPresence::Present(actual) if actual == &expected)
    {
        return Err(capture_invalid(
            "closed card create after image differs from its retained INSERT facts",
        ));
    }
    Ok(())
}

async fn read_after_target(
    tx: &mut Transaction<'_, MySql>,
    subject: EligibilitySourceSubject,
    before: &IdentityTargetImage,
) -> Result<IdentityTargetImage, PolicyError> {
    let (entity, key, query, id) = match subject {
        EligibilitySourceSubject::UserStatus { user_id }
        | EligibilitySourceSubject::UserDelete { user_id } => (
            "platform_user",
            serde_json::json!({"userId": user_id}),
            "SELECT user_id, status, display_name, email, phone, CAST(deleted_at AS CHAR) AS deleted_at \
             FROM platform_user WHERE user_id = ?",
            user_id,
        ),
        EligibilitySourceSubject::TenantStatus { tenant_id }
        | EligibilitySourceSubject::TenantDelete { tenant_id } => (
            "tenant",
            serde_json::json!({"tenantId": tenant_id}),
            "SELECT tenant_id, tenant_name, tenant_code, status FROM tenant WHERE tenant_id = ?",
            tenant_id,
        ),
        EligibilitySourceSubject::CardStatus { card_id } => (
            "user_card",
            serde_json::json!({"cardId": card_id}),
            "SELECT card_id, card_status, user_id, tenant_id, domain_id, template_id \
             FROM user_card WHERE card_id = ?",
            card_id,
        ),
        EligibilitySourceSubject::CardCreate { card_id } => (
            "user_card",
            serde_json::json!({"cardId": card_id}),
            "SELECT card_id, card_status, user_id, tenant_id, domain_id, template_id, \
             card_type, level_id, priority, is_primary, CAST(valid_from AS CHAR) AS valid_from, \
             CAST(valid_until AS CHAR) AS valid_until FROM user_card WHERE card_id = ?",
            card_id,
        ),
    };
    let after = match subject {
        EligibilitySourceSubject::UserStatus { .. }
        | EligibilitySourceSubject::UserDelete { .. } => {
            let row: Option<UserEligibilityImageRow> = sqlx::query_as(query)
                .bind(id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|error| capture_db_error(error, "read user eligibility after image"))?;
            row.map(
                |UserEligibilityImageRow {
                     user_id,
                     status,
                     display_name,
                     email,
                     phone,
                     deleted_at,
                 }| {
                    serde_json::json!({
                        "userId": user_id,
                        "status": status,
                        "displayName": display_name,
                        "email": email,
                        "phone": phone,
                        "deletedAt": deleted_at,
                    })
                },
            )
        }
        EligibilitySourceSubject::TenantStatus { .. }
        | EligibilitySourceSubject::TenantDelete { .. } => {
            let row: Option<(i64, String, String, String)> = sqlx::query_as(query)
                .bind(id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|error| capture_db_error(error, "read tenant eligibility after image"))?;
            row.map(|(tenant_id, name, code, status)| {
                serde_json::json!({
                    "tenantId": tenant_id,
                    "name": name,
                    "code": code,
                    "status": status,
                })
            })
        }
        EligibilitySourceSubject::CardStatus { .. } => {
            let row: Option<CardEligibilityAfterImageRow> = sqlx::query_as(query)
                .bind(id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|error| capture_db_error(error, "read card eligibility after image"))?;
            row.map(
                |CardEligibilityAfterImageRow {
                     card_id,
                     card_status,
                     user_id,
                     tenant_id,
                     domain_id,
                     template_id,
                 }| {
                    serde_json::json!({
                        "cardId": card_id,
                        "cardStatus": card_status,
                        "userId": user_id,
                        "tenantId": tenant_id,
                        "domainId": domain_id,
                        "templateId": template_id,
                    })
                },
            )
        }
        EligibilitySourceSubject::CardCreate { .. } => {
            let row: Option<CreatedCardImage> = sqlx::query_as(query)
                .bind(id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|error| {
                    capture_db_error(error, "read created card eligibility after image")
                })?;
            row.map(serde_json::to_value)
                .transpose()
                .map_err(|error| capture_invalid(format!("encode created card image: {error}")))?
        }
    };
    let mut target = before.clone();
    target.after = match after {
        Some(value) => IdentityPresence::Present(value),
        None => IdentityPresence::Absent,
    };
    if target.entity != entity || target.key != key {
        return Err(capture_invalid(
            "eligibility target identity changed during mutation",
        ));
    }
    Ok(target)
}

async fn read_audit_receipts(
    tx: &mut Transaction<'_, MySql>,
    subject: EligibilitySourceSubject,
    operation_id: &str,
) -> Result<Vec<IdentityReceipt>, PolicyError> {
    let rows: Vec<(i64, String, Option<String>)> = sqlx::query_as(
        "SELECT id, event_type, detail FROM audit_log WHERE request_id = ? FOR UPDATE",
    )
    .bind(operation_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|error| capture_db_error(error, "read eligibility audit correlation"))?;
    let target_id = subject_id(subject);
    let mut receipts = Vec::new();
    for (id, event_type, detail) in rows {
        let detail_value = detail
            .as_deref()
            .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok());
        let matches_target = detail_value.as_ref().is_some_and(|value| {
            ["targetId", "targetUserId", "targetCardId"]
                .iter()
                .any(|field| {
                    value.get(*field).and_then(serde_json::Value::as_i64) == Some(target_id)
                })
                || value
                    .get("mutation")
                    .and_then(|value| value.get("targetId"))
                    .and_then(serde_json::Value::as_i64)
                    == Some(target_id)
        });
        if matches_target {
            receipts.push(IdentityReceipt {
                entity: "audit_log".to_owned(),
                key: serde_json::json!({"id": id, "eventType": event_type}),
                kind: "INSERT".to_owned(),
                rows_affected: 1,
                durable_id: id.to_string(),
            });
        }
    }
    if receipts.is_empty() {
        return Err(capture_invalid(
            "eligibility source mutation has no matching durable audit correlation",
        ));
    }
    Ok(receipts)
}

async fn read_card_completion_receipts(
    tx: &mut Transaction<'_, MySql>,
    operation_id: &str,
    cards: &[(i64, Option<i64>)],
    mut receipts: Vec<IdentityReceipt>,
) -> Result<(Vec<EligibilityCompletionCapture>, Vec<IdentityReceipt>), PolicyError> {
    let messages: Vec<(String, String)> = sqlx::query_as(
        "SELECT message_id, payload_json FROM al_message_outbox \
         WHERE operation_id = ? AND message_type = 'ELIGIBILITY_INVALIDATED' FOR UPDATE",
    )
    .bind(operation_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|error| capture_db_error(error, "read eligibility typed intent rows"))?;
    let mut captures = Vec::with_capacity(cards.len());
    for (card_id, tenant_id) in cards {
        let head: Option<(i64, i64, Option<String>)> = sqlx::query_as(
            "SELECT source_generation, revoke_fence, last_event_id \
             FROM authorization_projection_head WHERE aggregate_type = ? AND aggregate_id = ? FOR UPDATE",
        )
        .bind(ELIGIBILITY_AGGREGATE_TYPE)
        .bind(card_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| capture_db_error(error, "read eligibility head"))?;
        let Some((generation, revoke_watermark, Some(event_id))) = head else {
            return Err(capture_invalid(
                "eligibility head is missing its event identity",
            ));
        };
        let generation = u64::try_from(generation)
            .map_err(|_| capture_invalid("eligibility generation is negative"))?;
        let revoke_watermark = u64::try_from(revoke_watermark)
            .map_err(|_| capture_invalid("eligibility revoke watermark is negative"))?;
        if generation == 0 || revoke_watermark > generation {
            return Err(capture_invalid(
                "eligibility head has invalid generation fencing",
            ));
        }
        let outbox: Option<(i64, i64)> = sqlx::query_as(
            "SELECT source_generation, revoke_fence FROM authorization_projection_outbox \
             WHERE event_id = ? AND aggregate_type = ? AND aggregate_id = ? FOR UPDATE",
        )
        .bind(&event_id)
        .bind(ELIGIBILITY_AGGREGATE_TYPE)
        .bind(card_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| capture_db_error(error, "read eligibility projection outbox"))?;
        if outbox != Some((generation as i64, revoke_watermark as i64)) {
            return Err(capture_invalid("eligibility outbox differs from its head"));
        }
        receipts.push(IdentityReceipt {
            entity: "authorization_projection_outbox".to_owned(),
            key: serde_json::json!({"eventId": event_id, "aggregateId": card_id}),
            kind: "INSERT".to_owned(),
            rows_affected: 1,
            durable_id: event_id.clone(),
        });
        let mut matching = Vec::new();
        for (message_id, payload_json) in &messages {
            let value: serde_json::Value = serde_json::from_str(payload_json).map_err(|_| {
                capture_invalid("eligibility typed intent payload is not valid JSON")
            })?;
            let payload_card_id = value
                .get("payload")
                .and_then(|payload| payload.get("cardId"))
                .and_then(serde_json::Value::as_i64)
                .or_else(|| value.get("cardId").and_then(serde_json::Value::as_i64));
            if payload_card_id == Some(*card_id) {
                matching.push(message_id.clone());
            }
        }
        if matching.len() != 1 {
            return Err(capture_invalid(
                "eligibility typed intent does not have exactly one card identity",
            ));
        }
        let message_id = matching.remove(0);
        if message_id != event_id {
            return Err(capture_invalid(
                "eligibility projection event and typed intent identities differ",
            ));
        }
        receipts.push(IdentityReceipt {
            entity: "al_message_outbox".to_owned(),
            key: serde_json::json!({"messageId": message_id, "operationId": operation_id}),
            kind: "INSERT".to_owned(),
            rows_affected: 1,
            durable_id: message_id.clone(),
        });
        captures.push(EligibilityCompletionCapture {
            card_id: *card_id,
            tenant_id: *tenant_id,
            generation,
            revoke_watermark,
            outbox_event_id: event_id,
            message_id,
        });
    }
    Ok((captures, receipts))
}

impl<'tx, 'conn> EligibilitySourceCapture<'tx, 'conn> {
    pub async fn begin_in_tx(
        tx: &'tx mut Transaction<'conn, MySql>,
        admission: &AuthorizationAdmission,
        subject: EligibilitySourceSubject,
    ) -> Result<Self, PolicyError> {
        let id = subject_id(subject);
        if id <= 0 {
            return Err(capture_invalid(
                "eligibility source subject id must be positive",
            ));
        }
        let target = match subject {
            EligibilitySourceSubject::UserStatus { user_id }
            | EligibilitySourceSubject::UserDelete { user_id } => {
                read_user_before(tx, user_id).await?
            }
            EligibilitySourceSubject::TenantStatus { tenant_id }
            | EligibilitySourceSubject::TenantDelete { tenant_id } => {
                read_tenant_before(tx, tenant_id).await?
            }
            EligibilitySourceSubject::CardStatus { card_id } => {
                read_card_before(tx, card_id).await?
            }
            EligibilitySourceSubject::CardCreate { .. } => {
                return Err(capture_invalid(
                    "CardCreate requires begin_card_create_in_tx so the capture owns the INSERT",
                ));
            }
        };
        let selected_cards = scan_active_cards(tx, subject).await?;
        Ok(Self {
            tx: Some(tx),
            admission: admission.clone(),
            subject,
            operation: subject_operation(subject),
            target,
            selected_cards,
            captured_receipts: Vec::new(),
            created_card_spec: None,
        })
    }

    /// Closed CardCreate capture. The caller supplies only insert facts, never
    /// a predicted id or a fabricated before-image. The INSERT, generated key,
    /// and locked after-image all belong to this capture and its transaction.
    pub async fn begin_card_create_in_tx(
        tx: &'tx mut Transaction<'conn, MySql>,
        admission: &AuthorizationAdmission,
        spec: CardCreateInsertSpec,
    ) -> Result<Self, PolicyError> {
        spec.validate()?;
        validate_card_create_admission(admission, &spec)?;
        let insert = sqlx::query(
            "INSERT INTO user_card \
             (user_id, domain_id, tenant_id, card_type, card_status, template_id, level_id, priority, is_primary) \
             VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?)",
        )
        .bind(spec.user_id)
        .bind(spec.domain_id)
        .bind(spec.tenant_id)
        .bind(&spec.card_type)
        .bind(spec.template_id)
        .bind(spec.level_id)
        .bind(spec.priority)
        .bind(spec.is_primary)
        .execute(&mut **tx)
        .await
        .map_err(|error| capture_db_error(error, "closed card create insert"))?;
        if insert.rows_affected() != 1 || insert.last_insert_id() == 0 {
            return Err(capture_invalid(
                "closed card create insert did not produce exactly one durable id",
            ));
        }
        let card_id = i64::try_from(insert.last_insert_id())
            .map_err(|_| capture_invalid("closed card create id exceeds supported range"))?;
        let before = absent_card_target(card_id);
        let after = read_after_target(
            tx,
            EligibilitySourceSubject::CardCreate { card_id },
            &before,
        )
        .await?;
        if !matches!(before.before, IdentityPresence::Absent)
            || !matches!(before.after, IdentityPresence::Absent)
            || !matches!(after.after, IdentityPresence::Present(_))
        {
            return Err(capture_invalid(
                "closed card create did not prove before-absent and after-present",
            ));
        }
        validate_created_card_image(&after, card_id, &spec)?;
        let receipt = IdentityReceipt {
            entity: "user_card".to_owned(),
            key: serde_json::json!({"cardId": card_id}),
            kind: "INSERT".to_owned(),
            rows_affected: insert.rows_affected(),
            durable_id: card_id.to_string(),
        };
        Ok(Self {
            tx: Some(tx),
            admission: admission.clone(),
            subject: EligibilitySourceSubject::CardCreate { card_id },
            operation: EligibilitySourceOperation::CardCreate,
            target: before,
            selected_cards: vec![(card_id, Some(spec.tenant_id))],
            captured_receipts: vec![receipt],
            created_card_spec: Some(spec),
        })
    }

    pub fn created_card_id(&self) -> Option<i64> {
        match self.subject {
            EligibilitySourceSubject::CardCreate { card_id } => Some(card_id),
            _ => None,
        }
    }

    pub fn with_tx_mut(&mut self) -> &mut Transaction<'conn, MySql> {
        self.tx
            .as_deref_mut()
            .expect("eligibility source capture transaction was already finished")
    }

    pub fn operation(&self) -> EligibilitySourceOperation {
        self.operation
    }

    pub fn selected_cards(&self) -> &[(i64, Option<i64>)] {
        &self.selected_cards
    }

    pub async fn finish_in_tx(self) -> Result<EligibilitySourceEvidenceReceipt, PolicyError> {
        self.finish(false).await
    }

    /// Seal the same closed INSERT origin for a grant-publication source batch.
    /// This receipt cannot be converted to independent eligibility completion.
    pub async fn finish_publication_in_tx(
        self,
    ) -> Result<EligibilitySourceEvidenceReceipt, PolicyError> {
        if self.operation != EligibilitySourceOperation::CardCreate {
            return Err(capture_invalid(
                "publication origin requires a closed card INSERT",
            ));
        }
        self.finish(true).await
    }

    async fn finish(
        mut self,
        publication_origin: bool,
    ) -> Result<EligibilitySourceEvidenceReceipt, PolicyError> {
        let tx = self
            .tx
            .take()
            .ok_or_else(|| capture_invalid("eligibility source capture was already finished"))?;
        let operation_id = self.admission.operation_id();
        let after_target = read_after_target(&mut *tx, self.subject, &self.target).await?;
        if let Some(spec) = &self.created_card_spec {
            validate_created_card_image(&after_target, subject_id(self.subject), spec)?;
        }
        let source_targets = vec![after_target.clone()];
        let mut target_for_digest = self.target.clone();
        target_for_digest.after = after_target.after.clone();
        let (before_image_digest, after_image_digest) =
            identity_image_digests(&[target_for_digest.clone()])
                .map_err(|error| capture_invalid(error.to_string()))?;
        let mut receipts = self.captured_receipts;
        let source_receipt = captured_source_receipt(self.subject, &target_for_digest)?;
        if let Some(existing) = receipts.iter().find(|receipt| {
            receipt.entity == source_receipt.entity
                && receipt.durable_id == source_receipt.durable_id
        }) {
            if existing.key != source_receipt.key
                || existing.kind != source_receipt.kind
                || existing.rows_affected != source_receipt.rows_affected
            {
                return Err(capture_invalid(
                    "captured source statement conflicts with its actual row transition",
                ));
            }
        } else {
            receipts.push(source_receipt);
        }
        receipts.extend(read_audit_receipts(&mut *tx, self.subject, operation_id).await?);
        let (captures, receipts) =
            read_card_completion_receipts(&mut *tx, operation_id, &self.selected_cards, receipts)
                .await?;
        let completion = if captures.is_empty() {
            let subject_kind = zero_subject_kind(self.operation).ok_or_else(|| {
                capture_invalid("card eligibility mutation cannot prove an empty selector")
            })?;
            let tenant_id = match self.subject {
                EligibilitySourceSubject::TenantStatus { tenant_id }
                | EligibilitySourceSubject::TenantDelete { tenant_id } => Some(tenant_id),
                _ => None,
            };
            let selector_kind = if tenant_id.is_some() {
                AuthorityEligibilityEmptySelectionKind::ActiveCardsByTenantV1
            } else {
                AuthorityEligibilityEmptySelectionKind::ActiveCardsByUserV1
            };
            let zero = AuthorityEligibilityEmptySelectionEvidence {
                subject_kind,
                subject_id: subject_id(self.subject),
                tenant_id,
                schema_version: 1,
                selector: AuthorityEligibilityEmptySelectionSelector {
                    kind: selector_kind,
                    version: 1,
                    completeness: AuthorityEligibilityEmptySelectionCompleteness::ExactFullFanout,
                },
                selected_count: 0,
                source_before_image_digest: before_image_digest.clone(),
                source_after_image_digest: after_image_digest.clone(),
                selection_digest: String::new(),
            };
            let selection_digest = zero
                .recompute_selection_digest()
                .map_err(|error| capture_invalid(error.to_string()))?;
            AuthorityEligibilityCompletionEvidence {
                cards: Vec::new(),
                zero_card_selection: Some(AuthorityEligibilityEmptySelectionEvidence {
                    selection_digest,
                    ..zero
                }),
            }
        } else {
            build_eligibility_completion_evidence(&captures).map_err(|error| {
                capture_invalid(format!("eligibility completion capture invalid: {error:?}"))
            })?
        };
        let source_evidence = serde_json::json!({
            "targets": source_targets,
            "receipts": receipts,
            "fanout": {
                "eligibilityEvents": captures.len(),
                "affectedCards": self.selected_cards.iter().map(|(card_id, tenant_id)| serde_json::json!({
                    "cardId": card_id,
                    "tenantId": tenant_id,
                })).collect::<Vec<_>>(),
            },
        });
        let staged = completion
            .to_staged_envelope(source_evidence.clone())
            .map_err(|error| capture_invalid(error.to_string()))?;
        let _ = staged;
        Ok(EligibilitySourceEvidenceReceipt {
            completion,
            source_evidence,
            source_target: target_for_digest,
            source_receipts: receipts,
            before_image_digest,
            after_image_digest,
            operation: self.operation,
            publication_origin,
            card_rebind: None,
        })
    }
}

impl EligibilitySourceOperation {
    pub fn as_text(&self) -> &'static str {
        match self {
            Self::UserStatus => "USER_STATUS",
            Self::UserDelete => "USER_DELETE",
            Self::TenantStatus => "TENANT_STATUS",
            Self::TenantDelete => "TENANT_DELETE",
            Self::CardStatus => "CARD_STATUS",
            Self::CardCreate => "CARD_CREATE",
            Self::CardRebind => "CARD_REBIND",
        }
    }
}

/// Classify from the actual target entity and shared typed zero-selection
/// discriminator; operation IDs are correlation only and never evidence.
pub fn classify_eligibility_source_operation(
    artifact: &crate::authority_publication::IdentityStagedEvidence,
    completion: &AuthorityEligibilityCompletionEvidence,
) -> Option<EligibilitySourceOperation> {
    verification::classify_eligibility_source_operation(artifact, completion)
}

// ─────────────────────────────────────────────────────────────────────────────
// Authority-facing completion surface
// ─────────────────────────────────────────────────────────────────────────────

/// Terminal response validated by the real authority client. It retains the
/// immutable authority receipt rather than reducing it to a locally invented digest.
pub type AuthorityEligibilityCompletionTerminal =
    astral_types::AuthorityEligibilityCompletionResponse;

/// Authority-facing surface implemented by the real client. Reconciliation is
/// performed by re-reading the exact reservation binding and, only when safe,
/// issuing the same idempotent completion request.
#[async_trait::async_trait]
pub trait EligibilityCompletionGateway: Send + Sync {
    async fn complete_eligibility(
        &self,
        binding: AuthorityCommitBinding,
        completion: AuthorityEligibilityCompletionEvidence,
        retained: AuthorityRetainedStagedEvidence,
    ) -> Result<AuthorityEligibilityCompletionTerminal, astral_authority::AuthorityClientError>;

    async fn reconcile_eligibility(
        &self,
        binding: AuthorityCommitBinding,
        completion: AuthorityEligibilityCompletionEvidence,
        retained: AuthorityRetainedStagedEvidence,
    ) -> Result<
        Option<AuthorityEligibilityCompletionTerminal>,
        astral_authority::AuthorityClientError,
    >;
}

#[async_trait::async_trait]
impl EligibilityCompletionGateway for astral_authority::client::AuthorityClient {
    async fn complete_eligibility(
        &self,
        binding: AuthorityCommitBinding,
        completion: AuthorityEligibilityCompletionEvidence,
        retained: AuthorityRetainedStagedEvidence,
    ) -> Result<AuthorityEligibilityCompletionTerminal, astral_authority::AuthorityClientError>
    {
        astral_authority::client::AuthorityClient::complete_eligibility(
            self, binding, completion, retained,
        )
        .await
    }

    async fn reconcile_eligibility(
        &self,
        binding: AuthorityCommitBinding,
        completion: AuthorityEligibilityCompletionEvidence,
        retained: AuthorityRetainedStagedEvidence,
    ) -> Result<
        Option<AuthorityEligibilityCompletionTerminal>,
        astral_authority::AuthorityClientError,
    > {
        astral_authority::client::AuthorityClient::reconcile_eligibility(
            self, binding, completion, retained,
        )
        .await
        .map(Some)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Bounded worker configuration and report
// ─────────────────────────────────────────────────────────────────────────────

/// Hard-bounded completion worker configuration. The lease owner stays
/// distinct from the source-acknowledgement and publication workers, so the
/// three legs can never share or steal a durable lease.
#[derive(Debug, Clone)]
pub struct EligibilityCompletionReconcilerConfig {
    /// Rows leased per cycle: this protocol runs batch 1.
    pub batch_size: u32,
    /// Lease duration in seconds (5..=3600), set from DB UTC time.
    pub lease_seconds: i64,
    /// Maximum attempts before a row is quarantined (1..=64).
    pub max_attempts: u32,
    /// Stable worker identity; the lease owner is `worker_id/run_instance`.
    pub worker_id: String,
    /// Run-scoped unique instance id (uuid); two live runs never share a lease.
    pub run_instance_id: String,
    /// The ONE source owner pair this instance is responsible for.
    pub owned: AuthoritySourceOwnerEntry,
}

impl Default for EligibilityCompletionReconcilerConfig {
    fn default() -> Self {
        Self {
            batch_size: 1,
            lease_seconds: 30,
            max_attempts: 8,
            worker_id: "authority-eligibility-completion-worker".to_owned(),
            run_instance_id: String::new(),
            owned: AuthoritySourceOwnerEntry {
                service_id: String::new(),
                database_ids: Vec::new(),
            },
        }
    }
}

impl EligibilityCompletionReconcilerConfig {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if !(1..=8).contains(&self.batch_size) {
            return Err(PolicyError::InvalidContext(
                "eligibility completion batch_size must be within 1..=8".into(),
            ));
        }
        if !(5..=3600).contains(&self.lease_seconds) {
            return Err(PolicyError::InvalidContext(
                "eligibility completion lease_seconds must be within 5..=3600".into(),
            ));
        }
        if !(1..=64).contains(&self.max_attempts) {
            return Err(PolicyError::InvalidContext(
                "eligibility completion max_attempts must be within 1..=64".into(),
            ));
        }
        if self.worker_id.is_empty() || self.worker_id.len() + self.run_instance_id.len() + 1 > 128
        {
            return Err(PolicyError::InvalidContext(
                "eligibility completion worker identity must fit the 128-character lease owner"
                    .into(),
            ));
        }
        if self.owned.database_ids.is_empty() {
            return Err(PolicyError::InvalidContext(
                "eligibility completion source owner must register at least one database id".into(),
            ));
        }
        Ok(())
    }

    fn lease_owner(&self) -> String {
        format!("{}/{}", self.worker_id, self.run_instance_id)
    }

    fn owner_is_registered(&self, service_id: &str, database_id: &str) -> bool {
        self.owned.service_id == service_id
            && self.owned.database_ids.iter().any(|id| id == database_id)
    }
}

/// One `run_once` execution report. Terminal counts increment ONLY when their
/// CAS actually applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EligibilityCompletionReconcileReport {
    pub leased: u64,
    pub completed: u64,
    pub confirmed_completed: u64,
    pub stayed_pending: u64,
    pub quarantined: u64,
    pub skipped: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure decisions (unit-tested; no IO)
// ─────────────────────────────────────────────────────────────────────────────

/// Decision after one authority completion attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionOutcomeDecision {
    /// The authority returned a terminal receipt that matches this worker's
    /// exact request: finalize locally as COMPLETED.
    MarkCompleted,
    /// Reconcile by the stable reservation/operation identity first.
    ReconcileByStableIdentity,
    /// Stay pending under the durable lease.
    StayPending,
    /// Terminal operator quarantine with the recorded reason.
    Quarantine(&'static str),
}

/// Pure mapping from an authority completion outcome to the worker decision.
pub fn completion_outcome_decision(
    outcome: &Result<
        AuthorityEligibilityCompletionTerminal,
        astral_authority::AuthorityClientError,
    >,
) -> CompletionOutcomeDecision {
    match outcome {
        Ok(_) => CompletionOutcomeDecision::MarkCompleted,
        Err(error) => match error {
            astral_authority::AuthorityClientError::Rejected { code, .. } => match code.as_str() {
                "StateConflict" | "AlreadyExists" => {
                    CompletionOutcomeDecision::ReconcileByStableIdentity
                }
                "NotFound" => CompletionOutcomeDecision::Quarantine(
                    "authority has no reservation for the eligibility completion",
                ),
                "LeaseExpired" => CompletionOutcomeDecision::Quarantine(
                    "authority refused the eligibility completion: authorization lease expired",
                ),
                "CallerIdentityMismatch"
                | "DigestMismatch"
                | "TrustRootMismatch"
                | "EditionMismatch" => CompletionOutcomeDecision::Quarantine(
                    "authority rejected the eligibility completion binding",
                ),
                _ => CompletionOutcomeDecision::StayPending,
            },
            astral_authority::AuthorityClientError::UnknownOutcome { .. }
            | astral_authority::AuthorityClientError::Transport(_)
            | astral_authority::AuthorityClientError::Attestation(_)
            | astral_authority::AuthorityClientError::InsecureEndpoint
            | astral_authority::AuthorityClientError::Protocol(_)
            | astral_authority::AuthorityClientError::ProtocolError(_) => {
                CompletionOutcomeDecision::StayPending
            }
        },
    }
}

/// Whether an authoritative receipt matches the full committed binding and the
/// shared completion evidence sent by this worker.
pub fn terminal_matches_request(
    terminal: &AuthorityEligibilityCompletionTerminal,
    binding: &AuthorityCommitBinding,
    completion: &AuthorityEligibilityCompletionEvidence,
) -> bool {
    terminal.validate().is_ok()
        && terminal.receipt.binding == *binding
        && terminal.receipt.completion == *completion
        && terminal.receipt.reservation_id == binding.reservation_id
        && terminal.receipt.operation_id == binding.operation_id
        && terminal.receipt.event_id == binding.event_id
        && terminal.reservation.reservation_id == binding.reservation_id
        && terminal.reservation.intent.operation_id == binding.operation_id
}

// ─────────────────────────────────────────────────────────────────────────────
// The bounded worker
// ─────────────────────────────────────────────────────────────────────────────

/// The strict typed staged-evidence tag predicates. Kept in ONE place so the
/// selection, lease CAS and read-back can never drift apart.
pub(crate) const ELIGIBILITY_TAG_PREDICATE: &str =
    "JSON_TYPE(JSON_EXTRACT(staged_evidence, '$.coverage')) <> 'OBJECT' \
     AND JSON_UNQUOTE(JSON_EXTRACT(staged_evidence, '$.evidence.kind')) = 'ELIGIBILITY_COMPLETION'";

const COMPLETION_ROW_COLUMNS: &str = "reservation_id, operation_id, event_id, admission_proof_id, \
     request_binding_digest, mutation_kind, service_id, database_id, \
     source_commit_digest, before_image_digest, after_image_digest, source_receipts, \
     staged_evidence, status, attempts, generation, outcome_digest, committed_at";

const AUTHORITY_ELIGIBILITY_COMPLETION_KIND: &str = "ELIGIBILITY_COMPLETION";

/// Bounded lease/CAS/generation closure worker over tagged `COMMITTED`
/// eligibility outcomes. All lease and expiry comparisons use DB UTC
/// (`UNIX_TIMESTAMP()`), never the application clock.
pub struct AuthorityEligibilityCompletionReconciler {
    pool: Pool<MySql>,
    gateway: Arc<dyn EligibilityCompletionGateway>,
    config: EligibilityCompletionReconcilerConfig,
}

impl AuthorityEligibilityCompletionReconciler {
    pub fn new(
        pool: Pool<MySql>,
        gateway: Arc<dyn EligibilityCompletionGateway>,
        config: EligibilityCompletionReconcilerConfig,
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

    /// Select one tagged `COMMITTED` row and lease it under the generation
    /// fence. Exhausted rows are quarantined only after their lease expired.
    async fn lease_batch(&self) -> Result<(Vec<AuthoritySourceOutcomeRow>, u64, u64), PolicyError> {
        let mut selection = sqlx::QueryBuilder::<MySql>::new(
            "SELECT reservation_id, generation, attempts FROM authority_source_outcome \
             WHERE status = 'COMMITTED' AND mutation_kind = 'AUTHORIZATION_SOURCE' \
             AND (lease_until IS NULL OR lease_until <= UNIX_TIMESTAMP()) AND ",
        );
        selection.push(ELIGIBILITY_TAG_PREDICATE);
        self.push_owner_predicate(&mut selection);
        selection
            .push(" ORDER BY reservation_id LIMIT ")
            .push_bind(self.config.batch_size);
        let candidates: Vec<(String, u64, u32)> = selection
            .build_query_as()
            .fetch_all(&self.pool)
            .await
            .map_err(|error| {
                map_completion_sqlx_error(error, "list tagged eligibility outcomes")
            })?;
        let mut leased = Vec::with_capacity(candidates.len());
        let mut skipped = 0;
        let mut exhausted = 0;
        for (reservation_id, observed_generation, attempts) in candidates {
            if attempts >= self.config.max_attempts {
                let mut quarantine = sqlx::QueryBuilder::<MySql>::new(
                    "UPDATE authority_source_outcome SET status = 'QUARANTINED', \
                     last_error = 'eligibility completion retry budget exhausted; reconcile before recovery', \
                     generation = generation + 1, lease_owner = NULL, lease_until = NULL, \
                     updated_at = UNIX_TIMESTAMP() WHERE status = 'COMMITTED' \
                     AND (lease_until IS NULL OR lease_until <= UNIX_TIMESTAMP()) AND reservation_id = ",
                );
                quarantine
                    .push_bind(reservation_id.clone())
                    .push(" AND generation = ")
                    .push_bind(observed_generation)
                    .push(" AND attempts >= ")
                    .push_bind(self.config.max_attempts)
                    .push(" AND ")
                    .push(ELIGIBILITY_TAG_PREDICATE);
                self.push_owner_predicate(&mut quarantine);
                let result = quarantine
                    .build()
                    .execute(&self.pool)
                    .await
                    .map_err(|error| {
                        map_completion_sqlx_error(
                            error,
                            "quarantine exhausted eligibility completion",
                        )
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
                    "eligibility completion generation exhausted".into(),
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
                .push(
                    " AND status = 'COMMITTED' AND mutation_kind = 'AUTHORIZATION_SOURCE' \
                     AND generation = ",
                )
                .push_bind(observed_generation)
                .push(
                    " AND (lease_until IS NULL OR lease_until <= UNIX_TIMESTAMP()) AND attempts < ",
                )
                .push_bind(self.config.max_attempts)
                .push(" AND ")
                .push(ELIGIBILITY_TAG_PREDICATE);
            self.push_owner_predicate(&mut claim);
            let result = claim.build().execute(&self.pool).await.map_err(|error| {
                map_completion_sqlx_error(error, "lease tagged eligibility outcome")
            })?;
            if result.rows_affected() != 1 {
                skipped += 1;
                continue;
            }
            let mut readback = sqlx::QueryBuilder::<MySql>::new(format!(
                "SELECT {COMPLETION_ROW_COLUMNS} FROM authority_source_outcome \
                 WHERE reservation_id = ",
            ));
            readback
                .push_bind(reservation_id)
                .push(" AND status = 'COMMITTED' AND lease_owner = ")
                .push_bind(self.config.lease_owner())
                .push(" AND lease_until > UNIX_TIMESTAMP() AND generation = ")
                .push_bind(expected_generation)
                .push(" AND attempts <= ")
                .push_bind(self.config.max_attempts)
                .push(" AND ")
                .push(ELIGIBILITY_TAG_PREDICATE);
            self.push_owner_predicate(&mut readback);
            let row: Option<AuthoritySourceOutcomeRow> = readback
                .build_query_as()
                .fetch_optional(&self.pool)
                .await
                .map_err(|error| {
                    map_completion_sqlx_error(error, "reread leased eligibility outcome")
                })?;
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

    /// Finalize one leased row under the full fence: COMMITTED status, the
    /// post-lease generation, OUR lease owner and an unexpired DB-UTC lease.
    /// A worker that lost its lease can never finalize.
    async fn finalize(
        &self,
        row: &AuthoritySourceOutcomeRow,
        operation: Option<EligibilitySourceOperation>,
        response: Option<&AuthorityEligibilityCompletionTerminal>,
        reason: Option<&str>,
    ) -> Result<bool, PolicyError> {
        let mut tx = self.pool.begin().await.map_err(|error| {
            map_completion_sqlx_error(error, "begin eligibility completion finalization")
        })?;
        let (terminal_json, terminal_digest) = if let Some(response) = response {
            response
                .validate()
                .map_err(|error| PolicyError::InvalidContext(error.to_string()))?;
            let json = serde_json::to_string(response).map_err(|_| {
                PolicyError::InvalidContext(
                    "eligibility authority response cannot be encoded".into(),
                )
            })?;
            let digest = hex::encode(Sha256::digest(serde_json::to_vec(response).map_err(
                |_| {
                    PolicyError::InvalidContext(
                        "eligibility authority response cannot be encoded".into(),
                    )
                },
            )?));
            (Some(json), Some(digest))
        } else {
            (None, None)
        };
        let mut query = sqlx::QueryBuilder::<MySql>::new(if response.is_some() {
            "UPDATE authority_source_outcome SET status = 'COMPLETED', \
             authority_disposition = 'COMPLETED', authority_terminal_kind = "
        } else {
            "UPDATE authority_source_outcome SET status = 'QUARANTINED', last_error = "
        });
        if response.is_some() {
            query
                .push_bind(AUTHORITY_ELIGIBILITY_COMPLETION_KIND)
                .push(", authority_terminal_response = ")
                .push_bind(terminal_json.expect("terminal response JSON"))
                .push(", authority_terminal_response_digest = UNHEX(")
                .push_bind(terminal_digest.expect("terminal response digest"))
                .push(")");
        } else {
            query.push_bind(reason.unwrap_or("eligibility completion quarantined"));
        }
        query
            .push(
                ", lease_owner = NULL, lease_until = NULL, updated_at = UNIX_TIMESTAMP() \
                   WHERE reservation_id = ",
            )
            .push_bind(row.reservation_id.clone())
            .push(" AND status = 'COMMITTED' AND lease_owner = ")
            .push_bind(self.config.lease_owner())
            .push(" AND lease_until > UNIX_TIMESTAMP() AND generation = ")
            .push_bind(row.generation);
        self.push_owner_predicate(&mut query);
        let result =
            query.build().execute(&mut *tx).await.map_err(|error| {
                map_completion_sqlx_error(error, "finalize eligibility completion")
            })?;
        if result.rows_affected() != 1 {
            tx.rollback().await.map_err(|error| {
                map_completion_sqlx_error(error, "rollback skipped eligibility finalization")
            })?;
            return Ok(false);
        }
        if let Some(response) = response {
            let stored: Option<(String, String, Vec<u8>)> = sqlx::query_as(
                "SELECT authority_terminal_kind, CAST(authority_terminal_response AS CHAR), \
                 authority_terminal_response_digest FROM authority_source_outcome \
                 WHERE reservation_id = ? AND status = 'COMPLETED' AND generation = ? FOR UPDATE",
            )
            .bind(&row.reservation_id)
            .bind(row.generation)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| {
                map_completion_sqlx_error(error, "read back eligibility terminal response")
            })?;
            let Some((kind, json, digest)) = stored else {
                return Err(PolicyError::Repository(
                    "completed eligibility outcome has no terminal response".into(),
                ));
            };
            let stored_response: AuthorityEligibilityCompletionResponse =
                serde_json::from_str(&json).map_err(|_| {
                    PolicyError::Repository(
                        "stored eligibility terminal response is malformed".into(),
                    )
                })?;
            stored_response
                .validate()
                .map_err(|error| PolicyError::Repository(error.to_string()))?;
            let expected_digest =
                Sha256::digest(serde_json::to_vec(&stored_response).map_err(|_| {
                    PolicyError::Repository(
                        "stored eligibility terminal response cannot be encoded".into(),
                    )
                })?);
            if kind != AUTHORITY_ELIGIBILITY_COMPLETION_KIND
                || stored_response != *response
                || digest.as_slice() != expected_digest.as_slice()
            {
                return Err(PolicyError::Repository(
                    "stored eligibility terminal response failed exact validation".into(),
                ));
            }
            if operation == Some(EligibilitySourceOperation::CardCreate) {
                complete_empty_card_origin_in_tx(&mut tx, response).await?;
            }
        }
        tx.commit().await.map_err(|error| {
            map_completion_sqlx_error(error, "commit eligibility completion finalization")
        })?;
        Ok(true)
    }

    /// One bounded closure cycle.
    pub async fn run_once(&self) -> Result<EligibilityCompletionReconcileReport, PolicyError> {
        let mut report = EligibilityCompletionReconcileReport::default();
        let (rows, skipped, exhausted) = self.lease_batch().await?;
        report.leased = rows.len() as u64;
        report.skipped = skipped + exhausted;
        for row in rows {
            match self.process_row(self.gateway.as_ref(), &row).await {
                Processed::Completed => report.completed += 1,
                Processed::ConfirmedCompleted => report.confirmed_completed += 1,
                Processed::StayedPending => report.stayed_pending += 1,
                Processed::Quarantined => report.quarantined += 1,
            }
        }
        Ok(report)
    }

    async fn process_row(
        &self,
        gateway: &dyn EligibilityCompletionGateway,
        row: &AuthoritySourceOutcomeRow,
    ) -> Processed {
        // Exact read-back verification: the durable row must still satisfy its
        // canonical self-digest at the COMMITTED status.
        let record = match row.to_verified_publication_record("COMMITTED") {
            Ok(record) => record,
            Err(error) => {
                return self
                    .quarantine_row(
                        row,
                        &format!("eligibility outcome failed its read-back: {error}"),
                    )
                    .await
            }
        };
        let staged_evidence = row.staged_evidence.as_deref().ok_or(()).unwrap_or_default();
        if staged_evidence.is_empty() {
            return self
                .quarantine_row(row, "tagged eligibility outcome lacks its staged evidence")
                .await;
        }
        let retained_digest = match eligibility_retained_staged_evidence_digest(staged_evidence) {
            Ok(digest) => digest,
            Err(error) => {
                return self
                    .quarantine_row(row, &format!("staged evidence digest failed: {error}"))
                    .await
            }
        };
        let (_source_envelope, completion, source_value) =
            match parse_eligibility_envelope(staged_evidence) {
                Ok(parsed) => parsed,
                Err(error) => {
                    return self
                        .quarantine_row(
                            row,
                            &format!(
                                "staged evidence is not a valid eligibility completion: {error}"
                            ),
                        )
                        .await
                }
            };
        let artifact: crate::authority_publication::IdentityStagedEvidence =
            match serde_json::from_value(source_value) {
                Ok(artifact) => artifact,
                Err(error) => {
                    return self
                        .quarantine_row(
                            row,
                            &format!("retained identity artifact is invalid: {error}"),
                        )
                        .await
                }
            };
        let Some(operation) = classify_eligibility_source_operation(&artifact, &completion) else {
            return self
                .quarantine_row(
                    row,
                    "retained source images do not prove a whitelisted eligibility mutation",
                )
                .await;
        };
        let (before_image_digest, after_image_digest) =
            match crate::identity_image_digests(&artifact.targets) {
                Ok(digests) => digests,
                Err(error) => {
                    return self
                        .quarantine_row(
                            row,
                            &format!("identity source image digest failed: {error}"),
                        )
                        .await
                }
            };
        if record.before_image_digest.as_deref() != Some(before_image_digest.as_str())
            || record.after_image_digest.as_deref() != Some(after_image_digest.as_str())
        {
            return self
                .quarantine_row(
                    row,
                    "retained source target images do not match the committed before/after digests",
                )
                .await;
        }
        if let Err(error) = tokio::time::timeout(
            Duration::from_secs(3),
            verify_eligibility_completion_durable_facts(
                &self.pool,
                &row.operation_id,
                &completion,
                &artifact,
                operation,
            ),
        )
        .await
        .map_err(|_| {
            EligibilityVerificationError::transient(
                "eligibility durable verification exceeded 3 seconds",
            )
        })
        .and_then(|result| result)
        {
            return match error {
                EligibilityVerificationError::Transient(reason) => {
                    tracing::warn!(
                        reservation_id = %row.reservation_id,
                        operation_id = %row.operation_id,
                        reason = %reason,
                        "eligibility durable verification stayed pending after a transient read failure"
                    );
                    Processed::StayedPending
                }
                EligibilityVerificationError::Proof(reason) => {
                    self.quarantine_row(row, &reason).await
                }
            };
        }
        let Some(after_image_digest) = record.after_image_digest.clone() else {
            return self
                .quarantine_row(row, "source outcome lacks its after-image digest")
                .await;
        };
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
            after_image_digest,
            source_outcome_digest: hex::encode(&row.outcome_digest),
            staged_evidence_digest: retained_digest.clone(),
        };
        if binding.validate().is_err() {
            return self
                .quarantine_row(
                    row,
                    "source outcome cannot form a complete authority binding",
                )
                .await;
        }
        let retained = AuthorityRetainedStagedEvidence::new(staged_evidence.to_owned());
        let outcome = gateway
            .complete_eligibility(binding.clone(), completion.clone(), retained.clone())
            .await;
        match completion_outcome_decision(&outcome) {
            CompletionOutcomeDecision::MarkCompleted => {
                let terminal = outcome.expect("decision guarantees a terminal");
                if !terminal_matches_request(&terminal, &binding, &completion) {
                    return self
                        .quarantine_row(
                            row,
                            "authority terminal receipt does not match the completion request",
                        )
                        .await;
                }
                if self
                    .finalize(row, Some(operation), Some(&terminal), None)
                    .await
                    .unwrap_or(false)
                {
                    Processed::Completed
                } else {
                    Processed::StayedPending
                }
            }
            CompletionOutcomeDecision::ReconcileByStableIdentity => {
                let reconciled = gateway
                    .reconcile_eligibility(binding.clone(), completion.clone(), retained.clone())
                    .await;
                match reconciled {
                    Ok(Some(terminal))
                        if terminal_matches_request(&terminal, &binding, &completion) =>
                    {
                        if self
                            .finalize(row, Some(operation), Some(&terminal), None)
                            .await
                            .unwrap_or(false)
                        {
                            Processed::ConfirmedCompleted
                        } else {
                            Processed::StayedPending
                        }
                    }
                    Ok(Some(_)) => {
                        self.quarantine_row(
                            row,
                            "stable-identity reconciliation returned a non-matching completion",
                        )
                        .await
                    }
                    Ok(None) | Err(_) => Processed::StayedPending,
                }
            }
            CompletionOutcomeDecision::StayPending => Processed::StayedPending,
            CompletionOutcomeDecision::Quarantine(reason) => self.quarantine_row(row, reason).await,
        }
    }

    async fn quarantine_row(&self, row: &AuthoritySourceOutcomeRow, reason: &str) -> Processed {
        match self.finalize(row, None, None, Some(reason)).await {
            Ok(true) => {
                tracing::error!(
                    error_code = "AUTHORITY_ELIGIBILITY_COMPLETION_QUARANTINED",
                    reservation_id = %row.reservation_id,
                    operation_id = %row.operation_id,
                    reason = %reason,
                    "eligibility completion quarantined for operators"
                );
                Processed::Quarantined
            }
            _ => Processed::StayedPending,
        }
    }
}

enum Processed {
    Completed,
    ConfirmedCompleted,
    StayedPending,
    Quarantined,
}

/// Bounded exact request+response audit persisted with the local terminal.
/// The staged artifact itself is never altered.
#[cfg(test)]
fn completion_audit_json(
    terminal: &AuthorityEligibilityCompletionTerminal,
    retained_digest: &str,
) -> String {
    let audit = serde_json::json!({
        "kind": "ELIGIBILITY_COMPLETION_RECEIPT",
        "request": {
            "reservationId": terminal.receipt.reservation_id,
            "operationId": terminal.receipt.operation_id,
            "retainedStagedEvidenceDigest": retained_digest,
        },
        "response": terminal,
    });
    audit.to_string()
}

/// Strictly decode the shared staged envelope and its typed completion evidence.
pub(crate) fn parse_eligibility_envelope(
    staged_evidence: &str,
) -> Result<
    (
        AuthorityStagedSourceEvidence,
        AuthorityEligibilityCompletionEvidence,
        serde_json::Value,
    ),
    PolicyError,
> {
    let envelope: AuthorityStagedSourceEvidence =
        serde_json::from_str(staged_evidence).map_err(|error| {
            PolicyError::InvalidContext(format!("staged evidence envelope is invalid: {error}"))
        })?;
    let completion = AuthorityEligibilityCompletionEvidence::from_staged_envelope(&envelope)
        .map_err(|error| {
            PolicyError::InvalidContext(format!(
                "eligibility completion evidence is invalid: {error}"
            ))
        })?;
    let typed: astral_types::AuthorityEligibilityStagedEvidence =
        serde_json::from_value(envelope.evidence.clone()).map_err(|error| {
            PolicyError::InvalidContext(format!(
                "eligibility completion evidence is invalid: {error}"
            ))
        })?;
    if let Some(card_rebind) = &typed.card_rebind {
        if typed
            .source_evidence
            .get("fanout")
            .and_then(|fanout| fanout.get("cardRebind"))
            != Some(
                &serde_json::to_value(card_rebind)
                    .map_err(|error| capture_invalid(error.to_string()))?,
            )
        {
            return Err(capture_invalid(
                "rebind typed envelope differs from its retained source",
            ));
        }
    } else if typed
        .source_evidence
        .get("fanout")
        .and_then(|fanout| fanout.get("cardRebind"))
        .is_some()
    {
        return Err(capture_invalid("rebind source lacks its typed envelope"));
    }
    Ok((envelope, completion, typed.source_evidence))
}

enum EligibilityVerificationError {
    Transient(String),
    Proof(String),
}

impl EligibilityVerificationError {
    fn transient(message: impl Into<String>) -> Self {
        Self::Transient(message.into())
    }

    fn proof(message: impl Into<String>) -> Self {
        Self::Proof(message.into())
    }

    /// Preserve SQL source classification shared with the typed config reader.
    fn from_sqlx(error: sqlx::Error, context: &'static str) -> Self {
        use crate::authority_config_source::TypedSourceReadError;

        match TypedSourceReadError::from_sqlx(context, error) {
            TypedSourceReadError::SqlxTransient { context, source } => {
                Self::transient(format!("{context}: {source}"))
            }
            error => Self::proof(error.to_string()),
        }
    }
}

/// - the complete scope set equals the artifact's `affectedCards` exactly;
/// - every declared card's ELIGIBILITY head generation/revoke watermark and
///   last event id match byte-exactly;
/// - every declared projection outbox row and typed message intent row exists
///   with the exact declared identity and operation;
/// - the operation has ZERO actual canonical grant delta events.
///
/// Entry point the fence provider's reconciliation cycle joins as its third
/// leg. A production gateway is required; absence is a construction error.
pub async fn reconcile_eligibility_completions(
    pool: Pool<MySql>,
    gateway: Arc<dyn EligibilityCompletionGateway>,
    config: &EligibilityCompletionReconcilerConfig,
) -> Result<EligibilityCompletionReconcileReport, PolicyError> {
    let reconciler = AuthorityEligibilityCompletionReconciler::new(pool, gateway, config.clone())?;
    reconciler.run_once().await
}

#[cfg(test)]
mod tests;
