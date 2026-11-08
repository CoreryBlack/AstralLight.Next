//! Exact durable verification for the V7 ELIGIBILITY completion lane.
//!
//! This module only reads retained source proof and the durable rows it names.
//! Its read transaction is rolled back before the authority call.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{MySql, Pool, Transaction};

use astral_types::{
    AuthorityEligibilityCompletionEvidence, AuthorityEligibilityEmptySelectionSubjectKind,
    AUTHORIZATION_EDITION,
};

use crate::authority_publication::{
    identity_image_digests, IdentityPresence, IdentityStagedEvidence, IdentityTargetImage,
};

use super::{
    EligibilitySourceOperation, EligibilitySourceSubject, EligibilityVerificationError,
    ELIGIBILITY_AGGREGATE_TYPE, ELIGIBILITY_COMPLETION_MAX_CARDS,
};

const ELIGIBILITY_INVALIDATED: &str = "ELIGIBILITY_INVALIDATED";
const INVALIDATION_QUEUE: &str = "astral.authorization.invalidation";
const INVALIDATION_SCHEMA_VERSION: i32 = AUTHORIZATION_EDITION as i32;
const EVENT_TYPE_ELIGIBILITY_UPDATE: &str = "ELIGIBILITY_UPDATE";
const MAX_RETAINED_RECEIPTS: usize = 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredMessageEnvelope {
    message_id: String,
    operation_id: String,
    message_type: String,
    schema_version: i32,
    tenant_id: Option<i64>,
    origin_region: String,
    target_region: Option<String>,
    ordering_key: Option<String>,
    trace_id: Option<String>,
    created_at: String,
    expires_at: Option<String>,
    payload_sha256: String,
    #[serde(default)]
    authority_metadata: Option<Value>,
    payload: Value,
}

#[derive(Debug, sqlx::FromRow)]
struct CurrentUserEligibilityRow {
    user_id: i64,
    status: String,
    display_name: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    deleted_at: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct CurrentCardEligibilityRow {
    card_id: i64,
    card_status: String,
    user_id: Option<i64>,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
    template_id: Option<i64>,
}

#[derive(Debug, sqlx::FromRow)]
struct CurrentCreatedCardEligibilityRow {
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

#[derive(Debug, sqlx::FromRow)]
struct EligibilityProjectionOutboxRow {
    event_id: String,
    source_generation: i64,
    revoke_fence: i64,
    tenant_id: Option<i64>,
    event_type: String,
    payload_json: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct EligibilityMessageOutboxRow {
    message_id: String,
    operation_id: String,
    message_type: String,
    queue_name: String,
    tenant_id: Option<i64>,
    origin_region: String,
    target_region: Option<String>,
    schema_version: i32,
    ordering_key: Option<String>,
    payload_json: String,
    payload_sha256: String,
}

#[derive(Debug, sqlx::FromRow)]
struct ParentProjectionOutboxRow {
    event_id: String,
    aggregate_type: String,
    aggregate_id: i64,
    tenant_id: Option<i64>,
    event_type: String,
    source_generation: i64,
    revoke_fence: i64,
    payload_json: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct EligibilityAuditRow {
    id: i64,
    user_id: i64,
    card_id: Option<i64>,
    action: String,
    resource: String,
    decision: String,
    event_type: String,
    request_id: Option<String>,
    domain_id: Option<i64>,
    tenant_id: Option<i64>,
    detail: Option<String>,
}

struct AuditReceiptExpectation {
    event_type: &'static str,
    action: &'static str,
    detail_action: &'static str,
    decision: &'static str,
}

/// Classify from actual typed target images and the closed zero selector only.
/// Operation-id prefixes are correlation, never mutation evidence.
pub(super) fn classify_eligibility_source_operation(
    artifact: &IdentityStagedEvidence,
    completion: &AuthorityEligibilityCompletionEvidence,
) -> Option<EligibilitySourceOperation> {
    if artifact.targets.len() != 1 || completion.validate().is_err() {
        return None;
    }
    if artifact.fanout.get("cardRebind").is_some() {
        let evidence = super::card_rebind::classify(artifact)?;
        return (completion.cards.len() == 1
            && completion.cards[0].scope.card_identity()
                == Some((evidence.tenant_id, evidence.card_id))
            && artifact
                .fanout
                .get("eligibilityEvents")
                .and_then(Value::as_u64)
                == Some(1))
        .then_some(EligibilitySourceOperation::CardRebind);
    }
    let target = artifact.targets.first()?;
    let operation = classify_target_transition(target)?;
    if completion.cards.is_empty() {
        let zero = completion.zero_card_selection.as_ref()?;
        let expected_kind = match operation {
            EligibilitySourceOperation::UserStatus => {
                AuthorityEligibilityEmptySelectionSubjectKind::UserStatus
            }
            EligibilitySourceOperation::UserDelete => {
                AuthorityEligibilityEmptySelectionSubjectKind::UserDelete
            }
            EligibilitySourceOperation::TenantStatus => {
                AuthorityEligibilityEmptySelectionSubjectKind::TenantStatus
            }
            EligibilitySourceOperation::TenantDelete => {
                AuthorityEligibilityEmptySelectionSubjectKind::TenantDelete
            }
            EligibilitySourceOperation::CardStatus
            | EligibilitySourceOperation::CardCreate
            | EligibilitySourceOperation::CardRebind => return None,
        };
        if zero.subject_kind != expected_kind || zero.subject_id != target_id(target)? {
            return None;
        }
    } else if completion.zero_card_selection.is_some() {
        return None;
    }
    let eligibility_events = artifact
        .fanout
        .get("eligibilityEvents")
        .and_then(Value::as_u64)?;
    (eligibility_events == completion.cards.len() as u64).then_some(operation)
}

/// Verify exact durable facts before the external authority call.
pub(super) async fn verify_eligibility_completion_durable_facts(
    pool: &Pool<MySql>,
    operation_id: &str,
    completion: &AuthorityEligibilityCompletionEvidence,
    artifact: &IdentityStagedEvidence,
    operation: EligibilitySourceOperation,
) -> Result<(), EligibilityVerificationError> {
    let mut tx = pool.begin().await.map_err(|error| {
        EligibilityVerificationError::from_sqlx(error, "eligibility verification transaction begin")
    })?;
    let result = verify_in_tx(&mut tx, operation_id, completion, artifact, operation).await;
    let rollback = tx.rollback().await.map_err(|error| {
        EligibilityVerificationError::from_sqlx(
            error,
            "eligibility verification transaction rollback",
        )
    });
    match (result, rollback) {
        (_, Err(error)) => Err(error),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

async fn verify_in_tx(
    tx: &mut Transaction<'_, MySql>,
    operation_id: &str,
    completion: &AuthorityEligibilityCompletionEvidence,
    artifact: &IdentityStagedEvidence,
    operation: EligibilitySourceOperation,
) -> Result<(), EligibilityVerificationError> {
    if operation_id.trim().is_empty() || operation_id.trim() != operation_id {
        return Err(EligibilityVerificationError::proof(
            "eligibility completion operation identity is not canonical",
        ));
    }
    completion.validate().map_err(|error| {
        EligibilityVerificationError::proof(format!(
            "typed eligibility completion contract rejected: {error}"
        ))
    })?;
    if artifact.targets.len() != 1 {
        return Err(EligibilityVerificationError::proof(
            "eligibility completion requires exactly one retained source target",
        ));
    }
    if artifact.receipts.is_empty() || artifact.receipts.len() > MAX_RETAINED_RECEIPTS {
        return Err(EligibilityVerificationError::proof(
            "eligibility completion retained receipt set is outside its bound",
        ));
    }
    if artifact
        .delta
        .as_ref()
        .is_some_and(|delta| !delta.events.is_empty())
    {
        return Err(EligibilityVerificationError::proof(
            "eligibility completion carries actual grant delta evidence",
        ));
    }

    if operation == EligibilitySourceOperation::CardRebind {
        return super::card_rebind::verify_in_tx(tx, operation_id, completion, artifact).await;
    }
    let target = artifact.targets.first().expect("target count checked");
    let classified =
        classify_eligibility_source_operation(artifact, completion).ok_or_else(|| {
            EligibilityVerificationError::proof(
            "retained target transition and typed selector do not prove an eligibility operation",
        )
        })?;
    if classified != operation {
        return Err(EligibilityVerificationError::proof(
            "retained target transition does not match the supplied operation",
        ));
    }
    validate_zero_selection(completion, artifact, operation, target)?;

    let affected = exact_affected_cards(artifact)?;
    let declared = exact_declared_cards(completion)?;
    if affected != declared {
        return Err(EligibilityVerificationError::proof(
            "completion card set differs from the retained affected card set",
        ));
    }
    let subject = subject_for_operation(operation, target).ok_or_else(|| {
        EligibilityVerificationError::proof("retained target cannot form a typed source subject")
    })?;

    let current_target = read_current_target(tx, subject, target).await?;
    if !presence_equal(&current_target.after, &target.after) {
        return Err(EligibilityVerificationError::proof(
            "current source after image differs from the retained after image",
        ));
    }
    let current_operation = classify_target_transition(&current_target).ok_or_else(|| {
        EligibilityVerificationError::proof(
            "current source image no longer satisfies retained before/after classification",
        )
    })?;
    if current_operation != operation {
        return Err(EligibilityVerificationError::proof(
            "current source image classification drifted from the retained operation",
        ));
    }
    if let Some(zero) = completion.zero_card_selection.as_ref() {
        let (before_digest, after_digest) =
            identity_image_digests(&artifact.targets).map_err(|error| {
                EligibilityVerificationError::proof(format!(
                    "retained source image digest cannot be recomputed: {error}"
                ))
            })?;
        if zero.source_before_image_digest != before_digest
            || zero.source_after_image_digest != after_digest
        {
            return Err(EligibilityVerificationError::proof(
                "zero-card source image digests differ from retained target images",
            ));
        }
    }

    let actual_selector = read_selector_cards(tx, subject).await?;
    if actual_selector != affected {
        return Err(EligibilityVerificationError::proof(
            "durable selector result differs from the complete retained card set",
        ));
    }

    verify_heads_and_outboxes(tx, completion).await?;
    verify_message_set(tx, operation_id, completion).await?;
    verify_exact_receipts(tx, operation_id, operation, target, artifact, completion).await?;

    if operation == EligibilitySourceOperation::CardCreate {
        crate::authority_publication::verify_card_create_bindings_structured_in_tx(tx, artifact)
            .await
            .map_err(|error| match error {
                crate::authority_publication::CardCreateBindingVerifyError::Pending(message) => {
                    EligibilityVerificationError::proof(message)
                }
                crate::authority_publication::CardCreateBindingVerifyError::Database(error) => {
                    EligibilityVerificationError::from_sqlx(
                        error,
                        "CardCreate binding readback failed",
                    )
                }
            })?;
    } else if artifact.fanout.get("cardCreateRuleSetBindings").is_some() {
        return Err(EligibilityVerificationError::proof(
            "RuleSet creation bindings cannot accompany another eligibility mutation",
        ));
    }
    let grant_delta: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM authorization_delta_event WHERE operation_id = ? LIMIT 1 FOR UPDATE",
    )
    .bind(operation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| {
        EligibilityVerificationError::from_sqlx(error, "grant delta assertion failed")
    })?;
    if grant_delta.is_some() {
        return Err(EligibilityVerificationError::proof(
            "eligibility completion operation has an actual canonical grant delta",
        ));
    }
    Ok(())
}

pub(super) async fn verify_rebind_delivery(
    tx: &mut Transaction<'_, MySql>,
    operation_id: &str,
    completion: &AuthorityEligibilityCompletionEvidence,
    artifact: &IdentityStagedEvidence,
) -> Result<(), EligibilityVerificationError> {
    if exact_affected_cards(artifact)? != exact_declared_cards(completion)? {
        return Err(EligibilityVerificationError::proof(
            "rebind affected Card set differs",
        ));
    }
    verify_heads_and_outboxes(tx, completion).await?;
    verify_message_set(tx, operation_id, completion).await
}

fn exact_affected_cards(
    artifact: &IdentityStagedEvidence,
) -> Result<BTreeSet<(i64, i64)>, EligibilityVerificationError> {
    let cards = artifact.affected_cards().map_err(|error| {
        EligibilityVerificationError::proof(format!(
            "retained artifact affected card set is malformed: {error}"
        ))
    })?;
    if cards.len() > ELIGIBILITY_COMPLETION_MAX_CARDS {
        return Err(EligibilityVerificationError::proof(
            "retained affected card set exceeds the completion bound",
        ));
    }
    let mut result = BTreeSet::new();
    for card in cards {
        let Some(tenant_id) = card.tenant_id else {
            return Err(EligibilityVerificationError::proof(
                "affected card set lacks a tenant identity",
            ));
        };
        if card.card_id <= 0 || tenant_id <= 0 || !result.insert((tenant_id, card.card_id)) {
            return Err(EligibilityVerificationError::proof(
                "affected card set contains an invalid or duplicate identity",
            ));
        }
    }
    Ok(result)
}

fn exact_declared_cards(
    completion: &AuthorityEligibilityCompletionEvidence,
) -> Result<BTreeSet<(i64, i64)>, EligibilityVerificationError> {
    let mut result = BTreeSet::new();
    for card in &completion.cards {
        let Some((tenant_id, card_id)) = card.scope.card_identity() else {
            return Err(EligibilityVerificationError::proof(
                "completion contains a non-card scope",
            ));
        };
        if tenant_id <= 0 || card_id <= 0 || !result.insert((tenant_id, card_id)) {
            return Err(EligibilityVerificationError::proof(
                "completion contains an invalid or duplicate card identity",
            ));
        }
    }
    Ok(result)
}

fn validate_zero_selection(
    completion: &AuthorityEligibilityCompletionEvidence,
    artifact: &IdentityStagedEvidence,
    operation: EligibilitySourceOperation,
    target: &IdentityTargetImage,
) -> Result<(), EligibilityVerificationError> {
    if !completion.cards.is_empty() {
        if completion.zero_card_selection.is_some() {
            return Err(EligibilityVerificationError::proof(
                "non-empty eligibility completion carries a zero-card selector",
            ));
        }
        return Ok(());
    }
    let Some(zero) = completion.zero_card_selection.as_ref() else {
        return Err(EligibilityVerificationError::proof(
            "empty eligibility completion lacks its typed full-selector proof",
        ));
    };
    zero.validate().map_err(|error| {
        EligibilityVerificationError::proof(format!("zero-card selector rejected: {error}"))
    })?;
    if !exact_affected_cards(artifact)?.is_empty() || zero.selected_count != 0 {
        return Err(EligibilityVerificationError::proof(
            "zero-card completion does not retain an exact empty affected set",
        ));
    }
    if Some(zero.subject_id) != target_id(target) {
        return Err(EligibilityVerificationError::proof(
            "zero-card subject id differs from retained target",
        ));
    }
    let expected = match operation {
        EligibilitySourceOperation::UserStatus => {
            AuthorityEligibilityEmptySelectionSubjectKind::UserStatus
        }
        EligibilitySourceOperation::UserDelete => {
            AuthorityEligibilityEmptySelectionSubjectKind::UserDelete
        }
        EligibilitySourceOperation::TenantStatus => {
            AuthorityEligibilityEmptySelectionSubjectKind::TenantStatus
        }
        EligibilitySourceOperation::TenantDelete => {
            AuthorityEligibilityEmptySelectionSubjectKind::TenantDelete
        }
        EligibilitySourceOperation::CardStatus
        | EligibilitySourceOperation::CardCreate
        | EligibilitySourceOperation::CardRebind => {
            return Err(EligibilityVerificationError::proof(
                "card operation cannot prove a zero-card selector",
            ))
        }
    };
    if zero.subject_kind != expected {
        return Err(EligibilityVerificationError::proof(
            "zero-card subject kind differs from actual target transition",
        ));
    }
    Ok(())
}

fn subject_for_operation(
    operation: EligibilitySourceOperation,
    target: &IdentityTargetImage,
) -> Option<EligibilitySourceSubject> {
    let id = target_id(target)?;
    match operation {
        EligibilitySourceOperation::UserStatus => (target.entity == "platform_user")
            .then_some(EligibilitySourceSubject::UserStatus { user_id: id }),
        EligibilitySourceOperation::UserDelete => (target.entity == "platform_user")
            .then_some(EligibilitySourceSubject::UserDelete { user_id: id }),
        EligibilitySourceOperation::TenantStatus => (target.entity == "tenant")
            .then_some(EligibilitySourceSubject::TenantStatus { tenant_id: id }),
        EligibilitySourceOperation::TenantDelete => (target.entity == "tenant")
            .then_some(EligibilitySourceSubject::TenantDelete { tenant_id: id }),
        EligibilitySourceOperation::CardRebind => None,
        EligibilitySourceOperation::CardStatus => (target.entity == "user_card")
            .then_some(EligibilitySourceSubject::CardStatus { card_id: id }),
        EligibilitySourceOperation::CardCreate => (target.entity == "user_card")
            .then_some(EligibilitySourceSubject::CardCreate { card_id: id }),
    }
}

fn target_id(target: &IdentityTargetImage) -> Option<i64> {
    let field = match target.entity.as_str() {
        "platform_user" => "userId",
        "tenant" => "tenantId",
        "user_card" => "cardId",
        _ => return None,
    };
    let object = target.key.as_object()?;
    if object.len() != 1 {
        return None;
    }
    let id = object.get(field)?.as_i64()?;
    (id > 0).then_some(id)
}

fn classify_target_transition(target: &IdentityTargetImage) -> Option<EligibilitySourceOperation> {
    let id = target_id(target)?;
    let candidates: &[(EligibilitySourceOperation, EligibilitySourceSubject)] =
        match target.entity.as_str() {
            "platform_user" => &[
                (
                    EligibilitySourceOperation::UserStatus,
                    EligibilitySourceSubject::UserStatus { user_id: id },
                ),
                (
                    EligibilitySourceOperation::UserDelete,
                    EligibilitySourceSubject::UserDelete { user_id: id },
                ),
            ],
            "tenant" => &[
                (
                    EligibilitySourceOperation::TenantStatus,
                    EligibilitySourceSubject::TenantStatus { tenant_id: id },
                ),
                (
                    EligibilitySourceOperation::TenantDelete,
                    EligibilitySourceSubject::TenantDelete { tenant_id: id },
                ),
            ],
            "user_card" => &[
                (
                    EligibilitySourceOperation::CardStatus,
                    EligibilitySourceSubject::CardStatus { card_id: id },
                ),
                (
                    EligibilitySourceOperation::CardCreate,
                    EligibilitySourceSubject::CardCreate { card_id: id },
                ),
            ],
            _ => return None,
        };
    candidates.iter().find_map(|(operation, subject)| {
        super::captured_source_receipt(*subject, target)
            .ok()
            .map(|_| *operation)
    })
}

fn presence_equal(left: &IdentityPresence, right: &IdentityPresence) -> bool {
    match (left, right) {
        (IdentityPresence::Absent, IdentityPresence::Absent) => true,
        (IdentityPresence::Present(left), IdentityPresence::Present(right)) => left == right,
        _ => false,
    }
}

async fn read_current_target(
    tx: &mut Transaction<'_, MySql>,
    subject: EligibilitySourceSubject,
    target: &IdentityTargetImage,
) -> Result<IdentityTargetImage, EligibilityVerificationError> {
    let id = target_id(target).ok_or_else(|| {
        EligibilityVerificationError::proof("retained source target identity is malformed")
    })?;
    let after = match subject {
        EligibilitySourceSubject::UserStatus { .. }
        | EligibilitySourceSubject::UserDelete { .. } => {
            let row: Option<CurrentUserEligibilityRow> = sqlx::query_as(
                "SELECT user_id, status, display_name, email, phone, \
                 CAST(deleted_at AS CHAR) AS deleted_at \
                 FROM platform_user WHERE user_id = ? LIMIT 1 FOR UPDATE",
            )
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|error| {
                EligibilityVerificationError::from_sqlx(error, "read current user image")
            })?;
            row.map(
                |CurrentUserEligibilityRow {
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
            let row: Option<(i64, String, String, String)> = sqlx::query_as(
                "SELECT tenant_id, tenant_name, tenant_code, status \
                 FROM tenant WHERE tenant_id = ? LIMIT 1 FOR UPDATE",
            )
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|error| {
                EligibilityVerificationError::from_sqlx(error, "read current tenant image")
            })?;
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
            let row: Option<CurrentCardEligibilityRow> = sqlx::query_as(
                "SELECT card_id, card_status, user_id, tenant_id, domain_id, template_id \
                 FROM user_card WHERE card_id = ? LIMIT 1 FOR UPDATE",
            )
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|error| {
                EligibilityVerificationError::from_sqlx(error, "read current card image")
            })?;
            row.map(
                |CurrentCardEligibilityRow {
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
            let row: Option<CurrentCreatedCardEligibilityRow> = sqlx::query_as(
                "SELECT card_id, card_status, user_id, tenant_id, domain_id, template_id, \
                 card_type, level_id, priority, is_primary, \
                 CAST(valid_from AS CHAR) AS valid_from, CAST(valid_until AS CHAR) AS valid_until \
                 FROM user_card WHERE card_id = ? LIMIT 1 FOR UPDATE",
            )
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|error| {
                EligibilityVerificationError::from_sqlx(error, "read current created card image")
            })?;
            row.map(
                |CurrentCreatedCardEligibilityRow {
                     card_id,
                     card_status,
                     user_id,
                     tenant_id,
                     domain_id,
                     template_id,
                     card_type,
                     level_id,
                     priority,
                     is_primary,
                     valid_from,
                     valid_until,
                 }| {
                    serde_json::json!({
                        "cardId": card_id,
                        "cardStatus": card_status,
                        "userId": user_id,
                        "tenantId": tenant_id,
                        "domainId": domain_id,
                        "templateId": template_id,
                        "cardType": card_type,
                        "levelId": level_id,
                        "priority": priority,
                        "isPrimary": is_primary,
                        "validFrom": valid_from,
                        "validUntil": valid_until,
                    })
                },
            )
        }
    };
    let mut current = target.clone();
    current.after = match after {
        Some(value) => IdentityPresence::Present(value),
        None => IdentityPresence::Absent,
    };
    Ok(current)
}

async fn read_selector_cards(
    tx: &mut Transaction<'_, MySql>,
    subject: EligibilitySourceSubject,
) -> Result<BTreeSet<(i64, i64)>, EligibilityVerificationError> {
    let limit = i64::try_from(ELIGIBILITY_COMPLETION_MAX_CARDS + 1).map_err(|_| {
        EligibilityVerificationError::proof("eligibility selector bound overflows SQL integer")
    })?;
    let rows: Vec<(i64, Option<i64>)> = match subject {
        EligibilitySourceSubject::UserStatus { user_id }
        | EligibilitySourceSubject::UserDelete { user_id } => sqlx::query_as(
            "SELECT card_id, tenant_id FROM user_card \
             WHERE user_id = ? AND card_status = 'ACTIVE' \
             ORDER BY card_id LIMIT ? FOR UPDATE",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&mut **tx)
        .await
        .map_err(|error| {
            EligibilityVerificationError::from_sqlx(error, "read active user selector")
        })?,
        EligibilitySourceSubject::TenantStatus { tenant_id }
        | EligibilitySourceSubject::TenantDelete { tenant_id } => sqlx::query_as(
            "SELECT card_id, tenant_id FROM user_card \
             WHERE tenant_id = ? AND card_status = 'ACTIVE' \
             ORDER BY card_id LIMIT ? FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&mut **tx)
        .await
        .map_err(|error| {
            EligibilityVerificationError::from_sqlx(error, "read active tenant selector")
        })?,
        EligibilitySourceSubject::CardStatus { card_id }
        | EligibilitySourceSubject::CardCreate { card_id } => sqlx::query_as(
            "SELECT card_id, tenant_id FROM user_card \
             WHERE card_id = ? LIMIT 1 FOR UPDATE",
        )
        .bind(card_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(|error| EligibilityVerificationError::from_sqlx(error, "read card selector"))?,
    };
    if rows.len() > ELIGIBILITY_COMPLETION_MAX_CARDS {
        return Err(EligibilityVerificationError::proof(
            "durable eligibility selector exceeds the completion bound",
        ));
    }
    let mut result = BTreeSet::new();
    for (card_id, tenant_id) in rows {
        let Some(tenant_id) = tenant_id else {
            return Err(EligibilityVerificationError::proof(
                "durable selector returned a card without a tenant",
            ));
        };
        if card_id <= 0 || tenant_id <= 0 || !result.insert((tenant_id, card_id)) {
            return Err(EligibilityVerificationError::proof(
                "durable selector returned an invalid or duplicate card",
            ));
        }
        if matches!(
            subject,
            EligibilitySourceSubject::TenantStatus { tenant_id: expected }
                | EligibilitySourceSubject::TenantDelete { tenant_id: expected }
                if tenant_id != expected
        ) {
            return Err(EligibilityVerificationError::proof(
                "durable tenant selector crossed tenant ownership",
            ));
        }
    }
    Ok(result)
}

async fn verify_heads_and_outboxes(
    tx: &mut Transaction<'_, MySql>,
    completion: &AuthorityEligibilityCompletionEvidence,
) -> Result<BTreeSet<String>, EligibilityVerificationError> {
    let mut projection_ids = BTreeSet::new();
    for card in &completion.cards {
        let Some((tenant_id, card_id)) = card.scope.card_identity() else {
            return Err(EligibilityVerificationError::proof(
                "completion contains a non-card scope",
            ));
        };
        if card.message_id != card.outbox_event_id {
            return Err(EligibilityVerificationError::proof(
                "completion message and projection event identities differ",
            ));
        }
        let head: Option<(i64, i64, Option<String>)> = sqlx::query_as(
            "SELECT source_generation, revoke_fence, last_event_id \
             FROM authorization_projection_head \
             WHERE aggregate_type = ? AND aggregate_id = ? LIMIT 1 FOR UPDATE",
        )
        .bind(ELIGIBILITY_AGGREGATE_TYPE)
        .bind(card_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| EligibilityVerificationError::from_sqlx(error, "read eligibility head"))?;
        let Some((generation, revoke_fence, last_event_id)) = head else {
            return Err(EligibilityVerificationError::proof(format!(
                "card {card_id} has no durable ELIGIBILITY head"
            )));
        };
        let generation = u64::try_from(generation).map_err(|_| {
            EligibilityVerificationError::proof("durable eligibility generation is negative")
        })?;
        let revoke_fence = u64::try_from(revoke_fence).map_err(|_| {
            EligibilityVerificationError::proof("durable eligibility revoke fence is negative")
        })?;
        if generation == 0
            || revoke_fence > generation
            || generation != card.generation
            || revoke_fence != card.revoke_watermark
            || last_event_id.as_deref() != Some(card.outbox_event_id.as_str())
        {
            return Err(EligibilityVerificationError::proof(format!(
                "durable ELIGIBILITY head differs from card {card_id} completion identity"
            )));
        }
        let card_tenant: Option<i64> = sqlx::query_scalar(
            "SELECT tenant_id FROM user_card WHERE card_id = ? LIMIT 1 FOR UPDATE",
        )
        .bind(card_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| {
            EligibilityVerificationError::from_sqlx(error, "read eligibility card tenant")
        })?;
        if card_tenant != Some(tenant_id) {
            return Err(EligibilityVerificationError::proof(format!(
                "card {card_id} tenant differs from completion scope"
            )));
        }
        let outbox: Option<EligibilityProjectionOutboxRow> = sqlx::query_as(
            "SELECT event_id, source_generation, revoke_fence, tenant_id, event_type, payload_json \
             FROM authorization_projection_outbox \
             WHERE event_id = ? AND aggregate_type = ? AND aggregate_id = ? \
             LIMIT 1 FOR UPDATE",
        )
        .bind(&card.outbox_event_id)
        .bind(ELIGIBILITY_AGGREGATE_TYPE)
        .bind(card_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| {
            EligibilityVerificationError::from_sqlx(error, "read eligibility projection outbox")
        })?;
        let Some(EligibilityProjectionOutboxRow {
            event_id,
            source_generation: outbox_generation,
            revoke_fence: outbox_fence,
            tenant_id: outbox_tenant,
            event_type,
            payload_json: payload,
        }) = outbox
        else {
            return Err(EligibilityVerificationError::proof(format!(
                "card {card_id} completion event has no durable projection outbox row"
            )));
        };
        let actual_payload: Value = payload
            .as_deref()
            .ok_or_else(|| {
                EligibilityVerificationError::proof(
                    "eligibility projection outbox payload is absent",
                )
            })
            .and_then(|value| {
                serde_json::from_str(value).map_err(|error| {
                    EligibilityVerificationError::proof(format!(
                        "eligibility projection outbox payload is malformed: {error}"
                    ))
                })
            })?;
        let expected_payload = serde_json::json!({
            "cardId": card_id,
            "tenantId": tenant_id,
            "generation": generation,
        });
        if event_id != card.outbox_event_id
            || u64::try_from(outbox_generation).ok() != Some(generation)
            || u64::try_from(outbox_fence).ok() != Some(revoke_fence)
            || outbox_tenant != Some(tenant_id)
            || event_type != EVENT_TYPE_ELIGIBILITY_UPDATE
            || actual_payload != expected_payload
        {
            return Err(EligibilityVerificationError::proof(format!(
                "eligibility projection outbox row differs for card {card_id}"
            )));
        }
        if !projection_ids.insert(event_id) {
            return Err(EligibilityVerificationError::proof(
                "completion contains duplicate projection event identity",
            ));
        }
    }
    Ok(projection_ids)
}

async fn verify_message_set(
    tx: &mut Transaction<'_, MySql>,
    operation_id: &str,
    completion: &AuthorityEligibilityCompletionEvidence,
) -> Result<(), EligibilityVerificationError> {
    let limit = i64::try_from(ELIGIBILITY_COMPLETION_MAX_CARDS + 1).map_err(|_| {
        EligibilityVerificationError::proof("eligibility message-set bound overflows SQL integer")
    })?;
    let rows: Vec<EligibilityMessageOutboxRow> = sqlx::query_as(
        "SELECT message_id, operation_id, message_type, queue_name, tenant_id, origin_region, \
         target_region, schema_version, ordering_key, payload_json, payload_sha256 \
         FROM al_message_outbox \
         WHERE operation_id = ? AND message_type = 'ELIGIBILITY_INVALIDATED' \
         ORDER BY message_id LIMIT ? FOR UPDATE",
    )
    .bind(operation_id)
    .bind(limit)
    .fetch_all(&mut **tx)
    .await
    .map_err(|error| {
        EligibilityVerificationError::from_sqlx(error, "read eligibility message set")
    })?;
    if rows.len() > ELIGIBILITY_COMPLETION_MAX_CARDS {
        return Err(EligibilityVerificationError::proof(
            "durable eligibility message set exceeds the completion bound",
        ));
    }
    let mut expected: BTreeMap<String, (i64, String)> = BTreeMap::new();
    for card in &completion.cards {
        let (_, card_id) = card.scope.card_identity().ok_or_else(|| {
            EligibilityVerificationError::proof("completion contains a non-card scope")
        })?;
        if expected
            .insert(
                card.message_id.clone(),
                (card_id, card.outbox_event_id.clone()),
            )
            .is_some()
        {
            return Err(EligibilityVerificationError::proof(
                "completion contains duplicate message identity",
            ));
        }
    }
    let mut actual = BTreeSet::new();
    for EligibilityMessageOutboxRow {
        message_id,
        operation_id: stored_operation,
        message_type,
        queue_name,
        tenant_id,
        origin_region,
        target_region,
        schema_version,
        ordering_key,
        payload_json,
        payload_sha256,
    } in rows
    {
        if !actual.insert(message_id.clone()) {
            return Err(EligibilityVerificationError::proof(
                "durable eligibility message set contains duplicate identity",
            ));
        }
        let Some((card_id, event_id)) = expected.get(&message_id) else {
            return Err(EligibilityVerificationError::proof(
                "durable eligibility message set contains an undeclared message",
            ));
        };
        let envelope: StoredMessageEnvelope =
            serde_json::from_str(&payload_json).map_err(|error| {
                EligibilityVerificationError::proof(format!(
                    "typed eligibility envelope is malformed: {error}"
                ))
            })?;
        let expected_payload = serde_json::json!({ "cardId": card_id });
        let expected_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(&expected_payload).map_err(|error| {
                EligibilityVerificationError::proof(format!(
                    "eligibility payload cannot be encoded: {error}"
                ))
            })?,
        ));
        let expected_ordering_key = format!("authorization:eligibility/card/{card_id}");
        if message_id.as_str() != event_id.as_str()
            || stored_operation != operation_id
            || message_type != ELIGIBILITY_INVALIDATED
            || queue_name != INVALIDATION_QUEUE
            || tenant_id.is_some()
            || origin_region.trim().is_empty()
            || target_region.is_some()
            || schema_version != INVALIDATION_SCHEMA_VERSION
            || ordering_key.as_deref() != Some(expected_ordering_key.as_str())
            || envelope.message_id != message_id
            || envelope.operation_id != operation_id
            || envelope.message_type != ELIGIBILITY_INVALIDATED
            || envelope.schema_version != INVALIDATION_SCHEMA_VERSION
            || envelope.tenant_id.is_some()
            || envelope.origin_region != origin_region
            || envelope.target_region.is_some()
            || envelope.ordering_key.as_deref() != Some(expected_ordering_key.as_str())
            || envelope.trace_id.is_some()
            || envelope.expires_at.is_some()
            || envelope.authority_metadata.is_some()
            || envelope.created_at.trim().is_empty()
            || envelope.payload != expected_payload
            || envelope.payload_sha256 != expected_hash
            || payload_sha256 != expected_hash
        {
            return Err(EligibilityVerificationError::proof(
                "durable ELIGIBILITY_INVALIDATED envelope differs from typed card identity",
            ));
        }
    }
    let expected_ids: BTreeSet<String> = expected.keys().cloned().collect();
    if actual != expected_ids {
        return Err(EligibilityVerificationError::proof(
            "durable eligibility message set is not exactly equal to the completion set",
        ));
    }
    Ok(())
}

async fn verify_exact_receipts(
    tx: &mut Transaction<'_, MySql>,
    operation_id: &str,
    operation: EligibilitySourceOperation,
    target: &IdentityTargetImage,
    artifact: &IdentityStagedEvidence,
    completion: &AuthorityEligibilityCompletionEvidence,
) -> Result<(), EligibilityVerificationError> {
    let expected_source_receipt = super::captured_source_receipt(
        subject_for_operation(operation, target).ok_or_else(|| {
            EligibilityVerificationError::proof(
                "retained target cannot form a typed source subject for receipt validation",
            )
        })?,
        target,
    )
    .map_err(|error| {
        EligibilityVerificationError::proof(format!(
            "closed source transition receipt rejected: {error}"
        ))
    })?;
    let expected_target_entity = expected_source_receipt.entity.as_str();
    let expected_target_id = target_id(target).ok_or_else(|| {
        EligibilityVerificationError::proof("retained target id is unavailable for receipt checks")
    })?;
    let expected_source_kind = expected_source_receipt.kind.as_str();
    let expected_audit_event = match operation {
        EligibilitySourceOperation::UserStatus | EligibilitySourceOperation::UserDelete => {
            "IDENTITY_USER_MUTATION"
        }
        EligibilitySourceOperation::TenantStatus | EligibilitySourceOperation::TenantDelete => {
            "IDENTITY_ORG_MUTATION"
        }
        EligibilitySourceOperation::CardStatus
        | EligibilitySourceOperation::CardCreate
        | EligibilitySourceOperation::CardRebind => "USER_CARD_MUTATION",
    };
    let expected_audit_action = match operation {
        EligibilitySourceOperation::UserStatus | EligibilitySourceOperation::TenantStatus => {
            "update"
        }
        EligibilitySourceOperation::UserDelete | EligibilitySourceOperation::TenantDelete => {
            "delete"
        }
        EligibilitySourceOperation::CardRebind => "card_template_change",
        EligibilitySourceOperation::CardStatus => "card_status_change",
        EligibilitySourceOperation::CardCreate => "card_create",
    };
    let expected_audit_detail_action = match operation {
        EligibilitySourceOperation::UserStatus | EligibilitySourceOperation::TenantStatus => {
            "update"
        }
        EligibilitySourceOperation::UserDelete | EligibilitySourceOperation::TenantDelete => {
            "delete"
        }
        EligibilitySourceOperation::CardRebind => "card_template_change",
        EligibilitySourceOperation::CardStatus => "status_revoke",
        EligibilitySourceOperation::CardCreate => "card_create",
    };
    let expected_audit_decision = match operation {
        EligibilitySourceOperation::CardStatus => "CARD_REVOKED",
        EligibilitySourceOperation::CardCreate => "CARD_CREATED",
        _ => "SUCCESS",
    };
    let audit_expectation = AuditReceiptExpectation {
        event_type: expected_audit_event,
        action: expected_audit_action,
        detail_action: expected_audit_detail_action,
        decision: expected_audit_decision,
    };

    let completion_cards_by_event: BTreeMap<&str, (i64, i64)> = completion
        .cards
        .iter()
        .filter_map(|card| {
            card.scope
                .card_identity()
                .map(|(tenant_id, card_id)| (card.outbox_event_id.as_str(), (tenant_id, card_id)))
        })
        .collect();
    let completion_cards_by_message: BTreeMap<&str, (i64, i64)> = completion
        .cards
        .iter()
        .filter_map(|card| {
            card.scope
                .card_identity()
                .map(|(tenant_id, card_id)| (card.message_id.as_str(), (tenant_id, card_id)))
        })
        .collect();
    let mut seen = BTreeSet::new();
    let mut source_count = 0usize;
    let mut audit_count = 0usize;
    let mut eligibility_projection_count = 0usize;
    let mut parent_projection_count = 0usize;
    let mut message_count = 0usize;
    let expected_message_ids: BTreeSet<String> = artifact
        .receipts
        .iter()
        .filter(|receipt| receipt.entity == "al_message_outbox")
        .map(|receipt| receipt.durable_id.clone())
        .collect();
    let completion_message_ids: BTreeSet<String> = completion
        .cards
        .iter()
        .map(|card| card.message_id.clone())
        .collect();
    if expected_message_ids != completion_message_ids {
        return Err(EligibilityVerificationError::proof(
            "retained message receipts differ from the exact completion message set",
        ));
    }
    for receipt in &artifact.receipts {
        if receipt.rows_affected != 1
            || receipt.entity.trim().is_empty()
            || receipt.durable_id.trim().is_empty()
            || !seen.insert((receipt.entity.clone(), receipt.durable_id.clone()))
        {
            return Err(EligibilityVerificationError::proof(
                "retained source receipt set contains an invalid or duplicate identity",
            ));
        }
        match receipt.entity.as_str() {
            entity if entity == expected_target_entity => {
                source_count += 1;
                if receipt.kind != expected_source_kind
                    || receipt.durable_id != expected_target_id.to_string()
                    || receipt.key != target_key(expected_target_entity, expected_target_id)
                {
                    return Err(EligibilityVerificationError::proof(
                        "source target receipt differs from retained target identity",
                    ));
                }
            }
            "audit_log" => {
                audit_count += 1;
                verify_audit_receipt(
                    tx,
                    operation_id,
                    operation,
                    target,
                    receipt,
                    &audit_expectation,
                )
                .await?;
            }
            "authorization_projection_outbox" => {
                let event_id = receipt.durable_id.as_str();
                if receipt.kind != "INSERT" {
                    return Err(EligibilityVerificationError::proof(
                        "projection receipt is not an INSERT",
                    ));
                }
                if let Some((_, card_id)) = completion_cards_by_event.get(event_id) {
                    eligibility_projection_count += 1;
                    if !projection_receipt_key_matches(&receipt.key, event_id, *card_id) {
                        return Err(EligibilityVerificationError::proof(
                            "eligibility projection receipt differs from its completion card",
                        ));
                    }
                } else if matches!(
                    operation,
                    EligibilitySourceOperation::CardStatus
                        | EligibilitySourceOperation::CardCreate
                        | EligibilitySourceOperation::CardRebind
                ) && verify_parent_card_projection_receipt(
                    tx,
                    event_id,
                    expected_target_id,
                    target_tenant_id(target)?,
                    operation_id,
                    &receipt.key,
                    operation,
                )
                .await?
                {
                    parent_projection_count += 1;
                } else {
                    return Err(EligibilityVerificationError::proof(
                        "projection receipt is not a declared eligibility or card-parent event",
                    ));
                }
            }
            "al_message_outbox" => {
                message_count += 1;
                if receipt.kind != "INSERT"
                    || !completion_cards_by_message.contains_key(receipt.durable_id.as_str())
                    || receipt.key
                        != serde_json::json!({
                            "messageId": receipt.durable_id,
                            "operationId": operation_id,
                        })
                {
                    return Err(EligibilityVerificationError::proof(
                        "message receipt differs from durable typed envelope identity",
                    ));
                }
            }
            _ => {
                return Err(EligibilityVerificationError::proof(
                    "retained source receipt names an unsupported durable entity",
                ));
            }
        }
    }
    let expected_card_count = artifact
        .affected_cards()
        .map_err(|error| EligibilityVerificationError::proof(error.to_string()))?
        .len();
    if source_count != 1
        || audit_count != 1
        || eligibility_projection_count != expected_card_count
        || message_count != expected_card_count
        || parent_projection_count
            > if matches!(
                operation,
                EligibilitySourceOperation::CardStatus
                    | EligibilitySourceOperation::CardCreate
                    | EligibilitySourceOperation::CardRebind
            ) {
                1
            } else {
                0
            }
    {
        return Err(EligibilityVerificationError::proof(
            "retained source receipt set is not the exact target/audit/event/message set",
        ));
    }
    Ok(())
}

fn target_key(entity: &str, id: i64) -> Value {
    match entity {
        "platform_user" => serde_json::json!({ "userId": id }),
        "tenant" => serde_json::json!({ "tenantId": id }),
        "user_card" => serde_json::json!({ "cardId": id }),
        _ => Value::Null,
    }
}

fn projection_receipt_key_matches(key: &Value, event_id: &str, card_id: i64) -> bool {
    key == &serde_json::json!({ "eventId": event_id })
        || key == &serde_json::json!({ "eventId": event_id, "aggregateId": card_id })
}

fn target_tenant_id(target: &IdentityTargetImage) -> Result<i64, EligibilityVerificationError> {
    let tenant_id = match &target.after {
        IdentityPresence::Present(value) => value.get("tenantId").and_then(Value::as_i64),
        IdentityPresence::Absent => None,
    };
    tenant_id.filter(|value| *value > 0).ok_or_else(|| {
        EligibilityVerificationError::proof(
            "retained card target does not carry a positive tenant identity",
        )
    })
}

async fn verify_parent_card_projection_receipt(
    tx: &mut Transaction<'_, MySql>,
    event_id: &str,
    card_id: i64,
    tenant_id: i64,
    operation_id: &str,
    key: &Value,
    operation: EligibilitySourceOperation,
) -> Result<bool, EligibilityVerificationError> {
    if !projection_receipt_key_matches(key, event_id, card_id) {
        return Ok(false);
    }
    let (expected_event_type, expected_fence) = match operation {
        EligibilitySourceOperation::CardStatus => ("REVOKE", true),
        EligibilitySourceOperation::CardCreate => ("CARD_CREATED", false),
        _ => return Ok(false),
    };
    let row: Option<ParentProjectionOutboxRow> = sqlx::query_as(
        "SELECT event_id, aggregate_type, aggregate_id, tenant_id, event_type, \
             source_generation, revoke_fence, payload_json \
             FROM authorization_projection_outbox \
             WHERE event_id = ? LIMIT 1 FOR UPDATE",
    )
    .bind(event_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| {
        EligibilityVerificationError::from_sqlx(error, "read card parent projection outbox")
    })?;
    let Some(ParentProjectionOutboxRow {
        event_id: stored_event_id,
        aggregate_type,
        aggregate_id,
        tenant_id: stored_tenant_id,
        event_type,
        source_generation,
        revoke_fence,
        payload_json: payload,
    }) = row
    else {
        return Ok(false);
    };
    let payload: Value = payload
        .as_deref()
        .ok_or_else(|| {
            EligibilityVerificationError::proof("card parent projection payload is absent")
        })
        .and_then(|value| {
            serde_json::from_str(value).map_err(|error| {
                EligibilityVerificationError::proof(format!(
                    "card parent projection payload is malformed: {error}"
                ))
            })
        })?;
    let generation = u64::try_from(source_generation).ok();
    let fence = u64::try_from(revoke_fence).ok();
    let operation_matches =
        payload.get("operationId").and_then(Value::as_str) == Some(operation_id);
    let payload_matches = payload.get("cardId").and_then(Value::as_i64) == Some(card_id)
        && payload.get("tenantId").and_then(Value::as_i64) == Some(tenant_id)
        && payload.get("generation").and_then(Value::as_i64) == Some(source_generation)
        && payload
            .get("actorId")
            .and_then(Value::as_i64)
            .is_some_and(|value| value > 0);
    Ok(stored_event_id == event_id
        && aggregate_type == "CARD"
        && aggregate_id == card_id
        && stored_tenant_id == Some(tenant_id)
        && event_type == expected_event_type
        && generation.is_some_and(|value| value > 0)
        && if expected_fence {
            fence.is_some_and(|value| value > 0 && value <= generation.unwrap_or(0))
        } else {
            fence == Some(0)
        }
        && operation_matches
        && payload_matches)
}

async fn verify_audit_receipt(
    tx: &mut Transaction<'_, MySql>,
    operation_id: &str,
    operation: EligibilitySourceOperation,
    target: &IdentityTargetImage,
    receipt: &crate::authority_publication::IdentityReceipt,
    expected: &AuditReceiptExpectation,
) -> Result<(), EligibilityVerificationError> {
    let audit_id = receipt.durable_id.parse::<i64>().map_err(|_| {
        EligibilityVerificationError::proof("audit receipt durable id is not a positive integer")
    })?;
    if audit_id <= 0 || receipt.kind != "INSERT" {
        return Err(EligibilityVerificationError::proof(
            "audit receipt identity is invalid",
        ));
    }
    let key_id = receipt.key.get("id").and_then(Value::as_i64);
    let key_event = receipt.key.get("eventType").and_then(Value::as_str);
    if key_id != Some(audit_id) || key_event != Some(expected.event_type) {
        return Err(EligibilityVerificationError::proof(
            "audit receipt key differs from its durable identity",
        ));
    }
    let row: Option<EligibilityAuditRow> = sqlx::query_as(
        "SELECT id, user_id, card_id, action, resource, decision, event_type, request_id, \
         domain_id, tenant_id, detail FROM audit_log WHERE id = ? LIMIT 1 FOR UPDATE",
    )
    .bind(audit_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| {
        EligibilityVerificationError::from_sqlx(error, "read eligibility audit row")
    })?;
    let Some(EligibilityAuditRow {
        id,
        user_id,
        card_id,
        action,
        resource,
        decision,
        event_type,
        request_id,
        domain_id,
        tenant_id,
        detail,
    }) = row
    else {
        return Err(EligibilityVerificationError::proof(
            "retained audit receipt has no durable audit row",
        ));
    };
    let detail: Value = detail
        .as_deref()
        .ok_or_else(|| EligibilityVerificationError::proof("durable audit detail is absent"))
        .and_then(|value| {
            serde_json::from_str(value).map_err(|error| {
                EligibilityVerificationError::proof(format!(
                    "durable audit detail is malformed: {error}"
                ))
            })
        })?;
    let target_id = target_id(target)
        .ok_or_else(|| EligibilityVerificationError::proof("audit target identity is malformed"))?;
    let expected_resource = match operation {
        EligibilitySourceOperation::UserStatus | EligibilitySourceOperation::UserDelete => "user",
        EligibilitySourceOperation::TenantStatus | EligibilitySourceOperation::TenantDelete => {
            "tenant"
        }
        EligibilitySourceOperation::CardStatus
        | EligibilitySourceOperation::CardCreate
        | EligibilitySourceOperation::CardRebind => "user_card",
    };
    let expected_target_matches = match operation {
        EligibilitySourceOperation::UserStatus | EligibilitySourceOperation::UserDelete => {
            detail.get("targetType").and_then(Value::as_str) == Some("user")
                && detail.get("targetId").and_then(Value::as_i64) == Some(target_id)
        }
        EligibilitySourceOperation::TenantStatus | EligibilitySourceOperation::TenantDelete => {
            matches!(
                detail.get("targetType").and_then(Value::as_str),
                Some("tenant")
            ) && detail.get("targetId").and_then(Value::as_i64) == Some(target_id)
        }
        EligibilitySourceOperation::CardStatus
        | EligibilitySourceOperation::CardCreate
        | EligibilitySourceOperation::CardRebind => {
            detail.get("targetCardId").and_then(Value::as_i64) == Some(target_id)
        }
    };
    let detail_action_matches = detail
        .get("action")
        .and_then(Value::as_str)
        .is_some_and(|value| value == expected.detail_action);
    let detail_actor_id = detail.get("actorId").and_then(Value::as_i64);
    let detail_actor_card_id = detail.get("actorCardId").and_then(Value::as_i64);
    let detail_actor_tenant_id = detail.get("actorTenantId").and_then(Value::as_i64);
    let detail_actor_domain_id = detail.get("actorDomainId").and_then(Value::as_i64);
    let target_after_user_id = match &target.after {
        IdentityPresence::Present(value) => value.get("userId").and_then(Value::as_i64),
        IdentityPresence::Absent => None,
    };
    let target_after_tenant_id = match &target.after {
        IdentityPresence::Present(value) => value.get("tenantId").and_then(Value::as_i64),
        IdentityPresence::Absent => None,
    };
    let target_after_domain_id = match &target.after {
        IdentityPresence::Present(value) => value.get("domainId").and_then(Value::as_i64),
        IdentityPresence::Absent => None,
    };
    let actor_scope_matches = match operation {
        EligibilitySourceOperation::UserStatus
        | EligibilitySourceOperation::UserDelete
        | EligibilitySourceOperation::TenantStatus
        | EligibilitySourceOperation::TenantDelete => {
            detail_actor_id == Some(user_id)
                && detail_actor_card_id == card_id
                && detail_actor_tenant_id == tenant_id
                && detail_actor_domain_id == domain_id
                && card_id.is_some_and(|value| value > 0)
                && tenant_id.is_some_and(|value| value > 0)
        }
        EligibilitySourceOperation::CardStatus | EligibilitySourceOperation::CardRebind => {
            detail_actor_id == Some(user_id)
                && detail.get("ownerUserId").and_then(Value::as_i64) == target_after_user_id
                && card_id == Some(target_id)
                && tenant_id == target_after_tenant_id
                && domain_id == target_after_domain_id
        }
        EligibilitySourceOperation::CardCreate => {
            detail_actor_id == Some(user_id)
                && card_id == Some(target_id)
                && detail.get("tenantId").and_then(Value::as_i64) == target_after_tenant_id
                && detail.get("domainId").and_then(Value::as_i64) == target_after_domain_id
                && tenant_id == target_after_tenant_id
                && domain_id == target_after_domain_id
        }
    };
    let resource_matches = match operation {
        EligibilitySourceOperation::TenantStatus | EligibilitySourceOperation::TenantDelete => {
            resource == "tenant"
                && detail.get("targetType").and_then(Value::as_str) == Some("tenant")
        }
        EligibilitySourceOperation::UserStatus | EligibilitySourceOperation::UserDelete => {
            resource == "user"
        }
        EligibilitySourceOperation::CardStatus
        | EligibilitySourceOperation::CardCreate
        | EligibilitySourceOperation::CardRebind => resource == "user_card",
    };
    if id != audit_id
        || action != expected.action
        || resource != expected_resource
        || decision != expected.decision
        || event_type != expected.event_type
        || request_id.as_deref() != Some(operation_id)
        || detail.get("operationId").and_then(Value::as_str) != Some(operation_id)
        || !expected_target_matches
        || !detail_action_matches
        || !actor_scope_matches
        || !resource_matches
        || detail.get("operationId").and_then(Value::as_str) != Some(operation_id)
        || user_id <= 0
        || tenant_id.is_none_or(|value| value <= 0)
        || (matches!(
            operation,
            EligibilitySourceOperation::CardStatus
                | EligibilitySourceOperation::CardCreate
                | EligibilitySourceOperation::CardRebind
        ) && (card_id != Some(target_id) || tenant_id.is_none_or(|value| value <= 0)))
    {
        return Err(EligibilityVerificationError::proof(
            "durable audit row differs from its operation and target receipt",
        ));
    }
    Ok(())
}
