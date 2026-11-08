//! ProtectedBusiness lifecycle for permission requests.
//!
//! These workflows mutate approval facts only. They never append grant deltas,
//! authorization projection events, or invalidation delivery receipts.

use astral_db::{
    begin_protected_mutation_in_tx, finish_protected_mutation_in_tx, ProtectedMutationContext,
    ProtectedMutationStart, ProtectedSourceEvidence, RowPresence, TargetRowEvidence, WriteKind,
};
use astral_types::AstralError;
use serde::Serialize;
use sqlx::{MySql, MySqlPool, Transaction};

use super::NewRequest;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PermissionRequestEvidence {
    request_id: i64,
    user_id: i64,
    request_type: String,
    request_content: Option<String>,
    reason: Option<String>,
    status: String,
    approver_id: Option<i64>,
    approve_comment: Option<String>,
}

type PermissionRequestRow = (
    i64,
    i64,
    String,
    Option<String>,
    Option<String>,
    String,
    Option<i64>,
    Option<String>,
);

#[derive(Debug, sqlx::FromRow)]
struct CreateTargetCardRow {
    user_id: i64,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
    #[sqlx(rename = "card_status")]
    status: String,
    currently_valid: bool,
}

const REQUEST_FOR_UPDATE: &str =
    "SELECT request_id, user_id, request_type, request_content, reason, status, \
     approver_id, approve_comment FROM permission_request WHERE request_id = ? FOR UPDATE";

fn database(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!(
        "permission request protected mutation query failed: {error}"
    ))
}

fn commit_error(operation_id: &str, error: sqlx::Error) -> AstralError {
    AstralError::Pending(format!(
        "permission request protected mutation COMMIT outcome unknown; reconcile operation {operation_id} before retry: {error}"
    ))
}

fn row_evidence(row: PermissionRequestRow) -> PermissionRequestEvidence {
    PermissionRequestEvidence {
        request_id: row.0,
        user_id: row.1,
        request_type: row.2,
        request_content: row.3,
        reason: row.4,
        status: row.5,
        approver_id: row.6,
        approve_comment: row.7,
    }
}

async fn read_request_for_update(
    tx: &mut Transaction<'_, MySql>,
    request_id: i64,
) -> Result<Option<PermissionRequestRow>, AstralError> {
    sqlx::query_as(REQUEST_FOR_UPDATE)
        .bind(request_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(database)
}

fn cancel_after_matches(
    before: &PermissionRequestRow,
    after: &PermissionRequestRow,
    request_id: i64,
    user_id: i64,
    comment: Option<&str>,
) -> bool {
    after.0 == request_id
        && after.1 == user_id
        && after.1 == before.1
        && after.2 == before.2
        && after.3 == before.3
        && after.4 == before.4
        && after.5 == "CANCELLED"
        && after.6 == before.6
        && after.7.as_deref() == comment
}

fn reject_after_matches(
    before: &PermissionRequestRow,
    after: &PermissionRequestRow,
    request_id: i64,
    reviewer_id: i64,
    comment: Option<&str>,
) -> bool {
    after.0 == request_id
        && after.1 == before.1
        && after.2 == before.2
        && after.3 == before.3
        && after.4 == before.4
        && after.5 == "REJECTED"
        && after.6 == Some(reviewer_id)
        && after.7.as_deref() == comment
}

fn evidence(
    before: Option<PermissionRequestRow>,
    after: Option<PermissionRequestRow>,
    request_id: i64,
    kind: WriteKind,
    rows_affected: u64,
) -> Result<ProtectedSourceEvidence, AstralError> {
    ProtectedSourceEvidence::new()
        .target_row(TargetRowEvidence {
            entity: "permission_request",
            key: serde_json::json!({ "requestId": request_id }),
            before: RowPresence::from_option(before.map(row_evidence)),
            after: RowPresence::from_option(after.map(row_evidence)),
        })
        .map_err(|error| AstralError::Pending(error.to_string()))
        .map(|evidence| {
            evidence.receipt(
                "permission_request",
                serde_json::json!({ "requestId": request_id }),
                kind,
                rows_affected,
            )
        })
}

fn approval_audit_context(
    context: &ProtectedMutationContext,
    request_id: i64,
    workflow: &str,
) -> super::super::audit_log_repository::ApprovalAuditContext {
    super::super::audit_log_repository::ApprovalAuditContext {
        request_id: context.operation_id().to_owned(),
        approval_request_id: request_id,
        message_id: format!(
            "{}:permission-request:{}:{}",
            context.operation_id(),
            workflow,
            request_id
        ),
    }
}

pub(crate) async fn create_request(
    db: &MySqlPool,
    new: &NewRequest,
    context: &ProtectedMutationContext,
) -> Result<i64, AstralError> {
    context.require_request("permission_request", "create", None)?;
    if new.user_id != context.actor_id() || new.user_id <= 0 {
        return Err(AstralError::Permission(
            "permission request actor does not match the verified mutation context".into(),
        ));
    }

    let payload = serde_json::json!({
        "userId": new.user_id,
        "requestType": new.request_type,
        "requestContent": new.request_content,
        "reason": new.reason,
    });
    let mut tx = db.begin().await.map_err(database)?;
    if let ProtectedMutationStart::Completed(result) =
        begin_protected_mutation_in_tx(&mut tx, context, &payload).await?
    {
        return result
            .get("requestId")
            .and_then(serde_json::Value::as_i64)
            .filter(|id| *id > 0)
            .ok_or_else(|| {
                AstralError::Database("invalid durable permission request result".into())
            });
    }

    let card_id = verify_create_target_card(&mut tx, &new.request_content, context).await?;
    let insert = sqlx::query(
        "INSERT INTO permission_request (user_id, request_type, request_content, reason, status) \
         VALUES (?, ?, ?, ?, 'PENDING')",
    )
    .bind(new.user_id)
    .bind(&new.request_type)
    .bind(&new.request_content)
    .bind(&new.reason)
    .execute(&mut *tx)
    .await
    .map_err(database)?;
    if insert.rows_affected() != 1 {
        return Err(AstralError::Pending(
            "permission request insert affected an unexpected number of rows".into(),
        ));
    }
    let request_id = i64::try_from(insert.last_insert_id())
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| {
            AstralError::Pending("permission request insert returned an unusable id".into())
        })?;
    let after = read_request_for_update(&mut tx, request_id).await?;
    let Some(after_row) = after.clone() else {
        return Err(AstralError::Pending(
            "permission request insert has no same-transaction readback".into(),
        ));
    };
    if after_row.1 != new.user_id
        || after_row.2 != new.request_type
        || after_row.3.as_deref() != Some(new.request_content.as_str())
        || after_row.4.as_deref() != new.reason.as_deref()
        || after_row.5 != "PENDING"
    {
        return Err(AstralError::Pending(
            "permission request source readback differs from the requested values".into(),
        ));
    }

    let audit_context = approval_audit_context(context, request_id, "create");
    super::super::audit_log_repository::insert_approval_audit_in_tx(
        &mut tx,
        &super::super::audit_log_repository::ApprovalAuditEntry {
            actor_id: context.actor_id(),
            reviewer_id: None,
            target_user_id: new.user_id,
            target_card_id: Some(card_id),
            action: "create",
            decision: "PENDING",
            request_reason: new.reason.as_deref(),
            reviewer_comment: None,
            context: &audit_context,
        },
    )
    .await?;

    let result = serde_json::json!({ "requestId": request_id, "status": "PENDING" });
    let source_evidence = evidence(
        None,
        after,
        request_id,
        WriteKind::Insert,
        insert.rows_affected(),
    )?;
    finish_protected_mutation_in_tx(&mut tx, context, &result, &source_evidence).await?;
    tx.commit()
        .await
        .map_err(|error| commit_error(context.operation_id(), error))?;
    Ok(request_id)
}

pub(crate) async fn cancel_request(
    db: &MySqlPool,
    request_id: i64,
    user_id: i64,
    comment: Option<&str>,
    context: &ProtectedMutationContext,
) -> Result<(), AstralError> {
    context.require_request("permission_request", "update", Some(request_id))?;
    if user_id != context.actor_id() || request_id <= 0 {
        return Err(AstralError::Permission(
            "permission request cancellation actor or target is not bound to the mutation context"
                .into(),
        ));
    }
    let payload = serde_json::json!({
        "requestId": request_id,
        "userId": user_id,
        "comment": comment,
        "status": "CANCELLED",
    });
    let mut tx = db.begin().await.map_err(database)?;
    if let ProtectedMutationStart::Completed(result) =
        begin_protected_mutation_in_tx(&mut tx, context, &payload).await?
    {
        if result.get("requestId").and_then(serde_json::Value::as_i64) != Some(request_id)
            || result.get("status").and_then(serde_json::Value::as_str) != Some("CANCELLED")
        {
            return Err(AstralError::Database(
                "invalid durable cancellation result".into(),
            ));
        }
        return Ok(());
    }

    let before = read_request_for_update(&mut tx, request_id).await?;
    let Some(before_row) = before.clone() else {
        return Err(AstralError::Validation(
            "permission request does not exist".into(),
        ));
    };
    if before_row.1 != user_id || before_row.5 != "PENDING" {
        return Err(AstralError::Validation(
            "permission request is not pending or does not belong to requester".into(),
        ));
    }
    let update = sqlx::query(
        "UPDATE permission_request SET status='CANCELLED', approve_comment=?, updated_at=NOW() \
         WHERE request_id=? AND user_id=? AND status='PENDING'",
    )
    .bind(comment)
    .bind(request_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(database)?;
    if update.rows_affected() != 1 {
        return Err(AstralError::Validation(
            "permission request is no longer pending or does not belong to requester".into(),
        ));
    }
    let after = read_request_for_update(&mut tx, request_id).await?;
    let Some(after_row) = after.clone() else {
        return Err(AstralError::Pending(
            "cancelled permission request has no same-transaction readback".into(),
        ));
    };
    if !cancel_after_matches(&before_row, &after_row, request_id, user_id, comment) {
        return Err(AstralError::Pending(
            "cancelled permission request readback differs from the requested values".into(),
        ));
    }
    let audit_context = approval_audit_context(context, request_id, "cancel");
    super::super::audit_log_repository::insert_approval_audit_in_tx(
        &mut tx,
        &super::super::audit_log_repository::ApprovalAuditEntry {
            actor_id: context.actor_id(),
            reviewer_id: None,
            target_user_id: before_row.1,
            target_card_id: request_card_id(before_row.3.as_deref()),
            action: "cancel",
            decision: "CANCELLED",
            request_reason: before_row.4.as_deref(),
            reviewer_comment: comment,
            context: &audit_context,
        },
    )
    .await?;
    let result = serde_json::json!({ "requestId": request_id, "status": "CANCELLED" });
    let source_evidence = evidence(
        Some(before_row),
        after,
        request_id,
        WriteKind::Update,
        update.rows_affected(),
    )?;
    finish_protected_mutation_in_tx(&mut tx, context, &result, &source_evidence).await?;
    tx.commit()
        .await
        .map_err(|error| commit_error(context.operation_id(), error))
}

pub(crate) async fn reject_request(
    db: &MySqlPool,
    request_id: i64,
    reviewer_id: i64,
    comment: Option<&str>,
    context: &ProtectedMutationContext,
) -> Result<(), AstralError> {
    context.require_request("permission_request", "approve", Some(request_id))?;
    if reviewer_id != context.actor_id() || reviewer_id <= 0 || request_id <= 0 {
        return Err(AstralError::Permission(
            "permission request rejection actor or target is not bound to the mutation context"
                .into(),
        ));
    }
    let payload = serde_json::json!({
        "requestId": request_id,
        "reviewerId": reviewer_id,
        "comment": comment,
        "status": "REJECTED",
    });
    let mut tx = db.begin().await.map_err(database)?;
    if let ProtectedMutationStart::Completed(result) =
        begin_protected_mutation_in_tx(&mut tx, context, &payload).await?
    {
        if result.get("requestId").and_then(serde_json::Value::as_i64) != Some(request_id)
            || result.get("status").and_then(serde_json::Value::as_str) != Some("REJECTED")
        {
            return Err(AstralError::Database(
                "invalid durable rejection result".into(),
            ));
        }
        return Ok(());
    }

    let before = read_request_for_update(&mut tx, request_id).await?;
    let Some(before_row) = before.clone() else {
        return Err(AstralError::Validation(
            "permission request does not exist".into(),
        ));
    };
    if before_row.5 != "PENDING" {
        return Err(AstralError::Validation(
            "permission request is no longer pending".into(),
        ));
    }
    let update = sqlx::query(
        "UPDATE permission_request SET status='REJECTED', approver_id=?, approve_comment=? \
         WHERE request_id=? AND status='PENDING'",
    )
    .bind(reviewer_id)
    .bind(comment)
    .bind(request_id)
    .execute(&mut *tx)
    .await
    .map_err(database)?;
    if update.rows_affected() != 1 {
        return Err(AstralError::Validation(
            "permission request is no longer pending".into(),
        ));
    }
    let after = read_request_for_update(&mut tx, request_id).await?;
    let Some(after_row) = after.clone() else {
        return Err(AstralError::Pending(
            "rejected permission request has no same-transaction readback".into(),
        ));
    };
    if !reject_after_matches(&before_row, &after_row, request_id, reviewer_id, comment) {
        return Err(AstralError::Pending(
            "rejected permission request readback differs from the requested values".into(),
        ));
    }
    let audit_context = approval_audit_context(context, request_id, "reject");
    super::super::audit_log_repository::insert_approval_audit_in_tx(
        &mut tx,
        &super::super::audit_log_repository::ApprovalAuditEntry {
            actor_id: context.actor_id(),
            reviewer_id: Some(reviewer_id),
            target_user_id: before_row.1,
            target_card_id: request_card_id(before_row.3.as_deref()),
            action: "reject",
            decision: "REJECTED",
            request_reason: before_row.4.as_deref(),
            reviewer_comment: comment,
            context: &audit_context,
        },
    )
    .await?;
    let result = serde_json::json!({ "requestId": request_id, "status": "REJECTED" });
    let source_evidence = evidence(
        Some(before_row),
        after,
        request_id,
        WriteKind::Update,
        update.rows_affected(),
    )?;
    finish_protected_mutation_in_tx(&mut tx, context, &result, &source_evidence).await?;
    tx.commit()
        .await
        .map_err(|error| commit_error(context.operation_id(), error))
}

fn request_card_id(content: Option<&str>) -> Option<i64> {
    content
        .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok())
        .and_then(|value| value.get("cardId").and_then(serde_json::Value::as_i64))
}

async fn verify_create_target_card(
    tx: &mut Transaction<'_, MySql>,
    content: &str,
    context: &ProtectedMutationContext,
) -> Result<i64, AstralError> {
    let card_id = request_card_id(Some(content))
        .filter(|id| *id > 0)
        .ok_or_else(|| {
            AstralError::Validation("permission request requires a positive target card id".into())
        })?;
    let row: Option<CreateTargetCardRow> = sqlx::query_as(
        "SELECT user_id, tenant_id, domain_id, card_status, \
         ((valid_from IS NULL OR valid_from <= UTC_TIMESTAMP()) AND \
          (valid_until IS NULL OR valid_until >= UTC_TIMESTAMP())) AS currently_valid \
         FROM user_card WHERE card_id = ? FOR UPDATE",
    )
    .bind(card_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(database)?;
    let Some(row) = row else {
        return Err(AstralError::Permission(
            "permission request target card does not exist".into(),
        ));
    };
    if row.user_id != context.actor_id()
        || row.tenant_id != Some(context.tenant_id())
        || row.domain_id != context.domain_id()
        || row.status != "ACTIVE"
        || !row.currently_valid
    {
        return Err(AstralError::Permission(
            "permission request target card is not active, current, or owned by requester".into(),
        ));
    }
    let proof_scope = &context.admission().proof().scope;
    let domain_matches = match proof_scope.domain {
        astral_types::AuthorizationDomainScope::Exact(domain) => {
            Some(domain) == context.domain_id()
        }
        astral_types::AuthorizationDomainScope::NoDomain => context.domain_id().is_none(),
        astral_types::AuthorizationDomainScope::Any => false,
    };
    if proof_scope.user_id != Some(context.actor_id())
        || proof_scope.tenant_id != context.tenant_id()
        || !domain_matches
    {
        return Err(AstralError::Permission(
            "permission request target card does not match the admitted actor scope".into(),
        ));
    }
    Ok(card_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending_row() -> PermissionRequestRow {
        (
            41,
            7,
            "RULE".into(),
            Some(r#"{"resourceType":"permission_rule","actionCode":"read","cardId":3}"#.into()),
            Some("needs access".into()),
            "PENDING".into(),
            None,
            None,
        )
    }

    fn cancelled_row() -> PermissionRequestRow {
        let mut row = pending_row();
        row.5 = "CANCELLED".into();
        row.7 = Some("changed my mind".into());
        row
    }

    fn rejected_row() -> PermissionRequestRow {
        let mut row = pending_row();
        row.5 = "REJECTED".into();
        row.6 = Some(11);
        row.7 = Some("out of scope".into());
        row
    }

    #[test]
    fn cancel_after_comparator_requires_exact_source_and_decision_fields() {
        let before = pending_row();
        let after = cancelled_row();
        assert!(cancel_after_matches(
            &before,
            &after,
            41,
            7,
            Some("changed my mind")
        ));

        let mut cases = Vec::new();
        let mut row = after.clone();
        row.0 = 42;
        cases.push(row);
        let mut row = after.clone();
        row.1 = 8;
        cases.push(row);
        let mut row = after.clone();
        row.2 = "TEMP_PERMISSION".into();
        cases.push(row);
        let mut row = after.clone();
        row.3 = Some("forged-content".into());
        cases.push(row);
        let mut row = after.clone();
        row.4 = Some("forged-reason".into());
        cases.push(row);
        let mut row = after.clone();
        row.5 = "PENDING".into();
        cases.push(row);
        let mut row = after.clone();
        row.6 = Some(11);
        cases.push(row);
        let mut row = after;
        row.7 = Some("different comment".into());
        cases.push(row);

        for candidate in cases {
            assert!(
                !cancel_after_matches(&before, &candidate, 41, 7, Some("changed my mind")),
                "cancel comparator must reject every altered after-row field"
            );
        }
    }

    #[test]
    fn reject_after_comparator_requires_exact_source_and_decision_fields() {
        let before = pending_row();
        let after = rejected_row();
        assert!(reject_after_matches(
            &before,
            &after,
            41,
            11,
            Some("out of scope")
        ));

        let mut cases = Vec::new();
        let mut row = after.clone();
        row.0 = 42;
        cases.push(row);
        let mut row = after.clone();
        row.1 = 8;
        cases.push(row);
        let mut row = after.clone();
        row.2 = "TEMP_PERMISSION".into();
        cases.push(row);
        let mut row = after.clone();
        row.3 = Some("forged-content".into());
        cases.push(row);
        let mut row = after.clone();
        row.4 = Some("forged-reason".into());
        cases.push(row);
        let mut row = after.clone();
        row.5 = "PENDING".into();
        cases.push(row);
        let mut row = after.clone();
        row.6 = Some(12);
        cases.push(row);
        let mut row = after;
        row.7 = Some("different comment".into());
        cases.push(row);

        for candidate in cases {
            assert!(
                !reject_after_matches(&before, &candidate, 41, 11, Some("out of scope")),
                "reject comparator must reject every altered after-row field"
            );
        }
    }
}
