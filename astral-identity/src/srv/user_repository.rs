//! 用户管理数据访问 — UserRepository
//!
//! 对齐 Java `PlatformUserMapper` + `UserLocalCredentialMapper` 边界。
//! 只返回领域记录，不返回 Axum/HTTP 类型。

use std::sync::Arc;

use astral_db::authority_eligibility_completion::{
    EligibilitySourceCapture, EligibilitySourceEvidenceReceipt, EligibilitySourceSubject,
};
use astral_db::invalidation_delivery::InvalidationDeliveryContext;
use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::{AstralError, AuthorizationAdmission, UserCard};

use crate::srv::source_writer_guard;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserListRecord {
    pub user_id: i64,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub status: String,
}

/// user_card 基础行（对齐 platform_v4.user_card 真实列名）。
#[derive(Debug, Clone, sqlx::FromRow)]
struct UserCardRow {
    card_id: i64,
    user_id: Option<i64>,
    domain_id: Option<i64>,
    card_type: String,
    card_status: String,
    template_id: Option<i64>,
    level_id: Option<i64>,
    priority: Option<i32>,
    is_primary: Option<bool>,
    valid_from: Option<String>,
    valid_until: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
    tenant_id: Option<i64>,
}

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn count_users(&self) -> Result<i64, AstralError>;

    async fn list_users(&self, size: i64, offset: i64) -> Result<Vec<UserListRecord>, AstralError>;

    async fn get_user(&self, user_id: i64) -> Result<Option<UserListRecord>, AstralError>;

    /// 单条 COALESCE 更新，对齐 Java 单实体更新与 profile 更新模式。
    async fn update_user(
        &self,
        user_id: i64,
        display_name: Option<&str>,
        email: Option<&str>,
        phone: Option<&str>,
        status: Option<&str>,
        admission: Option<AuthorizationAdmission>,
    ) -> Result<(), AstralError>;

    async fn update_user_status(
        &self,
        user_id: i64,
        status: &str,
        admission: AuthorizationAdmission,
    ) -> Result<(), AstralError>;

    async fn soft_delete_user(
        &self,
        user_id: i64,
        admission: AuthorizationAdmission,
    ) -> Result<(), AstralError>;

    async fn list_user_cards(&self, user_id: i64) -> Result<Vec<UserCard>, AstralError>;
}

pub struct SqlxUserRepository {
    db: MySqlPool,
    delivery_context: Option<Arc<InvalidationDeliveryContext>>,
}

impl SqlxUserRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self {
            db,
            delivery_context: None,
        }
    }

    pub fn new_with_delivery_context(
        db: MySqlPool,
        delivery_context: Arc<InvalidationDeliveryContext>,
    ) -> Self {
        Self {
            db,
            delivery_context: Some(delivery_context),
        }
    }

    fn require_delivery_context(&self) -> Result<&InvalidationDeliveryContext, AstralError> {
        self.delivery_context.as_deref().ok_or_else(|| {
            AstralError::Pending(
                "eligibility mutation requires an injected invalidation delivery context".into(),
            )
        })
    }
}

/// platform_user 行镜像（mutation 实际触及的列 + 身份列）：before 侧来自
/// `FOR UPDATE` 锁定读，after 侧来自同事务写后回读——两侧都是真实探针，
/// 绝不以 actor 快照、operation id 或审计 detail 替代目标证据。
#[derive(Debug, Clone, sqlx::FromRow)]
struct UserRowImage {
    user_id: i64,
    status: String,
    display_name: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    deleted_at: Option<String>,
}

impl UserRowImage {
    fn to_row_json(&self) -> serde_json::Value {
        serde_json::json!({
            "userId": self.user_id,
            "status": self.status,
            "displayName": self.display_name,
            "email": self.email,
            "phone": self.phone,
            "deletedAt": self.deleted_at,
        })
    }
}

/// 行镜像 SQL：锁定读附加 `deleted_at IS NULL` 谓词，写后回读不带该谓词
/// （软删除后行仍在，回读携带 tombstone 才是真实 after 镜像）。
const USER_ROW_IMAGE_SQL: &str = "SELECT user_id, status, display_name, email, phone, \
     CAST(deleted_at AS CHAR) AS deleted_at FROM platform_user WHERE user_id = ?";

async fn lock_existing_user(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    user_id: i64,
) -> Result<Option<UserRowImage>, AstralError> {
    sqlx::query_as::<_, UserRowImage>(&format!(
        "{USER_ROW_IMAGE_SQL} AND deleted_at IS NULL FOR UPDATE"
    ))
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| AstralError::Database(format!("Lock user failed: {e}")))
}

/// 写后同事务回读（无 deleted_at 谓词）：`None` 是真实探针结果，证明行已不存在。
async fn read_back_user_row_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    user_id: i64,
) -> Result<Option<UserRowImage>, AstralError> {
    sqlx::query_as::<_, UserRowImage>(USER_ROW_IMAGE_SQL)
        .bind(user_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| AstralError::Database(format!("Read back user row failed: {e}")))
}

fn status_change_requires_eligibility_event(
    previous_status: &str,
    requested_status: Option<&str>,
) -> bool {
    requested_status.is_some_and(|status| previous_status != status.trim())
}

fn soft_delete_requires_eligibility_event(previous_status: Option<&str>) -> bool {
    previous_status.is_some()
}

/// user 状态/软删除 source 事务的 durable 审计关联输入（`audit_log`，与
/// card/org 写路径同事务审计族；caller 身份取自已验证 admission proof scope）。
struct UserMutationAuditEntry<'a> {
    caller_user_id: Option<i64>,
    caller_card_id: i64,
    caller_domain_id: Option<i64>,
    tenant_id: i64,
    action: &'a str,
    target_user_id: i64,
    operation_id: &'a str,
    detail: serde_json::Value,
}

const USER_MUTATION_AUDIT_INSERT_SQL: &str = "INSERT INTO audit_log \
     (user_id, card_id, action, resource, decision, reason, event_type, request_id, \
      domain_id, tenant_id, detail) \
     VALUES (?, ?, ?, 'user', 'SUCCESS', NULL, 'IDENTITY_USER_MUTATION', ?, ?, ?, ?)";

/// 把 user 状态/软删除的审计关联行写入同一事务并返回实际 audit_log 主键
/// （source outcome 的真实语句 receipt 需要 durable id）。
async fn insert_user_mutation_audit_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    entry: &UserMutationAuditEntry<'_>,
) -> Result<i64, AstralError> {
    if entry.target_user_id <= 0
        || entry.caller_card_id <= 0
        || entry.tenant_id <= 0
        || entry.action.trim().is_empty()
    {
        return Err(AstralError::Validation(
            "user mutation audit requires positive caller/target scope and an action".into(),
        ));
    }
    if entry.operation_id.trim().is_empty() || entry.operation_id.trim() != entry.operation_id {
        return Err(AstralError::Validation(
            "user mutation audit requires a canonical operation id".into(),
        ));
    }
    let detail = serde_json::json!({
        "actorId": entry.caller_user_id,
        "actorCardId": entry.caller_card_id,
        "actorTenantId": entry.tenant_id,
        "actorDomainId": entry.caller_domain_id,
        "targetType": "user",
        "targetId": entry.target_user_id,
        "action": entry.action,
        "operationId": entry.operation_id,
        "mutation": entry.detail,
    })
    .to_string();
    let result = sqlx::query(USER_MUTATION_AUDIT_INSERT_SQL)
        .bind(entry.caller_user_id)
        .bind(entry.caller_card_id)
        .bind(entry.action)
        .bind(entry.operation_id)
        .bind(entry.caller_domain_id)
        .bind(entry.tenant_id)
        .bind(detail)
        .execute(&mut **tx)
        .await
        .map_err(|e| AstralError::Database(format!("user mutation audit insert failed: {e}")))?;
    i64::try_from(result.last_insert_id())
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| {
            AstralError::Internal("user mutation audit insert returned an unusable id".into())
        })
}

/// admission proof scope 的 caller domain（仅 Exact 域携带具体值）。
fn admission_caller_domain_id(admission: &AuthorizationAdmission) -> Option<i64> {
    match admission.proof().scope.domain {
        astral_types::AuthorizationDomainScope::Exact(domain_id) => Some(domain_id),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
enum UserEligibilityMutation<'a> {
    Status {
        display_name: Option<&'a str>,
        email: Option<&'a str>,
        phone: Option<&'a str>,
        status: &'a str,
    },
    Delete,
}

struct UserMutationEvidence {
    after_row: Option<UserRowImage>,
    operation_id: String,
    updated_rows: u64,
    audit_id: i64,
    receipts: Vec<source_writer_guard::UserInvalidationReceipt>,
    affected_cards: Vec<(i64, Option<i64>)>,
}

struct UserEligibilityMutationContext<'a> {
    admission: &'a AuthorizationAdmission,
    user_id: i64,
    previous_row: &'a UserRowImage,
    operation_id: &'a str,
    mutation: UserEligibilityMutation<'a>,
    cards: Vec<(i64, Option<i64>)>,
    delivery_context: Option<&'a InvalidationDeliveryContext>,
}

async fn apply_user_eligibility_mutation_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    context: UserEligibilityMutationContext<'_>,
) -> Result<UserMutationEvidence, AstralError> {
    let UserEligibilityMutationContext {
        admission,
        user_id,
        previous_row,
        operation_id,
        mutation,
        cards,
        delivery_context,
    } = context;
    let (updated, action, detail, after_row) = match mutation {
        UserEligibilityMutation::Status {
            display_name,
            email,
            phone,
            status,
        } => {
            let updated = sqlx::query(
                "UPDATE platform_user SET display_name = COALESCE(?, display_name), \
                 email = COALESCE(?, email), phone = COALESCE(?, phone), \
                 status = COALESCE(?, status), updated_at = UTC_TIMESTAMP() \
                 WHERE user_id = ? AND deleted_at IS NULL",
            )
            .bind(display_name.map(str::trim))
            .bind(email.map(str::trim))
            .bind(phone.map(str::trim))
            .bind(Some(status.trim()))
            .bind(user_id)
            .execute(&mut **tx)
            .await
            .map_err(|error| AstralError::Database(format!("Update user failed: {error}")))?;
            if updated.rows_affected() != 1 {
                return Err(AstralError::Database(format!(
                    "user {user_id} vanished between the locked read and the source update"
                )));
            }
            let after = read_back_user_row_in_tx(tx, user_id).await?;
            (
                updated,
                "update",
                serde_json::json!({
                    "fromStatus": previous_row.status,
                    "toStatus": status.trim(),
                }),
                after,
            )
        }
        UserEligibilityMutation::Delete => {
            let updated = sqlx::query(
                "UPDATE platform_user SET deleted_at = CURRENT_TIMESTAMP \
                 WHERE user_id = ? AND deleted_at IS NULL",
            )
            .bind(user_id)
            .execute(&mut **tx)
            .await
            .map_err(|error| AstralError::Database(format!("Soft delete user failed: {error}")))?;
            if updated.rows_affected() != 1 {
                return Err(AstralError::Database(format!(
                    "user {user_id} vanished between the locked read and the soft delete"
                )));
            }
            let after = read_back_user_row_in_tx(tx, user_id).await?;
            (
                updated,
                "delete",
                serde_json::json!({
                    "fromStatus": previous_row.status,
                    "softDeleted": true,
                }),
                after,
            )
        }
    };

    let audit_id = insert_user_mutation_audit_in_tx(
        tx,
        &UserMutationAuditEntry {
            caller_user_id: admission.proof().scope.user_id,
            caller_card_id: admission.proof().scope.card_id,
            caller_domain_id: admission_caller_domain_id(admission),
            tenant_id: admission.proof().scope.tenant_id,
            action,
            target_user_id: user_id,
            operation_id,
            detail,
        },
    )
    .await?;

    let mut receipts = Vec::new();
    if !cards.is_empty() {
        let delivery_context = delivery_context.ok_or_else(|| {
            AstralError::Pending(
                "eligibility mutation requires an injected invalidation delivery context".into(),
            )
        })?;
        source_writer_guard::append_user_eligibility_with_invalidation_in_tx(
            tx,
            delivery_context,
            user_id,
            operation_id,
            cards.clone(),
            &mut receipts,
        )
        .await?;
    }

    Ok(UserMutationEvidence {
        after_row,
        operation_id: operation_id.to_owned(),
        updated_rows: updated.rows_affected(),
        audit_id,
        receipts,
        affected_cards: cards,
    })
}

/// 锁定行镜像，after 为写后同事务回读（软删除携带 tombstone；`Absent` 是真实
/// 探针）；receipt 覆盖 platform_user UPDATE、audit_log INSERT 与本事务写入的
/// ELIGIBILITY 投影/typed intent 行（`FOR UPDATE` 读回验证，durable id 即
/// event_id/message_id）。扇出先按共享 256 张卡上限整体拒绝；上限内的 receipt
/// 窗口保留显式 total，绝不伪造或丢弃计数。随后委托共享
/// `stage_identity_source_outcome_in_tx`（AuthorizationSource，coverage None）。
struct UserSourceOutcomeContext<'a> {
    admission: &'a AuthorizationAdmission,
    target_user_id: i64,
    before_row: &'a UserRowImage,
    after_row: Option<UserRowImage>,
    operation_id: &'a str,
    update_rows: u64,
    audit_id: i64,
    receipts: &'a [source_writer_guard::UserInvalidationReceipt],
    affected_cards: &'a [(i64, Option<i64>)],
    eligibility_receipt: Option<EligibilitySourceEvidenceReceipt>,
}

async fn stage_user_source_outcome(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    context: UserSourceOutcomeContext<'_>,
) -> Result<(), AstralError> {
    let UserSourceOutcomeContext {
        admission,
        target_user_id,
        before_row,
        after_row,
        operation_id,
        update_rows,
        audit_id,
        receipts,
        affected_cards,
        eligibility_receipt,
    } = context;
    let projection_event_ids: Vec<String> = receipts
        .iter()
        .map(|receipt| receipt.projection_event_id.clone())
        .collect();
    let message_ids: Vec<String> = receipts
        .iter()
        .map(|receipt| receipt.event_id.clone())
        .collect();
    let (projection_window, projection_total) = source_writer_guard::bounded_receipt_window(
        projection_event_ids,
        source_writer_guard::SOURCE_OUTCOME_RECEIPT_WINDOW,
    );
    let (message_window, message_total) = source_writer_guard::bounded_receipt_window(
        message_ids,
        source_writer_guard::SOURCE_OUTCOME_RECEIPT_WINDOW,
    );
    if receipts.len()
        > astral_db::authority_eligibility_completion::ELIGIBILITY_COMPLETION_MAX_CARDS
    {
        return Err(AstralError::Pending(
            "user eligibility completion exceeds the shared full-set evidence cap".into(),
        ));
    }
    let confirmed_events =
        source_writer_guard::read_back_projection_outbox_in_tx(tx, &projection_window).await?;
    let confirmed_intents =
        source_writer_guard::read_back_message_outbox_in_tx(tx, &message_window, operation_id)
            .await?;
    let mut outcome = source_writer_guard::IdentitySourceOutcome::new()
        .target(source_writer_guard::SourceTargetImage {
            entity: "platform_user",
            key: serde_json::json!({ "userId": target_user_id }),
            before: source_writer_guard::SourceRowPresence::present(before_row.to_row_json()),
            after: match after_row {
                Some(row) => source_writer_guard::SourceRowPresence::present(row.to_row_json()),
                None => source_writer_guard::SourceRowPresence::Absent,
            },
        })
        .receipt(source_writer_guard::SourceStatementReceipt {
            entity: "platform_user",
            key: serde_json::json!({ "userId": target_user_id }),
            kind: astral_db::WriteKind::Update,
            rows_affected: update_rows,
            durable_id: target_user_id.to_string(),
        })
        .receipt(source_writer_guard::SourceStatementReceipt {
            entity: "audit_log",
            key: serde_json::json!({ "id": audit_id }),
            kind: astral_db::WriteKind::Insert,
            rows_affected: 1,
            durable_id: audit_id.to_string(),
        });
    for event_id in &confirmed_events {
        outcome = outcome.receipt(source_writer_guard::SourceStatementReceipt {
            entity: "authorization_projection_outbox",
            key: serde_json::json!({ "eventId": event_id }),
            kind: astral_db::WriteKind::Insert,
            rows_affected: 1,
            durable_id: event_id.clone(),
        });
    }
    for message_id in &confirmed_intents {
        outcome = outcome.receipt(source_writer_guard::SourceStatementReceipt {
            entity: "al_message_outbox",
            key: serde_json::json!({ "messageId": message_id, "operationId": operation_id }),
            kind: astral_db::WriteKind::Insert,
            rows_affected: 1,
            durable_id: message_id.clone(),
        });
    }
    if confirmed_events.len() != projection_total || confirmed_intents.len() != message_total {
        return Err(AstralError::Pending(
            "user eligibility outbox receipt set is incomplete".into(),
        ));
    }
    let result = serde_json::json!({
        "operationId": operation_id,
        "targetUserId": target_user_id,
        "fromStatus": before_row.status,
        "rowsAffected": update_rows,
        "fanout": {
            "eligibilityEvents": projection_total,
            "messageEvents": message_total,
            "projectionReceipts": confirmed_events.len(),
            "intentReceipts": confirmed_intents.len(),
            // 实际完整受影响卡 owner 集合（事务内 FOR UPDATE 锁定扫描的真集，
            // 绝不猜测）：finite coverage 的 raw material，由共享 publication
            // candidate 装配层消费（scope 上限 256 由该层裁决）。
            "affectedCards": affected_cards
                .iter()
                .map(|(card_id, tenant_id)| serde_json::json!({
                    "cardId": card_id,
                    "tenantId": tenant_id,
                }))
                .collect::<Vec<_>>(),
        },
    });
    let outcome = if let Some(receipt) = eligibility_receipt {
        outcome.with_eligibility_receipt(receipt)
    } else if !affected_cards.is_empty() {
        return Err(AstralError::Pending(
            "user eligibility source mutation lacks its opaque completion receipt".into(),
        ));
    } else {
        outcome
    };
    source_writer_guard::stage_identity_source_outcome_in_tx(tx, admission, outcome, &result).await
}

#[async_trait]
impl UserRepository for SqlxUserRepository {
    async fn count_users(&self) -> Result<i64, AstralError> {
        let total: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM platform_user WHERE deleted_at IS NULL")
                .fetch_one(&self.db)
                .await
                .map_err(|e| AstralError::Database(format!("Count users failed: {e}")))?;
        Ok(total.0)
    }

    async fn list_users(&self, size: i64, offset: i64) -> Result<Vec<UserListRecord>, AstralError> {
        sqlx::query_as::<_, UserListRecord>(
            "SELECT u.user_id, c.login_name as username, u.display_name, u.email, u.phone, u.status \
             FROM platform_user u \
             LEFT JOIN user_local_credential c ON c.user_id = u.user_id \
             WHERE u.deleted_at IS NULL \
             ORDER BY u.user_id LIMIT ? OFFSET ?",
        )
        .bind(size)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AstralError::Database(format!("List users failed: {e}")))
    }

    async fn get_user(&self, user_id: i64) -> Result<Option<UserListRecord>, AstralError> {
        sqlx::query_as::<_, UserListRecord>(
            "SELECT u.user_id, c.login_name as username, u.display_name, u.email, u.phone, u.status \
             FROM platform_user u \
             LEFT JOIN user_local_credential c ON c.user_id = u.user_id \
             WHERE u.user_id = ? AND u.deleted_at IS NULL",
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AstralError::Database(format!("Get user failed: {e}")))
    }

    async fn update_user(
        &self,
        user_id: i64,
        display_name: Option<&str>,
        email: Option<&str>,
        phone: Option<&str>,
        status: Option<&str>,
        admission: Option<AuthorizationAdmission>,
    ) -> Result<(), AstralError> {
        // Profile-only updates do not affect card eligibility. Keep this path
        // free of projection work; the status-bearing path below owns the
        // proof-bound source mutation and ELIGIBILITY fanout transaction.
        if status.is_none() {
            let guard = source_writer_guard::begin_source_write()?;
            source_writer_guard::fenced_source_write(
                guard,
                sqlx::query(
                    "UPDATE platform_user SET \
                     display_name = COALESCE(?, display_name), \
                     email = COALESCE(?, email), \
                     phone = COALESCE(?, phone), \
                     updated_at = UTC_TIMESTAMP() \
                     WHERE user_id = ? AND deleted_at IS NULL",
                )
                .bind(display_name.map(str::trim))
                .bind(email.map(str::trim))
                .bind(phone.map(str::trim))
                .bind(user_id)
                .execute(&self.db),
            )
            .await
            .map_err(|e| AstralError::Database(format!("Update user profile failed: {e}")))?;
            return Ok(());
        }

        let admission = admission.ok_or_else(|| {
            AstralError::Pending(
                "status-bearing user update requires proof-bound authorization admission".into(),
            )
        })?;
        // 状态变更 source 事务的 hub writer 栅栏：begin 前取得（hub 已装则必须
        // 可得，不可得即拒绝写入），COMMIT await 前武装，commit 证明成功后
        // proven 释放；pre-commit 错误（已知回滚）随 Drop 干净释放。
        let source_guard = source_writer_guard::begin_source_write()?;
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AstralError::Database(format!("Begin update user tx failed: {e}")))?;
        let previous_row = lock_existing_user(&mut tx, user_id).await?;
        let Some(previous_row) = previous_row else {
            return Ok(());
        };
        source_writer_guard::validate_admission_caller_card(&mut tx, &admission).await?;
        let emit_eligibility =
            status_change_requires_eligibility_event(&previous_row.status, status);
        let operation_id = admission.operation_id().to_owned();
        // The DB-owned capture locks the source subject and exact selector before
        // any mutation; its opaque receipt is the only completion evidence.
        let eligibility_capture = if emit_eligibility {
            Some(
                EligibilitySourceCapture::begin_in_tx(
                    &mut tx,
                    &admission,
                    EligibilitySourceSubject::UserStatus { user_id },
                )
                .await
                .map_err(|error| AstralError::Pending(error.to_string()))?,
            )
        } else {
            None
        };
        let affected_cards = eligibility_capture
            .as_ref()
            .map(|capture| capture.selected_cards().to_vec())
            .unwrap_or_default();
        let delivery_context = if emit_eligibility {
            Some(self.require_delivery_context()?)
        } else {
            None
        };
        let (mut evidence, eligibility_receipt) = if let Some(mut capture) = eligibility_capture {
            let evidence = apply_user_eligibility_mutation_in_tx(
                capture.with_tx_mut(),
                UserEligibilityMutationContext {
                    admission: &admission,
                    user_id,
                    previous_row: &previous_row,
                    operation_id: &operation_id,
                    mutation: UserEligibilityMutation::Status {
                        display_name,
                        email,
                        phone,
                        status: status.unwrap_or(previous_row.status.as_str()),
                    },
                    cards: affected_cards,
                    delivery_context,
                },
            )
            .await?;
            let receipt = capture
                .finish_in_tx()
                .await
                .map_err(|error| AstralError::Pending(error.to_string()))?;
            (evidence, Some(receipt))
        } else {
            let evidence = apply_user_eligibility_mutation_in_tx(
                &mut tx,
                UserEligibilityMutationContext {
                    admission: &admission,
                    user_id,
                    previous_row: &previous_row,
                    operation_id: &operation_id,
                    mutation: UserEligibilityMutation::Status {
                        display_name,
                        email,
                        phone,
                        status: status.unwrap_or(previous_row.status.as_str()),
                    },
                    cards: Vec::new(),
                    delivery_context: None,
                },
            )
            .await?;
            (evidence, None)
        };

        source_writer_guard::validate_and_consume_admission(&mut tx, &admission).await?;
        stage_user_source_outcome(
            &mut tx,
            UserSourceOutcomeContext {
                admission: &admission,
                target_user_id: user_id,
                before_row: &previous_row,
                after_row: evidence.after_row,
                operation_id: &evidence.operation_id,
                update_rows: evidence.updated_rows,
                audit_id: evidence.audit_id,
                receipts: &evidence.receipts,
                affected_cards: &evidence.affected_cards,
                eligibility_receipt,
            },
        )
        .await?;
        // COMMIT await 前武装取消栅栏；commit 证明成功 → proven + LocalBus 直投
        // receipts（总 5s 预算），unknown/失败 → sticky uncertain + 零投递。
        source_writer_guard::arm_commit_fence(&source_guard);
        let commit_result = tx.commit().await;
        let proven_receipts =
            source_writer_guard::receipts_for_proven_commit(&mut evidence.receipts, &commit_result);
        source_writer_guard::settle_commit_fence(&source_guard, commit_result.is_ok());
        commit_result
            .map_err(|e| AstralError::Database(format!("Commit update user tx failed: {e}")))?;
        drop(source_guard);
        source_writer_guard::dispatch_proven_user_invalidation_receipts(proven_receipts).await;
        Ok(())
    }

    async fn update_user_status(
        &self,
        user_id: i64,
        status: &str,
        admission: AuthorizationAdmission,
    ) -> Result<(), AstralError> {
        // 状态变更 source 事务的 hub writer 栅栏（同 update_user 状态路径）。
        let source_guard = source_writer_guard::begin_source_write()?;
        let mut tx = self.db.begin().await.map_err(|e| {
            AstralError::Database(format!("Begin update user status tx failed: {e}"))
        })?;
        let previous_row = lock_existing_user(&mut tx, user_id).await?;
        let Some(previous_row) = previous_row else {
            return Ok(());
        };
        source_writer_guard::validate_admission_caller_card(&mut tx, &admission).await?;
        let requested_status = status.trim();
        let status_changed = previous_row.status != requested_status;
        let operation_id = admission.operation_id().to_owned();
        let delivery_context = if status_changed {
            Some(self.require_delivery_context()?)
        } else {
            None
        };
        let eligibility_capture = if status_changed {
            Some(
                EligibilitySourceCapture::begin_in_tx(
                    &mut tx,
                    &admission,
                    EligibilitySourceSubject::UserStatus { user_id },
                )
                .await
                .map_err(|error| AstralError::Pending(error.to_string()))?,
            )
        } else {
            None
        };
        let affected_cards = eligibility_capture
            .as_ref()
            .map(|capture| capture.selected_cards().to_vec())
            .unwrap_or_default();
        let (mut evidence, eligibility_receipt) = if let Some(mut capture) = eligibility_capture {
            let evidence = apply_user_eligibility_mutation_in_tx(
                capture.with_tx_mut(),
                UserEligibilityMutationContext {
                    admission: &admission,
                    user_id,
                    previous_row: &previous_row,
                    operation_id: &operation_id,
                    mutation: UserEligibilityMutation::Status {
                        display_name: None,
                        email: None,
                        phone: None,
                        status: requested_status,
                    },
                    cards: affected_cards,
                    delivery_context,
                },
            )
            .await?;
            let receipt = capture
                .finish_in_tx()
                .await
                .map_err(|error| AstralError::Pending(error.to_string()))?;
            (evidence, Some(receipt))
        } else {
            let evidence = apply_user_eligibility_mutation_in_tx(
                &mut tx,
                UserEligibilityMutationContext {
                    admission: &admission,
                    user_id,
                    previous_row: &previous_row,
                    operation_id: &operation_id,
                    mutation: UserEligibilityMutation::Status {
                        display_name: None,
                        email: None,
                        phone: None,
                        status: requested_status,
                    },
                    cards: Vec::new(),
                    delivery_context: None,
                },
            )
            .await?;
            (evidence, None)
        };
        source_writer_guard::validate_and_consume_admission(&mut tx, &admission).await?;
        stage_user_source_outcome(
            &mut tx,
            UserSourceOutcomeContext {
                admission: &admission,
                target_user_id: user_id,
                before_row: &previous_row,
                after_row: evidence.after_row,
                operation_id: &evidence.operation_id,
                update_rows: evidence.updated_rows,
                audit_id: evidence.audit_id,
                receipts: &evidence.receipts,
                affected_cards: &evidence.affected_cards,
                eligibility_receipt,
            },
        )
        .await?;
        source_writer_guard::arm_commit_fence(&source_guard);
        let commit_result = tx.commit().await;
        let proven_receipts =
            source_writer_guard::receipts_for_proven_commit(&mut evidence.receipts, &commit_result);
        source_writer_guard::settle_commit_fence(&source_guard, commit_result.is_ok());
        commit_result.map_err(|e| {
            AstralError::Database(format!("Commit update user status tx failed: {e}"))
        })?;
        drop(source_guard);
        source_writer_guard::dispatch_proven_user_invalidation_receipts(proven_receipts).await;
        Ok(())
    }

    async fn soft_delete_user(
        &self,
        user_id: i64,
        admission: AuthorizationAdmission,
    ) -> Result<(), AstralError> {
        // 软删除 source 事务的 hub writer 栅栏（同 update_user 状态路径）。
        let source_guard = source_writer_guard::begin_source_write()?;
        let mut tx =
            self.db.begin().await.map_err(|e| {
                AstralError::Database(format!("Begin soft delete user tx failed: {e}"))
            })?;
        let previous_row = lock_existing_user(&mut tx, user_id).await?;
        if !soft_delete_requires_eligibility_event(
            previous_row.as_ref().map(|row| row.status.as_str()),
        ) {
            return Ok(());
        }
        let previous_row = previous_row.expect("existing user row survived the eligibility gate");
        source_writer_guard::validate_admission_caller_card(&mut tx, &admission).await?;

        let operation_id = admission.operation_id().to_owned();
        let delivery_context = Some(self.require_delivery_context()?);
        let mut eligibility_capture = Some(
            EligibilitySourceCapture::begin_in_tx(
                &mut tx,
                &admission,
                EligibilitySourceSubject::UserDelete { user_id },
            )
            .await
            .map_err(|error| AstralError::Pending(error.to_string()))?,
        );
        let affected_cards = eligibility_capture
            .as_ref()
            .map(|capture| capture.selected_cards().to_vec())
            .unwrap_or_default();
        let mut evidence = if let Some(capture) = eligibility_capture.as_mut() {
            apply_user_eligibility_mutation_in_tx(
                capture.with_tx_mut(),
                UserEligibilityMutationContext {
                    admission: &admission,
                    user_id,
                    previous_row: &previous_row,
                    operation_id: &operation_id,
                    mutation: UserEligibilityMutation::Delete,
                    cards: affected_cards,
                    delivery_context,
                },
            )
            .await?
        } else {
            unreachable!("user delete capture is mandatory")
        };
        let eligibility_receipt = eligibility_capture
            .take()
            .expect("user delete capture is present")
            .finish_in_tx()
            .await
            .map_err(|error| AstralError::Pending(error.to_string()))?;
        source_writer_guard::validate_and_consume_admission(&mut tx, &admission).await?;
        stage_user_source_outcome(
            &mut tx,
            UserSourceOutcomeContext {
                admission: &admission,
                target_user_id: user_id,
                before_row: &previous_row,
                after_row: evidence.after_row,
                operation_id: &evidence.operation_id,
                update_rows: evidence.updated_rows,
                audit_id: evidence.audit_id,
                receipts: &evidence.receipts,
                affected_cards: &evidence.affected_cards,
                eligibility_receipt: Some(eligibility_receipt),
            },
        )
        .await?;
        source_writer_guard::arm_commit_fence(&source_guard);
        let commit_result = tx.commit().await;
        let proven_receipts =
            source_writer_guard::receipts_for_proven_commit(&mut evidence.receipts, &commit_result);
        source_writer_guard::settle_commit_fence(&source_guard, commit_result.is_ok());
        commit_result.map_err(|e| {
            AstralError::Database(format!("Commit soft delete user tx failed: {e}"))
        })?;
        drop(source_guard);
        source_writer_guard::dispatch_proven_user_invalidation_receipts(proven_receipts).await;
        Ok(())
    }

    async fn list_user_cards(&self, user_id: i64) -> Result<Vec<UserCard>, AstralError> {
        let rows = sqlx::query_as::<_, UserCardRow>(
            "SELECT card_id, user_id, domain_id, card_type, card_status, template_id, \
             level_id, priority, is_primary, valid_from, valid_until, created_at, updated_at, tenant_id \
             FROM user_card WHERE user_id = ? ORDER BY card_id",
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AstralError::Database(format!("List user cards failed: {e}")))?;

        Ok(rows
            .into_iter()
            .map(|r| UserCard {
                card_id: Some(r.card_id),
                user_id: r.user_id,
                domain_id: r.domain_id,
                card_type: r.card_type,
                card_status: r.card_status,
                template_id: r.template_id,
                level_id: r.level_id,
                priority: r.priority,
                is_primary: r.is_primary,
                valid_from: r.valid_from,
                valid_until: r.valid_until,
                created_at: r.created_at,
                updated_at: r.updated_at,
                tenant_id: r.tenant_id,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::{soft_delete_requires_eligibility_event, status_change_requires_eligibility_event};

    #[test]
    fn profile_only_update_does_not_emit_eligibility_event() {
        assert!(!status_change_requires_eligibility_event("ACTIVE", None));
    }

    #[test]
    fn unchanged_status_does_not_emit_eligibility_event() {
        assert!(!status_change_requires_eligibility_event(
            "ACTIVE",
            Some(" ACTIVE ")
        ));
    }

    #[test]
    fn changed_status_emits_eligibility_event() {
        assert!(status_change_requires_eligibility_event(
            "ACTIVE",
            Some("DISABLED")
        ));
    }

    #[test]
    fn soft_delete_emits_for_any_existing_user() {
        assert!(soft_delete_requires_eligibility_event(Some("ACTIVE")));
        assert!(soft_delete_requires_eligibility_event(Some("DISABLED")));
        assert!(!soft_delete_requires_eligibility_event(None));
    }

    #[test]
    fn user_status_transactions_require_proof_bound_admission_before_commit() {
        let source = include_str!("user_repository.rs");
        let impl_source = &source[source
            .find("impl UserRepository for SqlxUserRepository")
            .expect("UserRepository impl must stay in user_repository.rs")..];

        for (method, next_method) in [
            ("async fn update_user(", "async fn update_user_status("),
            ("async fn update_user_status(", "async fn soft_delete_user("),
            ("async fn soft_delete_user(", "async fn list_user_cards("),
        ] {
            let body = impl_source
                .split(method)
                .nth(1)
                .and_then(|body| body.split(next_method).next())
                .expect("user lifecycle method must be delimited");
            let admission_check = body
                .find("source_writer_guard::validate_admission_caller_card(&mut tx, &admission)")
                .expect("qualification writer must verify the caller card admission");
            let source_mutation = body
                .find("apply_user_eligibility_mutation_in_tx(")
                .expect("qualification writer must route its source mutation through the helper");
            let admission_consume = body
                .find("source_writer_guard::validate_and_consume_admission(&mut tx, &admission)")
                .expect("qualification writer must consume admission before commit");
            let commit = body
                .find("tx.commit().await")
                .expect("qualification writer must have an explicit commit await");
            assert!(
                admission_check < source_mutation
                    && source_mutation < admission_consume
                    && admission_consume < commit,
                "{method} must verify admission, mutate source, consume admission, then commit"
            );
        }

        let mutation_helper_start = source
            .find("async fn apply_user_eligibility_mutation_in_tx(")
            .expect("the user mutation helper must stay in user_repository.rs");
        let mutation_helper = &source[mutation_helper_start
            ..source[mutation_helper_start..]
                .find("\n/// 锁定行镜像")
                .map(|end| mutation_helper_start + end)
                .unwrap_or(source.len())];
        assert!(
            mutation_helper.contains("status = COALESCE(?, status)")
                && mutation_helper.contains("UPDATE platform_user SET deleted_at")
                && mutation_helper.contains("if updated.rows_affected() != 1")
                && mutation_helper.contains("read_back_user_row_in_tx(tx, user_id)"),
            "the shared user mutation helper must retain exact-row proof and after-image readback"
        );

        let profile_branch = impl_source
            .split("async fn update_user(")
            .nth(1)
            .and_then(|body| body.split("async fn update_user_status(").next())
            .expect("update_user implementation must be delimited");
        let profile_end = profile_branch
            .find("return Ok(());")
            .expect("profile-only branch must remain explicit");
        assert!(
            !profile_branch[..profile_end]
                .contains("source_writer_guard::validate_and_consume_admission"),
            "profile-only metadata updates must not consume an authorization admission"
        );
    }

    #[test]
    fn user_status_transactions_fence_capture_before_update_and_dispatch_after_proven_commit() {
        let source = include_str!("user_repository.rs");
        let capture_source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../astral-db/src/authority_eligibility_completion.rs"
        ));
        let capture_production = &capture_source[..capture_source
            .find("#[cfg(test)]")
            .expect("eligibility capture tests must follow production source")];
        assert!(
            capture_production.contains("ELIGIBILITY_COMPLETION_MAX_CARDS + 1")
                && capture_production.contains("LIMIT ? FOR UPDATE"),
            "the DB capture must retain bounded cap+1 FOR UPDATE selection"
        );
        assert!(
            capture_production.contains("eligibility selector crossed tenant ownership")
                && capture_production.contains(
                    "EligibilitySourceOperation::CardStatus | EligibilitySourceOperation::CardRebind => None"
                )
                && capture_production.contains("EligibilitySourceOperation::CardCreate => None"),
            "selector ownership and CardStatus/CardRebind/CardCreate empty-selection restrictions must remain fail-closed"
        );
        // 先切到 impl 块：trait 里也有同名方法声明，find 必须跳过 trait。
        let impl_source = &source[source
            .find("impl UserRepository for SqlxUserRepository")
            .expect("UserRepository impl must stay in user_repository.rs")..];

        for (method, next_method, subject, label) in [
            (
                "async fn update_user(",
                "async fn update_user_status(",
                "EligibilitySourceSubject::UserStatus { user_id }",
                "update_user",
            ),
            (
                "async fn update_user_status(",
                "async fn soft_delete_user(",
                "EligibilitySourceSubject::UserStatus { user_id }",
                "update_user_status",
            ),
            (
                "async fn soft_delete_user(",
                "async fn list_user_cards(",
                "EligibilitySourceSubject::UserDelete { user_id }",
                "soft_delete_user",
            ),
        ] {
            let body = impl_source
                .split(method)
                .nth(1)
                .and_then(|body| body.split(next_method).next())
                .unwrap_or_else(|| panic!("{label} body must be delimited"));
            let guard = body
                .find("let source_guard = source_writer_guard::begin_source_write()")
                .unwrap_or_else(|| panic!("{label} must hold the source writer guard"));
            let begin = body
                .find(".begin()")
                .unwrap_or_else(|| panic!("{label} must open its transaction"));
            let capture = body
                .find("EligibilitySourceCapture::begin_in_tx")
                .unwrap_or_else(|| panic!("{label} must use the DB-owned capture"));
            let subject_at = body
                .find(subject)
                .unwrap_or_else(|| panic!("{label} must use its typed capture subject"));
            let selected = body
                .find("capture.selected_cards()")
                .unwrap_or_else(|| panic!("{label} must derive affected cards from capture"));
            let source_mutation = body
                .find("apply_user_eligibility_mutation_in_tx(")
                .unwrap_or_else(|| panic!("{label} must route source mutation through the helper"));
            let tx_mut = body
                .find("capture.with_tx_mut()")
                .unwrap_or_else(|| panic!("{label} must use the capture transaction"));
            let finish = body
                .find("finish_in_tx()")
                .unwrap_or_else(|| panic!("{label} must finish an opaque completion receipt"));
            let admission_consume = body
                .find("source_writer_guard::validate_and_consume_admission(&mut tx, &admission)")
                .unwrap_or_else(|| panic!("{label} must consume admission before commit"));
            let stage = body
                .find("stage_user_source_outcome(")
                .unwrap_or_else(|| panic!("{label} must stage its real source outcome"));
            let arm = body
                .find("source_writer_guard::arm_commit_fence(&source_guard)")
                .unwrap_or_else(|| panic!("{label} must arm its commit fence"));
            let commit = body
                .find("tx.commit().await")
                .unwrap_or_else(|| panic!("{label} must await commit"));
            assert!(
                guard < begin && begin < capture && capture < subject_at && subject_at < selected,
                "{label}: guard, transaction, capture, subject, and selector order must remain closed"
            );
            assert!(
                selected < source_mutation && source_mutation < tx_mut && tx_mut < finish,
                "{label}: bounded selector must precede the same-transaction source mutation and finish"
            );
            assert!(
                finish < admission_consume && admission_consume < stage && stage < arm && arm < commit,
                "{label}: opaque receipt, admission, stage, and commit fence ordering must remain closed"
            );
            assert!(
                body.contains("admission.operation_id()") && body.contains("&operation_id"),
                "{label}: operation identity must come from the proof-bound admission"
            );
        }

        // 三个事务都不再调用 caller-owned bulk selector helpers: the DB capture
        // owns bounded selection, while the caller only relays selected cards.
        let obsolete_selector = format!("scan_{}eligibility_cards_in_tx", "user_");
        assert!(
            !source.contains(&obsolete_selector),
            "user callers must not retain the obsolete selector helper"
        );
        let bulk_helper = format!("append_eligibility_events_for_{}", "cards_in_tx");
        assert!(
            !source.contains(&bulk_helper),
            "user txs must use the bounded paired per-card append, not the bulk helper"
        );
    }

    /// 已 admitted user source 事务的真实 source outcome 契约钉（源形状）：
    /// source UPDATE 之后同事务回读 after 镜像；admission 消费之后、COMMIT
    /// await（arm 取消栅栏）之前完成 stage/promote；UPDATE 必须证明恰好一行。
    #[test]
    fn user_source_transactions_stage_real_outcomes_after_consume_before_commit() {
        let source = include_str!("user_repository.rs");
        let impl_source = &source[source
            .find("impl UserRepository for SqlxUserRepository")
            .expect("UserRepository impl must stay in user_repository.rs")..];
        for (anchor, next_anchor, label) in [
            (
                "async fn update_user(",
                "async fn update_user_status(",
                "update_user",
            ),
            (
                "async fn update_user_status(",
                "async fn soft_delete_user(",
                "update_user_status",
            ),
            (
                "async fn soft_delete_user(",
                "async fn list_user_cards(",
                "soft_delete_user",
            ),
        ] {
            let body = impl_source
                .split(anchor)
                .nth(1)
                .and_then(|body| body.split(next_anchor).next())
                .unwrap_or_else(|| panic!("{label} body must be delimited"));
            let update = body
                .find("apply_user_eligibility_mutation_in_tx(")
                .unwrap_or_else(|| {
                    panic!("{label} must route its source mutation through the helper")
                });
            let consume = body
                .find("source_writer_guard::validate_and_consume_admission(&mut tx, &admission)")
                .unwrap_or_else(|| panic!("{label} must consume its admission"));
            let stage = body
                .find("stage_user_source_outcome(")
                .unwrap_or_else(|| panic!("{label} must stage its real source outcome"));
            let arm = body
                .find("source_writer_guard::arm_commit_fence(&source_guard)")
                .expect("commit fence must stay");
            let commit = body
                .find("tx.commit().await")
                .expect("commit await must stay");
            assert!(
                update < consume,
                "{label}: source mutation helper must precede admission consumption"
            );
            assert!(
                consume < stage,
                "{label}: staging must follow the same-transaction admission consumption"
            );
            assert!(
                stage < arm,
                "{label}: staging must precede the commit fence"
            );
            assert!(arm < commit, "{label}: the commit await is armed last");
        }
        let mutation_start = source
            .find("async fn apply_user_eligibility_mutation_in_tx(")
            .expect("the user mutation helper must remain in the production region");
        let mutation_end = source[mutation_start..]
            .find("\n/// 锁定行镜像")
            .map(|end| mutation_start + end)
            .unwrap_or(source.len());
        let mutation_helper = &source[mutation_start..mutation_end];
        assert!(
            mutation_helper.contains("status = COALESCE(?, status)")
                && mutation_helper.contains("UPDATE platform_user SET deleted_at")
                && mutation_helper.contains("if updated.rows_affected() != 1")
                && mutation_helper.contains("read_back_user_row_in_tx(tx, user_id)"),
            "the helper must retain exact-row proof and after-image readback"
        );
        // user 侧只组装证据并委托共享 stage helper（AuthorizationSource、
        // coverage None），不复制第二份 canonical stage 语义。
        assert!(
            source.contains(
                "source_writer_guard::stage_identity_source_outcome_in_tx(tx, admission, outcome, &result)"
            ),
            "user staging must delegate to the shared Identity stage helper"
        );
    }

    /// 目标证据钉（源形状）：before 镜像来自 `FOR UPDATE` 锁定读、after 镜像
    /// 来自同事务回读；evidence 的 receipt 覆盖真实语句与同事务 outbox 读回，
    /// 绝不用 actor 快照/operation id 替代目标证据。
    #[test]
    fn user_outcome_evidence_is_assembled_from_real_rows_and_receipts() {
        let source = include_str!("user_repository.rs");
        let start = source
            .find("async fn stage_user_source_outcome(")
            .expect("the user stage helper must stay in user_repository.rs");
        let end = source[start..]
            .find("#[cfg(test)]")
            .expect("tests must follow the repository");
        let body = &source[start..start + end];
        assert!(
            body.contains("entity: \"platform_user\"")
                && body.contains("before: source_writer_guard::SourceRowPresence::present(before_row.to_row_json())"),
            "the target evidence must carry the real locked before image"
        );
        assert!(
            body.contains("read_back_projection_outbox_in_tx")
                && body.contains("read_back_message_outbox_in_tx"),
            "outbox receipts must be verified by in-transaction readback"
        );
        assert!(
            body.contains("bounded_receipt_window")
                && body.contains("\"eligibilityEvents\": projection_total")
                && body.contains("\"messageEvents\": message_total")
                && body.contains("confirmed_events.len() != projection_total")
                && body.contains("confirmed_intents.len() != message_total"),
            "fanout receipts must retain separate exact projection and message totals"
        );
        assert!(
            body.contains("entity: \"audit_log\"")
                && body.contains("durable_id: audit_id.to_string()"),
            "the in-transaction audit row must appear as a real receipt"
        );
    }
}
