//! 权限审批请求数据访问 — PermissionRequestRepository
//!
//! 对齐 Java `PermissionRequestMapper` 边界（permission_request 表）。
//! 审批事务（状态更新 + 规则 INSERT）收口为单一聚合方法。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::{AstralError, GrantState};

use crate::repository::audit_log_repository::validated_request_operation_id;
use crate::repository::grant_ledger_adapter::{
    append_approval_grant_in_tx, append_approval_remove_in_tx, build_approval_remove_draft,
    derive_approval_contribution_event_id, derive_approval_identity, derive_approval_operation_id,
    map_grant_repository_error, reject_unrepresentable_condition, ApprovalContributionKind,
    ApprovalGrantLedgerContext, ApprovalRemoveLedgerFacts, APPROVAL_AGGREGATE_TYPE,
};
use crate::repository::projection_repository::append_card_projection_with_metadata_in_tx;

/// 审批请求记录（permission_request）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PermissionRequestRecord {
    pub request_id: i64,
    pub user_id: i64,
    pub request_type: String,
    pub request_content: Option<String>,
    pub reason: Option<String>,
    pub status: String,
    pub approver_id: Option<i64>,
    pub approve_comment: Option<String>,
    pub created_at: Option<String>,
}

/// 新建请求参数
#[derive(Debug)]
pub struct NewRequest {
    pub user_id: i64,
    pub request_type: String,
    pub request_content: String,
    pub reason: Option<String>,
}

const PR_SELECT: &str =
    "request_id, user_id, request_type, request_content, reason, status, approver_id, \
     approve_comment, DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at";

#[async_trait]
pub trait PermissionRequestRepository: Send + Sync {
    /// 新建（request_type='RULE', status='PENDING'），返回 request_id
    async fn create_request(&self, new: &NewRequest) -> Result<i64, AstralError>;
    /// Verify the requester owns an ACTIVE, currently valid card before a request is inserted.
    async fn validate_card_for_user(&self, user_id: i64, card_id: i64) -> Result<(), AstralError>;
    async fn count_all(&self) -> Result<i64, AstralError>;
    /// 分页列表（ORDER BY created_at DESC）
    async fn list_all(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PermissionRequestRecord>, AstralError>;
    async fn get_request(
        &self,
        request_id: i64,
    ) -> Result<Option<PermissionRequestRecord>, AstralError>;
    async fn count_for_user(&self, user_id: i64) -> Result<i64, AstralError>;
    async fn list_for_user(
        &self,
        user_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PermissionRequestRecord>, AstralError>;
    async fn get_request_for_user(
        &self,
        request_id: i64,
        user_id: i64,
    ) -> Result<Option<PermissionRequestRecord>, AstralError>;
    async fn cancel_request(
        &self,
        request_id: i64,
        user_id: i64,
        comment: Option<&str>,
        request_id_header: Option<&str>,
    ) -> Result<(), AstralError>;
    async fn count_pending(&self) -> Result<i64, AstralError>;
    /// 分页 pending 列表
    async fn list_pending(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PermissionRequestRecord>, AstralError>;
    /// 审批事务：置 APPROVED + 插入 ALLOW 规则（同一事务，对齐 Java approve）
    #[allow(clippy::too_many_arguments)]
    async fn approve_with_rule(
        &self,
        request_id: i64,
        reviewer_id: i64,
        comment: Option<&str>,
        card_id: i64,
        resource: &str,
        action: &str,
        effect: &str,
        priority: i32,
        condition_json: Option<&str>,
        valid_from: Option<&str>,
        valid_to: Option<&str>,
        request_id_header: Option<&str>,
    ) -> Result<(), AstralError>;
    /// 驳回（REJECTED）
    async fn reject_request(
        &self,
        request_id: i64,
        reviewer_id: i64,
        comment: Option<&str>,
        request_id_header: Option<&str>,
    ) -> Result<(), AstralError>;
    /// 单条 APPROVAL 贡献的审批后撤销（post-approval revoke）。
    ///
    /// 仅接受 APPROVED 请求下仍活跃（enabled=1、ALLOW、provenance 指向本请求）
    /// 的 `permission_rule` 贡献：同一 source 事务内完成 CARD REVOKE 投影
    /// （真实 reviewer actor + 稳定 operation id）→ 授权账本 REMOVE tombstone
    /// （成对 before-image/digest）→ 贡献规则行删除 → 审批审计。
    ///
    /// 幂等语义：贡献已不存在且其账本 grant 头状态为 Removed/Revoked 时返回
    /// `Ok(false)`（proven no-op，不重复落 tombstone）；返回 `Ok(true)` 表示本次
    /// 调用实际执行了撤销。其余任何无法证明的状态一律 fail-closed 错误。
    ///
    /// 默认实现显式 `NotImplemented` fail-closed：未显式支持该生命周期的
    /// repository（含测试替身）绝不允许静默伪造撤销结果。
    async fn revoke_approved_contribution(
        &self,
        request_id: i64,
        rule_id: i64,
        reviewer_id: i64,
        comment: Option<&str>,
        request_id_header: Option<&str>,
    ) -> Result<bool, AstralError> {
        let _ = (request_id, rule_id, reviewer_id, comment, request_id_header);
        Err(AstralError::NotImplemented(
            "approval contribution revoke is not implemented by this repository".into(),
        ))
    }
    /// 是否由审批聚合事务追加 authorization projection。
    fn writes_projection_in_transaction(&self) -> bool {
        false
    }
}

pub struct SqlxPermissionRequestRepository {
    db: MySqlPool,
}

impl SqlxPermissionRequestRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

/// FOR UPDATE 锁定的 APPROVAL 贡献规则行：provenance/effect/enabled 全部来自
/// 锁定行本体，撤销身份不信任任何调用方声明。
#[derive(Debug, sqlx::FromRow)]
struct LockedApprovalContributionRule {
    card_id: i64,
    tenant_id: Option<i64>,
    effect: String,
    source_type: String,
    source_id: Option<i64>,
    enabled: Option<i32>,
}

/// FOR UPDATE 锁定的贡献承载卡身份事实（user_card 行 + 请求归属 join 一次取齐；
/// 撤销是安全方向，不要求卡仍 ACTIVE，但归属与租户/域边界必须可证明）。
#[derive(Debug, sqlx::FromRow)]
struct LockedContributionCard {
    user_id: i64,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
}

/// 锁定贡献承载卡：卡必须存在且属于请求的 user（provenance 归属证明）。
async fn lock_contribution_card_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    card_id: i64,
    request_id: i64,
) -> Result<Option<LockedContributionCard>, AstralError> {
    sqlx::query_as(
        "SELECT uc.user_id, uc.tenant_id, uc.domain_id FROM user_card uc \
         INNER JOIN permission_request pr ON pr.user_id = uc.user_id \
         WHERE uc.card_id = ? AND pr.request_id = ? FOR UPDATE",
    )
    .bind(card_id)
    .bind(request_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)
}

/// 单条审批贡献撤销的稳定 operation id（纯派生）：安全 request-id 头优先原样
/// 复用（与 approve/direct/delegation 同一门禁：仅 ASCII 安全集、≤ 64 字节），
/// 缺失/空白时从 `{request_id}:{rule_id}` 确定性派生
/// `approval:revoke:{request_id}:rule:{rule_id}`，与 approve 的
/// `approval:{request_id}` fallback 域分离，绝不做随机或截断回退。
///
/// 头部复用意味着同一 header 下 approve 与 revoke 共享 operation id：两者的
/// delta 事件号经 `mutation_kind`（add/remove）与投影事件号分域，账本/审计
/// 关联仍可区分。非正 id 或非法头部一律 Validation fail-closed。
fn derive_approval_revoke_operation_id(
    request_id: i64,
    rule_id: i64,
    request_id_header: Option<&str>,
) -> Result<String, AstralError> {
    if request_id <= 0 {
        return Err(AstralError::Validation(
            "approval revoke operation identity requires a positive permission_request id".into(),
        ));
    }
    if rule_id <= 0 {
        return Err(AstralError::Validation(
            "approval revoke operation identity requires a positive permission_rule id".into(),
        ));
    }
    let Some(header) = request_id_header else {
        return Ok(format!("approval:revoke:{request_id}:rule:{rule_id}"));
    };
    let usable = header.len()
        <= crate::repository::grant_ledger_adapter::MAX_HEADER_OPERATION_ID_LENGTH
        && header.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        });
    if !usable {
        return Err(AstralError::Validation(format!(
            "approval revoke request-id header is not reusable as a durable operation id: {header:?}"
        )));
    }
    Ok(header.to_owned())
}

#[async_trait]
impl PermissionRequestRepository for SqlxPermissionRequestRepository {
    fn writes_projection_in_transaction(&self) -> bool {
        true
    }

    async fn create_request(&self, new: &NewRequest) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO permission_request (user_id, request_type, request_content, reason, status) \
             VALUES (?, ?, ?, ?, 'PENDING')",
        )
        .bind(new.user_id)
        .bind(&new.request_type)
        .bind(&new.request_content)
        .bind(&new.reason)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn validate_card_for_user(&self, user_id: i64, card_id: i64) -> Result<(), AstralError> {
        let card: Option<(i64,)> = sqlx::query_as(
            "SELECT card_id FROM user_card \
             WHERE card_id = ? AND user_id = ? AND card_status = 'ACTIVE' \
               AND (valid_from IS NULL OR valid_from <= NOW()) \
               AND (valid_until IS NULL OR valid_until >= NOW())",
        )
        .bind(card_id)
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)?;
        if card.is_none() {
            return Err(AstralError::Validation(
                "permission request card must belong to requester and be ACTIVE and currently valid".into(),
            ));
        }
        Ok(())
    }

    async fn count_all(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM permission_request")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_all(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PermissionRequestRecord>, AstralError> {
        sqlx::query_as::<_, PermissionRequestRecord>(&format!(
            "SELECT {PR_SELECT} FROM permission_request ORDER BY created_at DESC LIMIT ? OFFSET ?"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_for_user(
        &self,
        user_id: i64,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PermissionRequestRecord>, AstralError> {
        sqlx::query_as::<_, PermissionRequestRecord>(&format!(
            "SELECT {PR_SELECT} FROM permission_request WHERE user_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?"
        ))
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn get_request(
        &self,
        request_id: i64,
    ) -> Result<Option<PermissionRequestRecord>, AstralError> {
        sqlx::query_as::<_, PermissionRequestRecord>(&format!(
            "SELECT {PR_SELECT} FROM permission_request WHERE request_id=?"
        ))
        .bind(request_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn count_for_user(&self, user_id: i64) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM permission_request WHERE user_id=?")
            .bind(user_id)
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn get_request_for_user(
        &self,
        request_id: i64,
        user_id: i64,
    ) -> Result<Option<PermissionRequestRecord>, AstralError> {
        sqlx::query_as::<_, PermissionRequestRecord>(&format!(
            "SELECT {PR_SELECT} FROM permission_request WHERE request_id=? AND user_id=?"
        ))
        .bind(request_id)
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn cancel_request(
        &self,
        request_id: i64,
        user_id: i64,
        comment: Option<&str>,
        request_id_header: Option<&str>,
    ) -> Result<(), AstralError> {
        use crate::repository::audit_log_repository::{
            insert_approval_audit_in_tx, ApprovalAuditContext, ApprovalAuditEntry,
        };

        // 统一 request-id 合同门禁：显式携带但超长/含不安全字节的 header 在任何
        // 事务副作用之前 Validation fail-closed —— 绝不允许 65+ 字节值进入
        // `audit_log.request_id` VARCHAR(64) 造成截断或写失败，也绝不静默替换。
        // 缺失/空白 header 维持既有稳定 fallback（approval:{request_id}），
        // 不产生随机或超长审计关联值。失败时事务未开始，无任何副作用。
        let request_id_header = validated_request_operation_id(request_id_header)?;
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let request: Option<(i64, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT user_id, request_content, reason FROM permission_request \
             WHERE request_id=? AND user_id=? AND status='PENDING' FOR UPDATE",
        )
        .bind(request_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        let Some((target_user_id, request_content, request_reason)) = request else {
            return Err(AstralError::Validation(
                "permission request is not pending or does not belong to requester".into(),
            ));
        };
        let target_card_id = request_content
            .as_deref()
            .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok())
            .and_then(|value| value.get("cardId").and_then(serde_json::Value::as_i64));

        let result = sqlx::query(
            "UPDATE permission_request SET status='CANCELLED', approve_comment=?, updated_at=NOW() \
             WHERE request_id=? AND user_id=? AND status='PENDING'",
        )
        .bind(comment)
        .bind(request_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Validation(
                "permission request is no longer pending or does not belong to requester".into(),
            ));
        }

        let context = ApprovalAuditContext::new(request_id_header.as_deref(), request_id);
        insert_approval_audit_in_tx(
            &mut tx,
            &ApprovalAuditEntry {
                actor_id: user_id,
                reviewer_id: None,
                target_user_id,
                target_card_id,
                action: "cancel",
                decision: "CANCELLED",
                request_reason: request_reason.as_deref(),
                reviewer_comment: comment,
                context: &context,
            },
        )
        .await?;
        tx.commit().await.map_err(db_error)
    }

    async fn count_pending(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM permission_request WHERE status='PENDING'",
        )
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_pending(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PermissionRequestRecord>, AstralError> {
        sqlx::query_as::<_, PermissionRequestRecord>(&format!(
            "SELECT {PR_SELECT} FROM permission_request WHERE status='PENDING' ORDER BY created_at DESC LIMIT ? OFFSET ?"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn revoke_approved_contribution(
        &self,
        request_id: i64,
        rule_id: i64,
        reviewer_id: i64,
        comment: Option<&str>,
        request_id_header: Option<&str>,
    ) -> Result<bool, AstralError> {
        use crate::repository::audit_log_repository::{
            insert_approval_audit_in_tx, ApprovalAuditContext, ApprovalAuditEntry,
        };

        // ── 事务前纯门禁（失败即零副作用）────────────────────────────────────
        // reviewer 必须是已验证的正数 actor；请求/规则主键必须可作身份维度。
        if reviewer_id <= 0 {
            return Err(AstralError::Permission(
                "approval contribution revoke requires a verified positive reviewer id".into(),
            ));
        }
        if request_id <= 0 || rule_id <= 0 {
            return Err(AstralError::Validation(
                "approval contribution revoke requires positive request and rule ids".into(),
            ));
        }
        // 统一 request-id 合同门禁（audit_log.request_id VARCHAR(64)）：显式携带但
        // 超长/含不安全字节的 header 在任何事务副作用之前 Validation fail-closed；
        // 绝不截断、绝不静默替换（与 cancel/reject/approve 同一门禁形状）。
        let request_id_header = validated_request_operation_id(request_id_header)?;
        // 撤销操作的稳定 durable operation id：头部安全复用，否则确定性派生。
        let operation_id =
            derive_approval_revoke_operation_id(request_id, rule_id, request_id_header.as_deref())?;

        let mut tx = self.db.begin().await.map_err(db_error)?;

        // ── 锁 1：请求行 —— 只有 APPROVED 请求的贡献可以撤销 ────────────────────
        let request: Option<(i64, Option<String>, Option<String>, String)> = sqlx::query_as(
            "SELECT user_id, request_content, reason, status FROM permission_request \
             WHERE request_id=? FOR UPDATE",
        )
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        let Some((target_user_id, request_content, request_reason, status)) = request else {
            return Err(AstralError::Validation(
                "permission request does not exist".into(),
            ));
        };
        if status != "APPROVED" {
            return Err(AstralError::Validation(format!(
                "permission request {request_id} is {status:?}; only APPROVED requests have a revocable contribution"
            )));
        }

        // ── 锁 2：贡献规则行 —— provenance/effect/enabled 全部从锁定行证明 ──────
        let locked_rule: Option<LockedApprovalContributionRule> = sqlx::query_as(
            "SELECT card_id, tenant_id, effect, source_type, source_id, enabled \
             FROM permission_rule WHERE rule_id=? FOR UPDATE",
        )
        .bind(rule_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;

        let (contribution_card_id, locked_rule_tenant) = match locked_rule {
            Some(rule) => {
                // provenance：规则必须是本请求经审批插入的 ALLOW 贡献（与 approve
                // 的 source_type/source_id 写入严格对齐），禁用行/legacy DENY 行/
                // 未知 effect 一律 fail-closed，绝不把非活跃或非本请求的规则
                // 伪装成可撤销贡献。
                if rule.source_type.trim() != "PERMISSION_REQUEST" {
                    return Err(AstralError::Validation(format!(
                        "permission rule {rule_id} is not a PERMISSION_REQUEST contribution (source_type {:?})",
                        rule.source_type
                    )));
                }
                if rule.source_id != Some(request_id) {
                    return Err(AstralError::Permission(
                        "permission rule does not belong to the given permission request".into(),
                    ));
                }
                if rule.enabled.unwrap_or(1) != 1 {
                    return Err(AstralError::Validation(format!(
                        "approval contribution rule {rule_id} is disabled; refusing to revoke a non-active contribution"
                    )));
                }
                let effect = rule.effect.trim();
                if effect.eq_ignore_ascii_case("DENY") {
                    return Err(AstralError::Validation(
                        "legacy DENY rule never entered the ALLOW-only ledger; refusing to fabricate an approval revoke tombstone".into(),
                    ));
                }
                if !effect.eq_ignore_ascii_case("ALLOW") {
                    return Err(AstralError::Validation(format!(
                        "approval contribution rule {rule_id} carries unknown effect {effect:?}; refusing to revoke it as an authorization contribution"
                    )));
                }
                (rule.card_id, Some(rule.tenant_id))
            }
            None => {
                // ── 幂等 no-op 分支：贡献行已不存在 ────────────────────────────
                // 本路径的撤销把规则删除与账本 tombstone 放在同一事务（无部分提交），
                // 因此"规则缺失 + 账本 grant 头已 Removed/Revoked"可证明该贡献已被
                // 本路径（或其它 durable 撤销路径）撤销 → `Ok(false)` proven no-op。
                // 账本 grant 仍 Active 或根本没有账本记录 = source/账本漂移或
                // 未入账授权被带外删除 → 一律 fail-closed，绝不静默吞掉。
                let probe_card_id = request_content
                    .as_deref()
                    .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok())
                    .and_then(|value| value.get("cardId").and_then(serde_json::Value::as_i64))
                    .filter(|id| *id > 0)
                    .ok_or_else(|| {
                        AstralError::Validation(format!(
                            "approved permission request {request_id} has no active approval rule and its content does not identify the contribution card; refusing to silently no-op"
                        ))
                    })?;
                let probe_card = lock_contribution_card_in_tx(&mut tx, probe_card_id, request_id)
                    .await?
                    .ok_or_else(|| {
                        AstralError::Validation(format!(
                            "contribution card {probe_card_id} of approved permission request {request_id} does not belong to the request user; cannot prove the contribution identity"
                        ))
                    })?;
                let probe_facts = ApprovalRemoveLedgerFacts {
                    tenant_id: probe_card.tenant_id,
                    domain_id: probe_card.domain_id,
                    card_id: probe_card_id,
                    user_id: probe_card.user_id,
                    request_id,
                    rule_id,
                };
                let probe_grant_id = derive_approval_identity(&probe_facts)?;
                let probe_head = astral_db::read_grant_head_for_update_in_tx(
                    &mut tx,
                    probe_facts.tenant_id.unwrap_or_default(),
                    APPROVAL_AGGREGATE_TYPE,
                    request_id,
                    probe_grant_id,
                )
                .await
                .map_err(map_grant_repository_error)?;
                return match probe_head {
                    Some(head)
                        if matches!(
                            head.payload.state,
                            GrantState::Removed | GrantState::Revoked
                        ) =>
                    {
                        // 同一请求/规则/卡身份的 grant 已 durably tombstoned：
                        // 幂等 no-op，事务无任何写入（drop 即回滚）。
                        Ok(false)
                    }
                    Some(_) => Err(AstralError::Internal(format!(
                        "approval rule {rule_id} of approved request {request_id} is missing while its ledger grant is still active; source/ledger divergence requires repair"
                    ))),
                    None => Err(AstralError::Validation(format!(
                        "approved request {request_id} has no active rule {rule_id} and no durable revoke evidence in the authorization ledger; refusing to silently no-op"
                    ))),
                };
            }
        };

        // ── 锁 3：承载卡行 —— 归属（请求 user）与租户/域边界从锁定行证明；
        // 撤销是安全方向：不要求卡仍 ACTIVE/valid，但身份必须可证明。─────────
        let contribution_card =
            lock_contribution_card_in_tx(&mut tx, contribution_card_id, request_id)
                .await?
                .ok_or_else(|| {
                    AstralError::Permission(
                "approval contribution card does not belong to the request user or does not exist"
                    .into(),
            )
                })?;
        // 锁定规则行与承载卡的租户归属漂移是 source 破坏，先于任何账本写入拒绝。
        if let (Some(rule_tenant), Some(card_tenant)) =
            (locked_rule_tenant.flatten(), contribution_card.tenant_id)
        {
            if rule_tenant != card_tenant {
                return Err(AstralError::Internal(
                    "approval contribution rule tenant drifts from its locked user_card row".into(),
                ));
            }
        }

        // 账本身份 facts：全部来自锁定 source 行；tenant NULL / 非正 id 在组装期
        // fail-closed（与 approve/cascade 同一 builder 契约）。
        let facts = ApprovalRemoveLedgerFacts {
            tenant_id: contribution_card.tenant_id,
            domain_id: contribution_card.domain_id,
            card_id: contribution_card_id,
            user_id: contribution_card.user_id,
            request_id,
            rule_id,
        };
        let grant_id = derive_approval_identity(&facts)?;
        // 本贡献独立且可重放的 delta 事件号（相同操作重放同号；纯计算先于写入）。
        let contribution_event_id = derive_approval_contribution_event_id(
            &operation_id,
            &facts,
            ApprovalContributionKind::Remove,
        )?;

        // ── 锁 4：授权账本 grant head FOR UPDATE —— before-image 锚点。缺失即
        // 未入账授权，拒绝撤销（与 cascade 同一门禁），不做 raw source 假撤销。──
        let head = astral_db::read_grant_head_for_update_in_tx(
            &mut tx,
            facts.tenant_id.unwrap_or_default(),
            APPROVAL_AGGREGATE_TYPE,
            request_id,
            grant_id,
        )
        .await
        .map_err(map_grant_repository_error)?
        .ok_or_else(|| {
            AstralError::Validation(format!(
                "approval grant ledger entry missing for rule {rule_id} (request {request_id}); \
                 refusing to revoke an un-versioned authorization"
            ))
        })?;

        // ── 锁 5：delta 版本链尾 FOR UPDATE → base/target 严格推进 ─────────────
        let last_target_version = astral_db::read_latest_delta_target_version_for_update_in_tx(
            &mut tx,
            facts.tenant_id.unwrap_or_default(),
            APPROVAL_AGGREGATE_TYPE,
            request_id,
            head.grant_id,
        )
        .await
        .map_err(map_grant_repository_error)?;
        let (base_version, target_version) = astral_db::next_delta_version(last_target_version)
            .map_err(map_grant_repository_error)?;

        // ── CARD REVOKE 父投影事件（真实 reviewer actor + 稳定 operation id）；
        // 返回的 durable 事件身份（generation/fence）绑定进 tombstone 依赖向量。──
        let parent_projection = append_card_projection_with_metadata_in_tx(
            &mut tx,
            contribution_card_id,
            "REVOKE",
            astral_db::ProjectionEventMetadata {
                actor_id: reviewer_id,
                operation_id: &operation_id,
            },
        )
        .await?;

        // REMOVE tombstone：before-image/digest 由 builder 从锁定 head 成对捕获，
        // grant id/provenance(source_entry=rule, source_id=request)/租户/卡归属
        // 对齐全部在 builder 内部门禁校验；不是普通 DENY，也不删除/篡改账本行。
        let draft = build_approval_remove_draft(
            &facts,
            &head,
            &operation_id,
            &parent_projection,
            &contribution_event_id,
        )?;
        append_approval_remove_in_tx(&mut tx, &draft, base_version, target_version).await?;

        // ── source 移除：CAS 白名单删除锁定贡献行（provenance/enabled 再次约束），
        // 计数必须精确为 1，否则整个事务回滚。请求状态保持 APPROVED（Java canonical
        // 状态集无 REVOKED 值，跨运行时状态语义变化不在本仓库擅改）；撤销事实由
        // 账本 tombstone + 同事务审计承载。────────────────────────────────────
        let deleted = sqlx::query(
            "DELETE FROM permission_rule \
             WHERE rule_id=? AND enabled=1 AND source_type='PERMISSION_REQUEST' AND source_id=?",
        )
        .bind(rule_id)
        .bind(request_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        if deleted.rows_affected() != 1 {
            return Err(AstralError::Internal(format!(
                "approval contribution delete touched {0} rows for rule {rule_id} while holding its lock",
                deleted.rows_affected()
            )));
        }

        // ── 审批审计（同事务）：action=revoke / decision=REVOKED（非普通 DENY），
        // 与账本/投影共享同一稳定 operation id 关联。──────────────────────────
        let context = ApprovalAuditContext::new(request_id_header.as_deref(), request_id);
        insert_approval_audit_in_tx(
            &mut tx,
            &ApprovalAuditEntry {
                actor_id: reviewer_id,
                reviewer_id: Some(reviewer_id),
                target_user_id,
                target_card_id: Some(contribution_card_id),
                action: "revoke",
                decision: "REVOKED",
                request_reason: request_reason.as_deref(),
                reviewer_comment: comment,
                context: &context,
            },
        )
        .await?;

        // commit 是唯一终态出口：之前任一步失败整体回滚，不存在部分提交。
        tx.commit().await.map_err(db_error)?;
        Ok(true)
    }

    async fn approve_with_rule(
        &self,
        request_id: i64,
        reviewer_id: i64,
        comment: Option<&str>,
        card_id: i64,
        resource: &str,
        action: &str,
        effect: &str,
        priority: i32,
        condition_json: Option<&str>,
        valid_from: Option<&str>,
        valid_to: Option<&str>,
        request_id_header: Option<&str>,
    ) -> Result<(), AstralError> {
        // 防御加固：repository 不是校验旁路。审批落库的 canonical grant 只接受
        // ALLOW，校验先于任何事务副作用（失败即无 source/outbox/audit 写入）。
        // canonical 合同无 condition 槽位：非空条件授权无法被无条件 ALLOW 忠实
        // 表达，任何副作用开始前 Validation fail-closed，不静默丢弃条件。
        let effect = crate::service::validate_canonical_grant_effect(effect)?;
        reject_unrepresentable_condition(condition_json, "approval approve_with_rule")?;
        // 防御加固：未注册资源/动作、空白值在任何事务副作用之前 Validation
        // fail-closed。返回归一化（trim）后的二元组，permission_rule INSERT 与
        // 授权账本 ADD 必须写入同一规范化值，消除 raw/trim 漂移。
        let (resource, action) =
            crate::service::personal_permission_service::validate_registry_resource_action(
                resource, action,
            )?;
        // 业务身份从稳定 request context 派生一次（不生成随机业务 identity）；
        // 失败发生在任何事务副作用之前。
        let operation_id = derive_approval_operation_id(request_id_header, request_id)?;
        let mut tx = self.db.begin().await.map_err(db_error)?;

        let target_card: Option<(i64,)> = sqlx::query_as(
            "SELECT uc.card_id FROM user_card uc \
             INNER JOIN permission_request pr ON pr.user_id = uc.user_id \
             WHERE pr.request_id = ? AND uc.card_id = ? AND uc.card_status = 'ACTIVE' \
               AND (uc.valid_from IS NULL OR uc.valid_from <= NOW()) \
               AND (uc.valid_until IS NULL OR uc.valid_until >= NOW()) FOR UPDATE",
        )
        .bind(request_id)
        .bind(card_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        if target_card.is_none() {
            return Err(AstralError::Permission(
                "approval target card does not belong to request user or is inactive".into(),
            ));
        }

        let result = sqlx::query(
            "UPDATE permission_request SET status='APPROVED', approver_id=?, approved_at=NOW(), approve_comment=? \
             WHERE request_id=? AND status='PENDING'",
        )
        .bind(reviewer_id)
        .bind(comment)
        .bind(request_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Validation(
                "permission request is no longer pending".into(),
            ));
        }

        // permission request 规则必须保留来源，便于撤销、审计和幂等治理。
        // tenant/domain 归属从锁定的目标卡行读取（对齐 Java：规则携带卡片租户）；
        // 租户为空时授权账本组装会 fail-closed，本条 source insert 不做假值回填。
        let (card_tenant_id, domain_id): (Option<i64>, Option<i64>) = sqlx::query_as(
            "SELECT uc.tenant_id, uc.domain_id FROM user_card uc WHERE uc.card_id = ? FOR UPDATE",
        )
        .bind(card_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?
        .ok_or_else(|| {
            AstralError::Permission("approval target card vanished during approval".into())
        })?;
        let rule_insert = sqlx::query(
            "INSERT INTO permission_rule (card_id, tenant_id, effect, resource_type, action_code, condition_json, priority, valid_from, valid_to, source_type, source_id, enabled) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PERMISSION_REQUEST', ?, 1)",
        )
        .bind(card_id)
        .bind(card_tenant_id)
        .bind(&effect)
        // 规范化（trim）值与授权账本 ADD 同源，杜绝 raw/trim 漂移。
        .bind(&resource)
        .bind(&action)
        .bind(condition_json)
        .bind(priority)
        .bind(valid_from)
        .bind(valid_to)
        .bind(request_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        if rule_insert.rows_affected() != 1 {
            return Err(AstralError::Internal(
                "permission_rule approval insert did not apply exactly one row".into(),
            ));
        }
        // 稳定 rule_id 即本审批贡献的 source_entry；账本 grant id 与后续撤销都依赖它。
        let rule_id = i64::try_from(rule_insert.last_insert_id())
            .ok()
            .filter(|id| *id > 0)
            .ok_or_else(|| {
                AstralError::Internal("permission_rule insert returned an unusable rule id".into())
            })?;

        // CARD APPROVED 投影事件携带真实 reviewer actor 与稳定 operation_id，并保留
        // durable 身份（event/generation/fence）供授权账本 delta 绑定；旧的丢身份
        // helper 不再用于这条路径。
        let projection = append_card_projection_with_metadata_in_tx(
            &mut tx,
            card_id,
            "APPROVED",
            astral_db::ProjectionEventMetadata {
                actor_id: reviewer_id,
                operation_id: &operation_id,
            },
        )
        .await?;

        let (target_user_id, request_reason): (i64, Option<String>) =
            sqlx::query_as("SELECT user_id, reason FROM permission_request WHERE request_id=?")
                .bind(request_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(db_error)?;
        let context = crate::repository::audit_log_repository::ApprovalAuditContext::new(
            request_id_header,
            request_id,
        );
        crate::repository::audit_log_repository::insert_approval_audit_in_tx(
            &mut tx,
            &crate::repository::audit_log_repository::ApprovalAuditEntry {
                actor_id: reviewer_id,
                reviewer_id: Some(reviewer_id),
                target_user_id,
                target_card_id: Some(card_id),
                action: "approve",
                decision: "APPROVED",
                request_reason: request_reason.as_deref(),
                reviewer_comment: comment,
                context: &context,
            },
        )
        .await?;

        // 同一事务内把 APPROVAL ALLOW 贡献追加进授权账本：
        // authorization_grant_revision（revision 1 Add）+ authorization_delta_event。
        // 任一失败向上传播并使整个事务回滚（含规则/状态/audit/outbox 写入）；
        // 不吞错、不降级只写旧链，也不把 ACK/APPROVED 当作新投影 READY。
        append_approval_grant_in_tx(
            &mut tx,
            &ApprovalGrantLedgerContext {
                user_card_tenant_id: card_tenant_id,
                domain_id,
                card_id,
                user_id: target_user_id,
                request_id,
                reviewer_id,
                rule_id,
                // 与 permission_rule INSERT 同一规范化（trim）值。
                resource: &resource,
                // RULE request_content（deny_unknown_fields）无法携带 resource id：
                // 显式 None → canonical 资源为显式类型级通配 `type:*`。
                resource_id: None,
                action: &action,
                condition_json,
                valid_from,
                valid_to,
                operation_id: &operation_id,
            },
            &projection,
        )
        .await?;

        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn reject_request(
        &self,
        request_id: i64,
        reviewer_id: i64,
        comment: Option<&str>,
        request_id_header: Option<&str>,
    ) -> Result<(), AstralError> {
        // PENDING 守卫：已 approve（规则已插入、projection 已落）的请求不得再被
        // reject 翻状态，否则请求状态与权限规则不一致（对齐 approve 的并发防护）。
        // 统一 request-id 合同门禁：显式携带但超长/含不安全字节的 header 在任何
        // 事务副作用之前 Validation fail-closed —— 绝不允许 65+ 字节值进入
        // `audit_log.request_id` VARCHAR(64) 造成截断或写失败，也绝不静默替换。
        // 缺失/空白 header 维持既有稳定 fallback（approval:{request_id}），
        // 不产生随机或超长审计关联值。失败时事务未开始，无任何副作用。
        let request_id_header = validated_request_operation_id(request_id_header)?;
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let request: Option<(i64, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT user_id, request_content, reason FROM permission_request \
             WHERE request_id=? AND status='PENDING' FOR UPDATE",
        )
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        let Some((target_user_id, request_content, request_reason)) = request else {
            return Err(AstralError::Validation(
                "permission request is no longer pending".into(),
            ));
        };
        let target_card_id = request_content
            .as_deref()
            .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok())
            .and_then(|value| value.get("cardId").and_then(serde_json::Value::as_i64));

        let result = sqlx::query(
            "UPDATE permission_request SET status='REJECTED', approver_id=?, approve_comment=? \
             WHERE request_id=? AND status='PENDING'",
        )
        .bind(reviewer_id)
        .bind(comment)
        .bind(request_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Validation(
                "permission request is no longer pending".into(),
            ));
        }

        let context = crate::repository::audit_log_repository::ApprovalAuditContext::new(
            request_id_header.as_deref(),
            request_id,
        );
        crate::repository::audit_log_repository::insert_approval_audit_in_tx(
            &mut tx,
            &crate::repository::audit_log_repository::ApprovalAuditEntry {
                actor_id: reviewer_id,
                reviewer_id: Some(reviewer_id),
                target_user_id,
                target_card_id,
                action: "reject",
                decision: "REJECTED",
                request_reason: request_reason.as_deref(),
                reviewer_comment: comment,
                context: &context,
            },
        )
        .await?;
        tx.commit().await.map_err(db_error)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!(
        "Permission request repository query failed: {error}"
    ))
}

#[cfg(test)]
mod approval_ledger_shape_tests {
    use crate::repository::audit_log_repository::validated_request_operation_id;
    use crate::repository::grant_ledger_adapter::{
        derive_approval_operation_id, MAX_HEADER_OPERATION_ID_LENGTH,
    };
    use crate::repository::permission_request_repository::derive_approval_revoke_operation_id;

    /// SQL 实现块的锚点：只在其后扫描方法体，避免测试源码自引用污染。
    const IMPL_ANCHOR: &str =
        "impl PermissionRequestRepository for SqlxPermissionRequestRepository";

    fn method_body<'a>(source: &'a str, signature: &str, terminator: &str, label: &str) -> &'a str {
        let after_impl = source
            .split(IMPL_ANCHOR)
            .nth(1)
            .expect("sqlx repository implementation must exist");
        let start = after_impl
            .find(signature)
            .unwrap_or_else(|| panic!("{label} signature `{signature}` must exist"));
        let rest = &after_impl[start..];
        let end = rest
            .find(terminator)
            .unwrap_or_else(|| panic!("{label} terminator `{terminator}` must exist"));
        &rest[..end]
    }

    /// 审批事务内的写入顺序与护栏（include_str! 结构断言，不连 DB）：
    /// 锁卡 → CAS APPROVED → 规则 INSERT（affected_rows + last_insert_id 校验）
    /// → CARD APPROVED 投影事件（真实 reviewer actor + 稳定 operation_id）
    /// → 审批 audit → 授权账本追加 → commit。
    #[test]
    fn approve_transaction_order_and_guards_are_pinned() {
        let source = include_str!("permission_request_repository.rs");
        let body = method_body(
            source,
            "async fn approve_with_rule(",
            "async fn reject_request(",
            "approve_with_rule",
        );

        let markers = [
            ("card lock", "FOR UPDATE"),
            ("CAS update", "status='APPROVED'"),
            ("CAS guard", "rows_affected() != 1"),
            ("rule insert", "INSERT INTO permission_rule"),
            ("rule affected guard", "rule_insert.rows_affected() != 1"),
            ("rule id guard", "last_insert_id()"),
            (
                "projection metadata call",
                "append_card_projection_with_metadata_in_tx",
            ),
            ("reviewer actor bound", "actor_id: reviewer_id"),
            ("operation id bound", "operation_id: &operation_id"),
            ("approval audit", "insert_approval_audit_in_tx"),
            ("grant ledger append", "append_approval_grant_in_tx"),
            ("commit last", "tx.commit()"),
        ];
        let commit_position = body.rfind("tx.commit()").expect("commit must exist");
        let mut previous = 0;
        for (label, marker) in markers {
            let position = body
                .find(marker)
                .unwrap_or_else(|| panic!("{label} marker `{marker}` must exist in approve tx"));
            assert!(
                position >= previous,
                "{label} must appear in order at or after offset {previous}"
            );
            // rollback guard：commit 只能是最后一步，之前的任何 marker 都不得越过它。
            if label != "commit last" {
                assert!(
                    position < commit_position,
                    "{label} must stay before the final commit"
                );
            }
            previous = position;
        }
    }

    /// 复核：拒绝旧丢身份 helper 出现在审批事务中。
    #[test]
    fn identity_dropping_card_projection_helper_is_not_used_in_approve_path() {
        let source = include_str!("permission_request_repository.rs");
        let body = method_body(
            source,
            "async fn approve_with_rule(",
            "async fn reject_request(",
            "approve_with_rule",
        );
        assert!(
            !body.contains("append_card_projection_in_tx"),
            "approval must use the metadata-returning projection writer"
        );
    }

    /// approve 事务前的 ResourceRegistry 门禁与规范化值同源（include_str! 结构
    /// 断言，不连 DB）：未注册资源/动作、空白值在任何事务副作用之前 Validation
    /// fail-closed；permission_rule INSERT 与授权账本 ADD 必须绑定同一归一化
    /// （trim）二元组，消除 raw/trim 漂移；全程禁止任何截断手段。
    #[test]
    fn approve_validates_registry_before_the_transaction_and_binds_one_normalized_pair() {
        let source = include_str!("permission_request_repository.rs");
        let body = method_body(
            source,
            "async fn approve_with_rule(",
            "async fn reject_request(",
            "approve_with_rule",
        );
        let validation = body
            .find("validate_registry_resource_action(")
            .expect("approve must gate resource/action through the shared registry validator");
        let begin = body
            .find("self.db.begin()")
            .expect("transaction begin must exist");
        assert!(
            validation < begin,
            "registry validation must fail closed before opening the transaction"
        );
        // 同一规范化值写入 permission_rule INSERT 与授权账本 ADD。
        let rule_bind = body
            .find(".bind(&resource)")
            .expect("rule insert must bind the normalized resource");
        let rule_action_bind = body
            .find(".bind(&action)")
            .expect("rule insert must bind the normalized action");
        let ledger_resource = body
            .find("resource: &resource")
            .expect("ledger ADD must receive the same normalized resource");
        let ledger_action = body
            .find("action: &action")
            .expect("ledger ADD must receive the same normalized action");
        assert!(validation < rule_bind && validation < rule_action_bind);
        assert!(validation < ledger_resource && validation < ledger_action);
        assert!(
            !body.contains(".truncate(") && !body.contains("chars().take("),
            "approval must never truncate resource/action values"
        );
    }

    /// 取消/驳回语义不受影响：两者都不含规则 INSERT、授权账本或 APPROVED 写入。
    #[test]
    fn cancel_and_reject_paths_do_not_touch_the_grant_ledger() {
        let source = include_str!("permission_request_repository.rs");
        let bodies = [
            (
                method_body(
                    source,
                    "async fn cancel_request(",
                    "async fn count_pending(",
                    "cancel_request",
                ),
                "cancel",
            ),
            (
                method_body(
                    source,
                    "async fn reject_request(",
                    "fn db_error",
                    "reject_request",
                ),
                "reject",
            ),
        ];

        for (body, label) in bodies {
            assert!(
                !body.contains("append_approval_grant_in_tx"),
                "{label} path must not write the authorization ledger"
            );
            assert!(
                !body.contains("INSERT INTO permission_rule"),
                "{label} path must not write permission rules"
            );
            assert!(
                !body.contains("GrantDelta") && !body.contains("'APPROVED'"),
                "{label} path must not carry grant deltas or approve semantics"
            );
        }
    }

    /// 取消/驳回必须先过统一 request-id 合同门禁再开事务：显式超长/不安全
    /// header 在任何副作用之前 Validation fail-closed；审计上下文只接收已校验值
    /// （或既有稳定 fallback 输入），且全程不允许出现任何截断手段。
    #[test]
    fn cancel_and_reject_validate_request_header_before_the_transaction() {
        let source = include_str!("permission_request_repository.rs");
        let bodies = [
            (
                method_body(
                    source,
                    "async fn cancel_request(",
                    "async fn count_pending(",
                    "cancel_request",
                ),
                "cancel",
            ),
            (
                method_body(
                    source,
                    "async fn reject_request(",
                    "fn db_error",
                    "reject_request",
                ),
                "reject",
            ),
        ];
        for (body, label) in bodies {
            let validation = body
                .find("validated_request_operation_id(request_id_header)")
                .unwrap_or_else(|| {
                    panic!("{label} must gate its header through the shared request-id contract")
                });
            let begin = body
                .find("self.db.begin()")
                .expect("transaction begin must exist");
            assert!(
                validation < begin,
                "{label} must fail closed on unsafe/oversized headers before opening the transaction"
            );
            let context_feed = body
                .find("request_id_header.as_deref()")
                .unwrap_or_else(|| {
                    panic!("{label} must feed the validated header into the audit context")
                });
            assert!(validation < context_feed);
            // 统一 64 字节合同禁止截断消化：不允许任何截断/切片手段。
            for forbidden in [".truncate(", "&header[..64]", "chars().take("] {
                assert!(
                    !body.contains(forbidden),
                    "{label} must never truncate the request-id header ({forbidden})"
                );
            }
        }
    }

    /// 统一 64 字节边界（纯测试）：与授权账本适配器共享同一上限常量；64 字节
    /// 原样放行、65 字节 Validation fail-closed；缺失/空白回退 Ok(None)，由调用方
    /// 走既有稳定 fallback（approval:{request_id}）—— 随机/超长值绝不进入
    /// audit_log.request_id VARCHAR(64)。
    #[test]
    fn unified_request_operation_id_gate_enforces_the_64_byte_boundary() {
        const MAX: usize = crate::repository::audit_log_repository::MAX_REQUEST_OPERATION_ID_LENGTH;
        let ok = "a".repeat(MAX);
        assert_eq!(
            validated_request_operation_id(Some(ok.as_str())).unwrap(),
            Some(ok.clone())
        );
        let too_long = format!("{ok}!");
        assert_eq!(too_long.len(), MAX + 1);
        assert!(matches!(
            validated_request_operation_id(Some(too_long.as_str())),
            Err(astral_types::AstralError::Validation(_))
        ));
        // 不安全字节同样 fail-closed（与本仓库 approve 路径同一门禁形状）。
        assert!(matches!(
            validated_request_operation_id(Some("bad id\nwith control")),
            Err(astral_types::AstralError::Validation(_))
        ));
        // 缺失/空白 → Ok(None)：无随机值、无超长内容可写。
        assert_eq!(validated_request_operation_id(None).unwrap(), None);
        assert_eq!(validated_request_operation_id(Some("   ")).unwrap(), None);
    }

    /// 审批后撤销（revoke）的事务写入顺序与护栏（include_str! 结构断言，不连 DB）：
    /// 锁请求（APPROVED 守卫）→ 锁规则（provenance/enabled/ALLOW 门禁）→ 锁承载卡
    /// （归属 join + 租户漂移守卫）→ 账本身份/贡献事件号纯派生 → grant head
    /// FOR UPDATE → delta 版本链尾 FOR UPDATE → CARD REVOKE 父投影（reviewer
    /// actor + 稳定 operation id）→ REMOVE tombstone（before-image 成对落库）
    /// → CAS 贡献行删除 → 审批审计 → commit。
    #[test]
    fn revoke_transaction_order_and_guards_are_pinned() {
        let source = include_str!("permission_request_repository.rs");
        let body = method_body(
            source,
            "async fn revoke_approved_contribution(",
            "async fn approve_with_rule(",
            "revoke_approved_contribution",
        );

        let markers = [
            ("request lock", "WHERE request_id=? FOR UPDATE"),
            ("approved guard", "!= \"APPROVED\""),
            (
                "provenance guard",
                "source_type.trim() != \"PERMISSION_REQUEST\"",
            ),
            ("active guard", "enabled.unwrap_or(1) != 1"),
            ("allow-only guard", "eq_ignore_ascii_case(\"ALLOW\")"),
            (
                "card ownership lock",
                "lock_contribution_card_in_tx(&mut tx, contribution_card_id, request_id)",
            ),
            ("tenant drift guard", "drifts from its locked user_card row"),
            (
                "contribution event id",
                "derive_approval_contribution_event_id",
            ),
            (
                "grant head lock",
                "let head = astral_db::read_grant_head_for_update_in_tx(",
            ),
            (
                "un-versioned guard",
                "refusing to revoke an un-versioned authorization",
            ),
            (
                "delta version lock",
                "read_latest_delta_target_version_for_update_in_tx",
            ),
            (
                "card revoke parent",
                "append_card_projection_with_metadata_in_tx",
            ),
            ("revoke event type", "\"REVOKE\""),
            ("reviewer actor bound", "actor_id: reviewer_id"),
            ("operation id bound", "operation_id: &operation_id"),
            ("remove tombstone", "build_approval_remove_draft"),
            ("remove append", "append_approval_remove_in_tx"),
            ("cas source delete", "WHERE rule_id=? AND enabled=1"),
            ("approval audit", "insert_approval_audit_in_tx("),
            ("revoke decision", "decision: \"REVOKED\""),
            ("commit last", "tx.commit()"),
        ];
        let commit_position = body.rfind("tx.commit()").expect("commit must exist");
        let mut previous = 0;
        for (label, marker) in markers {
            let position = body
                .find(marker)
                .unwrap_or_else(|| panic!("{label} marker `{marker}` must exist in revoke tx"));
            assert!(
                position >= previous,
                "{label} must appear in order at or after offset {previous}"
            );
            if label != "commit last" {
                assert!(
                    position < commit_position,
                    "{label} must stay before the final commit"
                );
            }
            previous = position;
        }
        // 承载卡归属证明 SQL 在模块级 helper 中：卡必须属于请求 user。
        assert!(
            source.contains("INNER JOIN permission_request pr ON pr.user_id = uc.user_id"),
            "contribution card lock must prove request-user ownership via the source join"
        );
    }

    /// 幂等 no-op 分支：贡献行缺失时必须先用稳定身份读账本 grant 头证明
    /// Removed/Revoked 才允许 `Ok(false)`；账本 Active 或无账本记录一律
    /// fail-closed（divergence/repair 提示），且 no-op 返回位于一切 durable
    /// 写入调用（投影/账本/删除/审计）之前。
    #[test]
    fn revoke_absent_contribution_is_proven_noop_or_fail_closed() {
        let source = include_str!("permission_request_repository.rs");
        let body = method_body(
            source,
            "async fn revoke_approved_contribution(",
            "async fn approve_with_rule(",
            "revoke_approved_contribution",
        );

        // `Ok(false)` 的代码级 return（rfind 跳过分支注释里的文字提及）。
        let noop_return = body
            .rfind("Ok(false)")
            .expect("absent-contribution probe must return Ok(false)");
        let probe_head = body
            .find("read_grant_head_for_update_in_tx")
            .expect("probe must anchor on the ledger grant head");
        assert!(
            probe_head < noop_return,
            "no-op success must be proven by the ledger grant head read"
        );
        for marker in ["GrantState::Removed", "GrantState::Revoked"] {
            let position = body
                .find(marker)
                .unwrap_or_else(|| panic!("probe must match tombstone state {marker}"));
            assert!(
                position < noop_return,
                "{marker} must gate the no-op return"
            );
        }
        // 无法证明的两种状态显式 fail-closed，绝不静默吞掉。
        assert!(body.contains("source/ledger divergence requires repair"));
        assert!(body.contains("refusing to silently no-op"));
        // no-op 返回先于任何 durable 写入：投影/账本 tombstone/删除/审计都更晚。
        for write in [
            "append_card_projection_with_metadata_in_tx",
            "build_approval_remove_draft",
            "append_approval_remove_in_tx",
            "DELETE FROM permission_rule",
            "insert_approval_audit_in_tx(",
        ] {
            let position = body
                .find(write)
                .unwrap_or_else(|| panic!("main path write `{write}` must exist"));
            assert!(
                noop_return < position,
                "no-op return must precede the first durable write marker `{write}`"
            );
        }
    }

    /// 撤销门禁先于事务：reviewer/主键正数门禁与统一 64 字节 request-id 合同
    /// 都在任何 `self.db.begin()` 之前 fail-closed；稳定 operation id 亦在事务前
    /// 派生；全程不允许任何截断手段。
    #[test]
    fn revoke_gates_identity_and_header_before_the_transaction() {
        let source = include_str!("permission_request_repository.rs");
        let body = method_body(
            source,
            "async fn revoke_approved_contribution(",
            "async fn approve_with_rule(",
            "revoke_approved_contribution",
        );
        let begin = body
            .find("self.db.begin()")
            .expect("transaction begin must exist");
        for gate in [
            "reviewer_id <= 0",
            "request_id <= 0 || rule_id <= 0",
            "validated_request_operation_id(request_id_header)",
            "derive_approval_revoke_operation_id(",
        ] {
            let position = body.find(gate).unwrap_or_else(|| {
                panic!("revoke gate `{gate}` must exist before the transaction")
            });
            assert!(
                position < begin,
                "revoke gate `{gate}` must fail closed before opening the transaction"
            );
        }
        // 统一 64 字节合同禁止截断消化（与 cancel/reject 同一条断言形状）。
        for forbidden in [".truncate(", "&header[..64]", "chars().take("] {
            assert!(
                !body.contains(forbidden),
                "revoke must never truncate the request-id header ({forbidden})"
            );
        }
    }

    /// 撤销 operation id 纯派生契约：缺失 header → 确定性
    /// `approval:revoke:{request_id}:rule:{rule_id}`（与 approve 的
    /// `approval:{request_id}` 域分离）；安全 header 原样复用；非法/超长/空白
    /// header 与非正 id 一律 Validation fail-closed，绝无随机或截断回退。
    #[test]
    fn revoke_operation_id_is_deterministic_domain_separated_and_fail_closed() {
        let fallback = derive_approval_revoke_operation_id(5, 9, None).unwrap();
        assert_eq!(fallback, "approval:revoke:5:rule:9");
        assert_ne!(
            fallback,
            derive_approval_operation_id(None, 5).unwrap(),
            "revoke fallback must be domain-separated from the approve fallback"
        );
        // 确定性重放：相同输入同号。
        assert_eq!(
            derive_approval_revoke_operation_id(5, 9, None).unwrap(),
            fallback
        );
        // 安全 header 原样复用（与 approve/direct/delegation 同一门禁）。
        assert_eq!(
            derive_approval_revoke_operation_id(5, 9, Some("req-42")).unwrap(),
            "req-42"
        );
        // 非法字符 / 超长 / 空白 header 一律 fail-closed（空白应在上游
        // validated_request_operation_id 归一为 None，这里防御性拒绝）。
        assert!(matches!(
            derive_approval_revoke_operation_id(5, 9, Some("bad id\nwith control")),
            Err(astral_types::AstralError::Validation(_))
        ));
        let too_long = "h".repeat(MAX_HEADER_OPERATION_ID_LENGTH + 1);
        assert!(matches!(
            derive_approval_revoke_operation_id(5, 9, Some(too_long.as_str())),
            Err(astral_types::AstralError::Validation(_))
        ));
        assert!(matches!(
            derive_approval_revoke_operation_id(5, 9, Some("   ")),
            Err(astral_types::AstralError::Validation(_))
        ));
        // 非正主键不可作身份维度。
        assert!(matches!(
            derive_approval_revoke_operation_id(0, 9, None),
            Err(astral_types::AstralError::Validation(_))
        ));
        assert!(matches!(
            derive_approval_revoke_operation_id(5, 0, None),
            Err(astral_types::AstralError::Validation(_))
        ));
    }

    /// trait 默认实现显式 NotImplemented fail-closed：未支持该生命周期的
    /// repository（含测试替身）绝不允许静默伪造撤销结果。
    #[test]
    fn trait_default_revoke_is_explicitly_fail_closed() {
        let source = include_str!("permission_request_repository.rs");
        let trait_part = source
            .split("impl PermissionRequestRepository for SqlxPermissionRequestRepository")
            .next()
            .expect("trait declaration must exist before the sqlx impl");
        assert!(
            trait_part.contains("async fn revoke_approved_contribution("),
            "trait must declare the revoke lifecycle"
        );
        let default_body = trait_part
            .split("async fn revoke_approved_contribution(")
            .nth(1)
            .expect("default body must follow the signature");
        assert!(
            default_body.contains("AstralError::NotImplemented("),
            "trait default must fail closed with NotImplemented"
        );
        assert!(
            !default_body.contains("Ok(true)") && !default_body.contains("Ok(false)"),
            "trait default must never fake a revoke outcome"
        );
    }
}
