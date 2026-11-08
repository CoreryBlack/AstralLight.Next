//! 权限继承配置数据访问 — InheritanceConfigRepository
//!
//! 对齐 Java `PermissionInheritanceConfigMapper` 边界（permission_inheritance_config 表）。
//!
//! ## 授权源事务（admission-hosted source mutation）
//!
//! `permission_inheritance_config` 是受管理员维护的配置事实。当前仓库 Rust
//! consumer trace 仅发现本仓 API/管理处理路径，没有当前 PolicyEngine、资格
//! 投影或授权解析 consumer；本配置不会制造 grant delta，也不会借升级本文件
//! 引入虚构 fan-out。本文件全部 mutation（upsert/delete）以
//! `AuthorizationSourceTransaction` 为宿主——复用 canonical
//! `begin_source_transaction_with_capability` / `commit_consuming`，不在本文件
//! 发明第二套事务/栅栏基础设施：
//! - `begin` 在 DB begin 之前取得 hub 源活动栅栏（hub 已安装而拒发证即在开启
//!   事务**之前** fail-closed，绝不留下无栅栏 writer）；`UserPending`（缺失
//!   admission）在 begin 即被拒绝；
//! - commit 前 canonical wrapper 完成 durable authority 对牌
//!   （`validate_authorization_admission_in_tx`）与 admission `consume_once`，
//!   之后才 arm 栅栏并 await COMMIT；只有 proven commit 返回成功；
//! - commit 未知/失败 → 栅栏 sticky uncertain、receipts 空集，绝不投递、绝不
//!   重放（UNKNOWN fail-closed）。
//!
//! 事务内按固定锁序先锁定 actor 卡行（user/tenant/domain/ACTIVE 复核 +
//! admission proof scope 对牌，与 departments/levels 同一形状），再锁定目标
//! resource_type 行（FOR UPDATE 行锁序列化并发 mutation）。upsert 与查回在
//! **同一事务**内原子完成（insert/upsert + reselect），响应行绝不依赖第二
//! 连接的事务外读取。
//!
//! ## V7 配置完成证据（不虚构 eligibility fanout）
//!
//! 该表目前没有已验证的有效授权/eligibility consumer，因而不追加授权 delta；
//! admission-backed mutation 仍必须经 ConfigCompletion 提交真实 before/after
//! 行镜像与同事务 audit receipt。consumer 缺失不豁免 durable source outcome，
//! 也不把当前/旧授权投影当作配置完成证据。
//! 遗留无 context mutation 方法一律 fail-closed（`inheritance_context_required`），
//! 无内部 system 旁路。`ResourceRegistry` 的注册资源类型校验属于进程内编排，
//! 由 HTTP handler 在**开启 source 事务之前**完成（本文件不依赖注册表）。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_db::grant_ledger::validated_request_operation_id;
use astral_types::{
    AstralError, AuthorizationAdmission, AuthorizationAuthorityScope, AuthorizationDomainScope,
    PolicyContext,
};

use crate::repository::authorization_source_transaction::{
    begin_source_transaction_with_capability, AuthorizationSourceTransaction,
    SourceMutationCapability,
};
use astral_db::{TypedRowOperation, TypedSourceRowLookup, TypedSourceTable};

/// 继承配置记录
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct InheritanceConfigRecord {
    pub id: i64,
    pub resource_type: String,
    pub inheritance_mode: String,
    pub updated_at: Option<i64>,
}

const INHERIT_SELECT_COLUMNS: &str = "id, resource_type, inheritance_mode, \
     UNIX_TIMESTAMP(updated_at) as updated_at";

// ===== mutation context =====

/// Gateway-verified identity and scope carried into one TrustGraph inheritance mutation.
///
/// 与 departments/levels 同一装配合同：身份只能来自 TrustGraph permission
/// 中间件安装的已验证 `PolicyContext`；Gateway 头不是授权来源，只允许在 API
/// 层与该 context 完全一致后使用。`request_id` 必须携带且通过统一持久化安全
/// 性校验（`validated_request_operation_id`）；缺失/纯空白/超长/非法字符一律
/// fail-closed，绝不静默替换、截断或随机补位。`source_capability` 初始为
/// `UserPending`，只有 `.with_admission(...)` 注入 proof-bound admission 后
/// 才允许开启用户 source 事务。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InheritanceMutationContext {
    actor_id: i64,
    actor_card_id: i64,
    actor_tenant_id: i64,
    actor_domain_id: i64,
    request_id: String,
    source_capability: SourceMutationCapability,
}

impl InheritanceMutationContext {
    /// Create only from the verified PolicyContext installed by TrustGraph permission middleware.
    pub(crate) fn from_policy_context(
        context: &PolicyContext,
        request_id: Option<&str>,
    ) -> Result<Self, AstralError> {
        if context.principal_kind.as_deref() != Some("PLATFORM_USER") {
            return Err(AstralError::Auth(
                "inheritance mutation requires a Gateway-verified platform user context".into(),
            ));
        }
        let actor_id = positive_context_id(context.user_id, "user_id")?;
        let actor_card_id = positive_context_id(context.card_id, "card_id")?;
        let actor_tenant_id = positive_context_id(context.tenant_id, "tenant_id")?;
        let actor_domain_id = positive_context_id(context.domain_id, "domain_id")?;
        let request_id = validated_request_operation_id(request_id)?.ok_or_else(|| {
            AstralError::Auth("inheritance mutation requires a canonical request id".into())
        })?;
        Ok(Self {
            actor_id,
            actor_card_id,
            actor_tenant_id,
            actor_domain_id,
            request_id,
            source_capability: SourceMutationCapability::UserPending,
        })
    }

    pub fn with_admission(mut self, admission: AuthorizationAdmission) -> Self {
        self.source_capability = SourceMutationCapability::user(admission);
        self
    }

    pub(crate) fn source_capability(&self) -> &SourceMutationCapability {
        &self.source_capability
    }

    fn request_id(&self) -> &str {
        &self.request_id
    }
}

fn positive_context_id(value: Option<i64>, name: &str) -> Result<i64, AstralError> {
    value.filter(|value| *value > 0).ok_or_else(|| {
        AstralError::Auth(format!("inheritance mutation requires a positive {name}"))
    })
}

fn inheritance_context_required() -> AstralError {
    AstralError::Auth(
        "inheritance config mutation requires Gateway-verified user-card context".into(),
    )
}

// ===== SQL 常量 =====

/// admission caller 卡行锁：把 admission scope 绑定到锁定的 user_card 行
/// （user/tenant/domain/ACTIVE 复核），与 departments/levels 同一形状。所有
/// 继承配置 mutation 的第一把锁，跨 upsert/delete 保持同一锁序避免死锁。
const INHERITANCE_MUTATION_ACTOR_LOCK_SQL: &str =
    "SELECT user_id, tenant_id, domain_id, card_status \
     FROM user_card WHERE card_id = ? FOR UPDATE";
/// 目标 resource_type 行锁：锁定读证明存在性并序列化并发 upsert/delete
/// （参数化 SQL；`idx_pic_resource_type` UNIQUE 由 DB 兜底）。
const INHERITANCE_ROW_LOCK_SQL: &str =
    "SELECT id FROM permission_inheritance_config WHERE resource_type = ? FOR UPDATE";
/// 审计关联 INSERT（仅绑定参数 + 固定常量；所有可变输入走 `?` 绑定，
/// 绝不拼接请求输入）。decision 按固定 mutation 语义常量绑定。
const INHERITANCE_MUTATION_AUDIT_INSERT_SQL: &str = "INSERT INTO audit_log \
     (user_id, card_id, action, resource, decision, reason, event_type, request_id, domain_id, tenant_id, detail) \
     VALUES (?, ?, ?, ?, 'SUCCESS', NULL, 'TRUSTGRAPH_INHERITANCE_MUTATION', ?, ?, ?, ?)";

/// `audit_log.event_type`（VARCHAR(32)）：继承配置 mutation 家族标记。
const INHERITANCE_AUDIT_EVENT_TYPE: &str = "TRUSTGRAPH_INHERITANCE_MUTATION";
/// `audit_log.resource`：继承配置聚合（permission_inheritance_config 表）。
const INHERITANCE_AUDIT_RESOURCE: &str = "permission_inheritance_config";

/// 纯校验：admission proof scope 必须与锁定的 actor 卡行完全一致
/// （tenant/card/user/domain）。域要求是显式 `Exact`，`Any`/`NoDomain`
/// 一律不匹配 —— 绝不放宽。任何不一致都是 Permission fail-closed。
fn ensure_inheritance_actor_scope_matches(
    scope: &AuthorizationAuthorityScope,
    actor_card_id: i64,
    user_id: i64,
    tenant_id: i64,
    domain_id: i64,
) -> Result<(), AstralError> {
    let domain_matches = matches!(
        scope.domain,
        AuthorizationDomainScope::Exact(value) if value == domain_id
    );
    if scope.tenant_id != tenant_id
        || scope.card_id != actor_card_id
        || scope.user_id != Some(user_id)
        || !domain_matches
    {
        return Err(AstralError::Permission(
            "authorization admission scope does not match the locked inheritance mutation actor card"
                .into(),
        ));
    }
    Ok(())
}

type InheritanceActorCardRow = (Option<i64>, Option<i64>, Option<i64>, String);

/// 第一把锁：锁定 admission caller 卡行并复核 user/card/tenant/domain scope。
///
/// 卡行必须存在、ACTIVE，且 user_id/tenant_id/domain_id 与 Gateway 验证
/// context 一致；携带 admission 时其 proof scope 还必须与锁定行一致。
async fn verify_inheritance_mutation_actor_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    context: &InheritanceMutationContext,
) -> Result<(), AstralError> {
    let actor: Option<InheritanceActorCardRow> =
        sqlx::query_as(INHERITANCE_MUTATION_ACTOR_LOCK_SQL)
            .bind(context.actor_card_id)
            .fetch_optional(&mut ***tx)
            .await
            .map_err(db_error)?;
    match actor {
        Some((Some(user_id), Some(tenant_id), Some(domain_id), status))
            if user_id == context.actor_id
                && tenant_id == context.actor_tenant_id
                && domain_id == context.actor_domain_id
                && status == "ACTIVE" =>
        {
            if let SourceMutationCapability::User(admission) = context.source_capability() {
                if admission.proof().operation_id != context.request_id() {
                    return Err(AstralError::Pending(
                        "inheritance config completion operation id differs from its admission proof".into(),
                    ));
                }
                ensure_inheritance_actor_scope_matches(
                    &admission.proof().scope,
                    context.actor_card_id,
                    user_id,
                    tenant_id,
                    domain_id,
                )?;
            }
            Ok(())
        }
        _ => Err(AstralError::Auth(
            "Gateway inheritance mutation card context no longer matches an active user_card"
                .into(),
        )),
    }
}

/// 同事务审计关联写入（request_id/event_type 承担源 mutation 关联）。
/// 任何失败上抛回滚整个 mutation；与 departments/levels 路径同一机制：
/// 不用 MQ-first AuditDualWrite，绝不在事务提交后异步补写本记录。
async fn insert_inheritance_mutation_audit_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    context: &InheritanceMutationContext,
    resource_type: &str,
    action: &str,
    details: serde_json::Value,
) -> Result<astral_db::TypedSourceAuditReceipt, AstralError> {
    if resource_type.trim().is_empty() || action.trim().is_empty() {
        return Err(AstralError::Validation(
            "inheritance mutation audit requires a non-empty resource type and action".into(),
        ));
    }
    let detail_json = serde_json::to_value(serde_json::json!({
        "requestId": context.request_id(),
        "actorCardId": context.actor_card_id,
        "actorTenantId": context.actor_tenant_id,
        "actorDomainId": context.actor_domain_id,
        "targetType": "permission_inheritance_config",
        "targetId": resource_type,
        "operationId": context.request_id(),
        "mutation": details,
    }))
    .map_err(|error| {
        AstralError::Validation(format!("inheritance audit serialization failed: {error}"))
    })?;
    let detail = serde_json::to_string(&detail_json).map_err(|error| {
        AstralError::Validation(format!("inheritance audit serialization failed: {error}"))
    })?;
    let result = sqlx::query(INHERITANCE_MUTATION_AUDIT_INSERT_SQL)
        .bind(context.actor_id)
        .bind(context.actor_card_id)
        .bind(action)
        .bind(INHERITANCE_AUDIT_RESOURCE)
        .bind(INHERITANCE_AUDIT_EVENT_TYPE)
        .bind(context.request_id())
        .bind(context.actor_domain_id)
        .bind(context.actor_tenant_id)
        .bind(detail)
        .execute(&mut ***tx)
        .await
        .map_err(|error| {
            AstralError::Database(format!("inheritance mutation audit insert failed: {error}"))
        })?;
    astral_db::TypedSourceAuditReceipt::from_same_tx_insert_id(result.last_insert_id() as i64)
}

#[async_trait]
pub trait InheritanceConfigRepository: Send + Sync {
    async fn count_configs(&self) -> Result<i64, AstralError>;
    /// 分页列表（ORDER BY resource_type）
    async fn list_configs(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<InheritanceConfigRecord>, AstralError>;
    /// UPSERT 后按 resource_type 查回（只读路径；mutation 走 `_with_context`）
    async fn get_by_resource_type(
        &self,
        resource_type: &str,
    ) -> Result<InheritanceConfigRecord, AstralError>;

    /// 遗留无 context upsert：一律 fail-closed（无 admission 旁路）。
    async fn upsert_by_resource_type(
        &self,
        resource_type: &str,
        inheritance_mode: &str,
    ) -> Result<(), AstralError> {
        let _ = (resource_type, inheritance_mode);
        Err(inheritance_context_required())
    }
    /// UPSERT 继承配置（proof-bound admission source transaction）。
    ///
    /// 事务内锁序：actor 卡行 → INSERT ... ON DUPLICATE KEY UPDATE → 同事务
    /// reselect。insert/upsert 与查回**同一事务内原子完成**，响应行绝不依赖
    /// 第二连接的事务外读取；resource_type 注册校验属于进程内 ResourceRegistry
    /// 编排，由 handler 在开启事务之前完成。commit 前 canonical wrapper 完成
    /// durable authority revalidation / consume_once，只有 proven commit 返回行。
    async fn upsert_with_context(
        &self,
        resource_type: &str,
        inheritance_mode: &str,
        context: &InheritanceMutationContext,
    ) -> Result<InheritanceConfigRecord, AstralError>;

    /// 遗留无 context update：一律 fail-closed（无 admission 旁路）。
    async fn update_by_id(&self, id: i64, inheritance_mode: &str) -> Result<bool, AstralError> {
        let _ = (id, inheritance_mode);
        Err(inheritance_context_required())
    }
    /// 遗留无 context delete：一律 fail-closed（无 admission 旁路）。
    async fn delete_by_id(&self, id: i64) -> Result<bool, AstralError> {
        let _ = id;
        Err(inheritance_context_required())
    }
    /// 遗留无 context delete：一律 fail-closed（无 admission 旁路）。
    async fn delete_by_resource_type(&self, resource_type: &str) -> Result<bool, AstralError> {
        let _ = resource_type;
        Err(inheritance_context_required())
    }
    /// 按 registered resource type 删除，返回是否命中
    /// （proof-bound admission source transaction）。
    ///
    /// 事务内锁序：actor 卡行 → 目标行锁（未命中返回 false，事务随 drop 回滚）
    /// → DELETE → 审计关联。只有 proven commit 返回命中。
    async fn delete_by_resource_type_with_context(
        &self,
        resource_type: &str,
        context: &InheritanceMutationContext,
    ) -> Result<bool, AstralError>;
}

pub struct SqlxInheritanceConfigRepository {
    db: MySqlPool,
}

impl SqlxInheritanceConfigRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl InheritanceConfigRepository for SqlxInheritanceConfigRepository {
    async fn count_configs(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM permission_inheritance_config")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_configs(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<InheritanceConfigRecord>, AstralError> {
        sqlx::query_as::<_, InheritanceConfigRecord>(&format!(
            "SELECT {INHERIT_SELECT_COLUMNS} FROM permission_inheritance_config \
             ORDER BY resource_type LIMIT ? OFFSET ?"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn get_by_resource_type(
        &self,
        resource_type: &str,
    ) -> Result<InheritanceConfigRecord, AstralError> {
        sqlx::query_as::<_, InheritanceConfigRecord>(&format!(
            "SELECT {INHERIT_SELECT_COLUMNS} FROM permission_inheritance_config WHERE resource_type = ?"
        ))
        .bind(resource_type)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn upsert_with_context(
        &self,
        resource_type: &str,
        inheritance_mode: &str,
        context: &InheritanceMutationContext,
    ) -> Result<InheritanceConfigRecord, AstralError> {
        // 授权源事务宿主：栅栏先于 DB begin 取得（hub 拒绝发证即 fail-closed，
        // 绝不留下无栅栏 writer）；UserPending（缺失 admission）在 begin 即被
        // 拒绝，commit 前 canonical wrapper 对牌 durable authority proof 并
        // consume_once，只有 proven commit 返回成功。
        let mut tx =
            begin_source_transaction_with_capability(&self.db, context.source_capability()).await?;
        // 第一把锁：actor 卡行（user/tenant/domain/ACTIVE + admission scope 对牌）。
        verify_inheritance_mutation_actor_in_tx(&mut tx, context).await?;
        let lookup = TypedSourceRowLookup::InheritanceResourceType {
            resource_type: resource_type.to_owned(),
        };
        let mut capture = tx.typed_row_capture(
            TypedSourceTable::InheritanceConfig,
            TypedRowOperation::Upsert,
        );
        capture.capture_before_in_tx(&lookup).await?;
        let resource_type_owned = resource_type.to_owned();
        let inheritance_mode_owned = inheritance_mode.to_owned();
        let result = capture
            .with_tx_mut(|tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO permission_inheritance_config (resource_type, inheritance_mode) \
                         VALUES (?, ?) \
                         ON DUPLICATE KEY UPDATE inheritance_mode = VALUES(inheritance_mode)",
                    )
                    .bind(resource_type_owned)
                    .bind(inheritance_mode_owned)
                    .execute(&mut **tx)
                    .await
                    .map_err(db_error)
                })
            })
            .await?;
        if result.rows_affected() == 0 {
            return Err(AstralError::Pending(
                "inheritance config upsert did not prove source effect".into(),
            ));
        }
        // 同事务 reselect：行锁（FOR UPDATE）+ 查回与 UPSERT 原子成立，响应行
        // 不依赖第二连接的事务外读取。
        capture.capture_after_in_tx(&lookup).await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        let row: Option<(i64,)> = sqlx::query_as(INHERITANCE_ROW_LOCK_SQL)
            .bind(resource_type)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?;
        let (id,) = row.ok_or_else(|| {
            AstralError::Database(format!(
                "inheritance config for resource_type '{resource_type}' disappeared during locked upsert"
            ))
        })?;
        let record = sqlx::query_as::<_, InheritanceConfigRecord>(&format!(
            "SELECT {INHERIT_SELECT_COLUMNS} FROM permission_inheritance_config WHERE id = ?"
        ))
        .bind(id)
        .fetch_one(&mut **tx)
        .await
        .map_err(db_error)?;
        let audit = insert_inheritance_mutation_audit_in_tx(
            &mut tx,
            context,
            resource_type,
            "inheritance_config_upsert",
            serde_json::json!({ "inheritanceMode": inheritance_mode }),
        )
        .await?;
        tx.stage_typed_source_image(image)?;
        tx.stage_typed_source_audit(audit)?;
        tx.commit_consuming().await?;
        Ok(record)
    }

    async fn delete_by_resource_type_with_context(
        &self,
        resource_type: &str,
        context: &InheritanceMutationContext,
    ) -> Result<bool, AstralError> {
        let mut tx =
            begin_source_transaction_with_capability(&self.db, context.source_capability()).await?;
        // 第一把锁：actor 卡行（user/tenant/domain/ACTIVE + admission scope 对牌）。
        verify_inheritance_mutation_actor_in_tx(&mut tx, context).await?;
        // 目标行锁：未命中返回 false（对齐既有 API 404 语义），事务随 drop
        // 回滚；命中则行锁与 DELETE 原子成立。
        let lookup = TypedSourceRowLookup::InheritanceResourceType {
            resource_type: resource_type.to_owned(),
        };
        let existing: Option<(i64,)> = sqlx::query_as(INHERITANCE_ROW_LOCK_SQL)
            .bind(resource_type)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db_error)?;
        let Some((id,)) = existing else {
            tx.commit_consuming().await?;
            return Ok(false);
        };
        let mut capture = tx.typed_row_capture(
            TypedSourceTable::InheritanceConfig,
            TypedRowOperation::Delete,
        );
        capture.capture_before_in_tx(&lookup).await?;
        let result = capture
            .with_tx_mut(|tx| {
                Box::pin(async move {
                    sqlx::query("DELETE FROM permission_inheritance_config WHERE id = ?")
                        .bind(id)
                        .execute(&mut **tx)
                        .await
                        .map_err(db_error)
                })
            })
            .await?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Database(format!(
                "inheritance config for resource_type '{resource_type}' disappeared during locked delete"
            )));
        }
        capture.capture_after_in_tx(&lookup).await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        let audit = insert_inheritance_mutation_audit_in_tx(
            &mut tx,
            context,
            resource_type,
            "inheritance_config_delete",
            serde_json::json!({ "status": "deleted" }),
        )
        .await?;
        tx.stage_typed_source_image(image)?;
        tx.stage_typed_source_audit(audit)?;
        tx.commit_consuming().await?;
        Ok(true)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!(
        "Inheritance config repository query failed: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_context(user_id: i64, card_id: i64, tenant_id: i64, domain_id: i64) -> PolicyContext {
        PolicyContext::builder()
            .user_id(Some(user_id))
            .principal_kind(Some("PLATFORM_USER".into()))
            .card_id(Some(card_id))
            .tenant_id(Some(tenant_id))
            .domain_id(Some(domain_id))
            .action("manage".into())
            .build()
    }

    fn admission_scope(
        tenant_id: i64,
        card_id: i64,
        user_id: i64,
        domain: AuthorizationDomainScope,
    ) -> AuthorizationAuthorityScope {
        AuthorizationAuthorityScope {
            tenant_id,
            card_id,
            user_id: Some(user_id),
            domain,
        }
    }

    // ── context 构造：缺失/非法身份 fail-closed，admission 装载可见 ────────

    #[test]
    fn inheritance_mutation_context_requires_verified_identity() {
        // 非平台身份拒绝
        let end_user = PolicyContext::builder()
            .user_id(Some(10))
            .principal_kind(Some("END_USER".into()))
            .card_id(Some(20))
            .tenant_id(Some(30))
            .domain_id(Some(40))
            .action("manage".into())
            .build();
        assert!(matches!(
            InheritanceMutationContext::from_policy_context(&end_user, Some("req-1")),
            Err(AstralError::Auth(_))
        ));
        // 缺失/非正 id 拒绝
        let incomplete = PolicyContext::builder()
            .user_id(Some(10))
            .principal_kind(Some("PLATFORM_USER".into()))
            .tenant_id(Some(30))
            .domain_id(Some(40))
            .action("manage".into())
            .build();
        assert!(matches!(
            InheritanceMutationContext::from_policy_context(&incomplete, Some("req-1")),
            Err(AstralError::Auth(_))
        ));
        // 缺失 request id 拒绝（授权 mutation 无随机 fallback）
        assert!(matches!(
            InheritanceMutationContext::from_policy_context(&policy_context(10, 20, 30, 40), None),
            Err(AstralError::Auth(_))
        ));
        // 非安全集字符 / 超长 request id 拒绝，绝不截断
        assert!(matches!(
            InheritanceMutationContext::from_policy_context(
                &policy_context(10, 20, 30, 40),
                Some("req id!")
            ),
            Err(AstralError::Validation(_))
        ));
        assert!(matches!(
            InheritanceMutationContext::from_policy_context(
                &policy_context(10, 20, 30, 40),
                Some("a".repeat(65).as_str())
            ),
            Err(AstralError::Validation(_))
        ));
        // 合法构造：UserPending 起步，with_admission 装载 proof-bound 能力
        let context = InheritanceMutationContext::from_policy_context(
            &policy_context(10, 20, 30, 40),
            Some("req-1"),
        )
        .unwrap();
        assert!(matches!(
            context.source_capability(),
            SourceMutationCapability::UserPending
        ));
        let admitted = context.with_admission(admission_for_test());
        assert!(matches!(
            admitted.source_capability(),
            SourceMutationCapability::User(_)
        ));
    }

    fn admission_for_test() -> AuthorizationAdmission {
        // 测试专用 admission 构造：走 from_verified_proof 合同入口，不手写内部
        // 状态。proof 本身只需通过结构校验即可（无签名验证；scope 对牌在锁定
        // 行复核时完成）。
        let proof = astral_types::AuthorizationFenceProof {
            authorization_edition: astral_types::AUTHORIZATION_EDITION,
            authority_id: "authority-test".into(),
            authority_term: 1,
            global_fence_sequence: 1,
            scope: admission_scope(30, 20, 10, AuthorizationDomainScope::Exact(40)),
            scope_generation: 1,
            revoke_watermark: 0,
            snapshot_hash: "a".repeat(64),
            parent_hash: None,
            operation_id: "op-inherit-test".into(),
            event_id: "evt-inherit-test".into(),
            key_id: "key-test".into(),
            key_epoch: 1,
            issued_at: 1_700_000_000,
            not_before: 1_700_000_000,
            expires_at: 1_700_000_400,
            request_nonce: "nonce-inherit-test".into(),
            request_binding_digest: None,
            scope_certificate_hash: None,
            proof_id: "proof-inherit-test".into(),
            signature: "ab".repeat(64),
        };
        AuthorizationAdmission::from_verified_proof(proof).expect("structurally valid proof")
    }

    /// 缺失 admission（UserPending）在开启 source 事务之前即被 canonical
    /// dispatcher 拒绝 —— 无 DB 连接也可证明的 fail-closed 合同。
    #[tokio::test]
    async fn user_pending_capability_is_refused_before_any_source_transaction() {
        let pool = MySqlPool::connect_lazy("mysql://invalid@localhost:1/none").unwrap();
        let context = InheritanceMutationContext::from_policy_context(
            &policy_context(10, 20, 30, 40),
            Some("req-1"),
        )
        .unwrap();
        let error = match begin_source_transaction_with_capability(
            &pool,
            context.source_capability(),
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("missing admission must not open a source transaction"),
        };
        assert!(
            matches!(error, AstralError::Pending(_)),
            "missing admission must fail closed as PENDING, got: {error:?}"
        );
    }

    // ── foreign scope：admission 与锁定 actor 卡行不一致一律 Permission ────

    #[test]
    fn actor_scope_mismatch_is_fail_closed_per_dimension() {
        const CARD: i64 = 20;
        const USER: i64 = 10;
        const TENANT: i64 = 30;
        const DOMAIN: i64 = 40;
        // 完全一致 → 放行
        assert!(ensure_inheritance_actor_scope_matches(
            &admission_scope(TENANT, CARD, USER, AuthorizationDomainScope::Exact(DOMAIN)),
            CARD,
            USER,
            TENANT,
            DOMAIN
        )
        .is_ok());
        // foreign tenant → 拒绝
        assert!(matches!(
            ensure_inheritance_actor_scope_matches(
                &admission_scope(31, CARD, USER, AuthorizationDomainScope::Exact(DOMAIN)),
                CARD,
                USER,
                TENANT,
                DOMAIN
            ),
            Err(AstralError::Permission(_))
        ));
        // foreign card → 拒绝
        assert!(matches!(
            ensure_inheritance_actor_scope_matches(
                &admission_scope(TENANT, 21, USER, AuthorizationDomainScope::Exact(DOMAIN)),
                CARD,
                USER,
                TENANT,
                DOMAIN
            ),
            Err(AstralError::Permission(_))
        ));
        // foreign user → 拒绝
        assert!(matches!(
            ensure_inheritance_actor_scope_matches(
                &admission_scope(TENANT, CARD, 11, AuthorizationDomainScope::Exact(DOMAIN)),
                CARD,
                USER,
                TENANT,
                DOMAIN
            ),
            Err(AstralError::Permission(_))
        ));
        // foreign domain → 拒绝
        assert!(matches!(
            ensure_inheritance_actor_scope_matches(
                &admission_scope(TENANT, CARD, USER, AuthorizationDomainScope::Exact(41)),
                CARD,
                USER,
                TENANT,
                DOMAIN
            ),
            Err(AstralError::Permission(_))
        ));
        // 非显式 Exact（Any/NoDomain）绝不匹配 —— 不放宽域要求
        assert!(matches!(
            ensure_inheritance_actor_scope_matches(
                &admission_scope(TENANT, CARD, USER, AuthorizationDomainScope::Any),
                CARD,
                USER,
                TENANT,
                DOMAIN
            ),
            Err(AstralError::Permission(_))
        ));
        assert!(matches!(
            ensure_inheritance_actor_scope_matches(
                &admission_scope(TENANT, CARD, USER, AuthorizationDomainScope::NoDomain),
                CARD,
                USER,
                TENANT,
                DOMAIN
            ),
            Err(AstralError::Permission(_))
        ));
    }

    // ── 审计关联：固定 event_type/resource 常量 + 全绑定参数 ──────────────

    #[test]
    fn audit_correlation_uses_bound_parameters_and_fixed_event_type() {
        assert_eq!(
            INHERITANCE_AUDIT_EVENT_TYPE,
            "TRUSTGRAPH_INHERITANCE_MUTATION"
        );
        assert!(
            INHERITANCE_AUDIT_EVENT_TYPE.len() <= 32,
            "audit_log.event_type is VARCHAR(32)"
        );
        assert_eq!(INHERITANCE_AUDIT_RESOURCE, "permission_inheritance_config");
        assert!(
            INHERITANCE_MUTATION_AUDIT_INSERT_SQL
                .contains("VALUES (?, ?, ?, ?, 'SUCCESS', NULL, 'TRUSTGRAPH_INHERITANCE_MUTATION', ?, ?, ?, ?)"),
            "audit insert must bind every mutable input"
        );
        assert!(
            INHERITANCE_MUTATION_AUDIT_INSERT_SQL.contains("request_id")
                && INHERITANCE_MUTATION_AUDIT_INSERT_SQL.contains("event_type"),
            "audit correlation must land in event_type/request_id columns"
        );
    }

    // ── 源序守卫：upsert/delete 事务内锁序与 commit 门 ───────────────────

    /// 自引用防呆：拼接构造 begin token，避免本测试模块源码字面量污染
    /// 全文件出现次数统计（include_str! 包含本测试自身）。
    fn wrapper_begin_token() -> &'static str {
        concat!(
            "begin_source_transaction_with_capability",
            "(&self.db, context.source_capability())"
        )
    }

    fn impl_segment(source: &'static str, start_marker: &str, end_marker: &str) -> &'static str {
        source
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("production must precede the test module")
            .split(start_marker)
            .nth(2)
            .expect("implementation must exist")
            .split(end_marker)
            .next()
            .expect("body must be delimited")
    }

    #[test]
    fn upsert_tx_orders_actor_lock_insert_reselect_audit_and_commit() {
        let source = include_str!("inheritance_config_repository.rs");
        let body = impl_segment(
            source,
            "async fn upsert_with_context",
            "async fn delete_by_resource_type_with_context",
        );
        let begin = body
            .find(wrapper_begin_token())
            .expect("upsert must host the mutation in the proof-bound source wrapper");
        let actor_lock = body
            .find("verify_inheritance_mutation_actor_in_tx(&mut tx, context)")
            .expect("upsert must lock the admission caller card first");
        let upsert = body
            .find("INSERT INTO permission_inheritance_config")
            .expect("upsert must mutate on the wrapper connection");
        let reselect = body
            .find("INHERITANCE_ROW_LOCK_SQL")
            .expect("upsert must reselect the row with a locked read in the same tx");
        let audit = body
            .find("insert_inheritance_mutation_audit_in_tx")
            .expect("upsert must write one audit correlation record");
        let commit = body
            .find("tx.commit_consuming()")
            .expect("upsert must commit through the wrapper consuming commit");
        assert!(
            begin < actor_lock
                && actor_lock < upsert
                && upsert < reselect
                && reselect < audit
                && audit < commit,
            "upsert must order: wrapper begin -> actor lock -> UPSERT -> locked reselect -> audit -> commit_consuming"
        );
        assert!(
            !body.contains("tx.commit()"),
            "upsert must not bypass the wrapper's proven-commit gate with a raw commit"
        );
    }

    #[test]
    fn delete_tx_orders_actor_lock_row_lock_delete_audit_and_commit() {
        let source = include_str!("inheritance_config_repository.rs");
        let body = impl_segment(
            source,
            "async fn delete_by_resource_type_with_context",
            "fn db_error",
        );
        let begin = body
            .find(wrapper_begin_token())
            .expect("delete must host the mutation in the proof-bound source wrapper");
        let actor_lock = body
            .find("verify_inheritance_mutation_actor_in_tx(&mut tx, context)")
            .expect("delete must lock the admission caller card first");
        let row_lock = body
            .find("INHERITANCE_ROW_LOCK_SQL")
            .expect("delete must lock the target row with a locked read");
        let row_delete = body
            .find("DELETE FROM permission_inheritance_config WHERE id = ?")
            .expect("delete must remove the row");
        let audit = body
            .find("insert_inheritance_mutation_audit_in_tx")
            .expect("delete must write one audit correlation record");
        let commit = body
            .rfind("tx.commit_consuming()")
            .expect("delete must commit through the wrapper's successful consuming commit");
        assert!(
            begin < actor_lock
                && actor_lock < row_lock
                && row_lock < row_delete
                && row_delete < audit
                && audit < commit,
            "delete must order: wrapper begin -> actor lock -> row lock -> DELETE -> audit -> commit_consuming"
        );
        assert!(
            !body.contains("tx.commit()"),
            "delete must not bypass the wrapper's proven-commit gate with a raw commit"
        );
    }

    // ── 范围结论：无 eligibility fanout、遗留入口 fail-closed ─────────────

    #[test]
    fn inheritance_mutations_have_no_eligibility_fanout_and_legacy_entries_fail_closed() {
        let source = include_str!("inheritance_config_repository.rs");
        // 继承配置行不参与资格/授权投影（模块头范围结论）：不得登记 ELIGIBILITY
        // 失效、不得追加任何投影 delta/receipt。
        let eligibility_token =
            concat!("append_eligibility_", "projection_with_invalidation_in_tx");
        let stage_token = concat!("stage_projection_", "receipt");
        let record_token = concat!("record_invalidation_", "receipt");
        assert!(
            !source.contains(eligibility_token)
                && !source.contains(stage_token)
                && !source.contains(record_token),
            "inheritance mutations must not invent eligibility/projection fanout"
        );
        // upsert/delete 全部以 proof-bound source transaction 为宿主。
        assert_eq!(
            source.matches(wrapper_begin_token()).count(),
            2,
            "upsert/delete must each use the proof-bound source wrapper"
        );
        // 遗留无 context mutation 入口一律 fail-closed（trait 默认实现）。
        let legacy = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source must exist");
        assert_eq!(
            legacy
                .matches("Err(inheritance_context_required())")
                .count(),
            4,
            "legacy upsert/update_by_id/delete_by_id/delete_by_resource_type must fail closed"
        );
        // actor 卡行与目标行锁定读都是 FOR UPDATE（原子守卫）。
        assert!(INHERITANCE_MUTATION_ACTOR_LOCK_SQL.contains("FOR UPDATE"));
        assert!(INHERITANCE_ROW_LOCK_SQL.contains("FOR UPDATE"));
    }
}
