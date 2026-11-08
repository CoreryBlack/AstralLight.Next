//! 用户等级定义数据访问 — LevelRepository
//!
//! 对齐 Java `IdentityUserLevelDefinitionMapper` 边界（user_card_level_definition 表）。
//!
//! ## 授权源事务（TG-A 批次：admission-hosted source mutation）
//!
//! `user_card_level_definition` 是受保护资源 resolver（`TargetLookupKind::UserLevel`）
//! 的 ownership 事实面：本仓全部 mutation（create/update/delete，含仅名称的
//! 元数据更新，保守同栅）以 `AuthorizationSourceTransaction` 为宿主——复用
//! canonical `begin_source_transaction_with_capability` / `commit_consuming`，
//! 不在本文件发明第二套事务/栅栏基础设施：
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
//! admission proof scope 对牌，与 departments 同一形状），再锁定目标等级行
//! （存在性 NotFound fail-closed + 行锁序列化并发 mutation）。
//!
//! ## 范围结论（不虚构 eligibility fanout）
//!
//! `user_card_level_definition` 不是 CanonicalGrant 源：policy-engine 与
//! astral-db 的 eligibility/投影消费路径均无本表引用（唯一消费方是
//! `resource_ownership` 的 ownership resolver 只读查询，其读面一致性由上述
//! hub 源活动栅栏保证）。因此本文件刻意不登记 ELIGIBILITY 失效事件、不追加
//! 任何投影 delta/receipt；卡片授权事实仍由 user_card/发布证据路径承载。
//! 同事务保留 `audit_log` 关联（request_id/event_type 关联源 mutation）。
//! 遗留无 context mutation 方法一律 fail-closed（`level_context_required`），
//! 无内部 system 旁路。

use async_trait::async_trait;
use sqlx::{MySqlPool, QueryBuilder};

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

/// 等级定义记录（user_card_level_definition）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LevelRecord {
    pub level_id: i64,
    pub domain_id: i64,
    pub level_no: i32,
    pub level_code: String,
    pub level_name: String,
    pub status: String,
    pub upgrade_strategy_json: Option<String>,
    pub description: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// 列表过滤条件（domain_id / status 可选）
#[derive(Debug, Default)]
pub struct LevelFilter {
    pub domain_id: Option<i64>,
    pub status: Option<String>,
}

/// 部分更新补丁（仅更新非 None 字段，对齐 Java Mapper.updateById 语义）
#[derive(Debug, Default)]
pub struct LevelPatch {
    pub level_name: Option<String>,
    pub level_code: Option<String>,
    pub level_no: Option<i32>,
    pub status: Option<String>,
    pub upgrade_strategy_json: Option<String>,
    pub description: Option<String>,
}

/// 新建等级定义参数（列与既有 INSERT 一致；status 固定 'ACTIVE' 起步）
#[derive(Debug, Clone)]
pub struct NewLevel {
    pub domain_id: i64,
    pub level_name: String,
    pub level_code: String,
    pub level_no: i32,
    pub upgrade_strategy_json: Option<String>,
    pub description: Option<String>,
}

// ===== mutation context =====

/// Gateway-verified identity and scope carried into one TrustGraph user-level mutation.
///
/// 与 departments 同一装配合同：身份只能来自 TrustGraph permission 中间件
/// 安装的已验证 `PolicyContext`；Gateway 头不是授权来源，只允许在 API 层与
/// 该 context 完全一致后使用。`request_id` 必须携带且通过统一持久化安全性
/// 校验（`validated_request_operation_id`）；缺失/纯空白/超长/非法字符一律
/// fail-closed，绝不静默替换、截断或随机补位。`source_capability` 初始为
/// `UserPending`，只有 `.with_admission(...)` 注入 proof-bound admission 后
/// 才允许开启用户 source 事务。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LevelMutationContext {
    actor_id: i64,
    actor_card_id: i64,
    actor_tenant_id: i64,
    actor_domain_id: i64,
    request_id: String,
    source_capability: SourceMutationCapability,
}

impl LevelMutationContext {
    /// Create only from the verified PolicyContext installed by TrustGraph permission middleware.
    pub(crate) fn from_policy_context(
        context: &PolicyContext,
        request_id: Option<&str>,
    ) -> Result<Self, AstralError> {
        if context.principal_kind.as_deref() != Some("PLATFORM_USER") {
            return Err(AstralError::Auth(
                "user level mutation requires a Gateway-verified platform user context".into(),
            ));
        }
        let actor_id = positive_context_id(context.user_id, "user_id")?;
        let actor_card_id = positive_context_id(context.card_id, "card_id")?;
        let actor_tenant_id = positive_context_id(context.tenant_id, "tenant_id")?;
        let actor_domain_id = positive_context_id(context.domain_id, "domain_id")?;
        let request_id = validated_request_operation_id(request_id)?.ok_or_else(|| {
            AstralError::Auth("user level mutation requires a canonical request id".into())
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
    value
        .filter(|value| *value > 0)
        .ok_or_else(|| AstralError::Auth(format!("user level mutation requires a positive {name}")))
}

fn level_context_required() -> AstralError {
    AstralError::Auth(
        "user level business mutation requires Gateway-verified user-card context".into(),
    )
}

fn ensure_level_operation_matches_admission(
    context: &LevelMutationContext,
) -> Result<(), AstralError> {
    match context.source_capability() {
        SourceMutationCapability::User(admission)
            if admission.proof().operation_id == context.request_id() =>
        {
            Ok(())
        }
        SourceMutationCapability::User(_) => Err(AstralError::Pending(
            "user level config completion operation id differs from its admission proof".into(),
        )),
        _ => Err(AstralError::Pending(
            "user level config completion requires proof-bound user admission".into(),
        )),
    }
}

// ===== SQL 常量 =====

const LEVEL_SELECT_COLUMNS: &str =
    "level_id, domain_id, level_no, level_code, level_name, status, \
     upgrade_strategy_json, description, \
     DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at, \
     DATE_FORMAT(updated_at, '%Y-%m-%dT%H:%i:%sZ') as updated_at";

/// admission caller 卡行锁：把 admission scope 绑定到锁定的 user_card 行
/// （user/tenant/domain/ACTIVE 复核），与 departments 同一形状。所有等级
/// mutation 的第一把锁，跨 create/update/delete 保持同一锁序避免死锁。
const LEVEL_MUTATION_ACTOR_LOCK_SQL: &str = "SELECT user_id, tenant_id, domain_id, card_status \
     FROM user_card WHERE card_id = ? FOR UPDATE";
/// 审计关联 INSERT（仅绑定参数 + 固定常量；所有可变输入走 `?` 绑定，
/// 绝不拼接请求输入）。decision 按固定 mutation 语义常量绑定。
const LEVEL_MUTATION_AUDIT_INSERT_SQL: &str = "INSERT INTO audit_log \
     (user_id, card_id, action, resource, decision, reason, event_type, request_id, domain_id, tenant_id, detail) \
     VALUES (?, ?, ?, ?, 'SUCCESS', NULL, ?, ?, ?, ?, ?)";

/// `audit_log.event_type`（VARCHAR(32)）：等级定义 mutation 家族标记。
const LEVEL_AUDIT_EVENT_TYPE: &str = "TRUSTGRAPH_USER_LEVEL_MUTATION";
/// `audit_log.resource`：等级定义聚合（user_card_level_definition 表）。
const LEVEL_AUDIT_RESOURCE: &str = "user_card_level_definition";

/// 纯校验：admission proof scope 必须与锁定的 actor 卡行完全一致
/// （tenant/card/user/domain）。域要求是显式 `Exact`，`Any`/`NoDomain`
/// 一律不匹配 —— 绝不放宽。任何不一致都是 Permission fail-closed。
fn ensure_level_actor_scope_matches(
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
            "authorization admission scope does not match the locked user level mutation actor card"
                .into(),
        ));
    }
    Ok(())
}

type LevelActorCardRow = (Option<i64>, Option<i64>, Option<i64>, String);

/// 第一把锁：锁定 admission caller 卡行并复核 user/card/tenant/domain scope。
///
/// 卡行必须存在、ACTIVE，且 user_id/tenant_id/domain_id 与 Gateway 验证
/// context 一致；携带 admission 时其 proof scope 还必须与锁定行一致。
async fn verify_level_mutation_actor_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    context: &LevelMutationContext,
) -> Result<(), AstralError> {
    let actor: Option<LevelActorCardRow> = sqlx::query_as(LEVEL_MUTATION_ACTOR_LOCK_SQL)
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
                ensure_level_actor_scope_matches(
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
            "Gateway user level mutation card context no longer matches an active user_card".into(),
        )),
    }
}

/// 同事务审计关联写入（request_id/event_type 承担源 mutation 关联）。
/// 任何失败上抛回滚整个 mutation；与 departments/level-template 路径同一
/// 机制：不用 MQ-first AuditDualWrite，绝不在事务提交后异步补写本记录。
async fn insert_level_mutation_audit_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    context: &LevelMutationContext,
    level_id: i64,
    action: &str,
    details: serde_json::Value,
) -> Result<astral_db::TypedSourceAuditReceipt, AstralError> {
    if level_id <= 0 || action.trim().is_empty() {
        return Err(AstralError::Validation(
            "user level mutation audit requires a positive target id and a non-empty action".into(),
        ));
    }
    let detail_json = serde_json::to_value(serde_json::json!({
        "requestId": context.request_id(),
        "actorCardId": context.actor_card_id,
        "actorTenantId": context.actor_tenant_id,
        "actorDomainId": context.actor_domain_id,
        "targetType": "user_level",
        "targetId": level_id,
        "operationId": context.request_id(),
        "mutation": details,
    }))
    .map_err(|error| {
        AstralError::Validation(format!("user level audit serialization failed: {error}"))
    })?;
    let detail = serde_json::to_string(&detail_json).map_err(|error| {
        AstralError::Validation(format!("user level audit serialization failed: {error}"))
    })?;
    let result = sqlx::query(LEVEL_MUTATION_AUDIT_INSERT_SQL)
        .bind(context.actor_id)
        .bind(context.actor_card_id)
        .bind(action)
        .bind(LEVEL_AUDIT_RESOURCE)
        .bind(LEVEL_AUDIT_EVENT_TYPE)
        .bind(context.request_id())
        .bind(context.actor_domain_id)
        .bind(context.actor_tenant_id)
        .bind(detail)
        .execute(&mut ***tx)
        .await
        .map_err(|error| {
            AstralError::Database(format!("user level mutation audit insert failed: {error}"))
        })?;
    astral_db::TypedSourceAuditReceipt::from_same_tx_insert_id(result.last_insert_id() as i64)
}

#[async_trait]
pub trait LevelRepository: Send + Sync {
    /// 列表总数（按过滤条件）
    async fn count_levels(&self, filter: &LevelFilter) -> Result<i64, AstralError>;
    /// 分页列表（ORDER BY domain_id, level_no）
    async fn list_levels(
        &self,
        filter: &LevelFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<LevelRecord>, AstralError>;
    async fn get_level(&self, id: i64) -> Result<Option<LevelRecord>, AstralError>;

    /// 遗留无 context create：一律 fail-closed（无 admission 旁路）。
    async fn create_level(
        &self,
        domain_id: i64,
        level_name: &str,
        level_code: &str,
        level_no: i32,
        upgrade_strategy_json: Option<&str>,
        description: Option<&str>,
    ) -> Result<i64, AstralError> {
        let _ = (
            domain_id,
            level_name,
            level_code,
            level_no,
            upgrade_strategy_json,
            description,
        );
        Err(level_context_required())
    }
    /// 新建等级定义（proof-bound admission source transaction）。
    ///
    /// 事务内锁序：actor 卡行 → INSERT。目标域存在性由既有 FK
    /// （fk_iuld_domain → platform_domain）兜底，与既有行为一致。
    /// commit 前 canonical wrapper 完成 durable authority revalidation /
    /// consume_once，只有 proven commit 返回新 id。
    async fn create_level_with_context(
        &self,
        new: &NewLevel,
        context: &LevelMutationContext,
    ) -> Result<i64, AstralError>;

    /// 遗留无 context update：一律 fail-closed（无 admission 旁路）。
    async fn update_level(&self, id: i64, patch: &LevelPatch) -> Result<(), AstralError> {
        let _ = (id, patch);
        Err(level_context_required())
    }
    /// 部分更新（仅应用非 None 字段；空补丁 no-op：无 source mutation，
    /// 不开启事务）。
    ///
    /// 事务内锁序：actor 卡行 → 目标等级行锁（NotFound fail-closed）。
    /// 只有 proven commit 返回成功。
    async fn update_level_with_context(
        &self,
        id: i64,
        patch: &LevelPatch,
        context: &LevelMutationContext,
    ) -> Result<(), AstralError>;

    /// 遗留无 context delete：一律 fail-closed（无 admission 旁路）。
    async fn delete_level(&self, id: i64) -> Result<bool, AstralError> {
        let _ = id;
        Err(level_context_required())
    }
    /// 删除（FK ON DELETE CASCADE 级联 identity_user_grading，级联语义保持
    /// 不变——不做手工级联删除），返回是否命中。
    ///
    /// 事务内锁序：actor 卡行 → 目标等级行锁（未命中返回 false，事务随
    /// drop 回滚）。只有 proven commit 返回命中。
    async fn delete_level_with_context(
        &self,
        id: i64,
        context: &LevelMutationContext,
    ) -> Result<bool, AstralError>;
}

pub struct SqlxLevelRepository {
    db: MySqlPool,
}

impl SqlxLevelRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

/// 向 QueryBuilder 追加 domain_id / status 过滤（列表与总数共用同一条件）
fn push_level_filter<'args>(builder: &mut QueryBuilder<'args, sqlx::MySql>, filter: &LevelFilter) {
    if let Some(domain_id) = filter.domain_id {
        builder.push(" AND domain_id = ").push_bind(domain_id);
    }
    if let Some(status) = &filter.status {
        builder
            .push(" AND status = ")
            .push_bind(status.to_uppercase());
    }
}

#[async_trait]
impl LevelRepository for SqlxLevelRepository {
    async fn count_levels(&self, filter: &LevelFilter) -> Result<i64, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(
            "SELECT COUNT(*) FROM user_card_level_definition WHERE 1=1",
        );
        push_level_filter(&mut builder, filter);
        builder
            .build_query_scalar::<i64>()
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_levels(
        &self,
        filter: &LevelFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<LevelRecord>, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(&format!(
            "SELECT {LEVEL_SELECT_COLUMNS} FROM user_card_level_definition WHERE 1=1"
        ));
        push_level_filter(&mut builder, filter);
        builder
            .push(" ORDER BY domain_id, level_no LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        builder
            .build_query_as::<LevelRecord>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn get_level(&self, id: i64) -> Result<Option<LevelRecord>, AstralError> {
        sqlx::query_as::<_, LevelRecord>(&format!(
            "SELECT {LEVEL_SELECT_COLUMNS} FROM user_card_level_definition WHERE level_id = ?"
        ))
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create_level_with_context(
        &self,
        new: &NewLevel,
        context: &LevelMutationContext,
    ) -> Result<i64, AstralError> {
        // 授权源事务宿主：栅栏先于 DB begin 取得（hub 拒绝发证即 fail-closed，
        // 绝不留下无栅栏 writer）；UserPending（缺失 admission）在 begin 即被
        // 拒绝，commit 前 canonical wrapper 对牌 durable authority proof 并
        // consume_once，只有 proven commit 返回成功。
        ensure_level_operation_matches_admission(context)?;
        let mut tx =
            begin_source_transaction_with_capability(&self.db, context.source_capability()).await?;
        // 第一把锁：actor 卡行（user/tenant/domain/ACTIVE + admission scope 对牌）。
        verify_level_mutation_actor_in_tx(&mut tx, context).await?;
        let lookup = TypedSourceRowLookup::LevelNatural {
            domain_id: new.domain_id,
            level_code: new.level_code.clone(),
        };
        let mut capture = tx.typed_row_capture(
            TypedSourceTable::UserCardLevelDefinition,
            TypedRowOperation::Insert,
        );
        capture.capture_before_in_tx(&lookup).await?;
        let level_name = new.level_name.clone();
        let level_code = new.level_code.clone();
        let level_no = new.level_no;
        let domain_id = new.domain_id;
        let upgrade_strategy_json = new.upgrade_strategy_json.clone();
        let description = new.description.clone();
        let result = capture
            .with_tx_mut(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO user_card_level_definition \
                         (domain_id, level_name, level_code, level_no, status, upgrade_strategy_json, description) \
                         VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?)",
                    )
                    .bind(domain_id)
                    .bind(level_name)
                    .bind(level_code)
                    .bind(level_no)
                    .bind(upgrade_strategy_json)
                    .bind(description)
                    .execute(&mut **tx)
                    .await
                    .map_err(db_error)
                })
            })
            .await?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Pending(
                "user level insert did not prove exactly one source row".into(),
            ));
        }
        let new_id = i64::try_from(result.last_insert_id())
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| AstralError::Pending("user level insert returned invalid id".into()))?;
        capture.capture_after_in_tx(&lookup).await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        let audit = insert_level_mutation_audit_in_tx(
            &mut tx,
            context,
            new_id,
            "user_level_create",
            serde_json::json!({
                "domainId": new.domain_id,
                "levelName": new.level_name,
                "levelCode": new.level_code,
                "levelNo": new.level_no,
            }),
        )
        .await?;
        tx.stage_typed_source_image(image)?;
        tx.stage_typed_source_audit(audit)?;
        tx.commit_consuming().await?;
        Ok(new_id)
    }

    async fn update_level_with_context(
        &self,
        id: i64,
        patch: &LevelPatch,
        context: &LevelMutationContext,
    ) -> Result<(), AstralError> {
        // 先把补丁装配成绑定参数 UPDATE（列名是编译期常量，值全部 push_bind）；
        // 空补丁 no-op：无 source mutation，不开启事务。
        let mut builder =
            QueryBuilder::<sqlx::MySql>::new("UPDATE user_card_level_definition SET ");
        let mut first = true;
        if let Some(status) = &patch.status {
            if !first {
                builder.push(", ");
            }
            builder.push("status = ").push_bind(status.to_uppercase());
            first = false;
        }
        if let Some(name) = &patch.level_name {
            if !first {
                builder.push(", ");
            }
            builder.push("level_name = ").push_bind(name.clone());
            first = false;
        }
        if let Some(code) = &patch.level_code {
            if !first {
                builder.push(", ");
            }
            builder.push("level_code = ").push_bind(code.clone());
            first = false;
        }
        if let Some(level_no) = patch.level_no {
            if !first {
                builder.push(", ");
            }
            builder.push("level_no = ").push_bind(level_no);
            first = false;
        }
        if let Some(json) = &patch.upgrade_strategy_json {
            if !first {
                builder.push(", ");
            }
            builder
                .push("upgrade_strategy_json = ")
                .push_bind(json.clone());
            first = false;
        }
        if let Some(desc) = &patch.description {
            if !first {
                builder.push(", ");
            }
            builder.push("description = ").push_bind(desc.clone());
            first = false;
        }
        if first {
            // 空补丁：无字段更新（对齐既有 handler 语义，直接返回）。零 SQL
            // 零副作用，不开启 source 事务。
            return Ok(());
        }
        builder.push(" WHERE level_id = ").push_bind(id);

        ensure_level_operation_matches_admission(context)?;
        let mut tx =
            begin_source_transaction_with_capability(&self.db, context.source_capability()).await?;
        // 第一把锁：actor 卡行（user/tenant/domain/ACTIVE + admission scope 对牌）。
        verify_level_mutation_actor_in_tx(&mut tx, context).await?;
        let mut capture = tx.typed_row_capture(
            TypedSourceTable::UserCardLevelDefinition,
            TypedRowOperation::Update,
        );
        capture
            .capture_before_in_tx(&TypedSourceRowLookup::PrimaryId { id })
            .await?;
        let result = capture
            .with_tx_mut(move |tx| {
                Box::pin(async move { builder.build().execute(&mut **tx).await.map_err(db_error) })
            })
            .await?;
        if result.rows_affected() > 0 {
            capture
                .capture_after_in_tx(&TypedSourceRowLookup::PrimaryId { id })
                .await?;
            let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
            let audit = insert_level_mutation_audit_in_tx(
                &mut tx,
                context,
                id,
                "user_level_update",
                serde_json::json!({
                    "levelName": patch.level_name,
                    "levelCode": patch.level_code,
                    "levelNo": patch.level_no,
                    "status": patch.status,
                    "upgradeStrategyJson": patch.upgrade_strategy_json,
                    "description": patch.description,
                }),
            )
            .await?;
            tx.stage_typed_source_image(image)?;
            tx.stage_typed_source_audit(audit)?;
        } else {
            // MySQL reports zero changed rows for an equal-value UPDATE; preserve
            // the existing no-op API result without inventing an image transition.
            return Err(AstralError::Pending(
                "user level update did not change source facts; config completion is not staged"
                    .into(),
            ));
        }
        tx.commit_consuming().await
    }

    async fn delete_level_with_context(
        &self,
        id: i64,
        context: &LevelMutationContext,
    ) -> Result<bool, AstralError> {
        ensure_level_operation_matches_admission(context)?;
        let mut tx =
            begin_source_transaction_with_capability(&self.db, context.source_capability()).await?;
        // 第一把锁：actor 卡行（user/tenant/domain/ACTIVE + admission scope 对牌）。
        verify_level_mutation_actor_in_tx(&mut tx, context).await?;
        let mut capture = tx.typed_row_capture(
            TypedSourceTable::UserCardLevelDefinition,
            TypedRowOperation::Delete,
        );
        capture
            .capture_before_in_tx(&TypedSourceRowLookup::PrimaryId { id })
            .await
            .map_err(|error| match error {
                AstralError::NotFound(_) => {
                    AstralError::NotFound(format!("user_level {id} not found"))
                }
                other => other,
            })?;
        let result = capture
            .with_tx_mut(|tx| {
                Box::pin(async move {
                    sqlx::query("DELETE FROM user_card_level_definition WHERE level_id = ?")
                        .bind(id)
                        .execute(&mut **tx)
                        .await
                        .map_err(db_error)
                })
            })
            .await?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Pending(format!(
                "user level {id} disappeared during typed locked delete"
            )));
        }
        capture
            .capture_after_in_tx(&TypedSourceRowLookup::PrimaryId { id })
            .await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        let audit = insert_level_mutation_audit_in_tx(
            &mut tx,
            context,
            id,
            "user_level_delete",
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
    AstralError::Database(format!("Level repository query failed: {error}"))
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
    fn level_mutation_context_requires_verified_identity() {
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
            LevelMutationContext::from_policy_context(&end_user, Some("req-1")),
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
            LevelMutationContext::from_policy_context(&incomplete, Some("req-1")),
            Err(AstralError::Auth(_))
        ));
        // 缺失 request id 拒绝（授权 mutation 无随机 fallback）
        assert!(matches!(
            LevelMutationContext::from_policy_context(&policy_context(10, 20, 30, 40), None),
            Err(AstralError::Auth(_))
        ));
        // 非安全集字符 / 超长 request id 拒绝，绝不截断
        assert!(matches!(
            LevelMutationContext::from_policy_context(
                &policy_context(10, 20, 30, 40),
                Some("req id!")
            ),
            Err(AstralError::Validation(_))
        ));
        assert!(matches!(
            LevelMutationContext::from_policy_context(
                &policy_context(10, 20, 30, 40),
                Some("a".repeat(65).as_str())
            ),
            Err(AstralError::Validation(_))
        ));
        // 合法构造：UserPending 起步，with_admission 装载 proof-bound 能力
        let context = LevelMutationContext::from_policy_context(
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
            operation_id: "op-level-test".into(),
            event_id: "evt-level-test".into(),
            key_id: "key-test".into(),
            key_epoch: 1,
            issued_at: 1_700_000_000,
            not_before: 1_700_000_000,
            expires_at: 1_700_000_400,
            request_nonce: "nonce-level-test".into(),
            request_binding_digest: None,
            scope_certificate_hash: None,
            proof_id: "proof-level-test".into(),
            signature: "ab".repeat(64),
        };
        AuthorizationAdmission::from_verified_proof(proof).expect("structurally valid proof")
    }

    /// 缺失 admission（UserPending）在开启 source 事务之前即被 canonical
    /// dispatcher 拒绝 —— 无 DB 连接也可证明的 fail-closed 合同。
    #[tokio::test]
    async fn user_pending_capability_is_refused_before_any_source_transaction() {
        let pool = MySqlPool::connect_lazy("mysql://invalid@localhost:1/none").unwrap();
        let context = LevelMutationContext::from_policy_context(
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
        assert!(ensure_level_actor_scope_matches(
            &admission_scope(TENANT, CARD, USER, AuthorizationDomainScope::Exact(DOMAIN)),
            CARD,
            USER,
            TENANT,
            DOMAIN
        )
        .is_ok());
        // foreign tenant → 拒绝
        assert!(matches!(
            ensure_level_actor_scope_matches(
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
            ensure_level_actor_scope_matches(
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
            ensure_level_actor_scope_matches(
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
            ensure_level_actor_scope_matches(
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
            ensure_level_actor_scope_matches(
                &admission_scope(TENANT, CARD, USER, AuthorizationDomainScope::Any),
                CARD,
                USER,
                TENANT,
                DOMAIN
            ),
            Err(AstralError::Permission(_))
        ));
        assert!(matches!(
            ensure_level_actor_scope_matches(
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
        assert_eq!(LEVEL_AUDIT_EVENT_TYPE, "TRUSTGRAPH_USER_LEVEL_MUTATION");
        assert!(
            LEVEL_AUDIT_EVENT_TYPE.len() <= 32,
            "audit_log.event_type is VARCHAR(32)"
        );
        assert_eq!(LEVEL_AUDIT_RESOURCE, "user_card_level_definition");
        assert!(
            LEVEL_MUTATION_AUDIT_INSERT_SQL
                .contains("VALUES (?, ?, ?, ?, 'SUCCESS', NULL, ?, ?, ?, ?, ?)"),
            "audit insert must bind every mutable input"
        );
        assert!(
            LEVEL_MUTATION_AUDIT_INSERT_SQL.contains("request_id")
                && LEVEL_MUTATION_AUDIT_INSERT_SQL.contains("event_type"),
            "audit correlation must land in event_type/request_id columns"
        );
    }

    // ── 源序守卫：create/update/delete 事务内锁序与 commit 门 ─────────────

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
            .split(start_marker)
            .nth(2)
            .expect("implementation must exist")
            .split(end_marker)
            .next()
            .expect("body must be delimited")
    }

    #[test]
    fn create_tx_orders_actor_lock_insert_audit_and_commit() {
        let source = include_str!("level_repository.rs");
        let body = impl_segment(
            source,
            "async fn create_level_with_context",
            "async fn update_level_with_context",
        );
        let begin = body
            .find(wrapper_begin_token())
            .expect("create must host the mutation in the proof-bound source wrapper");
        let actor_lock = body
            .find("verify_level_mutation_actor_in_tx(&mut tx, context)")
            .expect("create must bind the actor card facts first");
        let insert = body
            .find("INSERT INTO user_card_level_definition")
            .expect("create must insert on the wrapper connection");
        let audit = body
            .find("insert_level_mutation_audit_in_tx")
            .expect("create must write one audit correlation record");
        let commit = body
            .find("tx.commit_consuming()")
            .expect("create must commit through the wrapper consuming commit");
        assert!(
            begin < actor_lock && actor_lock < insert && insert < audit && audit < commit,
            "create must order: wrapper begin -> actor card lock -> INSERT -> audit -> commit_consuming"
        );
        assert!(
            !body.contains("tx.commit()"),
            "create must not bypass the wrapper's proven-commit gate with a raw commit"
        );
    }

    #[test]
    fn update_tx_orders_actor_lock_target_lock_update_audit_and_commit() {
        let source = include_str!("level_repository.rs");
        let body = impl_segment(
            source,
            "async fn update_level_with_context",
            "async fn delete_level_with_context",
        );
        let begin = body
            .find(wrapper_begin_token())
            .expect("update must host the mutation in the proof-bound source wrapper");
        let actor_lock = body
            .find("verify_level_mutation_actor_in_tx(&mut tx, context)")
            .expect("update must bind the actor card facts first");
        let target_lock = body
            .find("capture_before_in_tx(&TypedSourceRowLookup::PrimaryId { id })")
            .expect("update must capture and lock the target level before mutation");
        let update = body
            .find("builder.build().execute(&mut **tx)")
            .expect("update must mutate the level row on the wrapper connection");
        let audit = body
            .find("insert_level_mutation_audit_in_tx")
            .expect("update must write one audit correlation record");
        let commit = body
            .find("tx.commit_consuming()")
            .expect("update must commit through the wrapper consuming commit");
        assert!(
            begin < actor_lock
                && actor_lock < target_lock
                && target_lock < update
                && update < audit
                && audit < commit,
            "update must order: wrapper begin -> actor card lock -> target lock -> UPDATE -> audit -> commit_consuming"
        );
        assert!(
            !body.contains("tx.commit()"),
            "update must not bypass the wrapper's proven-commit gate with a raw commit"
        );
        // 空补丁 no-op 必须先于任何 source 事务（零 SQL 零副作用）。
        let empty_patch = body
            .find("return Ok(());")
            .expect("empty patch must stay a no-op");
        assert!(
            empty_patch < begin,
            "the empty-patch no-op must be decided before opening a source transaction"
        );
    }

    #[test]
    fn delete_tx_orders_actor_lock_target_lock_delete_audit_and_commit() {
        let source = include_str!("level_repository.rs");
        let body = impl_segment(source, "async fn delete_level_with_context", "fn db_error");
        let begin = body
            .find(wrapper_begin_token())
            .expect("delete must host the mutation in the proof-bound source wrapper");
        let actor_lock = body
            .find("verify_level_mutation_actor_in_tx(&mut tx, context)")
            .expect("delete must bind the actor card facts first");
        let target_lock = body
            .find("capture_before_in_tx(&TypedSourceRowLookup::PrimaryId { id })")
            .expect("delete must capture and lock the target level before mutation");
        let row_delete = body
            .find("DELETE FROM user_card_level_definition WHERE level_id = ?")
            .expect("delete must remove the level row");
        let audit = body
            .find("insert_level_mutation_audit_in_tx")
            .expect("delete must write one audit correlation record");
        let commit = body
            .find("tx.commit_consuming()")
            .expect("delete must commit through the wrapper consuming commit");
        assert!(
            begin < actor_lock
                && actor_lock < target_lock
                && target_lock < row_delete
                && row_delete < audit
                && audit < commit,
            "delete must order: wrapper begin -> actor card lock -> target lock -> DELETE -> audit -> commit_consuming"
        );
        assert!(
            !body.contains("tx.commit()"),
            "delete must not bypass the wrapper's proven-commit gate with a raw commit"
        );
    }

    // ── 范围结论：无 eligibility fanout、级联语义保持、遗留入口 fail-closed ─

    #[test]
    fn level_mutations_have_no_eligibility_fanout_and_legacy_entries_fail_closed() {
        let source = include_str!("level_repository.rs");
        // 等级定义行不参与资格/授权投影（模块头范围结论）：不得登记 ELIGIBILITY
        // 失效、不得追加任何投影 delta/receipt。
        let eligibility_token =
            concat!("append_eligibility_", "projection_with_invalidation_in_tx");
        let stage_token = concat!("stage_projection_", "receipt");
        let record_token = concat!("record_invalidation_", "receipt");
        assert!(
            !source.contains(eligibility_token)
                && !source.contains(stage_token)
                && !source.contains(record_token),
            "user level mutations must not invent eligibility/projection fanout"
        );
        // create/update/delete 全部以 proof-bound source transaction 为宿主。
        assert_eq!(
            source.matches(wrapper_begin_token()).count(),
            3,
            "create/update/delete must each use the proof-bound source wrapper"
        );
        // 遗留无 context mutation 入口一律 fail-closed（trait 默认实现）。
        let legacy = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source must exist");
        assert_eq!(
            legacy.matches("Err(level_context_required())").count(),
            3,
            "legacy create/update/delete must fail closed without a mutation context"
        );
        // actor 卡行与 typed before-image 都必须通过 FOR UPDATE 锁定读（原子守卫）。
        assert!(LEVEL_MUTATION_ACTOR_LOCK_SQL.contains("FOR UPDATE"));
        assert!(source.contains("capture_before_in_tx(&TypedSourceRowLookup::PrimaryId { id })"));
        // 级联语义保持：删除只发一条参数化 DELETE，由既有 FK 级联
        // identity_user_grading；不做手工级联删除、不改删除谓词。
        // （负向 token 用 concat! 拼接，避免测试自身字面量自引用假阳性。）
        assert!(
            source.contains("DELETE FROM user_card_level_definition WHERE level_id = ?"),
            "delete must keep the exact parameterized delete predicate"
        );
        let manual_cascade_token = concat!("DELETE FROM identity_", "user_grading");
        assert!(
            !source.contains(manual_cascade_token),
            "the identity_user_grading cascade must stay a database FK concern"
        );
    }
}
