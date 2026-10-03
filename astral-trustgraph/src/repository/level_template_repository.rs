//! 等级模板数据访问 — LevelTemplateRepository
//!
//! 对齐 Java `IdentityLevelTemplateMapper` 边界（identity_level_template +
//! identity_level_template_resource_map + identity_level_template_action_map）。
//!
//! **范围结论（governance row，2026-10-02 核验）**：identity_level_template 没有
//! 任何 PolicyEngine 数据面消费者（仅 API DTO、`resource_ownership` 的 domain
//! 归属解析与 card_template 的删除引用检查）；等级模板不是 CanonicalGrant 源，
//! 卡片规范授权在发卡/绑定时按其 RULE_SET 绑定物化，之后不从等级模板重导出。
//! 因此 create/update/delete **不产生授权账本 delta，也不再向 retired 旧 CARD
//! 链追加 REVOKE head/outbox**——该扇出在 retired 链路上对生产授权零效果，只
//! 会在 CARD head 上留下无重建来源的"伪撤销"。
//!
//! 但等级模板（尤其 domain_id 绑定）是 owning-binding 存在性 source：
//! resource_ownership 组合内存 resolver 缓存严格 server facts，依赖源活动栅栏
//! 保证 binding 更新的 epoch complete。create/update/delete 因此一律以
//! `AuthorizationSourceTransaction` 为宿主（栅栏先于 DB begin 取得，hub 拒绝
//! 发证即 fail-closed；COMMIT await 前 arm、Ok 证明才 disarm），并落一条覆盖
//! 整个 mutation 的 durable `audit_log` 关联记录（沿用既有同事务机制；不扩面、
//! 不新增审计维度）。

use async_trait::async_trait;
use sqlx::{MySqlPool, QueryBuilder, Transaction};

use astral_types::AstralError;

use crate::repository::audit_log_repository::validated_request_operation_id;
use crate::repository::authorization_source_transaction::AuthorizationSourceTransaction;

/// 等级模板记录（identity_level_template）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LevelTemplateRecord {
    pub template_id: i64,
    pub template_code: String,
    pub template_name: String,
    pub domain_id: i64,
    pub principal_type: String,
    pub grant_type: String,
    pub level_no: i32,
    pub user_card_template_id: Option<i64>,
    pub status: String,
    pub version_no: i32,
    pub force_cover: bool,
    pub description: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// 列表过滤（domain_id / level_no 可选）
#[derive(Debug, Default)]
pub struct LevelTemplateFilter {
    pub domain_id: Option<i64>,
    pub level_no: Option<i32>,
}

/// 部分更新补丁（status 需在白名单校验后传入）
#[derive(Debug, Default)]
pub struct LevelTemplatePatch {
    pub template_name: Option<String>,
    pub principal_type: Option<String>,
    pub grant_type: Option<String>,
    pub level_no: Option<i32>,
    pub user_card_template_id: Option<i64>,
    pub status: Option<String>,
    pub version_no: Option<i32>,
    pub force_cover: Option<bool>,
    pub description: Option<String>,
}

/// 删除结果（级联清理 + 受影响卡）
#[derive(Debug, Clone)]
pub struct DeleteOutcome {
    pub deleted: bool,
    pub affected_card_ids: Vec<i64>,
}

const LT_SELECT_COLUMNS: &str = "template_id, template_code, template_name, domain_id, \
     principal_type, grant_type, level_no, user_card_template_id, status, version_no, \
     force_cover, description, \
     DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at, \
     DATE_FORMAT(updated_at, '%Y-%m-%dT%H:%i:%sZ') as updated_at";

/// 新建等级模板参数
#[derive(Debug, Clone)]
pub struct NewLevelTemplate {
    pub template_code: String,
    pub template_name: String,
    pub domain_id: i64,
    pub principal_type: String,
    pub grant_type: String,
    pub level_no: i32,
    pub user_card_template_id: Option<i64>,
    pub version_no: i32,
    pub force_cover: bool,
    pub description: Option<String>,
}

/// 等级模板授权 mutation 的可信身份上下文（update / delete_with_cascade 共用）。
///
/// - `actor_id` 必须是 Gateway 验证后的 `x-user-id`（正数）；非正数一律 Auth
///   fail-closed。repository 绝不代替调用方发明 actor。
/// - `operation_id` 必须来自显式携带且通过统一持久化安全性校验
///   （`validated_request_operation_id`：长度 ≤ audit 列宽、ASCII 安全集、
///   无控制字符）的 `x-request-id`；缺失、纯空白、超长或非法字符一律
///   fail-closed，绝不静默替换、截断或随机补位。
///
/// 该身份同时写入 CARD REVOKE outbox payload（actorId/operationId，供 projection
/// worker 在快照后审计中复用而不发明 HTTP actor）与同事务 `audit_log` 关联记录
/// 的 request_id/detail，是模板 mutation → 卡片 REVOKE 扇出链路的唯一可关联锚点。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LevelTemplateMutationContext {
    actor_id: i64,
    operation_id: String,
}

impl LevelTemplateMutationContext {
    pub fn new(actor_id: i64, operation_id: &str) -> Result<Self, AstralError> {
        if actor_id <= 0 {
            return Err(AstralError::Auth(
                "level template mutation requires a verified positive actor id".into(),
            ));
        }
        // 统一入口校验：缺失/纯空白 → None；超长或含非安全集字符 → Validation
        // fail-closed。本路径为授权 mutation，缺失 operation id 直接拒绝，
        // 不走 legacy 随机 correlation。
        let validated = validated_request_operation_id(Some(operation_id))?;
        let operation_id = validated.ok_or_else(|| {
            AstralError::Validation(
                "level template mutation requires an explicit request operation id".into(),
            )
        })?;
        Ok(Self {
            actor_id,
            operation_id,
        })
    }

    pub fn actor_id(&self) -> i64 {
        self.actor_id
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
}

/// 审计 action：等级模板部分更新（governance mutation，同事务审计关联）。
const LEVEL_TEMPLATE_AUDIT_ACTION_UPDATE: &str = "level_template_update";
/// 审计 action：等级模板级联删除。
const LEVEL_TEMPLATE_AUDIT_ACTION_DELETE: &str = "level_template_delete";
/// `audit_log.decision` 固定值：模板 mutation 语义（非 CARD 撤销语义——本路径
/// 不追加任何 legacy 投影事件，见模块头范围结论）。
const LEVEL_TEMPLATE_AUDIT_DECISION_UPDATE: &str = "LEVEL_TEMPLATE_UPDATED";
const LEVEL_TEMPLATE_AUDIT_DECISION_DELETE: &str = "LEVEL_TEMPLATE_DELETED";
/// event_type（audit_log.event_type VARCHAR(32)）：等级模板 mutation 家族。
const LEVEL_TEMPLATE_AUDIT_EVENT_TYPE: &str = "LEVEL_TEMPLATE_MUTATION";
/// resource：模板聚合名（单表，无租户列可证明，明细中携带模板身份）。
const LEVEL_TEMPLATE_AUDIT_RESOURCE: &str = "level_template";

/// 审计关联 INSERT（仅绑定参数 + 固定常量；所有可变输入走 `?` 绑定，
/// 绝不拼接请求输入）。decision 按动作以固定常量绑定。
const LEVEL_TEMPLATE_AUDIT_INSERT_SQL: &str = "INSERT INTO audit_log \
     (user_id, card_id, action, resource, decision, reason, event_type, request_id, detail) \
     VALUES (?, NULL, ?, ?, ?, NULL, ?, ?, ?)";

/// 等级模板 mutation 的单条 durable 审计关联输入。
///
/// 一条记录覆盖整个 mutation 与其引用卡范围观测（不是逐卡一条）；
/// `affected_card_ids` 是 mutation 前捕获的引用 ACTIVE 卡集合（仅审计明细
/// 观测——governance mutation 不改卡片授权，见模块头范围结论）。
struct LevelTemplateAuditEntry<'a> {
    action: &'a str,
    decision: &'a str,
    template_id: i64,
    /// 删除路径在锁定读中捕获的模板身份（删除后 source 行不存在，审计是唯一
    /// 可查的 code/name 出处）；update 路径为 None。
    template_code: Option<&'a str>,
    template_name: Option<&'a str>,
    affected_card_ids: &'a [i64],
    /// update 路径实际应用的补丁字段（仅 Some 字段，确定性键序）；delete 为空对象。
    applied_fields: serde_json::Value,
    context: &'a LevelTemplateMutationContext,
}

impl LevelTemplateAuditEntry<'_> {
    /// 结构化审计详情；序列化失败必须阻止事务提交。
    fn detail_json(&self) -> Result<String, AstralError> {
        serde_json::to_string(&serde_json::json!({
            "templateId": self.template_id,
            "templateCode": self.template_code,
            "templateName": self.template_name,
            "operationId": self.context.operation_id(),
            "actorId": self.context.actor_id(),
            "affectedCardIds": self.affected_card_ids,
            "appliedFields": self.applied_fields,
        }))
        .map_err(|error| {
            AstralError::Validation(format!(
                "level template audit detail serialization failed: {error}"
            ))
        })
    }

    /// 纯校验：非空 action/decision、正数模板 id、正数 actor、非空 operation id、
    /// 非负卡片 id。缺失或非法拒绝落库（fail-closed）。
    fn validate(&self) -> Result<(), AstralError> {
        if self.action.trim().is_empty() {
            return Err(AstralError::Validation(
                "level template audit requires a non-empty action".into(),
            ));
        }
        if self.decision.trim().is_empty() {
            return Err(AstralError::Validation(
                "level template audit requires a non-empty decision".into(),
            ));
        }
        if self.template_id <= 0 {
            return Err(AstralError::Validation(
                "level template audit requires a positive template id".into(),
            ));
        }
        if self.context.actor_id() <= 0 {
            return Err(AstralError::Validation(
                "level template audit requires a positive actor id".into(),
            ));
        }
        if self.context.operation_id().trim().is_empty() {
            return Err(AstralError::Validation(
                "level template audit requires a non-empty operation id".into(),
            ));
        }
        for card_id in self.affected_card_ids {
            if *card_id <= 0 {
                return Err(AstralError::Validation(
                    "level template audit scope entries must carry positive card ids".into(),
                ));
            }
        }
        Ok(())
    }
}

/// 把等级模板 mutation 的审计关联写入调用方 source 事务。
///
/// 沿用既有机制：与 source mutation 同事务落 `audit_log`，任何失败回滚整个
/// mutation。不能复用 MQ-first AuditDualWrite：它可能在事务提交后异步落库。
/// `decision` 为按动作固定的 mutation 语义常量（governance mutation，不追加
/// 任何投影事件）。`user_id` 记录执行变更的管理员 actor。
async fn insert_level_template_audit_in_tx(
    tx: &mut Transaction<'_, sqlx::MySql>,
    entry: &LevelTemplateAuditEntry<'_>,
) -> Result<(), AstralError> {
    entry.validate()?;
    let detail = entry.detail_json()?;
    sqlx::query(LEVEL_TEMPLATE_AUDIT_INSERT_SQL)
        .bind(entry.context.actor_id())
        .bind(entry.action)
        .bind(LEVEL_TEMPLATE_AUDIT_RESOURCE)
        .bind(entry.decision)
        .bind(LEVEL_TEMPLATE_AUDIT_EVENT_TYPE)
        .bind(entry.context.operation_id())
        .bind(&detail)
        .execute(&mut **tx)
        .await
        .map_err(|error| {
            AstralError::Database(format!("level template audit insert failed: {error}"))
        })?;
    Ok(())
}

/// update 审计详情中的实际应用字段（仅 Some 字段；键名对齐 DTO camelCase）。
fn applied_patch_fields(patch: &LevelTemplatePatch) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    if let Some(status) = &patch.status {
        object.insert("status".into(), serde_json::json!(status));
    }
    if let Some(name) = &patch.template_name {
        object.insert("templateName".into(), serde_json::json!(name));
    }
    if let Some(desc) = &patch.description {
        object.insert("description".into(), serde_json::json!(desc));
    }
    if let Some(level_no) = patch.level_no {
        object.insert("levelNo".into(), serde_json::json!(level_no));
    }
    if let Some(principal_type) = &patch.principal_type {
        object.insert("principalType".into(), serde_json::json!(principal_type));
    }
    if let Some(grant_type) = &patch.grant_type {
        object.insert("grantType".into(), serde_json::json!(grant_type));
    }
    if let Some(user_card_template_id) = patch.user_card_template_id {
        object.insert(
            "userCardTemplateId".into(),
            serde_json::json!(user_card_template_id),
        );
    }
    if let Some(version_no) = patch.version_no {
        object.insert("versionNo".into(), serde_json::json!(version_no));
    }
    if let Some(force_cover) = patch.force_cover {
        object.insert("forceCover".into(), serde_json::json!(force_cover));
    }
    serde_json::Value::Object(object)
}

#[async_trait]
pub trait LevelTemplateRepository: Send + Sync {
    /// 列表总数（按过滤条件）
    async fn count_templates(&self, filter: &LevelTemplateFilter) -> Result<i64, AstralError>;
    /// 分页列表（ORDER BY template_id）
    async fn list_templates(
        &self,
        filter: &LevelTemplateFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<LevelTemplateRecord>, AstralError>;
    async fn get_template(&self, id: i64) -> Result<Option<LevelTemplateRecord>, AstralError>;
    async fn create_template(&self, new: &NewLevelTemplate) -> Result<i64, AstralError>;
    /// 部分更新（空补丁 no-op）。
    ///
    /// governance mutation（不产生账本 delta、不追加 legacy 投影事件，见模块头
    /// 范围结论）：以授权源事务为宿主（owning-binding 存在性 source 栅栏合同），
    /// 同事务落一条 `context` actor/operation 的 audit_log 关联记录。身份缺失或
    /// 非法时整个 mutation fail-closed。
    async fn update_template(
        &self,
        id: i64,
        patch: &LevelTemplatePatch,
        context: &LevelTemplateMutationContext,
    ) -> Result<(), AstralError>;
    /// 删除：级联清理两表 + 删除模板，返回是否命中与引用卡集合。
    ///
    /// 事务宿主与审计关联语义同 `update_template`；审计详情携带删除前锁定
    /// 读取的模板 code/name（删除后 source 行不存在）。
    async fn delete_with_cascade(
        &self,
        id: i64,
        context: &LevelTemplateMutationContext,
    ) -> Result<DeleteOutcome, AstralError>;
    /// 兼容哨兵（trait 默认 false；本 repository 覆写为 true，见 impl）。
    fn writes_projection_in_transaction(&self) -> bool {
        false
    }
}

pub struct SqlxLevelTemplateRepository {
    db: MySqlPool,
}

impl SqlxLevelTemplateRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

/// 追加过滤条件（列表与总数共用）
fn push_filter<'args>(
    builder: &mut QueryBuilder<'args, sqlx::MySql>,
    filter: &LevelTemplateFilter,
) {
    if let Some(domain_id) = filter.domain_id {
        builder.push(" AND domain_id = ").push_bind(domain_id);
    }
    if let Some(level_no) = filter.level_no {
        builder.push(" AND level_no = ").push_bind(level_no);
    }
}

/// 引用 ACTIVE 卡集合（audit 明细 scope 捕获，卡片 id 升序确定性）。
/// governance mutation 不改卡片授权（模块头范围结论），此读取**不加锁**、
/// 不驱动任何扇出——仅为审计明细提供引用卡集合观测。行数以 `LIMIT ?` 约束
/// （绑定值 = cap + 1，多取一行仅用于判定超限），绝不产生无界内存响应。
const AFFECTED_CARDS_SCOPE_SQL: &str = "SELECT DISTINCT uc.card_id FROM user_card uc \
     WHERE uc.template_id IN ( \
       SELECT user_card_template_id FROM identity_level_template WHERE template_id = ? \
     ) AND uc.card_status = 'ACTIVE' ORDER BY uc.card_id LIMIT ?";

/// 引用卡 scope 捕获的每事务上限：候选数超过上限即 Validation fail-closed、
/// 在**任何 source mutation 之前**整体拒绝（事务随 Err 回滚），绝不部分审计、
/// 绝不让 audit/响应 Vec 变成无界内存。与租户 ELIGIBILITY fanout 同一形状。
const LEVEL_TEMPLATE_AFFECTED_CARDS_CAP: usize = 512;

/// scope 捕获读取的行数上界（cap + 1：多取一行仅用于在单次读内判定超限）。
fn affected_card_scope_bound() -> i64 {
    LEVEL_TEMPLATE_AFFECTED_CARDS_CAP as i64 + 1
}

/// scope 捕获的容量守卫（纯函数，便于单测）：捕获行数超过 cap 即 fail-closed。
fn guard_affected_card_scope(captured: usize, template_id: i64) -> Result<(), AstralError> {
    if captured > LEVEL_TEMPLATE_AFFECTED_CARDS_CAP {
        return Err(AstralError::Validation(format!(
            "level template {template_id} referencing-card scope captured {captured} rows, \
             exceeding the per-transaction cap ({LEVEL_TEMPLATE_AFFECTED_CARDS_CAP}); \
             failing closed before any source mutation instead of an unbounded audit vector"
        )));
    }
    Ok(())
}

/// 引用卡 scope 捕获（update/delete 共用）：行数受限读取 + 容量守卫。
/// 必须在调用方的任何 source mutation 之前调用——超限 Err 即整体回滚，
/// 绝不先写后审。governance mutation 不加卡锁（模块头范围结论）。
async fn capture_affected_card_scope_in_tx(
    tx: &mut AuthorizationSourceTransaction,
    template_id: i64,
) -> Result<Vec<i64>, AstralError> {
    let affected_card_ids: Vec<i64> = sqlx::query_scalar(AFFECTED_CARDS_SCOPE_SQL)
        .bind(template_id)
        .bind(affected_card_scope_bound())
        .fetch_all(&mut ***tx)
        .await
        .map_err(db_error)?;
    guard_affected_card_scope(affected_card_ids.len(), template_id)?;
    Ok(affected_card_ids)
}

#[async_trait]
impl LevelTemplateRepository for SqlxLevelTemplateRepository {
    /// 覆写哨兵：本 repository 在自身事务内闭环处理全部副作用（无 post-commit
    /// 补偿）。retired 旧 CARD REVOKE 链路已随范围结论移除；保持 `true` 防止
    /// service 旧补偿路径（`request_card_projection("REVOKE")`，同为 retired
    /// 无效果链路）被重新激活。
    fn writes_projection_in_transaction(&self) -> bool {
        true
    }

    async fn count_templates(&self, filter: &LevelTemplateFilter) -> Result<i64, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(
            "SELECT COUNT(*) FROM identity_level_template WHERE 1=1",
        );
        push_filter(&mut builder, filter);
        builder
            .build_query_scalar::<i64>()
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_templates(
        &self,
        filter: &LevelTemplateFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<LevelTemplateRecord>, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(&format!(
            "SELECT {LT_SELECT_COLUMNS} FROM identity_level_template WHERE 1=1"
        ));
        push_filter(&mut builder, filter);
        builder
            .push(" ORDER BY template_id LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        builder
            .build_query_as::<LevelTemplateRecord>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn get_template(&self, id: i64) -> Result<Option<LevelTemplateRecord>, AstralError> {
        sqlx::query_as::<_, LevelTemplateRecord>(&format!(
            "SELECT {LT_SELECT_COLUMNS} FROM identity_level_template WHERE template_id = ?"
        ))
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create_template(&self, new: &NewLevelTemplate) -> Result<i64, AstralError> {
        // 授权源事务宿主：等级模板（domain 绑定）是 owning-binding 存在性
        // source，resource_ownership resolver 缓存严格 server facts，源活动
        // 栅栏保证 binding 更新的 epoch complete（见模块头范围结论）。
        let mut tx = AuthorizationSourceTransaction::begin(&self.db).await?;
        let result = sqlx::query(
            "INSERT INTO identity_level_template \
             (template_code, template_name, domain_id, principal_type, grant_type, level_no, \
              user_card_template_id, status, version_no, force_cover, description) \
             VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?)",
        )
        .bind(&new.template_code)
        .bind(&new.template_name)
        .bind(new.domain_id)
        .bind(&new.principal_type)
        .bind(&new.grant_type)
        .bind(new.level_no)
        .bind(new.user_card_template_id)
        .bind(new.version_no)
        .bind(new.force_cover)
        .bind(&new.description)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
        let new_id = result.last_insert_id() as i64;
        tx.commit_consuming().await?;
        Ok(new_id)
    }

    async fn update_template(
        &self,
        id: i64,
        patch: &LevelTemplatePatch,
        context: &LevelTemplateMutationContext,
    ) -> Result<(), AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new("UPDATE identity_level_template SET ");
        let mut first = true;
        if let Some(status) = &patch.status {
            if !first {
                builder.push(", ");
            }
            builder.push("status = ").push_bind(status.clone());
            first = false;
        }
        if let Some(name) = &patch.template_name {
            if !first {
                builder.push(", ");
            }
            builder.push("template_name = ").push_bind(name.clone());
            first = false;
        }
        if let Some(desc) = &patch.description {
            if !first {
                builder.push(", ");
            }
            builder.push("description = ").push_bind(desc.clone());
            first = false;
        }
        if let Some(level_no) = patch.level_no {
            if !first {
                builder.push(", ");
            }
            builder.push("level_no = ").push_bind(level_no);
            first = false;
        }
        if let Some(principal_type) = &patch.principal_type {
            if !first {
                builder.push(", ");
            }
            builder
                .push("principal_type = ")
                .push_bind(principal_type.clone());
            first = false;
        }
        if let Some(grant_type) = &patch.grant_type {
            if !first {
                builder.push(", ");
            }
            builder.push("grant_type = ").push_bind(grant_type.clone());
            first = false;
        }
        if let Some(user_card_template_id) = patch.user_card_template_id {
            if !first {
                builder.push(", ");
            }
            builder
                .push("user_card_template_id = ")
                .push_bind(user_card_template_id);
            first = false;
        }
        if let Some(version_no) = patch.version_no {
            if !first {
                builder.push(", ");
            }
            builder.push("version_no = ").push_bind(version_no);
            first = false;
        }
        if let Some(force_cover) = patch.force_cover {
            if !first {
                builder.push(", ");
            }
            builder.push("force_cover = ").push_bind(force_cover);
            first = false;
        }
        if first {
            return Ok(());
        }
        builder.push(" WHERE template_id = ").push_bind(id);

        // governance mutation（模块头范围结论）：不改任何卡片授权、不产生账本
        // delta、不追加 legacy 投影事件。事务宿主为授权源事务（owning-binding
        // 存在性 source 的栅栏合同）；mutation 前捕获引用 ACTIVE 卡集合仅作
        // 审计明细 scope 观测（行数受限 + 容量守卫，超限在任何写入前拒绝）。
        let mut tx = AuthorizationSourceTransaction::begin(&self.db).await?;
        let affected_card_ids = capture_affected_card_scope_in_tx(&mut tx, id).await?;

        let result = builder.build().execute(&mut **tx).await.map_err(db_error)?;
        if result.rows_affected() == 0 {
            // 模板不存在或补丁值与现值完全一致（MySQL 计变更行）：未发生
            // mutation，无审计变更；保持既有 no-op 语义，由 handler 的
            // get_template 决定 404。
            tx.commit_consuming().await?;
            return Ok(());
        }

        insert_level_template_audit_in_tx(
            &mut tx,
            &LevelTemplateAuditEntry {
                action: LEVEL_TEMPLATE_AUDIT_ACTION_UPDATE,
                decision: LEVEL_TEMPLATE_AUDIT_DECISION_UPDATE,
                template_id: id,
                template_code: None,
                template_name: None,
                affected_card_ids: &affected_card_ids,
                applied_fields: applied_patch_fields(patch),
                context,
            },
        )
        .await?;
        tx.commit_consuming().await?;
        Ok(())
    }

    async fn delete_with_cascade(
        &self,
        id: i64,
        context: &LevelTemplateMutationContext,
    ) -> Result<DeleteOutcome, AstralError> {
        // 授权源事务宿主（owning-binding 存在性 source，见模块头范围结论）。
        let mut tx = AuthorizationSourceTransaction::begin(&self.db).await?;
        // 引用 ACTIVE 卡集合（audit 明细 scope 观测）：删除前捕获，删除后
        // 模板行不存在无法重算；行数受限 + 容量守卫（超限在任何级联删除前
        // 拒绝回滚），不加锁、不驱动扇出。
        let affected_card_ids = capture_affected_card_scope_in_tx(&mut tx, id).await?;

        // 锁定读取模板身份用于删除后仍可追溯的审计 provenance。
        let template: Option<(String, String)> = sqlx::query_as(
            "SELECT template_code, template_name FROM identity_level_template \
             WHERE template_id = ? FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_error)?;
        let Some((template_code, template_name)) = template else {
            // 模板不存在：保持既有 not-deleted 语义（事务内无 mutation，
            // 不产生审计记录）。
            tx.commit_consuming().await?;
            return Ok(DeleteOutcome {
                deleted: false,
                affected_card_ids: Vec::new(),
            });
        };

        sqlx::query("DELETE FROM identity_level_template_resource_map WHERE template_id = ?")
            .bind(id)
            .execute(&mut **tx)
            .await
            .map_err(db_error)?;

        sqlx::query("DELETE FROM identity_level_template_action_map WHERE template_id = ?")
            .bind(id)
            .execute(&mut **tx)
            .await
            .map_err(db_error)?;

        let result = sqlx::query("DELETE FROM identity_level_template WHERE template_id = ?")
            .bind(id)
            .execute(&mut **tx)
            .await
            .map_err(db_error)?;
        if result.rows_affected() == 0 {
            // 锁定读已证明行存在，删除 0 行属于不可能状态：fail-closed 回滚，
            // 绝不静默报告 not-deleted 掩盖不一致。
            return Err(AstralError::Internal(
                "level template delete applied zero rows after a locked read".into(),
            ));
        }

        insert_level_template_audit_in_tx(
            &mut tx,
            &LevelTemplateAuditEntry {
                action: LEVEL_TEMPLATE_AUDIT_ACTION_DELETE,
                decision: LEVEL_TEMPLATE_AUDIT_DECISION_DELETE,
                template_id: id,
                template_code: Some(&template_code),
                template_name: Some(&template_name),
                affected_card_ids: &affected_card_ids,
                applied_fields: serde_json::Value::Object(serde_json::Map::new()),
                context,
            },
        )
        .await?;
        tx.commit_consuming().await?;

        Ok(DeleteOutcome {
            deleted: true,
            affected_card_ids,
        })
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Level template repository query failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 身份上下文：actor 非正 → Auth fail-closed；operation id 缺失/纯空白/
    /// 非法字符/超长 → Validation fail-closed；合法输入原样保留。
    #[test]
    fn mutation_context_fails_closed_on_missing_or_invalid_identity() {
        // actor 必须是 Gateway 验证的正数
        assert!(matches!(
            LevelTemplateMutationContext::new(0, "req-1"),
            Err(AstralError::Auth(_))
        ));
        assert!(matches!(
            LevelTemplateMutationContext::new(-7, "req-1"),
            Err(AstralError::Auth(_))
        ));
        // operation id 缺失或纯空白 → 拒绝（授权 mutation 无随机 fallback）
        assert!(matches!(
            LevelTemplateMutationContext::new(1, ""),
            Err(AstralError::Validation(_))
        ));
        assert!(matches!(
            LevelTemplateMutationContext::new(1, "   "),
            Err(AstralError::Validation(_))
        ));
        // 非安全集字符（空格/叹号）→ 拒绝，绝不静默归一化
        assert!(matches!(
            LevelTemplateMutationContext::new(1, "req id!"),
            Err(AstralError::Validation(_))
        ));
        // 超过 audit_log.request_id 宽度（64）→ 拒绝，绝不截断
        assert!(LevelTemplateMutationContext::new(1, "a".repeat(64).as_str()).is_ok());
        assert!(matches!(
            LevelTemplateMutationContext::new(1, "a".repeat(65).as_str()),
            Err(AstralError::Validation(_))
        ));
        // 合法输入：actor 与 operation id 原样保留
        let context = LevelTemplateMutationContext::new(42, "req-abc_123:45/6.7").unwrap();
        assert_eq!(context.actor_id(), 42);
        assert_eq!(context.operation_id(), "req-abc_123:45/6.7");
    }

    /// 审计详情：确定性 JSON，携带模板身份、operation/actor、引用卡范围与
    /// 应用的补丁字段；删除路径携带删除前捕获的 code/name。
    #[test]
    fn audit_entry_detail_is_deterministic_and_complete() {
        let context = LevelTemplateMutationContext::new(9, "op-1").unwrap();
        let update_entry = LevelTemplateAuditEntry {
            action: LEVEL_TEMPLATE_AUDIT_ACTION_UPDATE,
            decision: LEVEL_TEMPLATE_AUDIT_DECISION_UPDATE,
            template_id: 3,
            template_code: None,
            template_name: None,
            affected_card_ids: &[11, 7],
            applied_fields: applied_patch_fields(&LevelTemplatePatch {
                status: Some("INACTIVE".into()),
                level_no: Some(4),
                ..Default::default()
            }),
            context: &context,
        };
        let detail = update_entry.detail_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&detail).unwrap();
        assert_eq!(parsed["templateId"], 3);
        assert_eq!(parsed["operationId"], "op-1");
        assert_eq!(parsed["actorId"], 9);
        // 引用卡集合按调用方顺序原样保留（scope 观测，无事件配对）
        assert_eq!(parsed["affectedCardIds"], serde_json::json!([11, 7]));
        assert!(parsed.get("projectionEventIds").is_none());
        assert_eq!(parsed["appliedFields"]["status"], "INACTIVE");
        assert_eq!(parsed["appliedFields"]["levelNo"], 4);
        assert!(parsed["appliedFields"].get("templateName").is_none());
        // update 路径不捕获模板 code/name（仅删除路径锁定读取）
        assert!(parsed["templateCode"].is_null());
        assert!(parsed["templateName"].is_null());
        // 两次序列化结果一致（确定性）
        assert_eq!(update_entry.detail_json().unwrap(), detail);

        let delete_entry = LevelTemplateAuditEntry {
            action: LEVEL_TEMPLATE_AUDIT_ACTION_DELETE,
            decision: LEVEL_TEMPLATE_AUDIT_DECISION_DELETE,
            template_id: 3,
            template_code: Some("LT_CODE"),
            template_name: Some("LT_NAME"),
            affected_card_ids: &[],
            applied_fields: serde_json::Value::Object(serde_json::Map::new()),
            context: &context,
        };
        let parsed: serde_json::Value =
            serde_json::from_str(&delete_entry.detail_json().unwrap()).unwrap();
        assert_eq!(parsed["templateCode"], "LT_CODE");
        assert_eq!(parsed["templateName"], "LT_NAME");
        assert_eq!(parsed["affectedCardIds"], serde_json::json!([]));
    }

    /// 审计校验 fail-closed：空 action/decision / 非正模板 id / 非正卡 id /
    /// 非正 actor / 空 operation id 一律拒绝。
    #[test]
    fn audit_entry_validation_is_fail_closed() {
        // 统一构造 helper：生命周期与调用方局部值绑定，避免泄漏/静态提升。
        fn entry<'a>(
            action: &'a str,
            decision: &'a str,
            template_id: i64,
            affected: &'a [i64],
            context: &'a LevelTemplateMutationContext,
        ) -> LevelTemplateAuditEntry<'a> {
            LevelTemplateAuditEntry {
                action,
                decision,
                template_id,
                template_code: None,
                template_name: None,
                affected_card_ids: affected,
                applied_fields: serde_json::Value::Object(serde_json::Map::new()),
                context,
            }
        }

        let context = LevelTemplateMutationContext::new(9, "op-1").unwrap();
        let ok_cards = [7i64];
        assert!(entry(
            LEVEL_TEMPLATE_AUDIT_ACTION_UPDATE,
            LEVEL_TEMPLATE_AUDIT_DECISION_UPDATE,
            3,
            &ok_cards,
            &context
        )
        .validate()
        .is_ok());
        assert!(entry(
            LEVEL_TEMPLATE_AUDIT_ACTION_DELETE,
            LEVEL_TEMPLATE_AUDIT_DECISION_DELETE,
            3,
            &[],
            &context
        )
        .validate()
        .is_ok());

        let empty_action = entry(" ", LEVEL_TEMPLATE_AUDIT_DECISION_UPDATE, 3, &[], &context);
        assert!(empty_action.validate().is_err());

        let empty_decision = entry(LEVEL_TEMPLATE_AUDIT_ACTION_UPDATE, "  ", 3, &[], &context);
        assert!(empty_decision.validate().is_err());

        let zero_template = entry(
            LEVEL_TEMPLATE_AUDIT_ACTION_DELETE,
            LEVEL_TEMPLATE_AUDIT_DECISION_DELETE,
            0,
            &[],
            &context,
        );
        assert!(zero_template.validate().is_err());

        let zero_card = entry(
            LEVEL_TEMPLATE_AUDIT_ACTION_DELETE,
            LEVEL_TEMPLATE_AUDIT_DECISION_DELETE,
            3,
            &[0i64],
            &context,
        );
        assert!(zero_card.validate().is_err());
    }

    /// 源序守卫：update 事务内必须以授权源事务 begin 开场（owning-binding
    /// 存在性 source 栅栏合同），捕获引用卡 scope，执行 UPDATE，随后同事务
    /// 审计关联与 commit_consuming；绝不退回 legacy CARD REVOKE 扇出。
    #[test]
    fn update_tx_orders_wrapper_scope_audit_and_commit() {
        let source = include_str!("level_template_repository.rs");
        let update_body = source
            .split("async fn update_template")
            // 该字符串出现 3 次（trait 声明 / impl 实现 / 本测试的字面量）；
            // nth(2) 才是 impl 实现体段。
            .nth(2)
            .expect("update_template implementation must exist")
            .split("async fn delete_with_cascade")
            // 实现体段内第一个 delete_with_cascade 是同 impl 的 delete 声明，
            // next() 截到它之前 = 纯 update 实现体。
            .next()
            .expect("update_template body must be delimited");
        let wrapper_begin = update_body
            // 自引用防呆：拼接构造 joined token，避免本测试字面量污染
            // governance_row 测试的整文件出现次数统计。
            .find(concat!(
                "AuthorizationSourceTransaction::",
                "begin(&self.db)"
            ))
            .expect("update must host the governance mutation in the source wrapper");
        let scope = update_body
            .find("capture_affected_card_scope_in_tx")
            .expect("update must capture the referencing-card scope (bounded) for audit detail");
        let source_update = update_body
            // 锚定执行点而非 QueryBuilder 构造文本：UPDATE 语句字符串在事务
            // 开始前就由 QueryBuilder 持有，"先捕获后执行"的顺序只能以
            // build().execute() 的位置为准。
            .find("builder.build().execute(&mut **tx)")
            .expect("update must mutate the template row on the wrapper connection");
        let audit = update_body
            .find("insert_level_template_audit_in_tx")
            .expect("update must write one audit correlation record");
        // update 存在 no-op 分支的提前 commit；最终 commit 必须在审计之后。
        let commit = update_body
            .rfind("tx.commit_consuming()")
            .expect("update must commit through the wrapper consuming commit");
        assert!(
            wrapper_begin < scope && scope < source_update && source_update < audit && audit < commit,
            "update must order: wrapper begin -> card scope read -> source UPDATE -> audit -> commit_consuming"
        );
        assert!(
            !update_body.contains("tx.commit()"),
            "update must not bypass the wrapper's proven-commit gate with a raw commit"
        );
    }

    /// 源序守卫：delete 事务内必须以授权源事务 begin 开场，捕获引用卡 scope，
    /// 锁定读取模板 provenance，随后级联删除、审计关联与 commit_consuming；
    /// 绝不退回 legacy CARD REVOKE 扇出。
    #[test]
    fn delete_tx_orders_wrapper_scope_provenance_deletes_audit_and_commit() {
        let source = include_str!("level_template_repository.rs");
        let delete_body = source
            .split("async fn delete_with_cascade")
            // 该字符串出现 4 次（trait 声明 / impl 实现 / 两个测试的字面量）；
            // nth(2) 才是 impl 实现体段（到下一个测试字面量前）。
            .nth(2)
            .expect("delete_with_cascade implementation must exist")
            // 在 db_error 前截断，排除本测试模块的源码字面量干扰。
            .split("fn db_error")
            .next()
            .expect("delete_with_cascade body must be delimited");
        let wrapper_begin = delete_body
            // 自引用防呆：拼接构造 joined token（同 update 测试注释）。
            .find(concat!(
                "AuthorizationSourceTransaction::",
                "begin(&self.db)"
            ))
            .expect("delete must host the governance mutation in the source wrapper");
        let scope = delete_body
            .find("capture_affected_card_scope_in_tx")
            .expect("delete must capture the referencing-card scope (bounded) for audit detail");
        let provenance = delete_body
            .find("SELECT template_code, template_name FROM identity_level_template")
            .expect("delete must capture template provenance under lock");
        let map_delete = delete_body
            .find("DELETE FROM identity_level_template_resource_map WHERE template_id = ?")
            .expect("delete must cascade the resource map");
        let row_delete = delete_body
            .find("DELETE FROM identity_level_template WHERE template_id = ?")
            .expect("delete must remove the template row");
        let audit = delete_body
            .find("insert_level_template_audit_in_tx")
            .expect("delete must write one audit correlation record");
        let commit = delete_body
            // rfind：delete 实现内有两个 commit_consuming（not-found 短路分支 +
            // 最终提交）；序守卫必须锚定最终提交。
            .rfind("tx.commit_consuming()")
            .expect("delete must commit through the wrapper consuming commit");
        assert!(
            wrapper_begin < scope
                && scope < provenance
                && provenance < map_delete
                && map_delete < row_delete
                && row_delete < audit
                && audit < commit,
            "delete must order: wrapper begin -> card scope read -> provenance -> cascades -> audit -> commit_consuming"
        );
        assert!(
            !delete_body.contains("tx.commit()"),
            "delete must not bypass the wrapper's proven-commit gate with a raw commit"
        );
    }

    /// governance-row 范围结论（2026-10-02）：等级模板 mutation 不产生授权账本
    /// delta/revision（模板不是 CanonicalGrant 源，无 PolicyEngine 数据面消费者），
    /// 也不追加任何 legacy 投影事件（retired 旧 CARD REVOKE 链路对生产授权
    /// 零效果）；create/update/delete 全部以授权源事务为宿主。
    #[test]
    fn governance_row_has_no_ledger_delta_and_no_legacy_projection() {
        let source = include_str!("level_template_repository.rs");
        // 自引用防呆：token 必须拼接构造。include_str! 会把本测试模块自身的
        // 源码包含进 source，直接书写完整字面量会让 contains 恒真、守卫失效。
        let revision_token = concat!("authorization_grant_", "revision");
        let delta_token = concat!("authorization_delta_", "event");
        let adapter_token = concat!("grant_", "ledger");
        let card_projection_token = concat!("append_card_", "projection");
        let card_revoke_token = concat!("append_card_revokes_", "with_metadata_in_tx");
        let event_type_revoke_token = concat!("EVENT_TYPE_", "REVOKE");
        assert!(
            !source.contains(revision_token)
                && !source.contains(delta_token)
                && !source.contains(adapter_token),
            "level template mutations must not invent ledger deltas"
        );
        assert!(
            !source.contains(card_projection_token)
                && !source.contains(card_revoke_token)
                && !source.contains(event_type_revoke_token),
            "level template mutations must not emit legacy CARD projection/REVOKE events"
        );
        // create/update/delete 全部以授权源事务为宿主（owning-binding 存在性
        // source 的栅栏合同）。
        let begin_token = concat!("AuthorizationSourceTransaction::", "begin(&self.db)");
        assert_eq!(
            source.matches(begin_token).count(),
            3,
            "create/update/delete must each host their mutation in the source wrapper"
        );
        // 全部可变输入走绑定参数；decision/resource/event_type 为固定常量按动作绑定。
        assert!(
            LEVEL_TEMPLATE_AUDIT_INSERT_SQL.contains("VALUES (?, NULL, ?, ?, ?, NULL, ?, ?, ?)")
        );
        assert!(
            LEVEL_TEMPLATE_AUDIT_INSERT_SQL.contains("event_type")
                && LEVEL_TEMPLATE_AUDIT_INSERT_SQL.contains("request_id"),
            "audit correlation must land in event_type/request_id columns"
        );
        assert_eq!(LEVEL_TEMPLATE_AUDIT_RESOURCE, "level_template");
        assert_eq!(LEVEL_TEMPLATE_AUDIT_EVENT_TYPE, "LEVEL_TEMPLATE_MUTATION");
        assert_eq!(LEVEL_TEMPLATE_AUDIT_ACTION_UPDATE, "level_template_update");
        assert_eq!(LEVEL_TEMPLATE_AUDIT_ACTION_DELETE, "level_template_delete");
        assert_eq!(
            LEVEL_TEMPLATE_AUDIT_DECISION_UPDATE,
            "LEVEL_TEMPLATE_UPDATED"
        );
        assert_eq!(
            LEVEL_TEMPLATE_AUDIT_DECISION_DELETE,
            "LEVEL_TEMPLATE_DELETED"
        );
        // scope 捕获读取必须行数受限（LIMIT ?，cap+1）且不加锁：audit 观测
        // 不产生无界内存，也不构成锁 fanout（governance mutation 不改卡授权）。
        assert!(
            AFFECTED_CARDS_SCOPE_SQL.contains("LIMIT ?"),
            "card scope capture must be row-bounded for a finite audit vector"
        );
        assert!(
            !AFFECTED_CARDS_SCOPE_SQL.contains("FOR UPDATE"),
            "card scope capture is an audit-observability read, not a lock fanout"
        );
    }

    /// 引用卡 scope 容量守卫：bound = cap + 1（单次读内判定超限）；捕获数
    /// 超 cap 即 Validation fail-closed（在任何 source mutation 之前拒绝），
    /// cap 内放行；错误消息携带模板身份与超限事实。
    #[test]
    fn affected_card_scope_is_bounded_with_pre_mutation_reject() {
        const { assert!(LEVEL_TEMPLATE_AFFECTED_CARDS_CAP > 0) };
        assert_eq!(
            affected_card_scope_bound(),
            LEVEL_TEMPLATE_AFFECTED_CARDS_CAP as i64 + 1,
            "scope read bound must be cap + 1 so exceeding the cap is detectable in one read"
        );
        assert!(guard_affected_card_scope(0, 9).is_ok());
        assert!(guard_affected_card_scope(LEVEL_TEMPLATE_AFFECTED_CARDS_CAP, 9).is_ok());
        let err = guard_affected_card_scope(LEVEL_TEMPLATE_AFFECTED_CARDS_CAP + 1, 9)
            .expect_err("over-cap capture must fail closed");
        assert!(matches!(err, AstralError::Validation(_)));
        let message = err.to_string();
        assert!(message.contains('9'), "message must name the template");
        assert!(
            message.contains("before any source mutation"),
            "message must state the pre-mutation rejection contract"
        );
    }
}
