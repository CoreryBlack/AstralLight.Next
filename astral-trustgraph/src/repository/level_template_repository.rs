//! 等级模板数据访问 — LevelTemplateRepository
//!
//! 对齐 Java `IdentityLevelTemplateMapper` 边界（identity_level_template +
//! identity_level_template_resource_map + identity_level_template_action_map）。
//!
//! `update_template` / `delete_with_cascade` 是授权语义 mutation：同一 source
//! 事务内锁定受影响 ACTIVE 卡、写入带可信 actor/operation metadata 的 CARD
//! REVOKE head/outbox，并落一条覆盖整个 mutation/fanout 的 durable `audit_log`
//! 关联记录（沿用 `insert_approval_audit_in_tx` / `insert_user_card_cascade_audit_in_tx`
//! 的同事务机制）。等级模板不产生授权账本 delta（模板本身不是 CanonicalGrant）。

use async_trait::async_trait;
use sqlx::{MySqlPool, QueryBuilder, Transaction};

use astral_db::ProjectionEventMetadata;
use astral_types::AstralError;

use crate::repository::audit_log_repository::validated_request_operation_id;
use crate::repository::projection_repository::append_card_projection_with_metadata_in_tx;

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

/// 审计 action：等级模板部分更新（授权语义字段变更触发卡片 REVOKE 扇出）。
const LEVEL_TEMPLATE_AUDIT_ACTION_UPDATE: &str = "level_template_update";
/// 审计 action：等级模板级联删除。
const LEVEL_TEMPLATE_AUDIT_ACTION_DELETE: &str = "level_template_delete";
/// event_type（audit_log.event_type VARCHAR(32)）：等级模板授权 mutation 家族。
const LEVEL_TEMPLATE_AUDIT_EVENT_TYPE: &str = "LEVEL_TEMPLATE_MUTATION";
/// resource：模板聚合名（单表，无租户列可证明，明细中携带模板身份）。
const LEVEL_TEMPLATE_AUDIT_RESOURCE: &str = "level_template";

/// 审计关联 INSERT（仅绑定参数 + 固定 decision 常量；所有可变输入走 `?` 绑定，
/// 绝不拼接请求输入）。`decision` 与扇出的父 CARD REVOKE 投影事件语义对齐
/// （沿用 insert_user_card_cascade_audit_in_tx 的固定 decision 先例）。
const LEVEL_TEMPLATE_AUDIT_INSERT_SQL: &str = "INSERT INTO audit_log \
     (user_id, card_id, action, resource, decision, reason, event_type, request_id, detail) \
     VALUES (?, NULL, ?, ?, 'CARD_REVOKED', NULL, ?, ?, ?)";

/// 等级模板 mutation/fanout 的单条 durable 审计关联输入。
///
/// 一条记录覆盖整个 mutation 与全部卡片 REVOKE 扇出（不是逐卡一条）；
/// `projection_event_ids` 与 `affected_card_ids` 必须一一对应（每张锁定卡恰好
/// 一个 REVOKE 事件），缺失或错位一律拒绝落库。
struct LevelTemplateAuditEntry<'a> {
    action: &'a str,
    template_id: i64,
    /// 删除路径在锁定读中捕获的模板身份（删除后 source 行不存在，审计是唯一
    /// 可查的 code/name 出处）；update 路径为 None。
    template_code: Option<&'a str>,
    template_name: Option<&'a str>,
    affected_card_ids: &'a [i64],
    projection_event_ids: &'a [String],
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
            "projectionEventIds": self.projection_event_ids,
            "appliedFields": self.applied_fields,
        }))
        .map_err(|error| {
            AstralError::Validation(format!(
                "level template audit detail serialization failed: {error}"
            ))
        })
    }

    /// 纯校验：正数模板 id、非空 action、正数 actor、非空 operation id、
    /// 正数卡片 id 且与投影事件号一一对应。缺失或错位拒绝落库（fail-closed）。
    fn validate(&self) -> Result<(), AstralError> {
        if self.action.trim().is_empty() {
            return Err(AstralError::Validation(
                "level template audit requires a non-empty action".into(),
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
        if self.affected_card_ids.len() != self.projection_event_ids.len() {
            return Err(AstralError::Validation(
                "level template audit requires one REVOKE projection event id per affected card \
                 (card ids and event ids must align)"
                    .into(),
            ));
        }
        for (card_id, event_id) in self
            .affected_card_ids
            .iter()
            .zip(self.projection_event_ids.iter())
        {
            if *card_id <= 0 || event_id.trim().is_empty() {
                return Err(AstralError::Validation(
                    "level template audit fanout entries must carry positive card ids \
                     and non-empty projection event ids"
                        .into(),
                ));
            }
        }
        Ok(())
    }
}

/// 把等级模板 mutation/fanout 的审计关联写入调用方 source 事务。
///
/// 沿用 `insert_approval_audit_in_tx` / `insert_user_card_cascade_audit_in_tx` 的
/// 既有机制：与 source mutation、CARD head/outbox 同事务落 `audit_log`，任何失败
/// 回滚整个 mutation。不能复用 MQ-first AuditDualWrite：它可能在事务提交后异步落库。
/// `decision` 与扇出的父 CARD REVOKE 投影事件语义对齐（mutation 类语义；实际扇出
/// 范围见 detail.affectedCardIds，可能为空）。`user_id` 记录执行变更的管理员 actor。
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

/// 对受影响 ACTIVE 卡逐张追加带 metadata 的 CARD REVOKE head/outbox，
/// 返回与卡序一一对应的 durable 事件号（供同事务审计关联）。调用方持有事务；
/// 本函数不 commit、不触碰 Redis/MQ。
async fn append_card_revokes_with_metadata_in_tx(
    tx: &mut Transaction<'_, sqlx::MySql>,
    affected_card_ids: &[i64],
    context: &LevelTemplateMutationContext,
) -> Result<Vec<String>, AstralError> {
    let metadata = ProjectionEventMetadata {
        actor_id: context.actor_id(),
        operation_id: context.operation_id(),
    };
    let mut projection_event_ids = Vec::with_capacity(affected_card_ids.len());
    for card_id in affected_card_ids {
        let identity =
            append_card_projection_with_metadata_in_tx(tx, *card_id, "REVOKE", metadata).await?;
        projection_event_ids.push(identity.event_id);
    }
    Ok(projection_event_ids)
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
    /// 非空补丁是授权 mutation：同一事务内锁定受影响 ACTIVE 卡、写入带
    /// `context` actor/operation metadata 的 CARD REVOKE head/outbox，并落一条
    /// audit_log 关联记录。身份缺失或非法时整个 mutation fail-closed。
    async fn update_template(
        &self,
        id: i64,
        patch: &LevelTemplatePatch,
        context: &LevelTemplateMutationContext,
    ) -> Result<(), AstralError>;
    /// 删除：级联清理两表 + 删除模板，返回是否命中与受影响卡。
    ///
    /// 授权 mutation 语义同 `update_template`（metadata REVOKE + 同事务审计关联）；
    /// 审计详情携带删除前锁定读取的模板 code/name（删除后 source 行不存在）。
    async fn delete_with_cascade(
        &self,
        id: i64,
        context: &LevelTemplateMutationContext,
    ) -> Result<DeleteOutcome, AstralError>;
    /// 是否由删除聚合在同一事务内追加卡片 projection。
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

/// 锁定受影响 ACTIVE 卡（卡片 id 升序，扇出与审计详情确定性）。
const LOCK_AFFECTED_CARDS_SQL: &str = "SELECT DISTINCT uc.card_id FROM user_card uc \
     WHERE uc.template_id IN ( \
       SELECT user_card_template_id FROM identity_level_template WHERE template_id = ? \
     ) AND uc.card_status = 'ACTIVE' ORDER BY uc.card_id FOR UPDATE";

#[async_trait]
impl LevelTemplateRepository for SqlxLevelTemplateRepository {
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
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
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

        // 等级模板的授权语义字段（status/user_card_template_id/grant_type/level_no）
        // 变更会影响引用卡的授权快照：必须在同一事务内对受影响 ACTIVE 卡追加
        // 带 metadata 的 REVOKE projection 并落一条审计关联记录（对齐
        // delete_with_cascade 的锁定+投影模式），否则引用卡保持旧授权直到
        // 下次变更才收敛。
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let affected_card_ids: Vec<i64> = sqlx::query_scalar(LOCK_AFFECTED_CARDS_SQL)
            .bind(id)
            .fetch_all(&mut *tx)
            .await
            .map_err(db_error)?;

        let result = builder.build().execute(&mut *tx).await.map_err(db_error)?;
        if result.rows_affected() == 0 {
            // 模板不存在或补丁值与现值完全一致（MySQL 计变更行）：未发生授权
            // mutation，无扇出、无可审计变更；保持既有 no-op 语义，由 handler
            // 的 get_template 决定 404。
            tx.commit().await.map_err(db_error)?;
            return Ok(());
        }

        let projection_event_ids =
            append_card_revokes_with_metadata_in_tx(&mut tx, &affected_card_ids, context).await?;
        insert_level_template_audit_in_tx(
            &mut tx,
            &LevelTemplateAuditEntry {
                action: LEVEL_TEMPLATE_AUDIT_ACTION_UPDATE,
                template_id: id,
                template_code: None,
                template_name: None,
                affected_card_ids: &affected_card_ids,
                projection_event_ids: &projection_event_ids,
                applied_fields: applied_patch_fields(patch),
                context,
            },
        )
        .await?;
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn delete_with_cascade(
        &self,
        id: i64,
        context: &LevelTemplateMutationContext,
    ) -> Result<DeleteOutcome, AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        // Lock affected cards before deleting the template so source and projection
        // head/outbox commit atomically.
        let affected_card_ids: Vec<i64> = sqlx::query_scalar(LOCK_AFFECTED_CARDS_SQL)
            .bind(id)
            .fetch_all(&mut *tx)
            .await
            .map_err(db_error)?;

        // 锁定读取模板身份用于删除后仍可追溯的审计 provenance；锁序保持
        // cards → template（与 update 的隐式锁序一致，避免交叉死锁）。
        let template: Option<(String, String)> = sqlx::query_as(
            "SELECT template_code, template_name FROM identity_level_template \
             WHERE template_id = ? FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
        let Some((template_code, template_name)) = template else {
            // 模板不存在：保持既有 not-deleted 语义（事务内无 mutation，
            // 不产生投影/审计记录）。
            return Ok(DeleteOutcome {
                deleted: false,
                affected_card_ids: Vec::new(),
            });
        };

        sqlx::query("DELETE FROM identity_level_template_resource_map WHERE template_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;

        sqlx::query("DELETE FROM identity_level_template_action_map WHERE template_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;

        let result = sqlx::query("DELETE FROM identity_level_template WHERE template_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        if result.rows_affected() == 0 {
            // 锁定读已证明行存在，删除 0 行属于不可能状态：fail-closed 回滚，
            // 绝不静默报告 not-deleted 掩盖不一致。
            return Err(AstralError::Internal(
                "level template delete applied zero rows after a locked read".into(),
            ));
        }

        let projection_event_ids =
            append_card_revokes_with_metadata_in_tx(&mut tx, &affected_card_ids, context).await?;
        insert_level_template_audit_in_tx(
            &mut tx,
            &LevelTemplateAuditEntry {
                action: LEVEL_TEMPLATE_AUDIT_ACTION_DELETE,
                template_id: id,
                template_code: Some(&template_code),
                template_name: Some(&template_name),
                affected_card_ids: &affected_card_ids,
                projection_event_ids: &projection_event_ids,
                applied_fields: serde_json::Value::Object(serde_json::Map::new()),
                context,
            },
        )
        .await?;
        tx.commit().await.map_err(db_error)?;

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

    /// 审计详情：确定性 JSON，携带模板身份、operation/actor、扇出卡与事件号、
    /// 应用的补丁字段；删除路径携带删除前捕获的 code/name。
    #[test]
    fn audit_entry_detail_is_deterministic_and_complete() {
        let context = LevelTemplateMutationContext::new(9, "op-1").unwrap();
        let event_ids = vec!["evt-b".to_string(), "evt-a".to_string()];
        let update_entry = LevelTemplateAuditEntry {
            action: LEVEL_TEMPLATE_AUDIT_ACTION_UPDATE,
            template_id: 3,
            template_code: None,
            template_name: None,
            affected_card_ids: &[11, 7],
            projection_event_ids: &event_ids,
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
        // 卡与事件号按调用方顺序原样保留（一一对应由 validate 保证）
        assert_eq!(parsed["affectedCardIds"], serde_json::json!([11, 7]));
        assert_eq!(
            parsed["projectionEventIds"],
            serde_json::json!(["evt-b", "evt-a"])
        );
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
            template_id: 3,
            template_code: Some("LT_CODE"),
            template_name: Some("LT_NAME"),
            affected_card_ids: &[],
            projection_event_ids: &[],
            applied_fields: serde_json::Value::Object(serde_json::Map::new()),
            context: &context,
        };
        let parsed: serde_json::Value =
            serde_json::from_str(&delete_entry.detail_json().unwrap()).unwrap();
        assert_eq!(parsed["templateCode"], "LT_CODE");
        assert_eq!(parsed["templateName"], "LT_NAME");
        assert_eq!(parsed["affectedCardIds"], serde_json::json!([]));
    }

    /// 审计校验 fail-closed：空 action / 非正模板 id / 卡与事件号错位 /
    /// 非正卡 id / 空事件号一律拒绝。
    #[test]
    fn audit_entry_validation_is_fail_closed() {
        // 统一构造 helper：生命周期与调用方局部值绑定，避免泄漏/静态提升。
        fn entry<'a>(
            action: &'a str,
            template_id: i64,
            affected: &'a [i64],
            events: &'a [String],
            context: &'a LevelTemplateMutationContext,
        ) -> LevelTemplateAuditEntry<'a> {
            LevelTemplateAuditEntry {
                action,
                template_id,
                template_code: None,
                template_name: None,
                affected_card_ids: affected,
                projection_event_ids: events,
                applied_fields: serde_json::Value::Object(serde_json::Map::new()),
                context,
            }
        }

        let context = LevelTemplateMutationContext::new(9, "op-1").unwrap();
        let ok_events = vec!["evt-1".to_string()];
        let ok_cards = [7i64];
        assert!(entry(
            LEVEL_TEMPLATE_AUDIT_ACTION_DELETE,
            3,
            &ok_cards,
            &ok_events,
            &context
        )
        .validate()
        .is_ok());

        let empty_action = entry(" ", 3, &[], &[], &context);
        assert!(empty_action.validate().is_err());

        let zero_template = entry(LEVEL_TEMPLATE_AUDIT_ACTION_DELETE, 0, &[], &[], &context);
        assert!(zero_template.validate().is_err());

        // 卡与事件号数量不一致 → 拒绝（每张锁定卡必须恰好一个 REVOKE 事件）
        let misaligned_events = vec!["evt-1".to_string()];
        let misaligned_cards = [7i64, 8];
        assert!(entry(
            LEVEL_TEMPLATE_AUDIT_ACTION_DELETE,
            3,
            &misaligned_cards,
            &misaligned_events,
            &context
        )
        .validate()
        .is_err());

        let zero_card_events = vec!["evt-1".to_string()];
        let zero_card_ids = [0i64];
        assert!(entry(
            LEVEL_TEMPLATE_AUDIT_ACTION_DELETE,
            3,
            &zero_card_ids,
            &zero_card_events,
            &context
        )
        .validate()
        .is_err());

        let blank_event_ids = vec!["  ".to_string()];
        let blank_event_cards = [7i64];
        assert!(entry(
            LEVEL_TEMPLATE_AUDIT_ACTION_DELETE,
            3,
            &blank_event_cards,
            &blank_event_ids,
            &context
        )
        .validate()
        .is_err());
    }

    /// 源序守卫：update 事务内必须先锁定受影响卡，再执行 UPDATE，然后才是
    /// metadata REVOKE 扇出、审计关联与提交；禁止退回无 metadata 的旧入口。
    #[test]
    fn update_tx_orders_locks_projection_audit_and_commit() {
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
        let lock = update_body
            .find("LOCK_AFFECTED_CARDS_SQL")
            .expect("update must lock affected ACTIVE cards");
        let source_update = update_body
            // 锚定执行点而非 QueryBuilder 构造文本：UPDATE 语句字符串在事务
            // 开始前就由 QueryBuilder 持有，"先锁卡后执行"的顺序只能以
            // build().execute() 的位置为准。
            .find("builder.build().execute(&mut *tx)")
            .expect("update must mutate the template row");
        let projection = update_body
            .find("append_card_revokes_with_metadata_in_tx")
            .expect("update must append metadata CARD REVOKE projections");
        let audit = update_body
            .find("insert_level_template_audit_in_tx")
            .expect("update must write one audit correlation record");
        // update 存在 no-op 分支的提前 commit；最终 commit 必须在审计之后。
        let commit = update_body
            .rfind("tx.commit()")
            .expect("update must commit the source transaction");
        assert!(
            lock < source_update && source_update < projection && projection < audit && audit < commit,
            "update must order: card locks -> source UPDATE -> metadata REVOKE fanout -> audit -> commit"
        );
        // 同事务无 metadata 旧入口不得再用于该授权 mutation。
        assert!(
            !update_body.contains("append_card_projection_in_tx"),
            "level template mutations must not use the identity-less projection entry"
        );
    }

    /// 源序守卫：delete 事务内必须先锁卡，再锁定读取模板 provenance，随后
    /// 级联删除，最后 metadata REVOKE 扇出、审计关联与提交。
    #[test]
    fn delete_tx_orders_locks_provenance_deletes_projection_audit_and_commit() {
        let source = include_str!("level_template_repository.rs");
        let delete_body = source
            .split("async fn delete_with_cascade")
            // 该字符串出现 4 次（trait 声明 / impl 实现 / update 测试与本测试
            // 的字面量）；nth(2) 才是 impl 实现体段（到 update 测试字面量前）。
            .nth(2)
            .expect("delete_with_cascade implementation must exist")
            // 在 db_error 前截断，排除本测试模块的源码字面量干扰。
            .split("fn db_error")
            .next()
            .expect("delete_with_cascade body must be delimited");
        let lock = delete_body
            .find("LOCK_AFFECTED_CARDS_SQL")
            .expect("delete must lock affected ACTIVE cards before deleting the template");
        let provenance = delete_body
            .find("SELECT template_code, template_name FROM identity_level_template")
            .expect("delete must capture template provenance under lock");
        let map_delete = delete_body
            .find("DELETE FROM identity_level_template_resource_map WHERE template_id = ?")
            .expect("delete must cascade the resource map");
        let row_delete = delete_body
            .find("DELETE FROM identity_level_template WHERE template_id = ?")
            .expect("delete must remove the template row");
        let projection = delete_body
            .find("append_card_revokes_with_metadata_in_tx")
            .expect("delete must append metadata CARD REVOKE projections");
        let audit = delete_body
            .find("insert_level_template_audit_in_tx")
            .expect("delete must write one audit correlation record");
        let commit = delete_body
            .find("tx.commit()")
            .expect("delete must commit the source transaction");
        assert!(
            lock < provenance
                && provenance < map_delete
                && map_delete < row_delete
                && row_delete < projection
                && projection < audit
                && audit < commit,
            "delete must order: card locks -> provenance read -> cascades -> metadata REVOKE fanout -> audit -> commit"
        );
        assert!(
            !delete_body.contains("append_card_projection_in_tx"),
            "level template mutations must not use the identity-less projection entry"
        );
    }

    /// 模板 mutation 不产生授权账本 delta（模板不是 CanonicalGrant 源），
    /// 审计 INSERT 只用绑定参数 + 固定常量，不拼接任何请求输入。
    #[test]
    fn no_ledger_deltas_and_parameterized_audit_sql() {
        let source = include_str!("level_template_repository.rs");
        // 自引用防呆：token 必须拼接构造。include_str! 会把本测试模块自身的
        // 源码包含进 source，直接书写完整字面量会让 contains 恒真、守卫失效。
        let revision_token = concat!("authorization_grant_", "revision");
        let delta_token = concat!("authorization_delta_", "event");
        let adapter_token = concat!("grant_", "ledger");
        assert!(
            !source.contains(revision_token)
                && !source.contains(delta_token)
                && !source.contains(adapter_token),
            "level template mutations must not invent ledger deltas"
        );
        // 全部可变输入走绑定参数；decision/resource/event_type 为固定常量。
        assert!(LEVEL_TEMPLATE_AUDIT_INSERT_SQL
            .contains("VALUES (?, NULL, ?, ?, 'CARD_REVOKED', NULL, ?, ?, ?)"));
        assert!(
            LEVEL_TEMPLATE_AUDIT_INSERT_SQL.contains("event_type")
                && LEVEL_TEMPLATE_AUDIT_INSERT_SQL.contains("request_id"),
            "audit correlation must land in event_type/request_id columns"
        );
        assert_eq!(LEVEL_TEMPLATE_AUDIT_RESOURCE, "level_template");
        assert_eq!(LEVEL_TEMPLATE_AUDIT_EVENT_TYPE, "LEVEL_TEMPLATE_MUTATION");
        assert_eq!(LEVEL_TEMPLATE_AUDIT_ACTION_UPDATE, "level_template_update");
        assert_eq!(LEVEL_TEMPLATE_AUDIT_ACTION_DELETE, "level_template_delete");
    }
}
