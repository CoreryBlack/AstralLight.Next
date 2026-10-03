//! 用户卡数据访问 — CardRepository
//!
//! 对齐 Java `UserCardMapper` 边界。卡片查询与 CRUD 集中在 repository，
//! 行模型收敛为 `UserCard` 领域类型，不再在多个 handler 重复定义。
//!
//! # 授权 source mutation 五链契约（对齐 astral-trustgraph 同能力路径）
//!
//! 本 repository 的 `create_user_card` / `update_user_card_status` /
//! `update_user_card` 是影响有效授权的 source mutation（CARD/ELIGIBILITY 投影、
//! 模板 RuleSet 绑定的版本化账本贡献、审计关联全部同事务落库，任一失败整体
//! 回滚）。identity 与 trustgraph 是两个独立服务二进制（服务互依禁止），两侧
//! 通过共享的 `astral_db::grant_ledger` 纯组装层保证**同一张卡的同一条目绑定
//! 派生逐字节一致的 grant_id / contribution event id / canonical payload**：
//!
//! - create：模板 RuleSet 绑定按 trustgraph `UserCardRepository::create_card`
//!   同一语义物化 ALLOW ADD 贡献（rev1 base0→target1）+ BIND_CARD 审计；
//! - status：只认事务内 `FOR UPDATE` 锁定行 + 状态机（只能离开 ACTIVE，任何
//!   送回 ACTIVE 的请求整体拒绝 —— identity 不提供 restore/bind 守卫入口，
//!   与 trustgraph restore 语义一致：恢复必须走显式守卫路径，不隐式复活）；
//!   离开 ACTIVE 走 CARD REVOKE（带 actor/operation 元数据）+ ELIGIBILITY +
//!   `audit_log` 审计关联；
//! - template 变更：旧模板绑定先做版本化 REMOVE（head 缺失 fail-closed）再
//!   删除 ref，新模板绑定走与 create 相同的 ADD 物化，全程同一稳定 operation
//!   id，CARD/RULE_SET 投影与审计同事务。
//!
//! operation identity 单一契约：显式 `x-request-id` 经统一安全校验后原样贯穿
//! 全部账本/投影/审计写入；缺失时以**锁定中的 durable 代次**确定性派生，随机
//! fallback 绝不进入账本事件链。

use async_trait::async_trait;
use sqlx::{MySqlPool, QueryBuilder};

use astral_db::grant_ledger::{
    append_ruleset_grant_delta_in_tx, build_ruleset_add_draft, build_ruleset_remove_draft,
    derive_ruleset_contribution_event_id, derive_ruleset_identity, map_grant_repository_error,
    validated_request_operation_id, RuleSetEntryLedgerFacts, RuleSetMutationKind,
    RULE_SET_AGGREGATE_TYPE,
};
use astral_db::{
    next_delta_version, read_grant_head_for_update_in_tx,
    read_latest_delta_target_version_for_update_in_tx, ProjectionEventIdentity,
    ProjectionEventMetadata,
};
use astral_types::{
    AstralError, ProjectionAggregate, UserCard, EVENT_TYPE_ELIGIBILITY_UPDATE, EVENT_TYPE_REVOKE,
    EVENT_TYPE_RULE_SET_UPDATE, SYSTEM_ACTOR_ID,
};

#[derive(Debug, Clone)]
pub struct CardFilter {
    pub user_id: Option<i64>,
    pub status: Option<String>,
}

/// identity_card 基础行（app 会话签发读取；对应 internal.rs 原局部 struct）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct IdentityCardRow {
    pub card_id: Option<i64>,
    pub user_id: i64,
    pub status: String,
    pub token_version: Option<i64>,
    pub expires_at: Option<String>,
}

#[async_trait]
pub trait CardRepository: Send + Sync {
    /// 校验用户存在 ACTIVE 的 identity_card，返回其 card_id。
    async fn find_active_identity_card(&self, user_id: i64) -> Result<Option<i64>, AstralError>;

    /// 查询用户 ACTIVE 的 identity_card 完整行（app 会话签发用，按 card_id 升序取首条）。
    async fn find_active_identity_card_row(
        &self,
        user_id: i64,
    ) -> Result<Option<IdentityCardRow>, AstralError>;

    /// Ensure an APP_USER identity-only card exists without creating a user card.
    /// The boolean reports whether this call created the card for compensation.
    async fn ensure_active_identity_card(
        &self,
        user_id: i64,
    ) -> Result<(IdentityCardRow, bool), AstralError>;

    /// Remove only a card created by the current app-session attempt.
    async fn delete_created_identity_card(
        &self,
        user_id: i64,
        card_id: i64,
    ) -> Result<(), AstralError>;

    /// 创建模板绑定用户卡（授权 source mutation）。
    ///
    /// `actor_id` 必须是 Gateway 已验证的正数操作者（HTTP `x-user-id`）；缺失或
    /// 非正数在进入任何 durable 写入前整体拒绝。`request_operation_id` 是可选的
    /// `x-request-id`；携带时先过统一安全校验（不安全 header fail-closed），缺失
    /// 或空白时以锁定中的 durable RULE_SET 代次确定性派生稳定 operation id。
    async fn create_user_card(
        &self,
        user_id: i64,
        domain_id: Option<i64>,
        tenant_id: Option<i64>,
        template_id: i64,
        actor_id: i64,
        request_operation_id: Option<&str>,
    ) -> Result<UserCard, AstralError>;

    async fn list_user_cards(&self, filter: CardFilter) -> Result<Vec<UserCard>, AstralError>;

    async fn get_user_card(&self, card_id: i64) -> Result<Option<UserCard>, AstralError>;

    /// 变更用户卡状态（授权 source mutation，状态机对齐 trustgraph
    /// `update_card`）。
    ///
    /// 只能离开 ACTIVE（INACTIVE/SUSPENDED/DISABLED）；任何把非 ACTIVE 卡送回
    /// ACTIVE 的请求整体拒绝（restore/bind 是 trustgraph 侧的守卫专用入口，
    /// identity 不提供，也绝不在本入口新开授权恢复旁路）。离开 ACTIVE 走
    /// CARD REVOKE + ELIGIBILITY + `audit_log` 审计（同事务）。
    async fn update_user_card_status(
        &self,
        card_id: i64,
        status: &str,
        actor_id: i64,
        request_operation_id: Option<&str>,
    ) -> Result<(), AstralError>;

    /// 变更用户卡模板（授权 source mutation）。
    ///
    /// 模板变化时在同一事务内先对旧模板绑定做版本化 REMOVE（head 缺失
    /// fail-closed）并删除 ref，再按 create 语义物化新模板绑定的 ADD 贡献；
    /// 投影/审计同事务落库，任一失败整体回滚。
    async fn update_user_card(
        &self,
        card_id: i64,
        template_id: i64,
        domain_id: Option<i64>,
        tenant_id: Option<i64>,
        actor_id: i64,
        request_operation_id: Option<&str>,
    ) -> Result<(), AstralError>;
}

pub struct SqlxCardRepository {
    db: MySqlPool,
}

impl SqlxCardRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl CardRepository for SqlxCardRepository {
    async fn find_active_identity_card(&self, user_id: i64) -> Result<Option<i64>, AstralError> {
        sqlx::query_scalar(
            "SELECT card_id FROM identity_card \
             WHERE user_id = ? AND status = 'ACTIVE' \
               AND (expires_at IS NULL OR expires_at >= UTC_TIMESTAMP()) \
             LIMIT 1",
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AstralError::Database(format!("Query identity_card failed: {e}")))
    }

    async fn find_active_identity_card_row(
        &self,
        user_id: i64,
    ) -> Result<Option<IdentityCardRow>, AstralError> {
        sqlx::query_as::<_, IdentityCardRow>(
            "SELECT card_id, user_id, status, token_version, \
             DATE_FORMAT(expires_at, '%Y-%m-%dT%H:%i:%sZ') AS expires_at \
             FROM identity_card WHERE user_id = ? AND status = 'ACTIVE' \
               AND (expires_at IS NULL OR expires_at >= UTC_TIMESTAMP()) \
             ORDER BY card_id LIMIT 1",
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AstralError::Database(format!("Query identity_card failed: {e}")))
    }

    async fn ensure_active_identity_card(
        &self,
        user_id: i64,
    ) -> Result<(IdentityCardRow, bool), AstralError> {
        // hub 已装时先登记卡事实写者（writer-active 期间辅助读面 fail-closed）。
        let source_guard = begin_card_source_transaction()?;
        let mut tx = self.db.begin().await.map_err(|e| {
            AstralError::Database(format!("Begin identity card ensure tx failed: {e}"))
        })?;
        let existing_user: Option<(i64,)> =
            sqlx::query_as("SELECT id FROM app_user WHERE id = ? AND status = 'ACTIVE' FOR UPDATE")
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| AstralError::Database(format!("Query app_user failed: {e}")))?;
        if existing_user.is_none() {
            return Err(AstralError::NotFound("app user not found".into()));
        }
        let existing_platform_user: Option<(i64,)> = sqlx::query_as(
            "SELECT user_id FROM platform_user \
             WHERE user_id = ? AND status = 'ACTIVE' AND deleted_at IS NULL FOR UPDATE",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AstralError::Database(format!("Query platform user mapping failed: {e}")))?;
        if existing_platform_user.is_none() {
            return Err(AstralError::Permission(
                "App user has no mapped active platform identity".into(),
            ));
        }

        let existing = sqlx::query_as::<_, IdentityCardRow>(
            "SELECT card_id, user_id, status, token_version, \
             DATE_FORMAT(expires_at, '%Y-%m-%dT%H:%i:%sZ') AS expires_at \
             FROM identity_card WHERE user_id = ? AND status = 'ACTIVE' \
               AND (expires_at IS NULL OR expires_at >= UTC_TIMESTAMP()) \
             ORDER BY card_id LIMIT 1 FOR UPDATE",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AstralError::Database(format!("Query identity_card failed: {e}")))?;
        if let Some(card) = existing {
            arm_card_commit_fence(&source_guard);
            let commit_result = tx.commit().await;
            settle_card_commit_fence(&source_guard, &commit_result);
            commit_result.map_err(|e| {
                AstralError::Database(format!("Commit identity card ensure failed: {e}"))
            })?;
            return Ok((card, false));
        }

        let result = sqlx::query(
            "INSERT INTO identity_card (user_id, status, token_version) VALUES (?, 'ACTIVE', 1)",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AstralError::Database(format!("Create identity_card failed: {e}")))?;
        let card_id = result.last_insert_id() as i64;
        let card = IdentityCardRow {
            card_id: Some(card_id),
            user_id,
            status: "ACTIVE".into(),
            token_version: Some(1),
            expires_at: None,
        };
        arm_card_commit_fence(&source_guard);
        let commit_result = tx.commit().await;
        settle_card_commit_fence(&source_guard, &commit_result);
        commit_result.map_err(|e| {
            AstralError::Database(format!("Commit identity card ensure failed: {e}"))
        })?;
        Ok((card, true))
    }

    async fn delete_created_identity_card(
        &self,
        user_id: i64,
        card_id: i64,
    ) -> Result<(), AstralError> {
        // autocommit 写点同样必须持栅栏（不能因无 pool.begin 省略）：hub 已装
        // 则取不到 guard 直接拒绝；单语句 autocommit 的 Err 视为未知结果
        // （连接中断后语句可能已提交）→ 先 mark_uncertain 再上抛。
        let source_guard = begin_card_source_transaction()?;
        // autocommit 语句同样先武装取消栅栏（execute await 窗口内取消/掉线 →
        // Drop → sticky uncertain），结果判定后统一 settle。
        arm_card_commit_fence(&source_guard);
        let result: Result<(), sqlx::Error> = sqlx::query(
            "DELETE FROM identity_card WHERE card_id = ? AND user_id = ? AND status = 'ACTIVE'",
        )
        .bind(card_id)
        .bind(user_id)
        .execute(&self.db)
        .await
        .map(|_| ());
        settle_card_commit_fence(&source_guard, &result);
        result.map_err(|e| {
            AstralError::Database(format!("Delete created identity_card failed: {e}"))
        })?;
        Ok(())
    }

    async fn create_user_card(
        &self,
        user_id: i64,
        domain_id: Option<i64>,
        tenant_id: Option<i64>,
        template_id: i64,
        actor_id: i64,
        request_operation_id: Option<&str>,
    ) -> Result<UserCard, AstralError> {
        // ── Phase 0: 纯校验先于任何 durable 写入 ─────────────────────────────
        // 操作者身份：本入口是用户自助创建，必须携带 Gateway 已验证的正数 actor；
        // 绝不以系统身份冒充人类操作者落投影/账本/审计。
        require_positive_actor(actor_id, "create user card")?;
        // 模板绑定卡是账本 ALLOW 贡献的物化目标：tenant/user 正数、domain 携带时
        // 正数，任何无法证明的 scope 整卡创建失败，不降级只写旧链。
        validate_template_card_ledger_scope(user_id, tenant_id, domain_id, template_id)?;
        let request_operation_id = validated_request_operation_id(request_operation_id)?;

        // hub 已装时先登记卡事实写者（writer-active 期间辅助读面 fail-closed）。
        let source_guard = begin_card_source_transaction()?;
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AstralError::Database(format!("Begin card create tx failed: {e}")))?;
        // 问题 1 修正：身份卡不承担组织归属，此处只确认用户存在 ACTIVE 身份卡，
        // 不再要求 identity_card.tenant_id/domain_id 与请求 scope 匹配
        // （组织归属由新建的 user_card 自身承载）。
        let identity_scope: Option<(i64,)> = sqlx::query_as(
            "SELECT card_id FROM identity_card \
             WHERE user_id = ? AND status = 'ACTIVE' \
             ORDER BY card_id LIMIT 1 FOR UPDATE",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AstralError::Database(format!("Validate identity scope failed: {e}")))?;
        if identity_scope.is_none() || tenant_id.is_none() || domain_id.is_none() {
            return Err(AstralError::Permission(
                "User card scope requires an active identity card".into(),
            ));
        }
        // 发卡与 delete_tenant/delete_org 的并发边界闭合（统一锁序 tenant →
        // user_card，与删除路径的 tenant 行锁 → user_card 引用守卫同序）：
        // 本事务在写 user_card 之前先锁定**已存在**的 tenant 行。两个交错方向
        // 都被堵死 —— 删除事务已提交：此处锁不到行，fail-closed 拒绝发卡；
        // 删除事务在途：其引用守卫与本 INSERT 必然串行化在租户行锁上，不可能
        // 产生引用已删除租户的孤儿卡。本事务的 identity_card → tenant 取锁方向
        // 与既有路径（tenant → user_card、user_card → rule_set）无反向环，
        // 不引入死锁。不加级联、不改 schema。
        let issue_tenant_id = tenant_id.filter(|id| *id > 0).ok_or_else(|| {
            AstralError::Validation(format!(
                "user card requires a positive tenant scope, got {tenant_id:?}"
            ))
        })?;
        let locked_tenant: Option<(i64,)> =
            sqlx::query_as("SELECT tenant_id FROM tenant WHERE tenant_id = ? FOR UPDATE")
                .bind(issue_tenant_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| {
                    AstralError::Database(format!("Lock tenant for card issue failed: {e}"))
                })?;
        if locked_tenant.is_none() {
            return Err(AstralError::Validation(format!(
                "tenant {issue_tenant_id} does not exist; refusing to issue a user_card \
                 against a missing tenant (fail-closed)"
            )));
        }
        let result = sqlx::query(
            "INSERT INTO user_card \
             (user_id, domain_id, tenant_id, card_type, card_status, template_id, priority, is_primary) \
             VALUES (?, ?, ?, 'STANDARD', 'ACTIVE', ?, 100, 0)",
        )
        .bind(user_id)
        .bind(domain_id)
        .bind(tenant_id)
        .bind(template_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AstralError::Database(format!("Insert user_card failed: {e}")))?;
        // 新建卡主键是本事务拥有的 source 身份事实；不可用即持久层异常，整体拒绝。
        if result.last_insert_id() == 0 {
            return Err(AstralError::Internal(
                "user_card insert returned an unusable id".into(),
            ));
        }
        let card_id = result.last_insert_id() as i64;

        // 模板绑定失败必须回滚创建，避免卡片处于无授权规则集的半完成状态。
        let locked_rule_sets = lock_template_rule_sets_in_tx(&mut tx, template_id).await?;
        ensure_unique_template_rule_set_ids(&locked_rule_sets)?;
        let card_tenant_id = tenant_id.unwrap_or_default();
        for row in &locked_rule_sets {
            // Reject one-sided tenant scopes before any durable write; the
            // enclosing transaction rolls back the new card if any template
            // RuleSet is not in the same scope.
            validate_binding_tenants(row.tenant_id, tenant_id)?;
        }
        // Operation identity（首个 ledger/outbox/audit 写之前确定）：显式请求
        // id 原样贯穿，否则以锁定的最大 RULE_SET 代次确定性派生。
        let operation_id = request_operation_id.unwrap_or_else(|| {
            let locked_ruleset_generation = locked_rule_sets
                .iter()
                .filter_map(|row| row.source_generation)
                .max()
                .unwrap_or(0);
            derive_create_card_template_operation_id(
                card_id,
                template_id,
                locked_ruleset_generation,
            )
        });

        // ── CARD parent：单张带 actor/operation 元数据的 CARD_CREATED 事件 ──
        // 其 durable 身份作为本卡全部模板绑定 ADD 贡献的 generation/fence 锚点；
        // 与 trustgraph create_card 同一约定（不再逐绑定追加 RULE_SET_BOUND）。
        let parent_projection = append_projection_with_metadata(
            &mut tx,
            ProjectionAggregate::Card,
            card_id,
            "CARD_CREATED",
            actor_id,
            &operation_id,
        )
        .await?;

        for row in &locked_rule_sets {
            // Sources are locked by RuleSet id; prove each RuleSet before its reference.
            ensure_rule_set_projection_in_tx(
                &mut tx,
                row.rule_set_id,
                row.tenant_id,
                actor_id,
                &operation_id,
            )
            .await?;
            // 严格 ref 主键捕获：普通 INSERT（非 IGNORE）。新卡在本事务内不可能
            // 已有 ref —— IGNORE 命中旧行或拿不到可用主键都说明不变量已被破坏，
            // 必须整体失败而不是猜测 ref_id=0 或静默复用未知旧绑定。
            let inserted_ref = sqlx::query(
                "INSERT INTO card_rule_set_ref \
                 (card_id, rule_set_id, ref_type, tenant_id) VALUES (?, ?, 'BASE', ?)",
            )
            .bind(card_id)
            .bind(row.rule_set_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AstralError::Database(format!("Insert card_rule_set_ref failed: {e}")))?;
            let ref_id = i64::try_from(inserted_ref.last_insert_id())
                .ok()
                .filter(|id| *id > 0)
                .ok_or_else(|| {
                    AstralError::Internal("card_rule_set_ref insert returned an unusable id".into())
                })?;
            // 绑定本身是一次 RuleSet 授权语义变更：RULE_SET 投影事件 + BIND_CARD
            // 审计与标准 bind_card 同语义（缓存失效/快照重建契约一致）。
            let rule_projection = append_projection_with_metadata(
                &mut tx,
                ProjectionAggregate::RuleSet,
                row.rule_set_id,
                EVENT_TYPE_RULE_SET_UPDATE,
                actor_id,
                &operation_id,
            )
            .await?;
            // enabled+ALLOW 条目的标准 ADD 物化（rev1 base0→target1）；空 RuleSet
            // 合法返回空贡献集。贡献以 entry×card×ref 维度派生独立稳定事件号。
            let addition = materialize_template_adds_in_tx(
                &mut tx,
                row.rule_set_id,
                &parent_projection,
                actor_id,
                &operation_id,
                ref_id,
                card_id,
                user_id,
                card_tenant_id,
                domain_id,
                "BASE",
            )
            .await?;

            // BIND_CARD 审计关联面（同事务、序列化/DB 错误一律上抛回滚）：
            // parent CARD 事件、模板/租户/卡/ref 维度与全部贡献事件号可追溯。
            let addition_detail = serde_json::json!({
                "cardId": card_id,
                "tenantId": tenant_id,
                "templateId": template_id,
                "refId": ref_id,
                "refType": "BASE",
                "parentSourceEventId": parent_projection.event_id,
                "contributionEventIds": addition
                    .iter()
                    .map(|entry| entry.event_id.as_str())
                    .collect::<Vec<_>>(),
                "ruleSetEntryIds": addition.iter().map(|entry| entry.entry_id).collect::<Vec<_>>(),
                "boundCardIds": [card_id],
                "bindingRefIds": [ref_id],
            });
            insert_rule_set_projection_audit_in_tx(
                &mut tx,
                &RuleSetProjectionAuditEntry {
                    rule_set_id: row.rule_set_id,
                    entry_id: None,
                    aggregate_type: ProjectionAggregate::RuleSet.as_str(),
                    aggregate_id: row.rule_set_id,
                    event_id: &rule_projection.event_id,
                    source_generation: rule_projection.source_generation,
                    operation_id: &operation_id,
                    actor_id,
                    change_type: "BIND_CARD",
                    old_value_json: None,
                    new_value_json: Some(&addition_detail.to_string()),
                    tenant_id: rule_projection.tenant_id,
                },
            )
            .await?;
        }

        // 新卡自 ACTIVE 起即影响资格缓存，同事务落 ELIGIBILITY 事件
        // （独立轻量资格通道：evict `perm:card:active` 缓存 + 推进 head）。
        astral_db::append_projection_event_in_tx(
            &mut tx,
            ProjectionAggregate::Eligibility,
            card_id,
            EVENT_TYPE_ELIGIBILITY_UPDATE,
        )
        .await?;
        arm_card_commit_fence(&source_guard);
        let commit_result = tx.commit().await;
        settle_card_commit_fence(&source_guard, &commit_result);
        commit_result
            .map_err(|e| AstralError::Database(format!("Commit card create tx failed: {e}")))?;

        Ok(UserCard {
            card_id: Some(card_id),
            user_id: Some(user_id),
            domain_id,
            card_type: "STANDARD".into(),
            card_status: "ACTIVE".into(),
            template_id: Some(template_id),
            level_id: None,
            priority: Some(100),
            is_primary: Some(false),
            valid_from: None,
            valid_until: None,
            created_at: None,
            updated_at: None,
            tenant_id,
        })
    }

    async fn list_user_cards(&self, filter: CardFilter) -> Result<Vec<UserCard>, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(
            "SELECT card_id, user_id, domain_id, card_type, card_status, template_id, \
             level_id, priority, is_primary, valid_from, valid_until, created_at, updated_at, tenant_id \
             FROM user_card WHERE 1=1",
        );
        if let Some(user_id) = filter.user_id {
            builder.push(" AND user_id = ").push_bind(user_id);
        }
        if let Some(status) = filter.status {
            builder.push(" AND card_status = ").push_bind(status);
        }
        builder.push(" ORDER BY card_id LIMIT 100");

        let rows = builder
            .build_query_as::<UserCardRow>()
            .fetch_all(&self.db)
            .await
            .map_err(|e| AstralError::Database(format!("List user_cards failed: {e}")))?;
        Ok(rows.into_iter().map(UserCardRow::into_card).collect())
    }

    async fn get_user_card(&self, card_id: i64) -> Result<Option<UserCard>, AstralError> {
        sqlx::query_as::<_, UserCardRow>(
            "SELECT card_id, user_id, domain_id, card_type, card_status, template_id, \
             level_id, priority, is_primary, valid_from, valid_until, created_at, updated_at, tenant_id \
             FROM user_card WHERE card_id=?",
        )
        .bind(card_id)
        .fetch_optional(&self.db)
        .await
        .map(|row| row.map(UserCardRow::into_card))
        .map_err(|e| AstralError::Database(format!("Get user_card failed: {e}")))
    }

    async fn update_user_card_status(
        &self,
        card_id: i64,
        status: &str,
        actor_id: i64,
        request_operation_id: Option<&str>,
    ) -> Result<(), AstralError> {
        // ── Phase 0: 纯校验先于任何 durable 写入 ─────────────────────────────
        // 目标状态字母表（不信任 handler 白名单：未知字符串绝不进入 SQL 绑定值）。
        let requested_status = normalize_requested_card_status(status)?;
        let request_operation_id = validated_request_operation_id(request_operation_id)?;
        // 状态变更是授权 source mutation：必须携带 Gateway 已验证的正数 actor。
        require_positive_actor(actor_id, "user card status mutation")?;

        // hub 已装时先登记卡事实写者（writer-active 期间辅助读面 fail-closed）。
        let source_guard = begin_card_source_transaction()?;
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AstralError::Database(format!("Begin card status tx failed: {e}")))?;

        // ── Phase 1: 锁定行身份事实（迁移判定只认锁定状态，不信任请求旧读）──
        let locked: Option<LockedCardRow> = sqlx::query_as(
            "SELECT card_status, user_id, tenant_id, domain_id, template_id \
             FROM user_card WHERE card_id = ? FOR UPDATE",
        )
        .bind(card_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AstralError::Database(format!("Lock user_card failed: {e}")))?;
        let locked = locked.ok_or_else(|| AstralError::NotFound("user card not found".into()))?;
        let _owner_user_id =
            require_actor_owned_active_card(&locked, actor_id, card_id, "status mutation")?;

        let exits_active =
            classify_card_status_exits_active(&locked.card_status, &requested_status);
        // ── Phase 2: 状态机判定（先于 UPDATE；迁移非法则零副作用回滚）────────
        validate_card_status_transition(&locked.card_status, &requested_status)?;

        // 离开 ACTIVE 与同状态回显都以锁定 CARD head 代次确定性派生稳定
        // operation id（capture-before-write；身份失败时不残留任何 source 变更）。
        let locked_generation = lock_card_head_generation_in_tx(&mut tx, card_id).await?;
        let operation_id = match request_operation_id {
            Some(explicit) => explicit,
            None => derive_update_card_operation_id(card_id, locked_generation)?,
        };

        // ── Phase 3: source UPDATE（锁定状态下 status 谓词作为第二道防线）────
        let result =
            sqlx::query("UPDATE user_card SET card_status=? WHERE card_id=? AND card_status=?")
                .bind(&requested_status)
                .bind(card_id)
                .bind(&locked.card_status)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    AstralError::Database(format!("Update user_card status failed: {e}"))
                })?;
        if result.rows_affected() == 0 {
            return Err(AstralError::NotFound("user card not found".into()));
        }

        // ── Phase 4: 投影 + 审计（与 source UPDATE 同一事务）────────────────
        if exits_active {
            // 停用/吊销/挂起：带 actor/operation 元数据的 CARD REVOKE，ELIGIBILITY
            // 资格事件同事务（状态变更必然影响 `perm:card:active`），审计关联行
            // （`audit_log`，event_type `USER_CARD_MUTATION`）同事务落库。
            let parent_projection = append_projection_with_metadata(
                &mut tx,
                ProjectionAggregate::Card,
                card_id,
                EVENT_TYPE_REVOKE,
                actor_id,
                &operation_id,
            )
            .await?;
            astral_db::append_projection_event_in_tx(
                &mut tx,
                ProjectionAggregate::Eligibility,
                card_id,
                EVENT_TYPE_ELIGIBILITY_UPDATE,
            )
            .await?;
            insert_user_card_status_audit_in_tx(
                &mut tx,
                &UserCardStatusAuditEntry {
                    actor_id,
                    owner_user_id: locked.user_id.unwrap_or_default(),
                    target_card_id: card_id,
                    operation_id: &operation_id,
                    parent_event_id: &parent_projection.event_id,
                    from_status: &locked.card_status,
                    to_status: &requested_status,
                    tenant_id: locked.tenant_id,
                    domain_id: locked.domain_id,
                },
            )
            .await?;
        } else {
            // 同状态回显不是吊销：legacy CARD_UPDATE 语义保持，但投影带上
            // actor/operation 元数据（P0 审计/关联缺口修复），且不因回显失效
            // `perm:card:active` 资格（无 ELIGIBILITY 事件）。
            append_projection_with_metadata(
                &mut tx,
                ProjectionAggregate::Card,
                card_id,
                "CARD_UPDATE",
                actor_id,
                &operation_id,
            )
            .await?;
        }
        arm_card_commit_fence(&source_guard);
        let commit_result = tx.commit().await;
        settle_card_commit_fence(&source_guard, &commit_result);
        commit_result
            .map_err(|e| AstralError::Database(format!("Commit card status tx failed: {e}")))?;
        Ok(())
    }

    async fn update_user_card(
        &self,
        card_id: i64,
        template_id: i64,
        domain_id: Option<i64>,
        tenant_id: Option<i64>,
        actor_id: i64,
        request_operation_id: Option<&str>,
    ) -> Result<(), AstralError> {
        // ── Phase 0: 纯校验先于任何 durable 写入 ─────────────────────────────
        require_positive_actor(actor_id, "user card template mutation")?;
        if template_id <= 0 {
            return Err(AstralError::Validation(format!(
                "update user card requires a positive template id, got {template_id}"
            )));
        }
        let request_operation_id = validated_request_operation_id(request_operation_id)?;

        // hub 已装时先登记卡事实写者（writer-active 期间辅助读面 fail-closed）。
        let source_guard = begin_card_source_transaction()?;
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AstralError::Database(format!("Begin card update tx failed: {e}")))?;

        // ── Phase 1: 锁定行身份事实 ──────────────────────────────────────────
        let locked: Option<LockedCardRow> = sqlx::query_as(
            "SELECT card_status, user_id, tenant_id, domain_id, template_id \
             FROM user_card WHERE card_id = ? FOR UPDATE",
        )
        .bind(card_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AstralError::Database(format!("Lock user_card failed: {e}")))?;
        let locked = locked.ok_or_else(|| AstralError::NotFound("user card not found".into()))?;
        let owner_user_id =
            require_actor_owned_active_card(&locked, actor_id, card_id, "template mutation")?;
        if locked.tenant_id != tenant_id || locked.domain_id != domain_id {
            return Err(AstralError::Permission(
                "Card scope changes are not allowed from self-service".into(),
            ));
        }
        if locked.card_status != "ACTIVE" {
            return Err(AstralError::Permission(
                "self-service card template changes require an ACTIVE card".into(),
            ));
        }
        let card_tenant_id = locked.tenant_id.filter(|id| *id > 0).ok_or_else(|| {
            AstralError::Validation(format!(
                "user card {card_id} has a NULL/non-positive tenant_id; refusing to mutate template bindings without a tenant scope"
            ))
        })?;

        // 稳定 operation id：显式请求 id 原样贯穿，否则以锁定 CARD head 代次派生。
        let locked_generation = lock_card_head_generation_in_tx(&mut tx, card_id).await?;
        let operation_id = match request_operation_id {
            Some(explicit) => explicit,
            None => derive_update_card_operation_id(card_id, locked_generation)?,
        };

        if locked.template_id == Some(template_id) {
            // 同模板回显：无账本对账面，legacy CARD_UPDATE 投影带元数据 + 审计行。
            let parent_projection = append_projection_with_metadata(
                &mut tx,
                ProjectionAggregate::Card,
                card_id,
                "CARD_UPDATE",
                actor_id,
                &operation_id,
            )
            .await?;
            let detail = serde_json::json!({
                "actorId": actor_id,
                "ownerUserId": owner_user_id,
                "targetCardId": card_id,
                "operationId": operation_id,
                "parentEventId": parent_projection.event_id,
                "fromTemplateId": locked.template_id,
                "toTemplateId": template_id,
                "templateChanged": false,
                "action": "card_template_change",
            });
            insert_user_card_mutation_audit_in_tx(
                &mut tx,
                actor_id,
                card_id,
                "card_template_change",
                "CARD_UPDATED",
                &operation_id,
                locked.tenant_id,
                locked.domain_id,
                &detail.to_string(),
            )
            .await?;
            arm_card_commit_fence(&source_guard);
            let commit_result = tx.commit().await;
            settle_card_commit_fence(&source_guard, &commit_result);
            commit_result
                .map_err(|e| AstralError::Database(format!("Commit card update tx failed: {e}")))?;
            return Ok(());
        }

        // ── Phase 2: 模板绑定对账（REMOVE 旧模板 → ADD 新模板，同一事务）─────
        // REMOVAL：旧模板派生的 BASE 绑定集合先 plain 预读（仅用于确定升序锁
        // 集合），逐个 rule_set 升序锁定 source 行与 refs —— 与 binding-side
        // 家族（user_card → rule_set → refs/entries → grant head/delta）同方向。
        // 手动 OVERLAY 绑定不属于模板派生面，模板变更不触碰。
        let old_rule_set_ids: Vec<i64> = sqlx::query_scalar(
            "SELECT DISTINCT rs.rule_set_id FROM card_rule_set_ref ref \
             JOIN rule_set rs ON rs.rule_set_id = ref.rule_set_id \
             WHERE ref.card_id = ? AND ref.ref_type = 'BASE' \
               AND rs.source_type = 'TEMPLATE' AND rs.source_id = ? \
             ORDER BY rs.rule_set_id ASC",
        )
        .bind(card_id)
        .bind(locked.template_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| AstralError::Database(format!("Probe old template rule sets failed: {e}")))?;

        let mut removed_event_ids: Vec<String> = Vec::new();
        for rule_set_id in &old_rule_set_ids {
            // 规则集 source 行（FOR UPDATE；模板绑定缺失 source 行属于持久层
            // 不变式破坏 —— 无法证明绑定集合，fail-closed 拒绝而不是猜测）。
            let rule_set_tenant: Option<(Option<i64>,)> =
                sqlx::query_as("SELECT tenant_id FROM rule_set WHERE rule_set_id = ? FOR UPDATE")
                    .bind(rule_set_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|e| AstralError::Database(format!("Lock rule_set failed: {e}")))?;
            let Some((rule_set_tenant_id,)) = rule_set_tenant else {
                return Err(AstralError::Validation(format!(
                    "template rule set {rule_set_id} of card {card_id} has no source row; \
                     repair the binding before changing the card template"
                )));
            };
            validate_binding_tenants(rule_set_tenant_id, locked.tenant_id)?;

            // 该卡在该规则集下的模板派生 BASE 绑定引用（FOR UPDATE，id 升序）。
            let refs: Vec<(i64, String, Option<i64>)> = sqlx::query_as(
                "SELECT id, ref_type, tenant_id FROM card_rule_set_ref \
                 WHERE card_id = ? AND rule_set_id = ? AND ref_type = 'BASE' ORDER BY id FOR UPDATE",
            )
            .bind(card_id)
            .bind(rule_set_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| AstralError::Database(format!("Lock card_rule_set_ref failed: {e}")))?;
            // 分组来源即 card_rule_set_ref JOIN 结果，按冻结不变式不应为空。
            if refs.is_empty() {
                return Err(AstralError::Internal(format!(
                    "template rule set {rule_set_id} was probed for card {card_id} but its binding vanished under lock"
                )));
            }

            // enabled 条目锁定读取 + ALLOW-only 分类（未知 effect fail-closed）。
            let entries = read_rule_set_entries_in_tx(&mut tx, *rule_set_id, true).await?;
            let allow_entries = materializable_allow_entries(&entries)?;

            // 单张带 actor/operation 元数据的 CARD REVOKE 投影事件作为该 rule
            // set 全部 REMOVE 贡献的 generation/fence 锚点（与 trustgraph unbind
            // 同一语义）。
            let card_projection = append_projection_with_metadata(
                &mut tx,
                ProjectionAggregate::Card,
                card_id,
                EVENT_TYPE_REVOKE,
                actor_id,
                &operation_id,
            )
            .await?;

            let mut contribution_event_ids: Vec<String> = Vec::new();
            let mut rule_set_entry_ids: Vec<i64> = Vec::new();
            for (ref_id, ref_type, binding_tenant_id) in refs {
                // 每个引用行的租户一致性独立验证（不可证明的绑定整体拒绝）。
                if binding_tenant_id != locked.tenant_id {
                    return Err(AstralError::Permission(
                        "rule set unbinding requires matching card and binding tenant identities"
                            .into(),
                    ));
                }
                let removed = materialize_template_removes_in_tx(
                    &mut tx,
                    *rule_set_id,
                    &card_projection,
                    &operation_id,
                    ref_id,
                    card_id,
                    owner_user_id,
                    card_tenant_id,
                    locked.domain_id,
                    &ref_type,
                    &allow_entries,
                )
                .await?;
                for contribution in removed {
                    contribution_event_ids.push(contribution.event_id);
                    rule_set_entry_ids.push(contribution.entry_id);
                }
            }
            removed_event_ids.extend(contribution_event_ids.iter().cloned());

            // RULE_SET REVOKE 投影事件（captured tenant 保留，语义与 unbind 一致）。
            let rule_projection =
                astral_db::append_projection_event_with_metadata_and_tenant_in_tx(
                    &mut tx,
                    ProjectionAggregate::RuleSet,
                    *rule_set_id,
                    EVENT_TYPE_REVOKE,
                    Some(ProjectionEventMetadata {
                        actor_id,
                        operation_id: &operation_id,
                    }),
                    locked.tenant_id,
                )
                .await?;
            if rule_projection.tenant_id != locked.tenant_id {
                return Err(AstralError::Permission(
                    "RuleSet revoke projection tenant does not match binding scope".into(),
                ));
            }
            // UNBIND_CARD 审计关联行：parent RULE_SET 事件号 + 全部贡献维度。
            let old_value = serde_json::json!({
                "cardId": card_id,
                "tenantId": locked.tenant_id,
                "templateId": locked.template_id,
                "parentSourceEventId": rule_projection.event_id,
                "contributionEventIds": contribution_event_ids,
                "ruleSetEntryIds": rule_set_entry_ids,
                "boundCardIds": [card_id],
            })
            .to_string();
            insert_rule_set_projection_audit_in_tx(
                &mut tx,
                &RuleSetProjectionAuditEntry {
                    rule_set_id: *rule_set_id,
                    entry_id: None,
                    aggregate_type: ProjectionAggregate::RuleSet.as_str(),
                    aggregate_id: *rule_set_id,
                    event_id: &rule_projection.event_id,
                    source_generation: rule_projection.source_generation,
                    operation_id: &operation_id,
                    actor_id,
                    change_type: "UNBIND_CARD",
                    old_value_json: Some(&old_value),
                    new_value_json: None,
                    tenant_id: locked.tenant_id,
                },
            )
            .await?;

            // Source 删除最后执行：全部 REMOVE、RULE_SET 投影/审计都已从锁定
            // 捕获写完，任何失败回滚整个 mutation（绝不只删 source 不撤授权）。
            sqlx::query("DELETE FROM card_rule_set_ref WHERE card_id = ? AND rule_set_id = ?")
                .bind(card_id)
                .bind(rule_set_id)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    AstralError::Database(format!("Delete card_rule_set_ref failed: {e}"))
                })?;
        }

        // ADD：新模板 RuleSet 绑定（与 create_card 同一物化核心）。
        let locked_rule_sets = lock_template_rule_sets_in_tx(&mut tx, template_id).await?;
        ensure_unique_template_rule_set_ids(&locked_rule_sets)?;
        for row in &locked_rule_sets {
            validate_binding_tenants(row.tenant_id, locked.tenant_id)?;
        }
        // 单张带 actor/operation 元数据的 CARD RULE_SET_BOUND 事件作为全部新
        // 绑定 ADD 贡献的 generation/fence 锚点（与标准 bind 同一事件语义）。
        let add_anchor = append_projection_with_metadata(
            &mut tx,
            ProjectionAggregate::Card,
            card_id,
            "RULE_SET_BOUND",
            actor_id,
            &operation_id,
        )
        .await?;

        let mut added_event_ids: Vec<String> = Vec::new();
        for row in &locked_rule_sets {
            ensure_rule_set_projection_in_tx(
                &mut tx,
                row.rule_set_id,
                row.tenant_id,
                actor_id,
                &operation_id,
            )
            .await?;
            let inserted_ref = sqlx::query(
                "INSERT INTO card_rule_set_ref \
                 (card_id, rule_set_id, ref_type, tenant_id) VALUES (?, ?, 'BASE', ?)",
            )
            .bind(card_id)
            .bind(row.rule_set_id)
            .bind(locked.tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AstralError::Database(format!("Insert card_rule_set_ref failed: {e}")))?;
            let ref_id = i64::try_from(inserted_ref.last_insert_id())
                .ok()
                .filter(|id| *id > 0)
                .ok_or_else(|| {
                    AstralError::Internal("card_rule_set_ref insert returned an unusable id".into())
                })?;
            let rule_projection = append_projection_with_metadata(
                &mut tx,
                ProjectionAggregate::RuleSet,
                row.rule_set_id,
                EVENT_TYPE_RULE_SET_UPDATE,
                actor_id,
                &operation_id,
            )
            .await?;
            let addition = materialize_template_adds_in_tx(
                &mut tx,
                row.rule_set_id,
                &add_anchor,
                actor_id,
                &operation_id,
                ref_id,
                card_id,
                owner_user_id,
                card_tenant_id,
                locked.domain_id,
                "BASE",
            )
            .await?;

            let addition_detail = serde_json::json!({
                "cardId": card_id,
                "tenantId": locked.tenant_id,
                "templateId": template_id,
                "refId": ref_id,
                "refType": "BASE",
                "parentSourceEventId": add_anchor.event_id,
                "contributionEventIds": addition
                    .iter()
                    .map(|entry| entry.event_id.as_str())
                    .collect::<Vec<_>>(),
                "ruleSetEntryIds": addition.iter().map(|entry| entry.entry_id).collect::<Vec<_>>(),
                "boundCardIds": [card_id],
                "bindingRefIds": [ref_id],
            });
            insert_rule_set_projection_audit_in_tx(
                &mut tx,
                &RuleSetProjectionAuditEntry {
                    rule_set_id: row.rule_set_id,
                    entry_id: None,
                    aggregate_type: ProjectionAggregate::RuleSet.as_str(),
                    aggregate_id: row.rule_set_id,
                    event_id: &rule_projection.event_id,
                    source_generation: rule_projection.source_generation,
                    operation_id: &operation_id,
                    actor_id,
                    change_type: "BIND_CARD",
                    old_value_json: None,
                    new_value_json: Some(&addition_detail.to_string()),
                    tenant_id: rule_projection.tenant_id,
                },
            )
            .await?;
            added_event_ids.extend(
                addition
                    .into_iter()
                    .map(|entry| entry.event_id)
                    .collect::<Vec<_>>(),
            );
        }

        // ── Phase 3: source UPDATE（锁定状态下 template 谓词作为第二道防线）──
        let result = sqlx::query(
            "UPDATE user_card SET template_id=? WHERE card_id=? AND card_status='ACTIVE'",
        )
        .bind(template_id)
        .bind(card_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AstralError::Database(format!("Update user_card failed: {e}")))?;
        if result.rows_affected() == 0 {
            return Err(AstralError::NotFound("user card not found".into()));
        }

        // ── Phase 4: 投影 + 审计（与 source UPDATE 同一事务）────────────────
        let parent_projection = append_projection_with_metadata(
            &mut tx,
            ProjectionAggregate::Card,
            card_id,
            "CARD_UPDATE",
            actor_id,
            &operation_id,
        )
        .await?;
        let detail = serde_json::json!({
            "actorId": actor_id,
            "ownerUserId": owner_user_id,
            "targetCardId": card_id,
            "operationId": operation_id,
            "parentEventId": parent_projection.event_id,
            "fromTemplateId": locked.template_id,
            "toTemplateId": template_id,
            "templateChanged": true,
            "removedContributionEventIds": removed_event_ids,
            "addedContributionEventIds": added_event_ids,
            "action": "card_template_change",
        });
        insert_user_card_mutation_audit_in_tx(
            &mut tx,
            actor_id,
            card_id,
            "card_template_change",
            "CARD_UPDATED",
            &operation_id,
            locked.tenant_id,
            locked.domain_id,
            &detail.to_string(),
        )
        .await?;
        arm_card_commit_fence(&source_guard);
        let commit_result = tx.commit().await;
        settle_card_commit_fence(&source_guard, &commit_result);
        commit_result
            .map_err(|e| AstralError::Database(format!("Commit card update tx failed: {e}")))?;
        Ok(())
    }
}

/// Require a locked card row to remain owned by the authenticated actor and ACTIVE.
/// All mutation paths call this only after selecting the row `FOR UPDATE`.
fn require_actor_owned_active_card(
    locked: &LockedCardRow,
    actor_id: i64,
    card_id: i64,
    operation: &str,
) -> Result<i64, AstralError> {
    if locked.card_status != "ACTIVE" {
        return Err(AstralError::Permission(format!(
            "{operation} requires an ACTIVE user card"
        )));
    }
    let owner_user_id = locked.user_id.filter(|id| *id > 0).ok_or_else(|| {
        AstralError::Validation(format!(
            "user card {card_id} has no usable owner user id; refusing mutation without a provable owner"
        ))
    })?;
    if owner_user_id != actor_id {
        return Err(AstralError::Permission(format!(
            "Card ownership denied for {operation}"
        )));
    }
    Ok(owner_user_id)
}

/// 事务内锁定的用户卡身份事实（全部字段来自锁定行，不信任请求旧读）。
#[derive(Debug, Clone, sqlx::FromRow)]
struct LockedCardRow {
    card_status: String,
    user_id: Option<i64>,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
    /// `update_user_card` 专用；status 路径不读取（SQL 不返回该列）。
    #[allow(dead_code)]
    template_id: Option<i64>,
}

// ─────────────────────────────────────────────────────────────────────────────
// 卡状态迁移状态机（对齐 trustgraph `update_card`，纯逻辑，fail-closed）
// ─────────────────────────────────────────────────────────────────────────────

/// 可写入的 canonical 状态字母表（对齐 handler 白名单与 Java canonical 状态）。
const CARD_STATUS_ALPHABET: [&str; 4] = ["ACTIVE", "INACTIVE", "DISABLED", "SUSPENDED"];

/// 纯校验：请求携带的目标状态必须在 canonical 字母表内并归一为大写。
fn normalize_requested_card_status(raw: &str) -> Result<String, AstralError> {
    let upper = raw.trim().to_uppercase();
    if CARD_STATUS_ALPHABET.contains(&upper.as_str()) {
        Ok(upper)
    } else {
        Err(AstralError::Validation(format!(
            "card_status must be one of {CARD_STATUS_ALPHABET:?}, got {raw:?}"
        )))
    }
}

/// 卡状态迁移状态机（纯逻辑，fail-closed）。
///
/// 以锁定行证明的当前状态为准：
/// - 同状态：无迁移（允许回显，事件语义为 CARD_UPDATE）；
/// - ACTIVE → {INACTIVE, SUSPENDED, DISABLED}：离开 ACTIVE 的停用面，允许
///   （CARD REVOKE + actor/operation 元数据 + 同事务审计关联）；
/// - 其余一切迁移：拒绝 —— identity 侧不存在 restore/bind 守卫入口，任何把卡
///   送回 ACTIVE 的请求一律 fail-closed（与 trustgraph restore 语义一致：恢复
///   绝不隐式复活 grant，必须走显式守卫专用路径）。
fn validate_card_status_transition(current: &str, requested: &str) -> Result<(), AstralError> {
    if current == requested {
        return Ok(());
    }
    if current == "ACTIVE" && requested != "ACTIVE" {
        return Ok(());
    }
    let guidance = match (current, requested) {
        ("DISABLED", _) => {
            "DISABLED (revoked) cards may only leave that state through the guarded restore path \
             (trustgraph PUT /user-cards/{id}/restore); identity does not offer a restore entry"
        }
        (_, "ACTIVE") => {
            "re-entering ACTIVE is only allowed through guarded dedicated paths \
             (bind for PENDING/INACTIVE, restore for DISABLED); refusing an implicit \
             authorization revival"
        }
        _ => "generic update may only move a card out of ACTIVE (INACTIVE/SUSPENDED/DISABLED)",
    };
    Err(AstralError::Validation(format!(
        "card status transition {current} -> {requested} is not permitted through the generic \
         update path: {guidance}"
    )))
}

/// 状态变更离开 ACTIVE 的判定（纯逻辑）：以锁定行当前状态为基准 —— 只有
/// ACTIVE → 非 ACTIVE 是吊销面；同状态回显与未携带状态都不是吊销。状态机
/// （`validate_card_status_transition`）只放行同状态与离开 ACTIVE 两族迁移，
/// 因此非退出分支内不存在其他真实状态变化。
fn classify_card_status_exits_active(locked_status: &str, requested_status: &str) -> bool {
    locked_status == "ACTIVE" && requested_status != "ACTIVE"
}

// ─────────────────────────────────────────────────────────────────────────────
// 稳定 operation id 纯派生（与 trustgraph 同一契约：缺失 header 的路径以锁定中
// 的 durable 代次确定性派生，随机 fallback 绝不允许进入账本/事件链）
// ─────────────────────────────────────────────────────────────────────────────

/// 模板绑定卡创建：`user-card:create:{card_id}:tpl:{template_id}:ruleset-gen:{gen}`。
/// 与 trustgraph `derive_create_card_template_operation_id` 逐字节同格式，保证
/// 重放一致且两侧派生值域分离（card id 全局唯一）。
fn derive_create_card_template_operation_id(
    card_id: i64,
    template_id: i64,
    locked_ruleset_generation: i64,
) -> String {
    format!("user-card:create:{card_id}:tpl:{template_id}:ruleset-gen:{locked_ruleset_generation}")
}

/// 状态变更/模板变更（离开 ACTIVE 或回显）的稳定 operation id 纯派生：
/// `user-card:update:{card_id}:gen:{locked CARD head generation}`。
/// 与 trustgraph `derive_update_card_operation_id` 同一契约：card id 与代次任一
/// 非法即 Validation fail-closed，绝不以非法身份进入账本/事件链。
fn derive_update_card_operation_id(
    card_id: i64,
    locked_generation: i64,
) -> Result<String, AstralError> {
    if card_id <= 0 || locked_generation < 0 {
        return Err(AstralError::Validation(format!(
            "update-card operation identity requires a positive card id and a non-negative \
             locked CARD head generation, got card_id={card_id}, generation={locked_generation}"
        )));
    }
    Ok(format!(
        "user-card:update:{card_id}:gen:{locked_generation}"
    ))
}

/// 正数 actor 门禁（纯校验）：授权 source mutation 必须携带 Gateway 已验证的
/// 操作者，缺失或非正数整体拒绝，绝不以系统身份冒充人类操作者。
fn require_positive_actor(actor_id: i64, action: &'static str) -> Result<(), AstralError> {
    if actor_id <= 0 {
        return Err(AstralError::Auth(format!(
            "{action} requires a verified positive actor id propagated from the HTTP handler \
             (x-user-id); refusing an unattributable authorization mutation"
        )));
    }
    Ok(())
}

/// 模板绑定卡的最小 ledger scope 合同校验（纯逻辑，先于任何 durable 写入）：
/// tenant 必须非空正数、属主 user 必须非空正数、domain/template 携带时必须正数。
fn validate_template_card_ledger_scope(
    user_id: i64,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
    template_id: i64,
) -> Result<(), AstralError> {
    if template_id <= 0 {
        return Err(AstralError::Validation(format!(
            "create card requires a positive template id, got {template_id}"
        )));
    }
    if user_id <= 0 {
        return Err(AstralError::Validation(format!(
            "template-bound card creation requires a positive owner user id, got {user_id}"
        )));
    }
    let Some(tenant_id) = tenant_id else {
        return Err(AstralError::Validation(
            "template-bound card creation requires a positive tenant scope; refusing to \
             materialize ledger grants for a tenantless card"
                .into(),
        ));
    };
    if tenant_id <= 0 {
        return Err(AstralError::Validation(format!(
            "template-bound card creation requires a positive tenant scope, got {tenant_id}"
        )));
    }
    if let Some(domain_id) = domain_id {
        if domain_id <= 0 {
            return Err(AstralError::Validation(format!(
                "create card requires a positive domain id when scoped, got {domain_id}"
            )));
        }
    }
    Ok(())
}

/// 跨租户绑定判定纯逻辑（对齐 trustgraph `validate_binding_tenants` / Java
/// `RuleSetService.bindCardToRuleSet`）：
/// - 规则集与卡租户都非空且不一致 → 拒绝；
/// - 仅一侧有租户归属 → 拒绝，避免无法证明的跨范围绑定；
/// - 其余（同租户 / 都无租户）→ 允许。
fn validate_binding_tenants(
    rule_set_tenant: Option<i64>,
    card_tenant: Option<i64>,
) -> Result<(), AstralError> {
    match (rule_set_tenant, card_tenant) {
        (Some(rule_set_tenant), Some(card_tenant)) if rule_set_tenant != card_tenant => {
            return Err(AstralError::Permission(format!(
                "cross-tenant rule set binding not allowed: rule_set_tenant={rule_set_tenant}, card_tenant={card_tenant}"
            )));
        }
        (Some(_), None) => {
            return Err(AstralError::Permission(
                "tenant-scoped rule set cannot be bound to a tenantless card".into(),
            ));
        }
        (None, Some(_)) => {
            return Err(AstralError::Permission(
                "rule set without tenant_id cannot be bound in tenant context".into(),
            ));
        }
        (None, None) | (Some(_), Some(_)) => {}
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// 模板 RuleSet 绑定与条目事实（SQL 编排，锁定顺序对齐 binding-side 家族：
// user_card → rule_set 升序 → refs/entries（ORDER BY）→ grant head/delta）
// ─────────────────────────────────────────────────────────────────────────────

/// 锁定的模板 RuleSet 行：source 行与投影 head 由同一条升序 FOR UPDATE 捕获，
/// 是 tenant 校验、operation identity 派生与绑定物化的唯一事实来源。
#[derive(Debug, Clone, sqlx::FromRow)]
struct LockedTemplateRuleSetRow {
    rule_set_id: i64,
    tenant_id: Option<i64>,
    /// 该 RuleSet 当前的 durable 投影代次（head 缺失按 0 处理）。
    source_generation: Option<i64>,
}

/// 锁定模板下全部启用的 RuleSet（单语句，rule_set_id 升序；source 行与投影
/// head 一并 FOR UPDATE —— 与后续 ensure/rebuild 写入同一取锁方向）。
async fn lock_template_rule_sets_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    template_id: i64,
) -> Result<Vec<LockedTemplateRuleSetRow>, AstralError> {
    sqlx::query_as(
        "SELECT rs.rule_set_id AS rule_set_id, rs.tenant_id AS tenant_id, \
         h.source_generation AS source_generation \
         FROM rule_set rs \
         LEFT JOIN authorization_projection_head h \
           ON h.aggregate_type = 'RULE_SET' AND h.aggregate_id = rs.rule_set_id \
         WHERE rs.source_type = 'TEMPLATE' AND rs.source_id = ? AND rs.enabled = 1 \
         ORDER BY rs.rule_set_id ASC FOR UPDATE",
    )
    .bind(template_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| AstralError::Database(format!("Lock template rule sets failed: {e}")))
}

/// 模板 RuleSet 集合的不变量复核（纯逻辑）：主键查询天然唯一，结果集出现重复
/// 说明 template→rule_set 映射或读取被破坏 —— 事务内整体 fail-closed 拒绝。
fn ensure_unique_template_rule_set_ids(
    rows: &[LockedTemplateRuleSetRow],
) -> Result<(), AstralError> {
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        if !seen.insert(row.rule_set_id) {
            return Err(AstralError::Internal(format!(
                "template lookup returned duplicate template rule_set mapping {} in a single transaction; refusing to materialize a partially bound card",
                row.rule_set_id
            )));
        }
        // 负代次属于持久层不变式破坏，禁止作为 identity 派生输入。
        if row
            .source_generation
            .is_some_and(|generation| generation < 0)
        {
            return Err(AstralError::Validation(
                "RULE_SET projection head carries a negative generation; refusing to derive a create-card operation identity from it"
                    .into(),
            ));
        }
    }
    Ok(())
}

/// 写前锁定并读回的完整条目行（有效期按 UTC 文本读回，由共享组装层严格解析）。
#[derive(Debug, Clone, sqlx::FromRow)]
struct LockedRuleSetEntryRow {
    entry_id: i64,
    effect: String,
    resource_type: Option<String>,
    resource_id: Option<i64>,
    action_code: Option<String>,
    condition_json: Option<String>,
    #[allow(dead_code)]
    priority: i32,
    enabled: i32,
    valid_from: Option<String>,
    valid_to: Option<String>,
}

const LOCKED_RULE_SET_ENTRY_SELECT: &str =
    "entry_id AS entry_id, effect AS effect, resource_type AS resource_type, \
     resource_id AS resource_id, action_code AS action_code, condition_json AS condition_json, \
     priority AS priority, enabled AS enabled, \
     DATE_FORMAT(valid_from, '%Y-%m-%dT%H:%i:%s') AS valid_from, \
     DATE_FORMAT(valid_to, '%Y-%m-%dT%H:%i:%s') AS valid_to";

/// 锁定读取规则集条目（FOR UPDATE，entry_id 升序；`only_enabled` 过滤禁用行）。
async fn read_rule_set_entries_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    only_enabled: bool,
) -> Result<Vec<LockedRuleSetEntryRow>, AstralError> {
    let predicate = if only_enabled { " AND enabled = 1" } else { "" };
    sqlx::query_as::<_, LockedRuleSetEntryRow>(&format!(
        "SELECT {LOCKED_RULE_SET_ENTRY_SELECT} FROM rule_set_entry \
         WHERE rule_set_id = ?{predicate} ORDER BY entry_id FOR UPDATE"
    ))
    .bind(rule_set_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| AstralError::Database(format!("Lock rule_set_entry failed: {e}")))
}

/// 物化候选分类（纯逻辑）：enabled=1 且 effect 为 ALLOW 的条目是有效授权来源；
/// DENY（任何大小写）不是 canonical ALLOW、禁用行不生效 —— 两者安全跳过；
/// 其余未知 effect 值 fail-closed，不猜测语义。
fn materializable_allow_entries(
    entries: &[LockedRuleSetEntryRow],
) -> Result<Vec<&LockedRuleSetEntryRow>, AstralError> {
    entries
        .iter()
        .filter(|entry| entry.enabled == 1)
        .map(|entry| {
            let effect = entry.effect.trim();
            if effect.eq_ignore_ascii_case("ALLOW") {
                Ok(Some(entry))
            } else if effect.eq_ignore_ascii_case("DENY") {
                Ok(None)
            } else {
                Err(AstralError::Validation(format!(
                    "rule set entry {} carries unknown effect {:?}; refusing to classify it as an authorization contribution",
                    entry.entry_id, effect
                )))
            }
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|rows| rows.into_iter().flatten().collect())
}

/// 条目的 canonical 授权语义（resource/action 必须非空且可归一化；旧行为空时
/// 物化阶段按 canonical 合同显式拒绝，而不是 SQL 解码失败）。
fn canonical_entry_grant_fields(
    entry: &LockedRuleSetEntryRow,
) -> Result<(&str, &str), AstralError> {
    let resource = entry
        .resource_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AstralError::Validation(format!(
                "rule set entry {} lacks a usable resource; refusing to materialize a canonical grant",
                entry.entry_id
            ))
        })?;
    let action = entry
        .action_code
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            AstralError::Validation(format!(
                "rule set entry {} lacks a usable action; refusing to materialize a canonical grant",
                entry.entry_id
            ))
        })?;
    Ok((resource, action))
}

/// 已物化的一条账本贡献关联证据（entry × 独立事件号）。
struct ContributionEvidence {
    entry_id: i64,
    event_id: String,
}

/// 模板绑定 ADD 物化（对齐 trustgraph `append_card_create_ruleset_entry_adds_in_tx`
/// + `materialize_ruleset_adds_for_bound_card_in_tx`）。
///
/// 流程：条目锁定读取 → ALLOW-only 分类 → 每贡献独立可重放事件号 → ADD rev1
/// base0→target1（经共享 `astral_db::grant_ledger` 组装层，与 trustgraph 同一实现）。
/// 归属事实由调用方从本事务写入/锁定的行传入，正数 id / 租户边界逐项复核。
#[allow(clippy::too_many_arguments)]
async fn materialize_template_adds_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    card_projection: &ProjectionEventIdentity,
    actor_id: i64,
    operation_id: &str,
    ref_id: i64,
    card_id: i64,
    card_user_id: i64,
    card_tenant_id: i64,
    card_domain_id: Option<i64>,
    ref_type: &str,
) -> Result<Vec<ContributionEvidence>, AstralError> {
    if ref_id <= 0 || card_id <= 0 || rule_set_id <= 0 {
        return Err(AstralError::Internal(
            "template rule set binding requires positive card/rule-set/ref identifiers".into(),
        ));
    }
    let user_id = (card_user_id > 0).then_some(card_user_id).ok_or_else(|| {
        AstralError::Validation(format!(
            "card {card_id} has no usable owner user id; refusing to materialize template rule set grants without a provable owner"
        ))
    })?;
    // 归属事实合同：正数 id / 租户边界（创建路径不得物化不可证明的贡献）。
    if card_tenant_id <= 0 {
        return Err(AstralError::Validation(format!(
            "card {card_id} has a NULL/non-positive tenant scope; refusing to materialize rule set grants without a tenant boundary"
        )));
    }
    // 用户上下文 actor（正数）直接进入 provenance；canonical 合同拒绝非正 actor。
    let actor_user_id = (actor_id > 0).then_some(actor_id);

    let entries = read_rule_set_entries_in_tx(tx, rule_set_id, true).await?;
    let allow_entries = materializable_allow_entries(&entries)?;
    let mut added = Vec::with_capacity(allow_entries.len());
    for entry in allow_entries {
        let (resource, action) = canonical_entry_grant_fields(entry)?;
        let facts = RuleSetEntryLedgerFacts {
            tenant_id: card_tenant_id,
            domain_id: card_domain_id,
            card_id,
            user_id,
            rule_set_id,
            entry_id: entry.entry_id,
            ref_id,
            ref_type,
            resource,
            resource_id: entry.resource_id,
            action,
            condition_json: entry.condition_json.as_deref(),
            valid_from: entry.valid_from.as_deref(),
            valid_to: entry.valid_to.as_deref(),
        };
        let contribution_event_id =
            derive_ruleset_contribution_event_id(operation_id, &facts, RuleSetMutationKind::Add)?;
        let draft = build_ruleset_add_draft(
            &facts,
            operation_id,
            actor_user_id,
            card_projection,
            &contribution_event_id,
        )?;
        let (base_version, target_version) =
            next_delta_version(None).map_err(map_grant_repository_error)?;
        append_ruleset_grant_delta_in_tx(tx, &draft, base_version, target_version).await?;
        added.push(ContributionEvidence {
            entry_id: entry.entry_id,
            event_id: contribution_event_id,
        });
    }
    Ok(added)
}

/// 模板解绑 REMOVE 物化（对齐 trustgraph `materialize_ruleset_removals_for_card_in_tx`）：
/// head 缺失即 fail-closed（未 backfill 的 ALLOW 老数据禁止静默跳过，否则解绑会
/// 把账本里的活跃授权留成幽灵）；每贡献以 entry×card×ref 维度派生独立事件号。
#[allow(clippy::too_many_arguments)]
async fn materialize_template_removes_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    card_projection: &ProjectionEventIdentity,
    operation_id: &str,
    ref_id: i64,
    card_id: i64,
    card_user_id: i64,
    card_tenant_id: i64,
    card_domain_id: Option<i64>,
    ref_type: &str,
    allow_entries: &[&LockedRuleSetEntryRow],
) -> Result<Vec<ContributionEvidence>, AstralError> {
    let mut removed = Vec::with_capacity(allow_entries.len());
    for entry in allow_entries {
        let (resource, action) = canonical_entry_grant_fields(entry)?;
        let facts = RuleSetEntryLedgerFacts {
            tenant_id: card_tenant_id,
            domain_id: card_domain_id,
            card_id,
            user_id: card_user_id,
            rule_set_id,
            entry_id: entry.entry_id,
            ref_id,
            ref_type,
            resource,
            resource_id: entry.resource_id,
            action,
            condition_json: entry.condition_json.as_deref(),
            valid_from: entry.valid_from.as_deref(),
            valid_to: entry.valid_to.as_deref(),
        };
        let grant_id = derive_ruleset_identity(&facts)?;
        // head 缺失即 fail-closed：未版本化的授权无法安全撤销。
        let head = read_grant_head_for_update_in_tx(
            tx,
            card_tenant_id,
            RULE_SET_AGGREGATE_TYPE,
            rule_set_id,
            grant_id,
        )
        .await
        .map_err(map_grant_repository_error)?
        .ok_or_else(|| {
            AstralError::Validation(format!(
                "rule set entry {} has no versioned grant under card {}; refusing to revoke an un-versioned authorization",
                entry.entry_id, card_id
            ))
        })?;
        let last_target = read_latest_delta_target_version_for_update_in_tx(
            tx,
            card_tenant_id,
            RULE_SET_AGGREGATE_TYPE,
            rule_set_id,
            head.grant_id,
        )
        .await
        .map_err(map_grant_repository_error)?;
        let (base_version, target_version) =
            next_delta_version(last_target).map_err(map_grant_repository_error)?;
        let contribution_event_id = derive_ruleset_contribution_event_id(
            operation_id,
            &facts,
            RuleSetMutationKind::Remove,
        )?;
        let draft = build_ruleset_remove_draft(
            &facts,
            &head,
            operation_id,
            card_projection,
            &contribution_event_id,
        )?;
        append_ruleset_grant_delta_in_tx(tx, &draft, base_version, target_version).await?;
        removed.push(ContributionEvidence {
            entry_id: entry.entry_id,
            event_id: contribution_event_id,
        });
    }
    Ok(removed)
}

// ─────────────────────────────────────────────────────────────────────────────
// RULE_SET 投影证明（对齐 trustgraph `ensure_rule_set_projection_in_tx`：
// 同一 durable initial proof —— head 缺失或不一致时补写 INITIAL_REBUILD）
// ─────────────────────────────────────────────────────────────────────────────

const RULE_SET_INITIAL_REBUILD_CHANGE_TYPE: &str = "INITIAL_REBUILD";

#[derive(Debug, sqlx::FromRow)]
struct RuleSetProjectionHeadRow {
    source_generation: i64,
    last_event_id: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct RuleSetProjectionEventRow {
    source_generation: i64,
    tenant_id: Option<i64>,
    event_type: String,
    payload_json: Option<String>,
    status: String,
}

fn rule_set_projection_event_type_is_supported(event_type: &str) -> bool {
    matches!(event_type, EVENT_TYPE_RULE_SET_UPDATE | EVENT_TYPE_REVOKE)
}

fn rule_set_projection_event_status_is_acceptable(status: &str) -> bool {
    matches!(status, "PENDING" | "PROCESSED")
}

fn nullable_json_i64(value: &serde_json::Value) -> Option<Option<i64>> {
    if value.is_null() {
        Some(None)
    } else {
        value.as_i64().map(Some)
    }
}

fn rule_set_projection_payload_is_valid(
    payload_json: Option<&str>,
    rule_set_id: i64,
    source_generation: i64,
    tenant_id: Option<i64>,
) -> bool {
    let Some(payload_json) = payload_json else {
        return false;
    };
    let Ok(payload) = serde_json::from_str::<serde_json::Value>(payload_json) else {
        return false;
    };
    let actor_valid = payload
        .get("actorId")
        .and_then(serde_json::Value::as_i64)
        .is_some_and(|actor_id| actor_id == SYSTEM_ACTOR_ID || actor_id > 0);
    let operation_valid = payload
        .get("operationId")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|operation_id| !operation_id.trim().is_empty());
    actor_valid
        && operation_valid
        && payload.get("ruleSetId").and_then(serde_json::Value::as_i64) == Some(rule_set_id)
        && payload
            .get("generation")
            .and_then(serde_json::Value::as_i64)
            == Some(source_generation)
        && payload.get("tenantId").and_then(nullable_json_i64) == Some(tenant_id)
}

/// A current RuleSet projection event may be an update or a revoke. `REVOKE`
/// is not limited to deleting a RuleSet: deny-entry and binding-removal source
/// mutations deliberately use it while the RuleSet snapshot remains valid.
fn rule_set_projection_event_is_valid(
    event: &RuleSetProjectionEventRow,
    rule_set_id: i64,
    source_generation: i64,
    expected_tenant_id: Option<i64>,
) -> bool {
    event.source_generation == source_generation
        && event.tenant_id == expected_tenant_id
        && rule_set_projection_event_type_is_supported(&event.event_type)
        && rule_set_projection_event_status_is_acceptable(&event.status)
        && rule_set_projection_payload_is_valid(
            event.payload_json.as_deref(),
            rule_set_id,
            source_generation,
            expected_tenant_id,
        )
}

fn rule_set_projection_evidence_is_valid(event_is_valid: bool, source_audit_count: i64) -> bool {
    event_is_valid && source_audit_count > 0
}

/// Ensure a referenced RuleSet has the same durable initial proof used by
/// trustgraph card creation. Only a missing or inconsistent proof appends a
/// RULE_SET event; a normal card bind never mutates rule_set source.
async fn ensure_rule_set_projection_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    expected_tenant_id: Option<i64>,
    actor_id: i64,
    operation_id: &str,
) -> Result<(), AstralError> {
    let head: Option<RuleSetProjectionHeadRow> = sqlx::query_as(
        "SELECT source_generation, last_event_id \
         FROM authorization_projection_head \
         WHERE aggregate_type = 'RULE_SET' AND aggregate_id = ? FOR UPDATE",
    )
    .bind(rule_set_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| AstralError::Database(format!("Resolve RuleSet projection head failed: {e}")))?;

    let Some(RuleSetProjectionHeadRow {
        source_generation,
        last_event_id,
    }) = head
    else {
        append_initial_rule_set_projection_in_tx(
            tx,
            rule_set_id,
            expected_tenant_id,
            actor_id,
            operation_id,
        )
        .await?;
        return Ok(());
    };
    let Some(event_id) = last_event_id
        .as_deref()
        .map(str::trim)
        .filter(|event_id| !event_id.is_empty())
    else {
        append_initial_rule_set_projection_in_tx(
            tx,
            rule_set_id,
            expected_tenant_id,
            actor_id,
            operation_id,
        )
        .await?;
        return Ok(());
    };

    let event: Option<RuleSetProjectionEventRow> = sqlx::query_as(
        "SELECT source_generation, tenant_id, event_type, payload_json, status \
         FROM authorization_projection_outbox \
         WHERE aggregate_type = 'RULE_SET' AND aggregate_id = ? AND event_id = ? \
         FOR UPDATE",
    )
    .bind(rule_set_id)
    .bind(event_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| AstralError::Database(format!("Resolve RuleSet projection event failed: {e}")))?;
    let event_valid = event.as_ref().is_some_and(|event| {
        rule_set_projection_event_is_valid(
            event,
            rule_set_id,
            source_generation,
            expected_tenant_id,
        )
    });
    if !event_valid {
        append_initial_rule_set_projection_in_tx(
            tx,
            rule_set_id,
            expected_tenant_id,
            actor_id,
            operation_id,
        )
        .await?;
        return Ok(());
    }

    let source_audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM rule_set_projection_audit \
         WHERE aggregate_type = 'RULE_SET' AND aggregate_id = ? \
           AND event_id = ? AND source_generation = ? \
           AND change_type <> 'REBUILD_SNAPSHOT' AND tenant_id <=> ?",
    )
    .bind(rule_set_id)
    .bind(event_id)
    .bind(source_generation)
    .bind(expected_tenant_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|e| AstralError::Database(format!("Verify RuleSet source audit failed: {e}")))?;
    // 旧链 REBUILD_SNAPSHOT 复核随 head READY 语义退役（迁移 20260831000001）：
    // 快照重建通道已下线，有效当前事件 + source 审计关联即为完备证明。
    if rule_set_projection_evidence_is_valid(event_valid, source_audit_count) {
        return Ok(());
    }

    append_initial_rule_set_projection_in_tx(
        tx,
        rule_set_id,
        expected_tenant_id,
        actor_id,
        operation_id,
    )
    .await
}

/// 补写 RULE_SET 初始投影证明（INITIAL_REBUILD 审计），语义与 trustgraph 一致。
async fn append_initial_rule_set_projection_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    rule_set_id: i64,
    expected_tenant_id: Option<i64>,
    actor_id: i64,
    operation_id: &str,
) -> Result<(), AstralError> {
    let projection = append_projection_with_metadata(
        tx,
        ProjectionAggregate::RuleSet,
        rule_set_id,
        EVENT_TYPE_RULE_SET_UPDATE,
        actor_id,
        operation_id,
    )
    .await?;
    if projection.tenant_id != expected_tenant_id {
        return Err(AstralError::Permission(
            "RuleSet projection tenant does not match card binding scope".into(),
        ));
    }
    let new_value = serde_json::json!({
        "reason": "INITIAL_REBUILD_FOR_CARD_RULE_SET_BINDING",
        "ruleSetId": rule_set_id,
        "tenantId": expected_tenant_id,
        "actorId": actor_id,
        "operationId": operation_id,
    })
    .to_string();
    insert_rule_set_projection_audit_in_tx(
        tx,
        &RuleSetProjectionAuditEntry {
            rule_set_id,
            entry_id: None,
            aggregate_type: ProjectionAggregate::RuleSet.as_str(),
            aggregate_id: rule_set_id,
            event_id: &projection.event_id,
            source_generation: projection.source_generation,
            operation_id,
            actor_id,
            change_type: RULE_SET_INITIAL_REBUILD_CHANGE_TYPE,
            old_value_json: None,
            new_value_json: Some(&new_value),
            tenant_id: expected_tenant_id,
        },
    )
    .await
}

// ─────────────────────────────────────────────────────────────────────────────
// 投影与审计写入（全部在调用方 source transaction 内，不 commit、不触 Redis/MQ）
// ─────────────────────────────────────────────────────────────────────────────

/// 追加携带可信 actor/operation 元数据的投影事件（CARD/RULE_SET 通用）。
async fn append_projection_with_metadata(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    aggregate: ProjectionAggregate,
    aggregate_id: i64,
    event_type: &str,
    actor_id: i64,
    operation_id: &str,
) -> Result<ProjectionEventIdentity, AstralError> {
    astral_db::append_projection_event_with_metadata_in_tx(
        tx,
        aggregate,
        aggregate_id,
        event_type,
        Some(ProjectionEventMetadata {
            actor_id,
            operation_id,
        }),
    )
    .await
}

/// 锁定并读取 CARD 投影 head 的 durable 代次（缺失按 0；负值属持久层不变式
/// 破坏，禁止作为 identity 派生输入）。
async fn lock_card_head_generation_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    card_id: i64,
) -> Result<i64, AstralError> {
    let locked_generation: i64 = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT source_generation FROM authorization_projection_head \
         WHERE aggregate_type = 'CARD' AND aggregate_id = ? FOR UPDATE",
    )
    .bind(card_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| AstralError::Database(format!("Lock CARD projection head failed: {e}")))?
    .flatten()
    .unwrap_or(0);
    if locked_generation < 0 {
        return Err(AstralError::Validation(
            "CARD projection head carries a negative generation; refusing to derive a card \
             mutation operation identity from it"
                .into(),
        ));
    }
    Ok(locked_generation)
}

/// `rule_set_projection_audit` 审计关联输入（与 trustgraph 同表同列语义）。
struct RuleSetProjectionAuditEntry<'a> {
    rule_set_id: i64,
    entry_id: Option<i64>,
    aggregate_type: &'a str,
    aggregate_id: i64,
    event_id: &'a str,
    source_generation: i64,
    operation_id: &'a str,
    actor_id: i64,
    change_type: &'a str,
    old_value_json: Option<&'a str>,
    new_value_json: Option<&'a str>,
    tenant_id: Option<i64>,
}

#[derive(Debug, sqlx::FromRow)]
struct RuleSetProjectionAuditRow {
    rule_set_id: i64,
    entry_id: Option<i64>,
    changed_by: i64,
    change_type: String,
    old_value_json: Option<String>,
    new_value_json: Option<String>,
    tenant_id: Option<i64>,
    aggregate_type: String,
    aggregate_id: i64,
    source_generation: i64,
    operation_id: String,
}

/// 审计行不可变列冲突复核（重放/幂等分支）：已存在行与本次输入任一关联字段
/// 不一致都说明复用冲突，fail-closed 拒绝，绝不静默覆盖。
fn immutable_mismatch_fields(
    existing: &RuleSetProjectionAuditRow,
    incoming: &RuleSetProjectionAuditEntry<'_>,
) -> Vec<&'static str> {
    let mut mismatches = Vec::new();
    if existing.change_type != incoming.change_type {
        mismatches.push("change_type");
    }
    if existing.rule_set_id != incoming.rule_set_id {
        mismatches.push("rule_set_id");
    }
    if existing.entry_id != incoming.entry_id {
        mismatches.push("entry_id");
    }
    if existing.changed_by != incoming.actor_id {
        mismatches.push("changed_by");
    }
    if existing.old_value_json.as_deref() != incoming.old_value_json {
        mismatches.push("old_value_json");
    }
    if existing.new_value_json.as_deref() != incoming.new_value_json {
        mismatches.push("new_value_json");
    }
    if existing.tenant_id != incoming.tenant_id {
        mismatches.push("tenant_id");
    }
    if existing.aggregate_type != incoming.aggregate_type {
        mismatches.push("aggregate_type");
    }
    if existing.aggregate_id != incoming.aggregate_id {
        mismatches.push("aggregate_id");
    }
    if existing.source_generation != incoming.source_generation {
        mismatches.push("source_generation");
    }
    if existing.operation_id != incoming.operation_id {
        mismatches.push("operation_id");
    }
    mismatches
}

/// 把 RuleSet 投影审计关联行写入同一个 InnoDB 事务（对齐 trustgraph
/// `insert_rule_set_projection_audit_in_tx`，含唯一冲突幂等复核分支）。
async fn insert_rule_set_projection_audit_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    entry: &RuleSetProjectionAuditEntry<'_>,
) -> Result<(), AstralError> {
    if (entry.actor_id != SYSTEM_ACTOR_ID && entry.actor_id <= 0)
        || entry.event_id.trim().is_empty()
        || entry.operation_id.trim().is_empty()
    {
        return Err(AstralError::Validation(
            "RuleSet audit requires actor, event_id, and operation_id".into(),
        ));
    }
    let result = sqlx::query(
        "INSERT INTO rule_set_projection_audit \
         (rule_set_id, entry_id, changed_by, change_type, old_value_json, new_value_json, \
          changed_at, tenant_id, aggregate_type, aggregate_id, event_id, source_generation, operation_id) \
         VALUES (?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(), ?, ?, ?, ?, ?, ?)",
    )
    .bind(entry.rule_set_id)
    .bind(entry.entry_id)
    .bind(entry.actor_id)
    .bind(entry.change_type)
    .bind(entry.old_value_json)
    .bind(entry.new_value_json)
    .bind(entry.tenant_id)
    .bind(entry.aggregate_type)
    .bind(entry.aggregate_id)
    .bind(entry.event_id)
    .bind(entry.source_generation)
    .bind(entry.operation_id)
    .execute(&mut **tx)
    .await;

    match result {
        Ok(_) => Ok(()),
        Err(error)
            if error
                .as_database_error()
                .is_some_and(|db| db.is_unique_violation()) =>
        {
            let existing: Option<RuleSetProjectionAuditRow> = sqlx::query_as(
                "SELECT rule_set_id, entry_id, changed_by, change_type, old_value_json, \
                        new_value_json, tenant_id, aggregate_type, aggregate_id, \
                        source_generation, operation_id \
                 FROM rule_set_projection_audit \
                 WHERE event_id = ? AND source_generation = ? AND change_type = ? \
                 FOR UPDATE",
            )
            .bind(entry.event_id)
            .bind(entry.source_generation)
            .bind(entry.change_type)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|lookup_error| {
                AstralError::Database(format!(
                    "RuleSet audit duplicate lookup failed after insert conflict: {lookup_error}"
                ))
            })?;

            let Some(existing) = existing else {
                return Err(AstralError::Database(format!(
                    "RuleSet audit insert conflicted with an unknown unique key: {error}"
                )));
            };
            let mismatches = immutable_mismatch_fields(&existing, entry);
            if mismatches.is_empty() {
                Ok(())
            } else {
                Err(AstralError::Validation(format!(
                    "RuleSet audit immutable correlation conflict for event_id={}, source_generation={}, change_type={}: {}",
                    entry.event_id,
                    entry.source_generation,
                    entry.change_type,
                    mismatches.join(", ")
                )))
            }
        }
        Err(error) => Err(AstralError::Database(format!(
            "RuleSet audit insert failed: {error}"
        ))),
    }
}

/// 卡状态变更（离开 ACTIVE）的 durable 审计关联输入（`audit_log` 表）。
struct UserCardStatusAuditEntry<'a> {
    actor_id: i64,
    owner_user_id: i64,
    target_card_id: i64,
    operation_id: &'a str,
    parent_event_id: &'a str,
    from_status: &'a str,
    to_status: &'a str,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
}

/// 把用户卡状态变更的审计关联写入同一事务（对齐 trustgraph
/// `insert_user_card_status_audit_in_tx`：与 source UPDATE、CARD REVOKE
/// head/outbox、ELIGIBILITY 事件共享同一稳定 operation_id）。
async fn insert_user_card_status_audit_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    entry: &UserCardStatusAuditEntry<'_>,
) -> Result<(), AstralError> {
    if entry.actor_id <= 0 || entry.target_card_id <= 0 {
        return Err(AstralError::Validation(
            "user card status audit requires a positive actor id and target card id".into(),
        ));
    }
    if entry.operation_id.trim().is_empty() || entry.parent_event_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "user card status audit requires operation and parent event correlation".into(),
        ));
    }
    for status in [entry.from_status, entry.to_status] {
        if !CARD_STATUS_ALPHABET.contains(&status) {
            return Err(AstralError::Validation(format!(
                "user card status audit requires canonical statuses from {CARD_STATUS_ALPHABET:?}, got {status:?}"
            )));
        }
    }
    let detail = serde_json::json!({
        "actorId": entry.actor_id,
        "ownerUserId": entry.owner_user_id,
        "targetCardId": entry.target_card_id,
        "operationId": entry.operation_id,
        "parentEventId": entry.parent_event_id,
        "fromStatus": entry.from_status,
        "toStatus": entry.to_status,
        "action": "status_revoke",
    })
    .to_string();
    sqlx::query(
        "INSERT INTO audit_log \
         (user_id, card_id, action, resource, decision, reason, event_type, request_id, \
          domain_id, tenant_id, detail) \
         VALUES (?, ?, 'card_status_change', 'user_card', ?, NULL, 'USER_CARD_MUTATION', ?, ?, ?, ?)",
    )
    .bind(entry.actor_id)
    .bind(entry.target_card_id)
    // decision 与父 CARD REVOKE 投影事件的语义对齐（撤销事实贯穿两条链）。
    .bind("CARD_REVOKED")
    .bind(entry.operation_id)
    .bind(entry.domain_id)
    .bind(entry.tenant_id)
    .bind(detail)
    .execute(&mut **tx)
    .await
    .map_err(|e| AstralError::Database(format!("user card status audit insert failed: {e}")))?;
    Ok(())
}

/// 把用户卡模板变更的审计关联行写入同一事务（`audit_log` 表，事件族与状态
/// 变更审计一致：`USER_CARD_MUTATION`）。
#[allow(clippy::too_many_arguments)]
async fn insert_user_card_mutation_audit_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    actor_id: i64,
    target_card_id: i64,
    action: &'static str,
    decision: &'static str,
    operation_id: &str,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
    detail: &str,
) -> Result<(), AstralError> {
    if actor_id <= 0 || target_card_id <= 0 || operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "user card mutation audit requires a positive actor/target card and operation id"
                .into(),
        ));
    }
    sqlx::query(
        "INSERT INTO audit_log \
         (user_id, card_id, action, resource, decision, reason, event_type, request_id, \
          domain_id, tenant_id, detail) \
         VALUES (?, ?, ?, 'user_card', ?, NULL, 'USER_CARD_MUTATION', ?, ?, ?, ?)",
    )
    .bind(actor_id)
    .bind(target_card_id)
    .bind(action)
    .bind(decision)
    .bind(operation_id)
    .bind(domain_id)
    .bind(tenant_id)
    .bind(detail)
    .execute(&mut **tx)
    .await
    .map_err(|e| AstralError::Database(format!("user card mutation audit insert failed: {e}")))?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
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

impl UserCardRow {
    fn into_card(self) -> UserCard {
        UserCard {
            card_id: Some(self.card_id),
            user_id: self.user_id,
            domain_id: self.domain_id,
            card_type: self.card_type,
            card_status: self.card_status,
            template_id: self.template_id,
            level_id: self.level_id,
            priority: self.priority,
            is_primary: self.is_primary,
            valid_from: self.valid_from,
            valid_until: self.valid_until,
            created_at: self.created_at,
            updated_at: self.updated_at,
            tenant_id: self.tenant_id,
        }
    }
}

/// 辅助镜像激活的卡事实写者栅栏获取：**hub 已装则栅栏必须可得**（取不到即
/// `Err`，由写点 `?` 拒绝写入——绝不静默 no-op）；hub 未安装（独立 Identity
/// 部署）→ `Ok(None)`，行为不变。返回 `Ok(Some(guard))` 时必须在裸
/// `pool.begin()` / autocommit 执行**之前**：writer-active 期间 hub 辅助读面
/// fail-closed，镜像激活/对账不会与本写者的未决事务交错。
fn begin_card_source_transaction(
) -> Result<Option<astral_db::memory_projection_hub::SourceTransactionGuard>, AstralError> {
    match astral_db::memory_projection_hub() {
        None => Ok(None),
        Some(hub) => hub.begin_source_transaction().map(Some).ok_or_else(|| {
            AstralError::Internal(
                "memory projection hub is installed but the source writer guard is unavailable"
                    .to_owned(),
            )
        }),
    }
}

/// commit/autocommit await 前武装取消栅栏：guard 私有 `commit_unproven=true`。
/// await 窗口内任务被取消/连接掉线时 Drop 见 atomic=true → sticky uncertain
/// ——覆盖"结果后标记"无法覆盖的取消窗口。hub 未装（None）为 no-op。
fn arm_card_commit_fence(
    source_guard: &Option<astral_db::memory_projection_hub::SourceTransactionGuard>,
) {
    if let Some(guard) = source_guard {
        guard.mark_commit_started();
    }
}

/// 写结果已判定后的栅栏收尾：Ok → `mark_commit_proven` 清私有 atomic（Drop
/// 正常释放）；Err → 保持显式 `mark_uncertain`（uncertain_source sticky，既有
/// 语义；Drop 的 atomic 分支同向，双写幂等）。
fn settle_card_commit_fence(
    source_guard: &Option<astral_db::memory_projection_hub::SourceTransactionGuard>,
    result: &Result<(), sqlx::Error>,
) {
    match result {
        Ok(()) => {
            if let Some(guard) = source_guard {
                guard.mark_commit_proven();
            }
        }
        Err(_) => {
            if let Some(guard) = source_guard {
                guard.mark_uncertain();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn self_service_mutations_require_locked_active_owner() {
        let active = super::LockedCardRow {
            card_status: "ACTIVE".into(),
            user_id: Some(7),
            tenant_id: Some(3),
            domain_id: Some(4),
            template_id: Some(2),
        };
        assert_eq!(
            super::require_actor_owned_active_card(&active, 7, 11, "template mutation")
                .expect("matching actor must retain access"),
            7
        );
        assert!(
            super::require_actor_owned_active_card(&active, 8, 11, "template mutation").is_err()
        );

        let inactive = super::LockedCardRow {
            card_status: "SUSPENDED".into(),
            ..active.clone()
        };
        assert!(
            super::require_actor_owned_active_card(&inactive, 7, 11, "template mutation").is_err()
        );
    }

    #[test]
    fn owner_guard_follows_the_locked_row_in_each_self_service_mutation() {
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/srv/card_repository.rs"
        ));
        let implementation = &source[source
            .find("impl CardRepository for SqlxCardRepository")
            .expect("card repository implementation must exist")..];
        for (method, next) in [
            (
                "async fn update_user_card_status(",
                "async fn update_user_card(",
            ),
            ("async fn update_user_card(", "impl UserCardRow"),
        ] {
            let body_start = implementation
                .find(method)
                .expect("mutation method must exist");
            let body = &implementation[body_start..];
            let body_end = body.find(next).expect("next method boundary must exist");
            let body = &body[..body_end];
            let locked = body.find("FOR UPDATE").expect("card row must be locked");
            let owner_check = body
                .find("require_actor_owned_active_card")
                .or_else(|| body.find("locked.user_id != Some(actor_id)"))
                .expect("owner must be checked in mutation transaction");
            assert!(
                locked < owner_check,
                "locked owner fact must be checked after FOR UPDATE"
            );
        }
    }

    #[test]
    fn card_issue_locks_existing_tenant_before_user_card_insert() {
        // 发卡与 delete_tenant/delete_org 的并发边界回归（源形状，无 IO）：
        // create_user_card 必须在写 user_card 之前以事务内 FOR UPDATE 锁定
        // 已存在的 tenant 行（统一锁序 tenant → user_card），且锁定失败路径
        // fail-closed（租户不存在拒绝发卡）。
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/srv/card_repository.rs"
        ));
        // 先切到 impl 块：trait 里也有同名方法声明，find 必须跳过 trait。
        let source = &source[source
            .find("impl CardRepository for SqlxCardRepository")
            .expect("CardRepository impl must stay in card_repository.rs")..];
        let body_start = source
            .find("async fn create_user_card(")
            .expect("create_user_card implementation must stay in card_repository.rs");
        let body = &source[body_start..];
        let body_end = body
            .find("async fn list_user_cards(")
            .expect("list_user_cards must follow create_user_card in this file");
        let body = &body[..body_end];
        let tenant_lock = body
            .find("SELECT tenant_id FROM tenant WHERE tenant_id = ? FOR UPDATE")
            .expect("card issue must lock the existing tenant row inside the tx");
        let insert = body
            .find("INSERT INTO user_card")
            .expect("card issue must insert user_card in this file");
        assert!(
            tenant_lock < insert,
            "tenant row lock must be taken before the user_card INSERT"
        );
        assert!(
            body.contains("refusing to issue a user_card"),
            "a missing tenant must fail the issuance closed"
        );
    }

    #[test]
    fn card_fact_writers_hold_hub_guard_across_the_whole_transaction() {
        // 辅助镜像激活前置条件回归（源形状，无 IO）：四个卡事实写事务都必须
        // 先于 pool.begin 获取 hub 写者栅栏，每个 commit await 前武装取消栅栏
        //（mark_commit_started），结果判定后统一 settle（Ok → proven 清私有
        // atomic；Err → mark_uncertain 保持既有语义）。
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/srv/card_repository.rs"
        ));
        // 先切到 impl 块：trait 里也有同名方法声明，find 必须跳过 trait。
        let impl_source = &source[source
            .find("impl CardRepository for SqlxCardRepository")
            .expect("CardRepository impl must stay in card_repository.rs")..];
        for (anchor, next_anchor, label) in [
            (
                "async fn ensure_active_identity_card(",
                "async fn delete_created_identity_card(",
                "ensure_active_identity_card",
            ),
            (
                "async fn create_user_card(",
                "async fn list_user_cards(",
                "create_user_card",
            ),
            (
                "async fn update_user_card_status(",
                "async fn update_user_card(",
                "update_user_card_status",
            ),
            (
                "async fn update_user_card(",
                "impl UserCardRow",
                "update_user_card",
            ),
        ] {
            let start = impl_source
                .find(anchor)
                .unwrap_or_else(|| panic!("{label} must stay in card_repository.rs"));
            let end = impl_source[start..]
                .find(next_anchor)
                .unwrap_or_else(|| panic!("{label} body bound must stay stable"));
            let body = &impl_source[start..start + end];
            let guard = body
                .find("begin_card_source_transaction()")
                .unwrap_or_else(|| panic!("{label} must acquire the hub writer guard"));
            let first_commit = body
                .find("tx.commit()")
                .unwrap_or_else(|| panic!("{label} must commit in this file"));
            assert!(
                guard < first_commit,
                "{label}: hub writer guard must be acquired before pool.begin/tx"
            );
            let commits = body.matches("tx.commit()").count();
            let arms = body
                .matches("arm_card_commit_fence(&source_guard);")
                .count();
            let settles = body
                .matches("settle_card_commit_fence(&source_guard")
                .count();
            assert_eq!(
                commits, arms,
                "{label}: every commit await must be preceded by the cancellation fence"
            );
            assert_eq!(
                commits, settles,
                "{label}: every commit result must be settled (proven on Ok / uncertain on Err)"
            );
        }
    }

    #[test]
    fn autocommit_identity_card_delete_holds_guard_and_marks_unknown() {
        // 第 5 个写点（无 pool.begin 的 autocommit DELETE）同样必须先取栅栏、
        // execute await 前武装取消栅栏，且 Err 视为未知结果 settle 为
        // mark_uncertain——不能因无事务省略。
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/srv/card_repository.rs"
        ));
        let impl_source = &source[source
            .find("impl CardRepository for SqlxCardRepository")
            .expect("CardRepository impl must stay in card_repository.rs")..];
        let start = impl_source
            .find("async fn delete_created_identity_card(")
            .expect("delete_created_identity_card implementation must stay in this file");
        let end = impl_source[start..]
            .find("async fn create_user_card(")
            .expect("create_user_card must follow delete_created_identity_card");
        let body = &impl_source[start..start + end];
        let guard = body
            .find("let source_guard = begin_card_source_transaction()?;")
            .expect("autocommit write point must acquire the guard with ? (fail-closed)");
        let arm = body
            .find("arm_card_commit_fence(&source_guard);")
            .expect("autocommit await must be armed before execute");
        let settle = body
            .find("settle_card_commit_fence(&source_guard, &result)")
            .expect("autocommit result must be settled (proven on Ok / uncertain on Err)");
        let execute = body
            .find(".execute(&self.db)")
            .expect("the DELETE must execute in this file");
        assert!(
            guard < execute,
            "guard must be held before the autocommit write"
        );
        assert!(
            arm < execute,
            "the cancellation fence must be armed before the autocommit await"
        );
        assert!(
            settle > execute,
            "fence settlement must follow the write result"
        );
    }

    #[test]
    fn guard_acquisition_fails_closed_when_hub_is_installed() {
        // begin_card_source_transaction 语义钉（源形状）：hub 已装 + 栅栏不可得
        // 必须返回 Err（写点 `?` 拒绝），只有 hub 未安装才 Ok(None)——
        // 不允许"已装但失败"被吞成 no-op。全部 5 个写点都带 `?`。
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/srv/card_repository.rs"
        ));
        assert!(
            source
                .contains("-> Result<Option<astral_db::memory_projection_hub::SourceTransactionGuard>, AstralError>"),
            "the acquisition helper must return Result, not Option"
        );
        assert!(source.contains("None => Ok(None),"));
        assert!(
            source.contains(".ok_or_else(") && source.contains("AstralError::Internal("),
            "an installed hub must refuse a missing guard"
        );
        // 计数限定在 CardRepository impl 内（到 impl UserCardRow 为止），
        // 排除本测试模块自身的字符串字面量。
        let impl_source = &source[source
            .find("impl CardRepository for SqlxCardRepository")
            .expect("CardRepository impl must stay in card_repository.rs")
            ..source
                .find("impl UserCardRow")
                .expect("UserCardRow impl must follow the trait impl")];
        assert_eq!(
            impl_source
                .matches("let source_guard = begin_card_source_transaction()?;")
                .count(),
            5,
            "exactly the five card-fact write points acquire the guard fail-closed"
        );
    }
}
