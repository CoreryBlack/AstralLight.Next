//! 认证数据访问 — AuthRepository
//!
//! 对齐 Java `AuthService` 的 Mapper/Port 边界（PlatformUserMapper、
//! UserLocalCredentialMapper、UserIdentityMapper、IdentityCardMapper）。
//! 只返回领域记录，不返回 Axum/HTTP 类型。

use async_trait::async_trait;
use sqlx::MySqlPool;
use time::PrimitiveDateTime;

use astral_types::AstralError;

use crate::auth::{LoginAggregateRow, PasswordCredential};
use crate::srv::source_writer_guard;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PlatformUserRecord {
    pub username: String,
    pub display_name: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct IdentityCardRecord {
    pub card_id: i64,
    pub card_status: Option<String>,
}

/// 登录卡片聚合（对应 api.rs 原 LoginCardRow 查询）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LoginCardRecord {
    pub card_id: i64,
    pub user_id: Option<i64>,
    pub card_type: String,
    pub card_status: String,
    pub template_id: Option<i64>,
    pub level_id: Option<i64>,
    pub priority: Option<i32>,
    pub is_primary: Option<bool>,
    pub domain_id: Option<i64>,
    pub tenant_id: Option<i64>,
    pub template_code: Option<String>,
    pub template_name: Option<String>,
    pub level_code: Option<String>,
    pub level_name: Option<String>,
    pub level_no: Option<i32>,
    pub card_name: Option<String>,
    pub action_codes: Option<String>,
    pub base_rule_set_ids: Option<String>,
    pub overlay_rule_set_ids: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PermissionRecord {
    pub resource_type: String,
    pub action_code: String,
}

/// 当前用户资料（对应 api.rs 原 get_profile 查询）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ProfileRecord {
    pub user_id: i64,
    pub user_no: String,
    pub username: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub avatar_url: Option<String>,
    pub status: String,
    pub source_type: Option<String>,
    pub card_id: Option<i64>,
}

/// 登录/第三方登录时创建的 device session 参数。
#[derive(Debug, Clone)]
pub struct NewLoginSession {
    pub family_id: i64,
    pub user_id: i64,
    pub device_id: String,
    pub device_type: Option<String>,
    pub client_app_id: Option<String>,
    pub channel_code: Option<String>,
    pub current_user_card_id: Option<i64>,
    pub refresh_hash: String,
    pub refresh_expiry: PrimitiveDateTime,
}

#[async_trait]
pub trait AuthRepository: Send + Sync {
    async fn find_login_aggregate(
        &self,
        login: &str,
    ) -> Result<Option<LoginAggregateRow>, AstralError>;

    /// 按 Java `resolveLocalCredential` 优先级解析本地凭证：
    /// phone(规范化) → username(login_name) → email(platform_user)。
    async fn find_login_aggregate_resolved(
        &self,
        username: Option<&str>,
        phone: Option<&str>,
        email: Option<&str>,
    ) -> Result<Option<LoginAggregateRow>, AstralError>;

    async fn insert_register_user(
        &self,
        username: &str,
        password_hash: &str,
        real_name: Option<&str>,
        email: Option<&str>,
        phone: Option<&str>,
    ) -> Result<(i64, i64), AstralError>;

    async fn load_password_credential(
        &self,
        user_id: i64,
    ) -> Result<Option<PasswordCredential>, AstralError>;

    async fn update_password_hash(&self, user_id: i64, new_hash: &str) -> Result<(), AstralError>;

    async fn update_last_login_at(&self, user_id: i64) -> Result<(), AstralError>;

    async fn check_login_name_exists(&self, login_name: &str) -> Result<bool, AstralError>;

    async fn find_identity_by_account(
        &self,
        provider: &str,
        account_key: &str,
    ) -> Result<Option<i64>, AstralError>;

    async fn insert_identity(
        &self,
        user_id: i64,
        provider: &str,
        account_key: &str,
        subject_key: &str,
    ) -> Result<(), AstralError>;

    async fn find_platform_user(
        &self,
        user_id: i64,
    ) -> Result<Option<PlatformUserRecord>, AstralError>;

    async fn find_identity_card(
        &self,
        user_id: i64,
    ) -> Result<Option<IdentityCardRecord>, AstralError>;

    async fn find_login_cards(&self, user_id: i64) -> Result<Vec<LoginCardRecord>, AstralError>;

    /// 登录响应权限（与 api.rs 原语义一致：ALLOW + enabled，无时间窗过滤）。
    async fn find_login_permissions(
        &self,
        card_id: i64,
    ) -> Result<Vec<PermissionRecord>, AstralError>;

    /// 租户状态（对齐 Java 签发侧 `LEFT JOIN tenant t ... t.status AS tenant_status`；
    /// 租户缺失返回 None，JWT 省略该 claim）
    async fn find_tenant_status(&self, tenant_id: i64) -> Result<Option<String>, AstralError>;

    async fn find_profile(&self, user_id: i64) -> Result<Option<ProfileRecord>, AstralError>;

    async fn find_email_owner(
        &self,
        email: &str,
        exclude_user_id: i64,
    ) -> Result<Option<i64>, AstralError>;

    async fn find_phone_owner(
        &self,
        phone: &str,
        exclude_user_id: i64,
    ) -> Result<Option<i64>, AstralError>;

    async fn update_profile(
        &self,
        user_id: i64,
        display_name: Option<&str>,
        email: Option<&str>,
        phone: Option<&str>,
        avatar_url: Option<&str>,
    ) -> Result<(), AstralError>;

    /// 登录/第三方登录时创建 auth_device_session，返回新 session_id。
    async fn insert_login_session(&self, session: NewLoginSession) -> Result<i64, AstralError>;

    /// Bind the first v2 refresh JWT to the already-created durable session.
    async fn update_initial_refresh_token(
        &self,
        session_id: i64,
        expected_hash: &str,
        refresh_hash: &str,
        refresh_expiry: PrimitiveDateTime,
    ) -> Result<(), AstralError>;

    /// Redis 投影失败后的 family 清理（与 api.rs 原内联 DELETE 语义一致）。
    async fn delete_active_family(&self, family_id: i64, user_id: i64) -> Result<(), AstralError>;
}

pub struct SqlxAuthRepository {
    db: MySqlPool,
}

impl SqlxAuthRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

/// Starter 授权载体在注册事务内的唯一合法决策。
///
/// 规范授权不变式要求正式 eligibility/evidence 范围必须带租户边界；starter 卡契约
/// 又要求平台级无租户模板及其 TEMPLATE RuleSet。两者不可同时满足，因此注册事务
/// 永远无法为 starter user_card / card_rule_set_ref 绑定证明合法授权范围。
/// 本枚举刻意不提供任何“授予/绑定”变体：tenantless 规范授予路径在类型层不存在，
/// 注册只保留既有 tenantless 身份契约（identity_card/credential）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StarterGrantDecision {
    /// 无租户 ACTIVE starter 模板：跳过/延迟 starter 授权载体，不写任何授权行。
    DeferTenantlessTemplate,
}

/// 依据 DEFAULT_STARTER_CARD 模板的租户归属决定注册期处置：
/// tenantless 模板 → `DeferTenantlessTemplate`（跳过/延迟 starter 授权载体）；
/// tenantful 模板违反平台级 starter 契约 → fail closed（由调用方回滚注册事务）。
fn decide_starter_grant(
    starter_template_tenant_id: Option<i64>,
) -> Result<StarterGrantDecision, AstralError> {
    match starter_template_tenant_id {
        None => Ok(StarterGrantDecision::DeferTenantlessTemplate),
        Some(_) => Err(AstralError::Permission(
            "tenantful DEFAULT_STARTER_CARD template cannot be used as platform-level starter card"
                .into(),
        )),
    }
}

#[async_trait]
impl AuthRepository for SqlxAuthRepository {
    async fn find_login_aggregate(
        &self,
        login: &str,
    ) -> Result<Option<LoginAggregateRow>, AstralError> {
        crate::auth::find_login_aggregate(&self.db, login).await
    }

    async fn find_login_aggregate_resolved(
        &self,
        username: Option<&str>,
        phone: Option<&str>,
        email: Option<&str>,
    ) -> Result<Option<LoginAggregateRow>, AstralError> {
        crate::auth::find_login_aggregate_resolved(&self.db, username, phone, email).await
    }

    async fn insert_register_user(
        &self,
        username: &str,
        password_hash: &str,
        real_name: Option<&str>,
        email: Option<&str>,
        phone: Option<&str>,
    ) -> Result<(i64, i64), AstralError> {
        // 注册 source 事务（platform_user / user_local_credential / identity_card）
        // 的 hub writer 栅栏：begin 前取得（hub 已装则必须可得，不可得即拒绝
        // 注册），COMMIT await 前武装取消栅栏，commit 证明成功后 proven 释放；
        // pre-commit 错误（已知回滚，含 tenantful starter 模板 fail-closed）随
        // Drop 干净释放，绝不误报 uncertain。
        let source_guard = source_writer_guard::begin_source_write()?;
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AstralError::Database(format!("Begin tx failed: {e}")))?;

        let user_result = sqlx::query(
            "INSERT INTO platform_user (user_no, display_name, email, phone, source_type, status) \
             VALUES (?, ?, ?, ?, 'LOCAL', 'ACTIVE')",
        )
        .bind(username)
        .bind(real_name)
        .bind(email)
        .bind(phone)
        .execute(&mut *tx)
        .await
        .map_err(|e| AstralError::Database(format!("Insert platform_user failed: {e}")))?;
        let user_id = user_result.last_insert_id() as i64;

        sqlx::query(
            "INSERT INTO user_local_credential \
             (user_id, login_name, password_hash, password_algo, password_set_at, status) \
             VALUES (?, ?, ?, 'ARGON2ID', CURRENT_TIMESTAMP, 'ACTIVE')",
        )
        .bind(user_id)
        .bind(username)
        .bind(password_hash)
        .execute(&mut *tx)
        .await
        .map_err(|e| AstralError::Database(format!("Insert user_local_credential failed: {e}")))?;

        let card_result = sqlx::query(
            "INSERT INTO identity_card (user_id, status, token_version) VALUES (?, 'ACTIVE', 1)",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AstralError::Database(format!("Insert identity_card failed: {e}")))?;
        let card_id = card_result.last_insert_id() as i64;

        // 对齐 Java “无模板则不发 starter 卡”的跳过语义，同时落实规范授权不变式：
        // 正式 eligibility/evidence 范围要求租户边界，而 starter 契约是平台级无租户
        // （platform_v4 关联：rule_set.source_type='TEMPLATE' AND source_id=template_id，
        // 亦无租户），注册事务永远无法为 starter user_card / card_rule_set_ref 绑定
        // 证明合法授权范围。因此注册路径不再创建 tenantless starter 授权载体
        // （旧 INSERT IGNORE 绑定语义已移除，绝不静默写入 legacy-only 授权）：
        // - 无 ACTIVE 模板 → 维持 Java 语义跳过；
        // - tenantless ACTIVE 模板 → 延迟 starter 授权载体，注册只保留既有
        //   tenantless 身份契约（platform_user / user_local_credential / identity_card）；
        // - tenantful 模板违反平台级 starter 契约 → fail closed，事务回滚。
        // 仅读模板目录做处置判定，不再加写锁（本路径无任何基于该行的写入）。
        let starter_template: Option<(i64, Option<i64>)> = sqlx::query_as(
            "SELECT template_id, tenant_id FROM user_card_template \
             WHERE template_code = 'DEFAULT_STARTER_CARD' AND status = 'ACTIVE' \
             ORDER BY template_id ASC LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AstralError::Database(format!("Resolve starter template failed: {e}")))?;
        if let Some((starter_template_id, starter_template_tenant_id)) = starter_template {
            // 穷尽匹配：StarterGrantDecision 不存在可插入 starter 卡/RuleSet 绑定的
            // “授予”变体，tenantless 规范授予路径在类型层不可达。
            match decide_starter_grant(starter_template_tenant_id)? {
                StarterGrantDecision::DeferTenantlessTemplate => {
                    tracing::info!(
                        user_id,
                        starter_template_id,
                        "starter card grant deferred: tenantless starter template cannot \
                         satisfy formal eligibility/evidence scope; registration keeps \
                         identity card/credential only"
                    );
                }
            }
        }

        source_writer_guard::arm_commit_fence(&source_guard);
        tx.commit()
            .await
            .map_err(|e| AstralError::Database(format!("Commit tx failed: {e}")))?;
        source_writer_guard::settle_commit_fence(&source_guard, true);
        drop(source_guard);

        Ok((user_id, card_id))
    }

    async fn load_password_credential(
        &self,
        user_id: i64,
    ) -> Result<Option<PasswordCredential>, AstralError> {
        sqlx::query_as::<_, PasswordCredential>(
            "SELECT user_id, password_hash, status \
             FROM user_local_credential \
             WHERE user_id = ? AND status = 'ACTIVE' LIMIT 1",
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AstralError::Database(format!("Load password credential failed: {e}")))
    }

    async fn update_password_hash(&self, user_id: i64, new_hash: &str) -> Result<(), AstralError> {
        // 凭证事实 autocommit 写：source 栅栏（hub 未装 no-op；await 窗口武装
        // 取消栅栏，结果判定后 settle）。
        let source_guard = source_writer_guard::begin_source_write()?;
        source_writer_guard::fenced_source_write(
            source_guard,
            sqlx::query(
                "UPDATE user_local_credential \
                 SET password_hash = ?, password_algo = 'ARGON2ID', password_updated_at = CURRENT_TIMESTAMP, \
                     must_change_password = 0, updated_at = CURRENT_TIMESTAMP \
                 WHERE user_id = ? AND status = 'ACTIVE'",
            )
            .bind(new_hash)
            .bind(user_id)
            .execute(&self.db),
        )
        .await
        .map_err(|e| AstralError::Database(format!("Update password hash failed: {e}")))?;
        Ok(())
    }

    async fn update_last_login_at(&self, user_id: i64) -> Result<(), AstralError> {
        sqlx::query(
            "UPDATE user_local_credential SET last_login_at = CURRENT_TIMESTAMP WHERE user_id = ?",
        )
        .bind(user_id)
        .execute(&self.db)
        .await
        .map_err(|e| AstralError::Database(format!("Update last_login_at failed: {e}")))?;
        Ok(())
    }

    async fn check_login_name_exists(&self, login_name: &str) -> Result<bool, AstralError> {
        let row: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM user_local_credential WHERE login_name = ?")
                .bind(login_name)
                .fetch_one(&self.db)
                .await
                .map_err(|e| AstralError::Database(format!("Check duplicate failed: {e}")))?;
        Ok(row.0 > 0)
    }

    async fn find_identity_by_account(
        &self,
        provider: &str,
        account_key: &str,
    ) -> Result<Option<i64>, AstralError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT user_id FROM user_identity WHERE provider = ? AND account_key = ? LIMIT 1",
        )
        .bind(provider)
        .bind(account_key)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AstralError::Database(format!("Query user_identity failed: {e}")))
    }

    async fn insert_identity(
        &self,
        user_id: i64,
        provider: &str,
        account_key: &str,
        subject_key: &str,
    ) -> Result<(), AstralError> {
        // 第三方身份绑定 autocommit 写：source 栅栏（hub 未装 no-op）。
        let source_guard = source_writer_guard::begin_source_write()?;
        source_writer_guard::fenced_source_write(
            source_guard,
            sqlx::query(
                "INSERT IGNORE INTO user_identity \
                 (user_id, provider, account_key, subject_key, verified) VALUES (?, ?, ?, ?, ?)",
            )
            .bind(user_id)
            .bind(provider)
            .bind(account_key)
            .bind(subject_key)
            .bind(true)
            .execute(&self.db),
        )
        .await
        .map_err(|e| AstralError::Database(format!("Insert user_identity failed: {e}")))?;
        Ok(())
    }

    async fn find_platform_user(
        &self,
        user_id: i64,
    ) -> Result<Option<PlatformUserRecord>, AstralError> {
        sqlx::query_as::<_, PlatformUserRecord>(
            "SELECT username, display_name, status FROM platform_user WHERE user_id = ?",
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AstralError::Database(format!("Query platform_user failed: {e}")))
    }

    async fn find_identity_card(
        &self,
        user_id: i64,
    ) -> Result<Option<IdentityCardRecord>, AstralError> {
        sqlx::query_as::<_, IdentityCardRecord>(
            "SELECT card_id, status as card_status \
             FROM identity_card WHERE user_id = ? AND status = 'ACTIVE' \
               AND (expires_at IS NULL OR expires_at >= UTC_TIMESTAMP()) \
             LIMIT 1",
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AstralError::Database(format!("Query identity_card failed: {e}")))
    }

    async fn find_login_cards(&self, user_id: i64) -> Result<Vec<LoginCardRecord>, AstralError> {
        // 卡域查询只含身份/平台目录展示字段；权限摘要由共享快照查询批量回填
        let mut cards: Vec<LoginCardRecord> = sqlx::query_as::<_, LoginCardRecord>(
            "SELECT uc.card_id, uc.user_id, uc.card_type, uc.card_status, uc.template_id, uc.level_id, \
             uc.priority, uc.is_primary, uc.domain_id, uc.tenant_id, \
             t.template_code, t.template_name, l.level_code, l.level_name, l.level_no, \
             CONCAT(IFNULL(t.template_name,''), ' · ', IFNULL(l.level_name,'')) as card_name, \
             NULL as action_codes, NULL as base_rule_set_ids, NULL as overlay_rule_set_ids \
             FROM user_card uc \
             LEFT JOIN user_card_template t ON t.template_id = uc.template_id \
             LEFT JOIN user_card_level_definition l ON l.level_id = uc.level_id \
             WHERE uc.user_id = ? AND uc.card_status = 'ACTIVE' \
               AND uc.card_type != 'LEVEL_TEMPLATE_CARD' \
               AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
               AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()) \
             ORDER BY uc.is_primary DESC, uc.priority ASC, uc.card_id ASC",
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AstralError::Database(format!("Query user_cards failed: {e}")))?;

        // 批量回填权限摘要（快照读，无 N+1）
        let ids: Vec<i64> = cards.iter().map(|c| c.card_id).collect();
        let summaries = astral_db::load_card_permission_summaries(&self.db, &ids)
            .await
            .map_err(|e| AstralError::Database(format!("Query card summaries failed: {e}")))?;
        for card in &mut cards {
            let summary = summaries.get(&card.card_id);
            card.action_codes = summary.and_then(|s| s.action_codes.clone());
            card.base_rule_set_ids = summary.and_then(|s| s.base_rule_set_ids.clone());
            card.overlay_rule_set_ids = summary.and_then(|s| s.overlay_rule_set_ids.clone());
        }
        Ok(cards)
    }

    async fn find_login_permissions(
        &self,
        card_id: i64,
    ) -> Result<Vec<PermissionRecord>, AstralError> {
        // 权限视图读投影快照缓存（Cache-Aside + 投影门禁），不直读源表
        let rows = astral_db::find_effective_permissions_cached(&self.db, card_id)
            .await
            .map_err(|e| AstralError::Database(format!("Query card permissions failed: {e}")))?;
        Ok(rows
            .into_iter()
            .map(|row| PermissionRecord {
                resource_type: row.resource_type,
                action_code: row.action_code,
            })
            .collect())
    }

    async fn find_tenant_status(&self, tenant_id: i64) -> Result<Option<String>, AstralError> {
        sqlx::query_scalar::<_, String>("SELECT status FROM tenant WHERE tenant_id = ?")
            .bind(tenant_id)
            .fetch_optional(&self.db)
            .await
            .map_err(|e| AstralError::Database(format!("Query tenant status failed: {e}")))
    }

    async fn find_profile(&self, user_id: i64) -> Result<Option<ProfileRecord>, AstralError> {
        sqlx::query_as::<_, ProfileRecord>(
            "SELECT u.user_id, u.user_no, COALESCE(c.login_name, u.user_no) as username, \
             u.display_name, u.email, u.phone, u.avatar_url, u.status, u.source_type, ic.card_id \
             FROM platform_user u \
             LEFT JOIN user_local_credential c ON c.user_id = u.user_id AND c.status = 'ACTIVE' \
             LEFT JOIN identity_card ic ON ic.user_id = u.user_id AND ic.status = 'ACTIVE' \
             WHERE u.user_id = ? AND u.deleted_at IS NULL \
             ORDER BY ic.card_id LIMIT 1",
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AstralError::Database(format!("Query profile failed: {e}")))
    }

    async fn find_email_owner(
        &self,
        email: &str,
        exclude_user_id: i64,
    ) -> Result<Option<i64>, AstralError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT user_id FROM platform_user WHERE email = ? AND user_id <> ? AND deleted_at IS NULL LIMIT 1",
        )
        .bind(email)
        .bind(exclude_user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AstralError::Database(format!("Check email failed: {e}")))
    }

    async fn find_phone_owner(
        &self,
        phone: &str,
        exclude_user_id: i64,
    ) -> Result<Option<i64>, AstralError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT user_id FROM platform_user WHERE phone = ? AND user_id <> ? AND deleted_at IS NULL LIMIT 1",
        )
        .bind(phone)
        .bind(exclude_user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AstralError::Database(format!("Check phone failed: {e}")))
    }

    async fn update_profile(
        &self,
        user_id: i64,
        display_name: Option<&str>,
        email: Option<&str>,
        phone: Option<&str>,
        avatar_url: Option<&str>,
    ) -> Result<(), AstralError> {
        let result = sqlx::query(
            "UPDATE platform_user SET \
             display_name = COALESCE(?, display_name), \
             email = COALESCE(?, email), \
             phone = COALESCE(?, phone), \
             avatar_url = COALESCE(?, avatar_url), \
             updated_at = UTC_TIMESTAMP() \
             WHERE user_id = ? AND deleted_at IS NULL",
        )
        .bind(display_name.map(str::trim))
        .bind(email.map(str::trim))
        .bind(phone.map(str::trim))
        .bind(avatar_url.map(str::trim))
        .bind(user_id)
        .execute(&self.db)
        .await
        .map_err(|e| AstralError::Database(format!("Update profile failed: {e}")))?;
        if result.rows_affected() != 1 {
            return Err(AstralError::NotFound("user not found".into()));
        }
        Ok(())
    }

    async fn insert_login_session(&self, session: NewLoginSession) -> Result<i64, AstralError> {
        // 会话创建 autocommit 写：source 栅栏（hub 已装则 fail-closed；await
        // 窗口武装取消栅栏，结果判定后 settle）。
        let source_guard = source_writer_guard::begin_source_write()?;
        let result = source_writer_guard::fenced_source_write(
            source_guard,
            sqlx::query(
                "INSERT INTO auth_device_session \
                 (family_id, user_id, device_id, device_type, client_app_id, channel_code, \
                  current_user_card_id, session_state, session_version, session_epoch, \
                  refresh_token_hash, refresh_expires_at, status) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 1, 1, ?, ?, 'ACTIVE')",
            )
            .bind(session.family_id)
            .bind(session.user_id)
            .bind(session.device_id)
            .bind(session.device_type)
            .bind(session.client_app_id)
            .bind(session.channel_code)
            .bind(session.current_user_card_id)
            .bind(session.refresh_hash)
            .bind(session.refresh_expiry)
            .execute(&self.db),
        )
        .await
        .map_err(|e| AstralError::Database(format!("Save session failed: {e}")))?;
        if result.rows_affected() != 1 || result.last_insert_id() == 0 {
            return Err(AstralError::Database(
                "Save session failed: no durable session id".into(),
            ));
        }
        Ok(result.last_insert_id() as i64)
    }

    async fn update_initial_refresh_token(
        &self,
        session_id: i64,
        expected_hash: &str,
        refresh_hash: &str,
        refresh_expiry: PrimitiveDateTime,
    ) -> Result<(), AstralError> {
        // 初始 refresh 绑定事实 autocommit 写：source 栅栏（hub 未装 no-op；
        // CAS 未命中未发生 mutation，同样 proven 释放）。
        let source_guard = source_writer_guard::begin_source_write()?;
        let result = source_writer_guard::fenced_source_write(
            source_guard,
            sqlx::query(
                "UPDATE auth_device_session SET refresh_token_hash = ?, refresh_expires_at = ?, \
                 updated_at = UTC_TIMESTAMP() WHERE session_id = ? AND refresh_token_hash = ? \
                 AND status = 'ACTIVE' AND session_state = 'ACTIVE' AND session_version = 1 AND session_epoch = 1",
            )
            .bind(refresh_hash)
            .bind(refresh_expiry)
            .bind(session_id)
            .bind(expected_hash)
            .execute(&self.db),
        )
        .await
        .map_err(|e| AstralError::Database(format!("Bind initial refresh token failed: {e}")))?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Auth(
                "Initial session refresh binding was fenced".into(),
            ));
        }
        Ok(())
    }

    async fn delete_active_family(&self, family_id: i64, user_id: i64) -> Result<(), AstralError> {
        // family 清理（补偿路径）autocommit 写：source 栅栏（FK 级联删除会话，
        // 属会话事实 mutation；hub 未装 no-op）。
        let source_guard = source_writer_guard::begin_source_write()?;
        source_writer_guard::fenced_source_write(
            source_guard,
            sqlx::query(
                "DELETE FROM auth_token_family WHERE family_id = ? AND user_id = ? AND status = 'ACTIVE'",
            )
            .bind(family_id)
            .bind(user_id)
            .execute(&self.db),
        )
        .await
        .map_err(|e| AstralError::Database(format!("Cleanup token family failed: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 会话/凭证写点 source 栅栏形状回归（源形状，无 IO）：注册事务在 begin 前
    /// 取得栅栏、COMMIT await 前武装、commit 后 settle；五个单语句写点
    /// （insert_login_session / update_initial_refresh_token / update_password_hash
    /// / insert_identity / delete_active_family）均经 fenced_source_write 围栏。
    #[test]
    fn register_transaction_and_credential_writers_hold_the_source_writer_fence() {
        let source = include_str!("auth_repository.rs");
        // 先切到 impl 块：trait 里也有同名方法声明，find 必须跳过 trait。
        let impl_source = &source[source
            .find("impl AuthRepository for SqlxAuthRepository")
            .expect("AuthRepository impl must stay in auth_repository.rs")..];
        let body_between = |start: &str, end: &str| -> &str {
            impl_source
                .split(start)
                .nth(1)
                .unwrap_or_else(|| panic!("{start} must stay in the impl"))
                .split(end)
                .next()
                .unwrap_or_else(|| panic!("{end} must follow {start}"))
        };

        let register_body = body_between(
            "async fn insert_register_user(",
            "async fn load_password_credential(",
        );
        assert!(
            register_body
                .find("let source_guard = source_writer_guard::begin_source_write()")
                .expect("register tx must acquire the hub source writer guard")
                < register_body
                    // 多行方法链：self\n .db\n .begin()
                    .find(".begin()")
                    .expect("register tx must open its transaction"),
            "the register guard must be acquired before the transaction"
        );
        assert!(
            register_body
                .find("arm_commit_fence(&source_guard)")
                .unwrap()
                < register_body.find("tx.commit()").unwrap(),
            "the commit await must be armed by the cancellation fence"
        );
        assert!(
            register_body
                .find("settle_commit_fence(&source_guard, true)")
                .unwrap()
                > register_body.find("tx.commit()").unwrap(),
            "the fence is settled only after the commit outcome is proven"
        );

        for (method, end) in [
            (
                "async fn insert_login_session(",
                "async fn update_initial_refresh_token(",
            ),
            (
                "async fn update_initial_refresh_token(",
                "async fn delete_active_family(",
            ),
            ("async fn delete_active_family(", "#[cfg(test)]"), // trailing anchor: last impl method before tests
        ] {
            let body = body_between(method, end);
            assert!(
                body.contains("source_writer_guard::begin_source_write()")
                    && body.contains("source_writer_guard::fenced_source_write("),
                "{method} must run under the fenced source writer"
            );
        }

        let password_body = body_between(
            "async fn update_password_hash(",
            "async fn update_last_login_at(",
        );
        assert!(
            password_body.contains("source_writer_guard::begin_source_write()")
                && password_body.contains("source_writer_guard::fenced_source_write("),
            "update_password_hash must run under the fenced source writer"
        );
        let identity_body =
            body_between("async fn insert_identity(", "async fn find_platform_user(");
        assert!(
            identity_body.contains("source_writer_guard::begin_source_write()")
                && identity_body.contains("source_writer_guard::fenced_source_write("),
            "insert_identity must run under the fenced source writer"
        );
    }

    /// 形状测试：tenantless starter 模板的唯一出口是 `DeferTenantlessTemplate`
    /// （跳过/延迟授权载体）。穷尽匹配证明 `StarterGrantDecision` 不存在任何可插入
    /// starter user_card / card_rule_set_ref 绑定的“授予”变体，即注册路径不再声明
    /// tenantless 规范授予路径，也不会落入 INSERT IGNORE 类 legacy 授权写入。
    #[test]
    fn starter_grant_defers_tenantless_template_without_grant_path() {
        let decision = decide_starter_grant(None).expect("tenantless starter template must defer");
        match decision {
            StarterGrantDecision::DeferTenantlessTemplate => {}
        }
    }

    /// 形状测试：tenantful starter 模板违反平台级 starter 契约，必须 fail closed
    /// （不得降级为 tenantless 绑定，也不得静默写入 legacy-only 授权）。
    #[test]
    fn starter_grant_fails_closed_on_tenantful_template() {
        let error = decide_starter_grant(Some(7)).unwrap_err();
        assert!(
            matches!(&error, AstralError::Permission(message) if message.contains("tenantful")),
            "unexpected error: {error:?}"
        );
    }

    /// 形状测试：决策覆盖 `Option<i64>` 全域（None/Some 均有唯一确定出口），
    /// 注册事务内不存在第三个未定义分支。
    #[test]
    fn starter_grant_decision_is_total_over_template_tenant_scope() {
        assert!(matches!(
            decide_starter_grant(None),
            Ok(StarterGrantDecision::DeferTenantlessTemplate)
        ));
        assert!(decide_starter_grant(Some(0)).is_err());
        assert!(decide_starter_grant(Some(i64::MAX)).is_err());
        assert!(decide_starter_grant(None).is_ok());
    }
}
