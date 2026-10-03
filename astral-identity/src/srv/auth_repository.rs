//! 认证数据访问 — AuthRepository
//!
//! 对齐 Java `AuthService` 的 Mapper/Port 边界（PlatformUserMapper、
//! UserLocalCredentialMapper、UserIdentityMapper、IdentityCardMapper）。
//! 只返回领域记录，不返回 Axum/HTTP 类型。

use async_trait::async_trait;
use sqlx::{MySql, MySqlPool, QueryBuilder};
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

/// Existing generic login-session insertion parameters (kept stable for crate callers).
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

/// Single-use, actor-bound facts used by the atomic local-login issuance path.
#[derive(Debug, Clone)]
pub struct AtomicLoginSession {
    pub family_key: String,
    pub user_id: i64,
    pub expected_password_hash: String,
    pub credential_version: i64,
    pub migrated_password_hash: Option<String>,
    pub identity_card_id: i64,
    pub mfa_attempt_code: Option<String>,
    pub mfa_method: Option<String>,
    pub mfa_code: Option<String>,
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

    /// Stable compatibility entry point; the atomic revocation snapshot stays internal.
    async fn update_password_hash(&self, user_id: i64, new_hash: &str) -> Result<(), AstralError>;

    /// Atomically rotate a password and return the exact JTI snapshot committed to its v2 outbox.
    async fn update_password_hash_with_revocation(
        &self,
        user_id: i64,
        new_hash: &str,
        reason: &str,
        reset_token: Option<i64>,
    ) -> Result<Vec<String>, AstralError>;

    async fn update_password_hash_if_current(
        &self,
        user_id: i64,
        expected_hash: &str,
        expected_version: i64,
        new_hash: &str,
    ) -> Result<Vec<String>, AstralError>;

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

    /// Atomically revalidate the password/MFA actor and create a family+platform session.
    async fn create_login_family_and_session(
        &self,
        session: AtomicLoginSession,
    ) -> Result<(i64, i64), AstralError>;

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

    async fn update_password_transaction(
        &self,
        user_id: i64,
        expected_hash: Option<&str>,
        expected_version: Option<i64>,
        new_hash: &str,
        reason: &str,
        reset_token_id: Option<i64>,
    ) -> Result<Vec<String>, AstralError> {
        let source_guard = source_writer_guard::begin_source_write()?;
        let mut tx =
            self.db.begin().await.map_err(|e| {
                AstralError::Database(format!("Begin password update tx failed: {e}"))
            })?;
        let revoked_jtis = update_password_transaction_in_tx(
            &mut tx,
            user_id,
            expected_hash,
            expected_version,
            new_hash,
            reason,
            reset_token_id,
        )
        .await?;

        source_writer_guard::arm_commit_fence(&source_guard);
        tx.commit()
            .await
            .map_err(|e| AstralError::Database(format!("Commit password update tx failed: {e}")))?;
        source_writer_guard::settle_commit_fence(&source_guard, true);
        drop(source_guard);
        astral_db::note_revocations_in_process(
            &revoked_jtis,
            astral_db::REVOCATION_MIRROR_TTL_SECS,
        );
        Ok(revoked_jtis)
    }
}

pub(crate) async fn update_password_transaction_in_tx(
    tx: &mut sqlx::Transaction<'_, MySql>,
    user_id: i64,
    expected_hash: Option<&str>,
    expected_version: Option<i64>,
    new_hash: &str,
    reason: &str,
    reset_token_id: Option<i64>,
) -> Result<Vec<String>, AstralError> {
    let credential: Option<(String, i64)> = sqlx::query_as(
        "SELECT password_hash, credential_version FROM user_local_credential \
         WHERE user_id = ? AND status = 'ACTIVE' FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| AstralError::Database(format!("Lock password credential failed: {e}")))?;
    let Some((current_hash, current_version)) = credential else {
        if let Some(token_id) = reset_token_id {
            let _ = token_id;
        }
        return Err(AstralError::Auth("local credential not found".into()));
    };
    if current_version <= 0
        || expected_hash.is_some_and(|expected| expected != current_hash)
        || expected_version.is_some_and(|expected| expected != current_version)
    {
        return Err(AstralError::Auth(
            "credential changed; retry the operation".into(),
        ));
    }
    let next_version = current_version
        .checked_add(1)
        .ok_or_else(|| AstralError::Auth("Credential revision exhausted".into()))?;
    let jti_rows: Vec<(String,)> = sqlx::query_as(
        "SELECT jti FROM auth_session_jti_index WHERE user_id = ? AND status = 'ACTIVE' \
         AND expires_at > UTC_TIMESTAMP() ORDER BY jti LIMIT 4097 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| AstralError::Database(format!("Snapshot password revocation JTIs failed: {e}")))?;
    if jti_rows.len() > 4096 {
        return Err(AstralError::Validation(
            "Too many active credentials to rotate atomically; support is required".into(),
        ));
    }
    let revoked_jtis: Vec<String> = jti_rows.into_iter().map(|(jti,)| jti).collect();
    if let Some(token_id) = reset_token_id {
        let consumed = sqlx::query(
            "UPDATE password_reset_token SET used_at = UTC_TIMESTAMP() \
             WHERE id = ? AND user_id = ? AND used_at IS NULL AND expires_at > UTC_TIMESTAMP()",
        )
        .bind(token_id)
        .bind(user_id)
        .execute(&mut **tx)
        .await
        .map_err(|e| AstralError::Database(format!("Consume password reset token failed: {e}")))?;
        if consumed.rows_affected() != 1 {
            return Err(AstralError::Auth(
                "Invalid or already used password reset token".into(),
            ));
        }
    }
    if !revoked_jtis.is_empty() {
        let mut revoke = QueryBuilder::<MySql>::new(
            "UPDATE auth_session_jti_index SET status = 'DELETED', updated_at = UTC_TIMESTAMP() \
             WHERE user_id = ",
        );
        revoke.push_bind(user_id);
        revoke.push(" AND status = 'ACTIVE' AND jti IN (");
        let mut separated = revoke.separated(", ");
        for jti in &revoked_jtis {
            separated.push_bind(jti);
        }
        separated.push_unseparated(")");
        let result = revoke.build().execute(&mut **tx).await.map_err(|e| {
            AstralError::Database(format!("Revoke password JTI snapshot failed: {e}"))
        })?;
        if result.rows_affected() != revoked_jtis.len() as u64 {
            return Err(AstralError::Auth(
                "Password revocation JTI snapshot changed during transaction".into(),
            ));
        }
    }
    let changed = sqlx::query(
        "UPDATE user_local_credential SET password_hash = ?, password_algo = 'ARGON2ID', \
         credential_version = ?, password_updated_at = CURRENT_TIMESTAMP, \
         must_change_password = 0, updated_at = CURRENT_TIMESTAMP \
         WHERE user_id = ? AND status = 'ACTIVE' AND credential_version = ? \
           AND password_hash = ?",
    )
    .bind(new_hash)
    .bind(next_version)
    .bind(user_id)
    .bind(current_version)
    .bind(&current_hash)
    .execute(&mut **tx)
    .await
    .map_err(|e| AstralError::Database(format!("Update password credential failed: {e}")))?;
    if changed.rows_affected() != 1 {
        return Err(AstralError::Auth(
            "credential changed; retry the operation".into(),
        ));
    }

    sqlx::query(
        "UPDATE auth_device_session SET status = 'REVOKED', session_state = 'REVOKED', \
         session_version = session_version + 1, session_epoch = session_epoch + 1, \
         revoked_at = UTC_TIMESTAMP(), revoked_reason = ?, updated_at = UTC_TIMESTAMP() \
         WHERE user_id = ? AND status = 'ACTIVE' AND session_state = 'ACTIVE'",
    )
    .bind(reason)
    .bind(user_id)
    .execute(&mut **tx)
    .await
    .map_err(|e| {
        AstralError::Database(format!("Revoke sessions for password update failed: {e}"))
    })?;
    sqlx::query(
        "UPDATE auth_token_family SET status = 'REVOKED', revoked_at = UTC_TIMESTAMP(), \
         revoked_reason = ? \
         WHERE user_id = ? AND status = 'ACTIVE'",
    )
    .bind(reason)
    .bind(user_id)
    .execute(&mut **tx)
    .await
    .map_err(|e| {
        AstralError::Database(format!("Revoke families for password update failed: {e}"))
    })?;
    let operation_id = format!("identity:password:{user_id}:{next_version}");
    let payload = serde_json::json!({
        "v": 2,
        "userId": user_id,
        "jtis": revoked_jtis.clone(),
        "reason": reason,
    });
    sqlx::query(
        "INSERT INTO auth_session_outbox \
         (operation_id, session_id, event_type, sequence_number, projection_key, payload_json, status, created_at) \
         VALUES (?, NULL, 'REVOKE', 1, ?, ?, 'PENDING', UTC_TIMESTAMP())",
    )
    .bind(operation_id)
    .bind(format!("user:{user_id}"))
    .bind(payload.to_string())
    .execute(&mut **tx)
    .await
    .map_err(|e| AstralError::Database(format!("Write password revocation outbox failed: {e}")))?;

    Ok(revoked_jtis)
}

/// Starter 授权载体在注册事务内的唯一合法决策.
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

    async fn create_login_family_and_session(
        &self,
        session: AtomicLoginSession,
    ) -> Result<(i64, i64), AstralError> {
        let source_guard = source_writer_guard::begin_source_write()?;
        let mut tx =
            self.db.begin().await.map_err(|e| {
                AstralError::Database(format!("Begin login issuance tx failed: {e}"))
            })?;

        let credential: Option<(String, i64)> = sqlx::query_as(
            "SELECT password_hash, credential_version FROM user_local_credential \
             WHERE user_id = ? AND status = 'ACTIVE' FOR UPDATE",
        )
        .bind(session.user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| AstralError::Database(format!("Lock login credential failed: {e}")))?;
        let Some((current_hash, current_version)) = credential else {
            if let Some(attempt_code) = session.mfa_attempt_code.as_deref() {
                crate::srv::mfa::resolve_mfa_attempt_in_tx(
                    &mut tx,
                    attempt_code,
                    session.user_id,
                    session.mfa_method.as_deref().unwrap_or("UNKNOWN"),
                    false,
                    Some("invalid local credential"),
                )
                .await?;
                source_writer_guard::arm_commit_fence(&source_guard);
                tx.commit().await.map_err(|error| {
                    AstralError::Database(format!(
                        "Commit failed login evidence tx failed: {error}"
                    ))
                })?;
                source_writer_guard::settle_commit_fence(&source_guard, true);
            }
            return Err(AstralError::Auth("Invalid credentials".into()));
        };
        if current_hash != session.expected_password_hash
            || current_version != session.credential_version
            || current_version <= 0
        {
            if let Some(attempt_code) = session.mfa_attempt_code.as_deref() {
                crate::srv::mfa::resolve_mfa_attempt_in_tx(
                    &mut tx,
                    attempt_code,
                    session.user_id,
                    session.mfa_method.as_deref().unwrap_or("UNKNOWN"),
                    false,
                    Some("credential changed during login"),
                )
                .await?;
                source_writer_guard::arm_commit_fence(&source_guard);
                tx.commit().await.map_err(|error| {
                    AstralError::Database(format!(
                        "Commit failed login evidence tx failed: {error}"
                    ))
                })?;
                source_writer_guard::settle_commit_fence(&source_guard, true);
            }
            return Err(AstralError::Auth("Invalid credentials".into()));
        }

        // Recheck the identity/card/tenant pair while the credential row is locked,
        // so a stale password or changed identity context cannot mint a durable family.
        if let Some(user_card_id) = session.current_user_card_id {
            let eligible_card: Option<(i64,)> = sqlx::query_as(
                "SELECT uc.card_id FROM platform_user pu \
                 INNER JOIN identity_card ic ON ic.card_id = ? AND ic.user_id = pu.user_id \
                   AND ic.status = 'ACTIVE' AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
                 INNER JOIN user_card uc ON uc.card_id = ? AND uc.user_id = pu.user_id \
                   AND uc.card_status = 'ACTIVE' \
                   AND uc.card_type != 'LEVEL_TEMPLATE_CARD' \
                   AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
                   AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()) \
                 INNER JOIN tenant t ON t.tenant_id = uc.tenant_id AND t.status = 'ACTIVE' \
                 INNER JOIN tenant_domain_map tdm ON tdm.tenant_id = uc.tenant_id \
                   AND tdm.domain_id = uc.domain_id AND tdm.status = 'ACTIVE' \
                 WHERE pu.user_id = ? AND pu.status = 'ACTIVE' AND pu.deleted_at IS NULL \
                   AND uc.tenant_id > 0 AND uc.domain_id > 0 FOR UPDATE",
            )
            .bind(session.identity_card_id)
            .bind(user_card_id)
            .bind(session.user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| AstralError::Database(format!("Recheck login card pair failed: {e}")))?;
            if eligible_card.map(|(card_id,)| card_id) != Some(user_card_id) {
                return Err(AstralError::Auth("USER_CARD_SCOPE_REQUIRED".into()));
            }
        } else {
            // Login sessions are platform principals: a missing selected user card
            // never downgrades them into an identity-only AppUser session.
            return Err(AstralError::Auth("USER_CARD_SCOPE_REQUIRED".into()));
        }

        let factor = crate::srv::mfa::consume_login_factor_in_tx(
            &mut tx,
            session.user_id,
            session.mfa_method.as_deref(),
            session.mfa_code.as_deref(),
            false,
        )
        .await?;
        match factor {
            crate::srv::mfa::LoginFactorOutcome::Invalid
            | crate::srv::mfa::LoginFactorOutcome::Required => {
                let attempt_code = session.mfa_attempt_code.as_deref().ok_or_else(|| {
                    AstralError::Database("MFA attempt evidence reservation is required".into())
                })?;
                crate::srv::mfa::resolve_mfa_attempt_in_tx(
                    &mut tx,
                    attempt_code,
                    session.user_id,
                    session.mfa_method.as_deref().unwrap_or("UNKNOWN"),
                    false,
                    Some("invalid or missing login factor"),
                )
                .await?;
                source_writer_guard::arm_commit_fence(&source_guard);
                tx.commit().await.map_err(|e| {
                    AstralError::Database(format!("Commit failed login factor attempt: {e}"))
                })?;
                source_writer_guard::settle_commit_fence(&source_guard, true);
                drop(source_guard);
                return Err(AstralError::Auth("MFA_REQUIRED_OR_INVALID".into()));
            }
            crate::srv::mfa::LoginFactorOutcome::Consumed
            | crate::srv::mfa::LoginFactorOutcome::NotEnabled => {
                let attempt_code = session.mfa_attempt_code.as_deref().ok_or_else(|| {
                    AstralError::Database("MFA attempt evidence reservation is required".into())
                })?;
                crate::srv::mfa::resolve_mfa_attempt_in_tx(
                    &mut tx,
                    attempt_code,
                    session.user_id,
                    session.mfa_method.as_deref().unwrap_or("UNKNOWN"),
                    true,
                    None,
                )
                .await?;
            }
        }

        let version = if let Some(migrated_hash) = session.migrated_password_hash.as_deref() {
            let updated = sqlx::query(
                "UPDATE user_local_credential SET password_hash = ?, password_algo = 'ARGON2ID', \
                 credential_version = credential_version + 1, password_updated_at = CURRENT_TIMESTAMP, \
                 updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND status = 'ACTIVE' \
                   AND password_hash = ? AND credential_version = ?",
            )
            .bind(migrated_hash)
            .bind(session.user_id)
            .bind(&session.expected_password_hash)
            .bind(session.credential_version)
            .execute(&mut *tx)
            .await
            .map_err(|e| AstralError::Database(format!("Migrate login credential failed: {e}")))?;
            if updated.rows_affected() != 1 {
                return Err(AstralError::Auth("Invalid credentials".into()));
            }
            session
                .credential_version
                .checked_add(1)
                .ok_or_else(|| AstralError::Auth("Credential revision exhausted".into()))?
        } else {
            session.credential_version
        };

        sqlx::query(
            "INSERT INTO auth_token_family (user_id, family_key, status, issued_at, expires_at) \
             VALUES (?, ?, 'ACTIVE', UTC_TIMESTAMP(), ?)",
        )
        .bind(session.user_id)
        .bind(&session.family_key)
        .bind(session.refresh_expiry)
        .execute(&mut *tx)
        .await
        .map_err(|e| AstralError::Database(format!("Create login family failed: {e}")))?;
        let family_id: (i64,) = sqlx::query_as(
            "SELECT family_id FROM auth_token_family WHERE family_key = ? AND user_id = ?",
        )
        .bind(&session.family_key)
        .bind(session.user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AstralError::Database(format!("Read login family id failed: {e}")))?;

        let inserted = sqlx::query(
            "INSERT INTO auth_device_session \
             (family_id, user_id, device_id, device_type, client_app_id, channel_code, current_user_card_id, \
              credential_version, session_state, session_version, session_epoch, refresh_token_hash, refresh_expires_at, status) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 1, 1, ?, ?, 'ACTIVE')",
        )
        .bind(family_id.0)
        .bind(session.user_id)
        .bind(session.device_id)
        .bind(session.device_type)
        .bind(session.client_app_id)
        .bind(session.channel_code)
        .bind(session.current_user_card_id)
        .bind(version)
        .bind(session.refresh_hash)
        .bind(session.refresh_expiry)
        .execute(&mut *tx)
        .await
        .map_err(|e| AstralError::Database(format!("Save login session failed: {e}")))?;
        if inserted.rows_affected() != 1 || inserted.last_insert_id() == 0 {
            return Err(AstralError::Database(
                "Login session insert has no durable id".into(),
            ));
        }
        let session_id = inserted.last_insert_id() as i64;

        source_writer_guard::arm_commit_fence(&source_guard);
        tx.commit()
            .await
            .map_err(|e| AstralError::Database(format!("Commit login issuance tx failed: {e}")))?;
        source_writer_guard::settle_commit_fence(&source_guard, true);
        drop(source_guard);
        Ok((family_id.0, session_id))
    }

    async fn load_password_credential(
        &self,
        user_id: i64,
    ) -> Result<Option<PasswordCredential>, AstralError> {
        sqlx::query_as::<_, PasswordCredential>(
            "SELECT user_id, password_hash, status, credential_version \
             FROM user_local_credential \
             WHERE user_id = ? AND status = 'ACTIVE' LIMIT 1",
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AstralError::Database(format!("Load password credential failed: {e}")))
    }

    async fn update_password_hash(&self, user_id: i64, new_hash: &str) -> Result<(), AstralError> {
        self.update_password_hash_with_revocation(user_id, new_hash, "PASSWORD_CHANGED", None)
            .await
            .map(|_| ())
    }

    async fn update_password_hash_with_revocation(
        &self,
        user_id: i64,
        new_hash: &str,
        reason: &str,
        reset_token: Option<i64>,
    ) -> Result<Vec<String>, AstralError> {
        self.update_password_transaction(user_id, None, None, new_hash, reason, reset_token)
            .await
    }

    async fn update_password_hash_if_current(
        &self,
        user_id: i64,
        expected_hash: &str,
        expected_version: i64,
        new_hash: &str,
    ) -> Result<Vec<String>, AstralError> {
        self.update_password_transaction(
            user_id,
            Some(expected_hash),
            Some(expected_version),
            new_hash,
            "PASSWORD_CHANGED",
            None,
        )
        .await
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
        let source_guard = source_writer_guard::begin_source_write()?;
        let result = source_writer_guard::fenced_source_write(
            source_guard,
            sqlx::query(
                "INSERT INTO auth_device_session \
                 (family_id, user_id, device_id, device_type, client_app_id, channel_code, \
                  current_user_card_id, credential_version, session_state, session_version, session_epoch, \
                  refresh_token_hash, refresh_expires_at, status) \
                 SELECT ?, ?, ?, ?, ?, ?, ?, lc.credential_version, 'ACTIVE', 1, 1, ?, ?, 'ACTIVE' \
                 FROM user_local_credential lc JOIN platform_user pu ON pu.user_id = lc.user_id \
                   AND pu.status = 'ACTIVE' AND pu.deleted_at IS NULL \
                 WHERE lc.user_id = ? AND lc.status = 'ACTIVE' AND lc.credential_version > 0",
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
            .bind(session.user_id)
            .execute(&self.db),
        )
        .await
        .map_err(|e| AstralError::Database(format!("Save session failed: {e}")))?;
        if result.rows_affected() != 1 || result.last_insert_id() == 0 {
            return Err(AstralError::Auth(
                "Credential revision could not be proven for session issuance".into(),
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
        assert!(password_body.contains("self.update_password_hash_with_revocation("));
        assert!(password_body.contains("self.update_password_transaction("));
        let transaction_body = source
            .split("async fn update_password_transaction(")
            .nth(1)
            .unwrap()
            .split("/// Starter")
            .next()
            .unwrap();
        let guard = transaction_body
            .find("source_writer_guard::begin_source_write()?")
            .unwrap();
        let begin = transaction_body.find("self.db.begin()").unwrap();
        let arm = transaction_body
            .find("arm_commit_fence(&source_guard)")
            .unwrap();
        let commit = transaction_body.find("tx.commit()").unwrap();
        let settle = transaction_body
            .find("settle_commit_fence(&source_guard, true)")
            .unwrap();
        assert!(guard < begin && begin < arm && arm < commit && commit < settle);
        assert!(transaction_body.contains("update_password_transaction_in_tx("));
        let shared_password_body = source
            .split("pub(crate) async fn update_password_transaction_in_tx(")
            .nth(1)
            .expect("password mutation closure must be shared with raw helpers")
            .split("/// Starter")
            .next()
            .unwrap();
        for invariant in [
            "FOR UPDATE",
            "LIMIT 4097 FOR UPDATE",
            "jti_rows.len() > 4096",
            "credential_version = ?",
            "Password revocation JTI snapshot changed during transaction",
            "UPDATE auth_device_session",
            "UPDATE auth_token_family",
            "INSERT INTO auth_session_outbox",
        ] {
            assert!(
                shared_password_body.contains(invariant),
                "shared password closure must retain {invariant}"
            );
        }
        assert!(
            !shared_password_body.contains("tx.commit()")
                && !shared_password_body.contains("note_revocations_in_process"),
            "the shared helper must leave commit and post-commit work to its caller"
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
