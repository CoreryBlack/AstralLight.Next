//! Shared source, identity and audit repositories.
//!
//! The V6 authorization adapter has its own module and explicit exports. Source
//! management queries remain separate from formal published-evidence reads.

use sqlx::{MySql, MySqlPool, Transaction};
use time::{Duration, OffsetDateTime, PrimitiveDateTime};

mod authorization;
pub use authorization::{
    check_card_active_cached, check_card_active_cached_with_options, CardActiveContext,
    SqlxRuleRepository,
};

/// 数据库操作错误
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("Database query failed: {0}")]
    Query(#[from] sqlx::Error),

    #[error("Row mapping failed: {0}")]
    Mapping(String),
}

/// Predicate used by user-facing audit views. Internal scheduler lifecycle
/// evidence remains durable and queryable by its event type, but must not be
/// counted as a user request or authorization audit entry.
pub const USER_VISIBLE_AUDIT_PREDICATE: &str = "decision <> 'INTERNAL'";

fn user_visible_audit_from_clause() -> String {
    format!("FROM audit_log WHERE {USER_VISIBLE_AUDIT_PREDICATE}")
}

// ===== 模块级公共函数（非 trait 方法，供各业务模块直接调用） =====

/// Canonical token family row. `family_id` is the BIGINT storage PK and
/// `family_key` is the unique opaque key supplied by the caller.
#[derive(Debug, sqlx::FromRow)]
pub struct TokenFamilyRow {
    pub family_id: i64,
    pub user_id: i64,
    pub family_key: String,
    pub status: String,
    pub issued_at: time::PrimitiveDateTime,
    pub expires_at: Option<time::PrimitiveDateTime>,
    pub revoked_at: Option<time::PrimitiveDateTime>,
    pub revoked_reason: Option<String>,
    pub metadata_json: Option<String>,
}

/// 查询用户所有 ACTIVE 卡片 ID
pub async fn find_active_cards_by_user(
    pool: &MySqlPool,
    user_id: i64,
) -> Result<Vec<i64>, DbError> {
    let rows = sqlx::query_as::<_, (i64,)>(
        "SELECT card_id FROM user_card WHERE user_id = ? AND card_status = 'ACTIVE'          AND (valid_from IS NULL OR valid_from <= NOW())          AND (valid_until IS NULL OR valid_until >= NOW())"
    ).bind(user_id).fetch_all(pool).await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

/// 查询 token family（按 BIGINT family_id 主键查询）。
pub async fn find_token_family(
    pool: &MySqlPool,
    family_id: i64,
) -> Result<Option<TokenFamilyRow>, DbError> {
    Ok(sqlx::query_as::<_, TokenFamilyRow>(
        "SELECT family_id, user_id, family_key, status, issued_at, expires_at, revoked_at, revoked_reason, metadata_json \
         FROM auth_token_family WHERE family_id = ?",
    )
    .bind(family_id)
    .fetch_optional(pool)
    .await?)
}

/// 创建 token family；插入 family_key 并返回 BIGINT LAST_INSERT_ID。
pub async fn create_token_family(
    pool: &MySqlPool,
    family_key: &str,
    user_id: i64,
) -> Result<i64, DbError> {
    let now = OffsetDateTime::now_utc();
    let expires_at = PrimitiveDateTime::new(
        (now + Duration::days(30)).date(),
        (now + Duration::days(30)).time(),
    );
    let result = sqlx::query(
        "INSERT INTO auth_token_family \
         (user_id, family_key, status, issued_at, expires_at) \
         VALUES (?, ?, 'ACTIVE', UTC_TIMESTAMP(), ?)",
    )
    .bind(user_id)
    .bind(family_key)
    .bind(expires_at)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 || result.last_insert_id() == 0 {
        return Err(DbError::Mapping(
            "token family was not durably created".into(),
        ));
    }
    Ok(result.last_insert_id() as i64)
}

/// Insert a security-sensitive audit entry inside the caller's source transaction.
/// The transaction owner retains the commit fence and therefore controls whether
/// the mutation and its audit correlation become durable together.
pub async fn insert_audit_log_in_tx(
    tx: &mut Transaction<'_, MySql>,
    entry: &astral_common::audit::AuditEntry,
) -> Result<(), DbError> {
    let event_type_str = serde_json::to_value(&entry.event_type)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    sqlx::query(
        "INSERT INTO audit_log (user_id, card_id, action, resource, decision, reason, event_type, source_ip, request_id, domain_id, tenant_id, detail) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(entry.user_id)
    .bind(entry.card_id)
    .bind(&entry.action)
    .bind(&entry.resource)
    .bind(&entry.decision)
    .bind(&entry.reason)
    .bind(&event_type_str)
    .bind(&entry.source_ip)
    .bind(&entry.request_id)
    .bind(entry.domain_id)
    .bind(entry.tenant_id)
    .bind(&entry.detail)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
// 插入审计日志到 DB
pub async fn insert_audit_log(
    pool: &MySqlPool,
    entry: &astral_common::audit::AuditEntry,
) -> Result<(), DbError> {
    let event_type_str = serde_json::to_value(&entry.event_type)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default();

    sqlx::query(
        "INSERT INTO audit_log (user_id, card_id, action, resource, decision, reason, event_type, source_ip, request_id, domain_id, tenant_id, detail) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
        .bind(entry.user_id)
        .bind(entry.card_id)
        .bind(&entry.action)
        .bind(&entry.resource)
        .bind(&entry.decision)
        .bind(&entry.reason)
        .bind(&event_type_str)
        .bind(&entry.source_ip)
        .bind(&entry.request_id)
        .bind(entry.domain_id)
        .bind(entry.tenant_id)
        .bind(&entry.detail)
        .execute(pool)
        .await?;
    Ok(())
}

/// 权限决策审计（fire-and-forget，对齐 Java `AuditService.record(PolicyContext, PolicyDecision)`）
///
/// 各服务权限中间件在每个判定（ALLOW/DENY）后调用；DB 写入失败仅记 warning 不阻塞
/// 主请求（审计非关键路径，决策本身已 fail-closed）。
#[allow(clippy::too_many_arguments)]
pub async fn record_permission_audit(
    pool: &MySqlPool,
    user_id: Option<i64>,
    card_id: Option<i64>,
    domain_id: Option<i64>,
    resource: &str,
    action: &str,
    allowed: bool,
    reason: &str,
    path: &str,
) {
    let entry = astral_common::audit::AuditEntry {
        user_id,
        card_id,
        action: action.to_string(),
        resource: resource.to_string(),
        decision: if allowed {
            "ALLOW".into()
        } else {
            "DENY".into()
        },
        reason: Some(reason.to_string()),
        event_type: astral_common::audit::AuditEventType::PermissionCheck,
        category: Some(astral_common::audit::AuditCategory::Permission),
        source_ip: None,
        request_id: None,
        domain_id,
        tenant_id: None,
        detail: Some(path.to_string()),
    };
    if let Err(e) = insert_audit_log(pool, &entry).await {
        tracing::warn!(error = %e, "permission audit insert failed");
    }
}

/// ALLOW 命中统计落库（fire-and-forget，对齐 Java：ALLOW 命中异步写入 permission_hit_stat）。
/// `rule_source` 使用 canonical 来源值：RULE_SET / PERMISSION_RULE / DELEGATION / TEMPLATE；DB 不可用仅记 debug。
pub async fn record_permission_hit(
    pool: &MySqlPool,
    card_id: i64,
    resource_type: &str,
    action_code: &str,
    rule_source: Option<&str>,
) {
    if let Err(e) =
        upsert_permission_hit_stat(pool, card_id, resource_type, action_code, rule_source).await
    {
        tracing::debug!(card_id, resource = resource_type, action = action_code, error = %e, "hit stat upsert failed");
    }
}

/// 用户 MFA 配置行
#[derive(Debug, sqlx::FromRow)]
pub struct UserMfaRow {
    pub id: Option<i64>,
    pub user_id: i64,
    pub mfa_type: String,
    pub secret_enc: Option<Vec<u8>>,
    pub phone: Option<String>,
    pub email: Option<String>,
    pub is_enabled: i32,
    pub is_primary: i32,
    pub backup_codes_hash: Option<String>,
    pub backup_codes_used: i32,
    pub verified_at: Option<time::PrimitiveDateTime>,
    pub last_used_at: Option<time::PrimitiveDateTime>,
    pub last_totp_counter: Option<i64>,
}

/// 查询用户 MFA 配置
pub async fn find_user_mfa(
    pool: &MySqlPool,
    user_id: i64,
    mfa_type: &str,
) -> Result<Option<UserMfaRow>, DbError> {
    let row = sqlx::query_as::<_, UserMfaRow>(
        "SELECT id, user_id, mfa_type, secret_enc, phone, email, is_enabled, is_primary, \
         backup_codes_hash, backup_codes_used, verified_at, last_used_at, last_totp_counter \
         FROM user_mfa WHERE user_id = ? AND mfa_type = ?",
    )
    .bind(user_id)
    .bind(mfa_type)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// 查询用户所有已启用的 MFA 配置
pub async fn find_enabled_mfa_for_user(
    pool: &MySqlPool,
    user_id: i64,
) -> Result<Vec<UserMfaRow>, DbError> {
    let rows = sqlx::query_as::<_, UserMfaRow>(
        "SELECT id, user_id, mfa_type, secret_enc, phone, email, is_enabled, is_primary, \
         backup_codes_hash, backup_codes_used, verified_at, last_used_at, last_totp_counter \
         FROM user_mfa WHERE user_id = ? AND is_enabled = 1",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// 创建或更新用户 MFA 配置
pub async fn upsert_user_mfa(
    pool: &MySqlPool,
    user_id: i64,
    mfa_type: &str,
    secret_enc: Option<&[u8]>,
    backup_codes_hash: Option<&str>,
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO user_mfa (user_id, mfa_type, secret_enc, backup_codes_hash, is_enabled, is_primary) \
         VALUES (?, ?, ?, ?, 1, 1) \
         ON DUPLICATE KEY UPDATE secret_enc = VALUES(secret_enc), backup_codes_hash = VALUES(backup_codes_hash), \
         is_enabled = 1, backup_codes_used = 0, updated_at = CURRENT_TIMESTAMP"
    )
        .bind(user_id)
        .bind(mfa_type)
        .bind(secret_enc)
        .bind(backup_codes_hash)
        .execute(pool)
        .await?;
    Ok(())
}

/// Stage a factor disabled; possession must be proven through the authenticated
/// verification route before it becomes an MFA login requirement.
pub async fn stage_user_mfa(
    pool: &MySqlPool,
    user_id: i64,
    mfa_type: &str,
    secret_enc: Option<&[u8]>,
    backup_codes_hash: Option<&str>,
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO user_mfa (user_id, mfa_type, secret_enc, backup_codes_hash, is_enabled, is_primary, backup_codes_used, last_totp_counter) \
         VALUES (?, ?, ?, ?, 0, 0, 0, NULL) \
         ON DUPLICATE KEY UPDATE secret_enc = VALUES(secret_enc), \
         backup_codes_hash = VALUES(backup_codes_hash), is_enabled = 0, \
         backup_codes_used = 0, verified_at = NULL, last_totp_counter = NULL, \
         updated_at = CURRENT_TIMESTAMP",
    )
    .bind(user_id)
    .bind(mfa_type)
    .bind(secret_enc)
    .bind(backup_codes_hash)
    .execute(pool)
    .await?;
    Ok(())
}

/// Activate a staged TOTP factor only after its first, unused counter is proven.
pub async fn activate_pending_totp(
    pool: &MySqlPool,
    user_id: i64,
    counter: i64,
) -> Result<bool, DbError> {
    let result = sqlx::query(
        "UPDATE user_mfa SET is_enabled = 1, is_primary = 1, verified_at = CURRENT_TIMESTAMP, \
         last_totp_counter = ?, last_used_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP \
         WHERE user_id = ? AND mfa_type = 'TOTP' AND is_enabled = 0 \
           AND secret_enc IS NOT NULL AND (last_totp_counter IS NULL OR last_totp_counter < ?)",
    )
    .bind(counter)
    .bind(user_id)
    .bind(counter)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Disable user MFA
pub async fn disable_user_mfa(
    pool: &MySqlPool,
    user_id: i64,
    mfa_type: &str,
) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE user_mfa SET is_enabled = 0, secret_enc = NULL, backup_codes_hash = NULL, \
         updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND mfa_type = ?",
    )
    .bind(user_id)
    .bind(mfa_type)
    .execute(pool)
    .await?;
    Ok(())
}

/// 递增备份码使用计数并更新最后使用时间
pub async fn mark_mfa_used(pool: &MySqlPool, user_id: i64, mfa_type: &str) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE user_mfa SET backup_codes_used = backup_codes_used + 1, last_used_at = CURRENT_TIMESTAMP \
         WHERE user_id = ? AND mfa_type = ?"
    )
        .bind(user_id)
        .bind(mfa_type)
        .execute(pool)
        .await?;
    Ok(())
}

/// 插入 MFA 尝试日志
pub async fn insert_mfa_attempt(
    pool: &MySqlPool,
    user_id: i64,
    mfa_type: &str,
    success: bool,
    ip: Option<&str>,
    failure_reason: Option<&str>,
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO mfa_attempt_log (user_id, mfa_type, success, ip, failure_reason) VALUES (?, ?, ?, ?, ?)"
    )
        .bind(user_id)
        .bind(mfa_type)
        .bind(success as i32)
        .bind(ip)
        .bind(failure_reason)
        .execute(pool)
        .await?;
    Ok(())
}

/// 统计最近 N 分钟内的 MFA 失败次数
pub async fn count_recent_mfa_failures(
    pool: &MySqlPool,
    user_id: i64,
    window_minutes: i32,
) -> Result<i32, DbError> {
    let row: (i32,) = sqlx::query_as(
        "SELECT COUNT(*) FROM mfa_attempt_log \
         WHERE user_id = ? AND success = 0 AND status IN ('FAILED', 'PENDING') \
           AND attempted_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? MINUTE)",
    )
    .bind(user_id)
    .bind(window_minutes)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

// ===== I-4: 规则集/SoD/命中统计 Repository 函数（对齐 Java Mapper 层）=====
//
// Java 基线对照:
// - RuleSetMapper: AstralGeneral/.../mapper/RuleSetMapper.java
// - SodPolicyMapper: AstralGeneral/.../mapper/SodPolicyMapper.java
// - PermissionDelegationMapper: AstralGeneral/.../mapper/PermissionDelegationMapper.java

use astral_types::PermissionHitStat;

/// 记录权限命中统计（upsert）
/// Java 对照: PermissionHitStatMapper.upsert()
pub async fn upsert_permission_hit_stat(
    pool: &MySqlPool,
    card_id: i64,
    resource_type: &str,
    action_code: &str,
    rule_source: Option<&str>,
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO permission_hit_stat (card_id, resource_type, action_code, hit_count, last_hit_at, rule_source) \
         VALUES (?, ?, ?, 1, NOW(), ?) \
         ON DUPLICATE KEY UPDATE hit_count = hit_count + 1, last_hit_at = NOW(), rule_source = VALUES(rule_source)"
    )
        .bind(card_id)
        .bind(resource_type)
        .bind(action_code)
        .bind(rule_source)
        .execute(pool)
        .await?;
    Ok(())
}

/// 查询权限命中统计（Top N）
/// Java 对照: PermissionHitStatMapper.selectTop()
pub async fn find_top_permission_hit_stats(
    pool: &MySqlPool,
    limit: i32,
) -> Result<Vec<PermissionHitStat>, DbError> {
    let rows = sqlx::query_as::<_, PermissionHitStatRow>(
        "SELECT card_id, resource_type, action_code, \
         CAST(hit_count AS SIGNED) as hit_count, \
         UNIX_TIMESTAMP(last_hit_at) as last_hit_at, rule_source \
         FROM permission_hit_stat ORDER BY hit_count DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| PermissionHitStat {
            id: None,
            card_id: r.card_id,
            resource_type: r.resource_type,
            action_code: r.action_code,
            hit_count: r.hit_count,
            last_hit_at: r.last_hit_at,
            rule_source: r.rule_source,
        })
        .collect())
}

// ===== 内部行类型（I-4 补充）=====

#[derive(Debug, sqlx::FromRow)]
struct PermissionHitStatRow {
    card_id: i64,
    resource_type: String,
    action_code: String,
    hit_count: i64,
    last_hit_at: Option<i64>,
    rule_source: Option<String>,
}

/// 密码重置令牌行
#[derive(Debug, sqlx::FromRow)]
pub struct PasswordResetTokenRow {
    pub id: i64,
    pub user_id: i64,
    pub card_number: String,
    /// 稳定调用方 operation id（与 `al_delivery_intent.operation_id` 关联；
    /// 旧行/未绑定为 NULL → 不可消费）。
    pub operation_id: Option<String>,
    /// 本凭证外发所用的稳定 delivery intent 身份
    /// （`al_delivery_intent.message_id`；旧行/未绑定为 NULL → 不可消费）。
    pub delivery_message_id: Option<String>,
    pub token: String,
    pub expires_at: time::PrimitiveDateTime,
    pub used_at: Option<time::PrimitiveDateTime>,
    pub created_at: Option<time::PrimitiveDateTime>,
}

/// 插入密码重置令牌（taskId `authority-v7-peripheral-20261107`：同时绑定
/// 稳定 operation id 与 delivery intent message id；凭证出生即
/// PENDING-by-construction，只有 durable DELIVERED 证据可使其可消费）。
/// `executor` 接受连接池或调用方事务（签发 + 审计关联同事务由调用方组合）。
pub async fn insert_password_reset_token<'e, E>(
    executor: E,
    user_id: i64,
    card_number: &str,
    token_hash: &str,
    operation_id: &str,
    delivery_message_id: &str,
    expires_at: &time::PrimitiveDateTime,
) -> Result<(), DbError>
where
    E: sqlx::Executor<'e, Database = MySql>,
{
    sqlx::query(
        "INSERT INTO password_reset_token \
         (user_id, card_number, token, operation_id, delivery_message_id, expires_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(card_number)
    .bind(token_hash)
    .bind(operation_id)
    .bind(delivery_message_id)
    .bind(expires_at)
    .execute(executor)
    .await?;
    Ok(())
}

/// 作废指定密码重置令牌（按用户 + SHA-256 哈希 CAS）。
///
/// `used_at IS NULL` 使清理幂等：更新 0 行表示令牌不存在或已经不可用，
/// 两种结果都不能留下一个仍可消费的令牌。调用方不得把原始令牌传入日志、
/// durable payload 或响应。
pub async fn invalidate_password_reset_token(
    pool: &MySqlPool,
    user_id: i64,
    token_hash: &str,
) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE password_reset_token SET used_at = UTC_TIMESTAMP() \
         WHERE user_id = ? AND token = ? AND used_at IS NULL",
    )
    .bind(user_id)
    .bind(token_hash)
    .execute(pool)
    .await?;
    Ok(())
}

/// 查找未使用的密码重置令牌（按 token hash）。可消费性不由此查询决定：
/// 消费必须经 join `al_delivery_intent.state='DELIVERED'` 的同事务门。
pub async fn find_valid_password_reset_token(
    pool: &MySqlPool,
    token_hash: &str,
) -> Result<Option<PasswordResetTokenRow>, DbError> {
    let row = sqlx::query_as::<_, PasswordResetTokenRow>(
        "SELECT id, user_id, card_number, operation_id, delivery_message_id, token, expires_at, used_at, created_at \
         FROM password_reset_token \
         WHERE token = ? AND used_at IS NULL AND expires_at > NOW() \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// 原子消费密码重置令牌。返回 1 表示本次消费成功，0 表示令牌已被其他请求
/// 消费、投递证据未达 durable DELIVERED，或 operation/message 绑定缺失或
/// 不匹配。
pub async fn mark_password_reset_token_used(pool: &MySqlPool, id: i64) -> Result<bool, DbError> {
    let result = sqlx::query(
        "UPDATE password_reset_token prt \
         JOIN al_delivery_intent adi ON adi.message_id = prt.delivery_message_id \
         SET prt.used_at = NOW() \
         WHERE prt.id = ? AND prt.used_at IS NULL AND prt.expires_at > NOW() \
           AND adi.state = 'DELIVERED' \
           AND CAST(adi.message_id AS BINARY) = CAST(prt.delivery_message_id AS BINARY) \
           AND CAST(adi.operation_id AS BINARY) = CAST(prt.operation_id AS BINARY)",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// 事务内原子消费密码重置令牌（与密码哈希更新同一事务）。
///
/// 双绑定消费门：`delivery_message_id` 与 `operation_id` 都必须与 intent 行
/// **二进制精确相等**（两侧列 collation 不同：utf8mb4_unicode_ci vs
/// ascii_bin——自然等值会被 coerc 到 unicode_ci 产生大小写/尾空格等价，故
/// ON 用自然等值保住 `uq_delivery_intent_message` 索引探活，WHERE 以
/// `CAST(... AS BINARY)` 强制字节级精确），state 必须为 durable
/// `DELIVERED`。任一绑定缺失（旧行 NULL；CAST(NULL)=NULL，谓词不真）或
/// 不匹配 → 0 行 → 拒绝消费，fail-closed。`used_at IS NULL` 即 replay
/// 边界：并发请求中仅一个能成功消费。
pub async fn mark_password_reset_token_used_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    id: i64,
) -> Result<bool, DbError> {
    let result = sqlx::query(
        "UPDATE password_reset_token prt \
         JOIN al_delivery_intent adi ON adi.message_id = prt.delivery_message_id \
         SET prt.used_at = NOW() \
         WHERE prt.id = ? AND prt.used_at IS NULL AND prt.expires_at > NOW() \
           AND adi.state = 'DELIVERED' \
           AND CAST(adi.message_id AS BINARY) = CAST(prt.delivery_message_id AS BINARY) \
           AND CAST(adi.operation_id AS BINARY) = CAST(prt.operation_id AS BINARY)",
    )
    .bind(id)
    .execute(&mut **tx)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// 作废用户所有未使用的重置令牌
pub async fn invalidate_user_password_reset_tokens(
    pool: &MySqlPool,
    user_id: i64,
) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE password_reset_token SET used_at = NOW() WHERE user_id = ? AND used_at IS NULL",
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

// ===== Phase 2a: Identity — 验证码 =====
//
// TTL/GC ownership（所有权边界）：
// - 行 TTL 由调用方（astral-identity）计算 `expires_at` 时拥有；本模块只存储
//   与按 TTL 过滤，不自造有效期。
// - Supersession：同一 (target, purpose) 至多存在一个未消费验证码；签发在新
//   短事务内先删除同 key 未消费行再插入，禁止旧码与新码并行有效。
// - GC：已消费/已过期死行由两条有界路径清理——签发时的同 key 删除，以及
//   `cleanup_expired_verification_codes` 的有界扫描（索引 idx_vc_expires）。
//   本模块不启动后台 worker；GC 由调用方在签发路径上机会式触发且不阻塞签发。

/// 验证码行
#[derive(Debug, sqlx::FromRow)]
pub struct VerificationCodeRow {
    pub id: i64,
    pub target: String,
    pub purpose: String,
    pub code: String,
    pub expires_at: time::PrimitiveDateTime,
    pub verified_at: Option<time::PrimitiveDateTime>,
    pub created_at: Option<time::PrimitiveDateTime>,
}

/// 签发验证码：在同一短事务内先作废同 (target, purpose) 的全部未消费旧码，
/// 再插入新码。返回新码的 durable 行 id，作为 send/verify 之间稳定的
/// operation/audit correlation id（验证码明文不入日志）。
///
/// 调用方拥有 TTL（`expires_at`）；本函数只保证"同 key 至多一个活跃码"。
/// 并发校验在签发事务提交前后要么看到旧码（随后 CAS 因行被删而失败，fail-closed），
/// 要么看到新码，不存在双活窗口。
pub async fn issue_verification_code(
    pool: &MySqlPool,
    target: &str,
    purpose: &str,
    code: &str,
    expires_at: &time::PrimitiveDateTime,
) -> Result<i64, DbError> {
    let mut tx = pool.begin().await?;
    // Supersede：未消费旧码（含已过期未清理的）从此不可再被校验；
    // `verified_at IS NULL` 保持"活跃码"语义不与"已消费"混淆。
    sqlx::query(
        "DELETE FROM verification_code \
         WHERE target = ? AND purpose = ? AND verified_at IS NULL",
    )
    .bind(target)
    .bind(purpose)
    .execute(&mut *tx)
    .await?;
    let result = sqlx::query(
        "INSERT INTO verification_code (target, purpose, code, expires_at) VALUES (?, ?, ?, ?)",
    )
    .bind(target)
    .bind(purpose)
    .bind(code)
    .bind(expires_at)
    .execute(&mut *tx)
    .await?;
    if result.rows_affected() != 1 || result.last_insert_id() == 0 {
        tx.rollback().await?;
        return Err(DbError::Mapping(
            "verification code was not durably issued".into(),
        ));
    }
    let code_id = result.last_insert_id() as i64;
    tx.commit().await?;
    Ok(code_id)
}

/// 有界机会式 GC：删除过期时间早于 `retention` 之前（已过期，无论是否消费）
/// 的死行，单次最多 `limit` 行。走 idx_vc_expires 索引，扫描量有界；
/// GC 失败只影响存储膨胀，不影响验证码正确性，调用方应记录失败但不阻塞签发。
pub async fn cleanup_expired_verification_codes(
    pool: &MySqlPool,
    retention: Duration,
    limit: u64,
) -> Result<u64, DbError> {
    let cutoff = OffsetDateTime::now_utc() - retention;
    let cutoff_prim = PrimitiveDateTime::new(cutoff.date(), cutoff.time());
    let result = sqlx::query("DELETE FROM verification_code WHERE expires_at < ? LIMIT ?")
        .bind(cutoff_prim)
        .bind(limit)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// 查找指定 target + purpose 未使用、未过期的验证码（按创建时间倒序取最新）。
/// 签发侧 supersede 保证同 key 至多一个活跃码；本查询只做候选选择，
/// 消费必须经 `mark_verification_code_verified` 的 CAS。
pub async fn find_valid_verification_code(
    pool: &MySqlPool,
    target: &str,
    purpose: &str,
) -> Result<Option<VerificationCodeRow>, DbError> {
    let row = sqlx::query_as::<_, VerificationCodeRow>(
        "SELECT id, target, purpose, code, expires_at, verified_at, created_at \
         FROM verification_code \
         WHERE target = ? AND purpose = ? AND verified_at IS NULL AND expires_at > NOW() \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(target)
    .bind(purpose)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// 一次性消费验证码（one-shot CAS/replay 边界）：仅当 `verified_at` 仍为 NULL、
/// 未过期且 id + target + purpose + code 完全匹配时置 `verified_at`；
/// 并发校验中只有一个成功，其余得到 false（调用方必须 fail-closed 拒绝）。
pub async fn mark_verification_code_verified(
    pool: &MySqlPool,
    id: i64,
    target: &str,
    purpose: &str,
    code: &str,
) -> Result<bool, DbError> {
    let result = sqlx::query(
        "UPDATE verification_code SET verified_at = NOW() \
         WHERE id = ? AND target = ? AND purpose = ? AND code = ? \
           AND verified_at IS NULL AND expires_at > NOW()",
    )
    .bind(id)
    .bind(target)
    .bind(purpose)
    .bind(code)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Consume a verified MFA recovery code from the locked method row.
/// Hash array parsing and exact member removal happen inside the same short transaction.
pub async fn consume_mfa_recovery_code(
    pool: &MySqlPool,
    user_id: i64,
    code_hash: &str,
) -> Result<bool, DbError> {
    let mut tx = pool.begin().await?;
    let row: Option<(String, i32)> = sqlx::query_as(
        "SELECT backup_codes_hash, backup_codes_used FROM user_mfa \
         WHERE user_id = ? AND mfa_type = 'RECOVERY_CODES' AND is_enabled = 1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((serialized, used)) = row else {
        tx.rollback().await?;
        return Ok(false);
    };
    if used < 0 || used as usize >= 10 {
        tx.rollback().await?;
        return Ok(false);
    }
    let mut hashes: Vec<String> = serde_json::from_str(&serialized)
        .map_err(|error| DbError::Mapping(format!("MFA recovery hash list is invalid: {error}")))?;
    let Some(index) = hashes.iter().position(|hash| hash == code_hash) else {
        tx.rollback().await?;
        return Ok(false);
    };
    hashes.remove(index);
    let updated = sqlx::query(
        "UPDATE user_mfa SET backup_codes_hash = ?, backup_codes_used = backup_codes_used + 1, \
         last_used_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP \
         WHERE user_id = ? AND mfa_type = 'RECOVERY_CODES' AND is_enabled = 1 \
           AND backup_codes_used = ? AND backup_codes_hash = ?",
    )
    .bind(serde_json::to_string(&hashes).map_err(|error| {
        DbError::Mapping(format!("Serialize MFA recovery hashes failed: {error}"))
    })?)
    .bind(user_id)
    .bind(used)
    .bind(&serialized)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        tx.rollback().await?;
        return Ok(false);
    }
    tx.commit().await?;
    Ok(true)
}

/// Confirm a staged recovery factor by consuming the presented code in the same transaction that enables it.
pub async fn activate_pending_recovery_code(
    pool: &MySqlPool,
    user_id: i64,
    code_hash: &str,
) -> Result<bool, DbError> {
    let mut tx = pool.begin().await?;
    let row: Option<(String, i32)> = sqlx::query_as(
        "SELECT backup_codes_hash, backup_codes_used FROM user_mfa \
         WHERE user_id = ? AND mfa_type = 'RECOVERY_CODES' AND is_enabled = 0 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((serialized, used)) = row else {
        tx.rollback().await?;
        return Ok(false);
    };
    let mut hashes: Vec<String> = serde_json::from_str(&serialized)
        .map_err(|error| DbError::Mapping(format!("MFA recovery hash list is invalid: {error}")))?;
    let Some(index) = hashes.iter().position(|hash| hash == code_hash) else {
        tx.rollback().await?;
        return Ok(false);
    };
    hashes.remove(index);
    let changed = sqlx::query(
        "UPDATE user_mfa SET backup_codes_hash = ?, backup_codes_used = ?, is_enabled = 1, \
         is_primary = 1, verified_at = CURRENT_TIMESTAMP, last_used_at = CURRENT_TIMESTAMP, \
         updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND mfa_type = 'RECOVERY_CODES' \
           AND is_enabled = 0 AND backup_codes_used = ? AND backup_codes_hash = ?",
    )
    .bind(serde_json::to_string(&hashes).map_err(|error| DbError::Mapping(error.to_string()))?)
    .bind(used + 1)
    .bind(user_id)
    .bind(used)
    .bind(&serialized)
    .execute(&mut *tx)
    .await?;
    if changed.rows_affected() != 1 {
        tx.rollback().await?;
        return Ok(false);
    }
    tx.commit().await?;
    Ok(true)
}

/// Atomically record a TOTP step as consumed. Concurrent requests using the same
/// time-step cannot both mint a grant or verify a code.
pub async fn consume_mfa_totp_counter(
    pool: &MySqlPool,
    user_id: i64,
    counter: i64,
) -> Result<bool, DbError> {
    let result = sqlx::query(
        "UPDATE user_mfa SET last_totp_counter = ?, last_used_at = CURRENT_TIMESTAMP, \
         updated_at = CURRENT_TIMESTAMP \
         WHERE user_id = ? AND mfa_type = 'TOTP' AND is_enabled = 1 \
           AND (last_totp_counter IS NULL OR last_totp_counter < ?)",
    )
    .bind(counter)
    .bind(user_id)
    .bind(counter)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Durable attempt reservation. PENDING rows count as failures until resolved;
/// abandoning a request can never reopen the brute-force budget.
pub async fn reserve_mfa_attempt(
    pool: &MySqlPool,
    user_id: i64,
    attempt_code: &str,
    mfa_type: &str,
    ip: Option<&str>,
    user_agent: Option<&str>,
) -> Result<(), DbError> {
    let mut tx = pool.begin().await?;
    // Serialize attempts on the account credential row so concurrent nodes cannot
    // all observe spare budget and reserve more than the configured maximum.
    let credential: Option<(i64,)> = sqlx::query_as(
        "SELECT credential_id FROM user_local_credential WHERE user_id = ? AND status = 'ACTIVE' FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    if credential.is_none() {
        tx.rollback().await?;
        return Err(DbError::Mapping(
            "MFA attempt actor has no active local credential".into(),
        ));
    }
    let failures: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM mfa_attempt_log WHERE user_id = ? AND success = 0 \
         AND status IN ('FAILED', 'PENDING') AND attempted_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 15 MINUTE)",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    if failures.0 >= 5 {
        tx.rollback().await?;
        return Err(DbError::Mapping("MFA attempt limit exceeded".into()));
    }
    sqlx::query(
        "INSERT INTO mfa_attempt_log \
         (user_id, mfa_type, attempt_code, status, success, ip, user_agent, failure_reason) \
         VALUES (?, ?, ?, 'PENDING', 0, ?, ?, 'verification in progress')",
    )
    .bind(user_id)
    .bind(mfa_type)
    .bind(attempt_code)
    .bind(ip)
    .bind(user_agent)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Resolve an attempt reservation. DB failure is returned to the caller (fail-closed).
pub async fn resolve_mfa_attempt(
    pool: &MySqlPool,
    attempt_code: &str,
    success: bool,
    failure_reason: Option<&str>,
) -> Result<(), DbError> {
    let result = sqlx::query(
        "UPDATE mfa_attempt_log SET success = ?, status = ?, failure_reason = ?, \
         attempted_at = CURRENT_TIMESTAMP \
         WHERE attempt_code = ? AND status = 'PENDING' AND success = 0",
    )
    .bind(success as i32)
    .bind(if success { "SUCCEEDED" } else { "FAILED" })
    .bind(failure_reason)
    .bind(attempt_code)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        return Err(DbError::Mapping(
            "MFA attempt reservation could not be resolved exactly once".into(),
        ));
    }
    Ok(())
}

/// Resolve a management verification attempt only for the reserved actor and factor method.
pub async fn resolve_mfa_attempt_for_actor(
    pool: &MySqlPool,
    attempt_code: &str,
    user_id: i64,
    mfa_type: &str,
    success: bool,
    failure_reason: Option<&str>,
) -> Result<(), DbError> {
    let result = sqlx::query(
        "UPDATE mfa_attempt_log SET success = ?, status = ?, failure_reason = ?, \
         attempted_at = CURRENT_TIMESTAMP \
         WHERE attempt_code = ? AND user_id = ? AND mfa_type = ? \
           AND status = 'PENDING' AND success = 0",
    )
    .bind(success as i32)
    .bind(if success { "SUCCEEDED" } else { "FAILED" })
    .bind(failure_reason)
    .bind(attempt_code)
    .bind(user_id)
    .bind(mfa_type)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        return Err(DbError::Mapping(
            "MFA attempt actor/method reservation was not pending".into(),
        ));
    }
    Ok(())
}

// ===== Phase 2a: Identity — 管理员统计 =====

/// 系统统计结果
#[derive(Debug, Clone)]
pub struct SystemStatsResult {
    pub total_users: i64,
    pub total_cards: i64,
    pub active_sessions: i64,
    pub requests_today: i64,
}

/// 查询系统统计
pub async fn query_system_stats(pool: &MySqlPool) -> Result<SystemStatsResult, DbError> {
    // 真实表结构：identity_card 无 deleted_at 列；platform_user 才有 deleted_at
    // total_users 统计平台用户数（未删除）
    let total_users: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM platform_user WHERE deleted_at IS NULL")
            .fetch_one(pool)
            .await?;

    // total_cards 统计活跃用户卡（真实列名 card_status）
    let total_cards: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM user_card WHERE card_status = 'ACTIVE'")
            .fetch_one(pool)
            .await?;

    let active_sessions: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM auth_device_session WHERE status = 'ACTIVE'")
            .fetch_one(pool)
            .await?;

    let requests_today_sql = format!(
        "SELECT COUNT(*) {} AND created_at >= CURDATE()",
        user_visible_audit_from_clause()
    );
    let requests_today: (i64,) = sqlx::query_as(&requests_today_sql).fetch_one(pool).await?;

    Ok(SystemStatsResult {
        total_users: total_users.0,
        total_cards: total_cards.0,
        active_sessions: active_sessions.0,
        requests_today: requests_today.0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_visible_audit_queries_exclude_internal_scheduler_rows() {
        assert_eq!(USER_VISIBLE_AUDIT_PREDICATE, "decision <> 'INTERNAL'");
        let from_clause = user_visible_audit_from_clause();
        assert_eq!(from_clause, "FROM audit_log WHERE decision <> 'INTERNAL'");
        let requests_today_sql = format!(
            "SELECT COUNT(*) {} AND created_at >= CURDATE()",
            user_visible_audit_from_clause()
        );
        assert!(requests_today_sql.contains("decision <> 'INTERNAL'"));
        assert!(requests_today_sql.contains("created_at >= CURDATE()"));

        let source = include_str!("repository.rs");
        for function_name in [
            "pub async fn query_system_stats",
            "pub async fn query_audit_logs",
            "pub async fn count_audit_logs",
        ] {
            let body = source
                .split(function_name)
                .nth(1)
                .expect("user-visible audit reader must exist");
            assert!(
                body.contains("user_visible_audit_from_clause()"),
                "{function_name} must exclude INTERNAL audit rows"
            );
        }
    }

    /// 密码重置消费门契约（source-shape，taskId
    /// `authority-v7-peripheral-20261107`）：两个消费 helper 的 UPDATE 必须
    /// 同时对 message_id 与 operation_id 双绑定做**二进制精确**比对
    /// （CAST AS BINARY——两侧列 collation 不同，自然等值会被 coerc 到
    /// unicode_ci 产生大小写/尾空格等价）并要求 durable `DELIVERED`——缺一
    /// 即为可被 NULL 绑定/错绑定绕过的消费门。（作废 helper 的无门 used_at
    /// 直写是刻意的 housekeeping，不在本契约内。）
    #[test]
    fn password_reset_consumption_gate_binds_both_columns() {
        let source = include_str!("repository.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert_eq!(
            production.matches("JOIN al_delivery_intent adi").count(),
            2,
            "both pool and tx consume helpers must gate via the join"
        );
        for anchor in [
            "CAST(adi.message_id AS BINARY) = CAST(prt.delivery_message_id AS BINARY)",
            "CAST(adi.operation_id AS BINARY) = CAST(prt.operation_id AS BINARY)",
            "adi.state = 'DELIVERED'",
            "prt.used_at IS NULL",
        ] {
            assert_eq!(
                production.matches(anchor).count(),
                2,
                "both consume helpers must carry {anchor}"
            );
        }
    }

    /// 消费门负例/正例（显式 ignored integration；AGENTS §10.0：无真实 DB
    /// 只登记，不折算 PASS）。需要 ASTRAL_PASSWORD_RESET_TEST_MYSQL_URL 且已
    /// 应用 migration 20261107000008。覆盖：operation NULL 拒绝、operation
    /// 错绑定拒绝、message 错绑定拒绝、QUEUED/ACCEPTED 拒绝、DELIVERED 消费
    /// 一次成功 + 重放拒绝。
    #[tokio::test]
    #[ignore = "requires ASTRAL_PASSWORD_RESET_TEST_MYSQL_URL with migration 20261107000008 applied"]
    async fn password_reset_delivery_binding_gate_negatives_and_positives() {
        let Some(url) = std::env::var("ASTRAL_PASSWORD_RESET_TEST_MYSQL_URL")
            .ok()
            .map(|url| url.trim().to_owned())
            .filter(|url| !url.is_empty())
        else {
            eprintln!("[SKIP] ASTRAL_PASSWORD_RESET_TEST_MYSQL_URL not set");
            return;
        };
        let pool = MySqlPool::connect(&url).await.expect("connect test mysql");

        async fn insert_intent(
            pool: &MySqlPool,
            message_id: &str,
            operation_id: &str,
            state: &str,
        ) -> i64 {
            sqlx::query(
                "INSERT INTO al_delivery_intent \
                 (message_id, operation_id, channel_kind, recipient, payload_class, state) \
                 VALUES (?, ?, 'EMAIL', 'gate-test@example.com', 'EPHEMERAL_SECRET', ?)",
            )
            .bind(message_id)
            .bind(operation_id)
            .bind(state)
            .execute(pool)
            .await
            .expect("insert intent fixture")
            .last_insert_id() as i64
        }

        async fn insert_token(
            pool: &MySqlPool,
            token_hash: &str,
            operation_id: Option<&str>,
            delivery_message_id: Option<&str>,
        ) -> i64 {
            sqlx::query(
                "INSERT INTO password_reset_token \
                 (user_id, card_number, token, operation_id, delivery_message_id, expires_at) \
                 VALUES (42, 'gate-test', ?, ?, ?, DATE_ADD(NOW(), INTERVAL 30 MINUTE))",
            )
            .bind(token_hash)
            .bind(operation_id)
            .bind(delivery_message_id)
            .execute(pool)
            .await
            .expect("insert token fixture")
            .last_insert_id() as i64
        }

        async fn cleanup(pool: &MySqlPool, token_id: i64, intent_id: i64) {
            let _ = sqlx::query("DELETE FROM password_reset_token WHERE id = ?")
                .bind(token_id)
                .execute(pool)
                .await;
            let _ = sqlx::query("DELETE FROM al_delivery_intent WHERE id = ?")
                .bind(intent_id)
                .execute(pool)
                .await;
        }

        let run = uuid::Uuid::now_v7().simple().to_string();

        // 负例 1：operation 绑定 NULL（部分绑定旧行形态）→ 拒绝。
        let intent = insert_intent(
            &pool,
            &format!("msg-null-{run}"),
            &format!("op-null-{run}"),
            "DELIVERED",
        )
        .await;
        let token = insert_token(
            &pool,
            &format!("tok-null-{run}"),
            None,
            Some(&format!("msg-null-{run}")),
        )
        .await;
        assert!(
            !mark_password_reset_token_used(&pool, token).await.unwrap(),
            "NULL operation binding must be refused"
        );
        cleanup(&pool, token, intent).await;

        // 负例 2：operation 错绑定（message 匹配但 operation 不一致）→ 拒绝。
        let intent = insert_intent(
            &pool,
            &format!("msg-x-{run}"),
            &format!("op-real-{run}"),
            "DELIVERED",
        )
        .await;
        let token = insert_token(
            &pool,
            &format!("tok-x-{run}"),
            Some(&format!("op-wrong-{run}")),
            Some(&format!("msg-x-{run}")),
        )
        .await;
        assert!(
            !mark_password_reset_token_used(&pool, token).await.unwrap(),
            "mismatched operation binding must be refused"
        );
        cleanup(&pool, token, intent).await;

        // 负例 3：message 错绑定（operation 匹配但 message 指向其他 intent）→ 拒绝。
        let intent = insert_intent(
            &pool,
            &format!("msg-m-{run}"),
            &format!("op-m-{run}"),
            "DELIVERED",
        )
        .await;
        let token = insert_token(
            &pool,
            &format!("tok-m-{run}"),
            Some(&format!("op-m-{run}")),
            Some(&format!("msg-other-{run}")),
        )
        .await;
        assert!(
            !mark_password_reset_token_used(&pool, token).await.unwrap(),
            "mismatched message binding must be refused"
        );
        cleanup(&pool, token, intent).await;

        // 负例 4：投递未证明（QUEUED / ACCEPTED）→ 拒绝。
        for state in ["QUEUED", "ACCEPTED"] {
            let intent = insert_intent(
                &pool,
                &format!("msg-{state}-{run}"),
                &format!("op-{state}-{run}"),
                state,
            )
            .await;
            let token = insert_token(
                &pool,
                &format!("tok-{state}-{run}"),
                Some(&format!("op-{state}-{run}")),
                Some(&format!("msg-{state}-{run}")),
            )
            .await;
            assert!(
                !mark_password_reset_token_used(&pool, token).await.unwrap(),
                "state {state} must not satisfy the delivery gate"
            );
            cleanup(&pool, token, intent).await;
        }

        // 负例 5：collation 等价必须被拒绝（intent 列 utf8mb4_unicode_ci 对
        // ascii 内容本会大小写不敏感匹配；CAST AS BINARY 门要求字节级精确）。
        let intent = insert_intent(
            &pool,
            &format!("msg-case-{run}"),
            &format!("op-case-{run}"),
            "DELIVERED",
        )
        .await;
        let token = insert_token(
            &pool,
            &format!("tok-case-{run}"),
            Some(&format!("OP-CASE-{run}")),
            Some(&format!("MSG-CASE-{run}")),
        )
        .await;
        assert!(
            !mark_password_reset_token_used(&pool, token).await.unwrap(),
            "case-variant bindings must not satisfy the binary gate"
        );
        cleanup(&pool, token, intent).await;

        // 正例：完整绑定 + DELIVERED → 消费一次成功；重放（CAS）拒绝。
        let intent = insert_intent(
            &pool,
            &format!("msg-ok-{run}"),
            &format!("op-ok-{run}"),
            "DELIVERED",
        )
        .await;
        let token = insert_token(
            &pool,
            &format!("tok-ok-{run}"),
            Some(&format!("op-ok-{run}")),
            Some(&format!("msg-ok-{run}")),
        )
        .await;
        assert!(
            mark_password_reset_token_used(&pool, token).await.unwrap(),
            "fully bound DELIVERED credential must be consumable"
        );
        assert!(
            !mark_password_reset_token_used(&pool, token).await.unwrap(),
            "consumed credential must not be consumable twice (CAS)"
        );
        cleanup(&pool, token, intent).await;

        pool.close().await;
    }

    /// 验证码仓储契约（source-shape）：签发必须先 supersede 同 key 未消费旧码，
    /// GC 必须有界，消费必须保持 one-shot CAS。行为验证需要真实 MySQL
    /// integration（本测试只锁 SQL 形状与失败安全语义）。
    #[test]
    fn verification_code_repository_contract() {
        let source = include_str!("repository.rs");

        // 旧的无 supersede 直插入口必须退役，唯一调用方已迁移到签发事务。
        // 检索锚点动态拼接，避免 include_str! 自引用假阳性。
        let legacy_insert = concat!("pub async fn ", "insert_", "verification_code");
        assert!(
            !source.contains(legacy_insert),
            "legacy direct insert entry point must not be reintroduced; use issue_verification_code"
        );

        let issue_body = source
            .split("pub async fn issue_verification_code")
            .nth(1)
            .and_then(|rest| rest.split("pub async fn ").next())
            .expect("issue_verification_code must exist");
        assert!(
            issue_body.contains("pool.begin()"),
            "issuance must run supersede + insert in one short transaction"
        );
        assert!(
            issue_body.contains("verified_at IS NULL"),
            "supersede must only delete unconsumed prior codes (consumed rows are GC-owned)"
        );
        assert!(
            issue_body.contains("DELETE FROM verification_code"),
            "issuance must supersede prior active codes for the same key"
        );
        assert!(
            issue_body.contains("rows_affected() != 1 || result.last_insert_id() == 0"),
            "issuance must prove durable insert before returning the correlation id"
        );

        let gc_body = source
            .split("pub async fn cleanup_expired_verification_codes")
            .nth(1)
            .and_then(|rest| rest.split("pub async fn ").next())
            .expect("cleanup_expired_verification_codes must exist");
        assert!(
            gc_body.contains("LIMIT ?"),
            "GC must be bounded per call, not an unbounded sweep"
        );

        let find_body = source
            .split("pub async fn find_valid_verification_code")
            .nth(1)
            .and_then(|rest| rest.split("pub async fn ").next())
            .expect("find_valid_verification_code must exist");
        assert!(
            find_body.contains("verified_at IS NULL AND expires_at > NOW()"),
            "candidate selection must respect TTL and consumption state"
        );

        let mark_body = source
            .split("pub async fn mark_verification_code_verified")
            .nth(1)
            .and_then(|rest| rest.split("pub async fn ").next())
            .expect("mark_verification_code_verified must exist");
        assert!(
            mark_body.contains("verified_at IS NULL AND expires_at > NOW()"),
            "one-shot CAS must keep the replay boundary (unconsumed + unexpired)"
        );
        assert!(
            mark_body.contains("id = ? AND target = ? AND purpose = ? AND code = ?"),
            "CAS must bind the full identity, not just the row id"
        );
    }
}

/// 审计日志条目查询结果（对齐 admin.rs AuditLogEntry）
#[derive(Debug, sqlx::FromRow)]
pub struct AuditLogQueryRow {
    pub id: i64,
    pub user_id: i64,
    pub action: String,
    pub resource: String,
    pub detail: Option<String>,
    pub created_at: Option<time::PrimitiveDateTime>,
}

/// 查询审计日志（分页）
pub async fn query_audit_logs(
    pool: &MySqlPool,
    user_id: Option<i64>,
    action: Option<&str>,
    page: i64,
    size: i64,
) -> Result<Vec<AuditLogQueryRow>, DbError> {
    let offset = (page - 1).max(0) * size;

    let mut sql = format!(
        "SELECT id, user_id, action, resource, COALESCE(detail, '') as detail, created_at {}",
        user_visible_audit_from_clause()
    );
    let mut _has_user_filter = false;
    let mut _has_action_filter = false;

    if user_id.is_some() {
        sql.push_str(" AND user_id = ?");
        _has_user_filter = true;
    }
    if let Some(a) = action {
        if !a.is_empty() {
            sql.push_str(" AND action = ?");
            _has_action_filter = true;
        }
    }

    sql.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

    let mut query = sqlx::query_as::<_, AuditLogQueryRow>(&sql);
    if let Some(uid) = user_id {
        query = query.bind(uid);
    }
    if let Some(a) = action {
        if !a.is_empty() {
            query = query.bind(a);
        }
    }
    query = query.bind(size).bind(offset);

    let rows = query.fetch_all(pool).await?;
    Ok(rows)
}

/// 审计日志总数（与 query_audit_logs 同过滤条件；admin 分页用）。
pub async fn count_audit_logs(
    pool: &MySqlPool,
    user_id: Option<i64>,
    action: Option<&str>,
) -> Result<i64, DbError> {
    let mut sql = format!("SELECT COUNT(*) {}", user_visible_audit_from_clause());
    let mut _has_user_filter = false;
    let mut _has_action_filter = false;

    if user_id.is_some() {
        sql.push_str(" AND user_id = ?");
        _has_user_filter = true;
    }
    if let Some(a) = action {
        if !a.is_empty() {
            sql.push_str(" AND action = ?");
            _has_action_filter = true;
        }
    }

    let mut query = sqlx::query_scalar::<_, i64>(&sql);
    if let Some(uid) = user_id {
        query = query.bind(uid);
    }
    if let Some(a) = action {
        if !a.is_empty() {
            query = query.bind(a);
        }
    }
    query.fetch_one(pool).await.map_err(DbError::from)
}

// ===== 安全与教育域公共函数 =====

/// 查询默认密码策略
pub async fn find_default_password_policy(
    pool: &MySqlPool,
) -> Result<Option<astral_types::PasswordPolicy>, DbError> {
    #[derive(Debug, sqlx::FromRow)]
    struct Row {
        id: Option<i64>,
        name: String,
        min_length: i32,
        max_length: Option<i32>,
        require_uppercase: bool,
        require_lowercase: bool,
        require_digit: bool,
        require_special: bool,
        special_chars: Option<String>,
        max_retries: i32,
        lockout_minutes: i32,
        password_expiry_days: Option<i32>,
        history_count: i32,
        is_default: bool,
        status: String,
    }
    let row = sqlx::query_as::<_, Row>(
        "SELECT * FROM password_policy WHERE is_default = 1 AND status = 'ACTIVE' LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| astral_types::PasswordPolicy {
        id: r.id,
        name: r.name,
        min_length: r.min_length,
        max_length: r.max_length,
        require_uppercase: r.require_uppercase,
        require_lowercase: r.require_lowercase,
        require_digit: r.require_digit,
        require_special: r.require_special,
        special_chars: r.special_chars,
        max_retries: r.max_retries,
        lockout_minutes: r.lockout_minutes,
        password_expiry_days: r.password_expiry_days,
        history_count: r.history_count,
        is_default: r.is_default,
        status: r.status,
    }))
}

/// 插入安全事件
pub async fn insert_security_event(
    pool: &MySqlPool,
    user_id: Option<i64>,
    event_type: &str,
    severity: &str,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    detail: Option<&str>,
) -> Result<i64, DbError> {
    let result = sqlx::query(
        "INSERT INTO security_event (user_id, event_type, severity, ip_address, user_agent, detail) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(user_id).bind(event_type).bind(severity).bind(ip_address).bind(user_agent).bind(detail)
    .execute(pool).await?;
    Ok(result.last_insert_id() as i64)
}

/// 查询启用的 OAuth 提供商
pub async fn find_enabled_oauth_providers(
    pool: &MySqlPool,
) -> Result<Vec<astral_types::OauthProvider>, DbError> {
    #[derive(Debug, sqlx::FromRow)]
    struct Row {
        id: Option<i64>,
        provider_name: String,
        client_id: String,
        client_secret_encrypted: Option<String>,
        authorize_url: Option<String>,
        token_url: Option<String>,
        userinfo_url: Option<String>,
        scope: Option<String>,
        enabled: bool,
        created_at: Option<i64>,
    }
    let rows =
        sqlx::query_as::<_, Row>("SELECT * FROM oauth_provider WHERE enabled = 1 ORDER BY id")
            .fetch_all(pool)
            .await?;
    Ok(rows
        .into_iter()
        .map(|r| astral_types::OauthProvider {
            id: r.id,
            provider_name: r.provider_name,
            client_id: r.client_id,
            client_secret_encrypted: r.client_secret_encrypted,
            authorize_url: r.authorize_url,
            token_url: r.token_url,
            userinfo_url: r.userinfo_url,
            scope: r.scope,
            enabled: r.enabled,
            created_at: r.created_at,
        })
        .collect())
}

/// 按 code 查询学校
pub async fn find_school_by_code(
    pool: &MySqlPool,
    code: &str,
) -> Result<Option<astral_types::School>, DbError> {
    #[derive(Debug, sqlx::FromRow)]
    struct Row {
        id: Option<i64>,
        name: String,
        code: Option<String>,
        province: Option<String>,
        city: Option<String>,
        district: Option<String>,
        address: Option<String>,
        school_type: Option<String>,
        logo_url: Option<String>,
        contact_phone: Option<String>,
        contact_email: Option<String>,
        status: String,
        created_at: Option<i64>,
    }
    let row = sqlx::query_as::<_, Row>("SELECT * FROM school WHERE code = ? AND status = 'ACTIVE'")
        .bind(code)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| astral_types::School {
        id: r.id,
        name: r.name,
        code: r.code,
        province: r.province,
        city: r.city,
        district: r.district,
        address: r.address,
        school_type: r.school_type,
        logo_url: r.logo_url,
        contact_phone: r.contact_phone,
        contact_email: r.contact_email,
        status: r.status,
        created_at: r.created_at,
    }))
}
