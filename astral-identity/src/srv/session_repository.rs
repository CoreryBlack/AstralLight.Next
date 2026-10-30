//! 会话数据访问 — SessionRepository
//!
//! 只承载 auth_device_session / auth_token_family / auth_session_jti_index 的
//! **纯单语句原子 SQL**。CAS 轮换顺序、session grant mirror、jti fan-out 和 family
//! 级联撤销编排保留在 `srv::session`，不允许把编排函数下沉到本文件。
//!
//! source writer 栅栏边界：无外部调用方栅栏兜底的 family 创建叶子
//! （[`create_token_family_with_expiry`]）在本文件内经 `fenced_source_write`
//! 自围（autocommit await 窗口武装取消栅栏，Ok → proven；Err/取消 → sticky
//! uncertain）。其余 mutation（revoke 系列）由调用方集群栅栏统一持有，本文件
//! 保持裸 SQL，绝不双重围栏。

use sqlx::MySqlPool;
use time::PrimitiveDateTime;

use astral_types::AstralError;

use crate::srv::source_writer_guard;

/// Canonical auth_device_session row. All DATETIME columns use sqlx's
/// existing `time` feature mapping to `PrimitiveDateTime`.
#[allow(dead_code)]
#[derive(Debug, sqlx::FromRow)]
pub(crate) struct DeviceSessionRow {
    pub session_id: i64,
    pub family_id: i64,
    pub user_id: i64,
    pub device_id: String,
    pub device_type: Option<String>,
    pub client_app_id: Option<String>,
    pub channel_code: Option<String>,
    pub current_user_card_id: Option<i64>,
    pub credential_version: Option<i64>,
    pub session_state: String,
    pub session_version: i64,
    pub session_epoch: i64,
    pub refresh_token_hash: String,
    pub refresh_expires_at: Option<PrimitiveDateTime>,
    pub status: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub last_seen_at: Option<PrimitiveDateTime>,
    pub revoked_at: Option<PrimitiveDateTime>,
    pub revoked_reason: Option<String>,
    pub created_at: PrimitiveDateTime,
    pub updated_at: PrimitiveDateTime,
}

/// Canonical auth_token_family row.
#[derive(Debug, sqlx::FromRow)]
#[allow(dead_code)]
pub(crate) struct TokenFamilyRow {
    pub family_id: i64,
    pub user_id: i64,
    pub family_key: String,
    pub status: String,
    pub issued_at: PrimitiveDateTime,
    pub expires_at: Option<PrimitiveDateTime>,
    pub revoked_at: Option<PrimitiveDateTime>,
    pub revoked_reason: Option<String>,
    pub metadata_json: Option<String>,
}

pub(crate) const DEVICE_SESSION_COLUMNS: &str = "session_id, family_id, user_id, device_id, device_type, \
     client_app_id, channel_code, current_user_card_id, credential_version, session_state, session_version, session_epoch, \
     refresh_token_hash, refresh_expires_at, status, ip_address, user_agent, last_seen_at, \
     revoked_at, revoked_reason, created_at, updated_at";

/// 按 refresh_token_hash 加载活跃会话（refresh 链路 Step 1）。
pub(crate) async fn load_active_refresh_session(
    db: &MySqlPool,
    refresh_hash: &str,
) -> Result<Option<DeviceSessionRow>, AstralError> {
    sqlx::query_as::<_, DeviceSessionRow>(&format!(
        "SELECT {DEVICE_SESSION_COLUMNS} FROM auth_device_session \
         WHERE refresh_token_hash = ? AND status = 'ACTIVE' AND session_state = 'ACTIVE'"
    ))
    .bind(refresh_hash)
    .fetch_optional(db)
    .await
    .map_err(|e| AstralError::Database(format!("Query session failed: {e}")))
}

/// 按已签名的 session/user/family 上下文加载当前活跃会话。
///
/// 该查询用于区分“refresh hash 已轮换”的重放与无法证明归属的输入；
/// 不按客户端提供的 refresh hash 定位，避免旧 refresh 在切换幂等键后绕过复用检测。
pub(crate) async fn load_active_session_context(
    db: &MySqlPool,
    session_id: i64,
    user_id: i64,
    family_id: i64,
) -> Result<Option<DeviceSessionRow>, AstralError> {
    sqlx::query_as::<_, DeviceSessionRow>(&format!(
        "SELECT {DEVICE_SESSION_COLUMNS} FROM auth_device_session \
         WHERE session_id = ? AND user_id = ? AND family_id = ? \
           AND status = 'ACTIVE' AND session_state = 'ACTIVE' LIMIT 1"
    ))
    .bind(session_id)
    .bind(user_id)
    .bind(family_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AstralError::Database(format!("Query session context failed: {e}")))
}

/// 按 BIGINT family_id 加载 token family 行。
pub(crate) async fn load_family_row(
    db: &MySqlPool,
    family_id: i64,
) -> Result<Option<TokenFamilyRow>, AstralError> {
    sqlx::query_as::<_, TokenFamilyRow>(
        "SELECT family_id, user_id, family_key, status, issued_at, expires_at, revoked_at, \
         revoked_reason, metadata_json FROM auth_token_family WHERE family_id = ?",
    )
    .bind(family_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AstralError::Database(format!("Query family failed: {e}")))
}

/// 创建带过期时间的 token family，返回 BIGINT family_id。
///
/// 签发叶子自围 source writer 栅栏（本函数的调用方——session.rs 公共委托
/// wrapper——不再围栏，避免双重围栏）：hub 已装则 fail-closed 取得，INSERT
/// await 窗口前武装取消栅栏，结果判定后 settle（Ok → proven；Err/取消 →
/// sticky uncertain）。
pub(crate) async fn create_token_family_with_expiry(
    db: &MySqlPool,
    family_key: &str,
    user_id: i64,
    expires_at: PrimitiveDateTime,
) -> Result<i64, AstralError> {
    let source_guard = source_writer_guard::begin_source_write()?;
    let result = source_writer_guard::fenced_source_write(
        source_guard,
        sqlx::query(
            "INSERT INTO auth_token_family (user_id, family_key, status, issued_at, expires_at) \
             VALUES (?, ?, 'ACTIVE', UTC_TIMESTAMP(), ?)",
        )
        .bind(user_id)
        .bind(family_key)
        .bind(expires_at)
        .execute(db),
    )
    .await
    .map_err(|e| AstralError::Database(format!("Create family failed: {e}")))?;
    if result.rows_affected() != 1 || result.last_insert_id() == 0 {
        return Err(AstralError::Database(
            "Create family failed: no durable family id".into(),
        ));
    }
    Ok(result.last_insert_id() as i64)
}

#[cfg(test)]
mod tests {
    #[test]
    fn issuance_leaves_are_self_fenced() {
        let source = include_str!("session_repository.rs");
        let impl_source = &source[..source
            .find("#[cfg(test)]")
            .expect("tests module must stay at the end of session_repository.rs")];

        let leaf = "async fn create_token_family_with_expiry(";
        let body = impl_source
            .split(leaf)
            .nth(1)
            .unwrap_or_else(|| panic!("{leaf} must stay in session_repository.rs"));
        assert!(
            body.contains("source_writer_guard::begin_source_write()")
                && body.contains("source_writer_guard::fenced_source_write("),
            "{leaf} must be self-fenced via the shared source writer helper"
        );
        assert!(
            impl_source.contains("load_active_session_context(")
                && impl_source.contains("session_id = ? AND user_id = ? AND family_id = ?")
        );
        for removed in [
            "revoke_session(",
            "list_session_ids_by_family(",
            "list_active_session_ids_by_user(",
            "revoke_user_sessions(",
            "revoke_user_token_families(",
            "revoke_family_cas(",
            "revoke_family_sessions(",
        ] {
            assert!(
                !impl_source.contains(removed),
                "legacy raw revoke helper {removed} must stay physically removed"
            );
        }
    }
}
