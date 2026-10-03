//! 会话数据访问 — SessionRepository
//!
//! 只承载 auth_device_session / auth_token_family / auth_session_jti_index 的
//! **纯单语句原子 SQL**。CAS 轮换顺序、Redis 投影、jti fan-out 和 family
//! 级联撤销编排保留在 `srv::session`，不允许把编排函数下沉到本文件。
//!
//! source writer 栅栏边界：仅**无外部调用方栅栏兜底**的两个签发叶子
//! （[`create_token_family_with_expiry`] / [`insert_app_device_session`]）在本
//! 文件内经 `fenced_source_write` 自围（autocommit await 窗口武装取消栅栏，
//! Ok → proven；Err/取消 → sticky uncertain）。其余 mutation（revoke/cleanup
//! 系列）由调用方集群栅栏统一持有，本文件保持裸 SQL，绝不双重围栏。

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
     client_app_id, channel_code, current_user_card_id, session_state, session_version, session_epoch, \
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

/// 撤销单个会话（单语句，由调用方编排投影 fan-out 顺序）。
pub(crate) async fn revoke_session(
    db: &MySqlPool,
    id: i64,
    reason: &str,
) -> Result<(), AstralError> {
    let result = sqlx::query(
        "UPDATE auth_device_session SET status = 'REVOKED', session_state = 'REVOKED', \
         session_version = session_version + 1, session_epoch = session_epoch + 1, \
         revoked_at = UTC_TIMESTAMP(), revoked_reason = ?, updated_at = UTC_TIMESTAMP() \
         WHERE session_id = ? AND status = 'ACTIVE' AND session_state = 'ACTIVE'",
    )
    .bind(reason)
    .bind(id)
    .execute(db)
    .await
    .map_err(|e| AstralError::Database(format!("Revoke session failed: {e}")))?;
    if result.rows_affected() > 1 {
        return Err(AstralError::Database(
            "Revoke session CAS affected multiple rows".into(),
        ));
    }
    Ok(())
}

/// 列出 family 下全部 session_id（供撤销编排 fan-out）。
pub(crate) async fn list_session_ids_by_family(
    db: &MySqlPool,
    family_id: i64,
) -> Result<Vec<i64>, AstralError> {
    let rows: Vec<(i64,)> =
        sqlx::query_as("SELECT session_id FROM auth_device_session WHERE family_id = ?")
            .bind(family_id)
            .fetch_all(db)
            .await
            .map_err(|e| AstralError::Database(format!("Load family sessions failed: {e}")))?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// 列出用户全部活跃 session_id（供 revokeAllForUser 编排 fan-out）。
pub(crate) async fn list_active_session_ids_by_user(
    db: &MySqlPool,
    user_id: i64,
) -> Result<Vec<i64>, AstralError> {
    let rows: Vec<(i64,)> = sqlx::query_as(
        "SELECT session_id FROM auth_device_session \
         WHERE user_id = ? AND status = 'ACTIVE' AND session_state = 'ACTIVE'",
    )
    .bind(user_id)
    .fetch_all(db)
    .await
    .map_err(|e| AstralError::Database(format!("Load user sessions failed: {e}")))?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

/// 按 user 批量关闭活跃会话（单语句，revokeAllForUser 编排调用）。
pub(crate) async fn revoke_user_sessions(
    db: &MySqlPool,
    user_id: i64,
    reason: &str,
) -> Result<(), AstralError> {
    sqlx::query(
        "UPDATE auth_device_session SET status = 'REVOKED', session_state = 'REVOKED', \
         session_version = session_version + 1, session_epoch = session_epoch + 1, \
         revoked_at = UTC_TIMESTAMP(), revoked_reason = ?, updated_at = UTC_TIMESTAMP() \
         WHERE user_id = ? AND status = 'ACTIVE' AND session_state = 'ACTIVE'",
    )
    .bind(reason)
    .bind(user_id)
    .execute(db)
    .await
    .map_err(|e| AstralError::Database(format!("Revoke user sessions failed: {e}")))?;
    Ok(())
}

/// 按 user 批量撤销活跃 token family（单语句，revokeAllForUser 编排调用）。
pub(crate) async fn revoke_user_token_families(
    db: &MySqlPool,
    user_id: i64,
    reason: &str,
) -> Result<(), AstralError> {
    sqlx::query(
        "UPDATE auth_token_family SET status = 'REVOKED', revoked_at = UTC_TIMESTAMP(), \
         revoked_reason = ? WHERE user_id = ? AND status = 'ACTIVE'",
    )
    .bind(reason)
    .bind(user_id)
    .execute(db)
    .await
    .map_err(|e| AstralError::Database(format!("Revoke user token families failed: {e}")))?;
    Ok(())
}

/// family CAS 撤销（单语句，revoke_token_family 编排调用）。
pub(crate) async fn revoke_family_cas(
    db: &MySqlPool,
    family_id: i64,
    reason: &str,
) -> Result<(), AstralError> {
    let result = sqlx::query(
        "UPDATE auth_token_family SET status = 'REVOKED', revoked_at = UTC_TIMESTAMP(), \
         revoked_reason = ? WHERE family_id = ? AND status = 'ACTIVE'",
    )
    .bind(reason)
    .bind(family_id)
    .execute(db)
    .await
    .map_err(|e| AstralError::Database(format!("Revoke family failed: {e}")))?;
    if result.rows_affected() > 1 {
        return Err(AstralError::Database(
            "Revoke family CAS affected multiple rows".into(),
        ));
    }
    Ok(())
}

/// 级联撤销 family 下全部活跃会话（单语句，revoke_token_family 编排调用）。
pub(crate) async fn revoke_family_sessions(
    db: &MySqlPool,
    family_id: i64,
    reason: &str,
) -> Result<(), AstralError> {
    sqlx::query(
        "UPDATE auth_device_session SET status = 'REVOKED', session_state = 'REVOKED', \
         session_version = session_version + 1, session_epoch = session_epoch + 1, \
         revoked_at = UTC_TIMESTAMP(), revoked_reason = ?, updated_at = UTC_TIMESTAMP() \
         WHERE family_id = ? AND status = 'ACTIVE' AND session_state = 'ACTIVE'",
    )
    .bind(reason)
    .bind(family_id)
    .execute(db)
    .await
    .map_err(|e| AstralError::Database(format!("Cascade revoke sessions failed: {e}")))?;
    Ok(())
}

/// App 会话签发：插入 auth_device_session 行（app 设备，绑定 family + refresh 哈希），
/// 返回 session_id。失败时由调用方编排 family 补偿清理。
///
/// 签发叶子自围 source writer 栅栏（internal.rs 调用点保持裸调用，避免双重
/// 围栏）：hub 已装则 fail-closed 取得，INSERT await 窗口前武装取消栅栏，
/// 结果判定后 settle（Ok → proven；Err/取消 → sticky uncertain）。
pub(crate) async fn insert_app_device_session(
    db: &MySqlPool,
    family_id: i64,
    user_id: i64,
    refresh_token_hash: &str,
    refresh_expires_at: PrimitiveDateTime,
) -> Result<i64, AstralError> {
    let source_guard = source_writer_guard::begin_source_write()?;
    let result = source_writer_guard::fenced_source_write(
        source_guard,
        sqlx::query(
            "INSERT INTO auth_device_session (family_id, user_id, device_id, current_user_card_id, session_state, session_version, session_epoch, refresh_token_hash, refresh_expires_at, status) \
             VALUES (?, ?, 'app', ?, 'ACTIVE', 1, 1, ?, ?, 'ACTIVE')",
        )
        .bind(family_id)
        .bind(user_id)
        // identity_card.card_id 不是 user_card.card_id；不跨写
        .bind(None::<i64>)
        .bind(refresh_token_hash)
        .bind(refresh_expires_at)
        .execute(db),
    )
    .await
    .map_err(|e| AstralError::Database(format!("Insert app device session failed: {e}")))?;
    if result.rows_affected() == 1 && result.last_insert_id() > 0 {
        Ok(result.last_insert_id() as i64)
    } else {
        Err(AstralError::Database(
            "Session issuance failed: no durable session id".into(),
        ))
    }
}

/// 清理指定用户 ACTIVE 的 token family（app 会话失败补偿；幂等）。
pub(crate) async fn cleanup_active_family(
    db: &MySqlPool,
    family_id: i64,
    user_id: i64,
) -> Result<(), AstralError> {
    sqlx::query(
        "DELETE FROM auth_token_family WHERE family_id = ? AND user_id = ? AND status = 'ACTIVE'",
    )
    .bind(family_id)
    .bind(user_id)
    .execute(db)
    .await
    .map_err(|e| AstralError::Database(format!("Cleanup token family failed: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    /// 签发叶子 source 栅栏形状回归（源形状，无 IO）：
    /// 1. `create_token_family_with_expiry` / `insert_app_device_session` 两个
    ///    签发叶子必须经 `begin_source_write` + `fenced_source_write` 自围
    ///    （autocommit await 窗口武装取消栅栏；Ok → proven；Err/取消 → sticky
    ///    uncertain——取消缝语义由 `source_writer_guard` 的通用真实
    ///    pending-future 取消测试在本地 hub 上涵盖，本测试做结构固定）；
    /// 2. revoke/cleanup 系列保持裸 SQL——由调用方集群/调用点栅栏统一持有
    ///    （session.rs 集群、internal.rs 补偿点），绝不双重围栏。
    #[test]
    fn issuance_leaves_are_self_fenced_and_revoke_leaves_stay_outer_fenced() {
        let source = include_str!("session_repository.rs");
        let impl_source = &source[..source
            .find("#[cfg(test)]")
            .expect("tests module must stay at the end of session_repository.rs")];

        for leaf in [
            "async fn create_token_family_with_expiry(",
            "async fn insert_app_device_session(",
        ] {
            let body = impl_source
                .split(leaf)
                .nth(1)
                .unwrap_or_else(|| panic!("{leaf} must stay in session_repository.rs"));
            assert!(
                body.contains("source_writer_guard::begin_source_write()")
                    && body.contains("source_writer_guard::fenced_source_write("),
                "{leaf} must be self-fenced via the shared source writer helper"
            );
        }

        for outer_fenced in [
            "async fn revoke_session(",
            "async fn revoke_user_sessions(",
            "async fn revoke_user_token_families(",
            "async fn revoke_family_cas(",
            "async fn revoke_family_sessions(",
            "async fn cleanup_active_family(",
        ] {
            let body = impl_source
                .split(outer_fenced)
                .nth(1)
                .unwrap_or_else(|| panic!("{outer_fenced} must stay in session_repository.rs"));
            // 截到下一个函数文档注释（下一函数起始）之前，即本函数体。
            let body_end = body.find("/// ").unwrap_or(body.len());
            let body = &body[..body_end];
            assert!(
                !body.contains("fenced_source_write"),
                "{outer_fenced} must stay bare SQL: its callers' cluster/call-site fence owns it"
            );
        }
    }
}
