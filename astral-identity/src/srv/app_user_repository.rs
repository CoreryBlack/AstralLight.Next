//! App 用户数据访问 — AppUserRepository
//!
//! 只承载 app_user 表的**纯单语句原子 SQL**（与 `session_repository` 同风格：
//! `pub(crate)` 自由函数，由 handler/service 编排）。app 会话签发前置校验用。

use sqlx::MySqlPool;

use astral_types::AstralError;

/// 校验 app_user 存在且 ACTIVE，返回其 id（内部 app-session 签发前置检查）。
pub(crate) async fn find_active_app_user_id(
    db: &MySqlPool,
    user_id: i64,
) -> Result<Option<i64>, AstralError> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM app_user WHERE id = ? AND status = 'ACTIVE'")
            .bind(user_id)
            .fetch_optional(db)
            .await
            .map_err(|e| AstralError::Database(format!("Query app_user failed: {e}")))?;
    Ok(row.map(|r| r.0))
}
