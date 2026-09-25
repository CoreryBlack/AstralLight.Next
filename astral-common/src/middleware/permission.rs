//! 权限检查中间件与工具函数
//!
//! 提供 `require_permission()` 函数供路由处理器调用，
//! 以及 `extract_user_id()` 从请求头提取用户身份。
//!
//! 对应 Java `@RequirePermission` + `PermissionAspect`。
//! 内置 1% 采样一致性巡检（对齐 Java `SnapshotConsistencyChecker`）。

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::middleware::permission_check_shared::physical_policy_context;
use astral_types::PolicyContext;
use policy_engine::{PolicyEngine, RuleRepository};

/// 重导出全局一致性检查器（委托到 policy_engine::consistency::get_consistency_checker）
pub use policy_engine::get_consistency_checker;

/// Compatibility helper for non-targeted internal checks. It constructs an
/// `Unresolved` HTTP context, so it intentionally denies protected-resource
/// authorization unless a service-specific resolver path is used instead.
pub async fn require_permission<R: RuleRepository>(
    headers: &HeaderMap,
    engine: &PolicyEngine,
    repo: &R,
    resource: &str,
    action: &str,
) -> Result<PolicyContext, Box<Response>> {
    let ctx = physical_policy_context(headers, resource, action, None)
        .map_err(|status| Box::new(status.into_response()))?;
    let decision = engine.evaluate(&ctx, repo).await;

    // 一致性检查已由 PolicyEngine.evaluate() 内部执行（1% 采样），
    // 无需在此重复调用。全局 CHECKER 实例保留供 consistency_monitor 端点查询 stats/violations。

    if !decision.allowed {
        tracing::warn!(
            user_id = ?ctx.user_id,
            resource,
            action,
            reason = %decision.reason,
            "permission denied"
        );
        return Err(Box::new(
            (StatusCode::FORBIDDEN, "Permission denied").into_response(),
        ));
    }

    Ok(ctx)
}

/// 提取 x-user-id 头
pub fn extract_user_id(headers: &HeaderMap) -> Option<i64> {
    headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok())
}
