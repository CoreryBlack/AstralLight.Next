//! Monitor 权限检查中间件

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use astral_common::audit::org_provenance_audit_detail;
use astral_common::middleware::permission_check_shared::{
    path_matches_prefix, physical_policy_context, request_target_id, resolve_permission_action,
    BoxedResponse, PathResourceMap,
};
use astral_db::{
    check_sod_conflict, check_sod_conflict_with_org, load_org_sod_admission,
    resolve_resource_ownership, SqlxRuleRepository,
};

use crate::AppState;

/// 注意：路由通过 `.nest("/api/v1/monitor", ...)` 注册，
/// axum 会自动剥离 `/api/v1/monitor` 前缀，因此中间件收到的路径不包含此前缀。
pub const MONITOR_PATH_MAP: PathResourceMap = &[
    ("/alerts", "monitor"),
    ("/alert-rules", "monitor"),
    ("/alert-history", "monitor"),
    ("/notifications", "notification"),
    ("/channels", "notification"),
    ("/cache", "monitor"),
    ("/latency", "monitor"),
    ("/resources", "monitor"),
    ("/trend", "monitor"),
    ("/services", "monitor"),
    ("/alerts-summary", "monitor"),
    ("/metrics", "monitor"),
    ("/activities", "monitor"),
    ("/activity-logs", "monitor"),
    ("/audit-logs", "monitor"),
    ("/rules", "monitor"),
    ("/system-info", "monitor"),
    ("/dashboard", "monitor"),
    ("/consistency-check", "monitor"),
];

pub async fn monitor_permission_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, BoxedResponse> {
    let path = req.uri().path();
    let method = req.method().clone();

    let resource = match MONITOR_PATH_MAP
        .iter()
        .find(|(prefix, _)| path_matches_prefix(path, prefix))
    {
        Some((_, r)) => *r,
        None => {
            tracing::warn!(path, "no monitor resource mapping, denying");
            return Err(BoxedResponse::new(
                (
                    StatusCode::FORBIDDEN,
                    format!("No permission mapping for path: {}", path),
                )
                    .into_response(),
            ));
        }
    };

    let action = match resolve_permission_action(resource, path, method.as_str()) {
        Some(action) => action,
        None => return Ok(next.run(req).await),
    };

    let query_target_id = request_target_id(&req);
    let mut ctx = physical_policy_context(req.headers(), resource, action, query_target_id)
        .map_err(|status| BoxedResponse::new(status.into_response()))?;
    let resolution = resolve_resource_ownership(
        &state.db,
        resource,
        path,
        method.as_str(),
        query_target_id,
        ctx.card_id,
        ctx.user_id,
    )
    .await;
    resolution.apply_to(&mut ctx);
    let user_id = ctx.user_id;
    let card_id = ctx.card_id;
    let tenant_id = ctx.tenant_id;
    let resource_owner_id = ctx.resource_owner_id;

    // 正式授权仓储必须携带启动期冻结的 ORG_SCOPE 旗标（default-off；冻结于
    // 共享 AppConfig，与 identity/trustgraph 同一严格解析器与默认关闭语义），
    // 避免同一受管租户在不同宿主间出现 org_scope 准入 split-brain。
    // 绝不逐请求读 env。
    let repo = SqlxRuleRepository::new(state.db.clone())
        .with_org_scope_enabled(state.config.org_scope_enabled);
    let decision = state.engine.evaluate(&ctx, &repo).await;

    // 权限决策审计（MQ-first，DB fallback；故障不影响权限决策）。
    // ORG_SCOPE 判定携带 provenance 时，detail 升级为有界结构化 JSON
    // （路径 + 校验通过的 orgProvenance）；非 ORG 判定 detail 仍为纯请求路径，
    // 行为不变。provenance 不进入 Prometheus 标签。
    {
        let audit_resource = resource.to_string();
        let audit_action = action.to_string();
        let audit_reason = decision.reason.clone();
        let audit_path = path.to_string();
        let audit_allowed = decision.allowed;
        let audit_domain_id = ctx.domain_id;
        let audit_detail = decision
            .org_provenance
            .as_ref()
            .and_then(|provenance| org_provenance_audit_detail(path, provenance));
        let pool = state.db.clone();
        let hit_phase =
            policy_engine::PolicyEngine::allow_source_phase(&decision).map(String::from);
        tokio::spawn(async move {
            astral_common::audit::record_permission_audit_with_request_detail(
                user_id,
                card_id,
                audit_domain_id,
                tenant_id,
                &audit_resource,
                &audit_action,
                audit_allowed,
                &audit_reason,
                &audit_path,
                None,
                audit_detail,
            )
            .await;
            if audit_allowed {
                if let Some(card) = card_id {
                    astral_db::record_permission_hit(
                        &pool,
                        card,
                        &audit_resource,
                        &audit_action,
                        hit_phase.as_deref(),
                    )
                    .await;
                }
            }
        });
    }

    if !decision.allowed {
        return Err(BoxedResponse::new(
            (
                StatusCode::FORBIDDEN,
                format!(
                    "Permission denied: {} for {}:{}",
                    decision.reason, resource, action
                ),
            )
                .into_response(),
        ));
    }

    if let Some(so_card_id) = card_id {
        // 对组织 ALLOW，先把 PolicyEngine 返回的 provenance 与 fresh organization
        // publication/member evidence 经共享 helper 重新装配，再进入 deny-only
        // 复核；读取、钉栅或匹配失败统一进入 unavailable 分支，绝不把组织持有
        // 权限折算为空集。非 ORG 判定保持既有纯 deny-only 检查不变。
        let sod_result = match load_org_sod_admission(&state.db, &ctx, &decision).await {
            Ok(Some(admission)) => {
                check_sod_conflict_with_org(&state.db, &ctx, &admission, resource_owner_id).await
            }
            Ok(None) => {
                check_sod_conflict(
                    &state.db,
                    so_card_id,
                    user_id,
                    resource,
                    action,
                    resource_owner_id,
                )
                .await
            }
            Err(error) => Err(error),
        };
        match sod_result {
            Ok(result) if result.has_conflict => {
                return Err(BoxedResponse::new(
                    (
                        StatusCode::FORBIDDEN,
                        format!(
                            "SoD conflict: {} holds conflicting permission '{}' per policy '{}'",
                            resource,
                            result.conflict_permission.unwrap_or_default(),
                            result.conflict_policy.unwrap_or_default(),
                        ),
                    )
                        .into_response(),
                ));
            }
            Ok(_) => {}
            Err(error) => {
                tracing::error!(card_id = so_card_id, resource, action, %error, "SoD check unavailable; denying");
                return Err(BoxedResponse::new(
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "SoD check unavailable; request denied",
                    )
                        .into_response(),
                ));
            }
        }
    }

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    /// 宿主 SoD 分发形状守卫（对齐 TrustGraph/identity 的源文本守卫惯例）：
    /// ORG provenance 判定必须先经 shared fresh 准入装配
    /// （`load_org_sod_admission`）再进入 `check_sod_conflict_with_org`
    /// deny-only 复核；无 provenance 时回落纯 `check_sod_conflict`；审计
    /// detail 必须经 shared 有界 provenance helper 并通过显式 detail 审计
    /// 入口传播。本地不得重新引入任何重复 helper 定义。
    #[test]
    fn sod_dispatch_wires_org_provenance_to_fresh_admission_recheck() {
        let source = include_str!("middleware.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        let loader = production
            .find("load_org_sod_admission(&state.db, &ctx, &decision)")
            .expect("org dispatch must load fresh admission via the shared helper");
        let with_org = production
            .find("check_sod_conflict_with_org(&state.db, &ctx, &admission, resource_owner_id)")
            .expect("org admission must recheck via check_sod_conflict_with_org");
        let plain = production
            .find("check_sod_conflict(")
            .expect("non-org decisions must keep the plain deny-only SoD check");
        assert!(
            loader < with_org && with_org < plain,
            "dispatch order must be loader -> with_org -> plain fallback"
        );
        assert!(
            !production.contains("fn org_provenance_audit_detail"),
            "the bounded provenance detail helper must come from astral_common::audit"
        );
        assert!(production.contains("org_provenance_audit_detail(path, provenance)"));
        assert!(production.contains("record_permission_audit_with_request_detail("));
    }
}
