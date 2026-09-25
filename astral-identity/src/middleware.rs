//! Identity 权限检查中间件
//!
//! 对齐 TrustGraph 的 `permission_check.rs` 模式。

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use astral_common::audit::org_provenance_audit_detail;
use astral_common::middleware::permission_check_shared::{
    physical_policy_context, request_target_id, resolve_permission_action, BoxedResponse,
    PathResourceMap,
};
use astral_common::token_contract::PrincipalKind;
use astral_db::{
    check_sod_conflict, check_sod_conflict_with_org, load_org_sod_admission,
    resolve_resource_ownership, SqlxRuleRepository,
};

use crate::AppState;

pub const IDENTITY_PATH_MAP: PathResourceMap = &[
    // 此中间件挂载在 `/api/v1/auth` 路由下，收到的是剥离前缀后的路径。
    ("/sessions", "identity_users"),
    ("/sessions/refresh", "identity_users"),
    ("/sessions/switch-card", "identity_users"),
    ("/sessions/logout", "identity_users"),
    ("/sessions/revoke", "identity_users"),
    ("/register", "identity_users"),
    ("/users", "identity_users"),
    ("/cards", "identity_users"),
    ("/identities", "identity_users"),
    ("/providers", "identity_users"),
    ("/password", "identity_users"),
    ("/admin", "identity_users"),
    ("/verification", "identity_users"),
    ("/orgs", "organization"),
    ("/domains", "domain"),
    ("/tenants", "platform_tenant"),
    ("/me", "identity_users"),
    ("/mfa", "identity_users"),
    ("/internal/sessions", "identity_users"),
];

const IDENTITY_SKIP_PATHS: &[&str] = &[
    // 认证入口（无 JWT 时可访问，路径已剥离 /api/v1/auth 前缀）
    "/sessions",
    "/sessions/refresh",
    "/sessions/switch-card",
    "/sessions/logout",
    "/sessions/revoke",
    "/register",
    "/password/forgot",
    "/password/reset",
    "/verification/send",
    "/verification/verify",
    "/internal/sessions",
    // 自服务路径（仅需有效 JWT，不需要权限规则检查）
    "/me",
    "/providers",
    "/sessions/switch-card",
];

pub async fn identity_permission_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, BoxedResponse> {
    let path = req.uri().path();
    let method = req.method().clone();

    if is_identity_skip_path(path) {
        if is_credential_bootstrap_path(path) {
            return Ok(next.run(req).await);
        }
        let ctx = physical_policy_context(
            req.headers(),
            "identity_users",
            "read",
            request_target_id(&req),
        )
        .map_err(|status| BoxedResponse::new(status.into_response()))?;
        verify_active_identity_context(&state, &ctx).await?;
        if ctx.principal_kind.as_deref() == Some(PrincipalKind::PlatformUser.as_str()) {
            verify_active_card_context(
                &state,
                ctx.card_id,
                ctx.user_id,
                ctx.tenant_id,
                ctx.domain_id,
            )
            .await?;
        }
        return Ok(next.run(req).await);
    }

    let resource = match IDENTITY_PATH_MAP.iter().find(|(prefix, _)| {
        path == *prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    }) {
        Some((_, r)) => *r,
        None => {
            tracing::warn!(path, "no identity resource mapping, denying");
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

    // 正式授权仓储必须携带启动期冻结的 ORG_SCOPE 旗标（default-off；与
    // TrustGraph 共享同一严格解析器与默认关闭语义），避免同一受管租户在
    // 不同宿主间出现 org_scope 准入 split-brain。绝不逐请求读 env。
    let repo =
        SqlxRuleRepository::new(state.db.clone()).with_org_scope_enabled(state.org_scope_enabled);
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
        tracing::warn!(
            user_id = ?user_id,
            card_id = ?card_id,
            resource = resource,
            action = action,
            reason = %decision.reason,
            path = path,
            "permission_denied"
        );
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
                tracing::warn!(
                    card_id = so_card_id, resource = resource, action = action,
                    policy = ?result.conflict_policy, "sod_conflict_denied"
                );
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

fn is_identity_skip_path(path: &str) -> bool {
    IDENTITY_SKIP_PATHS.iter().any(|prefix| {
        path == *prefix
            || path
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

fn is_credential_bootstrap_path(path: &str) -> bool {
    matches!(
        path,
        "/sessions"
            | "/sessions/switch-card"
            | "/sessions/refresh"
            | "/sessions/logout"
            | "/sessions/revoke"
            | "/register"
            | "/password/forgot"
            | "/verification/send"
            | "/verification/verify"
            | "/internal/sessions"
    ) || path
        .strip_prefix("/password/reset/")
        .is_some_and(|token| !token.is_empty() && !token.contains('/'))
}

async fn verify_active_identity_context(
    state: &AppState,
    ctx: &astral_types::PolicyContext,
) -> Result<(), BoxedResponse> {
    let identity_card_id = ctx
        .identity_card_id
        .filter(|value| *value > 0)
        .ok_or_else(|| card_context_error("IDENTITY_CARD_REQUIRED"))?;
    let user_id = ctx
        .user_id
        .filter(|value| *value > 0)
        .ok_or_else(|| card_context_error("CARD_CONTEXT_USER_REQUIRED"))?;
    let row = sqlx::query_as::<_, (i64, i64, String)>(
        "SELECT card_id, user_id, status FROM identity_card \
         WHERE card_id = ? AND user_id = ? \
           AND (expires_at IS NULL OR expires_at >= UTC_TIMESTAMP()) \
         LIMIT 1",
    )
    .bind(identity_card_id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| card_context_error("IDENTITY_CARD_CONTEXT_UNAVAILABLE"))?
    .ok_or_else(|| card_context_error("IDENTITY_CARD_CONTEXT_NOT_FOUND"))?;
    if row.2 != "ACTIVE" {
        return Err(card_context_error("IDENTITY_CARD_CONTEXT_INVALID"));
    }
    Ok(())
}

async fn verify_active_card_context(
    state: &AppState,
    card_id: Option<i64>,
    user_id: Option<i64>,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
) -> Result<(), BoxedResponse> {
    let Some(card_id) = card_id.filter(|value| *value > 0) else {
        return Ok(());
    };
    let user_id = user_id
        .filter(|value| *value > 0)
        .ok_or_else(|| card_context_error("CARD_CONTEXT_USER_REQUIRED"))?;
    let card = state
        .card_repository
        .get_user_card(card_id)
        .await
        .map_err(|_| card_context_error("CARD_CONTEXT_UNAVAILABLE"))?
        .ok_or_else(|| card_context_error("CARD_CONTEXT_NOT_FOUND"))?;
    if card.user_id != Some(user_id) || card.card_status != "ACTIVE" {
        return Err(card_context_error("CARD_CONTEXT_INVALID"));
    }
    if tenant_id.is_some() && card.tenant_id != tenant_id {
        return Err(card_context_error("CARD_CONTEXT_TENANT_MISMATCH"));
    }
    if domain_id.is_some() && card.domain_id != domain_id {
        return Err(card_context_error("CARD_CONTEXT_DOMAIN_MISMATCH"));
    }
    let now = time::OffsetDateTime::now_utc();
    if let Some(valid_from) = card.valid_from.as_deref() {
        let parsed =
            time::OffsetDateTime::parse(valid_from, &time::format_description::well_known::Rfc3339)
                .map_err(|_| card_context_error("CARD_CONTEXT_VALIDITY_UNAVAILABLE"))?;
        if parsed > now {
            return Err(card_context_error("CARD_CONTEXT_NOT_YET_VALID"));
        }
    }
    if let Some(valid_until) = card.valid_until.as_deref() {
        let parsed = time::OffsetDateTime::parse(
            valid_until,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| card_context_error("CARD_CONTEXT_VALIDITY_UNAVAILABLE"))?;
        if parsed < now {
            return Err(card_context_error("CARD_CONTEXT_EXPIRED"));
        }
    }
    Ok(())
}

fn card_context_error(reason: &str) -> BoxedResponse {
    BoxedResponse::new(
        (
            StatusCode::FORBIDDEN,
            format!("Card context denied: {reason}"),
        )
            .into_response(),
    )
}

#[cfg(test)]
mod tests {
    use super::{is_credential_bootstrap_path, is_identity_skip_path};

    #[test]
    fn management_paths_do_not_skip_permission_evaluation() {
        assert!(!is_identity_skip_path("/users"));
        assert!(!is_identity_skip_path("/admin/stats"));
        assert!(!is_identity_skip_path("/mfa-extra"));
        assert!(!is_identity_skip_path("/wechat/miniprogram/login"));
    }

    #[test]
    fn credential_bootstrap_uses_reset_token_segment_boundary() {
        assert!(is_credential_bootstrap_path("/password/reset/token"));
        assert!(!is_credential_bootstrap_path("/password/reset"));
        assert!(!is_credential_bootstrap_path("/password/reset-extra"));
        assert!(!is_credential_bootstrap_path("/password/reset/token/extra"));
        assert!(!is_credential_bootstrap_path("/mfa/status"));
        assert!(!is_identity_skip_path("/mfa/status"));
    }

    /// 宿主 SoD 分发形状守卫（对齐 TrustGraph/sod_check 的源文本守卫惯例）：
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
