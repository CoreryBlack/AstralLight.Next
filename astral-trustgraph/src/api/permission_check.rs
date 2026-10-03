//! 路由级权限检查中间件
//!
//! 对齐 Java `PermissionAspect.enforce()` + `@RequirePermission`。
//! 拦截所有 `/main/api/v1/*` 请求，根据 HTTP 方法 + 路径前缀映射到
//! (resource_type, action)，调用 `PolicyEngine.evaluate()` 做权限判定。
//!
//! 方法→动作映射（对齐 Java PermissionAspect 的 action 推断）：
//!   GET / HEAD → "read"
//!   POST → "create"
//!   PUT / PATCH → "update"
//!   DELETE → "delete"

use std::time::Instant;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use astral_common::audit::org_provenance_audit_detail;
use astral_common::error::AppError;
use astral_common::middleware::permission_check_shared::{
    path_matches_prefix, physical_policy_context, request_target_id, resolve_permission_action,
    BoxedResponse,
};
use astral_db::{
    check_sod_conflict_with_context, check_sod_conflict_with_context_and_org,
    load_org_sod_admission_mirrored, resolve_resource_ownership,
    CachedPublishedEvidenceRuleRepository, SqlxRuleRepository,
};
use astral_types::AstralError;

use crate::observability::{
    classify_policy_decision, record_authorization_decision, record_authorization_request,
    record_sod_check, AuthorizationAdmissionOutcome, SodCheckOutcome,
};
use crate::AppState;

/// 路径前缀 → 资源类型映射表
///
/// 对应 Java Controller 上的 `@RequirePermission(resource = "xxx", action = "yyy")`
/// 注意：此中间件在 nest("/main/api/v1", ...) 内部运行，路径前缀已被剥离
pub const TRUSTGRAPH_PATH_RESOURCE_MAP: &[(&str, &str)] = &[
    ("/org-authority-edges", "org_authority_edge"),
    ("/org-unit-cards", "org_unit_card"),
    ("/org-memberships", "org_membership"),
    ("/permission-rules", "permission_rule"),
    ("/rule-sets", "permission_rule"),
    ("/audit", "audit"),
    ("/audit-quarantine", "audit_quarantine"),
    ("/simulation", "permission_rule"),
    ("/permission-requests", "permission_request"),
    ("/delegations", "permission_rule"),
    ("/admin-groups", "admin_group"),
    ("/templates", "identity_level_template"),
    ("/sod-policies", "permission_rule"),
    ("/hit-stats", "audit"),
    ("/stats", "monitor"),
    ("/tenants", "platform_tenant"),
    ("/platform-packages", "platform_package"),
    ("/departments", "platform_dept"),
    ("/users", "user"),
    ("/consistency", "monitor"),
    ("/arbiter", "monitor"),
    // 内部测试控制面（api::test_control）：复用已注册资源 monitor 的 read 动作，
    // 走正常 PolicyEngine 链路；路由本身默认关闭，启用后另有常量时间 token 校验。
    ("/internal/test-control", "monitor"),
    ("/inheritance", "permission_inheritance"),
    ("/cross-org-grants", "cross_org_grant"),
    ("/compliance", "audit"),
    ("/operations", "audit"),
    ("/domains", "domain"),
    ("/resource-types", "domain_resource_type"),
    ("/actions", "permission_action"),
    ("/user-levels", "domain"),
    ("/user-gradings", "domain"),
    ("/level-templates", "permission_rule"),
    ("/user-cards", "domain"),
    ("/card-templates", "domain"),
    ("/global-admins", "authorization"),
];

/// 放行路径：TrustGraph 业务端点统一经过 PolicyEngine；健康检查在主路由外单独暴露。
const SKIP_PATHS: &[&str] = &[];

/// 对象级 target_id 只来自显式 query 键（对齐 Java `PermissionAspect.resolveResourceId`），
/// 不从未知路径段推断，避免把分页/attempt 等无关数字误当授权资源。
fn resource_for_path(path: &str) -> Option<&'static str> {
    TRUSTGRAPH_PATH_RESOURCE_MAP
        .iter()
        .find(|(prefix, _)| path_matches_prefix(path, prefix))
        .map(|(_, resource)| *resource)
}

fn resolve_trustgraph_permission_action(
    resource: &str,
    path: &str,
    method: &str,
) -> Option<&'static str> {
    if resource == "org_authority_edge"
        && method == "POST"
        && (path.ends_with("/move") || path.ends_with("/detach"))
    {
        return Some("update");
    }
    if resource == "org_unit_card" && method == "POST" && path.contains("/revoke") {
        return Some("update");
    }
    if resource == "org_membership" && method == "POST" && path.ends_with("/revoke") {
        return Some("update");
    }
    if resource == "audit_quarantine" && method == "POST" && path.ends_with("/replay") {
        return Some("replay");
    }
    // 执剑人仲裁端点（POST /arbiter/arbitrate）映射到 monitor 资源一等注册的
    // `arbitrate` 动作（registry-first，与 audit_quarantine/replay 同型）。
    // HTTP 默认映射给 POST 推导 `create`，而 monitor 从未注册 create —— 无规则
    // 可授予它，端点被 DEFAULT_DENY 结构性锁死（三节点战役 S12/S13 发现的远程
    // 面阻塞）。GET /arbiter/stats 走默认 read，无需特例。
    if resource == "monitor" && method == "POST" && path.contains("/arbiter") {
        return Some("arbitrate");
    }
    resolve_permission_action(resource, path, method)
}

fn audit_request_id(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get("x-request-id")?.to_str().ok()?;
    match crate::repository::audit_log_repository::validated_request_operation_id(Some(raw)) {
        Ok(request_id) => request_id,
        Err(_) => {
            tracing::warn!("permission audit request id rejected by canonical safety gate");
            None
        }
    }
}

///
/// 用法（在 route group 的最外层应用）:
/// ```
/// use axum::{routing::get, Router};
/// use astral_trustgraph::{api::permission_check::permission_check_middleware, AppState};
///
/// fn build_router(state: AppState) -> Router {
///     Router::new()
///         .route("/permission-rules", get(|| async { "ok" }))
///         .layer(axum::middleware::from_fn_with_state(
///             state.clone(),
///             permission_check_middleware,
///         ))
///         .with_state(state)
/// }
/// ```
pub async fn permission_check_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, BoxedResponse> {
    let request_id = audit_request_id(req.headers());
    #[cfg(feature = "e1-observability")]
    {
        policy_engine::e1_observation::scope_request(
            request_id.clone(),
            permission_check_middleware_scoped(state, req, next, request_id),
        )
        .await
    }
    #[cfg(not(feature = "e1-observability"))]
    {
        permission_check_middleware_scoped(state, req, next, request_id).await
    }
}

async fn permission_check_middleware_scoped(
    state: AppState,
    mut req: Request,
    next: Next,
    request_id: Option<String>,
) -> Result<Response, BoxedResponse> {
    let authorization_started = Instant::now();
    let path = req.uri().path();
    let method = req.method().clone();

    // 放行路径
    if SKIP_PATHS.iter().any(|p| {
        path == *p
            || path
                .strip_prefix(p)
                .is_some_and(|rest| rest.starts_with('/'))
    }) {
        return Ok(next.run(req).await);
    }

    // 匹配路径前缀 → 资源类型
    let resource = match resource_for_path(path) {
        Some(resource) => resource,
        None => {
            tracing::warn!(path, "no resource mapping for path, denying");
            record_authorization_request(
                AuthorizationAdmissionOutcome::RejectedMethodOrRoute,
                authorization_started.elapsed(),
            );
            return Err(BoxedResponse::new(
                (
                    StatusCode::FORBIDDEN,
                    format!("No permission mapping for path: {}", path),
                )
                    .into_response(),
            ));
        }
    };

    let action = match resolve_trustgraph_permission_action(resource, path, method.as_str()) {
        Some(action) => action,
        None => {
            tracing::warn!(path, method = %method, "no permission action for protected route, denying");
            record_authorization_request(
                AuthorizationAdmissionOutcome::RejectedMethodOrRoute,
                authorization_started.elapsed(),
            );
            return Err(BoxedResponse::new(
                (
                    StatusCode::METHOD_NOT_ALLOWED,
                    format!(
                        "No permission action for method {} on path {}",
                        method, path
                    ),
                )
                    .into_response(),
            ));
        }
    };

    // Capture once before authority reads; installed-but-unavailable is a refusal.
    let admission_fence = match astral_db::memory_projection_hub() {
        None => None,
        Some(hub) => match hub.capture_authority_fence() {
            Some(fence) => Some(fence),
            None => {
                record_authorization_request(
                    AuthorizationAdmissionOutcome::RejectedContext,
                    authorization_started.elapsed(),
                );
                tracing::error!(
                    path = path,
                    "admission fence unavailable: source writer active or outcome unknown; denying"
                );
                return Err(BoxedResponse::new(
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "admission fence unavailable; request denied".to_string(),
                    )
                        .into_response(),
                ));
            }
        },
    };

    let query_target_id = request_target_id(&req);
    let mut ctx = match physical_policy_context(req.headers(), resource, action, query_target_id) {
        Ok(ctx) => ctx,
        Err(status) => {
            record_authorization_request(
                AuthorizationAdmissionOutcome::RejectedContext,
                authorization_started.elapsed(),
            );
            return Err(BoxedResponse::new(status.into_response()));
        }
    };
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
    #[cfg(feature = "e1-observability")]
    {
        let stamp = policy_engine::e1_observation::stamp();
        tracing::info!(
            target: "authz_e1",
            event = "signed_context_bound",
            request_id = stamp.request_id.as_deref().unwrap_or(""),
            process_observation_id = %stamp.process_observation_id,
            event_sequence = stamp.event_sequence,
            wall_unix_ns = %stamp.wall_unix_ns,
            user_id = ?ctx.user_id,
            identity_card_id = ?ctx.identity_card_id,
            card_id = ?ctx.card_id,
            tenant_id = ?ctx.tenant_id,
            domain_id = ?ctx.domain_id,
            resource,
            action,
            "e1 authorization observation"
        );
    }
    let user_id = ctx.user_id;
    let card_id = ctx.card_id;
    let tenant_id = ctx.tenant_id;
    let resource_owner_id = ctx.resource_owner_id;

    // 进程内 evidence 缓存包装（装配侧接线）：load_published_card_authorization
    // 走"指针对牌 + epoch + 时钟重验"命中协议，miss/漂移回源严格 reader；
    // engine 的 ALLOW 前复读由此退化为同一缓存条目的恒等克隆，其有效强度由
    // 包装层的读前/读后双读对牌承担。policy-engine 与 astral-db 严格 reader
    // 零改动。见 astral_db::evidence_cache 模块文档。
    //
    // 单机内存镜像读面（default-off）：组合进程安装
    // astral_db::memory_projection_hub 后，命中镜像的直接返回与 durable 同源
    // 的已验证证据（同一纯装配函数），pending/未预热一律回退既有链路。
    let decision = if astral_db::memory_mirror_is_installed() {
        let repo = astral_db::MemoryMirroredRuleRepository::new(
            CachedPublishedEvidenceRuleRepository::new(
                SqlxRuleRepository::new(state.db.clone())
                    .with_org_scope_enabled(state.org_scope_enabled),
                state.db.clone(),
            ),
        )
        .with_durable_refill(state.db.clone());
        state.engine.evaluate(&ctx, &repo).await
    } else {
        let repo = CachedPublishedEvidenceRuleRepository::new(
            SqlxRuleRepository::new(state.db.clone())
                .with_org_scope_enabled(state.org_scope_enabled),
            state.db.clone(),
        );
        state.engine.evaluate(&ctx, &repo).await
    };
    record_authorization_decision(classify_policy_decision(&decision));
    #[cfg(feature = "e1-observability")]
    {
        let stamp = policy_engine::e1_observation::stamp();
        tracing::info!(
            target: "authz_e1",
            event = "decision_return",
            request_id = stamp.request_id.as_deref().unwrap_or(""),
            process_observation_id = %stamp.process_observation_id,
            event_sequence = stamp.event_sequence,
            wall_unix_ns = %stamp.wall_unix_ns,
            user_id = ?user_id,
            tenant_id = ?tenant_id,
            card_id = ?card_id,
            resource,
            action,
            allowed = decision.allowed,
            reason = %decision.reason,
            "e1 authorization observation"
        );
    }

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
        let audit_request_id = request_id.clone();
        let audit_detail = decision
            .org_provenance
            .as_ref()
            .and_then(|provenance| org_provenance_audit_detail(path, provenance));
        let hit_phase =
            policy_engine::PolicyEngine::allow_source_phase(&decision).map(String::from);
        let pool = state.db.clone();
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
                audit_request_id,
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
        record_authorization_request(
            AuthorizationAdmissionOutcome::RejectedPolicy,
            authorization_started.elapsed(),
        );
        tracing::warn!(
            user_id = ?user_id,
            card_id = ?card_id,
            resource = resource,
            action = action,
            reason = %decision.reason,
            path = path,
            "permission_denied"
        );
        // 统一消息包络：拒绝体必须对牌 ApiResponse JSON 形状（与 handlers 的
        // AppError 渲染同源——403 / PERMISSION_DENIED / reasonCode 由 reason 中
        // 的 DEFAULT_DENY 等稳定码派生）。纯文本 body 曾使远程断言无法对牌
        // （三节点战役 S12/S13 发现）。
        return Err(BoxedResponse::new(
            AppError(AstralError::Permission(format!(
                "Permission denied: {} for {}:{}",
                decision.reason, resource, action
            )))
            .into_response(),
        ));
    }

    // SoD 冲突检查（对齐 Java PermissionAspect → SodService.checkDynamicSoD）。
    // 对组织 ALLOW，先把 PolicyEngine 返回的 provenance 经 context-aware
    // mirrored 装配入口与组织准入证据对牌（复合进程 warm 命中走辅助镜像的
    // strict read contract，零 DB；镜像 miss/pending 回落既有 fresh DB 严格
    // 读），再进入 deny-only 复核；读取、钉栅或匹配失败统一进入 unavailable
    // 分支，绝不把组织持有权限折算为空集。非 ORG 判定走 context-aware 纯
    // deny-only 入口（warm 态同样零 DB；durable 回退与旧路径同语义）。
    if let Some(so_card_id) = card_id {
        let sod_started = Instant::now();
        let sod_result = match load_org_sod_admission_mirrored(&state.db, &ctx, &decision).await {
            Ok(Some(admission)) => {
                check_sod_conflict_with_context_and_org(
                    &state.db,
                    &ctx,
                    &admission,
                    resource_owner_id,
                )
                .await
            }
            Ok(None) => check_sod_conflict_with_context(&state.db, &ctx, resource_owner_id).await,
            Err(error) => Err(error),
        };
        match sod_result {
            Ok(result) if result.has_conflict => {
                record_sod_check(SodCheckOutcome::Conflict, sod_started.elapsed());
                record_authorization_request(
                    AuthorizationAdmissionOutcome::RejectedSod,
                    authorization_started.elapsed(),
                );
                tracing::warn!(
                    card_id = so_card_id,
                    resource = resource,
                    action = action,
                    policy = ?result.conflict_policy,
                    "sod_conflict_denied"
                );
                return Err(BoxedResponse::new(
                    (
                        StatusCode::FORBIDDEN,
                        format!(
                            "SoD conflict: {} holds conflicting permission '{}' per policy '{}'",
                            resource,
                            result.conflict_permission.unwrap_or_default(),
                            result.conflict_policy.unwrap_or_default()
                        ),
                    )
                        .into_response(),
                ));
            }
            Ok(_) => {
                record_sod_check(SodCheckOutcome::Clear, sod_started.elapsed());
            }
            Err(error) => {
                record_sod_check(SodCheckOutcome::Unavailable, sod_started.elapsed());
                record_authorization_request(
                    AuthorizationAdmissionOutcome::RejectedSod,
                    authorization_started.elapsed(),
                );
                tracing::error!(card_id = so_card_id, resource, action, %error, "SoD check unavailable; denying");
                return Err(BoxedResponse::new(
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "SoD check unavailable; request denied".to_string(),
                    )
                        .into_response(),
                ));
            }
        }
    }

    // Compare the original fence after all authority reads. A cold installation
    // can invalidate it; the next request must evaluate from the new baseline.
    if let Some(fence) = admission_fence {
        let fence_holds = astral_db::memory_projection_hub()
            .is_some_and(|hub| hub.authority_fence_matches(fence));
        if !fence_holds {
            record_authorization_request(
                AuthorizationAdmissionOutcome::RejectedContext,
                authorization_started.elapsed(),
            );
            tracing::error!(
                user_id = ?user_id,
                card_id = ?card_id,
                resource = resource,
                action = action,
                path = path,
                "admission fence mismatch: source state changed under an allowed request; denying"
            );
            return Err(BoxedResponse::new(
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "admission fence mismatch; request denied".to_string(),
                )
                    .into_response(),
            ));
        }
    }

    #[cfg(feature = "e1-observability")]
    {
        let stamp = policy_engine::e1_observation::stamp();
        tracing::info!(
            target: "authz_e1",
            event = "host_admission",
            request_id = stamp.request_id.as_deref().unwrap_or(""),
            process_observation_id = %stamp.process_observation_id,
            event_sequence = stamp.event_sequence,
            wall_unix_ns = %stamp.wall_unix_ns,
            user_id = ?user_id,
            tenant_id = ?tenant_id,
            card_id = ?card_id,
            resource,
            action,
            "e1 authorization observation"
        );
    }

    tracing::debug!(
        user_id = ?user_id,
        resource = resource,
        action = action,
        "permission_allowed"
    );

    record_authorization_request(
        AuthorizationAdmissionOutcome::Admitted,
        authorization_started.elapsed(),
    );

    // 将校验后的上下文注入请求扩展，供下游 handler 使用
    req.extensions_mut().insert(ctx);
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::{
        audit_request_id, request_target_id, resolve_trustgraph_permission_action,
        resource_for_path, TRUSTGRAPH_PATH_RESOURCE_MAP,
    };
    use axum::extract::Request;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn canonical_domain_paths_resolve_resource_and_action() {
        let cases = [
            ("/audit-quarantine", "audit_quarantine", "GET", "read"),
            (
                "/audit-quarantine/7/replay",
                "audit_quarantine",
                "POST",
                "replay",
            ),
            ("/arbiter/arbitrate", "monitor", "POST", "arbitrate"),
            ("/arbiter/stats", "monitor", "GET", "read"),
            ("/stats", "monitor", "GET", "read"),
            ("/stats/projector", "monitor", "GET", "read"),
            ("/consistency/report", "monitor", "GET", "read"),
            ("/domains", "domain", "GET", "read"),
            (
                "/resource-types/scan",
                "domain_resource_type",
                "POST",
                "scan",
            ),
            ("/actions/scan/async", "permission_action", "POST", "scan"),
            ("/user-levels/7", "domain", "GET", "read"),
            ("/user-gradings", "domain", "POST", "update"),
            (
                "/level-templates/precheck",
                "permission_rule",
                "POST",
                "read",
            ),
            ("/user-cards/7/bind", "domain", "POST", "update"),
            ("/card-templates/5/rules/batch", "domain", "POST", "create"),
        ];

        for (path, expected_resource, method, expected_action) in cases {
            let resource = resource_for_path(path).expect("canonical path must be mapped");
            assert_eq!(resource, expected_resource, "resource for {path}");
            assert_eq!(
                resolve_trustgraph_permission_action(resource, path, method),
                Some(expected_action),
                "action for {path}"
            );
        }
    }

    fn literal_route_paths(source: &str) -> Vec<&str> {
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        let mut remaining = production;
        let mut paths = Vec::new();
        while let Some(marker) = remaining.find(".route(") {
            let arguments = remaining[marker + ".route(".len()..].trim_start();
            assert!(
                arguments.starts_with('"'),
                "main API route declarations must use a literal path"
            );
            let quoted = &arguments[1..];
            let end = quoted
                .find('"')
                .expect("literal route path must have a closing quote");
            paths.push(&quoted[..end]);
            remaining = &quoted[end + 1..];
        }
        paths
    }

    #[test]
    fn every_registered_main_api_route_has_a_resource_mapping() {
        let route_sources = [
            ("approval", include_str!("approval.rs")),
            ("arbiter", include_str!("arbiter.rs")),
            ("audit", include_str!("audit.rs")),
            ("audit_replay", include_str!("audit_replay.rs")),
            ("card_templates", include_str!("card_templates.rs")),
            (
                "consistency_monitor",
                include_str!("consistency_monitor.rs"),
            ),
            ("cross_org_grants", include_str!("cross_org_grants.rs")),
            ("delegation", include_str!("delegation.rs")),
            ("departments", include_str!("departments.rs")),
            ("domains", include_str!("domains.rs")),
            ("global_admin", include_str!("global_admin.rs")),
            ("inheritance", include_str!("inheritance.rs")),
            ("level_templates", include_str!("level_templates.rs")),
            ("permission_actions", include_str!("permission_actions.rs")),
            (
                "personal_permissions",
                include_str!("personal_permissions.rs"),
            ),
            ("org_authorities", include_str!("org_authorities.rs")),
            ("platform_packages", include_str!("platform_packages.rs")),
            ("resource_types", include_str!("resource_types.rs")),
            ("rule_sets", include_str!("rule_sets.rs")),
            ("rules", include_str!("rules.rs")),
            ("simulation", include_str!("simulation.rs")),
            ("sod", include_str!("sod.rs")),
            ("stats", include_str!("stats.rs")),
            ("templates", include_str!("templates.rs")),
            ("tenants", include_str!("tenants.rs")),
            ("user_cards", include_str!("user_cards.rs")),
            ("user_gradings", include_str!("user_gradings.rs")),
            ("user_levels", include_str!("user_levels.rs")),
        ];
        let mut route_count = 0usize;
        for (module, source) in route_sources {
            for path in literal_route_paths(source) {
                route_count += 1;
                assert!(
                    resource_for_path(path).is_some(),
                    "registered route lacks permission mapping: {module}:{path}"
                );
            }
        }
        assert!(route_count >= 150, "route scan unexpectedly incomplete");

        assert_eq!(
            resource_for_path(crate::api::test_control::TEST_CONTROL_ROUTE),
            Some("monitor")
        );
        let test_control_source = include_str!("test_control.rs");
        let test_control_production = test_control_source
            .split("#[cfg(test)]")
            .next()
            .unwrap_or(test_control_source);
        assert_eq!(test_control_production.matches(".route(").count(), 1);
        assert!(test_control_production.contains(".route(TEST_CONTROL_ROUTE"));
    }

    #[test]
    fn legacy_domain_prefix_is_unknown_and_not_an_alias() {
        assert!(resource_for_path("/domain/domains").is_none());
        assert!(resource_for_path("/domain/user-cards/7/bind").is_none());
        assert!(resource_for_path("/domain/card-templates/5/rules/batch").is_none());
        assert!(TRUSTGRAPH_PATH_RESOURCE_MAP
            .iter()
            .all(|(prefix, _)| !prefix.starts_with("/domain/")));
    }

    #[test]
    fn audit_quarantine_path_mapping_uses_read_and_replay_actions() {
        assert_eq!(
            resource_for_path("/audit-quarantine"),
            Some("audit_quarantine")
        );
        assert_eq!(
            resolve_trustgraph_permission_action("audit_quarantine", "/audit-quarantine", "GET"),
            Some("read")
        );
        assert_eq!(
            resolve_trustgraph_permission_action(
                "audit_quarantine",
                "/audit-quarantine/7/replay",
                "POST",
            ),
            Some("replay")
        );
    }

    #[test]
    fn unknown_methods_never_resolve_to_a_permission_bypass() {
        for method in ["OPTIONS", "TRACE", "CONNECT", "CUSTOM"] {
            assert_eq!(
                resolve_trustgraph_permission_action("monitor", "/stats/projector", method),
                None
            );
        }
    }

    #[test]
    fn audit_request_id_uses_the_durable_canonical_gate() {
        let mut headers = HeaderMap::new();
        assert_eq!(audit_request_id(&headers), None);

        headers.insert(
            "x-request-id",
            HeaderValue::from_static("us27-e1:reader/42"),
        );
        assert_eq!(
            audit_request_id(&headers).as_deref(),
            Some("us27-e1:reader/42")
        );

        headers.insert(
            "x-request-id",
            HeaderValue::from_str(&"x".repeat(65)).expect("ASCII header"),
        );
        assert_eq!(audit_request_id(&headers), None);

        headers.insert("x-request-id", HeaderValue::from_static("unsafe request"));
        assert_eq!(audit_request_id(&headers), None);
    }

    #[test]
    fn object_id_query_uses_the_shared_explicit_key_grammar() {
        use axum::body::Body;
        let request = |query: &str| {
            Request::builder()
                .uri(format!("/permission-rules/check?{query}"))
                .body(Body::empty())
                .unwrap()
        };

        assert_eq!(request_target_id(&request("target_id=11")), Some(11));
        assert_eq!(request_target_id(&request("resource_id=12")), Some(12));
        assert_eq!(request_target_id(&request("id=13")), Some(13));
        assert_eq!(request_target_id(&request("card_id=14")), Some(14));
        assert_eq!(request_target_id(&request("targetId=15")), Some(15));
        assert_eq!(request_target_id(&request("resourceId=16")), Some(16));
        assert_eq!(request_target_id(&request("cardId=17")), Some(17));
    }

    #[test]
    fn object_id_query_rejects_malformed_and_pins_conflict_semantics() {
        use axum::body::Body;
        let request = |query: &str| {
            Request::builder()
                .uri(format!("/permission-rules/check?{query}"))
                .body(Body::empty())
                .unwrap()
        };

        // 非正数、溢出、非数字、空值一律忽略（无对象级目标 → 不做对象级判定）。
        assert_eq!(request_target_id(&request("id=0")), None);
        assert_eq!(request_target_id(&request("id=-3")), None);
        assert_eq!(request_target_id(&request("id=99999999999999999999")), None);
        assert_eq!(request_target_id(&request("id=i64max+1")), None);
        assert_eq!(request_target_id(&request("id=abc")), None);
        assert_eq!(request_target_id(&request("id=")), None);

        // 重复/冲突键：首个匹配键确定性生效，不静默合并、不取最大值。
        assert_eq!(request_target_id(&request("id=5&id=7")), Some(5));
        assert_eq!(
            request_target_id(&request("target_id=5&card_id=7")),
            Some(5)
        );
        assert_eq!(
            request_target_id(&request("card_id=7&target_id=5")),
            Some(7)
        );
        assert_eq!(request_target_id(&request("junk=1&target_id=9")), Some(9));
    }

    #[test]
    fn every_mapped_resource_is_registered_and_grantable() {
        // 路径映射里的每个资源必须在 ResourceRegistry 注册，且至少可被
        // `read` 规则授予（否则该路由的所有 GET 会结构性不可授予）。
        use astral_types::ResourceRegistry;
        let registry = ResourceRegistry::global();
        for (prefix, resource) in TRUSTGRAPH_PATH_RESOURCE_MAP {
            assert!(
                registry.validate(resource, "read").is_ok(),
                "mapped path {prefix} references resource `{resource}` that is not registered with a `read` action"
            );
        }
        // trustgraph 特例动作必须是一等注册动作（registry-first 合同）。
        assert!(registry.validate("audit_quarantine", "replay").is_ok());
        assert!(registry.validate("monitor", "arbitrate").is_ok());
    }

    /// 宿主 SoD 分发与准入栅栏形状守卫（对齐 sod_check 的源文本守卫惯例）：
    /// ORG provenance 判定必须先经 context-aware mirrored 装配
    /// （`load_org_sod_admission_mirrored`），再进入
    /// `check_sod_conflict_with_org` deny-only 复核；无 provenance 时走
    /// context-aware 纯 deny-only 入口（`check_sod_conflict_with_context`）。
    /// 准入栅栏必须在**一切权威读取之前**捕获（先于
    /// `resolve_resource_ownership` 与引擎评估），hub 已安装而栅栏不可得
    /// （capture None）必须立即 503 拒绝（绝不无栅栏放行），并在 SoD 之后、
    /// admit 之前最终复核（`authority_fence_matches`）——覆盖
    /// evaluate/ownership/SoD 全窗口。审计 detail 必须经 shared 有界
    /// provenance helper 并通过显式 detail 审计入口传播。本地不再保留任何
    /// 重复 helper 定义。
    #[test]
    fn sod_dispatch_wires_org_provenance_to_fresh_admission_recheck() {
        let source = include_str!("permission_check.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        let fence_capture = production
            .find("capture_authority_fence")
            .expect("host must capture the opaque admission fence before authorization");
        let ownership = production
            .find("resolve_resource_ownership(")
            .expect("ownership resolution must exist after the fence capture");
        let loader = production
            .find("load_org_sod_admission_mirrored(&state.db, &ctx, &decision)")
            .expect("org dispatch must assemble admission via the mirrored context-aware helper");
        let with_org = production
            .find("check_sod_conflict_with_context_and_org(")
            .expect("org admission must recheck via the canonical context-aware and_org entry");
        let plain = production
            .find("check_sod_conflict_with_context(&state.db, &ctx, resource_owner_id)")
            .expect("non-org decisions must keep the context-aware deny-only SoD check");
        let fence_recheck = production
            .find("authority_fence_matches")
            .expect("host must recheck the admission fence before admitting");
        assert!(
            fence_capture < ownership,
            "the fence must be captured before ANY authority read (ownership resolution included)"
        );
        assert!(
            ownership < loader && loader < with_org && with_org < plain,
            "dispatch order must be ownership -> mirrored loader -> with_org -> context-aware plain"
        );
        assert!(
            plain < fence_recheck,
            "the fence recheck must run after the whole SoD window, before admission"
        );
        // hub 已安装而栅栏不可得（capture None）→ 立即 503 fail-closed。
        assert!(
            production.contains("admission fence unavailable"),
            "a missing fence on an installed hub must be rejected immediately"
        );
        assert!(
            !production.contains("fn org_provenance_audit_detail"),
            "the bounded provenance detail helper must come from astral_common::audit"
        );
        assert!(
            !production.contains("fn org_sod_admission"),
            "the admission loader must come from astral_db"
        );
        assert!(production.contains("org_provenance_audit_detail(path, provenance)"));
        assert!(production.contains("record_permission_audit_with_request_detail("));
        // 不允许把可伪造的 u64 计数器当栅栏：复核必须走 opaque AuthorityReadFence。
        assert!(
            !production.contains("admission_epoch") && !production.contains("fence_counter"),
            "admission fence must stay opaque (AuthorityReadFence), not a raw counter"
        );
        // 栅栏 token 只允许在一切权威读取之前**捕获一次**；末尾复核只比较已
        // 捕获栅栏——不存在"重新采样 token 覆盖旧读"的放行路径。
        assert_eq!(
            production.matches("capture_authority_fence").count(),
            1,
            "the admission fence must be captured exactly once, before authority reads"
        );
        // 漂移分支是安全 Pending（503 可重试），绝不折算成放行（栅栏块内
        // 不出现 Admitted；真正的 Admitted 记录在栅栏复核通过之后）。
        let fence_block_end = production[fence_recheck..]
            .find("host_admission")
            .map_or(production.len(), |index| fence_recheck + index);
        let mismatch_branch = &production[fence_recheck..fence_block_end];
        assert!(
            mismatch_branch.contains("SERVICE_UNAVAILABLE"),
            "a fence mismatch must be a retryable 503 safe-pending, not an admission"
        );
        assert!(
            !mismatch_branch.contains("AuthorizationAdmissionOutcome::Admitted"),
            "no admission may be recorded inside or after a failed fence recheck"
        );
    }
}
