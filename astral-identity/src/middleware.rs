//! Identity 权限检查中间件
//!
//! 对齐 TrustGraph 的 `permission_check.rs` 模式。

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use astral_common::audit::org_provenance_audit_detail;
use astral_common::middleware::ip_rate_limit::{
    rate_limit_response, resolve_client_ip, IpRateLimiter, TrustedProxySet,
};
use astral_common::middleware::permission_check_shared::{
    physical_policy_context, request_target_id, resolve_permission_action, BoxedResponse,
    PathResourceMap,
};
use astral_common::token_contract::PrincipalKind;
use astral_db::{
    check_sod_conflict_with_context, check_sod_conflict_with_context_and_org,
    load_org_sod_admission_mirrored, resolve_resource_ownership, AuthorityReadFence,
    SqlxRuleRepository,
};

use crate::AppState;

pub const IDENTITY_PATH_MAP: PathResourceMap = &[
    ("/integrations/identity-mappings", "authorization"),
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
    ("/profile", "identity_users"),
    ("/change-password", "identity_users"),
    ("/password", "identity_users"),
    ("/admin", "identity_users"),
    ("/verification", "identity_users"),
    ("/orgs", "organization"),
    ("/domains", "domain"),
    ("/tenants", "platform_tenant"),
    ("/me", "identity_users"),
    ("/mfa", "identity_users"),
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
    // 自服务路径（仅需有效 JWT，不需要权限规则检查）
    "/me",
    "/providers",
    "/sessions/switch-card",
];

pub async fn identity_permission_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, BoxedResponse> {
    let request_path = req.uri().path().to_owned();
    let path = request_path.as_str();
    let method = req.method().clone();

    if is_identity_skip_path(path) {
        if is_credential_bootstrap_path(path) {
            // Scope exception：bootstrap/公开路径无 policy 判定、无授权读取
            // 依赖，不取宿主准入栅栏。
            return Ok(next.run(req).await);
        }
        // 自服务严格校验（活动身份/卡上下文验证 = 权威读取）同样持宿主准入
        // 栅栏：读取之前捕获，验证窗口之后复核漂移。
        let admission_fence = capture_identity_admission_fence()?;
        let ctx = physical_policy_context(
            req.headers(),
            "identity_users",
            "read",
            request_target_id(&req),
        )
        .map_err(|status| BoxedResponse::new(status.into_response()))?;
        require_platform_user(&ctx)?;
        verify_active_identity_context(&state, &ctx).await?;
        if ctx.principal_kind.as_deref().and_then(PrincipalKind::parse)
            == Some(PrincipalKind::PlatformUser)
        {
            verify_active_card_context(
                &state,
                ctx.card_id,
                ctx.user_id,
                ctx.tenant_id,
                ctx.domain_id,
            )
            .await?;
        }
        verify_identity_admission_fence(admission_fence)?;
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

    // 宿主准入栅栏：在**一切权威读取之前**（ownership 解析、引擎评估、SoD
    // 均在其后）捕获 hub 严格读 token 的 opaque 快照。hub 已安装而栅栏不可得
    // （writer-active / source outcome unknown / worker 失效旗标）→ 立即 503
    // fail-closed：本宿主绝不以"无栅栏"状态消费任何授权读取。
    let admission_fence = capture_identity_admission_fence()?;

    let query_target_id = request_target_id(&req);
    let mut ctx = physical_policy_context(req.headers(), resource, action, query_target_id)
        .map_err(|status| BoxedResponse::new(status.into_response()))?;
    require_platform_user(&ctx)?;
    ctx.request_operation_id = Some(
        astral_common::middleware::request_binding::request_operation_id(&req)
            .map_err(|status| BoxedResponse::new(status.into_response()))?,
    );
    ctx.request_fingerprint = Some(
        astral_common::middleware::request_binding::bind_http_request(&mut req)
            .await
            .map_err(|status| BoxedResponse::new(status.into_response()))?,
    );
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
    //
    // 单机内存镜像读面（default-off）：组合进程安装
    // astral_db::memory_projection_hub 后命中镜像，pending/未预热回退 DB。
    let evaluation = if astral_db::memory_mirror_is_installed() {
        let repo = astral_db::MemoryMirroredRuleRepository::new(
            SqlxRuleRepository::new(state.db.clone())
                .with_org_scope_enabled(state.org_scope_enabled)
                .with_authority_provider_opt(state.authorization_fence_provider.clone())
                .with_authority_required(state.config.authority_runtime_mode.requires_authority()),
        )
        // Mirror hits are admissible only when the same configured trust-root
        // verifier is present; otherwise this remains durable-only.
        .with_authority_provider_opt(
            state
                .authorization_fence_provider
                .clone()
                .map(|provider| provider as Arc<dyn policy_engine::AuthorizationFenceProvider>),
        )
        // 镜像 miss 时回填 strict durable bundle（MySQL 直读），
        // 与 hub strict_refill 契约一致；读取失败按既有 pending/DB 回退语义处理。
        .with_durable_refill(state.db.clone());
        state.engine.evaluate_with_admission(&ctx, &repo).await
    } else {
        let repo = SqlxRuleRepository::new(state.db.clone())
            .with_org_scope_enabled(state.org_scope_enabled)
            .with_authority_provider_opt(state.authorization_fence_provider.clone())
            .with_authority_required(state.config.authority_runtime_mode.requires_authority());
        state.engine.evaluate_with_admission(&ctx, &repo).await
    };
    let (decision, authorization_admission) = evaluation.into_parts();

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
        if let Err(reason) = astral_common::audit::spawn_owned_audit(async move {
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
        }) {
            tracing::error!(reason, "policy audit task was not admitted");
        }
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
        // 对组织 ALLOW，先把 PolicyEngine 返回的 provenance 经 context-aware
        // mirrored 装配入口与组织准入证据对牌（复合进程 warm 命中走辅助镜像
        // strict read contract，零 DB；镜像 miss/pending 回落既有 fresh DB
        // 严格读），再进入 deny-only 复核；读取、钉栅或匹配失败统一进入
        // unavailable 分支，绝不把组织持有权限折算为空集。非 ORG 判定走
        // context-aware 纯 deny-only 入口（warm 态零 DB；durable 回退与既有
        // 纯 deny-only 检查同语义）。
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

    // 宿主最终同 token 复核（admission fence recheck）：覆盖 evaluate、
    // ownership 解析与 SoD 的全部读取窗口。栅栏漂移 → 503 安全 Pending
    // （可重试：重试请求以新基线重新捕获并重新评估）；只比较已捕获栅栏，
    // 绝不重采新 token 覆盖旧读，绝不折算成放行。
    verify_identity_admission_fence(admission_fence)?;

    let source_abort = if !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") {
        let provider = state
            .authorization_fence_provider
            .as_ref()
            .ok_or_else(|| BoxedResponse::new(StatusCode::SERVICE_UNAVAILABLE.into_response()))?;
        let admission = authorization_admission
            .as_ref()
            .ok_or_else(|| BoxedResponse::new(StatusCode::SERVICE_UNAVAILABLE.into_response()))?;
        let abort = provider
            .reserve_mutation_with_abort(&ctx, admission)
            .await
            .map_err(|_| BoxedResponse::new(StatusCode::SERVICE_UNAVAILABLE.into_response()))?;
        Some((provider.clone(), abort))
    } else {
        None
    };
    req.extensions_mut().insert(ctx);
    if let Some(authorization_admission) = authorization_admission {
        req.extensions_mut().insert(authorization_admission);
    }

    let response = next.run(req).await;
    if let Some((provider, abort)) = source_abort {
        if let Err(error) = provider.abort_source_reservation(&abort).await {
            tracing::warn!(operation_id = %abort.operation_id, reservation_id = %abort.reservation_id, error = %error, "identity post-handler source abort remains unknown; stable identity recovery required");
        }
    }
    Ok(response)
}

/// Identity 宿主准入栅栏捕获：在**一切权威读取之前**调用（管理路由的
/// ownership/引擎评估/SoD，以及自服务严格校验的活动上下文验证）。委托
/// canonical `MemoryProjectionHub::capture_authority_fence`（opaque
/// AuthorityReadFence，token 不外露、不可伪造；default-off：hub 未安装 →
/// `Ok(None)`，非 composite 维持既有安全包络）。hub 已安装而栅栏不可得
/// （writer-active / source outcome unknown / worker 失效旗标）→ `Err`
/// 503 fail-closed——本宿主绝不以"无栅栏"状态消费任何授权读取，也绝不
/// 允许 None 静默放行。bootstrap/公开路径（无 policy 判定）为 scope
/// exception，不取栅栏。
fn capture_identity_admission_fence() -> Result<Option<AuthorityReadFence>, BoxedResponse> {
    match astral_db::memory_projection_hub() {
        None => Ok(None),
        Some(hub) => hub.capture_authority_fence().map(Some).ok_or_else(|| {
            tracing::error!(
                "admission fence unavailable: source writer active or outcome unknown; denying"
            );
            BoxedResponse::new(
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "admission fence unavailable; request denied",
                )
                    .into_response(),
            )
        }),
    }
}

/// 栅栏终检（admission fence recheck）：只比较已捕获栅栏——绝不重采新
/// token 覆盖旧读；漂移 → 503 安全 Pending（客户端重试即可，重试以新基线
/// 重新捕获并以新事实重新评估），绝不折算成放行。
fn verify_identity_admission_fence(fence: Option<AuthorityReadFence>) -> Result<(), BoxedResponse> {
    let Some(fence) = fence else {
        return Ok(());
    };
    let holds =
        astral_db::memory_projection_hub().is_some_and(|hub| hub.authority_fence_matches(fence));
    if !holds {
        tracing::error!(
            "admission fence mismatch: source state changed under a verified request; denying"
        );
        return Err(BoxedResponse::new(
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "admission fence mismatch; request denied",
            )
                .into_response(),
        ));
    }
    Ok(())
}

/// Verification 路由的进程内 per-IP 限流（Identity 直连监听器防护）。
///
/// ## 共享实现（本模块不重复实现计数器）
///
/// 计数核心、受信代理匹配与客户端 IP 解析复用
/// `astral_common::middleware::ip_rate_limit`（`IpRateLimiter` /
/// `TrustedProxySet` / `resolve_client_ip`），与 Gateway `rate_limit` 中间件
/// 同源：共享 `astral_common::config::RateLimitCfg` 合同（1s 固定窗口，cap =
/// `requests_per_second + burst_size` 饱和加法，enabled=false 时放行），bucket
/// 携带 last_seen、TTL+GC 回收空闲桶并有硬容量上限（容量耗尽时新 key
/// fail-closed，绝不静默接纳）；客户端 IP 只信任来自
/// `config.gateway.trusted_proxy_ips` 配置代理的 `X-Forwarded-For` /
/// `X-Real-IP`（XFF 链内取从右向左第一个非受信地址），否则回退 TCP 对端地址
/// （`ConnectInfo` 扩展，由直连监听器 `into_make_service_with_connect_info`
/// 注入；缺失时聚合到 `None` 单桶，绝不因缺扩展而 panic 或放行）。非法受信
/// 代理条目解析期丢弃并告警（fail-closed），非法转发头不产出桶 key。
///
/// ## 已知边界（刻意保留，不发明跨副本限流）
///
/// 计数状态是单副本进程内的：跨副本不做强一致，攻击预算按副本数线性放大。
/// 当前部署中没有任何组件提供跨副本全局预算——Gateway 的 `rate_limit` 中间件
/// 同样是进程内本地限流，不构成全局预算；真正的跨副本持久化配额属独立任务
/// （落地前不生效）。经 Gateway 转发的请求若 Gateway 对端不在
/// trusted_proxy_ips（且 Gateway 未注入 XFF），将共享 Gateway 对端地址的
/// 单个桶（聚合边界）；直连流量按真实对端 IP 分桶。本限流只做可用性保护：
/// 不产生 `AuthorizationAdmission`、不读取/消费宿主准入栅栏，bootstrap 路由
/// 保持 admission-free 语义不变。
struct VerificationRateLimit {
    limiter: IpRateLimiter,
    trusted: TrustedProxySet,
}

static VERIFICATION_IP_LIMITER: OnceLock<VerificationRateLimit> = OnceLock::new();

/// Identity 直连监听器上 verification 路由的 per-IP 限流入口（仅挂在
/// `/verification/send` 与 `/verification/verify` 两个路由上，见 runtime
/// 装配；不产生 AuthorizationAdmission、不消费准入栅栏）。
pub async fn verification_ip_rate_limit(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    // 配置来自首个请求的启动期冻结 AppConfig（对齐 Gateway 注入模式）。
    let shared = VERIFICATION_IP_LIMITER.get_or_init(|| {
        let trusted = TrustedProxySet::compile(&state.config.gateway.trusted_proxy_ips);
        for entry in trusted.invalid_entries() {
            tracing::warn!(
                entry = %entry,
                "invalid gateway.trusted_proxy_ips entry; ignored (fail closed to peer address)"
            );
        }
        VerificationRateLimit {
            limiter: IpRateLimiter::new(state.config.rate_limit.clone()),
            trusted,
        }
    });
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connect_info| connect_info.0.ip());
    let client = resolve_client_ip(req.headers(), peer, &shared.trusted);
    if !shared.limiter.check(client) {
        tracing::warn!(client = ?client, path = req.uri().path(), "verification rate limit exceeded");
        return rate_limit_response(&req, "verification-rate-limit-error");
    }
    next.run(req).await
}

fn require_platform_user(ctx: &astral_types::PolicyContext) -> Result<(), BoxedResponse> {
    if ctx.principal_kind.as_deref().and_then(PrincipalKind::parse)
        == Some(PrincipalKind::PlatformUser)
    {
        return Ok(());
    }

    Err(BoxedResponse::new(
        (
            StatusCode::FORBIDDEN,
            "Identity service requires a platform user principal",
        )
            .into_response(),
    ))
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
        assert!(!is_identity_skip_path("/profile"));
        assert!(!is_identity_skip_path("/change-password"));
        assert!(!is_identity_skip_path("/profile/extra"));
        assert!(!is_identity_skip_path("/profile-extra"));
        assert!(!is_identity_skip_path("/change-password-extra"));
        assert!(!is_identity_skip_path("/users"));
        assert!(!is_identity_skip_path("/users/7/password"));
        assert!(!is_credential_bootstrap_path("/users/7/password"));
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
    /// ORG provenance 判定必须先经 context-aware mirrored 准入装配
    /// （`load_org_sod_admission_mirrored`）再进入 `check_sod_conflict_with_org`
    /// deny-only 复核；无 provenance 时走 context-aware 纯 deny-only 入口
    /// （`check_sod_conflict_with_context`）；审计 detail 必须经 shared 有界
    /// provenance helper 并通过显式 detail 审计入口传播。本地不得重新引入
    /// 任何重复 helper 定义。
    #[test]
    fn sod_dispatch_wires_org_provenance_to_fresh_admission_recheck() {
        let source = include_str!("middleware.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        let fence_capture = production
            .find("capture_identity_admission_fence()")
            .expect("host must capture the opaque admission fence before authority reads");
        let ownership = production
            .find("resolve_resource_ownership(")
            .expect("management-route ownership resolution must exist");
        let self_verify = production
            .find("verify_active_identity_context(&state, &ctx)")
            .expect("self-service strict context verification must exist");
        assert!(
            fence_capture < self_verify,
            "self-service strict checks must run after the fence capture"
        );
        // 管理路由路径同样在 ownership 之前捕获（共享 helper 的第二次调用）。
        let management_capture = production[fence_capture + 1..]
            .find("capture_identity_admission_fence()")
            .map_or(production.len(), |index| fence_capture + 1 + index);
        assert!(
            management_capture < ownership,
            "management-route authority reads must run after the fence capture"
        );
        let loader = production
            .find("load_org_sod_admission_mirrored(&state.db, &ctx, &decision)")
            .expect("org dispatch must assemble admission via the mirrored context-aware helper");
        let with_org = production
            .find("check_sod_conflict_with_context_and_org(")
            .expect("org admission must recheck via the canonical context-aware and_org entry");
        let plain = production
            .find("check_sod_conflict_with_context(&state.db, &ctx, resource_owner_id)")
            .expect("non-org decisions must keep the context-aware deny-only SoD check");
        // 两条受保护路径各有终检（自服务严格校验 + 管理路由 SoD 之后）；
        // 管理路由的终检必须在整个 SoD 窗口之后。
        assert!(loader < with_org && with_org < plain);
        let recheck_calls: Vec<usize> = production
            .match_indices("verify_identity_admission_fence(admission_fence)")
            .map(|(index, _)| index)
            .collect();
        assert_eq!(
            recheck_calls.len(),
            2,
            "both protected paths (self-service strict checks and management routes) must recheck the fence"
        );
        let fence_recheck = recheck_calls[1];
        assert!(
            plain < fence_recheck,
            "the management-route fence recheck must run after the whole SoD window, before admission"
        );
        // hub 已安装而栅栏不可得（capture None）→ 立即 503 fail-closed；
        // 漂移分支同样 503 安全 Pending——绝不折算成放行。
        assert!(
            production.contains("admission fence unavailable")
                && production.contains("admission fence mismatch"),
            "missing-fence and fence-mismatch states must both be rejected with a stable 503"
        );
        // 栅栏 token 只允许在权威读取之前捕获一次（共享 helper，单点采样；
        // 按 `.capture_authority_fence()` 调用点计数，文档引用不计入）；
        // 终检只比较已捕获栅栏，不存在"重新采样 token 覆盖旧读"的放行路径。
        assert_eq!(
            production.matches(".capture_authority_fence()").count(),
            1,
            "the admission fence must be captured exactly once via the shared helper"
        );
        assert!(
            !production.contains("fn org_provenance_audit_detail"),
            "the bounded provenance detail helper must come from astral_common::audit"
        );
        assert!(production.contains("org_provenance_audit_detail(path, provenance)"));
        assert!(production.contains("record_permission_audit_with_request_detail("));
    }

    /// Verification 路由 IP 限流的装配形状守卫：Identity 直连监听器必须给
    /// verification 路由接线进程内 per-IP 限流，serve 必须注入 ConnectInfo
    /// （对端地址回退）；限流语义必须复用共享
    /// `astral_common::middleware::ip_rate_limit` 实现（与 Gateway 同源），
    /// 本模块不得重新实现桶计数，且不得消费准入栅栏或产生
    /// AuthorizationAdmission（bootstrap 路由保持 admission-free）。仅扫描
    /// 生产区域，避免测试自引用。
    #[test]
    fn verification_ip_limit_wiring_contract() {
        let middleware_source = include_str!("middleware.rs");
        let runtime_source = include_str!("runtime.rs");
        let middleware_production = middleware_source
            .split("#[cfg(test)]")
            .next()
            .unwrap_or(middleware_source);
        let runtime_production = runtime_source
            .split("#[cfg(test)]")
            .next()
            .unwrap_or(runtime_source);

        // 运行时装配：verification 子路由以 route_layer 挂 per-IP 限流中间件
        // （仅命中路由时消耗预算）；直连监听器注入对端地址扩展。装配点必须
        // 出现在限流入口引用之前。
        let wiring_site = runtime_production
            .find("verification_routes()")
            .expect("the runtime must merge the verification routes");
        assert!(
            runtime_production.contains("verification_routes().route_layer("),
            "the IP limiter must ride a route_layer on the verification subrouter"
        );
        assert!(
            runtime_production[wiring_site..].contains("middleware::verification_ip_rate_limit"),
            "the verification subrouter must be wired to middleware::verification_ip_rate_limit"
        );
        assert!(
            runtime_production
                .contains("into_make_service_with_connect_info::<std::net::SocketAddr>()"),
            "the direct listener must provide ConnectInfo so the limiter can resolve the peer address"
        );

        // 语义复用：计数核心、受信代理匹配与客户端 IP 解析必须来自共享
        // `astral_common::middleware::ip_rate_limit`（与 Gateway 同源），本模块
        // 不得重新实现桶计数；进程内单例 + 共享有界 429 形状；跨副本限制
        // 刻意保留（见模块文档）。
        assert!(
            middleware_production.contains("astral_common::middleware::ip_rate_limit"),
            "the limiter must delegate to the shared ip_rate_limit implementation"
        );
        assert!(
            middleware_production.contains("IpRateLimiter::new(")
                && middleware_production.contains("TrustedProxySet::compile(")
                && middleware_production.contains("resolve_client_ip("),
            "the shared counter, trusted-proxy matching and client resolution must be wired"
        );
        assert!(middleware_production.contains("VERIFICATION_IP_LIMITER"));
        assert!(
            !middleware_production.contains("buckets.lock()"),
            "the local middleware must not re-implement bucket counting (shared IpRateLimiter owns it)"
        );

        // 限流是可用性保护：不消费准入栅栏（全模块仍只有权限中间件那一处
        // capture），不产生/插入 AuthorizationAdmission，429 走有界共享形状。
        assert_eq!(
            middleware_production
                .matches(".capture_authority_fence()")
                .count(),
            1,
            "the IP limiter must not capture the admission fence"
        );
        let limiter_start = middleware_production
            .find("pub async fn verification_ip_rate_limit(")
            .expect("the limiter entry point must remain");
        let limiter_end = middleware_production[limiter_start..]
            .find("fn require_platform_user(")
            .map(|offset| limiter_start + offset)
            .unwrap_or(middleware_production.len());
        let limiter_body = &middleware_production[limiter_start..limiter_end];
        assert!(
            !limiter_body.contains("AuthorizationAdmission"),
            "the IP limiter is availability protection only and must stay admission-free"
        );
        assert!(
            limiter_body.contains("rate_limit_response(&req, \"verification-rate-limit-error\")"),
            "rejected requests must use the shared bounded 429 shape with the verification trace prefix"
        );
    }
}
