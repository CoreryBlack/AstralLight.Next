//! Identity 权限检查中间件
//!
//! 对齐 TrustGraph 的 `permission_check.rs` 模式。

use std::net::SocketAddr;
use std::sync::OnceLock;

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
use astral_db::AuthorityReadFence;

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
    // 认证入口（无 JWT 时可访问，路径已剥离 /api/v1/auth 前缀）。
    "/sessions",
    "/sessions/refresh",
    "/sessions/switch-card",
    "/sessions/logout",
    "/sessions/revoke",
    "/register",
    "/password/forgot",
    "/verification/send",
    "/verification/verify",
];

pub async fn identity_permission_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, BoxedResponse> {
    let request_path = req.uri().path().to_owned();
    let path = request_path.as_str();
    let method = req.method().clone();

    if matches!(
        identity_skip_kind(method.as_str(), path),
        Some(IdentitySkipKind::CredentialBootstrap)
    ) {
        // Scope exception：bootstrap/公开路径无 policy 判定、无授权读取
        // 依赖，不取宿主准入栅栏。
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
        None => {
            return Err(BoxedResponse::new(
                (
                    StatusCode::FORBIDDEN,
                    format!("No permission action mapping for identity route: {method} {path}"),
                )
                    .into_response(),
            ));
        }
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
    let read_surface = astral_db::authorization_read_surface()
        .ok_or_else(|| BoxedResponse::new(StatusCode::SERVICE_UNAVAILABLE.into_response()))?;
    // Request handle 绑定同一个 startup-frozen read surface；CertifiedMemory 请求在此
    // 取得单次 token，Durable/Mirror 保持无 token 语义。
    let request = read_surface
        .begin_request()
        .map_err(|_| BoxedResponse::new(StatusCode::SERVICE_UNAVAILABLE.into_response()))?;
    let resolution = request
        .resolve_ownership(
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

    let evaluation = request.evaluate_with_admission(&state.engine, &ctx).await;
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
        let sod_result = request.check_sod(&ctx, &decision).await;
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
    request
        .ensure_current()
        .map_err(|_| BoxedResponse::new(StatusCode::SERVICE_UNAVAILABLE.into_response()))?;
    verify_identity_admission_fence(admission_fence)?;

    let source_abort = if !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") {
        request
            .ensure_mutation_commit_fence()
            .map_err(|_| BoxedResponse::new(StatusCode::SERVICE_UNAVAILABLE.into_response()))?;
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
    if let Some((provider, abort)) = &source_abort {
        if request.ensure_current().is_err()
            || verify_identity_admission_fence(admission_fence).is_err()
        {
            match provider.abort_source_reservation(abort).await {
                Ok(report) => {
                    tracing::warn!(operation_id = %abort.operation_id, reservation_id = %abort.reservation_id, proof_id = %abort.proof_id, outcome = ?report.outcome, "identity pre-handler fence changed; source abort result")
                }
                Err(error) => {
                    tracing::warn!(operation_id = %abort.operation_id, reservation_id = %abort.reservation_id, proof_id = %abort.proof_id, %error, "identity pre-handler fence changed; source abort remains unknown")
                }
            }
            return Err(BoxedResponse::new(
                StatusCode::SERVICE_UNAVAILABLE.into_response(),
            ));
        }
    }
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

fn identity_skip_kind(method: &str, path: &str) -> Option<IdentitySkipKind> {
    is_credential_bootstrap_path(path)
        .then_some(())
        .and_then(|()| (method == "POST").then_some(IdentitySkipKind::CredentialBootstrap))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentitySkipKind {
    CredentialBootstrap,
}

fn is_identity_skip_path(path: &str) -> bool {
    IDENTITY_SKIP_PATHS.contains(&path)
        || path
            .strip_prefix("/password/reset/")
            .is_some_and(|token| !token.is_empty() && !token.contains('/'))
}

fn is_credential_bootstrap_path(path: &str) -> bool {
    is_identity_skip_path(path)
}

#[cfg(test)]
mod tests {
    use super::{
        identity_skip_kind, is_credential_bootstrap_path, is_identity_skip_path, IdentitySkipKind,
    };
    use astral_common::middleware::permission_check_shared::resolve_permission_action;

    #[test]
    fn skip_routes_require_registered_methods() {
        assert_eq!(
            identity_skip_kind("POST", "/sessions"),
            Some(IdentitySkipKind::CredentialBootstrap)
        );
        assert_eq!(
            identity_skip_kind("POST", "/password/reset/token"),
            Some(IdentitySkipKind::CredentialBootstrap)
        );
        assert_eq!(identity_skip_kind("OPTIONS", "/sessions"), None);
        assert_eq!(identity_skip_kind("GET", "/sessions"), None);
        assert_eq!(identity_skip_kind("POST", "/providers"), None);
        assert_eq!(identity_skip_kind("GET", "/providers"), None);
        assert_eq!(identity_skip_kind("GET", "/me"), None);
    }

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
    fn unknown_identity_action_is_not_a_handler_bypass() {
        assert_eq!(
            resolve_permission_action("identity_users", "/users/7/password", "OPTIONS"),
            None
        );
        let source = include_str!("middleware.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        let action_branch = production
            .split("let action = match resolve_permission_action")
            .nth(1)
            .expect("identity middleware must resolve an action before evaluation");
        let action_branch = action_branch
            .split("// 宿主准入栅栏")
            .next()
            .expect("identity action branch must precede the admission fence");
        assert!(
            action_branch.contains("StatusCode::FORBIDDEN"),
            "unknown identity actions must return a stable refusal"
        );
        assert!(
            !action_branch.contains("next.run(req).await"),
            "unknown identity actions must not reach a handler"
        );
    }

    #[test]
    fn credential_bootstrap_paths_are_exact_or_single_token() {
        assert!(is_credential_bootstrap_path("/password/reset/token"));
        assert!(!is_credential_bootstrap_path("/password/reset"));
        assert!(!is_credential_bootstrap_path("/password/reset-extra"));
        assert!(!is_credential_bootstrap_path("/password/reset/token/extra"));
        assert!(!is_credential_bootstrap_path("/register/status"));
        assert!(!is_credential_bootstrap_path("/sessions/refresh/extra"));
        assert!(!is_credential_bootstrap_path("/verification/send/extra"));
        assert!(!is_credential_bootstrap_path("/mfa/status"));
        assert!(!is_identity_skip_path("/mfa/status"));
    }

    #[test]
    fn self_service_routes_do_not_bypass_policy_evaluation() {
        assert!(!is_identity_skip_path("/me"));
        assert!(!is_identity_skip_path("/me/cards"));
        assert!(!is_identity_skip_path("/me/permissions"));
        assert!(!is_identity_skip_path("/me/cards/7"));
        assert!(!is_identity_skip_path("/providers"));
        assert!(!is_identity_skip_path("/providers/oidc"));
    }

    /// 所有受保护路径共用请求句柄，ownership、规则评估和 SoD 后复核栅栏。
    #[test]
    fn sod_dispatch_wires_org_provenance_to_fresh_admission_recheck() {
        let source = include_str!("middleware.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        let fence_capture = production
            .find("capture_identity_admission_fence()")
            .expect("host must capture the opaque admission fence before authority reads");
        let ownership = production
            .find(".resolve_ownership(")
            .expect("protected routes must resolve ownership");
        let evaluation = production
            .find(".evaluate_with_admission(&state.engine, &ctx)")
            .expect("protected routes must evaluate the policy");
        assert!(fence_capture < ownership && ownership < evaluation);
        let sod_dispatch = production
            .find("request.check_sod(&ctx, &decision)")
            .expect("protected routes must use the request-bound SoD check");
        assert!(
            !production.contains("load_org_sod_admission_mirrored(")
                && !production.contains("check_sod_conflict_with_context_and_org(")
                && !production.contains("check_sod_conflict_with_context(&state.db"),
            "host middleware must not bypass the frozen read surface with durable SoD helpers"
        );
        assert!(evaluation < sod_dispatch);
        let token_recheck = production
            .find(".ensure_current()")
            .expect("the request token must be rechecked before admission");
        let fence_recheck = production
            .find("verify_identity_admission_fence(admission_fence)")
            .expect("the captured admission fence must be rechecked");
        assert!(sod_dispatch < token_recheck && token_recheck < fence_recheck);
        let mutation_gate = production.find(".ensure_mutation_commit_fence()").unwrap();
        let reservation = production
            .find(".reserve_mutation_with_abort(&ctx, admission)")
            .unwrap();
        assert!(mutation_gate < reservation);
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
