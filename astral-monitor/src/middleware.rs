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

use crate::AppState;

/// 注意：路由通过 `.nest("/api/v1/monitor", ...)` 注册，
/// axum 会自动剥离 `/api/v1/monitor` 前缀，因此中间件收到的路径不包含此前缀。
pub const MONITOR_PATH_MAP: PathResourceMap = &[
    ("/alerts", "monitor"),
    ("/alert-rules", "monitor"),
    ("/alert-history", "monitor"),
    ("/notifications", "notification"),
    ("/channels", "notification"),
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
];

async fn abort_source_reservation_and_record(
    provider: &astral_db::SqlxAuthorizationFenceProvider,
    abort: &astral_db::SourceReservationAbort,
    phase: &'static str,
) {
    match provider.abort_source_reservation(abort).await {
        Ok(report) => {
            let proven = matches!(
                report.outcome,
                astral_db::SourceAbortOutcome::Aborted
                    | astral_db::SourceAbortOutcome::AlreadyAborted
            );
            if proven {
                tracing::info!(
                    phase,
                    operation_id = %report.operation_id,
                    reservation_id = %report.reservation_id,
                    proof_id = %abort.proof_id,
                    request_digest = %abort.request_digest,
                    reason = %abort.reason,
                    outcome = ?report.outcome,
                    observed_disposition = ?report.observed_disposition,
                    "durable source reservation abort proven"
                );
            } else {
                tracing::warn!(
                    phase,
                    operation_id = %report.operation_id,
                    reservation_id = %report.reservation_id,
                    proof_id = %abort.proof_id,
                    request_digest = %abort.request_digest,
                    reason = %abort.reason,
                    outcome = ?report.outcome,
                    observed_disposition = ?report.observed_disposition,
                    "source reservation abort not proven; stable identity recovery required"
                );
            }
        }
        Err(error) => {
            tracing::warn!(
                phase,
                operation_id = %abort.operation_id,
                reservation_id = %abort.reservation_id,
                proof_id = %abort.proof_id,
                request_digest = %abort.request_digest,
                reason = %abort.reason,
                outcome = "UNKNOWN",
                error = %error,
                "source reservation abort outcome unknown; stable identity recovery required"
            );
        }
    }
}

pub async fn monitor_permission_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, BoxedResponse> {
    let request_path = req.uri().path().to_owned();
    let path = request_path.as_str();
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
        None => {
            tracing::warn!(path, method = %method, "no permission action for protected route, denying");
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

    let admission_fence = match astral_db::memory_projection_hub() {
        None => None,
        Some(hub) => match hub.capture_authority_fence() {
            Some(fence) => Some(fence),
            None => {
                tracing::error!("monitor admission fence unavailable; denying request");
                return Err(BoxedResponse::new(
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "admission fence unavailable; request denied",
                    )
                        .into_response(),
                ));
            }
        },
    };

    let query_target_id = request_target_id(&req);
    let mut ctx = physical_policy_context(req.headers(), resource, action, query_target_id)
        .map_err(|status| BoxedResponse::new(status.into_response()))?;
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
    let read_request = read_surface.begin_request().map_err(|error| {
        tracing::error!(%error, "monitor authorization request token unavailable");
        BoxedResponse::new(
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "authorization request token unavailable; request denied",
            )
                .into_response(),
        )
    })?;
    let resolution = read_request
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

    let evaluation = read_request
        .evaluate_with_admission(&state.engine, &ctx)
        .await;
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
            tracing::error!(reason, "monitor permission audit task rejected");
        }
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
        let sod_result = read_request.check_sod(&ctx, &decision).await;
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

    if let Err(error) = read_request.ensure_current() {
        tracing::error!(%error, "monitor authorization request token changed; denying request");
        return Err(BoxedResponse::new(
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "authorization request token changed; request denied",
            )
                .into_response(),
        ));
    }

    if let Some(fence) = admission_fence {
        if !astral_db::memory_projection_hub().is_some_and(|hub| hub.authority_fence_matches(fence))
        {
            tracing::error!("monitor admission fence mismatch; denying request");
            return Err(BoxedResponse::new(
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "admission fence mismatch; request denied",
                )
                    .into_response(),
            ));
        }
    }

    let source_abort = if !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") {
        read_request
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

    // The reservation await is an independent consistency window. Recheck the
    // original request token and captured fence before exposing the mutation to
    // the handler; never replace them with a newly sampled request.
    if let Some((provider, abort)) = &source_abort {
        let token_error = read_request.ensure_current().err();
        let token_changed = token_error.is_some();
        let fence_holds = admission_fence.is_none_or(|fence| {
            astral_db::memory_projection_hub().is_some_and(|hub| hub.authority_fence_matches(fence))
        });
        if let Some(error) = token_error {
            tracing::error!(%error, "monitor post-reservation request token changed; handler denied");
        }
        if !fence_holds {
            tracing::error!("monitor post-reservation admission fence changed; handler denied");
        }
        if token_changed || !fence_holds {
            abort_source_reservation_and_record(provider, abort, "monitor_post_reservation").await;
            return Err(BoxedResponse::new(
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "authorization state changed after reservation; request denied",
                )
                    .into_response(),
            ));
        }
    }

    req.extensions_mut().insert(ctx);
    if let Some(authorization_admission) = authorization_admission {
        req.extensions_mut().insert(authorization_admission);
    }

    let response = next.run(req).await;
    if let Some((provider, abort)) = source_abort {
        abort_source_reservation_and_record(&provider, &abort, "monitor_post_handler").await;
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use astral_common::middleware::permission_check_shared::resolve_permission_action;
    use astral_types::ResourceRegistry;

    #[test]
    fn post_reservation_gate_rechecks_and_aborts_before_handler() {
        let source = include_str!("middleware.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let gate = production.find(".ensure_mutation_commit_fence()").unwrap();
        let reservation = production
            .find(".reserve_mutation_with_abort(&ctx, admission)")
            .unwrap();
        assert!(gate < reservation);
        let handler = production[reservation..]
            .find("next.run(req).await")
            .unwrap()
            + reservation;
        let window = &production[reservation..handler];
        let token = window.find("read_request.ensure_current()").unwrap();
        let fence = window.find("authority_fence_matches(fence)").unwrap();
        let abort = window
            .find("abort_source_reservation_and_record(provider, abort")
            .unwrap();
        let denial = window[abort..].find("return Err(").unwrap() + abort;
        assert!(token < abort && fence < abort && abort < denial);
        assert!(!window.contains("begin_request("));
    }

    #[test]
    fn monitor_write_routes_use_registered_actions() {
        let registry = ResourceRegistry::global();
        for action in [
            "read",
            "create",
            "update",
            "delete",
            "scan",
            "reset",
            "arbitrate",
        ] {
            assert!(
                registry.validate("monitor", action).is_ok(),
                "monitor:{action}"
            );
        }

        for (path, method, action) in [
            ("/alerts", "POST", "create"),
            ("/alert-rules", "POST", "create"),
            ("/alerts/3", "PUT", "update"),
            ("/alert-rules/3", "DELETE", "delete"),
            ("/alerts/3/toggle", "POST", "update"),
            ("/alert-rules/3/toggle", "PUT", "update"),
            ("/alert-history/7/ack", "PUT", "update"),
        ] {
            assert_eq!(
                resolve_permission_action("monitor", path, method),
                Some(action),
                "{method} {path}"
            );
            assert!(registry.validate("monitor", action).is_ok(), "{action}");
        }
        for (path, method, action) in [
            ("/notifications", "POST", "create"),
            ("/notifications/3", "PUT", "update"),
            ("/notifications/3/test", "POST", "test"),
        ] {
            assert_eq!(
                resolve_permission_action("notification", path, method),
                Some(action),
                "{method} {path}"
            );
            assert!(
                registry.validate("notification", action).is_ok(),
                "notification:{action}"
            );
        }
    }

    /// 宿主 SoD 分发形状守卫（对齐 TrustGraph/Identity 的源文本守卫惯例）：
    /// 受保护请求必须经 frozen read surface 完成 ownership、admission-bearing
    /// evaluation 与 SoD deny-only 复核；CertifiedMemory 不得从宿主回到 durable
    /// helper。审计 detail 必须经 shared 有界 provenance helper 并通过显式 detail
    /// 审计入口传播。本地不得重新引入任何重复 helper 定义。
    #[test]
    fn sod_dispatch_wires_org_provenance_to_fresh_admission_recheck() {
        let source = include_str!("middleware.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        let dispatch: String = production
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        let fence_capture = dispatch
            .find("capture_authority_fence()")
            .expect("host must capture the opaque admission fence before authority reads");
        let ownership = dispatch
            .find("read_request.resolve_ownership(")
            .expect("host must resolve ownership through the request-scoped read handle");
        let evaluation = dispatch
            .find("read_request.evaluate_with_admission(&state.engine,&ctx)")
            .expect("host must evaluate through the request-scoped read handle");
        let sod_dispatch = dispatch
            .find("read_request.check_sod(&ctx,&decision)")
            .expect("host SoD must use the request-scoped read handle");
        assert!(
            fence_capture < ownership && ownership < evaluation && evaluation < sod_dispatch,
            "dispatch order must be fence -> ownership -> evaluation -> SoD"
        );
        assert!(
            !production.contains("load_org_sod_admission(")
                && !production.contains("check_sod_conflict_with_context_and_org(")
                && !production.contains("check_sod_conflict_with_context(&state.db"),
            "host middleware must not bypass the frozen read surface with durable SoD helpers"
        );
        assert!(
            !production.contains("resolve_resource_ownership("),
            "host middleware must not bypass the frozen read surface with durable ownership"
        );
        let fence_recheck = dispatch
            .find("authority_fence_matches(fence)")
            .expect("host must recheck the captured authority fence before admission");
        assert!(
            sod_dispatch < fence_recheck,
            "the fence recheck must run after the complete SoD window"
        );
        assert!(
            !production.contains("fn org_provenance_audit_detail"),
            "the bounded provenance detail helper must come from astral_common::audit"
        );
        assert!(production.contains("org_provenance_audit_detail(path, provenance)"));
        assert!(production.contains("record_permission_audit_with_request_detail("));
    }
}
