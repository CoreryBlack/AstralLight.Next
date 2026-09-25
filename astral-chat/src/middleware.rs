//! Chat 权限检查中间件

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use astral_common::middleware::permission_check_shared::{
    path_matches_prefix, physical_policy_context, request_target_id, resolve_permission_action,
    PathResourceMap,
};
use astral_db::{check_sod_conflict, resolve_resource_ownership, SqlxRuleRepository};

use crate::AppState;

/// 注意：此中间件在 nest("/v1/chat", ...) 内部运行，
/// 路径前缀已被 axum 剥离，所以使用剥离后的路径
pub const CHAT_PATH_MAP: PathResourceMap = &[
    ("/messages", "chat_message"),
    ("/sessions", "chat_conversation"),
    ("/groups", "chat_conversation"),
    ("/receipts", "chat_message"),
    ("/ws", "chat_conversation"),
];

fn chat_resource_for_path(path: &str) -> Option<&'static str> {
    CHAT_PATH_MAP
        .iter()
        .find(|(prefix, _)| path_matches_prefix(path, prefix))
        .map(|(_, resource)| *resource)
}

pub async fn chat_permission_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, Response> {
    let path = req.uri().path();
    let method = req.method().clone();

    let resource = match chat_resource_for_path(path) {
        Some(resource) => resource,
        None => {
            tracing::warn!(path, "no chat resource mapping, denying");
            return Err((
                StatusCode::FORBIDDEN,
                format!("No permission mapping for path: {}", path),
            )
                .into_response());
        }
    };

    let action = match resolve_permission_action(resource, path, method.as_str()) {
        Some(action) => action,
        None => return Ok(next.run(req).await),
    };

    let query_target_id = request_target_id(&req);
    let mut ctx = physical_policy_context(req.headers(), resource, action, query_target_id)
        .map_err(|status| status.into_response())?;
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

    let repo = SqlxRuleRepository::new(state.db.clone())
        .with_org_scope_enabled(state.config.org_scope_enabled);
    let decision = state.engine.evaluate(&ctx, &repo).await;

    // 权限决策审计（MQ-first，DB fallback；故障不影响权限决策）
    {
        let audit_resource = resource.to_string();
        let audit_action = action.to_string();
        let audit_reason = decision.reason.clone();
        let audit_path = path.to_string();
        let audit_allowed = decision.allowed;
        let audit_domain_id = ctx.domain_id;
        let pool = state.db.clone();
        let hit_phase =
            policy_engine::PolicyEngine::allow_source_phase(&decision).map(String::from);
        tokio::spawn(async move {
            astral_common::audit::record_permission_audit(
                user_id,
                card_id,
                audit_domain_id,
                tenant_id,
                &audit_resource,
                &audit_action,
                audit_allowed,
                &audit_reason,
                &audit_path,
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
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "Permission denied: {} for {}:{}",
                decision.reason, resource, action
            ),
        )
            .into_response());
    }

    if let Some(so_card_id) = card_id {
        match check_sod_conflict(
            &state.db,
            so_card_id,
            user_id,
            resource,
            action,
            resource_owner_id,
        )
        .await
        {
            Ok(result) if result.has_conflict => {
                return Err((
                    StatusCode::FORBIDDEN,
                    format!(
                        "SoD conflict: {} holds conflicting permission '{}' per policy '{}'",
                        resource,
                        result.conflict_permission.unwrap_or_default(),
                        result.conflict_policy.unwrap_or_default(),
                    ),
                )
                    .into_response());
            }
            Ok(_) => {}
            Err(error) => {
                tracing::error!(card_id = so_card_id, resource, action, %error, "SoD check unavailable; denying");
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "SoD check unavailable; request denied",
                )
                    .into_response());
            }
        }
    }

    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::chat_resource_for_path;

    #[test]
    fn chat_ws_permission_mapping_is_segment_bounded() {
        assert_eq!(chat_resource_for_path("/ws"), Some("chat_conversation"));
        assert_eq!(chat_resource_for_path("/ws/42"), Some("chat_conversation"));
        assert_eq!(chat_resource_for_path("/ws/42/extra"), Some("chat_conversation"));
        assert_eq!(chat_resource_for_path("/wsfoo"), None);
    }
}
