//! Learn 权限检查中间件

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use astral_common::middleware::permission_check_shared::{
    physical_policy_context, resolve_permission_action, PathResourceMap,
};
use astral_db::{check_sod_conflict_with_context, SqlxRuleRepository};

use crate::ownership::resolve_learn_resource_ownership;

use crate::AppState;

/// 管理端路由在 nest("/v1/admin/learn", ...) 内部使用的路径映射。
pub const LEARN_PATH_MAP: PathResourceMap = &[
    ("/subjects", "learn_subject"),
    ("/questions", "learn_question"),
    ("/chapters", "learn_chapter"),
    ("/exams", "learn_exam"),
    ("/courses", "learn_course"),
    ("/enrollments", "learn_course"),
    ("/grades", "learn_statistics"),
    ("/publishing", "learn_course"),
    ("/assignments", "learn_course"),
    ("/discussions", "learn_course"),
    ("/classes", "learn_school"),
    ("/submissions", "learn_course"),
    ("/levels", "learn_level"),
    ("/statistics", "learn_statistics"),
    ("/checkins", "learn_checkin"),
    ("/documents", "learn_document"),
    ("/devices", "learn_device"),
    ("/system-settings", "learn_system_setting"),
    ("/webhook-configs", "learn_webhook"),
    ("/wrong-questions", "learn_question"),
    ("/solutions", "learn_question"),
];

/// App 端路由在 nest("/v1/app/learn", ...) 内部使用的路径映射。
pub const LEARN_APP_PATH_MAP: PathResourceMap = &[
    ("/progress", "learn_progress"),
    ("/levels", "learn_level"),
    ("/level-play", "learn_level_play"),
    ("/checkins", "learn_checkin"),
    ("/solutions", "learn_question"),
    ("/wrong-questions", "learn_question"),
    ("/user-answers", "learn_user_answer"),
    ("/user-subjects", "learn_user_subject"),
    ("/question-first-attempts", "learn_question_first_attempt"),
    ("/exams", "learn_exam"),
    ("/devices", "learn_device"),
    ("/subjects", "learn_subject"),
    ("/courses", "learn_course"),
];

/// App 用户路由在 nest("/v1/app/users", ...) 内部使用的路径映射。
/// 登录和登出是认证端点，由认证层处理，不纳入资源策略检查。
pub const LEARN_APP_USER_PATH_MAP: PathResourceMap = &[
    ("/me", "user_profile"),
    ("/identity", "user_profile"),
    ("/learning-profile", "user_profile"),
];

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn resource_action(
    path: &str,
    method: &str,
    map: PathResourceMap,
) -> Result<Option<(&'static str, &'static str)>, (StatusCode, String)> {
    let resource = map
        .iter()
        .find(|(prefix, _)| path_matches_prefix(path, prefix))
        .map(|(_, resource)| *resource)
        .ok_or_else(|| {
            (
                StatusCode::FORBIDDEN,
                format!("No permission mapping for path: {path}"),
            )
        })?;
    let Some(action) = resolve_permission_action(resource, path, method) else {
        return Ok(None);
    };
    Ok(Some((resource, action)))
}

fn parse_target_id(query: Option<&str>) -> Option<i64> {
    query.and_then(|query| {
        query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            match key {
                "target_id" | "resource_id" | "id" | "card_id" => {
                    value.parse::<i64>().ok().filter(|value| *value > 0)
                }
                _ => None,
            }
        })
    })
}

#[allow(clippy::result_large_err)]
async fn check_learn_permission(
    state: &AppState,
    uri: &axum::http::Uri,
    method: &str,
    headers: &axum::http::HeaderMap,
    path_map: PathResourceMap,
    service: &'static str,
) -> Result<(), Response> {
    let path = uri.path();
    let Some((resource, action)) =
        resource_action(path, method, path_map).map_err(IntoResponse::into_response)?
    else {
        return Ok(());
    };
    let target_id = parse_target_id(uri.query());
    let mut ctx = physical_policy_context(headers, resource, action, target_id)
        .map_err(|status| status.into_response())?;
    // Capture the original shared authority fence before the row read. The
    // Learn row locks below protect the inspected metadata; the unchanged fence
    // check after PolicyEngine and SoD rejects concurrent registered source writes.
    let hub = astral_db::memory_projection_hub();
    let authority_fence = if let Some(hub) = hub {
        let fence = hub.capture_authority_fence().ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Learn source state is changing",
            )
                .into_response()
        })?;
        Some((hub, fence))
    } else {
        None
    };
    // The ownership query runs in this transaction and its FOR SHARE locks stay
    // held through PolicyEngine and SoD. The captured source fence is checked
    // before releasing the locks, rejecting registered source-writer races.
    let mut ownership_tx = state.db.begin().await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Learn ownership read unavailable",
        )
            .into_response()
    })?;
    let resolution = resolve_learn_resource_ownership(
        &mut ownership_tx,
        resource,
        path,
        method,
        target_id,
        ctx.user_id,
    )
    .await;
    resolution.apply_to(&mut ctx);
    if matches!(
        &resolution,
        astral_db::ResourceOwnershipResolution::Unresolved { .. }
            | astral_db::ResourceOwnershipResolution::Unavailable { .. }
    ) {
        tracing::warn!(
            service,
            resource,
            path,
            ownership = resolution.code(),
            "Learn target ownership unresolved; denying before policy evaluation"
        );
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Learn resource ownership is unresolved",
        )
            .into_response());
    }
    if !matches!(
        &resolution,
        astral_db::ResourceOwnershipResolution::TenantScoped { .. }
            | astral_db::ResourceOwnershipResolution::Global { .. }
    ) {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "Learn ownership contract unavailable",
        )
            .into_response());
    }
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
        if let Err(reason) = astral_common::audit::spawn_owned_audit(async move {
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
        }) {
            tracing::error!(reason, "owned Learn permission audit admission refused");
        }
    }

    if !decision.allowed {
        tracing::warn!(service, ?user_id, resource, action, reason = %decision.reason, "permission_denied");
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "Permission denied: {} for {resource}:{action}",
                decision.reason
            ),
        )
            .into_response());
    }
    if let Some(so_card_id) = card_id {
        match check_sod_conflict_with_context(&state.db, &ctx, resource_owner_id).await {
            Ok(result) if result.has_conflict => {
                return Err((
                    StatusCode::FORBIDDEN,
                    format!(
                        "SoD conflict: {} holds conflicting permission '{}' per policy '{}'",
                        resource,
                        result.conflict_permission.unwrap_or_default(),
                        result.conflict_policy.unwrap_or_default()
                    ),
                )
                    .into_response());
            }
            Ok(_) => {}
            Err(error) => {
                tracing::error!(card_id = so_card_id, resource, action, %error, "SoD check unavailable; denying");
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "SoD check failed; request denied",
                )
                    .into_response());
            }
        }
    }
    ownership_tx.commit().await.map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Learn ownership read transaction failed",
        )
            .into_response()
    })?;
    if let Some((hub, fence)) = authority_fence {
        if !hub.authority_fence_matches(fence) {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "Learn source state changed during authorization",
            )
                .into_response());
        }
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
pub async fn learn_permission_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, Response> {
    check_learn_permission(
        &state,
        req.uri(),
        req.method().as_str(),
        req.headers(),
        LEARN_PATH_MAP,
        "learn-admin",
    )
    .await?;
    Ok(next.run(req).await)
}

#[allow(clippy::result_large_err)]
pub async fn learn_app_permission_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, Response> {
    check_learn_permission(
        &state,
        req.uri(),
        req.method().as_str(),
        req.headers(),
        LEARN_APP_PATH_MAP,
        "learn-app",
    )
    .await?;
    Ok(next.run(req).await)
}

#[allow(clippy::result_large_err)]
pub async fn learn_app_user_permission_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, Response> {
    // Authentication endpoints are intentionally outside resource policy.
    if matches!(
        req.uri().path(),
        "/login" | "/logout" | "/v1/app/users/login" | "/v1/app/users/logout"
    ) {
        return Ok(next.run(req).await);
    }
    check_learn_permission(
        &state,
        req.uri(),
        req.method().as_str(),
        req.headers(),
        LEARN_APP_USER_PATH_MAP,
        "learn-app-users",
    )
    .await?;
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::{Effect, PolicyContext, PolicyError};
    use policy_engine::{
        PermissionRule, PolicyEngine, RuleRepository, RuleSetEntry, RuleSetSnapshot,
    };

    struct ContractRepo {
        snapshots: Vec<RuleSetSnapshot>,
        rules: Vec<PermissionRule>,
    }

    #[async_trait::async_trait]
    impl RuleRepository for ContractRepo {
        async fn load_rule_set_snapshots(
            &self,
            _card_id: i64,
        ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
            Ok(self.snapshots.clone())
        }
        async fn load_permission_rules(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(self.rules.clone())
        }
    }

    fn contract_context(target_id: Option<i64>) -> PolicyContext {
        PolicyContext::builder()
            .user_id(Some(42))
            .card_id(Some(7))
            .tenant_id(Some(10))
            .resource(Some("learn_progress".into()))
            .action("read".into())
            .target_id(target_id)
            // 测试中目标资源 id 即属主 id；OwnerOnly 要求 resource_owner_id == user_id
            .resource_owner_id(target_id)
            .build()
    }
    #[test]
    fn app_mappings_and_actions_are_exact() {
        assert_eq!(
            resource_action("/progress/12/3", "GET", LEARN_APP_PATH_MAP).unwrap(),
            Some(("learn_progress", "read"))
        );
        assert_eq!(
            resource_action("/user-answers", "POST", LEARN_APP_PATH_MAP).unwrap(),
            Some(("learn_user_answer", "create"))
        );
        assert_eq!(
            resource_action("/wrong-questions/9/master", "POST", LEARN_APP_PATH_MAP).unwrap(),
            Some(("learn_question", "create"))
        );
        assert_eq!(
            resource_action("/devices", "GET", LEARN_APP_PATH_MAP).unwrap(),
            Some(("learn_device", "read"))
        );
        assert_eq!(
            resource_action("/level-play/start", "POST", LEARN_APP_PATH_MAP).unwrap(),
            Some(("learn_level_play", "play"))
        );
    }

    #[test]
    fn unknown_app_path_is_denied_by_default() {
        assert_eq!(
            resource_action("/unknown", "GET", LEARN_APP_PATH_MAP)
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn path_mapping_requires_segment_boundary() {
        assert_eq!(
            resource_action("/progress/12", "GET", LEARN_APP_PATH_MAP).unwrap(),
            Some(("learn_progress", "read"))
        );
        assert_eq!(
            resource_action("/progressive", "GET", LEARN_APP_PATH_MAP)
                .unwrap_err()
                .0,
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn object_id_query_accepts_only_snake_case_keys() {
        assert_eq!(parse_target_id(Some("target_id=11")), Some(11));
        assert_eq!(parse_target_id(Some("resource_id=12")), Some(12));
        assert_eq!(parse_target_id(Some("id=13")), Some(13));
        assert_eq!(parse_target_id(Some("card_id=14")), Some(14));
        assert_eq!(parse_target_id(Some("targetId=11")), None);
        assert_eq!(parse_target_id(Some("resourceId=12")), None);
        assert_eq!(parse_target_id(Some("cardId=14")), None);
    }

    #[test]
    fn authentication_endpoints_are_not_policy_mapped() {
        assert!(resource_action("/login", "POST", LEARN_APP_USER_PATH_MAP).is_err());
        assert!(resource_action("/logout", "POST", LEARN_APP_USER_PATH_MAP).is_err());
        assert_eq!(
            resource_action("/me", "GET", LEARN_APP_USER_PATH_MAP).unwrap(),
            Some(("user_profile", "read"))
        );
    }
    #[tokio::test]
    async fn policy_deny_contract_is_explicit() {
        let engine = PolicyEngine::new();
        let repo = ContractRepo {
            snapshots: vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "BASE".into(),
                entries: vec![RuleSetEntry {
                    effect: Effect::Deny,
                    resource: Some("learn_progress".into()),
                    action: Some("read".into()),
                    condition: None,
                }],
            }],
            rules: vec![],
        };
        let decision = engine.evaluate(&contract_context(Some(42)), &repo).await;
        assert!(
            !decision.allowed,
            "explicit policy deny must reject the request"
        );
        assert!(decision.reason.contains("DENY") || decision.reason.contains("deny"));
    }

    #[tokio::test]
    async fn ownership_mismatch_user_42_target_owner_43_is_denied() {
        let engine = PolicyEngine::new();
        let repo = ContractRepo {
            snapshots: vec![],
            rules: vec![PermissionRule {
                id: 1,
                effect: Effect::Allow,
                resource: "learn_progress:42".into(),
                action: "read".into(),
                condition: Some(serde_json::json!({
                    "condition_type": "OwnerOnlyCondition",
                    "params": {}
                })),
            }],
        };
        let decision = engine.evaluate(&contract_context(Some(43)), &repo).await;
        assert!(
            !decision.allowed,
            "user 42 must not access resource owned by user 43"
        );
    }

    #[tokio::test]
    async fn ownership_mismatch_without_target_id_is_denied() {
        let engine = PolicyEngine::new();
        let repo = ContractRepo {
            snapshots: vec![],
            rules: vec![PermissionRule {
                id: 1,
                effect: Effect::Allow,
                resource: "learn_progress:*".into(),
                action: "read".into(),
                condition: Some(serde_json::json!({
                    "condition_type": "OwnerOnlyCondition",
                    "params": {}
                })),
            }],
        };
        let decision = engine.evaluate(&contract_context(None), &repo).await;
        assert!(
            !decision.allowed,
            "missing resource owner target must be denied"
        );
        assert!(decision.reason.contains("DENY") || decision.reason.contains("deny"));
    }
}
