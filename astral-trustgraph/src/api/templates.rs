//! 策略模板管理与审计报表 — HTTP adapter
//!
//! 数据访问在 `repository::template_repository`，sync 的逐卡 rebuild 编排在
//! `service::template_service`。HTTP 层仅解析参数、组装 DTO、包装响应。

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_types::AstralError;

use crate::api::async_tracker::{self, AsyncTask};
use crate::repository::audit_log_repository::RuleSetMutationContext;
use crate::repository::template_repository::{TemplateRuleInput, TemplateRuleRecord};
use crate::AppState;

/// 模板ID最大长度
const TEMPLATE_ID_MAX_LEN: usize = 64;

async fn require_template_admin(state: &AppState, headers: &HeaderMap) -> Result<i64, AppError> {
    crate::api::require_platform_admin(state, headers).await
}

fn mutation_context(headers: &HeaderMap) -> Result<RuleSetMutationContext, AppError> {
    let actor_id = headers
        .get("x-user-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| AppError(AstralError::Auth("verified actor is required".into())))?;
    let operation_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok());
    RuleSetMutationContext::user(actor_id, operation_id).map_err(AppError::from)
}

fn parse_template_numeric_id(id: &str) -> Result<i64, AppError> {
    let parsed = id.parse::<i64>().map_err(|_| {
        AppError(AstralError::Validation(
            "template authorization requires a numeric template_id".into(),
        ))
    })?;
    if parsed <= 0 {
        return Err(AppError(AstralError::Validation(
            "template authorization requires a positive numeric template_id".into(),
        )));
    }
    Ok(parsed)
}

/// Parse the complete template rule payload. A malformed array item is an
/// explicit validation error; silently dropping it would create a different
/// authorization template than the caller requested.
fn parse_template_rules(req: &serde_json::Value) -> Result<Vec<TemplateRuleInput>, AppError> {
    let Some(rule_value) = req.get("rules") else {
        return Ok(Vec::new());
    };
    let rule_arr = rule_value
        .as_array()
        .ok_or_else(|| AppError(AstralError::Validation("rules must be an array".into())))?;
    rule_arr
        .iter()
        .enumerate()
        .map(|(index, rule)| {
            let object = rule.as_object().ok_or_else(|| {
                AppError(AstralError::Validation(format!(
                    "rules[{index}] must be an object"
                )))
            })?;
            let resource = object
                .get("resource")
                .and_then(|value| value.as_str())
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    AppError(AstralError::Validation(format!(
                        "rules[{index}].resource is required"
                    )))
                })?;
            let action = object
                .get("action")
                .and_then(|value| value.as_str())
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    AppError(AstralError::Validation(format!(
                        "rules[{index}].action is required"
                    )))
                })?;
            // fail-closed：模板规则是 RuleSet 条目的 source 定义，同样是 canonical
            // grant —— 只接受 ALLOW（大小写归一），缺省视为 ALLOW。
            let effect_input = object
                .get("effect")
                .and_then(|value| value.as_str())
                .unwrap_or("ALLOW");
            let effect = crate::service::validate_canonical_grant_effect(effect_input)?;
            Ok(TemplateRuleInput {
                effect,
                resource: resource.to_owned(),
                action: action.to_owned(),
            })
        })
        .collect()
}

/// 验证模板ID格式
fn validate_template_id(id: &str) -> Result<(), AppError> {
    if id.is_empty() {
        return Err(AppError(AstralError::Validation(
            "Template ID cannot be empty".into(),
        )));
    }
    if id.len() > TEMPLATE_ID_MAX_LEN {
        return Err(AppError(AstralError::Validation(format!(
            "Template ID too long (max {TEMPLATE_ID_MAX_LEN} characters)"
        ))));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(AppError(AstralError::Validation(
            "Template ID can only contain letters, numbers, underscores, and hyphens".into(),
        )));
    }
    Ok(())
}

/// 策略模板响应 DTO
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyTemplate {
    pub id: String,
    pub name: String,
    pub rule_count: i64,
    pub resources: Vec<String>,
}

/// 合规报表
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceReport {
    pub total_policies: i64,
    pub active_policies: i64,
    pub over_permission_count: i64,
    pub unused_permission_count: i64,
    pub recent_changes: Vec<PolicyChange>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyChange {
    pub id: i64,
    pub resource: String,
    pub action: String,
    pub changed_by: i64,
    pub changed_at: String,
}

pub fn template_routes() -> Router<AppState> {
    Router::new()
        .route("/templates", get(list_templates))
        .route("/templates", post(create_template))
        .route("/templates/{id}", get(get_template))
        .route("/templates/{id}", put(update_template))
        // Retained only to return an explicit breaking/deprecation error. Direct
        // template-to-card materialization is no longer a supported write path.
        .route("/templates/{id}/apply", post(retired_template_apply))
        .route(
            "/templates/{id}/apply/async",
            post(retired_template_apply_async),
        )
        .route("/templates/{id}/sync", post(sync_template))
        .route("/templates/{id}/rules", get(list_template_rules))
        .route("/templates/{id}/rules", post(create_template_rule))
        .route("/templates/rules/{rule_id}", put(update_template_rule))
        .route("/templates/rules/{rule_id}", delete(delete_template_rule))
        .route("/templates/rules/{rule_id}", get(get_template_rule))
        .route("/operations/{task_id}", get(get_operation_status))
        // Java 兼容别名
        .route("/compliance/overview", get(compliance_overview))
        .route("/compliance/report", get(compliance_report))
}

/// GET /main/api/v1/templates
async fn list_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<PolicyTemplate>>>, AppError> {
    require_template_admin(&state, &headers).await?;
    let total = state.template_repository.count_templates().await?;
    let rows = state
        .template_repository
        .list_templates(page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(|t| PolicyTemplate {
            id: t.id.clone(),
            name: t.id.replace("__", ""),
            rule_count: t.rule_count,
            resources: t.resources,
        })
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

/// POST /main/api/v1/templates
async fn create_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<ApiResponse<PolicyTemplate>>, AppError> {
    require_template_admin(&state, &headers).await?;
    let template_id = req
        .get("id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            AppError(AstralError::Validation(
                "template id is required and must be a numeric user_card_template.template_id"
                    .into(),
            ))
        })?;
    validate_template_id(template_id)?;
    parse_template_numeric_id(template_id)?;
    let context = mutation_context(&headers)?;

    let rules = parse_template_rules(&req)?;
    state
        .template_repository
        .create_template(template_id, &rules, &context)
        .await?;

    tracing::info!(template_id, "template created");
    Ok(Json(ApiResponse::success(PolicyTemplate {
        id: template_id.to_string(),
        name: template_id.replace("__", ""),
        rule_count: rules.len() as i64,
        resources: vec![],
    })))
}

/// GET /main/api/v1/templates/{id}
async fn get_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<PolicyTemplate>>, AppError> {
    require_template_admin(&state, &headers).await?;
    validate_template_id(&id)?;
    parse_template_numeric_id(&id)?;
    let t = state.template_repository.get_template(&id).await?;
    Ok(Json(ApiResponse::success(PolicyTemplate {
        id: t.id.clone(),
        name: t.id.replace("__", ""),
        rule_count: t.rule_count,
        resources: t.resources,
    })))
}

/// PUT /main/api/v1/templates/{id} — 事务性删旧插新
async fn update_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_template_admin(&state, &headers).await?;
    validate_template_id(&id)?;
    parse_template_numeric_id(&id)?;
    let context = mutation_context(&headers)?;

    let rules = parse_template_rules(&req)?;

    let inserted = state
        .template_service
        .update_template(&id, &rules, &context)
        .await?;
    tracing::info!(template_id = %id, rules_inserted = inserted, "template updated");

    Ok(Json(ApiResponse::success(serde_json::json!({
        "template_id": id,
        "rules_inserted": inserted,
    }))))
}

const RETIRED_TEMPLATE_APPLY_MESSAGE: &str =
    "template apply endpoints are retired; materialize the template RuleSet and bind cards through /rule-sets/card/{card_id}/bind";

async fn retired_template_apply(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_template_admin(&state, &headers).await?;
    Err(AppError(AstralError::NotImplemented(
        RETIRED_TEMPLATE_APPLY_MESSAGE.into(),
    )))
}

async fn retired_template_apply_async(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(_id): Path<String>,
) -> Result<Json<ApiResponse<AsyncTask>>, AppError> {
    require_template_admin(&state, &headers).await?;
    Err(AppError(AstralError::NotImplemented(
        RETIRED_TEMPLATE_APPLY_MESSAGE.into(),
    )))
}

/// GET /main/api/v1/compliance/overview
async fn compliance_overview(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<ComplianceReport>>, AppError> {
    require_template_admin(&state, &headers).await?;
    let data = state.template_repository.compliance_overview().await?;
    Ok(Json(ApiResponse::success(ComplianceReport {
        total_policies: data.total_rules,
        active_policies: data.active_rules,
        over_permission_count: data.over_permission_cards,
        unused_permission_count: data.unused_permission_rules,
        recent_changes: data
            .recent_changes
            .into_iter()
            .map(|c| PolicyChange {
                id: c.id,
                resource: c.resource,
                action: c.action,
                changed_by: c.changed_by,
                changed_at: c.changed_at,
            })
            .collect(),
    })))
}

/// GET /main/api/v1/compliance/report
async fn compliance_report(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_template_admin(&state, &headers).await?;
    let (total_cards, total_rules, avg_rules) =
        state.template_repository.compliance_report().await?;
    Ok(Json(ApiResponse::success(serde_json::json!({
        "generated_at": time::OffsetDateTime::now_utc().to_string(),
        "total_cards": total_cards,
        "total_policies": total_rules,
        "policies_per_card_avg": avg_rules.unwrap_or(0.0),
    }))))
}

/// POST /main/api/v1/templates/{id}/sync — 同步模板变更到所有引用卡
async fn sync_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_template_admin(&state, &headers).await?;
    validate_template_id(&id)?;
    parse_template_numeric_id(&id)?;
    let context = mutation_context(&headers)?;
    let outcome = state.template_service.sync_template(&id, &context).await?;
    Ok(Json(ApiResponse::success(serde_json::json!({
        "template_id": id,
        "total_cards": outcome.total_cards,
        "synced": outcome.synced,
    }))))
}

/// GET /main/api/v1/templates/{id}/rules — 查询模板规则列表
async fn list_template_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<Vec<TemplateRuleRow>>>, AppError> {
    require_template_admin(&state, &headers).await?;
    validate_template_id(&id)?;
    parse_template_numeric_id(&id)?;
    let rows = state
        .template_repository
        .list_template_rules(&id)
        .await?
        .into_iter()
        .map(TemplateRuleRow::from)
        .collect();
    Ok(Json(ApiResponse::success(rows)))
}

/// POST /main/api/v1/templates/{id}/rules — 新增模板规则
async fn create_template_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<CreateTemplateRuleRequest>,
) -> Result<Json<ApiResponse<TemplateRuleRow>>, AppError> {
    require_template_admin(&state, &headers).await?;
    validate_template_id(&id)?;
    parse_template_numeric_id(&id)?;
    // fail-closed：canonical 模板规则只接受 ALLOW（大小写归一后写入 source）
    let effect =
        crate::service::validate_canonical_grant_effect(req.effect.as_deref().unwrap_or("ALLOW"))?;
    let context = mutation_context(&headers)?;
    let rule_id = state
        .template_repository
        .create_template_rule(
            &id,
            &TemplateRuleInput {
                effect,
                resource: req.resource,
                action: req.action,
            },
            &context,
        )
        .await?;
    let row = state
        .template_repository
        .get_template_rule(rule_id)
        .await?
        .map(TemplateRuleRow::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("template rule {rule_id}"))))?;

    tracing::info!(template_id = %id, rule_id, "template rule created");
    Ok(Json(ApiResponse::success(row)))
}

/// PUT /main/api/v1/templates/rules/{rule_id} — 更新模板规则
async fn update_template_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(rule_id): Path<i64>,
    Json(req): Json<UpdateTemplateRuleRequest>,
) -> Result<Json<ApiResponse<TemplateRuleRow>>, AppError> {
    require_template_admin(&state, &headers).await?;
    // fail-closed：显式提供的 effect 也必须为 ALLOW（大小写归一）；
    // 缺省沿用既有 DB 值，最终写入 effect 由 repository 校验（遗留 DENY 行 fail-closed 拒绝）。
    let effect = match req.effect.as_deref() {
        Some(raw) => Some(crate::service::validate_canonical_grant_effect(raw)?),
        None => None,
    };
    let context = mutation_context(&headers)?;
    state
        .template_repository
        .update_template_rule(
            rule_id,
            effect.as_deref(),
            req.resource.as_deref(),
            req.action.as_deref(),
            &context,
        )
        .await?;

    let row = state
        .template_repository
        .get_template_rule(rule_id)
        .await?
        .map(TemplateRuleRow::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("template rule {rule_id}"))))?;

    tracing::info!(rule_id, "template rule updated");
    Ok(Json(ApiResponse::success(row)))
}

/// GET /main/api/v1/templates/rules/{rule_id} — 查询单条模板规则
async fn get_template_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(rule_id): Path<i64>,
) -> Result<Json<ApiResponse<TemplateRuleRow>>, AppError> {
    require_template_admin(&state, &headers).await?;
    let row = state
        .template_repository
        .get_template_rule(rule_id)
        .await?
        .map(TemplateRuleRow::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("template rule {rule_id}"))))?;
    Ok(Json(ApiResponse::success(row)))
}

/// DELETE /main/api/v1/templates/rules/{rule_id} — 删除模板规则
async fn delete_template_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(rule_id): Path<i64>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_template_admin(&state, &headers).await?;
    let context = mutation_context(&headers)?;

    let deleted = state
        .template_repository
        .delete_template_rule(rule_id, &context)
        .await?;
    if !deleted {
        return Err(AppError(AstralError::NotFound(format!(
            "template rule {rule_id}"
        ))));
    }

    tracing::info!(rule_id, "template rule deleted");
    Ok(Json(ApiResponse::success(
        serde_json::json!({ "id": rule_id, "deleted": true }),
    )))
}

/// GET /main/api/v1/operations/{task_id} — 查询异步操作状态
async fn get_operation_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(task_id): Path<String>,
) -> Result<Json<ApiResponse<AsyncTask>>, AppError> {
    let requester_user_id = headers
        .get("x-user-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|id| *id > 0)
        .ok_or_else(|| AppError(AstralError::Auth("verified requester required".into())))?;
    let requester_card_id = headers
        .get("x-user-card-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|id| *id > 0)
        .ok_or_else(|| {
            AppError(AstralError::Permission(
                "requester card context required".into(),
            ))
        })?;
    let requester_tenant_id = headers
        .get("x-user-card-tenant-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|id| *id > 0)
        .ok_or_else(|| {
            AppError(AstralError::Permission(
                "requester tenant context required".into(),
            ))
        })?;
    let requester_domain_id = headers
        .get("x-user-card-domain-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|id| *id > 0)
        .ok_or_else(|| {
            AppError(AstralError::Permission(
                "requester domain context required".into(),
            ))
        })?;
    let task = async_tracker::load_operation_for_requester(
        &state.db,
        &task_id,
        requester_user_id,
        requester_card_id,
        requester_tenant_id,
        requester_domain_id,
    )
    .await
    .map_err(AppError::from)?
    .ok_or_else(|| AppError(AstralError::NotFound(format!("operation {task_id}"))))?;
    Ok(Json(ApiResponse::success(task)))
}

// ===== Template Rule DTOs =====

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateRuleRow {
    pub id: i64,
    pub template_id: String,
    pub effect: String,
    pub resource: String,
    pub action: String,
}

impl From<crate::repository::template_repository::TemplateRuleRecord> for TemplateRuleRow {
    fn from(r: TemplateRuleRecord) -> Self {
        Self {
            id: r.id,
            template_id: r.template_id,
            effect: r.effect,
            resource: r.resource,
            action: r.action,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTemplateRuleRequest {
    pub effect: Option<String>,
    pub resource: String,
    pub action: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTemplateRuleRequest {
    pub effect: Option<String>,
    pub resource: Option<String>,
    pub action: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_template_rules_are_rejected_instead_of_dropped() {
        let request = serde_json::json!({
            "rules": [
                {"resource": "learn_course", "action": "read"},
                {"resource": "learn_course"}
            ]
        });
        let error = parse_template_rules(&request).unwrap_err();
        assert!(matches!(
            error,
            AppError(AstralError::Validation(message)) if message.contains("rules[1].action")
        ));
    }

    #[test]
    fn non_array_template_rules_are_rejected() {
        let request = serde_json::json!({"rules": {"resource": "learn_course"}});
        assert!(matches!(
            parse_template_rules(&request),
            Err(AppError(AstralError::Validation(message))) if message.contains("array")
        ));
    }

    #[test]
    fn template_rule_effect_is_allow_only() {
        // 缺省 effect 视为 ALLOW
        let rules = parse_template_rules(&serde_json::json!({
            "rules": [{"resource": "learn_course", "action": "read"}]
        }))
        .expect("missing effect defaults to ALLOW");
        assert_eq!(rules[0].effect, "ALLOW");

        // 大小写/空白归一后写入 canonical ALLOW
        let rules = parse_template_rules(&serde_json::json!({
            "rules": [{"resource": "learn_course", "action": "read", "effect": " allow "}]
        }))
        .expect("case-insensitive ALLOW must be accepted");
        assert_eq!(rules[0].effect, "ALLOW");

        // DENY/未知值/空值在解析期拒绝，不进入任何 source 写入
        for rejected in ["DENY", "deny", "GRANT", "", "   "] {
            let error = parse_template_rules(&serde_json::json!({
                "rules": [{"resource": "learn_course", "action": "read", "effect": rejected}]
            }))
            .expect_err("non-ALLOW template rule effect must be rejected");
            assert!(
                matches!(&error, AppError(AstralError::Validation(message)) if message.contains("ALLOW")),
                "rejected={rejected:?} unexpected={error:?}"
            );
        }
    }

    #[test]
    fn test_valid_template_ids() {
        assert!(validate_template_id("custom").is_ok());
        assert!(validate_template_id("my-template").is_ok());
        assert!(validate_template_id("__SUPERADMIN__").is_ok());
        assert!(validate_template_id("role_admin_v2").is_ok());
        assert!(validate_template_id("a").is_ok());
    }

    #[test]
    fn test_empty_template_id() {
        assert!(validate_template_id("").is_err());
    }

    #[test]
    fn test_too_long_template_id() {
        let long_id = "a".repeat(65);
        assert!(validate_template_id(&long_id).is_err());
        let max_id = "a".repeat(64);
        assert!(validate_template_id(&max_id).is_ok());
    }

    #[test]
    fn test_invalid_characters() {
        assert!(validate_template_id("template@123").is_err());
        assert!(validate_template_id("template with spaces").is_err());
        assert!(validate_template_id("template;DROP").is_err());
        assert!(validate_template_id("template/path").is_err());
        assert!(validate_template_id("template.yaml").is_err());
    }

    #[test]
    fn template_rule_apply_requires_numeric_schema_id() {
        assert!(parse_template_numeric_id("__SUPERADMIN__").is_err());
        assert!(parse_template_numeric_id("0").is_err());
        assert!(parse_template_numeric_id("-1").is_err());
        assert_eq!(parse_template_numeric_id("42").unwrap(), 42);
    }

    #[test]
    fn retired_template_apply_has_explicit_breaking_message() {
        assert!(RETIRED_TEMPLATE_APPLY_MESSAGE.contains("retired"));
        assert!(RETIRED_TEMPLATE_APPLY_MESSAGE.contains("RuleSet"));
    }

    #[test]
    fn test_unicode_rejected() {
        assert!(validate_template_id("模板ID").is_err());
        assert!(validate_template_id("template\u{0000}").is_err());
    }
}
