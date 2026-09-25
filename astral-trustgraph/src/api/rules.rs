//! 规则管理 API — HTTP adapter
//!
//! 对齐 platform_v4 真实表结构（permission_rule）。
//! 数据访问在 `repository::rule_repository`，写路径副作用链
//! （快照重建 + 缓存清除）编排在 `service::rule_write_service`。
//! HTTP 层仅解析参数、组装 DTO、包装响应。

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_db::resolve_resource_ownership;
use astral_types::{AstralError, ResourceRegistry};

fn current_card_id(headers: &HeaderMap) -> Result<i64, AppError> {
    headers
        .get("x-user-card-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            AppError(AstralError::Permission(
                "verified card context is required".into(),
            ))
        })
}

fn require_current_card(headers: &HeaderMap, target_card_id: i64) -> Result<(), AppError> {
    if current_card_id(headers)? != target_card_id {
        return Err(AppError(AstralError::Permission(
            "target card does not match verified card context".into(),
        )));
    }
    Ok(())
}

/// 已验证的管理范围：操作者必须携带 user/tenant/domain 上下文。
///
/// 对齐 Java `CardManagementScopeServiceImpl.requireCardManagementScope`：
/// operator 缺 tenant/domain 直接拒绝；GlobalAdmin 例外仅放宽"目标 == 操作者"
/// 的相等性，仍要求操作者上下文存在。
/// scope 只接受 user-card 上下文（中间件已强制注入），禁止回退 identity tenant/domain。
fn require_management_context(headers: &HeaderMap) -> Result<(), AppError> {
    if parse_header_id(headers, "x-user-id").is_none() {
        return Err(scope_denied());
    }
    parse_header_id(headers, "x-user-card-tenant-id").ok_or_else(scope_denied)?;
    parse_header_id(headers, "x-user-card-domain-id").ok_or_else(scope_denied)?;
    Ok(())
}

fn parse_header_id(headers: &HeaderMap, name: &str) -> Option<i64> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
}

const SCOPE_DENIED: &str = "CARD_MANAGEMENT_SCOPE_DENIED";

fn scope_denied() -> AppError {
    AppError(AstralError::Permission(SCOPE_DENIED.into()))
}

/// 目标卡管理范围校验：目标卡 tenant/domain 与操作者一致，否则 GlobalAdmin ACTIVE 例外。
///
/// 对齐 Java `requireCardManagement(cardId)`（读卡 → tenant/domain 比对 + GlobalAdmin）。
/// 目标卡 tenant/domain 为 NULL 视为不匹配（fail-closed）。
/// `pub(crate)` 供 templates.rs（template apply/apply_async）复用逐卡校验。
pub(crate) async fn require_card_scope(
    state: &AppState,
    headers: &HeaderMap,
    card_id: i64,
) -> Result<(), AppError> {
    let user_id = parse_header_id(headers, "x-user-id").ok_or_else(scope_denied)?;
    require_management_context(headers)?;
    let card = state
        .user_card_repository
        .get_card(card_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(scope_denied)?;
    let card_tenant = card.tenant_id.ok_or_else(scope_denied)?;
    let card_domain = card.domain_id.ok_or_else(scope_denied)?;
    // scope 只接受 user-card 上下文，禁止回退 identity tenant/domain。
    let operator_tenant =
        parse_header_id(headers, "x-user-card-tenant-id").ok_or_else(scope_denied)?;
    let operator_domain =
        parse_header_id(headers, "x-user-card-domain-id").ok_or_else(scope_denied)?;
    if operator_tenant == card_tenant && operator_domain == card_domain {
        return Ok(());
    }
    // GlobalAdmin ACTIVE 例外放行跨范围
    if state
        .global_admin_repository
        .is_active_admin(user_id)
        .await
        .map_err(AppError::from)?
    {
        return Ok(());
    }
    Err(scope_denied())
}

/// 规则管理范围校验：先解析规则 → 再校验其卡（对齐 Java `requireRuleManagement(ruleId)`）。
async fn require_rule_scope(
    state: &AppState,
    headers: &HeaderMap,
    rule_id: i64,
) -> Result<(), AppError> {
    let rule_card_id = state
        .rule_repository
        .get_rule_card_id(rule_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(scope_denied)?;
    require_card_scope(state, headers, rule_card_id).await
}

use crate::repository::grant_ledger_adapter::DirectRuleMutationContext;
use crate::repository::rule_repository::RuleRecord;
use crate::service::rule_write_service::{CreateRuleRequest, UpdateRuleRequest};
use crate::AppState;

/// 从 Gateway 已验证身份头构造 direct 规则 mutation 上下文：
/// actor 必须存在且为正；可选 `x-request-id` 头透传为 operation 关联。
fn mutation_context(headers: &HeaderMap) -> Result<DirectRuleMutationContext, AppError> {
    let actor_id = parse_header_id(headers, "x-user-id").ok_or_else(scope_denied)?;
    let request_id_header = headers.get("x-request-id").and_then(|v| v.to_str().ok());
    DirectRuleMutationContext::user(actor_id, request_id_header).map_err(AppError::from)
}

/// 规则响应 DTO（对齐前端 PermissionRuleItem camelCase 序列化）
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleDto {
    pub rule_id: i64,
    pub card_id: i64,
    pub tenant_id: Option<i64>,
    pub resource_type: String,
    pub resource_id: Option<i64>,
    pub action_code: String,
    pub effect: String,
    pub condition_json: Option<String>,
    pub priority: i32,
    pub source_type: String,
    pub source_id: Option<i64>,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
    pub enabled: Option<i32>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl From<RuleRecord> for RuleDto {
    fn from(r: RuleRecord) -> Self {
        Self {
            rule_id: r.rule_id,
            card_id: r.card_id,
            tenant_id: r.tenant_id,
            resource_type: r.resource_type,
            resource_id: r.resource_id,
            action_code: r.action_code,
            effect: r.effect,
            condition_json: r.condition_json,
            priority: r.priority,
            source_type: r.source_type,
            source_id: r.source_id,
            valid_from: r.valid_from,
            valid_to: r.valid_to,
            enabled: r.enabled,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// 创建/更新规则请求（对齐前端 PermissionRuleItem）
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleRequest {
    pub card_id: i64,
    pub effect: String,
    pub resource_type: String,
    pub action_code: String,
    pub priority: Option<i32>,
    pub condition_json: Option<String>,
    /// Public permission-rule CRUD accepts only card-owned source types.
    /// Template authorization is owned by the template/RuleSet APIs.
    pub source_type: Option<String>,
    pub resource_id: Option<i64>,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
    pub enabled: Option<i32>,
}

pub fn rule_routes() -> Router<AppState> {
    Router::new()
        // 对齐前端路径 /main/api/v1/permission-rules
        .route("/permission-rules", get(list_rules))
        .route("/permission-rules", post(create_rule))
        .route("/permission-rules/{id}", get(get_rule))
        .route("/permission-rules/{id}", put(update_rule))
        .route("/permission-rules/{id}", delete(delete_rule))
        .route("/permission-rules/validate", post(validate_rule))
        .route("/permission-rules/registry", get(list_resource_types))
        .route("/permission-rules/check", get(check_permission))
        .route("/permission-rules/card/{card_id}", get(list_rules_by_card))
        .route(
            "/permission-rules/card/{card_id}",
            delete(delete_rules_by_card),
        )
}

/// 按 cardId 查询规则列表
async fn list_rules_by_card(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(card_id): Path<i64>,
) -> Result<Json<ApiResponse<Vec<RuleDto>>>, AppError> {
    require_current_card(&headers, card_id)?;
    require_card_scope(&state, &headers, card_id).await?;
    let rows = state
        .rule_repository
        .list_rules_by_card(card_id)
        .await?
        .into_iter()
        .map(RuleDto::from)
        .collect();
    Ok(Json(ApiResponse::success(rows)))
}

/// 按 cardId 删除所有规则
async fn delete_rules_by_card(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(card_id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    require_current_card(&headers, card_id)?;
    require_card_scope(&state, &headers, card_id).await?;
    state
        .rule_write_service
        .delete_rules_by_card(card_id, &mutation_context(&headers)?)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

/// 权限检查
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CheckPermissionQuery {
    card_id: i64,
    resource_type: String,
    action_code: String,
    resource_id: Option<i64>,
}

async fn check_permission(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<CheckPermissionQuery>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let context_card_id = headers
        .get("x-user-card-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok());
    if context_card_id != Some(q.card_id) {
        return Err(AppError(AstralError::Permission(
            "card context does not match requested card".into(),
        )));
    }
    require_card_scope(&state, &headers, q.card_id).await?;

    // 统一走物理双卡上下文：principal_kind + identity_card_id 一并注入，
    // 引擎的 check_card_active 才能完成双卡匹配校验（手工构造会缺 identity 字段）。
    let mut ctx = astral_common::middleware::permission_check_shared::physical_policy_context(
        &headers,
        &q.resource_type,
        &q.action_code,
        q.resource_id,
    )
    .map_err(|status| AppError(AstralError::Permission(format!("{status}"))))?;
    // This endpoint is a self-card permission inspection operation, not access
    // to the query-addressed business object. Its route is explicitly global in
    // the shared resolver, while q.resource_id remains the policy-match target.
    let resolution = resolve_resource_ownership(
        &state.db,
        "permission_rule",
        "/permission-rules/check",
        "GET",
        q.resource_id,
        ctx.card_id,
        ctx.user_id,
    )
    .await;
    resolution.apply_to(&mut ctx);
    // 与 permission_check 中间件同一份启动期冻结旗标：正式授权仓储必须携带
    // org_scope 准入状态（default-off），避免同进程内构造出无旗标仓储造成
    // 与策略引擎宿主不一致的 ORG_AUTHORITY_DISABLED 判定（split-brain）。
    let repo = astral_db::SqlxRuleRepository::new(state.db.clone())
        .with_org_scope_enabled(state.org_scope_enabled);
    let decision = state.engine.evaluate(&ctx, &repo).await;
    let result = if decision.allowed {
        "ALLOW"
    } else if decision.reason == "NO_MATCH" {
        "NO_MATCH"
    } else {
        "DENY"
    };
    Ok(Json(ApiResponse::success(
        serde_json::json!({ "effect": result, "reason": decision.reason }),
    )))
}

async fn list_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<RuleDto>>>, AppError> {
    let card_id = current_card_id(&headers)?;
    require_card_scope(&state, &headers, card_id).await?;
    let all_rows = state.rule_repository.list_rules_by_card(card_id).await?;
    let total = all_rows.len() as i64;
    let start = page.offset().max(0) as usize;
    let end = (start + page.effective_size() as usize).min(all_rows.len());
    let rows = if start < end {
        all_rows[start..end]
            .iter()
            .cloned()
            .map(RuleDto::from)
            .collect()
    } else {
        Vec::new()
    };
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

async fn create_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RuleRequest>,
) -> Result<Json<ApiResponse<RuleDto>>, AppError> {
    require_current_card(&headers, req.card_id)?;
    require_card_scope(&state, &headers, req.card_id).await?;
    // Reject template/delegation/system ownership claims at the public API
    // boundary; only card-owned rules are valid here.
    crate::service::rule_write_service::validate_public_rule_source_type(
        req.source_type.as_deref(),
    )
    .map_err(AppError::from)?;
    let row = state
        .rule_write_service
        .create_rule(
            &CreateRuleRequest {
                card_id: req.card_id,
                effect: req.effect,
                resource_type: req.resource_type,
                action_code: req.action_code,
                priority: req.priority,
                condition_json: req.condition_json,
                valid_from: req.valid_from,
                valid_to: req.valid_to,
                source_type: req.source_type,
                resource_id: req.resource_id,
                enabled: req.enabled,
            },
            &mutation_context(&headers)?,
        )
        .await?;
    Ok(Json(ApiResponse::success(row.into())))
}

async fn get_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<RuleDto>>, AppError> {
    let current_card_id = current_card_id(&headers)?;
    // 对齐 Java `requireRuleManagement(ruleId)`：先解析规则归属卡再做范围校验
    require_rule_scope(&state, &headers, id).await?;
    let row = state
        .rule_repository
        .get_rule(id)
        .await?
        .filter(|row| row.card_id == current_card_id)
        .map(RuleDto::from)
        .ok_or_else(|| AppError(AstralError::Internal(format!("Rule {id} not found"))))?;
    Ok(Json(ApiResponse::success(row)))
}

async fn update_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<RuleRequest>,
) -> Result<Json<ApiResponse<RuleDto>>, AppError> {
    require_current_card(&headers, req.card_id)?;
    require_rule_scope(&state, &headers, id).await?;
    crate::service::rule_write_service::validate_public_rule_source_type(
        req.source_type.as_deref(),
    )
    .map_err(AppError::from)?;
    let row = state
        .rule_write_service
        .update_rule(
            id,
            &UpdateRuleRequest {
                card_id: req.card_id,
                effect: req.effect,
                resource_type: req.resource_type,
                action_code: req.action_code,
                priority: req.priority,
                condition_json: req.condition_json,
                valid_from: req.valid_from,
                valid_to: req.valid_to,
            },
            &mutation_context(&headers)?,
        )
        .await?;
    Ok(Json(ApiResponse::success(row.into())))
}

async fn delete_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let current_card_id = current_card_id(&headers)?;
    // 对齐 Java `requireRuleManagement(ruleId)`：先解析规则归属卡再做范围校验
    require_rule_scope(&state, &headers, id).await?;
    let rule_card_id = state
        .rule_repository
        .get_rule_card_id(id)
        .await?
        .ok_or_else(|| AppError(AstralError::NotFound(format!("Rule {id} not found"))))?;
    if rule_card_id != current_card_id {
        return Err(AppError(AstralError::Permission(
            "target card does not match verified card context".into(),
        )));
    }
    state
        .rule_write_service
        .delete_rule(id, &mutation_context(&headers)?)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn validate_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RuleRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_current_card(&headers, req.card_id)?;
    require_card_scope(&state, &headers, req.card_id).await?;
    // 与 canonical 写路径一致的 fail-closed 校验：只接受 ALLOW
    crate::service::validate_canonical_grant_effect(&req.effect).map_err(AppError::from)?;
    crate::service::rule_write_service::validate_public_rule_source_type(
        req.source_type.as_deref(),
    )
    .map_err(AppError::from)?;
    Ok(Json(ApiResponse::success(
        serde_json::json!({"valid": true}),
    )))
}

async fn list_resource_types(
    State(_state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<serde_json::Value>>>, AppError> {
    let reg = ResourceRegistry::global();
    let types: Vec<serde_json::Value> = reg
        .list_resources()
        .iter()
        .map(|name| {
            let actions = reg.list_actions(name).unwrap_or_default();
            let supported_conditions = reg.list_supported_conditions(name).unwrap_or_default();
            serde_json::json!({
                "resourceType": name,
                "actions": actions,
                "supportedConditions": supported_conditions,
                "description": serde_json::Value::Null,
            })
        })
        .collect();
    Ok(Json(ApiResponse::success(types)))
}
