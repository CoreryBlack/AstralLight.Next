//! 规则集管理 API — HTTP adapter
//!
//! 对齐 platform_v4 真实表结构（rule_set / rule_set_entry / card_rule_set_ref）。
//! 数据访问在 `repository::rule_set_repository`，写路径副作用链
//! （规则集/卡片快照重建 + 缓存清除）编排在 `service::rule_set_write_service`。
//! HTTP 层仅解析参数、组装 DTO、包装响应。

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_types::AstralError;

use crate::api::require_platform_admin;
use crate::repository::audit_log_repository::RuleSetMutationContext;
use crate::repository::rule_set_repository::{CardRuleSetBindingRow, RuleSetSummary};
use crate::service::rule_set_write_service::{
    AddEntryRequest, BindCardRequest, CreateRuleSetRequest, UpdateEntryRequest,
    UpdateRuleSetRequest,
};
use crate::AppState;

/// 规则集响应 DTO（对齐前端 RuleSetItem camelCase 序列化）
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetDto {
    pub id: Option<i64>,
    pub name: String,
    pub ref_type: String,
    pub description: Option<String>,
    pub entry_count: i32,
    pub bound_card_count: i32,
}

impl From<RuleSetSummary> for RuleSetDto {
    fn from(s: RuleSetSummary) -> Self {
        Self {
            id: Some(s.id),
            name: s.name,
            ref_type: s.ref_type,
            description: s.description,
            entry_count: s.entry_count as i32,
            bound_card_count: s.bound_card_count as i32,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CardRuleSetBindingDto {
    pub rule_set_id: i64,
    pub rule_set_name: String,
    pub rule_set_code: String,
    pub ref_type: String,
}

impl From<CardRuleSetBindingRow> for CardRuleSetBindingDto {
    fn from(row: CardRuleSetBindingRow) -> Self {
        Self {
            rule_set_id: row.rule_set_id,
            rule_set_name: row.rule_set_name,
            rule_set_code: row.rule_set_code,
            ref_type: row.ref_type,
        }
    }
}

/// 规则集条目响应 DTO（对齐前端 RuleSetEntryItem）
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetEntryDto {
    pub id: Option<i64>,
    pub effect: String,
    pub resource: Option<String>,
    pub resource_id: Option<i64>,
    pub action: Option<String>,
    pub condition_json: Option<String>,
    pub priority: i32,
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

fn require_card_context(headers: &HeaderMap, card_id: i64) -> Result<(), AppError> {
    let context_card_id = headers
        .get("x-user-card-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok());
    if context_card_id != Some(card_id) {
        return Err(AppError(AstralError::Permission(
            "card context does not match requested card".into(),
        )));
    }
    // Gateway 已校验并签名 tenant/domain 头；卡片身份仍必须与路径 cardId 一致。
    Ok(())
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BindCardRequestDto {
    pub rule_set_id: i64,
    pub ref_type: String,
}

pub fn rule_set_routes() -> Router<crate::AppState> {
    Router::new()
        .route("/rule-sets", get(list_rule_sets))
        .route("/rule-sets", post(create_rule_set))
        .route("/rule-sets/{id}", get(get_rule_set))
        .route("/rule-sets/{id}", put(update_rule_set))
        .route("/rule-sets/{id}", delete(delete_rule_set))
        .route("/rule-sets/{id}/entries", get(list_entries))
        .route("/rule-sets/{id}/entries", post(add_entry))
        .route("/rule-sets/{id}/entries/batch", put(replace_entries))
        .route("/rule-sets/{id}/entries/{entry_id}", put(update_entry))
        .route("/rule-sets/{id}/entries/{entry_id}", delete(delete_entry))
        .route("/rule-sets/card/{card_id}/bind", post(bind_card_canonical))
        .route(
            "/rule-sets/card/{card_id}/unbind/{rule_set_id}",
            delete(unbind_card_canonical),
        )
        .route(
            "/rule-sets/card/{card_id}/bindings",
            get(list_card_bindings),
        )
        .route("/rule-sets/templates", get(list_templates))
}

async fn list_rule_sets(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<RuleSetDto>>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let total = state.rule_set_repository.count_rule_sets().await?;
    let rows = state
        .rule_set_repository
        .list_rule_sets(page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(RuleSetDto::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

async fn create_rule_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RuleSetDto>,
) -> Result<Json<ApiResponse<RuleSetDto>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = mutation_context(&headers)?;
    // 对齐 platform_v4：code (UNIQUE NOT NULL) 用 name 作为默认值，source_type 存储 ref_type
    let new_id = state
        .rule_set_write_service
        .create_rule_set(
            &CreateRuleSetRequest {
                name: req.name.clone(),
                ref_type: req.ref_type.clone(),
                description: req.description.clone(),
            },
            &context,
        )
        .await?;
    Ok(Json(ApiResponse::success(RuleSetDto {
        id: Some(new_id),
        ..req
    })))
}

async fn get_rule_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<RuleSetDto>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let dto = state
        .rule_set_repository
        .get_rule_set(id)
        .await?
        .map(RuleSetDto::from)
        .ok_or_else(|| {
            AppError(astral_types::AstralError::Internal(
                "Rule set not found".into(),
            ))
        })?;
    Ok(Json(ApiResponse::success(dto)))
}

async fn update_rule_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<RuleSetDto>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = mutation_context(&headers)?;
    // source_type 是所有权判别器，generic update 不可变：wire DTO 仍接受
    // `refType`（请求兼容），但它不再被转发为变更字段 —— repository 的 UPDATE
    // 不写 source_type，审计只记录实际变更的字段（name/description）。
    state
        .rule_set_write_service
        .update_rule_set(
            id,
            &UpdateRuleSetRequest {
                name: req.name,
                description: req.description,
            },
            &context,
        )
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn delete_rule_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = mutation_context(&headers)?;
    state
        .rule_set_write_service
        .delete_rule_set(id, &context)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn replace_entries(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(rs_id): Path<i64>,
    Json(entries): Json<Vec<RuleSetEntryDto>>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = mutation_context(&headers)?;
    let requests = entries
        .into_iter()
        .map(|entry| AddEntryRequest {
            effect: entry.effect,
            resource: entry.resource,
            resource_id: entry.resource_id,
            action: entry.action,
            condition_json: entry.condition_json,
            priority: entry.priority,
        })
        .collect::<Vec<_>>();
    state
        .rule_set_write_service
        .replace_entries(rs_id, &requests, &context)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn bind_card_canonical(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(card_id): Path<i64>,
    Json(req): Json<BindCardRequestDto>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = mutation_context(&headers)?;
    require_card_context(&headers, card_id)?;
    state
        .rule_set_write_service
        .bind_card(
            req.rule_set_id,
            &BindCardRequest {
                card_id,
                ref_type: req.ref_type,
            },
            &context,
        )
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn unbind_card_canonical(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((card_id, rule_set_id)): Path<(i64, i64)>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = mutation_context(&headers)?;
    require_card_context(&headers, card_id)?;
    state
        .rule_set_write_service
        .unbind_card(
            rule_set_id,
            &BindCardRequest {
                card_id,
                ref_type: "BASE".into(),
            },
            &context,
        )
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn list_card_bindings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(card_id): Path<i64>,
) -> Result<Json<ApiResponse<Vec<CardRuleSetBindingDto>>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    require_card_context(&headers, card_id)?;
    let rows = state
        .rule_set_write_service
        .list_card_bindings(card_id)
        .await?
        .into_iter()
        .map(CardRuleSetBindingDto::from)
        .collect();
    Ok(Json(ApiResponse::success(rows)))
}

async fn list_entries(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(rs_id): Path<i64>,
) -> Result<Json<ApiResponse<Vec<RuleSetEntryDto>>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let rows = state
        .rule_set_repository
        .list_entries(rs_id)
        .await?
        .into_iter()
        .map(|e| RuleSetEntryDto {
            id: Some(e.entry_id),
            effect: e.effect,
            resource: e.resource_type,
            resource_id: e.resource_id,
            action: e.action_code,
            condition_json: e.condition_json,
            priority: e.priority,
        })
        .collect();
    Ok(Json(ApiResponse::success(rows)))
}

async fn add_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(rs_id): Path<i64>,
    Json(req): Json<RuleSetEntryDto>,
) -> Result<Json<ApiResponse<RuleSetEntryDto>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = mutation_context(&headers)?;
    // 对齐 platform_v4：resource_type, action_code, enabled=1
    let entry_id = state
        .rule_set_write_service
        .add_entry(
            rs_id,
            &AddEntryRequest {
                effect: req.effect.clone(),
                resource: req.resource.clone(),
                resource_id: req.resource_id,
                action: req.action.clone(),
                condition_json: req.condition_json.clone(),
                priority: req.priority,
            },
            &context,
        )
        .await?;
    Ok(Json(ApiResponse::success(RuleSetEntryDto {
        id: Some(entry_id),
        ..req
    })))
}

async fn update_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((rs_id, eid)): Path<(i64, i64)>,
    Json(req): Json<RuleSetEntryDto>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = mutation_context(&headers)?;
    // 对齐 platform_v4：resource_type, action_code, entry_id
    state
        .rule_set_write_service
        .update_entry(
            rs_id,
            eid,
            &UpdateEntryRequest {
                effect: req.effect,
                resource: req.resource,
                resource_id: req.resource_id,
                action: req.action,
                condition_json: req.condition_json,
                priority: req.priority,
            },
            &context,
        )
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn delete_entry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((rs_id, eid)): Path<(i64, i64)>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = mutation_context(&headers)?;
    state
        .rule_set_write_service
        .delete_entry(rs_id, eid, &context)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn list_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<RuleSetDto>>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let total = state.rule_set_repository.count_templates().await?;
    let rows = state
        .rule_set_repository
        .list_templates(page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(RuleSetDto::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn canonical_user_card_context_must_match() {
        let mut headers = HeaderMap::new();
        headers.insert("x-user-card-id", HeaderValue::from_static("7"));
        assert!(require_card_context(&headers, 7).is_ok());
        assert!(matches!(
            require_card_context(&headers, 8),
            Err(AppError(AstralError::Permission(_)))
        ));
    }

    #[test]
    fn rule_set_dto_wire_contract_still_accepts_ref_type() {
        // wire 兼容性锁定：refType 仍是公开请求/响应契约的一部分。generic update
        // 在 service/repository 层把它当只读所有权展示，不再作为变更字段转发；
        // create 仍接受它（空/TEMPLATE 由所有权预留门禁在 mutation 前拒绝）。
        let dto: RuleSetDto = serde_json::from_str(
            r#"{"id":1,"name":"n","refType":"BASE","description":null,
                "entryCount":0,"boundCardCount":0}"#,
        )
        .expect("refType must remain part of the public wire contract");
        assert_eq!(dto.ref_type, "BASE");
        let serialized = serde_json::to_string(&dto).expect("dto must serialize");
        assert!(serialized.contains("\"refType\":\"BASE\""));
    }
}
