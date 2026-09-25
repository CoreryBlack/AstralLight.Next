//! /me 系列端点 — 当前用户的卡片、身份、权限、菜单
//!
//! 对应 Java `IdentitySessionController`，查询和业务编排由 `MeService` 负责。

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::get;
use axum::{Json, Router};

use astral_common::contract::ApiResponse;
use astral_common::error::AppError;
use astral_common::middleware::permission::extract_user_id;

use crate::AppState;

/// Java `MenuService` 返回的菜单 key。
pub type MenuItem = String;

/// 用户卡片上下文（对齐前端 UserCardContext 类型）。
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserCardContext {
    pub card_id: i64,
    pub card_name: Option<String>,
    pub card_type: String,
    pub domain_id: Option<i64>,
    pub tenant_id: Option<i64>,
    pub status: String,
    pub template_code: Option<String>,
    pub token_version: Option<i64>,
    pub expires_at: Option<i64>,
    pub is_default: Option<bool>,
    pub is_starter: Option<bool>,
    pub action_codes: Vec<String>,
    pub rule_set_ids: Vec<i64>,
    pub overlay_rule_set_ids: Vec<i64>,
    pub structure_node_id: Option<i64>,
}

pub fn me_routes() -> Router<AppState> {
    Router::new()
        .route("/me", get(get_my_profile))
        .route("/me/cards", get(list_my_cards))
        .route("/me/identities", get(list_my_identities))
        .route("/me/permissions", get(list_my_permissions))
        .route("/me/menus", get(list_my_menus))
}

/// GET /api/v1/auth/me — 当前用户基本信息。
async fn get_my_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let user_id = require_user_id(&headers)?;
    let profile = state.me_service.profile(user_id).await?;

    let response = match profile {
        Some(profile) => serde_json::json!({
            "userId": profile.user_id,
            "displayName": profile.display_name,
            "email": profile.email,
            "phone": profile.phone,
            "status": profile.status,
            "domainId": profile.domain_id,
            "tenantId": profile.tenant_id,
        }),
        None => serde_json::json!({
            "userId": user_id,
            "displayName": null,
            "email": null,
            "phone": null,
            "status": "UNKNOWN",
            "domainId": null,
            "tenantId": null,
        }),
    };

    Ok(Json(ApiResponse::success(response)))
}

/// GET /api/v1/auth/me/cards — 列出当前用户的可用卡片。
async fn list_my_cards(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<Vec<UserCardContext>>>, AppError> {
    let user_id = require_user_id(&headers)?;
    Ok(Json(ApiResponse::success(
        state.me_service.cards(user_id).await?,
    )))
}

/// GET /api/v1/auth/me/identities — 列出当前用户的身份列表。
async fn list_my_identities(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<Vec<serde_json::Value>>>, AppError> {
    let user_id = require_user_id(&headers)?;
    Ok(Json(ApiResponse::success(
        state.me_service.identities(user_id).await?,
    )))
}

/// GET /api/v1/auth/me/permissions — 列出当前用户的有效权限。
async fn list_my_permissions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<Vec<String>>>, AppError> {
    let user_id = require_user_id(&headers)?;
    let card_id = requested_card_id(&headers);
    let permissions = state.me_service.permissions(user_id, card_id).await?;

    tracing::debug!(user_id, card_id = ?card_id, count = permissions.len(), "listed effective permissions");
    Ok(Json(ApiResponse::success(permissions)))
}

/// GET /api/v1/auth/me/menus — 列出当前用户可访问的菜单。
async fn list_my_menus(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<Vec<MenuItem>>>, AppError> {
    let user_id = require_user_id(&headers)?;
    let menus = state
        .me_service
        .menus(user_id, requested_card_id(&headers))
        .await?;
    Ok(Json(ApiResponse::success(menus)))
}

fn require_user_id(headers: &HeaderMap) -> Result<i64, AppError> {
    extract_user_id(headers).ok_or_else(|| {
        AppError(astral_types::AstralError::Auth(
            "X-User-Id header required".into(),
        ))
    })
}

fn requested_card_id(headers: &HeaderMap) -> Option<i64> {
    headers
        .get("x-user-card-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
}
