//! 卡片管理 API — HTTP adapter
//!
//! 对应 Java `CardController`。卡片 CRUD 在 `CardRepository`，
//! 切卡会话旋转保留在 `session::switch_card_session`。

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::Deserialize;

use astral_common::audit::{
    global_audit_dual_write, record_audit, AuditCategory, AuditEntry, AuditEventType,
};
use astral_common::contract::{ApiResponse, EmptyResponse};
use astral_common::error::AppError;
use astral_common::middleware::permission::extract_user_id;
use astral_types::UserCard;

use crate::auth::LoginResponse;
use crate::srv::card_repository::CardFilter;
use crate::srv::session::switch_card_session;
use crate::AppState;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCardRequest {
    pub template_id: i64,
    pub card_name: Option<String>,
    pub domain_id: Option<i64>,
    pub tenant_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SwitchCardRequest {
    pub target_user_card_id: i64,
    pub device_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CardStatusRequest {
    pub status: String,
}

/// Record card-switch attempts without changing the session-rotation result.
///
/// The audit writer keeps MQ-first/DB-fallback semantics; when it is not
/// initialized, structured tracing remains the observable fallback.
fn spawn_card_switch_audit(headers: &HeaderMap, target_card_id: i64, allowed: bool) {
    let entry = AuditEntry {
        user_id: extract_user_id(headers),
        card_id: (target_card_id > 0).then_some(target_card_id),
        action: "switch".into(),
        resource: "identity_card".into(),
        decision: if allowed { "ALLOW" } else { "DENY" }.into(),
        reason: Some(
            if allowed {
                "CARD_SWITCH_SUCCESS"
            } else {
                "CARD_SWITCH_FAILED"
            }
            .into(),
        ),
        event_type: AuditEventType::CardSwitch,
        category: Some(AuditCategory::CardSwitch),
        source_ip: headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        request_id: headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        domain_id: None,
        tenant_id: None,
        detail: Some(format!("targetCardId={target_card_id}")),
    };

    let Some(writer) = global_audit_dual_write() else {
        record_audit(entry);
        return;
    };
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.spawn(async move {
            writer.write(entry).await;
        });
    } else {
        record_audit(entry);
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CardQuery {
    pub user_id: Option<i64>,
    pub status: Option<String>,
}

pub fn card_routes() -> Router<AppState> {
    Router::new()
        .route("/cards", post(create_card))
        .route("/cards", get(list_cards))
        .route("/cards/{id}", get(get_card))
        .route("/cards/{id}/status", put(update_card_status))
        .route("/cards/{id}", put(update_card))
        .route("/sessions/switch-card", post(switch_card))
}

async fn create_card(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateCardRequest>,
) -> Result<Json<ApiResponse<UserCard>>, AppError> {
    let user_id = require_user_id(&headers)?;
    state
        .card_repository
        .find_active_identity_card(user_id)
        .await?
        .ok_or_else(|| {
            AppError(astral_types::AstralError::NotFound(format!(
                "no active identity_card for user {user_id}"
            )))
        })?;
    // 问题 1 修正：身份卡不承担组织归属，identity 头不再注入。
    // 请求 scope 与当前授权 user-card 的 scope 一致才允许创建。
    let user_card_tenant_id = headers
        .get("x-user-card-tenant-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok());
    let user_card_domain_id = headers
        .get("x-user-card-domain-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok());
    if req.tenant_id != user_card_tenant_id || req.domain_id != user_card_domain_id {
        return Err(AppError(astral_types::AstralError::Permission(
            "Card scope must match current user-card scope".into(),
        )));
    }
    // 卡创建是授权 source mutation：actor 必须是 Gateway 已验证的 x-user-id；
    // 可选 x-request-id 经统一安全校验后作为稳定 operation id（缺失时由
    // repository 以 durable 代次确定性派生，随机 fallback 绝不进入账本）。
    Ok(Json(ApiResponse::success(
        state
            .card_repository
            .create_user_card(
                user_id,
                req.domain_id,
                req.tenant_id,
                req.template_id,
                user_id,
                request_operation_id(&headers),
            )
            .await?,
    )))
}

async fn list_cards(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<CardQuery>,
) -> Result<Json<ApiResponse<Vec<UserCard>>>, AppError> {
    let user_id = require_user_id(&headers)?;
    let requested_status = q.status;
    Ok(Json(ApiResponse::success(
        state
            .card_repository
            .list_user_cards(CardFilter {
                user_id: Some(user_id),
                status: requested_status,
            })
            .await?,
    )))
}

async fn get_card(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<UserCard>>, AppError> {
    let user_id = require_user_id(&headers)?;
    let card = owned_card(&state, id, user_id, &headers).await?;
    Ok(Json(ApiResponse::success(card)))
}

async fn update_card_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<CardStatusRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let user_id = require_user_id(&headers)?;
    let _ = owned_card(&state, id, user_id, &headers).await?;
    state
        .card_repository
        .update_user_card_status(id, &req.status, user_id, request_operation_id(&headers))
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

/// POST /api/v1/auth/sessions/switch-card — durable card session rotation.
async fn switch_card(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SwitchCardRequest>,
) -> Result<Json<ApiResponse<LoginResponse>>, AppError> {
    let response = switch_card_session(
        &state,
        &headers,
        req.target_user_card_id,
        req.device_id.as_deref(),
    )
    .await;
    spawn_card_switch_audit(&headers, req.target_user_card_id, response.is_ok());
    let response = response?;
    Ok(Json(ApiResponse::success(response)))
}

async fn update_card(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<CreateCardRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let user_id = require_user_id(&headers)?;
    let card = owned_card(&state, id, user_id, &headers).await?;
    if req.tenant_id != card.tenant_id || req.domain_id != card.domain_id {
        return Err(AppError(astral_types::AstralError::Permission(
            "Card scope changes are not allowed from self-service".into(),
        )));
    }
    state
        .card_repository
        .update_user_card(
            id,
            req.template_id,
            req.domain_id,
            req.tenant_id,
            user_id,
            request_operation_id(&headers),
        )
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

/// 提取可选的 `x-request-id`（已 trim；空白视为缺失），供 repository 的统一
/// operation identity 门禁复用为 durable operation id。
fn request_operation_id(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

async fn owned_card(
    state: &AppState,
    card_id: i64,
    user_id: i64,
    headers: &HeaderMap,
) -> Result<UserCard, AppError> {
    let card = state
        .card_repository
        .get_user_card(card_id)
        .await?
        .ok_or_else(|| AppError(astral_types::AstralError::NotFound("Card not found".into())))?;
    if card.user_id != Some(user_id) || card.card_status != "ACTIVE" {
        return Err(AppError(astral_types::AstralError::Permission(
            "Card ownership denied".into(),
        )));
    }
    let tenant_id = headers
        .get("x-user-card-tenant-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok());
    let domain_id = headers
        .get("x-user-card-domain-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok());
    if tenant_id != card.tenant_id || domain_id != card.domain_id {
        return Err(AppError(astral_types::AstralError::Permission(
            "Card scope denied".into(),
        )));
    }
    Ok(card)
}

fn require_user_id(headers: &HeaderMap) -> Result<i64, AppError> {
    headers
        .get("X-User-Id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| {
            AppError(astral_types::AstralError::Auth(
                "X-User-Id header required".into(),
            ))
        })
}
