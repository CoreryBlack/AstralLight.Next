//! 用户管理 API — HTTP adapter
//!
//! 对应 Java `UsersController`。编排在 `UserService`。

use axum::extract::{Extension, Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};

use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse};
use astral_common::error::AppError;
use astral_types::{AuthorizationAdmission, UserCard};

use crate::srv::user_service::{
    CreateUserRequest, SetPasswordRequest, UpdateStatusRequest, UpdateUserRequest, UserListItem,
    UserQuery,
};
use crate::AppState;

/// 用户管理路由
pub fn user_routes() -> Router<AppState> {
    Router::new()
        .route("/users", get(list_users).post(create_user))
        .route("/users/{id}", get(get_user).put(update_user))
        .route("/users/{id}/status", put(update_user_status))
        .route("/users/{id}", delete(delete_user))
        .route("/users/{id}/cards", get(list_user_cards))
        .route("/users/{id}/password", post(set_password))
}

fn validated_request_operation_id(headers: &HeaderMap) -> Result<Option<String>, AppError> {
    let raw = headers
        .get("x-request-id")
        .map(|value| {
            value
                .to_str()
                .map_err(|_| astral_types::AstralError::Validation("invalid x-request-id".into()))
        })
        .transpose()
        .map_err(AppError::from)?;
    astral_db::grant_ledger::validated_request_operation_id(raw).map_err(AppError::from)
}

async fn list_users(
    State(state): State<AppState>,
    Query(query): Query<UserQuery>,
) -> Result<Json<ApiResponse<PageResponse<UserListItem>>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.user_service.list_users(&state, &query).await?,
    )))
}

async fn create_user(
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.user_service.create_user(&state, &req).await?,
    )))
}

async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.user_service.get_user(&state, id).await?,
    )))
}

async fn update_user(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    admission: Option<Extension<AuthorizationAdmission>>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let request_operation_id = validated_request_operation_id(&headers)?;
    let admission = admission.map(|Extension(value)| value);
    state
        .user_service
        .update_user(&state, id, &req, request_operation_id.as_deref(), admission)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn update_user_status(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Extension(admission): Extension<AuthorizationAdmission>,
    Json(req): Json<UpdateStatusRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let request_operation_id = validated_request_operation_id(&headers)?;
    state
        .user_service
        .update_user_status(&state, id, &req, request_operation_id.as_deref(), admission)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn delete_user(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    Extension(admission): Extension<AuthorizationAdmission>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let request_operation_id = validated_request_operation_id(&headers)?;
    state
        .user_service
        .delete_user(&state, id, request_operation_id.as_deref(), admission)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn list_user_cards(
    State(state): State<AppState>,
    Path(user_id): Path<i64>,
) -> Result<Json<ApiResponse<Vec<UserCard>>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.user_service.list_user_cards(&state, user_id).await?,
    )))
}

async fn set_password(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Extension(admission): Extension<AuthorizationAdmission>,
    Json(req): Json<SetPasswordRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.user_service.set_password(id, &req, admission).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

#[cfg(test)]
mod tests {
    /// 源形状守卫：`update_user` 是唯一允许缺失 admission 的用户写 handler
    ///（profile-only metadata 更新为明确非资格语义；status-bearing 分支由
    /// `UserService::update_user` 在任何 durable 副作用之前 fail-closed 要求
    /// admission），必须可选提取并转发 admission；status/delete/password 等
    /// 必然影响有效资格或凭证的 handler 必须保持必选提取。
    #[test]
    fn user_update_handler_extracts_optional_admission_and_required_handlers_keep_extraction() {
        let source = include_str!("users.rs");

        // update_user：可选提取 + 转发（缺失时由 service 在 session revoke 之前 PENDING）。
        let update_start = source
            .find("async fn update_user(")
            .expect("update_user handler must stay in users.rs");
        let update_end = source[update_start..]
            .find("async fn update_user_status(")
            .expect("update_user body boundary must exist");
        let update_body = &source[update_start..update_start + update_end];
        assert!(
            update_body.contains("admission: Option<Extension<AuthorizationAdmission>>"),
            "update_user must keep the optional admission extraction"
        );
        assert!(
            update_body.contains("admission.map(|Extension(value)| value)"),
            "update_user must forward the admission into the service"
        );

        // 资格/凭证写入 handler：必选提取，缺失时 axum 直接拒绝请求。
        for (handler, next_anchor) in [
            ("async fn update_user_status(", "async fn delete_user("),
            ("async fn delete_user(", "async fn list_user_cards("),
            ("async fn set_password(", "#[cfg(test)]"),
        ] {
            let start = source
                .find(handler)
                .unwrap_or_else(|| panic!("{handler} handler must stay in users.rs"));
            let end = source[start..]
                .find(next_anchor)
                .unwrap_or_else(|| panic!("{handler} body boundary must exist"));
            let body = &source[start..start + end];
            assert!(
                body.contains("Extension(admission): Extension<AuthorizationAdmission>"),
                "{handler} must keep the required admission extraction"
            );
        }
    }
}
