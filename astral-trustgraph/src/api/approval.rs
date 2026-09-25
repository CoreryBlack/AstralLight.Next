//! 权限审批流 — HTTP adapter
//!
//! 数据访问在 `repository::permission_request_repository`，审批编排
//! （事务 + 异步副作用链）在 `service::approval_service`。
//! HTTP 层仅解析参数、组装前端兼容 DTO、包装响应。

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;

use crate::api::require_platform_admin;
use crate::repository::permission_request_repository::{NewRequest, PermissionRequestRecord};
use crate::AppState;

/// Java/前端 canonical RULE 内容。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestContent {
    pub resource_type: String,
    pub action_code: String,
    pub card_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effect: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition_json: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<String>,
}

impl RequestContent {
    fn normalize(&mut self) -> Result<(), AppError> {
        self.resource_type = self.resource_type.trim().to_string();
        self.action_code = self.action_code.trim().to_string();
        // fail-closed：canonical RULE 请求只接受 ALLOW（大小写归一后回写）；
        // 拒绝结果由 PolicyEngine DEFAULT_DENY/PENDING 表达，不作为 grant 提交。
        if let Some(raw) = self.effect.as_deref() {
            let normalized =
                crate::service::validate_canonical_grant_effect(raw).map_err(AppError::from)?;
            self.effect = Some(normalized);
        }
        Ok(())
    }

    fn into_value(self) -> serde_json::Value {
        serde_json::to_value(self).expect("RequestContent is serializable")
    }
}

fn normalize_request_type(raw: &str) -> Result<String, AppError> {
    let request_type = raw.trim().to_uppercase();
    if !matches!(
        request_type.as_str(),
        "RULE" | "LEVEL_UP" | "TEMP_PERMISSION"
    ) {
        return Err(AppError(astral_types::AstralError::Validation(
            "unsupported permission request type".into(),
        )));
    }
    Ok(request_type)
}

fn normalize_rule_content(
    value: &serde_json::Value,
) -> Result<(RequestContent, serde_json::Value), AppError> {
    if !value.is_object() {
        return Err(AppError(astral_types::AstralError::Validation(
            "requestContent must be an object".into(),
        )));
    }
    let mut content: RequestContent = serde_json::from_value(value.clone()).map_err(|_| {
        AppError(astral_types::AstralError::Validation(
            "RULE requestContent requires resourceType/actionCode and optional cardId".into(),
        ))
    })?;
    content.normalize()?;
    if content.resource_type.is_empty() || content.action_code.is_empty() {
        return Err(AppError(astral_types::AstralError::Validation(
            "RULE resourceType and actionCode must not be empty".into(),
        )));
    }
    let normalized = content.clone().into_value();
    Ok((content, normalized))
}

/// Java/前端 canonical 提交 DTO。request_content 保留原始 JSON，审批服务按 request_type
/// 分派；认证身份只从 Gateway 注入的 x-user-id 读取。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionRequestSubmit {
    pub request_type: String,
    pub request_content: serde_json::Value,
    pub reason: Option<String>,
}

/// `permission_request` 响应 DTO（前端兼容：展开 RULE 内容）
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequest {
    pub id: Option<i64>,
    pub requester_id: i64,
    pub request_type: String,
    pub request_content: serde_json::Value,
    pub resource: String,
    pub action: String,
    pub reason: Option<String>,
    pub status: String,
    pub reviewer_id: Option<i64>,
    pub review_comment: Option<String>,
    pub card_id: Option<i64>,
    pub created_at: Option<String>,
}

/// 从 DB Row + 解析 request_content JSON 构造前端兼容 DTO
fn row_to_dto(r: PermissionRequestRecord) -> PermissionRequest {
    let request_content = r
        .request_content
        .as_deref()
        .and_then(|value| serde_json::from_str(value).ok())
        .unwrap_or(serde_json::Value::Null);
    let content = serde_json::from_value::<RequestContent>(request_content.clone()).ok();
    PermissionRequest {
        id: Some(r.request_id),
        requester_id: r.user_id,
        request_type: r.request_type,
        request_content,
        resource: content
            .as_ref()
            .map(|c| c.resource_type.clone())
            .unwrap_or_default(),
        action: content
            .as_ref()
            .map(|c| c.action_code.clone())
            .unwrap_or_default(),
        reason: r.reason,
        status: r.status,
        reviewer_id: r.approver_id,
        review_comment: r.approve_comment,
        card_id: content.and_then(|c| c.card_id),
        created_at: r.created_at,
    }
}

fn verified_reviewer_id(headers: &HeaderMap) -> Result<i64, AppError> {
    astral_common::middleware::permission::extract_user_id(headers)
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            AppError(astral_types::AstralError::Auth(
                "reviewer_identity_required".into(),
            ))
        })
}

fn request_id_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApprovalAction {
    pub comment: Option<String>,
}

pub fn approval_routes() -> Router<AppState> {
    Router::new()
        .route("/permission-requests", post(create_request))
        .route("/permission-requests", get(list_requests))
        .route("/permission-requests/mine", get(list_my_requests))
        .route("/permission-requests/{id}", get(get_request))
        .route("/permission-requests/{id}/cancel", post(cancel_request))
        .route("/permission-requests/{id}/approve", post(approve_request))
        .route("/permission-requests/{id}/reject", post(reject_request))
        .route("/permission-requests/pending", get(list_pending))
}

async fn create_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PermissionRequestSubmit>,
) -> Result<Json<ApiResponse<PermissionRequest>>, AppError> {
    let requester_id = headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|id| *id > 0)
        .ok_or_else(|| {
            AppError(astral_types::AstralError::Auth(
                "x-user-id header required".into(),
            ))
        })?;
    let request_type = normalize_request_type(&req.request_type)?;
    if request_type != "RULE" {
        return Err(AppError(astral_types::AstralError::NotImplemented(
            format!("permission request type {request_type} approval is not implemented"),
        )));
    }
    let (_, content_value) = normalize_rule_content(&req.request_content)?;
    let content = serde_json::to_string(&content_value).map_err(|error| {
        AppError(astral_types::AstralError::Validation(format!(
            "invalid requestContent: {error}"
        )))
    })?;
    let request_id = state
        .approval_service
        .create_request(&NewRequest {
            user_id: requester_id,
            request_type: request_type.clone(),
            request_content: content.clone(),
            reason: req.reason.clone(),
        })
        .await?;
    Ok(Json(ApiResponse::success(PermissionRequest {
        id: Some(request_id),
        requester_id,
        request_type,
        request_content: content_value.clone(),
        resource: content_value
            .get("resourceType")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        action: content_value
            .get("actionCode")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string(),
        reason: req.reason,
        status: "PENDING".into(),
        reviewer_id: None,
        review_comment: None,
        card_id: serde_json::from_str::<RequestContent>(&content)
            .ok()
            .and_then(|c| c.card_id),
        created_at: None,
    })))
}

async fn list_my_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<PermissionRequest>>>, AppError> {
    let user_id = verified_reviewer_id(&headers)?;
    let total = state
        .permission_request_repository
        .count_for_user(user_id)
        .await?;
    let rows = state
        .permission_request_repository
        .list_for_user(user_id, page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(row_to_dto)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

async fn cancel_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    body: Option<Json<ApprovalAction>>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let user_id = verified_reviewer_id(&headers)?;
    state
        .permission_request_repository
        .cancel_request(
            id,
            user_id,
            body.as_ref()
                .and_then(|Json(action)| action.comment.as_deref()),
            request_id_header(&headers),
        )
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn list_requests(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<PermissionRequest>>>, AppError> {
    // 全表权限申请列表超出 Java 契约（Java 无全表端点，前端 canonical 只走 /mine），
    // 仅允许已验证的 ACTIVE GlobalAdmin 查看，避免普通 operator 读取全库申请。
    require_platform_admin(&state, &headers).await?;
    let total = state.permission_request_repository.count_all().await?;
    let rows = state
        .permission_request_repository
        .list_all(page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(row_to_dto)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

async fn get_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<PermissionRequest>>, AppError> {
    let user_id = verified_reviewer_id(&headers)?;
    let r = state
        .permission_request_repository
        .get_request_for_user(id, user_id)
        .await?
        .ok_or_else(|| {
            AppError(astral_types::AstralError::NotFound(
                "Request not found".into(),
            ))
        })?;
    Ok(Json(ApiResponse::success(row_to_dto(r))))
}

async fn approve_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    body: Option<Json<ApprovalAction>>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let reviewer_id = verified_reviewer_id(&headers)?;
    state
        .approval_service
        .approve(
            id,
            reviewer_id,
            body.as_ref()
                .and_then(|Json(action)| action.comment.as_deref()),
            request_id_header(&headers),
        )
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn reject_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    body: Option<Json<ApprovalAction>>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let reviewer_id = verified_reviewer_id(&headers)?;
    state
        .approval_service
        .reject(
            id,
            reviewer_id,
            body.as_ref()
                .and_then(|Json(action)| action.comment.as_deref()),
            request_id_header(&headers),
        )
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn list_pending(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<PermissionRequest>>>, AppError> {
    // Java 权威无 /pending 端点；全库 PENDING 列表同样仅限已验证 ACTIVE GlobalAdmin。
    require_platform_admin(&state, &headers).await?;
    let total = state.permission_request_repository.count_pending().await?;
    let rows = state
        .permission_request_repository
        .list_pending(page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(row_to_dto)
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

    #[test]
    fn canonical_rule_content_is_normalized_and_preserved() {
        let (content, value) = normalize_rule_content(&serde_json::json!({
            "resourceType": "  learn_course ",
            "actionCode": " read ",
            "cardId": 7
        }))
        .expect("canonical RULE content should be valid");

        assert_eq!(content.resource_type, "learn_course");
        assert_eq!(content.action_code, "read");
        assert_eq!(content.card_id, Some(7));
        assert_eq!(value["resourceType"], "learn_course");
        assert_eq!(value["actionCode"], "read");
        assert_eq!(value["cardId"], 7);
    }

    #[test]
    fn rule_submission_effect_is_allow_only() {
        let (content, value) = normalize_rule_content(&serde_json::json!({
            "resourceType": "learn_course",
            "actionCode": "read",
            "cardId": 7,
            "effect": " allow "
        }))
        .expect("case-insensitive ALLOW must be accepted");
        assert_eq!(content.effect.as_deref(), Some("ALLOW"));
        assert_eq!(value["effect"], "ALLOW");

        for rejected in ["DENY", "deny", "GRANT", "", "   "] {
            let error = normalize_rule_content(&serde_json::json!({
                "resourceType": "learn_course",
                "actionCode": "read",
                "cardId": 7,
                "effect": rejected
            }))
            .expect_err("non-ALLOW RULE effect must be rejected at submit time");
            assert!(
                matches!(
                    &error,
                    AppError(astral_types::AstralError::Validation(message))
                        if message.contains("ALLOW")
                ),
                "rejected={rejected:?} unexpected={error:?}"
            );
        }
    }

    #[test]
    fn legacy_rule_aliases_are_rejected() {
        let error = normalize_rule_content(&serde_json::json!({
            "resource": "learn_course",
            "action": "read",
            "card_id": 7
        }))
        .expect_err("legacy RULE aliases must be rejected");
        assert!(matches!(error.0, astral_types::AstralError::Validation(_)));
    }

    #[test]
    fn legacy_approval_action_alias_is_rejected() {
        let error = serde_json::from_value::<ApprovalAction>(serde_json::json!({
            "approveComment": "legacy"
        }))
        .expect_err("legacy approval action field must be rejected");
        assert!(matches!(error, serde_json::Error { .. }));
    }

    #[test]
    fn unknown_submit_field_is_rejected() {
        let error = serde_json::from_value::<PermissionRequestSubmit>(serde_json::json!({
            "requestType": "RULE",
            "requestContent": {
                "resourceType": "learn_course",
                "actionCode": "read"
            },
            "reason": "test",
            "request_type": "RULE"
        }))
        .expect_err("unknown submit field must be rejected");
        assert!(matches!(error, serde_json::Error { .. }));
    }

    #[test]
    fn unknown_request_type_is_validation_error() {
        let error = normalize_request_type("UNKNOWN").expect_err("unknown type must be rejected");
        assert!(matches!(error.0, astral_types::AstralError::Validation(_)));
    }

    #[test]
    fn known_unimplemented_request_types_are_not_implemented() {
        for request_type in ["LEVEL_UP", "TEMP_PERMISSION"] {
            let normalized = normalize_request_type(request_type).unwrap();
            let error = AppError(astral_types::AstralError::NotImplemented(format!(
                "permission request type {normalized} approval is not implemented"
            )));
            assert!(matches!(
                error.0,
                astral_types::AstralError::NotImplemented(_)
            ));
        }
    }

    #[test]
    fn malformed_rule_content_is_rejected() {
        let error = normalize_rule_content(&serde_json::json!({
            "resourceType": "",
            "actionCode": "read"
        }))
        .expect_err("empty resource type must be rejected");
        assert!(matches!(error.0, astral_types::AstralError::Validation(_)));
    }

    #[test]
    fn request_id_header_ignores_missing_blank_and_invalid_values() {
        let mut headers = HeaderMap::new();
        assert_eq!(request_id_header(&headers), None);
        headers.insert("x-request-id", "   ".parse().unwrap());
        assert_eq!(request_id_header(&headers), None);
        headers.insert("x-request-id", "approval-request-42".parse().unwrap());
        assert_eq!(request_id_header(&headers), Some("approval-request-42"));
    }
}
