//! 群组 API
//!
//! 对应 Java `GroupController` + `GroupServiceImpl`。
//! 基于 chat_conversation (conversation_type='GROUP') + chat_conversation_member 表。
//! 数据访问在 `repository::conversation_repository` / `repository::member_repository`，
//! 角色校验与编排在 `service::group_service`。HTTP 层仅解析参数、组装 DTO。
//!
//! 群组角色体系: OWNER > ADMIN > MEMBER
//! - OWNER: 全部权限（解散、转让、任免管理员、踢人）
//! - ADMIN: 编辑群信息、加人、踢普通成员
//! - MEMBER: 查看、发言、退群

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;

use super::util::current_chat_scope;
use crate::repository::conversation_repository::GroupPatch;
use crate::AppState;

// ===== Response types =====

/// 群组响应
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct GroupResponse {
    pub id: i64,
    pub name: String,
    pub conversation_type: String,
    pub owner_id: Option<i64>,
    pub avatar: Option<String>,
    pub max_members: i64,
    pub status: String,
    pub member_count: i64,
    pub created_at: Option<i64>,
}

/// 群组成员响应
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct GroupMemberResponse {
    pub user_id: i64,
    pub role: String,
    pub nickname: Option<String>,
    pub muted: bool,
    pub pinned: bool,
    pub joined_at: Option<i64>,
}

// ===== Request types =====

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateGroupRequest {
    pub name: String,
    #[serde(default)]
    pub avatar: Option<String>,
    #[serde(default = "default_max_members")]
    pub max_members: i64,
}

fn default_max_members() -> i64 {
    500
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateGroupRequest {
    pub name: Option<String>,
    pub avatar: Option<String>,
    pub max_members: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddMemberRequest {
    pub user_id: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferOwnerRequest {
    pub new_owner_id: i64,
}

// ===== Routes =====

pub fn group_routes() -> Router<AppState> {
    Router::new()
        .route("/groups", post(create_group))
        .route("/groups", get(list_groups))
        .route("/groups/{id}", get(get_group))
        .route("/groups/{id}", put(update_group))
        .route("/groups/{id}", delete(disband_group))
        .route("/groups/{id}/members", get(list_members))
        .route("/groups/{id}/members", post(add_member))
        .route("/groups/{id}/members/{user_id}", delete(remove_member))
        .route("/groups/{id}/transfer-owner", put(transfer_owner))
}

// ===== Handlers =====

/// POST /v1/chat/groups — 创建群组
async fn create_group(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<Json<ApiResponse<GroupResponse>>, AppError> {
    let scope = current_chat_scope(&headers)?;
    let group = state
        .group_service
        .create_group(&scope, req.name, req.avatar, req.max_members)
        .await?;
    Ok(Json(ApiResponse::success(group)))
}

/// GET /v1/chat/groups — 列出当前用户加入的群组（分页）
async fn list_groups(
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<GroupResponse>>>, AppError> {
    let scope = current_chat_scope(&headers)?;
    let page = params.page.max(1);
    let size = params.effective_size();
    let result = state.group_service.list_groups(&scope, page, size).await?;
    Ok(Json(ApiResponse::success(result)))
}

/// GET /v1/chat/groups/{id} — 获取群组详情（验证成员资格）
async fn get_group(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<GroupResponse>>, AppError> {
    let scope = current_chat_scope(&headers)?;
    let group = state.group_service.get_group(&scope, id).await?;
    Ok(Json(ApiResponse::success(group)))
}

/// PUT /v1/chat/groups/{id} — 更新群组信息（OWNER/ADMIN 可操作）
async fn update_group(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateGroupRequest>,
) -> Result<Json<ApiResponse<GroupResponse>>, AppError> {
    let scope = current_chat_scope(&headers)?;
    let patch = GroupPatch {
        name: req.name,
        avatar: req.avatar,
        max_members: req.max_members,
    };
    let group = state.group_service.update_group(&scope, id, patch).await?;
    Ok(Json(ApiResponse::success(group)))
}

/// DELETE /v1/chat/groups/{id} — 解散群组（仅 OWNER）
async fn disband_group(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<GroupResponse>>, AppError> {
    let scope = current_chat_scope(&headers)?;
    let group = state.group_service.disband_group(&scope, id).await?;
    Ok(Json(ApiResponse::success(group)))
}

/// GET /v1/chat/groups/{id}/members — 列出群组成员（分页）
async fn list_members(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<GroupMemberResponse>>>, AppError> {
    let scope = current_chat_scope(&headers)?;
    let page = params.page.max(1);
    let size = params.effective_size();
    let result = state
        .group_service
        .list_members(&scope, id, page, size)
        .await?;
    Ok(Json(ApiResponse::success(result)))
}

/// POST /v1/chat/groups/{id}/members — 添加成员（OWNER/ADMIN）
async fn add_member(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<AddMemberRequest>,
) -> Result<Json<ApiResponse<GroupMemberResponse>>, AppError> {
    let scope = current_chat_scope(&headers)?;
    let member = state
        .group_service
        .add_member(&scope, id, req.user_id)
        .await?;
    Ok(Json(ApiResponse::success(member)))
}

/// DELETE /v1/chat/groups/{id}/members/{user_id} — 移除成员（自退或管理员踢人）
async fn remove_member(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((id, target_user_id)): Path<(i64, i64)>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    let scope = current_chat_scope(&headers)?;
    state
        .group_service
        .remove_member(&scope, id, target_user_id)
        .await?;
    Ok(Json(ApiResponse::success(())))
}

/// PUT /v1/chat/groups/{id}/transfer-owner — 转让群主（单事务）
async fn transfer_owner(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<TransferOwnerRequest>,
) -> Result<Json<ApiResponse<GroupResponse>>, AppError> {
    let scope = current_chat_scope(&headers)?;
    let group = state
        .group_service
        .transfer_owner(&scope, id, req.new_owner_id)
        .await?;
    Ok(Json(ApiResponse::success(group)))
}

#[cfg(test)]
mod tests {
    use super::*;
    // 角色校验已下沉到 service::group_service（原 handler 内联逻辑迁移）
    use crate::service::group_service::{require_admin, require_owner};

    // ===== Helper function tests =====

    #[test]
    fn test_require_admin_owner_allows() {
        assert!(require_admin("OWNER").is_ok());
    }

    #[test]
    fn test_require_admin_admin_allows() {
        assert!(require_admin("ADMIN").is_ok());
    }

    #[test]
    fn test_require_admin_member_denies() {
        assert!(require_admin("MEMBER").is_err());
    }

    #[test]
    fn test_require_owner_owner_allows() {
        assert!(require_owner("OWNER").is_ok());
    }

    #[test]
    fn test_require_owner_admin_denies() {
        assert!(require_owner("ADMIN").is_err());
    }

    #[test]
    fn test_require_owner_member_denies() {
        assert!(require_owner("MEMBER").is_err());
    }

    #[test]
    fn test_create_group_request_defaults() {
        let req = CreateGroupRequest {
            name: "test-group".into(),
            avatar: None,
            max_members: default_max_members(),
        };
        assert_eq!(req.name, "test-group");
        assert_eq!(req.max_members, 500);
    }

    #[test]
    fn test_create_group_request_camel_case() {
        let json = r#"{"name": "test", "maxMembers": 100}"#;
        let req: CreateGroupRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "test");
        assert_eq!(req.max_members, 100);
    }

    #[test]
    fn test_group_response_serde() {
        let resp = GroupResponse {
            id: 1,
            name: "my-group".into(),
            conversation_type: "GROUP".into(),
            owner_id: Some(42),
            avatar: Some("https://example.com/avatar.png".into()),
            max_members: 500,
            status: "ACTIVE".into(),
            member_count: 5,
            created_at: Some(1700000000),
        };
        let json = serde_json::to_string(&resp).unwrap();
        // camelCase 序列化
        assert!(json.contains("\"name\":\"my-group\""));
        assert!(json.contains("\"ownerId\":42"));
        assert!(json.contains("\"conversationType\":\"GROUP\""));
        assert!(json.contains("\"avatar\":\"https://example.com/avatar.png\""));
        assert!(json.contains("\"maxMembers\":500"));
        assert!(json.contains("\"memberCount\":5"));
        assert!(json.contains("\"createdAt\":1700000000"));
        assert!(json.contains("\"status\":\"ACTIVE\""));
    }

    #[test]
    fn test_add_member_request() {
        let json = r#"{"userId": 100}"#;
        let req: AddMemberRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.user_id, 100);
    }

    #[test]
    fn test_transfer_owner_request() {
        let json = r#"{"newOwnerId": 200}"#;
        let req: TransferOwnerRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.new_owner_id, 200);
    }

    #[test]
    fn test_update_group_request() {
        let json = r#"{"name": "new-name", "avatar": "new-avatar.png"}"#;
        let req: UpdateGroupRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, Some("new-name".into()));
        assert_eq!(req.avatar, Some("new-avatar.png".into()));
        assert!(req.max_members.is_none());
    }

    #[test]
    fn test_group_member_response_serde() {
        let member = GroupMemberResponse {
            user_id: 42,
            role: "ADMIN".into(),
            nickname: Some("admin".into()),
            muted: false,
            pinned: true,
            joined_at: Some(1700000000),
        };
        let json = serde_json::to_string(&member).unwrap();
        // camelCase 序列化
        assert!(json.contains("\"role\":\"ADMIN\""));
        assert!(json.contains("\"pinned\":true"));
        assert!(json.contains("\"muted\":false"));
        assert!(json.contains("\"userId\":42"));
        assert!(json.contains("\"joinedAt\":1700000000"));
    }
}
