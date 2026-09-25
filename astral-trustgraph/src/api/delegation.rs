//! 委托管理与角色分组 — HTTP adapter
//!
//! 对应 Java `DelegationController` + `AdminGroupController`。
//! 数据访问在 `repository::admin_group_repository`（admin_group + admin_group_member，
//! 删除级联单事务）与 `repository::delegation_repository`（permission_delegation 规则
//! 生命周期）；委托编排在 `service::delegation_service`。

use axum::extract::{Extension, Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, EmptyResponse};
use astral_common::error::AppError;
use astral_types::{AstralError, PolicyContext};

use crate::repository::delegation_repository::DelegationMutationContext;
use crate::service::delegation_service::{
    CreateDelegationRequest as CreateDelegationCmd, UpdateDelegationRequest as UpdateDelegationCmd,
};
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct CardIdQuery {
    pub card_id: i64,
}

/// 管理组
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase")]
pub struct AdminGroup {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub scope: String,
}

/// 管理组（含成员数）
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminGroupWithCount {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub scope: String,
    pub member_count: i64,
}

/// 权限委派
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Delegation {
    pub id: Option<i64>,
    pub delegator_id: i64,
    pub delegate_id: i64,
    pub resource: String,
    pub action: String,
    pub expires_at: Option<String>,
    pub status: String,
}

/// 群组创建请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateGroupRequest {
    pub name: String,
    pub description: Option<String>,
    pub scope: Option<String>,
}

/// 添加成员请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddMemberRequest {
    pub user_id: i64,
}

/// 委托创建请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDelegationRequest {
    pub delegator_id: i64,
    pub delegate_id: i64,
    pub resource: String,
    pub action: String,
    pub expires_at: Option<String>,
}

/// 委托更新请求（仅允许更新 resource/action/expires_at，禁止修改 delegator_id）
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDelegationRequest {
    pub resource: String,
    pub action: String,
    pub expires_at: Option<String>,
}

fn delegation_context(
    headers: &HeaderMap,
    policy_context: &PolicyContext,
) -> Result<DelegationMutationContext, AppError> {
    let operation_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok());
    DelegationMutationContext::from_policy_context(policy_context, operation_id)
        .map_err(AppError::from)
}

pub fn delegation_routes() -> Router<AppState> {
    Router::new()
        .route("/admin-groups", get(list_groups))
        .route("/admin-groups", post(create_group))
        .route("/admin-groups/{id}", get(get_group))
        .route("/admin-groups/{id}", put(update_group))
        .route("/admin-groups/{id}", delete(delete_group))
        .route("/admin-groups/{id}/members", get(list_group_members))
        .route("/admin-groups/{id}/members", post(add_group_member))
        .route(
            "/admin-groups/{id}/members/{uid}",
            delete(remove_group_member),
        )
        .route("/delegations", get(list_delegations))
        .route("/delegations/by-delegator", get(list_by_delegator))
        .route("/delegations/by-delegate", get(list_by_delegate))
        .route("/delegations", post(create_delegation))
        .route("/delegations/{id}", put(update_delegation))
        .route("/delegations/{id}/revoke", post(revoke_delegation))
}

/// GET /main/api/v1/admin-groups — 全部管理组（含成员数，repository 防 N+1）
async fn list_groups(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<AdminGroupWithCount>>>, AppError> {
    let rows = state.admin_group_repository.list_with_counts().await?;
    let result = rows
        .into_iter()
        .map(|r| AdminGroupWithCount {
            id: r.id,
            name: r.name,
            description: r.description,
            scope: r.scope,
            member_count: r.member_count,
        })
        .collect();
    Ok(Json(ApiResponse::success(result)))
}

/// POST /main/api/v1/admin-groups
async fn create_group(
    State(state): State<AppState>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<Json<ApiResponse<AdminGroup>>, AppError> {
    let scope = req.scope.unwrap_or_else(|| "GLOBAL".into());
    let id = state
        .admin_group_repository
        .create(&req.name, req.description.as_deref(), &scope)
        .await?;
    tracing::info!(name = %req.name, "admin group created");
    Ok(Json(ApiResponse::success(AdminGroup {
        id,
        name: req.name,
        description: req.description,
        scope,
    })))
}

/// GET /main/api/v1/admin-groups/{id}
async fn get_group(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<AdminGroup>>, AppError> {
    let group = state
        .admin_group_repository
        .get(id)
        .await?
        .map(|r| AdminGroup {
            id: r.id,
            name: r.name,
            description: r.description,
            scope: r.scope,
        })
        .ok_or_else(|| astral_types::AstralError::Validation("Group not found".into()))?;
    Ok(Json(ApiResponse::success(group)))
}

/// PUT /main/api/v1/admin-groups/{id}
async fn update_group(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let scope = req.scope.unwrap_or_else(|| "GLOBAL".into());
    state
        .admin_group_repository
        .update(id, &req.name, req.description.as_deref(), &scope)
        .await?;
    tracing::info!(id, "admin group updated");
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

/// DELETE /main/api/v1/admin-groups/{id} — 级联删除成员 + 组（单事务）
async fn delete_group(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.admin_group_repository.delete(id).await?;
    tracing::warn!(id, "admin group deleted");
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

/// GET /main/api/v1/admin-groups/{id}/members
async fn list_group_members(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<Vec<i64>>>, AppError> {
    let members = state.admin_group_repository.list_member_ids(id).await?;
    Ok(Json(ApiResponse::success(members)))
}

/// POST /main/api/v1/admin-groups/{id}/members — INSERT IGNORE 幂等
async fn add_group_member(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<AddMemberRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state
        .admin_group_repository
        .add_member(id, req.user_id)
        .await?;
    tracing::info!(group_id = id, user_id = %req.user_id, "member added");
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

/// DELETE /main/api/v1/admin-groups/{id}/members/{uid}
async fn remove_group_member(
    State(state): State<AppState>,
    Path((id, uid)): Path<(i64, i64)>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.admin_group_repository.remove_member(id, uid).await?;
    tracing::info!(group_id = id, user_id = uid, "member removed");
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

/// GET /main/api/v1/delegations
///
/// platform_v4.permission_delegation 真实列通过 repository 别名映射到前端兼容字段名；
/// ACTIVE 且已过 effective_until 时展示为 EXPIRED。
async fn list_delegations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
) -> Result<Json<ApiResponse<Vec<Delegation>>>, AppError> {
    let context = delegation_context(&headers, &policy_context)?;
    let rows = state.delegation_repository.list_all(&context).await?;
    let delegations = rows
        .into_iter()
        .map(|r| Delegation {
            id: Some(r.id),
            delegator_id: r.delegator_id,
            delegate_id: r.delegate_id,
            resource: r.resource,
            action: r.action,
            expires_at: r.expires_ts.map(|ts| ts.to_string()),
            status: r.status,
        })
        .collect();
    Ok(Json(ApiResponse::success(delegations)))
}

async fn list_by_delegator(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
    Query(query): Query<CardIdQuery>,
) -> Result<Json<ApiResponse<Vec<Delegation>>>, AppError> {
    let context = delegation_context(&headers, &policy_context)?;
    require_caller_card(query.card_id, &context, "delegator")?;
    let rows = state
        .delegation_repository
        .list_by_delegator(query.card_id, &context)
        .await?;
    Ok(Json(ApiResponse::success(
        rows.into_iter().map(to_delegation).collect(),
    )))
}

async fn list_by_delegate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
    Query(query): Query<CardIdQuery>,
) -> Result<Json<ApiResponse<Vec<Delegation>>>, AppError> {
    let context = delegation_context(&headers, &policy_context)?;
    require_caller_card(query.card_id, &context, "delegate")?;
    let rows = state
        .delegation_repository
        .list_by_delegate(query.card_id, &context)
        .await?;
    Ok(Json(ApiResponse::success(
        rows.into_iter().map(to_delegation).collect(),
    )))
}

fn require_caller_card(
    requested_card_id: i64,
    context: &DelegationMutationContext,
    role: &str,
) -> Result<(), AppError> {
    if requested_card_id != context.caller_card_id() {
        return Err(AppError(AstralError::Permission(format!(
            "delegation {role} query must use the verified caller card"
        ))));
    }
    Ok(())
}

fn to_delegation(r: crate::repository::delegation_repository::DelegationViewRecord) -> Delegation {
    Delegation {
        id: Some(r.id),
        delegator_id: r.delegator_id,
        delegate_id: r.delegate_id,
        resource: r.resource,
        action: r.action,
        expires_at: r.expires_ts.map(|ts| ts.to_string()),
        status: r.status,
    }
}

/// POST /main/api/v1/delegations
///
/// platform_v4.permission_delegation: effective_from/effective_until 是 NOT NULL，
/// 创建时 effective_from=NOW()，effective_until 由请求的 expires_at 推算（默认 24h 后）。
/// 幂等：已存在相同 ACTIVE 委托时返回已有记录；新建时同事务写入 DELEGATION 规则。
///
/// resource/action 先经 ResourceRegistry 校验并 trim（与 repository 写入边界
/// 复用同一 `validate_registry_resource_action`），响应回显规范化值，保证回显
/// 与持久化值零漂移；repository 侧会以同一函数再次校验（纵深防御）。
async fn create_delegation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
    Json(req): Json<CreateDelegationRequest>,
) -> Result<Json<ApiResponse<Delegation>>, AppError> {
    let context = delegation_context(&headers, &policy_context)?;
    if req.delegator_id != context.caller_card_id() {
        return Err(AppError(AstralError::Permission(
            "delegator_id must match the verified caller card".into(),
        )));
    }
    let (normalized_resource, normalized_action) =
        crate::service::personal_permission_service::validate_registry_resource_action(
            &req.resource,
            &req.action,
        )
        .map_err(AppError::from)?;
    let outcome = state
        .delegation_service
        .create_delegation(
            &CreateDelegationCmd {
                delegator_id: context.caller_card_id(),
                delegate_id: req.delegate_id,
                resource: normalized_resource.clone(),
                action: normalized_action.clone(),
                expires_at: req.expires_at.clone(),
            },
            &context,
        )
        .await?;

    Ok(Json(ApiResponse::success(Delegation {
        id: Some(outcome.delegation_id),
        delegator_id: context.caller_card_id(),
        delegate_id: req.delegate_id,
        resource: normalized_resource,
        action: normalized_action,
        expires_at: req.expires_at,
        status: "ACTIVE".into(),
    })))
}

/// PUT /main/api/v1/delegations/{id}
///
/// 仅更新 resource_type/action_code/effective_until，禁止修改 delegator/delegate。
/// 同步重建该委托的 DELEGATION 规则（删旧插新），防止权限与展示漂移。
async fn update_delegation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateDelegationRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let context = delegation_context(&headers, &policy_context)?;
    state
        .delegation_service
        .update_delegation(
            id,
            &UpdateDelegationCmd {
                resource: req.resource,
                action: req.action,
                expires_at: req.expires_at,
            },
            &context,
        )
        .await?;

    tracing::info!(
        id,
        request_id = context.request_id_header(),
        "delegation updated"
    );
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

/// DELETE /main/api/v1/delegations/{id}
///
/// 撤销委托：置 status='REVOKED'、记录 revoked_at，并清理该委托的
/// DELEGATION 规则、重建被委托卡快照（对齐 Java DelegationService.revokeDelegation）。
async fn revoke_delegation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let context = delegation_context(&headers, &policy_context)?;
    state
        .delegation_service
        .revoke_delegation(id, &context)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}
