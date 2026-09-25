//! 租户管理 API（TenantController）— HTTP adapter
//!
//! 数据访问在 `repository::tenant_repository`，path/depth 计算、邀请 token、
//! 到期推算等内嵌逻辑在 `service::tenant_service`。HTTP 层仅解析参数、组装 DTO。

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::Deserialize;

use astral_common::contract::{ApiResponse, PageResponse};
use astral_common::error::AppError;
use astral_types::{
    Tenant, TenantAuditLog, TenantDomainMap, TenantInvitation, TenantMember, TenantPurchase,
};

use crate::repository::tenant_repository::{
    TenantAuditLogRecord, TenantDomainMapRecord, TenantFilter, TenantInvitationRecord,
    TenantMemberRecord, TenantPurchaseRecord, TenantRecord,
};
use crate::AppState;

// ===== Record → DTO =====

impl From<TenantRecord> for Tenant {
    fn from(r: TenantRecord) -> Self {
        Self {
            id: Some(r.id),
            domain_id: r.domain_id,
            name: r.name,
            status: r.status,
            parent_tenant_id: r.parent_tenant_id,
            path: r.path,
            depth: r.depth,
        }
    }
}

impl From<TenantMemberRecord> for TenantMember {
    fn from(r: TenantMemberRecord) -> Self {
        Self {
            id: Some(r.id),
            tenant_id: r.tenant_id,
            user_id: r.user_id,
            role: r.role,
            status: r.status,
            display_name: r.display_name,
            joined_at: r.joined_at,
            left_at: r.left_at,
        }
    }
}

impl From<TenantInvitationRecord> for TenantInvitation {
    fn from(r: TenantInvitationRecord) -> Self {
        Self {
            id: Some(r.id),
            tenant_id: r.tenant_id,
            inviter_id: r.inviter_id,
            invitee_email: r.invitee_email,
            invitee_user_id: r.invitee_user_id,
            token: r.token,
            role: r.role,
            status: r.status,
            expires_at: r.expires_at,
            message: r.message,
            accepted_at: r.accepted_at,
        }
    }
}

impl From<TenantPurchaseRecord> for TenantPurchase {
    fn from(r: TenantPurchaseRecord) -> Self {
        Self {
            id: Some(r.id),
            tenant_id: r.tenant_id,
            plan_id: r.plan_id,
            plan_name: r.plan_name,
            amount: r.amount,
            currency: r.currency,
            billing_cycle: r.billing_cycle,
            status: r.status,
            payment_method: r.payment_method,
            payment_channel: r.payment_channel,
            transaction_id: r.transaction_id,
            period_start: r.period_start,
            period_end: r.period_end,
            paid_at: r.paid_at,
            refunded_at: r.refunded_at,
            remark: r.remark,
        }
    }
}

impl From<TenantDomainMapRecord> for TenantDomainMap {
    fn from(r: TenantDomainMapRecord) -> Self {
        Self {
            id: Some(r.id),
            tenant_id: r.tenant_id,
            domain_id: r.domain_id,
            is_primary: r.is_primary,
            mapping_type: r.mapping_type,
            status: r.status,
        }
    }
}

impl From<TenantAuditLogRecord> for TenantAuditLog {
    fn from(r: TenantAuditLogRecord) -> Self {
        Self {
            id: Some(r.id),
            tenant_id: r.tenant_id,
            actor_id: r.actor_id,
            actor_name: r.actor_name,
            action: r.action,
            action_label: r.action_label,
            target_type: r.target_type,
            target_id: r.target_id,
            detail: r.detail,
            result: r.result,
            reason: r.reason,
            source_ip: r.source_ip,
            user_agent: r.user_agent,
            created_at: r.created_at,
        }
    }
}

// ===== DTO =====

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateTenantRequest {
    pub domain_id: i64,
    pub name: String,
    pub parent_tenant_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTenantRequest {
    pub name: Option<String>,
    pub status: Option<String>, // ACTIVE | SUSPENDED | TERMINATED
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteMemberRequest {
    pub user_id: Option<i64>,
    pub email: Option<String>,
    pub role: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PurchasePackageRequest {
    pub plan_id: i64,
    pub plan_name: String,
    pub amount: i64,
    pub currency: Option<String>,
    pub billing_cycle: Option<String>,
    pub payment_method: Option<String>,
    pub payment_channel: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddDomainRequest {
    pub domain_id: i64,
    pub mapping_type: Option<String>,
    pub is_primary: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateMemberFieldRequest {
    pub value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantListQuery {
    pub keyword: Option<String>,
    pub status: Option<String>,
    pub page: Option<i64>,
    pub size: Option<i64>,
}

// ===== Routes =====

pub fn tenant_routes() -> Router<AppState> {
    Router::new()
        // 租户 CRUD
        .route("/tenants", get(list_tenants))
        .route("/tenants", post(create_tenant))
        .route("/tenants/types", get(list_tenant_types))
        .route("/tenants/mine", get(my_tenants))
        .route("/tenants/invitations/{code}", get(get_invitation_by_code))
        .route("/tenants/invitations/{code}/use", post(use_invitation_code))
        .route("/tenants/{id}", get(get_tenant))
        .route("/tenants/{id}", put(update_tenant))
        .route("/tenants/{id}", delete(delete_tenant))
        .route("/tenants/{id}/suspend", put(suspend_tenant))
        .route("/tenants/{id}/activate", put(activate_tenant))
        // 子租户
        .route("/tenants/{id}/sub-tenants", get(list_sub_tenants))
        .route("/tenants/{id}/sub-tenants", post(create_sub_tenant))
        .route("/tenants/{id}/tree", get(get_tenant_tree))
        // 成员
        .route("/tenants/{id}/members", get(list_members))
        .route("/tenants/{id}/members", post(add_member))
        .route("/tenants/{id}/members/{user_id}", delete(remove_member))
        .route(
            "/tenants/{id}/members/{user_id}/admin-level",
            put(update_member_admin_level),
        )
        .route(
            "/tenants/{id}/members/{user_id}/department",
            put(update_member_department),
        )
        .route(
            "/tenants/{id}/members/{user_id}/role",
            put(update_member_role),
        )
        // 域映射
        .route("/tenants/{id}/domains", get(list_tenant_domains))
        .route("/tenants/{id}/domains", post(add_tenant_domain))
        .route(
            "/tenants/{id}/domains/{domain_id}",
            delete(remove_tenant_domain),
        )
        // 购买
        .route("/tenants/{id}/purchases", get(list_purchases))
        .route("/tenants/{id}/purchases", post(purchase_package))
        // 邀请
        .route("/tenants/{id}/invitations", get(list_invitations))
        .route("/tenants/{id}/invitations", post(create_invitation))
        .route(
            "/tenants/{id}/invitations/{invitation_id}",
            delete(cancel_invitation),
        )
        // 审计
        .route("/tenants/{id}/audit-log", get(list_audit_log))
}

// ===== Tenant handlers =====

/// 列出租户（支持 keyword/status 过滤 + 分页）
async fn list_tenants(
    State(state): State<AppState>,
    Query(q): Query<TenantListQuery>,
) -> Result<Json<ApiResponse<PageResponse<Tenant>>>, AppError> {
    let page = q.page.unwrap_or(1).max(1);
    let size = q.size.unwrap_or(20).min(100);
    let offset = (page - 1) * size;

    let filter = TenantFilter {
        keyword: q.keyword,
        status: q.status,
    };
    let total = state.tenant_repository.count_tenants(&filter).await?;
    let tenants: Vec<Tenant> = state
        .tenant_repository
        .list_tenants(&filter, size, offset)
        .await?
        .into_iter()
        .map(Tenant::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        tenants, total, page, size,
    ))))
}

/// GET /types — 租户类型枚举（对齐 Java TenantType.values()）
async fn list_tenant_types() -> Result<Json<ApiResponse<Vec<serde_json::Value>>>, AppError> {
    let types = vec![
        serde_json::json!({"value": "ENTERPRISE", "label": "企业版"}),
        serde_json::json!({"value": "EDUCATION", "label": "教育版"}),
        serde_json::json!({"value": "PERSONAL", "label": "个人版"}),
        serde_json::json!({"value": "TRIAL", "label": "试用版"}),
    ];
    Ok(Json(ApiResponse::success(types)))
}

/// GET /mine — 当前用户所属租户列表
async fn my_tenants(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<Vec<Tenant>>>, AppError> {
    let user_id: i64 = headers
        .get("X-User-Id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| AppError(astral_types::AstralError::Auth("X-User-Id required".into())))?;

    let tenants: Vec<Tenant> = state
        .tenant_repository
        .list_my_tenants(user_id)
        .await?
        .into_iter()
        .map(Tenant::from)
        .collect();
    Ok(Json(ApiResponse::success(tenants)))
}

/// 获取单个租户详情
async fn get_tenant(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<Tenant>>, AppError> {
    let row = state
        .tenant_repository
        .get_tenant(id)
        .await?
        .map(Tenant::from)
        .ok_or_else(|| AppError(astral_types::AstralError::NotFound(format!("tenant {id}"))))?;
    Ok(Json(ApiResponse::success(row)))
}

/// 创建租户（含层级计算）
async fn create_tenant(
    State(state): State<AppState>,
    Json(req): Json<CreateTenantRequest>,
) -> Result<Json<ApiResponse<Tenant>>, AppError> {
    let outcome = state
        .tenant_service
        .create_tenant(&req.name, req.parent_tenant_id)
        .await?;
    let row = state
        .tenant_repository
        .get_tenant(outcome.tenant_id)
        .await?
        .map(Tenant::from)
        .ok_or_else(|| {
            AppError(astral_types::AstralError::Database(format!(
                "tenant {} not found after insert",
                outcome.tenant_id
            )))
        })?;
    Ok(Json(ApiResponse::success(row)))
}

/// 更新租户（名称/状态）
async fn update_tenant(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateTenantRequest>,
) -> Result<Json<ApiResponse<Tenant>>, AppError> {
    if let Some(ref name) = req.name {
        state.tenant_repository.update_tenant_name(id, name).await?;
    }
    if let Some(ref status) = req.status {
        let upper = status.to_uppercase();
        if upper != "ACTIVE" && upper != "SUSPENDED" && upper != "TERMINATED" {
            return Err(AppError(astral_types::AstralError::Validation(
                "status must be ACTIVE, SUSPENDED, or TERMINATED".into(),
            )));
        }
        state
            .tenant_repository
            .update_tenant_status(id, &upper)
            .await?;
    }

    let row = state
        .tenant_repository
        .get_tenant(id)
        .await?
        .map(Tenant::from)
        .ok_or_else(|| AppError(astral_types::AstralError::NotFound(format!("tenant {id}"))))?;
    Ok(Json(ApiResponse::success(row)))
}

/// 删除租户
async fn delete_tenant(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    let deleted = state.tenant_repository.delete_tenant(id).await?;
    if !deleted {
        return Err(AppError(astral_types::AstralError::NotFound(format!(
            "tenant {id} not found"
        ))));
    }
    tracing::info!(id, "tenant deleted");
    Ok(Json(ApiResponse::success(())))
}

/// PUT /{id}/suspend — 暂停租户
async fn suspend_tenant(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<Tenant>>, AppError> {
    let transitioned = state
        .tenant_repository
        .transition_tenant_status(id, "ACTIVE", "SUSPENDED")
        .await?;
    if !transitioned {
        return Err(AppError(astral_types::AstralError::NotFound(format!(
            "tenant {id} (not ACTIVE)"
        ))));
    }
    let row = state
        .tenant_repository
        .get_tenant(id)
        .await?
        .map(Tenant::from)
        .ok_or_else(|| AppError(astral_types::AstralError::NotFound(format!("tenant {id}"))))?;
    tracing::info!(id, "tenant suspended");
    Ok(Json(ApiResponse::success(row)))
}

/// PUT /{id}/activate — 激活租户
async fn activate_tenant(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<Tenant>>, AppError> {
    let transitioned = state
        .tenant_repository
        .transition_tenant_status(id, "SUSPENDED", "ACTIVE")
        .await?;
    if !transitioned {
        return Err(AppError(astral_types::AstralError::NotFound(format!(
            "tenant {id} (not SUSPENDED)"
        ))));
    }
    let row = state
        .tenant_repository
        .get_tenant(id)
        .await?
        .map(Tenant::from)
        .ok_or_else(|| AppError(astral_types::AstralError::NotFound(format!("tenant {id}"))))?;
    tracing::info!(id, "tenant activated");
    Ok(Json(ApiResponse::success(row)))
}

/// GET /{id}/sub-tenants — 子租户列表
async fn list_sub_tenants(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<Vec<Tenant>>>, AppError> {
    let tenants: Vec<Tenant> = state
        .tenant_repository
        .list_sub_tenants(id)
        .await?
        .into_iter()
        .map(Tenant::from)
        .collect();
    Ok(Json(ApiResponse::success(tenants)))
}

/// POST /{id}/sub-tenants — 创建子租户
async fn create_sub_tenant(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<CreateTenantRequest>,
) -> Result<Json<ApiResponse<Tenant>>, AppError> {
    let outcome = state
        .tenant_service
        .create_sub_tenant(id, &req.name)
        .await?;
    let row = state
        .tenant_repository
        .get_tenant(outcome.tenant_id)
        .await?
        .map(Tenant::from)
        .ok_or_else(|| {
            AppError(astral_types::AstralError::Database(format!(
                "tenant {} not found after insert",
                outcome.tenant_id
            )))
        })?;
    Ok(Json(ApiResponse::success(row)))
}

/// GET /{id}/tree — 租户树（所有后代）
async fn get_tenant_tree(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<Vec<Tenant>>>, AppError> {
    let tenants: Vec<Tenant> = state
        .tenant_repository
        .list_tenant_tree(id)
        .await?
        .into_iter()
        .map(Tenant::from)
        .collect();
    Ok(Json(ApiResponse::success(tenants)))
}

// ===== Member handlers =====

/// 列出租户成员
async fn list_members(
    State(state): State<AppState>,
    Path(tenant_id): Path<i64>,
) -> Result<Json<ApiResponse<Vec<TenantMember>>>, AppError> {
    let members: Vec<TenantMember> = state
        .tenant_repository
        .list_members(tenant_id)
        .await?
        .into_iter()
        .map(TenantMember::from)
        .collect();
    Ok(Json(ApiResponse::success(members)))
}

/// 添加租户成员
async fn add_member(
    State(state): State<AppState>,
    Path(tenant_id): Path<i64>,
    Json(req): Json<InviteMemberRequest>,
) -> Result<Json<ApiResponse<TenantMember>>, AppError> {
    let user_id = req.user_id.ok_or_else(|| {
        AppError(astral_types::AstralError::Validation(
            "user_id is required".into(),
        ))
    })?;

    let role_upper = req.role.to_uppercase();
    if !["OWNER", "ADMIN", "MEMBER", "GUEST"].contains(&role_upper.as_str()) {
        return Err(AppError(astral_types::AstralError::Validation(
            "role must be OWNER, ADMIN, MEMBER, or GUEST".into(),
        )));
    }

    state
        .tenant_repository
        .upsert_member(tenant_id, user_id, &role_upper)
        .await?;
    let member: TenantMember = state
        .tenant_repository
        .get_member(tenant_id, user_id)
        .await?
        .into();
    Ok(Json(ApiResponse::success(member)))
}

/// 移除租户成员
async fn remove_member(
    State(state): State<AppState>,
    Path((tenant_id, user_id)): Path<(i64, i64)>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    let removed = state
        .tenant_repository
        .remove_member(tenant_id, user_id)
        .await?;
    if !removed {
        return Err(AppError(astral_types::AstralError::NotFound(format!(
            "member {user_id} in tenant {tenant_id}"
        ))));
    }
    tracing::info!(tenant_id, user_id, "member removed");
    Ok(Json(ApiResponse::success(())))
}

/// PUT /{id}/members/{user_id}/admin-level — 修改成员管理等级
async fn update_member_admin_level(
    State(state): State<AppState>,
    Path((tenant_id, user_id)): Path<(i64, i64)>,
    Json(req): Json<UpdateMemberFieldRequest>,
) -> Result<Json<ApiResponse<TenantMember>>, AppError> {
    let admin_level: i32 = req.value.parse().unwrap_or(0);
    let updated = state
        .tenant_repository
        .update_member_field(tenant_id, user_id, "admin_level", admin_level.to_string())
        .await?;
    if !updated {
        return Err(AppError(astral_types::AstralError::NotFound(format!(
            "member {user_id} in tenant {tenant_id}"
        ))));
    }
    let row: TenantMember = state
        .tenant_repository
        .get_member(tenant_id, user_id)
        .await?
        .into();
    Ok(Json(ApiResponse::success(row)))
}

/// PUT /{id}/members/{user_id}/department — 修改成员部门
async fn update_member_department(
    State(state): State<AppState>,
    Path((tenant_id, user_id)): Path<(i64, i64)>,
    Json(req): Json<UpdateMemberFieldRequest>,
) -> Result<Json<ApiResponse<TenantMember>>, AppError> {
    let dept_id: i64 = req.value.parse().unwrap_or(0);
    let updated = state
        .tenant_repository
        .update_member_field(tenant_id, user_id, "dept_id", dept_id.to_string())
        .await?;
    if !updated {
        return Err(AppError(astral_types::AstralError::NotFound(format!(
            "member {user_id} in tenant {tenant_id}"
        ))));
    }
    let row: TenantMember = state
        .tenant_repository
        .get_member(tenant_id, user_id)
        .await?
        .into();
    Ok(Json(ApiResponse::success(row)))
}

/// PUT /{id}/members/{user_id}/role — 修改成员角色
async fn update_member_role(
    State(state): State<AppState>,
    Path((tenant_id, user_id)): Path<(i64, i64)>,
    Json(req): Json<UpdateMemberFieldRequest>,
) -> Result<Json<ApiResponse<TenantMember>>, AppError> {
    let role = req.value.to_uppercase();
    if !["OWNER", "ADMIN", "MEMBER", "GUEST"].contains(&role.as_str()) {
        return Err(AppError(astral_types::AstralError::Validation(
            "role must be OWNER/ADMIN/MEMBER/GUEST".into(),
        )));
    }
    let updated = state
        .tenant_repository
        .update_member_field(tenant_id, user_id, "role_type", role)
        .await?;
    if !updated {
        return Err(AppError(astral_types::AstralError::NotFound(format!(
            "member {user_id} in tenant {tenant_id}"
        ))));
    }
    let row: TenantMember = state
        .tenant_repository
        .get_member(tenant_id, user_id)
        .await?
        .into();
    Ok(Json(ApiResponse::success(row)))
}

// ===== Invitation handlers =====

/// 列出租户邀请
async fn list_invitations(
    State(state): State<AppState>,
    Path(tenant_id): Path<i64>,
) -> Result<Json<ApiResponse<Vec<TenantInvitation>>>, AppError> {
    let invitations: Vec<TenantInvitation> = state
        .tenant_repository
        .list_invitations(tenant_id)
        .await?
        .into_iter()
        .map(TenantInvitation::from)
        .collect();
    Ok(Json(ApiResponse::success(invitations)))
}

/// 创建租户邀请
async fn create_invitation(
    State(state): State<AppState>,
    Path(tenant_id): Path<i64>,
    Json(req): Json<InviteMemberRequest>,
) -> Result<Json<ApiResponse<TenantInvitation>>, AppError> {
    let invitation: TenantInvitation = state
        .tenant_service
        .create_invitation(tenant_id, &req.role)
        .await?
        .into();
    Ok(Json(ApiResponse::success(invitation)))
}

/// DELETE /{id}/invitations/{invitation_id} — 撤销邀请
async fn cancel_invitation(
    State(state): State<AppState>,
    Path((tenant_id, invitation_id)): Path<(i64, i64)>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let canceled = state
        .tenant_repository
        .cancel_invitation(tenant_id, invitation_id)
        .await?;
    if !canceled {
        return Err(AppError(astral_types::AstralError::NotFound(format!(
            "active invitation {invitation_id}"
        ))));
    }
    tracing::info!(tenant_id, invitation_id, "invitation canceled");
    Ok(Json(ApiResponse::success(
        serde_json::json!({ "id": invitation_id, "status": "REVOKED" }),
    )))
}

/// GET /invitations/{code} — 查看邀请详情
async fn get_invitation_by_code(
    State(state): State<AppState>,
    Path(code): Path<String>,
) -> Result<Json<ApiResponse<TenantInvitation>>, AppError> {
    let row = state
        .tenant_repository
        .get_invitation_by_code(&code)
        .await?
        .map(TenantInvitation::from)
        .ok_or_else(|| {
            AppError(astral_types::AstralError::NotFound(format!(
                "invitation {code}"
            )))
        })?;
    Ok(Json(ApiResponse::success(row)))
}

/// POST /invitations/{code}/use — 使用邀请码加入租户
async fn use_invitation_code(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(code): Path<String>,
) -> Result<Json<ApiResponse<TenantMember>>, AppError> {
    let user_id: i64 = headers
        .get("X-User-Id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| AppError(astral_types::AstralError::Auth("X-User-Id required".into())))?;

    let outcome = state
        .tenant_service
        .use_invitation_code(&code, user_id)
        .await?;
    let member: TenantMember = state
        .tenant_repository
        .get_member(outcome.tenant_id, user_id)
        .await?
        .into();
    Ok(Json(ApiResponse::success(member)))
}

// ===== Purchase handlers =====

/// 列出租户购买/订阅记录
async fn list_purchases(
    State(state): State<AppState>,
    Path(tenant_id): Path<i64>,
) -> Result<Json<ApiResponse<Vec<TenantPurchase>>>, AppError> {
    let purchases: Vec<TenantPurchase> = state
        .tenant_repository
        .list_purchases(tenant_id)
        .await?
        .into_iter()
        .map(TenantPurchase::from)
        .collect();
    Ok(Json(ApiResponse::success(purchases)))
}

/// POST /{id}/purchases — 购买套餐
async fn purchase_package(
    State(state): State<AppState>,
    Path(tenant_id): Path<i64>,
    Json(req): Json<PurchasePackageRequest>,
) -> Result<Json<ApiResponse<TenantPurchase>>, AppError> {
    let outcome = state
        .tenant_service
        .purchase_package(tenant_id, req.plan_id, req.billing_cycle.as_deref())
        .await?;
    let row = state
        .tenant_repository
        .get_purchase(outcome.purchase_id)
        .await?
        .into();
    Ok(Json(ApiResponse::success(row)))
}

// ===== Domain mapping handlers =====

/// GET /{id}/domains — 列出租户域映射
async fn list_tenant_domains(
    State(state): State<AppState>,
    Path(tenant_id): Path<i64>,
) -> Result<Json<ApiResponse<Vec<TenantDomainMap>>>, AppError> {
    let rows: Vec<TenantDomainMap> = state
        .tenant_repository
        .list_tenant_domains(tenant_id)
        .await?
        .into_iter()
        .map(TenantDomainMap::from)
        .collect();
    Ok(Json(ApiResponse::success(rows)))
}

/// POST /{id}/domains — 添加域映射
async fn add_tenant_domain(
    State(state): State<AppState>,
    Path(tenant_id): Path<i64>,
    Json(req): Json<AddDomainRequest>,
) -> Result<Json<ApiResponse<TenantDomainMap>>, AppError> {
    let mapping_type = req.mapping_type.unwrap_or_else(|| "OWNED".into());
    let valid_types = ["OWNED", "SHARED", "ISOLATED"];
    if !valid_types.contains(&mapping_type.as_str()) {
        return Err(AppError(astral_types::AstralError::Validation(format!(
            "mapping_type must be one of {valid_types:?}"
        ))));
    }

    state
        .tenant_repository
        .upsert_tenant_domain(tenant_id, req.domain_id)
        .await?;
    let row = state
        .tenant_repository
        .get_tenant_domain(tenant_id, req.domain_id)
        .await?
        .into();
    tracing::info!(tenant_id, domain_id = req.domain_id, mapping_type = %mapping_type, "domain mapping added");
    Ok(Json(ApiResponse::success(row)))
}

/// DELETE /{id}/domains/{domain_id} — 删除域映射
async fn remove_tenant_domain(
    State(state): State<AppState>,
    Path((tenant_id, domain_id)): Path<(i64, i64)>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let removed = state
        .tenant_repository
        .remove_tenant_domain(tenant_id, domain_id)
        .await?;
    if !removed {
        return Err(AppError(astral_types::AstralError::NotFound(format!(
            "domain mapping tenant={tenant_id} domain={domain_id}"
        ))));
    }
    tracing::info!(tenant_id, domain_id, "domain mapping removed");
    Ok(Json(ApiResponse::success(
        serde_json::json!({ "tenant_id": tenant_id, "domain_id": domain_id, "deleted": true }),
    )))
}

// ===== Audit log handlers =====

/// 列出租户审计日志
async fn list_audit_log(
    State(state): State<AppState>,
    Path(tenant_id): Path<i64>,
) -> Result<Json<ApiResponse<Vec<TenantAuditLog>>>, AppError> {
    let logs: Vec<TenantAuditLog> = state
        .tenant_repository
        .list_audit_log(tenant_id)
        .await?
        .into_iter()
        .map(TenantAuditLog::from)
        .collect();
    Ok(Json(ApiResponse::success(logs)))
}

// ===== DataScopeRuleProvider =====

/// 注册 trustgraph 模块的租户相关数据范围规则
pub fn register_trustgraph_data_scope_rules() {
    use policy_engine::register_global_rule;
    use policy_engine::{DataScopeRule, DataScopeType};

    let trustgraph_tables: Vec<(&str, &str, DataScopeType)> = vec![
        // 租户核心表
        ("tenant", "tenant_id", DataScopeType::Tenant),
        ("tenant_domain_map", "tenant_id", DataScopeType::Tenant),
        ("tenant_members", "tenant_id", DataScopeType::Tenant),
        ("tenant_invitation", "tenant_id", DataScopeType::Tenant),
        ("tenant_purchase", "tenant_id", DataScopeType::Tenant),
        ("tenant_audit_log", "tenant_id", DataScopeType::Tenant),
        // TrustGraph 权限表
        ("rule_set", "tenant_id", DataScopeType::Tenant),
        ("rule_set_entry", "tenant_id", DataScopeType::Tenant),
        ("rule_set_snapshot", "tenant_id", DataScopeType::Tenant),
        ("audit_log", "tenant_id", DataScopeType::Tenant),
        ("permission_rule", "tenant_id", DataScopeType::Tenant),
        ("permission_delegation", "tenant_id", DataScopeType::Tenant),
        ("permission_hit_stat", "tenant_id", DataScopeType::Tenant),
    ];

    let count = trustgraph_tables.len();
    for (table, column, scope_type) in trustgraph_tables {
        register_global_rule(DataScopeRule::new(table, column, scope_type));
    }

    tracing::info!("registered {} trustgraph data scope rules", count);
}
