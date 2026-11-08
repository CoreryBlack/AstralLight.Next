//! 组织/域/租户管理 API — HTTP adapter
//!
//! 编排与 record→DTO 映射在 `OrgService`，HTTP 层仅解析路径参数并包装响应。

use axum::extract::{Extension, Path, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};

use astral_common::contract::{ApiResponse, EmptyResponse};
use astral_common::error::AppError;
use astral_types::{AstralError, AuthorizationAdmission};

use crate::srv::org_repository::OrgMutationContext;
use crate::srv::org_service::{Domain, Organization, Tenant};
use crate::AppState;

fn org_mutation_context(headers: &HeaderMap) -> Result<OrgMutationContext, AppError> {
    let parse = |name: &'static str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value > 0)
            .ok_or_else(|| {
                AppError(AstralError::Auth(format!(
                    "Gateway-verified {name} is required for org mutation"
                )))
            })
    };
    OrgMutationContext::new(
        parse("x-user-id")?,
        parse("x-user-card-id")?,
        parse("x-user-card-tenant-id")?,
        parse("x-user-card-domain-id")?,
        headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
    )
    .map_err(AppError)
}

pub fn org_routes() -> Router<AppState> {
    Router::new()
        .route("/orgs", get(list_orgs))
        .route("/orgs", post(create_org))
        .route("/orgs/{id}", get(get_org))
        .route("/orgs/{id}", put(update_org))
        .route("/orgs/{id}", delete(delete_org))
        .route("/orgs/{id}/domains", get(list_org_domains))
}

pub fn domain_routes() -> Router<AppState> {
    Router::new()
        .route("/domains", get(list_all_domains))
        .route("/domains", post(create_domain))
        .route("/domains/{id}", get(get_domain))
        .route("/domains/{id}", put(update_domain))
        .route("/domains/{id}", delete(delete_domain))
        .route("/domains/{id}/tenants", get(list_domain_tenants))
}

pub fn tenant_routes() -> Router<AppState> {
    Router::new()
        .route("/tenants", get(list_all_tenants))
        .route("/tenants", post(create_tenant))
        .route("/tenants/{id}", get(get_tenant))
        .route("/tenants/{id}", put(update_tenant))
        .route("/tenants/{id}", delete(delete_tenant))
}

async fn list_orgs(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<Organization>>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.org_service.list_orgs().await?,
    )))
}

async fn create_org(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<Organization>,
) -> Result<Json<ApiResponse<Organization>>, AppError> {
    let context = org_mutation_context(&headers)?;
    Ok(Json(ApiResponse::success(
        state
            .org_service
            .create_org_with_context(&req, &context)
            .await?,
    )))
}

async fn get_org(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<Organization>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.org_service.get_org(id).await?,
    )))
}

async fn update_org(
    State(state): State<AppState>,
    headers: HeaderMap,
    // 状态迁移影响有效资格：携带中间件认证的 proof-bound admission；纯
    // metadata 更新允许缺失（repository 仅在状态迁移分支 fail-closed 要求）。
    admission: Option<Extension<AuthorizationAdmission>>,
    Path(id): Path<i64>,
    Json(req): Json<Organization>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let context =
        org_mutation_context(&headers)?.with_admission(admission.map(|Extension(value)| value));
    state
        .org_service
        .update_org_with_context(id, &req, &context)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn delete_org(
    State(state): State<AppState>,
    headers: HeaderMap,
    // 删除必然改变全部 ACTIVE 卡的有效资格：必须携带 proof-bound admission。
    Extension(admission): Extension<AuthorizationAdmission>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let context = org_mutation_context(&headers)?.with_admission(Some(admission));
    state
        .org_service
        .delete_org_with_context(id, &context)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn list_org_domains(
    State(state): State<AppState>,
    Path(org_id): Path<i64>,
) -> Result<Json<ApiResponse<Vec<Domain>>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.org_service.list_org_domains(org_id).await?,
    )))
}

async fn list_all_domains(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<Domain>>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.org_service.list_all_domains().await?,
    )))
}

async fn create_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<Domain>,
) -> Result<Json<ApiResponse<Domain>>, AppError> {
    let context = org_mutation_context(&headers)?;
    Ok(Json(ApiResponse::success(
        state
            .org_service
            .create_domain_with_context(&req, &context)
            .await?,
    )))
}

async fn get_domain(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<Domain>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.org_service.get_domain(id).await?,
    )))
}

async fn update_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<Domain>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let context = org_mutation_context(&headers)?;
    state
        .org_service
        .update_domain_with_context(id, &req, &context)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn delete_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let context = org_mutation_context(&headers)?;
    state
        .org_service
        .delete_domain_with_context(id, &context)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn list_domain_tenants(
    State(state): State<AppState>,
    Path(did): Path<i64>,
) -> Result<Json<ApiResponse<Vec<Tenant>>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.org_service.list_domain_tenants(did).await?,
    )))
}

async fn list_all_tenants(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<Tenant>>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.org_service.list_all_tenants().await?,
    )))
}

async fn create_tenant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<Tenant>,
) -> Result<Json<ApiResponse<Tenant>>, AppError> {
    let context = org_mutation_context(&headers)?;
    Ok(Json(ApiResponse::success(
        state
            .org_service
            .create_tenant_with_context(&req, &context)
            .await?,
    )))
}

async fn get_tenant(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<Tenant>>, AppError> {
    Ok(Json(ApiResponse::success(
        state.org_service.get_tenant(id).await?,
    )))
}

async fn update_tenant(
    State(state): State<AppState>,
    headers: HeaderMap,
    // 状态迁移影响有效资格：携带中间件认证的 proof-bound admission；纯
    // metadata 更新允许缺失（repository 仅在状态迁移分支 fail-closed 要求）。
    admission: Option<Extension<AuthorizationAdmission>>,
    Path(id): Path<i64>,
    Json(req): Json<Tenant>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let context =
        org_mutation_context(&headers)?.with_admission(admission.map(|Extension(value)| value));
    state
        .org_service
        .update_tenant_with_context(id, &req, &context)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn delete_tenant(
    State(state): State<AppState>,
    headers: HeaderMap,
    // 删除必然改变全部 ACTIVE 卡的有效资格：必须携带 proof-bound admission。
    Extension(admission): Extension<AuthorizationAdmission>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let context = org_mutation_context(&headers)?.with_admission(Some(admission));
    state
        .org_service
        .delete_tenant_with_context(id, &context)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

#[cfg(test)]
mod tests {
    /// 源形状守卫：四条影响有效资格的 handler 必须提取中间件插入的
    /// proof-bound admission 并绑定进 mutation context（状态迁移更新为可选、
    /// repository 内 fail-closed；删除为必选）；create/domain 路径不改变任何
    /// 卡的有效资格，不得提取或消费 admission。
    #[test]
    fn eligibility_affecting_org_handlers_extract_and_forward_admission() {
        let source = include_str!("orgs.rs");
        for (handler, next_anchor, signature, binding) in [
            (
                "async fn update_org(",
                "async fn delete_org(",
                "admission: Option<Extension<AuthorizationAdmission>>",
                "with_admission(admission.map(|Extension(value)| value))",
            ),
            (
                "async fn update_tenant(",
                "async fn delete_tenant(",
                "admission: Option<Extension<AuthorizationAdmission>>",
                "with_admission(admission.map(|Extension(value)| value))",
            ),
            (
                "async fn delete_org(",
                "async fn list_org_domains(",
                "Extension(admission): Extension<AuthorizationAdmission>",
                "with_admission(Some(admission))",
            ),
            (
                "async fn delete_tenant(",
                "#[cfg(test)]",
                "Extension(admission): Extension<AuthorizationAdmission>",
                "with_admission(Some(admission))",
            ),
        ] {
            let start = source
                .find(handler)
                .unwrap_or_else(|| panic!("{handler} handler must stay in orgs.rs"));
            let end = source[start..]
                .find(next_anchor)
                .unwrap_or_else(|| panic!("{handler} body boundary must exist"));
            let body = &source[start..start + end];
            assert!(
                body.contains(signature),
                "{handler} must extract the middleware-inserted admission"
            );
            assert!(
                body.contains(binding),
                "{handler} must bind the admission into the org mutation context"
            );
        }
        // create/domain 变更不影响任何卡的有效资格：不提取、不消费 admission。
        for (handler, next_anchor) in [
            ("async fn create_org(", "async fn get_org("),
            ("async fn create_domain(", "async fn get_domain("),
            ("async fn create_tenant(", "async fn get_tenant("),
            ("async fn update_domain(", "async fn delete_domain("),
            ("async fn delete_domain(", "async fn list_domain_tenants("),
        ] {
            let start = source
                .find(handler)
                .unwrap_or_else(|| panic!("{handler} handler must stay in orgs.rs"));
            let end = source[start..]
                .find(next_anchor)
                .unwrap_or_else(|| panic!("{handler} body boundary must exist"));
            let body = &source[start..start + end];
            assert!(
                !body.contains("AuthorizationAdmission"),
                "{handler} must not extract or consume an authorization admission"
            );
        }
    }
}
