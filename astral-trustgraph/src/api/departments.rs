//! 部门 CRUD API — HTTP adapter
//!
//! 对齐 Java `DepartmentController` + `DepartmentService`。
//! 数据访问在 `repository::department_repository`，HTTP 层仅解析参数、校验
//! 白名单并包装响应。
//!
//! create/update/delete 是部门治理 mutation：handler 必须提取 permission
//! 中间件注入的 `AuthorizationAdmission` 与已验证 `PolicyContext`，且 Gateway
//! 身份头必须与该 context 完全一致后才能构造 `DepartmentMutationContext`
//! （缺失 admission 的 Extension 提取直接 fail-closed）。GET/list 为只读路径，
//! 不注入 admission、不开启 source 事务。事务内的租户/scope 对牌、行锁、
//! 守卫与 proven-commit 语义由 repository 承担。

use axum::extract::{Extension, Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_types::{AstralError, AuthorizationAdmission, PolicyContext};

use crate::repository::department_repository::{
    DepartmentFilter, DepartmentMutationContext, DepartmentPatch, DepartmentRecord, NewDepartment,
};
use crate::AppState;

// ===== 数据模型 =====

/// 部门响应 DTO（对齐 platform_v4.departments camelCase）
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Department {
    pub id: i64,
    pub tenant_id: i64,
    pub name: String,
    pub code: Option<String>,
    pub parent_id: Option<i64>,
    pub sort_order: Option<i32>,
    pub status: String,
    pub description: Option<String>,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
}

impl From<DepartmentRecord> for Department {
    fn from(r: DepartmentRecord) -> Self {
        Self {
            id: r.id,
            tenant_id: r.tenant_id,
            name: r.name,
            code: r.code,
            parent_id: r.parent_id,
            sort_order: r.sort_order,
            status: r.status,
            description: r.description,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// 创建部门请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDepartmentRequest {
    pub tenant_id: i64,
    pub name: String,
    pub code: Option<String>,
    pub parent_id: Option<i64>,
    pub sort_order: Option<i32>,
    pub description: Option<String>,
}

/// 更新部门请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDepartmentRequest {
    pub name: Option<String>,
    pub code: Option<String>,
    pub parent_id: Option<i64>,
    pub sort_order: Option<i32>,
    pub description: Option<String>,
}

/// 列表查询参数
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListDepartmentsQuery {
    pub parent_id: Option<i64>,
    pub tenant_id: Option<i64>,
}

// ===== 路由注册 =====

pub fn department_routes() -> Router<AppState> {
    Router::new()
        .route("/departments", get(list_departments))
        .route("/departments", post(create_department))
        .route("/departments/{id}", put(update_department))
        .route("/departments/{id}", delete(delete_department))
}

// ===== Handlers =====

/// Build a department mutation context from the permission middleware's verified
/// extension. The Gateway headers are only accepted when they exactly agree with
/// that extension; the proof-bound admission is required for the source transaction.
fn department_mutation_context(
    headers: &HeaderMap,
    policy_context: &PolicyContext,
    admission: AuthorizationAdmission,
) -> Result<DepartmentMutationContext, AppError> {
    let parse = |name: &'static str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value > 0)
            .ok_or_else(|| {
                AppError(AstralError::Auth(format!(
                    "Gateway-verified {name} is required"
                )))
            })
    };
    let user_id = parse("x-user-id")?;
    let card_id = parse("x-user-card-id")?;
    let tenant_id = parse("x-user-card-tenant-id")?;
    let domain_id = parse("x-user-card-domain-id")?;
    if policy_context.principal_kind.as_deref() != Some("PLATFORM_USER")
        || policy_context.user_id != Some(user_id)
        || policy_context.card_id != Some(card_id)
        || policy_context.tenant_id != Some(tenant_id)
        || policy_context.domain_id != Some(domain_id)
    {
        return Err(AppError(AstralError::Auth(
            "department mutation Gateway headers do not match the verified PolicyContext".into(),
        )));
    }
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok());
    DepartmentMutationContext::from_policy_context(policy_context, request_id)
        .map(|context| context.with_admission(admission))
        .map_err(AppError::from)
}

/// GET /main/api/v1/departments — 列出部门（支持 parent_id/tenant_id 过滤，分页）
async fn list_departments(
    State(state): State<AppState>,
    Query(query): Query<ListDepartmentsQuery>,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<Department>>>, AppError> {
    let filter = DepartmentFilter {
        parent_id: query.parent_id,
        tenant_id: query.tenant_id,
    };
    let total = state
        .department_repository
        .count_departments(&filter)
        .await?;
    let rows = state
        .department_repository
        .list_departments(&filter, page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(Department::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

/// POST /main/api/v1/departments — 创建部门
async fn create_department(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
    Extension(admission): Extension<AuthorizationAdmission>,
    Json(req): Json<CreateDepartmentRequest>,
) -> Result<Json<ApiResponse<Department>>, AppError> {
    let context = department_mutation_context(&headers, &policy_context, admission)?;
    let new = NewDepartment {
        tenant_id: req.tenant_id,
        name: req.name,
        code: req.code,
        parent_id: req.parent_id,
        sort_order: req.sort_order.unwrap_or(0),
        description: req.description,
    };
    let new_id = state
        .department_repository
        .create_department_with_context(&new, &context)
        .await?;
    let row = state
        .department_repository
        .get_department(new_id)
        .await?
        .map(Department::from)
        .ok_or_else(|| {
            AppError(AstralError::Database(format!(
                "department {new_id} not found after insert"
            )))
        })?;

    tracing::info!(id = new_id, name = %new.name, "department created");
    Ok(Json(ApiResponse::success(row)))
}

/// PUT /main/api/v1/departments/{id} — 更新部门
async fn update_department(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
    Extension(admission): Extension<AuthorizationAdmission>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateDepartmentRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let context = department_mutation_context(&headers, &policy_context, admission)?;
    let patch = DepartmentPatch {
        name: req.name,
        code: req.code,
        parent_id: req.parent_id,
        sort_order: req.sort_order,
        description: req.description,
    };
    state
        .department_repository
        .update_department_with_context(id, &patch, &context)
        .await?;

    tracing::info!(id, "department updated");
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

/// DELETE /main/api/v1/departments/{id} — 删除部门
async fn delete_department(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
    Extension(admission): Extension<AuthorizationAdmission>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let context = department_mutation_context(&headers, &policy_context, admission)?;
    state
        .department_repository
        .delete_department_with_context(id, &context)
        .await?;

    tracing::warn!(id, "department deleted");
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn platform_policy_context(
        user_id: i64,
        card_id: i64,
        tenant_id: i64,
        domain_id: i64,
    ) -> PolicyContext {
        PolicyContext::builder()
            .user_id(Some(user_id))
            .principal_kind(Some("PLATFORM_USER".into()))
            .card_id(Some(card_id))
            .tenant_id(Some(tenant_id))
            .domain_id(Some(domain_id))
            .action("manage".into())
            .build()
    }

    fn verified_headers(
        user_id: i64,
        card_id: i64,
        tenant_id: i64,
        domain_id: i64,
        request_id: &str,
    ) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("x-user-id", user_id.to_string()),
            ("x-user-card-id", card_id.to_string()),
            ("x-user-card-tenant-id", tenant_id.to_string()),
            ("x-user-card-domain-id", domain_id.to_string()),
            ("x-request-id", request_id.to_string()),
        ] {
            headers.insert(
                name,
                HeaderValue::from_str(&value).expect("valid header value"),
            );
        }
        headers
    }

    /// 部门 mutation 与租户 mutation 共用同一装配合同：Gateway 头必须与验证过
    /// 的 PolicyContext 完全一致，缺头/不一致/非平台身份一律拒绝。
    #[test]
    fn department_mutation_context_requires_header_policy_agreement() {
        let policy = platform_policy_context(10, 20, 30, 40);
        let admission_fn = || {
            // admission 只作为不透明能力透传；装配合同测试关注 header/context
            // 一致性与 request id，能力本身由 repository 的锁定行对牌复核。
            build_test_admission()
        };
        let agreed = department_mutation_context(
            &verified_headers(10, 20, 30, 40, "req-7"),
            &policy,
            admission_fn(),
        );
        assert!(agreed.is_ok(), "agreed headers must build the context");

        for tampered in [
            verified_headers(11, 20, 30, 40, "req-7"),
            verified_headers(10, 21, 30, 40, "req-7"),
            verified_headers(10, 20, 31, 40, "req-7"),
            verified_headers(10, 20, 30, 41, "req-7"),
        ] {
            assert!(
                department_mutation_context(&tampered, &policy, admission_fn()).is_err(),
                "any header disagreeing with the verified PolicyContext must be rejected"
            );
        }
        assert!(
            department_mutation_context(&HeaderMap::new(), &policy, admission_fn()).is_err(),
            "missing Gateway headers must be rejected"
        );

        let non_platform = PolicyContext::builder()
            .user_id(Some(10))
            .principal_kind(Some("END_USER".into()))
            .card_id(Some(20))
            .tenant_id(Some(30))
            .domain_id(Some(40))
            .action("manage".into())
            .build();
        assert!(
            department_mutation_context(
                &verified_headers(10, 20, 30, 40, "req-7"),
                &non_platform,
                admission_fn()
            )
            .is_err(),
            "non-platform principal must be rejected"
        );

        // 缺失 request id：授权 mutation 无随机 fallback，直接拒绝。
        let mut no_request_id = verified_headers(10, 20, 30, 40, "req-7");
        no_request_id.remove("x-request-id");
        assert!(
            department_mutation_context(&no_request_id, &policy, admission_fn()).is_err(),
            "a missing request id must fail closed"
        );
    }

    /// 结构守卫（include_str!，不连 DB）：create/update/delete 必须提取
    /// `Extension<AuthorizationAdmission>` 与 `Extension<PolicyContext>` 并
    /// 经 `department_mutation_context` 装配后走 `_with_context` 入口；
    /// GET/list 保持只读（不提取 admission、不开启 source 事务）。
    #[test]
    fn mutation_handlers_require_admission_and_read_paths_stay_context_free() {
        let source = include_str!("departments.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source must exist");
        let handler_body = |name: &str| -> String {
            let start = production
                .find(&format!("async fn {name}"))
                .unwrap_or_else(|| panic!("{name} handler must exist"));
            let rest = &production[start..];
            let end = rest[1..]
                .find("async fn ")
                .map(|offset| offset + 1)
                .unwrap_or(rest.len());
            rest[..end].to_owned()
        };

        for name in [
            "create_department",
            "update_department",
            "delete_department",
        ] {
            let body = handler_body(name);
            assert!(
                body.contains("Extension(admission): Extension<AuthorizationAdmission>"),
                "{name} must require the proof-bound admission extension"
            );
            assert!(
                body.contains("Extension(policy_context): Extension<PolicyContext>"),
                "{name} must require the verified PolicyContext extension"
            );
            assert!(
                body.contains("department_mutation_context(&headers, &policy_context, admission)"),
                "{name} must assemble the mutation context through the verified path"
            );
            assert!(
                body.contains("_with_context"),
                "{name} must dispatch through the context-bound repository entry"
            );
        }

        let list_body = handler_body("list_departments");
        assert!(
            !list_body.contains("AuthorizationAdmission")
                && !list_body.contains("begin_source_transaction"),
            "GET/list must stay a read-only path without admission or source transactions"
        );
        assert!(
            !production.contains("tx.commit()"),
            "the HTTP adapter must never commit a source transaction directly"
        );
    }

    fn build_test_admission() -> AuthorizationAdmission {
        let proof = astral_types::AuthorizationFenceProof {
            authorization_edition: astral_types::AUTHORIZATION_EDITION,
            authority_id: "authority-test".into(),
            authority_term: 1,
            global_fence_sequence: 1,
            scope: astral_types::AuthorizationAuthorityScope {
                tenant_id: 30,
                card_id: 20,
                user_id: Some(10),
                domain: astral_types::AuthorizationDomainScope::Exact(40),
            },
            scope_generation: 1,
            revoke_watermark: 0,
            snapshot_hash: "a".repeat(64),
            parent_hash: None,
            operation_id: "op-dept-api-test".into(),
            event_id: "evt-dept-api-test".into(),
            key_id: "key-test".into(),
            key_epoch: 1,
            issued_at: 1_700_000_000,
            not_before: 1_700_000_000,
            expires_at: 1_700_000_400,
            request_nonce: "nonce-dept-api-test".into(),
            request_binding_digest: None,
            scope_certificate_hash: None,
            proof_id: "proof-dept-api-test".into(),
            signature: "ab".repeat(64),
        };
        AuthorizationAdmission::from_verified_proof(proof).expect("structurally valid proof")
    }
}
