//! 域 CRUD API（DomainController 拆分模块 1/7）— HTTP adapter
//!
//! 提供域（domain）的 CRUD 操作与默认域同步。
//! 对齐 Java `DomainControlController` 中域管理部分。
//! 数据访问在 `repository::domain_repository`，HTTP 层仅解析参数并包装响应。
//! 路径前缀：`/main/api/v1/domains`
//!
//! create/update/delete 是域治理 mutation：handler 必须提取 permission 中间件
//! 注入的 `AuthorizationAdmission` 与已验证 `PolicyContext`，且 Gateway 身份头
//! 必须与该 context 完全一致后才能构造 `DomainMutationContext`（缺失 admission
//! 的 Extension 提取直接 fail-closed）；`require_platform_admin` 的既有
//! GlobalAdmin 门禁保持不变。GET/list 为只读路径，不注入 admission、不开启
//! source 事务；`defaults/sync` 保留 bootstrap/system 语义（幂等直连写入、
//! 不强制用户 admission）。事务内的 actor 卡行对牌、目标域行锁与
//! proven-commit 语义由 repository 承担。

use axum::extract::{Extension, Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_types::{AstralError, AuthorizationAdmission, PolicyContext};

use crate::api::require_platform_admin;
use crate::repository::domain_repository::{
    DomainFilter, DomainMutationContext, DomainPatch, DomainRecord, NewDomain,
};
use crate::AppState;

// ===== DTO =====

/// Domain response follows the persisted domain fields.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainDto {
    pub id: i64,
    pub name: String,
    pub code: Option<String>,
    pub description: Option<String>,
    pub status: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl From<DomainRecord> for DomainDto {
    fn from(r: DomainRecord) -> Self {
        Self {
            id: r.id,
            name: r.name,
            code: r.code,
            description: r.description,
            status: r.status,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDomainRequest {
    pub name: String,
    pub code: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateDomainRequest {
    pub name: Option<String>,
    pub code: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainQuery {
    pub status: Option<String>,
}

// ===== Routes =====

pub fn domain_routes() -> Router<AppState> {
    Router::new()
        .route("/domains", get(list_domains))
        .route("/domains", post(create_domain))
        .route("/domains/{id}", get(get_domain))
        .route("/domains/{id}", put(update_domain))
        .route("/domains/{id}", delete(delete_domain))
        .route("/domains/defaults/sync", post(sync_default_domains))
}

// ===== Handlers =====

/// Build a domain mutation context from the permission middleware's verified
/// extension. The Gateway headers are only accepted when they exactly agree with
/// that extension; the proof-bound admission is required for the source transaction.
fn domain_mutation_context(
    headers: &HeaderMap,
    policy_context: &PolicyContext,
    admission: AuthorizationAdmission,
) -> Result<DomainMutationContext, AppError> {
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
            "domain mutation Gateway headers do not match the verified PolicyContext".into(),
        )));
    }
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok());
    DomainMutationContext::from_policy_context(policy_context, request_id)
        .map(|context| context.with_admission(admission))
        .map_err(AppError::from)
}

/// GET /main/api/v1/domains — 列表（支持 status 过滤，分页）
async fn list_domains(
    State(state): State<AppState>,
    Query(q): Query<DomainQuery>,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<DomainDto>>>, AppError> {
    let filter = DomainFilter {
        status: q.status.as_ref().map(|s| s.to_uppercase()),
    };
    let total = state.domain_repository.count_domains(&filter).await?;
    let rows = state
        .domain_repository
        .list_domains(&filter, page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(DomainDto::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

/// GET /main/api/v1/domains/{id} — 查询
async fn get_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<DomainDto>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let row = state
        .domain_repository
        .get_domain(id)
        .await?
        .map(DomainDto::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("domain {id}"))))?;
    Ok(Json(ApiResponse::success(row)))
}

/// POST /main/api/v1/domains — 创建
///
/// 域治理 mutation：要求已验证 ACTIVE GlobalAdmin；经 proof-bound admission
/// source transaction 落库。
async fn create_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
    Extension(admission): Extension<AuthorizationAdmission>,
    Json(req): Json<CreateDomainRequest>,
) -> Result<Json<ApiResponse<DomainDto>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = domain_mutation_context(&headers, &policy_context, admission)?;
    let status = req
        .status
        .map(|s| s.to_uppercase())
        .unwrap_or_else(|| "ACTIVE".into());
    if status != "ACTIVE" && status != "INACTIVE" {
        return Err(AppError(AstralError::Validation(
            "status must be ACTIVE or INACTIVE".into(),
        )));
    }

    let new = NewDomain {
        name: req.name,
        code: req.code,
        status,
    };
    let new_id = state
        .domain_repository
        .create_domain_with_context(&new, &context)
        .await?;
    let row = state
        .domain_repository
        .get_domain(new_id)
        .await?
        .map(DomainDto::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("domain {new_id}"))))?;

    tracing::info!(id = new_id, name = %new.name, "domain created");
    Ok(Json(ApiResponse::success(row)))
}

/// PUT /main/api/v1/domains/{id} — 更新
///
/// 域治理 mutation：要求已验证 ACTIVE GlobalAdmin；经 proof-bound admission
/// source transaction 落库。
async fn update_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
    Extension(admission): Extension<AuthorizationAdmission>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateDomainRequest>,
) -> Result<Json<ApiResponse<DomainDto>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = domain_mutation_context(&headers, &policy_context, admission)?;
    // 状态白名单校验（对齐现有 handler 语义）
    let status = match req.status.as_ref() {
        Some(raw) => {
            let upper = raw.to_uppercase();
            if upper != "ACTIVE" && upper != "INACTIVE" {
                return Err(AppError(AstralError::Validation(
                    "status must be ACTIVE or INACTIVE".into(),
                )));
            }
            Some(upper)
        }
        None => None,
    };

    let patch = DomainPatch {
        name: req.name,
        code: req.code,
        status,
    };
    state
        .domain_repository
        .update_domain_with_context(id, &patch, &context)
        .await?;

    let row = state
        .domain_repository
        .get_domain(id)
        .await?
        .map(DomainDto::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("domain {id}"))))?;

    tracing::info!(id, "domain updated");
    Ok(Json(ApiResponse::success(row)))
}

/// DELETE /main/api/v1/domains/{id} — 删除域（软删除）
///
/// 域治理 mutation：要求已验证 ACTIVE GlobalAdmin；经 proof-bound admission
/// source transaction 落库（软删除语义保持不变）。
async fn delete_domain(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy_context): Extension<PolicyContext>,
    Extension(admission): Extension<AuthorizationAdmission>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let context = domain_mutation_context(&headers, &policy_context, admission)?;
    let deleted = state
        .domain_repository
        .delete_domain_with_context(id, &context)
        .await?;
    if !deleted {
        return Err(AppError(AstralError::NotFound(format!(
            "domain {id} (not found or already inactive)"
        ))));
    }

    tracing::info!(id, "domain soft-deleted");
    Ok(Json(ApiResponse::success(
        serde_json::json!({ "id": id, "status": "INACTIVE" }),
    )))
}

/// POST /main/api/v1/domains/defaults/sync — 同步默认域
///
/// bootstrap/system 语义：幂等确保系统至少有一个默认域（名为 "默认域"），
/// 保留既有直连写入与容错语义，不强制用户 admission（不走 `_with_context`
/// 用户 source 事务路径）。platform_v4 中 platform_domain 表无 org_id 列，
/// 不再按组织维度同步。
async fn sync_default_domains(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let result = state.domain_repository.sync_default_domain().await?;

    tracing::info!(
        existing_domains = result.existing,
        created = result.created,
        "default domains synced"
    );
    Ok(Json(ApiResponse::success(serde_json::json!({
        "existing_domains": result.existing,
        "domains_created": result.created,
    }))))
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

    /// 域 mutation 与 departments/user-levels mutation 共用同一装配合同：
    /// Gateway 头必须与验证过的 PolicyContext 完全一致，缺头/不一致/非平台
    /// 身份/缺失 request id 一律拒绝。
    #[test]
    fn domain_mutation_context_requires_header_policy_agreement() {
        let policy = platform_policy_context(10, 20, 30, 40);
        let admission_fn = || {
            // admission 只作为不透明能力透传；装配合同测试关注 header/context
            // 一致性与 request id，能力本身由 repository 的锁定行对牌复核。
            build_test_admission()
        };
        let agreed = domain_mutation_context(
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
                domain_mutation_context(&tampered, &policy, admission_fn()).is_err(),
                "any header disagreeing with the verified PolicyContext must be rejected"
            );
        }
        assert!(
            domain_mutation_context(&HeaderMap::new(), &policy, admission_fn()).is_err(),
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
            domain_mutation_context(
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
            domain_mutation_context(&no_request_id, &policy, admission_fn()).is_err(),
            "a missing request id must fail closed"
        );
    }

    /// 结构守卫（include_str!，不连 DB）：create/update/delete 必须提取
    /// `Extension<AuthorizationAdmission>` 与 `Extension<PolicyContext>`、
    /// 保留 `require_platform_admin` 门禁、并经 `domain_mutation_context`
    /// 装配后走 `_with_context` 入口；GET/list 保持只读（不提取 admission、
    /// 不开启 source 事务）；`defaults/sync` 保持 bootstrap/system 语义，
    /// 不强制用户 admission。
    #[test]
    fn mutation_handlers_require_admission_and_read_paths_stay_context_free() {
        let source = include_str!("domains.rs");
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

        for name in ["create_domain", "update_domain", "delete_domain"] {
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
                body.contains(concat!(
                    "require_platform_",
                    "admin(&state, &headers).await?"
                )),
                "{name} must keep the platform admin gate"
            );
            assert!(
                body.contains("domain_mutation_context(&headers, &policy_context, admission)"),
                "{name} must assemble the mutation context through the verified path"
            );
            assert!(
                body.contains("_with_context"),
                "{name} must dispatch through the context-bound repository entry"
            );
        }

        for name in ["list_domains", "get_domain"] {
            let body = handler_body(name);
            assert!(
                !body.contains("AuthorizationAdmission")
                    && !body.contains("begin_source_transaction"),
                "{name} must stay a read-only path without admission or source transactions"
            );
        }

        // bootstrap/system 语义保留：defaults/sync 不提取用户 admission、
        // 不经 mutation context 装配。
        let sync_body = handler_body("sync_default_domains");
        assert!(
            !sync_body.contains("Extension<AuthorizationAdmission>")
                && !sync_body.contains("Extension<PolicyContext>")
                && !sync_body.contains("domain_mutation_context(")
                && !sync_body.contains("_with_context"),
            "defaults/sync must stay a bootstrap path without forced user admission"
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
            operation_id: "op-domain-api-test".into(),
            event_id: "evt-domain-api-test".into(),
            key_id: "key-test".into(),
            key_epoch: 1,
            issued_at: 1_700_000_000,
            not_before: 1_700_000_000,
            expires_at: 1_700_000_400,
            request_nonce: "nonce-domain-api-test".into(),
            request_binding_digest: None,
            scope_certificate_hash: None,
            proof_id: "proof-domain-api-test".into(),
            signature: "ab".repeat(64),
        };
        AuthorizationAdmission::from_verified_proof(proof).expect("structurally valid proof")
    }
}
