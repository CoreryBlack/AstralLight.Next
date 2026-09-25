//! 跨组织授权 API — HTTP adapter
//!
//! 对齐 Java `CrossOrgGrantService`。
//! 提供跨组织授权的**管理侧读取**端点；写入端点 fail-closed。
//!
//! **fail-closed 写边界**：`GrantSourceKind` 是封闭的规范来源集，cross_org_grant
//! 不属于其中任何来源族，且没有任何 policy/projection 读者消费该表。因此
//! `create_cross_org_grant` / `revoke_cross_org_grant` 把 repository 的
//! `AstralError::NotImplemented`（HTTP 501）经 `?` 原样向上传播，绝不把失败的
//! 写入包装为成功响应；真正的写拒绝发生在 repository 层（任何 INSERT/UPDATE
//! 之前），HTTP 层只负责忠实转发。
//!
//! `list_cross_org_grants` 保留为纯 SELECT 的管理侧读取（administrative read），
//! 不是正式授权事实；其结果不得用作 PolicyEngine 放行依据。
//! 数据访问在 `repository::cross_org_grant_repository`，HTTP 层仅解析参数并包装响应。

use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_types::AstralError;

use crate::repository::cross_org_grant_repository::CrossOrgGrantRecord;
use crate::AppState;

// ===== 数据模型 =====

/// 跨组织授权响应 DTO（对齐 Java 实体 camelCase 序列化）
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CrossOrgGrant {
    pub id: i64,
    pub from_org_id: i64,
    pub to_org_id: i64,
    pub resource: String,
    pub action: String,
    pub status: String,
    pub expires_at: Option<i64>,
    pub created_at: Option<i64>,
}

impl From<CrossOrgGrantRecord> for CrossOrgGrant {
    fn from(r: CrossOrgGrantRecord) -> Self {
        Self {
            id: r.id,
            from_org_id: r.from_org_id,
            to_org_id: r.to_org_id,
            resource: r.resource,
            action: r.action,
            status: r.status,
            expires_at: r.expires_at,
            created_at: r.created_at,
        }
    }
}

/// 创建跨组织授权请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCrossOrgGrantRequest {
    pub from_org_id: i64,
    pub to_org_id: i64,
    pub resource: String,
    pub action: String,
    /// UNIX 时间戳（秒），过期时间
    pub expires_at: Option<i64>,
}

// ===== 路由注册 =====

pub fn cross_org_grant_routes() -> Router<AppState> {
    Router::new()
        .route("/cross-org-grants", get(list_cross_org_grants))
        // 写入端点 fail-closed：POST/DELETE 一律透传 repository 的 501 NotImplemented。
        .route("/cross-org-grants", post(create_cross_org_grant))
        .route("/cross-org-grants/{id}", delete(revoke_cross_org_grant))
}

// ===== Handlers =====

/// GET /main/api/v1/cross-org-grants — 列出所有跨组织授权（分页）
///
/// 管理侧读取（administrative read），非正式授权事实。
async fn list_cross_org_grants(
    State(state): State<AppState>,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<CrossOrgGrant>>>, AppError> {
    let total = state.cross_org_grant_repository.count_grants().await?;
    let rows = state
        .cross_org_grant_repository
        .list_grants(page.effective_size(), page.offset())
        .await?;
    let result = rows.into_iter().map(CrossOrgGrant::from).collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        result,
        total,
        page.page,
        page.effective_size(),
    ))))
}

/// POST /main/api/v1/cross-org-grants — 创建跨组织授权
///
/// fail-closed：repository 在任何 INSERT 之前返回 `NotImplemented`，本 handler
/// 经 `?` 透传该失败（HTTP 501），不会产生成功响应，也不会记录“已创建”日志。
async fn create_cross_org_grant(
    State(state): State<AppState>,
    Json(req): Json<CreateCrossOrgGrantRequest>,
) -> Result<Json<ApiResponse<CrossOrgGrant>>, AppError> {
    if req.from_org_id == req.to_org_id {
        return Err(AppError(AstralError::Validation(
            "from_org_id and to_org_id must be different".into(),
        )));
    }

    // fail-closed 写边界：upsert_grant 在任何 INSERT/UPDATE 之前拒绝，
    // 错误经 `?` 原样向上传播为 501。
    let row = state
        .cross_org_grant_repository
        .upsert_grant(
            req.from_org_id,
            req.to_org_id,
            &req.resource,
            &req.action,
            req.expires_at,
        )
        .await?;

    tracing::info!(
        id = row.id,
        from = req.from_org_id,
        to = req.to_org_id,
        resource = %req.resource,
        action = %req.action,
        "cross-org grant created"
    );

    Ok(Json(ApiResponse::success(CrossOrgGrant::from(row))))
}

/// DELETE /main/api/v1/cross-org-grants/{id} — 撤销跨组织授权
///
/// fail-closed：repository 在任何 UPDATE 之前返回 `NotImplemented`，本 handler
/// 经 `?` 透传该失败（HTTP 501），不会产生成功响应。
async fn revoke_cross_org_grant(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    // fail-closed 写边界：revoke_grant 在任何 UPDATE 之前拒绝，错误经 `?` 透传。
    let revoked = state.cross_org_grant_repository.revoke_grant(id).await?;
    if !revoked {
        return Err(AppError(AstralError::NotFound(format!(
            "cross-org grant {id} not found"
        ))));
    }

    tracing::warn!(id, "cross-org grant revoked");
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 提取 handler 函数体（到下一个列 0 的 `}` 为止）。
    fn handler_body<'a>(source: &'a str, fn_name: &str) -> &'a str {
        let marker = format!("async fn {fn_name}");
        let after = source
            .split(marker.as_str())
            .nth(1)
            .expect("handler must exist in this module");
        let end = after.find("\n}").unwrap_or(after.len());
        &after[..end]
    }

    /// 生产代码部分（剥离测试模块，避免断言文本自身命中）。
    fn production_source() -> &'static str {
        include_str!("cross_org_grants.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap()
    }

    /// fail-closed 形状守卫：create handler 必须把 repository 的写入拒绝经 `?`
    /// 向上传播，成功响应只能在 repository 调用之后构造，且不得吞错。
    #[test]
    fn create_handler_surfaces_repository_failure_instead_of_success() {
        let body = handler_body(production_source(), "create_cross_org_grant");

        let upsert = body
            .find(".upsert_grant(")
            .expect("create handler must delegate the write to the repository");
        let propagation = body
            .find(".await?")
            .expect("repository failure must propagate via `?`");
        let success = body
            .find("ApiResponse::success")
            .expect("success shape must remain after a repository Ok");
        assert!(
            upsert < propagation && propagation < success,
            "success may only be constructed after the repository call returns Ok; \
             the write guard itself lives in the repository"
        );

        for forbidden in ["let _ =", ".ok()", "unwrap_or", ".unwrap()", ".expect("] {
            assert!(
                !body.contains(forbidden),
                "create handler must not swallow the fail-closed error (found {forbidden})"
            );
        }
    }

    /// fail-closed 形状守卫：revoke handler 必须经 `?` 透传 repository 的写入拒绝。
    #[test]
    fn revoke_handler_surfaces_repository_failure_instead_of_success() {
        let body = handler_body(production_source(), "revoke_cross_org_grant");

        let revoke = body
            .find(".revoke_grant(")
            .expect("revoke handler must delegate the write to the repository");
        let propagation = body
            .find(".await?")
            .expect("repository failure must propagate via `?`");
        assert!(
            revoke < propagation,
            "revoke failure must propagate via `?` before any success response"
        );

        for forbidden in ["let _ =", ".ok()", "unwrap_or", ".unwrap()", ".expect("] {
            assert!(
                !body.contains(forbidden),
                "revoke handler must not swallow the fail-closed error (found {forbidden})"
            );
        }
    }

    /// list/count 保持为纯管理侧读取：handler 不得调用任何写入方法。
    #[test]
    fn list_handler_remains_administrative_read_only() {
        let body = handler_body(production_source(), "list_cross_org_grants");
        assert!(body.contains("count_grants"));
        assert!(body.contains("list_grants"));
        assert!(!body.contains("upsert_grant"));
        assert!(!body.contains("revoke_grant"));
    }

    /// 路由形状守卫：写入端点仍然路由到上述 fail-closed handlers（501 而非 404）。
    #[test]
    fn write_endpoints_stay_routed_to_the_fail_closed_handlers() {
        let routes = production_source();
        assert!(routes.contains("post(create_cross_org_grant)"));
        assert!(routes.contains("delete(revoke_cross_org_grant)"));
    }

    /// 纯请求解析守卫：camelCase 载荷解析形状保持稳定（API 契约未因 fail-closed 而变形）。
    #[test]
    fn create_request_parses_camel_case_payload() {
        let request: CreateCrossOrgGrantRequest = serde_json::from_str(
            r#"{"fromOrgId":1,"toOrgId":2,"resource":"learn_course","action":"read"}"#,
        )
        .expect("camelCase payload must parse");
        assert_eq!(request.from_org_id, 1);
        assert_eq!(request.to_org_id, 2);
        assert_eq!(request.resource, "learn_course");
        assert_eq!(request.action, "read");
        assert_eq!(request.expires_at, None);
    }
}
