//! 租户上下文中间件
//!
//! 自动将 `x-identity-tenant-id` / `x-identity-domain-id` 请求头注入 SQLx 查询上下文。
//! 配合 `DataScopeRuleProvider` 使用，实现自动化的租户数据隔离。
//!
//! # 使用方式
//!
//! 本中间件将租户信息注入到 Request extensions 中，供后续的 SQLx 查询层读取。
//! 应用层在构建查询时调用 `build_tenant_where()` 自动拼接参数化 WHERE 条件。
//!
//! ```
//! use astral_common::middleware::tenant_context::{
//!     build_tenant_where, TenantContext,
//! };
//! use axum::body::Body;
//! use axum::http::Request;
//!
//! // 从请求中提取租户上下文
//! let mut req = Request::new(Body::empty());
//! req.headers_mut().insert(
//!     "x-user-card-tenant-id",
//!     "42".parse().expect("valid header value"),
//! );
//! req.headers_mut().insert(
//!     "x-user-card-domain-id",
//!     "10".parse().expect("valid header value"),
//! );
//! let ctx = TenantContext::from_headers(req.headers());
//!
//! // 注入到请求 extension，供下游处理器读取
//! req.extensions_mut().insert(ctx.clone());
//!
//! // 在查询时自动追加参数化过滤
//! let (filter, params) = build_tenant_where("", ctx.tenant_id, ctx.domain_id);
//! assert_eq!(filter, "AND tenant_id = ? AND domain_id = ?");
//! assert_eq!(params, vec![42, 10]);
//! ```

use axum::extract::Request;
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;

/// 租户上下文：从请求头中提取的租户隔离标识
///
/// 上游网关注入 identity/user-card 分离的 tenant/domain 头。

#[derive(Debug, Clone, Default)]
pub struct TenantContext {
    /// 当前租户 ID
    pub tenant_id: Option<i64>,
    /// 当前域 ID
    pub domain_id: Option<i64>,
    /// 当前用户 ID
    pub user_id: Option<i64>,
    /// 当前身份卡 ID
    pub card_id: Option<i64>,
    /// 租户状态
    pub tenant_status: Option<String>,
}

impl TenantContext {
    /// 从请求头的身份信息构建租户上下文
    pub fn from_headers(headers: &HeaderMap) -> Self {
        Self {
            tenant_id: headers
                .get("x-user-card-tenant-id")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<i64>().ok()),
            domain_id: headers
                .get("x-user-card-domain-id")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<i64>().ok()),
            user_id: headers
                .get("x-user-id")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<i64>().ok()),
            card_id: headers
                .get("x-user-card-id")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<i64>().ok()),
            tenant_status: headers
                .get("x-tenant-status")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
        }
    }

    /// 租户是否为 ACTIVE 状态
    pub fn is_tenant_active(&self) -> bool {
        self.tenant_status
            .as_deref()
            .map(|s| s == "ACTIVE")
            .unwrap_or(true)
    }

    /// 将租户上下文转换为 SQL WHERE 子句片段
    ///
    /// 返回形如 `"AND tenant_id = 42 AND domain_id = 10"` 的 SQL 片段。
    /// 如果没有任何过滤条件，返回空字符串。
    pub fn to_sql_filter(&self) -> String {
        let mut clauses: Vec<String> = Vec::new();
        if let Some(tid) = self.tenant_id {
            clauses.push(format!("tenant_id = {tid}"));
        }
        if let Some(did) = self.domain_id {
            clauses.push(format!("domain_id = {did}"));
        }
        if clauses.is_empty() {
            String::new()
        } else {
            format!("AND {}", clauses.join(" AND "))
        }
    }
}

/// 租户上下文中间件
///
/// 从请求头中提取租户标识，注入到 Request extensions 中。
/// 下游处理器/服务通过 `req.extensions().get::<TenantContext>()` 获取。
pub async fn tenant_context_middleware(mut req: Request, next: Next) -> Response {
    let ctx = TenantContext::from_headers(req.headers());
    req.extensions_mut().insert(ctx);
    next.run(req).await
}

/// 从请求扩展中读取租户上下文
///
/// # 参数
/// * `req` - axum 请求引用
///
/// # 返回
/// 如果扩展中不存在 TenantContext，返回默认空上下文
pub fn extract_tenant_context(req: &Request) -> TenantContext {
    req.extensions()
        .get::<TenantContext>()
        .cloned()
        .unwrap_or_default()
}

/// 根据租户上下文和表别名，生成参数化 SQL WHERE 片段
///
/// # 参数
/// * `table_alias` - 表别名（如 `"t"`、`"m"`），空字符串表示无别名
/// * `tenant_id` - 可选的租户 ID，None 时不生成 tenant 过滤
/// * `domain_id` - 可选的域 ID，None 时不生成 domain 过滤
///
/// # 返回
/// `(where_clause, params)` 元组，where_clause 形如 `"AND t.tenant_id = ? AND t.domain_id = ?"`
/// params 为对应的参数值列表
pub fn build_tenant_where(
    table_alias: &str,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
) -> (String, Vec<i64>) {
    let prefix = if table_alias.is_empty() {
        String::new()
    } else {
        format!("{}.", table_alias)
    };

    let mut clauses: Vec<String> = Vec::new();
    let mut params: Vec<i64> = Vec::new();

    if let Some(tid) = tenant_id {
        clauses.push(format!("{prefix}tenant_id = ?"));
        params.push(tid);
    }
    if let Some(did) = domain_id {
        clauses.push(format!("{prefix}domain_id = ?"));
        params.push(did);
    }

    if clauses.is_empty() {
        (String::new(), params)
    } else {
        (format!("AND {}", clauses.join(" AND ")), params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_from_headers_tenant_only() {
        let mut headers = HeaderMap::new();
        headers.insert("x-identity-tenant-id", HeaderValue::from_static("42"));
        let ctx = TenantContext::from_headers(&headers);
        assert!(ctx.tenant_id.is_none());
        assert!(ctx.domain_id.is_none());
    }

    #[test]
    fn test_from_headers_all_fields() {
        let mut headers = HeaderMap::new();
        headers.insert("x-user-card-tenant-id", HeaderValue::from_static("1"));
        headers.insert("x-user-card-domain-id", HeaderValue::from_static("10"));
        headers.insert("x-user-id", HeaderValue::from_static("100"));
        headers.insert("x-user-card-id", HeaderValue::from_static("5"));
        headers.insert("x-tenant-status", HeaderValue::from_static("ACTIVE"));
        let ctx = TenantContext::from_headers(&headers);
        assert_eq!(ctx.tenant_id, Some(1));
        assert_eq!(ctx.domain_id, Some(10));
        assert_eq!(ctx.user_id, Some(100));
        assert_eq!(ctx.card_id, Some(5));
        assert_eq!(ctx.tenant_status.as_deref(), Some("ACTIVE"));
    }

    #[test]
    fn test_to_sql_filter_tenant_only() {
        let ctx = TenantContext {
            tenant_id: Some(42),
            ..Default::default()
        };
        assert_eq!(ctx.to_sql_filter(), "AND tenant_id = 42");
    }

    #[test]
    fn test_to_sql_filter_tenant_and_domain() {
        let ctx = TenantContext {
            tenant_id: Some(1),
            domain_id: Some(10),
            ..Default::default()
        };
        assert_eq!(ctx.to_sql_filter(), "AND tenant_id = 1 AND domain_id = 10");
    }

    #[test]
    fn test_to_sql_filter_empty() {
        let ctx = TenantContext::default();
        assert_eq!(ctx.to_sql_filter(), "");
    }

    #[test]
    fn test_is_tenant_active() {
        let ctx = TenantContext {
            tenant_status: Some("ACTIVE".into()),
            ..Default::default()
        };
        assert!(ctx.is_tenant_active());

        let ctx = TenantContext {
            tenant_status: Some("SUSPENDED".into()),
            ..Default::default()
        };
        assert!(!ctx.is_tenant_active());
    }

    #[test]
    fn test_build_tenant_where() {
        let (clause, params) = build_tenant_where("t", Some(42), Some(10));
        assert_eq!(clause, "AND t.tenant_id = ? AND t.domain_id = ?");
        assert_eq!(params, vec![42, 10]);
    }

    #[test]
    fn test_build_tenant_where_no_alias() {
        let (clause, params) = build_tenant_where("", Some(42), None);
        assert_eq!(clause, "AND tenant_id = ?");
        assert_eq!(params, vec![42]);
    }

    #[test]
    fn test_build_tenant_where_empty() {
        let (clause, params) = build_tenant_where("", None, None);
        assert_eq!(clause, "");
        assert!(params.is_empty());
    }
}
