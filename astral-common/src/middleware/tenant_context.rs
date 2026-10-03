//! 租户上下文中间件
//!
//! 将签名 Gateway 注入的 user-card tenant/domain 事实注入请求扩展，供显式
//! query builders 使用。此中间件本身不修改 SQL，也不代表 `DataScopeRuleProvider`
//! 会自动施加数据范围规则；任何缺失 tenant 的 SQL 过滤构造都返回零行谓词。
//!
//! # 使用方式
//!
//! 本中间件将租户信息注入到 Request extensions 中，供后续的 SQLx 查询层读取。
//! 应用层在构建查询时调用 `build_tenant_where()` 自动拼接参数化 WHERE 条件。
//!
//! ```
//! use astral_common::middleware::tenant_context::{build_tenant_where, TenantContext};
//! use axum::body::Body;
//! use axum::http::Request;
//!
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
//! req.extensions_mut().insert(ctx.clone());
//! let (filter, params) = build_tenant_where("t", ctx.tenant_id, ctx.domain_id);
//! assert_eq!(filter, "AND t.tenant_id = ? AND t.domain_id = ?");
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

    /// 将租户上下文转换为 fail-closed SQL WHERE 子句片段。
    ///
    /// 返回形如 `AND tenant_id = 42 AND domain_id = 10` 的 SQL 片段。缺失租户时
    /// 总是返回 `AND 1 = 0`，即使存在 domain/user 字段也不允许扩大到跨租户
    /// 查询。此片段不是通用 SQL 重写器；若基础谓词含 `OR`，调用方必须显式
    /// 括起它，或改用受限 [`TenantScopedQuery`](crate::middleware::tenant_filter::TenantScopedQuery)。
    pub fn to_sql_filter(&self) -> String {
        let Some(tenant_id) = self.tenant_id.filter(|value| *value > 0) else {
            return "AND 1 = 0".into();
        };
        let mut clauses = vec![format!("tenant_id = {tenant_id}")];
        if let Some(domain_id) = self.domain_id {
            if domain_id <= 0 {
                return "AND 1 = 0".into();
            }
            clauses.push(format!("domain_id = {domain_id}"));
        }
        format!("AND {}", clauses.join(" AND "))
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

/// Extract tenant context from request extensions.
///
/// This returns an empty context if middleware did not install one. Query builders
/// must treat that absence as unscoped and fail closed; this helper does not
/// establish or apply SQL scope by itself.
pub fn extract_tenant_context(req: &Request) -> TenantContext {
    req.extensions()
        .get::<TenantContext>()
        .cloned()
        .unwrap_or_default()
}

/// 根据租户上下文和表别名，生成参数化 SQL WHERE 片段
///
/// # 参数
/// * `table_alias` - simple identifier for a table alias; empty means unqualified
/// * `tenant_id` - positive tenant ID; missing or invalid values fail closed
/// * `domain_id` - optional positive domain ID
///
/// # Return
/// `(where_clause, params)`. Missing tenant, invalid ID, or invalid alias returns
/// `AND 1 = 0` with no parameters. This helper is not an arbitrary SQL parser; if
/// you append it to a base query containing `OR`, parenthesize that query first.
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
    let alias_valid = table_alias.is_empty()
        || (table_alias
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
            && table_alias
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'));

    let Some(tenant_id) = tenant_id.filter(|value| *value > 0) else {
        return ("AND 1 = 0".into(), params);
    };
    if domain_id.is_some_and(|value| value <= 0) || !alias_valid {
        return ("AND 1 = 0".into(), params);
    }
    clauses.push(format!("{prefix}tenant_id = ?"));
    params.push(tenant_id);
    if let Some(domain_id) = domain_id {
        clauses.push(format!("{prefix}domain_id = ?"));
        params.push(domain_id);
    }

    (format!("AND {}", clauses.join(" AND ")), params)
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
    fn test_to_sql_filter_missing_tenant_fails_closed() {
        let ctx = TenantContext::default();
        assert_eq!(ctx.to_sql_filter(), "AND 1 = 0");
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
    fn test_build_tenant_where_missing_tenant_fails_closed() {
        let (clause, params) = build_tenant_where("", None, None);
        assert_eq!(clause, "AND 1 = 0");
        assert!(params.is_empty());
    }

    #[test]
    fn test_build_tenant_where_rejects_invalid_alias_and_scope() {
        assert_eq!(
            build_tenant_where("t; DROP", Some(42), None),
            ("AND 1 = 0".into(), vec![])
        );
        assert_eq!(
            build_tenant_where("t", Some(42), Some(0)),
            ("AND 1 = 0".into(), vec![])
        );
    }
}
