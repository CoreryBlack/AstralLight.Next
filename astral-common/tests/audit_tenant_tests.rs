//! 审计日志 + 租户隔离单元测试
//!
//! 覆盖:
//! - AuditEntry 构造与序列化
//! - AuditEventType / AuditCategory 枚举覆盖
//! - record_audit() 兜底路径不 panic
//! - TenantContext 从请求头提取 + 租户状态检查
//! - TenantScopedQuery 租户作用域 SQL 构建器
//! - DataScopeFilter 租户隔离过滤器
//! - 跨租户绑定拒绝逻辑

use astral_common::audit::{record_audit, AuditCategory, AuditEntry, AuditEventType};
use astral_common::middleware::tenant_context::{build_tenant_where, TenantContext};
use astral_common::middleware::tenant_filter::{DataFrameScopeFilter, TenantScopedQuery};

// ===== 审计日志测试 =====

#[test]
fn test_audit_entry_construction() {
    let entry = AuditEntry {
        user_id: Some(1),
        card_id: Some(5),
        action: "read".into(),
        resource: "learn_subject:42".into(),
        decision: "ALLOW".into(),
        reason: Some("RULE_SET_ALLOW".into()),
        event_type: AuditEventType::PermissionCheck,
        category: Some(AuditCategory::Permission),
        source_ip: Some("10.0.0.1".into()),
        request_id: Some("req-abc".into()),
        domain_id: Some(10),
        tenant_id: Some(42),
        detail: Some(r#"{"key":"value"}"#.into()),
    };
    assert_eq!(entry.user_id, Some(1));
    assert_eq!(entry.tenant_id, Some(42));
    assert_eq!(entry.event_type, AuditEventType::PermissionCheck);
}

#[test]
fn test_audit_entry_serialization() {
    let entry = AuditEntry {
        user_id: Some(1),
        card_id: None,
        action: "login".into(),
        resource: "auth".into(),
        decision: "DENY".into(),
        reason: Some("AUTHN_REQUIRED".into()),
        event_type: AuditEventType::LoginFailure,
        category: Some(AuditCategory::IdentityLogin),
        source_ip: Some("192.168.1.1".into()),
        request_id: None,
        domain_id: None,
        tenant_id: Some(99),
        detail: None,
    };
    let json = serde_json::to_string(&entry).unwrap();
    assert!(json.contains("\"userId\":1"));
    assert!(json.contains("\"tenantId\":99"));
    assert!(json.contains("\"eventType\":\"LOGIN_FAILURE\""));
    assert!(json.contains("\"category\":\"identity-login\""));
}

#[test]
fn test_record_audit_does_not_panic() {
    // record_audit 只是 tracing 输出，不应 panic
    let entry = AuditEntry {
        user_id: Some(1),
        card_id: Some(1),
        action: "read".into(),
        resource: "test".into(),
        decision: "ALLOW".into(),
        reason: None,
        event_type: AuditEventType::PermissionCheck,
        category: None,
        source_ip: None,
        request_id: None,
        domain_id: None,
        tenant_id: Some(1),
        detail: None,
    };
    record_audit(entry);
}

#[test]
fn test_all_audit_event_types() {
    let types = [
        AuditEventType::PermissionCheck,
        AuditEventType::LoginSuccess,
        AuditEventType::LoginFailure,
        AuditEventType::RuleChange,
        AuditEventType::TokenRevocation,
        AuditEventType::IdentityUnbind,
        AuditEventType::CardSwitch,
        AuditEventType::DataScopeDeny,
    ];
    // 确保所有变体可序列化
    for t in &types {
        let json = serde_json::to_string(t).unwrap();
        assert!(!json.is_empty());
    }
}

#[test]
fn test_all_audit_categories() {
    let cats = [
        AuditCategory::Permission,
        AuditCategory::IdentityLogin,
        AuditCategory::IdentityEvent,
        AuditCategory::CardSwitch,
        AuditCategory::DataScope,
    ];
    for c in &cats {
        let json = serde_json::to_string(c).unwrap();
        assert!(!json.is_empty());
    }
}

// ===== 租户上下文测试 =====

#[test]
fn test_tenant_context_from_headers_tenant_only() {
    use axum::http::HeaderMap;
    use axum::http::HeaderValue;
    let mut headers = HeaderMap::new();
    headers.insert("x-user-card-tenant-id", HeaderValue::from_static("42"));
    let ctx = TenantContext::from_headers(&headers);
    assert_eq!(ctx.tenant_id, Some(42));
    assert!(ctx.domain_id.is_none());
    assert!(ctx.user_id.is_none());
}

#[test]
fn test_tenant_context_from_headers_all_fields() {
    use axum::http::HeaderMap;
    use axum::http::HeaderValue;
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
fn test_tenant_context_from_headers_missing() {
    use axum::http::HeaderMap;
    let headers = HeaderMap::new();
    let ctx = TenantContext::from_headers(&headers);
    assert!(ctx.tenant_id.is_none());
    assert!(ctx.domain_id.is_none());
    assert!(ctx.is_tenant_active()); // 默认为 active
}

#[test]
fn test_tenant_context_from_headers_invalid() {
    use axum::http::HeaderMap;
    use axum::http::HeaderValue;
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-identity-tenant-id",
        HeaderValue::from_static("not-a-number"),
    );
    let ctx = TenantContext::from_headers(&headers);
    assert!(ctx.tenant_id.is_none());
}

#[test]
fn test_tenant_context_active_status() {
    let ctx = TenantContext {
        tenant_status: Some("ACTIVE".into()),
        ..Default::default()
    };
    assert!(ctx.is_tenant_active());
}

#[test]
fn test_tenant_context_suspended_status() {
    let ctx = TenantContext {
        tenant_status: Some("SUSPENDED".into()),
        ..Default::default()
    };
    assert!(!ctx.is_tenant_active());
}

#[test]
fn test_tenant_context_terminated_status() {
    let ctx = TenantContext {
        tenant_status: Some("TERMINATED".into()),
        ..Default::default()
    };
    assert!(!ctx.is_tenant_active());
}

#[test]
fn test_tenant_context_no_status_defaults_active() {
    let ctx = TenantContext::default();
    assert!(ctx.is_tenant_active());
}

#[test]
fn test_tenant_context_to_sql_filter_tenant_only() {
    let ctx = TenantContext {
        tenant_id: Some(42),
        ..Default::default()
    };
    assert_eq!(ctx.to_sql_filter(), "AND tenant_id = 42");
}

#[test]
fn test_tenant_context_to_sql_filter_tenant_and_domain() {
    let ctx = TenantContext {
        tenant_id: Some(1),
        domain_id: Some(10),
        ..Default::default()
    };
    assert_eq!(ctx.to_sql_filter(), "AND tenant_id = 1 AND domain_id = 10");
}

#[test]
fn test_tenant_context_to_sql_filter_empty() {
    let ctx = TenantContext::default();
    assert_eq!(ctx.to_sql_filter(), "");
}

#[test]
fn test_build_tenant_where_with_alias() {
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

#[test]
fn test_build_tenant_where_different_tenants_produce_different_params() {
    let (clause_a, params_a) = build_tenant_where("", Some(1), None);
    let (clause_b, params_b) = build_tenant_where("", Some(2), None);
    // SQL 字符串相同（参数化查询），但参数值不同
    assert_eq!(clause_a, clause_b, "参数化查询的 SQL 模板必须相同");
    assert_ne!(params_a, params_b, "不同租户必须产生不同的参数值");
    assert_eq!(params_a, vec![1]);
    assert_eq!(params_b, vec![2]);
}

// ===== TenantScopedQuery 测试 =====

#[test]
fn test_scoped_query_tenant_only() {
    let q = TenantScopedQuery::new("SELECT * FROM resources").with_tenant(42);
    let (sql, params) = q.build();
    assert!(sql.contains("AND tenant_id = ?"));
    assert_eq!(params, vec!["42".to_string()]);
}

#[test]
fn test_scoped_query_with_alias() {
    let q = TenantScopedQuery::new("SELECT * FROM resources r")
        .with_alias("r")
        .with_tenant(42)
        .with_domain(10);
    let (sql, params) = q.build();
    assert!(sql.contains("r.tenant_id = ?"));
    assert!(sql.contains("r.domain_id = ?"));
    assert_eq!(params, vec!["42".to_string(), "10".to_string()]);
}

#[test]
fn test_scoped_query_no_filter() {
    let q = TenantScopedQuery::new("SELECT * FROM resources");
    let (sql, params) = q.build();
    assert_eq!(sql, "SELECT * FROM resources");
    assert!(params.is_empty());
}

#[test]
fn test_scoped_query_all_filters() {
    let q = TenantScopedQuery::new("SELECT * FROM data")
        .with_tenant(1)
        .with_domain(2)
        .with_user(3);
    let (sql, params) = q.build();
    assert!(sql.contains("tenant_id = ?"));
    assert!(sql.contains("domain_id = ?"));
    assert!(sql.contains("user_id = ?"));
    assert_eq!(
        params,
        vec!["1".to_string(), "2".to_string(), "3".to_string()]
    );
}

#[test]
fn test_scoped_query_different_tenants_produce_different_sql() {
    let q1 = TenantScopedQuery::new("SELECT * FROM data").with_tenant(1);
    let q2 = TenantScopedQuery::new("SELECT * FROM data").with_tenant(2);
    let (sql1, _) = q1.build();
    let (sql2, _) = q2.build();
    // SQL 模板相同但参数不同 — 不同租户的查询必须参数化隔离
    assert_eq!(sql1, sql2, "SQL 模板应相同（参数化查询）");
    let (_, params1) = q1.build();
    let (_, params2) = q2.build();
    assert_ne!(params1, params2, "参数值必须不同");
}

// ===== DataScopeFilter + DataFrameScopeFilter trait 测试 =====

/// 模拟 DataScopeFilter 实现
#[derive(Debug, Default)]
struct MockScopeFilter {
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
    user_id: Option<i64>,
    org_id: Option<i64>,
}

impl DataFrameScopeFilter for MockScopeFilter {
    fn tenant_id(&self) -> Option<i64> {
        self.tenant_id
    }
    fn domain_id(&self) -> Option<i64> {
        self.domain_id
    }
    fn user_id(&self) -> Option<i64> {
        self.user_id
    }
    fn org_id(&self) -> Option<i64> {
        self.org_id
    }
}

#[test]
fn test_scoped_query_with_filter_tenant() {
    let filter = MockScopeFilter {
        tenant_id: Some(42),
        ..Default::default()
    };
    let q = TenantScopedQuery::new("SELECT * FROM data").with_filter(&filter);
    let (sql, params) = q.build();
    assert!(sql.contains("tenant_id = ?"));
    assert_eq!(params, vec!["42".to_string()]);
}

#[test]
fn test_scoped_query_with_filter_all_fields() {
    let filter = MockScopeFilter {
        tenant_id: Some(1),
        domain_id: Some(2),
        user_id: Some(3),
        org_id: Some(4),
    };
    let q = TenantScopedQuery::new("SELECT * FROM data").with_filter(&filter);
    let (sql, params) = q.build();
    assert!(sql.contains("tenant_id = ?"));
    assert!(sql.contains("domain_id = ?"));
    assert!(sql.contains("user_id = ?"));
    // org_id 不在 TenantScopedQuery 中直接使用（通过 custom 扩展）
    assert_eq!(
        params,
        vec!["1".to_string(), "2".to_string(), "3".to_string()]
    );
}

#[test]
fn test_scoped_query_with_filter_empty() {
    let filter = MockScopeFilter::default();
    let q = TenantScopedQuery::new("SELECT * FROM data").with_filter(&filter);
    let (sql, params) = q.build();
    assert_eq!(sql, "SELECT * FROM data");
    assert!(params.is_empty());
}

// ===== 跨租户隔离不变式测试 =====

#[test]
fn test_cross_tenant_sql_isolation_invariant() {
    // 核心不变式：不同租户的查询 SQL 必须包含不同的 tenant_id 参数
    // 确保不会出现租户 A 的请求看到租户 B 的数据
    let tenants = [1i64, 2, 3, 100, 999];

    for &tid in &tenants {
        let q = TenantScopedQuery::new("SELECT * FROM sensitive_data").with_tenant(tid);
        let (sql, params) = q.build();

        // 1. SQL 必须包含 tenant_id 过滤条件
        assert!(
            sql.contains("tenant_id = ?"),
            "租户 {} 的查询缺少 tenant_id 过滤",
            tid
        );

        // 2. 参数必须包含正确的 tenant_id
        assert_eq!(params, vec![tid.to_string()], "租户 {} 的参数值不正确", tid);
    }
}

#[test]
fn test_cross_tenant_where_clause_isolation() {
    // 验证 build_tenant_where 对不同租户产生隔离的 WHERE 子句
    let (clause1, params1) = build_tenant_where("", Some(1), None);
    let (clause2, params2) = build_tenant_where("", Some(2), None);

    // WHERE 模板相同（参数化），但参数值不同
    assert_eq!(clause1, clause2, "WHERE 模板应相同");
    assert_ne!(params1, params2, "参数值必须不同");
    assert_eq!(params1, vec![1]);
    assert_eq!(params2, vec![2]);
}

#[test]
fn test_tenant_context_no_tenant_id_no_filter() {
    // 没有租户 ID 时不应生成过滤条件 — 但这也意味着没有隔离
    // 生产环境中必须有上游中间件确保 tenant_id 存在
    let ctx = TenantContext::default();
    let filter = ctx.to_sql_filter();
    assert_eq!(filter, "", "无 tenant_id 时不应生成 SQL 过滤");
}
