//! 租户过滤中间件（Phase-2a 实现）
//!
//! SQLx 自动 tenant_id 过滤工具（SQL 重写 + TenantScopedQuery）。
//! 提供参数化的查询包装，自动追加 `AND tenant_id = ?` 条件。

/// 租户作用域查询包装（参数化）
///
/// # 用法
///
/// ```
/// use astral_common::middleware::tenant_filter::TenantScopedQuery;
///
/// let scoped = TenantScopedQuery::new(
///     "SELECT * FROM my_table WHERE deleted = 0",
/// )
/// .with_tenant(42)
/// .with_domain(10);
/// let (sql, params) = scoped.build();
/// assert_eq!(
///     sql,
///     "SELECT * FROM my_table WHERE deleted = 0 AND tenant_id = ? AND domain_id = ?"
/// );
/// assert_eq!(params, vec!["42".to_string(), "10".to_string()]);
/// ```
#[derive(Debug, Clone)]
pub struct TenantScopedQuery {
    /// 原始 SQL（不含租户过滤）
    base_sql: String,
    /// 可选的租户 ID
    tenant_id: Option<i64>,
    /// 可选的域 ID
    domain_id: Option<i64>,
    /// 可选的用户 ID
    user_id: Option<i64>,
    /// 表别名
    table_alias: String,
}

impl TenantScopedQuery {
    /// 创建新的租户作用域查询
    pub fn new(base_sql: impl Into<String>) -> Self {
        Self {
            base_sql: base_sql.into(),
            tenant_id: None,
            domain_id: None,
            user_id: None,
            table_alias: String::new(),
        }
    }

    /// 设置表别名（用于 JOIN 查询中消除歧义）
    pub fn with_alias(mut self, alias: impl Into<String>) -> Self {
        self.table_alias = alias.into();
        self
    }

    /// 设置租户 ID 过滤
    pub fn with_tenant(mut self, tenant_id: i64) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    /// 设置域 ID 过滤
    pub fn with_domain(mut self, domain_id: i64) -> Self {
        self.domain_id = Some(domain_id);
        self
    }

    /// 设置用户 ID 过滤（个人数据隔离）
    pub fn with_user(mut self, user_id: i64) -> Self {
        self.user_id = Some(user_id);
        self
    }

    /// 从 DataFrameScopeFilter 设置所有过滤条件
    pub fn with_filter(mut self, filter: &impl DataFrameScopeFilter) -> Self {
        if let Some(tid) = filter.tenant_id() {
            self.tenant_id = Some(tid);
        }
        if let Some(did) = filter.domain_id() {
            self.domain_id = Some(did);
        }
        if let Some(uid) = filter.user_id() {
            self.user_id = Some(uid);
        }
        self
    }

    /// 构建最终 SQL 和参数列表
    ///
    /// 返回 `(sql, params)`。SQL 中的 `?` 占位符应与 params 顺序一致。
    pub fn build(&self) -> (String, Vec<String>) {
        let mut clauses: Vec<String> = Vec::new();
        let mut params: Vec<String> = Vec::new();

        let prefix = if self.table_alias.is_empty() {
            String::new()
        } else {
            format!("{}.", self.table_alias)
        };

        if let Some(tid) = self.tenant_id {
            clauses.push(format!("{prefix}tenant_id = ?"));
            params.push(tid.to_string());
        }
        if let Some(did) = self.domain_id {
            clauses.push(format!("{prefix}domain_id = ?"));
            params.push(did.to_string());
        }
        if let Some(uid) = self.user_id {
            clauses.push(format!("{prefix}user_id = ?"));
            params.push(uid.to_string());
        }

        let sql = if clauses.is_empty() {
            self.base_sql.clone()
        } else {
            format!("{} AND {}", self.base_sql, clauses.join(" AND "))
        };

        (sql, params)
    }

    /// 构建 SQL 字符串（不含参数绑定）
    pub fn build_sql(&self) -> String {
        self.build().0
    }

    /// 获取参数值列表
    pub fn params(&self) -> Vec<String> {
        self.build().1
    }
}

/// 数据帧范围过滤器 trait
///
/// 由 `policy_engine::DataScopeFilter` 实现，在 trustgraph 服务中
/// 解析策略上下文并生成 SQL WHERE 片段。
pub trait DataFrameScopeFilter {
    fn tenant_id(&self) -> Option<i64>;
    fn domain_id(&self) -> Option<i64>;
    fn user_id(&self) -> Option<i64>;
    fn org_id(&self) -> Option<i64>;
}

/// 将策略上下文转换为 SQL 过滤条件并绑定到查询
pub async fn apply_tenant_scope(
    base_sql: &str,
    filter: &impl DataFrameScopeFilter,
) -> (String, Vec<String>) {
    let scoped = TenantScopedQuery::new(base_sql).with_filter(filter);
    scoped.build()
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
