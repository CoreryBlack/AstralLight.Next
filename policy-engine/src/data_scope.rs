//! 数据范围规则系统
//!
//! 本模块对应 Java 端 `com.coreryblack.astral_general.common.config` 包下的：
//! - `DataScopeType` — 作用域类型枚举（DOMAIN / CARD / TENANT）
//! - `DataScopeRule` — 单张表的数据权限规则（表名 + 列名 + 作用域类型）
//! - `DataScopeRuleProvider` — 业务模块向共享数据权限处理器注册受作用域约束的表
//! - `CardDataPermissionHandler` — MyBatis-Plus 多数据权限处理器（Rust 端用 DataScopeRegistry 代替）
//!
//! 此外保留 Rust 端独有的 `DataScopeFilter` + `DataScopeFilterResolver`，
//! 用于从 `PolicyContext` 推导运行时数据级过滤条件（SQL WHERE 片段）。
//!
//! # 架构关系
//!
//! ```text
//! Java                          Rust
//! ─────────────────────────    ──────────────────────────────────
//! DataScopeType (enum)     →   DataScopeType (enum)
//! DataScopeRule (record)   →   DataScopeRule (struct)
//! DataScopeRuleProvider    →   DataScopeRuleProvider (trait)
//! (各模块 @Component 实现)  →   TrustGraphDataScopeRuleProvider 等 impl
//! CardDataPermissionHandler →   DataScopeRegistry (全局表→规则映射)
//! DataScopeBypassHolder    →   data_scope_bypass (thread-local / task-local)
//! ```

use astral_types::PolicyContext;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

// ============================================================================
// DataScopeType — 对齐 Java DataScopeType.java
// ============================================================================

/// 数据权限作用域类型
///
/// Java 基线: `com.coreryblack.astral_general.common.config.DataScopeType`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DataScopeType {
    /// 域级隔离：按 domain_id 过滤
    Domain,
    /// 卡级隔离：按 card_id 过滤
    Card,
    /// 租户级隔离：按 tenant_id 过滤
    Tenant,
}

impl DataScopeType {
    /// 从字符串解析（大小写不敏感）
    pub fn from_str_insensitive(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "DOMAIN" => Some(Self::Domain),
            "CARD" => Some(Self::Card),
            "TENANT" => Some(Self::Tenant),
            _ => None,
        }
    }

    /// 转为 Java 兼容的字符串表示
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Domain => "DOMAIN",
            Self::Card => "CARD",
            Self::Tenant => "TENANT",
        }
    }
}

impl std::fmt::Display for DataScopeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ============================================================================
// DataScopeRule — 对齐 Java DataScopeRule.java (record)
// ============================================================================

/// 单张表的数据权限规则
///
/// Java 基线: `com.coreryblack.astral_general.common.config.DataScopeRule`
///
/// - `table_name`: 表名（小写）
/// - `column_name`: 作用域字段名
/// - `scope_type`: 作用域类型
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataScopeRule {
    pub table_name: String,
    pub column_name: String,
    pub scope_type: DataScopeType,
}

impl DataScopeRule {
    pub fn new(
        table_name: impl Into<String>,
        column_name: impl Into<String>,
        scope_type: DataScopeType,
    ) -> Self {
        Self {
            table_name: table_name.into().to_lowercase(),
            column_name: column_name.into(),
            scope_type,
        }
    }
}

// ============================================================================
// DataScopeRuleProvider trait — 对齐 Java DataScopeRuleProvider.java
// ============================================================================

/// 业务模块向共享数据权限处理器注册自己受作用域约束的表。
///
/// Java 基线: `com.coreryblack.astral_general.common.config.DataScopeRuleProvider`
///
/// # 实现示例
///
/// ```
/// use policy_engine::{DataScopeRule, DataScopeRuleProvider, DataScopeType};
///
/// pub struct TrustGraphDataScopeRuleProvider;
///
/// impl DataScopeRuleProvider for TrustGraphDataScopeRuleProvider {
///     fn get_rules(&self) -> Vec<DataScopeRule> {
///         vec![
///             DataScopeRule::new("rule_set", "tenant_id", DataScopeType::Tenant),
///             DataScopeRule::new("tenant", "tenant_id", DataScopeType::Tenant),
///         ]
///     }
/// }
/// ```
pub trait DataScopeRuleProvider: Send + Sync {
    /// 返回当前模块注册的数据权限规则
    fn get_rules(&self) -> Vec<DataScopeRule>;
}

// ============================================================================
// DataScopeRegistry — 对齐 Java CardDataPermissionHandler 的注册表部分
// ============================================================================

/// 全局数据范围规则注册表
///
/// 对应 Java `CardDataPermissionHandler` 中的 `registeredRules` HashMap。
/// 各模块在启动时通过 `register()` 注册自己的 `DataScopeRuleProvider`，
/// 运行时通过 `get_rule(table_name)` 查找某张表的作用域规则。
pub struct DataScopeRegistry {
    rules: HashMap<String, DataScopeRule>,
}

impl DataScopeRegistry {
    /// 创建空注册表
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
        }
    }

    /// 注册一个 provider 的所有规则
    ///
    /// 等价于 Java `CardDataPermissionHandler` 构造函数中遍历 providers 的逻辑。
    pub fn register(&mut self, provider: &dyn DataScopeRuleProvider) {
        for rule in provider.get_rules() {
            let key = rule.table_name.to_lowercase();
            self.rules.insert(key, rule);
        }
    }

    /// 直接注册单条规则
    pub fn register_rule(&mut self, rule: DataScopeRule) {
        let key = rule.table_name.to_lowercase();
        self.rules.insert(key, rule);
    }

    /// 按表名查找规则
    pub fn get_rule(&self, table_name: &str) -> Option<&DataScopeRule> {
        let key = table_name.replace('`', "").to_lowercase();
        self.rules.get(&key)
    }

    /// 已注册的表数量
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// 返回所有已注册的规则
    pub fn all_rules(&self) -> impl Iterator<Item = &DataScopeRule> {
        self.rules.values()
    }
}

impl Default for DataScopeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// DataScopeBypass — 对齐 Java DataScopeBypassHolder
// ============================================================================

/// 数据范围绕过开关。
///
/// A bypass is a task-local async scope, never a thread-local flag. Prefer
/// [`with_bypass`] around the complete trusted maintenance future. The legacy
/// synchronous `open`/`close` methods only affect an already active `with_bypass`
/// scope; outside one they are no-ops and cannot affect another task.
pub struct DataScopeBypass;

tokio::task_local! {
    static BYPASS_DEPTH: std::cell::Cell<usize>;
    static BYPASS_BASE_DEPTH: usize;
    static BYPASS_SCOPE_ID: u64;
}

static NEXT_BYPASS_SCOPE_ID: AtomicU64 = AtomicU64::new(1);

/// Run a trusted maintenance future with data-scope bypass enabled.
///
/// The flag follows this future across every `.await`, nests safely, and is
/// restored by task-local scoping when the future completes, errors, is cancelled,
/// or unwinds. It is not inherited by a separately spawned Tokio task.
pub async fn with_bypass<F: std::future::Future>(future: F) -> F::Output {
    let parent_depth = BYPASS_DEPTH.try_with(|depth| depth.get()).unwrap_or(0);
    let inherited_floor = BYPASS_BASE_DEPTH.try_with(|depth| *depth).unwrap_or(0);
    let base_depth = inherited_floor.saturating_add(1);
    let scope_id = NEXT_BYPASS_SCOPE_ID.fetch_add(1, Ordering::Relaxed);
    let scoped = BYPASS_DEPTH.scope(std::cell::Cell::new(parent_depth.max(base_depth)), future);
    BYPASS_SCOPE_ID
        .scope(scope_id, BYPASS_BASE_DEPTH.scope(base_depth, scoped))
        .await
}

impl DataScopeBypass {
    /// Legacy synchronous opener; effective only inside [`with_bypass`].
    #[deprecated(note = "use with_bypass(future) to scope bypass across awaits")]
    pub fn open() {
        let _ = BYPASS_DEPTH.try_with(|depth| depth.set(depth.get().saturating_add(1)));
    }

    /// Legacy synchronous closer; never drops below the active scoped base.
    #[deprecated(note = "use with_bypass(future) to scope bypass across awaits")]
    pub fn close() {
        let floor = BYPASS_BASE_DEPTH.try_with(|depth| *depth).unwrap_or(0);
        let _ = BYPASS_DEPTH.try_with(|depth| depth.set(depth.get().saturating_sub(1).max(floor)));
    }

    /// Whether the current async task is inside a bypass scope.
    pub fn is_bypassed() -> bool {
        BYPASS_DEPTH
            .try_with(|depth| depth.get() > 0)
            .unwrap_or(false)
    }
}

/// Legacy RAII guard, !Send so it cannot be transferred across async tasks.
///
/// It only adjusts a `with_bypass` scope active at construction; creating it
/// outside such a scope or dropping it after its originating nested scope has
/// ended is a no-op.
pub struct DataScopeBypassGuard {
    scope_id: Option<u64>,
    floor: usize,
    _not_send: PhantomData<Rc<()>>,
}

impl DataScopeBypassGuard {
    pub fn new() -> Self {
        let scope_id = BYPASS_SCOPE_ID.try_with(|scope_id| *scope_id).ok();
        let floor = BYPASS_BASE_DEPTH.try_with(|depth| *depth).unwrap_or(0);
        #[allow(deprecated)]
        DataScopeBypass::open();
        Self {
            scope_id,
            floor,
            _not_send: PhantomData,
        }
    }
}

#[allow(deprecated)]
impl Default for DataScopeBypassGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DataScopeBypassGuard {
    #[allow(deprecated)]
    fn drop(&mut self) {
        let Some(scope_id) = self.scope_id else {
            return;
        };
        let is_originating_scope = BYPASS_SCOPE_ID
            .try_with(|current_scope| *current_scope == scope_id)
            .unwrap_or(false);
        if is_originating_scope {
            let _ = BYPASS_DEPTH
                .try_with(|depth| depth.set(depth.get().saturating_sub(1).max(self.floor)));
        }
    }
}

// ============================================================================
// DataScopeFilter + DataScopeFilterResolver — Rust 独有的上下文级过滤器
// ============================================================================

/// 数据范围过滤器
///
/// 包含从策略上下文推导出的数据级访问控制条件。
/// 应用层将此过滤器中的字段自动拼接到 SQL 查询中。
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DataScopeFilter {
    /// 租户 ID 过滤（None=不限制）
    pub tenant_id: Option<i64>,
    /// 域 ID 过滤
    pub domain_id: Option<i64>,
    /// 用户 ID 过滤（个人数据隔离）
    pub user_id: Option<i64>,
    /// 组织 ID 过滤
    pub org_id: Option<i64>,
    /// 自定义键值对过滤（扩展字段）
    pub custom: Vec<(String, serde_json::Value)>,
}

impl DataScopeFilter {
    /// 是否为空（没有任何过滤条件）
    pub fn is_empty(&self) -> bool {
        self.tenant_id.is_none()
            && self.domain_id.is_none()
            && self.user_id.is_none()
            && self.org_id.is_none()
            && self.custom.is_empty()
    }

    /// 合并另一个过滤器（后者覆盖前者同名键）
    pub fn merge(&mut self, other: &DataScopeFilter) {
        if let Some(v) = other.tenant_id {
            self.tenant_id = Some(v);
        }
        if let Some(v) = other.domain_id {
            self.domain_id = Some(v);
        }
        if let Some(v) = other.user_id {
            self.user_id = Some(v);
        }
        if let Some(v) = other.org_id {
            self.org_id = Some(v);
        }
        self.custom.extend(other.custom.clone());
    }
}

/// 上下文级数据范围过滤器解析器
///
/// 注意：这与 Java 的 `DataScopeRuleProvider` trait 是不同的东西。
/// Java 的 trait 负责注册"哪些表受作用域约束"（静态规则），
/// 而此解析器负责从运行时 `PolicyContext` 推导"当前请求应该过滤到哪个范围"（动态过滤）。
///
/// 为避免名称冲突，此处命名为 `DataScopeFilterResolver`。
#[derive(Debug, Clone)]
pub struct DataScopeFilterResolver;

impl DataScopeFilterResolver {
    /// 创建新的解析器实例
    pub fn new() -> Self {
        Self
    }

    /// 从策略上下文解析数据范围过滤器
    ///
    /// # 推导规则
    ///
    /// | 上下文字段 | 过滤字段 | 条件 |
    /// |-----------|---------|------|
    /// | `tenant_id` | `tenant_id` | 如果存在，则过滤到该租户 |
    /// | `domain_id` | `domain_id` | 如果存在，则过滤到该域 |
    /// | `user_id` | `user_id` | 如果 action 以 "personal:" 开头，则过滤到该用户 |
    pub async fn resolve(&self, ctx: &PolicyContext) -> DataScopeFilter {
        let mut filter = DataScopeFilter::default();

        // 租户隔离：如果上下文中指定了租户，则过滤到该租户的数据
        if let Some(tenant_id) = ctx.tenant_id {
            filter.tenant_id = Some(tenant_id);
        }

        // 域隔离：如果上下文中指定了域，则过滤到该域的数据
        if let Some(domain_id) = ctx.domain_id {
            filter.domain_id = Some(domain_id);
        }

        // 个人数据隔离：只有个人范围的操作才过滤用户
        if ctx.action.starts_with("personal:") {
            if let Some(user_id) = ctx.user_id {
                filter.user_id = Some(user_id);
            }
        }

        // 通过 request 扩展字段自定义过滤条件
        if let Some(ref req) = ctx.request {
            if let Some(org_id) = req.get("org_id").and_then(|v| v.as_i64()) {
                filter.org_id = Some(org_id);
            }

            // 自定义 kv 过滤（格式：`{ "filters": { "department_id": 3 } }`）
            if let Some(filters) = req.get("filters").and_then(|v| v.as_object()) {
                for (k, v) in filters {
                    filter.custom.push((k.clone(), v.clone()));
                }
            }
        }

        filter
    }
}

impl Default for DataScopeFilterResolver {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// 全局注册表单例
// ============================================================================

/// 全局 DataScopeRegistry 单例
///
/// 各模块在初始化时调用 `register_global(provider)` 注册自己的规则。
static GLOBAL_REGISTRY: OnceLock<std::sync::RwLock<DataScopeRegistry>> = OnceLock::new();

fn global_registry() -> &'static std::sync::RwLock<DataScopeRegistry> {
    GLOBAL_REGISTRY.get_or_init(|| std::sync::RwLock::new(DataScopeRegistry::new()))
}

/// 向全局注册表注册一个 provider
pub fn register_global(provider: &dyn DataScopeRuleProvider) {
    let mut registry = global_registry().write().unwrap();
    registry.register(provider);
}

/// 向全局注册表注册单条规则
pub fn register_global_rule(rule: DataScopeRule) {
    let mut registry = global_registry().write().unwrap();
    registry.register_rule(rule);
}

/// 从全局注册表查找表的数据范围规则
pub fn get_global_rule(table_name: &str) -> Option<DataScopeRule> {
    let registry = global_registry().read().unwrap();
    registry.get_rule(table_name).cloned()
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- DataScopeType 测试 ---

    #[test]
    fn test_data_scope_type_from_str() {
        assert_eq!(
            DataScopeType::from_str_insensitive("DOMAIN"),
            Some(DataScopeType::Domain)
        );
        assert_eq!(
            DataScopeType::from_str_insensitive("domain"),
            Some(DataScopeType::Domain)
        );
        assert_eq!(
            DataScopeType::from_str_insensitive("TENANT"),
            Some(DataScopeType::Tenant)
        );
        assert_eq!(
            DataScopeType::from_str_insensitive("card"),
            Some(DataScopeType::Card)
        );
        assert_eq!(DataScopeType::from_str_insensitive("unknown"), None);
    }

    #[test]
    fn test_data_scope_type_as_str() {
        assert_eq!(DataScopeType::Domain.as_str(), "DOMAIN");
        assert_eq!(DataScopeType::Card.as_str(), "CARD");
        assert_eq!(DataScopeType::Tenant.as_str(), "TENANT");
    }

    #[test]
    fn test_data_scope_type_serde() {
        let json = serde_json::to_string(&DataScopeType::Tenant).unwrap();
        assert_eq!(json, "\"TENANT\"");
        let parsed: DataScopeType = serde_json::from_str("\"DOMAIN\"").unwrap();
        assert_eq!(parsed, DataScopeType::Domain);
    }

    // --- DataScopeRule 测试 ---

    #[test]
    fn test_data_scope_rule_new_lowercases_table_name() {
        let rule = DataScopeRule::new("Rule_Set", "tenant_id", DataScopeType::Tenant);
        assert_eq!(rule.table_name, "rule_set");
        assert_eq!(rule.column_name, "tenant_id");
        assert_eq!(rule.scope_type, DataScopeType::Tenant);
    }

    // --- DataScopeRegistry 测试 ---

    struct MockProvider;
    impl DataScopeRuleProvider for MockProvider {
        fn get_rules(&self) -> Vec<DataScopeRule> {
            vec![
                DataScopeRule::new("table_a", "tenant_id", DataScopeType::Tenant),
                DataScopeRule::new("table_b", "domain_id", DataScopeType::Domain),
            ]
        }
    }

    #[test]
    fn test_registry_register_and_lookup() {
        let mut registry = DataScopeRegistry::new();
        registry.register(&MockProvider);
        assert_eq!(registry.len(), 2);

        let rule = registry.get_rule("table_a").unwrap();
        assert_eq!(rule.scope_type, DataScopeType::Tenant);

        let rule = registry.get_rule("TABLE_B").unwrap();
        assert_eq!(rule.scope_type, DataScopeType::Domain);

        assert!(registry.get_rule("table_c").is_none());
    }

    #[test]
    fn test_registry_strips_backticks() {
        let mut registry = DataScopeRegistry::new();
        registry.register(&MockProvider);
        let rule = registry.get_rule("`table_a`").unwrap();
        assert_eq!(rule.column_name, "tenant_id");
    }

    #[test]
    fn test_registry_register_single_rule() {
        let mut registry = DataScopeRegistry::new();
        registry.register_rule(DataScopeRule::new(
            "custom_table",
            "card_id",
            DataScopeType::Card,
        ));
        assert_eq!(registry.len(), 1);
        assert!(registry.get_rule("custom_table").is_some());
    }

    #[test]
    fn test_registry_empty() {
        let registry = DataScopeRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    // --- DataScopeBypass tests ---

    #[tokio::test]
    async fn bypass_is_scoped_to_the_async_task_across_await() {
        assert!(!DataScopeBypass::is_bypassed());
        with_bypass(async {
            assert!(DataScopeBypass::is_bypassed());
            tokio::task::yield_now().await;
            assert!(DataScopeBypass::is_bypassed());
            with_bypass(async {
                assert!(DataScopeBypass::is_bypassed());
                tokio::task::yield_now().await;
            })
            .await;
            assert!(DataScopeBypass::is_bypassed());
        })
        .await;
        assert!(!DataScopeBypass::is_bypassed());
    }

    #[tokio::test]
    async fn bypass_does_not_leak_to_another_spawned_task() {
        with_bypass(async {
            assert!(DataScopeBypass::is_bypassed());
            let child = tokio::spawn(async { DataScopeBypass::is_bypassed() });
            assert!(!child.await.unwrap());
            assert!(DataScopeBypass::is_bypassed());
        })
        .await;
        assert!(!DataScopeBypass::is_bypassed());
    }

    #[tokio::test]
    async fn bypass_is_cleared_on_cancellation() {
        let task = tokio::spawn(with_bypass(std::future::pending::<()>()));
        tokio::task::yield_now().await;
        task.abort();
        let _ = task.await;
        assert!(!DataScopeBypass::is_bypassed());
    }

    #[tokio::test]
    async fn legacy_bypass_guard_cannot_enable_a_global_thread_bypass() {
        assert!(!DataScopeBypass::is_bypassed());
        #[allow(deprecated)]
        {
            #[allow(deprecated)]
            let _guard = DataScopeBypassGuard::new();
            assert!(!DataScopeBypass::is_bypassed());
        }
        assert!(!DataScopeBypass::is_bypassed());
    }

    #[tokio::test]
    async fn legacy_guard_adjusts_only_its_originating_nested_scope() {
        with_bypass(async {
            assert!(DataScopeBypass::is_bypassed());
            {
                #[allow(deprecated)]
                let _outer_guard = DataScopeBypassGuard::new();
                with_bypass(async {
                    assert!(DataScopeBypass::is_bypassed());
                })
                .await;
                assert!(DataScopeBypass::is_bypassed());
            }
            assert!(DataScopeBypass::is_bypassed());
        })
        .await;
        assert!(!DataScopeBypass::is_bypassed());
    }

    // --- DataScopeFilterResolver 测试 ---

    #[tokio::test]
    async fn test_resolve_tenant_only() {
        let resolver = DataScopeFilterResolver::new();
        let ctx = PolicyContext::builder()
            .action("read".into())
            .tenant_id(Some(42))
            .build();
        let filter = resolver.resolve(&ctx).await;
        assert_eq!(filter.tenant_id, Some(42));
        assert!(filter.domain_id.is_none());
        assert!(filter.user_id.is_none());
    }

    #[tokio::test]
    async fn test_resolve_tenant_and_domain() {
        let resolver = DataScopeFilterResolver::new();
        let ctx = PolicyContext::builder()
            .action("write".into())
            .tenant_id(Some(1))
            .domain_id(Some(10))
            .build();
        let filter = resolver.resolve(&ctx).await;
        assert_eq!(filter.tenant_id, Some(1));
        assert_eq!(filter.domain_id, Some(10));
    }

    #[tokio::test]
    async fn test_resolve_personal_scope() {
        let resolver = DataScopeFilterResolver::new();
        let ctx = PolicyContext::builder()
            .action("personal:read".into())
            .tenant_id(Some(5))
            .user_id(Some(100))
            .build();
        let filter = resolver.resolve(&ctx).await;
        assert_eq!(filter.tenant_id, Some(5));
        assert_eq!(filter.user_id, Some(100));
    }

    #[tokio::test]
    async fn test_resolve_no_tenant() {
        let resolver = DataScopeFilterResolver::new();
        let ctx = PolicyContext::builder().action("read".into()).build();
        let filter = resolver.resolve(&ctx).await;
        assert!(filter.is_empty());
    }

    #[tokio::test]
    async fn test_resolve_custom_filters() {
        let resolver = DataScopeFilterResolver::new();
        let ctx = PolicyContext::builder()
            .action("read".into())
            .tenant_id(Some(1))
            .request(Some(serde_json::json!({
                "org_id": 77,
                "filters": {
                    "department_id": 3,
                    "project_id": 99
                }
            })))
            .build();
        let filter = resolver.resolve(&ctx).await;
        assert_eq!(filter.org_id, Some(77));
        assert!(filter.custom.iter().any(|(k, _)| k == "department_id"));
        assert!(filter.custom.iter().any(|(k, _)| k == "project_id"));
    }

    // --- 全局注册表测试 ---

    #[test]
    fn test_global_registry() {
        // 注册一条规则（可能因测试运行顺序有其他规则，只验证查找功能正常）
        register_global_rule(DataScopeRule::new(
            "test_global_table",
            "tenant_id",
            DataScopeType::Tenant,
        ));
        let rule = get_global_rule("test_global_table");
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().scope_type, DataScopeType::Tenant);
    }
}
