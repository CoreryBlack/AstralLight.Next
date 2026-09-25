//! 资源类型注册表
//!
//! 平台通过 `ResourceRegistry` 集中管理所有可授权的资源类型及其合法动作。
//! 使用 `OnceLock` 惰性初始化，首次 `global()` 调用时自动注册所有内置类型。
//!
//! 还包含动作别名映射（如 write → create/update/delete）和 resourceKey 工具函数。

use std::collections::{HashMap, HashSet};
use std::sync::{OnceLock, RwLock};

use serde::Serialize;

use crate::RegistryError;

/// 全局资源注册表实例（惰性初始化）
static RESOURCE_REGISTRY: OnceLock<ResourceRegistry> = OnceLock::new();

/// 动作别名映射（正向：别名 → 展开的动作集合）
///
/// 例如 `write` 展开为 `create`, `update`, `delete`。
/// 当规则中定义了 `action=write`，对 `create`/`update`/`delete` 的请求也应匹配。
pub const ACTION_ALIASES: &[(&str, &[&str])] = &[("write", &["create", "update", "delete"])];

/// 反向别名映射：动作 → 别名来源集合
///
/// 例如 `create` 可追溯到别名 `write`。
/// 当请求 `action=delete` 但没有规则直接匹配时，回退尝试匹配别名 `write`。
static REVERSE_ALIASES: OnceLock<HashMap<&'static str, Vec<&'static str>>> = OnceLock::new();

fn build_reverse_aliases() -> HashMap<&'static str, Vec<&'static str>> {
    let mut map: HashMap<&'static str, Vec<&'static str>> = HashMap::new();
    for &(alias, expanded) in ACTION_ALIASES {
        for &action in expanded {
            map.entry(action).or_default().push(alias);
        }
    }
    map
}

/// 获取指定动作的别名来源（反向映射）
///
/// 例如 `get_alias_sources("create")` 返回 `["write"]`。
pub fn get_alias_sources(action: &str) -> Vec<&'static str> {
    let map = REVERSE_ALIASES.get_or_init(build_reverse_aliases);
    map.get(action).cloned().unwrap_or_default()
}

/// 构建 resourceKey = `resourceType:targetId`
///
/// 如果 target_id 为 None，附加 `:*` 表示类型级通配。
/// 例如 `build_resource_key("learn_subject", Some(42))` → `"learn_subject:42"`
/// `build_resource_key("learn_subject", None)` → `"learn_subject:*"`
pub fn build_resource_key(resource: &str, target_id: Option<i64>) -> String {
    match target_id {
        Some(id) => format!("{resource}:{id}"),
        None => format!("{resource}:*"),
    }
}

/// 从 resourceKey 中提取 resource type 和 resource ID 字符串
///
/// 例如 `parse_resource_key("learn_subject:42")` → `("learn_subject", Some("42"))`
/// `parse_resource_key("learn_subject:*")` → `("learn_subject", Some("*"))`
pub fn parse_resource_key(key: &str) -> (&str, Option<&str>) {
    if let Some(colon) = key.rfind(':') {
        let resource_type = &key[..colon];
        let resource_id = &key[colon + 1..];
        let resource_id = if resource_id.is_empty() || resource_id == "*" {
            None
        } else {
            Some(resource_id)
        };
        (resource_type, resource_id)
    } else {
        (key, None)
    }
}

/// 检查 resourceKey 是否是通配（含 `:*` 后缀）
pub fn is_wildcard_key(key: &str) -> bool {
    key.ends_with(":*")
}

/// 将 specific resourceKey 转为通配 key（forward wildcard）
///
/// 例如 `"learn_subject:42"` → `Some("learn_subject:*")`
/// 已经是通配的 key 返回 None。
pub fn to_wildcard_key(key: &str) -> Option<String> {
    if is_wildcard_key(key) {
        return None;
    }
    key.rfind(':').map(|colon| format!("{}:*", &key[..colon]))
}

/// 资源类型信息（含条件元数据，对齐 Java `ResourceTypeInfo`)
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceTypeInfo {
    /// 合法动作集合
    pub actions: HashSet<String>,
    /// 支持的条件类型名称集合（如 `"timeRange"`, `"ownerOnly"`）
    pub supported_conditions: HashSet<String>,
}

impl ResourceTypeInfo {
    fn new(actions: &[&str], conditions: &[&str]) -> Self {
        Self {
            actions: actions.iter().map(|a| a.to_string()).collect(),
            supported_conditions: conditions.iter().map(|c| c.to_string()).collect(),
        }
    }
}

/// 资源类型注册表
pub struct ResourceRegistry {
    inner: RwLock<HashMap<String, ResourceTypeInfo>>,
}

impl ResourceRegistry {
    /// 获取全局注册表实例（首次调用时自动注册内置类型）
    pub fn global() -> &'static ResourceRegistry {
        RESOURCE_REGISTRY.get_or_init(Self::new_with_builtins)
    }

    fn new_with_builtins() -> ResourceRegistry {
        let mut reg = ResourceRegistry {
            inner: RwLock::new(HashMap::new()),
        };
        reg.register_builtin_types();
        reg
    }

    fn register_builtin_types(&mut self) {
        // Learn 模块
        self.register_with_conditions(
            "learn_subject",
            &["read", "create", "update", "delete", "import", "export"],
            &[
                "scope:SELF",
                "ownerOnly",
                "belongsToTenant",
                "resourceProperty",
            ],
        );
        self.register_with_conditions(
            "learn_question",
            &["read", "create", "update", "delete", "import", "export"],
            &["scope:SELF", "ownerOnly", "resourceProperty"],
        );
        self.register_with_conditions(
            "learn_exam",
            &["read", "create", "update", "delete", "publish"],
            &["scope:SELF", "rateLimit"],
        );
        self.register_with_conditions(
            "learn_level",
            &["read", "create", "update", "delete"],
            &[
                "scope:SELF",
                "ownerOnly",
                "belongsToTenant",
                "resourceProperty",
            ],
        );
        self.register_with_conditions(
            "learn_solution",
            &["read", "create", "update", "delete"],
            &["scope:SELF", "ownerOnly", "resourceProperty"],
        );
        self.register_with_conditions("learn_wrong_question", &["read", "write"], &["scope:SELF"]);
        self.register_with_conditions("learn_statistics", &["read"], &["rateLimit"]);
        self.register_with_conditions(
            "learn_school",
            &["read", "create", "update", "delete"],
            &["belongsToTenant", "resourceProperty"],
        );
        self.register_with_conditions(
            "learn_course",
            &["read", "create", "update", "delete"],
            &["scope:SELF", "timeRange", "resourceProperty"],
        );
        self.register_with_conditions(
            "learn_checkin",
            &["read", "create", "update", "delete"],
            &["scope:SELF", "timeRange"],
        );
        // App Learn resources use explicit resource types for policy matching.
        self.register_with_conditions("learn_progress", &["read", "create"], &["scope:SELF"]);
        self.register_with_conditions("learn_user_answer", &["read", "create"], &["scope:SELF"]);
        self.register_with_conditions(
            "learn_user_subject",
            &["read", "create", "delete"],
            &["scope:SELF"],
        );
        self.register_with_conditions(
            "learn_question_first_attempt",
            &["read", "create"],
            &["scope:SELF"],
        );
        self.register_with_conditions(
            "learn_chapter",
            &["read", "create", "update", "delete"],
            &[
                "scope:SELF",
                "ownerOnly",
                "belongsToTenant",
                "resourceProperty",
            ],
        );
        self.register_with_conditions(
            "learn_level_play",
            &["play"],
            &["timeRange", "deviceType", "rateLimit"],
        );
        self.register("learn_device", &["read"]);
        self.register_with_conditions(
            "learn_document",
            &["read", "create", "update", "delete"],
            &["scope:SELF", "belongsToTenant"],
        );
        self.register_with_conditions(
            "learn_system_setting",
            &["read", "update"],
            &["belongsToTenant"],
        );
        self.register_with_conditions(
            "learn_webhook",
            &["read", "create", "update", "delete"],
            &["belongsToTenant"],
        );
        self.register("user_profile", &["read"]);
        // TrustGraph 模块
        self.register(
            "permission_rule",
            &["read", "create", "update", "delete", "bind-permission"],
        );
        self.register(
            "permission_request",
            &["read", "create", "update", "approve"],
        );
        self.register("delegation", &["read", "create", "update", "delete"]);
        self.register("admin_group", &["read", "create", "update", "delete"]);
        self.register("permission_inheritance", &["read", "update"]);
        self.register("cross_org_grant", &["read", "update"]);
        self.register("enterprise_permission", &["read", "update"]);
        self.register("enterprise", &["read", "create", "update", "delete"]);
        self.register("authorization", &["read", "update"]);
        self.register("audit", &["read", "export"]);
        self.register("audit_quarantine", &["read", "replay"]);
        // `arbitrate` 供执剑人控制面 POST /arbiter/arbitrate 使用（trustgraph
        // permission_check 特例映射）；monitor 不注册 create，HTTP 默认 POST→
        // create 推导曾使该端点被 DEFAULT_DENY 结构性锁死。
        self.register("monitor", &["read", "scan", "arbitrate"]);
        self.register("domain", &["read", "create", "update", "delete"]);
        self.register(
            "domain_resource_type",
            &["read", "create", "update", "delete", "scan"],
        );
        // DomainControl 拆分后的资源类型（对齐 Java DomainControlController 拆分）
        self.register(
            "resource_type",
            &["read", "create", "update", "delete", "scan"],
        );
        self.register(
            "permission_action",
            &["read", "create", "update", "delete", "scan"],
        );
        self.register(
            "identity_user_grading",
            &["read", "create", "update", "delete"],
        );
        self.register("user", &["read", "bind-permission"]);
        // Identity 模块
        self.register("identity_users", &["read", "create", "update", "delete"]);
        self.register("identity_card", &["read", "create", "update", "delete"]);
        self.register(
            "identity_level_template",
            &["read", "create", "update", "delete"],
        );
        self.register(
            "identity_user_level",
            &["read", "create", "update", "delete"],
        );
        // 系统管理
        self.register("user_card", &["read", "create", "update", "delete"]);
        self.register(
            "user_card_template",
            &["read", "create", "update", "delete"],
        );
        self.register("rule_set", &["read", "create", "update", "delete"]);
        self.register("menu", &["read", "create", "update", "delete"]);
        self.register(
            "migration",
            &["read", "create", "update", "delete", "import", "export"],
        );
        // SaaS 多租户
        self.register(
            "platform_tenant",
            &["read", "create", "update", "delete", "suspend", "activate"],
        );
        self.register(
            "platform_package",
            &["read", "create", "update", "delete", "publish", "deprecate"],
        );
        self.register("platform_dept", &["read", "create", "update", "delete"]);
        self.register(
            "platform_tenant_member",
            &["read", "create", "update", "delete"],
        );
        self.register("platform_tenant_purchase", &["read", "create"]);
        self.register("platform_tenant_invitation", &["read", "create", "delete"]);
        self.register(
            "org_authority_edge",
            &["read", "create", "update", "bootstrap"],
        );
        self.register("org_unit_card", &["read", "create", "update"]);
        self.register("org_membership", &["read", "create", "update"]);
        // Chat 模块
        self.register("chat_message", &["read", "create", "update", "delete"]);
        self.register("chat_conversation", &["read", "create", "update", "delete"]);
        self.register("chat_offline_message", &["read", "create"]);
        // 通知
        self.register("notification", &["read", "create", "update"]);
        // 组织
        self.register("organization", &["read", "create", "update", "delete"]);
    }

    /// 校验资源类型和动作是否合法
    pub fn validate(&self, resource: &str, action: &str) -> Result<(), RegistryError> {
        let map = self.inner.read().expect("RwLock poisoned");
        let info = map
            .get(resource)
            .ok_or_else(|| RegistryError::UnregisteredResource(resource.to_string()))?;

        if info.actions.contains(action) {
            Ok(())
        } else {
            Err(RegistryError::InvalidAction {
                resource: resource.to_string(),
                action: action.to_string(),
            })
        }
    }

    /// 校验资源类型、动作和条件是否合法
    pub fn validate_with_conditions(
        &self,
        resource: &str,
        action: &str,
        condition_type: Option<&str>,
    ) -> Result<(), RegistryError> {
        let map = self.inner.read().expect("RwLock poisoned");
        let info = map
            .get(resource)
            .ok_or_else(|| RegistryError::UnregisteredResource(resource.to_string()))?;

        if !info.actions.contains(action) {
            return Err(RegistryError::InvalidAction {
                resource: resource.to_string(),
                action: action.to_string(),
            });
        }

        if let Some(cond) = condition_type {
            if !info.supported_conditions.contains(cond) {
                return Err(RegistryError::UnsupportedCondition {
                    resource: resource.to_string(),
                    condition: cond.to_string(),
                });
            }
        }

        Ok(())
    }

    /// 列出所有注册的资源类型
    pub fn list_resources(&self) -> Vec<String> {
        let map = self.inner.read().expect("RwLock poisoned");
        let mut keys: Vec<String> = map.keys().cloned().collect();
        keys.sort();
        keys
    }

    /// 列出指定资源类型的合法动作
    pub fn list_actions(&self, resource: &str) -> Option<Vec<String>> {
        let map = self.inner.read().expect("RwLock poisoned");
        map.get(resource).map(|info| {
            let mut v: Vec<String> = info.actions.iter().cloned().collect();
            v.sort();
            v
        })
    }

    /// 列出指定资源类型支持的条件类型
    pub fn list_supported_conditions(&self, resource: &str) -> Option<Vec<String>> {
        let map = self.inner.read().expect("RwLock poisoned");
        map.get(resource).map(|info| {
            let mut v: Vec<String> = info.supported_conditions.iter().cloned().collect();
            v.sort();
            v
        })
    }

    fn register(&mut self, resource: &str, actions: &[&str]) {
        self.register_with_conditions(resource, actions, &[]);
    }

    /// 带条件元数据的注册（对齐 Java `ResourceTypeInfo.supportedConditions`）
    fn register_with_conditions(&mut self, resource: &str, actions: &[&str], conditions: &[&str]) {
        let info = ResourceTypeInfo::new(actions, conditions);
        self.inner
            .write()
            .expect("RwLock poisoned")
            .insert(resource.to_string(), info);
    }

    /// 返回已注册的资源类型数量
    pub fn count(&self) -> usize {
        self.inner.read().expect("RwLock poisoned").len()
    }

    /// 列出所有注册的资源类型及其完整信息（含条件元数据，用于 API 暴露）
    pub fn list_resource_info(&self) -> Vec<(String, ResourceTypeInfo)> {
        let map = self.inner.read().expect("RwLock poisoned");
        let mut result: Vec<(String, ResourceTypeInfo)> =
            map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_validate() {
        let reg = ResourceRegistry::global();
        assert!(reg.validate("learn_subject", "read").is_ok());
        assert!(reg.validate("learn_subject", "write").is_err());
        assert!(reg.validate("nonexistent", "read").is_err());
    }

    #[test]
    fn test_registry_list_resources() {
        let reg = ResourceRegistry::global();
        let resources = reg.list_resources();
        assert!(resources.contains(&"learn_subject".to_string()));
        assert!(resources.contains(&"audit".to_string()));
        assert!(resources.contains(&"audit_quarantine".to_string()));
    }

    #[test]
    fn audit_quarantine_registers_only_metadata_read_and_replay_actions() {
        let reg = ResourceRegistry::global();
        assert!(reg.validate("audit_quarantine", "read").is_ok());
        assert!(reg.validate("audit_quarantine", "replay").is_ok());
        assert!(reg.validate("audit_quarantine", "create").is_err());
    }

    #[test]
    fn monitor_registers_arbitrate_but_never_create() {
        // 执剑人控制面动作（POST /arbiter/arbitrate）必须一等注册；monitor
        // 刻意不注册 create —— HTTP 默认 POST→create 推导曾使该端点被
        // DEFAULT_DENY 结构性锁死且无规则可授予（S12/S13 战役发现）。
        let reg = ResourceRegistry::global();
        assert!(reg.validate("monitor", "read").is_ok());
        assert!(reg.validate("monitor", "scan").is_ok());
        assert!(reg.validate("monitor", "arbitrate").is_ok());
        assert!(reg.validate("monitor", "create").is_err());
    }

    #[test]
    fn test_registry_list_actions() {
        let reg = ResourceRegistry::global();
        let actions = reg.list_actions("learn_subject").unwrap();
        assert!(actions.contains(&"import".to_string()));
    }

    // --- 动作别名测试 ---

    #[test]
    fn test_alias_forward() {
        // write 应展开为 create, update, delete
        let mut found = false;
        for &(alias, expanded) in ACTION_ALIASES {
            if alias == "write" {
                assert!(expanded.contains(&"create"));
                assert!(expanded.contains(&"update"));
                assert!(expanded.contains(&"delete"));
                found = true;
            }
        }
        assert!(found, "write alias must exist");
    }

    #[test]
    fn test_alias_reverse() {
        let sources = get_alias_sources("create");
        assert!(sources.contains(&"write"));

        let sources = get_alias_sources("delete");
        assert!(sources.contains(&"write"));

        // 没有别名的动作
        let sources = get_alias_sources("read");
        assert!(sources.is_empty());
    }

    // --- resourceKey 工具测试 ---

    #[test]
    fn test_build_resource_key_with_id() {
        assert_eq!(
            build_resource_key("learn_subject", Some(42)),
            "learn_subject:42"
        );
    }

    #[test]
    fn test_build_resource_key_without_id() {
        assert_eq!(build_resource_key("learn_subject", None), "learn_subject:*");
    }

    #[test]
    fn test_parse_resource_key() {
        let (rt, id) = parse_resource_key("learn_subject:42");
        assert_eq!(rt, "learn_subject");
        assert_eq!(id, Some("42"));
    }

    #[test]
    fn test_parse_resource_key_wildcard() {
        let (rt, id) = parse_resource_key("learn_subject:*");
        assert_eq!(rt, "learn_subject");
        assert_eq!(id, None);
    }

    #[test]
    fn test_parse_resource_key_no_id() {
        let (rt, id) = parse_resource_key("learn_subject");
        assert_eq!(rt, "learn_subject");
        assert_eq!(id, None);
    }

    #[test]
    fn test_is_wildcard_key() {
        assert!(is_wildcard_key("learn_subject:*"));
        assert!(!is_wildcard_key("learn_subject:42"));
        assert!(!is_wildcard_key("learn_subject"));
    }

    #[test]
    fn test_to_wildcard_key() {
        assert_eq!(
            to_wildcard_key("learn_subject:42"),
            Some("learn_subject:*".into())
        );
        assert_eq!(to_wildcard_key("learn_subject:*"), None);
        assert_eq!(to_wildcard_key("nosep"), None);
    }
}
