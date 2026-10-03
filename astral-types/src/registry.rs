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

/// A persisted custom resource definition accepted by the central registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomResourceRegistration {
    /// Exact canonical resource type name.
    pub resource_type: String,
    /// Exact concrete action names. Wildcards and action aliases are rejected.
    pub actions: Vec<String>,
}

/// Validation errors returned by controlled custom-resource registration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryRegistrationError {
    #[error("invalid resource type '{resource_type}'")]
    InvalidResourceType { resource_type: String },
    #[error("invalid action '{action}' for resource '{resource_type}'")]
    InvalidAction {
        resource_type: String,
        action: String,
    },
    #[error("reserved action alias '{action}' is not accepted for resource '{resource_type}'")]
    ReservedActionAlias {
        resource_type: String,
        action: String,
    },
    #[error("resource '{resource_type}' must declare at least one action")]
    EmptyActions { resource_type: String },
    #[error("action '{action}' is duplicated for resource '{resource_type}'")]
    DuplicateAction {
        resource_type: String,
        action: String,
    },
    #[error("conflicting registration for resource '{resource_type}'")]
    ConflictingResource { resource_type: String },
    #[error("built-in resource '{resource_type}' cannot be modified")]
    BuiltinResource { resource_type: String },
    #[error("resource registry lock is unavailable")]
    RegistryUnavailable,
    #[error("custom resource registry exceeds its configured bounds")]
    RegistryTooLarge,
    #[error("custom resource registry has too many resource types")]
    TooManyResources,
    #[error("resource '{resource_type}' exceeds the configured action limit")]
    TooManyActions { resource_type: String },
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

/// Maximum number of persisted custom resource definitions accepted at startup.
pub const MAX_CUSTOM_RESOURCE_TYPES: usize = 512;
/// Maximum number of concrete actions accepted for one custom resource.
pub const MAX_CUSTOM_RESOURCE_ACTIONS: usize = 64;
/// Maximum total encoded identifier bytes accepted for one registry load.
pub const MAX_CUSTOM_RESOURCE_REGISTRY_BYTES: usize = 64 * 1024;
/// Maximum byte length accepted for a resource type identifier.
pub const MAX_RESOURCE_TYPE_NAME_BYTES: usize = 128;
/// Maximum byte length accepted for an action identifier.
pub const MAX_ACTION_NAME_BYTES: usize = 64;

fn valid_registry_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
}

fn validate_custom_action_aliases(
    resource_type: &str,
    actions: &[String],
) -> Result<(), RegistryRegistrationError> {
    for &(alias, expanded) in ACTION_ALIASES {
        if actions.iter().any(|action| action == alias)
            && !expanded
                .iter()
                .all(|expanded_action| actions.iter().any(|action| action == expanded_action))
        {
            return Err(RegistryRegistrationError::ReservedActionAlias {
                resource_type: resource_type.to_owned(),
                action: alias.to_owned(),
            });
        }
    }
    Ok(())
}

fn prepare_custom_resource_registrations<I>(
    registrations: I,
) -> Result<HashMap<String, Vec<String>>, RegistryRegistrationError>
where
    I: IntoIterator<Item = CustomResourceRegistration>,
{
    let mut staged = HashMap::<String, Vec<String>>::new();
    let mut total_bytes = 0usize;
    for mut registration in registrations {
        if staged.len() >= MAX_CUSTOM_RESOURCE_TYPES
            && !staged.contains_key(&registration.resource_type)
        {
            return Err(RegistryRegistrationError::TooManyResources);
        }
        if !valid_registry_identifier(&registration.resource_type)
            || registration.resource_type.len() > MAX_RESOURCE_TYPE_NAME_BYTES
        {
            return Err(RegistryRegistrationError::InvalidResourceType {
                resource_type: registration.resource_type,
            });
        }
        if registration.actions.is_empty() {
            return Err(RegistryRegistrationError::EmptyActions {
                resource_type: registration.resource_type,
            });
        }
        if registration.actions.len() > MAX_CUSTOM_RESOURCE_ACTIONS {
            return Err(RegistryRegistrationError::TooManyActions {
                resource_type: registration.resource_type,
            });
        }
        let mut unique_actions = HashSet::with_capacity(registration.actions.len());
        for action in &registration.actions {
            if !valid_registry_identifier(action) || action.len() > MAX_ACTION_NAME_BYTES {
                return Err(RegistryRegistrationError::InvalidAction {
                    resource_type: registration.resource_type.clone(),
                    action: action.clone(),
                });
            }
            if !unique_actions.insert(action.clone()) {
                return Err(RegistryRegistrationError::DuplicateAction {
                    resource_type: registration.resource_type.clone(),
                    action: action.clone(),
                });
            }
        }
        total_bytes = total_bytes
            .saturating_add(registration.resource_type.len())
            .saturating_add(registration.actions.iter().map(String::len).sum::<usize>());
        if total_bytes > MAX_CUSTOM_RESOURCE_REGISTRY_BYTES {
            return Err(RegistryRegistrationError::RegistryTooLarge);
        }
        registration.actions.sort();
        match staged.get(&registration.resource_type) {
            Some(existing) if existing != &registration.actions => {
                return Err(RegistryRegistrationError::ConflictingResource {
                    resource_type: registration.resource_type,
                });
            }
            Some(_) => {}
            None => {
                staged.insert(registration.resource_type, registration.actions);
            }
        }
    }
    Ok(staged)
}

/// 资源类型注册表
pub struct ResourceRegistry {
    inner: RwLock<HashMap<String, ResourceTypeInfo>>,
    builtin_actions: HashMap<String, HashSet<String>>,
}

impl ResourceRegistry {
    /// 获取全局注册表实例（首次调用时自动注册内置类型）
    pub fn global() -> &'static ResourceRegistry {
        RESOURCE_REGISTRY.get_or_init(Self::new_with_builtins)
    }

    /// Validate persisted custom resources without mutating the live registry.
    pub fn validate_custom_resources<I>(
        &self,
        registrations: I,
    ) -> Result<(), RegistryRegistrationError>
    where
        I: IntoIterator<Item = CustomResourceRegistration>,
    {
        let staged = prepare_custom_resource_registrations(registrations)?;
        let registry = self
            .inner
            .read()
            .map_err(|_| RegistryRegistrationError::RegistryUnavailable)?;
        self.validate_staged_custom_resources(&registry, &staged)
    }

    /// Validate an explicit update of an already-registered custom resource.
    ///
    /// Action changes are persisted before being applied to the current process;
    /// the method validates schema and protects compiled-in resources.
    pub fn validate_custom_resource_update(
        &self,
        registration: CustomResourceRegistration,
    ) -> Result<(), RegistryRegistrationError> {
        let staged = prepare_custom_resource_registrations([registration])?;
        let Some((resource_type, actions)) = staged.iter().next() else {
            return Err(RegistryRegistrationError::RegistryTooLarge);
        };
        let registry = self
            .inner
            .read()
            .map_err(|_| RegistryRegistrationError::RegistryUnavailable)?;
        if self.builtin_actions.contains_key(resource_type) {
            return Err(RegistryRegistrationError::BuiltinResource {
                resource_type: resource_type.clone(),
            });
        }
        if !registry.contains_key(resource_type) {
            return Err(RegistryRegistrationError::ConflictingResource {
                resource_type: resource_type.clone(),
            });
        }
        validate_custom_action_aliases(resource_type, actions)
    }

    /// Whether `resource` is part of the compiled registry and cannot be modified
    /// by persisted custom-registry operations.
    pub fn is_builtin_resource(&self, resource: &str) -> bool {
        self.builtin_actions.contains_key(resource)
    }

    /// Replace the action set for an already-registered custom resource after its
    /// persistence transaction succeeds. Compiled-in resources are immutable and
    /// new custom `write` aliases are rejected unless fully expanded actions exist.
    pub fn replace_custom_resource_actions(
        &self,
        registration: CustomResourceRegistration,
    ) -> Result<(), RegistryRegistrationError> {
        let staged = prepare_custom_resource_registrations([registration])?;
        let (resource_type, actions) = staged
            .into_iter()
            .next()
            .ok_or(RegistryRegistrationError::RegistryUnavailable)?;
        let mut registry = self
            .inner
            .write()
            .map_err(|_| RegistryRegistrationError::RegistryUnavailable)?;
        if self.builtin_actions.contains_key(&resource_type) {
            return Err(RegistryRegistrationError::BuiltinResource { resource_type });
        }
        validate_custom_action_aliases(&resource_type, &actions)?;
        let info = registry.get_mut(&resource_type).ok_or_else(|| {
            RegistryRegistrationError::ConflictingResource {
                resource_type: resource_type.clone(),
            }
        })?;
        info.actions = actions.into_iter().collect();
        Ok(())
    }

    /// Remove an already-registered custom resource after its persistence delete
    /// succeeds. Compiled-in resources cannot be removed.
    pub fn unregister_custom_resource(
        &self,
        resource_type: &str,
    ) -> Result<(), RegistryRegistrationError> {
        if !valid_registry_identifier(resource_type)
            || resource_type.len() > MAX_RESOURCE_TYPE_NAME_BYTES
        {
            return Err(RegistryRegistrationError::InvalidResourceType {
                resource_type: resource_type.into(),
            });
        }
        if self.builtin_actions.contains_key(resource_type) {
            return Err(RegistryRegistrationError::BuiltinResource {
                resource_type: resource_type.into(),
            });
        }
        let mut registry = self
            .inner
            .write()
            .map_err(|_| RegistryRegistrationError::RegistryUnavailable)?;
        registry.remove(resource_type).ok_or_else(|| {
            RegistryRegistrationError::ConflictingResource {
                resource_type: resource_type.into(),
            }
        })?;
        Ok(())
    }

    /// Register persisted custom resources using an additive, validated contract.
    ///
    /// The operation is batch-atomic. Identical repeated custom rows and persisted
    /// built-in rows whose actions are a subset of the compiled action set are
    /// idempotent; stale/mismatched rows fail closed without expanding built-in
    /// authority. Custom resources reject wildcards and incomplete `write` aliases.
    pub fn register_custom_resources<I>(
        &self,
        registrations: I,
    ) -> Result<(), RegistryRegistrationError>
    where
        I: IntoIterator<Item = CustomResourceRegistration>,
    {
        let staged = prepare_custom_resource_registrations(registrations)?;
        let mut registry = self
            .inner
            .write()
            .map_err(|_| RegistryRegistrationError::RegistryUnavailable)?;
        self.validate_staged_custom_resources(&registry, &staged)?;

        for (resource_type, actions) in staged {
            if self.builtin_actions.contains_key(&resource_type)
                || registry.contains_key(&resource_type)
            {
                continue;
            }
            registry.insert(
                resource_type,
                ResourceTypeInfo {
                    actions: actions.into_iter().collect(),
                    supported_conditions: HashSet::new(),
                },
            );
        }
        Ok(())
    }

    fn validate_staged_custom_resources(
        &self,
        registry: &HashMap<String, ResourceTypeInfo>,
        staged: &HashMap<String, Vec<String>>,
    ) -> Result<(), RegistryRegistrationError> {
        for (resource_type, actions) in staged {
            if let Some(builtin_actions) = self.builtin_actions.get(resource_type) {
                if !actions
                    .iter()
                    .all(|action| builtin_actions.contains(action))
                {
                    return Err(RegistryRegistrationError::BuiltinResource {
                        resource_type: resource_type.clone(),
                    });
                }
                continue;
            }
            validate_custom_action_aliases(resource_type, actions)?;
            if let Some(existing) = registry.get(resource_type) {
                if existing.actions.len() != actions.len()
                    || !actions
                        .iter()
                        .all(|action| existing.actions.contains(action))
                {
                    return Err(RegistryRegistrationError::ConflictingResource {
                        resource_type: resource_type.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    fn new_with_builtins() -> ResourceRegistry {
        let mut reg = ResourceRegistry {
            inner: RwLock::new(HashMap::new()),
            builtin_actions: HashMap::new(),
        };
        reg.register_builtin_types();
        reg.builtin_actions = reg
            .inner
            .read()
            .expect("builtin registry lock must be available during initialization")
            .iter()
            .map(|(resource, info)| (resource.clone(), info.actions.clone()))
            .collect();
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
        // TrustGraph monitor operations use explicit write actions rather than
        // relying on POST→create or wildcard grants: alert rules (create/update/delete),
        // consistency scans, stats reset, and the arbiter control plane.
        self.register(
            "monitor",
            &[
                "read",
                "create",
                "update",
                "delete",
                "scan",
                "reset",
                "arbitrate",
            ],
        );
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
        self.register("notification", &["read", "create", "update", "test"]);
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
    fn persisted_builtin_rows_allow_only_compatible_action_subsets() {
        let registry = ResourceRegistry::global();
        for actions in [
            vec!["read".into()],
            vec![
                "read".into(),
                "create".into(),
                "update".into(),
                "delete".into(),
            ],
        ] {
            assert!(registry
                .validate_custom_resources([CustomResourceRegistration {
                    resource_type: "monitor".into(),
                    actions,
                }])
                .is_ok());
        }
        let monitor_actions = registry.list_actions("monitor").unwrap();
        assert!(registry
            .validate_custom_resources([CustomResourceRegistration {
                resource_type: "monitor".into(),
                actions: monitor_actions,
            }])
            .is_ok());
    }

    #[test]
    fn monitor_and_notification_register_only_explicit_route_actions() {
        let reg = ResourceRegistry::global();
        for action in [
            "read",
            "create",
            "update",
            "delete",
            "scan",
            "reset",
            "arbitrate",
        ] {
            assert!(
                reg.validate("monitor", action).is_ok(),
                "missing monitor:{action}"
            );
        }
        assert!(reg.validate("monitor", "write").is_err());
        assert!(reg.validate("notification", "test").is_ok());
    }

    #[test]
    fn custom_registration_is_validated_bounded_and_idempotent() {
        let registry = ResourceRegistry::global();
        let unique = format!("test_custom_resource_{}", std::process::id());
        let actions = vec!["read".to_owned(), "approve".to_owned()];
        let registration = CustomResourceRegistration {
            resource_type: unique.clone(),
            actions: actions.clone(),
        };
        assert!(registry
            .validate_custom_resources([registration.clone()])
            .is_ok());
        assert!(registry
            .register_custom_resources([registration.clone()])
            .is_ok());
        assert!(registry
            .register_custom_resources([CustomResourceRegistration {
                resource_type: unique.clone(),
                actions: vec!["approve".into(), "read".into()],
            }])
            .is_ok());
        assert!(registry.validate(&unique, "read").is_ok());
        assert!(registry.validate(&unique, "approve").is_ok());
        assert!(registry.validate(&unique, "delete").is_err());
        assert!(registry.validate("learn_wrong_question", "write").is_ok());

        assert!(registry
            .register_custom_resources([CustomResourceRegistration {
                resource_type: unique.clone(),
                actions: vec!["read".into()],
            }])
            .is_err());
        assert!(registry
            .validate_custom_resources([CustomResourceRegistration {
                resource_type: "monitor".into(),
                actions: vec!["read".into(), "unknown".into()],
            }])
            .is_err());

        for (resource_type, actions) in [
            ("bad*resource", vec!["read".into()]),
            ("safe_resource", vec!["*".into()]),
            ("safe_alias", vec!["write".into()]),
            ("safe_empty", Vec::new()),
        ] {
            assert!(registry
                .validate_custom_resources([CustomResourceRegistration {
                    resource_type: resource_type.into(),
                    actions,
                }])
                .is_err());
        }
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
