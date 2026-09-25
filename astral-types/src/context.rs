//! 权限评估上下文
//!
//! `PolicyContext` 封装一次权限请求的完整上下文。`action` 为必填字段，
//! 其余字段默认均持 `None`/空集合，通过 typed-builder 的可选 setter 链式调用。

use typed_builder::TypedBuilder;

/// Server-side classification of whether a Global target additionally requires
/// platform-wide administration authority.
///
/// This is meaningful only with [`ResourceOwnershipScope::Global`] and is
/// written exclusively by the service-side resource-owner resolver. `Unspecified`
/// is deliberately the default so a hand-built or incompletely migrated Global
/// HTTP context fails closed instead of silently treating ordinary card evidence
/// as platform authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GlobalAccessRequirement {
    /// No resolver contract established the Global route's access requirement.
    #[default]
    Unspecified,
    /// A live, database-backed `identity_global_admin` record is required in
    /// addition to formal PolicyEngine rule evidence.
    ActiveGlobalAdmin,
    /// A narrowly declared non-control-plane Global endpoint may use ordinary
    /// formal policy evidence after its handler-specific server-side checks.
    PolicyEvidence,
}

/// Server-side classification of the protected target resource.
///
/// `tenant_scoped` means that a trusted resolver loaded the target owner's
/// tenant (and, when applicable, domain) from an authoritative service-side
/// store. `global` is reserved for an explicitly classified control-plane
/// resource with no tenant owner. `unresolved` and `unavailable` are HTTP
/// resolver outcomes that must fail closed before any tenant-owned ORG_SCOPE
/// admission. `internal` is the default only for in-process typed callers and
/// tests; HTTP context construction must explicitly begin as `Unresolved`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResourceOwnershipScope {
    #[default]
    Internal,
    TenantScoped,
    Global,
    Unresolved,
    Unavailable,
}

/// 权限评估请求上下文
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, TypedBuilder)]
#[serde(rename_all = "camelCase")]
pub struct PolicyContext {
    #[builder(default)]
    pub user_id: Option<i64>,

    /// 认证主体类型。真实请求必须由 Gateway 注入，纯策略测试可为空。
    #[builder(default)]
    pub principal_kind: Option<String>,

    #[builder(default)]
    pub card_id: Option<i64>,

    /// 当前认证身份卡 ID。与 `card_id`（用户卡）严格分离。
    /// 身份卡不承担组织归属（tenant/domain 由 user_card 承载，问题 1 修正）。
    #[builder(default)]
    pub identity_card_id: Option<i64>,

    #[builder(default)]
    pub template_id: Option<i64>,

    #[builder(default)]
    pub action_codes: Vec<String>,

    #[builder(default)]
    pub domain_id: Option<i64>,

    #[builder(default)]
    pub tenant_id: Option<i64>,

    /// Authoritatively resolved target-resource tenant. This is meaningful only
    /// when `resource_ownership_scope` is `TenantScoped`; it must be populated
    /// by a server-side resource-owner resolver, never copied from actor identity
    /// or client-controlled request data.
    #[builder(default)]
    pub resource_tenant_id: Option<i64>,

    /// Authoritatively resolved target-resource domain when the tenant-owned
    /// resource has one. This is never a client-provided request fact.
    #[builder(default)]
    pub resource_domain_id: Option<i64>,

    /// Whether the target has been classified by the server-side resource-owner
    /// resolver. Authenticated actor context alone remains `Unresolved`.
    #[builder(default)]
    #[serde(default)]
    pub resource_ownership_scope: ResourceOwnershipScope,

    /// Additional server-side access requirement for a `Global` target. This is
    /// never derived from a role string, request body, query parameter, or
    /// client-controlled header.
    #[builder(default)]
    #[serde(default)]
    pub global_access_requirement: GlobalAccessRequirement,

    #[builder(default)]
    pub structure_node_id: Option<i64>,

    #[builder(default)]
    pub resource: Option<String>,

    /// 请求的动作（必填），编译期由 typed-builder 强制
    pub action: String,

    #[builder(default)]
    pub target_id: Option<i64>,

    /// 目标资源属主 user id。只有服务端权威资源解析器可填充该事实；普通 HTTP
    /// 中间件当前不从任何客户端或转发 header 写入此字段。
    ///
    /// 供 OwnerOnly 条件与 DYNAMIC SoD 求值：OwnerOnly 要求
    /// `resource_owner_id == user_id`（无法解析或不等 → deny，fail-closed 对齐
    /// Java ConditionEvaluator 的 `ownerUserId.equals(currentUserId)`）。
    #[builder(default)]
    pub resource_owner_id: Option<i64>,

    #[builder(default)]
    pub sensitivity_level: Option<i32>,

    #[builder(default)]
    pub ip: Option<String>,

    #[builder(default)]
    pub user_agent: Option<String>,

    /// 请求体附加数据（传递给条件评估器）
    #[builder(default)]
    pub request: Option<serde_json::Value>,

    /// 语言环境（对齐 Java PolicyContext.locale）
    #[builder(default)]
    #[serde(default)]
    pub locale: Option<String>,

    /// 是否限定域范围（对齐 Java PolicyContext.domainScoped）
    #[builder(default)]
    #[serde(default)]
    pub domain_scoped: bool,

    /// 是否启用权限继承（对齐 Java PolicyContext.inheritanceEnabled）
    #[builder(default)]
    #[serde(default)]
    pub inheritance_enabled: bool,
}
