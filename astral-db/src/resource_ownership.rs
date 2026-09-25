//! Server-side protected-resource ownership resolution.
//!
//! Gateway headers authenticate the actor, not the object being accessed. This
//! module resolves object ownership from server-side rows before a protected HTTP
//! request reaches `PolicyEngine.evaluate()`. A missing source contract is an
//! explicit fail-closed outcome; it is never interpreted as the caller owning
//! the target.

use astral_types::{GlobalAccessRequirement, PolicyContext, ResourceOwnershipScope};
use sqlx::MySqlPool;

/// Result of resolving a protected route's target resource.
///
/// `Unresolved` means the database contract completed but cannot prove a single
/// target ownership tuple. `Unavailable` means the authoritative lookup itself
/// failed. Both are applied to `PolicyContext` and rejected by `PolicyEngine`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceOwnershipResolution {
    TenantScoped {
        target_id: Option<i64>,
        tenant_id: i64,
        domain_id: Option<i64>,
        owner_id: Option<i64>,
    },
    Global {
        target_id: Option<i64>,
        access_requirement: GlobalAccessRequirement,
    },
    Unresolved {
        code: &'static str,
    },
    Unavailable {
        code: &'static str,
    },
}

impl ResourceOwnershipResolution {
    /// Apply a resolver outcome to a context that was built from verified actor
    /// headers. This always clears previous target facts before writing the new
    /// classification so a stale caller-owned fact cannot survive a failed lookup.
    pub fn apply_to(&self, ctx: &mut PolicyContext) {
        ctx.target_id = None;
        ctx.resource_tenant_id = None;
        ctx.resource_domain_id = None;
        ctx.resource_owner_id = None;
        ctx.global_access_requirement = GlobalAccessRequirement::Unspecified;
        match self {
            Self::TenantScoped {
                target_id,
                tenant_id,
                domain_id,
                owner_id,
            } => {
                ctx.target_id = *target_id;
                ctx.resource_tenant_id = Some(*tenant_id);
                ctx.resource_domain_id = *domain_id;
                ctx.resource_owner_id = *owner_id;
                ctx.resource_ownership_scope = ResourceOwnershipScope::TenantScoped;
            }
            Self::Global {
                target_id,
                access_requirement,
            } => {
                ctx.target_id = *target_id;
                ctx.global_access_requirement = *access_requirement;
                ctx.resource_ownership_scope = ResourceOwnershipScope::Global;
            }
            Self::Unresolved { .. } => {
                ctx.resource_ownership_scope = ResourceOwnershipScope::Unresolved;
            }
            Self::Unavailable { .. } => {
                ctx.resource_ownership_scope = ResourceOwnershipScope::Unavailable;
            }
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::TenantScoped { .. } => "resource_ownership.resolved",
            Self::Global { .. } => "resource_ownership.global",
            Self::Unresolved { code } | Self::Unavailable { code } => code,
        }
    }
}

/// Resolve the target resource identified by a protected route.
///
/// Ownership facts originate only from the matched route contract and a
/// server-side row. Query identifiers are accepted only for a closed, declared
/// query-addressed route; a create/action route cannot attach an arbitrary
/// query object's tenant to itself. `actor_card_id` and `actor_user_id` are used
/// only for a small set of explicitly actor-unit governance operations. The
/// resolver re-reads the card from `user_card` and verifies its owner against the
/// signed actor before deriving any target facts; it never copies signed
/// tenant/domain headers into the target scope.
pub async fn resolve_resource_ownership(
    pool: &MySqlPool,
    resource: &str,
    path: &str,
    method: &str,
    query_target_id: Option<i64>,
    actor_card_id: Option<i64>,
    actor_user_id: Option<i64>,
) -> ResourceOwnershipResolution {
    match route_ownership_contract(resource, path, method, query_target_id) {
        RouteOwnershipContract::OrgMembership { membership_id } => {
            ownership_from_lookup(None, resolve_org_membership(pool, membership_id).await)
        }
        RouteOwnershipContract::ActorUnit => {
            let lookup = match (actor_card_id, actor_user_id) {
                (Some(card_id), Some(user_id)) => resolve_actor_unit_card(pool, card_id, user_id)
                    .await
                    .map(|(tenant_id, domain_id)| (tenant_id, domain_id, None)),
                (None, _) => Err(ResolverLookupError::Unresolved(
                    "resource_ownership.actor_card_missing",
                )),
                (_, None) => Err(ResolverLookupError::Unresolved(
                    "resource_ownership.actor_user_missing",
                )),
            };
            ownership_from_lookup(None, lookup)
        }
        RouteOwnershipContract::Global {
            target_id,
            access_requirement,
        } => ResourceOwnershipResolution::Global {
            target_id,
            access_requirement,
        },
        RouteOwnershipContract::TenantTarget { target_id, lookup } => ownership_from_lookup(
            Some(target_id),
            resolve_target_lookup(pool, target_id, lookup).await,
        ),
        RouteOwnershipContract::Unresolved { code } => {
            ResourceOwnershipResolution::Unresolved { code }
        }
    }
}

fn ownership_from_lookup(
    target_id: Option<i64>,
    result: Result<(i64, Option<i64>, Option<i64>), ResolverLookupError>,
) -> ResourceOwnershipResolution {
    match result {
        Ok((tenant_id, domain_id, owner_id)) => {
            tenant_scoped(target_id, tenant_id, domain_id, owner_id)
        }
        Err(ResolverLookupError::Unresolved(code)) => {
            ResourceOwnershipResolution::Unresolved { code }
        }
        Err(ResolverLookupError::Unavailable(code)) => {
            ResourceOwnershipResolution::Unavailable { code }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolverLookupError {
    Unresolved(&'static str),
    Unavailable(&'static str),
}

/// The authoritative source table selected by an explicit target route. This
/// is intentionally a closed route contract: adding a protected object route
/// requires naming its lookup kind here before it can reach the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetLookupKind {
    Tenant,
    EnterpriseOrganization,
    UserCard,
    User,
    Delegation,
    LevelTemplate,
    RuleSet,
    PermissionRule,
    OrgScopeRequest,
    PermissionRequest,
    AuditRecord,
    ChatConversation,
    ChatConversationWithoutOwner,
    ChatMessage,
    CardTemplate,
    UserLevel,
    UserGrading,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteOwnershipContract<'a> {
    OrgMembership {
        membership_id: &'a str,
    },
    ActorUnit,
    Global {
        target_id: Option<i64>,
        access_requirement: GlobalAccessRequirement,
    },
    TenantTarget {
        target_id: i64,
        lookup: TargetLookupKind,
    },
    Unresolved {
        code: &'static str,
    },
}

fn route_ownership_contract<'a>(
    resource: &str,
    path: &'a str,
    method: &str,
    query_target_id: Option<i64>,
) -> RouteOwnershipContract<'a> {
    if resource == "org_membership" {
        if let Some(membership_id) = org_membership_id(path) {
            return RouteOwnershipContract::OrgMembership { membership_id };
        }
    }

    if is_actor_unit_route(resource, path, method) {
        return RouteOwnershipContract::ActorUnit;
    }

    let target_id = match resolved_target_id(resource, path, method, query_target_id) {
        Ok(target_id) => target_id,
        Err(code) => return RouteOwnershipContract::Unresolved { code },
    };

    if let Some(access_requirement) = global_access_requirement(resource, path, method, target_id) {
        return RouteOwnershipContract::Global {
            target_id,
            access_requirement,
        };
    }

    let Some(target_id) = target_id else {
        return RouteOwnershipContract::Unresolved {
            code: "resource_ownership.target_missing",
        };
    };

    match target_lookup_kind(resource, path) {
        Some(lookup) => RouteOwnershipContract::TenantTarget { target_id, lookup },
        None => RouteOwnershipContract::Unresolved {
            code: target_lookup_unresolved_code(resource),
        },
    }
}
fn target_lookup_kind(resource: &str, path: &str) -> Option<TargetLookupKind> {
    match resource {
        "platform_tenant" | "org_authority_edge" | "org_unit_card" => {
            Some(TargetLookupKind::Tenant)
        }
        "organization" => Some(TargetLookupKind::EnterpriseOrganization),
        "identity_users" | "user" if path.starts_with("/cards/") => {
            Some(TargetLookupKind::UserCard)
        }
        "identity_users" | "user" if path.starts_with("/users/") || path.starts_with("/ws/") => {
            Some(TargetLookupKind::User)
        }
        "permission_rule"
            if path.starts_with("/permission-rules/card/")
                || path.starts_with("/rule-sets/card/") =>
        {
            Some(TargetLookupKind::UserCard)
        }
        "permission_rule" if path.starts_with("/delegations/") => {
            Some(TargetLookupKind::Delegation)
        }
        "permission_rule" if path.starts_with("/level-templates/") => {
            Some(TargetLookupKind::LevelTemplate)
        }
        "permission_rule" if path.starts_with("/rule-sets/") => Some(TargetLookupKind::RuleSet),
        "permission_rule" if path.starts_with("/permission-rules/") => {
            Some(TargetLookupKind::PermissionRule)
        }
        "permission_request" if path.starts_with("/permission-requests/org-scopes/") => {
            Some(TargetLookupKind::OrgScopeRequest)
        }
        "permission_request" if path.starts_with("/permission-requests/") => {
            Some(TargetLookupKind::PermissionRequest)
        }
        "audit" => Some(TargetLookupKind::AuditRecord),
        "chat_conversation" if path.starts_with("/ws/") => Some(TargetLookupKind::User),
        "chat_conversation" => Some(TargetLookupKind::ChatConversation),
        "chat_message"
            if path.starts_with("/messages/") && !path.starts_with("/messages/session/") =>
        {
            Some(TargetLookupKind::ChatMessage)
        }
        "chat_message"
            if path.starts_with("/receipts/") || path.starts_with("/messages/session/") =>
        {
            Some(TargetLookupKind::ChatConversationWithoutOwner)
        }
        "domain" if path.starts_with("/user-cards/") => Some(TargetLookupKind::UserCard),
        "domain" if path.starts_with("/card-templates/") => Some(TargetLookupKind::CardTemplate),
        "domain" if path.starts_with("/user-levels/") => Some(TargetLookupKind::UserLevel),
        "domain" if path.starts_with("/user-gradings/") => Some(TargetLookupKind::UserGrading),
        _ => None,
    }
}

fn target_lookup_unresolved_code(resource: &str) -> &'static str {
    match resource {
        "platform_dept" => "resource_ownership.department_tenant_contract_unmapped",
        "org_membership" => "resource_ownership.org_membership_locator_unsupported",
        "identity_users" | "user" => "resource_ownership.identity_user_route_unmapped",
        "permission_rule" => "resource_ownership.permission_rule_route_unmapped",
        "permission_request" => "resource_ownership.permission_request_route_unmapped",
        "chat_message" => "resource_ownership.chat_message_route_unmapped",
        "domain" => "resource_ownership.domain_route_unmapped",
        _ => "resource_ownership.resource_unmapped",
    }
}

async fn resolve_target_lookup(
    pool: &MySqlPool,
    target_id: i64,
    kind: TargetLookupKind,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    match kind {
        TargetLookupKind::Tenant => resolve_tenant(pool, target_id).await,
        TargetLookupKind::EnterpriseOrganization => {
            resolve_enterprise_organization(pool, target_id).await
        }
        TargetLookupKind::UserCard => resolve_user_card(pool, target_id).await,
        TargetLookupKind::User => resolve_user(pool, target_id).await,
        TargetLookupKind::Delegation => resolve_delegation(pool, target_id).await,
        TargetLookupKind::LevelTemplate => resolve_level_template(pool, target_id).await,
        TargetLookupKind::RuleSet => resolve_rule_set(pool, target_id).await,
        TargetLookupKind::PermissionRule => resolve_permission_rule(pool, target_id).await,
        TargetLookupKind::OrgScopeRequest => resolve_org_scope_request(pool, target_id).await,
        TargetLookupKind::PermissionRequest => resolve_permission_request(pool, target_id).await,
        TargetLookupKind::AuditRecord => resolve_audit_record(pool, target_id).await,
        TargetLookupKind::ChatConversation => resolve_chat_conversation(pool, target_id).await,
        TargetLookupKind::ChatConversationWithoutOwner => {
            resolve_chat_conversation_without_owner(pool, target_id).await
        }
        TargetLookupKind::ChatMessage => resolve_chat_message(pool, target_id).await,
        TargetLookupKind::CardTemplate => resolve_card_template(pool, target_id).await,
        TargetLookupKind::UserLevel => resolve_user_level(pool, target_id).await,
        TargetLookupKind::UserGrading => resolve_user_grading(pool, target_id).await,
    }
}

type DelegationScopeRow = (
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
);

/// Read the authoritative GlobalAdmin source row without caching.
///
/// Formal authorization calls this at the Global control-plane ownership gate
/// and again before returning an ALLOW. Management-scope helpers may layer a
/// bounded cache above this read, but they must not replace it inside
/// `PolicyEngine.evaluate()` because a stale positive result expands authority.
pub async fn is_active_global_admin(pool: &MySqlPool, user_id: i64) -> Result<bool, sqlx::Error> {
    if user_id <= 0 {
        return Ok(false);
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM identity_global_admin WHERE user_id = ? AND status = 'ACTIVE'",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;
    Ok(count > 0)
}

fn tenant_scoped(
    target_id: Option<i64>,
    tenant_id: i64,
    domain_id: Option<i64>,
    owner_id: Option<i64>,
) -> ResourceOwnershipResolution {
    if tenant_id <= 0
        || domain_id.is_some_and(|domain_id| domain_id <= 0)
        || owner_id.is_some_and(|owner_id| owner_id <= 0)
    {
        return ResourceOwnershipResolution::Unresolved {
            code: "resource_ownership.invalid_authoritative_facts",
        };
    }
    ResourceOwnershipResolution::TenantScoped {
        target_id,
        tenant_id,
        domain_id,
        owner_id,
    }
}

/// Some protected routes are actor-scoped by their endpoint contract rather than
/// by a path object. The handler must independently prove that the request only
/// operates on the verified caller card (or its administrative unit). The
/// resolver still reloads that card from server-side state and verifies the
/// signed actor before deriving target tenant/domain; neither a body tenant nor
/// a query object becomes a target fact.
fn is_actor_unit_route(resource: &str, path: &str, method: &str) -> bool {
    matches!(
        (resource, path, method),
        ("org_authority_edge", "/org-authority-edges/attach", "POST")
            | ("org_authority_edge", "/org-authority-edges/move", "POST")
            | ("org_authority_edge", "/org-authority-edges/detach", "POST")
            | ("org_membership", "/org-memberships", "POST")
            | (
                "permission_request",
                "/permission-requests/org-scopes",
                "POST"
            )
            | ("permission_rule", "/delegations", "GET")
            | ("permission_rule", "/delegations", "POST")
            | ("permission_rule", "/delegations/by-delegator", "GET")
            | ("permission_rule", "/delegations/by-delegate", "GET")
            // Rule CRUD collection routes bind the body/list target to the
            // verified current card, and the handler repeats its server-side
            // management-scope check before any repository write/read.
            | ("permission_rule", "/permission-rules", "GET")
            | ("permission_rule", "/permission-rules", "POST")
            // Chat collection/create routes construct `ChatScope` only for a
            // verified PlatformUser and all repository operations constrain the
            // work to that active card's tenant/domain scope.
            | ("chat_conversation", "/groups", "GET")
            | ("chat_conversation", "/groups", "POST")
            | ("chat_conversation", "/sessions", "GET")
            | ("chat_conversation", "/sessions", "POST")
    )
}

fn org_membership_id(path: &str) -> Option<&str> {
    let membership_id = path
        .strip_prefix("/org-memberships/")?
        .strip_suffix("/revoke")?;
    (!membership_id.is_empty() && !membership_id.contains('/')).then_some(membership_id)
}

/// Explicit Global classification is intentionally route-aware. A resource with
/// no durable owner is not automatically Global, and the resolver records the
/// required access proof alongside every Global result.
///
/// `ActiveGlobalAdmin` is enforced inside `PolicyEngine.evaluate()` against a
/// fresh server-side `identity_global_admin` read before and after formal rule
/// evidence. `PolicyEvidence` is reserved for narrowly self-scoped utilities
/// whose handlers independently constrain the subject to the verified caller.
/// Any path not named here remains `Unresolved` instead of inheriting an actor
/// tenant or becoming a platform-wide endpoint by convention.
fn global_access_requirement(
    resource: &str,
    path: &str,
    method: &str,
    target_id: Option<i64>,
) -> Option<GlobalAccessRequirement> {
    use GlobalAccessRequirement::{ActiveGlobalAdmin, PolicyEvidence};

    // Self-service/static utilities have no tenant-owned target. Their handlers
    // independently bind any subject to the signed caller (or return fixed
    // metadata), while strict evidence from the active card remains required.
    if matches!(
        (resource, path, method),
        ("permission_rule", "/permission-rules/check", "GET")
            | ("permission_rule", "/permission-rules/registry", "GET")
            | ("permission_rule", "/permission-rules/validate", "POST")
            | ("identity_users", "/cards", "GET")
            | ("identity_users", "/cards", "POST")
            | ("identity_users", "/mfa/status", "GET")
            | ("identity_users", "/mfa/enable", "POST")
            | ("identity_users", "/mfa/disable", "POST")
            | ("identity_users", "/mfa/verify", "POST")
            | ("identity_users", "/mfa/recovery-codes", "POST")
            | ("permission_request", "/permission-requests/mine", "GET")
            | ("platform_tenant", "/tenants/mine", "GET")
            | ("platform_tenant", "/tenants/types", "GET")
            // This route is default-off and also requires a constant-time
            // deployment token; its normal PolicyEngine evidence remains an
            // additional defense rather than a GlobalAdmin prerequisite.
            | ("monitor", "/internal/test-control/worker-id", "GET")
    ) {
        return Some(PolicyEvidence);
    }

    if matches!(
        resource,
        "domain_resource_type"
            | "permission_action"
            | "platform_package"
            | "authorization"
            | "permission_inheritance"
            | "admin_group"
            | "cross_org_grant"
            | "identity_level_template"
            | "audit_quarantine"
    ) {
        return Some(ActiveGlobalAdmin);
    }

    if resource == "audit" && target_id.is_none() {
        return Some(ActiveGlobalAdmin);
    }

    if resource == "domain" && (path == "/domains" || path.starts_with("/domains/")) {
        return Some(ActiveGlobalAdmin);
    }

    if resource == "permission_rule"
        && (path.starts_with("/simulation")
            || path == "/sod-policies"
            || path.starts_with("/sod-policies/"))
    {
        return Some(ActiveGlobalAdmin);
    }

    if resource == "monitor"
        && (matches!(
            path,
            "/stats"
                | "/stats/reset"
                | "/stats/projector"
                | "/consistency/check"
                | "/consistency/check/stats"
                | "/consistency/check/violations"
                | "/arbiter/arbitrate"
                | "/arbiter/stats"
                | "/alerts"
                | "/alert-rules"
                | "/alert-history"
                | "/rules"
                | "/cache"
                | "/latency"
                | "/resources"
                | "/trend"
                | "/services"
                | "/metrics"
                | "/activities"
                | "/activity-logs"
                | "/audit-logs"
                | "/system-info"
                | "/dashboard"
                | "/consistency-check"
        ) || path.starts_with("/alerts/")
            || path.starts_with("/alert-rules/")
            || path.starts_with("/alert-history/")
            || path.starts_with("/metrics/"))
    {
        return Some(ActiveGlobalAdmin);
    }

    if resource == "notification"
        && (path == "/notifications" || path.starts_with("/notifications/") || path == "/channels")
    {
        return Some(ActiveGlobalAdmin);
    }

    if matches!(
        (resource, path, method),
        // These are platform-wide directory/admin operations. They have no
        // tenant-owned target row, so a fresh GlobalAdmin proof and strict
        // published policy evidence are both required.
        ("identity_users", "/users", "GET")
            | ("identity_users", "/users", "POST")
            | ("identity_users", "/admin/stats", "GET")
            | ("identity_users", "/admin/audit-log", "GET")
            | ("organization", "/orgs", "GET")
            | ("organization", "/orgs", "POST")
            | ("platform_tenant", "/tenants", "GET")
            | ("platform_tenant", "/tenants", "POST")
            // Monitor reads and mutations are platform operations; this summary
            // has no tenant/user filter in its handler.
            | ("monitor", "/alerts-summary", "GET")
    ) {
        return Some(ActiveGlobalAdmin);
    }

    match (resource, path, method) {
        // Rule-set collection and template catalog handlers are platform control
        // plane. Object paths remain resolver-backed tenant/domain targets.
        ("permission_rule", "/rule-sets", "GET")
        | ("permission_rule", "/rule-sets", "POST")
        | ("permission_rule", "/rule-sets/templates", "GET")
        // Whole-request and pending-request queues are platform views. The
        // caller-filtered /mine read has its own PolicyEvidence contract above.
        | ("permission_request", "/permission-requests", "GET")
        | ("permission_request", "/permission-requests/pending", "GET")
        // Targetless template and level catalog operations are platform control
        // plane; object routes continue through resolver-backed target facts.
        | ("permission_rule", "/level-templates", "GET")
        | ("permission_rule", "/level-templates", "POST")
        | ("permission_rule", "/level-templates/sync", "POST")
        | ("permission_rule", "/level-templates/precheck", "POST")
        | ("domain", "/card-templates", "GET")
        | ("domain", "/card-templates", "POST")
        | ("domain", "/user-levels", "POST")
        | ("domain", "/user-gradings", "POST") => Some(ActiveGlobalAdmin),
        _ => None,
    }
}

/// Return only a route-declared numeric object identifier. This is deliberately
/// resource-aware: a number in an action route is not automatically an object
/// identifier for a different resource family.
fn path_target_id(resource: &str, path: &str) -> Option<i64> {
    match resource {
        "chat_message" if path.starts_with("/messages/session/") => {
            positive_path_segment(path, "/messages/session/")
        }
        "chat_message" if path.starts_with("/messages/") => {
            positive_path_segment(path, "/messages/")
        }
        "chat_message" if path.starts_with("/receipts/") => {
            positive_path_segment(path, "/receipts/")
        }
        "chat_conversation" if path.starts_with("/sessions/") => {
            positive_path_segment(path, "/sessions/")
        }
        "chat_conversation" if path.starts_with("/groups/") => {
            positive_path_segment(path, "/groups/")
        }
        "chat_conversation" if path.starts_with("/ws/") => positive_path_segment(path, "/ws/"),
        "identity_users" | "user" if path.starts_with("/cards/") => {
            positive_path_segment(path, "/cards/")
        }
        "identity_users" | "user" if path.starts_with("/users/") => {
            positive_path_segment(path, "/users/")
        }
        "organization" if path.starts_with("/orgs/") => positive_path_segment(path, "/orgs/"),
        "platform_tenant" if path.starts_with("/tenants/") => {
            positive_path_segment(path, "/tenants/")
        }
        "org_authority_edge" if path.starts_with("/org-authority-edges/roots/") => {
            positive_path_segment(path, "/org-authority-edges/roots/")
        }
        "org_unit_card" if path.starts_with("/org-unit-cards/") => {
            positive_path_segment(path, "/org-unit-cards/")
        }
        "permission_request" if path.starts_with("/permission-requests/org-scopes/") => {
            positive_path_segment(path, "/permission-requests/org-scopes/")
        }
        "permission_request" if path.starts_with("/permission-requests/") => {
            positive_path_segment(path, "/permission-requests/")
        }
        "permission_rule" if path.starts_with("/permission-rules/card/") => {
            positive_path_segment(path, "/permission-rules/card/")
        }
        "permission_rule" if path.starts_with("/permission-rules/") => {
            positive_path_segment(path, "/permission-rules/")
        }
        "permission_rule" if path.starts_with("/rule-sets/card/") => {
            positive_path_segment(path, "/rule-sets/card/")
        }
        "permission_rule" if path.starts_with("/rule-sets/") => {
            positive_path_segment(path, "/rule-sets/")
        }
        "permission_rule" if path.starts_with("/delegations/") => {
            positive_path_segment(path, "/delegations/")
        }
        "permission_rule" if path.starts_with("/level-templates/") => {
            positive_path_segment(path, "/level-templates/")
        }
        "permission_rule" if path.starts_with("/sod-policies/") => {
            positive_path_segment(path, "/sod-policies/")
        }
        "audit" if path.starts_with("/audit/") => positive_path_segment(path, "/audit/"),
        "platform_dept" if path.starts_with("/departments/") => {
            positive_path_segment(path, "/departments/")
        }
        "domain" if path.starts_with("/user-cards/") => positive_path_segment(path, "/user-cards/"),
        "domain" if path.starts_with("/card-templates/") => {
            positive_path_segment(path, "/card-templates/")
        }
        "domain" if path.starts_with("/user-levels/") => {
            positive_path_segment(path, "/user-levels/")
        }
        "domain" if path.starts_with("/user-gradings/") => {
            positive_path_segment(path, "/user-gradings/")
        }
        "domain" if path.starts_with("/domains/") => positive_path_segment(path, "/domains/"),
        _ => None,
    }
}

fn positive_path_segment(path: &str, prefix: &str) -> Option<i64> {
    path.strip_prefix(prefix)
        .and_then(|value| value.split('/').next())
        .and_then(|segment| segment.parse::<i64>().ok())
        .filter(|value| *value > 0)
}

fn query_target_is_declared(resource: &str, path: &str, method: &str) -> bool {
    matches!(
        (resource, path, method),
        ("permission_rule", "/permission-rules/check", "GET")
    )
}

fn resolved_target_id(
    resource: &str,
    path: &str,
    method: &str,
    query_target_id: Option<i64>,
) -> Result<Option<i64>, &'static str> {
    let path_target_id = path_target_id(resource, path);
    match (path_target_id, query_target_id) {
        (Some(path_target_id), Some(query_target_id)) if path_target_id != query_target_id => {
            Err("resource_ownership.path_query_target_mismatch")
        }
        (Some(path_target_id), _) => Ok(Some(path_target_id)),
        (None, Some(query_target_id)) if query_target_is_declared(resource, path, method) => {
            Ok(Some(query_target_id))
        }
        (None, Some(_)) => Err("resource_ownership.query_target_not_declared"),
        (None, None) => Ok(None),
    }
}

async fn resolve_actor_unit_card(
    pool: &MySqlPool,
    card_id: i64,
    actor_user_id: i64,
) -> Result<(i64, Option<i64>), ResolverLookupError> {
    let (tenant_id, domain_id, owner_id) = resolve_user_card(pool, card_id).await?;
    actor_unit_card_facts(tenant_id, domain_id, owner_id, actor_user_id)
}

fn actor_unit_card_facts(
    tenant_id: i64,
    domain_id: Option<i64>,
    owner_id: Option<i64>,
    actor_user_id: i64,
) -> Result<(i64, Option<i64>), ResolverLookupError> {
    if actor_user_id <= 0 {
        return Err(ResolverLookupError::Unresolved(
            "resource_ownership.actor_user_invalid",
        ));
    }
    if owner_id != Some(actor_user_id) {
        return Err(ResolverLookupError::Unresolved(
            "resource_ownership.actor_card_owner_mismatch",
        ));
    }
    Ok((tenant_id, domain_id))
}

async fn resolve_user_card(
    pool: &MySqlPool,
    card_id: i64,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    let row: Option<(Option<i64>, Option<i64>, Option<i64>)> =
        sqlx::query_as("SELECT tenant_id, domain_id, user_id FROM user_card WHERE card_id = ?")
            .bind(card_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| {
                ResolverLookupError::Unavailable("resource_ownership.user_card_lookup_failed")
            })?;
    row.ok_or(ResolverLookupError::Unresolved(
        "resource_ownership.user_card_not_found",
    ))
    .and_then(|(tenant_id, domain_id, owner_id)| {
        let tenant_id = tenant_id.ok_or(ResolverLookupError::Unresolved(
            "resource_ownership.user_card_tenant_missing",
        ))?;
        Ok((tenant_id, domain_id, owner_id))
    })
}

async fn resolve_delegation(
    pool: &MySqlPool,
    delegation_id: i64,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    let row: Option<DelegationScopeRow> = sqlx::query_as(
        "SELECT delegator_card.tenant_id, delegator_card.domain_id, delegator_card.user_id, \
                    delegate_card.tenant_id, delegate_card.domain_id \
             FROM permission_delegation pd \
             INNER JOIN user_card delegator_card ON delegator_card.card_id = pd.delegator_card_id \
             INNER JOIN user_card delegate_card ON delegate_card.card_id = pd.delegate_card_id \
             WHERE pd.delegation_id = ?",
    )
    .bind(delegation_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| ResolverLookupError::Unavailable("resource_ownership.delegation_lookup_failed"))?;
    let (
        delegator_tenant_id,
        delegator_domain_id,
        delegator_owner_id,
        delegate_tenant_id,
        delegate_domain_id,
    ) = row.ok_or(ResolverLookupError::Unresolved(
        "resource_ownership.delegation_not_found_or_scope_missing",
    ))?;
    delegation_scope_facts(
        delegator_tenant_id,
        delegator_domain_id,
        delegator_owner_id,
        delegate_tenant_id,
        delegate_domain_id,
    )
}

/// A delegation is administratively owned by its delegator. Both cards must
/// nevertheless prove the same tenant/domain scope before the target can be
/// classified; a stale cross-scope row is not a partial ownership fact.
fn delegation_scope_facts(
    delegator_tenant_id: Option<i64>,
    delegator_domain_id: Option<i64>,
    delegator_owner_id: Option<i64>,
    delegate_tenant_id: Option<i64>,
    delegate_domain_id: Option<i64>,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    let (
        delegator_tenant_id,
        delegator_domain_id,
        delegator_owner_id,
        delegate_tenant_id,
        delegate_domain_id,
    ) = (
        delegator_tenant_id.ok_or(ResolverLookupError::Unresolved(
            "resource_ownership.delegation_delegator_tenant_missing",
        ))?,
        delegator_domain_id.ok_or(ResolverLookupError::Unresolved(
            "resource_ownership.delegation_delegator_domain_missing",
        ))?,
        delegator_owner_id.ok_or(ResolverLookupError::Unresolved(
            "resource_ownership.delegation_delegator_owner_missing",
        ))?,
        delegate_tenant_id.ok_or(ResolverLookupError::Unresolved(
            "resource_ownership.delegation_delegate_tenant_missing",
        ))?,
        delegate_domain_id.ok_or(ResolverLookupError::Unresolved(
            "resource_ownership.delegation_delegate_domain_missing",
        ))?,
    );
    if delegator_tenant_id <= 0
        || delegator_domain_id <= 0
        || delegator_owner_id <= 0
        || delegate_tenant_id <= 0
        || delegate_domain_id <= 0
    {
        return Err(ResolverLookupError::Unresolved(
            "resource_ownership.delegation_scope_invalid",
        ));
    }
    if delegator_tenant_id != delegate_tenant_id || delegator_domain_id != delegate_domain_id {
        return Err(ResolverLookupError::Unresolved(
            "resource_ownership.delegation_endpoint_scope_mismatch",
        ));
    }
    Ok((
        delegator_tenant_id,
        Some(delegator_domain_id),
        Some(delegator_owner_id),
    ))
}

async fn resolve_level_template(
    pool: &MySqlPool,
    template_id: i64,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    let row: Option<(Option<i64>,)> =
        sqlx::query_as("SELECT domain_id FROM identity_level_template WHERE template_id = ?")
            .bind(template_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| {
                ResolverLookupError::Unavailable("resource_ownership.level_template_lookup_failed")
            })?;
    let (domain_id,) = row.ok_or(ResolverLookupError::Unresolved(
        "resource_ownership.level_template_not_found",
    ))?;
    let domain_id = domain_id.ok_or(ResolverLookupError::Unresolved(
        "resource_ownership.level_template_domain_missing",
    ))?;
    resolve_single_tenant_domain(pool, domain_id, None).await
}

/// Resolve a tenant-owned object. A tenant is its own authoritative target even
/// when it has zero or multiple active domains: those cardinalities mean the
/// object is tenant-wide, not that its tenant owner is ambiguous. Only a single
/// active mapping supplies an optional target-domain fact.
async fn resolve_tenant(
    pool: &MySqlPool,
    target_id: i64,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    resolve_tenant_row(pool, target_id, "resource_ownership.tenant_not_found").await
}

/// Identity's `/orgs/{id}` adapter exposes a subset of `tenant` rows whose
/// `tenant_type` is `ENTERPRISE`. The primary key is therefore a tenant target,
/// but the resolver verifies that the requested row remains in that subset so an
/// organization route cannot be used to classify another tenant type.
async fn resolve_enterprise_organization(
    pool: &MySqlPool,
    target_id: i64,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    let row: Option<(i64, i64, Option<i64>)> = sqlx::query_as(
        "SELECT t.tenant_id, COUNT(DISTINCT m.domain_id), \
                CASE WHEN COUNT(DISTINCT m.domain_id) = 1 THEN MIN(m.domain_id) ELSE NULL END \
         FROM tenant t \
         LEFT JOIN tenant_domain_map m \
           ON m.tenant_id = t.tenant_id AND m.status = 'ACTIVE' \
         WHERE t.tenant_id = ? AND t.tenant_type = 'ENTERPRISE' \
         GROUP BY t.tenant_id",
    )
    .bind(target_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| {
        ResolverLookupError::Unavailable("resource_ownership.organization_lookup_failed")
    })?;
    let (tenant_id, active_domain_count, only_domain_id) = row.ok_or(
        ResolverLookupError::Unresolved("resource_ownership.organization_not_found"),
    )?;
    tenant_scope_facts(tenant_id, active_domain_count, only_domain_id)
}

async fn resolve_tenant_row(
    pool: &MySqlPool,
    target_id: i64,
    not_found_code: &'static str,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    let row: Option<(i64, i64, Option<i64>)> = sqlx::query_as(
        "SELECT t.tenant_id, COUNT(DISTINCT m.domain_id), \
                CASE WHEN COUNT(DISTINCT m.domain_id) = 1 THEN MIN(m.domain_id) ELSE NULL END \
         FROM tenant t \
         LEFT JOIN tenant_domain_map m \
           ON m.tenant_id = t.tenant_id AND m.status = 'ACTIVE' \
         WHERE t.tenant_id = ? \
         GROUP BY t.tenant_id",
    )
    .bind(target_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| ResolverLookupError::Unavailable("resource_ownership.tenant_lookup_failed"))?;
    let (tenant_id, active_domain_count, only_domain_id) =
        row.ok_or(ResolverLookupError::Unresolved(not_found_code))?;
    tenant_scope_facts(tenant_id, active_domain_count, only_domain_id)
}

fn tenant_scope_facts(
    tenant_id: i64,
    active_domain_count: i64,
    only_domain_id: Option<i64>,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    if tenant_id <= 0 {
        return Err(ResolverLookupError::Unresolved(
            "resource_ownership.tenant_id_invalid",
        ));
    }
    match active_domain_count {
        0 => Ok((tenant_id, None, None)),
        1 => {
            let domain_id = only_domain_id.ok_or(ResolverLookupError::Unresolved(
                "resource_ownership.tenant_single_domain_missing",
            ))?;
            if domain_id <= 0 {
                return Err(ResolverLookupError::Unresolved(
                    "resource_ownership.tenant_single_domain_invalid",
                ));
            }
            Ok((tenant_id, Some(domain_id), None))
        }
        count if count > 1 => Ok((tenant_id, None, None)),
        _ => Err(ResolverLookupError::Unresolved(
            "resource_ownership.tenant_domain_count_invalid",
        )),
    }
}

async fn resolve_user(
    pool: &MySqlPool,
    user_id: i64,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    let rows: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT tenant_id, domain_id FROM user_card \
         WHERE user_id = ? AND tenant_id IS NOT NULL AND domain_id IS NOT NULL \
         GROUP BY tenant_id, domain_id LIMIT 2",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(|_| ResolverLookupError::Unavailable("resource_ownership.user_scope_lookup_failed"))?;
    match rows.as_slice() {
        [(tenant_id, domain_id)] => Ok((*tenant_id, Some(*domain_id), Some(user_id))),
        [] => Err(ResolverLookupError::Unresolved(
            "resource_ownership.user_scope_missing",
        )),
        _ => Err(ResolverLookupError::Unresolved(
            "resource_ownership.user_scope_ambiguous",
        )),
    }
}

async fn resolve_org_membership(
    pool: &MySqlPool,
    membership_id: &str,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT tenant_id, user_id FROM org_scope_membership WHERE membership_id = ?",
    )
    .bind(membership_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| {
        ResolverLookupError::Unavailable("resource_ownership.org_membership_lookup_failed")
    })?;
    let (tenant_id, user_id) = row.ok_or(ResolverLookupError::Unresolved(
        "resource_ownership.org_membership_not_found",
    ))?;
    let (tenant_id, domain_id, _) = resolve_tenant(pool, tenant_id).await?;
    Ok((tenant_id, domain_id, Some(user_id)))
}

async fn resolve_org_scope_request(
    pool: &MySqlPool,
    request_id: i64,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT target_tenant_id, requester_user_id FROM org_scope_request WHERE request_id = ?",
    )
    .bind(request_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| {
        ResolverLookupError::Unavailable("resource_ownership.org_request_lookup_failed")
    })?;
    let (tenant_id, requester_user_id) = row.ok_or(ResolverLookupError::Unresolved(
        "resource_ownership.org_request_not_found",
    ))?;
    let (tenant_id, domain_id, _) = resolve_tenant(pool, tenant_id).await?;
    Ok((tenant_id, domain_id, Some(requester_user_id)))
}

async fn resolve_permission_rule(
    pool: &MySqlPool,
    rule_id: i64,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    let row: Option<(Option<i64>, Option<i64>, Option<i64>)> = sqlx::query_as(
        "SELECT pr.tenant_id, uc.domain_id, uc.user_id \
         FROM permission_rule pr \
         INNER JOIN user_card uc ON uc.card_id = pr.card_id \
         WHERE pr.rule_id = ? AND pr.tenant_id = uc.tenant_id",
    )
    .bind(rule_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| {
        ResolverLookupError::Unavailable("resource_ownership.permission_rule_lookup_failed")
    })?;
    row.ok_or(ResolverLookupError::Unresolved(
        "resource_ownership.permission_rule_not_found",
    ))
    .and_then(|(tenant_id, domain_id, owner_id)| {
        let tenant_id = tenant_id.ok_or(ResolverLookupError::Unresolved(
            "resource_ownership.permission_rule_tenant_missing",
        ))?;
        Ok((tenant_id, domain_id, owner_id))
    })
}

async fn resolve_rule_set(
    pool: &MySqlPool,
    rule_set_id: i64,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    let row: Option<(Option<i64>,)> =
        sqlx::query_as("SELECT tenant_id FROM rule_set WHERE rule_set_id = ?")
            .bind(rule_set_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| {
                ResolverLookupError::Unavailable("resource_ownership.rule_set_lookup_failed")
            })?;
    let tenant_id =
        row.and_then(|(tenant_id,)| tenant_id)
            .ok_or(ResolverLookupError::Unresolved(
                "resource_ownership.rule_set_tenant_missing",
            ))?;
    Ok((tenant_id, None, None))
}

async fn resolve_permission_request(
    pool: &MySqlPool,
    request_id: i64,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    let rows: Vec<(i64, i64, i64)> = sqlx::query_as(
        "SELECT pr.user_id, uc.tenant_id, uc.domain_id \
         FROM permission_request pr \
         INNER JOIN user_card uc ON uc.user_id = pr.user_id \
         WHERE pr.request_id = ? AND uc.tenant_id IS NOT NULL AND uc.domain_id IS NOT NULL \
         GROUP BY pr.user_id, uc.tenant_id, uc.domain_id LIMIT 2",
    )
    .bind(request_id)
    .fetch_all(pool)
    .await
    .map_err(|_| {
        ResolverLookupError::Unavailable("resource_ownership.permission_request_lookup_failed")
    })?;
    match rows.as_slice() {
        [(owner_id, tenant_id, domain_id)] => Ok((*tenant_id, Some(*domain_id), Some(*owner_id))),
        [] => Err(ResolverLookupError::Unresolved(
            "resource_ownership.permission_request_scope_missing",
        )),
        _ => Err(ResolverLookupError::Unresolved(
            "resource_ownership.permission_request_scope_ambiguous",
        )),
    }
}

async fn resolve_audit_record(
    pool: &MySqlPool,
    audit_id: i64,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    let row: Option<(Option<i64>, Option<i64>, Option<i64>)> =
        sqlx::query_as("SELECT tenant_id, domain_id, user_id FROM audit_log WHERE id = ?")
            .bind(audit_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| {
                ResolverLookupError::Unavailable("resource_ownership.audit_lookup_failed")
            })?;
    row.ok_or(ResolverLookupError::Unresolved(
        "resource_ownership.audit_not_found",
    ))
    .and_then(|(tenant_id, domain_id, owner_id)| {
        let tenant_id = tenant_id.ok_or(ResolverLookupError::Unresolved(
            "resource_ownership.audit_tenant_missing",
        ))?;
        Ok((tenant_id, domain_id, owner_id))
    })
}

async fn resolve_chat_conversation(
    pool: &MySqlPool,
    conversation_id: i64,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    resolve_chat_conversation_inner(pool, conversation_id, true).await
}

async fn resolve_chat_conversation_without_owner(
    pool: &MySqlPool,
    conversation_id: i64,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    resolve_chat_conversation_inner(pool, conversation_id, false).await
}

async fn resolve_chat_conversation_inner(
    pool: &MySqlPool,
    conversation_id: i64,
    include_owner: bool,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    let row: Option<(i64, i64, Option<i64>)> = sqlx::query_as(
        "SELECT scoped.tenant_id, c.domain_id, c.owner_id \
         FROM chat_conversation c \
         INNER JOIN ( \
             SELECT domain_id, MIN(tenant_id) AS tenant_id \
             FROM tenant_domain_map WHERE status = 'ACTIVE' \
             GROUP BY domain_id HAVING COUNT(DISTINCT tenant_id) = 1 \
         ) scoped ON scoped.domain_id = c.domain_id \
         WHERE c.id = ? AND c.is_deleted = 0",
    )
    .bind(conversation_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| {
        ResolverLookupError::Unavailable("resource_ownership.chat_conversation_lookup_failed")
    })?;
    row.map(|(tenant_id, domain_id, owner_id)| {
        (
            tenant_id,
            Some(domain_id),
            include_owner.then_some(owner_id).flatten(),
        )
    })
    .ok_or(ResolverLookupError::Unresolved(
        "resource_ownership.chat_conversation_scope_missing_or_ambiguous",
    ))
}

async fn resolve_chat_message(
    pool: &MySqlPool,
    message_id: i64,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    let row: Option<(i64, i64, Option<i64>)> = sqlx::query_as(
        "SELECT scoped.tenant_id, c.domain_id, msg.sender_id \
         FROM chat_message msg \
         INNER JOIN chat_conversation c ON c.id = msg.conversation_id \
         INNER JOIN ( \
             SELECT domain_id, MIN(tenant_id) AS tenant_id \
             FROM tenant_domain_map WHERE status = 'ACTIVE' \
             GROUP BY domain_id HAVING COUNT(DISTINCT tenant_id) = 1 \
         ) scoped ON scoped.domain_id = c.domain_id \
         WHERE msg.id = ? AND c.is_deleted = 0",
    )
    .bind(message_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| {
        ResolverLookupError::Unavailable("resource_ownership.chat_message_lookup_failed")
    })?;
    row.map(|(tenant_id, domain_id, owner_id)| (tenant_id, Some(domain_id), owner_id))
        .ok_or(ResolverLookupError::Unresolved(
            "resource_ownership.chat_message_scope_missing_or_ambiguous",
        ))
}

async fn resolve_card_template(
    pool: &MySqlPool,
    template_id: i64,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    let row: Option<(Option<i64>, Option<i64>)> =
        sqlx::query_as("SELECT tenant_id, domain_id FROM user_card_template WHERE template_id = ?")
            .bind(template_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| {
                ResolverLookupError::Unavailable("resource_ownership.card_template_lookup_failed")
            })?;
    let (tenant_id, domain_id) = row.ok_or(ResolverLookupError::Unresolved(
        "resource_ownership.card_template_not_found",
    ))?;
    let tenant_id = tenant_id.ok_or(ResolverLookupError::Unresolved(
        "resource_ownership.card_template_tenant_missing",
    ))?;
    Ok((tenant_id, domain_id, None))
}

async fn resolve_user_level(
    pool: &MySqlPool,
    level_id: i64,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    let row: Option<(Option<i64>,)> =
        sqlx::query_as("SELECT domain_id FROM user_card_level_definition WHERE level_id = ?")
            .bind(level_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| {
                ResolverLookupError::Unavailable("resource_ownership.user_level_lookup_failed")
            })?;
    let (domain_id,) = row.ok_or(ResolverLookupError::Unresolved(
        "resource_ownership.user_level_not_found",
    ))?;
    let domain_id = domain_id.ok_or(ResolverLookupError::Unresolved(
        "resource_ownership.user_level_domain_missing",
    ))?;
    resolve_single_tenant_domain(pool, domain_id, None).await
}

async fn resolve_user_grading(
    pool: &MySqlPool,
    grading_id: i64,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    let row: Option<(Option<i64>, Option<i64>)> =
        sqlx::query_as("SELECT domain_id, user_id FROM identity_user_grading WHERE id = ?")
            .bind(grading_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| {
                ResolverLookupError::Unavailable("resource_ownership.user_grading_lookup_failed")
            })?;
    let (domain_id, owner_id) = row.ok_or(ResolverLookupError::Unresolved(
        "resource_ownership.user_grading_not_found",
    ))?;
    let domain_id = domain_id.ok_or(ResolverLookupError::Unresolved(
        "resource_ownership.user_grading_domain_missing",
    ))?;
    let owner_id = owner_id.ok_or(ResolverLookupError::Unresolved(
        "resource_ownership.user_grading_owner_missing",
    ))?;
    resolve_single_tenant_domain(pool, domain_id, Some(owner_id)).await
}

async fn resolve_single_tenant_domain(
    pool: &MySqlPool,
    domain_id: i64,
    owner_id: Option<i64>,
) -> Result<(i64, Option<i64>, Option<i64>), ResolverLookupError> {
    let rows: Vec<(i64,)> = sqlx::query_as(
        "SELECT tenant_id FROM tenant_domain_map \
         WHERE domain_id = ? AND status = 'ACTIVE' \
         GROUP BY tenant_id LIMIT 2",
    )
    .bind(domain_id)
    .fetch_all(pool)
    .await
    .map_err(|_| {
        ResolverLookupError::Unavailable("resource_ownership.domain_tenant_lookup_failed")
    })?;
    match rows.as_slice() {
        [(tenant_id,)] => Ok((*tenant_id, Some(domain_id), owner_id)),
        [] => Err(ResolverLookupError::Unresolved(
            "resource_ownership.domain_tenant_scope_missing",
        )),
        _ => Err(ResolverLookupError::Unresolved(
            "resource_ownership.domain_tenant_scope_ambiguous",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::{GlobalAccessRequirement, PolicyContext};

    #[test]
    fn path_target_is_authoritative_over_matching_query_target() {
        assert_eq!(
            resolved_target_id("permission_rule", "/permission-rules/7", "GET", Some(7)),
            Ok(Some(7))
        );
        assert_eq!(
            resolved_target_id("permission_rule", "/permission-rules/7", "GET", Some(8)),
            Err("resource_ownership.path_query_target_mismatch")
        );
    }

    #[test]
    fn query_target_requires_declared_get_route() {
        assert_eq!(
            resolved_target_id("permission_rule", "/permission-rules/check", "GET", Some(7)),
            Ok(Some(7))
        );
        assert_eq!(
            resolved_target_id(
                "permission_rule",
                "/permission-rules/check",
                "POST",
                Some(7)
            ),
            Err("resource_ownership.query_target_not_declared")
        );
        assert_eq!(
            resolved_target_id("permission_rule", "/permission-rules", "POST", Some(7)),
            Err("resource_ownership.query_target_not_declared")
        );
    }

    #[test]
    fn unknown_numeric_segments_are_not_targets() {
        assert_eq!(
            resolved_target_id("learn_level", "/levels/5/play", "GET", None),
            Ok(None)
        );
        assert_eq!(
            resolved_target_id("unknown", "/not-a-route/5", "GET", None),
            Ok(None)
        );
    }

    #[test]
    fn actor_unit_routes_require_the_declared_post_method() {
        assert!(is_actor_unit_route(
            "org_authority_edge",
            "/org-authority-edges/attach",
            "POST"
        ));
        assert!(!is_actor_unit_route(
            "org_authority_edge",
            "/org-authority-edges/attach",
            "GET"
        ));
        assert!(is_actor_unit_route(
            "permission_rule",
            "/delegations",
            "POST"
        ));
        assert!(is_actor_unit_route(
            "permission_rule",
            "/delegations/by-delegator",
            "GET"
        ));
        assert!(is_actor_unit_route(
            "permission_rule",
            "/permission-rules",
            "GET"
        ));
        assert!(is_actor_unit_route(
            "permission_rule",
            "/permission-rules",
            "POST"
        ));
        assert!(!is_actor_unit_route(
            "permission_request",
            "/permission-requests",
            "POST"
        ));
        assert!(!is_actor_unit_route(
            "permission_request",
            "/permission-requests/mine",
            "GET"
        ));
        assert!(!is_actor_unit_route(
            "platform_tenant",
            "/tenants/mine",
            "GET"
        ));
        assert!(!is_actor_unit_route("identity_users", "/cards", "GET"));
        assert!(!is_actor_unit_route("identity_users", "/cards", "POST"));
        assert!(!is_actor_unit_route(
            "identity_users",
            "/mfa/enable",
            "POST"
        ));
        assert!(!is_actor_unit_route("identity_users", "/users", "GET"));
        assert!(is_actor_unit_route("chat_conversation", "/groups", "POST"));
        assert!(is_actor_unit_route("chat_conversation", "/sessions", "GET"));
        assert!(!is_actor_unit_route("chat_message", "/messages", "POST"));
        assert!(!is_actor_unit_route(
            "permission_rule",
            "/delegations/7",
            "PUT"
        ));
    }

    #[test]
    fn actor_unit_route_precedes_query_target_classification() {
        assert_eq!(
            resolved_target_id(
                "permission_rule",
                "/delegations/by-delegator",
                "GET",
                Some(7)
            ),
            Err("resource_ownership.query_target_not_declared")
        );
        assert!(is_actor_unit_route(
            "permission_rule",
            "/delegations/by-delegator",
            "GET"
        ));
    }

    #[test]
    fn actor_unit_card_facts_require_matching_signed_actor() {
        assert_eq!(
            actor_unit_card_facts(7, Some(8), Some(9), 9),
            Ok((7, Some(8)))
        );
        assert_eq!(
            actor_unit_card_facts(7, Some(8), Some(10), 9),
            Err(ResolverLookupError::Unresolved(
                "resource_ownership.actor_card_owner_mismatch"
            ))
        );
        assert_eq!(
            actor_unit_card_facts(7, Some(8), Some(9), 0),
            Err(ResolverLookupError::Unresolved(
                "resource_ownership.actor_user_invalid"
            ))
        );
    }

    #[test]
    fn global_route_access_contracts_are_exact() {
        assert_eq!(
            global_access_requirement("permission_rule", "/rule-sets", "GET", None),
            Some(GlobalAccessRequirement::ActiveGlobalAdmin)
        );
        assert_eq!(
            global_access_requirement(
                "permission_request",
                "/permission-requests/pending",
                "GET",
                None
            ),
            Some(GlobalAccessRequirement::ActiveGlobalAdmin)
        );
        assert_eq!(
            global_access_requirement("permission_rule", "/level-templates/precheck", "POST", None),
            Some(GlobalAccessRequirement::ActiveGlobalAdmin)
        );
        assert_eq!(
            global_access_requirement("domain", "/user-levels", "POST", None),
            Some(GlobalAccessRequirement::ActiveGlobalAdmin)
        );
        assert_eq!(
            global_access_requirement("permission_rule", "/permission-rules/check", "GET", None),
            Some(GlobalAccessRequirement::PolicyEvidence)
        );
        assert_eq!(
            global_access_requirement(
                "permission_rule",
                "/permission-rules/validate",
                "POST",
                None
            ),
            Some(GlobalAccessRequirement::PolicyEvidence)
        );
        assert_eq!(
            global_access_requirement("platform_tenant", "/tenants", "GET", None),
            Some(GlobalAccessRequirement::ActiveGlobalAdmin)
        );
        assert_eq!(
            global_access_requirement("identity_users", "/users", "POST", None),
            Some(GlobalAccessRequirement::ActiveGlobalAdmin)
        );
        assert_eq!(
            global_access_requirement("identity_users", "/admin/stats", "GET", None),
            Some(GlobalAccessRequirement::ActiveGlobalAdmin)
        );
        assert_eq!(
            global_access_requirement("organization", "/orgs", "GET", None),
            Some(GlobalAccessRequirement::ActiveGlobalAdmin)
        );
        assert_eq!(
            global_access_requirement("monitor", "/alerts-summary", "GET", None),
            Some(GlobalAccessRequirement::ActiveGlobalAdmin)
        );
        assert_eq!(
            global_access_requirement(
                "permission_request",
                "/permission-requests/mine",
                "GET",
                None
            ),
            Some(GlobalAccessRequirement::PolicyEvidence)
        );
        assert_eq!(
            global_access_requirement("platform_tenant", "/tenants/mine", "GET", None),
            Some(GlobalAccessRequirement::PolicyEvidence)
        );
        assert_eq!(
            global_access_requirement("identity_users", "/cards", "POST", None),
            Some(GlobalAccessRequirement::PolicyEvidence)
        );
        assert_eq!(
            global_access_requirement("identity_users", "/mfa/enable", "POST", None),
            Some(GlobalAccessRequirement::PolicyEvidence)
        );
        assert_eq!(
            global_access_requirement("domain", "/user-levels", "GET", None),
            None
        );
    }

    #[test]
    fn target_routes_and_control_plane_routes_have_distinct_contracts() {
        assert_eq!(
            global_access_requirement("domain", "/domains/7", "GET", Some(7)),
            Some(GlobalAccessRequirement::ActiveGlobalAdmin)
        );
        assert_eq!(
            global_access_requirement("domain", "/user-levels/7", "GET", Some(7)),
            None
        );
        assert_eq!(
            global_access_requirement("domain", "/user-levels", "GET", None),
            None
        );
        assert_eq!(
            global_access_requirement("domain", "/user-gradings/7", "GET", Some(7)),
            None
        );
        assert_eq!(
            global_access_requirement("permission_rule", "/sod-policies/7", "GET", Some(7)),
            Some(GlobalAccessRequirement::ActiveGlobalAdmin)
        );
        assert_eq!(
            global_access_requirement("permission_rule", "/sod-policies", "POST", None),
            Some(GlobalAccessRequirement::ActiveGlobalAdmin)
        );
    }

    #[test]
    fn path_target_routes_identify_only_their_declared_objects() {
        assert_eq!(path_target_id("domain", "/user-levels/7"), Some(7));
        assert_eq!(path_target_id("domain", "/user-gradings/8"), Some(8));
        assert_eq!(path_target_id("domain", "/user-levels"), None);
        assert_eq!(path_target_id("domain", "/user-levels/invalid"), None);
        assert_eq!(path_target_id("platform_dept", "/departments/9"), Some(9));
        assert_eq!(path_target_id("organization", "/orgs/12"), Some(12));
        assert_eq!(path_target_id("organization", "/orgs/12/domains"), Some(12));
        assert_eq!(
            path_target_id("permission_rule", "/delegations/10/revoke"),
            Some(10)
        );
        assert_eq!(
            path_target_id("permission_rule", "/level-templates/11"),
            Some(11)
        );
    }

    #[test]
    fn resolved_or_unmapped_object_paths_do_not_gain_global_contracts() {
        assert_eq!(
            global_access_requirement("monitor", "/alerts-summary", "POST", None),
            None,
            "only the declared dashboard read is global; an undeclared method stays closed"
        );
        assert_eq!(
            global_access_requirement("platform_dept", "/departments/9", "GET", Some(9)),
            None
        );
        assert_eq!(
            global_access_requirement("permission_rule", "/delegations/10", "GET", Some(10)),
            None
        );
        assert_eq!(
            global_access_requirement("permission_rule", "/level-templates/11", "GET", Some(11)),
            None
        );
        assert_eq!(
            global_access_requirement("organization", "/orgs/12", "GET", Some(12)),
            None
        );
    }

    #[test]
    fn delegation_requires_matching_endpoint_scope_and_delegator_owner() {
        assert_eq!(
            delegation_scope_facts(Some(7), Some(8), Some(9), Some(7), Some(8)),
            Ok((7, Some(8), Some(9)))
        );
        assert_eq!(
            delegation_scope_facts(Some(7), Some(8), Some(9), Some(10), Some(8)),
            Err(ResolverLookupError::Unresolved(
                "resource_ownership.delegation_endpoint_scope_mismatch"
            ))
        );
        assert_eq!(
            delegation_scope_facts(Some(7), Some(8), None, Some(7), Some(8)),
            Err(ResolverLookupError::Unresolved(
                "resource_ownership.delegation_delegator_owner_missing"
            ))
        );
    }

    #[test]
    fn applying_tenant_scoped_resolution_replaces_all_target_facts() {
        let mut ctx = PolicyContext::builder()
            .target_id(Some(1))
            .resource_tenant_id(Some(2))
            .resource_domain_id(Some(3))
            .resource_owner_id(Some(4))
            .action("read".to_owned())
            .build();
        ResourceOwnershipResolution::TenantScoped {
            target_id: Some(7),
            tenant_id: 8,
            domain_id: Some(9),
            owner_id: Some(10),
        }
        .apply_to(&mut ctx);
        assert_eq!(
            ctx.resource_ownership_scope,
            ResourceOwnershipScope::TenantScoped
        );
        assert_eq!(ctx.target_id, Some(7));
        assert_eq!(ctx.resource_tenant_id, Some(8));
        assert_eq!(ctx.resource_domain_id, Some(9));
        assert_eq!(ctx.resource_owner_id, Some(10));
    }

    #[test]
    fn applying_unavailable_resolution_clears_target_facts() {
        let mut ctx = PolicyContext::builder()
            .target_id(Some(7))
            .resource_tenant_id(Some(8))
            .resource_domain_id(Some(9))
            .resource_owner_id(Some(10))
            .action("read".to_owned())
            .build();
        ResourceOwnershipResolution::Unavailable {
            code: "resource_ownership.test_unavailable",
        }
        .apply_to(&mut ctx);
        assert_eq!(
            ctx.resource_ownership_scope,
            ResourceOwnershipScope::Unavailable
        );
        assert_eq!(ctx.target_id, None);
        assert_eq!(ctx.resource_tenant_id, None);
        assert_eq!(ctx.resource_domain_id, None);
        assert_eq!(ctx.resource_owner_id, None);
    }

    #[test]
    fn applying_unresolved_resolution_clears_target_facts() {
        let mut ctx = PolicyContext::builder()
            .resource_tenant_id(Some(7))
            .resource_domain_id(Some(8))
            .resource_owner_id(Some(9))
            .action("read".to_owned())
            .build();
        ResourceOwnershipResolution::Unresolved {
            code: "resource_ownership.test",
        }
        .apply_to(&mut ctx);
        assert_eq!(
            ctx.resource_ownership_scope,
            ResourceOwnershipScope::Unresolved
        );
        assert_eq!(ctx.resource_tenant_id, None);
        assert_eq!(ctx.resource_domain_id, None);
        assert_eq!(ctx.resource_owner_id, None);
    }

    #[test]
    fn applying_global_resolution_clears_query_target_and_owner_facts() {
        let mut ctx = PolicyContext::builder()
            .target_id(Some(7))
            .resource_tenant_id(Some(7))
            .resource_owner_id(Some(9))
            .action("read".to_owned())
            .build();
        ResourceOwnershipResolution::Global {
            target_id: None,
            access_requirement: GlobalAccessRequirement::ActiveGlobalAdmin,
        }
        .apply_to(&mut ctx);
        assert_eq!(ctx.resource_ownership_scope, ResourceOwnershipScope::Global);
        assert_eq!(
            ctx.global_access_requirement,
            GlobalAccessRequirement::ActiveGlobalAdmin
        );
        assert_eq!(ctx.target_id, None);
        assert_eq!(ctx.resource_tenant_id, None);
        assert_eq!(ctx.resource_owner_id, None);
    }

    #[test]
    fn tenant_scope_keeps_tenant_wide_targets_unconstrained_by_domain_count() {
        assert_eq!(tenant_scope_facts(7, 0, None), Ok((7, None, None)));
        assert_eq!(tenant_scope_facts(7, 1, Some(8)), Ok((7, Some(8), None)));
        assert_eq!(tenant_scope_facts(7, 2, None), Ok((7, None, None)));
        assert_eq!(
            tenant_scope_facts(7, 1, None),
            Err(ResolverLookupError::Unresolved(
                "resource_ownership.tenant_single_domain_missing"
            ))
        );
        assert_eq!(
            tenant_scope_facts(7, 1, Some(0)),
            Err(ResolverLookupError::Unresolved(
                "resource_ownership.tenant_single_domain_invalid"
            ))
        );
    }

    #[test]
    fn route_contract_preserves_global_target_and_fail_closed_boundaries() {
        assert_eq!(
            route_ownership_contract("identity_users", "/users", "GET", None),
            RouteOwnershipContract::Global {
                target_id: None,
                access_requirement: GlobalAccessRequirement::ActiveGlobalAdmin,
            }
        );
        assert_eq!(
            route_ownership_contract("identity_users", "/users/7", "GET", None),
            RouteOwnershipContract::TenantTarget {
                target_id: 7,
                lookup: TargetLookupKind::User,
            }
        );
        assert_eq!(
            route_ownership_contract("monitor", "/alert-rules/7", "DELETE", None),
            RouteOwnershipContract::Global {
                target_id: None,
                access_requirement: GlobalAccessRequirement::ActiveGlobalAdmin,
            }
        );
        assert_eq!(
            route_ownership_contract("platform_dept", "/departments/7", "PUT", None),
            RouteOwnershipContract::Unresolved {
                code: "resource_ownership.department_tenant_contract_unmapped",
            }
        );
        assert_eq!(
            route_ownership_contract(
                "permission_request",
                "/permission-requests/mine",
                "GET",
                None,
            ),
            RouteOwnershipContract::Global {
                target_id: None,
                access_requirement: GlobalAccessRequirement::PolicyEvidence,
            }
        );
        assert_eq!(
            route_ownership_contract("identity_users", "/cards", "GET", None),
            RouteOwnershipContract::Global {
                target_id: None,
                access_requirement: GlobalAccessRequirement::PolicyEvidence,
            }
        );
        assert_eq!(
            route_ownership_contract("platform_tenant", "/tenants/mine", "GET", None),
            RouteOwnershipContract::Global {
                target_id: None,
                access_requirement: GlobalAccessRequirement::PolicyEvidence,
            }
        );
        assert_eq!(
            route_ownership_contract("identity_users", "/mfa/enable", "POST", None),
            RouteOwnershipContract::Global {
                target_id: None,
                access_requirement: GlobalAccessRequirement::PolicyEvidence,
            }
        );
        assert_eq!(
            route_ownership_contract("chat_message", "/messages", "POST", None),
            RouteOwnershipContract::Unresolved {
                code: "resource_ownership.target_missing",
            }
        );
    }

    #[test]
    fn tenant_scoped_rejects_non_positive_authoritative_values() {
        assert!(matches!(
            tenant_scoped(Some(7), 0, None, None),
            ResourceOwnershipResolution::Unresolved { .. }
        ));
        assert!(matches!(
            tenant_scoped(Some(7), 1, Some(0), None),
            ResourceOwnershipResolution::Unresolved { .. }
        ));
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct DeclaredRouteMethod {
        path: String,
        method: &'static str,
    }

    fn route_call_end(source: &str, open_paren: usize) -> usize {
        let mut depth = 0usize;
        let mut quoted = false;
        let mut escaped = false;
        for (offset, character) in source[open_paren..].char_indices() {
            let index = open_paren + offset;
            if quoted {
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    quoted = false;
                }
                continue;
            }
            match character {
                '"' => quoted = true,
                '(' => depth += 1,
                ')' => {
                    depth = depth
                        .checked_sub(1)
                        .expect("route call nesting must be valid");
                    if depth == 0 {
                        return index;
                    }
                }
                _ => {}
            }
        }
        panic!("route call must have a closing parenthesis");
    }

    fn route_function_source<'a>(source: &'a str, function_name: &str) -> &'a str {
        let marker = format!("fn {function_name}(");
        let function_start = source
            .find(&marker)
            .unwrap_or_else(|| panic!("route function must exist: {function_name}"));
        let body_start = function_start
            + source[function_start..]
                .find('{')
                .expect("route function must open a body");
        let body_end = brace_block_end(source, body_start);
        &source[function_start..=body_end]
    }

    fn brace_block_end(source: &str, open_brace: usize) -> usize {
        let mut depth = 0usize;
        let mut quoted = false;
        let mut escaped = false;
        for (offset, character) in source[open_brace..].char_indices() {
            let index = open_brace + offset;
            if quoted {
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    quoted = false;
                }
                continue;
            }
            match character {
                '"' => quoted = true,
                '{' => depth += 1,
                '}' => {
                    depth = depth
                        .checked_sub(1)
                        .expect("route function braces must be balanced");
                    if depth == 0 {
                        return index;
                    }
                }
                _ => {}
            }
        }
        panic!("route function body must close");
    }

    fn router_merge_calls(source: &str, binding: &str) -> Vec<String> {
        let binding_marker = format!("let {binding} = Router::new()");
        let router = source
            .split(&binding_marker)
            .nth(1)
            .unwrap_or_else(|| panic!("router binding must exist: {binding}"));
        let router = router
            .split(".layer(axum::middleware::from_fn_with_state(")
            .next()
            .expect("protected router must retain its permission layer");
        let mut cursor = 0usize;
        let mut calls = Vec::new();
        while let Some(relative_start) = router[cursor..].find(".merge(") {
            let start = cursor + relative_start;
            let open_paren = start + ".merge".len();
            let end = route_call_end(router, open_paren);
            let call = router[open_paren + 1..end].trim();
            assert!(
                call.starts_with("srv::"),
                "protected router merge must name a service route builder: {call}"
            );
            calls.push(call.to_owned());
            cursor = end + 1;
        }
        calls
    }

    fn assert_router_merge_inventory(source: &str, binding: &str, expected: &[&str]) {
        let actual = router_merge_calls(source, binding);
        let expected = expected
            .iter()
            .map(|call| (*call).to_owned())
            .collect::<Vec<_>>();
        assert_eq!(
            actual, expected,
            "{binding} router merge list changed; update the ownership-contract inventory"
        );
    }

    fn literal_route_methods(source: &str) -> Vec<DeclaredRouteMethod> {
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        let mut cursor = 0usize;
        let mut routes = Vec::new();
        while let Some(relative_start) = production[cursor..].find(".route(") {
            let start = cursor + relative_start;
            let open_paren = start + ".route".len();
            let end = route_call_end(production, open_paren);
            let mut first_argument = open_paren + 1;
            while production
                .as_bytes()
                .get(first_argument)
                .is_some_and(u8::is_ascii_whitespace)
            {
                first_argument += 1;
            }
            if production.as_bytes().get(first_argument) != Some(&b'"') {
                cursor = end + 1;
                continue;
            }
            let path_start = first_argument + 1;
            let path_end = production[path_start..end]
                .find('"')
                .map(|offset| path_start + offset)
                .expect("literal route path must close its quote");
            let path = &production[path_start..path_end];
            let invocation = &production[path_end + 1..end];
            for (needle, method) in [
                ("get(", "GET"),
                ("post(", "POST"),
                ("put(", "PUT"),
                ("patch(", "PATCH"),
                ("delete(", "DELETE"),
                ("head(", "HEAD"),
            ] {
                if invocation.contains(needle) {
                    routes.push(DeclaredRouteMethod {
                        path: path.to_owned(),
                        method,
                    });
                }
            }
            cursor = end + 1;
        }
        routes
    }

    fn path_map_entries<'a>(source: &'a str, anchor: &str) -> Vec<(&'a str, &'a str)> {
        let section = source
            .split(anchor)
            .nth(1)
            .expect("path map anchor must exist")
            .split("];")
            .next()
            .expect("path map must close");
        section
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                let rest = line.strip_prefix("(\"")?;
                let (path, resource) = rest.split_once("\", \"")?;
                let resource = resource.trim_end_matches(',').trim_end();
                let resource = resource.strip_suffix(')')?;
                let resource = resource.strip_suffix('"')?;
                Some((path, resource))
            })
            .collect()
    }

    fn mapped_resource<'a>(entries: &[(&'a str, &'a str)], path: &str) -> Option<&'a str> {
        entries
            .iter()
            .find(|(prefix, _)| {
                path == *prefix
                    || path
                        .strip_prefix(prefix)
                        .is_some_and(|remaining| remaining.starts_with('/'))
            })
            .map(|(_, resource)| *resource)
    }

    fn concrete_path(declared_path: &str) -> String {
        let mut concrete = String::with_capacity(declared_path.len());
        let mut remaining = declared_path;
        while let Some(open) = remaining.find('{') {
            concrete.push_str(&remaining[..open]);
            let close = remaining[open..]
                .find('}')
                .map(|offset| open + offset)
                .expect("route parameter must close");
            concrete.push('7');
            remaining = &remaining[close + 1..];
        }
        concrete.push_str(remaining);
        concrete
    }

    fn is_identity_skip_route(path: &str) -> bool {
        [
            "/sessions",
            "/register",
            "/password/forgot",
            "/password/reset",
            "/verification/send",
            "/verification/verify",
            "/internal/sessions",
            "/me",
            "/providers",
        ]
        .iter()
        .any(|prefix| {
            path == *prefix
                || path
                    .strip_prefix(prefix)
                    .is_some_and(|remaining| remaining.starts_with('/'))
        })
    }

    fn is_identity_pre_resolver_deny(path: &str, method: &str) -> bool {
        matches!(
            (path, method),
            ("/profile", "GET") | ("/profile", "PUT") | ("/change-password", "POST")
        )
    }

    fn intentionally_pre_resolver_route(service: &str, path: &str, method: &str) -> bool {
        (service == "identity" && is_identity_pre_resolver_deny(path, method))
            || matches!(
                (service, path, method),
                ("learn-admin", "/announcements", "GET")
                    | ("learn-admin", "/announcements", "POST")
                    | ("learn-admin", "/announcements/{id}", "GET")
                    | ("learn-admin", "/announcements/{id}", "PUT")
                    | ("learn-admin", "/announcements/{id}", "DELETE")
                    | ("learn-app-users", "/login", "POST")
                    | ("learn-app-users", "/logout", "POST")
            )
    }

    fn intentionally_principal_kind_bypass_route(
        service: &str,
        resource: &str,
        path: &str,
        method: &str,
    ) -> bool {
        matches!(
            (service, resource, path, method),
            ("learn-app-users", "user_profile", "/me", "GET")
                | ("learn-app-users", "user_profile", "/identity", "GET")
                | (
                    "learn-app-users",
                    "user_profile",
                    "/learning-profile",
                    "GET"
                )
        )
    }

    fn intentionally_fail_closed(
        service: &str,
        resource: &str,
        path: &str,
        method: &str,
        code: &str,
    ) -> bool {
        if matches!(service, "learn-admin" | "learn-app")
            && resource.starts_with("learn_")
            && code == "resource_ownership.target_missing"
        {
            return true;
        }
        matches!(
            (service, resource, path, method, code),
            (
                "chat",
                "chat_message",
                "/messages",
                "POST",
                "resource_ownership.target_missing"
            ) | (
                "chat",
                "chat_message",
                "/receipts",
                "POST",
                "resource_ownership.target_missing"
            ) | (
                "trustgraph",
                "permission_request",
                "/permission-requests",
                "POST",
                "resource_ownership.target_missing"
            ) | (
                "trustgraph",
                "platform_tenant",
                "/tenants/invitations/{code}",
                "GET",
                "resource_ownership.target_missing"
            ) | (
                "trustgraph",
                "platform_tenant",
                "/tenants/invitations/{code}/use",
                "POST",
                "resource_ownership.target_missing"
            ) | (
                "trustgraph",
                "platform_dept",
                "/departments",
                "GET",
                "resource_ownership.target_missing"
            ) | (
                "trustgraph",
                "platform_dept",
                "/departments",
                "POST",
                "resource_ownership.target_missing"
            ) | (
                "trustgraph",
                "platform_dept",
                "/departments/{id}",
                "PUT",
                "resource_ownership.department_tenant_contract_unmapped"
            ) | (
                "trustgraph",
                "platform_dept",
                "/departments/{id}",
                "DELETE",
                "resource_ownership.department_tenant_contract_unmapped"
            ) | (
                "trustgraph",
                "domain",
                "/user-cards",
                "GET",
                "resource_ownership.target_missing"
            ) | (
                "trustgraph",
                "domain",
                "/user-cards",
                "POST",
                "resource_ownership.target_missing"
            ) | (
                "trustgraph",
                "domain",
                "/user-levels",
                "GET",
                "resource_ownership.target_missing"
            ) | (
                "trustgraph",
                "domain",
                "/user-gradings",
                "GET",
                "resource_ownership.target_missing"
            )
        )
    }

    fn assert_service_route_contracts(
        service: &str,
        route_sources: &[&str],
        path_map_source: &str,
        path_map_anchor: &str,
    ) -> usize {
        let map = path_map_entries(path_map_source, path_map_anchor);
        assert!(!map.is_empty(), "{service} path map must not be empty");
        let mut count = 0usize;
        for source in route_sources {
            for route in literal_route_methods(source) {
                count += 1;
                if service == "identity" && is_identity_skip_route(&route.path) {
                    continue;
                }
                let Some(resource) = mapped_resource(&map, &route.path) else {
                    assert!(
                        intentionally_pre_resolver_route(service, &route.path, route.method),
                        "protected route lacks a path-map entry or named pre-resolver denial: {service}:{}:{}",
                        route.method,
                        route.path,
                    );
                    continue;
                };
                let principal_kind_bypass = intentionally_principal_kind_bypass_route(
                    service,
                    resource,
                    &route.path,
                    route.method,
                );
                let concrete_path = concrete_path(&route.path);
                match route_ownership_contract(resource, &concrete_path, route.method, None) {
                    RouteOwnershipContract::Unresolved { code } => assert!(
                        intentionally_fail_closed(
                            service,
                            resource,
                            &route.path,
                            route.method,
                            code,
                        ) || (principal_kind_bypass
                            && code == "resource_ownership.target_missing"),
                        "protected route has an unreviewed fail-closed resolver outcome: {service}:{}:{} resource={resource} code={code}",
                        route.method,
                        route.path,
                    ),
                    RouteOwnershipContract::ActorUnit
                    | RouteOwnershipContract::OrgMembership { .. }
                    | RouteOwnershipContract::TenantTarget { .. }
                    | RouteOwnershipContract::Global { .. } => {}
                }
            }
        }
        count
    }

    #[test]
    fn every_protected_router_route_has_a_named_ownership_contract() {
        let identity_middleware = include_str!("../../astral-identity/src/middleware.rs");
        let identity_count = assert_service_route_contracts(
            "identity",
            &[
                include_str!("../../astral-identity/src/api.rs"),
                include_str!("../../astral-identity/src/srv/users.rs"),
                include_str!("../../astral-identity/src/srv/cards.rs"),
                include_str!("../../astral-identity/src/srv/session.rs"),
                include_str!("../../astral-identity/src/srv/password.rs"),
                include_str!("../../astral-identity/src/srv/admin.rs"),
                include_str!("../../astral-identity/src/srv/verification.rs"),
                include_str!("../../astral-identity/src/srv/mfa.rs"),
                include_str!("../../astral-identity/src/srv/orgs.rs"),
                include_str!("../../astral-identity/src/srv/me.rs"),
            ],
            identity_middleware,
            "pub const IDENTITY_PATH_MAP:",
        );
        assert!(
            identity_count >= 45,
            "identity route scan unexpectedly incomplete"
        );

        let trustgraph_middleware =
            include_str!("../../astral-trustgraph/src/api/permission_check.rs");
        let trustgraph_count = assert_service_route_contracts(
            "trustgraph",
            &[
                include_str!("../../astral-trustgraph/src/api/approval.rs"),
                include_str!("../../astral-trustgraph/src/api/arbiter.rs"),
                include_str!("../../astral-trustgraph/src/api/audit.rs"),
                include_str!("../../astral-trustgraph/src/api/audit_replay.rs"),
                include_str!("../../astral-trustgraph/src/api/card_templates.rs"),
                include_str!("../../astral-trustgraph/src/api/consistency_monitor.rs"),
                include_str!("../../astral-trustgraph/src/api/cross_org_grants.rs"),
                include_str!("../../astral-trustgraph/src/api/delegation.rs"),
                include_str!("../../astral-trustgraph/src/api/departments.rs"),
                include_str!("../../astral-trustgraph/src/api/domains.rs"),
                include_str!("../../astral-trustgraph/src/api/global_admin.rs"),
                include_str!("../../astral-trustgraph/src/api/inheritance.rs"),
                include_str!("../../astral-trustgraph/src/api/level_templates.rs"),
                include_str!("../../astral-trustgraph/src/api/org_authorities.rs"),
                include_str!("../../astral-trustgraph/src/api/permission_actions.rs"),
                include_str!("../../astral-trustgraph/src/api/personal_permissions.rs"),
                include_str!("../../astral-trustgraph/src/api/platform_packages.rs"),
                include_str!("../../astral-trustgraph/src/api/resource_types.rs"),
                include_str!("../../astral-trustgraph/src/api/rule_sets.rs"),
                include_str!("../../astral-trustgraph/src/api/rules.rs"),
                include_str!("../../astral-trustgraph/src/api/simulation.rs"),
                include_str!("../../astral-trustgraph/src/api/sod.rs"),
                include_str!("../../astral-trustgraph/src/api/stats.rs"),
                include_str!("../../astral-trustgraph/src/api/templates.rs"),
                include_str!("../../astral-trustgraph/src/api/tenants.rs"),
                include_str!("../../astral-trustgraph/src/api/user_cards.rs"),
                include_str!("../../astral-trustgraph/src/api/user_gradings.rs"),
                include_str!("../../astral-trustgraph/src/api/user_levels.rs"),
            ],
            trustgraph_middleware,
            "pub const TRUSTGRAPH_PATH_RESOURCE_MAP:",
        );
        assert!(
            trustgraph_count >= 150,
            "trustgraph route scan unexpectedly incomplete"
        );

        let monitor_middleware = include_str!("../../astral-monitor/src/middleware.rs");
        let monitor_main = include_str!("../../astral-monitor/src/main.rs");
        let monitor_api_routes = monitor_main
            .split("let api_routes =")
            .nth(1)
            .expect("monitor API router must exist")
            .split(".layer(")
            .next()
            .expect("monitor API router must retain permission layer");
        let monitor_count = assert_service_route_contracts(
            "monitor",
            &[
                include_str!("../../astral-monitor/src/alerts.rs"),
                include_str!("../../astral-monitor/src/notifications.rs"),
                include_str!("../../astral-monitor/src/dashboard.rs"),
                monitor_api_routes,
            ],
            monitor_middleware,
            "pub const MONITOR_PATH_MAP:",
        );
        assert!(
            monitor_count >= 35,
            "monitor route scan unexpectedly incomplete"
        );

        let chat_main = include_str!("../../astral-chat/src/main.rs");
        assert_router_merge_inventory(
            chat_main,
            "api_routes",
            &[
                "srv::messages::message_routes()",
                "srv::sessions::session_routes()",
                "srv::groups::group_routes()",
                "srv::realtime::ws_routes()",
                "srv::receipts::receipt_routes()",
            ],
        );
        let learn_main = include_str!("../../astral-learn/src/main.rs");
        assert_router_merge_inventory(
            learn_main,
            "admin_routes",
            &[
                "srv::subjects::subject_routes()",
                "srv::questions::question_routes()",
                "srv::exams::exam_routes()",
                "srv::courses::course_routes()",
                "srv::enrollments::enrollment_routes()",
                "srv::grades::grade_routes()",
                "srv::publishing::publishing_routes()",
                "srv::assignments::assignment_routes()",
                "srv::discussions::discussion_routes()",
                "srv::classes::class_routes()",
                "srv::submissions::submission_routes()",
                "srv::chapters::chapter_routes()",
                "srv::levels::level_routes()",
                "srv::statistics::statistics_routes()",
                "srv::checkins::checkin_admin_routes()",
                "srv::documents::document_routes()",
                "srv::devices::device_admin_routes()",
                "srv::system_settings::system_setting_routes()",
                "srv::webhook_configs::webhook_config_routes()",
                "srv::wrong_questions::wrong_question_routes()",
                "srv::solutions::solution_routes()",
            ],
        );
        assert_router_merge_inventory(
            learn_main,
            "app_learn_routes",
            &[
                "srv::progress::progress_routes()",
                "srv::levels::level_app_routes()",
                "srv::checkins::checkin_app_routes()",
                "srv::solutions::solution_routes()",
                "srv::wrong_questions::wrong_question_routes()",
                "srv::user_answers::user_answer_routes()",
                "srv::user_subjects::user_subject_routes()",
                "srv::first_attempts::first_attempt_routes()",
                "srv::exams_app::exam_app_routes()",
                "srv::devices::device_app_routes()",
                "srv::subjects::subject_routes()",
                "srv::courses::course_routes()",
            ],
        );
        assert_router_merge_inventory(
            learn_main,
            "app_user_routes",
            &["srv::app_users::app_user_routes()"],
        );

        let chat_middleware = include_str!("../../astral-chat/src/middleware.rs");
        let chat_count = assert_service_route_contracts(
            "chat",
            &[
                route_function_source(
                    include_str!("../../astral-chat/src/srv/messages.rs"),
                    "message_routes",
                ),
                route_function_source(
                    include_str!("../../astral-chat/src/srv/sessions.rs"),
                    "session_routes",
                ),
                route_function_source(
                    include_str!("../../astral-chat/src/srv/groups.rs"),
                    "group_routes",
                ),
                route_function_source(
                    include_str!("../../astral-chat/src/srv/realtime.rs"),
                    "ws_routes",
                ),
                route_function_source(
                    include_str!("../../astral-chat/src/srv/receipts.rs"),
                    "receipt_routes",
                ),
            ],
            chat_middleware,
            "pub const CHAT_PATH_MAP:",
        );
        assert_eq!(chat_count, 22, "review every protected Chat route");

        let learn_middleware = include_str!("../../astral-learn/src/middleware.rs");
        let learn_admin_count = assert_service_route_contracts(
            "learn-admin",
            &[
                route_function_source(
                    include_str!("../../astral-learn/src/srv/subjects.rs"),
                    "subject_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/questions.rs"),
                    "question_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/exams.rs"),
                    "exam_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/courses.rs"),
                    "course_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/enrollments.rs"),
                    "enrollment_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/grades.rs"),
                    "grade_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/publishing.rs"),
                    "publishing_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/assignments.rs"),
                    "assignment_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/discussions.rs"),
                    "discussion_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/classes.rs"),
                    "class_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/submissions.rs"),
                    "submission_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/chapters.rs"),
                    "chapter_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/levels.rs"),
                    "level_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/statistics.rs"),
                    "statistics_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/checkins.rs"),
                    "checkin_admin_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/documents.rs"),
                    "document_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/devices.rs"),
                    "device_admin_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/system_settings.rs"),
                    "system_setting_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/webhook_configs.rs"),
                    "webhook_config_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/wrong_questions.rs"),
                    "wrong_question_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/solutions.rs"),
                    "solution_routes",
                ),
            ],
            learn_middleware,
            "pub const LEARN_PATH_MAP:",
        );
        assert_eq!(
            learn_admin_count, 103,
            "review every protected Learn admin route"
        );

        let learn_app_count = assert_service_route_contracts(
            "learn-app",
            &[
                route_function_source(
                    include_str!("../../astral-learn/src/srv/progress.rs"),
                    "progress_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/levels.rs"),
                    "level_app_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/checkins.rs"),
                    "checkin_app_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/solutions.rs"),
                    "solution_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/wrong_questions.rs"),
                    "wrong_question_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/user_answers.rs"),
                    "user_answer_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/user_subjects.rs"),
                    "user_subject_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/first_attempts.rs"),
                    "first_attempt_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/exams_app.rs"),
                    "exam_app_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/devices.rs"),
                    "device_app_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/subjects.rs"),
                    "subject_routes",
                ),
                route_function_source(
                    include_str!("../../astral-learn/src/srv/courses.rs"),
                    "course_routes",
                ),
            ],
            learn_middleware,
            "pub const LEARN_APP_PATH_MAP:",
        );
        assert_eq!(
            learn_app_count, 40,
            "review every protected Learn app route"
        );

        let learn_app_user_count = assert_service_route_contracts(
            "learn-app-users",
            &[route_function_source(
                include_str!("../../astral-learn/src/srv/app_users.rs"),
                "app_user_routes",
            )],
            learn_middleware,
            "pub const LEARN_APP_USER_PATH_MAP:",
        );
        assert_eq!(
            learn_app_user_count, 5,
            "review every Learn app-user route, including explicit exemptions"
        );

        assert_eq!(
            route_ownership_contract("monitor", "/internal/test-control/worker-id", "GET", None,),
            RouteOwnershipContract::Global {
                target_id: None,
                access_requirement: GlobalAccessRequirement::PolicyEvidence,
            },
            "the default-off test-control route has a separate explicit contract"
        );
    }

    #[test]
    fn every_http_middleware_resolves_target_ownership_before_evaluation() {
        let middleware_sources = [
            (
                "identity",
                include_str!("../../astral-identity/src/middleware.rs"),
            ),
            (
                "trustgraph",
                include_str!("../../astral-trustgraph/src/api/permission_check.rs"),
            ),
            (
                "monitor",
                include_str!("../../astral-monitor/src/middleware.rs"),
            ),
            ("chat", include_str!("../../astral-chat/src/middleware.rs")),
            (
                "learn",
                include_str!("../../astral-learn/src/middleware.rs"),
            ),
        ];
        for (service, source) in middleware_sources {
            let production = source.split("#[cfg(test)]").next().unwrap_or(source);
            assert!(
                production.contains("physical_policy_context("),
                "{service} HTTP middleware must start from verified physical actor facts"
            );
            assert!(
                production.contains("resolve_resource_ownership("),
                "{service} HTTP middleware must resolve server-side target ownership"
            );
            assert!(
                production.contains("resolution.apply_to(&mut ctx)"),
                "{service} HTTP middleware must apply the resolver result before evaluation"
            );
            assert!(
                production.contains(".evaluate(&ctx"),
                "{service} HTTP middleware must send the resolved context to PolicyEngine"
            );
            assert!(
                !production.contains("PolicyContext::builder("),
                "{service} production HTTP middleware must not bypass the resolver with a hand-built context"
            );
        }
    }
}
