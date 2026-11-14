//! memory—v1 §4.11/§4.12/§4.14: Governance routes ①-⑤ declarations and
//! mutation plan types.
//!
//! Route metadata declarations auto-register into the registry (§4.9).
//! The handlers are batch-B implementation stubs: they define the route
//! shape, request types and mutation plan types. The full T2 write-path
//! wiring (restricted write gateway through the composition) is the
//! batch-B implementation completion.

use serde::Deserialize;

use crate::api::permission_check::MemoryV1RouteDeclaration;

/// memory—v1 §4.11: governance route metadata declarations — these are
/// the batch-B governance routes (①-⑤), auto-registered via §4.9.
pub const GOVERNANCE_ROUTE_DECLARATIONS: &[MemoryV1RouteDeclaration] = &[
    MemoryV1RouteDeclaration {
        method: "POST",
        path: "/governance/bindings",
        resource: "binding",
        action: "create",
    },
    MemoryV1RouteDeclaration {
        method: "POST",
        path: "/governance/bindings/confirm",
        resource: "binding",
        action: "confirm",
    },
    MemoryV1RouteDeclaration {
        method: "DELETE",
        path: "/governance/bindings",
        resource: "binding",
        action: "remove",
    },
    MemoryV1RouteDeclaration {
        method: "POST",
        path: "/governance/bindings/revoke-confirmation",
        resource: "binding",
        action: "revoke-confirmation",
    },
    MemoryV1RouteDeclaration {
        method: "POST",
        path: "/governance/rule-sets",
        resource: "rule_set",
        action: "create",
    },
    MemoryV1RouteDeclaration {
        method: "POST",
        path: "/governance/rule-sets/publish",
        resource: "rule_set",
        action: "version-publish",
    },
    MemoryV1RouteDeclaration {
        method: "POST",
        path: "/governance/user-cards/disable",
        resource: "user_card",
        action: "disable",
    },
];

/// memory—v1 §4.12: management mutation plan types for the governance routes.
///
/// Each variant maps to one `RootOwner::execute_mutation` call after the
/// T2 evaluation returns ALLOW. The route handler constructs the plan
/// from the request body and the root facts.
#[derive(Debug)]
pub enum GovernanceMutationPlan {
    BindingCreate {
        binding_id: [u8; 16],
        user_card_id: [u8; 16],
        rule_set_id: [u8; 16],
        layer: String,
        confirmation_id: [u8; 16],
        version_bytes: Vec<u8>,
        confirmer_user_id: [u8; 16],
    },
    BindingConfirm {
        binding_id: [u8; 16],
        rule_set_id: [u8; 16],
        confirmation_id: [u8; 16],
        version_bytes: Vec<u8>,
    },
    BindingRemove {
        binding_id: [u8; 16],
    },
    RevokeConfirmation {
        confirmation_id: [u8; 16],
    },
    RuleSetCreate {
        rule_set_id: [u8; 16],
        owner_tenant_id: [u8; 16],
    },
    VersionPublish {
        rule_set_id: [u8; 16],
        version_bytes: Vec<u8>,
        content_bytes: Vec<u8>,
    },
    UserCardDisable {
        user_card_id: [u8; 16],
    },
}

/// memory—v1 §4.14: audit event emission — structured log with the B-4
/// field set; persistent rows land via C-2 five-piece writing.
pub struct GovernanceAuditEvent<'a> {
    pub operator_user: &'a str,
    pub operator_identity: &'a str,
    pub action: &'a str,
    pub resource: &'a str,
    pub target: &'a str,
    pub approver: &'a str,
    pub operation_id: &'a str,
    pub root_version: u64,
}

pub fn emit_governance_audit(event: &GovernanceAuditEvent<'_>) {
    tracing::info!(
        target = event.target,
        operator_user = event.operator_user,
        operator_identity = event.operator_identity,
        approver = event.approver,
        action = event.action,
        resource = event.resource,
        operation_id = event.operation_id,
        root_version = event.root_version,
        "memory-v1 governance mutation"
    );
}

/// memory—v1 §4.11 B-1.2: governance confirm-type entries must declare
/// `ownerScope: all` — the contract requirement that prevents the
/// strict-default scope from silently blocking all confirm actions.
pub const GOVERNANCE_SCOPE_REQUIREMENT: &str =
    "confirm-type governance entries must declare ownerScope:all (B-1.2 N-1); \
     entries without this are structurally unable to confirm for other users";

// ── Request body types (route inputs) ───────────────────────────────────

#[derive(Deserialize)]
pub struct GovernanceBindingCreateBody {
    pub binding_id: String,
    pub user_card_id: String,
    pub rule_set_id: String,
    pub binding_layer: String,
}

#[derive(Deserialize)]
pub struct GovernanceBindingConfirmBody {
    pub binding_id: String,
    pub rule_set_id: String,
}

#[derive(Deserialize)]
pub struct GovernanceBindingRemoveBody {
    pub binding_id: String,
}

#[derive(Deserialize)]
pub struct GovernanceRevokeConfirmationBody {
    pub confirmation_id: String,
}

#[derive(Deserialize)]
pub struct GovernanceRuleSetCreateBody {
    pub rule_set_id: String,
    pub owner_tenant_id: String,
    pub content: String,
}

#[derive(Deserialize)]
pub struct GovernanceVersionPublishBody {
    pub rule_set_id: String,
    pub content: String,
}

#[derive(Deserialize)]
pub struct GovernanceUserCardDisableBody {
    pub user_card_id: String,
}
