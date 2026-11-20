//! memory—v1 §4.11/§4.12/§4.14: T2 governance routes and restricted root writes.
//!
//! The middleware freezes the bounded body, operation binding and memory-v1
//! admission before these handlers run. Handlers reconstruct a mutation from
//! those values, but return PENDING before execution until the durable audit and
//! operation-reconciliation owner is installed.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use astral_authorization_root::memory_v1_db_rows::{
    BindingConfirmationRow, BindingLayer, BindingRow, RuleSetChangeConfirmationRow, RuleSetRow,
    RuleSetVersionRow, UserCardRow, UserCardStatus,
};
use astral_authorization_root::memory_v1_request::RequestRootExtension;
use astral_authorization_root::memory_v1_root::{
    GovernanceTargetFacts, ManagementMutationV2, RootMetadata, RootStatus,
};
use astral_authorization_root::memory_v1_rules::{
    canonical_version_bytes, version_digest, MemoryV1OwnerScope, MemoryV1TenantScope,
};
use astral_authorization_root::memory_v1_session::RequestSessionExtension;
use astral_common::config::MemoryV1ConfirmationBatchLimit;
use astral_common::contract::ApiResponse;
use astral_common::error::AppError;
use astral_types::memory_v1::MemoryId;
use astral_types::AstralError;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use policy_engine::memory_v1_batch::{MemoryV1BatchAdmission, MemoryV1BatchItem};
use policy_engine::memory_v1_batch_plan::{
    MemoryV1BatchPlan, MemoryV1BatchPlanError, MemoryV1BatchPlanItem, MAX_BATCH_PLAN_SCOPE_BYTES,
};
use policy_engine::memory_v1_formal::{MemoryV1Admission, MemoryV1RuleSetChangeIntent};
use serde::{Deserialize, Serialize};

use crate::api::permission_check::{MemoryV1AdditionalAdmissions, MemoryV1BoundRequest};
use crate::service::memory_v1_governance_commit::{
    FailClosedMemoryV1GovernanceCommitPort, MemoryV1GovernanceCommitPort,
    MemoryV1GovernanceCommitRequest,
};
use crate::service::memory_v1_mutation_coordinator::MutationAuditCandidate;
use crate::AppState;
use astral_types::memory_v1_audit::{
    MemoryV1AuditAction, MemoryV1AuditActor, MemoryV1AuditBindingState, MemoryV1AuditCardState,
    MemoryV1AuditChange, MemoryV1AuditConfirmationRef, MemoryV1AuditConfirmationState,
    MemoryV1AuditConfirmations, MemoryV1AuditContext, MemoryV1AuditDecisionInput,
    MemoryV1AuditEvent, MemoryV1AuditObject, MemoryV1AuditObjectState, MemoryV1AuditOperation,
    MemoryV1AuditRootObservation, MemoryV1AuditRootStatus, MemoryV1AuditRootVersion,
    MemoryV1AuditRuleSetState, MemoryV1AuditRuleSetStatus, MemoryV1AuditSource, MemoryV1AuditTime,
};

/// Legacy governance route descriptions. Registration and authorization use
/// `MEMORY_V1_ROUTE_REGISTRATIONS`, including its compound actions.
/// This historical slice does not itself install a route or grant authority.
pub const GOVERNANCE_ROUTE_DECLARATIONS:
    &[crate::api::permission_check::MemoryV1RouteDeclaration] = &[
    crate::api::permission_check::MemoryV1RouteDeclaration {
        method: "POST",
        path: "/governance/bindings",
        resource: "binding",
        action: "create",
    },
    crate::api::permission_check::MemoryV1RouteDeclaration {
        method: "POST",
        path: "/governance/bindings/confirm",
        resource: "binding",
        action: "confirm",
    },
    crate::api::permission_check::MemoryV1RouteDeclaration {
        method: "POST",
        path: "/governance/bindings/confirm/batch",
        resource: "binding",
        action: "confirm",
    },
    crate::api::permission_check::MemoryV1RouteDeclaration {
        method: "DELETE",
        path: "/governance/bindings",
        resource: "binding",
        action: "remove",
    },
    crate::api::permission_check::MemoryV1RouteDeclaration {
        method: "POST",
        path: "/governance/bindings/revoke-confirmation",
        resource: "binding",
        action: "revoke-confirmation",
    },
    crate::api::permission_check::MemoryV1RouteDeclaration {
        method: "POST",
        path: "/governance/rule-sets",
        resource: "rule_set",
        action: "create",
    },
    crate::api::permission_check::MemoryV1RouteDeclaration {
        method: "POST",
        path: "/governance/rule-sets/publish",
        resource: "rule_set",
        action: "version-publish",
    },
    crate::api::permission_check::MemoryV1RouteDeclaration {
        method: "POST",
        path: "/governance/rule-sets/retire",
        resource: "rule_set",
        action: "retire",
    },
    crate::api::permission_check::MemoryV1RouteDeclaration {
        method: "POST",
        path: "/governance/user-cards",
        resource: "user_card",
        action: "create",
    },
    crate::api::permission_check::MemoryV1RouteDeclaration {
        method: "POST",
        path: "/governance/user-cards/enable",
        resource: "user_card",
        action: "enable",
    },
    crate::api::permission_check::MemoryV1RouteDeclaration {
        method: "POST",
        path: "/governance/user-cards/disable",
        resource: "user_card",
        action: "disable",
    },
];

/// Legacy description of governance intent; it is not an admission or a
/// sufficient input to the restricted mutation path.
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

const MAX_SCOPE_BYTES: usize = 4096;
const MAX_CONTENT_BYTES: usize = 1024 * 1024;

/// Legacy request DTOs retained for source compatibility. They do not carry the
/// confirmation facts required by the current governance handlers.
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

/// memory—v1: A strict request body used for creating a binding.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingCreateRequest {
    pub binding_id: String,
    pub user_card_id: String,
    pub rule_set_id: String,
    pub binding_layer: String,
    #[serde(default)]
    pub valid_from: Option<i64>,
    #[serde(default)]
    pub valid_until: Option<i64>,
    #[serde(default)]
    pub owner_scope: MemoryV1OwnerScope,
    #[serde(default)]
    pub tenant_scope: MemoryV1TenantScope,
    pub confirmation_id: String,
    pub confirmation_scope: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingConfirmationBatchRequest {
    items: Vec<BindingConfirmationBatchItemRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingConfirmationBatchItemRequest {
    sequence: u32,
    binding_id: String,
    confirmation_id: String,
    rule_set_id: String,
    scope: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingConfirmRequest {
    pub binding_id: String,
    #[serde(default)]
    pub rule_set_id: Option<String>,
    pub confirmation_id: String,
    pub scope: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceBindingRemoveBody {
    pub binding_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceRevokeConfirmationBody {
    pub confirmation_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSetCreateRequest {
    pub rule_set_id: String,
    pub owner_tenant_id: String,
    pub content: String,
    pub version_bytes: String,
    pub change_confirmation_id: String,
    pub affected_scope: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionPublishRequest {
    pub rule_set_id: String,
    pub content: String,
    pub version_bytes: String,
    pub change_confirmation_id: String,
    pub affected_scope: String,
}

/// memory—v1: Retirement accepts only the target rule-set identifier.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSetRetireRequest {
    rule_set_id: String,
}

/// memory—v1: New cards require explicit candidate, beneficiary and tenant IDs.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserCardCreateRequest {
    user_card_id: String,
    user_id: String,
    tenant_id: String,
}

/// memory—v1: Enable accepts only the target card identifier.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserCardEnableRequest {
    user_card_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceUserCardDisableBody {
    pub user_card_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GovernanceMutationResponse {
    root_version: u64,
    root_digest: String,
    operation_id: String,
}

#[derive(Debug)]
struct GovernanceError(AppError);

impl From<AppError> for GovernanceError {
    fn from(error: AppError) -> Self {
        Self(error)
    }
}

impl IntoResponse for GovernanceError {
    fn into_response(self) -> Response {
        let AppError(error) = self.0;
        if matches!(&error, AstralError::Pending(_)) {
            let mut response = (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "code": 503,
                    "message": "Authorization pending",
                    "decision": "AUTHORIZATION_PENDING",
                    "reasonCode": "AUTHORIZATION_PENDING"
                })),
            )
                .into_response();
            response.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                axum::http::HeaderValue::from_static("3"),
            );
            astral_common::middleware::permission_check_shared::AuthorizationPendingRefusal::attach(
                &mut response,
            );
            response
        } else {
            AppError(error).into_response()
        }
    }
}

struct MutationContext {
    bound: MemoryV1BoundRequest,
    root: RootMetadata,
    commit_port: Arc<dyn MemoryV1GovernanceCommitPort>,
    actor: [u8; 16],
    actor_identity_card: [u8; 16],
    target: [u8; 16],
    target_tenant: [u8; 16],
    target_owner: Option<[u8; 16]>,
    trusted_time: i64,
    /// The selected rule-set version and digest captured in the admitted read
    /// phase for publication or retirement.
    previous_rule_set_state: Option<(Vec<u8>, [u8; 32])>,
}

fn parse_id(value: &str, field: &'static str) -> Result<[u8; 16], AppError> {
    let id = value
        .parse::<MemoryId>()
        .map_err(|_| validation_error(field))?
        .into_bytes();
    if id == [0; 16] {
        return Err(validation_error(field));
    }
    Ok(id)
}

fn validation_error(field: &str) -> AppError {
    AppError(AstralError::Validation(format!(
        "invalid memory-v1 field: {field}"
    )))
}

fn audit_unavailable(field: &str) -> AppError {
    AppError(AstralError::Pending(format!(
        "governance audit candidate is unavailable: {field}"
    )))
}

fn parse_body<T: for<'de> Deserialize<'de>>(bound: &MemoryV1BoundRequest) -> Result<T, AppError> {
    serde_json::from_slice(&bound.body).map_err(|_| validation_error("body"))
}

/// memory—v1: Parse the complete ordered batch before batch authorization.
///
/// This is shared with the permission middleware so it cannot authorize only an
/// anchor item. The original bounded bytes remain owned by `MemoryV1BoundRequest`;
/// this function only derives the evaluator's target values from them.
pub(crate) fn parse_binding_confirmation_batch_items(
    body: &[u8],
    limit: MemoryV1ConfirmationBatchLimit,
) -> Result<Vec<MemoryV1BatchItem>, StatusCode> {
    let request: BindingConfirmationBatchRequest =
        serde_json::from_slice(body).map_err(|_| StatusCode::BAD_REQUEST)?;
    if request.items.is_empty() || request.items.len() > limit.get() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut binding_ids = HashSet::with_capacity(request.items.len());
    let mut confirmation_ids = HashSet::with_capacity(request.items.len());
    let mut items = Vec::with_capacity(request.items.len());
    for (position, item) in request.items.into_iter().enumerate() {
        if item.sequence as usize != position {
            return Err(StatusCode::BAD_REQUEST);
        }
        let binding_id =
            parse_id(&item.binding_id, "binding_id").map_err(|_| StatusCode::BAD_REQUEST)?;
        let confirmation_id = parse_id(&item.confirmation_id, "confirmation_id")
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        // The rule-set ID is checked here even though the evaluator derives the
        // authoritative value from the binding root fact; it is part of the
        // complete body/admission equality checked by the handler helper.
        parse_id(&item.rule_set_id, "rule_set_id").map_err(|_| StatusCode::BAD_REQUEST)?;
        bounded_text(item.scope, "scope", MAX_BATCH_PLAN_SCOPE_BYTES)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        if !binding_ids.insert(binding_id) || !confirmation_ids.insert(confirmation_id) {
            return Err(StatusCode::BAD_REQUEST);
        }
        items.push(MemoryV1BatchItem {
            sequence: item.sequence,
            binding_id,
            confirmation_id,
        });
    }
    Ok(items)
}

fn bounded_text(value: String, field: &'static str, max: usize) -> Result<Vec<u8>, AppError> {
    let bytes = value.into_bytes();
    if bytes.is_empty() || bytes.len() > max {
        return Err(validation_error(field));
    }
    Ok(bytes)
}

fn binding_layer(value: &str) -> Result<BindingLayer, AppError> {
    match value {
        "BASE" => Ok(BindingLayer::Base),
        "OVERLAY" => Ok(BindingLayer::Overlay),
        _ => Err(validation_error("binding_layer")),
    }
}

fn now_unix_seconds() -> Result<i64, AppError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AppError(AstralError::Pending("trusted time unavailable".into())))?
        .as_secs();
    i64::try_from(seconds)
        .map_err(|_| AppError(AstralError::Pending("trusted time unavailable".into())))
}

fn operation_bytes(bound: &MemoryV1BoundRequest) -> Vec<u8> {
    bound.operation_id.as_bytes().to_vec()
}

fn time_bytes(time: i64) -> Vec<u8> {
    time.to_be_bytes().to_vec()
}

fn canonical_version(
    version_bytes: Vec<u8>,
    content: Vec<u8>,
    timestamp: Vec<u8>,
    rule_set_id: [u8; 16],
) -> RuleSetVersionRow {
    let hash_input_bytes = canonical_version_bytes(&version_bytes, &content, &timestamp);
    let hash_bytes = version_digest(&hash_input_bytes);
    RuleSetVersionRow {
        rule_set_id,
        version_bytes,
        content_bytes: content,
        timestamp_bytes: timestamp,
        hash_input_bytes,
        hash_bytes,
    }
}

fn root_scope(request: &Request) -> Result<RequestRootExtension, AppError> {
    request
        .extensions()
        .get::<RequestRootExtension>()
        .cloned()
        .ok_or_else(|| AppError(AstralError::Pending("request root unavailable".into())))
}

fn batch_plan_error(error: MemoryV1BatchPlanError) -> AppError {
    let field = match error {
        MemoryV1BatchPlanError::InvalidCount => "items",
        MemoryV1BatchPlanError::TargetMismatch => "target",
        MemoryV1BatchPlanError::InvalidConfirmation => "confirmation",
        MemoryV1BatchPlanError::InvalidTime => "confirmed_at",
        MemoryV1BatchPlanError::DigestUnavailable => "batch",
    };
    validation_error(field)
}

/// memory—v1: Build a confirmation-batch candidate after the protected batch
/// handler has received a complete batch admission from permission middleware.
///
/// The handler now invokes this helper through the mounted batch route, but this
/// helper deliberately performs no mutation. The returned plan is an offline
/// candidate value only: it is not a restricted admission, a commit capability,
/// durable proof, or a substitute for the commit-time session/root/fence/audit
/// checks. The body supplies only ordered target IDs and bounded opaque scope
/// bytes. The selected version, confirmer, operation ID and confirmation time are
/// derived from the same serving root/session admission; client values cannot
/// replace those facts. The middleware must call the batch evaluator before
/// invoking it. Keeping this crate-private prevents an external caller from
/// treating the candidate builder as a public authorization or mutation API.
pub(crate) fn build_binding_confirmation_batch_candidate(
    root: &RequestRootExtension,
    session: &RequestSessionExtension,
    admission: &MemoryV1BatchAdmission,
    bound: &MemoryV1BoundRequest,
    limit: MemoryV1ConfirmationBatchLimit,
) -> Result<MemoryV1BatchPlan, AppError> {
    let body: BindingConfirmationBatchRequest = parse_body(bound)?;
    if admission.operation_id() != bound.operation_id.as_bytes()
        || admission.operation_fingerprint() != bound.fingerprint.as_bytes()
    {
        return Err(AppError(AstralError::Permission(
            "AUTHORIZATION_BINDING_MISMATCH".into(),
        )));
    }
    if body.items.is_empty() || body.items.len() > limit.get() {
        return Err(validation_error("items"));
    }
    if body.items.len() != admission.targets().len() {
        return Err(AppError(AstralError::Permission(
            "AUTHORIZATION_TARGET_MISMATCH".into(),
        )));
    }

    let trusted_time = now_unix_seconds()?;
    if trusted_time < admission.trusted_time_unix_seconds() {
        return Err(AppError(AstralError::Pending(
            "authorization admission is stale".into(),
        )));
    }
    session
        .revalidate_authority(root, trusted_time)
        .map_err(|_| {
            AppError(AstralError::Pending(
                "session authority unavailable or stale".into(),
            ))
        })?;
    let mut candidates = Vec::with_capacity(body.items.len());
    session
        .with_context(root, |facts, reader| {
            if facts.candidate_identity() != admission.identity()
                || trusted_time < admission.trusted_time_unix_seconds()
                || !facts.valid_at(trusted_time)
                || reader.metadata() != admission.root()
                || !matches!(reader.is_current(), Ok(true))
            {
                return Err(AppError(AstralError::Pending(
                    "authorization admission is stale".into(),
                )));
            }
            for (item, target) in body.items.iter().zip(admission.targets()) {
                if item.sequence != target.item.sequence
                    || parse_id(&item.binding_id, "binding_id")? != target.item.binding_id
                    || parse_id(&item.confirmation_id, "confirmation_id")?
                        != target.item.confirmation_id
                    || parse_id(&item.rule_set_id, "rule_set_id")? != target.rule_set_id
                {
                    return Err(AppError(AstralError::Permission(
                        "AUTHORIZATION_TARGET_MISMATCH".into(),
                    )));
                }
                let facts_for_target = reader
                    .binding_target(target.item.binding_id)
                    .map_err(|_| AppError(AstralError::Pending("target unavailable".into())))?;
                if facts_for_target.user_card_id != target.user_card_id
                    || facts_for_target.rule_set_id != target.rule_set_id
                    || facts_for_target.owner_user_id != target.beneficiary_user_id
                    || facts_for_target.tenant_id != target.tenant_id
                {
                    return Err(AppError(AstralError::Pending(
                        "authorization target changed".into(),
                    )));
                }
                let version = reader
                    .selected_version_bytes(target.rule_set_id)
                    .map_err(|_| {
                        AppError(AstralError::Pending("selected version unavailable".into()))
                    })?;
                candidates.push(MemoryV1BatchPlanItem {
                    sequence: item.sequence,
                    confirmation: BindingConfirmationRow {
                        confirmation_id: target.item.confirmation_id,
                        binding_id: target.item.binding_id,
                        rule_set_id: target.rule_set_id,
                        version_bytes: version,
                        confirmer_user_id: admission.identity().user_id.into_bytes(),
                        scope_bytes: bounded_text(
                            item.scope.clone(),
                            "scope",
                            MAX_BATCH_PLAN_SCOPE_BYTES,
                        )?,
                        operation_id: admission.operation_id().to_vec(),
                        confirmed_at_bytes: admission
                            .trusted_time_unix_seconds()
                            .to_be_bytes()
                            .to_vec(),
                        revoked_at: None,
                        revoked_by: None,
                    },
                });
            }
            Ok(())
        })
        .map_err(|_| AppError(AstralError::Pending("session/root unavailable".into())))??;
    MemoryV1BatchPlan::new(admission, &candidates).map_err(batch_plan_error)
}

fn admitted_context(
    request: &Request,
    resource: &str,
    action: &str,
    additional_actions: &[&str],
) -> Result<MutationContext, AppError> {
    let admission = request
        .extensions()
        .get::<MemoryV1Admission>()
        .cloned()
        .ok_or_else(|| {
            AppError(AstralError::Pending(
                "authorization admission unavailable".into(),
            ))
        })?;
    let bound = request
        .extensions()
        .get::<MemoryV1BoundRequest>()
        .cloned()
        .ok_or_else(|| AppError(AstralError::Pending("bound request unavailable".into())))?;
    let extras = request
        .extensions()
        .get::<MemoryV1AdditionalAdmissions>()
        .ok_or_else(|| {
            AppError(AstralError::Pending(
                "additional admissions unavailable".into(),
            ))
        })?;
    let actual_operation =
        astral_common::middleware::request_binding::request_operation_id(request)
            .map_err(|_| validation_error("operation_id"))?;
    let actual_fingerprint =
        astral_common::middleware::request_binding::fingerprint_bound_http_request(
            request,
            &bound.body,
        );
    let expected_change_intent = match (resource, action) {
        ("rule_set", "create") => Some(MemoryV1RuleSetChangeIntent::Create),
        ("rule_set", "version-publish") => Some(MemoryV1RuleSetChangeIntent::Publish),
        _ => None,
    };
    if admission.resource() != resource
        || admission.action() != action
        || admission.change_intent().is_some()
        || (expected_change_intent.is_some() && additional_actions != ["confirm-change"])
        || (expected_change_intent.is_none() && additional_actions.contains(&"confirm-change"))
        || admission.operation_id() != bound.operation_id.as_bytes()
        || admission.operation_fingerprint() != bound.fingerprint.as_bytes()
        || actual_operation != bound.operation_id
        || actual_fingerprint != bound.fingerprint
        || extras.0.len() != additional_actions.len()
    {
        return Err(AppError(AstralError::Permission(
            "AUTHORIZATION_BINDING_MISMATCH".into(),
        )));
    }
    for (extra, expected_action) in extras.0.iter().zip(additional_actions) {
        if extra.resource() != resource
            || extra.action() != *expected_action
            || extra.change_intent()
                != if *expected_action == "confirm-change" {
                    expected_change_intent
                } else {
                    None
                }
            || extra.root() != admission.root()
            || extra.identity() != admission.identity()
            || extra.target() != admission.target()
            || extra.target_tenant() != admission.target_tenant()
            || extra.target_owner() != admission.target_owner()
            || extra.operation_id() != admission.operation_id()
            || extra.operation_fingerprint() != admission.operation_fingerprint()
            || extra.trusted_time_unix_seconds() != admission.trusted_time_unix_seconds()
        {
            return Err(AppError(AstralError::Permission(
                "AUTHORIZATION_BINDING_MISMATCH".into(),
            )));
        }
    }
    let root = root_scope(request)?;
    let target = admission
        .target()
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| validation_error("target"))?;
    let target_tenant = admission
        .target_tenant()
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| validation_error("target_tenant"))?;
    let target_owner = admission
        .target_owner()
        .map(|value| {
            value
                .try_into()
                .map_err(|_| validation_error("target_owner"))
        })
        .transpose()?;
    let commit_port = request
        .extensions()
        .get::<Arc<dyn MemoryV1GovernanceCommitPort>>()
        .cloned()
        .unwrap_or_else(|| Arc::new(FailClosedMemoryV1GovernanceCommitPort));
    let session = request
        .extensions()
        .get::<astral_authorization_root::memory_v1_session::RequestSessionExtension>()
        .cloned()
        .ok_or_else(|| AppError(AstralError::Pending("session unavailable".into())))?;
    let trusted_time = now_unix_seconds()?;
    session
        .with_context(&root, |facts, reader| {
            if facts.candidate_identity() != admission.identity()
                || trusted_time < admission.trusted_time_unix_seconds()
                || !facts.valid_at(trusted_time)
                || reader.metadata() != admission.root()
                || !matches!(reader.is_current(), Ok(true))
            {
                return Err(AppError(AstralError::Pending(
                    "authorization admission is stale".into(),
                )));
            }
            Ok(())
        })
        .map_err(|_| AppError(AstralError::Pending("session/root unavailable".into())))??;
    // memory—v1: Recheck the live authority outside the root reader callback.
    session
        .revalidate_authority(&root, trusted_time)
        .map_err(|_| {
            AppError(AstralError::Pending(
                "session authority unavailable or stale".into(),
            ))
        })?;
    let root_metadata = session
        .with_context(&root, |_, reader| reader.metadata())
        .map_err(|_| AppError(AstralError::Pending("session/root unavailable".into())))?;
    if root_metadata != admission.root() {
        return Err(AppError(AstralError::Pending(
            "authorization admission is stale".into(),
        )));
    }
    Ok(MutationContext {
        actor: admission.identity().user_id.into_bytes(),
        actor_identity_card: admission.identity().identity_card_id.into_bytes(),
        bound,
        root: root_metadata,
        commit_port,
        target,
        target_tenant,
        target_owner,
        trusted_time,
        previous_rule_set_state: None,
    })
}

fn check_target(
    context: &MutationContext,
    target: [u8; 16],
    facts: GovernanceTargetFacts,
) -> Result<(), AppError> {
    let owner = (facts.owner_user_id != [0; 16]).then_some(facts.owner_user_id);
    if context.target != target
        || context.target_tenant != facts.tenant_id
        || context.target_owner != owner
    {
        return Err(AppError(AstralError::Permission(
            "AUTHORIZATION_TARGET_MISMATCH".into(),
        )));
    }
    Ok(())
}

/// memory—v1: Derive the complete T2 audit value from one admitted mutation.
///
/// Every observed state, summary and confirmation fact comes from the same
/// mutation value the durable owner will publish; the context carries the exact
/// admission observation (actor, operation, fingerprint, trusted time and the
/// serving root metadata). Nothing here proves persistence; the candidate stays
/// a value until the future durable audit owner verifies and persists it.
fn build_governance_audit_event(
    context: &MutationContext,
    mutation: &ManagementMutationV2,
) -> Result<MemoryV1AuditEvent, AppError> {
    let fingerprint_bytes = astral_types::memory_v1_audit::memory_v1_audit_fingerprint_from_hex(
        &context.bound.fingerprint,
    )
    .map_err(|_| audit_unavailable("operation_fingerprint"))?;
    let operation = MemoryV1AuditOperation::new(&context.bound.operation_id, fingerprint_bytes)
        .map_err(|_| audit_unavailable("operation_id"))?;
    let actor = MemoryV1AuditActor::new(
        astral_types::memory_v1::MemoryId::from_bytes(context.actor),
        astral_types::memory_v1::MemoryId::from_bytes(context.actor_identity_card),
    );
    let (resource, action, reason) = match mutation {
        ManagementMutationV2::BindingCreate { .. } => {
            ("binding", "create", "GOVERNANCE_BINDING_CREATE")
        }
        ManagementMutationV2::BindingRemove { .. } => {
            ("binding", "remove", "GOVERNANCE_BINDING_REMOVE")
        }
        ManagementMutationV2::ConfirmationCreate { .. } => {
            ("binding", "confirm", "GOVERNANCE_BINDING_CONFIRM")
        }
        ManagementMutationV2::ConfirmationRevoke { .. }
        | ManagementMutationV2::RuleSetChangeConfirmationRevoke { .. } => (
            "binding",
            "revoke-confirmation",
            "GOVERNANCE_CONFIRMATION_REVOKE",
        ),
        ManagementMutationV2::ConfirmationBatch { .. } => {
            return Err(AppError(AstralError::Pending(
                "governance batch audit candidate issuer is unavailable".into(),
            )));
        }
        ManagementMutationV2::UserCardCreate { .. } => {
            ("user_card", "create", "GOVERNANCE_USER_CARD_CREATE")
        }
        ManagementMutationV2::UserCardStatus { status, .. } => match status {
            UserCardStatus::Active => ("user_card", "enable", "GOVERNANCE_USER_CARD_ENABLE"),
            UserCardStatus::Disabled => ("user_card", "disable", "GOVERNANCE_USER_CARD_DISABLE"),
        },
        ManagementMutationV2::RuleSetCreate { .. } => {
            ("rule_set", "create", "GOVERNANCE_RULE_SET_CREATE")
        }
        ManagementMutationV2::RuleSetRetire { .. } => {
            ("rule_set", "retire", "GOVERNANCE_RULE_SET_RETIRE")
        }
        ManagementMutationV2::VersionPublish { .. } => {
            ("rule_set", "version-publish", "GOVERNANCE_RULE_SET_PUBLISH")
        }
        // memory—v1 §15.10.3: A service-period context load is not a governed
        // management change; it has no governance audit vocabulary and never
        // reaches a governance route. Fail closed as unavailable.
        ManagementMutationV2::ContextLoad { .. } => {
            return Err(audit_unavailable("context_load_not_governable"));
        }
    };
    let (target, before, after) = match mutation {
        ManagementMutationV2::BindingCreate { row, .. } => (
            MemoryV1AuditObject::Binding(astral_types::memory_v1::MemoryId::from_bytes(
                row.binding_id,
            )),
            MemoryV1AuditObjectState::Absent,
            MemoryV1AuditObjectState::Binding(MemoryV1AuditBindingState::Active),
        ),
        ManagementMutationV2::BindingRemove { binding_id, .. } => (
            MemoryV1AuditObject::Binding(astral_types::memory_v1::MemoryId::from_bytes(
                *binding_id,
            )),
            MemoryV1AuditObjectState::Binding(MemoryV1AuditBindingState::Active),
            MemoryV1AuditObjectState::Binding(MemoryV1AuditBindingState::Removed),
        ),
        ManagementMutationV2::ConfirmationCreate { row } => (
            MemoryV1AuditObject::Confirmation(astral_types::memory_v1::MemoryId::from_bytes(
                row.confirmation_id,
            )),
            MemoryV1AuditObjectState::Absent,
            MemoryV1AuditObjectState::Confirmation(MemoryV1AuditConfirmationState::Active),
        ),
        ManagementMutationV2::ConfirmationRevoke {
            confirmation_id, ..
        }
        | ManagementMutationV2::RuleSetChangeConfirmationRevoke {
            confirmation_id, ..
        } => (
            MemoryV1AuditObject::Confirmation(astral_types::memory_v1::MemoryId::from_bytes(
                *confirmation_id,
            )),
            MemoryV1AuditObjectState::Confirmation(MemoryV1AuditConfirmationState::Active),
            MemoryV1AuditObjectState::Confirmation(MemoryV1AuditConfirmationState::Revoked),
        ),
        ManagementMutationV2::UserCardCreate { row } => (
            MemoryV1AuditObject::UserCard(astral_types::memory_v1::MemoryId::from_bytes(
                row.user_card_id,
            )),
            MemoryV1AuditObjectState::Absent,
            MemoryV1AuditObjectState::UserCard(MemoryV1AuditCardState::Active),
        ),
        ManagementMutationV2::UserCardStatus {
            user_card_id,
            status,
        } => (
            MemoryV1AuditObject::UserCard(astral_types::memory_v1::MemoryId::from_bytes(
                *user_card_id,
            )),
            MemoryV1AuditObjectState::UserCard(match status {
                UserCardStatus::Active => MemoryV1AuditCardState::Disabled,
                UserCardStatus::Disabled => MemoryV1AuditCardState::Active,
            }),
            MemoryV1AuditObjectState::UserCard(match status {
                UserCardStatus::Active => MemoryV1AuditCardState::Active,
                UserCardStatus::Disabled => MemoryV1AuditCardState::Disabled,
            }),
        ),
        ManagementMutationV2::RuleSetCreate {
            rule_set, version, ..
        } => (
            MemoryV1AuditObject::RuleSet(astral_types::memory_v1::MemoryId::from_bytes(
                rule_set.rule_set_id,
            )),
            MemoryV1AuditObjectState::Absent,
            MemoryV1AuditObjectState::RuleSet(
                MemoryV1AuditRuleSetState::new_with_status(
                    &version.version_bytes,
                    version_hash(&version.hash_bytes)?,
                    MemoryV1AuditRuleSetStatus::Active,
                )
                .map_err(|_| audit_unavailable("rule_set_version"))?,
            ),
        ),
        ManagementMutationV2::RuleSetRetire { .. } => {
            // The before state is the same root-phase observation the retire
            // handler captured: the current version and its stored digest.
            let Some((current_version, content_hash)) = context.previous_rule_set_state.as_ref()
            else {
                return Err(AppError(AstralError::Pending(
                    "governance retirement audit observation unavailable".into(),
                )));
            };
            (
                MemoryV1AuditObject::RuleSet(astral_types::memory_v1::MemoryId::from_bytes(
                    context.target,
                )),
                MemoryV1AuditObjectState::RuleSet(
                    MemoryV1AuditRuleSetState::new_with_status(
                        current_version,
                        *content_hash,
                        MemoryV1AuditRuleSetStatus::Active,
                    )
                    .map_err(|_| audit_unavailable("rule_set_version"))?,
                ),
                MemoryV1AuditObjectState::RuleSet(
                    MemoryV1AuditRuleSetState::new_with_status(
                        current_version,
                        *content_hash,
                        MemoryV1AuditRuleSetStatus::Retired,
                    )
                    .map_err(|_| audit_unavailable("rule_set_version"))?,
                ),
            )
        }
        ManagementMutationV2::ConfirmationBatch { .. } => {
            return Err(AppError(AstralError::Pending(
                "governance batch audit candidate issuer is unavailable".into(),
            )));
        }
        ManagementMutationV2::VersionPublish {
            rule_set_id,
            version_row,
            new_current_version,
            ..
        } => {
            let (previous_version, previous_hash) = context
                .previous_rule_set_state
                .as_ref()
                .ok_or_else(|| audit_unavailable("previous_rule_set_version"))?;
            (
                MemoryV1AuditObject::RuleSet(astral_types::memory_v1::MemoryId::from_bytes(
                    *rule_set_id,
                )),
                MemoryV1AuditObjectState::RuleSet(
                    MemoryV1AuditRuleSetState::new_with_status(
                        previous_version,
                        *previous_hash,
                        MemoryV1AuditRuleSetStatus::Active,
                    )
                    .map_err(|_| audit_unavailable("previous_rule_set_version"))?,
                ),
                MemoryV1AuditObjectState::RuleSet(
                    MemoryV1AuditRuleSetState::new_with_status(
                        new_current_version,
                        version_hash(&version_row.hash_bytes)?,
                        MemoryV1AuditRuleSetStatus::Active,
                    )
                    .map_err(|_| audit_unavailable("rule_set_version"))?,
                ),
            )
        }
        ManagementMutationV2::ContextLoad { .. } => {
            return Err(audit_unavailable("context_load_not_governable"));
        }
    };
    let (approver, summary_bytes, confirmations) = match mutation {
        ManagementMutationV2::BindingCreate { row, confirmation } => {
            let _ = row;
            (
                astral_types::memory_v1::MemoryId::from_bytes(context.actor),
                MutationAuditCandidate::governance_mutation_summary(mutation)
                    .map_err(map_audit_summary_error)?,
                MemoryV1AuditConfirmations::references(&[MemoryV1AuditConfirmationRef::Binding(
                    astral_types::memory_v1::MemoryId::from_bytes(confirmation.confirmation_id),
                )])
                .map_err(|_| audit_unavailable("confirmation"))?,
            )
        }
        ManagementMutationV2::ConfirmationCreate { row } => (
            astral_types::memory_v1::MemoryId::from_bytes(context.actor),
            MutationAuditCandidate::governance_mutation_summary(mutation)
                .map_err(map_audit_summary_error)?,
            MemoryV1AuditConfirmations::references(&[MemoryV1AuditConfirmationRef::Binding(
                astral_types::memory_v1::MemoryId::from_bytes(row.confirmation_id),
            )])
            .map_err(|_| audit_unavailable("confirmation"))?,
        ),
        ManagementMutationV2::BindingRemove { removed_by, .. }
        | ManagementMutationV2::ConfirmationRevoke {
            revoked_by: removed_by,
            ..
        }
        | ManagementMutationV2::RuleSetChangeConfirmationRevoke {
            revoked_by: removed_by,
            ..
        } => (
            astral_types::memory_v1::MemoryId::from_bytes(*removed_by),
            MutationAuditCandidate::governance_mutation_summary(mutation)
                .map_err(map_audit_summary_error)?,
            MemoryV1AuditConfirmations::not_applicable(),
        ),
        ManagementMutationV2::UserCardCreate { row } => (
            astral_types::memory_v1::MemoryId::from_bytes(row.user_id),
            MutationAuditCandidate::governance_mutation_summary(mutation)
                .map_err(map_audit_summary_error)?,
            MemoryV1AuditConfirmations::not_applicable(),
        ),
        ManagementMutationV2::UserCardStatus { .. } => (
            astral_types::memory_v1::MemoryId::from_bytes(context.actor),
            MutationAuditCandidate::governance_mutation_summary(mutation)
                .map_err(map_audit_summary_error)?,
            MemoryV1AuditConfirmations::not_applicable(),
        ),
        ManagementMutationV2::RuleSetCreate {
            change_confirmation,
            ..
        }
        | ManagementMutationV2::VersionPublish {
            change_confirmation,
            ..
        } => (
            astral_types::memory_v1::MemoryId::from_bytes(change_confirmation.confirmer_user_id),
            MutationAuditCandidate::governance_mutation_summary(mutation)
                .map_err(map_audit_summary_error)?,
            MemoryV1AuditConfirmations::references(&[MemoryV1AuditConfirmationRef::RuleSetChange(
                astral_types::memory_v1::MemoryId::from_bytes(change_confirmation.confirmation_id),
            )])
            .map_err(|_| audit_unavailable("change_confirmation"))?,
        ),
        ManagementMutationV2::RuleSetRetire { .. } => (
            astral_types::memory_v1::MemoryId::from_bytes(context.actor),
            MutationAuditCandidate::governance_mutation_summary(mutation)
                .map_err(map_audit_summary_error)?,
            // A retirement revokes nothing and applies nothing on its own; it
            // marks the rule set retired for future evaluations.
            MemoryV1AuditConfirmations::not_applicable(),
        ),
        ManagementMutationV2::ConfirmationBatch { rows } => {
            // One batch = one root CAS; the audit event carries every ordered
            // confirmation the batch installs.
            let refs: Vec<MemoryV1AuditConfirmationRef> = rows
                .iter()
                .map(|row| {
                    MemoryV1AuditConfirmationRef::Binding(
                        astral_types::memory_v1::MemoryId::from_bytes(row.confirmation_id),
                    )
                })
                .collect();
            (
                astral_types::memory_v1::MemoryId::from_bytes(context.actor),
                MutationAuditCandidate::governance_mutation_summary(mutation)
                    .map_err(map_audit_summary_error)?,
                MemoryV1AuditConfirmations::references(&refs)
                    .map_err(|_| audit_unavailable("confirmation"))?,
            )
        }
        ManagementMutationV2::ContextLoad { .. } => {
            return Err(audit_unavailable("context_load_not_governable"));
        }
    };
    let root_version = MemoryV1AuditRootVersion::new(
        astral_types::memory_v1::MemoryId::from_bytes(
            *context.root.instance_id.as_uuid().as_bytes(),
        ),
        context.root.version,
    );
    let audit_context = MemoryV1AuditContext::new(
        actor,
        MemoryV1AuditTime::new(context.trusted_time)
            .map_err(|_| audit_unavailable("trusted_time"))?,
        MemoryV1AuditAction::new(resource, action)
            .map_err(|_| audit_unavailable("audit_action"))?,
        reason,
        operation,
        MemoryV1AuditRootObservation::new(
            root_version,
            context.root.digest,
            MemoryV1AuditRootStatus::Serving,
        ),
    )
    .map_err(|_| audit_unavailable("audit_context"))?;
    let change = MemoryV1AuditChange::new(
        Some(approver),
        Some(target),
        Some(MemoryV1AuditObject::Tenant(
            astral_types::memory_v1::MemoryId::from_bytes(context.target_tenant),
        )),
        Some(summary_bytes),
        Some(before),
        Some(after),
        Some(confirmations),
        Some(root_version),
        Some(MemoryV1AuditRootVersion::new(
            astral_types::memory_v1::MemoryId::from_bytes(
                *context.root.instance_id.as_uuid().as_bytes(),
            ),
            context.root.version.checked_add(1).ok_or_else(|| {
                AppError(AstralError::Pending(
                    "governance root version exhausted".into(),
                ))
            })?,
        )),
        MemoryV1AuditSource::Ordinary,
    );
    MemoryV1AuditEvent::change(audit_context, MemoryV1AuditDecisionInput::Allow, change).map_err(
        |_| {
            AppError(AstralError::Pending(
                "governance audit event construction failed".into(),
            ))
        },
    )
}

fn version_hash(hash_bytes: &[u8]) -> Result<[u8; 32], AppError> {
    let bytes: [u8; 32] = hash_bytes
        .try_into()
        .map_err(|_| audit_unavailable("version_hash"))?;
    Ok(bytes)
}

fn map_audit_summary_error(
    error: crate::service::memory_v1_mutation_coordinator::CoordinatorError,
) -> AppError {
    AppError(AstralError::Pending(format!(
        "governance audit summary is unavailable: {error}"
    )))
}

fn commit(
    context: MutationContext,
    mutation: ManagementMutationV2,
) -> Result<GovernanceMutationResponse, AppError> {
    let request_operation_id = context.bound.operation_id.clone();
    let request_fingerprint = context.bound.fingerprint.clone();
    let root = context.root;
    let audit = MutationAuditCandidate::Single(
        astral_types::memory_v1_audit::MemoryV1AuditT2SingleChangeCandidate::try_from(
            build_governance_audit_event(&context, &mutation)?,
        )
        .map_err(|_| {
            AppError(AstralError::Pending(
                "governance audit candidate construction failed".into(),
            ))
        })?,
    );
    let result = context
        .commit_port
        .commit(MemoryV1GovernanceCommitRequest {
            operation_id: request_operation_id.clone(),
            request_fingerprint: request_fingerprint.clone(),
            root,
            actor: context.actor,
            target: context.target,
            target_tenant: context.target_tenant,
            target_owner: context.target_owner,
            trusted_time_unix_seconds: context.trusted_time,
            mutation,
            audit,
        })
        .map_err(AppError)?;
    let expected_version = root.version.checked_add(1).ok_or_else(|| {
        AppError(AstralError::Pending(
            "governance root version exhausted".into(),
        ))
    })?;
    if result.operation_id != request_operation_id
        || result.root.instance_id != root.instance_id
        || result.root.version != expected_version
        || result.root.digest == [0; 32]
        || result.root.status != RootStatus::Serving
    {
        return Err(AppError(AstralError::Pending(
            "governance commit proof does not match request root".into(),
        )));
    }
    Ok(GovernanceMutationResponse {
        root_version: result.root.version,
        root_digest: hex::encode(result.root.digest),
        operation_id: result.operation_id,
    })
}

/// memory—v1: Mount only the T2 routes; permission middleware remains the gate.
pub fn governance_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/governance/bindings",
            post(binding_create).delete(binding_remove),
        )
        .route("/governance/bindings/confirm", post(binding_confirm))
        .route(
            "/governance/bindings/confirm/batch",
            post(binding_confirmation_batch),
        )
        .route(
            "/governance/bindings/revoke-confirmation",
            post(revoke_confirmation),
        )
        .route("/governance/rule-sets", post(rule_set_create))
        .route("/governance/rule-sets/publish", post(version_publish))
        .route("/governance/rule-sets/retire", post(rule_set_retire))
        .route("/governance/user-cards", post(user_card_create))
        .route("/governance/user-cards/enable", post(user_card_enable))
        .route("/governance/user-cards/disable", post(user_card_disable))
}

// memory—v1: Recheck the startup-frozen batch limit before constructing a candidate.
async fn binding_confirmation_batch(
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<ApiResponse<GovernanceMutationResponse>>, GovernanceError> {
    let root = root_scope(&request)?;
    let session = request
        .extensions()
        .get::<RequestSessionExtension>()
        .cloned()
        .ok_or_else(|| AppError(AstralError::Pending("session unavailable".into())))?;
    let admission = request
        .extensions()
        .get::<MemoryV1BatchAdmission>()
        .cloned()
        .ok_or_else(|| {
            AppError(AstralError::Pending(
                "batch authorization admission unavailable".into(),
            ))
        })?;
    let bound = request
        .extensions()
        .get::<MemoryV1BoundRequest>()
        .cloned()
        .ok_or_else(|| AppError(AstralError::Pending("bound request unavailable".into())))?;
    let actual_operation =
        astral_common::middleware::request_binding::request_operation_id(&request)
            .map_err(|_| validation_error("operation_id"))?;
    let actual_fingerprint =
        astral_common::middleware::request_binding::fingerprint_bound_http_request(
            &request,
            &bound.body,
        );
    if actual_operation != bound.operation_id
        || admission.operation_id() != bound.operation_id.as_bytes()
        || actual_fingerprint != bound.fingerprint
        || admission.operation_fingerprint() != bound.fingerprint.as_bytes()
    {
        return Err(AppError(AstralError::Permission(
            "AUTHORIZATION_BINDING_MISMATCH".into(),
        ))
        .into());
    }
    build_binding_confirmation_batch_candidate(
        &root,
        &session,
        &admission,
        &bound,
        state.config.memory_v1_confirmation_batch_limit,
    )?;
    // The candidate is deliberately discarded until the durable audit and
    // restricted root-commit owner is installed. No mutation is attempted.
    Err(AppError(AstralError::Pending(
        "governance audit and operation reconciliation unavailable".into(),
    ))
    .into())
}

async fn binding_create(
    request: Request,
) -> Result<Json<ApiResponse<GovernanceMutationResponse>>, GovernanceError> {
    let bound = request
        .extensions()
        .get::<MemoryV1BoundRequest>()
        .ok_or_else(|| AppError(AstralError::Pending("bound request unavailable".into())))?;
    let overlay_only = crate::api::permission_check::is_overlay_only_request(
        &root_scope(&request)?,
        "/governance/bindings",
        &bound.body,
    )
    .map_err(|_| {
        AppError(AstralError::Pending(
            "binding classification unavailable".into(),
        ))
    })?;
    let additional_actions: &[&str] = if overlay_only {
        &["confirm", "create-overlay-only"]
    } else {
        &["confirm"]
    };
    let context = admitted_context(&request, "binding", "create", additional_actions)?;
    let body: BindingCreateRequest = parse_body(&context.bound)?;
    let binding_id = parse_id(&body.binding_id, "binding_id")?;
    let user_card_id = parse_id(&body.user_card_id, "user_card_id")?;
    let rule_set_id = parse_id(&body.rule_set_id, "rule_set_id")?;
    let confirmation_id = parse_id(&body.confirmation_id, "confirmation_id")?;
    let (facts, version) = root_scope(&request)?
        .with_reader(|reader| {
            let facts = reader.binding_create_target(user_card_id, rule_set_id)?;
            let version = reader.selected_version_bytes(rule_set_id)?;
            Ok::<_, astral_authorization_root::memory_v1_root::RootError>((facts, version))
        })
        .map_err(|_| AppError(AstralError::Pending("root unavailable".into())))?
        .map_err(|_| AppError(AstralError::Pending("target unavailable".into())))?;
    check_target(&context, binding_id, facts)?;
    if overlay_only && facts.owner_user_id == context.actor {
        return Err(AppError(AstralError::Permission("SELF_OVERLAY_ONLY_CREATION".into())).into());
    }
    let timestamp = time_bytes(context.trusted_time);
    let mutation = ManagementMutationV2::BindingCreate {
        row: BindingRow {
            binding_id,
            user_card_id,
            rule_set_id,
            binding_layer: binding_layer(&body.binding_layer)?,
            valid_from: body.valid_from,
            valid_until: body.valid_until,
            owner_scope: body.owner_scope,
            tenant_scope: body.tenant_scope,
            removed_at: None,
            removed_by: None,
        },
        confirmation: BindingConfirmationRow {
            confirmation_id,
            binding_id,
            rule_set_id,
            version_bytes: version,
            confirmer_user_id: context.actor,
            scope_bytes: bounded_text(
                body.confirmation_scope,
                "confirmation_scope",
                MAX_SCOPE_BYTES,
            )?,
            operation_id: operation_bytes(&context.bound),
            confirmed_at_bytes: timestamp,
            revoked_at: None,
            revoked_by: None,
        },
    };
    let response = commit(context, mutation)?;
    Ok(Json(ApiResponse::success(response)))
}

async fn binding_confirm(
    request: Request,
) -> Result<Json<ApiResponse<GovernanceMutationResponse>>, GovernanceError> {
    let context = admitted_context(&request, "binding", "confirm", &[])?;
    let body: BindingConfirmRequest = parse_body(&context.bound)?;
    let binding_id = parse_id(&body.binding_id, "binding_id")?;
    let confirmation_id = parse_id(&body.confirmation_id, "confirmation_id")?;
    let (facts, version) = root_scope(&request)?
        .with_reader(|reader| {
            let target = reader.binding_target(binding_id)?;
            let version = reader.selected_version_bytes(target.rule_set_id)?;
            Ok::<_, astral_authorization_root::memory_v1_root::RootError>((target, version))
        })
        .map_err(|_| AppError(AstralError::Pending("root unavailable".into())))?
        .map_err(|_| AppError(AstralError::Pending("root unavailable".into())))?;
    check_target(&context, binding_id, facts)?;
    let rule_set_id = facts.rule_set_id;
    if body
        .rule_set_id
        .as_deref()
        .is_some_and(|value| parse_id(value, "rule_set_id").ok() != Some(rule_set_id))
    {
        return Err(validation_error("rule_set_id").into());
    }
    let mutation = ManagementMutationV2::ConfirmationCreate {
        row: BindingConfirmationRow {
            confirmation_id,
            binding_id,
            rule_set_id,
            version_bytes: version,
            confirmer_user_id: context.actor,
            scope_bytes: bounded_text(body.scope, "scope", MAX_SCOPE_BYTES)?,
            operation_id: operation_bytes(&context.bound),
            confirmed_at_bytes: time_bytes(context.trusted_time),
            revoked_at: None,
            revoked_by: None,
        },
    };
    Ok(Json(ApiResponse::success(commit(context, mutation)?)))
}

async fn binding_remove(
    request: Request,
) -> Result<Json<ApiResponse<GovernanceMutationResponse>>, GovernanceError> {
    let context = admitted_context(&request, "binding", "remove", &[])?;
    let body: GovernanceBindingRemoveBody = parse_body(&context.bound)?;
    let binding_id = parse_id(&body.binding_id, "binding_id")?;
    let facts = root_scope(&request)?
        .with_reader(|reader| reader.binding_target(binding_id))
        .map_err(|_| AppError(AstralError::Pending("root unavailable".into())))?
        .map_err(|_| AppError(AstralError::Pending("target unavailable".into())))?;
    check_target(&context, binding_id, facts)?;
    let mutation = ManagementMutationV2::BindingRemove {
        binding_id,
        removed_at: context.trusted_time,
        removed_by: context.actor,
    };
    Ok(Json(ApiResponse::success(commit(context, mutation)?)))
}

async fn revoke_confirmation(
    request: Request,
) -> Result<Json<ApiResponse<GovernanceMutationResponse>>, GovernanceError> {
    let context = admitted_context(&request, "binding", "revoke-confirmation", &[])?;
    let body: GovernanceRevokeConfirmationBody = parse_body(&context.bound)?;
    let confirmation_id = parse_id(&body.confirmation_id, "confirmation_id")?;
    let facts = root_scope(&request)?
        .with_reader(|reader| reader.confirmation_target(confirmation_id))
        .map_err(|_| AppError(AstralError::Pending("root unavailable".into())))?
        .map_err(|_| AppError(AstralError::Pending("target unavailable".into())))?;
    check_target(&context, confirmation_id, facts)?;
    let mutation = ManagementMutationV2::ConfirmationRevoke {
        confirmation_id,
        revoked_at: context.trusted_time,
        revoked_by: context.actor,
    };
    Ok(Json(ApiResponse::success(commit(context, mutation)?)))
}

async fn rule_set_create(
    request: Request,
) -> Result<Json<ApiResponse<GovernanceMutationResponse>>, GovernanceError> {
    let context = admitted_context(&request, "rule_set", "create", &["confirm-change"])?;
    let body: RuleSetCreateRequest = parse_body(&context.bound)?;
    let rule_set_id = parse_id(&body.rule_set_id, "rule_set_id")?;
    let owner_tenant_id = parse_id(&body.owner_tenant_id, "owner_tenant_id")?;
    let facts = root_scope(&request)?
        .with_reader(|reader| reader.rule_set_create_target(rule_set_id, owner_tenant_id))
        .map_err(|_| AppError(AstralError::Pending("root unavailable".into())))?
        .map_err(|_| AppError(AstralError::Pending("target unavailable".into())))?;
    check_target(&context, rule_set_id, facts)?;
    let version_bytes = bounded_text(body.version_bytes, "version_bytes", 255)?;
    let content = bounded_text(body.content, "content", MAX_CONTENT_BYTES)?;
    let change_confirmation_id = parse_id(&body.change_confirmation_id, "change_confirmation_id")?;
    let timestamp = time_bytes(context.trusted_time);
    let version = canonical_version(
        version_bytes.clone(),
        content,
        timestamp.clone(),
        rule_set_id,
    );
    let mutation = ManagementMutationV2::RuleSetCreate {
        rule_set: RuleSetRow {
            status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
            rule_set_id,
            owner_tenant_id,
            current_version_bytes: version_bytes.clone(),
        },
        version,
        change_confirmation: RuleSetChangeConfirmationRow {
            confirmation_id: change_confirmation_id,
            rule_set_id,
            version_bytes,
            confirmer_user_id: context.actor,
            affected_scope_bytes: bounded_text(
                body.affected_scope,
                "affected_scope",
                MAX_SCOPE_BYTES,
            )?,
            operation_id: operation_bytes(&context.bound),
            confirmed_at_bytes: timestamp,
            revoked_at: None,
            revoked_by: None,
        },
    };
    Ok(Json(ApiResponse::success(commit(context, mutation)?)))
}

async fn version_publish(
    request: Request,
) -> Result<Json<ApiResponse<GovernanceMutationResponse>>, GovernanceError> {
    let mut context =
        admitted_context(&request, "rule_set", "version-publish", &["confirm-change"])?;
    let body: VersionPublishRequest = parse_body(&context.bound)?;
    let rule_set_id = parse_id(&body.rule_set_id, "rule_set_id")?;
    let (facts, selected) = root_scope(&request)?
        .with_reader(|reader| {
            Ok::<_, astral_authorization_root::memory_v1_root::RootError>((
                reader.active_rule_set_target(rule_set_id)?,
                reader.selected_version_row(rule_set_id)?,
            ))
        })
        .map_err(|_| AppError(AstralError::Pending("root unavailable".into())))?
        .map_err(|_| AppError(AstralError::Pending("target unavailable".into())))?;
    check_target(&context, rule_set_id, facts)?;
    context.previous_rule_set_state = Some((
        selected.version_bytes.clone(),
        version_hash(&selected.hash_bytes)?,
    ));
    let version_bytes = bounded_text(body.version_bytes, "version_bytes", 255)?;
    let content = bounded_text(body.content, "content", MAX_CONTENT_BYTES)?;
    let change_confirmation_id = parse_id(&body.change_confirmation_id, "change_confirmation_id")?;
    let timestamp = time_bytes(context.trusted_time);
    let version = canonical_version(
        version_bytes.clone(),
        content,
        timestamp.clone(),
        rule_set_id,
    );
    let mutation = ManagementMutationV2::VersionPublish {
        rule_set_id,
        version_row: version,
        new_current_version: version_bytes.clone(),
        change_confirmation: RuleSetChangeConfirmationRow {
            confirmation_id: change_confirmation_id,
            rule_set_id,
            version_bytes,
            confirmer_user_id: context.actor,
            affected_scope_bytes: bounded_text(
                body.affected_scope,
                "affected_scope",
                MAX_SCOPE_BYTES,
            )?,
            operation_id: operation_bytes(&context.bound),
            confirmed_at_bytes: timestamp,
            revoked_at: None,
            revoked_by: None,
        },
    };
    Ok(Json(ApiResponse::success(commit(context, mutation)?)))
}

// memory—v1: Bind retirement to its own admission and the same root target.
async fn rule_set_retire(
    request: Request,
) -> Result<Json<ApiResponse<GovernanceMutationResponse>>, GovernanceError> {
    let context = admitted_context(&request, "rule_set", "retire", &[])?;
    let body: RuleSetRetireRequest = parse_body(&context.bound)?;
    let rule_set_id = parse_id(&body.rule_set_id, "rule_set_id")?;
    let (facts, version_row) = root_scope(&request)?
        .with_reader(|reader| {
            let facts = reader.active_rule_set_target(rule_set_id)?;
            let version = reader.selected_version_row(rule_set_id)?;
            Ok::<_, astral_authorization_root::memory_v1_root::RootError>((facts, version))
        })
        .map_err(|_| AppError(AstralError::Pending("root unavailable".into())))?
        .map_err(|_| AppError(AstralError::Pending("target unavailable".into())))?;
    check_target(&context, rule_set_id, facts)?;
    let hash = version_hash(&version_row.hash_bytes)?;
    let mutation = ManagementMutationV2::RuleSetRetire { rule_set_id };
    let mut context = context;
    context.previous_rule_set_state = Some((version_row.version_bytes.clone(), hash));
    Ok(Json(ApiResponse::success(commit(context, mutation)?)))
}

// memory—v1: Construct only an unbound candidate after the independent create admission.
async fn user_card_create(
    request: Request,
) -> Result<Json<ApiResponse<GovernanceMutationResponse>>, GovernanceError> {
    let context = admitted_context(&request, "user_card", "create", &[])?;
    let body: UserCardCreateRequest = parse_body(&context.bound)?;
    let user_card_id = parse_id(&body.user_card_id, "user_card_id")?;
    let user_id = parse_id(&body.user_id, "user_id")?;
    let tenant_id = parse_id(&body.tenant_id, "tenant_id")?;
    let facts = root_scope(&request)?
        .with_reader(|reader| reader.user_card_create_target(user_card_id, user_id, tenant_id))
        .map_err(|_| AppError(AstralError::Pending("root unavailable".into())))?
        .map_err(|_| AppError(AstralError::Pending("target unavailable".into())))?;
    check_target(&context, user_card_id, facts)?;
    let mutation = ManagementMutationV2::UserCardCreate {
        row: UserCardRow {
            user_card_id,
            user_id,
            tenant_id,
            status: UserCardStatus::Active,
        },
    };
    Ok(Json(ApiResponse::success(commit(context, mutation)?)))
}

// memory—v1: Enable is separately authorized and cannot bypass commit PENDING.
async fn user_card_enable(
    request: Request,
) -> Result<Json<ApiResponse<GovernanceMutationResponse>>, GovernanceError> {
    let context = admitted_context(&request, "user_card", "enable", &[])?;
    let body: UserCardEnableRequest = parse_body(&context.bound)?;
    let user_card_id = parse_id(&body.user_card_id, "user_card_id")?;
    let facts = root_scope(&request)?
        .with_reader(|reader| reader.user_card_target(user_card_id))
        .map_err(|_| AppError(AstralError::Pending("root unavailable".into())))?
        .map_err(|_| AppError(AstralError::Pending("target unavailable".into())))?;
    check_target(&context, user_card_id, facts)?;
    let mutation = ManagementMutationV2::UserCardStatus {
        user_card_id,
        status: UserCardStatus::Active,
    };
    Ok(Json(ApiResponse::success(commit(context, mutation)?)))
}

async fn user_card_disable(
    request: Request,
) -> Result<Json<ApiResponse<GovernanceMutationResponse>>, GovernanceError> {
    let context = admitted_context(&request, "user_card", "disable", &[])?;
    let body: GovernanceUserCardDisableBody = parse_body(&context.bound)?;
    let user_card_id = parse_id(&body.user_card_id, "user_card_id")?;
    let facts = root_scope(&request)?
        .with_reader(|reader| reader.user_card_target(user_card_id))
        .map_err(|_| AppError(AstralError::Pending("root unavailable".into())))?
        .map_err(|_| AppError(AstralError::Pending("target unavailable".into())))?;
    check_target(&context, user_card_id, facts)?;
    let mutation = ManagementMutationV2::UserCardStatus {
        user_card_id,
        status: UserCardStatus::Disabled,
    };
    Ok(Json(ApiResponse::success(commit(context, mutation)?)))
}

/// memory—v1: Legacy tracing fields for a governance mutation.
///
/// The current governance handlers do not call this helper. Emitting this event
/// writes a log only; it does not establish the required durable audit record.
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

/// memory—v1 §4.11 B-1.2: confirm-type governance entries require all-owner
/// scope so the engine does not silently make cross-user confirmation impossible.
pub const GOVERNANCE_SCOPE_REQUIREMENT: &str =
    "confirm-type governance entries must declare ownerScope:all (B-1.2 N-1); \
     entries without this are structurally unable to confirm for other users";

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::service::memory_v1_governance_commit::MemoryV1GovernanceCommitResponse;
    use astral_authorization_root::memory_v1_db_rows::{
        CandidateRows, CurrentSelection, IdentityCardRow, TenantRow, UserRow,
    };
    use astral_authorization_root::memory_v1_hamt::CandidateBudget;
    use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
    use astral_authorization_root::memory_v1_request::RequestRootScope;
    use astral_authorization_root::memory_v1_root::install_process_root;
    use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
    use astral_common::middleware::permission_check_shared::AuthorizationPendingRefusal;
    use astral_types::memory_v1::CandidateIdentity;
    use axum::body::{Body, Bytes};
    use policy_engine::memory_v1_batch::MemoryV1BatchRequest;
    use policy_engine::memory_v1_formal::{MemoryV1Decision, MemoryV1Request};
    use policy_engine::PolicyEngine;

    #[derive(Clone)]
    struct RecordingCommitPort {
        seen: Arc<Mutex<Vec<MemoryV1GovernanceCommitRequest>>>,
        response: Option<MemoryV1GovernanceCommitResponse>,
    }

    impl MemoryV1GovernanceCommitPort for RecordingCommitPort {
        fn commit(
            &self,
            request: MemoryV1GovernanceCommitRequest,
        ) -> Result<MemoryV1GovernanceCommitResponse, AstralError> {
            self.seen.lock().unwrap().push(request);
            self.response.clone().ok_or_else(|| {
                AstralError::Pending("recording owner has no configured response".into())
            })
        }
    }

    fn test_root_metadata(version: u64, digest: [u8; 32]) -> RootMetadata {
        RootMetadata {
            instance_id: astral_authorization_root::memory_v1_root::RootInstanceId::from_uuid(
                uuid::Uuid::from_bytes([9; 16]),
            ),
            version,
            digest,
            budget: CandidateBudget {
                max_table_rows: 1,
                max_bindings_per_read: 1,
            },
            row_count: 1,
            status: RootStatus::Serving,
        }
    }

    #[test]
    fn commit_port_receives_the_complete_bound_candidate() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let before = test_root_metadata(7, [7; 32]);
        let after = test_root_metadata(8, [8; 32]);
        let port = RecordingCommitPort {
            seen: Arc::clone(&seen),
            response: Some(MemoryV1GovernanceCommitResponse {
                operation_id: "op".into(),
                root: after,
            }),
        };
        let mutation = ManagementMutationV2::UserCardStatus {
            user_card_id: [2; 16],
            status: UserCardStatus::Disabled,
        };
        let result = commit(
            MutationContext {
                bound: MemoryV1BoundRequest {
                    operation_id: "op".into(),
                    fingerprint: "ab".repeat(32),
                    body: Bytes::new(),
                },
                root: before,
                commit_port: Arc::new(port),
                actor: [1; 16],
                actor_identity_card: [4; 16],
                target: [2; 16],
                target_tenant: [3; 16],
                target_owner: Some([1; 16]),
                trusted_time: 123,
                previous_rule_set_state: None,
            },
            mutation.clone(),
        )
        .expect("proof-backed response shape is accepted");
        assert_eq!(result.operation_id, "op");
        assert_eq!(result.root_version, 8);
        assert_eq!(result.root_digest, hex::encode([8; 32]));

        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.operation_id, "op");
        assert_eq!(request.request_fingerprint, "ab".repeat(32));
        assert_eq!(request.root, before);
        assert_eq!(request.actor, [1; 16]);
        assert_eq!(request.target, [2; 16]);
        assert_eq!(request.target_tenant, [3; 16]);
        assert_eq!(request.target_owner, Some([1; 16]));
        assert_eq!(request.trusted_time_unix_seconds, 123);
        assert_eq!(
            astral_authorization_root::memory_v1_mutation_wire::encode_mutation(&request.mutation)
                .unwrap(),
            astral_authorization_root::memory_v1_mutation_wire::encode_mutation(&mutation).unwrap()
        );
    }

    #[test]
    fn commit_rejects_a_response_bound_to_another_operation_or_root_version() {
        let cases = [
            MemoryV1GovernanceCommitResponse {
                operation_id: "other-op".into(),
                root: test_root_metadata(8, [8; 32]),
            },
            MemoryV1GovernanceCommitResponse {
                operation_id: "op".into(),
                root: test_root_metadata(9, [9; 32]),
            },
        ];
        for response in cases {
            let result = commit(
                MutationContext {
                    bound: MemoryV1BoundRequest {
                        operation_id: "op".into(),
                        fingerprint: "cd".repeat(32),
                        body: Bytes::new(),
                    },
                    root: test_root_metadata(7, [7; 32]),
                    commit_port: Arc::new(RecordingCommitPort {
                        seen: Arc::new(Mutex::new(Vec::new())),
                        response: Some(response),
                    }),
                    actor: [1; 16],
                    actor_identity_card: [4; 16],
                    target: [2; 16],
                    target_tenant: [3; 16],
                    target_owner: None,
                    trusted_time: 123,
                    previous_rule_set_state: None,
                },
                ManagementMutationV2::UserCardStatus {
                    user_card_id: [2; 16],
                    status: UserCardStatus::Disabled,
                },
            );
            assert!(matches!(
                result,
                Err(AppError(AstralError::Pending(message)))
                    if message == "governance commit proof does not match request root"
            ));
        }
    }

    #[test]
    fn legacy_route_descriptions_match_registered_primary_actions() {
        use crate::api::permission_check::MEMORY_V1_ROUTE_REGISTRATIONS;

        for legacy in GOVERNANCE_ROUTE_DECLARATIONS {
            assert!(MEMORY_V1_ROUTE_REGISTRATIONS.iter().any(|registered| {
                registered.method == legacy.method
                    && registered.path == legacy.path
                    && registered.resource == legacy.resource
                    && registered.action == legacy.action
            }));
        }
        assert_eq!(
            MEMORY_V1_ROUTE_REGISTRATIONS
                .iter()
                .filter(|registered| registered.path.starts_with("/governance/"))
                .count(),
            GOVERNANCE_ROUTE_DECLARATIONS.len()
        );
    }

    #[test]
    fn legacy_governance_dtos_keep_their_shape_without_authorizing_mutations() {
        let binding: GovernanceBindingCreateBody = serde_json::from_value(serde_json::json!({
            "binding_id": "binding",
            "user_card_id": "card",
            "rule_set_id": "rules",
            "binding_layer": "BASE",
            "legacy_extra": true,
        }))
        .unwrap();
        let GovernanceBindingCreateBody {
            binding_id,
            user_card_id,
            rule_set_id,
            binding_layer,
        } = binding;
        assert_eq!(
            (binding_id, user_card_id, rule_set_id, binding_layer),
            (
                "binding".into(),
                "card".into(),
                "rules".into(),
                "BASE".into()
            )
        );
        let confirm = GovernanceBindingConfirmBody {
            binding_id: "binding".into(),
            rule_set_id: "rules".into(),
        };
        assert_eq!(confirm.rule_set_id, "rules");
        let _ = GovernanceRuleSetCreateBody {
            rule_set_id: "rules".into(),
            owner_tenant_id: "tenant".into(),
            content: "content".into(),
        };
        let _ = GovernanceVersionPublishBody {
            rule_set_id: "rules".into(),
            content: "content".into(),
        };
        assert!(
            serde_json::from_value::<BindingCreateRequest>(serde_json::json!({
                "binding_id": "binding",
                "user_card_id": "card",
                "rule_set_id": "rules",
                "binding_layer": "BASE",
            }))
            .is_err()
        );
    }

    #[test]
    // memory—v1: The parser applies both the configured and hard count limits.
    fn confirmation_batch_parser_enforces_operational_limit() {
        let body = |count: usize| {
            serde_json::json!({
                "items": (0..count).map(|index| serde_json::json!({
                    "sequence": index,
                    "binding_id": MemoryId::from_bytes(((index + 1) as u128).to_be_bytes()).to_string(),
                    "confirmation_id": MemoryId::from_bytes(((index + 101) as u128).to_be_bytes()).to_string(),
                    "rule_set_id": MemoryId::from_bytes([7; 16]).to_string(),
                    "scope": "scope",
                })).collect::<Vec<_>>()
            })
            .to_string()
        };
        let two = MemoryV1ConfirmationBatchLimit::new(2).unwrap();
        assert!(parse_binding_confirmation_batch_items(body(0).as_bytes(), two).is_err());
        assert_eq!(
            parse_binding_confirmation_batch_items(body(1).as_bytes(), two)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            parse_binding_confirmation_batch_items(body(2).as_bytes(), two)
                .unwrap()
                .len(),
            2
        );
        assert!(parse_binding_confirmation_batch_items(body(3).as_bytes(), two).is_err());
        let hard = MemoryV1ConfirmationBatchLimit::default();
        assert_eq!(
            parse_binding_confirmation_batch_items(body(64).as_bytes(), hard)
                .unwrap()
                .len(),
            64
        );
        assert!(parse_binding_confirmation_batch_items(body(65).as_bytes(), hard).is_err());
    }

    #[test]
    // memory—v1: Exercise candidate construction with the same operational bound.
    fn batch_candidate_helper_derives_root_facts_without_mounting_a_route() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_BATCH_CANDIDATE_HELPER_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "api::governance_routes::tests::batch_candidate_helper_derives_root_facts_without_mounting_a_route",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "stdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            return;
        }

        let id = |value: u8| [value; 16];
        let actor_rules = br#"{"rules":[{"ruleId":"confirm","resource":"binding","action":"confirm","effect":"ALLOW","ownerScope":"all","tenantScope":"self"}]}"#;
        let empty_rules = br#"{"rules":[]}"#;
        let rows = CandidateRows {
            users: (1..=3)
                .map(|value| UserRow { user_id: id(value) })
                .collect(),
            identity_cards: (1..=3)
                .map(|value| IdentityCardRow {
                    identity_card_id: id(value + 10),
                    user_id: id(value),
                })
                .collect(),
            tenants: vec![TenantRow {
                tenant_id: id(3),
                parent_tenant_id: None,
            }],
            user_cards: vec![
                UserCardRow {
                    user_card_id: id(4),
                    user_id: id(1),
                    tenant_id: id(3),
                    status: UserCardStatus::Active,
                },
                UserCardRow {
                    user_card_id: id(5),
                    user_id: id(2),
                    tenant_id: id(3),
                    status: UserCardStatus::Active,
                },
                UserCardRow {
                    user_card_id: id(6),
                    user_id: id(3),
                    tenant_id: id(3),
                    status: UserCardStatus::Active,
                },
            ],
            rule_sets: vec![
                RuleSetRow {
                    status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                    rule_set_id: id(10),
                    owner_tenant_id: id(3),
                    current_version_bytes: vec![1],
                },
                RuleSetRow {
                    status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                    rule_set_id: id(11),
                    owner_tenant_id: id(3),
                    current_version_bytes: vec![1],
                },
                RuleSetRow {
                    status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                    rule_set_id: id(12),
                    owner_tenant_id: id(3),
                    current_version_bytes: vec![1],
                },
            ],
            rule_set_versions: vec![
                canonical_version(vec![1], actor_rules.to_vec(), vec![1], id(10)),
                canonical_version(vec![1], empty_rules.to_vec(), vec![1], id(11)),
                canonical_version(vec![1], empty_rules.to_vec(), vec![1], id(12)),
            ],
            bindings: vec![
                BindingRow {
                    binding_id: id(20),
                    user_card_id: id(4),
                    rule_set_id: id(10),
                    binding_layer: BindingLayer::Base,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::AllUsers,
                    tenant_scope: MemoryV1TenantScope::SelfTenant,
                    removed_at: None,
                    removed_by: None,
                },
                BindingRow {
                    binding_id: id(21),
                    user_card_id: id(5),
                    rule_set_id: id(11),
                    binding_layer: BindingLayer::Base,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::SelfUser,
                    tenant_scope: MemoryV1TenantScope::SelfTenant,
                    removed_at: None,
                    removed_by: None,
                },
                BindingRow {
                    binding_id: id(22),
                    user_card_id: id(6),
                    rule_set_id: id(12),
                    binding_layer: BindingLayer::Base,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::SelfUser,
                    tenant_scope: MemoryV1TenantScope::SelfTenant,
                    removed_at: None,
                    removed_by: None,
                },
            ],
            binding_confirmations: vec![
                BindingConfirmationRow {
                    confirmation_id: id(120),
                    binding_id: id(20),
                    rule_set_id: id(10),
                    version_bytes: vec![1],
                    confirmer_user_id: id(1),
                    scope_bytes: vec![1],
                    operation_id: vec![1],
                    confirmed_at_bytes: vec![1],
                    revoked_at: None,
                    revoked_by: None,
                },
                BindingConfirmationRow {
                    confirmation_id: id(121),
                    binding_id: id(21),
                    rule_set_id: id(11),
                    version_bytes: vec![1],
                    confirmer_user_id: id(1),
                    scope_bytes: vec![1],
                    operation_id: vec![1],
                    confirmed_at_bytes: vec![1],
                    revoked_at: Some(1),
                    revoked_by: Some(id(1)),
                },
                BindingConfirmationRow {
                    confirmation_id: id(122),
                    binding_id: id(22),
                    rule_set_id: id(12),
                    version_bytes: vec![1],
                    confirmer_user_id: id(1),
                    scope_bytes: vec![1],
                    operation_id: vec![1],
                    confirmed_at_bytes: vec![1],
                    revoked_at: Some(1),
                    revoked_by: Some(id(1)),
                },
            ],
            rule_set_change_confirmations: (10..=12)
                .map(|rule_set_id| RuleSetChangeConfirmationRow {
                    confirmation_id: id(rule_set_id + 20),
                    rule_set_id: id(rule_set_id),
                    version_bytes: vec![1],
                    confirmer_user_id: id(1),
                    affected_scope_bytes: vec![1],
                    operation_id: vec![1],
                    confirmed_at_bytes: vec![1],
                    revoked_at: None,
                    revoked_by: None,
                })
                .collect(),
        };
        let owner = install_process_root(
            rows,
            (10..=12)
                .map(|rule_set_id| CurrentSelection {
                    rule_set_id: id(rule_set_id),
                    version_bytes: vec![1],
                })
                .collect(),
            CandidateBudget {
                max_table_rows: 64,
                max_bindings_per_read: 8,
            },
        )
        .unwrap();
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "binding".into(),
                actions: vec!["confirm".into()],
            }])
            .unwrap();
        // The isolated fixture exercises rule evaluation, not adoption evidence.
        owner.adopt_serving_for_isolated_tests().unwrap();

        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let scope = RequestRootScope::new(owner.handle(), uuid::Uuid::new_v4());
        let root = scope.extension();
        let identity = CandidateIdentity {
            user_id: MemoryId::from_bytes(id(1)),
            identity_card_id: MemoryId::from_bytes(id(11)),
            user_card_id: MemoryId::from_bytes(id(4)),
            tenant_id: MemoryId::from_bytes(id(3)),
        };
        let trusted_now = now_unix_seconds().unwrap();
        let issued = authority
            .identity_session_adapter()
            .issue_verified_session_in_root(&root, identity, trusted_now - 60, 3600)
            .unwrap();
        let session = authority
            .verifier()
            .verify_and_bind(issued.credential(), trusted_now, &root)
            .unwrap();
        let operation_id = "batch-http-candidate";
        let target_items = [
            MemoryV1BatchItem {
                sequence: 0,
                binding_id: id(21),
                confirmation_id: id(150),
            },
            MemoryV1BatchItem {
                sequence: 1,
                binding_id: id(22),
                confirmation_id: id(151),
            },
        ];
        let body = Bytes::from(
            serde_json::json!({
                "items": [
                    {"sequence": 0, "binding_id": MemoryId::from_bytes(id(21)).to_string(), "confirmation_id": MemoryId::from_bytes(id(150)).to_string(), "rule_set_id": MemoryId::from_bytes(id(11)).to_string(), "scope": "client-scope-a"},
                    {"sequence": 1, "binding_id": MemoryId::from_bytes(id(22)).to_string(), "confirmation_id": MemoryId::from_bytes(id(151)).to_string(), "rule_set_id": MemoryId::from_bytes(id(12)).to_string(), "scope": "client-scope-b"}
                ]
            })
            .to_string(),
        );
        let bound_for = |body: Bytes| {
            let request = Request::builder()
                .method("POST")
                .uri("/governance/bindings/confirm/batch")
                .header("x-request-id", operation_id)
                .body(Body::empty())
                .unwrap();
            let fingerprint =
                astral_common::middleware::request_binding::fingerprint_bound_http_request(
                    &request, &body,
                );
            MemoryV1BoundRequest {
                operation_id: operation_id.into(),
                fingerprint,
                body,
            }
        };
        let bound = bound_for(body.clone());
        let evaluation = PolicyEngine::new().evaluate_memory_v1_confirmation_batch(
            &root,
            &session,
            &MemoryV1BatchRequest {
                operation_id: operation_id.as_bytes(),
                operation_fingerprint: bound.fingerprint.as_bytes(),
                items: &target_items,
            },
        );
        assert_eq!(evaluation.decision, MemoryV1Decision::Allow);
        let admission = evaluation.admission.expect("batch evaluator admission");
        let before = owner.handle().metadata().unwrap();
        let limit = MemoryV1ConfirmationBatchLimit::new(2).unwrap();
        let plan =
            build_binding_confirmation_batch_candidate(&root, &session, &admission, &bound, limit)
                .expect("candidate plan is constructed");
        assert!(build_binding_confirmation_batch_candidate(
            &root,
            &session,
            &admission,
            &bound,
            MemoryV1ConfirmationBatchLimit::new(1).unwrap(),
        )
        .is_err());
        assert_eq!(owner.handle().metadata().unwrap(), before);
        // The value is only a candidate: this test calls the helper directly,
        // without invoking the mounted route or any RootOwner mutation API.
        match plan.mutation() {
            ManagementMutationV2::ConfirmationBatch { rows } => {
                assert_eq!(rows.len(), 2);
                assert_eq!(rows[0].version_bytes, vec![1]);
                assert_eq!(rows[1].version_bytes, vec![1]);
                assert_eq!(rows[0].confirmer_user_id, id(1));
                assert_eq!(rows[1].confirmer_user_id, id(1));
                assert_eq!(rows[0].operation_id, operation_id.as_bytes());
                assert_eq!(rows[1].operation_id, operation_id.as_bytes());
                assert_eq!(
                    rows[0].confirmed_at_bytes,
                    admission.trusted_time_unix_seconds().to_be_bytes()
                );
                assert_eq!(rows[1].scope_bytes, b"client-scope-b");
            }
            _ => panic!("unexpected mutation candidate"),
        }

        let mut wrong_body = serde_json::json!({
            "items": [
                {"sequence": 1, "binding_id": MemoryId::from_bytes(id(21)).to_string(), "confirmation_id": MemoryId::from_bytes(id(150)).to_string(), "rule_set_id": MemoryId::from_bytes(id(11)).to_string(), "scope": "client-scope-a"},
                {"sequence": 0, "binding_id": MemoryId::from_bytes(id(22)).to_string(), "confirmation_id": MemoryId::from_bytes(id(151)).to_string(), "rule_set_id": MemoryId::from_bytes(id(12)).to_string(), "scope": "client-scope-b"}
            ]
        });
        let wrong_bound = bound_for(Bytes::from(wrong_body.take().to_string()));
        assert!(build_binding_confirmation_batch_candidate(
            &root,
            &session,
            &admission,
            &wrong_bound,
            limit,
        )
        .is_err());
        let empty_bound = bound_for(Bytes::from_static(br#"{"items":[]}"#));
        assert!(build_binding_confirmation_batch_candidate(
            &root,
            &session,
            &admission,
            &empty_bound,
            limit,
        )
        .is_err());
        let mut mismatched_operation = bound.clone();
        mismatched_operation.operation_id = "other-operation".into();
        assert!(build_binding_confirmation_batch_candidate(
            &root,
            &session,
            &admission,
            &mismatched_operation,
            limit,
        )
        .is_err());
    }

    // memory—v1: Real compound admissions remain bound to each governance request.
    #[tokio::test]
    async fn rule_set_change_route_admissions_bind_intent_and_request() {
        use crate::api::permission_check::{evaluate_route_action, memory_v1_route_declaration};
        use axum::http::Method;
        use policy_engine::memory_v1_compound::{
            MemoryV1CompoundAction, MemoryV1CompoundRequest, MemoryV1CompoundTargetKind,
        };
        use policy_engine::memory_v1_formal::MemoryV1DenySource;

        const CHILD: &str = "ASTRAL_MEMORY_V1_CHANGE_ROUTE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "api::governance_routes::tests::rule_set_change_route_admissions_bind_intent_and_request", "--nocapture"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "stdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            return;
        }

        let (user, identity_card, tenant, card, rules, binding, other_rules, new_rules) = (
            [1; 16], [2; 16], [3; 16], [4; 16], [5; 16], [6; 16], [9; 16], [10; 16],
        );
        let content = br#"{"rules":[{"ruleId":"create","resource":"rule_set","action":"create","effect":"ALLOW","ownerScope":"all"},{"ruleId":"publish","resource":"rule_set","action":"version-publish","effect":"ALLOW","ownerScope":"all"},{"ruleId":"confirm","resource":"rule_set","action":"confirm-change","effect":"ALLOW","ownerScope":"all"},{"ruleId":"retire","resource":"rule_set","action":"retire","effect":"ALLOW","ownerScope":"all"},{"ruleId":"enable","resource":"user_card","action":"enable","effect":"ALLOW","ownerScope":"all"},{"ruleId":"card-create","resource":"user_card","action":"create","effect":"ALLOW","ownerScope":"all"}]}"#.to_vec();
        let rows = CandidateRows {
            users: vec![UserRow { user_id: user }],
            identity_cards: vec![IdentityCardRow {
                identity_card_id: identity_card,
                user_id: user,
            }],
            tenants: vec![TenantRow {
                tenant_id: tenant,
                parent_tenant_id: None,
            }],
            user_cards: vec![
                UserCardRow {
                    user_card_id: card,
                    user_id: user,
                    tenant_id: tenant,
                    status: UserCardStatus::Active,
                },
                UserCardRow {
                    user_card_id: [11; 16],
                    user_id: user,
                    tenant_id: tenant,
                    status: UserCardStatus::Disabled,
                },
            ],
            rule_sets: vec![rules, other_rules]
                .into_iter()
                .map(|rule_set_id| RuleSetRow {
                    status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                    rule_set_id,
                    owner_tenant_id: tenant,
                    current_version_bytes: vec![1],
                })
                .collect(),
            rule_set_versions: vec![
                canonical_version(vec![1], content.clone(), vec![1], rules),
                canonical_version(vec![1], content, vec![1], other_rules),
            ],
            bindings: vec![BindingRow {
                binding_id: binding,
                user_card_id: card,
                rule_set_id: rules,
                binding_layer: BindingLayer::Base,
                valid_from: None,
                valid_until: None,
                owner_scope: MemoryV1OwnerScope::AllUsers,
                tenant_scope: MemoryV1TenantScope::SelfTenant,
                removed_at: None,
                removed_by: None,
            }],
            binding_confirmations: vec![BindingConfirmationRow {
                confirmation_id: [7; 16],
                binding_id: binding,
                rule_set_id: rules,
                version_bytes: vec![1],
                confirmer_user_id: user,
                scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            }],
            rule_set_change_confirmations: vec![rules, other_rules]
                .into_iter()
                .enumerate()
                .map(|(index, rule_set_id)| RuleSetChangeConfirmationRow {
                    confirmation_id: [20 + index as u8; 16],
                    rule_set_id,
                    version_bytes: vec![1],
                    confirmer_user_id: user,
                    affected_scope_bytes: vec![1],
                    operation_id: vec![1],
                    confirmed_at_bytes: vec![1],
                    revoked_at: None,
                    revoked_by: None,
                })
                .collect(),
        };
        let owner = install_process_root(
            rows,
            vec![rules, other_rules]
                .into_iter()
                .map(|rule_set_id| CurrentSelection {
                    rule_set_id,
                    version_bytes: vec![1],
                })
                .collect(),
            CandidateBudget {
                max_table_rows: 32,
                max_bindings_per_read: 4,
            },
        )
        .unwrap();
        owner
            .install_registry(&[
                RegistryDeclaration {
                    resource: "rule_set".into(),
                    actions: vec![
                        "create".into(),
                        "version-publish".into(),
                        "confirm-change".into(),
                        "retire".into(),
                    ],
                },
                RegistryDeclaration {
                    resource: "user_card".into(),
                    actions: vec!["enable".into(), "create".into()],
                },
            ])
            .unwrap();
        // The isolated fixture exercises compound admission without claiming provenance.
        owner.adopt_serving_for_isolated_tests().unwrap();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let scope = RequestRootScope::new(owner.handle(), uuid::Uuid::new_v4());
        let root = scope.extension();
        let credential = authority
            .identity_session_adapter()
            .issue_verified_session_in_root(
                &root,
                CandidateIdentity {
                    user_id: MemoryId::from_bytes(user),
                    identity_card_id: MemoryId::from_bytes(identity_card),
                    user_card_id: MemoryId::from_bytes(card),
                    tenant_id: MemoryId::from_bytes(tenant),
                },
                now_unix_seconds().unwrap() - 1,
                300,
            )
            .unwrap();
        let session = authority
            .verifier()
            .verify_and_bind(credential.credential(), now_unix_seconds().unwrap(), &root)
            .unwrap();
        let engine = PolicyEngine::new();

        for (path, target, primary_action, intent) in [
            (
                "/governance/rule-sets",
                new_rules,
                "create",
                MemoryV1RuleSetChangeIntent::Create,
            ),
            (
                "/governance/rule-sets/publish",
                other_rules,
                "version-publish",
                MemoryV1RuleSetChangeIntent::Publish,
            ),
        ] {
            let body = Bytes::from(if intent == MemoryV1RuleSetChangeIntent::Publish {
                serde_json::json!({
                    "rule_set_id": MemoryId::from_bytes(target).to_string(),
                    "content": "{\"rules\":[]}",
                    "version_bytes": "2",
                    "change_confirmation_id": MemoryId::from_bytes([31; 16]).to_string(),
                    "affected_scope": "tenant",
                })
                .to_string()
            } else {
                serde_json::json!({"rule_set_id": MemoryId::from_bytes(target).to_string(), "owner_tenant_id": MemoryId::from_bytes(tenant).to_string()}).to_string()
            });
            let mut request = Request::builder()
                .method("POST")
                .uri(path)
                .header("x-request-id", "change-route-test")
                .body(Body::empty())
                .unwrap();
            let fingerprint =
                astral_common::middleware::request_binding::fingerprint_bound_http_request(
                    &request, &body,
                );
            let base = MemoryV1Request {
                resource: "rule_set",
                action: primary_action,
                target: Some(&target),
                target_tenant: Some(&tenant),
                target_owner: None,
                operation_id: b"change-route-test",
                operation_fingerprint: fingerprint.as_bytes(),
            };
            let (target_facts, target_kind) = root
                .with_reader(|reader| match intent {
                    MemoryV1RuleSetChangeIntent::Create => reader
                        .rule_set_create_target(target, tenant)
                        .map(|facts| (facts, MemoryV1CompoundTargetKind::RuleSetCreate)),
                    MemoryV1RuleSetChangeIntent::Publish => reader
                        .rule_set_target(target)
                        .map(|facts| (facts, MemoryV1CompoundTargetKind::Existing)),
                })
                .unwrap()
                .unwrap();
            let actions = [
                MemoryV1CompoundAction {
                    request: base,
                    change_intent: None,
                    target_facts,
                    target_kind,
                },
                MemoryV1CompoundAction {
                    request: MemoryV1Request {
                        action: "confirm-change",
                        ..base
                    },
                    change_intent: Some(intent),
                    target_facts,
                    target_kind,
                },
            ];
            let evaluation = engine.evaluate_memory_v1_compound(
                &root,
                &session,
                &MemoryV1CompoundRequest { actions: &actions },
            );
            assert_eq!(evaluation.decision, MemoryV1Decision::Allow);
            assert_eq!(evaluation.admissions.len(), 2);
            let mut admissions = evaluation.admissions.into_iter();
            let primary = admissions.next().unwrap();
            let confirmation = admissions.next().unwrap();
            assert_eq!(confirmation.change_intent(), Some(intent));
            assert_eq!(
                primary.trusted_time_unix_seconds(),
                confirmation.trusted_time_unix_seconds()
            );
            request.extensions_mut().insert(primary);
            request
                .extensions_mut()
                .insert(MemoryV1AdditionalAdmissions(vec![confirmation.clone()]));
            request.extensions_mut().insert(MemoryV1BoundRequest {
                operation_id: "change-route-test".into(),
                fingerprint: fingerprint.clone(),
                body: body.clone(),
            });
            request.extensions_mut().insert(root.clone());
            request.extensions_mut().insert(session.clone());
            admitted_context(&request, "rule_set", primary_action, &["confirm-change"])
                .expect("matching admissions");
            assert!(admitted_context(&request, "rule_set", primary_action, &[]).is_err());
            request
                .extensions_mut()
                .insert(MemoryV1AdditionalAdmissions(vec![]));
            assert!(
                admitted_context(&request, "rule_set", primary_action, &["confirm-change"])
                    .is_err()
            );
            request
                .extensions_mut()
                .insert(MemoryV1AdditionalAdmissions(vec![confirmation]));
            request
                .extensions_mut()
                .get_mut::<MemoryV1BoundRequest>()
                .unwrap()
                .body = Bytes::from_static(b"{}");
            assert!(
                admitted_context(&request, "rule_set", primary_action, &["confirm-change"])
                    .is_err()
            );

            if intent == MemoryV1RuleSetChangeIntent::Publish {
                request
                    .extensions_mut()
                    .get_mut::<MemoryV1BoundRequest>()
                    .unwrap()
                    .body = body;
                let old_hash = root
                    .with_reader(|reader| reader.selected_version_row(target))
                    .unwrap()
                    .map(|row| version_hash(&row.hash_bytes).unwrap())
                    .unwrap();
                let seen = Arc::new(Mutex::new(Vec::new()));
                let port: Arc<dyn MemoryV1GovernanceCommitPort> = Arc::new(RecordingCommitPort {
                    seen: Arc::clone(&seen),
                    response: None,
                });
                request.extensions_mut().insert(port);
                assert_eq!(
                    version_publish(request)
                        .await
                        .unwrap_err()
                        .into_response()
                        .status(),
                    StatusCode::SERVICE_UNAVAILABLE
                );
                let requests = seen.lock().unwrap();
                let [record] = requests.as_slice() else {
                    panic!("expected exactly one commit");
                };
                let MutationAuditCandidate::Single(audit) = &record.audit else {
                    panic!("expected single-change audit");
                };
                assert_eq!(
                    audit.before(),
                    &MemoryV1AuditObjectState::RuleSet(
                        MemoryV1AuditRuleSetState::new_with_status(
                            &[1],
                            old_hash,
                            MemoryV1AuditRuleSetStatus::Active,
                        )
                        .unwrap(),
                    ),
                );
                assert_eq!(record.root, owner.handle().metadata().unwrap());
            }

            let wrong_intent = if intent == MemoryV1RuleSetChangeIntent::Create {
                MemoryV1RuleSetChangeIntent::Publish
            } else {
                MemoryV1RuleSetChangeIntent::Create
            };
            assert_ne!(
                engine
                    .evaluate_memory_v1_rule_set_change(
                        &root,
                        &session,
                        &MemoryV1Request {
                            action: "confirm-change",
                            ..base
                        },
                        wrong_intent
                    )
                    .decision,
                MemoryV1Decision::Allow
            );
            assert_ne!(
                engine
                    .evaluate_memory_v1(
                        &root,
                        &session,
                        &MemoryV1Request {
                            action: "confirm-change",
                            ..base
                        }
                    )
                    .decision,
                MemoryV1Decision::Allow
            );
        }
        // memory—v1: Retire uses one distinct admission and cannot commit while
        // the durable audit/reconciliation owner is absent.
        let retire_path = "/governance/rule-sets/retire";
        let body = Bytes::from(
            serde_json::json!({"rule_set_id": MemoryId::from_bytes(other_rules).to_string()})
                .to_string(),
        );
        let make_request = |body: Bytes| {
            let mut request = Request::builder()
                .method("POST")
                .uri(retire_path)
                .header("x-request-id", "retire-route-test")
                .body(Body::empty())
                .unwrap();
            let fingerprint =
                astral_common::middleware::request_binding::fingerprint_bound_http_request(
                    &request, &body,
                );
            request.extensions_mut().insert(MemoryV1BoundRequest {
                operation_id: "retire-route-test".into(),
                fingerprint,
                body,
            });
            request.extensions_mut().insert(root.clone());
            request.extensions_mut().insert(session.clone());
            request
        };
        let request = make_request(body.clone());
        let fingerprint = request
            .extensions()
            .get::<MemoryV1BoundRequest>()
            .unwrap()
            .fingerprint
            .clone();
        let facts = root
            .with_reader(|reader| reader.rule_set_target(other_rules))
            .unwrap()
            .unwrap();
        let actions = [MemoryV1CompoundAction {
            request: MemoryV1Request {
                resource: "rule_set",
                action: "retire",
                target: Some(&other_rules),
                target_tenant: Some(&tenant),
                target_owner: None,
                operation_id: b"retire-route-test",
                operation_fingerprint: fingerprint.as_bytes(),
            },
            change_intent: None,
            target_facts: facts,
            target_kind: MemoryV1CompoundTargetKind::Existing,
        }];
        let evaluation = engine.evaluate_memory_v1_compound(
            &root,
            &session,
            &MemoryV1CompoundRequest { actions: &actions },
        );
        assert_eq!(evaluation.decision, MemoryV1Decision::Allow);
        assert_eq!(evaluation.admissions.len(), 1);
        let admission = evaluation.admissions[0].clone();
        let with_admission = |mut request: Request| {
            request.extensions_mut().insert(admission.clone());
            request
                .extensions_mut()
                .insert(MemoryV1AdditionalAdmissions(vec![]));
            request
        };
        let before = owner.handle().metadata().unwrap();
        let missing = rule_set_retire(make_request(body.clone()))
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(missing.status(), StatusCode::SERVICE_UNAVAILABLE);
        let pending = rule_set_retire(with_admission(make_request(body.clone())))
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(pending.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(owner.handle().metadata().unwrap(), before);

        let bad_body = Bytes::from(
            serde_json::json!({"rule_set_id": MemoryId::from_bytes(rules).to_string()}).to_string(),
        );
        assert_eq!(
            rule_set_retire(with_admission(make_request(bad_body)))
                .await
                .unwrap_err()
                .into_response()
                .status(),
            StatusCode::FORBIDDEN,
        );
        let mismatched_target_body = Bytes::from(
            serde_json::json!({"rule_set_id": MemoryId::from_bytes(rules).to_string()}).to_string(),
        );
        let mismatched_request = make_request(mismatched_target_body);
        let mismatched_fingerprint = mismatched_request
            .extensions()
            .get::<MemoryV1BoundRequest>()
            .unwrap()
            .fingerprint
            .clone();
        let mismatched_actions = [MemoryV1CompoundAction {
            request: MemoryV1Request {
                operation_fingerprint: mismatched_fingerprint.as_bytes(),
                ..actions[0].request
            },
            ..actions[0]
        }];
        let mismatched_evaluation = engine.evaluate_memory_v1_compound(
            &root,
            &session,
            &MemoryV1CompoundRequest {
                actions: &mismatched_actions,
            },
        );
        assert_eq!(mismatched_evaluation.decision, MemoryV1Decision::Allow);
        let mut mismatched_request = mismatched_request;
        mismatched_request
            .extensions_mut()
            .insert(mismatched_evaluation.admissions[0].clone());
        mismatched_request
            .extensions_mut()
            .insert(MemoryV1AdditionalAdmissions(vec![]));
        admitted_context(&mismatched_request, "rule_set", "retire", &[])
            .expect("the admission and body fingerprint match");
        let mismatch = rule_set_retire(mismatched_request)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(mismatch.status(), StatusCode::FORBIDDEN);
        let mismatch_body = axum::body::to_bytes(mismatch.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&mismatch_body).contains("AUTHORIZATION_TARGET_MISMATCH"));
        assert_eq!(owner.handle().metadata().unwrap(), before);

        let extra_body = Bytes::from(
            serde_json::json!({"rule_set_id": MemoryId::from_bytes(other_rules).to_string(), "confirm_change": true}).to_string(),
        );
        assert!(serde_json::from_slice::<RuleSetRetireRequest>(&extra_body).is_err());
        let mut wrong_operation = with_admission(make_request(body.clone()));
        wrong_operation
            .extensions_mut()
            .get_mut::<MemoryV1BoundRequest>()
            .unwrap()
            .operation_id = "other".into();
        assert!(admitted_context(&wrong_operation, "rule_set", "retire", &[]).is_err());
        let mut wrong_admission = with_admission(make_request(body));
        wrong_admission
            .extensions_mut()
            .insert(MemoryV1AdditionalAdmissions(vec![admission]));
        assert!(admitted_context(&wrong_admission, "rule_set", "retire", &[]).is_err());
        assert_eq!(owner.handle().metadata().unwrap(), before);

        // memory—v1: A disabled empty card's enable admission reaches the same
        // unavailable durable-owner gate without altering the root.
        let enable_target = [11; 16];
        let enable_body = Bytes::from(
            serde_json::json!({
                "user_card_id": MemoryId::from_bytes(enable_target).to_string()
            })
            .to_string(),
        );
        let mut enable_request = Request::builder()
            .method("POST")
            .uri("/governance/user-cards/enable")
            .header("x-request-id", "enable-route-test")
            .body(Body::empty())
            .unwrap();
        let enable_fingerprint =
            astral_common::middleware::request_binding::fingerprint_bound_http_request(
                &enable_request,
                &enable_body,
            );
        let enable_facts = root
            .with_reader(|reader| reader.user_card_target(enable_target))
            .unwrap()
            .unwrap();
        let enable_actions = [MemoryV1CompoundAction {
            request: MemoryV1Request {
                resource: "user_card",
                action: "enable",
                target: Some(&enable_target),
                target_tenant: Some(&tenant),
                target_owner: Some(&user),
                operation_id: b"enable-route-test",
                operation_fingerprint: enable_fingerprint.as_bytes(),
            },
            change_intent: None,
            target_facts: enable_facts,
            target_kind: MemoryV1CompoundTargetKind::UserCardEnable,
        }];
        let enable_evaluation = engine.evaluate_memory_v1_compound(
            &root,
            &session,
            &MemoryV1CompoundRequest {
                actions: &enable_actions,
            },
        );
        assert_eq!(enable_evaluation.decision, MemoryV1Decision::Allow);
        assert_eq!(enable_evaluation.admissions.len(), 1);
        enable_request
            .extensions_mut()
            .insert(enable_evaluation.admissions[0].clone());
        enable_request
            .extensions_mut()
            .insert(MemoryV1AdditionalAdmissions(vec![]));
        enable_request
            .extensions_mut()
            .insert(MemoryV1BoundRequest {
                operation_id: "enable-route-test".into(),
                fingerprint: enable_fingerprint,
                body: enable_body,
            });
        enable_request.extensions_mut().insert(root.clone());
        enable_request.extensions_mut().insert(session.clone());
        let enable_error = user_card_enable(enable_request).await.unwrap_err();
        assert!(
            matches!(&enable_error.0.0, AstralError::Pending(reason) if reason == "governance audit and operation reconciliation unavailable")
        );
        assert_eq!(
            enable_error.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(owner.handle().metadata().unwrap(), before);

        // memory—v1: An admission for card A cannot be reused for target card B,
        // even when the request binding is recomputed for body B.
        let substitution_body = Bytes::from(
            serde_json::json!({
                "user_card_id": MemoryId::from_bytes(card).to_string()
            })
            .to_string(),
        );
        let mut substitution_request = Request::builder()
            .method("POST")
            .uri("/governance/user-cards/enable")
            .header("x-request-id", "enable-target-substitution-test")
            .body(Body::empty())
            .unwrap();
        let substitution_fingerprint =
            astral_common::middleware::request_binding::fingerprint_bound_http_request(
                &substitution_request,
                &substitution_body,
            );
        let substitution_actions = [MemoryV1CompoundAction {
            request: MemoryV1Request {
                resource: "user_card",
                action: "enable",
                target: Some(&enable_target),
                target_tenant: Some(&tenant),
                target_owner: Some(&user),
                operation_id: b"enable-target-substitution-test",
                operation_fingerprint: substitution_fingerprint.as_bytes(),
            },
            change_intent: None,
            target_facts: enable_facts,
            target_kind: MemoryV1CompoundTargetKind::UserCardEnable,
        }];
        let substitution_evaluation = engine.evaluate_memory_v1_compound(
            &root,
            &session,
            &MemoryV1CompoundRequest {
                actions: &substitution_actions,
            },
        );
        assert_eq!(substitution_evaluation.decision, MemoryV1Decision::Allow);
        assert_eq!(substitution_evaluation.admissions.len(), 1);
        let substitution_admission = substitution_evaluation.admissions[0].clone();
        assert_eq!(
            substitution_admission.target(),
            Some(enable_target.as_slice())
        );
        assert_eq!(
            substitution_admission.operation_fingerprint(),
            substitution_fingerprint.as_bytes()
        );
        substitution_request
            .extensions_mut()
            .insert(substitution_admission);
        substitution_request
            .extensions_mut()
            .insert(MemoryV1AdditionalAdmissions(vec![]));
        substitution_request
            .extensions_mut()
            .insert(MemoryV1BoundRequest {
                operation_id: "enable-target-substitution-test".into(),
                fingerprint: substitution_fingerprint,
                body: substitution_body,
            });
        substitution_request.extensions_mut().insert(root.clone());
        substitution_request
            .extensions_mut()
            .insert(session.clone());
        admitted_context(&substitution_request, "user_card", "enable", &[])
            .expect("admission and body-B fingerprint match");
        let mismatch = user_card_enable(substitution_request)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(mismatch.status(), StatusCode::FORBIDDEN);
        let mismatch_body = axum::body::to_bytes(mismatch.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&mismatch_body).contains("AUTHORIZATION_TARGET_MISMATCH"));
        assert_eq!(owner.handle().metadata().unwrap(), before);

        assert!(serde_json::from_slice::<UserCardEnableRequest>(
            br#"{"user_card_id":"x","other":true}"#
        )
        .is_err());

        // memory—v1: A create admission is bound to candidate owner, tenant,
        // request bytes and operation; the durable owner remains unavailable.
        let new_card = [12; 16];
        let create_body = Bytes::from(
            serde_json::json!({
                "user_card_id": MemoryId::from_bytes(new_card).to_string(),
                "user_id": MemoryId::from_bytes(user).to_string(),
                "tenant_id": MemoryId::from_bytes(tenant).to_string(),
            })
            .to_string(),
        );
        let make_create_request = |body: Bytes| {
            let mut request = Request::builder()
                .method("POST")
                .uri("/governance/user-cards")
                .header("x-request-id", "card-create-route-test")
                .body(Body::empty())
                .unwrap();
            let fingerprint =
                astral_common::middleware::request_binding::fingerprint_bound_http_request(
                    &request, &body,
                );
            request.extensions_mut().insert(MemoryV1BoundRequest {
                operation_id: "card-create-route-test".into(),
                fingerprint,
                body,
            });
            request.extensions_mut().insert(root.clone());
            request.extensions_mut().insert(session.clone());
            request
        };
        let request = make_create_request(create_body.clone());
        let create_fingerprint = request
            .extensions()
            .get::<MemoryV1BoundRequest>()
            .unwrap()
            .fingerprint
            .clone();
        let create_facts = root
            .with_reader(|reader| reader.user_card_create_target(new_card, user, tenant))
            .unwrap()
            .unwrap();
        let create_actions = [MemoryV1CompoundAction {
            request: MemoryV1Request {
                resource: "user_card",
                action: "create",
                target: Some(&new_card),
                target_tenant: Some(&tenant),
                target_owner: Some(&user),
                operation_id: b"card-create-route-test",
                operation_fingerprint: create_fingerprint.as_bytes(),
            },
            change_intent: None,
            target_facts: create_facts,
            target_kind: MemoryV1CompoundTargetKind::UserCardCreate,
        }];
        let create_evaluation = engine.evaluate_memory_v1_compound(
            &root,
            &session,
            &MemoryV1CompoundRequest {
                actions: &create_actions,
            },
        );
        assert_eq!(create_evaluation.decision, MemoryV1Decision::Allow);
        assert_eq!(create_evaluation.admissions.len(), 1);
        let create_admission = create_evaluation.admissions[0].clone();
        let attach_create = |mut request: Request| {
            request.extensions_mut().insert(create_admission.clone());
            request
                .extensions_mut()
                .insert(MemoryV1AdditionalAdmissions(vec![]));
            request
        };
        let missing = user_card_create(make_create_request(create_body.clone()))
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(missing.status(), StatusCode::SERVICE_UNAVAILABLE);
        let error = user_card_create(attach_create(make_create_request(create_body.clone())))
            .await
            .unwrap_err();
        assert!(
            matches!(&error.0.0, AstralError::Pending(reason) if reason == "governance audit and operation reconciliation unavailable")
        );
        assert_eq!(
            error.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(owner.handle().metadata().unwrap(), before);
        let mut tampered = attach_create(make_create_request(create_body.clone()));
        tampered
            .extensions_mut()
            .get_mut::<MemoryV1BoundRequest>()
            .unwrap()
            .body = Bytes::from_static(b"{}");
        assert!(admitted_context(&tampered, "user_card", "create", &[]).is_err());
        assert!(serde_json::from_slice::<UserCardCreateRequest>(
            br#"{"user_card_id":"x","user_id":"y","tenant_id":"z","extra":true}"#
        )
        .is_err());
        let other_card = [13; 16];
        let wrong_body = Bytes::from(
            serde_json::json!({
                "user_card_id": MemoryId::from_bytes(other_card).to_string(),
                "user_id": MemoryId::from_bytes(user).to_string(),
                "tenant_id": MemoryId::from_bytes(tenant).to_string(),
            })
            .to_string(),
        );
        let mut wrong_request = make_create_request(wrong_body);
        let wrong_fingerprint = wrong_request
            .extensions()
            .get::<MemoryV1BoundRequest>()
            .unwrap()
            .fingerprint
            .clone();
        let wrong_actions = [MemoryV1CompoundAction {
            request: MemoryV1Request {
                operation_fingerprint: wrong_fingerprint.as_bytes(),
                ..create_actions[0].request
            },
            ..create_actions[0]
        }];
        let wrong_evaluation = engine.evaluate_memory_v1_compound(
            &root,
            &session,
            &MemoryV1CompoundRequest {
                actions: &wrong_actions,
            },
        );
        assert_eq!(wrong_evaluation.decision, MemoryV1Decision::Allow);
        wrong_request
            .extensions_mut()
            .insert(wrong_evaluation.admissions[0].clone());
        wrong_request
            .extensions_mut()
            .insert(MemoryV1AdditionalAdmissions(vec![]));
        admitted_context(&wrong_request, "user_card", "create", &[]).expect("fingerprint is bound");
        let mismatch = user_card_create(wrong_request)
            .await
            .unwrap_err()
            .into_response();
        assert_eq!(mismatch.status(), StatusCode::FORBIDDEN);
        let mismatch_body = axum::body::to_bytes(mismatch.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&mismatch_body).contains("AUTHORIZATION_TARGET_MISMATCH"));
        assert_eq!(owner.handle().metadata().unwrap(), before);

        let route =
            memory_v1_route_declaration(&Method::POST, "/governance/rule-sets/publish").unwrap();
        let self_affected = evaluate_route_action(
            &engine,
            &root,
            &session,
            route,
            &MemoryV1Request {
                resource: "rule_set",
                action: "confirm-change",
                target: Some(&rules),
                target_tenant: Some(&tenant),
                target_owner: None,
                operation_id: b"op",
                operation_fingerprint: b"fingerprint",
            },
        )
        .unwrap();
        assert_eq!(self_affected.decision, MemoryV1Decision::Deny);
        assert_eq!(
            self_affected.deny_source,
            Some(MemoryV1DenySource::SelfConfirmation)
        );
    }

    // memory—v1: Revoke an authority-bound session only after a real admission.
    #[test]
    fn revoked_session_after_admission_refuses_governance_context() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_GOVERNANCE_SESSION_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "api::governance_routes::tests::revoked_session_after_admission_refuses_governance_context",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "stdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            return;
        }

        let user = [1; 16];
        let identity_card = [2; 16];
        let tenant = [3; 16];
        let card = [4; 16];
        let rules = [5; 16];
        let binding = [6; 16];
        let content = br#"{"rules":[{"ruleId":"disable","resource":"user_card","action":"disable","effect":"ALLOW"}]}"#.to_vec();
        let version = canonical_version(vec![1], content, vec![1], rules);
        let rows = CandidateRows {
            users: vec![UserRow { user_id: user }],
            identity_cards: vec![IdentityCardRow {
                identity_card_id: identity_card,
                user_id: user,
            }],
            tenants: vec![TenantRow {
                tenant_id: tenant,
                parent_tenant_id: None,
            }],
            user_cards: vec![UserCardRow {
                user_card_id: card,
                user_id: user,
                tenant_id: tenant,
                status: UserCardStatus::Active,
            }],
            rule_sets: vec![RuleSetRow {
                status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                rule_set_id: rules,
                owner_tenant_id: tenant,
                current_version_bytes: vec![1],
            }],
            rule_set_versions: vec![version],
            bindings: vec![BindingRow {
                binding_id: binding,
                user_card_id: card,
                rule_set_id: rules,
                binding_layer: BindingLayer::Base,
                valid_from: None,
                valid_until: None,
                owner_scope: MemoryV1OwnerScope::SelfUser,
                tenant_scope: MemoryV1TenantScope::SelfTenant,
                removed_at: None,
                removed_by: None,
            }],
            binding_confirmations: vec![BindingConfirmationRow {
                confirmation_id: [7; 16],
                binding_id: binding,
                rule_set_id: rules,
                version_bytes: vec![1],
                confirmer_user_id: user,
                scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            }],
            rule_set_change_confirmations: vec![RuleSetChangeConfirmationRow {
                confirmation_id: [8; 16],
                rule_set_id: rules,
                version_bytes: vec![1],
                confirmer_user_id: user,
                affected_scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            }],
        };
        let owner = install_process_root(
            rows,
            vec![CurrentSelection {
                rule_set_id: rules,
                version_bytes: vec![1],
            }],
            CandidateBudget {
                max_table_rows: 32,
                max_bindings_per_read: 4,
            },
        )
        .unwrap();
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "user_card".into(),
                actions: vec!["disable".into()],
            }])
            .unwrap();
        // The isolated fixture exercises session revalidation, not production adoption.
        owner.adopt_serving_for_isolated_tests().unwrap();
        let before = owner.handle().metadata().unwrap();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let issuer = authority.identity_session_adapter();
        let scope = RequestRootScope::new(owner.handle(), uuid::Uuid::new_v4());
        let root = scope.extension();
        let credential = issuer
            .issue_verified_session_in_root(
                &root,
                CandidateIdentity {
                    user_id: MemoryId::from_bytes(user),
                    identity_card_id: MemoryId::from_bytes(identity_card),
                    user_card_id: MemoryId::from_bytes(card),
                    tenant_id: MemoryId::from_bytes(tenant),
                },
                now_unix_seconds().unwrap() - 1,
                300,
            )
            .unwrap();
        let session = authority
            .verifier()
            .verify_and_bind(credential.credential(), now_unix_seconds().unwrap(), &root)
            .unwrap();
        let body = Bytes::from(
            serde_json::json!({"user_card_id": MemoryId::from_bytes(card).to_string()}).to_string(),
        );
        let mut request = Request::builder()
            .method("POST")
            .uri("/governance/user-cards/disable")
            .header("x-request-id", "governance-session-test")
            .body(Body::empty())
            .unwrap();
        let fingerprint =
            astral_common::middleware::request_binding::fingerprint_bound_http_request(
                &request, &body,
            );
        let evaluation = PolicyEngine::new().evaluate_memory_v1(
            &root,
            &session,
            &MemoryV1Request {
                resource: "user_card",
                action: "disable",
                target: Some(&card),
                target_tenant: Some(&tenant),
                target_owner: Some(&user),
                operation_id: b"governance-session-test",
                operation_fingerprint: fingerprint.as_bytes(),
            },
        );
        assert_eq!(evaluation.decision, MemoryV1Decision::Allow);
        request
            .extensions_mut()
            .insert(evaluation.admission.expect("real admission"));
        request.extensions_mut().insert(root);
        request.extensions_mut().insert(session);
        request
            .extensions_mut()
            .insert(MemoryV1AdditionalAdmissions(vec![]));
        request.extensions_mut().insert(MemoryV1BoundRequest {
            operation_id: "governance-session-test".into(),
            fingerprint,
            body,
        });

        // The same admitted request reaches the unchanged durable-audit gate while live.
        let context =
            admitted_context(&request, "user_card", "disable", &[]).expect("live session admitted");
        let error = commit(
            context,
            ManagementMutationV2::UserCardStatus {
                user_card_id: card,
                status: UserCardStatus::Disabled,
            },
        )
        .unwrap_err();
        assert!(
            matches!(&error.0, AstralError::Pending(reason) if reason == "governance audit and operation reconciliation unavailable")
        );
        let response = GovernanceError(error).into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(AuthorizationPendingRefusal::is_attached(
            response.extensions()
        ));
        assert_eq!(owner.handle().metadata().unwrap(), before);

        assert_eq!(
            issuer
                .revoke_sessions_for_user_card(MemoryId::from_bytes(card))
                .unwrap(),
            1
        );
        let error = match admitted_context(&request, "user_card", "disable", &[]) {
            Ok(_) => panic!("revoked session must not produce a mutation context"),
            Err(error) => error,
        };
        assert!(
            matches!(error.0, AstralError::Pending(ref reason) if reason == "session authority unavailable or stale")
        );
        let response = GovernanceError(error).into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(AuthorizationPendingRefusal::is_attached(
            response.extensions()
        ));
        assert_eq!(owner.handle().metadata().unwrap(), before);
    }

    #[test]
    fn missing_durable_audit_refuses_without_mutating_root() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_GOVERNANCE_PENDING_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "api::governance_routes::tests::missing_durable_audit_refuses_without_mutating_root",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "stdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            return;
        }
        let owner = install_process_root(
            CandidateRows::default(),
            vec![],
            CandidateBudget {
                max_table_rows: 16,
                max_bindings_per_read: 4,
            },
        )
        .unwrap();
        let before = owner.handle().metadata().unwrap();
        let context = MutationContext {
            bound: MemoryV1BoundRequest {
                operation_id: "op".into(),
                fingerprint: "fingerprint".into(),
                body: Bytes::new(),
            },
            root: before,
            commit_port: Arc::new(FailClosedMemoryV1GovernanceCommitPort),
            actor: [1; 16],
            actor_identity_card: [4; 16],
            target: [2; 16],
            target_tenant: [3; 16],
            target_owner: Some([1; 16]),
            trusted_time: 1,
            previous_rule_set_state: None,
        };
        let result = commit(
            context,
            ManagementMutationV2::UserCardStatus {
                user_card_id: [2; 16],
                status: UserCardStatus::Disabled,
            },
        );
        let response = GovernanceError(result.unwrap_err()).into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(AuthorizationPendingRefusal::is_attached(
            response.extensions()
        ));
        assert_eq!(owner.handle().metadata().unwrap(), before);
    }
}
