use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

use crate::{
    signing::{request_digest, request_facts_digest},
    validation::{
        bounded_identifier, identifier, opaque_identifier, validate_digest, validate_revision,
    },
    MAX_DECISION_REASON_BYTES, MAX_DECISION_TTL_MS, MAX_REQUEST_BODY_BYTES,
};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ContractError {
    #[error("invalid {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("signature is invalid")]
    InvalidSignature,
    #[error("signature key id does not match the expected key")]
    KeyIdMismatch,
    #[error("request or decision binding does not match")]
    BindingMismatch,
    #[error("signed decision is expired or outside its validity window")]
    DecisionExpired,
    #[error("signed outcome is deny or pending")]
    DecisionNotAllowed,
    #[error("canonical payload exceeds its configured size limit")]
    PayloadTooLarge,
    #[error("serialization failed: {0}")]
    Serialization(String),
}

pub(crate) fn invalid(field: &'static str, reason: &'static str) -> ContractError {
    ContractError::InvalidField { field, reason }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalSubject {
    pub issuer: String,
    pub subject: String,
}

impl ExternalSubject {
    pub fn validate(&self) -> Result<(), ContractError> {
        opaque_identifier(&self.issuer)
            .map_err(|_| invalid("issuer", "invalid opaque identifier"))?;
        opaque_identifier(&self.subject)
            .map_err(|_| invalid("subject", "invalid opaque identifier"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceOperation {
    Object,
    ScopedCollection,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceFacts {
    pub resource_type: String,
    /// V1 uses positive decimal app-local IDs; opaque IDs are not accepted.
    pub target_id: String,
    pub external_tenant_id: String,
    pub external_domain_id: String,
    pub owner: Option<ExternalSubject>,
    pub revision: String,
    pub operation: ResourceOperation,
}

impl ResourceFacts {
    pub fn validate(&self) -> Result<(), ContractError> {
        bounded_identifier(&self.resource_type, "resource_type", 64)?;
        validate_positive_target_id(&self.target_id)?;
        opaque_identifier(&self.external_tenant_id)
            .map_err(|_| invalid("external_tenant_id", "invalid identifier"))?;
        opaque_identifier(&self.external_domain_id)
            .map_err(|_| invalid("external_domain_id", "invalid identifier"))?;
        validate_revision(&self.revision, "facts.revision")?;
        if let Some(owner) = &self.owner {
            owner.validate()?;
        }
        Ok(())
    }
}

pub(crate) fn validate_positive_target_id(value: &str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > 19
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
        || value.parse::<i64>().ok().filter(|id| *id > 0).is_none()
    {
        return Err(invalid("target_id", "must be a positive decimal integer"));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRequest {
    pub app_id: String,
    pub key_id: String,
    /// SHA-256 digest of the canonical application manifest, lowercase hex.
    pub manifest_digest: String,
    /// The manifest/mapping revision selected by the platform integration.
    pub revision: String,
    pub request_id: String,
    /// Base64url-safe random nonce; at least 128 bits of entropy is required.
    pub nonce: String,
    /// Unix timestamp in milliseconds.
    pub timestamp: u64,
    /// Gateway-authenticated session token identifier. The platform must
    /// compare this signed value with the verified Gateway identity context.
    pub session_token_id: String,
    /// External actor identity. This is not facts.owner and is never a platform ID.
    pub subject: ExternalSubject,
    /// Business operation whose policy permission is being evaluated.
    pub method: String,
    /// Business request path plus optional query string, without scheme/authority.
    pub path: String,
    pub action: String,
    pub operation_id: String,
    pub facts: ResourceFacts,
}

impl AuthorizationRequest {
    pub fn validate(&self) -> Result<(), ContractError> {
        bounded_identifier(&self.app_id, "app_id", 64)?;
        bounded_identifier(&self.key_id, "key_id", 64)?;
        validate_digest(&self.manifest_digest, "manifest_digest")?;
        validate_revision(&self.revision, "revision")?;
        bounded_identifier(&self.request_id, "request_id", 64)?;
        if self.nonce.len() < 22 || self.nonce.len() > 128 || !is_base64url_no_pad(&self.nonce) {
            return Err(invalid(
                "nonce",
                "must be 22..=128 unpadded base64url characters",
            ));
        }
        if self.timestamp == 0 {
            return Err(invalid(
                "timestamp",
                "must be a positive Unix millisecond value",
            ));
        }
        opaque_identifier(&self.session_token_id)
            .map_err(|_| invalid("session_token_id", "invalid opaque identifier"))?;
        self.subject.validate()?;
        validate_method(&self.method)?;
        validate_request_path(&self.path)?;
        bounded_identifier(&self.action, "action", 64)?;
        bounded_identifier(&self.operation_id, "operation_id", 64)?;
        self.facts.validate()?;
        let bytes = serde_json::to_vec(self).map_err(serialize_error)?;
        if bytes.len() > MAX_REQUEST_BODY_BYTES {
            return Err(ContractError::PayloadTooLarge);
        }
        Ok(())
    }

    /// Apply the single protocol-wide freshness window; callers cannot widen it.
    pub fn validate_at(&self, now_ms: u64) -> Result<(), ContractError> {
        self.validate()?;
        if self.timestamp.abs_diff(now_ms) > crate::MAX_CLOCK_SKEW_MS {
            return Err(invalid(
                "timestamp",
                "outside the accepted clock-skew window",
            ));
        }
        Ok(())
    }

    pub fn body_digest(&self) -> Result<String, ContractError> {
        self.validate()?;
        request_digest(self)
    }

    pub fn digest(&self) -> Result<String, ContractError> {
        self.body_digest()
    }

    pub fn facts_digest(&self) -> Result<String, ContractError> {
        self.facts.validate()?;
        request_facts_digest(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthorizationRequest {
    pub request: AuthorizationRequest,
    /// Unpadded base64url Ed25519 signature.
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOutcome {
    Allow,
    Deny,
    Pending,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionScope {
    pub app_id: String,
    pub subject: ExternalSubject,
    pub resource_type: String,
    pub target_id: String,
    pub external_tenant_id: String,
    pub external_domain_id: String,
    pub operation: ResourceOperation,
}

impl DecisionScope {
    pub(crate) fn from_request(request: &AuthorizationRequest) -> Self {
        Self {
            app_id: request.app_id.clone(),
            subject: request.subject.clone(),
            resource_type: request.facts.resource_type.clone(),
            target_id: request.facts.target_id.clone(),
            external_tenant_id: request.facts.external_tenant_id.clone(),
            external_domain_id: request.facts.external_domain_id.clone(),
            operation: request.facts.operation,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationDecision {
    pub request_digest: String,
    pub facts_digest: String,
    pub request_id: String,
    pub scope: DecisionScope,
    pub mapping_revision: String,
    pub outcome: DecisionOutcome,
    pub reason: Option<String>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

impl AuthorizationDecision {
    pub fn bound_to(
        request: &AuthorizationRequest,
        mapping_revision: impl Into<String>,
        outcome: DecisionOutcome,
        reason: Option<String>,
        now_ms: u64,
    ) -> Result<Self, ContractError> {
        request.validate()?;
        let decision = Self {
            request_digest: request.digest()?,
            facts_digest: request.facts_digest()?,
            request_id: request.request_id.clone(),
            scope: DecisionScope::from_request(request),
            mapping_revision: mapping_revision.into(),
            outcome,
            reason,
            issued_at_ms: now_ms,
            expires_at_ms: now_ms
                .checked_add(MAX_DECISION_TTL_MS)
                .ok_or(invalid("expires_at_ms", "timestamp overflow"))?,
        };
        decision.validate_for(request, now_ms)?;
        Ok(decision)
    }

    pub(crate) fn validate_for(
        &self,
        request: &AuthorizationRequest,
        now_ms: u64,
    ) -> Result<(), ContractError> {
        request.validate()?;
        validate_decision_shape(self)?;
        if self.request_digest != request.digest()?
            || self.facts_digest != request.facts_digest()?
            || self.request_id != request.request_id
            || self.scope != DecisionScope::from_request(request)
        {
            return Err(ContractError::BindingMismatch);
        }
        // A future-dated signed allow could otherwise carry its whole TTL into
        // the future. Decisions are usable only after issuance and never past expiry.
        if self.issued_at_ms > now_ms || now_ms >= self.expires_at_ms {
            return Err(ContractError::DecisionExpired);
        }
        Ok(())
    }
}

pub(crate) fn validate_decision_shape(
    decision: &AuthorizationDecision,
) -> Result<(), ContractError> {
    validate_digest(&decision.request_digest, "decision.request_digest")?;
    validate_digest(&decision.facts_digest, "decision.facts_digest")?;
    bounded_identifier(&decision.request_id, "decision.request_id", 64)?;
    identifier(&decision.scope.app_id)
        .map_err(|_| invalid("scope.app_id", "invalid identifier"))?;
    decision.scope.subject.validate()?;
    identifier(&decision.scope.resource_type)
        .map_err(|_| invalid("scope.resource_type", "invalid identifier"))?;
    validate_positive_target_id(&decision.scope.target_id)?;
    opaque_identifier(&decision.scope.external_tenant_id)
        .map_err(|_| invalid("scope.external_tenant_id", "invalid identifier"))?;
    opaque_identifier(&decision.scope.external_domain_id)
        .map_err(|_| invalid("scope.external_domain_id", "invalid identifier"))?;
    validate_revision(&decision.mapping_revision, "mapping_revision")?;
    if let Some(reason) = &decision.reason {
        if reason.len() > MAX_DECISION_REASON_BYTES || reason.chars().any(char::is_control) {
            return Err(invalid("reason", "too long or contains control characters"));
        }
    }
    if decision.expires_at_ms <= decision.issued_at_ms
        || decision.expires_at_ms - decision.issued_at_ms > MAX_DECISION_TTL_MS
    {
        return Err(ContractError::DecisionExpired);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthorizationDecision {
    pub key_id: String,
    pub decision: AuthorizationDecision,
    /// Unpadded base64url Ed25519 signature.
    pub signature: String,
}

#[derive(Debug)]
pub struct VerifiedAuthorizationDecision {
    decision: AuthorizationDecision,
}

impl VerifiedAuthorizationDecision {
    pub(crate) fn new(decision: AuthorizationDecision) -> Self {
        Self { decision }
    }

    /// Read-only, fully signed authorization scope for an explicit application-side recheck.
    pub fn scope(&self) -> &DecisionScope {
        &self.decision.scope
    }

    /// Ensure a result still belongs to this exact signed request.
    pub fn matches_request(&self, request: &AuthorizationRequest) -> bool {
        request.validate().is_ok()
            && self.decision.request_digest == request.digest().unwrap_or_default()
            && self.decision.facts_digest == request.facts_digest().unwrap_or_default()
            && self.decision.scope == DecisionScope::from_request(request)
    }

    /// Recheck the short decision window against the local wall clock immediately before use.
    pub fn validate_current(&self, request: &AuthorizationRequest) -> Result<(), ContractError> {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid("clock", "system clock precedes Unix epoch"))?
            .as_millis();
        let now_ms = u64::try_from(now_ms).map_err(|_| invalid("clock", "time is out of range"))?;
        self.decision.validate_for(request, now_ms)
    }

    pub fn outcome(&self) -> &DecisionOutcome {
        &self.decision.outcome
    }

    pub fn mapping_revision(&self) -> &str {
        &self.decision.mapping_revision
    }

    pub fn reason(&self) -> Option<&str> {
        self.decision.reason.as_deref()
    }

    pub fn issued_at_ms(&self) -> u64 {
        self.decision.issued_at_ms
    }

    pub fn expires_at_ms(&self) -> u64 {
        self.decision.expires_at_ms
    }

    pub fn is_allow(&self) -> bool {
        matches!(self.decision.outcome, DecisionOutcome::Allow)
    }

    /// Return a verified allow only when all facts still bind and it remains fresh.
    pub fn require_allow_current(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<(), ContractError> {
        self.validate_current(request)?;
        if !self.matches_request(request) || !self.is_allow() {
            return Err(ContractError::DecisionNotAllowed);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApiResponseEnvelope<T> {
    pub success: bool,
    pub code: i32,
    pub message: String,
    pub data: Option<T>,
    #[serde(default)]
    pub error_type: Option<String>,
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub reason_code: Option<String>,
    #[serde(default)]
    pub required_permission: Option<String>,
    #[serde(default)]
    pub request_path: Option<String>,
    #[serde(default)]
    pub request_method: Option<String>,
    pub timestamp: i64,
    #[serde(default)]
    pub trace_id: Option<String>,
}

pub(crate) fn validate_method(method: &str) -> Result<(), ContractError> {
    if matches!(
        method,
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
    ) {
        Ok(())
    } else {
        Err(invalid(
            "method",
            "unsupported or non-canonical HTTP method",
        ))
    }
}

fn validate_request_path(path: &str) -> Result<(), ContractError> {
    crate::validation::validate_path(path, true)
}

fn is_base64url_no_pad(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

fn serialize_error(error: serde_json::Error) -> ContractError {
    ContractError::Serialization(error.to_string())
}
