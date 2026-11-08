//! Root-authorized source bootstrap contract.
//!
//! This contract is deliberately separate from [`AuthorizationAdmission`],
//! [`AuthorizationFenceProof`], and ordinary source reservations. A ROOT-signed
//! ticket approves one complete source aggregate; the authority then issues an
//! opaque, one-use capability for the registered source/database pair. The
//! capability is not an F1 admission and cannot be passed to ordinary source
//! mutation APIs.
//!
//! The payload uses the same field semantics as the canonical template and
//! RuleSet source DTOs, but excludes database-generated ids and timestamps.
//! The eventual DB bridge must create those values and return actual receipts
//! in [`AuthoritySourceBootstrapCompletion`].

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::{
    authority_counter, authority_digest, authority_field, authority_signature_encoding,
    authority_text, authority_time_window, authority_timestamp, authority_verify_strict,
    AuthorityProtocolError, AuthorityReadGate,
};
use crate::{ResourceRegistry, AUTHORIZATION_EDITION};

pub const AUTHORITY_PATH_SOURCE_BOOTSTRAP_PREPARE: &str =
    "/main/api/v1/authority-source-bootstraps/prepare";
pub const AUTHORITY_PATH_SOURCE_BOOTSTRAP_FINALIZE: &str =
    "/main/api/v1/authority-source-bootstraps/finalize";
pub const AUTHORITY_PATH_SOURCE_BOOTSTRAP_RECONCILE: &str =
    "/main/api/v1/authority-source-bootstraps/reconcile";
pub const AUTHORITY_OPERATION_SOURCE_BOOTSTRAP_PREPARE: &str = "source_bootstrap_prepare";
pub const AUTHORITY_OPERATION_SOURCE_BOOTSTRAP_FINALIZE: &str = "source_bootstrap_finalize";
pub const AUTHORITY_OPERATION_SOURCE_BOOTSTRAP_RECONCILE: &str = "source_bootstrap_reconcile";

const TICKET_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_SOURCE_BOOTSTRAP_TICKET_V1\0";
const TICKET_DIGEST_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_SOURCE_BOOTSTRAP_TICKET_DIGEST_V1\0";
const CAPABILITY_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_SOURCE_BOOTSTRAP_CAPABILITY_V1\0";
const COMPLETION_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_SOURCE_BOOTSTRAP_COMPLETION_V1\0";
const MAX_RULES: usize = 16_384;
const MAX_BINDINGS: usize = 4_096;
const MAX_SOURCE_TEXT: usize = 512;

/// The source aggregate family approved by the ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthoritySourceBootstrapKind {
    TemplateRuleSet,
}

impl AuthoritySourceBootstrapKind {
    pub const fn as_text(self) -> &'static str {
        match self {
            Self::TemplateRuleSet => "TEMPLATE_RULE_SET",
        }
    }
}

/// Database-independent creation shape for `user_card_template`.
///
/// Names and semantics follow [`crate::UserCardTemplate`]. `template_id`,
/// `created_at`, and `updated_at` are intentionally absent: the DB owner must
/// generate and capture them in its transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceBootstrapTemplateRoot {
    pub domain_id: i64,
    pub tenant_id: Option<i64>,
    pub parent_template_id: Option<i64>,
    pub template_code: String,
    pub template_name: String,
    pub card_type: String,
    pub template_scope: Option<String>,
    pub version_no: Option<i32>,
    pub default_priority: Option<i32>,
    pub default_roles_json: Option<String>,
    pub resource_scope_json: Option<String>,
    pub status: String,
}

/// Database-independent creation shape for `permission_rule_template`.
///
/// The fields intentionally match the canonical `PermissionRuleTemplate` rule
/// semantics. Only generated `template_rule_id` and timestamps are omitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceBootstrapTemplateRule {
    pub resource_type: String,
    pub resource_id: Option<i64>,
    pub action_code: String,
    pub effect: String,
    pub condition_json: Option<String>,
    pub priority: i32,
    pub enabled: bool,
}

/// Database-independent creation shape for `rule_set`.
///
/// `source_id` is generated only after the template INSERT and is therefore
/// excluded. `source_type` remains signed and must be `TEMPLATE`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceBootstrapRuleSetRoot {
    pub name: String,
    pub code: String,
    pub description: Option<String>,
    pub source_type: String,
    pub enabled: bool,
    pub tenant_id: Option<i64>,
}

/// Database-independent creation shape with the canonical
/// `RuleSetEntryDefinition` field meanings. `entry_id`, `rule_set_id`, and
/// timestamps are generated/captured by the DB owner and are not signed input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceBootstrapRuleSetEntry {
    pub resource_type: String,
    pub resource_id: Option<i64>,
    pub action_code: String,
    pub effect: String,
    pub condition_json: Option<String>,
    pub priority: i32,
    pub enabled: bool,
    pub valid_from: Option<String>,
    pub valid_to: Option<String>,
    pub tenant_id: Option<i64>,
}

/// Explicit card RuleSet bindings. The initial template aggregate may carry an
/// empty vector, but it may never omit the field or silently invent a binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceBootstrapRuleSetBinding {
    pub card_id: i64,
    pub ref_type: String,
    pub tenant_id: Option<i64>,
}

/// Complete typed source aggregate approved by a ROOT ticket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySourceBootstrapBundle {
    pub kind: AuthoritySourceBootstrapKind,
    pub template: SourceBootstrapTemplateRoot,
    pub template_rules: Vec<SourceBootstrapTemplateRule>,
    pub rule_set: SourceBootstrapRuleSetRoot,
    pub rule_set_entries: Vec<SourceBootstrapRuleSetEntry>,
    pub bindings: Vec<SourceBootstrapRuleSetBinding>,
}

impl AuthoritySourceBootstrapBundle {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        if self.kind != AuthoritySourceBootstrapKind::TemplateRuleSet {
            return Err(AuthorityProtocolError::InvalidText { field: "kind" });
        }
        let template = &self.template;
        positive_id(template.domain_id, "domain_id")?;
        positive_optional_id(template.tenant_id, "tenant_id")?;
        positive_optional_id(template.parent_template_id, "parent_template_id")?;
        bounded_source_text(&template.template_code, "template_code")?;
        bounded_source_text(&template.template_name, "template_name")?;
        bounded_source_text(&template.card_type, "card_type")?;
        if let Some(scope) = &template.template_scope {
            bounded_source_text(scope, "template_scope")?;
        }
        if let Some(value) = template.default_roles_json.as_deref() {
            bounded_source_text(value, "default_roles_json")?;
        }
        if let Some(value) = template.resource_scope_json.as_deref() {
            bounded_source_text(value, "resource_scope_json")?;
        }
        if template.status != "ACTIVE" {
            return Err(AuthorityProtocolError::InvalidText { field: "status" });
        }

        let rule_set = &self.rule_set;
        bounded_source_text(&rule_set.name, "rule_set_name")?;
        bounded_source_text(&rule_set.code, "rule_set_code")?;
        if rule_set.code != template.template_code
            || rule_set.source_type != "TEMPLATE"
            || !rule_set.enabled
            || rule_set.tenant_id != template.tenant_id
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        if let Some(description) = &rule_set.description {
            bounded_source_text(description, "rule_set_description")?;
        }

        if self.template_rules.is_empty() || self.template_rules.len() > MAX_RULES {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }
        if self.rule_set_entries.len() != self.template_rules.len()
            || self.rule_set_entries.len() > MAX_RULES
        {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }
        if self.bindings.len() > MAX_BINDINGS {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }

        let registry = ResourceRegistry::global();
        let mut seen_rules = std::collections::BTreeSet::new();
        for (index, rule) in self.template_rules.iter().enumerate() {
            validate_rule(registry, rule)?;
            let key = (
                rule.resource_type.clone(),
                rule.resource_id,
                rule.action_code.clone(),
                rule.condition_json.clone(),
                rule.priority,
            );
            if !seen_rules.insert(key) {
                return Err(AuthorityProtocolError::InvalidCoverage);
            }
            let entry = &self.rule_set_entries[index];
            if entry.resource_type != rule.resource_type
                || entry.resource_id != rule.resource_id
                || entry.action_code != rule.action_code
                || entry.effect != "ALLOW"
                || entry.condition_json != rule.condition_json
                || entry.priority != rule.priority
                || entry.enabled != rule.enabled
                || entry.valid_from.is_some()
                || entry.valid_to.is_some()
                || entry.tenant_id.is_some()
            {
                return Err(AuthorityProtocolError::DigestMismatch {
                    field: "rule_set_entries",
                });
            }
        }

        // Every currently registered ResourceRegistry action must be covered by
        // an enabled, type-wide, unconditional ALLOW. Alias `write` is accepted
        // only through the same canonical expansion used by startup adoption.
        for resource in registry.list_resources() {
            for action in registry.list_actions(&resource).unwrap_or_default() {
                let covered = self.template_rules.iter().any(|rule| {
                    rule.enabled
                        && rule.resource_id.is_none()
                        && rule.condition_json.is_none()
                        && rule.resource_type == resource
                        && rule.effect == "ALLOW"
                        && action_covered_by_rule(&rule.action_code, &action)
                });
                if !covered {
                    return Err(AuthorityProtocolError::InvalidCoverage);
                }
            }
        }

        let mut bindings = std::collections::BTreeSet::new();
        for binding in &self.bindings {
            positive_id(binding.card_id, "binding_card_id")?;
            if !matches!(binding.ref_type.as_str(), "BASE" | "OVERLAY")
                || !bindings.insert((binding.card_id, binding.ref_type.clone()))
                || binding.tenant_id != template.tenant_id
            {
                return Err(AuthorityProtocolError::InvalidCoverage);
            }
        }
        let encoded =
            serde_json::to_vec(self).map_err(|_| AuthorityProtocolError::CanonicalSerialization)?;
        if encoded.len() > super::AUTHORITY_MAX_BODY_BYTES {
            return Err(AuthorityProtocolError::InvalidText {
                field: "source_bootstrap_bundle_bytes",
            });
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, AuthorityProtocolError> {
        self.validate()?;
        let payload =
            serde_json::to_vec(self).map_err(|_| AuthorityProtocolError::CanonicalSerialization)?;
        let mut bytes = Vec::with_capacity(TICKET_DIGEST_DOMAIN.len() + payload.len() + 16);
        bytes.extend_from_slice(TICKET_DIGEST_DOMAIN);
        authority_field(&mut bytes, &payload.len().to_string());
        bytes.extend_from_slice(&payload);
        Ok(super::authority_sha256_hex(&bytes))
    }
}

fn positive_id(value: i64, field: &'static str) -> Result<(), AuthorityProtocolError> {
    (value > 0)
        .then_some(())
        .ok_or(AuthorityProtocolError::InvalidIdentifier { field })
}

fn positive_optional_id(
    value: Option<i64>,
    field: &'static str,
) -> Result<(), AuthorityProtocolError> {
    if let Some(value) = value {
        positive_id(value, field)?;
    }
    Ok(())
}

fn bounded_source_text(value: &str, field: &'static str) -> Result<(), AuthorityProtocolError> {
    if value.is_empty()
        || value.len() > MAX_SOURCE_TEXT
        || value.trim() != value
        || value.chars().any(|character| character.is_control())
    {
        return Err(AuthorityProtocolError::InvalidText { field });
    }
    Ok(())
}

fn validate_rule(
    registry: &ResourceRegistry,
    rule: &SourceBootstrapTemplateRule,
) -> Result<(), AuthorityProtocolError> {
    bounded_source_text(&rule.resource_type, "resource_type")?;
    bounded_source_text(&rule.action_code, "action_code")?;
    if rule.resource_id.is_some_and(|value| value <= 0) {
        return Err(AuthorityProtocolError::InvalidIdentifier {
            field: "resource_id",
        });
    }
    if rule.condition_json.is_some() || rule.priority < 0 || rule.effect != "ALLOW" || !rule.enabled
    {
        return Err(AuthorityProtocolError::InvalidCoverage);
    }
    if !action_is_registered(registry, &rule.resource_type, &rule.action_code) {
        return Err(AuthorityProtocolError::InvalidCoverage);
    }
    Ok(())
}

fn action_is_registered(registry: &ResourceRegistry, resource: &str, action: &str) -> bool {
    if registry.validate(resource, action).is_ok() {
        return true;
    }
    crate::ACTION_ALIASES
        .iter()
        .find(|(alias, _)| *alias == action)
        .is_some_and(|(_, expanded)| {
            expanded
                .iter()
                .all(|candidate| registry.validate(resource, candidate).is_ok())
        })
}

fn action_covered_by_rule(stored_action: &str, requested_action: &str) -> bool {
    stored_action == requested_action
        || crate::ACTION_ALIASES
            .iter()
            .find(|(alias, _)| *alias == stored_action)
            .is_some_and(|(_, expanded)| expanded.contains(&requested_action))
}

/// ROOT-signed complete source instruction. The signature is verified against
/// the durable trust-root ROOT role, never against a caller-supplied key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySourceBootstrapTicket {
    pub protocol_version: u16,
    pub authorization_edition: u16,
    pub authority_id: String,
    pub root_id: String,
    pub trust_root_digest: String,
    pub root_key_id: String,
    pub operation_id: String,
    pub event_id: String,
    pub nonce: String,
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
    pub service_id: String,
    pub database_id: String,
    pub payload: AuthoritySourceBootstrapBundle,
    pub signature: String,
}

impl AuthoritySourceBootstrapTicket {
    pub fn validate_unsigned(&self) -> Result<(), AuthorityProtocolError> {
        if self.protocol_version != super::AUTHORITY_PROTOCOL_VERSION
            || self.authorization_edition != AUTHORIZATION_EDITION
        {
            return Err(AuthorityProtocolError::WrongEdition);
        }
        authority_text(&self.authority_id, "authority_id")?;
        authority_text(&self.root_id, "root_id")?;
        authority_digest(&self.trust_root_digest, "trust_root_digest")?;
        authority_text(&self.root_key_id, "root_key_id")?;
        authority_text(&self.operation_id, "operation_id")?;
        authority_text(&self.event_id, "event_id")?;
        authority_text(&self.nonce, "nonce")?;
        authority_timestamp(self.issued_at, "issued_at")?;
        authority_time_window(self.not_before, self.issued_at, self.expires_at)?;
        authority_text(&self.service_id, "service_id")?;
        authority_text(&self.database_id, "database_id")?;
        self.payload.validate()?;
        let encoded =
            serde_json::to_vec(self).map_err(|_| AuthorityProtocolError::CanonicalSerialization)?;
        if encoded.len() > super::AUTHORITY_MAX_BODY_BYTES {
            return Err(AuthorityProtocolError::InvalidText {
                field: "source_bootstrap_ticket_bytes",
            });
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.validate_unsigned()?;
        authority_signature_encoding(&self.signature)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, AuthorityProtocolError> {
        self.validate_unsigned()?;
        let payload = serde_json::to_vec(&self.payload)
            .map_err(|_| AuthorityProtocolError::CanonicalSerialization)?;
        let mut bytes = Vec::with_capacity(1024 + payload.len());
        bytes.extend_from_slice(TICKET_DOMAIN);
        authority_field(&mut bytes, &self.protocol_version.to_string());
        authority_field(&mut bytes, &self.authorization_edition.to_string());
        for value in [
            &self.authority_id,
            &self.root_id,
            &self.trust_root_digest,
            &self.root_key_id,
            &self.operation_id,
            &self.event_id,
            &self.nonce,
            &self.service_id,
            &self.database_id,
        ] {
            authority_field(&mut bytes, value);
        }
        authority_field(&mut bytes, &self.issued_at.to_string());
        authority_field(&mut bytes, &self.not_before.to_string());
        authority_field(&mut bytes, &self.expires_at.to_string());
        authority_field(&mut bytes, &payload.len().to_string());
        bytes.extend_from_slice(&payload);
        Ok(bytes)
    }

    pub fn payload_digest(&self) -> Result<String, AuthorityProtocolError> {
        self.payload.digest()
    }

    pub fn artifact_digest(&self) -> Result<String, AuthorityProtocolError> {
        self.validate()?;
        let mut bytes = self.signing_bytes()?;
        authority_field(&mut bytes, &self.signature);
        Ok(super::authority_sha256_hex(&bytes))
    }

    pub fn sign(&mut self, root_signing_key: &SigningKey) -> Result<(), AuthorityProtocolError> {
        self.signature.clear();
        self.validate_unsigned()?;
        self.signature = hex::encode(root_signing_key.sign(&self.signing_bytes()?).to_bytes());
        Ok(())
    }

    pub fn verify(&self, root_verifying_key: &VerifyingKey) -> Result<(), AuthorityProtocolError> {
        self.validate()?;
        authority_verify_strict(root_verifying_key, &self.signing_bytes()?, &self.signature)
    }

    pub fn verify_at(
        &self,
        root_verifying_key: &VerifyingKey,
        now_seconds: i64,
    ) -> Result<(), AuthorityProtocolError> {
        self.verify(root_verifying_key)?;
        if now_seconds < self.not_before || now_seconds >= self.expires_at {
            return Err(AuthorityProtocolError::NotCurrentlyValid);
        }
        Ok(())
    }
}

/// Durable authority-issued opaque capability. It is intentionally not
/// convertible to `AuthorizationAdmission` and cannot enter ordinary F1 APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySourceBootstrapCapability {
    pub protocol_version: u16,
    pub authorization_edition: u16,
    pub authority_id: String,
    pub operation_id: String,
    pub event_id: String,
    pub ticket_digest: String,
    pub reservation_id: String,
    pub service_id: String,
    pub database_id: String,
    pub root_key_id: String,
    pub trust_root_digest: String,
    pub authority_term: u64,
    pub global_fence_sequence: u64,
    pub gate_epoch: u64,
    pub read_gate_digest: String,
    pub key_id: String,
    pub key_epoch: u64,
    pub issued_at: i64,
    pub not_before: i64,
    pub expires_at: i64,
    pub capability_nonce: String,
    pub signature: String,
}

impl AuthoritySourceBootstrapCapability {
    pub fn validate_unsigned(&self) -> Result<(), AuthorityProtocolError> {
        if self.protocol_version != super::AUTHORITY_PROTOCOL_VERSION
            || self.authorization_edition != AUTHORIZATION_EDITION
        {
            return Err(AuthorityProtocolError::WrongEdition);
        }
        for (value, field) in [
            (&self.authority_id, "authority_id"),
            (&self.operation_id, "operation_id"),
            (&self.event_id, "event_id"),
            (&self.reservation_id, "reservation_id"),
            (&self.service_id, "service_id"),
            (&self.database_id, "database_id"),
            (&self.root_key_id, "root_key_id"),
            (&self.capability_nonce, "capability_nonce"),
        ] {
            authority_text(value, field)?;
        }
        authority_digest(&self.ticket_digest, "ticket_digest")?;
        authority_digest(&self.trust_root_digest, "trust_root_digest")?;
        authority_counter(self.authority_term, "authority_term")?;
        authority_counter(self.global_fence_sequence, "global_fence_sequence")?;
        authority_counter(self.gate_epoch, "gate_epoch")?;
        authority_digest(&self.read_gate_digest, "read_gate_digest")?;
        authority_text(&self.key_id, "key_id")?;
        authority_counter(self.key_epoch, "key_epoch")?;
        authority_timestamp(self.issued_at, "issued_at")?;
        authority_time_window(self.not_before, self.issued_at, self.expires_at)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.validate_unsigned()?;
        authority_signature_encoding(&self.signature)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, AuthorityProtocolError> {
        self.validate_unsigned()?;
        let mut bytes = Vec::with_capacity(768);
        bytes.extend_from_slice(CAPABILITY_DOMAIN);
        authority_field(&mut bytes, &self.protocol_version.to_string());
        authority_field(&mut bytes, &self.authorization_edition.to_string());
        for value in [
            &self.authority_id,
            &self.operation_id,
            &self.event_id,
            &self.ticket_digest,
            &self.reservation_id,
            &self.service_id,
            &self.database_id,
            &self.root_key_id,
            &self.trust_root_digest,
            &self.read_gate_digest,
            &self.key_id,
            &self.capability_nonce,
        ] {
            authority_field(&mut bytes, value);
        }
        for value in [
            self.authority_term,
            self.global_fence_sequence,
            self.gate_epoch,
            self.key_epoch,
        ] {
            authority_field(&mut bytes, &value.to_string());
        }
        for value in [self.issued_at, self.not_before, self.expires_at] {
            authority_field(&mut bytes, &value.to_string());
        }
        Ok(bytes)
    }

    pub fn sign_with(&mut self, signing_key: &SigningKey) -> Result<(), AuthorityProtocolError> {
        self.signature.clear();
        self.validate_unsigned()?;
        self.signature = hex::encode(signing_key.sign(&self.signing_bytes()?).to_bytes());
        Ok(())
    }

    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), AuthorityProtocolError> {
        self.validate()?;
        authority_verify_strict(verifying_key, &self.signing_bytes()?, &self.signature)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthoritySourceBootstrapState {
    Reserved,
    Completed,
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySourceBootstrapReservation {
    pub reservation_id: String,
    pub operation_id: String,
    pub event_id: String,
    pub ticket_digest: String,
    pub service_id: String,
    pub database_id: String,
    pub state: AuthoritySourceBootstrapState,
    pub authority_term: u64,
    pub global_fence_sequence: u64,
    pub created_at: i64,
    pub updated_at: i64,
    pub completed_at: Option<i64>,
}

impl AuthoritySourceBootstrapReservation {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        for (value, field) in [
            (&self.reservation_id, "reservation_id"),
            (&self.operation_id, "operation_id"),
            (&self.event_id, "event_id"),
            (&self.service_id, "service_id"),
            (&self.database_id, "database_id"),
        ] {
            authority_text(value, field)?;
        }
        authority_digest(&self.ticket_digest, "ticket_digest")?;
        authority_counter(self.authority_term, "authority_term")?;
        authority_counter(self.global_fence_sequence, "global_fence_sequence")?;
        authority_timestamp(self.created_at, "created_at")?;
        authority_timestamp(self.updated_at, "updated_at")?;
        if self.created_at > self.updated_at {
            return Err(AuthorityProtocolError::InvalidTimeWindow);
        }
        match (self.state, self.completed_at) {
            (AuthoritySourceBootstrapState::Completed, Some(completed_at))
                if completed_at >= self.created_at && completed_at == self.updated_at =>
            {
                authority_timestamp(completed_at, "completed_at")?;
            }
            (AuthoritySourceBootstrapState::Completed, _) => {
                return Err(AuthorityProtocolError::InvalidTimeWindow);
            }
            (_, None) => {}
            (_, Some(_)) => return Err(AuthorityProtocolError::InvalidTimeWindow),
        }
        Ok(())
    }
}

/// Real source-side completion evidence. Every digest is an actual receipt
/// digest produced by the future DB bridge; the authority never fabricates one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySourceBootstrapCompletion {
    pub reservation_id: String,
    pub operation_id: String,
    pub event_id: String,
    pub ticket_digest: String,
    pub source_payload_digest: String,
    pub before_image_digest: String,
    pub source_commit_digest: String,
    pub after_image_digest: String,
    pub source_outcome_digest: String,
    pub staged_evidence_digest: String,
    pub audit_receipt_digest: String,
    pub committed_at: i64,
}

impl AuthoritySourceBootstrapCompletion {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        for (value, field) in [
            (&self.reservation_id, "reservation_id"),
            (&self.operation_id, "operation_id"),
            (&self.event_id, "event_id"),
        ] {
            authority_text(value, field)?;
        }
        for (value, field) in [
            (&self.ticket_digest, "ticket_digest"),
            (&self.source_payload_digest, "source_payload_digest"),
            (&self.before_image_digest, "before_image_digest"),
            (&self.source_commit_digest, "source_commit_digest"),
            (&self.after_image_digest, "after_image_digest"),
            (&self.source_outcome_digest, "source_outcome_digest"),
            (&self.staged_evidence_digest, "staged_evidence_digest"),
            (&self.audit_receipt_digest, "audit_receipt_digest"),
        ] {
            authority_digest(value, field)?;
        }
        authority_timestamp(self.committed_at, "committed_at")
    }

    pub fn digest(&self) -> Result<String, AuthorityProtocolError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(768);
        bytes.extend_from_slice(COMPLETION_DOMAIN);
        for value in [
            &self.reservation_id,
            &self.operation_id,
            &self.event_id,
            &self.ticket_digest,
            &self.source_payload_digest,
            &self.before_image_digest,
            &self.source_commit_digest,
            &self.after_image_digest,
            &self.source_outcome_digest,
            &self.staged_evidence_digest,
            &self.audit_receipt_digest,
        ] {
            authority_field(&mut bytes, value);
        }
        authority_field(&mut bytes, &self.committed_at.to_string());
        Ok(super::authority_sha256_hex(&bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySourceBootstrapCompletionReceipt {
    pub completion: AuthoritySourceBootstrapCompletion,
    pub authority_id: String,
    pub authority_term: u64,
    pub global_fence_sequence: u64,
    pub key_id: String,
    pub key_epoch: u64,
    pub frontier: super::GlobalAuthorityFrontier,
    pub completed_at: i64,
    pub signature: String,
}

impl AuthoritySourceBootstrapCompletionReceipt {
    pub fn validate_unsigned(&self) -> Result<(), AuthorityProtocolError> {
        self.completion.validate()?;
        authority_text(&self.authority_id, "authority_id")?;
        authority_counter(self.authority_term, "authority_term")?;
        authority_counter(self.global_fence_sequence, "global_fence_sequence")?;
        authority_text(&self.key_id, "key_id")?;
        authority_counter(self.key_epoch, "key_epoch")?;
        self.frontier.validate()?;
        if self.authority_id != self.frontier.authority_id
            || self.authority_term != self.frontier.authority_term
            || self.global_fence_sequence != self.frontier.global_fence_sequence
            || self.key_id != self.frontier.key_id
            || self.key_epoch != self.frontier.key_epoch
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        authority_timestamp(self.completed_at, "completed_at")?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.validate_unsigned()?;
        authority_signature_encoding(&self.signature)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, AuthorityProtocolError> {
        self.validate_unsigned()?;
        let completion_digest = self.completion.digest()?;
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(COMPLETION_DOMAIN);
        authority_field(&mut bytes, &self.authority_id);
        authority_field(&mut bytes, &self.authority_term.to_string());
        authority_field(&mut bytes, &self.global_fence_sequence.to_string());
        authority_field(&mut bytes, &self.key_id);
        authority_field(&mut bytes, &self.key_epoch.to_string());
        let frontier = serde_json::to_vec(&self.frontier)
            .map_err(|_| AuthorityProtocolError::CanonicalSerialization)?;
        authority_field(&mut bytes, &frontier.len().to_string());
        bytes.extend_from_slice(&frontier);
        authority_field(&mut bytes, &self.completed_at.to_string());
        authority_field(&mut bytes, &completion_digest);
        Ok(bytes)
    }

    pub fn sign_with(&mut self, signing_key: &SigningKey) -> Result<(), AuthorityProtocolError> {
        self.signature.clear();
        self.validate_unsigned()?;
        self.signature = hex::encode(signing_key.sign(&self.signing_bytes()?).to_bytes());
        Ok(())
    }

    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), AuthorityProtocolError> {
        self.validate()?;
        authority_verify_strict(verifying_key, &self.signing_bytes()?, &self.signature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySourceBootstrapPrepareRequest {
    pub caller: super::AuthorityCallerIdentity,
    pub ticket: AuthoritySourceBootstrapTicket,
}

impl AuthoritySourceBootstrapPrepareRequest {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.caller.validate()?;
        self.ticket.validate()?;
        if self.ticket.service_id != self.caller.service_id {
            return Err(AuthorityProtocolError::CallerIdentityMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySourceBootstrapPrepareResponse {
    pub capability: AuthoritySourceBootstrapCapability,
    pub reservation: AuthoritySourceBootstrapReservation,
    pub global_frontier: super::GlobalAuthorityFrontier,
    pub gate_epoch: u64,
    pub read_gate: AuthorityReadGate,
}

impl AuthoritySourceBootstrapPrepareResponse {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.capability.validate()?;
        self.reservation.validate()?;
        self.global_frontier.validate()?;
        self.read_gate.validate()?;
        authority_counter(self.gate_epoch, "gate_epoch")?;
        if self.gate_epoch == 0 {
            return Err(AuthorityProtocolError::InvalidCounter {
                field: "gate_epoch",
            });
        }
        let read_gate_digest = self.read_gate.digest()?;
        if self.capability.read_gate_digest != read_gate_digest
            || self.capability.gate_epoch != self.gate_epoch
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        if self.capability.reservation_id != self.reservation.reservation_id
            || self.capability.operation_id != self.reservation.operation_id
            || self.capability.event_id != self.reservation.event_id
            || self.capability.ticket_digest != self.reservation.ticket_digest
            || self.capability.service_id != self.reservation.service_id
            || self.capability.database_id != self.reservation.database_id
            || self.capability.authority_id != self.global_frontier.authority_id
            || self.capability.authority_term != self.global_frontier.authority_term
            || self.capability.global_fence_sequence != self.global_frontier.global_fence_sequence
            || self.capability.key_id != self.global_frontier.key_id
            || self.capability.key_epoch != self.global_frontier.key_epoch
            || self.reservation.state != AuthoritySourceBootstrapState::Reserved
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySourceBootstrapFinalizeRequest {
    pub caller: super::AuthorityCallerIdentity,
    pub capability: AuthoritySourceBootstrapCapability,
    pub completion: AuthoritySourceBootstrapCompletion,
}

impl AuthoritySourceBootstrapFinalizeRequest {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.caller.validate()?;
        self.capability.validate()?;
        self.completion.validate()?;
        if self.capability.service_id != self.caller.service_id
            || self.capability.reservation_id != self.completion.reservation_id
            || self.capability.operation_id != self.completion.operation_id
            || self.capability.event_id != self.completion.event_id
            || self.capability.ticket_digest != self.completion.ticket_digest
            || self.completion.source_payload_digest.is_empty()
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySourceBootstrapFinalizeResponse {
    pub reservation: AuthoritySourceBootstrapReservation,
    pub receipt: AuthoritySourceBootstrapCompletionReceipt,
    pub global_frontier: super::GlobalAuthorityFrontier,
}

impl AuthoritySourceBootstrapFinalizeResponse {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.reservation.validate()?;
        self.receipt.validate()?;
        self.global_frontier.validate()?;
        if self.reservation.state != AuthoritySourceBootstrapState::Completed
            || self.global_frontier != self.receipt.frontier
            || self.receipt.completion.reservation_id != self.reservation.reservation_id
            || self.receipt.completion.operation_id != self.reservation.operation_id
            || self.receipt.completion.ticket_digest != self.reservation.ticket_digest
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySourceBootstrapReconcileRequest {
    pub caller: super::AuthorityCallerIdentity,
    pub operation_id: String,
    pub ticket_digest: String,
}

impl AuthoritySourceBootstrapReconcileRequest {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.caller.validate()?;
        authority_text(&self.operation_id, "operation_id")?;
        authority_digest(&self.ticket_digest, "ticket_digest")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySourceBootstrapReconcileResponse {
    pub operation_id: String,
    pub ticket_digest: String,
    pub reservation: Option<AuthoritySourceBootstrapReservation>,
    pub capability: Option<AuthoritySourceBootstrapCapability>,
    pub receipt: Option<AuthoritySourceBootstrapCompletionReceipt>,
    pub global_frontier: super::GlobalAuthorityFrontier,
    pub gate_epoch: u64,
    pub read_gate: AuthorityReadGate,
}

impl AuthoritySourceBootstrapReconcileResponse {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        authority_text(&self.operation_id, "operation_id")?;
        authority_digest(&self.ticket_digest, "ticket_digest")?;
        self.global_frontier.validate()?;
        self.read_gate.validate()?;
        authority_counter(self.gate_epoch, "gate_epoch")?;
        if self.gate_epoch == 0 {
            return Err(AuthorityProtocolError::InvalidCounter {
                field: "gate_epoch",
            });
        }
        match (&self.reservation, &self.capability, &self.receipt) {
            (None, None, None) => Ok(()),
            (Some(reservation), Some(capability), receipt) => {
                reservation.validate()?;
                capability.validate()?;
                if reservation.operation_id != self.operation_id
                    || reservation.ticket_digest != self.ticket_digest
                    || capability.operation_id != self.operation_id
                    || capability.ticket_digest != self.ticket_digest
                    || capability.reservation_id != reservation.reservation_id
                    || capability.event_id != reservation.event_id
                    || capability.service_id != reservation.service_id
                    || capability.database_id != reservation.database_id
                    || capability.authority_term != reservation.authority_term
                    || capability.global_fence_sequence != reservation.global_fence_sequence
                    || capability.authority_id != self.global_frontier.authority_id
                    || (reservation.state == AuthoritySourceBootstrapState::Completed)
                        != receipt.is_some()
                {
                    return Err(AuthorityProtocolError::ScopeMismatch);
                }
                if let Some(receipt) = receipt {
                    receipt.validate()?;
                    if receipt.completion.reservation_id != reservation.reservation_id
                        || receipt.completion.operation_id != reservation.operation_id
                        || receipt.completion.event_id != reservation.event_id
                        || receipt.completion.ticket_digest != reservation.ticket_digest
                        || receipt.completed_at != reservation.completed_at.unwrap_or_default()
                        || receipt.authority_id != capability.authority_id
                    {
                        return Err(AuthorityProtocolError::ScopeMismatch);
                    }
                }
                Ok(())
            }
            _ => Err(AuthorityProtocolError::ScopeMismatch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn bundle() -> AuthoritySourceBootstrapBundle {
        let registry = ResourceRegistry::global();
        let mut rules = Vec::new();
        let mut entries = Vec::new();
        for resource in registry.list_resources() {
            for action in registry.list_actions(&resource).unwrap_or_default() {
                rules.push(SourceBootstrapTemplateRule {
                    resource_type: resource.clone(),
                    resource_id: None,
                    action_code: action.clone(),
                    effect: "ALLOW".to_owned(),
                    condition_json: None,
                    priority: 100_000 - rules.len() as i32,
                    enabled: true,
                });
                entries.push(SourceBootstrapRuleSetEntry {
                    resource_type: resource.clone(),
                    resource_id: None,
                    action_code: action,
                    effect: "ALLOW".to_owned(),
                    condition_json: None,
                    priority: 100_000 - entries.len() as i32,
                    enabled: true,
                    valid_from: None,
                    valid_to: None,
                    tenant_id: None,
                });
            }
        }
        AuthoritySourceBootstrapBundle {
            kind: AuthoritySourceBootstrapKind::TemplateRuleSet,
            template: SourceBootstrapTemplateRoot {
                domain_id: 1,
                tenant_id: None,
                parent_template_id: None,
                template_code: "bootstrap-code".to_owned(),
                template_name: "bootstrap".to_owned(),
                card_type: "SYSTEM".to_owned(),
                template_scope: Some("SYSTEM".to_owned()),
                version_no: Some(1),
                default_priority: Some(100),
                default_roles_json: None,
                resource_scope_json: None,
                status: "ACTIVE".to_owned(),
            },
            template_rules: rules,
            rule_set: SourceBootstrapRuleSetRoot {
                name: "bootstrap-code".to_owned(),
                code: "bootstrap-code".to_owned(),
                description: None,
                source_type: "TEMPLATE".to_owned(),
                enabled: true,
                tenant_id: None,
            },
            rule_set_entries: entries,
            bindings: Vec::new(),
        }
    }

    fn ticket() -> AuthoritySourceBootstrapTicket {
        AuthoritySourceBootstrapTicket {
            protocol_version: super::super::AUTHORITY_PROTOCOL_VERSION,
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "authority-1".to_owned(),
            root_id: "root-1".to_owned(),
            trust_root_digest: "aa".repeat(32),
            root_key_id: "root-key".to_owned(),
            operation_id: "op-bootstrap-1".to_owned(),
            event_id: "event-bootstrap-1".to_owned(),
            nonce: "nonce-bootstrap-1".to_owned(),
            issued_at: 1_000,
            not_before: 1_000,
            expires_at: 2_000,
            service_id: "bootstrap-runner".to_owned(),
            database_id: "db-1".to_owned(),
            payload: bundle(),
            signature: String::new(),
        }
    }

    #[test]
    fn root_ticket_digest_is_stable_and_payload_tampering_fails() {
        let signing = SigningKey::from_bytes(&[7; 32]);
        let mut value = ticket();
        value.sign(&signing).unwrap();
        let digest = value.artifact_digest().unwrap();
        assert_eq!(digest, value.artifact_digest().unwrap());
        value.verify(&signing.verifying_key()).unwrap();
        value.payload.template.template_code = "other-code".to_owned();
        assert!(value.verify(&signing.verifying_key()).is_err());
    }

    #[test]
    fn invalid_window_and_incomplete_registry_fail_closed() {
        let mut value = ticket();
        value.expires_at = value.issued_at;
        assert!(value.validate_unsigned().is_err());
        let mut value = ticket();
        value.payload.template_rules.pop();
        value.payload.rule_set_entries.pop();
        assert!(value.validate_unsigned().is_err());
    }

    #[test]
    fn serde_rejects_unknown_source_fields() {
        let value = serde_json::to_value(ticket()).unwrap();
        let mut object = value.as_object().unwrap().clone();
        object.insert("unexpected".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<AuthoritySourceBootstrapTicket>(
            serde_json::Value::Object(object)
        )
        .is_err());
    }

    #[test]
    fn opaque_capability_is_not_an_ordinary_admission() {
        let capability = AuthoritySourceBootstrapCapability {
            protocol_version: super::super::AUTHORITY_PROTOCOL_VERSION,
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "authority-1".to_owned(),
            operation_id: "op".to_owned(),
            event_id: "event".to_owned(),
            ticket_digest: "aa".repeat(32),
            reservation_id: "res".to_owned(),
            service_id: "source".to_owned(),
            database_id: "db".to_owned(),
            root_key_id: "root".to_owned(),
            trust_root_digest: "bb".repeat(32),
            authority_term: 1,
            global_fence_sequence: 1,
            gate_epoch: 1,
            read_gate_digest: "cc".repeat(32),
            key_id: "signer".to_owned(),
            key_epoch: 1,
            issued_at: 1,
            not_before: 1,
            expires_at: 2,
            capability_nonce: "nonce".to_owned(),
            signature: "00".repeat(64),
        };
        assert!(capability.validate().is_ok());
        assert_eq!(capability.ticket_digest, "aa".repeat(32));
    }
}
