//! Distinct production ELIGIBILITY completion contract (V7).
//!
//! Eligibility-sync source mutations do not publish grant certificates: their
//! durable source commit carries typed staged evidence whose exact canonical
//! bytes are pinned by `staged_evidence_digest` in the commit binding. This
//! module is the typed completion path for those mutations: the trusted
//! source presents the FULL exact COMMITTED binding plus the retained staged
//! evidence bytes, the authority re-proves the digest pin, strict-decodes the
//! dedicated eligibility shape, and records an immutable completion receipt
//! that moves the reservation to the terminal [`AuthorityReservationState::
//! Completed`] state in the same leader-fenced CAS that advances the global
//! frontier and the read-gate epoch.
//!
//! Fail-closed properties:
//! - The declared completion can never diverge from the commit-pinned
//!   evidence: the request must carry the exact retained envelope text, its
//!   canonical digest must equal the STORED commit binding's
//!   `staged_evidence_digest`, and the declared [`AuthorityEligibility
//!   CompletionEvidence`] must equal the shape decoded from those bytes.
//! - The evidence is a dedicated typed shape, never arbitrary JSON: the
//!   envelope declares NO grant coverage (mutually exclusive with the
//!   publication OBJECT selector), carries the `ELIGIBILITY_COMPLETION` kind
//!   discriminator, the typed completion, and the verbatim source mirror the DB
//!   owner strictly validates. Unknown fields are rejected; nonempty card sets
//!   are finite (1..=256), sorted and deduplicated. An empty card set requires
//!   the closed V1 active-cards-by-subject full-fanout receipt, with exact
//!   subject/mutation pairing and a recomputed digest; bare `[]` is denied.
//! - A stable exact replay of the same request reads back the stored receipt
//!   with the recorded post-completion frontier and never re-issues; any
//!   binding or completion substitution is a genuine conflict.
//! - Zero grant/certificate/publication writes happen on this path.

use serde::{Deserialize, Serialize};

use super::{
    authority_counter, authority_digest, authority_text, authority_timestamp,
    AuthorityCallerIdentity, AuthorityCommitBinding, AuthorityProtocolError,
    AuthorityProtocolScope, AuthorityReadGate, AuthorityReservationDisposition,
    AuthorityScopeReservation, AuthorityStagedSourceEvidence, GlobalAuthorityFrontier,
};
use crate::AUTHORIZATION_EDITION;

/// Frozen internal HTTP path (plural resource, kebab-case, frozen main
/// prefix). Shared by the service and the client library.
pub const AUTHORITY_PATH_ELIGIBILITY_COMPLETIONS: &str =
    "/main/api/v1/authority-eligibility-completions";

/// The explicit allowed-operation string a trusted source must carry in its
/// registered `allowed_operations` before it may call the completion endpoint.
pub const AUTHORITY_OPERATION_ELIGIBILITY_COMPLETION: &str = "eligibility_completion";

/// Upper bound for the retained staged-evidence text (mirrors the DB-side
/// staged-evidence byte bound and [`AuthorityStagedSourceEvidence`]).
const RETAINED_EVIDENCE_MAX_BYTES: usize = 256 * 1024;
/// Maximum number of per-card completion entries in one receipt.
const MAX_COMPLETION_CARDS: usize = 256;

/// The exact retained staged-evidence envelope text as persisted on the
/// durable source-outcome row at COMMIT.
///
/// The digest pin is NOT a passthrough: the authority recomputes the
/// canonical digest over this text (`canonical_digest`, byte-exact twin of
/// the DB-side `staged_evidence_digest`) and compares it against the STORED
/// commit binding, so a request can never declare a different completion
/// than the one staged at commit time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthorityRetainedStagedEvidence(String);

impl AuthorityRetainedStagedEvidence {
    pub fn new(text: String) -> Self {
        Self(text)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        if self.0.is_empty() || self.0.len() > RETAINED_EVIDENCE_MAX_BYTES {
            return Err(AuthorityProtocolError::InvalidText {
                field: "retained_staged_evidence",
            });
        }
        serde_json::from_str::<serde_json::Value>(&self.0).map_err(|_| {
            AuthorityProtocolError::InvalidText {
                field: "retained_staged_evidence",
            }
        })?;
        Ok(())
    }

    /// Canonical compact re-serialization of the envelope text (the exact
    /// canonicalization the DB-side staged-evidence digest applies).
    pub fn canonical_text(&self) -> Result<String, AuthorityProtocolError> {
        self.validate()?;
        let value: serde_json::Value = serde_json::from_str(&self.0)
            .map_err(|_| AuthorityProtocolError::CanonicalSerialization)?;
        serde_json::to_string(&value).map_err(|_| AuthorityProtocolError::CanonicalSerialization)
    }

    /// SHA-256 over the canonical envelope text — the recomputed digest pin
    /// compared against the stored commit binding's `staged_evidence_digest`.
    pub fn canonical_digest(&self) -> Result<String, AuthorityProtocolError> {
        Ok(super::authority_sha256_hex(
            self.canonical_text()?.as_bytes(),
        ))
    }

    /// Strict decode of the retained text into the staged evidence envelope.
    pub fn staged_envelope(&self) -> Result<AuthorityStagedSourceEvidence, AuthorityProtocolError> {
        self.validate()?;
        serde_json::from_str(&self.0).map_err(|_| AuthorityProtocolError::DigestMismatch {
            field: "retained_staged_evidence",
        })
    }
}

/// Typed discriminator of the dedicated eligibility staged evidence. The
/// staged shape below is the ONLY shape the completion path decodes: a
/// generic JSON object that merely contains cards is never accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityEligibilityEvidenceKind {
    EligibilityCompletion,
}

impl AuthorityEligibilityEvidenceKind {
    pub const fn as_text(self) -> &'static str {
        "ELIGIBILITY_COMPLETION"
    }
}

/// Exact source artifact for a template rebind that changed the template but
/// produced no materializable grant contribution. The aggregate images are
/// canonical bytes emitted by the registered typed RuleSet reader; callers do
/// not provide a partial or generic JSON replacement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCardRebindEvidence {
    pub card_id: i64,
    pub tenant_id: i64,
    pub user_id: i64,
    pub domain_id: Option<i64>,
    pub old_template_id: Option<i64>,
    pub new_template_id: i64,
    pub new_template_image: String,
    pub before_card: AuthorityCardRebindCardImage,
    pub after_card: AuthorityCardRebindCardImage,
    pub old_base_refs: Vec<AuthorityCardRebindBaseRef>,
    pub new_base_refs: Vec<AuthorityCardRebindBaseRef>,
    pub before_rule_sets: Vec<AuthorityCardRebindRuleSetAggregate>,
    pub after_rule_sets: Vec<AuthorityCardRebindRuleSetAggregate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCardRebindCardImage {
    pub card_id: i64,
    pub card_status: String,
    pub user_id: Option<i64>,
    pub tenant_id: Option<i64>,
    pub domain_id: Option<i64>,
    pub template_id: Option<i64>,
    pub card_type: String,
    pub level_id: Option<i64>,
    pub priority: i32,
    pub is_primary: bool,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCardRebindBaseRef {
    pub id: i64,
    pub card_id: i64,
    pub rule_set_id: i64,
    pub ref_type: String,
    pub tenant_id: Option<i64>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCardRebindRuleSetAggregate {
    pub rule_set_id: i64,
    /// Canonical full typed aggregate emitted by `read_typed_source_row_image_in_tx_typed`.
    pub canonical_image: String,
}

impl AuthorityCardRebindRuleSetAggregate {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        super::authority_positive_id(self.rule_set_id, "rule_set_id")?;
        if self.canonical_image.is_empty()
            || self.canonical_image.len() > RETAINED_EVIDENCE_MAX_BYTES
        {
            return Err(AuthorityProtocolError::InvalidText {
                field: "canonical_image",
            });
        }
        let value: serde_json::Value =
            serde_json::from_str(&self.canonical_image).map_err(|_| {
                AuthorityProtocolError::InvalidText {
                    field: "canonical_image",
                }
            })?;
        if !value.is_object()
            || serde_json::to_string(&value)
                .map_err(|_| AuthorityProtocolError::CanonicalSerialization)?
                != self.canonical_image
        {
            return Err(AuthorityProtocolError::InvalidText {
                field: "canonical_image",
            });
        }
        let root = value
            .get("root")
            .and_then(serde_json::Value::as_object)
            .ok_or(AuthorityProtocolError::InvalidCoverage)?;
        if root.get("rule_set_id").and_then(serde_json::Value::as_i64) != Some(self.rule_set_id)
            || root.get("source_type").and_then(serde_json::Value::as_str) != Some("TEMPLATE")
            || root
                .get("source_id")
                .and_then(serde_json::Value::as_i64)
                .is_none()
            || !value
                .get("entries")
                .is_some_and(serde_json::Value::is_array)
            || !value
                .get("bindings")
                .is_some_and(serde_json::Value::is_array)
        {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }
        super::config_completion::validate_card_rebind_aggregate(self)
    }
}

impl AuthorityCardRebindEvidence {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        super::authority_positive_id(self.card_id, "card_id")?;
        super::authority_positive_id(self.tenant_id, "tenant_id")?;
        super::authority_positive_id(self.user_id, "user_id")?;
        if self.old_template_id.is_some_and(|id| id <= 0) {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }
        super::authority_positive_id(self.new_template_id, "new_template_id")?;
        if self.old_template_id == Some(self.new_template_id)
            || self.domain_id.is_some_and(|id| id <= 0)
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        self.validate_template()?;
        self.validate_card_image(&self.before_card, self.old_template_id)?;
        self.validate_card_image(&self.after_card, Some(self.new_template_id))?;
        let mut expected_after = self.before_card.clone();
        expected_after.template_id = Some(self.new_template_id);
        if self.after_card != expected_after {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        if self.old_base_refs.len() > 1024
            || self.new_base_refs.len() > 1024
            || self.before_rule_sets.len() > 256
            || self.after_rule_sets.len() > 256
        {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }
        self.validate_refs(&self.old_base_refs)?;
        self.validate_refs(&self.new_base_refs)?;
        self.validate_rule_sets(&self.before_rule_sets)?;
        self.validate_rule_sets(&self.after_rule_sets)?;
        if self
            .before_rule_sets
            .iter()
            .map(|row| row.rule_set_id)
            .collect::<Vec<_>>()
            != self
                .after_rule_sets
                .iter()
                .map(|row| row.rule_set_id)
                .collect::<Vec<_>>()
        {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }
        Ok(())
    }

    pub fn validate_template(&self) -> Result<(), AuthorityProtocolError> {
        super::config_completion::validate_card_rebind_template(self)
    }

    fn validate_card_image(
        &self,
        image: &AuthorityCardRebindCardImage,
        expected_template: Option<i64>,
    ) -> Result<(), AuthorityProtocolError> {
        if image.card_id != self.card_id
            || image.card_status != "ACTIVE"
            || image.user_id != Some(self.user_id)
            || image.tenant_id != Some(self.tenant_id)
            || image.domain_id != self.domain_id
            || image.template_id != expected_template
            || image.card_type.is_empty()
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        Ok(())
    }

    fn validate_refs(
        &self,
        refs: &[AuthorityCardRebindBaseRef],
    ) -> Result<(), AuthorityProtocolError> {
        let mut previous = 0;
        for reference in refs {
            super::authority_positive_id(reference.id, "ref_id")?;
            super::authority_positive_id(reference.rule_set_id, "ref_rule_set_id")?;
            if reference.card_id != self.card_id
                || reference.ref_type != "BASE"
                || reference.tenant_id != Some(self.tenant_id)
                || reference.created_at.trim().is_empty()
                || reference.id <= previous
            {
                return Err(AuthorityProtocolError::InvalidCoverage);
            }
            previous = reference.id;
        }
        Ok(())
    }

    fn validate_rule_sets(
        &self,
        aggregates: &[AuthorityCardRebindRuleSetAggregate],
    ) -> Result<(), AuthorityProtocolError> {
        let mut previous = 0;
        for aggregate in aggregates {
            aggregate.validate()?;
            if aggregate.rule_set_id <= previous {
                return Err(AuthorityProtocolError::InvalidCoverage);
            }
            let value: serde_json::Value = serde_json::from_str(&aggregate.canonical_image)
                .map_err(|_| AuthorityProtocolError::InvalidText {
                    field: "canonical_image",
                })?;
            let root = value
                .get("root")
                .and_then(serde_json::Value::as_object)
                .ok_or(AuthorityProtocolError::InvalidCoverage)?;
            let source_id = root.get("source_id").and_then(serde_json::Value::as_i64);
            if !(source_id == self.old_template_id || source_id == Some(self.new_template_id))
                || !root
                    .get("tenant_id")
                    .is_some_and(|value| value.is_null() || value.as_i64() == Some(self.tenant_id))
            {
                return Err(AuthorityProtocolError::ScopeMismatch);
            }
            previous = aggregate.rule_set_id;
        }
        Ok(())
    }
}

///
/// The envelope declares NO grant coverage: eligibility completion and the
/// publication OBJECT selector are mutually exclusive, and the complete
/// finite card set is carried by [`Self::completion`] alone.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityEligibilityStagedEvidence {
    pub kind: AuthorityEligibilityEvidenceKind,
    /// The typed per-card completion contract.
    pub completion: AuthorityEligibilityCompletionEvidence,
    /// Optional strict CardRebind source aggregate. It is present only for a
    /// different-template rebind whose actual materializable delta set is empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card_rebind: Option<AuthorityCardRebindEvidence>,
    /// Verbatim mirror of the actual source evidence retained by the source
    /// transaction: targets, receipts, audit and fanout identities of the
    /// Identity artifact. Opaque to the authority protocol; strictly parsed
    /// and validated by the registered DB source owner (the registered
    /// explicit source capability plus the DB typed capture is the trusted
    /// execution boundary).
    pub source_evidence: serde_json::Value,
}

impl AuthorityEligibilityStagedEvidence {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.completion.validate()?;
        if let Some(card_rebind) = &self.card_rebind {
            card_rebind.validate()?;
        }
        if !self.source_evidence.is_object() {
            return Err(AuthorityProtocolError::InvalidText {
                field: "source_evidence",
            });
        }
        let encoded = serde_json::to_vec(&self.source_evidence)
            .map_err(|_| AuthorityProtocolError::CanonicalSerialization)?;
        if encoded.len() > RETAINED_EVIDENCE_MAX_BYTES {
            return Err(AuthorityProtocolError::InvalidText {
                field: "source_evidence",
            });
        }
        Ok(())
    }
}

/// One card's exact ELIGIBILITY completion identity: the canonical CARD
/// scope plus the exact ELIGIBILITY head (generation/revoke) and the outbox
/// event/message identities that carried the completion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityEligibilityCardCompletion {
    /// Canonical CARD scope: `user_id: None`, `domain: Any`. ORG scopes and
    /// lens-bearing card scopes are rejected.
    pub scope: AuthorityProtocolScope,
    /// Exact ELIGIBILITY head generation after the completion. Positive.
    pub generation: u64,
    /// Exact ELIGIBILITY head revoke watermark. Never ahead of `generation`.
    pub revoke_watermark: u64,
    /// Stable outbox event identity that carried this card's completion.
    pub outbox_event_id: String,
    /// Stable message identity paired with `outbox_event_id`.
    pub message_id: String,
}

impl AuthorityEligibilityCardCompletion {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        if self.scope.canonical_card_publication_scope().as_ref() != Some(&self.scope) {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        self.scope.validate()?;
        authority_counter(self.generation, "generation")?;
        if self.revoke_watermark > self.generation {
            return Err(AuthorityProtocolError::RevokeWatermarkAhead);
        }
        authority_text(&self.outbox_event_id, "outbox_event_id")?;
        authority_text(&self.message_id, "message_id")?;
        Ok(())
    }

    /// Canonical, bounded store key of the completed card identity.
    pub fn card_key(&self) -> Result<String, AuthorityProtocolError> {
        self.scope.store_key_text()
    }
}

/// The complete finite card set of one eligibility completion: non-empty, at
/// most [`MAX_COMPLETION_CARDS`] entries, strictly sorted and deduplicated by
/// the canonical store key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityEligibilityCompletionEvidence {
    pub cards: Vec<AuthorityEligibilityCardCompletion>,
    /// Exact source-proven full fanout receipt for an explicitly empty result.
    /// A bare empty card list is never accepted as a completion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zero_card_selection: Option<AuthorityEligibilityEmptySelectionEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityEligibilityEmptySelectionEvidence {
    pub subject_kind: AuthorityEligibilityEmptySelectionSubjectKind,
    pub subject_id: i64,
    pub tenant_id: Option<i64>,
    pub schema_version: u16,
    pub selector: AuthorityEligibilityEmptySelectionSelector,
    pub selected_count: u64,
    pub source_before_image_digest: String,
    pub source_after_image_digest: String,
    pub selection_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityEligibilityEmptySelectionSubjectKind {
    UserStatus,
    UserDelete,
    TenantStatus,
    TenantDelete,
}

impl AuthorityEligibilityEmptySelectionSubjectKind {
    fn as_text(self) -> &'static str {
        match self {
            Self::UserStatus => "USER_STATUS",
            Self::UserDelete => "USER_DELETE",
            Self::TenantStatus => "TENANT_STATUS",
            Self::TenantDelete => "TENANT_DELETE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityEligibilityEmptySelectionKind {
    #[serde(rename = "ACTIVE_CARDS_BY_USER_V1")]
    ActiveCardsByUserV1,
    #[serde(rename = "ACTIVE_CARDS_BY_TENANT_V1")]
    ActiveCardsByTenantV1,
}

impl AuthorityEligibilityEmptySelectionKind {
    fn as_text(self) -> &'static str {
        match self {
            Self::ActiveCardsByUserV1 => "ACTIVE_CARDS_BY_USER_V1",
            Self::ActiveCardsByTenantV1 => "ACTIVE_CARDS_BY_TENANT_V1",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityEligibilityEmptySelectionCompleteness {
    ExactFullFanout,
}

impl AuthorityEligibilityEmptySelectionCompleteness {
    fn as_text(self) -> &'static str {
        match self {
            Self::ExactFullFanout => "EXACT_FULL_FANOUT",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityEligibilityEmptySelectionSelector {
    pub kind: AuthorityEligibilityEmptySelectionKind,
    pub version: u16,
    pub completeness: AuthorityEligibilityEmptySelectionCompleteness,
}

impl AuthorityEligibilityEmptySelectionEvidence {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        if self.subject_id <= 0 {
            return Err(AuthorityProtocolError::InvalidIdentifier {
                field: "subject_id",
            });
        }
        let (expected_kind, expected_tenant) = match self.subject_kind {
            AuthorityEligibilityEmptySelectionSubjectKind::UserStatus
            | AuthorityEligibilityEmptySelectionSubjectKind::UserDelete => (
                AuthorityEligibilityEmptySelectionKind::ActiveCardsByUserV1,
                None,
            ),
            AuthorityEligibilityEmptySelectionSubjectKind::TenantStatus
            | AuthorityEligibilityEmptySelectionSubjectKind::TenantDelete => (
                AuthorityEligibilityEmptySelectionKind::ActiveCardsByTenantV1,
                Some(self.subject_id),
            ),
        };
        if self.selector.kind != expected_kind || self.tenant_id != expected_tenant {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        if expected_tenant.is_some_and(|tenant_id| tenant_id <= 0) {
            return Err(AuthorityProtocolError::InvalidIdentifier { field: "tenant_id" });
        }
        if self.schema_version != 1
            || self.selector.version != 1
            || self.selector.completeness
                != AuthorityEligibilityEmptySelectionCompleteness::ExactFullFanout
            || self.selected_count != 0
        {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }
        authority_digest(
            &self.source_before_image_digest,
            "source_before_image_digest",
        )?;
        authority_digest(&self.source_after_image_digest, "source_after_image_digest")?;
        authority_digest(&self.selection_digest, "selection_digest")?;
        if self.recompute_selection_digest()? != self.selection_digest {
            return Err(AuthorityProtocolError::DigestMismatch {
                field: "selection_digest",
            });
        }
        Ok(())
    }

    /// SHA-256 over the frozen domain-separated length-prefixed V1 field list.
    pub fn recompute_selection_digest(&self) -> Result<String, AuthorityProtocolError> {
        let mut bytes = b"ASTRAL_ELIGIBILITY_EMPTY_SELECTION_V1\0".to_vec();
        super::authority_field(&mut bytes, self.subject_kind.as_text());
        super::authority_field(&mut bytes, &self.subject_id.to_string());
        super::authority_field(
            &mut bytes,
            &self
                .tenant_id
                .map_or_else(|| "-".to_owned(), |id| id.to_string()),
        );
        super::authority_field(&mut bytes, &self.schema_version.to_string());
        super::authority_field(&mut bytes, self.selector.kind.as_text());
        super::authority_field(&mut bytes, &self.selector.version.to_string());
        super::authority_field(&mut bytes, self.selector.completeness.as_text());
        super::authority_field(&mut bytes, &self.selected_count.to_string());
        super::authority_field(&mut bytes, &self.source_before_image_digest);
        super::authority_field(&mut bytes, &self.source_after_image_digest);
        Ok(super::authority_sha256_hex(&bytes))
    }
}

impl AuthorityEligibilityCompletionEvidence {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        if self.cards.len() > MAX_COMPLETION_CARDS {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }
        if self.cards.is_empty() {
            self.zero_card_selection
                .as_ref()
                .ok_or(AuthorityProtocolError::InvalidCoverage)?
                .validate()?;
            return Ok(());
        }
        if self.zero_card_selection.is_some() {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }
        let mut previous: Option<String> = None;
        for card in &self.cards {
            card.validate()?;
            let key = card.card_key()?;
            if let Some(previous) = &previous {
                if &key <= previous {
                    // Unsorted or duplicated card identity: the declared set
                    // is never repaired silently.
                    return Err(AuthorityProtocolError::InvalidCoverage);
                }
            }
            previous = Some(key);
        }
        Ok(())
    }

    /// Strictly decode the typed shape from a staged evidence envelope.
    ///
    /// The envelope must declare NO grant coverage (mutual exclusion with the
    /// publication selector), and its `evidence` value must be exactly the
    /// dedicated [`AuthorityEligibilityStagedEvidence`] shape with the
    /// `ELIGIBILITY_COMPLETION` kind. Anything else — grant coverage, mixed
    /// kinds, ORG scopes, unknown fields, generic JSON — is rejected.
    pub fn from_staged_envelope(
        envelope: &AuthorityStagedSourceEvidence,
    ) -> Result<Self, AuthorityProtocolError> {
        envelope.validate()?;
        if envelope.coverage.is_some() {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }
        let staged: AuthorityEligibilityStagedEvidence =
            serde_json::from_value(envelope.evidence.clone())
                .map_err(|_| AuthorityProtocolError::DigestMismatch { field: "evidence" })?;
        staged.validate()?;
        Ok(staged.completion)
    }

    /// The canonical staged envelope a source owner serializes for this
    /// completion: `coverage: None`, the typed `ELIGIBILITY_COMPLETION`
    /// shape, and the verbatim source mirror. The exact text of this envelope
    /// is what the canonical digest pins at COMMIT.
    pub fn to_staged_envelope(
        &self,
        source_evidence: serde_json::Value,
    ) -> Result<AuthorityStagedSourceEvidence, AuthorityProtocolError> {
        self.validate()?;
        let staged = AuthorityEligibilityStagedEvidence {
            kind: AuthorityEligibilityEvidenceKind::EligibilityCompletion,
            completion: self.clone(),
            card_rebind: None,
            source_evidence,
        };
        staged.validate()?;
        Ok(AuthorityStagedSourceEvidence {
            coverage: None,
            evidence: serde_json::to_value(&staged)
                .map_err(|_| AuthorityProtocolError::CanonicalSerialization)?,
        })
    }

    /// The canonical staged envelope for an eligibility completion with an
    /// optional strict CardRebind aggregate artifact.
    pub fn to_staged_envelope_with_card_rebind(
        &self,
        source_evidence: serde_json::Value,
        card_rebind: Option<AuthorityCardRebindEvidence>,
    ) -> Result<AuthorityStagedSourceEvidence, AuthorityProtocolError> {
        self.validate()?;
        if let Some(card_rebind) = &card_rebind {
            card_rebind.validate()?;
        }
        let staged = AuthorityEligibilityStagedEvidence {
            kind: AuthorityEligibilityEvidenceKind::EligibilityCompletion,
            completion: self.clone(),
            card_rebind,
            source_evidence,
        };
        staged.validate()?;
        Ok(AuthorityStagedSourceEvidence {
            coverage: None,
            evidence: serde_json::to_value(&staged)
                .map_err(|_| AuthorityProtocolError::CanonicalSerialization)?,
        })
    }
}

/// declared typed completion plus the retained staged-evidence bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityEligibilityCompletionRequest {
    pub caller: AuthorityCallerIdentity,
    /// Full exact COMMITTED binding echoed from the commit response. Its
    /// `staged_evidence_digest` is the evidence-digest pin this request is
    /// verified against (against the STORED binding, never trusted alone).
    pub binding: AuthorityCommitBinding,
    /// Declared typed completion. Must equal the shape decoded from the
    /// retained bytes; substitution is rejected, never repaired.
    pub completion: AuthorityEligibilityCompletionEvidence,
    /// Exact retained staged-evidence envelope text pinned at COMMIT.
    pub retained_staged_evidence: AuthorityRetainedStagedEvidence,
}

impl AuthorityEligibilityCompletionRequest {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.caller.validate()?;
        self.binding.validate()?;
        if self.binding.mutation_kind != super::AuthorityMutationKind::AuthorizationSource {
            return Err(AuthorityProtocolError::StateConflict {
                record: "reservation",
                state: super::AuthorityMutationKind::ProtectedBusiness
                    .as_text()
                    .to_owned(),
            });
        }
        if self.binding.service_id != self.caller.service_id {
            return Err(AuthorityProtocolError::CallerIdentityMismatch);
        }
        self.completion.validate()?;
        self.retained_staged_evidence.validate()?;
        // Self-consistent pin: the retained bytes must carry exactly the
        // digest the request's own binding declares. The service re-proves
        // this against the STORED binding.
        if self.retained_staged_evidence.canonical_digest()? != self.binding.staged_evidence_digest
        {
            return Err(AuthorityProtocolError::DigestMismatch {
                field: "staged_evidence_digest",
            });
        }
        Ok(())
    }
}

/// Immutable completion receipt: created once by the authority in the same
/// leader-fenced CAS that flips the reservation to
/// [`super::AuthorityReservationState::Completed`], advances the global
/// frontier and bumps the read-gate epoch. A stable exact replay reads this
/// receipt back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityEligibilityCompletionReceipt {
    pub receipt_id: String,
    pub reservation_id: String,
    pub operation_id: String,
    pub event_id: String,
    /// The exact commit binding the completion was proven against.
    pub binding: AuthorityCommitBinding,
    /// The typed completion exactly as decoded from the pinned evidence.
    pub completion: AuthorityEligibilityCompletionEvidence,
    pub completed_at: i64,
    /// The COMPLETE post-completion frontier recorded in the same CAS; a
    /// replay serves this frontier and never re-advances the current one.
    pub global_frontier: GlobalAuthorityFrontier,
}

impl AuthorityEligibilityCompletionReceipt {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        use super::authority_text as text;
        text(&self.receipt_id, "receipt_id")?;
        text(&self.reservation_id, "reservation_id")?;
        text(&self.operation_id, "operation_id")?;
        text(&self.event_id, "event_id")?;
        self.binding.validate()?;
        self.completion.validate()?;
        authority_timestamp(self.completed_at, "completed_at")?;
        self.global_frontier.validate()?;
        if self.binding.reservation_id != self.reservation_id
            || self.binding.operation_id != self.operation_id
            || self.binding.event_id != self.event_id
            || self.global_frontier.authorization_edition != AUTHORIZATION_EDITION
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        Ok(())
    }
}

/// Response of one eligibility completion: the terminal enum echo, the
/// reservation in its terminal state, the immutable receipt, and the
/// frontier that this completion produced (or recorded, on replay).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityEligibilityCompletionResponse {
    pub disposition: AuthorityReservationDisposition,
    pub reservation: AuthorityScopeReservation,
    pub receipt: AuthorityEligibilityCompletionReceipt,
    pub global_frontier: GlobalAuthorityFrontier,
    pub read_gate: AuthorityReadGate,
}

impl AuthorityEligibilityCompletionResponse {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        use super::{AuthorityMutationKind, AuthorityReservationState};
        self.receipt.validate()?;
        self.reservation.validate()?;
        self.global_frontier.validate()?;
        self.read_gate.validate()?;
        if self.disposition != AuthorityReservationDisposition::Completed
            || self.reservation.state != AuthorityReservationState::Completed
            || self.reservation.intent.mutation_kind != AuthorityMutationKind::AuthorizationSource
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        let binding = &self.receipt.binding;
        if self.reservation.reservation_id != self.receipt.reservation_id
            || self.reservation.intent.operation_id != self.receipt.operation_id
            || self.reservation.intent.event_id != self.receipt.event_id
            || self.reservation.intent.service_id != binding.service_id
            || self.reservation.intent.database_id != binding.database_id
            || self.reservation.intent.request_digest != binding.request_digest
            || self.reservation.source_commit_digest.as_deref()
                != Some(binding.source_commit_digest.as_str())
            || self.reservation.after_image_digest.as_deref()
                != Some(binding.after_image_digest.as_str())
            || self.reservation.source_outcome_digest.as_deref()
                != Some(binding.source_outcome_digest.as_str())
            // The eligibility path never publishes: no certificate identity,
            // no certified scopes, no canonical publication proof.
            || self.reservation.certificate_id.is_some()
            || !self.reservation.certified_scopes.is_empty()
            // First completion and replay both serve the recorded frontier.
            || self.global_frontier != self.receipt.global_frontier
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority_protocol::{
        AuthorityMutationKind, AuthorityOrgMemberSubject, AuthorityOrgScope, AuthorityWireError,
        AuthorityWireErrorCode,
    };

    fn canonical_card(card_id: i64) -> AuthorityProtocolScope {
        AuthorityProtocolScope::Card(crate::AuthorizationAuthorityScope {
            tenant_id: 7,
            card_id,
            user_id: None,
            domain: crate::AuthorizationDomainScope::Any,
        })
    }

    fn card(card_id: i64) -> AuthorityEligibilityCardCompletion {
        AuthorityEligibilityCardCompletion {
            scope: canonical_card(card_id),
            generation: 4,
            revoke_watermark: 2,
            outbox_event_id: "outbox-event-1".to_owned(),
            message_id: "message-1".to_owned(),
        }
    }

    fn evidence() -> AuthorityEligibilityCompletionEvidence {
        AuthorityEligibilityCompletionEvidence {
            cards: vec![card(17), card(18)],
            zero_card_selection: None,
        }
    }

    fn zero_selection(
        subject_kind: AuthorityEligibilityEmptySelectionSubjectKind,
        subject_id: i64,
        tenant_id: Option<i64>,
    ) -> AuthorityEligibilityEmptySelectionEvidence {
        let kind = match subject_kind {
            AuthorityEligibilityEmptySelectionSubjectKind::UserStatus
            | AuthorityEligibilityEmptySelectionSubjectKind::UserDelete => {
                AuthorityEligibilityEmptySelectionKind::ActiveCardsByUserV1
            }
            AuthorityEligibilityEmptySelectionSubjectKind::TenantStatus
            | AuthorityEligibilityEmptySelectionSubjectKind::TenantDelete => {
                AuthorityEligibilityEmptySelectionKind::ActiveCardsByTenantV1
            }
        };
        let mut selection = AuthorityEligibilityEmptySelectionEvidence {
            subject_kind,
            subject_id,
            tenant_id,
            schema_version: 1,
            selector: AuthorityEligibilityEmptySelectionSelector {
                kind,
                version: 1,
                completeness: AuthorityEligibilityEmptySelectionCompleteness::ExactFullFanout,
            },
            selected_count: 0,
            source_before_image_digest: "aa".repeat(32),
            source_after_image_digest: "bb".repeat(32),
            selection_digest: String::new(),
        };
        selection.selection_digest = selection.recompute_selection_digest().unwrap();
        selection
    }

    fn source_mirror() -> serde_json::Value {
        serde_json::json!({
            "targets": [{"card_id": 17, "tenant_id": 7}],
            "receipts": [{"receipt_id": "r-1"}],
            "audit": {"actor": "identity-owner"},
            "fanout": [{"message_id": "message-1"}]
        })
    }

    fn envelope_text(evidence: &AuthorityEligibilityCompletionEvidence) -> String {
        serde_json::to_string(&evidence.to_staged_envelope(source_mirror()).unwrap()).unwrap()
    }

    #[test]
    fn canonical_digest_is_order_insensitive_and_binds_exact_content() {
        let original = envelope_text(&evidence());
        let retained = AuthorityRetainedStagedEvidence::new(original.clone());
        let digest = retained.canonical_digest().unwrap();
        assert_eq!(digest.len(), 64);

        // Order-insensitive canonicalization (the DB twin contract): the
        // same content with different key order and spacing carries one
        // digest; content drift never does.
        let reordered = AuthorityRetainedStagedEvidence::new(
            r#"{ "evidence": { "sourceEvidence": { "targets": [ { "card_id": 17, "tenant_id": 7 } ], "receipts": [ { "receipt_id": "r-1" } ], "audit": { "actor": "identity-owner" }, "fanout": [ { "message_id": "message-1" } ] }, "kind": "ELIGIBILITY_COMPLETION", "completion": { "cards": [ { "scope": { "kind": "CARD", "tenantId": 7, "cardId": 17, "userId": null, "domain": "ANY" }, "generation": 4, "revokeWatermark": 2, "outboxEventId": "outbox-event-1", "messageId": "message-1" }, { "scope": { "kind": "CARD", "tenantId": 7, "cardId": 18, "userId": null, "domain": "ANY" }, "generation": 4, "revokeWatermark": 2, "outboxEventId": "outbox-event-1", "messageId": "message-1" } ] } }, "coverage": null }"#.to_owned(),
        );
        assert_ne!(reordered.as_str(), retained.as_str());
        assert_eq!(reordered.canonical_digest().unwrap(), digest);

        // Content drift changes the digest.
        let mut drifted = evidence();
        drifted.cards[0].generation = 5;
        let drifted = AuthorityRetainedStagedEvidence::new(envelope_text(&drifted));
        assert_ne!(drifted.canonical_digest().unwrap(), digest);

        // Invalid JSON and empty text fail closed.
        assert!(AuthorityRetainedStagedEvidence::new("{invalid".to_owned())
            .canonical_digest()
            .is_err());
        assert!(AuthorityRetainedStagedEvidence::new(String::new())
            .validate()
            .is_err());
    }

    #[test]
    fn evidence_shape_rejects_org_lensed_unsorted_and_empty_sets() {
        let mut mixed = evidence();
        mixed.cards[1].scope = AuthorityProtocolScope::Org(AuthorityOrgScope {
            tenant_id: 7,
            root_tenant_id: None,
            member: AuthorityOrgMemberSubject {
                user_id: 1,
                identity_card_id: 2,
                card_id: 3,
            },
        });
        assert!(matches!(
            mixed.validate(),
            Err(AuthorityProtocolError::ScopeMismatch)
        ));

        let mut lensed = evidence();
        lensed.cards[0].scope = AuthorityProtocolScope::Card(crate::AuthorizationAuthorityScope {
            tenant_id: 7,
            card_id: 17,
            user_id: Some(23),
            domain: crate::AuthorizationDomainScope::Exact(31),
        });
        assert!(matches!(
            lensed.validate(),
            Err(AuthorityProtocolError::ScopeMismatch)
        ));

        let mut unsorted = evidence();
        unsorted.cards.swap(0, 1);
        assert!(matches!(
            unsorted.validate(),
            Err(AuthorityProtocolError::InvalidCoverage)
        ));

        let duplicate = AuthorityEligibilityCompletionEvidence {
            cards: vec![card(17), card(17)],
            zero_card_selection: None,
        };
        assert!(matches!(
            duplicate.validate(),
            Err(AuthorityProtocolError::InvalidCoverage)
        ));

        assert!(matches!(
            AuthorityEligibilityCompletionEvidence {
                cards: Vec::new(),
                zero_card_selection: None,
            }
            .validate(),
            Err(AuthorityProtocolError::InvalidCoverage)
        ));

        for (subject_kind, tenant_id) in [
            (
                AuthorityEligibilityEmptySelectionSubjectKind::UserStatus,
                None,
            ),
            (
                AuthorityEligibilityEmptySelectionSubjectKind::UserDelete,
                None,
            ),
            (
                AuthorityEligibilityEmptySelectionSubjectKind::TenantStatus,
                Some(42),
            ),
            (
                AuthorityEligibilityEmptySelectionSubjectKind::TenantDelete,
                Some(42),
            ),
        ] {
            AuthorityEligibilityCompletionEvidence {
                cards: Vec::new(),
                zero_card_selection: Some(zero_selection(subject_kind, 42, tenant_id)),
            }
            .validate()
            .unwrap();
        }

        let mut wrong_scope = zero_selection(
            AuthorityEligibilityEmptySelectionSubjectKind::TenantStatus,
            42,
            Some(42),
        );
        wrong_scope.tenant_id = Some(7);
        wrong_scope.selection_digest = wrong_scope.recompute_selection_digest().unwrap();
        assert!(AuthorityEligibilityCompletionEvidence {
            cards: Vec::new(),
            zero_card_selection: Some(wrong_scope),
        }
        .validate()
        .is_err());

        let mut wrong_kind = zero_selection(
            AuthorityEligibilityEmptySelectionSubjectKind::UserStatus,
            42,
            None,
        );
        wrong_kind.selector.kind = AuthorityEligibilityEmptySelectionKind::ActiveCardsByTenantV1;
        wrong_kind.selection_digest = wrong_kind.recompute_selection_digest().unwrap();
        assert!(wrong_kind.validate().is_err());

        let mut nonzero_count = zero_selection(
            AuthorityEligibilityEmptySelectionSubjectKind::UserStatus,
            42,
            None,
        );
        nonzero_count.selected_count = 1;
        assert!(nonzero_count.validate().is_err());

        let mut unknown_selector = zero_selection(
            AuthorityEligibilityEmptySelectionSubjectKind::UserStatus,
            42,
            None,
        );
        unknown_selector.selector.version = 2;
        unknown_selector.selection_digest = unknown_selector.recompute_selection_digest().unwrap();
        assert!(unknown_selector.validate().is_err());

        let mut revoke_ahead = evidence();
        revoke_ahead.cards[0].revoke_watermark = 5;
        assert!(matches!(
            revoke_ahead.validate(),
            Err(AuthorityProtocolError::RevokeWatermarkAhead)
        ));

        let mut zero_generation = evidence();
        zero_generation.cards[0].generation = 0;
        assert!(matches!(
            zero_generation.validate(),
            Err(AuthorityProtocolError::InvalidCounter { .. })
        ));
    }

    #[test]
    fn envelope_decoding_requires_the_typed_kind_and_no_grant_coverage() {
        let evidence = evidence();
        let envelope = evidence.to_staged_envelope(source_mirror()).unwrap();
        assert!(
            envelope.coverage.is_none(),
            "eligibility never declares grant coverage"
        );
        assert_eq!(
            AuthorityEligibilityCompletionEvidence::from_staged_envelope(&envelope).unwrap(),
            evidence
        );

        // Grant coverage on the envelope is mutually exclusive and refused.
        let mut covered = envelope.clone();
        covered.coverage = Some(crate::authority_protocol::AuthorityStagedScopeCoverage {
            scopes: vec![canonical_card(17)],
        });
        assert!(matches!(
            AuthorityEligibilityCompletionEvidence::from_staged_envelope(&covered),
            Err(AuthorityProtocolError::InvalidCoverage)
        ));

        // Unknown fields inside the typed evidence are rejected: generic JSON
        // that merely contains cards is never a completion.
        let mut raw =
            serde_json::to_value(evidence.to_staged_envelope(source_mirror()).unwrap()).unwrap();
        raw["evidence"]["extra"] = serde_json::json!(1);
        let smuggled: AuthorityStagedSourceEvidence = serde_json::from_value(raw).unwrap();
        assert!(AuthorityEligibilityCompletionEvidence::from_staged_envelope(&smuggled).is_err());

        // A foreign kind discriminator is rejected.
        let mut foreign =
            serde_json::to_value(evidence.to_staged_envelope(source_mirror()).unwrap()).unwrap();
        foreign["evidence"]["kind"] = serde_json::json!("GRANT_PUBLICATION");
        let foreign: AuthorityStagedSourceEvidence = serde_json::from_value(foreign).unwrap();
        assert!(AuthorityEligibilityCompletionEvidence::from_staged_envelope(&foreign).is_err());

        // The verbatim source mirror survives the round trip untouched.
        let decoded: AuthorityEligibilityStagedEvidence =
            serde_json::from_value(envelope.evidence).unwrap();
        assert_eq!(decoded.source_evidence, source_mirror());
        assert_eq!(decoded.kind.as_text(), "ELIGIBILITY_COMPLETION");

        // A non-object source mirror is refused.
        let scalar = evidence.clone();
        assert!(matches!(
            scalar.to_staged_envelope(serde_json::json!(7)),
            Err(AuthorityProtocolError::InvalidText { .. })
        ));
    }

    #[test]
    fn request_validation_pins_digest_and_caller_and_kind() {
        let mut request = AuthorityEligibilityCompletionRequest {
            caller: AuthorityCallerIdentity {
                service_id: "astral-db-primary".to_owned(),
                request_nonce: "nonce-1".to_owned(),
                issued_at: 1_700,
            },
            binding: binding(),
            completion: evidence(),
            retained_staged_evidence: AuthorityRetainedStagedEvidence::new(String::new()),
        };
        let text = envelope_text(&evidence());
        let digest = AuthorityRetainedStagedEvidence::new(text.clone())
            .canonical_digest()
            .unwrap();
        request.retained_staged_evidence = AuthorityRetainedStagedEvidence::new(text);
        request.binding.staged_evidence_digest = digest;
        request.validate().unwrap();

        // Digest pin mismatch is rejected.
        let mut wrong_digest = request.clone();
        wrong_digest.binding.staged_evidence_digest = "04".repeat(32);
        assert!(matches!(
            wrong_digest.validate(),
            Err(AuthorityProtocolError::DigestMismatch { .. })
        ));

        // Caller identity mismatch is rejected.
        let mut wrong_caller = request.clone();
        wrong_caller.caller.service_id = "astral-db-other".to_owned();
        assert!(matches!(
            wrong_caller.validate(),
            Err(AuthorityProtocolError::CallerIdentityMismatch)
        ));

        // ProtectedBusiness bindings never complete eligibility.
        let mut protected = request;
        protected.binding.mutation_kind = AuthorityMutationKind::ProtectedBusiness;
        assert!(matches!(
            protected.validate(),
            Err(AuthorityProtocolError::StateConflict { .. })
        ));
    }

    fn binding() -> AuthorityCommitBinding {
        AuthorityCommitBinding {
            reservation_id: "res-1".to_owned(),
            operation_id: "operation-1".to_owned(),
            event_id: "event-1".to_owned(),
            admission_proof_id: "proof-1".to_owned(),
            mutation_kind: AuthorityMutationKind::AuthorizationSource,
            service_id: "astral-db-primary".to_owned(),
            database_id: "db-1".to_owned(),
            request_digest: "ab".repeat(32),
            source_commit_digest: "cd".repeat(32),
            before_image_digest: Some("ef".repeat(32)),
            after_image_digest: "01".repeat(32),
            source_outcome_digest: "02".repeat(32),
            staged_evidence_digest: "03".repeat(32),
        }
    }

    #[test]
    fn wire_serialization_names_are_frozen() {
        // The kind discriminator VALUE is SCREAMING_SNAKE_CASE (enum variant
        // rename); struct FIELD names are camelCase. Both frozen here so the
        // DB worker and the client library cannot drift.
        assert_eq!(
            serde_json::to_value(AuthorityEligibilityEvidenceKind::EligibilityCompletion).unwrap(),
            serde_json::json!("ELIGIBILITY_COMPLETION")
        );
        let staged: serde_json::Value =
            serde_json::to_value(evidence().to_staged_envelope(source_mirror()).unwrap()).unwrap();
        let envelope = staged.as_object().unwrap();
        assert_eq!(envelope["coverage"], serde_json::json!(null));
        let evidence_json = envelope["evidence"].as_object().unwrap();
        assert_eq!(
            evidence_json["kind"],
            serde_json::json!("ELIGIBILITY_COMPLETION")
        );
        // Exact camelCase field names at every level (top to bottom).
        assert!(evidence_json.get("completion").is_some());
        assert!(evidence_json.get("sourceEvidence").is_some());
        assert_eq!(
            evidence_json["completion"]["cards"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let card = &evidence_json["completion"]["cards"][0];
        for field in [
            "scope",
            "generation",
            "revokeWatermark",
            "outboxEventId",
            "messageId",
        ] {
            assert!(card.get(field).is_some(), "missing card field {field}");
        }
        assert_eq!(card["scope"]["kind"], serde_json::json!("CARD"));
        assert_eq!(card["scope"]["domain"], serde_json::json!("ANY"));
        assert_eq!(card["scope"]["userId"], serde_json::json!(null));

        // The retained evidence travels as a transparent JSON string.
        let text = envelope_text(&evidence());
        assert_eq!(
            serde_json::to_value(AuthorityRetainedStagedEvidence::new(text.clone())).unwrap(),
            serde_json::json!(text)
        );

        // Request field names are camelCase end to end.
        let request = serde_json::json!({
            "caller": {"serviceId": "s", "requestNonce": "n", "issuedAt": 1},
            "binding": serde_json::to_value(binding()).unwrap(),
            "completion": serde_json::to_value(evidence()).unwrap(),
            "retainedStagedEvidence": text,
        });
        let decoded: AuthorityEligibilityCompletionRequest =
            serde_json::from_value(request).unwrap();
        assert_eq!(decoded.completion, evidence());

        // The state/disposition terminal echo serializes as COMPLETED.
        assert_eq!(
            serde_json::to_value(AuthorityReservationDisposition::Completed).unwrap(),
            serde_json::json!("COMPLETED")
        );
        assert_eq!(
            serde_json::to_value(super::super::AuthorityReservationState::Completed).unwrap(),
            serde_json::json!("COMPLETED")
        );
    }

    #[test]
    fn wire_error_taxonomy_stays_closed() {
        assert!(matches!(
            AuthorityWireError::from_protocol(&AuthorityProtocolError::RevokeWatermarkAhead).code,
            AuthorityWireErrorCode::Rejected
        ));
    }
}
