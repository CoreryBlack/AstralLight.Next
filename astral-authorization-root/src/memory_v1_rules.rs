//! memory—v1: Closed rule content and deterministic version integrity.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::memory_v1_db_rows::{
    BindingConfirmationRow, BindingLayer, RuleSetChangeConfirmationRow, RuleSetVersionRow,
};

const HASH_DOMAIN: &[u8] = b"astrallight/memory-v1/rule-set-version/1\0";
const MAX_RULES: usize = 4096;
const MAX_TEXT_BYTES: usize = 256;
/// memory—v1 §4.4: rule identifiers are at most 64 bytes and unique within a version.
pub const MAX_RULE_ID_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemoryV1RuleEffect {
    Allow,
    Deny,
}

/// memory—v1 §4.10: owner visibility scope; absent entries default to the
/// strictest form (`self`), per the fail-closed default.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum MemoryV1OwnerScope {
    /// Only objects whose trusted owner attribute equals the session user.
    #[default]
    #[serde(rename = "self")]
    SelfUser,
    /// No owner constraint.
    #[serde(rename = "all")]
    AllUsers,
}

/// memory—v1 §4.10: tenant visibility scope; absent entries default to the
/// strictest form (`self`). Descendant resolution happens in the root tenant
/// tree, never here.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum MemoryV1TenantScope {
    /// Only objects whose trusted tenant attribute equals the card tenant.
    #[default]
    #[serde(rename = "self")]
    SelfTenant,
    /// The card tenant plus its resolved descendants in the root tenant tree.
    #[serde(rename = "self+descendants")]
    SelfAndDescendants,
}

/// memory—v1 §4.4: entry-level validity window in trusted Unix seconds.
///
/// Both bounds are optional; `from` is inclusive and `until` exclusive. An
/// absent window is an open interval. A window where both bounds are present
/// with `from >= until` fails content parsing.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MemoryV1Validity {
    #[serde(default)]
    pub from: Option<i64>,
    #[serde(default)]
    pub until: Option<i64>,
}

impl MemoryV1Validity {
    /// memory—v1 §4.4: `from <= t` and (`until` absent or `t < until`).
    pub fn active_at(&self, at: i64) -> bool {
        window_active(self.from, self.until, at)
    }
}

/// memory—v1 §4.4: one window bound pair; both bounds optional.
///
/// Shared by entry-level validity and binding-level validity so the two-level
/// intersection (§4.10) uses exactly the same boundary semantics.
pub fn window_active(from: Option<i64>, until: Option<i64>, at: i64) -> bool {
    from.is_none_or(|from| from <= at) && until.is_none_or(|until| at < until)
}

/// memory—v1 §4.4: one closed rule entry.
///
/// `rule_id` is required and unique within its rule-set version. Absent
/// `validity` is an open interval; absent scopes default to the strictest
/// `self`/`self` combination.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MemoryV1Rule {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    pub resource: String,
    pub action: String,
    pub effect: MemoryV1RuleEffect,
    #[serde(default)]
    pub validity: Option<MemoryV1Validity>,
    #[serde(default, rename = "ownerScope")]
    pub owner_scope: MemoryV1OwnerScope,
    #[serde(default, rename = "tenantScope")]
    pub tenant_scope: MemoryV1TenantScope,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MemoryV1RuleSetContent {
    pub rules: Vec<MemoryV1Rule>,
}

/// memory—v1 §4.4: one type-level hit before window and scope predicates run.
///
/// The formal engine applies the two-level window (entry ∩ binding) and the
/// two-layer scope (entry ∩ binding) with request context; this type only
/// carries what the content declares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryV1RuleHit<'a> {
    pub rule_id: &'a str,
    pub effect: MemoryV1RuleEffect,
    pub validity: Option<&'a MemoryV1Validity>,
    pub owner_scope: MemoryV1OwnerScope,
    pub tenant_scope: MemoryV1TenantScope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryV1RuleMatch {
    Allow,
    Deny,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryV1BindingMatch {
    Allow,
    Deny,
    None,
    Incomplete,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum MemoryV1RuleError {
    #[error("rule-set version fields must be non-empty")]
    EmptyField,
    #[error("rule-set version hash input does not match canonical fields")]
    HashInputMismatch,
    #[error("rule-set version hash does not match canonical fields")]
    HashMismatch,
    #[error("rule-set content is invalid: {0}")]
    InvalidContent(String),
    #[error("rule-set contains too many rules")]
    TooManyRules,
    #[error("rule-set rule field is invalid")]
    InvalidRule,
    #[error("rule-set rule identifiers are not unique within the version")]
    DuplicateRuleId,
    #[error("rule-set validity window is invalid")]
    InvalidValidity,
    #[error("binding confirmation does not match the selected version")]
    ConfirmationMismatch,
}

impl MemoryV1RuleSetContent {
    /// Parse and validate the closed memory—v1 rule grammar.
    ///
    /// §4.4: validates rule identifier uniqueness and window ordering; absent
    /// scopes default to the strictest form and absent windows stay open.
    pub fn parse(bytes: &[u8]) -> Result<Self, MemoryV1RuleError> {
        let content: Self = serde_json::from_slice(bytes)
            .map_err(|error| MemoryV1RuleError::InvalidContent(error.to_string()))?;
        if content.rules.len() > MAX_RULES {
            return Err(MemoryV1RuleError::TooManyRules);
        }
        let mut rule_ids = std::collections::BTreeSet::new();
        for rule in &content.rules {
            if rule.rule_id.is_empty()
                || rule.rule_id.len() > MAX_RULE_ID_BYTES
                || rule.resource.is_empty()
                || rule.action.is_empty()
                || rule.resource.len() > MAX_TEXT_BYTES
                || rule.action.len() > MAX_TEXT_BYTES
            {
                return Err(MemoryV1RuleError::InvalidRule);
            }
            if !rule_ids.insert(rule.rule_id.as_str()) {
                return Err(MemoryV1RuleError::DuplicateRuleId);
            }
            if let Some(validity) = &rule.validity {
                if let (Some(from), Some(until)) = (validity.from, validity.until) {
                    if from >= until {
                        return Err(MemoryV1RuleError::InvalidValidity);
                    }
                }
            }
        }
        Ok(content)
    }

    /// memory—v1 §4.8: every type-level hit, without window or scope applied.
    ///
    /// The formal engine consumes this list and applies the two-level window
    /// and two-layer scope predicates with request context; the collapsed
    /// `evaluate` view below remains only for non-formal helpers that cannot
    /// supply that context.
    pub fn rule_hits(&self, resource: &str, action: &str) -> Vec<MemoryV1RuleHit<'_>> {
        self.rules
            .iter()
            .filter(|rule| rule.resource == resource && rule.action == action)
            .map(|rule| MemoryV1RuleHit {
                rule_id: rule.rule_id.as_str(),
                effect: rule.effect,
                validity: rule.validity.as_ref(),
                owner_scope: rule.owner_scope,
                tenant_scope: rule.tenant_scope,
            })
            .collect()
    }

    /// Collapsed type-level match. Scope and validity are **not** applied:
    /// this helper must not be used by the formal decision path, which owns
    /// the window and scope predicates (§4.4/§4.10).
    pub fn evaluate(&self, resource: &str, action: &str) -> MemoryV1RuleMatch {
        let mut allow = false;
        let mut deny = false;
        for rule in &self.rules {
            if rule.resource != resource || rule.action != action {
                continue;
            }
            match rule.effect {
                MemoryV1RuleEffect::Allow => allow = true,
                MemoryV1RuleEffect::Deny => deny = true,
            }
        }
        if deny {
            MemoryV1RuleMatch::Deny
        } else if allow {
            MemoryV1RuleMatch::Allow
        } else {
            MemoryV1RuleMatch::None
        }
    }
}

/// Validate the version's canonical hash and parse its rule content.
pub fn parse_version(
    version: &RuleSetVersionRow,
) -> Result<MemoryV1RuleSetContent, MemoryV1RuleError> {
    if version.version_bytes.is_empty()
        || version.content_bytes.is_empty()
        || version.timestamp_bytes.is_empty()
    {
        return Err(MemoryV1RuleError::EmptyField);
    }
    let canonical = canonical_version_bytes(
        &version.version_bytes,
        &version.content_bytes,
        &version.timestamp_bytes,
    );
    if version.hash_input_bytes != canonical {
        return Err(MemoryV1RuleError::HashInputMismatch);
    }
    let digest: [u8; 32] = Sha256::digest(&canonical).into();
    if version.hash_bytes.as_slice() != digest {
        return Err(MemoryV1RuleError::HashMismatch);
    }
    MemoryV1RuleSetContent::parse(&version.content_bytes)
}

// memory—v1 §4.11/N-16 (B-3.8): structural validation of a binding's
// confirmation row is independent of the selected rule-set version. This
// check does not prove confirmer authority or scope coverage; the evaluator must
// require those separately. Version freshness is carried by the rule-set change
// confirmation.
pub fn binding_confirmation_valid(
    confirmation: &BindingConfirmationRow,
    binding_id: [u8; 16],
    rule_set_id: [u8; 16],
) -> bool {
    confirmation.binding_id == binding_id
        && confirmation.rule_set_id == rule_set_id
        && confirmation.confirmer_user_id != [0; 16]
        && !confirmation.scope_bytes.is_empty()
        && !confirmation.operation_id.is_empty()
        && !confirmation.confirmed_at_bytes.is_empty()
}

/// memory—v1 §4.11/§4.12: The state of a binding's whole confirmation set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingConfirmationState {
    /// Exactly one valid confirmation is active and no active row is invalid.
    Active,
    /// Every structurally valid confirmation has been revoked.
    Withdrawn,
    /// No valid confirmation exists, an active row is invalid, or multiple are active.
    Invalid,
}

/// memory—v1 §4.11/§4.12: Classify an unordered set without allowing a valid
/// confirmation to conceal an invalid active row or another active confirmation.
/// Revoked historical rows do not grant authority; an incomplete tombstone is
/// always invalid.
pub fn classify_binding_confirmations<'a>(
    confirmations: impl IntoIterator<Item = &'a BindingConfirmationRow>,
    binding_id: [u8; 16],
    rule_set_id: [u8; 16],
) -> BindingConfirmationState {
    let mut valid = false;
    let mut active = false;
    for confirmation in confirmations {
        if confirmation.revoked_at.is_some() != confirmation.revoked_by.is_some() {
            return BindingConfirmationState::Invalid;
        }
        let structurally_valid = binding_confirmation_valid(confirmation, binding_id, rule_set_id);
        if confirmation.revoked_at.is_none() {
            if !structurally_valid || active {
                return BindingConfirmationState::Invalid;
            }
            active = true;
        }
        valid |= structurally_valid;
    }
    if active {
        BindingConfirmationState::Active
    } else if valid {
        BindingConfirmationState::Withdrawn
    } else {
        BindingConfirmationState::Invalid
    }
}

/// memory—v1 §4.11/§4.12/§4.13: The state of change confirmations for the
/// explicitly selected current version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeConfirmationState {
    /// At least one structurally valid, non-revoked confirmation covers the
    /// current version, and no non-revoked current-version row is invalid.
    Active,
    /// Current-version confirmation rows exist, but every one is a complete
    /// revocation tombstone. A revoked confirmation never proves freshness.
    Withdrawn,
    /// No confirmation row covers the current version. Historical rows do not
    /// satisfy the current-version freshness invariant.
    Missing,
    /// A current-version active row is malformed, a row belongs to another
    /// rule set, or a tombstone has only one half present.
    Invalid,
}

/// memory—v1 §4.11/§4.12/§4.13: Classify change confirmations against the
/// explicit current-version pointer.
///
/// Multiple valid active confirmations for one version are permitted as
/// traceability records. The classifier is deliberately not an `any(valid)`
/// reduction: a malformed active row for the same current version makes the
/// whole current-version evidence invalid, even when another row is valid.
/// Complete revoked rows are historical tombstones and never grant freshness;
/// rows for an older version are ignored for current-version qualification.
/// A half tombstone is structural corruption regardless of version.
pub fn classify_change_confirmations<'a>(
    confirmations: impl IntoIterator<Item = &'a RuleSetChangeConfirmationRow>,
    rule_set_id: [u8; 16],
    version: &[u8],
) -> ChangeConfirmationState {
    if version.is_empty() {
        return ChangeConfirmationState::Invalid;
    }
    let mut current_seen = false;
    let mut current_active = false;

    for confirmation in confirmations {
        if confirmation.revoked_at.is_some() != confirmation.revoked_by.is_some() {
            return ChangeConfirmationState::Invalid;
        }
        if confirmation.rule_set_id != rule_set_id {
            return ChangeConfirmationState::Invalid;
        }
        if confirmation.version_bytes != version {
            continue;
        }
        current_seen = true;
        if confirmation.revoked_at.is_some() {
            continue;
        }
        if !change_confirmation_valid(confirmation, rule_set_id, version) {
            return ChangeConfirmationState::Invalid;
        }
        current_active = true;
    }

    if current_active {
        ChangeConfirmationState::Active
    } else if current_seen {
        ChangeConfirmationState::Withdrawn
    } else {
        ChangeConfirmationState::Missing
    }
}

/// Legacy structural comparison for callers that record the binding-time version.
///
/// This is not an authorization decision: the current version still requires a
/// separate active change confirmation, and revoked confirmations must not grant
/// access. New authorization code uses [`binding_confirmation_valid`] together
/// with [`change_confirmation_valid`].
pub fn confirmation_matches(
    confirmation: &BindingConfirmationRow,
    binding_id: [u8; 16],
    rule_set_id: [u8; 16],
    version: &[u8],
) -> bool {
    binding_confirmation_valid(confirmation, binding_id, rule_set_id)
        && confirmation.version_bytes == version
}

// memory—v1 §4.11/§4.5 (N-16/B-3.8): the CURRENT version is servable only with
// a non-revoked change confirmation for exactly that version (版本新鲜度不变式:
// 首版与每次发布同事务确认).
pub fn change_confirmation_valid(
    confirmation: &RuleSetChangeConfirmationRow,
    rule_set_id: [u8; 16],
    version: &[u8],
) -> bool {
    confirmation.rule_set_id == rule_set_id
        && confirmation.version_bytes == version
        && confirmation.confirmer_user_id != [0; 16]
        && !confirmation.affected_scope_bytes.is_empty()
        && !confirmation.operation_id.is_empty()
        && !confirmation.confirmed_at_bytes.is_empty()
}

pub fn evaluate_binding(
    layer: BindingLayer,
    content: &MemoryV1RuleSetContent,
    confirmed: bool,
    resource: &str,
    action: &str,
) -> MemoryV1BindingMatch {
    if !confirmed {
        return MemoryV1BindingMatch::Incomplete;
    }
    match (layer, content.evaluate(resource, action)) {
        (_, MemoryV1RuleMatch::None) => MemoryV1BindingMatch::None,
        (BindingLayer::Base, MemoryV1RuleMatch::Allow)
        | (BindingLayer::Overlay, MemoryV1RuleMatch::Allow) => MemoryV1BindingMatch::Allow,
        (_, MemoryV1RuleMatch::Deny) => MemoryV1BindingMatch::Deny,
    }
}

pub fn canonical_version_bytes(version: &[u8], content: &[u8], timestamp: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        HASH_DOMAIN.len() + version.len() + content.len() + timestamp.len() + 24,
    );
    bytes.extend_from_slice(HASH_DOMAIN);
    for field in [version, content, timestamp] {
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    bytes
}

/// memory—v1 §4.4: the version digest over the canonical encoding — the exact
/// computation a conforming writer performs when registering a version.
pub fn version_digest(canonical_input: &[u8]) -> Vec<u8> {
    Sha256::digest(canonical_input).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(content: &[u8]) -> RuleSetVersionRow {
        let version = vec![1];
        let timestamp = vec![2];
        let input = canonical_version_bytes(&version, content, &timestamp);
        RuleSetVersionRow {
            rule_set_id: [3; 16],
            version_bytes: version,
            content_bytes: content.to_vec(),
            timestamp_bytes: timestamp,
            hash_input_bytes: input.clone(),
            hash_bytes: Sha256::digest(input).to_vec(),
        }
    }

    #[test]
    fn legacy_confirmation_comparison_preserves_version_matching() {
        let confirmation = BindingConfirmationRow {
            confirmation_id: [1; 16],
            binding_id: [2; 16],
            rule_set_id: [3; 16],
            version_bytes: b"v1".to_vec(),
            confirmer_user_id: [4; 16],
            scope_bytes: b"scope".to_vec(),
            operation_id: b"operation".to_vec(),
            confirmed_at_bytes: b"time".to_vec(),
            revoked_at: None,
            revoked_by: None,
        };
        assert!(confirmation_matches(&confirmation, [2; 16], [3; 16], b"v1"));
        assert!(!confirmation_matches(
            &confirmation,
            [2; 16],
            [3; 16],
            b"v2"
        ));
        assert!(!confirmation_matches(
            &confirmation,
            [5; 16],
            [3; 16],
            b"v1"
        ));
        assert!(binding_confirmation_valid(&confirmation, [2; 16], [3; 16]));
    }

    #[test]
    // memory—v1 §4.11/§4.12: Set classification is unordered and cannot
    // confuse corrupt active rows, missing evidence, and historical withdrawals.
    fn binding_confirmation_set_classification() {
        let valid = BindingConfirmationRow {
            confirmation_id: [1; 16],
            binding_id: [2; 16],
            rule_set_id: [3; 16],
            version_bytes: b"v1".to_vec(),
            confirmer_user_id: [4; 16],
            scope_bytes: b"scope".to_vec(),
            operation_id: b"operation".to_vec(),
            confirmed_at_bytes: b"time".to_vec(),
            revoked_at: None,
            revoked_by: None,
        };
        let mut second_active = valid.clone();
        second_active.confirmation_id = [5; 16];
        let mut revoked = valid.clone();
        revoked.revoked_at = Some(100);
        revoked.revoked_by = Some([4; 16]);
        let mut invalid = valid.clone();
        invalid.scope_bytes.clear();
        let mut invalid_revoked = revoked.clone();
        invalid_revoked.scope_bytes.clear();
        let mut incomplete_tombstone = valid.clone();
        incomplete_tombstone.revoked_at = Some(100);

        for (rows, expected) in [
            (vec![], BindingConfirmationState::Invalid),
            (vec![&invalid], BindingConfirmationState::Invalid),
            (vec![&invalid_revoked], BindingConfirmationState::Invalid),
            (vec![&valid], BindingConfirmationState::Active),
            (vec![&revoked], BindingConfirmationState::Withdrawn),
            (
                vec![&revoked, &invalid_revoked],
                BindingConfirmationState::Withdrawn,
            ),
            (vec![&revoked, &valid], BindingConfirmationState::Active),
            (
                vec![&valid, &second_active],
                BindingConfirmationState::Invalid,
            ),
            (
                vec![&revoked, &valid, &second_active],
                BindingConfirmationState::Invalid,
            ),
            (vec![&valid, &invalid], BindingConfirmationState::Invalid),
            (vec![&revoked, &invalid], BindingConfirmationState::Invalid),
            (
                vec![&valid, &incomplete_tombstone],
                BindingConfirmationState::Invalid,
            ),
        ] {
            assert_eq!(
                classify_binding_confirmations(rows.iter().copied(), [2; 16], [3; 16]),
                expected
            );
            assert_eq!(
                classify_binding_confirmations(rows.iter().rev().copied(), [2; 16], [3; 16]),
                expected
            );
        }
    }

    #[test]
    // memory—v1 §4.11–§4.13: current-version change evidence must classify
    // the whole set; a valid row cannot conceal corrupt active evidence.
    fn change_confirmation_set_classification_distinguishes_current_and_history() {
        let valid = RuleSetChangeConfirmationRow {
            confirmation_id: [1; 16],
            rule_set_id: [3; 16],
            version_bytes: b"v2".to_vec(),
            confirmer_user_id: [4; 16],
            affected_scope_bytes: b"scope".to_vec(),
            operation_id: b"operation".to_vec(),
            confirmed_at_bytes: b"time".to_vec(),
            revoked_at: None,
            revoked_by: None,
        };
        let mut second_valid = valid.clone();
        second_valid.confirmation_id = [2; 16];
        let mut historical = valid.clone();
        historical.confirmation_id = [3; 16];
        historical.version_bytes = b"v1".to_vec();
        let mut revoked = valid.clone();
        revoked.confirmation_id = [4; 16];
        revoked.revoked_at = Some(100);
        revoked.revoked_by = Some([5; 16]);
        let mut malformed = valid.clone();
        malformed.confirmation_id = [5; 16];
        malformed.affected_scope_bytes.clear();
        let mut half_tombstone = valid.clone();
        half_tombstone.confirmation_id = [6; 16];
        half_tombstone.revoked_at = Some(100);

        let classify = |rows: &[RuleSetChangeConfirmationRow]| {
            classify_change_confirmations(rows.iter(), [3; 16], b"v2")
        };
        assert_eq!(classify(&[]), ChangeConfirmationState::Missing);
        assert_eq!(
            classify(&[historical.clone()]),
            ChangeConfirmationState::Missing
        );
        assert_eq!(
            classify(&[revoked.clone()]),
            ChangeConfirmationState::Withdrawn
        );
        assert_eq!(
            classify(std::slice::from_ref(&valid)),
            ChangeConfirmationState::Active
        );
        assert_eq!(
            classify(&[valid.clone(), second_valid.clone()]),
            ChangeConfirmationState::Active
        );
        assert_eq!(
            classify(&[valid.clone(), malformed.clone()]),
            ChangeConfirmationState::Invalid
        );
        assert_eq!(
            classify(&[revoked.clone(), valid.clone()]),
            ChangeConfirmationState::Active
        );
        assert_eq!(
            classify(&[valid.clone(), half_tombstone.clone()]),
            ChangeConfirmationState::Invalid
        );

        let mut wrong_set = historical.clone();
        wrong_set.rule_set_id = [9; 16];
        assert_eq!(classify(&[wrong_set]), ChangeConfirmationState::Invalid);

        assert_eq!(
            classify_change_confirmations([&valid], [3; 16], b""),
            ChangeConfirmationState::Invalid
        );

        // Classification is independent of candidate row order.
        let reversed = [second_valid.clone(), malformed.clone()];
        assert_eq!(classify(&reversed), ChangeConfirmationState::Invalid);
        assert_eq!(
            classify_change_confirmations(reversed.iter().rev(), [3; 16], b"v2"),
            ChangeConfirmationState::Invalid
        );
    }

    #[test]
    fn validates_hash_and_overlay_deny() {
        let allow = br#"{"rules":[{"ruleId":"R1","resource":"platform_tenant","action":"create","effect":"ALLOW"}]}"#;
        let parsed = MemoryV1RuleSetContent::parse(allow).unwrap();
        assert_eq!(
            parsed.evaluate("platform_tenant", "create"),
            MemoryV1RuleMatch::Allow
        );
        assert!(parse_version(&version(allow)).is_ok());
    }

    // memory—v1 §4.4: absent validity is open; absent scope is strictest.
    #[test]
    fn absent_validity_and_scope_default_strict() {
        let content = MemoryV1RuleSetContent::parse(
            br#"{"rules":[{"ruleId":"R1","resource":"r","action":"read","effect":"ALLOW"}]}"#,
        )
        .unwrap();
        let hits = content.rule_hits("r", "read");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_id, "R1");
        assert_eq!(hits[0].validity, None);
        assert_eq!(hits[0].owner_scope, MemoryV1OwnerScope::SelfUser);
        assert_eq!(hits[0].tenant_scope, MemoryV1TenantScope::SelfTenant);
        assert!(hits[0].validity.is_none_or(|v| v.active_at(0)));
        assert!(hits[0].validity.is_none_or(|v| v.active_at(i64::MAX)));
    }

    // memory—v1 §4.4: window boundaries are from-inclusive and until-exclusive.
    #[test]
    fn window_boundaries_are_from_inclusive_until_exclusive() {
        let content = MemoryV1RuleSetContent::parse(
            br#"{"rules":[{"ruleId":"R1","resource":"r","action":"read","effect":"ALLOW","validity":{"from":10,"until":20}}]}"#,
        )
        .unwrap();
        let hits = content.rule_hits("r", "read");
        let validity = hits[0].validity.unwrap();
        assert!(!validity.active_at(9));
        assert!(validity.active_at(10));
        assert!(validity.active_at(19));
        assert!(!validity.active_at(20));
    }

    // memory—v1 §4.4: an inverted window fails content parsing.
    #[test]
    fn inverted_window_fails_parsing() {
        let content =
            br#"{"rules":[{"ruleId":"R1","resource":"r","action":"read","effect":"ALLOW","validity":{"from":20,"until":10}}]}"#;
        assert_eq!(
            MemoryV1RuleSetContent::parse(content),
            Err(MemoryV1RuleError::InvalidValidity)
        );
    }

    // memory—v1 §4.4: rule identifiers are required and unique within a version.
    #[test]
    fn rule_ids_are_required_and_unique() {
        let missing = br#"{"rules":[{"resource":"r","action":"read","effect":"ALLOW"}]}"#;
        assert!(matches!(
            MemoryV1RuleSetContent::parse(missing),
            Err(MemoryV1RuleError::InvalidContent(_))
        ));
        let duplicate =
            br#"{"rules":[{"ruleId":"R1","resource":"r","action":"read","effect":"ALLOW"},{"ruleId":"R1","resource":"r","action":"write","effect":"DENY"}]}"#;
        assert_eq!(
            MemoryV1RuleSetContent::parse(duplicate),
            Err(MemoryV1RuleError::DuplicateRuleId)
        );
        let too_long = format!(
            r#"{{"rules":[{{"ruleId":"{}","resource":"r","action":"read","effect":"ALLOW"}}]}}"#,
            "R".repeat(MAX_RULE_ID_BYTES + 1)
        );
        assert_eq!(
            MemoryV1RuleSetContent::parse(too_long.as_bytes()),
            Err(MemoryV1RuleError::InvalidRule)
        );
    }

    // memory—v1 §4.10: declared scopes survive parsing and reach the hits.
    #[test]
    fn declared_scopes_reach_hits() {
        let content = MemoryV1RuleSetContent::parse(
            br#"{"rules":[{"ruleId":"R1","resource":"r","action":"read","effect":"ALLOW","ownerScope":"all","tenantScope":"self+descendants"}]}"#,
        )
        .unwrap();
        let hits = content.rule_hits("r", "read");
        assert_eq!(hits[0].owner_scope, MemoryV1OwnerScope::AllUsers);
        assert_eq!(
            hits[0].tenant_scope,
            MemoryV1TenantScope::SelfAndDescendants
        );
    }

    // memory—v1 §4.10: unknown scope values are rejected, never widened.
    #[test]
    fn unknown_scope_values_fail_parsing() {
        let content =
            br#"{"rules":[{"ruleId":"R1","resource":"r","action":"read","effect":"ALLOW","ownerScope":"everyone"}]}"#;
        assert!(MemoryV1RuleSetContent::parse(content).is_err());
    }

    // memory—v1 §4.4: hits stay exhaustive and order-faithful for the engine.
    #[test]
    fn hits_list_every_type_level_match() {
        let content = MemoryV1RuleSetContent::parse(
            br#"{"rules":[
                {"ruleId":"A","resource":"r","action":"read","effect":"ALLOW"},
                {"ruleId":"B","resource":"r","action":"read","effect":"DENY"},
                {"ruleId":"C","resource":"r","action":"write","effect":"ALLOW"}
            ]}"#,
        )
        .unwrap();
        let hits = content.rule_hits("r", "read");
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].rule_id, "A");
        assert_eq!(hits[1].rule_id, "B");
    }
}
