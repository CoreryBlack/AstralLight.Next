//! ORG source-outcome capture: same-transaction binding of an admitted org
//! mutation to its actual durable facts, receipts, and provable coverage.
//!
//! Contract (V7 authority, Rust 规范 §15.9.3):
//! - Called inside the mutation's source transaction, AFTER the proof-bound
//!   admission was durably consumed (the staging API re-verifies the
//!   `authorization_admission_use` row) and BEFORE commit. No network I/O.
//! - Facts are re-read from the append-only `org_scope_revision` ledger by
//!   `operation_id` (idx_osv_operation) — the complete, exact record of what
//!   this transaction wrote; receipts are the real durable row identities
//!   (`revision_row_id`, `org_event_id`), never invented ids.
//! - Before/after image digests are computed over the exact stored ledger
//!   payload digests (predecessor revision row = before; own row = after) with
//!   domain separation. No actor authorization snapshot is ever involved.
//! - Coverage is declared ONLY from a completeness proof captured in this same
//!   transaction; otherwise it stays `None` (unknown GLOBAL, operator-owned).
//!   Proofs (all under existing indexes, no new schema):
//!   - single membership fact + node head untouched by this operation → the
//!     one member-exact ORG scope (create AND revoke: the revoke scope still
//!     certifies through a revocation-frontier certificate, never None);
//!   - unit-content facts (GRANT/MASK) + the unit node row lock held to commit
//!     (`last_operation_id == operation_id`) + no direct child units
//!     (idx_osn_parent) + the bounded active member read (idx_osmem_unit,
//!     cap+1) → EXACT over that member set; empty/overflow/mixed/tree fanout
//!     → None. Unknown never guesses.

use astral_types::org_scope::OrgMembership;
use astral_types::{
    AuthorityMutationKind, AuthorityOrgMemberSubject, AuthorityOrgScope, AuthorityProtocolScope,
    AuthorityStagedScopeCoverage, AuthorizationAdmission,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{MySql, Row, Transaction};

use super::*;

/// Version marker of the owner's staged evidence payload (envelope.evidence).
pub(crate) const ORG_SOURCE_EVIDENCE_MARKER: &str = "orgSourceEvidenceV1";

/// Batch bounds. A direct org mutation writes a handful of facts; anything
/// beyond these caps is a contract violation and fails closed instead of
/// being truncated or guessed.
pub(crate) const MAX_ORG_CAPTURE_FACTS: usize = 64;
pub(crate) const MAX_ORG_CAPTURE_OUTBOX: usize = 256;
/// Staged coverage hard cap (type contract: 1..=256 scopes).
pub(crate) const ORG_COVERAGE_MAX_SCOPES: usize = 256;

pub(crate) const ORG_SOURCE_BEFORE_IMAGE_DOMAIN: &[u8] = b"ASTRAL_ORG_SOURCE_BEFORE_V7\0";
pub(crate) const ORG_SOURCE_AFTER_IMAGE_DOMAIN: &[u8] = b"ASTRAL_ORG_SOURCE_AFTER_V7\0";
const COMMIT_DOMAIN: &[u8] = b"ASTRAL_ORG_SOURCE_COMMIT_V7\0";

const CAPTURE_FACT_SELECT_SQL: &str = "SELECT revision_row_id, subject_kind, tenant_id, \
     subject_id, revision, payload_json, payload_digest FROM org_scope_revision \
     WHERE operation_id = ? ORDER BY revision_row_id LIMIT ?";
const CAPTURE_PREDECESSOR_DIGEST_SQL: &str = "SELECT payload_digest FROM org_scope_revision \
     WHERE subject_kind = ? AND subject_id = ? AND revision = ?";
const CAPTURE_OUTBOX_SELECT_SQL: &str = "SELECT org_event_id, event_id, event_kind, tenant_id \
     FROM org_scope_outbox WHERE operation_id = ? ORDER BY org_event_id LIMIT ?";
const CAPTURE_AUDIT_SELECT_SQL: &str =
    "SELECT audit_id, tenant_id, action, subject_kind, subject_id, request_id \
     FROM org_scope_audit WHERE operation_id = ? ORDER BY audit_id LIMIT ?";
const NODE_LAST_OPERATION_SQL: &str = "SELECT last_operation_id FROM org_scope_node \
     WHERE tenant_id = ?";
const DIRECT_CHILD_PROBE_SQL: &str = "SELECT 1 FROM org_scope_node \
     WHERE parent_tenant_id = ? LIMIT 1";
const UNIT_ACTIVE_MEMBER_SQL: &str = "SELECT tenant_id, root_tenant_id, user_id, \
     identity_card_id, card_id FROM org_scope_membership \
     WHERE tenant_id = ? AND active = 1 LIMIT ?";

/// One captured ledger fact. `payload_json` is transient capture context (the
/// exact bytes the fact was written with); the evidence envelope keeps only
/// digests so the staged payload stays bounded.
#[derive(Debug, Clone)]
pub(crate) struct CapturedOrgFact {
    pub fact: OrgSourceFactEvidence,
    pub payload_json: String,
}

/// One durable fact transition bound into the staged evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OrgSourceFactEvidence {
    pub subject_kind: String,
    pub tenant_id: i64,
    pub subject_id: String,
    pub revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_digest_hex: Option<String>,
    pub after_digest_hex: String,
    pub revision_row_id: i64,
}

/// One durable outbox receipt identity produced by the same transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OrgSourceOutboxReceiptEvidence {
    pub org_event_id: i64,
    pub event_id: String,
    pub event_kind: String,
    pub tenant_id: i64,
}

/// Existing same-transaction org audit row. Capture stores its actual durable
/// primary key and source correlation; it never emits a replacement event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OrgSourceAuditReceiptEvidence {
    pub audit_id: i64,
    pub tenant_id: i64,
    pub action: String,
    pub subject_kind: String,
    pub subject_id: String,
    pub request_id: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OrgMembershipCreateReceiptEvidence {
    pub tenant_id: i64,
    pub root_tenant_id: i64,
    pub user_id: i64,
    pub identity_card_id: i64,
    pub card_id: i64,
    pub membership_id: String,
    pub operation_id: String,
    pub before_absent: bool,
    pub insert_rows_affected: u64,
    pub audit: OrgSourceAuditReceiptEvidence,
}

impl OrgMembershipCreateReceiptEvidence {
    pub(crate) fn validate(&self) -> Result<(), AstralError> {
        validated_operation_id(&self.operation_id)?;
        positive_i64(self.tenant_id, "tenant_id")?;
        positive_i64(self.root_tenant_id, "root_tenant_id")?;
        positive_i64(self.user_id, "user_id")?;
        positive_i64(self.identity_card_id, "identity_card_id")?;
        positive_i64(self.card_id, "card_id")?;
        if self.insert_rows_affected != 1
            || uuid::Uuid::parse_str(&self.membership_id).is_err()
            || self.audit.audit_id <= 0
            || self.audit.tenant_id != self.tenant_id
            || self.audit.action != "MEMBERSHIP_CREATE"
            || self.audit.subject_kind != "MEMBERSHIP"
            || self.audit.subject_id != self.membership_id
        {
            return Err(AstralError::Validation(
                "code=org_scope.membership_create_receipt_invalid".into(),
            ));
        }
        Ok(())
    }
}

/// The owner's typed staged evidence (envelope.evidence payload, V1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OrgSourceOutcomeEvidenceV1 {
    pub marker: String,
    pub operation_id: String,
    pub facts: Vec<OrgSourceFactEvidence>,
    pub outbox: Vec<OrgSourceOutboxReceiptEvidence>,
    pub audits: Vec<OrgSourceAuditReceiptEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_create_receipt: Option<OrgMembershipCreateReceiptEvidence>,
    pub before_digest_hex: String,
    pub after_digest_hex: String,
    pub commit_digest_hex: String,
}

impl OrgSourceOutcomeEvidenceV1 {
    pub(crate) fn validate(&self) -> Result<(), AstralError> {
        if self.marker != ORG_SOURCE_EVIDENCE_MARKER {
            return Err(AstralError::Validation(format!(
                "code=org_scope.capture_marker_mismatch;marker={}",
                self.marker
            )));
        }
        validated_operation_id(&self.operation_id)?;
        if self.facts.is_empty() || self.facts.len() > MAX_ORG_CAPTURE_FACTS {
            return Err(AstralError::Validation(format!(
                "code=org_scope.capture_fact_capacity;facts={}",
                self.facts.len()
            )));
        }
        if self.outbox.is_empty() || self.outbox.len() > MAX_ORG_CAPTURE_OUTBOX {
            return Err(AstralError::Validation(format!(
                "code=org_scope.capture_outbox_capacity;outbox={}",
                self.outbox.len()
            )));
        }
        if self.audits.is_empty() || self.audits.len() > MAX_ORG_CAPTURE_FACTS {
            return Err(AstralError::Validation(
                "code=org_scope.capture_audit_capacity".into(),
            ));
        }
        let mut audit_ids = std::collections::BTreeSet::new();
        for audit in &self.audits {
            if audit.audit_id <= 0
                || audit.tenant_id <= 0
                || audit.action.is_empty()
                || audit.subject_kind.is_empty()
                || audit.subject_id.is_empty()
                || !audit_ids.insert(audit.audit_id)
            {
                return Err(AstralError::Validation(
                    "code=org_scope.capture_audit_invalid".into(),
                ));
            }
        }
        if let Some(receipt) = &self.membership_create_receipt {
            receipt.validate()?;
            if !self.audits.iter().any(|audit| audit == &receipt.audit) {
                return Err(AstralError::Validation(
                    "code=org_scope.membership_create_audit_mismatch".into(),
                ));
            }
            if receipt.operation_id != self.operation_id
                || self.facts.len() != 1
                || self.outbox.len() != 1
                || self.facts[0].subject_kind != "MEMBERSHIP"
                || self.facts[0].tenant_id != receipt.tenant_id
                || self.facts[0].subject_id != receipt.membership_id
                || self.facts[0].revision != 1
                || self.facts[0].before_digest_hex.is_some()
                || self.outbox[0].tenant_id != receipt.tenant_id
                || self.outbox[0].event_kind != ORG_EVENT_MEMBERSHIP_CHANGED
            {
                return Err(AstralError::Validation(
                    "code=org_scope.membership_create_evidence_mismatch".into(),
                ));
            }
        }
        for digest in self
            .facts
            .iter()
            .flat_map(|fact| [&fact.after_digest_hex])
            .chain(
                self.facts
                    .iter()
                    .filter_map(|fact| fact.before_digest_hex.as_ref()),
            )
            .chain([
                &self.before_digest_hex,
                &self.after_digest_hex,
                &self.commit_digest_hex,
            ])
        {
            if hex::decode(digest)
                .map(|bytes| bytes.len() != 32)
                .unwrap_or(true)
            {
                return Err(AstralError::Validation(
                    "code=org_scope.capture_digest_invalid".into(),
                ));
            }
        }
        Ok(())
    }

    /// Canonical bounded JSON for the staged envelope (≤256 KiB envelope cap).
    pub(crate) fn evidence_json(&self) -> Result<String, AstralError> {
        let json = serde_json::to_string(self).map_err(|error| {
            AstralError::Internal(format!("org_scope capture evidence serialize: {error}"))
        })?;
        if json.len() > 256 * 1024 {
            return Err(AstralError::Validation(
                "code=org_scope.capture_evidence_capacity".into(),
            ));
        }
        Ok(json)
    }

    /// The real durable receipt identities committed with this outcome.
    pub(crate) fn receipt_identities(
        &self,
    ) -> Vec<crate::authority_source_outcome::AuthoritySourceReceiptIdentity> {
        let mut receipts: Vec<_> = self
            .facts
            .iter()
            .map(
                |fact| crate::authority_source_outcome::AuthoritySourceReceiptIdentity {
                    identity_kind: "org_scope_revision_row".into(),
                    identity: fact.revision_row_id.to_string(),
                },
            )
            .chain(self.outbox.iter().map(|receipt| {
                crate::authority_source_outcome::AuthoritySourceReceiptIdentity {
                    identity_kind: "org_scope_outbox_event".into(),
                    identity: receipt.org_event_id.to_string(),
                }
            }))
            .chain(self.audits.iter().map(|receipt| {
                crate::authority_source_outcome::AuthoritySourceReceiptIdentity {
                    identity_kind: "org_scope_audit_row".into(),
                    identity: receipt.audit_id.to_string(),
                }
            }))
            .collect();
        receipts.sort_by(|left, right| {
            left.identity_kind
                .cmp(&right.identity_kind)
                .then(left.identity.cmp(&right.identity))
        });
        receipts
    }

    /// Whether every fact is a membership fact (member-scoped mutation).
    pub(crate) fn all_membership_facts(&self) -> bool {
        self.facts
            .iter()
            .all(|fact| fact.subject_kind == "MEMBERSHIP")
    }

    /// Whether any fact is a membership fact (mixed batches are fail-closed).
    pub(crate) fn any_membership_fact(&self) -> bool {
        self.facts
            .iter()
            .any(|fact| fact.subject_kind == "MEMBERSHIP")
    }

    /// Whether every fact belongs to unit content (GRANT/MASK subjects only).
    pub(crate) fn all_unit_content_facts(&self) -> bool {
        !self.facts.is_empty()
            && self
                .facts
                .iter()
                .all(|fact| matches!(fact.subject_kind.as_str(), "GRANT" | "MASK"))
    }
}

fn digest_field(hash: &mut Sha256, value: &str) {
    hash.update((value.len() as u32).to_be_bytes());
    hash.update(value.as_bytes());
}

/// Before/after batch image digest over the exact stored ledger digests.
/// An absent before-state (first revision of a subject) contributes the `[0]`
/// marker, so the batch digest is always defined without inventing content.
pub(crate) fn org_source_image_digest(
    domain: &[u8],
    facts: &[OrgSourceFactEvidence],
    before: bool,
) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update((facts.len() as u64).to_be_bytes());
    for fact in facts {
        hash.update(fact.tenant_id.to_be_bytes());
        digest_field(&mut hash, &fact.subject_kind);
        digest_field(&mut hash, &fact.subject_id);
        hash.update(fact.revision.to_be_bytes());
        let digest = if before {
            fact.before_digest_hex.as_deref()
        } else {
            Some(fact.after_digest_hex.as_str())
        };
        match digest {
            None => hash.update([0]),
            Some(value) => {
                hash.update([1]);
                hash.update(value.as_bytes());
            }
        }
        hash.update(fact.revision_row_id.to_be_bytes());
    }
    hex::encode(hash.finalize())
}

/// Commit digest over the complete captured document (facts + receipts +
/// audits + optional first-insert proof + both image digests), length-prefixed
/// to avoid ambiguity.
pub(crate) fn org_source_commit_digest(
    facts: &[OrgSourceFactEvidence],
    outbox: &[OrgSourceOutboxReceiptEvidence],
    audits: &[OrgSourceAuditReceiptEvidence],
    membership_create_receipt: Option<&OrgMembershipCreateReceiptEvidence>,
    before_digest_hex: &str,
    after_digest_hex: &str,
) -> Result<String, AstralError> {
    let document = serde_json::to_vec(&(
        facts,
        outbox,
        audits,
        membership_create_receipt,
        before_digest_hex,
        after_digest_hex,
    ))
    .map_err(|error| {
        AstralError::Internal(format!("org_scope capture commit document: {error}"))
    })?;
    let mut hash = Sha256::new();
    hash.update(COMMIT_DOMAIN);
    hash.update((document.len() as u64).to_be_bytes());
    hash.update(&document);
    Ok(hex::encode(hash.finalize()))
}

/// Re-read the complete fact batch written by this operation from the
/// append-only ledger (idx_osv_operation) with each fact's predecessor digest.
async fn capture_facts_in_tx(
    tx: &mut Transaction<'static, MySql>,
    operation_id: &str,
) -> Result<Vec<CapturedOrgFact>, AstralError> {
    let rows = sqlx::query(CAPTURE_FACT_SELECT_SQL)
        .bind(operation_id)
        .bind(MAX_ORG_CAPTURE_FACTS as i64 + 1)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_err)?;
    if rows.is_empty() {
        return Err(AstralError::Validation(
            "code=org_scope.capture_facts_missing".into(),
        ));
    }
    if rows.len() > MAX_ORG_CAPTURE_FACTS {
        return Err(AstralError::Validation(
            "code=org_scope.capture_fact_capacity".into(),
        ));
    }
    let mut facts = Vec::with_capacity(rows.len());
    for row in &rows {
        let subject_kind: String = row.try_get("subject_kind").map_err(db_err)?;
        let tenant_id: i64 = row.try_get("tenant_id").map_err(db_err)?;
        let subject_id: String = row.try_get("subject_id").map_err(db_err)?;
        let revision = row_generation(
            row.try_get::<i64, _>("revision").map_err(db_err)?,
            "capture.revision",
        )?;
        let payload_json: String = row.try_get("payload_json").map_err(db_err)?;
        let after_digest: Vec<u8> = row.try_get("payload_digest").map_err(db_err)?;
        let before_digest = if revision == 1 {
            None
        } else {
            let predecessor: Option<Vec<u8>> = sqlx::query(CAPTURE_PREDECESSOR_DIGEST_SQL)
                .bind(&subject_kind)
                .bind(&subject_id)
                .bind(gen_to_i64(revision - 1, "capture.predecessor_revision")?)
                .fetch_optional(&mut **tx)
                .await
                .map_err(db_err)?
                .map(|row| row.try_get(0).map_err(db_err))
                .transpose()?;
            // A missing predecessor row behind a non-first revision is a
            // broken ledger: fail closed instead of capturing a gap.
            Some(predecessor.ok_or_else(|| {
                AstralError::Database("code=org_scope.capture_predecessor_missing".into())
            })?)
        };
        facts.push(CapturedOrgFact {
            fact: OrgSourceFactEvidence {
                subject_kind,
                tenant_id,
                subject_id,
                revision,
                before_digest_hex: before_digest.map(hex::encode),
                after_digest_hex: hex::encode(after_digest),
                revision_row_id: row.try_get("revision_row_id").map_err(db_err)?,
            },
            payload_json,
        });
    }
    Ok(facts)
}

/// Re-read the complete audit row set written by this operation and require it
/// to be the expected existing source audit (no duplicate event is created).
async fn capture_audits_in_tx(
    tx: &mut Transaction<'static, MySql>,
    operation_id: &str,
) -> Result<Vec<OrgSourceAuditReceiptEvidence>, AstralError> {
    let rows = sqlx::query(CAPTURE_AUDIT_SELECT_SQL)
        .bind(operation_id)
        .bind(MAX_ORG_CAPTURE_FACTS as i64 + 1)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_err)?;
    if rows.is_empty() || rows.len() > MAX_ORG_CAPTURE_FACTS {
        return Err(AstralError::Validation(
            "code=org_scope.capture_audit_capacity".into(),
        ));
    }
    rows.iter()
        .map(|row| {
            Ok(OrgSourceAuditReceiptEvidence {
                audit_id: row.try_get("audit_id").map_err(db_err)?,
                tenant_id: row.try_get("tenant_id").map_err(db_err)?,
                action: row.try_get("action").map_err(db_err)?,
                subject_kind: row.try_get("subject_kind").map_err(db_err)?,
                subject_id: row.try_get("subject_id").map_err(db_err)?,
                request_id: row.try_get("request_id").map_err(db_err)?,
            })
        })
        .collect()
}

/// Re-read the complete outbox receipt set written by this operation.
async fn capture_outbox_in_tx(
    tx: &mut Transaction<'static, MySql>,
    operation_id: &str,
) -> Result<Vec<OrgSourceOutboxReceiptEvidence>, AstralError> {
    let rows = sqlx::query(CAPTURE_OUTBOX_SELECT_SQL)
        .bind(operation_id)
        .bind(MAX_ORG_CAPTURE_OUTBOX as i64 + 1)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_err)?;
    if rows.is_empty() {
        return Err(AstralError::Validation(
            "code=org_scope.capture_outbox_missing".into(),
        ));
    }
    if rows.len() > MAX_ORG_CAPTURE_OUTBOX {
        return Err(AstralError::Validation(
            "code=org_scope.capture_outbox_capacity".into(),
        ));
    }
    rows.iter()
        .map(|row| {
            Ok(OrgSourceOutboxReceiptEvidence {
                org_event_id: row.try_get("org_event_id").map_err(db_err)?,
                event_id: row.try_get("event_id").map_err(db_err)?,
                event_kind: row.try_get("event_kind").map_err(db_err)?,
                tenant_id: row.try_get("tenant_id").map_err(db_err)?,
            })
        })
        .collect()
}

/// Member-exact ORG scope built from a typed membership fact.
fn member_scope(membership: &OrgMembership) -> Result<AuthorityProtocolScope, AstralError> {
    let scope = AuthorityProtocolScope::Org(AuthorityOrgScope {
        tenant_id: membership.tenant_id,
        root_tenant_id: Some(membership.root_tenant_id),
        member: AuthorityOrgMemberSubject {
            user_id: membership.user_id,
            identity_card_id: membership.identity_card_id,
            card_id: membership.card_id,
        },
    });
    scope.validate().map_err(|error| {
        AstralError::Validation(format!(
            "code=org_scope.capture_scope_invalid;detail={error}"
        ))
    })?;
    Ok(scope)
}

/// Single-fact membership coverage proof: exactly one MEMBERSHIP fact and the
/// unit node head untouched by this operation (membership facts never advance
/// the node). Applies to create AND revoke: the revoked member's scope still
/// closes through a revocation-frontier certificate.
async fn single_member_coverage_in_tx(
    tx: &mut Transaction<'static, MySql>,
    facts: &[CapturedOrgFact],
    operation_id: &str,
    unit_tenant_id: i64,
) -> Result<Option<AuthorityStagedScopeCoverage>, AstralError> {
    debug_assert_eq!(facts.len(), 1);
    let captured = &facts[0];
    let membership: OrgMembership = serde_json::from_str(&captured.payload_json).map_err(|_| {
        AstralError::Validation("code=org_scope.capture_membership_payload_invalid".into())
    })?;
    membership.validate().map_err(org_err)?;
    if membership.tenant_id != unit_tenant_id
        || captured.fact.tenant_id != unit_tenant_id
        || membership.operation_id != operation_id
    {
        return Ok(None);
    }
    // The node head must not carry this operation: membership facts never
    // advance the unit source head; if they did, this would be a mixed
    // content+membership mutation whose coverage is not provable here.
    let node_last_operation: Option<String> = sqlx::query_scalar(NODE_LAST_OPERATION_SQL)
        .bind(unit_tenant_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?;
    if node_last_operation.as_deref() == Some(operation_id) {
        return Ok(None);
    }
    let coverage = AuthorityStagedScopeCoverage {
        scopes: vec![member_scope(&membership)?],
    };
    coverage.validate().map_err(|error| {
        AstralError::Validation(format!(
            "code=org_scope.capture_coverage_invalid;detail={error}"
        ))
    })?;
    Ok(Some(coverage))
}

/// Unit-content coverage proof. Soundness rests on the unit node row lock
/// (held from the mutation's advance until commit): concurrent unit-content
/// mutations and membership creates serialize on it, so the bounded active
/// member read (idx_osmem_unit) plus the no-direct-children probe
/// (idx_osn_parent) prove the complete affected member set. Overflow, empty
/// sets, descendant fanout, and mixed subjects stay None (unknown GLOBAL).
async fn unit_content_coverage_in_tx(
    tx: &mut Transaction<'static, MySql>,
    facts: &[CapturedOrgFact],
    operation_id: &str,
    unit_tenant_id: i64,
) -> Result<Option<AuthorityStagedScopeCoverage>, AstralError> {
    if facts
        .iter()
        .any(|captured| captured.fact.tenant_id != unit_tenant_id)
    {
        return Ok(None);
    }
    // The unit source head must have advanced under this operation while the
    // node row lock is held: this is what invalidates the sealed publication.
    let node_last_operation: Option<String> = sqlx::query_scalar(NODE_LAST_OPERATION_SQL)
        .bind(unit_tenant_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?;
    if node_last_operation.as_deref() != Some(operation_id) {
        return Ok(None);
    }
    // Any direct child unit would inherit the head advance through dependency
    // propagation; that descendant fanout is not provable in this transaction.
    let has_child: Option<i8> = sqlx::query_scalar(DIRECT_CHILD_PROBE_SQL)
        .bind(unit_tenant_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?;
    if has_child.is_some() {
        return Ok(None);
    }
    let rows = sqlx::query(UNIT_ACTIVE_MEMBER_SQL)
        .bind(unit_tenant_id)
        .bind(ORG_COVERAGE_MAX_SCOPES as i64 + 1)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_err)?;
    if rows.is_empty() || rows.len() > ORG_COVERAGE_MAX_SCOPES {
        return Ok(None);
    }
    let mut scopes = Vec::with_capacity(rows.len());
    let mut root_tenant_id: Option<i64> = None;
    for row in &rows {
        let tenant_id: i64 = row.try_get("tenant_id").map_err(db_err)?;
        let row_root: i64 = row.try_get("root_tenant_id").map_err(db_err)?;
        let user_id: i64 = row.try_get("user_id").map_err(db_err)?;
        let identity_card_id: i64 = row.try_get("identity_card_id").map_err(db_err)?;
        let card_id: i64 = row.try_get("card_id").map_err(db_err)?;
        if tenant_id != unit_tenant_id {
            return Ok(None);
        }
        match root_tenant_id {
            Some(root) if root != row_root => return Ok(None),
            other => root_tenant_id = Some(other.unwrap_or(row_root)),
        }
        let scope = AuthorityProtocolScope::Org(AuthorityOrgScope {
            tenant_id,
            root_tenant_id: Some(row_root),
            member: AuthorityOrgMemberSubject {
                user_id,
                identity_card_id,
                card_id,
            },
        });
        scope.validate().map_err(|error| {
            AstralError::Validation(format!(
                "code=org_scope.capture_scope_invalid;detail={error}"
            ))
        })?;
        scopes.push(scope);
    }
    let coverage = AuthorityStagedScopeCoverage { scopes };
    coverage.validate().map_err(|error| {
        AstralError::Validation(format!(
            "code=org_scope.capture_coverage_invalid;detail={error}"
        ))
    })?;
    Ok(Some(coverage))
}

/// Derive the declared coverage from the captured facts plus in-transaction
/// completeness proofs. Mixed fact classes (membership + content) never
/// declare EXACT; unknown stays None (GLOBAL, operator-owned).
async fn derive_coverage_in_tx(
    tx: &mut Transaction<'static, MySql>,
    facts: &[CapturedOrgFact],
    operation_id: &str,
    unit_tenant_id: i64,
) -> Result<Option<AuthorityStagedScopeCoverage>, AstralError> {
    let any_membership = facts
        .iter()
        .any(|captured| captured.fact.subject_kind == "MEMBERSHIP");
    let all_membership = facts
        .iter()
        .all(|captured| captured.fact.subject_kind == "MEMBERSHIP");
    if any_membership && !all_membership {
        return Ok(None);
    }
    if all_membership {
        if facts.len() != 1 {
            return Ok(None);
        }
        return single_member_coverage_in_tx(tx, facts, operation_id, unit_tenant_id).await;
    }
    if facts
        .iter()
        .all(|captured| matches!(captured.fact.subject_kind.as_str(), "GRANT" | "MASK"))
    {
        return unit_content_coverage_in_tx(tx, facts, operation_id, unit_tenant_id).await;
    }
    Ok(None)
}

/// Read back one exact existing audit receipt after producer insertion. Every
/// identity is selected from the same transaction's durable audit rows.
pub(crate) async fn read_operation_audit_receipt_in_tx(
    tx: &mut Transaction<'static, MySql>,
    operation_id: &str,
    tenant_id: i64,
    action: &str,
    subject_kind: &str,
    subject_id: &str,
) -> Result<OrgSourceAuditReceiptEvidence, AstralError> {
    let audits = capture_audits_in_tx(tx, operation_id).await?;
    let matches: Vec<_> = audits
        .into_iter()
        .filter(|audit| {
            audit.tenant_id == tenant_id
                && audit.action == action
                && audit.subject_kind == subject_kind
                && audit.subject_id == subject_id
        })
        .collect();
    match matches.as_slice() {
        [receipt] => Ok(receipt.clone()),
        _ => Err(AstralError::Validation(
            "code=org_scope.audit_receipt_missing_or_ambiguous".into(),
        )),
    }
}

/// Capture the actual durable facts/receipts of this org mutation and bind
/// them to the admitted reservation in the SAME transaction (stage + promote
/// via the shared admission-bound owner entry point). Must be called after
/// `consume_org_authority_admission` (the staging API proves the durable
/// admission-use row) and before commit. Database-only: no network I/O.
pub(crate) async fn capture_and_stage_in_tx(
    tx: &mut Transaction<'static, MySql>,
    admission: &AuthorizationAdmission,
    operation_id: &str,
    unit_tenant_id: i64,
    membership_create_receipt: Option<OrgMembershipCreateReceiptEvidence>,
) -> Result<(), AstralError> {
    validated_operation_id(operation_id)?;
    let facts = capture_facts_in_tx(tx, operation_id).await?;
    let outbox = capture_outbox_in_tx(tx, operation_id).await?;
    let audits = capture_audits_in_tx(tx, operation_id).await?;
    let fact_evidence: Vec<OrgSourceFactEvidence> =
        facts.iter().map(|captured| captured.fact.clone()).collect();
    if let Some(receipt) = &membership_create_receipt {
        receipt.validate()?;
        if receipt.operation_id != operation_id || receipt.tenant_id != unit_tenant_id {
            return Err(AstralError::Validation(
                "code=org_scope.membership_create_receipt_binding_mismatch".into(),
            ));
        }
        let matching_fact = facts.iter().any(|captured| {
            captured.fact.subject_kind == "MEMBERSHIP"
                && captured.fact.tenant_id == receipt.tenant_id
                && captured.fact.subject_id == receipt.membership_id
                && captured.fact.revision == 1
                && captured.fact.before_digest_hex.is_none()
                && serde_json::from_str::<OrgMembership>(&captured.payload_json).is_ok_and(
                    |membership| {
                        membership.tenant_id == receipt.tenant_id
                            && membership.root_tenant_id == receipt.root_tenant_id
                            && membership.user_id == receipt.user_id
                            && membership.identity_card_id == receipt.identity_card_id
                            && membership.card_id == receipt.card_id
                            && membership.membership_id == receipt.membership_id
                            && membership.operation_id == operation_id
                            && membership.active
                    },
                )
        });
        if !matching_fact {
            return Err(AstralError::Validation(
                "code=org_scope.membership_create_receipt_fact_mismatch".into(),
            ));
        }
    }
    let before_digest_hex =
        org_source_image_digest(ORG_SOURCE_BEFORE_IMAGE_DOMAIN, &fact_evidence, true);
    let after_digest_hex =
        org_source_image_digest(ORG_SOURCE_AFTER_IMAGE_DOMAIN, &fact_evidence, false);
    let commit_digest_hex = org_source_commit_digest(
        &fact_evidence,
        &outbox,
        &audits,
        membership_create_receipt.as_ref(),
        &before_digest_hex,
        &after_digest_hex,
    )?;
    let evidence = OrgSourceOutcomeEvidenceV1 {
        marker: ORG_SOURCE_EVIDENCE_MARKER.to_owned(),
        operation_id: operation_id.to_owned(),
        facts: fact_evidence,
        outbox,
        audits,
        membership_create_receipt,
        before_digest_hex,
        after_digest_hex,
        commit_digest_hex,
    };
    evidence.validate()?;
    let coverage = derive_coverage_in_tx(tx, &facts, operation_id, unit_tenant_id).await?;
    let outcome = crate::authority_source_outcome::AuthoritySourceOutcomeEvidence {
        source_commit_digest: evidence.commit_digest_hex.clone(),
        before_image_digest: evidence.before_digest_hex.clone(),
        after_image_digest: evidence.after_digest_hex.clone(),
        source_receipts: evidence.receipt_identities(),
    };
    let evidence_json = evidence.evidence_json()?;
    crate::stage_admitted_source_outcome_with_coverage_in_tx(
        tx,
        admission,
        AuthorityMutationKind::AuthorizationSource,
        evidence_json,
        &outcome,
        coverage,
    )
    .await
    .map_err(AstralError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(subject_kind: &str, revision: u64, before: Option<&str>) -> OrgSourceFactEvidence {
        OrgSourceFactEvidence {
            subject_kind: subject_kind.to_owned(),
            tenant_id: 7,
            subject_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            revision,
            before_digest_hex: before.map(|value| value.to_owned()),
            after_digest_hex: "aa".repeat(32),
            revision_row_id: 42,
        }
    }

    #[test]
    fn image_digests_are_domain_separated_and_marker_stable() {
        let facts = vec![
            fact("GRANT", 1, None),
            fact("GRANT", 2, Some(&"bb".repeat(32))),
        ];
        let before = org_source_image_digest(ORG_SOURCE_BEFORE_IMAGE_DOMAIN, &facts, true);
        let after = org_source_image_digest(ORG_SOURCE_AFTER_IMAGE_DOMAIN, &facts, false);
        assert_ne!(before, after);
        assert_eq!(
            before,
            org_source_image_digest(ORG_SOURCE_BEFORE_IMAGE_DOMAIN, &facts, true),
            "digest must be deterministic"
        );
        // An absent before-state contributes the [0] marker: the digest is
        // always defined without inventing content.
        let only_first = vec![fact("MEMBERSHIP", 1, None)];
        let before_first =
            org_source_image_digest(ORG_SOURCE_BEFORE_IMAGE_DOMAIN, &only_first, true);
        assert_ne!(before_first, before);
    }

    #[test]
    fn commit_digest_binds_facts_outbox_and_images() {
        let facts = vec![fact("MEMBERSHIP", 1, None)];
        let outbox = vec![OrgSourceOutboxReceiptEvidence {
            org_event_id: 9,
            event_id: "org:membership_changed:uuid".to_owned(),
            event_kind: "MEMBERSHIP_CHANGED".to_owned(),
            tenant_id: 7,
        }];
        let audits = vec![OrgSourceAuditReceiptEvidence {
            audit_id: 7,
            tenant_id: 7,
            action: "MEMBERSHIP_CREATE".to_owned(),
            subject_kind: "MEMBERSHIP".to_owned(),
            subject_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            request_id: None,
        }];
        let before = org_source_image_digest(ORG_SOURCE_BEFORE_IMAGE_DOMAIN, &facts, true);
        let after = org_source_image_digest(ORG_SOURCE_AFTER_IMAGE_DOMAIN, &facts, false);
        let commit =
            org_source_commit_digest(&facts, &outbox, &audits, None, &before, &after).unwrap();
        assert_eq!(
            commit,
            org_source_commit_digest(&facts, &outbox, &audits, None, &before, &after).unwrap()
        );
        let other_outbox = vec![OrgSourceOutboxReceiptEvidence {
            org_event_id: 10,
            ..outbox[0].clone()
        }];
        assert_ne!(
            commit,
            org_source_commit_digest(&facts, &other_outbox, &audits, None, &before, &after)
                .unwrap(),
            "receipt identity mutation must change the commit digest"
        );
        let other_audits = vec![OrgSourceAuditReceiptEvidence {
            audit_id: 8,
            ..audits[0].clone()
        }];
        assert_ne!(
            commit,
            org_source_commit_digest(&facts, &outbox, &other_audits, None, &before, &after)
                .unwrap(),
            "audit identity mutation must change the commit digest"
        );
        assert_ne!(
            commit,
            org_source_commit_digest(&facts, &outbox, &audits, None, &after, &after).unwrap(),
            "image digest mutation must change the commit digest"
        );
    }

    #[test]
    fn evidence_validation_rejects_marker_capacity_and_digest_defects() {
        let membership_receipt = OrgMembershipCreateReceiptEvidence {
            tenant_id: 7,
            root_tenant_id: 1,
            user_id: 23,
            identity_card_id: 31,
            card_id: 17,
            membership_id: "11111111-1111-4111-8111-111111111111".into(),
            operation_id: "op-1".into(),
            before_absent: true,
            insert_rows_affected: 1,
            audit: OrgSourceAuditReceiptEvidence {
                audit_id: 1,
                tenant_id: 7,
                action: "MEMBERSHIP_CREATE".into(),
                subject_kind: "MEMBERSHIP".into(),
                subject_id: "11111111-1111-4111-8111-111111111111".into(),
                request_id: None,
            },
        };
        let evidence = OrgSourceOutcomeEvidenceV1 {
            marker: ORG_SOURCE_EVIDENCE_MARKER.to_owned(),
            operation_id: "op-1".to_owned(),
            facts: vec![fact("MEMBERSHIP", 1, None)],
            outbox: vec![OrgSourceOutboxReceiptEvidence {
                org_event_id: 9,
                event_id: "org:membership_changed:uuid".to_owned(),
                event_kind: "MEMBERSHIP_CHANGED".to_owned(),
                tenant_id: 7,
            }],
            audits: vec![OrgSourceAuditReceiptEvidence {
                audit_id: 1,
                tenant_id: 7,
                action: "MEMBERSHIP_CREATE".into(),
                subject_kind: "MEMBERSHIP".into(),
                subject_id: "11111111-1111-4111-8111-111111111111".into(),
                request_id: None,
            }],
            membership_create_receipt: Some(membership_receipt),
            before_digest_hex: org_source_image_digest(
                ORG_SOURCE_BEFORE_IMAGE_DOMAIN,
                &[fact("MEMBERSHIP", 1, None)],
                true,
            ),
            after_digest_hex: "aa".repeat(32),
            commit_digest_hex: "cc".repeat(32),
        };
        evidence.validate().unwrap();
        assert_eq!(evidence.receipt_identities().len(), 3);
        assert_eq!(
            evidence.receipt_identities()[2],
            crate::authority_source_outcome::AuthoritySourceReceiptIdentity {
                identity_kind: "org_scope_revision_row".into(),
                identity: "42".into(),
            }
        );
        assert!(evidence.all_membership_facts());
        assert!(evidence.any_membership_fact());
        assert!(!evidence.all_unit_content_facts());

        let mut wrong_marker = evidence.clone();
        wrong_marker.marker = "orgSourceEvidenceV2".to_owned();
        assert!(wrong_marker.validate().is_err());

        let mut empty_facts = evidence.clone();
        empty_facts.facts.clear();
        assert!(empty_facts.validate().is_err());

        let mut empty_outbox = evidence.clone();
        empty_outbox.outbox.clear();
        assert!(empty_outbox.validate().is_err());

        let mut short_digest = evidence.clone();
        short_digest.after_digest_hex = "aa".repeat(31);
        assert!(short_digest.validate().is_err());

        let mut bad_hex = evidence.clone();
        bad_hex.commit_digest_hex = "zz".repeat(32);
        assert!(bad_hex.validate().is_err());

        // JSON round trip is strict: unknown fields fail closed.
        let json = evidence.evidence_json().unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value["extra"] = serde_json::Value::Bool(true);
        let decoded: Result<OrgSourceOutcomeEvidenceV1, _> = serde_json::from_value(value);
        assert!(decoded.is_err(), "unknown evidence fields must be refused");
    }

    #[test]
    fn content_fact_classification_matches_subject_sets() {
        let grant = fact("GRANT", 1, None);
        let mask = OrgSourceFactEvidence {
            subject_kind: "MASK".to_owned(),
            ..fact("GRANT", 1, None)
        };
        let membership = fact("MEMBERSHIP", 1, None);
        let node = OrgSourceFactEvidence {
            subject_kind: "NODE".to_owned(),
            ..fact("GRANT", 1, None)
        };
        let base = || OrgSourceOutcomeEvidenceV1 {
            marker: ORG_SOURCE_EVIDENCE_MARKER.to_owned(),
            operation_id: "op-1".to_owned(),
            facts: Vec::new(),
            outbox: vec![],
            audits: vec![OrgSourceAuditReceiptEvidence {
                audit_id: 1,
                tenant_id: 7,
                action: "ACTION".into(),
                subject_kind: "NODE".into(),
                subject_id: "7".into(),
                request_id: None,
            }],
            membership_create_receipt: None,
            before_digest_hex: "aa".repeat(32),
            after_digest_hex: "aa".repeat(32),
            commit_digest_hex: "cc".repeat(32),
        };
        let content = OrgSourceOutcomeEvidenceV1 {
            facts: vec![grant.clone(), mask],
            ..base()
        };
        assert!(content.all_unit_content_facts());
        assert!(!content.all_membership_facts());
        let mixed = OrgSourceOutcomeEvidenceV1 {
            facts: vec![grant, membership],
            ..base()
        };
        assert!(mixed.any_membership_fact() && !mixed.all_membership_facts());
        assert!(!mixed.all_unit_content_facts());
        let node_fact = OrgSourceOutcomeEvidenceV1 {
            facts: vec![node],
            ..base()
        };
        assert!(!node_fact.all_unit_content_facts());
    }

    #[test]
    fn membership_create_receipt_keeps_historical_insert_evidence_but_not_first_scope_eligibility()
    {
        let audit = OrgSourceAuditReceiptEvidence {
            audit_id: 7,
            tenant_id: 7,
            action: "MEMBERSHIP_CREATE".into(),
            subject_kind: "MEMBERSHIP".into(),
            subject_id: "22222222-2222-4222-8222-222222222222".into(),
            request_id: None,
        };
        let receipt = OrgMembershipCreateReceiptEvidence {
            tenant_id: 7,
            root_tenant_id: 1,
            user_id: 23,
            identity_card_id: 31,
            card_id: 17,
            membership_id: audit.subject_id.clone(),
            operation_id: "op-1".into(),
            before_absent: false,
            insert_rows_affected: 1,
            audit,
        };
        // A legitimate rejoin still captures its actual source mutation; only
        // the first-certificate validator may reject historical tuple reuse.
        assert!(receipt.validate().is_ok());
        let evidence = OrgSourceOutcomeEvidenceV1 {
            marker: ORG_SOURCE_EVIDENCE_MARKER.into(),
            operation_id: receipt.operation_id.clone(),
            facts: vec![OrgSourceFactEvidence {
                subject_kind: "MEMBERSHIP".into(),
                tenant_id: 7,
                subject_id: receipt.membership_id.clone(),
                revision: 1,
                before_digest_hex: None,
                after_digest_hex: "aa".repeat(32),
                revision_row_id: 42,
            }],
            outbox: vec![OrgSourceOutboxReceiptEvidence {
                org_event_id: 9,
                event_id: "org:membership_changed:uuid".into(),
                event_kind: "MEMBERSHIP_CHANGED".into(),
                tenant_id: 7,
            }],
            audits: vec![receipt.audit.clone()],
            membership_create_receipt: Some(receipt.clone()),
            before_digest_hex: "aa".repeat(32),
            after_digest_hex: "bb".repeat(32),
            commit_digest_hex: "cc".repeat(32),
        };
        assert!(evidence.validate().is_ok());
        let mut unrelated_node_event = evidence;
        unrelated_node_event.outbox[0].event_kind = "NODE_CREATED".into();
        assert!(unrelated_node_event.validate().is_err());

        let mut absent_receipt = receipt;
        absent_receipt.before_absent = true;
        assert!(absent_receipt.validate().is_ok());
    }

    #[test]
    fn member_scope_is_member_exact_and_validated() {
        let membership = OrgMembership {
            membership_id: "22222222-2222-4222-8222-222222222222".to_owned(),
            tenant_id: 7,
            root_tenant_id: 1,
            user_id: 23,
            identity_card_id: 31,
            card_id: 17,
            revision: 1,
            active: true,
            validity: astral_types::ValidityWindow::between(1_000, 2_000),
            operation_id: "op-1".to_owned(),
        };
        let scope = member_scope(&membership).unwrap();
        let AuthorityProtocolScope::Org(org) = &scope else {
            panic!("org scope expected");
        };
        assert_eq!(org.tenant_id, 7);
        assert_eq!(org.root_tenant_id, Some(1));
        assert_eq!(org.member.user_id, 23);
        assert_eq!(org.member.identity_card_id, 31);
        assert_eq!(org.member.card_id, 17);
        assert_eq!(scope.store_key_text().unwrap(), "ORG:7:1:23:31:17");
    }

    /// The staging entry point is the shared admission-bound owner API with
    /// EXACT-or-None coverage; nothing here may bypass the durable
    /// reservation/admission-use verification.
    #[test]
    fn staging_goes_through_the_shared_coverage_owner_api() {
        let source = include_str!("org_authority_capture.rs");
        assert!(source.contains("crate::stage_admitted_source_outcome_with_coverage_in_tx("));
        assert!(source.contains("AuthorityMutationKind::AuthorizationSource"));
        // Split literal so this assertion cannot self-match its own text.
        let bypass_call = format!("stage_authority_source_{}tx(", "outcome");
        assert!(
            !source.contains(&bypass_call),
            "capture must not bypass the admission-bound staging wrapper"
        );
        // The capture never reads or derives anything from an authorization
        // snapshot: digests come from ledger payload digests only.
        let snapshot_type = format!("Authorization{}Proof", "Fence");
        assert!(!source.contains(&snapshot_type));
        assert!(source.contains("payload_digest"));
    }
}
