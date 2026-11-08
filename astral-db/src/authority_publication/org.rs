//! ORG source-owner publication candidate (V7): certification candidates
//! rebuilt from exact retained org source evidence and strict WorkerOwned
//! completion proofs.
//!
//! Contract (Rust 规范 §15.9):
//! - The certificate content identity is `org_authority_evidence_hash` over
//!   the FULL current (publication, node, membership) evidence — never an
//!   actor snapshot, never the current database self-signed arbitrarily: the
//!   candidate re-verifies every retained receipt (ledger rows, outbox rows)
//!   against the approved source operation before any state is read.
//! - The sealed publication must be the exact WorkerOwned completion of this
//!   source operation: current-pointer identity equality, SEALED status,
//!   manifest digest recomputed from the sealed segments, and
//!   `publication.operation_id == source operation` for content operations.
//! - Baseline chaining is exact: membership-scoped operations require the
//!   baseline manifest identity to be byte-identical (unchanged publication);
//!   content operations require the single next generation
//!   (baseline generation + 1). Intermediate bundles stay PENDING.
//! - Revoked members and deactivated units certify through the shared
//!   revocation-frontier hash (`astral_types::
//!   org_authority_revocation_evidence_hash`, single structural validator,
//!   node OR member inactive): no active state is ever fabricated, and the
//!   strict DB read gate keeps refusing ALLOW for inactive states.

use super::*;
use sha2::{Digest, Sha256};

use crate::org_scope_repository::{
    load_node_in_tx, load_sealed_publication_in_tx, membership_from_row, org_source_commit_digest,
    org_source_image_digest, typed_membership, OrgMembershipCreateReceiptEvidence,
    OrgMembershipRow, OrgSourceFactEvidence, OrgSourceOutboxReceiptEvidence,
    OrgSourceOutcomeEvidenceV1, ORG_SOURCE_AFTER_IMAGE_DOMAIN, ORG_SOURCE_BEFORE_IMAGE_DOMAIN,
};
use astral_types::org_scope::{
    org_dependency_digest_hex, org_manifest_digest_hex, OrgAdmissionEvidence,
    OrgManifestDigestMaterial, OrgMembership, OrgPublication, ORG_SCOPE_AGGREGATE_TYPE,
};
use astral_types::AuthorityOrgScope;
use astral_types::{org_authority_evidence_hash, org_authority_revocation_evidence_hash};

const ORG_SEMANTIC_CONTENT_DOMAIN: &[u8] = b"ASTRAL_ORG_SEMANTIC_CONTENT_V7\0";

const VERIFY_FACT_REVISION_SQL: &str = "SELECT revision_row_id, payload_digest, operation_id \
     FROM org_scope_revision WHERE subject_kind = ? AND subject_id = ? AND revision = ?";
const VERIFY_RECEIPT_SQL: &str = "SELECT event_id, event_kind, tenant_id, operation_id, status \
     FROM org_scope_outbox WHERE org_event_id = ?";
const VERIFY_AUDIT_SQL: &str =
    "SELECT tenant_id, action, subject_kind, subject_id, request_id, operation_id \
     FROM org_scope_audit WHERE audit_id = ?";
/// Current membership state for a member-exact scope: the active row wins
/// (unique per card), otherwise the latest inactive row is the tombstone.
const MEMBER_STATE_SQL: &str = "SELECT membership_id, tenant_id, root_tenant_id, user_id, \
     identity_card_id, card_id, revision, active, valid_from, valid_until, operation_id \
     FROM org_scope_membership \
     WHERE tenant_id = ? AND user_id = ? AND identity_card_id = ? AND card_id = ? \
     ORDER BY active DESC, revision DESC LIMIT 1";

/// Exact ledger receipt verification: the fact's revision row must exist with
/// the retained digest and carry the approved source operation id; the
/// before-digest must equal the true predecessor revision row (or be absent
/// exactly at revision 1).
async fn verify_fact_receipt_in_tx(
    tx: &mut Transaction<'_, MySql>,
    fact: &OrgSourceFactEvidence,
    operation_id: &str,
) -> Result<(), PolicyError> {
    let row: Option<(i64, Vec<u8>, String)> = sqlx::query_as(VERIFY_FACT_REVISION_SQL)
        .bind(&fact.subject_kind)
        .bind(&fact.subject_id)
        .bind(i64::try_from(fact.revision).map_err(|_| pending("fact revision overflow"))?)
        .fetch_optional(&mut **tx)
        .await
        .map_err(pending)?;
    let (revision_row_id, payload_digest, row_operation_id) =
        row.ok_or_else(|| pending("an approved org fact is missing from the revision ledger"))?;
    if revision_row_id != fact.revision_row_id
        || hex::encode(&payload_digest) != fact.after_digest_hex
        || row_operation_id != operation_id
    {
        return Err(pending(
            "an approved org fact no longer matches its retained receipt identity",
        ));
    }
    if fact.revision == 1 {
        if fact.before_digest_hex.is_some() {
            return Err(pending(
                "a first org revision must not declare a before image",
            ));
        }
        return Ok(());
    }
    let predecessor: Option<(Vec<u8>,)> = sqlx::query_as(
        "SELECT payload_digest FROM org_scope_revision \
             WHERE subject_kind = ? AND subject_id = ? AND revision = ?",
    )
    .bind(&fact.subject_kind)
    .bind(&fact.subject_id)
    .bind(
        i64::try_from(fact.revision - 1)
            .map_err(|_| pending("fact predecessor revision overflow"))?,
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(pending)?;
    let (predecessor_digest,) =
        predecessor.ok_or_else(|| pending("an approved org fact has no predecessor revision"))?;
    if fact.before_digest_hex.as_deref() != Some(hex::encode(predecessor_digest).as_str()) {
        return Err(pending(
            "an approved org fact's before image diverges from its predecessor revision",
        ));
    }
    Ok(())
}

/// Exact outbox receipt verification: the durable event row must exist and
/// carry the retained identity plus the approved source operation binding.
async fn verify_audit_receipt_in_tx(
    tx: &mut Transaction<'_, MySql>,
    receipt: &crate::org_scope_repository::OrgSourceAuditReceiptEvidence,
    operation_id: &str,
) -> Result<(), PolicyError> {
    let row: Option<(i64, String, String, String, Option<i64>, String)> =
        sqlx::query_as(VERIFY_AUDIT_SQL)
            .bind(receipt.audit_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(pending)?;
    let (tenant_id, action, subject_kind, subject_id, request_id, row_operation_id) =
        row.ok_or_else(|| pending("an approved org audit receipt is missing"))?;
    if tenant_id != receipt.tenant_id
        || action != receipt.action
        || subject_kind != receipt.subject_kind
        || subject_id != receipt.subject_id
        || request_id != receipt.request_id
        || row_operation_id != operation_id
    {
        return Err(pending(
            "an approved org audit receipt no longer matches its retained identity",
        ));
    }
    Ok(())
}

async fn verify_outbox_receipt_in_tx(
    tx: &mut Transaction<'_, MySql>,
    receipt: &OrgSourceOutboxReceiptEvidence,
    operation_id: &str,
) -> Result<(), PolicyError> {
    let row: Option<(String, String, i64, String, String)> = sqlx::query_as(VERIFY_RECEIPT_SQL)
        .bind(receipt.org_event_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(pending)?;
    let (event_id, event_kind, tenant_id, row_operation_id, _status) =
        row.ok_or_else(|| pending("an approved org outbox receipt is missing"))?;
    if event_id != receipt.event_id
        || event_kind != receipt.event_kind
        || tenant_id != receipt.tenant_id
        || row_operation_id != operation_id
    {
        return Err(pending(
            "an approved org outbox receipt no longer matches its retained identity",
        ));
    }
    Ok(())
}

/// Canonical semantic content digest over the sealed segment bytes (sealed
/// order, digest + content bound). Owner-internal, deterministic.
fn org_semantic_hash_hex(publication: &OrgPublication) -> String {
    let mut hash = Sha256::new();
    hash.update(ORG_SEMANTIC_CONTENT_DOMAIN);
    hash.update((publication.segments.len() as u64).to_be_bytes());
    for segment in &publication.segments {
        hash.update(segment.index.to_be_bytes());
        digest_field(&mut hash, &segment.digest_hex);
        let content = serde_json::to_vec(&segment.content).unwrap_or_default();
        hash.update((content.len() as u64).to_be_bytes());
        hash.update(&content);
    }
    hex::encode(hash.finalize())
}

fn digest_field(hash: &mut Sha256, value: &str) {
    hash.update((value.len() as u32).to_be_bytes());
    hash.update(value.as_bytes());
}

/// The single manifest identity bound into ORG certificates: recomputed from
/// the sealed publication material (segments + dependency vector + fences),
/// not copied from any mutable pointer.
fn org_manifest_identity(
    publication: &OrgPublication,
    primary_event_id: &str,
) -> Result<AuthorityManifestIdentity, PolicyError> {
    let recomputed = org_manifest_digest_hex(&OrgManifestDigestMaterial {
        tenant_id: publication.tenant_id,
        root_tenant_id: publication.root_tenant_id,
        generation: publication.generation,
        relationship_revision: publication.relationship_revision,
        revoke_fence: publication.revoke_fence,
        dependencies: &publication.dependencies,
        segments: &publication.segments,
        compiler_version: &publication.compiler_version,
        operation_id: &publication.operation_id,
    })
    .map_err(pending)?;
    if recomputed != publication.manifest_digest_hex {
        return Err(pending(
            "sealed publication manifest digest does not match its sealed segments",
        ));
    }
    let identity = AuthorityManifestIdentity {
        aggregate_type: ORG_SCOPE_AGGREGATE_TYPE.to_owned(),
        aggregate_id: publication.tenant_id,
        manifest_digest_hex: publication.manifest_digest_hex.clone(),
        dependency_hash_hex: org_dependency_digest_hex(&publication.dependencies)
            .map_err(pending)?,
        semantic_hash_hex: org_semantic_hash_hex(publication),
        generation: publication.generation,
        revoke_fence: publication.revoke_fence,
        event_id: primary_event_id.to_owned(),
        operation_id: publication.operation_id.clone(),
    };
    identity.validate().map_err(pending)?;
    Ok(identity)
}

/// Exact baseline chaining requirements, split out for direct unit testing.
/// Membership-scoped operations publish the unchanged publication (manifest
/// identity equal); content operations must be the single next generation.
fn baseline_step_error(
    membership_only: bool,
    previous_generation: u64,
    current_generation: u64,
) -> Option<&'static str> {
    if membership_only {
        (previous_generation != current_generation).then_some(
            "baseline publication identity diverges from the unchanged sealed publication",
        )
    } else {
        (previous_generation.checked_add(1) != Some(current_generation))
            .then_some("publication chain skips an approved parent generation")
    }
}

/// Membership is an independently versioned eligibility fact. Its mutation
/// does not advance the unit content/topology head, but certification still
/// requires both fences and the exact current membership after-image to match
/// the retained approved source fact. This prevents a later membership event
/// from being signed against a stale node/publication pair.
struct MembershipSourceFreshnessContext<'a> {
    node_generation: u64,
    publication_generation: u64,
    node_revoke_fence: u64,
    publication_revoke_fence: u64,
    node_relationship_revision: u64,
    publication_relationship_revision: u64,
    publication_operation_id: &'a str,
    membership_id: &'a str,
    fact_membership_id: &'a str,
    membership_revision: u64,
    fact_revision: u64,
    membership_operation_id: &'a str,
    evidence_operation_id: &'a str,
}

fn membership_source_freshness_error(
    context: &MembershipSourceFreshnessContext<'_>,
) -> Option<&'static str> {
    if context.node_generation != context.publication_generation
        || context.node_revoke_fence != context.publication_revoke_fence
        || context.node_relationship_revision != context.publication_relationship_revision
    {
        return Some("unit source head advanced past the sealed publication");
    }
    if context.publication_operation_id == context.evidence_operation_id {
        return Some("membership source operation cannot be the sealed publication operation");
    }
    if context.membership_id != context.fact_membership_id {
        return Some("member state is not the exact approved membership fact");
    }
    if context.membership_revision != context.fact_revision {
        return Some("membership revision differs from the approved source fact");
    }
    if context.membership_operation_id != context.evidence_operation_id {
        return Some("membership state is not the exact approved source operation");
    }
    None
}

/// The source operation's primary event receipt: exactly one non-propagation
/// event binds its event identity. Membership events are retained here as source
/// correlation only; WorkerOwned publication still rejects MEMBERSHIP_CHANGED.
fn primary_receipt(
    evidence: &OrgSourceOutcomeEvidenceV1,
) -> Result<&OrgSourceOutboxReceiptEvidence, PolicyError> {
    let primary: Vec<_> = evidence
        .outbox
        .iter()
        .filter(|receipt| {
            !matches!(
                receipt.event_kind.as_str(),
                "SUBTREE_PROPAGATE" | "DEPENDENCY_PROPAGATE"
            )
        })
        .collect();
    match primary.as_slice() {
        [receipt] => Ok(receipt),
        _ => Err(pending(
            "org staged evidence must carry exactly one publication-driving receipt",
        )),
    }
}

/// A first membership must attach to an already sealed historical baseline.
/// The membership source operation cannot also be the operation that sealed the
/// baseline publication; otherwise the candidate would self-certify a new
/// publication identity from the current membership mutation.
fn first_membership_baseline_error(
    publication: &OrgPublication,
    receipt: &OrgMembershipCreateReceiptEvidence,
) -> Option<&'static str> {
    (publication.operation_id == receipt.operation_id)
        .then_some("first ORG membership requires a historical sealed baseline")
}

/// Load the member-exact current membership state (active row wins; latest
/// inactive row is the tombstone for a revoked member).
fn validate_first_membership_scope(
    scope: &AuthorityOrgScope,
    membership: &OrgMembership,
    publication: &OrgPublication,
    receipt: &OrgMembershipCreateReceiptEvidence,
) -> Result<(), PolicyError> {
    receipt.validate().map_err(pending)?;
    if let Some(detail) = first_membership_baseline_error(publication, receipt) {
        return Err(pending(detail));
    }
    if !receipt.before_absent
        || receipt.insert_rows_affected != 1
        || receipt.operation_id != membership.operation_id
        || receipt.membership_id != membership.membership_id
        || receipt.tenant_id != scope.tenant_id
        || Some(receipt.root_tenant_id) != scope.root_tenant_id
        || receipt.user_id != scope.member.user_id
        || receipt.identity_card_id != scope.member.identity_card_id
        || receipt.card_id != scope.member.card_id
        || membership.tenant_id != receipt.tenant_id
        || membership.root_tenant_id != receipt.root_tenant_id
        || membership.user_id != receipt.user_id
        || membership.identity_card_id != receipt.identity_card_id
        || membership.card_id != receipt.card_id
        || membership.revision != 1
        || !membership.active
        || membership.operation_id != receipt.operation_id
        || publication.tenant_id != receipt.tenant_id
        || publication.root_tenant_id != receipt.root_tenant_id
        || publication.generation != 1
        || publication.relationship_revision != 1
        || publication.revoke_fence != 0
        || !publication.segments.is_empty()
    {
        return Err(pending(
            "first ORG scope requires exact absent-before INSERT and approved zero-base sealed publication",
        ));
    }
    Ok(())
}

async fn membership_tuple_has_prior_row_in_tx(
    tx: &mut Transaction<'_, MySql>,
    receipt: &OrgMembershipCreateReceiptEvidence,
) -> Result<bool, PolicyError> {
    let prior: Option<String> = sqlx::query_scalar(
        "SELECT membership_id FROM org_scope_membership \
         WHERE tenant_id = ? AND user_id = ? AND identity_card_id = ? AND card_id = ? \
           AND NOT (membership_id = ? AND operation_id = ? AND revision = 1 AND active = 1) \
         ORDER BY revision DESC LIMIT 1",
    )
    .bind(receipt.tenant_id)
    .bind(receipt.user_id)
    .bind(receipt.identity_card_id)
    .bind(receipt.card_id)
    .bind(&receipt.membership_id)
    .bind(&receipt.operation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(pending)?;
    Ok(prior.is_some())
}

async fn load_member_state_in_tx(
    tx: &mut Transaction<'_, MySql>,
    tenant_id: i64,
    user_id: i64,
    identity_card_id: i64,
    card_id: i64,
) -> Result<Option<OrgMembership>, PolicyError> {
    let row: Option<sqlx::mysql::MySqlRow> = sqlx::query(MEMBER_STATE_SQL)
        .bind(tenant_id)
        .bind(user_id)
        .bind(identity_card_id)
        .bind(card_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(pending)?;
    row.map(|row| -> Result<OrgMembership, PolicyError> {
        let row: OrgMembershipRow = membership_from_row(&row).map_err(pending)?;
        typed_membership(&row).map_err(pending)
    })
    .transpose()
}

/// Rebuild the ORG certification candidate for one member-exact scope from
/// the retained staged evidence (envelope.evidence payload). Every retained
/// receipt is re-verified against the ledger/outbox before any current state
/// is read; the sealed publication must be the exact WorkerOwned completion
/// of the approved source operation. Database-only: no network I/O.
pub(super) async fn load_org_candidate_in_tx(
    tx: &mut Transaction<'_, MySql>,
    scope: &AuthorityProtocolScope,
    staged: &serde_json::Value,
    baseline: Option<&AuthorityScopePublicationCertificate>,
) -> Result<AuthorityPublicationCandidate, PolicyError> {
    let AuthorityProtocolScope::Org(org) = scope else {
        return Err(pending("org publication candidate requires an ORG scope"));
    };
    org.validate().map_err(pending)?;
    let Some(root_tenant_id) = org.root_tenant_id else {
        return Err(pending("ORG scope must pin its administrative root"));
    };
    let evidence: OrgSourceOutcomeEvidenceV1 = serde_json::from_value(staged.clone())
        .map_err(|_| pending("org staged evidence is not the owner's typed payload"))?;
    evidence.validate().map_err(pending)?;

    // 1-2. Exact retained receipts before any current-state read.
    for fact in &evidence.facts {
        verify_fact_receipt_in_tx(tx, fact, &evidence.operation_id).await?;
    }
    for receipt in &evidence.outbox {
        verify_outbox_receipt_in_tx(tx, receipt, &evidence.operation_id).await?;
    }
    for receipt in &evidence.audits {
        verify_audit_receipt_in_tx(tx, receipt, &evidence.operation_id).await?;
    }
    if let Some(receipt) = &evidence.membership_create_receipt {
        verify_audit_receipt_in_tx(tx, &receipt.audit, &evidence.operation_id).await?;
    }
    let durable_audits: Vec<(i64, i64, String, String, String, Option<i64>)> = sqlx::query_as(
        "SELECT audit_id, tenant_id, action, subject_kind, subject_id, request_id \
         FROM org_scope_audit WHERE operation_id = ? ORDER BY audit_id",
    )
    .bind(&evidence.operation_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(pending)?;
    if durable_audits.len() != evidence.audits.len()
        || durable_audits
            .iter()
            .zip(&evidence.audits)
            .any(|(row, receipt)| {
                row.0 != receipt.audit_id
                    || row.1 != receipt.tenant_id
                    || row.2 != receipt.action
                    || row.3 != receipt.subject_kind
                    || row.4 != receipt.subject_id
                    || row.5 != receipt.request_id
            })
    {
        return Err(pending(
            "retained org audit set differs from the exact durable operation audit rows",
        ));
    }

    // 3. The approved batch digests must recompute exactly.
    let before = org_source_image_digest(ORG_SOURCE_BEFORE_IMAGE_DOMAIN, &evidence.facts, true);
    let after = org_source_image_digest(ORG_SOURCE_AFTER_IMAGE_DOMAIN, &evidence.facts, false);
    if before != evidence.before_digest_hex || after != evidence.after_digest_hex {
        return Err(pending(
            "org staged image digests do not match the retained facts",
        ));
    }
    let commit = org_source_commit_digest(
        &evidence.facts,
        &evidence.outbox,
        &evidence.audits,
        evidence.membership_create_receipt.as_ref(),
        &before,
        &after,
    )
    .map_err(pending)?;
    if commit != evidence.commit_digest_hex {
        return Err(pending(
            "org staged commit digest does not match the retained batch",
        ));
    }

    // 4. Classification. Mixed membership+content batches fail closed.
    let membership_only = evidence.all_membership_facts();
    if evidence.membership_create_receipt.is_some() && !membership_only {
        return Err(pending(
            "membership-create receipt cannot accompany non-membership source facts",
        ));
    }
    if evidence.any_membership_fact() && !membership_only {
        return Err(pending("mixed org fact classes cannot be certified"));
    }
    let content_operation = !membership_only;
    if content_operation && !evidence.all_unit_content_facts() {
        return Err(pending(
            "org staged facts are neither membership nor unit-content facts",
        ));
    }
    if content_operation
        && evidence
            .facts
            .iter()
            .any(|fact| fact.tenant_id != org.tenant_id)
    {
        return Err(pending(
            "org content facts belong to a different publication unit",
        ));
    }
    let primary = primary_receipt(&evidence)?;

    // 5. Current state: sealed publication + node head + member state.
    let publication = load_sealed_publication_in_tx(tx, org.tenant_id)
        .await
        .map_err(pending)?
        .ok_or_else(|| pending("unit has no provable current sealed publication"))?;
    if publication.root_tenant_id != root_tenant_id {
        return Err(pending(
            "sealed publication root differs from the ORG scope",
        ));
    }
    publication.validate().map_err(pending)?;
    let node_row = load_node_in_tx(tx, org.tenant_id)
        .await
        .map_err(pending)?
        .ok_or_else(|| pending("unit node row is absent"))?;
    let node = crate::org_scope_repository::typed_node(&node_row)
        .map_err(|_| pending("unit node row is not a provable typed node"))?;
    // An inactive node is NOT a hard reject here: a deactivated unit is a
    // revocation state whose scope certificate is issued through the
    // revocation frontier below.
    if node.generation != publication.generation
        || node.revoke_fence != publication.revoke_fence
        || node.relationship_revision != publication.relationship_revision
    {
        return Err(pending(
            "unit source head advanced past the sealed publication",
        ));
    }
    let membership = load_member_state_in_tx(
        tx,
        org.tenant_id,
        org.member.user_id,
        org.member.identity_card_id,
        org.member.card_id,
    )
    .await?
    .ok_or_else(|| pending("member-exact scope has no membership state"))?;
    if membership.root_tenant_id != root_tenant_id {
        return Err(pending("member state root differs from the ORG scope"));
    }

    // 6. Classification proofs against the current durable state.
    // Seal integrity is re-proven from the sealed material in BOTH branches;
    // the manifest identity keeps the publication's own event binding: an
    // unchanged publication carries the BASELINE manifest verbatim (old
    // sealing event), a content operation binds this operation's primary
    // receipt event.
    let recomputed_manifest_digest = org_manifest_digest_hex(&OrgManifestDigestMaterial {
        tenant_id: publication.tenant_id,
        root_tenant_id: publication.root_tenant_id,
        generation: publication.generation,
        relationship_revision: publication.relationship_revision,
        revoke_fence: publication.revoke_fence,
        dependencies: &publication.dependencies,
        segments: &publication.segments,
        compiler_version: &publication.compiler_version,
        operation_id: &publication.operation_id,
    })
    .map_err(pending)?;
    if recomputed_manifest_digest != publication.manifest_digest_hex {
        return Err(pending(
            "sealed publication manifest digest does not match its sealed segments",
        ));
    }
    if membership_only {
        let fact = &evidence.facts[0];
        if let Some(detail) = membership_source_freshness_error(&MembershipSourceFreshnessContext {
            node_generation: node.generation,
            publication_generation: publication.generation,
            node_revoke_fence: node.revoke_fence,
            publication_revoke_fence: publication.revoke_fence,
            node_relationship_revision: node.relationship_revision,
            publication_relationship_revision: publication.relationship_revision,
            publication_operation_id: &publication.operation_id,
            membership_id: &membership.membership_id,
            fact_membership_id: &fact.subject_id,
            membership_revision: membership.revision,
            fact_revision: fact.revision,
            membership_operation_id: &membership.operation_id,
            evidence_operation_id: &evidence.operation_id,
        }) {
            return Err(pending(detail));
        }
        let live_json = serde_json::to_string(&membership)
            .map_err(|_| pending("member state cannot be canonicalized"))?;
        if Sha256::digest(live_json.as_bytes()).to_vec()
            != hex::decode(&fact.after_digest_hex).map_err(pending)?
        {
            return Err(pending(
                "member state bytes diverge from the approved after image",
            ));
        }
    } else if publication.operation_id != evidence.operation_id {
        return Err(pending(
            "sealed publication is not the WorkerOwned completion of this source operation",
        ));
    }

    // 7. Baseline chaining (exact; no guessed intermediate bundles). The sole
    // parentless case is the normal first membership create whose transaction
    // recorded exact tuple absence + INSERT receipt, and whose unchanged sealed
    // baseline is a genuine empty generation-0 publication. ROOT/import and
    // historical/rejoined memberships never inherit this exception.
    let (manifest, parent_certificate_hash) = match baseline {
        Some(baseline) => {
            if baseline.scope != *scope {
                return Err(pending("baseline scope differs"));
            }
            if baseline.manifests.len() != 1 {
                return Err(pending(
                    "ORG baseline must carry exactly one manifest identity",
                ));
            }
            if let Some(step_error) = baseline_step_error(
                membership_only,
                baseline.manifests[0].generation,
                publication.generation,
            ) {
                return Err(pending(step_error));
            }
            let manifest = if membership_only {
                if baseline.manifests[0].manifest_digest_hex != publication.manifest_digest_hex {
                    return Err(pending(
                        "baseline publication identity diverges from the unchanged sealed publication",
                    ));
                }
                baseline.manifests[0].clone()
            } else {
                org_manifest_identity(&publication, &primary.event_id)?
            };
            (manifest, Some(baseline.record_digest().map_err(pending)?))
        }
        None => {
            let receipt = evidence.membership_create_receipt.as_ref().ok_or_else(|| {
                pending("first ORG scope publication lacks source-proven membership creation")
            })?;
            validate_first_membership_scope(org, &membership, &publication, receipt)?;
            if !receipt.before_absent {
                return Err(pending(
                    "first ORG scope membership create lacks an absent-before source proof",
                ));
            }
            if membership_tuple_has_prior_row_in_tx(tx, receipt).await? {
                return Err(pending(
                    "first ORG scope membership tuple has historical rows; ROOT/import recovery is required",
                ));
            }
            (
                org_manifest_identity(&publication, &primary.event_id)?,
                None,
            )
        }
    };

    // 8. Content identity: the full publication/node/member evidence hash.
    // Single type owner: the positive hash enforces the complete
    // OrgAdmissionEvidence contract; the revocation hash reuses the shared
    // structural validator and requires node OR member inactive. The strict
    // DB read gate keeps refusing ALLOW for inactive states — nothing is
    // fabricated here.
    let now: i64 = sqlx::query_scalar("SELECT CAST(UNIX_TIMESTAMP() AS SIGNED)")
        .fetch_one(&mut **tx)
        .await
        .map_err(pending)?;
    let admission_evidence = OrgAdmissionEvidence {
        publication,
        node,
        membership,
        checked_at_unix: now,
    };
    let snapshot_hash = if admission_evidence.node.active && admission_evidence.membership.active {
        admission_evidence.validate().map_err(pending)?;
        org_authority_evidence_hash(&admission_evidence).map_err(pending)?
    } else {
        org_authority_revocation_evidence_hash(&admission_evidence).map_err(pending)?
    };
    if baseline.is_some_and(|baseline| baseline.snapshot_hash == snapshot_hash) {
        return Err(pending("source receipts do not change the declared scope"));
    }
    Ok(AuthorityPublicationCandidate {
        scope: scope.clone(),
        manifests: vec![manifest],
        snapshot_hash,
        parent_certificate_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::authority_protocol::AuthorityOrgMemberSubject;

    fn sealed_publication() -> OrgPublication {
        astral_types::org_scope::OrgPublication {
            tenant_id: 7,
            root_tenant_id: 1,
            generation: 4,
            relationship_revision: 2,
            revoke_fence: 1,
            dependencies: vec![astral_types::org_scope::OrgDependency {
                tenant_id: 1,
                generation: 9,
                revoke_fence: 2,
                relationship_revision: 3,
            }],
            manifest_digest_hex: String::new(),
            compiler_version: astral_types::AUTHORIZATION_ORG_COMPILER_VERSION.to_owned(),
            segments: Vec::new(),
            operation_id: "op-seal".to_owned(),
        }
    }

    #[test]
    fn manifest_identity_recomputes_from_sealed_material() {
        let mut publication = sealed_publication();
        let digest = org_manifest_digest_hex(&OrgManifestDigestMaterial {
            tenant_id: publication.tenant_id,
            root_tenant_id: publication.root_tenant_id,
            generation: publication.generation,
            relationship_revision: publication.relationship_revision,
            revoke_fence: publication.revoke_fence,
            dependencies: &publication.dependencies,
            segments: &publication.segments,
            compiler_version: &publication.compiler_version,
            operation_id: &publication.operation_id,
        })
        .unwrap();
        publication.manifest_digest_hex = digest;
        let identity = org_manifest_identity(&publication, "org:grant_revoked:e1").unwrap();
        assert_eq!(identity.aggregate_type, "ORG_SCOPE");
        assert_eq!(identity.aggregate_id, 7);
        assert_eq!(identity.generation, 4);
        assert_eq!(identity.revoke_fence, 1);
        assert_eq!(identity.event_id, "org:grant_revoked:e1");
        assert_eq!(identity.operation_id, "op-seal");
        // The recomputed dependency hash is the canonical dependency digest.
        assert_eq!(
            identity.dependency_hash_hex,
            org_dependency_digest_hex(&publication.dependencies).unwrap()
        );
        // A tampered sealed manifest digest cannot produce an identity.
        let mut forged = publication.clone();
        forged.manifest_digest_hex = "ab".repeat(32);
        assert!(org_manifest_identity(&forged, "e").is_err());
    }

    #[test]
    fn semantic_hash_binds_segment_bytes_and_order() {
        let mut publication = sealed_publication();
        assert_eq!(
            org_semantic_hash_hex(&publication),
            org_semantic_hash_hex(&publication)
        );
        let mut with_segment = publication.clone();
        with_segment.segments = vec![astral_types::org_scope::OrgSegment {
            index: 0,
            digest_hex: "cd".repeat(32),
            content: serde_json::json!({
                "key": { "resource": "doc", "action": "read" },
                "contributions": []
            }),
        }];
        assert_ne!(
            org_semantic_hash_hex(&publication),
            org_semantic_hash_hex(&with_segment)
        );
        let mut reordered = with_segment.clone();
        reordered.segments[0].digest_hex = "ef".repeat(32);
        assert_ne!(
            org_semantic_hash_hex(&with_segment),
            org_semantic_hash_hex(&reordered)
        );
        publication.segments = with_segment.segments;
    }

    #[test]
    fn baseline_step_requires_unchanged_or_single_next_generation() {
        assert!(baseline_step_error(true, 4, 4).is_none());
        assert!(baseline_step_error(true, 4, 5).is_some());
        assert!(baseline_step_error(false, 4, 5).is_none());
        assert!(baseline_step_error(false, 4, 4).is_some());
        assert!(baseline_step_error(false, 4, 6).is_some());
        assert!(baseline_step_error(false, u64::MAX, u64::MAX).is_some());
    }

    fn membership_receipt(before_absent: bool) -> OrgMembershipCreateReceiptEvidence {
        OrgMembershipCreateReceiptEvidence {
            tenant_id: 7,
            root_tenant_id: 1,
            user_id: 23,
            identity_card_id: 31,
            card_id: 17,
            membership_id: "22222222-2222-4222-8222-222222222222".into(),
            operation_id: "op-1".into(),
            before_absent,
            insert_rows_affected: 1,
            audit: crate::org_scope_repository::OrgSourceAuditReceiptEvidence {
                audit_id: 9,
                tenant_id: 7,
                action: "MEMBERSHIP_CREATE".into(),
                subject_kind: "MEMBERSHIP".into(),
                subject_id: "22222222-2222-4222-8222-222222222222".into(),
                request_id: None,
            },
        }
    }

    fn first_membership(
        scope: &AuthorityOrgScope,
        _publication: &OrgPublication,
        before_absent: bool,
    ) -> OrgMembership {
        OrgMembership {
            membership_id: "22222222-2222-4222-8222-222222222222".into(),
            tenant_id: 7,
            root_tenant_id: 1,
            user_id: scope.member.user_id,
            identity_card_id: scope.member.identity_card_id,
            card_id: scope.member.card_id,
            revision: 1,
            active: true,
            validity: astral_types::ValidityWindow::perpetual(),
            operation_id: if before_absent {
                "op-1".into()
            } else {
                "other-op".into()
            },
        }
    }

    #[test]
    fn first_membership_requires_actual_insert_and_empty_sealed_baseline() {
        let scope = AuthorityOrgScope {
            tenant_id: 7,
            root_tenant_id: Some(1),
            member: AuthorityOrgMemberSubject {
                user_id: 23,
                identity_card_id: 31,
                card_id: 17,
            },
        };
        let mut publication = sealed_publication();
        publication.tenant_id = 7;
        publication.root_tenant_id = 1;
        publication.generation = 1;
        publication.relationship_revision = 1;
        publication.revoke_fence = 0;
        publication.dependencies.clear();
        publication.operation_id = "op-bootstrap".into();
        publication.segments.clear();
        publication.manifest_digest_hex = org_manifest_digest_hex(&OrgManifestDigestMaterial {
            tenant_id: publication.tenant_id,
            root_tenant_id: publication.root_tenant_id,
            generation: publication.generation,
            relationship_revision: publication.relationship_revision,
            revoke_fence: publication.revoke_fence,
            dependencies: &publication.dependencies,
            segments: &publication.segments,
            compiler_version: &publication.compiler_version,
            operation_id: &publication.operation_id,
        })
        .unwrap();

        assert!(validate_first_membership_scope(
            &scope,
            &first_membership(&scope, &publication, true),
            &publication,
            &membership_receipt(true),
        )
        .is_ok());
        assert!(
            validate_first_membership_scope(
                &scope,
                &first_membership(&scope, &publication, false),
                &publication,
                &membership_receipt(false),
            )
            .is_err(),
            "historical tuple must not inherit the first-scope exception"
        );

        let mut nonempty = publication.clone();
        nonempty.segments.push(astral_types::org_scope::OrgSegment {
            index: 0,
            digest_hex: "aa".repeat(32),
            content: serde_json::json!({}),
        });
        assert!(
            validate_first_membership_scope(
                &scope,
                &first_membership(&scope, &publication, true),
                &nonempty,
                &membership_receipt(true),
            )
            .is_err(),
            "first scope requires an empty segment vector"
        );
        assert!(
            validate_first_membership_scope(
                &scope,
                &first_membership(&scope, &publication, true),
                &publication,
                &membership_receipt(false),
            )
            .is_err(),
            "first scope requires tuple absence before INSERT"
        );
    }

    #[test]
    fn first_membership_requires_historical_publication_operation() {
        let mut publication = sealed_publication();
        publication.operation_id = "op-bootstrap".into();
        let receipt = membership_receipt(true);
        assert!(first_membership_baseline_error(&publication, &receipt).is_none());
        publication.operation_id = receipt.operation_id.clone();
        assert!(first_membership_baseline_error(&publication, &receipt).is_some());
    }

    #[test]
    fn membership_source_freshness_rejects_stale_node_and_wrong_membership_version() {
        let context = |node_generation,
                       membership_revision,
                       membership_operation_id,
                       publication_operation_id| {
            MembershipSourceFreshnessContext {
                node_generation,
                publication_generation: 1,
                node_revoke_fence: 0,
                publication_revoke_fence: 0,
                node_relationship_revision: 1,
                publication_relationship_revision: 1,
                publication_operation_id,
                membership_id: "membership-1",
                fact_membership_id: "membership-1",
                membership_revision,
                fact_revision: 1,
                membership_operation_id,
                evidence_operation_id: "op-membership",
            }
        };
        assert!(
            membership_source_freshness_error(&context(1, 1, "op-membership", "op-bootstrap"))
                .is_none()
        );
        assert!(
            membership_source_freshness_error(&context(2, 1, "op-membership", "op-bootstrap"))
                .is_some()
        );
        assert!(
            membership_source_freshness_error(&context(1, 2, "op-membership", "op-bootstrap"))
                .is_some()
        );
        assert!(
            membership_source_freshness_error(&context(1, 1, "op-old", "op-bootstrap")).is_some()
        );
        assert!(membership_source_freshness_error(&context(
            1,
            1,
            "op-membership",
            "op-membership"
        ))
        .is_some());
    }

    #[test]
    fn primary_receipt_requires_exactly_one_publication_driver() {
        let receipt = OrgSourceOutboxReceiptEvidence {
            org_event_id: 1,
            event_id: "org:grant_revoked:e1".to_owned(),
            event_kind: "GRANT_REVOKED".to_owned(),
            tenant_id: 7,
        };
        let propagate = OrgSourceOutboxReceiptEvidence {
            org_event_id: 2,
            event_id: "org:dependency_propagate:e2".to_owned(),
            event_kind: "DEPENDENCY_PROPAGATE".to_owned(),
            tenant_id: 7,
        };
        let evidence = OrgSourceOutcomeEvidenceV1 {
            marker: crate::org_scope_repository::org_authority_capture::ORG_SOURCE_EVIDENCE_MARKER
                .to_owned(),
            operation_id: "op-1".to_owned(),
            facts: Vec::new(),
            outbox: vec![propagate.clone(), receipt.clone()],
            audits: vec![crate::org_scope_repository::OrgSourceAuditReceiptEvidence {
                audit_id: 1,
                tenant_id: 7,
                action: "GRANT_REVOKE".into(),
                subject_kind: "GRANT".into(),
                subject_id: "grant-1".into(),
                request_id: None,
            }],
            membership_create_receipt: None,
            before_digest_hex: "aa".repeat(32),
            after_digest_hex: "bb".repeat(32),
            commit_digest_hex: "cc".repeat(32),
        };
        assert_eq!(primary_receipt(&evidence).unwrap().org_event_id, 1);
        let only_propagate = OrgSourceOutcomeEvidenceV1 {
            outbox: vec![propagate],
            ..evidence.clone()
        };
        assert!(primary_receipt(&only_propagate).is_err());
        let two_drivers = OrgSourceOutcomeEvidenceV1 {
            outbox: vec![receipt.clone(), receipt],
            ..evidence
        };
        assert!(primary_receipt(&two_drivers).is_err());
    }

    /// The ORG candidate never decodes the card delta evidence and never
    /// imports an authorization snapshot as a content identity.
    #[test]
    fn org_candidate_is_delta_free_and_snapshot_free() {
        let source = include_str!("org.rs");
        let delta_type = format!("Delta{}Evidence", "SourceOutcome");
        let snapshot_type = format!("Authorization{}Proof", "Fence");
        assert!(!source.contains(&delta_type));
        assert!(!source.contains(&snapshot_type));
        let snapshot_hash_call = format!("{}::evidence_content_hash", snapshot_type);
        assert!(!source.contains(&snapshot_hash_call));
        assert!(source.contains("org_authority_evidence_hash"));
        // Every retained receipt is re-verified before any current-state read.
        let verify = source.find("async fn verify_fact_receipt_in_tx").unwrap();
        let load_state = source
            .find("let publication = load_sealed_publication_in_tx")
            .unwrap();
        assert!(verify < load_state);
        let verify_outbox = source.find("async fn verify_outbox_receipt_in_tx").unwrap();
        assert!(verify_outbox < load_state);
    }
}
