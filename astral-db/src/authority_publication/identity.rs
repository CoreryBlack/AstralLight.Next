//! Identity (astral-identity) source outcome publication candidates.
//!
//! Everything here is built ONLY from the typed staged artifact the Identity
//! source owner serialized inside its approved source transaction
//! (`astral-identity::srv::source_writer_guard::IdentitySourceOutcome::finalize`
//! ⇄ [`IdentityStagedEvidence`], one shared serde contract — these are the only
//! registered cross-crate DTOs of this module) plus exact durable reads.
//! Nothing is derived from an actor authorization snapshot and no consumer ACK
//! is ever guessed:
//!
//! - CARD delta routes (`create_user_card` / `update_user_card` rebind): the
//!   artifact binds the REAL `DeltaSourceOutcomeEvidence` captured in the
//!   source transaction over the actual grant revisions. Publication
//!   additionally requires the complete WorkerOwned completion chain, the
//!   captured-batch equality, and the strict published card bundle. FIRST
//!   PUBLICATION of a newly created card is provable without a baseline: the
//!   artifact's real before-Absent probe for the new card plus a delta batch
//!   that chains from base version 0 — exactly the approved source
//!   transaction's own proof of an empty baseline, never a self-signed read of
//!   the current DB.
//! - ELIGIBILITY outcomes (user/org status + delete, card status, echoes):
//!   DELTA-ONLY gating — no candidate is ever built by reusing an existing
//!   certificate's issuance. Without a captured delta the row is explicitly
//!   PENDING; the durable reconciliation of those outcomes lives in
//!   [`reconcile_identity_eligibility_outcome_in_tx`], the standalone hook the
//!   dedicated eligibility completion protocol will consume.

use super::*;

const IDENTITY_OUTCOME_DOMAIN: &[u8] = b"ASTRAL_IDENTITY_SOURCE_OUTCOME_V7\0";

/// Exact shared before/after image digests for the retained Identity target
/// sequence. This preserves source-outcome framing so eligibility verification
/// cannot drift from the staging writer.
pub fn identity_image_digests(
    targets: &[IdentityTargetImage],
) -> Result<(String, String), PolicyError> {
    fn image(
        kind: &'static str,
        targets: &[IdentityTargetImage],
        before: bool,
    ) -> Result<String, PolicyError> {
        use sha2::{Digest, Sha256};
        let mut bytes = Vec::new();
        bytes.extend_from_slice(IDENTITY_OUTCOME_DOMAIN);
        bytes.extend_from_slice(kind.as_bytes());
        bytes.push(0);
        for target in targets {
            let side = if before {
                &target.before
            } else {
                &target.after
            };
            let part = identity_target_image_bytes(kind, target, side)?;
            bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
            bytes.extend_from_slice(&part);
        }
        Ok(hex::encode(Sha256::digest(&bytes)))
    }
    Ok((
        image("BEFORE", targets, true)?,
        image("AFTER", targets, false)?,
    ))
}

fn identity_target_image_bytes(
    kind: &'static str,
    target: &IdentityTargetImage,
    side: &IdentityPresence,
) -> Result<Vec<u8>, PolicyError> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(IDENTITY_OUTCOME_DOMAIN);
    for part in [kind, target.entity.as_str()] {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part.as_bytes());
    }
    let key = serde_json::to_string(&target.key)
        .map_err(|error| pending(format!("identity image key encoding failed: {error}")))?;
    bytes.extend_from_slice(&(key.len() as u64).to_be_bytes());
    bytes.extend_from_slice(key.as_bytes());
    match side {
        IdentityPresence::Absent => bytes.extend_from_slice(b"ABSENT"),
        IdentityPresence::Present(value) => {
            let value = serde_json::to_string(value).map_err(|error| {
                pending(format!("identity image value encoding failed: {error}"))
            })?;
            bytes.extend_from_slice(value.as_bytes());
        }
    }
    Ok(bytes)
}

// ─────────────────────────────────────────────────────────────────────────────
// Registered shared staged DTO (the single serde contract with the Identity
// source owner; `pub` for cross-crate consumption, construction happens
// through serde on both sides — no public builder surface).
// ─────────────────────────────────────────────────────────────────────────────

/// Shared staged artifact DTO for Identity source outcomes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityStagedEvidence {
    pub targets: Vec<IdentityTargetImage>,
    pub receipts: Vec<IdentityReceipt>,
    /// Per-path fanout totals (e.g. `eligibilityEvents`, `ruleSetRefs`) plus
    /// the mandatory `affectedCards` set recorded inside the source tx.
    #[serde(default)]
    pub fanout: serde_json::Value,
    /// The REAL `DeltaSourceOutcomeEvidence` captured inside the approved
    /// source transaction over the actual grant revisions (card delta routes).
    /// `None` ⇒ no canonical delta exists for this mutation (delta-only gating
    /// keeps the outcome PENDING); a fabricated delta never enters this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta: Option<DeltaSourceOutcomeEvidence>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityTargetImage {
    pub entity: String,
    pub key: serde_json::Value,
    pub before: IdentityPresence,
    pub after: IdentityPresence,
}

/// One side of a real target-row probe: `absent` is a genuine probe result
/// (create/delete truth), never a placeholder.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityPresence {
    Absent,
    Present(serde_json::Value),
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityReceipt {
    pub entity: String,
    pub key: serde_json::Value,
    /// `astral_db::WriteKind::as_text()` (`INSERT`/`UPDATE`/`DELETE`/`PROBE`).
    pub kind: String,
    pub rows_affected: u64,
    /// The exact durable id (PK value / event id / message id).
    pub durable_id: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityAffectedCard {
    pub card_id: i64,
    pub tenant_id: Option<i64>,
}

impl IdentityStagedEvidence {
    /// The complete affected card owner set declared by the source transaction.
    pub fn affected_cards(&self) -> Result<Vec<IdentityAffectedCard>, PolicyError> {
        let cards = self
            .fanout
            .get("affectedCards")
            .ok_or_else(|| pending("identity staged artifact declares no affected card set"))?;
        serde_json::from_value(cards.clone())
            .map_err(|error| pending(format!("identity affected card set is malformed: {error}")))
    }

    fn target_probe(
        &self,
        entity: &str,
        key_field: &str,
        card_id: i64,
    ) -> Option<&IdentityTargetImage> {
        self.targets.iter().find(|target| {
            target.entity == entity
                && target
                    .key
                    .get(key_field)
                    .and_then(|value| value.as_i64())
                    .is_some_and(|value| value == card_id)
        })
    }

    pub(super) fn proves_new_card_insert(
        &self,
        card: &astral_types::AuthorizationAuthorityScope,
    ) -> bool {
        self.target_probe("user_card", "cardId", card.card_id)
            .is_some_and(|probe| {
                matches!(probe.before, IdentityPresence::Absent)
                    && matches!(&probe.after, IdentityPresence::Present(after)
                        if after.get("cardId").and_then(serde_json::Value::as_i64) == Some(card.card_id)
                            && after.get("tenantId").and_then(serde_json::Value::as_i64) == Some(card.tenant_id))
                    && self.receipts.iter().any(|receipt| {
                        receipt.entity == "user_card"
                            && receipt.kind.eq_ignore_ascii_case("insert")
                            && receipt.rows_affected == 1
                            && receipt.durable_id == card.card_id.to_string()
                            && receipt.key.get("cardId").and_then(serde_json::Value::as_i64)
                                == Some(card.card_id)
                    })
            })
    }

    fn receipt_count(&self, entity: &str) -> usize {
        self.receipts
            .iter()
            .filter(|receipt| receipt.entity == entity)
            .count()
    }
}

/// 纯谓词：一个真实 delta append request 是否属于本卡 scope。有意义负例：
/// 异租户、异卡、`None` card_id（非卡归属的 delta 不能进入卡 scope 认证）。
fn delta_request_belongs_to_card_scope(
    request_tenant_id: i64,
    request_card_id: Option<i64>,
    card: &astral_types::AuthorizationAuthorityScope,
) -> bool {
    request_tenant_id == card.tenant_id
        && request_card_id.is_some_and(|request_card| request_card == card.card_id)
}

/// Identity publication entry point. Dispatched by
/// `super::load_source_candidate_in_tx` for staged artifacts that carry real
/// target probes instead of a bare trustgraph delta batch.
pub(super) async fn load_identity_candidate_in_tx(
    tx: &mut Transaction<'_, MySql>,
    scope: &AuthorityProtocolScope,
    staged: &serde_json::Value,
    baseline: Option<&AuthorityScopePublicationCertificate>,
    empty_card_origin: Option<&VerifiedEmptyCardOrigin>,
) -> Result<AuthorityPublicationCandidate, PolicyError> {
    let AuthorityProtocolScope::Card(card) = scope else {
        return Err(pending("identity publication requires a card scope"));
    };
    let artifact: IdentityStagedEvidence =
        serde_json::from_value(staged.clone()).map_err(pending)?;
    let affected = artifact.affected_cards()?;
    if !affected
        .iter()
        .any(|entry| entry.card_id == card.card_id && entry.tenant_id == Some(card.tenant_id))
    {
        return Err(pending(
            "published scope is outside the declared affected card set",
        ));
    }
    // DELTA-ONLY gating: the artifact must bind the REAL in-transaction delta
    // proof. An absent/empty batch is an explicit PENDING — no candidate is
    // ever built by reusing an existing certificate's issuance; the durable
    // reconciliation of eligibility-only outcomes is delegated to
    // reconcile_identity_eligibility_outcome_in_tx (the future completion
    // protocol's hook) and fails closed here.
    match artifact.delta.as_ref() {
        Some(delta) if !delta.events.is_empty() => {
            load_identity_delta_candidate_in_tx(
                tx,
                scope,
                &artifact,
                delta,
                baseline,
                empty_card_origin,
            )
            .await
        }
        _ => {
            reconcile_identity_eligibility_outcome_in_tx(tx, scope, &artifact).await?;
            Err(pending(
                "identity eligibility-only outcome awaits its dedicated completion protocol; \
                 no publication candidate is built without a canonical delta",
            ))
        }
    }
}

/// Card delta route: exact WorkerOwned completion chain + captured-batch
/// equality + strict published card bundle, with first-publication support.
///
/// With a baseline the parent `validate_transition` enforces the certified
/// prior state. WITHOUT a baseline (first publication of a newly created card)
/// the artifact must prove the empty baseline itself: a real before-Absent
/// probe for the scope card plus an `insert` receipt, and every changed
/// aggregate must chain from generation 0 through approved completions that
/// end exactly at the current manifest.
async fn load_identity_delta_candidate_in_tx(
    tx: &mut Transaction<'_, MySql>,
    scope: &AuthorityProtocolScope,
    artifact: &IdentityStagedEvidence,
    delta: &DeltaSourceOutcomeEvidence,
    baseline: Option<&AuthorityScopePublicationCertificate>,
    empty_card_origin: Option<&VerifiedEmptyCardOrigin>,
) -> Result<AuthorityPublicationCandidate, PolicyError> {
    let AuthorityProtocolScope::Card(card) = scope else {
        return Err(pending("not a card scope"));
    };
    // The declared scope's card write must be the artifact's real probe pair,
    // and the after image must DECLARE this scope's exact card/tenant identity
    // (the source outcome digest binds the bytes; the candidate verifies the
    // declared values against the scope it is about to certify).
    let probe = artifact
        .target_probe("user_card", "cardId", card.card_id)
        .ok_or_else(|| pending("identity delta publication lacks the real card target probe"))?;
    if let IdentityPresence::Present(after) = &probe.after {
        let after_card = after.get("cardId").and_then(|value| value.as_i64());
        let after_tenant = after.get("tenantId").and_then(|value| value.as_i64());
        if after_card != Some(card.card_id) || after_tenant != Some(card.tenant_id) {
            return Err(pending(
                "the card after image does not declare the certified card identity",
            ));
        }
    }
    match baseline {
        None => {
            // A newly created card proves its own empty baseline with the
            // before-Absent INSERT probe. A pre-existing empty card reaching
            // its first grant must instead carry a freshly reconciled origin.
            if !matches!(probe.before, IdentityPresence::Absent)
                && !empty_card_origin
                    .is_some_and(|origin| origin.proves(card.tenant_id, card.card_id))
            {
                return Err(pending(
                    "first grant publication requires a freshly reconciled empty-card origin",
                ));
            }
            // First publication: a newly created card proves an empty baseline
            // with the approved before-Absent INSERT. An existing empty card
            // proves the same base-0 chain with the reconciled origin token.
            if !matches!(probe.after, IdentityPresence::Present(_)) {
                return Err(pending(
                    "first card publication requires an after-present card probe",
                ));
            }
            if matches!(probe.before, IdentityPresence::Absent)
                && !artifact.receipts.iter().any(|receipt| {
                    receipt.entity == "user_card"
                        && receipt.kind.eq_ignore_ascii_case("insert")
                        && receipt.rows_affected == 1
                        && receipt.durable_id == card.card_id.to_string()
                        && receipt.key.get("cardId").and_then(|value| value.as_i64())
                            == Some(card.card_id)
                })
            {
                return Err(pending(
                    "first card publication requires the actual user_card insert receipt bound to this card",
                ));
            }
        }
        Some(cert) => {
            if &cert.scope != scope {
                return Err(pending("baseline scope differs"));
            }
            if !matches!(probe.before, IdentityPresence::Present(_))
                || !matches!(probe.after, IdentityPresence::Present(_))
            {
                return Err(pending(
                    "card delta publication requires real before/after row probes",
                ));
            }
        }
    }
    // CardCreate has an independent finite RuleSet binding artifact. Its
    // verifier re-reads the exact typed aggregate, projections, audits, refs,
    // and ADD rows under this publication transaction's locks.
    super::verify_card_create_bindings_in_tx(tx, artifact).await?;
    // Lane -> pointer -> delta is the existing WorkerOwned completion lock order.
    let mut requests = crate::grant_repository::load_source_receipts_in_tx(tx, delta)
        .await
        .map_err(pending)?;
    requests.sort_by(|a, b| {
        (a.tenant_id, &a.aggregate_type, a.aggregate_id, &a.event_id).cmp(&(
            b.tenant_id,
            &b.aggregate_type,
            b.aggregate_id,
            &b.event_id,
        ))
    });
    let mut completed = Vec::with_capacity(requests.len());
    for request in &requests {
        if !delta_request_belongs_to_card_scope(request.tenant_id, request.card_id, card) {
            return Err(pending(
                "the captured delta batch belongs to another card scope",
            ));
        }
        let Some(proof) = crate::projection_execution::completion_in_tx(tx, request)
            .await
            .map_err(pending)?
        else {
            return Err(pending(
                "an exact approved receipt has no durable WorkerOwned completion",
            ));
        };
        completed.push((request, proof));
    }
    if crate::capture_delta_source_outcome_in_tx(tx, &requests)
        .await
        .map_err(pending)?
        != *delta
    {
        return Err(pending(
            "actual source revisions differ from the approved batch",
        ));
    }
    let evidence_scope = astral_types::PublishedCardEvidenceScope {
        tenant_id: card.tenant_id,
        card_id: card.card_id,
        user_filter: card.user_id,
        domain: match card.domain {
            astral_types::AuthorizationDomainScope::Any => {
                astral_types::DomainScopeRequirement::Unconstrained
            }
            astral_types::AuthorizationDomainScope::NoDomain => {
                astral_types::DomainScopeRequirement::ExactlyNone
            }
            astral_types::AuthorizationDomainScope::Exact(id) => {
                astral_types::DomainScopeRequirement::ExactlySome(id)
            }
        },
    };
    let bundle =
        crate::authorization_projection_repository::load_published_card_state_bundle_in_tx(
            tx,
            &evidence_scope,
        )
        .await
        .map_err(pending)?;
    let now: i64 = sqlx::query_scalar("SELECT CAST(UNIX_TIMESTAMP() AS SIGNED)")
        .fetch_one(&mut **tx)
        .await
        .map_err(pending)?;
    let evidence = bundle.evidence_at(now).map_err(pending)?;
    let manifests = match baseline {
        Some(cert) => super::validate_transition(scope, &evidence, Some(cert), &completed)?,
        None => validate_first_publication(scope, &evidence, &completed)?,
    };
    Ok(AuthorityPublicationCandidate {
        scope: scope.clone(),
        manifests,
        snapshot_hash: AuthorizationFenceProof::evidence_content_hash(&evidence)
            .map_err(pending)?,
        parent_certificate_hash: baseline
            .map(AuthorityScopePublicationCertificate::record_digest)
            .transpose()
            .map_err(pending)?,
    })
}

/// First-publication transition: no baseline exists, so every current manifest
/// must be the exact final approved completion of a chain that starts at
/// generation 0 (base-version-0 deltas of the approved source transaction) —
/// the empty-baseline proof, never a self-signed current read.
fn validate_first_publication(
    scope: &AuthorityProtocolScope,
    evidence: &PublishedCardAuthorization,
    completed: &[(&DeltaEventAppendRequest, crate::OwnedDeltaCompletionProof)],
) -> Result<Vec<AuthorityManifestIdentity>, PolicyError> {
    scope.validate().map_err(pending)?;
    evidence.validate().map_err(pending)?;
    let AuthorityProtocolScope::Card(card) = scope else {
        return Err(pending("not a card scope"));
    };
    if card.tenant_id != evidence.tenant_id || card.card_id != evidence.card_id {
        return Err(pending(
            "published scope differs from the declared affected scope",
        ));
    }
    if evidence.manifests.is_empty() {
        return Err(pending(
            "first publication requires at least one approved manifest; a card without \
             materialized grants has no publishable content",
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut current = Vec::with_capacity(evidence.manifests.len());
    for summary in &evidence.manifests {
        let identity = manifest_identity(summary);
        identity.validate().map_err(pending)?;
        let key = (identity.aggregate_type.clone(), identity.aggregate_id);
        if !seen.insert(key) {
            return Err(pending("duplicate current aggregate"));
        }
        let mut chain: Vec<_> = completed
            .iter()
            .filter(|(request, _)| {
                request.tenant_id == card.tenant_id
                    && request.aggregate_type == identity.aggregate_type
                    && request.aggregate_id == identity.aggregate_id
            })
            .collect();
        chain.sort_by_key(|(_, proof)| proof.generation());
        let mut generation = 0u64;
        let mut revoke_fence = 0u64;
        let mut parent_digest: Option<String> = None;
        if chain.is_empty() {
            return Err(pending("unapproved aggregate publication"));
        }
        for (_, proof) in &chain {
            generation = generation
                .checked_add(1)
                .ok_or_else(|| pending("generation overflow"))?;
            if proof.generation() != generation
                || !proof.extends_manifest(parent_digest.as_deref(), revoke_fence)
            {
                return Err(pending(
                    "publication chain skips an approved parent or retracts a revoke fence",
                ));
            }
            revoke_fence = proof.revoke_fence();
            parent_digest = Some(proof.manifest_digest_hex());
        }
        if !chain
            .last()
            .is_some_and(|(_, proof)| proof.matches_manifest(summary))
        {
            return Err(pending(
                "current manifest is not the exact final approved completion",
            ));
        }
        current.push(identity);
    }
    Ok(current)
}

/// 资格 outcome 的 durable 对账（独立 helper，待新 Completion 协议接续）：
/// 核 exact immutable before/after 目标探针、同事务审计 receipt、以及按
/// operation id 的**完整** durable ELIGIBILITY typed intent 集合（绝不猜测
/// consumer ACK），并确认当前 strict DB 资格读门可加载且通过既有校验。
/// 本 helper 只做对账，绝不构造 publication candidate、绝不复用任何已签发
/// 证书；closure 语义由专用 Completion 协议接手。
async fn reconcile_identity_eligibility_outcome_in_tx(
    tx: &mut Transaction<'_, MySql>,
    scope: &AuthorityProtocolScope,
    artifact: &IdentityStagedEvidence,
) -> Result<(), PolicyError> {
    let AuthorityProtocolScope::Card(card) = scope else {
        return Err(pending("not a card scope"));
    };
    // Exact immutable before/after probes for every declared target row; the
    // user_card target (when present) must be this scope's card and its after
    // image must declare this scope's exact card/tenant identity.
    for target in &artifact.targets {
        if target.entity == "user_card" {
            let probe_card_id = target
                .key
                .get("cardId")
                .and_then(|value| value.as_i64())
                .ok_or_else(|| pending("user_card probe key is malformed"))?;
            if probe_card_id != card.card_id {
                return Err(pending("user_card probe belongs to another card scope"));
            }
            if let IdentityPresence::Present(after) = &target.after {
                let after_card = after.get("cardId").and_then(|value| value.as_i64());
                let after_tenant = after.get("tenantId").and_then(|value| value.as_i64());
                if after_card != Some(card.card_id) || after_tenant != Some(card.tenant_id) {
                    return Err(pending(
                        "the card after image does not declare the certified card identity",
                    ));
                }
            }
        }
    }
    if artifact.receipt_count("audit_log") == 0 {
        return Err(pending(
            "eligibility reconciliation requires the in-transaction audit receipt",
        ));
    }
    // Complete durable ELIGIBILITY receipts by operation id: every declared
    // eligibility event must exist as a typed intent row on the durable outbox
    // (the message ids ARE the projection event ids). The receipt window
    // included in the artifact must be a subset of those durable rows.
    let eligibility_events = artifact
        .fanout
        .get("eligibilityEvents")
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    if eligibility_events > 0 {
        let operation_id = artifact
            .receipts
            .iter()
            .find(|receipt| receipt.entity == "al_message_outbox")
            .and_then(|receipt| receipt.key.get("operationId"))
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                pending("eligibility reconciliation declares no typed intent receipts")
            })?;
        let durable_intents: Vec<(String, String)> = sqlx::query_as(
            "SELECT message_id, operation_id FROM al_message_outbox \
             WHERE operation_id = ? ORDER BY message_id FOR UPDATE",
        )
        .bind(operation_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(|error| pending(format!("durable eligibility receipt read failed: {error}")))?;
        if durable_intents.len() as u64 != eligibility_events {
            return Err(pending(
                "declared eligibility fanout differs from the durable typed intent set",
            ));
        }
        for receipt in artifact
            .receipts
            .iter()
            .filter(|receipt| receipt.entity == "al_message_outbox")
        {
            if !durable_intents
                .iter()
                .any(|(message_id, stored_operation)| {
                    message_id == &receipt.durable_id && stored_operation == operation_id
                })
            {
                return Err(pending(
                    "an included eligibility receipt is missing its durable row",
                ));
            }
        }
    }
    // 当前 strict DB 资格读门：bundle 必须可加载并通过既有校验（ELIGIBILITY
    // head 防 stale 的语义由既有 strict 读面承担，这里只证明读门可用）。
    let evidence_scope = astral_types::PublishedCardEvidenceScope {
        tenant_id: card.tenant_id,
        card_id: card.card_id,
        user_filter: card.user_id,
        domain: match card.domain {
            astral_types::AuthorizationDomainScope::Any => {
                astral_types::DomainScopeRequirement::Unconstrained
            }
            astral_types::AuthorizationDomainScope::NoDomain => {
                astral_types::DomainScopeRequirement::ExactlyNone
            }
            astral_types::AuthorizationDomainScope::Exact(id) => {
                astral_types::DomainScopeRequirement::ExactlySome(id)
            }
        },
    };
    let bundle =
        crate::authorization_projection_repository::load_published_card_state_bundle_in_tx(
            tx,
            &evidence_scope,
        )
        .await
        .map_err(pending)?;
    let now: i64 = sqlx::query_scalar("SELECT CAST(UNIX_TIMESTAMP() AS SIGNED)")
        .fetch_one(&mut **tx)
        .await
        .map_err(pending)?;
    let evidence = bundle.evidence_at(now).map_err(pending)?;
    evidence.validate().map_err(pending)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 卡 scope 归属纯谓词：同租户同卡放行；异租户、异卡、None card_id 一律
    /// 拒绝（None 是非卡归属 delta，不能进入卡 scope 认证）。
    #[test]
    fn delta_scope_predicate_accepts_only_the_exact_card() {
        let card = astral_types::AuthorizationAuthorityScope {
            tenant_id: 3,
            card_id: 7,
            user_id: Some(5),
            domain: astral_types::AuthorizationDomainScope::Exact(4),
        };
        assert!(delta_request_belongs_to_card_scope(3, Some(7), &card));
        assert!(
            !delta_request_belongs_to_card_scope(9, Some(7), &card),
            "a different tenant never belongs to this card scope"
        );
        assert!(
            !delta_request_belongs_to_card_scope(3, Some(8), &card),
            "a different card never belongs to this card scope"
        );
        assert!(
            !delta_request_belongs_to_card_scope(3, None, &card),
            "a non-card-owned delta cannot enter a card scope certification"
        );
    }

    #[test]
    fn new_card_insert_requires_the_exact_before_after_and_statement() {
        let card = astral_types::AuthorizationAuthorityScope {
            tenant_id: 3,
            card_id: 7,
            user_id: None,
            domain: astral_types::AuthorizationDomainScope::Any,
        };
        let artifact = IdentityStagedEvidence {
            targets: vec![IdentityTargetImage {
                entity: "user_card".into(),
                key: serde_json::json!({"cardId": 7}),
                before: IdentityPresence::Absent,
                after: IdentityPresence::Present(serde_json::json!({"cardId": 7, "tenantId": 3})),
            }],
            receipts: vec![IdentityReceipt {
                entity: "user_card".into(),
                key: serde_json::json!({"cardId": 7}),
                kind: "INSERT".into(),
                rows_affected: 1,
                durable_id: "7".into(),
            }],
            fanout: serde_json::json!({}),
            delta: None,
        };
        assert!(artifact.proves_new_card_insert(&card));
        let mut changed = artifact.clone();
        changed.targets[0].before = IdentityPresence::Present(serde_json::json!({"cardId": 7}));
        assert!(!changed.proves_new_card_insert(&card));
        let mut changed = artifact.clone();
        changed.targets[0].after = IdentityPresence::Absent;
        assert!(!changed.proves_new_card_insert(&card));
        for (field, value) in [("cardId", 8), ("tenantId", 4)] {
            let mut changed = artifact.clone();
            let IdentityPresence::Present(after) = &mut changed.targets[0].after else {
                unreachable!()
            };
            after[field] = serde_json::json!(value);
            assert!(!changed.proves_new_card_insert(&card));
        }
        let mut changed = artifact.clone();
        changed.receipts[0].kind = "UPDATE".into();
        assert!(!changed.proves_new_card_insert(&card));
        let mut changed = artifact.clone();
        changed.receipts[0].rows_affected = 0;
        assert!(!changed.proves_new_card_insert(&card));
        let mut changed = artifact.clone();
        changed.receipts[0].durable_id = "8".into();
        assert!(!changed.proves_new_card_insert(&card));
        let mut changed = artifact;
        changed.receipts[0].key = serde_json::json!({"cardId": 8});
        assert!(!changed.proves_new_card_insert(&card));
    }

    /// 共享 DTO 契约钉：targets/receipts/delta 之外不允许未知字段；presence
    /// 的 absent 是字符串真值、present 携带真实行镜像（JSON 透传）。
    #[test]
    fn shared_dto_shape_is_exact() {
        let artifact = IdentityStagedEvidence {
            targets: vec![IdentityTargetImage {
                entity: "user_card".into(),
                key: serde_json::json!({ "cardId": 7 }),
                before: IdentityPresence::Absent,
                after: IdentityPresence::Present(serde_json::json!({ "cardId": 7 })),
            }],
            receipts: vec![IdentityReceipt {
                entity: "user_card".into(),
                key: serde_json::json!({ "cardId": 7 }),
                kind: "INSERT".into(),
                rows_affected: 1,
                durable_id: "7".into(),
            }],
            fanout: serde_json::json!({
                "affectedCards": [{ "cardId": 7, "tenantId": 3 }],
            }),
            delta: None,
        };
        let serialized = serde_json::to_value(&artifact).unwrap();
        assert!(
            !serialized.as_object().unwrap().contains_key("delta"),
            "a none delta is omitted on the wire (never fabricated)"
        );
        let parsed: IdentityStagedEvidence = serde_json::from_value(serde_json::json!({
            "targets": serialized["targets"],
            "receipts": serialized["receipts"],
            "fanout": serialized["fanout"],
        }))
        .expect("delta is optional on the wire");
        assert!(parsed.delta.is_none());
        assert_eq!(parsed.affected_cards().unwrap().len(), 1);
        assert!(
            serde_json::from_value::<IdentityStagedEvidence>(serde_json::json!({
                "targets": [], "receipts": [], "fanout": {},
                "unknown": true,
            }))
            .is_err(),
            "unknown fields must be refused (deny_unknown_fields)"
        );
    }
}
