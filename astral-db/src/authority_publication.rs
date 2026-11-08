//! Certification candidates from exact source receipts and strict published evidence.
//!
//! Completion proves a historical event. A current card bundle is accepted only
//! when every changed aggregate is a contiguous chain of approved completions
//! and every unchanged aggregate retains its authority-certified identity.

use std::collections::{BTreeMap, BTreeSet};

use astral_types::{
    AuthorityCallerIdentity, AuthorityCertifyRequest, AuthorityManifestIdentity,
    AuthorityProtocolScope, AuthorityScopePublicationCertificate, AuthorityScopeReservation,
    AuthorizationFenceProof, PolicyError, PublishedCardAuthorization,
};
use sqlx::{MySql, Transaction};

use crate::authority_publication::empty_card_origin::VerifiedEmptyCardOrigin;
use crate::{DeltaEventAppendRequest, DeltaSourceOutcomeEvidence, OwnedDeltaCompletionProof};

fn pending(message: impl std::fmt::Display) -> PolicyError {
    PolicyError::Repository(format!("authority publication pending: {message}"))
}

/// Opaque candidate: only exact durable closure and a complete strict card read
/// can construct it. It is not a current authorization verdict.
pub(crate) struct AuthorityPublicationCandidate {
    scope: AuthorityProtocolScope,
    manifests: Vec<AuthorityManifestIdentity>,
    snapshot_hash: String,
    parent_certificate_hash: Option<String>,
}

fn manifest_identity(
    manifest: &astral_types::PublishedAggregateManifestSummary,
) -> AuthorityManifestIdentity {
    AuthorityManifestIdentity {
        aggregate_type: manifest.aggregate_type.clone(),
        aggregate_id: manifest.aggregate_id,
        manifest_digest_hex: manifest.manifest_digest_hex.clone(),
        dependency_hash_hex: manifest.dependency_hash_hex.clone(),
        semantic_hash_hex: manifest.semantic_hash_hex.clone(),
        generation: manifest.generation,
        revoke_fence: manifest.revoke_fence,
        event_id: manifest.event_id.clone(),
        operation_id: manifest.operation_id.clone(),
    }
}

/// No authority/network I/O occurs while these consistency locks are held.
async fn load_candidate_in_tx(
    tx: &mut Transaction<'_, MySql>,
    scope: &AuthorityProtocolScope,
    source: &DeltaSourceOutcomeEvidence,
    baseline: Option<&AuthorityScopePublicationCertificate>,
    empty_card_origin: Option<&VerifiedEmptyCardOrigin>,
) -> Result<AuthorityPublicationCandidate, PolicyError> {
    let AuthorityProtocolScope::Card(card) = scope else {
        return Err(pending(
            "ORG publication requires its own complete source owner",
        ));
    };
    if baseline.is_none()
        && !empty_card_origin.is_some_and(|origin| origin.proves(card.tenant_id, card.card_id))
    {
        return Err(pending(
            "first card publication requires a freshly reconciled empty-card origin",
        ));
    }
    let mut requests = crate::grant_repository::load_source_receipts_in_tx(tx, source)
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
    // Lane -> pointer -> delta is the existing WorkerOwned completion lock order.
    // Sort aggregates before acquiring their lanes; never lock a delta first.
    for request in &requests {
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
    // With all completion lanes held, revalidate actual revisions and deltas
    // against the complete source owner's retained batch.
    if crate::capture_delta_source_outcome_in_tx(tx, &requests)
        .await
        .map_err(pending)?
        != *source
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
    let manifests = validate_transition(scope, &evidence, baseline, &completed)?;
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

fn validate_transition(
    scope: &AuthorityProtocolScope,
    evidence: &PublishedCardAuthorization,
    baseline: Option<&AuthorityScopePublicationCertificate>,
    completed: &[(&DeltaEventAppendRequest, OwnedDeltaCompletionProof)],
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
    let baseline = baseline
        .ok_or_else(|| pending("first scope publication requires approved bootstrap evidence"))?;
    if &baseline.scope != scope {
        return Err(pending("baseline scope differs"));
    }
    let previous = baseline.manifests.as_slice();
    let mut prior = BTreeMap::new();
    for manifest in previous {
        if prior
            .insert(
                (manifest.aggregate_type.clone(), manifest.aggregate_id),
                manifest,
            )
            .is_some()
        {
            return Err(pending("duplicate baseline aggregate"));
        }
    }
    let mut current = Vec::with_capacity(evidence.manifests.len());
    let mut seen = BTreeSet::new();
    let mut changed = false;
    for summary in &evidence.manifests {
        let identity = manifest_identity(summary);
        identity.validate().map_err(pending)?;
        let key = (identity.aggregate_type.clone(), identity.aggregate_id);
        if !seen.insert((identity.aggregate_type.clone(), identity.aggregate_id)) {
            return Err(pending("duplicate current aggregate"));
        }
        let old = prior.remove(&key);
        if old != Some(&identity) {
            changed = true;
            let mut chain: Vec<_> = completed
                .iter()
                .filter(|(request, _)| {
                    request.tenant_id == card.tenant_id
                        && request.card_id.is_none_or(|id| id == card.card_id)
                        && request.aggregate_type == identity.aggregate_type
                        && request.aggregate_id == identity.aggregate_id
                })
                .collect();
            chain.sort_by_key(|(_, proof)| proof.generation());
            let mut generation = old.map_or(0, |manifest| manifest.generation);
            let mut revoke_fence = old.map_or(0, |manifest| manifest.revoke_fence);
            let mut parent_digest = old.map(|manifest| manifest.manifest_digest_hex.clone());
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
        }
        current.push(identity);
    }
    if !prior.is_empty() {
        return Err(pending("a certified aggregate disappeared"));
    }
    if !changed {
        return Err(pending("source receipts do not change the declared scope"));
    }
    Ok(current)
}

impl AuthorityPublicationCandidate {
    pub(crate) fn request(
        self,
        caller: AuthorityCallerIdentity,
        reservation: &AuthorityScopeReservation,
        source: &crate::authority_source_outcome::AuthoritySourceOutcomeRecord,
        outcome_digest: String,
        authority_id: String,
    ) -> Result<AuthorityCertifyRequest, PolicyError> {
        let after = source
            .after_image_digest
            .clone()
            .ok_or_else(|| pending("actual after image missing"))?;
        // The signer chooses record IDs/timestamps. Completion uses only the
        // immutable reservation frontier and exact source/publication bundle.
        let mut certificate = AuthorityScopePublicationCertificate {
            protocol_version: astral_types::AUTHORITY_PROTOCOL_VERSION,
            authorization_edition: astral_types::AUTHORIZATION_EDITION,
            authority_id,
            authority_term: reservation.authority_term,
            global_fence_sequence: reservation.fence_sequence_at_prepare,
            certificate_id: "candidate".into(),
            intent_digest: reservation.intent_digest.clone(),
            reservation_id: reservation.reservation_id.clone(),
            operation_id: source.operation_id.clone(),
            event_id: source.event_id.clone(),
            scope: self.scope.clone(),
            approved_request_digest: source.request_binding_digest.clone(),
            before_image_digest: source.before_image_digest.clone(),
            after_image_digest: after.clone(),
            source_commit_digest: source.source_commit_digest.clone(),
            completion_digest: "00".repeat(32),
            snapshot_hash: self.snapshot_hash.clone(),
            source_outcome_digest: outcome_digest.clone(),
            parent_certificate_hash: self.parent_certificate_hash,
            manifests: self.manifests.clone(),
            key_id: "candidate".into(),
            key_epoch: 1,
            issued_at: source.committed_at,
            not_before: source.committed_at,
            expires_at: None,
            certificate_nonce: "candidate".into(),
            signature: String::new(),
        };
        certificate.completion_digest =
            certificate.recompute_completion_digest().map_err(pending)?;
        let request = AuthorityCertifyRequest {
            caller,
            reservation_id: reservation.reservation_id.clone(),
            scope: self.scope,
            before_image_digest: source.before_image_digest.clone(),
            after_image_digest: after,
            snapshot_hash: self.snapshot_hash,
            source_outcome_digest: outcome_digest,
            manifests: self.manifests,
            completion_digest: certificate.completion_digest,
        };
        request.validate().map_err(pending)?;
        Ok(request)
    }
}

mod card_create;
pub(crate) mod empty_card_origin;
mod identity;
mod org;
mod runtime;

pub(crate) use card_create::CardCreateBindingVerifyError;
pub use card_create::{
    CardCreateRuleSetCapture, CardCreateRuleSetCaptureSpec, CardCreateRuleSetReceipt,
};

pub(crate) async fn verify_card_create_bindings_structured_in_tx(
    tx: &mut Transaction<'_, MySql>,
    artifact: &IdentityStagedEvidence,
) -> Result<(), CardCreateBindingVerifyError> {
    card_create::verify_card_create_bindings_structured_in_tx(tx, artifact).await
}

pub(crate) async fn verify_card_create_bindings_in_tx(
    tx: &mut Transaction<'_, MySql>,
    artifact: &IdentityStagedEvidence,
) -> Result<(), PolicyError> {
    verify_card_create_bindings_structured_in_tx(tx, artifact)
        .await
        .map_err(|error| match error {
            CardCreateBindingVerifyError::Pending(message) => pending(message),
            CardCreateBindingVerifyError::Database(error) => {
                PolicyError::Repository(format!("CardCreate binding database read failed: {error}"))
            }
        })
}

pub use identity::{
    identity_image_digests, IdentityAffectedCard, IdentityPresence, IdentityReceipt,
    IdentityStagedEvidence, IdentityTargetImage,
};

#[cfg(test)]
mod tests;

pub(crate) async fn persist_authority_certificate(
    pool: &sqlx::MySqlPool,
    certificate: &AuthorityScopePublicationCertificate,
) -> Result<(), PolicyError> {
    runtime::persist_authority_certificate(pool, certificate).await
}

pub(crate) use runtime::reconcile_publications;
