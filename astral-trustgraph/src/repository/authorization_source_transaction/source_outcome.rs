//! Same-transaction readback of the complete authorization source receipt batch.

use super::{InvalidationReceipt, SourceProjectionReceipt, PROJECTION_RECEIPT_CAP};
use astral_types::{
    config_source_commit_digest, AstralError, AuthorityConfigAudit,
    AuthorityConfigCompletionEvidence, AuthorityConfigCompletionKind, AuthorityConfigGateContract,
    AuthorityConfigSourceBatch, AuthorityConfigSourceImage, AuthorityMutationKind,
    AuthorityProtocolScope, AuthorizationAdmission,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{MySql, Transaction};

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceProjectionEvidence {
    outbox_id: i64,
    event_id: String,
    aggregate_type: String,
    aggregate_id: i64,
    tenant_id: Option<i64>,
    event_type: String,
    source_generation: i64,
    sequence_number: i64,
    revoke_fence: i64,
    payload: serde_json::Value,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InvalidationEvidence {
    message_id: String,
    operation_id: String,
    queue_name: String,
    envelope: astral_mq::MessageEnvelope,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SourceBatchEvidence {
    /// Present only for grant-delta owners; typed (config) owners carry real
    /// row-image receipts instead and keep this absent. The delta-row staged
    /// shape stays byte-compatible with the certification reader
    /// (`envelope.evidence.get("delta")`).
    #[serde(skip_serializing_if = "Option::is_none")]
    delta: Option<astral_db::DeltaSourceOutcomeEvidence>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    source_images: Vec<AuthorityConfigSourceImage>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    audits: Vec<AuthorityConfigAudit>,
    source_projection: Vec<SourceProjectionEvidence>,
    invalidations: Vec<InvalidationEvidence>,
}

/// Convert only the sealed opaque DB receipt into the shared config wire type.
/// The lookup is carried verbatim because it binds DELETE absence and the
/// exact aggregate/natural identity independently of the selected primary key.
fn wire_image(receipt: &astral_db::TypedSourceRowImageReceipt) -> AuthorityConfigSourceImage {
    AuthorityConfigSourceImage {
        table: receipt.table(),
        key: receipt.key(),
        lookup: receipt.lookup().to_owned(),
        operation: receipt.operation(),
        before_image_digest: receipt.before_image_digest().to_owned(),
        after_image_digest: receipt.after_image_digest().to_owned(),
        before_image: receipt.before_image().to_owned(),
        after_image: receipt.after_image().to_owned(),
    }
}

/// Exact same-transaction readback of one durable audit row; the audit
/// correlation is part of the typed source evidence, never a writer label.
fn pending(message: impl Into<String>) -> AstralError {
    AstralError::Pending(message.into())
}

fn database(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("source evidence readback failed: {error}"))
}

/// The delta revisions are the immutable canonical authorization mutation.
/// Legacy head/outbox and transport rows are additional exact correlations;
/// they never substitute for those actual grant before/after images.
/// Typed (config) owners with no grant delta supply REAL opaque row-image
/// receipts (built by the astral-db typed delegate) plus an in-transaction
/// durable audit correlation; both are read back exactly below.
pub(super) struct SourceOutcomeBatch<'a> {
    pub admission: &'a AuthorizationAdmission,
    pub deltas: &'a [astral_db::DeltaEventAppendRequest],
    pub sources: &'a [SourceProjectionReceipt],
    pub invalidations: &'a [InvalidationReceipt],
    pub source_images: &'a [astral_db::TypedSourceRowImageReceipt],
    pub source_audits: &'a [astral_db::TypedSourceAuditReceipt],
    pub publication_origin:
        Option<&'a astral_db::authority_eligibility_completion::EligibilitySourceEvidenceReceipt>,
    pub card_create_bindings: &'a [card_create::CardCreateBindingReceipt],
}

pub(super) async fn stage_source_outcome(
    tx: &mut Transaction<'_, MySql>,
    batch: SourceOutcomeBatch<'_>,
) -> Result<(), AstralError> {
    let SourceOutcomeBatch {
        admission,
        deltas,
        sources,
        invalidations,
        source_images,
        source_audits,
        publication_origin,
        card_create_bindings,
    } = batch;
    if deltas.is_empty()
        && sources.is_empty()
        && invalidations.is_empty()
        && source_images.is_empty()
        && source_audits.is_empty()
    {
        return Err(pending(
            "authorization source owner has not supplied actual immutable source evidence",
        ));
    }
    if deltas
        .len()
        .saturating_add(sources.len())
        .saturating_add(invalidations.len())
        .saturating_add(source_images.len())
        .saturating_add(source_audits.len())
        > PROJECTION_RECEIPT_CAP
    {
        return Err(pending(
            "complete source receipt batch exceeds its evidence capacity",
        ));
    }
    let (delta, source_images, audits) = if deltas.is_empty() {
        // Typed config is a disjoint lane: it carries only the opaque row/audit
        // receipts. Projection and invalidation owners must never be combined
        // with this terminal completion contract.
        if !sources.is_empty() || !invalidations.is_empty() {
            return Err(pending(
                "typed config source outcome cannot mix projection or invalidation receipts",
            ));
        }
        if source_images.is_empty() {
            return Err(pending(
                "typed config source outcome requires real opaque row-image receipts",
            ));
        }
        if source_audits.is_empty() {
            return Err(pending(
                "typed config source outcome requires same-transaction audit correlation",
            ));
        }
        let expected_operation = admission.proof().operation_id.as_str();
        let audits = read_back_typed_audits(tx, source_audits, expected_operation).await?;
        let mut source_images: Vec<_> = source_images.iter().map(wire_image).collect();
        source_images.sort_by(|left, right| {
            (left.table.as_str(), left.key).cmp(&(right.table.as_str(), right.key))
        });
        (None, source_images, audits)
    } else {
        if !source_images.is_empty() || !source_audits.is_empty() {
            return Err(pending(
                "delta owners must not mix typed row-image evidence into their batch",
            ));
        }
        let delta = astral_db::capture_delta_source_outcome_in_tx(tx, deltas)
            .await
            .map_err(|error| pending(error.to_string()))?;
        (Some(delta), Vec::new(), Vec::new())
    };
    let mut receipts: Vec<_> = delta
        .as_ref()
        .map(|delta| {
            delta.receipts.iter().map(|receipt| {
                astral_db::authority_source_outcome::AuthoritySourceReceiptIdentity {
                    identity_kind: receipt.identity_kind.clone(),
                    identity: receipt.identity.clone(),
                }
            })
        })
        .into_iter()
        .flatten()
        .collect();
    for image in &source_images {
        receipts.push(
            astral_db::authority_source_outcome::AuthoritySourceReceiptIdentity {
                identity_kind: "typed_source_row_image".into(),
                identity: format!(
                    "{}:{}:{}",
                    image.table.as_str(),
                    image.key,
                    operation_text(image.operation)
                ),
            },
        );
    }
    for audit in &audits {
        receipts.push(
            astral_db::authority_source_outcome::AuthoritySourceReceiptIdentity {
                identity_kind: "audit_log".into(),
                identity: audit.audit_log_id.to_string(),
            },
        );
    }
    let mut source_projection = Vec::with_capacity(sources.len());
    let mut sorted_sources: Vec<_> = sources.iter().collect();
    sorted_sources.sort_by_key(|receipt| &receipt.event_id);
    for expected in sorted_sources {
        type SourceRow = (
            i64,
            String,
            String,
            i64,
            Option<i64>,
            String,
            i64,
            i64,
            i64,
            String,
        );
        let row: SourceRow = sqlx::query_as(
            "SELECT outbox_id, event_id, aggregate_type, aggregate_id, tenant_id, event_type, \
             source_generation, sequence_number, revoke_fence, CAST(payload_json AS CHAR) \
             FROM authorization_projection_outbox WHERE event_id = ? FOR UPDATE",
        )
        .bind(&expected.event_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(database)?
        .ok_or_else(|| pending("source projection receipt is missing its durable row"))?;
        if row.0 <= 0
            || row.1 != expected.event_id
            || row.2 != expected.aggregate_type
            || row.3 != expected.aggregate_id
            || row.4 != expected.tenant_id
            || row.6 != expected.source_generation
            || row.7 != expected.source_generation
            || row.8 != expected.revoke_fence
        {
            return Err(pending(
                "source projection receipt differs from its durable row",
            ));
        }
        receipts.push(
            astral_db::authority_source_outcome::AuthoritySourceReceiptIdentity {
                identity_kind: "authorization_projection_outbox".into(),
                identity: row.0.to_string(),
            },
        );
        source_projection.push(SourceProjectionEvidence {
            outbox_id: row.0,
            event_id: row.1,
            aggregate_type: row.2,
            aggregate_id: row.3,
            tenant_id: row.4,
            event_type: row.5,
            source_generation: row.6,
            sequence_number: row.7,
            revoke_fence: row.8,
            payload: serde_json::from_str(&row.9)
                .map_err(|_| pending("invalid source projection payload"))?,
        });
    }
    let mut invalidation_evidence = Vec::with_capacity(invalidations.len());
    let mut sorted_invalidations: Vec<_> = invalidations.iter().collect();
    sorted_invalidations.sort_by_key(|receipt| &receipt.event_id);
    for expected in sorted_invalidations {
        type MessageRow = (
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<i64>,
            String,
            Option<String>,
            Option<String>,
            i32,
        );
        let row: MessageRow = sqlx::query_as(
            "SELECT message_id, operation_id, queue_name, CAST(payload_json AS CHAR), payload_sha256, \
             CAST(authority_metadata_json AS CHAR), CAST(headers_json AS CHAR), tenant_id, origin_region, \
             target_region, ordering_key, schema_version FROM al_message_outbox WHERE message_id = ? FOR UPDATE",
        ).bind(&expected.event_id).fetch_optional(&mut **tx).await.map_err(database)?
            .ok_or_else(|| pending("invalidation receipt is missing its durable row"))?;
        let envelope: astral_mq::MessageEnvelope = serde_json::from_str(&row.3)
            .map_err(|_| pending("durable invalidation envelope cannot be decoded"))?;
        envelope.validate().map_err(pending)?;
        let metadata = envelope.authority_metadata_json().map_err(pending)?;
        let metadata_equal = match (row.5.as_deref(), metadata.as_deref()) {
            (None, None) => true,
            (Some(stored), Some(expected)) => serde_json::from_str::<serde_json::Value>(stored)
                .ok()
                .zip(serde_json::from_str::<serde_json::Value>(expected).ok())
                .is_some_and(|(a, b)| a == b),
            _ => false,
        };
        if row.0 != expected.event_id
            || row.1 != expected.operation_id
            || row.2 != astral_mq::invalidation::INVALIDATION_QUEUE
            || envelope != expected.envelope
            || row.4 != envelope.payload_sha256
            || !metadata_equal
            || row.6.is_some()
            || row.7 != envelope.tenant_id
            || row.8 != envelope.origin_region
            || row.9 != envelope.target_region
            || row.10 != envelope.ordering_key
            || row.11 != envelope.schema_version
        {
            return Err(pending(
                "invalidation receipt differs from its durable envelope",
            ));
        }
        receipts.push(
            astral_db::authority_source_outcome::AuthoritySourceReceiptIdentity {
                identity_kind: "al_message_outbox".into(),
                identity: row.0.clone(),
            },
        );
        invalidation_evidence.push(InvalidationEvidence {
            message_id: row.0,
            operation_id: row.1,
            queue_name: row.2,
            envelope,
        });
    }
    let (mut before_image_digest, mut after_image_digest) = match &delta {
        Some(delta) => (
            delta.before_digest_hex.clone(),
            delta.after_digest_hex.clone(),
        ),
        // Typed owners bind the real per-row images captured by the delegate;
        // the absent-row images are real digests, so the binding stays String.
        None => typed_image_digests(&source_images)?,
    };
    let invalidation_owners = invalidation_evidence
        .iter()
        .map(|evidence| typed_invalidation_owner(&evidence.envelope))
        .collect::<Result<Vec<_>, AstralError>>()?;
    let coverage = match &delta {
        Some(delta) if publication_origin.is_some() => derive_card_create_coverage(
            delta,
            &source_projection,
            &invalidation_owners,
            card_create_bindings,
        )?,
        Some(delta) => derive_finite_coverage(delta, &source_projection, &invalidation_owners)?,
        // A typed (config) batch has no captured card owner set: its affected
        // eligibility fanout is not provable here and stays operator-owned.
        None => None,
    };
    let is_config_completion = delta.is_none();
    let (staged, source_commit_digest) = if let Some(origin) = publication_origin {
        let delta =
            delta.ok_or_else(|| pending("card publication origin has no real grant delta"))?;
        let artifact = astral_db::IdentityStagedEvidence {
            targets: vec![origin.source_target().clone()],
            receipts: origin.source_receipts().to_vec(),
            fanout: {
                let mut fanout = origin
                    .source_evidence()
                    .get("fanout")
                    .cloned()
                    .ok_or_else(|| pending("card publication origin has no captured fanout"))?;
                let object = fanout
                    .as_object_mut()
                    .ok_or_else(|| pending("card publication origin fanout is not an object"))?;
                if card_create_bindings.is_empty() {
                    return Err(pending(
                        "CardCreate publication requires retained RuleSet binding artifacts",
                    ));
                }
                object.insert(
                    "cardCreateRuleSetBindings".into(),
                    card_create::card_create_binding_evidence(card_create_bindings)?,
                );
                fanout
            },
            delta: Some(delta),
        };
        let card = origin
            .completion()
            .cards
            .first()
            .filter(|_| origin.completion().cards.len() == 1)
            .ok_or_else(|| pending("card publication origin must name exactly one created card"))?;
        let AuthorityProtocolScope::Card(card_scope) = &card.scope else {
            return Err(pending("card publication origin has a non-card scope"));
        };
        let delta = artifact
            .delta
            .as_ref()
            .expect("real delta was required above");
        if !origin.is_publication_origin()
            || delta.events.iter().any(|event| {
                event.tenant_id != card_scope.tenant_id || event.card_id != Some(card_scope.card_id)
            })
        {
            return Err(pending(
                "card publication delta differs from its closed INSERT origin",
            ));
        }
        let (before, after) = astral_db::identity_image_digests(&artifact.targets)
            .map_err(|error| pending(error.to_string()))?;
        if before != origin.before_image_digest() || after != origin.after_image_digest() {
            return Err(pending(
                "card publication target digests differ from captured origin",
            ));
        }
        before_image_digest = before;
        after_image_digest = after;
        for receipt in origin.source_receipts() {
            let identity = astral_db::authority_source_outcome::AuthoritySourceReceiptIdentity {
                identity_kind: format!("{}:{}", receipt.entity, receipt.kind),
                identity: receipt.durable_id.clone(),
            };
            if !receipts.contains(&identity) {
                receipts.push(identity);
            }
        }
        let staged =
            serde_json::to_string(&artifact).map_err(|error| pending(error.to_string()))?;
        let result = serde_json::to_string(origin.source_evidence())
            .map_err(|error| pending(error.to_string()))?;
        let digest = astral_db::source_commit_digest(&staged, &result);
        (staged, digest)
    } else if is_config_completion {
        let completion = AuthorityConfigCompletionEvidence {
            kind: AuthorityConfigCompletionKind::ConfigCompletion,
            gate_contract: AuthorityConfigGateContract::DurableConfigV7,
            source_batch: AuthorityConfigSourceBatch {
                delta: None,
                source_images,
                audits,
                source_projection: Vec::new(),
                invalidations: Vec::new(),
            },
        };
        completion
            .validate(&admission.proof().operation_id)
            .map_err(|error| {
                pending(format!(
                    "typed config completion evidence is invalid: {error}"
                ))
            })?;
        // `staged` is the inner evidence value: the durable staging API adds
        // AuthorityStagedSourceEvidence around it. The shared helper rebuilds
        // that same complete wrapper for the producer digest.
        let (staged, source_commit_digest) = config_staged_evidence_and_digest(&completion)?;
        (staged, source_commit_digest)
    } else {
        let staged = serde_json::to_string(&SourceBatchEvidence {
            delta,
            source_images,
            audits,
            source_projection,
            invalidations: invalidation_evidence,
        })
        .map_err(|error| pending(error.to_string()))?;
        let mut hash = Sha256::new();
        hash.update(b"ASTRAL_TRUSTGRAPH_SOURCE_BATCH_V7\0");
        hash.update((staged.len() as u64).to_be_bytes());
        hash.update(staged.as_bytes());
        (staged, hex::encode(hash.finalize()))
    };
    if staged.len() > astral_db::MAX_DELTA_EVIDENCE_JSON_BYTES {
        return Err(pending(
            "complete source evidence exceeds the staging byte capacity",
        ));
    }
    let evidence = astral_db::authority_source_outcome::AuthoritySourceOutcomeEvidence {
        source_commit_digest,
        before_image_digest,
        after_image_digest,
        source_receipts: receipts,
    };
    astral_db::stage_admitted_source_outcome_with_coverage_in_tx(
        tx,
        admission,
        AuthorityMutationKind::AuthorizationSource,
        staged,
        &evidence,
        coverage,
    )
    .await
    .map_err(|error| pending(error.to_string()))
}

fn config_staged_evidence_and_digest(
    completion: &AuthorityConfigCompletionEvidence,
) -> Result<(String, String), AstralError> {
    let staged = serde_json::to_string(completion).map_err(|error| {
        pending(format!(
            "typed config completion cannot be encoded: {error}"
        ))
    })?;
    let source_commit_digest = config_source_commit_digest(completion)
        .map_err(|error| pending(format!("typed config completion digest failed: {error}")))?;
    Ok((staged, source_commit_digest))
}

/// Consume the eligibility owner's opaque receipt and stage its independent
/// completion lane. This path deliberately has no config images, audit list,
/// grant delta, projection receipts, or invalidation receipts; the parent must
/// select it before the config/delta branch and then continue through the same
/// source-transaction COMMIT path.
pub(super) async fn stage_eligibility_source_outcome(
    tx: &mut Transaction<'_, MySql>,
    admission: &AuthorizationAdmission,
    receipt: astral_db::authority_eligibility_completion::EligibilitySourceEvidenceReceipt,
    bindings: &[card_create::CardCreateBindingReceipt],
) -> Result<(), AstralError> {
    let is_card_create = receipt.operation()
        == astral_db::authority_eligibility_completion::EligibilitySourceOperation::CardCreate;
    let mut source_evidence = receipt.source_evidence().clone();
    if !bindings.is_empty() {
        if !is_card_create
            || bindings.iter().any(|binding| {
                binding.source_evidence()["emptyRuleSet"] != true
                    || binding.source_evidence()["addDeltas"]
                        .as_array()
                        .is_none_or(|deltas| !deltas.is_empty())
            })
        {
            return Err(pending(
                "independent eligibility completion requires empty CardCreate bindings",
            ));
        }
        source_evidence["fanout"]
            .as_object_mut()
            .ok_or_else(|| pending("CardCreate eligibility fanout is not an object"))?
            .insert(
                "cardCreateRuleSetBindings".into(),
                card_create::card_create_binding_evidence(bindings)?,
            );
    }
    let before_image_digest = receipt.before_image_digest().to_owned();
    let after_image_digest = receipt.after_image_digest().to_owned();
    let source_receipts = receipt
        .source_receipts()
        .iter()
        .map(
            |source| astral_db::authority_source_outcome::AuthoritySourceReceiptIdentity {
                identity_kind: format!("{}:{}", source.entity, source.kind),
                identity: source.durable_id.clone(),
            },
        )
        .collect::<Vec<_>>();
    if source_receipts.is_empty() {
        return Err(pending(
            "eligibility source outcome requires actual durable receipt identities",
        ));
    }
    let mut staged = receipt
        .into_staged_envelope()
        .map_err(|error| pending(format!("eligibility source evidence is invalid: {error}")))?;
    staged.evidence["sourceEvidence"] = source_evidence.clone();
    if staged.coverage.is_some() {
        return Err(pending(
            "eligibility source outcome cannot declare publication coverage",
        ));
    }
    let staged_json = serde_json::to_string(&staged.evidence).map_err(|error| {
        pending(format!(
            "eligibility source evidence cannot be encoded: {error}"
        ))
    })?;
    let result_json = serde_json::to_string(&source_evidence).map_err(|error| {
        pending(format!(
            "eligibility source result cannot be encoded: {error}"
        ))
    })?;
    let evidence = astral_db::authority_source_outcome::AuthoritySourceOutcomeEvidence {
        source_commit_digest: astral_db::source_commit_digest(&staged_json, &result_json),
        before_image_digest,
        after_image_digest,
        source_receipts,
    };
    astral_db::stage_admitted_source_outcome_with_coverage_in_tx(
        tx,
        admission,
        AuthorityMutationKind::AuthorizationSource,
        staged_json,
        &evidence,
        None,
    )
    .await
    .map_err(|error| pending(error.to_string()))
}

/// Exact same-transaction readback of every declared audit row. The audit
/// correlation is durable evidence: a missing row, or one whose `request_id`
/// does not bind THIS source operation, fails the transaction instead of
/// staging a label.
async fn read_back_typed_audits(
    tx: &mut Transaction<'_, MySql>,
    audits: &[astral_db::TypedSourceAuditReceipt],
    expected_operation_id: &str,
) -> Result<Vec<AuthorityConfigAudit>, AstralError> {
    let mut evidence = Vec::with_capacity(audits.len());
    for audit in audits {
        type AuditRow = (
            i64,
            i64,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
        );
        let row: AuditRow = sqlx::query_as(
            "SELECT id, user_id, action, resource, decision, event_type, request_id \
             FROM audit_log WHERE id = ? FOR UPDATE",
        )
        .bind(audit.audit_log_id())
        .fetch_optional(&mut **tx)
        .await
        .map_err(database)?
        .ok_or_else(|| pending("audit receipt is missing its durable row"))?;
        if row.0 <= 0 {
            return Err(pending("audit receipt identity is invalid"));
        }
        if row.6.as_deref() != Some(expected_operation_id) {
            return Err(pending(
                "audit receipt is not correlated to this source operation",
            ));
        }
        evidence.push(AuthorityConfigAudit {
            audit_log_id: row.0,
            user_id: row.1,
            action: row.2,
            resource: row.3,
            decision: row.4,
            event_type: row
                .5
                .ok_or_else(|| pending("audit receipt lacks its event type"))?,
            request_id: row.6,
        });
    }
    evidence.sort_by_key(|audit| audit.audit_log_id);
    Ok(evidence)
}

/// Shared typed before/after digest framing used by the source owner and tests.
fn typed_image_digests(
    images: &[AuthorityConfigSourceImage],
) -> Result<(String, String), AstralError> {
    astral_types::config_image_digests(images).map_err(|error| pending(error.to_string()))
}

fn operation_text(operation: astral_types::AuthorityConfigSourceOperation) -> &'static str {
    match operation {
        astral_types::AuthorityConfigSourceOperation::Insert => "INSERT",
        astral_types::AuthorityConfigSourceOperation::Upsert => "UPSERT",
        astral_types::AuthorityConfigSourceOperation::Update => "UPDATE",
        astral_types::AuthorityConfigSourceOperation::Delete => "DELETE",
    }
}

/// Coverage-attribution facts of one same-transaction typed invalidation.
#[derive(Debug, Clone, PartialEq, Eq)]
enum InvalidationOwner {
    /// Evidence invalidation. The contract keeps card ownership optional; only
    /// a proven (tenant, card) pair can ever anchor finite coverage.
    Evidence {
        tenant_id: i64,
        card_id: Option<i64>,
    },
    /// Eligibility invalidation carries only a globally-scoped card id.
    Eligibility { card_id: i64 },
    /// Session revocation is user-scoped and can never be attributed to the
    /// captured card owner set.
    SessionRevoked,
}

/// Decode one durable invalidation envelope through the single typed-contract
/// owner (`InvalidationEvent::from_envelope`): envelope validity, schema
/// version, strict payload decoding, typed contract validation and
/// transport-metadata agreement all fail closed. Any contract failure is a
/// batch integrity failure, never a silently narrowed coverage.
fn typed_invalidation_owner(
    envelope: &astral_mq::MessageEnvelope,
) -> Result<InvalidationOwner, AstralError> {
    match astral_mq::invalidation::InvalidationEvent::from_envelope(envelope) {
        Ok(astral_mq::invalidation::InvalidationEvent::EvidenceInvalidated(value)) => {
            Ok(InvalidationOwner::Evidence {
                tenant_id: value.tenant_id,
                card_id: value.card_id,
            })
        }
        Ok(astral_mq::invalidation::InvalidationEvent::EligibilityInvalidated(value)) => {
            Ok(InvalidationOwner::Eligibility {
                card_id: value.card_id,
            })
        }
        Ok(astral_mq::invalidation::InvalidationEvent::SessionRevoked(_)) => {
            Ok(InvalidationOwner::SessionRevoked)
        }
        Err(error) => Err(pending(format!(
            "durable invalidation envelope fails its typed contract: {error}"
        ))),
    }
}

/// Derive the complete finite card coverage this source batch may declare.
///
/// The candidate set comes ONLY from the captured immutable delta batch
/// (`complete_card_coverage`). Source-projection rows are the head/outbox
/// channel (CARD/ELIGIBILITY/RULE_SET) with event ids independent of the
/// delta batch, so attribution is by TYPED OWNER, never by event identity:
/// a CARD row names its card as `aggregate_id` and must land inside the
/// captured owner set; an ELIGIBILITY row is card-scoped by `aggregate_id`
/// and maps only through its own tenant or a unique owner set; RULE_SET and
/// unknown channels are shared and can never be attributed (declaration
/// stays `None`; the reservation barrier stays GLOBAL; fanout is never
/// guessed). A positively contradictory claim — a CARD/ELIGIBILITY row
/// anchored to a different tenant or card than the captured owner set — is
/// a batch integrity failure. Durable-row readback stays exact elsewhere;
/// generation/fence counters are validated only inside their own aggregate
/// domain and are never compared across aggregates here.
fn derive_card_create_coverage(
    delta: &astral_db::DeltaSourceOutcomeEvidence,
    sources: &[SourceProjectionEvidence],
    invalidations: &[InvalidationOwner],
    bindings: &[card_create::CardCreateBindingReceipt],
) -> Result<Option<astral_types::AuthorityStagedScopeCoverage>, AstralError> {
    let mut approved_adds = std::collections::BTreeMap::new();
    let mut approved_rule_sets = std::collections::BTreeMap::new();
    for binding in bindings {
        let evidence = binding.source_evidence();
        let rule_set_id = binding.rule_set_id();
        if approved_rule_sets.insert(rule_set_id, evidence).is_some() {
            return Err(pending("CardCreate has duplicate RuleSet owners"));
        }
        let additions = evidence["addDeltas"]
            .as_array()
            .ok_or_else(|| pending("CardCreate binding has no exact ADD set"))?;
        for addition in additions {
            let event_id = addition["eventId"]
                .as_str()
                .ok_or_else(|| pending("CardCreate ADD has no event identity"))?;
            if approved_adds.insert(event_id, addition).is_some() {
                return Err(pending("CardCreate bindings repeat an ADD event"));
            }
        }
    }
    if approved_adds.len() != delta.events.len() {
        return Err(pending(
            "CardCreate bindings do not cover the complete delta batch",
        ));
    }
    for event in &delta.events {
        let addition = approved_adds
            .get(event.event_id.as_str())
            .ok_or_else(|| pending("CardCreate delta is outside its retained binding"))?;
        let actual: serde_json::Value = serde_json::from_str(&event.delta_json)
            .map_err(|_| pending("CardCreate immutable delta cannot be decoded"))?;
        if event.event_type != "ADD"
            || addition["delta"] != actual
            || addition["operationId"].as_str() != Some(event.operation_id.as_str())
            || addition["aggregateType"].as_str() != Some(event.aggregate_type.as_str())
            || addition["aggregateId"].as_i64() != Some(event.aggregate_id)
            || addition["tenantId"].as_i64() != Some(event.tenant_id)
            || addition["cardId"].as_i64() != event.card_id
            || addition["sourceGeneration"].as_u64() != Some(event.source_generation)
            || addition["revokeFence"].as_u64() != Some(event.revoke_fence)
        {
            return Err(pending(
                "CardCreate ADD batch differs from its binding receipt",
            ));
        }
    }
    let mut card_sources = Vec::new();
    for source in sources {
        if source.aggregate_type != astral_types::ProjectionAggregate::RULE_SET {
            card_sources.push(source.clone());
            continue;
        }
        let binding = approved_rule_sets
            .get(&source.aggregate_id)
            .ok_or_else(|| pending("CardCreate has an unproved shared RuleSet source event"))?;
        let audits = binding["audit"]
            .as_array()
            .ok_or_else(|| pending("CardCreate binding lacks retained source audit"))?;
        if source.event_type != "RULE_SET_UPDATE"
            || !audits.iter().any(|audit| {
                audit["eventId"].as_str() == Some(source.event_id.as_str())
                    && audit["ruleSetId"].as_i64() == Some(source.aggregate_id)
                    && audit["sourceGeneration"].as_i64() == Some(source.source_generation)
                    && audit["tenantId"].as_i64() == source.tenant_id
                    && audit["operationId"] == source.payload["operationId"]
            })
        {
            return Err(pending(
                "CardCreate shared source event lacks exact binding attribution",
            ));
        }
    }
    derive_finite_coverage(delta, &card_sources, invalidations)
}

fn derive_finite_coverage(
    delta: &astral_db::DeltaSourceOutcomeEvidence,
    source_projection: &[SourceProjectionEvidence],
    invalidations: &[InvalidationOwner],
) -> Result<Option<astral_types::AuthorityStagedScopeCoverage>, AstralError> {
    let Some(coverage) = delta
        .complete_card_coverage()
        .map_err(|error| pending(error.to_string()))?
    else {
        return Ok(None);
    };
    let mut owner_set = std::collections::BTreeSet::new();
    for event in &delta.events {
        let card_id = event
            .card_id
            .expect("complete coverage proved every event carries its card owner");
        owner_set.insert((event.tenant_id, card_id));
    }
    for row in source_projection {
        match row.aggregate_type.as_str() {
            astral_types::ProjectionAggregate::CARD => {
                let Some(tenant_id) = row.tenant_id else {
                    // A CARD row without its tenant cannot be attributed to
                    // any proven owner: the batch may fan out beyond it.
                    return Ok(None);
                };
                if !owner_set.contains(&(tenant_id, row.aggregate_id)) {
                    return Err(pending(
                        "CARD source projection is anchored outside the captured card owner set",
                    ));
                }
            }
            astral_types::ProjectionAggregate::ELIGIBILITY => {
                match row.tenant_id {
                    Some(tenant_id) => {
                        if !owner_set.contains(&(tenant_id, row.aggregate_id)) {
                            return Err(pending(
                                "ELIGIBILITY source projection is anchored outside the captured card owner set",
                            ));
                        }
                    }
                    None => {
                        // The eligibility row carries no tenant: it maps only
                        // through a single proven owner card.
                        if owner_set.len() != 1 {
                            return Ok(None);
                        }
                        let Some(&(_, owner_card)) = owner_set.iter().next() else {
                            return Err(pending("captured card owner set is unexpectedly empty"));
                        };
                        if owner_card != row.aggregate_id {
                            return Err(pending(
                                "ELIGIBILITY source projection contradicts the captured card owner set",
                            ));
                        }
                    }
                }
            }
            // Shared projection channels cannot be attributed to the captured
            // card owner set: the batch may fan out beyond it.
            _ => return Ok(None),
        }
    }
    for owner in invalidations {
        match owner {
            InvalidationOwner::Evidence {
                tenant_id,
                card_id: Some(card_id),
            } => {
                if !owner_set.contains(&(*tenant_id, *card_id)) {
                    return Err(pending(
                        "invalidation evidence is anchored outside the captured card owner set",
                    ));
                }
            }
            // An evidence invalidation without a card owner cannot be
            // attributed: the batch may fan out beyond the captured set.
            InvalidationOwner::Evidence {
                tenant_id: _,
                card_id: None,
            } => return Ok(None),
            InvalidationOwner::Eligibility { card_id } => {
                // The eligibility key is globally card-scoped: it maps into the
                // owner set only when that set is a single proven card.
                if owner_set.len() != 1 {
                    return Ok(None);
                }
                let Some(&(_, owner_card)) = owner_set.iter().next() else {
                    return Err(pending("captured card owner set is unexpectedly empty"));
                };
                if owner_card != *card_id {
                    return Err(pending(
                        "eligibility invalidation contradicts the captured card owner set",
                    ));
                }
            }
            // A session revocation cannot prove the affected card set.
            InvalidationOwner::SessionRevoked => return Ok(None),
        }
    }
    Ok(Some(coverage))
}

#[cfg(test)]
mod config_digest_tests {
    use super::*;
    use sha2::Digest;

    #[test]
    fn config_producer_hashes_full_wrapper_but_stages_inner_evidence() {
        let before_image =
            r#"{"id":1,"name":"before","description":null,"scope":null,"created_at":null}"#;
        let after_image =
            r#"{"id":1,"name":"after","description":null,"scope":null,"created_at":null}"#;
        let completion = AuthorityConfigCompletionEvidence {
            kind: AuthorityConfigCompletionKind::ConfigCompletion,
            gate_contract: AuthorityConfigGateContract::DurableConfigV7,
            source_batch: AuthorityConfigSourceBatch {
                delta: None,
                source_images: vec![AuthorityConfigSourceImage {
                    table: astral_types::AuthorityConfigSourceTable::AdminGroup,
                    key: 1,
                    lookup: serde_json::to_string(
                        &astral_types::AuthorityConfigSourceLookup::PrimaryId { id: 1 },
                    )
                    .unwrap(),
                    operation: astral_types::AuthorityConfigSourceOperation::Update,
                    before_image_digest: hex::encode(sha2::Sha256::digest(before_image.as_bytes())),
                    after_image_digest: hex::encode(sha2::Sha256::digest(after_image.as_bytes())),
                    before_image: before_image.to_owned(),
                    after_image: after_image.to_owned(),
                }],
                audits: vec![AuthorityConfigAudit {
                    audit_log_id: 1,
                    user_id: 7,
                    action: "UPDATE".to_owned(),
                    resource: "admin-group".to_owned(),
                    decision: "ALLOW".to_owned(),
                    event_type: "CONFIG_MUTATION".to_owned(),
                    request_id: Some("operation-1".to_owned()),
                }],
                source_projection: Vec::new(),
                invalidations: Vec::new(),
            },
        };
        completion.validate("operation-1").unwrap();
        let (staged, digest) = config_staged_evidence_and_digest(&completion).unwrap();
        let parsed_inner: AuthorityConfigCompletionEvidence =
            serde_json::from_str(&staged).unwrap();
        assert_eq!(parsed_inner, completion);

        let wrapper = astral_types::AuthorityStagedSourceEvidence {
            coverage: None,
            evidence: serde_json::to_value(&completion).unwrap(),
        };
        let canonical = serde_json::to_vec(&wrapper).unwrap();
        let mut framed = Vec::new();
        framed.extend_from_slice(b"ASTRAL_TRUSTGRAPH_SOURCE_BATCH_V7\0");
        framed.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
        framed.extend_from_slice(&canonical);
        assert_eq!(digest, hex::encode(sha2::Sha256::digest(framed)));
    }
}

#[cfg(test)]
mod tests;

pub(super) mod card_create;
