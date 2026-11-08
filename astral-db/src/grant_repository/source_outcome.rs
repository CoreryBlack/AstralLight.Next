//! Capture exact immutable delta/revision facts inside their source transaction.

use astral_types::{CanonicalGrant, GrantDelta, GrantState};
use sha2::{Digest, Sha256};
use sqlx::{MySql, Transaction};

use super::{
    decode_ledger_row, decode_stored_grant_payload, encode_grant_id_sql,
    validate_delta_payload_pairing, verify_owned_stable_event_request_binding,
    DeltaEventAppendRequest, GrantRepositoryError, OwnedStableEventRow, RawLedgerRow,
    AUTHORIZATION_COMPILER_VERSION, LEDGER_LOAD_COLUMNS, OWNED_STABLE_EVENT_SELECT_SQL,
};

pub const MAX_DELTA_EVIDENCE_EVENTS: usize = 1024;
pub const MAX_DELTA_EVIDENCE_JSON_BYTES: usize = 256 * 1024;
pub const MAX_DELTA_EVIDENCE_RECEIPTS: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeltaSourceEventEvidence {
    pub tenant_id: i64,
    pub card_id: Option<i64>,
    pub aggregate_type: String,
    pub aggregate_id: i64,
    pub event_id: String,
    pub operation_id: String,
    pub event_type: String,
    pub grant_id: String,
    pub base_version: i64,
    pub target_version: i64,
    pub source_generation: u64,
    pub revoke_fence: u64,
    pub invalidates_published_evidence: bool,
    pub delta_event_id: i64,
    pub revision_id: i64,
    pub predecessor_revision_id: Option<i64>,
    pub grant_revision: u64,
    pub is_tombstone: bool,
    pub delta_json: String,
    pub semantic_hash_hex: String,
    pub dependency_hash_hex: String,
    pub compiler_version: String,
    pub before_digest_hex: Option<String>,
    pub after_digest_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeltaSourceReceipt {
    pub identity_kind: String,
    pub identity: String,
}

/// One batch may span tenants and aggregates; every event carries its own scope.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeltaSourceOutcomeEvidence {
    pub events: Vec<DeltaSourceEventEvidence>,
    pub receipts: Vec<DeltaSourceReceipt>,
    pub before_digest_hex: String,
    pub after_digest_hex: String,
    pub commit_digest_hex: String,
}

impl DeltaSourceOutcomeEvidence {
    pub fn staged_json(&self) -> Result<Vec<u8>, GrantRepositoryError> {
        let bytes = serde_json::to_vec(self).map_err(mapping)?;
        if bytes.len() > MAX_DELTA_EVIDENCE_JSON_BYTES {
            return Err(invalid("staged_json_capacity"));
        }
        Ok(bytes)
    }

    /// Complete card ownership recorded by this immutable delta batch. A
    /// shared aggregate without a card owner cannot prove finite coverage.
    pub fn complete_card_coverage(
        &self,
    ) -> Result<Option<astral_types::AuthorityStagedScopeCoverage>, GrantRepositoryError> {
        if self.events.is_empty() || self.events.len() > MAX_DELTA_EVIDENCE_EVENTS {
            return Err(invalid("event_capacity"));
        }
        let mut cards = std::collections::BTreeSet::new();
        for event in &self.events {
            let Some(card_id) = event.card_id else {
                return Ok(None);
            };
            if event.tenant_id <= 0 || card_id <= 0 {
                return Err(invalid("card_coverage_identity"));
            }
            cards.insert((event.tenant_id, card_id));
            if cards.len() > 256 {
                return Ok(None);
            }
        }
        let coverage = astral_types::AuthorityStagedScopeCoverage {
            scopes: cards
                .into_iter()
                .map(|(tenant_id, card_id)| {
                    astral_types::AuthorityProtocolScope::Card(
                        astral_types::AuthorizationAuthorityScope {
                            tenant_id,
                            card_id,
                            user_id: None,
                            domain: astral_types::AuthorizationDomainScope::Any,
                        },
                    )
                })
                .collect(),
        };
        coverage.validate().map_err(mapping)?;
        Ok(Some(coverage))
    }

    pub fn into_source_outcome(
        self,
    ) -> Result<
        (
            String,
            crate::authority_source_outcome::AuthoritySourceOutcomeEvidence,
        ),
        GrantRepositoryError,
    > {
        let staged = String::from_utf8(self.staged_json()?).map_err(mapping)?;
        Ok((
            staged,
            crate::authority_source_outcome::AuthoritySourceOutcomeEvidence {
                source_commit_digest: self.commit_digest_hex,
                before_image_digest: self.before_digest_hex,
                after_image_digest: self.after_digest_hex,
                source_receipts: self
                    .receipts
                    .into_iter()
                    .map(|receipt| {
                        crate::authority_source_outcome::AuthoritySourceReceiptIdentity {
                            identity_kind: receipt.identity_kind,
                            identity: receipt.identity,
                        }
                    })
                    .collect(),
            },
        ))
    }
}

fn invalid(code: &str) -> GrantRepositoryError {
    GrantRepositoryError::ScopeViolation(format!("code=grant_repository.delta_evidence_{code}"))
}

fn mapping(error: impl std::fmt::Display) -> GrantRepositoryError {
    GrantRepositoryError::Mapping(format!(
        "code=grant_repository.delta_evidence_encoding;error={error}"
    ))
}

fn validate_evidence_batch(
    requests: &[DeltaEventAppendRequest],
) -> Result<(), GrantRepositoryError> {
    if requests.is_empty() || requests.len() > MAX_DELTA_EVIDENCE_EVENTS {
        return Err(invalid("event_capacity"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for request in requests {
        if !seen.insert((request.tenant_id, request.event_id.as_str())) {
            return Err(invalid("duplicate_event"));
        }
        validate_delta_payload_pairing(&request.delta_json, request.event_type, request.grant_id)?;
    }
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
struct EvidenceRevisionRow {
    revision_id: i64,
    #[sqlx(flatten)]
    ledger: RawLedgerRow,
}

fn bind_revision_scope(
    request: &DeltaEventAppendRequest,
    row: &EvidenceRevisionRow,
) -> Result<CanonicalGrant, GrantRepositoryError> {
    if row.revision_id <= 0
        || row.ledger.tenant_id != request.tenant_id
        || request
            .card_id
            .is_some_and(|card_id| row.ledger.card_id != Some(card_id))
        || row.ledger.aggregate_type != request.aggregate_type
        || row.ledger.aggregate_id != request.aggregate_id
        || row.ledger.grant_id != encode_grant_id_sql(request.grant_id)?
    {
        return Err(invalid("revision_scope"));
    }
    Ok(decode_ledger_row(&row.ledger)?.grant)
}

/// Reconstruct the exact source transition. Projection versions and per-grant
/// revisions are independent counters and must never be substituted for each other.
fn bind_transition(
    request: &DeltaEventAppendRequest,
    delta: &GrantDelta,
    target: &EvidenceRevisionRow,
    predecessor: Option<&EvidenceRevisionRow>,
) -> Result<(Option<String>, String), GrantRepositoryError> {
    let after = bind_revision_scope(request, target)?;
    if after.revision != delta.revision()?
        || target.ledger.event_id != request.event_id
        || target.ledger.operation_id != request.operation_id
        || hex::encode(&target.ledger.semantic_hash) != request.semantic_hash_hex
        || hex::encode(&target.ledger.dependency_hash) != request.dependency_hash_hex
    {
        return Err(invalid("target_binding"));
    }
    let before = predecessor
        .map(|row| bind_revision_scope(request, row))
        .transpose()?;
    match (delta.expected_revision(), &before) {
        (Some(expected), Some(before))
            if before.revision == expected && before.state == GrantState::Active => {}
        (None, None) => {}
        _ => return Err(invalid("expected_predecessor")),
    }
    let before_json = before
        .as_ref()
        .map(CanonicalGrant::canonical_input)
        .transpose()?;
    match (
        &before_json,
        &request.before_image_json,
        &request.before_digest_hex,
    ) {
        (Some(actual), Some(declared), Some(digest)) => {
            let declared = decode_stored_grant_payload(declared)?.canonical_input()?;
            if &declared != actual || hex::encode(Sha256::digest(actual.as_bytes())) != *digest {
                return Err(invalid("before_image"));
            }
        }
        (None, None, None) => {}
        _ => return Err(invalid("before_image_presence")),
    }
    let expected_after = match delta {
        GrantDelta::Add { grant } | GrantDelta::Update { grant, .. } => grant.canonical_input()?,
        GrantDelta::Remove { .. } | GrantDelta::Revoke { .. } => {
            let mut tombstone = before.ok_or_else(|| invalid("missing_tombstone_predecessor"))?;
            tombstone.revision = delta.revision()?;
            tombstone.state = if matches!(delta, GrantDelta::Remove { .. }) {
                GrantState::Removed
            } else {
                GrantState::Revoked
            };
            tombstone.provenance.operation_id = request.operation_id.clone();
            tombstone.provenance.event_id = Some(request.event_id.clone());
            tombstone.canonical_input()?
        }
    };
    let after_json = after.canonical_input()?;
    if after_json != expected_after {
        return Err(invalid("after_image"));
    }
    Ok((before_json, after_json))
}

fn image_digest(domain: &[u8], facts: &[DeltaSourceEventEvidence], before: bool) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update((facts.len() as u64).to_be_bytes());
    for event in facts {
        hash.update(event.tenant_id.to_be_bytes());
        for field in [
            &event.aggregate_type,
            &event.aggregate_id.to_string(),
            &event.event_id,
            &event.grant_id,
        ] {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field.as_bytes());
        }
        let digest = if before {
            event.before_digest_hex.as_deref()
        } else {
            Some(event.after_digest_hex.as_str())
        };
        match digest {
            None => hash.update([0]),
            Some(value) => {
                hash.update([1]);
                hash.update(value.as_bytes());
            }
        }
    }
    hex::encode(hash.finalize())
}

/// Capture actual rows while the source transaction still owns its locks. This
/// reads immutable revisions and deltas only, with no authority or transport I/O.
pub async fn capture_delta_source_outcome_in_tx(
    tx: &mut Transaction<'_, MySql>,
    requests: &[DeltaEventAppendRequest],
) -> Result<DeltaSourceOutcomeEvidence, GrantRepositoryError> {
    validate_evidence_batch(requests)?;
    let mut sorted: Vec<_> = requests.iter().collect();
    sorted.sort_by_key(|request| {
        (
            request.tenant_id,
            &request.aggregate_type,
            request.aggregate_id,
            &request.event_id,
        )
    });
    let select = format!(
        "SELECT revision_id, {LEDGER_LOAD_COLUMNS} FROM authorization_grant_revision \
        WHERE tenant_id = ? AND aggregate_type = ? AND aggregate_id = ? AND grant_id = ? "
    );
    let target_sql = format!("{select} AND revision_no = ? FOR UPDATE");
    let predecessor_sql =
        format!("{select} AND revision_no < ? ORDER BY revision_no DESC LIMIT 1 FOR UPDATE");
    let mut events = Vec::with_capacity(sorted.len());
    let mut receipts = Vec::with_capacity(sorted.len());
    for request in sorted {
        let delta = validate_delta_payload_pairing(
            &request.delta_json,
            request.event_type,
            request.grant_id,
        )?;
        let grant_key = encode_grant_id_sql(request.grant_id)?;
        let revision = i64::try_from(delta.revision()?.value()).map_err(mapping)?;
        let stored: OwnedStableEventRow = sqlx::query_as(OWNED_STABLE_EVENT_SELECT_SQL)
            .bind(&request.event_id)
            .bind(request.tenant_id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(|| invalid("missing_delta"))?;
        verify_owned_stable_event_request_binding(request, &stored)?;
        let target: EvidenceRevisionRow = sqlx::query_as(&target_sql)
            .bind(request.tenant_id)
            .bind(&request.aggregate_type)
            .bind(request.aggregate_id)
            .bind(&grant_key)
            .bind(revision)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(|| invalid("missing_revision"))?;
        // This preceding row must equal the delta's explicit expected revision;
        // a gap or an undeclared predecessor fails rather than becoming a fallback.
        let predecessor: Option<EvidenceRevisionRow> = sqlx::query_as(&predecessor_sql)
            .bind(request.tenant_id)
            .bind(&request.aggregate_type)
            .bind(request.aggregate_id)
            .bind(&grant_key)
            .bind(revision)
            .fetch_optional(&mut **tx)
            .await?;
        let (before, after) = bind_transition(request, &delta, &target, predecessor.as_ref())?;
        if stored.delta_event_id <= 0 {
            return Err(invalid("delta_row_identity"));
        }
        receipts.push(DeltaSourceReceipt {
            identity_kind: "authorization_delta_revision_pair".into(),
            identity: format!("{}:{}", stored.delta_event_id, target.revision_id),
        });
        events.push(DeltaSourceEventEvidence {
            tenant_id: request.tenant_id,
            card_id: request.card_id,
            aggregate_type: request.aggregate_type.clone(),
            aggregate_id: request.aggregate_id,
            event_id: request.event_id.clone(),
            operation_id: request.operation_id.clone(),
            event_type: request.event_type.as_str().into(),
            grant_id: grant_key,
            base_version: request.base_version,
            target_version: request.target_version,
            source_generation: request.source_generation,
            revoke_fence: request.revoke_fence,
            invalidates_published_evidence: request.invalidates_published_evidence,
            delta_event_id: stored.delta_event_id,
            revision_id: target.revision_id,
            predecessor_revision_id: predecessor.as_ref().map(|row| row.revision_id),
            grant_revision: delta.revision()?.value(),
            is_tombstone: target.ledger.is_tombstone != 0,
            delta_json: serde_json::to_string(&delta.canonicalized()?).map_err(mapping)?,
            semantic_hash_hex: request.semantic_hash_hex.clone(),
            dependency_hash_hex: request.dependency_hash_hex.clone(),
            compiler_version: AUTHORIZATION_COMPILER_VERSION.into(),
            before_digest_hex: before.map(|value| hex::encode(Sha256::digest(value.as_bytes()))),
            after_digest_hex: hex::encode(Sha256::digest(after.as_bytes())),
        });
    }
    let before_digest_hex = image_digest(b"ASTRAL_DELTA_SOURCE_BEFORE_V7\0", &events, true);
    let after_digest_hex = image_digest(b"ASTRAL_DELTA_SOURCE_AFTER_V7\0", &events, false);
    let document = serde_json::to_vec(&(&events, &receipts, &before_digest_hex, &after_digest_hex))
        .map_err(mapping)?;
    let mut hash = Sha256::new();
    hash.update(b"ASTRAL_DELTA_SOURCE_COMMIT_V7\0");
    hash.update((document.len() as u64).to_be_bytes());
    hash.update(document);
    let evidence = DeltaSourceOutcomeEvidence {
        events,
        receipts,
        before_digest_hex,
        after_digest_hex,
        commit_digest_hex: hex::encode(hash.finalize()),
    };
    evidence.staged_json()?;
    Ok(evidence)
}

/// Recover complete immutable receipts from retained source evidence. Queue
/// ownership/status is not a completion proof; callers must separately verify
/// WorkerOwned publication closure for every returned receipt.
pub(crate) async fn load_source_receipts_in_tx(
    tx: &mut Transaction<'_, MySql>,
    expected: &DeltaSourceOutcomeEvidence,
) -> Result<Vec<DeltaEventAppendRequest>, GrantRepositoryError> {
    if expected.events.is_empty() || expected.events.len() > MAX_DELTA_EVIDENCE_EVENTS {
        return Err(invalid("event_capacity"));
    }
    expected.staged_json()?;
    let mut requests = Vec::with_capacity(expected.events.len());
    for event in &expected.events {
        // Immutable receipt discovery takes no locks. The completion owner
        // acquires lane/pointer/delta locks before actual revision revalidation.
        let statement = OWNED_STABLE_EVENT_SELECT_SQL.trim_end_matches(" FOR UPDATE");
        let row: OwnedStableEventRow = sqlx::query_as(statement)
            .bind(&event.event_id)
            .bind(event.tenant_id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(|| invalid("missing_delta"))?;
        if row.delta_event_id != event.delta_event_id {
            return Err(invalid("delta_row_identity"));
        }
        let before_image_json = row
            .before_image_json
            .as_deref()
            .map(|image| -> Result<String, GrantRepositoryError> {
                Ok(decode_stored_grant_payload(image)?.canonical_input()?)
            })
            .transpose()?;
        requests.push(DeltaEventAppendRequest {
            tenant_id: event.tenant_id,
            card_id: event.card_id,
            aggregate_type: event.aggregate_type.clone(),
            aggregate_id: event.aggregate_id,
            grant_id: super::decode_grant_id_sql(&event.grant_id)?,
            event_id: event.event_id.clone(),
            operation_id: event.operation_id.clone(),
            event_type: super::DeltaEventType::from_sql(&event.event_type)?,
            base_version: event.base_version,
            target_version: event.target_version,
            source_generation: event.source_generation,
            revoke_fence: event.revoke_fence,
            invalidates_published_evidence: event.invalidates_published_evidence,
            before_image_json,
            before_digest_hex: event.before_digest_hex.clone(),
            delta_json: event.delta_json.clone(),
            semantic_hash_hex: event.semantic_hash_hex.clone(),
            dependency_hash_hex: event.dependency_hash_hex.clone(),
            compiler_version: event.compiler_version.clone(),
            next_attempt_at: None,
        });
    }
    validate_evidence_batch(&requests)?;
    Ok(requests)
}

#[cfg(test)]
mod tests;
