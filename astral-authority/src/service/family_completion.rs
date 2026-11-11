//! Authority-owned completion receipts for CertifiedMemory families.

use astral_types::{
    AuthorityCertifiedMemoryFamily, AuthorityFamilyCompletionReceipt,
    AuthorityFamilyCompletionReconcileRequest, AuthorityFamilyCompletionReconcileResponse,
    AuthorityFamilyCompletionRequest, AuthorityFamilyCompletionResponse, AuthorityMutationKind,
    AuthorityProtocolError, AuthorityReservationDisposition, AuthorityReservationState,
    AuthorityScopeReservation, GlobalAuthorityFrontier, AUTHORITY_OPERATION_FAMILY_COMPLETION,
};

use serde::{Deserialize, Serialize};

use super::{decode, encode, fresh_id, mutation_digest, now_unix, AuthorityService};
use crate::error::{AuthorityServiceError, AuthorityStoreError};
use crate::store::{StoreOp, StoreTxn, StoreTxnOutcome};

// No independently verifiable source-owned completeness proof is available at
// this authority boundary yet. This is a protection, not a proof of completion.
fn source_owned_family_completeness_verified() -> bool {
    false
}

fn validate_aggregate_text(value: &str, field: &'static str) -> Result<(), AuthorityProtocolError> {
    if value.is_empty()
        || value.len() > 128
        || value.trim() != value
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(AuthorityProtocolError::InvalidText { field });
    }
    Ok(())
}

fn validate_aggregate_digest(
    value: &str,
    field: &'static str,
) -> Result<(), AuthorityProtocolError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AuthorityProtocolError::InvalidDigest { field });
    }
    Ok(())
}

fn validate_aggregate_counter(
    value: u64,
    field: &'static str,
) -> Result<(), AuthorityProtocolError> {
    if value == 0 {
        return Err(AuthorityProtocolError::InvalidCounter { field });
    }
    Ok(())
}

fn validate_aggregate_timestamp(
    value: i64,
    field: &'static str,
) -> Result<(), AuthorityProtocolError> {
    if value <= 0 {
        return Err(AuthorityProtocolError::InvalidCounter { field });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoredFamilyCompletionAggregate {
    reservation_id: String,
    operation_id: String,
    event_id: String,
    source_commit_digest: String,
    source_outcome_digest: String,
    scope: astral_types::AuthorityFamilyScope,
    scope_generation: u64,
    revoke_watermark: u64,
    family_receipt_ids: Vec<String>,
    family_completion_digests: Vec<String>,
    family_bundle_digest: String,
    aggregate_digest: String,
    certified_at: i64,
    global_frontier: GlobalAuthorityFrontier,
}

impl StoredFamilyCompletionAggregate {
    fn validate(&self) -> Result<(), AuthorityProtocolError> {
        if self.family_receipt_ids.len() != AuthorityCertifiedMemoryFamily::required().len()
            || self.family_completion_digests.len() != self.family_receipt_ids.len()
            || self
                .family_receipt_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self
                .family_completion_digests
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }
        validate_aggregate_text(&self.reservation_id, "reservation_id")?;
        validate_aggregate_text(&self.operation_id, "operation_id")?;
        validate_aggregate_text(&self.event_id, "event_id")?;
        validate_aggregate_digest(&self.source_commit_digest, "source_commit_digest")?;
        validate_aggregate_digest(&self.source_outcome_digest, "source_outcome_digest")?;
        self.scope.validate()?;
        validate_aggregate_counter(self.scope_generation, "scope_generation")?;
        if self.revoke_watermark > self.scope_generation {
            return Err(AuthorityProtocolError::RevokeWatermarkAhead);
        }
        for receipt_id in &self.family_receipt_ids {
            validate_aggregate_text(receipt_id, "receipt_id")?;
        }
        for digest in &self.family_completion_digests {
            validate_aggregate_digest(digest, "completion_digest")?;
        }
        validate_aggregate_digest(&self.family_bundle_digest, "family_bundle_digest")?;
        validate_aggregate_digest(&self.aggregate_digest, "aggregate_digest")?;
        validate_aggregate_timestamp(self.certified_at, "certified_at")?;
        self.global_frontier.validate()
    }
}

fn family_bundle_digest(
    scope: &astral_types::AuthorityFamilyScope,
    receipts: &[(
        AuthorityCertifiedMemoryFamily,
        AuthorityFamilyCompletionReceipt,
    )],
) -> Result<String, AuthorityProtocolError> {
    let mut entries = receipts
        .iter()
        .map(|(family, receipt)| Ok((*family, receipt.completion.completion_digest()?)))
        .collect::<Result<Vec<_>, AuthorityProtocolError>>()?;
    entries.sort_by_key(|(family, _)| family.as_text());
    let mut bytes = Vec::with_capacity(64 + entries.len() * 80);
    bytes.extend_from_slice(b"ASTRAL_CERTIFIED_MEMORY_FAMILY_BUNDLE_V1\0");
    let tenant = scope
        .tenant_id
        .map_or_else(|| "-".to_owned(), |id| id.to_string());
    for value in [tenant.as_str(), scope.scope.as_str()] {
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    for (family, digest) in entries {
        for value in [family.as_text(), digest.as_str()] {
            bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
    }
    Ok(super::sha256_hex(&bytes))
}

struct FamilyAggregateIdentity<'a> {
    reservation_id: &'a str,
    operation_id: &'a str,
    event_id: &'a str,
    source_commit_digest: &'a str,
    source_outcome_digest: &'a str,
}

fn family_aggregate_digest(
    identity: FamilyAggregateIdentity<'_>,
    scope: &astral_types::AuthorityFamilyScope,
    scope_generation: u64,
    revoke_watermark: u64,
    receipts: &[(
        AuthorityCertifiedMemoryFamily,
        AuthorityFamilyCompletionReceipt,
    )],
) -> Result<String, AuthorityProtocolError> {
    let mut bytes = Vec::with_capacity(2048);
    bytes.extend_from_slice(b"ASTRAL_AUTHORITY_CERTIFIED_MEMORY_FAMILY_AGGREGATE_V1\0");
    for value in [
        identity.reservation_id,
        identity.operation_id,
        identity.event_id,
        identity.source_commit_digest,
        identity.source_outcome_digest,
        &scope.scope,
    ] {
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    let tenant = scope
        .tenant_id
        .map_or_else(|| "-".to_owned(), |id| id.to_string());
    bytes.extend_from_slice(&(tenant.len() as u32).to_be_bytes());
    bytes.extend_from_slice(tenant.as_bytes());
    for value in [scope_generation.to_string(), revoke_watermark.to_string()] {
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    for (family, receipt) in receipts {
        let family_text = family.as_text();
        let completion_digest = receipt.completion.completion_digest()?;
        for value in [
            family_text,
            receipt.receipt_id.as_str(),
            completion_digest.as_str(),
        ] {
            bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
    }
    Ok(super::sha256_hex(&bytes))
}

impl AuthorityService {
    pub(crate) async fn verify_family_aggregate_for_root(
        &self,
        reservation: &AuthorityScopeReservation,
        proposal: &astral_types::AuthorityCertifiedMemoryRootProposal,
        state: &super::VerifiedAuthorityState,
    ) -> Result<(), AuthorityServiceError> {
        if !reservation.intent.coverage.is_global()
            || reservation.state != AuthorityReservationState::Certified
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "reservation",
                    state: reservation.state.as_text().to_owned(),
                },
            ));
        }
        let aggregate_record = self
            .store
            .get(
                &self
                    .keys
                    .family_completion_aggregate(&reservation.reservation_id),
            )
            .await?
            .ok_or(AuthorityServiceError::Protocol(
                AuthorityProtocolError::NotFound {
                    record: "family_completion_aggregate",
                },
            ))?;
        let aggregate: StoredFamilyCompletionAggregate =
            decode(&aggregate_record.value, "family completion aggregate")?;
        aggregate
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        let source_commit_digest =
            reservation
                .source_commit_digest
                .as_deref()
                .ok_or(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::StateConflict {
                        record: "reservation",
                        state: "SOURCE_COMMIT_MISSING".to_owned(),
                    },
                ))?;
        let source_outcome_digest =
            reservation
                .source_outcome_digest
                .as_deref()
                .ok_or(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::StateConflict {
                        record: "reservation",
                        state: "SOURCE_OUTCOME_MISSING".to_owned(),
                    },
                ))?;
        if aggregate.reservation_id != reservation.reservation_id
            || aggregate.operation_id != reservation.intent.operation_id
            || aggregate.event_id != reservation.intent.event_id
            || aggregate.source_commit_digest != source_commit_digest
            || aggregate.source_outcome_digest != source_outcome_digest
            || aggregate.family_bundle_digest != proposal.family_bundle_digest
            || aggregate.operation_id != proposal.operation_id
            || aggregate.event_id != proposal.event_id
            || aggregate.source_commit_digest != proposal.source_commit_digest
            || aggregate.source_outcome_digest != proposal.source_outcome_digest
            || aggregate.scope_generation != proposal.scope_generation
            || aggregate.revoke_watermark != proposal.revoke_watermark
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch,
            ));
        }
        let mut receipts = Vec::with_capacity(AuthorityCertifiedMemoryFamily::required().len());
        for family in AuthorityCertifiedMemoryFamily::required() {
            let receipt_record = self
                .store
                .get(
                    &self
                        .keys
                        .family_completion(&reservation.reservation_id, family.as_text()),
                )
                .await?
                .ok_or(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::NotFound {
                        record: "family_completion_receipt",
                    },
                ))?;
            let operation_record = self
                .store
                .get(&self.keys.family_completion_operation(
                    &reservation.intent.operation_id,
                    family.as_text(),
                ))
                .await?
                .ok_or(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::NotFound {
                        record: "family_completion_operation_receipt",
                    },
                ))?;
            let receipt: AuthorityFamilyCompletionReceipt =
                decode(&receipt_record.value, "family completion receipt")?;
            let operation_receipt: AuthorityFamilyCompletionReceipt = decode(
                &operation_record.value,
                "family completion operation receipt",
            )?;
            receipt
                .validate()
                .map_err(AuthorityServiceError::Protocol)?;
            operation_receipt
                .validate()
                .map_err(AuthorityServiceError::Protocol)?;
            if receipt != operation_receipt {
                return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "family completion receipt indexes disagree".to_owned(),
                )));
            }
            receipts.push((family, receipt));
        }
        let first = &receipts[0].1.completion;
        if receipts.iter().any(|(family, receipt)| {
            let completion = &receipt.completion;
            completion.family != *family
                || completion.reservation_id != reservation.reservation_id
                || completion.operation_id != reservation.intent.operation_id
                || completion.event_id != reservation.intent.event_id
                || completion.scope != first.scope
                || completion.scope_generation != first.scope_generation
                || completion.revoke_watermark != first.revoke_watermark
                || completion.source_commit_digest != source_commit_digest
                || completion.source_outcome_digest != source_outcome_digest
        }) {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch,
            ));
        }
        let expected_bundle = family_bundle_digest(&first.scope, &receipts)?;
        if expected_bundle != aggregate.family_bundle_digest {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::DigestMismatch {
                    field: "family_bundle_digest",
                },
            ));
        }
        let aggregate_digest = family_aggregate_digest(
            FamilyAggregateIdentity {
                reservation_id: aggregate.reservation_id.as_str(),
                operation_id: aggregate.operation_id.as_str(),
                event_id: aggregate.event_id.as_str(),
                source_commit_digest: aggregate.source_commit_digest.as_str(),
                source_outcome_digest: aggregate.source_outcome_digest.as_str(),
            },
            &aggregate.scope,
            aggregate.scope_generation,
            aggregate.revoke_watermark,
            &receipts,
        )?;
        if aggregate_digest != aggregate.aggregate_digest
            || aggregate.scope != first.scope
            || aggregate.scope_generation != first.scope_generation
            || aggregate.revoke_watermark != first.revoke_watermark
            || aggregate.family_receipt_ids != {
                let mut ids = receipts
                    .iter()
                    .map(|(_, receipt)| receipt.receipt_id.clone())
                    .collect::<Vec<_>>();
                ids.sort();
                ids
            }
            || aggregate.family_completion_digests != {
                let mut digests = receipts
                    .iter()
                    .map(|(_, receipt)| receipt.completion.completion_digest())
                    .collect::<Result<Vec<_>, _>>()?;
                digests.sort();
                digests
            }
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::DigestMismatch {
                    field: "family_completion_aggregate",
                },
            ));
        }
        state.verify_historical_frontier(&aggregate.global_frontier)?;
        Ok(())
    }

    async fn try_finalize_family_aggregate(
        &self,
        reservation_record: &crate::store::StoredRecord,
        reservation: &AuthorityScopeReservation,
        state: &super::VerifiedAuthorityState,
        now: i64,
    ) -> Result<Option<(AuthorityScopeReservation, GlobalAuthorityFrontier)>, AuthorityServiceError>
    {
        if reservation.state != AuthorityReservationState::Committed {
            return Ok(None);
        }
        if let Some(record) = self
            .store
            .get(
                &self
                    .keys
                    .family_completion_aggregate(&reservation.reservation_id),
            )
            .await?
        {
            let aggregate: StoredFamilyCompletionAggregate =
                decode(&record.value, "family completion aggregate")?;
            aggregate
                .validate()
                .map_err(AuthorityServiceError::Protocol)?;
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "family_completion_aggregate",
                    state: "MARKER_WITH_COMMITTED_RESERVATION".to_owned(),
                },
            ));
        }
        let source_commit_digest =
            reservation
                .source_commit_digest
                .as_deref()
                .ok_or(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::StateConflict {
                        record: "reservation",
                        state: "SOURCE_COMMIT_MISSING".to_owned(),
                    },
                ))?;
        let source_outcome_digest =
            reservation
                .source_outcome_digest
                .as_deref()
                .ok_or(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::StateConflict {
                        record: "reservation",
                        state: "SOURCE_OUTCOME_MISSING".to_owned(),
                    },
                ))?;
        // Existing receipts and publication certificates do not establish
        // source-owned family completeness. Keep the original validation order,
        // but never create an aggregate until that proof can be verified here.
        if !source_owned_family_completeness_verified() {
            return Ok(None);
        }
        if !Self::certified_memory_publication_proof_available() {
            return Ok(None);
        }
        let binding_record = self
            .store
            .get(&self.keys.commit_binding(&reservation.reservation_id))
            .await?
            .ok_or_else(|| {
                AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "family completion source commit binding is missing".into(),
                ))
            })?;
        let binding: astral_types::AuthorityCommitBinding =
            decode(&binding_record.value, "source commit binding")?;
        let coverage = self.load_commit_coverage(reservation, &binding).await?;
        if !self
            .coverage_allows_automatic_close(&coverage, reservation, None)
            .await?
        {
            return Ok(None);
        }
        let mut receipts = Vec::with_capacity(AuthorityCertifiedMemoryFamily::required().len());
        for family in AuthorityCertifiedMemoryFamily::required() {
            let key = self
                .keys
                .family_completion(&reservation.reservation_id, family.as_text());
            let operation_key = self
                .keys
                .family_completion_operation(&reservation.intent.operation_id, family.as_text());
            let record = self.store.get(&key).await?;
            let operation_record = self.store.get(&operation_key).await?;
            let (record, operation_record) = match (record, operation_record) {
                (None, None) => return Ok(None),
                (Some(record), Some(operation_record)) => (record, operation_record),
                _ => {
                    return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                        "family completion receipt indexes are incomplete".into(),
                    )));
                }
            };
            let receipt: AuthorityFamilyCompletionReceipt =
                decode(&record.value, "family completion receipt")?;
            let operation_receipt: AuthorityFamilyCompletionReceipt = decode(
                &operation_record.value,
                "family completion operation receipt",
            )?;
            receipt
                .validate()
                .map_err(AuthorityServiceError::Protocol)?;
            operation_receipt
                .validate()
                .map_err(AuthorityServiceError::Protocol)?;
            if receipt != operation_receipt {
                return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "family completion receipt indexes disagree".into(),
                )));
            }
            receipts.push((family, receipt));
        }
        let first = &receipts[0].1.completion;
        let scope = first.scope.clone();
        let generation = first.scope_generation;
        let revoke = first.revoke_watermark;
        for (family, receipt) in &receipts {
            let completion = &receipt.completion;
            if completion.family != *family
                || completion.reservation_id != reservation.reservation_id
                || completion.operation_id != reservation.intent.operation_id
                || completion.event_id != reservation.intent.event_id
                || completion.scope != scope
                || completion.source_commit_digest != source_commit_digest
                || completion.source_outcome_digest != source_outcome_digest
                || completion.scope_generation != generation
                || completion.revoke_watermark != revoke
            {
                return Err(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::ScopeMismatch,
                ));
            }
        }
        let family_bundle_digest = family_bundle_digest(&scope, &receipts)?;
        let aggregate_digest = family_aggregate_digest(
            FamilyAggregateIdentity {
                reservation_id: &reservation.reservation_id,
                operation_id: &reservation.intent.operation_id,
                event_id: &reservation.intent.event_id,
                source_commit_digest,
                source_outcome_digest,
            },
            &scope,
            generation,
            revoke,
            &receipts,
        )?;
        let mut receipt_ids: Vec<String> = receipts
            .iter()
            .map(|(_, receipt)| receipt.receipt_id.clone())
            .collect();
        receipt_ids.sort();
        let mut completion_digests: Vec<String> = receipts
            .iter()
            .map(|(_, receipt)| receipt.completion.completion_digest())
            .collect::<Result<_, _>>()?;
        completion_digests.sort();
        let next_frontier = state
            .frontier
            .advance(
                &reservation.intent.operation_id,
                &mutation_digest("family-aggregate", &aggregate_digest),
                now,
            )
            .map_err(AuthorityServiceError::Protocol)?;
        let aggregate = StoredFamilyCompletionAggregate {
            reservation_id: reservation.reservation_id.clone(),
            operation_id: reservation.intent.operation_id.clone(),
            event_id: reservation.intent.event_id.clone(),
            source_commit_digest: reservation.source_commit_digest.clone().unwrap_or_default(),
            source_outcome_digest: reservation
                .source_outcome_digest
                .clone()
                .unwrap_or_default(),
            scope,
            scope_generation: generation,
            revoke_watermark: revoke,
            family_receipt_ids: receipt_ids,
            family_completion_digests: completion_digests,
            family_bundle_digest,
            aggregate_digest,
            certified_at: now,
            global_frontier: next_frontier.clone(),
        };
        aggregate
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        let mut certified = reservation.clone();
        certified.state = AuthorityReservationState::Certified;
        certified.updated_at = now;
        certified
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        let outcome = self
            .execute_leader_txn(
                StoreTxn::new()
                    .with_op(StoreOp::PutIfAbsent {
                        key: self
                            .keys
                            .family_completion_aggregate(&reservation.reservation_id),
                        value: encode(&aggregate)?,
                    })
                    .with_op(StoreOp::ReplaceIfRevision {
                        key: self.keys.reservation(&reservation.reservation_id),
                        expected_revision: reservation_record.revision,
                        value: encode(&certified)?,
                    })
                    .with_op(StoreOp::ReplaceIfRevision {
                        key: self.keys.frontier(),
                        expected_revision: state.frontier_revision,
                        value: encode(&next_frontier)?,
                    })
                    .with_op(self.bump_gate_epoch_op(state)?),
            )
            .await
            .map_err(|error| self.map_store_error(error, &reservation.reservation_id))?;
        match outcome {
            StoreTxnOutcome::Applied { .. } => Ok(Some((certified, next_frontier))),
            StoreTxnOutcome::PreconditionFailed { .. } => Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "family_completion_aggregate",
                    state: "CONCURRENT".to_owned(),
                },
            )),
        }
    }
}

impl AuthorityService {
    pub async fn reconcile_family_completion(
        &self,
        request: &AuthorityFamilyCompletionReconcileRequest,
    ) -> Result<AuthorityFamilyCompletionReconcileResponse, AuthorityServiceError> {
        self.authorize(&request.caller, AUTHORITY_OPERATION_FAMILY_COMPLETION)?;
        let source = self
            .config
            .trusted_source_by_id(&request.caller.service_id)
            .ok_or_else(|| AuthorityServiceError::NotAuthorized {
                caller: request.caller.service_id.clone(),
                operation: AUTHORITY_OPERATION_FAMILY_COMPLETION,
            })?;
        if !source
            .allowed_database_ids
            .iter()
            .any(|database| database == &request.database_id)
        {
            return Err(AuthorityServiceError::NotAuthorized {
                caller: request.database_id.clone(),
                operation: AUTHORITY_OPERATION_FAMILY_COMPLETION,
            });
        }
        request
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        let reservation_record = self
            .store
            .get(&self.keys.reservation(&request.reservation_id))
            .await?
            .ok_or(AuthorityServiceError::Protocol(
                AuthorityProtocolError::NotFound {
                    record: "reservation",
                },
            ))?;
        let reservation: AuthorityScopeReservation =
            decode(&reservation_record.value, "reservation")?;
        reservation
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        if !reservation.intent.coverage.is_global() {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::InvalidCoverage,
            ));
        }
        if reservation.intent.service_id != request.caller.service_id
            || reservation.intent.database_id != request.database_id
            || reservation.intent.operation_id != request.operation_id
            || reservation.intent.mutation_kind != AuthorityMutationKind::AuthorizationSource
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch,
            ));
        }
        let binding_record = self
            .store
            .get(&self.keys.commit_binding(&reservation.reservation_id))
            .await?
            .ok_or_else(|| {
                AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "family completion reconciliation source commit binding is missing".into(),
                ))
            })?;
        let binding: astral_types::AuthorityCommitBinding =
            decode(&binding_record.value, "source commit binding")?;
        binding
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        if binding.reservation_id != reservation.reservation_id
            || binding.operation_id != request.operation_id
            || binding.event_id != reservation.intent.event_id
            || binding.database_id != request.database_id
            || binding.service_id != request.caller.service_id
            || reservation.source_commit_digest.as_deref()
                != Some(binding.source_commit_digest.as_str())
            || reservation.source_outcome_digest.as_deref()
                != Some(binding.source_outcome_digest.as_str())
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch,
            ));
        }
        let family = request.family.as_text();
        let receipt_record = self
            .store
            .get(&self.keys.family_completion(&request.reservation_id, family))
            .await?;
        let operation_record = self
            .store
            .get(
                &self
                    .keys
                    .family_completion_operation(&request.operation_id, family),
            )
            .await?;
        let receipt = match (receipt_record, operation_record) {
            (None, None) => None,
            (Some(_), None) | (None, Some(_)) => {
                return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "family completion receipt indexes are incomplete".into(),
                )))
            }
            (Some(reservation_record), Some(operation_record)) => {
                let reservation_receipt: AuthorityFamilyCompletionReceipt =
                    decode(&reservation_record.value, "family completion receipt")?;
                let operation_receipt: AuthorityFamilyCompletionReceipt = decode(
                    &operation_record.value,
                    "family completion operation receipt",
                )?;
                reservation_receipt
                    .validate()
                    .map_err(AuthorityServiceError::Protocol)?;
                operation_receipt
                    .validate()
                    .map_err(AuthorityServiceError::Protocol)?;
                if reservation_receipt != operation_receipt {
                    return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                        "family completion receipt indexes disagree".into(),
                    )));
                }
                let receipt = reservation_receipt;
                if receipt.completion.family != request.family
                    || receipt.completion.reservation_id != request.reservation_id
                    || receipt.completion.operation_id != request.operation_id
                    || receipt.completion.event_id != binding.event_id
                    || receipt.completion.source_commit_digest
                        != reservation.source_commit_digest.clone().unwrap_or_default()
                    || receipt.completion.source_outcome_digest
                        != reservation
                            .source_outcome_digest
                            .clone()
                            .unwrap_or_default()
                {
                    return Err(AuthorityServiceError::Protocol(
                        AuthorityProtocolError::ScopeMismatch,
                    ));
                }
                Some(receipt)
            }
        };
        let state = self.load_verified_state().await?;
        if let Some(receipt) = &receipt {
            state.verify_historical_frontier(&receipt.global_frontier)?;
        }
        let global_frontier = receipt
            .as_ref()
            .map(|receipt| receipt.global_frontier.clone())
            .unwrap_or_else(|| state.frontier.clone());
        let read_gate = self.evaluate_read_gate().await?;
        let response = AuthorityFamilyCompletionReconcileResponse {
            reservation,
            receipt,
            global_frontier,
            read_gate,
        };
        response
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        Ok(response)
    }

    pub async fn record_family_completion(
        &self,
        request: &AuthorityFamilyCompletionRequest,
    ) -> Result<AuthorityFamilyCompletionResponse, AuthorityServiceError> {
        self.authorize(&request.caller, AUTHORITY_OPERATION_FAMILY_COMPLETION)?;
        let source = self
            .config
            .trusted_source_by_id(&request.caller.service_id)
            .ok_or_else(|| AuthorityServiceError::NotAuthorized {
                caller: request.caller.service_id.clone(),
                operation: AUTHORITY_OPERATION_FAMILY_COMPLETION,
            })?;
        if !source
            .allowed_database_ids
            .iter()
            .any(|database| database == &request.database_id)
        {
            return Err(AuthorityServiceError::NotAuthorized {
                caller: request.database_id.clone(),
                operation: AUTHORITY_OPERATION_FAMILY_COMPLETION,
            });
        }
        request
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;

        let reservation_record = self
            .store
            .get(&self.keys.reservation(&request.completion.reservation_id))
            .await?
            .ok_or(AuthorityServiceError::Protocol(
                AuthorityProtocolError::NotFound {
                    record: "reservation",
                },
            ))?;
        let reservation: AuthorityScopeReservation =
            decode(&reservation_record.value, "reservation")?;
        reservation
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        if !reservation.intent.coverage.is_global() {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::InvalidCoverage,
            ));
        }
        if reservation.intent.service_id != request.caller.service_id
            || reservation.intent.database_id != request.database_id
            || reservation.intent.operation_id != request.completion.operation_id
            || reservation.intent.event_id != request.completion.event_id
            || reservation.intent.mutation_kind != AuthorityMutationKind::AuthorizationSource
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch,
            ));
        }
        if reservation.source_commit_digest.as_deref()
            != Some(request.completion.source_commit_digest.as_str())
            || reservation.source_outcome_digest.as_deref()
                != Some(request.completion.source_outcome_digest.as_str())
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::DigestMismatch {
                    field: "source_binding",
                },
            ));
        }
        let binding_record = self
            .store
            .get(&self.keys.commit_binding(&reservation.reservation_id))
            .await?
            .ok_or_else(|| {
                AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "family completion source commit binding is missing".into(),
                ))
            })?;
        let binding: astral_types::AuthorityCommitBinding =
            decode(&binding_record.value, "source commit binding")?;
        binding
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        if binding.reservation_id != reservation.reservation_id
            || binding.operation_id != request.completion.operation_id
            || binding.event_id != request.completion.event_id
            || binding.database_id != request.database_id
            || binding.service_id != request.caller.service_id
            || binding.source_commit_digest != request.completion.source_commit_digest
            || binding.source_outcome_digest != request.completion.source_outcome_digest
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch,
            ));
        }
        request
            .completion
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;

        let family = request.completion.family.as_text();
        let operation_key = self
            .keys
            .family_completion_operation(&request.completion.operation_id, family);
        let receipt_key = self
            .keys
            .family_completion(&reservation.reservation_id, family);
        let operation_record = self.store.get(&operation_key).await?;
        let receipt_record = self.store.get(&receipt_key).await?;

        // A durable receipt is immutable and read-only replayable. Look it up
        // before leader/state mutation checks so failover or a later reservation
        // transition cannot turn an already proven completion into UNKNOWN.
        if operation_record.is_some() || receipt_record.is_some() {
            let (Some(operation_record), Some(receipt_record)) = (operation_record, receipt_record)
            else {
                return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "family completion receipt indexes are incomplete".into(),
                )));
            };
            let operation_receipt: AuthorityFamilyCompletionReceipt = decode(
                &operation_record.value,
                "family completion operation receipt",
            )?;
            let reservation_receipt: AuthorityFamilyCompletionReceipt =
                decode(&receipt_record.value, "family completion receipt")?;
            operation_receipt
                .validate()
                .map_err(AuthorityServiceError::Protocol)?;
            reservation_receipt
                .validate()
                .map_err(AuthorityServiceError::Protocol)?;
            if operation_receipt != reservation_receipt {
                return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "family completion receipt indexes disagree".into(),
                )));
            }
            let receipt = reservation_receipt;
            let expected = request
                .completion
                .clone()
                .into_receipted_completion(receipt.receipt_id.clone())
                .map_err(AuthorityServiceError::Protocol)?;
            if receipt.completion != expected {
                return Err(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::DigestMismatch {
                        field: "family_completion_request",
                    },
                ));
            }
            let state = self.load_verified_state().await?;
            state.verify_historical_frontier(&receipt.global_frontier)?;
            if receipt.global_frontier.authority_id != state.frontier.authority_id
                || receipt.global_frontier.authority_term > state.frontier.authority_term
                || receipt.global_frontier.global_fence_sequence
                    > state.frontier.global_fence_sequence
            {
                return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "family completion receipt frontier is not in authority history".to_owned(),
                )));
            }
            let mut response_reservation = reservation;
            if response_reservation.state == AuthorityReservationState::Committed {
                if let Some((certified, _aggregate_frontier)) = self
                    .try_finalize_family_aggregate(
                        &reservation_record,
                        &response_reservation,
                        &state,
                        now_unix(),
                    )
                    .await?
                {
                    response_reservation = certified;
                }
            }
            let read_gate = self.evaluate_read_gate().await?;
            let response = AuthorityFamilyCompletionResponse {
                disposition: AuthorityReservationDisposition::from_reservation(
                    &response_reservation,
                ),
                reservation: response_reservation,
                global_frontier: receipt.global_frontier.clone(),
                read_gate,
                receipt,
            };

            response
                .validate()
                .map_err(AuthorityServiceError::Protocol)?;
            return Ok(response);
        }

        self.require_leader()?;
        if reservation.state != AuthorityReservationState::Committed {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch,
            ));
        }

        if !source_owned_family_completeness_verified() {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "family_completion",
                    state: "SOURCE_COMPLETENESS_UNVERIFIED".into(),
                },
            ));
        }

        let state = self.load_verified_state().await?;
        let now = now_unix();
        let receipt_id = fresh_id("family");
        let completion = request
            .completion
            .clone()
            .into_receipted_completion(receipt_id.clone())
            .map_err(AuthorityServiceError::Protocol)?;
        let completion_digest = completion
            .completion_digest()
            .map_err(AuthorityServiceError::Protocol)?;
        let next_frontier = state
            .frontier
            .advance(
                &request.completion.operation_id,
                &mutation_digest("family-completion", &completion_digest),
                now,
            )
            .map_err(AuthorityServiceError::Protocol)?;
        let receipt = AuthorityFamilyCompletionReceipt {
            receipt_id,
            completion,
            completed_at: now,
            global_frontier: next_frontier.clone(),
        };
        receipt
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        let txn = StoreTxn::new()
            .with_op(StoreOp::PutIfAbsent {
                key: receipt_key,
                value: encode(&receipt)?,
            })
            .with_op(StoreOp::PutIfAbsent {
                key: operation_key,
                value: encode(&receipt)?,
            })
            .with_op(StoreOp::ReplaceIfRevision {
                key: self.keys.frontier(),
                expected_revision: state.frontier_revision,
                value: encode(&next_frontier)?,
            })
            .with_op(self.bump_gate_epoch_op(&state)?);
        let outcome = self
            .execute_leader_txn(txn)
            .await
            .map_err(|error| self.map_store_error(error, &request.completion.operation_id))?;
        match outcome {
            StoreTxnOutcome::PreconditionFailed { .. } => Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "family_completion",
                    state: "CONCURRENT".into(),
                },
            )),
            StoreTxnOutcome::Applied { .. } => {
                let mut response_reservation = reservation;
                if let Some(updated_record) = self
                    .store
                    .get(&self.keys.reservation(&request.completion.reservation_id))
                    .await?
                {
                    let updated_reservation: AuthorityScopeReservation =
                        decode(&updated_record.value, "reservation")?;
                    updated_reservation
                        .validate()
                        .map_err(AuthorityServiceError::Protocol)?;
                    let updated_state = self.load_verified_state().await?;
                    if let Some((certified, _aggregate_frontier)) = self
                        .try_finalize_family_aggregate(
                            &updated_record,
                            &updated_reservation,
                            &updated_state,
                            now_unix(),
                        )
                        .await?
                    {
                        response_reservation = certified;
                    } else {
                        response_reservation = updated_reservation;
                    }
                }
                let read_gate = self.evaluate_read_gate().await?;
                let response = AuthorityFamilyCompletionResponse {
                    disposition: AuthorityReservationDisposition::from_reservation(
                        &response_reservation,
                    ),
                    reservation: response_reservation,
                    global_frontier: next_frontier,
                    read_gate,
                    receipt,
                };
                response
                    .validate()
                    .map_err(AuthorityServiceError::Protocol)?;
                Ok(response)
            }
        }
    }
}
