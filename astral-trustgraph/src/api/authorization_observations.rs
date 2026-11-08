//! Read-only, tenant-scoped S15 production observation endpoint.
//!
//! This route reports durable evidence planes independently. It never evaluates
//! policy, calls the authority, mutates data, or interprets HTTP success as ALLOW.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use astral_common::contract::ApiResponse;
use astral_common::error::AppError;
use astral_db::authority_source_outcome::{
    canonical_outcome_digest, AuthoritySourceOutcomeRecord, AuthoritySourceOutcomeStaged,
    AuthoritySourceReceiptIdentity,
};
use astral_db::DeltaSourceOutcomeEvidence;
use astral_types::{
    AstralError, AuthorityConfigSourceImage, AuthorityMutationKind, AuthorityStagedSourceEvidence,
    AuthorizationMessageMetadata, PolicyContext, PublishedEvidenceAggregate,
    ResourceOwnershipScope,
};
use axum::extract::{Extension, RawQuery, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;

use crate::AppState;

const ROUTE: &str = "/authorization-observations/s15";
const READ_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_STAGED_EVIDENCE_BYTES: usize = 256 * 1024;
const MAX_RECEIPTS: usize = 1024;
const MAX_AUDIT_ROWS: usize = 64;
const SCHEMA: &str = "astral.s15.authorization-observation/v1";
const SOURCE_SCOPE_BINDING_NOT_PROVEN: &str = "source_outcome_scope_not_proven";
const AUTHORITY_RECEIPT_NOT_VERIFIED: &str = "authority_acceptance_receipt_not_verified";

pub fn authorization_observation_routes() -> Router<AppState> {
    Router::new().route(ROUTE, get(observe_s15))
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ObservationQuery {
    run_id: String,
    operation_id: String,
    reservation_id: String,
    message_id: String,
    tenant_id: i64,
    card_id: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceStatus {
    Proven,
    Pending,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourcePhase {
    Staged,
    SourceCommitDurable,
    AuthorityCommitted,
    Published,
    Completed,
    Quarantined,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObservationCorrelation {
    /// Caller-supplied harness identity; the source schema does not persist it.
    pub run_id: String,
    pub run_id_binding: EvidenceStatus,
    pub operation_id: String,
    pub reservation_id: String,
    pub message_id: String,
    pub tenant_id: i64,
    pub card_id: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceObservation {
    pub status: EvidenceStatus,
    pub authority_commit_status: EvidenceStatus,
    /// The local source row is not an independently verified authority receipt.
    pub authority_commit_reason_code: Option<&'static str>,
    pub phase: SourcePhase,
    pub owner_identity_status: EvidenceStatus,
    pub reservation_id: Option<String>,
    pub operation_id: Option<String>,
    pub event_id: Option<String>,
    pub admission_proof_id: Option<String>,
    pub mutation_kind: Option<String>,
    pub service_id: Option<String>,
    pub database_id: Option<String>,
    pub request_binding_digest: Option<String>,
    pub source_commit_digest: Option<String>,
    pub before_image_digest: Option<String>,
    pub after_image_digest: Option<String>,
    pub outcome_digest: Option<String>,
    pub source_generation: Option<u64>,
    pub revoke_fence: Option<u64>,
    pub lease_generation: Option<u64>,
    pub committed_at_unix_seconds: Option<i64>,
    pub reason_code: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageObservation {
    pub status: EvidenceStatus,
    pub message_id: Option<String>,
    pub operation_id: Option<String>,
    pub tenant_id: Option<i64>,
    pub payload_digest: Option<String>,
    pub durable_state: Option<String>,
    pub observed_at_unix_ms: Option<i64>,
    pub reason_code: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditObservation {
    pub status: EvidenceStatus,
    pub receipt_count: Option<usize>,
    pub exact_receipts_verified: Option<bool>,
    pub observed_at_unix_ms: Option<i64>,
    pub reason_code: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadGateObservation {
    pub status: EvidenceStatus,
    pub positive_authorization_ready: Option<bool>,
    pub hub_authority_state: Option<String>,
    pub observed_at_unix_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LivenessObservation {
    pub status: EvidenceStatus,
    pub process_reached_handler: bool,
    pub observed_at_unix_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityFrontierObservation {
    pub status: EvidenceStatus,
    pub reason_code: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentObservation {
    pub node_identity_status: EvidenceStatus,
    pub region_id: Option<String>,
    pub node_id: Option<String>,
    /// No production S15 node-to-half/controller registry is wired into this route.
    pub topology_status: EvidenceStatus,
    pub half: Option<String>,
    pub controller: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct S15AuthorizationObservation {
    pub schema: &'static str,
    pub correlation: ObservationCorrelation,
    pub observed_at_unix_ms: i64,
    pub source: SourceObservation,
    pub outbox: MessageObservation,
    pub inbox: MessageObservation,
    pub audit: AuditObservation,
    pub read_gate: ReadGateObservation,
    pub liveness: LivenessObservation,
    pub authority_frontier: AuthorityFrontierObservation,
    pub deployment: DeploymentObservation,
}

#[derive(Debug, FromRow)]
struct SourceOutcomeDbRow {
    reservation_id: String,
    operation_id: String,
    event_id: String,
    admission_proof_id: String,
    request_binding_digest: String,
    mutation_kind: String,
    service_id: String,
    database_id: String,
    source_commit_digest: Option<String>,
    before_image_digest: Option<String>,
    after_image_digest: Option<String>,
    source_receipts: Option<String>,
    staged_evidence: Option<String>,
    status: String,
    generation: u64,
    outcome_digest: String,
    committed_at: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceBatchEvidence {
    #[serde(default)]
    delta: Option<DeltaSourceOutcomeEvidence>,
    #[serde(default)]
    source_images: Vec<AuthorityConfigSourceImage>,
    #[serde(default)]
    audits: Vec<astral_types::AuthorityConfigAudit>,
    #[serde(default)]
    source_projection: Vec<SourceProjectionEvidence>,
    #[serde(default)]
    invalidations: Vec<InvalidationEvidence>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    payload: Value,
}

#[derive(Debug, Clone, FromRow)]
struct SourceProjectionDbRow {
    outbox_id: i64,
    event_id: String,
    aggregate_type: String,
    aggregate_id: i64,
    tenant_id: Option<i64>,
    event_type: String,
    source_generation: i64,
    sequence_number: i64,
    revoke_fence: i64,
    payload_json: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InvalidationEvidence {
    message_id: String,
    operation_id: String,
    queue_name: String,
    envelope: StrictMessageEnvelope,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StrictMessageEnvelope {
    message_id: String,
    operation_id: String,
    message_type: String,
    schema_version: i32,
    tenant_id: Option<i64>,
    origin_region: String,
    target_region: Option<String>,
    ordering_key: Option<String>,
    trace_id: Option<String>,
    created_at: String,
    expires_at: Option<String>,
    payload_sha256: String,
    #[serde(default)]
    authority_metadata: Option<AuthorizationMessageMetadata>,
    payload: Value,
}

impl StrictMessageEnvelope {
    fn into_message_envelope(self) -> astral_mq::MessageEnvelope {
        astral_mq::MessageEnvelope {
            message_id: self.message_id,
            operation_id: self.operation_id,
            message_type: self.message_type,
            schema_version: self.schema_version,
            tenant_id: self.tenant_id,
            origin_region: self.origin_region,
            target_region: self.target_region,
            ordering_key: self.ordering_key,
            trace_id: self.trace_id,
            created_at: self.created_at,
            expires_at: self.expires_at,
            payload_sha256: self.payload_sha256,
            authority_metadata: self.authority_metadata,
            payload: self.payload,
        }
    }
}

#[derive(Debug, FromRow)]
struct OutboxDbRow {
    message_id: String,
    operation_id: String,
    message_type: String,
    queue_name: String,
    tenant_id: Option<i64>,
    origin_region: String,
    target_region: Option<String>,
    ordering_key: Option<String>,
    schema_version: i32,
    payload_json: String,
    payload_sha256: String,
    authority_metadata_json: Option<String>,
    status: String,
    observed_at_unix_ms: i64,
}

#[derive(Debug, FromRow)]
struct InboxDbRow {
    message_id: String,
    operation_id: String,
    tenant_id: Option<i64>,
    payload_sha256: String,
    status: String,
    observed_at_unix_ms: i64,
}

#[derive(Debug, FromRow)]
struct AuditDbRow {
    id: i64,
    user_id: i64,
    action: String,
    resource: String,
    decision: String,
    event_type: Option<String>,
    request_id: Option<String>,
    tenant_id: Option<i64>,
    card_id: Option<i64>,
}

struct VerifiedSource {
    observation: SourceObservation,
    envelope: Option<AuthorityStagedSourceEvidence>,
    batch: Option<SourceBatchEvidence>,
}

async fn observe_s15(
    State(state): State<AppState>,
    Extension(policy): Extension<PolicyContext>,
    RawQuery(raw_query): RawQuery,
) -> Result<Json<ApiResponse<S15AuthorizationObservation>>, AppError> {
    let query = parse_query(raw_query.as_deref()).map_err(|code| {
        AppError(AstralError::Validation(format!(
            "invalid observation query: {code}"
        )))
    })?;
    validate_policy_scope(&policy, &query)?;

    let started = Instant::now();
    let observed_at = unix_time_ms();
    let result =
        tokio::time::timeout(READ_TIMEOUT, load_observation(&state, &query, observed_at)).await;
    let observation = match result {
        Ok(observation) => observation,
        Err(_) => unknown_observation(&state, &query, observed_at, "observation_deadline_exceeded"),
    };
    tracing::info!(
        phase = "authorization_observation_complete",
        elapsed_ms = started.elapsed().as_millis() as u64,
        retry_count = 0u8,
        stream_disconnect = false,
        "S15 read-only authorization observation completed"
    );
    Ok(Json(ApiResponse::success(observation)))
}

fn validate_policy_scope(policy: &PolicyContext, query: &ObservationQuery) -> Result<(), AppError> {
    let matches = policy.resource.as_deref() == Some("monitor")
        && policy.action == "read"
        && policy.resource_ownership_scope == ResourceOwnershipScope::TenantScoped
        && policy.resource_tenant_id == Some(query.tenant_id)
        && policy.target_id == Some(query.card_id);
    if matches {
        Ok(())
    } else {
        Err(AppError(AstralError::Permission(
            "observation target does not match verified tenant-scoped policy ownership".into(),
        )))
    }
}

fn parse_query(raw: Option<&str>) -> Result<ObservationQuery, &'static str> {
    let raw = raw.ok_or("query_required")?;
    if raw.is_empty() || raw.len() > 512 {
        return Err("query_size");
    }
    let allowed: BTreeSet<&str> = [
        "runId",
        "operationId",
        "reservationId",
        "messageId",
        "tenantId",
        "cardId",
    ]
    .into_iter()
    .collect();
    let mut values = BTreeMap::new();
    for pair in raw.split('&') {
        let (key, value) = pair.split_once('=').ok_or("query_pair")?;
        if !allowed.contains(key) || value.is_empty() || values.contains_key(key) {
            return Err("query_key_or_duplicate");
        }
        if !value.is_ascii()
            || value
                .bytes()
                .any(|byte| byte == b'%' || byte == b'+' || byte.is_ascii_whitespace())
        {
            return Err("query_value_encoding");
        }
        values.insert(key, value);
    }
    if values.len() != allowed.len() {
        return Err("query_fields_missing");
    }
    let run_id = values["runId"];
    let suffix = run_id
        .strip_prefix("authz-validation-")
        .ok_or("run_id_format")?;
    if suffix.is_empty()
        || suffix.len() > 64
        || !suffix.as_bytes()[0].is_ascii_alphanumeric()
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("run_id_format");
    }
    // The V7 request/protocol identity ceiling is 128 bytes; the current
    // authority_source_outcome table is narrower (VARCHAR(64)), so longer
    // identities will simply have no matching local outcome. Never truncate.
    let operation_id =
        canonical_text(values["operationId"], 128, true).ok_or("operation_id_format")?;
    let reservation_id =
        canonical_text(values["reservationId"], 128, true).ok_or("reservation_id_format")?;
    let message_id = canonical_text(values["messageId"], 128, true).ok_or("message_id_format")?;
    let tenant_id = canonical_positive_i64(values["tenantId"]).ok_or("tenant_id_format")?;
    let card_id = canonical_positive_i64(values["cardId"]).ok_or("card_id_format")?;
    Ok(ObservationQuery {
        run_id: run_id.to_owned(),
        operation_id: operation_id.to_owned(),
        reservation_id: reservation_id.to_owned(),
        message_id: message_id.to_owned(),
        tenant_id,
        card_id,
    })
}

fn canonical_text(value: &str, max: usize, allow_slash: bool) -> Option<&str> {
    if value.is_empty()
        || value.len() > max
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':')
                || (allow_slash && byte == b'/')
        })
    {
        None
    } else {
        Some(value)
    }
}

fn canonical_positive_i64(value: &str) -> Option<i64> {
    let parsed = value.parse::<i64>().ok().filter(|number| *number > 0)?;
    (parsed.to_string() == value).then_some(parsed)
}

async fn load_observation(
    state: &AppState,
    query: &ObservationQuery,
    observed_at: i64,
) -> S15AuthorizationObservation {
    let source = match load_source(&state.db, query).await {
        Ok(source) => source,
        Err(reason) => VerifiedSource::unknown(query, reason),
    };
    let mut outbox = MessageObservation::unknown("source_message_binding_unavailable");
    let mut inbox = MessageObservation::unknown("trusted_node_or_message_binding_unavailable");
    let mut audit = AuditObservation::unknown("typed_audit_binding_unavailable");

    if source.observation.status == EvidenceStatus::Proven {
        if let (Some(batch), Some(envelope)) = (&source.batch, &source.envelope) {
            if let Some(invalidation) = exact_invalidation(batch, query) {
                outbox = match load_outbox_batch(&state.db, query, batch).await {
                    Ok(rows) => rows
                        .into_iter()
                        .find(|row| row.message_id == invalidation.message_id)
                        .map(|row| {
                            outbox_message_observation(&row)
                                .unwrap_or_else(MessageObservation::unknown)
                        })
                        .unwrap_or_else(|| {
                            MessageObservation::unknown("outbox_target_row_missing_or_mismatch")
                        }),
                    Err(reason) => MessageObservation::unknown(reason),
                };
                if outbox.status == EvidenceStatus::Proven {
                    inbox = load_inbox(&state.db, state, query, &outbox).await;
                }
            }
            audit = load_audits(&state.db, query, &source.observation, batch).await;
            let _retained_staged_evidence_is_digest_bound = envelope.validate().is_ok();
        }
    }

    let hub = astral_db::memory_projection_hub::memory_projection_hub();
    let (read_gate_status, ready, hub_state) = match hub {
        Some(hub) => {
            let ready = hub.positive_authorization_ready();
            (
                if ready {
                    EvidenceStatus::Proven
                } else {
                    EvidenceStatus::Pending
                },
                Some(ready),
                Some(format!("{:?}", hub.authority_state())),
            )
        }
        None => (EvidenceStatus::Unknown, None, None),
    };
    let deployment = deployment_observation(state);
    let correlation = ObservationCorrelation {
        run_id: query.run_id.clone(),
        // runId is supplied by the harness and is intentionally not treated as a
        // permission fact or source-side durable correlation.
        run_id_binding: EvidenceStatus::Unknown,
        operation_id: query.operation_id.clone(),
        reservation_id: query.reservation_id.clone(),
        message_id: query.message_id.clone(),
        tenant_id: query.tenant_id,
        card_id: query.card_id,
    };
    S15AuthorizationObservation {
        schema: SCHEMA,
        correlation,
        observed_at_unix_ms: observed_at,
        source: source.observation,
        outbox,
        inbox,
        audit,
        read_gate: ReadGateObservation {
            status: read_gate_status,
            positive_authorization_ready: ready,
            hub_authority_state: hub_state,
            observed_at_unix_ms: observed_at,
        },
        liveness: LivenessObservation {
            status: EvidenceStatus::Proven,
            process_reached_handler: true,
            observed_at_unix_ms: observed_at,
        },
        authority_frontier: AuthorityFrontierObservation {
            status: EvidenceStatus::Unknown,
            reason_code: "frontier_requires_separate_s15_authority_client_observation",
        },
        deployment,
    }
}

async fn load_source(
    pool: &sqlx::MySqlPool,
    query: &ObservationQuery,
) -> Result<VerifiedSource, &'static str> {
    let rows: Vec<SourceOutcomeDbRow> = sqlx::query_as(
        "SELECT reservation_id, operation_id, event_id, admission_proof_id, \
         LOWER(HEX(request_binding_digest)) AS request_binding_digest, mutation_kind, \
         service_id, database_id, LOWER(HEX(source_commit_digest)) AS source_commit_digest, \
         LOWER(HEX(before_image_digest)) AS before_image_digest, \
         LOWER(HEX(after_image_digest)) AS after_image_digest, \
         CAST(source_receipts AS CHAR) AS source_receipts, \
         CAST(staged_evidence AS CHAR) AS staged_evidence, status, generation, \
         LOWER(HEX(outcome_digest)) AS outcome_digest, committed_at \
         FROM authority_source_outcome \
         WHERE reservation_id = ? AND operation_id = ? \
           AND JSON_CONTAINS( \
             JSON_EXTRACT(staged_evidence, '$.evidence.delta.events'), \
             JSON_OBJECT('tenantId', ?, 'cardId', ?) \
           ) = 1 \
         LIMIT 2",
    )
    .bind(&query.reservation_id)
    .bind(&query.operation_id)
    .bind(query.tenant_id)
    .bind(query.card_id)
    .fetch_all(pool)
    .await
    .map_err(|_| "source_outcome_query_unavailable")?;
    if rows.is_empty() {
        return Err("source_outcome_exact_scoped_row_not_found");
    }
    if rows.len() != 1 {
        return Err("source_outcome_ambiguous");
    }
    let row = rows.into_iter().next().expect("one row checked");
    if row.reservation_id != query.reservation_id || row.operation_id != query.operation_id {
        return Err("source_outcome_binding_mismatch");
    }
    let staged_json = row
        .staged_evidence
        .as_deref()
        .filter(|value| !value.is_empty() && value.len() <= MAX_STAGED_EVIDENCE_BYTES)
        .ok_or("source_staged_evidence_missing_or_oversized")?;
    let envelope: AuthorityStagedSourceEvidence = serde_json::from_str(staged_json)
        .map_err(|_| "source_staged_evidence_not_closed_typed_json")?;
    envelope
        .validate()
        .map_err(|_| "source_staged_evidence_invalid")?;
    let batch = parse_observer_source_batch(&envelope)?;
    if let Err(code) = verify_row_scope_binding(&row, &envelope, &batch, query) {
        return Ok(VerifiedSource::unknown(query, code));
    }
    if let Some(batch) = batch.as_ref() {
        if let Err(code) = verify_source_projection_rows(pool, batch).await {
            return Ok(VerifiedSource::unknown(query, code));
        }
    }
    let (mut status, phase, _) = verify_source_row(&row, staged_json)?;
    let (source_generation, revoke_fence) =
        match verify_card_scope(&row, &envelope, batch.as_ref(), query) {
            Ok(scope) => scope,
            Err(code) => {
                return Ok(VerifiedSource::unknown(query, code));
            }
        };
    let owner_identity_status = trusted_owner_matches(&row.service_id, &row.database_id);
    let reason_code = if owner_identity_status != EvidenceStatus::Proven {
        status = EvidenceStatus::Unknown;
        Some("registered_source_owner_identity_unavailable_or_mismatched")
    } else {
        None
    };
    if status != EvidenceStatus::Proven {
        // Keep only the caller's correlation tuple; a local source row whose
        // complete scope/owner binding is not proven must not leak its fields.
        return Ok(VerifiedSource::unknown(
            query,
            reason_code.unwrap_or("source_outcome_not_committed"),
        ));
    }
    let observation = SourceObservation {
        status,
        // Local status and outcome digest prove only this source DB record. They
        // are not an immutable, independently verified authority acceptance.
        authority_commit_status: EvidenceStatus::Unknown,
        authority_commit_reason_code: Some(AUTHORITY_RECEIPT_NOT_VERIFIED),
        phase,
        owner_identity_status,
        reservation_id: Some(row.reservation_id.clone()),
        operation_id: Some(row.operation_id.clone()),
        event_id: Some(row.event_id.clone()),
        admission_proof_id: Some(row.admission_proof_id.clone()),
        mutation_kind: Some(row.mutation_kind.clone()),
        service_id: Some(row.service_id.clone()),
        database_id: Some(row.database_id.clone()),
        request_binding_digest: Some(row.request_binding_digest.clone()),
        source_commit_digest: row.source_commit_digest.clone(),
        before_image_digest: row.before_image_digest.clone(),
        after_image_digest: row.after_image_digest.clone(),
        outcome_digest: Some(row.outcome_digest.clone()),
        source_generation,
        revoke_fence,
        lease_generation: Some(row.generation),
        committed_at_unix_seconds: Some(row.committed_at),
        reason_code: None,
    };
    Ok(VerifiedSource {
        observation,
        envelope: Some(envelope),
        batch,
    })
}

fn parse_observer_source_batch(
    envelope: &AuthorityStagedSourceEvidence,
) -> Result<Option<SourceBatchEvidence>, &'static str> {
    let evidence = &envelope.evidence;
    if let Some(images) = evidence.get("sourceImages") {
        if !images.as_array().is_some_and(Vec::is_empty) {
            return Err("typed_source_images_not_supported_by_delta_observer");
        }
    }
    if evidence.get("kind").is_some() || evidence.get("sourceBatch").is_some() {
        return Err("typed_source_evidence_requires_shared_contract_observer");
    }
    match serde_json::from_value::<SourceBatchEvidence>(evidence.clone()) {
        Ok(batch) if batch.delta.is_some() => Ok(Some(batch)),
        Ok(_) => Err("source_delta_evidence_missing"),
        Err(_) => Err("source_delta_evidence_not_closed_typed_json"),
    }
}

fn verify_row_scope_binding(
    row: &SourceOutcomeDbRow,
    staged: &AuthorityStagedSourceEvidence,
    batch: &Option<SourceBatchEvidence>,
    query: &ObservationQuery,
) -> Result<(), &'static str> {
    if row.reservation_id != query.reservation_id || row.operation_id != query.operation_id {
        return Err("source_reservation_operation_binding_mismatch");
    }
    let batch = batch
        .as_ref()
        .ok_or("source_evidence_schema_not_supported_by_observer")?;
    let delta = batch
        .delta
        .as_ref()
        .ok_or("source_delta_evidence_missing")?;
    if delta.events.is_empty() || delta.events.len() > MAX_RECEIPTS {
        return Err("source_delta_event_capacity_invalid");
    }
    let matching_events: Vec<_> = delta
        .events
        .iter()
        .filter(|event| {
            event.operation_id == query.operation_id
                && event.event_id == row.event_id
                && event.tenant_id == query.tenant_id
                && event.card_id == Some(query.card_id)
        })
        .collect();
    if matching_events.len() != 1 {
        return Err("source_exact_tenant_card_operation_event_not_bound");
    }
    let exact = exact_invalidation(batch, query).ok_or("source_message_binding_unknown")?;
    let envelope = exact.envelope.clone().into_message_envelope();
    let invalidation = astral_mq::InvalidationEvent::from_envelope(&envelope)
        .map_err(|_| "source_invalidation_envelope_invalid")?;
    if !matches!(
        invalidation,
        astral_mq::InvalidationEvent::EvidenceInvalidated(value)
            if value.tenant_id == query.tenant_id
                && value.card_id == Some(query.card_id)
                && value.aggregate_type == PublishedEvidenceAggregate::UserCard
                && value.aggregate_id == query.card_id
    ) {
        return Err("source_message_scope_or_fence_mismatch");
    }
    let coverage = delta
        .complete_card_coverage()
        .map_err(|_| "source_card_coverage_invalid")?
        .ok_or("source_card_coverage_incomplete")?;
    if staged.coverage.as_ref() != Some(&coverage) {
        return Err("source_card_coverage_binding_mismatch");
    }
    Ok(())
}

async fn verify_source_projection_rows(
    pool: &sqlx::MySqlPool,
    batch: &SourceBatchEvidence,
) -> Result<(), &'static str> {
    let mut seen_outbox_ids = BTreeSet::new();
    for expected in &batch.source_projection {
        if expected.outbox_id <= 0 || !seen_outbox_ids.insert(expected.outbox_id) {
            return Err(SOURCE_SCOPE_BINDING_NOT_PROVEN);
        }
        let rows: Vec<SourceProjectionDbRow> = sqlx::query_as(
            "SELECT outbox_id, event_id, aggregate_type, aggregate_id, tenant_id, event_type, \
             source_generation, sequence_number, revoke_fence, CAST(payload_json AS CHAR) AS payload_json \
             FROM authorization_projection_outbox WHERE outbox_id = ? LIMIT 2",
        )
        .bind(expected.outbox_id)
        .fetch_all(pool)
        .await
        .map_err(|_| SOURCE_SCOPE_BINDING_NOT_PROVEN)?;
        if rows.len() != 1 {
            return Err(SOURCE_SCOPE_BINDING_NOT_PROVEN);
        }
        let row = rows.into_iter().next().expect("one row checked");
        let payload = row
            .payload_json
            .as_deref()
            .ok_or(SOURCE_SCOPE_BINDING_NOT_PROVEN)
            .and_then(|payload| {
                serde_json::from_str::<Value>(payload).map_err(|_| SOURCE_SCOPE_BINDING_NOT_PROVEN)
            })?;
        if !source_projection_matches(expected, &row, &payload) {
            return Err(SOURCE_SCOPE_BINDING_NOT_PROVEN);
        }
    }
    Ok(())
}

fn source_projection_matches(
    expected: &SourceProjectionEvidence,
    actual: &SourceProjectionDbRow,
    actual_payload: &Value,
) -> bool {
    actual.outbox_id == expected.outbox_id
        && actual.event_id == expected.event_id
        && actual.aggregate_type == expected.aggregate_type
        && actual.aggregate_id == expected.aggregate_id
        && actual.tenant_id == expected.tenant_id
        && actual.event_type == expected.event_type
        && actual.source_generation == expected.source_generation
        && actual.sequence_number == expected.sequence_number
        && actual.revoke_fence == expected.revoke_fence
        && actual_payload == &expected.payload
}

fn verify_source_row(
    row: &SourceOutcomeDbRow,
    staged_json: &str,
) -> Result<(EvidenceStatus, SourcePhase, EvidenceStatus), &'static str> {
    let kind =
        AuthorityMutationKind::parse(&row.mutation_kind).ok_or("source_mutation_kind_unknown")?;
    if !valid_sha256(&row.request_binding_digest) || !valid_sha256(&row.outcome_digest) {
        return Err("source_digest_encoding_invalid");
    }
    match row.status.as_str() {
        "STAGED" => {
            let staged = AuthoritySourceOutcomeStaged {
                reservation_id: row.reservation_id.clone(),
                operation_id: row.operation_id.clone(),
                event_id: row.event_id.clone(),
                admission_proof_id: row.admission_proof_id.clone(),
                request_binding_digest: row.request_binding_digest.clone(),
                mutation_kind: kind,
                service_id: row.service_id.clone(),
                database_id: row.database_id.clone(),
                staged_evidence_json: staged_json.to_owned(),
                committed_at: row.committed_at,
            };
            if staged
                .staged_digest()
                .map_err(|_| "source_staged_digest_invalid")?
                != row.outcome_digest
            {
                return Err("source_staged_digest_mismatch");
            }
            Ok((
                EvidenceStatus::Pending,
                SourcePhase::Staged,
                EvidenceStatus::Pending,
            ))
        }
        "PENDING" | "COMMITTED" | "PUBLISHED" | "COMPLETE" | "COMPLETED" | "QUARANTINED" => {
            let source_commit_digest = row
                .source_commit_digest
                .as_deref()
                .ok_or("source_commit_digest_missing")?;
            let before_image_digest = row
                .before_image_digest
                .as_deref()
                .ok_or("source_before_digest_missing")?;
            let after_image_digest = row
                .after_image_digest
                .as_deref()
                .ok_or("source_after_digest_missing")?;
            for digest in [
                source_commit_digest,
                before_image_digest,
                after_image_digest,
            ] {
                if !valid_sha256(digest) {
                    return Err("source_digest_encoding_invalid");
                }
            }
            let receipts_json = row
                .source_receipts
                .as_deref()
                .ok_or("source_receipts_missing")?;
            let source_receipts: Vec<AuthoritySourceReceiptIdentity> =
                serde_json::from_str(receipts_json)
                    .map_err(|_| "source_receipts_not_closed_typed_json")?;
            if source_receipts.is_empty() || source_receipts.len() > MAX_RECEIPTS {
                return Err("source_receipt_capacity_invalid");
            }
            let record = AuthoritySourceOutcomeRecord {
                reservation_id: row.reservation_id.clone(),
                operation_id: row.operation_id.clone(),
                event_id: row.event_id.clone(),
                admission_proof_id: row.admission_proof_id.clone(),
                request_binding_digest: row.request_binding_digest.clone(),
                mutation_kind: kind,
                service_id: row.service_id.clone(),
                database_id: row.database_id.clone(),
                source_commit_digest: source_commit_digest.to_owned(),
                before_image_digest: Some(before_image_digest.to_owned()),
                after_image_digest: Some(after_image_digest.to_owned()),
                source_receipts,
                committed_at: row.committed_at,
            };
            let recomputed = canonical_outcome_digest(&record, Some(staged_json))
                .map_err(|_| "source_outcome_digest_invalid")?;
            if recomputed != row.outcome_digest {
                return Err("source_outcome_digest_mismatch");
            }
            let phase = match row.status.as_str() {
                "PENDING" => SourcePhase::SourceCommitDurable,
                "COMMITTED" => SourcePhase::AuthorityCommitted,
                "PUBLISHED" => SourcePhase::Published,
                "COMPLETE" | "COMPLETED" => SourcePhase::Completed,
                "QUARANTINED" => SourcePhase::Quarantined,
                _ => SourcePhase::Unknown,
            };
            // Local source outcome states do not contain an immutable authority
            // acceptance receipt. Never promote COMMITTED/PUBLISHED/COMPLETED
            // to authority proof; a separate historical receipt adapter would
            // be required for PROVEN here.
            let authority_status = EvidenceStatus::Unknown;
            let source_status = if row.status == "QUARANTINED" {
                EvidenceStatus::Unknown
            } else {
                EvidenceStatus::Proven
            };
            Ok((source_status, phase, authority_status))
        }
        _ => Err("source_status_unknown"),
    }
}

fn verify_card_scope(
    row: &SourceOutcomeDbRow,
    envelope: &AuthorityStagedSourceEvidence,
    batch: Option<&SourceBatchEvidence>,
    query: &ObservationQuery,
) -> Result<(Option<u64>, Option<u64>), &'static str> {
    let batch = batch.ok_or("source_evidence_schema_not_supported_by_observer")?;
    if batch.source_images.len() > MAX_RECEIPTS
        || batch.audits.len() > MAX_AUDIT_ROWS
        || batch.source_projection.len() > MAX_RECEIPTS
        || batch.invalidations.len() > MAX_RECEIPTS
    {
        return Err("source_evidence_capacity_invalid");
    }
    let delta = batch
        .delta
        .as_ref()
        .ok_or("source_card_delta_unavailable")?;
    let coverage = delta
        .complete_card_coverage()
        .map_err(|_| "source_card_coverage_invalid")?
        .ok_or("source_card_coverage_incomplete")?;
    if envelope.coverage.as_ref() != Some(&coverage) {
        return Err("source_card_coverage_binding_mismatch");
    }
    let source_events: Vec<_> = delta
        .events
        .iter()
        .filter(|event| event.operation_id == query.operation_id)
        .collect();
    if !source_events.iter().any(|event| {
        event.event_id == row.event_id
            && event.tenant_id == query.tenant_id
            && event.card_id == Some(query.card_id)
    }) {
        return Err("source_card_event_binding_unknown");
    }
    if source_events.iter().any(|event| {
        event.tenant_id <= 0
            || event.card_id.is_some_and(|card_id| card_id <= 0)
            || event.source_generation == 0
            || event.revoke_fence > event.source_generation
    }) {
        return Err("source_card_event_invalid");
    }
    let mut expected_receipts = Vec::new();
    expected_receipts.extend(
        delta
            .receipts
            .iter()
            .map(|receipt| (receipt.identity_kind.clone(), receipt.identity.clone())),
    );
    expected_receipts.extend(batch.source_projection.iter().map(|projection| {
        (
            "authorization_projection_outbox".to_owned(),
            projection.outbox_id.to_string(),
        )
    }));
    expected_receipts.extend(batch.invalidations.iter().map(|invalidation| {
        (
            "al_message_outbox".to_owned(),
            invalidation.message_id.clone(),
        )
    }));
    if !batch.source_images.is_empty() {
        expected_receipts.extend(batch.source_images.iter().map(|image| {
            (
                "typed_source_row_image".to_owned(),
                format!(
                    "{}:{}:{}",
                    image.table.as_str(),
                    image.key,
                    source_operation_text(image.operation)
                ),
            )
        }));
    }
    if !batch.audits.is_empty() {
        expected_receipts.extend(
            batch
                .audits
                .iter()
                .map(|audit| ("audit_log".to_owned(), audit.audit_log_id.to_string())),
        );
    }
    let receipt_json = row
        .source_receipts
        .as_deref()
        .ok_or("source_receipts_missing")?;
    let actual: Vec<AuthoritySourceReceiptIdentity> =
        serde_json::from_str(receipt_json).map_err(|_| "source_receipts_not_closed_typed_json")?;
    let mut actual_pairs: Vec<_> = actual
        .iter()
        .map(|receipt| (receipt.identity_kind.clone(), receipt.identity.clone()))
        .collect();
    expected_receipts.sort();
    actual_pairs.sort();
    if expected_receipts != actual_pairs {
        return Err("source_receipt_set_mismatch");
    }
    let exact_message = exact_invalidation(batch, query).ok_or("source_message_binding_unknown")?;
    let envelope = exact_message.envelope.clone().into_message_envelope();
    let event = astral_mq::InvalidationEvent::from_envelope(&envelope)
        .map_err(|_| "source_invalidation_envelope_invalid")?;
    match event {
        astral_mq::InvalidationEvent::EvidenceInvalidated(value)
            if value.tenant_id == query.tenant_id
                && value.card_id == Some(query.card_id)
                && value.aggregate_type == PublishedEvidenceAggregate::UserCard
                && value.aggregate_id == query.card_id
                && source_events.iter().any(|source| {
                    source.source_generation == value.source_generation
                        && source.revoke_fence == value.revoke_fence
                }) => {}
        _ => return Err("source_message_scope_or_fence_mismatch"),
    }
    let event = source_events
        .into_iter()
        .find(|event| event.event_id == row.event_id)
        .ok_or("source_card_event_binding_unknown")?;
    Ok((Some(event.source_generation), Some(event.revoke_fence)))
}

fn exact_invalidation<'a>(
    batch: &'a SourceBatchEvidence,
    query: &ObservationQuery,
) -> Option<&'a InvalidationEvidence> {
    batch.invalidations.iter().find(|invalidation| {
        invalidation.message_id == query.message_id
            && invalidation.operation_id == query.operation_id
            && invalidation.envelope.message_id == query.message_id
            && invalidation.envelope.operation_id == query.operation_id
            && invalidation.envelope.tenant_id == Some(query.tenant_id)
    })
}

async fn load_outbox_batch(
    pool: &sqlx::MySqlPool,
    query: &ObservationQuery,
    batch: &SourceBatchEvidence,
) -> Result<Vec<OutboxDbRow>, &'static str> {
    validate_staged_invalidation_identities(batch, query)?;
    let mut rows = Vec::with_capacity(batch.invalidations.len());
    for expected in &batch.invalidations {
        let candidates: Vec<OutboxDbRow> = sqlx::query_as(
            "SELECT message_id, operation_id, message_type, queue_name, tenant_id, origin_region, \
             target_region, ordering_key, schema_version, CAST(payload_json AS CHAR) AS payload_json, \
             LOWER(payload_sha256) AS payload_sha256, CAST(authority_metadata_json AS CHAR) AS authority_metadata_json, \
             status, CAST(UNIX_TIMESTAMP(created_at) * 1000 AS SIGNED) AS observed_at_unix_ms \
             FROM al_message_outbox WHERE message_id = ? AND operation_id = ? AND tenant_id = ? LIMIT 2",
        )
        .bind(&expected.message_id)
        .bind(&expected.operation_id)
        .bind(query.tenant_id)
        .fetch_all(pool)
        .await
        .map_err(|_| "outbox_query_unavailable")?;
        if candidates.len() != 1 {
            return Err(if candidates.is_empty() {
                "outbox_staged_row_missing"
            } else {
                "outbox_staged_row_duplicate"
            });
        }
        let row = candidates.into_iter().next().expect("one row checked");
        let stored: astral_mq::MessageEnvelope =
            serde_json::from_str(&row.payload_json).map_err(|_| "outbox_envelope_invalid")?;
        let expected_envelope = expected.envelope.clone().into_message_envelope();
        let stored_metadata = row
            .authority_metadata_json
            .as_deref()
            .map(serde_json::from_str::<AuthorizationMessageMetadata>)
            .transpose()
            .map_err(|_| "outbox_authority_metadata_invalid")?;
        if stored != expected_envelope
            || stored.validate().is_err()
            || stored_metadata != expected_envelope.authority_metadata
            || row.message_id != expected.message_id
            || row.operation_id != expected.operation_id
            || row.tenant_id != expected.envelope.tenant_id
            || row.message_type != expected_envelope.message_type
            || row.queue_name != expected.queue_name
            || row.origin_region != expected_envelope.origin_region
            || row.target_region != expected_envelope.target_region
            || row.ordering_key != expected_envelope.ordering_key
            || row.schema_version != expected_envelope.schema_version
            || row.payload_sha256 != expected_envelope.payload_sha256
        {
            return Err("outbox_staged_row_field_mismatch");
        }
        if safe_outbox_state(&row.status).is_none() {
            return Err("outbox_status_unknown");
        }
        rows.push(row);
    }
    Ok(rows)
}

fn validate_staged_invalidation_identities(
    batch: &SourceBatchEvidence,
    query: &ObservationQuery,
) -> Result<(), &'static str> {
    if batch.invalidations.is_empty() || batch.invalidations.len() > MAX_RECEIPTS {
        return Err("source_invalidation_capacity_invalid");
    }
    let mut seen_message_ids = BTreeSet::new();
    for invalidation in &batch.invalidations {
        if invalidation.message_id.is_empty()
            || invalidation.message_id.len() > 128
            || invalidation.operation_id != query.operation_id
            || invalidation.envelope.message_id != invalidation.message_id
            || invalidation.envelope.operation_id != query.operation_id
            || invalidation.envelope.tenant_id != Some(query.tenant_id)
            || invalidation.queue_name != astral_mq::invalidation::INVALIDATION_QUEUE
        {
            return Err("outbox_staged_identity_mismatch");
        }
        if !seen_message_ids.insert(invalidation.message_id.as_str()) {
            return Err("outbox_staged_message_duplicate");
        }
    }
    Ok(())
}

fn outbox_message_observation(row: &OutboxDbRow) -> Result<MessageObservation, &'static str> {
    let durable_state = safe_outbox_state(&row.status).ok_or("outbox_status_unknown")?;
    Ok(MessageObservation {
        status: EvidenceStatus::Proven,
        message_id: Some(row.message_id.clone()),
        operation_id: Some(row.operation_id.clone()),
        tenant_id: row.tenant_id,
        payload_digest: Some(row.payload_sha256.clone()),
        durable_state: Some(durable_state),
        observed_at_unix_ms: Some(row.observed_at_unix_ms),
        reason_code: None,
    })
}

async fn load_inbox(
    pool: &sqlx::MySqlPool,
    state: &AppState,
    query: &ObservationQuery,
    outbox: &MessageObservation,
) -> MessageObservation {
    let region = state.config.region_id.as_str();
    let node = state.config.node_id.as_str();
    if region == "local"
        || node == "local-node"
        || region.trim().is_empty()
        || node.trim().is_empty()
    {
        return MessageObservation::unknown("trusted_node_identity_not_configured");
    }
    let result: Result<Vec<InboxDbRow>, sqlx::Error> = sqlx::query_as(
        "SELECT message_id, operation_id, tenant_id, LOWER(payload_sha256) AS payload_sha256, \
         status, CAST(UNIX_TIMESTAMP(created_at) * 1000 AS SIGNED) AS observed_at_unix_ms \
         FROM authorization_invalidation_inbox \
         WHERE node_region = ? AND node_id = ? AND message_id = ? AND operation_id = ? AND tenant_id = ? LIMIT 2",
    )
    .bind(region)
    .bind(node)
    .bind(&query.message_id)
    .bind(&query.operation_id)
    .bind(query.tenant_id)
    .fetch_all(pool)
    .await;
    match result {
        Ok(rows) if rows.len() == 1 => {
            let row = rows.into_iter().next().expect("one row checked");
            let digest_matches =
                outbox.payload_digest.as_deref() == Some(row.payload_sha256.as_str());
            if !digest_matches
                || row.message_id != query.message_id
                || row.operation_id != query.operation_id
                || row.tenant_id != Some(query.tenant_id)
            {
                return MessageObservation::unknown("inbox_exact_binding_mismatch");
            }
            let durable_state = match safe_inbox_state(&row.status) {
                Some(state) => state,
                None => return MessageObservation::unknown("inbox_status_unknown"),
            };
            MessageObservation {
                status: EvidenceStatus::Proven,
                message_id: Some(row.message_id),
                operation_id: Some(row.operation_id),
                tenant_id: row.tenant_id,
                payload_digest: Some(row.payload_sha256),
                durable_state: Some(durable_state),
                observed_at_unix_ms: Some(row.observed_at_unix_ms),
                reason_code: None,
            }
        }
        Ok(_) => MessageObservation::unknown("inbox_exact_row_missing_or_ambiguous"),
        Err(_) => MessageObservation::unknown("inbox_query_unavailable"),
    }
}

async fn load_audits(
    pool: &sqlx::MySqlPool,
    query: &ObservationQuery,
    source: &SourceObservation,
    batch: &SourceBatchEvidence,
) -> AuditObservation {
    if source.status != EvidenceStatus::Proven || batch.audits.is_empty() {
        return AuditObservation::unknown(
            "typed_audit_receipts_not_available_for_this_source_kind",
        );
    }
    if batch.audits.len() > MAX_AUDIT_ROWS {
        return AuditObservation::unknown("audit_receipt_capacity_exceeded");
    }
    let row_time = unix_time_ms();
    for expected in &batch.audits {
        if expected.audit_log_id <= 0 || expected.user_id <= 0 {
            return AuditObservation::unknown("audit_receipt_identity_invalid");
        }
        let row: Result<Option<AuditDbRow>, sqlx::Error> = sqlx::query_as(
            "SELECT id, user_id, action, resource, decision, event_type, request_id, tenant_id, card_id \
             FROM audit_log WHERE id = ? AND request_id = ? AND tenant_id = ? AND card_id = ? LIMIT 2",
        )
        .bind(expected.audit_log_id)
        .bind(&query.operation_id)
        .bind(query.tenant_id)
        .bind(query.card_id)
        .fetch_optional(pool)
        .await;
        match row {
            Ok(Some(row))
                if row.id == expected.audit_log_id
                    && row.user_id == expected.user_id
                    && row.action == expected.action
                    && row.resource == expected.resource
                    && row.decision == expected.decision
                    && row.event_type.as_deref() == Some(expected.event_type.as_str())
                    && row.request_id.as_deref() == Some(query.operation_id.as_str())
                    && row.tenant_id == Some(query.tenant_id)
                    && row.card_id == Some(query.card_id) => {}
            _ => return AuditObservation::unknown("audit_exact_receipt_missing_or_mismatched"),
        }
    }
    AuditObservation {
        status: EvidenceStatus::Proven,
        receipt_count: Some(batch.audits.len()),
        exact_receipts_verified: Some(true),
        observed_at_unix_ms: Some(row_time),
        reason_code: None,
    }
}

fn trusted_owner_matches(service_id: &str, database_id: &str) -> EvidenceStatus {
    let configured_service = std::env::var("ASTRAL_AUTHORITY_SERVICE_ID").ok();
    let configured_database = std::env::var("ASTRAL_AUTHORITY_DATABASE_ID").ok();
    match (
        configured_service.as_deref(),
        configured_database.as_deref(),
    ) {
        (Some(service), Some(database)) if !service.is_empty() && !database.is_empty() => {
            if service == service_id && database == database_id {
                EvidenceStatus::Proven
            } else {
                EvidenceStatus::Unknown
            }
        }
        _ => EvidenceStatus::Unknown,
    }
}

fn deployment_observation(state: &AppState) -> DeploymentObservation {
    let region_id = state.config.region_id.trim();
    let node_id = state.config.node_id.trim();
    let configured = !region_id.is_empty()
        && !node_id.is_empty()
        && region_id != "local"
        && node_id != "local-node";
    DeploymentObservation {
        node_identity_status: if configured {
            EvidenceStatus::Proven
        } else {
            EvidenceStatus::Unknown
        },
        region_id: configured.then(|| region_id.to_owned()),
        node_id: configured.then(|| node_id.to_owned()),
        topology_status: EvidenceStatus::Unknown,
        half: None,
        controller: None,
    }
}

impl VerifiedSource {
    fn unknown(query: &ObservationQuery, reason: &'static str) -> Self {
        Self {
            observation: SourceObservation {
                status: if reason == "source_outcome_exact_row_not_found" {
                    EvidenceStatus::Pending
                } else {
                    EvidenceStatus::Unknown
                },
                authority_commit_status: EvidenceStatus::Unknown,
                authority_commit_reason_code: Some(AUTHORITY_RECEIPT_NOT_VERIFIED),
                phase: SourcePhase::Unknown,
                owner_identity_status: EvidenceStatus::Unknown,
                reservation_id: Some(query.reservation_id.clone()),
                operation_id: Some(query.operation_id.clone()),
                event_id: None,
                admission_proof_id: None,
                mutation_kind: None,
                service_id: None,
                database_id: None,
                request_binding_digest: None,
                source_commit_digest: None,
                before_image_digest: None,
                after_image_digest: None,
                outcome_digest: None,
                source_generation: None,
                revoke_fence: None,
                lease_generation: None,
                committed_at_unix_seconds: None,
                reason_code: Some(reason),
            },
            envelope: None,
            batch: None,
        }
    }
}

impl MessageObservation {
    fn unknown(reason: &'static str) -> Self {
        Self {
            status: EvidenceStatus::Unknown,
            message_id: None,
            operation_id: None,
            tenant_id: None,
            payload_digest: None,
            durable_state: None,
            observed_at_unix_ms: None,
            reason_code: Some(reason),
        }
    }
}

impl AuditObservation {
    fn unknown(reason: &'static str) -> Self {
        Self {
            status: EvidenceStatus::Unknown,
            receipt_count: None,
            exact_receipts_verified: None,
            observed_at_unix_ms: None,
            reason_code: Some(reason),
        }
    }
}

fn safe_outbox_state(value: &str) -> Option<String> {
    matches!(
        value,
        "PENDING" | "PROCESSING" | "IN_DOUBT" | "PROCESSED" | "QUARANTINED"
    )
    .then(|| value.to_owned())
}

fn safe_inbox_state(value: &str) -> Option<String> {
    matches!(value, "PENDING" | "APPLIED").then(|| value.to_owned())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn source_operation_text(operation: astral_types::AuthorityConfigSourceOperation) -> &'static str {
    match operation {
        astral_types::AuthorityConfigSourceOperation::Insert => "INSERT",
        astral_types::AuthorityConfigSourceOperation::Upsert => "UPSERT",
        astral_types::AuthorityConfigSourceOperation::Update => "UPDATE",
        astral_types::AuthorityConfigSourceOperation::Delete => "DELETE",
    }
}

fn unix_time_ms() -> i64 {
    time::OffsetDateTime::now_utc()
        .unix_timestamp_nanos()
        .div_euclid(1_000_000) as i64
}

fn unknown_observation(
    state: &AppState,
    query: &ObservationQuery,
    observed_at: i64,
    reason: &'static str,
) -> S15AuthorizationObservation {
    let mut source = VerifiedSource::unknown(query, reason).observation;
    source.reason_code = Some(reason);
    let deployment = deployment_observation(state);
    let hub = astral_db::memory_projection_hub::memory_projection_hub();
    let (gate_status, ready, hub_state) =
        hub.map_or((EvidenceStatus::Unknown, None, None), |hub| {
            let ready = hub.positive_authorization_ready();
            (
                if ready {
                    EvidenceStatus::Proven
                } else {
                    EvidenceStatus::Pending
                },
                Some(ready),
                Some(format!("{:?}", hub.authority_state())),
            )
        });
    S15AuthorizationObservation {
        schema: SCHEMA,
        correlation: ObservationCorrelation {
            run_id: query.run_id.clone(),
            run_id_binding: EvidenceStatus::Unknown,
            operation_id: query.operation_id.clone(),
            reservation_id: query.reservation_id.clone(),
            message_id: query.message_id.clone(),
            tenant_id: query.tenant_id,
            card_id: query.card_id,
        },
        observed_at_unix_ms: observed_at,
        source,
        outbox: MessageObservation::unknown(reason),
        inbox: MessageObservation::unknown(reason),
        audit: AuditObservation::unknown(reason),
        read_gate: ReadGateObservation {
            status: gate_status,
            positive_authorization_ready: ready,
            hub_authority_state: hub_state,
            observed_at_unix_ms: observed_at,
        },
        liveness: LivenessObservation {
            status: EvidenceStatus::Proven,
            process_reached_handler: true,
            observed_at_unix_ms: observed_at,
        },
        authority_frontier: AuthorityFrontierObservation {
            status: EvidenceStatus::Unknown,
            reason_code: "frontier_requires_separate_s15_authority_client_observation",
        },
        deployment,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_query() -> &'static str {
        "runId=authz-validation-sample1&operationId=op-1&reservationId=res-1&messageId=msg-1&tenantId=7&cardId=42"
    }

    #[test]
    fn strict_query_accepts_exact_canonical_scope_and_rejects_unknown_or_duplicate_fields() {
        let query = parse_query(Some(valid_query())).unwrap();
        assert_eq!(query.tenant_id, 7);
        assert_eq!(query.card_id, 42);
        assert_eq!(query.run_id, "authz-validation-sample1");
        assert!(parse_query(Some(&format!("{}&nodeId=AL1", valid_query()))).is_err());
        assert!(parse_query(Some(&format!("{}&cardId=43", valid_query()))).is_err());
        assert!(parse_query(Some("runId=authz-validation-sample1&operationId=op-1&reservationId=res-1&messageId=msg-1&tenantId=7&cardId=042")).is_err());
        assert!(parse_query(Some("runId=authz-validation-sample1&operationId=op%2F1&reservationId=res-1&messageId=msg-1&tenantId=7&cardId=42")).is_err());
        assert!(parse_query(None).is_err());
    }

    #[test]
    fn run_id_is_correlation_only_not_source_or_permission_evidence() {
        let query = parse_query(Some(valid_query())).unwrap();
        let source = VerifiedSource::unknown(&query, "no_source");
        assert_eq!(source.observation.status, EvidenceStatus::Unknown);
        let output = unknown_observation_for_test(&query);
        assert_eq!(output.correlation.run_id_binding, EvidenceStatus::Unknown);
    }

    fn unknown_observation_for_test(query: &ObservationQuery) -> S15AuthorizationObservation {
        let mut source = VerifiedSource::unknown(query, "no_source").observation;
        source.status = EvidenceStatus::Proven;
        S15AuthorizationObservation {
            schema: SCHEMA,
            correlation: ObservationCorrelation {
                run_id: query.run_id.clone(),
                run_id_binding: EvidenceStatus::Unknown,
                operation_id: query.operation_id.clone(),
                reservation_id: query.reservation_id.clone(),
                message_id: query.message_id.clone(),
                tenant_id: query.tenant_id,
                card_id: query.card_id,
            },
            observed_at_unix_ms: 1,
            source,
            outbox: MessageObservation::unknown("unknown"),
            inbox: MessageObservation::unknown("unknown"),
            audit: AuditObservation::unknown("unknown"),
            read_gate: ReadGateObservation {
                status: EvidenceStatus::Unknown,
                positive_authorization_ready: None,
                hub_authority_state: None,
                observed_at_unix_ms: 1,
            },
            liveness: LivenessObservation {
                status: EvidenceStatus::Proven,
                process_reached_handler: true,
                observed_at_unix_ms: 1,
            },
            authority_frontier: AuthorityFrontierObservation {
                status: EvidenceStatus::Unknown,
                reason_code: "not_observed",
            },
            deployment: DeploymentObservation {
                node_identity_status: EvidenceStatus::Unknown,
                region_id: None,
                node_id: None,
                topology_status: EvidenceStatus::Unknown,
                half: None,
                controller: None,
            },
        }
    }

    #[test]
    fn source_projection_binding_compares_every_durable_field() {
        let expected = SourceProjectionEvidence {
            outbox_id: 9,
            event_id: "event-9".to_owned(),
            aggregate_type: "CARD".to_owned(),
            aggregate_id: 42,
            tenant_id: Some(7),
            event_type: "UPDATE".to_owned(),
            source_generation: 3,
            sequence_number: 4,
            revoke_fence: 1,
            payload: serde_json::json!({"operationId":"op-1"}),
        };
        let actual = SourceProjectionDbRow {
            outbox_id: 9,
            event_id: "event-9".to_owned(),
            aggregate_type: "CARD".to_owned(),
            aggregate_id: 42,
            tenant_id: Some(7),
            event_type: "UPDATE".to_owned(),
            source_generation: 3,
            sequence_number: 4,
            revoke_fence: 1,
            payload_json: None,
        };
        assert!(source_projection_matches(
            &expected,
            &actual,
            &expected.payload
        ));

        let mismatches = [
            SourceProjectionDbRow {
                outbox_id: 10,
                ..actual.clone()
            },
            SourceProjectionDbRow {
                event_id: "event-other".to_owned(),
                ..actual.clone()
            },
            SourceProjectionDbRow {
                aggregate_type: "RULE_SET".to_owned(),
                ..actual.clone()
            },
            SourceProjectionDbRow {
                aggregate_id: 43,
                ..actual.clone()
            },
            SourceProjectionDbRow {
                tenant_id: Some(8),
                ..actual.clone()
            },
            SourceProjectionDbRow {
                event_type: "DELETE".to_owned(),
                ..actual.clone()
            },
            SourceProjectionDbRow {
                source_generation: 4,
                ..actual.clone()
            },
            SourceProjectionDbRow {
                sequence_number: 5,
                ..actual.clone()
            },
            SourceProjectionDbRow {
                revoke_fence: 2,
                ..actual.clone()
            },
        ];
        for mismatch in mismatches {
            assert!(!source_projection_matches(
                &expected,
                &mismatch,
                &expected.payload
            ));
        }
        assert!(!source_projection_matches(
            &expected,
            &SourceProjectionDbRow {
                payload_json: Some("{}".to_owned()),
                ..actual.clone()
            },
            &serde_json::json!({}),
        ));
    }

    #[test]
    fn source_projection_payload_binding_rejects_semantically_different_json() {
        let expected = SourceProjectionEvidence {
            outbox_id: 9,
            event_id: "event-9".to_owned(),
            aggregate_type: "CARD".to_owned(),
            aggregate_id: 42,
            tenant_id: Some(7),
            event_type: "UPDATE".to_owned(),
            source_generation: 3,
            sequence_number: 4,
            revoke_fence: 1,
            payload: serde_json::json!({"operationId":"op-1"}),
        };
        let actual = SourceProjectionDbRow {
            outbox_id: 9,
            event_id: "event-9".to_owned(),
            aggregate_type: "CARD".to_owned(),
            aggregate_id: 42,
            tenant_id: Some(7),
            event_type: "UPDATE".to_owned(),
            source_generation: 3,
            sequence_number: 4,
            revoke_fence: 1,
            payload_json: Some("{\"operationId\":\"op-1\"}".to_owned()),
        };
        assert!(source_projection_matches(
            &expected,
            &actual,
            &expected.payload
        ));
        assert!(!source_projection_matches(
            &expected,
            &actual,
            &serde_json::json!({"operationId":"op-2"}),
        ));
    }

    #[test]
    fn durable_message_states_are_plane_specific_and_unknown_states_fail_closed() {
        for state in [
            "PENDING",
            "PROCESSING",
            "IN_DOUBT",
            "PROCESSED",
            "QUARANTINED",
        ] {
            assert_eq!(safe_outbox_state(state).as_deref(), Some(state));
        }
        for state in ["PENDING", "APPLIED"] {
            assert_eq!(safe_inbox_state(state).as_deref(), Some(state));
        }
        for state in ["", "STAGED", "FAILED", "COMPLETED", "UNKNOWN"] {
            assert!(safe_outbox_state(state).is_none());
            assert!(safe_inbox_state(state).is_none());
        }
    }

    #[test]
    fn staged_invalidation_identity_rejects_duplicate_messages_and_scope_drift() {
        let query = parse_query(Some(valid_query())).unwrap();
        let envelope = StrictMessageEnvelope {
            message_id: "msg-1".into(),
            operation_id: "op-1".into(),
            message_type: "EVIDENCE_INVALIDATED".into(),
            schema_version: 1,
            tenant_id: Some(7),
            origin_region: "region-a".into(),
            target_region: None,
            ordering_key: Some("card:42".into()),
            trace_id: None,
            created_at: "2026-11-07T00:00:00Z".into(),
            expires_at: None,
            payload_sha256: "a".repeat(64),
            authority_metadata: None,
            payload: serde_json::json!({}),
        };
        let invalidation = InvalidationEvidence {
            message_id: "msg-1".into(),
            operation_id: "op-1".into(),
            queue_name: astral_mq::invalidation::INVALIDATION_QUEUE.into(),
            envelope,
        };
        let duplicate_batch = SourceBatchEvidence {
            delta: None,
            source_images: Vec::new(),
            audits: Vec::new(),
            source_projection: Vec::new(),
            invalidations: vec![invalidation.clone(), invalidation],
        };
        assert_eq!(
            validate_staged_invalidation_identities(&duplicate_batch, &query),
            Err("outbox_staged_message_duplicate")
        );

        let mut drifted = duplicate_batch.invalidations[0].clone();
        drifted.envelope.tenant_id = Some(8);
        let drifted_batch = SourceBatchEvidence {
            invalidations: vec![drifted],
            ..duplicate_batch
        };
        assert_eq!(
            validate_staged_invalidation_identities(&drifted_batch, &query),
            Err("outbox_staged_identity_mismatch")
        );
    }

    #[test]
    fn retained_source_and_message_shapes_reject_unknown_fields() {
        let bad_envelope = r#"{"coverage":null,"evidence":{"delta":null,"extra":true}}"#;
        let envelope: AuthorityStagedSourceEvidence = serde_json::from_str(bad_envelope).unwrap();
        assert!(serde_json::from_value::<SourceBatchEvidence>(envelope.evidence).is_err());
        let bad_message = r#"{"messageId":"m","operationId":"o","messageType":"EVIDENCE_INVALIDATED","schemaVersion":1,"tenantId":7,"originRegion":"r","targetRegion":null,"orderingKey":"k","traceId":null,"createdAt":"2026-11-07T00:00:00Z","expiresAt":null,"payloadSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","authorityMetadata":null,"payload":{},"extra":true}"#;
        assert!(serde_json::from_str::<StrictMessageEnvelope>(bad_message).is_err());
    }
}
