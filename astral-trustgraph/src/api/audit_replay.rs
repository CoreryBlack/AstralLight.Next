//! 审计隔离队列的受控查看与重放申请 API。
//!
//! 该模块只操作 `astral-db` 的隔离表契约：GET 端点返回元数据，POST 端点只把
//! 行推进到 `REPLAY_REQUESTED`，不会读取 raw body、租约 secret、AMQP properties，
//! 也不会发布 RabbitMQ 消息。真正的 raw claim/publish 仍属于后续 worker 边界。

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::config::MessageTransport;
use astral_common::contract::ApiResponse;
use astral_common::error::AppError;
use astral_db::{
    request_replay_with_context, AuditQuarantineMetadata, AuditQuarantineStatus,
    ReplayAuditContext, MAX_CANONICAL_REQUEST_ID_LENGTH, MAX_LIST_LIMIT,
};
use astral_types::AstralError;

use crate::api::require_platform_admin;
use crate::AppState;

const SOURCE_QUEUE: &str = "astral.audit.log";
const SOURCE_EXCHANGE: &str = "astral.direct";
const SOURCE_ROUTING_KEY: &str = "audit.log";
const MESSAGE_TYPE: &str = "AUDIT_LOG";
const DEFAULT_LIMIT: u32 = 20;
const MAX_OPERATION_ID_LENGTH: usize = astral_db::MAX_OPERATION_ID_LENGTH;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QuarantineListQuery {
    status: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayRequest {}

/// Safe public representation of [`AuditQuarantineMetadata`].
///
/// In particular, this type has no raw payload, lease token/token hash, or AMQP
/// properties. The byte identity is rendered as a non-secret hex digest.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditQuarantineMetadataDto {
    pub id: i64,
    pub identity_key: String,
    pub message_id: String,
    pub message_type: String,
    pub source_queue: String,
    pub source_exchange: String,
    pub source_routing_key: String,
    pub retry_count: u32,
    pub attempts: u32,
    pub replay_attempts: u32,
    pub failure_reason: String,
    pub status: String,
    pub replay_lease_owner: Option<String>,
    pub replay_lease_generation: u64,
    pub replay_lease_expires_at: Option<String>,
    pub replay_requested_by: Option<String>,
    pub replay_requested_at: Option<String>,
    pub first_failed_at: String,
    pub last_failed_at: String,
    pub quarantined_at: String,
    pub replayed_at: Option<String>,
}

impl From<AuditQuarantineMetadata> for AuditQuarantineMetadataDto {
    fn from(metadata: AuditQuarantineMetadata) -> Self {
        Self {
            id: metadata.id,
            identity_key: hex_encode(&metadata.identity_key),
            message_id: metadata.message_id,
            message_type: metadata.message_type,
            source_queue: metadata.source_queue,
            source_exchange: metadata.source_exchange,
            source_routing_key: metadata.source_routing_key,
            retry_count: metadata.retry_count,
            attempts: metadata.attempts,
            replay_attempts: metadata.replay_attempts,
            failure_reason: metadata.failure_reason,
            status: metadata.status.as_str().to_owned(),
            replay_lease_owner: metadata.replay_lease_owner,
            replay_lease_generation: metadata.replay_lease_generation,
            replay_lease_expires_at: metadata
                .replay_lease_expires_at
                .map(|value| value.to_string()),
            replay_requested_by: metadata.replay_requested_by,
            replay_requested_at: metadata.replay_requested_at.map(|value| value.to_string()),
            first_failed_at: metadata.first_failed_at.to_string(),
            last_failed_at: metadata.last_failed_at.to_string(),
            quarantined_at: metadata.quarantined_at.to_string(),
            replayed_at: metadata.replayed_at.map(|value| value.to_string()),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReplayRequestResponse {
    id: i64,
    operation_id: String,
    accepted: bool,
    item: AuditQuarantineMetadataDto,
}

pub fn audit_replay_routes() -> Router<AppState> {
    Router::new()
        .route("/audit-quarantine", get(list_quarantine))
        .route("/audit-quarantine/{id}", get(get_quarantine))
        .route(
            "/audit-quarantine/{id}/replay",
            post(request_quarantine_replay),
        )
}

async fn list_quarantine(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<QuarantineListQuery>,
) -> Result<Json<ApiResponse<Vec<AuditQuarantineMetadataDto>>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    let status = normalize_status(query.status.as_deref())?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT);
    let offset = query.offset.unwrap_or(0);
    validate_paging(limit, offset)?;

    let items = astral_db::list_quarantine_metadata_by_status(&state.db, status, limit, offset)
        .await
        .map_err(database_error)?
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(Json(ApiResponse::success(items)))
}

async fn get_quarantine(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<AuditQuarantineMetadataDto>>, AppError> {
    require_platform_admin(&state, &headers).await?;
    if id <= 0 {
        return Err(validation_error("quarantine id must be positive"));
    }
    let item = astral_db::get_quarantine_metadata_by_id(&state.db, id)
        .await
        .map_err(database_error)?
        .ok_or_else(|| {
            AppError(AstralError::NotFound(
                "audit quarantine record not found".into(),
            ))
        })?;
    Ok(Json(ApiResponse::success(item.into())))
}

async fn request_quarantine_replay(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    _body: Option<Json<ReplayRequest>>,
) -> Result<Json<ApiResponse<ReplayRequestResponse>>, AppError> {
    let operator_id = require_platform_admin(&state, &headers).await?;
    if id <= 0 {
        return Err(validation_error("quarantine id must be positive"));
    }
    let transport = state
        .config
        .message_transport()
        .map_err(|error| AppError(AstralError::Config(error.to_string())))?;
    if !replay_transport_supported(transport) {
        return Err(AppError(AstralError::NotImplemented(
            "audit quarantine replay is unsupported with local message transport; no replay worker can drain requests".into(),
        )));
    }

    let metadata = astral_db::get_quarantine_metadata_by_id(&state.db, id)
        .await
        .map_err(database_error)?
        .ok_or_else(|| {
            AppError(AstralError::NotFound(
                "audit quarantine record not found".into(),
            ))
        })?;
    validate_replay_route(&metadata)?;

    let operation_id = resolve_operation_id(&headers)?;
    let actor_card_id = headers
        .get("x-user-card-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            AppError(AstralError::Auth(
                "verified user-card context required".into(),
            ))
        })?;
    let tenant_id = headers
        .get("x-user-card-tenant-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| AppError(AstralError::Auth("verified tenant context required".into())))?;
    let domain_id = headers
        .get("x-user-card-domain-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| AppError(AstralError::Auth("verified domain context required".into())))?;
    let accepted = request_replay_with_context(
        &state.db,
        id,
        &operation_id,
        &operator_id.to_string(),
        ReplayAuditContext {
            actor_card_id: Some(actor_card_id),
            tenant_id: Some(tenant_id),
            domain_id: Some(domain_id),
        },
    )
    .await
    .map_err(database_error)?;
    if !accepted {
        return Err(AppError(AstralError::Validation(
            "audit quarantine replay is not requestable in its current state or its request identity conflicts".into(),
        )));
    }

    let item = astral_db::get_quarantine_metadata_by_id(&state.db, id)
        .await
        .map_err(database_error)?
        .ok_or_else(|| {
            AppError(AstralError::NotFound(
                "audit quarantine record not found".into(),
            ))
        })?;
    Ok(Json(ApiResponse::success(ReplayRequestResponse {
        id,
        operation_id,
        accepted: true,
        item: item.into(),
    })))
}

fn replay_transport_supported(transport: MessageTransport) -> bool {
    matches!(transport, MessageTransport::Rabbit)
}

fn normalize_status(value: Option<&str>) -> Result<&'static str, AppError> {
    match value.unwrap_or(AuditQuarantineStatus::Quarantined.as_str()) {
        "QUARANTINED" => Ok("QUARANTINED"),
        "REPLAY_REQUESTED" => Ok("REPLAY_REQUESTED"),
        "REPLAYING" => Ok("REPLAYING"),
        "REPLAY_CONFIRMED" => Ok("REPLAY_CONFIRMED"),
        _ => Err(validation_error("unsupported audit quarantine status")),
    }
}

fn validate_paging(limit: u32, offset: u32) -> Result<(), AppError> {
    if limit == 0 || limit > MAX_LIST_LIMIT || offset > astral_db::MAX_LIST_OFFSET {
        return Err(validation_error("audit quarantine paging is out of range"));
    }
    Ok(())
}

fn validate_replay_route(metadata: &AuditQuarantineMetadata) -> Result<(), AppError> {
    if metadata.source_queue != SOURCE_QUEUE
        || metadata.source_exchange != SOURCE_EXCHANGE
        || metadata.source_routing_key != SOURCE_ROUTING_KEY
        || metadata.message_type != MESSAGE_TYPE
    {
        return Err(validation_error(
            "audit quarantine source route is not allowed for TrustGraph replay",
        ));
    }
    Ok(())
}

fn resolve_operation_id(headers: &HeaderMap) -> Result<String, AppError> {
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let candidate = request_id
        .map(str::to_owned)
        .unwrap_or_else(|| format!("audit-replay-{}", uuid::Uuid::new_v4()));

    if request_id.is_some_and(|value| value.len() > MAX_CANONICAL_REQUEST_ID_LENGTH)
        || candidate.len() > MAX_OPERATION_ID_LENGTH
        || candidate.contains('\0')
        || !candidate
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(validation_error("request id is invalid"));
    }
    Ok(candidate)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validation_error(message: &str) -> AppError {
    AppError(AstralError::Validation(message.to_owned()))
}

fn database_error(error: astral_db::DbError) -> AppError {
    AppError(AstralError::Database(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_route_is_exactly_allowlisted() {
        let metadata = test_metadata(
            SOURCE_QUEUE,
            SOURCE_EXCHANGE,
            SOURCE_ROUTING_KEY,
            MESSAGE_TYPE,
        );
        assert!(validate_replay_route(&metadata).is_ok());
        for changed in [
            (
                "astral.other.queue",
                SOURCE_EXCHANGE,
                SOURCE_ROUTING_KEY,
                MESSAGE_TYPE,
            ),
            (
                SOURCE_QUEUE,
                "astral.topic",
                SOURCE_ROUTING_KEY,
                MESSAGE_TYPE,
            ),
            (SOURCE_QUEUE, SOURCE_EXCHANGE, "audit.other", MESSAGE_TYPE),
            (SOURCE_QUEUE, SOURCE_EXCHANGE, SOURCE_ROUTING_KEY, "OTHER"),
        ] {
            assert!(validate_replay_route(&test_metadata(
                changed.0, changed.1, changed.2, changed.3
            ))
            .is_err());
        }
    }

    #[test]
    fn paging_rejects_zero_and_values_above_five_hundred() {
        assert!(validate_paging(1, 0).is_ok());
        assert!(validate_paging(0, 0).is_err());
        assert!(validate_paging(MAX_LIST_LIMIT + 1, 0).is_err());
    }

    #[test]
    fn request_ids_fit_the_canonical_audit_column() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-request-id",
            "a".repeat(MAX_CANONICAL_REQUEST_ID_LENGTH).parse().unwrap(),
        );
        assert!(resolve_operation_id(&headers).is_ok());
        headers.insert(
            "x-request-id",
            "a".repeat(MAX_CANONICAL_REQUEST_ID_LENGTH + 1)
                .parse()
                .unwrap(),
        );
        assert!(resolve_operation_id(&headers).is_err());
        headers.insert("x-request-id", "unsafe request".parse().unwrap());
        assert!(resolve_operation_id(&headers).is_err());
    }

    #[test]
    fn local_transport_replay_refusal_has_no_durable_request() {
        assert!(!replay_transport_supported(MessageTransport::Local));
        assert!(replay_transport_supported(MessageTransport::Rabbit));
    }

    #[test]
    fn unknown_replay_body_fields_are_rejected() {
        let error = serde_json::from_value::<ReplayRequest>(serde_json::json!({
            "operator": "spoofed",
            "role": "SUPER_ADMIN"
        }))
        .expect_err("operator and role must never be accepted from the body");
        assert!(error.to_string().contains("unknown field"));
    }

    fn test_metadata(
        source_queue: &str,
        source_exchange: &str,
        source_routing_key: &str,
        message_type: &str,
    ) -> AuditQuarantineMetadata {
        let timestamp = time::PrimitiveDateTime::new(
            time::Date::from_calendar_date(2026, time::Month::January, 1).unwrap(),
            time::Time::MIDNIGHT,
        );
        AuditQuarantineMetadata {
            id: 1,
            identity_key: [0; 32],
            message_id: "message-1".into(),
            message_type: message_type.into(),
            source_queue: source_queue.into(),
            source_exchange: source_exchange.into(),
            source_routing_key: source_routing_key.into(),
            retry_count: 1,
            attempts: 1,
            replay_attempts: 0,
            failure_reason: "failure".into(),
            status: AuditQuarantineStatus::Quarantined,
            replay_lease_owner: None,
            replay_lease_generation: 0,
            replay_lease_expires_at: None,
            replay_requested_by: None,
            replay_requested_at: None,
            first_failed_at: timestamp,
            last_failed_at: timestamp,
            quarantined_at: timestamp,
            replayed_at: None,
        }
    }
}
