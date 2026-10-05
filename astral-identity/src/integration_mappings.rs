//! Identity-owned administration of pre-established external subject mappings.

use astral_common::contract::ApiResponse;
use astral_db::{
    create_integration_identity_mapping, set_integration_identity_mapping_status,
    CreateIntegrationIdentityMapping, IntegrationIdentityKey, IntegrationIdentityMappingError,
    IntegrationIdentityMappingStatus, SetIntegrationIdentityMappingStatus,
};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{post, put};
use axum::{Json, Router};
use serde::Deserialize;

use crate::AppState;

pub(crate) fn enabled_from_env() -> Result<bool, &'static str> {
    match std::env::var("ASTRAL_SDK_IDENTITY_MAPPING_ENABLED") {
        Err(std::env::VarError::NotPresent) => Ok(false),
        Ok(value) if value == "false" => Ok(false),
        Ok(value) if value == "true" => Ok(true),
        _ => Err("invalid integration identity mapping enablement"),
    }
}

pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/integrations/identity-mappings", post(create))
        .route("/integrations/identity-mappings/status", put(change_status))
        .layer(DefaultBodyLimit::max(8192))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MappingCreateRequest {
    app_id: String,
    issuer: String,
    subject: String,
    user_id: i64,
    identity_card_id: i64,
    operation_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MappingStatusRequest {
    app_id: String,
    issuer: String,
    subject: String,
    expected_revision: u64,
    status: String,
    operation_id: String,
}

async fn require_active_global_admin(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<i64, MappingHttpError> {
    let user_id = headers
        .get("x-user-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| refused(StatusCode::UNAUTHORIZED, "IDENTITY_REQUIRED", None, false))?;
    let repository = astral_db::SqlxRuleRepository::new(state.db.clone());
    let active = policy_engine::RuleRepository::is_active_global_admin(&repository, user_id)
        .await
        .map_err(|_| {
            refused(
                StatusCode::SERVICE_UNAVAILABLE,
                "PLATFORM_ADMIN_UNAVAILABLE",
                None,
                false,
            )
        })?;
    if !active {
        return Err(refused(
            StatusCode::FORBIDDEN,
            "PLATFORM_ADMIN_REQUIRED",
            None,
            false,
        ));
    }
    Ok(user_id)
}

async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<MappingCreateRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, MappingHttpError> {
    let actor_id = require_active_global_admin(&state, &headers).await?;
    let key = IntegrationIdentityKey::new(request.app_id, request.issuer, request.subject)
        .map_err(|error| mapping_error(error, &request.operation_id))?;
    let operation_id = request.operation_id.clone();
    let revision = create_integration_identity_mapping(
        &state.db,
        CreateIntegrationIdentityMapping {
            key,
            user_id: request.user_id,
            identity_card_id: request.identity_card_id,
            operation_id: request.operation_id,
            actor_id,
        },
    )
    .await
    .map_err(|error| mapping_error(error, &operation_id))?;
    Ok(Json(ApiResponse::success(
        serde_json::json!({"revision": revision, "operationId": operation_id}),
    )))
}

async fn change_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<MappingStatusRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, MappingHttpError> {
    let actor_id = require_active_global_admin(&state, &headers).await?;
    let status = match request.status.as_str() {
        "DISABLED" => IntegrationIdentityMappingStatus::Disabled,
        "REVOKED" => IntegrationIdentityMappingStatus::Revoked,
        _ => {
            return Err(refused(
                StatusCode::BAD_REQUEST,
                "INVALID_MAPPING_STATUS",
                None,
                false,
            ))
        }
    };
    let key = IntegrationIdentityKey::new(request.app_id, request.issuer, request.subject)
        .map_err(|error| mapping_error(error, &request.operation_id))?;
    let operation_id = request.operation_id.clone();
    let revision = set_integration_identity_mapping_status(
        &state.db,
        SetIntegrationIdentityMappingStatus {
            key,
            expected_revision: request.expected_revision,
            status,
            operation_id: request.operation_id,
            actor_id,
        },
    )
    .await
    .map_err(|error| mapping_error(error, &operation_id))?;
    Ok(Json(ApiResponse::success(
        serde_json::json!({"revision": revision, "operationId": operation_id}),
    )))
}

fn mapping_error(error: IntegrationIdentityMappingError, operation_id: &str) -> MappingHttpError {
    use IntegrationIdentityMappingError::*;
    let (status, code, reconcile) = match error {
        InvalidInput { .. } => (StatusCode::BAD_REQUEST, "INVALID_IDENTITY_MAPPING", false),
        Conflict(_) => (StatusCode::CONFLICT, "IDENTITY_MAPPING_CONFLICT", false),
        NotFound => (StatusCode::NOT_FOUND, "IDENTITY_MAPPING_NOT_FOUND", false),
        SourceIdentityUnavailable => (
            StatusCode::FORBIDDEN,
            "IDENTITY_MAPPING_SOURCE_UNAVAILABLE",
            false,
        ),
        UnknownCommit(_) | InDoubtOperation(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "IDENTITY_MAPPING_OUTCOME_UNKNOWN",
            true,
        ),
        Database(_) | SchemaMismatch(_) | CorruptRow(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "IDENTITY_MAPPING_UNAVAILABLE",
            false,
        ),
    };
    refused(status, code, Some(operation_id), reconcile)
}

struct MappingHttpError {
    status: StatusCode,
    code: &'static str,
    operation_id: Option<String>,
    reconcile: bool,
}

fn refused(
    status: StatusCode,
    code: &'static str,
    operation_id: Option<&str>,
    reconcile: bool,
) -> MappingHttpError {
    MappingHttpError {
        status,
        code,
        reconcile,
        operation_id: operation_id
            .filter(|id| id.len() <= 64 && id.is_ascii())
            .map(str::to_owned),
    }
}

impl IntoResponse for MappingHttpError {
    fn into_response(self) -> Response {
        let MappingHttpError {
            status,
            code,
            operation_id,
            reconcile,
        } = self;
        let mut response = ApiResponse::<serde_json::Value>::error(
            status.as_u16().into(),
            "Identity mapping refused",
        );
        response.reason_code = Some(code.into());
        response.decision = Some(
            if reconcile || status == StatusCode::SERVICE_UNAVAILABLE {
                "PENDING"
            } else {
                "DENY"
            }
            .into(),
        );
        response.data = Some(serde_json::json!({"operationId": operation_id,
            "reconcileRequired": reconcile, "automaticRetry": false}));
        (status, Json(response)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn repository_errors_preserve_conflict_and_unknown_without_sql_details() {
        for (error, status, unknown) in [
            (
                IntegrationIdentityMappingError::Conflict("revision"),
                StatusCode::CONFLICT,
                false,
            ),
            (
                IntegrationIdentityMappingError::NotFound,
                StatusCode::NOT_FOUND,
                false,
            ),
            (
                IntegrationIdentityMappingError::Database("sensitive SQL".into()),
                StatusCode::SERVICE_UNAVAILABLE,
                false,
            ),
            (
                IntegrationIdentityMappingError::UnknownCommit("sensitive SQL".into()),
                StatusCode::SERVICE_UNAVAILABLE,
                true,
            ),
            (
                IntegrationIdentityMappingError::InDoubtOperation("pending"),
                StatusCode::SERVICE_UNAVAILABLE,
                true,
            ),
        ] {
            let response = mapping_error(error, "original-operation").into_response();
            assert_eq!(response.status(), status);
            let bytes = to_bytes(response.into_body(), 8192).await.unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["data"]["operationId"], "original-operation");
            assert_eq!(body["data"]["reconcileRequired"], unknown);
            assert!(!String::from_utf8(bytes.to_vec())
                .unwrap()
                .contains("sensitive SQL"));
            if unknown {
                assert_eq!(body["decision"], "PENDING");
            }
        }
    }
}
