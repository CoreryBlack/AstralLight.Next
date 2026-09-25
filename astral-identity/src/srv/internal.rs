use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime, PrimitiveDateTime};
use uuid::Uuid;

use crate::auth::{
    issue_access_token_for_identity_only, issue_refresh_token, sha256_hash, SessionContext,
    SessionGrant,
};
use crate::srv::app_user_repository::find_active_app_user_id;
use crate::srv::session::{create_token_family_with_expiry, store_session_grant_in_redis};
use crate::srv::session_repository::{cleanup_active_family, insert_app_device_session};
use crate::AppState;
use astral_common::audit::{spawn_internal_session_audit, InternalSessionAuditReason};
use astral_common::contract::ApiResponse;
use astral_common::error::AppError;
use astral_common::middleware::internal_signature::{
    normalize_query, sha256_hex, timestamp_is_within_tolerance, valid_component, valid_sha256_hex,
    verify_internal_signature, InternalSignatureInput, INTERNAL_BODY_SHA256_HEADER,
    INTERNAL_CALLER_GATEWAY, INTERNAL_CALLER_HEADER, INTERNAL_IDEMPOTENCY_HEADER,
    INTERNAL_KEY_ID_HEADER, INTERNAL_NONCE_HEADER, INTERNAL_PROTOCOL_HEADER,
    INTERNAL_PROTOCOL_VERSION, INTERNAL_REQUEST_ID_HEADER, INTERNAL_ROUTE_HEADER,
    INTERNAL_SERVICE_HEADER, INTERNAL_SESSION_PATH, INTERNAL_SIGNATURE_HEADER,
    INTERNAL_TIMESTAMP_HEADER, KEY_ID_GATEWAY_TO_IDENTITY, ROUTE_GATEWAY_TO_IDENTITY,
};
use astral_common::token_contract::PrincipalKind;
use astral_types::{AstralError, IdentityCard};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
pub struct AppSessionRequest {
    pub user_id: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSessionResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in_millis: i64,
    pub refresh_expires_in_millis: i64,
}

/// Internal service contract for Gateway -> Identity app-login. Only Identity
/// signs tokens; callers never receive or store signing keys.
pub fn internal_routes() -> Router<AppState> {
    Router::new().route(INTERNAL_SESSION_PATH, post(issue_app_session))
}

const INTERNAL_REPLAY_TTL_SECS: u64 = 60;
const INTERNAL_IDEMPOTENCY_TTL_SECS: u64 = 300;
const MAX_INTERNAL_BODY_BYTES: usize = 1024 * 1024;

fn internal_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn internal_auth_error(reason: InternalSessionAuditReason) -> AppError {
    AppError::from(AstralError::Auth(reason.as_str().into()))
}

fn audited_internal_error(user_id: i64, reason: InternalSessionAuditReason) -> AppError {
    spawn_internal_session_audit(user_id, false, reason);
    internal_auth_error(reason)
}

fn audit_and_preserve_error(
    user_id: i64,
    reason: InternalSessionAuditReason,
    error: AppError,
) -> AppError {
    spawn_internal_session_audit(user_id, false, reason);
    error
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedInternalAssertion {
    protocol_version: String,
    key_id: String,
    caller_service: String,
    method: String,
    path: String,
    normalized_query: String,
    body_sha256: String,
    target_user_id: String,
    timestamp: String,
    nonce: String,
    request_id: String,
    idempotency_key: String,
    route: String,
}

impl ValidatedInternalAssertion {
    fn signature_input(&self) -> InternalSignatureInput<'_> {
        InternalSignatureInput {
            protocol_version: &self.protocol_version,
            key_id: &self.key_id,
            caller_service: &self.caller_service,
            method: &self.method,
            path: &self.path,
            normalized_query: &self.normalized_query,
            body_sha256: &self.body_sha256,
            target_user_id: &self.target_user_id,
            timestamp: &self.timestamp,
            nonce: &self.nonce,
            request_id: &self.request_id,
            idempotency_key: &self.idempotency_key,
            route: &self.route,
        }
    }
}

#[derive(Debug, Clone)]
struct InternalAssertionRequest<'a> {
    secret: &'a str,
    timestamp_tolerance_secs: i64,
    headers: &'a HeaderMap,
    method: &'a str,
    path: &'a str,
    query: Option<&'a str>,
    body: &'a [u8],
    user_id: i64,
    now_ms: i128,
}

/// Validate the complete assertion without touching Redis. This pure boundary
/// keeps protocol rejection testable and ensures no request value is audited
/// before the HMAC has verified the signed target user id.
fn validate_internal_assertion(
    request: InternalAssertionRequest<'_>,
) -> Result<ValidatedInternalAssertion, InternalSessionAuditReason> {
    let InternalAssertionRequest {
        secret,
        timestamp_tolerance_secs,
        headers,
        method,
        path,
        query,
        body,
        user_id,
        now_ms,
    } = request;
    let value = |name: &str| internal_header(headers, name).unwrap_or("");
    if headers.contains_key("authorization")
        || headers.contains_key("x-internal-service-ts")
        || headers.contains_key("x-internal-service-signature")
    {
        return Err(InternalSessionAuditReason::InternalAssertionInvalid);
    }
    let required = [
        INTERNAL_PROTOCOL_HEADER,
        INTERNAL_SERVICE_HEADER,
        INTERNAL_CALLER_HEADER,
        INTERNAL_TIMESTAMP_HEADER,
        INTERNAL_NONCE_HEADER,
        INTERNAL_REQUEST_ID_HEADER,
        INTERNAL_IDEMPOTENCY_HEADER,
        INTERNAL_BODY_SHA256_HEADER,
        INTERNAL_SIGNATURE_HEADER,
        INTERNAL_KEY_ID_HEADER,
        INTERNAL_ROUTE_HEADER,
    ];
    if required
        .iter()
        .any(|name| internal_header(headers, name).is_none())
    {
        return Err(InternalSessionAuditReason::InternalAssertionMissing);
    }
    if method != "POST"
        || path != INTERNAL_SESSION_PATH
        || query.is_some()
        || value(INTERNAL_PROTOCOL_HEADER) != INTERNAL_PROTOCOL_VERSION
        || value(INTERNAL_SERVICE_HEADER) != INTERNAL_CALLER_GATEWAY
        || value(INTERNAL_CALLER_HEADER) != INTERNAL_CALLER_GATEWAY
        || value(INTERNAL_KEY_ID_HEADER) != KEY_ID_GATEWAY_TO_IDENTITY
        || value(INTERNAL_ROUTE_HEADER) != ROUTE_GATEWAY_TO_IDENTITY
        || !valid_component(value(INTERNAL_NONCE_HEADER), 128)
        || !valid_component(value(INTERNAL_REQUEST_ID_HEADER), 128)
        || !valid_component(value(INTERNAL_IDEMPOTENCY_HEADER), 256)
        || !valid_component(value(INTERNAL_ROUTE_HEADER), 128)
        || !valid_sha256_hex(value(INTERNAL_BODY_SHA256_HEADER))
    {
        return Err(InternalSessionAuditReason::InternalAssertionInvalid);
    }
    let body_hash = sha256_hex(body);
    if value(INTERNAL_BODY_SHA256_HEADER) != body_hash {
        return Err(InternalSessionAuditReason::InternalBodyHashInvalid);
    }

    let assertion = ValidatedInternalAssertion {
        protocol_version: value(INTERNAL_PROTOCOL_HEADER).to_owned(),
        key_id: value(INTERNAL_KEY_ID_HEADER).to_owned(),
        caller_service: value(INTERNAL_SERVICE_HEADER).to_owned(),
        method: method.to_owned(),
        path: path.to_owned(),
        normalized_query: normalize_query(query),
        body_sha256: value(INTERNAL_BODY_SHA256_HEADER).to_owned(),
        target_user_id: user_id.to_string(),
        timestamp: value(INTERNAL_TIMESTAMP_HEADER).to_owned(),
        nonce: value(INTERNAL_NONCE_HEADER).to_owned(),
        request_id: value(INTERNAL_REQUEST_ID_HEADER).to_owned(),
        idempotency_key: value(INTERNAL_IDEMPOTENCY_HEADER).to_owned(),
        route: value(INTERNAL_ROUTE_HEADER).to_owned(),
    };
    let input = assertion.signature_input();
    if !timestamp_is_within_tolerance(input.timestamp, timestamp_tolerance_secs, now_ms)
        || !verify_internal_signature(secret, &input, value(INTERNAL_SIGNATURE_HEADER))
    {
        return Err(InternalSessionAuditReason::InternalSignatureInvalid);
    }
    Ok(assertion)
}

/// Verify Gateway's complete internal-v1 assertion after buffering the raw body.
/// The Redis claims are deliberately made only after cryptographic verification.
async fn verify_internal_service_request(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    query: Option<&str>,
    body: &[u8],
    user_id: i64,
) -> Result<(), AppError> {
    let assertion = match validate_internal_assertion(InternalAssertionRequest {
        secret: &state.config.gateway.internal_service_secret,
        timestamp_tolerance_secs: state.config.gateway.timestamp_tolerance_secs,
        headers,
        method,
        path,
        query,
        body,
        user_id,
        now_ms: OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000,
    }) {
        Ok(assertion) => assertion,
        Err(reason) => return Err(audited_internal_error(0, reason)),
    };
    let input = assertion.signature_input();
    let body_hash = assertion.body_sha256.as_str();

    let client = redis::Client::open(state.config.redis_url.as_str()).map_err(|_| {
        audited_internal_error(user_id, InternalSessionAuditReason::AuthStateUnavailable)
    })?;
    let mut conn = client.get_connection_manager().await.map_err(|_| {
        audited_internal_error(user_id, InternalSessionAuditReason::AuthStateUnavailable)
    })?;
    let replay_key = astral_common::middleware::internal_signature::replay_key("identity", &input);
    let claimed: Option<String> = redis::cmd("SET")
        .arg(&replay_key)
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(INTERNAL_REPLAY_TTL_SECS)
        .query_async(&mut conn)
        .await
        .map_err(|_| {
            audited_internal_error(user_id, InternalSessionAuditReason::AuthStateUnavailable)
        })?;
    if claimed.is_none() {
        return Err(audited_internal_error(
            user_id,
            InternalSessionAuditReason::InternalReplayDetected,
        ));
    }

    let idem_key = astral_common::middleware::internal_signature::idempotency_key(
        "identity",
        input.caller_service,
        input.route,
        input.idempotency_key,
    );
    let marker = format!("processing:{body_hash}");
    let claimed: Option<String> = redis::cmd("SET")
        .arg(&idem_key)
        .arg(&marker)
        .arg("NX")
        .arg("EX")
        .arg(INTERNAL_IDEMPOTENCY_TTL_SECS)
        .query_async(&mut conn)
        .await
        .map_err(|_| {
            audited_internal_error(user_id, InternalSessionAuditReason::AuthStateUnavailable)
        })?;
    if claimed.is_none() {
        let existing: Option<String> = conn.get(&idem_key).await.map_err(|_| {
            audited_internal_error(user_id, InternalSessionAuditReason::AuthStateUnavailable)
        })?;
        return if existing
            .as_deref()
            .is_some_and(|value| value.ends_with(body_hash))
        {
            Err(audited_internal_error(
                user_id,
                InternalSessionAuditReason::IdempotencyReplay,
            ))
        } else {
            Err(audited_internal_error(
                user_id,
                InternalSessionAuditReason::IdempotencyConflict,
            ))
        };
    }
    Ok(())
}

async fn cleanup_app_session_failure(
    state: &AppState,
    family_id: i64,
    user_id: i64,
    created_identity_card: bool,
    identity_card_id: Option<i64>,
) {
    if let Err(error) = cleanup_active_family(&state.db, family_id, user_id).await {
        tracing::error!(family_id, %error, "app session family cleanup failed");
    }
    if created_identity_card {
        if let Some(card_id) = identity_card_id {
            if let Err(error) = state
                .card_repository
                .delete_created_identity_card(user_id, card_id)
                .await
            {
                tracing::error!(user_id, card_id, %error, "app session identity card cleanup failed");
            }
        }
    }
}

async fn issue_app_session(
    State(state): State<AppState>,
    request: Request,
) -> Result<Response, AppError> {
    let (parts, body_stream) = request.into_parts();
    let body = axum::body::to_bytes(body_stream, MAX_INTERNAL_BODY_BYTES)
        .await
        .map_err(|_| {
            spawn_internal_session_audit(0, false, InternalSessionAuditReason::BodyTooLarge);
            internal_auth_error(InternalSessionAuditReason::BodyTooLarge)
        })?;
    let req: AppSessionRequest = serde_json::from_slice(&body).map_err(|_| {
        spawn_internal_session_audit(0, false, InternalSessionAuditReason::BodyInvalid);
        internal_auth_error(InternalSessionAuditReason::BodyInvalid)
    })?;
    verify_internal_service_request(
        &state,
        &parts.headers,
        parts.method.as_str(),
        parts.uri.path(),
        parts.uri.query(),
        &body,
        req.user_id,
    )
    .await?;
    if req.user_id <= 0 {
        return Err(audited_internal_error(
            0,
            InternalSessionAuditReason::AppUserNotFound,
        ));
    }
    // app_user 存在性校验（app_user_repository 自由函数）
    let active = find_active_app_user_id(&state.db, req.user_id)
        .await
        .map_err(|_| {
            spawn_internal_session_audit(
                req.user_id,
                false,
                InternalSessionAuditReason::AuthStateUnavailable,
            );
            AppError::from(AstralError::Auth("Session issuance unavailable".into()))
        })?;
    if active.is_none() {
        return Err(audited_internal_error(
            req.user_id,
            InternalSessionAuditReason::AppUserNotFound,
        ));
    }
    let (card_row, created_identity_card) = state
        .card_repository
        .ensure_active_identity_card(req.user_id)
        .await
        .map_err(|error| {
            audit_and_preserve_error(
                req.user_id,
                InternalSessionAuditReason::SessionIssuanceFailed,
                AppError::from(error),
            )
        })?;
    let identity_card_id = card_row.card_id;
    let id_card = IdentityCard {
        card_id: card_row.card_id,
        user_id: card_row.user_id,
        status: card_row.status,
        token_version: card_row.token_version,
        expires_at: card_row.expires_at,
        disabled_reason: None,
        last_used_at: None,
        created_at: None,
        updated_at: None,
    };
    let refresh_lifetime = state.config.jwt.refresh.expiry_seconds;
    let refresh_expiry = {
        let now = OffsetDateTime::now_utc() + Duration::seconds(refresh_lifetime);
        PrimitiveDateTime::new(now.date(), now.time())
    };
    let family_key = Uuid::new_v4().to_string();
    let family_id =
        match create_token_family_with_expiry(&state.db, &family_key, req.user_id, refresh_expiry)
            .await
        {
            Ok(family_id) => family_id,
            Err(error) => {
                if created_identity_card {
                    if let Some(card_id) = identity_card_id {
                        let _ = state
                            .card_repository
                            .delete_created_identity_card(req.user_id, card_id)
                            .await;
                    }
                }
                return Err(audit_and_preserve_error(
                    req.user_id,
                    InternalSessionAuditReason::SessionIssuanceFailed,
                    AppError::from(error),
                ));
            }
        };
    let placeholder_hash = sha256_hash(&format!("pending:{}", Uuid::new_v4()));
    // 设备会话行写入（session_repository 自由函数）
    let session_result = insert_app_device_session(
        &state.db,
        family_id,
        req.user_id,
        &placeholder_hash,
        refresh_expiry,
    )
    .await;
    let session_id = match session_result {
        Ok(session_id) => session_id,
        Err(session_error) => {
            cleanup_app_session_failure(
                &state,
                family_id,
                req.user_id,
                created_identity_card,
                identity_card_id,
            )
            .await;
            return Err(audit_and_preserve_error(
                req.user_id,
                InternalSessionAuditReason::SessionIssuanceFailed,
                AppError::from(session_error),
            ));
        }
    };
    let session_context = SessionContext {
        session_id,
        session_version: 1,
        session_epoch: 1,
        family_id,
    };
    let access =
        match issue_access_token_for_identity_only(&state.config.jwt, &id_card, session_context) {
            Ok(token) => token,
            Err(error) => {
                cleanup_app_session_failure(
                    &state,
                    family_id,
                    req.user_id,
                    created_identity_card,
                    identity_card_id,
                )
                .await;
                return Err(audit_and_preserve_error(
                    req.user_id,
                    InternalSessionAuditReason::SessionIssuanceFailed,
                    AppError::from(error),
                ));
            }
        };
    let refresh = match issue_refresh_token(
        &state.config.jwt,
        req.user_id,
        PrincipalKind::AppUser,
        session_context,
    ) {
        Ok(token) => token,
        Err(error) => {
            cleanup_app_session_failure(
                &state,
                family_id,
                req.user_id,
                created_identity_card,
                identity_card_id,
            )
            .await;
            return Err(audit_and_preserve_error(
                req.user_id,
                InternalSessionAuditReason::SessionIssuanceFailed,
                AppError::from(error),
            ));
        }
    };
    let refresh_hash = sha256_hash(&refresh.token);
    if let Err(error) = sqlx::query(
        "UPDATE auth_device_session SET refresh_token_hash = ? WHERE session_id = ? \
         AND refresh_token_hash = ? AND status = 'ACTIVE' AND session_state = 'ACTIVE'",
    )
    .bind(&refresh_hash)
    .bind(session_id)
    .bind(&placeholder_hash)
    .execute(&state.db)
    .await
    .map_err(|error| AstralError::Database(format!("Bind app refresh token failed: {error}")))
    .and_then(|result| {
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(AstralError::Auth(
                "App session refresh binding was fenced".into(),
            ))
        }
    }) {
        cleanup_app_session_failure(
            &state,
            family_id,
            req.user_id,
            created_identity_card,
            identity_card_id,
        )
        .await;
        return Err(audit_and_preserve_error(
            req.user_id,
            InternalSessionAuditReason::SessionIssuanceFailed,
            AppError::from(error),
        ));
    }
    if let Err(redis_error) = store_session_grant_in_redis(
        &state,
        &access,
        SessionGrant::active(
            &access,
            PrincipalKind::AppUser,
            req.user_id,
            session_id,
            id_card.card_id,
            None,
            None,
            None,
            1,
            1,
            family_id,
        ),
    )
    .await
    {
        cleanup_app_session_failure(
            &state,
            family_id,
            req.user_id,
            created_identity_card,
            identity_card_id,
        )
        .await;
        return Err(audit_and_preserve_error(
            req.user_id,
            InternalSessionAuditReason::SessionIssuanceFailed,
            AppError::from(redis_error),
        ));
    }
    spawn_internal_session_audit(
        req.user_id,
        true,
        InternalSessionAuditReason::AppSessionSuccess,
    );
    Ok(Json(ApiResponse::success(AppSessionResponse {
        access_token: access.token,
        refresh_token: refresh.token,
        token_type: "Bearer".into(),
        expires_in_millis: access.expires_in * 1000,
        refresh_expires_in_millis: refresh.expires_in * 1000,
    }))
    .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_common::middleware::internal_signature::compute_internal_signature;
    use astral_common::middleware::internal_signature::INTERNAL_CALLER_LEARN;
    use axum::http::{HeaderValue, Method};

    const SECRET: &str = "gateway-to-identity-test-secret-0123456789";
    const NOW_MS: i128 = 1_700_000_000_000;
    const USER_ID: i64 = 42;

    fn signed_headers(body: &[u8], timestamp: &str) -> HeaderMap {
        let body_hash = sha256_hex(body);
        let nonce = "nonce-1";
        let request_id = "request-1";
        let idempotency_key = "idempotency-1";
        let route = ROUTE_GATEWAY_TO_IDENTITY;
        let input = InternalSignatureInput {
            protocol_version: INTERNAL_PROTOCOL_VERSION,
            key_id: KEY_ID_GATEWAY_TO_IDENTITY,
            caller_service: INTERNAL_CALLER_GATEWAY,
            method: "POST",
            path: INTERNAL_SESSION_PATH,
            normalized_query: "",
            body_sha256: &body_hash,
            target_user_id: "42",
            timestamp,
            nonce,
            request_id,
            idempotency_key,
            route,
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            INTERNAL_PROTOCOL_HEADER,
            HeaderValue::from_static(INTERNAL_PROTOCOL_VERSION),
        );
        headers.insert(
            INTERNAL_SERVICE_HEADER,
            HeaderValue::from_static(INTERNAL_CALLER_GATEWAY),
        );
        headers.insert(
            INTERNAL_CALLER_HEADER,
            HeaderValue::from_static(INTERNAL_CALLER_GATEWAY),
        );
        headers.insert(
            INTERNAL_TIMESTAMP_HEADER,
            HeaderValue::from_str(timestamp).unwrap(),
        );
        headers.insert(INTERNAL_NONCE_HEADER, HeaderValue::from_static(nonce));
        headers.insert(
            INTERNAL_REQUEST_ID_HEADER,
            HeaderValue::from_static(request_id),
        );
        headers.insert(
            INTERNAL_IDEMPOTENCY_HEADER,
            HeaderValue::from_static(idempotency_key),
        );
        headers.insert(
            INTERNAL_BODY_SHA256_HEADER,
            HeaderValue::from_str(&body_hash).unwrap(),
        );
        headers.insert(
            INTERNAL_SIGNATURE_HEADER,
            HeaderValue::from_str(&compute_internal_signature(SECRET, &input)).unwrap(),
        );
        headers.insert(
            INTERNAL_KEY_ID_HEADER,
            HeaderValue::from_static(KEY_ID_GATEWAY_TO_IDENTITY),
        );
        headers.insert(INTERNAL_ROUTE_HEADER, HeaderValue::from_static(route));
        headers
    }

    fn validate(
        headers: &HeaderMap,
        body: &[u8],
        user_id: i64,
    ) -> Result<ValidatedInternalAssertion, InternalSessionAuditReason> {
        validate_internal_assertion(InternalAssertionRequest {
            secret: SECRET,
            timestamp_tolerance_secs: 30,
            headers,
            method: Method::POST.as_str(),
            path: INTERNAL_SESSION_PATH,
            query: None,
            body,
            user_id,
            now_ms: NOW_MS,
        })
    }

    #[test]
    fn direct_learn_headers_are_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(
            INTERNAL_SERVICE_HEADER,
            HeaderValue::from_static(INTERNAL_CALLER_LEARN),
        );
        headers.insert(
            "x-internal-service-ts",
            HeaderValue::from_static("1700000000000"),
        );
        headers.insert(
            "x-internal-service-signature",
            HeaderValue::from_static("legacy"),
        );
        assert_eq!(
            validate(&headers, br#"{"userId":42}"#, USER_ID),
            Err(InternalSessionAuditReason::InternalAssertionInvalid)
        );
    }

    #[test]
    fn valid_assertion_is_accepted_without_redis() {
        let body = br#"{"userId":42}"#;
        let headers = signed_headers(body, "1700000000000");
        let assertion = validate(&headers, body, USER_ID).expect("valid assertion");
        assert_eq!(assertion.target_user_id, "42");
    }

    #[test]
    fn method_path_query_body_user_and_signature_mutations_are_rejected() {
        let body = br#"{"userId":42}"#;
        let headers = signed_headers(body, "1700000000000");
        assert_eq!(
            validate_internal_assertion(InternalAssertionRequest {
                secret: SECRET,
                timestamp_tolerance_secs: 30,
                headers: &headers,
                method: "GET",
                path: INTERNAL_SESSION_PATH,
                query: None,
                body,
                user_id: USER_ID,
                now_ms: NOW_MS,
            }),
            Err(InternalSessionAuditReason::InternalAssertionInvalid)
        );
        assert_eq!(
            validate_internal_assertion(InternalAssertionRequest {
                secret: SECRET,
                timestamp_tolerance_secs: 30,
                headers: &headers,
                method: "POST",
                path: "/api/v1/auth/internal/session",
                query: None,
                body,
                user_id: USER_ID,
                now_ms: NOW_MS,
            }),
            Err(InternalSessionAuditReason::InternalAssertionInvalid)
        );
        assert_eq!(
            validate_internal_assertion(InternalAssertionRequest {
                secret: SECRET,
                timestamp_tolerance_secs: 30,
                headers: &headers,
                method: "POST",
                path: INTERNAL_SESSION_PATH,
                query: Some("unexpected=true"),
                body,
                user_id: USER_ID,
                now_ms: NOW_MS,
            }),
            Err(InternalSessionAuditReason::InternalAssertionInvalid)
        );

        let changed_body = br#"{"userId":43}"#;
        assert_eq!(
            validate(&headers, changed_body, USER_ID),
            Err(InternalSessionAuditReason::InternalBodyHashInvalid)
        );
        assert_eq!(
            validate(&headers, body, 43),
            Err(InternalSessionAuditReason::InternalSignatureInvalid)
        );

        let mut invalid_signature = headers.clone();
        invalid_signature.insert(
            INTERNAL_SIGNATURE_HEADER,
            HeaderValue::from_static("invalid"),
        );
        assert_eq!(
            validate(&invalid_signature, body, USER_ID),
            Err(InternalSessionAuditReason::InternalSignatureInvalid)
        );
    }

    #[test]
    fn unknown_json_fields_are_rejected_before_assertion_verification() {
        let body = br#"{"userId":42,"phone":"not-a-contract-field"}"#;
        assert!(serde_json::from_slice::<AppSessionRequest>(body).is_err());
    }

    #[test]
    fn illegal_and_expired_assertions_are_rejected() {
        let body = br#"{"userId":42}"#;
        let mut illegal = signed_headers(body, "1700000000000");
        let oversized_nonce = "n".repeat(129);
        illegal.insert(
            INTERNAL_NONCE_HEADER,
            HeaderValue::from_str(&oversized_nonce).unwrap(),
        );
        assert_eq!(
            validate(&illegal, body, USER_ID),
            Err(InternalSessionAuditReason::InternalAssertionInvalid)
        );

        let expired = signed_headers(body, "1699999900000");
        assert_eq!(
            validate(&expired, body, USER_ID),
            Err(InternalSessionAuditReason::InternalSignatureInvalid)
        );
    }
}
