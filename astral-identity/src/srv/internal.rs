use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
#[cfg(feature = "redis-compat")]
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime, PrimitiveDateTime};
use uuid::Uuid;

use crate::auth::{
    issue_access_token_for_identity_only, issue_refresh_token, sha256_hash, SessionContext,
    SessionGrant,
};
use crate::srv::app_user_repository::find_active_app_user_id;
use crate::srv::session::{create_token_family_with_expiry, store_session_grant_projection};
use crate::srv::session_repository::{cleanup_active_family, insert_app_device_session};
use crate::srv::source_writer_guard;
use crate::AppState;
use astral_common::audit::{spawn_internal_session_audit, InternalSessionAuditReason};
use astral_common::contract::ApiResponse;
use astral_common::error::AppError;
use astral_common::middleware::internal_signature::{
    idempotency_key, normalize_query, replay_key, sha256_hex, timestamp_is_within_tolerance,
    valid_component, valid_sha256_hex, verify_internal_signature, InternalSignatureInput,
    INTERNAL_BODY_SHA256_HEADER, INTERNAL_CALLER_GATEWAY, INTERNAL_CALLER_HEADER,
    INTERNAL_IDEMPOTENCY_HEADER, INTERNAL_KEY_ID_HEADER, INTERNAL_NONCE_HEADER,
    INTERNAL_PROTOCOL_HEADER, INTERNAL_PROTOCOL_VERSION, INTERNAL_REQUEST_ID_HEADER,
    INTERNAL_ROUTE_HEADER, INTERNAL_SERVICE_HEADER, INTERNAL_SESSION_PATH,
    INTERNAL_SIGNATURE_HEADER, INTERNAL_TIMESTAMP_HEADER, KEY_ID_GATEWAY_TO_IDENTITY,
    ROUTE_GATEWAY_TO_IDENTITY,
};
use astral_common::token_contract::PrincipalKind;
use astral_db::{
    claim_idempotency_guard, claim_replay_guard, idempotency_marker_decision, load_guard_marker,
    GuardClaim, GUARD_SCOPE_IDENTITY_IDEMPOTENCY, GUARD_SCOPE_IDENTITY_REPLAY,
};
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

/// replay 记忆窗口下限（秒）：必须覆盖整个时间戳容忍窗，否则 guard 过期后
/// 断言仍可在容忍窗内重放。实际 TTL 取 `timestamp_tolerance_secs.max(60)`
/// （对齐 Gateway durable guard 前例；默认 tolerance=30 时与历史固定 60s
/// 完全一致）。
const INTERNAL_REPLAY_TTL_SECS: i64 = 60;
/// 幂等 in-flight 标记 TTL（秒）：与历史 Redis `SET NX EX 300` 语义一致。
const INTERNAL_IDEMPOTENCY_TTL_SECS: i64 = 300;
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

/// Guard 声明阶段的统一拒绝语义（纯枚举，fail-closed）：store 故障/未知
/// 一律 `StateUnavailable`，绝不本地放行；其余按历史 Redis 语义分类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InternalGuardRejection {
    ReplayDetected,
    IdempotencyReplay,
    IdempotencyConflict,
    StateUnavailable,
}

impl InternalGuardRejection {
    fn audit_reason(self) -> InternalSessionAuditReason {
        match self {
            Self::ReplayDetected => InternalSessionAuditReason::InternalReplayDetected,
            Self::IdempotencyReplay => InternalSessionAuditReason::IdempotencyReplay,
            Self::IdempotencyConflict => InternalSessionAuditReason::IdempotencyConflict,
            Self::StateUnavailable => InternalSessionAuditReason::AuthStateUnavailable,
        }
    }
}

fn guard_rejection_error(user_id: i64, rejection: InternalGuardRejection) -> AppError {
    audited_internal_error(user_id, rejection.audit_reason())
}

/// replay 声明判定（纯函数，store 无关）：Claimed 放行、Duplicate 重放、
/// store 故障/未知按不可用拒绝。
fn replay_claim_outcome(claim: Result<GuardClaim, ()>) -> Result<(), InternalGuardRejection> {
    match claim {
        Ok(GuardClaim::Claimed) => Ok(()),
        Ok(GuardClaim::Duplicate) => Err(InternalGuardRejection::ReplayDetected),
        Err(()) => Err(InternalGuardRejection::StateUnavailable),
    }
}

/// 幂等声明判定（纯函数，store 无关）。marker 判定复用
/// [`astral_db::idempotency_marker_decision`]（与 Gateway 同一决策原语）：
/// 同 key 同 body → 重放，同 key 异 body / 行消失（并发 purge 竞态）→ 冲突，
/// marker 读取故障 → 未知拒绝；store 故障 → 不可用拒绝。
fn idempotency_claim_outcome(
    claim: Result<GuardClaim, ()>,
    marker: Result<Option<String>, ()>,
    body_hash: &str,
) -> Result<(), InternalGuardRejection> {
    match claim {
        Ok(GuardClaim::Claimed) => Ok(()),
        Ok(GuardClaim::Duplicate) => match marker {
            Ok(Some(existing)) => {
                match idempotency_marker_decision(Some(existing.as_str()), body_hash) {
                    Ok(GuardClaim::Duplicate) => Err(InternalGuardRejection::IdempotencyReplay),
                    // marker 判定不产生 Claimed（仅声明路径返回）；穷尽匹配兜底拒绝。
                    Ok(GuardClaim::Claimed) | Err(_) => {
                        Err(InternalGuardRejection::IdempotencyConflict)
                    }
                }
            }
            // 行消失：fail-closed 按冲突拒绝，绝不重放。
            Ok(None) => Err(InternalGuardRejection::IdempotencyConflict),
            Err(()) => Err(InternalGuardRejection::StateUnavailable),
        },
        Err(()) => Err(InternalGuardRejection::StateUnavailable),
    }
}

/// 默认 Redis-free 路径：MySQL durable guard（`auth_internal_request_guard`，
/// 与 Gateway 完全相同的原语）。UNIQUE(guard_scope, guard_key) 即分布式互斥，
/// `expires_at` 承载 TTL（purge 过期后可重声明，等价 SET NX EX），多节点安全；
/// DB 不可用 → `StateUnavailable`（fail-closed），绝不本地放行。
async fn claim_internal_guards_mysql(
    db: &sqlx::MySqlPool,
    input: &InternalSignatureInput<'_>,
    body_hash: &str,
    replay_ttl_secs: i64,
) -> Result<(), InternalGuardRejection> {
    let replay_key = replay_key("identity", input);
    let claim = claim_replay_guard(
        db,
        GUARD_SCOPE_IDENTITY_REPLAY,
        &replay_key,
        replay_ttl_secs,
    )
    .await
    .map_err(|_| ());
    replay_claim_outcome(claim)?;

    let idem_key = idempotency_key(
        "identity",
        input.caller_service,
        input.route,
        input.idempotency_key,
    );
    let claim = claim_idempotency_guard(
        db,
        GUARD_SCOPE_IDENTITY_IDEMPOTENCY,
        &idem_key,
        body_hash,
        INTERNAL_IDEMPOTENCY_TTL_SECS,
    )
    .await
    .map_err(|_| ());
    let marker = if matches!(claim, Ok(GuardClaim::Duplicate)) {
        load_guard_marker(db, GUARD_SCOPE_IDENTITY_IDEMPOTENCY, &idem_key)
            .await
            .map_err(|_| ())
    } else {
        Ok(None)
    };
    idempotency_claim_outcome(claim, marker, body_hash)
}

/// 兼容路径：仅在 runtime 依据 `redis_projection_compat_enabled`（显式开启且
/// URL 非空，见 `RedisCompatRequiresUrl` 校验）装配 compat adapter 时可达。
/// 复用启动期建立的 ConnectionManager，不再逐请求 `Client::open`；claim 语义
/// 与历史 `SET NX EX` 逐字段一致。
#[cfg(feature = "redis-compat")]
async fn claim_internal_guards_redis_compat(
    conn: &mut redis::aio::ConnectionManager,
    input: &InternalSignatureInput<'_>,
    body_hash: &str,
    replay_ttl_secs: i64,
) -> Result<(), InternalGuardRejection> {
    // Redis SET NX 返回 Ok(nil) 表示键已存在 → Duplicate；命令错误 → Err(())。
    let replay_key = replay_key("identity", input);
    let claimed: Result<Option<String>, _> = redis::cmd("SET")
        .arg(&replay_key)
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(replay_ttl_secs)
        .query_async(conn)
        .await;
    let claim: Result<GuardClaim, ()> = match claimed {
        Ok(Some(_)) => Ok(GuardClaim::Claimed),
        Ok(None) => Ok(GuardClaim::Duplicate),
        Err(_) => Err(()),
    };
    replay_claim_outcome(claim)?;

    let idem_key = idempotency_key(
        "identity",
        input.caller_service,
        input.route,
        input.idempotency_key,
    );
    let claimed: Result<Option<String>, _> = redis::cmd("SET")
        .arg(&idem_key)
        .arg(format!("processing:{body_hash}"))
        .arg("NX")
        .arg("EX")
        .arg(INTERNAL_IDEMPOTENCY_TTL_SECS)
        .query_async(conn)
        .await;
    let claim: Result<GuardClaim, ()> = match claimed {
        Ok(Some(_)) => Ok(GuardClaim::Claimed),
        Ok(None) => Ok(GuardClaim::Duplicate),
        Err(_) => Err(()),
    };
    let marker = if matches!(claim, Ok(GuardClaim::Duplicate)) {
        conn.get::<_, Option<String>>(&idem_key)
            .await
            .map_err(|_| ())
    } else {
        Ok(None)
    };
    idempotency_claim_outcome(claim, marker, body_hash)
}

/// Verify Gateway's complete internal-v1 assertion after buffering the raw body.
///
/// replay/idempotency 声明只在 HMAC 验签通过后进行。默认 Redis-free 路径使用
/// MySQL durable guard（与 Gateway 相同原语，多节点安全、fail-closed）；仅当
/// `redis_projection_compat_enabled` 显式开启且 runtime 装配了 compat adapter
/// （`state.redis = Some`，启动期已验证非空 URL 并完成连接）时走历史 Redis
/// 语义。两条路径共享同一套纯判定层（`replay_claim_outcome` /
/// `idempotency_claim_outcome`），错误语义逐项对齐：
/// store 故障/未知 → `AuthStateUnavailable`（审计后拒绝），重放/冲突分别
/// `InternalReplayDetected` / `IdempotencyReplay` / `IdempotencyConflict`。
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
    let replay_ttl_secs = state
        .config
        .gateway
        .timestamp_tolerance_secs
        .max(INTERNAL_REPLAY_TTL_SECS);
    #[cfg(feature = "redis-compat")]
    let outcome = match state.redis.as_ref() {
        // 显式 compat：runtime 仅在 redis_projection_compat_enabled 开启且
        // URL 非空时装配（见 runtime.rs），复用其 ConnectionManager。
        Some(conn) => {
            let mut conn = conn.clone();
            claim_internal_guards_redis_compat(&mut conn, &input, body_hash, replay_ttl_secs).await
        }
        // 默认 Redis-free：MySQL durable guard（auth_internal_request_guard）。
        None => claim_internal_guards_mysql(&state.db, &input, body_hash, replay_ttl_secs).await,
    };
    // 默认 Redis-free：MySQL durable guard（auth_internal_request_guard）。
    // feature-off 构建中 compat adapter 不存在（AppState 无 redis 字段），
    // 一律 durable guard，绝不静默改判。
    #[cfg(not(feature = "redis-compat"))]
    let outcome = claim_internal_guards_mysql(&state.db, &input, body_hash, replay_ttl_secs).await;
    outcome.map_err(|rejection| guard_rejection_error(user_id, rejection))
}

async fn cleanup_app_session_failure(
    state: &AppState,
    family_id: i64,
    user_id: i64,
    created_identity_card: bool,
    identity_card_id: Option<i64>,
) {
    // 补偿清理（family DELETE，FK 级联删除会话）同样持有 source writer 栅栏：
    // 失败路径的 source mutation 不绕过 writer 互斥；栅栏不可得视为清理失败
    // （仅记录，与清理 SQL 失败同语义——补偿本身 best-effort）。
    match source_writer_guard::begin_source_write() {
        Ok(source_guard) => {
            if let Err(error) = source_writer_guard::fenced_source_write(source_guard, async {
                cleanup_active_family(&state.db, family_id, user_id).await
            })
            .await
            {
                tracing::error!(family_id, %error, "app session family cleanup failed");
            }
        }
        Err(fence_error) => {
            tracing::error!(
                family_id,
                %fence_error,
                "app session family cleanup fence unavailable; cleanup skipped"
            );
        }
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
    // App 会话 refresh 绑定事实（会话创建事实束的一部分）的 autocommit source
    // 栅栏：hub 已装则 fail-closed 取得；await 窗口武装取消栅栏，结果判定后
    // settle（绑定 CAS 未命中未发生 mutation，同样 proven 释放）。
    let bind_guard = source_writer_guard::begin_source_write()?;
    if let Err(error) = source_writer_guard::fenced_source_write(
        bind_guard,
        sqlx::query(
            "UPDATE auth_device_session SET refresh_token_hash = ? WHERE session_id = ? \
             AND refresh_token_hash = ? AND status = 'ACTIVE' AND session_state = 'ACTIVE'",
        )
        .bind(&refresh_hash)
        .bind(session_id)
        .bind(&placeholder_hash)
        .execute(&state.db),
    )
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
    if let Err(projection_error) = store_session_grant_projection(
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
            AppError::from(projection_error),
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

    fn sample_input<'a>(body_hash: &'a str) -> InternalSignatureInput<'a> {
        InternalSignatureInput {
            protocol_version: INTERNAL_PROTOCOL_VERSION,
            key_id: KEY_ID_GATEWAY_TO_IDENTITY,
            caller_service: INTERNAL_CALLER_GATEWAY,
            method: "POST",
            path: INTERNAL_SESSION_PATH,
            normalized_query: "",
            body_sha256: body_hash,
            target_user_id: "42",
            timestamp: "1700000000000",
            nonce: "nonce-1",
            request_id: "request-1",
            idempotency_key: "idempotency-1",
            route: ROUTE_GATEWAY_TO_IDENTITY,
        }
    }

    #[test]
    fn guard_rejection_maps_to_fail_closed_audit_reasons() {
        assert_eq!(
            InternalGuardRejection::ReplayDetected.audit_reason(),
            InternalSessionAuditReason::InternalReplayDetected
        );
        assert_eq!(
            InternalGuardRejection::IdempotencyReplay.audit_reason(),
            InternalSessionAuditReason::IdempotencyReplay
        );
        assert_eq!(
            InternalGuardRejection::IdempotencyConflict.audit_reason(),
            InternalSessionAuditReason::IdempotencyConflict
        );
        // store 故障/未知结果 → AUTH_STATE_UNAVAILABLE（拒绝放行，不降级）。
        assert_eq!(
            InternalGuardRejection::StateUnavailable.audit_reason(),
            InternalSessionAuditReason::AuthStateUnavailable
        );
    }

    #[test]
    fn claimed_guard_outcomes_accept_request_without_redis() {
        // 默认 MySQL durable 路径的接受判定：两阶段均 Claimed → 放行，
        // 全程无 Redis 参与（state.redis = None 时唯一可达路径）。
        assert_eq!(replay_claim_outcome(Ok(GuardClaim::Claimed)), Ok(()));
        assert_eq!(
            idempotency_claim_outcome(Ok(GuardClaim::Claimed), Ok(None), "abc"),
            Ok(())
        );
    }

    #[test]
    fn replay_claim_outcome_rejects_duplicate_and_unknown() {
        assert_eq!(
            replay_claim_outcome(Ok(GuardClaim::Duplicate)),
            Err(InternalGuardRejection::ReplayDetected)
        );
        // store 故障/未知结果 fail-closed。
        assert_eq!(
            replay_claim_outcome(Err(())),
            Err(InternalGuardRejection::StateUnavailable)
        );
    }

    #[test]
    fn idempotency_claim_outcome_covers_replay_conflict_missing_and_unknown() {
        let body_hash = sha256_hex(br#"{"userId":42}"#);
        let other_hash = sha256_hex(br#"{"userId":43}"#);
        let marker = format!("processing:{body_hash}");
        // 同 key 同 body → 重放（复用共享 marker 决策原语）。
        assert_eq!(
            idempotency_claim_outcome(
                Ok(GuardClaim::Duplicate),
                Ok(Some(marker.clone())),
                &body_hash
            ),
            Err(InternalGuardRejection::IdempotencyReplay)
        );
        // 同 key 异 body → 冲突。
        assert_eq!(
            idempotency_claim_outcome(
                Ok(GuardClaim::Duplicate),
                Ok(Some(format!("processing:{other_hash}"))),
                &body_hash
            ),
            Err(InternalGuardRejection::IdempotencyConflict)
        );
        // 行消失（并发 purge 竞态）→ fail-closed 冲突拒绝，绝不重放。
        assert_eq!(
            idempotency_claim_outcome(Ok(GuardClaim::Duplicate), Ok(None), &body_hash),
            Err(InternalGuardRejection::IdempotencyConflict)
        );
        // marker 读取故障 → 未知拒绝。
        assert_eq!(
            idempotency_claim_outcome(Ok(GuardClaim::Duplicate), Err(()), &body_hash),
            Err(InternalGuardRejection::StateUnavailable)
        );
        // 声明阶段 store 故障 → 未知拒绝。
        assert_eq!(
            idempotency_claim_outcome(Err(()), Ok(Some(marker)), &body_hash),
            Err(InternalGuardRejection::StateUnavailable)
        );
    }

    #[test]
    fn identity_guard_keys_are_stable_namespaced_and_bounded() {
        let body_hash = sha256_hex(br#"{"userId":42}"#);
        let input = sample_input(&body_hash);
        let identity_replay = replay_key("identity", &input);
        let identity_idem = idempotency_key(
            "identity",
            input.caller_service,
            input.route,
            input.idempotency_key,
        );

        // 稳定性：同上下文 → 同键（durable guard 的幂等性依赖稳定键）。
        assert_eq!(identity_replay, replay_key("identity", &input));
        assert_eq!(
            identity_idem,
            idempotency_key(
                "identity",
                input.caller_service,
                input.route,
                input.idempotency_key
            )
        );

        // 命名空间隔离：identity 键不得与 gateway 键碰撞。
        assert_ne!(identity_replay, replay_key("gateway", &input));
        assert_ne!(
            identity_idem,
            idempotency_key(
                "gateway",
                input.caller_service,
                input.route,
                input.idempotency_key
            )
        );

        // 有界性：scope + 派生键必须满足 guard 表输入约束，防止超长键打满表。
        assert!(astral_db::guard_input_is_valid(
            astral_db::GUARD_SCOPE_IDENTITY_REPLAY,
            &identity_replay
        ));
        assert!(astral_db::guard_input_is_valid(
            astral_db::GUARD_SCOPE_IDENTITY_IDEMPOTENCY,
            &identity_idem
        ));

        // marker 约定与 durable guard 写入侧（processing:{body_sha256}）一致。
        assert_eq!(
            idempotency_marker_decision(Some(&format!("processing:{body_hash}")), &body_hash),
            Ok(GuardClaim::Duplicate)
        );
    }

    #[test]
    fn redis_free_default_path_is_wired_to_durable_guard() {
        let source = include_str!("internal.rs");
        // 逐请求 Client::open 必须移除：默认路径不得再依赖 Redis 可用性。
        // needle 由片段拼出，避免本测试源码自匹配。
        let needle = format!("redis::Client::{}", "ope");
        let needle = format!("{needle}n");
        assert!(
            !source.contains(&needle),
            "per-request redis client construction must not return"
        );
        // 默认路径绑定 MySQL durable guard 原语（与 Gateway 同表同语义）。
        assert!(source.contains("claim_replay_guard"));
        assert!(source.contains("claim_idempotency_guard"));
        assert!(source.contains("GUARD_SCOPE_IDENTITY_REPLAY"));
        assert!(source.contains("GUARD_SCOPE_IDENTITY_IDEMPOTENCY"));
        // 实现选择以 runtime 装配的 compat adapter 为准：Some=显式兼容路径，
        // None=默认 MySQL durable 路径。
        assert!(source.contains("match state.redis.as_ref()"));
        // 判定层复用共享 marker 决策原语，与 Gateway 语义一致。
        assert!(source.contains("idempotency_marker_decision"));
    }

    /// 会话创建事实束的 source 栅栏形状回归（源形状，无 IO）：app 会话签发的
    /// refresh 绑定 UPDATE 与失败补偿 family 清理都必须持有 source writer 栅栏
    /// （hub 未装 no-op；绑定 await 窗口武装取消栅栏）。
    #[test]
    fn app_session_bind_and_cleanup_hold_the_source_writer_fence() {
        let source = include_str!("internal.rs");
        let issue_body = source
            .split("async fn issue_app_session(")
            .nth(1)
            .expect("issue_app_session must stay")
            .split("#[cfg(test)]")
            .next()
            .expect("tests module must follow the handler");
        let bind = issue_body
            .find("let bind_guard = source_writer_guard::begin_source_write()")
            .expect("the app session refresh binding must acquire the source writer guard");
        let bind_sql = issue_body
            .find("UPDATE auth_device_session SET refresh_token_hash = ?")
            .expect("the binding UPDATE must stay");
        assert!(
            bind < bind_sql,
            "the fence must be acquired before the binding statement"
        );
        assert!(
            issue_body.contains("fenced_source_write("),
            "the binding must run under the fenced writer"
        );

        let cleanup_body = source
            .split("async fn cleanup_app_session_failure(")
            .nth(1)
            .expect("cleanup helper must stay")
            .split("async fn issue_app_session(")
            .next()
            .expect("issue_app_session must follow the cleanup helper");
        assert!(
            cleanup_body.contains("source_writer_guard::begin_source_write()")
                && cleanup_body.contains("fenced_source_write("),
            "the family cleanup compensation must run under the fenced writer"
        );
    }
}
