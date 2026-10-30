//! 会话管理 + Token 刷新/撤销
//!
//! 对应 Java `TokenServiceImpl` 的刷新/撤销部分。
//! 包含 Token Family 追踪（对齐 platform_v4 的 auth_token_family + auth_device_session）。
//!
//! Schema contract: both session_id and family_id are BIGINT storage IDs;
//! auth_token_family.family_key is the opaque unique business key.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use sqlx::{MySql, QueryBuilder, Transaction};
use time::{Duration, OffsetDateTime, PrimitiveDateTime};

use astral_common::contract::{ApiResponse, EmptyResponse};
use astral_common::error::AppError;
use astral_common::middleware::decode_v2_token;
use astral_common::token_contract::{normalize_revocation_reason, PrincipalKind, TokenUse};
use astral_types::AstralError;

use super::session_repository::{self as session_repo, DeviceSessionRow};
use super::source_writer_guard;
use crate::auth::{
    issue_access_token, issue_refresh_token, map_eligibility_error, sha256_hash, LoginResponse,
    SessionContext, SessionGrant, TokenResult,
};
use crate::AppState;

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RevokeSessionRequest {
    pub reason: Option<String>,
}

// Canonical `auth_device_session` row type is shared with
// `session_repository` to keep one sqlx mapping.

/// 会话路由
pub fn session_routes() -> Router<AppState> {
    Router::new()
        .route("/sessions/refresh", post(refresh_token))
        .route("/sessions/revoke", post(revoke_session))
        .route("/sessions/logout", post(logout))
}

/// POST /api/v1/auth/sessions/refresh — rotate the access/refresh pair.
///
/// 对齐 Java TokenServiceImpl.resolveRefreshSession()：
/// 1. 查找设备会话 → 2. 检查 family 有效性 → 3. 检查过期 → 4. 签发新 token → 5. 更新会话
fn is_platform_user(principal_kind: &str) -> bool {
    principal_kind == PrincipalKind::PlatformUser.as_str()
}

async fn refresh_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<LoginResponse>>, AppError> {
    let raw_refresh = bearer_token(&headers)
        .ok_or_else(|| AppError::from(AstralError::Auth("REFRESH_BEARER_REQUIRED".into())))?;
    let (claims, token_use) = decode_v2_token(raw_refresh, &state.config).map_err(|reason| {
        AppError::from(AstralError::Auth(format!(
            "Invalid refresh token: {reason}"
        )))
    })?;
    if token_use != TokenUse::Refresh {
        return Err(AppError::from(AstralError::Auth(
            "REFRESH_TOKEN_REQUIRED".into(),
        )));
    }
    let session_id = claims
        .sid
        .ok_or_else(|| AppError::from(AstralError::Auth("SESSION_CONTEXT_INVALID".into())))?;
    let family_id = claims
        .family_id
        .ok_or_else(|| AppError::from(AstralError::Auth("SESSION_CONTEXT_INVALID".into())))?;
    let user_id = claims
        .sub
        .parse::<i64>()
        .map_err(|_| AppError::from(AstralError::Auth("SESSION_CONTEXT_INVALID".into())))?;
    let refresh_hash = sha256_hash(raw_refresh);
    // Reject stale APP_USER and other non-platform principals before any refresh
    // lookup or rotation can occur.
    if !is_platform_user(&claims.principal_kind) {
        return Err(AppError::from(AstralError::Auth(
            "PRINCIPAL_KIND_INVALID".into(),
        )));
    }
    let session = match session_repo::load_active_refresh_session(&state.db, &refresh_hash)
        .await?
        .filter(|row| {
            row.session_id == session_id
                && row.family_id == family_id
                && row.user_id == user_id
                && row.session_version == claims.session_version.unwrap_or_default()
                && row.session_epoch == claims.sev.unwrap_or_default()
        }) {
        Some(session) => session,
        None => {
            // A validly signed refresh token that still names an active session
            // but no longer matches its durable hash is a reuse signal. Revoke
            // the family before returning the failure so a stolen rotated token
            // cannot leave the replacement credential usable.
            if let Some(current) =
                session_repo::load_active_session_context(&state.db, session_id, user_id, family_id)
                    .await?
            {
                if current.refresh_token_hash != refresh_hash {
                    if let Err(error) =
                        revoke_token_family(&state, current.family_id, "TOKEN_REUSE_DETECTED").await
                    {
                        return Err(AppError::from(AstralError::Auth(format!(
                            "TOKEN_REUSE_DETECTED; failed to revoke family: {error}"
                        ))));
                    }
                    return Err(AppError::from(AstralError::Auth(
                        "Token reuse detected. All sessions have been revoked.".into(),
                    )));
                }
            }
            return Err(AppError::from(AstralError::Auth(
                "Invalid refresh session".into(),
            )));
        }
    };
    if session
        .credential_version
        .is_none_or(|version| version <= 0)
    {
        return Err(AppError::from(AstralError::Auth(
            "CREDENTIAL_REVISION_REQUIRED".into(),
        )));
    }
    refresh_token_from_session(&state, session, raw_refresh).await
}

async fn refresh_token_from_session(
    state: &AppState,
    session: DeviceSessionRow,
    raw_refresh: &str,
) -> Result<Json<ApiResponse<LoginResponse>>, AppError> {
    let now = utc_db_now();
    let refresh_hash = sha256_hash(raw_refresh);

    // Step 2: 检查 Token Family 有效性（platform_v4: family_id 是 BIGINT FK）
    match check_family_valid(&state.db, session.family_id).await {
        Ok(FamilyStatus::Revoked) => {
            // Token 被盗：已撤销的 family 中出现 refresh 尝试 → 撤销该会话及 family
            tracing::warn!(
                user_id = %session.user_id,
                family_id = %session.family_id,
                "refresh token reuse detected: family already revoked"
            );
            if let Err(e) =
                revoke_token_family(state, session.family_id, "TOKEN_REUSE_DETECTED").await
            {
                return Err(AppError::from(AstralError::Auth(format!(
                    "TOKEN_REUSE_DETECTED; failed to revoke token family: {e}"
                ))));
            }
            return Err(AppError::from(AstralError::Auth(
                "Token reuse detected. All sessions have been revoked.".into(),
            )));
        }
        Ok(FamilyStatus::Expired) => {
            return Err(AppError::from(AstralError::Auth(
                "Token family expired. Please login again.".into(),
            )));
        }
        Ok(FamilyStatus::Active) => {}
        Ok(FamilyStatus::NotFound) => {
            // A session without a verifiable family cannot safely mint a replacement token.
            // This also rejects legacy/corrupt family_id=0 rows; only sessions with a
            // persisted, active family retain refresh compatibility.
            tracing::warn!(family_id = %session.family_id, "refresh refused: token family not found");
            return Err(AppError::from(AstralError::Auth(
                "Token family not found. Please login again.".into(),
            )));
        }
        Ok(FamilyStatus::Unknown(status)) => {
            // Fail closed: new/invalid family states must never be treated as ACTIVE.
            tracing::warn!(family_id = %session.family_id, status = %status, "refresh refused: unknown token family status");
            return Err(AppError::from(AstralError::Auth(
                "Token family status is not refreshable. Please login again.".into(),
            )));
        }
        Err(e) => {
            // Family state is security-critical: do not issue a new access token when
            // its database lookup is unavailable.
            tracing::error!(family_id = %session.family_id, error = %e, "check_family_valid failed, refusing refresh");
            return Err(AppError::from(e));
        }
    }

    // Step 3: 检查过期
    if session
        .refresh_expires_at
        .map(|expires_at| expires_at <= now)
        .unwrap_or(true)
    {
        tracing::warn!(session_id = %session.session_id, "refresh failed: token expired");
        return Err(AppError::from(AstralError::Auth(
            "Refresh token expired".into(),
        )));
    }

    // Step 4: 查询用户信息（JOIN identity_card + platform_user）
    // identity_card 只提供身份事实；组织 scope 随后从 selected user_card 读取。
    let user = sqlx::query_as::<_, (i64, i64, String, Option<i64>, Option<String>)>(
        "SELECT ic.card_id, ic.user_id, ic.status, ic.token_version, \
                DATE_FORMAT(ic.expires_at, '%Y-%m-%dT%H:%i:%sZ') AS expires_at \
         FROM identity_card ic \
         INNER JOIN platform_user u ON u.user_id = ic.user_id AND u.deleted_at IS NULL \
         WHERE ic.user_id = ? AND u.status = 'ACTIVE' AND ic.status = 'ACTIVE' \
           AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
         ORDER BY ic.card_id ASC LIMIT 1",
    )
    .bind(session.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AstralError::Database(format!("Query user failed: {e}")))?
    .ok_or_else(|| AstralError::Auth("User not found".into()))?;

    let id_card = astral_types::IdentityCard {
        card_id: Some(user.0),
        user_id: user.1,
        status: user.2,
        token_version: user.3,
        expires_at: user.4,
        disabled_reason: None,
        last_used_at: None,
        created_at: None,
        updated_at: None,
    };

    // Platform sessions require the persisted user card. Identity and organization
    // scope are reloaded and validated before rotating any credential.
    let user_card_for_jwt = match session.current_user_card_id {
        Some(target_card_id) => {
            let uc = sqlx::query_as::<
                _,
                (
                    i64,
                    Option<i64>,
                    String,
                    Option<i64>,
                    Option<i64>,
                    Option<i32>,
                    Option<bool>,
                    Option<i64>,
                ),
            >(
                "SELECT uc.card_id, uc.domain_id, uc.card_type, uc.template_id, uc.tenant_id, \
                                uc.priority, uc.is_primary, uc.level_id \
                         FROM user_card uc \
                         INNER JOIN tenant t ON t.tenant_id = uc.tenant_id AND t.status = 'ACTIVE' \
                         INNER JOIN tenant_domain_map tdm ON tdm.tenant_id = uc.tenant_id \
                           AND tdm.domain_id = uc.domain_id AND tdm.status = 'ACTIVE' \
                         WHERE uc.card_id = ? AND uc.user_id = ? AND uc.card_status = 'ACTIVE' \
                           AND uc.tenant_id > 0 AND uc.domain_id > 0 \
                           AND uc.card_type != 'LEVEL_TEMPLATE_CARD' \
                           AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
                           AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP())",
            )
            .bind(target_card_id)
            .bind(session.user_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AstralError::Database(format!("Query user_card failed: {e}")))?;
            match uc {
                Some((
                    card_id,
                    domain_id,
                    card_type,
                    template_id,
                    tenant_id,
                    priority,
                    is_primary,
                    level_id,
                )) => {
                    // 签发资格权威校验：identity / user_card 重读后统一走资格服务，
                    // tenant/domain ACTIVE 与时间窗口在签发前强制校验（fail-closed）。
                    // 组织事实仍来自 user_card 行本身（JWT claims 不变），资格结果仅作门禁。
                    if let Err(error) =
                        astral_db::CardEligibilityService::verify_platform_card_pair(
                            &state.db,
                            &astral_types::PlatformCardPairRequest {
                                user_id: session.user_id,
                                identity_card_id: user.0,
                                user_card_id: card_id,
                            },
                        )
                        .await
                    {
                        tracing::warn!(
                            session_id = %session.session_id,
                            target_card_id,
                            user_id = %session.user_id,
                            error = %error,
                            "refresh refused: platform card pair not eligible"
                        );
                        return Err(AppError::from(map_eligibility_error(error, |_| {
                            AstralError::Auth("USER_CARD_SCOPE_REQUIRED".into())
                        })));
                    }
                    Some(astral_types::UserCard {
                        card_id: Some(card_id),
                        user_id: Some(user.1),
                        domain_id,
                        card_type,
                        card_status: "ACTIVE".to_string(),
                        template_id,
                        level_id,
                        priority,
                        is_primary,
                        valid_from: None,
                        valid_until: None,
                        created_at: None,
                        updated_at: None,
                        tenant_id,
                    })
                }
                None => {
                    tracing::warn!(
                        session_id = %session.session_id,
                        target_card_id,
                        user_id = %session.user_id,
                        "refresh refused: persisted user card no longer available"
                    );
                    return Err(AppError::from(AstralError::Auth(
                        "CARD_SELECTION_REQUIRED: persisted user card no longer available".into(),
                    )));
                }
            }
        }
        None => {
            tracing::warn!(
                session_id = %session.session_id,
                user_id = %session.user_id,
                "refresh refused: no user card bound to platform session"
            );
            return Err(AppError::from(AstralError::Auth(
                "CARD_SELECTION_REQUIRED: no user card bound to session".into(),
            )));
        }
    };

    let next_session_version = session.session_version.checked_add(1).ok_or_else(|| {
        AstralError::Auth("Session version exhausted. Please login again.".into())
    })?;
    let next_session_epoch = session
        .session_epoch
        .checked_add(1)
        .ok_or_else(|| AstralError::Auth("Session epoch exhausted. Please login again.".into()))?;
    let current_credential_version: Option<i64> = sqlx::query_scalar(
        "SELECT credential_version FROM user_local_credential WHERE user_id = ? AND status = 'ACTIVE' LIMIT 1",
    )
    .bind(session.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| AstralError::Database(format!("Verify refresh credential revision failed: {error}")))?;
    if current_credential_version
        .is_none_or(|version| version <= 0 || session.credential_version != Some(version))
    {
        return Err(AppError::from(AstralError::Auth(
            "CREDENTIAL_REVISION_MISMATCH".into(),
        )));
    }

    let new_expiry = now + Duration::seconds(state.config.jwt.refresh.expiry_seconds);
    let session_context = SessionContext {
        session_id: session.session_id,
        session_version: next_session_version,
        session_epoch: next_session_epoch,
        family_id: session.family_id,
    };
    let access_card = user_card_for_jwt
        .as_ref()
        .ok_or_else(|| AppError::from(AstralError::Auth("USER_CARD_CONTEXT_REQUIRED".into())))?;
    let token_result = issue_access_token(
        &state.config.jwt,
        &id_card,
        access_card,
        session_context,
        None,
    )?;
    let new_refresh_result =
        issue_refresh_token(&state.config.jwt, session.user_id, session_context)?;
    let new_refresh_hash = sha256_hash(&new_refresh_result.token);
    let new_access_token = token_result.token.clone();
    let expires_in = token_result.expires_in;

    // Step 6: 原子轮换 refresh token。旧 hash 必须仍是当前值；并发请求中只有一个
    // UPDATE 能影响一行，失败者按 token reuse 处理并撤销整个 family。
    // 会话轮换的 autocommit source 栅栏：hub 已装则 fail-closed 取得（不可得即
    // 拒绝轮换），await 窗口前武装取消栅栏——窗口内取消/掉线 → sticky
    // uncertain_source；结果判定后 proven 释放（CAS 未命中 0 行未发生 mutation，
    // 同样 proven）。栅栏只围本条 SQL，不覆盖其前后的已验证本地加速登记。
    let rotation_guard = source_writer_guard::begin_source_write()?;
    let rotation = source_writer_guard::fenced_source_write(
        rotation_guard,
        sqlx::query(
            "UPDATE auth_device_session SET refresh_token_hash = ?, refresh_expires_at = ?, \
             session_state = 'ACTIVE', session_version = ?, session_epoch = ?, \
             last_seen_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP \
             WHERE session_id = ? AND user_id = ? AND refresh_token_hash = ? \
               AND status = 'ACTIVE' AND session_state = 'ACTIVE' \
               AND session_version = ? AND session_epoch = ?",
        )
        .bind(&new_refresh_hash)
        .bind(new_expiry)
        .bind(next_session_version)
        .bind(next_session_epoch)
        .bind(session.session_id)
        .bind(session.user_id)
        .bind(&refresh_hash)
        .bind(session.session_version)
        .bind(session.session_epoch)
        .execute(&state.db),
    )
    .await
    .map_err(|e| AstralError::Database(format!("Rotate refresh token failed: {e}")))?;

    if !rotation_succeeded(rotation.rows_affected()) {
        tracing::warn!(
            session_id = %session.session_id,
            family_id = %session.family_id,
            "refresh token reuse detected during atomic rotation"
        );
        revoke_token_family(state, session.family_id, "TOKEN_REUSE_DETECTED")
            .await
            .map_err(|e| {
                AstralError::Auth(format!(
                    "TOKEN_REUSE_DETECTED; failed to revoke token family: {e}"
                ))
            })?;
        return Err(AppError::from(AstralError::Auth(
            "Token reuse detected. All sessions have been revoked.".into(),
        )));
    }

    // The old access proof is closed only after the refresh-session CAS is
    // proven successful. A failed or unknown CAS therefore cannot partially
    // revoke the still-current credential.
    delete_session_projections_before_epoch(state, session.session_id, next_session_epoch)
        .await
        .map_err(AppError::from)?;

    // Credential tracking is security-critical: durable JTI proof in
    // auth_session_jti_index is authoritative. Failure revokes the durable family
    // so a rotated refresh state cannot survive without a trackable access token.
    if let Err(projection_error) = store_session_grant_projection(
        state,
        &token_result,
        SessionGrant::active(
            &token_result,
            session.user_id,
            session.session_id,
            id_card.card_id,
            user_card_for_jwt.as_ref().and_then(|card| card.card_id),
            user_card_for_jwt.as_ref().and_then(|card| card.tenant_id),
            user_card_for_jwt.as_ref().and_then(|card| card.domain_id),
            next_session_version,
            next_session_epoch,
            session.family_id,
        ),
    )
    .await
    {
        if let Err(revoke_error) =
            revoke_token_family(state, session.family_id, "ACCESS_TRACKING_UNAVAILABLE").await
        {
            tracing::error!(
                family_id = %session.family_id,
                %projection_error,
                %revoke_error,
                "access tracking failed and family revocation failed"
            );
        }
        return Err(AppError::from(projection_error));
    }

    // The CAS above is the only refresh-token state transition.

    tracing::info!(user_id = %id_card.user_id, "token refreshed");

    let expires_in_millis = expires_in * 1000;
    let refresh_expires_in_millis = state.config.jwt.refresh.expiry_seconds * 1000;

    let resp = LoginResponse {
        access_token: new_access_token,
        refresh_token: new_refresh_result.token,
        token_type: "Bearer".into(),
        expires_in_millis,
        refresh_expires_in_millis,
        user: None,
        current_card: None,
        available_cards: None,
        permissions: None,
        roles: Some(vec!["USER".into()]),
        enterprises: None,
        session: Some(serde_json::json!({
            "sessionId": session.session_id,
            "familyId": session.family_id,
            "sessionVersion": next_session_version,
            "sessionEpoch": next_session_epoch,
            "sessionState": "ACTIVE",
            "currentUserCardId": user_card_for_jwt.as_ref().and_then(|card| card.card_id),
        })),
    };

    Ok(Json(ApiResponse::success(resp)))
}

async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RevokeSessionRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    let raw = logout_bearer_credential(&headers)?;
    let (claims, token_use) = decode_v2_token(raw, &state.config)
        .map_err(|reason| AppError::from(AstralError::Auth(reason.into())))?;
    if !is_platform_user(&claims.principal_kind) {
        return Err(AppError::from(AstralError::Auth(
            "PRINCIPAL_KIND_INVALID".into(),
        )));
    }
    let reason = normalize_revocation_reason(req.reason.as_deref().unwrap_or("USER_REVOKED"))
        .map_err(|error| AppError::from(AstralError::Validation(error.into())))?;
    let user_id = claims
        .sub
        .parse::<i64>()
        .map_err(|_| AppError::from(AstralError::Auth("SESSION_CONTEXT_INVALID".into())))?;
    match token_use {
        TokenUse::Access => {
            let session_id = claims.sid.ok_or_else(|| {
                AppError::from(AstralError::Auth("SESSION_CONTEXT_INVALID".into()))
            })?;
            revoke_access_jti_transaction(&state, user_id, session_id, &claims.jti, &reason)
                .await
                .map_err(AppError::from)?;
        }
        TokenUse::Refresh => {
            let refresh_hash = sha256_hash(raw);
            let session_id = claims.sid.ok_or_else(|| {
                AppError::from(AstralError::Auth("SESSION_CONTEXT_INVALID".into()))
            })?;
            let family_id = claims.family_id.ok_or_else(|| {
                AppError::from(AstralError::Auth("SESSION_CONTEXT_INVALID".into()))
            })?;
            let session_version = claims.session_version.ok_or_else(|| {
                AppError::from(AstralError::Auth("SESSION_CONTEXT_INVALID".into()))
            })?;
            let session_epoch = claims.sev.ok_or_else(|| {
                AppError::from(AstralError::Auth("SESSION_CONTEXT_INVALID".into()))
            })?;
            let session_context = RefreshSessionContext {
                session_id,
                user_id,
                family_id,
                session_version,
                session_epoch,
            };
            let session = load_current_refresh_session_or_revoke_reuse(
                &state,
                session_context,
                &refresh_hash,
                "Invalid refresh session",
            )
            .await?;
            let operation_id = stable_revocation_operation_id(
                "session",
                &format!("{}:{refresh_hash}", session.session_id),
                &reason,
            );
            revoke_session_transaction(
                &state,
                session.session_id,
                &refresh_hash,
                operation_id,
                &reason,
            )
            .await
            .map_err(AppError::from)?;
        }
    }
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<String>>, AppError> {
    let raw = logout_bearer_credential(&headers)?;
    let (claims, token_use) = decode_v2_token(raw, &state.config)
        .map_err(|reason| AppError::from(AstralError::Auth(reason.into())))?;
    if !is_platform_user(&claims.principal_kind) {
        return Err(AppError::from(AstralError::Auth(
            "PRINCIPAL_KIND_INVALID".into(),
        )));
    }
    match token_use {
        TokenUse::Access => {
            let user_id = claims
                .sub
                .parse::<i64>()
                .map_err(|_| AppError::from(AstralError::Auth("SESSION_CONTEXT_INVALID".into())))?;
            let session_id = claims.sid.ok_or_else(|| {
                AppError::from(AstralError::Auth("SESSION_CONTEXT_INVALID".into()))
            })?;
            revoke_access_jti_transaction(&state, user_id, session_id, &claims.jti, "LOGOUT")
                .await
                .map_err(AppError::from)?;
        }
        TokenUse::Refresh => {
            let user_id = claims
                .sub
                .parse::<i64>()
                .map_err(|_| AppError::from(AstralError::Auth("SESSION_CONTEXT_INVALID".into())))?;
            let session_id = claims.sid.ok_or_else(|| {
                AppError::from(AstralError::Auth("SESSION_CONTEXT_INVALID".into()))
            })?;
            let family_id = claims.family_id.ok_or_else(|| {
                AppError::from(AstralError::Auth("SESSION_CONTEXT_INVALID".into()))
            })?;
            let session_version = claims.session_version.ok_or_else(|| {
                AppError::from(AstralError::Auth("SESSION_CONTEXT_INVALID".into()))
            })?;
            let session_epoch = claims.sev.ok_or_else(|| {
                AppError::from(AstralError::Auth("SESSION_CONTEXT_INVALID".into()))
            })?;
            let session_context = RefreshSessionContext {
                session_id,
                user_id,
                family_id,
                session_version,
                session_epoch,
            };
            revoke_logout_refresh(&state, raw, session_context).await?;
        }
    }
    Ok(Json(ApiResponse::success("Logged out".into())))
}

#[derive(Debug, Clone, Copy)]
struct RefreshSessionContext {
    session_id: i64,
    user_id: i64,
    family_id: i64,
    session_version: i64,
    session_epoch: i64,
}

async fn load_current_refresh_session_or_revoke_reuse(
    state: &AppState,
    context: RefreshSessionContext,
    refresh_hash: &str,
    invalid_message: &'static str,
) -> Result<DeviceSessionRow, AppError> {
    if let Some(session) = session_repo::load_active_refresh_session(&state.db, refresh_hash)
        .await?
        .filter(|row| {
            row.session_id == context.session_id
                && row.user_id == context.user_id
                && row.family_id == context.family_id
                && row.session_version == context.session_version
                && row.session_epoch == context.session_epoch
        })
    {
        return Ok(session);
    }

    if let Some(current) = session_repo::load_active_session_context(
        &state.db,
        context.session_id,
        context.user_id,
        context.family_id,
    )
    .await?
    {
        if current.session_version != context.session_version
            || current.session_epoch != context.session_epoch
        {
            return Err(AppError::from(AstralError::Auth(invalid_message.into())));
        }
        if current.refresh_token_hash != refresh_hash {
            if let Err(error) =
                revoke_token_family(state, current.family_id, "TOKEN_REUSE_DETECTED").await
            {
                return Err(AppError::from(AstralError::Auth(format!(
                    "TOKEN_REUSE_DETECTED; failed to revoke family: {error}"
                ))));
            }
            return Err(AppError::from(AstralError::Auth(
                "Token reuse detected. All sessions have been revoked.".into(),
            )));
        }
    }

    Err(AppError::from(AstralError::Auth(invalid_message.into())))
}

/// logout/revoke 共用的凭证前置门：Authorization 头缺失或非 Bearer 形态
/// 直接拒绝，任何数据库或 token 解码都不会被触碰。
fn logout_bearer_credential(headers: &HeaderMap) -> Result<&str, AppError> {
    bearer_token(headers).ok_or_else(|| AppError::from(AstralError::Auth("BEARER_REQUIRED".into())))
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

async fn revoke_logout_refresh(
    state: &AppState,
    refresh_token: &str,
    context: RefreshSessionContext,
) -> Result<(), AppError> {
    let refresh_hash = sha256_hash(refresh_token);
    let session = load_current_refresh_session_or_revoke_reuse(
        state,
        context,
        &refresh_hash,
        "Invalid refresh token",
    )
    .await?;
    let operation_id = stable_revocation_operation_id(
        "session",
        &format!("{}:{refresh_hash}", session.session_id),
        "LOGOUT",
    );
    revoke_session_transaction(
        state,
        session.session_id,
        &refresh_hash,
        operation_id,
        "LOGOUT",
    )
    .await
    .map_err(AppError::from)
}

const MAX_REVOCATION_SNAPSHOT_JTIS: usize = 4096;

#[derive(Debug, Clone, Copy)]
enum RevocationTarget<'a> {
    Access {
        session_id: i64,
        user_id: i64,
        jti: &'a str,
    },
    Session {
        session_id: i64,
        refresh_hash: &'a str,
    },
    Family {
        family_id: i64,
    },
    User {
        user_id: i64,
    },
}

fn stable_revocation_operation_id(scope: &str, key: &str, reason: &str) -> String {
    let operation_key = format!("{key}\u{1f}{reason}");
    let operation_hash = sha256_hash(&operation_key);
    format!(
        "identity:{scope}:{}",
        &operation_hash[..32.min(operation_hash.len())]
    )
}

async fn revoke_access_jti_transaction(
    state: &AppState,
    user_id: i64,
    session_id: i64,
    jti: &str,
    reason: &str,
) -> Result<(), AstralError> {
    if jti.trim().is_empty() {
        return Err(AstralError::Auth("TOKEN_ID_REQUIRED".into()));
    }
    let operation_id =
        stable_revocation_operation_id("access", &format!("{session_id}:{jti}"), reason);
    revoke_transaction(
        state,
        RevocationTarget::Access {
            session_id,
            user_id,
            jti,
        },
        operation_id,
        reason,
    )
    .await
}

async fn revoke_session_transaction(
    state: &AppState,
    session_id: i64,
    refresh_hash: &str,
    operation_id: String,
    reason: &str,
) -> Result<(), AstralError> {
    revoke_transaction(
        state,
        RevocationTarget::Session {
            session_id,
            refresh_hash,
        },
        operation_id,
        reason,
    )
    .await
}

async fn revoke_transaction(
    state: &AppState,
    target: RevocationTarget<'_>,
    operation_id: String,
    reason: &str,
) -> Result<(), AstralError> {
    let reason = normalize_revocation_reason(reason)
        .map_err(|error| AstralError::Validation(error.into()))?;
    let source_guard = source_writer_guard::begin_source_write()?;
    let mut tx = state.db.begin().await.map_err(|error| {
        AstralError::Database(format!("Begin revocation transaction failed: {error}"))
    })?;

    let existing_payload = sqlx::query_scalar::<_, Option<String>>(
        "SELECT payload_json FROM auth_session_outbox \
         WHERE operation_id = ? AND sequence_number = 1 FOR UPDATE",
    )
    .bind(&operation_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| AstralError::Database(format!("Load revocation operation failed: {error}")))?;
    let expected_user_id = match target {
        RevocationTarget::Access { user_id, .. } | RevocationTarget::User { user_id } => user_id,
        RevocationTarget::Session { .. } | RevocationTarget::Family { .. } => 0,
    };
    if let Some(payload) = existing_payload.flatten() {
        let snapshot = parse_current_revocation_snapshot(Some(&payload))?;
        if snapshot.reason != reason
            || (expected_user_id > 0 && snapshot.user_id != expected_user_id)
        {
            tx.rollback().await.map_err(|error| {
                AstralError::Database(format!(
                    "Rollback conflicting revocation operation failed: {error}"
                ))
            })?;
            return Err(AstralError::Auth(
                "SESSION_REVOCATION_IDEMPOTENCY_CONFLICT".into(),
            ));
        }
        if matches!(target, RevocationTarget::User { .. }) {
            let (_, current_session_ids, current_jtis, _, _) =
                lock_revocation_snapshot(&mut tx, target).await?;
            if !current_session_ids.is_empty() || !current_jtis.is_empty() {
                tx.rollback().await.map_err(|error| {
                    AstralError::Database(format!(
                        "Rollback conflicting revocation operation failed: {error}"
                    ))
                })?;
                return Err(AstralError::Auth(
                    "SESSION_REVOCATION_IDEMPOTENCY_CONFLICT".into(),
                ));
            }
        }
        tx.rollback().await.map_err(|error| {
            AstralError::Database(format!(
                "Rollback duplicate revocation operation failed: {error}"
            ))
        })?;
        astral_db::note_revocations_in_process(
            &snapshot.jtis,
            astral_db::REVOCATION_MIRROR_TTL_SECS,
        );
        for jti in &snapshot.jtis {
            mark_registry_revoked(jti, REVOKED_TTL_SECS);
        }
        return Ok(());
    }

    let (user_id, session_ids, revoked_jtis, session_id, family_ids) =
        lock_revocation_snapshot(&mut tx, target).await?;

    match target {
        RevocationTarget::Access {
            session_id,
            user_id,
            jti,
        } => {
            let result = sqlx::query(
                "UPDATE auth_session_jti_index SET status = 'DELETED', updated_at = UTC_TIMESTAMP() \
                 WHERE session_id = ? AND user_id = ? AND jti = ? AND status = 'ACTIVE'",
            )
            .bind(session_id)
            .bind(user_id)
            .bind(jti)
            .execute(&mut *tx)
            .await
            .map_err(|error| AstralError::Database(format!("Revoke access JTI failed: {error}")))?;
            if result.rows_affected() != 1 {
                return Err(AstralError::Auth(
                    "ACCESS_PROOF_REVOCATION_NOT_APPLIED".into(),
                ));
            }
        }
        RevocationTarget::Session { session_id, .. } => {
            let result = sqlx::query(
                "UPDATE auth_device_session SET status = 'REVOKED', session_state = 'REVOKED', \
                 session_version = session_version + 1, session_epoch = session_epoch + 1, \
                 revoked_at = UTC_TIMESTAMP(), revoked_reason = ?, updated_at = UTC_TIMESTAMP() \
                 WHERE session_id = ? AND status = 'ACTIVE' AND session_state = 'ACTIVE'",
            )
            .bind(&reason)
            .bind(session_id)
            .execute(&mut *tx)
            .await
            .map_err(|error| AstralError::Database(format!("Revoke session failed: {error}")))?;
            if result.rows_affected() != 1 {
                return Err(AstralError::Auth("SESSION_REVOCATION_NOT_APPLIED".into()));
            }
            close_revocation_jtis_in_tx(&mut tx, user_id, &revoked_jtis).await?;
        }
        RevocationTarget::Family { family_id } => {
            let family = sqlx::query(
                "UPDATE auth_token_family SET status = 'REVOKED', revoked_at = UTC_TIMESTAMP(), \
                 revoked_reason = ? WHERE family_id = ? AND status = 'ACTIVE'",
            )
            .bind(&reason)
            .bind(family_id)
            .execute(&mut *tx)
            .await
            .map_err(|error| AstralError::Database(format!("Revoke family failed: {error}")))?;
            if family.rows_affected() != 1 {
                return Err(AstralError::Auth(
                    "TOKEN_FAMILY_REVOCATION_NOT_APPLIED".into(),
                ));
            }
            let sessions = sqlx::query(
                "UPDATE auth_device_session SET status = 'REVOKED', session_state = 'REVOKED', \
                 session_version = session_version + 1, session_epoch = session_epoch + 1, \
                 revoked_at = UTC_TIMESTAMP(), revoked_reason = ?, updated_at = UTC_TIMESTAMP() \
                 WHERE family_id = ? AND status = 'ACTIVE' AND session_state = 'ACTIVE'",
            )
            .bind(&reason)
            .bind(family_id)
            .execute(&mut *tx)
            .await
            .map_err(|error| {
                AstralError::Database(format!("Revoke family sessions failed: {error}"))
            })?;
            if sessions.rows_affected() != session_ids.len() as u64 {
                return Err(AstralError::Auth(
                    "TOKEN_FAMILY_SESSION_SNAPSHOT_CHANGED".into(),
                ));
            }
            close_revocation_jtis_in_tx(&mut tx, user_id, &revoked_jtis).await?;
        }
        RevocationTarget::User { user_id } => {
            let sessions = sqlx::query(
                "UPDATE auth_device_session SET status = 'REVOKED', session_state = 'REVOKED', \
                 session_version = session_version + 1, session_epoch = session_epoch + 1, \
                 revoked_at = UTC_TIMESTAMP(), revoked_reason = ?, updated_at = UTC_TIMESTAMP() \
                 WHERE user_id = ? AND status = 'ACTIVE' AND session_state = 'ACTIVE'",
            )
            .bind(&reason)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(|error| {
                AstralError::Database(format!("Revoke user sessions failed: {error}"))
            })?;
            if sessions.rows_affected() != session_ids.len() as u64 {
                return Err(AstralError::Auth("USER_SESSION_SNAPSHOT_CHANGED".into()));
            }
            if family_ids.is_empty() {
                // The empty aggregate set is a valid no-op after the user row and
                // session snapshot are locked; never emit `IN ()` SQL.
            } else {
                let mut families_query = QueryBuilder::<MySql>::new(
                    "UPDATE auth_token_family SET status = 'REVOKED', revoked_at = UTC_TIMESTAMP(), revoked_reason = ? WHERE family_id IN (",
                );
                families_query.push_bind(&reason);
                let mut family_ids_bind = families_query.separated(", ");
                for family_id in &family_ids {
                    family_ids_bind.push_bind(family_id);
                }
                family_ids_bind.push_unseparated(") AND status = 'ACTIVE'");
                let families = families_query
                    .build()
                    .execute(&mut *tx)
                    .await
                    .map_err(|error| {
                        AstralError::Database(format!("Revoke user families failed: {error}"))
                    })?;
                if families.rows_affected() != family_ids.len() as u64 {
                    return Err(AstralError::Auth("USER_FAMILY_SNAPSHOT_CHANGED".into()));
                }
            }
            close_revocation_jtis_in_tx(&mut tx, user_id, &revoked_jtis).await?;
        }
    }

    let payload = serde_json::json!({
        "v": 2,
        "reason": reason,
        "userId": user_id,
        "jtis": revoked_jtis,
        "typedShards": true,
    })
    .to_string();
    let audit_resource = match target {
        RevocationTarget::Access { session_id, .. }
        | RevocationTarget::Session { session_id, .. } => format!("session:{session_id}"),
        RevocationTarget::Family { family_id } => format!("token-family:{family_id}"),
        RevocationTarget::User { user_id } => format!("user:{user_id}"),
    };
    astral_db::insert_audit_log_in_tx(
        &mut tx,
        &astral_common::audit::AuditEntry {
            user_id: Some(user_id),
            card_id: None,
            action: "REVOKE_SESSION".into(),
            resource: audit_resource,
            decision: "PENDING".into(),
            reason: Some(reason.clone()),
            event_type: astral_common::audit::AuditEventType::TokenRevocation,
            category: Some(astral_common::audit::AuditCategory::IdentityEvent),
            source_ip: None,
            request_id: Some(operation_id.clone()),
            domain_id: None,
            tenant_id: None,
            detail: Some(format!(
                "operation_id={operation_id};jti_count={};typed_shards=true",
                revoked_jtis.len()
            )),
        },
    )
    .await
    .map_err(|error| AstralError::Database(format!("Write revocation audit failed: {error}")))?;
    sqlx::query(
        "INSERT INTO auth_session_outbox \
         (operation_id, session_id, event_type, sequence_number, projection_key, payload_json, status, created_at) \
         VALUES (?, ?, 'REVOKE', 1, ?, ?, 'PENDING', UTC_TIMESTAMP())",
    )
    .bind(&operation_id)
    .bind(session_id)
    .bind(format!("user:{user_id}"))
    .bind(payload)
    .execute(&mut *tx)
    .await
    .map_err(|error| AstralError::Database(format!("Write revocation outbox failed: {error}")))?;

    let committed_shards = astral_mq::invalidation::append_session_revocation_shards_in_tx(
        &mut tx,
        user_id,
        &revoked_jtis,
        &operation_id,
    )
    .await
    .map_err(|error| AstralError::Database(format!("Write revocation shards failed: {error}")))?;

    source_writer_guard::arm_commit_fence(&source_guard);
    tx.commit().await.map_err(|error| {
        AstralError::Database(format!("Commit revocation transaction failed: {error}"))
    })?;
    source_writer_guard::settle_commit_fence(&source_guard, true);
    drop(source_guard);

    astral_mq::consumers::deliver_committed_session_shards(&committed_shards).await;
    astral_db::note_revocations_in_process(&revoked_jtis, astral_db::REVOCATION_MIRROR_TTL_SECS);
    for jti in &revoked_jtis {
        mark_registry_revoked(jti, REVOKED_TTL_SECS);
    }
    Ok(())
}

async fn lock_revocation_snapshot(
    tx: &mut Transaction<'_, MySql>,
    target: RevocationTarget<'_>,
) -> Result<(i64, Vec<i64>, Vec<String>, Option<i64>, Vec<i64>), AstralError> {
    let limit = i64::try_from(MAX_REVOCATION_SNAPSHOT_JTIS + 1)
        .map_err(|_| AstralError::Internal("revocation snapshot cap overflow".into()))?;
    match target {
        RevocationTarget::Access {
            session_id,
            user_id,
            jti,
        } => {
            let session: Option<(i64,)> = sqlx::query_as(
                "SELECT session_id FROM auth_device_session WHERE session_id = ? AND user_id = ? FOR UPDATE",
            )
            .bind(session_id)
            .bind(user_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|error| AstralError::Database(format!("Lock access session failed: {error}")))?;
            if session.is_none() {
                return Err(AstralError::Auth("SESSION_NOT_FOUND".into()));
            }
            let row: Option<(String, String)> = sqlx::query_as(
                "SELECT jti, status FROM auth_session_jti_index \
                 WHERE session_id = ? AND user_id = ? AND jti = ? LIMIT 1 FOR UPDATE",
            )
            .bind(session_id)
            .bind(user_id)
            .bind(jti)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|error| AstralError::Database(format!("Lock access JTI failed: {error}")))?;
            let Some((jti, status)) = row else {
                return Err(AstralError::Auth("ACCESS_PROOF_NOT_FOUND".into()));
            };
            if status != "ACTIVE" {
                return Err(AstralError::Auth("ACCESS_PROOF_ALREADY_REVOKED".into()));
            }
            Ok((
                user_id,
                vec![session_id],
                vec![jti],
                Some(session_id),
                Vec::new(),
            ))
        }
        RevocationTarget::Session {
            session_id,
            refresh_hash,
        } => {
            let row: Option<(i64, i64, String)> = sqlx::query_as(
                "SELECT session_id, user_id, status FROM auth_device_session \
                 WHERE session_id = ? AND refresh_token_hash = ? FOR UPDATE",
            )
            .bind(session_id)
            .bind(refresh_hash)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|error| {
                AstralError::Database(format!("Lock refresh session failed: {error}"))
            })?;
            let Some((session_id, user_id, status)) = row else {
                return Err(AstralError::Auth("SESSION_NOT_FOUND".into()));
            };
            if status != "ACTIVE" {
                return Err(AstralError::Auth("SESSION_ALREADY_REVOKED".into()));
            }
            let jtis: Vec<(String,)> = sqlx::query_as(
                "SELECT jti FROM auth_session_jti_index WHERE session_id = ? AND status = 'ACTIVE' \
                 ORDER BY jti LIMIT ? FOR UPDATE",
            )
            .bind(session_id)
            .bind(limit)
            .fetch_all(&mut **tx)
            .await
            .map_err(|error| AstralError::Database(format!("Snapshot session JTIs failed: {error}")))?;
            let jtis = bounded_revocation_jtis(jtis)?;
            Ok((
                user_id,
                vec![session_id],
                jtis,
                Some(session_id),
                Vec::new(),
            ))
        }
        RevocationTarget::Family { family_id } => {
            let family: Option<(i64, i64, String)> = sqlx::query_as(
                "SELECT family_id, user_id, status FROM auth_token_family WHERE family_id = ? FOR UPDATE",
            )
            .bind(family_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|error| AstralError::Database(format!("Lock token family failed: {error}")))?;
            let Some((_, user_id, status)) = family else {
                return Err(AstralError::Auth("TOKEN_FAMILY_NOT_FOUND".into()));
            };
            if status != "ACTIVE" {
                return Err(AstralError::Auth("TOKEN_FAMILY_ALREADY_REVOKED".into()));
            }
            let sessions: Vec<(i64,)> = sqlx::query_as(
                "SELECT session_id FROM auth_device_session WHERE family_id = ? AND status = 'ACTIVE' \
                 AND session_state = 'ACTIVE' ORDER BY session_id FOR UPDATE",
            )
            .bind(family_id)
            .fetch_all(&mut **tx)
            .await
            .map_err(|error| AstralError::Database(format!("Lock family sessions failed: {error}")))?;
            let jtis: Vec<(String,)> = sqlx::query_as(
                "SELECT i.jti FROM auth_session_jti_index i \
                 INNER JOIN auth_device_session s ON s.session_id = i.session_id \
                 WHERE s.family_id = ? AND i.status = 'ACTIVE' ORDER BY i.jti LIMIT ? FOR UPDATE",
            )
            .bind(family_id)
            .bind(limit)
            .fetch_all(&mut **tx)
            .await
            .map_err(|error| {
                AstralError::Database(format!("Snapshot family JTIs failed: {error}"))
            })?;
            Ok((
                user_id,
                sessions.into_iter().map(|(id,)| id).collect(),
                bounded_revocation_jtis(jtis)?,
                None,
                vec![family_id],
            ))
        }
        RevocationTarget::User { user_id } => {
            let user: Option<(i64,)> = sqlx::query_as(
                "SELECT user_id FROM platform_user WHERE user_id = ? AND deleted_at IS NULL FOR UPDATE",
            )
            .bind(user_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|error| AstralError::Database(format!("Lock user for revocation failed: {error}")))?;
            if user.is_none() {
                return Err(AstralError::Auth("USER_NOT_FOUND".into()));
            }
            let family_ids: Vec<(i64,)> = sqlx::query_as(
                "SELECT family_id FROM auth_token_family WHERE user_id = ? AND status = 'ACTIVE' \
                 ORDER BY family_id FOR UPDATE",
            )
            .bind(user_id)
            .fetch_all(&mut **tx)
            .await
            .map_err(|error| {
                AstralError::Database(format!("Lock user families failed: {error}"))
            })?;
            let sessions: Vec<(i64,)> = sqlx::query_as(
                "SELECT session_id FROM auth_device_session WHERE user_id = ? AND status = 'ACTIVE' \
                 AND session_state = 'ACTIVE' ORDER BY session_id FOR UPDATE",
            )
            .bind(user_id)
            .fetch_all(&mut **tx)
            .await
            .map_err(|error| AstralError::Database(format!("Lock user sessions failed: {error}")))?;
            let jtis: Vec<(String,)> = sqlx::query_as(
                "SELECT jti FROM auth_session_jti_index WHERE user_id = ? AND status = 'ACTIVE' \
                 ORDER BY jti LIMIT ? FOR UPDATE",
            )
            .bind(user_id)
            .bind(limit)
            .fetch_all(&mut **tx)
            .await
            .map_err(|error| {
                AstralError::Database(format!("Snapshot user JTIs failed: {error}"))
            })?;
            Ok((
                user_id,
                sessions.into_iter().map(|(id,)| id).collect(),
                bounded_revocation_jtis(jtis)?,
                None,
                family_ids.into_iter().map(|(id,)| id).collect(),
            ))
        }
    }
}

fn bounded_revocation_jtis(rows: Vec<(String,)>) -> Result<Vec<String>, AstralError> {
    if rows.len() > MAX_REVOCATION_SNAPSHOT_JTIS {
        return Err(AstralError::Validation(
            "Too many active credentials to revoke atomically; support is required".into(),
        ));
    }
    Ok(rows.into_iter().map(|(jti,)| jti).collect())
}

async fn close_revocation_jtis_in_tx(
    tx: &mut Transaction<'_, MySql>,
    user_id: i64,
    jtis: &[String],
) -> Result<(), AstralError> {
    if jtis.is_empty() {
        return Ok(());
    }
    let mut query = QueryBuilder::<MySql>::new(
        "UPDATE auth_session_jti_index SET status = 'DELETED', updated_at = UTC_TIMESTAMP() WHERE user_id = ",
    );
    query.push_bind(user_id);
    query.push(" AND status = 'ACTIVE' AND jti IN (");
    let mut separated = query.separated(", ");
    for jti in jtis {
        separated.push_bind(jti);
    }
    separated.push_unseparated(")");
    let result = query.build().execute(&mut **tx).await.map_err(|error| {
        AstralError::Database(format!("Close revocation JTI snapshot failed: {error}"))
    })?;
    if result.rows_affected() != jtis.len() as u64 {
        return Err(AstralError::Auth(
            "Revocation JTI snapshot changed during transaction".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct RevocationSnapshot {
    user_id: i64,
    reason: String,
    jtis: Vec<String>,
}

fn parse_current_revocation_snapshot(
    payload: Option<&str>,
) -> Result<RevocationSnapshot, AstralError> {
    let payload = payload
        .ok_or_else(|| AstralError::Auth("SESSION_REVOCATION_RECONCILIATION_REQUIRED".into()))?;
    let value: serde_json::Value = serde_json::from_str(payload)
        .map_err(|_| AstralError::Auth("SESSION_REVOCATION_RECONCILIATION_REQUIRED".into()))?;
    if value.get("v").and_then(serde_json::Value::as_i64) != Some(2)
        || value
            .get("typedShards")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
    {
        return Err(AstralError::Auth(
            "SESSION_REVOCATION_RECONCILIATION_REQUIRED".into(),
        ));
    }
    let user_id = value
        .get("userId")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| AstralError::Auth("SESSION_REVOCATION_RECONCILIATION_REQUIRED".into()))?;
    let reason = normalize_revocation_reason(
        value
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                AstralError::Auth("SESSION_REVOCATION_RECONCILIATION_REQUIRED".into())
            })?,
    )
    .map_err(|_| AstralError::Auth("SESSION_REVOCATION_RECONCILIATION_REQUIRED".into()))?;
    let jtis = value
        .get("jtis")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| AstralError::Auth("SESSION_REVOCATION_RECONCILIATION_REQUIRED".into()))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|jti| !jti.trim().is_empty())
                .map(str::to_owned)
                .ok_or_else(|| {
                    AstralError::Auth("SESSION_REVOCATION_RECONCILIATION_REQUIRED".into())
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if jtis.len() > MAX_REVOCATION_SNAPSHOT_JTIS {
        return Err(AstralError::Auth(
            "SESSION_REVOCATION_RECONCILIATION_REQUIRED".into(),
        ));
    }
    Ok(RevocationSnapshot {
        user_id,
        reason,
        jtis,
    })
}

// ===== Token Family 管理函数 =====

/// Family 状态
enum FamilyStatus {
    Active,
    Expired,
    Revoked,
    NotFound,
    Unknown(String),
}

fn is_refresh_family_id_valid(family_id: i64) -> bool {
    family_id > 0
}

fn utc_db_now() -> PrimitiveDateTime {
    let now = OffsetDateTime::now_utc();
    PrimitiveDateTime::new(now.date(), now.time())
}

fn rotation_succeeded(rows_affected: u64) -> bool {
    rows_affected == 1
}

fn family_status(status: &str) -> FamilyStatus {
    match status {
        "ACTIVE" => FamilyStatus::Active,
        "EXPIRED" => FamilyStatus::Expired,
        "REVOKED" => FamilyStatus::Revoked,
        status => FamilyStatus::Unknown(status.to_string()),
    }
}

/// 检查 token family 是否有效（按 BIGINT family_id 主键 lookup）。
async fn check_family_valid(
    db: &sqlx::MySqlPool,
    family_id: i64,
) -> Result<FamilyStatus, AstralError> {
    if !is_refresh_family_id_valid(family_id) {
        return Ok(FamilyStatus::NotFound);
    }

    let row = session_repo::load_family_row(db, family_id).await?;

    match row {
        Some(f) => {
            if f.expires_at
                .map(|expires_at| expires_at <= utc_db_now())
                .unwrap_or(false)
            {
                Ok(FamilyStatus::Expired)
            } else {
                Ok(family_status(&f.status))
            }
        }
        None => Ok(FamilyStatus::NotFound),
    }
}

/// 撤销整个 token family（检测到 token 被盗时调用）。
/// family_id is the canonical BIGINT primary/foreign key shared by both tables.
async fn revoke_token_family(
    state: &AppState,
    family_id: i64,
    reason: &str,
) -> Result<(), AstralError> {
    let operation_id = stable_revocation_operation_id("family", &family_id.to_string(), reason);
    revoke_transaction(
        state,
        RevocationTarget::Family { family_id },
        operation_id,
        reason,
    )
    .await
}

/// Revoke every active session and token family for a user.
///
/// The source rows, exact JTI snapshot, v2 parent outbox row, and typed
/// SESSION_REVOKED intents commit as one durable transaction. Process-local
/// deny acceleration is installed only after that commit is proven.
pub(crate) async fn revoke_all_sessions_for_user(
    state: &AppState,
    user_id: i64,
    reason: &str,
    request_operation_id: Option<&str>,
) -> Result<(), AstralError> {
    let request_operation_id =
        astral_db::grant_ledger::validated_request_operation_id(request_operation_id)?
            .ok_or_else(|| AstralError::Auth("REVOCATION_REQUEST_ID_REQUIRED".into()))?;
    let operation_id = stable_revocation_operation_id(
        "user",
        &format!("{user_id}:{}", request_operation_id),
        reason,
    );
    revoke_transaction(
        state,
        RevocationTarget::User { user_id },
        operation_id,
        reason,
    )
    .await
}

/// Create a family with the same UTC DATETIME expiry used by its sessions.
pub async fn create_token_family_with_expiry(
    db: &sqlx::MySqlPool,
    family_key: &str,
    user_id: i64,
    expires_at: PrimitiveDateTime,
) -> Result<i64, AstralError> {
    session_repo::create_token_family_with_expiry(db, family_key, user_id, expires_at).await
}

/// Store the durable access proof for a newly issued credential.
///
/// `auth_session_jti_index` is the authoritative Gateway admission fact; proof
/// failure aborts issuance (the caller compensates by closing the family).
/// After the strict MySQL proof, the verified-only mirror is best-effort and
/// cannot authorize an unverified grant (see
/// [`astral_db::install_verified_access_grant`]).
pub(crate) async fn store_session_grant_projection(
    state: &AppState,
    token: &TokenResult,
    grant: SessionGrant,
) -> Result<(), AstralError> {
    if !is_platform_user(&grant.principal_kind) {
        return Err(AstralError::Auth("PRINCIPAL_KIND_INVALID".into()));
    }
    record_platform_session_jti_proof(
        state,
        token,
        grant.user_id,
        grant.session_id,
        grant.session_epoch,
        grant
            .identity_card_id
            .ok_or_else(|| AstralError::Auth("IDENTITY_CARD_CONTEXT_REQUIRED".into()))?,
    )
    .await?;

    install_verified_session_grant_mirror(state, token, &grant);
    Ok(())
}

/// 把签发结果换算成 Gateway 侧同一套绑定上下文，并以 strict DB 复核结果
/// 登记进程内镜像（未安装镜像时 no-op；复核不过只放弃加速，不阻断签发）。
fn install_verified_session_grant_mirror(
    state: &AppState,
    token: &TokenResult,
    grant: &SessionGrant,
) {
    if grant.principal_kind != "PLATFORM_USER" {
        return;
    }
    let bind = astral_common::session_projection_store::SessionBindContext {
        user_id: grant.user_id,
        session_id: grant.session_id,
        session_version: grant.session_version,
        session_epoch: grant.session_epoch,
        token_family_id: grant.token_family_id,
        principal_kind: "PLATFORM_USER",
        identity_card_id: grant.identity_card_id,
        user_card_id: grant.user_card_id,
        user_card_tenant_id: grant.user_card_tenant_id,
        user_card_domain_id: grant.user_card_domain_id,
        expires_at_epoch_second: token.expires_at_epoch_second,
    };
    let issued = astral_common::session_projection_store::IssuedAccessGrant {
        jti: token.jti.clone(),
        session_id: grant.session_id,
        session_version: grant.session_version,
        session_epoch: grant.session_epoch,
        user_id: grant.user_id,
        token_family_id: grant.token_family_id,
        identity_card_id: grant.identity_card_id,
        user_card_id: grant.user_card_id,
        user_card_tenant_id: grant.user_card_tenant_id,
        user_card_domain_id: grant.user_card_domain_id,
        principal_kind: "PLATFORM_USER",
        expires_at_epoch_second: token.expires_at_epoch_second,
    };
    let pool = state.db.clone();
    tokio::spawn(async move {
        match astral_db::install_verified_access_grant(&pool, issued, &bind).await {
            Ok(installed) => {
                if !installed {
                    tracing::debug!("session grant mirror skipped: durable fact not verifiable");
                }
            }
            Err(error) => {
                // 镜像缺失只退化为 Gateway strict DB 读取；不阻断签发。
                tracing::warn!(%error, "session grant mirror install failed");
            }
        }
    });
}

/// Record a strict PlatformUser JTI proof, including card and credential fences.
async fn record_platform_session_jti_proof(
    state: &AppState,
    token: &TokenResult,
    user_id: i64,
    session_id: i64,
    session_epoch: i64,
    identity_card_id: i64,
) -> Result<(), AstralError> {
    astral_db::record_platform_session_jti_proof(
        &state.db,
        session_id,
        &token.jti,
        user_id,
        session_epoch,
        token.expires_at_epoch_second,
        identity_card_id,
    )
    .await
}

async fn delete_session_projections_before_epoch(
    state: &AppState,
    session_id: i64,
    epoch_exclusive: i64,
) -> Result<(), AstralError> {
    let indexed_jtis =
        astral_db::load_active_jtis_by_session_before_epoch(&state.db, session_id, epoch_exclusive)
            .await?;
    delete_indexed_session_projections(
        &indexed_jtis
            .iter()
            .map(|jti| (jti.clone(),))
            .collect::<Vec<_>>(),
    )
    .await?;
    astral_db::close_jti_proofs_by_session_before_epoch(&state.db, session_id, epoch_exclusive)
        .await?;
    Ok(())
}

/// Register a durably revoked JTI in bounded process-local acceleration
/// surfaces. These markers only accelerate denial; MySQL remains authoritative.
fn mark_registry_revoked(jti: &str, ttl_seconds: u64) {
    if let Some(store) = astral_common::session_projection_store::global_session_projection_store()
    {
        store.note_revocation(jti, ttl_seconds);
    }
    if let Some(registry) =
        astral_common::session_revocation_registry::global_session_revocation_registry()
    {
        registry.mark_revoked(jti, ttl_seconds as i64);
    }
}

async fn delete_indexed_session_projections(indexed_jtis: &[(String,)]) -> Result<(), AstralError> {
    for (jti,) in indexed_jtis {
        mark_registry_revoked(jti, REVOKED_TTL_SECS);
    }
    Ok(())
}

/// Post-commit projection of only the JTI snapshot returned by the atomic
/// password mutation; this helper never reloads a broader snapshot.
pub(crate) async fn project_password_revocation(
    revoked_jtis: &[String],
) -> Result<(), AstralError> {
    for jti in revoked_jtis {
        if jti.trim().is_empty() {
            return Err(AstralError::Validation(
                "Password revocation snapshot contains an empty JTI".into(),
            ));
        }
    }
    astral_db::note_revocations_in_process(revoked_jtis, astral_db::REVOCATION_MIRROR_TTL_SECS);
    for jti in revoked_jtis {
        mark_registry_revoked(jti, REVOKED_TTL_SECS);
    }
    Ok(())
}

const REVOKED_TTL_SECS: u64 = 7 * 24 * 3600;

/// Durable operation states for the CURRENT V6 switch-card state machine.
/// Only the two in-flight states below are eligible for recovery. `UNKNOWN`
/// and every historical state are reconciliation-only and are never replayed.
pub(crate) const SWITCH_OPERATION_STATUS_CAS_PENDING: &str = "CAS_PENDING";
pub(crate) const SWITCH_OPERATION_STATUS_COMMITTED_PENDING_PROJECTION: &str =
    "COMMITTED_PENDING_PROJECTION";
const SWITCH_OPERATION_STATUS_COMPLETED: &str = "COMPLETED";
const SWITCH_OPERATION_STATUS_FAILED: &str = "FAILED";
const SWITCH_OPERATION_STATUS_UNKNOWN: &str = "UNKNOWN";
const SWITCH_OPERATION_STATUS_NAMES: [&str; 5] = [
    SWITCH_OPERATION_STATUS_CAS_PENDING,
    SWITCH_OPERATION_STATUS_COMMITTED_PENDING_PROJECTION,
    SWITCH_OPERATION_STATUS_COMPLETED,
    SWITCH_OPERATION_STATUS_FAILED,
    SWITCH_OPERATION_STATUS_UNKNOWN,
];
pub(crate) const SWITCH_OPERATION_RECOVERY_ATTEMPT_LIMIT: i32 = 5;
const SWITCH_OPERATION_RECOVERY_LEASE_SECONDS: i64 = 30;

fn is_recoverable_switch_operation_status(status: &str) -> bool {
    matches!(
        status,
        SWITCH_OPERATION_STATUS_CAS_PENDING | SWITCH_OPERATION_STATUS_COMMITTED_PENDING_PROJECTION
    )
}

struct SwitchCardPrepared {
    response: LoginResponse,
    access_token: TokenResult,
    user_id: i64,
    session_id: i64,
    family_id: i64,
    source_card_id: i64,
    target_card_id: i64,
    identity_card_id: i64,
    previous_session_version: i64,
    previous_session_epoch: i64,
    expected_session_version: i64,
    expected_session_epoch: i64,
    old_refresh_hash: String,
    new_refresh_hash: String,
    new_refresh_expires_at: PrimitiveDateTime,
    effective_device_id: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct SwitchOperationRow {
    operation_id: String,
    user_id: i64,
    request_hash: String,
    refresh_token_hash: String,
    source_card_id: Option<i64>,
    target_card_id: Option<i64>,
    session_id: Option<i64>,
    selected_identity_card_id: Option<i64>,
    previous_session_version: Option<i64>,
    previous_session_epoch: Option<i64>,
    expected_session_version: Option<i64>,
    expected_session_epoch: Option<i64>,
    device_id: Option<String>,
    new_refresh_token_hash: Option<String>,
    new_refresh_expires_at: Option<PrimitiveDateTime>,
    status: String,
    response_ciphertext: Option<String>,
    response_expires_at: Option<PrimitiveDateTime>,
    recovery_expires_at: Option<PrimitiveDateTime>,
    recovery_attempts: i32,
    recovery_claim_owner: Option<String>,
    recovery_claim_expires_at: Option<PrimitiveDateTime>,
    last_error: Option<String>,
}

struct SwitchOperationInsert<'a> {
    operation_id: &'a str,
    user_id: i64,
    idempotency_key: &'a str,
    request_hash: &'a str,
    refresh_hash: &'a str,
    prepared: &'a SwitchCardPrepared,
    response_ciphertext: &'a str,
    response_expires_at: PrimitiveDateTime,
    recovery_expires_at: PrimitiveDateTime,
}

#[derive(Debug, sqlx::FromRow)]
struct SwitchDurableSessionRow {
    session_id: i64,
    user_id: i64,
    family_id: i64,
    current_user_card_id: Option<i64>,
    session_state: String,
    session_version: i64,
    session_epoch: i64,
    refresh_token_hash: String,
    status: String,
}

struct SwitchResponseProof {
    access_token: TokenResult,
    user_id: i64,
    session_id: i64,
    family_id: i64,
    identity_card_id: i64,
    target_card_id: i64,
    tenant_id: i64,
    domain_id: i64,
    session_version: i64,
    session_epoch: i64,
}

#[derive(Debug, sqlx::FromRow)]
struct SwitchCardRow {
    card_id: i64,
    user_id: i64,
    domain_id: Option<i64>,
    tenant_id: Option<i64>,
    template_id: Option<i64>,
    level_id: Option<i64>,
    card_type: String,
    card_status: String,
    priority: Option<i32>,
    is_primary: Option<bool>,
    template_code: Option<String>,
    template_name: Option<String>,
    level_code: Option<String>,
    level_name: Option<String>,
    level_no: Option<i32>,
    action_codes: Option<String>,
    base_rule_set_ids: Option<String>,
    overlay_rule_set_ids: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct SwitchUserRow {
    user_id: i64,
    user_no: String,
    display_name: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    status: String,
}

/// Rotate the authenticated durable session onto a user-owned active card.
///
/// The refresh JWT is the only credential. Its session context is checked against
/// the durable row before the idempotent operation is created. Recovery is keyed
/// only by `(user_id, operation_type, idempotency_key_hash)` after that lookup.
pub(crate) async fn switch_card_session(
    state: &AppState,
    headers: &HeaderMap,
    target_card_id: i64,
    device_id: Option<&str>,
) -> Result<LoginResponse, AppError> {
    let refresh_token = bearer_token(headers)
        .ok_or_else(|| AppError::from(AstralError::Auth("REFRESH_BEARER_REQUIRED".into())))?;
    let (claims, token_use) = decode_v2_token(refresh_token, &state.config).map_err(|reason| {
        AppError::from(AstralError::Auth(format!(
            "Invalid refresh token: {reason}"
        )))
    })?;
    if token_use != TokenUse::Refresh {
        return Err(AppError::from(AstralError::Auth(
            "REFRESH_TOKEN_REQUIRED".into(),
        )));
    }
    if !is_platform_user(&claims.principal_kind) {
        return Err(AppError::from(AstralError::Auth(
            "SWITCH_CARD_PLATFORM_USER_REQUIRED".into(),
        )));
    }
    let session_id = claims
        .sid
        .ok_or_else(|| AppError::from(AstralError::Auth("SESSION_CONTEXT_INVALID".into())))?;
    let family_id = claims
        .family_id
        .ok_or_else(|| AppError::from(AstralError::Auth("SESSION_CONTEXT_INVALID".into())))?;
    let user_id = claims
        .sub
        .parse::<i64>()
        .map_err(|_| AppError::from(AstralError::Auth("SESSION_CONTEXT_INVALID".into())))?;
    let refresh_hash = sha256_hash(refresh_token);
    let idempotency_key = required_idempotency_key(headers)?;
    if target_card_id <= 0 {
        return Err(AppError::from(AstralError::Validation(
            "targetUserCardId required".into(),
        )));
    }

    let normalized_device_id = device_id.map(str::trim).filter(|value| !value.is_empty());
    if let Some(operation) = load_switch_operation(state, user_id, idempotency_key).await? {
        validate_switch_recovery_context(state, &operation, session_id, family_id, target_card_id)
            .await?;
        if operation.status != SWITCH_OPERATION_STATUS_COMPLETED {
            let expected_request_hash = switch_request_hash(
                user_id,
                operation.source_card_id.ok_or_else(|| {
                    AppError::from(AstralError::Auth(
                        "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
                    ))
                })?,
                target_card_id,
                &claims.jti,
                &refresh_hash,
                normalized_device_id,
            );
            if operation.request_hash != expected_request_hash {
                return Err(AppError::from(AstralError::Validation(
                    "IDEMPOTENCY_KEY_REUSED".into(),
                )));
            }
        }
        return replay_or_recover_switch_operation(state, operation, &refresh_hash).await;
    }

    let session = match session_repo::load_active_refresh_session(&state.db, &refresh_hash)
        .await?
        .filter(|row| {
            row.session_id == session_id
                && row.family_id == family_id
                && row.user_id == user_id
                && row.current_user_card_id.is_some()
                && row.credential_version.is_some_and(|version| version > 0)
                && row.session_version == claims.session_version.unwrap_or_default()
                && row.session_epoch == claims.sev.unwrap_or_default()
        }) {
        Some(session) => session,
        None => {
            // A validly signed refresh token that still names this active session
            // but no longer matches its durable hash is a reuse signal, including
            // requests that changed the idempotency key after a completed switch.
            if let Some(current) =
                session_repo::load_active_session_context(&state.db, session_id, user_id, family_id)
                    .await?
            {
                if current.refresh_token_hash != refresh_hash {
                    if let Err(error) =
                        revoke_token_family(state, current.family_id, "TOKEN_REUSE_DETECTED").await
                    {
                        return Err(AppError::from(AstralError::Auth(format!(
                            "TOKEN_REUSE_DETECTED; failed to revoke token family: {error}"
                        ))));
                    }
                    return Err(AppError::from(AstralError::Auth(
                        "Token reuse detected. All sessions have been revoked.".into(),
                    )));
                }
            }
            return Err(AppError::from(AstralError::Auth(
                "Invalid refresh session".into(),
            )));
        }
    };
    if target_card_id <= 0 {
        return Err(AppError::from(AstralError::Validation(
            "targetUserCardId required".into(),
        )));
    }
    let _ = session_response_key()?;

    let from_card_id = session
        .current_user_card_id
        .ok_or_else(|| AppError::from(AstralError::Auth("CARD_SELECTION_REQUIRED".into())))?;
    let request_hash = switch_request_hash(
        user_id,
        from_card_id,
        target_card_id,
        &claims.jti,
        &refresh_hash,
        normalized_device_id,
    );
    let prepared = prepare_switch_card(
        state,
        headers,
        user_id,
        from_card_id,
        target_card_id,
        refresh_token,
        normalized_device_id,
    )
    .await?;
    let operation_id = uuid::Uuid::new_v4().to_string();
    let ciphertext = encrypt_operation_response(&operation_id, &prepared.response)?;
    let response_expires_at = response_expiry()?;
    let recovery_expires_at = recovery_expiry()?;

    // The encrypted response and every CAS input are durable before the source
    // mutation. This is the only path that creates a new switch operation.
    let operation = begin_switch_operation(
        state,
        SwitchOperationInsert {
            operation_id: &operation_id,
            user_id,
            idempotency_key,
            request_hash: &request_hash,
            refresh_hash: &refresh_hash,
            prepared: &prepared,
            response_ciphertext: &ciphertext,
            response_expires_at,
            recovery_expires_at,
        },
    )
    .await?;
    let operation = match operation {
        Some(existing) => {
            if existing.request_hash != request_hash {
                return Err(AppError::from(AstralError::Validation(
                    "IDEMPOTENCY_KEY_REUSED".into(),
                )));
            }
            validate_switch_recovery_context(
                state,
                &existing,
                session_id,
                family_id,
                target_card_id,
            )
            .await?;
            return replay_or_recover_switch_operation(state, existing, &refresh_hash).await;
        }
        None => load_switch_operation_by_id(state, &operation_id)
            .await?
            .ok_or_else(|| {
                AppError::from(AstralError::Auth(
                    "SESSION_OPERATION_PENDING_RECONCILIATION".into(),
                ))
            })?,
    };

    replay_or_recover_switch_operation(state, operation, &refresh_hash).await
}

fn required_idempotency_key(headers: &HeaderMap) -> Result<&str, AppError> {
    let key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 255)
        .ok_or_else(|| {
            AppError::from(AstralError::Validation("IDEMPOTENCY_KEY_REQUIRED".into()))
        })?;
    Ok(key)
}

const SWITCH_OPERATION_SELECT: &str =
    "SELECT operation_id, user_id, request_hash, refresh_token_hash, source_card_id, target_card_id, session_id, \
     selected_identity_card_id, previous_session_version, previous_session_epoch, \
     expected_session_version, expected_session_epoch, device_id, new_refresh_token_hash, new_refresh_expires_at, \
     status, response_ciphertext, response_expires_at, recovery_expires_at, recovery_attempts, recovery_claim_owner, recovery_claim_expires_at, last_error \
     FROM auth_session_operation";

async fn validate_switch_recovery_context(
    state: &AppState,
    operation: &SwitchOperationRow,
    session_id: i64,
    family_id: i64,
    target_card_id: i64,
) -> Result<(), AppError> {
    if operation.session_id != Some(session_id) || operation.target_card_id != Some(target_card_id)
    {
        return Err(AppError::from(AstralError::Validation(
            "IDEMPOTENCY_KEY_REUSED".into(),
        )));
    }
    let operation_family_id = load_switch_operation_family_id(operation, state).await?;
    if operation_family_id != family_id {
        return Err(AppError::from(AstralError::Validation(
            "IDEMPOTENCY_KEY_REUSED".into(),
        )));
    }
    Ok(())
}

async fn load_switch_operation(
    state: &AppState,
    user_id: i64,
    idempotency_key: &str,
) -> Result<Option<SwitchOperationRow>, AppError> {
    let query = format!(
        "{SWITCH_OPERATION_SELECT} WHERE user_id = ? AND operation_type = 'SWITCH_CARD' \
         AND idempotency_key_hash = ? LIMIT 1"
    );
    sqlx::query_as::<_, SwitchOperationRow>(&query)
        .bind(user_id)
        .bind(sha256_hash(idempotency_key))
        .fetch_optional(&state.db)
        .await
        .map_err(|error| AstralError::Database(format!("Load switch operation failed: {error}")))
        .map_err(AppError::from)
}

async fn load_switch_operation_by_id(
    state: &AppState,
    operation_id: &str,
) -> Result<Option<SwitchOperationRow>, AppError> {
    let query = format!("{SWITCH_OPERATION_SELECT} WHERE operation_id = ? LIMIT 1");
    sqlx::query_as::<_, SwitchOperationRow>(&query)
        .bind(operation_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|error| AstralError::Database(format!("Load switch operation failed: {error}")))
        .map_err(AppError::from)
}

async fn begin_switch_operation(
    state: &AppState,
    input: SwitchOperationInsert<'_>,
) -> Result<Option<SwitchOperationRow>, AppError> {
    let insert = sqlx::query(
        "INSERT INTO auth_session_operation \
         (operation_id, user_id, operation_type, idempotency_key_hash, request_hash, refresh_token_hash, \
          session_id, source_card_id, target_card_id, selected_identity_card_id, previous_session_version, \
          previous_session_epoch, expected_session_version, expected_session_epoch, device_id, new_refresh_token_hash, \
          new_refresh_expires_at, status, response_ciphertext, response_expires_at, recovery_expires_at) \
         VALUES (?, ?, 'SWITCH_CARD', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'CAS_PENDING', ?, ?, ?)"
    )
    .bind(input.operation_id)
    .bind(input.user_id)
    .bind(sha256_hash(input.idempotency_key))
    .bind(input.request_hash)
    .bind(input.refresh_hash)
    .bind(input.prepared.session_id)
    .bind(input.prepared.source_card_id)
    .bind(input.prepared.target_card_id)
    .bind(input.prepared.identity_card_id)
    .bind(input.prepared.previous_session_version)
    .bind(input.prepared.previous_session_epoch)
    .bind(input.prepared.expected_session_version)
    .bind(input.prepared.expected_session_epoch)
    .bind(&input.prepared.effective_device_id)
    .bind(&input.prepared.new_refresh_hash)
    .bind(input.prepared.new_refresh_expires_at)
    .bind(input.response_ciphertext)
    .bind(input.response_expires_at)
    .bind(input.recovery_expires_at)
    .execute(&state.db)
    .await;

    match insert {
        Ok(result) if result.rows_affected() == 1 => Ok(None),
        Ok(_) => Err(AppError::from(AstralError::Database(
            "Switch operation insert affected an unexpected row count".into(),
        ))),
        Err(insert_error) => load_switch_operation(state, input.user_id, input.idempotency_key)
            .await?
            .map(Some)
            .ok_or_else(|| {
                AppError::from(AstralError::Database(format!(
                    "Create switch operation failed: {insert_error}"
                )))
            }),
    }
}

fn switch_recovery_claimant(operation_id: &str) -> String {
    let attempt = format!("{operation_id}:{}", uuid::Uuid::new_v4());
    let digest = sha256_hash(&attempt);
    format!("switch-recovery-{}", &digest[..48.min(digest.len())])
}

async fn claim_switch_operation(
    state: &AppState,
    operation_id: &str,
    claimant: &str,
) -> Result<bool, AppError> {
    let result = sqlx::query(
        "UPDATE auth_session_operation SET recovery_claim_owner = ?, \
         recovery_claim_expires_at = DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND), \
         recovery_attempts = recovery_attempts + CASE WHEN recovery_attempts < ? THEN 1 ELSE 0 END, \
         updated_at = UTC_TIMESTAMP() \
         WHERE operation_id = ? AND status IN (?, ?) AND recovery_attempts <= ? \
           AND recovery_expires_at IS NOT NULL \
           AND (recovery_claim_expires_at IS NULL OR recovery_claim_expires_at <= UTC_TIMESTAMP())",
    )
    .bind(claimant)
    .bind(SWITCH_OPERATION_RECOVERY_LEASE_SECONDS)
    .bind(SWITCH_OPERATION_RECOVERY_ATTEMPT_LIMIT)
    .bind(operation_id)
    .bind(SWITCH_OPERATION_STATUS_CAS_PENDING)
    .bind(SWITCH_OPERATION_STATUS_COMMITTED_PENDING_PROJECTION)
    .bind(SWITCH_OPERATION_RECOVERY_ATTEMPT_LIMIT)
    .execute(&state.db)
    .await
    .map_err(|error| AstralError::Database(format!("Claim switch operation failed: {error}")))?;
    Ok(result.rows_affected() == 1)
}

async fn claim_switch_operation_for_recovery(
    state: &AppState,
    operation_id: &str,
) -> Result<Option<(SwitchOperationRow, String)>, AppError> {
    let claimant = switch_recovery_claimant(operation_id);
    if !claim_switch_operation(state, operation_id, &claimant).await? {
        return Ok(None);
    }
    let operation = load_switch_operation_by_id(state, operation_id)
        .await?
        .ok_or_else(|| {
            AppError::from(AstralError::Auth(
                "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
            ))
        })?;
    if operation.recovery_claim_owner.as_deref() != Some(claimant.as_str()) {
        return Err(AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        )));
    }
    Ok(Some((operation, claimant)))
}

async fn release_switch_operation_claim(
    state: &AppState,
    operation_id: &str,
    claimant: &str,
) -> Result<(), AppError> {
    let result = sqlx::query(
        "UPDATE auth_session_operation SET recovery_claim_owner = NULL, \
         recovery_claim_expires_at = NULL, updated_at = UTC_TIMESTAMP() \
         WHERE operation_id = ? AND recovery_claim_owner = ? \
           AND recovery_claim_expires_at > UTC_TIMESTAMP()",
    )
    .bind(operation_id)
    .bind(claimant)
    .execute(&state.db)
    .await
    .map_err(|error| {
        AstralError::Database(format!("Release switch operation claim failed: {error}"))
    })?;
    if result.rows_affected() == 1 {
        return Ok(());
    }
    Err(AppError::from(AstralError::Auth(
        "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
    )))
}

async fn mark_switch_operation_failed(
    state: &AppState,
    operation: &SwitchOperationRow,
    claimant: &str,
    reason: &str,
) -> Result<(), AppError> {
    let result = sqlx::query(
        "UPDATE auth_session_operation AS operation SET status = ?, last_error = ?, \
         recovery_claim_owner = NULL, recovery_claim_expires_at = NULL, updated_at = UTC_TIMESTAMP() \
         WHERE operation_id = ? AND status IN (?, ?) AND recovery_claim_owner = ? \
           AND recovery_claim_expires_at > UTC_TIMESTAMP() \
           AND EXISTS (SELECT 1 FROM auth_device_session AS session \
             WHERE session.session_id = operation.session_id \
               AND session.user_id = operation.user_id \
               AND session.current_user_card_id = operation.source_card_id \
               AND session.refresh_token_hash = operation.refresh_token_hash \
               AND session.status = 'ACTIVE' AND session.session_state = 'ACTIVE' \
               AND session.session_version = operation.previous_session_version \
               AND session.session_epoch = operation.previous_session_epoch)",
    )
    .bind(SWITCH_OPERATION_STATUS_FAILED)
    .bind(reason.chars().take(255).collect::<String>())
    .bind(&operation.operation_id)
    .bind(SWITCH_OPERATION_STATUS_CAS_PENDING)
    .bind(SWITCH_OPERATION_STATUS_COMMITTED_PENDING_PROJECTION)
    .bind(claimant)
    .execute(&state.db)
    .await
    .map_err(|error| AstralError::Database(format!("Mark switch operation failed: {error}")))?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        let current = load_switch_operation_by_id(state, &operation.operation_id).await?;
        if current
            .as_ref()
            .is_some_and(|row| row.status == SWITCH_OPERATION_STATUS_FAILED)
        {
            Ok(())
        } else {
            Err(AppError::from(AstralError::Auth(
                "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
            )))
        }
    }
}

async fn mark_switch_operation_unknown(
    state: &AppState,
    operation_id: &str,
    reason: &str,
    claimant: &str,
) -> Result<(), AppError> {
    let result = sqlx::query(
        "UPDATE auth_session_operation SET status = ?, last_error = ?, \
         recovery_claim_owner = NULL, recovery_claim_expires_at = NULL, updated_at = UTC_TIMESTAMP() \
         WHERE operation_id = ? AND status IN (?, ?) AND recovery_claim_owner = ? \
           AND recovery_claim_expires_at > UTC_TIMESTAMP()",
    )
    .bind(SWITCH_OPERATION_STATUS_UNKNOWN)
    .bind(reason.chars().take(255).collect::<String>())
    .bind(operation_id)
    .bind(SWITCH_OPERATION_STATUS_CAS_PENDING)
    .bind(SWITCH_OPERATION_STATUS_COMMITTED_PENDING_PROJECTION)
    .bind(claimant)
    .execute(&state.db)
    .await
    .map_err(|error| AstralError::Database(format!("Mark switch operation unknown: {error}")))?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        let current = load_switch_operation_by_id(state, operation_id).await?;
        if current
            .as_ref()
            .is_some_and(|row| row.status == SWITCH_OPERATION_STATUS_UNKNOWN)
        {
            Ok(())
        } else {
            Err(AppError::from(AstralError::Auth(
                "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
            )))
        }
    }
}

async fn prepare_switch_card(
    state: &AppState,
    headers: &HeaderMap,
    user_id: i64,
    from_card_id: i64,
    target_card_id: i64,
    refresh_token: &str,
    requested_device_id: Option<&str>,
) -> Result<SwitchCardPrepared, AppError> {
    let refresh_hash = sha256_hash(refresh_token);
    let session = load_active_refresh_session(&state.db, &refresh_hash).await?;
    if session.user_id != user_id || session.current_user_card_id != Some(from_card_id) {
        return Err(AppError::from(AstralError::Auth("CARD_NOT_FOUND".into())));
    }
    match check_family_valid(&state.db, session.family_id).await? {
        FamilyStatus::Active => {}
        _ => return Err(AppError::from(AstralError::Auth("TOKEN_EXPIRED".into()))),
    }
    if session
        .refresh_expires_at
        .map(|expires_at| expires_at <= utc_db_now())
        .unwrap_or(true)
    {
        return Err(AppError::from(AstralError::Auth("TOKEN_EXPIRED".into())));
    }

    let user = sqlx::query_as::<_, SwitchUserRow>(
        "SELECT user_id, user_no, display_name, email, phone, status FROM platform_user \
         WHERE user_id = ? AND deleted_at IS NULL LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| AstralError::Database(format!("Load switch user failed: {error}")))?
    .filter(|row| row.status == "ACTIVE")
    .ok_or_else(|| AppError::from(AstralError::Auth("user_not_found".into())))?;

    let card_rows = load_active_switch_cards(&state.db, user_id).await?;
    let target = card_rows
        .iter()
        .find(|card| card.card_id == target_card_id && card.user_id == user_id)
        .ok_or_else(|| AppError::from(AstralError::Auth("CARD_NOT_FOUND".into())))?;
    let target_card = switch_card_value(target);
    let available_cards = card_rows.iter().map(switch_card_value).collect::<Vec<_>>();
    let permissions = load_card_permissions(&state.db, target_card_id).await?;

    let identity = sqlx::query_as::<_, (i64, Option<i64>, Option<String>)>(
        "SELECT card_id, token_version, \
                DATE_FORMAT(expires_at, '%Y-%m-%dT%H:%i:%sZ') AS expires_at \
         FROM identity_card \
         WHERE user_id = ? AND status = 'ACTIVE' \
           AND (expires_at IS NULL OR expires_at >= UTC_TIMESTAMP()) \
         ORDER BY card_id ASC LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| AstralError::Database(format!("Load switch identity card failed: {error}")))?
    .ok_or_else(|| AppError::from(AstralError::Auth("CARD_NOT_FOUND".into())))?;

    // 签发资格权威校验：目标 user_card 选定后统一走资格服务，补齐签发侧对
    // tenant/domain ACTIVE 与对应关系证明的检查缺口（load_active_switch_cards 仅校验
    // user_card 自身状态/时间窗，不校验组织线路）。失败 fail-closed 拒绝切换，
    // 幂等 operation / session rotation / rollback 路径保持不变。
    if let Err(error) = astral_db::CardEligibilityService::verify_platform_card_pair(
        &state.db,
        &astral_types::PlatformCardPairRequest {
            user_id,
            identity_card_id: identity.0,
            user_card_id: target_card_id,
        },
    )
    .await
    {
        tracing::warn!(
            user_id,
            target_card_id,
            error = %error,
            "card switch refused: platform card pair not eligible"
        );
        return Err(AppError::from(map_eligibility_error(error, |_| {
            AstralError::Auth("USER_CARD_SCOPE_REQUIRED".into())
        })));
    }

    let next_session_version = session
        .session_version
        .checked_add(1)
        .ok_or_else(|| AstralError::Auth("Session version exhausted".into()))?;
    let next_session_epoch = session
        .session_epoch
        .checked_add(1)
        .ok_or_else(|| AstralError::Auth("Session epoch exhausted".into()))?;
    let refresh_lifetime = state.config.jwt.refresh.expiry_seconds;
    let refresh_expires_at = utc_db_now()
        .checked_add(Duration::seconds(refresh_lifetime))
        .ok_or_else(|| AstralError::Auth("Refresh expiry overflow".into()))?;
    let id_card = astral_types::IdentityCard {
        card_id: Some(identity.0),
        user_id,
        status: "ACTIVE".into(),
        token_version: identity.1,
        expires_at: identity.2,
        disabled_reason: None,
        last_used_at: None,
        created_at: None,
        updated_at: None,
    };
    let user_card = astral_types::UserCard {
        card_id: Some(target.card_id),
        user_id: Some(user_id),
        domain_id: target.domain_id,
        card_type: target.card_type.clone(),
        card_status: target.card_status.clone(),
        template_id: target.template_id,
        level_id: target.level_id,
        priority: target.priority,
        is_primary: target.is_primary,
        valid_from: None,
        valid_until: None,
        created_at: None,
        updated_at: None,
        tenant_id: target.tenant_id,
    };
    let session_context = SessionContext {
        session_id: session.session_id,
        session_version: next_session_version,
        session_epoch: next_session_epoch,
        family_id: session.family_id,
    };
    let token = issue_access_token(
        &state.config.jwt,
        &id_card,
        &user_card,
        session_context,
        None,
    )?;
    let refresh_result = issue_refresh_token(&state.config.jwt, user_id, session_context)?;
    let refresh_hash = sha256_hash(&refresh_result.token);
    let response = LoginResponse {
        access_token: token.token.clone(),
        // Switch-card preserves the long-lived credential. It only rotates the
        // access projection and its session epoch.
        refresh_token: refresh_result.token.clone(),
        token_type: "Bearer".into(),
        expires_in_millis: token.expires_in * 1000,
        refresh_expires_in_millis: refresh_lifetime * 1000,
        user: Some(serde_json::json!({
            "userId": user.user_id,
            "username": user.user_no,
            "displayName": user.display_name,
            "email": user.email,
            "phone": user.phone,
            "status": user.status,
            "hasLocalCredential": true,
        })),
        current_card: Some(target_card),
        available_cards: Some(available_cards),
        permissions: Some(permissions),
        roles: Some(vec!["USER".into()]),
        enterprises: Some(vec![]),
        session: Some(serde_json::json!({
            "sessionId": session.session_id,
            "familyId": session.family_id,
            "sessionVersion": next_session_version,
            "sessionEpoch": next_session_epoch,
            "sessionState": "ACTIVE",
            "currentUserCardId": target_card_id,
        })),
    };

    // Preparation has no durable side effects. The old projection is closed only
    // after the session CAS is proven, immediately before the new JTI proof.
    let effective_device_id = requested_device_id
        .unwrap_or(&session.device_id)
        .to_string();
    Ok(SwitchCardPrepared {
        response,
        access_token: token,
        user_id,
        session_id: session.session_id,
        family_id: session.family_id,
        source_card_id: from_card_id,
        target_card_id,
        identity_card_id: identity.0,
        previous_session_version: session.session_version,
        previous_session_epoch: session.session_epoch,
        expected_session_version: next_session_version,
        expected_session_epoch: next_session_epoch,
        old_refresh_hash: sha256_hash(refresh_token),
        new_refresh_hash: refresh_hash,
        new_refresh_expires_at: refresh_expires_at,
        effective_device_id,
        ip_address: request_header_text(headers, "x-forwarded-for"),
        user_agent: request_header_text(headers, "user-agent"),
    })
}

async fn reconcile_capped_switch_operation(
    state: &AppState,
    operation: &SwitchOperationRow,
    claimant: &str,
) -> Result<(), AppError> {
    let durable = load_switch_durable_session(state, operation).await?;
    match durable {
        Some(row) if switch_session_is_expected(&row, operation) => {
            transition_switch_operation_to_projection(state, operation, claimant).await
        }
        Some(row) if switch_session_is_previous(&row, operation) => {
            mark_switch_operation_failed(
                state,
                operation,
                claimant,
                "RECOVERY_ATTEMPT_LIMIT_REACHED",
            )
            .await?;
            Err(AppError::from(AstralError::Auth(
                "SESSION_OPERATION_FAILED".into(),
            )))
        }
        Some(_) | None => {
            mark_switch_operation_unknown(
                state,
                &operation.operation_id,
                "RECOVERY_ATTEMPT_LIMIT_STATE_UNPROVABLE",
                claimant,
            )
            .await?;
            Err(AppError::from(AstralError::Auth(
                "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
            )))
        }
    }
}

async fn apply_switch_cas(
    state: &AppState,
    operation: &SwitchOperationRow,
    claimant: &str,
) -> Result<(), AppError> {
    if operation.status != SWITCH_OPERATION_STATUS_CAS_PENDING {
        return Ok(());
    }
    if operation.recovery_attempts >= SWITCH_OPERATION_RECOVERY_ATTEMPT_LIMIT {
        return reconcile_capped_switch_operation(state, operation, claimant).await;
    }
    let session_id = operation.session_id.ok_or_else(|| {
        AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        ))
    })?;
    let user_id = operation.user_id;
    let family_id = load_switch_operation_family_id(operation, state).await?;
    let source_card_id = operation.source_card_id.ok_or_else(|| {
        AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        ))
    })?;
    let target_card_id = operation.target_card_id.ok_or_else(|| {
        AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        ))
    })?;
    let previous_session_version = operation.previous_session_version.ok_or_else(|| {
        AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        ))
    })?;
    let previous_session_epoch = operation.previous_session_epoch.ok_or_else(|| {
        AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        ))
    })?;
    let expected_session_version = operation.expected_session_version.ok_or_else(|| {
        AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        ))
    })?;
    let expected_session_epoch = operation.expected_session_epoch.ok_or_else(|| {
        AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        ))
    })?;
    let new_refresh_hash = operation.new_refresh_token_hash.as_deref().ok_or_else(|| {
        AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        ))
    })?;
    let old_refresh_hash = operation.refresh_token_hash.as_str();
    let device_id = match operation.device_id.as_deref() {
        Some(device_id) => Some(device_id.to_owned()),
        None => load_switch_session_device_id(state, operation).await?,
    };
    let rotation_guard = source_writer_guard::begin_source_write()?;
    let rotation = source_writer_guard::fenced_source_write(
        rotation_guard,
        sqlx::query(
            "UPDATE auth_device_session SET device_id = COALESCE(?, device_id), \
             current_user_card_id = ?, session_state = 'ACTIVE', session_version = ?, session_epoch = ?, \
             refresh_token_hash = ?, refresh_expires_at = ?, status = 'ACTIVE', revoked_at = NULL, \
             revoked_reason = NULL, last_seen_at = UTC_TIMESTAMP(), updated_at = UTC_TIMESTAMP() \
             WHERE session_id = ? AND user_id = ? AND family_id = ? AND current_user_card_id = ? \
             AND refresh_token_hash = ? AND status = 'ACTIVE' AND session_state = 'ACTIVE' \
             AND session_version = ? AND session_epoch = ? \
             AND EXISTS (SELECT 1 FROM auth_session_operation operation \
               WHERE operation.operation_id = ? AND operation.status = ? \
                 AND operation.recovery_claim_owner = ? \
                 AND operation.recovery_claim_expires_at > UTC_TIMESTAMP())",
        )
        .bind(device_id.as_deref())
        .bind(target_card_id)
        .bind(expected_session_version)
        .bind(expected_session_epoch)
        .bind(new_refresh_hash)
        .bind(operation.new_refresh_expires_at)
        .bind(session_id)
        .bind(user_id)
        .bind(family_id)
        .bind(source_card_id)
        .bind(old_refresh_hash)
        .bind(previous_session_version)
        .bind(previous_session_epoch)
        .bind(&operation.operation_id)
        .bind(SWITCH_OPERATION_STATUS_CAS_PENDING)
        .bind(claimant)
        .execute(&state.db),
    )
    .await;

    let rotation = match rotation {
        Ok(value) => value,
        Err(_error) => {
            let durable = load_switch_durable_session(state, operation).await?;
            match durable {
                Some(row) if switch_session_is_expected(&row, operation) => {
                    transition_switch_operation_to_projection(state, operation, claimant).await?;
                    return Ok(());
                }
                Some(row) if switch_session_is_previous(&row, operation) => {
                    mark_switch_operation_failed(state, operation, claimant, "CAS_NOT_APPLIED")
                        .await?;
                    return Err(AppError::from(AstralError::Auth(
                        "SESSION_VERSION_CONFLICT".into(),
                    )));
                }
                Some(_) | None => {
                    mark_switch_operation_unknown(
                        state,
                        &operation.operation_id,
                        "CAS_OUTCOME_UNPROVABLE",
                        claimant,
                    )
                    .await?;
                    return Err(AppError::from(AstralError::Auth(
                        "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
                    )));
                }
            }
        }
    };
    if rotation.rows_affected() != 1 {
        let durable = load_switch_durable_session(state, operation).await?;
        match durable {
            Some(row) if switch_session_is_expected(&row, operation) => {
                transition_switch_operation_to_projection(state, operation, claimant).await
            }
            Some(row) if switch_session_is_previous(&row, operation) => {
                let _ = mark_switch_operation_failed(state, operation, claimant, "CAS_NOT_APPLIED")
                    .await;
                Err(AppError::from(AstralError::Auth(
                    "SESSION_VERSION_CONFLICT".into(),
                )))
            }
            _ => {
                let _ = mark_switch_operation_unknown(
                    state,
                    &operation.operation_id,
                    "CAS_STATE_UNPROVABLE",
                    claimant,
                )
                .await;
                Err(AppError::from(AstralError::Auth(
                    "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
                )))
            }
        }
    } else {
        transition_switch_operation_to_projection(state, operation, claimant).await
    }
}

async fn load_switch_session_device_id(
    state: &AppState,
    operation: &SwitchOperationRow,
) -> Result<Option<String>, AppError> {
    let session_id = operation.session_id.ok_or_else(|| {
        AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        ))
    })?;
    sqlx::query_scalar::<_, String>(
        "SELECT device_id FROM auth_device_session WHERE session_id = ? AND user_id = ? LIMIT 1",
    )
    .bind(session_id)
    .bind(operation.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| AstralError::Database(format!("Load switch device id failed: {error}")))
    .map_err(AppError::from)
}

async fn load_switch_operation_family_id(
    operation: &SwitchOperationRow,
    state: &AppState,
) -> Result<i64, AppError> {
    let session_id = operation.session_id.ok_or_else(|| {
        AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        ))
    })?;
    sqlx::query_scalar::<_, i64>(
        "SELECT family_id FROM auth_device_session WHERE session_id = ? LIMIT 1",
    )
    .bind(session_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| AstralError::Database(format!("Load switch session family failed: {error}")))?
    .ok_or_else(|| {
        AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        ))
    })
}

async fn transition_switch_operation_to_projection(
    state: &AppState,
    operation: &SwitchOperationRow,
    claimant: &str,
) -> Result<(), AppError> {
    let result = sqlx::query(
        "UPDATE auth_session_operation SET status = ?, updated_at = UTC_TIMESTAMP() \
         WHERE operation_id = ? AND status = ? AND recovery_claim_owner = ? \
           AND recovery_claim_expires_at > UTC_TIMESTAMP()",
    )
    .bind(SWITCH_OPERATION_STATUS_COMMITTED_PENDING_PROJECTION)
    .bind(&operation.operation_id)
    .bind(SWITCH_OPERATION_STATUS_CAS_PENDING)
    .bind(claimant)
    .execute(&state.db)
    .await
    .map_err(|error| {
        AstralError::Database(format!("Record switch CAS completion failed: {error}"))
    })?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        let current = load_switch_operation_by_id(state, &operation.operation_id).await?;
        if current.as_ref().is_some_and(|row| {
            row.status == SWITCH_OPERATION_STATUS_COMMITTED_PENDING_PROJECTION
                || row.status == SWITCH_OPERATION_STATUS_COMPLETED
        }) {
            Ok(())
        } else {
            let _ = mark_switch_operation_unknown(
                state,
                &operation.operation_id,
                "CAS_STATUS_TRANSITION_UNKNOWN",
                claimant,
            )
            .await;
            Err(AppError::from(AstralError::Auth(
                "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
            )))
        }
    }
}

async fn load_switch_durable_session(
    state: &AppState,
    operation: &SwitchOperationRow,
) -> Result<Option<SwitchDurableSessionRow>, AppError> {
    sqlx::query_as::<_, SwitchDurableSessionRow>(
        "SELECT session_id, user_id, family_id, current_user_card_id, session_state, \
         session_version, session_epoch, refresh_token_hash, status \
         FROM auth_device_session WHERE session_id = ? AND user_id = ? LIMIT 1",
    )
    .bind(operation.session_id)
    .bind(operation.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| AstralError::Database(format!("Load switch durable session failed: {error}")))
    .map_err(AppError::from)
}

fn switch_session_is_expected(
    session: &SwitchDurableSessionRow,
    operation: &SwitchOperationRow,
) -> bool {
    session.current_user_card_id == operation.target_card_id
        && session.session_version == operation.expected_session_version.unwrap_or_default()
        && session.session_epoch == operation.expected_session_epoch.unwrap_or_default()
        && operation
            .new_refresh_token_hash
            .as_deref()
            .is_some_and(|hash| hash == session.refresh_token_hash)
        && session.status == "ACTIVE"
        && session.session_state == "ACTIVE"
}

fn switch_session_is_previous(
    session: &SwitchDurableSessionRow,
    operation: &SwitchOperationRow,
) -> bool {
    session.current_user_card_id == operation.source_card_id
        && session.session_version == operation.previous_session_version.unwrap_or_default()
        && session.session_epoch == operation.previous_session_epoch.unwrap_or_default()
        && session.refresh_token_hash == operation.refresh_token_hash
        && session.status == "ACTIVE"
        && session.session_state == "ACTIVE"
}

async fn load_active_refresh_session(
    db: &sqlx::MySqlPool,
    refresh_hash: &str,
) -> Result<DeviceSessionRow, AppError> {
    session_repo::load_active_refresh_session(db, refresh_hash)
        .await?
        .ok_or_else(|| AppError::from(AstralError::Auth("TOKEN_EXPIRED".into())))
}

async fn load_active_switch_cards(
    db: &sqlx::MySqlPool,
    user_id: i64,
) -> Result<Vec<SwitchCardRow>, AppError> {
    // 卡域查询只含身份/平台目录展示字段；权限摘要由共享快照查询批量回填
    let mut cards: Vec<SwitchCardRow> = sqlx::query_as::<_, SwitchCardRow>(
        "SELECT uc.card_id, uc.user_id, uc.domain_id, uc.tenant_id, uc.template_id, uc.level_id, \
         uc.card_type, uc.card_status, uc.priority, uc.is_primary, t.template_code, t.template_name, \
         l.level_code, l.level_name, l.level_no, \
         NULL as action_codes, NULL as base_rule_set_ids, NULL as overlay_rule_set_ids \
         FROM user_card uc \
         LEFT JOIN user_card_template t ON t.template_id = uc.template_id \
         LEFT JOIN user_card_level_definition l ON l.level_id = uc.level_id \
         WHERE uc.user_id = ? AND uc.card_status = 'ACTIVE' \
           AND uc.card_type != 'LEVEL_TEMPLATE_CARD' \
           AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
           AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()) \
         ORDER BY uc.is_primary DESC, uc.priority ASC, uc.card_id ASC",
    )
    .bind(user_id)
    .fetch_all(db)
    .await
    .map_err(|error| AppError::from(AstralError::Database(format!("Load switch cards failed: {error}"))))?;

    // 批量回填权限摘要（快照读，无 N+1）
    let ids: Vec<i64> = cards.iter().map(|c| c.card_id).collect();
    let summaries = astral_db::load_card_permission_summaries(db, &ids)
        .await
        .map_err(|error| {
            AppError::from(AstralError::Database(format!(
                "Load switch summaries failed: {error}"
            )))
        })?;
    for card in &mut cards {
        let summary = summaries.get(&card.card_id);
        card.action_codes = summary.and_then(|s| s.action_codes.clone());
        card.base_rule_set_ids = summary.and_then(|s| s.base_rule_set_ids.clone());
        card.overlay_rule_set_ids = summary.and_then(|s| s.overlay_rule_set_ids.clone());
    }
    Ok(cards)
}

fn switch_card_value(card: &SwitchCardRow) -> serde_json::Value {
    let parse_strings = |value: &Option<String>| {
        value
            .as_deref()
            .map(|csv| {
                csv.split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    let parse_ids = |value: &Option<String>| {
        value
            .as_deref()
            .map(|csv| {
                csv.split(',')
                    .filter_map(|value| value.trim().parse::<i64>().ok())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    serde_json::json!({
        "cardId": card.card_id,
        "userId": card.user_id,
        "domainId": card.domain_id,
        "tenantId": card.tenant_id,
        "templateId": card.template_id,
        "levelId": card.level_id,
        "cardType": card.card_type,
        "cardStatus": card.card_status,
        "priority": card.priority,
        "isPrimary": card.is_primary,
        "isDefault": card.is_primary,
        "isStarter": card.card_type == "STARTER_CARD",
        "templateCode": card.template_code,
        "templateName": card.template_name,
        "levelCode": card.level_code,
        "levelName": card.level_name,
        "levelNo": card.level_no,
        "cardName": format!("{} · {}", card.template_name.as_deref().unwrap_or(""), card.level_name.as_deref().unwrap_or("")),
        "status": card.card_status,
        "actionCodes": parse_strings(&card.action_codes),
        "ruleSetIds": parse_ids(&card.base_rule_set_ids),
        "overlayRuleSetIds": parse_ids(&card.overlay_rule_set_ids),
    })
}

async fn load_card_permissions(
    db: &sqlx::MySqlPool,
    card_id: i64,
) -> Result<Vec<String>, AppError> {
    // 权限视图读投影快照缓存（Cache-Aside + 投影门禁），不直读源表
    let rows = astral_db::find_effective_permissions_cached(db, card_id)
        .await
        .map_err(|error| {
            AstralError::Database(format!("Load switch permissions failed: {error}"))
        })?;
    Ok(rows
        .into_iter()
        .map(|row| format!("{}:{}", row.resource_type, row.action_code))
        .collect())
}

fn switch_request_hash(
    user_id: i64,
    from_card_id: i64,
    target_card_id: i64,
    access_token_id: &str,
    refresh_hash: &str,
    device_id: Option<&str>,
) -> String {
    sha256_hash(&format!(
        "{user_id}|{from_card_id}|{target_card_id}|{}|{refresh_hash}|{}",
        sha256_hash(access_token_id),
        device_id.unwrap_or_default()
    ))
}

fn response_expiry() -> Result<PrimitiveDateTime, AppError> {
    let seconds = session_response_ttl_seconds().clamp(1, 3600);
    utc_db_now()
        .checked_add(Duration::seconds(seconds))
        .ok_or_else(|| AppError::from(AstralError::Auth("Session response expiry overflow".into())))
}

fn recovery_expiry() -> Result<PrimitiveDateTime, AppError> {
    let response_seconds = session_response_ttl_seconds().clamp(1, 3600);
    let recovery_seconds = session_recovery_ttl_seconds().clamp(response_seconds, 86_400);
    utc_db_now()
        .checked_add(Duration::seconds(recovery_seconds))
        .ok_or_else(|| AppError::from(AstralError::Auth("Session recovery expiry overflow".into())))
}

fn session_response_aes_gcm_key() -> String {
    std::env::var("IDENTITY_SESSION_RESPONSE_AES_GCM_KEY")
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn session_response_ttl_seconds() -> i64 {
    std::env::var("IDENTITY_SESSION_RESPONSE_TTL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(300)
}

fn session_recovery_ttl_seconds() -> i64 {
    std::env::var("IDENTITY_SESSION_RECOVERY_TTL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(3600)
}

fn session_response_key() -> Result<[u8; 32], AppError> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(session_response_aes_gcm_key())
        .map_err(|_| {
            AppError::from(AstralError::Auth(
                "SESSION_RESPONSE_ENCRYPTION_REQUIRED".into(),
            ))
        })?;
    raw.try_into().map_err(|_| {
        AppError::from(AstralError::Auth(
            "SESSION_RESPONSE_ENCRYPTION_KEY_INVALID".into(),
        ))
    })
}

fn encrypt_operation_response(
    operation_id: &str,
    response: &LoginResponse,
) -> Result<String, AppError> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use base64::Engine;
    use rand::RngCore;

    let key = session_response_key()?;
    let plaintext = serde_json::to_vec(response).map_err(|error| {
        AppError::from(AstralError::Internal(format!(
            "Serialize switch response failed: {error}"
        )))
    })?;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| {
        AppError::from(AstralError::Auth(
            "SESSION_RESPONSE_ENCRYPTION_KEY_INVALID".into(),
        ))
    })?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: operation_id.as_bytes(),
            },
        )
        .map_err(|_| {
            AppError::from(AstralError::Internal(
                "Encrypt switch response failed".into(),
            ))
        })?;
    Ok(format!(
        "v1.{}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ciphertext)
    ))
}

fn decrypt_switch_operation_response(
    operation: &SwitchOperationRow,
    allow_expired_response: bool,
) -> Result<LoginResponse, AppError> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use base64::Engine;

    if !allow_expired_response
        && operation
            .response_expires_at
            .map(|expires_at| expires_at <= utc_db_now())
            .unwrap_or(true)
    {
        return Err(AppError::from(AstralError::Auth(
            "IDEMPOTENCY_RESPONSE_EXPIRED".into(),
        )));
    }
    let ciphertext = operation.response_ciphertext.as_deref().ok_or_else(|| {
        AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RESPONSE_UNAVAILABLE".into(),
        ))
    })?;
    let mut parts = ciphertext.split('.');
    let (version, nonce, encrypted) = (parts.next(), parts.next(), parts.next());
    if version != Some("v1") || nonce.is_none() || encrypted.is_none() || parts.next().is_some() {
        return Err(AppError::from(AstralError::Auth(
            "SESSION_RESPONSE_CIPHERTEXT_INVALID".into(),
        )));
    }
    let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(nonce.unwrap())
        .map_err(|_| {
            AppError::from(AstralError::Auth(
                "SESSION_RESPONSE_CIPHERTEXT_INVALID".into(),
            ))
        })?;
    let encrypted = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encrypted.unwrap())
        .map_err(|_| {
            AppError::from(AstralError::Auth(
                "SESSION_RESPONSE_CIPHERTEXT_INVALID".into(),
            ))
        })?;
    if nonce.len() != 12 {
        return Err(AppError::from(AstralError::Auth(
            "SESSION_RESPONSE_CIPHERTEXT_INVALID".into(),
        )));
    }
    let key = session_response_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| {
        AppError::from(AstralError::Auth(
            "SESSION_RESPONSE_ENCRYPTION_KEY_INVALID".into(),
        ))
    })?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &encrypted,
                aad: operation.operation_id.as_bytes(),
            },
        )
        .map_err(|_| {
            AppError::from(AstralError::Auth(
                "SESSION_RESPONSE_CIPHERTEXT_INVALID".into(),
            ))
        })?;
    serde_json::from_slice(&plaintext).map_err(|_| {
        AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RESPONSE_UNAVAILABLE".into(),
        ))
    })
}

async fn replay_or_recover_switch_operation(
    state: &AppState,
    operation: SwitchOperationRow,
    presented_refresh_hash: &str,
) -> Result<LoginResponse, AppError> {
    match operation.status.as_str() {
        SWITCH_OPERATION_STATUS_COMPLETED => {
            validate_completed_switch_replay(state, &operation, presented_refresh_hash).await?;
            let response = decrypt_switch_operation_response(&operation, false)?;
            verify_switch_completion(state, &operation, &response, None).await?;
            Ok(response)
        }
        SWITCH_OPERATION_STATUS_FAILED => Err(AppError::from(AstralError::Auth(
            "SESSION_OPERATION_FAILED".into(),
        ))),
        SWITCH_OPERATION_STATUS_UNKNOWN => Err(AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        ))),
        SWITCH_OPERATION_STATUS_CAS_PENDING
        | SWITCH_OPERATION_STATUS_COMMITTED_PENDING_PROJECTION => {
            recover_switch_operation(state, operation, false, Some(presented_refresh_hash)).await
        }
        _ => Err(AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        ))),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum CompletedSwitchReplayDecision {
    Allow,
    RevokeFamily { family_id: i64 },
    ReconciliationRequired,
}

fn classify_completed_switch_replay(
    operation: &SwitchOperationRow,
    durable: Option<&SwitchDurableSessionRow>,
    presented_refresh_hash: &str,
) -> CompletedSwitchReplayDecision {
    let Some(durable) = durable else {
        return CompletedSwitchReplayDecision::ReconciliationRequired;
    };
    if !switch_session_is_expected(durable, operation) {
        return CompletedSwitchReplayDecision::ReconciliationRequired;
    }
    if durable.refresh_token_hash == presented_refresh_hash {
        CompletedSwitchReplayDecision::Allow
    } else {
        CompletedSwitchReplayDecision::RevokeFamily {
            family_id: durable.family_id,
        }
    }
}

async fn validate_completed_switch_replay(
    state: &AppState,
    operation: &SwitchOperationRow,
    presented_refresh_hash: &str,
) -> Result<(), AppError> {
    let durable = load_switch_durable_session(state, operation).await?;
    match classify_completed_switch_replay(operation, durable.as_ref(), presented_refresh_hash) {
        CompletedSwitchReplayDecision::Allow => Ok(()),
        CompletedSwitchReplayDecision::ReconciliationRequired => Err(AppError::from(
            AstralError::Auth("SESSION_OPERATION_RECONCILIATION_REQUIRED".into()),
        )),
        CompletedSwitchReplayDecision::RevokeFamily { family_id } => {
            if let Err(error) = revoke_token_family(state, family_id, "TOKEN_REUSE_DETECTED").await
            {
                return Err(AppError::from(AstralError::Auth(format!(
                    "TOKEN_REUSE_DETECTED; failed to revoke token family: {error}"
                ))));
            }
            Err(AppError::from(AstralError::Auth(
                "Token reuse detected. All sessions have been revoked.".into(),
            )))
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum InFlightSwitchRecoveryDecision {
    AllowOriginalRequest,
    AllowWorkerReconciliation,
    ReconciliationRequired,
}

fn classify_in_flight_switch_recovery(
    operation: &SwitchOperationRow,
    presented_refresh_hash: Option<&str>,
) -> InFlightSwitchRecoveryDecision {
    match presented_refresh_hash {
        Some(hash) if hash == operation.refresh_token_hash => {
            InFlightSwitchRecoveryDecision::AllowOriginalRequest
        }
        Some(_) => InFlightSwitchRecoveryDecision::ReconciliationRequired,
        None => InFlightSwitchRecoveryDecision::AllowWorkerReconciliation,
    }
}

async fn recover_switch_operation(
    state: &AppState,
    mut operation: SwitchOperationRow,
    allow_recovery_expired_response: bool,
    presented_refresh_hash: Option<&str>,
) -> Result<LoginResponse, AppError> {
    if matches!(
        classify_in_flight_switch_recovery(&operation, presented_refresh_hash),
        InFlightSwitchRecoveryDecision::ReconciliationRequired
    ) {
        return Err(AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        )));
    }
    let Some((claimed, claimant)) =
        claim_switch_operation_for_recovery(state, &operation.operation_id).await?
    else {
        return Err(AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        )));
    };
    operation = claimed;
    let durable = load_switch_durable_session(state, &operation).await?;
    if operation.recovery_expires_at.is_none() {
        release_switch_operation_claim(state, &operation.operation_id, &claimant).await?;
        return Err(AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        )));
    }
    if operation
        .recovery_expires_at
        .is_some_and(|expires_at| expires_at <= utc_db_now())
    {
        match durable {
            Some(ref row) if switch_session_is_expected(row, &operation) => {
                transition_switch_operation_to_projection(state, &operation, &claimant).await?;
                operation = load_switch_operation_by_id(state, &operation.operation_id)
                    .await?
                    .ok_or_else(|| {
                        AppError::from(AstralError::Auth(
                            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
                        ))
                    })?;
            }
            Some(row) if switch_session_is_previous(&row, &operation) => {
                mark_switch_operation_failed(
                    state,
                    &operation,
                    &claimant,
                    "SESSION_RECOVERY_DEADLINE_EXPIRED",
                )
                .await?;
                return Err(AppError::from(AstralError::Auth(
                    "SESSION_OPERATION_FAILED".into(),
                )));
            }
            Some(_) | None => {
                mark_switch_operation_unknown(
                    state,
                    &operation.operation_id,
                    "SESSION_RECOVERY_DEADLINE_STATE_UNPROVABLE",
                    &claimant,
                )
                .await?;
                return Err(AppError::from(AstralError::Auth(
                    "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
                )));
            }
        }
    }
    if operation.status == SWITCH_OPERATION_STATUS_CAS_PENDING {
        match durable {
            Some(ref row) if switch_session_is_expected(row, &operation) => {
                transition_switch_operation_to_projection(state, &operation, &claimant).await?;
            }
            Some(row) if switch_session_is_previous(&row, &operation) => {
                if operation.recovery_attempts >= SWITCH_OPERATION_RECOVERY_ATTEMPT_LIMIT {
                    reconcile_capped_switch_operation(state, &operation, &claimant).await?;
                } else {
                    apply_switch_cas(state, &operation, &claimant).await?;
                }
            }
            Some(_) | None => {
                let _ = mark_switch_operation_unknown(
                    state,
                    &operation.operation_id,
                    "CAS_STATE_UNPROVABLE",
                    &claimant,
                )
                .await;
                return Err(AppError::from(AstralError::Auth(
                    "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
                )));
            }
        }
    } else if durable
        .as_ref()
        .is_none_or(|row| !switch_session_is_expected(row, &operation))
    {
        let _ = mark_switch_operation_unknown(
            state,
            &operation.operation_id,
            "PROJECTION_STATE_UNPROVABLE",
            &claimant,
        )
        .await;
        return Err(AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        )));
    }
    let response =
        match decrypt_switch_operation_response(&operation, allow_recovery_expired_response) {
            Ok(response) => response,
            Err(error) => {
                if operation.recovery_attempts >= SWITCH_OPERATION_RECOVERY_ATTEMPT_LIMIT {
                    let _ = mark_switch_operation_unknown(
                        state,
                        &operation.operation_id,
                        "RECOVERY_RESPONSE_UNPROVABLE",
                        &claimant,
                    )
                    .await;
                } else {
                    let _ =
                        release_switch_operation_claim(state, &operation.operation_id, &claimant)
                            .await;
                }
                return Err(error);
            }
        };
    operation = load_switch_operation_by_id(state, &operation.operation_id)
        .await?
        .ok_or_else(|| {
            AppError::from(AstralError::Auth(
                "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
            ))
        })?;
    complete_switch_operation(state, operation, response, &claimant).await
}

/// Durable recovery entry point owned by the session worker. It intentionally
/// returns no response: the worker may only reconcile the durable state machine,
/// never create a second source mutation or expose a token to a caller.
pub(crate) async fn recover_switch_operation_from_worker(
    state: &AppState,
    operation_id: &str,
) -> Result<(), AppError> {
    let Some(operation) = load_switch_operation_by_id(state, operation_id).await? else {
        return Ok(());
    };
    if !is_recoverable_switch_operation_status(&operation.status) {
        return Ok(());
    }
    recover_switch_operation(state, operation, true, None)
        .await
        .map(|_| ())
}

async fn complete_switch_operation(
    state: &AppState,
    operation: SwitchOperationRow,
    response: LoginResponse,
    claimant: &str,
) -> Result<LoginResponse, AppError> {
    let proof = ensure_switch_jti_proof(state, &operation, &response, Some(claimant)).await?;
    restore_session_grant_projection(
        state,
        &proof.access_token,
        SessionGrant::active(
            &proof.access_token,
            proof.user_id,
            proof.session_id,
            Some(proof.identity_card_id),
            Some(proof.target_card_id),
            Some(proof.tenant_id),
            Some(proof.domain_id),
            proof.session_version,
            proof.session_epoch,
            proof.family_id,
        ),
    )
    .await
    .map_err(AppError::from)?;

    let updated = sqlx::query(
        "UPDATE auth_session_operation SET status = ?, completed_at = UTC_TIMESTAMP(), \
         recovery_claim_owner = NULL, recovery_claim_expires_at = NULL, \
         updated_at = UTC_TIMESTAMP() \
         WHERE operation_id = ? AND status = ? AND recovery_claim_owner = ? \
           AND recovery_claim_expires_at > UTC_TIMESTAMP()",
    )
    .bind(SWITCH_OPERATION_STATUS_COMPLETED)
    .bind(&operation.operation_id)
    .bind(SWITCH_OPERATION_STATUS_COMMITTED_PENDING_PROJECTION)
    .bind(claimant)
    .execute(&state.db)
    .await;
    match updated {
        Ok(result) if result.rows_affected() == 1 => Ok(response),
        Ok(_) => {
            let current = load_switch_operation_by_id(state, &operation.operation_id).await?;
            if current
                .as_ref()
                .is_some_and(|row| row.status == SWITCH_OPERATION_STATUS_COMPLETED)
            {
                verify_switch_completion(
                    state,
                    current.as_ref().unwrap(),
                    &response,
                    Some(claimant),
                )
                .await?;
                Ok(response)
            } else {
                let _ = mark_switch_operation_unknown(
                    state,
                    &operation.operation_id,
                    "OPERATION_COMPLETION_UNKNOWN",
                    claimant,
                )
                .await;
                Err(AppError::from(AstralError::Auth(
                    "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
                )))
            }
        }
        Err(error) => {
            let _ = mark_switch_operation_unknown(
                state,
                &operation.operation_id,
                "OPERATION_COMPLETION_UNKNOWN",
                claimant,
            )
            .await;
            Err(AppError::from(AstralError::Database(format!(
                "Complete switch operation failed: {error}"
            ))))
        }
    }
}

async fn ensure_switch_jti_proof(
    state: &AppState,
    operation: &SwitchOperationRow,
    response: &LoginResponse,
    claimant: Option<&str>,
) -> Result<SwitchResponseProof, AppError> {
    let (claims, token_use) =
        decode_v2_token(&response.access_token, &state.config).map_err(|_| {
            AppError::from(AstralError::Auth(
                "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
            ))
        })?;
    let operation_family_id = load_switch_operation_family_id(operation, state).await?;
    if token_use != TokenUse::Access
        || claims.principal_kind != PrincipalKind::PlatformUser.as_str()
        || claims.sub.parse::<i64>().ok() != Some(operation.user_id)
        || claims.sid != operation.session_id
        || claims.family_id != Some(operation_family_id)
        || claims.identity_card_id != operation.selected_identity_card_id
        || claims.user_card_id != operation.target_card_id
        || claims.session_version != operation.expected_session_version
        || claims.sev != operation.expected_session_epoch
    {
        let _ = mark_switch_operation_unknown(
            state,
            &operation.operation_id,
            "ACCESS_PROOF_BINDING_MISMATCH",
            claimant.unwrap_or_default(),
        )
        .await;
        return Err(AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        )));
    }
    let identity_card_id = operation.selected_identity_card_id.ok_or_else(|| {
        AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        ))
    })?;
    let target_card_id = operation.target_card_id.ok_or_else(|| {
        AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        ))
    })?;
    let session_id = operation.session_id.ok_or_else(|| {
        AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        ))
    })?;
    let expected_session_epoch = operation.expected_session_epoch.ok_or_else(|| {
        AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        ))
    })?;
    let session = load_switch_durable_session(state, operation)
        .await?
        .filter(|row| switch_session_is_expected(row, operation))
        .ok_or_else(|| {
            AppError::from(AstralError::Auth(
                "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
            ))
        })?;
    delete_session_projections_before_epoch(state, session.session_id, expected_session_epoch)
        .await
        .map_err(AppError::from)?;

    let token = TokenResult {
        token: response.access_token.clone(),
        jti: claims.jti.clone(),
        expires_in: claims.exp as i64 - OffsetDateTime::now_utc().unix_timestamp(),
        issued_at_epoch_second: claims.iat as i64,
        expires_at_epoch_second: claims.exp as i64,
    };
    if let Err(error) = record_platform_session_jti_proof(
        state,
        &token,
        operation.user_id,
        session_id,
        expected_session_epoch,
        identity_card_id,
    )
    .await
    {
        let existing: Option<(i64,)> = sqlx::query_as(
            "SELECT jti_id FROM auth_session_jti_index WHERE session_id = ? AND user_id = ? \
             AND jti = ? AND session_epoch = ? AND status = 'ACTIVE' LIMIT 1",
        )
        .bind(session_id)
        .bind(operation.user_id)
        .bind(&claims.jti)
        .bind(expected_session_epoch)
        .fetch_optional(&state.db)
        .await
        .map_err(|query_error| {
            AstralError::Database(format!(
                "Verify switch JTI after proof error failed: {query_error}; original: {error}"
            ))
        })?;
        if existing.is_none() {
            let _ = mark_switch_operation_unknown(
                state,
                &operation.operation_id,
                "ACCESS_PROOF_UNPROVABLE",
                claimant.unwrap_or_default(),
            )
            .await;
            return Err(AppError::from(AstralError::Auth(
                "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
            )));
        }
    }

    let tenant_domain: Option<(i64, i64)> = sqlx::query_as(
        "SELECT uc.tenant_id, uc.domain_id FROM user_card uc \
         INNER JOIN tenant t ON t.tenant_id = uc.tenant_id AND t.status = 'ACTIVE' \
         INNER JOIN tenant_domain_map tdm ON tdm.tenant_id = uc.tenant_id \
           AND tdm.domain_id = uc.domain_id AND tdm.status = 'ACTIVE' \
         WHERE uc.card_id = ? AND uc.user_id = ? AND uc.card_status = 'ACTIVE' \
           AND uc.tenant_id > 0 AND uc.domain_id > 0 LIMIT 1",
    )
    .bind(target_card_id)
    .bind(operation.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| AstralError::Database(format!("Load switch card scope failed: {error}")))?;
    let (tenant_id, domain_id) = tenant_domain.ok_or_else(|| {
        AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        ))
    })?;
    if claims.user_card_tenant_id != Some(tenant_id)
        || claims.user_card_domain_id != Some(domain_id)
    {
        let _ = mark_switch_operation_unknown(
            state,
            &operation.operation_id,
            "ACCESS_SCOPE_BINDING_MISMATCH",
            claimant.unwrap_or_default(),
        )
        .await;
        return Err(AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
        )));
    }

    Ok(SwitchResponseProof {
        access_token: token,
        user_id: operation.user_id,
        session_id,
        family_id: session.family_id,
        identity_card_id,
        target_card_id,
        tenant_id,
        domain_id,
        session_version: operation.expected_session_version.ok_or_else(|| {
            AppError::from(AstralError::Auth(
                "SESSION_OPERATION_RECONCILIATION_REQUIRED".into(),
            ))
        })?,
        session_epoch: expected_session_epoch,
    })
}

async fn verify_switch_completion(
    state: &AppState,
    operation: &SwitchOperationRow,
    response: &LoginResponse,
    claimant: Option<&str>,
) -> Result<(), AppError> {
    let _ = ensure_switch_jti_proof(state, operation, response, claimant).await?;
    Ok(())
}

/// Re-project a previously proven access credential (switch-card recovery).
///
/// Durable proof is written by the caller (`auth_session_jti_index`); this
/// function only installs the verified process-local acceleration mirror.
async fn restore_session_grant_projection(
    state: &AppState,
    token: &TokenResult,
    grant: SessionGrant,
) -> Result<(), AstralError> {
    install_verified_session_grant_mirror(state, token, &grant);
    Ok(())
}

fn request_header_text(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn switch_requires_refresh_bearer_and_idempotency_key() {
        let empty = HeaderMap::new();
        assert!(bearer_token(&empty).is_none());
        assert!(required_idempotency_key(&empty).is_err());

        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer refresh.jwt".parse().unwrap());
        headers.insert("idempotency-key", "switch-1".parse().unwrap());
        assert_eq!(bearer_token(&headers), Some("refresh.jwt"));
        assert_eq!(required_idempotency_key(&headers).unwrap(), "switch-1");
    }

    #[test]
    fn switch_request_hash_binds_source_target_and_credentials() {
        let baseline = switch_request_hash(7, 11, 13, "jti-a", "refresh-hash", Some("device-a"));
        assert_ne!(
            baseline,
            switch_request_hash(7, 11, 14, "jti-a", "refresh-hash", Some("device-a"))
        );
        assert_ne!(
            baseline,
            switch_request_hash(7, 12, 13, "jti-a", "refresh-hash", Some("device-a"))
        );
        assert_ne!(
            baseline,
            switch_request_hash(7, 11, 13, "jti-b", "refresh-hash", Some("device-a"))
        );
        assert_ne!(
            baseline,
            switch_request_hash(7, 11, 13, "jti-a", "refresh-hash", Some("device-b"))
        );
    }

    #[test]
    fn switch_operation_recovery_state_set_is_v6_only() {
        assert_eq!(
            SWITCH_OPERATION_STATUS_NAMES,
            [
                "CAS_PENDING",
                "COMMITTED_PENDING_PROJECTION",
                "COMPLETED",
                "FAILED",
                "UNKNOWN"
            ]
        );
        assert!(is_recoverable_switch_operation_status(
            SWITCH_OPERATION_STATUS_CAS_PENDING
        ));
        assert!(is_recoverable_switch_operation_status(
            SWITCH_OPERATION_STATUS_COMMITTED_PENDING_PROJECTION
        ));
        for status in [
            "PENDING",
            "COMPLETED",
            "FAILED",
            "UNKNOWN",
            "COMMITTED_PENDING_REDIS",
        ] {
            assert!(!is_recoverable_switch_operation_status(status));
        }
    }

    #[test]
    fn completed_switch_replay_allows_only_the_current_refresh_hash() {
        let operation = switch_operation_fixture("new-refresh");
        let durable = switch_durable_session_fixture("new-refresh");
        assert_eq!(
            classify_completed_switch_replay(&operation, Some(&durable), "new-refresh"),
            CompletedSwitchReplayDecision::Allow
        );
        assert_eq!(
            classify_completed_switch_replay(&operation, Some(&durable), "old-refresh"),
            CompletedSwitchReplayDecision::RevokeFamily { family_id: 77 }
        );
        assert_eq!(
            classify_completed_switch_replay(&operation, None, "new-refresh"),
            CompletedSwitchReplayDecision::ReconciliationRequired
        );
    }

    #[test]
    fn in_flight_switch_recovery_accepts_only_original_bearer_or_worker_proof() {
        let operation = switch_operation_fixture("new-refresh");
        assert_eq!(
            classify_in_flight_switch_recovery(&operation, Some("old-refresh")),
            InFlightSwitchRecoveryDecision::AllowOriginalRequest
        );
        assert_eq!(
            classify_in_flight_switch_recovery(&operation, Some("new-refresh")),
            InFlightSwitchRecoveryDecision::ReconciliationRequired
        );
        assert_eq!(
            classify_in_flight_switch_recovery(&operation, None),
            InFlightSwitchRecoveryDecision::AllowWorkerReconciliation
        );
    }

    #[test]
    fn switch_replay_source_checks_current_hash_and_recovery_fences() {
        let source = include_str!("session.rs");
        let switch_body = source
            .split("pub(crate) async fn switch_card_session(")
            .nth(1)
            .and_then(|tail| tail.split("fn required_idempotency_key").next())
            .expect("switch session body must stay bounded");
        assert!(switch_body.contains("load_active_session_context("));
        assert!(switch_body.contains("TOKEN_REUSE_DETECTED"));
        assert!(switch_body.contains("operation.status != SWITCH_OPERATION_STATUS_COMPLETED"));
        assert!(switch_body.contains("validate_switch_recovery_context"));
        let stale_refresh_body = source
            .split("async fn load_current_refresh_session_or_revoke_reuse(")
            .nth(1)
            .and_then(|tail| tail.split("/// logout/revoke 共用的凭证前置门").next())
            .expect("stale refresh helper must remain bounded");
        assert!(stale_refresh_body.contains("session_version"));
        assert!(stale_refresh_body.contains("session_epoch"));
        assert!(stale_refresh_body.contains("current.refresh_token_hash != refresh_hash"));
        assert!(stale_refresh_body.contains("TOKEN_REUSE_DETECTED"));
        assert!(source.contains("revoke_logout_refresh(&state, raw"));
        let replay_body = source
            .split("async fn replay_or_recover_switch_operation(")
            .nth(1)
            .and_then(|tail| {
                tail.split("async fn validate_completed_switch_replay")
                    .next()
            })
            .expect("replay helper must stay bounded");
        assert!(replay_body.contains("presented_refresh_hash"));
        assert!(replay_body.contains(
            "recover_switch_operation(state, operation, false, Some(presented_refresh_hash))"
        ));
        let recovery_body = source
            .split("async fn recover_switch_operation(")
            .nth(1)
            .and_then(|tail| {
                tail.split("/// Durable recovery entry point owned by the session worker")
                    .next()
            })
            .expect("recovery helper must remain bounded");
        assert!(recovery_body
            .contains("classify_in_flight_switch_recovery(&operation, presented_refresh_hash)"));
        assert!(recovery_body.contains("presented_refresh_hash: Option<&str>"));
        assert!(source.contains("recover_switch_operation(state, operation, true, None)"));
        let claim_body = source
            .split("async fn claim_switch_operation(")
            .nth(1)
            .and_then(|tail| {
                tail.split("async fn claim_switch_operation_for_recovery")
                    .next()
            })
            .expect("claim helper must stay bounded");
        assert!(claim_body.contains("recovery_expires_at IS NOT NULL"));
        let release_body = source
            .split("async fn release_switch_operation_claim(")
            .nth(1)
            .and_then(|tail| tail.split("async fn mark_switch_operation_failed").next())
            .expect("release helper must stay bounded");
        assert!(release_body.contains("recovery_claim_owner = ?"));
        assert!(release_body.contains("recovery_claim_expires_at > UTC_TIMESTAMP()"));
        let failed_body = source
            .split("async fn mark_switch_operation_failed(")
            .nth(1)
            .and_then(|tail| tail.split("async fn mark_switch_operation_unknown").next())
            .expect("failed transition must stay bounded");
        assert!(failed_body.contains("status IN (?, ?)"));
    }

    fn switch_operation_fixture(refresh_hash: &str) -> SwitchOperationRow {
        SwitchOperationRow {
            operation_id: "operation-a".into(),
            user_id: 7,
            request_hash: "request".into(),
            refresh_token_hash: "old-refresh".into(),
            source_card_id: Some(11),
            target_card_id: Some(13),
            session_id: Some(55),
            selected_identity_card_id: Some(66),
            previous_session_version: Some(1),
            previous_session_epoch: Some(1),
            expected_session_version: Some(2),
            expected_session_epoch: Some(2),
            device_id: Some("device".into()),
            new_refresh_token_hash: Some(refresh_hash.into()),
            new_refresh_expires_at: None,
            status: SWITCH_OPERATION_STATUS_COMPLETED.into(),
            response_ciphertext: None,
            response_expires_at: None,
            recovery_expires_at: None,
            recovery_attempts: 0,
            recovery_claim_owner: None,
            recovery_claim_expires_at: None,
            last_error: None,
        }
    }

    fn switch_durable_session_fixture(refresh_hash: &str) -> SwitchDurableSessionRow {
        SwitchDurableSessionRow {
            session_id: 55,
            user_id: 7,
            family_id: 77,
            current_user_card_id: Some(13),
            session_state: "ACTIVE".into(),
            session_version: 2,
            session_epoch: 2,
            refresh_token_hash: refresh_hash.into(),
            status: "ACTIVE".into(),
        }
    }
    #[test]
    fn session_response_key_requires_base64_encoded_256_bit_key() {
        let _guard = session_response_env_lock().lock().unwrap();
        unsafe { std::env::remove_var("IDENTITY_SESSION_RESPONSE_AES_GCM_KEY") };
        assert!(session_response_key().is_err());

        unsafe {
            std::env::set_var(
                "IDENTITY_SESSION_RESPONSE_AES_GCM_KEY",
                base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
            )
        };
        assert_eq!(session_response_key().unwrap(), [7u8; 32]);
        unsafe { std::env::remove_var("IDENTITY_SESSION_RESPONSE_AES_GCM_KEY") };
    }

    #[test]
    fn encrypted_switch_replay_is_bound_to_operation_id() {
        let _guard = session_response_env_lock().lock().unwrap();

        unsafe {
            std::env::set_var(
                "IDENTITY_SESSION_RESPONSE_AES_GCM_KEY",
                base64::engine::general_purpose::STANDARD.encode([9u8; 32]),
            )
        };
        let response = LoginResponse {
            access_token: "access".into(),
            refresh_token: "refresh".into(),
            token_type: "Bearer".into(),
            expires_in_millis: 1_000,
            refresh_expires_in_millis: 2_000,
            user: None,
            current_card: None,
            available_cards: None,
            permissions: Some(vec![]),
            roles: Some(vec!["USER".into()]),
            enterprises: Some(vec![]),
            session: Some(serde_json::json!({
                "sessionId": 1,
                "familyId": 2,
                "sessionVersion": 3,
                "sessionEpoch": 4,
                "sessionState": "ACTIVE",
                "currentUserCardId": 5,
            })),
        };
        let ciphertext = encrypt_operation_response("operation-a", &response).unwrap();
        let operation = SwitchOperationRow {
            operation_id: "operation-a".into(),
            user_id: 7,
            request_hash: "request".into(),
            refresh_token_hash: "refresh".into(),
            source_card_id: Some(1),
            target_card_id: Some(5),
            session_id: Some(1),
            selected_identity_card_id: Some(2),
            previous_session_version: Some(2),
            previous_session_epoch: Some(3),
            expected_session_version: Some(3),
            expected_session_epoch: Some(4),
            device_id: None,
            new_refresh_token_hash: Some("new-refresh".into()),
            new_refresh_expires_at: response_expiry().ok(),
            status: "COMPLETED".into(),
            response_ciphertext: Some(ciphertext),
            response_expires_at: response_expiry().ok(),
            recovery_expires_at: response_expiry().ok(),
            recovery_attempts: 0,
            recovery_claim_owner: None,
            recovery_claim_expires_at: None,
            last_error: None,
        };
        assert_eq!(
            decrypt_switch_operation_response(&operation, false)
                .unwrap()
                .access_token,
            "access"
        );
        let wrong_operation = SwitchOperationRow {
            operation_id: "operation-b".into(),
            ..operation
        };
        assert!(decrypt_switch_operation_response(&wrong_operation, false).is_err());
        unsafe { std::env::remove_var("IDENTITY_SESSION_RESPONSE_AES_GCM_KEY") };
    }

    fn session_response_env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    #[test]
    fn logout_requires_a_credential() {
        // The handler-level gate (not a duplicate bearer_token unit check):
        // anything but a non-empty Bearer credential is BEARER_REQUIRED and
        // no later stage (db lookup, token decode, revocation) is reached.
        assert!(logout_bearer_credential(&HeaderMap::new()).is_err());
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Basic dXNlcjpwYXNz".parse().unwrap());
        assert!(logout_bearer_credential(&headers).is_err());
        headers.insert("authorization", "Bearer ".parse().unwrap());
        assert!(logout_bearer_credential(&headers).is_err());
        headers.insert("authorization", "Bearer token-1".parse().unwrap());
        let credential = logout_bearer_credential(&headers).expect("valid bearer");
        assert_eq!(credential, "token-1");
        // The rejection carries the contract error, not a generic failure.
        let error = logout_bearer_credential(&HeaderMap::new()).unwrap_err();
        assert!(error.to_string().contains("BEARER_REQUIRED"));
    }

    #[test]
    fn logout_accepts_only_bearer_access_header() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer access.jwt".parse().unwrap());
        assert_eq!(bearer_token(&headers), Some("access.jwt"));
        headers.insert("authorization", "Basic access.jwt".parse().unwrap());
        assert!(bearer_token(&headers).is_none());
    }

    #[test]
    fn refresh_requires_persisted_positive_family_id() {
        assert!(!is_refresh_family_id_valid(0));
        assert!(!is_refresh_family_id_valid(-1));
        assert!(is_refresh_family_id_valid(1));
    }

    #[test]
    fn unknown_family_status_is_not_refreshable() {
        assert!(
            matches!(family_status("SUSPENDED"), FamilyStatus::Unknown(status) if status == "SUSPENDED")
        );
        assert!(!matches!(family_status("SUSPENDED"), FamilyStatus::Active));
    }

    #[test]
    fn refresh_rotation_requires_exactly_one_row() {
        assert!(rotation_succeeded(1));
        assert!(!rotation_succeeded(0));
        assert!(!rotation_succeeded(2));
    }

    #[tokio::test]
    async fn family_database_failure_is_an_error() {
        let db = sqlx::MySqlPool::connect_lazy("mysql://localhost:1/identity")
            .expect("lazy pool construction should succeed");
        let result = check_family_valid(&db, 1).await;
        assert!(matches!(result, Err(AstralError::Database(_))));
    }

    /// 通过同一个 V6 source transaction 完成会话撤销、JTI proof 关闭、父 outbox 和 typed shard intent；
    /// commit 被证明后才安装本地 deny 加速。
    #[test]
    fn revocation_transaction_source_shape_holds_fence_and_durable_order() {
        let source = include_str!("session.rs");
        let body = source
            .split("async fn revoke_transaction(")
            .nth(1)
            .expect("revoke_transaction must stay")
            .split("async fn lock_revocation_snapshot(")
            .next()
            .expect("revocation transaction body must be bounded");
        let ordered = [
            "source_writer_guard::begin_source_write()",
            "state.db.begin()",
            "lock_revocation_snapshot(&mut tx, target)",
            "INSERT INTO auth_session_outbox",
            "append_session_revocation_shards_in_tx(",
            "source_writer_guard::arm_commit_fence(&source_guard)",
            "tx.commit().await",
            "source_writer_guard::settle_commit_fence(&source_guard, true)",
            "astral_db::note_revocations_in_process(",
        ];
        let positions = ordered
            .iter()
            .map(|needle| {
                body.find(needle)
                    .unwrap_or_else(|| panic!("missing {needle}"))
            })
            .collect::<Vec<_>>();
        let mirror = body
            .rfind("astral_db::note_revocations_in_process(")
            .expect("post-commit mirror installation must stay after the commit fence");
        assert!(positions[..positions.len() - 1]
            .windows(2)
            .all(|pair| pair[0] < pair[1]));
        assert!(positions[positions.len() - 2] < mirror);
        for mutation in [
            "UPDATE auth_session_jti_index SET status = 'DELETED'",
            "UPDATE auth_device_session SET status = 'REVOKED'",
            "UPDATE auth_token_family SET status = 'REVOKED'",
        ] {
            assert!(
                body.contains(mutation),
                "missing durable mutation {mutation}"
            );
        }
        assert!(body.contains("typedShards"));
        assert!(body.contains("WHERE operation_id = ? AND sequence_number = 1 FOR UPDATE"));
        assert!(body.contains("SESSION_REVOCATION_IDEMPOTENCY_CONFLICT"));
        assert!(!body.contains("session_repo::revoke_"));
    }

    #[test]
    fn revocation_lock_order_is_outbox_then_user_family_session_jti() {
        let source = include_str!("session.rs");
        let transaction = source
            .split("async fn revoke_transaction(")
            .nth(1)
            .and_then(|tail| tail.split("async fn lock_revocation_snapshot(").next())
            .expect("revocation transaction body must remain bounded");
        let outbox = transaction
            .find("WHERE operation_id = ? AND sequence_number = 1 FOR UPDATE")
            .expect("idempotency outbox row must be locked first");
        let snapshot_call = transaction
            .find("lock_revocation_snapshot(&mut tx, target)")
            .expect("revocation transaction must use the shared lock helper");
        assert!(outbox < snapshot_call);

        let snapshot_start = source
            .find("async fn lock_revocation_snapshot(")
            .expect("revocation snapshot helper must remain");
        let snapshot_end = source[snapshot_start..]
            .find("\nfn bounded_revocation_jtis")
            .map(|offset| snapshot_start + offset)
            .expect("revocation snapshot helper must remain bounded");
        let snapshot = &source[snapshot_start..snapshot_end];
        let user_branch = snapshot
            .find("RevocationTarget::User { user_id } => {")
            .map(|offset| &snapshot[offset..])
            .expect("user revocation snapshot branch must remain");
        let user = user_branch
            .find("SELECT user_id FROM platform_user")
            .expect("user aggregate must be locked");
        let family = user_branch
            .find("SELECT family_id FROM auth_token_family")
            .expect("token families must be locked");
        let sessions = user_branch
            .find("SELECT session_id FROM auth_device_session")
            .expect("device sessions must be locked");
        let jtis = user_branch
            .find("SELECT jti FROM auth_session_jti_index")
            .expect("JTI snapshot must be locked");
        assert!(user < family && family < sessions && sessions < jtis);
    }

    #[test]
    fn switch_completion_closes_prior_epoch_proofs_before_new_proof() {
        let source = include_str!("session.rs");
        let body = source
            .split("async fn ensure_switch_jti_proof(")
            .nth(1)
            .expect("switch proof helper must stay")
            .split("async fn verify_switch_completion(")
            .next()
            .expect("switch proof body must be bounded");
        let close = body
        .find("delete_session_projections_before_epoch(state, session.session_id, expected_session_epoch)")
        .expect("switch proof must close prior epoch proofs");
        let record = body
            .find("record_platform_session_jti_proof(")
            .expect("switch proof must record the new durable proof");
        assert!(close < record);
    }

    #[test]
    fn switch_unknown_cas_reconciles_durable_session_before_unknown() {
        let source = include_str!("session.rs");
        let body = source
            .split("let rotation = match rotation {")
            .nth(1)
            .expect("switch CAS result branch must stay")
            .split("if rotation.rows_affected() != 1")
            .next()
            .expect("switch CAS result branch must be bounded");
        assert!(body.contains("load_switch_durable_session(state, operation).await?"));
        assert!(body.contains("switch_session_is_expected(&row, operation)"));
        assert!(body.contains("switch_session_is_previous(&row, operation)"));
        assert!(body.contains("CAS_OUTCOME_UNPROVABLE"));
        assert!(!body.contains("CAS_OUTCOME_UNKNOWN"));
    }
}
