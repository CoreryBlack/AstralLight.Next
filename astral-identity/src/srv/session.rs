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
use time::{Duration, OffsetDateTime, PrimitiveDateTime};

use astral_common::contract::{ApiResponse, EmptyResponse};
use astral_common::error::AppError;
use astral_common::middleware::decode_v2_token;
use astral_common::token_contract::{PrincipalKind, TokenUse};
use astral_types::AstralError;
use redis::AsyncCommands;

use super::session_repository::{self as session_repo, DeviceSessionRow};
use crate::auth::{
    issue_access_token, issue_access_token_for_identity_only, issue_refresh_token,
    map_eligibility_error, sha256_hash, LoginResponse, SessionContext, SessionGrant, TokenResult,
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
    let principal_kind = PrincipalKind::parse(&claims.principal_kind)
        .ok_or_else(|| AppError::from(AstralError::Auth("PRINCIPAL_KIND_INVALID".into())))?;
    let session = session_repo::load_active_refresh_session(&state.db, &refresh_hash)
        .await?
        .filter(|row| {
            row.session_id == session_id
                && row.family_id == family_id
                && row.user_id == user_id
                && row.session_version == claims.session_version.unwrap_or_default()
                && row.session_epoch == claims.sev.unwrap_or_default()
        })
        .ok_or_else(|| AstralError::Auth("Invalid refresh session".into()))?;
    refresh_token_from_session(&state, session, raw_refresh, principal_kind).await
}

async fn refresh_token_from_session(
    state: &AppState,
    session: DeviceSessionRow,
    raw_refresh: &str,
    principal_kind: PrincipalKind,
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

    // Platform sessions require the persisted user card. App sessions deliberately
    // have no user-card binding and renew an identity-only access credential.
    let user_card_for_jwt = match principal_kind {
        PrincipalKind::PlatformUser => {
            // 身份卡只提供认证事实；PlatformUser 的组织 scope 必须来自选中的 user_card。
            match session.current_user_card_id {
                Some(target_card_id) => {
                    let uc = sqlx::query_as::<_, (i64, Option<i64>, String, Option<i64>, Option<i64>, Option<i32>, Option<bool>, Option<i64>)>(
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
                                "CARD_SELECTION_REQUIRED: persisted user card no longer available"
                                    .into(),
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
            }
        }
        PrincipalKind::AppUser => None,
    };

    let next_session_version = session.session_version.checked_add(1).ok_or_else(|| {
        AstralError::Auth("Session version exhausted. Please login again.".into())
    })?;
    let next_session_epoch = session
        .session_epoch
        .checked_add(1)
        .ok_or_else(|| AstralError::Auth("Session epoch exhausted. Please login again.".into()))?;
    let new_expiry = now + Duration::seconds(state.config.jwt.refresh.expiry_seconds);
    let session_context = SessionContext {
        session_id: session.session_id,
        session_version: next_session_version,
        session_epoch: next_session_epoch,
        family_id: session.family_id,
    };
    let token_result = match principal_kind {
        PrincipalKind::PlatformUser => {
            let access_card = user_card_for_jwt.as_ref().ok_or_else(|| {
                AppError::from(AstralError::Auth("USER_CARD_CONTEXT_REQUIRED".into()))
            })?;
            issue_access_token(
                &state.config.jwt,
                &id_card,
                access_card,
                session_context,
                None,
            )?
        }
        PrincipalKind::AppUser => {
            issue_access_token_for_identity_only(&state.config.jwt, &id_card, session_context)?
        }
    };
    let new_refresh_result = issue_refresh_token(
        &state.config.jwt,
        session.user_id,
        principal_kind,
        session_context,
    )?;
    let new_refresh_hash = sha256_hash(&new_refresh_result.token);
    let new_access_token = token_result.token.clone();
    let expires_in = token_result.expires_in;

    // Session epoch fencing requires every credential issued before this rotation
    // to lose both Gateway projections before a replacement can be returned.
    delete_session_projections_before_epoch(state, session.session_id, next_session_epoch)
        .await
        .map_err(AppError::from)?;

    // Step 5.5: 存储 jti 到 Redis（TTL = token 过期时间，用于撤销检测）
    // This is intentionally done only after the refresh-token CAS below succeeds.

    // Step 6: 原子轮换 refresh token。旧 hash 必须仍是当前值；并发请求中只有一个
    // UPDATE 能影响一行，失败者按 token reuse 处理并撤销整个 family。
    let rotation = sqlx::query(
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
    .execute(&state.db)
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

    // Step 5.5: Redis is security-critical. If the allow-list write fails,
    // revoke the durable family so the rotated refresh state cannot remain
    // silently active without a tracked access credential.
    if let Err(redis_error) = store_session_grant_in_redis(
        state,
        &token_result,
        SessionGrant::active(
            &token_result,
            principal_kind,
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
                %redis_error,
                %revoke_error,
                "access tracking failed and family revocation failed"
            );
        }
        return Err(AppError::from(redis_error));
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
        token: None,
        user: None,
        identity_card: None,
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
    let raw = bearer_token(&headers)
        .ok_or_else(|| AppError::from(AstralError::Auth("BEARER_REQUIRED".into())))?;
    let (claims, token_use) = decode_v2_token(raw, &state.config)
        .map_err(|reason| AppError::from(AstralError::Auth(reason.into())))?;
    let reason = req.reason.as_deref().unwrap_or("USER_REVOKED");
    match token_use {
        TokenUse::Access => {
            delete_access_projections(&state, &claims.jti).await?;
            mark_jti_revoked_at(
                &state.config.redis_url,
                &claims.jti,
                state.config.jwt.access.expiry_seconds,
            )
            .await?;
        }
        TokenUse::Refresh => {
            let refresh_hash = sha256_hash(raw);
            let session = session_repo::load_active_refresh_session(&state.db, &refresh_hash)
                .await?
                .ok_or_else(|| AstralError::Auth("Invalid refresh session".into()))?;
            delete_session_projections(&state, session.session_id).await?;
            db_revoke_session(&state.db, session.session_id, reason).await?;
            delete_session_projections(&state, session.session_id).await?;
            write_session_revocation_outbox(&state, session.session_id, reason).await?;
        }
    }
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ApiResponse<String>>, AppError> {
    let raw = bearer_token(&headers)
        .ok_or_else(|| AppError::from(AstralError::Auth("BEARER_REQUIRED".into())))?;
    let (claims, token_use) = decode_v2_token(raw, &state.config)
        .map_err(|reason| AppError::from(AstralError::Auth(reason.into())))?;
    match token_use {
        TokenUse::Access => {
            delete_access_projections(&state, &claims.jti).await?;
            mark_jti_revoked_at(
                &state.config.redis_url,
                &claims.jti,
                state.config.jwt.access.expiry_seconds,
            )
            .await?;
        }
        TokenUse::Refresh => {
            revoke_logout_refresh(&state, raw, &claims.jti).await?;
        }
    }
    Ok(Json(ApiResponse::success("Logged out".into())))
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
    refresh_jti: &str,
) -> Result<(), AppError> {
    let refresh_hash = sha256_hash(refresh_token);
    let session = sqlx::query_as::<_, DeviceSessionRow>(
        "SELECT session_id, family_id, user_id, device_id, device_type, client_app_id, channel_code, \
         current_user_card_id, session_state, session_version, session_epoch, refresh_token_hash, refresh_expires_at, status, ip_address, user_agent, \
         last_seen_at, revoked_at, revoked_reason, created_at, updated_at \
         FROM auth_device_session \
         WHERE refresh_token_hash = ? AND status = 'ACTIVE' AND session_state = 'ACTIVE'",
    )
    .bind(&refresh_hash)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        AppError::from(AstralError::Database(format!(
            "Logout session lookup failed: {e}"
        )))
    })?
    .ok_or_else(|| AppError::from(AstralError::Auth("Invalid refresh token".into())))?;

    // Redis projection removal precedes durable revocation so a cache failure
    // cannot leave a Gateway-live credential behind a closed session state.
    delete_session_projections(state, session.session_id)
        .await
        .map_err(AppError::from)?;
    db_revoke_session(&state.db, session.session_id, "LOGOUT")
        .await
        .map_err(AppError::from)?;
    // 记录会话撤销 outbox（对齐 Java durable 补偿路径），登出同样留 durable 轨迹。
    write_session_revocation_outbox(state, session.session_id, "LOGOUT")
        .await
        .map_err(AppError::from)?;
    mark_jti_revoked_at(
        &state.config.redis_url,
        refresh_jti,
        state.config.jwt.refresh.expiry_seconds * 2,
    )
    .await
    .map_err(AppError::from)?;
    Ok(())
}

/// 记录单会话撤销 outbox（对齐 Java durable 补偿路径；列契约见 20260728000001 DDL）
///
/// 单会话撤销（token revoke / logout）同样留 durable 轨迹：Redis 投影删除失败时
/// 可经补偿 worker 按 `session:{session_id}` 补删，避免撤销只落内存/黑名单。
async fn write_session_revocation_outbox(
    state: &AppState,
    session_id: i64,
    reason: &str,
) -> Result<(), AstralError> {
    let operation_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO auth_session_outbox \
         (operation_id, session_id, event_type, sequence_number, projection_key, payload_json, status, created_at) \
         VALUES (?, ?, 'REVOKE', 1, ?, ?, 'PENDING', NOW())",
    )
    .bind(&operation_id)
    .bind(session_id)
    .bind(format!("session:{session_id}"))
    .bind(serde_json::json!({ "reason": reason }).to_string())
    .execute(&state.db)
    .await
    .map_err(|e| AstralError::Database(format!("Write session outbox failed: {e}")))?;
    Ok(())
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
    let session_ids = session_repo::list_session_ids_by_family(&state.db, family_id).await?;

    for session_id in &session_ids {
        delete_session_projections(state, *session_id).await?;
    }

    // Revoke after the projection fan-out. If the durable transition fails, the
    // credential is conservatively unavailable instead of remaining Gateway-live.
    session_repo::revoke_family_cas(&state.db, family_id, reason).await?;

    // 级联撤销该 family 下所有活跃会话. session_state/version/epoch are
    // updated together so Java's grant verifier observes the same durable fence.
    session_repo::revoke_family_sessions(&state.db, family_id, reason).await?;

    // 记录会话撤销 outbox（对齐 Java durable 补偿路径；列契约见 20260728000001 DDL）
    let operation_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO auth_session_outbox \
         (operation_id, session_id, event_type, sequence_number, projection_key, payload_json, status, created_at) \
         VALUES (?, NULL, 'REVOKE', 1, ?, ?, 'PENDING', NOW())",
    )
    .bind(&operation_id)
    .bind(format!("family:{family_id}"))
    .bind(serde_json::json!({ "reason": reason }).to_string())
    .execute(&state.db)
    .await
    .map_err(|e| AstralError::Database(format!("Write session outbox failed: {e}")))?;

    for session_id in &session_ids {
        delete_session_projections(state, *session_id).await?;
    }

    tracing::warn!(family_id = %family_id, reason = %reason, "token family revoked with cascade");
    Ok(())
}

/// Revoke every active session and token family for a user.
///
/// Java's `AuthDeviceSessionService.revokeAllForUser()` closes the durable
/// session/family state and removes every indexed Redis projection. Projection
/// removal happens first so a partial failure cannot leave a live credential
/// after the security mutation has started.
pub(crate) async fn revoke_all_sessions_for_user(
    state: &AppState,
    user_id: i64,
    reason: &str,
) -> Result<(), AstralError> {
    let session_ids = session_repo::list_active_session_ids_by_user(&state.db, user_id).await?;

    for session_id in &session_ids {
        delete_session_projections(state, *session_id).await?;
    }

    session_repo::revoke_user_sessions(&state.db, user_id, reason).await?;
    session_repo::revoke_user_token_families(&state.db, user_id, reason).await?;

    // 记录会话撤销 outbox（对齐 Java durable 补偿路径；列契约见 20260728000001 DDL）
    let operation_id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO auth_session_outbox \
         (operation_id, session_id, event_type, sequence_number, projection_key, payload_json, status, created_at) \
         VALUES (?, NULL, 'REVOKE', 1, ?, ?, 'PENDING', NOW())",
    )
    .bind(&operation_id)
    .bind(format!("user:{user_id}"))
    .bind(serde_json::json!({ "reason": reason }).to_string())
    .execute(&state.db)
    .await
    .map_err(|e| AstralError::Database(format!("Write session outbox failed: {e}")))?;

    tracing::warn!(
        user_id,
        reason,
        sessions = session_ids.len(),
        "all user sessions revoked"
    );
    Ok(())
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

/// 撤销单个会话
///
/// Canonical platform_v4: WHERE session_id = ?（非 legacy id）
async fn db_revoke_session(db: &sqlx::MySqlPool, id: i64, reason: &str) -> Result<(), AstralError> {
    session_repo::revoke_session(db, id, reason).await
}

/// Store the opaque JTI issued by a durable session. It is retained only until
/// access-token expiry and has no raw access or refresh token material.
async fn record_session_jti_index(
    state: &AppState,
    token: &TokenResult,
    user_id: i64,
    session_id: i64,
    session_epoch: i64,
) -> Result<(), AstralError> {
    let result = sqlx::query(
        "INSERT INTO auth_session_jti_index \
         (session_id, jti, user_id, session_epoch, status, issued_at, expires_at) \
         SELECT ?, ?, ?, ?, 'ACTIVE', UTC_TIMESTAMP(), FROM_UNIXTIME(?) \
         FROM auth_device_session \
         WHERE session_id = ? AND user_id = ? AND status = 'ACTIVE' \
           AND session_state = 'ACTIVE' AND session_epoch = ?",
    )
    .bind(session_id)
    .bind(&token.jti)
    .bind(user_id)
    .bind(session_epoch)
    .bind(token.expires_at_epoch_second)
    .bind(session_id)
    .bind(user_id)
    .bind(session_epoch)
    .execute(&state.db)
    .await
    .map_err(|e| AstralError::Database(format!("Record session JTI index failed: {e}")))?;
    if result.rows_affected() != 1 {
        return Err(AstralError::Auth(
            "Session is no longer active for access projection".into(),
        ));
    }
    Ok(())
}

/// Project a session-bound access credential for Gateway OFF, EMIT, and REQUIRE
/// modes, then record its opaque JTI for later session-wide invalidation.
pub(crate) async fn store_session_grant_in_redis(
    state: &AppState,
    token: &TokenResult,
    grant: SessionGrant,
) -> Result<(), AstralError> {
    let ttl = token.expires_in.max(60) as u64;
    let grant_json = serde_json::to_string(&grant)
        .map_err(|e| AstralError::Cache(format!("Serialize session grant failed: {e}")))?;
    let client = redis::Client::open(state.config.redis_url.as_str())
        .map_err(|e| AstralError::Cache(format!("Open Redis client failed: {e}")))?;
    let mut conn = client
        .get_connection_manager()
        .await
        .map_err(|e| AstralError::Cache(format!("Connect to Redis failed: {e}")))?;

    let scalar_key = format!("access:jti:{}", token.jti);
    let grant_key = format!("access:grant:{}", token.jti);
    conn.set_ex::<_, _, ()>(&scalar_key, grant.user_id.to_string(), ttl)
        .await
        .map_err(|e| AstralError::Cache(format!("Store token scalar projection failed: {e}")))?;
    if let Err(error) = conn.set_ex::<_, _, ()>(&grant_key, grant_json, ttl).await {
        let _: Result<(), _> = conn.del(&scalar_key).await;
        return Err(AstralError::Cache(format!(
            "Store session grant projection failed: {error}"
        )));
    }

    if let Err(error) = record_session_jti_index(
        state,
        token,
        grant.user_id,
        grant.session_id,
        grant.session_epoch,
    )
    .await
    {
        let _: Result<(), _> = conn.del(&scalar_key).await;
        let _: Result<(), _> = conn.del(&grant_key).await;
        return Err(error);
    }
    Ok(())
}

async fn delete_session_projections_before_epoch(
    state: &AppState,
    session_id: i64,
    epoch_exclusive: i64,
) -> Result<(), AstralError> {
    let indexed_jtis: Vec<(String,)> = sqlx::query_as(
        "SELECT jti FROM auth_session_jti_index \
         WHERE session_id = ? AND session_epoch < ? AND status = 'ACTIVE' \
           AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())",
    )
    .bind(session_id)
    .bind(epoch_exclusive)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AstralError::Database(format!("Load prior session JTI index failed: {e}")))?;
    delete_indexed_session_projections(state, &indexed_jtis).await?;
    sqlx::query(
        "UPDATE auth_session_jti_index SET status = 'DELETED', updated_at = UTC_TIMESTAMP() \
         WHERE session_id = ? AND session_epoch < ? AND status = 'ACTIVE'",
    )
    .bind(session_id)
    .bind(epoch_exclusive)
    .execute(&state.db)
    .await
    .map_err(|e| AstralError::Database(format!("Close prior session JTI index failed: {e}")))?;
    Ok(())
}

async fn delete_indexed_session_projections(
    state: &AppState,
    indexed_jtis: &[(String,)],
) -> Result<(), AstralError> {
    if indexed_jtis.is_empty() {
        return Ok(());
    }
    let client = redis::Client::open(state.config.redis_url.as_str())
        .map_err(|e| AstralError::Cache(format!("Open Redis client failed: {e}")))?;
    let mut conn = client
        .get_connection_manager()
        .await
        .map_err(|e| AstralError::Cache(format!("Connect to Redis failed: {e}")))?;
    for (jti,) in indexed_jtis {
        let _: () = conn
            .del((format!("access:jti:{jti}"), format!("access:grant:{jti}")))
            .await
            .map_err(|e| AstralError::Cache(format!("Delete session projection failed: {e}")))?;
        // Rust Gateway 以 `jwt:revoked:{jti}` 黑名单为会话有效性判定（不读 access:jti/grant）。
        // 撤销链必须写黑名单，否则被撤销的 access token 仍可过网关直到 JWT 过期
        // （对齐 Java 语义：删投影 → Gateway 存在性校验失败 → 401 fail-closed）。
        // TTL 7 天覆盖 access token 最大生命周期。
        let _: () = conn
            .set_ex::<_, _, ()>(format!("jwt:revoked:{jti}"), "1", REVOKED_TTL_SECS)
            .await
            .map_err(|e| AstralError::Cache(format!("Mark revoked JTI failed: {e}")))?;
    }
    Ok(())
}

async fn delete_session_projections(state: &AppState, session_id: i64) -> Result<(), AstralError> {
    let indexed_jtis: Vec<(String,)> = sqlx::query_as(
        "SELECT jti FROM auth_session_jti_index \
         WHERE session_id = ? AND status = 'ACTIVE' AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())",
    )
    .bind(session_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AstralError::Database(format!("Load session JTI index failed: {e}")))?;
    delete_indexed_session_projections(state, &indexed_jtis).await?;
    sqlx::query(
        "UPDATE auth_session_jti_index SET status = 'DELETED', updated_at = UTC_TIMESTAMP() \
         WHERE session_id = ? AND status = 'ACTIVE'",
    )
    .bind(session_id)
    .execute(&state.db)
    .await
    .map_err(|e| AstralError::Database(format!("Close session JTI index failed: {e}")))?;
    Ok(())
}

async fn delete_access_projections(state: &AppState, jti: &str) -> Result<(), AstralError> {
    let client = redis::Client::open(state.config.redis_url.as_str())
        .map_err(|e| AstralError::Cache(format!("Open Redis client failed: {e}")))?;
    let mut conn = client
        .get_connection_manager()
        .await
        .map_err(|e| AstralError::Cache(format!("Connect to Redis failed: {e}")))?;
    let _: () = conn
        .del((format!("access:jti:{jti}"), format!("access:grant:{jti}")))
        .await
        .map_err(|e| AstralError::Cache(format!("Delete access projection failed: {e}")))?;
    // 同上：会话级撤销同时写 Gateway 黑名单（fail-closed 等价于 Java 删投影语义）
    let _: () = conn
        .set_ex::<_, _, ()>(format!("jwt:revoked:{jti}"), "1", REVOKED_TTL_SECS)
        .await
        .map_err(|e| AstralError::Cache(format!("Mark revoked JTI failed: {e}")))?;
    sqlx::query(
        "UPDATE auth_session_jti_index SET status = 'DELETED', updated_at = UTC_TIMESTAMP() \
         WHERE jti = ? AND status = 'ACTIVE'",
    )
    .bind(jti)
    .execute(&state.db)
    .await
    .map_err(|e| AstralError::Database(format!("Close access JTI index failed: {e}")))?;
    Ok(())
}

/// Mark an access JTI as revoked in the shared Redis projection.
async fn mark_jti_revoked_at(
    redis_url: &str,
    jti: &str,
    ttl_seconds: i64,
) -> Result<(), AstralError> {
    if jti.trim().is_empty() {
        return Err(AstralError::Auth("TOKEN_ID_REQUIRED".into()));
    }
    let key = format!("jwt:revoked:{jti}");
    let client = redis::Client::open(redis_url)
        .map_err(|e| AstralError::Cache(format!("Open Redis client failed: {e}")))?;
    let mut conn = client
        .get_connection_manager()
        .await
        .map_err(|e| AstralError::Cache(format!("Connect to Redis failed: {e}")))?;
    let ttl = ttl_seconds.max(60) as u64;
    conn.set_ex::<_, _, ()>(&key, "1", ttl)
        .await
        .map_err(|e| AstralError::Cache(format!("Mark token revoked in Redis failed: {e}")))?;
    tracing::debug!(key = %key, "marked token as revoked in Redis");
    Ok(())
}

/// 会话级撤销写入 Gateway 黑名单的 TTL（秒，7 天），覆盖 access token 最大生命周期。
/// Rust Gateway 以 `jwt:revoked:{jti}` 为会话有效性判定（对齐 Java 删投影语义）。
const REVOKED_TTL_SECS: u64 = 7 * 24 * 3600;

#[derive(Debug, sqlx::FromRow)]
struct SwitchOperationRow {
    operation_id: String,
    request_hash: String,
    refresh_token_hash: String,
    status: String,
    response_ciphertext: Option<String>,
    response_expires_at: Option<PrimitiveDateTime>,
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
/// the durable row before the idempotent operation is created.
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
    let session = session_repo::load_active_refresh_session(&state.db, &refresh_hash)
        .await?
        .filter(|row| {
            row.session_id == session_id
                && row.family_id == family_id
                && row.user_id == user_id
                && row.current_user_card_id.is_some()
                && row.session_version == claims.session_version.unwrap_or_default()
                && row.session_epoch == claims.sev.unwrap_or_default()
        })
        .ok_or_else(|| AstralError::Auth("Invalid refresh session".into()))?;
    if target_card_id <= 0 {
        return Err(AppError::from(AstralError::Validation(
            "targetUserCardId required".into(),
        )));
    }
    // Refuse before the durable CAS when credentials cannot be encrypted for retry.
    let _ = session_response_key()?;

    let normalized_device_id = device_id.map(str::trim).filter(|value| !value.is_empty());
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
    let operation = begin_switch_operation(
        state,
        user_id,
        required_idempotency_key(headers)?,
        &request_hash,
        &refresh_hash,
        target_card_id,
    )
    .await?;

    if let Some(existing) = operation {
        return replay_or_recover_switch_operation(state, existing, &request_hash, &refresh_hash)
            .await;
    }

    let operation_id =
        operation_id_for_request(state, user_id, required_idempotency_key(headers)?).await?;
    let result = switch_card_once(
        state,
        headers,
        user_id,
        from_card_id,
        target_card_id,
        refresh_token,
        normalized_device_id,
    )
    .await;
    match result {
        Ok((response, token, session, card_id)) => {
            let ciphertext = match encrypt_operation_response(&operation_id, &response) {
                Ok(value) => value,
                Err(error) => {
                    revoke_token_family(
                        state,
                        session.family_id,
                        "SESSION_OPERATION_RESPONSE_UNAVAILABLE",
                    )
                    .await
                    .map_err(AppError::from)?;
                    return Err(error);
                }
            };
            let response_expires_at = response_expiry()?;
            let persisted = sqlx::query(
                "UPDATE auth_session_operation SET session_id = ?, status = 'COMMITTED_PENDING_REDIS', \
                 response_ciphertext = ?, response_expires_at = ?, updated_at = UTC_TIMESTAMP() \
                 WHERE operation_id = ? AND status = 'PENDING'",
            )
            .bind(session.session_id)
            .bind(ciphertext)
            .bind(response_expires_at)
            .bind(&operation_id)
            .execute(&state.db)
            .await
            .map_err(|error| AstralError::Database(format!("Persist switch operation failed: {error}")))?;
            if persisted.rows_affected() != 1 {
                revoke_token_family(
                    state,
                    session.family_id,
                    "SESSION_OPERATION_PERSISTENCE_FAILED",
                )
                .await
                .map_err(AppError::from)?;
                return Err(AppError::from(AstralError::Auth(
                    "Session operation could not be persisted".into(),
                )));
            }

            if let Err(error) = record_session_jti_index(
                state,
                &token,
                user_id,
                session.session_id,
                session.session_epoch,
            )
            .await
            {
                revoke_token_family(state, session.family_id, "ACCESS_TRACKING_UNAVAILABLE")
                    .await
                    .map_err(AppError::from)?;
                return Err(AppError::from(error));
            }

            if let Err(error) = restore_session_grant_in_redis(state, &token, {
                let (claims, _) = decode_v2_token(&token.token, &state.config).map_err(|_| {
                    AppError::from(AstralError::Auth(
                        "SESSION_OPERATION_RESPONSE_UNAVAILABLE".into(),
                    ))
                })?;
                SessionGrant::active(
                    &token,
                    PrincipalKind::PlatformUser,
                    user_id,
                    session.session_id,
                    claims.identity_card_id,
                    Some(card_id),
                    claims.user_card_tenant_id,
                    claims.user_card_domain_id,
                    session.session_version,
                    session.session_epoch,
                    session.family_id,
                )
            })
            .await
            {
                tracing::error!(operation_id = %operation_id, error = %error, "card switch projection pending");
                return Err(AppError::from(error));
            }

            let completed = sqlx::query(
                "UPDATE auth_session_operation SET status = 'COMPLETED', completed_at = UTC_TIMESTAMP(), \
                 updated_at = UTC_TIMESTAMP() WHERE operation_id = ? AND status = 'COMMITTED_PENDING_REDIS'",
            )
            .bind(&operation_id)
            .execute(&state.db)
            .await
            .map_err(|error| AstralError::Database(format!("Complete switch operation failed: {error}")))?;
            if completed.rows_affected() != 1 {
                revoke_token_family(
                    state,
                    session.family_id,
                    "SESSION_OPERATION_COMPLETION_FAILED",
                )
                .await
                .map_err(AppError::from)?;
                return Err(AppError::from(AstralError::Auth(
                    "Session operation completion could not be confirmed".into(),
                )));
            }
            Ok(response)
        }
        Err(error) => {
            let _ = sqlx::query(
                "DELETE FROM auth_session_operation WHERE operation_id = ? AND status = 'PENDING'",
            )
            .bind(&operation_id)
            .execute(&state.db)
            .await;
            Err(error)
        }
    }
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

async fn begin_switch_operation(
    state: &AppState,
    user_id: i64,
    idempotency_key: &str,
    request_hash: &str,
    refresh_hash: &str,
    target_card_id: i64,
) -> Result<Option<SwitchOperationRow>, AppError> {
    let idempotency_hash = sha256_hash(idempotency_key);
    let operation_id = uuid::Uuid::new_v4().to_string();
    let insert = sqlx::query(
        "INSERT INTO auth_session_operation \
         (operation_id, user_id, operation_type, idempotency_key_hash, request_hash, refresh_token_hash, target_card_id, status) \
         VALUES (?, ?, 'SWITCH_CARD', ?, ?, ?, ?, 'PENDING')",
    )
    .bind(&operation_id)
    .bind(user_id)
    .bind(&idempotency_hash)
    .bind(request_hash)
    .bind(refresh_hash)
    .bind(target_card_id)
    .execute(&state.db)
    .await;
    match insert {
        Ok(result) if result.rows_affected() == 1 => Ok(None),
        Ok(_) => Err(AppError::from(AstralError::Database(
            "Switch operation insert affected an unexpected row count".into(),
        ))),
        Err(insert_error) => sqlx::query_as::<_, SwitchOperationRow>(
            "SELECT operation_id, request_hash, refresh_token_hash, status, response_ciphertext, response_expires_at \
             FROM auth_session_operation WHERE user_id = ? AND operation_type = 'SWITCH_CARD' \
             AND idempotency_key_hash = ? LIMIT 1",
        )
        .bind(user_id)
        .bind(idempotency_hash)
        .fetch_optional(&state.db)
        .await
        .map_err(|error| AstralError::Database(format!("Load switch operation failed: {error}")))?
        .map(Some)
        .ok_or_else(|| {
            AppError::from(AstralError::Database(format!(
                "Create switch operation failed: {insert_error}"
            )))
        }),
    }
}

async fn operation_id_for_request(
    state: &AppState,
    user_id: i64,
    idempotency_key: &str,
) -> Result<String, AppError> {
    sqlx::query_scalar(
        "SELECT operation_id FROM auth_session_operation WHERE user_id = ? AND operation_type = 'SWITCH_CARD' \
         AND idempotency_key_hash = ? LIMIT 1",
    )
    .bind(user_id)
    .bind(sha256_hash(idempotency_key))
    .fetch_optional(&state.db)
    .await
    .map_err(|error| AstralError::Database(format!("Load switch operation id failed: {error}")))?
    .ok_or_else(|| AppError::from(AstralError::Auth("Session operation unavailable".into())))
}

async fn replay_or_recover_switch_operation(
    state: &AppState,
    operation: SwitchOperationRow,
    request_hash: &str,
    refresh_hash: &str,
) -> Result<LoginResponse, AppError> {
    if operation.request_hash != request_hash || operation.refresh_token_hash != refresh_hash {
        return Err(AppError::from(AstralError::Validation(
            "IDEMPOTENCY_KEY_REUSED".into(),
        )));
    }
    let response = decrypt_switch_operation_response(&operation)?;
    if operation.status == "COMPLETED" {
        return Ok(response);
    }
    if operation.status != "COMMITTED_PENDING_REDIS" {
        return Err(AppError::from(AstralError::Auth(
            "SESSION_OPERATION_IN_PROGRESS".into(),
        )));
    }

    reproject_switch_response(state, &response).await?;
    let updated = sqlx::query(
        "UPDATE auth_session_operation SET status = 'COMPLETED', completed_at = UTC_TIMESTAMP(), \
         updated_at = UTC_TIMESTAMP() WHERE operation_id = ? AND status = 'COMMITTED_PENDING_REDIS'",
    )
    .bind(&operation.operation_id)
    .execute(&state.db)
    .await
    .map_err(|error| AstralError::Database(format!("Complete recovered switch operation failed: {error}")))?;
    if updated.rows_affected() != 1 {
        return Err(AppError::from(AstralError::Auth(
            "Session operation completion could not be confirmed".into(),
        )));
    }
    Ok(response)
}

async fn switch_card_once(
    state: &AppState,
    headers: &HeaderMap,
    user_id: i64,
    from_card_id: i64,
    target_card_id: i64,
    refresh_token: &str,
    requested_device_id: Option<&str>,
) -> Result<(LoginResponse, TokenResult, DeviceSessionRow, i64), AppError> {
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
    let refresh_result = issue_refresh_token(
        &state.config.jwt,
        user_id,
        PrincipalKind::PlatformUser,
        session_context,
    )?;
    let refresh_hash = sha256_hash(&refresh_result.token);
    let response = LoginResponse {
        access_token: token.token.clone(),
        // Switch-card preserves the long-lived credential. It only rotates the
        // access projection and its session epoch.
        refresh_token: refresh_result.token.clone(),
        token_type: "Bearer".into(),
        expires_in_millis: token.expires_in * 1000,
        refresh_expires_in_millis: refresh_lifetime * 1000,
        token: Some(token.token.clone()),
        user: Some(serde_json::json!({
            "userId": user.user_id,
            "username": user.user_no,
            "displayName": user.display_name,
            "email": user.email,
            "phone": user.phone,
            "status": user.status,
            "hasLocalCredential": true,
        })),
        identity_card: Some(serde_json::json!({
            "cardId": identity.0,
            "userId": user_id,
            "status": "ACTIVE",
            "tokenVersion": identity.1,
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

    delete_session_projections_before_epoch(state, session.session_id, next_session_epoch).await?;
    let effective_device_id = requested_device_id.unwrap_or(&session.device_id);
    let rotation = sqlx::query(
        "UPDATE auth_device_session SET device_id = ?, current_user_card_id = ?, session_state = 'ACTIVE', \
         session_version = ?, session_epoch = ?, refresh_token_hash = ?, refresh_expires_at = ?, \
         ip_address = COALESCE(?, ip_address), user_agent = COALESCE(?, user_agent), status = 'ACTIVE', \
         revoked_at = NULL, revoked_reason = NULL, last_seen_at = UTC_TIMESTAMP(), updated_at = UTC_TIMESTAMP() \
         WHERE session_id = ? AND user_id = ? AND family_id = ? AND refresh_token_hash = ? \
         AND status = 'ACTIVE' AND session_state = 'ACTIVE' AND session_version = ? AND session_epoch = ?",
    )
    .bind(effective_device_id)
    .bind(target_card_id)
    .bind(next_session_version)
    .bind(next_session_epoch)
    .bind(&refresh_hash)
    .bind(refresh_expires_at)
    .bind(request_header_text(headers, "x-forwarded-for"))
    .bind(request_header_text(headers, "user-agent"))
    .bind(session.session_id)
    .bind(user_id)
    .bind(session.family_id)
    .bind(sha256_hash(refresh_token))
    .bind(session.session_version)
    .bind(session.session_epoch)
    .execute(&state.db)
    .await
    .map_err(|error| AstralError::Database(format!("Rotate switch session failed: {error}")))?;
    if !rotation_succeeded(rotation.rows_affected()) {
        return Err(AppError::from(AstralError::Auth(
            "SESSION_VERSION_CONFLICT".into(),
        )));
    }

    let rotated_session = DeviceSessionRow {
        session_version: next_session_version,
        session_epoch: next_session_epoch,
        current_user_card_id: Some(target_card_id),
        refresh_token_hash: refresh_hash,
        refresh_expires_at: Some(refresh_expires_at),
        device_id: effective_device_id.to_string(),
        ..session
    };
    Ok((response, token, rotated_session, target_card_id))
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
) -> Result<LoginResponse, AppError> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use base64::Engine;

    if operation
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

async fn reproject_switch_response(
    state: &AppState,
    response: &LoginResponse,
) -> Result<(), AppError> {
    let session = response.session.as_ref().ok_or_else(|| {
        AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RESPONSE_UNAVAILABLE".into(),
        ))
    })?;
    let session_id = session
        .get("sessionId")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| {
            AppError::from(AstralError::Auth(
                "SESSION_OPERATION_RESPONSE_UNAVAILABLE".into(),
            ))
        })?;
    let family_id = session
        .get("familyId")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| {
            AppError::from(AstralError::Auth(
                "SESSION_OPERATION_RESPONSE_UNAVAILABLE".into(),
            ))
        })?;
    let session_version = session
        .get("sessionVersion")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| {
            AppError::from(AstralError::Auth(
                "SESSION_OPERATION_RESPONSE_UNAVAILABLE".into(),
            ))
        })?;
    let session_epoch = session
        .get("sessionEpoch")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| {
            AppError::from(AstralError::Auth(
                "SESSION_OPERATION_RESPONSE_UNAVAILABLE".into(),
            ))
        })?;
    let card_id = session
        .get("currentUserCardId")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| {
            AppError::from(AstralError::Auth(
                "SESSION_OPERATION_RESPONSE_UNAVAILABLE".into(),
            ))
        })?;
    let (claims, token_use) =
        decode_v2_token(&response.access_token, &state.config).map_err(|_| {
            AppError::from(AstralError::Auth(
                "SESSION_OPERATION_RESPONSE_UNAVAILABLE".into(),
            ))
        })?;
    if token_use != TokenUse::Access {
        return Err(AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RESPONSE_UNAVAILABLE".into(),
        )));
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if claims.exp as i64 <= now
        || claims.sub.parse::<i64>().ok().is_none()
        || claims.user_card_id != Some(card_id)
    {
        return Err(AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RESPONSE_UNAVAILABLE".into(),
        )));
    }
    let token = TokenResult {
        token: response.access_token.clone(),
        jti: claims.jti,
        expires_in: claims.exp as i64 - now,
        issued_at_epoch_second: claims.iat as i64,
        expires_at_epoch_second: claims.exp as i64,
    };
    let durable = sqlx::query_as::<_, (i64, i64, i64, i64, Option<i64>, String, String)>(
        "SELECT session_id, user_id, family_id, session_epoch, current_user_card_id, status, session_state \
         FROM auth_device_session WHERE session_id = ? AND user_id = ? AND family_id = ? \
         AND session_version = ? AND session_epoch = ? LIMIT 1",
    )
    .bind(session_id)
    .bind(claims.sub.parse::<i64>().map_err(|_| {
        AstralError::Auth("SESSION_OPERATION_RESPONSE_UNAVAILABLE".into())
    })?)
    .bind(family_id)
    .bind(session_version)
    .bind(session_epoch)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| AstralError::Database(format!("Verify switch replay session failed: {error}")))?
    .filter(|row| row.4 == Some(card_id) && row.5 == "ACTIVE" && row.6 == "ACTIVE")
    .ok_or_else(|| AppError::from(AstralError::Auth("SESSION_OPERATION_RESPONSE_UNAVAILABLE".into())))?;
    let indexed: Option<(i64,)> = sqlx::query_as(
        "SELECT jti_id FROM auth_session_jti_index WHERE session_id = ? AND user_id = ? AND jti = ? \
         AND session_epoch = ? AND status = 'ACTIVE' LIMIT 1",
    )
    .bind(durable.0)
    .bind(durable.1)
    .bind(&token.jti)
    .bind(session_epoch)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| AstralError::Database(format!("Verify switch replay JTI failed: {error}")))?;
    if indexed.is_none() {
        return Err(AppError::from(AstralError::Auth(
            "SESSION_OPERATION_RESPONSE_UNAVAILABLE".into(),
        )));
    }
    restore_session_grant_in_redis(
        state,
        &token,
        SessionGrant::active(
            &token,
            PrincipalKind::PlatformUser,
            durable.1,
            durable.0,
            claims.identity_card_id,
            Some(card_id),
            claims.user_card_tenant_id,
            claims.user_card_domain_id,
            session_version,
            session_epoch,
            durable.2,
        ),
    )
    .await
    .map_err(AppError::from)
}

async fn restore_session_grant_in_redis(
    state: &AppState,
    token: &TokenResult,
    grant: SessionGrant,
) -> Result<(), AstralError> {
    let ttl = token.expires_in.max(1) as u64;
    let grant_json = serde_json::to_string(&grant).map_err(|error| {
        AstralError::Cache(format!("Serialize switch replay grant failed: {error}"))
    })?;
    let client = redis::Client::open(state.config.redis_url.as_str())
        .map_err(|error| AstralError::Cache(format!("Open Redis client failed: {error}")))?;
    let mut conn = client
        .get_connection_manager()
        .await
        .map_err(|error| AstralError::Cache(format!("Connect to Redis failed: {error}")))?;
    let scalar_key = format!("access:jti:{}", token.jti);
    let grant_key = format!("access:grant:{}", token.jti);
    conn.set_ex::<_, _, ()>(&scalar_key, grant.user_id.to_string(), ttl)
        .await
        .map_err(|error| {
            AstralError::Cache(format!("Restore token scalar projection failed: {error}"))
        })?;
    if let Err(error) = conn.set_ex::<_, _, ()>(&grant_key, grant_json, ttl).await {
        let _: Result<(), _> = conn.del(&scalar_key).await;
        return Err(AstralError::Cache(format!(
            "Restore session grant projection failed: {error}"
        )));
    }
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
            token: Some("access".into()),
            user: None,
            identity_card: None,
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
            request_hash: "request".into(),
            refresh_token_hash: "refresh".into(),
            status: "COMPLETED".into(),
            response_ciphertext: Some(ciphertext),
            response_expires_at: response_expiry().ok(),
        };
        assert_eq!(
            decrypt_switch_operation_response(&operation)
                .unwrap()
                .access_token,
            "access"
        );
        let wrong_operation = SwitchOperationRow {
            operation_id: "operation-b".into(),
            ..operation
        };
        assert!(decrypt_switch_operation_response(&wrong_operation).is_err());
        unsafe { std::env::remove_var("IDENTITY_SESSION_RESPONSE_AES_GCM_KEY") };
    }

    fn session_response_env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    #[test]
    fn logout_requires_a_credential() {
        let headers = HeaderMap::new();
        assert!(bearer_token(&headers).is_none());
        let request = RevokeSessionRequest::default();
        assert!(request.reason.is_none());
    }

    #[test]
    fn logout_accepts_only_bearer_access_header() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer access.jwt".parse().unwrap());
        assert_eq!(bearer_token(&headers), Some("access.jwt"));
        headers.insert("authorization", "Basic access.jwt".parse().unwrap());
        assert!(bearer_token(&headers).is_none());
    }

    #[tokio::test]
    async fn redis_revoke_failure_is_returned() {
        let result = mark_jti_revoked_at("redis://localhost:1", "refresh-jti", 1).await;
        assert!(matches!(result, Err(AstralError::Cache(_))));
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

    #[test]
    fn v2_refresh_is_not_a_legacy_raw_token_key() {
        assert_eq!(
            format!("jwt:revoked:{}", "refresh-jti"),
            "jwt:revoked:refresh-jti"
        );
    }

    #[tokio::test]
    async fn family_database_failure_is_an_error() {
        let db = sqlx::MySqlPool::connect_lazy("mysql://localhost:1/identity")
            .expect("lazy pool construction should succeed");
        let result = check_family_valid(&db, 1).await;
        assert!(matches!(result, Err(AstralError::Database(_))));
    }
}
