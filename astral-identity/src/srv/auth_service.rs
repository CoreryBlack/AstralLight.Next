//! 认证应用服务 — 对应 Java `AuthServiceImpl` + `TokenServiceImpl` 编排边界。
//!
//! 负责登录、注册、资料与改密编排。数据访问通过 `AuthRepository`，
//! 会话 family/Redis 投影通过 `srv::session` 的安全编排保留。

use std::sync::Arc;

use serde::Deserialize;
use time::{Duration, OffsetDateTime, PrimitiveDateTime};

use astral_common::error::AppError;
use astral_common::token_contract::PrincipalKind;
use astral_types::{AstralError, IdentityCard};

use crate::auth::{
    derive_roles_from_action_codes, derive_roles_from_cards, hash_password, issue_access_token,
    issue_refresh_token, map_eligibility_error, normalize_phone, sha256_hash, verify_password,
    LoginResponse, PasswordVerifyResult, SessionContext, SessionGrant, TokenClaimsExtra,
};
use crate::srv::auth_repository::AuthRepository;
use crate::srv::session::{
    create_token_family_with_expiry, revoke_all_sessions_for_user, store_session_grant_in_redis,
};
use crate::AppState;

// ===== 请求 DTO（对应 Java LoginRequest/RegisterRequest） =====

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    pub username: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub password: Option<String>,

    pub provider: Option<String>,
    pub subject_key: Option<String>,
    pub account_key: Option<String>,
    pub provider_user_id: Option<String>,
    pub provider_account_id: Option<String>,
    pub provider_subject_id: Option<String>,
    pub provider_subject_type: Option<String>,
    pub provider_account_type: Option<String>,
    pub app_id: Option<String>,
    pub client_app_id: Option<String>,
    pub tenant_id: Option<String>,
    pub channel_code: Option<String>,
    pub access_token: Option<String>,
    pub email_verified: Option<bool>,

    pub display_name: Option<String>,
    pub avatar_url: Option<String>,

    pub client_id: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub device_id: Option<String>,

    pub remember_me: Option<bool>,

    /// 显式选卡：多张 ACTIVE user_card 时必须提供（对齐 Java 不变式 15）
    pub target_card_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub real_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProfileRequest {
    pub real_name: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

pub struct AuthService {
    repository: Arc<dyn AuthRepository>,
}

impl AuthService {
    pub fn new(repository: Arc<dyn AuthRepository>) -> Self {
        Self { repository }
    }

    pub async fn login(
        &self,
        state: &AppState,
        req: &LoginRequest,
    ) -> Result<LoginResponse, AppError> {
        let result = self.login_inner(state, req).await;
        if let Err(error) = &result {
            // Keep the authentication error authoritative while persisting a
            // local LOGIN_FAILURE audit record whenever the database is usable.
            let user_id = self.login_failure_user_id(req).await;
            record_login_failure_audit(
                &state.db,
                user_id,
                req.client_ip.as_deref(),
                req.user_agent.as_deref(),
                error.to_string(),
            )
            .await;
        }
        result
    }

    async fn login_inner(
        &self,
        state: &AppState,
        req: &LoginRequest,
    ) -> Result<LoginResponse, AppError> {
        // 不变式 14：通用登录仅接受本地 username/email/phone + password；
        // OAuth/provider 输入不得作为未验证身份断言参与登录（对齐 Java OAUTH_DISABLED）。
        if has_oauth_input(req) {
            return Err(AppError::from(AstralError::Auth("OAUTH_DISABLED".into())));
        }

        // 解析登录标识（对齐 Java resolveLocalCredential）：
        // phone(规范化) → username(login_name) → email(platform_user)
        let username = req
            .username
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let phone = req
            .phone
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let email = req
            .email
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if username.is_none() && phone.is_none() && email.is_none() {
            return Err(AppError::from(AstralError::Validation(
                "username, phone or email required".into(),
            )));
        }

        let agg = self
            .repository
            .find_login_aggregate_resolved(username, phone, email)
            .await?
            .ok_or_else(|| {
                tracing::warn!("login failed: user not found");
                AstralError::Auth("Invalid credentials".into())
            })?;

        if agg.user_status != "ACTIVE" {
            tracing::warn!(user_id = %agg.user_id, status = %agg.user_status, "login failed: user not active");
            return Err(AppError::from(AstralError::Auth(
                "Account is not active".into(),
            )));
        }
        if let Some(ref card_status) = agg.card_status {
            if card_status != "ACTIVE" {
                tracing::warn!(user_id = %agg.user_id, card_status = %card_status, "login failed: card not active");
                return Err(AppError::from(AstralError::Auth(
                    "Identity card is not active".into(),
                )));
            }
        }

        if agg.card_id.is_none() || agg.card_status.as_deref() != Some("ACTIVE") {
            tracing::warn!(user_id = %agg.user_id, "login failed: active identity card not found");
            return Err(AppError::from(AstralError::Auth("CARD_NOT_FOUND".into())));
        }

        let password = req
            .password
            .as_deref()
            .ok_or_else(|| AstralError::Validation("password required for local login".into()))?;
        match verify_password(password, agg.password_hash.as_str())? {
            PasswordVerifyResult::Match => {}
            PasswordVerifyResult::Migrated(new_hash) => {
                if let Err(e) = self
                    .repository
                    .update_password_hash(agg.user_id, &new_hash)
                    .await
                {
                    tracing::warn!(error = %e, "password migration failed");
                }
            }
        }

        if let Err(e) = self.repository.update_last_login_at(agg.user_id).await {
            tracing::warn!(error = %e, "update last_login_at failed, non-blocking");
        }

        let cards = self.repository.find_login_cards(agg.user_id).await?;
        let cards_json: Vec<serde_json::Value> = cards.iter().map(login_card_to_json).collect();

        // 显式选卡（对齐 Java 不变式 15）
        let current_card: Option<serde_json::Value> =
            select_login_card(&cards_json, req.target_card_id).map_err(AppError::from)?;
        let jwt_card_id: Option<i64> = current_card
            .as_ref()
            .and_then(|c| c.get("cardId").and_then(|v| v.as_i64()));
        let jwt_tenant_id: Option<i64> = current_card
            .as_ref()
            .and_then(|c| c.get("tenantId").and_then(|v| v.as_i64()));
        let jwt_template_id: Option<i64> = current_card
            .as_ref()
            .and_then(|c| c.get("templateId").and_then(|v| v.as_i64()));

        let id_card = IdentityCard {
            card_id: agg.card_id,
            user_id: agg.user_id,
            status: "ACTIVE".into(),
            token_version: agg.token_version,
            expires_at: agg.identity_expires_at.clone(),
            disabled_reason: None,
            last_used_at: None,
            created_at: None,
            updated_at: None,
        };

        let user_card_for_jwt = current_card
            .as_ref()
            .map(|c| astral_types::UserCard {
                card_id: c.get("cardId").and_then(|v| v.as_i64()),
                user_id: Some(agg.user_id),
                domain_id: c.get("domainId").and_then(|v| v.as_i64()),
                card_type: c
                    .get("cardType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("PLATFORM_CARD")
                    .to_string(),
                card_status: "ACTIVE".to_string(),
                template_id: jwt_template_id,
                level_id: c.get("levelId").and_then(|v| v.as_i64()),
                priority: c.get("priority").and_then(|v| v.as_i64()).map(|v| v as i32),
                is_primary: c.get("isPrimary").and_then(|v| v.as_bool()),
                valid_from: None,
                valid_until: None,
                created_at: None,
                updated_at: None,
                tenant_id: c.get("tenantId").and_then(|v| v.as_i64()),
            })
            .ok_or_else(|| AstralError::Auth("CARD_SELECTION_REQUIRED".into()))?;

        // 签发资格权威校验（对齐物理双卡权限链路设计）：用户 / identity_card 与目标
        // user_card 选定后，统一调用资格服务替代独立 scope SQL 作为最终签发门禁。
        // 资格服务单条 JOIN 同时校验身份线路 / user_card 线路 / 组织线路
        // （tenant/domain ACTIVE + 时间窗口），失败一律 fail-closed 拒绝签发。
        // identity_card 只提供身份事实，组织事实仅来自目标 user_card（资格服务内部复核）。
        let identity_card_id = agg
            .card_id
            .ok_or_else(|| AstralError::Auth("CARD_NOT_FOUND".into()))?;
        let Some(user_card_id) = jwt_card_id else {
            return Err(AppError::from(AstralError::Permission(
                "USER_CARD_SCOPE_REQUIRED".into(),
            )));
        };
        if let Err(error) = astral_db::CardEligibilityService::verify_platform_card_pair(
            &state.db,
            &astral_types::PlatformCardPairRequest {
                user_id: agg.user_id,
                identity_card_id,
                user_card_id,
            },
        )
        .await
        {
            tracing::warn!(
                user_id = %agg.user_id,
                identity_card_id,
                user_card_id,
                error = %error,
                "login refused: platform card pair not eligible"
            );
            return Err(AppError::from(map_eligibility_error(error, |_| {
                AstralError::Permission("USER_CARD_SCOPE_REQUIRED".into())
            })));
        }

        let refresh_lifetime = state.config.jwt.refresh.expiry_seconds;
        let refresh_expiry = utc_db_datetime_after(refresh_lifetime);
        let family_key = uuid::Uuid::new_v4().to_string();
        let family_id =
            create_token_family_with_expiry(&state.db, &family_key, agg.user_id, refresh_expiry)
                .await?;

        let session_card_id = jwt_card_id;
        let placeholder_hash = sha256_hash(&format!("pending:{}", uuid::Uuid::new_v4()));
        let session_id = self
            .repository
            .insert_login_session(crate::srv::auth_repository::NewLoginSession {
                family_id,
                user_id: agg.user_id,
                device_id: req.device_id.clone().unwrap_or_else(|| "unknown".into()),
                device_type: Some("UNKNOWN".into()),
                client_app_id: req.client_app_id.clone().or_else(|| req.client_id.clone()),
                channel_code: req.channel_code.clone(),
                current_user_card_id: session_card_id,
                refresh_hash: placeholder_hash.clone(),
                refresh_expiry,
            })
            .await?;

        // 权限/角色/租户状态（对齐 Java TokenServiceImpl 签发时刻实时求值）：
        // - permissions 来自投影快照（find_effective_permissions_cached，投影未 READY
        //   安全 miss 返回空，不直读源表）；仅 claims-mode 非 OFF 时写入 JWT（Java 默认 OFF 不发）。
        // - roles 来自当前卡 actionCodes（Java resolveRolesFromCard，排除 super_admin 类）；
        //   空则回退默认 USER。
        // - tenantStatus 来自卡所属 tenant status；无租户/无卡时保持 None。
        let current_permissions: Vec<String> = if let Some(card_id) = jwt_card_id {
            self.repository
                .find_login_permissions(card_id)
                .await?
                .into_iter()
                .map(|p| format!("{}:{}", p.resource_type, p.action_code))
                .collect()
        } else {
            vec![]
        };
        let current_action_codes: Vec<String> = jwt_card_id
            .and_then(|card_id| cards.iter().find(|c| c.card_id == card_id))
            .and_then(|c| c.action_codes.as_ref())
            .map(|codes| {
                codes
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let current_tenant_status: Option<String> = match jwt_tenant_id {
            Some(tenant_id) => self.repository.find_tenant_status(tenant_id).await?,
            None => None,
        };
        let claims_extra = TokenClaimsExtra {
            roles: derive_roles_from_action_codes(&current_action_codes),
            permissions: if state
                .config
                .session_grant_claims_mode
                .eq_ignore_ascii_case("OFF")
            {
                None
            } else {
                Some(current_permissions.clone())
            },
            tenant_status: current_tenant_status,
        };

        let session_context = SessionContext {
            session_id,
            session_version: 1,
            session_epoch: 1,
            family_id,
        };
        let access_token_result = issue_access_token(
            &state.config.jwt,
            &id_card,
            &user_card_for_jwt,
            session_context,
            Some(&claims_extra),
        )?;
        let refresh_token_result = issue_refresh_token(
            &state.config.jwt,
            agg.user_id,
            PrincipalKind::PlatformUser,
            session_context,
        )?;
        let refresh_hash = sha256_hash(&refresh_token_result.token);
        if let Err(error) = self
            .repository
            .update_initial_refresh_token(
                session_id,
                &placeholder_hash,
                &refresh_hash,
                refresh_expiry,
            )
            .await
        {
            let _ = self
                .repository
                .delete_active_family(family_id, agg.user_id)
                .await;
            return Err(AppError::from(error));
        }

        let projection_result = store_session_grant_in_redis(
            state,
            &access_token_result,
            SessionGrant::active(
                &access_token_result,
                PrincipalKind::PlatformUser,
                agg.user_id,
                session_id,
                id_card.card_id,
                Some(
                    user_card_for_jwt
                        .card_id
                        .ok_or_else(|| AstralError::Auth("USER_CARD_CONTEXT_REQUIRED".into()))?,
                ),
                user_card_for_jwt.tenant_id,
                user_card_for_jwt.domain_id,
                1,
                1,
                family_id,
            ),
        )
        .await;
        if let Err(redis_error) = projection_result {
            if let Err(cleanup_error) = self
                .repository
                .delete_active_family(family_id, agg.user_id)
                .await
            {
                tracing::error!(family_id = %family_id, %redis_error, %cleanup_error, "login token tracking failed and family cleanup failed");
            }
            return Err(AppError::from(redis_error));
        }

        let crate::auth::TokenResult {
            token: access_token,
            expires_in: expires_in_seconds,
            ..
        } = access_token_result;
        let refresh_token = refresh_token_result.token;
        let expires_in_millis = expires_in_seconds * 1000;
        let refresh_expires_in_millis = refresh_lifetime * 1000;

        tracing::info!(user_id = %agg.user_id, card_id = ?jwt_card_id, "login success");

        let user_info = serde_json::json!({
            "userId": agg.user_id,
            "username": agg.login_name,
            "displayName": agg.display_name,
            "email": agg.email,
            "phone": agg.phone,
            "status": agg.user_status,
            "hasLocalCredential": true,
        });

        let card_types: Vec<String> = cards_json
            .iter()
            .filter_map(|c| c.get("cardType").and_then(|v| v.as_str()).map(String::from))
            .collect();
        let roles = derive_roles_from_cards(&card_types);

        let permissions: Vec<String> = if let Some(card_id) = jwt_card_id {
            self.repository
                .find_login_permissions(card_id)
                .await?
                .into_iter()
                .map(|p| format!("{}:{}", p.resource_type, p.action_code))
                .collect()
        } else {
            vec![]
        };

        // 登录事件 MQ（fire-and-forget，对齐 Java loginEventProducer → astral.login.event）
        publish_login_event_async(
            agg.user_id,
            "local",
            req.client_ip.as_deref(),
            req.user_agent.as_deref(),
            true,
        );

        // 登录成功审计直写 DB（对齐 Java AuthServiceImpl 同步 auditLog 双写：
        // MQ 事件由 login.event consumer 异步落库，但 MQ producer 未注册/不可用期间
        // 同步审计保证 LOGIN_SUCCESS 不丢失）。失败时不阻断认证主链（与失败审计同策略）。
        record_login_success_audit(
            &state.db,
            agg.user_id,
            session_id,
            req.client_ip.as_deref(),
            req.user_agent.as_deref(),
        )
        .await;

        Ok(LoginResponse {
            access_token,
            refresh_token,
            token_type: "Bearer".into(),
            expires_in_millis,
            refresh_expires_in_millis,
            token: None,
            user: Some(user_info),
            identity_card: Some(serde_json::json!({
                "cardId": agg.card_id,
                "userId": agg.user_id,
                "status": agg.card_status,
                "tokenVersion": agg.token_version,
            })),
            current_card,
            available_cards: if cards_json.is_empty() {
                None
            } else {
                Some(cards_json)
            },
            permissions: Some(permissions),
            roles: Some(roles),
            enterprises: None,
            session: Some(serde_json::json!({
                "sessionId": session_id,
                "familyId": family_id,
                "sessionVersion": 1,
                "sessionEpoch": 1,
                "sessionState": "ACTIVE",
                "currentUserCardId": session_card_id,
            })),
        })
    }

    async fn login_failure_user_id(&self, req: &LoginRequest) -> Option<i64> {
        if has_oauth_input(req) {
            return None;
        }
        let username = req
            .username
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let phone = req
            .phone
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let email = req
            .email
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if username.is_none() && phone.is_none() && email.is_none() {
            return None;
        }
        self.repository
            .find_login_aggregate_resolved(username, phone, email)
            .await
            .ok()
            .flatten()
            .map(|aggregate| aggregate.user_id)
    }

    pub async fn login_third_party(
        &self,
        state: &AppState,
        req: &LoginRequest,
        provider: &str,
    ) -> Result<LoginResponse, AppError> {
        // Third-party identity verification is disabled. Reject before any
        // provider lookup, user creation, session creation, or token issuance.
        let _ = (state, req, provider);
        record_login_failure_audit(
            &state.db,
            None,
            req.client_ip.as_deref(),
            req.user_agent.as_deref(),
            "OAUTH_DISABLED".into(),
        )
        .await;
        Err(AppError::from(AstralError::Auth("OAUTH_DISABLED".into())))
    }

    pub async fn register(&self, _state: &AppState, req: &RegisterRequest) -> Result<(), AppError> {
        if req.username.trim().is_empty() || req.password.len() < 8 {
            return Err(AppError::from(AstralError::Validation(
                "username required, password min 8 chars".into(),
            )));
        }
        if self
            .repository
            .check_login_name_exists(&req.username)
            .await?
        {
            return Err(AppError::from(AstralError::Validation(
                "Username already exists".into(),
            )));
        }
        let hash = hash_password(&req.password)?;
        self.repository
            .insert_register_user(&req.username, &hash, req.real_name.as_deref(), None, None)
            .await?;
        tracing::info!(username = %req.username, "user registered");
        Ok(())
    }

    pub async fn get_profile(
        &self,
        _state: &AppState,
        user_id: i64,
    ) -> Result<serde_json::Value, AppError> {
        let row = self
            .repository
            .find_profile(user_id)
            .await?
            .ok_or_else(|| AppError::from(AstralError::NotFound("user not found".into())))?;
        Ok(serde_json::json!({
            "userId": row.user_id,
            "userNo": row.user_no,
            "username": row.username,
            "displayName": row.display_name,
            "email": row.email,
            "phone": row.phone,
            "avatarUrl": row.avatar_url,
            "status": row.status,
            "sourceType": row.source_type,
            "cardId": row.card_id,
        }))
    }

    pub async fn update_profile(
        &self,
        _state: &AppState,
        user_id: i64,
        req: &UpdateProfileRequest,
    ) -> Result<(), AppError> {
        let display_name = req.display_name.clone().or(req.real_name.clone());
        for (field, value, max_len) in [
            ("displayName", display_name.as_deref(), 128usize),
            ("email", req.email.as_deref(), 255usize),
            ("phone", req.phone.as_deref(), 32usize),
            ("avatarUrl", req.avatar_url.as_deref(), 512usize),
        ] {
            if let Some(value) = value {
                if value.trim().is_empty() || value.chars().count() > max_len {
                    return Err(AppError::from(AstralError::Validation(format!(
                        "{field} is blank or exceeds maximum length"
                    ))));
                }
            }
        }

        if let Some(email) = req.email.as_deref() {
            if self
                .repository
                .find_email_owner(email.trim(), user_id)
                .await?
                .is_some()
            {
                return Err(AppError::from(AstralError::Validation(
                    "email already exists".into(),
                )));
            }
        }
        // 手机号按登录同款规则归一化存储（对齐 Java 注册/写用户强制 normalizePhone）：
        // 用户写入 "+86 138-0013-8000" 若原样存，登录按 13800138000 反查将匹配不到。
        let normalized_phone = req.phone.as_deref().and_then(normalize_phone);
        if let Some(phone) = normalized_phone.as_deref() {
            if self
                .repository
                .find_phone_owner(phone, user_id)
                .await?
                .is_some()
            {
                return Err(AppError::from(AstralError::Validation(
                    "phone already exists".into(),
                )));
            }
        }

        self.repository
            .update_profile(
                user_id,
                display_name.as_deref(),
                req.email.as_deref(),
                normalized_phone.as_deref(),
                req.avatar_url.as_deref(),
            )
            .await?;
        tracing::info!(user_id, "profile updated");
        Ok(())
    }

    pub async fn change_password(
        &self,
        state: &AppState,
        user_id: i64,
        req: &ChangePasswordRequest,
    ) -> Result<(), AppError> {
        if req.new_password.len() < 8 {
            return Err(AppError::from(AstralError::Validation(
                "password length minimum 8".into(),
            )));
        }
        if req.old_password == req.new_password {
            return Err(AppError::from(AstralError::Validation(
                "new password must differ from old password".into(),
            )));
        }

        let credential = self
            .repository
            .load_password_credential(user_id)
            .await?
            .ok_or_else(|| {
                AppError::from(AstralError::Auth("local credential not found".into()))
            })?;
        if credential.status != "ACTIVE" {
            return Err(AppError::from(AstralError::Auth(
                "local credential is not active".into(),
            )));
        }
        verify_password(&req.old_password, &credential.password_hash).map_err(AppError::from)?;

        let new_hash = hash_password(&req.new_password).map_err(AppError::from)?;
        revoke_all_sessions_for_user(state, user_id, "PASSWORD_CHANGED")
            .await
            .map_err(AppError::from)?;
        self.repository
            .update_password_hash(user_id, &new_hash)
            .await
            .map_err(AppError::from)?;

        tracing::info!(user_id, "password changed and sessions revoked");
        Ok(())
    }
}

fn utc_db_datetime_after(seconds: i64) -> PrimitiveDateTime {
    let now = OffsetDateTime::now_utc() + Duration::seconds(seconds);
    PrimitiveDateTime::new(now.date(), now.time())
}

fn login_card_to_json(r: &crate::srv::auth_repository::LoginCardRecord) -> serde_json::Value {
    let action_codes_list: Vec<String> = r
        .action_codes
        .as_ref()
        .map(|s| {
            s.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let parse_i64_csv = |s: Option<&String>| -> Vec<i64> {
        s.map(|s| {
            s.split(',')
                .filter_map(|v| v.trim().parse::<i64>().ok())
                .collect()
        })
        .unwrap_or_default()
    };
    let rule_set_ids = parse_i64_csv(r.base_rule_set_ids.as_ref());
    let overlay_rule_set_ids = parse_i64_csv(r.overlay_rule_set_ids.as_ref());
    let is_starter = r.card_type == "STARTER_CARD";
    serde_json::json!({
        "cardId": r.card_id,
        "userId": r.user_id,
        "cardType": r.card_type,
        "cardStatus": r.card_status,
        "templateId": r.template_id,
        "levelId": r.level_id,
        "priority": r.priority,
        "isPrimary": r.is_primary,
        "domainId": r.domain_id,
        "tenantId": r.tenant_id,
        "templateCode": r.template_code,
        "templateName": r.template_name,
        "levelCode": r.level_code,
        "levelName": r.level_name,
        "levelNo": r.level_no,
        "cardName": r.card_name,
        "actionCodes": action_codes_list,
        "isDefault": r.is_primary,
        "isStarter": is_starter,
        "status": r.card_status,
        "ruleSetIds": rule_set_ids,
        "overlayRuleSetIds": overlay_rule_set_ids,
    })
}

/// 显式选卡（对齐 Java 不变式 15）：
/// - 0 张卡 → None（无卡签发，认证链后续拒绝）
/// - 1 张 ACTIVE 卡 → 自动签发
/// - 多张 ACTIVE 卡 → 必须提供 targetCardId 且命中候选列表；
///   缺失或非法目标返回 `CARD_SELECTION_REQUIRED`，不得创建任何会话/token/JTI 投影。
///
/// 登录事件 MQ 发布（fire-and-forget，对齐 Java loginEventProducer → astral.login.event）。
/// producer 未注册（MQ 延迟/不可用）时仅记 debug，登录主链路不受影响。
fn publish_login_event_async(
    user_id: i64,
    login_type: &str,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    success: bool,
) {
    if let Some(producer) = astral_common::service::global_mq_producer() {
        let login_type = login_type.to_string();
        let ip_address = ip_address.map(|s| s.to_string());
        let user_agent = user_agent.map(|s| s.to_string());
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.spawn(async move {
                if let Err(e) = producer
                    .publish_login_event(
                        user_id,
                        &login_type,
                        ip_address.as_deref(),
                        user_agent.as_deref(),
                        success,
                    )
                    .await
                {
                    tracing::warn!(user_id, error = %e, "login event publish failed");
                }
            });
        }
    } else {
        tracing::debug!(user_id, "MQ producer not registered, login event skipped");
    }
}

fn select_login_card(
    cards: &[serde_json::Value],
    target_card_id: Option<i64>,
) -> Result<Option<serde_json::Value>, AstralError> {
    match (cards.len(), target_card_id) {
        (0, _) => Err(AstralError::Auth("CARD_NOT_FOUND".into())),
        // 对齐 Java `issueTokensForCard`：显式 target 未命中候选统一返回
        // CARD_NOT_FOUND（单卡时 target 指向其他卡同样拒绝，不静默放行）。
        (1, Some(target)) if cards[0].get("cardId").and_then(|v| v.as_i64()) != Some(target) => {
            Err(AstralError::Auth("CARD_NOT_FOUND".into()))
        }
        (1, _) => Ok(cards.first().cloned()),
        (_, Some(target)) => cards
            .iter()
            .find(|c| c.get("cardId").and_then(|v| v.as_i64()) == Some(target))
            .cloned()
            .map(Some)
            .ok_or_else(|| AstralError::Auth("CARD_NOT_FOUND".into())),
        (_, None) => Err(AstralError::Auth("CARD_SELECTION_REQUIRED".into())),
    }
}

fn has_text(value: Option<&String>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
}

/// Match Java AuthenticationServiceImpl.hasOauthInput exactly, including
/// provider metadata and an explicitly supplied email_verified flag.
fn has_oauth_input(req: &LoginRequest) -> bool {
    has_text(req.provider.as_ref())
        || has_text(req.subject_key.as_ref())
        || has_text(req.account_key.as_ref())
        || has_text(req.provider_user_id.as_ref())
        || has_text(req.provider_account_id.as_ref())
        || has_text(req.provider_subject_id.as_ref())
        || has_text(req.provider_subject_type.as_ref())
        || has_text(req.provider_account_type.as_ref())
        || has_text(req.app_id.as_ref())
        || has_text(req.access_token.as_ref())
        || req.email_verified.is_some()
}

async fn record_login_failure_audit(
    pool: &sqlx::MySqlPool,
    user_id: Option<i64>,
    source_ip: Option<&str>,
    user_agent: Option<&str>,
    reason: String,
) {
    let entry = astral_common::audit::AuditEntry {
        // audit_log.user_id is NOT NULL; zero is the existing anonymous actor
        // sentinel used for failures where the account cannot be resolved.
        user_id: Some(user_id.unwrap_or(0)),
        card_id: None,
        action: "login".into(),
        resource: "identity".into(),
        decision: "DENY".into(),
        reason: Some(reason),
        event_type: astral_common::audit::AuditEventType::LoginFailure,
        category: Some(astral_common::audit::AuditCategory::IdentityLogin),
        source_ip: source_ip.map(str::to_owned),
        request_id: None,
        domain_id: None,
        tenant_id: None,
        detail: user_agent.map(|ua| format!("userAgent={ua}")),
    };
    if let Err(error) = astral_db::insert_audit_log(pool, &entry).await {
        tracing::warn!(error = %error, user_id = ?user_id, "login failure audit fallback failed");
    }
}

/// 登录成功审计直写 DB（对齐 Java AuthServiceImpl 同步 auditLog）。
///
/// MQ 事件由 login.event consumer 异步落库；此同步写入保证 MQ producer 未注册/
/// RabbitMQ 不可用期间 LOGIN_SUCCESS 审计不丢失。失败仅告警，不阻塞认证主链。
async fn record_login_success_audit(
    pool: &sqlx::MySqlPool,
    user_id: i64,
    _session_id: i64,
    source_ip: Option<&str>,
    user_agent: Option<&str>,
) {
    let entry = astral_common::audit::AuditEntry {
        user_id: Some(user_id),
        card_id: None,
        action: "login".into(),
        resource: "identity".into(),
        decision: "ALLOW".into(),
        reason: Some("LOGIN_SUCCESS".into()),
        event_type: astral_common::audit::AuditEventType::LoginSuccess,
        category: Some(astral_common::audit::AuditCategory::IdentityLogin),
        source_ip: source_ip.map(str::to_owned),
        request_id: None,
        domain_id: None,
        tenant_id: None,
        detail: user_agent.map(|ua| format!("userAgent={ua}")),
    };
    if let Err(error) = astral_db::insert_audit_log(pool, &entry).await {
        tracing::warn!(error = %error, user_id, "login success audit fallback failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card(id: i64) -> serde_json::Value {
        serde_json::json!({
            "cardId": id,
            "status": "ACTIVE",
        })
    }

    #[test]
    fn no_cards_returns_card_not_found() {
        let error = select_login_card(&[], None).unwrap_err();
        assert!(matches!(error, AstralError::Auth(message) if message == "CARD_NOT_FOUND"));
    }

    #[test]
    fn single_card_auto_selected() {
        let cards = vec![card(7)];
        let selected = select_login_card(&cards, None).unwrap();
        assert_eq!(selected.unwrap()["cardId"], 7);
    }

    #[test]
    fn multiple_cards_require_explicit_target() {
        let cards = vec![card(7), card(8)];
        let err = select_login_card(&cards, None).unwrap_err();
        assert!(matches!(err, AstralError::Auth(_)));
        assert!(err.to_string().contains("CARD_SELECTION_REQUIRED"));
    }

    #[test]
    fn explicit_target_selects_matching_card() {
        let cards = vec![card(7), card(8)];
        let selected = select_login_card(&cards, Some(8)).unwrap();
        assert_eq!(selected.unwrap()["cardId"], 8);
    }

    #[test]
    fn explicit_target_not_available_rejected() {
        let cards = vec![card(7), card(8)];
        let err = select_login_card(&cards, Some(99)).unwrap_err();
        assert!(matches!(err, AstralError::Auth(_)));
        assert!(err.to_string().contains("CARD_NOT_FOUND"));
    }

    #[test]
    fn single_card_with_mismatched_target_rejected() {
        // 对齐 Java issueTokensForCard：单卡时显式 target 指向其他卡同样拒绝
        let cards = vec![card(7)];
        let err = select_login_card(&cards, Some(99)).unwrap_err();
        assert!(matches!(err, AstralError::Auth(_)));
        assert!(err.to_string().contains("CARD_NOT_FOUND"));
        // 单卡 + target 命中 → 放行
        let selected = select_login_card(&cards, Some(7)).unwrap();
        assert_eq!(selected.unwrap()["cardId"], 7);
    }
    #[test]
    fn oauth_input_covers_java_login_request_fields() {
        let request: LoginRequest = serde_json::from_value(serde_json::json!({
            "provider": "",
            "subjectKey": "subject",
            "accountKey": "account",
            "providerUserId": "user",
            "providerAccountId": "account-id",
            "providerSubjectId": "subject-id",
            "providerSubjectType": "SUBJECT",
            "providerAccountType": "ACCOUNT",
            "appId": "app",
            "accessToken": "token",
            "emailVerified": false
        }))
        .unwrap();

        assert!(has_oauth_input(&request));
        assert_eq!(request.provider_subject_type.as_deref(), Some("SUBJECT"));
        assert_eq!(request.provider_account_type.as_deref(), Some("ACCOUNT"));
        assert_eq!(request.app_id.as_deref(), Some("app"));
        assert_eq!(request.email_verified, Some(false));
    }

    #[test]
    fn blank_oauth_metadata_does_not_override_local_login() {
        let request: LoginRequest = serde_json::from_value(serde_json::json!({
            "username": "alice",
            "password": "password",
            "provider": " ",
            "accessToken": ""
        }))
        .unwrap();

        assert!(!has_oauth_input(&request));
    }
}
