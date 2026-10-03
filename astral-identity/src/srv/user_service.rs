//! 用户管理应用服务 — 对应 Java `PlatformUserLifecycleService`。
//!
//! 写操作按 Java 契约：`setPassword`/禁用/删除 在同一编排内撤销该用户
//! 全部会话（先撤会话后写库，保持 fail-closed）。

use std::sync::Arc;

use serde::Deserialize;

use astral_common::contract::PageResponse;
use astral_common::error::AppError;
use astral_types::{AstralError, UserCard};

use crate::auth::hash_password;
use crate::srv::auth_repository::AuthRepository;
use crate::srv::session::revoke_all_sessions_for_user;
use crate::srv::user_repository::UserRepository;
use crate::AppState;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserQuery {
    pub status: Option<String>,
    pub page: Option<i64>,
    pub size: Option<i64>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserListItem {
    pub user_id: i64,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub status: String,
    pub cards: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub real_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub domain_id: Option<i64>,
    pub tenant_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserRequest {
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetPasswordRequest {
    pub password: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateStatusRequest {
    pub status: String,
}

pub struct UserService {
    users: Arc<dyn UserRepository>,
    auth: Arc<dyn AuthRepository>,
}

impl UserService {
    pub fn new(users: Arc<dyn UserRepository>, auth: Arc<dyn AuthRepository>) -> Self {
        Self { users, auth }
    }

    pub async fn list_users(
        &self,
        _state: &AppState,
        query: &UserQuery,
    ) -> Result<PageResponse<UserListItem>, AppError> {
        let page = query.page.unwrap_or(1).max(1);
        let size = query.size.unwrap_or(20).clamp(1, 100);
        let offset = (page - 1) * size;

        let total = self.users.count_users().await?;
        let users = self
            .users
            .list_users(size, offset)
            .await?
            .into_iter()
            .map(|row| UserListItem {
                user_id: row.user_id,
                username: row.username,
                display_name: row.display_name,
                email: row.email,
                phone: row.phone,
                status: row.status,
                cards: 0, // cards 计数需另查 user_card 表，列表场景默认 0
            })
            .collect();
        Ok(PageResponse::new(users, total, page, size))
    }

    pub async fn create_user(
        &self,
        _state: &AppState,
        req: &CreateUserRequest,
    ) -> Result<serde_json::Value, AppError> {
        if req.username.trim().is_empty() || req.password.len() < 8 {
            return Err(AppError(AstralError::Validation(
                "username required, password min 8 chars".into(),
            )));
        }
        if self.auth.check_login_name_exists(&req.username).await? {
            return Err(AppError(AstralError::Validation(
                "Username already exists".into(),
            )));
        }
        let password_hash = hash_password(&req.password)
            .map_err(|e| AppError(AstralError::Internal(e.to_string())))?;
        let (_uid, card_id) = self
            .auth
            .insert_register_user(
                &req.username,
                &password_hash,
                req.real_name.as_deref(),
                req.email.as_deref(),
                req.phone.as_deref(),
            )
            .await
            .map_err(AppError)?;

        tracing::info!(username = %req.username, card_id, "user created");
        Ok(serde_json::json!({
            "cardId": card_id,
            "username": req.username,
            "displayName": req.real_name,
            "status": "ACTIVE",
        }))
    }

    pub async fn get_user(
        &self,
        _state: &AppState,
        user_id: i64,
    ) -> Result<serde_json::Value, AppError> {
        let row =
            self.users.get_user(user_id).await?.ok_or_else(|| {
                AppError(AstralError::NotFound(format!("user {user_id} not found")))
            })?;
        Ok(serde_json::json!({
            "userId": row.user_id,
            "username": row.username,
            "displayName": row.display_name,
            "email": row.email,
            "phone": row.phone,
            "status": row.status,
        }))
    }

    pub async fn update_user(
        &self,
        state: &AppState,
        user_id: i64,
        req: &UpdateUserRequest,
    ) -> Result<(), AppError> {
        // 对齐 Java `PlatformUserLifecycleServiceImpl.update()`：状态变更为非 ACTIVE
        // （DISABLED 等）时先撤销全部会话，保持 fail-closed 顺序（与 update_user_status 一致）。
        if req
            .status
            .as_deref()
            .is_some_and(|status| status.to_uppercase() != "ACTIVE")
        {
            revoke_all_sessions_for_user(state, user_id, "USER_DISABLED")
                .await
                .map_err(AppError)?;
        }
        self.users
            .update_user(
                user_id,
                req.display_name.as_deref(),
                req.email.as_deref(),
                req.phone.as_deref(),
                req.status.as_deref(),
            )
            .await?;
        tracing::info!(user_id, "user updated");
        Ok(())
    }

    pub async fn update_user_status(
        &self,
        state: &AppState,
        user_id: i64,
        req: &UpdateStatusRequest,
    ) -> Result<(), AppError> {
        // Java `PlatformUserLifecycleService` 在禁用账号时撤销全部会话。
        if req.status != "ACTIVE" {
            revoke_all_sessions_for_user(state, user_id, "USER_DISABLED")
                .await
                .map_err(AppError)?;
        }
        self.users.update_user_status(user_id, &req.status).await?;
        tracing::info!(user_id, status = %req.status, "user status updated");
        Ok(())
    }

    pub async fn delete_user(&self, state: &AppState, user_id: i64) -> Result<(), AppError> {
        // Java `PlatformUserLifecycleService.delete` 在软删前撤销全部会话。
        revoke_all_sessions_for_user(state, user_id, "USER_DELETED")
            .await
            .map_err(AppError)?;
        self.users.soft_delete_user(user_id).await?;
        tracing::warn!(user_id, "user deleted (soft)");
        Ok(())
    }

    pub async fn list_user_cards(
        &self,
        _state: &AppState,
        user_id: i64,
    ) -> Result<Vec<UserCard>, AppError> {
        self.users
            .list_user_cards(user_id)
            .await
            .map_err(AppError::from)
    }

    pub async fn set_password(
        &self,
        state: &AppState,
        user_id: i64,
        req: &SetPasswordRequest,
    ) -> Result<(), AppError> {
        if req.password.len() < 8 {
            return Err(AppError(AstralError::Validation(
                "Password must be at least 8 characters".into(),
            )));
        }
        let password_hash = hash_password(&req.password)
            .map_err(|e| AppError(AstralError::Internal(e.to_string())))?;
        // Password hash, credential revision, sessions/families/JTIs, and the
        // durable v2 projection outbox commit together before external projection.
        let revoked_jtis = self
            .auth
            .update_password_hash_with_revocation(user_id, &password_hash, "PASSWORD_CHANGED", None)
            .await
            .map_err(AppError)?;
        #[cfg(feature = "redis-compat")]
        let redis = state.redis.as_ref();
        #[cfg(not(feature = "redis-compat"))]
        let redis: Option<&()> = None;
        crate::srv::session::project_password_revocation(state, &revoked_jtis, redis)
            .await
            .map_err(AppError)?;
        tracing::info!(user_id, "password set");
        Ok(())
    }

    /// 更新本地凭证密码哈希（password reset 用；透传 AuthRepository，对齐
    /// Java `PasswordResetService` 的 ARGON2ID 更新语义）。
    pub async fn update_password_hash(
        &self,
        user_id: i64,
        password_hash: &str,
    ) -> Result<(), AstralError> {
        self.auth.update_password_hash(user_id, password_hash).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::LoginAggregateRow;
    use crate::srv::auth_repository::{
        AuthRepository, IdentityCardRecord, LoginCardRecord, PermissionRecord, PlatformUserRecord,
        ProfileRecord,
    };
    use crate::srv::auth_service::AuthService;
    use async_trait::async_trait;

    struct FakeUserRepository {
        count: i64,
        users: Vec<crate::srv::user_repository::UserListRecord>,
    }

    #[async_trait]
    impl UserRepository for FakeUserRepository {
        async fn count_users(&self) -> Result<i64, AstralError> {
            Ok(self.count)
        }

        async fn list_users(
            &self,
            _size: i64,
            _offset: i64,
        ) -> Result<Vec<crate::srv::user_repository::UserListRecord>, AstralError> {
            Ok(self.users.clone())
        }

        async fn get_user(
            &self,
            user_id: i64,
        ) -> Result<Option<crate::srv::user_repository::UserListRecord>, AstralError> {
            Ok(self
                .users
                .iter()
                .find(|row| row.user_id == user_id)
                .cloned())
        }

        async fn update_user(
            &self,
            _user_id: i64,
            _display_name: Option<&str>,
            _email: Option<&str>,
            _phone: Option<&str>,
            _status: Option<&str>,
        ) -> Result<(), AstralError> {
            Ok(())
        }

        async fn update_user_status(
            &self,
            _user_id: i64,
            _status: &str,
        ) -> Result<(), AstralError> {
            Ok(())
        }

        async fn soft_delete_user(&self, _user_id: i64) -> Result<(), AstralError> {
            Ok(())
        }

        async fn list_user_cards(&self, _user_id: i64) -> Result<Vec<UserCard>, AstralError> {
            Ok(vec![])
        }
    }

    struct FakeAuthRepository;

    #[async_trait]
    impl AuthRepository for FakeAuthRepository {
        async fn find_login_aggregate(
            &self,
            _login: &str,
        ) -> Result<Option<LoginAggregateRow>, AstralError> {
            Ok(None)
        }

        async fn find_login_aggregate_resolved(
            &self,
            _username: Option<&str>,
            _phone: Option<&str>,
            _email: Option<&str>,
        ) -> Result<Option<LoginAggregateRow>, AstralError> {
            Ok(None)
        }

        async fn insert_register_user(
            &self,
            _username: &str,
            _password_hash: &str,
            _real_name: Option<&str>,
            _email: Option<&str>,
            _phone: Option<&str>,
        ) -> Result<(i64, i64), AstralError> {
            Ok((1, 1))
        }

        async fn load_password_credential(
            &self,
            _user_id: i64,
        ) -> Result<Option<crate::auth::PasswordCredential>, AstralError> {
            Ok(None)
        }

        async fn update_password_hash(
            &self,
            _user_id: i64,
            _new_hash: &str,
        ) -> Result<(), AstralError> {
            Ok(())
        }

        async fn update_password_hash_with_revocation(
            &self,
            _user_id: i64,
            _new_hash: &str,
            _reason: &str,
            _reset_token: Option<i64>,
        ) -> Result<Vec<String>, AstralError> {
            Ok(vec![])
        }

        async fn update_password_hash_if_current(
            &self,
            _user_id: i64,
            _expected_hash: &str,
            _expected_version: i64,
            _new_hash: &str,
        ) -> Result<Vec<String>, AstralError> {
            Ok(vec![])
        }

        async fn create_login_family_and_session(
            &self,
            _session: crate::srv::auth_repository::AtomicLoginSession,
        ) -> Result<(i64, i64), AstralError> {
            Ok((1, 1))
        }

        async fn update_last_login_at(&self, _user_id: i64) -> Result<(), AstralError> {
            Ok(())
        }

        async fn check_login_name_exists(&self, login_name: &str) -> Result<bool, AstralError> {
            Ok(login_name == "taken")
        }

        async fn find_identity_by_account(
            &self,
            _provider: &str,
            _account_key: &str,
        ) -> Result<Option<i64>, AstralError> {
            Ok(None)
        }

        async fn insert_identity(
            &self,
            _user_id: i64,
            _provider: &str,
            _account_key: &str,
            _subject_key: &str,
        ) -> Result<(), AstralError> {
            Ok(())
        }

        async fn find_platform_user(
            &self,
            _user_id: i64,
        ) -> Result<Option<PlatformUserRecord>, AstralError> {
            Ok(None)
        }

        async fn find_identity_card(
            &self,
            _user_id: i64,
        ) -> Result<Option<IdentityCardRecord>, AstralError> {
            Ok(None)
        }

        async fn find_login_cards(
            &self,
            _user_id: i64,
        ) -> Result<Vec<LoginCardRecord>, AstralError> {
            Ok(vec![])
        }

        async fn find_login_permissions(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRecord>, AstralError> {
            Ok(vec![])
        }

        async fn find_tenant_status(&self, _tenant_id: i64) -> Result<Option<String>, AstralError> {
            Ok(None)
        }

        async fn find_profile(&self, _user_id: i64) -> Result<Option<ProfileRecord>, AstralError> {
            Ok(None)
        }

        async fn find_email_owner(
            &self,
            _email: &str,
            _exclude_user_id: i64,
        ) -> Result<Option<i64>, AstralError> {
            Ok(None)
        }

        async fn find_phone_owner(
            &self,
            _phone: &str,
            _exclude_user_id: i64,
        ) -> Result<Option<i64>, AstralError> {
            Ok(None)
        }

        async fn update_profile(
            &self,
            _user_id: i64,
            _display_name: Option<&str>,
            _email: Option<&str>,
            _phone: Option<&str>,
            _avatar_url: Option<&str>,
        ) -> Result<(), AstralError> {
            Ok(())
        }

        async fn insert_login_session(
            &self,
            _session: crate::srv::auth_repository::NewLoginSession,
        ) -> Result<i64, AstralError> {
            Ok(1)
        }

        async fn update_initial_refresh_token(
            &self,
            _session_id: i64,
            _expected_hash: &str,
            _refresh_hash: &str,
            _refresh_expiry: time::PrimitiveDateTime,
        ) -> Result<(), AstralError> {
            Ok(())
        }

        async fn delete_active_family(
            &self,
            _family_id: i64,
            _user_id: i64,
        ) -> Result<(), AstralError> {
            Ok(())
        }
    }

    fn service() -> UserService {
        UserService::new(
            Arc::new(FakeUserRepository {
                count: 2,
                users: vec![crate::srv::user_repository::UserListRecord {
                    user_id: 1,
                    username: Some("alice".into()),
                    display_name: None,
                    email: Some("alice@example.com".into()),
                    phone: None,
                    status: "ACTIVE".into(),
                }],
            }),
            Arc::new(FakeAuthRepository),
        )
    }

    #[tokio::test]
    async fn list_users_passes_page_size_to_repository() {
        let service = service();
        let page = service
            .list_users(
                &state(),
                &UserQuery {
                    status: None,
                    page: Some(2),
                    size: Some(5),
                },
            )
            .await
            .unwrap();
        assert_eq!(page.total, 2);
        assert_eq!(page.page, 2);
        assert_eq!(page.size, 5);
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].username.as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn create_user_rejects_duplicate_login_name() {
        let service = service();
        let result = service
            .create_user(
                &state(),
                &CreateUserRequest {
                    username: "taken".into(),
                    password: "secret123".into(),
                    real_name: None,
                    email: None,
                    phone: None,
                    domain_id: None,
                    tenant_id: None,
                },
            )
            .await;
        assert!(result.is_err());
    }

    fn state() -> AppState {
        let db = sqlx::MySqlPool::connect_lazy("mysql://localhost:1/identity").unwrap();
        AppState {
            config: Arc::new(astral_common::config::AppConfig::default()),
            db,
            // Redis-free 默认路径：兼容 adapter 未安装（None）。仅 redis-compat
            // feature 编译（feature-off 构建中该字段不存在）。
            #[cfg(feature = "redis-compat")]
            redis: None,
            engine: Arc::new(policy_engine::PolicyEngine::new()),
            me_service: Arc::new(crate::srv::me_service::MeService::new(Arc::new(
                SqlxMeRepositoryLazy,
            ))),
            auth_service: Arc::new(AuthService::new(Arc::new(FakeAuthRepository))),
            user_service: Arc::new(UserService::new(
                Arc::new(FakeUserRepository {
                    count: 2,
                    users: vec![crate::srv::user_repository::UserListRecord {
                        user_id: 1,
                        username: Some("alice".into()),
                        display_name: None,
                        email: Some("alice@example.com".into()),
                        phone: None,
                        status: "ACTIVE".into(),
                    }],
                }),
                Arc::new(FakeAuthRepository),
            )),
            card_repository: Arc::new(crate::srv::card_repository::SqlxCardRepository::new(
                sqlx::MySqlPool::connect_lazy("mysql://localhost:1/identity").unwrap(),
            )),
            org_service: Arc::new(crate::srv::org_service::OrgService::new(Arc::new(
                crate::srv::org_repository::SqlxOrgRepository::new(
                    sqlx::MySqlPool::connect_lazy("mysql://localhost:1/identity").unwrap(),
                ),
            ))),
            org_scope_enabled: false,
        }
    }

    struct SqlxMeRepositoryLazy;

    #[async_trait]
    impl crate::srv::me_repository::MeRepository for SqlxMeRepositoryLazy {
        async fn find_profile(
            &self,
            _user_id: i64,
        ) -> Result<Option<crate::srv::me_repository::ProfileRecord>, AstralError> {
            Ok(None)
        }

        async fn find_active_cards(
            &self,
            _user_id: i64,
        ) -> Result<Vec<crate::srv::me_repository::UserCardRecord>, AstralError> {
            Ok(vec![])
        }

        async fn find_identities(
            &self,
            _user_id: i64,
        ) -> Result<Vec<crate::srv::me_repository::IdentityRecord>, AstralError> {
            Ok(vec![])
        }

        async fn resolve_card(
            &self,
            _user_id: i64,
            _requested_card_id: Option<i64>,
        ) -> Result<Option<i64>, AstralError> {
            Ok(None)
        }

        async fn find_effective_permissions(
            &self,
            _card_id: i64,
        ) -> Result<Vec<crate::srv::me_repository::PermissionRecord>, AstralError> {
            Ok(vec![])
        }
    }
}
