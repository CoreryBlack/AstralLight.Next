//! 用户管理应用服务 — 对应 Java `PlatformUserLifecycleService`。
//!
//! 写操作按 Java 契约：`setPassword`/禁用/删除 在同一编排内撤销该用户
//! 全部会话（先撤会话后写库，保持 fail-closed）。
//!
//! status-bearing 更新（`update_user` 携带 status）影响有效资格：先要求并
//! 验证 proof-bound `AuthorizationAdmission`（缺失 → PENDING，零 session
//! revoke 副作用），通过后保持 先撤会话 → repository 资格/状态 mutation 的
//! 顺序；纯 profile metadata 更新不要求 admission（非资格语义）。

use std::sync::Arc;

use serde::Deserialize;

use astral_common::contract::PageResponse;
use astral_common::error::AppError;
use astral_types::{AstralError, AuthorizationAdmission, UserCard};

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
        request_operation_id: Option<&str>,
        admission: Option<AuthorizationAdmission>,
    ) -> Result<(), AppError> {
        // 状态变更（status-bearing）影响有效资格：在产生任何 durable 副作用
        // （session revoke）之前，先要求并验证 proof-bound admission。缺失或
        // proof 契约非法时 fail-closed 返回 PENDING，绝不先撤销会话（durable
        // 的 caller-card/frontier 复核与一次性消费仍在 repository source
        // 事务内执行，见 `user_repository::update_user` 状态分支）。
        // 纯 profile metadata 更新（status=None）保持明确非资格语义：不要求
        // admission，不撤销会话。
        let status_bearing = req.status.is_some();
        let admission = if status_bearing {
            let admission = admission.ok_or_else(|| {
                AppError(AstralError::Pending(
                    "status-bearing user update requires proof-bound authorization admission"
                        .into(),
                ))
            })?;
            admission
                .proof()
                .validate()
                .map_err(|error| AppError(AstralError::Pending(error.to_string())))?;
            Some(admission)
        } else {
            admission
        };
        // 对齐 Java `PlatformUserLifecycleServiceImpl.update()`：状态变更为非 ACTIVE
        // （DISABLED 等）时先撤销全部会话，保持 fail-closed 顺序（与 update_user_status 一致）。
        if status_bearing
            && req
                .status
                .as_deref()
                .is_some_and(|status| status.to_uppercase() != "ACTIVE")
        {
            revoke_all_sessions_for_user(state, user_id, "USER_DISABLED", request_operation_id)
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
                admission,
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
        request_operation_id: Option<&str>,
        admission: AuthorizationAdmission,
    ) -> Result<(), AppError> {
        // Validate the carried proof before the session revoke side effect. The
        // repository repeats durable frontier/scope validation inside its source
        // transaction; this early structural gate prevents malformed admissions
        // from revoking sessions before that transaction can reject them.
        admission
            .proof()
            .validate()
            .map_err(|error| AppError(AstralError::Pending(error.to_string())))?;
        // Java `PlatformUserLifecycleService` 在禁用账号时撤销全部会话。
        if req.status != "ACTIVE" {
            revoke_all_sessions_for_user(state, user_id, "USER_DISABLED", request_operation_id)
                .await
                .map_err(AppError)?;
        }
        self.users
            .update_user_status(user_id, &req.status, admission)
            .await?;
        tracing::info!(user_id, status = %req.status, "user status updated");
        Ok(())
    }

    pub async fn delete_user(
        &self,
        state: &AppState,
        user_id: i64,
        request_operation_id: Option<&str>,
        admission: AuthorizationAdmission,
    ) -> Result<(), AppError> {
        // Keep the same pre-side-effect guard as status updates. Durable
        // authority revalidation remains owned by the source repository.
        admission
            .proof()
            .validate()
            .map_err(|error| AppError(AstralError::Pending(error.to_string())))?;
        // Java `PlatformUserLifecycleService.delete` 在软删前撤销全部会话。
        revoke_all_sessions_for_user(state, user_id, "USER_DELETED", request_operation_id)
            .await
            .map_err(AppError)?;
        self.users.soft_delete_user(user_id, admission).await?;
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
        user_id: i64,
        req: &SetPasswordRequest,
        admission: AuthorizationAdmission,
    ) -> Result<(), AppError> {
        if req.password.len() < 8 {
            return Err(AppError(AstralError::Validation(
                "Password must be at least 8 characters".into(),
            )));
        }
        let password_hash = hash_password(&req.password)
            .map_err(|e| AppError(AstralError::Internal(e.to_string())))?;
        // Password hash, credential revision, sessions/families/JTIs, and the
        // durable revocation outbox commit together before local deny acceleration.
        let revoked_jtis = self
            .auth
            .update_password_hash_with_revocation(
                user_id,
                &password_hash,
                "PASSWORD_CHANGED",
                None,
                Some(admission),
            )
            .await
            .map_err(AppError)?;
        crate::srv::session::project_password_revocation(&revoked_jtis)
            .await
            .map_err(AppError)?;
        tracing::info!(user_id, "password set");
        Ok(())
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeUserRepository {
        count: i64,
        users: Vec<crate::srv::user_repository::UserListRecord>,
        /// 记录 repository mutation 次数：断言 guard 拒绝路径零 mutation。
        update_calls: Arc<AtomicUsize>,
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
            _admission: Option<AuthorizationAdmission>,
        ) -> Result<(), AstralError> {
            self.update_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn update_user_status(
            &self,
            _user_id: i64,
            _status: &str,
            _admission: AuthorizationAdmission,
        ) -> Result<(), AstralError> {
            Ok(())
        }

        async fn soft_delete_user(
            &self,
            _user_id: i64,
            _admission: AuthorizationAdmission,
        ) -> Result<(), AstralError> {
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

        async fn update_password_hash_with_revocation(
            &self,
            _user_id: i64,
            _new_hash: &str,
            _reason: &str,
            _reset_token: Option<i64>,
            _admission: Option<AuthorizationAdmission>,
        ) -> Result<Vec<String>, AstralError> {
            Ok(vec![])
        }

        async fn update_password_hash_if_current(
            &self,
            _user_id: i64,
            _expected_hash: &str,
            _expected_version: i64,
            _new_hash: &str,
            _admission: AuthorizationAdmission,
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
            _admission: AuthorizationAdmission,
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
        service_with_recorder().0
    }

    /// 带 mutation 计数的 service 构造：guard 拒绝路径断言零 repository mutation。
    fn service_with_recorder() -> (UserService, Arc<AtomicUsize>) {
        let update_calls = Arc::new(AtomicUsize::new(0));
        let service = UserService::new(
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
                update_calls: Arc::clone(&update_calls),
            }),
            Arc::new(FakeAuthRepository),
        );
        (service, update_calls)
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

    /// 结构合法的 fixture admission（`from_verified_proof` 只做结构校验，
    /// 与 org_repository/user_repository 测试同做法；不做任何 IO）。
    fn admission_fixture() -> AuthorizationAdmission {
        AuthorizationAdmission::from_verified_proof(astral_types::AuthorizationFenceProof {
            authorization_edition: astral_types::AUTHORIZATION_EDITION,
            authority_id: "authority-a".to_owned(),
            authority_term: 1,
            global_fence_sequence: 2,
            scope: astral_types::AuthorizationAuthorityScope {
                tenant_id: 1,
                card_id: 1,
                user_id: Some(1),
                domain: astral_types::AuthorizationDomainScope::Any,
            },
            scope_generation: 2,
            revoke_watermark: 1,
            snapshot_hash: "ab".repeat(32),
            parent_hash: None,
            operation_id: "operation-1".to_owned(),
            event_id: "event-1".to_owned(),
            key_id: "key-1".to_owned(),
            key_epoch: 1,
            issued_at: 100,
            not_before: 99,
            expires_at: 110,
            request_nonce: "nonce-1".to_owned(),
            request_binding_digest: None,
            scope_certificate_hash: None,
            proof_id: "proof-1".to_owned(),
            signature: "00".repeat(64),
        })
        .expect("structural fixture admission")
    }

    /// status-bearing 更新缺 admission → 在任何 durable 副作用（session
    /// revoke / repository mutation）之前 fail-closed PENDING。
    #[tokio::test]
    async fn status_bearing_update_without_admission_is_pending_before_any_side_effect() {
        let (service, update_calls) = service_with_recorder();
        let error = service
            .update_user(
                &state(),
                1,
                &UpdateUserRequest {
                    display_name: None,
                    email: None,
                    phone: None,
                    status: Some("DISABLED".into()),
                },
                Some("req-op-1"),
                None,
            )
            .await
            .expect_err("missing admission must fail closed");
        assert!(
            matches!(error, AppError(AstralError::Pending(_))),
            "missing admission is a safe PENDING, not an implicit allow: {error:?}"
        );
        assert_eq!(
            update_calls.load(Ordering::SeqCst),
            0,
            "guard rejection must not reach the user repository mutation"
        );
    }

    /// 携带结构合法 admission 的 status-bearing 更新通过 guard 到达 repository
    ///（ACTIVE 状态不触发 session revoke，测试无需真实 DB）。
    #[tokio::test]
    async fn status_bearing_update_with_admission_passes_guard_to_repository() {
        let (service, update_calls) = service_with_recorder();
        service
            .update_user(
                &state(),
                1,
                &UpdateUserRequest {
                    display_name: None,
                    email: None,
                    phone: None,
                    status: Some("ACTIVE".into()),
                },
                Some("req-op-1"),
                Some(admission_fixture()),
            )
            .await
            .expect("admitted status-bearing update must pass the guard");
        assert_eq!(
            update_calls.load(Ordering::SeqCst),
            1,
            "admitted update must reach the repository exactly once"
        );
    }

    /// 纯 profile metadata 更新（status=None）保持明确非资格语义：不要求
    /// admission、不撤销会话、正常到达 repository。
    #[tokio::test]
    async fn profile_only_update_requires_no_admission() {
        let (service, update_calls) = service_with_recorder();
        service
            .update_user(
                &state(),
                1,
                &UpdateUserRequest {
                    display_name: Some("Alice".into()),
                    email: None,
                    phone: None,
                    status: None,
                },
                Some("req-op-1"),
                None,
            )
            .await
            .expect("profile-only update must not require an admission");
        assert_eq!(
            update_calls.load(Ordering::SeqCst),
            1,
            "profile-only update must still reach the repository"
        );
    }

    /// 源形状/顺序守卫：status-bearing `update_user` 内 admission guard
    /// （要求 + proof 契约验证）必须先于 `revoke_all_sessions_for_user`，
    /// revoke 必须先于 repository mutation——缺 admission 时绝不先产生
    /// session revoke durable 副作用。
    #[test]
    fn status_bearing_update_orders_admission_guard_before_revoke_before_repository_mutation() {
        let source = include_str!("user_service.rs");
        let body = source
            .split("pub async fn update_user(")
            .nth(1)
            .and_then(|rest| rest.split("pub async fn update_user_status(").next())
            .expect("update_user body must stay delimited in user_service.rs");
        let guard = body
            .find("status-bearing user update requires proof-bound authorization admission")
            .expect("status-bearing update must require a proof-bound admission");
        let guard_proof = body
            .find(".proof()")
            .expect("guard must revalidate the proof contract");
        let guard_validated = body
            .find(".validate()")
            .expect("guard must revalidate the proof contract");
        let revoke = body
            .find("revoke_all_sessions_for_user(state")
            .expect("session revoke call must stay in update_user");
        let mutation = body
            .find(".update_user(")
            .expect("repository mutation must stay in update_user");
        assert!(
            guard < guard_proof
                && guard_proof < guard_validated
                && guard_validated < revoke
                && revoke < mutation,
            "update_user must order admission guard < revoke call < repository mutation \
             (guard at {guard}, proof at {guard_proof}, validated at {guard_validated}, \
             revoke at {revoke}, mutate at {mutation})"
        );
    }

    fn state() -> AppState {
        let db = sqlx::MySqlPool::connect_lazy("mysql://localhost:1/identity").unwrap();
        AppState {
            config: Arc::new(astral_common::config::AppConfig::default()),
            db,
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
                    update_calls: Arc::new(AtomicUsize::new(0)),
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
            password_reset_notifier: Arc::new(
                crate::srv::password::UnavailablePasswordResetNotifier,
            ),
            authorization_fence_provider: None,
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
