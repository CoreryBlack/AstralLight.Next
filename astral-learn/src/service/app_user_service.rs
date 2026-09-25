//! App 用户登录编排 — AppUserService
//!
//! 对齐 Java `AppUserLoginServiceImpl`：验证码原子消费 → find-or-create 用户 →
//! Gateway internal-v1 会话签发 → 失败补偿删除新建用户。
//! 所有存储/HTTP 失败统一映射为非披露性 Auth 错误（对齐原 handler invalid_login）。
//! 会话签发经注入 `AppSessionIssuer`（测试注入失败 fake，验证补偿编排）。

use std::sync::Arc;

use crate::repository::app_user_repository::AppUserRepository;
use astral_common::middleware::internal_signature::{
    compute_internal_signature, normalize_query, sha256_hex, InternalSignatureInput,
    INTERNAL_BODY_SHA256_HEADER, INTERNAL_CALLER_HEADER, INTERNAL_CALLER_LEARN,
    INTERNAL_IDEMPOTENCY_HEADER, INTERNAL_KEY_ID_HEADER, INTERNAL_NONCE_HEADER,
    INTERNAL_PROTOCOL_HEADER, INTERNAL_PROTOCOL_VERSION, INTERNAL_REQUEST_ID_HEADER,
    INTERNAL_ROUTE_HEADER, INTERNAL_SERVICE_HEADER, INTERNAL_SESSION_PATH,
    INTERNAL_SIGNATURE_HEADER, INTERNAL_TIMESTAMP_HEADER, KEY_ID_LEARN_TO_GATEWAY,
    ROUTE_LEARN_TO_GATEWAY,
};
use astral_types::AstralError;

/// App 登录验证码用途（对齐原常量）
pub const APP_LOGIN_VERIFICATION_PURPOSE: &str = "APP_LOGIN";

/// 非披露性登录错误（与验证码缺失/无效/过期/存储失败不可区分）
pub fn invalid_login() -> AstralError {
    AstralError::Auth("Invalid login credentials".into())
}

/// 会话签发副作用端口（外部 identity 服务；测试注入失败 fake）
#[async_trait::async_trait]
pub trait AppSessionIssuer: Send + Sync {
    /// 签发 App 会话（Learn -> Gateway internal-v1；失败返回非披露性 Auth 错误）
    async fn issue_session(
        &self,
        gateway_service_uri: &str,
        user_id: i64,
        internal_service_secret: &str,
    ) -> Result<serde_json::Value, AstralError>;
}

/// 生产实现：调用 Gateway `/api/v1/auth/internal/sessions`
pub struct HmacAppSessionIssuer;

#[async_trait::async_trait]
impl AppSessionIssuer for HmacAppSessionIssuer {
    async fn issue_session(
        &self,
        gateway_service_uri: &str,
        user_id: i64,
        internal_service_secret: &str,
    ) -> Result<serde_json::Value, AstralError> {
        if gateway_service_uri.trim().is_empty() {
            return Err(AstralError::Config(
                "gateway_service_uri is not configured".into(),
            ));
        }
        if internal_service_secret.len() < 32 {
            return Err(AstralError::Config(
                "internal_service_secret is not configured".into(),
            ));
        }
        let body = serde_json::to_vec(&serde_json::json!({ "userId": user_id }))
            .map_err(|_| invalid_login())?;
        let body_hash = sha256_hex(&body);
        let timestamp = chrono_like_timestamp_ms();
        let nonce = uuid::Uuid::new_v4().to_string();
        let request_id = uuid::Uuid::new_v4().to_string();
        let idempotency_key = uuid::Uuid::new_v4().to_string();
        let query = normalize_query(None);
        let target_user_id = user_id.to_string();
        let input = InternalSignatureInput {
            protocol_version: INTERNAL_PROTOCOL_VERSION,
            key_id: KEY_ID_LEARN_TO_GATEWAY,
            caller_service: INTERNAL_CALLER_LEARN,
            method: "POST",
            path: INTERNAL_SESSION_PATH,
            normalized_query: &query,
            body_sha256: &body_hash,
            target_user_id: &target_user_id,
            timestamp: &timestamp,
            nonce: &nonce,
            request_id: &request_id,
            idempotency_key: &idempotency_key,
            route: ROUTE_LEARN_TO_GATEWAY,
        };
        let signature = compute_internal_signature(internal_service_secret, &input);
        let base = gateway_service_uri.trim_end_matches('/');
        let response = reqwest::Client::new()
            .post(format!("{base}{INTERNAL_SESSION_PATH}"))
            .header("content-type", "application/json")
            .header(INTERNAL_PROTOCOL_HEADER, INTERNAL_PROTOCOL_VERSION)
            .header(INTERNAL_SERVICE_HEADER, INTERNAL_CALLER_LEARN)
            .header(INTERNAL_CALLER_HEADER, INTERNAL_CALLER_LEARN)
            .header(INTERNAL_TIMESTAMP_HEADER, &timestamp)
            .header(INTERNAL_NONCE_HEADER, &nonce)
            .header(INTERNAL_REQUEST_ID_HEADER, &request_id)
            .header(INTERNAL_IDEMPOTENCY_HEADER, &idempotency_key)
            .header(INTERNAL_BODY_SHA256_HEADER, &body_hash)
            .header(INTERNAL_SIGNATURE_HEADER, &signature)
            .header(INTERNAL_KEY_ID_HEADER, KEY_ID_LEARN_TO_GATEWAY)
            .header(INTERNAL_ROUTE_HEADER, ROUTE_LEARN_TO_GATEWAY)
            .body(body)
            .send()
            .await
            .map_err(|_| invalid_login())?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(invalid_login());
        }
        let envelope: astral_common::contract::ApiResponse<serde_json::Value> =
            response.json().await.map_err(|_| invalid_login())?;
        if !envelope.success {
            return Err(invalid_login());
        }
        envelope.data.ok_or_else(invalid_login)
    }
}

/// 登录结果
#[derive(Debug, Clone)]
pub struct AppLoginOutcome {
    pub user_id: i64,
    /// 已存在用户可能无 phone（对齐原 handler 响应 Option 语义）
    pub phone: Option<String>,
    pub nickname: Option<String>,
    pub is_new: bool,
    pub session: serde_json::Value,
}

/// AppUserService（依赖注入 repository + 会话签发副作用）
pub struct AppUserService {
    repo: Arc<dyn AppUserRepository>,
    session_issuer: Arc<dyn AppSessionIssuer>,
}

impl AppUserService {
    pub fn new(
        repo: Arc<dyn AppUserRepository>,
        session_issuer: Arc<dyn AppSessionIssuer>,
    ) -> Self {
        Self {
            repo,
            session_issuer,
        }
    }

    /// App 登录：原子消费验证码 → find-or-create → 签发会话（失败补偿）
    pub async fn login(
        &self,
        gateway_service_uri: &str,
        internal_service_secret: &str,
        phone: String,
        code: &str,
    ) -> Result<AppLoginOutcome, AstralError> {
        // 原子消费（fail-closed；并发防复用）
        let consumed = self
            .repo
            .consume_verification_code(&phone, APP_LOGIN_VERIFICATION_PURPOSE, code)
            .await
            .map_err(|_| invalid_login())?;
        if !consumed {
            return Err(invalid_login());
        }

        let user = self
            .repo
            .find_by_phone(&phone)
            .await
            .map_err(|_| invalid_login())?;

        match user {
            Some(u) if u.status.eq_ignore_ascii_case("ACTIVE") => {
                let session = match self
                    .session_issuer
                    .issue_session(gateway_service_uri, u.id, internal_service_secret)
                    .await
                {
                    Ok(s) => s,
                    Err(error) => {
                        tracing::error!(user_id = u.id, %error, "identity session failed after verification consumption; code remains consumed");
                        return Err(invalid_login());
                    }
                };
                Ok(AppLoginOutcome {
                    user_id: u.id,
                    phone: u.phone,
                    nickname: u.nickname,
                    is_new: false,
                    session,
                })
            }
            Some(_) => Err(invalid_login()),
            None => {
                let nickname = format!(
                    "user_{}",
                    phone
                        .chars()
                        .filter(|c| c.is_ascii_digit())
                        .take(4)
                        .collect::<String>()
                );
                let user_id = self
                    .repo
                    .create(&phone, &nickname)
                    .await
                    .map_err(|_| invalid_login())?;
                let session = match self
                    .session_issuer
                    .issue_session(gateway_service_uri, user_id, internal_service_secret)
                    .await
                {
                    Ok(s) => s,
                    Err(error) => {
                        // 验证码一次性且保持已消费；仅删除本次新建的用户（已存在用户永不删除）
                        if let Err(cleanup_error) =
                            self.repo.cleanup_new_user(user_id, &phone).await
                        {
                            tracing::error!(user_id, %error, %cleanup_error, "new user session failed and cleanup failed; manual compensation required");
                            return Err(AstralError::Database(
                                "login compensation requires manual cleanup".into(),
                            ));
                        }
                        tracing::warn!(user_id, %error, "new user removed after identity session failure; code remains consumed");
                        return Err(invalid_login());
                    }
                };
                Ok(AppLoginOutcome {
                    user_id,
                    phone: Some(phone),
                    nickname: Some(nickname),
                    is_new: true,
                    session,
                })
            }
        }
    }
}

fn chrono_like_timestamp_ms() -> String {
    time::OffsetDateTime::now_utc()
        .unix_timestamp_nanos()
        .div_euclid(1_000_000)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::app_user_repository::AppUserRecord;
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// Fake AppUserRepository（记录消费/创建/补偿调用）
    struct FakeAppUserRepository {
        consumed: Mutex<bool>,
        existing: Mutex<Option<AppUserRecord>>,
        created: Mutex<Vec<String>>,
        cleanup: Mutex<Vec<(i64, String)>>,
    }

    impl FakeAppUserRepository {
        fn new(consumed: bool, existing: Option<AppUserRecord>) -> Self {
            Self {
                consumed: Mutex::new(consumed),
                existing: Mutex::new(existing),
                created: Mutex::new(Vec::new()),
                cleanup: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl AppUserRepository for FakeAppUserRepository {
        async fn consume_verification_code(
            &self,
            _phone: &str,
            _purpose: &str,
            _code: &str,
        ) -> Result<bool, AstralError> {
            Ok(*self.consumed.lock().unwrap())
        }

        async fn find_by_phone(&self, _phone: &str) -> Result<Option<AppUserRecord>, AstralError> {
            Ok(self.existing.lock().unwrap().clone())
        }

        async fn find_by_id(&self, _id: i64) -> Result<Option<AppUserRecord>, AstralError> {
            Ok(None)
        }

        async fn create(&self, phone: &str, _nickname: &str) -> Result<i64, AstralError> {
            self.created.lock().unwrap().push(phone.to_string());
            Ok(7)
        }

        async fn cleanup_new_user(&self, user_id: i64, phone: &str) -> Result<(), AstralError> {
            self.cleanup
                .lock()
                .unwrap()
                .push((user_id, phone.to_string()));
            Ok(())
        }
    }

    /// Fake 会话签发：总是失败（模拟 identity 服务不可用）
    struct FailingSessionIssuer;

    #[async_trait]
    impl AppSessionIssuer for FailingSessionIssuer {
        async fn issue_session(
            &self,
            _gateway_service_uri: &str,
            _user_id: i64,
            _internal_service_secret: &str,
        ) -> Result<serde_json::Value, AstralError> {
            Err(invalid_login())
        }
    }

    fn active_user() -> AppUserRecord {
        AppUserRecord {
            id: 3,
            phone: Some("+8613800138000".into()),
            nickname: Some("existing".into()),
            avatar_url: None,
            status: "ACTIVE".into(),
        }
    }

    #[tokio::test]
    async fn login_rejects_when_code_not_consumed() {
        // 验证码消费失败 → 非披露性 Auth 错误，不创建用户
        let repo = Arc::new(FakeAppUserRepository::new(false, None));
        let svc = AppUserService::new(repo.clone(), Arc::new(FailingSessionIssuer));
        let err = svc
            .login("", "", "13800138000".into(), "123456")
            .await
            .unwrap_err();
        assert!(matches!(err, AstralError::Auth(_)));
        assert!(repo.created.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn new_user_session_failure_compensates_with_cleanup() {
        // 新用户 + 会话失败 → 补偿删除本次新建用户（已消费验证码）
        let repo = Arc::new(FakeAppUserRepository::new(true, None));
        let svc = AppUserService::new(repo.clone(), Arc::new(FailingSessionIssuer));
        let err = svc
            .login("", "", "13800138000".into(), "123456")
            .await
            .unwrap_err();
        assert!(matches!(err, AstralError::Auth(_)));
        assert_eq!(repo.created.lock().unwrap().clone(), vec!["13800138000"]);
        assert_eq!(
            repo.cleanup.lock().unwrap().clone(),
            vec![(7, "13800138000".to_string())]
        );
    }

    #[tokio::test]
    async fn existing_user_session_failure_does_not_cleanup() {
        // 已存在用户 + 会话失败 → 不删除用户（仅消费验证码）
        let repo = Arc::new(FakeAppUserRepository::new(true, Some(active_user())));
        let svc = AppUserService::new(repo.clone(), Arc::new(FailingSessionIssuer));
        let err = svc
            .login("", "", "13800138000".into(), "123456")
            .await
            .unwrap_err();
        assert!(matches!(err, AstralError::Auth(_)));
        assert!(repo.created.lock().unwrap().is_empty());
        assert!(repo.cleanup.lock().unwrap().is_empty());
    }
}
