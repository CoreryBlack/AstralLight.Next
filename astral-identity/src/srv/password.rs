//! 密码重置流程 — HTTP adapter
//!
//! 对应 Java `PasswordResetController` + `PasswordResetService`。
//! 流程：请求重置 → 验证令牌 → 设置新密码。
//! 令牌存储于 password_reset_token 表，使用 SHA-256 哈希存储；
//! 数据访问在 `astral-db`（token 表 CRUD）+ `user_repository`（密码哈希更新）。

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;

use astral_common::contract::{ApiResponse, EmptyResponse};
use astral_common::error::AppError;
use astral_db::find_valid_password_reset_token;
use astral_types::AstralError;

use crate::auth::{hash_password, sha256_hash};
use crate::srv::auth_repository::{AuthRepository, SqlxAuthRepository};
use crate::srv::session::project_password_revocation;
use crate::AppState;

const PASSWORD_RESET_DELIVERY_UNAVAILABLE_MESSAGE: &str = "Password reset delivery is unavailable";
const PASSWORD_RESET_DELIVERY_UNAVAILABLE_REASON: &str = "PASSWORD_RESET_DELIVERY_UNAVAILABLE";

/// The Identity-owned delivery boundary for password reset credentials.
///
/// Implementations must be installed only after the reset hash is durable and
/// must never log, audit, or persist the raw token. The current workspace has
/// no approved provider or encrypted outbox consumer, so the only implementation
/// is [`UnavailablePasswordResetNotifier`].
#[async_trait::async_trait]
pub trait PasswordResetNotifier: Send + Sync {
    async fn deliver(
        &self,
        notification: PasswordResetNotification<'_>,
    ) -> Result<(), PasswordResetDeliveryError>;
}

/// In-memory notification input. It deliberately does not implement `Debug`,
/// `Serialize`, or `Clone`, preventing accidental inclusion in logs or payloads.
pub struct PasswordResetNotification<'a> {
    operation_id: &'a str,
    recipient: &'a str,
    token: &'a str,
    expires_at: time::PrimitiveDateTime,
}

impl<'a> PasswordResetNotification<'a> {
    fn new(
        operation_id: &'a str,
        recipient: &'a str,
        token: &'a str,
        expires_at: time::PrimitiveDateTime,
    ) -> Self {
        Self {
            operation_id,
            recipient,
            token,
            expires_at,
        }
    }

    /// Stable non-secret identity for this reset handoff.
    pub fn operation_id(&self) -> &str {
        self.operation_id
    }

    /// The destination identifier for a future approved delivery provider.
    pub fn recipient(&self) -> &str {
        self.recipient
    }

    /// The raw token exists only in memory for an approved delivery provider.
    /// Callers must not log, audit, or persist this value.
    pub fn token(&self) -> &str {
        self.token
    }

    pub fn expires_at(&self) -> time::PrimitiveDateTime {
        self.expires_at
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PasswordResetDeliveryError {
    #[error("password reset delivery unavailable")]
    Unavailable,
}

/// Derive a stable, non-secret handoff identity from the durable token hash.
/// The raw token never crosses this boundary and is not included in the id.
fn password_reset_operation_id(user_id: i64, token_hash: &str) -> String {
    format!(
        "password-reset:{user_id}:{}",
        sha256_hash(&format!("password-reset:v1:{user_id}:{token_hash}"))
    )
}

/// Deliver a reset credential and invalidate its durable token if delivery is
/// not proven. The invalidator is injected so tests exercise the same state
/// transition without a database or external service.
async fn deliver_or_invalidate<N, I, F>(
    notifier: &N,
    notification: PasswordResetNotification<'_>,
    invalidate: I,
) -> Result<(), PasswordResetDeliveryError>
where
    N: PasswordResetNotifier + ?Sized,
    I: FnOnce() -> F,
    F: std::future::Future<Output = Result<(), astral_db::DbError>>,
{
    let operation_id = notification.operation_id.to_owned();
    let delivery = notifier.deliver(notification).await;
    if delivery.is_err() {
        if let Err(_error) = invalidate().await {
            // The response remains non-success/PENDING. The error deliberately
            // contains no token material; reconciliation uses operation identity.
            tracing::error!(
                operation_id = %operation_id,
                "password reset token invalidation after delivery failure is unknown"
            );
        }
    }
    delivery
}

/// Fail-closed default until an approved provider or encrypted outbox worker
/// is available. This is not a fake delivery implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailablePasswordResetNotifier;

#[async_trait::async_trait]
impl PasswordResetNotifier for UnavailablePasswordResetNotifier {
    async fn deliver(
        &self,
        _notification: PasswordResetNotification<'_>,
    ) -> Result<(), PasswordResetDeliveryError> {
        Err(PasswordResetDeliveryError::Unavailable)
    }
}

fn password_reset_delivery_unavailable_body() -> ApiResponse<serde_json::Value> {
    let mut response = ApiResponse::error(
        StatusCode::SERVICE_UNAVAILABLE.as_u16() as i32,
        PASSWORD_RESET_DELIVERY_UNAVAILABLE_MESSAGE,
    );
    response.error_type = Some("DEPENDENCY_UNAVAILABLE".into());
    response.decision = Some("PENDING".into());
    response.reason_code = Some(PASSWORD_RESET_DELIVERY_UNAVAILABLE_REASON.into());
    response.data = Some(serde_json::json!({
        "reconcileRequired": false,
        "automaticRetry": false,
    }));
    response
}

fn password_reset_delivery_unavailable_response() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [("retry-after", "3")],
        Json(password_reset_delivery_unavailable_body()),
    )
        .into_response()
}

/// 请求密码重置
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestResetRequest {
    pub email: Option<String>,
    pub username: Option<String>,
}

/// 验证重置令牌并设置新密码
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

/// DbError → AppError 辅助转换
fn db_err(e: astral_db::DbError) -> AppError {
    AppError::from(AstralError::Database(format!("{e}")))
}

/// 密码重置路由
pub fn password_reset_routes() -> Router<AppState> {
    Router::new()
        .route("/password/forgot", post(request_reset))
        .route("/password/reset/{token}", post(reset_password))
}

/// POST /api/v1/auth/password/forgot — 请求密码重置
///
/// 本路由为未认证公开路径。**不得把明文重置令牌返回给调用方**：那等价于把
/// 账户接管凭证直接交给任何能枚举用户名/邮箱的人。当前没有安全投递通道，
/// 因此在账户查找或 token mutation 之前，已知和未知用户都返回相同的
/// 503/PENDING 合同。reset 端点仍按持有令牌方校验消费。
async fn request_reset(
    State(_state): State<AppState>,
    Json(req): Json<RequestResetRequest>,
) -> Result<Response, AppError> {
    // 解析登录标识（与登录路径一致：phone(规范化) → username → email）
    let username = req
        .username
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let email = req
        .email
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if username.is_none() && email.is_none() {
        return Err(AppError::from(AstralError::Validation(
            "username or email required".into(),
        )));
    }

    // No approved provider or encrypted delivery outbox is installed in the
    // current runtime. Return before account lookup or token mutation so known
    // and unknown identifiers have the same observable behavior and no usable
    // reset hash can survive a failed handoff.
    Ok(password_reset_delivery_unavailable_response())
}

/// POST /api/v1/auth/password/reset/:token — 使用令牌重置密码
async fn reset_password(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    // 密码策略：与注册/改密路径一致，至少 8 字符
    if req.new_password.len() < 8 {
        return Err(AppError::from(AstralError::Validation(
            "Password must be at least 8 characters".into(),
        )));
    }

    // 验证 token 一致性
    let path_token = if token.is_empty() { &req.token } else { &token };
    let token_hash = sha256_hash(path_token);

    // 查找有效令牌
    let row = find_valid_password_reset_token(&state.db, &token_hash)
        .await
        .map_err(db_err)?
        .ok_or_else(|| {
            AppError::from(AstralError::Auth(
                "Invalid or expired password reset token".into(),
            ))
        })?;

    // 先哈希新密码，避免事务内执行 Argon2 阻塞连接
    let new_hash = hash_password(&req.new_password).map_err(AppError::from)?;

    let repository = SqlxAuthRepository::new(state.db.clone());
    let revoked_jtis = repository
        .update_password_hash_with_revocation(
            row.user_id,
            &new_hash,
            "PASSWORD_RESET",
            Some(row.id),
        )
        .await
        .map_err(AppError::from)?;
    project_password_revocation(&revoked_jtis)
        .await
        .map_err(AppError::from)?;

    tracing::info!(user_id = row.user_id, "password reset completed via token");

    Ok(Json(ApiResponse::success(EmptyResponse)))
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use axum::http::StatusCode;

    use super::{
        deliver_or_invalidate, password_reset_delivery_unavailable_body,
        password_reset_delivery_unavailable_response, password_reset_operation_id,
        PasswordResetDeliveryError, PasswordResetNotification, PasswordResetNotifier,
        UnavailablePasswordResetNotifier,
    };

    #[tokio::test]
    async fn unavailable_notifier_does_not_return_or_render_the_raw_token() {
        let raw_token = "raw-reset-token-must-never-leak";
        let notification = PasswordResetNotification::new(
            "operation-1",
            "alice@example.com",
            raw_token,
            time::PrimitiveDateTime::MIN,
        );
        let error = UnavailablePasswordResetNotifier
            .deliver(notification)
            .await
            .expect_err("the default notifier must fail closed");

        assert_eq!(error.to_string(), "password reset delivery unavailable");
        assert!(!error.to_string().contains(raw_token));
    }

    #[tokio::test]
    async fn unavailable_response_is_generic_and_contains_no_token_material() {
        let raw_token = "raw-reset-token-must-never-leak";
        let body = serde_json::to_string(&password_reset_delivery_unavailable_body()).unwrap();
        assert!(body.contains("PASSWORD_RESET_DELIVERY_UNAVAILABLE"));
        assert!(body.contains("PENDING"));
        assert!(!body.contains(raw_token));

        let response = password_reset_delivery_unavailable_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers().get("retry-after").unwrap(), "3");
        let response_body = to_bytes(response.into_body(), 8192).await.unwrap();
        assert!(!String::from_utf8_lossy(&response_body).contains(raw_token));
    }

    #[test]
    fn unavailable_contract_is_independent_of_account_existence() {
        let first = password_reset_delivery_unavailable_body();
        let second = password_reset_delivery_unavailable_body();
        assert_eq!(first.code, second.code);
        assert_eq!(first.message, second.message);
        assert_eq!(first.error_type, second.error_type);
        assert_eq!(first.decision, second.decision);
        assert_eq!(first.reason_code, second.reason_code);
        assert_eq!(first.data, second.data);
    }

    struct FakeNotifier {
        result: Result<(), PasswordResetDeliveryError>,
        seen_operation_ids: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl PasswordResetNotifier for FakeNotifier {
        async fn deliver(
            &self,
            notification: PasswordResetNotification<'_>,
        ) -> Result<(), PasswordResetDeliveryError> {
            self.seen_operation_ids
                .lock()
                .unwrap()
                .push(notification.operation_id().to_owned());
            self.result
        }
    }

    #[tokio::test]
    async fn unavailable_delivery_invalidates_the_only_usable_token_and_keeps_operation_stable() {
        let user_id = 42;
        let raw_token = "raw-reset-token-never-persisted";
        let token_hash = super::sha256_hash(raw_token);
        let operation_id = password_reset_operation_id(user_id, &token_hash);
        let seen_operation_ids = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let notifier = FakeNotifier {
            result: Err(PasswordResetDeliveryError::Unavailable),
            seen_operation_ids: seen_operation_ids.clone(),
        };
        let mut usable_hash: Option<String> = Some(token_hash.clone());
        let result = deliver_or_invalidate(
            &notifier,
            PasswordResetNotification::new(
                &operation_id,
                "alice@example.com",
                raw_token,
                time::PrimitiveDateTime::MIN,
            ),
            || {
                let expected_hash = token_hash.clone();
                let result = if usable_hash.as_deref() == Some(expected_hash.as_str()) {
                    usable_hash = None;
                    Ok(())
                } else {
                    Err(astral_db::DbError::Mapping(
                        "reset token was not present for invalidation".into(),
                    ))
                };
                std::future::ready(result)
            },
        )
        .await;

        assert_eq!(result, Err(PasswordResetDeliveryError::Unavailable));
        assert!(
            usable_hash.is_none(),
            "unavailable delivery must not leave a usable token"
        );
        assert_eq!(
            seen_operation_ids.lock().unwrap().as_slice(),
            std::slice::from_ref(&operation_id)
        );
        assert!(!operation_id.contains(raw_token));
    }

    #[test]
    fn operation_id_is_stable_and_does_not_contain_raw_token() {
        let user_id = 42;
        let raw_token = "raw-reset-token-never-persisted";
        let token_hash = super::sha256_hash(raw_token);
        let first = password_reset_operation_id(user_id, &token_hash);
        let second = password_reset_operation_id(user_id, &token_hash);
        assert_eq!(first, second);
        assert!(!first.contains(raw_token));
        assert!(!first.contains(&token_hash));
    }

    #[test]
    fn reset_uses_atomic_password_mutation_and_projects_only_committed_snapshot() {
        let source = include_str!("password.rs");
        let body = source
            .split("async fn reset_password(")
            .nth(1)
            .expect("reset_password must stay in password.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("tests module must follow the handler");
        let mutation = body
            .find("update_password_hash_with_revocation")
            .expect("reset must use the atomic password+revocation repository method");
        let consume = body
            .find("Some(row.id)")
            .expect("reset token identity must be consumed in the source transaction");
        let projection = body
            .find("project_password_revocation(&revoked_jtis")
            .expect("post-commit projection must receive only the transaction snapshot");
        assert!(mutation < consume && consume < projection);
        assert!(!body.contains("revoke_all_sessions_for_user"));
        assert!(!body.contains("mark_password_reset_token_used_tx"));
        assert!(!body.contains("load_active_jtis_by_user"));
    }
}
