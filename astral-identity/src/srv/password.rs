//! 密码重置流程 — HTTP adapter
//!
//! 对应 Java `PasswordResetController` + `PasswordResetService`。
//! 流程：请求重置 → 验证令牌 → 设置新密码。
//! 令牌存储于 password_reset_token 表，使用 SHA-256 哈希存储；
//! 数据访问在 `astral-db`（token 表 CRUD）+ `user_repository`（密码哈希更新）。

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use std::net::SocketAddr;

use astral_common::audit::{
    audit_event_type_name, global_audit_dual_write, record_audit, spawn_owned_audit,
};
use astral_common::contract::{ApiResponse, EmptyResponse};
use astral_common::error::AppError;
use astral_db::{
    find_valid_password_reset_token, insert_password_reset_token, invalidate_password_reset_token,
    invalidate_user_password_reset_tokens,
};
use astral_types::AstralError;

use crate::auth::{find_login_aggregate_resolved, hash_password, sha256_hash};
use crate::srv::auth_repository::{AuthRepository, SqlxAuthRepository};
use crate::srv::session::project_password_revocation;
use crate::AppState;

const PASSWORD_RESET_DELIVERY_UNAVAILABLE_MESSAGE: &str = "Password reset delivery is unavailable";
const PASSWORD_RESET_DELIVERY_UNAVAILABLE_REASON: &str = "PASSWORD_RESET_DELIVERY_UNAVAILABLE";

/// 重置令牌有效期（30 分钟）。证据来源：仓库原始实现（initial snapshot
/// 起 `request_reset` 即硬编码 `minutes(30)`，非仅 DDL 注释推断）。TTL 由
/// 本调用方拥有（astral-db 只存储 `expires_at`）。
const PASSWORD_RESET_TOKEN_TTL: time::Duration = time::Duration::minutes(30);

/// 发送预算窗口与上限（durable 跨副本，复用 `verification_budget` 表，
/// scope=RESET / purpose=password-reset；helper 见
/// `astral_db::verification_durable_repository::bump_password_reset_send_budget`）。
/// 窗口对齐 token TTL：同（提交标识）至多每窗口投递一封，重复请求在窗口内
/// 被幂等吸收（统一响应、不再外发、不再落新令牌）；per-IP 上限约束未知标识
/// 的枚举型投递放大。
const PASSWORD_RESET_SEND_WINDOW: time::Duration = time::Duration::minutes(30);
const PASSWORD_RESET_CAP_PER_TARGET: i64 = 1;
const PASSWORD_RESET_CAP_PER_IP: i64 = 20;

/// The Identity-owned delivery boundary for password reset credentials.
///
/// Implementations must be installed only after the reset hash is durable and
/// must never log, audit, or persist the raw token. Production composition is
/// [`DeliveryPasswordResetNotifier`] (shared delivery owner, ephemeral-secret
/// payload class: durable intent metadata + CAS lease, but no payload — not
/// even a digest — is ever persisted); without delivery configuration the
/// runtime installs [`UnavailablePasswordResetNotifier`].
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
    #[error("password reset email was accepted by the MTA but delivery is not proven")]
    AcceptedNotDelivered,
    #[error("password reset delivery outcome is unknown; reconciliation required")]
    InDoubt,
    #[error("password reset delivery was definitively refused")]
    Rejected,
}

/// Mint a fresh, independent, non-secret handoff identity for one reset
/// operation (主审决策：不派生自 token hash——独立随机稳定 ID，随行绑定
/// `password_reset_token.operation_id` / `delivery_message_id` 持久化).
///
/// The id is random (uuid v7) and is held by the caller for the operation's
/// lifetime: it is never derived from the raw token (or any function of it),
/// so no offline brute-force oracle over reset tokens can exist. The same id
/// is bound to the durable token row and to the `al_delivery_intent` row via
/// `DeliveryOwner::message_id_for_operation`, making the credential
/// PENDING-by-construction and consumable only under durable `DELIVERED`
/// evidence.
fn mint_password_reset_operation_id() -> String {
    format!("password-reset:{}", uuid::Uuid::now_v7())
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

/// Fail-closed default until delivery configuration is provided. This is not
/// a fake delivery implementation.
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

/// Production adapter bridging the shared delivery owner
/// (`astral_common::delivery`) into the Identity-owned port.
///
/// Semantics (fail-closed):
/// - `Ok(())` ONLY on explicit delivery proof. Plain SMTP cannot prove
///   delivery, so an SMTP-only configuration never reports success here —
///   that is the truthful behavior, not a bug.
/// - `Accepted` (MTA queued) → [`PasswordResetDeliveryError::AcceptedNotDelivered`].
/// - `InDoubt` (dispatch began, outcome unknown) → [`PasswordResetDeliveryError::InDoubt`].
/// - Everything else → `Unavailable`/`Rejected`. Every error path lets
///   `deliver_or_invalidate` destroy the only usable token, so no usable
///   credential survives a failed or unknown handoff.
///
/// Payload rules: the raw token exists only inside the in-memory message
/// body. The durable intent row records metadata and a CAS lease but no body
/// and no body digest (EPHEMERAL_SECRET class), so UNKNOWN attempts cannot
/// be replayed across replicas or restarts and no secret material is
/// persisted.
pub struct DeliveryPasswordResetNotifier {
    owner: astral_common::delivery::DeliveryOwner,
    smtp: astral_common::delivery::channel_config::SmtpConfig,
}

impl std::fmt::Debug for DeliveryPasswordResetNotifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeliveryPasswordResetNotifier")
            .field("smtp_host", &self.smtp.host)
            .field("smtp_port", &self.smtp.port)
            .finish()
    }
}

#[async_trait::async_trait]
impl PasswordResetNotifier for DeliveryPasswordResetNotifier {
    async fn deliver(
        &self,
        notification: PasswordResetNotification<'_>,
    ) -> Result<(), PasswordResetDeliveryError> {
        let message = astral_common::delivery::DeliveryMessage::compose(
            astral_common::delivery::ChannelKind::Email,
            notification.operation_id(),
            Some(
                &astral_common::delivery::DeliveryOwner::message_id_for_operation(
                    notification.operation_id(),
                ),
            ),
            notification.recipient(),
            Some("Password reset / 密码重置"),
            &password_reset_email_body(notification.token(), notification.expires_at()),
            astral_common::delivery::PayloadClass::EphemeralSecret,
        )
        .map_err(|_| PasswordResetDeliveryError::Unavailable)?;
        let truth = self
            .owner
            .deliver_ephemeral_secret(
                &message,
                &astral_common::delivery::ResolvedChannel::Smtp(self.smtp.clone()),
            )
            .await;
        match truth.state {
            astral_common::delivery::DeliveryState::Delivered => Ok(()),
            astral_common::delivery::DeliveryState::Accepted => {
                Err(PasswordResetDeliveryError::AcceptedNotDelivered)
            }
            astral_common::delivery::DeliveryState::InDoubt => {
                Err(PasswordResetDeliveryError::InDoubt)
            }
            astral_common::delivery::DeliveryState::Failed
            | astral_common::delivery::DeliveryState::Expired => {
                Err(PasswordResetDeliveryError::Rejected)
            }
            _ => Err(PasswordResetDeliveryError::Unavailable),
        }
    }
}

/// Compose the reset email body. The raw token appears here and nowhere
/// else: never in logs, audit rows, errors, or durable intent rows.
fn password_reset_email_body(token: &str, expires_at: time::PrimitiveDateTime) -> String {
    format!(
        "A password reset was requested for your account.\n\
         Reset token: {token}\n\
         Expires at: {expires_at} UTC\n\n\
         If you did not request this, ignore this email; the token expires on its own.\n"
    )
}

/// Build the runtime notifier: real delivery when SMTP is configured through
/// protected environment references, otherwise the fail-closed unavailable
/// notifier. The durable intent store (metadata only for secrets) is backed
/// by the shared Identity pool so UNKNOWN attempts cannot be replayed across
/// replicas or restarts.
pub fn password_reset_notifier_from_env(
    db: sqlx::MySqlPool,
) -> std::sync::Arc<dyn PasswordResetNotifier> {
    match smtp_config_from_env() {
        Ok(smtp) => {
            let store: std::sync::Arc<dyn astral_common::delivery::DeliveryStore> =
                std::sync::Arc::new(astral_common::delivery::SqlxDeliveryIntentRepository::new(
                    db,
                ));
            let owner = astral_common::delivery::DeliveryOwner::builder(Some(store)).build();
            std::sync::Arc::new(DeliveryPasswordResetNotifier { owner, smtp })
        }
        // No delivery configuration is a valid fail-closed deployment.
        Err(()) => std::sync::Arc::new(UnavailablePasswordResetNotifier),
    }
}

/// Resolve the SMTP configuration from protected environment references.
/// Secrets are read from env var NAMES (`ASTRAL_SMTP_PASSWORD_ENV`), never
/// inline. Missing host/sender means "not configured".
fn smtp_config_from_env() -> Result<astral_common::delivery::channel_config::SmtpConfig, ()> {
    use astral_common::delivery::channel_config::{SmtpConfig, SmtpSecurity};
    use astral_common::delivery::endpoint::EndpointGuard;

    let host = env_trim("ASTRAL_SMTP_HOST")
        .filter(|value| !value.is_empty())
        .ok_or(())?;
    let port = env_trim("ASTRAL_SMTP_PORT")
        .map(|value| value.parse::<u16>().map_err(|_| ()))
        .transpose()?
        .unwrap_or(587);
    let security = match env_trim("ASTRAL_SMTP_SECURITY")
        .map(|value| value.to_ascii_uppercase())
        .as_deref()
    {
        None | Some("STARTTLS") => SmtpSecurity::StartTls,
        Some("TLS" | "WRAPPER" | "SSL") => SmtpSecurity::Wrapper,
        // Plaintext SMTP is never valid for password reset delivery.
        Some("NONE") => return Err(()),
        Some(_) => return Err(()),
    };
    let sender = env_trim("ASTRAL_SMTP_FROM")
        .filter(|value| !value.is_empty())
        .ok_or(())?;
    let username = env_trim("ASTRAL_SMTP_USERNAME").filter(|value| !value.is_empty());
    let password = match env_trim("ASTRAL_SMTP_PASSWORD_ENV") {
        Some(env_name) => Some(
            std::env::var(&env_name)
                .ok()
                .filter(|value| !value.trim().is_empty())
                .ok_or(())?,
        ),
        None => None,
    };
    if username.is_some() != password.is_some() {
        // Credentials are either both present or absent.
        return Err(());
    }
    let hello_name = env_trim("ASTRAL_SMTP_HELO")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "astral-identity".to_owned());
    let allowed_hosts = env_trim("ASTRAL_SMTP_ALLOWED_HOSTS")
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    // Explicit host allowlist is strongly recommended; when provided, the
    // configured host must be on it.
    if !allowed_hosts.is_empty()
        && !allowed_hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&host))
    {
        return Err(());
    }
    Ok(SmtpConfig {
        host,
        port,
        security,
        username,
        password,
        sender,
        hello_name,
        guard: EndpointGuard::public(allowed_hosts),
    })
}

fn env_trim(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
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

/// 统一受理响应（投递已配置路径）：已知与未知账户返回完全相同的合同
/// （反枚举不变式，见 `request_reset` 文档）。投递 typed truth 只进日志/
/// 指标，不改变本响应。
fn password_reset_request_accepted_response() -> Response {
    (StatusCode::OK, Json(ApiResponse::success(EmptyResponse))).into_response()
}

/// Reset-token TTL 是调用方拥有的；解析为 MySQL DATETIME 域（不 panic）。
fn reset_token_expires_at() -> time::PrimitiveDateTime {
    let deadline = time::OffsetDateTime::now_utc().saturating_add(PASSWORD_RESET_TOKEN_TTL);
    time::PrimitiveDateTime::new(deadline.date(), deadline.time())
}

/// 敏感访问审计 detail 上界：本路由 detail 是结构化短键值对
/// （opId/msgId/budget/issuance/delivery），远小于共享 AUDIT_DETAIL_MAX_BYTES
/// 重放边界。
const PASSWORD_RESET_AUDIT_DETAIL_MAX_BYTES: usize = 256;

/// typed delivery error → 审计标签（与 delivery truth 一一对应，无 secret）。
fn delivery_audit_label(error: &PasswordResetDeliveryError) -> &'static str {
    match error {
        PasswordResetDeliveryError::Unavailable => "NOT_ATTEMPTED",
        PasswordResetDeliveryError::AcceptedNotDelivered => "ACCEPTED",
        PasswordResetDeliveryError::InDoubt => "IN_DOUBT",
        PasswordResetDeliveryError::Rejected => "FAILED",
    }
}

/// 有界审计 detail：键值对按序拼接（调用方固定键序），整体按字符边界截断。
fn password_reset_audit_detail(pairs: &[(&str, String)]) -> String {
    let joined = pairs
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(";");
    astral_common::audit::truncate_at_char_boundary(&joined, PASSWORD_RESET_AUDIT_DETAIL_MAX_BYTES)
        .to_owned()
}

/// 敏感访问审计出口（与 verification 同源：MQ-first DB-fallback 双写；
/// writer 缺失或审计任务未被接纳时退化为结构化 tracing，绝不阻塞主链、
/// 绝不影响 HTTP 结果）。pre-auth 路由：user_id 使用已解析账户 id 或既有
/// 匿名 0 哨兵；detail 只携带稳定 operation/message id 与预算/签发/投递
/// 真值——绝不携带 token/login/email 明文。
fn spawn_password_reset_audit(entry: astral_common::audit::AuditEntry) {
    let Some(writer) = global_audit_dual_write() else {
        record_audit(entry);
        return;
    };
    let fallback = entry.clone();
    if let Err(reason) = spawn_owned_audit(async move { writer.write(entry).await }) {
        tracing::warn!(
            reason,
            "password reset audit task was not admitted; falling back to structured log"
        );
        record_audit(fallback);
    }
}

/// 组装敏感访问审计条目（resource/action/契约变体固定；detail 由调用方以
/// `password_reset_audit_detail` 构造）。
fn password_reset_audit_entry(
    user_id: i64,
    request_id: Option<&str>,
    detail: String,
) -> astral_common::audit::AuditEntry {
    astral_common::audit::AuditEntry {
        user_id: Some(user_id),
        card_id: None,
        action: "request".into(),
        resource: "password_reset".into(),
        decision: "ALLOW".into(),
        reason: Some(audit_event_type_name(
            &astral_common::audit::AuditEventType::PasswordResetIssued,
        )),
        event_type: astral_common::audit::AuditEventType::PasswordResetIssued,
        category: Some(astral_common::audit::AuditCategory::IdentityEvent),
        source_ip: None,
        request_id: request_id.map(str::to_owned),
        domain_id: None,
        tenant_id: None,
        detail: Some(detail),
    }
}

/// 签发一份重置凭证（主审后修复）：durable 落库（token 哈希 + 稳定
/// operation/message id 绑定 + 同事务签发审计）→ 经共享 delivery owner
/// 真实投递 → 非 DELIVERED 一律作废（housekeeping：安全边界是消费事务内
/// `delivery_message_id → al_delivery_intent.state='DELIVERED'` 的 join 门，
/// 不再依赖本失效）。
///
/// `operation_id` 由调用方在 issue 前生成（随机独立非 secret 稳定 ID，
/// 不派生自 token）；`message_id =
/// DeliveryOwner::message_id_for_operation(operation_id)` 与 durable 令牌行
/// 同值绑定。`persist` 在投递开始前于单一事务内落库 `(token_hash,
/// expires_at)` + 签发审计关联；落库失败 → 无任何外发（fail-closed）。
/// 明文令牌只存在于内存消息体。
async fn issue_reset_credential<P, PF, I, IF>(
    notifier: &dyn PasswordResetNotifier,
    operation_id: &str,
    raw_token: &str,
    recipient: &str,
    persist: P,
    invalidate: I,
) -> Result<(), PasswordResetDeliveryError>
where
    P: FnOnce(String, time::PrimitiveDateTime) -> PF,
    PF: std::future::Future<Output = Result<(), astral_db::DbError>>,
    I: FnOnce(String) -> IF,
    IF: std::future::Future<Output = Result<(), astral_db::DbError>>,
{
    let token_hash = sha256_hash(raw_token);
    let expires_at = reset_token_expires_at();
    // Durable 绑定先行：落库失败 → 没有任何外发（fail-closed），typed
    // Unavailable；不留内存外发路径。
    persist(token_hash.clone(), expires_at)
        .await
        .map_err(|_| PasswordResetDeliveryError::Unavailable)?;
    let notification =
        PasswordResetNotification::new(operation_id, recipient, raw_token, expires_at);
    let delivery =
        deliver_or_invalidate(notifier, notification, || invalidate(token_hash.clone())).await;
    match &delivery {
        Ok(()) => tracing::info!(
            operation_id = %operation_id,
            "password reset credential delivered (typed DELIVERED); token remains usable"
        ),
        Err(error) => tracing::warn!(
            operation_id = %operation_id,
            error = %error,
            "password reset delivery not proven; token invalidated (housekeeping; the consumption gate is the delivery join)"
        ),
    }
    delivery
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

/// 裸 sqlx::Error（事务 begin/commit 边界）→ AppError 辅助转换
fn sql_err(e: sqlx::Error) -> AppError {
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
/// 账户接管凭证直接交给任何能枚举用户名/邮箱的人。reset 端点仍按持有令牌
/// 方校验消费。
///
/// 响应合同（反枚举不变式：已知与未知账户可观察行为一致）：
/// - **投递未配置**（`UnavailablePasswordResetNotifier` 的部署，经与
///   `password_reset_notifier_from_env` 同源的受保护 env 探测判定）：在账户
///   查找或 token mutation 之前返回统一的 503/PENDING 合同——没有投递通道
///   是部署事实而非账户事实。
/// - **投递已配置**（真实 delivery owner，SMTP 经受保护 env 引用）：先经
///   durable 跨副本发送预算（提交标识 HMAC + 已解析客户端 IP HMAC；超预算
///   幂等吸收为统一响应，DB 拒绝则 503 fail-closed），再解析登录聚合（与
///   登录路径同源解析序）。已知账户先作废旧令牌，随后在**单一事务内**落库
///   SHA-256 哈希 + 稳定 `operation_id`/`delivery_message_id` 绑定 + 签发
///   审计关联，再经 `deliver_or_invalidate` 真实外发。凭证出生即
///   **PENDING-by-construction**：消费事务的
///   `delivery_message_id → al_delivery_intent.state='DELIVERED'` join 是
///   唯一可用性边界——只有 durable DELIVERED 证据可使其可消费（ACCEPTED/
///   IN_DOUBT/FAILED/未投递/未绑定一律拒绝），非 DELIVERED 的作废只是
///   housekeeping。已知与未知账户返回相同的统一受理响应；敏感访问审计经
///   既有双写/同事务入口记录稳定 id 与预算/签发/投递真值，绝不携带
///   token/login/email 明文。
///
/// 残余时序信号（刻意保留，已登记）：已配置部署下，已知账户的响应要等
/// 真实投递完成（上限 = delivery owner attempt_timeout），未知/超预算账户
/// 立即返回——状态与响应体统一，但响应时长可与账户存在性相关；投递侧
/// 有界超时封顶该差异。
async fn request_reset(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: ConnectInfo<SocketAddr>,
    Json(req): Json<RequestResetRequest>,
) -> Result<Response, AppError> {
    // 解析登录标识（与登录路径一致：username → email；本路由无 phone 字段）
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

    // 投递未配置是有效的 fail-closed 部署：统一 503/PENDING，先于账户查找与
    // token mutation（与 `password_reset_notifier_from_env` 同一 env 合同，
    // 探测失败只会收敛到"不外发"，绝不会用另一条通道放行）。
    if smtp_config_from_env().is_err() {
        return Ok(password_reset_delivery_unavailable_response());
    }

    // 敏感访问审计关联：x-request-id（与 monitor/protected mutation 同源）。
    let request_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty());

    // durable 发送预算主体：HMAC 密钥缺失 → 503（fail-closed：无预算键就
    // 无外发；密钥自身已 error 级告警）。预算键只含摘要，不含明文标识。
    let Some(hmac_key) = crate::srv::verification::durable::hmac_key() else {
        tracing::error!("password reset send budget unavailable: HMAC key not configured");
        spawn_password_reset_audit(password_reset_audit_entry(
            0,
            request_id,
            password_reset_audit_detail(&[
                ("budget", "UNAVAILABLE".to_string()),
                ("issuance", "ABSORBED".to_string()),
                ("delivery", "NONE".to_string()),
            ]),
        ));
        return Ok(password_reset_delivery_unavailable_response());
    };
    let mut identifier_hashes: Vec<[u8; 32]> = Vec::with_capacity(2);
    for identifier in username.into_iter().chain(email) {
        identifier_hashes.push(crate::srv::verification::durable::target_hash(
            hmac_key, identifier,
        ));
    }
    let ip_hash = crate::srv::verification::durable::client_ip_hash(
        hmac_key,
        &headers,
        Some(peer.0.ip()),
        &state.config.gateway.trusted_proxy_ips,
    );

    // 跨副本预算：同一短事务内递增（提交标识 ×N + IP）；超预算整体回滚
    // （无脏计数），幂等吸收为统一响应——不外发、不落令牌；DB 拒绝 →
    // 503 fail-closed（无 durable 预算就没有外发）。
    let window_start = crate::srv::verification::durable::budget_window_start(
        time::OffsetDateTime::now_utc(),
        PASSWORD_RESET_SEND_WINDOW,
    );
    let mut tx = state.db.begin().await.map_err(sql_err)?;
    let within = astral_db::verification_durable_repository::bump_password_reset_send_budget(
        &mut tx,
        &identifier_hashes,
        &ip_hash,
        window_start,
        PASSWORD_RESET_CAP_PER_TARGET,
        PASSWORD_RESET_CAP_PER_IP,
    )
    .await;
    let within = match within {
        Ok(within) => within,
        Err(error) => {
            drop(tx);
            tracing::error!(error = %error, "password reset budget store refused; fail closed");
            spawn_password_reset_audit(password_reset_audit_entry(
                0,
                request_id,
                password_reset_audit_detail(&[
                    ("budget", "REFUSED".to_string()),
                    ("issuance", "ABSORBED".to_string()),
                    ("delivery", "NONE".to_string()),
                ]),
            ));
            return Ok(password_reset_delivery_unavailable_response());
        }
    };
    if !within.iter().all(|within| *within) {
        drop(tx);
        tracing::warn!(
            targets = identifier_hashes.len(),
            "password reset send budget exhausted; idempotently absorbed"
        );
        spawn_password_reset_audit(password_reset_audit_entry(
            0,
            request_id,
            password_reset_audit_detail(&[
                ("budget", "EXHAUSTED".to_string()),
                ("issuance", "ABSORBED".to_string()),
                ("delivery", "NONE".to_string()),
            ]),
        ));
        return Ok(password_reset_request_accepted_response());
    }
    tx.commit().await.map_err(sql_err)?;

    // 已配置：解析登录聚合（username → email，与登录路径同源解析序）。
    let aggregate = find_login_aggregate_resolved(&state.db, username, None, email)
        .await
        .map_err(AppError::from)?;
    let Some(aggregate) = aggregate else {
        // 未知账户：不落任何行，统一受理响应（反枚举）。
        spawn_password_reset_audit(password_reset_audit_entry(
            0,
            request_id,
            password_reset_audit_detail(&[
                ("budget", "OK".to_string()),
                ("issuance", "SKIPPED_UNKNOWN".to_string()),
                ("delivery", "NONE".to_string()),
            ]),
        ));
        return Ok(password_reset_request_accepted_response());
    };
    let Some(recipient) = aggregate
        .email
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
    else {
        // 已知账户无投递地址：无凭证可投，不落任何行，统一受理响应。
        spawn_password_reset_audit(password_reset_audit_entry(
            aggregate.user_id,
            request_id,
            password_reset_audit_detail(&[
                ("budget", "OK".to_string()),
                ("issuance", "SKIPPED_NO_EMAIL".to_string()),
                ("delivery", "NONE".to_string()),
            ]),
        ));
        return Ok(password_reset_request_accepted_response());
    };

    // `card_number` 是 password_reset_token 的既有 NOT NULL 审计列。证据：
    // 仓库原始实现绑定的是发起重置的登录名（`login_name`，即
    // user_local_credential.login_name，缺失时空串），并非身份卡号——当前
    // 身份卡契约（v4/v5）无 card_number 列；沿用原始绑定形态，不冒充。
    let card_number = aggregate.login_name.clone().unwrap_or_default();
    let user_id = aggregate.user_id;

    // 原始流语义（initial snapshot 起）：签发新令牌前作废该用户全部旧令牌
    // （至多一份未消费令牌存活）。
    invalidate_user_password_reset_tokens(&state.db, user_id)
        .await
        .map_err(db_err)?;

    // issue 前生成随机独立非 secret 稳定 ID；message id 由其确定性派生并
    // 与 durable 令牌行同值绑定（消费门 = 该绑定 join DELIVERED）。
    let operation_id = mint_password_reset_operation_id();
    let message_id =
        astral_common::delivery::DeliveryOwner::message_id_for_operation(&operation_id);

    // 签发审计（与令牌行同事务 durable 落库，不依赖异步投递存活性）：
    // detail 只含稳定 id 与预算/签发/投递阶段真值，无 token/login/email。
    let issuance_audit = password_reset_audit_entry(
        user_id,
        request_id,
        password_reset_audit_detail(&[
            ("opId", operation_id.clone()),
            ("msgId", message_id.clone()),
            ("budget", "OK".to_string()),
            ("issuance", "ISSUED".to_string()),
            ("delivery", "PENDING".to_string()),
        ]),
    );

    let db = state.db.clone();
    let operation_id_bound = operation_id.clone();
    let message_id_bound = message_id.clone();
    let raw_token = uuid::Uuid::now_v7().to_string();
    let delivery = issue_reset_credential(
        state.password_reset_notifier.as_ref(),
        &operation_id,
        &raw_token,
        &recipient,
        |token_hash, expires_at| {
            let db = db.clone();
            let card_number = card_number.clone();
            let operation_id = operation_id_bound.clone();
            let message_id = message_id_bound.clone();
            let issuance_audit = issuance_audit.clone();
            async move {
                let mut tx = db.begin().await.map_err(astral_db::DbError::Query)?;
                insert_password_reset_token(
                    &mut *tx,
                    user_id,
                    &card_number,
                    &token_hash,
                    &operation_id,
                    &message_id,
                    &expires_at,
                )
                .await?;
                astral_db::insert_audit_log_in_tx(&mut tx, &issuance_audit).await?;
                tx.commit().await.map_err(astral_db::DbError::Query)?;
                Ok(())
            }
        },
        |token_hash| {
            let db = state.db.clone();
            async move { invalidate_password_reset_token(&db, user_id, &token_hash).await }
        },
    )
    .await;

    // 投递真值审计（housekeeping 之上的 typed truth；与签发审计经同一
    // opId/msgId 关联。durable 证据本体是 al_delivery_intent 行，本事件为
    // 可观测关联，尽力而为不阻塞主链）。
    let delivery_label: &str = match &delivery {
        Ok(()) => "DELIVERED",
        Err(error) => delivery_audit_label(error),
    };
    let token_state = if delivery.is_ok() {
        "kept"
    } else {
        "invalidated"
    };
    spawn_password_reset_audit(password_reset_audit_entry(
        user_id,
        request_id,
        password_reset_audit_detail(&[
            ("opId", operation_id.clone()),
            ("msgId", message_id.clone()),
            ("issuance", "ISSUED".to_string()),
            ("delivery", delivery_label.to_string()),
            ("tokenState", token_state.to_string()),
        ]),
    ));

    // 机会式有界 GC（同 verification 发送路径）：预算窗口行由共享
    // cleanup_expired_verification 覆盖（window_start 早于 retention 即删），
    // 单次每表有界；失败不阻塞主链。
    match astral_db::verification_durable_repository::cleanup_expired_verification(
        &state.db,
        time::Duration::hours(24),
        100,
    )
    .await
    {
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(error = %error, "password reset budget GC failed (non-fatal)")
        }
    }

    Ok(password_reset_request_accepted_response())
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
            None,
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
        deliver_or_invalidate, mint_password_reset_operation_id,
        password_reset_delivery_unavailable_body, password_reset_delivery_unavailable_response,
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
        let raw_token = "raw-reset-token-never-persisted";
        let token_hash = super::sha256_hash(raw_token);
        let operation_id = mint_password_reset_operation_id();
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
    fn minted_operation_id_is_random_and_never_derived_from_the_secret() {
        let raw_token = "raw-reset-token-never-persisted";
        let token_hash = super::sha256_hash(raw_token);
        let first = mint_password_reset_operation_id();
        let second = mint_password_reset_operation_id();
        // Fresh per operation (replay protection lives in the durable lease,
        // not in secret-derived determinism).
        assert_ne!(first, second);
        assert!(first.starts_with("password-reset:"));
        assert!(!first.contains(raw_token));
        assert!(!first.contains(&token_hash));
    }

    /// 敏感审计 detail：只携带稳定 id 与阶段真值，绝不携带
    /// token/login/email；整体有界。
    #[test]
    fn audit_detail_never_carries_secret_or_pii() {
        let raw_token = "raw-token-993311";
        let login_name = "alice.local";
        let email = "alice@example.com";
        let detail = super::password_reset_audit_detail(&[
            ("opId", "password-reset:0192abcd".to_string()),
            (
                "msgId",
                astral_common::delivery::DeliveryOwner::message_id_for_operation(
                    "password-reset:0192abcd",
                ),
            ),
            ("budget", "OK".to_string()),
            ("issuance", "ISSUED".to_string()),
            ("delivery", "PENDING".to_string()),
        ]);
        assert!(detail.contains("opId="));
        assert!(detail.contains("msgId="));
        assert!(detail.contains("issuance=ISSUED"));
        for secret in [raw_token, login_name, email] {
            assert!(
                !detail.contains(secret),
                "{secret} must never enter audit detail"
            );
        }
        // 有界：超长输入按字符边界截断。
        let long = super::password_reset_audit_detail(&[(
            "opId",
            "x".repeat(super::PASSWORD_RESET_AUDIT_DETAIL_MAX_BYTES + 64),
        )]);
        assert!(long.len() <= super::PASSWORD_RESET_AUDIT_DETAIL_MAX_BYTES + 8);
    }

    /// typed delivery error → 审计标签一一对应（无 secret，无歧义）。
    #[test]
    fn delivery_audit_labels_are_typed_and_disjoint() {
        use super::PasswordResetDeliveryError as E;
        let labels = [
            (E::Unavailable, "NOT_ATTEMPTED"),
            (E::AcceptedNotDelivered, "ACCEPTED"),
            (E::InDoubt, "IN_DOUBT"),
            (E::Rejected, "FAILED"),
        ];
        for (error, label) in labels {
            assert_eq!(super::delivery_audit_label(&error), label);
        }
        let all: Vec<_> = labels.iter().map(|(_, label)| *label).collect();
        let mut unique = all.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(all.len(), unique.len(), "audit labels must be disjoint");
    }

    /// `issue_reset_credential` 的注入式流测试：persist/invalidate 用内存
    /// 状态模拟 durable 哈希表，notifier 用既有 FakeNotifier。
    mod issuance {
        use super::super::{
            issue_reset_credential, PasswordResetDeliveryError, PasswordResetNotifier,
        };
        use std::sync::Mutex;

        struct FakeNotifier {
            result: Result<(), PasswordResetDeliveryError>,
        }

        #[async_trait::async_trait]
        impl PasswordResetNotifier for FakeNotifier {
            async fn deliver(
                &self,
                _notification: super::super::PasswordResetNotification<'_>,
            ) -> Result<(), PasswordResetDeliveryError> {
                self.result
            }
        }

        #[derive(Clone, Default)]
        struct Fixture {
            /// Arc 共享：persist/invalidate 闭包各自 clone 的是同一份共享
            /// 状态（与真实 durable 存储共享语义一致），而不是深拷贝。
            durable_hash: std::sync::Arc<Mutex<Option<String>>>,
            invalidated: std::sync::Arc<Mutex<Vec<String>>>,
        }

        impl Fixture {
            fn new() -> Self {
                Self::default()
            }

            fn invalidate(&self, token_hash: String) -> Result<(), astral_db::DbError> {
                let mut durable = self.durable_hash.lock().unwrap();
                if durable.as_deref() == Some(token_hash.as_str()) {
                    *durable = None;
                }
                self.invalidated.lock().unwrap().push(token_hash);
                Ok(())
            }

            fn persisted(&self) -> Option<String> {
                self.durable_hash.lock().unwrap().clone()
            }

            fn still_usable(&self) -> bool {
                self.durable_hash.lock().unwrap().is_some()
            }
        }

        async fn run(
            result: Result<(), PasswordResetDeliveryError>,
        ) -> (Fixture, Result<(), PasswordResetDeliveryError>) {
            let fixture = Fixture::new();
            let notifier = FakeNotifier { result };
            let operation_id = super::super::mint_password_reset_operation_id();
            let raw_token = uuid::Uuid::now_v7().to_string();
            let outcome = issue_reset_credential(
                &notifier,
                &operation_id,
                &raw_token,
                "alice@example.com",
                |token_hash, _expires_at| {
                    let fixture = fixture.clone();
                    async move {
                        *fixture.durable_hash.lock().unwrap() = Some(token_hash);
                        Ok(())
                    }
                },
                |token_hash| {
                    let fixture = fixture.clone();
                    async move { fixture.invalidate(token_hash) }
                },
            )
            .await;
            (fixture, outcome)
        }

        #[tokio::test]
        async fn delivered_keeps_exactly_one_usable_hash() {
            let (fixture, outcome) = run(Ok(())).await;
            assert_eq!(outcome, Ok(()));
            let persisted = fixture
                .persisted()
                .expect("hash must be durable before delivery");
            assert_eq!(
                persisted.len(),
                64,
                "SHA-256 hex hash is the only stored form"
            );
            assert!(
                fixture.still_usable(),
                "typed DELIVERED is the only truth that keeps the token usable"
            );
            assert!(
                fixture.invalidated.lock().unwrap().is_empty(),
                "delivered flow must not invalidate"
            );
        }

        #[tokio::test]
        async fn unaccepted_delivery_destroys_the_only_usable_token() {
            for result in [
                Err(PasswordResetDeliveryError::Unavailable),
                Err(PasswordResetDeliveryError::AcceptedNotDelivered),
                Err(PasswordResetDeliveryError::InDoubt),
                Err(PasswordResetDeliveryError::Rejected),
            ] {
                let (fixture, outcome) = run(result).await;
                assert!(outcome.is_err());
                assert!(
                    !fixture.still_usable(),
                    "no usable token may survive a non-DELIVERED truth"
                );
                assert_eq!(
                    fixture.invalidated.lock().unwrap().len(),
                    1,
                    "invalidation must run exactly once per failed handoff"
                );
            }
        }
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

    /// Adapter tests: the shared delivery owner with a static-truth transport.
    mod adapter {
        use super::super::password_reset_email_body;
        use super::super::{
            DeliveryPasswordResetNotifier, PasswordResetDeliveryError, PasswordResetNotifier,
            UnavailablePasswordResetNotifier,
        };
        use astral_common::delivery::{
            channel_config::SmtpConfig, endpoint::EndpointGuard, ChannelTransport, DeliveryMessage,
            DeliveryOwner, DeliveryTruth, ResolvedChannel,
        };
        use std::sync::Arc;

        fn fixture_smtp() -> SmtpConfig {
            SmtpConfig {
                host: "smtp.example.com".to_owned(),
                port: 2525,
                security: astral_common::delivery::channel_config::SmtpSecurity::StartTls,
                username: None,
                password: None,
                sender: "noreply@example.com".to_owned(),
                hello_name: "astral-test".to_owned(),
                guard: EndpointGuard::public(Vec::new()),
            }
        }

        struct StaticTransport {
            truth: std::sync::Mutex<Option<DeliveryTruth>>,
        }

        impl StaticTransport {
            fn new(truth: DeliveryTruth) -> Self {
                Self {
                    truth: std::sync::Mutex::new(Some(truth)),
                }
            }
        }

        #[async_trait::async_trait]
        impl ChannelTransport for StaticTransport {
            async fn dispatch(
                &self,
                _message: &DeliveryMessage,
                _channel: &ResolvedChannel,
            ) -> DeliveryTruth {
                self.truth
                    .lock()
                    .unwrap()
                    .take()
                    .expect("single dispatch expected")
            }
        }

        fn notifier(truth: DeliveryTruth) -> DeliveryPasswordResetNotifier {
            // Production shape: the ephemeral-secret path is fail-closed
            // without a durable store, so tests exercise the same composition
            // (in-memory store standing in for the SQL-backed one).
            DeliveryPasswordResetNotifier {
                owner: DeliveryOwner::builder(Some(Arc::new(
                    astral_common::delivery::InMemoryDeliveryStore::new(),
                )))
                .transport(Arc::new(StaticTransport::new(truth)))
                .build(),
                smtp: fixture_smtp(),
            }
        }

        fn notification<'a>(
            operation_id: &'a str,
            token: &'a str,
        ) -> super::super::PasswordResetNotification<'a> {
            super::super::PasswordResetNotification::new(
                operation_id,
                "alice@example.com",
                token,
                time::PrimitiveDateTime::MIN,
            )
        }

        #[tokio::test]
        async fn explicit_delivery_proof_is_the_only_success() {
            let raw_token = "raw-token-adapter-success";
            let result = notifier(DeliveryTruth::delivered(Some("p"), "receipt"))
                .deliver(notification("op-1", raw_token))
                .await;
            assert_eq!(result, Ok(()));
        }

        #[tokio::test]
        async fn smtp_acceptance_is_not_success_and_maps_to_typed_error() {
            let raw_token = "raw-token-adapter-accepted";
            let error = notifier(DeliveryTruth::accepted(
                None,
                "SMTP MTA queued the message; no final delivery proof exists for email",
            ))
            .deliver(notification("op-2", raw_token))
            .await
            .expect_err("acceptance must not claim delivery");
            assert_eq!(error, PasswordResetDeliveryError::AcceptedNotDelivered);
            assert!(!error.to_string().contains(raw_token));
        }

        #[tokio::test]
        async fn unknown_outcome_maps_to_reconciliation_required() {
            let raw_token = "raw-token-adapter-indoubt";
            let error = notifier(DeliveryTruth::in_doubt("connection lost after payload"))
                .deliver(notification("op-3", raw_token))
                .await
                .expect_err("unknown outcome must be typed");
            assert_eq!(error, PasswordResetDeliveryError::InDoubt);
            assert!(!error.to_string().contains(raw_token));
        }

        #[tokio::test]
        async fn definitive_refusal_maps_to_rejected() {
            let raw_token = "raw-token-adapter-rejected";
            let error = notifier(DeliveryTruth::failed("550 mailbox unavailable"))
                .deliver(notification("op-4", raw_token))
                .await
                .expect_err("refusal must be typed");
            assert_eq!(error, PasswordResetDeliveryError::Rejected);
        }

        #[tokio::test]
        async fn debug_output_never_leaks_the_token() {
            let raw_token = "raw-token-adapter-debug";
            let notifier = notifier(DeliveryTruth::delivered(None, "receipt"));
            let rendered = format!("{notifier:?}");
            assert!(!rendered.contains(raw_token));
            assert!(!rendered.contains("s3cret"));
        }

        #[test]
        fn email_body_carries_the_token_only_in_memory() {
            let raw_token = "raw-token-body-check";
            let body = password_reset_email_body(
                raw_token,
                time::PrimitiveDateTime::new(
                    time::Date::from_calendar_date(2026, time::Month::November, 7).unwrap(),
                    time::Time::MIDNIGHT,
                ),
            );
            assert!(body.contains(raw_token));
            assert!(body.contains("Expires at"));
        }

        #[tokio::test]
        async fn unavailable_notifier_still_fails_closed() {
            let raw_token = "raw-token-unavailable";
            let error = UnavailablePasswordResetNotifier
                .deliver(notification("op-5", raw_token))
                .await
                .expect_err("default notifier must fail closed");
            assert_eq!(error, PasswordResetDeliveryError::Unavailable);
        }
    }
}
