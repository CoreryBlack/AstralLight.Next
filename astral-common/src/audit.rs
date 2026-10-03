//! 审计日志服务
//!
//! 对齐 Java `AuditService`（AstralGeneral/.../service/AuditService.java:1-201）。
//!
//! 分层架构：
//! - `astral-common`：类型定义 + `record_audit()` 纯 tracing 日志（无 MQ/DB 依赖，避免循环依赖）
//! - `astral-trustgraph`：`AuditDualWriteService` 实现 MQ 主路径 + DB 降级双写
//!   （对齐 Java `sendViaMQ()` 模式，AuditService.java:124-137）
//!
//! Java 基线对照：
//! - 事件类型: AuditService.java:19-24 (6 种 + category 分类)
//! - MQ 双写: AuditService.java:124-137 sendViaMQ() — MQ 主路径 + DB fallbackInsert()

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::service::AUDIT_DETAIL_MAX_BYTES;

const MAX_OWNED_AUDIT_TASKS: usize = 1_024;

#[derive(Default)]
struct AuditTaskState {
    closed: bool,
    draining: bool,
    failed: bool,
    tasks: tokio::task::JoinSet<()>,
}

#[derive(Default)]
struct AuditTaskOwner {
    state: Mutex<AuditTaskState>,
    drain: tokio::sync::Mutex<()>,
}

impl AuditTaskOwner {
    fn spawn<F>(&self, task: F) -> Result<(), &'static str>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let mut state = self.state.lock().map_err(|_| "audit task owner poisoned")?;
        while let Some(result) = state.tasks.try_join_next() {
            if result.is_err() {
                state.failed = true;
                tracing::error!("owned policy audit task failed");
            }
        }
        if state.closed {
            return Err("audit task admission closed");
        }
        if state.tasks.len() >= MAX_OWNED_AUDIT_TASKS {
            return Err("audit task capacity exceeded");
        }
        state.tasks.spawn(task);
        Ok(())
    }

    async fn shutdown(&self, deadline: Duration) -> Result<(), String> {
        let _drain = self.drain.lock().await;
        let (mut tasks, failed) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| "audit task owner poisoned".to_owned())?;
            if state.draining {
                return Err("previous audit drain was interrupted; outcome unknown".to_owned());
            }
            state.closed = true;
            state.draining = true;
            (std::mem::take(&mut state.tasks), state.failed)
        };
        let mut failed = failed;
        let completed = tokio::time::timeout(deadline, async {
            while let Some(result) = tasks.join_next().await {
                failed |= result.is_err();
            }
        })
        .await
        .is_ok();
        if !completed {
            tasks.abort_all();
            failed = true;
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| "audit task owner poisoned".to_owned())?;
        state.draining = false;
        state.failed |= failed;
        if !completed {
            Err("policy audit drain timed out; pending outcomes unknown".to_owned())
        } else if state.failed {
            Err("policy audit task failure was observed during runtime".to_owned())
        } else {
            Ok(())
        }
    }
}

fn audit_task_owner() -> &'static AuditTaskOwner {
    static OWNER: OnceLock<AuditTaskOwner> = OnceLock::new();
    OWNER.get_or_init(AuditTaskOwner::default)
}

pub fn spawn_owned_audit<F>(task: F) -> Result<(), &'static str>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    audit_task_owner().spawn(task)
}

/// Call only after every producer has stopped; task drain is not durable audit proof.
pub async fn drain_owned_audit_tasks(deadline: Duration) -> Result<(), String> {
    audit_task_owner().shutdown(deadline).await
}

/// 审计事件类型（对齐 Java AuditService.java:19-24）
///
/// Java 6 种事件：LOGIN_SUCCESS, LOGIN_FAILURE, IDENTITY_UNBIND,
/// CARD_SWITCH, AUTHZ_CHECK, DATA_SCOPE_DENY
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditEventType {
    /// 对应 Java AUTHZ_CHECK — 权限检查（Java 常量为 AUTHZ_CHECK，非 PERMISSION_CHECK）
    #[serde(rename = "AUTHZ_CHECK")]
    PermissionCheck,
    /// 对应 Java LOGIN_SUCCESS
    LoginSuccess,
    /// 对应 Java LOGIN_FAILURE
    LoginFailure,
    /// 对应 Java — 规则变更
    RuleChange,
    /// 对应 Java — Token 撤销
    TokenRevocation,
    /// 对应 Java IDENTITY_UNBIND — 身份解绑
    IdentityUnbind,
    /// 对应 Java CARD_SWITCH — 卡片切换
    CardSwitch,
    /// 对应 Java DATA_SCOPE_DENY — 数据范围拒绝
    DataScopeDeny,
}

/// 审计日志分类（对齐 Java `sendViaMQ(message, category)` 的 category 参数）
///
/// Java 对照：AuditService.java:56,71,87,102,121
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditCategory {
    /// 对应 Java "permission" — 权限检查
    Permission,
    /// 对应 Java "identity-login" — 登录事件
    IdentityLogin,
    /// 对应 Java "identity-event" — 身份事件
    IdentityEvent,
    /// 对应 Java "card-switch" — 卡片切换
    CardSwitch,
    /// 对应 Java "data-scope" — 数据范围
    DataScope,
}

/// 审计日志条目
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub user_id: Option<i64>,
    pub card_id: Option<i64>,
    pub action: String,
    pub resource: String,
    pub decision: String,
    pub reason: Option<String>,
    pub event_type: AuditEventType,
    /// 审计分类（对齐 Java category 参数）
    pub category: Option<AuditCategory>,
    pub source_ip: Option<String>,
    pub request_id: Option<String>,
    pub domain_id: Option<i64>,
    pub tenant_id: Option<i64>,
    pub detail: Option<String>,
}

/// 审计日志 DB 写入适配器。
///
/// 该 trait 保持 `astral-common` 与 `astral-db` 解耦，业务服务可以注入自己
/// 的 SQLx adapter，而不会形成 common -> db -> common 的循环依赖。
#[async_trait::async_trait]
pub trait AuditDbWriter: Send + Sync {
    async fn insert_audit(&self, entry: &AuditEntry) -> Result<(), String>;
}

/// MQ-first + DB fallback 审计写入器。
///
/// MQ producer 复用 common 中已有的 `MqProducerRef` 适配器：MQ 尚未就绪时
/// 直接走 DB fallback；MQ 发布失败也走 DB fallback。DB fallback 失败会重试一次，
/// 最终通过 `record_audit` 留下结构化日志，且整个过程不会影响权限判定。
#[derive(Clone)]
pub struct AuditDualWrite {
    db: Arc<dyn AuditDbWriter>,
}

impl AuditDualWrite {
    pub fn new(db: Arc<dyn AuditDbWriter>) -> Self {
        Self { db }
    }

    /// 执行 MQ-first / DB-fallback 写入。
    pub async fn write(&self, entry: AuditEntry) {
        if let Some(producer) = crate::service::global_mq_producer() {
            let event = crate::service::AuditLogEvent {
                user_id: entry.user_id,
                card_id: entry.card_id,
                action: entry.action.clone(),
                resource: entry.resource.clone(),
                decision: entry.decision.clone(),
                reason: entry.reason.clone(),
                event_type: audit_event_type_name(&entry.event_type),
                source_ip: entry.source_ip.clone(),
                request_id: entry.request_id.clone(),
                domain_id: entry.domain_id,
                tenant_id: entry.tenant_id,
                detail: entry.detail.clone(),
            };
            match producer.publish_audit_log(event).await {
                Ok(()) => {
                    tracing::debug!(
                        event_type = %audit_event_type_name(&entry.event_type),
                        "audit log sent via MQ"
                    );
                    record_audit(entry);
                    return;
                }
                Err(error) => {
                    tracing::warn!(
                        error = %error,
                        event_type = %audit_event_type_name(&entry.event_type),
                        "MQ audit publish failed, using DB fallback"
                    );
                }
            }
        } else {
            tracing::debug!("MQ audit producer is not initialized, using DB fallback");
        }

        for attempt in 1..=2 {
            match self.db.insert_audit(&entry).await {
                Ok(()) => {
                    tracing::info!(
                        attempt,
                        event_type = %audit_event_type_name(&entry.event_type),
                        "audit log written to DB fallback"
                    );
                    record_audit(entry);
                    return;
                }
                Err(error) => {
                    tracing::error!(
                        attempt,
                        error = %error,
                        event_type = %audit_event_type_name(&entry.event_type),
                        "audit log DB fallback failed"
                    );
                }
            }
        }

        record_audit(entry);
    }

    /// 记录权限判定审计。调用方应在独立任务中调用，以免审计 IO 影响请求。
    #[allow(clippy::too_many_arguments)]
    pub async fn record_permission_check(
        &self,
        user_id: Option<i64>,
        card_id: Option<i64>,
        domain_id: Option<i64>,
        tenant_id: Option<i64>,
        resource: &str,
        action: &str,
        allowed: bool,
        reason: &str,
        path: &str,
    ) {
        self.record_permission_check_with_request_id(
            user_id, card_id, domain_id, tenant_id, resource, action, allowed, reason, path, None,
        )
        .await;
    }

    /// 记录带请求关联标识的权限判定审计。
    ///
    /// `request_id` 必须已由服务边界按其 durable 宽度和安全字符合同验证；
    /// common 层只原样传播，不截断或归一化。
    #[allow(clippy::too_many_arguments)]
    pub async fn record_permission_check_with_request_id(
        &self,
        user_id: Option<i64>,
        card_id: Option<i64>,
        domain_id: Option<i64>,
        tenant_id: Option<i64>,
        resource: &str,
        action: &str,
        allowed: bool,
        reason: &str,
        path: &str,
        request_id: Option<String>,
    ) {
        self.record_permission_check_with_request_detail(
            user_id, card_id, domain_id, tenant_id, resource, action, allowed, reason, path,
            request_id, None,
        )
        .await;
    }

    /// 记录带请求关联标识与显式 detail 的权限判定审计。
    ///
    /// `request_id` 必须已由服务边界按其 durable 宽度和安全字符合同验证；
    /// `detail` 是调用方构造好的有界审计明细（例如 ORG_SCOPE ALLOW 的结构化
    /// JSON provenance），common 层原样传播；`None` 或空白时回退请求路径，
    /// 保持非 ORG 判定的既有 detail 行为不变。
    #[allow(clippy::too_many_arguments)]
    pub async fn record_permission_check_with_request_detail(
        &self,
        user_id: Option<i64>,
        card_id: Option<i64>,
        domain_id: Option<i64>,
        tenant_id: Option<i64>,
        resource: &str,
        action: &str,
        allowed: bool,
        reason: &str,
        path: &str,
        request_id: Option<String>,
        detail: Option<String>,
    ) {
        self.write(AuditEntry {
            user_id,
            card_id,
            action: action.to_string(),
            resource: resource.to_string(),
            decision: if allowed { "ALLOW" } else { "DENY" }.to_string(),
            reason: Some(reason.to_string()),
            event_type: AuditEventType::PermissionCheck,
            category: Some(AuditCategory::Permission),
            source_ip: None,
            request_id,
            domain_id,
            tenant_id,
            detail: permission_audit_detail(detail, path),
        })
        .await;
    }
}

/// permission 审计 detail 合同：显式 detail 优先（生产方已负责有界化），
/// `None` 或空白时回退请求路径，保持既有非 ORG 行为不变。
fn permission_audit_detail(detail: Option<String>, path: &str) -> Option<String> {
    match detail {
        Some(detail) if !detail.trim().is_empty() => Some(detail),
        _ => Some(path.to_string()),
    }
}

/// 审计 detail JSON 的 schema 标记（区分结构化 detail 与既有纯路径 detail）。
pub const ORG_PROVENANCE_AUDIT_DETAIL_SCHEMA: &str = "audit-detail-org-v1";

/// 在 UTF-8 字符边界上把输入截断到不超过 `max_bytes` 字节。
pub fn truncate_at_char_boundary(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

/// 仅当决策携带通过 org_scope 合同校验的组织 provenance 时，构造有界结构化
/// JSON 审计 detail（正常请求路径 + orgProvenance）。校验失败视为不可信
/// provenance：仅告警并返回 `None`（审计层回退既有路径 detail），绝不影响
/// 授权决策，也绝不进入 Prometheus 标签（metrics 标签保持闭集枚举）。
///
/// detail 总字节上界即共享传输合同常量
/// [`crate::service::AUDIT_DETAIL_MAX_BYTES`]：先序列化并完整保留
/// provenance，再用 `path` 为空的基准序列化测出 schema wrapper 与
/// provenance 的真实字节开销，把剩余预算全部分配给请求路径；JSON 转义可能
/// 放大已截断路径的序列化长度（如控制字符展开为 `\u00XX`），因此按最终
/// 序列化结果迭代收缩路径原始字节预算直至收敛。wrapper 加 provenance 自身
/// 超界（当前 org_scope 合同字段上界下不可达，仅防御合同未来放宽）或序列化
/// 失败时，对审计增强 fail-closed：告警并返回 `None` 回退纯路径 detail。
/// 结构化 provenance 字段永不截断，授权决策不受影响。
///
/// 该 helper 是宿主无关的共享实现：TrustGraph/Identity/Monitor 宿主中间件对
/// ORG_SCOPE 判定统一经 [`record_permission_audit_with_request_detail`] 传播
/// 本函数的产出，保证跨宿主审计 detail 形状一致。
pub fn org_provenance_audit_detail(
    path: &str,
    provenance: &astral_types::org_scope::OrgBranchProvenance,
) -> Option<String> {
    if let Err(error) = provenance.validate() {
        tracing::warn!(
            code = error.code.as_str(),
            "org provenance failed audit detail validation; falling back to path detail"
        );
        return None;
    }
    let provenance_value = serde_json::to_value(provenance).ok()?;
    // 基准（path 为空）序列化：schema wrapper + 完整 provenance 的真实开销。
    let base = serde_json::to_string(&serde_json::json!({
        "schema": ORG_PROVENANCE_AUDIT_DETAIL_SCHEMA,
        "path": "",
        "orgProvenance": &provenance_value,
    }))
    .ok()?;
    if base.len() > AUDIT_DETAIL_MAX_BYTES {
        tracing::warn!(
            detail_bytes = base.len(),
            max_bytes = AUDIT_DETAIL_MAX_BYTES,
            "org provenance does not fit the audit detail replay bound; falling back to path detail"
        );
        return None;
    }
    let mut path_budget = AUDIT_DETAIL_MAX_BYTES - base.len();
    loop {
        let detail = serde_json::to_string(&serde_json::json!({
            "schema": ORG_PROVENANCE_AUDIT_DETAIL_SCHEMA,
            "path": truncate_at_char_boundary(path, path_budget),
            "orgProvenance": &provenance_value,
        }))
        .ok()?;
        if detail.len() <= AUDIT_DETAIL_MAX_BYTES {
            return Some(detail);
        }
        // 每移除一个输入字节至少减少一个输出字节（转义序列 >= 每输入字节
        // 1 字节），按超出量收缩原始预算必然收敛；预算归零后 detail 退化为
        // 基准序列化（<= 上界），循环终止。
        path_budget = path_budget.saturating_sub(detail.len() - AUDIT_DETAIL_MAX_BYTES);
    }
}

/// 事件类型的 wire 值，必须遵循 serde 合同而不是 Rust Debug 名称。
pub fn audit_event_type_name(event_type: &AuditEventType) -> String {
    serde_json::to_value(event_type)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_else(|| "UNKNOWN".to_string())
}

/// 进程级 DB writer 注册点。每个业务服务在启动时注入自己的 SQLx adapter。
static GLOBAL_AUDIT_DB_WRITER: OnceLock<Arc<dyn AuditDbWriter>> = OnceLock::new();

pub fn register_audit_db_writer(writer: Arc<dyn AuditDbWriter>) {
    let _ = GLOBAL_AUDIT_DB_WRITER.set(writer);
}

pub fn global_audit_dual_write() -> Option<AuditDualWrite> {
    GLOBAL_AUDIT_DB_WRITER
        .get()
        .cloned()
        .map(AuditDualWrite::new)
}

/// Static reasons permitted for Gateway -> Identity internal app-session
/// audit events. Keeping this as an enum prevents request data from leaking
/// into the audit reason/detail fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternalSessionAuditReason {
    AppSessionSuccess,
    AppUserNotFound,
    SessionIssuanceFailed,
    InternalAssertionInvalid,
    InternalAssertionMissing,
    InternalBodyHashInvalid,
    InternalSignatureInvalid,
    InternalReplayDetected,
    IdempotencyReplay,
    IdempotencyConflict,
    AuthStateUnavailable,
    BodyInvalid,
    BodyTooLarge,
}

impl InternalSessionAuditReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AppSessionSuccess => "APP_SESSION_SUCCESS",
            Self::AppUserNotFound => "APP_USER_NOT_FOUND",
            Self::SessionIssuanceFailed => "SESSION_ISSUANCE_FAILED",
            Self::InternalAssertionInvalid => "INTERNAL_ASSERTION_INVALID",
            Self::InternalAssertionMissing => "INTERNAL_ASSERTION_MISSING",
            Self::InternalBodyHashInvalid => "INTERNAL_BODY_HASH_INVALID",
            Self::InternalSignatureInvalid => "INTERNAL_SIGNATURE_INVALID",
            Self::InternalReplayDetected => "INTERNAL_REPLAY_DETECTED",
            Self::IdempotencyReplay => "IDEMPOTENCY_REPLAY",
            Self::IdempotencyConflict => "IDEMPOTENCY_CONFLICT",
            Self::AuthStateUnavailable => "AUTH_STATE_UNAVAILABLE",
            Self::BodyInvalid => "BODY_INVALID",
            Self::BodyTooLarge => "BODY_TOO_LARGE",
        }
    }
}

/// Queue an internal app-session audit event without blocking authentication.
/// The registered writer retains MQ-first/DB-fallback semantics; when no
/// writer is registered, structured tracing remains the safe fallback.
pub fn spawn_internal_session_audit(
    user_id: i64,
    success: bool,
    reason: InternalSessionAuditReason,
) {
    let entry = AuditEntry {
        user_id: Some(user_id),
        card_id: None,
        action: "login".into(),
        resource: "identity-internal-session".into(),
        decision: if success { "ALLOW" } else { "DENY" }.into(),
        reason: Some(reason.as_str().into()),
        event_type: if success {
            AuditEventType::LoginSuccess
        } else {
            AuditEventType::LoginFailure
        },
        category: Some(AuditCategory::IdentityLogin),
        source_ip: None,
        request_id: None,
        domain_id: None,
        tenant_id: None,
        detail: Some("gateway-to-identity-internal-session".into()),
    };

    let Some(writer) = global_audit_dual_write() else {
        record_audit(entry);
        return;
    };
    if tokio::runtime::Handle::try_current().is_err() {
        record_audit(entry);
        return;
    }
    let queued_entry = entry.clone();
    if let Err(reason) = spawn_owned_audit(async move {
        writer.write(queued_entry).await;
    }) {
        tracing::warn!(reason, "internal session audit admission refused");
        record_audit(entry);
    }
}

/// 公共权限审计入口：没有初始化 DB writer 时也保留 tracing 可观测记录。
#[allow(clippy::too_many_arguments)]
pub async fn record_permission_audit(
    user_id: Option<i64>,
    card_id: Option<i64>,
    domain_id: Option<i64>,
    tenant_id: Option<i64>,
    resource: &str,
    action: &str,
    allowed: bool,
    reason: &str,
    path: &str,
) {
    record_permission_audit_with_request_id(
        user_id, card_id, domain_id, tenant_id, resource, action, allowed, reason, path, None,
    )
    .await;
}

/// 公共权限审计入口，附带已由调用服务验证的请求关联标识。
#[allow(clippy::too_many_arguments)]
pub async fn record_permission_audit_with_request_id(
    user_id: Option<i64>,
    card_id: Option<i64>,
    domain_id: Option<i64>,
    tenant_id: Option<i64>,
    resource: &str,
    action: &str,
    allowed: bool,
    reason: &str,
    path: &str,
    request_id: Option<String>,
) {
    record_permission_audit_with_request_detail(
        user_id, card_id, domain_id, tenant_id, resource, action, allowed, reason, path,
        request_id, None,
    )
    .await;
}

/// 公共权限审计入口，附带已由调用服务验证的请求关联标识与显式有界 detail。
///
/// `detail` 优先于请求路径写入 audit detail（MQ 路径与 DB fallback 一致保留）；
/// `None`/空白时回退请求路径，非 ORG 判定行为不变。
#[allow(clippy::too_many_arguments)]
pub async fn record_permission_audit_with_request_detail(
    user_id: Option<i64>,
    card_id: Option<i64>,
    domain_id: Option<i64>,
    tenant_id: Option<i64>,
    resource: &str,
    action: &str,
    allowed: bool,
    reason: &str,
    path: &str,
    request_id: Option<String>,
    detail: Option<String>,
) {
    let Some(writer) = global_audit_dual_write() else {
        tracing::error!(
            resource,
            action,
            allowed,
            "audit DB writer is not initialized; permission decision remains unchanged"
        );
        record_audit(AuditEntry {
            user_id,
            card_id,
            action: action.to_string(),
            resource: resource.to_string(),
            decision: if allowed { "ALLOW" } else { "DENY" }.to_string(),
            reason: Some(reason.to_string()),
            event_type: AuditEventType::PermissionCheck,
            category: Some(AuditCategory::Permission),
            source_ip: None,
            request_id,
            domain_id,
            tenant_id,
            detail: permission_audit_detail(detail, path),
        });
        return;
    };
    writer
        .record_permission_check_with_request_detail(
            user_id, card_id, domain_id, tenant_id, resource, action, allowed, reason, path,
            request_id, detail,
        )
        .await;
}

/// 记录审计日志的结构化 tracing 兜底。
///
/// MQ-first/DB-fallback 由 `AuditDualWrite` 负责；此函数只输出不可丢失的
/// 可观测记录，避免在双写成功后再次发布 MQ 造成重复审计。
pub fn record_audit(entry: AuditEntry) {
    tracing::info!(
        target = "audit_log",
        user_id = ?entry.user_id,
        card_id = ?entry.card_id,
        action = %entry.action,
        resource = %entry.resource,
        decision = %entry.decision,
        reason = ?entry.reason,
        event_type = %audit_event_type_name(&entry.event_type),
        category = ?entry.category,
        source_ip = ?entry.source_ip,
        request_id = ?entry.request_id,
        domain_id = ?entry.domain_id,
        tenant_id = ?entry.tenant_id,
        detail = ?entry.detail,
        "audit"
    );
}

#[cfg(test)]
mod tests {
    use super::{
        audit_event_type_name, org_provenance_audit_detail, permission_audit_detail,
        truncate_at_char_boundary, AuditEventType, ORG_PROVENANCE_AUDIT_DETAIL_SCHEMA,
    };
    use crate::service::AUDIT_DETAIL_MAX_BYTES;
    use astral_types::org_scope::{OrgBranchKind, OrgBranchProvenance, OrgGrantRef};

    #[tokio::test]
    async fn owned_audit_tasks_drain_before_admission_closes() {
        let owner = super::AuditTaskOwner::default();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        owner
            .spawn(async {
                tokio::task::yield_now().await;
                done_tx.send(()).unwrap();
            })
            .unwrap();
        owner
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .unwrap();
        done_rx.await.unwrap();
        assert!(owner.spawn(async {}).is_err());
        owner
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn interrupted_audit_drain_cannot_report_success() {
        let owner = super::AuditTaskOwner::default();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        owner
            .spawn(async {
                ready_tx.send(()).unwrap();
                std::future::pending::<()>().await;
            })
            .unwrap();
        ready_rx.await.unwrap();
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(10),
            owner.shutdown(std::time::Duration::from_secs(1)),
        )
        .await
        .is_err());
        assert!(owner
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .unwrap_err()
            .contains("unknown"));
    }

    #[tokio::test]
    async fn audit_drain_timeout_is_sticky_failure() {
        let owner = super::AuditTaskOwner::default();
        owner.spawn(std::future::pending()).unwrap();
        assert!(owner
            .shutdown(std::time::Duration::from_millis(1))
            .await
            .is_err());
        assert!(owner
            .shutdown(std::time::Duration::from_secs(1))
            .await
            .is_err());
    }

    #[test]
    fn internal_session_audit_uses_owned_admission_with_tracing_fallback() {
        let source = include_str!("audit.rs");
        let body = source
            .split("pub fn spawn_internal_session_audit(")
            .nth(1)
            .unwrap()
            .split("pub async fn record_permission_audit(")
            .next()
            .unwrap();
        assert!(body.contains("spawn_owned_audit(async move"));
        assert!(body.contains("record_audit(entry)"));
        assert!(!body.contains("handle.spawn("));
    }

    #[test]
    fn permission_event_uses_authz_check_wire_contract() {
        let event = serde_json::to_value(AuditEventType::PermissionCheck).unwrap();
        assert_eq!(event.as_str(), Some("AUTHZ_CHECK"));
        assert_eq!(
            audit_event_type_name(&AuditEventType::PermissionCheck),
            "AUTHZ_CHECK"
        );
    }

    #[test]
    fn permission_audit_detail_prefers_explicit_detail_and_falls_back_to_path() {
        // 显式 detail（例如 ORG_SCOPE ALLOW 的结构化 JSON）原样保留。
        assert_eq!(
            permission_audit_detail(Some("{\"path\":\"/stats\"}".into()), "/stats"),
            Some("{\"path\":\"/stats\"}".to_string())
        );
        // None / 空白 detail 回退请求路径，保持非 ORG 行为不变。
        assert_eq!(
            permission_audit_detail(None, "/stats/projector"),
            Some("/stats/projector".to_string())
        );
        assert_eq!(
            permission_audit_detail(Some("   ".into()), "/stats/projector"),
            Some("/stats/projector".to_string())
        );
    }

    fn valid_org_provenance() -> OrgBranchProvenance {
        OrgBranchProvenance {
            receiving_tenant_id: 2,
            source_tenant_id: 1,
            resource_tenant_id: 2,
            root_tenant_id: 1,
            membership_id: "11111111-1111-4111-8111-111111111111".to_owned(),
            membership_revision: 3,
            branch_kind: OrgBranchKind::Shared,
            grant_ref: OrgGrantRef {
                tenant_id: 1,
                grant_id: "22222222-2222-4222-8222-222222222222".to_owned(),
                revision: 5,
            },
            publication_generation: 7,
            manifest_digest_hex: "a".repeat(64),
            approval_operation_id: "org-op-1".to_owned(),
        }
    }

    #[test]
    fn org_provenance_audit_detail_embeds_path_and_validated_provenance() {
        let detail = org_provenance_audit_detail("/stats/projector", &valid_org_provenance())
            .expect("valid provenance must produce a structured detail");
        // 正常路径 + 小体积 provenance 时不得触发任何截断或降级。
        assert!(detail.len() <= AUDIT_DETAIL_MAX_BYTES);
        let value: serde_json::Value = serde_json::from_str(&detail).unwrap();
        assert_eq!(value["schema"], ORG_PROVENANCE_AUDIT_DETAIL_SCHEMA);
        assert_eq!(value["schema"], "audit-detail-org-v1");
        assert_eq!(value["path"], "/stats/projector");
        assert_eq!(value["orgProvenance"]["receivingTenantId"], 2);
        assert_eq!(value["orgProvenance"]["sourceTenantId"], 1);
        assert_eq!(value["orgProvenance"]["branchKind"], "SHARED");
        assert_eq!(
            value["orgProvenance"]["grantRef"]["grantId"],
            "22222222-2222-4222-8222-222222222222"
        );
        assert_eq!(value["orgProvenance"]["publicationGeneration"], 7);
    }

    #[test]
    fn invalid_org_provenance_is_omitted_from_audit_detail() {
        // 合同校验失败（fail-closed）：provenance 不进入 detail，回退路径 detail；
        // 授权决策与 metrics 不受影响。
        let mut invalid = valid_org_provenance();
        invalid.receiving_tenant_id = 0;
        assert!(org_provenance_audit_detail("/stats", &invalid).is_none());
    }

    #[test]
    fn audit_detail_path_is_bounded_on_char_boundaries() {
        let short = "/stats";
        assert_eq!(
            truncate_at_char_boundary(short, AUDIT_DETAIL_MAX_BYTES),
            short
        );
        assert_eq!(truncate_at_char_boundary(short, 0), "");
        assert_eq!(truncate_at_char_boundary("", 8), "");

        let long_ascii = "/a".repeat(400);
        let truncated = truncate_at_char_boundary(&long_ascii, 512);
        assert_eq!(truncated.len(), 512);

        // 多字节字符：截断点必须落在 UTF-8 字符边界上。
        let multibyte = format!("{}中中中", "a".repeat(511));
        let truncated = truncate_at_char_boundary(&multibyte, 512);
        assert!(truncated.len() <= 512);
        assert!(multibyte.is_char_boundary(truncated.len()));
        // 预算为 0 时给出空路径而不是 panic。
        assert_eq!(truncate_at_char_boundary(&multibyte, 0), "");
    }

    #[test]
    fn org_audit_detail_stays_within_replay_bound_for_worst_case_provenance() {
        // 合同允许的最大体积 provenance（i64::MAX 租户、u64::MAX 代次、64 字节
        // digest 与操作 ID）叠加远超重放字段上界的多字节路径：无界拼接必然
        // 超过重放字段合同，路径必须按真实剩余预算（wrapper + provenance 实
        // 测开销之外的余额）截断。
        let mut provenance = valid_org_provenance();
        provenance.receiving_tenant_id = i64::MAX;
        provenance.source_tenant_id = i64::MAX;
        provenance.resource_tenant_id = i64::MAX;
        provenance.root_tenant_id = i64::MAX;
        provenance.membership_revision = u64::MAX;
        provenance.grant_ref.tenant_id = i64::MAX;
        provenance.grant_ref.revision = u64::MAX;
        provenance.publication_generation = u64::MAX;
        provenance.manifest_digest_hex = "b".repeat(64);
        provenance.approval_operation_id = "op".repeat(32);
        let serialized_provenance = serde_json::to_value(&provenance).unwrap();

        let path = format!("/{}", "中".repeat(600));
        let detail = org_provenance_audit_detail(&path, &provenance)
            .expect("contract-valid provenance must produce a structured detail");

        // 重放字段合同上界（共享合同常量 astral_common::service::AUDIT_DETAIL_MAX_BYTES）。
        assert!(
            detail.len() <= AUDIT_DETAIL_MAX_BYTES,
            "structured detail is {} bytes; bound is {AUDIT_DETAIL_MAX_BYTES}",
            detail.len()
        );
        let value: serde_json::Value =
            serde_json::from_str(&detail).expect("detail must be valid JSON");
        assert_eq!(value["schema"], ORG_PROVENANCE_AUDIT_DETAIL_SCHEMA);
        // 结构化 provenance 完整保留（永不截断、逐字段一致）。
        assert_eq!(value["orgProvenance"], serialized_provenance);
        // path 是原路径的字符边界安全前缀，且确实被有界化（非平凡截断）。
        let detail_path = value["path"].as_str().expect("path must be a JSON string");
        assert!(path.starts_with(detail_path));
        assert!(path.is_char_boundary(detail_path.len()));
        assert!(detail_path.len() < path.len());
    }

    #[test]
    fn org_audit_detail_bounding_converges_under_json_escape_expansion() {
        // JSON 转义会放大序列化长度（引号/反斜杠翻倍，控制字符展开为
        // \u00XX 六字节）：只按原始字节截断会超界，预算必须按最终序列化
        // 字节收敛。
        for path in [
            "\\\"".repeat(700),   // 每个输入字节转义后翻倍
            "\u{1}".repeat(1024), // 每个输入字节展开为 6 字节 \u0001
        ] {
            let detail = org_provenance_audit_detail(&path, &valid_org_provenance())
                .expect("path escaping must not drop the authorization provenance enrichment");
            assert!(
                detail.len() <= AUDIT_DETAIL_MAX_BYTES,
                "escaped detail is {} bytes; bound is {AUDIT_DETAIL_MAX_BYTES}",
                detail.len()
            );
            let value: serde_json::Value =
                serde_json::from_str(&detail).expect("detail must be valid JSON");
            assert_eq!(value["schema"], ORG_PROVENANCE_AUDIT_DETAIL_SCHEMA);
            assert!(value["orgProvenance"].is_object());
            let detail_path = value["path"].as_str().expect("path must be a JSON string");
            assert!(path.starts_with(detail_path));
        }
    }
}
