//! 具体消费者实现
//!
//! 各业务域的 MQ 消费者，在对应服务的 main.rs 中调用 `start()` 启动。
//! 每个消费者在独立的 tokio 任务中运行，互不阻塞。

use std::collections::HashSet;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use astral_db::{insert_or_increment_terminal, AuditQuarantineInput, AuditQuarantineStatus};
use futures_util::StreamExt;
use lapin::message::Delivery;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, BasicNackOptions};
use lapin::types::{FieldTable, ShortString};
use lapin::{Channel, Confirmation};
use redis::AsyncCommands;
use sqlx::MySqlPool;
use tokio::sync::oneshot;
use tokio::time::timeout;

use crate::config::{
    QueueDef, EXCHANGE_DLX, MAX_RETRY, QUEUES, QUEUE_AUDIT_LOG, QUEUE_AUTH_SESSION_REVOCATION,
    QUEUE_LOGIN_EVENT,
};
use crate::consumer::{
    canonical_legacy_message_id, claim_message, complete_message, decode_delivery,
    delivery_message_id, message_type_for_queue, release_message, retry_count_from_delivery,
    terminal_canonical_message_id, validate_delivery_envelope, Consumer, IdempotencyClaim,
};
use crate::error::MqError;
use crate::producer::{AuditLogPayload, AuthSessionRevocationPayload, LoginEventPayload};

/// 会话撤销消费所需 DB（由 identity main.rs 注入）
static SESSION_REVOCATION_DB: OnceLock<MySqlPool> = OnceLock::new();

/// 登录事件消费所需 DB（由 identity main.rs 注入）
static LOGIN_EVENT_DB: OnceLock<MySqlPool> = OnceLock::new();

/// 审计日志消费所需 DB（由 trustgraph main.rs 注入）
static AUDIT_LOG_DB: OnceLock<MySqlPool> = OnceLock::new();

/// 注入会话撤销 consumer 使用的 DB pool（仅 identity main.rs 调用一次）
pub fn set_session_revocation_db(pool: MySqlPool) {
    let _ = SESSION_REVOCATION_DB.set(pool);
}

/// 注入登录事件 consumer 使用的 DB pool（仅 identity main.rs 调用一次）
pub fn set_login_event_db(pool: MySqlPool) {
    let _ = LOGIN_EVENT_DB.set(pool);
}

/// 注入审计日志 consumer 使用的 DB pool（仅 trustgraph main.rs 调用一次）
pub fn set_audit_log_db(pool: MySqlPool) {
    let _ = AUDIT_LOG_DB.set(pool);
}

/// Generic envelope retained for compatibility with callers that only need to
/// inspect an untyped message. Business consumers must use a typed payload.
#[allow(dead_code)]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenericMessage {
    pub message_id: String,
    pub message_type: Option<String>,
    #[allow(dead_code)]
    pub card_id: Option<i64>,
    #[allow(dead_code)]
    pub user_id: Option<i64>,
    pub payload: Option<serde_json::Value>,
}

/// 启动通用业务消费者。
///
/// 审计、登录、权限刷新和会话撤销由各自 owner 服务显式启动；这里不再
/// 注册会 ACK 丢弃 payload 的通用 handler。
pub async fn start_all_consumers(_channel: &Channel) -> Result<Vec<String>, MqError> {
    Ok(Vec::new())
}

/// DLQ 消费归属。
///
/// `start_dlq_consumers` 只接受这两个当前有明确 owner 的值；没有 owner 的
/// Learn/Chat/Duo 队列仍保留在 topology，但不会被任何当前服务消费。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DlqOwner {
    Identity,
    TrustGraph,
}

impl DlqOwner {
    fn quarantine_queue(self, queue_name: &str) -> bool {
        matches!(
            (self, queue_name),
            (Self::Identity, QUEUE_LOGIN_EVENT) | (Self::TrustGraph, QUEUE_AUDIT_LOG)
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DlqStartupError {
    #[error("invalid DLQ owner mapping: {0}")]
    InvalidMapping(String),
    #[error("DLQ consumer startup failed: {0}")]
    Consume(String),
}

impl From<DlqStartupError> for MqError {
    fn from(error: DlqStartupError) -> Self {
        MqError::Consume(error.to_string())
    }
}

impl DlqOwner {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::TrustGraph => "trustgraph",
        }
    }
}

/// 启动指定 owner 的 DLQ 消费者，不允许默认全量消费。
///
/// 死信消息按 `x-retry-count` 预算重投回原业务队列（经 astral.dlx → 业务队列，携带递增计数）。
/// republish/confirm 失败使用独立 `x-dlq-republish-count` 预算；失败副本先确认写回 durable DLQ
/// 后 ACK 当前 delivery，无法确认保留时走结构化 terminal nack(requeue=false)。超过业务预算后进入终态并记录结构化告警。所有 `basic_consume` 在 starter 返回前完成；
/// 任一队列声明消费者失败都会返回错误，避免启动成功但静默缺 consumer。
///
/// owner mapping 是进程内静态契约：每个已声明业务队列必须出现且只能出现一次；
/// 未分配给当前 owner 的队列显式标记为 `None`，不会被 Identity 或 TrustGraph 领取。
/// 不使用隐式环境变量，也不依赖 broker-side leader election。
pub async fn start_dlq_consumers(
    channel: &Channel,
    owner: DlqOwner,
    quarantine_db: Option<MySqlPool>,
) -> Result<(), DlqStartupError> {
    use lapin::options::BasicConsumeOptions;
    use lapin::types::{FieldTable, ShortString};

    let queue_defs = dlq_queue_defs_for_owner(owner).map_err(DlqStartupError::InvalidMapping)?;
    let mut consumers = Vec::with_capacity(queue_defs.len());

    // 先完成全部 basic_consume，再创建后台任务。这样任何一个队列失败时
    // starter 都返回 Err，调用方不会把"部分启动"误判为成功。
    for def in queue_defs {
        let dlq = crate::config::dlx_routing_key(def.name);
        let consumer_tag = dlq_consumer_tag(owner, def.name);
        let consumer = channel
            .basic_consume(
                ShortString::from(dlq.as_str()),
                ShortString::from(consumer_tag.as_str()),
                BasicConsumeOptions::default(),
                FieldTable::default(),
            )
            .await
            .map_err(|error| {
                DlqStartupError::Consume(format!(
                    "owner={} queue={} consumer_tag={}: {error}",
                    owner.as_str(),
                    dlq,
                    consumer_tag
                ))
            })?;
        consumers.push((def, dlq, consumer_tag, consumer));
    }

    for (def, dlq, consumer_tag, consumer) in consumers {
        let channel = channel.clone();
        let business_queue = def.name.to_string();
        let business_rk = def.routing_key.to_string();
        let business_exchange = def.exchange_name.to_string();
        let owner_name = owner.as_str();
        let log_dlq = dlq.clone();
        let quarantine_db = quarantine_db.clone();
        let log_consumer_tag = consumer_tag.clone();
        tracing::info!(
            owner = owner_name,
            queue = %dlq,
            consumer_tag = %consumer_tag,
            "DLQ re-drive consumer started"
        );
        let context = DlqConsumerContext {
            owner: owner_name,
            dlq,
            consumer_tag,
            business_queue,
            business_rk,
            business_exchange,
            quarantine_db,
            quarantine_enabled: owner.quarantine_queue(def.name),
        };
        tokio::spawn(async move {
            if let Err(error) = run_dlq_consumer(channel, consumer, context).await {
                tracing::error!(
                    owner = owner_name,
                    queue = %log_dlq,
                    consumer_tag = %log_consumer_tag,
                    error = %error,
                    "DLQ consumer stopped"
                );
            }
        });
    }

    Ok(())
}

struct DlqConsumerContext {
    owner: &'static str,
    dlq: String,
    consumer_tag: String,
    business_queue: String,
    business_rk: String,
    business_exchange: String,
    quarantine_db: Option<MySqlPool>,
    quarantine_enabled: bool,
}

const HEADER_REPUBLISH_COUNT: &str = "x-dlq-republish-count";
const MAX_REPUBLISH_ATTEMPTS: u32 = 3;

#[derive(Debug, PartialEq, Eq)]
enum RepublishFailureAction {
    RetainAndRequeue { attempt: u32 },
    Terminal { attempt: u32 },
}

fn next_republish_failure_action(current_attempt: u32) -> RepublishFailureAction {
    let attempt = current_attempt
        .min(MAX_REPUBLISH_ATTEMPTS.saturating_sub(1))
        .saturating_add(1);
    if attempt >= MAX_REPUBLISH_ATTEMPTS {
        RepublishFailureAction::Terminal { attempt }
    } else {
        RepublishFailureAction::RetainAndRequeue { attempt }
    }
}

fn dlq_republish_count(delivery: &lapin::message::Delivery) -> u32 {
    delivery
        .properties
        .headers()
        .as_ref()
        .and_then(|headers| headers.inner().get(HEADER_REPUBLISH_COUNT))
        .and_then(|value| value.as_long_long_int())
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(0)
}

#[derive(Debug, PartialEq, Eq)]
enum TerminalCaptureResult {
    NotSelected,
    Captured { quarantine_id: i64 },
    Failed { reason: String },
}

/// The action after a terminal quarantine attempt. A capture-enabled queue
/// never falls through to the ordinary terminal ACK path.
#[derive(Debug, PartialEq, Eq)]
enum TerminalCaptureAction {
    AckAfterCapture,
    AckWithoutCapture,
    RetainAndRequeue { attempt: u32 },
    PreserveUnacked,
}

fn quarantine_owner_queue(queue_name: &str) -> bool {
    matches!(queue_name, QUEUE_AUDIT_LOG | QUEUE_LOGIN_EVENT)
}

fn terminal_capture_selected(context: &DlqConsumerContext) -> bool {
    quarantine_owner_queue(&context.business_queue) && context.quarantine_enabled
}

/// Once a quarantine write fails, use the existing durable DLQ budget while it
/// still has room. At the saturated count, leaving the delivery unacked is the
/// only fail-closed action: ACK would lose it and another same-count publish
/// would create an unbounded terminal loop.
fn capture_failure_action(current_attempt: u32) -> TerminalCaptureAction {
    if current_attempt < MAX_REPUBLISH_ATTEMPTS {
        TerminalCaptureAction::RetainAndRequeue {
            attempt: current_attempt.saturating_add(1),
        }
    } else {
        TerminalCaptureAction::PreserveUnacked
    }
}

fn terminal_capture_action(
    context: &DlqConsumerContext,
    result: &TerminalCaptureResult,
    current_attempt: u32,
) -> TerminalCaptureAction {
    if !quarantine_owner_queue(&context.business_queue) {
        return TerminalCaptureAction::AckWithoutCapture;
    }
    if !terminal_capture_selected(context) {
        return capture_failure_action(current_attempt);
    }
    match result {
        TerminalCaptureResult::Captured { .. } => TerminalCaptureAction::AckAfterCapture,
        TerminalCaptureResult::NotSelected | TerminalCaptureResult::Failed { .. } => {
            capture_failure_action(current_attempt)
        }
    }
}

fn quarantine_failure_reason(reason: &str, republish_count: u32) -> String {
    format!("{reason};dlq_republish_count={republish_count}")
}

/// Capture one terminal delivery only for the queues whose owner has the
/// quarantine repository. The original bytes and routing metadata are kept;
/// legacy login identities are resolved by `terminal_canonical_message_id`.
async fn capture_terminal_delivery(
    context: &DlqConsumerContext,
    delivery: &lapin::message::Delivery,
    retry_count: u32,
    republish_count: u32,
    failure_reason: &str,
) -> TerminalCaptureResult {
    if !quarantine_owner_queue(&context.business_queue) {
        return TerminalCaptureResult::NotSelected;
    }
    if !context.quarantine_enabled {
        return TerminalCaptureResult::Failed {
            reason: "quarantine_disabled".to_owned(),
        };
    }
    let Some(pool) = context.quarantine_db.as_ref() else {
        return TerminalCaptureResult::Failed {
            reason: "quarantine_db_unavailable".to_owned(),
        };
    };

    let input = AuditQuarantineInput {
        source_queue: context.business_queue.clone(),
        message_type: message_type_for_queue(&context.business_queue).to_owned(),
        canonical_message_id: terminal_canonical_message_id(delivery, &context.business_queue),
        raw_payload: delivery.data.clone(),
        source_exchange: context.business_exchange.clone(),
        source_routing_key: context.business_rk.clone(),
        retry_count,
        failure_reason: quarantine_failure_reason(failure_reason, republish_count),
    };
    match insert_or_increment_terminal(pool, &input).await {
        Ok(row) => TerminalCaptureResult::Captured {
            quarantine_id: row.id,
        },
        Err(error) => TerminalCaptureResult::Failed {
            reason: format!("quarantine_capture_error: {error}"),
        },
    }
}

struct RepublishFailureContext<'a> {
    context: &'a DlqConsumerContext,
    retry_count: u32,
    failure_reason: &'a str,
}

fn capture_failure_reason(result: &TerminalCaptureResult) -> &str {
    match result {
        TerminalCaptureResult::Failed { reason } => reason.as_str(),
        TerminalCaptureResult::NotSelected => "quarantine_capture_not_selected",
        TerminalCaptureResult::Captured { .. } => "quarantine_capture_succeeded",
    }
}

async fn retain_delivery(
    channel: &Channel,
    delivery: &lapin::message::Delivery,
    dlq: &str,
    current_attempt: u32,
) -> Result<u32, String> {
    use lapin::options::BasicPublishOptions;
    use lapin::types::{AMQPValue, ShortString};

    let action = next_republish_failure_action(current_attempt);
    let attempt = match action {
        RepublishFailureAction::RetainAndRequeue { attempt }
        | RepublishFailureAction::Terminal { attempt } => attempt,
    };
    let mut headers = delivery.properties.headers().clone().unwrap_or_default();
    headers.insert(
        ShortString::from(HEADER_REPUBLISH_COUNT),
        AMQPValue::LongLongInt(i64::from(attempt)),
    );
    let confirm = channel
        .basic_publish(
            ShortString::from(EXCHANGE_DLX),
            ShortString::from(dlq),
            BasicPublishOptions::default(),
            &delivery.data,
            delivery.properties.clone().with_headers(headers),
        )
        .await
        .map_err(|error| format!("durable_dlq_retention_publish_error: {error}"))?;
    match confirm.await {
        Ok(Confirmation::Ack(_)) => Ok(attempt),
        Ok(Confirmation::Nack(_)) => Err("durable_dlq_retention_nack".to_owned()),
        Ok(Confirmation::NotRequested) => Err("durable_dlq_retention_not_confirmed".to_owned()),
        Err(error) => Err(format!("durable_dlq_retention_confirmation_error: {error}")),
    }
}

async fn settle_capture_failure(
    channel: &Channel,
    delivery: &lapin::message::Delivery,
    context: &DlqConsumerContext,
    current_attempt: u32,
    failure_reason: &str,
) -> Result<(), MqError> {
    match capture_failure_action(current_attempt) {
        TerminalCaptureAction::RetainAndRequeue { attempt } => {
            match retain_delivery(channel, delivery, &context.dlq, current_attempt).await {
                Ok(retained_attempt) => {
                    tracing::error!(
                        owner = context.owner,
                        queue = %context.dlq,
                        consumer_tag = %context.consumer_tag,
                        business_queue = %context.business_queue,
                        retry = retry_count_from_delivery(delivery),
                        republish_attempt = retained_attempt,
                        capture_failure = failure_reason,
                        durable_retention = true,
                        ack_reason = "confirmed_bounded_dlq_retention_after_capture_failure",
                        "terminal quarantine capture failed; retained bounded DLQ copy"
                    );
                    debug_assert_eq!(attempt, retained_attempt);
                    channel
                        .basic_ack(
                            delivery.delivery_tag,
                            lapin::options::BasicAckOptions::default(),
                        )
                        .await
                        .map_err(|error| MqError::Consume(error.to_string()))?;
                }
                Err(retention_error) => {
                    // No ACK/NACK is issued: the current delivery remains the
                    // only known copy. This avoids both data loss and an
                    // unbounded same-header requeue loop.
                    tracing::error!(
                        owner = context.owner,
                        queue = %context.dlq,
                        consumer_tag = %context.consumer_tag,
                        business_queue = %context.business_queue,
                        retry = retry_count_from_delivery(delivery),
                        republish_attempt = current_attempt,
                        capture_failure = failure_reason,
                        retention_error = %retention_error,
                        terminal = true,
                        durable_retention = false,
                        fail_closed = true,
                        "terminal quarantine and bounded DLQ retention both failed; preserving unacked delivery"
                    );
                }
            }
        }
        TerminalCaptureAction::PreserveUnacked => {
            tracing::error!(
                owner = context.owner,
                queue = %context.dlq,
                consumer_tag = %context.consumer_tag,
                business_queue = %context.business_queue,
                retry = retry_count_from_delivery(delivery),
                republish_attempt = current_attempt,
                capture_failure = failure_reason,
                terminal = true,
                durable_retention = false,
                fail_closed = true,
                "terminal quarantine capture failed at bounded DLQ limit; preserving unacked delivery"
            );
        }
        TerminalCaptureAction::AckAfterCapture | TerminalCaptureAction::AckWithoutCapture => {
            unreachable!("capture failure must select a retention or preserve action")
        }
    }
    Ok(())
}

async fn settle_terminal_capture(
    channel: &Channel,
    delivery: &lapin::message::Delivery,
    context: &DlqConsumerContext,
    capture: TerminalCaptureResult,
    current_attempt: u32,
) -> Result<(), MqError> {
    let capture_reason = capture_failure_reason(&capture);
    match terminal_capture_action(context, &capture, current_attempt) {
        TerminalCaptureAction::AckAfterCapture => {
            if let TerminalCaptureResult::Captured { quarantine_id } = capture {
                tracing::error!(
                    owner = context.owner,
                    queue = %context.dlq,
                    consumer_tag = %context.consumer_tag,
                    business_queue = %context.business_queue,
                    quarantine_id,
                    retry = retry_count_from_delivery(delivery),
                    republish_attempt = current_attempt,
                    terminal = true,
                    quarantine = true,
                    quarantine_status = %AuditQuarantineStatus::Quarantined.as_str(),
                    "DLQ terminal delivery durably quarantined"
                );
            }
            channel
                .basic_ack(
                    delivery.delivery_tag,
                    lapin::options::BasicAckOptions::default(),
                )
                .await
                .map_err(|error| MqError::Consume(error.to_string()))?;
        }
        TerminalCaptureAction::AckWithoutCapture => {
            channel
                .basic_ack(
                    delivery.delivery_tag,
                    lapin::options::BasicAckOptions::default(),
                )
                .await
                .map_err(|error| MqError::Consume(error.to_string()))?;
        }
        TerminalCaptureAction::RetainAndRequeue { .. } | TerminalCaptureAction::PreserveUnacked => {
            settle_capture_failure(channel, delivery, context, current_attempt, capture_reason)
                .await?;
        }
    }
    Ok(())
}

async fn handle_republish_failure(
    channel: &Channel,
    delivery: &lapin::message::Delivery,
    context: RepublishFailureContext<'_>,
) -> Result<(), MqError> {
    let RepublishFailureContext {
        context,
        retry_count,
        failure_reason,
    } = context;
    use lapin::options::{BasicAckOptions, BasicNackOptions};

    let current_attempt = dlq_republish_count(delivery);
    let action = next_republish_failure_action(current_attempt);
    let retained_attempt =
        match retain_delivery(channel, delivery, &context.dlq, current_attempt).await {
            Ok(attempt) => attempt,
            Err(retention_error) => {
                if quarantine_owner_queue(&context.business_queue) {
                    let capture = capture_terminal_delivery(
                        context,
                        delivery,
                        retry_count,
                        current_attempt,
                        &format!("durable_dlq_retention_failure:{retention_error}"),
                    )
                    .await;
                    return settle_terminal_capture(
                        channel,
                        delivery,
                        context,
                        capture,
                        current_attempt,
                    )
                    .await;
                }
                tracing::error!(
                    owner = context.owner,
                    queue = %context.dlq,
                    consumer_tag = %context.consumer_tag,
                    business_queue = %context.business_queue,
                    retry = retry_count,
                    republish_attempt = current_attempt,
                    failure_reason,
                    retention_error = %retention_error,
                    terminal = true,
                    quarantine = false,
                    structured_evidence = true,
                    "DLQ republish terminal block; durable retention was not confirmed"
                );
                channel
                    .basic_nack(
                        delivery.delivery_tag,
                        BasicNackOptions {
                            multiple: false,
                            requeue: false,
                        },
                    )
                    .await
                    .map_err(|error| MqError::Consume(error.to_string()))?;
                return Ok(());
            }
        };

    match action {
        RepublishFailureAction::RetainAndRequeue { attempt } => {
            tracing::error!(
                owner = context.owner,
                queue = %context.dlq,
                consumer_tag = %context.consumer_tag,
                business_queue = %context.business_queue,
                retry = retry_count,
                republish_attempt = attempt,
                failure_reason,
                terminal = false,
                durable_retention = true,
                ack_reason = "confirmed_durable_dlq_retention",
                "DLQ republish failed; bounded attempt retained in durable DLQ"
            );
            debug_assert_eq!(attempt, retained_attempt);
            channel
                .basic_ack(delivery.delivery_tag, BasicAckOptions::default())
                .await
                .map_err(|error| MqError::Consume(error.to_string()))?;
        }
        RepublishFailureAction::Terminal { attempt } => {
            let capture = capture_terminal_delivery(
                context,
                delivery,
                retry_count,
                attempt,
                "republish_attempt_budget_exhausted",
            )
            .await;
            if quarantine_owner_queue(&context.business_queue) {
                return settle_terminal_capture(channel, delivery, context, capture, attempt).await;
            }
            tracing::error!(
                owner = context.owner,
                queue = %context.dlq,
                consumer_tag = %context.consumer_tag,
                business_queue = %context.business_queue,
                retry = retry_count,
                republish_attempt = attempt,
                failure_reason,
                terminal = true,
                durable_retention = true,
                ack_reason = "confirmed_durable_dlq_retention",
                quarantine = false,
                "DLQ republish poison terminal retained in durable DLQ"
            );
            debug_assert_eq!(attempt, retained_attempt);
            channel
                .basic_ack(delivery.delivery_tag, BasicAckOptions::default())
                .await
                .map_err(|error| MqError::Consume(error.to_string()))?;
        }
    }
    Ok(())
}

async fn run_dlq_consumer(
    channel: Channel,
    mut consumer: lapin::Consumer,
    context: DlqConsumerContext,
) -> Result<(), MqError> {
    let DlqConsumerContext {
        owner,
        dlq,
        consumer_tag,
        business_queue,
        business_rk,
        business_exchange,
        quarantine_db,
        quarantine_enabled,
    } = context;
    use futures_util::StreamExt;
    use lapin::options::{BasicAckOptions, BasicNackOptions};
    use lapin::types::{AMQPValue, ShortString};

    while let Some(delivery) = consumer.next().await {
        let delivery = delivery.map_err(|error| MqError::Consume(error.to_string()))?;
        let retry_count = retry_count_from_delivery(&delivery);
        let message_id = delivery_message_id(&delivery);
        let republish_count = dlq_republish_count(&delivery);
        let context = DlqConsumerContext {
            owner,
            dlq: dlq.clone(),
            consumer_tag: consumer_tag.clone(),
            business_queue: business_queue.clone(),
            business_rk: business_rk.clone(),
            business_exchange: business_exchange.clone(),
            quarantine_db: quarantine_db.clone(),
            quarantine_enabled,
        };
        if republish_count >= MAX_REPUBLISH_ATTEMPTS {
            let capture = capture_terminal_delivery(
                &context,
                &delivery,
                retry_count,
                republish_count,
                "republish_attempt_budget_exhausted",
            )
            .await;
            if quarantine_owner_queue(&business_queue) {
                settle_terminal_capture(&channel, &delivery, &context, capture, republish_count)
                    .await?;
            } else {
                channel
                    .basic_nack(
                        delivery.delivery_tag,
                        BasicNackOptions {
                            multiple: false,
                            requeue: false,
                        },
                    )
                    .await
                    .map_err(|error| MqError::Consume(error.to_string()))?;
            }
            continue;
        }
        if retry_count >= crate::config::MAX_RETRY {
            let context = DlqConsumerContext {
                owner,
                dlq: dlq.clone(),
                consumer_tag: consumer_tag.clone(),
                business_queue: business_queue.clone(),
                business_rk: business_rk.clone(),
                business_exchange: business_exchange.clone(),
                quarantine_db: quarantine_db.clone(),
                quarantine_enabled,
            };
            let failure_reason = terminal_failure_reason(&delivery);
            let capture = capture_terminal_delivery(
                &context,
                &delivery,
                retry_count,
                republish_count,
                &failure_reason,
            )
            .await;
            if quarantine_owner_queue(&business_queue) {
                settle_terminal_capture(&channel, &delivery, &context, capture, republish_count)
                    .await?;
            } else {
                // Preserve the existing ordinary-queue terminal ACK semantics.
                tracing::error!(
                    owner,
                    queue = %dlq,
                    consumer_tag = %consumer_tag,
                    message_id = %message_id,
                    retry = retry_count,
                    failure_reason = %failure_reason,
                    message_bytes = delivery.data.len(),
                    terminal = true,
                    quarantine = false,
                    "DLQ terminal drop after max retries"
                );
                channel
                    .basic_ack(delivery.delivery_tag, BasicAckOptions::default())
                    .await
                    .map_err(|error| MqError::Consume(error.to_string()))?;
            }
            continue;
        }
        // 重投：携带递增 x-retry-count 头，经业务交换机回投业务队列。
        // 小延迟避免立即回队造成热循环（近似 DLX/TTL 重试节奏）。
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let mut headers = delivery.properties.headers().clone().unwrap_or_default();
        headers.insert(
            ShortString::from("x-retry-count"),
            AMQPValue::LongLongInt((retry_count + 1) as i64),
        );
        let properties = delivery.properties.clone().with_headers(headers);
        let published = channel
            .basic_publish(
                ShortString::from(business_exchange.as_str()),
                ShortString::from(business_rk.as_str()),
                lapin::options::BasicPublishOptions::default(),
                &delivery.data,
                properties,
            )
            .await;
        match published {
            Ok(confirm) => match confirm.await {
                Ok(Confirmation::Ack(_)) => {
                    tracing::warn!(
                        owner,
                        queue = %dlq,
                        consumer_tag = %consumer_tag,
                        business_queue = %business_queue,
                        message_id = %message_id,
                        retry = retry_count + 1,
                        failure_reason = "handler_or_malformed_delivery_retry",
                        terminal = false,
                        "DLQ re-driven message back to business queue"
                    );
                    channel
                        .basic_ack(delivery.delivery_tag, BasicAckOptions::default())
                        .await
                        .map_err(|error| MqError::Consume(error.to_string()))?;
                }
                Ok(Confirmation::Nack(_)) | Ok(Confirmation::NotRequested) => {
                    let context = DlqConsumerContext {
                        owner,
                        dlq: dlq.clone(),
                        consumer_tag: consumer_tag.clone(),
                        business_queue: business_queue.clone(),
                        business_rk: business_rk.clone(),
                        business_exchange: business_exchange.clone(),
                        quarantine_db: quarantine_db.clone(),
                        quarantine_enabled,
                    };
                    handle_republish_failure(
                        &channel,
                        &delivery,
                        RepublishFailureContext {
                            context: &context,
                            retry_count,
                            failure_reason: "republish_not_confirmed",
                        },
                    )
                    .await?;
                }
                Err(error) => {
                    tracing::error!(
                        owner,
                        queue = %dlq,
                        consumer_tag = %consumer_tag,
                        message_id = %message_id,
                        retry = retry_count,
                        failure_reason = "republish_confirmation_error",
                        error = %error,
                        "DLQ republish not confirmed"
                    );
                    let context = DlqConsumerContext {
                        owner,
                        dlq: dlq.clone(),
                        consumer_tag: consumer_tag.clone(),
                        business_queue: business_queue.clone(),
                        business_rk: business_rk.clone(),
                        business_exchange: business_exchange.clone(),
                        quarantine_db: quarantine_db.clone(),
                        quarantine_enabled,
                    };
                    handle_republish_failure(
                        &channel,
                        &delivery,
                        RepublishFailureContext {
                            context: &context,
                            retry_count,
                            failure_reason: "republish_confirmation_error",
                        },
                    )
                    .await?;
                }
            },
            Err(error) => {
                tracing::error!(
                    owner,
                    queue = %dlq,
                    consumer_tag = %consumer_tag,
                    message_id = %message_id,
                    retry = retry_count,
                    failure_reason = "republish_error",
                    error = %error,
                    "DLQ republish failed"
                );
                let context = DlqConsumerContext {
                    owner,
                    dlq: dlq.clone(),
                    consumer_tag: consumer_tag.clone(),
                    business_queue: business_queue.clone(),
                    business_rk: business_rk.clone(),
                    business_exchange: business_exchange.clone(),
                    quarantine_db: quarantine_db.clone(),
                    quarantine_enabled,
                };
                handle_republish_failure(
                    &channel,
                    &delivery,
                    RepublishFailureContext {
                        context: &context,
                        retry_count,
                        failure_reason: "republish_error",
                    },
                )
                .await?;
            }
        }
    }

    Err(MqError::Consume(format!(
        "DLQ consumer stream ended: owner={owner} queue={dlq} consumer_tag={consumer_tag}"
    )))
}

const IDENTITY_DLQ_QUEUES: &[&str] = &[QUEUE_LOGIN_EVENT, QUEUE_AUTH_SESSION_REVOCATION];

const TRUSTGRAPH_DLQ_QUEUES: &[&str] = &[QUEUE_AUDIT_LOG];

struct DlqOwnerMapping {
    queue_name: &'static str,
    owner: Option<DlqOwner>,
}

/// Complete static classification of all topology queues. `None` is an explicit
/// no-current-owner classification, not permission for either service to consume.
const DLQ_OWNER_MAP: &[DlqOwnerMapping] = &[
    DlqOwnerMapping {
        queue_name: QUEUE_AUDIT_LOG,
        owner: Some(DlqOwner::TrustGraph),
    },
    DlqOwnerMapping {
        queue_name: crate::config::QUEUE_NOTIFICATION,
        owner: None,
    },
    DlqOwnerMapping {
        queue_name: crate::config::QUEUE_LEARNING_PROGRESS,
        owner: None,
    },
    DlqOwnerMapping {
        queue_name: QUEUE_LOGIN_EVENT,
        owner: Some(DlqOwner::Identity),
    },
    DlqOwnerMapping {
        queue_name: crate::config::QUEUE_SUBJECT_DELETE,
        owner: None,
    },
    DlqOwnerMapping {
        queue_name: QUEUE_AUTH_SESSION_REVOCATION,
        owner: Some(DlqOwner::Identity),
    },
    DlqOwnerMapping {
        queue_name: crate::config::QUEUE_CHAT_MESSAGE,
        owner: None,
    },
    DlqOwnerMapping {
        queue_name: crate::config::QUEUE_BUSINESS_CHAT,
        owner: None,
    },
    DlqOwnerMapping {
        queue_name: crate::config::QUEUE_DELIVERY_ACK,
        owner: None,
    },
    DlqOwnerMapping {
        queue_name: crate::config::QUEUE_READ_RECEIPT,
        owner: None,
    },
    DlqOwnerMapping {
        queue_name: crate::config::QUEUE_QUESTION_COMMENT,
        owner: None,
    },
    DlqOwnerMapping {
        queue_name: crate::config::QUEUE_QUESTION_SHARE,
        owner: None,
    },
];

fn dlq_consumer_tag(owner: DlqOwner, queue_name: &str) -> String {
    format!(
        "astral_dlq_{}_{}",
        owner.as_str(),
        queue_name.replace('.', "_")
    )
}

fn dlq_queue_defs_for_owner(owner: DlqOwner) -> Result<Vec<&'static QueueDef>, String> {
    validate_dlq_owner_mapping()?;
    let names = match owner {
        DlqOwner::Identity => IDENTITY_DLQ_QUEUES,
        DlqOwner::TrustGraph => TRUSTGRAPH_DLQ_QUEUES,
    };
    names
        .iter()
        .map(|name| {
            QUEUES
                .iter()
                .find(|def| def.name == *name)
                .ok_or_else(|| format!("owner={} references unknown queue={name}", owner.as_str()))
        })
        .collect()
}

fn validate_dlq_owner_mapping() -> Result<(), String> {
    let queue_names: HashSet<&str> = QUEUES.iter().map(|def| def.name).collect();
    if queue_names.len() != QUEUES.len() {
        return Err("topology contains duplicate queue names".into());
    }

    let mut mapped_names = HashSet::new();
    for mapping in DLQ_OWNER_MAP {
        if !queue_names.contains(mapping.queue_name) {
            return Err(format!(
                "mapping references unknown queue={}",
                mapping.queue_name
            ));
        }
        if !mapped_names.insert(mapping.queue_name) {
            return Err(format!(
                "queue mapped more than once: {}",
                mapping.queue_name
            ));
        }
    }
    if mapped_names.len() != QUEUES.len() {
        let omitted: Vec<_> = queue_names.difference(&mapped_names).copied().collect();
        return Err(format!("queue owner mapping omitted queues: {omitted:?}"));
    }

    validate_owner_queue_set(DlqOwner::Identity, IDENTITY_DLQ_QUEUES)?;
    validate_owner_queue_set(DlqOwner::TrustGraph, TRUSTGRAPH_DLQ_QUEUES)?;
    Ok(())
}

fn validate_owner_queue_set(owner: DlqOwner, names: &[&str]) -> Result<(), String> {
    let mut names_seen = HashSet::new();
    for name in names {
        if !names_seen.insert(*name) {
            return Err(format!(
                "owner={} queue listed more than once: {name}",
                owner.as_str()
            ));
        }
        let mapping = DLQ_OWNER_MAP
            .iter()
            .find(|mapping| mapping.queue_name == *name)
            .ok_or_else(|| format!("owner={} references unmapped queue={name}", owner.as_str()))?;
        if mapping.owner != Some(owner) {
            return Err(format!(
                "owner={} does not match queue={} mapping",
                owner.as_str(),
                name
            ));
        }
    }
    Ok(())
}

fn terminal_failure_reason(delivery: &lapin::message::Delivery) -> String {
    match validate_delivery_envelope(&delivery.data) {
        Ok(_) => "max_retries_exceeded".to_owned(),
        Err(reason) => reason,
    }
}

/// 启动 audit.log 消费者（仅 TrustGraph 消费）。
pub async fn start_audit_log_consumer(channel: &Channel) -> Result<(), MqError> {
    let audit_q = queue_name("audit.log");
    if audit_q.is_empty() {
        return Ok(());
    }
    let q = audit_q.to_string();
    let (ready_tx, ready_rx) = oneshot::channel();
    let owned_channel = channel.clone();
    tokio::spawn(async move {
        if let Err(error) = run_audit_log_batch_consumer(owned_channel, q, Some(ready_tx)).await {
            tracing::error!(queue = %audit_q, error = %error, "audit log consumer failed");
        }
    });
    ready_rx
        .await
        .map_err(|_| {
            MqError::Consume(format!(
                "audit log consumer startup task ended: queue={audit_q}"
            ))
        })?
        .map_err(|error| {
            MqError::Consume(format!(
                "audit log consumer registration failed: queue={audit_q}: {error}"
            ))
        })?;
    tracing::info!(queue = %audit_q, "AuditLogConsumer started (batched)");
    Ok(())
}

// ==================== AUDIT_LOG 消费者批量合并（性能优化卡点 3） ====================
//
// F3 压测：audit 消费者逐条持久化每条消息产生 3 次 DB 命令（mq_idempotent_log
// INSERT IGNORE + audit_log INSERT + mq_idempotent_log UPDATE），10 万 QPS 下
// 约占 DB 总容量 ~28%（不在请求延迟路径，但占吞吐）。批量合并将整批消息收敛
// 为**单事务 4 条批量 SQL**（幂等预检锁定读 + 幂等 claim 多行 + audit_log 多行
// + mark PROCESSED 多行），DB 命令数从 3×N 降为 4/批。
//
// 幂等与失败语义（与逐条路径一致，at-least-once 保持）：
// - Redis 租约 claim 层（`crate::consumer::claim_message`）逐条不变：
//   Completed → ack；InFlight → requeue（不消耗重试预算）；Claimed → 批量持久化
//   → complete → ack；
// - DB 幂等预检使用 `SELECT ... FOR UPDATE` 锁定既有行（与在途写者互斥）：行已
//   存在（已 PROCESSED 或崩溃残留 PROCESSING）等价于旧逐条语义的
//   `INSERT IGNORE` claim 失败 → 跳过 audit 行、仍 ack；
// - **批内任一 SQL 失败 → 整批回退逐条处理**（文档化选择）：单条毒消息不阻塞
//   整批；回退中仍失败的单条走 release 租约 + nack → DLX 预算重试；
// - ACK 前该消息的 durable 状态已随批事务落盘（durable proof 先于 ACK）。

/// 单批最大消息数。
const AUDIT_BATCH_MAX_MESSAGES: usize = 50;

/// 首条消息后继续凑批的窗口：低速率下最多增加 25ms 消费延迟（审计消费不在
/// 请求延迟路径）；高速率下 delivery 流已缓冲，窗口内即可凑满整批。
const AUDIT_BATCH_COLLECT_WINDOW: Duration = Duration::from_millis(25);

/// 已 claim 且待批量持久化的审计投递。
struct ClaimedAuditDelivery {
    delivery: Delivery,
    /// MQ 信封 messageId（Redis 租约键使用该 id）。
    message_id: String,
    /// Redis 处理租约 owner（complete/release 需要证明占有）。
    owner: String,
    payload: AuditLogPayload,
}

/// AUDIT_LOG 批量消费者主循环：凑批 → 逐条 decode/claim → 批量持久化 → 逐条确认。
async fn run_audit_log_batch_consumer(
    channel: Channel,
    audit_q: String,
    ready: Option<oneshot::Sender<Result<(), String>>>,
) -> Result<(), MqError> {
    let mut consumer = match channel
        .basic_consume(
            ShortString::from(audit_q.as_str()),
            ShortString::from(format!("consumer_{audit_q}")),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
    {
        Ok(consumer) => consumer,
        Err(error) => {
            if let Some(ready) = ready {
                let _ = ready.send(Err(error.to_string()));
            }
            return Err(error.into());
        }
    };
    if let Some(ready) = ready {
        let _ = ready.send(Ok(()));
    }

    tracing::info!(queue = %audit_q, "batched consumer started");

    let message_type = message_type_for_queue(&audit_q);
    let mut batch: Vec<Delivery> = Vec::with_capacity(AUDIT_BATCH_MAX_MESSAGES);
    loop {
        batch.clear();
        // 首条阻塞等待：流错误向上返回、流关闭正常结束（与逐条消费者一致）。
        match consumer.next().await {
            Some(Ok(delivery)) => batch.push(delivery),
            Some(Err(error)) => return Err(MqError::Consume(error.to_string())),
            None => return Ok(()),
        }
        // 窗口内继续凑批（高速率下 stream 已缓冲，凑满即走）。
        let deadline = Instant::now() + AUDIT_BATCH_COLLECT_WINDOW;
        while batch.len() < AUDIT_BATCH_MAX_MESSAGES {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match timeout(remaining, consumer.next()).await {
                Err(_elapsed) => break,
                Ok(None) => break,
                Ok(Some(Err(error))) => return Err(MqError::Consume(error.to_string())),
                Ok(Some(Ok(delivery))) => batch.push(delivery),
            }
        }
        process_audit_delivery_batch(&channel, &audit_q, message_type, &mut batch).await?;
    }
}

/// 对一批投递执行逐条 decode/claim，然后批量持久化并逐条确认。
async fn process_audit_delivery_batch(
    channel: &Channel,
    audit_q: &str,
    message_type: &'static str,
    batch: &mut Vec<Delivery>,
) -> Result<(), MqError> {
    let mut claimed: Vec<ClaimedAuditDelivery> = Vec::new();
    for delivery in batch.drain(..) {
        let retry_count = retry_count_from_delivery(&delivery);
        // Parse before invoking Redis or business handlers（与逐条路径一致）。
        let msg = match decode_delivery::<AuditLogPayload>(&delivery.data, audit_q) {
            Ok(msg) => msg,
            Err(failure_reason) => {
                let message_id = delivery_message_id(&delivery);
                tracing::error!(
                    queue = %audit_q,
                    message_id = %message_id,
                    retry = retry_count,
                    failure_reason = %failure_reason,
                    "malformed delivery sent to DLX"
                );
                dead_letter_delivery(channel, &delivery).await?;
                continue;
            }
        };
        if retry_count >= MAX_RETRY {
            tracing::warn!(
                queue = %audit_q,
                message_id = %msg.message_id,
                retry = retry_count,
                failure_reason = "max_retries_exceeded",
                "max retries exceeded; delivery sent to DLX"
            );
            dead_letter_delivery(channel, &delivery).await?;
            continue;
        }
        match claim_message(&msg.message_id, message_type).await {
            Err(error) => {
                tracing::error!(
                    queue = %audit_q,
                    message_id = %msg.message_id,
                    error = %error,
                    "idempotency claim unavailable, retrying message"
                );
                nack_delivery(channel, &delivery).await?;
            }
            Ok(IdempotencyClaim::Completed) => {
                tracing::debug!(
                    queue = %audit_q,
                    message_id = %msg.message_id,
                    "message already completed, acking"
                );
                ack_delivery(channel, &delivery).await?;
            }
            Ok(IdempotencyClaim::InFlight) => {
                tracing::debug!(
                    queue = %audit_q,
                    message_id = %msg.message_id,
                    "message processing lease is active, requeueing without consuming retry budget"
                );
                requeue_delivery(channel, &delivery).await?;
            }
            Ok(IdempotencyClaim::Claimed(owner)) => {
                claimed.push(ClaimedAuditDelivery {
                    delivery,
                    message_id: msg.message_id.clone(),
                    owner,
                    payload: msg.payload,
                });
            }
        }
    }
    if claimed.is_empty() {
        return Ok(());
    }
    flush_claimed_audit_batch(channel, audit_q, message_type, claimed).await;
    Ok(())
}

/// 批量持久化成功 → 逐条 complete + ack；失败 → 逐条回退（见节文档）。
async fn flush_claimed_audit_batch(
    channel: &Channel,
    audit_q: &str,
    message_type: &'static str,
    claimed: Vec<ClaimedAuditDelivery>,
) {
    let Some(pool) = AUDIT_LOG_DB.get() else {
        // DB 未初始化：与逐条路径一致按失败处理 → 释放租约 + nack（DLX 重试）。
        for item in claimed {
            let error: Box<dyn std::error::Error + Send> = box_err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "audit log consumer DB not initialized",
            ));
            release_and_nack(channel, audit_q, message_type, item, error).await;
        }
        return;
    };
    let started = Instant::now();
    match persist_audit_record_batch(pool, &claimed).await {
        Ok(()) => {
            tracing::debug!(
                queue = %audit_q,
                count = claimed.len(),
                elapsed_ms = started.elapsed().as_millis() as u64,
                "audit batch persisted"
            );
            for item in claimed {
                // complete（Redis 幂等标记 '1'）→ ack；complete 失败与逐条路径
                // 一致：不 ack（redelivery 后由 DB 幂等 claim 去重兜底）。
                match complete_message(&item.message_id, message_type, &item.owner).await {
                    Ok(true) => {
                        if let Err(error) = ack_delivery(channel, &item.delivery).await {
                            tracing::error!(
                                queue = %audit_q,
                                message_id = %item.message_id,
                                error = %error,
                                "audit batch ack failed"
                            );
                        }
                    }
                    Ok(false) => {
                        tracing::error!(
                            queue = %audit_q,
                            message_id = %item.message_id,
                            "message completion lease was lost"
                        );
                    }
                    Err(error) => {
                        tracing::error!(
                            queue = %audit_q,
                            message_id = %item.message_id,
                            error = %error,
                            "failed to complete message lease"
                        );
                    }
                }
            }
        }
        Err(batch_error) => {
            // 整批失败 → 逐条回退（文档化选择）：单条毒消息不阻塞整批；仍失败
            // 的单条走 release + nack → DLX 预算重试（at-least-once 保持）。
            tracing::warn!(
                queue = %audit_q,
                count = claimed.len(),
                error = %batch_error,
                "audit batch persist failed; falling back to per-record persistence"
            );
            for item in claimed {
                match handle_audit_log(&item.message_id, &item.payload).await {
                    Ok(()) => {
                        match complete_message(&item.message_id, message_type, &item.owner).await {
                            Ok(true) => {
                                if let Err(error) = ack_delivery(channel, &item.delivery).await {
                                    tracing::error!(
                                        queue = %audit_q,
                                        message_id = %item.message_id,
                                        error = %error,
                                        "audit fallback ack failed"
                                    );
                                }
                            }
                            Ok(false) => {
                                tracing::error!(
                                    queue = %audit_q,
                                    message_id = %item.message_id,
                                    "message completion lease was lost"
                                );
                            }
                            Err(error) => {
                                tracing::error!(
                                    queue = %audit_q,
                                    message_id = %item.message_id,
                                    error = %error,
                                    "failed to complete message lease"
                                );
                            }
                        }
                    }
                    Err(error) => {
                        release_and_nack(channel, audit_q, message_type, item, error).await;
                    }
                }
            }
        }
    }
}

/// 释放 Redis 处理租约并 nack（requeue=false → DLX），对齐逐条失败语义。
async fn release_and_nack(
    channel: &Channel,
    audit_q: &str,
    message_type: &'static str,
    item: ClaimedAuditDelivery,
    handler_error: Box<dyn std::error::Error + Send>,
) {
    tracing::warn!(
        queue = %audit_q,
        message_id = %item.message_id,
        error = %handler_error,
        "nacking for DLX retry"
    );
    if let Err(release_error) = release_message(&item.message_id, message_type, &item.owner).await {
        tracing::error!(
            queue = %audit_q,
            message_id = %item.message_id,
            error = %release_error,
            "failed to release message processing lease"
        );
    }
    if let Err(error) = nack_delivery(channel, &item.delivery).await {
        tracing::error!(
            queue = %audit_q,
            message_id = %item.message_id,
            error = %error,
            "audit batch nack failed"
        );
    }
}

/// 批量持久化：单事务 4 条批量 SQL。任何失败向上返回 → 整批回退逐条路径。
async fn persist_audit_record_batch(
    pool: &MySqlPool,
    claimed: &[ClaimedAuditDelivery],
) -> Result<(), Box<dyn std::error::Error + Send>> {
    if claimed.is_empty() {
        return Ok(());
    }
    // 批内同 message_id 去重：首条胜出（极端重复投递场景下避免重复 audit 行；
    // 未持久化的重复项由调用方按已完成消息确认，后续 redelivery 由 DB claim 去重）。
    let mut seen: HashSet<&str> = HashSet::with_capacity(claimed.len());
    let mut deduped: Vec<&ClaimedAuditDelivery> = Vec::with_capacity(claimed.len());
    for item in claimed {
        if seen.insert(item.message_id.as_str()) {
            deduped.push(item);
        }
    }
    let resolved_ids: Vec<String> = deduped
        .iter()
        .map(|item| resolve_audit_message_id(&item.message_id, &item.payload))
        .collect();
    let records: Vec<AuditRecord> = deduped
        .iter()
        .zip(&resolved_ids)
        .map(|(item, message_id)| audit_record_for_batch(message_id, &item.payload))
        .collect();

    let mut tx = pool.begin().await.map_err(box_err)?;
    // 1. 幂等预检（锁定读）：行已存在（已 PROCESSED 或崩溃残留 PROCESSING）
    //    等价于旧逐条语义的 INSERT IGNORE claim 失败 → 跳过 audit 行、仍 ack。
    //    FOR UPDATE 与在途写者互斥，锁定读看到的是提交后的最新版本。
    let select_sql = format!(
        "SELECT message_id FROM mq_idempotent_log WHERE message_type = ? AND message_id IN ({}) FOR UPDATE",
        sql_placeholders(records.len())
    );
    let mut select = sqlx::query_as::<_, (String,)>(&select_sql).bind(AUDIT_MESSAGE_TYPE);
    for record in &records {
        select = select.bind(record.message_id);
    }
    let existing: HashSet<String> = select
        .fetch_all(&mut *tx)
        .await
        .map_err(box_err)?
        .into_iter()
        .map(|(message_id,)| message_id)
        .collect();
    let fresh: Vec<&AuditRecord> = records
        .iter()
        .filter(|record| !existing.contains(record.message_id))
        .collect();
    if !fresh.is_empty() {
        // 2. 幂等 claim 多行（INSERT IGNORE 对齐逐条语义）。
        let claim_sql = format!(
            "INSERT IGNORE INTO mq_idempotent_log (message_type, message_id, status) VALUES {}",
            sql_repeated_values("(?, ?, 'PROCESSING')", fresh.len())
        );
        let mut claim = sqlx::query(&claim_sql);
        for record in &fresh {
            claim = claim.bind(AUDIT_MESSAGE_TYPE).bind(record.message_id);
        }
        claim.execute(&mut *tx).await.map_err(box_err)?;
        // 3. audit_log 多行。
        let audit_sql = format!(
            "INSERT INTO audit_log \
             (user_id, card_id, action, resource, decision, reason, event_type, source_ip, request_id, domain_id, tenant_id, detail) \
             VALUES {}",
            sql_repeated_values("(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", fresh.len())
        );
        let mut insert = sqlx::query(&audit_sql);
        for record in &fresh {
            insert = insert
                .bind(record.user_id)
                .bind(record.card_id)
                .bind(record.action)
                .bind(record.resource)
                .bind(record.decision)
                .bind(record.reason)
                .bind(record.event_type)
                .bind(record.source_ip)
                .bind(record.request_id)
                .bind(record.domain_id)
                .bind(record.tenant_id)
                .bind(&record.detail);
        }
        insert.execute(&mut *tx).await.map_err(box_err)?;
        // 4. mark PROCESSED 多行。
        let mark_sql = format!(
            "UPDATE mq_idempotent_log SET status = 'PROCESSED' WHERE message_type = ? AND message_id IN ({})",
            sql_placeholders(fresh.len())
        );
        let mut mark = sqlx::query(&mark_sql).bind(AUDIT_MESSAGE_TYPE);
        for record in &fresh {
            mark = mark.bind(record.message_id);
        }
        mark.execute(&mut *tx).await.map_err(box_err)?;
    }
    tx.commit().await.map_err(box_err)?;
    Ok(())
}

/// 从信封 id + payload 解析最终幂等 id（与 `handle_audit_log` 同规则：信封 id
/// 缺失时回退 canonical legacy id）。
fn resolve_audit_message_id(envelope_message_id: &str, msg: &AuditLogPayload) -> String {
    if !envelope_message_id.is_empty() {
        return envelope_message_id.to_owned();
    }
    msg.message_id.clone().unwrap_or_else(|| {
        let fields = [
            (
                "userId",
                msg.user_id
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "null".to_owned()),
            ),
            (
                "cardId",
                msg.card_id
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "null".to_owned()),
            ),
            ("action", msg.action.clone()),
            ("resource", msg.resource.clone()),
            ("decision", msg.decision.clone()),
            ("eventType", msg.event_type.clone()),
            (
                "requestId",
                msg.request_id.clone().unwrap_or_else(|| "null".to_owned()),
            ),
        ];
        canonical_legacy_message_id("audit", &fields)
    })
}

/// audit_log detail 字段（与 `handle_audit_log` 同规则）。
fn audit_detail_for_message_id(message_id: &str) -> Option<String> {
    Some(if message_id.starts_with("legacy-audit-v1-") {
        format!("messageId={message_id};legacyMessageIdFallback=true")
    } else {
        format!("messageId={message_id}")
    })
}

/// audit_log detail 落库规则：producer 提供的非空白 detail 优先（例如
/// ORG_SCOPE ALLOW 的结构化 JSON provenance，不得被 messageId-only 文本覆盖）；
/// 未提供时回退既有 messageId 关联文本（含 legacy 回退标记）。message-id 关联
/// 本身始终由 `mq_idempotent_log (message_type, message_id)` 持久化，不依赖
/// detail 列，因此保留 producer detail 不损失幂等/关联语义。
fn audit_record_detail(payload_detail: Option<&str>, message_id: &str) -> Option<String> {
    match payload_detail {
        Some(detail) if !detail.trim().is_empty() => Some(detail.to_owned()),
        _ => audit_detail_for_message_id(message_id),
    }
}

/// 以最终幂等 id + payload 构造批量插入用的审计记录（借用入参，无克隆）。
fn audit_record_for_batch<'a>(
    message_id: &'a str,
    payload: &'a AuditLogPayload,
) -> AuditRecord<'a> {
    AuditRecord {
        message_type: AUDIT_MESSAGE_TYPE,
        message_id,
        user_id: payload.user_id.unwrap_or(0),
        card_id: payload.card_id,
        action: &payload.action,
        resource: &payload.resource,
        decision: &payload.decision,
        reason: &payload.reason,
        event_type: &payload.event_type,
        source_ip: &payload.source_ip,
        request_id: &payload.request_id,
        domain_id: payload.domain_id,
        tenant_id: payload.tenant_id,
        detail: audit_record_detail(payload.detail.as_deref(), message_id),
    }
}

/// 生成 n 个 `?` 的逗号连接（IN 列表占位）。
fn sql_placeholders(n: usize) -> String {
    vec!["?"; n].join(",")
}

/// 生成 n 份 values 模板的逗号连接（多行 VALUES 占位）。
fn sql_repeated_values(template: &str, n: usize) -> String {
    vec![template; n].join(",")
}

/// 逐条投递确认原语（与 `Consumer` 的 ack/nack/DLX 处置一致，供批量循环复用）。
async fn ack_delivery(channel: &Channel, delivery: &Delivery) -> Result<(), MqError> {
    channel
        .basic_ack(delivery.delivery_tag, BasicAckOptions::default())
        .await?;
    Ok(())
}

async fn requeue_delivery(channel: &Channel, delivery: &Delivery) -> Result<(), MqError> {
    channel
        .basic_nack(
            delivery.delivery_tag,
            BasicNackOptions {
                multiple: false,
                requeue: true,
            },
        )
        .await?;
    Ok(())
}

async fn dead_letter_delivery(channel: &Channel, delivery: &Delivery) -> Result<(), MqError> {
    channel
        .basic_nack(
            delivery.delivery_tag,
            BasicNackOptions {
                multiple: false,
                requeue: false,
            },
        )
        .await?;
    Ok(())
}

async fn nack_delivery(channel: &Channel, delivery: &Delivery) -> Result<(), MqError> {
    dead_letter_delivery(channel, delivery).await
}

pub(crate) const AUDIT_MESSAGE_TYPE: &str = "AUDIT_LOG";
pub(crate) const LOGIN_EVENT_MESSAGE_TYPE: &str = "LOGIN_EVENT";

type AuditResult<T> = Result<T, Box<dyn std::error::Error + Send>>;

const AUDIT_IDEMPOTENCY_CLAIM_SQL: &str =
    "INSERT IGNORE INTO mq_idempotent_log (message_type, message_id, status) \
     VALUES (?, ?, 'PROCESSING')";
const AUDIT_LOG_INSERT_SQL: &str =
    "INSERT INTO audit_log \
     (user_id, card_id, action, resource, decision, reason, event_type, source_ip, request_id, domain_id, tenant_id, detail) \
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
const AUDIT_IDEMPOTENCY_MARK_PROCESSED_SQL: &str =
    "UPDATE mq_idempotent_log SET status = 'PROCESSED' \
     WHERE message_type = ? AND message_id = ?";

struct AuditRecord<'a> {
    message_type: &'a str,
    message_id: &'a str,
    user_id: i64,
    card_id: Option<i64>,
    action: &'a str,
    resource: &'a str,
    decision: &'a str,
    reason: &'a Option<String>,
    event_type: &'a str,
    source_ip: &'a Option<String>,
    request_id: &'a Option<String>,
    domain_id: Option<i64>,
    tenant_id: Option<i64>,
    detail: Option<String>,
}

#[async_trait::async_trait]
trait AuditTransaction {
    async fn claim(&mut self, message_type: &str, message_id: &str) -> AuditResult<bool>;
    async fn insert(&mut self, record: &AuditRecord<'_>) -> AuditResult<()>;
    async fn mark_processed(&mut self, message_type: &str, message_id: &str) -> AuditResult<()>;
}

async fn persist_audit_record<T: AuditTransaction + ?Sized>(
    tx: &mut T,
    record: &AuditRecord<'_>,
) -> AuditResult<bool> {
    if !tx.claim(record.message_type, record.message_id).await? {
        return Ok(false);
    }
    tx.insert(record).await?;
    tx.mark_processed(record.message_type, record.message_id)
        .await?;
    Ok(true)
}

struct SqlxAuditTransaction<'a, 'tx> {
    tx: &'a mut sqlx::Transaction<'tx, sqlx::MySql>,
}

#[async_trait::async_trait]
impl AuditTransaction for SqlxAuditTransaction<'_, '_> {
    async fn claim(&mut self, message_type: &str, message_id: &str) -> AuditResult<bool> {
        let result = sqlx::query(AUDIT_IDEMPOTENCY_CLAIM_SQL)
            .bind(message_type)
            .bind(message_id)
            .execute(&mut **self.tx)
            .await
            .map_err(box_err)?;
        Ok(result.rows_affected() != 0)
    }

    async fn insert(&mut self, record: &AuditRecord<'_>) -> AuditResult<()> {
        sqlx::query(AUDIT_LOG_INSERT_SQL)
            .bind(record.user_id)
            .bind(record.card_id)
            .bind(record.action)
            .bind(record.resource)
            .bind(record.decision)
            .bind(record.reason)
            .bind(record.event_type)
            .bind(record.source_ip)
            .bind(record.request_id)
            .bind(record.domain_id)
            .bind(record.tenant_id)
            .bind(&record.detail)
            .execute(&mut **self.tx)
            .await
            .map_err(box_err)?;
        Ok(())
    }

    async fn mark_processed(&mut self, message_type: &str, message_id: &str) -> AuditResult<()> {
        sqlx::query(AUDIT_IDEMPOTENCY_MARK_PROCESSED_SQL)
            .bind(message_type)
            .bind(message_id)
            .execute(&mut **self.tx)
            .await
            .map_err(box_err)?;
        Ok(())
    }
}

async fn handle_audit_log(
    message_id: &str,
    msg: &AuditLogPayload,
) -> Result<(), Box<dyn std::error::Error + Send>> {
    let Some(pool) = AUDIT_LOG_DB.get() else {
        return Err(box_err(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "audit log consumer DB not initialized",
        )));
    };
    let message_id = resolve_audit_message_id(message_id, msg);
    let mut tx = pool.begin().await.map_err(box_err)?;
    let mut audit_tx = SqlxAuditTransaction { tx: &mut tx };
    persist_audit_record(
        &mut audit_tx,
        &AuditRecord {
            message_type: AUDIT_MESSAGE_TYPE,
            message_id: &message_id,
            user_id: msg.user_id.unwrap_or(0),
            card_id: msg.card_id,
            action: &msg.action,
            resource: &msg.resource,
            decision: &msg.decision,
            reason: &msg.reason,
            event_type: &msg.event_type,
            source_ip: &msg.source_ip,
            request_id: &msg.request_id,
            domain_id: msg.domain_id,
            tenant_id: msg.tenant_id,
            detail: audit_record_detail(msg.detail.as_deref(), &message_id),
        },
    )
    .await?;
    tx.commit().await.map_err(box_err)?;
    Ok(())
}

/// 启动 login.event 消费者（仅 Identity 消费，对齐 Java LoginEventConsumer 归属）。
///
/// 处理登录事件 → 写 audit_log（LOGIN_SUCCESS/LOGIN_FAILURE），失败返回 Err →
/// Consumer 框架 nack/DLX 重试（不吞失败）。调用方须先 `set_login_event_db`。
pub async fn start_login_event_consumer(channel: &Channel) -> Result<(), MqError> {
    let login_q = queue_name("login.event");
    if login_q.is_empty() {
        return Ok(());
    }
    let consumer = Consumer::new_with_message_id(
        channel.clone(),
        |message_id: &str, msg: &LoginEventPayload| {
            let msg = msg.clone();
            let message_id = message_id.to_owned();
            async move { handle_login_event(&message_id, &msg).await }
        },
        login_q,
    );
    let q = login_q.to_string();
    tokio::spawn(async move {
        if let Err(e) = consumer.start().await {
            tracing::error!(queue = %q, error = %e, "consumer failed");
        }
    });
    tracing::info!(queue = %login_q, "LoginEventConsumer started");
    Ok(())
}

/// 登录事件入库（对齐 Java LoginEventConsumer → audit_log）。
async fn handle_login_event(
    message_id: &str,
    msg: &LoginEventPayload,
) -> Result<(), Box<dyn std::error::Error + Send>> {
    let Some(pool) = LOGIN_EVENT_DB.get() else {
        return Err(box_err(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "login event consumer DB not initialized",
        )));
    };
    let event_type = if msg.success {
        "LOGIN_SUCCESS"
    } else {
        "LOGIN_FAILURE"
    };
    let decision = if msg.success { "ALLOW" } else { "DENY" };
    let (message_id, legacy) = if message_id.is_empty() {
        let message_id = msg.message_id.clone().ok_or_else(|| {
            box_err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "login event messageId missing after envelope normalization",
            ))
        })?;
        (message_id, false)
    } else {
        (
            message_id.to_owned(),
            message_id.starts_with("legacy-login-v1-"),
        )
    };
    let mut tx = pool.begin().await.map_err(box_err)?;
    let mut audit_tx = SqlxAuditTransaction { tx: &mut tx };
    persist_audit_record(
        &mut audit_tx,
        &AuditRecord {
            message_type: LOGIN_EVENT_MESSAGE_TYPE,
            message_id: &message_id,
            user_id: msg.user_id,
            card_id: msg.card_id,
            action: "login",
            resource: "identity",
            decision,
            reason: &None,
            event_type,
            source_ip: &msg.ip_address,
            request_id: &None,
            domain_id: None,
            tenant_id: None,
            detail: Some(if legacy {
                format!("loginType={};legacyMessageIdFallback=true", msg.login_type)
            } else {
                format!("loginType={}", msg.login_type)
            }),
        },
    )
    .await?;
    tx.commit().await.map_err(box_err)?;
    tracing::debug!(
        user_id = msg.user_id,
        success = msg.success,
        "login event persisted"
    );
    Ok(())
}

/// 启动 auth.session.revocation 消费者（仅 Identity 消费，对齐 Java AuthSessionRevocationConsumer 归属）。
///
/// 调用方须先 `set_session_revocation_db`。
pub async fn start_auth_session_revocation_consumer(channel: &Channel) -> Result<(), MqError> {
    let revocation_q = queue_name("auth.session.revocation");
    if revocation_q.is_empty() {
        return Ok(());
    }
    let consumer = Consumer::new(
        channel.clone(),
        |msg: &AuthSessionRevocationPayload| {
            let msg = msg.clone();
            async move { handle_auth_session_revocation(&msg).await }
        },
        revocation_q,
    );
    let q = revocation_q.to_string();
    tokio::spawn(async move {
        if let Err(e) = consumer.start().await {
            tracing::error!(queue = %q, error = %e, "consumer failed");
        }
    });
    tracing::info!(queue = %revocation_q, "AuthSessionRevocationConsumer started");
    Ok(())
}

/// 按名称查找队列（供各专属 starter 复用）
fn queue_name(suffix: &str) -> &'static str {
    QUEUES
        .iter()
        .find(|q| q.name.contains(suffix))
        .map(|q| q.name)
        .unwrap_or("")
}

// ===== AuthSessionRevocationConsumer（对齐 Java AuthSessionRevocationConsumer）=====

/// 处理 auth.session.revocation 命令：撤销用户全部 durable session 与 token family，
/// 并删除 Redis access:jti / access:grant 投影。
///
/// 对齐 Java `AuthDeviceSessionService.revokeAllForUser`：DB 撤销 + session outbox +
/// Redis projection delete。失败返回 Err → Consumer 框架 nack/DLX 重试（不吞失败）。
async fn handle_auth_session_revocation(
    msg: &AuthSessionRevocationPayload,
) -> Result<(), Box<dyn std::error::Error + Send>> {
    let Some(pool) = SESSION_REVOCATION_DB.get() else {
        return Err(box_err(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "auth session revocation consumer DB not initialized",
        )));
    };
    let operation_id = msg
        .operation_id
        .clone()
        .unwrap_or_else(|| format!("legacy-revoke-{}", msg.user_id));
    let reason = msg.reason.trim();
    if reason.is_empty() {
        return Err(box_err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "auth session revocation reason is empty",
        )));
    }
    let mut tx = pool.begin().await.map_err(box_err)?;

    // Keep session state, version and epoch in lockstep with the local revoke
    // path. The predicates make retries idempotent after a committed attempt.
    sqlx::query(
        "UPDATE auth_device_session SET status = 'REVOKED', session_state = 'REVOKED', \
         session_version = session_version + 1, session_epoch = session_epoch + 1, \
         revoked_at = UTC_TIMESTAMP(), revoked_reason = ?, updated_at = UTC_TIMESTAMP() \
         WHERE user_id = ? AND status IN ('ACTIVE', 'PENDING') \
           AND session_state IN ('ACTIVE', 'PENDING')",
    )
    .bind(reason)
    .bind(msg.user_id)
    .execute(&mut *tx)
    .await
    .map_err(box_err)?;
    sqlx::query(
        "UPDATE auth_token_family SET status = 'REVOKED', revoked_at = UTC_TIMESTAMP(), \
         revoked_reason = ?, updated_at = UTC_TIMESTAMP() \
         WHERE user_id = ? AND status = 'ACTIVE'",
    )
    .bind(reason)
    .bind(msg.user_id)
    .execute(&mut *tx)
    .await
    .map_err(box_err)?;
    sqlx::query(
        "UPDATE auth_session_jti_index SET status = 'DELETED', updated_at = UTC_TIMESTAMP() \
         WHERE user_id = ? AND status = 'ACTIVE'",
    )
    .bind(msg.user_id)
    .execute(&mut *tx)
    .await
    .map_err(box_err)?;

    // The operation id is the durable idempotency boundary. Legacy messages
    // receive a deterministic fallback id so retries cannot create new rows.
    sqlx::query(
        "INSERT IGNORE INTO auth_session_outbox \
         (operation_id, session_id, event_type, sequence_number, projection_key, payload_json, status, created_at) \
         VALUES (?, NULL, 'REVOKE', 1, ?, ?, 'PENDING', NOW())",
    )
    .bind(&operation_id)
    .bind(format!("user:{}", msg.user_id))
    .bind(serde_json::json!({ "reason": reason, "userId": msg.user_id }).to_string())
    .execute(&mut *tx)
    .await
    .map_err(box_err)?;

    let jti_keys: Vec<(String,)> =
        sqlx::query_as("SELECT jti FROM auth_session_jti_index WHERE user_id = ?")
            .bind(msg.user_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(box_err)?;
    tx.commit().await.map_err(box_err)?;

    // Redis is part of the access-session contract. Any failure must escape so
    // the MQ consumer nacks and retries instead of acknowledging a live token.
    let redis_url = std::env::var("REDIS_URL")
        .or_else(|_| std::env::var("ASTRAL_REDIS_URL"))
        .unwrap_or_else(|_| "redis://localhost:6379".into());
    let client = redis::Client::open(redis_url.as_str()).map_err(box_err)?;
    let mut conn = client.get_connection_manager().await.map_err(box_err)?;
    for (jti,) in jti_keys {
        conn.del::<_, ()>((format!("access:jti:{jti}"), format!("access:grant:{jti}")))
            .await
            .map_err(box_err)?;
        conn.set_ex::<_, _, ()>(format!("jwt:revoked:{jti}"), "1", 7 * 24 * 3600)
            .await
            .map_err(box_err)?;
    }

    tracing::warn!(
        user_id = msg.user_id,
        operation_id = %operation_id,
        reason,
        "auth session revocation command processed"
    );
    Ok(())
}

/// 将 sqlx/IO 错误装箱为 `Box<dyn std::error::Error + Send>`（Consumer handler 签名要求）
fn box_err(e: impl std::error::Error + Send + 'static) -> Box<dyn std::error::Error + Send> {
    Box::new(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn republish_failure_attempts_progress_to_explicit_terminal() {
        assert_eq!(
            next_republish_failure_action(0),
            RepublishFailureAction::RetainAndRequeue { attempt: 1 }
        );
        assert_eq!(
            next_republish_failure_action(1),
            RepublishFailureAction::RetainAndRequeue { attempt: 2 }
        );
        assert_eq!(
            next_republish_failure_action(2),
            RepublishFailureAction::Terminal { attempt: 3 }
        );
        assert_eq!(
            next_republish_failure_action(99),
            RepublishFailureAction::Terminal { attempt: 3 }
        );
    }

    fn test_context(queue: &str, enabled: bool) -> DlqConsumerContext {
        DlqConsumerContext {
            owner: "test",
            dlq: "astral.dlx.test".to_owned(),
            consumer_tag: "test-consumer".to_owned(),
            business_queue: queue.to_owned(),
            business_rk: "test.routing".to_owned(),
            business_exchange: "astral.direct".to_owned(),
            quarantine_db: None,
            quarantine_enabled: enabled,
        }
    }

    #[test]
    fn terminal_capture_selection_is_limited_to_enabled_owner_queues() {
        assert!(terminal_capture_selected(&test_context(
            QUEUE_AUDIT_LOG,
            true
        )));
        assert!(terminal_capture_selected(&test_context(
            QUEUE_LOGIN_EVENT,
            true
        )));
        assert!(!terminal_capture_selected(&test_context(
            QUEUE_AUDIT_LOG,
            false
        )));
        assert!(!terminal_capture_selected(&test_context(
            crate::config::QUEUE_SUBJECT_DELETE,
            true
        )));
    }

    #[test]
    fn terminal_capture_success_acks_only_after_capture() {
        let audit = test_context(QUEUE_AUDIT_LOG, true);
        let login = test_context(QUEUE_LOGIN_EVENT, true);
        let ordinary = test_context(crate::config::QUEUE_SUBJECT_DELETE, false);
        assert_eq!(
            terminal_capture_action(
                &audit,
                &TerminalCaptureResult::Captured { quarantine_id: 7 },
                0,
            ),
            TerminalCaptureAction::AckAfterCapture
        );
        assert_eq!(
            terminal_capture_action(
                &login,
                &TerminalCaptureResult::Failed {
                    reason: "db".to_owned(),
                },
                0,
            ),
            TerminalCaptureAction::RetainAndRequeue { attempt: 1 }
        );
        assert_eq!(
            terminal_capture_action(&ordinary, &TerminalCaptureResult::NotSelected, 0,),
            TerminalCaptureAction::AckWithoutCapture
        );
    }

    #[test]
    fn terminal_capture_failure_uses_bounded_action() {
        assert_eq!(
            capture_failure_action(0),
            TerminalCaptureAction::RetainAndRequeue { attempt: 1 }
        );
        assert_eq!(
            capture_failure_action(MAX_REPUBLISH_ATTEMPTS - 1),
            TerminalCaptureAction::RetainAndRequeue {
                attempt: MAX_REPUBLISH_ATTEMPTS
            }
        );
        assert_eq!(
            capture_failure_action(MAX_REPUBLISH_ATTEMPTS),
            TerminalCaptureAction::PreserveUnacked
        );
        assert_eq!(
            capture_failure_action(u32::MAX),
            TerminalCaptureAction::PreserveUnacked
        );
    }

    #[test]
    fn quarantine_failure_reason_keeps_republish_evidence() {
        assert_eq!(
            quarantine_failure_reason("max_retries_exceeded", 3),
            "max_retries_exceeded;dlq_republish_count=3"
        );
    }

    #[test]
    fn idempotency_namespaces_are_distinct_and_schema_key_is_composite() {
        assert_eq!(AUDIT_MESSAGE_TYPE, "AUDIT_LOG");
        assert_eq!(LOGIN_EVENT_MESSAGE_TYPE, "LOGIN_EVENT");
        assert_ne!(AUDIT_MESSAGE_TYPE, LOGIN_EVENT_MESSAGE_TYPE);
        let schema = include_str!("../../astral-db/migrations/20240630000001_baseline.sql");
        assert!(schema.contains("UNIQUE KEY uk_mq_msg (message_type, message_id)"));
    }

    #[test]
    fn audit_consumer_sql_does_not_include_rust_escape_artifacts() {
        for query in [
            AUDIT_IDEMPOTENCY_CLAIM_SQL,
            AUDIT_LOG_INSERT_SQL,
            AUDIT_IDEMPOTENCY_MARK_PROCESSED_SQL,
        ] {
            assert!(
                !query.contains('\\'),
                "audit SQL contains a literal backslash: {query:?}"
            );
        }
    }

    #[test]
    fn batch_sql_fragments_are_placeholder_correct_and_escape_free() {
        assert_eq!(sql_placeholders(1), "?");
        assert_eq!(sql_placeholders(3), "?,?,?");
        assert_eq!(sql_repeated_values("(?, ?)", 2), "(?, ?),(?, ?)");
        let claim_values = sql_repeated_values("(?, ?, 'PROCESSING')", 2);
        let audit_values = sql_repeated_values("(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", 3);
        for fragment in [claim_values, audit_values, sql_placeholders(50)] {
            assert!(
                !fragment.contains('\\'),
                "batch SQL fragment contains a literal backslash: {fragment:?}"
            );
        }
    }

    fn sample_audit_payload() -> AuditLogPayload {
        AuditLogPayload {
            message_id: None,
            user_id: Some(7),
            card_id: Some(70),
            action: "read".into(),
            resource: "card".into(),
            decision: "ALLOW".into(),
            reason: Some("ok".into()),
            event_type: "PermissionCheck".into(),
            source_ip: Some("127.0.0.1".into()),
            request_id: Some("req-1".into()),
            domain_id: Some(2),
            tenant_id: Some(1),
            detail: None,
        }
    }

    #[test]
    fn audit_message_id_resolution_prefers_envelope_and_falls_back_to_legacy() {
        // 信封 id 存在 → 直接使用（Redis 租约与 DB 幂等键同源）。
        assert_eq!(
            resolve_audit_message_id("envelope-1", &sample_audit_payload()),
            "envelope-1"
        );
        // 信封 id 缺失且 payload 无 id → canonical legacy id（与逐条路径同规则）。
        let resolved = resolve_audit_message_id("", &sample_audit_payload());
        assert!(resolved.starts_with("legacy-audit-v1-"));
        // 相同 payload 的解析结果必须稳定（幂等键确定性）。
        assert_eq!(
            resolved,
            resolve_audit_message_id("", &sample_audit_payload())
        );
    }

    #[test]
    fn batch_audit_record_mapping_matches_per_record_path() {
        let payload = sample_audit_payload();
        let message_id = "envelope-9";
        let record = audit_record_for_batch(message_id, &payload);
        assert_eq!(record.message_type, AUDIT_MESSAGE_TYPE);
        assert_eq!(record.message_id, message_id);
        assert_eq!(record.user_id, 7);
        assert_eq!(record.card_id, Some(70));
        assert_eq!(record.action, "read");
        assert_eq!(record.resource, "card");
        assert_eq!(record.decision, "ALLOW");
        assert_eq!(record.reason, &Some("ok".into()));
        assert_eq!(record.event_type, "PermissionCheck");
        assert_eq!(record.source_ip, &Some("127.0.0.1".into()));
        assert_eq!(record.request_id, &Some("req-1".into()));
        assert_eq!(record.domain_id, Some(2));
        assert_eq!(record.tenant_id, Some(1));
        assert_eq!(record.detail.as_deref(), Some("messageId=envelope-9"));
        // legacy 前缀 id 携带回退标记（与逐条路径 detail 规则一致）。
        let legacy = audit_record_for_batch("legacy-audit-v1-abc", &payload);
        assert_eq!(
            legacy.detail.as_deref(),
            Some("messageId=legacy-audit-v1-abc;legacyMessageIdFallback=true")
        );
    }

    #[test]
    fn producer_supplied_detail_is_preserved_and_not_overwritten_by_message_id_text() {
        // producer 提供的结构化 detail（例如 ORG_SCOPE provenance JSON）必须
        // 原样落库，不得被 messageId-only 文本覆盖；幂等键仍走信封 message_id。
        let mut payload = sample_audit_payload();
        payload.detail = Some("{\"schema\":\"audit-detail-org-v1\",\"path\":\"/stats\"}".into());
        let record = audit_record_for_batch("envelope-10", &payload);
        assert_eq!(
            record.detail.as_deref(),
            Some("{\"schema\":\"audit-detail-org-v1\",\"path\":\"/stats\"}")
        );
        // 逐条回退路径同规则。
        assert_eq!(
            audit_record_detail(payload.detail.as_deref(), "legacy-audit-v1-abc").as_deref(),
            Some("{\"schema\":\"audit-detail-org-v1\",\"path\":\"/stats\"}")
        );
    }

    #[test]
    fn blank_or_missing_detail_falls_back_to_message_id_correlation_text() {
        // 旧消息（detail 缺失）与空白 detail 都回退 messageId 关联文本。
        let payload = sample_audit_payload();
        assert_eq!(
            audit_record_detail(payload.detail.as_deref(), "envelope-11").as_deref(),
            Some("messageId=envelope-11")
        );
        let mut blank = sample_audit_payload();
        blank.detail = Some("   ".into());
        assert_eq!(
            audit_record_detail(blank.detail.as_deref(), "envelope-12").as_deref(),
            Some("messageId=envelope-12")
        );
        assert_eq!(
            audit_record_detail(blank.detail.as_deref(), "legacy-audit-v1-abc").as_deref(),
            Some("messageId=legacy-audit-v1-abc;legacyMessageIdFallback=true")
        );
    }

    #[test]
    fn dlq_owner_mapping_is_complete_and_disjoint() {
        validate_dlq_owner_mapping().expect("static DLQ owner mapping must be valid");
        let identity: HashSet<_> = IDENTITY_DLQ_QUEUES.iter().copied().collect();
        let trustgraph: HashSet<_> = TRUSTGRAPH_DLQ_QUEUES.iter().copied().collect();
        assert!(identity.is_disjoint(&trustgraph));
        assert_eq!(identity.len(), IDENTITY_DLQ_QUEUES.len());
        assert_eq!(trustgraph.len(), TRUSTGRAPH_DLQ_QUEUES.len());
    }

    #[test]
    fn dlq_owner_sets_are_exact() {
        assert_eq!(
            IDENTITY_DLQ_QUEUES,
            &[QUEUE_LOGIN_EVENT, QUEUE_AUTH_SESSION_REVOCATION]
        );
        assert_eq!(TRUSTGRAPH_DLQ_QUEUES, &[QUEUE_AUDIT_LOG]);
        assert!(!IDENTITY_DLQ_QUEUES.contains(&crate::config::QUEUE_CHAT_MESSAGE));
        assert!(!TRUSTGRAPH_DLQ_QUEUES.contains(&crate::config::QUEUE_LEARNING_PROGRESS));
    }

    #[test]
    fn dlq_consumer_tags_are_owner_and_queue_specific() {
        assert_eq!(
            dlq_consumer_tag(DlqOwner::Identity, QUEUE_LOGIN_EVENT),
            "astral_dlq_identity_astral_login_event"
        );
        assert_ne!(
            dlq_consumer_tag(DlqOwner::Identity, QUEUE_LOGIN_EVENT),
            dlq_consumer_tag(DlqOwner::TrustGraph, QUEUE_LOGIN_EVENT)
        );
    }

    #[test]
    fn auth_session_revocation_queue_contract() {
        // 队列/路由键与 Java AuthSessionRevocationCommandService 一致
        assert_eq!(
            crate::config::QUEUE_AUTH_SESSION_REVOCATION,
            "astral.auth.session.revocation"
        );
        assert_eq!(
            crate::config::QUEUES
                .iter()
                .find(|q| q.name == crate::config::QUEUE_AUTH_SESSION_REVOCATION)
                .map(|q| q.routing_key),
            Some("auth.session.revocation")
        );
    }
}
