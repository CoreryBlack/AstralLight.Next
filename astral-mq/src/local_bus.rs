use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};

use crate::config::{
    local_route_for, route_for, QUEUE_AUDIT_LOG, QUEUE_AUTHORIZATION_INVALIDATION,
    QUEUE_AUTH_SESSION_REVOCATION, QUEUE_LOGIN_EVENT,
};
use crate::envelope::MessageEnvelope;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalOwner {
    Identity,
    TrustGraph,
    AuthorizationInvalidation,
}

fn expected_owner(queue: &str) -> Option<LocalOwner> {
    match queue {
        QUEUE_AUDIT_LOG => Some(LocalOwner::TrustGraph),
        QUEUE_AUTHORIZATION_INVALIDATION => Some(LocalOwner::AuthorizationInvalidation),
        QUEUE_LOGIN_EVENT | QUEUE_AUTH_SESSION_REVOCATION => Some(LocalOwner::Identity),
        _ => None,
    }
}

fn canonical_queue(queue: &str) -> Option<&'static str> {
    match queue {
        QUEUE_AUDIT_LOG => Some(QUEUE_AUDIT_LOG),
        QUEUE_AUTHORIZATION_INVALIDATION => Some(QUEUE_AUTHORIZATION_INVALIDATION),
        QUEUE_LOGIN_EVENT => Some(QUEUE_LOGIN_EVENT),
        QUEUE_AUTH_SESSION_REVOCATION => Some(QUEUE_AUTH_SESSION_REVOCATION),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LocalBusLimits {
    pub queue_capacity: usize,
    pub max_payload_bytes: usize,
    pub max_in_flight_bytes: usize,
}

impl Default for LocalBusLimits {
    fn default() -> Self {
        Self {
            queue_capacity: 128,
            max_payload_bytes: 256 * 1024,
            max_in_flight_bytes: 4 * 1024 * 1024,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LocalBusError {
    #[error("invalid local bus limits")]
    InvalidLimits,
    #[error("local queue or owner is not allowed: {0}")]
    InvalidOwner(String),
    #[error("local route is not declared: {0}")]
    InvalidRoute(String),
    #[error("local queue has no registered owner: {0}")]
    NoOwner(String),
    #[error("local queue owner is closed: {0}")]
    Closed(String),
    #[error("local queue or byte budget is full: {0}")]
    Full(String),
    #[error("local message exceeds payload limit: {actual} > {limit}")]
    TooLarge { actual: usize, limit: usize },
    #[error("local message is invalid: {0}")]
    InvalidMessage(String),
    #[error("local message id is already in flight: {0}")]
    Duplicate(String),
    #[error("local handler failed: {0}")]
    Handler(String),
    #[error("local handler result is unknown; reconcile before retrying: {0}")]
    UnknownOutcome(String),
}

struct LocalBusState {
    senders: Mutex<HashMap<&'static str, mpsc::Sender<LocalDelivery>>>,
    in_flight: Arc<Mutex<HashSet<String>>>,
    bytes: Arc<Semaphore>,
    limits: LocalBusLimits,
}

#[derive(Clone)]
pub struct LocalBus(Arc<LocalBusState>);

static GLOBAL_LOCAL_BUS: OnceLock<LocalBus> = OnceLock::new();

pub fn install_global_local_bus(bus: LocalBus) -> Result<(), LocalBusError> {
    GLOBAL_LOCAL_BUS
        .set(bus)
        .map_err(|_| LocalBusError::InvalidOwner("global bus already installed".into()))
}

pub fn global_local_bus() -> Option<LocalBus> {
    GLOBAL_LOCAL_BUS.get().cloned()
}

pub struct LocalReceiver {
    receiver: mpsc::Receiver<LocalDelivery>,
}

impl LocalReceiver {
    pub async fn recv(&mut self) -> Option<LocalDelivery> {
        self.receiver.recv().await
    }
}

struct InFlight {
    id: String,
    ids: Arc<Mutex<HashSet<String>>>,
    _bytes: OwnedSemaphorePermit,
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.ids.lock().unwrap().remove(&self.id);
    }
}

pub struct LocalDelivery {
    pub queue_name: &'static str,
    pub envelope: MessageEnvelope,
    reply: Option<oneshot::Sender<Result<(), String>>>,
    _in_flight: InFlight,
}

impl LocalDelivery {
    pub fn complete(mut self, result: Result<(), String>) {
        if let Some(reply) = self.reply.take() {
            let _ = reply.send(result);
        }
    }
}

impl LocalBus {
    pub fn new(limits: LocalBusLimits) -> Result<Self, LocalBusError> {
        if limits.queue_capacity == 0
            || limits.max_payload_bytes == 0
            || limits.max_payload_bytes > limits.max_in_flight_bytes
            || limits.max_in_flight_bytes > u32::MAX as usize
        {
            return Err(LocalBusError::InvalidLimits);
        }
        Ok(Self(Arc::new(LocalBusState {
            senders: Mutex::new(HashMap::new()),
            in_flight: Arc::new(Mutex::new(HashSet::new())),
            bytes: Arc::new(Semaphore::new(limits.max_in_flight_bytes)),
            limits,
        })))
    }

    pub fn register(
        &self,
        queue: &'static str,
        owner: LocalOwner,
    ) -> Result<LocalReceiver, LocalBusError> {
        if expected_owner(queue) != Some(owner) {
            return Err(LocalBusError::InvalidOwner(queue.into()));
        }
        let mut senders = self.0.senders.lock().unwrap();
        if senders.contains_key(queue) {
            return Err(LocalBusError::InvalidOwner(queue.into()));
        }
        let (sender, receiver) = mpsc::channel(self.0.limits.queue_capacity);
        senders.insert(queue, sender);
        Ok(LocalReceiver { receiver })
    }

    pub fn owners_ready(&self) -> bool {
        let senders = self.0.senders.lock().unwrap();
        [
            QUEUE_AUDIT_LOG,
            QUEUE_LOGIN_EVENT,
            QUEUE_AUTH_SESSION_REVOCATION,
            QUEUE_AUTHORIZATION_INVALIDATION,
        ]
        .iter()
        .all(|queue| senders.get(queue).is_some_and(|sender| !sender.is_closed()))
    }

    pub fn try_publish(
        &self,
        queue: &str,
        routing_key: &str,
        envelope: MessageEnvelope,
    ) -> Result<(), LocalBusError> {
        self.enqueue(queue, routing_key, envelope, None)
    }

    pub async fn publish_and_wait(
        &self,
        queue: &str,
        routing_key: &str,
        envelope: MessageEnvelope,
        deadline: Duration,
    ) -> Result<(), LocalBusError> {
        let id = envelope.message_id.clone();
        let (reply, receiver) = oneshot::channel();
        self.enqueue(queue, routing_key, envelope, Some(reply))?;
        match tokio::time::timeout(deadline, receiver).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(reason))) => Err(LocalBusError::Handler(reason)),
            Ok(Err(_)) | Err(_) => Err(LocalBusError::UnknownOutcome(id)),
        }
    }

    fn enqueue(
        &self,
        queue: &str,
        routing_key: &str,
        envelope: MessageEnvelope,
        reply: Option<oneshot::Sender<Result<(), String>>>,
    ) -> Result<(), LocalBusError> {
        if expected_owner(queue).is_none()
            || (route_for(queue, routing_key).is_none() && !local_route_for(queue, routing_key))
        {
            return Err(LocalBusError::InvalidRoute(queue.into()));
        }
        envelope.validate().map_err(LocalBusError::InvalidMessage)?;
        if queue == QUEUE_AUTHORIZATION_INVALIDATION {
            crate::invalidation::InvalidationEvent::from_envelope(&envelope).map_err(|error| {
                LocalBusError::InvalidMessage(format!(
                    "invalid authorization invalidation envelope: {error}"
                ))
            })?;
        }
        if envelope.target_region.is_some() {
            return Err(LocalBusError::InvalidMessage(
                "remote target requires Rabbit transport".into(),
            ));
        }
        let actual = serde_json::to_vec(&envelope)
            .map_err(|error| LocalBusError::InvalidMessage(error.to_string()))?
            .len();
        if actual > self.0.limits.max_payload_bytes {
            return Err(LocalBusError::TooLarge {
                actual,
                limit: self.0.limits.max_payload_bytes,
            });
        }
        let sender = self
            .0
            .senders
            .lock()
            .unwrap()
            .get(queue)
            .cloned()
            .ok_or_else(|| LocalBusError::NoOwner(queue.into()))?;
        let slot = sender.try_reserve().map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => LocalBusError::Full(queue.into()),
            mpsc::error::TrySendError::Closed(_) => LocalBusError::Closed(queue.into()),
        })?;
        let bytes = self
            .0
            .bytes
            .clone()
            .try_acquire_many_owned(actual as u32)
            .map_err(|_| LocalBusError::Full(queue.into()))?;
        let id = envelope.message_id.clone();
        let mut ids = self.0.in_flight.lock().unwrap();
        if !ids.insert(id.clone()) {
            return Err(LocalBusError::Duplicate(id));
        }
        drop(ids);
        let queue_name =
            canonical_queue(queue).ok_or_else(|| LocalBusError::InvalidRoute(queue.into()))?;
        slot.send(LocalDelivery {
            queue_name,
            envelope,
            reply,
            _in_flight: InFlight {
                id,
                ids: self.0.in_flight.clone(),
                _bytes: bytes,
            },
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn envelope(id: &str) -> MessageEnvelope {
        MessageEnvelope::new(id, id, "AUDIT_LOG", 1, "local", json!({"value": id})).unwrap()
    }

    fn bus(capacity: usize) -> LocalBus {
        LocalBus::new(LocalBusLimits {
            queue_capacity: capacity,
            ..LocalBusLimits::default()
        })
        .unwrap()
    }

    #[tokio::test]
    async fn invalidation_route_requires_typed_contract() {
        let bus = bus(2);
        let mut receiver = bus
            .register(
                QUEUE_AUTHORIZATION_INVALIDATION,
                LocalOwner::AuthorizationInvalidation,
            )
            .unwrap();
        let malformed = MessageEnvelope::new(
            "bad-invalidation",
            "bad-operation",
            crate::invalidation::EVIDENCE_INVALIDATED,
            crate::invalidation::INVALIDATION_SCHEMA_VERSION,
            "local",
            json!({"tenantId": 7}),
        )
        .unwrap();
        assert!(matches!(
            bus.try_publish(
                QUEUE_AUTHORIZATION_INVALIDATION,
                crate::config::ROUTING_KEY_AUTHORIZATION_INVALIDATION,
                malformed,
            ),
            Err(LocalBusError::InvalidMessage(reason))
                if reason.contains("invalid authorization invalidation envelope")
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(1), receiver.recv())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn valid_invalidation_route_is_admitted_only_with_local_owner() {
        let bus = bus(2);
        let mut receiver = bus
            .register(
                QUEUE_AUTHORIZATION_INVALIDATION,
                LocalOwner::AuthorizationInvalidation,
            )
            .unwrap();
        let event = crate::invalidation::InvalidationEvent::EvidenceInvalidated(
            crate::invalidation::EvidenceInvalidated {
                tenant_id: 7,
                card_id: Some(42),
                aggregate_type: astral_types::PublishedEvidenceAggregate::UserCard,
                aggregate_id: 42,
                published_generation: 10,
                source_generation: 10,
                revoke_fence: 0,
            },
        );
        let envelope = event
            .to_envelope("valid-invalidation", "valid-operation", "local")
            .unwrap();
        bus.try_publish(
            QUEUE_AUTHORIZATION_INVALIDATION,
            crate::config::ROUTING_KEY_AUTHORIZATION_INVALIDATION,
            envelope,
        )
        .unwrap();
        let delivery = receiver.recv().await.unwrap();
        assert_eq!(delivery.queue_name, QUEUE_AUTHORIZATION_INVALIDATION);
        delivery.complete(Ok(()));
    }

    #[tokio::test]
    async fn owner_route_capacity_and_completion_are_distinct() {
        let bus = bus(1);
        assert!(!bus.owners_ready());
        assert!(matches!(
            bus.try_publish(QUEUE_AUDIT_LOG, "audit.log", envelope("one")),
            Err(LocalBusError::NoOwner(_))
        ));
        assert!(matches!(
            bus.register(QUEUE_AUDIT_LOG, LocalOwner::Identity),
            Err(LocalBusError::InvalidOwner(_))
        ));
        let mut receiver = bus
            .register(QUEUE_AUDIT_LOG, LocalOwner::TrustGraph)
            .unwrap();
        assert!(matches!(
            bus.try_publish(QUEUE_AUDIT_LOG, "login.event", envelope("one")),
            Err(LocalBusError::InvalidRoute(_))
        ));
        bus.try_publish(QUEUE_AUDIT_LOG, "audit.log", envelope("one"))
            .unwrap();
        assert!(matches!(
            bus.try_publish(QUEUE_AUDIT_LOG, "audit.log", envelope("two")),
            Err(LocalBusError::Full(_))
        ));
        let delivery = receiver.recv().await.unwrap();
        assert_eq!(delivery.envelope.message_id, "one");
        assert!(matches!(
            bus.try_publish(QUEUE_AUDIT_LOG, "audit.log", envelope("one")),
            Err(LocalBusError::Duplicate(_))
        ));
        delivery.complete(Ok(()));
        bus.try_publish(QUEUE_AUDIT_LOG, "audit.log", envelope("two"))
            .unwrap();
        drop(receiver);
        assert!(matches!(
            bus.try_publish(QUEUE_AUDIT_LOG, "audit.log", envelope("three")),
            Err(LocalBusError::Closed(_))
        ));
    }

    #[tokio::test]
    async fn completion_wait_fails_closed_when_consumer_disappears() {
        let bus = bus(2);
        let mut receiver = bus
            .register(QUEUE_AUTH_SESSION_REVOCATION, LocalOwner::Identity)
            .unwrap();
        let waiter = tokio::spawn({
            let bus = bus.clone();
            async move {
                bus.publish_and_wait(
                    QUEUE_AUTH_SESSION_REVOCATION,
                    "auth.session.revocation",
                    envelope("revoke"),
                    Duration::from_secs(1),
                )
                .await
            }
        });
        let delivery = receiver.recv().await.unwrap();
        drop(delivery);
        assert_eq!(
            waiter.await.unwrap(),
            Err(LocalBusError::UnknownOutcome("revoke".into()))
        );
        drop(receiver);
    }

    /// 等待语义：`publish_and_wait` 只在 handler 调用 `delivery.complete`
    /// 后才以该结果收束 —— `complete(Ok)` 才是 `Ok`，`complete(Err)` 必须是
    /// `Handler` 错误（若 admission 即返回，此处会错误地得到 `Ok`）。
    #[tokio::test]
    async fn publish_and_wait_resolves_only_with_handler_completion_result() {
        let bus = bus(4);
        let mut receiver = bus
            .register(QUEUE_AUTH_SESSION_REVOCATION, LocalOwner::Identity)
            .unwrap();
        let handler = tokio::spawn(async move {
            let delivery = receiver.recv().await.unwrap();
            assert_eq!(delivery.envelope.message_id, "wait-ok");
            delivery.complete(Ok(()));
            let delivery = receiver.recv().await.unwrap();
            assert_eq!(delivery.envelope.message_id, "wait-fail");
            delivery.complete(Err("identity revocation failed".into()));
        });
        bus.publish_and_wait(
            QUEUE_AUTH_SESSION_REVOCATION,
            "auth.session.revocation",
            envelope("wait-ok"),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert!(matches!(
            bus.publish_and_wait(
                QUEUE_AUTH_SESSION_REVOCATION,
                "auth.session.revocation",
                envelope("wait-fail"),
                Duration::from_secs(1),
            )
            .await,
            Err(LocalBusError::Handler(reason)) if reason == "identity revocation failed"
        ));
        handler.await.unwrap();
    }

    /// deadline 到期且 delivery 从未完成 → 必须是 `UnknownOutcome`（fail
    /// closed），绝不返回成功。使用 `Duration::ZERO` 保证确定性：reply sender
    /// 仍被未完成的 delivery 持有，等待方只能因超时收束。
    #[tokio::test]
    async fn publish_and_wait_deadline_expiry_without_completion_is_unknown() {
        let bus = bus(4);
        let mut receiver = bus
            .register(QUEUE_AUTH_SESSION_REVOCATION, LocalOwner::Identity)
            .unwrap();
        let waiter = tokio::spawn({
            let bus = bus.clone();
            async move {
                bus.publish_and_wait(
                    QUEUE_AUTH_SESSION_REVOCATION,
                    "auth.session.revocation",
                    envelope("wait-deadline"),
                    Duration::ZERO,
                )
                .await
            }
        });
        let delivery = receiver.recv().await.unwrap();
        assert_eq!(delivery.envelope.message_id, "wait-deadline");
        assert_eq!(
            waiter.await.unwrap(),
            Err(LocalBusError::UnknownOutcome("wait-deadline".into()))
        );
        drop(delivery);
    }

    #[tokio::test]
    async fn payload_and_total_bytes_are_bounded_even_after_dequeue() {
        let limits = LocalBusLimits {
            queue_capacity: 2,
            max_payload_bytes: 512,
            max_in_flight_bytes: 512,
        };
        let bus = LocalBus::new(limits).unwrap();
        let mut receiver = bus
            .register(QUEUE_AUDIT_LOG, LocalOwner::TrustGraph)
            .unwrap();
        let mut large = envelope("large");
        large.payload = json!({"value": "x".repeat(1024)});
        large.payload_sha256 = crate::envelope::payload_digest(&large.payload).unwrap();
        assert!(matches!(
            bus.try_publish(QUEUE_AUDIT_LOG, "audit.log", large),
            Err(LocalBusError::TooLarge { .. })
        ));
        let first = envelope("first");
        let first_bytes = serde_json::to_vec(&first).unwrap().len();
        bus.try_publish(QUEUE_AUDIT_LOG, "audit.log", first)
            .unwrap();
        let delivery = receiver.recv().await.unwrap();
        let mut second = envelope("second");
        second.payload = json!({"value": "y".repeat(512 - first_bytes)});
        second.payload_sha256 = crate::envelope::payload_digest(&second.payload).unwrap();
        assert!(serde_json::to_vec(&second).unwrap().len() <= 512);
        assert!(matches!(
            bus.try_publish(QUEUE_AUDIT_LOG, "audit.log", second),
            Err(LocalBusError::Full(_))
        ));
        drop(delivery);
    }

    #[tokio::test]
    async fn fifo_for_single_queue_follows_admission_order() {
        let bus = bus(64);
        let mut receiver = bus
            .register(QUEUE_LOGIN_EVENT, LocalOwner::Identity)
            .unwrap();
        for index in 0..32 {
            bus.try_publish(
                QUEUE_LOGIN_EVENT,
                "login.event",
                envelope(&index.to_string()),
            )
            .unwrap();
        }
        for index in 0..32 {
            let delivery = receiver.recv().await.unwrap();
            assert_eq!(delivery.envelope.message_id, index.to_string());
            delivery.complete(Ok(()));
        }
    }

    /// 极端场景（并发写风暴）：N 个发布者并发入队、单消费者顺序消费。
    /// 验证两条不变式：
    /// - **零静默丢失**：每条消息恰好被投递一次（总量精确 = 发布总量）；
    /// - **每发布者内部有序**：单队列 FIFO 保证同一发布者的消息严格按
    ///   程序序到达（跨发布者的交错顺序不承诺，等价 RabbitMQ 每队列语义）。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_publisher_storm_delivers_exactly_once_with_per_publisher_order() {
        const PUBLISHERS: usize = 4;
        const PER_PUBLISHER: usize = 50;
        let bus = bus(PUBLISHERS * PER_PUBLISHER);
        let mut receiver = bus
            .register(QUEUE_AUDIT_LOG, LocalOwner::TrustGraph)
            .unwrap();

        let mut publishers = Vec::new();
        for publisher in 0..PUBLISHERS {
            let bus = bus.clone();
            publishers.push(tokio::spawn(async move {
                for sequence in 0..PER_PUBLISHER {
                    bus.try_publish(
                        QUEUE_AUDIT_LOG,
                        "audit.log",
                        envelope(&format!("pub{publisher}-seq{sequence:04}")),
                    )
                    .expect("admission within capacity must succeed");
                }
            }));
        }
        for publisher in publishers {
            publisher.await.unwrap();
        }

        let mut delivered = std::collections::HashSet::new();
        let mut last_sequence = [None; PUBLISHERS];
        for _ in 0..PUBLISHERS * PER_PUBLISHER {
            let delivery = receiver.recv().await.expect("queue must not be closed");
            let message_id = delivery.envelope.message_id.clone();
            let (publisher, sequence) = message_id
                .strip_prefix("pub")
                .and_then(|rest| rest.split_once("-seq"))
                .map(|(publisher, sequence)| {
                    (
                        publisher.parse::<usize>().unwrap(),
                        sequence.parse::<usize>().unwrap(),
                    )
                })
                .unwrap();
            // 零丢失 + 零重复：每条恰好出现一次。
            assert!(
                delivered.insert(message_id.clone()),
                "duplicate delivery of {message_id}"
            );
            // 每发布者严格递增（单消费者顺序消费）。
            assert!(
                last_sequence[publisher].is_none_or(|previous| sequence > previous),
                "per-publisher order violated at {message_id}"
            );
            last_sequence[publisher] = Some(sequence);
            delivery.complete(Ok(()));
        }
        assert_eq!(delivered.len(), PUBLISHERS * PER_PUBLISHER);
    }

    /// 极端场景（背压风暴）：队列打满后每一次溢出发布都必须得到显式
    /// 拒绝（`Full`），绝不出现"看似成功"的静默丢弃；随后已接纳的消息
    /// 全部完整可消费。
    #[tokio::test]
    async fn queue_full_storm_reports_every_overflow_explicitly() {
        const CAPACITY: usize = 8;
        const OVERFLOW: usize = 5;
        let bus = bus(CAPACITY);
        let mut receiver = bus
            .register(QUEUE_LOGIN_EVENT, LocalOwner::Identity)
            .unwrap();
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        for index in 0..CAPACITY + OVERFLOW {
            match bus.try_publish(
                QUEUE_LOGIN_EVENT,
                "login.event",
                envelope(&format!("storm-{index}")),
            ) {
                Ok(()) => accepted += 1,
                Err(LocalBusError::Full(_)) => rejected += 1,
                Err(error) => panic!("unexpected admission error: {error}"),
            }
        }
        assert_eq!(accepted, CAPACITY);
        assert_eq!(rejected, OVERFLOW);
        for index in 0..CAPACITY {
            let delivery = receiver.recv().await.unwrap();
            assert_eq!(delivery.envelope.message_id, format!("storm-{index}"));
            delivery.complete(Ok(()));
        }
    }

    /// 极限探针（informational）：持续收发的端到端吞吐——入队（含 envelope
    /// 校验/序列化/digest）+ 消费全链路，背压下生产者自旋重试。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn limit_sustained_delivery_throughput() {
        const MESSAGES: usize = 100_000;
        let bus = LocalBus::new(LocalBusLimits {
            queue_capacity: 4096,
            ..LocalBusLimits::default()
        })
        .unwrap();
        let mut receiver = bus
            .register(QUEUE_LOGIN_EVENT, LocalOwner::Identity)
            .unwrap();
        let producer = tokio::spawn({
            let bus = bus.clone();
            async move {
                for index in 0..MESSAGES {
                    let envelope = envelope(&format!("limit-{index}"));
                    loop {
                        match bus.try_publish(QUEUE_LOGIN_EVENT, "login.event", envelope.clone()) {
                            Ok(()) => break,
                            Err(LocalBusError::Full(_)) => tokio::task::yield_now().await,
                            Err(error) => panic!("unexpected admission error: {error}"),
                        }
                    }
                }
            }
        });
        let started = std::time::Instant::now();
        for _ in 0..MESSAGES {
            let delivery = receiver.recv().await.expect("queue must not be closed");
            delivery.complete(Ok(()));
        }
        producer.await.unwrap();
        let wall = started.elapsed();
        println!(
            "localbus sustained delivery: {} msgs, wall {:?}, throughput {:.0} msgs/s (envelope build + admission + delivery, end to end)",
            MESSAGES,
            wall,
            MESSAGES as f64 / wall.as_secs_f64()
        );
    }
}
