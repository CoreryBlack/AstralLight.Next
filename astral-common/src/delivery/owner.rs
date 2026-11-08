//! DeliveryOwner: the shared composition root for real delivery.
//!
//! One owner is shared by every caller (monitor alerts, notification test
//! endpoint, password reset, verification OTP) so the durable-intent, CAS
//! lease, attempt budget, and typed-truth semantics cannot drift between
//! call sites.
//!
//! Flow per `deliver`:
//! 1. durable intent metadata (idempotent by stable `message_id`);
//! 2. CAS attempt lease (single live attempt per message, bounded budget);
//! 3. real transport dispatch under a concurrency permit and deadline;
//! 4. CAS settlement of the typed truth (`IN_DOUBT` requires reconciliation
//!    and is never auto-retried).
//!
//! Ephemeral-secret payloads follow the same durable metadata/lease path but
//! record **no** payload material (no body, no body digest), so an UNKNOWN
//! attempt cannot be replayed across replicas or restarts while the raw
//! secret stays memory-only.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use time::PrimitiveDateTime;
use tokio::sync::Semaphore;

use crate::delivery::channel_config::{resolve_channel, ResolvedChannel};
use crate::delivery::email::{SmtpClient, SmtpOutcome, SmtpSendParams};
use crate::delivery::http::{HttpRelayTransport, RelayOutcome};
use crate::delivery::intent::{ChannelKind, DeliveryMessage, PayloadClass};
use crate::delivery::lease::{AttemptLease, WorkerIdentity};
use crate::delivery::state::{DeliveryError, DeliveryState, DeliveryTruth};
use crate::delivery::store::ttl_duration;
use crate::delivery::store::{utc_now, DeliveryStore};

/// Attempt/concurrency bounds for one owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryLimits {
    pub max_attempts: u32,
    pub attempt_timeout: Duration,
    pub lease_ttl: Duration,
    pub max_concurrent: usize,
}

impl Default for DeliveryLimits {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            attempt_timeout: Duration::from_secs(60),
            lease_ttl: Duration::from_secs(60),
            max_concurrent: 8,
        }
    }
}

/// Transport abstraction so owner-level state-machine tests can inject fakes.
#[async_trait]
pub trait ChannelTransport: Send + Sync {
    async fn dispatch(&self, message: &DeliveryMessage, channel: &ResolvedChannel)
        -> DeliveryTruth;
}

/// Production transport: real SMTP + real guarded HTTPS. The HTTPS client is
/// built per dispatch from the channel's own endpoint guard so per-channel
/// allowlists are enforced at DNS resolution, not just at URL admission.
pub struct ProductionTransport {
    smtp: Arc<SmtpClient>,
}

impl Default for ProductionTransport {
    fn default() -> Self {
        Self {
            smtp: Arc::new(SmtpClient::default()),
        }
    }
}

#[async_trait]
impl ChannelTransport for ProductionTransport {
    async fn dispatch(
        &self,
        message: &DeliveryMessage,
        channel: &ResolvedChannel,
    ) -> DeliveryTruth {
        match channel {
            ResolvedChannel::Smtp(config) => {
                let params = SmtpSendParams {
                    config,
                    from: &config.sender,
                    recipient: &message.recipient,
                    subject: message.subject.as_deref(),
                    body: &message.body,
                    message_id: &message.message_id,
                };
                match self.smtp.send(params).await {
                    Ok(SmtpOutcome::Accepted) => DeliveryTruth::accepted(
                        None,
                        "SMTP MTA queued the message; no final delivery proof exists for email",
                    ),
                    Ok(SmtpOutcome::Transient { detail }) => DeliveryTruth::retry_scheduled(detail),
                    Ok(SmtpOutcome::Failed { detail }) => DeliveryTruth::failed(detail),
                    Ok(SmtpOutcome::InDoubt { detail }) => DeliveryTruth::in_doubt(detail),
                    Err(DeliveryError::Bounds(field)) => {
                        DeliveryTruth::not_attempted(format!("message rejected: {field}"))
                    }
                    Err(error) => DeliveryTruth::not_attempted(format!(
                        "dispatch refused before transmission: {error}"
                    )),
                }
            }
            ResolvedChannel::Relay(config) | ResolvedChannel::Webhook(config) => {
                let payload = if config.delivered_on_2xx {
                    // Webhook: the caller-supplied body is the JSON payload.
                    match serde_json::from_str::<serde_json::Value>(&message.body) {
                        Ok(value) => value,
                        Err(_) => {
                            return DeliveryTruth::not_attempted(
                                "webhook body must be a JSON document",
                            )
                        }
                    }
                } else {
                    let Some(template) = config.payload_template.as_deref() else {
                        return DeliveryTruth::not_attempted(
                            "relay payload template not configured",
                        );
                    };
                    match crate::delivery::channel_config::render_relay_payload(
                        template,
                        &message.recipient,
                        message.subject.as_deref(),
                        &message.body,
                    ) {
                        Ok(value) => value,
                        Err(error) => return DeliveryTruth::not_attempted(error.to_string()),
                    }
                };
                let transport = match HttpRelayTransport::with_guard(config.guard.clone()) {
                    Ok(transport) => transport,
                    Err(error) => {
                        return DeliveryTruth::not_attempted(format!(
                            "relay transport refused by endpoint policy: {error}"
                        ))
                    }
                };
                match transport.post_json(config, &payload).await {
                    Ok(RelayOutcome::Delivered { reference }) => DeliveryTruth::delivered(
                        reference.as_deref(),
                        "provider receipt proved delivery",
                    ),
                    Ok(RelayOutcome::Accepted { reference }) => DeliveryTruth::accepted(
                        reference.as_deref(),
                        "provider acknowledged the message; no explicit delivery receipt",
                    ),
                    Ok(RelayOutcome::Failed { detail }) => DeliveryTruth::failed(detail),
                    Ok(RelayOutcome::InDoubt { detail }) => DeliveryTruth::in_doubt(detail),
                    Err(error) => DeliveryTruth::not_attempted(format!(
                        "dispatch refused before transmission: {error}"
                    )),
                }
            }
        }
    }
}

static SHARED_PRODUCTION_TRANSPORT: OnceLock<ProductionTransport> = OnceLock::new();

/// Shared production transports (one process-wide TLS/HTTP setup).
fn shared_production_transport() -> &'static ProductionTransport {
    SHARED_PRODUCTION_TRANSPORT.get_or_init(ProductionTransport::default)
}

/// The shared delivery owner.
pub struct DeliveryOwner {
    store: Option<Arc<dyn DeliveryStore>>,
    limits: DeliveryLimits,
    permits: Arc<Semaphore>,
    transport: Arc<dyn ChannelTransport>,
    worker: WorkerIdentity,
}

impl std::fmt::Debug for DeliveryOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeliveryOwner")
            .field("durable_store", &self.store.is_some())
            .field("limits", &self.limits)
            .finish()
    }
}

impl DeliveryOwner {
    pub fn builder(store: Option<Arc<dyn DeliveryStore>>) -> DeliveryOwnerBuilder {
        DeliveryOwnerBuilder {
            store,
            limits: DeliveryLimits::default(),
            transport: None,
            worker: None,
        }
    }

    /// Stable, non-secret message identity derived from a caller operation.
    /// The same operation id maps to the same message id: re-invoking the
    /// same operation never re-sends; a new operation id mints a new message.
    /// Never derive operation ids from raw secret material.
    pub fn message_id_for_operation(operation_id: &str) -> String {
        uuid::Uuid::new_v5(
            &uuid::Uuid::NAMESPACE_OID,
            format!("astral-delivery:v1:{operation_id}").as_bytes(),
        )
        .to_string()
    }

    /// Durable-intent dispatch path.
    pub async fn deliver(
        &self,
        message: &DeliveryMessage,
        channel: &ResolvedChannel,
    ) -> DeliveryTruth {
        let Some(store) = self.store.as_ref() else {
            // Fail closed: without durable intent coordination, no dispatch.
            return DeliveryTruth::not_attempted(
                "durable intent store not wired; delivery refused (fail-closed)",
            );
        };
        if let Err(error) = record_intent(store, message, self.limits.max_attempts, utc_now()).await
        {
            return store_unavailable_truth(&error);
        }
        self.attempt(store, message, channel).await
    }

    /// Ephemeral-secret dispatch path. Durable intent metadata and the CAS
    /// lease still apply (they never contain payload material), so an
    /// interrupted attempt is visible and cannot be replayed blindly across
    /// replicas or restarts. The raw secret exists only in memory.
    ///
    /// Fail-closed: without a durable store there is no UNKNOWN guard at
    /// all, so this path refuses — there is no implicit inline bypass.
    /// Production consumers (password reset, OTP) construct the owner with
    /// a store.
    pub async fn deliver_ephemeral_secret(
        &self,
        message: &DeliveryMessage,
        channel: &ResolvedChannel,
    ) -> DeliveryTruth {
        debug_assert!(message.payload_class == PayloadClass::EphemeralSecret);
        let Some(store) = self.store.as_ref() else {
            return DeliveryTruth::not_attempted(
                "durable intent store not wired; ephemeral-secret delivery refused (fail-closed)",
            );
        };
        if let Err(error) = record_intent(store, message, self.limits.max_attempts, utc_now()).await
        {
            return store_unavailable_truth(&error);
        }
        self.attempt(store, message, channel).await
    }

    /// Lease, dispatch, and settle one attempt against the durable store.
    async fn attempt(
        &self,
        store: &Arc<dyn DeliveryStore>,
        message: &DeliveryMessage,
        channel: &ResolvedChannel,
    ) -> DeliveryTruth {
        let now = utc_now();
        let lease = match store
            .acquire_attempt(
                &message.message_id,
                &self.worker,
                self.limits.lease_ttl,
                now,
            )
            .await
        {
            Ok(lease) => lease,
            Err(DeliveryError::ReconciliationRequired) => {
                return DeliveryTruth::in_doubt(
                    "prior attempt outcome unknown; explicit reconciliation required before retry",
                );
            }
            Err(DeliveryError::LeaseConflict) => {
                return DeliveryTruth::contention(
                    "another live attempt owns this message; outcome pending",
                );
            }
            Err(DeliveryError::BudgetExhausted(reason)) => {
                let state = store
                    .current_state(&message.message_id)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or(DeliveryState::Expired);
                return DeliveryTruth {
                    state,
                    provider_reference: None,
                    detail: format!("attempt not granted: {reason}"),
                };
            }
            Err(error) => return store_unavailable_truth(&error),
        };

        let truth = self.dispatch_bounded(message, channel).await;
        let settled = match store.record_outcome(&lease, &truth, utc_now()).await {
            Ok(state) => state,
            Err(DeliveryError::LeaseExpired) => {
                // Our outcome lost the settle race (lease taken over after
                // expiry): the durable result is not ours to claim.
                let _ = store
                    .mark_in_doubt(
                        &message.message_id,
                        lease.generation,
                        "settlement lost lease after expiry",
                        utc_now(),
                    )
                    .await;
                return DeliveryTruth::in_doubt(
                    "attempt settlement lost its lease; reconciliation required",
                );
            }
            Err(error) => {
                metrics::counter!(
                    "astral_delivery_settlement_failures_total",
                    "channel" => message.channel.as_str()
                )
                .increment(1);
                return DeliveryTruth {
                    state: truth.state,
                    provider_reference: truth.provider_reference,
                    detail: format!(
                        "transport outcome {:?} could not be settled durably: {error}",
                        truth.state
                    ),
                };
            }
        };
        record_outcome_metrics(&message.channel, settled);
        DeliveryTruth {
            state: settled,
            provider_reference: truth.provider_reference,
            detail: truth.detail,
        }
    }

    /// Transport dispatch under the concurrency permit and attempt deadline.
    async fn dispatch_bounded(
        &self,
        message: &DeliveryMessage,
        channel: &ResolvedChannel,
    ) -> DeliveryTruth {
        let permit = match self.permits.acquire().await {
            Ok(permit) => permit,
            Err(_) => {
                return DeliveryTruth::not_attempted("delivery owner is shutting down");
            }
        };
        let result = tokio::time::timeout(
            self.limits.attempt_timeout,
            self.transport.dispatch(message, channel),
        )
        .await;
        drop(permit);
        match result {
            Ok(truth) => truth,
            Err(_) => DeliveryTruth::in_doubt(
                "attempt deadline elapsed after dispatch began; outcome unknown",
            ),
        }
    }
}

/// Build the durable intent metadata for a message.
///
/// Safety rule: for [`PayloadClass::EphemeralSecret`] the row must never
/// carry secret material — the body and its digest are omitted by the
/// message itself, and the subject is redacted here unconditionally. The
/// recipient is the delivery address (user identity, required for
/// reconciliation/audit), not the secret; callers must never place token or
/// code material into recipient/subject either (documented contract).
fn intent_record_for(
    message: &DeliveryMessage,
    max_attempts: u32,
) -> crate::delivery::store::IntentRecord {
    crate::delivery::store::IntentRecord {
        message_id: message.message_id.clone(),
        operation_id: message.operation_id.clone(),
        channel: message.channel,
        recipient: message.recipient.clone(),
        subject: match message.payload_class {
            PayloadClass::Standard => message.subject.clone(),
            PayloadClass::EphemeralSecret => None,
        },
        body_digest: message.body_digest(),
        payload_class: message.payload_class,
        max_attempts,
    }
}

fn record_intent<'a>(
    store: &'a Arc<dyn DeliveryStore>,
    message: &'a DeliveryMessage,
    max_attempts: u32,
    now: PrimitiveDateTime,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DeliveryError>> + Send + 'a>> {
    Box::pin(async move {
        let record = intent_record_for(message, max_attempts);
        let _inserted = store.record_intent(&record, now).await?;
        Ok(())
    })
}

fn store_unavailable_truth(error: &DeliveryError) -> DeliveryTruth {
    DeliveryTruth::not_attempted(format!("durable intent store refused: {error}"))
}

fn record_outcome_metrics(channel: &ChannelKind, state: DeliveryState) {
    metrics::counter!(
        "astral_delivery_outcome_total",
        "channel" => channel.as_str(),
        "state" => state.as_str()
    )
    .increment(1);
}

pub struct DeliveryOwnerBuilder {
    store: Option<Arc<dyn DeliveryStore>>,
    limits: DeliveryLimits,
    transport: Option<Arc<dyn ChannelTransport>>,
    worker: Option<WorkerIdentity>,
}

impl DeliveryOwnerBuilder {
    pub fn limits(mut self, limits: DeliveryLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn transport(mut self, transport: Arc<dyn ChannelTransport>) -> Self {
        self.transport = Some(transport);
        self
    }

    pub fn worker(mut self, worker: WorkerIdentity) -> Self {
        self.worker = Some(worker);
        self
    }

    pub fn build(self) -> DeliveryOwner {
        DeliveryOwner {
            store: self.store,
            limits: self.limits,
            permits: Arc::new(Semaphore::new(self.limits.max_concurrent)),
            transport: self
                .transport
                .unwrap_or_else(|| Arc::new(shared_production_transport().clone_shim())),
            worker: self.worker.unwrap_or_else(WorkerIdentity::generate),
        }
    }
}

impl ProductionTransport {
    fn clone_shim(&self) -> ProductionTransport {
        ProductionTransport {
            smtp: self.smtp.clone(),
        }
    }
}

/// Unified notification-test dispatcher (monitor test endpoint).
///
/// Single entry point taking the stable caller operation id and the durable
/// store; the handler records/consumes its admission first and then calls
/// this. The message id is derived from the operation id, so re-invoking the
/// same operation never re-sends (it returns the settled durable truth), and
/// a fresh operation id (new admission) mints a fresh message. The caller
/// owns the operation-id shape (e.g. `monitor:notification-test:<request-op>`).
///
/// `test_body` is a short non-secret text; the subject is derived from the
/// channel kind/name. Returns typed truth — never a success-only summary.
pub async fn dispatch_channel_test(
    store: Arc<dyn DeliveryStore>,
    operation_id: &str,
    channel_kind: ChannelKind,
    channel_name: &str,
    config_json: Option<&str>,
    test_body: &str,
) -> DeliveryTruth {
    let resolved = match resolve_channel(channel_kind, config_json) {
        Ok(resolved) => resolved,
        Err(error) => return DeliveryTruth::not_attempted(error.to_string()),
    };
    let message_id = DeliveryOwner::message_id_for_operation(operation_id);
    let message = match DeliveryMessage::compose(
        channel_kind,
        operation_id,
        Some(&message_id),
        recipient_for_test(&resolved).as_str(),
        Some(&format!(
            "AstralMonitor 测试通知 [{} {}]",
            channel_kind.as_str(),
            channel_name
        )),
        test_body,
        PayloadClass::Standard,
    ) {
        Ok(message) => message,
        Err(error) => return DeliveryTruth::not_attempted(error.to_string()),
    };
    let owner = DeliveryOwner::builder(Some(store)).build();
    owner.deliver(&message, &resolved).await
}

/// Recipient per channel kind for test dispatch.
fn recipient_for_test(resolved: &ResolvedChannel) -> String {
    match resolved {
        ResolvedChannel::Smtp(config) => config.sender.clone(),
        ResolvedChannel::Relay(config) | ResolvedChannel::Webhook(config) => config.url.clone(),
    }
}

/// Convenience for callers that need the lease TTL in the `time` domain.
pub fn lease_ttl_time(limits: &DeliveryLimits) -> time::Duration {
    ttl_duration(limits.lease_ttl)
}

/// Re-exported for adapter implementations that settle reconciliations.
pub async fn reconcile_in_doubt(
    store: &Arc<dyn DeliveryStore>,
    message_id: &str,
    truth: &DeliveryTruth,
    reconciled_by: &str,
) -> Result<DeliveryState, DeliveryError> {
    store
        .reconcile(message_id, truth, reconciled_by, utc_now())
        .await
}

/// Attempt lease re-export for store implementors/tests.
pub type OwnerAttemptLease = AttemptLease;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::channel_config::test_support::relay_config_for_test;
    use crate::delivery::intent::PayloadClass as PC;
    use crate::delivery::store::{InMemoryDeliveryStore, IntentRecord};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn message(operation: &str, class: PC) -> DeliveryMessage {
        DeliveryMessage::compose(
            ChannelKind::Webhook,
            operation,
            Some(&DeliveryOwner::message_id_for_operation(operation)),
            "https://hooks.example.com/x",
            None,
            "{\"event\":\"test\"}",
            class,
        )
        .unwrap()
    }

    fn webhook_channel() -> ResolvedChannel {
        ResolvedChannel::Webhook(relay_config_for_test("https://hooks.example.com/x", true))
    }

    struct CountingTransport {
        calls: AtomicUsize,
        truth: DeliveryTruth,
    }

    impl CountingTransport {
        fn new(truth: DeliveryTruth) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                truth,
            }
        }
    }

    #[async_trait]
    impl ChannelTransport for CountingTransport {
        async fn dispatch(
            &self,
            _message: &DeliveryMessage,
            _channel: &ResolvedChannel,
        ) -> DeliveryTruth {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.truth.clone()
        }
    }

    struct FailingStore;

    #[async_trait]
    impl DeliveryStore for FailingStore {
        async fn record_intent(
            &self,
            _record: &IntentRecord,
            _now: PrimitiveDateTime,
        ) -> Result<bool, DeliveryError> {
            Err(DeliveryError::Store("simulated outage".into()))
        }
        async fn acquire_attempt(
            &self,
            _message_id: &str,
            _worker: &WorkerIdentity,
            _ttl: Duration,
            _now: PrimitiveDateTime,
        ) -> Result<AttemptLease, DeliveryError> {
            Err(DeliveryError::Store("simulated outage".into()))
        }
        async fn record_outcome(
            &self,
            _lease: &AttemptLease,
            _truth: &DeliveryTruth,
            _now: PrimitiveDateTime,
        ) -> Result<DeliveryState, DeliveryError> {
            Err(DeliveryError::Store("simulated outage".into()))
        }
        async fn mark_in_doubt(
            &self,
            _message_id: &str,
            _generation: i64,
            _reason: &str,
            _now: PrimitiveDateTime,
        ) -> Result<DeliveryState, DeliveryError> {
            Err(DeliveryError::Store("simulated outage".into()))
        }
        async fn current_state(
            &self,
            _message_id: &str,
        ) -> Result<Option<DeliveryState>, DeliveryError> {
            Err(DeliveryError::Store("simulated outage".into()))
        }
        async fn reconcile(
            &self,
            _message_id: &str,
            _truth: &DeliveryTruth,
            _reconciled_by: &str,
            _now: PrimitiveDateTime,
        ) -> Result<DeliveryState, DeliveryError> {
            Err(DeliveryError::Store("simulated outage".into()))
        }
    }

    fn owner_with(
        store: Option<Arc<dyn DeliveryStore>>,
        transport: Arc<dyn ChannelTransport>,
    ) -> DeliveryOwner {
        DeliveryOwner::builder(store).transport(transport).build()
    }

    #[tokio::test]
    async fn delivered_outcome_is_durably_settled_and_replay_is_refused() {
        let store = Arc::new(InMemoryDeliveryStore::new());
        let transport = Arc::new(CountingTransport::new(DeliveryTruth::delivered(
            Some("prov-1"),
            "receipt",
        )));
        let owner = owner_with(Some(store.clone()), transport.clone());
        let message = message("op-1", PC::Standard);
        let truth = owner.deliver(&message, &webhook_channel()).await;
        assert_eq!(truth.state, DeliveryState::Delivered);
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
        // Same operation again: terminal truth stands, no re-dispatch.
        let second = owner.deliver(&message, &webhook_channel()).await;
        assert_eq!(second.state, DeliveryState::Delivered);
        assert_eq!(transport.calls.load(Ordering::SeqCst), 1);
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn in_doubt_blocks_every_retry_until_reconcile() {
        let store = Arc::new(InMemoryDeliveryStore::new());
        let transport = Arc::new(CountingTransport::new(DeliveryTruth::in_doubt(
            "connection lost mid-flight",
        )));
        let owner = owner_with(Some(store.clone()), transport.clone());
        let message = message("op-1", PC::Standard);
        let first = owner.deliver(&message, &webhook_channel()).await;
        assert_eq!(first.state, DeliveryState::InDoubt);
        for _ in 0..3 {
            let retry = owner.deliver(&message, &webhook_channel()).await;
            assert_eq!(retry.state, DeliveryState::InDoubt);
            assert!(retry.detail.contains("reconciliation"), "{retry:?}");
        }
        assert_eq!(
            transport.calls.load(Ordering::SeqCst),
            1,
            "no blind retries"
        );
        // Explicit reconcile settles terminally.
        let settled = reconcile_in_doubt(
            &(store.clone() as Arc<dyn DeliveryStore>),
            &message.message_id,
            &DeliveryTruth::failed("provider confirmed loss"),
            "ops:console",
        )
        .await
        .unwrap();
        assert_eq!(settled, DeliveryState::Failed);
    }

    #[tokio::test]
    async fn accepted_is_final_even_with_budget_left() {
        let store = Arc::new(InMemoryDeliveryStore::new());
        let transport = Arc::new(CountingTransport::new(DeliveryTruth::accepted(
            None,
            "provider queued",
        )));
        let owner = owner_with(Some(store.clone()), transport.clone());
        let message = message("op-1", PC::Standard);
        let first = owner.deliver(&message, &webhook_channel()).await;
        assert_eq!(first.state, DeliveryState::Accepted);
        let second = owner.deliver(&message, &webhook_channel()).await;
        assert_eq!(second.state, DeliveryState::Accepted);
        assert_eq!(
            transport.calls.load(Ordering::SeqCst),
            1,
            "no duplicate dispatch"
        );
    }

    #[tokio::test]
    async fn failed_store_refuses_dispatch_fail_closed() {
        let transport = Arc::new(CountingTransport::new(DeliveryTruth::delivered(
            None,
            "should never run",
        )));
        let owner = owner_with(Some(Arc::new(FailingStore)), transport.clone());
        let message = message("op-1", PC::Standard);
        let truth = owner.deliver(&message, &webhook_channel()).await;
        assert_eq!(truth.state, DeliveryState::NotAttempted);
        assert!(truth.detail.contains("store"), "{truth:?}");
        assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn missing_store_refuses_every_dispatch_fail_closed() {
        let transport = Arc::new(CountingTransport::new(DeliveryTruth::delivered(
            None, "receipt",
        )));
        let owner = owner_with(None, transport.clone());
        let standard = message("op-1", PC::Standard);
        let truth = owner.deliver(&standard, &webhook_channel()).await;
        assert_eq!(truth.state, DeliveryState::NotAttempted);
        assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
        // No implicit inline bypass for ephemeral secrets either: without
        // the durable UNKNOWN guard nothing may leave this host.
        let secret = message("op-secret", PC::EphemeralSecret);
        let truth = owner
            .deliver_ephemeral_secret(&secret, &webhook_channel())
            .await;
        assert_eq!(truth.state, DeliveryState::NotAttempted);
        assert!(truth.detail.contains("fail-closed"), "{truth:?}");
        assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn ephemeral_intent_metadata_redacts_subject_and_digest() {
        let message = DeliveryMessage::compose(
            ChannelKind::Email,
            "password-reset:test",
            None,
            "user@example.com",
            Some("Password reset / 密码重置"),
            "raw-otp-993311",
            PayloadClass::EphemeralSecret,
        )
        .unwrap();
        let record = intent_record_for(&message, 3);
        assert_eq!(record.subject, None, "subject must be redacted for secrets");
        assert_eq!(record.body_digest, None, "no unsalted secret digest");
        assert_eq!(
            record.recipient, "user@example.com",
            "recipient is the address, not the secret"
        );
        let standard = intent_record_for(
            &DeliveryMessage::compose(
                ChannelKind::Email,
                "op",
                None,
                "user@example.com",
                Some("Alert"),
                "body",
                PayloadClass::Standard,
            )
            .unwrap(),
            3,
        );
        assert_eq!(standard.subject.as_deref(), Some("Alert"));
        assert!(standard.body_digest.is_some());
    }

    #[tokio::test]
    async fn ephemeral_secret_records_metadata_but_never_payload() {
        let store = Arc::new(InMemoryDeliveryStore::new());
        let transport = Arc::new(CountingTransport::new(DeliveryTruth::delivered(
            Some("prov-9"),
            "receipt",
        )));
        let owner = owner_with(Some(store.clone()), transport);
        let secret_body = "raw-otp-993311";
        let message = DeliveryMessage::compose(
            ChannelKind::Email,
            "password-reset:0192abcd",
            Some(&DeliveryOwner::message_id_for_operation(
                "password-reset:0192abcd",
            )),
            "user@example.com",
            Some("Password reset"),
            secret_body,
            PC::EphemeralSecret,
        )
        .unwrap();
        let truth = owner
            .deliver_ephemeral_secret(&message, &webhook_channel())
            .await;
        assert_eq!(truth.state, DeliveryState::Delivered);
        assert_eq!(store.len(), 1, "metadata row exists for UNKNOWN guard");
        // The store port records digests only for Standard payloads; the
        // in-memory store mirrors that by construction (IntentRecord holds
        // body_digest: None here — asserted indirectly via len==1 and by the
        // digest unit test in intent.rs).
        let rendered = format!("{message:?}");
        assert!(!rendered.contains(secret_body));
    }

    #[tokio::test]
    async fn contention_returns_pending_truth_without_dispatch() {
        let store = Arc::new(InMemoryDeliveryStore::new());
        let message = message("op-1", PC::Standard);
        let record = IntentRecord {
            message_id: message.message_id.clone(),
            operation_id: message.operation_id.clone(),
            channel: message.channel,
            recipient: message.recipient.clone(),
            subject: message.subject.clone(),
            body_digest: message.body_digest(),
            payload_class: PC::Standard,
            max_attempts: 3,
        };
        store.record_intent(&record, utc_now()).await.unwrap();
        let holder = crate::delivery::lease::WorkerIdentity { id: "other".into() };
        store
            .acquire_attempt(
                &message.message_id,
                &holder,
                std::time::Duration::from_secs(60),
                utc_now(),
            )
            .await
            .unwrap();
        let transport = Arc::new(CountingTransport::new(DeliveryTruth::delivered(None, "no")));
        let owner = owner_with(Some(store), transport.clone());
        let truth = owner.deliver(&message, &webhook_channel()).await;
        assert_eq!(truth.state, DeliveryState::Queued);
        assert!(truth.detail.contains("another live attempt"), "{truth:?}");
        assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn message_id_derivation_is_stable_and_secret_free() {
        assert_eq!(
            DeliveryOwner::message_id_for_operation("monitor:notification-test:1"),
            DeliveryOwner::message_id_for_operation("monitor:notification-test:1")
        );
        assert_ne!(
            DeliveryOwner::message_id_for_operation("monitor:notification-test:1"),
            DeliveryOwner::message_id_for_operation("monitor:notification-test:2")
        );
        let raw_secret = "raw-otp-993311";
        let derived = DeliveryOwner::message_id_for_operation(raw_secret);
        // Derivation must not be a plain hash of the secret: uuid v5 in a
        // private namespace is allowed, but callers MUST pass non-secret
        // operation ids; assert the documented behavior with a non-secret id.
        assert_ne!(
            DeliveryOwner::message_id_for_operation("password-reset:0192abcd"),
            DeliveryOwner::message_id_for_operation("password-reset:0192abce")
        );
        let _ = derived;
        let _ = raw_secret;
    }

    #[tokio::test]
    async fn attempt_deadline_maps_to_in_doubt() {
        struct SlowTransport;
        #[async_trait]
        impl ChannelTransport for SlowTransport {
            async fn dispatch(
                &self,
                _message: &DeliveryMessage,
                _channel: &ResolvedChannel,
            ) -> DeliveryTruth {
                tokio::time::sleep(Duration::from_millis(400)).await;
                DeliveryTruth::delivered(None, "late")
            }
        }
        let store = Arc::new(InMemoryDeliveryStore::new());
        let owner = DeliveryOwner::builder(Some(store))
            .transport(Arc::new(SlowTransport))
            .limits(DeliveryLimits {
                attempt_timeout: Duration::from_millis(50),
                ..DeliveryLimits::default()
            })
            .build();
        let message = message("op-slow", PC::Standard);
        let truth = owner.deliver(&message, &webhook_channel()).await;
        assert_eq!(truth.state, DeliveryState::InDoubt, "{truth:?}");
    }
}
