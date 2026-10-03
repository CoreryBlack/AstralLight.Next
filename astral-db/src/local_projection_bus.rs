//! In-process commit-proven projection delta dispatch bus (single-node path).
//!
//! # Contract
//!
//! - **Commit-only caller**: [`dispatch_committed_projection_delta`] must be
//!   invoked by the source wrapper ONLY after the source transaction carrying
//!   the durable `authorization_delta_event` row has COMMITTED. Admission to
//!   this bus is a scheduling hint, never business completion, never a durable
//!   proof: the durable row remains the single source of truth and the DB-poll
//!   recovery path keeps converging regardless of what happens here.
//! - **Bounded admission**: the bus is a bounded `tokio::sync::mpsc` channel
//!   plus bookkeeping under one mutex. Every dispatch is a synchronous
//!   `try_send`-shaped admission that returns immediately:
//!   - `Ok(())` — envelope queued (or a duplicate of an already-queued event;
//!     admission dedupes on the stable event identity),
//!   - `Err([LocalProjectionDispatchError])` — `NotInstalled` / `Overflow` /
//!     `Closed` / `InvalidPayload`. On `NotInstalled` / `Overflow` / `Closed`
//!     the hub (when installed) is marked channel-suspect so the memory read
//!     face fail-closes while the durable pending delta stays queued for the
//!     DB-poll recovery path. The caller never blocks and never re-reads the
//!     database to compensate: durable pending rows stay durable pending.
//! - **FIFO per exact tenant aggregate**: dispatch bookkeeping serializes
//!   admission under one mutex and `try_send` happens while that lock is
//!   held, so the channel order equals the dispatch call order; events of one
//!   exact `(tenant, card, aggregate_type, aggregate_id)` therefore queue in
//!   dispatch order. Deeper chain ordering (per-grant target versions) is
//!   enforced by the durable sibling-ordering gate at claim time — the bus
//!   never reorders and never authorizes.
//! - **Bounds**: channel capacity (entries), per-envelope payload cap,
//!   cumulative queued payload cap, and a per-aggregate queued-entry cap keep
//!   every dimension bounded; no unbounded queue exists on this path.
//! - **One owner / start once**: [`install_local_projection_bus`] installs the
//!   process-global bus exactly once; the receiver can be taken exactly once
//!   by the projector worker ([`LocalProjectionBus::take_receiver`]). Closing
//!   is idempotent; the receiver drains remaining envelopes after close.
//!
//! The bus carries the strict durable source facts only — the same
//! [`DeltaEventAppendRequest`] DTO the append path validated. It never
//! fabricates payloads, never reloads rows by id, and never substitutes for
//! the durable claim.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tokio::sync::mpsc;

use crate::grant_repository::DeltaEventAppendRequest;

// ─────────────────────────────────────────────────────────────────────────────
// Bounds
// ─────────────────────────────────────────────────────────────────────────────

/// Default channel capacity (envelopes). Bounded, never grown at runtime.
pub const LOCAL_PROJECTION_BUS_DEFAULT_CAPACITY: usize = 1024;

/// Hard upper bound for a caller-provided capacity; startup fails fast past it
/// instead of silently clamping.
pub const LOCAL_PROJECTION_BUS_MAX_CAPACITY: usize = 65_536;

/// Per-envelope payload cap: the request payload already passed the durable
/// append validation, so this bound only stops oversized foreign payloads from
/// monopolizing the bus. 512 KiB covers every documented delta shape.
pub const LOCAL_PROJECTION_BUS_MAX_PAYLOAD_BYTES: usize = 512 * 1024;

/// Cumulative queued payload cap across the whole bus (64 MiB).
pub const LOCAL_PROJECTION_BUS_MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;

/// Per-exact-aggregate queued envelope cap. A stalled aggregate can occupy at
/// most this many slots; the rest of the bus stays usable for other scopes.
pub const LOCAL_PROJECTION_BUS_MAX_QUEUED_PER_AGGREGATE: usize = 64;

// ─────────────────────────────────────────────────────────────────────────────
// Envelope / delivery DTOs
// ─────────────────────────────────────────────────────────────────────────────

/// Exact tenant aggregate key for FIFO bookkeeping. `card_id` participates so
/// card-scoped and unscoped chains never share a slot accounting bucket.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommitDeltaAggregateKey {
    pub tenant_id: i64,
    pub card_id: Option<i64>,
    pub aggregate_type: String,
    pub aggregate_id: i64,
}

impl CommitDeltaAggregateKey {
    pub fn of_request(request: &DeltaEventAppendRequest) -> Self {
        Self {
            tenant_id: request.tenant_id,
            card_id: request.card_id,
            aggregate_type: request.aggregate_type.clone(),
            aggregate_id: request.aggregate_id,
        }
    }
}

/// One commit-proven delta riding the in-process bus.
///
/// Carries the strict durable source facts (the very [`DeltaEventAppendRequest`]
/// whose source transaction committed). Admission to the bus is NOT business
/// completion: the durable delta row stays authoritative until the projector
/// publishes it through the normal durable path.
#[derive(Debug, Clone)]
pub struct CommitDeltaEnvelope {
    pub request: DeltaEventAppendRequest,
    /// Process-unique, monotonically increasing admission sequence.
    pub dispatch_sequence: u64,
    /// Admission-time payload size in bytes (bounded, see module bounds).
    pub payload_bytes: usize,
}

impl CommitDeltaEnvelope {
    pub fn aggregate_key(&self) -> CommitDeltaAggregateKey {
        CommitDeltaAggregateKey::of_request(&self.request)
    }

    /// Stable event identity used for duplicate bounding and tracing.
    pub fn event_id(&self) -> &str {
        &self.request.event_id
    }
}

/// Receive-side wrapper handed to the single worker owner. Adds receive-side
/// sequencing only; the payload facts are unchanged.
#[derive(Debug, Clone)]
pub struct CommitDeltaDelivery {
    pub envelope: CommitDeltaEnvelope,
    /// Monotonic receive sequence (worker-side observation order).
    pub receive_sequence: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────────

/// Typed dispatch admission failure. Every variant is terminal for THIS
/// admission only: the durable pending delta row is untouched and stays
/// queued for the DB-poll recovery path. `NotInstalled` / `Overflow` /
/// `Closed` additionally mark the hub channel suspect (when installed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalProjectionDispatchError {
    /// No bus installed in this process (e.g. Rabbit-mode deployment). The
    /// caller must not retry synchronously; durable recovery owns convergence.
    NotInstalled,
    /// Bus full or a bound (capacity / total bytes / per-aggregate) was hit.
    Overflow { reason: &'static str },
    /// Bus closed for new admissions (shutdown in progress).
    Closed,
    /// The request cannot ride the bus at all (contract violation of the
    /// commit-only caller, e.g. unknown stable event identity). Fail closed.
    InvalidPayload { reason: String },
}

impl LocalProjectionDispatchError {
    fn hub_suspect_reason(&self) -> Option<String> {
        match self {
            Self::NotInstalled => Some("code=local_projection_bus.not_installed".to_owned()),
            Self::Overflow { reason } => Some(format!(
                "code=local_projection_bus.overflow;reason={reason}"
            )),
            Self::Closed => Some("code=local_projection_bus.closed".to_owned()),
            Self::InvalidPayload { .. } => None,
        }
    }
}

impl fmt::Display for LocalProjectionDispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInstalled => write!(
                formatter,
                "code=local_projection_bus.not_installed;expected=installed_local_projection_bus"
            ),
            Self::Overflow { reason } => {
                write!(
                    formatter,
                    "code=local_projection_bus.overflow;reason={reason}"
                )
            }
            Self::Closed => {
                write!(
                    formatter,
                    "code=local_projection_bus.closed;expected=open_bus"
                )
            }
            Self::InvalidPayload { reason } => {
                write!(
                    formatter,
                    "code=local_projection_bus.invalid_payload;reason={reason}"
                )
            }
        }
    }
}

impl std::error::Error for LocalProjectionDispatchError {}

/// Install-time failure. `AlreadyInstalled` carries the diagnostic only; the
/// running bus is untouched (start-once discipline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalProjectionInstallError {
    AlreadyInstalled,
    InvalidConfig { reason: String },
}

impl fmt::Display for LocalProjectionInstallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyInstalled => write!(
                formatter,
                "code=local_projection_bus.already_installed;expected=fresh_install"
            ),
            Self::InvalidConfig { reason } => {
                write!(
                    formatter,
                    "code=local_projection_bus.invalid_config;reason={reason}"
                )
            }
        }
    }
}

impl std::error::Error for LocalProjectionInstallError {}

/// Receiver takeover failure: exactly one owner is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalProjectionOwnerTaken;

impl fmt::Display for LocalProjectionOwnerTaken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "code=local_projection_bus.owner_taken;expected=single_worker_owner"
        )
    }
}

impl std::error::Error for LocalProjectionOwnerTaken {}

// ─────────────────────────────────────────────────────────────────────────────
// Bus
// ─────────────────────────────────────────────────────────────────────────────

/// Validated bus bounds. Construct with [`LocalProjectionBusConfig::default`]
/// or [`LocalProjectionBusConfig::validated`]; the free function installer
/// rejects out-of-range values at startup instead of clamping silently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalProjectionBusConfig {
    pub capacity: usize,
    pub max_payload_bytes: usize,
    pub max_total_bytes: usize,
    pub max_queued_per_aggregate: usize,
}

impl LocalProjectionBusConfig {
    pub fn validated(self) -> Result<Self, LocalProjectionInstallError> {
        if self.capacity == 0 || self.capacity > LOCAL_PROJECTION_BUS_MAX_CAPACITY {
            return Err(LocalProjectionInstallError::InvalidConfig {
                reason: format!(
                    "code=local_projection_bus.capacity_out_of_bounds;value={};max={LOCAL_PROJECTION_BUS_MAX_CAPACITY}",
                    self.capacity
                ),
            });
        }
        if self.max_payload_bytes == 0 {
            return Err(LocalProjectionInstallError::InvalidConfig {
                reason: "code=local_projection_bus.zero_payload_bound".to_owned(),
            });
        }
        if self.max_total_bytes < self.max_payload_bytes {
            return Err(LocalProjectionInstallError::InvalidConfig {
                reason: "code=local_projection_bus.total_bytes_below_payload_bound".to_owned(),
            });
        }
        if self.max_queued_per_aggregate == 0 {
            return Err(LocalProjectionInstallError::InvalidConfig {
                reason: "code=local_projection_bus.zero_per_aggregate_bound".to_owned(),
            });
        }
        Ok(self)
    }
}

impl Default for LocalProjectionBusConfig {
    fn default() -> Self {
        Self {
            capacity: LOCAL_PROJECTION_BUS_DEFAULT_CAPACITY,
            max_payload_bytes: LOCAL_PROJECTION_BUS_MAX_PAYLOAD_BYTES,
            max_total_bytes: LOCAL_PROJECTION_BUS_MAX_TOTAL_BYTES,
            max_queued_per_aggregate: LOCAL_PROJECTION_BUS_MAX_QUEUED_PER_AGGREGATE,
        }
    }
}

#[derive(Debug, Default)]
struct BusBookkeeping {
    /// Queued event ids per exact aggregate (duplicate + per-aggregate bound).
    queued_event_ids: HashMap<CommitDeltaAggregateKey, HashSet<String>>,
    /// Cumulative queued payload bytes.
    queued_bytes: usize,
    /// Cumulative queued envelope count (mirrors the channel occupancy as
    /// observed from admission; decremented on [`LocalProjectionBus::acknowledge`]).
    queued_count: usize,
}

struct BusState {
    /// `None` after close: dropping the last sender closes the channel and
    /// lets the receiver drain.
    sender: Mutex<Option<mpsc::Sender<CommitDeltaEnvelope>>>,
    config: LocalProjectionBusConfig,
    bookkeeping: Mutex<BusBookkeeping>,
    closed: AtomicBool,
    close_reason: Mutex<Option<String>>,
}

/// Process-global bus instance. Clone-cheap (`Arc` inside).
#[derive(Clone)]
pub struct LocalProjectionBus(Arc<BusState>);

impl fmt::Debug for LocalProjectionBus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (queued_bytes, queued_count) = self
            .0
            .bookkeeping
            .lock()
            .map(|state| (state.queued_bytes, state.queued_count))
            .unwrap_or((0, 0));
        formatter
            .debug_struct("LocalProjectionBus")
            .field("capacity", &self.0.config.capacity)
            .field("closed", &self.0.closed.load(Ordering::Acquire))
            .field("queued_count", &queued_count)
            .field("queued_bytes", &queued_bytes)
            .finish()
    }
}

impl LocalProjectionBus {
    fn new(config: LocalProjectionBusConfig) -> (Self, mpsc::Receiver<CommitDeltaEnvelope>) {
        let (sender, receiver) = mpsc::channel(config.capacity);
        (
            Self(Arc::new(BusState {
                sender: Mutex::new(Some(sender)),
                config,
                bookkeeping: Mutex::new(BusBookkeeping::default()),
                closed: AtomicBool::new(false),
                close_reason: Mutex::new(None),
            })),
            receiver,
        )
    }

    /// Test-only constructor bypassing the process-global install so pure
    /// tests can exercise bounds/FIFO/close on an isolated instance.
    #[cfg(test)]
    fn new_for_tests(
        config: LocalProjectionBusConfig,
    ) -> (Self, mpsc::Receiver<CommitDeltaEnvelope>) {
        Self::new(config)
    }

    /// Synchronous bounded admission. See the module contract for semantics.
    pub fn dispatch(
        &self,
        request: DeltaEventAppendRequest,
    ) -> Result<(), LocalProjectionDispatchError> {
        if self.0.closed.load(Ordering::Acquire) {
            let error = LocalProjectionDispatchError::Closed;
            mark_hub_suspect_for(&error);
            return Err(error);
        }
        // Minimal bus-side contract checks; the durable append validation
        // remains the authoritative gate. These only stop structurally
        // unusable envelopes from occupying bounded slots.
        if request.event_id.trim().is_empty() || request.operation_id.trim().is_empty() {
            return Err(LocalProjectionDispatchError::InvalidPayload {
                reason: "code=local_projection_bus.empty_stable_identity".to_owned(),
            });
        }
        if request.tenant_id <= 0 || request.aggregate_id <= 0 {
            return Err(LocalProjectionDispatchError::InvalidPayload {
                reason: "code=local_projection_bus.non_positive_identity".to_owned(),
            });
        }
        let payload_bytes = payload_bytes_of(&request);
        if payload_bytes > self.0.config.max_payload_bytes {
            return Err(LocalProjectionDispatchError::InvalidPayload {
                reason: format!(
                    "code=local_projection_bus.payload_exceeds_bound;bytes={payload_bytes};max={}",
                    self.0.config.max_payload_bytes
                ),
            });
        }

        let key = CommitDeltaAggregateKey::of_request(&request);
        let event_id_owned = request.event_id.clone();
        // Single admission critical section: bookkeeping checks + try_send
        // stay under one mutex hold so channel order equals admission order
        // (per-exact-aggregate FIFO). The per-aggregate set borrow is scoped
        // to its checks only; the mutex guard itself stays alive throughout.
        let mut bookkeeping =
            self.0
                .bookkeeping
                .lock()
                .map_err(|_| LocalProjectionDispatchError::Overflow {
                    reason: "bookkeeping_poisoned",
                })?;

        let per_aggregate_len = match bookkeeping.queued_event_ids.get(&key) {
            Some(queued) => {
                if queued.contains(&event_id_owned) {
                    // Duplicate of an already-queued event: idempotent
                    // admission no-op. The durable row plus the earlier
                    // admission cover it.
                    return Ok(());
                }
                queued.len()
            }
            None => 0,
        };
        if per_aggregate_len >= self.0.config.max_queued_per_aggregate {
            let error = LocalProjectionDispatchError::Overflow {
                reason: "per_aggregate_cap",
            };
            mark_hub_suspect_for(&error);
            return Err(error);
        }
        if bookkeeping.queued_count >= self.0.config.capacity {
            let error = LocalProjectionDispatchError::Overflow {
                reason: "channel_capacity",
            };
            mark_hub_suspect_for(&error);
            return Err(error);
        }
        if bookkeeping.queued_bytes + payload_bytes > self.0.config.max_total_bytes {
            let error = LocalProjectionDispatchError::Overflow {
                reason: "total_bytes_cap",
            };
            mark_hub_suspect_for(&error);
            return Err(error);
        }

        let dispatch_sequence = NEXT_DISPATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let envelope = CommitDeltaEnvelope {
            request,
            dispatch_sequence,
            payload_bytes,
        };
        let sender = self
            .0
            .sender
            .lock()
            .map_err(|_| LocalProjectionDispatchError::Overflow {
                reason: "sender_poisoned",
            })?;
        let Some(sender) = sender.as_ref() else {
            let error = LocalProjectionDispatchError::Closed;
            mark_hub_suspect_for(&error);
            return Err(error);
        };
        match sender.try_send(envelope) {
            Ok(()) => {
                bookkeeping
                    .queued_event_ids
                    .entry(key)
                    .or_default()
                    .insert(event_id_owned);
                bookkeeping.queued_count += 1;
                bookkeeping.queued_bytes += payload_bytes;
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                let error = LocalProjectionDispatchError::Overflow {
                    reason: "channel_full",
                };
                mark_hub_suspect_for(&error);
                Err(error)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.0.closed.store(true, Ordering::Release);
                let error = LocalProjectionDispatchError::Closed;
                mark_hub_suspect_for(&error);
                Err(error)
            }
        }
    }
    /// Acknowledge one envelope as consumed by the worker, releasing its
    /// duplicate-guard slot and byte/count budget. The single owner calls this
    /// after `recv`; an unacknowledged crash leaves the slots until restart,
    /// which is acceptable because the bus dies with the process anyway.
    pub fn acknowledge(&self, envelope: &CommitDeltaEnvelope) {
        let key = envelope.aggregate_key();
        if let Ok(mut bookkeeping) = self.0.bookkeeping.lock() {
            if let Some(queued) = bookkeeping.queued_event_ids.get_mut(&key) {
                queued.remove(envelope.event_id());
                if queued.is_empty() {
                    bookkeeping.queued_event_ids.remove(&key);
                }
            }
            bookkeeping.queued_count = bookkeeping.queued_count.saturating_sub(1);
            bookkeeping.queued_bytes = bookkeeping
                .queued_bytes
                .saturating_sub(envelope.payload_bytes);
        }
    }

    /// Close the bus for new admissions; idempotent. The receiver keeps
    /// draining already-admitted envelopes (mpsc close semantics).
    pub fn close(&self, reason: &str) {
        let mut close_reason = match self.0.close_reason.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        if close_reason.is_some() {
            return;
        }
        *close_reason = Some(reason.to_owned());
        drop(close_reason);
        self.0.closed.store(true, Ordering::Release);
        // Drop the sender: the channel closes and the single receiver drains
        // already-admitted envelopes before observing `None`.
        if let Ok(mut sender_cell) = self.0.sender.lock() {
            *sender_cell = None;
        }
    }

    pub fn is_closed(&self) -> bool {
        self.0.closed.load(Ordering::Acquire)
    }

    pub fn config(&self) -> &LocalProjectionBusConfig {
        &self.0.config
    }

    /// Diagnostics snapshot (worker health reporting only, never a proof).
    pub fn occupancy(&self) -> (usize, usize) {
        self.0
            .bookkeeping
            .lock()
            .map(|state| (state.queued_count, state.queued_bytes))
            .unwrap_or((0, 0))
    }
}

static NEXT_DISPATCH_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn payload_bytes_of(request: &DeltaEventAppendRequest) -> usize {
    request.delta_json.len()
        + request.event_id.len()
        + request.operation_id.len()
        + request.aggregate_type.len()
        + request.compiler_version.len()
        + request.semantic_hash_hex.len()
        + request.dependency_hash_hex.len()
        + request.before_image_json.as_deref().map_or(0, str::len)
}

fn mark_hub_suspect_for(error: &LocalProjectionDispatchError) {
    let Some(reason) = error.hub_suspect_reason() else {
        return;
    };
    if let Some(hub) = crate::memory_projection_hub::memory_projection_hub() {
        hub.mark_channel_suspect(reason);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Process-global installation
// ─────────────────────────────────────────────────────────────────────────────

static GLOBAL_LOCAL_PROJECTION_BUS: OnceLock<Arc<BusState>> = OnceLock::new();

/// Install the process-global bus (start once). The receiver is retained for
/// the single worker owner; the returned handle exposes dispatch/close.
pub fn install_local_projection_bus(
    config: LocalProjectionBusConfig,
) -> Result<LocalProjectionBus, LocalProjectionInstallError> {
    let config = config.validated()?;
    let (bus, receiver) = LocalProjectionBus::new(config);
    let state = Arc::clone(&bus.0);
    if GLOBAL_LOCAL_PROJECTION_BUS.set(state).is_err() {
        return Err(LocalProjectionInstallError::AlreadyInstalled);
    }
    GLOBAL_LOCAL_PROJECTION_RECEIVER
        .lock()
        .expect("receiver cell not poisoned at install")
        .replace(receiver);
    Ok(bus)
}

/// Single-owner receiver cell; `take` moves the receiver out exactly once.
static GLOBAL_LOCAL_PROJECTION_RECEIVER: Mutex<Option<mpsc::Receiver<CommitDeltaEnvelope>>> =
    Mutex::new(None);

/// Process-global handle; `None` before install (Rabbit mode keeps the DB
/// poll path and never touches this bus).
pub fn local_projection_bus() -> Option<LocalProjectionBus> {
    GLOBAL_LOCAL_PROJECTION_BUS
        .get()
        .map(|state| LocalProjectionBus(Arc::clone(state)))
}

pub fn local_projection_bus_installed() -> bool {
    GLOBAL_LOCAL_PROJECTION_BUS.get().is_some()
}

/// Frozen source-wrapper admission entry (commit-only caller contract):
///
/// `dispatch_committed_projection_delta(request) -> Result<(), LocalProjectionDispatchError>`
///
/// - by-value owned request (caller keeps its own clone if needed),
/// - synchronous bounded `try_send` admission; returns immediately,
/// - admission is NOT business completion; the durable pending delta row
///   stays authoritative until the projector publishes it durably,
/// - `NotInstalled` / `Overflow` / `Closed` mark the hub channel suspect and
///   return the typed error; the caller must not block, retry synchronously,
///   or re-read the database to compensate.
pub fn dispatch_committed_projection_delta(
    request: DeltaEventAppendRequest,
) -> Result<(), LocalProjectionDispatchError> {
    match local_projection_bus() {
        Some(bus) => bus.dispatch(request),
        None => {
            let error = LocalProjectionDispatchError::NotInstalled;
            mark_hub_suspect_for(&error);
            Err(error)
        }
    }
}

/// Take the single worker receiver from the global installation. Exactly one
/// caller (the in-process projector worker) may ever receive it; later calls
/// fail with [`LocalProjectionOwnerTaken`].
pub fn take_global_local_projection_receiver(
) -> Result<mpsc::Receiver<CommitDeltaEnvelope>, LocalProjectionOwnerTaken> {
    let mut cell = GLOBAL_LOCAL_PROJECTION_RECEIVER
        .lock()
        .map_err(|_| LocalProjectionOwnerTaken)?;
    cell.take().ok_or(LocalProjectionOwnerTaken)
}

/// Close the global bus (idempotent; no-op when not installed).
pub fn close_local_projection_bus(reason: &str) {
    if let Some(bus) = local_projection_bus() {
        bus.close(reason);
    }
}

#[cfg(test)]
mod tests;
