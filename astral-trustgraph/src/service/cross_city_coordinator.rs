//! Cross-city authorization coordinator (P4 runtime slice, DEFAULT-OFF).
//!
//! This module is the production coordinator of the default-off cross-city
//! subsystem: a LIBRARY service (no HTTP route, no spawned worker, no runtime
//! loop of its own) that wires the existing durable primitives into one
//! guarded flow:
//!
//! 1. **Vote admission** — [`CrossCityCoordinator::admit_vote`] first runs the
//!    pure astral-common authentication boundary
//!    (`authenticate_zero_decision_evidence`) against the explicit fixed node
//!    key registry, then durably reserves the replay nonce and inserts the
//!    verified vote in ONE short source transaction
//!    (`record_cross_city_verified_vote_in_tx`). A raw/unsigned evidence can
//!    never reach the durable writer: the repository consumes only the opaque
//!    [`CrossCityAuthenticatedEvidence`] capability, and the durable
//!    reservation row is the storage-level witness of that verification.
//! 2. **Agreement sealing** — [`CrossCityCoordinator::seal_agreement`]
//!    re-derives the agreement certificate from the stored, reservation-proven
//!    votes and performs the guarded `AGREED` transition (evidence-derived
//!    digest only; the caller-supplied digest is never the source of truth).
//! 3. **Commit receipts** — [`CrossCityCoordinator::record_commit_receipt`]
//!    records a signed, durable source-apply receipt for one city node, only
//!    when the signer city is explicitly registered authoritative for the
//!    operation's scope and every version pin matches the locked parent.
//! 4. **Activation mint** — [`CrossCityCoordinator::activate_operation`]
//!    mints the operation activation proof ONLY from the durable two-city
//!    commit receipts (`mint_cross_city_operation_activation_in_tx`): without
//!    both cities' durable source-apply evidence the operation stays
//!    `ACTIVATING`/`IN_DOUBT` — no confirm message, no cache entry, and no
//!    boolean can substitute for the missing durable receipt.
//! 5. **Gate activation** — [`CrossCityCoordinator::activate_operation_gates`]
//!    mints the gate activation proof from the operation's DURABLE activation
//!    record (content hash = the derived commit digest) and runs the guarded
//!    `ACTIVE` gate transition.
//! 6. **Unknown outcomes** —
//!    [`CrossCityCoordinator::mark_unknown_outcome_in_doubt`] collapses any
//!    genuinely unknown outcome into `IN_DOUBT` (never a guess, never a
//!    discard, never a silent retry): the closed state machine keeps the
//!    fail-closed recovery edges.
//! 7. **Transport** — outbound messages go through the durable outbox first
//!    ([`CrossCityCoordinator::enqueue_phase_message`]); the typed
//!    [`CrossCityMessageTransport`] trait is injected (MQ adapter is a main
//!    wiring decision) and receives EXACTLY ONE post-commit best-effort send
//!    per enqueue: the outbox retry budget remains the only durability
//!    mechanism, and a transport failure can never roll a decision back or
//!    forward.
//!
//! # Default-off and configuration refusal
//!
//! [`CROSS_CITY_COORDINATOR_MODE_DEFAULT_ENABLED`] is `false` and
//! [`CrossCityCoordinatorConfig::default`] is disabled. A disabled
//! coordinator returns `GateBlocked` for every mutating call BEFORE touching
//! the database, the registry, or the transport. Enabling requires an
//! explicit, auditable [`CrossCityCoordinatorConfig::try_enable`] whose
//! missing/empty configuration is REFUSED (home city, positive coordinator
//! epoch, non-empty node key registry) — never defaulted.
//!
//! # Authorization boundary
//!
//! Nothing here grants anything. Decisions recorded here are durable
//! coordination evidence; the gate's `ACTIVE` state signals readiness of the
//! cross-city subsystem, and the ONLY authorization entry point remains
//! `PolicyEngine.evaluate()` over the regular fail-closed permission path.
//! This module contains no SQL, no HTTP, no cache, and no MQ client of its
//! own: all durable work is delegated to the astral-db cross-city repository
//! primitives inside short transactions owned by this module.

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::MySqlPool;
use thiserror::Error;

use astral_common::cross_city_signature::{
    authenticate_zero_decision_evidence, CrossCityAuthenticatedEvidence, CrossCitySignatureError,
};
use astral_db::{
    derive_cross_city_agreement_certificate_in_tx, insert_outbox_in_tx,
    load_cross_city_node_key_snapshot, load_gate_activation_mint_requests_in_tx,
    load_operation_for_update_in_tx, load_votes_for_operation_in_tx,
    mint_cross_city_gate_activation_in_tx, mint_cross_city_operation_activation_in_tx,
    record_cross_city_commit_receipt_in_tx, record_cross_city_verified_vote_in_tx,
    record_operation_failure_in_tx, require_votes_have_durable_reservations_in_tx,
    transition_operation_in_tx, CrossCityCommitReceiptMeta, CrossCityGateActivationMintRequest,
    CrossCityNodeKeySnapshot, CrossCityOperationActivationMintOutcome,
    CrossCityOperationFailureRequest, CrossCityOperationTransitionRequest, CrossCityOutboxInsert,
    CrossCityRuntimeRepositoryError, CrossCityTransportRepositoryError,
    CrossCityVerifiedVoteRecord,
};
use astral_types::{CrossCityMessagePhase, CrossCityOperationState, ZeroDecisionEvidence};

// ---------------------------------------------------------------------------
// Default-off mode gate
// ---------------------------------------------------------------------------

/// Compile-time marker: the cross-city coordinator is DEFAULT-OFF.
///
/// Mirrors `astral_types::CROSS_CITY_MODE_DEFAULT_ENABLED`. Nothing in this
/// module connects to a writer, runtime, projection, message path, or
/// authorization path until an explicit, auditable enablement (see
/// [`CrossCityCoordinatorConfig::try_enable`]) is performed by the embedding
/// process — never a change to this constant consulted silently.
pub const CROSS_CITY_COORDINATOR_MODE_DEFAULT_ENABLED: bool = false;

/// Configuration of the cross-city coordinator. Fail-closed by default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityCoordinatorConfig {
    enabled: bool,
    home_city_id: Option<String>,
    coordinator_epoch: u64,
}

impl CrossCityCoordinatorConfig {
    /// The fail-closed default: coordinator disabled; every mutating call
    /// returns `GateBlocked` before any I/O.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            home_city_id: None,
            coordinator_epoch: 0,
        }
    }

    /// Explicitly enable the coordinator. This is an auditable enablement
    /// decision: missing or empty configuration is REFUSED, never defaulted.
    ///
    /// Requirements (all mandatory):
    /// - `home_city_id`: non-empty, unpadded, bounded identifier of THIS
    ///   deployment's city (the outbox `source_city_id` of every message);
    /// - `coordinator_epoch`: positive, monotonic coordinator epoch fence;
    /// - `node_keys`: the EXPLICIT FIXED provider — a durably loaded node key
    ///   snapshot that must contain at least one usable registered identity.
    pub fn try_enable(
        home_city_id: &str,
        coordinator_epoch: u64,
        node_keys: &CrossCityNodeKeySnapshot,
    ) -> Result<Self, CrossCityCoordinatorError> {
        if home_city_id.trim() != home_city_id
            || home_city_id.is_empty()
            || home_city_id.len() > 191
            || home_city_id
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(CrossCityCoordinatorError::ConfigRefused(
                "home_city_id_missing_or_malformed",
            ));
        }
        if coordinator_epoch == 0 {
            return Err(CrossCityCoordinatorError::ConfigRefused(
                "coordinator_epoch_missing",
            ));
        }
        if node_keys.is_empty() {
            return Err(CrossCityCoordinatorError::ConfigRefused(
                "node_key_registry_missing",
            ));
        }
        Ok(Self {
            enabled: true,
            home_city_id: Some(home_city_id.to_owned()),
            coordinator_epoch,
        })
    }

    /// Whether the coordinator is enabled at all.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// The configured home city identifier (present only when enabled).
    #[must_use]
    pub const fn home_city_id(&self) -> Option<&String> {
        self.home_city_id.as_ref()
    }

    /// The configured coordinator epoch fence.
    #[must_use]
    pub const fn coordinator_epoch(&self) -> u64 {
        self.coordinator_epoch
    }
}

impl Default for CrossCityCoordinatorConfig {
    /// Fail-closed default: disabled until an explicit, auditable enablement.
    fn default() -> Self {
        Self::disabled()
    }
}

// ---------------------------------------------------------------------------
// Errors and typed outcomes
// ---------------------------------------------------------------------------

/// Typed failures of the cross-city coordinator. Every variant is
/// fail-closed: none of them ever widens authorization.
#[derive(Debug, Error)]
pub enum CrossCityCoordinatorError {
    /// The coordinator is disabled (default-off mode); no I/O happened.
    #[error("cross-city coordinator is disabled (default-off)")]
    GateBlocked,
    /// Enablement was refused: missing or malformed configuration.
    #[error("cross-city coordinator configuration refused: {0}")]
    ConfigRefused(&'static str),
    /// The authentication boundary refused the evidence (proven invalid).
    #[error(transparent)]
    Signature(#[from] CrossCitySignatureError),
    /// A cross-city repository primitive refused the input.
    #[error(transparent)]
    Repository(#[from] astral_db::CrossCityRepositoryError),
    /// The runtime-proof repository refused the input.
    #[error(transparent)]
    RuntimeRepository(#[from] CrossCityRuntimeRepositoryError),
    /// The transport repository refused the outbox write.
    #[error(transparent)]
    TransportRepository(#[from] CrossCityTransportRepositoryError),
    /// Storage failed while the transactional outcome was UNKNOWN: the
    /// operation may or may not be durable. Callers must reconcile through
    /// `mark_unknown_outcome_in_doubt` — never blind-retry.
    #[error("cross-city storage outcome unknown: {0}")]
    UnknownStorage(#[from] sqlx::Error),
}

impl CrossCityCoordinatorError {
    /// Stable machine-readable code for audit events and metrics.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::GateBlocked => "CROSS_CITY_GATE_BLOCKED",
            Self::ConfigRefused(_) => "CROSS_CITY_CONFIG_REFUSED",
            Self::Signature(_) => "CROSS_CITY_AUTHENTICATION_REFUSED",
            Self::Repository(_) => "CROSS_CITY_REPOSITORY_REFUSED",
            Self::RuntimeRepository(_) => "CROSS_CITY_RUNTIME_REPOSITORY_REFUSED",
            Self::TransportRepository(_) => "CROSS_CITY_TRANSPORT_REPOSITORY_REFUSED",
            Self::UnknownStorage(_) => "CROSS_CITY_STORAGE_UNKNOWN",
        }
    }
}

/// Typed outcome of one vote admission.
#[derive(Debug)]
pub enum CrossCityVoteAdmission {
    /// The vote passed the full boundary (authentication + durable replay
    /// reservation + verified-vote insert in one committed transaction).
    Recorded(Box<CrossCityVerifiedVoteRecord>),
    /// The coordinator is disabled (default-off); nothing was evaluated.
    GateBlocked,
    /// The evidence was PROVEN invalid or misbehaving (contract, expiry,
    /// signature, unknown/revoked key, or a proven replay). Never admitted;
    /// retained for audit.
    Quarantined(CrossCitySignatureError),
    /// The request was refused by a durable guard (binding, state whitelist,
    /// capacity, sealed agreement, scope authority). Never admitted.
    Refused(CrossCityCoordinatorError),
    /// The storage outcome is UNKNOWN (commit may or may not be durable).
    /// Reconcile through `mark_unknown_outcome_in_doubt`; never retry blindly.
    Unknown,
}

impl CrossCityVoteAdmission {
    /// Stable machine-readable decision code (audit/metrics).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Recorded(_) => "RECORDED",
            Self::GateBlocked => "GATE_BLOCKED",
            Self::Quarantined(_) => "QUARANTINED",
            Self::Refused(_) => "REFUSED",
            Self::Unknown => "UNKNOWN",
        }
    }

    /// The single safe positive predicate: only `Recorded` returns `true`.
    #[must_use]
    pub const fn is_recorded(&self) -> bool {
        matches!(self, Self::Recorded(_))
    }
}

/// Typed outcome of one agreement-sealing attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossCityAgreementSealOutcome {
    /// The agreement was sealed now; the digest is the EVIDENCE-DERIVED
    /// agreement certificate digest installed on the operation row.
    Sealed { agreement_digest: String },
    /// The operation was already `AGREED` (idempotent re-invocation).
    AlreadySealed,
}

// ---------------------------------------------------------------------------
// Injected collaborators (typed seams; main owns the concrete adapters)
// ---------------------------------------------------------------------------

/// One outbound cross-city message handed to the injected transport after the
/// durable outbox row was committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityOutboundMessage {
    pub message_id: String,
    pub operation_id: String,
    pub phase: CrossCityMessagePhase,
    pub source_city_id: String,
    pub destination_city_id: String,
    pub payload: Vec<u8>,
}

/// Typed transport dispatch failure (secret-free, bounded).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("cross-city transport dispatch failed: {code}")]
pub struct CrossCityTransportDispatchError {
    pub code: &'static str,
}

/// The typed transport seam of the coordinator. Production implementations
/// (MQ adapter) are a main-wiring decision; the coordinator itself never
/// constructs one and never retries a failed send (the durable outbox retry
/// budget owns redelivery).
#[async_trait]
pub trait CrossCityMessageTransport: Send + Sync {
    /// Best-effort, ONE-shot dispatch of an already-durable message.
    async fn send(
        &self,
        message: &CrossCityOutboundMessage,
    ) -> Result<(), CrossCityTransportDispatchError>;
}

/// One bounded, secret-free audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityCoordinatorAuditEvent {
    pub event_code: &'static str,
    pub operation_id: Option<String>,
    pub message_id: Option<String>,
    pub city_id: Option<String>,
    /// Truncated human-readable detail (bounded to 512 characters).
    pub detail: String,
}

impl CrossCityCoordinatorAuditEvent {
    /// Build one audit event with a bounded detail string.
    #[must_use]
    pub fn new(
        event_code: &'static str,
        operation_id: Option<String>,
        message_id: Option<String>,
        city_id: Option<String>,
        detail: &str,
    ) -> Self {
        let mut bounded: String = detail.chars().take(512).collect();
        if bounded.len() < detail.len() {
            bounded.push('…');
        }
        Self {
            event_code,
            operation_id,
            message_id,
            city_id,
            detail: bounded,
        }
    }
}

/// The typed audit sink seam (correlates on stable operation/message ids).
#[async_trait]
pub trait CrossCityCoordinatorAuditSink: Send + Sync {
    async fn record(&self, event: CrossCityCoordinatorAuditEvent);
}

/// No-op audit sink: the fail-open logging choice for tests and for
/// deployments that wire a real sink in main. Production enablements SHOULD
/// inject a durable sink; this type never pretends to persist anything.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopCrossCityAuditSink;

#[async_trait]
impl CrossCityCoordinatorAuditSink for NoopCrossCityAuditSink {
    async fn record(&self, _event: CrossCityCoordinatorAuditEvent) {}
}

// ---------------------------------------------------------------------------
// Coordinator service
// ---------------------------------------------------------------------------

/// The production cross-city coordinator: a library service over the durable
/// cross-city primitives. Construct it ONCE per process with an explicit,
/// auditable configuration and the explicit fixed node-key provider; main
/// owns the wiring (no HTTP route is provided or permitted here).
#[derive(Clone)]
pub struct CrossCityCoordinator {
    pool: MySqlPool,
    config: CrossCityCoordinatorConfig,
    node_keys: Arc<CrossCityNodeKeySnapshot>,
    transport: Arc<dyn CrossCityMessageTransport>,
    audit: Arc<dyn CrossCityCoordinatorAuditSink>,
}

impl CrossCityCoordinator {
    /// Load the durable node key registry and return it as the explicit
    /// fixed provider for [`Self::new`]/[`Self::try_new`]. One durable read;
    /// no transaction of its own.
    pub async fn load_node_key_provider(
        pool: &MySqlPool,
    ) -> Result<Arc<CrossCityNodeKeySnapshot>, CrossCityCoordinatorError> {
        let snapshot = load_cross_city_node_key_snapshot(pool).await?;
        Ok(Arc::new(snapshot))
    }

    /// Construct a DISABLED coordinator (fail-closed default). Enabling is a
    /// separate, auditable [`Self::try_new`] decision.
    #[must_use]
    pub fn disabled(
        pool: MySqlPool,
        node_keys: Arc<CrossCityNodeKeySnapshot>,
        transport: Arc<dyn CrossCityMessageTransport>,
        audit: Arc<dyn CrossCityCoordinatorAuditSink>,
    ) -> Self {
        Self {
            pool,
            config: CrossCityCoordinatorConfig::disabled(),
            node_keys,
            transport,
            audit,
        }
    }

    /// Construct an ENABLED coordinator; every missing piece of configuration
    /// is refused (never defaulted). The node-key provider must be the
    /// explicit fixed snapshot loaded from the durable registry.
    pub fn try_new(
        pool: MySqlPool,
        home_city_id: &str,
        coordinator_epoch: u64,
        node_keys: Arc<CrossCityNodeKeySnapshot>,
        transport: Arc<dyn CrossCityMessageTransport>,
        audit: Arc<dyn CrossCityCoordinatorAuditSink>,
    ) -> Result<Self, CrossCityCoordinatorError> {
        let config =
            CrossCityCoordinatorConfig::try_enable(home_city_id, coordinator_epoch, &node_keys)?;
        Ok(Self {
            pool,
            config,
            node_keys,
            transport,
            audit,
        })
    }

    /// The coordinator's (auditable) configuration.
    #[must_use]
    pub const fn config(&self) -> &CrossCityCoordinatorConfig {
        &self.config
    }

    /// Authenticate one evidence purely (no reservation, no I/O) against the
    /// explicit fixed node-key provider. The public seam for tests and for
    /// callers that must pre-classify evidence before any durable step.
    pub fn authenticate(
        &self,
        evidence: &ZeroDecisionEvidence,
        now_seconds: i64,
    ) -> Result<CrossCityAuthenticatedEvidence, CrossCitySignatureError> {
        authenticate_zero_decision_evidence(evidence, now_seconds, self.node_keys.as_ref())
    }

    /// Admit one node decision evidence: gate -> pure authentication ->
    /// durable (replay reservation + verified vote) in ONE short source
    /// transaction. Fail-closed on every non-`Recorded` path.
    pub async fn admit_vote(
        &self,
        operation_id: &str,
        evidence: &ZeroDecisionEvidence,
        now_seconds: i64,
    ) -> CrossCityVoteAdmission {
        // Step 1: the mode gate blocks EVERYTHING (no resolver call, no
        // signature check, no storage touch) while disabled.
        if !self.config.is_enabled() {
            return CrossCityVoteAdmission::GateBlocked;
        }
        // Step 2: pure cryptographic authentication (no reservation).
        let authenticated = match self.authenticate(evidence, now_seconds) {
            Ok(authenticated) => authenticated,
            Err(error) => return CrossCityVoteAdmission::Quarantined(error),
        };
        // Step 3: durable reservation + verified-vote insert, one transaction.
        let mut tx = match self.pool.begin().await {
            Ok(tx) => tx,
            Err(_) => return CrossCityVoteAdmission::Unknown,
        };
        let recorded = record_cross_city_verified_vote_in_tx(
            &mut tx,
            operation_id,
            &authenticated,
            now_seconds,
        )
        .await;
        let recorded = match recorded {
            Ok(recorded) => recorded,
            Err(CrossCityRuntimeRepositoryError::ReplayConflict(_)) => {
                // Proven replay: durable conflict, audit and stop.
                let _ = tx.rollback().await;
                self.audit
                    .record(CrossCityCoordinatorAuditEvent::new(
                        "cross_city_vote_replay_rejected",
                        Some(operation_id.to_owned()),
                        None,
                        Some(evidence.city_id.clone()),
                        &format!("node={}", evidence.node_id),
                    ))
                    .await;
                return CrossCityVoteAdmission::Quarantined(CrossCitySignatureError::NonceReplay);
            }
            Err(
                error @ (CrossCityRuntimeRepositoryError::Repository(_)
                | CrossCityRuntimeRepositoryError::Query(_)),
            ) => {
                let _ = tx.rollback().await;
                return CrossCityVoteAdmission::Refused(error.into());
            }
        };
        if let Err(error) = tx.commit().await {
            // The COMMIT outcome is unknown: the vote may or may not be
            // durable. Never retry blindly; reconcile instead.
            let _ = error;
            self.audit
                .record(CrossCityCoordinatorAuditEvent::new(
                    "cross_city_vote_commit_unknown",
                    Some(operation_id.to_owned()),
                    None,
                    Some(evidence.city_id.clone()),
                    "commit outcome unknown; reconcile required",
                ))
                .await;
            return CrossCityVoteAdmission::Unknown;
        }
        self.audit
            .record(CrossCityCoordinatorAuditEvent::new(
                "cross_city_vote_recorded",
                Some(operation_id.to_owned()),
                None,
                Some(recorded.evidence.city_id.clone()),
                &format!(
                    "vote_id={};node={}",
                    recorded.vote_id, recorded.evidence.node_id
                ),
            ))
            .await;
        CrossCityVoteAdmission::Recorded(Box::new(recorded))
    }

    /// Seal the agreement of one operation from its durable,
    /// reservation-proven votes (evidence-derived digest only) and move the
    /// operation to `AGREED` — one short transaction. Idempotent on an
    /// already-sealed operation.
    pub async fn seal_agreement(
        &self,
        operation_id: &str,
        now_seconds: i64,
    ) -> Result<CrossCityAgreementSealOutcome, CrossCityCoordinatorError> {
        if !self.config.is_enabled() {
            return Err(CrossCityCoordinatorError::GateBlocked);
        }
        let mut tx = self.pool.begin().await?;
        let operation = load_operation_for_update_in_tx(&mut tx, operation_id).await?;
        match operation.state {
            CrossCityOperationState::Proposed | CrossCityOperationState::Voting => {}
            CrossCityOperationState::Agreed => {
                tx.commit().await?;
                return Ok(CrossCityAgreementSealOutcome::AlreadySealed);
            }
            other => {
                let _ = other;
                return Err(CrossCityCoordinatorError::Repository(
                    astral_db::CrossCityRepositoryError::InvalidTransition(format!(
                        "code=cross_city_coordinator.seal_requires_voting_state;state={}",
                        operation.state.as_str()
                    )),
                ));
            }
        }
        // Only durably-verified votes may contribute: every stored vote must
        // carry its durable replay reservation row.
        let votes = load_votes_for_operation_in_tx(&mut tx, operation_id).await?;
        require_votes_have_durable_reservations_in_tx(&mut tx, operation_id, &votes)
            .await
            .map_err(CrossCityCoordinatorError::from)?;
        let certificate =
            derive_cross_city_agreement_certificate_in_tx(&mut tx, operation_id, now_seconds)
                .await?;
        transition_operation_in_tx(
            &mut tx,
            &CrossCityOperationTransitionRequest {
                operation_id: operation_id.to_owned(),
                expected_state: operation.state,
                target_state: CrossCityOperationState::Agreed,
                coordinator_epoch: self.config.coordinator_epoch,
                agreement_digest: Some(certificate.agreement_digest.clone()),
                activation_proof: None,
            },
            now_seconds,
        )
        .await?;
        tx.commit().await?;
        self.audit
            .record(CrossCityCoordinatorAuditEvent::new(
                "cross_city_agreement_sealed",
                Some(operation_id.to_owned()),
                None,
                None,
                &format!("agreement_digest={}", certificate.agreement_digest),
            ))
            .await;
        Ok(CrossCityAgreementSealOutcome::Sealed {
            agreement_digest: certificate.agreement_digest,
        })
    }

    /// Record one signed, durable source-apply commit receipt (one city
    /// node). Authentication happens first (pure); the receipt insert shares
    /// its transaction with the durable replay reservation and re-checks the
    /// authority scope and every version pin against the locked parent.
    pub async fn record_commit_receipt(
        &self,
        operation_id: &str,
        evidence: &ZeroDecisionEvidence,
        meta: &CrossCityCommitReceiptMeta,
        now_seconds: i64,
    ) -> Result<i64, CrossCityCoordinatorError> {
        if !self.config.is_enabled() {
            return Err(CrossCityCoordinatorError::GateBlocked);
        }
        let authenticated = self.authenticate(evidence, now_seconds)?;
        let mut tx = self.pool.begin().await?;
        let receipt_id = record_cross_city_commit_receipt_in_tx(
            &mut tx,
            operation_id,
            &authenticated,
            meta,
            now_seconds,
        )
        .await
        .map_err(CrossCityCoordinatorError::from)?;
        tx.commit().await?;
        self.audit
            .record(CrossCityCoordinatorAuditEvent::new(
                "cross_city_commit_receipt_recorded",
                Some(operation_id.to_owned()),
                None,
                Some(evidence.city_id.clone()),
                &format!("receipt_id={receipt_id};node={}", evidence.node_id),
            ))
            .await;
        Ok(receipt_id)
    }

    /// Mint the operation activation proof from the durable two-city commit
    /// receipts and move the operation to `ACTIVE` (terminal city phases are
    /// written atomically by the mint). Without BOTH cities' durable
    /// source-apply receipts this REFUSES — the operation stays in its
    /// commit-unknown state; nothing else can activate it.
    pub async fn activate_operation(
        &self,
        operation_id: &str,
        now_seconds: i64,
    ) -> Result<CrossCityOperationActivationMintOutcome, CrossCityCoordinatorError> {
        if !self.config.is_enabled() {
            return Err(CrossCityCoordinatorError::GateBlocked);
        }
        let mut tx = self.pool.begin().await?;
        let outcome = mint_cross_city_operation_activation_in_tx(
            &mut tx,
            operation_id,
            self.config.coordinator_epoch,
            now_seconds,
        )
        .await?;
        tx.commit().await?;
        self.audit
            .record(CrossCityCoordinatorAuditEvent::new(
                "cross_city_operation_activated",
                Some(operation_id.to_owned()),
                None,
                None,
                "activation minted from durable two-city commit receipts",
            ))
            .await;
        Ok(outcome)
    }

    /// Mint gate activation proofs from the operation's DURABLE activation
    /// record and move every gate pinned to the operation to `ACTIVE` — one
    /// short transaction over the deterministic gate list. A gate whose
    /// pinned versions disagree with the parent refuses (never repaired).
    pub async fn activate_operation_gates(
        &self,
        operation_id: &str,
        now_seconds: i64,
    ) -> Result<
        Vec<(
            CrossCityGateActivationMintRequest,
            astral_types::CrossCityGateState,
        )>,
        CrossCityCoordinatorError,
    > {
        if !self.config.is_enabled() {
            return Err(CrossCityCoordinatorError::GateBlocked);
        }
        let mut tx = self.pool.begin().await?;
        let requests = load_gate_activation_mint_requests_in_tx(&mut tx, operation_id).await?;
        let mut activated = Vec::with_capacity(requests.len());
        for request in &requests {
            let state =
                mint_cross_city_gate_activation_in_tx(&mut tx, request, now_seconds).await?;
            activated.push((request.clone(), state));
        }
        tx.commit().await?;
        self.audit
            .record(CrossCityCoordinatorAuditEvent::new(
                "cross_city_gates_activated",
                Some(operation_id.to_owned()),
                None,
                None,
                &format!("gate_count={}", activated.len()),
            ))
            .await;
        Ok(activated)
    }

    /// Collapse a genuinely unknown outcome into `IN_DOUBT` (fail-closed
    /// recovery edge of the closed state machine) with a bounded diagnostic.
    /// Idempotent for an operation already in `IN_DOUBT`.
    pub async fn mark_unknown_outcome_in_doubt(
        &self,
        operation_id: &str,
        expected_state: CrossCityOperationState,
        reason: &str,
        now_seconds: i64,
    ) -> Result<CrossCityOperationState, CrossCityCoordinatorError> {
        if !self.config.is_enabled() {
            return Err(CrossCityCoordinatorError::GateBlocked);
        }
        let mut tx = self.pool.begin().await?;
        record_operation_failure_in_tx(
            &mut tx,
            &CrossCityOperationFailureRequest {
                operation_id: operation_id.to_owned(),
                expected_state,
                coordinator_epoch: self.config.coordinator_epoch,
                message: reason.to_owned(),
            },
        )
        .await?;
        let final_state = transition_operation_in_tx(
            &mut tx,
            &CrossCityOperationTransitionRequest {
                operation_id: operation_id.to_owned(),
                expected_state,
                target_state: CrossCityOperationState::InDoubt,
                coordinator_epoch: self.config.coordinator_epoch,
                agreement_digest: None,
                activation_proof: None,
            },
            now_seconds,
        )
        .await?;
        tx.commit().await?;
        self.audit
            .record(CrossCityCoordinatorAuditEvent::new(
                "cross_city_operation_in_doubt",
                Some(operation_id.to_owned()),
                None,
                None,
                reason,
            ))
            .await;
        Ok(final_state)
    }

    /// Enqueue one outbound cross-city phase message through the DURABLE
    /// outbox (its own short transaction; the message id is DERIVED), then
    /// perform EXACTLY ONE post-commit best-effort transport send. A failed
    /// or unknown send NEVER rolls the decision back or forward: the outbox
    /// retry budget owns redelivery.
    pub async fn enqueue_phase_message(
        &self,
        operation_id: &str,
        phase: CrossCityMessagePhase,
        destination_city_id: &str,
        payload: Vec<u8>,
    ) -> Result<String, CrossCityCoordinatorError> {
        if !self.config.is_enabled() {
            return Err(CrossCityCoordinatorError::GateBlocked);
        }
        let Some(source_city_id) = self.config.home_city_id.clone() else {
            return Err(CrossCityCoordinatorError::ConfigRefused(
                "home_city_id_missing",
            ));
        };
        let request = CrossCityOutboxInsert {
            operation_id: operation_id.to_owned(),
            phase,
            source_city_id,
            destination_city_id: destination_city_id.to_owned(),
            payload,
        };
        let mut tx = self.pool.begin().await?;
        let record = match insert_outbox_in_tx(&mut tx, &request).await? {
            astral_db::CrossCityOutboxInsertOutcome::Created(record)
            | astral_db::CrossCityOutboxInsertOutcome::IdempotentExisting(record) => *record,
        };
        tx.commit().await?;
        let message = CrossCityOutboundMessage {
            message_id: record.message_id.clone(),
            operation_id: record.identity.operation_id.clone(),
            phase: record.identity.phase,
            source_city_id: record.identity.source_city_id.clone(),
            destination_city_id: record.identity.destination_city_id.clone(),
            payload: record.payload.clone(),
        };
        // Post-commit, bounded, best-effort: ONE send, no retry loop here.
        let dispatch = self.transport.send(&message).await;
        if let Err(error) = dispatch {
            self.audit
                .record(CrossCityCoordinatorAuditEvent::new(
                    "cross_city_message_send_failed",
                    Some(operation_id.to_owned()),
                    Some(message.message_id.clone()),
                    Some(destination_city_id.to_owned()),
                    error.code,
                ))
                .await;
        } else {
            self.audit
                .record(CrossCityCoordinatorAuditEvent::new(
                    "cross_city_message_sent",
                    Some(operation_id.to_owned()),
                    Some(message.message_id.clone()),
                    Some(destination_city_id.to_owned()),
                    phase.as_str(),
                ))
                .await;
        }
        Ok(record.message_id)
    }
}

// ---------------------------------------------------------------------------
// Tests (pure: no DB connection is ever established, no network, no MQ)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A pool that can never be used: every gated path must return before
    /// touching it, and these tests prove exactly that.
    fn unreachable_pool() -> MySqlPool {
        MySqlPool::connect_lazy("mysql://cross-city-gate-test@127.0.0.1:1/none")
            .expect("lazy pool constructs without connecting")
    }

    #[derive(Default)]
    struct RecordingTransport {
        sends: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait]
    impl CrossCityMessageTransport for RecordingTransport {
        async fn send(
            &self,
            message: &CrossCityOutboundMessage,
        ) -> Result<(), CrossCityTransportDispatchError> {
            self.sends
                .lock()
                .expect("transport recording lock")
                .push(message.message_id.clone());
            Ok(())
        }
    }

    fn disabled_coordinator(transport: Arc<RecordingTransport>) -> CrossCityCoordinator {
        CrossCityCoordinator::disabled(
            unreachable_pool(),
            Arc::new(CrossCityNodeKeySnapshot::default()),
            transport,
            Arc::new(NoopCrossCityAuditSink),
        )
    }

    #[test]
    fn coordinator_mode_is_default_off_at_compile_time_and_by_default_config() {
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(!CROSS_CITY_COORDINATOR_MODE_DEFAULT_ENABLED);
        }
        assert!(!CrossCityCoordinatorConfig::default().is_enabled());
        assert!(!CrossCityCoordinatorConfig::disabled().is_enabled());
        assert_eq!(
            CROSS_CITY_COORDINATOR_MODE_DEFAULT_ENABLED,
            astral_types::CROSS_CITY_MODE_DEFAULT_ENABLED
        );
    }

    #[test]
    fn try_enable_refuses_missing_or_malformed_configuration() {
        let empty_registry = CrossCityNodeKeySnapshot::default();
        let oversized_city = "x".repeat(192);
        let refusals = [
            ("empty_city", "", 1_u64),
            ("padded_city", " city-a ", 1_u64),
            ("oversized_city", oversized_city.as_str(), 1_u64),
            ("zero_epoch", "city-a", 0_u64),
        ];
        for (label, home, epoch) in refusals {
            let error = CrossCityCoordinatorConfig::try_enable(home, epoch, &empty_registry)
                .err()
                .unwrap_or_else(|| panic!("{label} configuration must be refused"));
            assert!(
                matches!(error, CrossCityCoordinatorError::ConfigRefused(_)),
                "{label}: unexpected error {error:?}"
            );
        }
        assert!(
            CrossCityCoordinatorConfig::try_enable("city-a", 1, &empty_registry).is_err(),
            "an empty node-key registry is missing configuration"
        );
    }

    #[tokio::test]
    async fn gate_blocked_short_circuits_every_mutation_before_storage_and_transport() {
        let transport = Arc::new(RecordingTransport::default());
        let coordinator = disabled_coordinator(transport.clone());
        assert!(!coordinator.config().is_enabled());

        let operation_id = "550e8400-e29b-41d4-a716-446655440000";
        let admission = coordinator
            .admit_vote(operation_id, &gate_evidence(), 1_000)
            .await;
        assert!(!admission.is_recorded());
        assert_eq!(admission.as_str(), "GATE_BLOCKED");

        assert!(matches!(
            coordinator.seal_agreement(operation_id, 1_000).await,
            Err(CrossCityCoordinatorError::GateBlocked)
        ));
        assert!(matches!(
            coordinator
                .record_commit_receipt(
                    operation_id,
                    &gate_evidence(),
                    &CrossCityCommitReceiptMeta {
                        target_generation: 4,
                        revoke_fence: 2,
                        coordinator_epoch: 1,
                    },
                    1_000,
                )
                .await,
            Err(CrossCityCoordinatorError::GateBlocked)
        ));
        assert!(matches!(
            coordinator.activate_operation(operation_id, 1_000).await,
            Err(CrossCityCoordinatorError::GateBlocked)
        ));
        assert!(matches!(
            coordinator
                .activate_operation_gates(operation_id, 1_000)
                .await,
            Err(CrossCityCoordinatorError::GateBlocked)
        ));
        assert!(matches!(
            coordinator
                .mark_unknown_outcome_in_doubt(
                    operation_id,
                    CrossCityOperationState::Activating,
                    "unknown",
                    1_000,
                )
                .await,
            Err(CrossCityCoordinatorError::GateBlocked)
        ));
        assert!(matches!(
            coordinator
                .enqueue_phase_message(
                    operation_id,
                    CrossCityMessagePhase::CommitConfirmed,
                    "city-beta",
                    b"payload".to_vec(),
                )
                .await,
            Err(CrossCityCoordinatorError::GateBlocked)
        ));

        // Nothing was evaluated, nothing was sent, nothing was stored.
        assert!(transport.sends.lock().expect("send log lock").is_empty());
    }

    fn gate_evidence() -> ZeroDecisionEvidence {
        ZeroDecisionEvidence::new(
            "city-alpha",
            "node-01",
            1,
            astral_types::NodeDecision::Allow,
            &"a".repeat(64),
            &"b".repeat(64),
            &"c".repeat(64),
            "gate-nonce",
            4_102_444_800,
            &"d".repeat(128),
        )
        .expect("gate-test evidence is contract-valid")
    }

    #[test]
    fn audit_detail_is_bounded_and_codes_are_stable_and_distinct() {
        let event = CrossCityCoordinatorAuditEvent::new(
            "cross_city_vote_recorded",
            Some("op".to_owned()),
            None,
            Some("city-alpha".to_owned()),
            &"x".repeat(600),
        );
        assert_eq!(event.detail.chars().count(), 513); // 512 + ellipsis
        assert!(event.detail.ends_with('\u{2026}'));

        let error_codes = [
            CrossCityCoordinatorError::GateBlocked.code(),
            CrossCityCoordinatorError::ConfigRefused("x").code(),
            CrossCityCoordinatorError::Signature(CrossCitySignatureError::ContractRejected).code(),
            CrossCityCoordinatorError::Repository(astral_db::CrossCityRepositoryError::NotFound(
                "x".to_owned(),
            ))
            .code(),
            CrossCityCoordinatorError::RuntimeRepository(
                CrossCityRuntimeRepositoryError::ReplayConflict("x".to_owned()),
            )
            .code(),
            CrossCityCoordinatorError::UnknownStorage(sqlx::Error::RowNotFound).code(),
        ];
        for i in 0..error_codes.len() {
            for j in (i + 1)..error_codes.len() {
                assert_ne!(error_codes[i], error_codes[j]);
            }
        }

        let admission_codes = [
            CrossCityVoteAdmission::GateBlocked.as_str(),
            CrossCityVoteAdmission::Quarantined(CrossCitySignatureError::NonceReplay).as_str(),
            CrossCityVoteAdmission::Unknown.as_str(),
            CrossCityVoteAdmission::Refused(CrossCityCoordinatorError::GateBlocked).as_str(),
        ];
        for i in 0..admission_codes.len() {
            for j in (i + 1)..admission_codes.len() {
                assert_ne!(admission_codes[i], admission_codes[j]);
            }
        }
    }

    // -- Source-shape guards (scan this file's own production slice) ----------

    fn production_source() -> &'static str {
        const TEST_MODULE_MARKER: &str = concat!("#[", "cfg(test)]");
        let source = include_str!("cross_city_coordinator.rs");
        source
            .split_once(TEST_MODULE_MARKER)
            .map(|(production, _)| production)
            .expect("test-module marker present")
    }

    fn production_function_body(signature_needle: &str) -> &'static str {
        let production = production_source();
        let start = production
            .find(signature_needle)
            .unwrap_or_else(|| panic!("production function missing: {signature_needle}"));
        let end = production[start..]
            .find("\n}")
            .map(|offset| start + offset)
            .unwrap_or_else(|| panic!("function body unterminated: {signature_needle}"));
        &production[start..end]
    }

    #[test]
    fn source_shape_library_service_has_no_http_storage_or_placeholder_paths() {
        let production = production_source();
        // A library service: no HTTP route, no handler, no server wiring.
        for forbidden in ["axum", "Router", "route(", "async fn handler"] {
            assert!(
                !production.contains(forbidden),
                "coordinator must not contain HTTP primitives: {forbidden}"
            );
        }
        // Every durable statement lives in astral-db; this module owns
        // transactions and decisions only.
        for forbidden in ["sqlx::query", "INSERT INTO", "UPDATE authorization"] {
            assert!(
                !production.contains(forbidden),
                "coordinator must not contain storage primitives: {forbidden}"
            );
        }
        // No placeholder may masquerade as completed work.
        for forbidden in ["unimplemented!", "todo!", "panic!"] {
            assert!(
                !production.contains(forbidden),
                "incomplete coordinator path: {forbidden}"
            );
        }
        // Transport and audit enter only through their typed seams.
        assert!(production.contains("Arc<dyn CrossCityMessageTransport>"));
        assert!(production.contains("Arc<dyn CrossCityCoordinatorAuditSink>"));
    }

    #[test]
    fn source_shape_gate_precedes_storage_and_authentication_precedes_durable_writes() {
        for signature in [
            "pub async fn admit_vote",
            "pub async fn seal_agreement",
            "pub async fn record_commit_receipt",
            "pub async fn activate_operation",
            "pub async fn activate_operation_gates",
            "pub async fn mark_unknown_outcome_in_doubt",
            "pub async fn enqueue_phase_message",
        ] {
            let body = production_function_body(signature);
            let gate = body
                .find("self.config.is_enabled()")
                .unwrap_or_else(|| panic!("mode gate missing in {signature}"));
            let storage = body
                .find("self.pool.begin()")
                .unwrap_or_else(|| panic!("storage access missing in {signature}"));
            assert!(
                gate < storage,
                "{signature} must gate the mode BEFORE touching storage"
            );
        }
        let vote_body = production_function_body("pub async fn admit_vote");
        let authenticate = vote_body
            .find("self.authenticate(")
            .expect("authentication step missing");
        let durable = vote_body
            .find("record_cross_city_verified_vote_in_tx")
            .expect("durable vote step missing");
        assert!(
            authenticate < durable,
            "pure authentication must precede the durable reservation+insert"
        );
    }
}
