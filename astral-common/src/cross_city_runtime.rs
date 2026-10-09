//! Cross-city signed-evidence admission runtime (P4, DEFAULT-OFF, pure).
//!
//! This module composes the frozen cross-city signature boundary
//! ([`crate::cross_city_signature`]) into one pure, in-process admission
//! flow: gate check, then strict signature verification, then atomic replay
//! reservation, then a typed admission decision. It adds no I/O, no
//! database, no network, no cache, no configuration loading, and no runtime
//! caller of its own. It never flips the cross-city mode switch and never
//! performs a state transition of [`CrossCityOperationState`]; state
//! transitions remain the coordinator's job backed by durable proof.
//!
//! # Default-off
//!
//! [`CROSS_CITY_RUNTIME_MODE_DEFAULT_ENABLED`] is `false` and
//! [`CrossCityRuntimeGate`] defaults to disabled. Nothing in this module is
//! wired into any writer, runtime, projection, message path, or
//! authorization path; enabling the gate is a separate, auditable decision
//! made explicitly by the caller - never a silent default.
//!
//! # Admission decision (fail-closed mapping)
//!
//! [`admit_cross_city_activation`] returns a closed
//! [`CrossCityActivationAdmission`] decision. The mapping is deliberately
//! fail-closed on every path:
//!
//! - Gate disabled: [`CrossCityActivationAdmission::GateBlocked`]. The
//!   evidence is not evaluated at all - no resolver call, no signature
//!   check, no replay reservation.
//! - Verification succeeded with decision `ALLOW`:
//!   [`CrossCityActivationAdmission::Admitted`], carrying the opaque
//!   [`CrossCityVerifiedEvidence`] capability.
//! - Verification succeeded with decision `DENY`:
//!   [`CrossCityActivationAdmission::Denied`] - a PROVEN negative from a
//!   verified signer. It is refused, never quarantined as invalid and never
//!   treated as unknown.
//! - Verification failed with
//!   [`CrossCitySignatureError::ReplayGuardUnavailable`]:
//!   [`CrossCityActivationAdmission::InDoubt`] - the reservation outcome is
//!   UNKNOWN (the guard could not prove it either way). The evidence must
//!   never be admitted, never be silently discarded, and never be retried
//!   in place; it must be reconciled exactly like the contract-layer
//!   `IN_DOUBT` state.
//! - Every other verification error (contract rejection, expiry, malformed
//!   or invalid signature, unknown node key, node-key mismatch, proven
//!   nonce replay): [`CrossCityActivationAdmission::Quarantined`] - the
//!   input is PROVEN invalid or misbehaving. It is never admitted, never
//!   retried in place, and stays available for audit.
//!
//! Only `Admitted` is a positive outcome. `is_admitted()` is the single
//! safe predicate; no other variant may ever be interpreted as permission
//! to proceed.
//!
//! # Durability boundary (production resolver/replay guard MUST be external)
//!
//! The resolver and replay-guard implementations provided here
//! ([`InMemoryCrossCityNodeKeyResolver`], [`InMemoryCrossCityReplayGuard`],
//! [`UnavailableCrossCityReplayGuard`]) are IN-MEMORY ADAPTERS for
//! composition testing and as reference shapes for future implementations.
//! They are NOT durable: process restart loses every reservation, and
//! concurrent replicas never share them. They must NEVER be presented as
//! production replay proof or production key material. The production
//! durable node-key resolver and the durable replay guard (whose
//! `reserve` must run in the same durable transaction as the evidence
//! insert) are deliberately ABSENT from this batch and MUST be implemented
//! externally against the [`CrossCityNodeKeyResolver`] and
//! [`CrossCityReplayGuard`] traits.
//!
//! # Authorization boundary
//!
//! An admission decision is NOT an authorization. This module never grants
//! anything, never reads or writes source data, and never replaces
//! `PolicyEngine.evaluate()`; `Admitted` only means "this evidence passed
//! the full signature and replay boundary and may be handed to the future
//! durable writer". Effective authorization still requires the regular
//! fail-closed permission path.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt;

use astral_types::{NodeDecision, ZeroDecisionEvidence};

use crate::cross_city_signature::{
    verify_zero_decision_evidence, CrossCityEvidenceReplayKey, CrossCityNodeIdentity,
    CrossCityNodeKeyRecord, CrossCityNodeKeyResolver, CrossCityReplayGuard,
    CrossCitySignatureError, CrossCityVerifiedEvidence,
};

// ---------------------------------------------------------------------------
// Default-off gate
// ---------------------------------------------------------------------------

/// Compile-time marker that the cross-city admission runtime is DEFAULT-OFF.
///
/// Mirrors `astral_types::CROSS_CITY_MODE_DEFAULT_ENABLED`. Nothing in this
/// module connects to a writer, coordinator, projection, or authorization
/// path. Any future enablement must be an explicit, auditable configuration
/// decision outside this crate - never a change to this constant consulted
/// silently from an authorization path.
pub const CROSS_CITY_RUNTIME_MODE_DEFAULT_ENABLED: bool = false;

/// Runtime mode gate of the cross-city admission flow.
///
/// The default is disabled (fail-closed, default-off). While disabled,
/// [`admit_cross_city_activation`] returns
/// [`CrossCityActivationAdmission::GateBlocked`] before touching the
/// evidence, the resolver, or the replay guard. Enabling the gate is an
/// explicit constructor call (`CrossCityRuntimeGate::enabled()`), never a
/// default, and remains an auditable decision of the embedding process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CrossCityRuntimeGate {
    enabled: bool,
}

impl CrossCityRuntimeGate {
    /// The fail-closed default gate: cross-city admission disabled.
    #[must_use]
    pub const fn disabled() -> Self {
        Self { enabled: false }
    }

    /// Explicitly enabled gate. Callers must treat this as an auditable
    /// enablement decision; nothing in this crate constructs it implicitly.
    #[must_use]
    pub const fn enabled() -> Self {
        Self { enabled: true }
    }

    /// Whether cross-city admission is enabled at all.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        self.enabled
    }
}

impl Default for CrossCityRuntimeGate {
    /// Fail-closed default: cross-city mode is default-off, so the runtime
    /// gate starts disabled until an explicit, auditable enablement.
    fn default() -> Self {
        Self::disabled()
    }
}

// ---------------------------------------------------------------------------
// Activation admission decision
// ---------------------------------------------------------------------------

/// Closed, typed admission decision for one cross-city activation evidence.
///
/// Exactly one positive variant exists ([`Self::Admitted`]); every other
/// variant is fail-closed and must never be interpreted as permission to
/// proceed. The distinction between [`Self::InDoubt`] and
/// [`Self::Quarantined`] matches the contract-layer vocabulary: `IN_DOUBT`
/// means the outcome is genuinely unknown (reconcile, never discard),
/// `QUARANTINED` means the input was proven invalid or misbehaving (audit
/// and stop). A verified `DENY` is a proven negative, not an unknown and
/// not an invalid input, so it has its own [`Self::Denied`] variant.
#[derive(Clone, PartialEq, Eq)]
pub enum CrossCityActivationAdmission {
    /// The evidence passed the full boundary (contract, canonical form,
    /// exact key identity, strict Ed25519 signature, atomic replay
    /// reservation) and its decision is `ALLOW`. The attached capability is
    /// the only value a future durable writer may consume.
    Admitted(CrossCityVerifiedEvidence),
    /// The evidence passed the full boundary and its decision is `DENY`:
    /// a proven negative from a verified signer. Never admitted, never
    /// quarantined as invalid, never treated as unknown.
    Denied(CrossCityVerifiedEvidence),
    /// The replay guard could not prove the reservation outcome
    /// (storage failure, timeout, unknown state): the outcome is UNKNOWN.
    /// The evidence must be reconciled through the durable path; it is
    /// never admitted, never silently discarded, and never retried in
    /// place by this runtime.
    InDoubt(CrossCitySignatureError),
    /// The input was PROVEN invalid or misbehaving (contract rejection,
    /// expiry, malformed/invalid signature, unknown node key, node-key
    /// mismatch, or a proven nonce replay). Never admitted; retained for
    /// audit.
    Quarantined(CrossCitySignatureError),
    /// The cross-city runtime gate is disabled (default-off mode). The
    /// evidence was not evaluated at all.
    GateBlocked,
}

impl CrossCityActivationAdmission {
    /// Stable machine-readable decision code, suitable for audit events and
    /// metrics. Codes never change meaning and never embed runtime data.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Admitted(_) => "ADMITTED",
            Self::Denied(_) => "DENIED",
            Self::InDoubt(_) => "IN_DOUBT",
            Self::Quarantined(_) => "QUARANTINED",
            Self::GateBlocked => "GATE_BLOCKED",
        }
    }

    /// The single safe positive predicate: only `Admitted` returns `true`.
    #[must_use]
    pub const fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted(_))
    }

    /// The verified-evidence capability, present exactly for the two
    /// variants whose underlying evidence fully verified (`Admitted` and
    /// `Denied`); `None` for every fail-closed variant.
    #[must_use]
    pub const fn verified_evidence(&self) -> Option<&CrossCityVerifiedEvidence> {
        match self {
            Self::Admitted(evidence) | Self::Denied(evidence) => Some(evidence),
            Self::InDoubt(_) | Self::Quarantined(_) | Self::GateBlocked => None,
        }
    }

    /// The typed verification failure, present exactly for the `InDoubt`
    /// and `Quarantined` variants.
    #[must_use]
    pub const fn verification_error(&self) -> Option<&CrossCitySignatureError> {
        match self {
            Self::InDoubt(error) | Self::Quarantined(error) => Some(error),
            Self::Admitted(_) | Self::Denied(_) | Self::GateBlocked => None,
        }
    }
}

impl fmt::Debug for CrossCityActivationAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Bounded, secret-free debug: decision code plus signer identity,
        // decision, and public digest for verified variants; the stable
        // error code for fail-closed variants. Signature bytes, nonces, and
        // every other raw evidence field are deliberately omitted.
        formatter
            .debug_struct("CrossCityActivationAdmission")
            .field("decision", &self.as_str())
            .field(
                "signer",
                &self
                    .verified_evidence()
                    .map(CrossCityVerifiedEvidence::signer_identity),
            )
            .field(
                "evidence_decision",
                &self
                    .verified_evidence()
                    .map(|evidence| evidence.evidence().decision),
            )
            .field(
                "evidence_digest",
                &self
                    .verified_evidence()
                    .map(|evidence| evidence.evidence().evidence_digest.as_str()),
            )
            .field(
                "reason_code",
                &self.verification_error().map(CrossCitySignatureError::code),
            )
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Fail-closed classification
// ---------------------------------------------------------------------------

/// Map one verification failure to its fail-closed admission decision.
///
/// [`CrossCitySignatureError::ReplayGuardUnavailable`] is the ONLY error
/// that means the outcome is genuinely unknown: the reservation may or may
/// not have been proven durable, so the only safe decision is `IN_DOUBT`
/// (reconcile later, never admit, never discard). Every other error is a
/// PROVEN property of the input - tampered fields, expired or non-canonical
/// evidence, wrong or unregistered signer identity, forged signature, or a
/// proven duplicate nonce - and lands in `QUARANTINED`.
///
/// Caveat pinned by the resolver contract: resolvers must return
/// [`CrossCitySignatureError::UnknownNodeKey`] only for a genuine "no key
/// registered for this exact identity" answer, never for infrastructure
/// outages. A resolver that cannot reach its registry must return a
/// different error (which this classification would conservatively route to
/// `IN_DOUBT` only if it is `ReplayGuardUnavailable`; any other resolver
/// outage error is quarantined and must be investigated through audit).
fn classify_verification_error(error: CrossCitySignatureError) -> CrossCityActivationAdmission {
    match error {
        CrossCitySignatureError::ReplayGuardUnavailable => {
            CrossCityActivationAdmission::InDoubt(error)
        }
        _ => CrossCityActivationAdmission::Quarantined(error),
    }
}

// ---------------------------------------------------------------------------
// Admission flow (gate -> verify signature -> replay reserve -> decision)
// ---------------------------------------------------------------------------

/// Admit (or refuse) one cross-city activation evidence.
///
/// Ordering is part of the contract:
///
/// 1. The runtime gate is checked FIRST. A disabled gate returns
///    [`CrossCityActivationAdmission::GateBlocked`] before the evidence is
///    touched: no resolver call, no signature check, no replay reservation.
/// 2. Everything else is delegated to
///    [`verify_zero_decision_evidence`], which pins the mandatory order
///    "verify the signature BEFORE reserving the replay nonce": strict
///    contract validation, canonical-form proof, signature decoding, exact
///    key-identity resolution, and strict Ed25519 verification ALL happen
///    before the replay guard is invoked, so the guard is never reached by
///    unverifiable input.
/// 3. A verified evidence is mapped by its PROVEN decision: `ALLOW` ->
///    [`CrossCityActivationAdmission::Admitted`], `DENY` ->
///    [`CrossCityActivationAdmission::Denied`].
/// 4. A verification failure is mapped fail-closed by
///    [`classify_verification_error`] (`ReplayGuardUnavailable` ->
///    `InDoubt`, everything else -> `Quarantined`).
///
/// This function is pure and synchronous. It performs no I/O of its own and
/// is NOT an authorization decision: `PolicyEngine.evaluate()` remains the
/// only authorization entry point.
pub fn admit_cross_city_activation<R, G>(
    gate: &CrossCityRuntimeGate,
    evidence: &ZeroDecisionEvidence,
    now_seconds: i64,
    resolver: &R,
    replay_guard: &G,
) -> CrossCityActivationAdmission
where
    R: CrossCityNodeKeyResolver,
    G: CrossCityReplayGuard,
{
    // Step 1: default-off gate. Nothing below runs while the mode is off.
    if !gate.is_enabled() {
        return CrossCityActivationAdmission::GateBlocked;
    }

    // Step 2-4: delegate to the frozen signature boundary (signature
    // verification strictly precedes the replay reservation inside it),
    // then map the outcome fail-closed.
    match verify_zero_decision_evidence(evidence, now_seconds, resolver, replay_guard) {
        Ok(verified) => match verified.evidence().decision {
            NodeDecision::Allow => CrossCityActivationAdmission::Admitted(verified),
            NodeDecision::Deny => CrossCityActivationAdmission::Denied(verified),
        },
        Err(error) => classify_verification_error(error),
    }
}

// ---------------------------------------------------------------------------
// In-memory, injectable adapters (NOT durable - see module docs)
// ---------------------------------------------------------------------------

/// In-memory, injectable [`CrossCityNodeKeyResolver`] adapter.
///
/// COMPOSITION-TEST AND REFERENCE SHAPE ONLY - NOT DURABLE. Records live in
/// a process-local map: restart loses them and replicas never share them.
/// The production durable node-key resolver MUST be implemented externally
/// against [`CrossCityNodeKeyResolver`].
///
/// Records are registered under their own exact identity and resolved by
/// that exact identity, so this adapter can never return a record whose
/// identity differs from the requested one (a misbehaving registry that
/// does is a production defect the verifier still catches as
/// [`CrossCitySignatureError::NodeKeyMismatch`]).
#[derive(Debug, Clone, Default)]
pub struct InMemoryCrossCityNodeKeyResolver {
    records: HashMap<CrossCityNodeIdentity, CrossCityNodeKeyRecord>,
}

impl InMemoryCrossCityNodeKeyResolver {
    /// Create an empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder form of [`Self::register`].
    #[must_use]
    pub fn with_record(mut self, record: CrossCityNodeKeyRecord) -> Self {
        self.register(record);
        self
    }

    /// Register one key record under its own exact identity.
    pub fn register(&mut self, record: CrossCityNodeKeyRecord) {
        self.records.insert(record.identity().clone(), record);
    }

    /// Whether the exact identity is registered.
    #[must_use]
    pub fn knows_identity(&self, identity: &CrossCityNodeIdentity) -> bool {
        self.records.contains_key(identity)
    }

    /// Number of registered records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether no record is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl CrossCityNodeKeyResolver for InMemoryCrossCityNodeKeyResolver {
    fn resolve_node_key(
        &self,
        identity: &CrossCityNodeIdentity,
    ) -> Result<CrossCityNodeKeyRecord, CrossCitySignatureError> {
        self.records
            .get(identity)
            .cloned()
            .ok_or(CrossCitySignatureError::UnknownNodeKey)
    }
}

/// In-memory, injectable [`CrossCityReplayGuard`] adapter.
///
/// COMPOSITION-TEST AND REFERENCE SHAPE ONLY - NOT DURABLE, NOT PROOF. The
/// reserved set lives in a process-local `RefCell`: process restart loses
/// every reservation, concurrent replicas never share them, and this guard
/// is not `Sync`. It must NEVER be presented as production replay
/// protection. The production durable replay guard MUST be implemented
/// externally against [`CrossCityReplayGuard`], with `reserve` running in
/// the same durable transaction as the evidence/vote insert.
#[derive(Debug, Clone, Default)]
pub struct InMemoryCrossCityReplayGuard {
    reserved: RefCell<HashSet<CrossCityEvidenceReplayKey>>,
}

impl InMemoryCrossCityReplayGuard {
    /// Create an empty guard.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the exact replay key is reserved.
    #[must_use]
    pub fn contains(&self, key: &CrossCityEvidenceReplayKey) -> bool {
        self.reserved.borrow().contains(key)
    }

    /// Number of reserved replay keys.
    #[must_use]
    pub fn reserved_count(&self) -> usize {
        self.reserved.borrow().len()
    }
}

impl CrossCityReplayGuard for InMemoryCrossCityReplayGuard {
    fn reserve(&self, key: &CrossCityEvidenceReplayKey) -> Result<(), CrossCitySignatureError> {
        if !self.reserved.borrow_mut().insert(key.clone()) {
            return Err(CrossCitySignatureError::NonceReplay);
        }
        Ok(())
    }
}

/// Always-unavailable [`CrossCityReplayGuard`] adapter.
///
/// COMPOSITION-TEST AND REFERENCE SHAPE ONLY - NOT DURABLE. Every
/// reservation attempt returns
/// [`CrossCitySignatureError::ReplayGuardUnavailable`], modelling a guard
/// outage so callers can prove the fail-closed `IN_DOUBT` behavior. The
/// production durable replay guard MUST be implemented externally.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableCrossCityReplayGuard;

impl UnavailableCrossCityReplayGuard {
    /// Create the unavailable guard.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl CrossCityReplayGuard for UnavailableCrossCityReplayGuard {
    fn reserve(&self, _key: &CrossCityEvidenceReplayKey) -> Result<(), CrossCitySignatureError> {
        Err(CrossCitySignatureError::ReplayGuardUnavailable)
    }
}

// ---------------------------------------------------------------------------
// Tests (pure: no network, no database, no cache, no external services)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet};
    use std::rc::Rc;

    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::cross_city_signature::cross_city_signature_message;

    /// The module source itself, pinned at compile time for source-shape tests.
    static MODULE_SOURCE: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        include_str!("cross_city_runtime.rs")
            .replace("\r\n", "\n")
            .split("#[cfg(test)]\nmod tests")
            .next()
            .expect("production source precedes the test module")
            .to_owned()
    });

    // -----------------------------------------------------------------------
    // Fixed test-only fixtures (never production key material)
    // -----------------------------------------------------------------------

    const TEST_CITY_ID: &str = "city-alpha";
    const TEST_NODE_ID: &str = "node-01";
    const TEST_OTHER_NODE_ID: &str = "node-02";
    const TEST_NODE_EPOCH: u64 = 7;

    /// Fixed test-only signing seed of the golden node.
    const TEST_SEED: [u8; 32] = *b"astral-cross-city-runtime-seed01";
    /// Second fixed test-only seed, used for wrong-key / mismatch fixtures.
    const TEST_SECOND_SEED: [u8; 32] = *b"astral-cross-city-runtime-seed02";

    /// Arbitrary 64 lowercase hex characters standing in for a proposal
    /// digest; the runtime boundary binds digests opaquely.
    const TEST_PROPOSAL_DIGEST: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    /// A second, different proposal digest (tampering / binding fixtures).
    const TEST_OTHER_PROPOSAL_DIGEST: &str =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const TEST_FRONTIER_DIGEST: &str =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const TEST_MUTATION_DIGEST: &str =
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const TEST_NONCE: &str = "runtime-nonce-001";
    const TEST_SECOND_NONCE: &str = "runtime-nonce-002";
    const TEST_EXPIRES_AT: i64 = 4102444800;
    const TEST_NOW: i64 = 1_700_000_000;

    // -----------------------------------------------------------------------
    // Recording test doubles (call-order and reservation observability)
    // -----------------------------------------------------------------------

    type EventLog = Rc<RefCell<Vec<&'static str>>>;

    fn event_log() -> EventLog {
        Rc::new(RefCell::new(Vec::new()))
    }

    /// Recording resolver over a fixed registry, including the ability to
    /// register a record under a WRONG lookup key to simulate a misbehaving
    /// registry returning a mismatched identity.
    struct RecordingResolver {
        records: HashMap<(String, String, u64), CrossCityNodeKeyRecord>,
        events: EventLog,
    }

    impl RecordingResolver {
        fn new(events: EventLog) -> Self {
            Self {
                records: HashMap::new(),
                events,
            }
        }

        fn with_record(self, record: CrossCityNodeKeyRecord) -> Self {
            let key = (
                record.identity().city_id().to_owned(),
                record.identity().node_id().to_owned(),
                record.identity().node_epoch(),
            );
            self.with_record_under(key, record)
        }

        fn with_record_under(
            mut self,
            key: (String, String, u64),
            record: CrossCityNodeKeyRecord,
        ) -> Self {
            self.records.insert(key, record);
            self
        }
    }

    impl CrossCityNodeKeyResolver for RecordingResolver {
        fn resolve_node_key(
            &self,
            identity: &CrossCityNodeIdentity,
        ) -> Result<CrossCityNodeKeyRecord, CrossCitySignatureError> {
            self.events.borrow_mut().push("resolver");
            let key = (
                identity.city_id().to_owned(),
                identity.node_id().to_owned(),
                identity.node_epoch(),
            );
            self.records
                .get(&key)
                .cloned()
                .ok_or(CrossCitySignatureError::UnknownNodeKey)
        }
    }

    /// Recording replay guard with the same semantics as the public
    /// in-memory adapter, plus call-order logging.
    struct RecordingGuard {
        reserved: RefCell<HashSet<CrossCityEvidenceReplayKey>>,
        events: EventLog,
    }

    impl RecordingGuard {
        fn new(events: EventLog) -> Self {
            Self {
                reserved: RefCell::new(HashSet::new()),
                events,
            }
        }

        fn reserved_count(&self) -> usize {
            self.reserved.borrow().len()
        }

        fn contains(&self, key: &CrossCityEvidenceReplayKey) -> bool {
            self.reserved.borrow().contains(key)
        }
    }

    impl CrossCityReplayGuard for RecordingGuard {
        fn reserve(&self, key: &CrossCityEvidenceReplayKey) -> Result<(), CrossCitySignatureError> {
            self.events.borrow_mut().push("replay_guard");
            if !self.reserved.borrow_mut().insert(key.clone()) {
                return Err(CrossCitySignatureError::NonceReplay);
            }
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    fn golden_identity() -> CrossCityNodeIdentity {
        CrossCityNodeIdentity::new(TEST_CITY_ID, TEST_NODE_ID, TEST_NODE_EPOCH)
            .expect("golden identity is valid")
    }

    fn record_for(seed: &[u8; 32], identity: CrossCityNodeIdentity) -> CrossCityNodeKeyRecord {
        let public_key_hex = hex::encode(SigningKey::from_bytes(seed).verifying_key().to_bytes());
        CrossCityNodeKeyRecord::from_public_key_hex(identity, &public_key_hex)
            .expect("test public key is canonical hex")
    }

    /// Build an evidence with a placeholder signature, compute the exact
    /// signed message from its canonical digest, sign it with `seed`, and
    /// rebuild the evidence with the real signature.
    fn signed_evidence_with(
        seed: &[u8; 32],
        node_id: &str,
        decision: NodeDecision,
        proposal_digest_hex: &str,
        nonce: &str,
        expires_at: i64,
    ) -> ZeroDecisionEvidence {
        let signing = SigningKey::from_bytes(seed);
        let unsigned = ZeroDecisionEvidence::new(
            TEST_CITY_ID,
            node_id,
            TEST_NODE_EPOCH,
            decision,
            proposal_digest_hex,
            TEST_FRONTIER_DIGEST,
            TEST_MUTATION_DIGEST,
            nonce,
            expires_at,
            &"a".repeat(128),
        )
        .expect("unsigned evidence is valid");
        let message = cross_city_signature_message(&unsigned.evidence_digest)
            .expect("signed message from canonical digest");
        let signature = signing.sign(&message);
        ZeroDecisionEvidence::new(
            TEST_CITY_ID,
            node_id,
            TEST_NODE_EPOCH,
            decision,
            proposal_digest_hex,
            TEST_FRONTIER_DIGEST,
            TEST_MUTATION_DIGEST,
            nonce,
            expires_at,
            &hex::encode(signature.to_bytes()),
        )
        .expect("signed evidence is valid")
    }

    fn golden_allow_evidence() -> ZeroDecisionEvidence {
        signed_evidence_with(
            &TEST_SEED,
            TEST_NODE_ID,
            NodeDecision::Allow,
            TEST_PROPOSAL_DIGEST,
            TEST_NONCE,
            TEST_EXPIRES_AT,
        )
    }

    fn golden_deny_evidence() -> ZeroDecisionEvidence {
        signed_evidence_with(
            &TEST_SEED,
            TEST_NODE_ID,
            NodeDecision::Deny,
            TEST_PROPOSAL_DIGEST,
            TEST_SECOND_NONCE,
            TEST_EXPIRES_AT,
        )
    }

    fn enabled_gate() -> CrossCityRuntimeGate {
        CrossCityRuntimeGate::enabled()
    }

    // -----------------------------------------------------------------------
    // Default-off gate
    // -----------------------------------------------------------------------

    #[test]
    // Deliberate compile-time pin: the build must fail if anyone flips the
    // default-off constant or the fail-closed gate default.
    #[allow(clippy::assertions_on_constants)]
    fn runtime_mode_is_default_off_at_compile_time_and_by_default_gate() {
        assert!(!CROSS_CITY_RUNTIME_MODE_DEFAULT_ENABLED);
        assert!(!CrossCityRuntimeGate::default().is_enabled());
        assert!(!CrossCityRuntimeGate::disabled().is_enabled());
        // Enablement is only possible through the explicit constructor.
        assert!(CrossCityRuntimeGate::enabled().is_enabled());
        assert_eq!(
            CROSS_CITY_RUNTIME_MODE_DEFAULT_ENABLED,
            astral_types::CROSS_CITY_MODE_DEFAULT_ENABLED
        );
    }

    #[test]
    fn gate_off_blocks_everything_before_any_evaluation() {
        let evidence = golden_allow_evidence();
        let events = event_log();
        let resolver = RecordingResolver::new(events.clone())
            .with_record(record_for(&TEST_SEED, golden_identity()));
        let guard = RecordingGuard::new(events.clone());

        let admission = admit_cross_city_activation(
            &CrossCityRuntimeGate::disabled(),
            &evidence,
            TEST_NOW,
            &resolver,
            &guard,
        );

        assert!(!admission.is_admitted());
        assert!(matches!(
            admission,
            CrossCityActivationAdmission::GateBlocked
        ));
        assert_eq!(admission.as_str(), "GATE_BLOCKED");
        // Nothing was evaluated: no resolver call, no signature check, no
        // replay reservation.
        assert!(events.borrow().is_empty());
        assert_eq!(guard.reserved_count(), 0);
    }

    // -----------------------------------------------------------------------
    // ALLOW / DENY happy paths
    // -----------------------------------------------------------------------

    #[test]
    fn verified_allow_evidence_is_admitted_with_capability() {
        let evidence = golden_allow_evidence();
        let events = event_log();
        let resolver = RecordingResolver::new(events.clone())
            .with_record(record_for(&TEST_SEED, golden_identity()));
        let guard = RecordingGuard::new(events.clone());

        let admission =
            admit_cross_city_activation(&enabled_gate(), &evidence, TEST_NOW, &resolver, &guard);

        assert!(admission.is_admitted());
        assert_eq!(admission.as_str(), "ADMITTED");
        let verified = admission
            .verified_evidence()
            .expect("admitted carries the capability");
        assert_eq!(verified.evidence().decision, NodeDecision::Allow);
        assert_eq!(
            verified.evidence().evidence_digest,
            evidence.evidence_digest
        );
        assert_eq!(verified.verified_at_seconds(), TEST_NOW);
        assert!(admission.verification_error().is_none());
        // Signature verification strictly precedes the replay reservation.
        assert_eq!(*events.borrow(), vec!["resolver", "replay_guard"]);
        assert_eq!(guard.reserved_count(), 1);
        assert!(guard.contains(verified.replay_key()));
    }

    #[test]
    fn verified_deny_evidence_is_denied_and_never_admitted() {
        let evidence = golden_deny_evidence();
        let resolver = RecordingResolver::new(event_log())
            .with_record(record_for(&TEST_SEED, golden_identity()));
        let guard = RecordingGuard::new(event_log());

        let admission =
            admit_cross_city_activation(&enabled_gate(), &evidence, TEST_NOW, &resolver, &guard);

        assert!(!admission.is_admitted());
        assert_eq!(admission.as_str(), "DENIED");
        let verified = admission
            .verified_evidence()
            .expect("denied carries the verified evidence");
        assert_eq!(verified.evidence().decision, NodeDecision::Deny);
        assert!(admission.verification_error().is_none());
        // A DENY evidence still verified, so its nonce was reserved; the
        // decision itself is nonetheless a proven refusal.
        assert_eq!(guard.reserved_count(), 1);
    }

    // -----------------------------------------------------------------------
    // Fail-closed verification paths
    // -----------------------------------------------------------------------

    #[test]
    fn unknown_node_key_is_quarantined_without_reservation() {
        let evidence = golden_allow_evidence();
        let events = event_log();
        let resolver = RecordingResolver::new(events.clone()); // empty registry
        let guard = RecordingGuard::new(events.clone());

        let admission =
            admit_cross_city_activation(&enabled_gate(), &evidence, TEST_NOW, &resolver, &guard);

        assert!(!admission.is_admitted());
        assert_eq!(admission.as_str(), "QUARANTINED");
        assert_eq!(
            admission.verification_error(),
            Some(&CrossCitySignatureError::UnknownNodeKey)
        );
        assert_eq!(admission.verified_evidence(), None);
        // The guard is never reached by unverifiable input.
        assert_eq!(*events.borrow(), vec!["resolver"]);
        assert_eq!(guard.reserved_count(), 0);
    }

    #[test]
    fn identity_mismatch_is_quarantined_without_reservation() {
        let evidence = golden_allow_evidence();
        // The registry answers the exact lookup key with a record belonging
        // to a DIFFERENT node identity: a misbehaving resolver.
        let other_identity =
            CrossCityNodeIdentity::new(TEST_CITY_ID, TEST_OTHER_NODE_ID, TEST_NODE_EPOCH)
                .expect("other identity is valid");
        let mismatched_record = record_for(&TEST_SECOND_SEED, other_identity);
        let events = event_log();
        let resolver = RecordingResolver::new(events.clone()).with_record_under(
            (
                TEST_CITY_ID.to_owned(),
                TEST_NODE_ID.to_owned(),
                TEST_NODE_EPOCH,
            ),
            mismatched_record,
        );
        let guard = RecordingGuard::new(events.clone());

        let admission =
            admit_cross_city_activation(&enabled_gate(), &evidence, TEST_NOW, &resolver, &guard);

        assert!(!admission.is_admitted());
        assert_eq!(admission.as_str(), "QUARANTINED");
        assert_eq!(
            admission.verification_error(),
            Some(&CrossCitySignatureError::NodeKeyMismatch)
        );
        assert_eq!(guard.reserved_count(), 0);
    }

    #[test]
    fn invalid_signature_is_quarantined_without_reservation() {
        // Signed by a DIFFERENT key than the one registered for the identity.
        let evidence = signed_evidence_with(
            &TEST_SECOND_SEED,
            TEST_NODE_ID,
            NodeDecision::Allow,
            TEST_PROPOSAL_DIGEST,
            TEST_NONCE,
            TEST_EXPIRES_AT,
        );
        let events = event_log();
        let resolver = RecordingResolver::new(events.clone())
            .with_record(record_for(&TEST_SEED, golden_identity()));
        let guard = RecordingGuard::new(events.clone());

        let admission =
            admit_cross_city_activation(&enabled_gate(), &evidence, TEST_NOW, &resolver, &guard);

        assert!(!admission.is_admitted());
        assert_eq!(admission.as_str(), "QUARANTINED");
        assert_eq!(
            admission.verification_error(),
            Some(&CrossCitySignatureError::InvalidSignature)
        );
        assert_eq!(guard.reserved_count(), 0);
    }

    #[test]
    fn replayed_evidence_is_quarantined_and_never_reserved_twice() {
        let evidence = golden_allow_evidence();
        let resolver = RecordingResolver::new(event_log())
            .with_record(record_for(&TEST_SEED, golden_identity()));
        let guard = RecordingGuard::new(event_log());

        let first =
            admit_cross_city_activation(&enabled_gate(), &evidence, TEST_NOW, &resolver, &guard);
        assert!(first.is_admitted());

        let second =
            admit_cross_city_activation(&enabled_gate(), &evidence, TEST_NOW, &resolver, &guard);
        assert!(!second.is_admitted());
        assert_eq!(second.as_str(), "QUARANTINED");
        assert_eq!(
            second.verification_error(),
            Some(&CrossCitySignatureError::NonceReplay)
        );
        // Exactly one reservation exists, from the first admission.
        assert_eq!(guard.reserved_count(), 1);
    }

    #[test]
    fn replay_guard_unavailable_is_in_doubt_and_never_admitted() {
        let evidence = golden_allow_evidence();
        let resolver = InMemoryCrossCityNodeKeyResolver::new()
            .with_record(record_for(&TEST_SEED, golden_identity()));
        let guard = UnavailableCrossCityReplayGuard::new();

        let admission =
            admit_cross_city_activation(&enabled_gate(), &evidence, TEST_NOW, &resolver, &guard);

        assert!(!admission.is_admitted());
        assert_eq!(admission.as_str(), "IN_DOUBT");
        assert_eq!(
            admission.verification_error(),
            Some(&CrossCitySignatureError::ReplayGuardUnavailable)
        );
        assert_eq!(admission.verified_evidence(), None);
    }

    #[test]
    fn expired_evidence_is_quarantined() {
        let evidence = golden_allow_evidence();
        let resolver = InMemoryCrossCityNodeKeyResolver::new()
            .with_record(record_for(&TEST_SEED, golden_identity()));
        let guard = InMemoryCrossCityReplayGuard::new();

        // The expiry bound is exclusive: now == expires_at is expired.
        let admission = admit_cross_city_activation(
            &enabled_gate(),
            &evidence,
            TEST_EXPIRES_AT,
            &resolver,
            &guard,
        );

        assert!(!admission.is_admitted());
        assert_eq!(admission.as_str(), "QUARANTINED");
        assert_eq!(
            admission.verification_error(),
            Some(&CrossCitySignatureError::ExpiredEvidence {
                now_seconds: TEST_EXPIRES_AT,
                expires_at: TEST_EXPIRES_AT,
            })
        );
        assert_eq!(guard.reserved_count(), 0);
    }

    #[test]
    fn tampered_evidence_digest_is_quarantined() {
        let mut evidence = golden_allow_evidence();
        evidence.evidence_digest = TEST_OTHER_PROPOSAL_DIGEST.to_owned();
        let resolver = InMemoryCrossCityNodeKeyResolver::new()
            .with_record(record_for(&TEST_SEED, golden_identity()));
        let guard = InMemoryCrossCityReplayGuard::new();

        let admission =
            admit_cross_city_activation(&enabled_gate(), &evidence, TEST_NOW, &resolver, &guard);

        assert!(!admission.is_admitted());
        assert_eq!(admission.as_str(), "QUARANTINED");
        assert_eq!(
            admission.verification_error(),
            Some(&CrossCitySignatureError::ContractRejected)
        );
        assert_eq!(guard.reserved_count(), 0);
    }

    // -----------------------------------------------------------------------
    // Public adapter behavior
    // -----------------------------------------------------------------------

    #[test]
    fn in_memory_resolver_resolves_exact_identity_and_fails_closed_on_unknown() {
        let identity = golden_identity();
        let record = record_for(&TEST_SEED, identity.clone());
        let mut resolver = InMemoryCrossCityNodeKeyResolver::new();
        assert!(resolver.is_empty());
        resolver.register(record.clone());
        assert_eq!(resolver.len(), 1);
        assert!(resolver.knows_identity(&identity));

        let resolved = resolver.resolve_node_key(&identity).expect("exact hit");
        assert_eq!(resolved.identity(), &identity);
        assert_eq!(resolved, record);

        let unknown = CrossCityNodeIdentity::new(TEST_CITY_ID, TEST_OTHER_NODE_ID, 1)
            .expect("unknown identity is valid");
        assert_eq!(
            resolver.resolve_node_key(&unknown),
            Err(CrossCitySignatureError::UnknownNodeKey)
        );
    }

    #[test]
    fn in_memory_guard_reserves_once_and_rejects_duplicates() {
        let identity = golden_identity();
        let evidence = golden_allow_evidence();
        let key = CrossCityEvidenceReplayKey::new(
            identity.city_id(),
            identity.node_id(),
            identity.node_epoch(),
            &evidence.nonce,
            &evidence.evidence_digest,
        )
        .expect("replay key is valid");
        let guard = InMemoryCrossCityReplayGuard::new();

        assert!(guard.reserve(&key).is_ok());
        assert!(guard.contains(&key));
        assert_eq!(guard.reserved_count(), 1);
        assert_eq!(
            guard.reserve(&key),
            Err(CrossCitySignatureError::NonceReplay)
        );
        assert_eq!(guard.reserved_count(), 1);
    }

    #[test]
    fn unavailable_guard_always_fails_closed() {
        let key = CrossCityEvidenceReplayKey::new(
            TEST_CITY_ID,
            TEST_NODE_ID,
            TEST_NODE_EPOCH,
            TEST_NONCE,
            TEST_PROPOSAL_DIGEST,
        )
        .expect("replay key is valid");
        assert_eq!(
            UnavailableCrossCityReplayGuard::new().reserve(&key),
            Err(CrossCitySignatureError::ReplayGuardUnavailable)
        );
    }

    // -----------------------------------------------------------------------
    // Decision surface
    // -----------------------------------------------------------------------

    #[test]
    fn admission_codes_are_stable_and_distinct() {
        let codes = [
            CrossCityActivationAdmission::GateBlocked.as_str(),
            CrossCityActivationAdmission::InDoubt(CrossCitySignatureError::ReplayGuardUnavailable)
                .as_str(),
            CrossCityActivationAdmission::Quarantined(CrossCitySignatureError::ContractRejected)
                .as_str(),
        ];
        assert_eq!(codes[0], "GATE_BLOCKED");
        assert_eq!(codes[1], "IN_DOUBT");
        assert_eq!(codes[2], "QUARANTINED");
        // Distinctness of every code the runtime can produce.
        let verified = {
            let evidence = golden_allow_evidence();
            let resolver = InMemoryCrossCityNodeKeyResolver::new()
                .with_record(record_for(&TEST_SEED, golden_identity()));
            let guard = InMemoryCrossCityReplayGuard::new();
            admit_cross_city_activation(&enabled_gate(), &evidence, TEST_NOW, &resolver, &guard)
        };
        let deny_code = {
            let evidence = golden_deny_evidence();
            let resolver = InMemoryCrossCityNodeKeyResolver::new()
                .with_record(record_for(&TEST_SEED, golden_identity()));
            let guard = InMemoryCrossCityReplayGuard::new();
            admit_cross_city_activation(&enabled_gate(), &evidence, TEST_NOW, &resolver, &guard)
        };
        let all = [
            codes[0],
            codes[1],
            codes[2],
            verified.as_str(),
            deny_code.as_str(),
        ];
        assert_eq!(all[3], "ADMITTED");
        assert_eq!(all[4], "DENIED");
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j]);
            }
        }
    }

    #[test]
    fn admission_debug_output_leaks_no_signature_material() {
        let evidence = golden_allow_evidence();
        let resolver = InMemoryCrossCityNodeKeyResolver::new()
            .with_record(record_for(&TEST_SEED, golden_identity()));
        let guard = InMemoryCrossCityReplayGuard::new();

        let admitted =
            admit_cross_city_activation(&enabled_gate(), &evidence, TEST_NOW, &resolver, &guard);
        let rendered = format!("{admitted:?}");
        assert!(rendered.contains("ADMITTED"));
        assert!(rendered.contains(TEST_NODE_ID));
        assert!(!rendered.contains(&evidence.signature));
        assert!(!rendered.contains(&evidence.nonce));

        let quarantined = admit_cross_city_activation(
            &enabled_gate(),
            &golden_allow_evidence(),
            TEST_NOW,
            &InMemoryCrossCityNodeKeyResolver::new(),
            &InMemoryCrossCityReplayGuard::new(),
        );
        let rendered = format!("{quarantined:?}");
        assert!(rendered.contains("QUARANTINED"));
        assert!(rendered.contains("CROSS_CITY_NODE_KEY_UNKNOWN"));
        assert!(!rendered.contains(&evidence.signature));
    }

    // -----------------------------------------------------------------------
    // Source-shape pins
    // -----------------------------------------------------------------------

    #[test]
    fn source_shape_pins_default_off_constant_and_flow_order() {
        assert!(MODULE_SOURCE
            .contains("pub const CROSS_CITY_RUNTIME_MODE_DEFAULT_ENABLED: bool = false;"));
        // The gate check precedes the verification call in the flow source,
        // so a disabled gate can never reach the evidence.
        let gate_check = MODULE_SOURCE
            .find("if !gate.is_enabled()")
            .expect("gate check exists in flow");
        let verify_call = MODULE_SOURCE
            .find("verify_zero_decision_evidence(evidence, now_seconds, resolver, replay_guard)")
            .expect("flow delegates to the frozen verifier");
        assert!(gate_check < verify_call);
        // The fail-closed classification is pinned in source.
        assert!(MODULE_SOURCE.contains("CrossCityActivationAdmission::InDoubt(error)"));
        assert!(MODULE_SOURCE.contains("CrossCityActivationAdmission::Quarantined(error)"));
    }

    #[test]
    fn source_shape_pins_nondurability_of_adapters() {
        // The adapters must never be documented or named as durable.
        assert!(MODULE_SOURCE.contains("NOT DURABLE"));
        assert!(MODULE_SOURCE.contains("MUST be implemented\n/// externally"));
        // Built dynamically so this assertion cannot trip over its own text.
        let forbidden = format!("durable {}memory", "in");
        assert!(!MODULE_SOURCE.to_lowercase().contains(&forbidden));
    }
}
