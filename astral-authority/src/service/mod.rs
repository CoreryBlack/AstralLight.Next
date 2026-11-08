//! Authority business logic: fence reads, reservations, commits,
//! certification and reconciliation.
//!
//! Fail-closed rules implemented here:
//! - Fence reads are linearizable and never advance the global frontier.
//!   Proof issuance records durable quorum-side bindings (fresh proof
//!   identity, caller nonce freshness, immutable policy-request digest), so a
//!   source intent can only reference a proof the authority itself issued for
//!   the exact same request digest. A service-supplied proof id alone can
//!   never create new authorization.
//! - Mutations require the quorum leader role; a standby never signs.
//! - Prepare enforces the lease window BEFORE acceptance, accepts an intent
//!   exactly once (put-if-absent), verifies the issued proof and the active
//!   frontier inside one atomic CAS transaction, and reports unknown etcd
//!   outcomes as [`AuthorityServiceError::UnknownOutcome`] — reconcile by
//!   stable reservation identity; never retry blindly.
//! - Positive reads stay blocked (GLOBAL coverage by default) while any
//!   reservation is pending, unknown or quarantined. Lease expiry never
//!   clears a reservation.
//! - Certification verifies the caller-supplied completion digest against a
//!   canonical recomputation over intent/before/after/manifest identities and
//!   only signs when reservation, intent, and image binding all match.
//!   Arbitrary database contents are never signed.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use astral_types::{
    AuthorityCallerIdentity, AuthorityCertifyRequest, AuthorityCertifyResponse,
    AuthorityCloseReservationRequest, AuthorityCloseReservationResponse, AuthorityCommitRequest,
    AuthorityCommitResponse, AuthorityExpectedFrontier, AuthorityFenceReadRequest,
    AuthorityFenceReadResponse, AuthorityIntentAcceptance, AuthorityManifestIdentity,
    AuthorityPrepareRequest, AuthorityPrepareResponse, AuthorityProtocolError,
    AuthorityProtocolScope, AuthorityReadGate, AuthorityReadProofRequest,
    AuthorityReconcileRequest, AuthorityReconcileResponse, AuthorityReconciliation,
    AuthorityReservationCoverage, AuthorityReservationDisposition, AuthorityReservationState,
    AuthorityScopePublicationCertificate, AuthorityScopeReservation, AuthoritySourceIntent,
    AuthorityStartupAttestation, AuthorityTrustRoot, AuthorizationFenceProof,
    GlobalAuthorityFrontier, AUTHORITY_PROTOCOL_VERSION, AUTHORIZATION_EDITION,
};
use sha2::{Digest, Sha256};

use crate::config::AuthorityServiceConfig;
use crate::error::{AuthorityServiceError, AuthorityStoreError};
use crate::signing::ProtectedAuthoritySigner;
use crate::store::{AuthorityStore, KeyLayout, StoreOp, StoreTxn, StoreTxnOutcome};

pub(crate) mod abort;
pub(crate) mod bootstrap;
mod certificate_records;
mod config_completion;
mod coverage;
mod eligibility_completion;
mod historical_frontier;
/// Durable leadership fence (lease-backed leader key + exact token compare).
/// See [`leadership`] for the §15.9.1 contract and the only safe install path.
pub mod leadership;
mod source_bootstrap;

/// Durable genesis value: the signed record plus the trust root it blesses.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredGenesis {
    pub record: astral_types::AuthorityGenesisRecord,
    pub trust_root: AuthorityTrustRoot,
}

/// Durable trust-root state: genesis anchor plus verified rotation chain.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredTrustRootState {
    pub root_id: String,
    pub genesis_trust_root_digest: String,
    pub active: AuthorityTrustRoot,
    pub rotations: Vec<astral_types::AuthorityKeyRotationCertificate>,
}

/// Durable intent acceptance record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredIntentRecord {
    pub intent_digest: String,
    pub reservation_id: String,
    pub accepted_at: i64,
    pub intent: AuthoritySourceIntent,
}

/// Durable proof receipt: the quorum-side identity binding of one issued
/// proof. Written atomically with the proof and the nonce index at mint time.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredProofReceipt {
    pub proof_id: String,
    pub request_nonce: String,
    /// Immutable policy-request digest this proof was minted for.
    pub request_binding_digest: String,
    /// Declared mutation kind; the later intent must carry the same kind.
    pub mutation_kind: astral_types::AuthorityMutationKind,
    /// Stable operation/event identity of the policy request (signed into
    /// the proof and matched by the later source intent).
    pub operation_id: String,
    pub event_id: String,
    pub caller_service_id: String,
    pub actor_scope_key: String,
    pub source_scope_key: String,
    pub authority_term: u64,
    pub global_fence_sequence: u64,
    pub key_epoch: u64,
    pub issued_at: i64,
    pub expires_at: i64,
}

/// Durable per-scope current publication pointer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredScopeCurrent {
    pub scope_key_text: String,
    pub snapshot_hash: String,
    pub scope_generation: u64,
    pub revoke_watermark: u64,
    pub certificate_hash: String,
    pub certificate_id: String,
    pub key_epoch: u64,
    pub updated_at: i64,
}

/// Verified authority state returned by one linearizable pass.
#[derive(Debug, Clone)]
pub struct VerifiedAuthorityState {
    pub genesis_trust_root: AuthorityTrustRoot,
    pub rotations: Vec<astral_types::AuthorityKeyRotationCertificate>,
    pub trust_root: AuthorityTrustRoot,
    pub frontier: GlobalAuthorityFrontier,
    /// etcd/memory revision of the frontier record; the CAS token for the
    /// next frontier advance.
    pub frontier_revision: u64,
    /// Monotonic read-gate epoch; every reservation mutation bumps it, and
    /// proof minting CAS-pins it so a proof can never be minted across a
    /// reservation change that the mint did not observe.
    pub gate_epoch: u64,
    pub gate_epoch_revision: u64,
}

/// Durable read-gate epoch: a single-key fencing token for the reservation
/// set. Any prepare/commit/certify/close replaces it under CAS, so read-proof
/// minting can compare exactly one revision instead of a whole prefix.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredGateEpoch {
    pub epoch: u64,
}

impl AuthorityService {
    /// CAS op that bumps the read-gate epoch to `state.gate_epoch + 1`.
    fn bump_gate_epoch_op(
        &self,
        state: &VerifiedAuthorityState,
    ) -> Result<StoreOp, AuthorityServiceError> {
        let next = state
            .gate_epoch
            .checked_add(1)
            .ok_or(AuthorityServiceError::Protocol(
                AuthorityProtocolError::InvalidCounter {
                    field: "gate_epoch",
                },
            ))?;
        Ok(StoreOp::ReplaceIfRevision {
            key: self.keys.gate_epoch(),
            expected_revision: state.gate_epoch_revision,
            value: encode(&StoredGateEpoch { epoch: next })?,
        })
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0)
}

fn fresh_id(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, AuthorityServiceError> {
    serde_json::to_vec(value).map_err(|_| {
        AuthorityServiceError::Protocol(AuthorityProtocolError::CanonicalSerialization)
    })
}

fn decode<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    what: &'static str,
) -> Result<T, AuthorityServiceError> {
    serde_json::from_slice(bytes)
        .map_err(|_| AuthorityServiceError::Store(AuthorityStoreError::Corrupt(what.to_owned())))
}

/// Stable digest over the two digest anchors of one mutation; feeds the
/// global chain digest derivation.
pub(crate) fn mutation_digest(first: &str, second: &str) -> String {
    fn field(bytes: &mut Vec<u8>, value: &str) {
        bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    let mut bytes = Vec::with_capacity(192);
    bytes.extend_from_slice(b"ASTRAL_AUTHORITY_MUTATION_DIGEST_V1\0");
    field(&mut bytes, first);
    field(&mut bytes, second);
    sha256_hex(&bytes)
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The authority service. Not `Clone`: the signer stays unique.
pub struct AuthorityService {
    config: AuthorityServiceConfig,
    keys: KeyLayout,
    store: Arc<dyn AuthorityStore>,
    signer: Arc<ProtectedAuthoritySigner>,
    leader: Arc<AtomicBool>,
    /// Durable leadership term (lease-backed leader key + exact token
    /// compare). Empty until the election or a CLI path binds through
    /// [`AuthorityService::bind_leadership_token`]; mutating transactions and
    /// read-only signing artifacts are gated by it (§15.9.1).
    leadership: leadership::LeadershipFence,
}

impl AuthorityService {
    pub fn new(
        config: AuthorityServiceConfig,
        store: Arc<dyn AuthorityStore>,
        signer: Arc<ProtectedAuthoritySigner>,
    ) -> Self {
        let keys = KeyLayout::new(&config.quorum.key_prefix);
        Self {
            leader: Arc::new(AtomicBool::new(false)),
            leadership: leadership::LeadershipFence::new(),
            config,
            keys,
            store,
            signer,
        }
    }

    /// Leader handle used by the election task to publish leadership state.
    pub fn leader_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.leader)
    }

    pub fn is_leader(&self) -> bool {
        self.leader.load(Ordering::Acquire)
    }

    pub fn config(&self) -> &AuthorityServiceConfig {
        &self.config
    }

    pub fn store(&self) -> &Arc<dyn AuthorityStore> {
        &self.store
    }

    pub fn keys(&self) -> &KeyLayout {
        &self.keys
    }

    fn require_leader(&self) -> Result<(), AuthorityServiceError> {
        if self.is_leader() {
            Ok(())
        } else {
            Err(AuthorityServiceError::NotLeader)
        }
    }

    fn require_active_signer(
        &self,
        state: &VerifiedAuthorityState,
    ) -> Result<(), AuthorityServiceError> {
        if self.signer.matches_trust_root(&state.trust_root)? {
            Ok(())
        } else {
            Err(AuthorityServiceError::SignerUnavailable)
        }
    }

    async fn verify_signing_frontier(
        &self,
        expected: &GlobalAuthorityFrontier,
    ) -> Result<(), AuthorityServiceError> {
        let state = self.load_verified_state().await?;
        self.require_active_signer(&state)?;
        if state.frontier != *expected {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::FrontierDiverged,
            ));
        }
        match self
            .execute_leader_txn(StoreTxn::new().with_op(StoreOp::RequireValue {
                key: self.keys.frontier(),
                value: encode(expected)?,
            }))
            .await?
        {
            StoreTxnOutcome::Applied { .. } => Ok(()),
            StoreTxnOutcome::PreconditionFailed { .. } => Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::FrontierDiverged,
            )),
        }
    }

    fn authorize(
        &self,
        caller: &AuthorityCallerIdentity,
        operation: &'static str,
    ) -> Result<(), AuthorityServiceError> {
        caller.validate().map_err(AuthorityServiceError::Protocol)?;
        match self.config.trusted_source_by_id(&caller.service_id) {
            Some(source) if source.allowed_operations.iter().any(|op| op == operation) => Ok(()),
            _ => Err(AuthorityServiceError::NotAuthorized {
                caller: caller.service_id.clone(),
                operation,
            }),
        }
    }

    /// Linearizable read and full verification of the durable trust chain.
    pub async fn load_verified_state(
        &self,
    ) -> Result<VerifiedAuthorityState, AuthorityServiceError> {
        let genesis_record = self.store.get(&self.keys.genesis()).await?.ok_or_else(|| {
            AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                "genesis record is missing; run the root-owned genesis tool".to_owned(),
            ))
        })?;
        let stored_genesis: StoredGenesis = decode(&genesis_record.value, "genesis record")?;
        stored_genesis
            .record
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        stored_genesis
            .trust_root
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        if stored_genesis.record.trust_root_digest
            != self.config.identity.pinned_genesis_trust_root_digest
            || stored_genesis.record.trust_root_digest
                != stored_genesis
                    .trust_root
                    .digest()
                    .map_err(AuthorityServiceError::Protocol)?
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::TrustRootMismatch,
            ));
        }
        let genesis_key = stored_genesis
            .trust_root
            .genesis_key()
            .map_err(AuthorityServiceError::Protocol)?
            .verifying_key()
            .map_err(AuthorityServiceError::Protocol)?;
        stored_genesis
            .record
            .verify(&stored_genesis.trust_root, &genesis_key)
            .map_err(AuthorityServiceError::Protocol)?;
        if stored_genesis.record.authority_id != self.config.identity.authority_id {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::CallerIdentityMismatch,
            ));
        }

        let root_record = self
            .store
            .get(&self.keys.trust_root())
            .await?
            .ok_or_else(|| {
                AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "trust root state is missing".to_owned(),
                ))
            })?;
        let root_state: StoredTrustRootState = decode(&root_record.value, "trust root state")?;
        if root_state.root_id != stored_genesis.trust_root.root_id
            || root_state.genesis_trust_root_digest != stored_genesis.record.trust_root_digest
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::TrustRootMismatch,
            ));
        }
        let mut active = stored_genesis.trust_root.clone();
        for rotation in &root_state.rotations {
            if rotation.authority_id != self.config.identity.authority_id {
                return Err(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::CallerIdentityMismatch,
                ));
            }
            let root_key = active
                .root_key()
                .map_err(AuthorityServiceError::Protocol)?
                .verifying_key()
                .map_err(AuthorityServiceError::Protocol)?;
            active = rotation
                .verify_after(&active, &root_key)
                .map_err(AuthorityServiceError::Protocol)?;
        }
        if root_state.active != active {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::TrustRootMismatch,
            ));
        }

        let frontier_record = self
            .store
            .get(&self.keys.frontier())
            .await?
            .ok_or_else(|| {
                AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "global frontier is missing; genesis must initialize it".to_owned(),
                ))
            })?;
        let frontier: GlobalAuthorityFrontier = decode(&frontier_record.value, "global frontier")?;
        frontier
            .matches_trust_root(&active)
            .map_err(AuthorityServiceError::Protocol)?;
        if frontier.authority_id != self.config.identity.authority_id {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::CallerIdentityMismatch,
            ));
        }
        let gate_epoch_record =
            self.store
                .get(&self.keys.gate_epoch())
                .await?
                .ok_or_else(|| {
                    AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                        "read-gate epoch is missing; genesis must initialize it".to_owned(),
                    ))
                })?;
        let gate_epoch: StoredGateEpoch = decode(&gate_epoch_record.value, "gate epoch")?;
        Ok(VerifiedAuthorityState {
            genesis_trust_root: stored_genesis.trust_root,
            rotations: root_state.rotations,
            trust_root: active,
            frontier,
            frontier_revision: frontier_record.revision,
            gate_epoch: gate_epoch.epoch,
            gate_epoch_revision: gate_epoch_record.revision,
        })
    }

    /// Build the fail-closed read gate from all durable reservations.
    async fn evaluate_read_gate(&self) -> Result<AuthorityReadGate, AuthorityServiceError> {
        let reservations = self
            .store
            .get_prefix(&self.keys.reservations_prefix())
            .await?;
        let mut blocking = Vec::new();
        for (_, record) in reservations {
            let reservation: AuthorityScopeReservation = decode(&record.value, "reservation")?;
            reservation
                .validate()
                .map_err(AuthorityServiceError::Protocol)?;
            // ProtectedBusiness reservations never enter the read barrier:
            // they terminate on the proven source commit.
            if reservation.state.blocks_positive_reads()
                && reservation.intent.mutation_kind.blocks_positive_reads()
            {
                blocking.push(astral_types::AuthorityReservationSummary {
                    reservation_id: reservation.reservation_id.clone(),
                    operation_id: reservation.intent.operation_id.clone(),
                    mutation_kind: reservation.intent.mutation_kind,
                    state: reservation.state,
                    coverage: reservation.intent.coverage.clone(),
                    created_at: reservation.created_at,
                });
            }
        }
        let bootstrap_reservations = self
            .store
            .get_prefix(&self.keys.source_bootstrap_reservations_prefix())
            .await?;
        for (_, record) in bootstrap_reservations {
            let reservation: astral_types::AuthoritySourceBootstrapReservation =
                decode(&record.value, "source bootstrap reservation")?;
            reservation
                .validate()
                .map_err(AuthorityServiceError::Protocol)?;
            if reservation.state == astral_types::AuthoritySourceBootstrapState::Reserved {
                blocking.push(astral_types::AuthorityReservationSummary {
                    reservation_id: reservation.reservation_id,
                    operation_id: reservation.operation_id,
                    mutation_kind: astral_types::AuthorityMutationKind::AuthorizationSource,
                    state: astral_types::AuthorityReservationState::Reserved,
                    coverage: astral_types::AuthorityReservationCoverage::Global,
                    created_at: reservation.created_at,
                });
            }
        }
        AuthorityReadGate::evaluate(blocking).map_err(AuthorityServiceError::Protocol)
    }

    /// Startup attestation for callers pinning the genesis trust root. The
    /// caller identity comes from the authenticated transport, not the body.
    pub async fn startup_attestation(
        &self,
        transport_service_id: &str,
    ) -> Result<AuthorityStartupAttestation, AuthorityServiceError> {
        // Reuse the caller validation for the transport-derived identity.
        AuthorityCallerIdentity {
            service_id: transport_service_id.to_owned(),
            request_nonce: "attestation".to_owned(),
            issued_at: 1,
        }
        .validate()
        .map_err(AuthorityServiceError::Protocol)?;
        self.verify_leadership_fenced().await?;
        let state = self.load_verified_state().await?;
        self.require_active_signer(&state)?;
        let issued_at = now_unix();
        let mut attestation = AuthorityStartupAttestation {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: self.config.identity.authority_id.clone(),
            global_frontier: state.frontier,
            trust_root: state.trust_root,
            genesis_trust_root: state.genesis_trust_root,
            rotations: state.rotations,
            leader: self.is_leader(),
            attestation_nonce: fresh_id("attest"),
            issued_at,
            expires_at: issued_at + 60,
            attestation_key_id: self.signer.key_id().to_owned(),
            signature: String::new(),
        };
        let bytes = attestation
            .signing_bytes()
            .map_err(AuthorityServiceError::Protocol)?;
        attestation.signature = self.signer.sign_checked(&bytes, true)?;
        attestation
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        self.verify_signing_frontier(&attestation.global_frontier)
            .await?;
        Ok(attestation)
    }

    /// Linearizable fence read. Never advances the frontier.
    pub async fn read_fence(
        &self,
        request: &AuthorityFenceReadRequest,
    ) -> Result<AuthorityFenceReadResponse, AuthorityServiceError> {
        self.authorize(&request.caller, "read_fence")?;
        request
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        let state = self.load_verified_state().await?;
        let read_gate = self.evaluate_read_gate().await?;
        let observed_at = now_unix();

        let mut scope_certificate = None;
        let mut scope_certificate_hash = None;
        if let Some(scope) = &request.scope {
            // Card publications live at the canonical (tenant, card)
            // identity: every user/domain lens of one card resolves to the
            // SAME immutable certificate. ORG scopes stay exact. The pointer
            // itself is a cache: resolve it through the verified certificate
            // record, never trust it alone.
            let (_publication_scope, scope_key) =
                certificate_records::publication_pointer_scope(scope)
                    .map_err(AuthorityServiceError::Protocol)?;
            match certificate_records::load_verified_scope_publication(
                self.store.as_ref(),
                &self.keys,
                &state,
                &scope_key,
            )
            .await?
            {
                None => {
                    if request.expected_certificate_hash.is_some() {
                        return Err(AuthorityServiceError::Protocol(
                            AuthorityProtocolError::FrontierDiverged,
                        ));
                    }
                }
                Some(publication) => {
                    if let Some(expected) = &request.expected_certificate_hash {
                        if expected != &publication.pointer.certificate_hash {
                            return Err(AuthorityServiceError::Protocol(
                                AuthorityProtocolError::FrontierDiverged,
                            ));
                        }
                    }
                    scope_certificate_hash = Some(publication.pointer.certificate_hash);
                    scope_certificate = Some(publication.certificate);
                }
            }
        }

        let proof = match &request.read_proof {
            Some(read_proof) => Some(
                self.mint_read_proof(read_proof, &state, &read_gate, &request.caller)
                    .await?,
            ),
            None => None,
        };

        Ok(AuthorityFenceReadResponse {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            authorization_edition: AUTHORIZATION_EDITION,
            global_frontier: state.frontier,
            read_gate,
            scope_certificate,
            scope_certificate_hash,
            proof,
            observed_at,
        })
    }

    /// Mint one fresh, nonce-bound, receipt-backed read proof.
    ///
    /// The proof content identity always comes from a certified publication
    /// (`source_scope`), never from caller-claimed values. The receipt binds
    /// proof identity + caller nonce + immutable policy-request digest
    /// quorum-side, atomically with proof issuance.
    async fn mint_read_proof(
        &self,
        read_proof: &AuthorityReadProofRequest,
        state: &VerifiedAuthorityState,
        read_gate: &AuthorityReadGate,
        caller: &AuthorityCallerIdentity,
    ) -> Result<AuthorizationFenceProof, AuthorityServiceError> {
        read_proof
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        self.require_leader()?;
        self.require_active_signer(state)?;
        let actor_scope_key = read_proof
            .actor_scope
            .store_key_text()
            .map_err(AuthorityServiceError::Protocol)?;
        // The proof binds the certified content of the CANONICAL publication
        // of the bound scope: card lenses share the immutable certificate,
        // while each proof keeps its exact actor lens below. ORG scopes stay
        // exact. The actor lens key itself is never canonicalized.
        let (_publication_scope, source_pointer_key) =
            certificate_records::publication_pointer_scope(read_proof.bound_scope())
                .map_err(AuthorityServiceError::Protocol)?;

        // Blocking is evaluated before the publication lookup so a pending
        // source operation always yields the actionable blocked signal. Card
        // blocking is identity-closed: any lens of a blocked (tenant, card)
        // blocks every other lens of the same card, while other cards and ORG
        // scopes are never conflated.
        if read_gate
            .blocks(&read_proof.actor_scope)
            .map_err(AuthorityServiceError::Protocol)?
            || read_gate
                .blocks(read_proof.bound_scope())
                .map_err(AuthorityServiceError::Protocol)?
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ReadsBlocked {
                    reservation_id: read_gate
                        .blocking_reservations
                        .first()
                        .map(|summary| summary.reservation_id.clone())
                        .unwrap_or_default(),
                },
            ));
        }

        // The proof content identity is resolved through the verified
        // certificate record behind the canonical publication pointer, never
        // the cached pointer and never a lens-specific key.
        let publication = certificate_records::load_verified_scope_publication(
            self.store.as_ref(),
            &self.keys,
            state,
            &source_pointer_key,
        )
        .await?
        .ok_or(AuthorityServiceError::Protocol(
            AuthorityProtocolError::NotFound {
                record: "scope_publication",
            },
        ))?;
        let scope_current = &publication.pointer;
        let scope_current_revision = publication.pointer_revision;

        if let Some(expected) = &read_proof.expected_frontier {
            let current = AuthorityExpectedFrontier {
                authority_term: state.frontier.authority_term,
                global_fence_sequence: state.frontier.global_fence_sequence,
                scope_generation: scope_current.scope_generation,
                revoke_watermark: scope_current.revoke_watermark,
                snapshot_hash: scope_current.snapshot_hash.clone(),
            };
            if expected != &current {
                return Err(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::FrontierDiverged,
                ));
            }
        }

        let issued_at = now_unix();
        let ttl = read_proof
            .proof_ttl_seconds
            .unwrap_or(self.config.policy.proof_ttl_seconds);
        let proof_id = fresh_id("prf");
        let receipt = StoredProofReceipt {
            proof_id: proof_id.clone(),
            request_nonce: read_proof.request_nonce.clone(),
            request_binding_digest: read_proof.request_binding_digest.clone(),
            mutation_kind: read_proof.mutation_kind,
            operation_id: read_proof.operation_id.clone(),
            event_id: read_proof.event_id.clone(),
            caller_service_id: caller.service_id.clone(),
            // Exact request lens for the actor; the source binds the actual
            // canonical certificate the proof content was drawn from.
            actor_scope_key: actor_scope_key.clone(),
            source_scope_key: source_pointer_key.clone(),
            authority_term: state.frontier.authority_term,
            global_fence_sequence: state.frontier.global_fence_sequence,
            key_epoch: state.frontier.key_epoch,
            issued_at,
            expires_at: issued_at + ttl,
        };

        let mut proof = AuthorizationFenceProof {
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: self.config.identity.authority_id.clone(),
            authority_term: state.frontier.authority_term,
            global_fence_sequence: state.frontier.global_fence_sequence,
            scope: match &read_proof.actor_scope {
                AuthorityProtocolScope::Card(card) => card.clone(),
                AuthorityProtocolScope::Org(_) => {
                    return Err(AuthorityServiceError::Protocol(
                        AuthorityProtocolError::ScopeMismatch,
                    ))
                }
            },
            scope_generation: scope_current.scope_generation,
            revoke_watermark: scope_current.revoke_watermark,
            snapshot_hash: scope_current.snapshot_hash.clone(),
            parent_hash: None,
            // Signed proof-to-certificate binding (V7): the proof content
            // identity is exactly the certified publication it was minted
            // from; `parent_hash` stays reserved for frontier chaining.
            scope_certificate_hash: Some(scope_current.certificate_hash.clone()),
            request_binding_digest: Some(read_proof.request_binding_digest.clone()),
            // The proof carries the policy request's stable operation and
            // event identity, not a server-side constant.
            operation_id: read_proof.operation_id.clone(),
            event_id: read_proof.event_id.clone(),
            key_id: self.signer.key_id().to_owned(),
            key_epoch: self.signer.key_epoch(),
            issued_at,
            not_before: issued_at,
            expires_at: issued_at + ttl,
            request_nonce: read_proof.request_nonce.clone(),
            proof_id,
            signature: String::new(),
        };
        let signing_bytes = proof
            .signing_bytes()
            .map_err(|error| AuthorityServiceError::Protocol(error.into()))?;
        proof.signature = self.signer.sign_checked(&signing_bytes, true)?;

        // One atomic quorum step: the minted proof is only valid while the
        // frontier, the certified scope pointer, AND the read-gate epoch are
        // exactly the observations it was signed against. A concurrent
        // prepare/commit/certify between the linearizable reads above and
        // this transaction fails the CAS and the mint is refused — a stale
        // ALLOW can never be minted. Proof identity, caller binding digest,
        // and nonce freshness remain single-use within the same transaction.
        let outcome = self
            .execute_leader_txn(
                StoreTxn::new()
                    .with_op(StoreOp::ReplaceIfRevision {
                        key: self.keys.frontier(),
                        expected_revision: state.frontier_revision,
                        value: encode(&state.frontier)?,
                    })
                    .with_op(StoreOp::ReplaceIfRevision {
                        key: self.keys.scope_current(&source_pointer_key),
                        expected_revision: scope_current_revision,
                        value: publication.pointer_value.clone(),
                    })
                    .with_op(StoreOp::ReplaceIfRevision {
                        key: self.keys.gate_epoch(),
                        expected_revision: state.gate_epoch_revision,
                        value: encode(&StoredGateEpoch {
                            epoch: state.gate_epoch,
                        })?,
                    })
                    .with_op(StoreOp::PutIfAbsent {
                        key: self.keys.proof_receipt(&proof.proof_id),
                        value: encode(&proof)?,
                    })
                    .with_op(StoreOp::PutIfAbsent {
                        key: self.keys.proof_binding(&proof.proof_id),
                        value: encode(&receipt)?,
                    })
                    .with_op(StoreOp::PutIfAbsent {
                        key: self
                            .keys
                            .proof_nonce(&actor_scope_key, &read_proof.request_nonce),
                        value: encode(&receipt)?,
                    }),
            )
            .await?;
        match outcome {
            StoreTxnOutcome::Applied { .. } => Ok(proof),
            StoreTxnOutcome::PreconditionFailed { .. } => {
                // Discriminate deterministically: a nonce/proof collision
                // means the nonce index now exists; anything else is a stale
                // observation. Never retried; the caller re-reads.
                let nonce_collision = self
                    .store
                    .get(
                        &self
                            .keys
                            .proof_nonce(&actor_scope_key, &read_proof.request_nonce),
                    )
                    .await?
                    .is_some();
                if nonce_collision {
                    Err(AuthorityServiceError::Protocol(
                        AuthorityProtocolError::AlreadyExists {
                            record: "read_proof_nonce",
                        },
                    ))
                } else {
                    Err(AuthorityServiceError::Protocol(
                        AuthorityProtocolError::FrontierDiverged,
                    ))
                }
            }
        }
    }

    /// Accept one approved source intent and reserve its scopes.
    pub async fn prepare_source_mutation(
        &self,
        request: &AuthorityPrepareRequest,
    ) -> Result<AuthorityPrepareResponse, AuthorityServiceError> {
        self.authorize(&request.caller, "prepare")?;
        request
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        self.require_leader()?;
        let intent = &request.intent;
        let intent_digest = intent.digest().map_err(AuthorityServiceError::Protocol)?;

        // Conservative coverage: GLOBAL until exact coverage is established.
        if !self.config.policy.exact_scope_coverage_enabled
            && !matches!(intent.coverage, AuthorityReservationCoverage::Global)
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::InvalidCoverage,
            ));
        }

        // Registered source process and database identities.
        let source = self.config.trusted_source_by_id(&intent.service_id).ok_or(
            AuthorityServiceError::NotAuthorized {
                caller: intent.service_id.clone(),
                operation: "prepare",
            },
        )?;
        if !source.allowed_database_ids.contains(&intent.database_id) {
            return Err(AuthorityServiceError::NotAuthorized {
                caller: intent.database_id.clone(),
                operation: "prepare",
            });
        }

        // Lease window is checked BEFORE acceptance: a source replay after
        // lease expiry is refused even if the original prepare never applied.
        let now = now_unix();
        if now < intent.lease_not_before || now >= intent.lease_expires_at {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::LeaseExpired,
            ));
        }

        // The referenced proof must be one this authority issued, still
        // unexpired, and bound quorum-side to the exact request digest.
        let proof_record = self
            .store
            .get(&self.keys.proof_receipt(&intent.admission_proof_id))
            .await?
            .ok_or(AuthorityServiceError::Protocol(
                AuthorityProtocolError::NotFound {
                    record: "admission_proof",
                },
            ))?;
        let proof: AuthorizationFenceProof = decode(&proof_record.value, "admission proof")?;
        proof
            .validate()
            .map_err(|error| AuthorityServiceError::Protocol(error.into()))?;
        if proof.expires_at <= now {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::LeaseExpired,
            ));
        }
        // The proof must carry EXACTLY the current frontier: the mint CAS
        // pinned it to one frontier; any later reserve/commit/rotation makes
        // it stale. This rejects stale ALLOW proofs for AuthorizationSource
        // AND ProtectedBusiness alike, barrier or not.
        let state = self.load_verified_state().await?;
        self.require_active_signer(&state)?;
        if proof.authority_term != state.frontier.authority_term
            || proof.global_fence_sequence != state.frontier.global_fence_sequence
            || proof.key_epoch != state.frontier.key_epoch
            || proof.key_id != state.frontier.key_id
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::FrontierDiverged,
            ));
        }
        // The scopes the intent would block must not already be blocked by
        // another in-flight reservation.
        let current_gate = self.evaluate_read_gate().await?;
        if intent.mutation_kind.blocks_positive_reads() {
            let covered: Vec<&AuthorityProtocolScope> = match &intent.coverage {
                AuthorityReservationCoverage::Global => Vec::new(),
                AuthorityReservationCoverage::Exact(scopes) => scopes.iter().collect(),
            };
            if intent.coverage.is_global() || !covered.is_empty() {
                let blocked = if intent.coverage.is_global() {
                    !current_gate.blocking_reservations.is_empty()
                } else {
                    covered.iter().any(|scope| {
                        current_gate
                            .blocks(scope)
                            .map_err(AuthorityServiceError::Protocol)
                            .unwrap_or(true)
                    })
                };
                if blocked {
                    return Err(AuthorityServiceError::Protocol(
                        AuthorityProtocolError::ReadsBlocked {
                            reservation_id: current_gate
                                .blocking_reservations
                                .first()
                                .map(|summary| summary.reservation_id.clone())
                                .unwrap_or_default(),
                        },
                    ));
                }
            }
        }
        // The quorum-side receipt binds the proof to BOTH the immutable
        // policy-request digest AND the caller service identity that minted
        // it: a service-supplied proof id alone never creates authorization.
        // The intent must belong to the authenticated caller: the authorize
        // role check does not bind the service identity by itself.
        if intent.service_id != request.caller.service_id {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::CallerIdentityMismatch,
            ));
        }
        let binding_record = self
            .store
            .get(&self.keys.proof_binding(&intent.admission_proof_id))
            .await?
            .ok_or(AuthorityServiceError::Protocol(
                AuthorityProtocolError::NotFound {
                    record: "admission_binding",
                },
            ))?;
        let proof_receipt: StoredProofReceipt = decode(&binding_record.value, "admission binding")?;
        if proof_receipt.proof_id != proof.proof_id
            || proof_receipt.request_nonce != proof.request_nonce
            || proof_receipt.authority_term != proof.authority_term
            || proof_receipt.global_fence_sequence != proof.global_fence_sequence
            || proof_receipt.key_epoch != proof.key_epoch
            || proof_receipt.expires_at != proof.expires_at
            || current_gate
                .blocks_scope_key(&proof_receipt.actor_scope_key)
                .map_err(AuthorityServiceError::Protocol)?
            || current_gate
                .blocks_scope_key(&proof_receipt.source_scope_key)
                .map_err(AuthorityServiceError::Protocol)?
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch,
            ));
        }
        if proof_receipt.request_binding_digest != intent.request_digest {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::DigestMismatch {
                    field: "request_digest",
                },
            ));
        }
        if proof_receipt.caller_service_id != intent.service_id {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::CallerIdentityMismatch,
            ));
        }
        // The intent must be the very operation the proof was minted for,
        // with the same declared mutation kind.
        if proof_receipt.operation_id != intent.operation_id
            || proof_receipt.event_id != intent.event_id
            || proof_receipt.mutation_kind != intent.mutation_kind
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch,
            ));
        }

        let reservation_id = fresh_id("res");
        let reservation = AuthorityScopeReservation {
            reservation_id: reservation_id.clone(),
            intent_digest: intent_digest.clone(),
            intent: intent.clone(),
            state: AuthorityReservationState::Reserved,
            authority_term: state.frontier.authority_term,
            fence_sequence_at_prepare: state.frontier.global_fence_sequence,
            created_at: now,
            updated_at: now,
            committed_at: None,
            source_commit_digest: None,
            after_image_digest: None,
            certificate_id: None,
            certified_scopes: Vec::new(),
            source_outcome_digest: None,
        };
        reservation
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        let next_frontier = state
            .frontier
            .advance(&intent.operation_id, &intent_digest, now)
            .map_err(AuthorityServiceError::Protocol)?;

        let intent_record = StoredIntentRecord {
            intent_digest: intent_digest.clone(),
            reservation_id: reservation_id.clone(),
            accepted_at: now,
            intent: intent.clone(),
        };
        let mut txn = StoreTxn::new()
            .with_op(StoreOp::PutIfAbsent {
                key: self.keys.intent(&intent_digest),
                value: encode(&intent_record)?,
            })
            .with_op(StoreOp::PutIfAbsent {
                key: self.keys.reservation(&reservation_id),
                value: encode(&reservation)?,
            })
            .with_op(StoreOp::ReplaceIfRevision {
                key: self.keys.frontier(),
                expected_revision: state.frontier_revision,
                value: encode(&next_frontier)?,
            })
            .with_op(self.bump_gate_epoch_op(&state)?);
        if intent.mutation_kind.blocks_positive_reads() {
            txn = txn.with_op(StoreOp::PutIfAbsent {
                key: self.keys.source_bootstrap_global_lock(),
                value: encode(&(
                    intent.operation_id.clone(),
                    reservation_id.clone(),
                    intent_digest.clone(),
                ))?,
            });
        }
        let outcome = self
            .execute_leader_txn(
                txn
                    // One issued admission proof authorizes at most one
                    // intent acceptance; the consume marker is atomic with
                    // the reservation so a replayed proof cannot prepare a
                    // second mutation.
                    .with_op(StoreOp::PutIfAbsent {
                        key: self.keys.proof_consumed(&intent.admission_proof_id),
                        value: reservation_id.clone().into_bytes(),
                    }),
            )
            .await;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => return Err(self.map_store_error(error, &reservation_id)),
        };
        match outcome {
            StoreTxnOutcome::PreconditionFailed { .. } => {
                // Discriminate deterministically: if the frontier or gate
                // epoch advanced between the linearizable reads and this
                // transaction, the proof is now stale (re-read and re-mint
                // deliberately, never retry); otherwise the intent/proof
                // duplicate is the conflict.
                let fresh = self.load_verified_state().await?;
                if fresh.frontier.global_fence_sequence != state.frontier.global_fence_sequence
                    || fresh.frontier.authority_term != state.frontier.authority_term
                    || fresh.gate_epoch != state.gate_epoch
                {
                    Err(AuthorityServiceError::Protocol(
                        AuthorityProtocolError::FrontierDiverged,
                    ))
                } else {
                    Err(AuthorityServiceError::Protocol(
                        AuthorityProtocolError::AlreadyExists {
                            record: "intent_or_proof",
                        },
                    ))
                }
            }
            StoreTxnOutcome::Applied { .. } => {
                let mut acceptance = AuthorityIntentAcceptance {
                    authorization_edition: AUTHORIZATION_EDITION,
                    authority_id: self.config.identity.authority_id.clone(),
                    intent_digest,
                    reservation_id: reservation_id.clone(),
                    authority_term: next_frontier.authority_term,
                    global_fence_sequence: next_frontier.global_fence_sequence,
                    key_id: self.signer.key_id().to_owned(),
                    key_epoch: self.signer.key_epoch(),
                    accepted_at: now,
                    acceptance_nonce: fresh_id("acc"),
                    signature: String::new(),
                };
                let bytes = acceptance
                    .signing_bytes()
                    .map_err(AuthorityServiceError::Protocol)?;
                self.verify_signing_frontier(&next_frontier).await?;
                acceptance.signature = self.signer.sign_checked(&bytes, true)?;
                self.verify_signing_frontier(&next_frontier).await?;
                acceptance
                    .validate()
                    .map_err(AuthorityServiceError::Protocol)?;
                let read_gate = self.evaluate_read_gate().await?;
                Ok(AuthorityPrepareResponse {
                    acceptance,
                    reservation,
                    global_frontier: next_frontier,
                    read_gate,
                })
            }
        }
    }

    /// Record the durable source commit against a reserved scope.
    pub async fn record_source_commit(
        &self,
        request: &AuthorityCommitRequest,
    ) -> Result<AuthorityCommitResponse, AuthorityServiceError> {
        self.authorize(&request.caller, "commit")?;
        request
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        self.require_leader()?;
        let now = now_unix();

        let reservation_record = self
            .store
            .get(&self.keys.reservation(&request.commit.reservation_id))
            .await?
            .ok_or(AuthorityServiceError::Protocol(
                AuthorityProtocolError::NotFound {
                    record: "reservation",
                },
            ))?;
        let mut reservation: AuthorityScopeReservation =
            decode(&reservation_record.value, "reservation")?;
        reservation
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        if reservation.intent.service_id != request.caller.service_id
            || reservation.intent.database_id != request.database_id
            || reservation.intent.operation_id != request.commit.operation_id
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::CallerIdentityMismatch,
            ));
        }
        if reservation.state != AuthorityReservationState::Reserved {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "reservation",
                    state: reservation.state.as_text().to_owned(),
                },
            ));
        }

        // Two-phase before-image binding: when the intent pinned a
        // before-image digest it must match exactly; the source-pinned
        // actual digest is required otherwise.
        match (
            &reservation.intent.before_image_digest,
            &request.commit.before_image_digest,
        ) {
            (Some(pinned), Some(actual)) if pinned == actual => {
                let _ = pinned;
            }
            (Some(_), Some(_)) => {
                return Err(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::DigestMismatch {
                        field: "before_image_digest",
                    },
                ))
            }
            (Some(_), None) => {
                return Err(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::DigestMismatch {
                        field: "before_image_digest",
                    },
                ))
            }
            (None, None) => {
                return Err(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::DigestMismatch {
                        field: "before_image_digest",
                    },
                ))
            }
            (None, Some(_)) => {}
        }
        if let AuthorityReservationCoverage::Exact(scopes) = &reservation.intent.coverage {
            let expected = astral_types::AuthorityStagedScopeCoverage {
                scopes: scopes.clone(),
            };
            let actual =
                request
                    .declared_coverage
                    .as_ref()
                    .ok_or(AuthorityServiceError::Protocol(
                        AuthorityProtocolError::InvalidCoverage,
                    ))?;
            if expected
                .coverage_digest()
                .map_err(AuthorityServiceError::Protocol)?
                != actual
                    .coverage_digest()
                    .map_err(AuthorityServiceError::Protocol)?
            {
                return Err(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::InvalidCoverage,
                ));
            }
        }
        let state = self.load_verified_state().await?;
        let digest = mutation_digest(
            &request.commit.source_commit_digest,
            &request.commit.after_image_digest,
        );
        let next_frontier = state
            .frontier
            .advance(&request.commit.operation_id, &digest, now)
            .map_err(AuthorityServiceError::Protocol)?;
        reservation.state = AuthorityReservationState::Committed;
        reservation.committed_at = Some(now);
        reservation.source_commit_digest = Some(request.commit.source_commit_digest.clone());
        reservation.after_image_digest = Some(request.commit.after_image_digest.clone());
        reservation.source_outcome_digest = Some(request.commit.source_outcome_digest.clone());
        reservation.updated_at = now;
        reservation
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;

        let binding = astral_types::AuthorityCommitBinding {
            reservation_id: reservation.reservation_id.clone(),
            operation_id: reservation.intent.operation_id.clone(),
            event_id: reservation.intent.event_id.clone(),
            admission_proof_id: reservation.intent.admission_proof_id.clone(),
            mutation_kind: reservation.intent.mutation_kind,
            service_id: reservation.intent.service_id.clone(),
            database_id: reservation.intent.database_id.clone(),
            request_digest: reservation.intent.request_digest.clone(),
            source_commit_digest: request.commit.source_commit_digest.clone(),
            before_image_digest: request.commit.before_image_digest.clone(),
            after_image_digest: request.commit.after_image_digest.clone(),
            source_outcome_digest: request.commit.source_outcome_digest.clone(),
            staged_evidence_digest: request.commit.staged_evidence_digest.clone(),
        };
        binding
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        let coverage = self.source_commit_coverage(request, &reservation, &binding)?;
        let outcome = self
            .execute_leader_txn(
                StoreTxn::new()
                    .with_op(StoreOp::PutIfAbsent {
                        key: self.keys.commit_binding(&request.commit.reservation_id),
                        value: encode(&binding)?,
                    })
                    .with_op(StoreOp::PutIfAbsent {
                        key: self.keys.commit_coverage(&request.commit.reservation_id),
                        value: encode(&coverage)?,
                    })
                    .with_op(StoreOp::ReplaceIfRevision {
                        key: self.keys.reservation(&request.commit.reservation_id),
                        expected_revision: reservation_record.revision,
                        value: encode(&reservation)?,
                    })
                    .with_op(StoreOp::ReplaceIfRevision {
                        key: self.keys.frontier(),
                        expected_revision: state.frontier_revision,
                        value: encode(&next_frontier)?,
                    })
                    .with_op(self.bump_gate_epoch_op(&state)?),
            )
            .await;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => return Err(self.map_store_error(error, &request.commit.reservation_id)),
        };
        match outcome {
            StoreTxnOutcome::PreconditionFailed { .. } => Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "reservation",
                    state: "CONCURRENT".to_owned(),
                },
            )),
            StoreTxnOutcome::Applied { .. } => {
                let read_gate = self.evaluate_read_gate().await?;
                Ok(AuthorityCommitResponse {
                    disposition: AuthorityReservationDisposition::Committed,
                    reservation: Some(reservation),
                    binding,
                    global_frontier: next_frontier,
                    read_gate,
                })
            }
        }
    }

    /// Certify the publication of one committed reservation.
    pub async fn certify_publication(
        &self,
        request: &AuthorityCertifyRequest,
    ) -> Result<AuthorityCertifyResponse, AuthorityServiceError> {
        self.authorize(&request.caller, "certify")?;
        request
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        if request
            .scope
            .canonical_card_publication_scope()
            .is_some_and(|canonical| canonical != request.scope)
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch,
            ));
        }
        self.require_leader()?;
        let now = now_unix();

        let reservation_record = self
            .store
            .get(&self.keys.reservation(&request.reservation_id))
            .await?
            .ok_or(AuthorityServiceError::Protocol(
                AuthorityProtocolError::NotFound {
                    record: "reservation",
                },
            ))?;
        let mut reservation: AuthorityScopeReservation =
            decode(&reservation_record.value, "reservation")?;
        reservation
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        if reservation.intent.service_id != request.caller.service_id {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::CallerIdentityMismatch,
            ));
        }
        if !matches!(
            reservation.state,
            AuthorityReservationState::Committed
                | AuthorityReservationState::Published
                | AuthorityReservationState::Certified
        ) {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "reservation",
                    state: reservation.state.as_text().to_owned(),
                },
            ));
        }
        if reservation.intent.mutation_kind
            != astral_types::AuthorityMutationKind::AuthorizationSource
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "reservation",
                    state: "PROTECTED_BUSINESS_NO_PUBLICATION".to_owned(),
                },
            ));
        }
        let after_image_digest = reservation.after_image_digest.clone().ok_or_else(|| {
            AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                "committed reservation lacks after image".to_owned(),
            ))
        })?;
        if after_image_digest != request.after_image_digest {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::DigestMismatch {
                    field: "after_image_digest",
                },
            ));
        }

        // The immutable prepare coverage stays in force throughout publication.
        // A GLOBAL source may separately declare complete finite coverage at
        // COMMIT; that declaration is verified below against its exact binding.
        match &reservation.intent.coverage {
            AuthorityReservationCoverage::Global => {}
            AuthorityReservationCoverage::Exact(scopes) => {
                if !scopes.contains(&request.scope) {
                    return Err(AuthorityServiceError::Protocol(
                        AuthorityProtocolError::ScopeMismatch,
                    ));
                }
            }
        }
        // Source outcome digest must be bound at commit and match the
        // certification request exactly.
        let bound_outcome_digest =
            reservation
                .source_outcome_digest
                .clone()
                .ok_or(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::StateConflict {
                        record: "reservation",
                        state: "NO_OUTCOME_DIGEST".to_owned(),
                    },
                ))?;
        if bound_outcome_digest != request.source_outcome_digest {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::DigestMismatch {
                    field: "source_outcome_digest",
                },
            ));
        }
        let binding_record = self
            .store
            .get(&self.keys.commit_binding(&request.reservation_id))
            .await?
            .ok_or_else(|| {
                AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "source commit binding is missing".to_owned(),
                ))
            })?;
        let binding: astral_types::AuthorityCommitBinding =
            decode(&binding_record.value, "source commit binding")?;
        binding
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        if binding.reservation_id != reservation.reservation_id
            || binding.operation_id != reservation.intent.operation_id
            || binding.event_id != reservation.intent.event_id
            || binding.admission_proof_id != reservation.intent.admission_proof_id
            || binding.service_id != reservation.intent.service_id
            || binding.database_id != reservation.intent.database_id
            || binding.request_digest != reservation.intent.request_digest
            || binding.mutation_kind != reservation.intent.mutation_kind
            || Some(binding.source_commit_digest.as_str())
                != reservation.source_commit_digest.as_deref()
            || binding.after_image_digest != request.after_image_digest
            || binding.source_outcome_digest != request.source_outcome_digest
            || binding.before_image_digest != request.before_image_digest
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch,
            ));
        }
        let coverage = self.load_commit_coverage(&reservation, &binding).await?;
        if !coverage.permits_scope(&request.scope)? {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch,
            ));
        }
        let scope_key_text = request
            .scope
            .store_key_text()
            .map_err(AuthorityServiceError::Protocol)?;
        if reservation.certified_scopes.contains(&scope_key_text) {
            let stored = self
                .store
                .get(
                    &self
                        .keys
                        .reservation_certificate(&request.reservation_id, &scope_key_text),
                )
                .await?
                .ok_or_else(|| {
                    AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                        "scope certification index is missing".to_owned(),
                    ))
                })?;
            let certificate_id: String = decode(&stored.value, "scope certification index")?;
            let stored = self
                .store
                .get(&self.keys.certificate(&certificate_id))
                .await?
                .ok_or_else(|| {
                    AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                        "scope certificate is missing".to_owned(),
                    ))
                })?;
            let certificate: AuthorityScopePublicationCertificate =
                decode(&stored.value, "scope certificate")?;
            let state = self.load_verified_state().await?;
            certificate_records::verify_certificate_record(&state, &certificate_id, &certificate)?;
            if certificate.reservation_id != request.reservation_id
                || certificate.intent_digest != reservation.intent_digest
                || certificate.operation_id != binding.operation_id
                || certificate.event_id != binding.event_id
                || certificate.approved_request_digest != binding.request_digest
                || certificate.source_commit_digest != binding.source_commit_digest
                || certificate.authority_term != reservation.authority_term
                || certificate.global_fence_sequence != reservation.fence_sequence_at_prepare
                || certificate.scope != request.scope
                || certificate.before_image_digest != request.before_image_digest
                || certificate.after_image_digest != request.after_image_digest
                || certificate.source_outcome_digest != request.source_outcome_digest
                || certificate.snapshot_hash != request.snapshot_hash
                || certificate.manifests != request.manifests
                || certificate.completion_digest != request.completion_digest
            {
                return Err(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::ScopeMismatch,
                ));
            }
            return Ok(AuthorityCertifyResponse {
                certificate,
                proof: None,
                reservation,
                global_frontier: state.frontier,
                read_gate: self.evaluate_read_gate().await?,
            });
        }
        if reservation.state == AuthorityReservationState::Certified {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "reservation",
                    state: "CERTIFIED".to_owned(),
                },
            ));
        }

        let state = self.load_verified_state().await?;
        self.require_active_signer(&state)?;
        // The publication parent is resolved through the VERIFIED previous
        // certificate record: signature, id/hash, snapshot and manifest
        // frontier are re-proven before they can anchor the next generation.
        let previous_publication = certificate_records::load_verified_scope_publication(
            self.store.as_ref(),
            &self.keys,
            &state,
            &scope_key_text,
        )
        .await?;
        let (scope_current_op, parent_certificate_hash) = match &previous_publication {
            Some(previous) => (
                previous.pointer_revision,
                Some(previous.pointer.certificate_hash.clone()),
            ),
            None => (0, None),
        };
        let (scope_generation, revoke_watermark) =
            manifest_frontier(&request.manifests).map_err(AuthorityServiceError::Protocol)?;
        if let Some(previous) = &previous_publication {
            let (previous_generation, previous_revoke_watermark) =
                manifest_frontier(&previous.certificate.manifests)
                    .map_err(AuthorityServiceError::Protocol)?;
            if scope_generation < previous_generation
                || revoke_watermark < previous_revoke_watermark
            {
                return Err(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::FrontierDiverged,
                ));
            }
        }
        // Per-aggregate continuity: nothing published may be dropped, move
        // generation/revoke backwards, or change identity at an unchanged
        // generation — the frontier maximum never masks a local regression.
        certificate_records::verify_publication_frontier_continuity(
            previous_publication
                .as_ref()
                .map(|previous| &previous.certificate),
            &request.manifests,
        )
        .map_err(AuthorityServiceError::Protocol)?;

        let before_image_digest = binding.before_image_digest.clone();

        let certificate_id = fresh_id("cert");
        // The certificate binds the IMMUTABLE RESERVATION FRONTIER (recorded
        // at prepare), not the current moving frontier — so the caller can
        // precompute the completion digest exactly.
        let mut certificate = AuthorityScopePublicationCertificate {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: self.config.identity.authority_id.clone(),
            authority_term: reservation.authority_term,
            global_fence_sequence: reservation.fence_sequence_at_prepare,
            certificate_id: certificate_id.clone(),
            intent_digest: reservation.intent_digest.clone(),
            reservation_id: reservation.reservation_id.clone(),
            operation_id: reservation.intent.operation_id.clone(),
            event_id: reservation.intent.event_id.clone(),
            scope: request.scope.clone(),
            approved_request_digest: reservation.intent.request_digest.clone(),
            before_image_digest,
            after_image_digest: after_image_digest.clone(),
            source_commit_digest: reservation.source_commit_digest.clone().unwrap_or_default(),
            completion_digest: request.completion_digest.clone(),
            snapshot_hash: request.snapshot_hash.clone(),
            parent_certificate_hash: parent_certificate_hash.clone(),
            source_outcome_digest: request.source_outcome_digest.clone(),
            manifests: request.manifests.clone(),
            key_id: self.signer.key_id().to_owned(),
            key_epoch: self.signer.key_epoch(),
            issued_at: now,
            not_before: now,
            expires_at: None,
            certificate_nonce: fresh_id("certn"),
            signature: String::new(),
        };
        // Verify-before-sign over intent/before/after/parent/manifest
        // identities; the parent certificate hash is derived from the
        // durable scope pointer, never caller-asserted.
        let recomputed = certificate
            .recompute_completion_digest()
            .map_err(AuthorityServiceError::Protocol)?;
        if recomputed != request.completion_digest {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::DigestMismatch {
                    field: "completion_digest",
                },
            ));
        }
        let cert_bytes = certificate
            .signing_bytes()
            .map_err(AuthorityServiceError::Protocol)?;
        certificate.signature = self.signer.sign_checked(&cert_bytes, true)?;
        certificate
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        let certificate_hash = certificate
            .record_digest()
            .map_err(AuthorityServiceError::Protocol)?;

        let digest = mutation_digest(&certificate_hash, &after_image_digest);
        let next_frontier = state
            .frontier
            .advance(&reservation.intent.operation_id, &digest, now)
            .map_err(AuthorityServiceError::Protocol)?;

        // Fresh card proof binds the publication's resulting frontier. It is
        // stored exactly like a minted read proof — full signed proof,
        // quorum-side binding receipt, and the one-use nonce index — in the
        // same atomic quorum step, so it stays readable back by stable proof
        // identity with an exact binding.
        let mut proof = None;
        let mut proof_store_ops: Vec<StoreOp> = Vec::new();
        if let AuthorityProtocolScope::Card(card_scope) = &request.scope {
            let proof_id = fresh_id("prf");
            let mut minted = AuthorizationFenceProof {
                authorization_edition: AUTHORIZATION_EDITION,
                authority_id: self.config.identity.authority_id.clone(),
                authority_term: next_frontier.authority_term,
                global_fence_sequence: next_frontier.global_fence_sequence,
                scope: card_scope.clone(),
                scope_generation,
                revoke_watermark,
                snapshot_hash: request.snapshot_hash.clone(),
                parent_hash: None,
                scope_certificate_hash: Some(certificate_hash.clone()),
                request_binding_digest: Some(reservation.intent.request_digest.clone()),
                operation_id: reservation.intent.operation_id.clone(),
                event_id: reservation.intent.event_id.clone(),
                key_id: self.signer.key_id().to_owned(),
                key_epoch: self.signer.key_epoch(),
                issued_at: now,
                not_before: now,
                expires_at: now + self.config.policy.proof_ttl_seconds,
                request_nonce: fresh_id("nonce"),
                proof_id: proof_id.clone(),
                signature: String::new(),
            };
            let signing_bytes = minted
                .signing_bytes()
                .map_err(|error| AuthorityServiceError::Protocol(error.into()))?;
            minted.signature = self.signer.sign_checked(&signing_bytes, true)?;
            let receipt = StoredProofReceipt {
                proof_id: proof_id.clone(),
                request_nonce: minted.request_nonce.clone(),
                request_binding_digest: reservation.intent.request_digest.clone(),
                mutation_kind: reservation.intent.mutation_kind,
                operation_id: reservation.intent.operation_id.clone(),
                event_id: reservation.intent.event_id.clone(),
                caller_service_id: reservation.intent.service_id.clone(),
                actor_scope_key: scope_key_text.clone(),
                source_scope_key: scope_key_text.clone(),
                authority_term: next_frontier.authority_term,
                global_fence_sequence: next_frontier.global_fence_sequence,
                key_epoch: next_frontier.key_epoch,
                issued_at: now,
                expires_at: now + self.config.policy.proof_ttl_seconds,
            };
            proof_store_ops.push(StoreOp::PutIfAbsent {
                key: self.keys.proof_receipt(&proof_id),
                value: encode(&minted)?,
            });
            proof_store_ops.push(StoreOp::PutIfAbsent {
                key: self.keys.proof_binding(&proof_id),
                value: encode(&receipt)?,
            });
            proof_store_ops.push(StoreOp::PutIfAbsent {
                key: self
                    .keys
                    .proof_nonce(&scope_key_text, &minted.request_nonce),
                value: encode(&receipt)?,
            });
            proof = Some(minted);
        }

        let new_scope_current = StoredScopeCurrent {
            scope_key_text: scope_key_text.clone(),
            snapshot_hash: request.snapshot_hash.clone(),
            scope_generation,
            revoke_watermark,
            certificate_hash: certificate_hash.clone(),
            certificate_id: certificate_id.clone(),
            key_epoch: state.frontier.key_epoch,
            updated_at: now,
        };
        reservation.certified_scopes.push(scope_key_text.clone());
        reservation.certified_scopes.sort();
        reservation.state = if self
            .coverage_allows_automatic_close(&coverage, &reservation, Some(&certificate))
            .await?
        {
            AuthorityReservationState::Certified
        } else {
            AuthorityReservationState::Published
        };
        reservation.certificate_id = Some(certificate_id.clone());
        reservation.updated_at = now;
        reservation
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;

        let scope_current_store_op = if previous_publication.is_some() {
            StoreOp::ReplaceIfRevision {
                key: self.keys.scope_current(&scope_key_text),
                expected_revision: scope_current_op,
                value: encode(&new_scope_current)?,
            }
        } else {
            StoreOp::PutIfAbsent {
                key: self.keys.scope_current(&scope_key_text),
                value: encode(&new_scope_current)?,
            }
        };
        let lock_revision = if reservation.state == AuthorityReservationState::Certified {
            let record = self
                .store
                .get(&self.keys.source_bootstrap_global_lock())
                .await?
                .ok_or_else(|| {
                    AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                        "authorization reservation global lock is missing".to_owned(),
                    ))
                })?;
            let owner: (String, String, String) =
                decode(&record.value, "authorization global lock")?;
            if owner.0 != reservation.intent.operation_id
                || owner.1 != reservation.reservation_id
                || owner.2 != reservation.intent_digest
            {
                return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "authorization reservation global lock owner differs".to_owned(),
                )));
            }
            Some(record.revision)
        } else {
            None
        };
        let mut txn = StoreTxn::new()
            .with_op(StoreOp::PutIfAbsent {
                key: self
                    .keys
                    .reservation_certificate(&request.reservation_id, &scope_key_text),
                value: encode(&certificate_id)?,
            })
            .with_op(StoreOp::PutIfAbsent {
                key: self.keys.certificate(&certificate_id),
                value: encode(&certificate)?,
            })
            .with_op(scope_current_store_op)
            .with_op(StoreOp::ReplaceIfRevision {
                key: self.keys.reservation(&reservation.reservation_id),
                expected_revision: reservation_record.revision,
                value: encode(&reservation)?,
            })
            .with_op(StoreOp::ReplaceIfRevision {
                key: self.keys.frontier(),
                expected_revision: state.frontier_revision,
                value: encode(&next_frontier)?,
            })
            .with_op(self.bump_gate_epoch_op(&state)?);
        if let Some(expected_revision) = lock_revision {
            txn = txn.with_op(StoreOp::DeleteIfRevision {
                key: self.keys.source_bootstrap_global_lock(),
                expected_revision,
            });
        }
        for op in proof_store_ops {
            txn = txn.with_op(op);
        }
        let outcome = self.execute_leader_txn(txn).await;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => return Err(self.map_store_error(error, &certificate_id)),
        };
        match outcome {
            StoreTxnOutcome::PreconditionFailed { .. } => Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "reservation",
                    state: "CONCURRENT".to_owned(),
                },
            )),
            StoreTxnOutcome::Applied { .. } => {
                let read_gate = self.evaluate_read_gate().await?;
                Ok(AuthorityCertifyResponse {
                    certificate,
                    proof,
                    reservation,
                    global_frontier: next_frontier,
                    read_gate,
                })
            }
        }
    }

    /// Reconcile one reservation by stable identity. Read-only, never retries.
    pub async fn reconcile_reservation(
        &self,
        request: &AuthorityReconcileRequest,
    ) -> Result<AuthorityReconcileResponse, AuthorityServiceError> {
        self.authorize(&request.caller, "reconcile")?;
        request
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        let state = self.load_verified_state().await?;
        let read_gate = self.evaluate_read_gate().await?;
        let reconciliation = match self
            .store
            .get(&self.keys.reservation(&request.reservation_id))
            .await?
        {
            None => AuthorityReconciliation {
                reservation_id: request.reservation_id.clone(),
                operation_id: request.operation_id.clone(),
                disposition: AuthorityReservationDisposition::NotFound,
                reservation: None,
            },
            Some(record) => {
                let reservation: AuthorityScopeReservation = decode(&record.value, "reservation")?;
                reservation
                    .validate()
                    .map_err(AuthorityServiceError::Protocol)?;
                if reservation.intent.operation_id != request.operation_id {
                    return Err(AuthorityServiceError::Protocol(
                        AuthorityProtocolError::CallerIdentityMismatch,
                    ));
                }
                AuthorityReconciliation {
                    reservation_id: reservation.reservation_id.clone(),
                    operation_id: reservation.intent.operation_id.clone(),
                    disposition: AuthorityReservationDisposition::from_reservation(&reservation),
                    reservation: Some(reservation),
                }
            }
        };
        reconciliation
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        let commit_binding = self
            .store
            .get(&self.keys.commit_binding(&request.reservation_id))
            .await?
            .map(|record| decode(&record.value, "source commit binding"))
            .transpose()?;
        let mut certified_publications = Vec::new();
        if let Some(reservation) = &reconciliation.reservation {
            // A Certified GLOBAL reservation is checked against the declared
            // finite coverage the source recorded with its commit, if any;
            // the classic conservative GLOBAL (no declared set) must carry a
            // non-empty actual history. Completeness is never fabricated on
            // the read path.
            let coverage_record;
            let mut declared_finite = None;
            if reservation.state == AuthorityReservationState::Certified
                && reservation.intent.coverage.is_global()
            {
                if let Some(binding) = commit_binding.as_ref() {
                    coverage_record = Some(self.load_commit_coverage(reservation, binding).await?);
                    declared_finite = coverage_record
                        .as_ref()
                        .and_then(|record| record.declared_coverage());
                }
            }
            certified_publications = certificate_records::verify_reservation_history(
                self.store.as_ref(),
                &self.keys,
                &state,
                reservation,
                commit_binding.as_ref(),
                false,
                declared_finite,
            )
            .await?;
        }
        let response = AuthorityReconcileResponse {
            reconciliation,
            commit_binding,
            certified_publications,
            global_frontier: state.frontier,
            read_gate,
        };
        response
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        Ok(response)
    }

    /// Operator-authorized close of one PUBLISHED (GLOBAL) reservation.
    ///
    /// Certification under GLOBAL coverage leaves the conservative barrier
    /// UP because the source cannot assert the affected scope set. Only an
    /// identity registered with the `close` operation — an operator, never
    /// the committing source — may clear it. The close is a leader-gated CAS
    /// that moves the reservation to CERTIFIED, bumps the read-gate epoch,
    /// and advances the frontier. The terminal flip never blesses unverified
    /// history: the reservation's publication history is verified end to end
    /// first, and a stable operator/reason/operation receipt is stored in the
    /// SAME CAS for audit and idempotency — a repeated or recovered close can
    /// read back by stable identity and never re-advances the frontier.
    pub async fn close_reservation(
        &self,
        request: &AuthorityCloseReservationRequest,
    ) -> Result<AuthorityCloseReservationResponse, AuthorityServiceError> {
        self.authorize(&request.caller, "close")?;
        request
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        self.require_leader()?;
        let now = now_unix();

        let reservation_record = self
            .store
            .get(&self.keys.reservation(&request.reservation_id))
            .await?
            .ok_or(AuthorityServiceError::Protocol(
                AuthorityProtocolError::NotFound {
                    record: "reservation",
                },
            ))?;
        let mut reservation: AuthorityScopeReservation =
            decode(&reservation_record.value, "reservation")?;
        reservation
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        if reservation.state != AuthorityReservationState::Published {
            // Unknown-outcome retry contract: a close of an already terminal
            // reservation is idempotent ONLY when the request is the EXACT
            // same close recorded in the durable receipt — stable operation
            // identity, operator and reason. The read-back serves the
            // terminal reservation with the receipt's recorded post-close
            // frontier (never the current frontier, and the frontier never
            // re-advances); any different binding is a genuine conflict.
            if reservation.state == AuthorityReservationState::Certified {
                if let Some(record) = self
                    .store
                    .get(&certificate_records::close_receipt_key(
                        &self.keys,
                        &request.reservation_id,
                    ))
                    .await?
                {
                    let receipt: certificate_records::StoredCloseReceipt =
                        decode(&record.value, "operator close receipt")?;
                    if receipt.reservation_id == reservation.reservation_id
                        && receipt.operation_id == request.operation_id
                        && receipt.operator == request.caller.service_id
                        && receipt.reason == request.reason
                    {
                        // The replay never trusts the receipt alone: the
                        // terminal history must STILL verify end to end
                        // (signer/binding/frontier/coverage completeness) and
                        // the receipt must describe exactly that history.
                        // Corrupted terminal state can never succeed a close
                        // replay.
                        let binding_record = self
                            .store
                            .get(&self.keys.commit_binding(&request.reservation_id))
                            .await?
                            .ok_or_else(|| {
                                AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                                    "source commit binding is missing".to_owned(),
                                ))
                            })?;
                        let binding: astral_types::AuthorityCommitBinding =
                            decode(&binding_record.value, "source commit binding")?;
                        let state = self.load_verified_state().await?;
                        let coverage_record =
                            self.load_commit_coverage(&reservation, &binding).await?;
                        certificate_records::verify_reservation_history(
                            self.store.as_ref(),
                            &self.keys,
                            &state,
                            &reservation,
                            Some(&binding),
                            true,
                            coverage_record.declared_coverage(),
                        )
                        .await?;
                        if receipt.certified_scopes != reservation.certified_scopes {
                            return Err(AuthorityServiceError::Store(
                                AuthorityStoreError::Corrupt(
                                    "close receipt does not match the certified history".to_owned(),
                                ),
                            ));
                        }
                        state.verify_historical_frontier(&receipt.frontier)?;
                        let read_gate = self.evaluate_read_gate().await?;
                        return Ok(AuthorityCloseReservationResponse {
                            reservation,
                            global_frontier: receipt.frontier,
                            read_gate,
                        });
                    }
                }
            }
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "reservation",
                    state: reservation.state.as_text().to_owned(),
                },
            ));
        }
        if !reservation.intent.coverage.is_global()
            || reservation.intent.operation_id != request.operation_id
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "reservation",
                    state: reservation.state.as_text().to_owned(),
                },
            ));
        }

        // The close blesses the reservation's publication history as
        // complete: verify every certified scope's certificate record end to
        // end BEFORE the terminal flip. A GLOBAL reservation with no actual
        // certified history is refused — the operator assertion completes the
        // conservative contract, it never fabricates a fanout proof — and a
        // recorded declared finite coverage must be fully certified.
        let binding_record = self
            .store
            .get(&self.keys.commit_binding(&request.reservation_id))
            .await?
            .ok_or_else(|| {
                AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "source commit binding is missing".to_owned(),
                ))
            })?;
        let binding: astral_types::AuthorityCommitBinding =
            decode(&binding_record.value, "source commit binding")?;
        let state = self.load_verified_state().await?;
        let coverage_record = self.load_commit_coverage(&reservation, &binding).await?;
        let certified = certificate_records::verify_reservation_history(
            self.store.as_ref(),
            &self.keys,
            &state,
            &reservation,
            Some(&binding),
            true,
            coverage_record.declared_coverage(),
        )
        .await?;
        debug_assert!(
            !certified.is_empty(),
            "the operator close requires a non-empty actual history"
        );

        reservation.state = AuthorityReservationState::Certified;
        reservation.updated_at = now;
        reservation
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;

        let digest = mutation_digest("reservation-close", &request.reservation_id);
        let next_frontier = state
            .frontier
            .advance(&request.operation_id, &digest, now)
            .map_err(AuthorityServiceError::Protocol)?;
        // Stable audit/idempotency receipt of THIS close: operator, reason,
        // stable operation identity, the exact history it blessed, and the
        // COMPLETE post-close frontier — stored put-if-absent in the same
        // quorum step, so an unknown-outcome retry reads back the original
        // result and a second close can never overwrite or re-advance.
        let receipt = certificate_records::StoredCloseReceipt {
            reservation_id: reservation.reservation_id.clone(),
            operation_id: request.operation_id.clone(),
            operator: request.caller.service_id.clone(),
            reason: request.reason.clone(),
            closed_at: now,
            certified_scopes: reservation.certified_scopes.clone(),
            frontier: next_frontier.clone(),
        };
        let lock_record = self
            .store
            .get(&self.keys.source_bootstrap_global_lock())
            .await?
            .ok_or_else(|| {
                AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "authorization reservation global lock is missing".to_owned(),
                ))
            })?;
        let lock_owner: (String, String, String) =
            decode(&lock_record.value, "authorization global lock")?;
        if lock_owner.0 != reservation.intent.operation_id
            || lock_owner.1 != reservation.reservation_id
            || lock_owner.2 != reservation.intent_digest
        {
            return Err(AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                "authorization reservation global lock owner differs".to_owned(),
            )));
        }
        let outcome = self
            .execute_leader_txn(
                StoreTxn::new()
                    .with_op(StoreOp::ReplaceIfRevision {
                        key: self.keys.reservation(&request.reservation_id),
                        expected_revision: reservation_record.revision,
                        value: encode(&reservation)?,
                    })
                    .with_op(StoreOp::ReplaceIfRevision {
                        key: self.keys.frontier(),
                        expected_revision: state.frontier_revision,
                        value: encode(&next_frontier)?,
                    })
                    .with_op(self.bump_gate_epoch_op(&state)?)
                    .with_op(StoreOp::PutIfAbsent {
                        key: certificate_records::close_receipt_key(
                            &self.keys,
                            &request.reservation_id,
                        ),
                        value: encode(&receipt)?,
                    })
                    .with_op(StoreOp::DeleteIfRevision {
                        key: self.keys.source_bootstrap_global_lock(),
                        expected_revision: lock_record.revision,
                    }),
            )
            .await;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => return Err(self.map_store_error(error, &request.reservation_id)),
        };
        match outcome {
            StoreTxnOutcome::PreconditionFailed { .. } => Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::StateConflict {
                    record: "reservation",
                    state: "CONCURRENT".to_owned(),
                },
            )),
            StoreTxnOutcome::Applied { .. } => {
                let read_gate = self.evaluate_read_gate().await?;
                Ok(AuthorityCloseReservationResponse {
                    reservation,
                    global_frontier: next_frontier,
                    read_gate,
                })
            }
        }
    }

    /// Key rotation, used only by the root-owned CLI tool.
    pub async fn apply_rotation(
        &self,
        certificate: &astral_types::AuthorityKeyRotationCertificate,
        new_signer: Arc<ProtectedAuthoritySigner>,
    ) -> Result<(), AuthorityServiceError> {
        self.require_leader()?;
        certificate
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        let state = self.load_verified_state().await?;
        if certificate.authority_id != state.frontier.authority_id {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch,
            ));
        }
        if let Some(existing) = state
            .rotations
            .iter()
            .find(|existing| existing.rotation_nonce == certificate.rotation_nonce)
        {
            return if existing == certificate {
                Ok(())
            } else {
                Err(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::FrontierDiverged,
                ))
            };
        }
        certificate
            .validate_at(now_unix())
            .map_err(AuthorityServiceError::Protocol)?;
        self.require_active_signer(&state)?;
        let root_key = state
            .trust_root
            .root_key()
            .map_err(AuthorityServiceError::Protocol)?
            .verifying_key()
            .map_err(AuthorityServiceError::Protocol)?;
        let next = certificate
            .verify_after(&state.trust_root, &root_key)
            .map_err(AuthorityServiceError::Protocol)?;
        if !new_signer.matches_trust_root(&next)? {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::TrustRootMismatch,
            ));
        }
        let root_record = self
            .store
            .get(&self.keys.trust_root())
            .await?
            .ok_or_else(|| {
                AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "trust root state missing".to_owned(),
                ))
            })?;
        let mut root_state: StoredTrustRootState = decode(&root_record.value, "trust root state")?;
        root_state.rotations.push(certificate.clone());
        root_state.active = next.clone();

        let now = now_unix();
        let rotation_digest = hex::encode(Sha256::digest(
            certificate
                .signing_bytes()
                .map_err(AuthorityServiceError::Protocol)?,
        ));
        let mut next_frontier = state
            .frontier
            .advance(&certificate.rotation_nonce, &rotation_digest, now)
            .map_err(AuthorityServiceError::Protocol)?;
        next_frontier.authority_term =
            state
                .frontier
                .authority_term
                .checked_add(1)
                .ok_or(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::InvalidCounter {
                        field: "authority_term",
                    },
                ))?;
        next_frontier.key_id = new_signer.key_id().to_owned();
        next_frontier.key_epoch = new_signer.key_epoch();
        next_frontier.trust_root_digest = next.digest().map_err(AuthorityServiceError::Protocol)?;
        next_frontier.updated_at = now;
        next_frontier
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;

        let outcome = self
            .execute_leader_txn(
                StoreTxn::new()
                    .with_op(StoreOp::ReplaceIfRevision {
                        key: self.keys.trust_root(),
                        expected_revision: root_record.revision,
                        value: encode(&root_state)?,
                    })
                    .with_op(StoreOp::ReplaceIfRevision {
                        key: self.keys.frontier(),
                        expected_revision: state.frontier_revision,
                        value: encode(&next_frontier)?,
                    }),
            )
            .await?;
        match outcome {
            StoreTxnOutcome::Applied { .. } => Ok(()),
            StoreTxnOutcome::PreconditionFailed { key } => Err(AuthorityServiceError::Store(
                AuthorityStoreError::PreconditionFailed { key },
            )),
        }
    }

    /// Genesis bootstrap, used only by the root-owned CLI tool.
    /// Returns true when the genesis was created, false when it existed.
    pub async fn initialize_genesis(
        &self,
        genesis: &StoredGenesis,
    ) -> Result<bool, AuthorityServiceError> {
        genesis
            .record
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        genesis
            .trust_root
            .validate()
            .map_err(AuthorityServiceError::Protocol)?;
        let genesis_key = genesis
            .trust_root
            .genesis_key()
            .map_err(AuthorityServiceError::Protocol)?
            .verifying_key()
            .map_err(AuthorityServiceError::Protocol)?;
        genesis
            .record
            .verify(&genesis.trust_root, &genesis_key)
            .map_err(AuthorityServiceError::Protocol)?;
        if genesis.record.trust_root_digest
            != genesis
                .trust_root
                .digest()
                .map_err(AuthorityServiceError::Protocol)?
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::TrustRootMismatch,
            ));
        }
        let signer_entry = genesis
            .trust_root
            .signer_key()
            .map_err(AuthorityServiceError::Protocol)?;
        let initial_frontier = GlobalAuthorityFrontier::genesis(
            &genesis.record.authority_id,
            &genesis.trust_root.root_id,
            &genesis.record.trust_root_digest,
            &signer_entry.key_id,
            signer_entry.key_epoch,
            now_unix(),
        )
        .map_err(AuthorityServiceError::Protocol)?;
        let root_state = StoredTrustRootState {
            root_id: genesis.trust_root.root_id.clone(),
            genesis_trust_root_digest: genesis.record.trust_root_digest.clone(),
            active: genesis.trust_root.clone(),
            rotations: Vec::new(),
        };
        let outcome = self
            .store
            .execute(
                StoreTxn::new()
                    .with_op(StoreOp::PutIfAbsent {
                        key: self.keys.genesis(),
                        value: encode(genesis)?,
                    })
                    .with_op(StoreOp::PutIfAbsent {
                        key: self.keys.trust_root(),
                        value: encode(&root_state)?,
                    })
                    .with_op(StoreOp::PutIfAbsent {
                        key: self.keys.frontier(),
                        value: encode(&initial_frontier)?,
                    })
                    .with_op(StoreOp::PutIfAbsent {
                        key: self.keys.gate_epoch(),
                        value: encode(&StoredGateEpoch { epoch: 1 })?,
                    }),
            )
            .await?;
        match outcome {
            StoreTxnOutcome::Applied { .. } => Ok(true),
            StoreTxnOutcome::PreconditionFailed { .. } => Ok(false),
        }
    }

    fn map_store_error(
        &self,
        error: AuthorityServiceError,
        operation_hint: &str,
    ) -> AuthorityServiceError {
        match error {
            AuthorityServiceError::Store(AuthorityStoreError::Unavailable(_)) => {
                AuthorityServiceError::UnknownOutcome {
                    operation_hint: operation_hint.to_owned(),
                }
            }
            other => other,
        }
    }
}

/// Highest (generation, revoke watermark) across manifest identities.
fn manifest_frontier(
    manifests: &[AuthorityManifestIdentity],
) -> Result<(u64, u64), AuthorityProtocolError> {
    let mut generation = 0u64;
    let mut revoke_watermark = 0u64;
    for manifest in manifests {
        manifest.validate()?;
        generation = generation.max(manifest.generation);
        revoke_watermark = revoke_watermark.max(manifest.revoke_fence);
    }
    Ok((generation, revoke_watermark))
}
