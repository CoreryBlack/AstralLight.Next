//! Internal authority client library.
//!
//! This client contains NO signing capability whatsoever: business processes
//! never hold authority signing keys. Security properties enforced here:
//! - https endpoints and an mTLS client identity are mandatory; the client
//!   refuses to build without them.
//! - The startup attestation is verified as a FULL chain anchored at the
//!   caller-recomputed genesis pin (genesis root digest recomputed, every
//!   rotation verified, active root derived, signature under the derived
//!   signer key). A self-signed attestation with a copied pin string cannot
//!   pass.
//! - The attestation cache expires strictly at `expires_at - margin`; every
//!   use re-checks freshness and re-attests when expired. A failed
//!   re-attestation fails closed: no stale root is ever used.
//! - Every typed response is validated (`validate()`) before it is returned,
//!   including certificate digest consistency inside fence reads.
//! - Response bodies are read with a hard byte cap before allocation.
//! - Zero automatic retries: send-uncertain failures are `UnknownOutcome`
//!   and must be reconciled by stable identity.

use std::sync::Arc;
use std::time::Duration;

use astral_types::{
    AuthorityAbortRequest, AuthorityAbortResponse, AuthorityCallerIdentity,
    AuthorityCertifyRequest, AuthorityCertifyResponse, AuthorityCloseReservationRequest,
    AuthorityCloseReservationResponse, AuthorityCommitBinding, AuthorityCommitRequest,
    AuthorityCommitResponse, AuthorityConfigCompletionEvidence, AuthorityConfigCompletionRequest,
    AuthorityConfigCompletionResponse, AuthorityEligibilityCompletionEvidence,
    AuthorityEligibilityCompletionRequest, AuthorityEligibilityCompletionResponse,
    AuthorityFenceReadRequest, AuthorityFenceReadResponse, AuthorityPrepareRequest,
    AuthorityPrepareResponse, AuthorityProtocolError, AuthorityReconcileRequest,
    AuthorityReconcileResponse, AuthorityRetainedStagedEvidence,
    AuthoritySourceBootstrapCompletion, AuthoritySourceBootstrapFinalizeRequest,
    AuthoritySourceBootstrapFinalizeResponse, AuthoritySourceBootstrapPrepareRequest,
    AuthoritySourceBootstrapPrepareResponse, AuthoritySourceBootstrapReconcileRequest,
    AuthoritySourceBootstrapReconcileResponse, AuthoritySourceBootstrapTicket,
    AuthoritySourceIntent, AuthorityStartupAttestation, AuthorityWireError,
    GlobalAuthorityFrontier, AUTHORITY_PATH_ATTESTATION_STARTUP, AUTHORITY_PATH_CONFIG_COMPLETIONS,
    AUTHORITY_PATH_ELIGIBILITY_COMPLETIONS, AUTHORITY_PATH_FENCE_CURRENT,
    AUTHORITY_PATH_PUBLICATION_CERTIFICATIONS, AUTHORITY_PATH_RESERVATION_ABORTS,
    AUTHORITY_PATH_RESERVATION_CLOSE, AUTHORITY_PATH_RESERVATION_RECONCILE,
    AUTHORITY_PATH_SOURCE_BOOTSTRAP_FINALIZE, AUTHORITY_PATH_SOURCE_BOOTSTRAP_PREPARE,
    AUTHORITY_PATH_SOURCE_BOOTSTRAP_RECONCILE, AUTHORITY_PATH_SOURCE_COMMITS,
    AUTHORITY_PATH_SOURCE_INTENTS,
};
use ed25519_dalek::VerifyingKey;
use serde::de::DeserializeOwned;
use tokio::sync::RwLock;

use crate::error::AuthorityClientError;

/// Hard cap for any single response body (fence reads carry certificates and
/// the full trust chain; 4 MiB bounds them comfortably).
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Re-attest this many seconds before the attested expiry.
const ATTESTATION_REFRESH_MARGIN_SECONDS: i64 = 10;

/// Allowed future clock skew when checking observation freshness.
const OBSERVATION_CLOCK_SKEW_SECONDS: i64 = 5;

/// Client configuration.
#[derive(Debug, Clone)]
pub struct AuthorityClientConfig {
    /// Base URL; must start with `https://`.
    pub base_url: String,
    /// Server CA bundle (PEM) for private PKIs.
    pub server_ca_pem: Vec<u8>,
    /// Mandatory mTLS identity: combined PEM (certificate then key).
    pub client_identity_pem: Vec<u8>,
    /// Logical service identity presented in every request body; must equal
    /// the identity registered for the client certificate fingerprint.
    pub service_id: String,
    /// Out-of-band pin: the genesis trust root digest. Recomputed, never
    /// copied from responses.
    pub pinned_genesis_trust_root_digest: String,
    pub request_timeout: Duration,
}

/// Chain-derived session: the attestation passed full verification, and the
/// active signer verifying key was derived from the pinned genesis root
/// through the rotation chain — never from a self-reported field.
#[derive(Debug, Clone)]
pub struct VerifiedAuthoritySigner {
    pub key_id: String,
    pub key_epoch: u64,
    /// Hex of the Ed25519 verifying key derived from the verified chain.
    pub verifying_key_hex: String,
    pub trust_root: astral_types::AuthorityTrustRoot,
    /// Recomputed genesis trust-root digest (equals the caller pin).
    pub genesis_trust_root_digest: String,
}

#[derive(Debug, Clone)]
struct CachedSession {
    attestation: AuthorityStartupAttestation,
    signer: VerifiedAuthoritySigner,
    verifying_key: VerifyingKey,
}

/// The authority client. Cheap to clone; contains no signing key material.
#[derive(Clone)]
pub struct AuthorityClient {
    http: reqwest::Client,
    base_url: String,
    service_id: String,
    pinned_genesis_trust_root_digest: String,
    session: Arc<RwLock<Option<CachedSession>>>,
}

impl std::fmt::Debug for AuthorityClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorityClient")
            .field("base_url", &self.base_url)
            .field("service_id", &self.service_id)
            .finish_non_exhaustive()
    }
}

impl AuthorityClient {
    /// Build the client. Fails closed on non-https endpoints, a missing pin,
    /// or a missing mTLS identity.
    pub fn new(config: AuthorityClientConfig) -> Result<Self, AuthorityClientError> {
        if !config.base_url.starts_with("https://") {
            return Err(AuthorityClientError::InsecureEndpoint);
        }
        if !astral_types::authority_protocol_digest_shape(&config.pinned_genesis_trust_root_digest)
        {
            return Err(AuthorityClientError::Attestation(
                "pinned_genesis_trust_root_digest must be 64 lowercase hex".to_owned(),
            ));
        }
        if config.client_identity_pem.is_empty() {
            return Err(AuthorityClientError::Attestation(
                "an mTLS client identity is mandatory for the internal authority channel"
                    .to_owned(),
            ));
        }
        let identity = reqwest::Identity::from_pem(&config.client_identity_pem)
            .map_err(|error| AuthorityClientError::Attestation(format!("identity pem: {error}")))?;
        let certificate = reqwest::Certificate::from_pem(&config.server_ca_pem)
            .map_err(|error| AuthorityClientError::Attestation(format!("CA pem: {error}")))?;
        let http = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .identity(identity)
            .add_root_certificate(certificate)
            .build()
            .map_err(|error| AuthorityClientError::Transport(error.to_string()))?;
        let base_url = config.base_url.trim_end_matches('/').to_owned();
        Ok(Self {
            http,
            base_url,
            service_id: config.service_id,
            pinned_genesis_trust_root_digest: config.pinned_genesis_trust_root_digest,
            session: Arc::new(RwLock::new(None)),
        })
    }

    fn caller(&self) -> AuthorityCallerIdentity {
        AuthorityCallerIdentity {
            service_id: self.service_id.clone(),
            request_nonce: uuid::Uuid::new_v4().simple().to_string(),
            issued_at: now_unix(),
        }
    }

    /// Fetch and fully verify the startup attestation against the pinned
    /// genesis digest. Returns a cached attestation only while it is still
    /// inside its validity window (minus the refresh margin); otherwise the
    /// cache is discarded and re-attestation is attempted, failing closed.
    pub async fn attest_startup(
        &self,
    ) -> Result<AuthorityStartupAttestation, AuthorityClientError> {
        self.verified_session()
            .await
            .map(|session| session.attestation)
    }

    /// The chain-derived active signer identity for provider construction:
    /// verifying key material only — the client never holds signing keys.
    /// The active trust root is derived by folding the rotation chain from
    /// the genesis root whose digest equals the caller pin, then the signer
    /// entry is selected from that derived root.
    pub async fn verified_active_signer(
        &self,
    ) -> Result<VerifiedAuthoritySigner, AuthorityClientError> {
        let session = self.verified_session().await?;
        Ok(session.signer)
    }

    async fn verified_session(&self) -> Result<CachedSession, AuthorityClientError> {
        {
            let cached = self.session.read().await;
            if let Some(entry) = cached.as_ref() {
                if entry.attestation.expires_at - ATTESTATION_REFRESH_MARGIN_SECONDS > now_unix() {
                    return Ok(entry.clone());
                }
            }
        }
        // Expired or absent: drop the cache first so a failed refresh can
        // never leave a stale root in place.
        {
            let mut cached = self.session.write().await;
            *cached = None;
        }
        let session = self.fetch_and_verify_session().await?;
        *self.session.write().await = Some(session.clone());
        Ok(session)
    }

    /// Force a new attestation after a durable completion. That mutation may
    /// advance the authority frontier beyond a still-fresh cached session, so
    /// using `verified_session` here could incorrectly reject its valid receipt
    /// as a future frontier. The write lock serializes refreshes and keeps a
    /// failed attestation from restoring an older cached session.
    async fn refresh_verified_session(&self) -> Result<CachedSession, AuthorityClientError> {
        let mut cached = self.session.write().await;
        *cached = None;
        let session = self.fetch_and_verify_session().await?;
        *cached = Some(session.clone());
        Ok(session)
    }

    async fn fetch_and_verify_session(&self) -> Result<CachedSession, AuthorityClientError> {
        let body = AuthorityFenceReadRequest {
            caller: self.caller(),
            scope: None,
            expected_certificate_hash: None,
            read_proof: None,
        };
        let attestation: AuthorityStartupAttestation =
            self.post(AUTHORITY_PATH_ATTESTATION_STARTUP, &body).await?;
        attestation
            .verify_chain_at(&self.pinned_genesis_trust_root_digest, now_unix())
            .map_err(|error| AuthorityClientError::Attestation(error.to_string()))?;
        // Derive the active signer key from the verified chain, never from a
        // self-reported field: the attestation verification already folded
        // every rotation under the pinned genesis root.
        let signer_entry = attestation
            .trust_root
            .signer_key()
            .map_err(|error| AuthorityClientError::Attestation(error.to_string()))?;
        let verifying_key = signer_entry
            .verifying_key()
            .map_err(|error| AuthorityClientError::Attestation(error.to_string()))?;
        Ok(CachedSession {
            signer: VerifiedAuthoritySigner {
                key_id: signer_entry.key_id.clone(),
                key_epoch: signer_entry.key_epoch,
                verifying_key_hex: signer_entry.verifying_key_hex.clone(),
                trust_root: attestation.trust_root.clone(),
                genesis_trust_root_digest: attestation
                    .genesis_trust_root
                    .digest()
                    .map_err(|error| AuthorityClientError::Attestation(error.to_string()))?,
            },
            verifying_key,
            attestation,
        })
    }

    /// Verify a response frontier against the attested genesis plus each
    /// verified historical trust-root rotation. Completion receipts can retain
    /// a frontier from before the current signer/root, but cannot claim another
    /// authority or diverge at the current fence.
    fn verify_attested_historical_frontier(
        session: &CachedSession,
        frontier: &GlobalAuthorityFrontier,
    ) -> Result<(), AuthorityClientError> {
        frontier
            .validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        let attestation = &session.attestation;
        let current = &attestation.global_frontier;
        if frontier.authority_id != attestation.authority_id
            || frontier.authority_id != current.authority_id
            || frontier.root_id != current.root_id
            || frontier.authorization_edition != attestation.authorization_edition
            || frontier.authorization_edition != current.authorization_edition
            || frontier.authority_term > current.authority_term
            || frontier.global_fence_sequence > current.global_fence_sequence
            || (frontier.global_fence_sequence == current.global_fence_sequence
                && frontier != current)
        {
            return Err(AuthorityClientError::Protocol(
                "historical response frontier is outside the attested authority bounds".to_owned(),
            ));
        }
        let mut root = attestation.genesis_trust_root.clone();
        let matches = |candidate: &astral_types::AuthorityTrustRoot| {
            frontier.matches_trust_root(candidate).is_ok()
        };
        if matches(&root) {
            return Ok(());
        }
        for rotation in &attestation.rotations {
            if rotation.authority_id != attestation.authority_id
                || rotation.root_id != root.root_id
                || rotation.authorization_edition != attestation.authorization_edition
            {
                return Err(AuthorityClientError::Protocol(
                    "attested rotation belongs to another authority or root".to_owned(),
                ));
            }
            let root_key = root
                .root_key()
                .and_then(|key| key.verifying_key())
                .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
            root = rotation
                .verify_after(&root, &root_key)
                .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
            if matches(&root) {
                return Ok(());
            }
        }
        Err(AuthorityClientError::Protocol(
            "historical response frontier does not match the attested rotation chain".to_owned(),
        ))
    }

    /// Resolve the verifying key for `key_id` from the attested trust root's
    /// key registry. Historical signer keys are retained by the rotation
    /// fold, so a certificate signed under an older epoch verifies under ITS
    /// OWN registered key — never the currently active one. Unknown ids and
    /// non-signer roles fail closed.
    fn registered_verifying_key(
        session: &CachedSession,
        key_id: &str,
        key_epoch: u64,
    ) -> Result<VerifyingKey, AuthorityClientError> {
        let entry = session
            .attestation
            .trust_root
            .key_by_id(key_id)
            .filter(|key| {
                key.role == astral_types::AuthorityRootKeyRole::Signer && key.key_epoch == key_epoch
            })
            .ok_or_else(|| {
                AuthorityClientError::Protocol(format!(
                    "key {key_id}@{key_epoch} is not a registered signer key in the attested trust root"
                ))
            })?;
        entry
            .verifying_key()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))
    }

    /// Cryptographic verification of one fence read against the
    /// chain-derived trust root: frontier/root identity, certificate
    /// signature under the CERTIFICATE'S OWN registered key (with its time
    /// window), proof signature under the frontier key epoch plus exact
    /// nonce/operation/event/scope/binding, proof-to-frontier and
    /// proof-to-certificate content consistency, and read-gate coverage for
    /// BOTH the actor and the source scope.
    fn verify_fence_read(
        session: &CachedSession,
        response: &AuthorityFenceReadResponse,
        requested: &AuthorityFenceReadRequest,
        now: i64,
    ) -> Result<(), AuthorityClientError> {
        response
            .global_frontier
            .matches_trust_root(&session.attestation.trust_root)
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        response
            .read_gate
            .validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        if let Some(certificate) = &response.scope_certificate {
            let certificate_key = Self::registered_verifying_key(
                session,
                &certificate.key_id,
                certificate.key_epoch,
            )?;
            certificate
                .verify_at(&certificate_key, now)
                .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
            let hash = certificate
                .record_digest()
                .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
            if response.scope_certificate_hash.as_deref() != Some(&hash) {
                return Err(AuthorityClientError::Protocol(
                    "certificate hash does not match the returned certificate".to_owned(),
                ));
            }
            if let Some(expected) = &requested.expected_certificate_hash {
                if expected != &hash {
                    return Err(AuthorityClientError::Protocol(
                        "returned certificate does not match the pinned hash".to_owned(),
                    ));
                }
            }
            // The certificate must be for exactly the scope that was requested
            // (and, when a read proof was requested, the bound source scope).
            if Some(&certificate.scope) != requested.scope.as_ref() {
                return Err(AuthorityClientError::Protocol(
                    "certificate scope does not match the requested scope".to_owned(),
                ));
            }
            if let Some(read_proof) = &requested.read_proof {
                if &certificate.scope != read_proof.bound_scope() {
                    return Err(AuthorityClientError::Protocol(
                        "certificate scope does not match the proof's bound source scope"
                            .to_owned(),
                    ));
                }
            }
        }
        // Observation freshness: the read must be as fresh as the request
        // allows (the requested proof TTL, bounded by the protocol maximum)
        // with a small clock-skew allowance; a future observation is invalid.
        let freshness_bound = requested
            .read_proof
            .as_ref()
            .and_then(|read_proof| read_proof.proof_ttl_seconds)
            .unwrap_or(astral_types::AUTHORITY_MAX_PROOF_TTL_SECONDS);
        if response.observed_at > now + OBSERVATION_CLOCK_SKEW_SECONDS
            || now - response.observed_at > freshness_bound
        {
            return Err(AuthorityClientError::Protocol(
                "fence observation is not fresh for the requested TTL".to_owned(),
            ));
        }
        if response.proof.is_some() != requested.read_proof.is_some() {
            return Err(AuthorityClientError::Protocol(
                "fence response proof presence does not match the request".to_owned(),
            ));
        }
        if let (Some(proof), Some(read_proof)) = (&response.proof, &requested.read_proof) {
            // The proof must verify under the ACTIVE frontier key epoch; a
            // proof minted under an older signer cannot claim the current
            // frontier.
            if proof.key_epoch != response.global_frontier.key_epoch
                || proof.key_id != response.global_frontier.key_id
            {
                return Err(AuthorityClientError::Protocol(
                    "proof signer does not match the reported frontier key".to_owned(),
                ));
            }
            proof
                .verify_at(&session.verifying_key, now)
                .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
            // Proof-to-frontier consistency.
            if proof.authority_term != response.global_frontier.authority_term
                || proof.global_fence_sequence != response.global_frontier.global_fence_sequence
            {
                return Err(AuthorityClientError::Protocol(
                    "proof frontier does not match the reported frontier".to_owned(),
                ));
            }
            // Exact request binding: nonce, operation/event identity, actor
            // scope, and immutable policy-request digest must match exactly
            // what this caller asked for.
            if proof.request_nonce != read_proof.request_nonce {
                return Err(AuthorityClientError::Protocol(
                    "proof nonce does not match the requested nonce".to_owned(),
                ));
            }
            if proof.operation_id != read_proof.operation_id
                || proof.event_id != read_proof.event_id
            {
                return Err(AuthorityClientError::Protocol(
                    "proof operation/event does not match the requested identity".to_owned(),
                ));
            }
            if proof.request_binding_digest.as_deref()
                != Some(read_proof.request_binding_digest.as_str())
            {
                return Err(AuthorityClientError::Protocol(
                    "proof binding digest does not match the requested digest".to_owned(),
                ));
            }
            if proof.scope
                != match &read_proof.actor_scope {
                    astral_types::AuthorityProtocolScope::Card(card) => card.clone(),
                    astral_types::AuthorityProtocolScope::Org(_) => {
                        return Err(AuthorityClientError::Protocol(
                            "read proofs are card-scoped".to_owned(),
                        ))
                    }
                }
            {
                return Err(AuthorityClientError::Protocol(
                    "proof scope does not match the requested actor scope".to_owned(),
                ));
            }
            // The mint-time gate must not have blocked the ACTOR scope nor
            // the SOURCE scope the proof binds.
            if response
                .read_gate
                .blocks(&read_proof.actor_scope)
                .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?
                || response
                    .read_gate
                    .blocks(read_proof.bound_scope())
                    .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?
            {
                return Err(AuthorityClientError::Protocol(
                    "proof minted while the read gate blocks a bound scope".to_owned(),
                ));
            }
            // Proof-to-certificate content consistency: when a certificate
            // for the bound source scope is present, the proof content
            // identity must be exactly that certified publication, and the
            // signed cert binding must reference it.
            if let Some(certificate) = &response.scope_certificate {
                if certificate.scope == *read_proof.bound_scope()
                    && (proof.snapshot_hash != certificate.snapshot_hash
                        || proof.scope_generation
                            != certificate
                                .manifests
                                .iter()
                                .map(|manifest| manifest.generation)
                                .max()
                                .unwrap_or(0)
                        || proof.scope_certificate_hash.as_deref()
                            != response.scope_certificate_hash.as_deref())
                {
                    return Err(AuthorityClientError::Protocol(
                        "proof content identity does not match the returned certificate".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Linearizable fence read, optionally with certificate and read proof.
    /// The caller nonce and the immutable policy-request digest are carried
    /// inside `read_proof` and bound quorum-side by the authority.
    pub async fn read_fence(
        &self,
        scope: Option<astral_types::AuthorityProtocolScope>,
        expected_certificate_hash: Option<String>,
        read_proof: Option<astral_types::AuthorityReadProofRequest>,
    ) -> Result<AuthorityFenceReadResponse, AuthorityClientError> {
        self.attest_startup().await?;
        let body = AuthorityFenceReadRequest {
            caller: self.caller(),
            scope,
            expected_certificate_hash,
            read_proof,
        };
        let response: AuthorityFenceReadResponse =
            self.post(AUTHORITY_PATH_FENCE_CURRENT, &body).await?;
        response
            .validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        let session = self.verified_session().await?;
        Self::verify_fence_read(&session, &response, &body, now_unix())?;
        Ok(response)
    }

    /// Verify a ROOT-signed source-bootstrap ticket against a freshly verified
    /// authority attestation without creating a reservation or sending a
    /// mutation request. The returned attestation is the same chain-verified
    /// view used for the ticket check and is safe for read-only preflight.
    pub async fn verify_source_bootstrap_ticket(
        &self,
        ticket: &AuthoritySourceBootstrapTicket,
    ) -> Result<AuthorityStartupAttestation, AuthorityClientError> {
        ticket
            .validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        let session = self.verified_session().await?;
        Self::verify_source_bootstrap_ticket_with_session(&session, ticket, now_unix())?;
        Ok(session.attestation)
    }

    fn verify_source_bootstrap_ticket_with_session(
        session: &CachedSession,
        ticket: &AuthoritySourceBootstrapTicket,
        now: i64,
    ) -> Result<(), AuthorityClientError> {
        let trust_root_digest = session
            .attestation
            .trust_root
            .digest()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        if ticket.authority_id != session.attestation.authority_id
            || ticket.root_id != session.attestation.trust_root.root_id
            || ticket.trust_root_digest != trust_root_digest
        {
            return Err(AuthorityClientError::Protocol(
                "source bootstrap ticket does not bind the attested trust root".to_owned(),
            ));
        }
        let root_key = session
            .attestation
            .trust_root
            .key_by_id(&ticket.root_key_id)
            .filter(|key| key.role == astral_types::AuthorityRootKeyRole::Root)
            .ok_or_else(|| {
                AuthorityClientError::Protocol(
                    "source bootstrap ticket does not name an attested ROOT key".to_owned(),
                )
            })?
            .verifying_key()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        ticket
            .verify_at(&root_key, now)
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))
    }

    /// Prepare one ROOT-signed source bootstrap ticket. The returned capability
    /// is intentionally opaque and is not an `AuthorizationAdmission`.
    pub async fn prepare_source_bootstrap(
        &self,
        ticket: AuthoritySourceBootstrapTicket,
    ) -> Result<AuthoritySourceBootstrapPrepareResponse, AuthorityClientError> {
        ticket
            .validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        let ticket_digest = ticket
            .artifact_digest()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        self.verify_source_bootstrap_ticket(&ticket).await?;
        let body = AuthoritySourceBootstrapPrepareRequest {
            caller: self.caller(),
            ticket,
        };
        let response: AuthoritySourceBootstrapPrepareResponse = self
            .post(AUTHORITY_PATH_SOURCE_BOOTSTRAP_PREPARE, &body)
            .await?;
        response
            .validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        let session = self.refresh_verified_session().await?;
        Self::verify_source_bootstrap_ticket_with_session(&session, &body.ticket, now_unix())?;
        let trust_root_digest = session
            .attestation
            .trust_root
            .digest()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        response
            .global_frontier
            .matches_trust_root(&session.attestation.trust_root)
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        if response.capability.key_id != session.signer.key_id
            || response.capability.key_epoch != session.signer.key_epoch
            || response.capability.trust_root_digest != trust_root_digest
            || response.reservation.state != astral_types::AuthoritySourceBootstrapState::Reserved
        {
            return Err(AuthorityClientError::Protocol(
                "source bootstrap capability is not issued by the active signer".to_owned(),
            ));
        }
        if !response.read_gate.global_pending
            || response.read_gate.positive_reads_allowed
            || !response
                .read_gate
                .blocking_reservations
                .iter()
                .any(|summary| {
                    summary.reservation_id == response.reservation.reservation_id
                        && summary.operation_id == response.reservation.operation_id
                        && summary.mutation_kind
                            == astral_types::AuthorityMutationKind::AuthorizationSource
                        && summary.state == astral_types::AuthorityReservationState::Reserved
                        && summary.coverage.is_global()
                })
        {
            return Err(AuthorityClientError::Protocol(
                "source bootstrap response does not establish the exact GLOBAL barrier".to_owned(),
            ));
        }
        let read_gate_digest = response
            .read_gate
            .digest()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        if response.capability.gate_epoch != response.gate_epoch
            || response.capability.read_gate_digest != read_gate_digest
        {
            return Err(AuthorityClientError::Protocol(
                "source bootstrap response gate binding is inconsistent".to_owned(),
            ));
        }
        let capability_key = Self::registered_verifying_key(
            &session,
            &response.capability.key_id,
            response.capability.key_epoch,
        )?;
        response
            .capability
            .verify(&capability_key)
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        if response.capability.ticket_digest != ticket_digest
            || response.capability.operation_id != body.ticket.operation_id
            || response.capability.event_id != body.ticket.event_id
            || response.capability.service_id != body.ticket.service_id
            || response.capability.database_id != body.ticket.database_id
            || response.capability.authority_id != response.global_frontier.authority_id
            || response.capability.authority_term != response.global_frontier.authority_term
            || response.capability.global_fence_sequence
                != response.global_frontier.global_fence_sequence
        {
            return Err(AuthorityClientError::Protocol(
                "source bootstrap capability does not bind the ROOT ticket".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Finalize only after the source owner has proven its DB transaction
    /// committed. The completion contains actual source/audit/outcome receipt
    /// digests; this client never synthesizes them.
    pub async fn finalize_source_bootstrap(
        &self,
        capability: astral_types::AuthoritySourceBootstrapCapability,
        completion: AuthoritySourceBootstrapCompletion,
    ) -> Result<AuthoritySourceBootstrapFinalizeResponse, AuthorityClientError> {
        capability
            .validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        completion
            .validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        let body = AuthoritySourceBootstrapFinalizeRequest {
            caller: self.caller(),
            capability,
            completion,
        };
        body.validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        self.attest_startup().await?;
        let response: AuthoritySourceBootstrapFinalizeResponse = self
            .post(AUTHORITY_PATH_SOURCE_BOOTSTRAP_FINALIZE, &body)
            .await?;
        response
            .validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        let session = self.refresh_verified_session().await?;
        Self::verify_attested_historical_frontier(&session, &response.receipt.frontier)?;
        let key = Self::registered_verifying_key(
            &session,
            &response.receipt.key_id,
            response.receipt.key_epoch,
        )?;
        response
            .receipt
            .verify(&key)
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        if response.global_frontier != response.receipt.frontier
            || response.receipt.completion != body.completion
            || response.receipt.authority_id != response.receipt.frontier.authority_id
            || response.receipt.authority_term != response.receipt.frontier.authority_term
            || response.receipt.global_fence_sequence
                != response.receipt.frontier.global_fence_sequence
        {
            return Err(AuthorityClientError::Protocol(
                "source bootstrap completion receipt does not bind the request".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Read-only reconciliation by the stable operation and ROOT-ticket
    /// digest. An unknown transport result is never converted into prepare or
    /// finalize replay by this method.
    pub async fn reconcile_source_bootstrap(
        &self,
        operation_id: String,
        ticket_digest: String,
    ) -> Result<AuthoritySourceBootstrapReconcileResponse, AuthorityClientError> {
        let body = AuthoritySourceBootstrapReconcileRequest {
            caller: self.caller(),
            operation_id,
            ticket_digest,
        };
        body.validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        let response: AuthoritySourceBootstrapReconcileResponse = self
            .post(AUTHORITY_PATH_SOURCE_BOOTSTRAP_RECONCILE, &body)
            .await?;
        response
            .validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        if response.operation_id != body.operation_id
            || response.ticket_digest != body.ticket_digest
        {
            return Err(AuthorityClientError::Protocol(
                "source bootstrap reconciliation request binding differs".to_owned(),
            ));
        }
        let session = self.refresh_verified_session().await?;
        Self::verify_attested_historical_frontier(&session, &response.global_frontier)?;
        response
            .read_gate
            .validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        if let Some(capability) = &response.capability {
            let is_reserved = response.reservation.as_ref().is_some_and(|reservation| {
                reservation.state == astral_types::AuthoritySourceBootstrapState::Reserved
            });
            if is_reserved
                && (capability.key_id != session.signer.key_id
                    || capability.key_epoch != session.signer.key_epoch
                    || capability.gate_epoch != response.gate_epoch
                    || capability.read_gate_digest
                        != response
                            .read_gate
                            .digest()
                            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?)
            {
                return Err(AuthorityClientError::Protocol(
                    "source bootstrap reconciliation capability is not bound to the live gate"
                        .to_owned(),
                ));
            }
            if is_reserved
                && (!response.read_gate.global_pending
                    || !response
                        .read_gate
                        .blocking_reservations
                        .iter()
                        .any(|summary| {
                            summary.reservation_id
                                == response
                                    .reservation
                                    .as_ref()
                                    .map(|reservation| reservation.reservation_id.as_str())
                                    .unwrap_or_default()
                                && summary.coverage.is_global()
                                && summary.state
                                    == astral_types::AuthorityReservationState::Reserved
                        }))
            {
                return Err(AuthorityClientError::Protocol(
                    "reserved bootstrap reconciliation lacks the exact GLOBAL barrier".to_owned(),
                ));
            }
            let key =
                Self::registered_verifying_key(&session, &capability.key_id, capability.key_epoch)?;
            capability
                .verify(&key)
                .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        }
        if let Some(receipt) = &response.receipt {
            Self::verify_attested_historical_frontier(&session, &receipt.frontier)?;
            let key = Self::registered_verifying_key(&session, &receipt.key_id, receipt.key_epoch)?;
            receipt
                .verify(&key)
                .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
            if receipt.frontier != response.global_frontier
                && receipt.frontier.global_fence_sequence
                    == response.global_frontier.global_fence_sequence
            {
                return Err(AuthorityClientError::Protocol(
                    "source bootstrap reconciliation receipt conflicts with its frontier"
                        .to_owned(),
                ));
            }
        }
        Ok(response)
    }

    /// Accept one approved source intent (prepare) and reserve its scopes.
    pub async fn prepare(
        &self,
        intent: AuthoritySourceIntent,
    ) -> Result<AuthorityPrepareResponse, AuthorityClientError> {
        self.attest_startup().await?;
        let intent_digest = intent
            .digest()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        let body = AuthorityPrepareRequest {
            caller: self.caller(),
            intent,
        };
        let response: AuthorityPrepareResponse =
            self.post(AUTHORITY_PATH_SOURCE_INTENTS, &body).await?;
        response
            .validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        let session = self.verified_session().await?;
        response
            .acceptance
            .verify(&session.verifying_key)
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        response
            .global_frontier
            .matches_trust_root(&session.attestation.trust_root)
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        if response.acceptance.intent_digest != intent_digest
            || response.reservation.intent_digest != intent_digest
            || response.reservation.state.as_text() != "RESERVED"
        {
            return Err(AuthorityClientError::Protocol(
                "prepare response does not bind the accepted intent".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Record the durable source commit against a reservation. The exact
    /// echoed binding is verified field-by-field against the request and the
    /// declared staged coverage.
    pub async fn commit(
        &self,
        commit: astral_types::AuthoritySourceCommitRecord,
        database_id: String,
        declared_coverage: Option<astral_types::AuthorityStagedScopeCoverage>,
    ) -> Result<AuthorityCommitResponse, AuthorityClientError> {
        self.attest_startup().await?;
        let body = AuthorityCommitRequest {
            caller: self.caller(),
            commit,
            database_id,
            declared_coverage,
        };
        let response: AuthorityCommitResponse =
            self.post(AUTHORITY_PATH_SOURCE_COMMITS, &body).await?;
        response
            .validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        let session = self.verified_session().await?;
        response
            .global_frontier
            .matches_trust_root(&session.attestation.trust_root)
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        if response.disposition.as_text() != "COMMITTED"
            || response
                .reservation
                .as_ref()
                .map(|reservation| reservation.state.as_text() != "COMMITTED")
                .unwrap_or(true)
        {
            return Err(AuthorityClientError::Protocol(
                "commit response does not reflect a committed reservation".to_owned(),
            ));
        }
        // Exact binding verification against the caller's own records.
        let binding = &response.binding;
        if binding.reservation_id != body.commit.reservation_id
            || binding.operation_id != body.commit.operation_id
            || binding.source_commit_digest != body.commit.source_commit_digest
            || binding.before_image_digest != body.commit.before_image_digest
            || binding.service_id != body.caller.service_id
            || binding.after_image_digest != body.commit.after_image_digest
            || binding.source_outcome_digest != body.commit.source_outcome_digest
            || binding.staged_evidence_digest != body.commit.staged_evidence_digest
            || binding.database_id != body.database_id
        {
            return Err(AuthorityClientError::Protocol(
                "commit response binding does not match the request".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Certify the publication of one committed reservation.
    pub async fn certify(
        &self,
        request: AuthorityCertifyRequest,
    ) -> Result<AuthorityCertifyResponse, AuthorityClientError> {
        self.attest_startup().await?;
        let response: AuthorityCertifyResponse = self
            .post(AUTHORITY_PATH_PUBLICATION_CERTIFICATIONS, &request)
            .await?;
        response
            .validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        let session = self.verified_session().await?;
        let certificate_key = Self::registered_verifying_key(
            &session,
            &response.certificate.key_id,
            response.certificate.key_epoch,
        )?;
        response
            .certificate
            .verify_at(&certificate_key, now_unix())
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        response
            .global_frontier
            .matches_trust_root(&session.attestation.trust_root)
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        if response.certificate.scope != request.scope
            || response.certificate.reservation_id != request.reservation_id
            || response.certificate.completion_digest != request.completion_digest
            || response.certificate.before_image_digest != request.before_image_digest
            || response.certificate.after_image_digest != request.after_image_digest
            || response.certificate.source_outcome_digest != request.source_outcome_digest
            || response.certificate.snapshot_hash != request.snapshot_hash
            || response.certificate.manifests != request.manifests
        {
            return Err(AuthorityClientError::Protocol(
                "certify response does not bind the requested publication".to_owned(),
            ));
        }
        if let Some(proof) = &response.proof {
            let proof_key =
                Self::registered_verifying_key(&session, &proof.key_id, proof.key_epoch)?;
            proof
                .verify_at(&proof_key, now_unix())
                .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
            if proof.scope_certificate_hash.as_deref()
                != Some(
                    response
                        .certificate
                        .record_digest()
                        .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?
                        .as_str(),
                )
            {
                return Err(AuthorityClientError::Protocol(
                    "publish proof does not bind the issued certificate".to_owned(),
                ));
            }
        }
        Ok(response)
    }

    /// Complete one exact COMMITTED eligibility mutation. This endpoint
    /// records only the typed eligibility receipt; it never publishes a grant
    /// certificate. Transport uncertainty is returned as UnknownOutcome and
    /// must be followed by `reconcile_eligibility` using the same binding and
    /// retained evidence (never replay the source mutation).
    pub async fn complete_eligibility(
        &self,
        binding: AuthorityCommitBinding,
        completion: AuthorityEligibilityCompletionEvidence,
        retained_staged_evidence: AuthorityRetainedStagedEvidence,
    ) -> Result<AuthorityEligibilityCompletionResponse, AuthorityClientError> {
        let body = AuthorityEligibilityCompletionRequest {
            caller: self.caller(),
            binding,
            completion,
            retained_staged_evidence,
        };
        body.validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        self.attest_startup().await?;
        let response: AuthorityEligibilityCompletionResponse = self
            .post(AUTHORITY_PATH_ELIGIBILITY_COMPLETIONS, &body)
            .await?;
        response
            .validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        let session = self.refresh_verified_session().await?;
        Self::verify_attested_historical_frontier(&session, &response.global_frontier)?;
        if response.receipt.binding != body.binding
            || response.receipt.completion != body.completion
            || response.reservation.reservation_id != body.binding.reservation_id
            || response.reservation.intent.operation_id != body.binding.operation_id
            || response.reservation.intent.event_id != body.binding.event_id
        {
            return Err(AuthorityClientError::Protocol(
                "eligibility completion response does not bind the exact request".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Reconcile an eligibility completion by stable identity without
    /// repeating any source mutation. Generic reconcile proves the exact
    /// reservation/commit binding first; if it is still COMMITTED, one
    /// idempotent typed-completion request may finish the authority CAS.
    pub async fn reconcile_eligibility(
        &self,
        binding: AuthorityCommitBinding,
        completion: AuthorityEligibilityCompletionEvidence,
        retained_staged_evidence: AuthorityRetainedStagedEvidence,
    ) -> Result<AuthorityEligibilityCompletionResponse, AuthorityClientError> {
        let observed = self
            .reconcile(binding.reservation_id.clone(), binding.operation_id.clone())
            .await?;
        let reservation = observed
            .reconciliation
            .reservation
            .as_ref()
            .ok_or_else(|| {
                AuthorityClientError::Protocol(
                    "eligibility reservation is not durable yet".to_owned(),
                )
            })?;
        if observed.commit_binding.as_ref() != Some(&binding)
            || reservation.intent.service_id != binding.service_id
            || reservation.intent.database_id != binding.database_id
            || reservation.intent.event_id != binding.event_id
            || reservation.intent.admission_proof_id != binding.admission_proof_id
            || reservation.intent.mutation_kind != binding.mutation_kind
            || reservation.intent.request_digest != binding.request_digest
        {
            return Err(AuthorityClientError::Protocol(
                "eligibility reconcile does not match the exact committed binding".to_owned(),
            ));
        }
        match reservation.state {
            astral_types::AuthorityReservationState::Committed => {
                self.complete_eligibility(binding, completion, retained_staged_evidence)
                    .await
            }
            astral_types::AuthorityReservationState::Completed => {
                if observed.reconciliation.disposition
                    != astral_types::AuthorityReservationDisposition::Completed
                {
                    return Err(AuthorityClientError::Protocol(
                        "eligibility terminal state is not COMPLETED".to_owned(),
                    ));
                }
                self.complete_eligibility(binding, completion, retained_staged_evidence)
                    .await
            }
            _ => Err(AuthorityClientError::Protocol(format!(
                "eligibility completion is not recoverable in reservation state {}",
                reservation.state.as_text()
            ))),
        }
    }

    /// Complete one exact COMMITTED configuration mutation. No publication
    /// certificate is created. On uncertain transport, use `reconcile_config`
    /// with the same immutable request inputs.
    pub async fn complete_config(
        &self,
        binding: AuthorityCommitBinding,
        completion: AuthorityConfigCompletionEvidence,
        retained_staged_evidence: AuthorityRetainedStagedEvidence,
    ) -> Result<AuthorityConfigCompletionResponse, AuthorityClientError> {
        let body = AuthorityConfigCompletionRequest {
            caller: self.caller(),
            binding,
            completion,
            retained_staged_evidence,
        };
        body.validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        self.attest_startup().await?;
        let response: AuthorityConfigCompletionResponse =
            self.post(AUTHORITY_PATH_CONFIG_COMPLETIONS, &body).await?;
        response
            .validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        let session = self.refresh_verified_session().await?;
        Self::verify_attested_historical_frontier(&session, &response.global_frontier)?;
        if response.receipt.binding != body.binding
            || response.receipt.completion != body.completion
            || response.reservation.reservation_id != body.binding.reservation_id
            || response.reservation.intent.operation_id != body.binding.operation_id
            || response.reservation.intent.event_id != body.binding.event_id
        {
            return Err(AuthorityClientError::Protocol(
                "config completion response does not bind the exact request".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Reconcile a config completion by stable identity without repeating
    /// source mutation. Only an exact COMMITTED/COMPLETED reservation and
    /// commit binding may proceed to the typed receipt endpoint.
    pub async fn reconcile_config(
        &self,
        binding: AuthorityCommitBinding,
        completion: AuthorityConfigCompletionEvidence,
        retained_staged_evidence: AuthorityRetainedStagedEvidence,
    ) -> Result<AuthorityConfigCompletionResponse, AuthorityClientError> {
        let observed = self
            .reconcile(binding.reservation_id.clone(), binding.operation_id.clone())
            .await?;
        let reservation = observed
            .reconciliation
            .reservation
            .as_ref()
            .ok_or_else(|| {
                AuthorityClientError::Protocol("config reservation is not durable yet".to_owned())
            })?;
        if observed.commit_binding.as_ref() != Some(&binding)
            || reservation.intent.service_id != binding.service_id
            || reservation.intent.database_id != binding.database_id
            || reservation.intent.event_id != binding.event_id
            || reservation.intent.admission_proof_id != binding.admission_proof_id
            || reservation.intent.mutation_kind != binding.mutation_kind
            || reservation.intent.request_digest != binding.request_digest
        {
            return Err(AuthorityClientError::Protocol(
                "config reconcile does not match the exact committed binding".to_owned(),
            ));
        }
        match reservation.state {
            astral_types::AuthorityReservationState::Committed => {
                self.complete_config(binding, completion, retained_staged_evidence)
                    .await
            }
            astral_types::AuthorityReservationState::Completed => {
                if observed.reconciliation.disposition
                    != astral_types::AuthorityReservationDisposition::Completed
                {
                    return Err(AuthorityClientError::Protocol(
                        "config terminal state is not COMPLETED".to_owned(),
                    ));
                }
                self.complete_config(binding, completion, retained_staged_evidence)
                    .await
            }
            _ => Err(AuthorityClientError::Protocol(format!(
                "config completion is not recoverable in reservation state {}",
                reservation.state.as_text()
            ))),
        }
    }

    /// Reconcile one reservation by stable identity (read-only).
    pub async fn reconcile(
        &self,
        reservation_id: String,
        operation_id: String,
    ) -> Result<AuthorityReconcileResponse, AuthorityClientError> {
        let body = AuthorityReconcileRequest {
            caller: self.caller(),
            reservation_id,
            operation_id,
        };
        let response: AuthorityReconcileResponse = self
            .post(AUTHORITY_PATH_RESERVATION_RECONCILE, &body)
            .await?;
        response
            .validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        let session = self.verified_session().await?;
        response
            .global_frontier
            .matches_trust_root(&session.attestation.trust_root)
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        for certificate in &response.certified_publications {
            let key = Self::registered_verifying_key(
                &session,
                &certificate.key_id,
                certificate.key_epoch,
            )?;
            certificate
                .verify(&key)
                .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
            if certificate.authority_id != response.global_frontier.authority_id
                || certificate.authority_term > response.global_frontier.authority_term
                || certificate.global_fence_sequence
                    > response.global_frontier.global_fence_sequence
            {
                return Err(AuthorityClientError::Protocol(
                    "historical publication is ahead of authority".into(),
                ));
            }
        }
        if response.reconciliation.reservation_id != body.reservation_id
            || response.reconciliation.operation_id != body.operation_id
        {
            return Err(AuthorityClientError::Protocol(
                "reconcile response does not bind the requested operation".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Operator-authorized close of one PUBLISHED (GLOBAL) reservation.
    pub async fn close_reservation(
        &self,
        request: AuthorityCloseReservationRequest,
    ) -> Result<AuthorityCloseReservationResponse, AuthorityClientError> {
        self.attest_startup().await?;
        let response: AuthorityCloseReservationResponse = self
            .post(AUTHORITY_PATH_RESERVATION_CLOSE, &request)
            .await?;
        response
            .validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        let session = self.verified_session().await?;
        response
            .global_frontier
            .matches_trust_root(&session.attestation.trust_root)
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        if response.reservation.state.as_text() != "CERTIFIED" {
            return Err(AuthorityClientError::Protocol(
                "close response does not reflect a certified reservation".to_owned(),
            ));
        }
        Ok(response)
    }

    /// Abort one `Reserved` reservation after a proven local rollback. The
    /// exact echoed receipt is verified field-by-field against the request;
    /// any binding mismatch is a protocol violation, never an abort.
    #[allow(clippy::too_many_arguments)]
    pub async fn abort(
        &self,
        reservation_id: String,
        operation_id: String,
        database_id: String,
        request_digest: String,
        abort_id: String,
        source_tombstone_digest: String,
        reason: String,
    ) -> Result<AuthorityAbortResponse, AuthorityClientError> {
        self.attest_startup().await?;
        let body = AuthorityAbortRequest {
            caller: self.caller(),
            reservation_id,
            operation_id,
            database_id,
            request_digest,
            abort_id,
            source_tombstone_digest,
            reason,
        };
        let response: AuthorityAbortResponse =
            self.post(AUTHORITY_PATH_RESERVATION_ABORTS, &body).await?;
        response
            .validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        let session = self.verified_session().await?;
        response
            .global_frontier
            .matches_trust_root(&session.attestation.trust_root)
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        // The receipt must be the exact abort of THIS request: stable abort
        // identity, exact source binding, exact reason and exact tombstone
        // digest, served with the terminal Aborted reservation.
        if response.disposition.as_text() != "ABORTED"
            || response.reservation.state.as_text() != "ABORTED"
            || response.receipt.reservation_id != body.reservation_id
            || response.receipt.abort_id != body.abort_id
            || response.receipt.operation_id != body.operation_id
            || response.receipt.database_id != body.database_id
            || response.receipt.request_digest != body.request_digest
            || response.receipt.source_tombstone_digest != body.source_tombstone_digest
            || response.receipt.service_id != body.caller.service_id
            || response.receipt.reason != body.reason.trim()
        {
            return Err(AuthorityClientError::Protocol(
                "abort response does not bind the requested abort".to_owned(),
            ));
        }
        Ok(response)
    }

    async fn post<B: serde::Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, AuthorityClientError> {
        let response = self
            .http
            .post(format!("{}{path}", self.base_url))
            .json(body)
            .send()
            .await
            .map_err(|error| {
                if error.is_connect() || error.is_timeout() || error.is_request() {
                    AuthorityClientError::UnknownOutcome {
                        operation_hint: path.to_owned(),
                    }
                } else {
                    AuthorityClientError::Transport(error.to_string())
                }
            })?;
        let status = response.status();
        let bytes = read_bounded(response, path).await?;
        if !status.is_success() {
            let wire_error: AuthorityWireError =
                serde_json::from_slice(&bytes).unwrap_or(AuthorityWireError {
                    code: astral_types::AuthorityWireErrorCode::Internal,
                    message: format!("HTTP {status}"),
                    leader_hint: None,
                    current_frontier: None,
                    current_certificate_hash: None,
                    reservation_id: None,
                });
            return Err(AuthorityClientError::Rejected {
                code: format!("{:?}", wire_error.code),
                message: wire_error.message,
            });
        }
        serde_json::from_slice(&bytes)
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))
    }
}

/// Read a response body with a hard cap enforced before allocation grows.
async fn read_bounded(
    response: reqwest::Response,
    operation_hint: &str,
) -> Result<Vec<u8>, AuthorityClientError> {
    if let Some(length) = response.content_length() {
        if length as usize > MAX_RESPONSE_BYTES {
            return Err(AuthorityClientError::Protocol(
                "response body exceeds the hard cap".to_owned(),
            ));
        }
    }
    let mut response = response;
    let mut buffer: Vec<u8> = Vec::with_capacity(1024);
    while let Some(chunk) =
        response
            .chunk()
            .await
            .map_err(|_| AuthorityClientError::UnknownOutcome {
                operation_hint: operation_hint.to_owned(),
            })?
    {
        if buffer.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(AuthorityClientError::Protocol(
                "response body exceeds the hard cap".to_owned(),
            ));
        }
        buffer.extend_from_slice(&chunk);
    }
    Ok(buffer)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0)
}

/// Convenience projection used by integrators to map client errors onto the
/// shared protocol taxonomy where the cases overlap.
pub fn client_error_to_protocol(error: &AuthorityClientError) -> Option<AuthorityProtocolError> {
    match error {
        AuthorityClientError::ProtocolError(protocol_error) => Some(protocol_error.clone()),
        AuthorityClientError::UnknownOutcome { operation_hint } => {
            Some(AuthorityProtocolError::UnknownOutcome {
                operation_hint: operation_hint.clone(),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::{
        AuthorityManifestIdentity, AuthorityProtocolScope, AuthorityReadProofRequest,
        AuthorityRootKey, AuthorityRootKeyRole, AuthorityScopePublicationCertificate,
        AuthorityTrustRoot, AuthorizationDomainScope, AuthorizationFenceProof,
        GlobalAuthorityFrontier, AUTHORITY_PROTOCOL_VERSION, AUTHORIZATION_EDITION,
    };
    use ed25519_dalek::{Signer, SigningKey};

    fn trust_root(
        active_signer: &SigningKey,
        historical_signer: &SigningKey,
    ) -> AuthorityTrustRoot {
        AuthorityTrustRoot {
            root_id: "root-1".to_owned(),
            keys: vec![
                AuthorityRootKey {
                    key_id: "signer-active".to_owned(),
                    key_epoch: 2,
                    role: AuthorityRootKeyRole::Signer,
                    verifying_key_hex: hex::encode(active_signer.verifying_key().as_bytes()),
                },
                AuthorityRootKey {
                    key_id: "signer-historical".to_owned(),
                    key_epoch: 1,
                    role: AuthorityRootKeyRole::Signer,
                    verifying_key_hex: hex::encode(historical_signer.verifying_key().as_bytes()),
                },
                AuthorityRootKey {
                    key_id: "root-1".to_owned(),
                    key_epoch: 2,
                    role: AuthorityRootKeyRole::Root,
                    verifying_key_hex: hex::encode([2u8; 32]),
                },
                AuthorityRootKey {
                    key_id: "genesis-1".to_owned(),
                    key_epoch: 1,
                    role: AuthorityRootKeyRole::Genesis,
                    verifying_key_hex: hex::encode([3u8; 32]),
                },
            ],
            created_at: 1_000,
        }
    }

    fn fixture_session(active: &SigningKey) -> (CachedSession, SigningKey) {
        let historical = SigningKey::from_bytes(&[0xB0; 32]);
        let trust_root = trust_root(active, &historical);
        let mut frontier = GlobalAuthorityFrontier::genesis(
            "authority-1",
            &trust_root.root_id,
            &trust_root.digest().unwrap(),
            "signer-active",
            2,
            1_500,
        )
        .unwrap();
        for index in 0..4 {
            frontier = frontier
                .advance(&format!("fixture-{index}"), &"bb".repeat(32), 1_500 + index)
                .unwrap();
        }
        let session =
            session_for_frontier(frontier, trust_root.clone(), trust_root, Vec::new(), active);
        (session, historical)
    }

    fn session_for_frontier(
        frontier: GlobalAuthorityFrontier,
        trust_root: astral_types::AuthorityTrustRoot,
        genesis_trust_root: astral_types::AuthorityTrustRoot,
        rotations: Vec<astral_types::AuthorityKeyRotationCertificate>,
        active_signer: &SigningKey,
    ) -> CachedSession {
        let attestation = signed_attestation(
            frontier,
            trust_root.clone(),
            genesis_trust_root.clone(),
            rotations,
            active_signer,
        );
        let attestation_key_id = attestation.attestation_key_id.clone();
        let genesis_trust_root_digest = genesis_trust_root.digest().unwrap();
        CachedSession {
            signer: VerifiedAuthoritySigner {
                key_id: attestation_key_id,
                key_epoch: trust_root.signer_key().unwrap().key_epoch,
                verifying_key_hex: hex::encode(active_signer.verifying_key().as_bytes()),
                trust_root,
                genesis_trust_root_digest,
            },
            verifying_key: active_signer.verifying_key(),
            attestation,
        }
    }

    fn advanced_frontier(
        mut frontier: GlobalAuthorityFrontier,
        operation: &str,
    ) -> GlobalAuthorityFrontier {
        frontier = frontier
            .advance(operation, &"ab".repeat(32), frontier.updated_at + 1)
            .unwrap();
        frontier
    }

    fn client_with_cached_session(base_url: String, session: CachedSession) -> AuthorityClient {
        AuthorityClient {
            http: reqwest::Client::new(),
            base_url,
            service_id: "client-test".to_owned(),
            pinned_genesis_trust_root_digest: session
                .attestation
                .genesis_trust_root
                .digest()
                .unwrap(),
            session: Arc::new(RwLock::new(Some(session))),
        }
    }

    fn attestation_trust_root(
        signer: &SigningKey,
        signer_id: &str,
        signer_epoch: u64,
    ) -> astral_types::AuthorityTrustRoot {
        let root_key = SigningKey::from_bytes(&[0x21; 32]);
        let genesis_key = SigningKey::from_bytes(&[0x22; 32]);
        astral_types::AuthorityTrustRoot {
            root_id: "client-root".to_owned(),
            keys: vec![
                AuthorityRootKey {
                    key_id: signer_id.to_owned(),
                    key_epoch: signer_epoch,
                    role: AuthorityRootKeyRole::Signer,
                    verifying_key_hex: hex::encode(signer.verifying_key().as_bytes()),
                },
                AuthorityRootKey {
                    key_id: "client-root".to_owned(),
                    key_epoch: 1,
                    role: AuthorityRootKeyRole::Root,
                    verifying_key_hex: hex::encode(root_key.verifying_key().as_bytes()),
                },
                AuthorityRootKey {
                    key_id: "client-genesis".to_owned(),
                    key_epoch: 1,
                    role: AuthorityRootKeyRole::Genesis,
                    verifying_key_hex: hex::encode(genesis_key.verifying_key().as_bytes()),
                },
            ],
            created_at: 1_000,
        }
    }

    fn signed_attestation(
        frontier: GlobalAuthorityFrontier,
        trust_root: astral_types::AuthorityTrustRoot,
        genesis_trust_root: astral_types::AuthorityTrustRoot,
        rotations: Vec<astral_types::AuthorityKeyRotationCertificate>,
        signer: &SigningKey,
    ) -> AuthorityStartupAttestation {
        let now = now_unix();
        let mut attestation = AuthorityStartupAttestation {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: frontier.authority_id.clone(),
            global_frontier: frontier,
            trust_root: trust_root.clone(),
            genesis_trust_root,
            rotations,
            leader: true,
            attestation_nonce: "fresh-client-test-attestation".to_owned(),
            issued_at: now - 1,
            expires_at: now + 120,
            attestation_key_id: trust_root.signer_key().unwrap().key_id.clone(),
            signature: String::new(),
        };
        attestation.sign_with(signer).unwrap();
        attestation
    }

    async fn serve_attestation_once(attestation: AuthorityStartupAttestation) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            let mut expected_len = None;
            loop {
                let read = stream.read(&mut chunk).await.unwrap();
                assert!(read > 0, "client closed before sending attestation request");
                request.extend_from_slice(&chunk[..read]);
                if expected_len.is_none() {
                    if let Some(header_end) =
                        request.windows(4).position(|window| window == b"\r\n\r\n")
                    {
                        let headers = String::from_utf8_lossy(&request[..header_end]);
                        let content_len = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        expected_len = Some(header_end + 4 + content_len);
                    }
                }
                if expected_len.is_some_and(|expected| request.len() >= expected) {
                    break;
                }
            }
            let body = serde_json::to_vec(&attestation).unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(&body).await.unwrap();
            stream.shutdown().await.unwrap();
        });
        format!("http://{address}")
    }

    async fn serve_raw_response_once(response: Vec<u8>) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let owner = tokio::spawn(async move {
            tokio::time::timeout(std::time::Duration::from_secs(2), async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    let read = stream.read(&mut chunk).await.unwrap();
                    assert!(read > 0, "client closed before sending the request");
                    request.extend_from_slice(&chunk[..read]);
                    assert!(request.len() <= 8192);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                stream.write_all(&response).await.unwrap();
                stream.shutdown().await.unwrap();
            })
            .await
            .expect("response fixture exceeded its bounded lifetime");
        });
        (format!("http://{address}"), owner)
    }

    #[tokio::test]
    async fn post_send_truncated_success_body_is_unknown_and_preserves_operation() {
        let (base_url, owner) = serve_raw_response_once(
            b"HTTP/1.1 200 OK\r\ncontent-length: 64\r\nconnection: close\r\n\r\n{\"ok\":".to_vec(),
        )
        .await;
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let (session, _) = fixture_session(&key);
        let mut client = client_with_cached_session(base_url, session);
        client.http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(1))
            .build()
            .unwrap();
        let result = client
            .post::<_, serde_json::Value>(
                AUTHORITY_PATH_SOURCE_BOOTSTRAP_FINALIZE,
                &serde_json::json!({}),
            )
            .await;
        owner.await.unwrap();
        assert!(
            matches!(result, Err(AuthorityClientError::UnknownOutcome { operation_hint })
            if operation_hint == AUTHORITY_PATH_SOURCE_BOOTSTRAP_FINALIZE)
        );
    }

    #[tokio::test]
    async fn oversized_response_is_rejected_before_reading_its_body() {
        let (base_url, owner) = serve_raw_response_once(
            format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                MAX_RESPONSE_BYTES + 1,
            )
            .into_bytes(),
        )
        .await;
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let (session, _) = fixture_session(&key);
        let mut client = client_with_cached_session(base_url, session);
        client.http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(1))
            .build()
            .unwrap();
        let result = client
            .post::<_, serde_json::Value>(
                AUTHORITY_PATH_SOURCE_BOOTSTRAP_FINALIZE,
                &serde_json::json!({}),
            )
            .await;
        owner.await.unwrap();
        assert!(
            matches!(result, Err(AuthorityClientError::Protocol(message)) if message.contains("hard cap"))
        );
    }

    fn manifests() -> Vec<AuthorityManifestIdentity> {
        vec![AuthorityManifestIdentity {
            aggregate_type: "USER_CARD".to_owned(),
            aggregate_id: 17,
            manifest_digest_hex: "cc".repeat(32),
            dependency_hash_hex: "dd".repeat(32),
            semantic_hash_hex: "ee".repeat(32),
            generation: 4,
            revoke_fence: 2,
            event_id: "event-1".to_owned(),
            operation_id: "operation-1".to_owned(),
        }]
    }

    fn card_scope() -> AuthorityProtocolScope {
        AuthorityProtocolScope::Card(astral_types::AuthorizationAuthorityScope {
            tenant_id: 7,
            card_id: 17,
            user_id: None,
            domain: AuthorizationDomainScope::Any,
        })
    }

    fn certificate(key: &SigningKey, key_id: &str) -> AuthorityScopePublicationCertificate {
        let mut certificate = AuthorityScopePublicationCertificate {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "authority-1".to_owned(),
            authority_term: 1,
            global_fence_sequence: 3,
            certificate_id: "cert-1".to_owned(),
            intent_digest: "11".repeat(32),
            reservation_id: "res-1".to_owned(),
            operation_id: "operation-1".to_owned(),
            event_id: "event-1".to_owned(),
            scope: card_scope(),
            approved_request_digest: "22".repeat(32),
            before_image_digest: Some("33".repeat(32)),
            after_image_digest: "44".repeat(32),
            source_commit_digest: "55".repeat(32),
            completion_digest: String::new(),
            snapshot_hash: "66".repeat(32),
            parent_certificate_hash: None,
            source_outcome_digest: "99".repeat(32),
            manifests: manifests(),
            key_id: key_id.to_owned(),
            key_epoch: if key_id == "signer-active" { 2 } else { 1 },
            issued_at: 1_500,
            not_before: 1_500,
            expires_at: None,
            certificate_nonce: "cert-nonce".to_owned(),
            signature: String::new(),
        };
        certificate.completion_digest = certificate.recompute_completion_digest().unwrap();
        certificate.sign(key).unwrap();
        certificate
    }

    fn proof(
        key: &SigningKey,
        operation_id: &str,
        event_id: &str,
        fence: u64,
        certificate_hash: &str,
    ) -> AuthorizationFenceProof {
        let mut proof = AuthorizationFenceProof {
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "authority-1".to_owned(),
            authority_term: 1,
            global_fence_sequence: fence,
            scope: match card_scope() {
                AuthorityProtocolScope::Card(card) => card,
                AuthorityProtocolScope::Org(_) => unreachable!(),
            },
            scope_generation: 4,
            revoke_watermark: 2,
            snapshot_hash: "66".repeat(32),
            parent_hash: None,
            scope_certificate_hash: Some(certificate_hash.to_owned()),
            request_binding_digest: Some("77".repeat(32)),
            operation_id: operation_id.to_owned(),
            event_id: event_id.to_owned(),
            key_id: "signer-active".to_owned(),
            key_epoch: 2,
            issued_at: 1_500,
            not_before: 1_500,
            expires_at: 9_999_999,
            request_nonce: "reader-nonce-1".to_owned(),
            proof_id: "prf-1".to_owned(),
            signature: String::new(),
        };
        let bytes = proof.signing_bytes().unwrap();
        proof.signature = hex::encode(key.sign(&bytes).to_bytes());
        proof
    }

    fn requested() -> AuthorityFenceReadRequest {
        AuthorityFenceReadRequest {
            caller: AuthorityCallerIdentity {
                service_id: "source-svc".to_owned(),
                request_nonce: "transport-nonce".to_owned(),
                issued_at: 1_500,
            },
            scope: Some(card_scope()),
            expected_certificate_hash: None,
            read_proof: Some(AuthorityReadProofRequest {
                actor_scope: card_scope(),
                mutation_kind: astral_types::AuthorityMutationKind::AuthorizationSource,
                source_scope: None,
                request_nonce: "reader-nonce-1".to_owned(),
                operation_id: "operation-1".to_owned(),
                event_id: "event-1".to_owned(),
                request_binding_digest: "77".repeat(32),
                expected_frontier: None,
                proof_ttl_seconds: None,
            }),
        }
    }

    fn response_with(
        certificate: Option<AuthorityScopePublicationCertificate>,
        proof: Option<AuthorizationFenceProof>,
    ) -> AuthorityFenceReadResponse {
        let scope_certificate_hash = certificate
            .as_ref()
            .map(|certificate| certificate.record_digest().unwrap());
        AuthorityFenceReadResponse {
            protocol_version: AUTHORITY_PROTOCOL_VERSION,
            authorization_edition: AUTHORIZATION_EDITION,
            global_frontier: GlobalAuthorityFrontier {
                authorization_edition: AUTHORIZATION_EDITION,
                authority_id: "authority-1".to_owned(),
                authority_term: 1,
                global_fence_sequence: 5,
                key_id: "signer-active".to_owned(),
                key_epoch: 2,
                root_id: "root-1".to_owned(),
                trust_root_digest: "aa".repeat(32),
                global_chain_digest: "bb".repeat(32),
                updated_at: 1_500,
            },
            read_gate: astral_types::AuthorityReadGate {
                positive_reads_allowed: true,
                global_pending: false,
                blocking_reservations: Vec::new(),
            },
            scope_certificate: certificate,
            scope_certificate_hash,
            proof,
            observed_at: 1_500,
        }
    }

    #[tokio::test]
    async fn completion_refreshes_pre_mutation_attestation_before_frontier_verification() {
        let active = SigningKey::from_bytes(&[7u8; 32]);
        let (pre_session, _) = fixture_session(&active);
        let pre_frontier = pre_session.attestation.global_frontier.clone();
        let completion_frontier = advanced_frontier(pre_frontier.clone(), "completion");

        // The pre-POST session is correctly too old to authorize this advanced
        // frontier. Completion must force an attestation refresh, not weaken
        // the upper-bound check.
        assert!(AuthorityClient::verify_attested_historical_frontier(
            &pre_session,
            &completion_frontier
        )
        .is_err());
        let current = signed_attestation(
            completion_frontier.clone(),
            pre_session.attestation.trust_root.clone(),
            pre_session.attestation.genesis_trust_root.clone(),
            Vec::new(),
            &active,
        );
        let base_url = serve_attestation_once(current).await;
        let client = client_with_cached_session(base_url, pre_session);
        assert_eq!(
            client.attest_startup().await.unwrap().global_frontier,
            pre_frontier
        );

        let refreshed = client.refresh_verified_session().await.unwrap();
        assert_eq!(refreshed.attestation.global_frontier, completion_frontier);
        assert_ne!(
            refreshed.attestation.global_frontier, pre_frontier,
            "the post-completion verifier must not reuse the cached pre-mutation frontier"
        );
        AuthorityClient::verify_attested_historical_frontier(&refreshed, &completion_frontier)
            .unwrap();
    }

    #[test]
    fn historical_frontier_rejects_same_fence_divergence_and_accepts_prior_rotation() {
        let active = SigningKey::from_bytes(&[7u8; 32]);
        let (session, _) = fixture_session(&active);
        let current = session.attestation.global_frontier.clone();
        let mut divergent = current.clone();
        divergent.global_chain_digest = "ee".repeat(32);
        assert!(
            AuthorityClient::verify_attested_historical_frontier(&session, &divergent).is_err()
        );

        let genesis_signer = SigningKey::from_bytes(&[0x31; 32]);
        let next_signer = SigningKey::from_bytes(&[0x32; 32]);
        let genesis = attestation_trust_root(&genesis_signer, "rotation-signer-1", 1);
        let root_signer = SigningKey::from_bytes(&[0x21; 32]);
        let old_receipt_frontier = GlobalAuthorityFrontier::genesis(
            "authority-1",
            &genesis.root_id,
            &genesis.digest().unwrap(),
            "rotation-signer-1",
            1,
            1_000,
        )
        .unwrap();
        let new_key = AuthorityRootKey {
            key_id: "rotation-signer-2".to_owned(),
            key_epoch: 2,
            role: AuthorityRootKeyRole::Signer,
            verifying_key_hex: hex::encode(next_signer.verifying_key().as_bytes()),
        };
        let mut rotated_root = genesis.clone();
        rotated_root.keys.push(new_key.clone());
        rotated_root.created_at = 1_001;
        let mut rotation = astral_types::AuthorityKeyRotationCertificate {
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "authority-1".to_owned(),
            root_id: genesis.root_id.clone(),
            previous_key_epoch: 1,
            new_key,
            previous_trust_root_digest: genesis.digest().unwrap(),
            new_trust_root_digest: rotated_root.digest().unwrap(),
            rotation_nonce: "client-rotation".to_owned(),
            issued_at: 1_001,
            not_before: 1_001,
            expires_at: 2_000,
            signed_by_key_id: String::new(),
            signature: String::new(),
        };
        rotation.sign(&root_signer, "rotation-root").unwrap();
        let mut current_after_rotation = old_receipt_frontier
            .advance("rotation", &"aa".repeat(32), 1_001)
            .unwrap();
        current_after_rotation.authority_term = 2;
        current_after_rotation.key_id = "rotation-signer-2".to_owned();
        current_after_rotation.key_epoch = 2;
        current_after_rotation.trust_root_digest = rotated_root.digest().unwrap();
        current_after_rotation = current_after_rotation
            .advance("later-completion", &"bb".repeat(32), 1_002)
            .unwrap();
        let rotated_session = session_for_frontier(
            current_after_rotation,
            rotated_root.clone(),
            genesis,
            vec![rotation],
            &next_signer,
        );
        AuthorityClient::verify_attested_historical_frontier(
            &rotated_session,
            &old_receipt_frontier,
        )
        .unwrap();
    }

    #[test]
    fn registered_key_lookup_fails_closed() {
        let active = SigningKey::from_bytes(&[7u8; 32]);
        let (session, _) = fixture_session(&active);
        assert!(AuthorityClient::registered_verifying_key(&session, "signer-active", 2).is_ok());
        assert!(
            AuthorityClient::registered_verifying_key(&session, "signer-historical", 1).is_ok()
        );
        // Wrong epoch for a known id fails closed.
        assert!(AuthorityClient::registered_verifying_key(&session, "signer-active", 1).is_err());
        assert!(AuthorityClient::registered_verifying_key(&session, "unknown-key", 1).is_err());
        assert!(AuthorityClient::registered_verifying_key(&session, "root-1", 2).is_err());
    }

    #[test]
    fn fence_verification_rejects_missing_requested_proof() {
        let active = SigningKey::from_bytes(&[7u8; 32]);
        let (session, _) = fixture_session(&active);
        let mut response = response_with(None, None);
        response.global_frontier.trust_root_digest = session.signer.trust_root.digest().unwrap();
        let error = AuthorityClient::verify_fence_read(&session, &response, &requested(), 2_000)
            .expect_err("a requested proof must be present in the response");
        assert!(
            matches!(error, AuthorityClientError::Protocol(message) if message.contains("proof presence"))
        );
    }

    #[test]
    fn fence_verification_rejects_unrequested_proof() {
        let active = SigningKey::from_bytes(&[7u8; 32]);
        let (session, _) = fixture_session(&active);
        let certificate = certificate(&active, "signer-active");
        let certificate_hash = certificate.record_digest().unwrap();
        let mut response = response_with(
            Some(certificate),
            Some(proof(
                &active,
                "operation-1",
                "event-1",
                5,
                &certificate_hash,
            )),
        );
        response.global_frontier.trust_root_digest = session.signer.trust_root.digest().unwrap();
        let mut request = requested();
        request.read_proof = None;
        let error = AuthorityClient::verify_fence_read(&session, &response, &request, 2_000)
            .expect_err("an unsolicited proof must not be accepted");
        assert!(
            matches!(error, AuthorityClientError::Protocol(message) if message.contains("proof presence"))
        );
    }
    #[test]
    fn fence_verification_binds_historical_certificate_and_fresh_request_proof() {
        let active = SigningKey::from_bytes(&[7u8; 32]);
        let (session, historical) = fixture_session(&active);
        // Certificate signed under the HISTORICAL signer epoch: verifies under
        // its own registered key, not the active one.
        let certificate = certificate(&historical, "signer-historical");
        let certificate_hash = certificate.record_digest().unwrap();
        let response = response_with(
            Some(certificate),
            Some(proof(
                &active,
                "operation-1",
                "event-1",
                5,
                &certificate_hash,
            )),
        );

        let mut response = response;
        response.global_frontier.trust_root_digest = session.signer.trust_root.digest().unwrap();
        let requested = requested();
        AuthorityClient::verify_fence_read(&session, &response, &requested, 2_000).unwrap();

        // Tampered operation identity must fail the requested binding.
        let mut tampered = response_with(
            response.scope_certificate.clone(),
            Some(proof(
                &active,
                "operation-OTHER",
                "event-1",
                5,
                &certificate_hash,
            )),
        );
        tampered.global_frontier.trust_root_digest = session.signer.trust_root.digest().unwrap();
        assert!(
            AuthorityClient::verify_fence_read(&session, &tampered, &requested, 2_000).is_err()
        );

        // A stale proof (older frontier) must fail frontier consistency.
        let mut stale_response = response_with(
            response.scope_certificate.clone(),
            Some(proof(
                &active,
                "operation-1",
                "event-1",
                4,
                &certificate_hash,
            )),
        );
        stale_response.global_frontier.trust_root_digest =
            session.signer.trust_root.digest().unwrap();
        assert!(
            AuthorityClient::verify_fence_read(&session, &stale_response, &requested, 2_000)
                .is_err()
        );
    }

    #[test]
    fn old_publication_certificate_survives_frontier_advance_and_future_is_rejected() {
        let active = SigningKey::from_bytes(&[7u8; 32]);
        let (session, historical) = fixture_session(&active);
        // Old publication (fence 3) verified against a FRESH frontier (5).
        let old_certificate = certificate(&historical, "signer-historical");
        let mut response = response_with(Some(old_certificate), None);
        let mut requested = requested();
        requested.read_proof = None;
        response.global_frontier.trust_root_digest = session.signer.trust_root.digest().unwrap();
        AuthorityClient::verify_fence_read(&session, &response, &requested, 2_000).unwrap();

        // A certificate with a future (regressing) fence is rejected.
        let mut future = response.scope_certificate.clone().unwrap();
        future.global_fence_sequence = 9;
        future.certificate_nonce = "future-nonce".to_owned();
        let signer_entry = session
            .attestation
            .trust_root
            .key_by_id(&future.key_id)
            .unwrap()
            .clone();
        let signing_key = SigningKey::from_bytes(&[0xB0; 32]);
        let _ = signer_entry;
        let mut resigned = future;
        resigned.completion_digest = resigned.recompute_completion_digest().unwrap();
        resigned.sign(&signing_key).unwrap();
        let future_response = response_with(Some(resigned), None);
        assert!(
            AuthorityClient::verify_fence_read(&session, &future_response, &requested, 2_000)
                .is_err()
        );

        // A certificate whose time window opens in the future is rejected.
        let mut not_yet = certificate(&historical, "signer-historical");
        not_yet.not_before = 9_999_999;
        not_yet.issued_at = 9_999_999;
        not_yet.certificate_nonce = "not-yet-nonce".to_owned();
        not_yet.completion_digest = not_yet.recompute_completion_digest().unwrap();
        not_yet.sign(&signing_key).unwrap();
        let not_yet_response = response_with(Some(not_yet), None);
        assert!(
            AuthorityClient::verify_fence_read(&session, &not_yet_response, &requested, 2_000)
                .is_err()
        );
    }

    #[test]
    fn certificate_scope_must_equal_requested_scope() {
        let active = SigningKey::from_bytes(&[7u8; 32]);
        let (session, historical) = fixture_session(&active);
        let mut certificate = certificate(&historical, "signer-historical");
        certificate.scope =
            AuthorityProtocolScope::Card(astral_types::AuthorizationAuthorityScope {
                tenant_id: 8,
                card_id: 18,
                user_id: None,
                domain: AuthorizationDomainScope::Any,
            });
        certificate.certificate_nonce = "other-scope".to_owned();
        certificate.completion_digest = certificate.recompute_completion_digest().unwrap();
        certificate.sign(&historical).unwrap();
        let response = response_with(Some(certificate), None);
        let mut requested = requested();
        requested.read_proof = None;
        assert!(
            AuthorityClient::verify_fence_read(&session, &response, &requested, 2_000).is_err()
        );
    }

    #[test]
    fn fence_verification_rejects_forged_certificate_and_blocked_gate() {
        let active = SigningKey::from_bytes(&[7u8; 32]);
        let (session, _historical) = fixture_session(&active);
        // Forged certificate: signed by an unregistered key.
        let attacker = SigningKey::from_bytes(&[0xFE; 32]);
        let forged = certificate(&attacker, "signer-active");
        assert!(AuthorityClient::verify_fence_read(
            &session,
            &response_with(Some(forged), None),
            &requested(),
            2_000
        )
        .is_err());

        // Blocked gate with a minted proof must fail.
        let minted = proof(&active, "operation-1", "event-1", 5, &"66".repeat(32));
        let mut blocked = response_with(None, Some(minted));
        blocked.global_frontier.trust_root_digest = session.signer.trust_root.digest().unwrap();
        blocked.read_gate = astral_types::AuthorityReadGate {
            positive_reads_allowed: false,
            global_pending: true,
            blocking_reservations: Vec::new(),
        };
        assert!(
            AuthorityClient::verify_fence_read(&session, &blocked, &requested(), 2_000).is_err()
        );
    }
}
