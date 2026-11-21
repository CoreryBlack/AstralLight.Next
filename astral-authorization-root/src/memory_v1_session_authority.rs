//! memory—v1: Process-local access-session authority for the single-node composition.
//!
//! The credential is an opaque bearer secret. It never encodes a user, card or
//! tenant identifier; those facts stay in the authority record and are returned
//! only after the authority validates the credential, validity window and
//! revocation generation. Identity owns the issuer capability in a composed
//! runtime; Gateway receives only the verifier capability.

use std::collections::HashMap;
use std::sync::{Arc, RwLock, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use super::memory_v1_request::RequestRootExtension;
use super::memory_v1_root::{MutationError, RootMetadata, RootMutationExecutor, RootOwner};
use super::memory_v1_session::{
    RequestSessionError, RequestSessionExtension, SessionAuthorityToken,
    SessionFreshnessBindingError, VerifiedSessionFacts,
};

mod cleanup;

use cleanup::{CleanupHint, CleanupPlan};

const CREDENTIAL_PREFIX: &str = "m1.";
const MAX_ACTIVE_SESSIONS: usize = 100_000;

#[derive(Clone)]
struct SessionRecord {
    credential_digest: [u8; 32],
    facts: VerifiedSessionFacts,
    revocation_generation: u64,
    revoked: bool,
}

struct SessionState {
    records: HashMap<[u8; 32], SessionRecord>,
    max_records: usize,
    last_issue_clock: Option<i64>,
    cleanup: CleanupHint,
}

struct IdentityProofState;

// memory—v1: Production only samples the process clock; fixture times are
// explicit and private to the module's isolated unit tests.
#[derive(Clone, Copy)]
enum IssueClock {
    System,
    #[cfg(all(test, feature = "test-support"))]
    Fixed {
        first: Option<i64>,
        final_time: Option<i64>,
    },
}

impl IssueClock {
    // memory—v1: Sample only the process clock or a private unit-test value.
    fn sample(self, final_check: bool) -> Option<i64> {
        match self {
            Self::System => {
                let _ = final_check;
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .ok()
                    .and_then(|duration| i64::try_from(duration.as_secs()).ok())
            }
            #[cfg(all(test, feature = "test-support"))]
            Self::Fixed { first, final_time } => {
                if final_check {
                    final_time
                } else {
                    first
                }
            }
        }
    }
}

/// A private authority-local provenance marker for an adapter-supplied principal.
///
/// It does not verify credentials: any in-process holder of the adapter can
/// supply a `CandidateIdentity`. Identity must authenticate the principal;
/// root-bound issuance independently rechecks the card relationship.
#[derive(Clone)]
struct MemoryV1IdentityProof {
    identity: CandidateIdentity,
    state: Weak<IdentityProofState>,
}

#[derive(Clone)]
struct MemoryV1IdentityProofIssuer {
    state: Arc<IdentityProofState>,
}

/// Capability retained by the trusted Identity/session adapter.
///
/// The composition root gives this capability only to Identity. The proof and
/// low-level session issuer types stay private to this crate, so callers cannot
/// assemble them as separate public capabilities.
#[derive(Clone)]
pub struct MemoryV1IdentitySessionAdapter {
    proof_issuer: MemoryV1IdentityProofIssuer,
    session_issuer: MemoryV1SessionIssuer,
}

/// The process-local owner of memory—v1 access-session state.
///
/// The owner is deliberately not cloneable: one composition root retains the
/// lifecycle owner while Identity and Gateway receive narrow capabilities. The
/// verifier cannot mint sessions and the issuer cannot read arbitrary records.
pub struct MemoryV1SessionAuthority {
    state: Arc<RwLock<SessionState>>,
    identity_proof_state: Arc<IdentityProofState>,
    authority_id: Arc<SessionAuthorityToken>,
}

/// Capability retained by Identity to issue and revoke memory—v1 sessions.
#[derive(Clone)]
struct MemoryV1SessionIssuer {
    state: Arc<RwLock<SessionState>>,
    identity_proof_state: Arc<IdentityProofState>,
    authority_id: Arc<SessionAuthorityToken>,
}

/// Read-only capability retained by Gateway to authenticate access credentials.
#[derive(Clone)]
pub struct MemoryV1SessionVerifier {
    state: Arc<RwLock<SessionState>>,
    authority_id: Arc<SessionAuthorityToken>,
}

/// Authenticated but not yet request-bound session facts.
///
/// Gateway may carry this opaque value through trusted in-process extensions;
/// only the request coordinator can bind it to the request root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryV1AuthenticatedSession {
    facts: VerifiedSessionFacts,
}

/// The credential returned to an Identity caller after successful issuance.
#[derive(Clone, PartialEq, Eq)]
pub struct MemoryV1IssuedSession {
    credential: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MemoryV1SessionAuthorityError {
    #[error("memory-v1 session validity window is invalid")]
    InvalidValidityWindow,
    #[error("memory-v1 session lifetime is too long")]
    LifetimeTooLong,
    #[error("memory-v1 session authority capacity is exhausted")]
    CapacityExhausted,
    #[error("memory-v1 session revocation generation is exhausted")]
    RevocationGenerationExhausted,
    #[error("memory-v1 session credential is invalid")]
    InvalidCredential,
    #[error("memory-v1 session is revoked")]
    Revoked,
    #[error("memory-v1 session is expired or not yet valid")]
    Expired,
    #[error("memory-v1 identity proof is not issued by this authority")]
    ForeignIdentityProof,
    #[error("memory-v1 session authority is unavailable")]
    Unavailable,
    #[error("memory-v1 session scope binding failed: {0}")]
    Scope(#[from] RequestSessionError),
}

/// memory—v1: Failure of the low-level card/session coordinator.
#[derive(Debug, Error)]
pub enum MemoryV1CardDisableError {
    /// Session locking or generation preflight failed.
    #[error(transparent)]
    Session(#[from] MemoryV1SessionAuthorityError),
    /// The exact root was unavailable or could not publish the candidate.
    #[error(transparent)]
    Root(#[from] MutationError),
}

impl MemoryV1SessionAuthority {
    /// Create an empty authority. No session exists until trusted Identity
    /// verification supplies a proof to the issuer.
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(SessionState {
                records: HashMap::new(),
                max_records: MAX_ACTIVE_SESSIONS,
                last_issue_clock: None,
                cleanup: CleanupHint::default(),
            })),
            identity_proof_state: Arc::new(IdentityProofState),
            authority_id: Arc::new(SessionAuthorityToken::new()),
        }
    }

    /// memory—v1: Bind this authority and root to each other's lifetime slots.
    /// Only the root owner may make the binding. Repeating it for the same pair
    /// succeeds; either a different root or authority is rejected permanently.
    /// This establishes neither session provenance nor production adoption.
    pub fn bind_to_root(&self, root: &RootOwner) -> Result<(), MemoryV1SessionAuthorityError> {
        if root.bind_session_authority(&self.authority_id) {
            Ok(())
        } else {
            Err(MemoryV1SessionAuthorityError::Unavailable)
        }
    }

    /// memory—v1: Hold the authority writer only in isolated contention tests.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn with_write_lock_for_test<T>(&self, f: impl FnOnce() -> T) -> T {
        let _guard = self.state.write().expect("test session lock poisoned");
        f()
    }

    /// memory—v1: Probe write availability without waiting in isolated tests.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn write_available_for_test(&self) -> bool {
        self.state.try_write().is_ok()
    }

    /// Return the narrow capability retained by the trusted Identity adapter.
    ///
    /// The adapter is the only public session-issuance surface. The intermediate
    /// proof and issuer types remain private to this crate, so callers cannot
    /// assemble a proof and a session issuer as separate public capabilities.
    pub fn identity_session_adapter(&self) -> MemoryV1IdentitySessionAdapter {
        MemoryV1IdentitySessionAdapter {
            proof_issuer: MemoryV1IdentityProofIssuer {
                state: Arc::clone(&self.identity_proof_state),
            },
            session_issuer: MemoryV1SessionIssuer {
                state: Arc::clone(&self.state),
                identity_proof_state: Arc::clone(&self.identity_proof_state),
                authority_id: Arc::clone(&self.authority_id),
            },
        }
    }

    /// memory—v1: The root-bound authority token for the disable
    /// coordinator. Crate-internal: the coordinator verifies the exact
    /// binding instead of trusting any caller-held capability.
    pub(crate) fn authority_token(&self) -> &Arc<SessionAuthorityToken> {
        &self.authority_id
    }

    /// Return a verifier that can only validate already-issued sessions.
    pub fn verifier(&self) -> MemoryV1SessionVerifier {
        MemoryV1SessionVerifier {
            state: Arc::clone(&self.state),
            authority_id: Arc::clone(&self.authority_id),
        }
    }

    // memory—v1: Refuse an already-poisoned authority before journaling a disable.
    pub(crate) fn can_coordinate_disable(&self) -> bool {
        !self.state.is_poisoned()
    }

    // memory—v1: Exclude live session checks and issuance during the root CAS
    // and revoke all matched records before releasing that writer. Generation
    // exhaustion must not prevent marking a record revoked.
    pub(crate) fn publish_card_disable<T>(
        &self,
        user_card_id: [u8; 16],
        publish: impl FnOnce() -> Result<T, MutationError>,
    ) -> Result<T, MutationError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| MutationError::CardDisableRequiresSessionCoordinator)?;
        let result = publish()?;
        let mut revoked = false;
        for record in state.records.values_mut() {
            if !record.revoked
                && record.facts.candidate_identity().user_card_id.into_bytes() == user_card_id
            {
                record.revocation_generation = record.revocation_generation.saturating_add(1);
                record.revoked = true;
                revoked = true;
            }
        }
        if revoked {
            state.cleanup.note_revocation();
        }
        Ok(result)
    }

    /// memory—v1: The low-level coordinator is not a governance capability.
    /// This public compatibility entry point always fails closed because it
    /// cannot establish admission, mutation binding, replay protection or audit.
    pub fn disable_card_with_sessions(
        &self,
        _root: &RootMutationExecutor,
        _user_card_id: MemoryId,
        _expected: RootMetadata,
    ) -> Result<(RootMetadata, usize), MemoryV1CardDisableError> {
        Err(MemoryV1SessionAuthorityError::Unavailable.into())
    }

    /// memory—v1: Simulate coordinated card disable in an isolated test only.
    /// This bypasses authorization and must never be used as a governance path.
    /// If any target generation is exhausted, all existing target sessions are
    /// revoked and an error is returned without changing the root. The card is
    /// not disabled and a later session may still be issued.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn disable_card_with_sessions_for_isolated_tests(
        &self,
        root: &RootMutationExecutor,
        user_card_id: MemoryId,
        expected: RootMetadata,
    ) -> Result<(RootMetadata, usize), MemoryV1CardDisableError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| MemoryV1SessionAuthorityError::Unavailable)?;
        let mut count = 0_usize;
        let mut exhausted = false;
        for record in state.records.values() {
            if !record.revoked && record.facts.candidate_identity().user_card_id == user_card_id {
                exhausted |= record.revocation_generation == u64::MAX;
                count = count
                    .checked_add(1)
                    .ok_or(MemoryV1SessionAuthorityError::CapacityExhausted)?;
            }
        }
        if exhausted {
            state.cleanup.note_revocation();
            for record in state.records.values_mut() {
                if !record.revoked && record.facts.candidate_identity().user_card_id == user_card_id
                {
                    if let Some(next) = record.revocation_generation.checked_add(1) {
                        record.revocation_generation = next;
                    }
                    record.revoked = true;
                }
            }
            return Err(MemoryV1SessionAuthorityError::RevocationGenerationExhausted.into());
        }
        let metadata = root.disable_card_with_session_updates_internal(
            &self.authority_id,
            user_card_id.into_bytes(),
            expected,
            || {
                if count != 0 {
                    state.cleanup.note_revocation();
                }
                for record in state.records.values_mut() {
                    if !record.revoked
                        && record.facts.candidate_identity().user_card_id == user_card_id
                    {
                        // The same writer is still held and every addition was checked.
                        record.revocation_generation = record.revocation_generation.wrapping_add(1);
                        record.revoked = true;
                    }
                }
            },
        )?;
        Ok((metadata, count))
    }
}

impl Default for MemoryV1SessionAuthority {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryV1IdentityProofIssuer {
    /// memory—v1: Mark the adapter-supplied identity as originating from this
    /// authority; this does not independently check credentials or card status.
    fn prove_verified_identity(&self, identity: CandidateIdentity) -> MemoryV1IdentityProof {
        MemoryV1IdentityProof {
            identity,
            state: Arc::downgrade(&self.state),
        }
    }
}

impl MemoryV1IdentitySessionAdapter {
    /// memory—v1: The original entry point cannot prove that a card remains
    /// active in the current root, so it fails closed. Identity callers must
    /// migrate to [`Self::issue_verified_session_in_root`].
    #[deprecated(since = "0.1.0", note = "use issue_verified_session_in_root")]
    pub fn issue_verified_session(
        &self,
        _identity: CandidateIdentity,
        _now_unix_seconds: i64,
        _lifetime_seconds: i64,
    ) -> Result<MemoryV1IssuedSession, MemoryV1SessionAuthorityError> {
        Err(MemoryV1SessionAuthorityError::Unavailable)
    }

    /// memory—v1: Issue without a root check only for isolated test fixtures.
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn issue_unchecked_for_test(
        &self,
        identity: CandidateIdentity,
        now_unix_seconds: i64,
        lifetime_seconds: i64,
    ) -> Result<MemoryV1IssuedSession, MemoryV1SessionAuthorityError> {
        let proof = self.proof_issuer.prove_verified_identity(identity);
        self.session_issuer
            .issue(proof, now_unix_seconds, lifetime_seconds)
    }

    /// memory—v1: Issue only if the request's card is still active in the
    /// current serving root at the session insertion linearization point.
    /// Credential and card verification remain the Identity caller's duty.
    /// Both clock observations must fall inside the requested validity window;
    /// cleanup uses no later than the first trusted observation.
    pub fn issue_verified_session_in_root(
        &self,
        root: &RequestRootExtension,
        identity: CandidateIdentity,
        now_unix_seconds: i64,
        lifetime_seconds: i64,
    ) -> Result<MemoryV1IssuedSession, MemoryV1SessionAuthorityError> {
        let proof = self.proof_issuer.prove_verified_identity(identity);
        self.session_issuer.issue_in_root(
            root,
            proof,
            now_unix_seconds,
            lifetime_seconds,
            IssueClock::System,
        )
    }

    /// Revoke an opaque session through the same Identity-owned capability.
    pub fn revoke(&self, credential: &str) -> Result<(), MemoryV1SessionAuthorityError> {
        self.session_issuer.revoke(credential)
    }

    /// Revoke all retained, not-yet-revoked sessions for one exact user card.
    ///
    /// `memory—v1`: this is a session-component capability for the restricted
    /// card-disable coordinator. It matches only the session records'
    /// `user_card_id`, does not authorize the caller, does not change card
    /// state, and does not prevent a later issuance. The coordinator must
    /// linearize card disablement and new issuance through the shared root.
    /// Every target is preflighted and then revoked under the same session
    /// writer. If any generation is exhausted, all targets are still revoked
    /// and the method returns `RevocationGenerationExhausted`.
    pub fn revoke_sessions_for_user_card(
        &self,
        user_card_id: MemoryId,
    ) -> Result<usize, MemoryV1SessionAuthorityError> {
        self.session_issuer
            .revoke_sessions_for_user_card(user_card_id)
    }
}

impl MemoryV1SessionIssuer {
    /// memory—v1: Fixture-only issuer uses an authority-local provenance marker;
    /// the adapter holder is responsible for verifying its supplied identity.
    #[cfg(any(test, feature = "test-support"))]
    fn issue(
        &self,
        proof: MemoryV1IdentityProof,
        now_unix_seconds: i64,
        lifetime_seconds: i64,
    ) -> Result<MemoryV1IssuedSession, MemoryV1SessionAuthorityError> {
        let (digest, record, issued) =
            self.prepare_issue(proof, now_unix_seconds, lifetime_seconds)?;
        let mut state = self
            .state
            .write()
            .map_err(|_| MemoryV1SessionAuthorityError::Unavailable)?;
        if let Some(cleanup) = CleanupPlan::prepare(&state, now_unix_seconds)? {
            cleanup.apply(&mut state, None);
        }
        Self::reserve_issued(&mut state, digest, None)?;
        let expiry = record.facts.expires_at_unix_seconds();
        Self::insert_prepared(&mut state, digest, record);
        state.cleanup.note_expiry(expiry);
        Ok(issued)
    }

    // memory—v1: The session writer serializes clock observations and the root
    // recheck; only insertion runs under the root lock, followed by cleanup.
    fn issue_in_root(
        &self,
        root: &RequestRootExtension,
        proof: MemoryV1IdentityProof,
        now_unix_seconds: i64,
        lifetime_seconds: i64,
        clock: IssueClock,
    ) -> Result<MemoryV1IssuedSession, MemoryV1SessionAuthorityError> {
        let identity = proof.identity;
        let (digest, record, issued) =
            self.prepare_issue(proof, now_unix_seconds, lifetime_seconds)?;
        root.with_reader(|reader| {
            let mut state = self
                .state
                .write()
                .map_err(|_| MemoryV1SessionAuthorityError::Unavailable)?;
            let observed = clock
                .sample(false)
                .filter(|time| *time >= 0)
                .ok_or(MemoryV1SessionAuthorityError::Unavailable)?;
            if state.last_issue_clock.is_some_and(|last| observed < last) {
                return Err(MemoryV1SessionAuthorityError::Unavailable);
            }
            state.last_issue_clock = Some(observed);
            if !record.facts.valid_at(observed) {
                return Err(MemoryV1SessionAuthorityError::Unavailable);
            }
            let cleanup = CleanupPlan::prepare(&state, now_unix_seconds)?;
            Self::reserve_issued(&mut state, digest, cleanup.as_ref())?;
            let expiry = record.facts.expires_at_unix_seconds();
            let issued = reader
                .try_with_current_login_card(identity, &self.authority_id, || {
                    let final_time = clock
                        .sample(true)
                        .filter(|time| *time >= observed)
                        .ok_or(MemoryV1SessionAuthorityError::Unavailable)?;
                    state.last_issue_clock = Some(final_time);
                    if !record.facts.valid_at(final_time) {
                        return Err(MemoryV1SessionAuthorityError::Unavailable);
                    }
                    Self::insert_prepared(&mut state, digest, record);
                    Ok(issued)
                })
                .map_err(|_| MemoryV1SessionAuthorityError::Unavailable)?
                .ok_or(MemoryV1SessionAuthorityError::Unavailable)??;
            // The session writer keeps the temporary extra record invisible.
            // Cleanup occurs only after the root lock has been released.
            if let Some(cleanup) = cleanup {
                cleanup.apply(&mut state, Some(expiry));
            } else {
                state.cleanup.note_expiry(expiry);
            }
            Ok(issued)
        })
        .map_err(|_| MemoryV1SessionAuthorityError::Unavailable)?
    }

    // memory—v1: Build the record before acquiring either synchronization lock.
    fn prepare_issue(
        &self,
        proof: MemoryV1IdentityProof,
        now_unix_seconds: i64,
        lifetime_seconds: i64,
    ) -> Result<([u8; 32], SessionRecord, MemoryV1IssuedSession), MemoryV1SessionAuthorityError>
    {
        if !proof
            .state
            .upgrade()
            .is_some_and(|state| Arc::ptr_eq(&state, &self.identity_proof_state))
        {
            return Err(MemoryV1SessionAuthorityError::ForeignIdentityProof);
        }
        if lifetime_seconds <= 0 {
            return Err(MemoryV1SessionAuthorityError::InvalidValidityWindow);
        }
        if lifetime_seconds > 86_400 {
            return Err(MemoryV1SessionAuthorityError::LifetimeTooLong);
        }
        if now_unix_seconds < 0 {
            return Err(MemoryV1SessionAuthorityError::InvalidValidityWindow);
        }
        let expires_at = now_unix_seconds
            .checked_add(lifetime_seconds)
            .ok_or(MemoryV1SessionAuthorityError::InvalidValidityWindow)?;
        let facts = VerifiedSessionFacts::issue(
            MemoryId::from_bytes(*Uuid::new_v4().as_bytes()),
            1,
            proof.identity,
            now_unix_seconds,
            expires_at,
            0,
        )
        .map_err(|_| MemoryV1SessionAuthorityError::InvalidValidityWindow)?;
        let credential = format!("{CREDENTIAL_PREFIX}{}", Uuid::new_v4());
        let digest = digest_credential(&credential);
        let record = SessionRecord {
            credential_digest: digest,
            facts,
            revocation_generation: 0,
            revoked: false,
        };
        Ok((digest, record, MemoryV1IssuedSession { credential }))
    }

    // memory—v1: Reserve capacity after accounting for the verified cleanup list.
    fn reserve_issued(
        state: &mut SessionState,
        digest: [u8; 32],
        cleanup: Option<&CleanupPlan>,
    ) -> Result<(), MemoryV1SessionAuthorityError> {
        if state.records.len() - cleanup.map_or(0, CleanupPlan::len) >= state.max_records {
            return Err(MemoryV1SessionAuthorityError::CapacityExhausted);
        }
        if state.records.contains_key(&digest) {
            return Err(MemoryV1SessionAuthorityError::Unavailable);
        }
        state
            .records
            .try_reserve(1)
            .map_err(|_| MemoryV1SessionAuthorityError::CapacityExhausted)
    }

    // memory—v1: Capacity was reserved while the same session writer was held.
    fn insert_prepared(state: &mut SessionState, digest: [u8; 32], record: SessionRecord) {
        state.records.insert(digest, record);
    }

    /// memory—v1: Revoke every non-revoked session record for one exact user card.
    ///
    /// Every target is revoked atomically even if a generation is exhausted;
    /// in that case the method returns an error rather than a success count.
    /// Repeated calls return zero after all targets have been revoked.
    fn revoke_sessions_for_user_card(
        &self,
        user_card_id: MemoryId,
    ) -> Result<usize, MemoryV1SessionAuthorityError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| MemoryV1SessionAuthorityError::Unavailable)?;
        let mut count = 0;
        let mut exhausted = false;
        for record in state.records.values() {
            if !record.revoked && record.facts.candidate_identity().user_card_id == user_card_id {
                count += 1;
                exhausted |= record.revocation_generation == u64::MAX;
            }
        }
        for record in state.records.values_mut() {
            if !record.revoked && record.facts.candidate_identity().user_card_id == user_card_id {
                if let Some(next) = record.revocation_generation.checked_add(1) {
                    record.revocation_generation = next;
                }
                record.revoked = true;
            }
        }
        if count != 0 {
            state.cleanup.note_revocation();
        }
        if exhausted {
            Err(MemoryV1SessionAuthorityError::RevocationGenerationExhausted)
        } else {
            Ok(count)
        }
    }

    /// memory—v1: Revoke even when the generation cannot be advanced; report
    /// exhaustion while retaining the record's fail-closed revoked flag.
    pub fn revoke(&self, credential: &str) -> Result<(), MemoryV1SessionAuthorityError> {
        let digest = parse_credential_digest(credential)?;
        let mut state = self
            .state
            .write()
            .map_err(|_| MemoryV1SessionAuthorityError::Unavailable)?;
        let record = state
            .records
            .get_mut(&digest)
            .ok_or(MemoryV1SessionAuthorityError::InvalidCredential)?;
        if record.revoked {
            return Ok(());
        }
        let result = match record.revocation_generation.checked_add(1) {
            Some(generation) => {
                record.revocation_generation = generation;
                Ok(())
            }
            None => Err(MemoryV1SessionAuthorityError::RevocationGenerationExhausted),
        };
        record.revoked = true;
        state.cleanup.note_revocation();
        result
    }
}

impl MemoryV1SessionVerifier {
    /// Construct a verifier that cannot authenticate any credential.
    ///
    /// This is reserved for isolated routers and compatibility tests that have
    /// no Identity session authority. It is never an authentication fallback.
    pub fn deny_all() -> Self {
        Self {
            state: Arc::new(RwLock::new(SessionState {
                records: HashMap::new(),
                max_records: MAX_ACTIVE_SESSIONS,
                last_issue_clock: None,
                cleanup: CleanupHint::default(),
            })),
            authority_id: Arc::new(SessionAuthorityToken::new()),
        }
    }

    /// Verify an opaque access credential at a trusted clock observation.
    pub fn verify(
        &self,
        credential: &str,
        now_unix_seconds: i64,
    ) -> Result<MemoryV1AuthenticatedSession, MemoryV1SessionAuthorityError> {
        let digest = parse_credential_digest(credential)?;
        let state = self
            .state
            .read()
            .map_err(|_| MemoryV1SessionAuthorityError::Unavailable)?;
        verify_record(&state, digest, now_unix_seconds)
    }

    /// Verify and bind while retaining the authority read lock through binding.
    /// A concurrent revoke cannot pass between credential validation and scope
    /// binding; the next request observes the incremented generation/revocation.
    pub fn verify_and_bind(
        &self,
        credential: &str,
        now_unix_seconds: i64,
        root: &RequestRootExtension,
    ) -> Result<RequestSessionExtension, MemoryV1SessionAuthorityError> {
        let digest = parse_credential_digest(credential)?;
        let state = self
            .state
            .read()
            .map_err(|_| MemoryV1SessionAuthorityError::Unavailable)?;
        let authenticated = verify_record(&state, digest, now_unix_seconds)?;
        let matches_root = root
            .has_session_authority(&self.authority_id)
            .map_err(|_| MemoryV1SessionAuthorityError::Unavailable)?;
        if !matches_root {
            return Err(MemoryV1SessionAuthorityError::InvalidCredential);
        }
        authenticated.bind_to(root, self.clone(), digest)
    }

    // memory—v1: Keep the matching live record stable through the caller's
    // nonblocking final check. Time is checked by that callback only after all
    // other final-check guards have been obtained.
    pub(crate) fn try_with_live_record<T>(
        &self,
        facts: &VerifiedSessionFacts,
        binding: &super::memory_v1_session::SessionAuthorityBinding,
        f: impl FnOnce(&VerifiedSessionFacts) -> T,
    ) -> Result<T, MemoryV1SessionAuthorityError> {
        if !binding.is_from(&self.authority_id) {
            return Err(MemoryV1SessionAuthorityError::InvalidCredential);
        }
        let state = self
            .state
            .try_read()
            .map_err(|_| MemoryV1SessionAuthorityError::Unavailable)?;
        let digest = binding.credential_digest();
        let record = state
            .records
            .get(&digest)
            .ok_or(MemoryV1SessionAuthorityError::InvalidCredential)?;
        if record.credential_digest != digest {
            return Err(MemoryV1SessionAuthorityError::InvalidCredential);
        }
        if record.revoked {
            return Err(MemoryV1SessionAuthorityError::Revoked);
        }
        if record.facts != *facts || record.revocation_generation != facts.revocation_generation() {
            return Err(MemoryV1SessionAuthorityError::InvalidCredential);
        }
        let result = f(&record.facts);
        drop(state);
        Ok(result)
    }

    /// memory—v1: Revalidate a request-bound session against the live authority record.
    ///
    /// This compatibility API rejects bindings made from cloned facts, foreign
    /// scopes or authorities, missing/cleaned records, revoked records,
    /// identity/version drift and invalid time windows. Its supplied time and
    /// standalone observation do not form the engine's combined final check.
    /// The request root is checked and its short reader lease is
    /// released before the authority lock is acquired, so this method never
    /// nests the two synchronization domains.
    pub fn revalidate_bound_session(
        &self,
        session: &RequestSessionExtension,
        root: &RequestRootExtension,
        now_unix_seconds: i64,
    ) -> Result<(), MemoryV1SessionAuthorityError> {
        let (facts, binding) = session
            .authority_binding_material(root)
            .map_err(map_freshness_binding_error)?;
        if !binding.is_from(&self.authority_id) {
            return Err(MemoryV1SessionAuthorityError::InvalidCredential);
        }
        if !facts.valid_at(now_unix_seconds) {
            return Err(MemoryV1SessionAuthorityError::Expired);
        }
        let state = self
            .state
            .read()
            .map_err(|_| MemoryV1SessionAuthorityError::Unavailable)?;
        let record = state
            .records
            .get(&binding.credential_digest())
            .ok_or(MemoryV1SessionAuthorityError::InvalidCredential)?;
        if record.credential_digest != binding.credential_digest() {
            return Err(MemoryV1SessionAuthorityError::InvalidCredential);
        }
        if record.revoked {
            return Err(MemoryV1SessionAuthorityError::Revoked);
        }
        if record.facts != facts
            || record.facts.session_id() != facts.session_id()
            || record.facts.session_version() != facts.session_version()
            || record.revocation_generation != facts.revocation_generation()
        {
            return Err(MemoryV1SessionAuthorityError::InvalidCredential);
        }
        if !record.facts.valid_at(now_unix_seconds) {
            return Err(MemoryV1SessionAuthorityError::Expired);
        }
        Ok(())
    }

    /// Verify with the process trusted UTC clock.
    pub fn verify_now(
        &self,
        credential: &str,
    ) -> Result<MemoryV1AuthenticatedSession, MemoryV1SessionAuthorityError> {
        self.verify(credential, trusted_now_unix_seconds())
    }
}

impl MemoryV1AuthenticatedSession {
    /// memory—v1: Bind authority-verified facts to one exact request root scope.
    ///
    /// This remains private to the authority module's verified flow; callers
    /// should use `MemoryV1SessionVerifier::verify_and_bind` so revocation is
    /// checked immediately before binding.
    fn bind_to(
        &self,
        root: &RequestRootExtension,
        verifier: MemoryV1SessionVerifier,
        credential_digest: [u8; 32],
    ) -> Result<RequestSessionExtension, MemoryV1SessionAuthorityError> {
        root.bind_authoritative_session(
            self.facts.clone(),
            Arc::clone(&verifier.authority_id),
            credential_digest,
            verifier,
        )
        .map_err(MemoryV1SessionAuthorityError::Scope)
    }

    /// Return a non-authorizing diagnostic copy for trusted observability.
    pub fn session_id(&self) -> MemoryId {
        self.facts.session_id()
    }

    /// memory—v1: Copy session facts without an authority binding for isolated tests.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn facts_for_test(&self) -> VerifiedSessionFacts {
        self.facts.clone()
    }
}

impl MemoryV1IssuedSession {
    /// Return the opaque bearer credential for the client transport.
    pub fn credential(&self) -> &str {
        &self.credential
    }
}

fn map_freshness_binding_error(
    error: SessionFreshnessBindingError,
) -> MemoryV1SessionAuthorityError {
    match error {
        SessionFreshnessBindingError::Scope(error) => {
            MemoryV1SessionAuthorityError::Scope(RequestSessionError::Scope(error))
        }
        SessionFreshnessBindingError::ForeignScope
        | SessionFreshnessBindingError::MissingAuthorityProof => {
            MemoryV1SessionAuthorityError::InvalidCredential
        }
    }
}

fn verify_record(
    state: &SessionState,
    digest: [u8; 32],
    now_unix_seconds: i64,
) -> Result<MemoryV1AuthenticatedSession, MemoryV1SessionAuthorityError> {
    let record = state
        .records
        .get(&digest)
        .ok_or(MemoryV1SessionAuthorityError::InvalidCredential)?;
    if record.credential_digest != digest {
        return Err(MemoryV1SessionAuthorityError::InvalidCredential);
    }
    if record.revoked {
        return Err(MemoryV1SessionAuthorityError::Revoked);
    }
    if !record.facts.valid_at(now_unix_seconds) {
        return Err(MemoryV1SessionAuthorityError::Expired);
    }
    Ok(MemoryV1AuthenticatedSession {
        facts: record.facts.clone(),
    })
}

fn digest_credential(credential: &str) -> [u8; 32] {
    Sha256::digest(credential.as_bytes()).into()
}

/// memory—v1: Recognize the opaque memory—v1 access-credential format.
///
/// Recognition is purely syntactic and authenticates nothing. A transport uses
/// it to route such a bearer to [`MemoryV1SessionVerifier`] instead of a legacy
/// token decoder; a malformed credential with this prefix is then rejected by
/// the verifier rather than reinterpreted by another decoder.
pub fn is_memory_v1_credential(credential: &str) -> bool {
    credential.starts_with(CREDENTIAL_PREFIX)
}

fn parse_credential_digest(credential: &str) -> Result<[u8; 32], MemoryV1SessionAuthorityError> {
    let value = credential
        .strip_prefix(CREDENTIAL_PREFIX)
        .ok_or(MemoryV1SessionAuthorityError::InvalidCredential)?;
    if value.parse::<Uuid>().is_err() || value.len() != 36 {
        return Err(MemoryV1SessionAuthorityError::InvalidCredential);
    }
    Ok(digest_credential(credential))
}

fn trusted_now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_v1_db_rows::CandidateRows;
    use crate::memory_v1_hamt::CandidateBudget;
    use crate::memory_v1_request::RequestRootScope;
    use crate::memory_v1_root::{install_process_root, RootHandle, RootOwner};
    use std::sync::OnceLock;
    use uuid::Uuid;

    #[cfg(feature = "test-support")]
    mod cleanup_contention;

    fn identity() -> CandidateIdentity {
        CandidateIdentity {
            user_id: MemoryId::from_bytes([1; 16]),
            identity_card_id: MemoryId::from_bytes([2; 16]),
            user_card_id: MemoryId::from_bytes([3; 16]),
            tenant_id: MemoryId::from_bytes([4; 16]),
        }
    }

    fn identity_for_card(card: u8) -> CandidateIdentity {
        CandidateIdentity {
            user_id: MemoryId::from_bytes([1; 16]),
            identity_card_id: MemoryId::from_bytes([2; 16]),
            user_card_id: MemoryId::from_bytes([card; 16]),
            tenant_id: MemoryId::from_bytes([4; 16]),
        }
    }

    fn card_id(card: u8) -> MemoryId {
        MemoryId::from_bytes([card; 16])
    }

    fn issue_for_card(
        adapter: &MemoryV1IdentitySessionAdapter,
        card: u8,
        now: i64,
    ) -> MemoryV1IssuedSession {
        adapter
            .issue_unchecked_for_test(identity_for_card(card), now, 300)
            .unwrap()
    }

    // memory—v1: Explicit fixed observations preserve the production root check.
    #[cfg(feature = "test-support")]
    fn issue_at(
        adapter: &MemoryV1IdentitySessionAdapter,
        root: &RequestRootExtension,
        identity: CandidateIdentity,
        now: i64,
        lifetime: i64,
    ) -> Result<MemoryV1IssuedSession, MemoryV1SessionAuthorityError> {
        adapter.session_issuer.issue_in_root(
            root,
            adapter.proof_issuer.prove_verified_identity(identity),
            now,
            lifetime,
            IssueClock::Fixed {
                first: Some(now),
                final_time: Some(now),
            },
        )
    }

    // memory—v1: Each isolated process binds its authority to one shared test root.
    fn scope(authority: &MemoryV1SessionAuthority) -> (RootHandle, RequestRootScope) {
        static OWNER: OnceLock<RootOwner> = OnceLock::new();
        let owner = OWNER.get_or_init(|| {
            install_process_root(
                CandidateRows::default(),
                vec![],
                CandidateBudget {
                    max_table_rows: 8,
                    max_bindings_per_read: 2,
                },
            )
            .expect("failed to install session authority test root")
        });
        authority.bind_to_root(owner).unwrap();
        let handle = owner.handle();
        let scope = RequestRootScope::new(handle.clone(), Uuid::new_v4());
        (handle, scope)
    }

    fn run_isolated(child: &str, test_name: &str) -> bool {
        if std::env::var_os(child).is_some() {
            return true;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name])
            .env(child, "1")
            .output()
            .expect("failed to start isolated session authority test");
        assert!(
            output.status.success(),
            "isolated session authority test failed: stdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "isolated session authority test did not run: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        false
    }

    // memory—v1: Build a serving fixture for the root/authority binding checks.
    #[cfg(feature = "test-support")]
    fn binding_security_serving_root() -> RootOwner {
        use crate::memory_v1_db_rows::{
            BindingConfirmationRow, BindingLayer, BindingRow, CurrentSelection, IdentityCardRow,
            RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, TenantRow, UserCardRow,
            UserCardStatus, UserRow,
        };
        use crate::memory_v1_registry::RegistryDeclaration;
        use crate::memory_v1_rules::{
            canonical_version_bytes, MemoryV1OwnerScope, MemoryV1TenantScope,
        };

        let version = vec![1];
        let timestamp = vec![1];
        let content = br#"{"rules":[{"ruleId":"R1","resource":"document","action":"read","effect":"ALLOW"}]}"#.to_vec();
        let hash_input = canonical_version_bytes(&version, &content, &timestamp);
        let rows = CandidateRows {
            users: vec![UserRow { user_id: [1; 16] }],
            identity_cards: vec![IdentityCardRow {
                identity_card_id: [2; 16],
                user_id: [1; 16],
            }],
            tenants: vec![TenantRow {
                tenant_id: [4; 16],
                parent_tenant_id: None,
            }],
            user_cards: vec![UserCardRow {
                user_card_id: [3; 16],
                user_id: [1; 16],
                tenant_id: [4; 16],
                status: UserCardStatus::Active,
            }],
            rule_sets: vec![RuleSetRow {
                rule_set_id: [5; 16],
                owner_tenant_id: [4; 16],
                current_version_bytes: version.clone(),
                status: crate::memory_v1_db_rows::RuleSetStatus::Active,
            }],
            rule_set_versions: vec![RuleSetVersionRow {
                rule_set_id: [5; 16],
                version_bytes: version.clone(),
                content_bytes: content,
                timestamp_bytes: timestamp,
                hash_bytes: Sha256::digest(&hash_input).to_vec(),
                hash_input_bytes: hash_input,
            }],
            bindings: vec![BindingRow {
                binding_id: [6; 16],
                user_card_id: [3; 16],
                rule_set_id: [5; 16],
                binding_layer: BindingLayer::Base,
                valid_from: None,
                valid_until: None,
                owner_scope: MemoryV1OwnerScope::default(),
                tenant_scope: MemoryV1TenantScope::default(),
                removed_at: None,
                removed_by: None,
            }],
            binding_confirmations: vec![BindingConfirmationRow {
                confirmation_id: [7; 16],
                binding_id: [6; 16],
                rule_set_id: [5; 16],
                version_bytes: version.clone(),
                confirmer_user_id: [1; 16],
                scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            }],
            rule_set_change_confirmations: vec![RuleSetChangeConfirmationRow {
                confirmation_id: [8; 16],
                rule_set_id: [5; 16],
                version_bytes: version.clone(),
                confirmer_user_id: [1; 16],
                affected_scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            }],
        };
        let owner = install_process_root(
            rows,
            vec![CurrentSelection {
                rule_set_id: [5; 16],
                version_bytes: version,
            }],
            CandidateBudget {
                max_table_rows: 32,
                max_bindings_per_read: 4,
            },
        )
        .unwrap();
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "document".to_owned(),
                actions: vec!["read".to_owned()],
            }])
            .unwrap();
        owner.adopt_serving_for_isolated_tests().unwrap();
        owner
    }

    // memory—v1: A root never transfers its session slot to another authority.
    #[test]
    fn session_authority_binding_security_is_permanent() {
        const CHILD: &str = "ASTRAL_SESSION_AUTHORITY_BINDING_PERMANENT_CHILD";
        if !run_isolated(
            CHILD,
            "memory_v1_session_authority::tests::session_authority_binding_security_is_permanent",
        ) {
            return;
        }
        let owner = install_process_root(
            CandidateRows::default(),
            vec![],
            CandidateBudget {
                max_table_rows: 8,
                max_bindings_per_read: 2,
            },
        )
        .unwrap();
        let first = MemoryV1SessionAuthority::new();
        let second = MemoryV1SessionAuthority::new();
        assert_eq!(first.bind_to_root(&owner), Ok(()));
        assert_eq!(first.bind_to_root(&owner), Ok(()));
        assert_eq!(
            second.bind_to_root(&owner),
            Err(MemoryV1SessionAuthorityError::Unavailable)
        );
        drop(first);
        assert_eq!(
            second.bind_to_root(&owner),
            Err(MemoryV1SessionAuthorityError::Unavailable)
        );
    }

    // memory—v1: Foreign authorities cannot issue, authenticate or disable a card.
    #[cfg(feature = "test-support")]
    #[test]
    fn session_authority_binding_security_rejects_foreign_operations() {
        use crate::memory_v1_root::{DependencyRecord, EvaluationDependency};
        use crate::memory_v1_session::{FinalCheckTimeConstraints, FinalCheckWindow};

        const CHILD: &str = "ASTRAL_SESSION_AUTHORITY_BINDING_FOREIGN_CHILD";
        if !run_isolated(
            CHILD,
            "memory_v1_session_authority::tests::session_authority_binding_security_rejects_foreign_operations",
        ) {
            return;
        }
        let owner = binding_security_serving_root();
        let authority = MemoryV1SessionAuthority::new();
        let foreign = MemoryV1SessionAuthority::new();
        let scope = RequestRootScope::new(owner.handle(), Uuid::new_v4());
        let root = scope.extension();
        let before = owner.handle().metadata().unwrap();

        assert!(matches!(
            issue_at(
                &authority.identity_session_adapter(),
                &root,
                identity(),
                100,
                300
            ),
            Err(MemoryV1SessionAuthorityError::Unavailable)
        ));
        assert!(authority.state.read().unwrap().records.is_empty());
        authority.bind_to_root(&owner).unwrap();
        let issued = issue_at(
            &authority.identity_session_adapter(),
            &root,
            identity(),
            100,
            300,
        )
        .expect("bound authority must issue for the active serving card");
        assert!(matches!(
            issue_at(
                &foreign.identity_session_adapter(),
                &root,
                identity(),
                100,
                300
            ),
            Err(MemoryV1SessionAuthorityError::Unavailable)
        ));
        assert!(foreign.state.read().unwrap().records.is_empty());
        let fake = foreign
            .identity_session_adapter()
            .issue_unchecked_for_test(identity(), 100, 300)
            .unwrap();
        let valid_session = authority
            .verifier()
            .verify_and_bind(issued.credential(), 100, &root)
            .unwrap();
        assert!(matches!(
            foreign
                .verifier()
                .verify_and_bind(fake.credential(), 100, &root),
            Err(MemoryV1SessionAuthorityError::InvalidCredential)
        ));
        // Bypass the verifier gate only here to exercise both downstream checks.
        let fake_session = foreign
            .verifier()
            .verify(fake.credential(), 100)
            .unwrap()
            .bind_to(
                &root,
                foreign.verifier(),
                digest_credential(fake.credential()),
            )
            .unwrap();
        let windows = [FinalCheckWindow {
            entry_validity: None,
            binding_from: None,
            binding_until: None,
        }];
        let constraints = FinalCheckTimeConstraints {
            start_time: 100,
            future_boundaries: &[],
            winning_windows: &windows,
        };
        valid_session
            .with_authoritative_context(&root, |_, reader, final_check| {
                let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
                let record = DependencyRecord {
                    card_id: [3; 16],
                    instance_id: reader.metadata().instance_id,
                    bindings: vec![EvaluationDependency {
                        binding_id: [6; 16],
                        rule_set_id: [5; 16],
                        version_bytes: vec![1],
                    }],
                    tenant_tree_version,
                    registry_version,
                };
                assert_eq!(
                    final_check
                        .expect("bound authority must receive final check")
                        .try_final_time_for_test(&record, &constraints, || Some(110)),
                    Some(110)
                );
                let _guard = foreign.state.read().unwrap();
                assert_eq!(
                    reader.try_with_rechecked_dependencies_and_target(
                        &record,
                        None,
                        Some(&foreign.authority_id),
                        || ()
                    ),
                    Ok(None)
                );
                assert_eq!(
                    reader.try_with_rechecked_dependencies_and_target(
                        &record,
                        None,
                        Some(&authority.authority_id),
                        || ()
                    ),
                    Ok(Some(()))
                );
            })
            .unwrap();
        fake_session
            .with_authoritative_context(&root, |_, _, final_check| {
                assert!(
                    final_check.is_none(),
                    "foreign authority must not receive SessionFinalCheck"
                );
            })
            .unwrap();
        assert!(matches!(
            foreign.disable_card_with_sessions_for_isolated_tests(
                &owner.mutation_executor(),
                card_id(3),
                before
            ),
            Err(MemoryV1CardDisableError::Root(
                MutationError::ConcurrentModification
            ))
        ));
        assert_eq!(owner.handle().metadata().unwrap(), before);
        assert!(authority
            .verifier()
            .verify(issued.credential(), 110)
            .is_ok());
        assert!(foreign.verifier().verify(fake.credential(), 110).is_ok());
        assert!(issue_at(
            &authority.identity_session_adapter(),
            &root,
            identity(),
            110,
            300
        )
        .is_ok());
    }

    // memory—v1: Neither public candidate writer can disable a card behind the
    // session authority; coordinated disable followed by enable keeps old
    // credentials revoked, while a newly issued credential remains usable.
    #[cfg(feature = "test-support")]
    #[test]
    fn raw_card_disable_cannot_bypass_session_revocation() {
        use crate::memory_v1_db_rows::UserCardStatus;
        use crate::memory_v1_root::{ManagementMutationV2, MutationPrecondition};

        const CHILD: &str = "ASTRAL_RAW_CARD_DISABLE_COORDINATION_CHILD";
        if !run_isolated(
            CHILD,
            "memory_v1_session_authority::tests::raw_card_disable_cannot_bypass_session_revocation",
        ) {
            return;
        }
        let owner = binding_security_serving_root();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let adapter = authority.identity_session_adapter();
        let scope = RequestRootScope::new(owner.handle(), Uuid::new_v4());
        let root = scope.extension();
        let issued = issue_at(&adapter, &root, identity(), 100, 300).unwrap();
        let verifier = authority.verifier();
        let bound = verifier
            .verify_and_bind(issued.credential(), 100, &root)
            .unwrap();
        assert_eq!(
            verifier.revalidate_bound_session(&bound, &root, 110),
            Ok(())
        );
        let before = owner.handle().metadata().unwrap();
        let disable = ManagementMutationV2::UserCardStatus {
            user_card_id: [3; 16],
            status: UserCardStatus::Disabled,
        };
        let precondition = MutationPrecondition {
            evaluated_root_version: before.version,
        };
        assert!(matches!(
            owner.execute_mutation_with_precondition(&disable, &precondition),
            Err(MutationError::ConcurrentModification)
        ));
        assert!(matches!(
            owner.mutation_executor().execute(&disable, &precondition),
            Err(MutationError::ConcurrentModification)
        ));
        assert!(matches!(
            authority.disable_card_with_sessions(&owner.mutation_executor(), card_id(3), before),
            Err(MemoryV1CardDisableError::Session(
                MemoryV1SessionAuthorityError::Unavailable
            ))
        ));
        assert!(matches!(
            owner.execute_mutation_with_precondition_for_isolated_tests(&disable, &precondition),
            Err(MutationError::CardDisableRequiresSessionCoordinator)
        ));
        assert!(matches!(
            owner
                .mutation_executor()
                .execute_for_isolated_tests(&disable, &precondition),
            Err(MutationError::CardDisableRequiresSessionCoordinator)
        ));
        assert_eq!(owner.handle().metadata().unwrap(), before);
        assert!(authority
            .verifier()
            .verify(issued.credential(), 110)
            .is_ok());

        let (disabled, revoked) = authority
            .disable_card_with_sessions_for_isolated_tests(
                &owner.mutation_executor(),
                card_id(3),
                before,
            )
            .unwrap();
        assert_eq!(revoked, 1);
        assert_eq!(disabled.version, before.version + 1);
        assert_eq!(
            verifier.revalidate_bound_session(&bound, &root, 110),
            Err(MemoryV1SessionAuthorityError::Revoked)
        );
        assert_eq!(
            authority.verifier().verify(issued.credential(), 110),
            Err(MemoryV1SessionAuthorityError::Revoked)
        );
        let disabled_scope = RequestRootScope::new(owner.handle(), Uuid::new_v4());
        assert!(matches!(
            authority.verifier().verify_and_bind(
                issued.credential(),
                110,
                &disabled_scope.extension()
            ),
            Err(MemoryV1SessionAuthorityError::Revoked)
        ));
        assert!(matches!(
            issue_at(&adapter, &disabled_scope.extension(), identity(), 110, 300),
            Err(MemoryV1SessionAuthorityError::Unavailable)
        ));
        owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &ManagementMutationV2::UserCardStatus {
                    user_card_id: [3; 16],
                    status: UserCardStatus::Active,
                },
                &MutationPrecondition {
                    evaluated_root_version: disabled.version,
                },
            )
            .unwrap();
        assert!(matches!(
            authority.verifier().verify(issued.credential(), 110),
            Err(MemoryV1SessionAuthorityError::Revoked
                | MemoryV1SessionAuthorityError::InvalidCredential)
        ));
        let enabled_scope = RequestRootScope::new(owner.handle(), Uuid::new_v4());
        let enabled_root = enabled_scope.extension();
        let fresh = issue_at(&adapter, &enabled_root, identity(), 110, 300).unwrap();
        let fresh_bound = verifier
            .verify_and_bind(fresh.credential(), 110, &enabled_root)
            .unwrap();
        assert_eq!(
            verifier.revalidate_bound_session(&fresh_bound, &enabled_root, 110),
            Ok(())
        );
    }

    // memory—v1: Exercise actual root rechecks and the production clock boundary.
    #[cfg(feature = "test-support")]
    #[test]
    fn issuance_cleanup_respects_clock_root_and_capacity() {
        const CHILD: &str = "ASTRAL_SESSION_CLEANUP_CLOCK_ROOT_CHILD";
        if !run_isolated(
            CHILD,
            "memory_v1_session_authority::tests::issuance_cleanup_respects_clock_root_and_capacity",
        ) {
            return;
        }
        let owner = binding_security_serving_root();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let adapter = authority.identity_session_adapter();
        let verifier = authority.verifier();
        let scope = RequestRootScope::new(owner.handle(), Uuid::new_v4());
        let root = scope.extension();
        let now = IssueClock::System.sample(false).unwrap();
        let other_identity = CandidateIdentity {
            user_id: MemoryId::from_bytes([20; 16]),
            identity_card_id: MemoryId::from_bytes([21; 16]),
            user_card_id: MemoryId::from_bytes([22; 16]),
            tenant_id: MemoryId::from_bytes([23; 16]),
        };
        let other = adapter
            .issue_unchecked_for_test(other_identity, now, 3_600)
            .unwrap();
        let expired = adapter
            .issue_unchecked_for_test(identity(), now - 20, 10)
            .unwrap();
        authority.state.write().unwrap().max_records = 2;

        // A failed root recheck must leave even the eligible expired record in place.
        let foreign_identity = CandidateIdentity {
            user_card_id: MemoryId::from_bytes([99; 16]),
            ..identity()
        };
        assert!(matches!(
            adapter.issue_verified_session_in_root(&root, foreign_identity, now, 300),
            Err(MemoryV1SessionAuthorityError::Unavailable)
        ));
        assert_eq!(authority.state.read().unwrap().records.len(), 2);
        assert!(matches!(
            verifier.verify(expired.credential(), now),
            Err(MemoryV1SessionAuthorityError::Expired)
        ));
        assert!(verifier.verify(other.credential(), now).is_ok());

        // Future issuance fails without reclaiming even expired records.
        assert!(matches!(
            adapter.issue_verified_session_in_root(&root, identity(), now + 40_000, 300),
            Err(MemoryV1SessionAuthorityError::Unavailable)
        ));
        assert_eq!(authority.state.read().unwrap().records.len(), 2);
        assert!(matches!(
            verifier.verify(expired.credential(), now),
            Err(MemoryV1SessionAuthorityError::Expired)
        ));
        assert!(verifier.verify(other.credential(), now).is_ok());
        let fresh = adapter
            .issue_verified_session_in_root(&root, identity(), now, 300)
            .unwrap();
        assert!(verifier.verify(other.credential(), now).is_ok());
        assert!(verifier.verify(fresh.credential(), now).is_ok());
        assert!(matches!(
            verifier.verify(expired.credential(), now),
            Err(MemoryV1SessionAuthorityError::InvalidCredential)
        ));
        assert_eq!(authority.state.read().unwrap().records.len(), 2);
        assert!(matches!(
            adapter.issue_verified_session_in_root(&root, identity(), now, 300),
            Err(MemoryV1SessionAuthorityError::CapacityExhausted)
        ));
        assert!(verifier.verify(other.credential(), now).is_ok());
        assert!(verifier.verify(fresh.credential(), now).is_ok());
    }

    // memory—v1: Missing and regressed observations cannot remove any record.
    #[cfg(feature = "test-support")]
    #[test]
    fn issuance_cleanup_rejects_missing_and_regressed_clock() {
        const CHILD: &str = "ASTRAL_SESSION_CLEANUP_BAD_CLOCK_CHILD";
        if !run_isolated(
            CHILD,
            "memory_v1_session_authority::tests::issuance_cleanup_rejects_missing_and_regressed_clock",
        ) {
            return;
        }
        let owner = binding_security_serving_root();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let adapter = authority.identity_session_adapter();
        let scope = RequestRootScope::new(owner.handle(), Uuid::new_v4());
        let root = scope.extension();
        let live = adapter
            .issue_unchecked_for_test(identity(), 100, 300)
            .unwrap();
        let expired = adapter
            .issue_unchecked_for_test(identity(), 50, 10)
            .unwrap();
        let issue_at = |observation| {
            adapter.session_issuer.issue_in_root(
                &root,
                adapter.proof_issuer.prove_verified_identity(identity()),
                200,
                300,
                IssueClock::Fixed {
                    first: observation,
                    final_time: observation,
                },
            )
        };
        assert!(matches!(
            issue_at(None),
            Err(MemoryV1SessionAuthorityError::Unavailable)
        ));
        assert_eq!(authority.state.read().unwrap().records.len(), 2);
        let issued = issue_at(Some(200)).unwrap();
        assert!(authority.verifier().verify(live.credential(), 200).is_ok());
        assert!(authority
            .verifier()
            .verify(issued.credential(), 200)
            .is_ok());
        assert!(matches!(
            authority.verifier().verify(expired.credential(), 200),
            Err(MemoryV1SessionAuthorityError::InvalidCredential)
        ));
        assert!(matches!(
            issue_at(Some(199)),
            Err(MemoryV1SessionAuthorityError::Unavailable)
        ));
        assert_eq!(authority.state.read().unwrap().records.len(), 2);
        assert!(authority.verifier().verify(live.credential(), 200).is_ok());
        assert!(authority
            .verifier()
            .verify(issued.credential(), 200)
            .is_ok());
    }

    // memory—v1: Both observations fence issuance without changing any records on failure.
    #[cfg(feature = "test-support")]
    #[test]
    fn issuance_checks_both_clock_observations() {
        const CHILD: &str = "ASTRAL_SESSION_TWO_CLOCKS_CHILD";
        if !run_isolated(
            CHILD,
            "memory_v1_session_authority::tests::issuance_checks_both_clock_observations",
        ) {
            return;
        }
        let owner = binding_security_serving_root();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let adapter = authority.identity_session_adapter();
        let verifier = authority.verifier();
        let scope = RequestRootScope::new(owner.handle(), Uuid::new_v4());
        let root = scope.extension();
        let other = adapter
            .issue_unchecked_for_test(identity_for_card(8), 100, 300)
            .unwrap();
        let expired = adapter
            .issue_unchecked_for_test(identity(), 50, 10)
            .unwrap();
        let issue = |now, lifetime, first, final_time| {
            adapter.session_issuer.issue_in_root(
                &root,
                adapter.proof_issuer.prove_verified_identity(identity()),
                now,
                lifetime,
                IssueClock::Fixed { first, final_time },
            )
        };
        for (now, lifetime, first, final_time) in [
            (201, 10, Some(200), Some(200)), // future
            (190, 10, Some(200), Some(200)), // already expired
            (200, 2, Some(201), Some(202)),  // expires at final observation
            (202, 10, Some(202), Some(201)), // regresses under root lock
            (202, 10, Some(202), None),      // final clock unavailable
        ] {
            assert!(matches!(
                issue(now, lifetime, first, final_time),
                Err(MemoryV1SessionAuthorityError::Unavailable)
            ));
            assert_eq!(authority.state.read().unwrap().records.len(), 2);
            assert!(verifier.verify(other.credential(), 200).is_ok());
            assert_eq!(
                verifier.verify(expired.credential(), 200),
                Err(MemoryV1SessionAuthorityError::Expired)
            );
        }
        let issued = issue(202, 1, Some(202), Some(202)).unwrap();
        assert!(verifier.verify(issued.credential(), 202).is_ok());
        assert_eq!(
            verifier.verify(issued.credential(), 203),
            Err(MemoryV1SessionAuthorityError::Expired)
        );
        assert!(verifier.verify(other.credential(), 202).is_ok());
        assert_eq!(
            verifier.verify(expired.credential(), 202),
            Err(MemoryV1SessionAuthorityError::InvalidCredential)
        );
    }

    #[test]
    #[allow(deprecated)]
    fn legacy_issuance_without_root_fails_closed() {
        let authority = MemoryV1SessionAuthority::new();
        let adapter = authority.identity_session_adapter();

        assert!(matches!(
            adapter.issue_verified_session(identity(), 100, 30),
            Err(MemoryV1SessionAuthorityError::Unavailable)
        ));
        assert!(authority.state.read().unwrap().records.is_empty());
    }

    // memory—v1: Overflow revokes all existing target sessions without disabling
    // the card; bound final checks fail while other cards and later issuance work.
    #[cfg(feature = "test-support")]
    #[test]
    fn card_disable_generation_overflow_has_no_partial_effect() {
        use crate::memory_v1_root::{DependencyRecord, EvaluationDependency};
        use crate::memory_v1_session::{FinalCheckTimeConstraints, FinalCheckWindow};

        const CHILD: &str = "ASTRAL_MEMORY_V1_CARD_DISABLE_OVERFLOW_CHILD";
        if !run_isolated(
            CHILD,
            "memory_v1_session_authority::tests::card_disable_generation_overflow_has_no_partial_effect",
        ) {
            return;
        }
        let owner = binding_security_serving_root();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let adapter = authority.identity_session_adapter();
        let verifier = authority.verifier();
        let scope = RequestRootScope::new(owner.handle(), Uuid::new_v4());
        let root = scope.extension();
        let first = issue_at(&adapter, &root, identity(), 100, 300).unwrap();
        let exhausted = issue_at(&adapter, &root, identity(), 100, 300).unwrap();
        let other = issue_for_card(&adapter, 4, 100);
        let bound_first = verifier
            .verify_and_bind(first.credential(), 100, &root)
            .unwrap();
        let bound_exhausted = verifier
            .verify_and_bind(exhausted.credential(), 100, &root)
            .unwrap();
        let windows = [FinalCheckWindow {
            entry_validity: None,
            binding_from: None,
            binding_until: None,
        }];
        let constraints = FinalCheckTimeConstraints {
            start_time: 100,
            future_boundaries: &[],
            winning_windows: &windows,
        };
        let final_time = |bound: &RequestSessionExtension| {
            bound
                .with_authoritative_context(&root, |_, reader, final_check| {
                    let (tenant_tree_version, registry_version) =
                        reader.dependency_versions().unwrap();
                    let dependencies = DependencyRecord {
                        card_id: [3; 16],
                        instance_id: reader.metadata().instance_id,
                        bindings: vec![EvaluationDependency {
                            binding_id: [6; 16],
                            rule_set_id: [5; 16],
                            version_bytes: vec![1],
                        }],
                        tenant_tree_version,
                        registry_version,
                    };
                    final_check.unwrap().try_final_time_for_test(
                        &dependencies,
                        &constraints,
                        || Some(110),
                    )
                })
                .unwrap()
        };
        assert_eq!(final_time(&bound_first), Some(110));
        assert_eq!(final_time(&bound_exhausted), Some(110));
        let exhausted_digest = digest_credential(exhausted.credential());
        authority
            .state
            .write()
            .unwrap()
            .records
            .get_mut(&exhausted_digest)
            .unwrap()
            .revocation_generation = u64::MAX;
        let before = owner.handle().metadata().unwrap();
        assert!(matches!(
            authority.disable_card_with_sessions_for_isolated_tests(
                &owner.mutation_executor(),
                card_id(3),
                before
            ),
            Err(MemoryV1CardDisableError::Session(
                MemoryV1SessionAuthorityError::RevocationGenerationExhausted
            ))
        ));
        assert_eq!(owner.handle().metadata().unwrap(), before);
        for issued in [&first, &exhausted] {
            assert_eq!(
                verifier.verify(issued.credential(), 110),
                Err(MemoryV1SessionAuthorityError::Revoked)
            );
        }
        assert_eq!(
            verifier.revalidate_bound_session(&bound_first, &root, 110),
            Err(MemoryV1SessionAuthorityError::Revoked)
        );
        assert_eq!(
            verifier.revalidate_bound_session(&bound_exhausted, &root, 110),
            Err(MemoryV1SessionAuthorityError::Revoked)
        );
        assert_eq!(final_time(&bound_first), None);
        assert_eq!(final_time(&bound_exhausted), None);
        assert!(verifier.verify(other.credential(), 110).is_ok());
        assert_eq!(
            authority
                .state
                .read()
                .unwrap()
                .records
                .get(&exhausted_digest)
                .unwrap()
                .revocation_generation,
            u64::MAX
        );
        let fresh = issue_at(&adapter, &root, identity(), 110, 300).unwrap();
        assert!(verifier.verify(fresh.credential(), 110).is_ok());
        assert!(verifier.verify(other.credential(), 110).is_ok());
        assert_eq!(owner.handle().metadata().unwrap(), before);
    }

    #[test]
    fn bound_session_revalidation_fails_after_revocation() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_SESSION_REVALIDATION_REVOKE_CHILD";
        if !run_isolated(
            CHILD,
            "memory_v1_session_authority::tests::bound_session_revalidation_fails_after_revocation",
        ) {
            return;
        }
        let authority = MemoryV1SessionAuthority::new();
        let adapter = authority.identity_session_adapter();
        let verifier = authority.verifier();
        let issued = adapter
            .issue_unchecked_for_test(identity(), 100, 30)
            .unwrap();
        let (_handle, request_scope) = scope(&authority);
        let root = request_scope.extension();
        let bound = verifier
            .verify_and_bind(issued.credential(), 100, &root)
            .unwrap();

        verifier
            .revalidate_bound_session(&bound, &root, 110)
            .expect("live bound session should pass");
        adapter.revoke(issued.credential()).unwrap();
        assert_eq!(
            verifier.revalidate_bound_session(&bound, &root, 110),
            Err(MemoryV1SessionAuthorityError::Revoked)
        );
    }

    #[test]
    fn revalidation_rejects_foreign_scope_and_authority() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_SESSION_FOREIGN_CHILD";
        if !run_isolated(
            CHILD,
            "memory_v1_session_authority::tests::revalidation_rejects_foreign_scope_and_authority",
        ) {
            return;
        }
        let first = MemoryV1SessionAuthority::new();
        let second = MemoryV1SessionAuthority::new();
        let adapter = first.identity_session_adapter();
        let issued = adapter
            .issue_unchecked_for_test(identity(), 100, 30)
            .unwrap();
        let (handle, first_scope) = scope(&first);
        let first_root = first_scope.extension();
        let bound = first
            .verifier()
            .verify_and_bind(issued.credential(), 100, &first_root)
            .unwrap();
        let second_scope = RequestRootScope::new(handle, Uuid::new_v4());
        let second_root = second_scope.extension();

        assert_eq!(
            first
                .verifier()
                .revalidate_bound_session(&bound, &second_root, 110),
            Err(MemoryV1SessionAuthorityError::InvalidCredential)
        );
        assert_eq!(
            second
                .verifier()
                .revalidate_bound_session(&bound, &first_root, 110),
            Err(MemoryV1SessionAuthorityError::InvalidCredential)
        );
    }

    #[test]
    fn compatibility_fact_binding_cannot_pass_live_revalidation() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_SESSION_COMPATIBILITY_CHILD";
        if !run_isolated(
            CHILD,
            "memory_v1_session_authority::tests::compatibility_fact_binding_cannot_pass_live_revalidation",
        ) {
            return;
        }
        let authority = MemoryV1SessionAuthority::new();
        let adapter = authority.identity_session_adapter();
        let verifier = authority.verifier();
        let issued = adapter
            .issue_unchecked_for_test(identity(), 100, 30)
            .unwrap();
        let authenticated = verifier.verify(issued.credential(), 100).unwrap();
        let (_handle, request_scope) = scope(&authority);
        let root = request_scope.extension();
        let cloned_facts = authenticated.facts.clone();
        let compatibility_bound = root.bind_session_facts(cloned_facts).unwrap();

        assert_eq!(
            verifier.revalidate_bound_session(&compatibility_bound, &root, 110),
            Err(MemoryV1SessionAuthorityError::InvalidCredential)
        );
    }

    #[test]
    fn revalidation_fails_closed_for_cleaned_records_and_bad_times() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_SESSION_CLEANUP_CHILD";
        if !run_isolated(
            CHILD,
            "memory_v1_session_authority::tests::revalidation_fails_closed_for_cleaned_records_and_bad_times",
        ) {
            return;
        }
        let authority = MemoryV1SessionAuthority::new();
        let adapter = authority.identity_session_adapter();
        let verifier = authority.verifier();
        let issued = adapter
            .issue_unchecked_for_test(identity(), 100, 1)
            .unwrap();
        let (_handle, request_scope) = scope(&authority);
        let root = request_scope.extension();
        let bound = verifier
            .verify_and_bind(issued.credential(), 100, &root)
            .unwrap();

        assert_eq!(
            verifier.revalidate_bound_session(&bound, &root, 101),
            Err(MemoryV1SessionAuthorityError::Expired)
        );
        authority.state.write().unwrap().records.clear();
        assert_eq!(
            verifier.revalidate_bound_session(&bound, &root, 100),
            Err(MemoryV1SessionAuthorityError::InvalidCredential)
        );

        let bad_time = adapter
            .issue_unchecked_for_test(identity(), 200, 10)
            .unwrap();
        let (_bad_handle, bad_request_scope) = scope(&authority);
        let bad_root = bad_request_scope.extension();
        let bad_bound = verifier
            .verify_and_bind(bad_time.credential(), 200, &bad_root)
            .unwrap();
        assert_eq!(
            verifier.revalidate_bound_session(&bad_bound, &bad_root, 199),
            Err(MemoryV1SessionAuthorityError::Expired)
        );
    }

    #[test]
    fn revoke_sessions_for_card_is_scoped_idempotent_and_empty_safe() {
        let authority = MemoryV1SessionAuthority::new();
        let adapter = authority.identity_session_adapter();
        let verifier = authority.verifier();
        let target_one = issue_for_card(&adapter, 3, 100);
        let target_two = issue_for_card(&adapter, 3, 100);
        let other_card = issue_for_card(&adapter, 4, 100);
        let already_revoked = issue_for_card(&adapter, 3, 100);
        adapter.revoke(already_revoked.credential()).unwrap();

        assert_eq!(
            adapter.revoke_sessions_for_user_card(card_id(9)).unwrap(),
            0
        );
        assert_eq!(
            adapter.revoke_sessions_for_user_card(card_id(3)).unwrap(),
            2
        );
        assert_eq!(
            adapter.revoke_sessions_for_user_card(card_id(3)).unwrap(),
            0
        );

        assert_eq!(
            verifier.verify(target_one.credential(), 110),
            Err(MemoryV1SessionAuthorityError::Revoked)
        );
        assert_eq!(
            verifier.verify(target_two.credential(), 110),
            Err(MemoryV1SessionAuthorityError::Revoked)
        );
        assert!(verifier.verify(other_card.credential(), 110).is_ok());
        assert_eq!(
            verifier.verify(already_revoked.credential(), 110),
            Err(MemoryV1SessionAuthorityError::Revoked)
        );
    }

    #[test]
    fn revoke_sessions_for_card_generation_overflow_is_atomic() {
        const CHILD: &str = "ASTRAL_SESSION_BATCH_EXHAUSTION_CHILD";
        if !run_isolated(CHILD, "memory_v1_session_authority::tests::revoke_sessions_for_card_generation_overflow_is_atomic") {
            return;
        }
        let authority = MemoryV1SessionAuthority::new();
        let adapter = authority.identity_session_adapter();
        let verifier = authority.verifier();
        let first = issue_for_card(&adapter, 3, 100);
        let second = issue_for_card(&adapter, 3, 100);
        let other = issue_for_card(&adapter, 4, 100);
        let (_handle, request_scope) = scope(&authority);
        let root = request_scope.extension();
        let bound_first = verifier
            .verify_and_bind(first.credential(), 100, &root)
            .unwrap();
        let bound_second = verifier
            .verify_and_bind(second.credential(), 100, &root)
            .unwrap();
        {
            let mut state = authority.state.write().unwrap();
            state
                .records
                .get_mut(&digest_credential(first.credential()))
                .unwrap()
                .revocation_generation = u64::MAX - 1;
            state
                .records
                .get_mut(&digest_credential(second.credential()))
                .unwrap()
                .revocation_generation = u64::MAX;
        }

        assert_eq!(
            adapter.revoke_sessions_for_user_card(card_id(3)),
            Err(MemoryV1SessionAuthorityError::RevocationGenerationExhausted)
        );
        assert_eq!(
            verifier.verify(first.credential(), 110),
            Err(MemoryV1SessionAuthorityError::Revoked)
        );
        assert_eq!(
            verifier.verify(second.credential(), 110),
            Err(MemoryV1SessionAuthorityError::Revoked)
        );
        assert_eq!(
            verifier.revalidate_bound_session(&bound_first, &root, 110),
            Err(MemoryV1SessionAuthorityError::Revoked)
        );
        assert_eq!(
            verifier.revalidate_bound_session(&bound_second, &root, 110),
            Err(MemoryV1SessionAuthorityError::Revoked)
        );
        assert!(verifier.verify(other.credential(), 110).is_ok());
        let state = authority.state.read().unwrap();
        assert_eq!(
            state
                .records
                .get(&digest_credential(first.credential()))
                .unwrap()
                .revocation_generation,
            u64::MAX
        );
        assert_eq!(
            state
                .records
                .get(&digest_credential(second.credential()))
                .unwrap()
                .revocation_generation,
            u64::MAX
        );
    }

    // memory—v1: Exhaustion revokes a bound record and blocks its final check.
    #[cfg(feature = "test-support")]
    #[test]
    fn exhausted_revocation_blocks_live_final_check() {
        use crate::memory_v1_root::{DependencyRecord, EvaluationDependency};
        use crate::memory_v1_session::{FinalCheckTimeConstraints, FinalCheckWindow};
        const CHILD: &str = "ASTRAL_SESSION_REVOKE_EXHAUSTION_FINAL_CHILD";
        if !run_isolated(
            CHILD,
            "memory_v1_session_authority::tests::exhausted_revocation_blocks_live_final_check",
        ) {
            return;
        }
        let owner = binding_security_serving_root();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let adapter = authority.identity_session_adapter();
        let scope = RequestRootScope::new(owner.handle(), Uuid::new_v4());
        let root = scope.extension();
        let issued = issue_at(&adapter, &root, identity(), 100, 300).unwrap();
        let verifier = authority.verifier();
        let bound = verifier
            .verify_and_bind(issued.credential(), 100, &root)
            .unwrap();
        let windows = [FinalCheckWindow {
            entry_validity: None,
            binding_from: None,
            binding_until: None,
        }];
        let constraints = FinalCheckTimeConstraints {
            start_time: 100,
            future_boundaries: &[],
            winning_windows: &windows,
        };
        let check = || {
            bound
                .with_authoritative_context(&root, |_, reader, final_check| {
                    let (tenant_tree_version, registry_version) =
                        reader.dependency_versions().unwrap();
                    let record = DependencyRecord {
                        card_id: [3; 16],
                        instance_id: reader.metadata().instance_id,
                        bindings: vec![EvaluationDependency {
                            binding_id: [6; 16],
                            rule_set_id: [5; 16],
                            version_bytes: vec![1],
                        }],
                        tenant_tree_version,
                        registry_version,
                    };
                    final_check
                        .unwrap()
                        .try_final_time_for_test(&record, &constraints, || Some(110))
                })
                .unwrap()
        };
        assert_eq!(check(), Some(110));
        authority
            .state
            .write()
            .unwrap()
            .records
            .get_mut(&digest_credential(issued.credential()))
            .unwrap()
            .revocation_generation = u64::MAX;
        assert_eq!(
            adapter.revoke(issued.credential()),
            Err(MemoryV1SessionAuthorityError::RevocationGenerationExhausted)
        );
        assert_eq!(
            verifier.verify(issued.credential(), 110),
            Err(MemoryV1SessionAuthorityError::Revoked)
        );
        assert_eq!(check(), None);
        assert_eq!(adapter.revoke(issued.credential()), Ok(()));
    }

    #[test]
    fn bound_sessions_for_disabled_card_fail_after_batch_revocation() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_SESSION_BATCH_BOUND_CHILD";
        if !run_isolated(
            CHILD,
            "memory_v1_session_authority::tests::bound_sessions_for_disabled_card_fail_after_batch_revocation",
        ) {
            return;
        }
        let authority = MemoryV1SessionAuthority::new();
        let adapter = authority.identity_session_adapter();
        let verifier = authority.verifier();
        let first = issue_for_card(&adapter, 3, 100);
        let second = issue_for_card(&adapter, 3, 100);
        let (_handle, first_scope) = scope(&authority);
        let first_root = first_scope.extension();
        let (_other_handle, second_scope) = scope(&authority);
        let second_root = second_scope.extension();
        let bound_first = verifier
            .verify_and_bind(first.credential(), 100, &first_root)
            .unwrap();
        let bound_second = verifier
            .verify_and_bind(second.credential(), 100, &second_root)
            .unwrap();

        assert_eq!(
            adapter.revoke_sessions_for_user_card(card_id(3)).unwrap(),
            2
        );
        assert_eq!(
            verifier.revalidate_bound_session(&bound_first, &first_root, 110),
            Err(MemoryV1SessionAuthorityError::Revoked)
        );
        assert_eq!(
            verifier.revalidate_bound_session(&bound_second, &second_root, 110),
            Err(MemoryV1SessionAuthorityError::Revoked)
        );
    }

    #[test]
    fn concurrent_issue_and_card_batch_revoke_have_one_lock_linearization() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let authority = Arc::new(MemoryV1SessionAuthority::new());
        let adapter = authority.identity_session_adapter();
        let verifier = authority.verifier();
        let initial = issue_for_card(&adapter, 3, 100);
        let barrier = Arc::new(Barrier::new(2));
        let revoke_adapter = adapter.clone();
        let revoke_barrier = Arc::clone(&barrier);
        let revoke_thread = thread::spawn(move || {
            revoke_barrier.wait();
            revoke_adapter.revoke_sessions_for_user_card(card_id(3))
        });
        let issue_adapter = adapter.clone();
        let issue_barrier = Arc::clone(&barrier);
        let issue_thread = thread::spawn(move || {
            issue_barrier.wait();
            issue_adapter.issue_unchecked_for_test(identity_for_card(3), 100, 300)
        });

        let revoke_result = revoke_thread.join().unwrap().unwrap();
        let issued = issue_thread.join().unwrap().unwrap();
        assert!(matches!(revoke_result, 1 | 2));

        let initial_result = verifier.verify(initial.credential(), 110);
        assert!(matches!(
            initial_result,
            Err(MemoryV1SessionAuthorityError::Revoked)
                | Err(MemoryV1SessionAuthorityError::InvalidCredential)
        ));
        let issued_result = verifier.verify(issued.credential(), 110);
        match revoke_result {
            1 => assert!(issued_result.is_ok()),
            2 => assert_eq!(issued_result, Err(MemoryV1SessionAuthorityError::Revoked)),
            _ => unreachable!("revoke count was checked above"),
        }
    }

    #[test]
    fn revoked_credential_does_not_reappear_after_later_same_card_issuance() {
        let authority = MemoryV1SessionAuthority::new();
        let adapter = authority.identity_session_adapter();
        let verifier = authority.verifier();
        let old = issue_for_card(&adapter, 3, 100);

        assert_eq!(adapter.revoke_sessions_for_user_card(card_id(3)), Ok(1));
        let replacement = issue_for_card(&adapter, 3, 200);

        assert!(matches!(
            verifier.verify(old.credential(), 210),
            Err(MemoryV1SessionAuthorityError::Revoked)
                | Err(MemoryV1SessionAuthorityError::InvalidCredential)
        ));
        assert!(verifier.verify(replacement.credential(), 210).is_ok());
    }

    #[test]
    fn opaque_credential_validates_and_revocation_closes_it() {
        let authority = MemoryV1SessionAuthority::new();
        let adapter = authority.identity_session_adapter();
        let verifier = authority.verifier();
        let issued = adapter
            .issue_unchecked_for_test(identity(), 100, 30)
            .unwrap();
        let session = verifier.verify(issued.credential(), 100).unwrap();
        assert_eq!(session.session_id().into_bytes().len(), 16);
        assert_eq!(
            verifier.verify(issued.credential(), 130),
            Err(MemoryV1SessionAuthorityError::Expired)
        );
        adapter.revoke(issued.credential()).unwrap();
        assert_eq!(
            verifier.verify(issued.credential(), 110),
            Err(MemoryV1SessionAuthorityError::Revoked)
        );
    }

    #[test]
    fn proof_from_another_authority_is_rejected_inside_the_private_boundary() {
        let first = MemoryV1SessionAuthority::new();
        let second = MemoryV1SessionAuthority::new();
        let proof = first
            .identity_session_adapter()
            .proof_issuer
            .prove_verified_identity(identity());
        assert!(matches!(
            second
                .identity_session_adapter()
                .session_issuer
                .issue(proof, 100, 30),
            Err(MemoryV1SessionAuthorityError::ForeignIdentityProof)
        ));
    }

    // memory—v1: Each revocation path must independently make cleanup eligible.
    #[test]
    fn cleanup_hint_tracks_expiry_and_each_revocation_path() {
        for path in 0..3 {
            let authority = MemoryV1SessionAuthority::new();
            let adapter = authority.identity_session_adapter();
            let verifier = authority.verifier();
            let live = issue_for_card(&adapter, 4, 100);
            let revoked = issue_for_card(&adapter, 3, 100);
            assert!(CleanupPlan::prepare(&authority.state.read().unwrap(), 399)
                .unwrap()
                .is_none());
            assert_eq!(
                CleanupPlan::prepare(&authority.state.read().unwrap(), 400)
                    .unwrap()
                    .unwrap()
                    .len(),
                2,
            );

            match path {
                0 => adapter.revoke(revoked.credential()).unwrap(),
                1 => assert_eq!(adapter.revoke_sessions_for_user_card(card_id(3)), Ok(1)),
                2 => authority.publish_card_disable([3; 16], || Ok(())).unwrap(),
                _ => unreachable!(),
            }
            assert_eq!(
                verifier.verify(revoked.credential(), 110),
                Err(MemoryV1SessionAuthorityError::Revoked),
            );
            authority.state.write().unwrap().max_records = 2;
            let fresh = issue_for_card(&adapter, 3, 110);
            assert_eq!(
                verifier.verify(revoked.credential(), 110),
                Err(MemoryV1SessionAuthorityError::InvalidCredential),
            );
            assert!(verifier.verify(live.credential(), 110).is_ok());
            assert!(verifier.verify(fresh.credential(), 110).is_ok());
            let state = authority.state.read().unwrap();
            assert_eq!(state.records.len(), 2);
            assert!(CleanupPlan::prepare(&state, 399).unwrap().is_none());
            assert_eq!(CleanupPlan::prepare(&state, 400).unwrap().unwrap().len(), 1);
        }
    }

    #[test]
    fn expired_records_are_reclaimed_before_capacity_is_checked() {
        let authority = MemoryV1SessionAuthority::new();
        let adapter = authority.identity_session_adapter();
        let verifier = authority.verifier();
        let expired = adapter
            .issue_unchecked_for_test(identity(), 100, 1)
            .unwrap();
        assert_eq!(authority.state.read().unwrap().records.len(), 1);

        let current = adapter
            .issue_unchecked_for_test(identity(), 102, 30)
            .unwrap();
        assert_eq!(authority.state.read().unwrap().records.len(), 1);
        assert_eq!(
            verifier.verify(expired.credential(), 102),
            Err(MemoryV1SessionAuthorityError::InvalidCredential)
        );
        assert!(verifier.verify(current.credential(), 102).is_ok());
    }

    #[test]
    fn capacity_is_bounded_and_repeated_revoke_is_idempotent() {
        let authority = MemoryV1SessionAuthority::new();
        authority.state.write().unwrap().max_records = 1;
        let adapter = authority.identity_session_adapter();
        let first = adapter
            .issue_unchecked_for_test(identity(), 100, 30)
            .unwrap();
        assert!(matches!(
            adapter.issue_unchecked_for_test(identity(), 100, 30),
            Err(MemoryV1SessionAuthorityError::CapacityExhausted)
        ));

        adapter.revoke(first.credential()).unwrap();
        assert_eq!(
            authority
                .state
                .read()
                .unwrap()
                .records
                .values()
                .next()
                .unwrap()
                .revocation_generation,
            1
        );
        adapter.revoke(first.credential()).unwrap();
        assert_eq!(
            authority
                .state
                .read()
                .unwrap()
                .records
                .values()
                .next()
                .unwrap()
                .revocation_generation,
            1
        );
    }

    #[test]
    fn malformed_or_legacy_credentials_are_rejected() {
        let authority = MemoryV1SessionAuthority::new();
        let verifier = authority.verifier();
        assert_eq!(
            verifier.verify("Bearer legacy", 100),
            Err(MemoryV1SessionAuthorityError::InvalidCredential)
        );
    }
}
