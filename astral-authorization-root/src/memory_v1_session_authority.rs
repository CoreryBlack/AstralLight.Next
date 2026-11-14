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
use super::memory_v1_session::{
    RequestSessionError, RequestSessionExtension, VerifiedSessionFacts,
};

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
}

struct IdentityProofState;

/// An Identity-owned proof that a memory—v1 principal was verified.
///
/// The fields are private and the value can only be obtained from the
/// IdentityProofIssuer capability belonging to one session authority. UUIDs,
/// headers and candidate rows cannot be converted into this type directly.
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
}

/// Capability retained by Identity to issue and revoke memory—v1 sessions.
#[derive(Clone)]
struct MemoryV1SessionIssuer {
    state: Arc<RwLock<SessionState>>,
    identity_proof_state: Arc<IdentityProofState>,
}

/// Read-only capability retained by Gateway to authenticate access credentials.
#[derive(Clone)]
pub struct MemoryV1SessionVerifier {
    state: Arc<RwLock<SessionState>>,
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

impl MemoryV1SessionAuthority {
    /// Create an empty authority. No session exists until trusted Identity
    /// verification supplies a proof to the issuer.
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(SessionState {
                records: HashMap::new(),
                max_records: MAX_ACTIVE_SESSIONS,
            })),
            identity_proof_state: Arc::new(IdentityProofState),
        }
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
            },
        }
    }

    /// Return a verifier that can only validate already-issued sessions.
    pub fn verifier(&self) -> MemoryV1SessionVerifier {
        MemoryV1SessionVerifier {
            state: Arc::clone(&self.state),
        }
    }
}

impl Default for MemoryV1SessionAuthority {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryV1IdentityProofIssuer {
    /// Construct a private proof after the Identity adapter has completed all
    /// credential and card checks. This type and method are crate-private.
    fn prove_verified_identity(&self, identity: CandidateIdentity) -> MemoryV1IdentityProof {
        MemoryV1IdentityProof {
            identity,
            state: Arc::downgrade(&self.state),
        }
    }
}

impl MemoryV1IdentitySessionAdapter {
    /// Issue an opaque session after the Identity-owned adapter has completed
    /// credential, card, tenant and lifecycle checks.
    ///
    /// The adapter deliberately accepts only the UUID-native memory—v1 identity
    /// value. Legacy integer identity facts cannot be converted at this boundary.
    pub fn issue_verified_session(
        &self,
        identity: CandidateIdentity,
        now_unix_seconds: i64,
        lifetime_seconds: i64,
    ) -> Result<MemoryV1IssuedSession, MemoryV1SessionAuthorityError> {
        let proof = self.proof_issuer.prove_verified_identity(identity);
        self.session_issuer
            .issue(proof, now_unix_seconds, lifetime_seconds)
    }

    /// Revoke an opaque session through the same Identity-owned capability.
    pub fn revoke(&self, credential: &str) -> Result<(), MemoryV1SessionAuthorityError> {
        self.session_issuer.revoke(credential)
    }
}

impl MemoryV1SessionIssuer {
    /// Issue one opaque access credential for an Identity-owned verification
    /// proof. Arbitrary `CandidateIdentity` values are not accepted here.
    fn issue(
        &self,
        proof: MemoryV1IdentityProof,
        now_unix_seconds: i64,
        lifetime_seconds: i64,
    ) -> Result<MemoryV1IssuedSession, MemoryV1SessionAuthorityError> {
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
        let mut state = self
            .state
            .write()
            .map_err(|_| MemoryV1SessionAuthorityError::Unavailable)?;
        state.records.retain(|_, record| {
            !record.revoked && record.facts.expires_at_unix_seconds() > now_unix_seconds
        });
        if state.records.len() >= state.max_records {
            return Err(MemoryV1SessionAuthorityError::CapacityExhausted);
        }
        state.records.insert(digest, record);
        Ok(MemoryV1IssuedSession { credential })
    }

    /// Revoke one credential and advance its revocation generation.
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
        record.revocation_generation = record
            .revocation_generation
            .checked_add(1)
            .ok_or(MemoryV1SessionAuthorityError::RevocationGenerationExhausted)?;
        record.revoked = true;
        Ok(())
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
            })),
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
        authenticated.bind_to(root)
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
    /// Bind authority-verified facts to one exact request root scope.
    ///
    /// This remains private to the authority module's verified flow; callers
    /// should use `MemoryV1SessionVerifier::verify_and_bind` so revocation is
    /// checked immediately before binding.
    fn bind_to(
        &self,
        root: &RequestRootExtension,
    ) -> Result<RequestSessionExtension, MemoryV1SessionAuthorityError> {
        root.bind_session_facts(self.facts.clone())
            .map_err(MemoryV1SessionAuthorityError::Scope)
    }

    /// Return a non-authorizing diagnostic copy for trusted observability.
    pub fn session_id(&self) -> MemoryId {
        self.facts.session_id()
    }
}

impl MemoryV1IssuedSession {
    /// Return the opaque bearer credential for the client transport.
    pub fn credential(&self) -> &str {
        &self.credential
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

    fn identity() -> CandidateIdentity {
        CandidateIdentity {
            user_id: MemoryId::from_bytes([1; 16]),
            identity_card_id: MemoryId::from_bytes([2; 16]),
            user_card_id: MemoryId::from_bytes([3; 16]),
            tenant_id: MemoryId::from_bytes([4; 16]),
        }
    }

    #[test]
    fn opaque_credential_validates_and_revocation_closes_it() {
        let authority = MemoryV1SessionAuthority::new();
        let adapter = authority.identity_session_adapter();
        let verifier = authority.verifier();
        let issued = adapter.issue_verified_session(identity(), 100, 30).unwrap();
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

    #[test]
    fn expired_records_are_reclaimed_before_capacity_is_checked() {
        let authority = MemoryV1SessionAuthority::new();
        let adapter = authority.identity_session_adapter();
        let verifier = authority.verifier();
        let expired = adapter.issue_verified_session(identity(), 100, 1).unwrap();
        assert_eq!(authority.state.read().unwrap().records.len(), 1);

        let current = adapter.issue_verified_session(identity(), 102, 30).unwrap();
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
        let first = adapter.issue_verified_session(identity(), 100, 30).unwrap();
        assert!(matches!(
            adapter.issue_verified_session(identity(), 100, 30),
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
