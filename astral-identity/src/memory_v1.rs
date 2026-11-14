use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

use astral_authorization_root::memory_v1_db_rows::Table;
use astral_authorization_root::memory_v1_hamt::CandidateError;
use astral_authorization_root::memory_v1_request::RequestRootExtension;
use astral_authorization_root::memory_v1_root::{RequestRootReader, RootError, RootStatus};
use astral_authorization_root::memory_v1_session_authority::{
    MemoryV1IdentitySessionAdapter, MemoryV1IssuedSession, MemoryV1SessionAuthorityError,
};
use astral_types::memory_v1::{CandidateIdentity, MemoryId};

const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_PASSWORD_BYTES: usize = 1024;

/// memory—v1: Credential lifecycle is separate from identity-card and
/// user-card lifecycle. A credential record is authentication input only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryV1CredentialStatus {
    Active,
    Disabled,
    Revoked,
}

/// memory—v1: UUID-native credential source row returned by an Identity-owned
/// repository. This is not an identity proof and contains no card or tenant.
#[derive(Clone)]
pub struct MemoryV1CredentialRecord {
    user_id: MemoryId,
    password_hash: String,
    status: MemoryV1CredentialStatus,
    credential_revision: u64,
}

impl MemoryV1CredentialRecord {
    /// memory—v1: Construct a repository record without accepting legacy IDs.
    pub fn new(
        user_id: MemoryId,
        password_hash: String,
        status: MemoryV1CredentialStatus,
        credential_revision: u64,
    ) -> Self {
        Self {
            user_id,
            password_hash,
            status,
            credential_revision,
        }
    }
}

/// Failures from the UUID-native credential source. Authentication callers must
/// not turn repository failure into an invalid-credential result or an ALLOW.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum MemoryV1CredentialRepositoryError {
    #[error("memory-v1 credential repository unavailable")]
    Unavailable,
    #[error("memory-v1 credential record is invalid")]
    InvalidRecord,
}

/// memory—v1: Identity-owned lookup port. The argument is already normalized by
/// `MemoryV1CredentialAuthenticator`; implementations must not reinterpret it.
#[async_trait]
pub trait MemoryV1CredentialRepository: Send + Sync {
    async fn find_by_identifier(
        &self,
        normalized_identifier: &str,
    ) -> Result<Option<MemoryV1CredentialRecord>, MemoryV1CredentialRepositoryError>;
}

/// A successful password check proves only the UUID user principal and the
/// credential revision. It does not prove card selection, tenant validity or
/// authorization, and cannot issue a memory—v1 session by itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryV1AuthenticatedCredential {
    user_id: MemoryId,
    credential_revision: u64,
}

impl MemoryV1AuthenticatedCredential {
    pub fn user_id(&self) -> MemoryId {
        self.user_id
    }

    pub fn credential_revision(&self) -> u64 {
        self.credential_revision
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum MemoryV1CredentialAuthenticationError {
    #[error("memory-v1 credential identifier is invalid")]
    InvalidIdentifier,
    #[error("memory-v1 credential is invalid")]
    InvalidCredentials,
    #[error("memory-v1 credential authentication is unavailable")]
    Unavailable,
}

/// memory—v1: Authenticate a UUID-native credential without touching the legacy
/// integer/JWT login service. The production HTTP route is intentionally not
/// wired until the credential, card, tenant and session contracts are complete.
#[derive(Clone)]
pub struct MemoryV1CredentialAuthenticator {
    repository: Arc<dyn MemoryV1CredentialRepository>,
}

impl MemoryV1CredentialAuthenticator {
    pub fn new(repository: Arc<dyn MemoryV1CredentialRepository>) -> Self {
        Self { repository }
    }

    /// Check a normalized UUID-native credential and return only its user
    /// principal. No `VerifiedMemoryV1Identity` or session is created here.
    pub async fn authenticate(
        &self,
        identifier: &str,
        password: &str,
    ) -> Result<MemoryV1AuthenticatedCredential, MemoryV1CredentialAuthenticationError> {
        let normalized = normalize_identifier(identifier)?;
        if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
            return Err(MemoryV1CredentialAuthenticationError::InvalidCredentials);
        }
        let record = self
            .repository
            .find_by_identifier(&normalized)
            .await
            .map_err(|error| match error {
                MemoryV1CredentialRepositoryError::Unavailable => {
                    MemoryV1CredentialAuthenticationError::Unavailable
                }
                MemoryV1CredentialRepositoryError::InvalidRecord => {
                    MemoryV1CredentialAuthenticationError::InvalidCredentials
                }
            })?
            .ok_or(MemoryV1CredentialAuthenticationError::InvalidCredentials)?;
        if record.status != MemoryV1CredentialStatus::Active || record.credential_revision == 0 {
            return Err(MemoryV1CredentialAuthenticationError::InvalidCredentials);
        }
        crate::auth::verify_password(password, &record.password_hash)
            .map_err(|_| MemoryV1CredentialAuthenticationError::InvalidCredentials)?;
        Ok(MemoryV1AuthenticatedCredential {
            user_id: record.user_id,
            credential_revision: record.credential_revision,
        })
    }
}

pub(crate) fn normalize_identifier(
    identifier: &str,
) -> Result<String, MemoryV1CredentialAuthenticationError> {
    let trimmed = identifier.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_IDENTIFIER_BYTES
        || !trimmed.is_ascii()
        || trimmed
            .chars()
            .any(|character| character.is_ascii_control())
    {
        return Err(MemoryV1CredentialAuthenticationError::InvalidIdentifier);
    }
    Ok(trimmed.to_ascii_lowercase())
}

/// Opaque UUID-native identity facts completed by an Identity-owned verifier.
///
/// The constructor is crate-private so an external router or transport adapter
/// cannot manufacture the value from client input. This value contains no legacy
/// integer identity and is not itself a permission decision.
#[derive(Clone, Copy)]
pub struct VerifiedMemoryV1Identity {
    identity: CandidateIdentity,
}

impl VerifiedMemoryV1Identity {
    /// memory—v1: Construct only after the Identity credential/card verifier has
    /// completed its authoritative checks.
    pub(crate) fn from_verified_facts(identity: CandidateIdentity) -> Self {
        Self { identity }
    }
}

/// Identity-owned boundary around the process session capability.
///
/// Gateway receives only the verifier capability. Identity retains this adapter
/// and is the only service boundary that can turn verified UUID-native facts into
/// an opaque `m1.*` credential. The existing legacy login flow does not call it.
#[derive(Clone)]
pub struct MemoryV1IdentitySession {
    adapter: MemoryV1IdentitySessionAdapter,
}

impl MemoryV1IdentitySession {
    /// memory—v1: Accept the capability injected by the single-node composition.
    pub fn from_session_adapter(adapter: MemoryV1IdentitySessionAdapter) -> Self {
        Self { adapter }
    }

    /// memory—v1: Issue a session only from an Identity-verified UUID principal.
    pub(crate) fn issue_verified_session(
        &self,
        identity: VerifiedMemoryV1Identity,
        now_unix_seconds: i64,
        lifetime_seconds: i64,
    ) -> Result<MemoryV1IssuedSession, MemoryV1SessionAuthorityError> {
        self.adapter
            .issue_verified_session(identity.identity, now_unix_seconds, lifetime_seconds)
    }

    /// memory—v1: Revoke through the same Identity-owned session boundary.
    ///
    /// Used by logout; the next request presenting the credential is refused.
    pub fn revoke(&self, credential: &str) -> Result<(), MemoryV1SessionAuthorityError> {
        self.adapter.revoke(credential)
    }

    /// memory—v1: Identity-owned login verification and session issuance.
    ///
    /// Authenticates the credential first, then verifies through `root` — the
    /// login request's own request-lifecycle reader — that the requested user
    /// card, its user, the user's identity card and the card's tenant form one
    /// consistent relationship in a `Serving` root. Only then is a
    /// [`VerifiedMemoryV1Identity`] formed and an opaque `m1.*` session issued.
    /// An unknown card and another user's card are both `CardNotOwned`; a
    /// non-serving root and any root or authority failure are `Unavailable`.
    /// Nothing falls back to the legacy login flow or to client-supplied IDs.
    pub async fn login(
        &self,
        authenticator: &MemoryV1CredentialAuthenticator,
        root: &RequestRootExtension,
        request: MemoryV1LoginRequest<'_>,
    ) -> Result<MemoryV1IssuedSession, MemoryV1LoginError> {
        let credential = authenticator
            .authenticate(request.identifier, request.password)
            .await
            .map_err(|error| match error {
                MemoryV1CredentialAuthenticationError::InvalidIdentifier => {
                    MemoryV1LoginError::InvalidIdentifier
                }
                MemoryV1CredentialAuthenticationError::InvalidCredentials => {
                    MemoryV1LoginError::InvalidCredentials
                }
                MemoryV1CredentialAuthenticationError::Unavailable => {
                    MemoryV1LoginError::Unavailable
                }
            })?;
        let user = credential.user_id();
        let identity = root
            .with_reader(|reader| verified_card_identity(reader, user, request.user_card_id))
            .map_err(|_| MemoryV1LoginError::Unavailable)??;
        self.issue_verified_session(
            VerifiedMemoryV1Identity::from_verified_facts(identity),
            request.now_unix_seconds,
            request.lifetime_seconds,
        )
        .map_err(|_| MemoryV1LoginError::Unavailable)
    }
}

/// memory—v1: Inputs of one Identity-owned memory—v1 login.
///
/// Deliberately not `Debug`, so the password cannot be logged by formatting.
#[derive(Clone, Copy)]
pub struct MemoryV1LoginRequest<'a> {
    /// The credential identifier; normalized by the authenticator.
    pub identifier: &'a str,
    /// The credential secret; checked against the stored password hash.
    pub password: &'a str,
    /// The user card the caller selects as its authorization carrier.
    pub user_card_id: MemoryId,
    /// Trusted UTC issuance time in Unix seconds.
    pub now_unix_seconds: i64,
    /// Requested session lifetime; the authority enforces its own maximum.
    pub lifetime_seconds: i64,
}

/// Failures of the Identity-owned memory—v1 login verification.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum MemoryV1LoginError {
    #[error("memory-v1 credential identifier is invalid")]
    InvalidIdentifier,
    #[error("memory-v1 credential is invalid")]
    InvalidCredentials,
    #[error("memory-v1 user card is not a card of the authenticated user")]
    CardNotOwned,
    #[error("memory-v1 login dependencies are unavailable")]
    Unavailable,
}

// memory—v1: Prove the selected card's dual-card and tenant relationship from one phase.
fn verified_card_identity(
    reader: &RequestRootReader,
    user: MemoryId,
    user_card_id: MemoryId,
) -> Result<CandidateIdentity, MemoryV1LoginError> {
    if reader.metadata().status != RootStatus::Serving {
        return Err(MemoryV1LoginError::Unavailable);
    }
    let user_bytes = user.into_bytes();
    let card_bytes = user_card_id.into_bytes();
    let relationship = reader.read_card(card_bytes, |context| {
        (context.card.user_card_id == card_bytes
            && context.card.user_id == user_bytes
            && context.user.user_id == user_bytes
            && context.identity.user_id == user_bytes
            && context.tenant.tenant_id == context.card.tenant_id)
            .then(|| CandidateIdentity {
                user_id: user,
                identity_card_id: MemoryId::from_bytes(context.identity.identity_card_id),
                user_card_id,
                tenant_id: MemoryId::from_bytes(context.card.tenant_id),
            })
    });
    match relationship {
        Ok(Some(identity)) => Ok(identity),
        Ok(None)
        | Err(RootError::Candidate(CandidateError::UnknownId {
            table: Table::UserCard,
            ..
        })) => Err(MemoryV1LoginError::CardNotOwned),
        Err(_) => Err(MemoryV1LoginError::Unavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
    use astral_types::memory_v1::MemoryId;
    use std::sync::Mutex;

    fn identity() -> CandidateIdentity {
        CandidateIdentity {
            user_id: MemoryId::from_bytes([1; 16]),
            identity_card_id: MemoryId::from_bytes([2; 16]),
            user_card_id: MemoryId::from_bytes([3; 16]),
            tenant_id: MemoryId::from_bytes([4; 16]),
        }
    }

    #[derive(Default)]
    struct FakeCredentialRepository {
        seen: Mutex<Vec<String>>,
        record: Option<MemoryV1CredentialRecord>,
        failure: Option<MemoryV1CredentialRepositoryError>,
    }

    #[async_trait]
    impl MemoryV1CredentialRepository for FakeCredentialRepository {
        async fn find_by_identifier(
            &self,
            normalized_identifier: &str,
        ) -> Result<Option<MemoryV1CredentialRecord>, MemoryV1CredentialRepositoryError> {
            self.seen
                .lock()
                .unwrap()
                .push(normalized_identifier.to_owned());
            if let Some(error) = self.failure {
                return Err(error);
            }
            Ok(self.record.clone())
        }
    }

    #[tokio::test]
    async fn uuid_credential_authentication_normalizes_and_returns_only_user_revision() {
        let hash = crate::auth::hash_password("correct").unwrap();
        let repository = Arc::new(FakeCredentialRepository {
            record: Some(MemoryV1CredentialRecord::new(
                identity().user_id,
                hash,
                MemoryV1CredentialStatus::Active,
                7,
            )),
            ..Default::default()
        });
        let authenticator = MemoryV1CredentialAuthenticator::new(repository.clone());
        let authenticated = authenticator
            .authenticate("  Alice@Example.TEST ", "correct")
            .await
            .unwrap();
        assert_eq!(authenticated.user_id(), identity().user_id);
        assert_eq!(authenticated.credential_revision(), 7);
        assert_eq!(
            repository.seen.lock().unwrap().as_slice(),
            ["alice@example.test"]
        );
    }

    #[tokio::test]
    async fn disabled_bad_hash_and_wrong_password_are_invalid_credentials() {
        for record in [
            MemoryV1CredentialRecord::new(
                identity().user_id,
                crate::auth::hash_password("correct").unwrap(),
                MemoryV1CredentialStatus::Disabled,
                1,
            ),
            MemoryV1CredentialRecord::new(
                identity().user_id,
                "not-an-argon2id-hash".into(),
                MemoryV1CredentialStatus::Active,
                1,
            ),
            MemoryV1CredentialRecord::new(
                identity().user_id,
                crate::auth::hash_password("correct").unwrap(),
                MemoryV1CredentialStatus::Active,
                1,
            ),
        ] {
            let repository = Arc::new(FakeCredentialRepository {
                record: Some(record),
                ..Default::default()
            });
            let result = MemoryV1CredentialAuthenticator::new(repository)
                .authenticate("alice", "wrong")
                .await;
            assert_eq!(
                result,
                Err(MemoryV1CredentialAuthenticationError::InvalidCredentials)
            );
        }
    }

    #[tokio::test]
    async fn repository_failure_stays_unavailable_and_invalid_identifiers_do_not_lookup() {
        let unavailable = Arc::new(FakeCredentialRepository {
            failure: Some(MemoryV1CredentialRepositoryError::Unavailable),
            ..Default::default()
        });
        assert_eq!(
            MemoryV1CredentialAuthenticator::new(unavailable)
                .authenticate("alice", "correct")
                .await,
            Err(MemoryV1CredentialAuthenticationError::Unavailable)
        );

        let repository = Arc::new(FakeCredentialRepository::default());
        assert_eq!(
            MemoryV1CredentialAuthenticator::new(repository.clone())
                .authenticate("\u{0}", "correct")
                .await,
            Err(MemoryV1CredentialAuthenticationError::InvalidIdentifier)
        );
        assert!(repository.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn only_verified_identity_value_enters_identity_session_boundary() {
        let authority = MemoryV1SessionAuthority::new();
        let session =
            MemoryV1IdentitySession::from_session_adapter(authority.identity_session_adapter());
        let principal = VerifiedMemoryV1Identity::from_verified_facts(identity());
        let issued = session.issue_verified_session(principal, 100, 30).unwrap();
        assert!(issued.credential().starts_with("m1."));
        assert!(authority
            .verifier()
            .verify(issued.credential(), 100)
            .is_ok());
    }
}
