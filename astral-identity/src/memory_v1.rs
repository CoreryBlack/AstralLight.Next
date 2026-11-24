use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

use astral_authorization_root::memory_v1_db_rows::{Table, UserCardStatus};
use astral_authorization_root::memory_v1_hamt::CandidateError;
use astral_authorization_root::memory_v1_request::RequestRootExtension;
use astral_authorization_root::memory_v1_root::{RequestRootReader, RootError, RootStatus};
use astral_authorization_root::memory_v1_session_authority::{
    MemoryV1IdentitySessionAdapter, MemoryV1IssuedSession, MemoryV1SessionAuthorityError,
};
use astral_types::memory_v1::{CandidateIdentity, MemoryId};

use crate::memory_v1_service::MemoryV1FileCredentials;

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
/// integer/JWT login service. The composed HTTP login route uses this
/// authenticator before checking the selected card and issuing a session.
#[derive(Clone)]
pub struct MemoryV1CredentialAuthenticator {
    repository: Arc<dyn MemoryV1CredentialRepository>,
    /// `Some` exists only for the composition-owned concrete FileCredentials
    /// snapshot. The public `new` constructor remains an unrestricted legacy
    /// injection point and therefore cannot satisfy a configured source pin.
    file_source: Option<Arc<MemoryV1FileCredentials>>,
}

impl MemoryV1CredentialAuthenticator {
    pub fn new(repository: Arc<dyn MemoryV1CredentialRepository>) -> Self {
        Self {
            repository,
            file_source: None,
        }
    }

    /// memory—v1: Build the configured authenticator only from Identity's
    /// immutable, concrete FileCredentials snapshot. The snapshot is shared by
    /// Arc and cannot be replaced through the repository trait object.
    pub fn from_file_credentials(credentials: Arc<MemoryV1FileCredentials>) -> Self {
        Self {
            repository: credentials.clone(),
            file_source: Some(credentials),
        }
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
    /// `Some` marks a composition-owned session whose authentication source is
    /// fixed to one immutable FileCredentials allocation.
    credential_source: Option<Arc<MemoryV1FileCredentials>>,
    /// `Some` fixes the server lifetime for a configured composition instance.
    session_lifetime_seconds: Option<i64>,
}

impl MemoryV1IdentitySession {
    /// memory—v1: Preserve the legacy adapter-only construction and its
    /// caller-supplied authenticator/lifetime behavior.
    pub fn from_session_adapter(adapter: MemoryV1IdentitySessionAdapter) -> Self {
        Self {
            adapter,
            credential_source: None,
            session_lifetime_seconds: None,
        }
    }

    /// memory—v1: Construct the composition-owned session from Identity's
    /// concrete immutable FileCredentials snapshot. The `Arc` allocation is
    /// retained as the source identity and the lifetime is fixed for this
    /// instance. Gateway never receives this session or its adapter.
    pub fn from_session_adapter_with_file_credentials(
        adapter: MemoryV1IdentitySessionAdapter,
        credentials: Arc<MemoryV1FileCredentials>,
        session_lifetime_seconds: i64,
    ) -> Self {
        Self {
            adapter,
            credential_source: Some(credentials),
            session_lifetime_seconds: Some(session_lifetime_seconds),
        }
    }

    fn validate_login_configuration(
        &self,
        authenticator: &MemoryV1CredentialAuthenticator,
        lifetime_seconds: i64,
    ) -> Result<(), MemoryV1LoginError> {
        if let Some(expected_source) = &self.credential_source {
            let source_matches = authenticator
                .file_source
                .as_ref()
                .is_some_and(|actual| Arc::ptr_eq(expected_source, actual));
            if !source_matches {
                return Err(MemoryV1LoginError::Unavailable);
            }
        }
        if self
            .session_lifetime_seconds
            .is_some_and(|expected| expected != lifetime_seconds)
        {
            return Err(MemoryV1LoginError::Unavailable);
        }
        Ok(())
    }

    /// memory—v1: Issue a session only from an Identity-verified UUID principal
    /// whose card is still current at insertion.
    pub(crate) fn issue_verified_session(
        &self,
        root: &RequestRootExtension,
        identity: VerifiedMemoryV1Identity,
        now_unix_seconds: i64,
        lifetime_seconds: i64,
    ) -> Result<MemoryV1IssuedSession, MemoryV1SessionAuthorityError> {
        self.adapter.issue_verified_session_in_root(
            root,
            identity.identity,
            now_unix_seconds,
            lifetime_seconds,
        )
    }

    /// memory—v1: Revoke through the same Identity-owned session boundary.
    ///
    /// Used by logout; the next request presenting the credential is refused.
    pub fn revoke(&self, credential: &str) -> Result<(), MemoryV1SessionAuthorityError> {
        self.adapter.revoke(credential)
    }

    /// memory—v1: Revoke all current process sessions for one user card.
    ///
    /// This is only a session-component operation for a later restricted card
    /// disable coordinator. It does not evaluate authorization, change the
    /// card's lifecycle state, or prevent a subsequent session issuance; the
    /// shared-root coordinator must provide those semantics and their
    /// linearization boundary.
    pub fn revoke_sessions_for_user_card(
        &self,
        user_card_id: MemoryId,
    ) -> Result<usize, MemoryV1SessionAuthorityError> {
        self.adapter.revoke_sessions_for_user_card(user_card_id)
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
        self.login_with_clock(
            authenticator,
            root,
            MemoryV1LoginInput {
                identifier: request.identifier,
                password: request.password,
                user_card_id: request.user_card_id,
                lifetime_seconds: request.lifetime_seconds,
            },
            || Some(request.now_unix_seconds),
        )
        .await
        .map(|(issued, _)| issued)
    }

    /// memory—v1: Observe time from the authority that will bind this session.
    pub(crate) fn policy_time(
        &self,
    ) -> Option<astral_authorization_root::memory_v1_policy_time::PolicyTime> {
        self.adapter.policy_time()
    }

    /// memory—v1: Sample the caller's issuance clock after authentication and card checks.
    pub(crate) async fn login_with_clock(
        &self,
        authenticator: &MemoryV1CredentialAuthenticator,
        root: &RequestRootExtension,
        request: MemoryV1LoginInput<'_>,
        clock: impl FnOnce() -> Option<i64>,
    ) -> Result<(MemoryV1IssuedSession, i64), MemoryV1LoginError> {
        self.login_with_issuance_time(authenticator, root, request, || std::future::ready(clock()))
            .await
    }

    /// memory—v1: Wait for issuance time after credential and card verification.
    /// No reader lease or session record is held across this wait. Issuance still
    /// rechecks the current card under the root and session locks.
    pub(crate) async fn login_with_issuance_time<F: std::future::Future<Output = Option<i64>>>(
        &self,
        authenticator: &MemoryV1CredentialAuthenticator,
        root: &RequestRootExtension,
        request: MemoryV1LoginInput<'_>,
        clock: impl FnOnce() -> F,
    ) -> Result<(MemoryV1IssuedSession, i64), MemoryV1LoginError> {
        self.validate_login_configuration(authenticator, request.lifetime_seconds)?;
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
        let issued_at = clock().await.ok_or(MemoryV1LoginError::Unavailable)?;
        let issued = self
            .issue_verified_session(
                root,
                VerifiedMemoryV1Identity::from_verified_facts(identity),
                issued_at,
                request.lifetime_seconds,
            )
            .map_err(|error| {
                tracing::debug!(target: "memory_v1_login_diagnostics", phase = "session_insert", %error, "memory-v1 login refused");
                MemoryV1LoginError::Unavailable
            })?;
        Ok((issued, issued_at))
    }
}

/// memory—v1: Login inputs whose issuance time is supplied by a trusted clock.
pub(crate) struct MemoryV1LoginInput<'a> {
    pub(crate) identifier: &'a str,
    pub(crate) password: &'a str,
    pub(crate) user_card_id: MemoryId,
    pub(crate) lifetime_seconds: i64,
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
    let relationship =
        reader.read_card_for_evaluation(card_bytes, |context, _has_binding_history| {
            (context.card.user_card_id == card_bytes
                && context.card.status == UserCardStatus::Active
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
    use astral_authorization_root::memory_v1_adoption::{
        AdoptionLimit, ColdLoadFacts, MEMORY_V1_CANDIDATE_SCHEMA_VERSION,
    };
    use astral_authorization_root::memory_v1_db_rows::{
        BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
        IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, TableCounts,
        TenantRow, UserCardRow, UserCardStatus as CardStatus, UserRow,
    };
    use astral_authorization_root::memory_v1_hamt::CandidateBudget;
    use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
    use astral_authorization_root::memory_v1_root::{
        install_process_root, ManagementMutationV2, MutationPrecondition, RootOwner,
    };
    use astral_authorization_root::memory_v1_rules::{
        canonical_version_bytes, version_digest, MemoryV1OwnerScope, MemoryV1TenantScope,
    };
    use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
    use astral_types::memory_v1::MemoryId;
    use std::process::Command;
    use std::sync::Mutex;
    use uuid::Uuid;

    // memory—v1: Align fixture time with the actual issuance clock.
    fn fixture_now() -> i64 {
        i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
    }

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

    const LOGIN_CHILD_ENV: &str = "ASTRAL_MEMORY_V1_DISABLED_LOGIN_CHILD";

    fn run_isolated(test_name: &str) {
        if std::env::var_os(LOGIN_CHILD_ENV).is_some() {
            return;
        }
        let output = Command::new(std::env::current_exe().expect("test executable is available"))
            .args(["--exact", test_name, "--nocapture"])
            .env(LOGIN_CHILD_ENV, "1")
            .output()
            .expect("failed to start isolated disabled-card login test");
        assert!(
            output.status.success(),
            "isolated test failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "isolated test did not report one passing test\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn id(value: u8) -> [u8; 16] {
        [value; 16]
    }

    fn login_fixture() -> (CandidateRows, Vec<CurrentSelection>) {
        let version_bytes = vec![1];
        let timestamp_bytes = vec![2];
        let content_bytes =
            br#"{"rules":[{"ruleId":"login-test","resource":"document","action":"read","effect":"ALLOW"}]}"#
                .to_vec();
        let hash_input_bytes =
            canonical_version_bytes(&version_bytes, &content_bytes, &timestamp_bytes);
        let version = RuleSetVersionRow {
            rule_set_id: id(5),
            version_bytes: version_bytes.clone(),
            content_bytes,
            timestamp_bytes,
            hash_bytes: version_digest(&hash_input_bytes),
            hash_input_bytes,
        };
        let binding = |binding_id: u8, card_id: u8| BindingRow {
            binding_id: id(binding_id),
            user_card_id: id(card_id),
            rule_set_id: id(5),
            binding_layer: BindingLayer::Base,
            valid_from: None,
            valid_until: None,
            owner_scope: MemoryV1OwnerScope::default(),
            tenant_scope: MemoryV1TenantScope::default(),
            removed_at: None,
            removed_by: None,
        };
        let confirmation = |confirmation_id: u8, binding_id: u8| BindingConfirmationRow {
            confirmation_id: id(confirmation_id),
            binding_id: id(binding_id),
            rule_set_id: id(5),
            version_bytes: version_bytes.clone(),
            confirmer_user_id: id(1),
            scope_bytes: vec![1],
            operation_id: vec![confirmation_id],
            confirmed_at_bytes: vec![1],
            revoked_at: None,
            revoked_by: None,
        };
        (
            CandidateRows {
                users: vec![UserRow { user_id: id(1) }],
                identity_cards: vec![IdentityCardRow {
                    identity_card_id: id(2),
                    user_id: id(1),
                }],
                tenants: vec![TenantRow {
                    tenant_id: id(3),
                    parent_tenant_id: None,
                }],
                user_cards: vec![
                    UserCardRow {
                        user_card_id: id(4),
                        user_id: id(1),
                        tenant_id: id(3),
                        status: CardStatus::Active,
                    },
                    UserCardRow {
                        user_card_id: id(6),
                        user_id: id(1),
                        tenant_id: id(3),
                        status: CardStatus::Disabled,
                    },
                ],
                rule_sets: vec![RuleSetRow {
                    status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                    rule_set_id: id(5),
                    owner_tenant_id: id(3),
                    current_version_bytes: version_bytes.clone(),
                }],
                rule_set_versions: vec![version],
                bindings: vec![binding(7, 4), binding(8, 6)],
                binding_confirmations: vec![confirmation(9, 7), confirmation(10, 8)],
                rule_set_change_confirmations: vec![RuleSetChangeConfirmationRow {
                    confirmation_id: id(11),
                    rule_set_id: id(5),
                    version_bytes,
                    confirmer_user_id: id(1),
                    affected_scope_bytes: vec![1],
                    operation_id: vec![11],
                    confirmed_at_bytes: vec![1],
                    revoked_at: None,
                    revoked_by: None,
                }],
            },
            vec![CurrentSelection {
                rule_set_id: id(5),
                version_bytes: vec![1],
            }],
        )
    }

    fn serving_login_owner() -> RootOwner {
        let (rows, selections) = login_fixture();
        let owner = install_process_root(
            rows,
            selections,
            CandidateBudget {
                max_table_rows: 32,
                max_bindings_per_read: 8,
            },
        )
        .expect("login fixture root installs");
        let counts = TableCounts {
            users: 1,
            identity_cards: 1,
            tenants: 1,
            user_cards: 2,
            rule_sets: 1,
            rule_set_versions: 1,
            bindings: 2,
            binding_confirmations: 2,
            rule_set_change_confirmations: 1,
        };
        owner
            .install_registry(&[RegistryDeclaration {
                resource: "document".to_owned(),
                actions: vec!["read".to_owned()],
            }])
            .expect("login fixture registry installs before adoption");
        owner
            .adopt_experimental(
                &ColdLoadFacts {
                    schema_contract_version: MEMORY_V1_CANDIDATE_SCHEMA_VERSION,
                    schema_fingerprint: [7; 32],
                    snapshot_counts: counts,
                    scanned_counts: counts,
                    captured_at_unix_seconds: 1_700_000_000,
                },
                &AdoptionLimit::EXPERIMENTAL,
            )
            .expect("login fixture root becomes serving");
        owner
    }

    #[tokio::test]
    async fn http_login_waits_until_the_session_covers_the_first_policy_interval() {
        use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

        use astral_authorization_root::memory_v1_request::RequestRootScope;
        use policy_engine::memory_v1_formal::{MemoryV1Decision, MemoryV1Request};

        let test_name = "runtime::memory_v1::tests::http_login_waits_until_the_session_covers_the_first_policy_interval";
        if std::env::var_os(LOGIN_CHILD_ENV).is_none() {
            run_isolated(test_name);
            return;
        }

        static ISSUED_AT: AtomicI64 = AtomicI64::new(0);
        static SAMPLES: AtomicUsize = AtomicUsize::new(0);
        let (rows, selections) = login_fixture();
        let owner = install_process_root(
            rows,
            selections,
            CandidateBudget {
                max_table_rows: 32,
                max_bindings_per_read: 8,
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
        let authority = MemoryV1SessionAuthority::with_clock_for_test(|| {
            let nanos = i128::from(ISSUED_AT.load(Ordering::Relaxed)) * 1_000_000_000;
            match SAMPLES.fetch_add(1, Ordering::Relaxed) {
                0 => Some((nanos + 100_000_000, 200_000_000)),
                1 => Some((nanos + 250_000_000, 200_000_000)),
                2..=3 => Some((nanos + 500_000_000, 200_000_000)),
                4..=5 => Some((nanos + 500_000_000, 499_999_999)),
                _ => None,
            }
        });
        authority.bind_to_root(&owner).unwrap();
        let session =
            MemoryV1IdentitySession::from_session_adapter(authority.identity_session_adapter());
        let authenticator =
            MemoryV1CredentialAuthenticator::new(Arc::new(FakeCredentialRepository {
                record: Some(MemoryV1CredentialRecord::new(
                    MemoryId::from_bytes(id(1)),
                    crate::auth::hash_password("correct").unwrap(),
                    MemoryV1CredentialStatus::Active,
                    1,
                )),
                ..Default::default()
            }));
        let input = || MemoryV1LoginInput {
            identifier: "alice",
            password: "correct",
            user_card_id: MemoryId::from_bytes(id(4)),
            lifetime_seconds: 30,
        };
        let login_scope = RequestRootScope::new(owner.handle(), Uuid::new_v4());
        let issued_at = fixture_now();
        ISSUED_AT.store(issued_at, Ordering::Relaxed);
        let response = crate::memory_v1_service::login_exchange(
            &session,
            &authenticator,
            &login_scope.extension(),
            input(),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            SAMPLES.load(Ordering::Relaxed),
            4,
            "wait until even a larger error radius cannot reach the previous tick"
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["data"]["expiresIn"], 29);
        let credential = json["data"]["accessToken"].as_str().unwrap();
        assert!(matches!(
            authority.verifier().verify(credential, issued_at - 1),
            Err(MemoryV1SessionAuthorityError::Expired)
        ));
        let read_scope = RequestRootScope::new(owner.handle(), Uuid::new_v4());
        let root = read_scope.extension();
        let bound = authority
            .verifier()
            .verify_and_bind(credential, issued_at, &root)
            .unwrap();
        let result = policy_engine::PolicyEngine::new().evaluate_memory_v1(
            &root,
            &bound,
            &MemoryV1Request {
                resource: "document",
                action: "read",
                target: None,
                target_owner: None,
                target_tenant: None,
                operation_id: b"first-read-after-http-login",
                operation_fingerprint: b"document-read",
            },
        );
        assert_eq!(result.decision, MemoryV1Decision::Allow);
        assert!(result.admission.is_some());
        assert_eq!(SAMPLES.load(Ordering::Relaxed), 6);

        // Losing the trusted clock cannot return a bearer using only wall time.
        let unavailable = crate::memory_v1_service::login_exchange(
            &session,
            &authenticator,
            &login_scope.extension(),
            input(),
        )
        .await;
        assert_eq!(
            unavailable.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        let body = axum::body::to_bytes(unavailable.into_body(), 4096)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["data"].is_null());
    }

    // memory—v1: Historical removed bindings must not exhaust a current
    // card's login budget; lifecycle and session revocation still fail closed.
    #[tokio::test]
    async fn login_ignores_removed_binding_history_without_reviving_sessions() {
        let test_name =
            "runtime::memory_v1::tests::login_ignores_removed_binding_history_without_reviving_sessions";
        if std::env::var_os(LOGIN_CHILD_ENV).is_none() {
            run_isolated(test_name);
            return;
        }

        let (mut rows, selections) = login_fixture();
        for binding_id in 20..40 {
            let mut historical = rows.bindings[0].clone();
            historical.binding_id = id(binding_id);
            historical.removed_at = Some(100);
            historical.removed_by = Some(id(1));
            rows.bindings.push(historical);
        }
        let owner = install_process_root(
            rows,
            selections,
            CandidateBudget {
                max_table_rows: 64,
                max_bindings_per_read: 8,
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
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let session =
            MemoryV1IdentitySession::from_session_adapter(authority.identity_session_adapter());
        let authenticator =
            MemoryV1CredentialAuthenticator::new(Arc::new(FakeCredentialRepository {
                record: Some(MemoryV1CredentialRecord::new(
                    identity().user_id,
                    crate::auth::hash_password("correct").unwrap(),
                    MemoryV1CredentialStatus::Active,
                    1,
                )),
                ..Default::default()
            }));
        let issued_at = fixture_now() - 1;
        let scope = astral_authorization_root::memory_v1_request::RequestRootScope::new(
            owner.handle(),
            Uuid::new_v4(),
        );
        let root = scope.extension();
        let issued = session
            .login(
                &authenticator,
                &root,
                MemoryV1LoginRequest {
                    identifier: "alice",
                    password: "correct",
                    user_card_id: MemoryId::from_bytes(id(4)),
                    now_unix_seconds: issued_at,
                    lifetime_seconds: 30,
                },
            )
            .await
            .expect("removed history does not prevent a valid login");
        assert!(authority
            .verifier()
            .verify(issued.credential(), issued_at)
            .is_ok());
        let before_revoke = owner.handle().metadata().unwrap();
        owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &ManagementMutationV2::ConfirmationRevoke {
                    confirmation_id: id(9),
                    revoked_at: issued_at,
                    revoked_by: id(1),
                },
                &MutationPrecondition {
                    evaluated_root_version: before_revoke.version,
                },
            )
            .unwrap();
        let fresh_scope = astral_authorization_root::memory_v1_request::RequestRootScope::new(
            owner.handle(),
            Uuid::new_v4(),
        );
        let fresh_root = fresh_scope.extension();
        let after_revoke = session
            .login(
                &authenticator,
                &fresh_root,
                MemoryV1LoginRequest {
                    identifier: "alice",
                    password: "correct",
                    user_card_id: MemoryId::from_bytes(id(4)),
                    now_unix_seconds: issued_at,
                    lifetime_seconds: 30,
                },
            )
            .await
            .expect("revoking authorization confirmation does not disable login");
        assert!(authority
            .verifier()
            .verify(after_revoke.credential(), issued_at)
            .is_ok());
        let before = owner.handle().metadata().unwrap();
        let (after, revoked) = authority
            .disable_card_with_sessions_for_isolated_tests(
                &owner.mutation_executor(),
                MemoryId::from_bytes(id(4)),
                before,
            )
            .unwrap();
        assert_eq!(revoked, 2);
        for credential in [issued.credential(), after_revoke.credential()] {
            assert!(matches!(
                authority.verifier().verify(credential, issued_at),
                Err(MemoryV1SessionAuthorityError::Revoked)
            ));
        }
        owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &ManagementMutationV2::UserCardStatus {
                    user_card_id: id(4),
                    status: CardStatus::Active,
                },
                &MutationPrecondition {
                    evaluated_root_version: after.version,
                },
            )
            .unwrap();
        assert!(matches!(
            authority.verifier().verify(issued.credential(), issued_at),
            Err(MemoryV1SessionAuthorityError::Revoked)
        ));
    }

    // memory—v1: A disabled card is never selected by a fresh login request.
    #[tokio::test]
    async fn serving_login_checks_card_status_in_one_reader_phase() {
        let test_name =
            "runtime::memory_v1::tests::serving_login_checks_card_status_in_one_reader_phase";
        if std::env::var_os(LOGIN_CHILD_ENV).is_none() {
            run_isolated(test_name);
            return;
        }

        let base = fixture_now() - 1;
        let owner = serving_login_owner();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let session =
            MemoryV1IdentitySession::from_session_adapter(authority.identity_session_adapter());
        let authenticator =
            MemoryV1CredentialAuthenticator::new(Arc::new(FakeCredentialRepository {
                record: Some(MemoryV1CredentialRecord::new(
                    identity().user_id,
                    crate::auth::hash_password("correct").unwrap(),
                    MemoryV1CredentialStatus::Active,
                    1,
                )),
                ..Default::default()
            }));

        let active_scope = astral_authorization_root::memory_v1_request::RequestRootScope::new(
            owner.handle(),
            Uuid::new_v4(),
        );
        let active_root = active_scope.extension();
        let stale_identity = active_root
            .with_reader(|reader| {
                verified_card_identity(reader, identity().user_id, MemoryId::from_bytes(id(4)))
            })
            .expect("root reader is available")
            .expect("active card is verified");
        let mismatch = CandidateIdentity {
            tenant_id: MemoryId::from_bytes(id(99)),
            ..stale_identity
        };
        assert!(matches!(
            session.issue_verified_session(
                &active_root,
                VerifiedMemoryV1Identity::from_verified_facts(mismatch),
                base,
                30,
            ),
            Err(MemoryV1SessionAuthorityError::Unavailable)
        ));
        let active = session
            .login(
                &authenticator,
                &active_root,
                MemoryV1LoginRequest {
                    identifier: "alice",
                    password: "correct",
                    user_card_id: MemoryId::from_bytes(id(4)),
                    now_unix_seconds: base,
                    lifetime_seconds: 30,
                },
            )
            .await
            .expect("active card login succeeds");
        assert!(authority
            .verifier()
            .verify(active.credential(), base)
            .is_ok());

        let disabled_scope = astral_authorization_root::memory_v1_request::RequestRootScope::new(
            owner.handle(),
            Uuid::new_v4(),
        );
        let disabled_root = disabled_scope.extension();
        assert!(matches!(
            session
                .login(
                    &authenticator,
                    &disabled_root,
                    MemoryV1LoginRequest {
                        identifier: "alice",
                        password: "correct",
                        user_card_id: MemoryId::from_bytes(id(6)),
                        now_unix_seconds: base,
                        lifetime_seconds: 30,
                    },
                )
                .await,
            Err(MemoryV1LoginError::CardNotOwned)
        ));

        let before = owner
            .handle()
            .metadata()
            .expect("root metadata is readable");
        let mut stale = before;
        stale.version += 1;
        assert!(authority
            .disable_card_with_sessions_for_isolated_tests(
                &owner.mutation_executor(),
                MemoryId::from_bytes(id(4)),
                stale
            )
            .is_err());
        assert!(authority
            .disable_card_with_sessions_for_isolated_tests(
                &owner.mutation_executor(),
                MemoryId::from_bytes(id(99)),
                before
            )
            .is_err());
        assert_eq!(owner.handle().metadata().unwrap(), before);
        assert!(authority
            .verifier()
            .verify(active.credential(), base)
            .is_ok());
        let (after, revoked) = authority
            .disable_card_with_sessions_for_isolated_tests(
                &owner.mutation_executor(),
                MemoryId::from_bytes(id(4)),
                before,
            )
            .expect("low-level card/session coordinator publishes");
        assert_eq!(after.version, before.version + 1);
        assert_eq!(revoked, 1);

        assert!(matches!(
            authority.verifier().verify(active.credential(), base),
            Err(MemoryV1SessionAuthorityError::Revoked)
        ));
        assert!(matches!(
            session.issue_verified_session(
                &active_root,
                VerifiedMemoryV1Identity::from_verified_facts(stale_identity),
                base,
                30,
            ),
            Err(MemoryV1SessionAuthorityError::Unavailable)
        ));

        let switched_scope = astral_authorization_root::memory_v1_request::RequestRootScope::new(
            owner.handle(),
            Uuid::new_v4(),
        );
        let switched_root = switched_scope.extension();
        assert!(matches!(
            session
                .login(
                    &authenticator,
                    &switched_root,
                    MemoryV1LoginRequest {
                        identifier: "alice",
                        password: "correct",
                        user_card_id: MemoryId::from_bytes(id(4)),
                        now_unix_seconds: base,
                        lifetime_seconds: 30,
                    },
                )
                .await,
            Err(MemoryV1LoginError::CardNotOwned)
        ));

        owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &ManagementMutationV2::UserCardStatus {
                    user_card_id: id(4),
                    status: CardStatus::Active,
                },
                &MutationPrecondition {
                    evaluated_root_version: after.version,
                },
            )
            .expect("low-level enable publishes");
        assert!(matches!(
            authority.verifier().verify(active.credential(), base),
            Err(MemoryV1SessionAuthorityError::Revoked
                | MemoryV1SessionAuthorityError::InvalidCredential)
        ));
        assert!(matches!(
            session.issue_verified_session(
                &active_root,
                VerifiedMemoryV1Identity::from_verified_facts(stale_identity),
                base,
                30,
            ),
            Err(MemoryV1SessionAuthorityError::Unavailable)
        ));
    }

    // memory—v1: Authentication delay is excluded from issuance, and clock
    // failures or a response delayed past expiry never return a credential.
    #[tokio::test]
    async fn login_samples_after_authentication_and_reports_remaining_validity() {
        use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

        struct DelayedRepository {
            authenticated_at: i64,
            record: MemoryV1CredentialRecord,
            clock: Arc<AtomicI64>,
        }

        #[async_trait]
        impl MemoryV1CredentialRepository for DelayedRepository {
            async fn find_by_identifier(
                &self,
                _: &str,
            ) -> Result<Option<MemoryV1CredentialRecord>, MemoryV1CredentialRepositoryError>
            {
                self.clock.store(self.authenticated_at, Ordering::SeqCst);
                Ok(Some(self.record.clone()))
            }
        }

        let test_name = "runtime::memory_v1::tests::login_samples_after_authentication_and_reports_remaining_validity";
        if std::env::var_os(LOGIN_CHILD_ENV).is_none() {
            run_isolated(test_name);
            return;
        }
        let base = fixture_now() - 51;
        let owner = serving_login_owner();
        let scope = astral_authorization_root::memory_v1_request::RequestRootScope::new(
            owner.handle(),
            Uuid::new_v4(),
        );
        let root = scope.extension();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let session =
            MemoryV1IdentitySession::from_session_adapter(authority.identity_session_adapter());
        let time = Arc::new(AtomicI64::new(base));
        let authenticator = MemoryV1CredentialAuthenticator::new(Arc::new(DelayedRepository {
            authenticated_at: base + 50,
            record: MemoryV1CredentialRecord::new(
                identity().user_id,
                crate::auth::hash_password("correct").unwrap(),
                MemoryV1CredentialStatus::Active,
                1,
            ),
            clock: Arc::clone(&time),
        }));
        let input = || MemoryV1LoginInput {
            identifier: "alice",
            password: "correct",
            user_card_id: MemoryId::from_bytes(id(4)),
            lifetime_seconds: 30,
        };
        let (issued, issued_at) = session
            .login_with_clock(&authenticator, &root, input(), || {
                Some(time.load(Ordering::SeqCst))
            })
            .await
            .expect("login succeeds after delayed authentication");
        assert_eq!(issued_at, base + 50);
        let credential = issued.credential().to_owned();
        assert!(authority.verifier().verify(&credential, base + 79).is_ok());
        assert!(matches!(
            authority.verifier().verify(&credential, base + 80),
            Err(MemoryV1SessionAuthorityError::Expired)
        ));
        let response =
            crate::memory_v1_service::login_success(&session, issued, issued_at, 30, || {
                Some((base + 57, base + 58))
            });
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["data"]["expiresIn"], 22);
        assert!(body["data"]["accessToken"] == credential);

        let calls = AtomicUsize::new(0);
        assert!(matches!(
            session
                .login_with_clock(&authenticator, &root, input(), || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    None
                })
                .await,
            Err(MemoryV1LoginError::Unavailable)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let bad_input = MemoryV1LoginInput {
            password: "wrong",
            ..input()
        };
        assert!(matches!(
            session
                .login_with_clock(&authenticator, &root, bad_input, || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Some(base + 50)
                })
                .await,
            Err(MemoryV1LoginError::InvalidCredentials)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        for response_time in [
            None,
            Some((base + 49, base + 50)),
            Some((base + 80, base + 80)),
            Some((base + 79, base + 80)),
        ] {
            let (issued, issued_at) = session
                .login_with_clock(&authenticator, &root, input(), || Some(base + 50))
                .await
                .unwrap();
            let credential = issued.credential().to_owned();
            let response =
                crate::memory_v1_service::login_success(&session, issued, issued_at, 30, || {
                    response_time
                });
            assert_eq!(
                response.status(),
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            );
            assert!(matches!(
                authority.verifier().verify(&credential, base + 50),
                Err(MemoryV1SessionAuthorityError::Revoked)
            ));
        }
    }

    // memory—v1: A root phase captured before disable cannot issue afterwards,
    // and a session issued first is included in the later revocation.
    #[tokio::test]
    async fn login_and_disable_share_the_card_commit_boundary() {
        let test_name =
            "runtime::memory_v1::tests::login_and_disable_share_the_card_commit_boundary";
        if std::env::var_os(LOGIN_CHILD_ENV).is_none() {
            run_isolated(test_name);
            return;
        }
        let base = fixture_now() - 1;
        let owner = serving_login_owner();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let session =
            MemoryV1IdentitySession::from_session_adapter(authority.identity_session_adapter());
        let scope = astral_authorization_root::memory_v1_request::RequestRootScope::new(
            owner.handle(),
            Uuid::new_v4(),
        );
        let root = scope.extension();
        let principal = root
            .with_reader(|reader| {
                verified_card_identity(reader, identity().user_id, MemoryId::from_bytes(id(4)))
            })
            .unwrap()
            .unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let writer = owner.mutation_executor();
        let before = owner.handle().metadata().unwrap();
        let (issued, mutation) = std::thread::scope(|threads| {
            let login_barrier = Arc::clone(&barrier);
            let login_session = &session;
            let login_root = &root;
            let login = threads.spawn(move || {
                login_barrier.wait();
                login_session.issue_verified_session(
                    login_root,
                    VerifiedMemoryV1Identity::from_verified_facts(principal),
                    base,
                    30,
                )
            });
            let disable_barrier = Arc::clone(&barrier);
            let disable_authority = &authority;
            let disable = threads.spawn(move || {
                disable_barrier.wait();
                disable_authority.disable_card_with_sessions_for_isolated_tests(
                    &writer,
                    MemoryId::from_bytes(id(4)),
                    before,
                )
            });
            barrier.wait();
            (login.join().unwrap(), disable.join().unwrap())
        });
        mutation.expect("disable publishes");
        match issued {
            Ok(issued) => assert!(matches!(
                authority.verifier().verify(issued.credential(), base),
                Err(MemoryV1SessionAuthorityError::Revoked)
            )),
            Err(error) => assert_eq!(error, MemoryV1SessionAuthorityError::Unavailable),
        }
        assert!(matches!(
            session.issue_verified_session(
                &root,
                VerifiedMemoryV1Identity::from_verified_facts(principal),
                base,
                30,
            ),
            Err(MemoryV1SessionAuthorityError::Unavailable)
        ));
    }

    #[tokio::test]
    async fn configured_session_pins_file_credentials_and_preserves_legacy_constructor() {
        let test_name = "runtime::memory_v1::tests::configured_session_pins_file_credentials_and_preserves_legacy_constructor";
        if std::env::var_os(LOGIN_CHILD_ENV).is_none() {
            run_isolated(test_name);
            return;
        }

        let owner = serving_login_owner();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let scope = astral_authorization_root::memory_v1_request::RequestRootScope::new(
            owner.handle(),
            Uuid::new_v4(),
        );
        let root = scope.extension();
        let user_id = identity().user_id;
        let credentials = Arc::new(
            crate::memory_v1_service::MemoryV1FileCredentials::from_json(&format!(
                r#"{{"version":1,"credentials":[{{"identifier":"Alice","userId":"{user_id}","passwordHash":"{}","status":"active","revision":1}}]}}"#,
                crate::auth::hash_password("correct").unwrap()
            ))
            .unwrap(),
        );
        let configured = MemoryV1IdentitySession::from_session_adapter_with_file_credentials(
            authority.identity_session_adapter(),
            Arc::clone(&credentials),
            30,
        );
        let pinned_authenticator =
            MemoryV1CredentialAuthenticator::from_file_credentials(Arc::clone(&credentials));
        fn request<'a>(password: &'a str, lifetime_seconds: i64) -> MemoryV1LoginRequest<'a> {
            MemoryV1LoginRequest {
                identifier: "alice",
                password,
                user_card_id: MemoryId::from_bytes(id(4)),
                now_unix_seconds: fixture_now() - 1,
                lifetime_seconds,
            }
        }

        let issued = configured
            .login(&pinned_authenticator, &root, request("correct", 30))
            .await
            .expect("the pinned file credential authenticates");
        assert!(authority
            .verifier()
            .verify(issued.credential(), fixture_now())
            .is_ok());
        assert!(matches!(
            configured
                .login(&pinned_authenticator, &root, request("wrong", 30))
                .await,
            Err(MemoryV1LoginError::InvalidCredentials)
        ));
        assert!(configured
            .login(&pinned_authenticator, &root, request("correct", 31))
            .await
            .is_err());

        let alternative_repository = Arc::new(FakeCredentialRepository {
            record: Some(MemoryV1CredentialRecord::new(
                user_id,
                crate::auth::hash_password("correct").unwrap(),
                MemoryV1CredentialStatus::Active,
                1,
            )),
            ..Default::default()
        });
        let alternative_authenticator =
            MemoryV1CredentialAuthenticator::new(alternative_repository.clone());
        assert!(configured
            .login(&alternative_authenticator, &root, request("correct", 30))
            .await
            .is_err());
        assert!(alternative_repository.seen.lock().unwrap().is_empty());

        let alternative_router = crate::memory_v1_service::memory_v1_auth_router(
            Arc::new(configured.clone()),
            alternative_authenticator,
            30,
        );
        let body = format!(
            r#"{{"identifier":"alice","password":"correct","userCardId":"{}"}}"#,
            MemoryId::from_bytes(id(4))
        );
        let response = tower::ServiceExt::oneshot(
            alternative_router,
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/v1/auth/sessions")
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .extension(root.clone())
                .body(axum::body::Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["reasonCode"], "IDENTITY_UNAVAILABLE");
        assert!(!body.to_string().contains("correct"));

        let legacy =
            MemoryV1IdentitySession::from_session_adapter(authority.identity_session_adapter());
        let legacy_issued = legacy
            .login(
                &MemoryV1CredentialAuthenticator::new(alternative_repository),
                &root,
                request("correct", 30),
            )
            .await
            .expect("the legacy adapter-only constructor keeps its behavior");
        assert!(authority
            .verifier()
            .verify(legacy_issued.credential(), fixture_now())
            .is_ok());
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

    // memory—v1: The Identity boundary cannot issue without the matching root.
    #[test]
    fn only_verified_identity_value_enters_identity_session_boundary() {
        let test_name =
            "runtime::memory_v1::tests::only_verified_identity_value_enters_identity_session_boundary";
        if std::env::var_os(LOGIN_CHILD_ENV).is_none() {
            run_isolated(test_name);
            return;
        }
        let base = fixture_now() - 1;
        let owner = serving_login_owner();
        let scope = astral_authorization_root::memory_v1_request::RequestRootScope::new(
            owner.handle(),
            Uuid::new_v4(),
        );
        let root = scope.extension();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let session =
            MemoryV1IdentitySession::from_session_adapter(authority.identity_session_adapter());
        let identity = root
            .with_reader(|reader| {
                verified_card_identity(reader, identity().user_id, MemoryId::from_bytes(id(4)))
            })
            .unwrap()
            .unwrap();
        let principal = VerifiedMemoryV1Identity::from_verified_facts(identity);
        let issued = session
            .issue_verified_session(&root, principal, base, 30)
            .unwrap();
        assert!(issued.credential().starts_with("m1."));
        assert!(authority
            .verifier()
            .verify(issued.credential(), base)
            .is_ok());
    }
}
