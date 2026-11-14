//! memory—v1: Opaque authenticated session facts bound to one request root.
//!
//! A [`VerifiedSessionFacts`] value is deliberately not constructible outside
//! this crate. A future Identity/session authority must add its trusted
//! issuance path here after validating credentials, session state, card
//! selection and revocation. UUID values, JWT claims, Gateway signatures and
//! candidate relationships are not issuance proof.

use std::sync::{Arc, Weak};

use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use thiserror::Error;

use crate::memory_v1_request::{RequestRootAccessError, RequestRootExtension};
use crate::memory_v1_root::RequestRootReader;

/// Facts that a validated memory—v1 ACCESS session would provide.
///
/// Fields stay private so callers cannot turn client supplied UUIDs or legacy
/// integer claims into an authenticated principal. The current branch has no
/// production issuer; therefore no formal request can obtain this value yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSessionFacts {
    session_id: MemoryId,
    session_version: u64,
    identity: CandidateIdentity,
    issued_at_unix_seconds: i64,
    expires_at_unix_seconds: i64,
    revocation_generation: u64,
}

/// A request-local capability carrying session facts and the same root scope.
///
/// This type is not serializable and cannot outlive the scope: it stores only a
/// weak reference to the request owner. Cloning it shares the capability but
/// does not create another root, reader or session.
#[derive(Clone)]
pub struct RequestSessionExtension {
    shared: Weak<super::memory_v1_request::RequestRootShared>,
    facts: Arc<VerifiedSessionFacts>,
}

/// Errors from binding or reading an authenticated request session.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RequestSessionError {
    /// The request scope has ended or was never available.
    #[error(transparent)]
    Scope(#[from] RequestRootAccessError),
    /// The capability belongs to a different request root scope.
    #[error("memory-v1 session facts are bound to another request scope")]
    ForeignScope,
}

impl VerifiedSessionFacts {
    /// Return the authenticated UUID identity after the session authority has
    /// supplied it. The value remains separate from the root relationship proof.
    pub fn candidate_identity(&self) -> CandidateIdentity {
        self.identity
    }

    /// Return the opaque session identifier for correlation and freshness checks.
    pub fn session_id(&self) -> MemoryId {
        self.session_id
    }

    /// Return the authority's monotonic session version.
    pub fn session_version(&self) -> u64 {
        self.session_version
    }

    /// Return the authority's issuance time in UTC Unix seconds.
    pub fn issued_at_unix_seconds(&self) -> i64 {
        self.issued_at_unix_seconds
    }

    /// Return the exclusive session expiry in UTC Unix seconds.
    pub fn expires_at_unix_seconds(&self) -> i64 {
        self.expires_at_unix_seconds
    }

    /// Return the revocation generation observed by the session authority.
    pub fn revocation_generation(&self) -> u64 {
        self.revocation_generation
    }

    /// Check the authority-provided validity window at a trusted observation.
    ///
    /// The caller must supply trusted time and separately recheck revocation or
    /// session state when the session contract requires it.
    pub fn valid_at(&self, now_unix_seconds: i64) -> bool {
        self.issued_at_unix_seconds <= now_unix_seconds
            && now_unix_seconds < self.expires_at_unix_seconds
    }

    // memory—v1: Only a trusted session-authority implementation inside this
    // crate may mint authenticated facts. This constructor is crate-private;
    // callers outside the authorization-root crate cannot manufacture facts.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn issue(
        session_id: MemoryId,
        session_version: u64,
        identity: CandidateIdentity,
        issued_at_unix_seconds: i64,
        expires_at_unix_seconds: i64,
        revocation_generation: u64,
    ) -> Result<Self, SessionFactsIssueError> {
        if issued_at_unix_seconds >= expires_at_unix_seconds {
            return Err(SessionFactsIssueError::InvalidValidityWindow);
        }
        Ok(Self {
            session_id,
            session_version,
            identity,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            revocation_generation,
        })
    }
}

/// Failure while a trusted session authority constructs facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum SessionFactsIssueError {
    /// The authority returned an empty or inverted validity interval.
    #[error("memory-v1 session validity window is empty or inverted")]
    InvalidValidityWindow,
}

impl RequestRootExtension {
    /// memory—v1: Bind authority-issued session facts to this exact request.
    ///
    /// The root extension itself is not an authentication proof. This method
    /// accepts only the opaque facts type, checks that this scope is still live,
    /// and records the scope identity so downstream code cannot mix facts and a
    /// different request root.
    pub fn bind_session_facts(
        &self,
        facts: VerifiedSessionFacts,
    ) -> Result<RequestSessionExtension, RequestSessionError> {
        let shared = self.active_shared().map_err(RequestSessionError::Scope)?;
        Ok(RequestSessionExtension {
            shared: Arc::downgrade(&shared),
            facts: Arc::new(facts),
        })
    }
}

impl RequestSessionExtension {
    /// Check that this capability was bound to the supplied root extension.
    pub fn is_bound_to(&self, root: &RequestRootExtension) -> bool {
        root.shares_scope_with(&self.shared)
    }

    /// Borrow facts and the same request reader for one synchronous callback.
    ///
    /// The reader is never returned from this callback and no lock is held while
    /// the callback runs. Scope or root failure is propagated unchanged.
    pub fn with_context<T>(
        &self,
        root: &RequestRootExtension,
        f: impl for<'a> FnOnce(&'a VerifiedSessionFacts, &'a RequestRootReader) -> T,
    ) -> Result<T, RequestSessionError> {
        if !self.is_bound_to(root) {
            return Err(RequestSessionError::ForeignScope);
        }
        let facts = Arc::clone(&self.facts);
        root.with_reader(|reader| f(facts.as_ref(), reader))
            .map_err(RequestSessionError::Scope)
    }

    /// Borrow only the opaque session facts after validating the scope binding.
    pub fn with_facts<T>(
        &self,
        root: &RequestRootExtension,
        f: impl FnOnce(&VerifiedSessionFacts) -> T,
    ) -> Result<T, RequestSessionError> {
        if !self.is_bound_to(root) {
            return Err(RequestSessionError::ForeignScope);
        }
        let facts = Arc::clone(&self.facts);
        root.with_reader(|_| f(facts.as_ref()))
            .map_err(RequestSessionError::Scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_v1_db_rows::CandidateRows;
    use crate::memory_v1_hamt::CandidateBudget;
    use crate::memory_v1_request::RequestRootScope;
    use crate::memory_v1_root::{install_process_root, RootHandle, RootOwner};
    use astral_types::memory_v1::MemoryId;
    use uuid::Uuid;

    fn facts() -> VerifiedSessionFacts {
        VerifiedSessionFacts::issue(
            MemoryId::from_bytes([9; 16]),
            4,
            CandidateIdentity {
                user_id: MemoryId::from_bytes([1; 16]),
                identity_card_id: MemoryId::from_bytes([2; 16]),
                user_card_id: MemoryId::from_bytes([3; 16]),
                tenant_id: MemoryId::from_bytes([4; 16]),
            },
            100,
            200,
            7,
        )
        .unwrap()
    }

    fn scope() -> (RootHandle, RequestRootScope) {
        static OWNER: std::sync::OnceLock<RootOwner> = std::sync::OnceLock::new();
        let owner = OWNER.get_or_init(|| {
            install_process_root(
                CandidateRows::default(),
                vec![],
                CandidateBudget {
                    max_table_rows: 8,
                    max_bindings_per_read: 2,
                },
            )
            .expect("failed to install session test root")
        });
        let handle = owner.handle();
        let scope = RequestRootScope::new(handle.clone(), Uuid::new_v4());
        (handle, scope)
    }

    #[test]
    fn authority_facts_validate_window_and_remain_opaque() {
        assert!(matches!(
            VerifiedSessionFacts::issue(
                MemoryId::from_bytes([1; 16]),
                1,
                facts().identity,
                20,
                20,
                0,
            ),
            Err(SessionFactsIssueError::InvalidValidityWindow)
        ));
        let facts = facts();
        assert!(facts.valid_at(100));
        assert!(!facts.valid_at(200));
        assert_eq!(facts.session_version(), 4);
        assert_eq!(facts.revocation_generation(), 7);
    }

    #[test]
    fn facts_cannot_mix_request_scopes_and_end_with_scope() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_SESSION_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "memory_v1_session::tests::facts_cannot_mix_request_scopes_and_end_with_scope",
                ])
                .env(CHILD, "1")
                .output()
                .expect("failed to start isolated session capability test");
            assert!(
                output.status.success(),
                "isolated test failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let (handle, first_scope) = scope();
        let first = first_scope.extension();
        let bound = first.bind_session_facts(facts()).unwrap();
        assert!(bound.is_bound_to(&first));
        assert_eq!(
            bound
                .with_context(&first, |facts, reader| {
                    (facts.session_id(), reader.request_id())
                })
                .unwrap()
                .0,
            MemoryId::from_bytes([9; 16])
        );

        let second_scope = RequestRootScope::new(handle, Uuid::new_v4());
        let second = second_scope.extension();
        assert_eq!(
            bound.with_context(&second, |_, _| ()),
            Err(RequestSessionError::ForeignScope)
        );
        drop(first_scope);
        let result = bound.with_context(&first, |_, _| ());
        assert_eq!(
            result,
            Err(RequestSessionError::Scope(
                RequestRootAccessError::ScopeEnded
            )),
            "unexpected result after scope drop: {result:?}"
        );
    }
}
