//! memory—v1: Opaque authenticated session facts bound to one request root.
//!
//! A [`VerifiedSessionFacts`] value is deliberately not constructible outside
//! this crate. A future Identity/session authority must add its trusted
//! issuance path here after validating credentials, session state, card
//! selection and revocation. UUID values, JWT claims, Gateway signatures and
//! candidate relationships are not issuance proof.

use std::sync::{Arc, OnceLock, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use thiserror::Error;

use crate::memory_v1_request::{RequestRootAccessError, RequestRootExtension};
use crate::memory_v1_root::{DependencyRecord, RequestRootReader, RootMetadata};
use crate::memory_v1_rules::{window_active, MemoryV1Validity};

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

/// An internal identity token for one session authority. Its root slot prevents
/// one authority and its credentials from being reused across installed roots.
#[derive(Debug)]
pub(crate) struct SessionAuthorityToken(OnceLock<crate::memory_v1_root::RootInstanceId>);

impl SessionAuthorityToken {
    // memory—v1: Mint a process-local authority identity.
    pub(crate) fn new() -> Self {
        Self(OnceLock::new())
    }

    // memory—v1: Bind this authority permanently to one installed root instance.
    pub(crate) fn bind_root(&self, root_id: crate::memory_v1_root::RootInstanceId) -> bool {
        self.0.set(root_id).is_ok() || self.0.get() == Some(&root_id)
    }
}

/// An internal binding proof that ties one request capability to the
/// authority and credential that produced its facts.
///
/// `bind_session_facts` deliberately does not create this value. That public
/// compatibility path can expose candidate facts to trusted in-process code,
/// but it cannot establish live-session freshness for a final ALLOW.
#[derive(Clone)]
pub(crate) struct SessionAuthorityBinding {
    authority_id: Arc<SessionAuthorityToken>,
    credential_digest: [u8; 32],
    verifier: super::memory_v1_session_authority::MemoryV1SessionVerifier,
}

impl SessionAuthorityBinding {
    // memory—v1: Compare the issuing authority's process-local identity.
    pub(crate) fn is_from(&self, authority_id: &Arc<SessionAuthorityToken>) -> bool {
        Arc::ptr_eq(&self.authority_id, authority_id)
    }

    // memory—v1: Return the digest identifying the bound credential record.
    pub(crate) fn credential_digest(&self) -> [u8; 32] {
        self.credential_digest
    }
}

/// Failures while obtaining the material needed for an authority freshness
/// check. The authority maps unproven or foreign material to its existing
/// invalid-credential failure so callers cannot use error detail as proof.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SessionFreshnessBindingError {
    Scope(RequestRootAccessError),
    ForeignScope,
    MissingAuthorityProof,
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
    authority_binding: Option<SessionAuthorityBinding>,
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
    /// different request root. Because no session authority proof is present,
    /// the result cannot pass the dedicated live-session revalidation API.
    pub fn bind_session_facts(
        &self,
        facts: VerifiedSessionFacts,
    ) -> Result<RequestSessionExtension, RequestSessionError> {
        let shared = self.active_shared().map_err(RequestSessionError::Scope)?;
        Ok(RequestSessionExtension {
            shared: Arc::downgrade(&shared),
            facts: Arc::new(facts),
            authority_binding: None,
        })
    }

    /// memory—v1: Bind facts together with an authority-owned proof. This is crate-private
    /// so an external caller cannot manufacture a live-session binding from a
    /// cloned [`VerifiedSessionFacts`] value.
    pub(crate) fn bind_authoritative_session(
        &self,
        facts: VerifiedSessionFacts,
        authority_id: Arc<SessionAuthorityToken>,
        credential_digest: [u8; 32],
        verifier: super::memory_v1_session_authority::MemoryV1SessionVerifier,
    ) -> Result<RequestSessionExtension, RequestSessionError> {
        let shared = self.active_shared().map_err(RequestSessionError::Scope)?;
        Ok(RequestSessionExtension {
            shared: Arc::downgrade(&shared),
            facts: Arc::new(facts),
            authority_binding: Some(SessionAuthorityBinding {
                authority_id,
                credential_digest,
                verifier,
            }),
        })
    }
}

/// memory—v1: Time windows of one winning rule and its binding.
#[derive(Clone, Copy)]
pub struct FinalCheckWindow {
    /// Rule-level validity, if constrained.
    pub entry_validity: Option<MemoryV1Validity>,
    /// Inclusive binding start, if constrained.
    pub binding_from: Option<i64>,
    /// Exclusive binding end, if constrained.
    pub binding_until: Option<i64>,
}

/// memory—v1: Time-dependent inputs recorded by one rule evaluation.
pub struct FinalCheckTimeConstraints<'a> {
    /// Trusted observation made at the beginning of evaluation.
    pub start_time: i64,
    /// Later activation boundaries that may alter the aggregate decision.
    pub future_boundaries: &'a [i64],
    /// Every matching ALLOW rule's time windows.
    pub winning_windows: &'a [FinalCheckWindow],
}

/// A request-scoped handle for a nonblocking live-record check.
///
/// memory—v1: This borrowed handle is valid only inside the reader callback.
/// It does not grant authorization or establish a mutation commit boundary.
pub struct SessionFinalCheck<'a> {
    facts: &'a VerifiedSessionFacts,
    binding: &'a SessionAuthorityBinding,
    reader: &'a RequestRootReader,
}

impl SessionFinalCheck<'_> {
    /// memory—v1: Sample and validate trusted time while the live session,
    /// root dependencies and registry version are stable. Object-specific fence
    /// observations bracket the sample. Failure or contention returns `None`.
    /// The result is not permission to commit a later mutation; the caller must
    /// perform its own commit checks.
    pub fn try_final_time(
        &self,
        record: &DependencyRecord,
        constraints: &FinalCheckTimeConstraints<'_>,
    ) -> Option<i64> {
        self.try_final_time_with(record, constraints, None, || {
            let seconds = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
            i64::try_from(seconds).ok()
        })
    }

    /// memory—v1: Inject a deterministic clock only in isolated test builds.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn try_final_time_for_test(
        &self,
        record: &DependencyRecord,
        constraints: &FinalCheckTimeConstraints<'_>,
        clock: impl FnOnce() -> Option<i64>,
    ) -> Option<i64> {
        self.try_final_time_with(record, constraints, None, clock)
    }

    /// memory—v1: Recheck the exact request snapshot and target fence using the
    /// same live-session, writer and registry guards. Object-specific fence
    /// observations bracket the trusted clock sample.
    pub fn try_final_time_exact_root(
        &self,
        record: &DependencyRecord,
        constraints: &FinalCheckTimeConstraints<'_>,
        metadata: RootMetadata,
        target_rule_set: [u8; 16],
    ) -> Option<i64> {
        self.try_final_time_with(
            record,
            constraints,
            Some((metadata, std::slice::from_ref(&target_rule_set))),
            || {
                let seconds = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
                i64::try_from(seconds).ok()
            },
        )
    }

    /// memory—v1: Inject the exact-root final clock in isolated tests only.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn try_final_time_exact_root_for_test(
        &self,
        record: &DependencyRecord,
        constraints: &FinalCheckTimeConstraints<'_>,
        metadata: RootMetadata,
        target_rule_set: [u8; 16],
        clock: impl FnOnce() -> Option<i64>,
    ) -> Option<i64> {
        self.try_final_time_with(
            record,
            constraints,
            Some((metadata, std::slice::from_ref(&target_rule_set))),
            clock,
        )
    }

    /// memory—v1: Recheck one exact root and every target rule-set fence with
    /// the live session, writer and registry held stable. Fence observations
    /// bracket the trusted clock. The caller must derive the complete target
    /// list from that root. This does not authorize a later mutation.
    pub fn try_final_time_exact_batch(
        &self,
        record: &DependencyRecord,
        constraints: &FinalCheckTimeConstraints<'_>,
        metadata: RootMetadata,
        target_rule_sets: &[[u8; 16]],
    ) -> Option<i64> {
        if target_rule_sets.is_empty() || target_rule_sets.contains(&[0; 16]) {
            return None;
        }
        self.try_final_time_with(
            record,
            constraints,
            Some((metadata, target_rule_sets)),
            || {
                let seconds = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
                i64::try_from(seconds).ok()
            },
        )
    }

    /// memory—v1: Inject the batch final clock in isolated tests only.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn try_final_time_exact_batch_for_test(
        &self,
        record: &DependencyRecord,
        constraints: &FinalCheckTimeConstraints<'_>,
        metadata: RootMetadata,
        target_rule_sets: &[[u8; 16]],
        clock: impl FnOnce() -> Option<i64>,
    ) -> Option<i64> {
        if target_rule_sets.is_empty() || target_rule_sets.contains(&[0; 16]) {
            return None;
        }
        self.try_final_time_with(
            record,
            constraints,
            Some((metadata, target_rule_sets)),
            clock,
        )
    }

    /// memory—v1: Recheck an active, root-derived card with no unremoved
    /// bindings while the exact root, session, registry and actor fences are
    /// stable. This proves only the target-card facts and exact-root observation;
    /// it does not establish resource/action authorization or permission to commit
    /// a later mutation. A previously disabled card is conservatively rejected.
    pub fn try_final_time_exact_empty_card(
        &self,
        record: &DependencyRecord,
        constraints: &FinalCheckTimeConstraints<'_>,
        metadata: RootMetadata,
        target: crate::memory_v1_root::GovernanceTargetFacts,
    ) -> Option<i64> {
        if target.user_card_id == [0; 16]
            || target.owner_user_id == [0; 16]
            || target.tenant_id == [0; 16]
            || target.rule_set_id != [0; 16]
        {
            return None;
        }
        self.try_final_time_with(record, constraints, Some((metadata, &[])), || {
            let valid = self
                .reader
                .read_card_for_evaluation(target.user_card_id, |context, _history| {
                    context.card.user_card_id == target.user_card_id
                        && context.card.user_id == target.owner_user_id
                        && context.card.tenant_id == target.tenant_id
                        && context.card.status == crate::memory_v1_db_rows::UserCardStatus::Active
                        && context.user.user_id == target.owner_user_id
                        && context.identity.user_id == target.owner_user_id
                        && context.tenant.tenant_id == target.tenant_id
                        && context.bindings.is_empty()
                })
                .ok()?;
            if !valid {
                return None;
            }
            let seconds = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
            i64::try_from(seconds).ok()
        })
    }

    /// memory—v1: Recheck a disabled, root-derived card with no unremoved
    /// bindings under the exact root, live session, registry and actor fences.
    /// The supplied target is only an expectation and is compared with the card,
    /// user, identity and tenant read from the guarded root snapshot. This is a
    /// prerequisite observation, not authorization to enable the card or commit.
    pub fn try_final_time_exact_empty_disabled_card(
        &self,
        record: &DependencyRecord,
        constraints: &FinalCheckTimeConstraints<'_>,
        metadata: RootMetadata,
        target: crate::memory_v1_root::GovernanceTargetFacts,
    ) -> Option<i64> {
        if target.user_card_id == [0; 16]
            || target.owner_user_id == [0; 16]
            || target.tenant_id == [0; 16]
            || target.rule_set_id != [0; 16]
        {
            return None;
        }
        self.try_final_time_with(record, constraints, Some((metadata, &[])), || {
            let valid = self
                .reader
                .read_card_for_evaluation(target.user_card_id, |context, _history| {
                    context.card.user_card_id == target.user_card_id
                        && context.card.user_id == target.owner_user_id
                        && context.card.tenant_id == target.tenant_id
                        && context.card.status == crate::memory_v1_db_rows::UserCardStatus::Disabled
                        && context.user.user_id == target.owner_user_id
                        && context.identity.user_id == target.owner_user_id
                        && context.tenant.tenant_id == target.tenant_id
                        && context.bindings.is_empty()
                })
                .ok()?;
            if !valid {
                return None;
            }
            let seconds = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
            i64::try_from(seconds).ok()
        })
    }

    /// memory—v1: Re-resolve a proposed user-card creation target while the
    /// exact root, live session, registry and actor fences remain stable. The
    /// supplied IDs are expectations only; the root must independently verify
    /// a historical user/tenant relationship and that the new card ID is unused.
    /// The historical relationship does not prove current membership or user status.
    /// This observation grants no resource/action permission or commit right.
    pub fn try_final_time_exact_user_card_create(
        &self,
        record: &DependencyRecord,
        constraints: &FinalCheckTimeConstraints<'_>,
        metadata: RootMetadata,
        target: crate::memory_v1_root::GovernanceTargetFacts,
    ) -> Option<i64> {
        if target.rule_set_id != [0; 16] {
            return None;
        }
        self.try_final_time_with(record, constraints, Some((metadata, &[])), || {
            let resolved = self
                .reader
                .user_card_create_target(
                    target.user_card_id,
                    target.owner_user_id,
                    target.tenant_id,
                )
                .ok()?;
            if resolved != target {
                return None;
            }
            let seconds = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
            i64::try_from(seconds).ok()
        })
    }

    // memory—v1: No production caller supplies code executed under the locks.
    fn try_final_time_with(
        &self,
        record: &DependencyRecord,
        constraints: &FinalCheckTimeConstraints<'_>,
        exact_target: Option<(RootMetadata, &[[u8; 16]])>,
        clock: impl FnOnce() -> Option<i64>,
    ) -> Option<i64> {
        if record.card_id != self.facts.candidate_identity().user_card_id.into_bytes() {
            return None;
        }
        self.binding
            .verifier
            .try_with_live_record(self.facts, self.binding, |live_facts| {
                self.reader.try_with_rechecked_dependencies_and_target(
                    record,
                    exact_target,
                    Some(&self.binding.authority_id),
                    || {
                        let now = clock()?;
                        if now < constraints.start_time
                            || !live_facts.valid_at(now)
                            || constraints
                                .future_boundaries
                                .iter()
                                .any(|boundary| *boundary <= now)
                            || constraints.winning_windows.is_empty()
                            || constraints.winning_windows.iter().any(|winning| {
                                !window_active(
                                    winning.entry_validity.and_then(|validity| validity.from),
                                    winning.entry_validity.and_then(|validity| validity.until),
                                    now,
                                ) || !window_active(
                                    winning.binding_from,
                                    winning.binding_until,
                                    now,
                                )
                            })
                        {
                            return None;
                        }
                        Some(now)
                    },
                )
            })
            .ok()
            .and_then(Result::ok)
            .flatten()
            .flatten()
    }
}

impl RequestSessionExtension {
    /// memory—v1: Borrow the exact request reader and a live-record check handle.
    ///
    /// Scope acquisition completes before the callback can acquire the session
    /// lock. Compatibility facts receive no final-check handle and cannot be
    /// used to produce an ALLOW. The result is not a commit authorization.
    pub fn with_authoritative_context<T>(
        &self,
        root: &RequestRootExtension,
        f: impl for<'a> FnOnce(
            &'a VerifiedSessionFacts,
            &'a RequestRootReader,
            Option<SessionFinalCheck<'a>>,
        ) -> T,
    ) -> Result<T, RequestSessionError> {
        if !self.is_bound_to(root) {
            return Err(RequestSessionError::ForeignScope);
        }
        root.with_reader(|reader| {
            let facts = self.facts.as_ref();
            let final_check = self
                .authority_binding
                .as_ref()
                .filter(|binding| reader.has_session_authority(&binding.authority_id))
                .map(|binding| SessionFinalCheck {
                    facts,
                    binding,
                    reader,
                });
            f(facts, reader, final_check)
        })
        .map_err(RequestSessionError::Scope)
    }

    /// Check that this capability was bound to the supplied root extension.
    pub fn is_bound_to(&self, root: &RequestRootExtension) -> bool {
        root.shares_scope_with(&self.shared)
    }

    /// memory—v1: Recheck the issuing authority's live record for this request.
    ///
    /// Compatibility bindings without an authority proof fail closed. A caller
    /// performing a later mutation must recheck again at its own commit boundary.
    pub fn revalidate_authority(
        &self,
        root: &RequestRootExtension,
        now_unix_seconds: i64,
    ) -> Result<(), super::memory_v1_session_authority::MemoryV1SessionAuthorityError> {
        let binding = self.authority_binding.as_ref().ok_or(
            super::memory_v1_session_authority::MemoryV1SessionAuthorityError::InvalidCredential,
        )?;
        binding
            .verifier
            .revalidate_bound_session(self, root, now_unix_seconds)
    }

    /// memory—v1: Capture the facts and authority binding after validating the exact
    /// request scope. The root reader lease is released before the caller can
    /// inspect authority state, so live-session checks do not nest the root and
    /// authority locks.
    pub(crate) fn authority_binding_material(
        &self,
        root: &RequestRootExtension,
    ) -> Result<(VerifiedSessionFacts, SessionAuthorityBinding), SessionFreshnessBindingError> {
        if !self.is_bound_to(root) {
            return Err(SessionFreshnessBindingError::ForeignScope);
        }
        let facts = Arc::clone(&self.facts);
        let binding = self
            .authority_binding
            .as_ref()
            .cloned()
            .ok_or(SessionFreshnessBindingError::MissingAuthorityProof)?;
        root.with_reader(|reader| {
            if reader.has_session_authority(&binding.authority_id) {
                Ok((facts.as_ref().clone(), binding))
            } else {
                Err(SessionFreshnessBindingError::MissingAuthorityProof)
            }
        })
        .map_err(SessionFreshnessBindingError::Scope)?
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
