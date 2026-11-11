//! `RuleRepository` adapter for the certified, process-local authorization model.
//!
//! This repository is intentionally memory-only. It owns no SQL pool, never
//! refills a missing value, and treats every serving/token/read-model failure as
//! a repository error so the policy engine can fail closed.

use std::sync::Arc;

use astral_types::{
    AuthorizationFenceProof, CertifiedAuthorizationState, PolicyContext, PolicyDecision,
    PolicyError, PublishedCardAuthorization, PublishedCardEvidenceScope,
};
use policy_engine::{
    AuthorizationFenceProvider, OrgAuthorityRead, PublishedEvidenceReadMode, RuleRepository,
};
use time::OffsetDateTime;

use crate::certified_memory_authority::{
    CardContextKey, CertifiedMemoryFailure, CertifiedMemoryReadModel, CertifiedMemoryReadToken,
    CertifiedMemoryServing, CertifiedMemoryStore, OrgReadKey,
};

/// A narrow `RuleRepository` backed only by an installed certified-memory
/// snapshot.
///
/// The store must be explicitly installed and marked serving by its owner. This
/// adapter does not install snapshots, obtain authority proofs, or fall back to
/// any durable reader when a value is absent or unavailable.
#[derive(Clone)]
pub struct CertifiedMemoryRuleRepository {
    store: Arc<CertifiedMemoryStore>,
    request_token: Option<CertifiedMemoryReadToken>,
}

/// Provider-aware certified repository. Snapshot facts remain memory-only;
/// fresh request-bound proofs and evidence certification come from the supplied
/// authority provider. This wrapper owns no SQL pool and never refills misses.
#[derive(Clone)]
pub struct CertifiedMemoryProofRepository<P> {
    memory: CertifiedMemoryRuleRepository,
    authority: Arc<P>,
}

/// Certified deny-only SoD read port. It is intentionally separate from
/// `RuleRepository`: mutation-time SoD remains on the durable transaction path,
/// while this adapter can be selected by a host only when the same snapshot token
/// proves card evidence and the complete bounded policy set.
#[derive(Clone)]
pub struct CertifiedMemorySodRepository {
    store: Arc<CertifiedMemoryStore>,
    request_token: Option<CertifiedMemoryReadToken>,
}

/// One-token SoD read batch. Policy rows and published card evidence are read
/// from the same certified snapshot so a replacement cannot split the facts
/// used by the deny-only evaluator.
#[derive(Clone)]
pub struct CertifiedSodReadSet {
    pub scope: PublishedCardEvidenceScope,
    pub policies: Vec<crate::certified_memory_authority::CertifiedSodPolicy>,
    pub evidence: Arc<PublishedCardAuthorization>,
}

impl CertifiedMemorySodRepository {
    pub fn new(store: Arc<CertifiedMemoryStore>) -> Self {
        Self {
            store,
            request_token: None,
        }
    }

    pub fn with_read_token(
        store: Arc<CertifiedMemoryStore>,
        token: CertifiedMemoryReadToken,
    ) -> Self {
        Self {
            store,
            request_token: Some(token),
        }
    }

    fn read_token(
        &self,
        operation: &'static str,
    ) -> Result<(CertifiedMemoryReadToken, i64), PolicyError> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let token = self.request_token.clone().ok_or_else(|| {
            PolicyError::Repository(format!(
                "certified_memory.{operation}.request_token_missing"
            ))
        })?;
        self.store
            .validate_read_token(&token, now)
            .map_err(|error| certified_memory_error(operation, error))?;
        Ok((token, now))
    }

    pub fn load_read_set(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<CertifiedSodReadSet, PolicyError> {
        let (token, now) = self.read_token("sod")?;
        let policies = self
            .store
            .read_sod_policies(&token, now)
            .map_err(|error| certified_memory_error("sod_policy", error))?;
        let evidence = self
            .store
            .read_published_card_evidence(&token, scope, now)
            .map_err(|error| certified_memory_error("sod_evidence", error))?
            .ok_or_else(|| {
                PolicyError::Repository("certified_memory.sod_evidence_missing".to_owned())
            })?;
        Ok(CertifiedSodReadSet {
            scope: scope.clone(),
            policies,
            evidence,
        })
    }

    pub fn load_policy_snapshot(
        &self,
    ) -> Result<Vec<crate::certified_memory_authority::CertifiedSodPolicy>, PolicyError> {
        let (token, now) = self.read_token("sod_policy")?;
        self.store
            .read_sod_policies(&token, now)
            .map_err(|error| certified_memory_error("sod_policy", error))
    }

    pub fn load_published_card_evidence(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<Arc<PublishedCardAuthorization>>, PolicyError> {
        let (token, now) = self.read_token("sod_evidence")?;
        self.store
            .read_published_card_evidence(&token, scope, now)
            .map_err(|error| certified_memory_error("sod_evidence", error))
    }

    pub fn load_org_admission(
        &self,
        context: &PolicyContext,
        decision: &PolicyDecision,
    ) -> Result<crate::sod_check::OrgSodAdmission, PolicyError> {
        let provenance = decision.org_provenance.clone().ok_or_else(|| {
            PolicyError::Repository("certified_memory.sod_org_provenance_missing".to_owned())
        })?;
        let key = OrgReadKey::from_policy_context(context).ok_or_else(|| {
            PolicyError::Repository("certified_memory.sod_org_context_missing".to_owned())
        })?;
        let (token, now) = self.read_token("sod_org")?;
        let value = self
            .store
            .read_org_authorization(&token, &key, now)
            .map_err(|error| certified_memory_error("sod_org", error))?
            .ok_or_else(|| {
                PolicyError::Repository("certified_memory.sod_org_evidence_missing".to_owned())
            })?;
        let evidence = match value {
            OrgAuthorityRead::Ready(evidence) => *evidence,
            OrgAuthorityRead::Pending { code } => {
                return Err(PolicyError::Repository(format!(
                    "certified_memory.sod_org_evidence_pending;{code}"
                )))
            }
            OrgAuthorityRead::Unavailable { code } => {
                return Err(PolicyError::Repository(format!(
                    "certified_memory.sod_org_evidence_unavailable;{code}"
                )))
            }
            OrgAuthorityRead::Disabled => {
                return Err(PolicyError::Repository(
                    "certified_memory.sod_org_evidence_disabled".to_owned(),
                ))
            }
            OrgAuthorityRead::Unmanaged => {
                return Err(PolicyError::Repository(
                    "certified_memory.sod_org_evidence_unmanaged".to_owned(),
                ))
            }
        };
        self.store
            .validate_read_token(&token, OffsetDateTime::now_utc().unix_timestamp())
            .map_err(|error| certified_memory_error("sod_org", error))?;
        Ok(crate::sod_check::OrgSodAdmission {
            evidence,
            provenance,
        })
    }

    pub fn positive_read_ready(&self) -> bool {
        self.request_token.as_ref().is_some_and(|token| {
            self.store
                .validate_read_token(token, OffsetDateTime::now_utc().unix_timestamp())
                .is_ok()
        })
    }
}

impl<P> CertifiedMemoryProofRepository<P>
where
    P: AuthorizationFenceProvider + 'static,
{
    pub fn new(store: Arc<CertifiedMemoryStore>, authority: Arc<P>) -> Self {
        Self {
            memory: CertifiedMemoryRuleRepository::new(Arc::clone(&store)),
            authority,
        }
    }

    pub fn with_read_token(
        store: Arc<CertifiedMemoryStore>,
        authority: Arc<P>,
        token: CertifiedMemoryReadToken,
    ) -> Self {
        Self {
            memory: CertifiedMemoryRuleRepository::with_read_token(store, token),
            authority,
        }
    }

    pub fn certified_store(&self) -> Arc<CertifiedMemoryStore> {
        self.memory.certified_store()
    }

    pub fn request_token(&self) -> Option<CertifiedMemoryReadToken> {
        self.memory.request_token()
    }

    pub fn with_request_token(&self, token: CertifiedMemoryReadToken) -> Self {
        Self {
            memory: CertifiedMemoryRuleRepository::with_read_token(
                self.memory.certified_store(),
                token,
            ),
            authority: Arc::clone(&self.authority),
        }
    }

    pub fn ensure_current(&self) -> Result<(), PolicyError> {
        self.memory.ensure_current()
    }

    fn validate_card_attestation(
        &self,
        proof: &AuthorizationFenceProof,
    ) -> Result<(), PolicyError> {
        let (token, now) = self.memory.begin_read("authority_attestation")?;
        let attestation = token.attestation().ok_or_else(|| {
            PolicyError::Repository("certified_memory.authority_attestation_missing".to_owned())
        })?;
        attestation
            .validate_at(token.generation(), now)
            .map_err(|error| {
                PolicyError::Repository(format!(
                    "certified_memory.authority_attestation_invalid;{error}"
                ))
            })?;
        let content_digest = token.content_digest().map_err(PolicyError::Repository)?;
        if content_digest != attestation.snapshot_hash {
            return Err(PolicyError::Repository(
                "certified_memory.root_snapshot_mismatch".to_owned(),
            ));
        }
        if proof.authority_term != attestation.authority_term
            || proof.global_fence_sequence != attestation.global_fence_sequence
            || proof.key_epoch != attestation.key_epoch
        {
            return Err(PolicyError::Repository(
                "certified_memory.authority_frontier_mismatch".to_owned(),
            ));
        }
        proof.validate_request_bound().map_err(|error| {
            PolicyError::Repository(format!("certified_memory.request_proof_invalid;{error}"))
        })
    }

    // deliberately independent from the certified-memory root content hash.
    fn validate_org_attestation(&self, proof: &AuthorizationFenceProof) -> Result<(), PolicyError> {
        let (token, now) = self.memory.begin_read("org_authority_attestation")?;
        let attestation = token.attestation().ok_or_else(|| {
            PolicyError::Repository("certified_memory.authority_attestation_missing".to_owned())
        })?;
        attestation
            .validate_at(token.generation(), now)
            .map_err(|error| {
                PolicyError::Repository(format!(
                    "certified_memory.authority_attestation_invalid;{error}"
                ))
            })?;
        if proof.authority_term != attestation.authority_term
            || proof.global_fence_sequence != attestation.global_fence_sequence
            || proof.key_epoch != attestation.key_epoch
        {
            return Err(PolicyError::Repository(
                "certified_memory.authority_frontier_mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

impl CertifiedMemoryRuleRepository {
    pub fn new(store: Arc<CertifiedMemoryStore>) -> Self {
        Self {
            store,
            request_token: None,
        }
    }

    pub fn with_read_token(
        store: Arc<CertifiedMemoryStore>,
        token: CertifiedMemoryReadToken,
    ) -> Self {
        Self {
            store,
            request_token: Some(token),
        }
    }

    pub fn request_token(&self) -> Option<CertifiedMemoryReadToken> {
        self.request_token.clone()
    }

    pub fn ensure_current(&self) -> Result<(), PolicyError> {
        let token = self.request_token.as_ref().ok_or_else(|| {
            PolicyError::Repository("certified_memory.request_token_missing".to_owned())
        })?;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        self.store
            .validate_read_token(token, now)
            .map_err(|error| certified_memory_error("request_token", error))
    }

    pub fn certified_store(&self) -> Arc<CertifiedMemoryStore> {
        Arc::clone(&self.store)
    }

    fn begin_read(
        &self,
        operation: &'static str,
    ) -> Result<
        (
            crate::certified_memory_authority::CertifiedMemoryReadToken,
            i64,
        ),
        PolicyError,
    > {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let token = self.request_token.clone().ok_or_else(|| {
            PolicyError::Repository(format!(
                "certified_memory.{operation}.request_token_missing"
            ))
        })?;
        self.store
            .validate_read_token(&token, now)
            .map_err(|error| certified_memory_error(operation, error))?;
        Ok((token, now))
    }
}

fn serving_code(serving: CertifiedMemoryServing) -> &'static str {
    match serving {
        CertifiedMemoryServing::Cold => "cold",
        CertifiedMemoryServing::Warming => "warming",
        CertifiedMemoryServing::Serving => "serving",
        CertifiedMemoryServing::Stale => "stale",
        CertifiedMemoryServing::Gap => "gap",
        CertifiedMemoryServing::Failed => "failed",
        CertifiedMemoryServing::Unknown => "unknown",
    }
}

fn certified_memory_error(operation: &str, error: CertifiedMemoryFailure) -> PolicyError {
    let detail = match error {
        CertifiedMemoryFailure::NotServing(serving) => {
            format!("not_serving.{}", serving_code(serving))
        }
        CertifiedMemoryFailure::Missing => "missing".to_owned(),
        CertifiedMemoryFailure::Invalid { code } => format!("invalid;{code}"),
        CertifiedMemoryFailure::Stale => "stale".to_owned(),
        CertifiedMemoryFailure::Gap => "gap".to_owned(),
        CertifiedMemoryFailure::Unknown => "unknown".to_owned(),
        CertifiedMemoryFailure::CapacityExceeded => "capacity_exceeded".to_owned(),
        CertifiedMemoryFailure::TokenNotCurrent => "token_not_current".to_owned(),
    };
    PolicyError::Repository(format!("certified_memory.{operation}_failed;{detail}"))
}

fn unsupported_proof(operation: &'static str) -> PolicyError {
    PolicyError::Repository(format!("certified_memory.{operation}_unsupported"))
}

#[async_trait::async_trait]
impl RuleRepository for CertifiedMemoryRuleRepository {
    async fn check_card_active(&self, ctx: &PolicyContext) -> Result<bool, PolicyError> {
        let (
            Some(user_id),
            Some(identity_card_id),
            Some(user_card_id),
            Some(tenant_id),
            Some(domain_id),
        ) = (
            ctx.user_id,
            ctx.identity_card_id,
            ctx.card_id,
            ctx.tenant_id,
            ctx.domain_id,
        )
        else {
            return Ok(false);
        };
        if [
            user_id,
            identity_card_id,
            user_card_id,
            tenant_id,
            domain_id,
        ]
        .into_iter()
        .any(|id| id <= 0)
        {
            return Ok(false);
        }

        let key = CardContextKey {
            user_id,
            identity_card_id,
            user_card_id,
        };
        let (token, now) = self.begin_read("check_card_active")?;
        let card = self
            .store
            .read_card_context(&token, &key, now)
            .map_err(|error| certified_memory_error("check_card_active", error))?;
        Ok(card.is_some_and(|card| {
            card.user_id == user_id
                && card.eligibility.user_card_tenant_id == tenant_id
                && card.eligibility.user_card_domain_id == domain_id
        }))
    }

    async fn is_active_global_admin(&self, user_id: i64) -> Result<bool, PolicyError> {
        if user_id <= 0 {
            return Ok(false);
        }
        let (token, now) = self.begin_read("global_admin")?;
        self.store
            .read_global_admin(&token, user_id, now)
            .map_err(|error| certified_memory_error("global_admin", error))
    }

    fn published_evidence_read_mode(&self) -> PublishedEvidenceReadMode {
        PublishedEvidenceReadMode::CertifiedMemory
    }

    fn positive_authorization_ready(&self) -> bool {
        self.request_token.as_ref().is_some_and(|token| {
            self.store
                .validate_read_token(token, OffsetDateTime::now_utc().unix_timestamp())
                .is_ok()
        })
    }

    async fn read_authorization_fence(
        &self,
        _scope: &PublishedCardEvidenceScope,
        _request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, PolicyError> {
        Err(unsupported_proof("authorization_fence_read"))
    }

    async fn read_request_authorization_fence(
        &self,
        _context: &PolicyContext,
        _scope: &PublishedCardEvidenceScope,
        _request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, PolicyError> {
        Err(unsupported_proof("request_authorization_fence_read"))
    }

    async fn read_org_authorization_fence(
        &self,
        _context: &PolicyContext,
        _evidence: &astral_types::org_scope::OrgAdmissionEvidence,
        _request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, PolicyError> {
        Err(unsupported_proof("org_authorization_fence_read"))
    }

    fn certify_authorization_evidence(
        &self,
        _proof: AuthorizationFenceProof,
        _evidence: Arc<PublishedCardAuthorization>,
        _scope: &PublishedCardEvidenceScope,
        _now_seconds: i64,
    ) -> Result<CertifiedAuthorizationState, PolicyError> {
        Err(unsupported_proof("authorization_evidence_certification"))
    }

    async fn load_published_card_authorization(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<Arc<PublishedCardAuthorization>>, PolicyError> {
        let (token, now) = self.begin_read("published_card_authorization")?;
        self.store
            .read_published_card_evidence(&token, scope, now)
            .map_err(|error| certified_memory_error("published_card_authorization", error))
    }

    async fn load_org_authorization(
        &self,
        ctx: &PolicyContext,
    ) -> Result<OrgAuthorityRead, PolicyError> {
        let Some(key) = OrgReadKey::from_policy_context(ctx) else {
            return Ok(OrgAuthorityRead::Pending {
                code: "org_scope.pending.context_missing".to_owned(),
            });
        };
        let (token, now) = self.begin_read("org_authorization")?;
        let read = self
            .store
            .read_org_authorization(&token, &key, now)
            .map_err(|error| certified_memory_error("org_authorization", error))?;
        Ok(read.unwrap_or(OrgAuthorityRead::Pending {
            code: "org_scope.pending.certified_memory_miss".to_owned(),
        }))
    }
}

#[async_trait::async_trait]
impl<P> RuleRepository for CertifiedMemoryProofRepository<P>
where
    P: AuthorizationFenceProvider + 'static,
{
    async fn check_card_active(&self, ctx: &PolicyContext) -> Result<bool, PolicyError> {
        self.memory.check_card_active(ctx).await
    }

    async fn is_active_global_admin(&self, user_id: i64) -> Result<bool, PolicyError> {
        self.memory.is_active_global_admin(user_id).await
    }

    fn published_evidence_read_mode(&self) -> PublishedEvidenceReadMode {
        PublishedEvidenceReadMode::CertifiedMemory
    }

    fn positive_authorization_ready(&self) -> bool {
        self.memory.positive_authorization_ready()
    }

    async fn read_authorization_fence(
        &self,
        _scope: &PublishedCardEvidenceScope,
        _request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, PolicyError> {
        Err(unsupported_proof("authorization_fence_read"))
    }

    async fn read_request_authorization_fence(
        &self,
        context: &PolicyContext,
        scope: &PublishedCardEvidenceScope,
        request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, PolicyError> {
        let proof = self
            .authority
            .read_request_authorization_fence(context, scope, request_nonce)
            .await?;
        self.validate_card_attestation(&proof)?;
        let binding = astral_types::authorization_request_digest(context)?;
        if proof.request_nonce != request_nonce
            || proof.request_binding_digest.as_deref() != Some(binding.as_str())
            || proof.scope.matches_evidence_scope(scope).is_err()
        {
            return Err(PolicyError::Repository(
                "certified_memory.request_proof_mismatch".to_owned(),
            ));
        }
        Ok(proof)
    }

    async fn read_org_authorization_fence(
        &self,
        context: &PolicyContext,
        evidence: &astral_types::org_scope::OrgAdmissionEvidence,
        request_nonce: &str,
    ) -> Result<AuthorizationFenceProof, PolicyError> {
        let read = self
            .authority
            .read_org_authorization_fence_with_certificate(context, evidence, request_nonce)
            .await?;
        self.validate_org_attestation(&read.proof)?;
        astral_types::validate_org_authority_proof_with_certificate(
            &read.proof,
            context,
            evidence,
            &read.certificate,
            request_nonce,
            OffsetDateTime::now_utc().unix_timestamp(),
        )
        .map_err(|error| {
            PolicyError::Repository(format!("certified_memory.org_proof_invalid;{error}"))
        })?;
        self.memory.ensure_current()?;
        Ok(read.proof)
    }

    fn certify_authorization_evidence(
        &self,
        proof: AuthorizationFenceProof,
        evidence: Arc<PublishedCardAuthorization>,
        scope: &PublishedCardEvidenceScope,
        now_seconds: i64,
    ) -> Result<CertifiedAuthorizationState, PolicyError> {
        self.validate_card_attestation(&proof)?;
        let (token, now) = self
            .memory
            .begin_read("authorization_evidence_certification")?;
        let installed = self
            .memory
            .store
            .read_published_card_evidence(&token, scope, now)
            .map_err(|error| certified_memory_error("authorization_evidence_certification", error))?
            .ok_or_else(|| {
                PolicyError::Repository("certified_memory.scope_evidence_missing".to_owned())
            })?;
        if !Arc::ptr_eq(&installed, &evidence) {
            return Err(PolicyError::Repository(
                "certified_memory.scope_evidence_mismatch".to_owned(),
            ));
        }
        let certified = self.authority.certify_authorization_evidence(
            proof.clone(),
            evidence,
            scope,
            now_seconds,
        )?;
        let certificate = certified.certificate().ok_or_else(|| {
            PolicyError::Repository("certified_memory.scope_certificate_missing".to_owned())
        })?;
        let certificate_hash = certificate.record_digest().map_err(|error| {
            PolicyError::Repository(format!(
                "certified_memory.scope_certificate_invalid;{error}"
            ))
        })?;
        if *certified.proof() != proof
            || !Arc::ptr_eq(&certified.evidence(), &installed)
            || proof.scope_certificate_hash.as_deref() != Some(certificate_hash.as_str())
        {
            return Err(PolicyError::Repository(
                "certified_memory.scope_certificate_mismatch".to_owned(),
            ));
        }
        self.validate_card_attestation(&proof)?;
        Ok(certified)
    }

    async fn load_published_card_authorization(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<Arc<PublishedCardAuthorization>>, PolicyError> {
        self.memory.load_published_card_authorization(scope).await
    }

    async fn load_org_authorization(
        &self,
        ctx: &PolicyContext,
    ) -> Result<OrgAuthorityRead, PolicyError> {
        self.memory.load_org_authorization(ctx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certified_memory_authority::{
        CertifiedCardContext, CertifiedMemoryConfig, CertifiedMemoryCoverage,
        CertifiedMemoryCoverageContract, CertifiedMemorySnapshot, GlobalAdminStatus,
    };
    use astral_types::{
        AuthorizationAuthorityScope, CardEligibility, CertifiedAuthorizationState,
        PublishedAggregateManifestSummary, PublishedCardAuthorizationGate,
        PublishedEvidenceGateStatus, AUTHORIZATION_EDITION,
    };
    use ed25519_dalek::Signer as _;

    struct FakeAuthorizationFenceProvider {
        proof: AuthorizationFenceProof,
        read_error: Option<String>,
        certified: Result<CertifiedAuthorizationState, String>,
    }

    impl FakeAuthorizationFenceProvider {
        fn succeeds(
            proof: AuthorizationFenceProof,
            certified: Result<CertifiedAuthorizationState, String>,
        ) -> Self {
            Self {
                proof,
                read_error: None,
                certified,
            }
        }

        fn fails_to_read(proof: AuthorizationFenceProof, error: &str) -> Self {
            Self {
                proof,
                read_error: Some(error.to_owned()),
                certified: Err("test certifier unused".to_owned()),
            }
        }
    }

    #[async_trait::async_trait]
    impl AuthorizationFenceProvider for FakeAuthorizationFenceProvider {
        async fn read_authorization_fence(
            &self,
            _scope: &PublishedCardEvidenceScope,
            _request_nonce: &str,
        ) -> Result<AuthorizationFenceProof, PolicyError> {
            if let Some(error) = &self.read_error {
                return Err(PolicyError::Repository(error.clone()));
            }
            Ok(self.proof.clone())
        }

        async fn read_request_authorization_fence(
            &self,
            _context: &PolicyContext,
            _scope: &PublishedCardEvidenceScope,
            _request_nonce: &str,
        ) -> Result<AuthorizationFenceProof, PolicyError> {
            if let Some(error) = &self.read_error {
                return Err(PolicyError::Repository(error.clone()));
            }
            Ok(self.proof.clone())
        }

        fn certify_authorization_evidence(
            &self,
            _proof: AuthorizationFenceProof,
            _evidence: Arc<PublishedCardAuthorization>,
            _scope: &PublishedCardEvidenceScope,
            _now_seconds: i64,
        ) -> Result<CertifiedAuthorizationState, PolicyError> {
            self.certified.clone().map_err(PolicyError::Repository)
        }
    }

    fn context() -> PolicyContext {
        PolicyContext::builder()
            .user_id(Some(7))
            .identity_card_id(Some(8))
            .card_id(Some(9))
            .tenant_id(Some(10))
            .domain_id(Some(11))
            .action("read".to_owned())
            .build()
    }

    fn evidence_scope() -> PublishedCardEvidenceScope {
        PublishedCardEvidenceScope {
            tenant_id: 10,
            card_id: 9,
            user_filter: Some(7),
            domain: astral_types::DomainScopeRequirement::ExactlySome(11),
        }
    }

    fn serving_store(snapshot_hash: String) -> Arc<CertifiedMemoryStore> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let mut snapshot =
            CertifiedMemorySnapshot::empty(1, now, now + 60, CertifiedMemoryCoverage::Complete)
                .expect("snapshot");
        snapshot
            .attach_attestation(
                crate::certified_memory_authority::CertifiedMemoryAttestation {
                    authority_term: 1,
                    global_fence_sequence: 1,
                    key_epoch: 1,
                    scope_generation: 1,
                    revoke_watermark: 0,
                    snapshot_hash,
                    issued_at_unix: now,
                    expires_at_unix: now + 60,
                },
            )
            .expect("attestation");
        snapshot
            .set_coverage_contract(CertifiedMemoryCoverageContract::complete())
            .expect("coverage contract");
        snapshot
            .insert_card_context(
                CardContextKey {
                    user_id: 7,
                    identity_card_id: 8,
                    user_card_id: 9,
                },
                CertifiedCardContext {
                    user_id: 7,
                    eligibility: CardEligibility {
                        identity_card_id: 8,
                        user_card_id: 9,
                        user_card_tenant_id: 10,
                        user_card_domain_id: 11,
                        effective_expiry: None,
                    },
                },
            )
            .expect("card context");
        snapshot
            .insert_global_admin(7, GlobalAdminStatus::Active)
            .expect("global admin");

        let store = Arc::new(CertifiedMemoryStore::new(
            CertifiedMemoryConfig::new(16, 64 * 1024, 60).expect("config"),
        ));
        let generation = snapshot.generation();
        store
            .install_coordinated(Arc::new(snapshot), now)
            .expect("install snapshot");
        store
            .mark_serving_coordinated(generation, now)
            .expect("serve snapshot");
        store
    }

    fn published_evidence() -> Arc<PublishedCardAuthorization> {
        Arc::new(PublishedCardAuthorization {
            tenant_id: 10,
            card_id: 9,
            read_unix_seconds: 1_700_000_000,
            gate: PublishedCardAuthorizationGate {
                status: PublishedEvidenceGateStatus::Ready,
                aggregate_manifest_count: 1,
                verified_record_count: 0,
                effective_grant_count: 0,
                not_in_effective_count: 0,
                equivalent_duplicate_collapsed_count: 0,
            },
            manifests: vec![PublishedAggregateManifestSummary {
                seal: astral_types::PublicationSeal::from_unix_seconds(1_700_000_000)
                    .expect("publication seal"),
                tenant_id: 10,
                card_id: 9,
                aggregate_type: "USER_CARD".to_owned(),
                aggregate_id: 9,
                manifest_id: 1,
                generation: 1,
                source_generation: 1,
                projected_generation: 1,
                revoke_fence: 0,
                cas_version: 1,
                semantic_hash_hex: "a".repeat(64),
                dependency_hash_hex: "b".repeat(64),
                manifest_digest_hex: "c".repeat(64),
                compiler_version: astral_types::AUTHORIZATION_COMPILER_VERSION.to_owned(),
                event_id: "event-1".to_owned(),
                operation_id: "operation-1".to_owned(),
                parent_manifest_id: None,
                segment_count: 1,
                declared_grant_row_count: 0,
            }],
            records: Vec::new(),
            effective_grants: Vec::new(),
        })
    }

    fn signed_proof(
        scope: &PublishedCardEvidenceScope,
        snapshot_hash: String,
        global_fence_sequence: u64,
    ) -> (AuthorizationFenceProof, ed25519_dalek::SigningKey) {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut proof = AuthorizationFenceProof {
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "authority-test".to_owned(),
            authority_term: 1,
            global_fence_sequence,
            scope: AuthorizationAuthorityScope::from_evidence_scope(scope),
            scope_generation: 1,
            revoke_watermark: 0,
            snapshot_hash,
            parent_hash: None,
            operation_id: "operation-test".to_owned(),
            event_id: "event-test".to_owned(),
            key_id: "key-test".to_owned(),
            key_epoch: 1,
            issued_at: now - 1,
            not_before: now - 1,
            expires_at: now + 60,
            request_nonce: "request-nonce".to_owned(),
            request_binding_digest: None,
            scope_certificate_hash: None,
            proof_id: "proof-test".to_owned(),
            signature: String::new(),
        };
        proof.signature = hex::encode(signing_key.sign(&proof.signing_bytes().unwrap()).to_bytes());
        (proof, signing_key)
    }

    struct CardProvider {
        proof: AuthorizationFenceProof,
        certificate: Option<astral_types::AuthorityScopePublicationCertificate>,
        key: ed25519_dalek::SigningKey,
    }

    #[async_trait::async_trait]
    impl AuthorizationFenceProvider for CardProvider {
        async fn read_authorization_fence(
            &self,
            _scope: &PublishedCardEvidenceScope,
            _nonce: &str,
        ) -> Result<AuthorizationFenceProof, PolicyError> {
            Err(PolicyError::Repository("scope-only read disabled".into()))
        }

        async fn read_request_authorization_fence(
            &self,
            _context: &PolicyContext,
            _scope: &PublishedCardEvidenceScope,
            nonce: &str,
        ) -> Result<AuthorizationFenceProof, PolicyError> {
            let mut proof = self.proof.clone();
            proof.request_nonce = nonce.to_owned();
            proof.proof_id = format!("proof-{nonce}");
            proof.signature =
                hex::encode(self.key.sign(&proof.signing_bytes().unwrap()).to_bytes());
            Ok(proof)
        }

        fn certify_authorization_evidence(
            &self,
            proof: AuthorizationFenceProof,
            evidence: Arc<PublishedCardAuthorization>,
            scope: &PublishedCardEvidenceScope,
            now: i64,
        ) -> Result<CertifiedAuthorizationState, PolicyError> {
            let cert = self
                .certificate
                .clone()
                .ok_or_else(|| PolicyError::Repository("missing certificate".into()))?;
            CertifiedAuthorizationState::new_with_certificate(
                proof,
                evidence,
                cert,
                &self.key.verifying_key(),
                &self.key.verifying_key(),
                now,
                scope,
            )
            .map_err(|error| PolicyError::Repository(error.to_string()))
        }
    }

    fn card_fixture(
        root_mismatch: bool,
    ) -> (Arc<CertifiedMemoryStore>, CardProvider, PolicyContext) {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let scope = evidence_scope();
        let evidence = published_evidence();
        let context = PolicyContext::builder()
            .principal_kind(Some("PLATFORM_USER".into()))
            .user_id(Some(7))
            .identity_card_id(Some(8))
            .card_id(Some(9))
            .tenant_id(Some(10))
            .domain_id(Some(11))
            .resource(Some("resource".into()))
            .action("read".into())
            .request_fingerprint(Some("a".repeat(64)))
            .request_operation_id(Some("operation-test".into()))
            .resource_ownership_scope(astral_types::ResourceOwnershipScope::TenantScoped)
            .build();
        let (mut proof, key) = signed_proof(
            &scope,
            AuthorizationFenceProof::evidence_content_hash(&evidence).unwrap(),
            1,
        );
        proof.request_binding_digest =
            Some(astral_types::authorization_request_digest(&context).unwrap());
        let mut certificate = astral_types::AuthorityScopePublicationCertificate {
            protocol_version: astral_types::AUTHORITY_PROTOCOL_VERSION,
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: proof.authority_id.clone(),
            authority_term: 1,
            global_fence_sequence: 1,
            certificate_id: "certificate".into(),
            intent_digest: "11".repeat(32),
            reservation_id: "reservation".into(),
            operation_id: "publication".into(),
            event_id: "publication-event".into(),
            scope: astral_types::AuthorityProtocolScope::Card(proof.scope.clone())
                .canonical_card_publication_scope()
                .unwrap(),
            approved_request_digest: "22".repeat(32),
            before_image_digest: None,
            after_image_digest: "33".repeat(32),
            source_commit_digest: "44".repeat(32),
            source_outcome_digest: "55".repeat(32),
            completion_digest: "00".repeat(32),
            snapshot_hash: proof.snapshot_hash.clone(),
            parent_certificate_hash: None,
            manifests: evidence
                .manifests
                .iter()
                .map(|m| astral_types::AuthorityManifestIdentity {
                    aggregate_type: m.aggregate_type.clone(),
                    aggregate_id: m.aggregate_id,
                    manifest_digest_hex: m.manifest_digest_hex.clone(),
                    dependency_hash_hex: m.dependency_hash_hex.clone(),
                    semantic_hash_hex: m.semantic_hash_hex.clone(),
                    generation: m.generation,
                    revoke_fence: m.revoke_fence,
                    event_id: m.event_id.clone(),
                    operation_id: m.operation_id.clone(),
                })
                .collect(),
            key_id: proof.key_id.clone(),
            key_epoch: 1,
            issued_at: now,
            not_before: now,
            expires_at: None,
            certificate_nonce: "certificate-nonce".into(),
            signature: String::new(),
        };
        certificate.completion_digest = certificate.recompute_completion_digest().unwrap();
        certificate.sign(&key).unwrap();
        proof.scope_certificate_hash = Some(certificate.record_digest().unwrap());
        let mut snapshot =
            CertifiedMemorySnapshot::empty(1, now, now + 60, CertifiedMemoryCoverage::Complete)
                .unwrap();
        snapshot
            .set_coverage_contract(CertifiedMemoryCoverageContract::complete())
            .unwrap();
        snapshot.insert_published_card(scope, evidence).unwrap();
        let digest = snapshot.content_digest().unwrap();
        snapshot
            .attach_attestation(
                crate::certified_memory_authority::CertifiedMemoryAttestation {
                    authority_term: 1,
                    global_fence_sequence: 1,
                    key_epoch: 1,
                    scope_generation: 1,
                    revoke_watermark: 0,
                    snapshot_hash: if root_mismatch {
                        "ff".repeat(32)
                    } else {
                        digest
                    },
                    issued_at_unix: now,
                    expires_at_unix: now + 60,
                },
            )
            .unwrap();
        let store = Arc::new(CertifiedMemoryStore::new(
            CertifiedMemoryConfig::new(16, 64 * 1024, 60).unwrap(),
        ));
        store.install_coordinated(Arc::new(snapshot), now).unwrap();
        store.mark_serving_coordinated(1, now).unwrap();
        (
            store,
            CardProvider {
                proof,
                certificate: Some(certificate),
                key,
            },
            context,
        )
    }

    #[test]
    fn runtime_invalidation_closes_existing_certified_tokens() {
        let store = serving_store("0".repeat(64));
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let token = store.begin_read(now).unwrap();
        crate::authorization_read_surface::invalidate_certified_store(&store);
        assert!(store.validate_read_token(&token, now).is_err());
        assert!(store.begin_read(now).is_err());
    }

    #[test]
    fn pure_ownership_rejects_invalidated_request_token() {
        let store = serving_store("0".repeat(64));
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let token = store.begin_read(now).unwrap();
        let request = crate::CertifiedOwnershipRequest {
            resource: "authorization".to_owned(),
            path: "/stats".to_owned(),
            method: "GET".to_owned(),
            query_target_id: None,
            actor_card_id: None,
            actor_user_id: None,
            now_unix: now,
        };
        assert!(
            crate::resolve_resource_ownership_certified_with_token(&store, &request, &token)
                .is_ok()
        );
        store.mark_stale().unwrap();
        assert_eq!(
            crate::resolve_resource_ownership_certified_with_token(&store, &request, &token),
            Err("resource_ownership.certified_memory_unavailable")
        );
    }

    #[tokio::test]
    async fn unbound_repositories_do_not_acquire_new_tokens() {
        let store = serving_store("0".repeat(64));
        let rules = CertifiedMemoryRuleRepository::new(Arc::clone(&store));
        let sod = CertifiedMemorySodRepository::new(store);
        assert!(rules.ensure_current().is_err());
        assert!(!rules.positive_authorization_ready());
        assert!(rules.check_card_active(&context()).await.is_err());
        assert!(sod.load_policy_snapshot().is_err());
    }

    #[tokio::test]
    async fn sod_read_set_missing_evidence_fails_closed_without_refill() {
        let store = serving_store("0".repeat(64));
        let token = store
            .begin_read(OffsetDateTime::now_utc().unix_timestamp())
            .unwrap();
        let repository = CertifiedMemorySodRepository::with_read_token(store, token);
        assert!(matches!(
            repository.load_read_set(&evidence_scope()),
            Err(PolicyError::Repository(message))
                if message == "certified_memory.sod_evidence_missing"
        ));
    }

    #[tokio::test]
    async fn reads_only_certified_memory_and_preserves_miss_semantics() {
        let store = serving_store("0".repeat(64));
        let token = store
            .begin_read(OffsetDateTime::now_utc().unix_timestamp())
            .unwrap();
        let repository = CertifiedMemoryRuleRepository::with_read_token(store, token);
        assert!(repository
            .check_card_active(&context())
            .await
            .expect("card read"));
        assert!(repository
            .is_active_global_admin(7)
            .await
            .expect("admin read"));
        assert!(!repository
            .is_active_global_admin(99)
            .await
            .expect("admin miss"));
        assert!(repository
            .load_published_card_authorization(&PublishedCardEvidenceScope {
                tenant_id: 10,
                card_id: 9,
                user_filter: Some(7),
                domain: astral_types::DomainScopeRequirement::ExactlySome(11),
            })
            .await
            .expect("published read")
            .is_none());
        assert!(matches!(
            repository.load_org_authorization(&context()).await,
            Ok(OrgAuthorityRead::Pending { code })
                if code == "org_scope.pending.certified_memory_miss"
        ));
    }

    #[tokio::test]
    async fn non_serving_reads_fail_closed_and_proofs_are_unsupported() {
        let store = Arc::new(CertifiedMemoryStore::new(CertifiedMemoryConfig::default()));
        let repository = CertifiedMemoryRuleRepository::new(store);
        assert!(!repository.positive_authorization_ready());
        assert!(matches!(
            repository.check_card_active(&context()).await,
            Err(PolicyError::Repository(message))
                if message == "certified_memory.check_card_active.request_token_missing"
        ));

        let scope = PublishedCardEvidenceScope {
            tenant_id: 10,
            card_id: 9,
            user_filter: Some(7),
            domain: astral_types::DomainScopeRequirement::ExactlySome(11),
        };
        assert_eq!(
            repository.published_evidence_read_mode(),
            PublishedEvidenceReadMode::CertifiedMemory
        );
        assert!(matches!(
            repository.read_authorization_fence(&scope, "nonce").await,
            Err(PolicyError::Repository(message))
                if message == "certified_memory.authorization_fence_read_unsupported"
        ));
    }

    #[tokio::test]
    async fn scope_only_provider_fence_is_rejected_before_positive_authorization() {
        let hash = "0".repeat(64);
        let scope = evidence_scope();
        let (proof, _) = signed_proof(&scope, hash.clone(), 1);
        let provider = FakeAuthorizationFenceProvider::succeeds(
            proof,
            Err("scope-only certifier must not be used".to_owned()),
        );
        let store = serving_store(hash);
        let token = store
            .begin_read(OffsetDateTime::now_utc().unix_timestamp())
            .unwrap();
        let repository =
            CertifiedMemoryProofRepository::with_read_token(store, Arc::new(provider), token);
        assert!(matches!(
            repository
                .read_authorization_fence(&scope, "request-nonce")
                .await,
            Err(PolicyError::Repository(message))
                if message == "certified_memory.authorization_fence_read_unsupported"
        ));
    }

    #[tokio::test]
    async fn scope_only_certification_is_rejected_even_with_matching_content() {
        let scope = evidence_scope();
        let evidence = published_evidence();
        let snapshot_hash = AuthorizationFenceProof::evidence_content_hash(evidence.as_ref())
            .expect("evidence hash");
        let (proof, signing_key) = signed_proof(&scope, snapshot_hash.clone(), 1);
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let certified = CertifiedAuthorizationState::new(
            proof.clone(),
            Arc::clone(&evidence),
            &signing_key.verifying_key(),
            now,
            &scope,
        )
        .expect("certified state");
        let store = serving_store(snapshot_hash);
        let token = store
            .begin_read(OffsetDateTime::now_utc().unix_timestamp())
            .unwrap();
        let repository = CertifiedMemoryProofRepository::with_read_token(
            store,
            Arc::new(FakeAuthorizationFenceProvider::succeeds(
                proof.clone(),
                Ok(certified),
            )),
            token,
        );

        assert!(matches!(
            repository
                .read_authorization_fence(&scope, "request-nonce")
                .await,
            Err(PolicyError::Repository(message))
                if message == "certified_memory.authorization_fence_read_unsupported"
        ));
        assert!(repository
            .certify_authorization_evidence(proof, evidence, &scope, now)
            .is_err());
    }

    #[tokio::test]
    async fn card_f0_f1_bind_distinct_root_and_scope_certificate() {
        let (store, provider, context) = card_fixture(false);
        let token = store
            .begin_read(OffsetDateTime::now_utc().unix_timestamp())
            .unwrap();
        assert_ne!(
            token.attestation().unwrap().snapshot_hash,
            provider.proof.snapshot_hash
        );
        let repository =
            CertifiedMemoryProofRepository::with_read_token(store, Arc::new(provider), token);
        let scope = evidence_scope();
        let mut proofs = Vec::new();
        for nonce in ["f0", "f1"] {
            let proof = repository
                .read_request_authorization_fence(&context, &scope, nonce)
                .await
                .unwrap();
            let evidence = repository
                .load_published_card_authorization(&scope)
                .await
                .unwrap()
                .unwrap();
            let certified = repository
                .certify_authorization_evidence(
                    proof.clone(),
                    evidence,
                    &scope,
                    OffsetDateTime::now_utc().unix_timestamp(),
                )
                .unwrap();
            assert!(certified.certificate().is_some());
            proofs.push(proof);
        }
        assert_ne!(proofs[0].request_nonce, proofs[1].request_nonce);
        assert_ne!(proofs[0].proof_id, proofs[1].proof_id);
        proofs[0].same_frontier_as(&proofs[1]).unwrap();
        for field in ["certificate", "key_id", "binding", "generation", "revoke"] {
            let mut changed = proofs[1].clone();
            match field {
                "certificate" => changed.scope_certificate_hash = Some("ee".repeat(32)),
                "key_id" => changed.key_id = "other-key".into(),
                "binding" => changed.request_binding_digest = Some("ee".repeat(32)),
                "generation" => changed.scope_generation += 1,
                "revoke" => changed.revoke_watermark = 1,
                _ => unreachable!(),
            }
            assert!(proofs[0].same_frontier_as(&changed).is_err(), "{field}");
        }
    }

    #[tokio::test]
    async fn card_proof_rejects_root_frontier_scope_and_certificate_drift() {
        for failure in [
            "root",
            "term",
            "fence",
            "key",
            "generation",
            "revoke",
            "hash",
            "certificate",
            "dependency",
            "binding",
            "missing",
        ] {
            let (store, mut provider, context) = card_fixture(failure == "root");
            match failure {
                "term" => provider.proof.authority_term += 1,
                "fence" => provider.proof.global_fence_sequence += 1,
                "key" => provider.proof.key_epoch += 1,
                "generation" => provider.proof.scope_generation += 1,
                "revoke" => provider.proof.revoke_watermark = 1,
                "hash" => provider.proof.snapshot_hash = "aa".repeat(32),
                "certificate" => provider.proof.scope_certificate_hash = Some("ee".repeat(32)),
                "dependency" => {
                    let cert = provider.certificate.as_mut().unwrap();
                    cert.manifests[0].dependency_hash_hex = "ee".repeat(32);
                    cert.completion_digest = cert.recompute_completion_digest().unwrap();
                    cert.sign(&provider.key).unwrap();
                    provider.proof.scope_certificate_hash = Some(cert.record_digest().unwrap());
                }
                "binding" => provider.proof.request_binding_digest = Some("ee".repeat(32)),
                "missing" => provider.certificate = None,
                _ => {}
            }
            let token = store
                .begin_read(OffsetDateTime::now_utc().unix_timestamp())
                .unwrap();
            let repository =
                CertifiedMemoryProofRepository::with_read_token(store, Arc::new(provider), token);
            let scope = evidence_scope();
            let result = match repository
                .read_request_authorization_fence(&context, &scope, "f0")
                .await
            {
                Ok(proof) => {
                    let evidence = repository
                        .load_published_card_authorization(&scope)
                        .await
                        .unwrap()
                        .unwrap();
                    repository
                        .certify_authorization_evidence(
                            proof,
                            evidence,
                            &scope,
                            OffsetDateTime::now_utc().unix_timestamp(),
                        )
                        .map(|_| ())
                }
                Err(error) => Err(error),
            };
            assert!(result.is_err(), "{failure} must fail closed");
        }
    }

    #[tokio::test]
    async fn provider_failure_is_not_converted_to_memory_miss() {
        let hash = "0".repeat(64);
        let scope = evidence_scope();
        let (proof, _) = signed_proof(&scope, hash.clone(), 1);
        let store = serving_store(hash);
        let token = store
            .begin_read(OffsetDateTime::now_utc().unix_timestamp())
            .unwrap();
        let repository = CertifiedMemoryProofRepository::with_read_token(
            store,
            Arc::new(FakeAuthorizationFenceProvider::fails_to_read(
                proof,
                "authority timeout",
            )),
            token,
        );
        assert!(matches!(
            repository
                .read_request_authorization_fence(&context(), &scope, "request-nonce")
                .await,
            Err(PolicyError::Repository(message)) if message == "authority timeout"
        ));
    }

    #[tokio::test]
    async fn non_serving_and_expired_memory_fail_closed() {
        let scope = evidence_scope();
        let (proof, _) = signed_proof(&scope, "0".repeat(64), 1);
        let provider = Arc::new(FakeAuthorizationFenceProvider::fails_to_read(
            proof,
            "unused authority error",
        ));
        let cold_repository = CertifiedMemoryProofRepository::new(
            Arc::new(CertifiedMemoryStore::new(CertifiedMemoryConfig::default())),
            Arc::clone(&provider),
        );
        assert!(!cold_repository.positive_authorization_ready());
        assert!(matches!(
            cold_repository.check_card_active(&context()).await,
            Err(PolicyError::Repository(message))
                if message == "certified_memory.check_card_active.request_token_missing"
        ));

        let stale_store = serving_store("0".repeat(64));
        let stale_token = stale_store
            .begin_read(OffsetDateTime::now_utc().unix_timestamp())
            .unwrap();
        stale_store.mark_stale().expect("mark memory stale");
        let stale_repository = CertifiedMemoryProofRepository::with_read_token(
            stale_store,
            Arc::clone(&provider),
            stale_token,
        );
        assert!(matches!(
            stale_repository.check_card_active(&context()).await,
            Err(PolicyError::Repository(message))
                if message == "certified_memory.check_card_active_failed;not_serving.stale"
        ));
    }

    #[tokio::test]
    async fn card_context_tenant_and_domain_are_checked_after_memory_read() {
        let store = serving_store("0".repeat(64));
        let token = store
            .begin_read(OffsetDateTime::now_utc().unix_timestamp())
            .unwrap();
        let repository = CertifiedMemoryRuleRepository::with_read_token(store, token);
        let mut mismatched = context();
        mismatched.tenant_id = Some(12);
        assert!(!repository
            .check_card_active(&mismatched)
            .await
            .expect("mismatched card read"));
    }
}
