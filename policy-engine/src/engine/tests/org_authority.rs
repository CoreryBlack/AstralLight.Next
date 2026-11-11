use super::*;
use astral_types::{
    org_authority_evidence_hash, org_authority_evidence_scope, AuthorizationAuthorityScope,
    AuthorizationFenceProof, AUTHORIZATION_EDITION,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    MissingInitial,
    MissingFinal,
    ReusedProof,
    WrongNonce,
    Expired,
    WrongActor,
    FrontierDrift,
    TermDrift,
    KeyDrift,
    ScopeDrift,
    GenerationDrift,
    RevokeDrift,
    BindingDrift,
    CertificateMismatch,
    DependencyDrift,
    MissingCertificate,
    InitialEvidenceDrift,
    FinalEvidenceDrift,
    NotServing,
}

struct CertifiedOrgRepo {
    evidence: OrgAdmissionEvidence,
    fault: Fault,
    org_reads: AtomicUsize,
    proof_reads: AtomicUsize,
    nonces: Mutex<Vec<String>>,
    proofs: Mutex<Vec<AuthorizationFenceProof>>,
}

impl CertifiedOrgRepo {
    fn new(fault: Fault) -> Self {
        Self {
            evidence: org_gate_admission_evidence(),
            fault,
            org_reads: AtomicUsize::new(0),
            proof_reads: AtomicUsize::new(0),
            nonces: Mutex::new(Vec::new()),
            proofs: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl RuleRepository for CertifiedOrgRepo {
    async fn check_card_active(&self, _ctx: &PolicyContext) -> Result<bool, PolicyError> {
        Ok(true)
    }

    async fn is_active_global_admin(&self, _user_id: i64) -> Result<bool, PolicyError> {
        Ok(false)
    }

    async fn load_published_card_authorization(
        &self,
        _scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<std::sync::Arc<PublishedCardAuthorization>>, PolicyError> {
        panic!("managed ORG must never fall back to card evidence")
    }

    async fn load_org_authorization(
        &self,
        _ctx: &PolicyContext,
    ) -> Result<OrgAuthorityRead, PolicyError> {
        let read = self.org_reads.fetch_add(1, Ordering::SeqCst);
        let mut evidence = self.evidence.clone();
        if (self.fault == Fault::InitialEvidenceDrift && read >= 1)
            || (self.fault == Fault::FinalEvidenceDrift && read >= 3)
        {
            evidence.membership.revision += 1;
        }
        Ok(OrgAuthorityRead::Ready(Box::new(evidence)))
    }

    fn published_evidence_read_mode(&self) -> PublishedEvidenceReadMode {
        PublishedEvidenceReadMode::CertifiedMemory
    }

    fn positive_authorization_ready(&self) -> bool {
        self.fault != Fault::NotServing
    }

    async fn read_org_authorization_fence(
        &self,
        ctx: &PolicyContext,
        evidence: &OrgAdmissionEvidence,
        nonce: &str,
    ) -> Result<AuthorizationFenceProof, PolicyError> {
        let read = self.proof_reads.fetch_add(1, Ordering::SeqCst);
        self.nonces.lock().unwrap().push(nonce.to_owned());
        if (self.fault == Fault::MissingInitial && read == 0)
            || (self.fault == Fault::MissingFinal && read == 1)
        {
            return Err(PolicyError::Repository("authority unavailable".to_owned()));
        }
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        // This trusted repository fixture tests scheduling/content checks. Signature
        // authentication is the production provider's responsibility.
        let mut proof = AuthorizationFenceProof {
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "org-test-authority".to_owned(),
            authority_term: 1,
            global_fence_sequence: 7,
            scope: AuthorizationAuthorityScope::from_evidence_scope(
                &org_authority_evidence_scope(ctx).unwrap(),
            ),
            scope_generation: evidence.publication.generation,
            revoke_watermark: evidence.publication.revoke_fence,
            snapshot_hash: org_authority_evidence_hash(evidence).unwrap(),
            parent_hash: None,
            operation_id: "org-publication".to_owned(),
            event_id: "org-publication-event".to_owned(),
            key_id: "org-test-key".to_owned(),
            key_epoch: 1,
            issued_at: now,
            not_before: now - 1,
            expires_at: now + 60,
            request_nonce: nonce.to_owned(),
            request_binding_digest: Some(astral_types::authorization_request_digest(ctx).unwrap()),
            scope_certificate_hash: Some("cd".repeat(32)),
            proof_id: format!("org-proof-{read}"),
            signature: "ab".repeat(64),
        };
        match self.fault {
            Fault::ReusedProof => proof.proof_id = "reused-org-proof".to_owned(),
            Fault::WrongNonce => proof.request_nonce = "unrequested-nonce".to_owned(),
            Fault::Expired => {
                proof.issued_at = now - 2;
                proof.not_before = now - 3;
                proof.expires_at = now - 1;
            }
            Fault::WrongActor => proof.scope.card_id += 1,
            Fault::FrontierDrift if read == 1 => proof.global_fence_sequence += 1,
            Fault::TermDrift if read == 1 => proof.authority_term += 1,
            Fault::KeyDrift if read == 1 => proof.key_epoch += 1,
            Fault::ScopeDrift if read == 1 => proof.scope.tenant_id += 1,
            Fault::GenerationDrift if read == 1 => proof.scope_generation += 1,
            Fault::RevokeDrift if read == 1 => proof.revoke_watermark += 1,
            Fault::BindingDrift if read == 1 => {
                proof.request_binding_digest = Some("ee".repeat(32))
            }
            Fault::CertificateMismatch if read == 1 => {
                proof.scope_certificate_hash = Some("ee".repeat(32))
            }
            Fault::DependencyDrift if read == 1 => proof.snapshot_hash = "dd".repeat(32),
            Fault::MissingCertificate if read == 1 => proof.scope_certificate_hash = None,
            _ => {}
        }
        self.proofs.lock().unwrap().push(proof.clone());
        Ok(proof)
    }
}

#[tokio::test]
async fn certified_org_uses_independent_fences_and_returns_final_admission() {
    let repo = CertifiedOrgRepo::new(Fault::None);
    let evaluation = PolicyEngine::new()
        .evaluate_with_admission(&org_gate_ctx(), &repo)
        .await;
    assert!(evaluation.decision.allowed, "{:?}", evaluation.decision);
    let admission = evaluation
        .admission()
        .expect("certified ORG ALLOW needs F1");
    assert_eq!(admission.proof_id(), "org-proof-1");
    let nonces = repo.nonces.lock().unwrap();
    assert_eq!(nonces.len(), 2);
    assert_ne!(nonces[0], nonces[1]);
    assert_eq!(admission.proof().request_nonce, nonces[1]);
    assert_ne!(admission.proof_id(), "org-proof-0");
    let proofs = repo.proofs.lock().unwrap();
    assert_eq!(proofs.len(), 2);
    assert_ne!(proofs[0].request_nonce, proofs[1].request_nonce);
    assert_ne!(proofs[0].proof_id, proofs[1].proof_id);
    proofs[0].same_frontier_as(&proofs[1]).unwrap();
    assert_eq!(repo.org_reads.load(Ordering::SeqCst), 4);
    assert!(admission.consume_once().is_ok());
    assert!(admission.consume_once().is_err());
}

#[tokio::test]
async fn certified_org_rejects_unavailable_replayed_or_changed_authority() {
    for fault in [
        Fault::MissingInitial,
        Fault::MissingFinal,
        Fault::ReusedProof,
        Fault::WrongNonce,
        Fault::Expired,
        Fault::WrongActor,
        Fault::FrontierDrift,
        Fault::TermDrift,
        Fault::KeyDrift,
        Fault::ScopeDrift,
        Fault::GenerationDrift,
        Fault::RevokeDrift,
        Fault::BindingDrift,
        Fault::CertificateMismatch,
        Fault::DependencyDrift,
        Fault::MissingCertificate,
        Fault::InitialEvidenceDrift,
        Fault::FinalEvidenceDrift,
        Fault::NotServing,
    ] {
        let repo = CertifiedOrgRepo::new(fault);
        let evaluation = PolicyEngine::new()
            .evaluate_with_admission(&org_gate_ctx(), &repo)
            .await;
        assert!(!evaluation.decision.allowed, "{:?}", evaluation.decision);
        assert_eq!(evaluation.decision.reason, "AUTHORIZATION_PENDING");
        assert!(
            evaluation.admission().is_none(),
            "DENY must discard capability"
        );
    }
}

#[tokio::test]
async fn org_content_identity_excludes_clock_and_binds_membership_and_publication() {
    let evidence = org_gate_admission_evidence();
    let original = org_authority_evidence_hash(&evidence).unwrap();
    let mut reread = evidence.clone();
    reread.checked_at_unix += 1;
    assert_eq!(original, org_authority_evidence_hash(&reread).unwrap());
    reread.membership.revision += 1;
    assert_ne!(original, org_authority_evidence_hash(&reread).unwrap());
    let mut changed_node = evidence;
    changed_node.node.operation_id = "different-approved-node-operation".to_owned();
    assert_ne!(
        original,
        org_authority_evidence_hash(&changed_node).unwrap()
    );
}
