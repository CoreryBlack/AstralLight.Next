//! memory—v1: the injected governance commit boundary.
//!
//! HTTP handlers construct a fully bound candidate and hand it to this port. The
//! port owns operation reconciliation, audit durability, journal publication,
//! root CAS and any asynchronous database work. TrustGraph defines the seam so
//! the single-node composition can inject its owner without reversing the crate
//! dependency direction.

use astral_authorization_root::memory_v1_root::{ManagementMutationV2, RootMetadata};
use astral_types::memory_v1_deny_observation::MemoryV1DenyObservation;
use astral_types::AstralError;

use crate::service::memory_v1_mutation_coordinator::{
    CoordinatorError, DenyResponse, MutationAuditCandidate,
};

/// The injected DENY proof boundary.
///
/// The permission middleware hands one complete evaluator observation to this
/// port. The port owns the durable DENY audit record, the journal append and
/// the two independent proofs; it may only return
/// [`DenyResponse::Forbidden`] after both proofs are verified. The default is
/// fail-closed [`DenyResponse::ServiceUnavailable`].
pub trait MemoryV1DenyProofPort: Send + Sync {
    fn prove_deny(&self, observation: MemoryV1DenyObservation)
        -> Result<DenyResponse, AstralError>;
}

/// Safe default: no owner installed, every DENY stays a fail-closed 503.
#[derive(Debug, Default)]
pub struct FailClosedMemoryV1DenyProofPort;

impl MemoryV1DenyProofPort for FailClosedMemoryV1DenyProofPort {
    fn prove_deny(
        &self,
        _observation: MemoryV1DenyObservation,
    ) -> Result<DenyResponse, AstralError> {
        Ok(DenyResponse::ServiceUnavailable)
    }
}

/// The exact request facts that survive the HTTP/admission boundary.
///
/// `request_fingerprint` remains the canonical lowercase representation produced
/// by the request-binding middleware. `audit` is mandatory and its operation,
/// root observation, actor, target, tenant, time and mutation summary are checked
/// before the durable owner receives this request. This value-level validation
/// does not prove that the supplied facts are true or persisted.
#[derive(Clone, Debug)]
pub struct MemoryV1GovernanceCommitRequest {
    pub operation_id: String,
    pub request_fingerprint: String,
    pub root: RootMetadata,
    pub actor: [u8; 16],
    pub target: [u8; 16],
    pub target_tenant: [u8; 16],
    pub target_owner: Option<[u8; 16]>,
    pub trusted_time_unix_seconds: i64,
    pub mutation: ManagementMutationV2,
    pub audit: MutationAuditCandidate,
}

impl MemoryV1GovernanceCommitRequest {
    /// Validate canonical request identity and value-level audit bindings.
    pub fn validate(&self) -> Result<(), AstralError> {
        let fingerprint = decode_fingerprint(&self.request_fingerprint)?;
        self.audit
            .validate_governance_binding(
                &self.operation_id,
                &fingerprint,
                self.root,
                self.actor,
                self.target,
                self.target_tenant,
                self.trusted_time_unix_seconds,
                &self.mutation,
            )
            .map_err(map_audit_binding_error)
    }
}

fn decode_fingerprint(value: &str) -> Result<[u8; 32], AstralError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AstralError::Pending(
            "governance request fingerprint is invalid".into(),
        ));
    }
    hex::decode(value)
        .map_err(|_| AstralError::Pending("governance request fingerprint is invalid".into()))?
        .try_into()
        .map_err(|_| AstralError::Pending("governance request fingerprint is invalid".into()))
}

fn map_audit_binding_error(error: CoordinatorError) -> AstralError {
    AstralError::Pending(format!("governance audit candidate is not bound: {error}"))
}

/// The proof-backed result exposed to the HTTP response adapter.
///
/// A port implementation must return this only after its local durable-prefix
/// and root-publication proof chain is closed. The response type itself does not
/// claim MySQL completion under the A/A1 persistence profile.
#[derive(Clone, Debug)]
pub struct MemoryV1GovernanceCommitResponse {
    pub operation_id: String,
    pub root: RootMetadata,
}

/// The sole TrustGraph entry point for memory-v1 governance mutations.
pub trait MemoryV1GovernanceCommitPort: Send + Sync {
    fn commit(
        &self,
        request: MemoryV1GovernanceCommitRequest,
    ) -> Result<MemoryV1GovernanceCommitResponse, AstralError>;
}

/// Safe default for offline, test and legacy compositions.
///
/// It deliberately performs no root, journal, database or audit operation. A
/// missing concrete owner is therefore an observable PENDING result rather than
/// an implicit fallback to a legacy repository.
#[derive(Debug, Default)]
pub struct FailClosedMemoryV1GovernanceCommitPort;

impl MemoryV1GovernanceCommitPort for FailClosedMemoryV1GovernanceCommitPort {
    fn commit(
        &self,
        request: MemoryV1GovernanceCommitRequest,
    ) -> Result<MemoryV1GovernanceCommitResponse, AstralError> {
        request.validate()?;
        Err(AstralError::Pending(
            "governance audit and operation reconciliation unavailable".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_authorization_root::memory_v1_db_rows::UserCardStatus;

    #[test]
    fn fail_closed_owner_rejects_an_unbound_audit_candidate_before_pending() {
        let port = FailClosedMemoryV1GovernanceCommitPort;
        // memory—v1: A complete but deliberately unbound T2 candidate (wrong
        // summary/operation binding) must fail value-level validation before the
        // durable owner would ever see the request.
        let mutation = ManagementMutationV2::UserCardStatus {
            user_card_id: [2; 16],
            status: UserCardStatus::Disabled,
        };
        let operation =
            astral_types::memory_v1_audit::MemoryV1AuditOperation::new("op", [0; 32]).unwrap();
        let context = astral_types::memory_v1_audit::MemoryV1AuditContext::new(
            astral_types::memory_v1_audit::MemoryV1AuditActor::new(
                astral_types::memory_v1::MemoryId::from_bytes([1; 16]),
                astral_types::memory_v1::MemoryId::from_bytes([4; 16]),
            ),
            astral_types::memory_v1_audit::MemoryV1AuditTime::new(1).unwrap(),
            astral_types::memory_v1_audit::MemoryV1AuditAction::new("user_card", "disable")
                .unwrap(),
            "GOVERNANCE_USER_CARD_DISABLE",
            operation,
            astral_types::memory_v1_audit::MemoryV1AuditRootObservation::new(
                astral_types::memory_v1_audit::MemoryV1AuditRootVersion::new(
                    astral_types::memory_v1::MemoryId::from_bytes(
                        *uuid::Uuid::from_bytes([1; 16]).as_bytes(),
                    ),
                    7,
                ),
                [7; 32],
                astral_types::memory_v1_audit::MemoryV1AuditRootStatus::Serving,
            ),
        )
        .unwrap();
        let change = astral_types::memory_v1_audit::MemoryV1AuditChange::new(
            Some(astral_types::memory_v1::MemoryId::from_bytes([1; 16])),
            Some(
                astral_types::memory_v1_audit::MemoryV1AuditObject::UserCard(
                    astral_types::memory_v1::MemoryId::from_bytes([2; 16]),
                ),
            ),
            Some(astral_types::memory_v1_audit::MemoryV1AuditObject::Tenant(
                astral_types::memory_v1::MemoryId::from_bytes([3; 16]),
            )),
            Some(
                astral_types::memory_v1_audit::MemoryV1AuditChangeSummary::new(b"unbound summary")
                    .unwrap(),
            ),
            Some(
                astral_types::memory_v1_audit::MemoryV1AuditObjectState::UserCard(
                    astral_types::memory_v1_audit::MemoryV1AuditCardState::Active,
                ),
            ),
            Some(
                astral_types::memory_v1_audit::MemoryV1AuditObjectState::UserCard(
                    astral_types::memory_v1_audit::MemoryV1AuditCardState::Disabled,
                ),
            ),
            Some(astral_types::memory_v1_audit::MemoryV1AuditConfirmations::not_applicable()),
            Some(
                astral_types::memory_v1_audit::MemoryV1AuditRootVersion::new(
                    astral_types::memory_v1::MemoryId::from_bytes(
                        *uuid::Uuid::from_bytes([1; 16]).as_bytes(),
                    ),
                    7,
                ),
            ),
            Some(
                astral_types::memory_v1_audit::MemoryV1AuditRootVersion::new(
                    astral_types::memory_v1::MemoryId::from_bytes(
                        *uuid::Uuid::from_bytes([1; 16]).as_bytes(),
                    ),
                    8,
                ),
            ),
            astral_types::memory_v1_audit::MemoryV1AuditSource::Ordinary,
        );
        let audit = crate::service::memory_v1_mutation_coordinator::MutationAuditCandidate::Single(
            astral_types::memory_v1_audit::MemoryV1AuditT2SingleChangeCandidate::try_from(
                astral_types::memory_v1_audit::MemoryV1AuditEvent::change(
                    context,
                    astral_types::memory_v1_audit::MemoryV1AuditDecisionInput::Allow,
                    change,
                )
                .unwrap(),
            )
            .unwrap(),
        );
        let result = port.commit(MemoryV1GovernanceCommitRequest {
            operation_id: "op".into(),
            request_fingerprint: "00".repeat(32),
            root: RootMetadata {
                instance_id: astral_authorization_root::memory_v1_root::RootInstanceId::from_uuid(
                    uuid::Uuid::from_bytes([1; 16]),
                ),
                version: 7,
                digest: [7; 32],
                budget: astral_authorization_root::memory_v1_hamt::CandidateBudget {
                    max_table_rows: 1,
                    max_bindings_per_read: 1,
                },
                row_count: 1,
                status: astral_authorization_root::memory_v1_root::RootStatus::Serving,
            },
            actor: [1; 16],
            target: [2; 16],
            target_tenant: [3; 16],
            target_owner: Some([1; 16]),
            trusted_time_unix_seconds: 1,
            mutation,
            audit,
        });
        assert!(matches!(
            result,
            Err(AstralError::Pending(message)) if message.starts_with("governance audit candidate is not bound")
        ));
    }
}
