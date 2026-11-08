//! Internal authority ingress/runtime port.
//!
//! This module deliberately wraps the existing durable issuer instead of
//! defining another authority state machine. It is an application boundary for
//! lease ingress, publication completion, proof consumption, and readback. The
//! issuer remains outside cloneable request state because it owns the protected
//! signing capability.

use async_trait::async_trait;

use astral_db::{IssuanceLeaseReconciliation, SqlxAuthorizationAuthorityIssuer};
use astral_types::{AuthorizationFenceProof, AuthorizationIssuanceLease, PolicyError};

/// Read-only observation returned by the durable issuer reconciliation API.
///
/// `Unknown` is terminal for the current attempt. Callers must reconcile by
/// stable lease identity before any new ingress or consumption attempt; this
/// wrapper never turns it into a retry instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityRuntimeDisposition {
    Pending,
    Ready,
    Consumed,
    Unknown,
}

impl AuthorityRuntimeDisposition {
    pub fn from_reconciliation(reconciliation: &IssuanceLeaseReconciliation) -> Self {
        match reconciliation {
            IssuanceLeaseReconciliation::Pending { .. } => Self::Pending,
            IssuanceLeaseReconciliation::Ready { .. } => Self::Ready,
            IssuanceLeaseReconciliation::Consumed { .. } => Self::Consumed,
            IssuanceLeaseReconciliation::Unknown { .. } => Self::Unknown,
        }
    }

    pub fn requires_readback_before_retry(self) -> bool {
        matches!(self, Self::Unknown)
    }

    pub fn permits_proof_consumption(self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// Internal authority ingress/issuance port.
///
/// The implementation delegates every operation to the existing issuer. In
/// particular, this port does not expose a signer, create a frontier, or add a
/// background retry loop. Deployment code must construct it only when the
/// protected issuer configuration is complete.
#[async_trait]
pub trait AuthorizationAuthorityPort: Send + Sync {
    async fn ingest_lease(&self, lease: AuthorizationIssuanceLease) -> Result<(), PolicyError>;

    async fn mark_lease_ready(&self, lease_id: &str) -> Result<(), PolicyError>;

    async fn consume_lease(&self, lease_id: &str) -> Result<AuthorizationFenceProof, PolicyError>;

    async fn reconcile_lease(
        &self,
        lease_id: &str,
    ) -> Result<IssuanceLeaseReconciliation, PolicyError>;
}

/// Non-cloneable owner of the protected authority issuer capability.
pub struct AuthorizationAuthorityRuntime {
    issuer: SqlxAuthorizationAuthorityIssuer,
}

impl AuthorizationAuthorityRuntime {
    pub fn new(issuer: SqlxAuthorizationAuthorityIssuer) -> Self {
        Self { issuer }
    }

    pub fn issuer(&self) -> &SqlxAuthorizationAuthorityIssuer {
        &self.issuer
    }
}

#[async_trait]
impl AuthorizationAuthorityPort for AuthorizationAuthorityRuntime {
    async fn ingest_lease(&self, lease: AuthorizationIssuanceLease) -> Result<(), PolicyError> {
        self.issuer.ingest_issuance_lease(&lease).await
    }

    async fn mark_lease_ready(&self, lease_id: &str) -> Result<(), PolicyError> {
        self.issuer.mark_issuance_lease_ready(lease_id).await
    }

    async fn consume_lease(&self, lease_id: &str) -> Result<AuthorizationFenceProof, PolicyError> {
        self.issuer.consume_issuance_lease(lease_id).await
    }

    async fn reconcile_lease(
        &self,
        lease_id: &str,
    ) -> Result<IssuanceLeaseReconciliation, PolicyError> {
        self.issuer.reconcile_issuance_lease(lease_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disposition_projects_existing_issuer_lifecycle_without_retrying_unknown() {
        assert_eq!(
            AuthorityRuntimeDisposition::from_reconciliation(
                &IssuanceLeaseReconciliation::Pending {
                    lease_id: "lease-1".into(),
                    request_nonce: "nonce-1".into(),
                },
            ),
            AuthorityRuntimeDisposition::Pending
        );
        assert_eq!(
            AuthorityRuntimeDisposition::from_reconciliation(&IssuanceLeaseReconciliation::Ready {
                lease_id: "lease-1".into(),
                request_nonce: "nonce-1".into(),
                completion_hash: "00".repeat(32),
                generation: 1,
                revoke_watermark: 0,
            },),
            AuthorityRuntimeDisposition::Ready
        );
        assert_eq!(
            AuthorityRuntimeDisposition::from_reconciliation(
                &IssuanceLeaseReconciliation::Unknown {
                    lease_id: "lease-1".into(),
                    reason: "commit result unknown".into(),
                },
            ),
            AuthorityRuntimeDisposition::Unknown
        );
        assert!(AuthorityRuntimeDisposition::Unknown.requires_readback_before_retry());
        assert!(!AuthorityRuntimeDisposition::Unknown.permits_proof_consumption());
        assert!(AuthorityRuntimeDisposition::Ready.permits_proof_consumption());
    }

    #[test]
    fn runtime_contract_does_not_expose_a_cloneable_signer_owner_or_retry_loop() {
        let source = include_str!("authorization_authority_runtime.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(production.contains("pub trait AuthorizationAuthorityPort"));
        assert!(production.contains("pub struct AuthorizationAuthorityRuntime"));
        assert!(!production.contains("impl Clone for AuthorizationAuthorityRuntime"));
        assert!(!production.contains("tokio::spawn"));
        assert!(!production.contains("interval("));
    }
}
