//! CertifiedMemory installation and readiness owner.
//!
//! This module owns only the lifecycle after durable materialization and an
//! authority response are available. It never creates a root, derives a family
//! completion, retries uncertain transport, or treats a local heartbeat as a
//! readiness proof.

use std::sync::Arc;

use astral_authority::client::{AuthorityClient, VerifiedCertifiedMemoryRoot};
use astral_types::authority_protocol::AuthorityCertifiedMemoryRootResponse;
use ed25519_dalek::VerifyingKey;
use thiserror::Error;

use crate::certified_memory_authority::CertifiedMemoryInvalidation;
use crate::certified_memory_authority::CertifiedMemorySnapshot;
use crate::certified_memory_coordinator::{
    CertifiedMemoryCoordinator, CertifiedMemoryCoordinatorError, CertifiedMemoryFamilyBundle,
    CertifiedMemoryRootObservation,
};
use crate::certified_memory_readiness::CertifiedMemoryReadinessCapability;
use crate::certified_memory_snapshot_builder::{
    CertifiedMemoryReadiness, CertifiedMemoryRuntimeState,
};

/// Installer lifecycle state, separate from listener/process liveness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertifiedMemoryInstallerStatus {
    Cold,
    Preparing,
    FenceSyncing,
    Serving,
    Pending,
    Unknown,
    Quarantined,
}

impl CertifiedMemoryInstallerStatus {
    pub const fn positive_reads_ready(self) -> bool {
        matches!(self, Self::Serving)
    }
}

/// The owner of the process-local certified-memory lifecycle.
#[derive(Debug)]
pub struct CertifiedMemoryInstaller {
    coordinator: Arc<CertifiedMemoryCoordinator>,
}

impl CertifiedMemoryInstaller {
    pub fn new(coordinator: Arc<CertifiedMemoryCoordinator>) -> Self {
        Self { coordinator }
    }

    pub fn coordinator(&self) -> Arc<CertifiedMemoryCoordinator> {
        Arc::clone(&self.coordinator)
    }

    pub fn status(&self) -> CertifiedMemoryInstallerStatus {
        match self.coordinator.state() {
            CertifiedMemoryRuntimeState::Cold => CertifiedMemoryInstallerStatus::Cold,
            CertifiedMemoryRuntimeState::Warming => CertifiedMemoryInstallerStatus::Preparing,
            CertifiedMemoryRuntimeState::FenceSyncing => {
                CertifiedMemoryInstallerStatus::FenceSyncing
            }
            CertifiedMemoryRuntimeState::Serving => CertifiedMemoryInstallerStatus::Serving,
            CertifiedMemoryRuntimeState::Pending => CertifiedMemoryInstallerStatus::Pending,
            CertifiedMemoryRuntimeState::Suspect => CertifiedMemoryInstallerStatus::Unknown,
            CertifiedMemoryRuntimeState::Quarantined => CertifiedMemoryInstallerStatus::Quarantined,
        }
    }

    pub fn readiness(&self, now_unix: i64) -> CertifiedMemoryReadiness {
        self.coordinator.readiness(now_unix)
    }

    /// Install a response that was verified by the authority client and whose
    /// signer key is explicitly supplied by the caller. The response's positive
    /// gate is checked independently from the local runtime gate.
    pub fn prepare_verified_response(
        &self,
        snapshot: Arc<CertifiedMemorySnapshot>,
        families: &CertifiedMemoryFamilyBundle,
        response: AuthorityCertifiedMemoryRootResponse,
        verifying_key: &VerifyingKey,
        now_unix: i64,
    ) -> Result<u64, CertifiedMemoryInstallerError> {
        if !response.read_gate.positive_reads_allowed {
            return Err(CertifiedMemoryInstallerError::AuthorityGateBlocked);
        }
        let root = CertifiedMemoryRootObservation::from_verified_root(
            response.root,
            verifying_key,
            now_unix,
        )?;
        self.coordinator
            .prepare(snapshot, families, root, now_unix)
            .map_err(Into::into)
    }

    /// Prepare from an online observation tied to the configured client and its
    /// chain-derived signer. Freshness and client provenance are rechecked here.
    pub fn prepare_client_verified_root(
        &self,
        snapshot: Arc<CertifiedMemorySnapshot>,
        families: &CertifiedMemoryFamilyBundle,
        client: &AuthorityClient,
        observation: &VerifiedCertifiedMemoryRoot,
        now_unix: i64,
    ) -> Result<u64, CertifiedMemoryInstallerError> {
        let root = CertifiedMemoryRootObservation::from_client_verified_root(
            client,
            observation,
            now_unix,
        )?;
        self.coordinator
            .prepare(snapshot, families, root, now_unix)
            .map_err(Into::into)
    }

    /// Open Serving only after independently owned worker, frontier and
    /// transport proofs are all explicit for the prepared generation.
    pub(crate) fn complete_serving(
        &self,
        generation: u64,
        readiness: &CertifiedMemoryReadinessCapability,
        now_unix: i64,
    ) -> Result<(), CertifiedMemoryInstallerError> {
        self.coordinator
            .complete_serving(generation, readiness, now_unix)
            .map_err(Into::into)
    }

    /// Any lost proof closes the positive read gate before reconciliation.
    pub fn invalidate(
        &self,
        invalidation: CertifiedMemoryInvalidation,
    ) -> Result<(), CertifiedMemoryInstallerError> {
        self.coordinator
            .invalidate(invalidation)
            .map_err(Into::into)
    }

    /// One authority-root read. The authority client itself performs exactly one
    /// HTTP attempt and reports uncertain transport as an unknown outcome.
    pub async fn read_current_root(
        &self,
        client: &AuthorityClient,
        expected_root_digest: Option<String>,
    ) -> Result<AuthorityCertifiedMemoryRootResponse, CertifiedMemoryInstallerError> {
        client
            .read_certified_memory_root(expected_root_digest)
            .await
            .map_err(|error| CertifiedMemoryInstallerError::Authority(error.to_string()))
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CertifiedMemoryInstallerError {
    #[error("authority root response did not permit positive reads")]
    AuthorityGateBlocked,
    #[error("authority client operation failed: {0}")]
    Authority(String),
    #[error("certified-memory coordinator rejected installation: {0}")]
    Coordinator(#[from] CertifiedMemoryCoordinatorError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certified_memory_authority::CertifiedMemoryConfig;
    use crate::certified_memory_coordinator::CertifiedMemoryCoordinator;
    use crate::certified_memory_snapshot_builder::CertifiedMemoryRuntime;

    #[test]
    fn cold_installer_is_never_ready() {
        let runtime = Arc::new(CertifiedMemoryRuntime::new(CertifiedMemoryConfig::default()));
        let installer =
            CertifiedMemoryInstaller::new(Arc::new(CertifiedMemoryCoordinator::new(runtime)));
        assert_eq!(installer.status(), CertifiedMemoryInstallerStatus::Cold);
        assert!(!installer.status().positive_reads_ready());
    }
}
