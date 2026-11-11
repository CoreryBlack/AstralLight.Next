//! CertifiedMemory composition root and lifecycle owner.
//!
//! This module deliberately stops at the boundary that can be proven by local
//! code. It owns the typed materializer, snapshot builder, coordinator and
//! installer, but it never invents family completion, authority evidence, or
//! readiness. Missing external inputs remain pending or unavailable.

use std::sync::{Arc, RwLock};

use astral_authority::client::AuthorityClient;
use ed25519_dalek::VerifyingKey;
use thiserror::Error;

use crate::certified_memory_authority::{
    CertifiedMemoryAttestation, CertifiedMemoryConfig, CertifiedMemoryInvalidation,
};
use crate::certified_memory_completion::CertifiedMemoryDurableOwnerContext;
use crate::certified_memory_family_owner::certified_memory_ledger_owners;
use crate::certified_memory_installer::{CertifiedMemoryInstaller, CertifiedMemoryInstallerError};
use crate::certified_memory_materializer::{
    CertifiedMemoryFamilyOwner, CertifiedMemoryFamilyOwnerRequest, CertifiedMemoryMaterializer,
    CertifiedMemoryMaterializerError,
};
use crate::certified_memory_readiness::{
    CertifiedMemoryLeaseBinding, CertifiedMemoryReadinessCapability, CertifiedMemoryReadinessOwner,
    CertifiedMemoryReadinessPorts, DurableFrontierPort, ReadinessError, TransportReadinessPort,
    WorkerOwnershipPort,
};
use crate::certified_memory_snapshot_builder::{
    CertifiedMemoryBuildError, CertifiedMemoryReadiness, CertifiedMemorySnapshotBuilder,
};

/// Lifecycle status owned by the composition root, separate from listener
/// liveness and HTTP readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertifiedMemoryCompositionStatus {
    Cold,
    Preparing,
    Serving,
    Pending,
    Unknown,
    Quarantined,
    Shutdown,
}

impl CertifiedMemoryCompositionStatus {
    pub const fn positive_reads_ready(self) -> bool {
        matches!(self, Self::Serving)
    }
}

/// Explicit composition inputs. No default input is treated as a positive
/// authority source; the default owner registry is intentionally unavailable.
#[derive(Debug, Clone, Default)]
pub struct CertifiedMemoryCompositionConfig {
    pub memory: CertifiedMemoryConfig,
}

/// Process-local owner of the certified authorization read model.
#[derive(Debug)]
pub struct CertifiedMemoryCompositionRoot {
    materializer: CertifiedMemoryMaterializer,
    builder: CertifiedMemorySnapshotBuilder,
    installer: CertifiedMemoryInstaller,
    authority_client: Option<AuthorityClient>,
    verifying_key: Option<VerifyingKey>,
    readiness_owner: RwLock<Option<CertifiedMemoryReadinessOwner>>,
    status: RwLock<CompositionState>,
}

#[derive(Debug)]
struct CompositionState {
    status: CertifiedMemoryCompositionStatus,
    epoch: u64,
}

impl CertifiedMemoryCompositionRoot {
    /// Build an explicit composition root. The owner registry is validated by
    /// [`CertifiedMemoryMaterializer::new`]; no owner is inferred from SQL.
    pub fn new(
        config: CertifiedMemoryCompositionConfig,
        owners: Vec<Arc<dyn CertifiedMemoryFamilyOwner>>,
    ) -> Result<Self, CertifiedMemoryCompositionError> {
        let materializer = CertifiedMemoryMaterializer::new(owners)?;
        Ok(Self::from_parts(config, materializer, None, None))
    }

    /// Build a composition root whose six family owners read only the durable
    /// completion ledger. A pool is an input boundary, not a proof of completion;
    /// absent rows, unknown reconciliation, or missing authority inputs remain
    /// non-positive during materialization and installation.
    pub fn from_durable_owner_context(
        config: CertifiedMemoryCompositionConfig,
        context: CertifiedMemoryDurableOwnerContext,
    ) -> Result<Self, CertifiedMemoryCompositionError> {
        Self::new(config, certified_memory_ledger_owners(context))
    }
    /// Build the safe startup placeholder. It can report Pending, but it can
    /// never produce a positive snapshot until real owners and authority inputs
    /// are explicitly supplied.
    pub fn pending(config: CertifiedMemoryCompositionConfig) -> Self {
        Self::from_parts(config, CertifiedMemoryMaterializer::pending(), None, None)
    }

    /// Attach the already validated authority transport and signer key. The
    /// client performs its own mTLS, attestation, signature and frontier checks;
    /// this root only consumes the verified response.
    pub fn with_authority(mut self, client: AuthorityClient, verifying_key: VerifyingKey) -> Self {
        self.authority_client = Some(client);
        self.verifying_key = Some(verifying_key);
        self
    }

    /// Reuse the production fence provider's authority client and trust session.
    /// A diagnostic provider cannot be used to establish this binding.
    pub fn with_authority_provider(
        mut self,
        provider: &crate::SqlxAuthorizationFenceProvider,
    ) -> Result<Self, astral_types::PolicyError> {
        self.authority_client = Some(provider.certified_memory_authority_client()?);
        self.verifying_key = None;
        Ok(self)
    }

    fn from_parts(
        config: CertifiedMemoryCompositionConfig,
        materializer: CertifiedMemoryMaterializer,
        authority_client: Option<AuthorityClient>,
        verifying_key: Option<VerifyingKey>,
    ) -> Self {
        let runtime = Arc::new(
            crate::certified_memory_snapshot_builder::CertifiedMemoryRuntime::new(config.memory),
        );
        let coordinator = Arc::new(crate::CertifiedMemoryCoordinator::new(runtime));
        let installer = CertifiedMemoryInstaller::new(coordinator);
        Self {
            materializer,
            builder: CertifiedMemorySnapshotBuilder::new(config.memory),
            installer,
            authority_client,
            verifying_key,
            readiness_owner: RwLock::new(None),
            status: RwLock::new(CompositionState {
                status: CertifiedMemoryCompositionStatus::Cold,
                epoch: 0,
            }),
        }
    }

    pub fn installer(&self) -> &CertifiedMemoryInstaller {
        &self.installer
    }

    pub fn certified_store(&self) -> Arc<crate::certified_memory_authority::CertifiedMemoryStore> {
        self.installer.coordinator().runtime().store()
    }

    pub fn status(&self) -> CertifiedMemoryCompositionStatus {
        let status = self
            .status
            .read()
            .map(|state| state.status)
            .unwrap_or(CertifiedMemoryCompositionStatus::Quarantined);
        if status == CertifiedMemoryCompositionStatus::Serving
            && self.installer.coordinator().state()
                != crate::certified_memory_snapshot_builder::CertifiedMemoryRuntimeState::Serving
        {
            CertifiedMemoryCompositionStatus::Unknown
        } else {
            status
        }
    }

    pub fn readiness(&self, now_unix: i64) -> CertifiedMemoryReadiness {
        self.installer.readiness(now_unix)
    }

    /// Startup preflight for a CertifiedMemory listener. This intentionally
    /// fails before any listener is spawned unless the root is already Serving.
    pub fn require_serving(&self, now_unix: i64) -> Result<(), CertifiedMemoryCompositionError> {
        if self.status() != CertifiedMemoryCompositionStatus::Serving
            || !self.readiness(now_unix).positive_reads_ready
        {
            return Err(CertifiedMemoryCompositionError::NotServing);
        }
        Ok(())
    }

    /// Materialize and verify one scope, then issue the owner for the prepared
    /// root. Uncertain authority transport is returned for reconciliation.
    pub async fn prepare(
        &self,
        request: &CertifiedMemoryFamilyOwnerRequest,
        attestation: CertifiedMemoryAttestation,
        installed_at_unix: i64,
        expires_at_unix: i64,
        lease: CertifiedMemoryLeaseBinding,
    ) -> Result<CertifiedMemoryReadinessOwner, CertifiedMemoryCompositionError> {
        let epoch = self.begin_prepare()?;
        let result = self
            .prepare_and_serve_inner(
                request,
                attestation,
                installed_at_unix,
                expires_at_unix,
                lease,
                epoch,
            )
            .await;
        if let Err(error) = &result {
            let mut state = match self.status.write() {
                Ok(state) => state,
                Err(_) => {
                    self.installer
                        .invalidate(CertifiedMemoryInvalidation::Unknown)?;
                    return Err(CertifiedMemoryCompositionError::StateUnavailable);
                }
            };
            if state.epoch == epoch && state.status == CertifiedMemoryCompositionStatus::Preparing {
                state.status = error.status();
            }
        }
        result
    }

    async fn prepare_and_serve_inner(
        &self,
        request: &CertifiedMemoryFamilyOwnerRequest,
        attestation: CertifiedMemoryAttestation,
        installed_at_unix: i64,
        expires_at_unix: i64,
        lease: CertifiedMemoryLeaseBinding,
        epoch: u64,
    ) -> Result<CertifiedMemoryReadinessOwner, CertifiedMemoryCompositionError> {
        let materialization = self.materializer.materialize(request).await?;
        let families = materialization.bundle.clone();
        let snapshot = self.builder.build_from_materialization(
            materialization,
            attestation,
            installed_at_unix,
            expires_at_unix,
        )?;
        let client = self
            .authority_client
            .as_ref()
            .ok_or(CertifiedMemoryCompositionError::AuthorityClientMissing)?;
        let response = client
            .read_certified_memory_root_verified(None)
            .await
            .map_err(|error| CertifiedMemoryInstallerError::Authority(error.to_string()))?;
        let (_, chain_key) = response
            .verified_root_and_key(client)
            .map_err(|error| CertifiedMemoryInstallerError::Authority(error.to_string()))?;
        if self
            .verifying_key
            .as_ref()
            .is_some_and(|configured_key| configured_key != &chain_key)
        {
            return Err(CertifiedMemoryInstallerError::Authority(
                "configured signer differs from the authority trust chain".to_owned(),
            )
            .into());
        }
        let mut state = match self.status.write() {
            Ok(state) => state,
            Err(_) => {
                self.installer
                    .invalidate(CertifiedMemoryInvalidation::Unknown)?;
                return Err(CertifiedMemoryCompositionError::StateUnavailable);
            }
        };
        if state.epoch != epoch || state.status != CertifiedMemoryCompositionStatus::Preparing {
            return Err(CertifiedMemoryCompositionError::NotServing);
        }
        let now_unix = time::OffsetDateTime::now_utc().unix_timestamp();
        self.installer
            .prepare_client_verified_root(snapshot, &families, client, &response, now_unix)?;
        let owner = self
            .installer
            .coordinator()
            .readiness_owner(lease)
            .map_err(CertifiedMemoryInstallerError::from)?;
        let mut readiness_owner = self.readiness_owner.write().map_err(|_| {
            let _ = self
                .installer
                .invalidate(CertifiedMemoryInvalidation::Unknown);
            CertifiedMemoryCompositionError::StateUnavailable
        })?;
        *readiness_owner = Some(owner.clone());
        state.status = CertifiedMemoryCompositionStatus::Preparing;
        Ok(owner)
    }

    /// Return the explicit ports that the composition root issued for this
    /// prepared root. The port methods that establish evidence remain crate
    /// private; external owners can only receive and hold these opaque handles.
    #[allow(dead_code)]
    pub(crate) fn readiness_ports(
        &self,
    ) -> Result<CertifiedMemoryReadinessPorts, CertifiedMemoryCompositionError> {
        self.readiness_owner
            .read()
            .map_err(|_| CertifiedMemoryCompositionError::StateUnavailable)?
            .as_ref()
            .map(CertifiedMemoryReadinessOwner::ports)
            .ok_or(CertifiedMemoryCompositionError::ReadinessNotPrepared)
    }

    /// Composition-root seam for the worker ownership owner. The opaque port
    /// can only be issued by a prepared owner; callers cannot construct a
    /// positive enum assertion instead.
    #[allow(dead_code)]
    pub(crate) fn inject_worker_ownership(
        &self,
        port: WorkerOwnershipPort,
    ) -> Result<(), CertifiedMemoryCompositionError> {
        let owner = self.current_readiness_owner()?;
        owner
            .inject_worker_ownership(port)
            .map_err(CertifiedMemoryCompositionError::Readiness)
    }

    #[allow(dead_code)]
    pub(crate) fn inject_durable_frontier(
        &self,
        port: DurableFrontierPort,
    ) -> Result<(), CertifiedMemoryCompositionError> {
        let owner = self.current_readiness_owner()?;
        owner
            .inject_durable_frontier(port)
            .map_err(CertifiedMemoryCompositionError::Readiness)
    }

    #[allow(dead_code)]
    pub(crate) fn inject_transport(
        &self,
        port: TransportReadinessPort,
    ) -> Result<(), CertifiedMemoryCompositionError> {
        let owner = self.current_readiness_owner()?;
        owner
            .inject_transport(port)
            .map_err(CertifiedMemoryCompositionError::Readiness)
    }

    #[allow(dead_code)]
    fn current_readiness_owner(
        &self,
    ) -> Result<CertifiedMemoryReadinessOwner, CertifiedMemoryCompositionError> {
        self.readiness_owner
            .read()
            .map_err(|_| CertifiedMemoryCompositionError::StateUnavailable)?
            .clone()
            .ok_or(CertifiedMemoryCompositionError::ReadinessNotPrepared)
    }

    /// Complete the prepared attempt after all three real owners establish their ports.
    pub fn prepare_and_serve(
        &self,
        readiness: &CertifiedMemoryReadinessCapability,
        generation: u64,
    ) -> Result<u64, CertifiedMemoryCompositionError> {
        let now_unix = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut state = self.status.write().map_err(|_| {
            let _ = self
                .installer
                .invalidate(CertifiedMemoryInvalidation::Unknown);
            CertifiedMemoryCompositionError::StateUnavailable
        })?;
        if state.status != CertifiedMemoryCompositionStatus::Preparing {
            return Err(CertifiedMemoryCompositionError::NotServing);
        }
        self.installer
            .complete_serving(generation, readiness, now_unix)?;
        state.status = CertifiedMemoryCompositionStatus::Serving;
        Ok(generation)
    }

    pub fn invalidate(
        &self,
        invalidation: CertifiedMemoryInvalidation,
    ) -> Result<(), CertifiedMemoryCompositionError> {
        // Serialize invalidation with prepare and activation. Otherwise a new
        // candidate can be installed and served after the installer is closed
        // but before this composition's state and epoch are updated.
        let mut state = match self.status.write() {
            Ok(state) => state,
            Err(_) => {
                self.installer.invalidate(invalidation)?;
                return Err(CertifiedMemoryCompositionError::StateUnavailable);
            }
        };
        self.installer.invalidate(invalidation)?;
        if let Ok(mut readiness_owner) = self.readiness_owner.write() {
            *readiness_owner = None;
        }
        if state.status != CertifiedMemoryCompositionStatus::Shutdown {
            state.status = match invalidation {
                CertifiedMemoryInvalidation::Stale => CertifiedMemoryCompositionStatus::Pending,
                CertifiedMemoryInvalidation::Gap | CertifiedMemoryInvalidation::Unknown => {
                    CertifiedMemoryCompositionStatus::Unknown
                }
                CertifiedMemoryInvalidation::Failed => {
                    CertifiedMemoryCompositionStatus::Quarantined
                }
            };
        }
        state.epoch = state
            .epoch
            .checked_add(1)
            .ok_or(CertifiedMemoryCompositionError::StateUnavailable)?;
        Ok(())
    }

    /// Close the positive gate before the caller drains listeners and workers.
    pub fn shutdown(&self) -> Result<(), CertifiedMemoryCompositionError> {
        let mut state = match self.status.write() {
            Ok(state) => state,
            Err(_) => {
                self.installer
                    .invalidate(CertifiedMemoryInvalidation::Unknown)?;
                return Err(CertifiedMemoryCompositionError::StateUnavailable);
            }
        };
        if state.status == CertifiedMemoryCompositionStatus::Shutdown {
            self.installer
                .invalidate(CertifiedMemoryInvalidation::Unknown)?;
            if let Ok(mut readiness_owner) = self.readiness_owner.write() {
                *readiness_owner = None;
            }
            return Ok(());
        }
        state.status = CertifiedMemoryCompositionStatus::Shutdown;
        self.installer
            .invalidate(CertifiedMemoryInvalidation::Unknown)?;
        if let Ok(mut readiness_owner) = self.readiness_owner.write() {
            *readiness_owner = None;
        }
        state.epoch = state
            .epoch
            .checked_add(1)
            .ok_or(CertifiedMemoryCompositionError::StateUnavailable)?;
        Ok(())
    }

    fn begin_prepare(&self) -> Result<u64, CertifiedMemoryCompositionError> {
        let mut state = match self.status.write() {
            Ok(state) => state,
            Err(_) => {
                self.installer
                    .invalidate(CertifiedMemoryInvalidation::Unknown)?;
                return Err(CertifiedMemoryCompositionError::StateUnavailable);
            }
        };
        if state.status == CertifiedMemoryCompositionStatus::Shutdown {
            return Err(CertifiedMemoryCompositionError::NotServing);
        }
        // A new prepare attempt invalidates and discards every old capability
        // before any new owner can be issued.
        self.installer
            .invalidate(CertifiedMemoryInvalidation::Unknown)?;
        if let Ok(mut readiness_owner) = self.readiness_owner.write() {
            *readiness_owner = None;
        }
        state.epoch = state
            .epoch
            .checked_add(1)
            .ok_or(CertifiedMemoryCompositionError::StateUnavailable)?;
        state.status = CertifiedMemoryCompositionStatus::Preparing;
        Ok(state.epoch)
    }
}

impl CertifiedMemoryCompositionError {
    const fn status(&self) -> CertifiedMemoryCompositionStatus {
        match self {
            Self::AuthorityClientMissing
            | Self::VerifyingKeyMissing
            | Self::Installer(CertifiedMemoryInstallerError::Authority(_)) => {
                CertifiedMemoryCompositionStatus::Unknown
            }
            Self::Materializer(CertifiedMemoryMaterializerError::Pending { .. })
            | Self::Build(CertifiedMemoryBuildError::Pending { .. }) => {
                CertifiedMemoryCompositionStatus::Pending
            }
            Self::Materializer(CertifiedMemoryMaterializerError::Unknown { .. })
            | Self::Materializer(CertifiedMemoryMaterializerError::Quarantined { .. })
            | Self::Build(CertifiedMemoryBuildError::Unavailable { .. })
            | Self::Installer(CertifiedMemoryInstallerError::AuthorityGateBlocked)
            | Self::Installer(CertifiedMemoryInstallerError::Coordinator(_))
            | Self::Build(_)
            | Self::Materializer(_)
            | Self::NotServing
            | Self::ReadinessNotPrepared
            | Self::Readiness(_)
            | Self::StateUnavailable => CertifiedMemoryCompositionStatus::Quarantined,
        }
    }
}

#[derive(Debug, Error)]
pub enum CertifiedMemoryCompositionError {
    #[error("certified-memory family materializer rejected composition: {0}")]
    Materializer(#[from] CertifiedMemoryMaterializerError),
    #[error("certified-memory snapshot build rejected composition: {0}")]
    Build(#[from] CertifiedMemoryBuildError),
    #[error("certified-memory installer rejected composition: {0}")]
    Installer(#[from] CertifiedMemoryInstallerError),
    #[error("certified-memory authority client is not configured")]
    AuthorityClientMissing,
    #[error("certified-memory verifying key is not configured")]
    VerifyingKeyMissing,
    #[error("certified-memory composition is not serving")]
    NotServing,
    #[error("certified-memory readiness owner has not been prepared")]
    ReadinessNotPrepared,
    #[error("certified-memory readiness capability rejected: {0}")]
    Readiness(#[from] ReadinessError),
    #[error("certified-memory composition state is unavailable")]
    StateUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::authority_protocol::{AuthorityCertifiedMemoryFamily, AuthorityFamilyScope};

    #[derive(Debug)]
    struct PausedOwner {
        entered: Arc<tokio::sync::Notify>,
        resume: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl CertifiedMemoryFamilyOwner for PausedOwner {
        fn family(&self) -> AuthorityCertifiedMemoryFamily {
            AuthorityCertifiedMemoryFamily::CardContext
        }

        async fn materialize(
            &self,
            _request: &CertifiedMemoryFamilyOwnerRequest,
        ) -> Result<
            crate::certified_memory_materializer::CertifiedMemoryFamilyMaterialization,
            CertifiedMemoryMaterializerError,
        > {
            self.entered.notify_one();
            self.resume.notified().await;
            Err(CertifiedMemoryMaterializerError::Pending {
                family: AuthorityCertifiedMemoryFamily::CardContext,
                code: "test.paused_owner",
            })
        }
    }

    #[tokio::test]
    async fn shutdown_fences_a_delayed_prepare() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let resume = Arc::new(tokio::sync::Notify::new());
        let mut owners: Vec<Arc<dyn CertifiedMemoryFamilyOwner>> = vec![Arc::new(PausedOwner {
            entered: entered.clone(),
            resume: resume.clone(),
        })];
        owners.extend(
            AuthorityCertifiedMemoryFamily::required()
                .into_iter()
                .filter(|family| *family != AuthorityCertifiedMemoryFamily::CardContext)
                .map(|family| Arc::new(crate::certified_memory_materializer::UnavailableCertifiedMemoryFamilyOwner::new(family)) as Arc<dyn CertifiedMemoryFamilyOwner>),
        );
        let root =
            Arc::new(CertifiedMemoryCompositionRoot::new(Default::default(), owners).unwrap());
        let task_root = root.clone();
        let task = tokio::spawn(async move {
            task_root
                .prepare(
                    &CertifiedMemoryFamilyOwnerRequest {
                        scope: AuthorityFamilyScope {
                            tenant_id: Some(7),
                            scope: "tenant:7".to_owned(),
                        },
                        generation: 1,
                        revoke_watermark: 0,
                        now_unix: 10_000,
                    },
                    CertifiedMemoryAttestation {
                        authority_term: 1,
                        global_fence_sequence: 1,
                        key_epoch: 1,
                        scope_generation: 1,
                        revoke_watermark: 0,
                        snapshot_hash: "a".repeat(64),
                        issued_at_unix: 9_000,
                        expires_at_unix: 20_000,
                    },
                    10_000,
                    20_000,
                    CertifiedMemoryLeaseBinding::new("test-lease", 1).unwrap(),
                )
                .await
        });
        entered.notified().await;
        root.shutdown().unwrap();
        resume.notify_one();
        assert!(task.await.unwrap().is_err());
        assert_eq!(root.status(), CertifiedMemoryCompositionStatus::Shutdown);
        assert!(!root.readiness(10_000).positive_reads_ready);
        assert!(root.begin_prepare().is_err());
    }

    #[test]
    fn poisoned_composition_shutdown_closes_serving_store() {
        use crate::certified_memory_authority::{
            CertifiedMemoryCoverage, CertifiedMemoryCoverageContract,
        };
        use crate::certified_memory_snapshot_builder::CertifiedMemorySnapshotInput;

        let root = Arc::new(CertifiedMemoryCompositionRoot::pending(Default::default()));
        let snapshot = root
            .builder
            .build(CertifiedMemorySnapshotInput {
                generation: 1,
                installed_at_unix: 10_000,
                expires_at_unix: 10_060,
                attestation: CertifiedMemoryAttestation {
                    authority_term: 1,
                    global_fence_sequence: 1,
                    key_epoch: 1,
                    scope_generation: 1,
                    revoke_watermark: 0,
                    snapshot_hash: "a".repeat(64),
                    issued_at_unix: 10_000,
                    expires_at_unix: 10_060,
                },
                coverage: CertifiedMemoryCoverage::Complete,
                coverage_contract: CertifiedMemoryCoverageContract::complete(),
                card_contexts: Vec::new(),
                global_admins: Vec::new(),
                org_reads: Vec::new(),
                ownership: Vec::new(),
                published_cards: Vec::new(),
                sod_policies: Vec::new(),
            })
            .expect("snapshot");
        let runtime = root.installer.coordinator().runtime();
        runtime
            .install_coordinated(snapshot, 10_001)
            .expect("install");
        runtime.begin_fence_sync(1).expect("fence");
        runtime
            .mark_serving_coordinated(1, 10_001)
            .expect("serving");
        let poisoner = Arc::clone(&root);
        assert!(std::thread::spawn(move || {
            let _guard = poisoner.status.write().expect("status lock");
            panic!("poison composition state");
        })
        .join()
        .is_err());
        assert!(matches!(
            root.shutdown(),
            Err(CertifiedMemoryCompositionError::StateUnavailable)
        ));
        assert!(root.certified_store().begin_read(10_001).is_err());
    }

    #[test]
    fn poisoned_composition_invalidation_closes_runtime() {
        let root = Arc::new(CertifiedMemoryCompositionRoot::pending(Default::default()));
        let poisoner = Arc::clone(&root);
        assert!(std::thread::spawn(move || {
            let _guard = poisoner.status.write().unwrap();
            panic!("poison composition state");
        })
        .join()
        .is_err());
        assert!(matches!(
            root.invalidate(CertifiedMemoryInvalidation::Unknown),
            Err(CertifiedMemoryCompositionError::StateUnavailable)
        ));
        assert_eq!(
            root.installer.coordinator().state(),
            crate::certified_memory_snapshot_builder::CertifiedMemoryRuntimeState::Quarantined
        );
        assert!(!root.readiness(10_000).positive_reads_ready);
    }

    #[test]
    fn invalidation_waits_for_composition_state_before_closing_runtime() {
        use std::sync::mpsc;
        use std::time::Duration;

        let root = Arc::new(CertifiedMemoryCompositionRoot::pending(Default::default()));
        let coordinator = root.installer.coordinator();
        let runtime = coordinator.runtime();
        let state = root.status.write().unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let invalidating_root = Arc::clone(&root);
        let invalidator = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            invalidating_root.invalidate(CertifiedMemoryInvalidation::Unknown)
        });
        started_rx.recv().unwrap();
        assert!(matches!(
            runtime.state(),
            crate::certified_memory_snapshot_builder::CertifiedMemoryRuntimeState::Cold
        ));
        // A writer waiting on status must not mutate the runtime while another
        // prepare or activation holds the composition lock.
        assert!(!invalidator.is_finished());
        std::thread::sleep(Duration::from_millis(20));
        assert!(matches!(
            runtime.state(),
            crate::certified_memory_snapshot_builder::CertifiedMemoryRuntimeState::Cold
        ));
        drop(state);
        invalidator.join().unwrap().unwrap();
        assert_eq!(root.status(), CertifiedMemoryCompositionStatus::Unknown);
        assert!(!root.readiness(10_000).positive_reads_ready);
    }

    #[test]
    fn pending_composition_never_reports_positive_readiness() {
        let root = CertifiedMemoryCompositionRoot::pending(Default::default());
        assert_eq!(root.status(), CertifiedMemoryCompositionStatus::Cold);
        assert!(!root.status().positive_reads_ready());
        assert!(!root.readiness(10_000).positive_reads_ready);
    }

    #[test]
    fn pending_composition_shutdown_closes_the_gate() {
        let root = CertifiedMemoryCompositionRoot::pending(Default::default());
        root.shutdown().expect("shutdown should close the gate");
        assert_eq!(root.status(), CertifiedMemoryCompositionStatus::Shutdown);
        assert!(!root.status().positive_reads_ready());
    }

    #[tokio::test]
    async fn pending_registry_keeps_the_first_family_non_positive() {
        let root = CertifiedMemoryCompositionRoot::pending(Default::default());
        let result = root
            .materializer
            .materialize(&CertifiedMemoryFamilyOwnerRequest {
                scope: AuthorityFamilyScope {
                    tenant_id: Some(7),
                    scope: "tenant:7".to_owned(),
                },
                generation: 1,
                revoke_watermark: 0,
                now_unix: 10_000,
            })
            .await;
        assert!(matches!(
            result,
            Err(CertifiedMemoryMaterializerError::Pending {
                family: AuthorityCertifiedMemoryFamily::CardContext,
                ..
            })
        ));
    }

    /// Fail-closed composition contract: without durable family completions and
    /// an authority client, `prepare_and_serve` must end Pending, never Serving,
    /// and `require_serving` must keep the listener gate closed. There is no
    /// SQL/mirror fallback on this path.
    #[tokio::test]
    async fn prepare_and_serve_without_durable_or_authority_inputs_stays_pending() {
        let root = CertifiedMemoryCompositionRoot::pending(Default::default());
        let request = CertifiedMemoryFamilyOwnerRequest {
            scope: AuthorityFamilyScope {
                tenant_id: Some(7),
                scope: "tenant:7".to_owned(),
            },
            generation: 1,
            revoke_watermark: 0,
            now_unix: 10_000,
        };
        let attestation = CertifiedMemoryAttestation {
            authority_term: 1,
            global_fence_sequence: 1,
            key_epoch: 1,
            scope_generation: 1,
            revoke_watermark: 0,
            snapshot_hash: "a".repeat(64),
            issued_at_unix: 9_000,
            expires_at_unix: 20_000,
        };
        let error = root
            .prepare(
                &request,
                attestation,
                10_000,
                20_000,
                CertifiedMemoryLeaseBinding::new("test-lease", 1).unwrap(),
            )
            .await
            .expect_err("missing durable and authority inputs must never serve");
        assert!(matches!(
            error,
            CertifiedMemoryCompositionError::Materializer(
                CertifiedMemoryMaterializerError::Pending { .. }
            )
        ));
        assert_eq!(root.status(), CertifiedMemoryCompositionStatus::Pending);
        assert!(!root.status().positive_reads_ready());
        assert!(!root.readiness(10_000).positive_reads_ready);
        assert!(
            root.require_serving(10_000).is_err(),
            "listener startup gate must stay closed without a real Serving root"
        );
    }
}
