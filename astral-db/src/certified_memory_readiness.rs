//! Readiness capabilities bound to a coordinator-owned preparation epoch.
//!
//! The composition owner distributes each port only to its corresponding real
//! worker, durable frontier, or transport owner. Establishing a port is an
//! assertion by that owner; it does not itself acquire a lease or sync data.

use std::sync::{Arc, Mutex};

use crate::certified_memory_authority::CertifiedMemoryInvalidation;
use crate::certified_memory_snapshot_builder::CertifiedMemoryRuntime;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedMemoryLeaseBinding {
    lease_id: String,
    lease_epoch: u64,
}

impl CertifiedMemoryLeaseBinding {
    pub fn new(lease_id: impl Into<String>, lease_epoch: u64) -> Result<Self, ReadinessError> {
        let lease_id = lease_id.into();
        if lease_id.trim().is_empty() || lease_epoch == 0 {
            return Err(ReadinessError::InvalidBinding);
        }
        Ok(Self {
            lease_id,
            lease_epoch,
        })
    }
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }
    pub const fn lease_epoch(&self) -> u64 {
        self.lease_epoch
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedMemoryReadinessBinding {
    root_digest: String,
    generation: u64,
    lease: CertifiedMemoryLeaseBinding,
}

impl CertifiedMemoryReadinessBinding {
    pub fn root_digest(&self) -> &str {
        &self.root_digest
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub fn lease(&self) -> &CertifiedMemoryLeaseBinding {
        &self.lease
    }
}

#[derive(Debug, Default)]
struct ReadinessState {
    worker: bool,
    frontier: bool,
    transport: bool,
    invalidation: Option<Result<(), String>>,
}

/// Opaque and specific to the coordinator-created owner instance.
#[derive(Debug)]
pub struct CertifiedMemoryReadinessCapability {
    binding: CertifiedMemoryReadinessBinding,
    state: Arc<Mutex<ReadinessState>>,
}

/// Distribute the ports only to the corresponding lifecycle owners.
#[derive(Debug, Clone)]
pub struct CertifiedMemoryReadinessOwner {
    binding: CertifiedMemoryReadinessBinding,
    state: Arc<Mutex<ReadinessState>>,
    runtime: Arc<CertifiedMemoryRuntime>,
}

#[allow(dead_code)]
impl CertifiedMemoryReadinessOwner {
    pub(crate) fn new(
        root_digest: String,
        generation: u64,
        lease: CertifiedMemoryLeaseBinding,
        runtime: Arc<CertifiedMemoryRuntime>,
    ) -> Self {
        Self {
            binding: CertifiedMemoryReadinessBinding {
                root_digest,
                generation,
                lease,
            },
            state: Arc::new(Mutex::new(ReadinessState::default())),
            runtime,
        }
    }
    pub fn binding(&self) -> &CertifiedMemoryReadinessBinding {
        &self.binding
    }
    pub(crate) fn worker_ownership(&self) -> WorkerOwnershipPort {
        WorkerOwnershipPort(self.clone())
    }
    pub(crate) fn durable_frontier(&self) -> DurableFrontierPort {
        DurableFrontierPort(self.clone())
    }
    pub(crate) fn transport(&self) -> TransportReadinessPort {
        TransportReadinessPort(self.clone())
    }

    /// Obtain the three opaque handles for the independently owned readiness
    /// inputs. The handles carry this owner's binding; they have no public
    /// state transition method.
    pub(crate) fn ports(&self) -> CertifiedMemoryReadinessPorts {
        CertifiedMemoryReadinessPorts {
            worker_ownership: self.worker_ownership(),
            durable_frontier: self.durable_frontier(),
            transport: self.transport(),
        }
    }

    pub fn capability(&self) -> Result<CertifiedMemoryReadinessCapability, ReadinessError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ReadinessError::StateUnavailable)?;
        if state.invalidation.is_some() {
            return Err(ReadinessError::Invalidated);
        }
        if !(state.worker && state.frontier && state.transport) {
            return Err(ReadinessError::Incomplete);
        }
        Ok(CertifiedMemoryReadinessCapability {
            binding: self.binding.clone(),
            state: Arc::clone(&self.state),
        })
    }

    /// Accept a port issued by this exact owner and establish its evidence.
    ///
    /// The port types are opaque values issued by the composition owner. The
    /// state transition is crate-private, so a caller cannot create positive
    /// evidence by invoking a public port method. A port from another owner,
    /// root, generation, or lease is rejected before it can change readiness.
    pub(crate) fn inject_worker_ownership(
        &self,
        port: WorkerOwnershipPort,
    ) -> Result<(), ReadinessError> {
        self.accept_port(&port.0)?;
        port.establish()
    }

    pub(crate) fn inject_durable_frontier(
        &self,
        port: DurableFrontierPort,
    ) -> Result<(), ReadinessError> {
        self.accept_port(&port.0)?;
        port.establish()
    }

    pub(crate) fn inject_transport(
        &self,
        port: TransportReadinessPort,
    ) -> Result<(), ReadinessError> {
        self.accept_port(&port.0)?;
        port.establish()
    }

    fn accept_port(&self, port: &CertifiedMemoryReadinessOwner) -> Result<(), ReadinessError> {
        if !Arc::ptr_eq(&self.state, &port.state) || self.binding != port.binding {
            return Err(ReadinessError::BindingMismatch);
        }
        Ok(())
    }

    /// Serialize loss with activation and close the actual runtime before return.
    pub fn invalidate(&self, reason: CertifiedMemoryInvalidation) -> Result<(), ReadinessError> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                let _ = self.runtime.invalidate(reason);
                return Err(ReadinessError::StateUnavailable);
            }
        };
        if let Some(result) = &state.invalidation {
            return result.clone().map_err(ReadinessError::RuntimeInvalidation);
        }
        let result = self
            .runtime
            .invalidate(reason)
            .map_err(|error| error.to_string());
        state.invalidation = Some(result.clone());
        result.map_err(ReadinessError::RuntimeInvalidation)
    }

    pub fn invalidation_callback(
        &self,
    ) -> Arc<dyn Fn(CertifiedMemoryInvalidation) -> Result<(), String> + Send + Sync> {
        let owner = self.clone();
        Arc::new(move |reason| owner.invalidate(reason).map_err(|error| error.to_string()))
    }

    pub(crate) fn with_capability<T>(
        &self,
        capability: &CertifiedMemoryReadinessCapability,
        root_digest: &str,
        generation: u64,
        activate: impl FnOnce() -> T,
    ) -> Result<T, ReadinessError> {
        if !Arc::ptr_eq(&self.state, &capability.state)
            || self.binding != capability.binding
            || self.binding.root_digest != root_digest
            || self.binding.generation != generation
        {
            return Err(ReadinessError::BindingMismatch);
        }
        let state = self
            .state
            .lock()
            .map_err(|_| ReadinessError::StateUnavailable)?;
        if state.invalidation.is_some() {
            return Err(ReadinessError::Invalidated);
        }
        if !(state.worker && state.frontier && state.transport) {
            return Err(ReadinessError::Incomplete);
        }
        Ok(activate())
    }

    fn establish(
        &self,
        select: impl FnOnce(&mut ReadinessState) -> &mut bool,
    ) -> Result<(), ReadinessError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ReadinessError::StateUnavailable)?;
        if state.invalidation.is_some() {
            return Err(ReadinessError::Invalidated);
        }
        *select(&mut state) = true;
        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct CertifiedMemoryReadinessPorts {
    worker_ownership: WorkerOwnershipPort,
    durable_frontier: DurableFrontierPort,
    transport: TransportReadinessPort,
}

#[allow(dead_code)]
impl CertifiedMemoryReadinessPorts {
    pub fn worker_ownership(&self) -> WorkerOwnershipPort {
        self.worker_ownership.clone()
    }

    pub fn durable_frontier(&self) -> DurableFrontierPort {
        self.durable_frontier.clone()
    }

    pub fn transport(&self) -> TransportReadinessPort {
        self.transport.clone()
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct WorkerOwnershipPort(CertifiedMemoryReadinessOwner);
#[allow(dead_code)]
impl WorkerOwnershipPort {
    pub(crate) fn establish(&self) -> Result<(), ReadinessError> {
        self.0.establish(|state| &mut state.worker)
    }
    pub fn invalidate(&self, reason: CertifiedMemoryInvalidation) -> Result<(), ReadinessError> {
        self.0.invalidate(reason)
    }
}
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct DurableFrontierPort(CertifiedMemoryReadinessOwner);
#[allow(dead_code)]
impl DurableFrontierPort {
    pub(crate) fn establish(&self) -> Result<(), ReadinessError> {
        self.0.establish(|state| &mut state.frontier)
    }
    pub fn invalidate(&self, reason: CertifiedMemoryInvalidation) -> Result<(), ReadinessError> {
        self.0.invalidate(reason)
    }
}
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct TransportReadinessPort(CertifiedMemoryReadinessOwner);
#[allow(dead_code)]
impl TransportReadinessPort {
    pub(crate) fn establish(&self) -> Result<(), ReadinessError> {
        self.0.establish(|state| &mut state.transport)
    }
    pub fn invalidate(&self, reason: CertifiedMemoryInvalidation) -> Result<(), ReadinessError> {
        self.0.invalidate(reason)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReadinessError {
    #[error("invalid readiness binding")]
    InvalidBinding,
    #[error("readiness evidence is incomplete")]
    Incomplete,
    #[error("readiness evidence is invalidated")]
    Invalidated,
    #[error("readiness owner or binding does not match the prepared root")]
    BindingMismatch,
    #[error("readiness state is unavailable")]
    StateUnavailable,
    #[error("runtime invalidation failed: {0}")]
    RuntimeInvalidation(String),
}
