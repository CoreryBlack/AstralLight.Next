//! memory—v1: the composition-owned serving-root mutation writer.
//!
//! The writer is the only component allowed to execute a serving-root mutation
//! in the unified single-node path. It is constructed exclusively around one
//! root owner whose current snapshot already validates a root-owned
//! `ProductionAdmission`; construction therefore proves the production
//! adoption gate once, and every later commit re-checks the exact observation
//! before building any candidate.
//!
//! The durable owner reserves the complete immutable journal record in
//! memory, publishes it together with the facts and the governance position
//! under one CAS, and only then writes the reserved record to the journal.
//! The root-owned reservation remains held until the same successor publishes
//! and the written record is verified. Card disable coordinates publication
//! with the bound session authority.

use std::sync::Arc;

use astral_authorization_root::memory_v1_root::{
    GovernanceFrontier, ManagementMutationV2, PreparedGovernedMutation, ProductionAdmission,
    ReservedGovernanceRecord, RootError, RootMetadata, RootOwner, RootStatus,
};
use astral_trustgraph::service::memory_v1_mutation_coordinator::{
    RootBinding, VerifiedRootAdmission,
};
#[cfg(test)]
use astral_types::memory_v1::MemoryId;
use thiserror::Error;

/// Errors from the controlled serving-root writer.
#[derive(Debug, Error)]
pub enum RootMutationWriterError {
    #[error("the root writer has no installed root")]
    NoRoot,
    #[error("the production admission does not match the current root")]
    AdmissionMismatch,
    #[error("the root is not serving")]
    NotServing,
    #[error("the requested observation is stale or foreign")]
    StaleObservation,
    #[error("the mutation kind is not controlled by this writer")]
    UnsupportedMutation,
    #[error("the root mutation failed: {0:?}")]
    Mutation(#[from] astral_authorization_root::memory_v1_root::MutationError),
}

/// The only serving-root mutation authority in the unified path.
pub struct RootMutationWriter {
    root: Arc<RootOwner>,
    admission: Arc<ProductionAdmission>,
    session_authority: Option<
        Arc<astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority>,
    >,
}

impl std::fmt::Debug for RootMutationWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RootMutationWriter([REDACTED])")
    }
}

impl RootMutationWriter {
    /// Construct the writer only after the exact current snapshot validates the
    /// production admission. The admission is retained so the capability's
    /// lifecycle stays tied to this writer, not to any caller-held handle.
    pub fn new(
        root: Arc<RootOwner>,
        admission: Arc<ProductionAdmission>,
    ) -> Result<Self, RootMutationWriterError> {
        let metadata = root
            .validate_production_admission(admission.as_ref())
            .map_err(|error| match error {
                RootError::ProductionAdmissionMismatch => {
                    RootMutationWriterError::AdmissionMismatch
                }
                _ => RootMutationWriterError::AdmissionMismatch,
            })?;
        if metadata.status != RootStatus::Serving {
            return Err(RootMutationWriterError::NotServing);
        }
        Ok(Self {
            root,
            admission,
            session_authority: None,
        })
    }

    /// The metadata validated at construction; diagnostics only.
    #[cfg(test)]
    pub(crate) fn observed(&self) -> RootMetadata {
        self.root.handle().metadata().unwrap_or(RootMetadata {
            instance_id: astral_authorization_root::memory_v1_root::RootInstanceId::from_uuid(
                uuid::Uuid::nil(),
            ),
            version: 0,
            digest: [0; 32],
            budget: astral_authorization_root::memory_v1_hamt::CandidateBudget {
                max_table_rows: 0,
                max_bindings_per_read: 0,
            },
            row_count: 0,
            status: RootStatus::Stopped,
        })
    }

    /// Re-derive the crate-private coordinator admission for one exact
    /// observation. The current root must still match the writer's production
    /// capability and the caller's observed metadata must equal the current
    /// metadata; anything else is refused before the request is bound.
    pub fn verified_admission(
        &self,
        observed: &RootMetadata,
    ) -> Result<VerifiedRootAdmission, RootMutationWriterError> {
        let metadata = self
            .root
            .validate_production_admission(self.admission.as_ref())
            .map_err(|_| RootMutationWriterError::AdmissionMismatch)?;
        if &metadata != observed {
            return Err(RootMutationWriterError::StaleObservation);
        }
        Ok(VerifiedRootAdmission::mint_from_production_owner(
            RootBinding::from_metadata(metadata),
        ))
    }

    /// memory—v1: Resolve a live DENY observation; stale or foreign roots
    /// have no historical proof on this value-only port.
    pub(crate) fn deny_frontier(
        &self,
        expected: &RootMetadata,
    ) -> Result<GovernanceFrontier, RootError> {
        self.root
            .current_governance_frontier(&self.admission, expected)
    }

    /// memory—v1: Read the complete reserved journal record that the exact
    /// live serving snapshot published. The commit owner calls this after the
    /// CAS succeeded, with the returned metadata, so the record it writes is
    /// taken from the published snapshot itself and never from caller-held
    /// state.
    pub(crate) fn published_record(
        &self,
        expected: &RootMetadata,
    ) -> Result<Option<ReservedGovernanceRecord>, RootError> {
        self.root
            .published_governance_record(&self.admission, expected)
    }

    /// memory—v1: Reserve and validate the exact request-bound successor before journaling.
    pub(crate) fn prepare(
        &self,
        observed: &RootMetadata,
        mutation: &ManagementMutationV2,
    ) -> Result<(VerifiedRootAdmission, PreparedGovernedMutation<'_>), RootMutationWriterError>
    {
        let prepared = self.root.prepare_governed_mutation(
            self.admission.as_ref(),
            observed,
            mutation,
            self.session_authority.as_deref(),
        )?;
        let admission = VerifiedRootAdmission::mint_from_production_owner(
            RootBinding::from_metadata(*observed),
        );
        Ok((admission, prepared))
    }

    /// memory—v1: Publish directly on an isolated fixture, without the journal.
    #[cfg(test)]
    pub(crate) fn publish(
        &self,
        mutation: &ManagementMutationV2,
    ) -> Result<RootMetadata, RootMutationWriterError> {
        self.prepare(&self.observed(), mutation)?
            .1
            .publish()
            .map_err(Into::into)
    }

    /// Bind the session authority that owns revocation generations. The
    /// composition calls this once, after the authority has been created and
    /// bound to the same root; a None argument removes a stale binding.
    pub fn set_session_authority(
        &mut self,
        authority: Option<
            Arc<astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority>,
        >,
    ) {
        self.session_authority = authority;
    }

    /// memory—v1: Publish a session-coordinated disable directly on an isolated fixture.
    #[cfg(test)]
    pub(crate) fn disable_card_with_sessions(
        &self,
        authority: &Arc<
            astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority,
        >,
        user_card_id: MemoryId,
    ) -> Result<RootMetadata, RootMutationWriterError> {
        if !self
            .session_authority
            .as_ref()
            .is_some_and(|bound| Arc::ptr_eq(bound, authority))
        {
            return Err(RootMutationWriterError::UnsupportedMutation);
        }
        self.publish(&ManagementMutationV2::UserCardStatus {
            user_card_id: user_card_id.into_bytes(),
            status: astral_authorization_root::memory_v1_db_rows::UserCardStatus::Disabled,
        })
    }
}
