//! memory—v1: the composition-owned serving-root mutation writer.
//!
//! The writer is the only component allowed to execute a serving-root mutation
//! in the unified single-node path. It is constructed exclusively around one
//! root owner whose current snapshot already validates a root-owned
//! `ProductionAdmission`; construction therefore proves the production
//! adoption gate once, and every later commit re-checks the exact observation
//! before building any candidate.
//!
//! Two controlled entry points exist:
//!
//! * [`RootMutationWriter::publish`] executes an ordinary governed mutation
//!   under the root writer lock with the CAS precondition fixed to the
//!   observed version, and returns the published metadata.
//! * [`RootMutationWriter::verified_admission`] re-derives the crate-private
//!   coordinator admission for one exact observation, refusing any stale or
//!   foreign observation before the durable commit owner binds its request.
//!
//! Card disable is intentionally absent here: a serving card disable must be
//! coordinated with the session authority (revocation generation), which is a
//! separate controlled path owned by the session authority. Returning an error
//! keeps the low-level refuse-unknowns contract.

use std::sync::Arc;

use astral_authorization_root::memory_v1_root::{
    ManagementMutationV2, MutationPrecondition, ProductionAdmission, RootError, RootMetadata,
    RootOwner, RootStatus,
};
use astral_trustgraph::service::memory_v1_mutation_coordinator::{
    RootBinding, VerifiedRootAdmission,
};
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
    executor: astral_authorization_root::memory_v1_root::RootMutationExecutor,
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
        let executor = root.mutation_executor();
        Ok(Self {
            root,
            executor,
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

    /// Publish one governed mutation against the observed root version.
    ///
    /// The precondition is fixed to the caller's observation so the CAS gate
    /// refuses a stale commit; the root writer lock serializes the candidate
    /// construction and the atomic publication. A card disable is refused
    /// because it requires the session-coordinated path.
    pub fn publish(
        &self,
        mutation: &ManagementMutationV2,
    ) -> Result<RootMetadata, RootMutationWriterError> {
        if matches!(
            mutation,
            ManagementMutationV2::UserCardStatus {
                status: astral_authorization_root::memory_v1_db_rows::UserCardStatus::Disabled,
                ..
            }
        ) {
            return Err(RootMutationWriterError::UnsupportedMutation);
        }
        let metadata = self
            .root
            .validate_production_admission(self.admission.as_ref())
            .map_err(|_| RootMutationWriterError::AdmissionMismatch)?;
        self.root
            .execute_serving_mutation_with_admission(
                self.admission.as_ref(),
                mutation,
                &MutationPrecondition {
                    evaluated_root_version: metadata.version,
                },
            )
            .map_err(RootMutationWriterError::Mutation)
    }

    /// The bound authority, for the commit owner's disable path.
    pub(crate) fn session_authority(
        &self,
    ) -> Option<
        &std::sync::Arc<
            astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority,
        >,
    > {
        self.session_authority.as_ref()
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

    /// Publish a session-coordinated card disable through the authority that
    /// owns revocation generations. The writer forwards the same production
    /// admission requirement before entering the coordinated path; the
    /// callback applies the revocation updates inside the root writer lock.
    pub fn disable_card_with_sessions(
        &self,
        authority: &std::sync::Arc<
            astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority,
        >,
        user_card_id: MemoryId,
    ) -> Result<
        (RootMetadata, usize),
        astral_authorization_root::memory_v1_session_authority::MemoryV1CardDisableError,
    > {
        // The authority must be the bound one; anything else fails closed.
        let Some(bound) = self.session_authority.as_ref() else {
            return Err(
                astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthorityError::Unavailable
                    .into(),
            );
        };
        if !std::sync::Arc::ptr_eq(bound, authority) {
            return Err(
                astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthorityError::Unavailable
                    .into(),
            );
        }
        // The admission requirement is re-checked by the coordinator itself
        // against this exact root; the observed metadata comes from the same
        // capability validation the ordinary publish path uses.
        let metadata = self
            .root
            .validate_production_admission(self.admission.as_ref())
            .map_err(|_| astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthorityError::Unavailable)?;
        let mut revoked = 0_usize;
        let metadata = self.executor.disable_card_with_session_updates(
            authority,
            user_card_id.into_bytes(),
            metadata,
            || {
                revoked = authority
                    .identity_session_adapter()
                    .revoke_sessions_for_user_card(user_card_id)
                    .unwrap_or(0);
            },
        )?;
        Ok((metadata, revoked))
    }
}
