//! memory—v1: Bind independent startup evidence to the root publication boundary.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::memory_v1_adoption::{
    startup::{
        active_registry_digest, AuthenticatedStartupEvidence, StartupEvidenceContext,
        StartupEvidenceSubject,
    },
    AdoptionEvidence, AdoptionEvidenceError, ColdLoadFacts,
};
use crate::memory_v1_registry::RegistrySnapshot;

use super::{
    AdoptionGrade, GovernanceFrontier, JournalAnchor, MemoryId, ProductionAdmission, RootError,
    RootMetadata, RootOwner, RootSnapshot,
};

pub(super) struct StartupPublicationCheck<'a> {
    registry_version: u64,
    evidence: &'a AuthenticatedStartupEvidence,
    verified_at: i64,
}

impl StartupPublicationCheck<'_> {
    // memory—v1: Recheck after structural validation and lock wait, before the root CAS.
    pub(super) fn verify(&self, registry_version: u64) -> Result<(), RootError> {
        if registry_version != self.registry_version {
            return Err(RootError::AdoptionSnapshotChanged);
        }
        let now = unix_now()?;
        if now < self.verified_at {
            return Err(AdoptionEvidenceError::InvalidTrustedTime.into());
        }
        self.evidence
            .check_window(now)
            .map_err(AdoptionEvidenceError::from)?;
        Ok(())
    }
}

fn unix_now() -> Result<i64, AdoptionEvidenceError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
        .ok_or(AdoptionEvidenceError::InvalidTrustedTime)
}

impl RootOwner {
    /// memory—v1: Read a non-authorizing subject for an independent issuer.
    /// The returned value is not an admission and captures no secret material.
    pub fn startup_subject(
        &self,
        facts: &ColdLoadFacts,
        installation_id: MemoryId,
        database_scope: [u8; 32],
        epoch: MemoryId,
        tail: JournalAnchor,
    ) -> Result<StartupEvidenceSubject, RootError> {
        let current = self.runtime.current.load_full();
        let registry = self
            .runtime
            .registry
            .snapshot()
            .map_err(RootError::Registry)?;
        startup_subject_for(
            &current,
            &registry,
            facts,
            installation_id,
            database_scope,
            epoch,
            tail,
        )
    }

    /// memory—v1: Adopt the exact installed snapshot with an independently
    /// signed startup envelope. No declarations-only fallback is attempted.
    pub fn adopt_with_signed_startup(
        &self,
        facts: &ColdLoadFacts,
        context: StartupEvidenceContext<'_>,
    ) -> Result<(RootMetadata, ProductionAdmission, [u8; 32]), RootError> {
        let current = self.runtime.current.load_full();
        let registry = self
            .runtime
            .registry
            .snapshot()
            .map_err(RootError::Registry)?;
        let subject = startup_subject_for(
            &current,
            &registry,
            facts,
            context.installation_id,
            context.database_scope,
            context.epoch,
            context.checkpoint_tail,
        )?;
        let now = unix_now()?;
        if now < facts.captured_at_unix_seconds || facts.captured_at_unix_seconds <= 0 {
            return Err(AdoptionEvidenceError::InvalidTrustedTime.into());
        }
        let startup = context
            .evidence
            .bind(&subject, now)
            .map_err(AdoptionEvidenceError::from)?;
        let evidence_digest = startup.envelope_digest;
        let counts = current.objects.table_counts();
        let evidence = AdoptionEvidence::from_verified_startup(
            current.metadata,
            counts,
            current.objects.has_valid_current_pointers(),
            facts,
            startup,
        );
        let verified = evidence.verify(current.metadata)?;
        let record = verified.record(
            AdoptionGrade::Production,
            Some(facts.schema_fingerprint),
            Some(counts),
        );
        let (metadata, snapshot) = self.adopt_snapshot_internal(
            &current,
            &verified.certificate,
            record,
            true,
            Some(StartupPublicationCheck {
                registry_version: registry.version,
                evidence: context.evidence,
                verified_at: now,
            }),
        )?;
        Ok((
            metadata,
            ProductionAdmission::for_published_snapshot(&self.runtime, &snapshot),
            evidence_digest,
        ))
    }
}

// memory—v1: Use the same observed subject for issuing requests and verifying startup.
fn startup_subject_for(
    current: &RootSnapshot,
    registry: &RegistrySnapshot,
    facts: &ColdLoadFacts,
    installation_id: MemoryId,
    database_scope: [u8; 32],
    epoch: MemoryId,
    tail: JournalAnchor,
) -> Result<StartupEvidenceSubject, RootError> {
    let frontier_matches = match current.frontier {
        GovernanceFrontier::Baseline => tail.mutation_sequence() == 0,
        GovernanceFrontier::Published(prefix) => {
            let anchor = prefix.anchor();
            prefix.epoch() == epoch
                && anchor.stream_id() == tail.stream_id()
                && anchor.mutation_sequence() == tail.mutation_sequence()
                && anchor.journal_sequence() <= tail.journal_sequence()
                && (anchor.journal_sequence() != tail.journal_sequence()
                    || anchor.frame_hash() == tail.frame_hash())
        }
        GovernanceFrontier::Unproven => false,
    };
    if !frontier_matches {
        return Err(AdoptionEvidenceError::SnapshotMismatch.into());
    }
    let registry_digest =
        active_registry_digest(registry).ok_or(AdoptionEvidenceError::SnapshotMismatch)?;
    Ok(StartupEvidenceSubject {
        installation_id,
        database_scope,
        schema_fingerprint: facts.schema_fingerprint,
        candidate_digest: current.metadata.digest,
        registry_digest,
        journal_stream: tail.stream_id(),
        journal_epoch: epoch,
        journal_sequence: tail.journal_sequence(),
        mutation_sequence: tail.mutation_sequence(),
        journal_tail_hash: *tail.frame_hash(),
    })
}
