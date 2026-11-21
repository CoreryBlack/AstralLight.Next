//! memory—v1: Serving-adoption evidence contract.
//!
//! Two grades exist.
//!
//! * **Production** needs all thirteen fact families proven (source provenance,
//!   snapshot identity, schema manifest, coverage, current selection, lifecycle,
//!   confirmation authority, resource ownership, eligibility, separation of
//!   duties, writer coverage, audit correlation, persistence and recovery) plus a
//!   trusted time. Startup verifies independently signed report references
//!   against the exact captured root and reconciles structural facts locally.
//! * **Experimental** is an explicit, operator-acknowledged profile for an
//!   isolated service run. It checks the caller's schema version and nonzero
//!   fingerprint, compares the reported counts with the root's rows, and checks
//!   the current-version pointers. Other fact families stay `Unverified` and
//!   require the caller to acknowledge each corresponding [`AdoptionLimit`].
//!
//! `AdoptionEvidence` has private fields, while [`ColdLoadFacts`] is supplied by
//! the caller. Experimental adoption does not independently prove the reported
//! schema, scan, snapshot provenance or capture time.

use thiserror::Error;

use crate::memory_v1_db_rows::TableCounts;
use crate::memory_v1_digest::ContentDigest;
use crate::memory_v1_hamt::CandidateBudget;
use crate::memory_v1_root::{RootInstanceId, RootMetadata, RootStatus, ServingAdoptionCertificate};

/// The only issuers that can be bound to a serving certificate.
///
/// This is crate-private so callers cannot select a serving grade by passing a
/// boolean or a caller-created enum. The verifier chooses the source from the
/// evidence path, and the root checks it again against the published record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AdoptionCertificateSource {
    /// Complete production evidence, when such a verifier exists.
    Production,
    /// Evidence accepted under the explicitly acknowledged experimental profile.
    Experimental,
    /// A test-only fixture; it cannot be presented as production evidence.
    #[cfg(any(test, feature = "test-support"))]
    IsolatedTest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EvidenceIssuer {
    Production,
    #[cfg(any(test, feature = "test-support"))]
    IsolatedTest,
}

/// State of one mandatory fact family in the memory—v1 serving-adoption decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EvidenceState {
    /// Established by a check the verifier performed itself.
    Proven,
    /// Could not be determined, or a check failed.
    Unknown,
    /// Its contract is not implemented; adoptable only as an acknowledged limit.
    Unverified,
}

/// Version of the root-side adoption input contract.
///
/// This is separate from the rule-set version and the process root version.
pub const MEMORY_V1_ADOPTION_SCHEMA_VERSION: u16 = 1;

/// Version of the UUID-native nine-table candidate shape required at adoption.
/// Version 4 requires an explicit rule-set lifecycle state.
/// This is independent of the root-side adoption input contract version.
pub const MEMORY_V1_CANDIDATE_SCHEMA_VERSION: u16 = 4;

/// A fact family an experimental adoption may leave unverified when the caller
/// acknowledges it by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AdoptionLimit {
    /// The database source is not independently proven trustworthy.
    SourceProvenance,
    /// The snapshot is not tied to a durable point such as a GTID.
    SnapshotIdentity,
    /// Complete lifecycle and validity facts are not proven.
    LifecycleAndValidity,
    /// Confirmation rows are not checked for confirmer authority.
    ConfirmationAuthority,
    /// Trusted resource ownership is not completely proven.
    ResourceOwnership,
    /// Complete eligibility and constraint facts are not proven.
    Eligibility,
    /// General separation-of-duties facts are not proven.
    SeparationOfDuties,
    /// Complete authorized-writer coverage is not proven.
    WriterCoverage,
    /// Decisions are not durably audited or correlated.
    AuditCorrelation,
    /// Durable writes and recovery reconciliation are not established.
    PersistenceRecovery,
}

impl AdoptionLimit {
    /// Every limit an experimental adoption records today.
    pub const EXPERIMENTAL: [AdoptionLimit; 10] = [
        Self::SourceProvenance,
        Self::SnapshotIdentity,
        Self::LifecycleAndValidity,
        Self::ConfirmationAuthority,
        Self::ResourceOwnership,
        Self::Eligibility,
        Self::SeparationOfDuties,
        Self::WriterCoverage,
        Self::AuditCorrelation,
        Self::PersistenceRecovery,
    ];

    /// memory—v1: Stable kebab-case name used in configuration and readiness output.
    pub const fn name(self) -> &'static str {
        match self {
            Self::SourceProvenance => "source-provenance",
            Self::SnapshotIdentity => "snapshot-identity",
            Self::LifecycleAndValidity => "lifecycle-and-validity",
            Self::ConfirmationAuthority => "confirmation-authority",
            Self::ResourceOwnership => "resource-ownership",
            Self::Eligibility => "eligibility",
            Self::SeparationOfDuties => "separation-of-duties",
            Self::WriterCoverage => "writer-coverage",
            Self::AuditCorrelation => "audit-correlation",
            Self::PersistenceRecovery => "persistence-recovery",
        }
    }

    /// memory—v1: What stays unverified when this limit is acknowledged.
    pub const fn description(self) -> &'static str {
        match self {
            Self::SourceProvenance => {
                "MySQL is the cold-start source, but its provenance and pre-start tampering, rollback or corruption are not independently proven"
            }
            Self::SnapshotIdentity => {
                "the snapshot is one REPEATABLE READ transaction with no GTID or binlog position tying it to a durable point"
            }
            Self::LifecycleAndValidity => {
                "card and binding states, validity windows and confirmation revocation are partly enforced, but complete lifecycle and validity facts are not proven"
            }
            Self::ConfirmationAuthority => {
                "confirmation structure and the current version's change confirmation are checked; confirmer authority and confirmation scope are not proven"
            }
            Self::ResourceOwnership => {
                "scope checks use target owner and tenant attribution; complete trusted resource-ownership facts are not proven"
            }
            Self::Eligibility => {
                "structural relationships and some eligibility constraints are checked, but complete business eligibility facts are not proven"
            }
            Self::SeparationOfDuties => {
                "self-confirmation and change-impact guards exist, but general separation-of-duties facts and enforcement are not proven"
            }
            Self::WriterCoverage => {
                "governance routes cannot commit; low-level root mutation seams exist, while authorized-writer coverage and external database privileges are not proven"
            }
            Self::AuditCorrelation => {
                "operation identifiers and structured logs exist, but decisions and mutations are not durably audited or correlated by this profile"
            }
            Self::PersistenceRecovery => {
                "MySQL is the cold-start source; in-memory mutations have no proven durable write or recovery reconciliation, and unpersisted changes may be lost on restart"
            }
        }
    }

    /// memory—v1: Parse a limit name; unknown names are refused.
    pub fn parse(name: &str) -> Option<Self> {
        Self::EXPERIMENTAL
            .into_iter()
            .find(|limit| limit.name() == name)
    }
}

/// Caller-supplied observations for one cold-load snapshot.
///
/// The root compares the reported counts with its own rows and checks the schema
/// contract version and nonzero fingerprint. These public fields do not prove
/// that a database adapter performed a scan or validated the schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColdLoadFacts {
    /// Caller-reported version of the schema contract.
    pub schema_contract_version: u16,
    /// Caller-reported fingerprint of the observed schema.
    pub schema_fingerprint: [u8; 32],
    /// Caller-reported `COUNT(*)` for each candidate table.
    pub snapshot_counts: TableCounts,
    /// Caller-reported ordered scan counts, per table.
    pub scanned_counts: TableCounts,
    /// Caller-reported capture time in Unix seconds; the adapter normally uses
    /// the host clock, which is not an independent time source. Only nonnegative
    /// values are accepted; their provenance and accuracy are not verified.
    pub captured_at_unix_seconds: i64,
}

impl ColdLoadFacts {
    // memory—v1: Both adoption grades reconcile the full source, including
    // verified historical version identities, not just resident version bodies.
    fn covers_source(&self, counts: TableCounts, metadata: RootMetadata) -> bool {
        counts == self.snapshot_counts
            && counts == self.scanned_counts
            && counts.total() == Some(metadata.row_count)
    }
}

pub mod startup;

/// How a serving root was adopted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdoptionGrade {
    /// All thirteen fact families proven against the exact candidate.
    Production,
    /// Operator-acknowledged limits; for an isolated service run only.
    Experimental,
    /// A fixture adopted by the test-only hook; proves nothing about the data.
    IsolatedTest,
}

/// What was recorded when one exact root snapshot became serving.
///
/// The record is published atomically with the initial serving snapshot. Later
/// snapshots may retain it as adoption history; it does not prove their freshness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdoptionRecord {
    /// How the root was adopted.
    pub grade: AdoptionGrade,
    /// Limits that stayed unverified and were acknowledged; empty for production.
    pub unverified: Vec<AdoptionLimit>,
    /// Caller-reported schema fingerprint, when a cold load supplied one.
    pub schema_fingerprint: Option<[u8; 32]>,
    /// Root row counts compared with caller-reported counts, when supplied.
    pub counts: Option<TableCounts>,
    /// Caller-reported capture time, when a cold load supplied one.
    pub captured_at_unix_seconds: Option<i64>,
}

/// Opaque evidence assembled for a snapshot verification.
///
/// No public constructor exists. Experimental evidence incorporates public,
/// caller-supplied cold-load facts that are not independently authenticated.
pub struct AdoptionEvidence {
    instance_id: RootInstanceId,
    version: u64,
    digest: ContentDigest,
    budget: CandidateBudget,
    row_count: usize,
    adoption_schema_version: u16,
    issuer: EvidenceIssuer,
    source_provenance: EvidenceState,
    snapshot_identity: EvidenceState,
    schema_manifest: EvidenceState,
    complete_coverage: EvidenceState,
    current_selection: EvidenceState,
    lifecycle_and_validity: EvidenceState,
    confirmation_authority: EvidenceState,
    resource_ownership: EvidenceState,
    eligibility: EvidenceState,
    separation_of_duties: EvidenceState,
    trusted_time_unix_seconds: Option<i64>,
    writer_coverage: EvidenceState,
    audit_correlation: EvidenceState,
    persistence_recovery: EvidenceState,
}

/// Reasons a candidate cannot be adopted as a serving root.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AdoptionEvidenceError {
    #[error("memory-v1 adoption evidence is missing: {0}")]
    Missing(&'static str),
    #[error("memory-v1 adoption evidence leaves an unverified limit unacknowledged: {0}")]
    Unacknowledged(&'static str),
    #[error("memory-v1 adoption evidence does not match the root snapshot")]
    SnapshotMismatch,
    #[error("memory-v1 adoption evidence requires a candidate root")]
    InvalidRootStatus,
    #[error("memory-v1 adoption evidence has an invalid trusted time")]
    InvalidTrustedTime,
    #[error("memory-v1 adoption evidence has an invalid root budget or row count")]
    InvalidBounds,
    #[error("memory-v1 adoption evidence uses unsupported contract version {0}")]
    UnsupportedSchemaVersion(u16),
    #[error(transparent)]
    Startup(#[from] startup::StartupEvidenceError),
}

/// The outcome of a successful evidence check, bound to one exact snapshot.
pub(crate) struct VerifiedAdoption {
    pub(crate) certificate: ServingAdoptionCertificate,
    pub(crate) unverified: Vec<AdoptionLimit>,
    pub(crate) trusted_time_unix_seconds: i64,
}

impl VerifiedAdoption {
    // memory—v1: The record published together with the snapshot it was verified for.
    pub(crate) fn record(
        &self,
        grade: AdoptionGrade,
        schema_fingerprint: Option<[u8; 32]>,
        counts: Option<TableCounts>,
    ) -> AdoptionRecord {
        AdoptionRecord {
            grade,
            unverified: self.unverified.clone(),
            schema_fingerprint,
            counts,
            captured_at_unix_seconds: Some(self.trusted_time_unix_seconds),
        }
    }
}

impl AdoptionEvidence {
    // memory—v1: The thirteen families in decision order, with the limit a caller
    // may acknowledge for each. `None` marks a family that can never be waived.
    fn families(&self) -> [(EvidenceState, &'static str, Option<AdoptionLimit>); 13] {
        [
            (
                self.source_provenance,
                "source provenance",
                Some(AdoptionLimit::SourceProvenance),
            ),
            (
                self.snapshot_identity,
                "consistent snapshot identity",
                Some(AdoptionLimit::SnapshotIdentity),
            ),
            (self.schema_manifest, "schema manifest", None),
            (self.complete_coverage, "complete coverage", None),
            (
                self.current_selection,
                "authoritative current selection",
                None,
            ),
            (
                self.lifecycle_and_validity,
                "lifecycle and validity",
                Some(AdoptionLimit::LifecycleAndValidity),
            ),
            (
                self.confirmation_authority,
                "confirmation authority",
                Some(AdoptionLimit::ConfirmationAuthority),
            ),
            (
                self.resource_ownership,
                "resource ownership",
                Some(AdoptionLimit::ResourceOwnership),
            ),
            (
                self.eligibility,
                "eligibility",
                Some(AdoptionLimit::Eligibility),
            ),
            (
                self.separation_of_duties,
                "separation of duties",
                Some(AdoptionLimit::SeparationOfDuties),
            ),
            (
                self.writer_coverage,
                "writer coverage",
                Some(AdoptionLimit::WriterCoverage),
            ),
            (
                self.audit_correlation,
                "audit correlation",
                Some(AdoptionLimit::AuditCorrelation),
            ),
            (
                self.persistence_recovery,
                "persistence and recovery",
                Some(AdoptionLimit::PersistenceRecovery),
            ),
        ]
    }

    // memory—v1: Every fact family that is not proven, in decision order. Production
    // adoption needs this list empty; the experimental grade may waive only families
    // that carry a limit. Reporting it changes no evidence and no root state.
    pub(crate) fn unproven_families(&self) -> Vec<&'static str> {
        self.families()
            .into_iter()
            .filter(|(state, _, _)| *state != EvidenceState::Proven)
            .map(|(_, name, _)| name)
            .collect()
    }

    /// Verify every mandatory evidence family and bind the result to one exact
    /// candidate metadata object. Production grade: every family must be proven.
    pub(crate) fn verify(
        &self,
        metadata: RootMetadata,
    ) -> Result<VerifiedAdoption, AdoptionEvidenceError> {
        self.verify_with(metadata, None)
    }

    /// Verify at experimental grade: families that cannot be waived must be
    /// proven; every other family must be proven or acknowledged by name.
    pub(crate) fn verify_experimental(
        &self,
        metadata: RootMetadata,
        acknowledged: &[AdoptionLimit],
    ) -> Result<VerifiedAdoption, AdoptionEvidenceError> {
        self.verify_with(metadata, Some(acknowledged))
    }

    fn verify_with(
        &self,
        metadata: RootMetadata,
        acknowledged: Option<&[AdoptionLimit]>,
    ) -> Result<VerifiedAdoption, AdoptionEvidenceError> {
        if metadata.status != RootStatus::Candidate {
            return Err(AdoptionEvidenceError::InvalidRootStatus);
        }
        if self.adoption_schema_version != MEMORY_V1_ADOPTION_SCHEMA_VERSION {
            return Err(AdoptionEvidenceError::UnsupportedSchemaVersion(
                self.adoption_schema_version,
            ));
        }
        if self.instance_id != metadata.instance_id
            || self.version != metadata.version
            || self.digest != metadata.digest
            || self.budget != metadata.budget
            || self.row_count != metadata.row_count
        {
            return Err(AdoptionEvidenceError::SnapshotMismatch);
        }
        if self.row_count == 0
            || self.budget.max_table_rows == 0
            || self.budget.max_bindings_per_read == 0
        {
            return Err(AdoptionEvidenceError::InvalidBounds);
        }
        let mut unverified = Vec::new();
        for (state, name, limit) in self.families() {
            match (state, acknowledged, limit) {
                (EvidenceState::Proven, _, _) => {}
                (EvidenceState::Unverified, Some(acknowledged), Some(limit)) => {
                    if !acknowledged.contains(&limit) {
                        return Err(AdoptionEvidenceError::Unacknowledged(name));
                    }
                    unverified.push(limit);
                }
                (EvidenceState::Unverified | EvidenceState::Unknown, _, _) => {
                    return Err(AdoptionEvidenceError::Missing(name));
                }
            }
        }
        let trusted_time = self
            .trusted_time_unix_seconds
            .ok_or(AdoptionEvidenceError::Missing("trusted time"))?;
        if trusted_time < 0 {
            return Err(AdoptionEvidenceError::InvalidTrustedTime);
        }
        unverified.sort();
        let source = match (acknowledged, self.issuer) {
            (Some(_), _) => AdoptionCertificateSource::Experimental,
            (None, EvidenceIssuer::Production) => AdoptionCertificateSource::Production,
            #[cfg(any(test, feature = "test-support"))]
            (None, EvidenceIssuer::IsolatedTest) => AdoptionCertificateSource::IsolatedTest,
        };
        Ok(VerifiedAdoption {
            certificate: ServingAdoptionCertificate::from_verified_snapshot(
                metadata.instance_id,
                metadata.version,
                metadata.digest,
                source,
            ),
            unverified,
            trusted_time_unix_seconds: trusted_time,
        })
    }

    /// Derive experimental-grade evidence for one exact candidate.
    ///
    /// `counts` and `valid_current_pointers` come from the candidate the root
    /// holds. Coverage requires the caller-reported snapshot and scan counts to
    /// match those rows; current selection requires every stored pointer to match
    /// a selection and version. Neither the scan nor schema attestation is
    /// independently authenticated here. Other unchecked families stay `Unverified`.
    pub(crate) fn from_cold_load(
        metadata: RootMetadata,
        counts: TableCounts,
        valid_current_pointers: bool,
        facts: &ColdLoadFacts,
    ) -> Self {
        let proven_if = |holds: bool| {
            if holds {
                EvidenceState::Proven
            } else {
                EvidenceState::Unknown
            }
        };
        let coverage = facts.covers_source(counts, metadata);
        let schema = facts.schema_contract_version == MEMORY_V1_CANDIDATE_SCHEMA_VERSION
            && facts.schema_fingerprint != [0; 32];
        Self {
            instance_id: metadata.instance_id,
            version: metadata.version,
            digest: metadata.digest,
            budget: metadata.budget,
            row_count: metadata.row_count,
            adoption_schema_version: MEMORY_V1_ADOPTION_SCHEMA_VERSION,
            issuer: EvidenceIssuer::Production,
            source_provenance: EvidenceState::Unverified,
            snapshot_identity: EvidenceState::Unverified,
            schema_manifest: proven_if(schema),
            complete_coverage: proven_if(coverage),
            current_selection: proven_if(valid_current_pointers),
            lifecycle_and_validity: EvidenceState::Unverified,
            confirmation_authority: EvidenceState::Unverified,
            resource_ownership: EvidenceState::Unverified,
            eligibility: EvidenceState::Unverified,
            separation_of_duties: EvidenceState::Unverified,
            trusted_time_unix_seconds: Some(facts.captured_at_unix_seconds),
            writer_coverage: EvidenceState::Unverified,
            audit_correlation: EvidenceState::Unverified,
            persistence_recovery: EvidenceState::Unverified,
        }
    }

    // memory—v1: Combine authenticated external reports with structural checks
    // over the candidate. The external signature cannot waive any local check.
    pub(crate) fn from_verified_startup(
        metadata: RootMetadata,
        counts: TableCounts,
        valid_current_pointers: bool,
        facts: &ColdLoadFacts,
        verified: startup::VerifiedStartupEvidence,
    ) -> Self {
        Self {
            source_provenance: EvidenceState::Proven,
            snapshot_identity: EvidenceState::Proven,
            lifecycle_and_validity: EvidenceState::Proven,
            confirmation_authority: EvidenceState::Proven,
            resource_ownership: EvidenceState::Proven,
            eligibility: EvidenceState::Proven,
            separation_of_duties: EvidenceState::Proven,
            writer_coverage: EvidenceState::Proven,
            audit_correlation: EvidenceState::Proven,
            persistence_recovery: EvidenceState::Proven,
            trusted_time_unix_seconds: Some(verified.trusted_time),
            ..Self::from_cold_load(metadata, counts, valid_current_pointers, facts)
        }
    }

    #[cfg(test)]
    pub(crate) fn with_unknown_coverage_for_test(mut self) -> Self {
        self.complete_coverage = EvidenceState::Unknown;
        self
    }

    // memory—v1: Test evidence is only a fixture assumption. Explicitly enabling
    // `test-support` can expose it in other builds; it is not a security boundary.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn complete_for_test(metadata: RootMetadata) -> Self {
        Self {
            instance_id: metadata.instance_id,
            version: metadata.version,
            digest: metadata.digest,
            budget: metadata.budget,
            row_count: metadata.row_count,
            adoption_schema_version: MEMORY_V1_ADOPTION_SCHEMA_VERSION,
            issuer: EvidenceIssuer::IsolatedTest,
            source_provenance: EvidenceState::Proven,
            snapshot_identity: EvidenceState::Proven,
            schema_manifest: EvidenceState::Proven,
            complete_coverage: EvidenceState::Proven,
            current_selection: EvidenceState::Proven,
            lifecycle_and_validity: EvidenceState::Proven,
            confirmation_authority: EvidenceState::Proven,
            resource_ownership: EvidenceState::Proven,
            eligibility: EvidenceState::Proven,
            separation_of_duties: EvidenceState::Proven,
            trusted_time_unix_seconds: Some(1),
            writer_coverage: EvidenceState::Proven,
            audit_correlation: EvidenceState::Proven,
            persistence_recovery: EvidenceState::Proven,
        }
    }
}

/// A family declaration. Naming a family is not independent evidence: this
/// value can model an assumption on an isolated test root, never establish a
/// fact on the process root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProvenFamily {
    family: AdoptionLimit,
}

impl ProvenFamily {
    /// The declared family; diagnostics only.
    pub const fn family(self) -> AdoptionLimit {
        self.family
    }

    /// memory—v1: Declare a family by name. Even a matching declaration does
    /// not attest that family's postcondition on the process root.
    pub const fn proven_for(family: AdoptionLimit) -> Self {
        Self { family }
    }
}

/// Inputs to the production gate. The root re-derives structural facts from
/// the candidate. The public family declarations are not independent proofs.
#[derive(Default)]
pub struct ProductionEvidenceInput {
    source_provenance: Option<ProvenFamily>,
    snapshot_identity: Option<ProvenFamily>,
    lifecycle_and_validity: Option<ProvenFamily>,
    confirmation_authority: Option<ProvenFamily>,
    resource_ownership: Option<ProvenFamily>,
    eligibility: Option<ProvenFamily>,
    separation_of_duties: Option<ProvenFamily>,
    writer_coverage: Option<ProvenFamily>,
    audit_correlation: Option<ProvenFamily>,
    persistence_recovery: Option<ProvenFamily>,
    /// A caller-supplied timestamp is not a trusted clock observation on the
    /// process root. Absence must not be represented as Unix epoch zero.
    trusted_time_unix_seconds: Option<i64>,
}

impl ProductionEvidenceInput {
    /// Record the caller's source-provenance declaration.
    pub fn with_source_provenance(&mut self, fact: ProvenFamily) -> &mut Self {
        self.source_provenance = Some(fact);
        self
    }

    /// Record the caller's consistent-snapshot-identity declaration.
    pub fn with_snapshot_identity(&mut self, fact: ProvenFamily) -> &mut Self {
        self.snapshot_identity = Some(fact);
        self
    }

    /// Record the caller's lifecycle-and-validity declaration.
    pub fn with_lifecycle_and_validity(&mut self, fact: ProvenFamily) -> &mut Self {
        self.lifecycle_and_validity = Some(fact);
        self
    }

    /// Record the caller's confirmation-authority declaration.
    pub fn with_confirmation_authority(&mut self, fact: ProvenFamily) -> &mut Self {
        self.confirmation_authority = Some(fact);
        self
    }

    /// Record the caller's resource-ownership declaration.
    pub fn with_resource_ownership(&mut self, fact: ProvenFamily) -> &mut Self {
        self.resource_ownership = Some(fact);
        self
    }

    /// Record the caller's eligibility declaration.
    pub fn with_eligibility(&mut self, fact: ProvenFamily) -> &mut Self {
        self.eligibility = Some(fact);
        self
    }

    /// Record the caller's separation-of-duties declaration.
    pub fn with_separation_of_duties(&mut self, fact: ProvenFamily) -> &mut Self {
        self.separation_of_duties = Some(fact);
        self
    }

    /// Record the caller's writer-coverage declaration.
    pub fn with_writer_coverage(&mut self, fact: ProvenFamily) -> &mut Self {
        self.writer_coverage = Some(fact);
        self
    }

    /// Record the caller's audit-correlation declaration.
    pub fn with_audit_correlation(&mut self, fact: ProvenFamily) -> &mut Self {
        self.audit_correlation = Some(fact);
        self
    }

    /// Record the caller's persistence-and-recovery declaration.
    pub fn with_persistence_recovery(&mut self, fact: ProvenFamily) -> &mut Self {
        self.persistence_recovery = Some(fact);
        self
    }

    /// Record the trusted clock observation for this bundle.
    pub fn with_trusted_time(&mut self, unix_seconds: i64) -> &mut Self {
        self.trusted_time_unix_seconds = Some(unix_seconds);
        self
    }

    /// memory—v1: Reconcile structural facts with the held candidate. Until
    /// independent evidence owners exist, declarations by name are assumptions
    /// usable only on a root installed by the isolated fixture registry.
    pub(crate) fn production_evidence(
        &self,
        metadata: RootMetadata,
        counts: TableCounts,
        valid_current_pointers: bool,
        facts: &ColdLoadFacts,
        isolated_fixture: bool,
    ) -> AdoptionEvidence {
        let proven_if = |holds: bool| {
            if holds {
                EvidenceState::Proven
            } else {
                EvidenceState::Unknown
            }
        };
        let coverage = facts.covers_source(counts, metadata);
        let schema = facts.schema_contract_version == MEMORY_V1_CANDIDATE_SCHEMA_VERSION
            && facts.schema_fingerprint != [0; 32];
        let declared = |family: Option<ProvenFamily>, limit: AdoptionLimit| {
            match family {
                Some(fact) if isolated_fixture && fact.family() == limit => EvidenceState::Proven,
                // A mismatched or absent fact is an unknown, never a proven value.
                _ => EvidenceState::Unknown,
            }
        };
        AdoptionEvidence {
            instance_id: metadata.instance_id,
            version: metadata.version,
            digest: metadata.digest,
            budget: metadata.budget,
            row_count: metadata.row_count,
            adoption_schema_version: MEMORY_V1_ADOPTION_SCHEMA_VERSION,
            issuer: EvidenceIssuer::Production,
            source_provenance: declared(self.source_provenance, AdoptionLimit::SourceProvenance),
            snapshot_identity: declared(self.snapshot_identity, AdoptionLimit::SnapshotIdentity),
            schema_manifest: proven_if(schema),
            complete_coverage: proven_if(coverage),
            current_selection: proven_if(valid_current_pointers),
            lifecycle_and_validity: declared(
                self.lifecycle_and_validity,
                AdoptionLimit::LifecycleAndValidity,
            ),
            confirmation_authority: declared(
                self.confirmation_authority,
                AdoptionLimit::ConfirmationAuthority,
            ),
            resource_ownership: declared(self.resource_ownership, AdoptionLimit::ResourceOwnership),
            eligibility: declared(self.eligibility, AdoptionLimit::Eligibility),
            separation_of_duties: declared(
                self.separation_of_duties,
                AdoptionLimit::SeparationOfDuties,
            ),
            trusted_time_unix_seconds: self.trusted_time_unix_seconds.filter(|_| isolated_fixture),
            writer_coverage: declared(self.writer_coverage, AdoptionLimit::WriterCoverage),
            audit_correlation: declared(self.audit_correlation, AdoptionLimit::AuditCorrelation),
            persistence_recovery: declared(
                self.persistence_recovery,
                AdoptionLimit::PersistenceRecovery,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> RootMetadata {
        RootMetadata {
            instance_id: RootInstanceId::from_uuid(uuid::Uuid::from_bytes([1; 16])),
            version: 3,
            digest: [2; 32],
            budget: CandidateBudget {
                max_table_rows: 8,
                max_bindings_per_read: 2,
            },
            row_count: 7,
            status: RootStatus::Candidate,
        }
    }

    // memory—v1: Seven rows across the nine tables, matching `metadata().row_count`.
    fn counts() -> TableCounts {
        TableCounts {
            users: 1,
            identity_cards: 1,
            tenants: 1,
            user_cards: 1,
            rule_sets: 1,
            rule_set_versions: 1,
            bindings: 1,
            ..TableCounts::default()
        }
    }

    fn facts() -> ColdLoadFacts {
        ColdLoadFacts {
            schema_contract_version: MEMORY_V1_CANDIDATE_SCHEMA_VERSION,
            schema_fingerprint: [9; 32],
            snapshot_counts: counts(),
            scanned_counts: counts(),
            captured_at_unix_seconds: 1_700_000_000,
        }
    }

    #[test]
    fn complete_evidence_binds_exact_snapshot() {
        let metadata = metadata();
        assert!(AdoptionEvidence::complete_for_test(metadata)
            .verify(metadata)
            .is_ok());
        let mut changed = metadata;
        changed.version += 1;
        assert!(matches!(
            AdoptionEvidence::complete_for_test(metadata).verify(changed),
            Err(AdoptionEvidenceError::SnapshotMismatch)
        ));
    }

    #[test]
    fn missing_evidence_stays_fail_closed() {
        let evidence =
            AdoptionEvidence::complete_for_test(metadata()).with_unknown_coverage_for_test();
        assert!(matches!(
            evidence.verify(metadata()),
            Err(AdoptionEvidenceError::Missing("complete coverage"))
        ));

        let mut no_time = AdoptionEvidence::complete_for_test(metadata());
        no_time.trusted_time_unix_seconds = None;
        assert!(matches!(
            no_time.verify(metadata()),
            Err(AdoptionEvidenceError::Missing("trusted time"))
        ));
    }

    #[test]
    fn unsupported_adoption_contract_stays_fail_closed() {
        let mut evidence = AdoptionEvidence::complete_for_test(metadata());
        evidence.adoption_schema_version += 1;
        assert!(matches!(
            evidence.verify(metadata()),
            Err(AdoptionEvidenceError::UnsupportedSchemaVersion(2))
        ));
    }

    #[test]
    fn cold_load_evidence_never_reaches_production_grade() {
        let evidence = AdoptionEvidence::from_cold_load(metadata(), counts(), true, &facts());
        assert!(matches!(
            evidence.verify(metadata()),
            Err(AdoptionEvidenceError::Missing("source provenance"))
        ));
    }

    #[test]
    // memory—v1: The production report names exactly the families a cold load cannot prove, in
    // decision order.
    fn production_report_names_exactly_the_families_no_fact_can_prove() {
        let evidence = AdoptionEvidence::from_cold_load(metadata(), counts(), true, &facts());
        assert_eq!(
            evidence.unproven_families(),
            vec![
                "source provenance",
                "consistent snapshot identity",
                "lifecycle and validity",
                "confirmation authority",
                "resource ownership",
                "eligibility",
                "separation of duties",
                "writer coverage",
                "audit correlation",
                "persistence and recovery",
            ]
        );
    }

    #[test]
    // memory—v1: A scan that disagrees with the snapshot is reported as unproven, never proven.
    fn production_report_names_a_snapshot_that_fails_coverage() {
        let mut mismatched = facts();
        mismatched.scanned_counts.users = 0;
        let unproven = AdoptionEvidence::from_cold_load(metadata(), counts(), true, &mismatched)
            .unproven_families();
        assert!(unproven.contains(&"complete coverage"), "{unproven:?}");
        assert!(!unproven.contains(&"schema manifest"), "{unproven:?}");
    }

    #[test]
    // memory—v1: Only complete test evidence leaves no family unproven.
    fn production_report_is_empty_only_when_every_family_is_proven() {
        assert!(AdoptionEvidence::complete_for_test(metadata())
            .unproven_families()
            .is_empty());
    }

    #[test]
    fn experimental_adoption_needs_every_limit_acknowledged_by_name() {
        let evidence = AdoptionEvidence::from_cold_load(metadata(), counts(), true, &facts());
        let all = AdoptionLimit::EXPERIMENTAL;
        let verified = evidence.verify_experimental(metadata(), &all).unwrap();
        assert_eq!(verified.unverified.len(), all.len());
        assert_eq!(verified.trusted_time_unix_seconds, 1_700_000_000);

        for omitted in all {
            let rest: Vec<_> = all.into_iter().filter(|limit| *limit != omitted).collect();
            assert!(
                matches!(
                    evidence.verify_experimental(metadata(), &rest),
                    Err(AdoptionEvidenceError::Unacknowledged(_))
                ),
                "{omitted:?} must be acknowledged explicitly"
            );
        }
        assert!(matches!(
            evidence.verify_experimental(metadata(), &[]),
            Err(AdoptionEvidenceError::Unacknowledged("source provenance"))
        ));
    }

    #[test]
    fn experimental_grade_cannot_waive_what_it_can_check() {
        let all = AdoptionLimit::EXPERIMENTAL;

        let mut snapshot_drift = facts();
        snapshot_drift.snapshot_counts.users += 1;
        let mut scan_drift = facts();
        scan_drift.scanned_counts.bindings += 1;
        for drift in [snapshot_drift, scan_drift] {
            let evidence = AdoptionEvidence::from_cold_load(metadata(), counts(), true, &drift);
            assert!(matches!(
                evidence.verify_experimental(metadata(), &all),
                Err(AdoptionEvidenceError::Missing("complete coverage"))
            ));
        }

        // The root's own rows disagree with the metadata's total.
        let mut short = counts();
        short.users = 0;
        let mut agreeing = facts();
        agreeing.snapshot_counts = short;
        agreeing.scanned_counts = short;
        let evidence = AdoptionEvidence::from_cold_load(metadata(), short, true, &agreeing);
        assert!(matches!(
            evidence.verify_experimental(metadata(), &all),
            Err(AdoptionEvidenceError::Missing("complete coverage"))
        ));

        let ambiguous = AdoptionEvidence::from_cold_load(metadata(), counts(), false, &facts());
        assert!(matches!(
            ambiguous.verify_experimental(metadata(), &all),
            Err(AdoptionEvidenceError::Missing(
                "authoritative current selection"
            ))
        ));

        let mut no_schema = facts();
        no_schema.schema_fingerprint = [0; 32];
        let evidence = AdoptionEvidence::from_cold_load(metadata(), counts(), true, &no_schema);
        assert!(matches!(
            evidence.verify_experimental(metadata(), &all),
            Err(AdoptionEvidenceError::Missing("schema manifest"))
        ));

        for version in [0, 1, 2, 3, MEMORY_V1_CANDIDATE_SCHEMA_VERSION + 1, u16::MAX] {
            let mut unsupported_schema = facts();
            unsupported_schema.schema_contract_version = version;
            let evidence =
                AdoptionEvidence::from_cold_load(metadata(), counts(), true, &unsupported_schema);
            assert!(
                matches!(
                    evidence.verify_experimental(metadata(), &all),
                    Err(AdoptionEvidenceError::Missing("schema manifest"))
                ),
                "unsupported candidate schema version {version} was accepted"
            );
        }

        let mut before_epoch = facts();
        before_epoch.captured_at_unix_seconds = -1;
        let evidence = AdoptionEvidence::from_cold_load(metadata(), counts(), true, &before_epoch);
        assert!(matches!(
            evidence.verify_experimental(metadata(), &all),
            Err(AdoptionEvidenceError::InvalidTrustedTime)
        ));
    }

    #[test]
    fn experimental_evidence_binds_exact_snapshot() {
        let evidence = AdoptionEvidence::from_cold_load(metadata(), counts(), true, &facts());
        let mut changed = metadata();
        changed.digest = [3; 32];
        assert!(matches!(
            evidence.verify_experimental(changed, &AdoptionLimit::EXPERIMENTAL),
            Err(AdoptionEvidenceError::SnapshotMismatch)
        ));
        let mut serving = metadata();
        serving.status = RootStatus::Serving;
        assert!(matches!(
            evidence.verify_experimental(serving, &AdoptionLimit::EXPERIMENTAL),
            Err(AdoptionEvidenceError::InvalidRootStatus)
        ));
    }

    #[test]
    fn limit_names_are_unique_and_round_trip() {
        let mut names: Vec<_> = AdoptionLimit::EXPERIMENTAL
            .into_iter()
            .map(AdoptionLimit::name)
            .collect();
        for limit in AdoptionLimit::EXPERIMENTAL {
            assert_eq!(AdoptionLimit::parse(limit.name()), Some(limit));
            assert!(!limit.description().is_empty());
        }
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), AdoptionLimit::EXPERIMENTAL.len());
        assert_eq!(AdoptionLimit::parse("everything"), None);
        assert_eq!(AdoptionLimit::parse(""), None);
    }
}
