//! memory—v1: Serving-adoption evidence contract.
//!
//! Two grades exist.
//!
//! * **Production** needs all thirteen fact families proven (source provenance,
//!   snapshot identity, schema manifest, coverage, current selection, lifecycle,
//!   confirmation authority, resource ownership, eligibility, separation of
//!   duties, writer coverage, audit correlation, persistence and recovery) plus a
//!   trusted time. It still has no constructor: the schema, snapshot manifest,
//!   lifecycle, confirmation authority, writer inventory, audit and recovery
//!   contracts are not implemented, so nothing can honestly mark them proven.
//! * **Experimental** is an explicit, operator-acknowledged profile for an
//!   isolated service run. The facts that can really be checked are checked and
//!   cannot be waived: the observed schema, complete table coverage re-derived
//!   from the root's own rows, and an unambiguous current version. Every other
//!   family stays `Unverified`; it is adopted only when the
//!   caller names that exact [`AdoptionLimit`] as acknowledged, and the limits
//!   are recorded next to the root for readiness output.
//!
//! Every field is private. A digest or a boolean supplied by an untrusted caller
//! is never accepted as evidence: the experimental constructor derives its
//! verdicts from the candidate the root actually holds.

use thiserror::Error;

use crate::memory_v1_db_rows::TableCounts;
use crate::memory_v1_digest::ContentDigest;
use crate::memory_v1_hamt::CandidateBudget;
use crate::memory_v1_root::{RootInstanceId, RootMetadata, RootStatus, ServingAdoptionCertificate};

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

/// A fact family an experimental adoption may leave unverified when the caller
/// acknowledges it by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AdoptionLimit {
    /// The database is trusted as the cold-start source.
    SourceProvenance,
    /// The snapshot is not tied to a durable point such as a GTID.
    SnapshotIdentity,
    /// The schema models no object state, expiry or deletion.
    LifecycleAndValidity,
    /// Confirmation rows are not checked for confirmer authority.
    ConfirmationAuthority,
    /// The schema models no resource ownership.
    ResourceOwnership,
    /// The schema models no eligibility or constraint facts.
    Eligibility,
    /// No separation-of-duties facts exist.
    SeparationOfDuties,
    /// Writers outside this process are not inventoried.
    WriterCoverage,
    /// Decisions are not durably audited or correlated.
    AuditCorrelation,
    /// Nothing is persisted and no recovery is defined.
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
                "the database is trusted as the cold-start source; tampering, rollback or corruption before startup is not detected"
            }
            Self::SnapshotIdentity => {
                "the snapshot is one REPEATABLE READ transaction with no GTID or binlog position tying it to a durable point"
            }
            Self::LifecycleAndValidity => {
                "the schema models no state, suspension, expiry or deletion; every row is treated as valid"
            }
            Self::ConfirmationAuthority => {
                "confirmations are checked for structure and the selected version only; the confirmer's authority is not verified"
            }
            Self::ResourceOwnership => {
                "the schema models no resource ownership; rules match on resource type and action only"
            }
            Self::Eligibility => "the schema models no eligibility or constraint facts",
            Self::SeparationOfDuties => "no separation-of-duties facts exist and none are enforced",
            Self::WriterCoverage => {
                "no in-process writer is mounted, but external writers and database privileges are not inventoried"
            }
            Self::AuditCorrelation => {
                "decisions are not durably audited or correlated by this profile"
            }
            Self::PersistenceRecovery => {
                "nothing is persisted and no recovery is defined; a restart reloads the database snapshot"
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

/// Facts only the database adapter can observe about one cold-load snapshot.
///
/// The root re-derives everything it can from the candidate it holds: the three
/// row-count views below must agree with each other and with the rows the root
/// was built from. The schema fields are the adapter's attestation that its
/// manifest check passed; the root can record them but cannot recheck them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ColdLoadFacts {
    /// Version of the schema contract the adapter validated the observed tables against.
    pub schema_contract_version: u16,
    /// Fingerprint of the validated observed schema.
    pub schema_fingerprint: [u8; 32],
    /// `COUNT(*)` of every candidate table, read inside the same snapshot transaction.
    pub snapshot_counts: TableCounts,
    /// Rows the adapter scanned to the end of an ordered query, per table.
    pub scanned_counts: TableCounts,
    /// UTC time of the capture read from the host clock, in Unix seconds. The
    /// host clock is not an independent time source.
    pub captured_at_unix_seconds: i64,
}

/// How a serving root was adopted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdoptionGrade {
    /// All thirteen fact families proven. No constructor exists yet.
    Production,
    /// Operator-acknowledged limits; for an isolated service run only.
    Experimental,
    /// A fixture adopted by the test-only hook; proves nothing about the data.
    IsolatedTest,
}

/// What was recorded when one exact root snapshot became serving.
///
/// The record is stored inside the serving snapshot it describes and published
/// with it in one compare-and-swap, so it can never describe another snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdoptionRecord {
    /// How the root was adopted.
    pub grade: AdoptionGrade,
    /// Limits that stayed unverified and were acknowledged; empty for production.
    pub unverified: Vec<AdoptionLimit>,
    /// Fingerprint of the validated schema, when a cold load supplied one.
    pub schema_fingerprint: Option<[u8; 32]>,
    /// Row counts verified against the snapshot, when a cold load supplied them.
    pub counts: Option<TableCounts>,
    /// Capture time from the host clock, when a cold load supplied one.
    pub captured_at_unix_seconds: Option<i64>,
}

/// Opaque evidence assembled from a trusted snapshot verification.
///
/// No public constructor exists. In particular, a digest or a boolean supplied
/// by an untrusted caller is never accepted as evidence.
pub struct AdoptionEvidence {
    instance_id: RootInstanceId,
    version: u64,
    digest: ContentDigest,
    budget: CandidateBudget,
    row_count: usize,
    adoption_schema_version: u16,
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
        Ok(VerifiedAdoption {
            certificate: ServingAdoptionCertificate::from_verified_snapshot(
                metadata.instance_id,
                metadata.version,
                metadata.digest,
            ),
            unverified,
            trusted_time_unix_seconds: trusted_time,
        })
    }

    /// Derive experimental-grade evidence for one exact candidate.
    ///
    /// `counts` and `single_version` come from the candidate the root holds, not
    /// from the caller. Coverage is proven only when the snapshot `COUNT(*)`, the
    /// ordered scan and the root's own rows agree table by table; the current
    /// selection only when every rule set has exactly one stored version. Every
    /// family without a real check stays `Unverified`.
    pub(crate) fn from_cold_load(
        metadata: RootMetadata,
        counts: TableCounts,
        single_version: bool,
        facts: &ColdLoadFacts,
    ) -> Self {
        let proven_if = |holds: bool| {
            if holds {
                EvidenceState::Proven
            } else {
                EvidenceState::Unknown
            }
        };
        let coverage = counts == facts.snapshot_counts
            && counts == facts.scanned_counts
            && counts.total() == Some(metadata.row_count);
        let schema = facts.schema_contract_version != 0 && facts.schema_fingerprint != [0; 32];
        Self {
            instance_id: metadata.instance_id,
            version: metadata.version,
            digest: metadata.digest,
            budget: metadata.budget,
            row_count: metadata.row_count,
            adoption_schema_version: MEMORY_V1_ADOPTION_SCHEMA_VERSION,
            source_provenance: EvidenceState::Unverified,
            snapshot_identity: EvidenceState::Unverified,
            schema_manifest: proven_if(schema),
            complete_coverage: proven_if(coverage),
            current_selection: proven_if(single_version),
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

    #[cfg(test)]
    pub(crate) fn with_unknown_coverage_for_test(mut self) -> Self {
        self.complete_coverage = EvidenceState::Unknown;
        self
    }

    // memory—v1: Test-only evidence for isolated compositions. It is compiled
    // only for this crate's unit tests or the dev-dependency `test-support`
    // feature, never for a production build.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn complete_for_test(metadata: RootMetadata) -> Self {
        Self {
            instance_id: metadata.instance_id,
            version: metadata.version,
            digest: metadata.digest,
            budget: metadata.budget,
            row_count: metadata.row_count,
            adoption_schema_version: MEMORY_V1_ADOPTION_SCHEMA_VERSION,
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
            schema_contract_version: 1,
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
