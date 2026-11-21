//! memory—v1: cold installation of the process root from a reconciled journal.
//!
//! The database was reconciled to this journal's applied prefix before the
//! capture (receipt reconciliation plus the exact apply-progress match inside
//! the snapshot loader), so the captured rows already carry every journaled
//! mutation: nothing is replayed onto the captured facts (Rust 规范
//! §15.10.4). The installer instead binds the journal's last mutation anchor
//! — its own anchor, not the frame tail — together with the exact captured
//! cold-load facts at the same candidate installation. A pure DENY suffix
//! advances only the frame tail and leaves the governance position at the
//! last mutation.
//!
//! Provenance is sealed: the only public entry is
//! [`ReconciledColdInstall::capture_and_bind`], an integrated recover-and-
//! capture over the verified pool, the chain- and checkpoint-verified journal,
//! its durability coordinator and the caller's capture budget. It verifies the
//! retained applied history, captures the nine fact tables at that exact
//! applied prefix, and binds the governance anchor privately inside this
//! module. [`ReconciledColdInstall`] has private fields and no other
//! constructor, so the governance position, the rows and the facts can never
//! be mixed across captures or supplied by a caller: there is no formal path
//! that passes a prefix for arbitrary rows. The value is consumed by
//! [`ReconciledColdInstall::install_and_adopt_production`], which installs the
//! candidate at the bound position and runs the unchanged production adoption
//! gate over the bound facts. Without complete capture evidence the
//! installation still refuses.

use std::time::Duration;

use astral_authorization_root::memory_v1_adoption::{
    startup::{AuthenticatedStartupEvidence, StartupEvidenceContext},
    ColdLoadFacts,
};
use astral_authorization_root::memory_v1_db_rows::CandidateRows;
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_root::{
    install_process_root_with_headroom_and_governance_prefix, GovernancePrefix,
    ProductionAdmission, RootError, RootOwner, RootStatus,
};
use astral_db::memory_v1_candidate_loader::{capture_startup_candidate, CaptureBudget};
use astral_types::memory_v1::MemoryId;
use astral_types::memory_v1_journal::{JournalAnchor, RecordKind};
use sqlx::MySqlPool;
use thiserror::Error;

use crate::memory_v1_durable_journal::{JournalDurability, MemoryV1DurableJournal};

/// The startup deadline for verifying the retained applied history; the
/// candidate snapshot loader enforces its own internal deadline.
const APPLIED_HISTORY_DEADLINE: Duration = Duration::from_secs(30);

/// Why a cold installation refused; every variant stops the startup before
/// any listener exists.
#[derive(Debug, Error)]
pub enum ColdInstallError {
    /// The retained applied history could not be verified (receipts, progress
    /// or the suffix consumption disagreed with the journal).
    #[error("the retained applied history could not be verified: {0}")]
    AppliedHistory(String),
    /// Verifying the retained applied history exceeded its startup deadline.
    #[error("verifying the retained applied history exceeded its deadline")]
    AppliedHistoryDeadline,
    /// The candidate snapshot at the applied prefix could not be captured.
    #[error("the candidate snapshot at the applied prefix could not be captured: {0}")]
    Capture(String),
    /// The capture carries no complete scan report, so the exact cold-load
    /// facts the adoption gate needs cannot be bound.
    #[error("the captured candidate carries no complete scan report")]
    IncompleteCapture,
    /// The journal's governance position cannot be proven against its own
    /// retained history: the scan is inconsistent or the boundary does not
    /// correspond to a retained mutation record.
    #[error("the reconciled journal's governance position is unknown or unverifiable")]
    UnknownPosition,
    /// The candidate has no valid current rule-set version pointer.
    #[error("the candidate has no valid current rule-set version pointer: {0:?}")]
    Selections(astral_authorization_root::memory_v1_db_rows::CurrentVersionPointerError),
    /// The candidate installation or the production adoption gate failed.
    #[error("cold candidate installation failed: {0:?}")]
    Install(RootError),
}

/// The exact captured candidate, its cold-load facts and the reconciled
/// governance position, bound together for one cold installation.
///
/// Private fields and the single integrated constructor make the value
/// unforgeable: the governance position is derived inside this module from
/// the journal's own state and never detaches as a parameter.
pub struct ReconciledColdInstall {
    rows: CandidateRows,
    facts: ColdLoadFacts,
    prefix: Option<GovernancePrefix>,
    database_scope: Option<[u8; 32]>,
    epoch: MemoryId,
    checkpoint_tail: JournalAnchor,
}

impl std::fmt::Debug for ReconciledColdInstall {
    // memory—v1
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReconciledColdInstall([REDACTED])")
    }
}

impl ReconciledColdInstall {
    /// Verify the retained applied history, capture the candidate snapshot at
    /// the journal's exact applied prefix and bind the journal's last mutation
    /// anchor to the captured facts in one integrated step.
    ///
    /// `pool` must be the reconciliation pool; `journal` must be the chain- and
    /// checkpoint-verified handle from the retained journal. There is no other
    /// constructor and no path that binds a caller-supplied position or rows.
    pub async fn capture_and_bind(
        pool: &MySqlPool,
        journal: &MemoryV1DurableJournal,
        durability: &JournalDurability,
        budget: CaptureBudget,
    ) -> Result<Self, ColdInstallError> {
        let verified = tokio::time::timeout(
            APPLIED_HISTORY_DEADLINE,
            crate::memory_v1_recovery_owner::verify_applied_history(pool, journal, durability),
        )
        .await
        .map_err(|_| ColdInstallError::AppliedHistoryDeadline)?;
        verified.map_err(|error| ColdInstallError::AppliedHistory(format!("{error:#}")))?;
        Self::capture_at_checkpoint(pool, journal, budget).await
    }

    /// memory—v1: Read an already-applied checkpoint for an independent issuer.
    /// This never reconciles, applies frames, or adopts the result.
    pub async fn capture_at_checkpoint(
        pool: &MySqlPool,
        journal: &MemoryV1DurableJournal,
        budget: CaptureBudget,
    ) -> Result<Self, ColdInstallError> {
        let capture =
            capture_startup_candidate(pool, budget, journal.epoch_id(), journal.position())
                .await
                .map_err(|error| ColdInstallError::Capture(error.to_string()))?;
        let astral_db::memory_v1_candidate_loader::CandidateCaptureWithSchemaDiagnostic {
            capture: capture_rows,
            schema_diagnostic,
        } = capture.candidate;
        if let Some(report) = &capture_rows.report {
            tracing::info!(
                capture_attempt = %report.attempt_id.as_uuid(),
                schema_contract_version = schema_diagnostic.contract_version(),
                schema_diagnostic = ?schema_diagnostic.fingerprint(),
                "memory-v1 candidate schema metadata matched"
            );
        }
        let astral_db::memory_v1_candidate_loader::UnverifiedCandidateRows { rows, report, .. } =
            capture_rows;
        let facts = Self::cold_facts_of(report.as_ref())?;
        let mut bound = Self::bind_verified(journal, rows, facts)?;
        bound.database_scope = Some(capture.database_scope);
        Ok(bound)
    }

    /// The exact cold-load facts of one capture; a capture without a complete
    /// scan report yields nothing and refuses the installation.
    fn cold_facts_of(
        report: Option<&astral_db::memory_v1_candidate_loader::CandidateCaptureReport>,
    ) -> Result<ColdLoadFacts, ColdInstallError> {
        report
            .and_then(|report| report.cold_load_facts())
            .ok_or(ColdInstallError::IncompleteCapture)
    }

    /// The shared binding core, private to this module: derive the governance
    /// position from the journal's own last mutation anchor and bind it with
    /// the exact captured facts.
    fn bind_verified(
        journal: &MemoryV1DurableJournal,
        rows: CandidateRows,
        facts: ColdLoadFacts,
    ) -> Result<Self, ColdInstallError> {
        let boundary = journal.last_mutation();
        // The frame tail and the mutation boundary must agree about the
        // governance sequence. DENY records advance the frame tail only, so a
        // pure DENY suffix leaves the governance sequence at the last mutation.
        if journal.position().mutation_sequence() != boundary.mutation_sequence() {
            return Err(ColdInstallError::UnknownPosition);
        }
        let prefix = if boundary.mutation_sequence() == 0 {
            None
        } else {
            // The boundary must correspond to a retained mutation record: the
            // scan's chain digest, sequence and kind identify exactly one.
            let record = journal
                .recovery_records()
                .iter()
                .find(|record| record.journal_sequence == boundary.journal_sequence())
                .ok_or(ColdInstallError::UnknownPosition)?;
            if record.kind != RecordKind::Mutation
                || record.mutation_sequence != boundary.mutation_sequence()
                || record.frame_hash != *boundary.frame_hash()
            {
                return Err(ColdInstallError::UnknownPosition);
            }
            Some(
                GovernancePrefix::new(boundary, journal.epoch_id())
                    .ok_or(ColdInstallError::UnknownPosition)?,
            )
        };
        Ok(Self {
            rows,
            facts,
            prefix,
            database_scope: None,
            epoch: journal.epoch_id(),
            checkpoint_tail: journal.position(),
        })
    }

    /// memory—v1: Export a non-authorizing subject for the independent issuer.
    /// This consumes the capture; the caller must never serve from it.
    pub fn into_startup_subject(
        self,
        probe: fn() -> Option<usize>,
        declarations: &[RegistryDeclaration],
        installation_id: MemoryId,
    ) -> Result<
        astral_authorization_root::memory_v1_adoption::startup::StartupEvidenceSubject,
        ColdInstallError,
    > {
        let scope = self
            .database_scope
            .ok_or(ColdInstallError::IncompleteCapture)?;
        let (facts, epoch, tail) = (self.facts, self.epoch, self.checkpoint_tail);
        self.install_candidate(probe, declarations)?
            .startup_subject(&facts, installation_id, scope, epoch, tail)
            .map_err(ColdInstallError::Install)
    }

    /// memory—v1: Verify externally signed evidence against this cold capture
    /// and publish only the exact candidate that it identified.
    pub fn install_and_adopt_signed_startup(
        self,
        probe: fn() -> Option<usize>,
        declarations: &[RegistryDeclaration],
        installation_id: MemoryId,
        evidence: &AuthenticatedStartupEvidence,
    ) -> Result<(RootOwner, std::sync::Arc<ProductionAdmission>), ColdInstallError> {
        let context = StartupEvidenceContext {
            installation_id,
            database_scope: self
                .database_scope
                .ok_or(ColdInstallError::IncompleteCapture)?,
            epoch: self.epoch,
            checkpoint_tail: self.checkpoint_tail,
            evidence,
        };
        let facts = self.facts;
        let owner = self.install_candidate(probe, declarations)?;
        let (_, admission, digest) = owner
            .adopt_with_signed_startup(&facts, context)
            .map_err(ColdInstallError::Install)?;
        tracing::info!(evidence_sha256 = %hex::encode(digest), installation = %installation_id, "memory-v1 signed startup evidence accepted");
        Ok((owner, std::sync::Arc::new(admission)))
    }

    // memory—v1: Keep the install, selection and registry checks common to both callers.
    fn install_candidate(
        self,
        probe: fn() -> Option<usize>,
        declarations: &[RegistryDeclaration],
    ) -> Result<RootOwner, ColdInstallError> {
        let selections = self
            .rows
            .current_version_selections()
            .map_err(ColdInstallError::Selections)?;
        let owner = install_process_root_with_headroom_and_governance_prefix(
            self.rows,
            selections,
            self.prefix,
            probe,
        )
        .map_err(ColdInstallError::Install)?;
        owner
            .install_registry(declarations)
            .map_err(|error| ColdInstallError::Install(RootError::Registry(error)))?;
        Ok(owner)
    }

    /// Consume the binding: install the candidate at the bound governance
    /// position and adopt it at the production grade over the bound facts.
    ///
    /// The production evidence gate is unchanged: the caller supplies the
    /// sealed production evidence input exactly as the adoption gate requires
    /// it, and the gate still verifies the bound facts against the installed
    /// snapshot. The prefix never detaches from the binding. The registry
    /// declarations and the headroom probe are supplied by the process owner
    /// (the composition's single copies).
    pub fn install_and_adopt_production(
        self,
        probe: fn() -> Option<usize>,
        declarations: &[RegistryDeclaration],
        sealed_input: &astral_authorization_root::memory_v1_adoption::ProductionEvidenceInput,
    ) -> Result<(RootOwner, std::sync::Arc<ProductionAdmission>), ColdInstallError> {
        let facts = self.facts;
        let owner = self.install_candidate(probe, declarations)?;
        let (metadata, admission) = owner
            .adopt_with_production_evidence(&facts, sealed_input)
            .map_err(ColdInstallError::Install)?;
        if metadata.status != RootStatus::Serving {
            return Err(ColdInstallError::Install(RootError::InconsistentCandidate));
        }
        Ok((owner, std::sync::Arc::new(admission)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_authorization_root::memory_v1_adoption::MEMORY_V1_CANDIDATE_SCHEMA_VERSION;
    use astral_authorization_root::memory_v1_db_rows::{
        BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, IdentityCardRow,
        RuleSetRow, RuleSetStatus, RuleSetVersionRow, TenantRow, UserCardRow, UserCardStatus,
        UserRow,
    };
    use astral_authorization_root::memory_v1_root::{
        install_isolated_test_root_with_governance_prefix, GovernanceFrontier,
    };
    use astral_trustgraph::service::memory_v1_mutation_coordinator::{
        JournalIdentity, MutationAuditCandidate, MutationRequest, VerifiedRootAdmission,
    };
    use astral_types::memory_v1::{CandidateIdentity, MemoryId};
    use astral_types::memory_v1_audit::{
        MemoryV1AuditAction, MemoryV1AuditActor, MemoryV1AuditCardState, MemoryV1AuditChange,
        MemoryV1AuditConfirmations, MemoryV1AuditContext, MemoryV1AuditDecisionInput,
        MemoryV1AuditDenySource, MemoryV1AuditEvent, MemoryV1AuditObject, MemoryV1AuditObjectState,
        MemoryV1AuditOperation, MemoryV1AuditRootObservation, MemoryV1AuditRootStatus,
        MemoryV1AuditRootVersion, MemoryV1AuditSource, MemoryV1AuditT2SingleChangeCandidate,
        MemoryV1AuditTime,
    };
    use astral_types::memory_v1_deny_observation::{
        MemoryV1DenyAffectedBindingState, MemoryV1DenyObservation, MemoryV1DenyRootObservation,
    };
    use astral_types::memory_v1_journal::JournalAnchor;
    use uuid::Uuid;

    /// Sufficient additional bytes for the fixture candidate.
    fn test_probe() -> Option<usize> {
        Some(1 << 20)
    }

    fn fixture_registry() -> Vec<RegistryDeclaration> {
        vec![RegistryDeclaration {
            resource: "document".to_owned(),
            actions: vec!["read".to_owned()],
        }]
    }

    // The reconciled fixture rows: the same final state the journaled enable
    // mutations describe, as the reconciled database would capture them.
    fn fixture_rows() -> CandidateRows {
        use astral_authorization_root::memory_v1_rules::{MemoryV1OwnerScope, MemoryV1TenantScope};
        use sha2::{Digest, Sha256};
        let id = |value: u8| [value; 16];
        let content =
            br#"{"rules":[{"ruleId":"R9","resource":"document","action":"read","effect":"ALLOW"}]}"#
                .to_vec();
        let version_bytes = vec![1u8];
        let timestamp_bytes = vec![1u8];
        let hash_input = astral_authorization_root::memory_v1_rules::canonical_version_bytes(
            &version_bytes,
            &content,
            &timestamp_bytes,
        );
        let hash = Sha256::digest(&hash_input).to_vec();
        let mut rows = CandidateRows {
            users: vec![UserRow { user_id: id(1) }],
            identity_cards: vec![IdentityCardRow {
                identity_card_id: id(2),
                user_id: id(1),
            }],
            tenants: vec![TenantRow {
                tenant_id: id(3),
                parent_tenant_id: None,
            }],
            user_cards: vec![UserCardRow {
                user_card_id: id(4),
                user_id: id(1),
                tenant_id: id(3),
                status: UserCardStatus::Active,
            }],
            rule_sets: vec![RuleSetRow {
                rule_set_id: id(5),
                owner_tenant_id: id(3),
                current_version_bytes: vec![1],
                status: RuleSetStatus::Active,
            }],
            rule_set_versions: vec![RuleSetVersionRow {
                rule_set_id: id(5),
                version_bytes: version_bytes.clone(),
                content_bytes: content,
                timestamp_bytes,
                hash_input_bytes: hash_input,
                hash_bytes: hash,
            }],
            bindings: vec![BindingRow {
                binding_id: id(6),
                user_card_id: id(4),
                rule_set_id: id(5),
                binding_layer: BindingLayer::Base,
                valid_from: None,
                valid_until: None,
                owner_scope: MemoryV1OwnerScope::default(),
                tenant_scope: MemoryV1TenantScope::default(),
                removed_at: None,
                removed_by: None,
            }],
            ..CandidateRows::default()
        };
        rows.binding_confirmations.push(BindingConfirmationRow {
            confirmation_id: id(7),
            binding_id: id(6),
            rule_set_id: id(5),
            version_bytes: vec![1],
            confirmer_user_id: id(1),
            scope_bytes: vec![1],
            operation_id: vec![1],
            confirmed_at_bytes: vec![1],
            revoked_at: None,
            revoked_by: None,
        });
        rows.rule_set_change_confirmations.push(
            astral_authorization_root::memory_v1_db_rows::RuleSetChangeConfirmationRow {
                confirmation_id: id(8),
                rule_set_id: id(5),
                version_bytes: vec![1],
                confirmer_user_id: id(1),
                affected_scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            },
        );
        rows
    }

    fn fixture_facts(rows: &CandidateRows) -> ColdLoadFacts {
        let counts = rows.table_counts();
        ColdLoadFacts {
            schema_contract_version: MEMORY_V1_CANDIDATE_SCHEMA_VERSION,
            schema_fingerprint: [7; 32],
            snapshot_counts: counts,
            scanned_counts: counts,
            captured_at_unix_seconds: 1_700_000_000,
        }
    }

    struct JournalDir(std::path::PathBuf);
    impl JournalDir {
        fn new(label: &str) -> Self {
            let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
            let dir = base.join(format!("astral-cold-install-{label}-{}", Uuid::new_v4()));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&dir).unwrap();
            Self(dir)
        }
        fn path(&self) -> std::path::PathBuf {
            self.0.join("journal.bin")
        }
    }
    impl Drop for JournalDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn open_journal(dir: &JournalDir) -> (MemoryV1DurableJournal, JournalDurability) {
        MemoryV1DurableJournal::create(
            &dir.path(),
            MemoryId::from_bytes([10; 16]),
            MemoryId::from_bytes([11; 16]),
            JournalAnchor::new(MemoryId::from_bytes([10; 16]), 0, 0, [5; 32]).unwrap(),
            crate::memory_v1_durable_journal::DurableJournalLimits::conservative(),
        )
        .unwrap()
    }

    fn synthetic_metadata() -> astral_authorization_root::memory_v1_root::RootMetadata {
        astral_authorization_root::memory_v1_root::RootMetadata {
            instance_id: astral_authorization_root::memory_v1_root::RootInstanceId::from_uuid(
                Uuid::from_bytes([21; 16]),
            ),
            version: 7,
            digest: [7; 32],
            budget: astral_authorization_root::memory_v1_hamt::CandidateBudget {
                max_table_rows: 32,
                max_bindings_per_read: 4,
            },
            row_count: 9,
            status: astral_authorization_root::memory_v1_root::RootStatus::Serving,
        }
    }

    fn enable_request(
        operation_id: &str,
        fingerprint_byte: u8,
        identity: JournalIdentity,
    ) -> MutationRequest {
        let mutation =
            astral_authorization_root::memory_v1_root::ManagementMutationV2::UserCardStatus {
                user_card_id: [4; 16],
                status: UserCardStatus::Active,
            };
        let metadata = synthetic_metadata();
        let instance = MemoryId::from_bytes(*metadata.instance_id.as_uuid().as_bytes());
        let context = MemoryV1AuditContext::new(
            MemoryV1AuditActor::new(MemoryId::from_bytes([1; 16]), MemoryId::from_bytes([2; 16])),
            MemoryV1AuditTime::new(1_700_000_000).unwrap(),
            MemoryV1AuditAction::new("user_card", "enable").unwrap(),
            "GOVERNANCE_USER_CARD_ENABLE",
            MemoryV1AuditOperation::new(operation_id, [fingerprint_byte; 32]).unwrap(),
            MemoryV1AuditRootObservation::new(
                MemoryV1AuditRootVersion::new(instance, metadata.version),
                metadata.digest,
                MemoryV1AuditRootStatus::Serving,
            ),
        )
        .unwrap();
        let summary = MutationAuditCandidate::governance_mutation_summary(&mutation).unwrap();
        let change = MemoryV1AuditChange::new(
            Some(MemoryId::from_bytes([1; 16])),
            Some(MemoryV1AuditObject::UserCard(MemoryId::from_bytes([4; 16]))),
            Some(MemoryV1AuditObject::Tenant(MemoryId::from_bytes([3; 16]))),
            Some(summary),
            Some(MemoryV1AuditObjectState::UserCard(
                MemoryV1AuditCardState::Disabled,
            )),
            Some(MemoryV1AuditObjectState::UserCard(
                MemoryV1AuditCardState::Active,
            )),
            Some(MemoryV1AuditConfirmations::not_applicable()),
            Some(MemoryV1AuditRootVersion::new(instance, metadata.version)),
            Some(MemoryV1AuditRootVersion::new(
                instance,
                metadata.version + 1,
            )),
            MemoryV1AuditSource::Ordinary,
        );
        MutationRequest::try_new(
            operation_id,
            [fingerprint_byte; 32],
            mutation,
            MutationAuditCandidate::Single(
                MemoryV1AuditT2SingleChangeCandidate::try_from(
                    MemoryV1AuditEvent::change(context, MemoryV1AuditDecisionInput::Allow, change)
                        .unwrap(),
                )
                .unwrap(),
            ),
            VerifiedRootAdmission::mint_from_production_owner(
                astral_trustgraph::service::memory_v1_mutation_coordinator::RootBinding::from_metadata(
                    metadata,
                ),
            ),
            identity,
        )
        .unwrap()
    }

    fn deny_frame(
        journal_sequence: u64,
        mutation_sequence: u64,
    ) -> astral_trustgraph::service::memory_v1_mutation_coordinator::DenyJournalRequest {
        let metadata = synthetic_metadata();
        let root_observation = MemoryV1DenyRootObservation::try_from_usize(
            MemoryId::from_bytes(*metadata.instance_id.as_uuid().as_bytes()),
            metadata.version,
            metadata.digest,
            MemoryV1AuditRootStatus::Serving,
            metadata.budget.max_table_rows,
            metadata.budget.max_bindings_per_read,
            metadata.row_count,
        )
        .unwrap();
        let observation = MemoryV1DenyObservation::new(
            root_observation,
            CandidateIdentity {
                user_id: MemoryId::from_bytes([1; 16]),
                identity_card_id: MemoryId::from_bytes([2; 16]),
                user_card_id: MemoryId::from_bytes([4; 16]),
                tenant_id: MemoryId::from_bytes([3; 16]),
            },
            1_700_000_000,
            "document",
            "read",
            None,
            Some(Vec::new()),
            None,
            MemoryV1DenyAffectedBindingState::inapplicable(),
            format!("deny-{journal_sequence}").into_bytes(),
            [9; 32].to_vec(),
            MemoryV1AuditDenySource::RuleDeny,
            None,
        )
        .unwrap();
        astral_trustgraph::service::memory_v1_mutation_coordinator::DenyJournalRequest::try_new(
            observation,
            JournalIdentity::new_deny(
                MemoryId::from_bytes([10; 16]),
                MemoryId::from_bytes([11; 16]),
                journal_sequence,
                mutation_sequence,
                MemoryId::from_bytes([15; 16]),
            )
            .unwrap(),
        )
        .unwrap()
    }

    // memory—v1: Genesis binds no governance position; the installed candidate
    // keeps the baseline frontier and the production gate adopts it Serving.
    #[test]
    fn genesis_binds_the_baseline_and_adopts_serving() {
        let dir = JournalDir::new("genesis");
        let (journal, _durability) = open_journal(&dir);
        let rows = fixture_rows();
        let facts = fixture_facts(&rows);

        let cold = ReconciledColdInstall::bind_verified(&journal, rows.clone(), facts).unwrap();
        assert!(cold.prefix.is_none());

        let selections = rows.current_version_selections().unwrap();
        let owner = install_isolated_test_root_with_governance_prefix(
            rows.clone(),
            selections,
            astral_authorization_root::memory_v1_hamt::CandidateBudget {
                max_table_rows: 32,
                max_bindings_per_read: 4,
            },
            None,
        )
        .unwrap();
        assert_eq!(
            owner.candidate_governance_frontier().unwrap(),
            GovernanceFrontier::Baseline
        );
        owner.install_registry(&fixture_registry()).unwrap();
        let (metadata, admission) = owner
            .adopt_with_production_evidence(&facts, &sealed_input())
            .unwrap();
        assert_eq!(
            metadata.status,
            astral_authorization_root::memory_v1_root::RootStatus::Serving
        );
        let frontier = owner
            .current_governance_frontier(&admission, &metadata)
            .unwrap();
        assert_eq!(frontier, GovernanceFrontier::Baseline);
    }

    // memory—v1: The sealed production evidence input a complete reconciliation
    // carries; every family is proven for the fixture, mirroring the gate's
    // decision order.
    fn sealed_input() -> astral_authorization_root::memory_v1_adoption::ProductionEvidenceInput {
        use astral_authorization_root::memory_v1_adoption::{AdoptionLimit, ProvenFamily};
        let proven = ProvenFamily::proven_for;
        let mut input =
            astral_authorization_root::memory_v1_adoption::ProductionEvidenceInput::default();
        input
            .with_source_provenance(proven(AdoptionLimit::SourceProvenance))
            .with_snapshot_identity(proven(AdoptionLimit::SnapshotIdentity))
            .with_lifecycle_and_validity(proven(AdoptionLimit::LifecycleAndValidity))
            .with_confirmation_authority(proven(AdoptionLimit::ConfirmationAuthority))
            .with_resource_ownership(proven(AdoptionLimit::ResourceOwnership))
            .with_eligibility(proven(AdoptionLimit::Eligibility))
            .with_separation_of_duties(proven(AdoptionLimit::SeparationOfDuties))
            .with_writer_coverage(proven(AdoptionLimit::WriterCoverage))
            .with_audit_correlation(proven(AdoptionLimit::AuditCorrelation))
            .with_persistence_recovery(proven(AdoptionLimit::PersistenceRecovery))
            .with_trusted_time(1_700_000_000);
        input
    }

    // memory—v1: Two journaled mutations and a pure DENY suffix bind the last
    // mutation's OWN anchor: the governance position stays at the mutation
    // boundary while the frame tail carries the deny. The binding happens on
    // the reopened journal — the production shape, whose retained history the
    // binder reads — and the process cold-install entry installs and adopts
    // the bound candidate Serving at that position.
    #[test]
    fn reconciled_mutations_and_a_deny_suffix_bind_the_last_mutation_anchor() {
        let dir = JournalDir::new("deny-suffix");
        let (first_tail, second_tail) = {
            let (mut journal, durability) = open_journal(&dir);
            let first = journal
                .prepare_mutation(
                    &enable_request(
                        "mut-1",
                        0xab,
                        JournalIdentity::new(
                            MemoryId::from_bytes([10; 16]),
                            MemoryId::from_bytes([11; 16]),
                            1,
                            1,
                            MemoryId::from_bytes([12; 16]),
                        )
                        .unwrap(),
                    ),
                    &durability,
                )
                .unwrap();
            let second = journal
                .prepare_mutation(
                    &enable_request(
                        "mut-2",
                        0xcd,
                        JournalIdentity::new(
                            MemoryId::from_bytes([10; 16]),
                            MemoryId::from_bytes([11; 16]),
                            2,
                            2,
                            MemoryId::from_bytes([13; 16]),
                        )
                        .unwrap(),
                    ),
                    &durability,
                )
                .unwrap();
            journal
                .prepare_deny(&deny_frame(3, 2), &durability)
                .unwrap();
            (first.tail_hash, second.tail_hash)
        };
        // Reopen: the production binder reads a journal whose retained history
        // the reopen scan verified, never a freshly created handle.
        let (journal, _durability) = {
            let tail = crate::memory_v1_durable_journal::MemoryV1DurableJournal::scan_tail(
                &dir.path(),
                MemoryId::from_bytes([10; 16]),
                MemoryId::from_bytes([11; 16]),
                JournalAnchor::new(MemoryId::from_bytes([10; 16]), 0, 0, [5; 32]).unwrap(),
                crate::memory_v1_durable_journal::DurableJournalLimits::conservative(),
            )
            .unwrap();
            crate::memory_v1_durable_journal::MemoryV1DurableJournal::open(
                &dir.path(),
                MemoryId::from_bytes([10; 16]),
                MemoryId::from_bytes([11; 16]),
                JournalAnchor::new(MemoryId::from_bytes([10; 16]), 0, 0, [5; 32]).unwrap(),
                tail,
                crate::memory_v1_durable_journal::DurableJournalLimits::conservative(),
            )
            .unwrap()
        };

        let rows = fixture_rows();
        let facts = fixture_facts(&rows);
        let cold = ReconciledColdInstall::bind_verified(&journal, rows, facts).unwrap();
        let prefix = cold.prefix.expect("the reconciled prefix binds");
        // The bound anchor is the last mutation's own frame, not the deny tail.
        assert_eq!(prefix.anchor().journal_sequence(), 2);
        assert_eq!(prefix.anchor().mutation_sequence(), 2);
        assert_eq!(prefix.anchor().frame_hash(), &second_tail);
        assert_eq!(prefix.epoch(), journal.epoch_id());
        // The frame tail carried the deny suffix and is not the anchor.
        assert_eq!(journal.position().journal_sequence(), 3);
        assert_eq!(journal.position().mutation_sequence(), 2);
        assert_ne!(prefix.anchor().frame_hash(), &first_tail);

        // Full acceptance on the isolated fixture: the bound candidate installs
        // at the bound position and adopts Serving through the unchanged
        // production evidence gate.
        let rows = fixture_rows();
        let selections = rows.current_version_selections().unwrap();
        let owner = install_isolated_test_root_with_governance_prefix(
            rows,
            selections,
            astral_authorization_root::memory_v1_hamt::CandidateBudget {
                max_table_rows: 32,
                max_bindings_per_read: 4,
            },
            cold.prefix,
        )
        .unwrap();
        owner.install_registry(&fixture_registry()).unwrap();
        let (metadata, admission) = owner
            .adopt_with_production_evidence(&cold.facts, &sealed_input())
            .unwrap();
        assert_eq!(
            metadata.status,
            astral_authorization_root::memory_v1_root::RootStatus::Serving
        );
        let frontier = owner
            .current_governance_frontier(&admission, &metadata)
            .unwrap();
        assert_eq!(frontier, GovernanceFrontier::Published(prefix));
    }

    // memory—v1: The formal process entry consumes the sealed binding, but the
    // production evidence gate keeps refusing while no independent evidence
    // issuer exists for the process root: no partial adoption publishes
    // Serving, and the failure is the gate's own missing-family refusal.
    #[test]
    fn the_process_entry_keeps_the_production_gate_refused() {
        let dir = JournalDir::new("process-gate");
        {
            let (mut journal, durability) = open_journal(&dir);
            journal
                .prepare_mutation(
                    &enable_request(
                        "mut-1",
                        0xab,
                        JournalIdentity::new(
                            MemoryId::from_bytes([10; 16]),
                            MemoryId::from_bytes([11; 16]),
                            1,
                            1,
                            MemoryId::from_bytes([12; 16]),
                        )
                        .unwrap(),
                    ),
                    &durability,
                )
                .unwrap();
        }
        let (journal, _durability) = {
            let tail = crate::memory_v1_durable_journal::MemoryV1DurableJournal::scan_tail(
                &dir.path(),
                MemoryId::from_bytes([10; 16]),
                MemoryId::from_bytes([11; 16]),
                JournalAnchor::new(MemoryId::from_bytes([10; 16]), 0, 0, [5; 32]).unwrap(),
                crate::memory_v1_durable_journal::DurableJournalLimits::conservative(),
            )
            .unwrap();
            crate::memory_v1_durable_journal::MemoryV1DurableJournal::open(
                &dir.path(),
                MemoryId::from_bytes([10; 16]),
                MemoryId::from_bytes([11; 16]),
                JournalAnchor::new(MemoryId::from_bytes([10; 16]), 0, 0, [5; 32]).unwrap(),
                tail,
                crate::memory_v1_durable_journal::DurableJournalLimits::conservative(),
            )
            .unwrap()
        };
        let cold = ReconciledColdInstall::bind_verified(
            &journal,
            fixture_rows(),
            fixture_facts(&fixture_rows()),
        )
        .unwrap();
        assert!(cold.prefix.is_some());

        let error = match cold.install_and_adopt_production(
            test_probe,
            &fixture_registry(),
            &sealed_input(),
        ) {
            Err(error) => error,
            Ok(_) => panic!("the gate must keep refusing on the process root"),
        };
        assert!(
            matches!(
                error,
                ColdInstallError::Install(
                    astral_authorization_root::memory_v1_root::RootError::AdoptionEvidence(
                        astral_authorization_root::memory_v1_adoption::AdoptionEvidenceError::Missing(
                            "source provenance",
                        )
                    )
                )
            ),
            "the gate must keep refusing on the process root: {error:?}"
        );
    }

    // memory—v1: A capture without a complete scan report yields no facts and
    // refuses the cold installation: no complete evidence, no install.
    #[test]
    fn a_capture_without_a_complete_report_is_refused() {
        let error = ReconciledColdInstall::cold_facts_of(None).unwrap_err();
        assert!(
            matches!(error, ColdInstallError::IncompleteCapture),
            "{error:?}"
        );
    }

    // memory—v1: The journal position must be proven, never assumed: reopening
    // against an unproven expected tail is refused, so an unknown position can
    // never reach the binder.
    #[test]
    fn an_unproven_journal_tail_is_refused() {
        let dir = JournalDir::new("unproven-tail");
        {
            let (mut journal, durability) = open_journal(&dir);
            journal
                .prepare_mutation(
                    &enable_request(
                        "mut-1",
                        0xab,
                        JournalIdentity::new(
                            MemoryId::from_bytes([10; 16]),
                            MemoryId::from_bytes([11; 16]),
                            1,
                            1,
                            MemoryId::from_bytes([12; 16]),
                        )
                        .unwrap(),
                    ),
                    &durability,
                )
                .unwrap();
        }
        let tail = crate::memory_v1_durable_journal::MemoryV1DurableJournal::scan_tail(
            &dir.path(),
            MemoryId::from_bytes([10; 16]),
            MemoryId::from_bytes([11; 16]),
            JournalAnchor::new(MemoryId::from_bytes([10; 16]), 0, 0, [5; 32]).unwrap(),
            crate::memory_v1_durable_journal::DurableJournalLimits::conservative(),
        )
        .unwrap();
        // An expected tail that was never proven against this installation is
        // refused before any candidate can bind it.
        let unproven = JournalAnchor::new(
            MemoryId::from_bytes([10; 16]),
            tail.journal_sequence(),
            tail.mutation_sequence(),
            [0x9d; 32],
        )
        .unwrap();
        assert!(
            crate::memory_v1_durable_journal::MemoryV1DurableJournal::open(
                &dir.path(),
                MemoryId::from_bytes([10; 16]),
                MemoryId::from_bytes([11; 16]),
                JournalAnchor::new(MemoryId::from_bytes([10; 16]), 0, 0, [5; 32]).unwrap(),
                unproven,
                crate::memory_v1_durable_journal::DurableJournalLimits::conservative(),
            )
            .is_err()
        );
    }

    // memory—v1: The isolated cold-install entry installs the candidate at the
    // exact bound position without adoption, for offline contract tests.
    #[test]
    fn the_isolated_entry_installs_the_exact_prefix() {
        let rows = fixture_rows();
        let selections = rows.current_version_selections().unwrap();
        let anchor = JournalAnchor::new(MemoryId::from_bytes([10; 16]), 4, 4, [0x77; 32]).unwrap();
        let prefix = GovernancePrefix::new(anchor, MemoryId::from_bytes([11; 16])).unwrap();
        let owner = install_isolated_test_root_with_governance_prefix(
            rows,
            selections,
            astral_authorization_root::memory_v1_hamt::CandidateBudget {
                max_table_rows: 32,
                max_bindings_per_read: 4,
            },
            Some(prefix),
        )
        .unwrap();
        assert_eq!(
            owner.candidate_governance_frontier().unwrap(),
            GovernanceFrontier::Published(prefix)
        );
    }
}

// memory—v1: The real-MySQL cold-install recovery integration (ignored),
// wired as a child module so it can read the binding's private fields.
#[cfg(test)]
mod mysql_recovery_tests;
