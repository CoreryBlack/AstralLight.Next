//! Offline structural plans for memory—v1 confirmation batches.
//!
//! A plan is only a value: it is not an authorization, a restricted commit,
//! a CAS, replay protection, a request-body proof, or durable audit. The batch
//! evaluator's fingerprint is caller-supplied and is recorded as such. Its
//! admission does not contain target version or scope facts; this module does
//! not verify version existence/currentness, scope meaning, or confirmation
//! validity against the root. Those must be established by a future governance
//! contract before any use in a commit path.
//!
//! For this local candidate API, version and scope are nonempty bounded opaque
//! bytes, and the time is the evaluator's final trusted Unix second encoded as
//! exactly eight big-endian bytes. These are local construction constraints,
//! not a database or external protocol. No scope or version byte encoding is
//! specified by the current confirmation-row contract.

use astral_authorization_root::memory_v1_db_rows::BindingConfirmationRow;
use astral_authorization_root::memory_v1_mutation_digest::{digest_mutation, MutationDigest};
use astral_authorization_root::memory_v1_root::{ManagementMutationV2, RootMetadata, RootStatus};
use astral_authorization_root::memory_v1_rules::version_digest;
use astral_types::memory_v1::CandidateIdentity;

use crate::memory_v1_batch::{MemoryV1BatchAdmission, MAX_MEMORY_V1_BINDING_CONFIRMATION_BATCH};

const DOMAIN: &[u8] = b"astrallight/memory-v1/confirmation-batch-plan-value/1\0";
/// Local candidate limit, matching the candidate schema's version column.
pub const MAX_BATCH_PLAN_VERSION_BYTES: usize = 255;
/// Local resource bound, not a definition of scope semantics.
pub const MAX_BATCH_PLAN_SCOPE_BYTES: usize = 4096;

/// Caller-supplied confirmation and its explicit evaluator sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryV1BatchPlanItem {
    pub sequence: u32,
    pub confirmation: BindingConfirmationRow,
}

/// Structural candidate construction failed; no mutation was executed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryV1BatchPlanError {
    InvalidCount,
    TargetMismatch,
    InvalidConfirmation,
    InvalidTime,
    DigestUnavailable,
}

/// Immutable local value binding the observation to a complete candidate mutation.
#[derive(Clone, Debug)]
pub struct MemoryV1BatchPlan {
    admission: MemoryV1BatchAdmission,
    mutation: ManagementMutationV2,
    mutation_digest: MutationDigest,
    digest: [u8; 32],
}

impl MemoryV1BatchPlan {
    /// memory—v1: Construct a structural candidate from an evaluator admission.
    ///
    /// This checks the complete row fields against the *available* admission
    /// fields and local bounds. It cannot establish the missing root facts or
    /// link the caller-supplied fingerprint to an HTTP request body.
    pub fn new(
        admission: &MemoryV1BatchAdmission,
        items: &[MemoryV1BatchPlanItem],
    ) -> Result<Self, MemoryV1BatchPlanError> {
        let targets = admission.targets();
        if items.is_empty()
            || items.len() > MAX_MEMORY_V1_BINDING_CONFIRMATION_BATCH
            || items.len() != targets.len()
        {
            return Err(MemoryV1BatchPlanError::InvalidCount);
        }
        if admission.root().status != RootStatus::Serving {
            return Err(MemoryV1BatchPlanError::TargetMismatch);
        }
        let time = admission.trusted_time_unix_seconds();
        if time < 0 {
            return Err(MemoryV1BatchPlanError::InvalidTime);
        }
        for (index, (item, target)) in items.iter().zip(targets).enumerate() {
            let row = &item.confirmation;
            if item.sequence as usize != index
                || item.sequence != target.item.sequence
                || row.binding_id != target.item.binding_id
                || row.confirmation_id != target.item.confirmation_id
                || row.rule_set_id != target.rule_set_id
            {
                return Err(MemoryV1BatchPlanError::TargetMismatch);
            }
            if row.confirmer_user_id != admission.identity().user_id.into_bytes()
                || row.operation_id != admission.operation_id()
                || row.revoked_at.is_some()
                || row.revoked_by.is_some()
                || row.version_bytes.is_empty()
                || row.version_bytes.len() > MAX_BATCH_PLAN_VERSION_BYTES
                || row.scope_bytes.is_empty()
                || row.scope_bytes.len() > MAX_BATCH_PLAN_SCOPE_BYTES
            {
                return Err(MemoryV1BatchPlanError::InvalidConfirmation);
            }
            if row.confirmed_at_bytes.as_slice() != time.to_be_bytes() {
                return Err(MemoryV1BatchPlanError::InvalidTime);
            }
        }
        let mutation = ManagementMutationV2::ConfirmationBatch {
            rows: items.iter().map(|item| item.confirmation.clone()).collect(),
        };
        let mutation_digest =
            digest_mutation(&mutation).map_err(|_| MemoryV1BatchPlanError::DigestUnavailable)?;
        let digest = plan_digest(admission, mutation_digest)?;
        Ok(Self {
            admission: admission.clone(),
            mutation,
            mutation_digest,
            digest,
        })
    }

    /// memory—v1: Return the root metadata observed by the evaluator.
    pub fn root(&self) -> RootMetadata {
        self.admission.root()
    }

    /// memory—v1: Return the evaluator's identity observation.
    pub fn identity(&self) -> CandidateIdentity {
        self.admission.identity()
    }

    /// memory—v1: Return the caller-supplied evaluator fingerprint.
    pub fn operation_fingerprint(&self) -> &[u8] {
        self.admission.operation_fingerprint()
    }

    /// memory—v1: Borrow the candidate value; this does not grant execution.
    pub fn mutation(&self) -> &ManagementMutationV2 {
        &self.mutation
    }

    /// memory—v1: Return the domain-separated digest of the complete mutation.
    pub fn mutation_digest(&self) -> MutationDigest {
        self.mutation_digest
    }

    /// memory—v1: Return the local context-and-mutation value digest.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// memory—v1: Compare proposed values with this immutable plan and digest.
    ///
    /// This is a value comparison only; it does not prove origin, freshness,
    /// request integrity, authorization, or replay resistance.
    pub fn matches(&self, items: &[MemoryV1BatchPlanItem], claimed_digest: &[u8; 32]) -> bool {
        if claimed_digest != &self.digest {
            return false;
        }
        Self::new(&self.admission, items).is_ok_and(|candidate| candidate.digest == self.digest)
    }
}

// memory—v1: Hash a bounded, domain-separated, unambiguous local context encoding.
fn plan_digest(
    admission: &MemoryV1BatchAdmission,
    mutation_digest: MutationDigest,
) -> Result<[u8; 32], MemoryV1BatchPlanError> {
    let root = admission.root();
    let identity = admission.identity();
    let mut bytes = Vec::with_capacity(256 + admission.targets().len() * 100);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(root.instance_id.as_uuid().as_bytes());
    bytes.extend_from_slice(&root.version.to_be_bytes());
    bytes.extend_from_slice(&root.digest);
    for n in [
        root.budget.max_table_rows,
        root.budget.max_bindings_per_read,
        root.row_count,
    ] {
        bytes.extend_from_slice(
            &u64::try_from(n)
                .map_err(|_| MemoryV1BatchPlanError::DigestUnavailable)?
                .to_be_bytes(),
        );
    }
    // Construction accepts only Serving, encoded as an explicit stable tag.
    bytes.push(1);
    for id in [
        identity.user_id,
        identity.identity_card_id,
        identity.user_card_id,
        identity.tenant_id,
    ] {
        bytes.extend_from_slice(id.as_bytes());
    }
    for value in [admission.operation_id(), admission.operation_fingerprint()] {
        bytes.extend_from_slice(
            &u64::try_from(value.len())
                .map_err(|_| MemoryV1BatchPlanError::DigestUnavailable)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(value);
    }
    bytes.extend_from_slice(&admission.trusted_time_unix_seconds().to_be_bytes());
    bytes.extend_from_slice(
        &u64::try_from(admission.targets().len())
            .map_err(|_| MemoryV1BatchPlanError::DigestUnavailable)?
            .to_be_bytes(),
    );
    for target in admission.targets() {
        bytes.extend_from_slice(&target.item.sequence.to_be_bytes());
        for id in [
            target.item.binding_id,
            target.item.confirmation_id,
            target.user_card_id,
            target.rule_set_id,
            target.beneficiary_user_id,
            target.tenant_id,
        ] {
            bytes.extend_from_slice(&id);
        }
    }
    bytes.extend_from_slice(&mutation_digest);
    version_digest(&bytes)
        .try_into()
        .map_err(|_| MemoryV1BatchPlanError::DigestUnavailable)
}
