//! memory—v1: UUID-native protected purchase mutation contract.
//!
//! This module is an isolated contract seam. It does not mount an HTTP route,
//! call the legacy integer purchase repository, or adapt to `AuthorizationAdmission`
//! / `ProtectedMutationContext`. A durable owner must add its own transaction,
//! audit, recovery and crash reconciliation implementation before this contract can
//! be used for a production mutation.

use std::collections::HashMap;
use std::sync::Mutex;

use astral_authorization_root::memory_v1_request::RequestRootExtension;
use astral_authorization_root::memory_v1_root::{RootMetadata, RootStatus};
use astral_authorization_root::memory_v1_session::RequestSessionExtension;
use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use policy_engine::memory_v1_formal::MemoryV1Admission;
use sha2::{Digest, Sha256};
use thiserror::Error;

const PURCHASE_RESOURCE: &str = "memory-v1-purchase";
const PURCHASE_ACTION: &str = "create";
const COMMAND_HASH_DOMAIN: &[u8] = b"astrallight/memory-v1/purchase-command/1\0";
const INTENT_HASH_DOMAIN: &[u8] = b"astrallight/memory-v1/purchase-intent/1\0";
const MAX_LEDGER_ENTRIES: usize = 100_000;

/// memory—v1: The only billing-cycle values accepted by the isolated purchase
/// command contract. This enum is independent of the legacy integer purchase API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MemoryV1BillingCycle {
    Monthly,
    Quarterly,
    Yearly,
}

impl MemoryV1BillingCycle {
    /// memory—v1: Encode the closed billing-cycle vocabulary for canonical hashing.
    fn tag(self) -> u8 {
        match self {
            Self::Monthly => 1,
            Self::Quarterly => 2,
            Self::Yearly => 3,
        }
    }
}

/// memory—v1: Server-side purchase input used to derive a stable command digest.
/// The digest is an integrity binding, not an authorization proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryV1PurchaseCommand {
    package_id: MemoryId,
    billing_cycle: MemoryV1BillingCycle,
}

impl MemoryV1PurchaseCommand {
    /// memory—v1: Construct a UUID-native purchase command.
    /// All-zero IDs are rejected as invalid business input even though
    /// `MemoryId` can represent them.
    pub fn new(
        package_id: MemoryId,
        billing_cycle: MemoryV1BillingCycle,
    ) -> Result<Self, MemoryV1MutationError> {
        if is_zero(package_id) {
            return Err(MemoryV1MutationError::InvalidInput("package_id"));
        }
        Ok(Self {
            package_id,
            billing_cycle,
        })
    }

    pub fn package_id(&self) -> MemoryId {
        self.package_id
    }

    pub fn billing_cycle(&self) -> MemoryV1BillingCycle {
        self.billing_cycle
    }

    /// memory—v1: Compute the canonical, domain-separated command digest.
    pub fn command_digest(&self) -> [u8; 32] {
        let mut frame = Vec::with_capacity(COMMAND_HASH_DOMAIN.len() + 24);
        frame.extend_from_slice(COMMAND_HASH_DOMAIN);
        append_bytes(&mut frame, self.package_id.as_bytes());
        frame.push(self.billing_cycle.tag());
        Sha256::digest(frame).into()
    }
}

/// Stable idempotency key for one UUID-native mutation in one tenant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MemoryV1OperationKey {
    tenant_id: MemoryId,
    operation_id: MemoryId,
}

impl MemoryV1OperationKey {
    pub fn tenant_id(&self) -> MemoryId {
        self.tenant_id
    }

    pub fn operation_id(&self) -> MemoryId {
        self.operation_id
    }
}

/// memory—v1: UUID-native purchase intent with a server-computed fingerprint.
/// The operation ID is the replay key; the fingerprint excludes it so a new
/// operation can represent the same command without making an old operation's
/// retry appear to be a changed payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryV1PurchaseIntent {
    key: MemoryV1OperationKey,
    actor: CandidateIdentity,
    command: MemoryV1PurchaseCommand,
    command_digest: [u8; 32],
    fingerprint: [u8; 32],
}

impl MemoryV1PurchaseIntent {
    /// Construct an intent from trusted server-side UUID facts and a command.
    /// The caller must still obtain a matching `MemoryV1Admission` from the
    /// PolicyEngine; this constructor does not authorize anything.
    pub fn new(
        operation_id: MemoryId,
        actor: CandidateIdentity,
        command: MemoryV1PurchaseCommand,
    ) -> Result<Self, MemoryV1MutationError> {
        if is_zero(operation_id) {
            return Err(MemoryV1MutationError::InvalidInput("operation_id"));
        }
        if is_zero(actor.user_id)
            || is_zero(actor.identity_card_id)
            || is_zero(actor.user_card_id)
            || is_zero(actor.tenant_id)
        {
            return Err(MemoryV1MutationError::InvalidInput("actor"));
        }
        let command_digest = command.command_digest();
        let fingerprint = intent_digest(actor, command, command_digest);
        Ok(Self {
            key: MemoryV1OperationKey {
                tenant_id: actor.tenant_id,
                operation_id,
            },
            actor,
            command,
            command_digest,
            fingerprint,
        })
    }

    pub fn key(&self) -> MemoryV1OperationKey {
        self.key
    }

    pub fn actor(&self) -> CandidateIdentity {
        self.actor
    }

    pub fn tenant_id(&self) -> MemoryId {
        self.key.tenant_id
    }

    pub fn operation_id(&self) -> MemoryId {
        self.key.operation_id
    }

    pub fn command(&self) -> MemoryV1PurchaseCommand {
        self.command
    }

    pub fn command_digest(&self) -> [u8; 32] {
        self.command_digest
    }

    /// The exact bytes that must be supplied as `MemoryV1Request`'s operation
    /// fingerprint and then returned by `MemoryV1Admission`.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    pub fn resource(&self) -> &'static str {
        PURCHASE_RESOURCE
    }

    pub fn action(&self) -> &'static str {
        PURCHASE_ACTION
    }
}

/// Exact binding captured after an admission and request session are rechecked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryV1MutationBinding {
    key: MemoryV1OperationKey,
    actor: CandidateIdentity,
    package_id: MemoryId,
    fingerprint: [u8; 32],
    root: RootMetadata,
    trusted_time_unix_seconds: i64,
}

impl MemoryV1MutationBinding {
    pub fn key(&self) -> MemoryV1OperationKey {
        self.key
    }

    pub fn actor(&self) -> CandidateIdentity {
        self.actor
    }

    pub fn package_id(&self) -> MemoryId {
        self.package_id
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    pub fn root(&self) -> RootMetadata {
        self.root
    }

    pub fn trusted_time_unix_seconds(&self) -> i64 {
        self.trusted_time_unix_seconds
    }
}

/// Audit durability is intentionally distinct from business completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryV1AuditState {
    Recorded,
    Pending,
    Unknown,
}

/// Failures while binding a UUID-native mutation to a fresh admission/session.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum MemoryV1MutationError {
    #[error("memory-v1 mutation input is invalid: {0}")]
    InvalidInput(&'static str),
    #[error("memory-v1 mutation admission does not match the intent: {0}")]
    AdmissionMismatch(&'static str),
    #[error("memory-v1 mutation root is not serving")]
    RootNotServing,
    #[error("memory-v1 mutation root changed or is unavailable")]
    RootChanged,
    #[error("memory-v1 mutation session is unavailable or expired")]
    SessionUnavailable,
    #[error("memory-v1 mutation ledger capacity is exhausted")]
    CapacityExhausted,
    #[error("memory-v1 mutation ledger is poisoned")]
    LedgerPoisoned,
    #[error("memory-v1 mutation lease is no longer active")]
    LeaseClosed,
}

/// Validate every binding that a future UUID-native purchase owner must enforce.
/// This function performs no source mutation and never adapts to a legacy proof.
pub fn validate_purchase_admission(
    root: &RequestRootExtension,
    session: &RequestSessionExtension,
    intent: &MemoryV1PurchaseIntent,
    admission: &MemoryV1Admission,
    now_unix_seconds: i64,
) -> Result<MemoryV1MutationBinding, MemoryV1MutationError> {
    let admission_root = admission.root();
    if admission_root.status != RootStatus::Serving {
        return Err(MemoryV1MutationError::RootNotServing);
    }
    if admission.identity() != intent.actor {
        return Err(MemoryV1MutationError::AdmissionMismatch("actor"));
    }
    if admission.resource() != PURCHASE_RESOURCE {
        return Err(MemoryV1MutationError::AdmissionMismatch("resource"));
    }
    if admission.action() != PURCHASE_ACTION {
        return Err(MemoryV1MutationError::AdmissionMismatch("action"));
    }
    if admission.operation_id() != intent.operation_id().as_bytes() {
        return Err(MemoryV1MutationError::AdmissionMismatch("operation_id"));
    }
    if admission.operation_fingerprint() != intent.fingerprint() {
        return Err(MemoryV1MutationError::AdmissionMismatch("fingerprint"));
    }
    if admission.target() != Some(intent.command.package_id().as_bytes().as_slice()) {
        return Err(MemoryV1MutationError::AdmissionMismatch("target"));
    }
    if now_unix_seconds < admission.trusted_time_unix_seconds() {
        return Err(MemoryV1MutationError::RootChanged);
    }

    session
        .with_context(root, |facts, reader| {
            if facts.candidate_identity() != intent.actor || !facts.valid_at(now_unix_seconds) {
                return Err(MemoryV1MutationError::SessionUnavailable);
            }
            if reader.metadata() != admission_root || !matches!(reader.is_current(), Ok(true)) {
                return Err(MemoryV1MutationError::RootChanged);
            }
            Ok(MemoryV1MutationBinding {
                key: intent.key,
                actor: intent.actor,
                package_id: intent.command.package_id(),
                fingerprint: intent.fingerprint,
                root: admission_root,
                trusted_time_unix_seconds: now_unix_seconds,
            })
        })
        .map_err(|_| MemoryV1MutationError::SessionUnavailable)?
}

/// A lease returned for a new operation claim. It is consumed by completion or
/// unknown-commit marking and cannot be reused after either transition.
pub struct MemoryV1MutationLease {
    key: MemoryV1OperationKey,
    fingerprint: [u8; 32],
}

impl MemoryV1MutationLease {
    pub fn key(&self) -> MemoryV1OperationKey {
        self.key
    }
}

/// Result of claiming one stable operation key.
pub enum MemoryV1MutationClaim<R> {
    New(MemoryV1MutationLease),
    Replayed {
        result: R,
        audit: MemoryV1AuditState,
    },
    InFlight,
    Conflict,
    UnknownCommit,
}

/// Result of consulting the local operation ledger. Missing durable evidence is
/// intentionally `Unknown`; this type never invents `NotCommitted`.
pub enum MemoryV1Reconciliation<R> {
    Committed {
        result: R,
        audit: MemoryV1AuditState,
    },
    InFlight,
    Unknown,
}

enum LedgerEntry<R> {
    InFlight {
        fingerprint: [u8; 32],
    },
    Completed {
        fingerprint: [u8; 32],
        result: R,
        audit: MemoryV1AuditState,
    },
    Unknown {
        fingerprint: [u8; 32],
    },
}

/// Bounded-scope in-process idempotency ledger for the contract tests and a
/// future owner seam. It is not durable: after restart, a real owner must query
/// authoritative operation evidence and keep the result UNKNOWN when absent.
pub struct MemoryV1MutationLedger<R> {
    entries: Mutex<HashMap<MemoryV1OperationKey, LedgerEntry<R>>>,
}

impl<R> Default for MemoryV1MutationLedger<R> {
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl<R: Clone> MemoryV1MutationLedger<R> {
    /// Claim a key, replay a proven completion, or preserve an unresolved commit.
    pub fn claim(
        &self,
        binding: &MemoryV1MutationBinding,
    ) -> Result<MemoryV1MutationClaim<R>, MemoryV1MutationError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| MemoryV1MutationError::LedgerPoisoned)?;
        match entries.get(&binding.key) {
            None => {
                if entries.len() >= MAX_LEDGER_ENTRIES {
                    return Err(MemoryV1MutationError::CapacityExhausted);
                }
                entries.insert(
                    binding.key,
                    LedgerEntry::InFlight {
                        fingerprint: binding.fingerprint,
                    },
                );
                Ok(MemoryV1MutationClaim::New(MemoryV1MutationLease {
                    key: binding.key,
                    fingerprint: binding.fingerprint,
                }))
            }
            Some(LedgerEntry::InFlight { fingerprint }) => {
                if *fingerprint == binding.fingerprint {
                    Ok(MemoryV1MutationClaim::InFlight)
                } else {
                    Ok(MemoryV1MutationClaim::Conflict)
                }
            }
            Some(LedgerEntry::Completed {
                fingerprint,
                result,
                audit,
            }) => {
                if *fingerprint == binding.fingerprint {
                    Ok(MemoryV1MutationClaim::Replayed {
                        result: result.clone(),
                        audit: *audit,
                    })
                } else {
                    Ok(MemoryV1MutationClaim::Conflict)
                }
            }
            Some(LedgerEntry::Unknown { fingerprint }) => {
                if *fingerprint == binding.fingerprint {
                    Ok(MemoryV1MutationClaim::UnknownCommit)
                } else {
                    Ok(MemoryV1MutationClaim::Conflict)
                }
            }
        }
    }

    /// Record a result only for the exact active lease.
    pub fn complete(
        &self,
        lease: MemoryV1MutationLease,
        result: R,
        audit: MemoryV1AuditState,
    ) -> Result<(), MemoryV1MutationError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| MemoryV1MutationError::LedgerPoisoned)?;
        match entries.get(&lease.key) {
            Some(LedgerEntry::InFlight { fingerprint }) if *fingerprint == lease.fingerprint => {
                entries.insert(
                    lease.key,
                    LedgerEntry::Completed {
                        fingerprint: lease.fingerprint,
                        result,
                        audit,
                    },
                );
                Ok(())
            }
            _ => Err(MemoryV1MutationError::LeaseClosed),
        }
    }

    /// Preserve uncertainty after a transport or commit error. The operation
    /// remains blocked until authoritative reconciliation changes its state.
    pub fn mark_unknown(&self, lease: MemoryV1MutationLease) -> Result<(), MemoryV1MutationError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| MemoryV1MutationError::LedgerPoisoned)?;
        match entries.get(&lease.key) {
            Some(LedgerEntry::InFlight { fingerprint }) if *fingerprint == lease.fingerprint => {
                entries.insert(
                    lease.key,
                    LedgerEntry::Unknown {
                        fingerprint: lease.fingerprint,
                    },
                );
                Ok(())
            }
            _ => Err(MemoryV1MutationError::LeaseClosed),
        }
    }

    /// Consult only the local evidence. An absent key is UNKNOWN because this
    /// in-memory ledger cannot prove that an earlier durable attempt did not run.
    pub fn reconcile(
        &self,
        key: MemoryV1OperationKey,
    ) -> Result<MemoryV1Reconciliation<R>, MemoryV1MutationError> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| MemoryV1MutationError::LedgerPoisoned)?;
        Ok(match entries.get(&key) {
            Some(LedgerEntry::InFlight { .. }) => MemoryV1Reconciliation::InFlight,
            Some(LedgerEntry::Unknown { .. }) | None => MemoryV1Reconciliation::Unknown,
            Some(LedgerEntry::Completed { result, audit, .. }) => {
                MemoryV1Reconciliation::Committed {
                    result: result.clone(),
                    audit: *audit,
                }
            }
        })
    }
}

fn is_zero(id: MemoryId) -> bool {
    id.as_bytes() == &[0; 16]
}

fn append_bytes(frame: &mut Vec<u8>, bytes: &[u8]) {
    frame.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    frame.extend_from_slice(bytes);
}

fn intent_digest(
    actor: CandidateIdentity,
    command: MemoryV1PurchaseCommand,
    command_digest: [u8; 32],
) -> [u8; 32] {
    let mut frame = Vec::with_capacity(256);
    frame.extend_from_slice(INTENT_HASH_DOMAIN);
    append_bytes(&mut frame, PURCHASE_RESOURCE.as_bytes());
    append_bytes(&mut frame, PURCHASE_ACTION.as_bytes());
    append_bytes(&mut frame, actor.user_id.as_bytes());
    append_bytes(&mut frame, actor.identity_card_id.as_bytes());
    append_bytes(&mut frame, actor.user_card_id.as_bytes());
    append_bytes(&mut frame, actor.tenant_id.as_bytes());
    append_bytes(&mut frame, command.package_id().as_bytes());
    frame.push(command.billing_cycle().tag());
    append_bytes(&mut frame, &command_digest);
    Sha256::digest(frame).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: u8) -> MemoryId {
        MemoryId::from_bytes([value; 16])
    }

    fn actor() -> CandidateIdentity {
        CandidateIdentity {
            user_id: id(1),
            identity_card_id: id(2),
            user_card_id: id(3),
            tenant_id: id(4),
        }
    }

    fn intent(operation: u8, package: u8) -> MemoryV1PurchaseIntent {
        MemoryV1PurchaseIntent::new(
            id(operation),
            actor(),
            MemoryV1PurchaseCommand::new(id(package), MemoryV1BillingCycle::Monthly).unwrap(),
        )
        .unwrap()
    }

    fn binding(operation: u8, package: u8) -> MemoryV1MutationBinding {
        let intent = intent(operation, package);
        MemoryV1MutationBinding {
            key: intent.key(),
            actor: intent.actor(),
            package_id: intent.command().package_id(),
            fingerprint: intent.fingerprint(),
            root: RootMetadata {
                instance_id: astral_authorization_root::memory_v1_root::RootInstanceId::from_uuid(
                    uuid::Uuid::from_bytes([9; 16]),
                ),
                version: 1,
                digest: [8; 32],
                budget: astral_authorization_root::memory_v1_hamt::CandidateBudget {
                    max_table_rows: 1,
                    max_bindings_per_read: 1,
                },
                row_count: 1,
                status: RootStatus::Serving,
            },
            trusted_time_unix_seconds: 100,
        }
    }

    #[test]
    fn canonical_purchase_fingerprint_changes_with_payload() {
        let first = intent(7, 8);
        let same = intent(7, 8);
        let changed = intent(7, 9);
        assert_eq!(first.command_digest(), same.command_digest());
        assert_eq!(first.fingerprint(), same.fingerprint());
        assert_ne!(first.fingerprint(), changed.fingerprint());
        assert_eq!(first.operation_id(), id(7));
        assert_eq!(first.tenant_id(), id(4));
    }

    #[test]
    fn mutation_ledger_replays_conflicts_and_preserves_unknown() {
        let ledger = MemoryV1MutationLedger::<String>::default();
        let first_binding = binding(7, 8);
        let lease = match ledger.claim(&first_binding).unwrap() {
            MemoryV1MutationClaim::New(lease) => lease,
            _ => panic!("first claim must be new"),
        };
        assert!(matches!(
            ledger.claim(&first_binding).unwrap(),
            MemoryV1MutationClaim::InFlight
        ));
        assert!(matches!(
            ledger.claim(&binding(7, 9)).unwrap(),
            MemoryV1MutationClaim::Conflict
        ));
        ledger
            .complete(lease, "purchase-1".to_owned(), MemoryV1AuditState::Recorded)
            .unwrap();
        match ledger.claim(&first_binding).unwrap() {
            MemoryV1MutationClaim::Replayed { result, audit } => {
                assert_eq!(result, "purchase-1");
                assert_eq!(audit, MemoryV1AuditState::Recorded);
            }
            _ => panic!("completed claim must replay"),
        }

        let unknown_binding = binding(9, 8);
        let unknown_lease = match ledger.claim(&unknown_binding).unwrap() {
            MemoryV1MutationClaim::New(lease) => lease,
            _ => panic!("second key must be new"),
        };
        ledger.mark_unknown(unknown_lease).unwrap();
        assert!(matches!(
            ledger.claim(&unknown_binding).unwrap(),
            MemoryV1MutationClaim::UnknownCommit
        ));
        assert!(matches!(
            ledger.reconcile(unknown_binding.key()).unwrap(),
            MemoryV1Reconciliation::Unknown
        ));
        assert!(matches!(
            ledger.reconcile(first_binding.key()).unwrap(),
            MemoryV1Reconciliation::Committed { .. }
        ));
    }

    #[test]
    fn invalid_business_ids_are_rejected_without_legacy_conversion() {
        assert!(matches!(
            MemoryV1PurchaseCommand::new(
                MemoryId::from_bytes([0; 16]),
                MemoryV1BillingCycle::Monthly
            ),
            Err(MemoryV1MutationError::InvalidInput("package_id"))
        ));
        assert!(matches!(
            MemoryV1PurchaseIntent::new(
                MemoryId::from_bytes([0; 16]),
                actor(),
                MemoryV1PurchaseCommand::new(id(8), MemoryV1BillingCycle::Monthly).unwrap()
            ),
            Err(MemoryV1MutationError::InvalidInput("operation_id"))
        ));
    }
}
