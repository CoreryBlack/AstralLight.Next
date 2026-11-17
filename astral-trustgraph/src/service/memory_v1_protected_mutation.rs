//! memory—v1: UUID-native protected purchase mutation contract.
//!
//! This module is an isolated contract seam. It does not mount an HTTP route,
//! call the legacy integer purchase repository, or adapt to `AuthorizationAdmission`
//! / `ProtectedMutationContext`. A durable owner must add its own transaction,
//! audit, recovery and crash reconciliation implementation before this contract can
//! be used for a production mutation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use astral_authorization_root::memory_v1_request::RequestRootExtension;
use astral_authorization_root::memory_v1_root::{RootMetadata, RootStatus};
use astral_authorization_root::memory_v1_session::RequestSessionExtension;
use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use policy_engine::memory_v1_formal::{MemoryV1Admission, MemoryV1Request};
use sha2::{Digest, Sha256};
use thiserror::Error;

const PURCHASE_RESOURCE: &str = "memory-v1-purchase";
const PURCHASE_ACTION: &str = "create";
const COMMAND_HASH_DOMAIN: &[u8] = b"astrallight/memory-v1/purchase-command/1\0";
const INTENT_HASH_DOMAIN: &[u8] = b"astrallight/memory-v1/purchase-intent/1\0";
const SCOPED_INTENT_HASH_DOMAIN: &[u8] = b"astrallight/memory-v1/purchase-scoped-intent/1\0";
// Matches the engine's per-attribution input budget; absence and empty remain distinct.
const MAX_SCOPE_BYTES: usize = 4096;
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

/// memory—v1: An owned, immutable scope-bound purchase intent. The supplied
/// scope is a claim, not proof of actual business attribution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryV1ScopedPurchaseIntent {
    intent: MemoryV1PurchaseIntent,
    target_tenant: Option<Vec<u8>>,
    target_owner: Option<Vec<u8>>,
    fingerprint: [u8; 32],
}

impl MemoryV1ScopedPurchaseIntent {
    /// memory—v1: Freeze bounded scope bytes before authorization evaluation.
    pub fn new(
        intent: MemoryV1PurchaseIntent,
        scope: MemoryV1PurchaseScope<'_>,
    ) -> Result<Self, MemoryV1MutationError> {
        for (name, value) in [
            ("target_tenant", scope.target_tenant),
            ("target_owner", scope.target_owner),
        ] {
            if value.is_some_and(|bytes| bytes.len() > MAX_SCOPE_BYTES) {
                return Err(MemoryV1MutationError::InvalidInput(name));
            }
        }
        let fingerprint = scoped_intent_digest(&intent, scope);
        Ok(Self {
            intent,
            target_tenant: scope.target_tenant.map(<[u8]>::to_vec),
            target_owner: scope.target_owner.map(<[u8]>::to_vec),
            fingerprint,
        })
    }

    /// memory—v1: Return the legacy intent, whose fingerprint is not scope-bound.
    pub fn intent(&self) -> MemoryV1PurchaseIntent {
        self.intent
    }

    /// memory—v1: Borrow the exact scope captured at construction.
    pub fn scope(&self) -> MemoryV1PurchaseScope<'_> {
        MemoryV1PurchaseScope {
            target_tenant: self.target_tenant.as_deref(),
            target_owner: self.target_owner.as_deref(),
        }
    }

    /// memory—v1: Return the versioned fingerprint for engine evaluation.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// memory—v1: Construct the engine request from the same frozen values.
    pub fn request(&self) -> MemoryV1Request<'_> {
        MemoryV1Request {
            resource: PURCHASE_RESOURCE,
            action: PURCHASE_ACTION,
            target: Some(self.intent.command.package_id.as_bytes()),
            target_tenant: self.target_tenant.as_deref(),
            target_owner: self.target_owner.as_deref(),
            operation_id: self.intent.key.operation_id.as_bytes(),
            operation_fingerprint: &self.fingerprint,
        }
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

/// memory—v1: Validate the purchase admission against the request and live session.
/// This compatibility candidate does **not** check `target_tenant` or
/// `target_owner` and must not be used to authorize a purchase mutation. Use
/// [`validate_purchase_admission_with_scope`] for explicit scope binding.
/// This function performs no source mutation and never adapts to a legacy proof.
/// Session revocation can occur after this observation; it is not an atomic
/// commit barrier. A business owner must recheck authorization, session and root
/// at its commit boundary and provide audit and persistence guarantees.
pub fn validate_purchase_admission(
    root: &RequestRootExtension,
    session: &RequestSessionExtension,
    intent: &MemoryV1PurchaseIntent,
    admission: &MemoryV1Admission,
    now_unix_seconds: i64,
) -> Result<MemoryV1MutationBinding, MemoryV1MutationError> {
    validate_purchase_admission_fingerprint(
        root,
        session,
        intent,
        admission,
        intent.fingerprint(),
        now_unix_seconds,
    )
}

// memory—v1: Share the live-session and exact admission checks across versions.
fn validate_purchase_admission_fingerprint(
    root: &RequestRootExtension,
    session: &RequestSessionExtension,
    intent: &MemoryV1PurchaseIntent,
    admission: &MemoryV1Admission,
    fingerprint: [u8; 32],
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
    if admission.operation_fingerprint() != fingerprint {
        return Err(MemoryV1MutationError::AdmissionMismatch("fingerprint"));
    }
    if admission.target() != Some(intent.command.package_id().as_bytes().as_slice()) {
        return Err(MemoryV1MutationError::AdmissionMismatch("target"));
    }
    if now_unix_seconds < admission.trusted_time_unix_seconds() {
        return Err(MemoryV1MutationError::RootChanged);
    }

    session
        .revalidate_authority(root, now_unix_seconds)
        .map_err(|_| MemoryV1MutationError::SessionUnavailable)?;

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
                fingerprint,
                root: admission_root,
                trusted_time_unix_seconds: now_unix_seconds,
            })
        })
        .map_err(|_| MemoryV1MutationError::SessionUnavailable)?
}

/// memory—v1: Expected target attribution supplied by the owning business service.
/// `None` is an explicit absence, not proof that an attribution does not exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryV1PurchaseScope<'a> {
    /// Expected tenant bytes, including whether they were supplied.
    pub target_tenant: Option<&'a [u8]>,
    /// Expected owner bytes, including whether they were supplied.
    pub target_owner: Option<&'a [u8]>,
}

/// memory—v1: Bind caller-supplied target attribution exactly to the admission,
/// then perform the existing intent, root and live-session checks.
///
/// The business owner must establish the truth and completeness of the expected
/// attribution independently; this comparison cannot establish either. It must
/// recheck attribution, authorization, session and root at the commit boundary,
/// and provide atomicity, replay protection, audit and persistence. This legacy
/// binding and legacy fingerprint do not carry the compared scope into the ledger;
/// use [`MemoryV1ScopedPurchaseIntent`] and [`validate_scoped_purchase_admission`]
/// for the scope-bound candidate. This isolated candidate is not a production
/// mutation or commit capability.
pub fn validate_purchase_admission_with_scope(
    root: &RequestRootExtension,
    session: &RequestSessionExtension,
    intent: &MemoryV1PurchaseIntent,
    admission: &MemoryV1Admission,
    expected: MemoryV1PurchaseScope<'_>,
    now_unix_seconds: i64,
) -> Result<MemoryV1MutationBinding, MemoryV1MutationError> {
    if admission.target_tenant() != expected.target_tenant {
        return Err(MemoryV1MutationError::AdmissionMismatch("target_tenant"));
    }
    if admission.target_owner() != expected.target_owner {
        return Err(MemoryV1MutationError::AdmissionMismatch("target_owner"));
    }
    validate_purchase_admission(root, session, intent, admission, now_unix_seconds)
}

/// memory—v1: A scoped binding is an observation, not a commit capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryV1ScopedMutationBinding {
    binding: MemoryV1MutationBinding,
    intent: MemoryV1ScopedPurchaseIntent,
}

impl MemoryV1ScopedMutationBinding {
    /// memory—v1: Return the operation key, whose tenant is the actor tenant.
    pub fn key(&self) -> MemoryV1OperationKey {
        self.binding.key
    }

    /// memory—v1: Inspect the immutable request and claimed scope.
    pub fn intent(&self) -> &MemoryV1ScopedPurchaseIntent {
        &self.intent
    }

    /// memory—v1: Return the observed root metadata.
    pub fn root(&self) -> RootMetadata {
        self.binding.root
    }

    /// memory—v1: Return the time of the session and root observation.
    pub fn trusted_time_unix_seconds(&self) -> i64 {
        self.binding.trusted_time_unix_seconds
    }
}

/// memory—v1: Check exact scoped intent against a real engine admission and live
/// session. The caller's scope is not proof of business ownership. A business
/// owner must independently establish and recheck attribution, authorization,
/// session, time and root at its atomic commit boundary, with durable replay,
/// audit and recovery guarantees. This isolated candidate provides none of those.
pub fn validate_scoped_purchase_admission(
    root: &RequestRootExtension,
    session: &RequestSessionExtension,
    intent: &MemoryV1ScopedPurchaseIntent,
    admission: &MemoryV1Admission,
    now_unix_seconds: i64,
) -> Result<MemoryV1ScopedMutationBinding, MemoryV1MutationError> {
    let scope = intent.scope();
    if admission.target_tenant() != scope.target_tenant {
        return Err(MemoryV1MutationError::AdmissionMismatch("target_tenant"));
    }
    if admission.target_owner() != scope.target_owner {
        return Err(MemoryV1MutationError::AdmissionMismatch("target_owner"));
    }
    let binding = validate_purchase_admission_fingerprint(
        root,
        session,
        &intent.intent,
        admission,
        intent.fingerprint,
        now_unix_seconds,
    )?;
    Ok(MemoryV1ScopedMutationBinding {
        binding,
        intent: intent.clone(),
    })
}

/// A lease returned for a new operation claim. It is consumed by completion or
/// unknown-commit marking and cannot be reused after either transition.
pub struct MemoryV1MutationLease {
    key: MemoryV1OperationKey,
    identity: LedgerIdentity,
    ledger_owner: Arc<()>,
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

/// memory—v1: Scoped reconciliation checks the entire versioned binding.
pub enum MemoryV1ScopedReconciliation<R> {
    Committed {
        result: R,
        audit: MemoryV1AuditState,
    },
    InFlight,
    Unknown,
    Conflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LedgerIdentity {
    Legacy([u8; 32]),
    Scoped([u8; 32]),
}

enum LedgerEntry<R> {
    InFlight {
        identity: LedgerIdentity,
    },
    Completed {
        identity: LedgerIdentity,
        result: R,
        audit: MemoryV1AuditState,
    },
    Unknown {
        identity: LedgerIdentity,
    },
}

/// Bounded-scope in-process idempotency ledger for the contract tests and a
/// future owner seam. It is not durable: after restart, a real owner must query
/// authoritative operation evidence and keep the result UNKNOWN when absent.
pub struct MemoryV1MutationLedger<R> {
    entries: Mutex<HashMap<MemoryV1OperationKey, LedgerEntry<R>>>,
    owner: Arc<()>,
}

impl<R> Default for MemoryV1MutationLedger<R> {
    // memory—v1: Every ledger gets a distinct owner token retained by its leases.
    fn default() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            owner: Arc::new(()),
        }
    }
}

impl<R: Clone> MemoryV1MutationLedger<R> {
    /// memory—v1: Claim a legacy key in the shared versioned ledger.
    pub fn claim(
        &self,
        binding: &MemoryV1MutationBinding,
    ) -> Result<MemoryV1MutationClaim<R>, MemoryV1MutationError> {
        self.claim_identity(binding.key, LedgerIdentity::Legacy(binding.fingerprint))
    }

    /// memory—v1: Claim a scoped binding in the same ledger as legacy claims.
    pub fn claim_scoped(
        &self,
        binding: &MemoryV1ScopedMutationBinding,
    ) -> Result<MemoryV1MutationClaim<R>, MemoryV1MutationError> {
        self.claim_identity(
            binding.key(),
            LedgerIdentity::Scoped(binding.intent.fingerprint),
        )
    }

    // memory—v1: Serialize claims and compare both fingerprint and version.
    fn claim_identity(
        &self,
        key: MemoryV1OperationKey,
        identity: LedgerIdentity,
    ) -> Result<MemoryV1MutationClaim<R>, MemoryV1MutationError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| MemoryV1MutationError::LedgerPoisoned)?;
        match entries.get(&key) {
            None => {
                if entries.len() >= MAX_LEDGER_ENTRIES {
                    return Err(MemoryV1MutationError::CapacityExhausted);
                }
                entries.insert(key, LedgerEntry::InFlight { identity });
                Ok(MemoryV1MutationClaim::New(MemoryV1MutationLease {
                    key,
                    identity,
                    ledger_owner: Arc::clone(&self.owner),
                }))
            }
            Some(LedgerEntry::InFlight { identity: existing }) => {
                if *existing == identity {
                    Ok(MemoryV1MutationClaim::InFlight)
                } else {
                    Ok(MemoryV1MutationClaim::Conflict)
                }
            }
            Some(LedgerEntry::Completed {
                identity: existing,
                result,
                audit,
            }) => {
                if *existing == identity {
                    Ok(MemoryV1MutationClaim::Replayed {
                        result: result.clone(),
                        audit: *audit,
                    })
                } else {
                    Ok(MemoryV1MutationClaim::Conflict)
                }
            }
            Some(LedgerEntry::Unknown { identity: existing }) => {
                if *existing == identity {
                    Ok(MemoryV1MutationClaim::UnknownCommit)
                } else {
                    Ok(MemoryV1MutationClaim::Conflict)
                }
            }
        }
    }

    /// memory—v1: Record a result only for the exact active lease and ledger.
    pub fn complete(
        &self,
        lease: MemoryV1MutationLease,
        result: R,
        audit: MemoryV1AuditState,
    ) -> Result<(), MemoryV1MutationError> {
        if !Arc::ptr_eq(&self.owner, &lease.ledger_owner) {
            return Err(MemoryV1MutationError::LeaseClosed);
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| MemoryV1MutationError::LedgerPoisoned)?;
        match entries.get(&lease.key) {
            Some(LedgerEntry::InFlight { identity }) if *identity == lease.identity => {
                entries.insert(
                    lease.key,
                    LedgerEntry::Completed {
                        identity: lease.identity,
                        result,
                        audit,
                    },
                );
                Ok(())
            }
            _ => Err(MemoryV1MutationError::LeaseClosed),
        }
    }

    /// memory—v1: Preserve uncertainty after a transport or commit error. The
    /// operation remains blocked until authoritative reconciliation.
    pub fn mark_unknown(&self, lease: MemoryV1MutationLease) -> Result<(), MemoryV1MutationError> {
        if !Arc::ptr_eq(&self.owner, &lease.ledger_owner) {
            return Err(MemoryV1MutationError::LeaseClosed);
        }
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| MemoryV1MutationError::LedgerPoisoned)?;
        match entries.get(&lease.key) {
            Some(LedgerEntry::InFlight { identity }) if *identity == lease.identity => {
                entries.insert(
                    lease.key,
                    LedgerEntry::Unknown {
                        identity: lease.identity,
                    },
                );
                Ok(())
            }
            _ => Err(MemoryV1MutationError::LeaseClosed),
        }
    }

    /// memory—v1: Consult legacy local evidence by key only. Scoped records are
    /// deliberately hidden; use `reconcile_scoped` with a checked binding.
    /// An absent key is UNKNOWN and does not prove an earlier attempt did not run.
    pub fn reconcile(
        &self,
        key: MemoryV1OperationKey,
    ) -> Result<MemoryV1Reconciliation<R>, MemoryV1MutationError> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| MemoryV1MutationError::LedgerPoisoned)?;
        Ok(match entries.get(&key) {
            Some(LedgerEntry::InFlight {
                identity: LedgerIdentity::Legacy(_),
            }) => MemoryV1Reconciliation::InFlight,
            Some(LedgerEntry::Completed {
                identity: LedgerIdentity::Legacy(_),
                result,
                audit,
            }) => MemoryV1Reconciliation::Committed {
                result: result.clone(),
                audit: *audit,
            },
            _ => MemoryV1Reconciliation::Unknown,
        })
    }

    /// memory—v1: Consult only evidence matching this exact scoped identity.
    /// A missing entry remains UNKNOWN and conflicts never reveal a result.
    pub fn reconcile_scoped(
        &self,
        binding: &MemoryV1ScopedMutationBinding,
    ) -> Result<MemoryV1ScopedReconciliation<R>, MemoryV1MutationError> {
        let entries = self
            .entries
            .lock()
            .map_err(|_| MemoryV1MutationError::LedgerPoisoned)?;
        let expected = LedgerIdentity::Scoped(binding.intent.fingerprint);
        Ok(match entries.get(&binding.key()) {
            None => MemoryV1ScopedReconciliation::Unknown,
            Some(LedgerEntry::InFlight { identity }) if *identity == expected => {
                MemoryV1ScopedReconciliation::InFlight
            }
            Some(LedgerEntry::Unknown { identity }) if *identity == expected => {
                MemoryV1ScopedReconciliation::Unknown
            }
            Some(LedgerEntry::Completed {
                identity,
                result,
                audit,
            }) if *identity == expected => MemoryV1ScopedReconciliation::Committed {
                result: result.clone(),
                audit: *audit,
            },
            Some(_) => MemoryV1ScopedReconciliation::Conflict,
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

// memory—v1: Encode absence separately from a present, possibly empty value.
fn append_optional_bytes(frame: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        None => frame.push(0),
        Some(bytes) => {
            frame.push(1);
            append_bytes(frame, bytes);
        }
    }
}

// memory—v1: The scoped domain commits to the legacy payload digest and exact
// tenant and owner byte strings. The replay operation ID remains in the key.
fn scoped_intent_digest(
    intent: &MemoryV1PurchaseIntent,
    scope: MemoryV1PurchaseScope<'_>,
) -> [u8; 32] {
    let mut frame = Vec::with_capacity(SCOPED_INTENT_HASH_DOMAIN.len() + 64);
    frame.extend_from_slice(SCOPED_INTENT_HASH_DOMAIN);
    append_bytes(&mut frame, &intent.fingerprint);
    append_optional_bytes(&mut frame, scope.target_tenant);
    append_optional_bytes(&mut frame, scope.target_owner);
    Sha256::digest(frame).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_authorization_root::memory_v1_db_rows::{
        BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
        IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetStatus,
        RuleSetVersionRow, TenantRow, UserCardRow, UserCardStatus, UserRow,
    };
    use astral_authorization_root::memory_v1_hamt::CandidateBudget;
    use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
    use astral_authorization_root::memory_v1_request::RequestRootScope;
    use astral_authorization_root::memory_v1_root::{
        install_process_root, ManagementMutationV2, MutationPrecondition,
    };
    use astral_authorization_root::memory_v1_rules::{
        canonical_version_bytes, version_digest, MemoryV1OwnerScope, MemoryV1TenantScope,
    };
    use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
    use policy_engine::memory_v1_formal::{MemoryV1Decision, MemoryV1Request};
    use policy_engine::PolicyEngine;
    use std::time::{SystemTime, UNIX_EPOCH};

    // memory—v1: Exercise the real root, session authority and engine in a
    // dedicated process because a process root can be installed only once.
    #[test]
    fn purchase_admission_rechecks_live_session() {
        const CHILD: &str = "ASTRAL_PURCHASE_SESSION_CONTRACT_CHILD";
        const TEST: &str = "service::memory_v1_protected_mutation::tests::purchase_admission_rechecks_live_session";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env(CHILD, "1")
                .output()
                .expect("start isolated purchase session test");
            assert!(
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "isolated test failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let content = br#"{"rules":[{"ruleId":"purchase","resource":"memory-v1-purchase","action":"create","effect":"ALLOW","ownerScope":"all","tenantScope":"self+descendants"}]}"#;
        let version = vec![1];
        let timestamp = vec![2];
        let hash_input = canonical_version_bytes(&version, content, &timestamp);
        let rows = CandidateRows {
            users: vec![UserRow { user_id: [1; 16] }],
            identity_cards: vec![IdentityCardRow {
                identity_card_id: [2; 16],
                user_id: [1; 16],
            }],
            tenants: vec![
                TenantRow {
                    tenant_id: [4; 16],
                    parent_tenant_id: None,
                },
                TenantRow {
                    tenant_id: [5; 16],
                    parent_tenant_id: Some([4; 16]),
                },
            ],
            user_cards: vec![UserCardRow {
                user_card_id: [3; 16],
                user_id: [1; 16],
                tenant_id: [4; 16],
                status: UserCardStatus::Active,
            }],
            rule_sets: vec![RuleSetRow {
                status: RuleSetStatus::Active,
                rule_set_id: [10; 16],
                owner_tenant_id: [4; 16],
                current_version_bytes: version.clone(),
            }],
            rule_set_versions: vec![RuleSetVersionRow {
                rule_set_id: [10; 16],
                version_bytes: version.clone(),
                content_bytes: content.to_vec(),
                timestamp_bytes: timestamp,
                hash_bytes: version_digest(&hash_input),
                hash_input_bytes: hash_input,
            }],
            bindings: vec![BindingRow {
                binding_id: [20; 16],
                user_card_id: [3; 16],
                rule_set_id: [10; 16],
                binding_layer: BindingLayer::Base,
                valid_from: None,
                valid_until: None,
                owner_scope: MemoryV1OwnerScope::AllUsers,
                tenant_scope: MemoryV1TenantScope::SelfAndDescendants,
                removed_at: None,
                removed_by: None,
            }],
            binding_confirmations: vec![BindingConfirmationRow {
                confirmation_id: [40; 16],
                binding_id: [20; 16],
                rule_set_id: [10; 16],
                version_bytes: version.clone(),
                confirmer_user_id: [1; 16],
                scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            }],
            rule_set_change_confirmations: vec![RuleSetChangeConfirmationRow {
                confirmation_id: [50; 16],
                rule_set_id: [10; 16],
                version_bytes: version.clone(),
                confirmer_user_id: [1; 16],
                affected_scope_bytes: vec![1],
                operation_id: vec![2],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            }],
        };
        let owner = install_process_root(
            rows,
            vec![CurrentSelection {
                rule_set_id: [10; 16],
                version_bytes: version,
            }],
            CandidateBudget {
                max_table_rows: 64,
                max_bindings_per_read: 8,
            },
        )
        .unwrap();
        owner
            .install_registry(&[RegistryDeclaration {
                resource: PURCHASE_RESOURCE.into(),
                actions: vec![PURCHASE_ACTION.into()],
            }])
            .unwrap();
        owner.adopt_serving_for_isolated_tests().unwrap();
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let adapter = authority.identity_session_adapter();
        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let scope = RequestRootScope::new(owner.handle(), Default::default());
        let root = scope.extension();
        let issued = adapter
            .issue_verified_session_in_root(&root, actor(), now - 1, 3600)
            .unwrap();
        let session = authority
            .verifier()
            .verify_and_bind(issued.credential(), now, &root)
            .unwrap();
        let intent = intent(7, 8);
        let fingerprint = intent.fingerprint();
        let target = *intent.command().package_id().as_bytes();
        let actor = intent.actor();
        let operation_id = intent.operation_id();
        let request = MemoryV1Request {
            resource: intent.resource(),
            action: intent.action(),
            target: Some(&target),
            target_owner: Some(actor.user_id.as_bytes()),
            target_tenant: Some(actor.tenant_id.as_bytes()),
            operation_id: operation_id.as_bytes(),
            operation_fingerprint: &fingerprint,
        };
        let engine = PolicyEngine::new();
        let evaluation = engine.evaluate_memory_v1(&root, &session, &request);
        assert_eq!(evaluation.decision, MemoryV1Decision::Allow);
        let admission = evaluation
            .admission
            .expect("engine must issue purchase admission");
        let checked_at = admission.trusted_time_unix_seconds();
        assert!(
            validate_purchase_admission(&root, &session, &intent, &admission, checked_at).is_ok()
        );

        // Obtain every admission from the real engine, using the same object,
        // actor, operation and fingerprint while varying only attribution.
        let tenant = *actor.tenant_id.as_bytes();
        let owner_id = *actor.user_id.as_bytes();
        let child_tenant = [5; 16];
        let other_owner = [6; 16];
        let original_scope = MemoryV1PurchaseScope {
            target_tenant: Some(&tenant),
            target_owner: Some(&owner_id),
        };
        let check = |candidate: &MemoryV1Admission, expected| {
            validate_purchase_admission_with_scope(
                &root,
                &session,
                &intent,
                candidate,
                expected,
                candidate.trusted_time_unix_seconds(),
            )
        };
        assert!(check(&admission, original_scope).is_ok());

        // The engine evaluates the frozen scoped request, not caller-provided
        // attribution paired with the legacy fingerprint.
        let scoped = MemoryV1ScopedPurchaseIntent::new(intent, original_scope).unwrap();
        let scoped_result = engine.evaluate_memory_v1(&root, &session, &scoped.request());
        assert_eq!(scoped_result.decision, MemoryV1Decision::Allow);
        let scoped_admission = scoped_result.admission.unwrap();
        let scoped_time = scoped_admission.trusted_time_unix_seconds();
        let scoped_binding = validate_scoped_purchase_admission(
            &root,
            &session,
            &scoped,
            &scoped_admission,
            scoped_time,
        )
        .unwrap();
        assert_eq!(scoped_binding.intent().scope(), original_scope);
        assert_eq!(scoped_binding.key().tenant_id(), actor.tenant_id);
        assert_eq!(
            validate_scoped_purchase_admission(&root, &session, &scoped, &admission, checked_at),
            Err(MemoryV1MutationError::AdmissionMismatch("fingerprint"))
        );
        let child_scope = MemoryV1PurchaseScope {
            target_tenant: Some(&child_tenant),
            target_owner: Some(&owner_id),
        };
        let child_scoped = MemoryV1ScopedPurchaseIntent::new(intent, child_scope).unwrap();
        let child_scoped_result =
            engine.evaluate_memory_v1(&root, &session, &child_scoped.request());
        assert_eq!(child_scoped_result.decision, MemoryV1Decision::Allow);
        let child_scoped_admission = child_scoped_result.admission.unwrap();
        let child_binding = validate_scoped_purchase_admission(
            &root,
            &session,
            &child_scoped,
            &child_scoped_admission,
            child_scoped_admission.trusted_time_unix_seconds(),
        )
        .unwrap();
        assert_eq!(child_binding.key(), scoped_binding.key());
        assert_eq!(child_binding.intent().scope(), child_scope);
        assert_eq!(
            validate_scoped_purchase_admission(
                &root,
                &session,
                &scoped,
                &child_scoped_admission,
                scoped_time
            ),
            Err(MemoryV1MutationError::AdmissionMismatch("target_tenant"))
        );
        let substituted_request = MemoryV1Request {
            target_tenant: Some(&child_tenant),
            ..scoped.request()
        };
        let substituted = engine.evaluate_memory_v1(&root, &session, &substituted_request);
        assert_eq!(substituted.decision, MemoryV1Decision::Allow);
        let substituted_admission = substituted.admission.unwrap();
        assert_eq!(
            validate_scoped_purchase_admission(
                &root,
                &session,
                &child_scoped,
                &substituted_admission,
                scoped_time
            ),
            Err(MemoryV1MutationError::AdmissionMismatch("fingerprint"))
        );
        let evaluate_scope = |target_tenant, target_owner| {
            engine.evaluate_memory_v1(
                &root,
                &session,
                &MemoryV1Request {
                    target_tenant,
                    target_owner,
                    ..request
                },
            )
        };
        let other_owner_result = evaluate_scope(Some(&tenant), Some(&other_owner));
        assert_eq!(other_owner_result.decision, MemoryV1Decision::Allow);
        let other_owner_admission = other_owner_result.admission.unwrap();
        let child_result = evaluate_scope(Some(&child_tenant), Some(&owner_id));
        assert_eq!(child_result.decision, MemoryV1Decision::Allow);
        let child_admission = child_result.admission.unwrap();
        assert_eq!(
            other_owner_admission.target_owner(),
            Some(other_owner.as_slice())
        );
        assert_eq!(
            other_owner_admission.target_tenant(),
            Some(tenant.as_slice())
        );
        assert_eq!(
            child_admission.target_tenant(),
            Some(child_tenant.as_slice())
        );
        assert_eq!(child_admission.target_owner(), Some(owner_id.as_slice()));
        for candidate in [&other_owner_admission, &child_admission] {
            assert_eq!(candidate.identity(), admission.identity());
            assert_eq!(candidate.target(), admission.target());
            assert_eq!(candidate.operation_id(), admission.operation_id());
            assert_eq!(
                candidate.operation_fingerprint(),
                admission.operation_fingerprint()
            );
        }
        assert_eq!(
            check(&other_owner_admission, original_scope),
            Err(MemoryV1MutationError::AdmissionMismatch("target_owner"))
        );
        assert_eq!(
            check(&child_admission, original_scope),
            Err(MemoryV1MutationError::AdmissionMismatch("target_tenant"))
        );
        assert!(check(
            &other_owner_admission,
            MemoryV1PurchaseScope {
                target_tenant: Some(&tenant),
                target_owner: Some(&other_owner),
            },
        )
        .is_ok());
        assert!(check(
            &child_admission,
            MemoryV1PurchaseScope {
                target_tenant: Some(&child_tenant),
                target_owner: Some(&owner_id),
            },
        )
        .is_ok());
        assert_eq!(
            check(
                &admission,
                MemoryV1PurchaseScope {
                    target_tenant: None,
                    target_owner: Some(&owner_id),
                },
            ),
            Err(MemoryV1MutationError::AdmissionMismatch("target_tenant"))
        );
        assert_eq!(
            check(
                &admission,
                MemoryV1PurchaseScope {
                    target_tenant: Some(&tenant),
                    target_owner: None,
                },
            ),
            Err(MemoryV1MutationError::AdmissionMismatch("target_owner"))
        );
        for (target_tenant, target_owner) in [
            (None, Some(owner_id.as_slice())),
            (Some(tenant.as_slice()), None),
            (None, None),
        ] {
            let missing = evaluate_scope(target_tenant, target_owner);
            assert_eq!(missing.decision, MemoryV1Decision::Pending);
            assert!(missing.admission.is_none());
        }
        assert_eq!(
            validate_purchase_admission_with_scope(
                &root,
                &session,
                &intent,
                &admission,
                original_scope,
                now + 3599,
            ),
            Err(MemoryV1MutationError::SessionUnavailable)
        );
        let other_scope = RequestRootScope::new(owner.handle(), Default::default());
        let other_root = other_scope.extension();
        assert_eq!(
            validate_purchase_admission(&other_root, &session, &intent, &admission, checked_at),
            Err(MemoryV1MutationError::SessionUnavailable)
        );
        assert_eq!(
            validate_purchase_admission(&root, &session, &intent, &admission, now + 3599),
            Err(MemoryV1MutationError::SessionUnavailable)
        );

        // Change the actual root while preserving the granting card and rule.
        owner
            .execute_mutation_with_precondition_for_isolated_tests(
                &ManagementMutationV2::UserCardCreate {
                    row: UserCardRow {
                        user_card_id: [30; 16],
                        user_id: [1; 16],
                        tenant_id: [4; 16],
                        status: UserCardStatus::Active,
                    },
                },
                &MutationPrecondition {
                    evaluated_root_version: admission.root().version,
                },
            )
            .unwrap();
        assert_eq!(
            validate_purchase_admission_with_scope(
                &root,
                &session,
                &intent,
                &admission,
                original_scope,
                checked_at,
            ),
            Err(MemoryV1MutationError::RootChanged)
        );
        assert_eq!(
            validate_scoped_purchase_admission(
                &root,
                &session,
                &scoped,
                &scoped_admission,
                scoped_time
            ),
            Err(MemoryV1MutationError::RootChanged)
        );
        let fresh_scope = RequestRootScope::new(owner.handle(), Default::default());
        let fresh_root = fresh_scope.extension();
        let fresh_session = authority
            .verifier()
            .verify_and_bind(issued.credential(), checked_at, &fresh_root)
            .unwrap();
        let fresh_evaluation = engine.evaluate_memory_v1(&fresh_root, &fresh_session, &request);
        assert_eq!(fresh_evaluation.decision, MemoryV1Decision::Allow);
        let fresh_admission = fresh_evaluation.admission.unwrap();
        let fresh_time = fresh_admission.trusted_time_unix_seconds();
        assert!(validate_purchase_admission(
            &fresh_root,
            &fresh_session,
            &intent,
            &fresh_admission,
            fresh_time
        )
        .is_ok());
        let metadata_before_revoke = owner.handle().metadata().unwrap();
        adapter.revoke(issued.credential()).unwrap();
        assert_eq!(owner.handle().metadata().unwrap(), metadata_before_revoke);
        assert_eq!(
            validate_purchase_admission_with_scope(
                &fresh_root,
                &fresh_session,
                &intent,
                &fresh_admission,
                original_scope,
                fresh_time
            ),
            Err(MemoryV1MutationError::SessionUnavailable)
        );
    }

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

    // memory—v1: Construct local ledger fixtures without claiming engine proof.
    fn scoped_binding(operation: u8, tenant: &[u8], owner: &[u8]) -> MemoryV1ScopedMutationBinding {
        let intent = MemoryV1ScopedPurchaseIntent::new(
            intent(operation, 8),
            MemoryV1PurchaseScope {
                target_tenant: Some(tenant),
                target_owner: Some(owner),
            },
        )
        .unwrap();
        let mut binding = binding(operation, 8);
        binding.fingerprint = intent.fingerprint();
        MemoryV1ScopedMutationBinding { binding, intent }
    }

    // memory—v1: Verify the wire frame and scope ownership independently of authorization.
    #[test]
    fn scoped_fingerprint_encodes_presence_lengths_and_owns_scope() {
        let mut encoded = Vec::new();
        append_optional_bytes(&mut encoded, None);
        append_optional_bytes(&mut encoded, Some(&[]));
        append_optional_bytes(&mut encoded, Some(&[1, 2]));
        assert_eq!(
            encoded,
            [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 1, 2]
        );

        let legacy = intent(7, 8);
        let make = |target_tenant, target_owner| {
            MemoryV1ScopedPurchaseIntent::new(
                legacy,
                MemoryV1PurchaseScope {
                    target_tenant,
                    target_owner,
                },
            )
            .unwrap()
        };
        let absent = make(None, None);
        let empty_tenant = make(Some(&[]), None);
        let empty_owner = make(None, Some(&[]));
        assert_ne!(absent.fingerprint(), empty_tenant.fingerprint());
        assert_ne!(absent.fingerprint(), empty_owner.fingerprint());
        assert_ne!(empty_tenant.fingerprint(), empty_owner.fingerprint());
        assert_ne!(absent.fingerprint(), legacy.fingerprint());
        assert_eq!(absent.fingerprint(), make(None, None).fingerprint());
        assert_eq!(
            absent.fingerprint(),
            MemoryV1ScopedPurchaseIntent::new(
                intent(9, 8),
                MemoryV1PurchaseScope {
                    target_tenant: None,
                    target_owner: None
                },
            )
            .unwrap()
            .fingerprint()
        );
        assert_ne!(
            absent.fingerprint(),
            MemoryV1ScopedPurchaseIntent::new(
                intent(7, 9),
                MemoryV1PurchaseScope {
                    target_tenant: None,
                    target_owner: None
                },
            )
            .unwrap()
            .fingerprint()
        );
        let mut changed_actor = actor();
        changed_actor.user_id = id(11);
        let different_actor =
            MemoryV1PurchaseIntent::new(id(7), changed_actor, legacy.command()).unwrap();
        assert_ne!(
            absent.fingerprint(),
            MemoryV1ScopedPurchaseIntent::new(
                different_actor,
                MemoryV1PurchaseScope {
                    target_tenant: None,
                    target_owner: None
                },
            )
            .unwrap()
            .fingerprint()
        );

        let frozen = MemoryV1ScopedPurchaseIntent::new(
            legacy,
            MemoryV1PurchaseScope {
                target_tenant: Some(&[4; 16]),
                target_owner: Some(&[1; 16]),
            },
        )
        .unwrap();
        let clone = frozen.clone();
        let changed_tenant = [8; 16];
        let changed_owner = [9; 16];
        assert_eq!(frozen.scope().target_tenant.unwrap(), &[4; 16]);
        assert_eq!(frozen.scope().target_owner.unwrap(), &[1; 16]);
        assert_eq!(clone, frozen);
        let changed = MemoryV1ScopedPurchaseIntent::new(
            legacy,
            MemoryV1PurchaseScope {
                target_tenant: Some(&changed_tenant),
                target_owner: Some(&changed_owner),
            },
        )
        .unwrap();
        assert_ne!(frozen.fingerprint(), changed.fingerprint());
        assert_ne!(
            make(Some(&[1]), Some(&[2, 3])).fingerprint(),
            make(Some(&[1, 2]), Some(&[3])).fingerprint()
        );

        let max = vec![1; MAX_SCOPE_BYTES];
        let too_long = vec![1; MAX_SCOPE_BYTES + 1];
        assert!(MemoryV1ScopedPurchaseIntent::new(
            legacy,
            MemoryV1PurchaseScope {
                target_tenant: Some(&max),
                target_owner: Some(&max),
            }
        )
        .is_ok());
        for (scope, field) in [
            (
                MemoryV1PurchaseScope {
                    target_tenant: Some(too_long.as_slice()),
                    target_owner: None,
                },
                "target_tenant",
            ),
            (
                MemoryV1PurchaseScope {
                    target_tenant: None,
                    target_owner: Some(too_long.as_slice()),
                },
                "target_owner",
            ),
        ] {
            assert_eq!(
                MemoryV1ScopedPurchaseIntent::new(legacy, scope),
                Err(MemoryV1MutationError::InvalidInput(field))
            );
        }
    }

    // memory—v1: Exercise scope and version conflicts through all local states.
    #[test]
    fn scoped_ledger_conflicts_and_queries_cover_all_states() {
        let ledger = MemoryV1MutationLedger::<String>::default();
        let first = scoped_binding(7, &[4; 16], &[1; 16]);
        let other_tenant = scoped_binding(7, &[5; 16], &[1; 16]);
        let other_owner = scoped_binding(7, &[4; 16], &[6; 16]);
        let legacy = binding(7, 8);
        let lease = match ledger.claim_scoped(&first).unwrap() {
            MemoryV1MutationClaim::New(lease) => lease,
            _ => panic!("first scoped claim must be new"),
        };
        let check_conflicts = || {
            for other in [&other_tenant, &other_owner] {
                assert!(matches!(
                    ledger.claim_scoped(other).unwrap(),
                    MemoryV1MutationClaim::Conflict
                ));
                assert!(matches!(
                    ledger.reconcile_scoped(other).unwrap(),
                    MemoryV1ScopedReconciliation::Conflict
                ));
            }
            assert!(matches!(
                ledger.claim(&legacy).unwrap(),
                MemoryV1MutationClaim::Conflict
            ));
            assert!(matches!(
                ledger.reconcile(first.key()).unwrap(),
                MemoryV1Reconciliation::Unknown
            ));
        };
        check_conflicts();
        assert!(matches!(
            ledger.claim_scoped(&first.clone()).unwrap(),
            MemoryV1MutationClaim::InFlight
        ));
        assert!(matches!(
            ledger.reconcile_scoped(&first).unwrap(),
            MemoryV1ScopedReconciliation::InFlight
        ));
        ledger
            .complete(lease, "result".into(), MemoryV1AuditState::Recorded)
            .unwrap();
        check_conflicts();
        assert!(
            matches!(ledger.claim_scoped(&first).unwrap(), MemoryV1MutationClaim::Replayed { result, audit: MemoryV1AuditState::Recorded } if result == "result")
        );
        assert!(
            matches!(ledger.reconcile_scoped(&first).unwrap(), MemoryV1ScopedReconciliation::Committed { result, audit: MemoryV1AuditState::Recorded } if result == "result")
        );

        let unknown = scoped_binding(9, &[4; 16], &[1; 16]);
        let unknown_other = scoped_binding(9, &[5; 16], &[1; 16]);
        let unknown_lease = match ledger.claim_scoped(&unknown).unwrap() {
            MemoryV1MutationClaim::New(lease) => lease,
            _ => panic!("new key must be claimed"),
        };
        ledger.mark_unknown(unknown_lease).unwrap();
        assert!(matches!(
            ledger.claim_scoped(&unknown).unwrap(),
            MemoryV1MutationClaim::UnknownCommit
        ));
        assert!(matches!(
            ledger.reconcile_scoped(&unknown).unwrap(),
            MemoryV1ScopedReconciliation::Unknown
        ));
        assert!(matches!(
            ledger.claim_scoped(&unknown_other).unwrap(),
            MemoryV1MutationClaim::Conflict
        ));
        assert!(matches!(
            ledger.reconcile_scoped(&unknown_other).unwrap(),
            MemoryV1ScopedReconciliation::Conflict
        ));
        assert!(matches!(
            ledger.claim(&binding(9, 8)).unwrap(),
            MemoryV1MutationClaim::Conflict
        ));

        let legacy_first = MemoryV1MutationLedger::<String>::default();
        let lease = match legacy_first.claim(&legacy).unwrap() {
            MemoryV1MutationClaim::New(lease) => lease,
            _ => panic!("legacy claim must be new"),
        };
        assert!(matches!(
            legacy_first.claim_scoped(&first).unwrap(),
            MemoryV1MutationClaim::Conflict
        ));
        assert!(matches!(
            legacy_first.reconcile_scoped(&first).unwrap(),
            MemoryV1ScopedReconciliation::Conflict
        ));
        legacy_first
            .complete(lease, "legacy".into(), MemoryV1AuditState::Recorded)
            .unwrap();
        assert!(matches!(
            legacy_first.claim_scoped(&first).unwrap(),
            MemoryV1MutationClaim::Conflict
        ));
        assert!(matches!(
            legacy_first.reconcile_scoped(&first).unwrap(),
            MemoryV1ScopedReconciliation::Conflict
        ));
    }

    // memory—v1: Competing clones and scopes share one serialized claim point.
    #[test]
    fn concurrent_scoped_claims_have_one_winner() {
        use std::sync::Barrier;
        let ledger = Arc::new(MemoryV1MutationLedger::<()>::default());
        let barrier = Arc::new(Barrier::new(16));
        let first = scoped_binding(7, &[4; 16], &[1; 16]);
        let second = scoped_binding(7, &[5; 16], &[1; 16]);
        let threads: Vec<_> = (0..16)
            .map(|index| {
                let ledger = Arc::clone(&ledger);
                let barrier = Arc::clone(&barrier);
                let binding = if index % 2 == 0 {
                    first.clone()
                } else {
                    second.clone()
                };
                std::thread::spawn(move || {
                    barrier.wait();
                    match ledger.claim_scoped(&binding).unwrap() {
                        MemoryV1MutationClaim::New(_) => 0,
                        MemoryV1MutationClaim::InFlight => 1,
                        MemoryV1MutationClaim::Conflict => 2,
                        _ => panic!("unexpected concurrent claim"),
                    }
                })
            })
            .collect();
        let results: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|&&result| result == 0).count(), 1);
        assert_eq!(results.iter().filter(|&&result| result == 1).count(), 7);
        assert_eq!(results.iter().filter(|&&result| result == 2).count(), 8);
    }

    // memory—v1: A lease from another ledger cannot complete or mark its entry.
    #[test]
    fn scoped_lease_is_bound_to_its_ledger() {
        let first = MemoryV1MutationLedger::<()>::default();
        let second = MemoryV1MutationLedger::<()>::default();
        let binding = scoped_binding(7, &[4; 16], &[1; 16]);
        let first_lease = match first.claim_scoped(&binding).unwrap() {
            MemoryV1MutationClaim::New(lease) => lease,
            _ => panic!("first ledger claim"),
        };
        let second_lease = match second.claim_scoped(&binding).unwrap() {
            MemoryV1MutationClaim::New(lease) => lease,
            _ => panic!("second ledger claim"),
        };
        assert_eq!(
            second.complete(first_lease, (), MemoryV1AuditState::Recorded),
            Err(MemoryV1MutationError::LeaseClosed)
        );
        assert!(matches!(
            second.reconcile_scoped(&binding).unwrap(),
            MemoryV1ScopedReconciliation::InFlight
        ));
        assert_eq!(
            first.mark_unknown(second_lease),
            Err(MemoryV1MutationError::LeaseClosed)
        );
        assert!(matches!(
            first.reconcile_scoped(&binding).unwrap(),
            MemoryV1ScopedReconciliation::InFlight
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
