//! Durable store contract for authority state.
//!
//! The contract is deliberately small and CAS-shaped so it maps one-to-one
//! onto etcd's linearizable reads and atomic transactions:
//! - [`AuthorityStore::get`] / [`AuthorityStore::get_prefix`] are linearizable
//!   (never serializable/stale) reads.
//! - [`AuthorityStore::execute`] applies a batch of conditional puts atomically:
//!   either every precondition holds and every put lands with one shared
//!   revision, or nothing is written.
//!
//! Values are opaque bytes at this layer; the service layer owns the typed
//! JSON encoding, so the store stays policy-free and testable.

pub mod etcd;
pub mod memory;

use async_trait::async_trait;

use crate::error::AuthorityStoreError;

/// Limits for one authority snapshot, including all requested ranges.
const SNAPSHOT_MAX_READS: usize = 64;
const SNAPSHOT_MAX_KEY_BYTES: usize = 1024;
const SNAPSHOT_MAX_VALUE_BYTES: usize = 512 * 1024;
const SNAPSHOT_MAX_RECORDS: usize = 256;
const SNAPSHOT_MAX_BYTES: usize = 2 * 1024 * 1024;

/// A single exact-key or complete prefix read within an atomic snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotRead {
    Key(String),
    Prefix(String),
}

impl SnapshotRead {
    fn key(&self) -> &str {
        match self {
            Self::Key(key) | Self::Prefix(key) => key,
        }
    }
}

/// Results correspond to the requested reads in order. An exact key yields
/// zero or one record; a prefix yields its complete, ordered range. Revision
/// is the store-wide snapshot revision, not the individual record CAS token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreSnapshot {
    pub revision: u64,
    pub reads: Vec<Vec<(String, StoredRecord)>>,
}

fn validate_snapshot_reads(reads: &[SnapshotRead]) -> Result<(), AuthorityStoreError> {
    if reads.is_empty()
        || reads.len() > SNAPSHOT_MAX_READS
        || reads
            .iter()
            .any(|read| read.key().is_empty() || read.key().len() > SNAPSHOT_MAX_KEY_BYTES)
    {
        return Err(AuthorityStoreError::Configuration(
            "invalid or oversized snapshot request".to_owned(),
        ));
    }
    for (index, left) in reads.iter().enumerate() {
        for right in &reads[index + 1..] {
            let overlaps = match (left, right) {
                (SnapshotRead::Key(a), SnapshotRead::Key(b)) => a == b,
                (SnapshotRead::Prefix(a), SnapshotRead::Prefix(b)) => {
                    a.starts_with(b) || b.starts_with(a)
                }
                (SnapshotRead::Prefix(prefix), SnapshotRead::Key(key))
                | (SnapshotRead::Key(key), SnapshotRead::Prefix(prefix)) => key.starts_with(prefix),
            };
            if overlaps {
                return Err(AuthorityStoreError::Configuration(
                    "overlapping snapshot reads".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn account_snapshot_record(
    count: &mut usize,
    bytes: &mut usize,
    key: &str,
    value: &[u8],
) -> Result<(), AuthorityStoreError> {
    if key.is_empty() || key.len() > SNAPSHOT_MAX_KEY_BYTES {
        return Err(snapshot_limit_error());
    }
    if value.len() > SNAPSHOT_MAX_VALUE_BYTES {
        return Err(snapshot_limit_error());
    }
    let next_count = count.checked_add(1).ok_or_else(snapshot_limit_error)?;
    let next_bytes = bytes
        .checked_add(key.len())
        .and_then(|size| size.checked_add(value.len()))
        .ok_or_else(snapshot_limit_error)?;
    if next_count > SNAPSHOT_MAX_RECORDS || next_bytes > SNAPSHOT_MAX_BYTES {
        return Err(snapshot_limit_error());
    }
    *count = next_count;
    *bytes = next_bytes;
    Ok(())
}

fn snapshot_limit_error() -> AuthorityStoreError {
    AuthorityStoreError::Unavailable("snapshot exceeds resource limits".to_owned())
}

/// One stored record with its modification revision (the CAS token).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecord {
    pub revision: u64,
    pub value: Vec<u8>,
}

/// One conditional put inside a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreOp {
    /// Put only when the key does not exist (create_revision == 0).
    PutIfAbsent { key: String, value: Vec<u8> },
    /// Put only when the key currently exists at exactly this revision.
    ReplaceIfRevision {
        key: String,
        expected_revision: u64,
        value: Vec<u8>,
    },
    /// Unconditional put.
    Put { key: String, value: Vec<u8> },
    /// Delete the key unconditionally.
    Delete { key: String },
    /// Delete the key only when it currently exists at exactly this revision.
    DeleteIfRevision { key: String, expected_revision: u64 },
    /// Pure precondition guard: the key must currently exist and hold exactly
    /// this value. This is compare-only and never writes anything, so a
    /// lease-backed record (e.g. the leader key) can gate a transaction
    /// without being overwritten and without disturbing its lease.
    RequireValue { key: String, value: Vec<u8> },
    /// Pure precondition guard: the key must exist at exactly this modification
    /// revision. It does not write the record or change its lease.
    RequireRevision { key: String, expected_revision: u64 },
    /// Pure precondition guard: the key must not currently exist.
    RequireAbsent { key: String },
}

impl StoreOp {
    pub fn key(&self) -> &str {
        match self {
            Self::PutIfAbsent { key, .. }
            | Self::ReplaceIfRevision { key, .. }
            | Self::Put { key, .. }
            | Self::Delete { key }
            | Self::DeleteIfRevision { key, .. }
            | Self::RequireValue { key, .. }
            | Self::RequireRevision { key, .. }
            | Self::RequireAbsent { key } => key,
        }
    }
}

/// An atomic batch of conditional puts.
#[derive(Debug, Clone, Default)]
pub struct StoreTxn {
    pub ops: Vec<StoreOp>,
}

impl StoreTxn {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_op(mut self, op: StoreOp) -> Self {
        self.ops.push(op);
        self
    }
}

/// Outcome of one executed transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreTxnOutcome {
    /// All preconditions held; every put landed at the given revisions
    /// (one revision per operation, shared per transaction in etcd terms).
    Applied { revisions: Vec<u64> },
    /// At least one precondition failed; nothing was written.
    PreconditionFailed { key: String },
}

/// The durable authority store.
#[async_trait]
pub trait AuthorityStore: Send + Sync + 'static {
    /// Linearizable read of one key.
    async fn get(&self, key: &str) -> Result<Option<StoredRecord>, AuthorityStoreError>;

    /// Linearizable prefix scan in ascending key order.
    async fn get_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<(String, StoredRecord)>, AuthorityStoreError>;

    /// Read disjoint exact keys and complete prefixes at one linearizable
    /// revision, or fail without returning partial results. Duplicate keys,
    /// overlapping prefixes and keys covered by a prefix are rejected.
    /// The in-memory implementation limits the combined record count and
    /// bytes; the etcd implementation is unavailable until its server-side
    /// response byte budget can be proven. No cross-call snapshot is implied.
    ///
    /// Observation alone is not proof of publication or permission to
    /// write: callers must validate evidence and fence subsequent mutations.
    /// A snapshot revision is not a CAS guard. Comparing only observed records
    /// cannot detect new keys under a prefix; a prefix-dependent mutation also
    /// needs a separately proven guard advanced atomically by every relevant
    /// insertion, deletion and update, plus the required leadership fence.
    async fn read_snapshot(
        &self,
        _reads: &[SnapshotRead],
    ) -> Result<StoreSnapshot, AuthorityStoreError> {
        Err(AuthorityStoreError::Unavailable(
            "atomic snapshot is not implemented by this store".to_owned(),
        ))
    }

    /// Atomic compare-and-swap transaction over multiple keys.
    async fn execute(&self, txn: StoreTxn) -> Result<StoreTxnOutcome, AuthorityStoreError>;
}

/// Canonical key layout for authority state.
#[derive(Debug, Clone)]
pub struct KeyLayout {
    prefix: String,
}

impl KeyLayout {
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.trim_matches('/').to_owned(),
        }
    }

    fn join(&self, suffix: &str) -> String {
        format!("{}/{}", self.prefix, suffix)
    }

    pub fn genesis(&self) -> String {
        self.join("genesis")
    }

    pub fn trust_root(&self) -> String {
        self.join("trust-root")
    }

    pub fn frontier(&self) -> String {
        self.join("frontier")
    }

    pub fn intent(&self, intent_digest: &str) -> String {
        self.join(&format!("intents/{intent_digest}"))
    }

    pub fn reservation(&self, reservation_id: &str) -> String {
        self.join(&format!("reservations/{reservation_id}"))
    }

    pub fn reservations_prefix(&self) -> String {
        self.join("reservations/")
    }

    pub fn commit_binding(&self, reservation_id: &str) -> String {
        self.join(&format!("source-commits/{reservation_id}"))
    }

    /// Immutable abort receipt of one reservation; written put-if-absent in
    /// the SAME quorum step that flips the reservation to `Aborted`, so the
    /// exact same abort replays by reading it back and nothing re-advances.
    pub fn abort_receipt(&self, reservation_id: &str) -> String {
        self.join(&format!("abort-receipts/{reservation_id}"))
    }

    pub fn commit_coverage(&self, reservation_id: &str) -> String {
        self.join(&format!("source-coverage/{reservation_id}"))
    }

    /// Immutable authority-owned receipt for one certified-memory family completion.
    pub fn family_completion(&self, reservation_id: &str, family: &str) -> String {
        self.join(&format!("family-completions/{reservation_id}/{family}"))
    }

    pub fn family_completion_prefix(&self, reservation_id: &str) -> String {
        self.join(&format!("family-completions/{reservation_id}/"))
    }

    pub fn family_completion_operation(&self, operation_id: &str, family: &str) -> String {
        self.join(&format!(
            "family-completion-operations/{operation_id}/{family}"
        ))
    }

    /// Immutable aggregate marker proving that all six CertifiedMemory family
    /// receipts were reconciled for one source reservation.
    pub fn family_completion_aggregate(&self, reservation_id: &str) -> String {
        self.join(&format!("family-completion-aggregates/{reservation_id}"))
    }

    /// Immutable eligibility completion receipt of one reservation; written
    /// put-if-absent in the SAME leader-fenced CAS that flips the reservation
    /// to its terminal `Completed` state, so the exact same completion
    /// replays by reading it back and nothing re-advances.
    pub fn eligibility_completion(&self, reservation_id: &str) -> String {
        self.join(&format!("eligibility-completions/{reservation_id}"))
    }

    /// Immutable terminal completion receipt for one captured config source mutation.
    pub fn config_completion(&self, reservation_id: &str) -> String {
        self.join(&format!("config-completions/{reservation_id}"))
    }

    pub fn reservation_certificate(&self, reservation_id: &str, scope_key: &str) -> String {
        self.join(&format!(
            "reservation-certificates/{reservation_id}/{scope_key}"
        ))
    }

    pub fn proof_receipt(&self, proof_id: &str) -> String {
        self.join(&format!("proofs/{proof_id}"))
    }

    /// Quorum-side binding of one issued proof to its immutable
    /// policy-request digest AND its caller service identity. Value is the
    /// full `StoredProofReceipt` JSON.
    pub fn proof_binding(&self, proof_id: &str) -> String {
        self.join(&format!("proof-bindings/{proof_id}"))
    }

    /// One-use marker: written by the prepare that consumes a proof, so one
    /// issued admission proof can authorize at most one intent acceptance.
    pub fn proof_consumed(&self, proof_id: &str) -> String {
        self.join(&format!("proof-consumed/{proof_id}"))
    }

    pub fn source_bootstrap_operation(&self, operation_id: &str) -> String {
        self.join(&format!("source-bootstraps/operations/{operation_id}"))
    }

    pub fn source_bootstrap_reservation(&self, reservation_id: &str) -> String {
        self.join(&format!("source-bootstraps/reservations/{reservation_id}"))
    }

    pub fn source_bootstrap_completion(&self, reservation_id: &str) -> String {
        self.join(&format!("source-bootstraps/completions/{reservation_id}"))
    }

    pub fn source_bootstrap_operations_prefix(&self) -> String {
        self.join("source-bootstraps/operations/")
    }

    pub fn source_bootstrap_reservations_prefix(&self) -> String {
        self.join("source-bootstraps/reservations/")
    }

    pub fn source_bootstrap_completions_prefix(&self) -> String {
        self.join("source-bootstraps/completions/")
    }

    pub fn source_bootstrap_global_lock(&self) -> String {
        self.join("source-bootstraps/global-lock")
    }

    pub fn gate_epoch(&self) -> String {
        self.join("gate-epoch")
    }

    /// Freshness index of one caller nonce per actor scope key.
    pub fn proof_nonce(&self, actor_scope_key: &str, request_nonce: &str) -> String {
        self.join(&format!("proof-nonces/{actor_scope_key}/{request_nonce}"))
    }

    pub fn certificate(&self, certificate_id: &str) -> String {
        self.join(&format!("certificates/{certificate_id}"))
    }

    pub fn scope_current(&self, scope_key_text: &str) -> String {
        self.join(&format!("scopes/{scope_key_text}"))
    }

    pub fn scope_prefix(&self) -> String {
        self.join("scopes/")
    }

    /// Immutable authority-owned certified-memory root record.
    pub fn certified_memory_root(&self, root_id: &str) -> String {
        self.join(&format!("certified-memory-roots/{root_id}"))
    }

    pub fn certified_memory_roots_prefix(&self) -> String {
        self.join("certified-memory-roots/")
    }

    /// Current certified-memory root pointer. The pointer is never the root
    /// fact by itself; readers must resolve and verify the immutable record.
    pub fn certified_memory_root_current(&self) -> String {
        self.join("certified-memory-root/current")
    }

    /// Stable operation idempotency record for certified-memory root install.
    pub fn certified_memory_root_operation(&self, operation_id: &str) -> String {
        self.join(&format!("certified-memory-root/operations/{operation_id}"))
    }

    pub fn certified_memory_root_operations_prefix(&self) -> String {
        self.join("certified-memory-root/operations/")
    }
}

#[cfg(test)]
mod snapshot_budget_tests {
    use super::*;

    #[test]
    fn account_enforces_combined_limits_without_changing_counters_on_failure() {
        let mut count = SNAPSHOT_MAX_RECORDS - 1;
        let mut bytes = SNAPSHOT_MAX_BYTES - 2;
        account_snapshot_record(&mut count, &mut bytes, "k", b"v").unwrap();
        assert_eq!((count, bytes), (SNAPSHOT_MAX_RECORDS, SNAPSHOT_MAX_BYTES));
        assert!(account_snapshot_record(&mut count, &mut bytes, "k", b"").is_err());
        assert_eq!((count, bytes), (SNAPSHOT_MAX_RECORDS, SNAPSHOT_MAX_BYTES));

        let mut count = 0;
        let mut bytes = SNAPSHOT_MAX_BYTES - 1;
        assert!(account_snapshot_record(&mut count, &mut bytes, "k", b"v").is_err());
        assert_eq!((count, bytes), (0, SNAPSHOT_MAX_BYTES - 1));
    }

    #[test]
    fn account_rejects_invalid_records_and_overflow_without_partial_accounting() {
        let mut count = 0;
        let mut bytes = 0;
        for (key, value) in [
            (String::new(), vec![]),
            ("k".repeat(SNAPSHOT_MAX_KEY_BYTES + 1), vec![]),
            ("k".into(), vec![0; SNAPSHOT_MAX_VALUE_BYTES + 1]),
        ] {
            assert!(account_snapshot_record(&mut count, &mut bytes, &key, &value).is_err());
            assert_eq!((count, bytes), (0, 0));
        }
        count = usize::MAX;
        assert!(account_snapshot_record(&mut count, &mut bytes, "k", b"").is_err());
        assert_eq!((count, bytes), (usize::MAX, 0));
        count = 0;
        bytes = usize::MAX;
        assert!(account_snapshot_record(&mut count, &mut bytes, "k", b"").is_err());
        assert_eq!((count, bytes), (0, usize::MAX));
    }
}
