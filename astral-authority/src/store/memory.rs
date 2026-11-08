//! In-memory implementation of the authority store contract.
//!
//! Used by store-contract tests and as a reference for the etcd semantics:
//! one shared revision per applied transaction, strict precondition checks,
//! and strictly linearizable reads (the mutex is the total order). This store
//! is not durable and must not be used in production deployments.
//!
//! Lease parity: [`MemoryAuthorityStore::grant_lease`] allocates a lease,
//! [`MemoryAuthorityStore::try_acquire_leader_key`] attaches a CAS-written
//! key to it, and [`MemoryAuthorityStore::expire_lease`] deterministically
//! reproduces the etcd lease expiry/revoke effect (every attached key is
//! deleted, the leader key included). Expiry is explicit instead of
//! wall-clock so tests are deterministic; the observable state transitions
//! are the production ones.

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::error::AuthorityStoreError;
use crate::store::{AuthorityStore, StoreOp, StoreTxn, StoreTxnOutcome, StoredRecord};

#[derive(Debug, Default)]
struct MemoryInner {
    revision: u64,
    entries: BTreeMap<String, StoredRecord>,
    /// lease id -> keys attached to it (etcd parity: lease expiry/revoke
    /// deletes every attached key).
    leases: BTreeMap<i64, Vec<String>>,
    next_lease_id: i64,
}

/// In-memory store with etcd-equivalent CAS semantics.
#[derive(Debug, Default)]
pub struct MemoryAuthorityStore {
    inner: Mutex<MemoryInner>,
}

impl MemoryAuthorityStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Current global revision (test observation only).
    pub fn current_revision(&self) -> u64 {
        self.inner.lock().expect("memory store poisoned").revision
    }

    /// Allocate a lease id (etcd `lease_grant` parity). The TTL is accepted
    /// for signature parity; expiry is controlled deterministically through
    /// [`Self::expire_lease`].
    pub fn grant_lease(&self, ttl_seconds: i64) -> i64 {
        let _unused = ttl_seconds;
        let mut inner = self.inner.lock().expect("memory store poisoned");
        inner.next_lease_id += 1;
        inner.next_lease_id
    }

    /// True while the lease has been granted and not expired/revoked.
    pub fn lease_keep_alive(&self, lease_id: i64) -> bool {
        let inner = self.inner.lock().expect("memory store poisoned");
        inner.leases.contains_key(&lease_id)
    }

    /// Reproduce the etcd lease expiry/revoke effect: delete the lease and
    /// every key attached to it. Returns true when the lease existed.
    pub fn expire_lease(&self, lease_id: i64) -> bool {
        let mut inner = self.inner.lock().expect("memory store poisoned");
        let Some(attached) = inner.leases.remove(&lease_id) else {
            return false;
        };
        for key in attached {
            inner.entries.remove(&key);
        }
        true
    }

    /// CAS `create_revision == 0` acquisition of the leader key, attached to
    /// `lease_id` (etcd parity with `PutOptions::with_lease`): when the lease
    /// is expired/revoked, the key disappears and every exact-value compare
    /// against `token_value` fails.
    pub fn try_acquire_leader_key(&self, key: &str, lease_id: i64, token_value: &[u8]) -> bool {
        let mut inner = self.inner.lock().expect("memory store poisoned");
        if inner.entries.contains_key(key) {
            return false;
        }
        let revision = inner.revision + 1;
        inner.revision = revision;
        inner.entries.insert(
            key.to_owned(),
            StoredRecord {
                revision,
                value: token_value.to_vec(),
            },
        );
        inner
            .leases
            .entry(lease_id)
            .or_default()
            .push(key.to_owned());
        true
    }
}

#[async_trait]
impl AuthorityStore for MemoryAuthorityStore {
    async fn get(&self, key: &str) -> Result<Option<StoredRecord>, AuthorityStoreError> {
        let inner = self.inner.lock().expect("memory store poisoned");
        Ok(inner.entries.get(key).cloned())
    }

    async fn get_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<(String, StoredRecord)>, AuthorityStoreError> {
        let inner = self.inner.lock().expect("memory store poisoned");
        Ok(inner
            .entries
            .range(prefix.to_owned()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, record)| (key.clone(), record.clone()))
            .collect())
    }

    async fn execute(&self, txn: StoreTxn) -> Result<StoreTxnOutcome, AuthorityStoreError> {
        let mut inner = self.inner.lock().expect("memory store poisoned");
        // Check every precondition first; nothing is written unless all hold.
        for op in &txn.ops {
            match op {
                StoreOp::PutIfAbsent { key, .. } => {
                    if inner.entries.contains_key(key) {
                        return Ok(StoreTxnOutcome::PreconditionFailed { key: key.clone() });
                    }
                }
                StoreOp::ReplaceIfRevision {
                    key,
                    expected_revision,
                    ..
                } => match inner.entries.get(key) {
                    Some(record) if record.revision == *expected_revision => {}
                    _ => {
                        return Ok(StoreTxnOutcome::PreconditionFailed { key: key.clone() });
                    }
                },
                StoreOp::Put { .. } => {}
                StoreOp::Delete { key: _ } => {}
                StoreOp::DeleteIfRevision {
                    key,
                    expected_revision,
                } => match inner.entries.get(key) {
                    Some(record) if record.revision == *expected_revision => {}
                    _ => {
                        return Ok(StoreTxnOutcome::PreconditionFailed { key: key.clone() });
                    }
                },
                StoreOp::RequireValue { key, value } => {
                    // Compare-only: the record must exist and hold EXACTLY
                    // these bytes; nothing is ever written for this op.
                    match inner.entries.get(key) {
                        Some(record) if record.value == *value => {}
                        _ => {
                            return Ok(StoreTxnOutcome::PreconditionFailed { key: key.clone() });
                        }
                    }
                }
                StoreOp::RequireAbsent { key } => {
                    if inner.entries.contains_key(key) {
                        return Ok(StoreTxnOutcome::PreconditionFailed { key: key.clone() });
                    }
                }
            }
        }
        // etcd assigns one revision per transaction; mirror that here.
        // RequireValue produces no revision (compare-only), so a txn with no
        // mutating ops consumes no revision, and the reported revisions align
        // with the mutating ops only, matching the etcd implementation's
        // op_response mapping.
        let has_writes = txn.ops.iter().any(|op| {
            !matches!(
                op,
                StoreOp::RequireValue { .. } | StoreOp::RequireAbsent { .. }
            )
        });
        if has_writes {
            inner.revision += 1;
        }
        let revision = inner.revision;
        let mut revisions = Vec::new();
        for op in &txn.ops {
            match op {
                StoreOp::PutIfAbsent { key, value }
                | StoreOp::ReplaceIfRevision { key, value, .. }
                | StoreOp::Put { key, value } => {
                    inner.entries.insert(
                        key.clone(),
                        StoredRecord {
                            revision,
                            value: value.clone(),
                        },
                    );
                    revisions.push(revision);
                }
                StoreOp::Delete { key } | StoreOp::DeleteIfRevision { key, .. } => {
                    inner.entries.remove(key);
                    revisions.push(revision);
                }
                StoreOp::RequireValue { .. } => {}
                StoreOp::RequireAbsent { .. } => {}
            }
        }
        Ok(StoreTxnOutcome::Applied { revisions })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn require_value_is_compare_only_and_exact() {
        let store = MemoryAuthorityStore::new();
        store
            .execute(StoreTxn::new().with_op(StoreOp::PutIfAbsent {
                key: "k".to_owned(),
                value: b"v1".to_vec(),
            }))
            .await
            .unwrap();
        let revision_before = store.current_revision();

        // Exact match: applied, but nothing written and no revision consumed.
        let outcome = store
            .execute(StoreTxn::new().with_op(StoreOp::RequireValue {
                key: "k".to_owned(),
                value: b"v1".to_vec(),
            }))
            .await
            .unwrap();
        assert_eq!(outcome, StoreTxnOutcome::Applied { revisions: vec![] });
        assert_eq!(store.current_revision(), revision_before);

        // Mutating op after the guard still lands at one revision.
        let outcome = store
            .execute(
                StoreTxn::new()
                    .with_op(StoreOp::RequireValue {
                        key: "k".to_owned(),
                        value: b"v1".to_vec(),
                    })
                    .with_op(StoreOp::PutIfAbsent {
                        key: "k2".to_owned(),
                        value: b"v2".to_vec(),
                    }),
            )
            .await
            .unwrap();
        assert_eq!(
            outcome,
            StoreTxnOutcome::Applied {
                revisions: vec![store.current_revision()]
            }
        );

        // Value divergence and missing key are both precondition failures.
        for probe in [b"v2".to_vec(), Vec::new()] {
            let outcome = store
                .execute(StoreTxn::new().with_op(StoreOp::RequireValue {
                    key: "k".to_owned(),
                    value: probe,
                }))
                .await
                .unwrap();
            assert_eq!(
                outcome,
                StoreTxnOutcome::PreconditionFailed {
                    key: "k".to_owned()
                }
            );
        }
        assert_eq!(store.current_revision(), revision_before + 1);
    }

    #[tokio::test]
    async fn lease_expiry_deletes_attached_leader_key_and_breaks_fence() {
        let store = MemoryAuthorityStore::new();
        let lease = store.grant_lease(15);
        assert!(store.try_acquire_leader_key("leader", lease, b"token-a"));
        assert!(store.lease_keep_alive(lease));
        assert!(store.get("leader").await.unwrap().is_some());

        // Second acquisition while held is refused (CAS create_revision==0).
        let lease_b = store.grant_lease(15);
        assert!(!store.try_acquire_leader_key("leader", lease_b, b"token-b"));

        // Expiry deletes the attached key; the next term can acquire.
        assert!(store.expire_lease(lease));
        assert!(!store.lease_keep_alive(lease));
        assert!(store.get("leader").await.unwrap().is_none());
        assert!(store.try_acquire_leader_key("leader", lease_b, b"token-b"));
        // Expiring again is a no-op that reports false.
        assert!(!store.expire_lease(lease));
    }
}
