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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use async_trait::async_trait;

use crate::error::AuthorityStoreError;
use crate::store::{
    account_snapshot_record, validate_snapshot_reads, AuthorityStore, SnapshotRead, StoreOp,
    StoreSnapshot, StoreTxn, StoreTxnOutcome, StoredRecord,
};

#[derive(Debug)]
struct MemoryInner {
    revision: u64,
    entries: BTreeMap<String, StoredRecord>,
    /// lease id -> keys attached to it (etcd parity: lease expiry/revoke
    /// deletes every attached key).
    leases: BTreeMap<i64, BTreeSet<String>>,
    /// Current lease owner for each attached key. The reverse index prevents
    /// an expired lease from deleting a newer record at the same key after a
    /// normal delete/recreate cycle.
    key_leases: BTreeMap<String, i64>,
    next_lease_id: i64,
}

impl Default for MemoryInner {
    fn default() -> Self {
        Self {
            // etcd reserves revision zero for nonexistence and starts at one.
            revision: 1,
            entries: BTreeMap::new(),
            leases: BTreeMap::new(),
            key_leases: BTreeMap::new(),
            next_lease_id: 0,
        }
    }
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

    fn detach_key(inner: &mut MemoryInner, key: &str) {
        let Some(lease_id) = inner.key_leases.remove(key) else {
            return;
        };
        if let Some(attached) = inner.leases.get_mut(&lease_id) {
            attached.remove(key);
        }
    }

    fn attach_key(inner: &mut MemoryInner, key: &str, lease_id: i64) {
        if let Some(previous_lease_id) = inner.key_leases.insert(key.to_owned(), lease_id) {
            if previous_lease_id != lease_id {
                if let Some(attached) = inner.leases.get_mut(&previous_lease_id) {
                    attached.remove(key);
                }
            }
        }
        inner
            .leases
            .entry(lease_id)
            .or_default()
            .insert(key.to_owned());
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
        let lease_id = inner.next_lease_id;
        inner.leases.insert(lease_id, BTreeSet::new());
        lease_id
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
        let mut removed = false;
        for key in attached {
            if inner.key_leases.get(&key).copied() != Some(lease_id) {
                continue;
            }
            inner.key_leases.remove(&key);
            removed |= inner.entries.remove(&key).is_some();
        }
        if removed {
            inner.revision += 1;
        }
        true
    }

    /// CAS `create_revision == 0` acquisition of the leader key, attached to
    /// `lease_id` (etcd parity with `PutOptions::with_lease`): when the lease
    /// is expired/revoked, the key disappears and every exact-value compare
    /// against `token_value` fails.
    pub fn try_acquire_leader_key(&self, key: &str, lease_id: i64, token_value: &[u8]) -> bool {
        let mut inner = self.inner.lock().expect("memory store poisoned");
        if !inner.leases.contains_key(&lease_id) {
            return false;
        }
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
        Self::attach_key(&mut inner, key, lease_id);
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

    async fn read_snapshot(
        &self,
        reads: &[SnapshotRead],
    ) -> Result<StoreSnapshot, AuthorityStoreError> {
        validate_snapshot_reads(reads)?;
        let inner = self.inner.lock().map_err(|_| {
            AuthorityStoreError::Unavailable("memory store lock poisoned".to_owned())
        })?;
        let mut results = Vec::with_capacity(reads.len());
        let (mut count, mut bytes) = (0, 0);
        for read in reads {
            let mut records = Vec::new();
            match read {
                SnapshotRead::Key(key) => {
                    if let Some(record) = inner.entries.get(key) {
                        account_snapshot_record(&mut count, &mut bytes, key, &record.value)?;
                        records.push((key.clone(), record.clone()));
                    }
                }
                SnapshotRead::Prefix(prefix) => {
                    for (key, record) in inner.entries.range(prefix.clone()..) {
                        if !key.starts_with(prefix) {
                            break;
                        }
                        account_snapshot_record(&mut count, &mut bytes, key, &record.value)?;
                        records.push((key.clone(), record.clone()));
                    }
                }
            }
            results.push(records);
        }
        Ok(StoreSnapshot {
            revision: inner.revision,
            reads: results,
        })
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
                StoreOp::RequireRevision {
                    key,
                    expected_revision,
                } => match inner.entries.get(key) {
                    Some(record) if record.revision == *expected_revision => {}
                    _ => {
                        return Ok(StoreTxnOutcome::PreconditionFailed { key: key.clone() });
                    }
                },
                StoreOp::RequireAbsent { key } => {
                    if inner.entries.contains_key(key) {
                        return Ok(StoreTxnOutcome::PreconditionFailed { key: key.clone() });
                    }
                }
            }
        }
        // A put always advances the transaction revision. A delete advances
        // it only when a key actually exists; deleting absent keys is a no-op.
        // Successful compare-only guards produce no operation response.
        let has_writes = txn.ops.iter().any(|op| match op {
            StoreOp::PutIfAbsent { .. }
            | StoreOp::ReplaceIfRevision { .. }
            | StoreOp::Put { .. } => true,
            StoreOp::Delete { key } | StoreOp::DeleteIfRevision { key, .. } => {
                inner.entries.contains_key(key)
            }
            StoreOp::RequireValue { .. }
            | StoreOp::RequireRevision { .. }
            | StoreOp::RequireAbsent { .. } => false,
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
                    Self::detach_key(&mut inner, key);
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
                    Self::detach_key(&mut inner, key);
                    inner.entries.remove(key);
                    revisions.push(revision);
                }
                StoreOp::RequireValue { .. } => {}
                StoreOp::RequireRevision { .. } => {}
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
    async fn existing_record_guards_reject_absence_without_partial_writes() {
        let store = MemoryAuthorityStore::new();
        for guard in [
            StoreOp::ReplaceIfRevision {
                key: "missing".into(),
                expected_revision: 0,
                value: b"unexpected".to_vec(),
            },
            StoreOp::DeleteIfRevision {
                key: "missing".into(),
                expected_revision: 0,
            },
            StoreOp::RequireRevision {
                key: "missing".into(),
                expected_revision: 0,
            },
            StoreOp::RequireValue {
                key: "missing".into(),
                value: Vec::new(),
            },
            StoreOp::ReplaceIfRevision {
                key: "missing".into(),
                expected_revision: u64::MAX,
                value: b"unexpected".to_vec(),
            },
            StoreOp::DeleteIfRevision {
                key: "missing".into(),
                expected_revision: u64::MAX,
            },
            StoreOp::RequireRevision {
                key: "missing".into(),
                expected_revision: u64::MAX,
            },
        ] {
            let revision = store.current_revision();
            let outcome = store
                .execute(StoreTxn::new().with_op(guard).with_op(StoreOp::Put {
                    key: "companion".into(),
                    value: b"unexpected".to_vec(),
                }))
                .await
                .unwrap();
            assert!(matches!(
                outcome,
                StoreTxnOutcome::PreconditionFailed { .. }
            ));
            assert_eq!(store.current_revision(), revision);
            assert!(store.get("missing").await.unwrap().is_none());
            assert!(store.get("companion").await.unwrap().is_none());
        }

        store
            .execute(StoreTxn::new().with_op(StoreOp::Put {
                key: "empty".into(),
                value: Vec::new(),
            }))
            .await
            .unwrap();
        assert!(matches!(
            store
                .execute(StoreTxn::new().with_op(StoreOp::RequireValue {
                    key: "empty".into(),
                    value: Vec::new(),
                }))
                .await
                .unwrap(),
            StoreTxnOutcome::Applied { .. }
        ));
    }

    #[tokio::test]
    async fn snapshot_reads_exact_keys_and_complete_prefix_at_one_revision() {
        let store = MemoryAuthorityStore::new();
        store
            .execute(
                StoreTxn::new()
                    .with_op(StoreOp::Put {
                        key: "scope/b".into(),
                        value: b"b".to_vec(),
                    })
                    .with_op(StoreOp::Put {
                        key: "scope/a".into(),
                        value: b"a".to_vec(),
                    })
                    .with_op(StoreOp::Put {
                        key: "frontier".into(),
                        value: b"f".to_vec(),
                    }),
            )
            .await
            .unwrap();
        let snapshot = store
            .read_snapshot(&[
                SnapshotRead::Key("frontier".into()),
                SnapshotRead::Prefix("scope/".into()),
                SnapshotRead::Key("absent".into()),
            ])
            .await
            .unwrap();
        assert_eq!(snapshot.revision, store.current_revision());
        assert_eq!(snapshot.reads[0][0].1.value, b"f");
        assert_eq!(
            snapshot.reads[1]
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            vec!["scope/a", "scope/b"]
        );
        assert!(snapshot.reads[2].is_empty());
        assert!(snapshot
            .reads
            .iter()
            .flatten()
            .all(|(_, record)| record.revision == snapshot.revision));
    }

    #[tokio::test]
    async fn snapshot_rejects_invalid_and_oversized_results() {
        let store = MemoryAuthorityStore::new();
        assert!(store.read_snapshot(&[]).await.is_err());
        assert!(store
            .read_snapshot(&[SnapshotRead::Prefix(String::new())])
            .await
            .is_err());
        assert!(store
            .read_snapshot(&vec![
                SnapshotRead::Key("a".into());
                super::super::SNAPSHOT_MAX_READS + 1
            ])
            .await
            .is_err());
        store
            .execute(StoreTxn::new().with_op(StoreOp::Put {
                key: "large".into(),
                value: vec![0; super::super::SNAPSHOT_MAX_BYTES],
            }))
            .await
            .unwrap();
        assert!(store
            .read_snapshot(&[SnapshotRead::Key("large".into())])
            .await
            .is_err());
        let mut txn = StoreTxn::new();
        for index in 0..=super::super::SNAPSHOT_MAX_RECORDS {
            txn = txn.with_op(StoreOp::Put {
                key: format!("prefix/{index:04}"),
                value: vec![],
            });
        }
        store.execute(txn).await.unwrap();
        assert!(store
            .read_snapshot(&[SnapshotRead::Prefix("prefix/".into())])
            .await
            .is_err());
    }

    #[tokio::test]
    async fn snapshot_rejects_overlapping_reads_and_accepts_disjoint_ranges() {
        let store = MemoryAuthorityStore::new();
        let invalid = [
            vec![SnapshotRead::Key("a".into()), SnapshotRead::Key("a".into())],
            vec![
                SnapshotRead::Prefix("a/".into()),
                SnapshotRead::Prefix("a/".into()),
            ],
            vec![
                SnapshotRead::Prefix("a/".into()),
                SnapshotRead::Prefix("a/b/".into()),
            ],
            vec![
                SnapshotRead::Prefix("a/b/".into()),
                SnapshotRead::Prefix("a/".into()),
            ],
            vec![
                SnapshotRead::Prefix("a/".into()),
                SnapshotRead::Key("a/b".into()),
            ],
            vec![
                SnapshotRead::Key("a/b".into()),
                SnapshotRead::Prefix("a/".into()),
            ],
        ];
        for reads in invalid {
            assert!(matches!(
                store.read_snapshot(&reads).await,
                Err(AuthorityStoreError::Configuration(_))
            ));
        }
        assert!(store
            .read_snapshot(&[
                SnapshotRead::Key("a".into()),
                SnapshotRead::Prefix("a/".into()),
                SnapshotRead::Prefix("b/".into()),
            ])
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn snapshot_applies_record_limit_across_disjoint_reads() {
        let store = MemoryAuthorityStore::new();
        let mut txn = StoreTxn::new();
        for index in 0..=super::super::SNAPSHOT_MAX_RECORDS {
            let prefix = if index % 2 == 0 { "a/" } else { "b/" };
            txn = txn.with_op(StoreOp::Put {
                key: format!("{prefix}{index:04}"),
                value: vec![],
            });
        }
        store.execute(txn).await.unwrap();
        for prefix in ["a/", "b/"] {
            assert!(store
                .read_snapshot(&[SnapshotRead::Prefix(prefix.into())])
                .await
                .is_ok());
        }
        assert!(matches!(
            store
                .read_snapshot(&[
                    SnapshotRead::Prefix("a/".into()),
                    SnapshotRead::Prefix("b/".into())
                ])
                .await,
            Err(AuthorityStoreError::Unavailable(_))
        ));
    }

    #[tokio::test]
    async fn revisions_start_at_one_and_only_real_deletes_advance_them() {
        let store = MemoryAuthorityStore::new();
        let initial = store
            .read_snapshot(&[SnapshotRead::Key("missing".into())])
            .await
            .unwrap();
        assert_eq!(initial.revision, 1);
        assert!(initial.reads[0].is_empty());

        let outcome = store
            .execute(
                StoreTxn::new()
                    .with_op(StoreOp::Delete {
                        key: "missing".into(),
                    })
                    .with_op(StoreOp::Delete {
                        key: "other".into(),
                    }),
            )
            .await
            .unwrap();
        assert_eq!(
            outcome,
            StoreTxnOutcome::Applied {
                revisions: vec![1, 1]
            }
        );
        assert_eq!(store.current_revision(), 1);
        store
            .execute(StoreTxn::new().with_op(StoreOp::Put {
                key: "present".into(),
                value: vec![1],
            }))
            .await
            .unwrap();
        assert_eq!(store.current_revision(), 2);
        store
            .execute(
                StoreTxn::new()
                    .with_op(StoreOp::Delete {
                        key: "missing".into(),
                    })
                    .with_op(StoreOp::Delete {
                        key: "present".into(),
                    }),
            )
            .await
            .unwrap();
        assert_eq!(store.current_revision(), 3);
        assert!(store.get("present").await.unwrap().is_none());
        store
            .execute(StoreTxn::new().with_op(StoreOp::Delete {
                key: "present".into(),
            }))
            .await
            .unwrap();
        assert_eq!(store.current_revision(), 3);

        let lease = store.grant_lease(1);
        assert!(store.try_acquire_leader_key("leader", lease, b"token"));
        let before_expire = store.current_revision();
        assert!(store.expire_lease(lease));
        assert_eq!(store.current_revision(), before_expire + 1);
        assert!(!store.expire_lease(lease));
        assert_eq!(store.current_revision(), before_expire + 1);

        let lease = store.grant_lease(1);
        assert!(store.try_acquire_leader_key("leader", lease, b"token"));
        store
            .execute(StoreTxn::new().with_op(StoreOp::Delete {
                key: "leader".into(),
            }))
            .await
            .unwrap();
        let after_delete = store.current_revision();
        assert!(store.expire_lease(lease));
        assert_eq!(store.current_revision(), after_delete);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn snapshot_never_mixes_concurrent_transaction_versions() {
        let store = std::sync::Arc::new(MemoryAuthorityStore::new());
        let writer = store.clone();
        let task = tokio::spawn(async move {
            for n in 1_u32..=500 {
                let value = n.to_be_bytes().to_vec();
                writer
                    .execute(
                        StoreTxn::new()
                            .with_op(StoreOp::Put {
                                key: "a".into(),
                                value: value.clone(),
                            })
                            .with_op(StoreOp::Put {
                                key: "b".into(),
                                value,
                            }),
                    )
                    .await
                    .unwrap();
                tokio::task::yield_now().await;
            }
        });
        for _ in 0..500 {
            let snapshot = store
                .read_snapshot(&[SnapshotRead::Key("a".into()), SnapshotRead::Key("b".into())])
                .await
                .unwrap();
            assert_eq!(
                snapshot.reads[0].first().map(|(_, record)| record),
                snapshot.reads[1].first().map(|(_, record)| record)
            );
            tokio::task::yield_now().await;
        }
        task.await.unwrap();
    }

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
    async fn require_revision_guards_writes_without_changing_record_or_lease() {
        let store = MemoryAuthorityStore::new();
        let lease = store.grant_lease(15);
        assert!(store.try_acquire_leader_key("guard", lease, b"token"));
        let guarded = store.get("guard").await.unwrap().unwrap();
        let revision_before = store.current_revision();

        let guard = || StoreOp::RequireRevision {
            key: "guard".into(),
            expected_revision: guarded.revision,
        };
        assert_eq!(guard().key(), "guard");
        assert_eq!(
            store
                .execute(StoreTxn::new().with_op(guard()))
                .await
                .unwrap(),
            StoreTxnOutcome::Applied { revisions: vec![] }
        );
        assert_eq!(store.current_revision(), revision_before);
        let outcome = store
            .execute(StoreTxn::new().with_op(guard()).with_op(StoreOp::Put {
                key: "result".into(),
                value: b"ok".to_vec(),
            }))
            .await
            .unwrap();
        assert_eq!(
            outcome,
            StoreTxnOutcome::Applied {
                revisions: vec![revision_before + 1]
            }
        );
        assert_eq!(store.get("guard").await.unwrap(), Some(guarded));
        assert_eq!(store.get("result").await.unwrap().unwrap().value, b"ok");
        assert!(store.expire_lease(lease));
        assert_eq!(store.get("guard").await.unwrap(), None);
        assert_eq!(store.get("result").await.unwrap().unwrap().value, b"ok");
    }

    #[tokio::test]
    async fn require_revision_failure_prevents_all_writes() {
        let store = MemoryAuthorityStore::new();
        store
            .execute(StoreTxn::new().with_op(StoreOp::Put {
                key: "guard".into(),
                value: b"original".to_vec(),
            }))
            .await
            .unwrap();
        let guarded = store.get("guard").await.unwrap().unwrap();
        let revision_before = store.current_revision();
        for (key, expected_revision) in [
            ("guard", guarded.revision + 1),
            ("guard", u64::MAX),
            ("missing", 0),
            ("missing", guarded.revision),
        ] {
            let outcome = store
                .execute(
                    StoreTxn::new()
                        .with_op(StoreOp::Put {
                            key: "before".into(),
                            value: b"must not write".to_vec(),
                        })
                        .with_op(StoreOp::RequireRevision {
                            key: key.into(),
                            expected_revision,
                        })
                        .with_op(StoreOp::Put {
                            key: "after".into(),
                            value: b"must not write".to_vec(),
                        }),
                )
                .await
                .unwrap();
            assert_eq!(
                outcome,
                StoreTxnOutcome::PreconditionFailed { key: key.into() }
            );
            assert_eq!(store.get("before").await.unwrap(), None);
            assert_eq!(store.get("after").await.unwrap(), None);
            assert_eq!(store.get("guard").await.unwrap(), Some(guarded.clone()));
            assert_eq!(store.current_revision(), revision_before);
        }
    }

    #[tokio::test]
    async fn leader_key_requires_an_active_granted_lease() {
        let store = MemoryAuthorityStore::new();

        assert!(!store.try_acquire_leader_key("ungranted", 1, b"token"));

        let lease = store.grant_lease(15);
        assert!(store.lease_keep_alive(lease));
        assert!(store.try_acquire_leader_key("leader", lease, b"token"));

        assert!(store.expire_lease(lease));
        assert!(!store.try_acquire_leader_key("expired", lease, b"token"));
    }

    #[tokio::test]
    async fn expired_lease_does_not_delete_a_recreated_key_owned_by_another_lease() {
        let store = MemoryAuthorityStore::new();
        let lease_a = store.grant_lease(15);
        assert!(store.try_acquire_leader_key("leader", lease_a, b"token-a"));

        store
            .execute(StoreTxn::new().with_op(StoreOp::Delete {
                key: "leader".to_owned(),
            }))
            .await
            .unwrap();

        let lease_b = store.grant_lease(15);
        assert!(store.try_acquire_leader_key("leader", lease_b, b"token-b"));
        assert!(store.expire_lease(lease_a));
        assert_eq!(
            store.get("leader").await.unwrap().unwrap().value,
            b"token-b"
        );
        assert!(store.lease_keep_alive(lease_b));
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
