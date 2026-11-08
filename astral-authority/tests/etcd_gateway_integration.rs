#![cfg(feature = "service")]

//! Ignored integration test against a real etcd quorum through the v3 JSON
//! gateway.
//!
//! Semantics per repo rules:
//! - This test is `#[ignore]`d by default and never counts as a PASS by
//!   itself.
//! - When `RUST_INTEGRATION_REQUIRED=1` is set but the environment is
//!   missing, the test FAILS loudly instead of silently skipping.
//! - Without `RUST_INTEGRATION_REQUIRED=1` and without a reachable etcd, it
//!   reports `[SKIP]` (recorded as skipped, never as passed).
//!
//! Environment:
//! - `ASTRAL_AUTHORITY_ETCD_ENDPOINTS` — comma-separated gateway endpoints
//!   (default `http://127.0.0.1:2379`).

use astral_authority::store::etcd::EtcdAuthorityStore;
use astral_authority::store::{AuthorityStore, StoreOp, StoreTxn};

fn endpoints() -> Vec<String> {
    std::env::var("ASTRAL_AUTHORITY_ETCD_ENDPOINTS")
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_else(|_| vec!["http://127.0.0.1:2379".to_owned()])
}

#[tokio::test]
#[ignore = "requires a real etcd quorum with the v3 JSON gateway enabled"]
async fn etcd_gateway_store_contract() {
    let required = std::env::var("RUST_INTEGRATION_REQUIRED").as_deref() == Ok("1");
    let endpoints = endpoints();
    let store = match EtcdAuthorityStore::connect(&endpoints, false, None, None, None, None).await {
        Ok(store) => store,
        Err(error) => {
            if required {
                panic!(
                    "RUST_INTEGRATION_REQUIRED=1: cannot connect etcd gateway {endpoints:?}: {error}"
                );
            }
            eprintln!("[SKIP] etcd gateway not reachable: {error}");
            return;
        }
    };

    let run_id = uuid::Uuid::new_v4().simple().to_string();
    let key = format!("astral-authority-integration/{run_id}/cas");
    let second = format!("astral-authority-integration/{run_id}/second");

    // Linearizable get of a missing key.
    assert!(store.get(&key).await.unwrap().is_none());

    // Put-if-absent wins exactly once.
    let first = store
        .execute(StoreTxn::new().with_op(StoreOp::PutIfAbsent {
            key: key.clone(),
            value: b"one".to_vec(),
        }))
        .await
        .unwrap();
    let first_revision = match first {
        astral_authority::store::StoreTxnOutcome::Applied { revisions } => revisions[0],
        other => panic!("first put-if-absent must apply, got {other:?}"),
    };
    assert!(first_revision > 0);

    // Second put-if-absent on the same key must fail the precondition.
    let replay = store
        .execute(StoreTxn::new().with_op(StoreOp::PutIfAbsent {
            key: key.clone(),
            value: b"two".to_vec(),
        }))
        .await
        .unwrap();
    assert!(matches!(
        replay,
        astral_authority::store::StoreTxnOutcome::PreconditionFailed { .. }
    ));

    // Atomic multi-key txn: one failing precondition writes NOTHING.
    let atomic = store
        .execute(
            StoreTxn::new()
                .with_op(StoreOp::ReplaceIfRevision {
                    key: key.clone(),
                    expected_revision: first_revision + 1,
                    value: b"never".to_vec(),
                })
                .with_op(StoreOp::Put {
                    key: second.clone(),
                    value: b"also-never".to_vec(),
                }),
        )
        .await
        .unwrap();
    assert!(matches!(
        atomic,
        astral_authority::store::StoreTxnOutcome::PreconditionFailed { .. }
    ));
    assert!(
        store.get(&second).await.unwrap().is_none(),
        "a failed txn must not partially write"
    );

    // Matching CAS + companion write lands at one shared revision.
    let applied = store
        .execute(
            StoreTxn::new()
                .with_op(StoreOp::ReplaceIfRevision {
                    key: key.clone(),
                    expected_revision: first_revision,
                    value: b"updated".to_vec(),
                })
                .with_op(StoreOp::Put {
                    key: second.clone(),
                    value: b"companion".to_vec(),
                }),
        )
        .await
        .unwrap();
    match applied {
        astral_authority::store::StoreTxnOutcome::Applied { revisions } => {
            assert_eq!(revisions.len(), 2);
            assert_eq!(revisions[0], revisions[1], "one revision per txn");
        }
        other => panic!("CAS txn must apply, got {other:?}"),
    }

    // Prefix scan is linearizable and ordered.
    let prefix = format!("astral-authority-integration/{run_id}/");
    let records = store.get_prefix(&prefix).await.unwrap();
    assert_eq!(records.len(), 2);
    assert!(records[0].0 < records[1].0);

    // Leader lease lifecycle: grant, acquire via CAS (the key carries the
    // exact term token value and is attached to the lease), keep alive.
    let lease_id = store.lease_grant(10).await.unwrap();
    let leader_key = format!("astral-authority-integration/{run_id}/leader");
    let token_value = astral_authority::service::leadership::LeadershipTokenRecord::new(
        "authority-integration",
        "etcd-gateway-itest",
        lease_id,
    )
    .encode();
    let acquired = store
        .try_acquire_leader_key(&leader_key, lease_id, &token_value)
        .await
        .unwrap();
    assert!(acquired, "first acquire must win");
    let reacquired = store
        .try_acquire_leader_key(&leader_key, lease_id, &token_value)
        .await
        .unwrap();
    assert!(!reacquired, "second acquire must lose the CAS");
    assert!(store.lease_keep_alive(lease_id).await.unwrap());

    // Cleanup: the test owns only its run-scoped keys and deletes them.
    for (key, record) in store
        .get_prefix(&format!("astral-authority-integration/{run_id}/"))
        .await
        .unwrap()
    {
        let _ = store
            .execute(StoreTxn::new().with_op(StoreOp::DeleteIfRevision {
                key,
                expected_revision: record.revision,
            }))
            .await;
    }
    assert!(store
        .get_prefix(&format!("astral-authority-integration/{run_id}/"))
        .await
        .unwrap()
        .is_empty());
}
