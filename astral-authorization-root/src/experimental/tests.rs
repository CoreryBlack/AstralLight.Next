use super::*;
use crate::model::{
    SingleNodeCardRuleSetRef, SingleNodeDatabaseSnapshot, SingleNodeDomain, SingleNodeIdentityCard,
    SingleNodeMemoryRoot, SingleNodePermissionRule, SingleNodeRootVersion, SingleNodeRuleSet,
    SingleNodeRuleSetEntry, SingleNodeTenant, SingleNodeUser, SingleNodeUserCard,
};
use astral_types::{BindingLayer, GrantEffect, ValidityWindow};
use std::sync::{mpsc, Barrier};
use std::thread;

fn operation(value: &str) -> OperationId {
    OperationId::new(value).unwrap()
}

fn make_owner() -> RootOwner {
    // Independent instances keep parallel unit tests isolated; the public
    // constructor's process-wide registration is tested separately.
    RootOwner::with_registration(false)
}

fn root(binding_id: i64, entry_id: i64, direct_rule_id: i64) -> SingleNodeMemoryRoot {
    SingleNodeMemoryRoot::build(SingleNodeDatabaseSnapshot {
        version: SingleNodeRootVersion {
            source_snapshot_id: "mysql-snapshot-1".to_owned(),
            generation: 7,
            dependency_frontier_digest: "ab".repeat(32),
            revoke_watermark: 2,
        },
        users: vec![SingleNodeUser {
            user_id: 20,
            status: "ACTIVE".to_owned(),
            deleted_at_unix: None,
        }],
        identity_cards: vec![SingleNodeIdentityCard {
            card_id: 10,
            user_id: 20,
            status: "ACTIVE".to_owned(),
            expires_at_unix: None,
        }],
        user_cards: vec![
            card(40, 30, Some(50)),
            card(41, 31, Some(50)),
            card(40, 32, None),
        ],
        tenants: vec![
            SingleNodeTenant {
                tenant_id: 40,
                tenant_code: "tenant-a".to_owned(),
                parent_tenant_id: None,
            },
            SingleNodeTenant {
                tenant_id: 41,
                tenant_code: "tenant-b".to_owned(),
                parent_tenant_id: None,
            },
        ],
        domains: vec![SingleNodeDomain {
            domain_id: 50,
            domain_code: Some("domain-a".to_owned()),
        }],
        tenant_domains: vec![],
        org_memberships: vec![],
        rule_sets: vec![
            SingleNodeRuleSet {
                rule_set_id: 70,
                code: "base-a".to_owned(),
                tenant_id: Some(40),
                source_type: "MANUAL".to_owned(),
                source_id: Some(70),
                status: "ACTIVE".to_owned(),
            },
            SingleNodeRuleSet {
                rule_set_id: 71,
                code: "base-b".to_owned(),
                tenant_id: Some(41),
                source_type: "MANUAL".to_owned(),
                source_id: Some(71),
                status: "ACTIVE".to_owned(),
            },
        ],
        rule_set_entries: vec![entry(entry_id, 70), entry(81, 71)],
        card_rule_set_refs: vec![
            SingleNodeCardRuleSetRef {
                binding_id,
                card_id: 30,
                rule_set_id: 70,
                tenant_id: 40,
                binding_layer: BindingLayer::Base,
            },
            SingleNodeCardRuleSetRef {
                binding_id: 101,
                card_id: 31,
                rule_set_id: 71,
                tenant_id: 41,
                binding_layer: BindingLayer::Base,
            },
        ],
        permission_rules: vec![rule(direct_rule_id, 40, 30), rule(122, 41, 31)],
        published_pointers: vec![],
        global_admins: vec![],
        sod_policies: vec![],
    })
    .expect("fixture is a valid candidate root")
}

fn card(tenant_id: i64, card_id: i64, domain_id: Option<i64>) -> SingleNodeUserCard {
    SingleNodeUserCard {
        card_id,
        user_id: Some(20),
        tenant_id,
        domain_id,
        status: "ACTIVE".to_owned(),
        valid_from_unix: None,
        valid_to_unix: None,
    }
}

fn entry(entry_id: i64, rule_set_id: i64) -> SingleNodeRuleSetEntry {
    SingleNodeRuleSetEntry {
        entry_id,
        rule_set_id,
        resource_type: "device".to_owned(),
        resource_id: Some(90),
        action_code: "read".to_owned(),
        effect: GrantEffect::Allow,
        condition_json: None,
        priority: 1,
        enabled: true,
        validity: ValidityWindow::perpetual(),
    }
}

fn rule(rule_id: i64, tenant_id: i64, card_id: i64) -> SingleNodePermissionRule {
    SingleNodePermissionRule {
        rule_id,
        card_id,
        tenant_id,
        resource_type: "device".to_owned(),
        resource_id: Some(90),
        action_code: "read".to_owned(),
        effect: GrantEffect::Allow,
        condition_json: Some("{\"region\":\"local\"}".to_owned()),
        priority: 3,
        source_type: "MANUAL".to_owned(),
        source_id: None,
        enabled: true,
        validity: ValidityWindow::perpetual(),
    }
}

fn install(owner: &RootOwner, id: &str, candidate: SingleNodeMemoryRoot) {
    owner
        .close_for_mutation(operation(id), Duration::from_secs(30))
        .unwrap()
        .install_for_test(candidate, Instant::now() + Duration::from_secs(30))
        .unwrap();
}

fn read(
    handle: &RootHandle,
    tenant_id: i64,
    card_id: i64,
) -> Result<Option<ScopedCardFacts>, Error> {
    handle.begin_read(tenant_id, card_id)?.commit()
}

#[test]
fn public_owner_is_unique_and_drop_revokes_old_handles() {
    let _serial = crate::TEST_OWNER_LOCK.lock().unwrap();
    let first = RootOwner::new().unwrap();
    let manager_budget = crate::manager::ManagerBudget {
        build: crate::model::SingleNodeRootBuildBudget::default(),
        attempt_timeout: Duration::from_secs(10),
        candidate_ttl: Duration::from_secs(10),
    };
    assert!(matches!(
        crate::manager::RootManager::new(manager_budget),
        Err(crate::manager::Error::AlreadyRegistered)
    ));
    let old = first.handle();
    assert!(matches!(RootOwner::new(), Err(Error::OwnerAlreadyExists)));
    drop(first);
    assert_eq!(
        old.status().unwrap().gate,
        GateStatus::Closed {
            reason: ClosedReason::OwnerDropped,
            operation_id: None
        }
    );
    let replacement = RootOwner::new().unwrap();
    assert!(!old.same_instance(&replacement.handle()));
    assert_eq!(old.begin_read(40, 30).err(), Some(Error::Closed));

    drop(replacement);
    let manager = crate::manager::RootManager::new(manager_budget).unwrap();
    assert!(matches!(RootOwner::new(), Err(Error::OwnerAlreadyExists)));
    drop(manager);
    let replacement = RootOwner::new().unwrap();
    let active = replacement
        .close_for_mutation(operation("still-active"), Duration::from_secs(30))
        .unwrap();
    let closed = replacement.handle();
    drop(replacement);
    assert_eq!(
        closed.status().unwrap().gate,
        GateStatus::Closed {
            reason: ClosedReason::OwnerDropped,
            operation_id: Some(operation("still-active")),
        }
    );
    assert!(matches!(RootOwner::new(), Err(Error::OwnerAlreadyExists)));
    drop(active);
    drop(closed);
    assert!(matches!(RootOwner::new(), Err(Error::OwnerAlreadyExists)));
    let retained = UNRESOLVED_OWNER.get().unwrap().lock().unwrap();
    assert_eq!(
        retained.status().gate,
        GateStatus::Closed {
            reason: ClosedReason::OwnerDropped,
            operation_id: Some(operation("still-active")),
        }
    );
    // The sticky registration is process-wide; reset it only in this isolated test.
    OWNER_EXISTS.store(false, Ordering::Release);
}

#[test]
fn shared_views_return_only_scoped_model_facts() {
    let owner = make_owner();
    let one = owner.handle();
    let two = one.clone();
    assert!(one.same_instance(&two));
    assert_eq!(one.begin_read(40, 30).err(), Some(Error::Closed));
    install(&owner, "install-1", root(100, 80, 121));

    let a = read(&one, 40, 30).unwrap().unwrap();
    assert_eq!(
        a.bindings
            .iter()
            .map(|row| row.binding_id)
            .collect::<Vec<_>>(),
        vec![100]
    );
    assert_eq!(a.entries, vec![entry(80, 70)]);
    assert_eq!(a.direct_rules, vec![rule(121, 40, 30)]);
    let b = read(&two, 41, 31).unwrap().unwrap();
    assert_eq!(b.bindings[0].binding_id, 101);
    assert_eq!(b.entries[0].entry_id, 81);
    assert_eq!(b.direct_rules[0].rule_id, 122);
    assert_eq!(read(&one, 40, 31), Ok(None));
    assert_eq!(read(&two, 41, 30), Ok(None));
    assert_eq!(read(&two, 42, 30), Ok(None));
    assert_eq!(read(&one, 40, 32), Ok(None));
    assert_eq!(one.begin_read(0, 30).err(), Some(Error::InvalidScope));
    assert_eq!(one.begin_read(40, 0).err(), Some(Error::InvalidScope));
    assert_eq!(one.status().unwrap(), two.status().unwrap());
}

#[test]
fn closing_revokes_old_token_and_switches_real_database_keys() {
    let owner = make_owner();
    let handle = owner.handle();
    install(&owner, "first", root(100, 80, 121));
    let old = handle.begin_read(40, 30).unwrap();
    let weak = Arc::downgrade(owner.inner.lock().unwrap().snapshot.as_ref().unwrap());
    let first = handle.status().unwrap();
    let guard = owner
        .close_for_mutation(operation("second"), Duration::from_secs(10))
        .unwrap();
    assert_eq!(handle.begin_read(40, 30).err(), Some(Error::Closed));
    assert!(
        weak.upgrade().is_none(),
        "an outstanding token retained the old root"
    );
    guard
        .install_for_test(root(102, 82, 123), Instant::now() + Duration::from_secs(10))
        .unwrap();
    let second = handle.status().unwrap();
    assert_eq!(second.install_revision, first.install_revision + 1);
    assert!(second.gate_epoch > first.gate_epoch);
    assert_eq!(old.commit(), Err(Error::StaleRead));
    assert!(weak.upgrade().is_none());
    let changed = read(&handle, 40, 30).unwrap().unwrap();
    assert_eq!(changed.bindings[0].binding_id, 102);
    assert_eq!(changed.entries[0].entry_id, 82);
    assert_eq!(changed.direct_rules[0].rule_id, 123);
    assert_eq!(
        read(&handle, 41, 31).unwrap().unwrap().bindings[0].binding_id,
        101
    );
}

#[test]
fn each_captured_identity_field_is_checked_at_commit() {
    let owner = make_owner();
    let handle = owner.handle();
    install(&owner, "first", root(100, 80, 121));

    let mut wrong_epoch = handle.begin_read(40, 30).unwrap();
    wrong_epoch.epoch -= 1;
    assert_eq!(wrong_epoch.commit(), Err(Error::StaleRead));

    let mut wrong_revision = handle.begin_read(40, 30).unwrap();
    wrong_revision.install_revision -= 1;
    assert_eq!(wrong_revision.commit(), Err(Error::StaleRead));

    let mut wrong_digest = handle.begin_read(40, 30).unwrap();
    wrong_digest.content_digest = root(102, 82, 123).content_digest().to_owned();
    assert_eq!(wrong_digest.commit(), Err(Error::StaleRead));
    assert_eq!(
        read(&handle, 40, 30).unwrap().unwrap().bindings[0].binding_id,
        100
    );
}

#[test]
fn replacement_digest_and_revision_are_independent_fences() {
    let owner = make_owner();
    let handle = owner.handle();
    install(&owner, "first", root(100, 80, 121));
    let old = handle.begin_read(40, 30).unwrap();
    {
        // Model a faulty replacement that leaves both counters unchanged.
        let mut inner = owner.inner.lock().unwrap();
        inner.snapshot = Some(Arc::new(state::Snapshot {
            root: root(102, 82, 123),
            expires_at: Instant::now() + Duration::from_secs(30),
        }));
    }
    assert_eq!(old.commit(), Err(Error::StaleRead));
    assert_eq!(
        read(&handle, 40, 30).unwrap().unwrap().bindings[0].binding_id,
        102
    );

    let old = handle.begin_read(40, 30).unwrap();
    {
        // Even a byte-identical root cannot reuse a captured install identity.
        let mut inner = owner.inner.lock().unwrap();
        inner.revision += 1;
    }
    assert_eq!(old.commit(), Err(Error::StaleRead));
}

#[test]
fn concurrent_identical_reinstall_rejects_old_read() {
    let owner = make_owner();
    let handle = owner.handle();
    install(&owner, "first", root(100, 80, 121));
    let old = handle.begin_read(40, 30).unwrap();
    let old_digest = old.content_digest.clone();
    let old_revision = old.install_revision;
    let (ready, proceed) = mpsc::channel();
    let reader = thread::spawn(move || {
        proceed.recv().unwrap();
        old.commit()
    });

    install(&owner, "same-content", root(100, 80, 121));
    let new_read = handle.begin_read(40, 30).unwrap();
    assert_eq!(new_read.content_digest, old_digest);
    assert!(new_read.install_revision > old_revision);
    ready.send(()).unwrap();
    assert_eq!(reader.join().unwrap(), Err(Error::StaleRead));
    assert_eq!(
        new_read.commit().unwrap().unwrap().bindings[0].binding_id,
        100
    );
}

#[test]
fn close_serializes_with_commit_in_both_orders() {
    let owner = make_owner();
    let handle = owner.handle();
    install(&owner, "first", root(100, 80, 121));
    let read = handle.begin_read(40, 30).unwrap();
    assert_eq!(read.commit().unwrap().unwrap().bindings[0].binding_id, 100);
    let guard = owner
        .close_for_mutation(operation("second"), Duration::from_secs(30))
        .unwrap();
    guard
        .install_for_test(root(102, 82, 123), Instant::now() + Duration::from_secs(30))
        .unwrap();

    let read = handle.begin_read(40, 30).unwrap();
    let held = owner.inner.lock().unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let reader_barrier = Arc::clone(&barrier);
    let (send, recv) = mpsc::channel();
    let reader = thread::spawn(move || {
        reader_barrier.wait();
        send.send(read.commit()).unwrap();
    });
    barrier.wait();
    let mut held = held;
    held.close(ClosedReason::Mutation, Some(operation("third")))
        .unwrap();
    drop(held);
    assert_eq!(recv.recv().unwrap(), Err(Error::StaleRead));
    reader.join().unwrap();
}

#[test]
fn concurrent_close_and_commit_never_allow_a_commit_after_close() {
    for i in 0..100 {
        let owner = make_owner();
        let handle = owner.handle();
        install(&owner, "setup", root(100, 80, 121));
        let read = handle.begin_read(40, 30).unwrap();
        let start = Arc::new(Barrier::new(2));
        let start_reader = Arc::clone(&start);
        let reader = thread::spawn(move || {
            start_reader.wait();
            read.commit()
        });
        start.wait();
        let guard = owner
            .close_for_mutation(operation(&format!("close-{i}")), Duration::from_secs(10))
            .unwrap();
        let result = reader.join().unwrap();
        assert!(matches!(result, Ok(Some(_)) | Err(Error::StaleRead)));
        assert_eq!(handle.begin_read(40, 30).err(), Some(Error::Closed));
        drop(guard);
    }
}

#[test]
fn cancellation_unknown_expiry_and_bad_candidate_stay_closed() {
    let owner = make_owner();
    let handle = owner.handle();
    install(&owner, "first", root(100, 80, 121));
    let old = handle.begin_read(40, 30).unwrap();
    let guard = owner
        .close_for_mutation(operation("cancelled"), Duration::from_secs(10))
        .unwrap();
    assert!(matches!(
        owner.close_for_mutation(operation("concurrent"), Duration::from_secs(1)),
        Err(Error::Busy)
    ));
    guard.mark_unknown();
    assert_eq!(old.commit(), Err(Error::StaleRead));
    assert_eq!(
        handle.status().unwrap().gate,
        GateStatus::Closed {
            reason: ClosedReason::Unknown,
            operation_id: Some(operation("cancelled"))
        }
    );
    assert!(matches!(
        owner.close_for_mutation(operation("retry"), Duration::from_secs(1)),
        Err(Error::Unknown)
    ));

    let owner = make_owner();
    let guard = owner
        .close_for_mutation(operation("invalid-expiry"), Duration::from_secs(10))
        .unwrap();
    assert_eq!(
        guard.install_for_test(root(100, 80, 121), Instant::now()),
        Err(Error::InvalidDeadline)
    );
    assert_eq!(
        owner.handle().status().unwrap().gate,
        GateStatus::Closed {
            reason: ClosedReason::Unknown,
            operation_id: Some(operation("invalid-expiry"))
        }
    );

    let owner = make_owner();
    let guard = owner
        .close_for_mutation(operation("expired"), Duration::from_secs(10))
        .unwrap();
    {
        let mut inner = owner.inner.lock().unwrap();
        if let Phase::Pending { deadline, .. } = &mut inner.phase {
            *deadline = Instant::now();
        }
    }
    assert_eq!(
        guard.install_for_test(root(100, 80, 121), Instant::now() + Duration::from_secs(10)),
        Err(Error::Unknown)
    );
    assert_eq!(
        owner.handle().status().unwrap().gate,
        GateStatus::Closed {
            reason: ClosedReason::Unknown,
            operation_id: Some(operation("expired"))
        }
    );
}

#[test]
fn unresolved_shutdown_remains_blocked_and_retains_operation_identity() {
    let owner = make_owner();
    let guard = owner
        .close_for_mutation(operation("cancelled-before-drop"), Duration::from_secs(10))
        .unwrap();
    guard.mark_unknown();
    {
        let mut inner = owner.inner.lock().unwrap();
        assert!(inner.shutdown());
        assert_eq!(
            inner.status().gate,
            GateStatus::Closed {
                reason: ClosedReason::OwnerDropped,
                operation_id: Some(operation("cancelled-before-drop")),
            }
        );
    }

    let owner = make_owner();
    let guard = owner
        .close_for_mutation(operation("timed-out"), Duration::from_secs(10))
        .unwrap();
    {
        let mut inner = owner.inner.lock().unwrap();
        inner.expire(Instant::now() + Duration::from_secs(11));
        assert!(inner.shutdown());
        assert_eq!(
            inner.status().gate,
            GateStatus::Closed {
                reason: ClosedReason::OwnerDropped,
                operation_id: Some(operation("timed-out")),
            }
        );
    }
    drop(guard);
}

#[test]
fn root_expiry_and_owner_drop_revoke_existing_reads() {
    let owner = make_owner();
    let handle = owner.handle();
    install(&owner, "first", root(100, 80, 121));
    let read = handle.begin_read(40, 30).unwrap();
    let weak = Arc::downgrade(owner.inner.lock().unwrap().snapshot.as_ref().unwrap());
    {
        let mut inner = owner.inner.lock().unwrap();
        inner.expire(Instant::now() + Duration::from_secs(31));
    }
    assert!(weak.upgrade().is_none());
    assert_eq!(read.commit(), Err(Error::StaleRead));
    assert_eq!(
        handle.status().unwrap().gate,
        GateStatus::Closed {
            reason: ClosedReason::Expired,
            operation_id: None
        }
    );
    install(&owner, "second", root(102, 82, 123));
    let read = handle.begin_read(40, 30).unwrap();
    drop(owner);
    assert_eq!(read.commit(), Err(Error::StaleRead));
    assert_eq!(
        handle.status().unwrap().gate,
        GateStatus::Closed {
            reason: ClosedReason::OwnerDropped,
            operation_id: None
        }
    );
}

#[test]
fn invalid_operation_and_deadline_fail_closed() {
    assert_eq!(OperationId::new(""), Err(Error::InvalidOperationId));
    assert_eq!(OperationId::new("space id"), Err(Error::InvalidOperationId));
    assert_eq!(
        OperationId::new("x".repeat(129)),
        Err(Error::InvalidOperationId)
    );
    assert!(OperationId::new("x".repeat(128)).is_ok());
    let owner = make_owner();
    install(&owner, "first", root(100, 80, 121));
    let handle = owner.handle();
    let read = handle.begin_read(40, 30).unwrap();
    assert!(matches!(
        owner.close_for_mutation(operation("zero"), Duration::ZERO),
        Err(Error::InvalidDeadline)
    ));
    assert_eq!(read.commit(), Err(Error::StaleRead));
    assert_eq!(
        handle.status().unwrap().gate,
        GateStatus::Closed {
            reason: ClosedReason::Expired,
            operation_id: Some(operation("zero"))
        }
    );
}

#[test]
fn drop_owner_during_mutation_prevents_late_install() {
    let owner = make_owner();
    let handle = owner.handle();
    let guard = owner
        .close_for_mutation(operation("pending"), Duration::from_secs(10))
        .unwrap();
    drop(owner);
    assert_eq!(
        guard.install_for_test(root(100, 80, 121), Instant::now() + Duration::from_secs(10)),
        Err(Error::Unknown)
    );
    assert_eq!(
        handle.status().unwrap().gate,
        GateStatus::Closed {
            reason: ClosedReason::OwnerDropped,
            operation_id: Some(operation("pending"))
        }
    );
}
