//! memory—v1: Regression coverage for the ordinary final-clock root bracket.

use super::{budget, id, install_fixture_registry, serving_ready};
use crate::memory_v1_root::{
    DependencyRecord, ManagementMutationV2, MutationPrecondition, RequestRootReader, RootOwner,
    RootRegistry,
};
use crate::memory_v1_session_authority::MemoryV1SessionAuthority;
use uuid::Uuid;

// memory—v1: Bind the ordinary path to the installed session authority. An
// omitted record entry must not hide an active dependency in the actor index.
fn with_ordinary_recheck(run: impl FnOnce(&RootOwner, &RequestRootReader, &DependencyRecord)) {
    let (rows, selections) = serving_ready();
    let owner = RootRegistry::new()
        .install_candidate(rows, selections, budget())
        .unwrap();
    install_fixture_registry(&owner);
    owner.adopt_serving_for_isolated_tests().unwrap();
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&owner).unwrap();
    let reader = owner.handle().begin_request(Uuid::new_v4()).unwrap();
    let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
    let record = DependencyRecord {
        card_id: id(4),
        instance_id: reader.metadata().instance_id,
        bindings: Vec::new(),
        tenant_tree_version,
        registry_version,
    };
    let token = owner.runtime.session_authority.get().unwrap();
    assert_eq!(
        reader.try_with_rechecked_dependencies_and_target(&record, None, Some(token), || ()),
        Ok(Some(()))
    );
    run(&owner, &reader, &record);
}

#[test]
fn ordinary_recheck_refuses_unlisted_confirmation_change_during_sample() {
    with_ordinary_recheck(|owner, reader, record| {
        let token = owner.runtime.session_authority.get().unwrap();
        let before = reader.metadata();
        let outcome =
            reader.try_with_rechecked_dependencies_and_target(record, None, Some(token), || {
                let after = owner
                    .execute_mutation_with_precondition_for_isolated_tests(
                        &ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                            confirmation_id: id(8),
                            revoked_at: 42,
                            revoked_by: id(1),
                        },
                        &MutationPrecondition {
                            evaluated_root_version: before.version,
                        },
                    )
                    .unwrap();
                assert_eq!(after.version, before.version + 1);
            });
        assert_eq!(outcome, Ok(None));
    });
}

#[test]
fn ordinary_recheck_refuses_invalidation_during_sample() {
    with_ordinary_recheck(|owner, reader, record| {
        let runtime = &owner.runtime;
        let token = runtime.session_authority.get().unwrap();
        assert_eq!(
            reader.try_with_rechecked_dependencies_and_target(record, None, Some(token), || {
                let _writer = runtime.mutation_lock.write().unwrap();
                RootOwner::publish_invalid_snapshot(runtime, &runtime.current.load_full());
            }),
            Ok(None)
        );
    });
}

#[test]
fn ordinary_recheck_refuses_writer_poison_during_sample() {
    with_ordinary_recheck(|owner, reader, record| {
        let runtime = &owner.runtime;
        let token = runtime.session_authority.get().unwrap();
        assert_eq!(
            reader.try_with_rechecked_dependencies_and_target(record, None, Some(token), || {
                std::thread::scope(|scope| {
                    assert!(scope
                        .spawn(|| {
                            let _writer = runtime.mutation_lock.write().unwrap();
                            panic!("write failure");
                        })
                        .join()
                        .is_err());
                });
            }),
            Ok(None)
        );
    });
}
