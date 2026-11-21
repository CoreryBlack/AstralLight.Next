//! memory—v1: Compare incremental source replacement with cold capture of its archive.

use super::tests::{install_fixture_registry, serving_ready};
use super::{
    CandidateBudget, CandidateError, ManagementMutationV2, MutationError, MutationPrecondition,
    RootRegistry,
};
use crate::memory_v1_digest::Key;
use crate::memory_v1_rules::{canonical_version_bytes, version_digest};

#[test]
fn repeated_publication_retains_one_body_and_rejects_used_version_ids() {
    let (mut archive, selections) = serving_ready();
    let budget = CandidateBudget {
        max_table_rows: 32,
        max_bindings_per_read: 4,
    };
    let owner = RootRegistry::new()
        .install_candidate(archive.clone(), selections, budget)
        .unwrap();
    install_fixture_registry(&owner);
    owner.adopt_serving_for_isolated_tests().unwrap();
    let initial = owner.runtime.current.load_full();
    let source = &archive.rule_set_versions[0];
    let id = source.rule_set_id;
    let initial_version = source.clone();
    let initial_confirmation = archive.rule_set_change_confirmations[0].clone();
    let publish = |version: u8, confirmation: u8| {
        let mut row = initial_version.clone();
        row.version_bytes = vec![version];
        row.timestamp_bytes = vec![confirmation];
        if version == 2 {
            row.content_bytes = br#"{"rules":[{"ruleId":"R9","resource":"document","action":"read","effect":"DENY"}]}"#.to_vec();
        }
        row.hash_input_bytes =
            canonical_version_bytes(&row.version_bytes, &row.content_bytes, &row.timestamp_bytes);
        row.hash_bytes = version_digest(&row.hash_input_bytes);
        let mut change = initial_confirmation.clone();
        change.confirmation_id = [confirmation; 16];
        change.version_bytes = row.version_bytes.clone();
        change.operation_id = vec![confirmation];
        let result = owner.execute_mutation_with_precondition_for_isolated_tests(
            &ManagementMutationV2::VersionPublish {
                rule_set_id: id,
                version_row: row.clone(),
                new_current_version: row.version_bytes.clone(),
                change_confirmation: change.clone(),
            },
            &MutationPrecondition {
                evaluated_root_version: owner.handle().metadata().unwrap().version,
            },
        );
        (result, row, change)
    };
    let slot = Key::source_slot(id);
    for version in [2, 3] {
        let (result, row, change) = publish(version, version + 10);
        let metadata = result.unwrap();
        archive.rule_sets[0].current_version_bytes = row.version_bytes.clone();
        archive.rule_set_versions.push(row.clone());
        archive.rule_set_change_confirmations.push(change);
        let current = owner.runtime.current.load_full();
        assert!(current.objects.has_single_version_per_rule_set());
        assert_eq!(current.objects.selected_version(id).unwrap(), Some(&row));
        assert_eq!(
            current.digest_index.get(&slot).unwrap()[2].as_ref(),
            Some(&row.content_bytes)
        );
        for n in 1..=version {
            assert_eq!(current.objects.version(id, &[n]).is_some(), n == version);
            assert!(current
                .digest_index
                .get(&Key::rule_set_version(id, vec![n]))
                .is_none());
        }
        let binding = &archive.bindings[0];
        let confirmation = &archive.binding_confirmations[0];
        assert_eq!(
            current.objects.binding_for_digest(binding.binding_id),
            Some(binding)
        );
        assert_eq!(
            current.objects.confirmation(confirmation.confirmation_id),
            Some(confirmation)
        );
        assert_eq!(
            current
                .objects
                .card_dependency_generation(binding.user_card_id),
            initial
                .objects
                .card_dependency_generation(binding.user_card_id)
        );
        assert_eq!(current.objects.table_counts(), archive.table_counts());
        assert_eq!(Some(metadata.row_count), archive.table_counts().total());
        let cold = RootRegistry::new()
            .install_candidate(
                archive.clone(),
                archive.current_version_selections().unwrap(),
                budget,
            )
            .unwrap();
        assert_eq!(cold.handle().metadata().unwrap().digest, metadata.digest);
    }
    let before = owner.runtime.current.load_full();
    for used in [1, 2, 3] {
        assert!(matches!(publish(used, used + 20).0,
            Err(MutationError::Candidate(CandidateError::DuplicateVersion { rule_set_id, version_bytes }))
                if rule_set_id == id && version_bytes == [used]));
        assert!(std::sync::Arc::ptr_eq(
            &before,
            &owner.runtime.current.load_full()
        ));
    }
    assert_eq!(
        initial.objects.selected_version(id).unwrap(),
        Some(&initial_version)
    );
}
