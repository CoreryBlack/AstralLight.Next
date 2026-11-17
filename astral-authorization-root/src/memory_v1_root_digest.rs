//! memory—v1: Incremental digest updates for one candidate root mutation.
//!
//! The full rebuild and this path use the same row encoders. A prepared index is
//! private until the owner publishes it with the corresponding candidate and
//! metadata. It is not evidence of source provenance or persistence.

use std::collections::BTreeSet;

use crate::memory_v1_digest::{Change, DigestIndex, Key};
use crate::memory_v1_hamt::HamtCandidate;
use crate::memory_v1_hamt_runtime::{
    binding_change, card_change, change_confirmation_change, confirmation_change, rule_set_change,
    version_change, RuntimeError,
};
use crate::memory_v1_root::{ManagementMutationV2, MutationError};

// DigestIndex::prepare bounds individual batches at 128 changes. Preparing
// several batches on a private clone preserves all-or-nothing publication.
const DIGEST_BATCH_SIZE: usize = 128;

// memory—v1: Bind each mutation's exact resulting rows to the existing index.
pub(crate) fn prepare_root_digest(
    current: &DigestIndex,
    next: &HamtCandidate,
    mutation: &ManagementMutationV2,
) -> Result<DigestIndex, MutationError> {
    let mut changes = Vec::new();
    let inconsistent = || MutationError::Runtime(RuntimeError::InconsistentCandidate);
    match mutation {
        ManagementMutationV2::BindingCreate { row, confirmation } => {
            let binding = next
                .binding_for_digest(row.binding_id)
                .ok_or_else(inconsistent)?;
            let confirmation = next
                .confirmation(confirmation.confirmation_id)
                .ok_or_else(inconsistent)?;
            changes.push(binding_change(binding));
            changes.push(confirmation_change(confirmation));
        }
        ManagementMutationV2::BindingRemove { binding_id, .. } => {
            let binding = next
                .binding_for_digest(*binding_id)
                .ok_or_else(inconsistent)?;
            changes.push(binding_change(binding));
        }
        ManagementMutationV2::ConfirmationCreate { row } => {
            let confirmation = next
                .confirmation(row.confirmation_id)
                .ok_or_else(inconsistent)?;
            changes.push(confirmation_change(confirmation));
        }
        ManagementMutationV2::ConfirmationRevoke {
            confirmation_id, ..
        } => {
            let confirmation = next
                .confirmation(*confirmation_id)
                .ok_or_else(inconsistent)?;
            changes.push(confirmation_change(confirmation));
        }
        ManagementMutationV2::RuleSetChangeConfirmationRevoke {
            confirmation_id, ..
        } => {
            let confirmation = next
                .change_confirmation(*confirmation_id)
                .ok_or_else(inconsistent)?;
            changes.push(change_confirmation_change(confirmation));
        }
        ManagementMutationV2::ConfirmationBatch { rows } => {
            for row in rows {
                let confirmation = next
                    .confirmation(row.confirmation_id)
                    .ok_or_else(inconsistent)?;
                changes.push(confirmation_change(confirmation));
            }
        }
        ManagementMutationV2::UserCardCreate { row } => {
            let card = next.user_card(row.user_card_id).ok_or_else(inconsistent)?;
            if card != row {
                return Err(inconsistent());
            }
            changes.push(card_change(card));
        }
        ManagementMutationV2::UserCardStatus { user_card_id, .. } => {
            let card = next.user_card(*user_card_id).ok_or_else(inconsistent)?;
            changes.push(card_change(card));
        }
        ManagementMutationV2::RuleSetCreate {
            rule_set,
            version,
            change_confirmation,
        } => {
            let rule_set = next
                .rule_set(rule_set.rule_set_id)
                .ok_or_else(inconsistent)?;
            let version = next
                .version(version.rule_set_id, &version.version_bytes)
                .ok_or_else(inconsistent)?;
            let confirmation = next
                .change_confirmation(change_confirmation.confirmation_id)
                .ok_or_else(inconsistent)?;
            changes.push(rule_set_change(rule_set));
            changes.push(version_change(version));
            changes.push(change_confirmation_change(confirmation));
            changes.push(Change::select_current(
                rule_set.rule_set_id,
                version.version_bytes.clone(),
            ));
        }
        ManagementMutationV2::RuleSetRetire { rule_set_id } => {
            let rule_set = next.rule_set(*rule_set_id).ok_or_else(inconsistent)?;
            changes.push(rule_set_change(rule_set));
        }
        ManagementMutationV2::VersionPublish {
            rule_set_id,
            new_current_version,
            change_confirmation,
            ..
        } => {
            let rule_set = next.rule_set(*rule_set_id).ok_or_else(inconsistent)?;
            let version = next
                .version(*rule_set_id, new_current_version)
                .ok_or_else(inconsistent)?;
            let confirmation = next
                .change_confirmation(change_confirmation.confirmation_id)
                .ok_or_else(inconsistent)?;
            changes.push(rule_set_change(rule_set));
            changes.push(version_change(version));
            changes.push(change_confirmation_change(confirmation));
            changes.push(Change::select_current(
                *rule_set_id,
                new_current_version.clone(),
            ));
        }
    }
    prepare_batches(current, changes)
}

// memory—v1: Reject duplicate identities across all chunks, including a duplicate
// split across the 128-change boundary, before producing any prepared index.
fn prepare_batches(
    current: &DigestIndex,
    changes: Vec<Change>,
) -> Result<DigestIndex, MutationError> {
    let mut seen = BTreeSet::new();
    for change in &changes {
        let key: &Key = match change {
            Change::Put { key, .. } | Change::Delete { key } => key,
        };
        if !seen.insert(key.clone()) {
            return Err(MutationError::Runtime(RuntimeError::Digest(
                crate::memory_v1_digest::DigestError::DuplicateKey,
            )));
        }
    }
    let mut result = current.clone();
    for batch in changes.chunks(DIGEST_BATCH_SIZE) {
        result = result
            .prepare(batch.iter().cloned())
            .map_err(|error| MutationError::Runtime(RuntimeError::Digest(error)))?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_v1_db_rows::{
        BinaryId, BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows,
        CurrentSelection, IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow,
        RuleSetVersionRow, TenantRow, UserCardRow, UserCardStatus, UserRow,
    };
    use crate::memory_v1_digest::{DigestError, Table};
    use crate::memory_v1_hamt::{CandidateBudget, HamtCandidate};
    use crate::memory_v1_hamt_runtime::digest_rows;
    use crate::memory_v1_rules::{MemoryV1OwnerScope, MemoryV1TenantScope};

    fn id(value: u8) -> BinaryId {
        [value; 16]
    }

    fn wide_id(kind: u8, value: usize) -> BinaryId {
        let mut result = [0; 16];
        result[0] = kind;
        result[8..].copy_from_slice(&(value as u64).to_be_bytes());
        result
    }

    fn budget(max_table_rows: usize, max_bindings_per_read: usize) -> CandidateBudget {
        CandidateBudget {
            max_table_rows,
            max_bindings_per_read,
        }
    }

    fn version(rule_set_id: BinaryId, value: u8) -> RuleSetVersionRow {
        let version_bytes = vec![value];
        let content_bytes =
            br#"{"rules":[{"ruleId":"read","resource":"document","action":"read","effect":"ALLOW"}]}"#
                .to_vec();
        let timestamp_bytes = vec![value];
        let hash_input_bytes = crate::memory_v1_rules::canonical_version_bytes(
            &version_bytes,
            &content_bytes,
            &timestamp_bytes,
        );
        let hash_bytes = crate::memory_v1_rules::version_digest(&hash_input_bytes);
        RuleSetVersionRow {
            rule_set_id,
            version_bytes,
            content_bytes,
            timestamp_bytes,
            hash_input_bytes,
            hash_bytes,
        }
    }

    fn binding(binding_id: BinaryId, user_card_id: BinaryId, rule_set_id: BinaryId) -> BindingRow {
        BindingRow {
            binding_id,
            user_card_id,
            rule_set_id,
            binding_layer: BindingLayer::Base,
            valid_from: Some(10),
            valid_until: Some(20),
            owner_scope: MemoryV1OwnerScope::AllUsers,
            tenant_scope: MemoryV1TenantScope::SelfAndDescendants,
            removed_at: None,
            removed_by: None,
        }
    }

    fn binding_confirmation(
        confirmation_id: BinaryId,
        binding_id: BinaryId,
        rule_set_id: BinaryId,
        version_bytes: Vec<u8>,
        confirmer_user_id: BinaryId,
    ) -> BindingConfirmationRow {
        BindingConfirmationRow {
            confirmation_id,
            binding_id,
            rule_set_id,
            version_bytes,
            confirmer_user_id,
            scope_bytes: vec![0x80, 1],
            operation_id: vec![2],
            confirmed_at_bytes: vec![3],
            revoked_at: None,
            revoked_by: None,
        }
    }

    fn change_confirmation(
        confirmation_id: BinaryId,
        rule_set_id: BinaryId,
        version_bytes: Vec<u8>,
        confirmer_user_id: BinaryId,
    ) -> RuleSetChangeConfirmationRow {
        RuleSetChangeConfirmationRow {
            confirmation_id,
            rule_set_id,
            version_bytes,
            confirmer_user_id,
            affected_scope_bytes: vec![0x80, 4],
            operation_id: vec![5],
            confirmed_at_bytes: vec![6],
            revoked_at: None,
            revoked_by: None,
        }
    }

    fn base_rows() -> (CandidateRows, Vec<CurrentSelection>) {
        let user_id = id(1);
        let tenant_id = id(3);
        let card_id = id(4);
        let rule_set_id = id(5);
        let version_row = version(rule_set_id, 1);
        (
            CandidateRows {
                users: vec![UserRow { user_id }],
                identity_cards: vec![IdentityCardRow {
                    identity_card_id: id(2),
                    user_id,
                }],
                tenants: vec![TenantRow {
                    tenant_id,
                    parent_tenant_id: None,
                }],
                user_cards: vec![UserCardRow {
                    user_card_id: card_id,
                    user_id,
                    tenant_id,
                    status: UserCardStatus::Active,
                }],
                rule_sets: vec![RuleSetRow {
                    rule_set_id,
                    owner_tenant_id: tenant_id,
                    current_version_bytes: vec![1],
                    status: crate::memory_v1_db_rows::RuleSetStatus::Active,
                }],
                rule_set_versions: vec![version_row],
                bindings: vec![binding(id(6), card_id, rule_set_id)],
                binding_confirmations: vec![binding_confirmation(
                    id(7),
                    id(6),
                    rule_set_id,
                    vec![1],
                    user_id,
                )],
                rule_set_change_confirmations: vec![change_confirmation(
                    id(8),
                    rule_set_id,
                    vec![1],
                    user_id,
                )],
            },
            vec![CurrentSelection {
                rule_set_id,
                version_bytes: vec![1],
            }],
        )
    }

    fn candidate(rows: CandidateRows, selections: Vec<CurrentSelection>) -> HamtCandidate {
        HamtCandidate::build(rows, selections, budget(5000, 8)).unwrap()
    }

    fn digest(candidate: &HamtCandidate) -> DigestIndex {
        let (rows, selections) = candidate.digest_inputs();
        digest_rows(&rows, &selections).unwrap()
    }

    fn assert_incremental_equals_rebuild(
        current: &DigestIndex,
        next: &HamtCandidate,
        mutation: ManagementMutationV2,
    ) {
        let incremental = prepare_root_digest(current, next, &mutation).unwrap();
        let rebuilt = digest(next);
        assert_eq!(incremental.digest(), rebuilt.digest());
    }

    #[test]
    // memory—v1: Retirement changes the rule-set leaf and incremental digest.
    fn retirement_digest_matches_full_rebuild() {
        let (mut rows, selections) = base_rows();
        rows.user_cards[0].status = UserCardStatus::Disabled;
        let before = candidate(rows, selections);
        let after = before.with_rule_set_retired(id(5)).unwrap();
        let initial = digest(&before);
        let rebuilt = digest(&after);
        assert_ne!(initial.digest(), rebuilt.digest());
        assert_incremental_equals_rebuild(
            &initial,
            &after,
            ManagementMutationV2::RuleSetRetire { rule_set_id: id(5) },
        );
    }

    #[test]
    // memory—v1: Incremental insertion hashes precisely the created card.
    fn user_card_create_digest_matches_rebuild() {
        let (rows, selections) = base_rows();
        let before = candidate(rows, selections);
        let row = UserCardRow {
            user_card_id: id(40),
            user_id: id(1),
            tenant_id: id(3),
            status: UserCardStatus::Active,
        };
        let after = before.with_user_card_create(row.clone()).unwrap();
        let initial = digest(&before);
        assert_ne!(initial.digest(), digest(&after).digest());
        assert_incremental_equals_rebuild(
            &initial,
            &after,
            ManagementMutationV2::UserCardCreate { row: row.clone() },
        );
        let mut mismatched = row;
        mismatched.user_id = id(90);
        assert!(prepare_root_digest(
            &initial,
            &after,
            &ManagementMutationV2::UserCardCreate { row: mismatched }
        )
        .is_err());
    }

    #[test]
    // memory—v1: Every supported root mutation preserves incremental/full digest equivalence.
    fn incremental_digest_matches_full_rebuild_for_all_mutations() {
        let (rows, selections) = base_rows();

        let mut create_rows = rows.clone();
        create_rows.bindings.clear();
        create_rows.binding_confirmations.clear();
        let create_base = candidate(create_rows, selections.clone());
        let created_binding = binding(id(6), id(4), id(5));
        let created_confirmation = binding_confirmation(id(7), id(6), id(5), vec![1], id(1));
        let create_next = create_base
            .with_binding_insert(created_binding.clone())
            .unwrap()
            .with_confirmation_insert(created_confirmation.clone())
            .unwrap();
        assert_eq!(
            create_next.binding_for_digest(id(6)).unwrap().owner_scope,
            MemoryV1OwnerScope::AllUsers
        );
        assert_eq!(
            create_next.binding_for_digest(id(6)).unwrap().tenant_scope,
            MemoryV1TenantScope::SelfAndDescendants
        );
        assert_incremental_equals_rebuild(
            &digest(&create_base),
            &create_next,
            ManagementMutationV2::BindingCreate {
                row: created_binding,
                confirmation: created_confirmation,
            },
        );

        let base = candidate(rows.clone(), selections.clone());
        let removed = base.with_binding_removed(id(6), 100, id(1)).unwrap();
        let removed_binding = removed.binding_for_digest(id(6)).unwrap();
        assert_eq!(removed_binding.removed_at, Some(100));
        assert_eq!(removed_binding.removed_by, Some(id(1)));
        assert_incremental_equals_rebuild(
            &digest(&base),
            &removed,
            ManagementMutationV2::BindingRemove {
                binding_id: id(6),
                removed_at: 100,
                removed_by: id(1),
            },
        );

        let mut confirmation_rows = rows.clone();
        confirmation_rows.binding_confirmations.clear();
        let confirmation_base = candidate(confirmation_rows, selections.clone());
        let created_confirmation = binding_confirmation(id(7), id(6), id(5), vec![1], id(1));
        let confirmation_next = confirmation_base
            .with_confirmation_insert(created_confirmation.clone())
            .unwrap();
        assert_incremental_equals_rebuild(
            &digest(&confirmation_base),
            &confirmation_next,
            ManagementMutationV2::ConfirmationCreate {
                row: created_confirmation,
            },
        );

        let revoked = base.with_confirmation_revoked(id(7), 101, id(1)).unwrap();
        assert_eq!(revoked.confirmation(id(7)).unwrap().revoked_at, Some(101));
        assert_incremental_equals_rebuild(
            &digest(&base),
            &revoked,
            ManagementMutationV2::ConfirmationRevoke {
                confirmation_id: id(7),
                revoked_at: 101,
                revoked_by: id(1),
            },
        );

        let change_revoked = base
            .with_change_confirmation_revoked(id(8), 102, id(1))
            .unwrap();
        assert_eq!(
            change_revoked
                .change_confirmation(id(8))
                .unwrap()
                .revoked_by,
            Some(id(1))
        );
        assert_incremental_equals_rebuild(
            &digest(&base),
            &change_revoked,
            ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                confirmation_id: id(8),
                revoked_at: 102,
                revoked_by: id(1),
            },
        );

        let mut batch_rows = rows.clone();
        batch_rows.users.push(UserRow { user_id: id(9) });
        batch_rows.identity_cards.push(IdentityCardRow {
            identity_card_id: id(10),
            user_id: id(9),
        });
        batch_rows.user_cards.push(UserCardRow {
            user_card_id: id(11),
            user_id: id(9),
            tenant_id: id(3),
            status: UserCardStatus::Active,
        });
        batch_rows.rule_sets.push(RuleSetRow {
            rule_set_id: id(12),
            owner_tenant_id: id(3),
            current_version_bytes: vec![1],
            status: crate::memory_v1_db_rows::RuleSetStatus::Active,
        });
        batch_rows.rule_set_versions.push(version(id(12), 1));
        batch_rows.bindings.push(binding(id(13), id(11), id(12)));
        batch_rows.binding_confirmations.clear();
        let batch_base = candidate(batch_rows, selections.clone());
        let batch = vec![
            binding_confirmation(id(7), id(6), id(5), vec![1], id(1)),
            binding_confirmation(id(14), id(13), id(12), vec![1], id(9)),
        ];
        let batch_next = batch_base.with_confirmations_batch(&batch).unwrap();
        assert_incremental_equals_rebuild(
            &digest(&batch_base),
            &batch_next,
            ManagementMutationV2::ConfirmationBatch { rows: batch },
        );

        let disabled = base
            .with_user_card_status(id(4), UserCardStatus::Disabled)
            .unwrap();
        assert_eq!(
            disabled.user_card(id(4)).unwrap().status,
            UserCardStatus::Disabled
        );
        assert_incremental_equals_rebuild(
            &digest(&base),
            &disabled,
            ManagementMutationV2::UserCardStatus {
                user_card_id: id(4),
                status: UserCardStatus::Disabled,
            },
        );

        let new_rule_set = RuleSetRow {
            rule_set_id: id(15),
            owner_tenant_id: id(3),
            current_version_bytes: vec![2],
            status: crate::memory_v1_db_rows::RuleSetStatus::Active,
        };
        let new_version = version(id(15), 2);
        let new_change_confirmation = change_confirmation(id(16), id(15), vec![2], id(1));
        let created_rule_set = base
            .with_rule_set_create(new_rule_set.clone(), new_version.clone())
            .unwrap()
            .with_change_confirmation_insert(new_change_confirmation.clone())
            .unwrap();
        assert_eq!(
            created_rule_set
                .rule_set(id(15))
                .unwrap()
                .current_version_bytes,
            vec![2]
        );
        assert_eq!(
            created_rule_set
                .selected_version(id(15))
                .unwrap()
                .unwrap()
                .version_bytes,
            vec![2]
        );
        assert_incremental_equals_rebuild(
            &digest(&base),
            &created_rule_set,
            ManagementMutationV2::RuleSetCreate {
                rule_set: new_rule_set,
                version: new_version,
                change_confirmation: new_change_confirmation,
            },
        );

        let published_version = version(id(5), 2);
        let published_change_confirmation = change_confirmation(id(17), id(5), vec![2], id(1));
        let published = base
            .append_version(published_version.clone())
            .unwrap()
            .with_current_version(id(5), &[2])
            .unwrap()
            .with_change_confirmation_insert(published_change_confirmation.clone())
            .unwrap();
        assert_eq!(
            published.rule_set(id(5)).unwrap().current_version_bytes,
            vec![2]
        );
        assert_eq!(
            published
                .selected_version(id(5))
                .unwrap()
                .unwrap()
                .version_bytes,
            vec![2]
        );
        assert_incremental_equals_rebuild(
            &digest(&base),
            &published,
            ManagementMutationV2::VersionPublish {
                rule_set_id: id(5),
                version_row: published_version,
                new_current_version: vec![2],
                change_confirmation: published_change_confirmation,
            },
        );
    }

    fn batch_fixture(
        count: usize,
    ) -> (
        CandidateRows,
        Vec<CurrentSelection>,
        Vec<BindingConfirmationRow>,
    ) {
        let tenant_id = id(50);
        let mut rows = CandidateRows {
            tenants: vec![TenantRow {
                tenant_id,
                parent_tenant_id: None,
            }],
            ..CandidateRows::default()
        };
        let mut selections = Vec::with_capacity(count);
        let mut confirmations = Vec::with_capacity(count);
        for index in 0..count {
            let user_id = wide_id(1, index);
            let identity_card_id = wide_id(2, index);
            let card_id = wide_id(3, index);
            let rule_set_id = wide_id(4, index);
            let binding_id = wide_id(5, index);
            let confirmation_id = wide_id(6, index);
            rows.users.push(UserRow { user_id });
            rows.identity_cards.push(IdentityCardRow {
                identity_card_id,
                user_id,
            });
            rows.user_cards.push(UserCardRow {
                user_card_id: card_id,
                user_id,
                tenant_id,
                status: UserCardStatus::Active,
            });
            rows.rule_sets.push(RuleSetRow {
                rule_set_id,
                owner_tenant_id: tenant_id,
                current_version_bytes: vec![1],
                status: crate::memory_v1_db_rows::RuleSetStatus::Active,
            });
            rows.rule_set_versions.push(version(rule_set_id, 1));
            rows.bindings
                .push(binding(binding_id, card_id, rule_set_id));
            confirmations.push(binding_confirmation(
                confirmation_id,
                binding_id,
                rule_set_id,
                vec![1],
                user_id,
            ));
            selections.push(CurrentSelection {
                rule_set_id,
                version_bytes: vec![1],
            });
        }
        (rows, selections, confirmations)
    }

    #[test]
    // memory—v1: Confirmation batches remain equivalent across the 128-change chunk boundary.
    fn confirmation_batch_digest_matches_rebuild_at_128_and_129_changes() {
        for count in [128, 129] {
            let (rows, selections, confirmations) = batch_fixture(count);
            let base = candidate(rows, selections);
            let current = digest(&base);
            let next = base.with_confirmations_batch(&confirmations).unwrap();
            assert_incremental_equals_rebuild(
                &current,
                &next,
                ManagementMutationV2::ConfirmationBatch {
                    rows: confirmations,
                },
            );
        }
    }

    #[test]
    // memory—v1: Duplicate identities crossing a digest chunk are rejected atomically.
    fn duplicate_key_across_digest_chunks_is_rejected_atomically() {
        let duplicate = Key::row(Table::User, wide_id(0x10, 1));
        let mut changes = vec![Change::Put {
            key: duplicate.clone(),
            fields: vec![Some(vec![1])],
        }];
        for index in 0..127 {
            changes.push(Change::Put {
                key: Key::row(Table::User, wide_id(0x20, index)),
                fields: vec![Some(vec![2])],
            });
        }
        changes.push(Change::Put {
            key: duplicate,
            fields: vec![Some(vec![3])],
        });
        let original = DigestIndex::new();
        let original_digest = original.digest();
        assert!(matches!(
            prepare_batches(&original, changes),
            Err(MutationError::Runtime(RuntimeError::Digest(
                DigestError::DuplicateKey
            )))
        ));
        assert_eq!(original.digest(), original_digest);
    }

    #[test]
    // memory—v1: Capacity failure does not mutate the original prepared digest.
    fn digest_capacity_failure_preserves_original_index() {
        let user_id = id(1);
        let tenant_id = id(3);
        let card_id = id(4);
        let rule_set_id = id(5);
        let mut rows = CandidateRows {
            users: vec![UserRow { user_id }],
            identity_cards: vec![IdentityCardRow {
                identity_card_id: id(2),
                user_id,
            }],
            tenants: vec![TenantRow {
                tenant_id,
                parent_tenant_id: None,
            }],
            user_cards: vec![UserCardRow {
                user_card_id: card_id,
                user_id,
                tenant_id,
                status: UserCardStatus::Active,
            }],
            rule_sets: vec![RuleSetRow {
                rule_set_id,
                owner_tenant_id: tenant_id,
                current_version_bytes: vec![1],
                status: crate::memory_v1_db_rows::RuleSetStatus::Active,
            }],
            rule_set_versions: vec![version(rule_set_id, 1)],
            rule_set_change_confirmations: vec![change_confirmation(
                id(8),
                rule_set_id,
                vec![1],
                user_id,
            )],
            ..CandidateRows::default()
        };
        for index in 0..4088 {
            rows.tenants.push(TenantRow {
                tenant_id: wide_id(0xee, index),
                parent_tenant_id: None,
            });
        }
        let base = HamtCandidate::build(
            rows,
            vec![CurrentSelection {
                rule_set_id,
                version_bytes: vec![1],
            }],
            budget(5000, 0),
        )
        .unwrap();
        let current = digest(&base);
        assert_eq!(base.digest_inputs().0.table_counts().total(), Some(4095));
        let new_binding = binding(id(6), card_id, rule_set_id);
        let new_confirmation = binding_confirmation(id(7), id(6), rule_set_id, vec![1], user_id);
        let next = base
            .with_binding_insert(new_binding.clone())
            .unwrap()
            .with_confirmation_insert(new_confirmation.clone())
            .unwrap();
        let original_digest = current.digest();
        assert!(matches!(
            prepare_root_digest(
                &current,
                &next,
                &ManagementMutationV2::BindingCreate {
                    row: new_binding,
                    confirmation: new_confirmation,
                },
            ),
            Err(MutationError::Runtime(RuntimeError::Digest(
                DigestError::LimitExceeded
            )))
        ));
        assert_eq!(current.digest(), original_digest);
    }

    #[test]
    // memory—v1: Every mutation rejects a missing target row without a digest update.
    fn missing_digest_targets_are_rejected_for_each_mutation_variant() {
        let next =
            HamtCandidate::build(CandidateRows::default(), Vec::new(), budget(32, 0)).unwrap();
        let (rows, _) = base_rows();
        let mutations = vec![
            ManagementMutationV2::BindingCreate {
                row: rows.bindings[0].clone(),
                confirmation: rows.binding_confirmations[0].clone(),
            },
            ManagementMutationV2::BindingRemove {
                binding_id: id(6),
                removed_at: 1,
                removed_by: id(1),
            },
            ManagementMutationV2::ConfirmationCreate {
                row: rows.binding_confirmations[0].clone(),
            },
            ManagementMutationV2::ConfirmationRevoke {
                confirmation_id: id(7),
                revoked_at: 1,
                revoked_by: id(1),
            },
            ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                confirmation_id: id(8),
                revoked_at: 1,
                revoked_by: id(1),
            },
            ManagementMutationV2::ConfirmationBatch {
                rows: vec![rows.binding_confirmations[0].clone()],
            },
            ManagementMutationV2::UserCardStatus {
                user_card_id: id(4),
                status: UserCardStatus::Disabled,
            },
            ManagementMutationV2::RuleSetCreate {
                rule_set: rows.rule_sets[0].clone(),
                version: rows.rule_set_versions[0].clone(),
                change_confirmation: rows.rule_set_change_confirmations[0].clone(),
            },
            ManagementMutationV2::VersionPublish {
                rule_set_id: id(5),
                version_row: rows.rule_set_versions[0].clone(),
                new_current_version: vec![1],
                change_confirmation: rows.rule_set_change_confirmations[0].clone(),
            },
        ];
        for mutation in mutations {
            let current = digest_rows(&CandidateRows::default(), &[]).unwrap();
            assert!(matches!(
                prepare_root_digest(&current, &next, &mutation),
                Err(MutationError::Runtime(RuntimeError::InconsistentCandidate))
            ));
        }
    }

    #[test]
    // memory—v1: Binding digest preparation ignores the public binding-read budget.
    fn binding_digest_preparation_does_not_consume_read_budget() {
        let (rows, selections) = base_rows();
        let mut create_rows = rows.clone();
        create_rows.bindings.clear();
        create_rows.binding_confirmations.clear();
        let create_base =
            HamtCandidate::build(create_rows, selections.clone(), budget(32, 0)).unwrap();
        let create_binding = binding(id(6), id(4), id(5));
        let create_confirmation = binding_confirmation(id(7), id(6), id(5), vec![1], id(1));
        let create_next = create_base
            .with_binding_insert(create_binding.clone())
            .unwrap()
            .with_confirmation_insert(create_confirmation.clone())
            .unwrap();
        assert_incremental_equals_rebuild(
            &digest(&create_base),
            &create_next,
            ManagementMutationV2::BindingCreate {
                row: create_binding,
                confirmation: create_confirmation,
            },
        );

        let remove_base = HamtCandidate::build(rows, selections, budget(32, 0)).unwrap();
        let remove_next = remove_base.with_binding_removed(id(6), 200, id(1)).unwrap();
        assert_incremental_equals_rebuild(
            &digest(&remove_base),
            &remove_next,
            ManagementMutationV2::BindingRemove {
                binding_id: id(6),
                removed_at: 200,
                removed_by: id(1),
            },
        );
    }
}
