//! Experimental inspection of one memory-v1 candidate root.
//!
//! This path is deliberately separate from formal authorization. Candidate rows
//! do not establish completeness, status, confirmation validity, resource
//! ownership, or rule semantics. This module cannot return an ALLOW or a
//! `PolicyDecision` and must not be used to authorize a request.

use astral_authorization_root::memory_v1_db_rows::{BinaryId, UserCardStatus};
use astral_authorization_root::memory_v1_hamt_runtime::{HamtRuntimeHandle, RuntimeCardContext};
use astral_authorization_root::memory_v1_root::RequestRootReader;
use astral_types::memory_v1::CandidateIdentity;

/// Candidate identity supplied to the inspection. It is not an authentication proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateRequest {
    pub user_id: BinaryId,
    pub identity_card_id: BinaryId,
    pub user_card_id: BinaryId,
    pub tenant_id: BinaryId,
}

/// The outcome is always non-authorizing, including when relationships agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateInspection {
    /// The supplied identity does not match the rows observed for this card.
    IdentityMismatch,
    /// A referenced rule set has no selected version in this candidate.
    MissingSelection,
    /// The owner changed after the candidate was read.
    Changed,
    /// The candidate could not be read or rechecked.
    Unavailable,
    /// Relationships agree, but the candidate is not authorization evidence.
    Unverified,
}

// memory—v1: Compare the candidate identity and selection in one borrowed view.
fn inspect_context(context: RuntimeCardContext<'_>, request: &CandidateRequest) -> (bool, bool) {
    let matches = context.user.user_id == request.user_id
        && context.identity.identity_card_id == request.identity_card_id
        && context.identity.user_id == request.user_id
        && context.card.user_card_id == request.user_card_id
        && context.card.user_id == request.user_id
        && context.card.tenant_id == request.tenant_id
        && context.tenant.tenant_id == request.tenant_id;
    let all_selected = context
        .bindings
        .iter()
        .all(|binding| binding.selected.is_some());
    (matches, all_selected)
}

/// memory—v1: Inspect a candidate using the request's shared reader and recheck it.
///
/// This is not an authorization decision; even `Unverified` must never grant
/// permission. Read or owner failures are reported as unavailable.
pub fn inspect_request_candidate(
    reader: &RequestRootReader,
    request: &CandidateRequest,
) -> CandidateInspection {
    let (matches, all_selected) = match reader.read_card(request.user_card_id, |context| {
        inspect_context(context, request)
    }) {
        Ok(value) => value,
        Err(_) => return CandidateInspection::Unavailable,
    };
    match reader.is_current() {
        Ok(true) => {}
        Ok(false) => return CandidateInspection::Changed,
        Err(_) => return CandidateInspection::Unavailable,
    }
    if !matches {
        CandidateInspection::IdentityMismatch
    } else if !all_selected {
        CandidateInspection::MissingSelection
    } else {
        CandidateInspection::Unverified
    }
}

/// memory—v1: Inspect typed candidate identity with the same request reader.
///
/// The conversion preserves all 16 bytes of each ID. Neither the identity nor
/// any inspection outcome proves authentication or permits authorization.
/// Read or owner failures remain unavailable; a matching candidate is unverified.
pub fn inspect_typed_request_candidate(
    reader: &RequestRootReader,
    identity: &CandidateIdentity,
) -> CandidateInspection {
    let request = CandidateRequest {
        user_id: identity.user_id.into_bytes(),
        identity_card_id: identity.identity_card_id.into_bytes(),
        user_card_id: identity.user_card_id.into_bytes(),
        tenant_id: identity.tenant_id.into_bytes(),
    };
    inspect_request_candidate(reader, &request)
}

/// memory—v1: Inspect one candidate context and recheck its owner-bound token.
///
/// This does not parse rule bytes or decide whether a request is authorized.
/// The caller must never translate `Unverified` into permission to proceed.
pub fn inspect_candidate(
    root: &HamtRuntimeHandle,
    request: &CandidateRequest,
) -> CandidateInspection {
    inspect_with(root, request, || {})
}

// memory—v1: Inspect and recheck the same candidate around a bounded callback.
fn inspect_with(
    root: &HamtRuntimeHandle,
    request: &CandidateRequest,
    after_read: impl FnOnce(),
) -> CandidateInspection {
    let read = match root.read_card(request.user_card_id, |context| {
        inspect_context(context, request)
    }) {
        Ok(read) => read,
        Err(_) => return CandidateInspection::Unavailable,
    };
    after_read();
    match root.is_current(&read.token) {
        Ok(true) => {}
        Ok(false) => return CandidateInspection::Changed,
        Err(_) => return CandidateInspection::Unavailable,
    }
    if !read.value.0 {
        CandidateInspection::IdentityMismatch
    } else if !read.value.1 {
        CandidateInspection::MissingSelection
    } else {
        CandidateInspection::Unverified
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_authorization_root::memory_v1_db_rows::{
        BindingLayer, BindingRow, CandidateRows, CurrentSelection, IdentityCardRow, RuleSetRow,
        RuleSetVersionRow, TenantRow, UserCardRow, UserRow,
    };
    use astral_authorization_root::memory_v1_hamt::CandidateBudget;
    use astral_authorization_root::memory_v1_hamt_runtime::HamtRuntimeOwner;
    use astral_authorization_root::memory_v1_rules::{MemoryV1OwnerScope, MemoryV1TenantScope};
    use astral_types::memory_v1::MemoryId;

    // memory—v1: Create distinct candidate identities for isolation checks.
    fn id(value: u8) -> BinaryId {
        [value; 16]
    }

    // memory—v1: Build a bounded candidate without implying complete facts.
    fn owner(select_version: bool) -> HamtRuntimeOwner {
        owner_with_binding_budget(select_version, 4)
    }

    // memory—v1: Vary the read budget independently of the supplied rows.
    fn owner_with_binding_budget(
        select_version: bool,
        max_bindings_per_read: usize,
    ) -> HamtRuntimeOwner {
        let rows = CandidateRows {
            users: vec![UserRow { user_id: id(1) }],
            identity_cards: vec![IdentityCardRow {
                identity_card_id: id(2),
                user_id: id(1),
            }],
            tenants: vec![TenantRow {
                tenant_id: id(3),
                parent_tenant_id: None,
            }],
            user_cards: vec![UserCardRow {
                user_card_id: id(4),
                user_id: id(1),
                tenant_id: id(3),
                status: UserCardStatus::Active,
            }],
            rule_sets: vec![RuleSetRow {
                rule_set_id: id(5),
                owner_tenant_id: id(3),
                current_version_bytes: vec![1],
            }],
            rule_set_versions: vec![RuleSetVersionRow {
                rule_set_id: id(5),
                version_bytes: vec![1],
                content_bytes: vec![1],
                timestamp_bytes: vec![1],
                hash_input_bytes: vec![1],
                hash_bytes: vec![1],
            }],
            bindings: vec![BindingRow {
                binding_id: id(6),
                user_card_id: id(4),
                rule_set_id: id(5),
                binding_layer: BindingLayer::Base,
                valid_from: None,
                valid_until: None,
                owner_scope: MemoryV1OwnerScope::default(),
                tenant_scope: MemoryV1TenantScope::default(),
                removed_at: None,
                removed_by: None,
            }],
            ..CandidateRows::default()
        };
        let selections = if select_version {
            vec![CurrentSelection {
                rule_set_id: id(5),
                version_bytes: vec![1],
            }]
        } else {
            vec![]
        };
        HamtRuntimeOwner::new(
            rows,
            selections,
            CandidateBudget {
                max_table_rows: 32,
                max_bindings_per_read,
            },
        )
        .unwrap()
    }

    // memory—v1: Build the identity to inspect, without granting permission.
    fn request() -> CandidateRequest {
        CandidateRequest {
            user_id: id(1),
            identity_card_id: id(2),
            user_card_id: id(4),
            tenant_id: id(3),
        }
    }

    // memory—v1: One process root and reader cover identity, selection, and owner lifetime.
    #[test]
    fn request_reader_candidate_checks_remain_non_authorizing() {
        use astral_authorization_root::memory_v1_root::install_process_root;

        let rows = CandidateRows {
            users: vec![UserRow { user_id: id(1) }, UserRow { user_id: id(11) }],
            identity_cards: vec![
                IdentityCardRow {
                    identity_card_id: id(2),
                    user_id: id(1),
                },
                IdentityCardRow {
                    identity_card_id: id(12),
                    user_id: id(11),
                },
            ],
            tenants: vec![
                TenantRow {
                    tenant_id: id(3),
                    parent_tenant_id: None,
                },
                TenantRow {
                    tenant_id: id(13),
                    parent_tenant_id: None,
                },
            ],
            user_cards: vec![
                UserCardRow {
                    user_card_id: id(4),
                    user_id: id(1),
                    tenant_id: id(3),
                    status: UserCardStatus::Active,
                },
                UserCardRow {
                    user_card_id: id(7),
                    user_id: id(1),
                    tenant_id: id(3),
                    status: UserCardStatus::Active,
                },
                UserCardRow {
                    user_card_id: id(14),
                    user_id: id(11),
                    tenant_id: id(3),
                    status: UserCardStatus::Active,
                },
                UserCardRow {
                    user_card_id: id(15),
                    user_id: id(1),
                    tenant_id: id(13),
                    status: UserCardStatus::Active,
                },
            ],
            rule_sets: vec![
                RuleSetRow {
                    rule_set_id: id(5),
                    owner_tenant_id: id(3),
                    current_version_bytes: vec![1],
                },
                RuleSetRow {
                    rule_set_id: id(8),
                    owner_tenant_id: id(3),
                    current_version_bytes: vec![1],
                },
            ],
            rule_set_versions: vec![RuleSetVersionRow {
                rule_set_id: id(5),
                version_bytes: vec![1],
                content_bytes: vec![1],
                timestamp_bytes: vec![1],
                hash_input_bytes: vec![1],
                hash_bytes: vec![1],
            }],
            bindings: vec![
                BindingRow {
                    binding_id: id(6),
                    user_card_id: id(4),
                    rule_set_id: id(5),
                    binding_layer: BindingLayer::Base,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::default(),
                    tenant_scope: MemoryV1TenantScope::default(),
                    removed_at: None,
                    removed_by: None,
                },
                BindingRow {
                    binding_id: id(9),
                    user_card_id: id(7),
                    rule_set_id: id(8),
                    binding_layer: BindingLayer::Base,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::default(),
                    tenant_scope: MemoryV1TenantScope::default(),
                    removed_at: None,
                    removed_by: None,
                },
            ],
            ..CandidateRows::default()
        };
        let owner = install_process_root(
            rows,
            vec![CurrentSelection {
                rule_set_id: id(5),
                version_bytes: vec![1],
            }],
            CandidateBudget {
                max_table_rows: 32,
                max_bindings_per_read: 4,
            },
        )
        .unwrap();
        let reader = owner
            .handle()
            .begin_request("00000000-0000-4000-8000-000000000001".parse().unwrap())
            .unwrap();

        assert_eq!(
            inspect_request_candidate(&reader, &request()),
            CandidateInspection::Unverified
        );
        for mismatch in [
            CandidateRequest {
                user_id: id(10),
                ..request()
            },
            CandidateRequest {
                identity_card_id: id(10),
                ..request()
            },
            CandidateRequest {
                tenant_id: id(10),
                ..request()
            },
        ] {
            assert_eq!(
                inspect_request_candidate(&reader, &mismatch),
                CandidateInspection::IdentityMismatch
            );
        }
        assert_eq!(
            inspect_request_candidate(
                &reader,
                &CandidateRequest {
                    user_card_id: id(7),
                    ..request()
                },
            ),
            CandidateInspection::MissingSelection
        );
        assert_eq!(
            inspect_request_candidate(
                &reader,
                &CandidateRequest {
                    user_card_id: id(10),
                    ..request()
                },
            ),
            CandidateInspection::Unavailable
        );
        // UUID values enter directly, without a numeric identity mapping.
        let identity = CandidateIdentity {
            user_id: "01010101-0101-0101-0101-010101010101".parse().unwrap(),
            identity_card_id: "02020202-0202-0202-0202-020202020202".parse().unwrap(),
            user_card_id: "04040404-0404-0404-0404-040404040404".parse().unwrap(),
            tenant_id: "03030303-0303-0303-0303-030303030303".parse().unwrap(),
        };
        assert_eq!(
            inspect_typed_request_candidate(&reader, &identity),
            CandidateInspection::Unverified
        );
        for mismatch in [
            CandidateIdentity {
                user_id: MemoryId::from_bytes(id(11)),
                ..identity
            },
            CandidateIdentity {
                identity_card_id: MemoryId::from_bytes(id(12)),
                ..identity
            },
            CandidateIdentity {
                user_card_id: MemoryId::from_bytes(id(14)),
                ..identity
            },
            CandidateIdentity {
                user_card_id: MemoryId::from_bytes(id(15)),
                ..identity
            },
            CandidateIdentity {
                tenant_id: MemoryId::from_bytes(id(13)),
                ..identity
            },
            CandidateIdentity {
                user_id: MemoryId::from_bytes([0; 16]),
                ..identity
            },
        ] {
            assert_eq!(
                inspect_typed_request_candidate(&reader, &mismatch),
                CandidateInspection::IdentityMismatch
            );
        }
        assert_eq!(
            inspect_typed_request_candidate(
                &reader,
                &CandidateIdentity {
                    user_card_id: MemoryId::from_bytes(id(7)),
                    ..identity
                },
            ),
            CandidateInspection::MissingSelection
        );
        assert_eq!(
            inspect_typed_request_candidate(
                &reader,
                &CandidateIdentity {
                    user_card_id: MemoryId::from_bytes(id(10)),
                    ..identity
                },
            ),
            CandidateInspection::Unavailable
        );
        drop(owner);
        assert_eq!(
            inspect_request_candidate(&reader, &request()),
            CandidateInspection::Unavailable
        );
        assert_eq!(
            inspect_typed_request_candidate(&reader, &identity),
            CandidateInspection::Unavailable
        );
    }

    // memory—v1: Matching rows and arbitrary rule bytes never yield an ALLOW.
    #[test]
    fn matching_candidate_is_unverified() {
        let owner = owner(true);
        assert_eq!(
            inspect_candidate(&owner.handle(), &request()),
            CandidateInspection::Unverified
        );
    }

    // memory—v1: Each independently supplied identity must match the same card.
    #[test]
    fn mismatched_user_identity_and_tenant_are_not_accepted() {
        let owner = owner(true);
        for request in [
            CandidateRequest {
                user_id: id(9),
                ..request()
            },
            CandidateRequest {
                identity_card_id: id(9),
                ..request()
            },
            CandidateRequest {
                tenant_id: id(9),
                ..request()
            },
        ] {
            assert_eq!(
                inspect_candidate(&owner.handle(), &request),
                CandidateInspection::IdentityMismatch
            );
        }
        let missing_card = CandidateRequest {
            user_card_id: id(9),
            ..request()
        };
        assert_eq!(
            inspect_candidate(&owner.handle(), &missing_card),
            CandidateInspection::Unavailable
        );
    }

    // memory—v1: A write between reading and rechecking invalidates the observation.
    #[test]
    fn root_change_during_inspection_is_detected() {
        use astral_authorization_root::memory_v1_hamt_runtime::{SelectionChange, VersionChange};

        let mut owner = owner(true);
        let handle = owner.handle();
        let token = handle.token().unwrap();
        let prepared = owner
            .prepare(&token, id(5), VersionChange::Keep, SelectionChange::Clear)
            .unwrap();
        let result = inspect_with(&handle, &request(), || {
            owner.commit(prepared).unwrap();
        });
        assert_eq!(result, CandidateInspection::Changed);
    }

    // memory—v1: A matching context remains invalid if its owner disappears before recheck.
    #[test]
    fn owner_drop_between_read_and_recheck_is_unavailable() {
        let owner = owner(true);
        let handle = owner.handle();
        assert_eq!(
            inspect_with(&handle, &request(), || drop(owner)),
            CandidateInspection::Unavailable
        );
    }

    // memory—v1: Same content under another owner cannot satisfy the captured token.
    #[test]
    fn identical_candidate_from_another_owner_cannot_recheck_the_token() {
        use astral_authorization_root::memory_v1_hamt_runtime::RuntimeError;

        let first = owner(true);
        let second = owner(true);
        let token = first.handle().read_card(id(4), |_| ()).unwrap().token;
        assert_eq!(
            token.metadata(),
            second.handle().token().unwrap().metadata()
        );
        assert!(matches!(
            second.handle().is_current(&token),
            Err(RuntimeError::ForeignOwner)
        ));
    }

    // memory—v1: Restoring identical content does not restore a prior observation.
    #[test]
    fn restored_candidate_content_still_invalidates_read() {
        use astral_authorization_root::memory_v1_hamt_runtime::{SelectionChange, VersionChange};

        let mut owner = owner(true);
        let handle = owner.handle();
        let before = handle.token().unwrap();
        let result = inspect_with(&handle, &request(), || {
            let clear = owner
                .prepare(&before, id(5), VersionChange::Keep, SelectionChange::Clear)
                .unwrap();
            owner.commit(clear).unwrap();
            let changed = handle.token().unwrap();
            let restore = owner
                .prepare(
                    &changed,
                    id(5),
                    VersionChange::Keep,
                    SelectionChange::Set(vec![1]),
                )
                .unwrap();
            owner.commit(restore).unwrap();
        });
        let after = handle.token().unwrap();
        assert_eq!(before.metadata().digest, after.metadata().digest);
        assert_eq!(after.metadata().version, before.metadata().version + 2);
        assert_eq!(result, CandidateInspection::Changed);
    }

    // memory—v1: A concurrent completed update invalidates the captured inspection.
    #[test]
    fn concurrent_update_before_recheck_is_detected() {
        use astral_authorization_root::memory_v1_hamt_runtime::{SelectionChange, VersionChange};
        use std::sync::mpsc::sync_channel;
        use std::time::Duration;

        let mut owner = owner(true);
        let handle = owner.handle();
        let token = handle.token().unwrap();
        let prepared = owner
            .prepare(&token, id(5), VersionChange::Keep, SelectionChange::Clear)
            .unwrap();
        let (read_tx, read_rx) = sync_channel(1);
        let (resume_tx, resume_rx) = sync_channel(1);
        let reader = std::thread::spawn(move || {
            inspect_with(&handle, &request(), || {
                read_tx.send(()).unwrap();
                resume_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            })
        });
        read_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        owner.commit(prepared).unwrap();
        resume_tx.send(()).unwrap();
        assert_eq!(reader.join().unwrap(), CandidateInspection::Changed);
    }

    // memory—v1: A bounded read fails as a whole rather than reporting a partial context.
    #[test]
    fn binding_budget_exhaustion_is_unavailable() {
        let owner = owner_with_binding_budget(true, 0);
        assert_eq!(
            inspect_candidate(&owner.handle(), &request()),
            CandidateInspection::Unavailable
        );
    }

    // memory—v1: Missing current content and owner shutdown stay non-authorizing.
    #[test]
    fn missing_selection_and_dropped_owner_are_unavailable_for_authorization() {
        let owner = owner(false);
        let handle = owner.handle();
        assert_eq!(
            inspect_candidate(&handle, &request()),
            CandidateInspection::MissingSelection
        );
        drop(owner);
        assert_eq!(
            inspect_candidate(&handle, &request()),
            CandidateInspection::Unavailable
        );
    }
}
