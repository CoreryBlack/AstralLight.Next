use super::*;
use crate::memory_v1_facts::BindingLayer;
use std::sync::{Arc, Barrier};
use std::thread;

// memory—v1: Bound both serialized candidate partitions for these isolated tests.
fn limits() -> Limits {
    Limits {
        max_slots: 2,
        max_value_bytes: 64 * 1024,
        max_capture_slots: 2,
        max_change_slots: 2,
    }
}

// memory—v1: Construct a current tuple using the experimental digest interface.
fn current(version: &[u8], content: &[u8]) -> CurrentRuleSet {
    let tuple = ExperimentalRuleSet::new(version.to_vec(), content.to_vec(), vec![0, 255]).unwrap();
    CurrentRuleSet {
        rule_set_id: 40,
        version: tuple.version().to_vec(),
        content: tuple.content().to_vec(),
        timestamp: tuple.timestamp().to_vec(),
        hash: *tuple.hash(),
    }
}

// memory—v1: Supply a parent, child, colleague and two explicitly shared bindings.
fn sample() -> CandidateState {
    CandidateState {
        facts: CandidateFacts {
            users: vec![User { user_id: 1 }, User { user_id: 2 }],
            tenants: vec![
                Tenant {
                    tenant_id: 10,
                    parent_tenant_id: None,
                },
                Tenant {
                    tenant_id: 11,
                    parent_tenant_id: Some(10),
                },
            ],
            identity_cards: vec![
                IdentityCard {
                    identity_card_id: 20,
                    user_id: 1,
                },
                IdentityCard {
                    identity_card_id: 21,
                    user_id: 2,
                },
            ],
            user_cards: vec![
                UserCard {
                    user_card_id: 30,
                    user_id: 1,
                    tenant_id: 10,
                },
                UserCard {
                    user_card_id: 31,
                    user_id: 1,
                    tenant_id: 11,
                },
                UserCard {
                    user_card_id: 32,
                    user_id: 2,
                    tenant_id: 10,
                },
                UserCard {
                    user_card_id: 33,
                    user_id: 2,
                    tenant_id: 11,
                },
            ],
            rule_sets: vec![RuleSet {
                rule_set_id: 40,
                owner_tenant_id: 10,
            }],
            bindings: vec![
                Binding {
                    binding_id: 50,
                    user_card_id: 30,
                    tenant_id: 10,
                    rule_set_id: 40,
                    layer: BindingLayer::Base,
                },
                Binding {
                    binding_id: 51,
                    user_card_id: 31,
                    tenant_id: 11,
                    rule_set_id: 40,
                    layer: BindingLayer::Overlay,
                },
            ],
            binding_confirmations: vec![
                BindingConfirmation {
                    confirmation_id: 60,
                    binding_id: 50,
                    rule_set_id: 40,
                    confirmer_user_id: 2,
                    version_bytes: vec![0, 255],
                    scope_bytes: vec![],
                    operation_id: vec![0, 1, 255],
                    confirmed_at_bytes: b"not-a-time".to_vec(),
                },
                BindingConfirmation {
                    confirmation_id: 61,
                    binding_id: 50,
                    rule_set_id: 40,
                    confirmer_user_id: 1,
                    version_bytes: vec![],
                    scope_bytes: vec![255, 0],
                    operation_id: vec![],
                    confirmed_at_bytes: vec![],
                },
            ],
            rule_set_change_confirmations: vec![],
        },
        current_rule_sets: vec![current(b"v1", b"first rules")],
    }
}

#[test]
// memory—v1: Reject mismatched user, identity card, user card and tenant inputs.
fn read_requires_the_exact_dual_card_tenant_relationship() {
    let owner = CandidateOwner::new(sample(), limits()).unwrap();
    let handle = owner.handle();
    let read = handle.read_card(1, 20, 30, 10).unwrap();
    assert_eq!(read.context.user.user_id, 1);
    assert_eq!(read.context.identity_card.identity_card_id, 20);
    assert_eq!(read.context.card.user_card_id, 30);
    assert_eq!(read.context.tenant.tenant_id, 10);

    for (user, identity, card, tenant) in [
        (2, 20, 30, 10),
        (1, 21, 30, 10),
        (1, 20, 32, 10),
        (1, 20, 30, 11),
        (1, 20, 999, 10),
        (1, 20, 31, 10),
    ] {
        assert!(matches!(
            handle.read_card(user, identity, card, tenant),
            Err(CandidateError::CardMismatch)
        ));
    }
}

#[test]
// memory—v1: Return direct bindings only despite hierarchy and shared colleagues.
fn parent_child_and_colleague_do_not_gain_automatic_bindings() {
    let mut candidate = sample();
    candidate
        .facts
        .bindings
        .retain(|binding| binding.binding_id == 50);
    let owner = CandidateOwner::new(candidate, limits()).unwrap();
    let handle = owner.handle();
    assert_eq!(
        handle
            .read_card(1, 20, 30, 10)
            .unwrap()
            .context
            .bindings
            .len(),
        1
    );
    for (user, identity, card, tenant) in [(1, 20, 31, 11), (2, 21, 32, 10), (2, 21, 33, 11)] {
        assert!(handle
            .read_card(user, identity, card, tenant)
            .unwrap()
            .context
            .bindings
            .is_empty());
    }
}

#[test]
// memory—v1: Update the shared tuple for both cards and reject the old read token.
fn shared_rule_set_replacement_is_immediately_visible_and_old_read_is_stale() {
    let initial = sample();
    let mut owner = CandidateOwner::new(initial.clone(), limits()).unwrap();
    let handle = owner.handle();
    let old_parent = handle.read_card(1, 20, 30, 10).unwrap();
    let old_child = handle.read_card(1, 20, 31, 11).unwrap();
    assert_eq!(
        *old_parent.context.bindings[0].current,
        initial.current_rule_sets[0]
    );
    assert_eq!(
        *old_child.context.bindings[0].current,
        initial.current_rule_sets[0]
    );

    let mut next = initial.clone();
    next.current_rule_sets[0] = current(b"v2", b"replacement rules");
    let committed = owner.replace(&old_parent, next.clone()).unwrap();
    assert_eq!(committed.version, old_parent.metadata().version + 1);
    assert_ne!(committed.digest, old_parent.metadata().digest);
    assert!(!handle.is_current(&old_parent).unwrap());
    assert!(!handle.is_current(&old_child).unwrap());
    for (card, tenant) in [(30, 10), (31, 11)] {
        let read = handle.read_card(1, 20, card, tenant).unwrap();
        assert_eq!(read.metadata(), committed);
        assert_eq!(*read.context.bindings[0].current, next.current_rule_sets[0]);
        assert!(handle.is_current(&read).unwrap());
    }
    assert_eq!(
        *old_parent.context.bindings[0].current,
        initial.current_rule_sets[0]
    );
    assert!(matches!(
        owner.replace(&old_child, initial),
        Err(CandidateError::StaleCapture)
    ));
    let after = handle.read_card(1, 20, 30, 10).unwrap();
    assert_eq!(after.metadata(), committed);
    assert_eq!(
        *after.context.bindings[0].current,
        next.current_rule_sets[0]
    );
}

#[test]
// memory—v1: Bind capture tokens to their owner even when metadata is identical.
fn foreign_owner_token_cannot_observe_current_or_replace() {
    let candidate = sample();
    let mut first = CandidateOwner::new(candidate.clone(), limits()).unwrap();
    let second = CandidateOwner::new(candidate.clone(), limits()).unwrap();
    let first_handle = first.handle();
    let first_read = first_handle.read_card(1, 20, 30, 10).unwrap();
    let foreign = second.handle().read_card(1, 20, 30, 10).unwrap();
    assert_eq!(first_read.metadata(), foreign.metadata());
    assert!(!first_handle.is_current(&foreign).unwrap());
    assert!(!second.handle().is_current(&first_read).unwrap());
    let mut next = candidate;
    next.current_rule_sets[0] = current(b"v2", b"foreign replacement");
    assert!(matches!(
        first.replace(&foreign, next),
        Err(CandidateError::StaleCapture)
    ));
    let after = first_handle.read_card(1, 20, 30, 10).unwrap();
    assert_eq!(after.metadata(), first_read.metadata());
    assert_eq!(after.context, first_read.context);
    assert!(first_handle.is_current(&first_read).unwrap());
}

#[test]
// memory—v1: Distinguish an unloaded current tuple from an empty binding list.
fn bound_rule_set_without_current_tuple_is_missing() {
    let mut candidate = sample();
    candidate.current_rule_sets.clear();
    let owner = CandidateOwner::new(candidate, limits()).unwrap();
    let handle = owner.handle();
    for (card, tenant) in [(30, 10), (31, 11)] {
        assert!(matches!(
            handle.read_card(1, 20, card, tenant),
            Err(CandidateError::MissingCurrentRuleSet(40))
        ));
    }
    assert!(handle
        .read_card(2, 21, 32, 10)
        .unwrap()
        .context
        .bindings
        .is_empty());
}

#[test]
// memory—v1: Preserve opaque confirmation rows without interpreting their contents.
fn confirmations_are_returned_verbatim_for_their_binding_only() {
    let candidate = sample();
    let owner = CandidateOwner::new(candidate.clone(), limits()).unwrap();
    let handle = owner.handle();
    let parent = handle.read_card(1, 20, 30, 10).unwrap();
    assert_eq!(
        parent.context.bindings[0].confirmations,
        candidate.facts.binding_confirmations
    );
    let child = handle.read_card(1, 20, 31, 11).unwrap();
    assert!(child.context.bindings[0].confirmations.is_empty());
}

#[test]
// memory—v1: Leave facts, rule contents, version and digest untouched on rejection.
fn invalid_candidates_do_not_commit_facts_or_hash() {
    let initial = sample();
    let mut owner = CandidateOwner::new(initial.clone(), limits()).unwrap();
    let handle = owner.handle();
    let before = handle.read_card(1, 20, 30, 10).unwrap();
    let child_before = handle.read_card(1, 20, 31, 11).unwrap();

    let mut invalid_facts = initial.clone();
    invalid_facts.facts.bindings[0].tenant_id = 11;
    invalid_facts.current_rule_sets[0] = current(b"v2", b"must not commit");
    assert!(matches!(
        owner.replace(&before, invalid_facts),
        Err(CandidateError::Facts(
            ValidationError::BindingTenantMismatch { binding_id: 50, .. }
        ))
    ));
    let mut invalid_hash = initial.clone();
    invalid_hash.facts.tenants[1].parent_tenant_id = None;
    invalid_hash.current_rule_sets[0].content = b"tampered".to_vec();
    assert!(matches!(
        owner.replace(&before, invalid_hash),
        Err(CandidateError::RuleSet(
            RuleSetIntegrityError::DigestMismatch
        ))
    ));
    let mut unknown = initial.clone();
    unknown.current_rule_sets[0].rule_set_id = 999;
    assert!(matches!(
        owner.replace(&before, unknown),
        Err(CandidateError::UnknownRuleSet(999))
    ));
    let mut duplicate = initial.clone();
    duplicate
        .current_rule_sets
        .push(duplicate.current_rule_sets[0].clone());
    assert!(matches!(
        owner.replace(&before, duplicate),
        Err(CandidateError::DuplicateRuleSet(40))
    ));

    let after = handle.read_card(1, 20, 30, 10).unwrap();
    let child_after = handle.read_card(1, 20, 31, 11).unwrap();
    assert_eq!(after.metadata(), before.metadata());
    assert_eq!(after.context, before.context);
    assert_eq!(child_after.metadata(), child_before.metadata());
    assert_eq!(child_after.context, child_before.context);
    assert!(handle.is_current(&before).unwrap());
    assert!(handle.is_current(&child_before).unwrap());
}

#[test]
// memory—v1: Allow empty and incomplete candidates to be repaired with an observation token.
fn owner_tokens_support_initialization_and_missing_tuple_repair() {
    let mut owner = CandidateOwner::new(CandidateState::default(), limits()).unwrap();
    let handle = owner.handle();
    let initial = handle.token().unwrap();
    let mut incomplete = sample();
    incomplete.current_rule_sets.clear();
    owner
        .replace_if_current(&initial, incomplete.clone())
        .unwrap();
    assert!(matches!(
        owner.replace_if_current(&initial, sample()),
        Err(CandidateError::StaleCapture)
    ));
    assert!(matches!(
        handle.read_card(1, 20, 30, 10),
        Err(CandidateError::MissingCurrentRuleSet(40))
    ));
    let repair = handle.token().unwrap();
    incomplete
        .current_rule_sets
        .push(current(b"v1", b"repaired"));
    owner.replace_if_current(&repair, incomplete).unwrap();
    assert_eq!(
        handle.read_card(1, 20, 30, 10).unwrap().context().bindings[0]
            .current
            .content,
        b"repaired"
    );
}

#[test]
// memory—v1: Reject limits incapable of reading and updating both partitions.
fn constructor_rejects_insufficient_partition_limits() {
    let mut too_small = limits();
    too_small.max_capture_slots = 1;
    assert!(matches!(
        CandidateOwner::new(sample(), too_small),
        Err(CandidateError::Kernel(StateError::InvalidLimits))
    ));
    too_small = limits();
    too_small.max_change_slots = 1;
    assert!(matches!(
        CandidateOwner::new(sample(), too_small),
        Err(CandidateError::Kernel(StateError::InvalidLimits))
    ));
}

#[test]
// memory—v1: Multiple bindings in one read share the rule-set allocation.
fn repeated_bindings_share_current_rule_content() {
    let mut candidate = sample();
    let mut binding = candidate.facts.bindings[0].clone();
    binding.binding_id = 99;
    candidate.facts.bindings.push(binding);
    let owner = CandidateOwner::new(candidate, limits()).unwrap();
    let read = owner.handle().read_card(1, 20, 30, 10).unwrap();
    assert!(Arc::ptr_eq(
        &read.context().bindings[0].current,
        &read.context().bindings[1].current
    ));
}

#[test]
// memory—v1: Concurrent readers observe a complete facts and rules batch with its digest.
fn concurrent_reads_never_mix_facts_and_rules_from_different_batches() {
    const READERS: usize = 4;
    const WRITES: u64 = 300;
    const READS: usize = 2_000;
    let even = sample();
    let mut odd = even.clone();
    odd.facts.tenants[1].parent_tenant_id = None;
    odd.current_rule_sets[0] = current(b"v2", b"other batch");

    let even_owner = CandidateOwner::new(even.clone(), limits()).unwrap();
    let odd_owner = CandidateOwner::new(odd.clone(), limits()).unwrap();
    let even_read = even_owner.handle().read_card(1, 20, 31, 11).unwrap();
    let odd_read = odd_owner.handle().read_card(1, 20, 31, 11).unwrap();
    let even_context = even_read.context.clone();
    let odd_context = odd_read.context.clone();
    let even_digest = even_read.metadata().digest;
    let odd_digest = odd_read.metadata().digest;
    assert_ne!(even_context, odd_context);
    assert_ne!(even_digest, odd_digest);

    let mut owner = CandidateOwner::new(even.clone(), limits()).unwrap();
    let handle = owner.handle();
    let ready = Arc::new(Barrier::new(READERS + 1));
    let mut readers = Vec::new();
    for _ in 0..READERS {
        let handle = handle.clone();
        let ready = Arc::clone(&ready);
        let even_context = even_context.clone();
        let odd_context = odd_context.clone();
        readers.push(thread::spawn(move || {
            ready.wait();
            for _ in 0..READS {
                let read = handle.read_card(1, 20, 31, 11).unwrap();
                let (context, digest) = if read.metadata().version.is_multiple_of(2) {
                    (&even_context, even_digest)
                } else {
                    (&odd_context, odd_digest)
                };
                assert_eq!(&read.context, context);
                assert_eq!(read.metadata().digest, digest);
            }
        }));
    }
    ready.wait();
    for version in 1..=WRITES {
        let read = handle.read_card(1, 20, 31, 11).unwrap();
        let candidate = if version % 2 == 0 { &even } else { &odd };
        let metadata = owner.replace(&read, candidate.clone()).unwrap();
        assert_eq!(metadata.version, version);
        thread::yield_now();
    }
    for reader in readers {
        reader.join().unwrap();
    }
    let final_read = handle.read_card(1, 20, 31, 11).unwrap();
    assert_eq!(final_read.metadata().version, WRITES);
    assert_eq!(final_read.metadata().digest, even_digest);
    assert_eq!(final_read.context, even_context);
}
