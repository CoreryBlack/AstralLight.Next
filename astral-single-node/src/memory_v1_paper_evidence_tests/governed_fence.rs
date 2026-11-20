//! memory—v1: Governed rule publication against real readers and a local journal.

use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use astral_authorization_root::memory_v1_db_rows::RuleSetChangeConfirmationRow;
use astral_authorization_root::memory_v1_request::RequestRootScope;
use astral_authorization_root::memory_v1_root::{
    MutationError, MutationPrecondition, RootError, RootStatus,
};
use astral_authorization_root::memory_v1_rules::{canonical_version_bytes, version_digest};
use astral_types::memory_v1::CandidateIdentity;
use astral_types::memory_v1_audit::{
    MemoryV1AuditConfirmationRef, MemoryV1AuditRuleSetState, MemoryV1AuditRuleSetStatus,
};
use policy_engine::memory_v1_formal::{MemoryV1Decision, MemoryV1PendingSource, MemoryV1Request};
use policy_engine::PolicyEngine;
use uuid::Uuid;

use super::*;

const TARGET: [u8; 16] = [5; 16];
const UNRELATED: [u8; 16] = [15; 16];
const UNRELATED_CARD: [u8; 16] = [14; 16];
const CONFIRMATION: [u8; 16] = [9; 16];

fn two_rule_sets() -> TestRoot {
    let (mut rows, mut selections) = fixture_rows();
    let mut card = rows.user_cards[0].clone();
    card.user_card_id = UNRELATED_CARD;
    rows.user_cards.push(card);
    let mut rule_set = rows.rule_sets[0].clone();
    rule_set.rule_set_id = UNRELATED;
    rows.rule_sets.push(rule_set);
    let mut version = rows.rule_set_versions[0].clone();
    version.rule_set_id = UNRELATED;
    rows.rule_set_versions.push(version);
    let mut binding = rows.bindings[0].clone();
    binding.binding_id = [16; 16];
    binding.user_card_id = UNRELATED_CARD;
    binding.rule_set_id = UNRELATED;
    rows.bindings.push(binding);
    let mut binding_confirmation = rows.binding_confirmations[0].clone();
    binding_confirmation.confirmation_id = [17; 16];
    binding_confirmation.binding_id = [16; 16];
    binding_confirmation.rule_set_id = UNRELATED;
    rows.binding_confirmations.push(binding_confirmation);
    let mut change_confirmation = rows.rule_set_change_confirmations[0].clone();
    change_confirmation.confirmation_id = [18; 16];
    change_confirmation.rule_set_id = UNRELATED;
    rows.rule_set_change_confirmations.push(change_confirmation);
    selections.push(CurrentSelection {
        rule_set_id: UNRELATED,
        version_bytes: vec![1],
    });
    let counts = rows.table_counts();
    let owner = install_isolated_test_root(rows, selections, budget()).unwrap();
    owner.install_registry(&registry_declarations()).unwrap();
    let (_, admission) = owner
        .adopt_with_production_evidence(&cold_facts(counts), &sealed_input())
        .unwrap();
    TestRoot {
        owner: Arc::new(owner),
        admission: Arc::new(admission),
        dir: scratch_dir("fence"),
    }
}

fn publish_request(root: RootMetadata, operation_id: &str) -> MemoryV1GovernanceCommitRequest {
    let version = vec![2];
    let timestamp = vec![2];
    let content =
        br#"{"rules":[{"ruleId":"R9","resource":"document","action":"read","effect":"DENY"}]}"#
            .to_vec();
    let canonical = canonical_version_bytes(&version, &content, &timestamp);
    let hash: [u8; 32] = version_digest(&canonical).try_into().unwrap();
    let mutation = ManagementMutationV2::VersionPublish {
        rule_set_id: TARGET,
        version_row: RuleSetVersionRow {
            rule_set_id: TARGET,
            version_bytes: version.clone(),
            hash_input_bytes: canonical,
            hash_bytes: hash.to_vec(),
            content_bytes: content,
            timestamp_bytes: timestamp,
        },
        new_current_version: version.clone(),
        change_confirmation: RuleSetChangeConfirmationRow {
            confirmation_id: CONFIRMATION,
            rule_set_id: TARGET,
            version_bytes: version.clone(),
            confirmer_user_id: ACTOR,
            affected_scope_bytes: vec![1],
            operation_id: operation_id.as_bytes().to_vec(),
            confirmed_at_bytes: vec![1],
            revoked_at: None,
            revoked_by: None,
        },
    };
    let instance = MemoryId::from_bytes(*root.instance_id.as_uuid().as_bytes());
    let root_version = MemoryV1AuditRootVersion::new(instance, root.version);
    let context = MemoryV1AuditContext::new(
        MemoryV1AuditActor::new(MemoryId::from_bytes(ACTOR), MemoryId::from_bytes([2; 16])),
        MemoryV1AuditTime::new(TRUSTED_TIME).unwrap(),
        MemoryV1AuditAction::new("rule_set", "version-publish").unwrap(),
        "GOVERNANCE_RULE_SET_PUBLISH",
        MemoryV1AuditOperation::new(operation_id, [0xab; 32]).unwrap(),
        MemoryV1AuditRootObservation::new(
            root_version,
            root.digest,
            MemoryV1AuditRootStatus::Serving,
        ),
    )
    .unwrap();
    let selected = |version, hash| {
        MemoryV1AuditObjectState::RuleSet(
            MemoryV1AuditRuleSetState::new_with_status(
                version,
                hash,
                MemoryV1AuditRuleSetStatus::Active,
            )
            .unwrap(),
        )
    };
    let old = fixture_rows().0.rule_set_versions.remove(0);
    let change = MemoryV1AuditChange::new(
        Some(MemoryId::from_bytes(ACTOR)),
        Some(MemoryV1AuditObject::RuleSet(MemoryId::from_bytes(TARGET))),
        Some(MemoryV1AuditObject::Tenant(MemoryId::from_bytes(TENANT))),
        Some(MutationAuditCandidate::governance_mutation_summary(&mutation).unwrap()),
        Some(selected(
            &old.version_bytes,
            old.hash_bytes.try_into().unwrap(),
        )),
        Some(selected(&version, hash)),
        Some(
            MemoryV1AuditConfirmations::references(&[MemoryV1AuditConfirmationRef::RuleSetChange(
                MemoryId::from_bytes(CONFIRMATION),
            )])
            .unwrap(),
        ),
        Some(root_version),
        Some(MemoryV1AuditRootVersion::new(instance, root.version + 1)),
        MemoryV1AuditSource::Ordinary,
    );
    MemoryV1GovernanceCommitRequest {
        operation_id: operation_id.to_owned(),
        request_fingerprint: fingerprint_hex(),
        root,
        actor: ACTOR,
        target: TARGET,
        target_tenant: TENANT,
        target_owner: None,
        trusted_time_unix_seconds: TRUSTED_TIME,
        mutation,
        audit: MutationAuditCandidate::Single(
            MemoryV1AuditT2SingleChangeCandidate::try_from(
                MemoryV1AuditEvent::change(context, MemoryV1AuditDecisionInput::Allow, change)
                    .unwrap(),
            )
            .unwrap(),
        ),
    }
}

#[test]
fn commit_fence_blocks_only_dependent_reads_and_refuses_competing_writer() {
    let root = two_rule_sets();
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&root.owner).unwrap();
    let handle = root.owner.handle();
    let before = handle.metadata().unwrap();
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let issue = |card| {
        let scope = RequestRootScope::new(handle.clone(), Uuid::new_v4());
        authority
            .identity_session_adapter()
            .issue_verified_session_in_root(
                &scope.extension(),
                CandidateIdentity {
                    user_id: MemoryId::from_bytes(ACTOR),
                    identity_card_id: MemoryId::from_bytes([2; 16]),
                    user_card_id: MemoryId::from_bytes(card),
                    tenant_id: MemoryId::from_bytes(TENANT),
                },
                now - 1,
                300,
            )
            .unwrap()
    };
    let affected = issue(CARD);
    let unrelated = issue(UNRELATED_CARD);
    let engine = PolicyEngine::new();
    let evaluate = |credential| {
        let scope = RequestRootScope::new(handle.clone(), Uuid::new_v4());
        let context = scope.extension();
        let session = authority
            .verifier()
            .verify_and_bind(credential, now, &context)
            .unwrap();
        engine.evaluate_memory_v1(
            &context,
            &session,
            &MemoryV1Request {
                resource: "document",
                action: "read",
                target: None,
                target_owner: None,
                target_tenant: None,
                operation_id: b"fence-read",
                operation_fingerprint: b"fence-read",
            },
        )
    };
    assert_eq!(
        evaluate(affected.credential()).decision,
        MemoryV1Decision::Allow
    );
    assert_eq!(
        evaluate(unrelated.credential()).decision,
        MemoryV1Decision::Allow
    );

    let (ready_tx, ready_rx) = mpsc::channel();
    let (continue_tx, continue_rx) = mpsc::channel();
    let continue_rx = std::sync::Mutex::new(continue_rx);
    let mut owner = assembled_owner(&root);
    owner.set_before_append(move || {
        ready_tx.send(()).unwrap();
        continue_rx
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
    });
    let applied = std::thread::scope(|scope| {
        let first = scope.spawn(|| owner.commit(publish_request(before, "fence-first")));
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(handle.metadata().unwrap(), before);
        assert_eq!(file_len(&journal_path(&root)), 0);
        let active = evaluate(affected.credential());
        assert_eq!(active.decision, MemoryV1Decision::Pending);
        assert_eq!(
            active.pending_source,
            Some(MemoryV1PendingSource::FenceActive)
        );
        assert!(active.admission.is_none());
        assert_eq!(
            evaluate(unrelated.credential()).decision,
            MemoryV1Decision::Allow
        );
        assert!(matches!(
            owner.commit(publish_request(before, "fence-second")),
            Err(AstralError::Pending(_))
        ));
        assert_eq!(file_len(&journal_path(&root)), 0);
        continue_tx.send(()).unwrap();
        first.join().unwrap().unwrap().root
    });
    assert_eq!(applied.version, before.version + 1);
    assert!(!handle
        .begin_request(Uuid::new_v4())
        .unwrap()
        .is_fenced(TARGET)
        .unwrap());
    assert_eq!(
        evaluate(affected.credential()).decision,
        MemoryV1Decision::Deny
    );
    assert_eq!(
        evaluate(unrelated.credential()).decision,
        MemoryV1Decision::Allow
    );
    drop(owner);
    assert_eq!(reopen_journal(&root).0.record_count(), 1);
}

#[test]
fn a_known_refusal_releases_the_fence_without_publishing() {
    let root = production_root("fence-known-refusal");
    let writer = writer_for(&root);
    let handle = root.owner.handle();
    let before = handle.metadata().unwrap();
    let mut mutation = publish_request(before, "fence-bad").mutation;
    assert!(matches!(
        root.owner.execute_serving_mutation_with_admission(
            root.admission.as_ref(),
            &mutation,
            &MutationPrecondition {
                evaluated_root_version: before.version
            },
        ),
        Err(MutationError::ModificationFenceRequired)
    ));
    if let ManagementMutationV2::VersionPublish {
        new_current_version,
        ..
    } = &mut mutation
    {
        *new_current_version = vec![99];
    }
    assert!(writer.prepare(&before, &mutation).is_err());
    assert_eq!(handle.metadata().unwrap(), before);
    assert!(!handle
        .begin_request(Uuid::new_v4())
        .unwrap()
        .is_fenced(TARGET)
        .unwrap());
    let owner = assembled_owner(&root);
    owner
        .commit(publish_request(before, "fence-corrected"))
        .unwrap();
}

#[test]
fn an_unknown_append_withdraws_serving_before_releasing_the_window() {
    use std::io::Write as _;

    let root = production_root("fence-unknown");
    let handle = root.owner.handle();
    let before = handle.metadata().unwrap();
    let reader = handle.begin_request(Uuid::new_v4()).unwrap();
    let mut owner = assembled_owner(&root);
    let journal = journal_path(&root);
    owner.set_before_append(move || {
        // Simulate a changed local file; the real journal detects it and fences writes.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&journal)
            .unwrap()
            .write_all(&[0])
            .unwrap();
    });
    let error = owner
        .commit(publish_request(before, "fence-unknown"))
        .unwrap_err();
    assert!(pending_reason(&error).contains("FileChanged"));
    assert!(matches!(
        handle.metadata(),
        Err(RootError::Unavailable(RootStatus::Invalid))
    ));
    assert!(!reader.is_current().unwrap());
    assert!(!reader.is_fenced(TARGET).unwrap());
    assert!(owner
        .commit(publish_request(before, "fence-no-retry"))
        .is_err());
    assert_eq!(file_len(&journal_path(&root)), 1);
}
