//! memory—v1: Cancel or publish the same last-confirmation withdrawal on independent roots.

use super::*;
use astral_authorization_root::memory_v1_request::RequestRootExtension;
use astral_authorization_root::memory_v1_root::{
    DependencyRecord, EvaluationDependency, RootHandle,
};
use astral_authorization_root::memory_v1_rules::ChangeConfirmationState;
use astral_authorization_root::memory_v1_session::{
    FinalCheckTimeConstraints, FinalCheckWindow, RequestSessionExtension,
};
use astral_trustgraph::service::memory_v1_mutation_coordinator::decode_journal_payload;
use astral_types::memory_v1_audit::MemoryV1AuditConfirmationState;

const LAST: [u8; 16] = [8; 16];
const OPERATION: &str = "withdraw-last-change-confirmation";
const WAIT: Duration = Duration::from_secs(5);

fn withdrawal_request(root: RootMetadata) -> MemoryV1GovernanceCommitRequest {
    let mutation = ManagementMutationV2::RuleSetChangeConfirmationRevoke {
        confirmation_id: LAST,
        revoked_at: TRUSTED_TIME,
        revoked_by: ACTOR,
    };
    let actor = MemoryId::from_bytes(ACTOR);
    let instance = MemoryId::from_bytes(*root.instance_id.as_uuid().as_bytes());
    let before = MemoryV1AuditRootVersion::new(instance, root.version);
    let context = MemoryV1AuditContext::new(
        MemoryV1AuditActor::new(actor, MemoryId::from_bytes([2; 16])),
        MemoryV1AuditTime::new(TRUSTED_TIME).unwrap(),
        MemoryV1AuditAction::new("binding", "revoke-confirmation").unwrap(),
        "GOVERNANCE_CONFIRMATION_REVOKE",
        MemoryV1AuditOperation::new(OPERATION, [0xab; 32]).unwrap(),
        MemoryV1AuditRootObservation::new(before, root.digest, MemoryV1AuditRootStatus::Serving),
    )
    .unwrap();
    let change = MemoryV1AuditChange::new(
        Some(actor),
        Some(MemoryV1AuditObject::Confirmation(MemoryId::from_bytes(
            LAST,
        ))),
        Some(MemoryV1AuditObject::Tenant(MemoryId::from_bytes(TENANT))),
        Some(MutationAuditCandidate::governance_mutation_summary(&mutation).unwrap()),
        Some(MemoryV1AuditObjectState::Confirmation(
            MemoryV1AuditConfirmationState::Active,
        )),
        Some(MemoryV1AuditObjectState::Confirmation(
            MemoryV1AuditConfirmationState::Revoked,
        )),
        Some(MemoryV1AuditConfirmations::not_applicable()),
        Some(before),
        Some(MemoryV1AuditRootVersion::new(instance, root.version + 1)),
        MemoryV1AuditSource::Ordinary,
    );
    MemoryV1GovernanceCommitRequest {
        operation_id: OPERATION.to_owned(),
        request_fingerprint: fingerprint_hex(),
        root,
        actor: ACTOR,
        target: LAST,
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

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap()
}

fn request() -> MemoryV1Request<'static> {
    MemoryV1Request {
        resource: "document",
        action: "read",
        target: None,
        target_owner: None,
        target_tenant: None,
        operation_id: b"withdraw-read",
        operation_fingerprint: b"withdraw-read",
    }
}

fn confirmation(handle: &RootHandle) -> ChangeConfirmationState {
    handle
        .begin_request(Uuid::new_v4())
        .unwrap()
        .read_card_for_evaluation(CARD, |card, _| {
            assert_eq!(card.bindings.len(), 1);
            let binding = &card.bindings[0];
            assert_eq!(binding.rule_set.rule_set_id, TARGET);
            assert_eq!(binding.selected.unwrap().version_bytes, [1]);
            binding.change_confirmation_state
        })
        .unwrap()
}

// memory—v1: Inject only the clock in the ordinary final check. Its input describes
// this fixture's single unconditional grant, not a second policy evaluator.
fn clock_probe(
    root: &RequestRootExtension,
    session: &RequestSessionExtension,
    clock: impl FnOnce() -> Option<i64>,
) -> Option<i64> {
    session
        .with_authoritative_context(root, |_, reader, check| {
            let (tenant_tree_version, registry_version) = reader.dependency_versions().unwrap();
            let bindings = reader
                .read_card_for_evaluation(CARD, |card, _| {
                    card.bindings
                        .iter()
                        .map(|b| EvaluationDependency {
                            binding_id: b.binding.binding_id,
                            rule_set_id: b.rule_set.rule_set_id,
                            version_bytes: b.selected.unwrap().version_bytes.clone(),
                        })
                        .collect()
                })
                .unwrap();
            let record = DependencyRecord {
                card_id: CARD,
                instance_id: reader.metadata().instance_id,
                bindings,
                tenant_tree_version,
                registry_version,
            };
            let constraints = FinalCheckTimeConstraints {
                start_time: now(),
                future_boundaries: &[],
                winning_windows: &[FinalCheckWindow {
                    entry_validity: None,
                    binding_from: None,
                    binding_until: None,
                }],
            };
            check
                .unwrap()
                .try_final_time_for_test(&record, &constraints, clock)
        })
        .unwrap()
}

fn trace(commit: bool) {
    let root = two_rule_sets();
    let handle = root.owner.handle();
    let before = handle.metadata().unwrap();
    let authority = MemoryV1SessionAuthority::new();
    authority.bind_to_root(&root.owner).unwrap();
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
                now() - 1,
                300,
            )
            .unwrap()
    };
    let affected = issue(CARD);
    let shared = issue(SHARED_CARD);
    let unrelated = issue(UNRELATED_CARD);
    let engine = PolicyEngine::new();
    let fresh = |credential: &str| {
        let scope = RequestRootScope::new(handle.clone(), Uuid::new_v4());
        let ctx = scope.extension();
        let session = authority
            .verifier()
            .verify_and_bind(credential, now(), &ctx)
            .unwrap();
        engine.evaluate_memory_v1(&ctx, &session, &request())
    };
    let scope = RequestRootScope::new(handle.clone(), Uuid::new_v4());
    let ctx = scope.extension();
    let session = authority
        .verifier()
        .verify_and_bind(affected.credential(), now(), &ctx)
        .unwrap();
    for credential in [&affected, &shared, &unrelated] {
        assert_eq!(
            fresh(credential.credential()).decision,
            MemoryV1Decision::Allow
        );
    }
    assert_eq!(
        engine
            .evaluate_memory_v1(&ctx, &session, &request())
            .decision,
        MemoryV1Decision::Allow
    );
    assert!(clock_probe(&ctx, &session, || Some(now())).is_some());
    let fenced = || {
        handle
            .begin_request(Uuid::new_v4())
            .unwrap()
            .is_fenced(TARGET)
            .unwrap()
    };
    assert!(!fenced());
    let req = withdrawal_request(before);
    req.validate().unwrap();
    let writer = writer_for(&root);
    let mut owner = assembled_owner(&root);
    // A zero-byte existing journal is not reopenable. Seed the same deny-only
    // prefix in each history; it changes neither policy nor mutation sequence.
    const PREFIX: &str = "withdraw-control-prefix";
    assert_eq!(
        owner
            .prove_deny(live_deny_observation(&root, PREFIX))
            .unwrap(),
        DenyResponse::Forbidden
    );
    let prefix = std::fs::read(journal_path(&root)).unwrap();
    assert!(!prefix.is_empty());
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = std::sync::Mutex::new(release_rx);
    let pause = move || {
        ready_tx.send(()).unwrap();
        release_rx.lock().unwrap().recv_timeout(WAIT).unwrap();
    };
    // Called by the writer only: either after successful prepare, or immediately before CAS.
    let pause = Arc::new(pause);
    let commit_pause = Arc::clone(&pause);
    owner.set_before_append(move || commit_pause());
    let after = std::thread::scope(|threads| {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (sample_tx, sample_rx) = mpsc::channel();
        let (observed_tx, observed_rx) = mpsc::channel();
        let (closed_tx, closed_rx) = mpsc::channel();
        let (ctx, session) = (&ctx, &session);
        let reader = threads.spawn(move || {
            clock_probe(ctx, session, || {
                entered_tx.send(()).unwrap();
                sample_rx.recv_timeout(WAIT).unwrap();
                assert!(fenced());
                let tick = now();
                observed_tx.send(tick).unwrap();
                closed_rx.recv_timeout(WAIT).unwrap();
                assert!(!fenced());
                Some(tick)
            })
        });
        entered_rx.recv_timeout(WAIT).unwrap();
        let owner_ref = &owner;
        let change = threads.spawn(move || {
            if commit {
                let receipt = owner_ref.commit(req).unwrap();
                assert_eq!(receipt.operation_id, OPERATION);
                Some(receipt.root)
            } else {
                let (_, prepared) = writer.prepare(&req.root, &req.mutation).unwrap();
                pause();
                drop(prepared);
                None
            }
        });
        ready_rx.recv_timeout(WAIT).unwrap();
        assert!(fenced());
        assert_eq!(confirmation(&handle), ChangeConfirmationState::Active);
        assert_eq!(handle.metadata().unwrap(), before);
        assert_eq!(std::fs::read(journal_path(&root)).unwrap(), prefix);
        for credential in [&affected, &shared] {
            let result = fresh(credential.credential());
            assert_eq!(
                result.pending_source,
                Some(MemoryV1PendingSource::FenceActive)
            );
            assert_eq!(result.decision, MemoryV1Decision::Pending);
            assert!(result.admission.is_none());
        }
        assert_eq!(
            fresh(unrelated.credential()).decision,
            MemoryV1Decision::Allow
        );
        sample_tx.send(()).unwrap();
        let tick = observed_rx.recv_timeout(WAIT).unwrap();
        release_tx.send(()).unwrap();
        let published = change.join().unwrap();
        assert!(!fenced());
        closed_tx.send(()).unwrap();
        assert_eq!(
            reader.join().unwrap(),
            None,
            "an actual sample inside preparation cannot witness an admission"
        );
        eprintln!("withdraw_sample op={OPERATION} commit={commit} endpoints=closed,closed sample_tick={tick} fence_at_sample=open final_time=None fresh_open=FenceActive,FenceActive unrelated_open=Allow");
        let after = handle.metadata().unwrap();
        assert_eq!(published, commit.then_some(after));
        after
    });
    let held = engine.evaluate_memory_v1(&ctx, &session, &request());
    assert_eq!(held.decision, MemoryV1Decision::Pending);
    assert!(held.admission.is_none());
    assert_eq!(
        fresh(unrelated.credential()).decision,
        MemoryV1Decision::Allow
    );
    for credential in [&affected, &shared] {
        let result = fresh(credential.credential());
        if commit {
            assert_eq!(result.decision, MemoryV1Decision::Pending);
            assert_eq!(
                result.pending_source,
                Some(MemoryV1PendingSource::ContextInvalid)
            );
            assert!(result.admission.is_none());
        } else {
            assert_eq!(result.decision, MemoryV1Decision::Allow);
            assert!(result.admission.is_some());
        }
    }
    let state = confirmation(&handle);
    let reserved = root
        .owner
        .published_governance_record(&root.admission, &after)
        .unwrap();
    drop(owner);
    let (journal, _sync) = reopen_journal(&root);
    let records = journal.recovery_records();
    assert_eq!(records.len(), 1 + usize::from(commit));
    assert_eq!(records[0].operation_id, PREFIX);
    assert_eq!(records[0].kind, RecordKind::Deny);
    assert_eq!(
        (records[0].journal_sequence, records[0].mutation_sequence),
        (1, 0)
    );
    let journal_bytes = std::fs::read(journal_path(&root)).unwrap();
    eprintln!(
        "withdraw_journal op={OPERATION} commit={commit} raw_hex={}",
        hex::encode(&journal_bytes)
    );
    let suffix = journal_bytes.strip_prefix(prefix.as_slice()).unwrap();
    if commit {
        assert_eq!(state, ChangeConfirmationState::Withdrawn);
        assert_eq!(after.version, before.version + 1);
        assert_ne!(after.digest, before.digest);
        let reserved = reserved.unwrap();
        let frame = &records[1];
        assert_eq!(frame.kind, RecordKind::Mutation);
        assert_eq!(frame.operation_id, OPERATION);
        assert_eq!((frame.journal_sequence, frame.mutation_sequence), (2, 1));
        assert_eq!(reserved.message_id(), frame.message_id);
        assert_eq!(reserved.tail_hash(), frame.frame_hash);
        assert_eq!(reserved.frame(), suffix);
        let decoded = decode_journal_payload(&frame.payload).unwrap();
        assert_eq!(decoded.operation_id(), OPERATION);
        assert_eq!(frame.request_fingerprint, [0xab; 32]);
        assert!(
            matches!(decoded.mutation(), ManagementMutationV2::RuleSetChangeConfirmationRevoke { confirmation_id, revoked_at, revoked_by } if *confirmation_id == LAST && *revoked_at == TRUSTED_TIME && *revoked_by == ACTOR)
        );
        decoded
            .audit()
            .validate_governance_binding(
                OPERATION,
                &frame.request_fingerprint,
                before,
                ACTOR,
                LAST,
                TENANT,
                TRUSTED_TIME,
                decoded.mutation(),
            )
            .unwrap();
    } else {
        assert_eq!(state, ChangeConfirmationState::Active);
        assert_eq!(after, before);
        assert!(reserved.is_none());
        assert_eq!(std::fs::read(journal_path(&root)).unwrap(), prefix);
    }
    eprintln!("withdraw_result op={OPERATION} commit={commit} before={} after={} digest_before={} digest_after={} confirmation={state:?} held={:?} unrelated=Allow reopened_frames={}", before.version, after.version, hex::encode(before.digest), hex::encode(after.digest), held.decision, records.len());
}

#[test]
fn cancel_last_confirmation_with_a_sample_inside_preparation() {
    trace(false);
}

#[test]
fn commit_last_confirmation_with_a_sample_inside_preparation() {
    trace(true);
}
