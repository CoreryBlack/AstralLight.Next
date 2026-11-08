use super::*;

use std::borrow::Cow;
use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use astral_types::{
    AuthorityCommitBinding, AuthorityEligibilityCardCompletion,
    AuthorityEligibilityCompletionEvidence, AuthorityEligibilityCompletionReceipt,
    AuthorityEligibilityCompletionResponse, AuthorityEligibilityEmptySelectionCompleteness,
    AuthorityEligibilityEmptySelectionEvidence, AuthorityEligibilityEmptySelectionKind,
    AuthorityEligibilityEmptySelectionSelector, AuthorityEligibilityEmptySelectionSubjectKind,
    AuthorityMutationKind, AuthorityProtocolScope, AuthorityReadGate, AuthorityReservationCoverage,
    AuthorityReservationDisposition, AuthorityReservationState, AuthorityRetainedStagedEvidence,
    AuthorityScopeReservation, AuthoritySourceIntent, AuthorizationAuthorityScope,
    AuthorizationDomainScope, GlobalAuthorityFrontier, AUTHORIZATION_EDITION,
};

use crate::authority_config_source::TypedSourceReadError;
use crate::authority_publication::{IdentityPresence, IdentityStagedEvidence, IdentityTargetImage};

fn capture(
    card_id: i64,
    tenant_id: i64,
    generation: u64,
    revoke: u64,
) -> EligibilityCompletionCapture {
    EligibilityCompletionCapture {
        card_id,
        tenant_id: Some(tenant_id),
        generation,
        revoke_watermark: revoke,
        outbox_event_id: format!("evt-{card_id}-{generation}"),
        message_id: format!("evt-{card_id}-{generation}"),
    }
}

fn envelope_with(captures: &[EligibilityCompletionCapture]) -> AuthorityStagedSourceEvidence {
    build_eligibility_completion_envelope(
        captures,
        serde_json::json!({
            "targets": [{ "entity": "platform_user", "key": {"userId": 7},
                          "before": {"present": {"userId": 7, "status": "ACTIVE", "deletedAt": null}},
                          "after": {"present": {"userId": 7, "status": "DISABLED", "deletedAt": null}} }],
            "receipts": [{ "entity": "audit_log", "key": {"id": 1}, "kind": "INSERT",
                           "rowsAffected": 1, "durableId": "1" }],
            "fanout": { "affectedCards": [{"cardId": 7, "tenantId": 3}] },
        }),
    )
    .expect("valid captures build an envelope")
}

fn source_artifact(
    entity: &str,
    key: serde_json::Value,
    before: IdentityPresence,
    after: IdentityPresence,
    card_id: i64,
    tenant_id: i64,
) -> IdentityStagedEvidence {
    IdentityStagedEvidence {
        targets: vec![IdentityTargetImage {
            entity: entity.to_owned(),
            key,
            before,
            after,
        }],
        receipts: Vec::new(),
        fanout: serde_json::json!({
            "eligibilityEvents": if card_id > 0 { 1 } else { 0 },
            "affectedCards": if card_id > 0 {
                serde_json::json!([{"cardId": card_id, "tenantId": tenant_id}])
            } else {
                serde_json::json!([])
            },
        }),
        delta: None,
    }
}

#[test]
fn captured_source_receipt_requires_a_real_typed_row_transition() {
    let cases = [
        (
            EligibilitySourceSubject::UserStatus { user_id: 7 },
            "platform_user",
            "userId",
            "UPDATE",
            IdentityPresence::Present(
                serde_json::json!({"userId": 7, "status": "ACTIVE", "deletedAt": null}),
            ),
            IdentityPresence::Present(
                serde_json::json!({"userId": 7, "status": "DISABLED", "deletedAt": null}),
            ),
        ),
        (
            EligibilitySourceSubject::UserDelete { user_id: 7 },
            "platform_user",
            "userId",
            "UPDATE",
            IdentityPresence::Present(
                serde_json::json!({"userId": 7, "status": "ACTIVE", "deletedAt": null}),
            ),
            IdentityPresence::Present(
                serde_json::json!({"userId": 7, "status": "ACTIVE", "deletedAt": "2026-11-08 00:00:00"}),
            ),
        ),
        (
            EligibilitySourceSubject::TenantStatus { tenant_id: 7 },
            "tenant",
            "tenantId",
            "UPDATE",
            IdentityPresence::Present(serde_json::json!({"tenantId": 7, "status": "ACTIVE"})),
            IdentityPresence::Present(serde_json::json!({"tenantId": 7, "status": "DISABLED"})),
        ),
        (
            EligibilitySourceSubject::TenantDelete { tenant_id: 7 },
            "tenant",
            "tenantId",
            "DELETE",
            IdentityPresence::Present(serde_json::json!({"tenantId": 7, "status": "ACTIVE"})),
            IdentityPresence::Absent,
        ),
        (
            EligibilitySourceSubject::CardStatus { card_id: 7 },
            "user_card",
            "cardId",
            "UPDATE",
            IdentityPresence::Present(
                serde_json::json!({"cardId": 7, "tenantId": 3, "cardStatus": "ACTIVE"}),
            ),
            IdentityPresence::Present(
                serde_json::json!({"cardId": 7, "tenantId": 3, "cardStatus": "SUSPENDED"}),
            ),
        ),
        (
            EligibilitySourceSubject::CardCreate { card_id: 7 },
            "user_card",
            "cardId",
            "INSERT",
            IdentityPresence::Absent,
            IdentityPresence::Present(
                serde_json::json!({"cardId": 7, "tenantId": 3, "cardStatus": "ACTIVE"}),
            ),
        ),
    ];
    for (subject, entity, field, kind, before, after) in cases {
        let target = IdentityTargetImage {
            entity: entity.to_owned(),
            key: serde_json::json!({field: 7}),
            before,
            after,
        };
        let receipt = captured_source_receipt(subject, &target).expect("actual typed transition");
        assert_eq!(receipt.entity, entity);
        assert_eq!(receipt.key, target.key);
        assert_eq!(receipt.kind, kind);
        assert_eq!(receipt.durable_id, "7");
        assert_eq!(receipt.rows_affected, 1);

        let mut unchanged = target.clone();
        unchanged.after = unchanged.before.clone();
        assert!(captured_source_receipt(subject, &unchanged).is_err());
        let mut wrong_key = target.clone();
        wrong_key.key = serde_json::json!({field: 8});
        assert!(captured_source_receipt(subject, &wrong_key).is_err());
        let mut wrong_image = target.clone();
        if let IdentityPresence::Present(value) = &mut wrong_image.after {
            value[field] = serde_json::json!(8);
        } else if let IdentityPresence::Present(value) = &mut wrong_image.before {
            value[field] = serde_json::json!(8);
        }
        assert!(captured_source_receipt(subject, &wrong_image).is_err());
        let mut wrong_entity = target;
        wrong_entity.entity = "permission_rule".into();
        assert!(captured_source_receipt(subject, &wrong_entity).is_err());
    }
}

#[test]
fn captured_card_transition_rejects_tenant_drift_and_user_delete_rejects_absence() {
    let mut target = IdentityTargetImage {
        entity: "user_card".into(),
        key: serde_json::json!({"cardId": 7}),
        before: IdentityPresence::Present(
            serde_json::json!({"cardId": 7, "tenantId": 3, "cardStatus": "ACTIVE"}),
        ),
        after: IdentityPresence::Present(
            serde_json::json!({"cardId": 7, "tenantId": 4, "cardStatus": "SUSPENDED"}),
        ),
    };
    assert!(
        captured_source_receipt(EligibilitySourceSubject::CardStatus { card_id: 7 }, &target)
            .is_err()
    );
    target.entity = "platform_user".into();
    target.key = serde_json::json!({"userId": 7});
    target.before = IdentityPresence::Present(serde_json::json!({"userId": 7, "deletedAt": null}));
    target.after = IdentityPresence::Absent;
    assert!(
        captured_source_receipt(EligibilitySourceSubject::UserDelete { user_id: 7 }, &target)
            .is_err()
    );
}

fn zero_selection(
    subject_kind: AuthorityEligibilityEmptySelectionSubjectKind,
    subject_id: i64,
    tenant_id: Option<i64>,
) -> AuthorityEligibilityEmptySelectionEvidence {
    let kind = match subject_kind {
        AuthorityEligibilityEmptySelectionSubjectKind::UserStatus
        | AuthorityEligibilityEmptySelectionSubjectKind::UserDelete => {
            AuthorityEligibilityEmptySelectionKind::ActiveCardsByUserV1
        }
        AuthorityEligibilityEmptySelectionSubjectKind::TenantStatus
        | AuthorityEligibilityEmptySelectionSubjectKind::TenantDelete => {
            AuthorityEligibilityEmptySelectionKind::ActiveCardsByTenantV1
        }
    };
    let mut selection = AuthorityEligibilityEmptySelectionEvidence {
        subject_kind,
        subject_id,
        tenant_id,
        schema_version: 1,
        selector: AuthorityEligibilityEmptySelectionSelector {
            kind,
            version: 1,
            completeness: AuthorityEligibilityEmptySelectionCompleteness::ExactFullFanout,
        },
        selected_count: 0,
        source_before_image_digest: "aa".repeat(32),
        source_after_image_digest: "bb".repeat(32),
        selection_digest: String::new(),
    };
    selection.selection_digest = selection
        .recompute_selection_digest()
        .expect("zero-selection digest computes");
    selection
}

fn zero_completion(
    subject_kind: AuthorityEligibilityEmptySelectionSubjectKind,
    subject_id: i64,
    tenant_id: Option<i64>,
) -> AuthorityEligibilityCompletionEvidence {
    AuthorityEligibilityCompletionEvidence {
        cards: Vec::new(),
        zero_card_selection: Some(zero_selection(subject_kind, subject_id, tenant_id)),
    }
}

fn canonical_card_scope(tenant_id: i64, card_id: i64) -> AuthorityProtocolScope {
    AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
        tenant_id,
        card_id,
        user_id: None,
        domain: AuthorizationDomainScope::Any,
    })
}

fn completion_for_terminal() -> AuthorityEligibilityCompletionEvidence {
    AuthorityEligibilityCompletionEvidence {
        cards: vec![AuthorityEligibilityCardCompletion {
            scope: canonical_card_scope(3, 7),
            generation: 5,
            revoke_watermark: 2,
            outbox_event_id: "evt-7-5".to_owned(),
            message_id: "evt-7-5".to_owned(),
        }],
        zero_card_selection: None,
    }
}

fn binding_for_terminal(
    completion: &AuthorityEligibilityCompletionEvidence,
) -> AuthorityCommitBinding {
    let retained = serde_json::to_string(
        &completion
            .to_staged_envelope(serde_json::json!({"targets": [], "receipts": [], "fanout": {}}))
            .expect("terminal staged envelope"),
    )
    .expect("terminal staged envelope encodes");
    AuthorityCommitBinding {
        reservation_id: "res-1".to_owned(),
        operation_id: "op-1".to_owned(),
        event_id: "event-1".to_owned(),
        admission_proof_id: "proof-1".to_owned(),
        mutation_kind: AuthorityMutationKind::AuthorizationSource,
        service_id: "identity".to_owned(),
        database_id: "db-1".to_owned(),
        request_digest: "11".repeat(32),
        source_commit_digest: "22".repeat(32),
        before_image_digest: Some("33".repeat(32)),
        after_image_digest: "44".repeat(32),
        source_outcome_digest: "55".repeat(32),
        staged_evidence_digest: eligibility_retained_staged_evidence_digest(&retained)
            .expect("retained digest"),
    }
}

fn terminal_for(
    binding: &AuthorityCommitBinding,
    completion: &AuthorityEligibilityCompletionEvidence,
) -> AuthorityEligibilityCompletionTerminal {
    let intent = AuthoritySourceIntent {
        authorization_edition: AUTHORIZATION_EDITION,
        mutation_kind: AuthorityMutationKind::AuthorizationSource,
        operation_id: binding.operation_id.clone(),
        event_id: binding.event_id.clone(),
        admission_proof_id: binding.admission_proof_id.clone(),
        request_digest: binding.request_digest.clone(),
        service_id: binding.service_id.clone(),
        database_id: binding.database_id.clone(),
        coverage: AuthorityReservationCoverage::Global,
        before_image_digest: binding.before_image_digest.clone(),
        lease_not_before: 1_000,
        lease_expires_at: 2_000,
        intent_nonce: "intent-1".to_owned(),
    };
    let intent_digest = intent.digest().expect("intent digest");
    let frontier = GlobalAuthorityFrontier {
        authorization_edition: AUTHORIZATION_EDITION,
        authority_id: "authority-1".to_owned(),
        authority_term: 1,
        global_fence_sequence: 2,
        key_id: "key-1".to_owned(),
        key_epoch: 1,
        root_id: "root-1".to_owned(),
        trust_root_digest: "66".repeat(32),
        global_chain_digest: "77".repeat(32),
        updated_at: 1_500,
    };
    let reservation = AuthorityScopeReservation {
        reservation_id: binding.reservation_id.clone(),
        intent_digest,
        intent,
        state: AuthorityReservationState::Completed,
        authority_term: 1,
        fence_sequence_at_prepare: 1,
        created_at: 1_000,
        updated_at: 1_500,
        committed_at: Some(1_200),
        source_commit_digest: Some(binding.source_commit_digest.clone()),
        after_image_digest: Some(binding.after_image_digest.clone()),
        certificate_id: None,
        certified_scopes: Vec::new(),
        source_outcome_digest: Some(binding.source_outcome_digest.clone()),
    };
    let receipt = AuthorityEligibilityCompletionReceipt {
        receipt_id: "receipt-1".to_owned(),
        reservation_id: binding.reservation_id.clone(),
        operation_id: binding.operation_id.clone(),
        event_id: binding.event_id.clone(),
        binding: binding.clone(),
        completion: completion.clone(),
        completed_at: 1_500,
        global_frontier: frontier.clone(),
    };
    AuthorityEligibilityCompletionResponse {
        disposition: AuthorityReservationDisposition::Completed,
        reservation,
        receipt,
        global_frontier: frontier,
        read_gate: AuthorityReadGate {
            positive_reads_allowed: true,
            global_pending: false,
            blocking_reservations: Vec::new(),
        },
    }
}

#[test]
fn envelope_shape_is_exact_and_refuses_deviations() {
    let envelope = envelope_with(&[capture(7, 3, 5, 2)]);
    assert_eq!(envelope.evidence["kind"], "ELIGIBILITY_COMPLETION");
    assert_eq!(envelope.coverage, None);
    let completion = AuthorityEligibilityCompletionEvidence::from_staged_envelope(&envelope)
        .expect("typed completion parses");
    assert_eq!(completion.cards.len(), 1);
    assert_eq!(
        completion.cards[0].scope,
        AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
            tenant_id: 3,
            card_id: 7,
            user_id: None,
            domain: AuthorizationDomainScope::Any,
        })
    );
    assert_eq!(completion.cards[0].generation, 5);

    let raw = serde_json::to_value(&envelope).unwrap();
    let mut tampered = raw.clone();
    tampered["extra"] = serde_json::json!(1);
    assert!(serde_json::from_value::<AuthorityStagedSourceEvidence>(tampered).is_err());

    let mut wrong_kind = raw.clone();
    wrong_kind["evidence"]["kind"] = serde_json::json!("GRANT_PUBLICATION");
    let wrong_kind: AuthorityStagedSourceEvidence = serde_json::from_value(wrong_kind).unwrap();
    assert!(AuthorityEligibilityCompletionEvidence::from_staged_envelope(&wrong_kind).is_err());

    let mut lensed = raw.clone();
    lensed["evidence"]["completion"]["cards"][0]["scope"]["userId"] = serde_json::json!(5);
    let parsed: AuthorityStagedSourceEvidence = serde_json::from_value(lensed).unwrap();
    assert!(AuthorityEligibilityCompletionEvidence::from_staged_envelope(&parsed).is_err());

    let mut zero = raw;
    zero["evidence"]["completion"]["cards"][0]["generation"] = serde_json::json!(0);
    let parsed: AuthorityStagedSourceEvidence = serde_json::from_value(zero).unwrap();
    assert!(AuthorityEligibilityCompletionEvidence::from_staged_envelope(&parsed).is_err());
}

#[test]
fn staging_builder_refuses_capacity_and_invalid_captures() {
    let many: Vec<EligibilityCompletionCapture> = (1..=ELIGIBILITY_COMPLETION_MAX_CARDS + 1)
        .map(|card_id| capture(card_id as i64, 3, 1, 0))
        .collect();
    assert_eq!(
        build_eligibility_completion_evidence(&many),
        Err(EligibilityCompletionStagingError::CapacityExceeded)
    );
    let no_tenant = EligibilityCompletionCapture {
        card_id: 7,
        tenant_id: None,
        generation: 1,
        revoke_watermark: 0,
        outbox_event_id: "evt".into(),
        message_id: "evt".into(),
    };
    assert!(matches!(
        build_eligibility_completion_evidence(&[no_tenant]),
        Err(EligibilityCompletionStagingError::Invalid(_))
    ));
    assert!(matches!(
        build_eligibility_completion_evidence(&[capture(7, 3, 0, 0)]),
        Err(EligibilityCompletionStagingError::Invalid(_))
    ));
    assert!(matches!(
        build_eligibility_completion_evidence(&[]),
        Err(EligibilityCompletionStagingError::Invalid(_))
    ));
}

#[test]
fn evidence_is_canonically_sorted_and_unique() {
    let mut captures = vec![capture(9, 3, 2, 1), capture(7, 3, 4, 0)];
    captures.reverse();
    let evidence = build_eligibility_completion_evidence(&captures).expect("valid set");
    let keys: Vec<String> = evidence
        .cards
        .iter()
        .map(|card| card.scope.store_key_text().unwrap())
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted);
    let mut duplicated = evidence.clone();
    duplicated.cards.push(duplicated.cards[0].clone());
    assert!(duplicated.validate().is_err());
}

#[test]
fn retained_digest_matches_the_shared_staged_digest_algorithm() {
    let envelope = envelope_with(&[capture(7, 3, 5, 2)]);
    let inserted = serde_json::to_string(&envelope).unwrap();
    let reformatted = {
        let value: serde_json::Value = serde_json::from_str(&inserted).unwrap();
        serde_json::to_string_pretty(&value).unwrap()
    };
    assert_ne!(inserted, reformatted);
    assert_eq!(
        eligibility_retained_staged_evidence_digest(&inserted).unwrap(),
        eligibility_retained_staged_evidence_digest(&reformatted).unwrap()
    );
    assert_eq!(
        eligibility_retained_staged_evidence_digest(&inserted).unwrap(),
        eligibility_retained_staged_evidence_digest(&inserted).unwrap()
    );
}

#[test]
fn wrapper_parse_refuses_coverage_and_malformed_envelopes() {
    let envelope = envelope_with(&[capture(7, 3, 5, 2)]);
    let wrapped = serde_json::json!({
        "coverage": null,
        "evidence": envelope.evidence.clone(),
    });
    let parsed = parse_eligibility_envelope(&wrapped.to_string()).expect("valid wrapper");
    assert_eq!(parsed.0, envelope);
    let with_coverage = serde_json::json!({
        "coverage": { "scopes": [] },
        "evidence": envelope.evidence.clone(),
    });
    assert!(parse_eligibility_envelope(&with_coverage.to_string()).is_err());
    assert!(
        parse_eligibility_envelope(&serde_json::json!({"coverage": null}).to_string()).is_err()
    );
}

#[test]
fn operation_whitelist_accepts_only_true_eligibility_paths() {
    let user_artifact = source_artifact(
        "platform_user",
        serde_json::json!({"userId": 7}),
        IdentityPresence::Present(
            serde_json::json!({"userId": 7, "status": "ACTIVE", "deletedAt": null}),
        ),
        IdentityPresence::Present(
            serde_json::json!({"userId": 7, "status": "DISABLED", "deletedAt": null}),
        ),
        7,
        3,
    );
    let user_completion = build_eligibility_completion_evidence(&[capture(7, 3, 5, 2)]).unwrap();
    assert_eq!(
        classify_eligibility_source_operation(&user_artifact, &user_completion),
        Some(EligibilitySourceOperation::UserStatus)
    );

    let user_delete_artifact = source_artifact(
        "platform_user",
        serde_json::json!({"userId": 7}),
        IdentityPresence::Present(
            serde_json::json!({"userId": 7, "status": "ACTIVE", "deletedAt": null}),
        ),
        IdentityPresence::Present(serde_json::json!({"userId": 7, "deletedAt": "2026-11-08"})),
        -1,
        0,
    );
    assert_eq!(
        classify_eligibility_source_operation(
            &user_delete_artifact,
            &zero_completion(
                AuthorityEligibilityEmptySelectionSubjectKind::UserDelete,
                7,
                None,
            ),
        ),
        Some(EligibilitySourceOperation::UserDelete)
    );

    let tenant_artifact = source_artifact(
        "tenant",
        serde_json::json!({"tenantId": 3}),
        IdentityPresence::Present(serde_json::json!({"tenantId": 3, "status": "ACTIVE"})),
        IdentityPresence::Present(serde_json::json!({"tenantId": 3, "status": "DISABLED"})),
        7,
        3,
    );
    assert_eq!(
        classify_eligibility_source_operation(&tenant_artifact, &user_completion),
        Some(EligibilitySourceOperation::TenantStatus)
    );
    let tenant_delete_artifact = source_artifact(
        "tenant",
        serde_json::json!({"tenantId": 3}),
        IdentityPresence::Present(serde_json::json!({"tenantId": 3, "status": "ACTIVE"})),
        IdentityPresence::Absent,
        -1,
        0,
    );
    assert_eq!(
        classify_eligibility_source_operation(
            &tenant_delete_artifact,
            &zero_completion(
                AuthorityEligibilityEmptySelectionSubjectKind::TenantDelete,
                3,
                Some(3),
            ),
        ),
        Some(EligibilitySourceOperation::TenantDelete)
    );

    let card_status_artifact = source_artifact(
        "user_card",
        serde_json::json!({"cardId": 7}),
        IdentityPresence::Present(
            serde_json::json!({"cardId": 7, "tenantId": 3, "cardStatus": "ACTIVE"}),
        ),
        IdentityPresence::Present(
            serde_json::json!({"cardId": 7, "tenantId": 3, "cardStatus": "DISABLED"}),
        ),
        7,
        3,
    );
    assert_eq!(
        classify_eligibility_source_operation(&card_status_artifact, &user_completion),
        Some(EligibilitySourceOperation::CardStatus)
    );

    let card_create_artifact = source_artifact(
        "user_card",
        serde_json::json!({"cardId": 7}),
        IdentityPresence::Absent,
        IdentityPresence::Present(
            serde_json::json!({"cardId": 7, "tenantId": 3, "cardStatus": "ACTIVE"}),
        ),
        7,
        3,
    );
    assert_eq!(
        classify_eligibility_source_operation(&card_create_artifact, &user_completion),
        Some(EligibilitySourceOperation::CardCreate)
    );

    let config_artifact = source_artifact(
        "permission_rule",
        serde_json::json!({"id": 1}),
        IdentityPresence::Present(serde_json::json!({"id": 1})),
        IdentityPresence::Present(serde_json::json!({"id": 1, "status": "ACTIVE"})),
        7,
        3,
    );
    assert_eq!(
        classify_eligibility_source_operation(&config_artifact, &user_completion),
        None
    );
}

struct FixtureGateway {
    terminal: AuthorityEligibilityCompletionTerminal,
    binding: AuthorityCommitBinding,
    completion: AuthorityEligibilityCompletionEvidence,
    retained: AuthorityRetainedStagedEvidence,
}

impl FixtureGateway {
    fn assert_request(
        &self,
        binding: &AuthorityCommitBinding,
        completion: &AuthorityEligibilityCompletionEvidence,
        retained: &AuthorityRetainedStagedEvidence,
    ) {
        assert_eq!(binding, &self.binding);
        assert_eq!(completion, &self.completion);
        assert_eq!(retained, &self.retained);
    }
}

#[async_trait::async_trait]
impl EligibilityCompletionGateway for FixtureGateway {
    async fn complete_eligibility(
        &self,
        binding: AuthorityCommitBinding,
        completion: AuthorityEligibilityCompletionEvidence,
        retained: AuthorityRetainedStagedEvidence,
    ) -> Result<AuthorityEligibilityCompletionTerminal, astral_authority::AuthorityClientError>
    {
        self.assert_request(&binding, &completion, &retained);
        Ok(self.terminal.clone())
    }

    async fn reconcile_eligibility(
        &self,
        binding: AuthorityCommitBinding,
        completion: AuthorityEligibilityCompletionEvidence,
        retained: AuthorityRetainedStagedEvidence,
    ) -> Result<
        Option<AuthorityEligibilityCompletionTerminal>,
        astral_authority::AuthorityClientError,
    > {
        self.assert_request(&binding, &completion, &retained);
        Ok(Some(self.terminal.clone()))
    }
}

#[tokio::test]
async fn gateway_contract_uses_the_full_binding_completion_and_retained_evidence() {
    let completion = completion_for_terminal();
    let binding = binding_for_terminal(&completion);
    let terminal = terminal_for(&binding, &completion);
    let retained = AuthorityRetainedStagedEvidence::new(
        serde_json::to_string(&envelope_with(&[capture(7, 3, 5, 2)])).unwrap(),
    );
    let gateway = FixtureGateway {
        terminal,
        binding: binding.clone(),
        completion: completion.clone(),
        retained: retained.clone(),
    };
    assert!(gateway
        .complete_eligibility(binding.clone(), completion.clone(), retained.clone())
        .await
        .is_ok());
    assert!(gateway
        .reconcile_eligibility(binding, completion, retained)
        .await
        .unwrap()
        .is_some());
}

#[test]
fn completion_outcome_keeps_unknown_pending_and_reconciles_conflicts() {
    let completion = completion_for_terminal();
    let binding = binding_for_terminal(&completion);
    let terminal = terminal_for(&binding, &completion);
    assert_eq!(
        completion_outcome_decision(&Ok(terminal)),
        CompletionOutcomeDecision::MarkCompleted
    );
    let conflict = Err(astral_authority::AuthorityClientError::Rejected {
        code: "StateConflict".into(),
        message: "already progressed".into(),
    });
    assert_eq!(
        completion_outcome_decision(&conflict),
        CompletionOutcomeDecision::ReconcileByStableIdentity
    );
    let binding_error = Err(astral_authority::AuthorityClientError::Rejected {
        code: "DigestMismatch".into(),
        message: "binding".into(),
    });
    assert!(matches!(
        completion_outcome_decision(&binding_error),
        CompletionOutcomeDecision::Quarantine(_)
    ));
    let unknown = Err(astral_authority::AuthorityClientError::UnknownOutcome {
        operation_hint: "op-1".into(),
    });
    assert_eq!(
        completion_outcome_decision(&unknown),
        CompletionOutcomeDecision::StayPending
    );
}

#[test]
fn terminal_must_match_the_exact_request() {
    let completion = completion_for_terminal();
    let binding = binding_for_terminal(&completion);
    let terminal = terminal_for(&binding, &completion);
    assert!(terminal_matches_request(&terminal, &binding, &completion));

    let mut foreign_binding = binding.clone();
    foreign_binding.reservation_id = "res-2".into();
    assert!(!terminal_matches_request(
        &terminal,
        &foreign_binding,
        &completion
    ));
    let mut foreign_completion = completion.clone();
    foreign_completion.cards[0].generation += 1;
    assert!(!terminal_matches_request(
        &terminal,
        &binding,
        &foreign_completion
    ));
    let mut foreign_terminal = terminal.clone();
    foreign_terminal.receipt.operation_id = "op-2".into();
    assert!(!terminal_matches_request(
        &foreign_terminal,
        &binding,
        &completion
    ));
}

#[test]
fn completion_audit_binds_request_and_response() {
    let completion = completion_for_terminal();
    let binding = binding_for_terminal(&completion);
    let terminal = terminal_for(&binding, &completion);
    let audit = completion_audit_json(&terminal, "retained-digest");
    assert!(audit.len() < 4096, "the audit must stay bounded");
    let parsed: serde_json::Value = serde_json::from_str(&audit).unwrap();
    assert_eq!(parsed["request"]["reservationId"], "res-1");
    assert_eq!(parsed["request"]["operationId"], "op-1");
    assert_eq!(
        parsed["request"]["retainedStagedEvidenceDigest"],
        "retained-digest"
    );
    assert_eq!(parsed["response"]["disposition"], "COMPLETED");
    assert_eq!(parsed["response"]["receipt"]["operationId"], "op-1");
}

#[test]
fn config_bounds_stay_bounded() {
    let mut config = EligibilityCompletionReconcilerConfig::default();
    assert!(config.validate().is_err());
    config.owned = AuthoritySourceOwnerEntry {
        service_id: "identity".into(),
        database_ids: vec!["db-1".into()],
    };
    config.run_instance_id = "run-1".into();
    assert!(config.validate().is_ok());
    config.batch_size = 9;
    assert!(config.validate().is_err());
    config.batch_size = 1;
    config.lease_seconds = 4;
    assert!(config.validate().is_err());
    config.lease_seconds = 30;
    config.max_attempts = 0;
    assert!(config.validate().is_err());
}

fn valid_card_create_spec() -> CardCreateInsertSpec {
    CardCreateInsertSpec {
        user_id: 101,
        tenant_id: 3,
        domain_id: Some(9),
        card_type: "STANDARD".to_owned(),
        template_id: Some(11),
        level_id: Some(12),
        priority: 4,
        is_primary: true,
    }
}

#[derive(Debug, Clone)]
struct CreatedCardImageFixture {
    card_id: i64,
    card_status: String,
    user_id: Option<i64>,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
    template_id: Option<i64>,
    card_type: String,
    level_id: Option<i64>,
    priority: i32,
    is_primary: bool,
    valid_from: Option<String>,
    valid_until: Option<String>,
}

impl CreatedCardImageFixture {
    fn to_target(&self) -> IdentityTargetImage {
        IdentityTargetImage {
            entity: "user_card".to_owned(),
            key: serde_json::json!({"cardId": self.card_id}),
            before: IdentityPresence::Absent,
            after: IdentityPresence::Present(serde_json::json!({
                "cardId": self.card_id,
                "cardStatus": self.card_status,
                "userId": self.user_id,
                "tenantId": self.tenant_id,
                "domainId": self.domain_id,
                "templateId": self.template_id,
                "cardType": self.card_type,
                "levelId": self.level_id,
                "priority": self.priority,
                "isPrimary": self.is_primary,
                "validFrom": self.valid_from,
                "validUntil": self.valid_until,
            })),
        }
    }
}

fn card_image_for(spec: &CardCreateInsertSpec, card_id: i64) -> CreatedCardImageFixture {
    CreatedCardImageFixture {
        card_id,
        card_status: "ACTIVE".to_owned(),
        user_id: Some(spec.user_id),
        tenant_id: Some(spec.tenant_id),
        domain_id: spec.domain_id,
        template_id: spec.template_id,
        card_type: spec.card_type.clone(),
        level_id: spec.level_id,
        priority: spec.priority,
        is_primary: spec.is_primary,
        valid_from: None,
        valid_until: None,
    }
}

fn target_for_image(image: &CreatedCardImageFixture) -> IdentityTargetImage {
    image.to_target()
}

#[test]
fn card_create_spec_validates_each_identity_and_canonical_field() {
    let valid = valid_card_create_spec();
    assert!(valid.validate().is_ok());

    for invalid in [
        CardCreateInsertSpec {
            user_id: 0,
            ..valid.clone()
        },
        CardCreateInsertSpec {
            tenant_id: 0,
            ..valid.clone()
        },
        CardCreateInsertSpec {
            domain_id: Some(0),
            ..valid.clone()
        },
        CardCreateInsertSpec {
            template_id: Some(0),
            ..valid.clone()
        },
        CardCreateInsertSpec {
            level_id: Some(0),
            ..valid.clone()
        },
        CardCreateInsertSpec {
            card_type: String::new(),
            ..valid.clone()
        },
        CardCreateInsertSpec {
            card_type: "lowercase".into(),
            ..valid.clone()
        },
        CardCreateInsertSpec {
            card_type: "HAS-HYPHEN".into(),
            ..valid.clone()
        },
        CardCreateInsertSpec {
            card_type: "CARD2".into(),
            ..valid.clone()
        },
        CardCreateInsertSpec {
            card_type: "X".repeat(33),
            ..valid.clone()
        },
    ] {
        assert!(
            invalid.validate().is_err(),
            "invalid spec must be refused: {invalid:?}"
        );
    }

    assert!(CardCreateInsertSpec {
        domain_id: None,
        ..valid
    }
    .validate()
    .is_ok());
}

#[test]
fn card_create_image_rejects_every_insert_fact_tamper() {
    let spec = valid_card_create_spec();
    let image = card_image_for(&spec, 501);
    let target = target_for_image(&image);
    assert!(validate_created_card_image(&target, 501, &spec).is_ok());

    let mut tampered = image.clone();
    tampered.card_id += 1;
    assert!(validate_created_card_image(&target_for_image(&tampered), 501, &spec).is_err());
    for tamper in [
        {
            let mut value = image.clone();
            value.card_status = "DISABLED".into();
            value
        },
        {
            let mut value = image.clone();
            value.user_id = Some(102);
            value
        },
        {
            let mut value = image.clone();
            value.tenant_id = Some(4);
            value
        },
        {
            let mut value = image.clone();
            value.domain_id = Some(10);
            value
        },
        {
            let mut value = image.clone();
            value.template_id = Some(13);
            value
        },
        {
            let mut value = image.clone();
            value.card_type = "ELEVATED".into();
            value
        },
        {
            let mut value = image.clone();
            value.level_id = Some(14);
            value
        },
        {
            let mut value = image.clone();
            value.priority = 5;
            value
        },
        {
            let mut value = image.clone();
            value.is_primary = false;
            value
        },
        {
            let mut value = image.clone();
            value.valid_from = Some("2026-11-08".into());
            value
        },
        {
            let mut value = image.clone();
            value.valid_until = Some("2027-11-08".into());
            value
        },
    ] {
        assert!(
            validate_created_card_image(&target_for_image(&tamper), 501, &spec).is_err(),
            "tampered created-card image must be refused: {tamper:?}"
        );
    }

    let mut wrong_key = target.clone();
    wrong_key.key = serde_json::json!({"cardId": 502});
    assert!(validate_created_card_image(&wrong_key, 501, &spec).is_err());
    let mut wrong_entity = target.clone();
    wrong_entity.entity = "platform_user".into();
    assert!(validate_created_card_image(&wrong_entity, 501, &spec).is_err());
    let mut wrong_before = target.clone();
    wrong_before.before = IdentityPresence::Present(serde_json::json!({"cardId": 501}));
    assert!(validate_created_card_image(&wrong_before, 501, &spec).is_err());
}

#[test]
fn card_create_image_matches_distinct_owners_with_exact_tenant_and_domain() {
    let first = valid_card_create_spec();
    let second = CardCreateInsertSpec {
        user_id: 202,
        ..first.clone()
    };
    assert!(validate_created_card_image(
        &target_for_image(&card_image_for(&first, 601)),
        601,
        &first
    )
    .is_ok());
    assert!(validate_created_card_image(
        &target_for_image(&card_image_for(&second, 602)),
        602,
        &second
    )
    .is_ok());

    let mut wrong_tenant = card_image_for(&first, 601);
    wrong_tenant.tenant_id = Some(4);
    assert!(validate_created_card_image(&target_for_image(&wrong_tenant), 601, &first).is_err());
    let mut wrong_domain = card_image_for(&first, 601);
    wrong_domain.domain_id = Some(10);
    assert!(validate_created_card_image(&target_for_image(&wrong_domain), 601, &first).is_err());

    let no_domain = CardCreateInsertSpec {
        domain_id: None,
        ..first
    };
    assert!(validate_created_card_image(
        &target_for_image(&card_image_for(&no_domain, 603)),
        603,
        &no_domain
    )
    .is_ok());
}

fn card_create_admission_proof() -> astral_types::AuthorizationFenceProof {
    astral_types::AuthorizationFenceProof {
        authorization_edition: AUTHORIZATION_EDITION,
        authority_id: "authority-test".into(),
        authority_term: 1,
        global_fence_sequence: 2,
        scope: AuthorizationAuthorityScope {
            tenant_id: 3,
            card_id: 4,
            user_id: Some(5),
            domain: AuthorizationDomainScope::Exact(9),
        },
        scope_generation: 1,
        revoke_watermark: 0,
        snapshot_hash: "11".repeat(32),
        parent_hash: None,
        operation_id: "card-create-operation".into(),
        event_id: "card-create-event".into(),
        key_id: "key-test".into(),
        key_epoch: 1,
        issued_at: 100,
        not_before: 100,
        expires_at: 160,
        request_nonce: "nonce-test".into(),
        request_binding_digest: Some("33".repeat(32)),
        scope_certificate_hash: Some("44".repeat(32)),
        proof_id: "proof-test".into(),
        signature: "22".repeat(64),
    }
}

#[test]
fn card_create_admission_allows_a_distinct_target_owner_with_exact_scope() {
    let spec = valid_card_create_spec();
    let proof = card_create_admission_proof();
    assert_ne!(proof.scope.user_id, Some(spec.user_id));
    let admission = AuthorizationAdmission::from_verified_proof(proof.clone()).unwrap();
    assert!(validate_card_create_admission(&admission, &spec).is_ok());
    let other_owner = CardCreateInsertSpec {
        user_id: 202,
        ..spec.clone()
    };
    assert!(validate_card_create_admission(&admission, &other_owner).is_ok());

    let mut no_domain_proof = proof;
    no_domain_proof.scope.domain = AuthorizationDomainScope::NoDomain;
    let no_domain = AuthorizationAdmission::from_verified_proof(no_domain_proof).unwrap();
    let no_domain_spec = CardCreateInsertSpec {
        domain_id: None,
        ..spec
    };
    assert!(validate_card_create_admission(&no_domain, &no_domain_spec).is_ok());
}

#[test]
fn card_create_admission_rejects_unbound_or_inexact_scope() {
    let spec = valid_card_create_spec();
    let original = card_create_admission_proof();
    let mut alternatives = vec![original.clone(); 5];
    alternatives[0].scope.tenant_id += 1;
    alternatives[1].scope.domain = AuthorizationDomainScope::Exact(10);
    alternatives[2].scope.domain = AuthorizationDomainScope::Any;
    alternatives[3].scope.domain = AuthorizationDomainScope::NoDomain;
    alternatives[4].request_binding_digest = None;
    for proof in alternatives {
        let admission = AuthorizationAdmission::from_verified_proof(proof).unwrap();
        assert!(validate_card_create_admission(&admission, &spec).is_err());
    }
    let mut no_actor_proof = original;
    no_actor_proof.scope.user_id = None;
    let no_actor = AuthorizationAdmission::from_verified_proof(no_actor_proof).unwrap();
    assert!(validate_card_create_admission(&no_actor, &spec).is_err());
}

#[test]
fn publication_origin_receipt_cannot_become_independent_eligibility_completion() {
    let spec = valid_card_create_spec();
    let image = card_image_for(&spec, 701);
    let receipt = EligibilitySourceEvidenceReceipt {
        completion: build_eligibility_completion_evidence(&[capture(701, 3, 1, 0)]).unwrap(),
        source_evidence: serde_json::json!({"targets": [], "receipts": [], "fanout": {}}),
        source_target: target_for_image(&image),
        source_receipts: Vec::new(),
        before_image_digest: "aa".repeat(32),
        after_image_digest: "bb".repeat(32),
        operation: EligibilitySourceOperation::CardCreate,
        publication_origin: true,
        card_rebind: None,
    };
    let error = receipt
        .into_staged_envelope()
        .expect_err("publication-origin receipt must stay out of eligibility completion");
    assert!(error.to_string().contains("publication card origin"));
}

#[derive(Debug)]
struct UnknownDatabaseError;

impl fmt::Display for UnknownDatabaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown database failure")
    }
}

impl StdError for UnknownDatabaseError {}

impl sqlx::error::DatabaseError for UnknownDatabaseError {
    fn message(&self) -> &str {
        "unknown database failure"
    }

    fn code(&self) -> Option<Cow<'_, str>> {
        Some(Cow::Borrowed("ZZ999"))
    }

    fn as_error(&self) -> &(dyn StdError + Send + Sync + 'static) {
        self
    }

    fn as_error_mut(&mut self) -> &mut (dyn StdError + Send + Sync + 'static) {
        self
    }

    fn into_error(self: Box<Self>) -> Box<dyn StdError + Send + Sync + 'static> {
        self
    }

    fn kind(&self) -> sqlx::error::ErrorKind {
        sqlx::error::ErrorKind::Other
    }
}

#[test]
fn sqlx_transient_allowlist_classifies_only_explicit_retryable_variants() {
    let errors = [
        sqlx::Error::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, "io")),
        sqlx::Error::Tls(Box::new(UnknownDatabaseError)),
        sqlx::Error::PoolTimedOut,
        sqlx::Error::PoolClosed,
        sqlx::Error::WorkerCrashed,
    ];
    for error in errors {
        assert!(matches!(
            TypedSourceReadError::from_sqlx("allowlist", error),
            TypedSourceReadError::SqlxTransient {
                context: "allowlist",
                ..
            }
        ));
    }
}

#[test]
fn sqlx_schema_and_protocol_errors_are_not_transient_and_retain_sources() {
    let protocol =
        TypedSourceReadError::from_sqlx("protocol", sqlx::Error::Protocol("bad packet".into()));
    match protocol {
        TypedSourceReadError::SqlxSchema { context, source } => {
            assert_eq!(context, "protocol");
            assert!(matches!(source, sqlx::Error::Protocol(_)));
        }
        other => panic!("protocol error was misclassified: {other:?}"),
    }

    for error in [
        sqlx::Error::Configuration(Box::new(UnknownDatabaseError)),
        sqlx::Error::RowNotFound,
        sqlx::Error::Decode(Box::new(UnknownDatabaseError)),
        sqlx::Error::Database(Box::new(UnknownDatabaseError)),
    ] {
        assert!(matches!(
            TypedSourceReadError::from_sqlx("schema", error),
            TypedSourceReadError::SqlxSchema {
                context: "schema",
                ..
            }
        ));
    }
}

#[test]
fn sqlx_classification_preserves_original_error_text() {
    let error = sqlx::Error::Io(std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "connection reset by peer",
    ));
    match TypedSourceReadError::from_sqlx("preserve", error) {
        TypedSourceReadError::SqlxTransient { source, .. } => {
            assert!(source.to_string().contains("connection reset by peer"));
        }
        other => panic!("expected transient IO error, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires isolated MySQL, real production owner data, and a real mTLS authority endpoint"]
async fn live_eligibility_completion_closes_a_real_production_owner_row() {
    let required = std::env::var("RUST_INTEGRATION_REQUIRED").as_deref() == Ok("1");
    let required_env = |name: &str| -> Option<String> {
        match std::env::var(name) {
            Ok(value) if !value.is_empty() => Some(value),
            _ => None,
        }
    };
    let Some(database_url) = required_env("ASTRAL_ELIGIBILITY_COMPLETION_TEST_MYSQL_URL") else {
        assert!(
            !required,
            "isolated eligibility MySQL dependency is missing"
        );
        eprintln!("[INCOMPLETE] isolated eligibility MySQL dependency is missing");
        return;
    };
    let Some(authority_url) = required_env("ASTRAL_AUTHORITY_BASE_URL") else {
        assert!(!required, "real authority endpoint is missing");
        eprintln!("[INCOMPLETE] real authority endpoint is missing; no stub is accepted");
        return;
    };
    let Some(ca_path) = required_env("ASTRAL_AUTHORITY_CA_PEM_PATH") else {
        assert!(!required, "authority CA path is missing");
        eprintln!("[INCOMPLETE] authority CA path is missing");
        return;
    };
    let Some(identity_path) = required_env("ASTRAL_AUTHORITY_CLIENT_IDENTITY_PEM_PATH") else {
        assert!(!required, "authority mTLS identity path is missing");
        eprintln!("[INCOMPLETE] authority mTLS identity path is missing");
        return;
    };
    let Some(service_id) = required_env("ASTRAL_ELIGIBILITY_COMPLETION_TEST_SERVICE_ID") else {
        assert!(!required, "production source owner service id is missing");
        eprintln!("[INCOMPLETE] production source owner service id is missing");
        return;
    };
    let Some(database_id) = required_env("ASTRAL_ELIGIBILITY_COMPLETION_TEST_DATABASE_ID") else {
        assert!(!required, "production source owner database id is missing");
        eprintln!("[INCOMPLETE] production source owner database id is missing");
        return;
    };
    let Some(pinned_genesis) = required_env("ASTRAL_AUTHORITY_GENESIS_TRUST_ROOT_DIGEST") else {
        assert!(!required, "authority genesis trust-root pin is missing");
        eprintln!("[INCOMPLETE] authority genesis trust-root pin is missing");
        return;
    };
    let ca = std::fs::read(ca_path).expect("authority CA PEM is readable");
    let identity = std::fs::read(identity_path).expect("authority client identity PEM is readable");
    let pool = sqlx::MySqlPool::connect(&database_url)
        .await
        .expect("isolated eligibility MySQL is reachable");
    let eligible_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM authority_source_outcome \
         WHERE status = 'COMMITTED' AND mutation_kind = 'AUTHORIZATION_SOURCE' \
           AND service_id = ? AND database_id = ? AND staged_evidence IS NOT NULL",
    )
    .bind(&service_id)
    .bind(&database_id)
    .fetch_one(&pool)
    .await
    .expect("production owner outcome query succeeds");
    if eligible_rows == 0 {
        assert!(
            !required,
            "no real production-owner committed eligibility row is available"
        );
        eprintln!("[INCOMPLETE] no real production-owner committed eligibility row is available");
        return;
    }
    let authority = astral_authority::client::AuthorityClient::new(
        astral_authority::client::AuthorityClientConfig {
            base_url: authority_url,
            server_ca_pem: ca,
            client_identity_pem: identity,
            service_id: service_id.clone(),
            pinned_genesis_trust_root_digest: pinned_genesis,
            request_timeout: Duration::from_secs(3),
        },
    )
    .expect("real authority client construction");
    let config = EligibilityCompletionReconcilerConfig {
        worker_id: "eligibility-completion-integration".to_owned(),
        run_instance_id: uuid::Uuid::new_v4().simple().to_string(),
        owned: AuthoritySourceOwnerEntry {
            service_id,
            database_ids: vec![database_id],
        },
        ..Default::default()
    };
    let report = reconcile_eligibility_completions(pool, Arc::new(authority), &config)
        .await
        .expect("real authority completion reconciliation");
    assert!(
        report.completed + report.confirmed_completed > 0,
        "required real integration did not close a production-owner row: {report:?}"
    );
}
