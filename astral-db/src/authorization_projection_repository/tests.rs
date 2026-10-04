use super::*;
use crate::grant_repository::DELTA_STATUS_QUARANTINED;
use astral_types::{
    BindingLayer, DomainScopeRequirement, GrantEffect, GrantId, GrantProvenance, GrantRevision,
    GrantSourceKind, GrantState, TenantScope, ValidityWindow,
};

/// 维度守卫测试的“字段名 + 篡改函数”用例（type_complexity 别名）。
type DimensionCase<'a, T> = (&'a str, Box<dyn Fn(&mut T) + 'a>);

const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// 源码锚定守卫：source-freshness 门（撤权类未发布 delta 探针）只允许
/// 出现在正式证据读入口（`load_published_card_grant_evidence_in_tx`）。
/// projector 的 frontier/发布路径（`read_published_authorization_state_in_tx`
/// / `load_published_aggregate_frontier_in_tx` / `project_authorization_delta_in_tx`）
/// 在发布时自身 delta 尚未 `SUCCEEDED`——若经过探针会被自己自锁，永远
/// 无法发布。该不变式由本测试钉死，防止未来重构误接线。另钉两个语义：
/// 探针必须是非锁定读（锁定读会与发布者在 delta 行锁上互饿——P3 风暴
/// 实测教训），且必须只拦撤权类（REMOVE/REVOKE 或 fence 超前）。
#[test]
fn source_freshness_gate_is_reader_only_and_never_on_projector_paths() {
    let source = include_str!("../authorization_projection_repository.rs");
    // 只检查生产代码区域：测试模块自身提到探针名是合法的（本守卫测试）。
    let production = source
        .split("#[cfg(test)]")
        .next()
        .expect("production region must exist");

    // 读取器函数体：探针必须存在。
    let reader_body = production
        .split("pub async fn load_published_card_grant_evidence_in_tx")
        .nth(1)
        .and_then(|body| {
            body.split("\npub async fn load_published_card_grant_evidence(")
                .next()
        })
        .expect("strict evidence reader must exist");
    assert!(
        reader_body.contains("card_has_unsafe_pending_delta_in_tx"),
        "strict evidence reader must gate on unsafe pending deltas"
    );

    // 探针定义体：走钉死的 SQL 常量。
    let probe_body = production
        .split("async fn card_has_unsafe_pending_delta_in_tx")
        .nth(1)
        .and_then(|body| body.split("\nasync fn ").next())
        .expect("freshness probe must exist");
    assert!(
        probe_body.contains("FRESHNESS_GATE_PROBE_SQL"),
        "probe must run through the pinned SQL constant"
    );
    assert!(
        !FRESHNESS_GATE_PROBE_SQL.contains("FOR UPDATE"),
        "probe must be NON-LOCKING: a locking probe starves the publisher \
             on the delta row lock (P3 storm lesson)"
    );
    assert!(
        FRESHNESS_GATE_PROBE_SQL.contains("invalidates_published_evidence <> 0"),
        "probe must use the durable row-level published-evidence invalidation fact"
    );
    assert!(
        FRESHNESS_GATE_PROBE_SQL.contains("status <> 'SUCCEEDED'"),
        "probe must consider PENDING/LEASED/QUARANTINED deltas"
    );
    assert!(
        FRESHNESS_GATE_PROBE_SQL.contains("event_type IN ('REMOVE', 'REVOKE')"),
        "probe must block grant-removing deltas (stale-ALLOW direction)"
    );
    assert!(
        FRESHNESS_GATE_PROBE_SQL.contains("revoke_fence > COALESCE"),
        "probe must block fence-raising deltas beyond the published fence"
    );
    // 2026-09-04 修订：探针必须同时覆盖卡作用域与 aggregate-wide（NULL card）
    // 的撤权类未发布 delta——aggregate-wide 的 REMOVE/REVOKE/fence 抬升对
    // 本卡读取同样是 stale-ALLOW 方向，普通 `card_id = ?` 会漏掉它们。
    assert!(
        FRESHNESS_GATE_PROBE_SQL.contains("(card_id = ? OR card_id IS NULL)"),
        "probe must cover both the card scope and aggregate-wide (NULL card) deltas"
    );
    // 已发布水位子查询必须 NULL-safe（<=>）：NULL card 行对 NULL card 已发布
    // 水位比较；普通 `=` 使 `NULL = NULL` 恒 UNKNOWN → 水位折叠为 0，令已被
    // 已发布水位覆盖的 aggregate-wide delta 误报 PENDING。
    assert!(
        FRESHNESS_GATE_PROBE_SQL.contains("p.card_id <=> authorization_delta_event.card_id"),
        "published-watermark correlation must be NULL-safe (<=>), never plain ="
    );
    assert!(
        !FRESHNESS_GATE_PROBE_SQL.contains("p.card_id = authorization_delta_event"),
        "plain = watermark correlation must not survive the NULL-safe fix"
    );

    // projector 路径：任何函数体都不得引用探针。
    for projector_fn in [
        "pub async fn read_published_authorization_state_in_tx",
        "pub async fn load_published_aggregate_frontier_in_tx",
        "pub async fn project_authorization_delta_in_tx",
        "pub async fn publish_current_pointer_in_tx",
    ] {
        let body = production
            .split(projector_fn)
            .nth(1)
            .and_then(|body| body.split("\npub ").next())
            .unwrap_or_else(|| panic!("{projector_fn} must exist"));
        assert!(
            !body.contains("card_has_unsafe_pending_delta_in_tx"),
            "{projector_fn} must never run the source-freshness gate; \
                 the projector would self-deadlock on its own unpublished delta"
        );
    }
}

fn tenant() -> TenantScope {
    TenantScope::new(7, Some(11)).unwrap()
}

fn grant(unique_tail: u16) -> CanonicalGrant {
    CanonicalGrant {
        grant_id: GrantId::parse(&format!(
            "550e8400-e29b-41d4-a716-44665544{unique_tail:04x}"
        ))
        .unwrap(),
        revision: GrantRevision::initial(),
        state: GrantState::Active,
        source_kind: GrantSourceKind::RuleSet,
        binding_layer: BindingLayer::Base,
        tenant: tenant(),
        card_id: 17,
        user_id: 42,
        resource: "learn_subject:1".to_owned(),
        action: "read".to_owned(),
        effect: GrantEffect::Allow,
        validity: ValidityWindow::perpetual(),
        provenance: GrantProvenance {
            source_id: "rule-set-entry-9".to_owned(),
            source_entry: None,
            binding_id: Some("binding-3".to_owned()),
            delegation_id: None,
            operation_id: "op-1".to_owned(),
            event_id: Some("event-1".to_owned()),
            actor_user_id: Some(42),
        },
    }
}

fn identity() -> ProjectionAggregateIdentity {
    ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap()
}

fn digest_input<'a>(digest_hexes: Vec<String>) -> ManifestDigestInput<'a> {
    ManifestDigestInput {
        tenant_id: 7,
        aggregate_type: "CARD",
        aggregate_id: 17,
        card_id: None,
        generation: 3,
        source_generation: 9,
        projected_generation: 9,
        event_id: "event-stage",
        operation_id: "op-stage",
        semantic_hash_hex: HASH_A,
        dependency_hash_hex: HASH_B,
        compiler_version: "phase2-authorization-kernel-v1",
        parent_manifest_id: Some(2),
        revoke_fence: 1,
        segment_content_digests_hex: digest_hexes,
    }
}

// ── Status purity ───────────────────────────────────────────────────────

#[test]
fn status_parse_is_explicit_and_unknown_values_fail_closed() {
    for (text, expected) in [
        ("BUILDING", AuthorizationManifestStatus::Building),
        ("READY", AuthorizationManifestStatus::Ready),
        ("COMMITTED", AuthorizationManifestStatus::Committed),
        ("SUPERSEDED", AuthorizationManifestStatus::Superseded),
        ("QUARANTINED", AuthorizationManifestStatus::Quarantined),
    ] {
        assert_eq!(AuthorizationManifestStatus::parse(text).unwrap(), expected);
        assert_eq!(expected.as_str(), text);
    }
    assert!(
        AuthorizationManifestStatus::parse("ready").is_err()
            && AuthorizationManifestStatus::parse("").is_err()
            && AuthorizationManifestStatus::parse("ARCHIVED").is_err()
    );
}

#[test]
fn status_transition_table_matches_documented_edges() {
    use AuthorizationManifestStatus::*;
    assert!(Building.can_transition_to(Ready));
    assert!(Building.can_transition_to(Quarantined));
    assert!(Ready.can_transition_to(Committed));
    assert!(Ready.can_transition_to(Quarantined));
    assert!(Committed.can_transition_to(Superseded));
    assert!(Committed.can_transition_to(Quarantined));
    for (from, to) in [
        (Building, Committed),
        (Building, Superseded),
        (Ready, Ready),
        (Ready, Superseded),
        (Building, Building),
        (Committed, Committed),
        (Superseded, Ready),
        (Superseded, Quarantined),
        (Quarantined, Building),
        (Quarantined, Ready),
    ] {
        assert!(
            !from.can_transition_to(to),
            "{from:?} -> {to:?} must be refused"
        );
        assert!(from.validate_transition(to).is_err());
    }
    assert!(Building.validate_transition(Ready).is_ok());
}

#[test]
fn digest_codec_round_trip_rejects_uppercase_wrong_length_and_noncanon_uuids() {
    let encoded = Sha256Digest::from_hex(HASH_A).unwrap();
    assert_eq!(encoded.as_hex(), HASH_A);
    assert_eq!(
        Sha256Digest::from_bytes(encoded.as_bytes().to_vec()).unwrap(),
        encoded
    );

    assert!(Sha256Digest::from_hex(&HASH_A.to_ascii_uppercase()).is_err());
    assert!(Sha256Digest::from_hex(&HASH_A[..63]).is_err());
    assert!(Sha256Digest::from_hex(&format!("{HASH_A}ff")).is_err());
    assert!(Sha256Digest::from_hex(&"g".repeat(64)).is_err());

    // Canonical lowercase spelling survives; uppercase spellings do not.
    let grant_id = GrantId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap();
    assert_eq!(grant_id.as_str(), "550e8400-e29b-41d4-a716-446655440000");
    assert_ne!(
        grant_id.as_str(),
        "550E8400-E29B-41D4-A716-446655440000",
        "uppercase encodings must never be treated as canonical"
    );
    assert!(GrantId::parse("00000000-0000-0000-0000-000000000000").is_err());
}

#[test]
fn checked_bigint_conversions_fail_closed_on_overflow_and_negatives() {
    assert_eq!(bind_u64(i64::MAX as u64, "probe").unwrap(), i64::MAX);
    assert!(bind_u64((i64::MAX as u64) + 1, "probe").is_err());
    assert_eq!(
        read_counter_i64(i64::MAX, "probe").unwrap(),
        i64::MAX as u64
    );
    assert!(read_counter_i64(-1, "probe").is_err());
    assert!(read_counter_i64(i64::MIN, "probe").is_err());
    assert_eq!(bind_i32(i32::MAX as u64, "probe").unwrap(), i32::MAX);
    assert!(bind_i32((i32::MAX as u64) + 1, "probe").is_err());
    assert!(positive_i64(0, "probe").is_err());
    assert!(positive_i64(-5, "probe").is_err());
    assert!(validated_option_card_id(Some(3)).is_ok());
    assert!(validated_option_card_id(Some(0)).is_err());
    assert!(validated_option_card_id(None).is_ok());
}

// ── Payload codec ───────────────────────────────────────────────────────

#[test]
fn segment_payload_round_trip_is_byte_exact_and_deterministic() {
    let first = encode_segment_payload(&[grant(1), grant(2)]).unwrap();
    let second = encode_segment_payload(&[grant(1), grant(2)]).unwrap();
    assert_eq!(first, second);
    let decoded = decode_segment_payload(&first).unwrap();
    assert_eq!(decoded.len(), 2);

    // Content addressing binds the exact stored bytes.
    let digest = Sha256Digest::from_raw_bytes(sha256_digest_bytes(&first));
    assert_eq!(digest.as_hex().len(), 64);
    // Distinct payloads must address differently.
    let other = encode_segment_payload(&[grant(1)]).unwrap();
    assert_ne!(first, other);

    // Empty segments stay representable and stable.
    let empty = encode_segment_payload(&[]).unwrap();
    assert_eq!(empty, encode_segment_payload(&[]).unwrap());
    assert!(decode_segment_payload(&empty).unwrap().is_empty());
}

#[test]
fn segment_payload_rejects_tampered_and_structurally_broken_bytes() {
    let canonical = encode_segment_payload(&[grant(3)]).unwrap();

    // Syntactically valid JSON whose bytes deviate from canonical form.
    let tampered = {
        let mut bytes = canonical.clone();
        bytes.insert(1, b' ');
        bytes
    };
    assert!(decode_segment_payload(&tampered).is_err());

    // Structurally invalid JSON fails closed outright.
    assert!(decode_segment_payload(b"{not json").is_err());
    assert!(decode_segment_payload(b"null").is_err());
}

// ── Manifest digest seal ────────────────────────────────────────────────

#[test]
fn manifest_digest_is_order_sensitive_and_binds_every_field() {
    let base = compute_manifest_digest(&digest_input(vec![HASH_A.to_owned()])).unwrap();
    let same = compute_manifest_digest(&digest_input(vec![HASH_A.to_owned()])).unwrap();
    assert_eq!(base, same);

    let reordered =
        compute_manifest_digest(&digest_input(vec![HASH_B.to_owned(), HASH_A.to_owned()])).unwrap();
    let alternate =
        compute_manifest_digest(&digest_input(vec![HASH_A.to_owned(), HASH_B.to_owned()])).unwrap();
    assert_ne!(
        reordered, alternate,
        "ordinal order participates in the seal"
    );
    assert_ne!(base, reordered);

    let empty_list = compute_manifest_digest(&digest_input(vec![])).unwrap();
    assert_ne!(empty_list, base);

    // Invalid child digest text fails closed.
    let bad_child = ManifestDigestInput {
        segment_content_digests_hex: vec!["zzzz".repeat(32)],
        ..digest_input(vec![])
    };
    assert!(compute_manifest_digest(&bad_child).is_err());

    // Uppercase child digests are refused.
    let uppercase_child = ManifestDigestInput {
        segment_content_digests_hex: vec![HASH_A.to_ascii_uppercase()],
        ..digest_input(vec![])
    };
    assert!(compute_manifest_digest(&uppercase_child).is_err());

    // A different card scope changes the seal.
    let with_card = ManifestDigestInput {
        card_id: Some(17),
        ..digest_input(vec![HASH_A.to_owned()])
    };
    assert_ne!(compute_manifest_digest(&with_card).unwrap(), base);
}

// ── Ordinal completeness ────────────────────────────────────────────────

#[test]
fn contiguous_ordinals_sum_counts_and_flag_gaps_duplicates() {
    assert_eq!(validate_contiguous_ordinals(&[]).unwrap(), 0);
    assert_eq!(
        validate_contiguous_ordinals(&[(0, 3), (1, 0), (2, 9)]).unwrap(),
        12
    );

    // Gapped sequence refuses.
    let error = validate_contiguous_ordinals(&[(0, 1), (2, 1)]).unwrap_err();
    assert!(
        matches!(error, AuthorizationProjectionError::Mapping(ref message)
            if message.contains("ordinal_gap"))
    );

    // Duplicate ordinal shifts the sequence and therefore refuses too.
    let error = validate_contiguous_ordinals(&[(0, 1), (0, 1)]).unwrap_err();
    assert!(
        matches!(error, AuthorizationProjectionError::Mapping(ref message)
            if message.contains("ordinal_gap"))
    );
}

// ── Reuse validation ────────────────────────────────────────────────────

fn parent_view(ordinal: u64, identity: &ProjectionAggregateIdentity) -> (u64, ParentReferenceView) {
    (
        ordinal,
        ParentReferenceView {
            ordinal,
            identity: identity.clone(),
            segment_id: 100 + ordinal as i64,
            content_digest_hex: HASH_A.to_owned(),
        },
    )
}

#[test]
fn reuse_validation_accepts_only_same_aggregate_known_ordinals() {
    let identity = identity();
    let references = vec![parent_view(0, &identity), parent_view(1, &identity)];
    let plan = vec![
        StagedSegmentContent::ReuseParent { parent_ordinal: 0 },
        StagedSegmentContent::New(vec![grant(5)]),
        StagedSegmentContent::ReuseParent { parent_ordinal: 1 },
    ];
    let (new_count, reused_count) =
        validate_staging_plan_against_parent(&identity, &plan, Some(&references)).unwrap();
    assert_eq!((new_count, reused_count), (1, 2));

    // Unknown parent ordinal fails closed.
    let unknown_plan = vec![StagedSegmentContent::ReuseParent { parent_ordinal: 9 }];
    assert!(
        validate_staging_plan_against_parent(&identity, &unknown_plan, Some(&references)).is_err()
    );

    // Reuse without a parent (first build) fails closed.
    assert!(validate_staging_plan_against_parent(&identity, &unknown_plan, None).is_err());

    // Cross-aggregate reuse fails closed even with an exact digest hit.
    let foreign = ProjectionAggregateIdentity::new(7, "CARD", 99).unwrap();
    let foreign_references = vec![parent_view(0, &foreign)];
    assert!(validate_staging_plan_against_parent(
        &identity,
        &unknown_plan,
        Some(&foreign_references)
    )
    .is_err());

    // Cross-tenant reuse fails closed.
    let other_tenant = ProjectionAggregateIdentity::new(8, "CARD", 17).unwrap();
    let cross_tenant_references = vec![parent_view(0, &other_tenant)];
    assert!(validate_staging_plan_against_parent(
        &identity,
        &unknown_plan,
        Some(&cross_tenant_references)
    )
    .is_err());
}

#[test]
fn reuse_validation_caps_plan_size() {
    let identity = identity();
    let oversized: Vec<StagedSegmentContent> = (0..MAX_SEGMENTS_PER_MANIFEST + 1)
        .map(|_| StagedSegmentContent::New(vec![]))
        .collect();
    assert!(validate_staging_plan_against_parent(&identity, &oversized, None).is_err());
    let maximal: Vec<StagedSegmentContent> = (0..MAX_SEGMENTS_PER_MANIFEST)
        .map(|_| StagedSegmentContent::New(vec![]))
        .collect();
    assert!(validate_staging_plan_against_parent(&identity, &maximal, None).is_ok());
}

#[test]
fn reuse_validation_refuses_duplicate_parent_ordinals_and_segments() {
    let identity = identity();
    let references = vec![parent_view(0, &identity), parent_view(1, &identity)];

    // The same parent ordinal claimed twice is refused before any write.
    let duplicated_ordinal = vec![
        StagedSegmentContent::ReuseParent { parent_ordinal: 0 },
        StagedSegmentContent::ReuseParent { parent_ordinal: 1 },
        StagedSegmentContent::ReuseParent { parent_ordinal: 0 },
    ];
    let error =
        validate_staging_plan_against_parent(&identity, &duplicated_ordinal, Some(&references))
            .unwrap_err();
    assert!(
        matches!(&error, AuthorizationProjectionError::Mapping(message)
                if message.contains("duplicate_parent_ordinal_reuse")),
        "{error:?}"
    );

    // Two distinct ordinals sharing one parent segment row (corrupt or
    // shadowed parent set) are refused as a duplicate segment claim too.
    let (_, shared_view) = parent_view(0, &identity);
    let shadowing = vec![
        (
            0,
            ParentReferenceView {
                ordinal: 0,
                ..shared_view.clone()
            },
        ),
        (
            1,
            ParentReferenceView {
                ordinal: 1,
                ..shared_view
            },
        ),
    ];
    let shared_segment_claim = vec![
        StagedSegmentContent::ReuseParent { parent_ordinal: 0 },
        StagedSegmentContent::ReuseParent { parent_ordinal: 1 },
    ];
    let error =
        validate_staging_plan_against_parent(&identity, &shared_segment_claim, Some(&shadowing))
            .unwrap_err();
    assert!(
        matches!(&error, AuthorizationProjectionError::Mapping(message)
                if message.contains("duplicate_parent_segment_reuse")),
        "{error:?}"
    );

    // A healthy plan touching distinct ordinals still validates.
    let healthy = vec![
        StagedSegmentContent::ReuseParent { parent_ordinal: 0 },
        StagedSegmentContent::ReuseParent { parent_ordinal: 1 },
    ];
    assert!(validate_staging_plan_against_parent(&identity, &healthy, Some(&references)).is_ok());
}

// ── Publish preconditions ───────────────────────────────────────────────

fn ready_target(generation: u64, manifest_id: i64) -> TargetManifestView {
    TargetManifestView {
        identity: identity(),
        card_id: Some(17),
        manifest_id,
        parent_manifest_id: (generation > 1).then_some(400),
        generation,
        status_str: MANIFEST_STATUS_READY.to_owned(),
        semantic_hash_hex: HASH_A.to_owned(),
        dependency_hash_hex: HASH_B.to_owned(),
        compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        reference_count: 1,
    }
}

#[test]
fn publish_validation_happy_path_and_first_publication_gate() {
    let target = ready_target(1, 500);
    let expectation = AuthorizationPublishExpectation {
        current_pointer: None,
        expected_target_semantic_hash_hex: HASH_A.to_owned(),
        expected_target_dependency_hash_hex: HASH_B.to_owned(),
        expected_target_compiler_version: "phase2-authorization-kernel-v1".to_owned(),
    };
    assert!(validate_manifest_publish(&expectation, &target).is_ok());

    // First-publication generation errors are checked after the target has
    // supplied the only valid first-publication lineage: no parent.
    let later_target = TargetManifestView {
        parent_manifest_id: None,
        ..ready_target(2, 501)
    };
    let error = validate_manifest_publish(&expectation, &later_target).unwrap_err();
    assert!(
        matches!(error, AuthorizationProjectionError::ManifestPublishConflict(ref message)
            if message.contains("first_publication_requires_generation_one"))
    );

    let continuation_target = ready_target(2, 501);
    let continuing_expectation = AuthorizationPublishExpectation {
        current_pointer: Some(CurrentPointerView {
            identity: identity(),
            card_id: Some(17),
            current_generation: 1,
            manifest_id: 400,
            revoke_fence: 2,
            revoke_fence_proven: true,
            cas_version: 3,
        }),
        ..expectation.clone()
    };
    assert!(validate_manifest_publish(&continuing_expectation, &continuation_target).is_ok());
}

#[test]
fn publish_validation_fails_closed_on_target_deviations() {
    let expectation = AuthorizationPublishExpectation {
        current_pointer: None,
        expected_target_semantic_hash_hex: HASH_A.to_owned(),
        expected_target_dependency_hash_hex: HASH_B.to_owned(),
        expected_target_compiler_version: "phase2-authorization-kernel-v1".to_owned(),
    };

    // Target not READY.
    let building_target = TargetManifestView {
        status_str: MANIFEST_STATUS_BUILDING.to_owned(),
        ..ready_target(1, 500)
    };
    let error = validate_manifest_publish(&expectation, &building_target).unwrap_err();
    assert!(
        matches!(error, AuthorizationProjectionError::NotReady(ref message)
            if message.contains("target_not_ready"))
    );

    // Semantic hash disagreement with the compile output.
    let target = ready_target(1, 500);
    let drifted = AuthorizationPublishExpectation {
        expected_target_semantic_hash_hex: HASH_B.to_owned(),
        ..expectation.clone()
    };
    let error = validate_manifest_publish(&drifted, &target).unwrap_err();
    assert!(
        matches!(error, AuthorizationProjectionError::ManifestPublishConflict(ref message)
            if message.contains("publish_target_semantic_mismatch"))
    );

    // Dependency hash disagreement.
    let drifted = AuthorizationPublishExpectation {
        expected_target_dependency_hash_hex: HASH_A.to_owned(),
        ..expectation.clone()
    };
    let error = validate_manifest_publish(&drifted, &target).unwrap_err();
    assert!(
        matches!(error, AuthorizationProjectionError::ManifestPublishConflict(ref message)
            if message.contains("publish_target_dependency_mismatch"))
    );

    // Compiler version disagreement.
    let drifted = AuthorizationPublishExpectation {
        expected_target_compiler_version: "other-compiler".to_owned(),
        ..expectation
    };
    let error = validate_manifest_publish(&drifted, &target).unwrap_err();
    assert!(
        matches!(error, AuthorizationProjectionError::ManifestPublishConflict(ref message)
            if message.contains("publish_target_compiler_mismatch"))
    );
}

#[test]
fn publish_validation_fails_closed_on_pointer_chain_breaks() {
    let pointer =
        |current_generation: u64, manifest_id: i64, identity: ProjectionAggregateIdentity| {
            CurrentPointerView {
                identity,
                card_id: Some(17),
                current_generation,
                manifest_id,
                revoke_fence: 2,
                revoke_fence_proven: true,
                cas_version: 9,
            }
        };
    let expectation_for =
        |pointer_view: Option<CurrentPointerView>| AuthorizationPublishExpectation {
            current_pointer: pointer_view,
            expected_target_semantic_hash_hex: HASH_A.to_owned(),
            expected_target_dependency_hash_hex: HASH_B.to_owned(),
            expected_target_compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        };

    // Generation gap between pointer and target.
    let target = ready_target(2, 501);
    let gapped = expectation_for(Some(pointer(5, 400, identity())));
    let error = validate_manifest_publish(&gapped, &target).unwrap_err();
    assert!(
        matches!(error, AuthorizationProjectionError::ManifestPublishConflict(ref message)
            if message.contains("publish_generation_gap"))
    );

    // Identity split between pointer and target.
    let foreign_identity = ProjectionAggregateIdentity::new(7, "CARD", 999).unwrap();
    let split = expectation_for(Some(pointer(1, 400, foreign_identity)));
    let error = validate_manifest_publish(&split, &target).unwrap_err();
    assert!(matches!(
        error,
        AuthorizationProjectionError::IdentityMismatch(_)
    ));

    // Re-publishing the same manifest is refused (sequence stays valid).
    let same = expectation_for(Some(pointer(1, 501, identity())));
    let error = validate_manifest_publish(&same, &target).unwrap_err();
    assert!(
        matches!(error, AuthorizationProjectionError::ManifestPublishConflict(ref message)
            if message.contains("publish_same_manifest"))
    );
}

#[test]
fn publish_validation_rejects_card_scope_splits() {
    // Pointer scope vs stored manifest scope must agree exactly; any
    // Some-vs-None or foreign-card split refuses as identity mismatch.
    let pointer = |card_id: Option<i64>| CurrentPointerView {
        identity: identity(),
        card_id,
        current_generation: 1,
        manifest_id: 400,
        revoke_fence: 2,
        revoke_fence_proven: true,
        cas_version: 9,
    };
    let with_card = |card_id: Option<i64>| TargetManifestView {
        card_id,
        ..ready_target(2, 501)
    };
    let expectation_with =
        |pointer_view: Option<CurrentPointerView>| AuthorizationPublishExpectation {
            current_pointer: pointer_view,
            expected_target_semantic_hash_hex: HASH_A.to_owned(),
            expected_target_dependency_hash_hex: HASH_B.to_owned(),
            expected_target_compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        };

    // Card-scoped pointer reading back against a NULL-scoped target.
    let error =
        validate_manifest_publish(&expectation_with(Some(pointer(Some(17)))), &with_card(None))
            .unwrap_err();
    assert!(
        matches!(&error, AuthorizationProjectionError::IdentityMismatch(message)
                if message.contains("publish_pointer_target_card_scope_mismatch")),
        "{error:?}"
    );

    // Legacy NULL residue on the pointer vs card-scoped target.
    let error =
        validate_manifest_publish(&expectation_with(Some(pointer(None))), &with_card(Some(17)))
            .unwrap_err();
    assert!(
        matches!(&error, AuthorizationProjectionError::IdentityMismatch(message)
                if message.contains("publish_pointer_target_card_scope_mismatch")),
        "{error:?}"
    );

    // Agreement keeps validating.
    assert!(validate_manifest_publish(
        &expectation_with(Some(pointer(Some(17)))),
        &with_card(Some(17))
    )
    .is_ok());
    assert!(
        validate_manifest_publish(&expectation_with(Some(pointer(None))), &with_card(None)).is_ok()
    );
}

#[test]
fn fence_continuity_enforces_monotonicity_or_paired_evidence() {
    // Mandatory paired evidence: monotonicity is still enforced, but the
    // previous "half-supplied pair" case is now unrepresentable by the
    // typed fields (`u64`, not `Option`) — a deliberate API-level fix for
    // the self-proving `PublishRevokeFenceEvidence(None, None)` hole.
    assert!(validate_publish_fence_continuity(3, 3).is_ok());
    assert!(validate_publish_fence_continuity(3, 4).is_ok());

    let error = validate_publish_fence_continuity(5, 4).unwrap_err();
    assert!(
        matches!(error, AuthorizationProjectionError::ManifestPublishConflict(ref message)
            if message.contains("fence_regression"))
    );

    // First publications must present the zero initial fence; any other
    // value is invented evidence, never defaulted silently.
    assert!(validate_first_publication_previous_fence(false, 0).is_ok());
    assert!(validate_first_publication_previous_fence(true, 3).is_ok());
    let error = validate_first_publication_previous_fence(false, 2).unwrap_err();
    assert!(
        matches!(error, AuthorizationProjectionError::ManifestPublishConflict(ref message)
            if message.contains("first_publication_requires_zero_previous_fence"))
    );
}

#[test]
fn previous_fence_authority_takes_only_the_locked_pointer_row() {
    // Evidence agreeing with the durable pointer state passes.
    assert!(validate_publish_previous_fence_authority(None, 0).is_ok());
    assert!(validate_publish_previous_fence_authority(Some(4), 4).is_ok());

    // Any disagreement between caller evidence and the authoritative
    // locked pointer refuses — forged higher, stale lower, both alike.
    for (durable, evidence) in [(Some(4), 3_u64), (Some(4), 5), (Some(0), 1), (None, 1)] {
        let error = validate_publish_previous_fence_authority(durable, evidence).unwrap_err();
        assert!(
            matches!(
                error,
                AuthorizationProjectionError::CurrentPointerCasConflict(ref message)
                    if message.contains("previous_fence_not_authoritative")
            ),
            "durable={durable:?};evidence={evidence}"
        );
        assert!(
            format!("{error}").contains(&format!("durable={}", durable.unwrap_or(0))),
            "the refusal must name the authoritative value"
        );
    }
}

#[test]
fn pointer_proof_latch_distinguishes_legacy_zero_from_proven_zero() {
    assert!(validate_current_pointer_proof(None).is_ok());
    assert!(validate_pointer_proof_state(0, true).is_ok());
    assert!(validate_pointer_proof_state(7, true).is_ok());

    for fence in [0, 7] {
        let error = validate_pointer_proof_state(fence, false).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::NotReady(ref message)
                if message.contains("backfill_or_rehearsal_required")
                    && message.contains("pointer_proof_unproven"))
        );
    }

    let mut unproven = CurrentPointerView {
        identity: identity(),
        card_id: Some(17),
        current_generation: 1,
        manifest_id: 400,
        revoke_fence: 0,
        revoke_fence_proven: false,
        cas_version: 1,
    };
    assert!(validate_current_pointer_proof(Some(&unproven)).is_err());
    unproven.revoke_fence_proven = true;
    assert!(validate_current_pointer_proof(Some(&unproven)).is_ok());
}

#[test]
fn zero_sentinel_never_proves_history_without_the_latch() {
    for claimed in [0, 2] {
        let error = validate_zero_sentinel_fence_history(claimed, Some((0, false))).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::NotReady(ref message)
                if message.contains("backfill_or_rehearsal_required")
                    && message.contains("pointer_proof_unproven"))
        );
    }

    // A Rust-published zero fence is proven and may advance to a positive
    // fence; only numeric history is never used as proof.
    validate_zero_sentinel_fence_history(0, Some((0, true))).unwrap();
    validate_zero_sentinel_fence_history(3, Some((0, true))).unwrap();
    let error = validate_zero_sentinel_fence_history(2, Some((3, true))).unwrap_err();
    assert!(
        matches!(error, AuthorizationProjectionError::ManifestPublishConflict(ref message)
            if message.contains("fence_regression"))
    );
    validate_zero_sentinel_fence_history(7, None).unwrap();
}

#[test]
fn staging_sql_shape_persists_durable_lineage_columns() {
    // The manifest insert writes BOTH new columns on every build.
    assert!(
        MANIFEST_INSERT_SQL.contains("parent_manifest_id, revoke_fence, status"),
        "{MANIFEST_INSERT_SQL}"
    );
    assert!(MANIFEST_INSERT_SQL.ends_with("'BUILDING')"));
    // Row readers expose the same columns so restart reconciliation and
    // immutable-replay verification can rely on them byte-for-byte.
    assert!(MANIFEST_ROW_COLUMNS.contains("parent_manifest_id"));
    assert!(MANIFEST_ROW_COLUMNS.contains("revoke_fence"));
    assert!(POINTER_ROW_COLUMNS.contains("revoke_fence"));
    assert!(POINTER_ROW_COLUMNS.contains("revoke_fence_proven"));
}

#[test]
fn projector_command_shape_pins_stage_revoke_fence_to_published_evidence() {
    let mut command = shaped_command();
    assert_eq!(command.stage.revoke_fence, command.fences.new_revoke_fence);
    assert!(validate_projector_command_shape(&command).is_ok());

    command.stage.revoke_fence += 1;
    let error = validate_projector_command_shape(&command)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("command_stage_revoke_fence_mismatch"),
        "{error}"
    );
}

#[test]
fn resumed_reference_equivalence_requires_full_field_agreement() {
    let identity = identity();
    let snapshot = AuthorizationSegmentSnapshot {
        segment_id: 42,
        identity: identity.clone(),
        card_id: Some(17),
        content_digest: Sha256Digest::from_hex(HASH_A).unwrap(),
        semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
        dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
        compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        format: SEGMENT_FORMAT_AUTHORIZATION_GRANTS_JSON_V1.to_owned(),
        row_count: 2,
        byte_size: 128,
        grants: vec![grant(1), grant(2)],
    };
    let record = |mutate: &dyn Fn(&mut AuthorizationSegmentReferenceRecord)| {
        let mut base = AuthorizationSegmentReferenceRecord {
            reference_id: 7,
            manifest_id: 500,
            identity: identity.clone(),
            card_id: Some(17),
            generation: 3,
            ordinal: 1,
            segment_id: 42,
            content_digest: Sha256Digest::from_hex(HASH_A).unwrap(),
            event_id: "event-stage".to_owned(),
            operation_id: "op-stage".to_owned(),
        };
        mutate(&mut base);
        base
    };
    let expectation_for =
        |manifest_id: i64, generation: u64, ordinal: u64| ResumedReferenceExpectation {
            identity: &identity,
            card_id: Some(17),
            event_id: "event-stage",
            operation_id: "op-stage",
            manifest_id,
            generation,
            ordinal,
            snapshot: &snapshot,
        };
    let matches = |candidate: &AuthorizationSegmentReferenceRecord| {
        resumed_reference_matches(candidate, &expectation_for(500, 3, 1))
    };

    // Byte-for-byte agreement resumes as an idempotent skip.
    assert!(matches(&record(&|_| {})));

    // Any durable dimension drifting from the plan refuses resume.
    for mutation in [
        "manifest_id",
        "ordinal",
        "generation",
        "identity",
        "card_id",
        "segment_id",
        "content_digest",
        "event_id",
        "operation_id",
    ] {
        let candidate = record(
            &|row: &mut AuthorizationSegmentReferenceRecord| match mutation {
                "manifest_id" => row.manifest_id = 501,
                "ordinal" => row.ordinal = 2,
                "generation" => row.generation = 4,
                "identity" => row.identity.aggregate_id = 99,
                "card_id" => row.card_id = None,
                "segment_id" => row.segment_id = 43,
                "content_digest" => row.content_digest = Sha256Digest::from_hex(HASH_B).unwrap(),
                "event_id" => row.event_id = "other-event".to_owned(),
                _ => row.operation_id = "other-op".to_owned(),
            },
        );
        assert!(!matches(&candidate), "{mutation} drift must refuse resume");
    }

    // A winner committed at a different slot position is not this plan's
    // row either.
    let shifted = record(&|_| {});
    assert!(!resumed_reference_matches(
        &shifted,
        &expectation_for(500, 3, 2)
    ));
}

// ── Identity text gates ─────────────────────────────────────────────────

#[test]
fn aggregate_identity_validates_charset_positivity_and_texts() {
    assert!(ProjectionAggregateIdentity::new(7, "CARD", 17).is_ok());
    assert!(ProjectionAggregateIdentity::new(0, "CARD", 17).is_err());
    assert!(ProjectionAggregateIdentity::new(-1, "CARD", 17).is_err());
    assert!(ProjectionAggregateIdentity::new(7, "CARD", 0).is_err());
    assert!(ProjectionAggregateIdentity::new(7, "", 17).is_err());
    assert!(ProjectionAggregateIdentity::new(7, "CA RD", 17).is_err());
    assert!(ProjectionAggregateIdentity::new(7, "A".repeat(33).as_str(), 17).is_err());
    assert!(truncate_last_error("0123456789").len() <= MAX_LAST_ERROR_LENGTH);
    assert!(validated_text("event", MAX_EVENT_ID_LENGTH, "event_id").is_ok());
    assert!(validated_text("", MAX_EVENT_ID_LENGTH, "event_id").is_err());
    assert!(validated_text("a\tb", MAX_EVENT_ID_LENGTH, "event_id").is_err());
}

// ── Compiler bridge ─────────────────────────────────────────────────────

#[test]
fn hot_state_bridge_preserves_deterministic_segment_order() {
    use astral_types::DependencyVersion;
    use policy_engine::HotState;

    let dependency_vector = astral_types::DependencyVector::new(vec![
        DependencyVersion::new("card", 4, 0).unwrap(),
        DependencyVersion::new("rule-set", 3, 1).unwrap(),
    ])
    .unwrap();
    let state = HotState::from_grants(
        tenant(),
        5,
        vec![grant(0x21), grant(0x22)],
        dependency_vector,
    )
    .unwrap();
    let plan = stage_plan_new_segments_from_hot_state(&state).unwrap();
    let references = state.segment_references();
    assert_eq!(plan.len(), references.len());
    assert_eq!(plan.len(), state.segments.len());
    for entry in &plan {
        match entry {
            StagedSegmentContent::New(grants) => {
                let encoded = encode_segment_payload(grants).unwrap();
                let computed = Sha256Digest::from_raw_bytes(sha256_digest_bytes(&encoded));
                assert_eq!(computed.as_hex().len(), 64);
            }
            StagedSegmentContent::ReuseParent { .. } => panic!("bridge yields fresh segments"),
        }
    }
}

// ── SQL shape tests (text/binding shape only; NOT integration) ──────────

#[test]
fn pointer_cas_statement_shape_pins_every_fence_column() {
    for fragment in [
        "AND current_generation = ?",
        "AND manifest_id = ?",
        "AND cas_version = ?",
        // Null-safe card-scope guard: a scoped pointer can only advance
        // while the stored card_id still equals the requested scope.
        "AND card_id <=> ?",
        // The durable revoke fence is both moved and pinned by the CAS:
        // the WHERE guard refuses any move off a pointer whose fence no
        // longer equals the authoritative previous value.
        "revoke_fence = ?",
        "AND revoke_fence = ?",
        "cas_version = cas_version + 1",
    ] {
        assert!(
            POINTER_CAS_UPDATE_SQL.contains(fragment),
            "missing {fragment}"
        );
    }
    // The CAS update re-pins the scope in SET as well as guarding it.
    assert!(POINTER_CAS_UPDATE_SQL.contains("SET current_generation = ?, card_id = ?,"));
    assert!(
        POINTER_CAS_UPDATE_SQL.contains("compiler_version = ?, revoke_fence = ?,"),
        "the new fence must move inside the same CAS UPDATE"
    );

    // Promotion is pinned to READY plus the observed CAS counter AND the
    // evidence.new revoke fence.
    assert!(MANIFEST_PROMOTE_SQL.contains("AND status = 'READY'"));
    assert!(MANIFEST_PROMOTE_SQL.contains("AND cas_version = ?"));
    assert!(
        MANIFEST_PROMOTE_SQL.contains("AND revoke_fence = ?"),
        "promotion must pin the manifest's own revoke fence"
    );

    // Superseding touches history only after CAS success and never deletes.
    assert!(MANIFEST_SUPERSEDE_SQL.contains("AND status = 'COMMITTED'"));
    for statement in [
        POINTER_CAS_UPDATE_SQL,
        MANIFEST_PROMOTE_SQL,
        MANIFEST_SUPERSEDE_SQL,
        POINTER_FIRST_INSERT_SQL,
    ] {
        assert!(
            !statement.to_uppercase().contains("DELETE"),
            "no deletes allowed"
        );
    }
    assert!(POINTER_FIRST_INSERT_SQL.ends_with("'READY')"));
}

#[test]
fn pointer_statements_propagate_card_scope_and_promotion_clears_lease() {
    // First publication persists the card scope explicitly so a
    // card-scoped chain never starts with a NULL `card_id`.
    assert!(POINTER_FIRST_INSERT_SQL.contains("tenant_id, card_id, aggregate_type"));
    assert_eq!(POINTER_FIRST_INSERT_SQL.matches('?').count(), 12);

    // CAS updates both re-pin and guard the scope; every value binds,
    // including the moved new fence and its pinned previous guard.
    assert_eq!(POINTER_CAS_UPDATE_SQL.matches('?').count(), 17);
    assert!(!POINTER_CAS_UPDATE_SQL.to_uppercase().contains("DELETE"));

    // Promotion to COMMITTED clears the residual builder lease inside
    // the same guarded update (status/cas/hash guards unchanged).
    assert!(MANIFEST_PROMOTE_SQL.contains("lease_owner = NULL"));
    assert!(MANIFEST_PROMOTE_SQL.contains("lease_token_hash = NULL"));
    assert!(MANIFEST_PROMOTE_SQL.contains("lease_expires_at = NULL"));
    assert!(MANIFEST_PROMOTE_SQL.contains("last_error = NULL"));

    // Resume verification reads one ordinal slot under lock and never
    // deletes or rewrites committed reference rows.
    let resume_read =
        format!("{SELECT_PREFIX}{REFERENCE_ROW_COLUMNS}{REFERENCE_BY_MANIFEST_ORDINAL_TAIL}");
    assert!(resume_read.contains("WHERE manifest_id = ? AND segment_ordinal = ? FOR UPDATE"));
    assert!(!resume_read.to_uppercase().contains("DELETE"));
    assert!(!resume_read.to_uppercase().contains("UPDATE "));
    assert!(REFERENCE_INSERT_SQL.starts_with("INSERT INTO"));
}

#[test]
fn lease_statements_guard_owner_token_liveness_and_status() {
    for (statement, status_fragment) in [
        (MANIFEST_HEARTBEAT_SQL, None),
        (MANIFEST_HEARTBEAT_WITH_CAS_SQL, None),
        (MANIFEST_RELEASE_SQL, Some("AND status = 'BUILDING'")),
        (
            MANIFEST_QUARANTINE_SQL,
            Some("status IN ('BUILDING', 'READY')"),
        ),
    ] {
        assert!(statement.contains("AND lease_owner = ?"), "{statement}");
        assert!(
            statement.contains("AND lease_token_hash = ?"),
            "{statement}"
        );
        assert!(
            statement.contains("lease_expires_at > UTC_TIMESTAMP()"),
            "{statement}"
        );
        if let Some(fragment) = status_fragment {
            assert!(statement.contains(fragment));
        }
    }
    // Only hashed tokens ever travel into statements.
    assert!(!MANIFEST_CLAIM_INSTALL_SQL.contains("lease_token ="));
    assert!(MANIFEST_CLAIM_INSTALL_SQL.contains("lease_token_hash = ?"));
    assert!(MANIFEST_CLAIM_INSTALL_SQL.contains("lease_expires_at <= UTC_TIMESTAMP()"));
    // Live leases are never stolen on claim.
    assert!(!MANIFEST_CLAIM_CANDIDATE_SQL.contains("status = 'LEASED'"));
}

#[test]
fn staged_queries_are_parameterized_without_interpolation_surface() {
    for statement in [
        SEGMENT_SELECT_BY_DIGEST_SQL,
        SEGMENT_INSERT_SQL,
        REFERENCE_INSERT_SQL,
        MANIFEST_INSERT_SQL,
        MANIFEST_CLAIM_CANDIDATE_SQL,
        MANIFEST_FINALIZE_SQL,
    ] {
        assert!(
            !statement.contains('{'),
            "brace interpolation surface in: {statement}"
        );
    }
    assert_eq!(REFERENCE_INSERT_SQL.matches('?').count(), 11);
    assert_eq!(MANIFEST_INSERT_SQL.matches('?').count(), 15);
    assert_eq!(SEGMENT_INSERT_SQL.matches('?').count(), 12);
    assert_eq!(MANIFEST_CLAIM_INSTALL_SQL.matches('?').count(), 4);
    assert_eq!(MANIFEST_FINALIZE_SQL.matches('?').count(), 8);
    // Pointer writes carry the card scope end-to-end: first insert binds
    // tenant/card/type/id/gen/manifest/provenance/hashes/compiler/fence
    // (12), CAS update adds the scope re-pin plus its null-safe guard and
    // the pinned previous fence (17).
    assert_eq!(POINTER_CAS_UPDATE_SQL.matches('?').count(), 17);
    assert_eq!(POINTER_FIRST_INSERT_SQL.matches('?').count(), 12);
    assert_eq!(MANIFEST_PROMOTE_SQL.matches('?').count(), 10);

    // Resume readback statement stays fully parameterized.
    let resume_read =
        format!("{SELECT_PREFIX}{REFERENCE_ROW_COLUMNS}{REFERENCE_BY_MANIFEST_ORDINAL_TAIL}");
    assert_eq!(resume_read.matches('?').count(), 2);
}

#[test]
fn finalize_guard_keeps_building_unpublishable_until_complete() {
    assert!(MANIFEST_FINALIZE_SQL.contains("AND status = 'BUILDING'"));
    assert!(MANIFEST_FINALIZE_SQL.contains("AND cas_version = ?"));
    assert!(MANIFEST_FINALIZE_SQL.contains("AND lease_expires_at > UTC_TIMESTAMP()"));
    assert!(!MANIFEST_FINALIZE_SQL.to_uppercase().contains("DELETE"));
}

// ── Impact plans: vocabulary, normalization and bridging ───────────────

#[test]
fn impact_plan_vocabulary_is_explicit_and_fail_closed() {
    for (text, expected) in [
        ("PENDING", AuthorizationImpactPlanStatus::Pending),
        ("SUCCEEDED", AuthorizationImpactPlanStatus::Succeeded),
    ] {
        assert_eq!(
            AuthorizationImpactPlanStatus::parse(text).unwrap(),
            expected
        );
        assert_eq!(expected.as_str(), text);
    }
    assert!(AuthorizationImpactPlanStatus::parse("READY").is_err());
    assert!(AuthorizationImpactPlanStatus::parse("").is_err());

    assert!(AuthorizationImpactPlanStatus::Pending
        .can_transition_to(AuthorizationImpactPlanStatus::Succeeded));
    for (from, to) in [
        (
            AuthorizationImpactPlanStatus::Succeeded,
            AuthorizationImpactPlanStatus::Pending,
        ),
        (
            AuthorizationImpactPlanStatus::Succeeded,
            AuthorizationImpactPlanStatus::Succeeded,
        ),
        (
            AuthorizationImpactPlanStatus::Pending,
            AuthorizationImpactPlanStatus::Pending,
        ),
    ] {
        assert!(!from.can_transition_to(to));
    }

    for (text, expected) in [
        ("SEGMENT_UPSERT", AuthorizationImpactItemType::SegmentUpsert),
        ("SEGMENT_REMOVE", AuthorizationImpactItemType::SegmentRemove),
    ] {
        assert_eq!(AuthorizationImpactItemType::parse(text).unwrap(), expected);
        assert_eq!(expected.as_str(), text);
    }
    assert!(AuthorizationImpactItemType::parse("UPSERT").is_err());
    assert!(AuthorizationImpactItemType::parse("").is_err());
}

fn impact_item_upsert(key: &str) -> AuthorizationImpactItemInput {
    AuthorizationImpactItemInput {
        projection_key: key.to_owned(),
        item_type: AuthorizationImpactItemType::SegmentUpsert,
        grant_id: None,
        before_digest_hex: None,
        after_digest_hex: Some(HASH_A.to_owned()),
    }
}

#[test]
fn impact_item_normalization_sorts_dedupes_and_enforces_digest_pairing() {
    let items = vec![
        impact_item_upsert("b-key"),
        impact_item_upsert("a-key"),
        // Identical duplicate collapses silently.
        impact_item_upsert("b-key"),
    ];
    let normalized = normalize_impact_items(&items).unwrap();
    let keys: Vec<&str> = normalized
        .iter()
        .map(|item| item.projection_key.as_str())
        .collect();
    assert_eq!(
        keys,
        vec!["a-key", "b-key"],
        "byte-ascending order is required"
    );

    // Divergent duplicate under one key refuses instead of merging.
    let mut divergent = impact_item_upsert("a-key");
    divergent.after_digest_hex = Some(HASH_B.to_owned());
    let conflicting = vec![impact_item_upsert("a-key"), divergent];
    assert!(matches!(
        normalize_impact_items(&conflicting),
        Err(AuthorizationProjectionError::ScopeViolation(ref message))
            if message.contains("impact_item_key_conflict")
    ));

    // UPSERT demands an after digest; REMOVE demands before-only.
    let upsert_missing_after = AuthorizationImpactItemInput {
        projection_key: "k".to_owned(),
        item_type: AuthorizationImpactItemType::SegmentUpsert,
        grant_id: None,
        before_digest_hex: Some(HASH_B.to_owned()),
        after_digest_hex: None,
    };
    assert!(matches!(
        normalize_impact_items(&[upsert_missing_after]),
        Err(AuthorizationProjectionError::ScopeViolation(ref message))
            if message.contains("upsert_requires_after_digest")
    ));
    let remove_ok = AuthorizationImpactItemInput {
        projection_key: "r".to_owned(),
        item_type: AuthorizationImpactItemType::SegmentRemove,
        grant_id: None,
        before_digest_hex: Some(HASH_B.to_owned()),
        after_digest_hex: None,
    };
    let normalized_remove = normalize_impact_items(std::slice::from_ref(&remove_ok)).unwrap();
    assert_eq!(normalized_remove[0].after_digest, None);
    assert_eq!(
        normalized_remove[0].before_digest,
        Some(Sha256Digest::from_hex(HASH_B).unwrap())
    );
    let mut remove_with_after = remove_ok;
    remove_with_after.after_digest_hex = Some(HASH_A.to_owned());
    assert!(matches!(
        normalize_impact_items(&[remove_with_after]),
        Err(AuthorizationProjectionError::ScopeViolation(ref message))
            if message.contains("remove_digest_pairing")
    ));

    // Key hygiene: whitespace/control characters, emptiness, caps and
    // non-hex digest payloads all fail closed.
    for poisoned_key in ["", " spaced\t"] {
        let bad = impact_item_upsert(poisoned_key);
        assert!(normalize_impact_items(&[bad]).is_err(), "{poisoned_key}");
    }
    let oversized = impact_item_upsert(&"k".repeat(MAX_PROJECTION_KEY_LENGTH + 1));
    assert!(normalize_impact_items(&[oversized]).is_err());
    let boundary = impact_item_upsert(&"k".repeat(MAX_PROJECTION_KEY_LENGTH));
    assert!(normalize_impact_items(&[boundary]).is_ok());
    let non_hex = impact_item_upsert("k");
    let mut non_hex = non_hex;
    non_hex.after_digest_hex = Some("zz".repeat(32));
    assert!(normalize_impact_items(&[non_hex]).is_err());

    // Plans must carry at least one item.
    assert!(matches!(
        normalize_impact_items(&[]),
        Err(AuthorizationProjectionError::ScopeViolation(ref message))
            if message.contains("empty_impact_plan")
    ));
}

#[test]
fn impact_plan_sql_shape_pins_identity_guarded_completion_and_no_deletes() {
    assert_eq!(IMPACT_PLAN_INSERT_SQL.matches('?').count(), 13);
    assert_eq!(IMPACT_ITEM_INSERT_SQL.matches('?').count(), 15);
    assert!(IMPACT_PLAN_INSERT_SQL.ends_with("'PENDING')"));
    assert!(IMPACT_ITEM_INSERT_SQL.ends_with("'PENDING')"));
    assert!(IMPACT_ITEMS_BY_PLAN_TAIL.contains("ORDER BY projection_key ASC FOR UPDATE"));
    assert!(IMPACT_PLAN_BY_EVENT_TAIL.contains("WHERE event_id = ? FOR UPDATE"));
    assert!(IMPACT_PLAN_BY_TARGET_GENERATION_TAIL
        .contains("AND aggregate_type = ? AND aggregate_id = ? AND target_generation = ?"));
    // Completion stays guarded by event + aggregate identity and PENDING.
    for fragment in [
        "SET status = 'SUCCEEDED'",
        "WHERE plan_id = ? AND event_id = ?",
        "AND tenant_id = ?",
        "AND aggregate_type = ?",
        "AND aggregate_id = ?",
        "AND status = 'PENDING'",
    ] {
        assert!(IMPACT_PLAN_COMPLETE_SQL.contains(fragment), "{fragment}");
    }
    for statement in [
        IMPACT_PLAN_INSERT_SQL,
        IMPACT_ITEM_INSERT_SQL,
        IMPACT_PLAN_COMPLETE_SQL,
        IMPACT_ITEM_COUNT_SQL,
    ] {
        assert!(!statement.to_uppercase().contains("DELETE"), "{statement}");
        assert!(!statement.contains('{'), "no interpolation surface");
    }
}

// ── Item root-link decoding ────────────────────────────────────────────

fn linked_identity() -> ProjectionAggregateIdentity {
    ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap()
}

fn item_raw_row() -> ImpactItemRawSqlRow {
    ImpactItemRawSqlRow {
        item_id: 3,
        plan_id: 9,
        tenant_id: 7,
        card_id: Some(17),
        aggregate_type: "CARD".to_owned(),
        aggregate_id: 17,
        event_id: "evt".to_owned(),
        operation_id: "op".to_owned(),
        projection_key: "{\"action\":\"read\",\"cardId\":17}".to_owned(),
        item_type: "SEGMENT_UPSERT".to_owned(),
        grant_id: None,
        base_version: 0,
        target_version: 1,
        before_digest: None,
        after_digest: Some(vec![1u8; 32]),
        dependency_hash: vec![8u8; 32],
        status: "PENDING".to_owned(),
    }
}

#[test]
fn impact_item_decode_rejects_root_link_drift() {
    let identity = linked_identity();
    let dependency = Sha256Digest::from_bytes(vec![8u8; 32]).unwrap();
    let event_id = "evt".to_owned();
    let operation_id = "op".to_owned();
    let root = ImpactRootLink {
        plan_id: 9,
        identity: &identity,
        card_id: Some(17),
        event_id: &event_id,
        operation_id: &operation_id,
        base_version: 0,
        target_version: 1,
        dependency_hash: &dependency,
    };
    let expect_failure = |mutate: &dyn Fn(&mut ImpactItemRawSqlRow), needle: &str| {
        let mut row = item_raw_row();
        mutate(&mut row);
        let error = row.decode_against(&root).unwrap_err().to_string();
        assert!(error.contains(needle), "expected {needle} inside: {error}");
    };

    let happy = item_raw_row().decode_against(&root).unwrap();
    assert_eq!(happy.item_type, AuthorizationImpactItemType::SegmentUpsert);
    assert_eq!(happy.item_id, 3);

    // A row belonging to a different plan root is foreign even when every
    // denormalized column matches.
    expect_failure(&|row| row.plan_id = 10, "impact_item_identity_mismatch");

    expect_failure(
        &|row| row.aggregate_id = 999,
        "impact_item_identity_mismatch",
    );
    expect_failure(&|row| row.card_id = None, "impact_item_root_link_mismatch");
    expect_failure(
        &|row| row.event_id = "other".to_owned(),
        "impact_item_root_link_mismatch",
    );
    expect_failure(
        &|row| row.operation_id = "other".to_owned(),
        "impact_item_root_link_mismatch",
    );
    expect_failure(
        &|row| row.target_version = 9,
        "impact_item_root_link_mismatch",
    );
    expect_failure(
        &|row| row.dependency_hash = vec![7u8; 32],
        "impact_item_dependency_mismatch",
    );
    expect_failure(
        &|row| row.status = "DONE".to_owned(),
        "impact_item_status_unexpected",
    );
    expect_failure(
        &|row| row.item_type = "MIXED".to_owned(),
        "unknown_impact_item_type",
    );
    expect_failure(
        &|row| row.grant_id = Some("550E8400-E29B-41D4-A716-446655440000".to_owned()),
        "invalid_char36_grant_id",
    );
}

// ── Compiler bridge ────────────────────────────────────────────────────

#[test]
fn compiler_plan_bridge_maps_changed_segments_only() {
    use policy_engine::{ProjectionKey, SegmentImpact};
    let key_a = ProjectionKey::new(17, 42, "learn_subject:1", "read").unwrap();
    let key_b = ProjectionKey::new(18, 42, "learn_subject:2", "write").unwrap();
    let plan = policy_engine::ImpactPlan {
        affected_keys: vec![key_a.clone(), key_b.clone()],
        affected_segments: vec![
            SegmentImpact {
                key: key_a.clone(),
                segment_id: "segment-a".to_owned(),
                before_content_hash: None,
                after_content_hash: Some(HASH_A.to_owned()),
                content_changed: true,
            },
            // Unchanged segments are intentionally NOT persisted.
            SegmentImpact {
                key: key_b.clone(),
                segment_id: "segment-b".to_owned(),
                before_content_hash: Some(HASH_A.to_owned()),
                after_content_hash: Some(HASH_A.to_owned()),
                content_changed: false,
            },
            SegmentImpact {
                key: ProjectionKey::new(19, 42, "learn_subject:3", "read").unwrap(),
                segment_id: "segment-c".to_owned(),
                before_content_hash: Some(HASH_B.to_owned()),
                after_content_hash: None,
                content_changed: true,
            },
        ],
        full_rebuild: false,
        reason: None,
    };

    let request = impact_plan_request_from_compiler_plan(
        linked_identity(),
        Some(17),
        "evt",
        "op",
        1,
        2,
        0,
        1,
        HASH_A,
        HASH_B,
        "phase2-authorization-kernel-v1",
        &plan,
    )
    .unwrap();

    assert_eq!(request.items.len(), 2, "unchanged segment must drop out");
    let mapped_types: Vec<AuthorizationImpactItemType> =
        request.items.iter().map(|item| item.item_type).collect();
    assert_eq!(
        mapped_types,
        vec![
            AuthorizationImpactItemType::SegmentUpsert,
            AuthorizationImpactItemType::SegmentRemove
        ]
    );
    assert!(request.items.iter().all(|item| item.grant_id.is_none()));
    assert_eq!(request.semantic_hash_hex, HASH_A);
    assert_eq!(request.dependency_hash_hex, HASH_B);

    // A segment carrying no content evidence fails closed.
    let empty_evidence = policy_engine::ImpactPlan {
        affected_keys: vec![],
        affected_segments: vec![SegmentImpact {
            key: key_a,
            segment_id: "segment-d".to_owned(),
            before_content_hash: None,
            after_content_hash: None,
            content_changed: true,
        }],
        full_rebuild: false,
        reason: None,
    };
    assert!(matches!(
        impact_plan_request_from_compiler_plan(
            linked_identity(),
            None,
            "evt",
            "op",
            1,
            2,
            0,
            1,
            HASH_A,
            HASH_B,
            "phase2-authorization-kernel-v1",
            &empty_evidence,
        ),
        Err(AuthorizationProjectionError::Mapping(ref message))
            if message.contains("impact_item_without_content_evidence")
    ));
}

// ── Linkage validation ─────────────────────────────────────────────────

fn build_claimed_event() -> (ClaimedDeltaEvent, DeltaLeaseIdentity) {
    let delta_json = serde_json::to_string(&astral_types::GrantDelta::add(grant(1))).unwrap();
    let claimed = ClaimedDeltaEvent {
        delta_event_id: 21,
        event_id: "event-delta".to_owned(),
        operation_id: "op-delta".to_owned(),
        event_type: crate::grant_repository::DeltaEventType::Add,
        tenant_id: 7,
        card_id: Some(17),
        aggregate_type: "CARD".to_owned(),
        aggregate_id: 17,
        grant_id: GrantId::parse("550e8400-e29b-41d4-a716-446655440001").unwrap(),
        base_version: 0,
        target_version: 1,
        source_generation: 5,
        revoke_fence: 2,
        before_image_json: None,
        before_digest: None,
        delta_json,
        semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
        dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
        compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        attempts: 1,
        cas_version: 4,
        lease_owner: "worker-x".to_owned(),
        lease_expires_at: time::PrimitiveDateTime::new(
            time::Date::from_calendar_date(2031, time::Month::March, 3).unwrap(),
            time::Time::MIDNIGHT,
        ),
    };
    let lease_identity = DeltaLeaseIdentity {
        delta_event_id: 21,
        event_id: "event-delta".to_owned(),
        lease_owner: "worker-x".to_owned(),
        lease_token: crate::grant_repository::DeltaLeaseToken::for_test("token-x"),
    };
    (claimed, lease_identity)
}

fn linkage_pair(
    claimed: &ClaimedDeltaEvent,
) -> (
    AuthorizationDeltaLinkageView,
    DeltaProjectorExpectation,
    PublishRevokeFenceEvidence,
    CompileModeEvidence,
) {
    let view = AuthorizationDeltaLinkageView::from_claimed_row(claimed).unwrap();
    let expectation = DeltaProjectorExpectation {
        identity: view.identity.clone(),
        card_id: view.card_id,
        event_id: view.event_id.clone(),
        operation_id: view.operation_id.clone(),
        base_version: view.base_version,
        target_version: view.target_version,
        source_generation: view.source_generation,
        semantic_hash_hex: view.semantic_hash.as_hex(),
        dependency_hash_hex: view.dependency_hash.as_hex(),
        compiler_version: view.compiler_version.clone(),
    };
    let fences = PublishRevokeFenceEvidence {
        previous_revoke_fence: 2,
        new_revoke_fence: 2,
    };
    let mode = CompileModeEvidence {
        compile_mode: astral_types::ProjectionCompileMode::Incremental,
        full_rebuild_reason: None,
    };
    (view, expectation, fences, mode)
}

#[test]
fn linkage_happy_path_agrees_on_every_dimension() {
    let (claimed, _lease) = build_claimed_event();
    let (view, expectation, fences, mode) = linkage_pair(&claimed);
    assert!(validate_delta_projector_linkage(&view, &expectation, fences, &mode).is_ok());

    // The view builds identically from a client-side claim object.
    let client_view = AuthorizationDeltaLinkageView::from_claim(&DeltaEventClaim {
        delta_event_id: claimed.delta_event_id,
        event_id: claimed.event_id.clone(),
        operation_id: claimed.operation_id.clone(),
        event_type: claimed.event_type,
        tenant_id: claimed.tenant_id,
        card_id: claimed.card_id,
        aggregate_type: claimed.aggregate_type.clone(),
        aggregate_id: claimed.aggregate_id,
        grant_id: claimed.grant_id,
        base_version: claimed.base_version,
        target_version: claimed.target_version,
        source_generation: claimed.source_generation,
        revoke_fence: claimed.revoke_fence,
        before_image_json: claimed.before_image_json.clone(),
        before_digest: claimed.before_digest,
        delta_json: claimed.delta_json.clone(),
        semantic_hash: claimed.semantic_hash,
        dependency_hash: claimed.dependency_hash,
        compiler_version: claimed.compiler_version.clone(),
        attempts: claimed.attempts,
        cas_version: claimed.cas_version,
        lease_owner: claimed.lease_owner.clone(),
        lease_token: crate::grant_repository::DeltaLeaseToken::for_test("t"),
        lease_expires_at: claimed.lease_expires_at,
    })
    .unwrap();
    assert_eq!(client_view, view);
}

#[test]
fn linkage_refuses_each_drift_dimension_with_distinct_codes() {
    let (claimed, _) = build_claimed_event();
    let (view, expectation, fences, mode) = linkage_pair(&claimed);
    let run = |expectation: &DeltaProjectorExpectation,
               fences: PublishRevokeFenceEvidence,
               mode: &CompileModeEvidence| {
        validate_delta_projector_linkage(&view, expectation, fences, mode)
            .err()
            .map(|error| error.to_string())
    };

    let expect_code = |result: Option<String>, needle: &str| {
        let text = result.expect("expected refusal");
        assert!(text.contains(needle), "expected {needle} inside: {text}");
    };

    // Identity / scope / provenance mismatches.
    let mut drifted = expectation.clone();
    drifted.identity.aggregate_id = 99;
    expect_code(run(&drifted, fences, &mode), "linkage_identity_mismatch");

    let mut drifted = expectation.clone();
    drifted.card_id = None;
    expect_code(run(&drifted, fences, &mode), "linkage_card_scope_mismatch");

    let mut drifted = expectation.clone();
    drifted.event_id = "other-event".to_owned();
    expect_code(run(&drifted, fences, &mode), "linkage_event_mismatch");

    let mut drifted = expectation.clone();
    drifted.operation_id = "other-op".to_owned();
    expect_code(run(&drifted, fences, &mode), "linkage_operation_mismatch");

    // Version windows.
    let mut drifted = expectation.clone();
    drifted.target_version += 1;
    expect_code(run(&drifted, fences, &mode), "linkage_version_mismatch");

    // Equal-but-invalid windows fail the structural gate even though the
    // equality checks would pass.
    let mut bad_view = view.clone();
    bad_view.base_version = -1;
    bad_view.target_version = -1;
    let mut bad_expectation = expectation.clone();
    bad_expectation.base_version = -1;
    bad_expectation.target_version = -1;
    expect_code(
        validate_delta_projector_linkage(&bad_view, &bad_expectation, fences, &mode)
            .err()
            .map(|error| error.to_string()),
        "linkage_invalid_versions",
    );

    let mut drifted = expectation.clone();
    drifted.source_generation += 1;
    expect_code(
        run(&drifted, fences, &mode),
        "linkage_source_generation_mismatch",
    );

    // Hash trio.
    let mut drifted = expectation.clone();
    drifted.semantic_hash_hex = HASH_B.to_owned();
    expect_code(run(&drifted, fences, &mode), "linkage_semantic_mismatch");

    let mut drifted = expectation.clone();
    drifted.dependency_hash_hex = HASH_A.to_owned();
    expect_code(run(&drifted, fences, &mode), "linkage_dependency_mismatch");

    let mut drifted = expectation.clone();
    drifted.compiler_version = "other-compiler".to_owned();
    expect_code(run(&drifted, fences, &mode), "linkage_compiler_mismatch");

    // Fence evidence: regression and publish fences below the claimed
    // delta's stored fence are refused. Half-supplied pairs cannot even be
    // constructed anymore (mandatory `u64` fields).
    expect_code(
        run(
            &expectation,
            PublishRevokeFenceEvidence {
                previous_revoke_fence: 5,
                new_revoke_fence: 4,
            },
            &mode,
        ),
        "fence_regression",
    );
    expect_code(
        run(
            &expectation,
            PublishRevokeFenceEvidence {
                previous_revoke_fence: 0,
                new_revoke_fence: 0,
            },
            &mode,
        ),
        "fence_below_claimed_delta",
    );

    // Compile-mode/reason consistency.
    expect_code(
        run(
            &expectation,
            fences,
            &CompileModeEvidence {
                compile_mode: astral_types::ProjectionCompileMode::FullRebuild,
                full_rebuild_reason: None,
            },
        ),
        "full_rebuild_requires_reason",
    );
    expect_code(
        run(
            &expectation,
            fences,
            &CompileModeEvidence {
                compile_mode: astral_types::ProjectionCompileMode::Incremental,
                full_rebuild_reason: Some(policy_engine::FullRebuildReason::DependencyChanged),
            },
        ),
        "reason_without_full_rebuild",
    );
    assert!(validate_compile_mode_evidence(&CompileModeEvidence {
        compile_mode: astral_types::ProjectionCompileMode::FullRebuild,
        full_rebuild_reason: Some(policy_engine::FullRebuildReason::WildcardImpact),
    })
    .is_ok());
}

// ── Archive intents ────────────────────────────────────────────────────

#[test]
fn archive_outbox_vocabulary_and_transitions_are_explicit() {
    for (text, expected) in [
        ("PENDING", AuthorizationArchiveOutboxStatus::Pending),
        ("LEASED", AuthorizationArchiveOutboxStatus::Leased),
        ("SUCCEEDED", AuthorizationArchiveOutboxStatus::Succeeded),
        ("QUARANTINED", AuthorizationArchiveOutboxStatus::Quarantined),
    ] {
        assert_eq!(
            AuthorizationArchiveOutboxStatus::parse(text).unwrap(),
            expected
        );
        assert_eq!(expected.as_str(), text);
    }
    assert!(AuthorizationArchiveOutboxStatus::parse("ARCHIVED").is_err());

    use AuthorizationArchiveOutboxStatus::*;
    assert!(Pending.can_transition_to(Leased));
    assert!(Leased.can_transition_to(Pending));
    assert!(Leased.can_transition_to(Succeeded));
    assert!(Pending.can_transition_to(Quarantined));
    assert!(Leased.can_transition_to(Quarantined));
    for (from, to) in [
        (Succeeded, Pending),
        (Quarantined, Leased),
        (Succeeded, Leased),
    ] {
        assert!(!from.can_transition_to(to));
    }
}

#[test]
fn archive_lease_tokens_redact_debug_and_hash_deterministically() {
    let token = ArchiveLeaseToken::for_test("run-token-archive");
    assert_eq!(format!("{token:?}"), "ArchiveLeaseToken(REDACTED)");
    assert_eq!(
        token.token_hash(),
        Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"run-token-archive"))
    );
    assert_ne!(
        token.token_hash(),
        ArchiveLeaseToken::for_test("run-token-other").token_hash()
    );
}

/// Shape guard for the bounded-retry predicate: a PENDING row carrying a
/// future `next_attempt_at` must be non-claimable, while expired leases
/// stay reclaimable. The candidate selection and the install CAS must
/// repeat the SAME eligibility arm so a racing install can never widen
/// eligibility. (Runtime behavior on real MySQL belongs to the explicit
/// integration suite; this pins the durable contract text itself.)
#[test]
fn archive_claim_predicate_respects_future_pending_backoff_in_candidates_and_install() {
    const FUTURE_GUARD: &str = "(next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP())";
    const EXPIRED_LEASE_GUARD: &str = "(status = 'LEASED' \
           AND lease_expires_at IS NOT NULL \
           AND lease_expires_at <= UTC_TIMESTAMP())";
    for (name, sql) in [
        ("unscoped_candidate", ARCHIVE_CLAIM_CANDIDATE_UNSCOPED_SQL),
        (
            "card_scoped_candidate",
            ARCHIVE_CLAIM_CANDIDATE_CARD_SCOPED_SQL,
        ),
        ("install", ARCHIVE_CLAIM_INSTALL_SQL),
    ] {
        assert!(
            sql.contains(FUTURE_GUARD),
            "{name} must refuse future-scheduled PENDING rows"
        );
        assert!(
            sql.contains(EXPIRED_LEASE_GUARD),
            "{name} must keep reclaiming only expired leases"
        );
        // Exactly one PENDING arm: no legacy unguarded fragment may remain.
        let pending_arms = sql.matches("status = 'PENDING'").count();
        let guarded_arms = sql.matches("status = 'PENDING' AND").count();
        assert_eq!(pending_arms, 1, "{name} must keep a single PENDING arm");
        assert_eq!(
            guarded_arms, 1,
            "{name}'s single PENDING arm must carry the backoff guard"
        );
        assert!(
            !sql.contains("(status = 'PENDING')"),
            "{name} must not retain the unguarded PENDING arm"
        );
    }
}

#[test]
fn archivable_chain_digest_readback_refuses_unarchivable_statuses_without_reading() {
    // Pure status-gate check via the documented vocabulary: only COMMITTED
    // and SUPERSEDED are archivable terminal states.
    assert_eq!(
        AuthorizationManifestStatus::parse(MANIFEST_STATUS_COMMITTED).unwrap(),
        AuthorizationManifestStatus::Committed
    );
    assert_eq!(
        AuthorizationManifestStatus::parse(MANIFEST_STATUS_SUPERSEDED).unwrap(),
        AuthorizationManifestStatus::Superseded
    );
    for refused in [
        MANIFEST_STATUS_BUILDING,
        MANIFEST_STATUS_READY,
        MANIFEST_STATUS_QUARANTINED,
    ] {
        assert_ne!(
            AuthorizationManifestStatus::parse(refused).unwrap(),
            AuthorizationManifestStatus::Committed
        );
        assert_ne!(
            AuthorizationManifestStatus::parse(refused).unwrap(),
            AuthorizationManifestStatus::Superseded
        );
    }
}

#[test]
fn archive_key_derivation_is_deterministic_bounded_and_typed() {
    let identity = linked_identity();
    let first = derive_archive_key(&identity, 4).unwrap();
    let second = derive_archive_key(&linked_identity(), 4).unwrap();
    assert_eq!(first, second);
    assert!(first.starts_with("astral-auth-archive/v1/7/CARD/17/generation-4"));
    assert!(first.len() <= MAX_ARCHIVE_KEY_LENGTH);
    // Different generations/aggregates never collide silently.
    assert_ne!(derive_archive_key(&identity, 5).unwrap(), first);
    let foreign = ProjectionAggregateIdentity::new(8, "RULE_SET", 17).unwrap();
    assert_ne!(derive_archive_key(&foreign, 4).unwrap(), first);
}

fn pointer_record(generation: u64, manifest_id: i64) -> AuthorizationCurrentPointerRecord {
    AuthorizationCurrentPointerRecord {
        pointer_id: 5,
        identity: linked_identity(),
        card_id: Some(17),
        current_generation: generation,
        manifest_id,
        event_id: "parent-event".to_owned(),
        operation_id: "parent-op".to_owned(),
        semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
        dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
        compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        revoke_fence: 2,
        revoke_fence_proven: true,
        cas_version: 12,
    }
}

#[test]
fn archive_decision_requires_a_real_parent_and_first_publish_stays_clean() {
    match decide_archive_intent(None) {
        ArchiveIntentRequirement::NoArchiveRequired => {}
        ArchiveIntentRequirement::Required { .. } => panic!("first publish must not archive"),
    }
    match decide_archive_intent(Some(&pointer_record(3, 44))) {
        ArchiveIntentRequirement::NoArchiveRequired => panic!("parent demands an intent"),
        ArchiveIntentRequirement::Required { parent_pointer } => {
            assert_eq!(parent_pointer.manifest_id, 44);
            assert_eq!(parent_pointer.current_generation, 3);
            assert_eq!(parent_pointer.event_id, "parent-event");
        }
    }
}

fn archive_raw_row() -> ArchiveOutboxRawSqlRow {
    ArchiveOutboxRawSqlRow {
        archive_outbox_id: 77,
        tenant_id: 7,
        card_id: Some(17),
        aggregate_type: "CARD".to_owned(),
        aggregate_id: 17,
        manifest_id: 44,
        generation: 3,
        event_id: "parent-event".to_owned(),
        operation_id: "parent-op".to_owned(),
        archive_key: "astral-auth-archive/v1/7/CARD/17/generation-3".to_owned(),
        semantic_hash: vec![1u8; 32],
        dependency_hash: vec![2u8; 32],
        compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        archived_revoke_fence: 2,
        status: "PENDING".to_owned(),
        attempts: 0,
        cas_version: 1,
        archived_at: None,
    }
}

fn archive_request_from(row: &ArchiveOutboxRawSqlRow) -> AuthorizationArchiveIntentAppendRequest {
    AuthorizationArchiveIntentAppendRequest {
        identity: ProjectionAggregateIdentity::new(
            row.tenant_id,
            row.aggregate_type.clone(),
            row.aggregate_id,
        )
        .unwrap(),
        card_id: row.card_id,
        archived_manifest_id: row.manifest_id,
        archived_generation: row.generation as u64,
        event_id: row.event_id.clone(),
        operation_id: row.operation_id.clone(),
        archive_key: row.archive_key.clone(),
        semantic_hash_hex: hex::encode(&row.semantic_hash),
        dependency_hash_hex: hex::encode(&row.dependency_hash),
        compiler_version: row.compiler_version.clone(),
        archived_revoke_fence: row.archived_revoke_fence as u64,
    }
}

#[test]
fn archive_decode_enforces_status_stamp_discipline_and_replay_equivalence() {
    let row = archive_raw_row();
    let decoded = row.decode().unwrap();
    assert_eq!(decoded.status, AuthorizationArchiveOutboxStatus::Pending);
    assert!(decoded.archived_at.is_none());
    assert_eq!(decoded.archived_manifest_id, 44);

    // Replay equivalence holds byte-for-byte...
    let request = archive_request_from(&row);
    row.assert_equivalent_replay(
        &request,
        &Sha256Digest::from_bytes(vec![1u8; 32]).unwrap(),
        &Sha256Digest::from_bytes(vec![2u8; 32]).unwrap(),
    )
    .unwrap();

    // ...and every immutable dimension surfaces an explicit conflict.
    let expect_conflict = |mutate: &dyn Fn(&mut AuthorizationArchiveIntentAppendRequest),
                           needle: &str| {
        let mut drifted = request.clone();
        mutate(&mut drifted);
        let error = archive_raw_row()
            .assert_equivalent_replay(
                &drifted,
                &Sha256Digest::from_bytes(vec![1u8; 32]).unwrap(),
                &Sha256Digest::from_bytes(vec![2u8; 32]).unwrap(),
            )
            .unwrap_err()
            .to_string();
        assert!(error.contains(needle), "expected {needle} inside: {error}");
    };
    expect_conflict(
        &|request: &mut AuthorizationArchiveIntentAppendRequest| request.identity.aggregate_id = 18,
        "archive_replay_identity",
    );
    expect_conflict(
        &|request: &mut AuthorizationArchiveIntentAppendRequest| request.card_id = None,
        "archive_replay_card_scope",
    );
    expect_conflict(
        &|request: &mut AuthorizationArchiveIntentAppendRequest| request.archived_manifest_id = 45,
        "archive_replay_manifest",
    );
    expect_conflict(
        &|request: &mut AuthorizationArchiveIntentAppendRequest| request.archived_generation = 4,
        "archive_replay_generation",
    );
    expect_conflict(
        &|request: &mut AuthorizationArchiveIntentAppendRequest| {
            request.event_id = "other".to_owned()
        },
        "archive_replay_event",
    );
    expect_conflict(
        &|request: &mut AuthorizationArchiveIntentAppendRequest| {
            request.operation_id = "other".to_owned()
        },
        "archive_replay_operation",
    );
    expect_conflict(
        &|request: &mut AuthorizationArchiveIntentAppendRequest| {
            request.archive_key = "drift".to_owned()
        },
        "archive_replay_key",
    );
    expect_conflict(
        &|request: &mut AuthorizationArchiveIntentAppendRequest| {
            request.compiler_version = "other".to_owned()
        },
        "archive_replay_compiler",
    );
    // The copied parent fence participates in immutable replay too.
    assert_eq!(decoded.archived_revoke_fence, 2);
    expect_conflict(
        &|request: &mut AuthorizationArchiveIntentAppendRequest| request.archived_revoke_fence = 3,
        "archive_replay_revoke_fence",
    );
    // Hash drift is detected through the paired digest comparison.
    let error = archive_raw_row()
        .assert_equivalent_replay(
            &request,
            &Sha256Digest::from_bytes(vec![9u8; 32]).unwrap(),
            &Sha256Digest::from_bytes(vec![2u8; 32]).unwrap(),
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("archive_replay_hash"), "{error}");

    // Stamp discipline: success without a timestamp and a timestamp
    // without success are BOTH corrupt state.
    let succeeded_late = ArchiveOutboxRawSqlRow {
        status: "SUCCEEDED".to_owned(),
        ..archive_raw_row()
    };
    assert!(succeeded_late.decode().is_err());
    let stamped_pending = ArchiveOutboxRawSqlRow {
        archived_at: Some(time::PrimitiveDateTime::new(
            time::Date::from_calendar_date(2030, time::Month::May, 5).unwrap(),
            time::Time::MIDNIGHT,
        )),
        ..archive_raw_row()
    };
    assert!(stamped_pending.decode().is_err());
    // Negative counters refuse too.
    let negative_attempts = ArchiveOutboxRawSqlRow {
        attempts: -1,
        ..archive_raw_row()
    };
    assert!(negative_attempts.decode().is_err());
}

#[test]
fn archive_statements_pin_guards_and_never_delete_or_randomize() {
    assert_eq!(ARCHIVE_INTENT_INSERT_SQL.matches('?').count(), 13);
    assert!(ARCHIVE_INTENT_INSERT_SQL.ends_with("'PENDING')"));
    assert!(
        ARCHIVE_MANIFEST_INSERT_SQL.matches('?').count() == 14,
        "{ARCHIVE_MANIFEST_INSERT_SQL}"
    );
    assert!(
        ARCHIVE_INTENT_INSERT_SQL.contains("archived_revoke_fence"),
        "intent insert must persist the copied parent fence"
    );
    assert!(
        ARCHIVE_MANIFEST_INSERT_SQL.contains("archived_revoke_fence"),
        "manifest proof insert must persist the parent fence"
    );
    assert!(ARCHIVE_INTENT_BY_EVENT_TAIL.contains("WHERE event_id = ? FOR UPDATE"));
    assert!(ARCHIVE_INTENT_BY_GENERATION_TAIL
        .contains("AND aggregate_type = ? AND aggregate_id = ? AND generation = ?"));

    // Candidate selection keeps the delta-queue discipline: future-scheduled
    // PENDING rows wait for their backoff stamp, expired leases stay
    // reclaimable, deterministic order, row lock, no live stealing.
    for statement in [
        ARCHIVE_CLAIM_CANDIDATE_UNSCOPED_SQL,
        ARCHIVE_CLAIM_CANDIDATE_CARD_SCOPED_SQL,
        ARCHIVE_CLAIM_INSTALL_SQL,
    ] {
        assert!(
            statement.contains(
                "status = 'PENDING' \
                     AND (next_attempt_at IS NULL OR next_attempt_at <= UTC_TIMESTAMP())"
            ),
            "{statement}"
        );
        assert!(
            statement.contains("lease_expires_at <= UTC_TIMESTAMP()"),
            "{statement}"
        );
        assert!(
            !statement.contains("(status = 'PENDING')"),
            "the unguarded PENDING arm must never come back: {statement}"
        );
        if statement != ARCHIVE_CLAIM_INSTALL_SQL {
            assert!(statement.contains("FOR UPDATE"));
            assert!(
                statement.contains("ORDER BY COALESCE(next_attempt_at, created_at)"),
                "{statement}"
            );
        }
    }
    assert!(!ARCHIVE_CLAIM_CANDIDATE_UNSCOPED_SQL.contains("lease_expires_at >= UTC_TIMESTAMP()"));

    // Install stores only the token HASH and bumps counters.
    assert!(ARCHIVE_CLAIM_INSTALL_SQL.contains("lease_token_hash = ?"));
    assert!(ARCHIVE_CLAIM_INSTALL_SQL.contains("cas_version = cas_version + 1"));
    assert!(ARCHIVE_CLAIM_INSTALL_SQL.contains("attempts = attempts + 1"));

    // Guard suffix covers ownership, status and liveness for every mutation.
    for fragment in [
        "AND status = 'LEASED'",
        "AND lease_owner = ?",
        "AND lease_token_hash = ?",
        "lease_expires_at IS NOT NULL",
        "lease_expires_at > UTC_TIMESTAMP()",
    ] {
        assert!(ARCHIVE_LEASE_GUARD_SUFFIX.contains(fragment), "{fragment}");
    }
    assert!(ARCHIVE_COMPLETE_SQL_BASE.contains("archived_at = UTC_TIMESTAMP()"));
    assert!(ARCHIVE_FAIL_SQL_BASE.contains("TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP())"));
    assert!(ARCHIVE_RELEASE_SQL_BASE.contains("next_attempt_at = NULL"));

    for statement in [
        ARCHIVE_CLAIM_INSTALL_SQL,
        ARCHIVE_LEASE_GUARD_SUFFIX,
        ARCHIVE_COMPLETE_SQL_BASE,
        ARCHIVE_FAIL_SQL_BASE,
        ARCHIVE_RELEASE_SQL_BASE,
    ] {
        assert!(!statement.to_uppercase().contains("DELETE"));
    }
}

// ── Combined projector command shape ───────────────────────────────────

fn shaped_stage() -> AuthorizationStageRequest {
    AuthorizationStageRequest {
        identity: linked_identity(),
        card_id: Some(17),
        target_generation: 2,
        source_generation: 5,
        projected_generation: 5,
        event_id: "event-delta".to_owned(),
        operation_id: "op-delta".to_owned(),
        semantic_hash_hex: HASH_A.to_owned(),
        dependency_hash_hex: HASH_B.to_owned(),
        compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        revoke_fence: 2,
        segments: vec![StagedSegmentContent::New(vec![grant(1)])],
    }
}

fn shaped_plan() -> AuthorizationImpactPlanAppendRequest {
    AuthorizationImpactPlanAppendRequest {
        identity: linked_identity(),
        card_id: Some(17),
        event_id: "event-delta".to_owned(),
        operation_id: "op-delta".to_owned(),
        base_generation: 1,
        target_generation: 2,
        base_version: 0,
        target_version: 1,
        semantic_hash_hex: HASH_A.to_owned(),
        dependency_hash_hex: HASH_B.to_owned(),
        compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        items: vec![impact_item_upsert("{\"action\":\"read\",\"cardId\":17}")],
    }
}

fn shaped_command() -> DeltaProjectorPublishCommand {
    let (_, lease_identity) = build_claimed_event();
    DeltaProjectorPublishCommand {
        delta_lease_identity: lease_identity,
        expectation: DeltaProjectorExpectation {
            identity: linked_identity(),
            card_id: Some(17),
            event_id: "event-delta".to_owned(),
            operation_id: "op-delta".to_owned(),
            base_version: 0,
            target_version: 1,
            source_generation: 5,
            semantic_hash_hex: HASH_A.to_owned(),
            dependency_hash_hex: HASH_B.to_owned(),
            compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        },
        fences: PublishRevokeFenceEvidence {
            previous_revoke_fence: 2,
            new_revoke_fence: 2,
        },
        mode: CompileModeEvidence {
            compile_mode: astral_types::ProjectionCompileMode::Incremental,
            full_rebuild_reason: None,
        },
        stage: shaped_stage(),
        finalize_expected_reference_count: Some(1),
        impact_plan: shaped_plan(),
        manifest_lease_owner: "worker-x".to_owned(),
        manifest_lease_seconds: 120,
    }
}

#[test]
fn command_shape_accepts_the_fully_aligned_package() {
    let command = shaped_command();
    assert!(validate_projector_command_shape(&command).is_ok());
}

#[test]
fn command_shape_refuses_cross_component_drift_before_any_sql_runs() {
    let expect_refusal = |mutate: &dyn Fn(&mut DeltaProjectorPublishCommand), needle: &str| {
        let mut command = shaped_command();
        mutate(&mut command);
        let error = validate_projector_command_shape(&command)
            .unwrap_err()
            .to_string();
        assert!(error.contains(needle), "expected {needle} inside: {error}");
    };

    expect_refusal(
        &|command| command.stage.identity.aggregate_id = 18,
        "command_identity_mismatch",
    );
    expect_refusal(
        &|command| command.impact_plan.card_id = None,
        "command_card_scope_mismatch",
    );
    expect_refusal(
        &|command| command.impact_plan.event_id = "other".to_owned(),
        "command_provenance_mismatch",
    );
    expect_refusal(
        &|command| command.stage.operation_id = "other".to_owned(),
        "command_provenance_mismatch",
    );
    expect_refusal(
        &|command| command.stage.source_generation = 6,
        "command_source_generation_mismatch",
    );
    expect_refusal(
        &|command| {
            command.impact_plan.semantic_hash_hex = HASH_B.to_owned();
        },
        "command_hash_mismatch",
    );
    expect_refusal(
        &|command| command.stage.compiler_version = "other".to_owned(),
        "command_compiler_mismatch",
    );
    expect_refusal(
        &|command| {
            command.impact_plan.target_version = 9;
        },
        "command_version_window_mismatch",
    );

    // Mode evidence re-validates through the shape gate.
    expect_refusal(
        &|command| {
            command.mode.compile_mode = astral_types::ProjectionCompileMode::FullRebuild;
            command.mode.full_rebuild_reason = None;
        },
        "full_rebuild_requires_reason",
    );

    // Malformed items stay away from SQL entirely.
    expect_refusal(
        &|command| {
            let mut broken = impact_item_upsert("{\"action\":\"read\"}");
            broken.after_digest_hex = None;
            command.impact_plan.items = vec![broken];
        },
        "upsert_requires_after_digest",
    );

    // An empty item list is refused like any other plan draft.
    expect_refusal(
        &|command| command.impact_plan.items = Vec::new(),
        "empty_impact_plan",
    );
}

// ── Segment-local seals (fix A) ─────────────────────────────────────────

fn sealed_snapshot(
    identity: &ProjectionAggregateIdentity,
    card_id: Option<i64>,
    compiler_version: &str,
    grants: &[CanonicalGrant],
    segment_id: i64,
) -> AuthorizationSegmentSnapshot {
    let payload = encode_segment_payload(grants).unwrap();
    let content_digest = Sha256Digest::from_raw_bytes(sha256_digest_bytes(&payload));
    let (semantic, dependency) = segment_local_seal_pair(
        identity,
        card_id,
        compiler_version,
        grants.len() as u64,
        &content_digest,
    )
    .unwrap();
    AuthorizationSegmentSnapshot {
        segment_id,
        identity: identity.clone(),
        card_id,
        content_digest,
        semantic_hash: semantic,
        dependency_hash: dependency,
        compiler_version: compiler_version.to_owned(),
        format: SEGMENT_FORMAT_AUTHORIZATION_GRANTS_JSON_V1.to_owned(),
        row_count: grants.len() as u64,
        byte_size: payload.len() as u64,
        grants: grants.to_vec(),
    }
}

#[test]
fn segment_local_seals_bind_every_immutable_dimension_and_stay_generation_invariant() {
    let identity = identity();
    let snapshot = sealed_snapshot(&identity, Some(17), "compiler-v1", &[grant(1)], 9);

    // Deterministic: recomputation reproduces both seals exactly.
    let recomputed = segment_local_seal_pair(
        &identity,
        Some(17),
        "compiler-v1",
        snapshot.row_count,
        &snapshot.content_digest,
    )
    .unwrap();
    assert_eq!(snapshot.semantic_hash, recomputed.0);
    assert_eq!(snapshot.dependency_hash, recomputed.1);
    // Distinct domain tags never collide.
    assert_ne!(snapshot.semantic_hash, snapshot.dependency_hash);

    // Every bound dimension moves at least one seal when it drifts.
    for mutation in [
        "tenant",
        "aggregate",
        "card",
        "compiler",
        "row_count",
        "content_digest",
    ] {
        let drifted_input = |identity_ref: &ProjectionAggregateIdentity,
                             card: Option<i64>,
                             compiler: &str,
                             row_count: u64,
                             digest: &Sha256Digest| {
            segment_local_seal_pair(identity_ref, card, compiler, row_count, digest).unwrap()
        };
        let (semantic, dependency) = match mutation {
            "tenant" => drifted_input(
                &ProjectionAggregateIdentity::new(8, "CARD", 17).unwrap(),
                Some(17),
                "compiler-v1",
                1,
                &snapshot.content_digest,
            ),
            "aggregate" => drifted_input(
                &ProjectionAggregateIdentity::new(7, "CARD", 18).unwrap(),
                Some(17),
                "compiler-v1",
                1,
                &snapshot.content_digest,
            ),
            "card" => drifted_input(&identity, None, "compiler-v1", 1, &snapshot.content_digest),
            "compiler" => drifted_input(
                &identity,
                Some(17),
                "compiler-v2",
                1,
                &snapshot.content_digest,
            ),
            "row_count" => drifted_input(
                &identity,
                Some(17),
                "compiler-v1",
                2,
                &snapshot.content_digest,
            ),
            _ => drifted_input(
                &identity,
                Some(17),
                "compiler-v1",
                1,
                &Sha256Digest::from_hex(HASH_B).unwrap(),
            ),
        };
        assert_ne!(
            snapshot.semantic_hash, semantic,
            "{mutation} must move the semantic seal"
        );
        assert_ne!(
            snapshot.dependency_hash, dependency,
            "{mutation} must move the dependency seal"
        );
    }
}

#[test]
fn verify_segment_local_seal_refuses_tampered_metadata_fail_closed() {
    let identity = identity();
    let base = sealed_snapshot(&identity, Some(17), "compiler-v1", &[grant(1)], 9);
    verify_segment_local_seal(&base).unwrap();

    // Tampering ANY local dimension without recomputing the seals is
    // corrupt storage. This includes compiler stamps and LOCAL hash
    // columns, which no longer compare against any manifest-global value.
    let mut tampered = base.clone();
    tampered.card_id = None;
    assert!(verify_segment_local_seal(&tampered).is_err());

    let mut tampered = base.clone();
    tampered.compiler_version = "compiler-v2".to_owned();
    assert!(verify_segment_local_seal(&tampered).is_err());

    let mut tampered = base.clone();
    tampered.row_count = 4;
    assert!(verify_segment_local_seal(&tampered).is_err());

    let mut tampered = base.clone();
    tampered.semantic_hash = Sha256Digest::from_hex(HASH_B).unwrap();
    assert!(verify_segment_local_seal(&tampered).is_err());

    let mut tampered = base.clone();
    tampered.dependency_hash = Sha256Digest::from_hex(HASH_A).unwrap();
    assert!(verify_segment_local_seal(&tampered).is_err());

    let mut tampered = base.clone();
    tampered.content_digest = Sha256Digest::from_hex(HASH_B).unwrap();
    assert!(verify_segment_local_seal(&tampered).is_err());
}

#[test]
fn identical_segment_verification_reports_compiler_stamp_divergence_as_its_own_code() {
    let identity = linked_identity();
    let request = shaped_stage();
    let grants = vec![grant(1)];

    // Baseline: the same stamp reproduces a byte-identical admissible row.
    let snapshot = sealed_snapshot(
        &identity,
        Some(17),
        request.compiler_version.as_str(),
        &grants,
        9,
    );
    let (semantic_seal, dependency_seal) = segment_local_seal_pair(
        &request.identity,
        request.card_id,
        request.compiler_version.as_str(),
        snapshot.row_count,
        &snapshot.content_digest,
    )
    .unwrap();
    assert_identical_segment(
        &snapshot,
        &request,
        &snapshot.content_digest,
        &semantic_seal,
        &dependency_seal,
        request.compiler_version.as_str(),
    )
    .unwrap();

    // A future compiler upgrade that legitimately reuses the byte-identical
    // payload hits the one-row-per-digest key with a diverging stamp. The
    // payload is proven intact, so this carries the dedicated machine code
    // and is NEVER labeled `digest_metadata_collision` (corruption family).
    let upgraded_request_compiler = "phase2-authorization-kernel-v2";
    let (upgraded_semantic, upgraded_dependency) = segment_local_seal_pair(
        &request.identity,
        request.card_id,
        upgraded_request_compiler,
        snapshot.row_count,
        &snapshot.content_digest,
    )
    .unwrap();
    let error = assert_identical_segment(
        &snapshot,
        &request,
        &snapshot.content_digest,
        &upgraded_semantic,
        &upgraded_dependency,
        upgraded_request_compiler,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains(SEGMENT_COMPILER_STAMP_DIVERGENCE_CODE),
        "compiler stamp divergence must report its dedicated code: {error}"
    );
    assert!(
        !error.contains("digest_metadata_collision"),
        "proven-intact content must not be labeled corrupt: {error}"
    );

    // The corruption-family codes stay exactly where they were: a seal
    // mismatch under the SAME stamp (tampered columns) and a foreign
    // format stamp.
    let mut corrupted_seals = snapshot.clone();
    corrupted_seals.semantic_hash = Sha256Digest::from_hex(HASH_B).unwrap();
    let error = assert_identical_segment(
        &corrupted_seals,
        &request,
        &snapshot.content_digest,
        &semantic_seal,
        &dependency_seal,
        request.compiler_version.as_str(),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("digest_metadata_collision"), "{error}");

    let mut foreign_format = snapshot.clone();
    foreign_format.format = "foreign_format".to_owned();
    let error = assert_identical_segment(
        &foreign_format,
        &request,
        &snapshot.content_digest,
        &semantic_seal,
        &dependency_seal,
        request.compiler_version.as_str(),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("digest_metadata_collision"), "{error}");

    // Cross-scope reuse of one digest is still a hard collision.
    let foreign_request = AuthorizationStageRequest {
        identity: ProjectionAggregateIdentity::new(7, "CARD", 18).unwrap(),
        ..shaped_stage()
    };
    let error = assert_identical_segment(
        &snapshot,
        &foreign_request,
        &snapshot.content_digest,
        &semantic_seal,
        &dependency_seal,
        request.compiler_version.as_str(),
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("cross_aggregate_digest_collision"),
        "{error}"
    );
}

/// Generation 1→2 real-delta rehearsal, purely: two unchanged segments
/// (`A`, `C`) keep their refs while only `B` is rewritten, and the target
/// manifest's GLOBAL semantic/dependency hashes legitimately move without
/// breaking any seal check.
#[test]
fn generation_delta_reuses_unchanged_segments_and_writes_only_the_changed_one() {
    let identity = identity();
    let compiler = "phase2-authorization-kernel-v1";

    // Generation 1: three NEW segments A / B / C.
    let grants_a = vec![grant(1)];
    let grants_b = vec![grant(2)];
    let grants_c = vec![grant(3)];
    let snap_a = sealed_snapshot(&identity, Some(17), compiler, &grants_a, 101);
    let snap_b = sealed_snapshot(&identity, Some(17), compiler, &grants_b, 102);
    let snap_c = sealed_snapshot(&identity, Some(17), compiler, &grants_c, 103);

    // Parent generation-1 references pointing at those contents.
    let parent_records = vec![
        AuthorizationSegmentReferenceRecord {
            reference_id: 1,
            manifest_id: 500,
            identity: identity.clone(),
            card_id: Some(17),
            generation: 1,
            ordinal: 0,
            segment_id: snap_a.segment_id,
            content_digest: snap_a.content_digest,
            event_id: "event-gen1".to_owned(),
            operation_id: "op-gen1".to_owned(),
        },
        AuthorizationSegmentReferenceRecord {
            reference_id: 2,
            manifest_id: 500,
            identity: identity.clone(),
            card_id: Some(17),
            generation: 1,
            ordinal: 1,
            segment_id: snap_b.segment_id,
            content_digest: snap_b.content_digest,
            event_id: "event-gen1".to_owned(),
            operation_id: "op-gen1".to_owned(),
        },
        AuthorizationSegmentReferenceRecord {
            reference_id: 3,
            manifest_id: 500,
            identity: identity.clone(),
            card_id: Some(17),
            generation: 1,
            ordinal: 2,
            segment_id: snap_c.segment_id,
            content_digest: snap_c.content_digest,
            event_id: "event-gen1".to_owned(),
            operation_id: "op-gen1".to_owned(),
        },
    ];

    // Generation 2 target: real delta moves BOTH global hashes…
    let gen1_semantic = Sha256Digest::from_hex(HASH_A).unwrap();
    let gen1_dependency = Sha256Digest::from_hex(HASH_B).unwrap();
    let gen2_semantic = Sha256Digest::from_hex(HASH_B).unwrap();
    let gen2_dependency = Sha256Digest::from_hex(HASH_A).unwrap();
    assert_ne!(gen1_semantic, gen2_semantic);
    assert_ne!(gen1_dependency, gen2_dependency);

    // …while the unchanged segments' LOCAL seals stay bit-identical (the
    // seal surface excludes generation numbers, provenance and global
    // hashes entirely).
    for (record, snapshot) in [(&parent_records[0], &snap_a), (&parent_records[2], &snap_c)] {
        let recomputed = segment_local_seal_pair(
            &identity,
            Some(17),
            compiler,
            snapshot.row_count,
            &snapshot.content_digest,
        )
        .unwrap();
        assert_eq!(snapshot.semantic_hash, recomputed.0);
        assert_eq!(snapshot.dependency_hash, recomputed.1);
        // The decoupling itself: a seal is NOT the (moved) global hash.
        assert_ne!(snapshot.semantic_hash, gen2_semantic);
        // Reference ↔ content ↔ local-seal pairing survives.
        verify_reference_content_pair(record, snapshot, &identity).unwrap();
    }

    // The generation-2 staging plan: reuse A and C, rewrite B only.
    let grants_b2 = vec![grant(0x22)];
    assert_ne!(
        encode_segment_payload(&grants_b2).unwrap(),
        encode_segment_payload(&grants_b).unwrap(),
        "the B delta must really change segment bytes"
    );
    let snap_b2 = sealed_snapshot(&identity, Some(17), compiler, &grants_b2, -1);
    let plan = vec![
        StagedSegmentContent::ReuseParent { parent_ordinal: 0 },
        StagedSegmentContent::New(grants_b2.clone()),
        StagedSegmentContent::ReuseParent { parent_ordinal: 2 },
    ];
    let counts = validate_staging_plan_against_parent(
        &identity,
        &plan,
        Some(parent_reference_views(&parent_records).as_slice()),
    )
    .unwrap();
    assert_eq!(counts, (1, 2), "only B is written; A and C are true refs");

    // Every dim of the reused rows would satisfy finalize/publish/read:
    // LOCAL seal verification passes per segment, and ONLY the rewritten
    // segment carries a new content address.
    for snapshot in [&snap_a, &snap_c] {
        verify_segment_local_seal(snapshot).unwrap();
    }
    verify_segment_local_seal(&snap_b2).unwrap();
    assert_ne!(snap_b2.content_digest, snap_b.content_digest);
}

#[test]
fn parent_chain_verification_pins_the_parents_own_global_hashes_only() {
    let identity = identity();
    let compiler = "phase2-authorization-kernel-v1";
    let snap_a = sealed_snapshot(&identity, Some(17), compiler, &[grant(1)], 201);
    let snap_b = sealed_snapshot(&identity, Some(17), compiler, &[grant(2)], 202);

    let mut parent_row = ManifestRawSqlRow {
        manifest_id: 700,
        tenant_id: identity.tenant_id,
        card_id: Some(17),
        aggregate_type: identity.aggregate_type.clone(),
        aggregate_id: identity.aggregate_id,
        generation: 1,
        source_generation: 5,
        projected_generation: 5,
        event_id: "event-gen1".to_owned(),
        operation_id: "op-gen1".to_owned(),
        semantic_hash: gen1_hash_vec("semantic"),
        dependency_hash: gen1_hash_vec("dependency"),
        compiler_version: compiler.to_owned(),
        manifest_digest: Vec::new(),
        status: MANIFEST_STATUS_COMMITTED.to_owned(),
        cas_version: 2,
        lease_owner: None,
        lease_token_hash: None,
        lease_expires_at: None,
        parent_manifest_id: None,
        revoke_fence: 0,
    };
    let references = [
        AuthorizationSegmentReferenceRecord {
            reference_id: 11,
            manifest_id: 700,
            identity: identity.clone(),
            card_id: Some(17),
            generation: 1,
            ordinal: 0,
            segment_id: snap_a.segment_id,
            content_digest: snap_a.content_digest,
            event_id: "event-gen1".to_owned(),
            operation_id: "op-gen1".to_owned(),
        },
        AuthorizationSegmentReferenceRecord {
            reference_id: 12,
            manifest_id: 700,
            identity: identity.clone(),
            card_id: Some(17),
            generation: 1,
            ordinal: 1,
            segment_id: snap_b.segment_id,
            content_digest: snap_b.content_digest,
            event_id: "event-gen1".to_owned(),
            operation_id: "op-gen1".to_owned(),
        },
    ];
    // Seal the parent over its OWN hashes plus the ordered digests.
    let semantic_hex = hex::encode(&parent_row.semantic_hash);
    let dependency_hex = hex::encode(&parent_row.dependency_hash);
    let sealed = compute_manifest_digest(&ManifestDigestInput {
        tenant_id: parent_row.tenant_id,
        aggregate_type: &parent_row.aggregate_type,
        aggregate_id: parent_row.aggregate_id,
        card_id: parent_row.card_id,
        generation: 1,
        source_generation: 5,
        projected_generation: 5,
        event_id: &parent_row.event_id,
        operation_id: &parent_row.operation_id,
        semantic_hash_hex: &semantic_hex,
        dependency_hash_hex: &dependency_hex,
        compiler_version: &parent_row.compiler_version,
        parent_manifest_id: parent_row.decode_parent_manifest_id().unwrap(),
        revoke_fence: parent_row.decode_revoke_fence().unwrap(),
        segment_content_digests_hex: vec![
            snap_a.content_digest.as_hex(),
            snap_b.content_digest.as_hex(),
        ],
    })
    .unwrap();
    parent_row.manifest_digest = sealed.as_bytes().to_vec();

    verify_parent_manifest_chain(&parent_row, &references).unwrap();

    // Any internal drift breaks the parent's own seal…
    let mut drifted = parent_row.clone();
    drifted.semantic_hash = gen1_hash_vec("semantic-drift");
    let error = verify_parent_manifest_chain(&drifted, &references).unwrap_err();
    assert!(
        matches!(error, AuthorizationProjectionError::Corrupt(ref message)
            if message.contains("parent_manifest_digest_seal_broken"))
    );

    // …including reordered reference evidence.
    let reordered = [references[1].clone(), references[0].clone()];
    assert!(verify_parent_manifest_chain(&parent_row, &reordered).is_err());

    // Gapped ordinals refuse outright.
    let mut gapped = references.clone();
    gapped[1].ordinal = 3;
    assert!(verify_parent_manifest_chain(&parent_row, &gapped).is_err());
}

fn gen1_hash_vec(seed: &str) -> Vec<u8> {
    sha256_digest_bytes(seed.as_bytes()).to_vec()
}

// ── Archive durable proofs (fix B) ──────────────────────────────────────

fn archive_identity() -> ProjectionAggregateIdentity {
    ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap()
}

fn archive_digest_input<'a>(
    semantic: &'a Sha256Digest,
    dependency: &'a Sha256Digest,
    chain: &'a Sha256Digest,
) -> AuthorizationArchiveDigestInput<'a> {
    AuthorizationArchiveDigestInput {
        tenant_id: 7,
        aggregate_type: "CARD",
        aggregate_id: 17,
        card_id: Some(17),
        archived_manifest_id: 500,
        archived_generation: 3,
        event_id: "event-gen2",
        operation_id: "op-gen2",
        archive_key: "astral-auth-archive/v1/7/CARD/17/generation-3",
        archived_revoke_fence: 2,
        semantic_hash: semantic,
        dependency_hash: dependency,
        compiler_version: "phase2-authorization-kernel-v1",
        manifest_chain_digest: chain,
    }
}

#[test]
fn archive_proof_digest_binds_every_dimension_deterministically() {
    let semantic = Sha256Digest::from_hex(HASH_A).unwrap();
    let dependency = Sha256Digest::from_hex(HASH_B).unwrap();
    let chain = Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"chain"));
    let baseline =
        compute_authorization_archive_digest(&archive_digest_input(&semantic, &dependency, &chain))
            .unwrap();
    // Deterministic across independent invocations.
    assert_eq!(
        baseline,
        compute_authorization_archive_digest(
            &archive_digest_input(&semantic, &dependency, &chain,)
        )
        .unwrap()
    );

    // Each textual/binary dimension participates; statuses/timestamps do
    // not enter the seal by design.
    let alt_chain = Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"other"));
    let base = || archive_digest_input(&semantic, &dependency, &chain);
    let expects = [
        (
            AuthorizationArchiveDigestInput {
                archived_manifest_id: 501,
                ..base()
            },
            "archived_manifest_id",
        ),
        (
            AuthorizationArchiveDigestInput {
                archived_generation: 4,
                ..base()
            },
            "archived_generation",
        ),
        (
            AuthorizationArchiveDigestInput {
                event_id: "event-other",
                ..base()
            },
            "event_id",
        ),
        (
            AuthorizationArchiveDigestInput {
                operation_id: "op-other",
                ..base()
            },
            "operation_id",
        ),
        (
            AuthorizationArchiveDigestInput {
                archive_key: "astral-auth-archive/v1/7/CARD/17/generation-4",
                ..base()
            },
            "archive_key",
        ),
        (
            AuthorizationArchiveDigestInput {
                archived_revoke_fence: 3,
                ..base()
            },
            "archived_revoke_fence",
        ),
        (
            AuthorizationArchiveDigestInput {
                compiler_version: "other-compiler",
                ..base()
            },
            "compiler_version",
        ),
        (
            AuthorizationArchiveDigestInput {
                card_id: None,
                ..base()
            },
            "card_scope",
        ),
        (
            AuthorizationArchiveDigestInput {
                semantic_hash: &dependency,
                ..base()
            },
            "semantic_hash",
        ),
        (
            AuthorizationArchiveDigestInput {
                dependency_hash: &semantic,
                ..base()
            },
            "dependency_hash",
        ),
        (
            AuthorizationArchiveDigestInput {
                manifest_chain_digest: &alt_chain,
                ..base()
            },
            "manifest_chain_digest",
        ),
    ];
    for (input, dimension) in expects {
        let digest = compute_authorization_archive_digest(&input).unwrap();
        assert_ne!(baseline, digest, "{dimension} must move the seal");
    }
}

fn archive_manifest_raw_row(
    status: &str,
    archived_at: Option<time::PrimitiveDateTime>,
) -> ArchiveManifestRawSqlRow {
    ArchiveManifestRawSqlRow {
        archive_manifest_id: 900,
        tenant_id: 7,
        card_id: Some(17),
        aggregate_type: "CARD".to_owned(),
        aggregate_id: 17,
        manifest_id: 500,
        generation: 3,
        event_id: "event-gen2".to_owned(),
        operation_id: "op-gen2".to_owned(),
        archive_key: "astral-auth-archive/v1/7/CARD/17/generation-3".to_owned(),
        archive_digest: sha256_digest_bytes(b"archive").to_vec(),
        semantic_hash: sha256_digest_bytes(b"semantic").to_vec(),
        dependency_hash: sha256_digest_bytes(b"dependency").to_vec(),
        compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        archived_revoke_fence: 2,
        status: status.to_owned(),
        cas_version: 1,
        archived_at,
    }
}

fn stamp() -> time::PrimitiveDateTime {
    time::PrimitiveDateTime::new(
        time::Date::from_calendar_date(2031, time::Month::March, 3).unwrap(),
        time::Time::MIDNIGHT,
    )
}

#[test]
fn archive_manifest_status_vocabulary_and_stamp_parity_fail_closed() {
    // Status vocabulary mirrors the schema default plus one terminal word.
    assert_eq!("STAGED", ARCHIVE_MANIFEST_STATUS_STAGED);
    assert_eq!("ARCHIVED", ARCHIVE_MANIFEST_STATUS_ARCHIVED);
    assert!(AuthorizationArchiveManifestStatus::parse("PENDING").is_err());
    assert!(AuthorizationArchiveManifestStatus::parse("").is_err());
    assert!(AuthorizationArchiveManifestStatus::Staged
        .can_transition_to(AuthorizationArchiveManifestStatus::Archived));
    assert!(!AuthorizationArchiveManifestStatus::Archived
        .can_transition_to(AuthorizationArchiveManifestStatus::Staged));

    // Terminal-with-stamp and staged-without-stamp decode cleanly.
    assert!(archive_manifest_raw_row("ARCHIVED", Some(stamp()))
        .decode()
        .is_ok());
    assert!(archive_manifest_raw_row("STAGED", None).decode().is_ok());

    // Parity violations are corrupt storage, never normalized away.
    for (status, stamp_value, expected_code) in [
        ("ARCHIVED", None, "archive_terminal_without_stamp"),
        (
            "STAGED",
            Some(stamp()),
            "archive_stamp_without_terminal_status",
        ),
    ] {
        let error = archive_manifest_raw_row(status, stamp_value)
            .decode()
            .unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::Corrupt(ref message)
                if message.contains(expected_code)),
            "expected {expected_code}"
        );
    }
    assert!(archive_manifest_raw_row("SUCCEEDED", Some(stamp()))
        .decode()
        .is_err());
    assert!(archive_manifest_raw_row("", None).decode().is_err());
}

fn succeeded_outbox_record() -> AuthorizationArchiveOutboxRecord {
    AuthorizationArchiveOutboxRecord {
        archive_outbox_id: 300,
        identity: archive_identity(),
        card_id: Some(17),
        archived_manifest_id: 500,
        archived_generation: 3,
        event_id: "event-gen2".to_owned(),
        operation_id: "op-gen2".to_owned(),
        archive_key: "astral-auth-archive/v1/7/CARD/17/generation-3".to_owned(),
        semantic_hash: Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"semantic")),
        dependency_hash: Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"dependency")),
        compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        archived_revoke_fence: 2,
        status: AuthorizationArchiveOutboxStatus::Leased,
        attempts: 1,
        cas_version: 4,
        archived_at: None,
    }
}

fn archiving_proof_record(
    stamp_value: Option<time::PrimitiveDateTime>,
) -> AuthorizationArchiveManifestProof {
    AuthorizationArchiveManifestProof {
        archive_manifest_id: 900,
        identity: archive_identity(),
        card_id: Some(17),
        archived_manifest_id: 500,
        archived_generation: 3,
        event_id: "event-gen2".to_owned(),
        operation_id: "op-gen2".to_owned(),
        archive_key: "astral-auth-archive/v1/7/CARD/17/generation-3".to_owned(),
        semantic_hash: Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"semantic")),
        dependency_hash: Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"dependency")),
        compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        archived_revoke_fence: 2,
        archive_digest: Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"sealed")),
        status: AuthorizationArchiveManifestStatus::Archived,
        cas_version: 0,
        archived_at: stamp_value,
    }
}

#[test]
fn terminal_gate_and_intent_pairing_refuse_every_drift_dimension() {
    // STAGED proofs never complete intents.
    let mut proof = archiving_proof_record(Some(stamp()));
    proof.status = AuthorizationArchiveManifestStatus::Staged;
    let error = validate_terminal_archive_proof(&proof).unwrap_err();
    assert!(
        matches!(error, AuthorizationProjectionError::Mapping(ref message)
            if message.contains("archive_proof_not_terminal"))
    );
    proof.status = AuthorizationArchiveManifestStatus::Archived;

    // Terminal without its exclusive stamp is corrupt.
    let unstamped = archiving_proof_record(None);
    assert!(
        matches!(validate_terminal_archive_proof(&unstamped).unwrap_err(),
                     AuthorizationProjectionError::Corrupt(ref message)
                if message.contains("archive_terminal_without_stamp"))
    );

    // Happy path pairs cleanly.
    let intent = succeeded_outbox_record();
    ensure_archive_proof_matches_intent(&intent, &proof).unwrap();

    // Each shared dimension drifts with a distinct, named refusal.
    let expect_mismatch = |proof: &AuthorizationArchiveManifestProof, dimension: &str| {
        let error = ensure_archive_proof_matches_intent(&intent, proof).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::ImmutableConflict(ref message)
                if message.contains(dimension)),
            "expected dimension {dimension}"
        );
    };

    let mut drifted = proof.clone();
    drifted.identity.aggregate_id = 99;
    expect_mismatch(&drifted, "identity");

    let mut drifted = proof.clone();
    drifted.card_id = None;
    expect_mismatch(&drifted, "card_scope");

    let mut drifted = proof.clone();
    drifted.archived_manifest_id = 501;
    expect_mismatch(&drifted, "archived_manifest_id");

    let mut drifted = proof.clone();
    drifted.archived_generation = 4;
    expect_mismatch(&drifted, "generation");

    let mut drifted = proof.clone();
    drifted.event_id = "other-event".to_owned();
    expect_mismatch(&drifted, "event_id");

    let mut drifted = proof.clone();
    drifted.operation_id = "other-op".to_owned();
    expect_mismatch(&drifted, "operation_id");

    let mut drifted = proof.clone();
    drifted.archive_key = "astral-auth-archive/v1/7/CARD/17/generation-4".to_owned();
    expect_mismatch(&drifted, "archive_key");

    let mut drifted = proof.clone();
    drifted.semantic_hash = Sha256Digest::from_hex(HASH_A).unwrap();
    expect_mismatch(&drifted, "hash_trio");

    let mut drifted = proof.clone();
    drifted.compiler_version = "other-compiler".to_owned();
    expect_mismatch(&drifted, "compiler_version");

    let mut drifted = proof.clone();
    drifted.archived_revoke_fence += 1;
    expect_mismatch(&drifted, "archived_revoke_fence");
}

// ── published aggregate frontier planning (pure assembly) ───────────────

fn sql_placeholder_count(sql: &str) -> usize {
    sql.bytes().filter(|byte| *byte == b'?').count()
}

fn frontier_identity() -> ProjectionAggregateIdentity {
    ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap()
}

const FRONTIER_COMPILER: &str = "phase2-authorization-kernel-v1";

fn frontier_pointer(
    generation: u64,
    event: &str,
    operation: &str,
) -> AuthorizationCurrentPointerRecord {
    AuthorizationCurrentPointerRecord {
        pointer_id: 3,
        identity: frontier_identity(),
        card_id: Some(17),
        current_generation: generation,
        manifest_id: 700 + generation as i64,
        event_id: event.to_owned(),
        operation_id: operation.to_owned(),
        semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
        dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
        compiler_version: FRONTIER_COMPILER.to_owned(),
        revoke_fence: 4,
        revoke_fence_proven: true,
        cas_version: 12,
    }
}

fn frontier_manifest(
    generation: u64,
    event: &str,
    operation: &str,
    source_generation: u64,
    revoke_fence: u64,
) -> PublishedGenerationSummary {
    PublishedGenerationSummary {
        manifest_id: 700 + generation as i64,
        generation,
        source_generation,
        projected_generation: source_generation + generation,
        event_id: event.to_owned(),
        operation_id: operation.to_owned(),
        semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
        dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
        compiler_version: FRONTIER_COMPILER.to_owned(),
        manifest_digest: Sha256Digest::from_raw_bytes(sha256_digest_bytes(b"manifest")),
        parent_manifest_id: Some(699),
        revoke_fence,
        card_id: Some(17),
    }
}

fn frontier_plan_evidence(
    generation: u64,
    base_generation: u64,
    event: &str,
    operation: &str,
    base_version: i64,
    target_version: i64,
) -> FrontierPlanEvidence {
    FrontierPlanEvidence {
        plan_id: generation as i64,
        event_id: event.to_owned(),
        operation_id: operation.to_owned(),
        card_id: Some(17),
        base_generation,
        target_generation: generation,
        base_version,
        target_version,
        semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
        dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
        compiler_version: FRONTIER_COMPILER.to_owned(),
        status: AuthorizationImpactPlanStatus::Succeeded,
    }
}

#[allow(clippy::too_many_arguments)]
fn frontier_delta_evidence(
    event: &str,
    operation: &str,
    grant: GrantId,
    base_version: i64,
    target_version: i64,
    source_generation: u64,
    revoke_fence: u64,
    status: &str,
) -> FrontierDeltaEvidence {
    FrontierDeltaEvidence {
        delta_event_id: 1000,
        event_id: event.to_owned(),
        operation_id: operation.to_owned(),
        event_type: DeltaEventType::Update,
        card_id: Some(17),
        tenant_id: 7,
        aggregate_type: "CARD".to_owned(),
        aggregate_id: 17,
        grant_id: grant,
        base_version,
        target_version,
        source_generation,
        revoke_fence,
        semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
        dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
        compiler_version: FRONTIER_COMPILER.to_owned(),
        status_str: status.to_owned(),
    }
}

fn frontier_grant(tail: u16) -> GrantId {
    GrantId::parse(&format!("550e8400-e29b-41d4-a716-44665544{tail:04x}")).unwrap()
}

/// Three honest generations; grants interleave and one grant returns in
/// generation 3 continuing exactly at its previous per-grant target.
fn happy_frontier_inputs() -> (
    ProjectionAggregateIdentity,
    AuthorizationCurrentPointerRecord,
    PublishedGenerationSummary,
    Vec<FrontierPlanEvidence>,
    std::collections::BTreeMap<String, FrontierDeltaEvidence>,
) {
    let identity = frontier_identity();
    let pointer = frontier_pointer(3, "e-g3", "op-final");
    let manifest = frontier_manifest(3, "e-g3", "op-final", 30, 4);
    let plans = vec![
        frontier_plan_evidence(1, 0, "e-g1", "op-1", 0, 1),
        frontier_plan_evidence(2, 1, "e-g2", "op-2", 0, 1),
        frontier_plan_evidence(3, 2, "e-g3", "op-final", 1, 2),
    ];
    let deltas = [
        frontier_delta_evidence(
            "e-g1",
            "op-1",
            frontier_grant(1),
            0,
            1,
            10,
            0,
            DELTA_STATUS_SUCCEEDED,
        ),
        frontier_delta_evidence(
            "e-g2",
            "op-2",
            frontier_grant(2),
            0,
            1,
            20,
            0,
            DELTA_STATUS_SUCCEEDED,
        ),
        frontier_delta_evidence(
            "e-g3",
            "op-final",
            frontier_grant(1),
            1,
            2,
            30,
            4,
            DELTA_STATUS_SUCCEEDED,
        ),
    ]
    .into_iter()
    .map(|delta| (delta.event_id.clone(), delta))
    .collect();
    (identity, pointer, manifest, plans, deltas)
}

fn assemble_happy() -> PublishedAggregateFrontier {
    let (identity, pointer, manifest, plans, deltas) = happy_frontier_inputs();
    assemble_published_aggregate_frontier(&identity, &pointer, &manifest, &plans, &deltas, &[])
        .expect("honest chain must assemble")
}

#[test]
fn published_frontier_assembles_contiguous_chain_with_event_mapping() {
    let frontier = assemble_happy();
    assert_eq!(frontier.events.len(), 3);
    assert_eq!(frontier.card_id, Some(17));
    assert_eq!(frontier.pointer.current_generation, 3);
    for (position, event) in frontier.events.iter().enumerate() {
        assert_eq!(event.generation as usize, position + 1);
    }
    assert_eq!(frontier.events[2].grant_id, frontier_grant(1));
    assert_eq!(
        (
            frontier.events[2].delta_base_version,
            frontier.events[2].delta_target_version
        ),
        (1, 2)
    );
    assert_eq!(frontier.frontier_generation("e-g2"), Some(2));
    assert_eq!(frontier.frontier_generation("absent"), None);
}

#[test]
fn published_frontier_refuses_gaps_duplicates_and_unfinished_plans() {
    type FrontierMutator<'m> = &'m dyn Fn(
        &mut Vec<FrontierPlanEvidence>,
        &mut std::collections::BTreeMap<String, FrontierDeltaEvidence>,
        &mut PublishedGenerationSummary,
        &mut AuthorizationCurrentPointerRecord,
    );
    let expect_failure = |mutate: FrontierMutator, needle: &str| {
        let (identity, mut pointer, mut manifest, mut plans, mut deltas) = happy_frontier_inputs();
        mutate(&mut plans, &mut deltas, &mut manifest, &mut pointer);
        let error = assemble_published_aggregate_frontier(
            &identity,
            &pointer,
            &manifest,
            &plans,
            &deltas,
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains(needle), "expected {needle} inside: {error}");
    };

    // A PENDING plan can never prove an aggregate generation.
    expect_failure(
        &|plans, _, _, _| plans[0].status = AuthorizationImpactPlanStatus::Pending,
        "frontier_plan_not_succeeded",
    );
    // Missing a middle plan surfaces the generation gap.
    expect_failure(
        &|plans, deltas, _, _| {
            plans.remove(1);
            deltas.remove("e-g2");
        },
        "frontier_generation_gap",
    );
    // Linkage drift between plan and its delta is immutable-history damage.
    expect_failure(
        &|_, deltas, _, _| deltas.get_mut("e-g3").unwrap().target_version = 99,
        "frontier_plan_delta_linkage_drift",
    );
    // Cross-tenant delta rows never prove this aggregate.
    expect_failure(
        &|_, deltas, _, _| deltas.get_mut("e-g1").unwrap().tenant_id = 999,
        "frontier_delta_scope_mismatch",
    );
    // Card-scope drift inside the plan slice fails too.
    expect_failure(
        &|plans, _, _, _| plans[1].card_id = None,
        "frontier_plan_card_mismatch",
    );
    // Duplicate per-grant (grant, target) pairs abort (plan + delta moved
    // together so pure linkage passes and the real duplicate fires).
    expect_failure(
        &|plans, deltas, _, _| {
            plans[2].base_version = 0;
            plans[2].target_version = 1;
            let delta = deltas.get_mut("e-g3").unwrap();
            delta.base_version = 0;
            delta.target_version = 1;
        },
        "frontier_duplicate_grant_version",
    );
    // Same-grant chaining must continue exactly at the previous target —
    // a restart from version 0 is refused (plan and delta moved together
    // so pure linkage passes first).
    expect_failure(
        &|plans, deltas, _, _| {
            plans[2].base_version = 0;
            deltas.get_mut("e-g3").unwrap().base_version = 0;
        },
        "frontier_same_grant_chain_gap",
    );
    // Surplus delta evidence without a matching plan is junk input.
    expect_failure(
        &|_, deltas, _, _| {
            let surplus = frontier_delta_evidence(
                "e-surplus",
                "op-x",
                frontier_grant(9),
                0,
                1,
                40,
                0,
                DELTA_STATUS_SUCCEEDED,
            );
            deltas.insert(surplus.event_id.clone(), surplus);
        },
        "frontier_surplus_delta_evidence",
    );
    // A missing delta row for an existing plan aborts explicitly.
    expect_failure(
        &|_, deltas, _, _| {
            deltas.remove("e-g2");
        },
        "frontier_delta_missing",
    );
    // Latest generation must tie to the pointer event identity.
    expect_failure(
        &|_, _, _, pointer| pointer.event_id = "e-forged".to_owned(),
        "frontier_latest_pointer_tie_break",
    );
    // Manifest/pointer card splits are corrupt before anything else runs.
    expect_failure(
        &|_, _, manifest, _| manifest.card_id = None,
        "frontier_manifest_card_split",
    );
    // Zero generation pointers cannot have plans behind them (both sides
    // moved so the summary-agreement gate does not shadow this rule).
    expect_failure(
        &|_, _, manifest, pointer| {
            pointer.current_generation = 0;
            manifest.generation = 0;
        },
        "frontier_zero_generation",
    );
}

#[test]
fn published_frontier_enforces_latest_fences_source_and_status_rules() {
    // Boundary equality: raising the fence to exactly the claimed delta's
    // level stays valid (raising only narrows authorization).
    {
        let (identity, pointer, mut manifest, plans, deltas) = happy_frontier_inputs();
        manifest.revoke_fence = 4; // == gen-3 delta fence
        assemble_published_aggregate_frontier(&identity, &pointer, &manifest, &plans, &deltas, &[])
            .expect("fence parity is acceptable");
    }
    // Regressing below the claimed delta's fence refuses.
    {
        let (identity, pointer, mut manifest, plans, deltas) = happy_frontier_inputs();
        manifest.revoke_fence = 3;
        let error = assemble_published_aggregate_frontier(
            &identity,
            &pointer,
            &manifest,
            &plans,
            &deltas,
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("frontier_fence_below_claimed_delta"),
            "{error}"
        );
    }
    // Source-generation drift between manifest and latest delta aborts.
    {
        let (identity, pointer, mut manifest, plans, deltas) = happy_frontier_inputs();
        manifest.source_generation = 31;
        let error = assemble_published_aggregate_frontier(
            &identity,
            &pointer,
            &manifest,
            &plans,
            &deltas,
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("frontier_source_generation_drift"),
            "{error}"
        );
    }
    // Non-SUCCEEDED delta rows can never prove generations.
    {
        let (identity, pointer, manifest, plans, mut deltas) = happy_frontier_inputs();
        deltas.get_mut("e-g2").unwrap().status_str = DELTA_STATUS_QUARANTINED.to_owned();
        let error = assemble_published_aggregate_frontier(
            &identity,
            &pointer,
            &manifest,
            &plans,
            &deltas,
            &[],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("frontier_delta_not_succeeded"), "{error}");
    }
    // Extra SUCCEEDED plans beyond G are immutable-history conflicts with
    // their rows surfaced for operators.
    {
        let (identity, pointer, manifest, plans, deltas) = happy_frontier_inputs();
        let extras = vec![ExtraSucceededImpactPlan {
            plan_id: 42,
            event_id: "e-hijack".to_owned(),
            target_generation: 7,
        }];
        let error = assemble_published_aggregate_frontier(
            &identity, &pointer, &manifest, &plans, &deltas, &extras,
        )
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("frontier_extra_succeeded_plan") && error.contains("e-hijack"),
            "{error}"
        );
    }
}

#[test]
fn frontier_plan_scan_bind_contract_pins_upper_bound_g_limit_g_plus_one() {
    // Bind contracts are pure, so they hold without any database session.
    assert_eq!(
        frontier_plan_scan_binds(3).expect("G fits BIGINT"),
        (3_i64, 4_i64),
        "inclusive upper bound binds G exactly; LIMIT binds the defensive
             duplicate allowance G+1 only"
    );
    assert_eq!(
        frontier_extra_probe_binds(3).expect("probe binds fit BIGINT"),
        (3_i64, MAX_EXTRA_SUCCEEDED_FRONTIER_SCAN),
        "exclusive probe lower bound binds G so a SUCCEEDED plan stranded
             exactly at G+1 cannot escape detection"
    );
    // The scan tail declares which placeholder owns the inclusive upper
    // bound (`<= ?`) versus the defensive limit (`LIMIT ?`).
    let plan_tail = FRONTIER_PLANS_BY_SCOPE_TAIL;
    assert!(plan_tail.contains("target_generation <= ?"), "{plan_tail}");
    assert!(plan_tail.contains("LIMIT ?"), "{plan_tail}");
    assert!(plan_tail.ends_with("FOR UPDATE"), "{plan_tail}");
}

#[test]
fn frontier_slice_leaves_future_pending_residue_off_the_row_cap() {
    // Pointer sits at G=3 while a generation-4 plan is legally staged as
    // PENDING (never published). With the pinned bind contract that staged
    // generation compares above the inclusive upper bound, so the main
    // scan excludes it: honest loading stays at exactly G rows and the
    // row cap (`> G rows ⇒ corrupt`) can never fire on future residue.
    const CURRENT_GENERATION: u64 = 3;
    let staged_target_generation = CURRENT_GENERATION + 1;
    let (upper_bound, limit) = frontier_plan_scan_binds(CURRENT_GENERATION).unwrap();
    assert!(
        staged_target_generation as i64 > upper_bound,
        "future plan must fall outside target_generation <= G"
    );
    assert!(
        limit == upper_bound + 1,
        "LIMIT is one row of duplicate defense above the honest budget"
    );

    // The corrected loader therefore delivers the complete honest slice
    // 1..=G even while G+1 residue exists in storage; assembly accepts it
    // untouched (no row-cap, no gap, pointer semantics unchanged).
    let (identity, pointer, manifest, plans, deltas) = happy_frontier_inputs();
    assert_eq!(
        plans.len(),
        CURRENT_GENERATION as usize,
        "honest slice covers every generation 1..=G"
    );
    assert_eq!(
        usize::try_from(limit).unwrap(),
        plans.len() + 1,
        "defensive LIMIT admits the honest slice plus one duplicate"
    );
    let frontier =
        assemble_published_aggregate_frontier(&identity, &pointer, &manifest, &plans, &deltas, &[])
            .expect("complete 1..=G slice plus unseen G+1 PENDING residue assembles");
    assert_eq!(frontier.events.len(), CURRENT_GENERATION as usize);
    assert_eq!(frontier.pointer.current_generation, CURRENT_GENERATION);
}

#[test]
fn frontier_rejects_succeeded_plan_stranded_exactly_at_next_generation() {
    // Probe semantics pin `target_generation > G` (never `> G + 1`): a
    // SUCCEEDED plan sitting precisely at G+1 while the pointer still
    // identifies G contradicts durable history and must abort fail-closed
    // with its identifying rows surfaced for operators.
    let (identity, pointer, manifest, plans, deltas) = happy_frontier_inputs();
    let extras = vec![ExtraSucceededImpactPlan {
        plan_id: 99,
        event_id: "e-stranded".to_owned(),
        target_generation: pointer.current_generation + 1,
    }];
    let error = assemble_published_aggregate_frontier(
        &identity, &pointer, &manifest, &plans, &deltas, &extras,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("frontier_extra_succeeded_plan") && error.contains("e-stranded"),
        "{error}"
    );
}

#[test]
fn frontier_statements_stay_parameterized_locked_and_legacy_free() {
    let statements = [
        ("plan scan", FRONTIER_PLANS_BY_SCOPE_TAIL, 5usize),
        ("delta fetch", FRONTIER_DELTA_BY_EVENT_TAIL, 1),
        (
            "extra succeeded probe",
            EXTRA_SUCCEEDED_FRONTIER_SCAN_SQL,
            5,
        ),
    ];
    let legacy_tokens = [
        "permission_rule_snapshot",
        "rule_set_snapshot",
        "authorization_projection_head",
        "ON DUPLICATE KEY",
    ];
    for (label, statement, placeholders) in statements {
        assert!(statement.contains("FOR UPDATE"), "{label} must lock rows");
        assert_eq!(
            sql_placeholder_count(statement),
            placeholders,
            "{label} bind list drifted"
        );
        for token in legacy_tokens {
            assert!(!statement.contains(token), "{label} references {token}");
        }
    }
    assert!(FRONTIER_PLANS_BY_SCOPE_TAIL.contains("ORDER BY target_generation ASC LIMIT ?"));
    assert!(FRONTIER_PLANS_BY_SCOPE_TAIL.contains("target_generation <= ?"));
    assert!(FRONTIER_DELTA_BY_EVENT_TAIL.contains("WHERE event_id = ? FOR UPDATE"));
    assert!(EXTRA_SUCCEEDED_FRONTIER_SCAN_SQL.contains("target_generation > ?"));
    assert!(EXTRA_SUCCEEDED_FRONTIER_SCAN_SQL.contains("status = 'SUCCEEDED'"));
}

// ── Published card grant evidence reader (pure assembly + SQL shape) ────

const EV_HASH_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn repeated_hex(byte: u8) -> String {
    hex::encode([byte; 32])
}

fn evidence_identity(aggregate_type: &str, aggregate_id: i64) -> ProjectionAggregateIdentity {
    ProjectionAggregateIdentity::new(7, aggregate_type, aggregate_id).unwrap()
}

fn evidence_pointer(
    aggregate_type: &str,
    aggregate_id: i64,
    manifest_id: i64,
) -> AuthorizationCurrentPointerRecord {
    AuthorizationCurrentPointerRecord {
        pointer_id: manifest_id,
        identity: evidence_identity(aggregate_type, aggregate_id),
        card_id: Some(17),
        current_generation: 41,
        manifest_id,
        event_id: format!("event-{aggregate_type}-{manifest_id}"),
        operation_id: format!("op-{aggregate_type}-{manifest_id}"),
        semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
        dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
        compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        revoke_fence: 1,
        revoke_fence_proven: true,
        cas_version: 5,
    }
}

fn evidence_grant_for(user_id: i64, tail: u16) -> CanonicalGrant {
    let mut sample = grant(tail);
    sample.user_id = user_id;
    sample
}

fn evidence_segment(
    identity: &ProjectionAggregateIdentity,
    segment_id: i64,
    grants: Vec<CanonicalGrant>,
) -> AuthorizationSegmentSnapshot {
    AuthorizationSegmentSnapshot {
        segment_id,
        identity: identity.clone(),
        card_id: Some(17),
        content_digest: Sha256Digest::from_hex(&repeated_hex((segment_id as u8) | 1)).unwrap(),
        semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
        dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
        compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        format: SEGMENT_FORMAT_AUTHORIZATION_GRANTS_JSON_V1.to_owned(),
        row_count: grants.len() as u64,
        byte_size: 128,
        grants,
    }
}

fn evidence_reference(
    pointer: &AuthorizationCurrentPointerRecord,
    ordinal: u64,
    segment: &AuthorizationSegmentSnapshot,
) -> AuthorizationSegmentReferenceRecord {
    AuthorizationSegmentReferenceRecord {
        reference_id: ordinal as i64 + 1,
        manifest_id: pointer.manifest_id,
        identity: pointer.identity.clone(),
        card_id: pointer.card_id,
        generation: pointer.current_generation,
        ordinal,
        segment_id: segment.segment_id,
        content_digest: segment.content_digest,
        event_id: pointer.event_id.clone(),
        operation_id: pointer.operation_id.clone(),
    }
}

fn published_card_state(
    pointer: &AuthorizationCurrentPointerRecord,
    segments: Vec<AuthorizationSegmentSnapshot>,
) -> AuthorizationPublishedState {
    let references = segments
        .iter()
        .enumerate()
        .map(|(ordinal, segment)| evidence_reference(pointer, ordinal as u64, segment))
        .collect();
    let total_grant_count = segments.iter().map(|s| s.row_count).sum::<u64>();
    AuthorizationPublishedState {
        pointer: pointer.clone(),
        manifest_id: pointer.manifest_id,
        generation: pointer.current_generation,
        source_generation: 42,
        projected_generation: 42,
        event_id: pointer.event_id.clone(),
        operation_id: pointer.operation_id.clone(),
        semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
        dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
        compiler_version: pointer.compiler_version.clone(),
        manifest_digest: Sha256Digest::from_hex(EV_HASH_C).unwrap(),
        parent_manifest_id: None,
        revoke_fence: pointer.revoke_fence,
        segments,
        references,
        total_grant_count,
    }
}

fn unconstrained_scope() -> PublishedCardEvidenceScope {
    PublishedCardEvidenceScope {
        tenant_id: 7,
        card_id: 17,
        user_filter: None,
        domain: DomainScopeRequirement::Unconstrained,
    }
}

fn expect_corrupt(
    result: Result<PublishedCardAuthorization, AuthorizationEvidenceError>,
) -> String {
    match result {
        Err(AuthorizationEvidenceError::Corrupt(message)) => message,
        other => panic!("expected Corrupt error, got {other:?}"),
    }
}

#[test]
fn published_card_aggregate_allowlist_is_the_documented_closed_set() {
    assert_eq!(
        PUBLISHED_CARD_AGGREGATE_TYPES,
        ["USER_CARD", "RULE_SET", "APPROVAL", "DELEGATION"]
    );
    const {
        assert!(MAX_PUBLISHED_CARD_AGGREGATES_PER_READ >= 1);
    }
}

#[test]
fn card_evidence_pointer_select_is_tenant_and_card_bound_deterministically_locked() {
    let statement =
        format!("{SELECT_PREFIX}{POINTER_ROW_COLUMNS}{POINTER_ROWS_FOR_TENANT_CARD_LOCKED_TAIL}");
    assert!(statement.contains("FROM authorization_projection_current"));
    assert!(statement.contains("WHERE tenant_id = ? AND card_id = ?"));
    assert!(statement.contains("ORDER BY aggregate_type ASC, aggregate_id ASC"));
    assert!(statement.ends_with("FOR UPDATE"), "{statement}");
    // Exactly the two scope bindings; no hidden third placeholder.
    assert_eq!(sql_placeholder_count(&statement), 2);
}

#[test]
fn whole_scope_pointer_scans_are_sql_bounded_cap_plus_one() {
    // Locked capture variant: same deterministic global order, with the
    // SQL itself cutting the read (and lock) set at `LIMIT ?` = cap + 1,
    // before `FOR UPDATE`.
    let locked =
        format!("{SELECT_PREFIX}{POINTER_ROW_COLUMNS}{POINTER_ROWS_ALL_LOCKED_BOUNDED_TAIL}");
    assert!(locked.contains("FROM authorization_projection_current"));
    assert!(locked.contains("ORDER BY tenant_id ASC, aggregate_type ASC, aggregate_id ASC"));
    let limit = locked
        .find("LIMIT ?")
        .expect("bounded lock tail must carry LIMIT ?");
    assert!(
        locked[limit..].contains("FOR UPDATE"),
        "locked bounded tail must keep FOR UPDATE after LIMIT: {locked}"
    );
    assert!(locked.ends_with("FOR UPDATE"), "{locked}");
    // Exactly the one over-limit probe binding; no hidden second
    // placeholder.
    assert_eq!(sql_placeholder_count(&locked), 1);

    // Non-locking hint variant: same bounded cut, no row locks.
    let ordered =
        format!("{SELECT_PREFIX}{POINTER_ROW_COLUMNS}{POINTER_ROWS_ALL_ORDERED_BOUNDED_TAIL}");
    assert!(ordered.contains("FROM authorization_projection_current"));
    assert!(ordered.contains("ORDER BY tenant_id ASC, aggregate_type ASC, aggregate_id ASC"));
    assert!(ordered.ends_with("LIMIT ?"), "{ordered}");
    assert!(!ordered.contains("FOR UPDATE"));
    assert_eq!(sql_placeholder_count(&ordered), 1);
}

#[test]
fn card_evidence_reader_path_has_no_legacy_snapshot_or_cache_fallback() {
    let forbidden = [
        "permission_rule_snapshot",
        "rule_set_snapshot",
        "authorization_projection_head",
        "cache",
    ];
    for fragment in [
        POINTER_ROWS_FOR_TENANT_CARD_LOCKED_TAIL,
        SELECT_PREFIX,
        POINTER_ROW_COLUMNS,
    ] {
        for token in forbidden {
            assert!(
                !fragment.to_ascii_lowercase().contains(token),
                "card evidence reader must not reference {token}"
            );
        }
    }
}

#[test]
fn multi_aggregate_evidence_merges_into_deterministic_order() {
    // Scrambled on purpose; the pure assembly must still order summaries
    // and records by (aggregate_type, aggregate_id).
    let states = vec![
        published_card_state(
            &evidence_pointer("USER_CARD", 17, 104),
            vec![evidence_segment(
                &evidence_identity("USER_CARD", 17),
                401,
                vec![evidence_grant_for(42, 0x0001)],
            )],
        ),
        published_card_state(
            &evidence_pointer("DELEGATION", 90, 102),
            vec![evidence_segment(
                &evidence_identity("DELEGATION", 90),
                402,
                vec![evidence_grant_for(42, 0x0002)],
            )],
        ),
        published_card_state(
            &evidence_pointer("RULE_SET", 55, 103),
            vec![evidence_segment(
                &evidence_identity("RULE_SET", 55),
                403,
                vec![evidence_grant_for(42, 0x0003)],
            )],
        ),
        published_card_state(
            &evidence_pointer("APPROVAL", 30, 101),
            vec![evidence_segment(
                &evidence_identity("APPROVAL", 30),
                404,
                vec![evidence_grant_for(43, 0x0004)],
            )],
        ),
    ];
    let evidence =
        assemble_published_card_evidence(&unconstrained_scope(), 1_000_000, &states).unwrap();
    evidence.validate().unwrap();

    let ordered_types: Vec<&str> = manifests_types(&evidence);
    assert_eq!(
        ordered_types,
        ["APPROVAL", "DELEGATION", "RULE_SET", "USER_CARD"]
    );
    let gate = &evidence.gate;
    assert_eq!(gate.status, PublishedEvidenceGateStatus::Ready);
    assert_eq!(gate.aggregate_manifest_count, 4);
    assert_eq!(gate.verified_record_count, 4);
    assert_eq!(gate.effective_grant_count, 4);
    assert_eq!(gate.not_in_effective_count, 0);
    assert_eq!(gate.equivalent_duplicate_collapsed_count, 0);
    assert_eq!(evidence.effective_grants.len(), 4);
    // Provenance stays per-aggregate; every record keeps its own origin.
    for record in &evidence.records {
        assert_ne!(record.publication_generation, record.grant.revision.value());
        assert!(!record.aggregate_type.is_empty());
    }
}

fn manifests_types(evidence: &PublishedCardAuthorization) -> Vec<&str> {
    evidence
        .manifests
        .iter()
        .map(|manifest| manifest.aggregate_type.as_str())
        .collect()
}

#[test]
fn empty_state_set_is_not_ready_instead_of_ok_empty() {
    let empty: Vec<AuthorizationPublishedState> = Vec::new();
    let error = assemble_published_card_evidence(&unconstrained_scope(), 7, &empty).unwrap_err();
    assert!(matches!(error, AuthorizationEvidenceError::NotReady(_)));
    assert_eq!(error.as_gate_status(), PublishedEvidenceGateStatus::Pending);
}

#[test]
fn unknown_aggregate_type_fails_the_whole_read() {
    let states = vec![published_card_state(
        &{
            let mut pointer = evidence_pointer("USER_CARD", 17, 1);
            pointer.identity.aggregate_type = "MYSTERY".to_owned();
            pointer
        },
        vec![evidence_segment(
            &evidence_identity("USER_CARD", 17),
            400,
            vec![evidence_grant_for(42, 0x0011)],
        )],
    )];
    let message = expect_corrupt(assemble_published_card_evidence(
        &unconstrained_scope(),
        100,
        &states,
    ));
    assert!(message.contains("unknown_aggregate_type"), "{message}");
}

#[test]
fn grant_tenant_or_card_scope_split_inside_committed_payload_is_corrupt() {
    let tenant_split_grant = {
        let mut sample = evidence_grant_for(42, 0x0021);
        sample.tenant.tenant_id = 8;
        sample
    };
    let card_split_grant = {
        let mut sample = evidence_grant_for(42, 0x0022);
        sample.card_id = 99;
        sample
    };
    for (label, broken) in [("tenant", tenant_split_grant), ("card", card_split_grant)] {
        let states = vec![published_card_state(
            &evidence_pointer("USER_CARD", 17, 1),
            vec![evidence_segment(
                &evidence_identity("USER_CARD", 17),
                405,
                vec![broken],
            )],
        )];
        let message = expect_corrupt(assemble_published_card_evidence(
            &unconstrained_scope(),
            100,
            &states,
        ));
        assert!(
            message.starts_with("code=published_card_evidence.grant_"),
            "{label}: {message}"
        );
    }
}

#[test]
fn expired_not_yet_valid_and_inactive_are_excluded_but_provenance_kept() {
    let now = 1_000_000_i64;
    let mut expired = evidence_grant_for(42, 0x0031);
    expired.validity = ValidityWindow::between(now - 10, now);
    let mut not_yet_valid = evidence_grant_for(42, 0x0032);
    not_yet_valid.validity = ValidityWindow::between(now + 5, now + 50);
    let mut revoked = evidence_grant_for(42, 0x0033);
    revoked.state = GrantState::Revoked;
    let mut archived = evidence_grant_for(42, 0x0034);
    archived.state = GrantState::Archived;

    let states = vec![published_card_state(
        &evidence_pointer("USER_CARD", 17, 1),
        vec![evidence_segment(
            &evidence_identity("USER_CARD", 17),
            406,
            vec![expired, not_yet_valid, revoked, archived],
        )],
    )];
    let evidence = assemble_published_card_evidence(&unconstrained_scope(), now, &states).unwrap();
    evidence.validate().unwrap();

    assert_eq!(evidence.effective_grants.len(), 0);
    assert_eq!(evidence.gate.verified_record_count, 4);
    assert_eq!(evidence.gate.not_in_effective_count, 4);
    let reasons: Vec<_> = evidence
        .records
        .iter()
        .map(|record| record.unaccepted_reason.unwrap())
        .collect();
    assert_eq!(
        reasons,
        vec![
            UnacceptedGrantReason::Expired,
            UnacceptedGrantReason::NotYetValid,
            UnacceptedGrantReason::InactiveState,
            UnacceptedGrantReason::InactiveState,
        ]
    );
}

#[test]
fn fully_equal_same_origin_duplicate_collapses_but_cross_origin_is_corrupt() {
    // Case A: identical duplicate inside ONE aggregate collapses.
    let twin = evidence_grant_for(42, 0x0041);
    let states = vec![published_card_state(
        &evidence_pointer("USER_CARD", 17, 1),
        vec![
            evidence_segment(&evidence_identity("USER_CARD", 17), 407, vec![twin.clone()]),
            evidence_segment(&evidence_identity("USER_CARD", 17), 408, vec![twin]),
        ],
    )];
    let evidence = assemble_published_card_evidence(&unconstrained_scope(), 100, &states).unwrap();
    assert_eq!(evidence.gate.equivalent_duplicate_collapsed_count, 1);
    assert_eq!(evidence.gate.verified_record_count, 1);
    assert_eq!(evidence.effective_grants.len(), 1);

    // Case B: same grant tuple under TWO different origins → corrupt;
    // provenance must never be merged silently across aggregates.
    let shared = evidence_grant_for(42, 0x0042);
    let conflicting_states = vec![
        published_card_state(
            &evidence_pointer("USER_CARD", 17, 1),
            vec![evidence_segment(
                &evidence_identity("USER_CARD", 17),
                409,
                vec![shared.clone()],
            )],
        ),
        published_card_state(
            &evidence_pointer("RULE_SET", 55, 2),
            vec![evidence_segment(
                &evidence_identity("RULE_SET", 55),
                410,
                vec![shared],
            )],
        ),
    ];
    let message = expect_corrupt(assemble_published_card_evidence(
        &unconstrained_scope(),
        100,
        &conflicting_states,
    ));
    assert!(
        message.contains("conflicting_grant_provenance"),
        "{message}"
    );
}

#[test]
fn unequal_same_origin_duplicate_is_also_conflicting_provenance() {
    let original = evidence_grant_for(42, 0x0051);
    let drifted = {
        let mut sample = original.clone();
        sample.resource = "learn_subject:2".to_owned();
        sample
    };
    let states = vec![published_card_state(
        &evidence_pointer("USER_CARD", 17, 1),
        vec![
            evidence_segment(&evidence_identity("USER_CARD", 17), 411, vec![original]),
            evidence_segment(&evidence_identity("USER_CARD", 17), 412, vec![drifted]),
        ],
    )];
    let message = expect_corrupt(assemble_published_card_evidence(
        &unconstrained_scope(),
        100,
        &states,
    ));
    assert!(message.contains("conflicting_grant_provenance"));
}

#[test]
fn user_and_domain_lens_narrow_without_inventing_corruption() {
    let domain_user = evidence_grant_for(42, 0x0061); // tenant Some(11)-domain fixture
    let mut plain_user = evidence_grant_for(43, 0x0062);
    plain_user.tenant.domain_id = None;

    let build_states = || {
        vec![published_card_state(
            &evidence_pointer("USER_CARD", 17, 1),
            vec![evidence_segment(
                &evidence_identity("USER_CARD", 17),
                413,
                vec![domain_user.clone(), plain_user.clone()],
            )],
        )]
    };

    // No lens: both accepted.
    let both =
        assemble_published_card_evidence(&unconstrained_scope(), 100, &build_states()).unwrap();
    assert_eq!(both.gate.effective_grant_count, 2);

    // User lens: only user 43 survives; 42 is excluded explicitly.
    let only_plain = assemble_published_card_evidence(
        &PublishedCardEvidenceScope {
            user_filter: Some(43),
            ..unconstrained_scope()
        },
        100,
        &build_states(),
    )
    .unwrap();
    assert_eq!(only_plain.gate.effective_grant_count, 1);
    assert_eq!(
        only_plain.records[0].unaccepted_reason,
        Some(UnacceptedGrantReason::OutOfUserFilter)
    );

    // Domain lens "must be None": excludes the Some(11)-domain grant.
    let none_domain_only = assemble_published_card_evidence(
        &PublishedCardEvidenceScope {
            domain: DomainScopeRequirement::ExactlyNone,
            ..unconstrained_scope()
        },
        100,
        &build_states(),
    )
    .unwrap();
    assert_eq!(none_domain_only.gate.effective_grant_count, 1);
    assert_eq!(
        none_domain_only.records[0].unaccepted_reason,
        Some(UnacceptedGrantReason::OutOfDomainFilter)
    );

    // Domain lens "exactly 11": flips which record survives.
    let exact_domain = assemble_published_card_evidence(
        &PublishedCardEvidenceScope {
            domain: DomainScopeRequirement::ExactlySome(11),
            ..unconstrained_scope()
        },
        100,
        &build_states(),
    )
    .unwrap();
    assert_eq!(exact_domain.gate.effective_grant_count, 1);
    assert_eq!(
        exact_domain.records[1].unaccepted_reason,
        Some(UnacceptedGrantReason::OutOfDomainFilter)
    );
}

#[test]
fn reader_refuses_card_scope_splits_and_declared_row_drift() {
    // Pointer without card scope can never enter a CARD-scoped read.
    let wide_pointer = {
        let mut pointer = evidence_pointer("USER_CARD", 17, 1);
        pointer.card_id = None;
        pointer
    };
    let message = expect_corrupt(assemble_published_card_evidence(
        &unconstrained_scope(),
        100,
        &[published_card_state(
            &wide_pointer,
            vec![evidence_segment(
                &evidence_identity("USER_CARD", 17),
                414,
                vec![evidence_grant_for(42, 0x0071)],
            )],
        )],
    ));
    assert!(message.contains("pointer_card_scope_split"));

    // Reference stamped with a different card than its pointer.
    let split_pointer = evidence_pointer("USER_CARD", 17, 1);
    let mut state = published_card_state(
        &split_pointer,
        vec![evidence_segment(
            &evidence_identity("USER_CARD", 17),
            415,
            vec![evidence_grant_for(42, 0x0072)],
        )],
    );
    state.references[0].card_id = Some(18);
    let message = expect_corrupt(assemble_published_card_evidence(
        &unconstrained_scope(),
        100,
        &[state],
    ));
    assert!(message.contains("reference_card_scope_split"));

    // Segment stamped with a different card than its manifest chain.
    let split_pointer = evidence_pointer("USER_CARD", 17, 1);
    let mut state = published_card_state(
        &split_pointer,
        vec![evidence_segment(
            &evidence_identity("USER_CARD", 17),
            416,
            vec![evidence_grant_for(42, 0x0073)],
        )],
    );
    state.segments[0].card_id = Some(19);
    let message = expect_corrupt(assemble_published_card_evidence(
        &unconstrained_scope(),
        100,
        &[state],
    ));
    assert!(message.contains("segment_card_scope_split"));

    // Reference whose generation disagrees with its manifest publication.
    let split_pointer = evidence_pointer("USER_CARD", 17, 1);
    let mut state = published_card_state(
        &split_pointer,
        vec![evidence_segment(
            &evidence_identity("USER_CARD", 17),
            417,
            vec![evidence_grant_for(42, 0x0074)],
        )],
    );
    state.references[0].generation = 40;
    let message = expect_corrupt(assemble_published_card_evidence(
        &unconstrained_scope(),
        100,
        &[state],
    ));
    assert!(message.contains("reference_generation_split"));

    // Declared sealed totals disagree with the actually walked payload rows.
    let split_pointer = evidence_pointer("USER_CARD", 17, 1);
    let mut state = published_card_state(
        &split_pointer,
        vec![evidence_segment(
            &evidence_identity("USER_CARD", 17),
            418,
            vec![evidence_grant_for(42, 0x0075)],
        )],
    );
    state.total_grant_count += 1;
    let message = expect_corrupt(assemble_published_card_evidence(
        &unconstrained_scope(),
        100,
        &[state],
    ));
    assert!(message.contains("walked_record_count_below_declared_segment_rows"));

    // Reference/segment pairing drift cannot slip through either.
    let split_pointer = evidence_pointer("USER_CARD", 17, 1);
    let mut state = published_card_state(
        &split_pointer,
        vec![evidence_segment(
            &evidence_identity("USER_CARD", 17),
            419,
            vec![evidence_grant_for(42, 0x0076)],
        )],
    );
    state
        .references
        .push(evidence_reference(&state.pointer, 1, &state.segments[0]));
    let message = expect_corrupt(assemble_published_card_evidence(
        &unconstrained_scope(),
        100,
        &[state],
    ));
    assert!(message.contains("reference_segment_pairing_split"));
}

#[test]
fn classification_tables_stay_fail_closed() {
    // Validity boundaries: upper bound exclusive, lower bound inclusive.
    let window = ValidityWindow::between(10, 20);
    assert_eq!(
        classify_validity_at(&window, 9),
        Some(UnacceptedGrantReason::NotYetValid)
    );
    assert_eq!(classify_validity_at(&window, 10), None);
    assert_eq!(classify_validity_at(&window, 19), None);
    assert_eq!(
        classify_validity_at(&window, 20),
        Some(UnacceptedGrantReason::Expired)
    );
    assert_eq!(classify_validity_at(&ValidityWindow::perpetual(), -5), None);

    // Gate vocabulary mapping of the typed error bridge.
    assert_eq!(
        AuthorizationEvidenceError::NotReady("code=x".to_owned()).as_gate_status(),
        PublishedEvidenceGateStatus::Pending
    );
    assert_eq!(
        AuthorizationEvidenceError::InvalidRequest("code=y".to_owned()).as_gate_status(),
        PublishedEvidenceGateStatus::Pending
    );
    assert_eq!(
        AuthorizationEvidenceError::Corrupt("code=z".to_owned()).as_gate_status(),
        PublishedEvidenceGateStatus::Corrupt
    );
}

#[test]
fn projection_errors_bridge_into_the_evidence_vocabulary_fail_closed() {
    use AuthorizationProjectionError as ProjectionError;
    let bridged: AuthorizationEvidenceError = ProjectionError::NotReady(
        "code=authorization_projection.current_pointer_missing".to_owned(),
    )
    .into();
    assert!(matches!(bridged, AuthorizationEvidenceError::NotReady(_)));

    let bridged: AuthorizationEvidenceError = ProjectionError::Corrupt(
        "code=authorization_projection.pointer_hash_chain_break".to_owned(),
    )
    .into();
    assert_eq!(
        bridged.as_gate_status(),
        PublishedEvidenceGateStatus::Corrupt
    );

    let bridged: AuthorizationEvidenceError =
        ProjectionError::IdentityMismatch("code=x".to_owned()).into();
    assert_eq!(
        bridged.as_gate_status(),
        PublishedEvidenceGateStatus::Corrupt
    );

    let bridged: AuthorizationEvidenceError = ProjectionError::Mapping("code=y".to_owned()).into();
    assert_eq!(
        bridged.as_gate_status(),
        PublishedEvidenceGateStatus::Corrupt
    );
}

// ── Archive-intent parent proof (pure fail-closed gate, no DB) ──────────

/// Durable parent manifest row whose every dimension matches
/// [`archive_intent_request`]; `status` is parameterized so lifecycle
/// gating can be exercised independently.
fn archive_parent_row(status: &str) -> ManifestRawSqlRow {
    ManifestRawSqlRow {
        manifest_id: 55,
        tenant_id: 7,
        card_id: Some(31),
        aggregate_type: "CARD".to_owned(),
        aggregate_id: 17,
        generation: 3,
        source_generation: 9,
        projected_generation: 9,
        event_id: "event-stage".to_owned(),
        operation_id: "op-stage".to_owned(),
        semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap().as_bytes().to_vec(),
        dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap().as_bytes().to_vec(),
        compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        manifest_digest: Sha256Digest::from_hex(HASH_A).unwrap().as_bytes().to_vec(),
        status: status.to_owned(),
        cas_version: 4,
        lease_owner: None,
        lease_token_hash: None,
        lease_expires_at: None,
        parent_manifest_id: Some(2),
        revoke_fence: 1,
    }
}

fn archive_intent_request() -> AuthorizationArchiveIntentAppendRequest {
    AuthorizationArchiveIntentAppendRequest {
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        card_id: Some(31),
        archived_manifest_id: 55,
        archived_generation: 3,
        event_id: "event-stage".to_owned(),
        operation_id: "op-stage".to_owned(),
        archive_key: "astral-auth-archive/v1/7/CARD/17/generation-3".to_owned(),
        semantic_hash_hex: HASH_A.to_owned(),
        dependency_hash_hex: HASH_B.to_owned(),
        compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        archived_revoke_fence: 1,
    }
}

fn prove_request(
    request: &AuthorizationArchiveIntentAppendRequest,
    parent: &ManifestRawSqlRow,
) -> Result<(), AuthorizationProjectionError> {
    prove_archive_intent_against_parent_manifest(
        request,
        &Sha256Digest::from_hex(&request.semantic_hash_hex).unwrap(),
        &Sha256Digest::from_hex(&request.dependency_hash_hex).unwrap(),
        parent,
    )
}

fn assert_parent_rejection(
    error: AuthorizationProjectionError,
    expected_variant: &str,
    expected_code: &str,
) {
    let (variant, code) = match error {
        AuthorizationProjectionError::IdentityMismatch(code) => ("IdentityMismatch", code),
        AuthorizationProjectionError::ImmutableConflict(code) => ("ImmutableConflict", code),
        AuthorizationProjectionError::NotReady(code) => ("NotReady", code),
        AuthorizationProjectionError::Corrupt(code) => ("Corrupt", code),
        AuthorizationProjectionError::Mapping(code) => ("Mapping", code),
        other => panic!("unexpected rejection variant: {other:?}"),
    };
    assert_eq!(
        variant, expected_variant,
        "unexpected variant for {expected_code}"
    );
    assert_eq!(code, expected_code);
}

#[test]
fn archive_intent_parent_proof_accepts_committed_and_superseded_parents() {
    for status in [MANIFEST_STATUS_COMMITTED, MANIFEST_STATUS_SUPERSEDED] {
        let request = archive_intent_request();
        prove_request(&request, &archive_parent_row(status)).unwrap_or_else(|error| {
            panic!("parent status {status} must accept a matching intent: {error}")
        });
    }
}

#[test]
fn archive_intent_parent_proof_rejects_unpublished_and_quarantined_parents() {
    let request = archive_intent_request();
    for status in [
        MANIFEST_STATUS_BUILDING,
        MANIFEST_STATUS_READY,
        MANIFEST_STATUS_QUARANTINED,
    ] {
        assert_parent_rejection(
                prove_request(&request, &archive_parent_row(status)).unwrap_err(),
                "NotReady",
                &format!(
                    "code=authorization_projection.archive_intent_parent_not_archivable;status={status}"
                ),
            );
    }
}

#[test]
fn archive_intent_parent_proof_rejects_every_dimension_mismatch_fail_closed() {
    let parent = archive_parent_row(MANIFEST_STATUS_COMMITTED);

    let mut request = archive_intent_request();
    request.identity = ProjectionAggregateIdentity::new(8, "CARD", 17).unwrap();
    assert_parent_rejection(
        prove_request(&request, &parent).unwrap_err(),
        "IdentityMismatch",
        "code=authorization_projection.archive_intent_parent_identity_mismatch",
    );

    let mut request = archive_intent_request();
    request.card_id = None;
    assert_parent_rejection(
        prove_request(&request, &parent).unwrap_err(),
        "IdentityMismatch",
        "code=authorization_projection.archive_intent_parent_card_scope_mismatch",
    );

    let dimension_cases: [DimensionCase<AuthorizationArchiveIntentAppendRequest>; 7] = [
        ("generation", Box::new(|r| r.archived_generation = 4)),
        (
            "event_id",
            Box::new(|r| r.event_id = "event-drift".to_owned()),
        ),
        (
            "operation_id",
            Box::new(|r| r.operation_id = "op-drift".to_owned()),
        ),
        (
            "semantic_hash",
            Box::new(|r| r.semantic_hash_hex = HASH_B.to_owned()),
        ),
        (
            "dependency_hash",
            Box::new(|r| r.dependency_hash_hex = HASH_A.to_owned()),
        ),
        (
            "compiler_version",
            Box::new(|r| r.compiler_version = "drifted-compiler".to_owned()),
        ),
        (
            "archived_revoke_fence",
            Box::new(|r| r.archived_revoke_fence = 2),
        ),
    ];
    for (dimension, mutate) in dimension_cases {
        let mut request = archive_intent_request();
        mutate(&mut request);
        assert_parent_rejection(
                prove_request(&request, &parent).unwrap_err(),
                "ImmutableConflict",
                &format!(
                    "code=authorization_projection.archive_intent_parent_mismatch;dimension={dimension}"
                ),
            );
    }
}

#[test]
fn archive_intent_parent_proof_fails_closed_on_unreadable_parent_counters() {
    let request = archive_intent_request();

    let mut parent = archive_parent_row(MANIFEST_STATUS_COMMITTED);
    parent.revoke_fence = -1;
    assert_parent_rejection(
        prove_request(&request, &parent).unwrap_err(),
        "Mapping",
        "code=authorization_projection.negative_bigint;field=manifest.revoke_fence;value=-1",
    );

    let mut parent = archive_parent_row(MANIFEST_STATUS_COMMITTED);
    parent.generation = -3;
    assert_parent_rejection(
        prove_request(&request, &parent).unwrap_err(),
        "Mapping",
        "code=authorization_projection.negative_bigint;field=manifest.generation;value=-3",
    );
}

// ── Archive-intent live-pointer proof (pure fail-closed gate) ───────────

/// Live current pointer whose every dimension matches
/// [`archive_intent_request`], carrying the durable fence-proof latch.
fn archive_live_pointer() -> AuthorizationCurrentPointerRecord {
    AuthorizationCurrentPointerRecord {
        pointer_id: 900,
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        card_id: Some(31),
        current_generation: 3,
        manifest_id: 55,
        event_id: "event-stage".to_owned(),
        operation_id: "op-stage".to_owned(),
        semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
        dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
        compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        revoke_fence: 1,
        revoke_fence_proven: true,
        cas_version: 6,
    }
}

fn prove_request_against_pointer(
    request: &AuthorizationArchiveIntentAppendRequest,
    pointer: Option<&AuthorizationCurrentPointerRecord>,
) -> Result<(), AuthorizationProjectionError> {
    prove_archive_intent_against_live_pointer(
        request,
        &Sha256Digest::from_hex(&request.semantic_hash_hex).unwrap(),
        &Sha256Digest::from_hex(&request.dependency_hash_hex).unwrap(),
        pointer,
    )
}

#[test]
fn archive_intent_pointer_proof_accepts_matching_proven_pointer() {
    let request = archive_intent_request();
    prove_request_against_pointer(&request, Some(&archive_live_pointer()))
        .expect("a matching proven live pointer must seed a new archive intent");
}

#[test]
fn archive_intent_pointer_proof_refuses_new_intent_without_live_pointer() {
    let request = archive_intent_request();
    // A superseded (pointer moved past) or never-published parent has no
    // live pointer: a NEW intent is refused instead of being seeded from
    // the manifest row's numeric fence alone. Only an already-committed
    // intent may be replayed after supersession.
    assert_parent_rejection(
        prove_request_against_pointer(&request, None).unwrap_err(),
        "NotReady",
        "code=authorization_projection.archive_intent_parent_pointer_missing",
    );
}

#[test]
fn archive_intent_pointer_proof_refuses_unproven_fence_latch_regardless_of_value() {
    let request = archive_intent_request();
    // Matching fence value but the pointer predates the Rust contract:
    // the latch, never the numeric value, decides.
    let mut unproven = archive_live_pointer();
    unproven.revoke_fence_proven = false;
    assert_parent_rejection(
        prove_request_against_pointer(&request, Some(&unproven)).unwrap_err(),
        "NotReady",
        "code=authorization_projection.archive_intent_pointer_fence_unproven;pointer_fence=1",
    );
    // The honest zero sentinel is equally refused while unproven.
    let mut unproven_zero = archive_live_pointer();
    unproven_zero.revoke_fence = 0;
    unproven_zero.revoke_fence_proven = false;
    assert_parent_rejection(
        prove_request_against_pointer(&request, Some(&unproven_zero)).unwrap_err(),
        "NotReady",
        "code=authorization_projection.archive_intent_pointer_fence_unproven;pointer_fence=0",
    );
}

#[test]
fn archive_intent_pointer_proof_rejects_every_dimension_mismatch_fail_closed() {
    let pointer = archive_live_pointer();

    let mut request = archive_intent_request();
    request.identity = ProjectionAggregateIdentity::new(8, "CARD", 17).unwrap();
    assert_parent_rejection(
        prove_request_against_pointer(&request, Some(&pointer)).unwrap_err(),
        "IdentityMismatch",
        "code=authorization_projection.archive_intent_pointer_identity_mismatch",
    );

    let mut request = archive_intent_request();
    request.card_id = None;
    assert_parent_rejection(
        prove_request_against_pointer(&request, Some(&pointer)).unwrap_err(),
        "IdentityMismatch",
        "code=authorization_projection.archive_intent_pointer_card_scope_mismatch",
    );

    let dimension_cases: [DimensionCase<AuthorizationArchiveIntentAppendRequest>; 8] = [
        (
            "archived_manifest_id",
            Box::new(|r| r.archived_manifest_id = 56),
        ),
        ("generation", Box::new(|r| r.archived_generation = 4)),
        (
            "event_id",
            Box::new(|r| r.event_id = "event-drift".to_owned()),
        ),
        (
            "operation_id",
            Box::new(|r| r.operation_id = "op-drift".to_owned()),
        ),
        (
            "semantic_hash",
            Box::new(|r| r.semantic_hash_hex = HASH_B.to_owned()),
        ),
        (
            "dependency_hash",
            Box::new(|r| r.dependency_hash_hex = HASH_A.to_owned()),
        ),
        (
            "compiler_version",
            Box::new(|r| r.compiler_version = "drifted-compiler".to_owned()),
        ),
        (
            "archived_revoke_fence",
            Box::new(|r| r.archived_revoke_fence = 2),
        ),
    ];
    for (dimension, mutate) in dimension_cases {
        let mut request = archive_intent_request();
        mutate(&mut request);
        assert_parent_rejection(
                prove_request_against_pointer(&request, Some(&pointer)).unwrap_err(),
                "ImmutableConflict",
                &format!(
                    "code=authorization_projection.archive_intent_pointer_mismatch;dimension={dimension}"
                ),
            );
    }
}

// ── Manifest v2 digest regressions (pure known answer + sensitivity) ────

/// Independent known answer over the exact `astral-auth-manifest-v2`
/// material (domain tag, big-endian i64 counters, `-1` sentinels for
/// absent card/parent, u32 length-prefixed ASCII, raw 32-byte hashes),
/// computed outside Rust from the documented encoding. Any change to the
/// domain, field order, widths or sentinels trips this pin.
const MANIFEST_V2_KNOWN_ANSWER: &str =
    "fc4c41e842bf940e5831626a40bde563be2dfe678eb1a1533d8f9229b6a286fd";

fn digest_input_v2(segments: Vec<String>) -> ManifestDigestInput<'static> {
    ManifestDigestInput {
        tenant_id: 7,
        aggregate_type: "CARD",
        aggregate_id: 17,
        card_id: None,
        generation: 3,
        source_generation: 9,
        projected_generation: 9,
        event_id: "event-stage",
        operation_id: "op-stage",
        semantic_hash_hex: HASH_A,
        dependency_hash_hex: HASH_B,
        compiler_version: "phase2-authorization-kernel-v1",
        parent_manifest_id: Some(2),
        revoke_fence: 1,
        segment_content_digests_hex: segments,
    }
}

#[test]
fn manifest_digest_v2_known_answer_pins_domain_encoding() {
    let digest = compute_manifest_digest(&digest_input_v2(vec![HASH_A.to_owned()])).unwrap();
    assert_eq!(digest.as_hex(), MANIFEST_V2_KNOWN_ANSWER);
}

#[test]
fn manifest_digest_changes_when_any_sealed_dimension_changes() {
    let base = compute_manifest_digest(&digest_input_v2(vec![HASH_A.to_owned()])).unwrap();
    let mutations: [DimensionCase<'static, ManifestDigestInput<'static>>; 7] = [
        (
            "parent_manifest_id",
            Box::new(|i| i.parent_manifest_id = Some(3)),
        ),
        (
            "parent_manifest_id_none",
            Box::new(|i| i.parent_manifest_id = None),
        ),
        ("revoke_fence", Box::new(|i| i.revoke_fence = 2)),
        ("event_id", Box::new(|i| i.event_id = "event-drift")),
        ("operation_id", Box::new(|i| i.operation_id = "op-drift")),
        (
            "compiler_version",
            Box::new(|i| i.compiler_version = "drifted-compiler"),
        ),
        (
            "segment_digest_same_length",
            Box::new(|i| i.segment_content_digests_hex = vec![HASH_B.to_owned()]),
        ),
    ];
    for (dimension, mutate) in mutations {
        let mut input = digest_input_v2(vec![HASH_A.to_owned()]);
        mutate(&mut input);
        let digest = compute_manifest_digest(&input).unwrap();
        assert_ne!(digest, base, "{dimension} must change the manifest digest");
    }
}

#[test]
fn manifest_digest_fails_closed_on_non_positive_parent_and_non_ascii_fields() {
    for parent in [0, -1] {
        let mut input = digest_input_v2(vec![HASH_A.to_owned()]);
        input.parent_manifest_id = Some(parent);
        let error = compute_manifest_digest(&input).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::ScopeViolation(ref message)
                if message.contains("authorization_projection.non_positive_id")
                    && message.contains("field=parent_manifest_id")),
            "parent id {parent} must be refused: {error:?}"
        );
    }

    let mut input = digest_input_v2(vec![HASH_A.to_owned()]);
    input.event_id = "événement";
    let error = compute_manifest_digest(&input).unwrap_err();
    assert!(
        matches!(error, AuthorizationProjectionError::ScopeViolation(ref message)
            if message.contains("non_ascii_provenance_digest_field"))
    );

    let mut input = digest_input_v2(vec![HASH_A.to_owned()]);
    input.compiler_version = "compilateur-vé2";
    let error = compute_manifest_digest(&input).unwrap_err();
    assert!(
        matches!(error, AuthorizationProjectionError::ScopeViolation(ref message)
            if message.contains("non_ascii_manifest_digest_field"))
    );
}

#[test]
fn first_publication_rejects_sealed_parent_lineage_fail_closed() {
    let expectation = AuthorizationPublishExpectation {
        current_pointer: None,
        expected_target_semantic_hash_hex: HASH_A.to_owned(),
        expected_target_dependency_hash_hex: HASH_B.to_owned(),
        expected_target_compiler_version: "phase2-authorization-kernel-v1".to_owned(),
    };
    let mut target = ready_target(1, 500);
    target.parent_manifest_id = Some(400);
    let error = validate_manifest_publish(&expectation, &target).unwrap_err();
    assert!(
        matches!(error, AuthorizationProjectionError::ManifestPublishConflict(ref message)
            if message.contains("first_publication_requires_no_parent"))
    );
}

// ── Archive proof parent gate (record path, pure fail-closed) ───────────

/// Proof request whose every dimension matches [`archive_parent_row`].
fn archive_proof_request() -> AuthorizationArchiveProofRequest {
    AuthorizationArchiveProofRequest {
        identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
        card_id: Some(31),
        archived_manifest_id: 55,
        archived_generation: 3,
        event_id: "event-stage".to_owned(),
        operation_id: "op-stage".to_owned(),
        archive_key: "astral-auth-archive/v1/7/CARD/17/generation-3".to_owned(),
        semantic_hash_hex: HASH_A.to_owned(),
        dependency_hash_hex: HASH_B.to_owned(),
        compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        archived_revoke_fence: 1,
        manifest_chain_digest_hex: HASH_A.to_owned(),
    }
}

fn prove_proof_request(
    request: &AuthorizationArchiveProofRequest,
    parent: &ManifestRawSqlRow,
) -> Result<(), AuthorizationProjectionError> {
    prove_archive_proof_request_against_parent_manifest(
        request,
        &Sha256Digest::from_hex(&request.semantic_hash_hex).unwrap(),
        &Sha256Digest::from_hex(&request.dependency_hash_hex).unwrap(),
        parent,
    )
}

#[test]
fn archive_proof_parent_gate_accepts_matching_committed_and_superseded() {
    for status in [MANIFEST_STATUS_COMMITTED, MANIFEST_STATUS_SUPERSEDED] {
        let request = archive_proof_request();
        prove_proof_request(&request, &archive_parent_row(status)).unwrap_or_else(|error| {
            panic!("parent status {status} must accept a matching proof: {error}")
        });
    }
}

#[test]
fn archive_proof_parent_gate_rejects_every_dimension_mismatch_fail_closed() {
    let parent = archive_parent_row(MANIFEST_STATUS_COMMITTED);

    let mut request = archive_proof_request();
    request.identity = ProjectionAggregateIdentity::new(8, "CARD", 17).unwrap();
    assert_parent_rejection(
        prove_proof_request(&request, &parent).unwrap_err(),
        "IdentityMismatch",
        "code=authorization_projection.archive_parent_identity_mismatch",
    );

    let mut request = archive_proof_request();
    request.card_id = None;
    assert_parent_rejection(
        prove_proof_request(&request, &parent).unwrap_err(),
        "IdentityMismatch",
        "code=authorization_projection.archive_parent_card_scope_mismatch",
    );

    let mut request = archive_proof_request();
    request.archived_generation = 4;
    assert_parent_rejection(
        prove_proof_request(&request, &parent).unwrap_err(),
        "Corrupt",
        "code=authorization_projection.archive_parent_generation_mismatch",
    );

    let mut request = archive_proof_request();
    request.event_id = "event-drift".to_owned();
    assert_parent_rejection(
        prove_proof_request(&request, &parent).unwrap_err(),
        "IdentityMismatch",
        "code=authorization_projection.archive_parent_provenance_mismatch",
    );

    let mut request = archive_proof_request();
    request.operation_id = "op-drift".to_owned();
    assert_parent_rejection(
        prove_proof_request(&request, &parent).unwrap_err(),
        "IdentityMismatch",
        "code=authorization_projection.archive_parent_provenance_mismatch",
    );

    let mut request = archive_proof_request();
    request.archived_revoke_fence = 2;
    assert_parent_rejection(
        prove_proof_request(&request, &parent).unwrap_err(),
        "ImmutableConflict",
        "code=authorization_projection.archive_parent_fence_mismatch",
    );

    // Defense in depth beyond the sealed chain: direct hash/compiler dims.
    let mut request = archive_proof_request();
    request.semantic_hash_hex = HASH_B.to_owned();
    assert_parent_rejection(
        prove_proof_request(&request, &parent).unwrap_err(),
        "Corrupt",
        "code=authorization_projection.archive_parent_semantic_hash_mismatch",
    );

    let mut request = archive_proof_request();
    request.dependency_hash_hex = HASH_A.to_owned();
    assert_parent_rejection(
        prove_proof_request(&request, &parent).unwrap_err(),
        "Corrupt",
        "code=authorization_projection.archive_parent_dependency_hash_mismatch",
    );

    let mut request = archive_proof_request();
    request.compiler_version = "drifted-compiler".to_owned();
    assert_parent_rejection(
        prove_proof_request(&request, &parent).unwrap_err(),
        "Corrupt",
        "code=authorization_projection.archive_parent_compiler_mismatch",
    );

    let request = archive_proof_request();
    let quarantined = archive_parent_row(MANIFEST_STATUS_QUARANTINED);
    assert_parent_rejection(
        prove_proof_request(&request, &quarantined).unwrap_err(),
        "NotReady",
        "code=authorization_projection.archive_parent_not_archivable;status=QUARANTINED",
    );
}

// ── Archive lease heartbeat (pure bounds + SQL shape) ───────────────────

#[test]
fn archive_lease_heartbeat_bounds_fail_closed() {
    for seconds in [0, MAX_ARCHIVE_LEASE_SECONDS + 1, -5] {
        let error = validate_archive_lease_material("itest-owner", seconds).unwrap_err();
        assert!(
            matches!(error, AuthorizationProjectionError::ScopeViolation(ref message)
                if message.contains("authorization_projection.invalid_archive_lease_seconds")),
            "seconds {seconds} must be refused: {error:?}"
        );
    }
    let error = validate_archive_lease_material("   ", 60).unwrap_err();
    assert!(
        matches!(error, AuthorizationProjectionError::ScopeViolation(ref message)
            if message.contains("field=lease_owner"))
    );
}

#[test]
fn archive_heartbeat_sql_renews_only_the_live_lease() {
    // Renewal mutates ONLY the expiry: no attempts, no cas_version, no
    // status write — retry accounting and CAS semantics stay untouched.
    assert!(ARCHIVE_HEARTBEAT_SQL
        .contains("SET lease_expires_at = TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP())"));
    assert!(!ARCHIVE_HEARTBEAT_SQL.contains("attempts"));
    assert!(!ARCHIVE_HEARTBEAT_SQL.contains("cas_version"));
    assert!(!ARCHIVE_HEARTBEAT_SQL.contains("status"));
    // The guard rebinds the full stable lease identity and requires the
    // row to still be LEASED with an unexpired (live) lease.
    let full = format!("{ARCHIVE_HEARTBEAT_SQL}{ARCHIVE_LEASE_GUARD_SUFFIX}");
    for fragment in [
        "WHERE archive_outbox_id = ? AND event_id = ?",
        "lease_owner = ?",
        "lease_token_hash = ?",
        "status = 'LEASED'",
        "lease_expires_at IS NOT NULL",
        "lease_expires_at > UTC_TIMESTAMP()",
    ] {
        assert!(full.contains(fragment), "heartbeat SQL lacks `{fragment}`");
    }
}

// ── Legacy fence-proof rehearsal (pure gates + SQL shapes, no DB) ───────

fn rehearsal_expectation() -> AuthorizationFenceProofRehearsalExpectation {
    AuthorizationFenceProofRehearsalExpectation {
        manifest_id: 55,
        generation: 1,
        semantic_hash_hex: HASH_A.to_owned(),
        dependency_hash_hex: HASH_B.to_owned(),
        compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        revoke_fence: 0,
        cas_version: 4,
    }
}

fn rehearsal_request() -> AuthorizationFenceProofRehearsalRequest {
    AuthorizationFenceProofRehearsalRequest {
        identity: identity(),
        card_id: Some(31),
        operator_id: 42,
        operation_id: "op-fence-rehearsal-20260826-0001".to_owned(),
        expectation: rehearsal_expectation(),
        reason: "operator_rehearsal_for_legacy_unproven_pointer".to_owned(),
    }
}

/// Durable pointer whose every dimension matches [`rehearsal_request`];
/// the latch is parameterized so both decision paths stay exercisable.
fn rehearsal_pointer(revoke_fence_proven: bool) -> AuthorizationCurrentPointerRecord {
    AuthorizationCurrentPointerRecord {
        pointer_id: 900,
        identity: identity(),
        card_id: Some(31),
        current_generation: 1,
        manifest_id: 55,
        event_id: "event-stage".to_owned(),
        operation_id: "op-stage".to_owned(),
        semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap(),
        dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap(),
        compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        revoke_fence: 0,
        revoke_fence_proven,
        cas_version: 4,
    }
}

/// Committed generation-one manifest matching the rehearsal pointer;
/// `status`/lineage/fence are parameterized for the refusal matrix.
fn rehearsal_manifest_row(status: &str) -> ManifestRawSqlRow {
    ManifestRawSqlRow {
        manifest_id: 55,
        tenant_id: 7,
        card_id: Some(31),
        aggregate_type: "CARD".to_owned(),
        aggregate_id: 17,
        generation: 1,
        source_generation: 9,
        projected_generation: 9,
        event_id: "event-stage".to_owned(),
        operation_id: "op-stage".to_owned(),
        semantic_hash: Sha256Digest::from_hex(HASH_A).unwrap().as_bytes().to_vec(),
        dependency_hash: Sha256Digest::from_hex(HASH_B).unwrap().as_bytes().to_vec(),
        compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        manifest_digest: Sha256Digest::from_hex(HASH_A).unwrap().as_bytes().to_vec(),
        status: status.to_owned(),
        cas_version: 4,
        lease_owner: None,
        lease_token_hash: None,
        lease_expires_at: None,
        parent_manifest_id: None,
        revoke_fence: 0,
    }
}

fn prove_rehearsal_manifest(
    pointer: &AuthorizationCurrentPointerRecord,
    manifest: &ManifestRawSqlRow,
) -> Result<(), AuthorizationProjectionError> {
    prove_fence_proof_rehearsal_manifest(pointer, manifest)
}

/// Variant check plus code-prefix check: rehearsal refusals may append
/// durable/evidence forensics after the stable machine code.
fn assert_rehearsal_rejection_prefix(
    error: AuthorizationProjectionError,
    expected_variant: &str,
    expected_code_prefix: &str,
) {
    let (variant, code) = match error {
        AuthorizationProjectionError::IdentityMismatch(code) => ("IdentityMismatch", code),
        AuthorizationProjectionError::CurrentPointerCasConflict(code) => {
            ("CurrentPointerCasConflict", code)
        }
        AuthorizationProjectionError::NotReady(code) => ("NotReady", code),
        AuthorizationProjectionError::Corrupt(code) => ("Corrupt", code),
        other => panic!("unexpected rejection variant: {other:?}"),
    };
    assert_eq!(
        variant, expected_variant,
        "unexpected variant for {expected_code_prefix}"
    );
    assert!(
        code.starts_with(expected_code_prefix),
        "code `{code}` lacks prefix `{expected_code_prefix}`"
    );
}

#[test]
fn fence_proof_rehearsal_request_shape_is_validated_fail_closed() {
    let request = rehearsal_request();
    validate_fence_proof_rehearsal_request(&request)
        .expect("a well-formed rehearsal request must validate");

    let mut mutated = rehearsal_request();
    mutated.operator_id = 0;
    assert!(matches!(
        validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
        AuthorizationProjectionError::ScopeViolation(ref message)
            if message.contains("field=operator_id")
    ));

    let mut mutated = rehearsal_request();
    mutated.operation_id = "  ".to_owned();
    assert!(matches!(
        validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
        AuthorizationProjectionError::ScopeViolation(ref message)
            if message.contains("field=operation_id")
    ));

    let mut mutated = rehearsal_request();
    mutated.operation_id = "o".repeat(MAX_FENCE_PROOF_REHEARSAL_OPERATION_ID_LENGTH + 1);
    assert!(matches!(
        validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
        AuthorizationProjectionError::ScopeViolation(ref message)
            if message.contains("field=operation_id")
    ));

    let mut mutated = rehearsal_request();
    mutated.reason = String::new();
    assert!(matches!(
        validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
        AuthorizationProjectionError::ScopeViolation(ref message)
            if message.contains("field=reason")
    ));

    let mut mutated = rehearsal_request();
    mutated.reason = "r".repeat(MAX_FENCE_PROOF_REHEARSAL_REASON_LENGTH + 1);
    assert!(matches!(
        validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
        AuthorizationProjectionError::ScopeViolation(ref message)
            if message.contains("field=reason")
    ));

    let mut mutated = rehearsal_request();
    mutated.expectation.generation = 0;
    assert!(matches!(
        validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
        AuthorizationProjectionError::ScopeViolation(ref message)
            if message.contains("invalid_rehearsal_generation")
    ));

    let mut mutated = rehearsal_request();
    mutated.expectation.semantic_hash_hex = "zz".to_owned();
    assert!(matches!(
        validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
        AuthorizationProjectionError::ScopeViolation(ref message)
            if message.contains("invalid_rehearsal_semantic_hash")
    ));

    let mut mutated = rehearsal_request();
    mutated.expectation.dependency_hash_hex = HASH_A[..30].to_owned();
    assert!(matches!(
        validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
        AuthorizationProjectionError::ScopeViolation(ref message)
            if message.contains("invalid_rehearsal_dependency_hash")
    ));

    let mut mutated = rehearsal_request();
    mutated.card_id = Some(0);
    assert!(matches!(
        validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
        AuthorizationProjectionError::ScopeViolation(ref message)
            if message.contains("field=card_id")
    ));

    let mut mutated = rehearsal_request();
    mutated.expectation.manifest_id = 0;
    assert!(matches!(
        validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
        AuthorizationProjectionError::ScopeViolation(ref message)
            if message.contains("field=expectation.manifest_id")
    ));

    let mut mutated = rehearsal_request();
    mutated.reason = "r".repeat(MAX_FENCE_PROOF_REHEARSAL_REASON_LENGTH + 1);
    assert!(matches!(
        validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
        AuthorizationProjectionError::ScopeViolation(ref message)
            if message.contains("field=reason")
    ));

    // Padding is refused outright: the raw values are bound verbatim into
    // the durable audit row, so they must equal their validated form.
    let mut mutated = rehearsal_request();
    mutated.operation_id = "  padded-operation-id  ".to_owned();
    assert!(matches!(
        validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
        AuthorizationProjectionError::ScopeViolation(ref message)
            if message.contains("invalid_rehearsal_operation_id_padding")
    ));

    let mut mutated = rehearsal_request();
    mutated.reason = "operator_rehearsal_reason ".to_owned();
    assert!(matches!(
        validate_fence_proof_rehearsal_request(&mutated).unwrap_err(),
        AuthorizationProjectionError::ScopeViolation(ref message)
            if message.contains("invalid_rehearsal_reason_padding")
    ));
}

#[test]
fn reference_card_scope_must_match_manifest_scope() {
    verify_reference_card_scope(None, None)
        .expect("aggregate-wide references must match an aggregate-wide manifest");
    verify_reference_card_scope(Some(31), Some(31)).expect("equal card scopes must validate");

    // A reference row claiming a foreign (or NULL/aggregate-wide) card
    // scope against a card-scoped manifest — or the inverse — is
    // cross-scope contamination and must fail closed.
    for (record_card_id, manifest_card_id) in
        [(Some(31), Some(32)), (Some(31), None), (None, Some(31))]
    {
        assert!(
                matches!(
                    verify_reference_card_scope(record_card_id, manifest_card_id).unwrap_err(),
                    AuthorizationProjectionError::IdentityMismatch(ref message)
                        if message.contains("code=authorization_projection.reference_card_scope_mismatch")
                ),
                "reference scope {record_card_id:?} vs manifest scope {manifest_card_id:?} must be refused"
            );
    }
}

#[test]
fn read_side_reference_cap_fails_closed_above_staging_bound() {
    enforce_segment_reference_cap(0).expect("zero references must pass the read cap");
    enforce_segment_reference_cap(MAX_SEGMENTS_PER_MANIFEST)
        .expect("exactly the bound must pass the read cap");
    assert!(matches!(
        enforce_segment_reference_cap(MAX_SEGMENTS_PER_MANIFEST + 1).unwrap_err(),
        AuthorizationProjectionError::ScopeViolation(ref message)
            if message.contains("code=authorization_projection.too_many_segments_per_manifest")
    ));
}

/// Minimal publish request whose every compared dimension matches
/// [`publish_readback_pointer`].
fn publish_readback_request() -> AuthorizationPublishRequest {
    AuthorizationPublishRequest {
        identity: identity(),
        card_id: Some(31),
        target_manifest_id: 55,
        target_generation: 1,
        current_pointer: None,
        expected_target_semantic_hash_hex: HASH_A.to_owned(),
        expected_target_dependency_hash_hex: HASH_B.to_owned(),
        expected_target_compiler_version: "phase2-authorization-kernel-v1".to_owned(),
        fences: PublishRevokeFenceEvidence {
            previous_revoke_fence: 0,
            new_revoke_fence: 5,
        },
    }
}

/// Pointer row as it must read back after the CAS: every dimension equals
/// the published evidence, with the target provenance passed explicitly.
fn publish_readback_pointer(
    request: &AuthorizationPublishRequest,
    event_id: &str,
    operation_id: &str,
) -> AuthorizationCurrentPointerRecord {
    AuthorizationCurrentPointerRecord {
        pointer_id: 900,
        identity: request.identity.clone(),
        card_id: request.card_id,
        current_generation: request.target_generation,
        manifest_id: request.target_manifest_id,
        event_id: event_id.to_owned(),
        operation_id: operation_id.to_owned(),
        semantic_hash: Sha256Digest::from_hex(&request.expected_target_semantic_hash_hex).unwrap(),
        dependency_hash: Sha256Digest::from_hex(&request.expected_target_dependency_hash_hex)
            .unwrap(),
        compiler_version: request.expected_target_compiler_version.clone(),
        revoke_fence: request.fences.new_revoke_fence,
        revoke_fence_proven: true,
        cas_version: 5,
    }
}

#[test]
fn post_publish_readback_proves_target_provenance() {
    let request = publish_readback_request();
    let target_event_id = "event-publish";
    let target_operation_id = "op-publish";
    let target_semantic = Sha256Digest::from_hex(HASH_A).unwrap();
    let target_dependency = Sha256Digest::from_hex(HASH_B).unwrap();

    let pointer = publish_readback_pointer(&request, target_event_id, target_operation_id);
    assert!(post_publish_pointer_agrees(
        &pointer,
        &request,
        target_event_id,
        target_operation_id,
        &target_semantic,
        &target_dependency,
    ));

    // Stale or forged provenance must fail the readback even when every
    // other dimension matches: the pointer may only carry the target
    // manifest's own event/operation identity.
    for forged_event_id in ["", "event-stage", "event-publish-x"] {
        let pointer = publish_readback_pointer(&request, forged_event_id, target_operation_id);
        assert!(
            !post_publish_pointer_agrees(
                &pointer,
                &request,
                target_event_id,
                target_operation_id,
                &target_semantic,
                &target_dependency,
            ),
            "event_id disagreement must fail the post-publish readback"
        );
    }
    for forged_operation_id in ["", "op-stage", "op-publish-x"] {
        let pointer = publish_readback_pointer(&request, target_event_id, forged_operation_id);
        assert!(
            !post_publish_pointer_agrees(
                &pointer,
                &request,
                target_event_id,
                target_operation_id,
                &target_semantic,
                &target_dependency,
            ),
            "operation_id disagreement must fail the post-publish readback"
        );
    }
}

fn verified_publication_fixture() -> (
    AuthorizationCurrentPointerRecord,
    ManifestRawSqlRow,
    Vec<AuthorizationSegmentReferenceRecord>,
    Vec<AuthorizationSegmentSnapshot>,
) {
    let mut manifest = rehearsal_manifest_row(MANIFEST_STATUS_COMMITTED);
    manifest.card_id = Some(17);
    let identity = manifest.decode_identity().unwrap();
    let snapshot = sealed_snapshot(
        &identity,
        manifest.card_id,
        &manifest.compiler_version,
        &[grant(1)],
        91,
    );
    manifest.manifest_digest = manifest
        .recomputed_digest(vec![snapshot.content_digest.as_hex()])
        .unwrap()
        .as_bytes()
        .to_vec();
    let pointer = AuthorizationCurrentPointerRecord {
        pointer_id: 1,
        identity: identity.clone(),
        card_id: manifest.card_id,
        current_generation: manifest.generation as u64,
        manifest_id: manifest.manifest_id,
        event_id: manifest.event_id.clone(),
        operation_id: manifest.operation_id.clone(),
        semantic_hash: Sha256Digest::from_bytes(manifest.semantic_hash.clone()).unwrap(),
        dependency_hash: Sha256Digest::from_bytes(manifest.dependency_hash.clone()).unwrap(),
        compiler_version: manifest.compiler_version.clone(),
        revoke_fence: manifest.revoke_fence as u64,
        revoke_fence_proven: true,
        cas_version: 1,
    };
    let reference = AuthorizationSegmentReferenceRecord {
        reference_id: 1,
        manifest_id: manifest.manifest_id,
        identity,
        card_id: manifest.card_id,
        generation: manifest.generation as u64,
        ordinal: 0,
        segment_id: snapshot.segment_id,
        content_digest: snapshot.content_digest,
        event_id: manifest.event_id.clone(),
        operation_id: manifest.operation_id.clone(),
    };
    (pointer, manifest, vec![reference], vec![snapshot])
}

#[test]
fn strict_reader_and_publisher_share_complete_state_assembly() {
    let (pointer, manifest, references, segments) = verified_publication_fixture();
    let state = assemble_verified_published_state(
        pointer.clone(),
        &manifest,
        references.clone(),
        segments.clone(),
    )
    .unwrap();
    assert_eq!(state.pointer, pointer);
    assert_eq!(state.segments, segments);
    assert_eq!(state.references, references);
    assert_eq!(state.source_generation, 9);
    assert_eq!(state.generation, 1);
    assert_eq!(state.total_grant_count, 1);
}

#[test]
fn shared_published_state_assembly_rejects_pointer_chain_and_seal_drift() {
    for dimension in [
        "proof",
        "pointer-generation",
        "pointer-manifest",
        "pointer-operation",
        "status",
        "reference",
        "segment",
        "length",
        "seal",
    ] {
        let (mut pointer, mut manifest, mut references, mut segments) =
            verified_publication_fixture();
        match dimension {
            "proof" => pointer.revoke_fence_proven = false,
            "pointer-generation" => pointer.current_generation += 1,
            "pointer-manifest" => pointer.manifest_id += 1,
            "pointer-operation" => pointer.operation_id.push_str("-other"),
            "status" => manifest.status = MANIFEST_STATUS_READY.to_owned(),
            "reference" => references[0].event_id.push_str("-other"),
            "segment" => segments[0].content_digest = Sha256Digest::from_hex(HASH_A).unwrap(),
            "length" => segments.clear(),
            "seal" => {
                manifest.manifest_digest =
                    Sha256Digest::from_hex(HASH_A).unwrap().as_bytes().to_vec()
            }
            _ => unreachable!(),
        }
        assert!(
            assemble_verified_published_state(pointer, &manifest, references, segments).is_err(),
            "{dimension}"
        );
    }
}

#[test]
fn fence_proof_rehearsal_decision_accepts_unproven_zero_fence_generation_one() {
    let decision = decide_fence_proof_rehearsal(&rehearsal_request(), &rehearsal_pointer(false))
        .expect("an exactly matching unproven zero-fence gen-one pointer must rehearse");
    assert_eq!(
        decision,
        FenceProofRehearsalDecision::RehearseLegacyZeroFence
    );
}

#[test]
fn fence_proof_rehearsal_replay_of_proven_pointer_is_a_verified_no_op() {
    // Exact replay after a successful latch: every dimension (including
    // the advanced CAS counter and the fence) matches => verified no-op.
    let decision = decide_fence_proof_rehearsal(&rehearsal_request(), &rehearsal_pointer(true))
        .expect("an exactly matching proven pointer must be a verified no-op");
    assert_eq!(decision, FenceProofRehearsalDecision::AlreadyProven);

    // A proven NONZERO fence is an equally valid no-op match when the
    // caller re-read the fresh evidence: the latch, never the value.
    let mut proven_positive = rehearsal_pointer(true);
    proven_positive.revoke_fence = 3;
    let mut fresh = rehearsal_request();
    fresh.expectation.revoke_fence = 3;
    assert_eq!(
        decide_fence_proof_rehearsal(&fresh, &proven_positive).unwrap(),
        FenceProofRehearsalDecision::AlreadyProven
    );
}

#[test]
fn fence_proof_rehearsal_refuses_identity_and_card_scope_drift() {
    for proven in [false, true] {
        let pointer = rehearsal_pointer(proven);

        let mut request = rehearsal_request();
        request.identity = ProjectionAggregateIdentity::new(8, "CARD", 17).unwrap();
        assert_parent_rejection(
            decide_fence_proof_rehearsal(&request, &pointer).unwrap_err(),
            "IdentityMismatch",
            "code=authorization_projection.fence_proof_identity_mismatch",
        );

        let mut request = rehearsal_request();
        request.card_id = None;
        assert_parent_rejection(
            decide_fence_proof_rehearsal(&request, &pointer).unwrap_err(),
            "IdentityMismatch",
            "code=authorization_projection.fence_proof_card_scope_mismatch",
        );
    }
}

#[test]
fn fence_proof_rehearsal_refuses_every_stale_expectation_dimension() {
    let dimension_cases: [DimensionCase<AuthorizationFenceProofRehearsalRequest>; 7] = [
        ("manifest_id", Box::new(|r| r.expectation.manifest_id = 56)),
        ("generation", Box::new(|r| r.expectation.generation = 2)),
        (
            "semantic_hash",
            Box::new(|r| r.expectation.semantic_hash_hex = HASH_B.to_owned()),
        ),
        (
            "dependency_hash",
            Box::new(|r| r.expectation.dependency_hash_hex = HASH_A.to_owned()),
        ),
        (
            "compiler_version",
            Box::new(|r| r.expectation.compiler_version = "drifted-compiler".to_owned()),
        ),
        ("revoke_fence", Box::new(|r| r.expectation.revoke_fence = 1)),
        ("cas_version", Box::new(|r| r.expectation.cas_version = 5)),
    ];
    for proven in [false, true] {
        let pointer = rehearsal_pointer(proven);
        for (dimension, mutate) in dimension_cases.iter() {
            let mut request = rehearsal_request();
            mutate(&mut request);
            assert_rehearsal_rejection_prefix(
                    decide_fence_proof_rehearsal(&request, &pointer).unwrap_err(),
                    "CurrentPointerCasConflict",
                    &format!(
                        "code=authorization_projection.fence_proof_expectation_mismatch;dimension={dimension}"
                    ),
                );
        }
    }
}

#[test]
fn fence_proof_rehearsal_refuses_unproven_nonzero_fence_and_multi_generation() {
    // A nonzero numeric fence on an unproven row is unprovable history.
    // The caller's expectation must first match the fresh durable value
    // (stale evidence is refused earlier as an expectation mismatch); the
    // legacy gate then refuses the value itself.
    let mut pointer = rehearsal_pointer(false);
    pointer.revoke_fence = 5;
    let mut fresh = rehearsal_request();
    fresh.expectation.revoke_fence = 5;
    assert_parent_rejection(
        decide_fence_proof_rehearsal(&fresh, &pointer).unwrap_err(),
        "NotReady",
        "code=authorization_projection.fence_proof_requires_zero_fence;pointer_fence=5",
    );
    // Stale evidence naming fence 0 against a durable 5 refuses earlier.
    assert_rehearsal_rejection_prefix(
        decide_fence_proof_rehearsal(&rehearsal_request(), &pointer).unwrap_err(),
        "CurrentPointerCasConflict",
        "code=authorization_projection.fence_proof_expectation_mismatch;dimension=revoke_fence",
    );

    // Generation-one chains only: a multi-generation legacy chain would
    // require proving a parent lineage the legacy rows cannot supply.
    let mut pointer = rehearsal_pointer(false);
    pointer.current_generation = 2;
    let mut fresh = rehearsal_request();
    fresh.expectation.generation = 2;
    assert_parent_rejection(
            decide_fence_proof_rehearsal(&fresh, &pointer).unwrap_err(),
            "NotReady",
            "code=authorization_projection.fence_proof_requires_generation_one_chain;pointer_generation=2",
        );
}

#[test]
fn fence_proof_rehearsal_manifest_proof_accepts_only_committed_generation_one() {
    let pointer = rehearsal_pointer(false);
    prove_rehearsal_manifest(&pointer, &rehearsal_manifest_row(MANIFEST_STATUS_COMMITTED))
        .expect("a committed parentless zero-fence gen-one manifest must prove");

    for status in [
        MANIFEST_STATUS_BUILDING,
        MANIFEST_STATUS_READY,
        MANIFEST_STATUS_SUPERSEDED,
        MANIFEST_STATUS_QUARANTINED,
    ] {
        assert_parent_rejection(
            prove_rehearsal_manifest(&pointer, &rehearsal_manifest_row(status)).unwrap_err(),
            "NotReady",
            &format!(
                "code=authorization_projection.fence_proof_manifest_not_committed;status={status}"
            ),
        );
    }

    let mut manifest = rehearsal_manifest_row(MANIFEST_STATUS_COMMITTED);
    manifest.parent_manifest_id = Some(2);
    assert_parent_rejection(
        prove_rehearsal_manifest(&pointer, &manifest).unwrap_err(),
        "Corrupt",
        "code=authorization_projection.fence_proof_manifest_has_parent;parent=Some(2)",
    );

    let mut manifest = rehearsal_manifest_row(MANIFEST_STATUS_COMMITTED);
    manifest.revoke_fence = 1;
    assert_parent_rejection(
        prove_rehearsal_manifest(&pointer, &manifest).unwrap_err(),
        "Corrupt",
        "code=authorization_projection.fence_proof_manifest_fence_nonzero;fence=1",
    );

    let mut manifest = rehearsal_manifest_row(MANIFEST_STATUS_COMMITTED);
    manifest.generation = 2;
    assert_parent_rejection(
        prove_rehearsal_manifest(&pointer, &manifest).unwrap_err(),
        "Corrupt",
        "code=authorization_projection.fence_proof_manifest_generation_split",
    );

    let mut manifest = rehearsal_manifest_row(MANIFEST_STATUS_COMMITTED);
    manifest.semantic_hash = Sha256Digest::from_hex(HASH_B).unwrap().as_bytes().to_vec();
    assert_parent_rejection(
        prove_rehearsal_manifest(&pointer, &manifest).unwrap_err(),
        "Corrupt",
        "code=authorization_projection.fence_proof_manifest_hash_chain_break",
    );

    let mut manifest = rehearsal_manifest_row(MANIFEST_STATUS_COMMITTED);
    manifest.dependency_hash = Sha256Digest::from_hex(HASH_A).unwrap().as_bytes().to_vec();
    assert_parent_rejection(
        prove_rehearsal_manifest(&pointer, &manifest).unwrap_err(),
        "Corrupt",
        "code=authorization_projection.fence_proof_manifest_hash_chain_break",
    );

    let mut manifest = rehearsal_manifest_row(MANIFEST_STATUS_COMMITTED);
    manifest.compiler_version = "drifted-compiler".to_owned();
    assert_parent_rejection(
        prove_rehearsal_manifest(&pointer, &manifest).unwrap_err(),
        "Corrupt",
        "code=authorization_projection.fence_proof_manifest_hash_chain_break",
    );

    let mut manifest = rehearsal_manifest_row(MANIFEST_STATUS_COMMITTED);
    manifest.card_id = None;
    assert_parent_rejection(
        prove_rehearsal_manifest(&pointer, &manifest).unwrap_err(),
        "IdentityMismatch",
        "code=authorization_projection.fence_proof_manifest_card_split",
    );

    let mut manifest = rehearsal_manifest_row(MANIFEST_STATUS_COMMITTED);
    manifest.tenant_id = 8;
    assert_parent_rejection(
        prove_rehearsal_manifest(&pointer, &manifest).unwrap_err(),
        "IdentityMismatch",
        "code=authorization_projection.fence_proof_manifest_identity_split",
    );
}

#[test]
fn fence_proof_rehearsal_statements_are_minimal_guards_only() {
    // The latch CAS sets ONLY the latch and the CAS increment: no other
    // column may move inside this statement.
    assert!(
        POINTER_FENCE_PROOF_LATCH_SQL.starts_with(
            "UPDATE authorization_projection_current \
                 SET revoke_fence_proven = 1, cas_version = cas_version + 1 WHERE "
        ),
        "{POINTER_FENCE_PROOF_LATCH_SQL}"
    );
    for fragment in [
        "tenant_id = ?",
        "aggregate_type = ?",
        "aggregate_id = ?",
        // Null-safe card scope pin, mirroring the publish CAS.
        "card_id <=> ?",
        "manifest_id = ?",
        "current_generation = ?",
        "cas_version = ?",
        "revoke_fence = ?",
        // The old latch value is part of the guard: a blanket re-latch or
        // a latch through any other state is unrepresentable.
        "revoke_fence_proven = 0",
    ] {
        assert!(
            POINTER_FENCE_PROOF_LATCH_SQL.contains(fragment),
            "latch CAS lacks `{fragment}`"
        );
    }
    assert_eq!(POINTER_FENCE_PROOF_LATCH_SQL.matches('?').count(), 8);

    // The audit row uses the established 9-column in-transaction shape
    // with fixed literals for resource/decision/event_type.
    assert!(FENCE_PROOF_AUDIT_INSERT_SQL.starts_with("INSERT INTO audit_log"));
    assert!(
            FENCE_PROOF_AUDIT_INSERT_SQL
                .contains("(user_id, card_id, action, resource, decision, reason, event_type, request_id, detail)"),
            "{FENCE_PROOF_AUDIT_INSERT_SQL}"
        );
    assert!(FENCE_PROOF_AUDIT_INSERT_SQL.contains("'authorization_projection_current'"));
    assert!(FENCE_PROOF_AUDIT_INSERT_SQL.contains("'ALLOW'"));
    assert!(FENCE_PROOF_AUDIT_INSERT_SQL.contains("'AUTHZ_FENCE_PROOF_LATCH'"));
    assert_eq!(FENCE_PROOF_AUDIT_INSERT_SQL.matches('?').count(), 6);

    // The multi-generation probe is index-bounded and refuse-only; a stray
    // READY generation is as unprovable as COMMITTED/SUPERSEDED history.
    assert!(MANIFEST_OTHER_COMMITTED_GENERATION_PROBE_SQL
        .contains("status IN ('COMMITTED', 'SUPERSEDED', 'READY')"));
    assert!(!MANIFEST_OTHER_COMMITTED_GENERATION_PROBE_SQL
        .contains("status IN ('COMMITTED', 'SUPERSEDED')"));
    assert!(MANIFEST_OTHER_COMMITTED_GENERATION_PROBE_SQL.contains("generation <> ?"));
    assert!(MANIFEST_OTHER_COMMITTED_GENERATION_PROBE_SQL.contains("LIMIT 1"));
    assert_eq!(
        MANIFEST_OTHER_COMMITTED_GENERATION_PROBE_SQL
            .matches('?')
            .count(),
        4
    );

    for statement in [
        POINTER_FENCE_PROOF_LATCH_SQL,
        FENCE_PROOF_AUDIT_INSERT_SQL,
        MANIFEST_OTHER_COMMITTED_GENERATION_PROBE_SQL,
    ] {
        assert!(
            !statement.contains('{'),
            "brace interpolation surface in: {statement}"
        );
        assert!(
            !statement.to_uppercase().contains("DELETE"),
            "no deletes allowed"
        );
    }
}
