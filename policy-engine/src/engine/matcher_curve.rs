//! 匹配器接力曲线探针（release + --ignored）：线性扫描（技术 A）的成本
//! 随 N 与匹配位置的变化——定位软件层接力点（A 线性扫描 → B 类型索引）。
//!
//! 位置偏差是本探针存在的理由：ceiling probe 把匹配 grant 放在第一个
//! 位置，find() 首中即胜，匹配器成本被系统性低估。这里测首/中/尾/缺席
//! 四种位置 × N {100, 1000, 4050}，混合资源类型（贴近真实卡面）。

use super::published::{match_published_effective_grant, MATCHER_INDEX_THRESHOLD};
use astral_types::registry::parse_resource_key;
use astral_types::{
    BindingLayer, CanonicalGrant, GrantEffect, GrantId, GrantProvenance, GrantRevision,
    GrantSourceKind, GrantState, PolicyContext, PublishedAggregateManifestSummary,
    PublishedCardAuthorization, PublishedCardAuthorizationGate, PublishedEvidenceGateStatus,
    TenantScope, ValidityWindow, VerifiedPublishedGrantRecord,
};
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

fn probe_grant(index: usize, resource: String) -> CanonicalGrant {
    CanonicalGrant {
        grant_id: GrantId::parse(&format!(
            "00000000-0000-0000-3000-{:012x}",
            (index as u64 + 1) & 0xffff_ffff_ffff
        ))
        .unwrap(),
        revision: GrantRevision::initial(),
        state: GrantState::Active,
        source_kind: GrantSourceKind::RuleSet,
        binding_layer: BindingLayer::Base,
        tenant: TenantScope::new(7, Some(11)).unwrap(),
        card_id: 1,
        user_id: 1,
        resource,
        action: "read".to_owned(),
        effect: GrantEffect::Allow,
        validity: ValidityWindow::perpetual(),
        provenance: GrantProvenance {
            source_id: "source-1".to_owned(),
            source_entry: Some("entry-1".to_owned()),
            binding_id: Some("binding-1".to_owned()),
            delegation_id: None,
            operation_id: "op-1".to_owned(),
            event_id: Some("event-1".to_owned()),
            actor_user_id: None,
        },
    }
}

/// 混合资源类型的证据：类型 ∈ {invoice, ledger, monitor, report}（各 1/4），
/// 对象级键 `type:{i}`。匹配目标 = `monitor:777`（对象级）。
fn mixed_evidence(size: usize, target: String) -> PublishedCardAuthorization {
    let types = ["invoice", "ledger", "monitor", "report"];
    let grants: Vec<CanonicalGrant> = (0..size)
        .map(|index| {
            let kind = types[index % types.len()];
            probe_grant(index, format!("{kind}:{index}"))
        })
        .collect();
    let mut all = grants;
    all.push(probe_grant(size, target));
    evidence_from(all, size + 1)
}

fn evidence_from(grants: Vec<CanonicalGrant>, declared: usize) -> PublishedCardAuthorization {
    let record_count = grants.len();
    let manifest = PublishedAggregateManifestSummary {
        tenant_id: 7,
        card_id: 1,
        aggregate_type: "CARD".to_owned(),
        aggregate_id: 1,
        manifest_id: 1,
        generation: 1,
        source_generation: 1,
        projected_generation: 1,
        revoke_fence: 0,
        cas_version: 1,
        semantic_hash_hex: "a".repeat(64),
        dependency_hash_hex: "b".repeat(64),
        manifest_digest_hex: "c".repeat(64),
        compiler_version: "test".to_owned(),
        event_id: "event-1".to_owned(),
        operation_id: "op-1".to_owned(),
        parent_manifest_id: None,
        segment_count: 1,
        declared_grant_row_count: declared as u64,
    };
    let records = grants
        .iter()
        .map(|grant| VerifiedPublishedGrantRecord {
            aggregate_type: "CARD".to_owned(),
            aggregate_id: 1,
            publication_generation: 1,
            revoke_fence: 0,
            manifest_id: 1,
            event_id: "event-1".to_owned(),
            operation_id: "op-1".to_owned(),
            semantic_hash_hex: "a".repeat(64),
            dependency_hash_hex: "b".repeat(64),
            compiler_version: "test".to_owned(),
            segment_ordinal: 0,
            position_in_segment: 0,
            grant: grant.clone(),
            accepted_into_effective_set: true,
            unaccepted_reason: None,
        })
        .collect();
    PublishedCardAuthorization {
        tenant_id: 7,
        card_id: 1,
        read_unix_seconds: 1_700_000_000,
        gate: PublishedCardAuthorizationGate {
            status: PublishedEvidenceGateStatus::Ready,
            aggregate_manifest_count: 1,
            verified_record_count: record_count,
            effective_grant_count: record_count,
            not_in_effective_count: 0,
            equivalent_duplicate_collapsed_count: 0,
        },
        manifests: vec![manifest],
        records,
        effective_grants: grants,
    }
}

fn probe_ctx() -> PolicyContext {
    PolicyContext::builder()
        .user_id(Some(1))
        .card_id(Some(1))
        .tenant_id(Some(7))
        .domain_id(Some(11))
        .action("read".into())
        .resource(Some("monitor:777".into()))
        .target_id(Some(42))
        .build()
}

static SINK: AtomicU64 = AtomicU64::new(0);

fn measure(
    evidence: &std::sync::Arc<PublishedCardAuthorization>,
    ctx: &PolicyContext,
    iters: usize,
) -> u128 {
    // 预热。
    for _ in 0..1_000 {
        let found = match_published_effective_grant(ctx, evidence, "monitor:777");
        black_box(found.is_some());
    }
    let start = Instant::now();
    for _ in 0..iters {
        let found = match_published_effective_grant(ctx, evidence, "monitor:777");
        SINK.fetch_add(found.is_some() as u64, Ordering::Relaxed);
    }
    start.elapsed().as_nanos() / iters as u128
}

#[ignore = "release-only matcher curve probe; run with --release -- --ignored"]
#[test]
fn matcher_cost_position_curve() {
    let ctx = probe_ctx();
    for size in [100usize, 1000, 4050] {
        // 位置扫描：目标对象级 grant 放在首/中/尾；缺席（全 noise，DENY 路径）。
        let kinds = [
            ("first", 0usize),
            ("middle", size / 2),
            ("last", size),
            ("absent", usize::MAX),
        ];
        for (label, position) in kinds {
            let evidence = mixed_evidence(size, format!("monitor:777"));
            // 把目标放到指定位置：重建 grants，将目标插到 position。
            let mut grants: Vec<CanonicalGrant> = (0..size)
                .map(|index| {
                    let kind = ["invoice", "ledger", "monitor", "report"][index % 4];
                    probe_grant(index, format!("{kind}:{index}"))
                })
                .collect();
            let target = probe_grant(size, "monitor:777".to_owned());
            match position {
                0 => grants.insert(0, target),
                mid if mid == size / 2 => grants.insert(mid, target),
                size_equal if size_equal == size => grants.push(target),
                _ => {}
            }
            let _ = &evidence;
            let evidence = evidence_from(grants, size + 1);
            let evidence = std::sync::Arc::new(evidence);
            let ns = measure(&evidence, &ctx, 20_000.min(size * 20).max(2_000));
            eprintln!(
                "[matcher {size:>4} | {label:>6}] {ns:>9} ns/decision (linear scan, mixed types)",
            );
        }
    }
}

/// 接力语义等价：索引路径（N>阈值）与线性扫描对同一证据、覆盖四类资源
/// 类型/对象级+类型级+通配请求/缺席，结果必须逐请求一致。
#[test]
fn relay_paths_are_semantically_equivalent() {
    let size = MATCHER_INDEX_THRESHOLD + 1;
    let types = ["invoice", "ledger", "monitor", "report"];
    let mut grants: Vec<CanonicalGrant> = (0..size)
        .map(|index| {
            let kind = types[index % types.len()];
            let resource = if index % 8 == 7 {
                format!("{kind}:*")
            } else {
                format!("{kind}:{index}")
            };
            probe_grant(index, resource)
        })
        .collect();
    // 通配 grant（跨类型）。
    grants.push(probe_grant(size, "*".to_owned()));
    // 类型级 grant（无 id）。
    grants.push(probe_grant(size + 1, "monitor".to_owned()));
    let evidence = std::sync::Arc::new(evidence_from(grants, size + 2));
    let ctx = probe_ctx();

    let linear = |request: &str| -> Option<String> {
        evidence
            .effective_grants
            .iter()
            .find(|grant| {
                let card_id = ctx.card_id.unwrap_or(0);
                let request_tenant = ctx.tenant_id.unwrap_or(0);
                let (request_type, request_id) = parse_resource_key(request);
                let type_level = request_id.is_none();
                if grant.card_id != card_id
                    || ctx.user_id.is_none_or(|user| grant.user_id != user)
                    || grant.tenant.tenant_id != request_tenant
                {
                    return false;
                }
                let (grant_type, grant_id) = parse_resource_key(&grant.resource);
                if grant_type != request_type && grant_type != "*" {
                    return false;
                }
                if type_level && grant_id.is_some() {
                    return false;
                }
                if !type_level && grant_id.is_some() && grant_id != request_id {
                    return false;
                }
                grant.action == "read"
            })
            .map(|grant| grant.resource.clone())
    };

    let requests = [
        "monitor:777",
        "monitor:*",
        "monitor",
        "invoice:1",
        "ledger:2",
        "report:3",
        "absent:99999",
        "unknown_type:1",
    ];
    for request in requests {
        let via_relay = match_published_effective_grant(&ctx, &evidence, request)
            .map(|grant| grant.resource.clone());
        assert_eq!(via_relay, linear(request), "relay diverged for {request}");
    }
}

/// 抖动退化探针：两张（四张）大卡交错判定——单槽缓存每次 ptr_eq miss
/// 都全量重建索引。若交错场景成本 >> 线性扫描，接力需要多槽/自适应。
#[test]
fn matcher_index_thrash_under_interleaved_cards() {
    let size = MATCHER_INDEX_THRESHOLD + 1;
    let evidence_a = std::sync::Arc::new(evidence_from(
        (0..size)
            .map(|index| probe_grant(index, format!("invoice:{index}")))
            .collect(),
        size,
    ));
    let evidence_b = std::sync::Arc::new(evidence_from(
        (0..size)
            .map(|index| probe_grant(index, format!("ledger:{index}")))
            .collect(),
        size,
    ));
    let ctx = probe_ctx();
    // 线性扫描基线（用 ≤阈值的小证据等价测量）：构造 N=threshold 线性扫描。
    let small = std::sync::Arc::new(evidence_from(
        (0..MATCHER_INDEX_THRESHOLD)
            .map(|index| probe_grant(index, format!("invoice:{index}")))
            .collect(),
        MATCHER_INDEX_THRESHOLD,
    ));
    let linear_baseline = {
        // 用小证据测线性成本按比例外推到 size（线性 O(N)）。
        let per_decision = measure(&small, &ctx, 5_000);
        per_decision * (size / MATCHER_INDEX_THRESHOLD) as u128
    };

    let interleave = |evidences: &[std::sync::Arc<PublishedCardAuthorization>]| {
        for _ in 0..500 {
            for evidence in evidences {
                black_box(match_published_effective_grant(&ctx, evidence, "invoice:1").is_some());
            }
        }
        let start = Instant::now();
        for _ in 0..100 {
            for evidence in evidences {
                black_box(match_published_effective_grant(&ctx, evidence, "invoice:1").is_some());
            }
        }
        start.elapsed().as_nanos() / 100
    };

    let two_card_ns = interleave(&[
        std::sync::Arc::clone(&evidence_a),
        std::sync::Arc::clone(&evidence_b),
    ]);
    eprintln!(
        "[thrash] 2-card interleave (index path, rebuild every decision): {two_card_ns} ns/decision | linear-extrapolated baseline {linear_baseline} ns",
    );
    let four = vec![
        std::sync::Arc::clone(&evidence_a),
        std::sync::Arc::clone(&evidence_b),
        std::sync::Arc::new(evidence_from(
            (0..size)
                .map(|index| probe_grant(index, format!("monitor:{index}")))
                .collect(),
            size,
        )),
        std::sync::Arc::new(evidence_from(
            (0..size)
                .map(|index| probe_grant(index, format!("report:{index}")))
                .collect(),
            size,
        )),
    ];
    let four_card_ns = interleave(&four);
    eprintln!("[thrash] 4-card interleave: {four_card_ns} ns/decision",);
}
