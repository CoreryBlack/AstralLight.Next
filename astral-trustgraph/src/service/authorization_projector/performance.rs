use super::*;
use std::hint::black_box;
use std::time::Instant;

fn measure(f: impl Fn() -> Vec<StagedSegmentContent>, repetitions: usize) -> u128 {
    let started = Instant::now();
    for _ in 0..repetitions {
        black_box(f());
    }
    started.elapsed().as_nanos() / repetitions as u128
}

#[test]
#[ignore = "local CPU-only complete stage plan no-regression matrix"]
fn complete_stage_plan_no_regression_matrix() {
    let samples = std::env::var("ASTRAL_PERF_SAMPLES")
        .map(|value| value.parse::<usize>().unwrap())
        .unwrap_or(15)
        .clamp(15, 30);
    for size in [1_u16, 8, 128, 512, 2_048] {
        let grants: Vec<_> = (0..size)
            .map(|id| {
                let mut grant = grant(id, 1, GrantState::Active);
                grant.resource = format!("learn_subject:{id}");
                grant
            })
            .collect();
        let candidate =
            HotState::from_grants(tenant_of(17), 4, grants, DependencyVector::default()).unwrap();
        for pattern in ["hit", "miss", "duplicate"] {
            let case = format!("stage/{size}/{pattern}");
            if std::env::var("ASTRAL_PERF_CASE").is_ok_and(|filter| !case.contains(&filter)) {
                continue;
            }
            let mut references = Vec::new();
            for (index, (_, segment)) in candidate.segments.iter().enumerate() {
                let digest = if pattern == "miss" {
                    hex_lower(&Sha256::digest(b"unrelated"))
                } else {
                    hex_lower(&Sha256::digest(
                        astral_db::encode_segment_payload(&segment.grants).unwrap(),
                    ))
                };
                let ordinal = if pattern == "duplicate" {
                    index % 7
                } else {
                    index
                };
                references.push(parent_view(ordinal as u64, &digest));
                if pattern == "duplicate" {
                    references.push(parent_view(ordinal as u64, &digest));
                }
            }
            assert_eq!(
                legacy_stage_plan(&candidate, &references),
                plan_stage_segments(&candidate, Some(&references)).unwrap()
            );
            let repetitions = if size <= 128 { 64 } else { 4 };
            black_box(measure(
                || legacy_stage_plan(&candidate, &references),
                repetitions,
            ));
            black_box(measure(
                || plan_stage_segments(&candidate, Some(&references)).unwrap(),
                repetitions,
            ));
            let mut old = Vec::new();
            let mut new = Vec::new();
            for sample in 0..samples {
                let (old_ns, new_ns) = if sample % 2 == 0 {
                    (
                        measure(
                            || legacy_stage_plan(black_box(&candidate), black_box(&references)),
                            repetitions,
                        ),
                        measure(
                            || {
                                plan_stage_segments(
                                    black_box(&candidate),
                                    Some(black_box(&references)),
                                )
                                .unwrap()
                            },
                            repetitions,
                        ),
                    )
                } else {
                    let new = measure(
                        || {
                            plan_stage_segments(black_box(&candidate), Some(black_box(&references)))
                                .unwrap()
                        },
                        repetitions,
                    );
                    (
                        measure(
                            || legacy_stage_plan(black_box(&candidate), black_box(&references)),
                            repetitions,
                        ),
                        new,
                    )
                };
                old.push(old_ns);
                new.push(new_ns);
            }
            println!(
                "PERF_MATRIX {}",
                serde_json::json!({
                    "case": case, "metric": "ns-per-plan", "legacy": old, "current": new,
                    "repetitions_per_sample": repetitions,
                })
            );
        }
    }
}

/// 调度曲线扫描：planner 在命中率 {0,50,100}% × hints {on,off} 的耗时——
/// 校准"digest 提示缓存是否常开"的切换阈值（局部最优组合成全局最优）。
#[test]
#[ignore = "local CPU-only scheduling-curve sweep"]
fn segment_digest_hint_scheduling_curve() {
    let samples = std::env::var("ASTRAL_PERF_SAMPLES")
        .map(|value| value.parse::<usize>().unwrap())
        .unwrap_or(9)
        .clamp(3, 30);
    let size = 4050usize;
    let compiler_version = policy_engine::COMPILER_VERSION.to_owned();

    let make_segments = |round: u64| -> Vec<(
        policy_engine::ProjectionKey,
        std::sync::Arc<policy_engine::SegmentContent>,
    )> {
        let grants: Vec<_> = (0..size)
            .map(|id| {
                let mut grant = grant(id as u16, 1, GrantState::Active);
                grant.resource = format!("learn_subject:{id}");
                grant.provenance.operation_id = format!("operation-{round}");
                grant
            })
            .collect();
        let candidate =
            HotState::from_grants(tenant_of(17), round, grants, DependencyVector::default())
                .unwrap();
        candidate
            .segments
            .iter()
            .map(|(key, segment)| (key.clone(), std::sync::Arc::clone(segment)))
            .collect()
    };

    let warm = make_segments(1);
    // 预备：真实 encode 一轮把全部键写入提示缓存（100% 命中基准）。
    let _ = plan_stage_segments_with_hints(&warm_to_candidate(&warm), None, true);

    for hit_ratio in [0.0f64, 0.25, 0.5, 1.0] {
        let mutated = ((1.0 - hit_ratio) * size as f64).round() as usize;
        let mut mixed = Vec::with_capacity(size);
        let mut index = 0usize;
        for (key, segment) in &warm {
            if index < mutated {
                let mut grants = segment.grants.clone();
                for g in &mut grants {
                    g.resource = format!("learn_subject:changed-{index}");
                }
                let content_hash = hex_lower(&Sha256::digest(serde_json::to_vec(&grants).unwrap()));
                let content = policy_engine::SegmentContent {
                    key: key.clone(),
                    grants,
                    content_hash,
                    segment_id: segment.segment_id.clone(),
                };
                mixed.push((key.clone(), std::sync::Arc::new(content)));
            } else {
                mixed.push((key.clone(), std::sync::Arc::clone(segment)));
            }
            index += 1;
        }
        let candidate = HotState::from_grants(
            tenant_of(17),
            2,
            Vec::<astral_types::CanonicalGrant>::new(),
            DependencyVector::default(),
        )
        .unwrap();
        let _ = candidate;

        let measure_on = || {
            let started = Instant::now();
            for _ in 0..samples {
                black_box(
                    plan_stage_segments_with_hints(
                        &warm_to_candidate(&mixed),
                        Some(&true_to_refs()),
                        true,
                    )
                    .unwrap()
                    .len(),
                );
            }
            started.elapsed().as_nanos() / samples as u128
        };
        let measure_off = || {
            let started = Instant::now();
            for _ in 0..samples {
                black_box(
                    plan_stage_segments_with_hints(
                        &warm_to_candidate(&mixed),
                        Some(&true_to_refs()),
                        false,
                    )
                    .unwrap()
                    .len(),
                );
            }
            started.elapsed().as_nanos() / samples as u128
        };
        let on_ns = measure_on();
        let off_ns = measure_off();
        eprintln!(
            "[curve {size}] hit={hit_ratio:>4.2} | hints-on {on_ns:>9}ns vs hints-off {off_ns:>9}ns per plan (segments {size})",
        );
    }
}

/// 测量辅助：把 (key, segment) 对还原为 planner 需要的 HotState 形状。
/// planner 只消费 segments 迭代；这里用 from_grants 建空态再替换段集合
/// 是不可行的（字段私有），改为直接构造携带段的 candidate——通过公开
/// from_grants 接口以 grants 重建，键集合一致即等价。
fn warm_to_candidate(
    segments: &[(
        policy_engine::ProjectionKey,
        std::sync::Arc<policy_engine::SegmentContent>,
    )],
) -> HotState {
    let grants: Vec<_> = segments
        .iter()
        .flat_map(|(_, segment)| segment.grants.iter().cloned())
        .collect();
    let version = 9;
    HotState::from_grants(tenant_of(17), version, grants, DependencyVector::default()).unwrap()
}

fn true_to_refs() -> Vec<(u64, ParentReferenceView)> {
    Vec::new()
}
