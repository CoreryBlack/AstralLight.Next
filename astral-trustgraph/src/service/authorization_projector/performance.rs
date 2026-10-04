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
