use super::*;
use std::hint::black_box;
use std::time::Instant;

fn reference(ordinal: u64, digest: String) -> (u64, ParentReferenceView) {
    (
        ordinal,
        ParentReferenceView {
            ordinal,
            identity: astral_db::ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
            segment_id: ordinal as i64 + 1,
            content_digest_hex: digest,
        },
    )
}

fn digest(id: u64) -> String {
    let value = id.wrapping_mul(0x9e3779b97f4a7c15);
    format!(
        "{value:016x}{:016x}{:016x}{:016x}",
        value.rotate_left(11),
        value.rotate_left(23),
        value.rotate_left(37)
    )
}

fn legacy(
    references: &[(u64, ParentReferenceView)],
    digests: &[String],
) -> Vec<astral_db::StagedSegmentContent> {
    use astral_db::StagedSegmentContent;
    let mut plan = Vec::with_capacity(digests.len());
    for digest in digests {
        let ordinal = references.iter().find_map(|(ordinal, view)| {
            (view.content_digest_hex == *digest && !plan.iter().any(|entry| matches!(entry, StagedSegmentContent::ReuseParent { parent_ordinal } if parent_ordinal == ordinal))).then_some(*ordinal)
        });
        plan.push(match ordinal {
            Some(parent_ordinal) => StagedSegmentContent::ReuseParent { parent_ordinal },
            None => StagedSegmentContent::New(Vec::new()),
        });
    }
    plan
}

fn current(
    references: &[(u64, ParentReferenceView)],
    digests: &[String],
) -> Vec<astral_db::StagedSegmentContent> {
    use astral_db::StagedSegmentContent;
    let mut lookup = ParentOrdinalLookup::new(references);
    let mut plan = Vec::with_capacity(digests.len());
    for digest in digests {
        let ordinal = lookup.take(digest);
        plan.push(match ordinal {
            Some(parent_ordinal) => StagedSegmentContent::ReuseParent { parent_ordinal },
            None => StagedSegmentContent::New(Vec::new()),
        });
    }
    plan
}

fn sample(f: impl Fn() -> Vec<astral_db::StagedSegmentContent>, repetitions: usize) -> u128 {
    let started = Instant::now();
    for _ in 0..repetitions {
        black_box(f());
    }
    started.elapsed().as_nanos() / repetitions as u128
}

fn fixture(size: usize, pattern: &str) -> (Vec<(u64, ParentReferenceView)>, Vec<String>) {
    let references = (0..size)
        .map(|index| {
            let ordinal = if pattern == "duplicate" {
                (index % 7) as u64
            } else {
                index as u64
            };
            let key = if pattern == "duplicate" {
                index % 13
            } else {
                index
            };
            reference(ordinal, digest(key as u64))
        })
        .collect();
    let digests = (0..size)
        .map(|index| {
            let key = match pattern {
                "miss" => index + size + 1,
                "mixed" if index % 2 == 0 => index + size + 1,
                "duplicate" => index % 13,
                _ => index,
            };
            digest(key as u64)
        })
        .collect();
    (references, digests)
}

#[test]
#[ignore = "local CPU-only parent lookup no-regression matrix"]
fn parent_lookup_no_regression_matrix() {
    let samples = std::env::var("ASTRAL_PERF_SAMPLES")
        .map(|value| value.parse::<usize>().unwrap())
        .unwrap_or(15)
        .clamp(15, 30);
    let mut cases = Vec::new();
    for size in [0, 1, 8, 32, 64, 128, 256, 512, 2_048] {
        for pattern in ["hit", "miss", "mixed", "duplicate"] {
            let (references, digests) = fixture(size, pattern);
            cases.push((format!("lookup/{size}/{pattern}"), references, digests));
        }
    }
    for (candidates, references, tail) in [
        (1, 2_048, false),
        (1, 2_048, true),
        (8, 2_048, false),
        (2_048, 8, true),
    ] {
        let (references, _) = fixture(references, "hit");
        let digests = (0..candidates)
            .map(|index| {
                let index = if tail {
                    references.len().saturating_sub(index + 1)
                } else {
                    index % references.len()
                };
                references[index].1.content_digest_hex.clone()
            })
            .collect();
        cases.push((
            format!(
                "lookup/imbalanced-{candidates}-{}-tail-{tail}",
                references.len()
            ),
            references,
            digests,
        ));
    }
    for (case, references, digests) in cases {
        if std::env::var("ASTRAL_PERF_CASE").is_ok_and(|filter| !case.contains(&filter)) {
            continue;
        }
        assert_eq!(
            legacy(&references, &digests),
            current(&references, &digests)
        );
        let repetitions = if digests.len() <= 128 { 256 } else { 8 };
        black_box(sample(|| legacy(&references, &digests), repetitions));
        black_box(sample(|| current(&references, &digests), repetitions));
        let mut old = Vec::new();
        let mut new = Vec::new();
        for sample_index in 0..samples {
            let (old_ns, new_ns) = if sample_index % 2 == 0 {
                (
                    sample(
                        || legacy(black_box(&references), black_box(&digests)),
                        repetitions,
                    ),
                    sample(
                        || current(black_box(&references), black_box(&digests)),
                        repetitions,
                    ),
                )
            } else {
                let new = sample(
                    || current(black_box(&references), black_box(&digests)),
                    repetitions,
                );
                (
                    sample(
                        || legacy(black_box(&references), black_box(&digests)),
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
                "case": case, "metric": "ns-per-batch", "legacy": old, "current": new,
                "repetitions_per_sample": repetitions,
            })
        );
    }
}
