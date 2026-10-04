//! Digest-indexed parent ordinals with stable input priority.

use std::collections::{HashMap, HashSet, VecDeque};

use astral_db::ParentReferenceView;

pub(super) struct ParentOrdinalLookup<'a> {
    by_digest: HashMap<&'a str, VecDeque<u64>>,
    consumed: HashSet<u64>,
}

impl<'a> ParentOrdinalLookup<'a> {
    pub(super) fn new(references: &'a [(u64, ParentReferenceView)]) -> Self {
        let mut by_digest: HashMap<&str, VecDeque<u64>> = HashMap::new();
        for (ordinal, view) in references {
            by_digest
                .entry(view.content_digest_hex.as_str())
                .or_default()
                .push_back(*ordinal);
        }
        Self {
            by_digest,
            consumed: HashSet::new(),
        }
    }

    pub(super) fn take(&mut self, digest: &str) -> Option<u64> {
        let ordinals = self.by_digest.get_mut(digest)?;
        while let Some(ordinal) = ordinals.pop_front() {
            // An ordinal is consumed globally, including references under other digests.
            if self.consumed.insert(ordinal) {
                return Some(ordinal);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    mod performance {
        include!("parent_ordinals/performance.rs");
    }
    use super::*;
    use astral_db::ProjectionAggregateIdentity;

    fn reference(ordinal: u64, digest: &str) -> (u64, ParentReferenceView) {
        (
            ordinal,
            ParentReferenceView {
                ordinal,
                identity: ProjectionAggregateIdentity::new(7, "CARD", 17).unwrap(),
                segment_id: ordinal as i64 + 1,
                content_digest_hex: digest.to_owned(),
            },
        )
    }

    #[test]
    fn stage_planning_duplicate_digest_and_ordinal_priority() {
        let references = [reference(9, "a"), reference(9, "a"), reference(3, "a")];
        let mut lookup = ParentOrdinalLookup::new(&references);
        assert_eq!(lookup.take("a"), Some(9));
        assert_eq!(lookup.take("a"), Some(3));
        assert_eq!(lookup.take("a"), None);
        let references = [reference(9, "a"), reference(9, "a"), reference(9, "b")];
        let mut lookup = ParentOrdinalLookup::new(&references);
        assert_eq!(lookup.take("a"), Some(9));
        assert_eq!(lookup.take("a"), None);
        assert_eq!(lookup.take("b"), None);
        assert_eq!(lookup.take("missing"), None);
    }

    #[test]
    fn stage_planning_lookup_consumes_each_reference_at_most_once() {
        let references: Vec<_> = (0..4_096).map(|id| reference(id % 32, "same")).collect();
        let mut lookup = ParentOrdinalLookup::new(&references);
        for _ in 0..4_096 {
            lookup.take("same");
            lookup.take("absent");
        }
        assert_eq!(lookup.consumed.len(), 32);
        assert!(lookup.by_digest.values().all(VecDeque::is_empty));
    }

    #[test]
    #[ignore = "local CPU-only lookup performance probe"]
    fn stage_planning_lookup_performance_probe() {
        use std::hint::black_box;
        use std::time::Instant;

        for size in [128_u64, 512, 2_048] {
            let references: Vec<_> = (0..size)
                .map(|id| reference(id, &format!("digest-{id}")))
                .collect();
            let digests: Vec<_> = references
                .iter()
                .map(|(_, view)| view.content_digest_hex.as_str())
                .collect();
            let start = Instant::now();
            let mut legacy = Vec::new();
            for digest in &digests {
                let ordinal = references.iter().find_map(|(ordinal, view)| {
                    (view.content_digest_hex == *digest && !legacy.contains(ordinal))
                        .then_some(*ordinal)
                });
                legacy.push(black_box(ordinal.unwrap()));
            }
            let legacy_ns = start.elapsed().as_nanos();
            let start = Instant::now();
            let mut lookup = ParentOrdinalLookup::new(&references);
            let indexed: Vec<_> = digests
                .iter()
                .map(|digest| black_box(lookup.take(digest).unwrap()))
                .collect();
            let indexed_ns = start.elapsed().as_nanos();
            assert_eq!(indexed, legacy);
            eprintln!("segment_lookup size={size} legacy_ns={legacy_ns} indexed_ns={indexed_ns}");
        }
    }
}
