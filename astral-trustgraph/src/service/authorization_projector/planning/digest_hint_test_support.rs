pub(crate) use super::digest_hints::{
    DigestHintCache, DigestHintStore, DisabledDigestHintStore, DIGEST_HINT_CACHE_CAPACITY,
};

use super::{HotState, ParentReferenceView, StagedSegmentContent};

pub(crate) fn plan_stage_segments_with_cache(
    candidate: &HotState,
    parent_references: Option<&[(u64, ParentReferenceView)]>,
    cache: &mut DigestHintCache,
) -> Result<Vec<StagedSegmentContent>, String> {
    plan_stage_segments_with_cache_mode(candidate, parent_references, true, cache)
}

pub(crate) fn plan_stage_segments_with_cache_mode(
    candidate: &HotState,
    parent_references: Option<&[(u64, ParentReferenceView)]>,
    use_digest_hints: bool,
    cache: &mut DigestHintCache,
) -> Result<Vec<StagedSegmentContent>, String> {
    plan_stage_segments_with_store(candidate, parent_references, use_digest_hints, cache)
}

pub(crate) fn plan_stage_segments_with_store_for_test(
    candidate: &HotState,
    parent_references: Option<&[(u64, ParentReferenceView)]>,
    cache: &mut impl DigestHintStore,
) -> Result<Vec<StagedSegmentContent>, String> {
    plan_stage_segments_with_store(candidate, parent_references, true, cache)
}

fn plan_stage_segments_with_store(
    candidate: &HotState,
    parent_references: Option<&[(u64, ParentReferenceView)]>,
    use_digest_hints: bool,
    cache: &mut impl DigestHintStore,
) -> Result<Vec<StagedSegmentContent>, String> {
    super::plan_stage_segments_with_store(candidate, parent_references, use_digest_hints, cache)
}
