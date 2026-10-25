//! Matcher semantic checks and isolated release probes.
//!
//! Run the ignored probes with:
//! `cargo test -p policy-engine --release --lib engine::published::matcher_curve -- --ignored --nocapture`

use super::{
    build_matcher_index, find_linear_published_grant, match_indexed_with_state,
    match_published_effective_grant, record_matcher_evidence_size, record_matcher_path,
    MatcherCacheState, MatcherPath, MATCHER_INDEX_THRESHOLD,
};
use astral_types::registry::parse_resource_key;
use astral_types::{
    BindingLayer, CanonicalGrant, GrantEffect, GrantId, GrantProvenance, GrantRevision,
    GrantSourceKind, GrantState, PolicyContext, PublishedAggregateManifestSummary,
    PublishedCardAuthorization, PublishedCardAuthorizationGate, PublishedEvidenceGateStatus,
    ResourceOwnershipScope, TenantScope, ValidityWindow, VerifiedPublishedGrantRecord,
};
use std::hint::black_box;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

static PROBE_METRICS_HANDLE: OnceLock<
    Result<metrics_exporter_prometheus::PrometheusHandle, String>,
> = OnceLock::new();

fn ensure_probe_metrics() -> metrics_exporter_prometheus::PrometheusHandle {
    PROBE_METRICS_HANDLE
        .get_or_init(|| {
            metrics_exporter_prometheus::PrometheusBuilder::new()
                .install_recorder()
                .map_err(|error| error.to_string())
        })
        .clone()
        .expect("matcher probe must install its Prometheus recorder")
}

const READ_UNIX_SECONDS: i64 = 1_700_000_000;
const MATCHER_CACHE_COOLDOWN_OPS: u64 = 1024;
const MIXED_RESOURCE_TYPES: [&str; 4] = ["invoice", "ledger", "monitor", "report"];

fn probe_grant(index: usize, resource: &str) -> CanonicalGrant {
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
        resource: resource.to_owned(),
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

fn evidence_from(grants: Vec<CanonicalGrant>) -> PublishedCardAuthorization {
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
        compiler_version: "matcher-probe".to_owned(),
        event_id: "event-1".to_owned(),
        operation_id: "op-1".to_owned(),
        parent_manifest_id: None,
        segment_count: 1,
        declared_grant_row_count: record_count as u64,
    };
    let records = grants
        .iter()
        .enumerate()
        .map(|(position, grant)| VerifiedPublishedGrantRecord {
            aggregate_type: "CARD".to_owned(),
            aggregate_id: 1,
            publication_generation: 1,
            revoke_fence: 0,
            manifest_id: 1,
            event_id: "event-1".to_owned(),
            operation_id: "op-1".to_owned(),
            semantic_hash_hex: "a".repeat(64),
            dependency_hash_hex: "b".repeat(64),
            compiler_version: "matcher-probe".to_owned(),
            segment_ordinal: 0,
            position_in_segment: position as u64,
            grant: grant.clone(),
            accepted_into_effective_set: true,
            unaccepted_reason: None,
        })
        .collect();
    PublishedCardAuthorization {
        tenant_id: 7,
        card_id: 1,
        read_unix_seconds: READ_UNIX_SECONDS,
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

fn assert_index_matches_linear(
    ctx: &PolicyContext,
    evidence: &Arc<PublishedCardAuthorization>,
    key: &str,
) {
    let (request_type, request_id) = parse_resource_key(key);
    let linear = find_linear_published_grant(ctx, evidence, request_type, request_id)
        .map(|grant| grant.grant_id);

    let mut state = MatcherCacheState::new();
    let (first, first_path) =
        match_indexed_with_state(ctx, evidence, request_type, request_id, &mut state);
    assert_eq!(first_path, MatcherPath::FirstSeenLinear);
    assert_eq!(
        first.map(|grant| grant.grant_id),
        linear,
        "first-seen linear match diverged for {key}"
    );

    let (indexed, build_path) =
        match_indexed_with_state(ctx, evidence, request_type, request_id, &mut state);
    assert_eq!(build_path, MatcherPath::IndexBuild);
    assert_eq!(
        indexed.map(|grant| grant.grant_id),
        linear,
        "index build diverged for {key}"
    );

    let (indexed_again, hit_path) =
        match_indexed_with_state(ctx, evidence, request_type, request_id, &mut state);
    assert_eq!(hit_path, MatcherPath::IndexHit);
    assert_eq!(
        indexed_again.map(|grant| grant.grant_id),
        linear,
        "index hit diverged for {key}"
    );
}

#[test]
fn matcher_metrics_render_fixed_labels_and_grant_distribution() {
    let handle = ensure_probe_metrics();
    for path in [
        MatcherPath::LinearThreshold,
        MatcherPath::FirstSeenLinear,
        MatcherPath::IndexBuild,
        MatcherPath::IndexHit,
    ] {
        record_matcher_path(path);
    }
    record_matcher_evidence_size(1000);
    let evidence = Arc::new(evidence_from(vec![probe_grant(1, "monitor:777")]));
    let ctx = probe_ctx();
    let _ = match_published_effective_grant(&ctx, &evidence, "monitor:777");
    let body = handle.render();
    for label in [
        "linear_threshold",
        "first_seen_linear",
        "index_build",
        "index_hit",
    ] {
        assert!(
            body.contains(&format!("path=\"{label}\"")),
            "matcher path {label} must be rendered: {body}"
        );
    }
    assert!(
        body.contains("astral_authz_matcher_effective_grants"),
        "grant-count histogram must be exported: {body}"
    );
    assert!(
        body.contains("astral_authz_matcher_paths_total"),
        "path counter must be exported: {body}"
    );
}

#[test]
fn indexed_path_uses_the_full_production_predicate_and_first_match() {
    let mut grants = Vec::new();

    let mut wrong_user = probe_grant(0, "monitor:777");
    wrong_user.user_id = 2;
    grants.push(wrong_user);

    let mut wrong_card = probe_grant(1, "monitor:777");
    wrong_card.card_id = 2;
    grants.push(wrong_card);

    let mut wrong_tenant = probe_grant(2, "monitor:777");
    wrong_tenant.tenant = TenantScope::new(8, Some(11)).unwrap();
    grants.push(wrong_tenant);

    let mut wrong_actor_domain = probe_grant(3, "monitor:777");
    wrong_actor_domain.tenant = TenantScope::new(7, Some(12)).unwrap();
    grants.push(wrong_actor_domain);

    let mut expired = probe_grant(4, "monitor:777");
    expired.validity = ValidityWindow::between(100, 200);
    grants.push(expired);

    let mut revoked = probe_grant(5, "monitor:777");
    revoked.state = GrantState::Revoked;
    grants.push(revoked);

    let mut wrong_action = probe_grant(6, "monitor:777");
    wrong_action.action = "delete".to_owned();
    grants.push(wrong_action);

    grants.push(probe_grant(7, "monitor:778"));

    let mut first_valid = probe_grant(8, "monitor:777");
    first_valid.action = "write".to_owned();
    grants.push(first_valid);

    grants.push(probe_grant(9, "monitor:777"));

    let evidence = Arc::new(evidence_from(grants));
    let mut ctx = probe_ctx();
    ctx.action = "create".to_owned();

    assert_index_matches_linear(&ctx, &evidence, "monitor:777");
    let (request_type, request_id) = parse_resource_key("monitor:777");
    let first = find_linear_published_grant(&ctx, &evidence, request_type, request_id).unwrap();
    assert_eq!(
        first.action, "write",
        "write alias must remain the first match"
    );
    assert_eq!(first.grant_id, evidence.effective_grants[8].grant_id);
}

#[test]
fn indexed_path_preserves_type_wildcard_and_evidence_order_semantics() {
    let typed_first = Arc::new(evidence_from(vec![
        probe_grant(0, "invoice:1"),
        probe_grant(1, "monitor:777"),
        probe_grant(2, "*"),
        probe_grant(3, "monitor"),
    ]));
    assert_index_matches_linear(&probe_ctx(), &typed_first, "monitor:777");
    assert_eq!(
        find_linear_published_grant(&probe_ctx(), &typed_first, "monitor", Some("777"))
            .unwrap()
            .resource,
        "monitor:777"
    );

    let wildcard_first = Arc::new(evidence_from(vec![
        probe_grant(4, "*"),
        probe_grant(5, "monitor:777"),
    ]));
    assert_index_matches_linear(&probe_ctx(), &wildcard_first, "monitor:777");
    assert_eq!(
        find_linear_published_grant(&probe_ctx(), &wildcard_first, "monitor", Some("777"))
            .unwrap()
            .resource,
        "*"
    );

    let type_level = Arc::new(evidence_from(vec![
        probe_grant(6, "monitor:777"),
        probe_grant(7, "monitor:888"),
        probe_grant(8, "monitor"),
    ]));
    for key in ["monitor", "monitor:*"] {
        assert_index_matches_linear(&probe_ctx(), &type_level, key);
        let (request_type, request_id) = parse_resource_key(key);
        assert_eq!(
            find_linear_published_grant(&probe_ctx(), &type_level, request_type, request_id)
                .unwrap()
                .resource,
            "monitor",
            "type-level requests must not match object-level grants"
        );
    }
}

#[test]
fn indexed_path_preserves_actor_and_authoritative_target_domain_checks() {
    let mut actor_domain_grant = probe_grant(0, "monitor:777");
    actor_domain_grant.tenant = TenantScope::new(7, Some(11)).unwrap();
    let mut target_domain_grant = probe_grant(1, "monitor:777");
    target_domain_grant.tenant = TenantScope::new(7, Some(12)).unwrap();
    let evidence = Arc::new(evidence_from(vec![actor_domain_grant, target_domain_grant]));

    let mut target_domain_ctx = probe_ctx();
    target_domain_ctx.domain_id = None;
    target_domain_ctx.resource_ownership_scope = ResourceOwnershipScope::TenantScoped;
    target_domain_ctx.resource_domain_id = Some(12);
    assert_index_matches_linear(&target_domain_ctx, &evidence, "monitor:777");
    let (request_type, request_id) = parse_resource_key("monitor:777");
    assert_eq!(
        find_linear_published_grant(&target_domain_ctx, &evidence, request_type, request_id)
            .unwrap()
            .tenant
            .domain_id,
        Some(12)
    );

    target_domain_ctx.domain_id = Some(11);
    assert_index_matches_linear(&target_domain_ctx, &evidence, "monitor:777");
    assert!(
        find_linear_published_grant(&target_domain_ctx, &evidence, request_type, request_id)
            .is_none()
    );
}

#[test]
fn production_threshold_dispatch_matches_the_linear_baseline() {
    let size = MATCHER_INDEX_THRESHOLD + 1;
    let evidence = Arc::new(evidence_from(
        (0..size)
            .map(|index| {
                let resource = if index + 1 == size {
                    "monitor:777".to_owned()
                } else {
                    format!(
                        "{}:{index}",
                        MIXED_RESOURCE_TYPES[index % MIXED_RESOURCE_TYPES.len()]
                    )
                };
                probe_grant(index, &resource)
            })
            .collect(),
    ));
    let ctx = probe_ctx();
    let thread_evidence = Arc::clone(&evidence);
    let thread_ctx = ctx.clone();
    let actual = std::thread::spawn(move || {
        match_published_effective_grant(&thread_ctx, &thread_evidence, "monitor:777")
            .map(|grant| grant.grant_id)
    })
    .join()
    .expect("matcher worker should complete");
    let (request_type, request_id) = parse_resource_key("monitor:777");
    let expected = find_linear_published_grant(&ctx, &evidence, request_type, request_id)
        .map(|grant| grant.grant_id);
    assert_eq!(actual, expected);
}

#[test]
fn matcher_cache_reuses_four_stable_arcs_and_evicts_the_oldest_slot() {
    let evidence = (0..5)
        .map(|_| benchmark_evidence(MATCHER_INDEX_THRESHOLD + 1, Distribution::Mixed, Some(0)))
        .collect::<Vec<_>>();
    let ctx = probe_ctx();
    let (request_type, request_id) = parse_resource_key("monitor:777");
    let mut state = MatcherCacheState::new();

    for card in evidence.iter().take(4) {
        let (_, first_path) =
            match_indexed_with_state(&ctx, card, request_type, request_id, &mut state);
        assert_eq!(first_path, MatcherPath::FirstSeenLinear);
    }
    for card in evidence.iter().take(4) {
        let (_, build_path) =
            match_indexed_with_state(&ctx, card, request_type, request_id, &mut state);
        assert_eq!(build_path, MatcherPath::IndexBuild);
    }
    for card in evidence.iter().take(4) {
        let (_, hit_path) =
            match_indexed_with_state(&ctx, card, request_type, request_id, &mut state);
        assert_eq!(hit_path, MatcherPath::IndexHit);
    }
    let (_, fifth_path) =
        match_indexed_with_state(&ctx, &evidence[4], request_type, request_id, &mut state);
    assert_eq!(fifth_path, MatcherPath::FirstSeenLinear);
    let (_, evicted_path) =
        match_indexed_with_state(&ctx, &evidence[0], request_type, request_id, &mut state);
    assert_eq!(evicted_path, MatcherPath::FirstSeenLinear);
}

#[test]
fn matcher_cache_first_seen_path_matches_full_linear_predicate() {
    let evidence = benchmark_evidence(
        MATCHER_INDEX_THRESHOLD + 1,
        Distribution::Mixed,
        Some(MATCHER_INDEX_THRESHOLD),
    );
    let ctx = probe_ctx();
    let (request_type, request_id) = parse_resource_key("monitor:777");
    let expected = find_linear_published_grant(&ctx, &evidence, request_type, request_id)
        .map(|grant| grant.grant_id);
    let mut state = MatcherCacheState::new();
    let (actual, path) =
        match_indexed_with_state(&ctx, &evidence, request_type, request_id, &mut state);
    assert_eq!(path, MatcherPath::FirstSeenLinear);
    assert_eq!(actual.map(|grant| grant.grant_id), expected);
}

#[derive(Clone, Copy)]
enum Distribution {
    Mixed,
    SingleType,
}

impl Distribution {
    fn label(self) -> &'static str {
        match self {
            Self::Mixed => "mixed",
            Self::SingleType => "single_type",
        }
    }

    fn resource_type(self, index: usize) -> &'static str {
        match self {
            Self::Mixed => MIXED_RESOURCE_TYPES[index % MIXED_RESOURCE_TYPES.len()],
            Self::SingleType => "monitor",
        }
    }
}

fn benchmark_evidence(
    size: usize,
    distribution: Distribution,
    match_position: Option<usize>,
) -> Arc<PublishedCardAuthorization> {
    let grants = (0..size)
        .map(|index| {
            let resource = if match_position == Some(index) {
                "monitor:777".to_owned()
            } else {
                let resource_type = distribution.resource_type(index);
                if resource_type == "monitor" && index == 777 {
                    "monitor:778".to_owned()
                } else {
                    format!("{resource_type}:{index}")
                }
            };
            probe_grant(index, &resource)
        })
        .collect();
    Arc::new(evidence_from(grants))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProbePath {
    Linear,
    IndexHit,
    IndexBuild,
}

impl ProbePath {
    fn label(self) -> &'static str {
        match self {
            Self::Linear => "forced_linear",
            Self::IndexHit => "forced_index_hit",
            Self::IndexBuild => "cold_index_build",
        }
    }
}

#[derive(Clone, Copy)]
struct Summary {
    median_ns: u128,
    p95_ns: u128,
}

fn summarize(mut samples: Vec<u128>) -> Summary {
    samples.sort_unstable();
    let median_ns = samples[samples.len() / 2];
    let p95_index = (samples.len() * 95).div_ceil(100).saturating_sub(1);
    Summary {
        median_ns,
        p95_ns: samples[p95_index],
    }
}

fn measure_path(
    evidence: Arc<PublishedCardAuthorization>,
    ctx: PolicyContext,
    path: ProbePath,
    iterations: usize,
    rounds: usize,
    entry: bool,
) -> Summary {
    let samples = std::thread::spawn(move || {
        let (request_type, request_id) = parse_resource_key("monitor:777");
        let _metrics_handle = entry.then(ensure_probe_metrics);
        if entry {
            for _ in 0..1_000 {
                let found = match_published_effective_grant(&ctx, &evidence, "monitor:777");
                black_box(found.map(|grant| &grant.grant_id));
            }
        }
        let mut samples = Vec::with_capacity(rounds);
        for _ in 0..rounds {
            if entry {
                let start = Instant::now();
                for _ in 0..iterations {
                    let found = match_published_effective_grant(&ctx, &evidence, "monitor:777");
                    black_box(found.map(|grant| &grant.grant_id));
                }
                samples.push(start.elapsed().as_nanos() / iterations as u128);
                continue;
            }

            match path {
                ProbePath::Linear => {
                    let start = Instant::now();
                    for _ in 0..iterations {
                        let found =
                            find_linear_published_grant(&ctx, &evidence, request_type, request_id);
                        black_box(found.map(|grant| &grant.grant_id));
                    }
                    samples.push(start.elapsed().as_nanos() / iterations as u128);
                }
                ProbePath::IndexHit => {
                    let mut state = MatcherCacheState::new();
                    let (first, first_path) = match_indexed_with_state(
                        &ctx,
                        &evidence,
                        request_type,
                        request_id,
                        &mut state,
                    );
                    assert_eq!(first_path, MatcherPath::FirstSeenLinear);
                    black_box(first.map(|grant| &grant.grant_id));
                    let (built, build_path) = match_indexed_with_state(
                        &ctx,
                        &evidence,
                        request_type,
                        request_id,
                        &mut state,
                    );
                    assert_eq!(build_path, MatcherPath::IndexBuild);
                    black_box(built.map(|grant| &grant.grant_id));
                    let start = Instant::now();
                    for _ in 0..iterations {
                        let (found, path) = match_indexed_with_state(
                            &ctx,
                            &evidence,
                            request_type,
                            request_id,
                            &mut state,
                        );
                        black_box((found.map(|grant| &grant.grant_id), path));
                    }
                    samples.push(start.elapsed().as_nanos() / iterations as u128);
                }
                ProbePath::IndexBuild => {
                    let mut elapsed = 0u128;
                    for _ in 0..iterations {
                        let mut cold_state = MatcherCacheState::new();
                        let (first, first_path) = match_indexed_with_state(
                            &ctx,
                            &evidence,
                            request_type,
                            request_id,
                            &mut cold_state,
                        );
                        assert_eq!(first_path, MatcherPath::FirstSeenLinear);
                        black_box(first.map(|grant| &grant.grant_id));
                        let start = Instant::now();
                        let (built, build_path) = match_indexed_with_state(
                            &ctx,
                            &evidence,
                            request_type,
                            request_id,
                            &mut cold_state,
                        );
                        assert_eq!(build_path, MatcherPath::IndexBuild);
                        black_box(built.map(|grant| &grant.grant_id));
                        elapsed += start.elapsed().as_nanos();
                    }
                    samples.push(elapsed / iterations as u128);
                }
            }
        }
        samples
    })
    .join()
    .expect("matcher probe worker should complete");
    summarize(samples)
}

fn iterations_for(size: usize, path: ProbePath) -> usize {
    match (path, size) {
        (ProbePath::Linear, 0..=100) => 20_000,
        (ProbePath::Linear, 101..=1000) => 5_000,
        (ProbePath::Linear, _) => 800,
        (ProbePath::IndexBuild, _) => 64,
        (ProbePath::IndexHit, _) => 20_000,
    }
}

#[ignore = "release-only matcher curve probe; run with --release -- --ignored --nocapture"]
#[test]
fn matcher_cost_position_curve() {
    let ctx = probe_ctx();
    let rounds = 21;
    for size in [100usize, 1000, 4050] {
        for distribution in [Distribution::Mixed, Distribution::SingleType] {
            for (position_label, position) in [
                ("first", Some(0)),
                ("middle", Some(size / 2)),
                ("last", Some(size - 1)),
                ("absent", None),
            ] {
                let evidence = benchmark_evidence(size, distribution, position);
                assert_eq!(evidence.effective_grants.len(), size);
                let linear = measure_path(
                    Arc::clone(&evidence),
                    ctx.clone(),
                    ProbePath::Linear,
                    iterations_for(size, ProbePath::Linear),
                    rounds,
                    false,
                );
                let indexed_hit = measure_path(
                    Arc::clone(&evidence),
                    ctx.clone(),
                    ProbePath::IndexHit,
                    iterations_for(size, ProbePath::IndexHit),
                    rounds,
                    false,
                );
                let index_build = measure_path(
                    Arc::clone(&evidence),
                    ctx.clone(),
                    ProbePath::IndexBuild,
                    iterations_for(size, ProbePath::IndexBuild),
                    rounds,
                    false,
                );
                let production_entry = measure_path(
                    evidence,
                    ctx.clone(),
                    ProbePath::IndexHit,
                    iterations_for(size, ProbePath::IndexHit),
                    rounds,
                    true,
                );
                eprintln!(
                    "[matcher n={size:>4} dist={} position={position_label:>6}] {} p50/p95={}/{} ns; {} p50/p95={}/{} ns; {} p50/p95={}/{} ns; production-entry p50/p95={}/{} ns",
                    distribution.label(),
                    ProbePath::Linear.label(),
                    linear.median_ns,
                    linear.p95_ns,
                    ProbePath::IndexHit.label(),
                    indexed_hit.median_ns,
                    indexed_hit.p95_ns,
                    ProbePath::IndexBuild.label(),
                    index_build.median_ns,
                    index_build.p95_ns,
                    production_entry.median_ns,
                    production_entry.p95_ns,
                );
            }
        }
    }
}

#[derive(Default)]
struct PathCounts {
    builds: usize,
    hits: usize,
    cooldowns: usize,
    probationary_linear: usize,
}

#[derive(Clone, Copy)]
enum CandidatePolicy {
    Current,
    FirstSeenLinear,
    ExponentialCooldown,
}

impl CandidatePolicy {
    fn label(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::FirstSeenLinear => "first_seen_linear",
            Self::ExponentialCooldown => "exponential_cooldown",
        }
    }
}

#[derive(Clone, Copy)]
enum CandidatePath {
    IndexBuild,
    IndexHit,
    LinearCooldown,
    FirstSeenLinear,
}

impl PathCounts {
    fn record_candidate(&mut self, path: CandidatePath) {
        match path {
            CandidatePath::IndexBuild => self.builds += 1,
            CandidatePath::IndexHit => self.hits += 1,
            CandidatePath::LinearCooldown => self.cooldowns += 1,
            CandidatePath::FirstSeenLinear => self.probationary_linear += 1,
        }
    }
}

fn match_index<'a>(
    ctx: &PolicyContext,
    evidence: &'a Arc<PublishedCardAuthorization>,
    request_type: &str,
    request_id: Option<&str>,
    index: &super::MatcherIndex,
) -> Option<&'a CanonicalGrant> {
    let mut candidates = Vec::with_capacity(index.wildcard.len() + 64);
    if let Some(bucket) = index.by_type.get(request_type) {
        candidates.extend_from_slice(bucket);
    }
    candidates.extend_from_slice(&index.wildcard);
    candidates.sort_unstable();
    candidates.into_iter().find_map(|position| {
        let grant = &evidence.effective_grants[position];
        super::grant_matches_request(
            ctx,
            request_type,
            request_id,
            request_id.is_none(),
            evidence.read_unix_seconds,
            grant,
        )
        .then_some(grant)
    })
}

struct LegacyCacheState {
    slots: [Option<(Arc<PublishedCardAuthorization>, super::MatcherIndex)>; 4],
    next_victim: usize,
    ops: u64,
    hits: u64,
    rebuilds: u64,
    disabled_until_ops: u64,
}

impl LegacyCacheState {
    fn new() -> Self {
        Self {
            slots: [None, None, None, None],
            next_victim: 0,
            ops: 0,
            hits: 0,
            rebuilds: 0,
            disabled_until_ops: 0,
        }
    }

    fn index_disabled(&mut self) -> bool {
        self.ops += 1;
        if self.ops < self.disabled_until_ops {
            return true;
        }
        if self.ops.is_multiple_of(MATCHER_CACHE_COOLDOWN_OPS) {
            let decisions = self.hits + self.rebuilds;
            let hit_pct = (self.hits * 100).checked_div(decisions);
            let degraded = hit_pct.is_some_and(|hit_pct| hit_pct < 25);
            self.hits = 0;
            self.rebuilds = 0;
            if degraded {
                self.disabled_until_ops = self.ops + MATCHER_CACHE_COOLDOWN_OPS;
                return true;
            }
        }
        false
    }

    fn lookup_or_build(
        &mut self,
        evidence: &Arc<PublishedCardAuthorization>,
    ) -> (&super::MatcherIndex, bool) {
        if let Some(position) = self.slots.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|(cached, _)| Arc::ptr_eq(cached, evidence))
        }) {
            self.hits += 1;
            return (&self.slots[position].as_ref().unwrap().1, true);
        }
        self.rebuilds += 1;
        let index = build_matcher_index(evidence);
        let victim = self.next_victim;
        self.slots[victim] = Some((Arc::clone(evidence), index));
        self.next_victim = (victim + 1) % self.slots.len();
        (&self.slots[victim].as_ref().unwrap().1, false)
    }
}

struct IncreasingCooldown {
    cooldown_window_ops: u64,
    disabled_until_ops: u64,
    next_window_check: u64,
}

impl IncreasingCooldown {
    fn new() -> Self {
        Self {
            cooldown_window_ops: MATCHER_CACHE_COOLDOWN_OPS,
            disabled_until_ops: 0,
            next_window_check: MATCHER_CACHE_COOLDOWN_OPS,
        }
    }

    fn index_disabled(&mut self, state: &mut LegacyCacheState) -> bool {
        state.ops += 1;
        if state.ops < self.disabled_until_ops {
            return true;
        }
        if state.ops < self.next_window_check {
            return false;
        }

        let decisions = state.hits + state.rebuilds;
        let hit_pct = (state.hits * 100).checked_div(decisions);
        let degraded = hit_pct.is_some_and(|hit_pct| hit_pct < 25);
        state.hits = 0;
        state.rebuilds = 0;
        if degraded {
            self.disabled_until_ops = state.ops + self.cooldown_window_ops;
            self.cooldown_window_ops = (self.cooldown_window_ops * 2).min(16_384);
            self.next_window_check = self.disabled_until_ops + MATCHER_CACHE_COOLDOWN_OPS;
            return true;
        }

        self.cooldown_window_ops = MATCHER_CACHE_COOLDOWN_OPS;
        self.next_window_check = state.ops + MATCHER_CACHE_COOLDOWN_OPS;
        false
    }
}

#[test]
fn production_probationary_cache_admits_reused_arc_after_one_linear_decision() {
    let evidence = benchmark_evidence(
        MATCHER_INDEX_THRESHOLD + 1,
        Distribution::Mixed,
        Some(MATCHER_INDEX_THRESHOLD),
    );
    let ctx = probe_ctx();
    let (request_type, request_id) = parse_resource_key("monitor:777");
    let expected = find_linear_published_grant(&ctx, &evidence, request_type, request_id)
        .map(|grant| grant.grant_id);
    let mut cache = MatcherCacheState::new();

    let (first, first_path) =
        match_indexed_with_state(&ctx, &evidence, request_type, request_id, &mut cache);
    assert_eq!(first_path, MatcherPath::FirstSeenLinear);
    assert_eq!(first.map(|grant| grant.grant_id), expected);

    let (second, second_path) =
        match_indexed_with_state(&ctx, &evidence, request_type, request_id, &mut cache);
    assert_eq!(second_path, MatcherPath::IndexBuild);
    assert_eq!(second.map(|grant| grant.grant_id), expected);

    let (third, third_path) =
        match_indexed_with_state(&ctx, &evidence, request_type, request_id, &mut cache);
    assert_eq!(third_path, MatcherPath::IndexHit);
    assert_eq!(third.map(|grant| grant.grant_id), expected);
}

#[test]
fn production_probationary_cache_avoids_builds_when_five_arcs_rotate() {
    let evidences = (0..5)
        .map(|_| {
            benchmark_evidence(
                MATCHER_INDEX_THRESHOLD + 1,
                Distribution::Mixed,
                Some(MATCHER_INDEX_THRESHOLD),
            )
        })
        .collect::<Vec<_>>();
    let ctx = probe_ctx();
    let (request_type, request_id) = parse_resource_key("monitor:777");
    let mut cache = MatcherCacheState::new();

    for _ in 0..4 {
        for evidence in &evidences {
            let (matched, path) =
                match_indexed_with_state(&ctx, evidence, request_type, request_id, &mut cache);
            assert_eq!(path, MatcherPath::FirstSeenLinear);
            assert!(matched.is_some());
        }
    }
}

#[test]
fn increasing_cooldown_doubles_after_repeated_low_reuse_windows() {
    let mut state = LegacyCacheState::new();
    let mut cooldown = IncreasingCooldown::new();
    state.ops = MATCHER_CACHE_COOLDOWN_OPS - 1;
    state.rebuilds = MATCHER_CACHE_COOLDOWN_OPS - 1;

    assert!(cooldown.index_disabled(&mut state));
    assert_eq!(cooldown.disabled_until_ops, 2 * MATCHER_CACHE_COOLDOWN_OPS);
    assert_eq!(cooldown.cooldown_window_ops, 2 * MATCHER_CACHE_COOLDOWN_OPS);
    assert_eq!(state.hits, 0);
    assert_eq!(state.rebuilds, 0);

    state.ops = cooldown.disabled_until_ops - 1;
    assert!(!cooldown.index_disabled(&mut state));
    state.ops = cooldown.next_window_check - 1;
    state.rebuilds = MATCHER_CACHE_COOLDOWN_OPS - 1;
    assert!(cooldown.index_disabled(&mut state));
    assert_eq!(cooldown.disabled_until_ops, 5 * MATCHER_CACHE_COOLDOWN_OPS);
    assert_eq!(cooldown.cooldown_window_ops, 4 * MATCHER_CACHE_COOLDOWN_OPS);
}

fn match_current_strategy<'a>(
    ctx: &PolicyContext,
    evidence: &'a Arc<PublishedCardAuthorization>,
    request_type: &str,
    request_id: Option<&str>,
    state: &mut LegacyCacheState,
) -> (Option<&'a CanonicalGrant>, CandidatePath) {
    if state.index_disabled() {
        return (
            find_linear_published_grant(ctx, evidence, request_type, request_id),
            CandidatePath::LinearCooldown,
        );
    }
    let (index, was_hit) = state.lookup_or_build(evidence);
    (
        match_index(ctx, evidence, request_type, request_id, index),
        if was_hit {
            CandidatePath::IndexHit
        } else {
            CandidatePath::IndexBuild
        },
    )
}

fn match_indexed_with_window<'a>(
    ctx: &PolicyContext,
    evidence: &'a Arc<PublishedCardAuthorization>,
    request_type: &str,
    request_id: Option<&str>,
    state: &mut LegacyCacheState,
    cooldown: &mut IncreasingCooldown,
) -> (Option<&'a CanonicalGrant>, CandidatePath) {
    if cooldown.index_disabled(state) {
        return (
            find_linear_published_grant(ctx, evidence, request_type, request_id),
            CandidatePath::LinearCooldown,
        );
    }
    let (index, was_hit) = state.lookup_or_build(evidence);
    (
        match_index(ctx, evidence, request_type, request_id, index),
        if was_hit {
            CandidatePath::IndexHit
        } else {
            CandidatePath::IndexBuild
        },
    )
}

fn interleave_candidate_sample(
    evidences: &[Arc<PublishedCardAuthorization>],
    ctx: &PolicyContext,
    iterations: usize,
    warmup_rounds: usize,
    policy: CandidatePolicy,
) -> (u128, PathCounts, u64) {
    let (request_type, request_id) = parse_resource_key("monitor:777");
    let mut current = LegacyCacheState::new();
    let mut probation = MatcherCacheState::new();
    let mut exponential = LegacyCacheState::new();
    let mut cooldown = IncreasingCooldown::new();
    let mut run = |evidence: &Arc<PublishedCardAuthorization>, counts: Option<&mut PathCounts>| {
        let (matched, path) = match policy {
            CandidatePolicy::Current => {
                match_current_strategy(ctx, evidence, request_type, request_id, &mut current)
            }
            CandidatePolicy::FirstSeenLinear => {
                let (matched, path) = match_indexed_with_state(
                    ctx,
                    evidence,
                    request_type,
                    request_id,
                    &mut probation,
                );
                let path = match path {
                    MatcherPath::FirstSeenLinear => CandidatePath::FirstSeenLinear,
                    MatcherPath::IndexBuild => CandidatePath::IndexBuild,
                    MatcherPath::IndexHit => CandidatePath::IndexHit,
                    MatcherPath::LinearThreshold => unreachable!("probe uses indexed evidence"),
                };
                (matched, path)
            }
            CandidatePolicy::ExponentialCooldown => match_indexed_with_window(
                ctx,
                evidence,
                request_type,
                request_id,
                &mut exponential,
                &mut cooldown,
            ),
        };
        if let Some(counts) = counts {
            counts.record_candidate(path);
        }
        black_box(matched.map(|grant| &grant.grant_id));
        black_box(path);
    };
    for _ in 0..warmup_rounds {
        for evidence in evidences {
            run(evidence, None);
        }
    }
    let decisions = iterations * evidences.len();
    let start = Instant::now();
    let mut counts = PathCounts::default();
    for _ in 0..iterations {
        for evidence in evidences {
            run(evidence, Some(&mut counts));
        }
    }
    (
        start.elapsed().as_nanos() / decisions as u128,
        counts,
        match policy {
            CandidatePolicy::ExponentialCooldown => cooldown.cooldown_window_ops,
            CandidatePolicy::Current | CandidatePolicy::FirstSeenLinear => {
                MATCHER_CACHE_COOLDOWN_OPS
            }
        },
    )
}

#[ignore = "release-only matcher candidate comparison; run with --release -- --ignored --nocapture"]
#[test]
fn matcher_cache_candidate_strategy_curve() {
    let size = MATCHER_INDEX_THRESHOLD + 1;
    let ctx = probe_ctx();
    let rounds = 11;
    let policies = [
        CandidatePolicy::Current,
        CandidatePolicy::FirstSeenLinear,
        CandidatePolicy::ExponentialCooldown,
    ];

    for distribution in [Distribution::Mixed, Distribution::SingleType] {
        for cardinality in [1usize, 2, 4, 5, 8] {
            let evidences = (0..cardinality)
                .map(|_| benchmark_evidence(size, distribution, Some(size - 1)))
                .collect::<Vec<_>>();
            for policy in policies {
                let samples = std::thread::spawn({
                    let evidences = evidences.clone();
                    let ctx = ctx.clone();
                    move || {
                        (0..rounds)
                            .map(|_| {
                                interleave_candidate_sample(&evidences, &ctx, 4096, 32, policy)
                            })
                            .collect::<Vec<_>>()
                    }
                })
                .join()
                .expect("matcher candidate probe worker should complete");
                let summary = summarize(samples.iter().map(|(ns, _, _)| *ns).collect());
                let (_, final_counts, final_cooldown) =
                    samples.last().expect("at least one probe round");
                eprintln!(
                    "[matcher policy={} dist={} stable-arcs={cardinality} position=last] p50/p95={}/{} ns/decision; builds={} hits={} cooldowns={} first-seen-linear={} cooldown-window={} ops",
                    policy.label(),
                    distribution.label(),
                    summary.median_ns,
                    summary.p95_ns,
                    final_counts.builds,
                    final_counts.hits,
                    final_counts.cooldowns,
                    final_counts.probationary_linear,
                    final_cooldown,
                );
            }
        }

        for (position_label, position) in [
            ("first", Some(0)),
            ("middle", Some(size / 2)),
            ("last", Some(size - 1)),
            ("absent", None),
        ] {
            let evidences = (0..4)
                .map(|_| benchmark_evidence(size, distribution, position))
                .collect::<Vec<_>>();
            for policy in policies {
                let samples = std::thread::spawn({
                    let evidences = evidences.clone();
                    let ctx = ctx.clone();
                    move || {
                        (0..rounds)
                            .map(|_| interleave_candidate_sample(&evidences, &ctx, 128, 32, policy))
                            .collect::<Vec<_>>()
                    }
                })
                .join()
                .expect("matcher candidate position probe worker should complete");
                let summary = summarize(samples.iter().map(|(ns, _, _)| *ns).collect());
                let (_, final_counts, final_cooldown) =
                    samples.last().expect("at least one probe round");
                eprintln!(
                    "[matcher policy={} dist={} stable-arcs=4 position={position_label}] p50/p95={}/{} ns/decision; builds={} hits={} cooldowns={} first-seen-linear={} cooldown-window={} ops",
                    policy.label(),
                    distribution.label(),
                    summary.median_ns,
                    summary.p95_ns,
                    final_counts.builds,
                    final_counts.hits,
                    final_counts.cooldowns,
                    final_counts.probationary_linear,
                    final_cooldown,
                );
            }

            let fresh_count = 32;
            let fresh_evidences = (0..fresh_count)
                .map(|_| benchmark_evidence(size, distribution, position))
                .collect::<Vec<_>>();
            for policy in policies {
                let samples = std::thread::spawn({
                    let evidences = fresh_evidences.clone();
                    let ctx = ctx.clone();
                    move || {
                        (0..rounds)
                            .map(|_| interleave_candidate_sample(&evidences, &ctx, 1, 0, policy))
                            .collect::<Vec<_>>()
                    }
                })
                .join()
                .expect("fresh-Arc candidate probe worker should complete");
                let summary = summarize(samples.iter().map(|(ns, _, _)| *ns).collect());
                let (_, final_counts, final_cooldown) =
                    samples.last().expect("at least one probe round");
                eprintln!(
                    "[matcher policy={} dist={} fresh-arcs={fresh_count} position={position_label}] p50/p95={}/{} ns/decision; builds={} hits={} cooldowns={} first-seen-linear={} cooldown-window={} ops",
                    policy.label(),
                    distribution.label(),
                    summary.median_ns,
                    summary.p95_ns,
                    final_counts.builds,
                    final_counts.hits,
                    final_counts.cooldowns,
                    final_counts.probationary_linear,
                    final_cooldown,
                );
            }
        }
    }
}
