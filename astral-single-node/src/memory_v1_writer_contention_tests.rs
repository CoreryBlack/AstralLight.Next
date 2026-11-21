//! memory—v1: HTTP governance writer contention measurement (same vs different
//! targets) over the synthetic production ports and the retained local journal.
//!
//! This module is the missing measurement lane for governance writer
//! contention. It reuses the warm-governance scenario's `SyntheticService` (the
//! isolated fixture root, private durable journal, real loopback TCP, real
//! gateway/authn/authz stack and the real durable commit owner) and drives it
//! with synthetic authorized governance operations only: `user_card:create`
//! mutations issued by the fixture's governance writer card, plus ordinary
//! ALLOW reads as the control lane.
//!
//! Lanes:
//!
//! * same-target contention — `WRITERS` concurrent creations of one identical
//!   user card with distinct operation ids; exactly one writer may publish and
//!   every other writer must observe a fail-closed 503 refusal,
//! * distinct-target contention — `WRITERS` concurrent creations of distinct
//!   user cards with distinct operation ids plus `READERS` overlapping ordinary
//!   registry reads; outcomes are timing-dependent, so only structural
//!   postconditions are asserted,
//! * ordinary read control — concurrent ALLOW reads during writer contention
//!   stay 200 and never journal.
//!
//! Refusal shapes are distinguished: a handler-level refusal carries the JSON
//! PENDING envelope (`AUTHORIZATION_PENDING`, `Retry-After: 3`), while a
//! pre-owner refusal (the middleware target read refusing a target that a
//! concurrent writer already published, or an unavailable reader) is a bare 503
//! with no body. Pre-owner refusals never reach the commit owner, so they
//! record no commit-phase samples at all; the server view quantifies that gap
//! through the owner-reached `prepare` count.
//!
//! Server view: the commit owner's phase histograms
//! (`astral_memory_v1_commit_phase_seconds{phase=...}` — including the
//! `prepare`, `journal_lock_wait`, `journal_lock_held` and `journal_durability`
//! phases) are rendered from the Prometheus recorder and reduced to counts,
//! mean and the exporter's own summary P50/P99. The `metrics` facade dispatch is
//! once per process, so the recorder install is the existing stress test's
//! process-global pattern; when another test in the same process already
//! installed a recorder, this run degrades to the client view and reports the
//! limitation instead of failing. When the recorder is installed, every
//! asserted phase sample's availability is checked explicitly: an absent
//! histogram fails the lane and can never pass as a zero count.
//!
//! Retained-journal correlation: after the service drains, the private journal
//! is reopened and every published operation must appear exactly once as a
//! mutation frame whose mutation sequence equals the response's root-version
//! delta; refused writers and reads must not appear at all.
//!
//! Measurement limits, stated plainly: single process, loopback TCP, isolated
//! fixture root, private temp journal, bounded workers and deadline; latency is
//! client wall-clock including a fresh TCP connection per request; all timing
//! figures are informational report values — the assertions are behavioural
//! floors, not performance gates. Nothing here proves database provenance,
//! production adoption or authorization of any real data.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use astral_authorization_root::memory_v1_db_rows::UserCardStatus;
use astral_authorization_root::memory_v1_root::ManagementMutationV2;
use astral_trustgraph::service::memory_v1_mutation_coordinator::{
    decode_journal_payload, journal_producer_boot_id,
};
use astral_types::memory_v1::MemoryId;
use astral_types::memory_v1_journal::RecordKind;
use serde_json::json;
use tokio::sync::Barrier;
use tokio::time::timeout;

use super::synthetic_scenarios::{paper_warm_rows, SyntheticService as ContentionService};
use super::{http, login};
use crate::memory_v1_composition::full_path_tests::{BOB, CARD_ALLOW, CARD_BOB, REGISTRY};

// memory—v1: The governance write route and the synthetic target identifiers.
// The same-target card and the distinct-target cards are unused elsewhere, so
// they cannot collide with any fixture row or retained identity.
const USER_CARDS: &str = "/main/api/v1/governance/user-cards";
const TENANT: [u8; 16] = [0x13; 16];
const SAME_TARGET: [u8; 16] = [0x5F; 16];

// memory—v1: Bounded worker and read counts; the whole scenario runs under one
// deadline so the lane can never run unbounded.
const WRITERS: usize = 4;
const READERS: usize = 4;
const READS_PER_READER: usize = 4;
const SCENARIO_DEADLINE: Duration = Duration::from_secs(120);

// memory—v1: The commit phases the server view quantifies: the owner-reached
// refusal boundary and the durable core only publishers reach.
const COMMIT_PHASES: [&str; 5] = [
    "prepare",
    "journal_lock_wait",
    "journal_lock_held",
    "journal_durability",
    "total",
];

// memory—v1: One classified governance write outcome with its client latency.
#[derive(Debug)]
struct WriteOutcome {
    operation: String,
    target: [u8; 16],
    ok: bool,
    pending: bool,
    /// A bare 503 with no body: the middleware refused before the commit owner.
    pre_owner: bool,
    root_version: Option<u64>,
    root_digest: Option<String>,
    latency_us: u64,
}

// memory—v1: The quantified summary of one latency sample set (report values,
// never pass/fail predicates).
struct Samples {
    count: usize,
    mean_us: u64,
    p50_us: u64,
    max_us: u64,
}

fn summarize(samples: &[u64]) -> Samples {
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let count = sorted.len();
    Samples {
        count,
        mean_us: if sorted.is_empty() {
            0
        } else {
            sorted.iter().sum::<u64>() / count as u64
        },
        p50_us: sorted.get(count / 2).copied().unwrap_or(0),
        max_us: sorted.last().copied().unwrap_or(0),
    }
}

// memory—v1: Pull one scalar out of the Prometheus text format. The commit
// owner labels each phase, so the sample line carries `phase="..."`.
fn extract_metric(rendered: &str, metric: &str, phase: &str) -> Option<f64> {
    rendered
        .lines()
        .filter(|line| line.starts_with(metric))
        .find(|line| line.contains(&format!("phase=\"{phase}\"")))
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|value| value.parse::<f64>().ok())
}

// memory—v1: Read one phase's exported summary quantile in microseconds. The
// exporter renders the commit-phase metric as a Prometheus summary, so P50/P99
// are the exporter's own quantiles, not reconstructed buckets.
fn extract_metric_quantile_us(rendered: &str, phase: &str, quantile: &str) -> u64 {
    rendered
        .lines()
        .filter(|line| line.starts_with("astral_memory_v1_commit_phase_seconds{"))
        .find(|line| {
            line.contains(&format!("phase=\"{phase}\""))
                && line.contains(&format!("quantile=\"{quantile}\""))
        })
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|value| value.parse::<f64>().ok())
        .map(|seconds| (seconds * 1_000_000.0) as u64)
        .unwrap_or(0)
}

// memory—v1: Run one write lane: every worker holds a distinct operation id and
// fires its `user_card:create` at the shared barrier. The only acceptable
// outcomes are a correlated publish (200) or one of the two fail-closed 503
// refusal shapes; anything else fails the lane immediately.
async fn run_write_lane(
    addr: SocketAddr,
    token: &str,
    prefix: &str,
    targets: &[[u8; 16]],
    barrier: Arc<Barrier>,
) -> Vec<WriteOutcome> {
    let mut handles = Vec::new();
    for (worker, target) in targets.iter().enumerate() {
        let barrier = Arc::clone(&barrier);
        let token = token.to_owned();
        let operation = format!("{prefix}-{worker:02}");
        let target = *target;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let body = json!({
                "user_card_id": MemoryId::from_bytes(target).to_string(),
                "user_id": MemoryId::from_bytes(BOB).to_string(),
                "tenant_id": MemoryId::from_bytes(TENANT).to_string(),
            });
            let started = Instant::now();
            let reply = http(
                addr,
                "POST",
                USER_CARDS,
                Some(&token),
                Some(&body),
                &[("x-request-id", operation.as_str())],
            )
            .await;
            let latency_us = u64::try_from(started.elapsed().as_micros()).unwrap();
            let ok = reply.status == 200
                && reply.body["data"]["operationId"].as_str() == Some(operation.as_str());
            let handler_pending = reply.status == 503
                && reply.body["reasonCode"] == "AUTHORIZATION_PENDING"
                && reply.header("retry-after") == Some("3")
                && reply.body["data"].is_null();
            // A bare 503 with no body: the middleware target read refused before
            // the commit owner was reached (fail-closed, no journal record).
            let pre_owner_pending = reply.status == 503 && reply.body.is_null();
            let pending = handler_pending || pre_owner_pending;
            assert!(
                ok || pending,
                "worker {worker} saw an unexpected governance outcome: status={} body={}",
                reply.status,
                reply.body
            );
            WriteOutcome {
                operation,
                target,
                ok,
                pending,
                pre_owner: pre_owner_pending,
                root_version: reply.body["data"]["rootVersion"].as_u64(),
                root_digest: reply.body["data"]["rootDigest"].as_str().map(str::to_owned),
                latency_us,
            }
        }));
    }
    let mut outcomes = Vec::new();
    for handle in handles {
        outcomes.push(handle.await.unwrap());
    }
    outcomes
}

// memory—v1: The ordinary read control: concurrent ALLOW registry reads during
// writer contention. Every read must stay 200 on a consistent snapshot.
async fn run_read_lane(addr: SocketAddr, token: String, barrier: Arc<Barrier>) -> Vec<u64> {
    let mut handles = Vec::new();
    for _reader in 0..READERS {
        let barrier = Arc::clone(&barrier);
        let token = token.clone();
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let mut latencies = Vec::new();
            for _ in 0..READS_PER_READER {
                let started = Instant::now();
                let reply = http(addr, "GET", REGISTRY, Some(&token), None, &[]).await;
                let latency_us = u64::try_from(started.elapsed().as_micros()).unwrap();
                assert_eq!(
                    reply.status, 200,
                    "an ordinary read must not be blocked by writer contention: {}",
                    reply.body
                );
                assert!(!reply.body["data"].is_null(), "{}", reply.body);
                latencies.push(latency_us);
            }
            latencies
        }));
    }
    let mut samples = Vec::new();
    for handle in handles {
        samples.extend(handle.await.unwrap());
    }
    samples
}

// memory—v1: The bounded measurement scenario. Selected explicitly by the
// DarkStar writer-contention suite; never runs under the default workspace gate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "selected by the DarkStar synthetic writer-contention suite"]
async fn writer_contention_same_and_distinct_targets_measurements() {
    // paper_warm_rows asserts the paper's 23-fact oracle counts internally, so
    // the fixture integrity gate runs on every selection of this lane.
    let rows = paper_warm_rows();
    timeout(SCENARIO_DEADLINE, writer_contention_scenario(rows))
        .await
        .expect("the writer contention scenario finished within the bounded deadline");
}

// memory—v1: Same-target and distinct-target writer contention with the read
// control, outcome counts, client latency, commit-phase server view and
// retained-journal correlation.
async fn writer_contention_scenario(
    rows: astral_authorization_root::memory_v1_db_rows::CandidateRows,
) {
    // The commit owner records phases through the metrics facade, whose global
    // dispatch is installed once per process. Install is best effort: when
    // another test in this process already installed a recorder, the server
    // view degrades and the limitation is reported below.
    let prometheus = match metrics_exporter_prometheus::PrometheusBuilder::new().install_recorder()
    {
        Ok(handle) => Some(handle),
        Err(_) => {
            eprintln!(
                "writer_contention server_view=unavailable reason=\"a process-global metrics recorder is already installed; the metrics facade dispatch is once per process, so this run quantifies the client view only\""
            );
            None
        }
    };
    let service = ContentionService::start(rows).await;
    let addr = service.addr;
    let baseline = service.root.metadata().unwrap().version;
    let bob = login(addr, "bob", "bob-secret", CARD_BOB).await;
    let alice = login(addr, "alice", "alice-secret", CARD_ALLOW).await;

    // ── Lane A: WRITERS concurrent creations of one identical target card. ──
    let same_targets = [SAME_TARGET; WRITERS];
    let same = run_write_lane(
        addr,
        &bob,
        &format!("contention-{}-same", uuid::Uuid::new_v4().simple()),
        &same_targets,
        Arc::new(Barrier::new(WRITERS)),
    )
    .await;
    let same_ok: Vec<&WriteOutcome> = same.iter().filter(|outcome| outcome.ok).collect();
    let same_pending: Vec<&WriteOutcome> = same.iter().filter(|outcome| outcome.pending).collect();
    assert_eq!(
        same_ok.len(),
        1,
        "exactly one same-target writer may publish: {same:?}"
    );
    assert_eq!(same_pending.len(), WRITERS - 1);
    assert_eq!(
        same_ok[0].root_version,
        Some(baseline + 1),
        "the same-target winner publishes exactly the next root version"
    );
    assert_eq!(
        service.root.metadata().unwrap().version,
        baseline + 1,
        "refused writers must not advance the root"
    );
    let after_same = baseline + 1;

    // ── Lane B: distinct targets plus the overlapping ordinary read control. ──
    let distinct_targets: Vec<[u8; 16]> = (0..WRITERS).map(|i| [0x70 + i as u8; 16]).collect();
    let barrier = Arc::new(Barrier::new(WRITERS + READERS));
    let read_handle = tokio::spawn(run_read_lane(addr, alice, Arc::clone(&barrier)));
    let distinct = run_write_lane(
        addr,
        &bob,
        &format!("contention-{}-distinct", uuid::Uuid::new_v4().simple()),
        &distinct_targets,
        barrier,
    )
    .await;
    let read_samples = read_handle.await.unwrap();
    assert_eq!(
        read_samples.len(),
        READERS * READS_PER_READER,
        "every ordinary read completed within the lane"
    );
    let distinct_ok: Vec<&WriteOutcome> = distinct.iter().filter(|outcome| outcome.ok).collect();
    let distinct_pending: Vec<&WriteOutcome> =
        distinct.iter().filter(|outcome| outcome.pending).collect();
    assert!(
        !distinct_ok.is_empty(),
        "the first distinct-target writer must publish: {distinct:?}"
    );
    assert_eq!(distinct_ok.len() + distinct_pending.len(), WRITERS);
    let mut deltas = BTreeSet::new();
    for outcome in &distinct_ok {
        deltas.insert(
            outcome
                .root_version
                .expect("a published response carries its root version")
                - after_same,
        );
    }
    let published: BTreeSet<u64> = (1..=distinct_ok.len() as u64).collect();
    assert_eq!(
        deltas, published,
        "published root versions are exactly the next contiguous versions"
    );
    let mut digests = BTreeSet::new();
    for outcome in same_ok.iter().chain(distinct_ok.iter()) {
        let digest = outcome
            .root_digest
            .as_ref()
            .expect("a published response carries its root digest");
        assert!(!digest.is_empty());
        assert!(
            digests.insert(digest.clone()),
            "each publish mints a new digest"
        );
    }
    assert_eq!(
        service.root.metadata().unwrap().version,
        after_same + distinct_ok.len() as u64,
        "the root advanced by exactly the published distinct-target mutations"
    );

    // ── Drain, reopen the retained journal and correlate every outcome. ──
    let dir = service.drain().await;
    let total_published = 1 + distinct_ok.len();
    let mut expected_targets: BTreeMap<String, [u8; 16]> = BTreeMap::new();
    expected_targets.insert(same_ok[0].operation.clone(), SAME_TARGET);
    for outcome in &distinct_ok {
        expected_targets.insert(outcome.operation.clone(), outcome.target);
    }
    {
        let (journal, _sync) = dir.reopen();
        let records = journal.recovery_records();
        assert_eq!(
            records.len(),
            total_published,
            "the retained journal holds exactly the published mutations and nothing else"
        );
        assert_eq!(
            journal.position().mutation_sequence(),
            total_published as u64
        );
        let mut retained_ops = BTreeSet::new();
        for (index, frame) in records.iter().enumerate() {
            let sequence = index as u64 + 1;
            assert!(
                matches!(frame.kind, RecordKind::Mutation),
                "ALLOW reads and refused writes never journal: frame {sequence} is {:?}",
                frame.kind
            );
            assert_eq!(frame.journal_sequence, sequence);
            assert_eq!(frame.mutation_sequence, sequence);
            assert!(
                retained_ops.insert(frame.operation_id.clone()),
                "a recorded operation identity is never written twice"
            );
            let decoded = decode_journal_payload(&frame.payload)
                .expect("a canonical retained mutation envelope");
            assert_eq!(decoded.operation_id(), frame.operation_id);
            assert_eq!(decoded.origin_boot_id(), Some(journal_producer_boot_id()));
            match decoded.mutation() {
                ManagementMutationV2::UserCardCreate { row } => {
                    assert_eq!(
                        row.user_card_id,
                        expected_targets
                            .get(&frame.operation_id)
                            .copied()
                            .expect("every retained operation is a published lane operation")
                    );
                    assert_eq!((row.user_id, row.tenant_id), (BOB, TENANT));
                    assert!(matches!(row.status, UserCardStatus::Active));
                }
                other => panic!("unexpected retained mutation at sequence {sequence}: {other:?}"),
            }
        }
        // Lane A completed before lane B started, so sequence 1 is its winner.
        assert_eq!(
            records[0].operation_id, same_ok[0].operation,
            "the retained first mutation is the same-target winner"
        );
        for outcome in &distinct_ok {
            // Root version and mutation sequence advance together from the same
            // baseline, so the response's version delta from the pre-lane
            // baseline is exactly the frame's mutation sequence.
            let delta = outcome.root_version.unwrap() - baseline;
            let frame = records
                .iter()
                .find(|frame| frame.operation_id == outcome.operation)
                .expect("every published operation is retained");
            assert_eq!(
                frame.mutation_sequence, delta,
                "the retained mutation sequence and the response root version are one counter"
            );
        }
    }

    // ── Server view: commit-phase samples for the owner-reached operations. ──
    let total_writes = WRITERS * 2;
    if let Some(handle) = &prometheus {
        let rendered = handle.render();
        let mut phase_counts: BTreeMap<&str, u64> = BTreeMap::new();
        for phase in COMMIT_PHASES {
            // Sample availability is asserted explicitly: an absent histogram
            // must fail this lane, never pass as a zero count.
            let count = extract_metric(
                &rendered,
                "astral_memory_v1_commit_phase_seconds_count",
                phase,
            )
            .map(|value| value as u64)
            .unwrap_or_else(|| {
                panic!(
                    "the commit-phase count sample for {phase} is absent from the rendered \
                     metrics; the filtered lane must not mark absent histograms as pass"
                )
            });
            phase_counts.insert(phase, count);
        }
        // Only publishers reach the durable core; pre-owner refusals record no
        // phases at all, and every publisher reaches each of them exactly once.
        for phase in [
            "journal_lock_wait",
            "journal_lock_held",
            "journal_durability",
        ] {
            assert_eq!(
                phase_counts[phase], total_published as u64,
                "phase {phase} must be sampled once per published mutation only"
            );
        }
        let owner_reached = phase_counts["prepare"];
        assert!(
            owner_reached >= total_published as u64,
            "every publisher reaches prepare: {owner_reached} < {total_published}"
        );
        assert!(
            owner_reached <= total_writes as u64,
            "no more owner-reached commits than write requests: {owner_reached} > {total_writes}"
        );
        let mut phase_report = String::from("writer_contention commit_phases");
        for phase in COMMIT_PHASES {
            let count = phase_counts[phase];
            let mean_us = extract_metric(
                &rendered,
                "astral_memory_v1_commit_phase_seconds_sum",
                phase,
            )
            .map(|seconds| (seconds * 1_000_000.0) as u64)
            .and_then(|sum_us| sum_us.checked_div(count));
            let p50 = extract_metric_quantile_us(&rendered, phase, "0.5");
            let p99 = extract_metric_quantile_us(&rendered, phase, "0.99");
            phase_report.push_str(&format!(
                " {}=count:{} mean_us:{} p50_us:{} p99_us:{}",
                phase,
                count,
                mean_us.unwrap_or(0),
                p50,
                p99,
            ));
        }
        eprintln!("{phase_report}");
        eprintln!(
            "writer_contention owner_boundary writes={total_writes} owner_reached={owner_reached} pre_owner_refusals={} published={total_published} note=\"pre-owner refusals record no commit-phase samples; owner-reached refusals stop at or after prepare\"",
            total_writes as u64 - owner_reached
        );
    }

    // ── Outcome counts and latency report (informational, bounded scope). ──
    let ok_latency = |outcomes: &[&WriteOutcome]| {
        summarize(
            &outcomes
                .iter()
                .map(|outcome| outcome.latency_us)
                .collect::<Vec<_>>(),
        )
    };
    let same_ok_q = ok_latency(&same_ok);
    let same_pending_q = ok_latency(&same_pending);
    let distinct_ok_q = ok_latency(&distinct_ok);
    let distinct_pending_q = ok_latency(&distinct_pending);
    let reads_q = summarize(&read_samples);
    let pre_owner =
        |outcomes: &[&WriteOutcome]| outcomes.iter().filter(|outcome| outcome.pre_owner).count();
    eprintln!(
        "writer_contention same_target workers={WRITERS} ok={} pending={} pending_json={} pending_bare_pre_owner={} ok_mean_us={} ok_p50_us={} ok_max_us={} pending_mean_us={} pending_p50_us={} pending_max_us={}",
        same_ok.len(),
        same_pending.len(),
        same_pending.len() - pre_owner(&same_pending),
        pre_owner(&same_pending),
        same_ok_q.mean_us,
        same_ok_q.p50_us,
        same_ok_q.max_us,
        same_pending_q.mean_us,
        same_pending_q.p50_us,
        same_pending_q.max_us,
    );
    eprintln!(
        "writer_contention distinct_target workers={WRITERS} ok={} pending={} pending_json={} pending_bare_pre_owner={} ok_mean_us={} ok_p50_us={} ok_max_us={} pending_mean_us={} pending_p50_us={} pending_max_us={}",
        distinct_ok.len(),
        distinct_pending.len(),
        distinct_pending.len() - pre_owner(&distinct_pending),
        pre_owner(&distinct_pending),
        distinct_ok_q.mean_us,
        distinct_ok_q.p50_us,
        distinct_ok_q.max_us,
        distinct_pending_q.mean_us,
        distinct_pending_q.p50_us,
        distinct_pending_q.max_us,
    );
    eprintln!(
        "writer_contention read_control readers={READERS} reads={} ok={} mean_us={} p50_us={} max_us={}",
        reads_q.count,
        read_samples.len(),
        reads_q.mean_us,
        reads_q.p50_us,
        reads_q.max_us,
    );
    eprintln!(
        "writer_contention retained_journal mutations={total_published} same_target_frame=1 distinct_frames={} deny_frames=0 journal_reopened=true listener_drained=true",
        total_published - 1
    );
    eprintln!(
        "measurement_limit: single process; loopback TCP; isolated fixture root; private temp journal; {WRITERS} writers/{READERS} readers; fresh TCP connection per request; latency is client wall clock including connect; phase p50/p99 are the exporter's summary quantiles; timings are informational, assertions are behavioural floors"
    );
    eprintln!("synthetic_evidence scenario=writer-contention");
    dir.remove();
}
