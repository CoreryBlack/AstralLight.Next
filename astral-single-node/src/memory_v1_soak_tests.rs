//! memory—v1: the opt-in sustained mixed-load soak over the synthetic loopback
//! service (ordinary reads, session lifecycle, ordinary governance, bounded
//! denial proofs) with per-window counters, P99 and process RSS.
//!
//! This module reuses the synthetic lane's isolated fixtures through the
//! `pub(super)` surface coordinated by the main agent:
//! `SyntheticService::{start, drain, addr, root}`, `paper_warm_rows`,
//! `JournalDir::{reopen, remove}` and the sibling `http`/`login` helpers.
//! It drives the real production composition (isolated fixture root, private
//! durable journal, real loopback TCP, real gateway/authn/authz stack and the
//! real durable commit owner) with a fixed offered load:
//!
//! * ordinary reads — an available baseline should ALLOW registry reads. Count
//!   exact fail-closed 503s separately and require at least 95% successful reads;
//!   this is a fixture sanity floor, not a production availability target;
//! * session lane — paired login + logout at a fixed interval so the session
//!   authority returns to its in-flight size every cycle;
//! * governance lane — exactly one ordinary `user_card:create` publish per
//!   window through the governed HTTP route (unique card per publish, unique
//!   operation id), so root, journal and checkpoint growth stay finite and
//!   predicted by the window count;
//! * denial lane — exactly one journaled fail-closed denial per window, run
//!   half a slot after the governance lane so the two lanes do not collide at
//!   the same instant. A deny whose proof races a concurrent mutation fails
//!   closed to a retryable 503; the accepted pending shapes are exact — no
//!   data plus one of the two exact contract reason codes
//!   (`AUTHORIZATION_AUDIT_UNAVAILABLE` with this lane's decision, or
//!   `AUTHORIZATION_PENDING`) — and any generic raw 503 is classified
//!   unexpected.
//!
//! Measurement limits, stated plainly: single process, loopback TCP, isolated
//! synthetic fixture, private temp journal, bounded workers and a bounded
//! duration; latency is client wall-clock including a fresh TCP connection per
//! request (the reused helper opens one connection per call); RSS samples the
//! test process itself via `sysinfo` and carries no sensitive data. All
//! timing/RSS figures are informational report values — the assertions are
//! behavioural floors (every issued request resolves as its lane's defined
//! outcome, the drain is clean, and journal/checkpoint growth equals the
//! counted mutations plus counted denials), never performance gates. Nothing
//! here proves database provenance, production adoption or authorization of
//! any real data, and nothing here claims production behaviour.
//!
//! Entry points:
//!
//! * `soak_smoke_...` — a non-ignored, short bounded smoke (four 1s windows);
//! * `soak_one_hour_...` — `#[ignore]` opt-in, one hour by default, with the
//!   hour count overridable only by `ASTRAL_MEMORY_V1_SOAK_HOURS` (1..=24).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use astral_types::memory_v1::MemoryId;
use astral_types::memory_v1_journal::{RecordKind, MAX_FRAME_BYTES};
use serde_json::{json, Value};
use tokio::time::MissedTickBehavior;

use super::synthetic_scenarios::{JournalDir, SyntheticService};
use super::{http, login, LOGOUT};
use crate::memory_v1_composition::full_path_tests::{
    BOB, CARD_ALLOW, CARD_BOB, CARD_UNBOUND, REGISTRY,
};

// memory—v1: The ordinary governance mutation surface reused from the paper
// warm-governance scenario (the fixture's governance writer card publishes it).
const GOVERNANCE_USER_CARDS: &str = "/main/api/v1/governance/user-cards";
const TENANT: [u8; 16] = [0x13; 16];
const OPERATION_PREFIX: &str = "soak";

// memory—v1: Tokens live at most 1800s; every long-lived lane refreshes well
// before expiry so an hour soak never observes an expired-session refusal.
const TOKEN_REFRESH_INTERVAL: Duration = Duration::from_secs(600);

/// The fixed offered load of one soak run; every rate is deterministic and the
/// denial and governance lanes offer exactly one request per window.
#[derive(Clone, Copy, Debug)]
struct SoakConfig {
    scenario: &'static str,
    windows: usize,
    window: Duration,
    read_workers: usize,
    read_interval: Duration,
    session_interval: Duration,
    lane_interval: Duration,
}

impl SoakConfig {
    fn duration(&self) -> Duration {
        self.window * self.windows as u32
    }

    // The exact number of fixed slots one interval-driven lane offers; every
    // soak interval must divide the run duration exactly.
    fn slots(&self, interval: Duration) -> usize {
        let duration = self.duration().as_nanos();
        let interval = interval.as_nanos();
        assert!(
            duration.is_multiple_of(interval),
            "soak interval {interval:?} must divide the run duration exactly"
        );
        (duration / interval) as usize
    }
}

/// One traffic lane; "matched" means the response is exactly the lane's
/// defined outcome, so a 403 denial is only expected in the deny lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum OpClass {
    Read,
    Session,
    Deny,
    Governance,
}

impl OpClass {
    fn label(self) -> &'static str {
        match self {
            OpClass::Read => "read",
            OpClass::Session => "session",
            OpClass::Deny => "deny",
            OpClass::Governance => "governance",
        }
    }
}

/// One completed request: the window it finished in, its lane, its outcome and
/// the client wall-clock RTT in microseconds. `matched` is the lane's primary
/// defined outcome; `pending` marks the retryable fail-closed 503 the deny
/// lane observes when its proof races a concurrent mutation.
struct Sample {
    window: usize,
    class: OpClass,
    matched: bool,
    pending: bool,
    status: u16,
    reason: String,
    rtt_us: u64,
}

/// Owned aggregate of one lane (or one window of one lane): completed count,
/// matched count, fail-closed pending count, RTT samples and the classified
/// unexpected outcomes.
#[derive(Default)]
struct LaneStat {
    completed: u64,
    matched: u64,
    pending: u64,
    rtts: Vec<u64>,
    pending_reasons: BTreeMap<String, usize>,
    unexpected: BTreeMap<(u16, String), usize>,
}

impl LaneStat {
    fn record(&mut self, sample: &Sample) {
        self.completed += 1;
        self.rtts.push(sample.rtt_us);
        if sample.matched {
            self.matched += 1;
        } else if sample.pending {
            self.pending += 1;
            *self
                .pending_reasons
                .entry(sample.reason.clone())
                .or_default() += 1;
        } else {
            *self
                .unexpected
                .entry((sample.status, sample.reason.clone()))
                .or_default() += 1;
        }
    }
}

/// One monitor tick: the process RSS sample for the window.
struct MonitorSample {
    window: usize,
    rss_bytes: Option<u64>,
}

/// Shared outcome bookkeeping: issues are counted when offered, samples when
/// completed, so a lost or panicked request shows up as an accounting gap.
struct Book {
    // Every lane is pre-registered so offer counting never mutates the map.
    issues: BTreeMap<OpClass, AtomicU64>,
    samples: Mutex<Vec<Sample>>,
    monitor: Mutex<Vec<MonitorSample>>,
}

impl Book {
    fn new() -> Self {
        Self {
            issues: [
                OpClass::Read,
                OpClass::Session,
                OpClass::Deny,
                OpClass::Governance,
            ]
            .into_iter()
            .map(|class| (class, AtomicU64::new(0)))
            .collect(),
            samples: Mutex::new(Vec::new()),
            monitor: Mutex::new(Vec::new()),
        }
    }

    fn issue(&self, class: OpClass) {
        self.issues[&class].fetch_add(1, Ordering::Relaxed);
    }

    fn record(&self, sample: Sample) {
        self.samples.lock().unwrap().push(sample);
    }
}

/// The (p99, max) of one RTT sample set, in microseconds.
fn pick_p99(samples: &[u64]) -> (u64, u64) {
    if samples.is_empty() {
        return (0, 0);
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let max = sorted[sorted.len() - 1];
    let index = ((sorted.len() as f64) * 0.99)
        .floor()
        .min((sorted.len() - 1) as f64) as usize;
    (sorted[index], max)
}

// memory—v1: Cross-platform process RSS through the dependency the composition
// already uses for headroom; the resident set of the test process is the
// serving composition's set. No sensitive data is read or reported.
fn process_rss_bytes() -> Option<u64> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
    let pid = sysinfo::get_current_pid().ok()?;
    let mut process = System::new();
    process.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        false,
        ProcessRefreshKind::nothing().with_memory(),
    );
    process.process(pid).map(|process| process.memory())
}

/// The fail-closed refusal reason a response carries, or a marker for an
/// unexpected body shape.
fn refusal_reason(body: &Value) -> String {
    body["reasonCode"]
        .as_str()
        .or_else(|| body["decision"].as_str())
        .unwrap_or("UNCLASSIFIED")
        .to_owned()
}

/// A stable per-run prefix for operation ids.
fn run_prefix() -> String {
    format!("{}-{}", OPERATION_PREFIX, uuid::Uuid::new_v4().simple())
}

/// Login one fresh session token and record the request in the session lane.
async fn session_login(
    addr: std::net::SocketAddr,
    book: &Book,
    window: usize,
    identifier: &str,
    password: &str,
    card: [u8; 16],
) -> String {
    book.issue(OpClass::Session);
    let began = Instant::now();
    let token = login(addr, identifier, password, card).await;
    book.record(Sample {
        window,
        class: OpClass::Session,
        matched: true,
        pending: false,
        status: 200,
        reason: "login".to_owned(),
        rtt_us: began.elapsed().as_micros() as u64,
    });
    token
}

/// Logout one live token and record the request in the session lane.
async fn session_logout(addr: std::net::SocketAddr, book: &Book, window: usize, token: &str) {
    book.issue(OpClass::Session);
    let began = Instant::now();
    let reply = http(addr, "POST", LOGOUT, Some(token), None, &[]).await;
    book.record(Sample {
        window,
        class: OpClass::Session,
        matched: reply.status == 200 && reply.body["success"] == json!(true),
        pending: false,
        status: reply.status,
        reason: refusal_reason(&reply.body),
        rtt_us: began.elapsed().as_micros() as u64,
    });
}

/// The window an op finished in, derived from the shared run start so every
/// worker and the monitor agree without extra coordination.
fn window_of(start: Instant, window: Duration, windows: usize) -> usize {
    ((start.elapsed().as_secs_f64() / window.as_secs_f64()) as usize).min(windows - 1)
}

/// Run one bounded soak: start the reused synthetic service, drive the fixed
/// mixed offered load for the configured duration, drain cleanly, reopen the
/// retained journal and verify finite bounded growth, then remove the
/// run-scoped directories.
async fn run_soak(config: SoakConfig) {
    let run = run_prefix();
    let book = Arc::new(Book::new());
    let windows = config.windows;

    let rows = super::synthetic_scenarios::paper_warm_rows();
    let service = SyntheticService::start(rows).await;
    let addr = service.addr;
    // The run clock starts once the service is serving, so worker windows and
    // monitor windows describe the same elapsed time.
    let start = Instant::now();
    let origin = tokio::time::Instant::now();
    let baseline_version = service.root.metadata().unwrap().version;
    // The offered load is a fixed slot count per lane: exactly one request per
    // slot, slots at k * interval for k in 0..slots, so the offered totals are
    // deterministic and no slow request can turn into a catch-up burst.
    let read_slots = config.slots(config.read_interval);
    let session_slots = config.slots(config.session_interval);
    let lane_slots = config.slots(config.lane_interval);

    let mut workers = Vec::new();

    // ── 1. Ordinary read workers: fixed pacing, self-refreshing tokens ─────
    for worker in 0..config.read_workers {
        let book = Arc::clone(&book);
        workers.push(tokio::spawn(async move {
            let (identifier, password, card) = if worker % 2 == 0 {
                ("alice", "alice-secret", CARD_ALLOW)
            } else {
                ("bob", "bob-secret", CARD_BOB)
            };
            let mut token = session_login(addr, &book, 0, identifier, password, card).await;
            let mut refreshed_at = Instant::now();
            for slot in 0..read_slots {
                tokio::time::sleep_until(origin + config.read_interval * slot as u32).await;
                let window = window_of(start, config.window, windows);
                book.issue(OpClass::Read);
                let began = Instant::now();
                let reply = http(addr, "GET", REGISTRY, Some(&token), None, &[]).await;
                let matched = reply.status == 200 && !reply.body["data"].is_null();
                let reason = refusal_reason(&reply.body);
                let pending = reply.status == 503
                    && reply.body["data"].is_null()
                    && reply.body["decision"] == reply.body["reasonCode"]
                    && matches!(
                        reason.as_str(),
                        "AUTHORIZATION_CONTEXT_INVALID" | "AUTHORIZATION_PENDING"
                    );
                book.record(Sample {
                    window,
                    class: OpClass::Read,
                    matched,
                    pending,
                    status: reply.status,
                    reason,
                    rtt_us: began.elapsed().as_micros() as u64,
                });
                if refreshed_at.elapsed() >= TOKEN_REFRESH_INTERVAL {
                    let window = window_of(start, config.window, windows);
                    let fresh =
                        session_login(addr, &book, window, identifier, password, card).await;
                    session_logout(addr, &book, window, &token).await;
                    token = fresh;
                    refreshed_at = Instant::now();
                }
            }
            let window = window_of(start, config.window, windows);
            session_logout(addr, &book, window, &token).await;
        }));
    }

    // ── 2. Session lane: paired login + logout at a fixed interval ─────────
    {
        let book = Arc::clone(&book);
        workers.push(tokio::spawn(async move {
            for slot in 0..session_slots {
                tokio::time::sleep_until(origin + config.session_interval * slot as u32).await;
                let window = window_of(start, config.window, windows);
                let token = session_login(addr, &book, window, "bob", "bob-secret", CARD_BOB).await;
                session_logout(addr, &book, window, &token).await;
            }
        }));
    }

    // ── 3. Denial lane: exactly one journaled fail-closed denial per window ─
    {
        let book = Arc::clone(&book);
        workers.push(tokio::spawn(async move {
            let mut token =
                session_login(addr, &book, 0, "alice", "alice-secret", CARD_UNBOUND).await;
            let mut refreshed_at = Instant::now();
            for slot in 0..lane_slots {
                // The deny lane runs half a slot after the governance lane so
                // the two lanes do not systematically collide at the same
                // instant; the offered rate is unchanged.
                tokio::time::sleep_until(
                    origin + config.lane_interval * slot as u32 + config.lane_interval / 2,
                )
                .await;
                let window = window_of(start, config.window, windows);
                book.issue(OpClass::Deny);
                let began = Instant::now();
                let reply = http(addr, "GET", REGISTRY, Some(&token), None, &[]).await;
                // A deny whose proof races a concurrent mutation cannot prove
                // its authorization-state prefix and fails closed to the
                // retryable 503; that is a defined outcome, not a failure. The
                // accepted pending shapes are exact — no data and one of the
                // two exact reason codes the deny-proof and pending contracts
                // emit (permission_check.rs denial_unavailable_response and
                // the §3.5 retryable pending): AUTHORIZATION_AUDIT_UNAVAILABLE
                // with this lane's decision, or AUTHORIZATION_PENDING. A
                // generic raw 503 never counts as an accepted pending.
                let matched = reply.status == 403
                    && reply.body["decision"] == json!("AUTHORIZATION_CARD_UNBOUND")
                    && reply.body["data"].is_null();
                let pending = reply.status == 503
                    && reply.body["data"].is_null()
                    && (reply.body["reasonCode"] == json!("AUTHORIZATION_AUDIT_UNAVAILABLE")
                        && reply.body["decision"] == json!("AUTHORIZATION_CARD_UNBOUND")
                        || reply.body["reasonCode"] == json!("AUTHORIZATION_PENDING"));
                book.record(Sample {
                    window,
                    class: OpClass::Deny,
                    matched,
                    pending,
                    status: reply.status,
                    reason: refusal_reason(&reply.body),
                    rtt_us: began.elapsed().as_micros() as u64,
                });
                if refreshed_at.elapsed() >= TOKEN_REFRESH_INTERVAL {
                    let window = window_of(start, config.window, windows);
                    let fresh =
                        session_login(addr, &book, window, "alice", "alice-secret", CARD_UNBOUND)
                            .await;
                    session_logout(addr, &book, window, &token).await;
                    token = fresh;
                    refreshed_at = Instant::now();
                }
            }
        }));
    }

    // ── 4. Governance lane: exactly one ordinary publish per window ────────
    {
        let book = Arc::clone(&book);
        let run = run.clone();
        workers.push(tokio::spawn(async move {
            let mut token = session_login(addr, &book, 0, "bob", "bob-secret", CARD_BOB).await;
            let mut refreshed_at = Instant::now();
            let sequence = AtomicU64::new(0);
            for slot in 0..lane_slots {
                tokio::time::sleep_until(origin + config.lane_interval * slot as u32).await;
                let window = window_of(start, config.window, windows);
                // The durable journal caps operation ids at 64 bytes, so the
                // run-scoped prefix plus a sequence number stays short.
                let operation = format!("{}-{}", run, sequence.fetch_add(1, Ordering::Relaxed));
                let card = MemoryId::from_bytes(uuid::Uuid::new_v4().into_bytes()).to_string();
                let body = json!({
                    "user_card_id": card,
                    "user_id": MemoryId::from_bytes(BOB).to_string(),
                    "tenant_id": MemoryId::from_bytes(TENANT).to_string(),
                });
                book.issue(OpClass::Governance);
                let began = Instant::now();
                let reply = http(
                    addr,
                    "POST",
                    GOVERNANCE_USER_CARDS,
                    Some(&token),
                    Some(&body),
                    &[("x-request-id", operation.as_str())],
                )
                .await;
                let matched =
                    reply.status == 200 && reply.body["data"]["operationId"] == json!(operation);
                book.record(Sample {
                    window,
                    class: OpClass::Governance,
                    matched,
                    pending: false,
                    status: reply.status,
                    reason: refusal_reason(&reply.body),
                    rtt_us: began.elapsed().as_micros() as u64,
                });
                if refreshed_at.elapsed() >= TOKEN_REFRESH_INTERVAL {
                    let window = window_of(start, config.window, windows);
                    let fresh =
                        session_login(addr, &book, window, "bob", "bob-secret", CARD_BOB).await;
                    session_logout(addr, &book, window, &token).await;
                    token = fresh;
                    refreshed_at = Instant::now();
                }
            }
            let window = window_of(start, config.window, windows);
            session_logout(addr, &book, window, &token).await;
        }));
    }

    // ── 5. Monitor: one RSS sample per window ──────────────────────────────
    let monitor = {
        let book = Arc::clone(&book);
        let window = config.window;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(window);
            tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
            for index in 0..windows {
                tick.tick().await;
                book.monitor.lock().unwrap().push(MonitorSample {
                    window: index,
                    rss_bytes: process_rss_bytes(),
                });
            }
        })
    };

    // ── 6. Join every lane; a worker panic is a recorded soak failure ──────
    let mut panics = Vec::new();
    for worker in workers {
        if let Err(error) = worker.await {
            panics.push(format!("{error:?}"));
        }
    }
    if let Err(error) = monitor.await {
        panics.push(format!("{error:?}"));
    }

    let publishes = issues_of(&book, OpClass::Governance);

    // ── 7. Report: per-window counters, P99, RSS, then lane totals; the whole
    //    report is printed before any assertion so evidence survives failures.
    //    The lock guards are scoped to the aggregation so none of them is held
    //    across the drain await below.
    let (per_window, totals) = {
        let samples = book.samples.lock().unwrap();
        let mut per_window: BTreeMap<(usize, OpClass), LaneStat> = BTreeMap::new();
        let mut totals: BTreeMap<OpClass, LaneStat> = BTreeMap::new();
        for sample in samples.iter() {
            per_window
                .entry((sample.window, sample.class))
                .or_default()
                .record(sample);
            totals.entry(sample.class).or_default().record(sample);
        }
        (per_window, totals)
    };
    let deny_matched = totals
        .get(&OpClass::Deny)
        .map(|lane| lane.matched)
        .unwrap_or(0);
    let monitor_by_window: BTreeMap<usize, u64> = {
        let monitor = book.monitor.lock().unwrap();
        monitor
            .iter()
            .filter_map(|sample| sample.rss_bytes.map(|bytes| (sample.window, bytes)))
            .collect()
    };

    eprintln!("\n=== memory-v1 soak report: {} ===", config.scenario);
    for ((window, class), group) in per_window.iter() {
        let (p99_us, max_us) = pick_p99(&group.rtts);
        let rss = monitor_by_window
            .get(window)
            .map(|bytes| format!("{} KiB", bytes / 1024))
            .unwrap_or_else(|| "unavailable".to_owned());
        eprintln!(
            "window={} {} issued={} matched={} pending={} p99_us={} max_us={} process_rss={}",
            window,
            class.label(),
            group.completed,
            group.matched,
            group.pending,
            p99_us,
            max_us,
            rss,
        );
    }

    for class in [
        OpClass::Read,
        OpClass::Session,
        OpClass::Deny,
        OpClass::Governance,
    ] {
        let issued = issues_of(&book, class);
        let empty = LaneStat::default();
        let lane = totals.get(&class).unwrap_or(&empty);
        let (p99_us, max_us) = pick_p99(&lane.rtts);
        eprintln!(
            "lane {} issued={} completed={} matched={} pending={} p99_us={} max_us={} pending_reasons={:?} unexpected={:?}",
            class.label(),
            issued,
            lane.completed,
            lane.matched,
            lane.pending,
            p99_us,
            max_us,
            lane.pending_reasons,
            lane.unexpected,
        );
        assert_eq!(
            issued,
            lane.completed,
            "lane {} lost {} offered requests (transport loss or worker panic)",
            class.label(),
            issued.saturating_sub(lane.completed),
        );
        if class == OpClass::Deny {
            // Every deny read must resolve as one of the two defined
            // authorization outcomes: a journaled 403 denial or the retryable
            // fail-closed 503 a concurrent-mutation race produces. The floor
            // keeps a persistently unavailable journal from passing unnoticed
            // while tolerating the proof race this mixed load itself creates.
            assert_eq!(
                issued,
                lane.matched + lane.pending,
                "lane {} recorded {} outcomes outside its defined set: {:?}",
                class.label(),
                lane.unexpected.values().sum::<usize>(),
                lane.unexpected,
            );
            assert!(
                lane.pending * 2 <= issued,
                "lane {} recorded {} fail-closed pendings of {} issued; the journal or deny proof path is persistently unavailable",
                class.label(),
                lane.pending,
                issued,
            );
        } else if class == OpClass::Read {
            assert_eq!(
                issued,
                lane.matched + lane.pending,
                "unexpected read outcomes: {:?}",
                lane.unexpected
            );
            assert!(
                lane.pending * 20 <= issued,
                "more than 5% of baseline reads were unavailable: {:?}",
                lane.pending_reasons
            );
        } else {
            assert_eq!(
                issued,
                lane.matched,
                "lane {} recorded {} unexpected outcomes: {:?}",
                class.label(),
                lane.unexpected.values().sum::<usize>(),
                lane.unexpected,
            );
        }
    }
    assert!(
        panics.is_empty(),
        "soak workers must not panic during the run: {panics:?}"
    );

    // The serving root is still alive here; the version must have advanced by
    // exactly the counted publishes before the drain removes the owner.
    assert_eq!(
        service.root.metadata().unwrap().version,
        baseline_version + publishes,
        "the serving root version must advance by exactly the accepted publishes"
    );

    // ── 8. Clean drain: the reused helper asserts the request budget, the
    //    owner and the listener; then the retained journal is reopened
    //    independently against its checkpoint. ──────────────────────────────
    let dir: JournalDir = service.drain().await;
    let journal_path = dir.0.join(super::super::JOURNAL_FILE_NAME);
    let slot0 = dir
        .0
        .join(format!("{}.ckpt.slot0", super::super::CHECKPOINT_BASE));
    let slot1 = dir
        .0
        .join(format!("{}.ckpt.slot1", super::super::CHECKPOINT_BASE));
    let entries: Vec<String> = std::fs::read_dir(&dir.0)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    let journal_bytes = std::fs::metadata(&journal_path).unwrap().len();
    let slot0_bytes = std::fs::metadata(&slot0).unwrap().len();
    let slot1_bytes = std::fs::metadata(&slot1).unwrap().len();

    let (journal, _durability) = dir.reopen();
    let mutation_sequence = journal.position().mutation_sequence();
    let record_count = journal.record_count();
    let mut mutation_operations = BTreeSet::new();
    let mut deny_records = 0_u64;
    for frame in journal.recovery_records() {
        match frame.kind {
            RecordKind::Mutation => {
                mutation_operations.insert(frame.operation_id.clone());
            }
            RecordKind::Deny => deny_records += 1,
        }
    }
    drop(journal);

    // ── 9. Finite bounded snapshot/journal growth ──────────────────────────
    // The publishes are all matched (asserted above) and a fail-closed pending
    // deny journals nothing, so the journal retains exactly one mutation frame
    // per accepted publish and one deny frame per journaled denial.
    assert_eq!(
        mutation_sequence, publishes,
        "the journal's mutation boundary must equal the accepted publishes"
    );
    assert_eq!(
        record_count,
        publishes + deny_records,
        "the journal must retain exactly one frame per counted outcome"
    );
    assert_eq!(
        mutation_operations.len() as u64,
        publishes,
        "each accepted publish must retain exactly one distinct operation id"
    );
    assert_eq!(
        deny_records, deny_matched,
        "each journaled denial must be one deny lane's matched 403 outcome"
    );
    assert!(
        mutation_operations
            .iter()
            .all(|operation| operation.starts_with(&run)),
        "retained mutation operation ids must carry the run prefix"
    );
    // The checkpoint store derives three controlled siblings from the journal
    // base name (memory_v1_durable_journal/checkpoint.rs): the writer lock and
    // the two fixed-slot sidecar images. Together with the journal file the
    // run's whole durable footprint is exactly these four fixed or counted
    // files.
    let mut expected_entries = vec![
        super::super::JOURNAL_FILE_NAME.to_owned(),
        format!("{}.ckpt.lock", super::super::CHECKPOINT_BASE),
        format!("{}.ckpt.slot0", super::super::CHECKPOINT_BASE),
        format!("{}.ckpt.slot1", super::super::CHECKPOINT_BASE),
    ];
    expected_entries.sort();
    let mut actual_entries = entries.clone();
    actual_entries.sort();
    assert_eq!(
        actual_entries, expected_entries,
        "the journal directory must hold exactly the journal and the checkpoint store's three fixed siblings"
    );
    assert_eq!(
        slot0_bytes, slot1_bytes,
        "both checkpoint slots hold one fixed-size record"
    );
    assert!(
        slot0_bytes > 0 && slot0_bytes <= 1024,
        "the checkpoint sidecar is a fixed two-slot ring, not a growth surface: {slot0_bytes} bytes"
    );
    assert!(
        journal_bytes <= (publishes + deny_records) * MAX_FRAME_BYTES as u64 + 4096,
        "the journal file must stay within its counted frames' bounded size"
    );

    // ── 10. Free the run-scoped directories and print the evidence line ────
    let final_rss = process_rss_bytes();
    dir.remove();
    let total_requests: u64 = book
        .issues
        .values()
        .map(|counter| counter.load(Ordering::Relaxed))
        .sum();
    eprintln!(
        "soak summary: scenario={} windows={} requests={} wall={:?} journal_records={} publishes={} denies_journaled={} denies_pending={} mutation_sequence={} journal_bytes={} slot_bytes={} final_process_rss={}",
        config.scenario,
        windows,
        total_requests,
        config.duration(),
        record_count,
        publishes,
        deny_records,
        issues_of(&book, OpClass::Deny) - deny_records,
        mutation_sequence,
        journal_bytes,
        slot0_bytes,
        final_rss
            .map(|bytes| format!("{} KiB", bytes / 1024))
            .unwrap_or_else(|| "unavailable".to_owned()),
    );
    eprintln!(
        "soak_evidence scenario={} windows={} requests={} journal_records={} clean_drain=true bounded_growth=true",
        config.scenario, windows, total_requests, record_count,
    );
}

fn issues_of(book: &Book, class: OpClass) -> u64 {
    book.issues
        .get(&class)
        .map(|counter| counter.load(Ordering::Relaxed))
        .unwrap_or(0)
}

// memory—v1: The short bounded smoke runs on every bin test invocation; it
// proves the whole soak path end to end inside four one-second windows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn soak_smoke_bounded_mixed_windows_report_and_bounded_growth() {
    let config = SoakConfig {
        scenario: "soak-smoke",
        windows: 4,
        window: Duration::from_secs(1),
        read_workers: 2,
        read_interval: Duration::from_millis(100),
        session_interval: Duration::from_millis(250),
        lane_interval: Duration::from_secs(1),
    };
    run_soak(config).await;
}

// memory—v1: The hour soak is opt-in only, selected by the exact ignored name;
// the default is one hour and `ASTRAL_MEMORY_V1_SOAK_HOURS` (1..=24) chooses a
// longer bounded run. Anything unparsable or out of range fails closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "opt-in one-hour soak: cargo test -p astral-single-node --bin astral-single-node -- --ignored --exact memory_v1_service::lifecycle_tests::soak_tests::soak_one_hour_sustained_mixed_load_bounded_growth --nocapture --test-threads=1"]
async fn soak_one_hour_sustained_mixed_load_bounded_growth() {
    const HOURS: &str = "ASTRAL_MEMORY_V1_SOAK_HOURS";
    let hours = match std::env::var_os(HOURS) {
        None => 1,
        Some(raw) => {
            let raw = raw.to_string_lossy().into_owned();
            let hours: u64 = raw
                .parse()
                .unwrap_or_else(|_| panic!("{HOURS} must be an integer hour count, not {raw:?}"));
            assert!(
                (1..=24).contains(&hours),
                "{HOURS} must be within 1..=24, not {hours}"
            );
            hours
        }
    };
    let config = SoakConfig {
        scenario: "soak-one-hour",
        windows: hours as usize * 360,
        window: Duration::from_secs(10),
        read_workers: 4,
        read_interval: Duration::from_millis(100),
        session_interval: Duration::from_millis(500),
        lane_interval: Duration::from_secs(10),
    };
    run_soak(config).await;
}
