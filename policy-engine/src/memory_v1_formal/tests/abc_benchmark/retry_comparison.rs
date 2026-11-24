//! memory—v1: One logical invocation spans fresh reads, including lock wait and retry delay.

use super::*;
use serde_json::{json, Value};

const EXACT: &str =
    "memory_v1_formal::tests::abc_benchmark::retry_comparison::ordinary_read_retry_comparison";
const CASE_ENV: &str = "ASTRAL_ABC_RETRY_CASE";
const LIMIT: usize = 8;
const BUDGET_NS: u64 = 2_000_000;
const READERS: usize = 8;
const ARMS: [Arm; 4] = [A, F, D, E];
const MODES: [&str; 4] = ["pure", "unrelated", "mixed50", "hot"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    OnTime,
    Late,
    Denied,
    Deadline,
    Exhausted,
}

struct Trial<T> {
    first: MemoryV1Decision,
    last: T,
    attempts: usize,
    elapsed: u64,
    end: End,
}

// Never cancel an in-flight synchronous read or reclassify its actual answer as PENDING.
fn logical<T>(
    mut read: impl FnMut() -> T,
    decide: impl Fn(&T) -> MemoryV1Decision,
    elapsed: impl Fn() -> u64,
    mut pause: impl FnMut(),
) -> Trial<T> {
    let mut first = None;
    for attempts in 1..=LIMIT {
        let last = read();
        let mut t = elapsed();
        let decision = decide(&last);
        let first = *first.get_or_insert(decision);
        let end = match decision {
            Allow if t <= BUDGET_NS => End::OnTime,
            Allow => End::Late,
            Deny => End::Denied,
            Pending if t >= BUDGET_NS => End::Deadline,
            Pending if attempts == LIMIT => End::Exhausted,
            Pending => {
                pause();
                t = elapsed();
                if t < BUDGET_NS {
                    continue;
                }
                End::Deadline
            }
        };
        return Trial {
            first,
            last,
            attempts,
            elapsed: t,
            end,
        };
    }
    unreachable!()
}

fn retry_controls() {
    use std::cell::Cell;
    let run = |script: &[(MemoryV1Decision, u64)], delay| {
        let mut script = script.iter().copied();
        let clock = Cell::new(0_u64);
        let trial = logical(
            || {
                let (d, cost) = script.next().expect("unexpected retry");
                clock.set(clock.get() + cost);
                d
            },
            |d| *d,
            || clock.get(),
            || clock.set(clock.get() + delay),
        );
        assert!(script.next().is_none());
        (trial.end, trial.first, trial.attempts, trial.elapsed)
    };
    assert_eq!(
        run(&[(Pending, 1), (Allow, 3)], 2),
        (End::OnTime, Pending, 2, 6)
    );
    assert_eq!(run(&[(Allow, BUDGET_NS)], 0).0, End::OnTime);
    assert_eq!(
        run(&[(Pending, 1), (Allow, BUDGET_NS)], 0),
        (End::Late, Pending, 2, BUDGET_NS + 1)
    );
    assert_eq!(
        run(&[(Deny, BUDGET_NS + 1)], 0),
        (End::Denied, Deny, 1, BUDGET_NS + 1)
    );
    assert_eq!(
        run(&[(Pending, 1), (Deny, 1)], 1),
        (End::Denied, Pending, 2, 3)
    );
    assert_eq!(run(&[(Pending, BUDGET_NS)], 0).0, End::Deadline);
    assert_eq!(
        run(&[(Pending, 1)], BUDGET_NS),
        (End::Deadline, Pending, 1, BUDGET_NS + 1)
    );
    assert_eq!(
        run(&[(Pending, 1); LIMIT], 0),
        (End::Exhausted, Pending, LIMIT, LIMIT as u64)
    );
}

#[derive(Default)]
struct Population {
    latency: Vec<u64>,
    successful_latency: Vec<u64>,
    on_time_latency: Vec<u64>,
    first: [usize; 3],
    attempts_histogram: [usize; LIMIT],
    on_time: usize,
    late: usize,
    denied: usize,
    late_denied: usize,
    deadline: usize,
    exhausted: usize,
}

impl Population {
    fn record(&mut self, t: Trial<MemoryV1Evaluation>, card: u8) {
        oracle(&t.last, card, 110, t.last.decision);
        if card == 4 {
            assert_ne!(t.last.decision, Deny);
        } else {
            assert_ne!(t.last.decision, Allow);
            if t.last.decision == Deny {
                assert_eq!(t.last.deny_source, Some(MemoryV1DenySource::RuleDenied));
            }
        }
        self.first[match t.first {
            Allow => 0,
            Deny => 1,
            Pending => 2,
        }] += 1;
        self.attempts_histogram[t.attempts - 1] += 1;
        self.latency.push(t.elapsed);
        match t.end {
            End::OnTime => {
                self.on_time += 1;
                self.on_time_latency.push(t.elapsed);
                self.successful_latency.push(t.elapsed);
            }
            End::Late => {
                self.late += 1;
                self.successful_latency.push(t.elapsed);
            }
            End::Denied => {
                self.denied += 1;
                self.late_denied += usize::from(t.elapsed > BUDGET_NS);
            }
            End::Deadline => self.deadline += 1,
            End::Exhausted => self.exhausted += 1,
        }
    }

    fn merge(&mut self, mut other: Self) {
        self.latency.append(&mut other.latency);
        self.successful_latency
            .append(&mut other.successful_latency);
        self.on_time_latency.append(&mut other.on_time_latency);
        for (x, y) in self.first.iter_mut().zip(other.first) {
            *x += y;
        }
        for (x, y) in self
            .attempts_histogram
            .iter_mut()
            .zip(other.attempts_histogram)
        {
            *x += y;
        }
        self.on_time += other.on_time;
        self.late += other.late;
        self.denied += other.denied;
        self.late_denied += other.late_denied;
        self.deadline += other.deadline;
        self.exhausted += other.exhausted;
    }

    fn report(self, expected: usize, eligible: bool, stable: bool) -> Value {
        assert_eq!(self.latency.len(), expected);
        assert_eq!(self.first.iter().sum::<usize>(), expected);
        assert_eq!(self.attempts_histogram.iter().sum::<usize>(), expected);
        assert_eq!(self.successful_latency.len(), self.on_time + self.late);
        assert_eq!(self.on_time_latency.len(), self.on_time);
        assert_eq!(
            self.on_time + self.late + self.denied + self.deadline + self.exhausted,
            expected
        );
        assert_eq!(
            if eligible {
                self.denied + self.first[1]
            } else {
                self.on_time + self.late + self.first[0]
            },
            0
        );
        if stable {
            assert_eq!(self.first[2], 0);
        }
        let attempts: usize = self
            .attempts_histogram
            .iter()
            .enumerate()
            .map(|(i, n)| (i + 1) * n)
            .sum();
        json!({"offered":expected, "first_allow":self.first[0], "first_deny":self.first[1], "first_pending":self.first[2], "attempts":attempts, "attempts_histogram":self.attempts_histogram, "on_time_allow":self.on_time, "late_allow":self.late, "deny":self.denied, "late_deny_subset":self.late_denied, "deadline_no_answer":self.deadline, "exhausted":self.exhausted, "logical_terminal_ns":dist(self.latency), "all_success_ns":dist(self.successful_latency), "on_time_success_ns":dist(self.on_time_latency)})
    }
}

fn cell(b: &Bench, arm: Arm, mode: &str, ops: usize, rep: usize, smoke: bool) -> Value {
    assert!(MODES.contains(&mode) && ops.is_multiple_of(4));
    let writes = if mode == "pure" {
        0
    } else if smoke {
        8
    } else {
        256
    };
    let plan: Vec<_> = (0..writes)
        .map(|i| {
            if mode == "unrelated" || (mode == "mixed50" && i % 2 == 1) {
                publication(13, i, OTHER)
            } else {
                publication(10, i, ALLOW)
            }
        })
        .collect();
    let initial = b.owner.handle().metadata().unwrap();
    let barrier = Barrier::new(READERS + 2);
    let mut positive = Population::default();
    let mut negative = Population::default();
    let (wall_ns, samples, wlat) = std::thread::scope(|s| {
        let readers: Vec<_> = (0..READERS)
            .map(|_| {
                s.spawn(|| {
                    let mut p = Population::default();
                    let mut n = Population::default();
                    let req = request();
                    barrier.wait();
                    for i in 0..ops {
                        let card = if i % 4 == 3 { 7 } else { 4 };
                        let start = Instant::now();
                        let result = logical(
                            || b.read(arm, card, &req, 110, 110, || {}).0,
                            |e| e.decision,
                            || ns(start),
                            std::thread::yield_now,
                        );
                        if card == 4 {
                            p.record(result, card);
                        } else {
                            n.record(result, card);
                        }
                    }
                    (p, n)
                })
            })
            .collect();
        let writer = s.spawn(|| {
            let mut times = Vec::with_capacity(plan.len());
            barrier.wait();
            for m in &plan {
                let start = Instant::now();
                let guard = arm.uses_fixture_gate().then(|| b.gate.write().unwrap());
                b.publish(m);
                drop(guard);
                times.push(ns(start));
            }
            times
        });
        let start = Instant::now();
        barrier.wait();
        let samples = readers
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>();
        let wlat = writer.join().unwrap();
        (ns(start), samples, wlat)
    });
    for (p, n) in samples {
        positive.merge(p);
        negative.merge(n);
    }
    assert_eq!(
        b.owner.handle().metadata().unwrap().version,
        initial.version + u64::from(writes)
    );
    let eligible = READERS * ops / 4 * 3;
    let rate = positive.on_time as f64 * 1e9 / wall_ns as f64;
    let stable = mode == "pure" || matches!(arm, A | F);
    let related = match mode {
        "pure" | "unrelated" => 0,
        "mixed50" => writes / 2,
        "hot" => writes,
        _ => unreachable!(),
    };
    json!({"arm":format!("{arm:?}"), "load":mode,"rep":rep,"smoke":smoke,"readers":READERS,"ops_per_reader":ops,"offered":READERS*ops,"related_writes":related,"unrelated_writes":writes-related,"max_attempts":LIMIT,"budget_ns":BUDGET_NS,"backoff":"yield_now","wall_ns":wall_ns,"on_time_admissions_per_s":rate,"writer_latency_ns":dist(wlat),"eligible":positive.report(eligible,true,stable),"ineligible":negative.report(READERS*ops-eligible,false,stable)})
}

#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "release benchmark in isolated child roots"
)]
fn ordinary_read_retry_comparison() {
    let smoke = cfg!(debug_assertions) || std::env::var_os("ASTRAL_ABC_RETRY_SMOKE").is_some();
    let ops = if smoke { 64 } else { 4096 };
    let reps = if smoke { 1 } else { ARMS.len() };
    if let Ok(case) = std::env::var(CASE_ENV) {
        let parts: Vec<_> = case.split(':').collect();
        assert_eq!(parts.len(), 3);
        let arm = *ARMS.iter().find(|a| format!("{a:?}") == parts[0]).unwrap();
        let b = Bench::new();
        if parts[1] == "control" {
            controls(&b, arm);
        } else {
            println!(
                "RETRY_RESULT {}",
                cell(&b, arm, parts[1], ops, parts[2].parse().unwrap(), smoke)
            );
        }
        return;
    }
    retry_controls();
    let mut cells = 0;
    for rep in 0..reps {
        for mode in std::iter::once("control").filter(|_| rep == 0).chain(MODES) {
            for index in 0..ARMS.len() {
                let arm = ARMS[(rep + index) % ARMS.len()];
                let case = format!("{arm:?}:{mode}:{rep}");
                let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
                cmd.args(["--exact", EXACT, "--test-threads=1", "--nocapture"]);
                if !cfg!(debug_assertions) {
                    cmd.arg("--ignored");
                }
                let out = cmd.env(CASE_ENV, &case).output().unwrap();
                let stdout = String::from_utf8(out.stdout).unwrap();
                print!("{stdout}");
                eprint!("{}", String::from_utf8_lossy(&out.stderr));
                assert!(
                    out.status.success() && stdout.contains("1 passed; 0 failed; 0 ignored"),
                    "{case}: {:?}",
                    out.status
                );
                // libtest can prefix the first uncaptured line with the test name.
                let rows: Vec<Value> = stdout
                    .lines()
                    .filter_map(|line| line.split_once("RETRY_RESULT "))
                    .map(|(_, data)| serde_json::from_str(data).unwrap())
                    .collect();
                assert_eq!(rows.len(), usize::from(mode != "control"));
                if let Some(row) = rows.first() {
                    assert_eq!(row["arm"], format!("{arm:?}"));
                    assert_eq!(row["rep"], rep);
                    assert_eq!(row["load"], mode);
                    assert_eq!(row["offered"], READERS * ops);
                    cells += 1;
                }
            }
        }
    }
    assert_eq!(cells, reps * ARMS.len() * MODES.len());
    println!(
        "RETRY_COMPLETE cells={cells} control_children={} retry_controls=8 smoke={smoke}",
        ARMS.len()
    );
}
