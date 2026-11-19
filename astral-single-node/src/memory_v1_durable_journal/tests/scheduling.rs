use super::{anchor, id, owner, request, TestDir};
use crate::memory_v1_durable_journal::{
    DurableJournalError, DurableJournalLimits, IoOperation, JournalDurability,
    LocalDurablePrefixReceipt, MemoryV1DurableJournal, PreparedAppend, SyncTestEvent,
};
use astral_trustgraph::service::memory_v1_mutation_coordinator::{
    DenyJournalRequest, JournalIdentity,
};
use astral_types::memory_v1::CandidateIdentity;
use astral_types::memory_v1_audit::{MemoryV1AuditDenySource, MemoryV1AuditRootStatus};
use astral_types::memory_v1_deny_observation::{
    MemoryV1DenyAffectedBindingState, MemoryV1DenyObservation, MemoryV1DenyRootObservation,
};
use std::fs;
use std::io;
use std::sync::{mpsc, Arc, Barrier, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(5);
type Receipt = Result<LocalDurablePrefixReceipt, DurableJournalError>;

struct ControlledFlush {
    durability: Arc<JournalDurability>,
    events: mpsc::Receiver<SyncTestEvent>,
}

impl ControlledFlush {
    // memory—v1: Stop each leader at its captured target before real sync_data.
    fn new(mut durability: JournalDurability) -> Self {
        let (events, receiver) = mpsc::channel();
        durability.sync_events = Some(events);
        Self {
            durability: Arc::new(durability),
            events: receiver,
        }
    }

    // memory—v1: Await actual coordinator registration, not thread startup.
    fn waiting(&self, end: u64) {
        assert!(matches!(
            self.events.recv_timeout(TIMEOUT).unwrap(),
            SyncTestEvent::Waiting(offset) if offset == end
        ));
    }

    // memory—v1: Expect one leader with this exact pre-sync prefix.
    fn flushing(&self, end: u64) -> mpsc::Sender<Result<(), DurableJournalError>> {
        match self.events.recv_timeout(TIMEOUT).unwrap() {
            SyncTestEvent::Flushing { target, resume } if target == end => resume,
            _ => panic!("expected flush through {end}"),
        }
    }

    // memory—v1: A blocked receipt times out before any join can hang the test.
    fn receipt(&self, append: PreparedAppend) -> (mpsc::Receiver<Receipt>, JoinHandle<()>) {
        let durability = Arc::clone(&self.durability);
        let (done, outcome) = mpsc::channel();
        let worker = thread::spawn(move || {
            let _ = done.send(append.into_durable_receipt(&durability));
        });
        (outcome, worker)
    }
}

impl Drop for ControlledFlush {
    // memory—v1: Release a stranded waiter if a regression trips a timeout.
    fn drop(&mut self) {
        if thread::panicking() {
            let mut state = self
                .durability
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            state.failed = true;
            for waiter in state.waiters.values() {
                waiter.notify_all();
            }
        }
    }
}

// memory—v1: Read the receipt before joining; no unbounded join on waiters.
fn receive(worker: (mpsc::Receiver<Receipt>, JoinHandle<()>)) -> Receipt {
    let (outcome, handle) = worker;
    let receipt = outcome.recv_timeout(TIMEOUT).expect("receipt timed out");
    handle.join().unwrap();
    receipt
}

// memory—v1: Exercise the DENY ingress with a valid bound observation.
fn deny_request(journal_sequence: u64, mutation_sequence: u64) -> DenyJournalRequest {
    let root = MemoryV1DenyRootObservation::try_from_usize(
        id(1),
        7,
        [7; 32],
        MemoryV1AuditRootStatus::Serving,
        32,
        4,
        9,
    )
    .unwrap();
    let observation = MemoryV1DenyObservation::new(
        root,
        CandidateIdentity {
            user_id: id(2),
            identity_card_id: id(3),
            user_card_id: id(4),
            tenant_id: id(5),
        },
        42,
        "permission_rule",
        "read",
        None,
        None,
        None,
        MemoryV1DenyAffectedBindingState::inapplicable(),
        b"deny-operation".to_vec(),
        [8; 32].to_vec(),
        MemoryV1AuditDenySource::NoMatch,
        None,
    )
    .unwrap();
    let identity =
        JournalIdentity::new_deny(id(10), id(11), journal_sequence, mutation_sequence, id(12))
            .unwrap();
    DenyJournalRequest::try_new(observation, identity).unwrap()
}

// memory—v1: Only a successful covering flush may release receipts. A later
// waiter must lead the next flush even when no new ensure_durable call arrives.
#[test]
fn covered_waiters_complete_and_uncovered_backlog_relays() {
    let directory = TestDir::new();
    let (mut journal, durability) = owner(&directory);
    let control = ControlledFlush::new(durability);
    let durability = &control.durability;
    let first_request = request("first", 1);
    let first = journal
        .prepare_mutation(&first_request, durability)
        .unwrap();
    let first_end = first.durable_end;
    let leader = control.receipt(first);
    let release_first = control.flushing(first_end);
    let replay = journal
        .prepare_mutation(&first_request, durability)
        .unwrap();
    let covered = control.receipt(replay);
    control.waiting(first_end);

    let second = journal
        .prepare_mutation(&request("second", 2), durability)
        .unwrap();
    let second_end = second.durable_end;
    let later = control.receipt(second);
    control.waiting(second_end);
    let deny = deny_request(3, 2);
    let third = journal.prepare_deny(&deny, durability).unwrap();
    let third_end = third.durable_end;
    let third_tail = third.tail_hash;
    let backlog = control.receipt(third);
    control.waiting(third_end);
    assert!(matches!(
        covered.0.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    assert!(matches!(later.0.try_recv(), Err(mpsc::TryRecvError::Empty)));

    release_first.send(Ok(())).unwrap();
    let release_backlog = control.flushing(third_end);
    assert_eq!(receive(leader).unwrap().end_offset(), first_end);
    assert_eq!(receive(covered).unwrap().end_offset(), first_end);
    assert!(matches!(later.0.try_recv(), Err(mpsc::TryRecvError::Empty)));
    assert!(matches!(
        backlog.0.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));

    release_backlog.send(Ok(())).unwrap();
    assert_eq!(receive(later).unwrap().end_offset(), second_end);
    let receipt = receive(backlog).unwrap();
    assert_eq!(receipt.end_offset(), third_end);
    assert_eq!(receipt.identity(), deny.journal());
    assert_eq!(receipt.audit_digest(), deny.audit_digest());
    assert_eq!(*receipt.tail_hash(), third_tail);
    assert_eq!(durability.sync_calls(), 2);
    assert!(durability.state.lock().unwrap().waiters.is_empty());
}

// memory—v1: Failure wakes both classes, leaves the old watermark untouched,
// and fences both kinds of prepare (including replays) and all receipts.
#[test]
fn flush_failure_wakes_waiters_and_fences_prepares() {
    let directory = TestDir::new();
    let (mut journal, durability) = owner(&directory);
    let control = ControlledFlush::new(durability);
    let durability = &control.durability;
    let first = journal
        .prepare_mutation(&request("first", 1), durability)
        .unwrap();
    let first_end = first.durable_end;
    let already_durable = first.clone();
    let worker = control.receipt(first);
    control.flushing(first_end).send(Ok(())).unwrap();
    receive(worker).unwrap();

    let second_request = request("second", 2);
    let second = journal
        .prepare_mutation(&second_request, durability)
        .unwrap();
    let second_end = second.durable_end;
    let leader = control.receipt(second.clone());
    let release = control.flushing(second_end);
    let covered = control.receipt(second);
    control.waiting(second_end);
    let deny = deny_request(3, 2);
    let later = journal.prepare_deny(&deny, durability).unwrap();
    let end = later.durable_end;
    let uncovered = control.receipt(later);
    control.waiting(end);

    release
        .send(Err(DurableJournalError::Io {
            operation: IoOperation::SyncFile,
            kind: io::ErrorKind::Other,
        }))
        .unwrap();
    for worker in [leader, covered, uncovered] {
        assert_eq!(receive(worker), Err(DurableJournalError::StickyUnknown));
    }
    assert_eq!(
        already_durable.into_durable_receipt(durability),
        Err(DurableJournalError::StickyUnknown)
    );
    assert!(matches!(
        journal.prepare_mutation(&second_request, durability),
        Err(DurableJournalError::StickyUnknown)
    ));
    assert!(matches!(
        journal.prepare_deny(&deny, durability),
        Err(DurableJournalError::StickyUnknown)
    ));
    assert_eq!(journal.file_position(), end);
    assert_eq!(fs::metadata(directory.path()).unwrap().len(), end);
    let state = durability.state.lock().unwrap();
    assert_eq!(state.durable_end, first_end);
    assert!(!state.in_flight);
    assert!(state.waiters.is_empty());
    assert_eq!(durability.sync_calls(), 2);
}

// memory—v1: A successful sync alone cannot prove a truncated prefix.
#[test]
fn successful_sync_below_length_floor_is_sticky_unknown() {
    let directory = TestDir::new();
    let (mut journal, durability) = owner(&directory);
    let prepared = journal
        .prepare_mutation(&request("first", 1), &durability)
        .unwrap();
    journal.file.set_len(prepared.durable_end - 1).unwrap();
    assert_eq!(
        prepared.into_durable_receipt(&durability),
        Err(DurableJournalError::StickyUnknown)
    );
    assert!(matches!(
        journal.prepare_mutation(&request("second", 2), &durability),
        Err(DurableJournalError::StickyUnknown)
    ));
    assert_eq!(durability.state.lock().unwrap().durable_end, 0);
    assert_eq!(durability.sync_calls(), 1);
}

// memory—v1: Idle flushes directly; covered and unregistered offsets do not sync.
#[test]
fn direct_flush_only_synchronizes_registered_uncovered_offsets() {
    let directory = TestDir::new();
    let (mut journal, durability) = owner(&directory);
    let prepared = journal
        .prepare_mutation(&request("first", 1), &durability)
        .unwrap();
    let end = prepared.durable_end;
    assert_eq!(
        durability.ensure_durable(end + 1),
        Err(DurableJournalError::InvalidRecord)
    );
    assert_eq!(durability.sync_calls(), 0);
    assert_eq!(
        prepared
            .into_durable_receipt(&durability)
            .unwrap()
            .end_offset(),
        end
    );
    assert_eq!(durability.ensure_durable(end), Ok(()));
    assert_eq!(durability.sync_calls(), 1);
    assert!(durability.state.lock().unwrap().waiters.is_empty());
}

// memory—v1: Opt-in real-file curve. Workers release the writer lease before
// waiting for a receipt to isolate journal concurrency from governance callers.
#[test]
#[ignore = "opt-in local release journal load curve"]
fn local_release_journal_curve() {
    const OPERATIONS: u64 = 1024;
    for workers in [1, 2, 4, 8, 16, 32] {
        for sample in 1..=3 {
            let directory = TestDir::new();
            let (journal, durability) = MemoryV1DurableJournal::create(
                &directory.path(),
                id(10),
                id(11),
                anchor(),
                DurableJournalLimits::new(OPERATIONS, 16 * 1024 * 1024, 1024 * 1024).unwrap(),
            )
            .unwrap();
            let journal = Arc::new(Mutex::new(journal));
            let durability = Arc::new(durability);
            let start = Arc::new(Barrier::new(workers + 1));
            let (done, outcomes) = mpsc::channel();
            let handles: Vec<_> = (0..workers)
                .map(|_| {
                    let (journal, durability, start, done) = (
                        Arc::clone(&journal),
                        Arc::clone(&durability),
                        Arc::clone(&start),
                        done.clone(),
                    );
                    thread::spawn(move || {
                        start.wait();
                        let mut latencies = Vec::new();
                        for _ in 0..OPERATIONS / workers as u64 {
                            let entered = Instant::now();
                            let prepared = {
                                let mut journal = journal.lock().unwrap();
                                let sequence = journal.position().journal_sequence() + 1;
                                let request = request(&format!("curve-{sequence}"), sequence);
                                journal.prepare_mutation(&request, &durability).unwrap()
                            };
                            let end = prepared.durable_end;
                            assert_eq!(
                                prepared
                                    .into_durable_receipt(&durability)
                                    .unwrap()
                                    .end_offset(),
                                end
                            );
                            latencies.push(entered.elapsed());
                        }
                        done.send(latencies).unwrap();
                    })
                })
                .collect();
            drop(done);
            let started = Instant::now();
            let deadline = started + TIMEOUT;
            start.wait();
            let mut latencies = Vec::new();
            for _ in 0..workers {
                latencies.extend(
                    outcomes
                        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                        .expect("curve worker timed out"),
                );
            }
            let elapsed = started.elapsed();
            for handle in handles {
                handle.join().unwrap();
            }
            let journal = journal.lock().unwrap();
            let state = durability.state.lock().unwrap();
            assert_eq!(journal.record_count(), OPERATIONS);
            assert_eq!(state.durable_end, journal.file_position());
            let syncs = durability.sync_calls();
            assert!((1..=OPERATIONS).contains(&syncs));
            if workers == 1 {
                assert_eq!(syncs, OPERATIONS);
            }
            latencies.sort_unstable();
            let us = |percent: usize| {
                latencies[(latencies.len() * percent).div_ceil(100) - 1].as_secs_f64() * 1e6
            };
            println!("workers={workers:>2} sample={sample} ops={OPERATIONS} syncs={syncs:>4} ops/s={:.0} p50/p95/p99={:.1}/{:.1}/{:.1}us", OPERATIONS as f64 / elapsed.as_secs_f64(), us(50), us(95), us(99));
        }
    }
}
