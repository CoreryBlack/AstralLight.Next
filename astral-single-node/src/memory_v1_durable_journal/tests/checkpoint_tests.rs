//! memory—v1: checkpoint sidecar and per-group persistence tests. The cases
//! cover the real startup and recovery paths: ordinary reopen across
//! consecutive generations, clean cut, wrong install, tail longer, missing
//! checkpoint, unclear newest slot, and unknown sync. Fixtures build genesis
//! explicitly through the bootstrap/attach interfaces; nothing in these tests
//! auto-creates or repairs a store.

use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use astral_trustgraph::service::memory_v1_mutation_coordinator::{
    decode_deny_journal_payload_with_origin, decode_journal_payload, DenyJournalRequest,
    JournalIdentity,
};
use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use astral_types::memory_v1_audit::{MemoryV1AuditDenySource, MemoryV1AuditRootStatus};
use astral_types::memory_v1_deny_observation::{
    MemoryV1DenyAffectedBindingState, MemoryV1DenyObservation, MemoryV1DenyRootObservation,
};
use astral_types::memory_v1_journal::{
    decode_record, encode_record, JournalAnchor, JournalError, JournalRecord, RecordKind,
};

use super::super::payload_digest;
use super::{anchor, id, limits, owner, request, TestDir};
use crate::memory_v1_durable_journal::{
    CheckpointError, CheckpointInstallId, CheckpointOpenStatus, CheckpointScanOutcome,
    DurableJournalError, DurableJournalState, IoOperation, JournalDurability,
    LocalCheckpointCoverage, LocalCheckpointStore, LocalDurablePrefixReceipt,
    MemoryV1DurableJournal, PreparedAppend, SyncTestEvent,
};

const TIMEOUT: Duration = Duration::from_secs(5);
type Receipt = Result<LocalDurablePrefixReceipt, DurableJournalError>;

// memory—v1: The shared install identity every fixture uses.
fn install() -> CheckpointInstallId {
    CheckpointInstallId::from_install_uuid([9; 16]).unwrap()
}

// memory—v1: A different installation must never adopt the same sidecar.
fn foreign_install() -> CheckpointInstallId {
    CheckpointInstallId::from_install_uuid([7; 16]).unwrap()
}

fn base(directory: &TestDir) -> PathBuf {
    directory.0.join("journal.ckpt")
}

fn journal_file_length(directory: &TestDir) -> u64 {
    fs::metadata(directory.path()).unwrap().len()
}

// memory—v1: Bootstrap the genesis sidecar: generation 1 covers the external
// baseline anchor at offset 0 and lives in slot 1.
fn bootstrap_genesis(directory: &TestDir) -> (LocalCheckpointStore, u64) {
    let coverage = LocalCheckpointCoverage::from_anchor(anchor(), 0);
    let (store, record) = LocalCheckpointStore::bootstrap(
        &base(directory),
        install(),
        id(10),
        id(11),
        anchor(),
        coverage,
        limits(),
    )
    .unwrap();
    assert_eq!(record.generation(), 1);
    (store, record.generation())
}

// memory—v1: Attach an explicitly opened sidecar to an open journal.
fn attach(
    journal: &MemoryV1DurableJournal,
    durability: &JournalDurability,
    store: LocalCheckpointStore,
) -> u64 {
    journal
        .attach_checkpoint(durability, store)
        .unwrap()
        .latest
        .generation()
}

fn open_sidecar(
    directory: &TestDir,
) -> Result<
    (
        LocalCheckpointStore,
        crate::memory_v1_durable_journal::LocalCheckpointRecord,
        CheckpointOpenStatus,
    ),
    CheckpointError,
> {
    LocalCheckpointStore::open(
        &base(directory),
        install(),
        id(10),
        id(11),
        anchor(),
        limits(),
    )
}

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

    // memory—v1: Expect one leader with this exact pre-sync prefix.
    fn flushing(&self, end: u64) -> mpsc::Sender<Result<(), DurableJournalError>> {
        match self.events.recv_timeout(TIMEOUT).unwrap() {
            SyncTestEvent::Flushing { target, resume } if target == end => resume,
            SyncTestEvent::Flushing { .. } => panic!("unexpected flush target"),
            SyncTestEvent::Waiting(_) => panic!("expected a flush, saw a waiter registration"),
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
    DenyJournalRequest::try_new(
        observation,
        JournalIdentity::new_deny(id(10), id(11), journal_sequence, mutation_sequence, id(12))
            .unwrap(),
    )
    .unwrap()
}

// memory—v1: Bootstrap refuses any existing sidecar file, and open refuses a
// foreign installation, stream, epoch, or baseline.
#[test]
fn bootstrap_binding_and_refusals() {
    let directory = TestDir::new();
    bootstrap_genesis(&directory);
    let coverage = LocalCheckpointCoverage::from_anchor(anchor(), 0);
    assert_eq!(
        LocalCheckpointStore::bootstrap(
            &base(&directory),
            install(),
            id(10),
            id(11),
            anchor(),
            coverage,
            limits()
        )
        .unwrap_err(),
        CheckpointError::TargetExists
    );

    assert_eq!(
        LocalCheckpointStore::open(
            &base(&directory),
            foreign_install(),
            id(10),
            id(11),
            anchor(),
            limits()
        )
        .unwrap_err(),
        CheckpointError::InstallMismatch
    );

    for (stream, epoch, baseline) in [
        (id(12), id(11), anchor()),
        (id(10), id(12), anchor()),
        (
            id(10),
            id(11),
            JournalAnchor::new(id(10), 0, 0, [6; 32]).unwrap(),
        ),
    ] {
        assert_eq!(
            LocalCheckpointStore::open(
                &base(&directory),
                install(),
                stream,
                epoch,
                baseline,
                limits()
            )
            .unwrap_err(),
            CheckpointError::BindingMismatch
        );
    }
}

// memory—v1: A missing sidecar is refused and a legacy journal requires the
// explicit bootstrap against its verified tail before serving.
#[test]
fn missing_sidecar_requires_explicit_bootstrap_then_serves() {
    let directory = TestDir::new();
    assert_eq!(
        LocalCheckpointStore::open(
            &base(&directory),
            install(),
            id(10),
            id(11),
            anchor(),
            limits()
        )
        .unwrap_err(),
        CheckpointError::MissingCheckpoint
    );

    let (mut journal, durability) = owner(&directory);
    // Give the legacy journal one durable record so the ordinary open path
    // applies (an empty journal is the genesis case, covered separately).
    let prepared = journal
        .prepare_mutation(&request("legacy-1", 1), &durability)
        .unwrap();
    prepared.into_durable_receipt(&durability).unwrap();
    let tail = journal.position();
    let offset = journal.file_position();
    drop(journal);
    drop(durability);

    // Ordinary startup without a sidecar refuses; the legacy journal is
    // bootstrapped explicitly against its verified tail.
    assert!(matches!(
        MemoryV1DurableJournal::open_checkpointed(
            &directory.path(),
            &base(&directory),
            install(),
            id(10),
            id(11),
            anchor(),
            limits()
        ),
        Err(DurableJournalError::CheckpointOwner(
            CheckpointError::MissingCheckpoint
        ))
    ));

    let (mut journal, durability) =
        MemoryV1DurableJournal::open(&directory.path(), id(10), id(11), anchor(), tail, limits())
            .unwrap();
    let coverage = LocalCheckpointCoverage::from_anchor(tail, offset);
    let (store, _) = LocalCheckpointStore::bootstrap(
        &base(&directory),
        install(),
        id(10),
        id(11),
        anchor(),
        coverage,
        limits(),
    )
    .unwrap();
    assert_eq!(attach(&journal, &durability, store), 1);
    let first = journal
        .prepare_mutation(&request("operation-1", 2), &durability)
        .unwrap();
    let receipt = first.into_durable_receipt(&durability).unwrap();
    assert_eq!(receipt.end_offset(), journal.file_position());
    let latest = durability.checkpoint_latest().unwrap();
    assert_eq!(latest.generation(), 2);
    assert_eq!(latest.journal_offset(), journal.file_position());
    assert_eq!(latest.journal_sequence(), 2);
}

// memory—v1: Ordinary reopen across consecutive generations 1 to 4. Each
// startup round goes through open_checkpointed, the parity slots alternate,
// and the chain stays linked.
#[test]
fn reopen_across_generations_one_to_four() {
    let directory = TestDir::new();
    // Genesis: an empty journal file plus the bootstrap generation 1.
    {
        let (journal, durability) = owner(&directory);
        let (store, _) = bootstrap_genesis(&directory);
        attach(&journal, &durability, store);
    }

    for round in 0..4_u64 {
        let (mut journal, durability) = MemoryV1DurableJournal::open_checkpointed(
            &directory.path(),
            &base(&directory),
            install(),
            id(10),
            id(11),
            anchor(),
            limits(),
        )
        .unwrap();
        // The sidecar record the startup adopted: generation round+1 covering
        // exactly the journal's verified tail.
        let adopted = durability.checkpoint_latest().unwrap();
        assert_eq!(adopted.generation(), round + 1);
        assert_eq!(adopted.journal_offset(), journal.file_position());

        let sequence = round + 1;
        let prepared = journal
            .prepare_mutation(&request(&format!("gen-{sequence}"), sequence), &durability)
            .unwrap();
        prepared.into_durable_receipt(&durability).unwrap();
        drop(journal);
        drop(durability);

        let (_, record, status) = open_sidecar(&directory).unwrap();
        assert_eq!(status, CheckpointOpenStatus::Complete);
        assert_eq!(record.generation(), round + 2);
        assert_eq!(record.journal_offset(), journal_file_length(&directory));
        assert_eq!(record.journal_sequence(), sequence);
    }

    // Final reopen: generation 5 is the newest record, chain-linked, covering
    // the whole on-disk journal.
    let (_, record, status) = open_sidecar(&directory).unwrap();
    assert_eq!(status, CheckpointOpenStatus::Complete);
    assert_eq!(record.generation(), 5);
}

// memory—v1: One checkpoint per flushed group, monotonic generations, DENY
// groups included, and the receipt only after its group's record.
#[test]
fn group_commit_persists_one_checkpoint_per_flush() {
    let directory = TestDir::new();
    let (mut journal, durability) = owner(&directory);
    let (store, _) = bootstrap_genesis(&directory);
    assert_eq!(attach(&journal, &durability, store), 1);
    let control = ControlledFlush::new(durability);
    let durability = &control.durability;

    let first = journal
        .prepare_mutation(&request("first", 1), durability)
        .unwrap();
    let first_end = first.durable_end;
    let leader = control.receipt(first);
    control.flushing(first_end).send(Ok(())).unwrap();
    let receipt = receive(leader).unwrap();
    assert_eq!(receipt.end_offset(), first_end);
    let latest = durability.checkpoint_latest().unwrap();
    assert_eq!(latest.generation(), 2);
    assert_eq!(latest.journal_offset(), first_end);
    assert_eq!(latest.journal_sequence(), 1);

    let deny = deny_request(2, 1);
    let prepared = journal.prepare_deny(&deny, durability).unwrap();
    let deny_end = prepared.durable_end;
    let worker = control.receipt(prepared);
    control.flushing(deny_end).send(Ok(())).unwrap();
    let receipt = receive(worker).unwrap();
    assert_eq!(receipt.end_offset(), deny_end);
    let latest = durability.checkpoint_latest().unwrap();
    assert_eq!(latest.generation(), 3);
    assert_eq!(latest.journal_offset(), deny_end);
    // A DENY does not advance the mutation sequence.
    assert_eq!(latest.mutation_sequence(), 1);
    drop(control);
    drop(journal);

    let (store, record, status) = open_sidecar(&directory).unwrap();
    assert_eq!(status, CheckpointOpenStatus::Complete);
    assert_eq!(record.generation(), 3);
    assert_eq!(record.journal_offset(), journal_file_length(&directory));
    assert_eq!(record.mutation_sequence(), 1);
    drop(store);
}

// memory—v1: A failed journal flush wakes waiters, fences prepares, and never
// records a checkpoint for the failed group.
#[test]
fn flush_failure_skips_checkpoint_and_fences() {
    let directory = TestDir::new();
    let (mut journal, durability) = owner(&directory);
    let (store, _) = bootstrap_genesis(&directory);
    assert_eq!(attach(&journal, &durability, store), 1);
    let control = ControlledFlush::new(durability);
    let durability = &control.durability;

    let prepared = journal
        .prepare_mutation(&request("first", 1), durability)
        .unwrap();
    let end = prepared.durable_end;
    let worker = control.receipt(prepared);
    control
        .flushing(end)
        .send(Err(DurableJournalError::Io {
            operation: IoOperation::SyncFile,
            kind: io::ErrorKind::Other,
        }))
        .unwrap();
    assert_eq!(receive(worker), Err(DurableJournalError::StickyUnknown));
    assert_eq!(durability.checkpoint_latest().unwrap().generation(), 1);
    assert!(matches!(
        journal.prepare_mutation(&request("second", 2), durability),
        Err(DurableJournalError::StickyUnknown)
    ));
}

// memory—v1: A checkpoint failure after a successful flush refuses the
// receipt and stays fenced even after the injection is removed.
#[test]
fn checkpoint_failure_after_successful_flush_is_sticky_unknown() {
    let directory = TestDir::new();
    let (mut journal, durability) = owner(&directory);
    let (store, _) = bootstrap_genesis(&directory);
    assert_eq!(attach(&journal, &durability, store), 1);
    let control = ControlledFlush::new(durability);
    let durability = &control.durability;
    durability
        .inject_checkpoint_failure
        .store(true, Ordering::SeqCst);

    let prepared = journal
        .prepare_mutation(&request("first", 1), durability)
        .unwrap();
    let end = prepared.durable_end;
    let worker = control.receipt(prepared);
    control.flushing(end).send(Ok(())).unwrap();
    assert_eq!(receive(worker), Err(DurableJournalError::StickyUnknown));
    assert_eq!(durability.checkpoint_latest().unwrap().generation(), 1);
    durability
        .inject_checkpoint_failure
        .store(false, Ordering::SeqCst);
    assert!(matches!(
        journal.prepare_mutation(&request("second", 2), durability),
        Err(DurableJournalError::StickyUnknown)
    ));
}

// memory—v1: Tail longer — flushed groups the sidecar never recorded are
// refused at ordinary startup and by attach; the single-scan verifier reports
// facts without adoption; explicit out-of-band repair re-bootstraps against
// the verified tail.
#[test]
fn tail_longer_is_refused_until_explicit_rebootstrap() {
    let directory = TestDir::new();
    {
        let (mut journal, durability) = owner(&directory);
        let (store, _) = bootstrap_genesis(&directory);
        assert_eq!(attach(&journal, &durability, store), 1);
        // Write frames without any flush: no group checkpoint exists for them.
        let _ = journal
            .prepare_mutation(&request("first", 1), &durability)
            .unwrap();
        let _ = journal
            .prepare_mutation(&request("second", 2), &durability)
            .unwrap();
        drop(journal);
        drop(durability);
    }
    let on_disk_offset = journal_file_length(&directory);
    assert!(on_disk_offset > 0);

    // Ordinary startup refuses with the precise behind facts.
    if let Err(DurableJournalError::CheckpointOwner(CheckpointError::CoverageBehind {
        record_offset,
        journal_offset,
    })) = MemoryV1DurableJournal::open_checkpointed(
        &directory.path(),
        &base(&directory),
        install(),
        id(10),
        id(11),
        anchor(),
        limits(),
    ) {
        assert_eq!((record_offset, journal_offset), (0, on_disk_offset));
    } else {
        panic!("expected the CoverageBehind refusal");
    }

    // Attach refuses the same way after an independent journal reopen.
    let tail =
        MemoryV1DurableJournal::scan_tail(&directory.path(), id(10), id(11), anchor(), limits())
            .unwrap();
    let (journal, durability) =
        MemoryV1DurableJournal::open(&directory.path(), id(10), id(11), anchor(), tail, limits())
            .unwrap();
    let (store, _, _) = LocalCheckpointStore::open(
        &base(&directory),
        install(),
        id(10),
        id(11),
        anchor(),
        limits(),
    )
    .unwrap();
    assert!(matches!(
        journal.attach_checkpoint(&durability, store),
        Err(DurableJournalError::CheckpointOwner(
            CheckpointError::CoverageBehind { .. }
        ))
    ));
    drop(journal);
    drop(durability);

    // The single-scan verifier reports TailLonger as facts, never adoption.
    let record = LocalCheckpointStore::open(
        &base(&directory),
        install(),
        id(10),
        id(11),
        anchor(),
        limits(),
    )
    .unwrap()
    .1;
    match MemoryV1DurableJournal::verify_checkpoint(
        &directory.path(),
        &install(),
        id(10),
        id(11),
        anchor(),
        &record,
        limits(),
    ) {
        Ok(CheckpointScanOutcome::TailLonger {
            journal_tail,
            journal_offset,
        }) => {
            assert_eq!(journal_offset, on_disk_offset);
            assert_eq!(journal_tail, tail);
        }
        _ => panic!("expected the TailLonger report"),
    }

    // Explicit out-of-band repair: delete the sidecar, re-bootstrap against
    // the verified tail, then ordinary startup becomes a clean cut.
    for suffix in [".ckpt.lock", ".ckpt.slot0", ".ckpt.slot1"] {
        let mut name = base(&directory).clone().into_os_string();
        name.push(suffix);
        fs::remove_file(PathBuf::from(name)).unwrap();
    }
    let (mut journal, durability) =
        MemoryV1DurableJournal::open(&directory.path(), id(10), id(11), anchor(), tail, limits())
            .unwrap();
    let coverage =
        LocalCheckpointCoverage::from_anchor(journal.position(), journal.file_position());
    let (store, _) = LocalCheckpointStore::bootstrap(
        &base(&directory),
        install(),
        id(10),
        id(11),
        anchor(),
        coverage,
        limits(),
    )
    .unwrap();
    assert_eq!(attach(&journal, &durability, store), 1);
    let prepared = journal
        .prepare_mutation(&request("third", 3), &durability)
        .unwrap();
    prepared.into_durable_receipt(&durability).unwrap();
    let latest = durability.checkpoint_latest().unwrap();
    assert_eq!(latest.generation(), 2);
    assert_eq!(latest.journal_sequence(), 3);
}

// memory—v1: An undecodable newest slot is conservatively refused; a truly
// empty companion slot is the normal bootstrap state; re-bootstrap without an
// explicit out-of-band deletion is refused.
#[test]
fn unclear_newest_slot_refuses_but_empty_companion_is_normal() {
    let directory = TestDir::new();
    {
        let (mut journal, durability) = owner(&directory);
        let (store, _) = bootstrap_genesis(&directory);
        assert_eq!(attach(&journal, &durability, store), 1);
        let prepared = journal
            .prepare_mutation(&request("first", 1), &durability)
            .unwrap();
        prepared.into_durable_receipt(&durability).unwrap();
        drop(journal);
        drop(durability);
    }
    // After generation 2, slot 0 holds the newest record and slot 1 holds
    // generation 1. Destroying the newest slot's image leaves one valid
    // record beside an undecodable slot: the newest generation's outcome is
    // unknown, so ordinary startup refuses.
    let mut slot0 = base(&directory).clone().into_os_string();
    slot0.push(".ckpt.slot0");
    let slot0 = PathBuf::from(slot0);
    let mut garbage = vec![0x5a_u8; 252];
    garbage[0] = b'X';
    fs::write(&slot0, &garbage).unwrap();

    assert_eq!(
        open_sidecar(&directory).unwrap_err(),
        CheckpointError::UnclearNewestSlot
    );

    assert_eq!(
        LocalCheckpointStore::bootstrap(
            &base(&directory),
            install(),
            id(10),
            id(11),
            anchor(),
            LocalCheckpointCoverage::from_anchor(anchor(), 0),
            limits()
        )
        .unwrap_err(),
        CheckpointError::TargetExists
    );
}

// memory—v1: Both slots unreadable refuse as a corrupt store; deletion plus
// explicit bootstrap is the only repair.
#[test]
fn corrupt_store_refuses_and_rebootstrap_needs_explicit_delete() {
    let directory = TestDir::new();
    bootstrap_genesis(&directory);
    for suffix in [".ckpt.slot0", ".ckpt.slot1"] {
        let mut name = base(&directory).clone().into_os_string();
        name.push(suffix);
        fs::write(PathBuf::from(name), b"torn").unwrap();
    }
    assert_eq!(
        open_sidecar(&directory).unwrap_err(),
        CheckpointError::CorruptStore
    );
    assert_eq!(
        LocalCheckpointStore::bootstrap(
            &base(&directory),
            install(),
            id(10),
            id(11),
            anchor(),
            LocalCheckpointCoverage::from_anchor(anchor(), 0),
            limits()
        )
        .unwrap_err(),
        CheckpointError::TargetExists
    );
}

// memory—v1: The genesis checkpoint supports an empty journal at ordinary
// startup, and the reopened owner serves group commits from generation 2.
#[test]
fn genesis_checkpoint_supports_empty_journal_at_startup() {
    let directory = TestDir::new();
    {
        let (journal, durability) = owner(&directory);
        let (store, _) = bootstrap_genesis(&directory);
        attach(&journal, &durability, store);
        // No appends: the journal file stays empty; crash-simulate the drop.
    }
    assert_eq!(journal_file_length(&directory), 0);
    let (mut journal, durability) = MemoryV1DurableJournal::open_checkpointed(
        &directory.path(),
        &base(&directory),
        install(),
        id(10),
        id(11),
        anchor(),
        limits(),
    )
    .unwrap();
    assert_eq!(journal.file_position(), 0);
    assert_eq!(journal.position(), anchor());
    assert_eq!(durability.checkpoint_latest().unwrap().generation(), 1);

    let prepared = journal
        .prepare_mutation(&request("first", 1), &durability)
        .unwrap();
    prepared.into_durable_receipt(&durability).unwrap();
    let latest = durability.checkpoint_latest().unwrap();
    assert_eq!(latest.generation(), 2);
    assert_eq!(latest.journal_sequence(), 1);
}

// memory—v1: The single-scan verifier distinguishes clean cut from foreign
// bindings and fabricated coverage, without trusting the record.
#[test]
fn verify_checkpoint_classifies_clean_cut_and_mismatches() {
    let directory = TestDir::new();
    let (mut journal, durability) = owner(&directory);
    let (store, _) = bootstrap_genesis(&directory);
    assert_eq!(attach(&journal, &durability, store), 1);
    let prepared = journal
        .prepare_mutation(&request("first", 1), &durability)
        .unwrap();
    prepared.into_durable_receipt(&durability).unwrap();
    let record = durability.checkpoint_latest().unwrap();

    assert_eq!(
        MemoryV1DurableJournal::verify_checkpoint(
            &directory.path(),
            &install(),
            id(10),
            id(11),
            anchor(),
            &record,
            limits()
        ),
        Ok(CheckpointScanOutcome::CleanCut)
    );

    // A record bound to another installation is refused before any scan.
    let (foreign, _) = LocalCheckpointStore::bootstrap(
        &directory.0.join("foreign.ckpt"),
        foreign_install(),
        id(10),
        id(11),
        anchor(),
        LocalCheckpointCoverage::from_anchor(anchor(), 0),
        limits(),
    )
    .unwrap();
    let foreign_record = foreign.latest_record();
    drop(foreign);
    assert_eq!(
        MemoryV1DurableJournal::verify_checkpoint(
            &directory.path(),
            &install(),
            id(10),
            id(11),
            anchor(),
            &foreign_record,
            limits()
        )
        .unwrap_err(),
        DurableJournalError::CheckpointOwner(CheckpointError::InstallMismatch)
    );

    // Coverage ahead of the journal's verified tail is refused at attach.
    let ahead_directory = TestDir::new();
    let (ahead_journal, ahead_durability) = owner(&ahead_directory);
    let (ahead_store, _) = LocalCheckpointStore::bootstrap(
        &base(&ahead_directory),
        install(),
        id(10),
        id(11),
        anchor(),
        LocalCheckpointCoverage::from_anchor(
            JournalAnchor::new(id(10), 1, 1, [9; 32]).unwrap(),
            100,
        ),
        limits(),
    )
    .unwrap();
    assert!(matches!(
        ahead_journal.attach_checkpoint(&ahead_durability, ahead_store),
        Err(DurableJournalError::CheckpointOwner(
            CheckpointError::CoverageAhead
        ))
    ));
    drop(ahead_journal);
    drop(ahead_durability);

    // An offset-0 record that does not state the baseline is ahead of an
    // empty journal for the verifier.
    let empty_directory = TestDir::new();
    let (_empty_journal, _empty_durability) = owner(&empty_directory);
    let (fabricating_store, _) = LocalCheckpointStore::bootstrap(
        &base(&empty_directory),
        install(),
        id(10),
        id(11),
        anchor(),
        LocalCheckpointCoverage::from_anchor(anchor(), 0),
        limits(),
    )
    .unwrap();
    let fabricated = fabricating_store
        .append(LocalCheckpointCoverage::from_anchor(
            JournalAnchor::new(id(10), 5, 5, [9; 32]).unwrap(),
            0,
        ))
        .unwrap();
    drop(fabricating_store);
    assert_eq!(
        MemoryV1DurableJournal::verify_checkpoint(
            &empty_directory.path(),
            &install(),
            id(10),
            id(11),
            anchor(),
            &fabricated,
            limits()
        )
        .unwrap_err(),
        DurableJournalError::CheckpointOwner(CheckpointError::CoverageAhead)
    );
}

// memory—v1: Opt-in real-file curve with the checkpoint sidecar attached.
// Compare against `local_release_journal_curve` in scheduling.rs: the
// per-group checkpoint adds one record write and one fdatasync per flush.
#[test]
#[ignore = "opt-in local release checkpoint curve"]
fn local_release_checkpoint_curve() {
    const OPERATIONS: u64 = 1024;
    for workers in [1, 2, 4, 8, 16, 32] {
        for sample in 1..=3 {
            let directory = TestDir::new();
            let (journal, durability) = MemoryV1DurableJournal::create(
                &directory.path(),
                id(10),
                id(11),
                anchor(),
                crate::memory_v1_durable_journal::DurableJournalLimits::new(
                    OPERATIONS,
                    16 * 1024 * 1024,
                    1024 * 1024,
                )
                .unwrap(),
            )
            .unwrap();
            let (store, _) = bootstrap_genesis(&directory);
            journal.attach_checkpoint(&durability, store).unwrap();
            let journal = Arc::new(std::sync::Mutex::new(journal));
            let durability = Arc::new(durability);
            let start = Arc::new(std::sync::Barrier::new(workers + 1));
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
            // The per-group checkpoint adds one record write and one
            // fdatasync per flush group, roughly doubling the single-worker
            // sample time; the collection budget stays generous while the
            // event handshakes keep the tight TIMEOUT.
            let deadline = started + Duration::from_secs(120);
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
            assert_eq!(journal.record_count(), OPERATIONS);
            let durable_end = durability.state.lock().unwrap().durable_end;
            assert_eq!(durable_end, journal.file_position());
            let latest = durability.checkpoint_latest().unwrap();
            assert_eq!(latest.journal_offset(), journal.file_position());
            let syncs = durability.sync_calls();
            assert!((1..=OPERATIONS).contains(&syncs));
            if workers == 1 {
                assert_eq!(syncs, OPERATIONS);
                assert_eq!(latest.generation(), OPERATIONS + 1);
            }
            latencies.sort_unstable();
            let us = |percent: usize| {
                latencies[(latencies.len() * percent).div_ceil(100) - 1].as_secs_f64() * 1e6
            };
            println!(
                "workers={workers:>2} sample={sample} ops={OPERATIONS} syncs={syncs:>4} ckpt_gen={:>4} ops/s={:.0} p50/p95/p99={:.1}/{:.1}/{:.1}us",
                latest.generation(),
                OPERATIONS as f64 / elapsed.as_secs_f64(),
                us(50),
                us(95),
                us(99)
            );
        }
    }
}

// memory—v1: Build the canonical frame bytes the root owner's reservation
// carries for the shared request fixture.
fn reserved_frame(sequence: u64, operation_id: &str, prev_hash: [u8; 32]) -> Vec<u8> {
    let payload = request(operation_id, sequence).journal_payload().unwrap();
    encode_record(&JournalRecord {
        stream_id: id(10),
        epoch_id: id(11),
        journal_sequence: sequence,
        message_id: MemoryId::from_bytes((u128::from(sequence) + 20).to_be_bytes()),
        operation_id,
        request_fingerprint: [4; 32],
        kind: RecordKind::Mutation,
        mutation_sequence: sequence,
        prev_hash,
        payload: &payload,
    })
    .unwrap()
}

// memory—v1: prepare_reserved_frame writes the published frame bytes
// verbatim, validates the chain against the current position, and feeds the
// same durability and checkpoint path as prepare_mutation.
#[test]
fn reserved_frame_writes_verbatim_through_checkpoint_path() {
    let directory = TestDir::new();
    let (mut journal, durability) = owner(&directory);
    let (store, _) = bootstrap_genesis(&directory);
    assert_eq!(attach(&journal, &durability, store), 1);

    let frame = reserved_frame(1, "reserved-1", *anchor().frame_hash());
    let prepared = journal.prepare_reserved_frame(&frame, &durability).unwrap();
    let receipt = prepared.into_durable_receipt(&durability).unwrap();
    assert_eq!(receipt.start_offset(), 0);
    assert_eq!(receipt.end_offset(), frame.len() as u64);
    let decoded = decode_record(&frame).unwrap();
    assert_eq!(*receipt.tail_hash(), decoded.digest);
    assert_eq!(receipt.identity(), request("reserved-1", 1).journal());
    // The durable file holds exactly the published bytes, unmodified.
    assert_eq!(fs::read(directory.path()).unwrap(), frame);
    // The group checkpoint covers the reserved frame through the shared path.
    let latest = durability.checkpoint_latest().unwrap();
    assert_eq!(latest.generation(), 2);
    assert_eq!(latest.journal_offset(), frame.len() as u64);
    assert_eq!(latest.journal_sequence(), 1);

    // The next reserved frame chains to the first one.
    let second = reserved_frame(2, "reserved-2", decoded.digest);
    let prepared = journal
        .prepare_reserved_frame(&second, &durability)
        .unwrap();
    prepared.into_durable_receipt(&durability).unwrap();
    assert_eq!(durability.checkpoint_latest().unwrap().generation(), 3);
    assert_eq!(journal.record_count(), 2);
}

// memory—v1: prepare_reserved_frame refuses duplicates, broken chains,
// foreign bindings, envelope mismatches, and non-mutation frames; the
// journal state stays clean on every refusal.
#[test]
fn reserved_frame_refuses_duplicates_and_invalid_frames() {
    let directory = TestDir::new();
    let (mut journal, durability) = owner(&directory);
    let frame = reserved_frame(1, "reserved-1", *anchor().frame_hash());
    journal.prepare_reserved_frame(&frame, &durability).unwrap();

    // An already-present operation is refused, even byte-identical.
    assert_eq!(
        journal
            .prepare_reserved_frame(&frame, &durability)
            .unwrap_err(),
        DurableJournalError::ExistingOperation
    );

    // Broken predecessor chain.
    let wrong_prev = reserved_frame(2, "reserved-2", [1; 32]);
    assert!(matches!(
        journal.prepare_reserved_frame(&wrong_prev, &durability),
        Err(DurableJournalError::Frame(JournalError::ChainMismatch))
    ));

    // Sequence gap.
    let gap = reserved_frame(4, "reserved-4", *journal.position().frame_hash());
    assert!(matches!(
        journal.prepare_reserved_frame(&gap, &durability),
        Err(DurableJournalError::Frame(JournalError::ChainMismatch))
    ));

    // Foreign stream is refused by the chain verifier.
    let foreign_stream = encode_record(&JournalRecord {
        stream_id: id(12),
        epoch_id: id(11),
        journal_sequence: 2,
        message_id: MemoryId::from_bytes(22u128.to_be_bytes()),
        operation_id: "reserved-foreign",
        request_fingerprint: [4; 32],
        kind: RecordKind::Mutation,
        mutation_sequence: 2,
        prev_hash: *journal.position().frame_hash(),
        payload: &request("reserved-foreign", 2).journal_payload().unwrap(),
    })
    .unwrap();
    assert!(matches!(
        journal.prepare_reserved_frame(&foreign_stream, &durability),
        Err(DurableJournalError::Frame(JournalError::ChainMismatch))
    ));

    // Foreign epoch passes the chain verifier but is refused by the owner.
    let foreign_epoch = encode_record(&JournalRecord {
        stream_id: id(10),
        epoch_id: id(12),
        journal_sequence: 2,
        message_id: MemoryId::from_bytes(22u128.to_be_bytes()),
        operation_id: "reserved-epoch",
        request_fingerprint: [4; 32],
        kind: RecordKind::Mutation,
        mutation_sequence: 2,
        prev_hash: *journal.position().frame_hash(),
        payload: &request("reserved-epoch", 2).journal_payload().unwrap(),
    })
    .unwrap();
    assert!(matches!(
        journal.prepare_reserved_frame(&foreign_epoch, &durability),
        Err(DurableJournalError::SequenceMismatch)
    ));

    // A mutation envelope bound to another operation is refused before any
    // byte is written.
    let rebound = encode_record(&JournalRecord {
        stream_id: id(10),
        epoch_id: id(11),
        journal_sequence: 2,
        message_id: MemoryId::from_bytes(22u128.to_be_bytes()),
        operation_id: "reserved-2",
        request_fingerprint: [4; 32],
        kind: RecordKind::Mutation,
        mutation_sequence: 2,
        prev_hash: *journal.position().frame_hash(),
        payload: &request("reserved-other", 2).journal_payload().unwrap(),
    })
    .unwrap();
    assert!(matches!(
        journal.prepare_reserved_frame(&rebound, &durability),
        Err(DurableJournalError::OperationConflict)
    ));

    // The journal state is unchanged after every refusal.
    assert_eq!(journal.record_count(), 1);
    assert_eq!(journal.file_position(), frame.len() as u64);
    assert_eq!(journal.state(), DurableJournalState::Ready);
    assert!(!journal.has_operation("reserved-2"));
}

// memory—v1: The scan retains the reconciliation fields: message identity,
// request fingerprint, chained predecessor, origin boot, canonical payload
// digest, and the predecessor mutation sequence a denial reconciles against.
#[test]
fn recovery_records_carry_reconciliation_fields() {
    let directory = TestDir::new();
    let (mut journal, durability) = owner(&directory);
    let first = journal
        .prepare_mutation(&request("mutation-1", 1), &durability)
        .unwrap();
    let first_hash = first.tail_hash;
    first.into_durable_receipt(&durability).unwrap();
    let deny = deny_request(2, 1);
    journal.prepare_deny(&deny, &durability).unwrap();
    drop(journal);
    drop(durability);

    let tail =
        MemoryV1DurableJournal::scan_tail(&directory.path(), id(10), id(11), anchor(), limits())
            .unwrap();
    let (journal, _) =
        MemoryV1DurableJournal::open(&directory.path(), id(10), id(11), anchor(), tail, limits())
            .unwrap();
    let records = journal.recovery_records();
    assert_eq!(records.len(), 2);

    let mutation = &records[0];
    let mutation_payload = request("mutation-1", 1).journal_payload().unwrap();
    assert_eq!(mutation.kind, RecordKind::Mutation);
    assert_eq!(mutation.journal_sequence, 1);
    assert_eq!(mutation.mutation_sequence, 1);
    assert_eq!(mutation.prev_mutation_sequence, 0);
    assert_eq!(
        mutation.message_id,
        request("mutation-1", 1).journal().message_id()
    );
    assert_eq!(mutation.request_fingerprint, [4; 32]);
    assert_eq!(mutation.prev_hash, *anchor().frame_hash());
    assert_eq!(mutation.payload, mutation_payload);
    assert_eq!(mutation.payload_digest, payload_digest(&mutation_payload));
    let decoded_mutation_payload = decode_journal_payload(&mutation_payload).unwrap();
    assert_eq!(
        mutation.origin_boot_id,
        decoded_mutation_payload.origin_boot_id()
    );
    assert_eq!(mutation.frame_hash, first_hash);

    let denial = &records[1];
    let deny_payload = deny.journal_payload().unwrap();
    assert_eq!(denial.kind, RecordKind::Deny);
    assert_eq!(denial.journal_sequence, 2);
    assert_eq!(denial.mutation_sequence, 1);
    assert_eq!(denial.prev_mutation_sequence, 1);
    assert_eq!(denial.prev_hash, first_hash);
    assert_eq!(denial.payload, deny_payload);
    let (deny_origin, _) = decode_deny_journal_payload_with_origin(&deny_payload).unwrap();
    assert_eq!(denial.origin_boot_id, deny_origin);
}

// memory—v1: A read of mutation 1 can finish after 3 has been published. The
// receipt describes that read, while the checkpoint and reopened DB predecessor stay at 3.
#[test]
fn historical_deny_keeps_observed_sequence_and_checkpoint_tail_distinct() {
    let directory = TestDir::new();
    let (mut journal, durability) = owner(&directory);
    let (store, _) = bootstrap_genesis(&directory);
    attach(&journal, &durability, store);
    for sequence in 1..=3 {
        journal
            .prepare_mutation(
                &request(&format!("mutation-{sequence}"), sequence),
                &durability,
            )
            .unwrap()
            .into_durable_receipt(&durability)
            .unwrap();
    }
    let mutation_tail = journal.position();
    assert!(matches!(
        journal.prepare_deny(&deny_request(4, 4), &durability),
        Err(DurableJournalError::SequenceMismatch)
    ));
    assert_eq!(journal.position(), mutation_tail);
    let deny = deny_request(4, 1);
    let receipt = journal
        .prepare_deny(&deny, &durability)
        .unwrap()
        .into_durable_receipt(&durability)
        .unwrap();
    assert_eq!(receipt.identity().mutation_sequence(), 1);
    let checkpoint = durability.checkpoint_latest().unwrap();
    let tail = checkpoint.coverage_anchor().unwrap();
    assert_eq!(tail, journal.position());
    assert_eq!((tail.journal_sequence(), tail.mutation_sequence()), (4, 3));
    drop((journal, durability));
    assert_eq!(
        MemoryV1DurableJournal::verify_checkpoint(
            &directory.path(),
            &install(),
            id(10),
            id(11),
            anchor(),
            &checkpoint,
            limits()
        )
        .unwrap(),
        CheckpointScanOutcome::CleanCut
    );
    let (reopened, _) = MemoryV1DurableJournal::open_checkpointed(
        &directory.path(),
        &base(&directory),
        install(),
        id(10),
        id(11),
        anchor(),
        limits(),
    )
    .unwrap();
    let denied = &reopened.recovery_records()[3];
    assert_eq!(denied.kind, RecordKind::Deny);
    assert_eq!(
        (denied.mutation_sequence, denied.prev_mutation_sequence),
        (1, 3)
    );
    assert_eq!(denied.prev_hash, *mutation_tail.frame_hash());
    assert_eq!(reopened.last_mutation(), mutation_tail);
    assert_eq!(reopened.position(), tail);
}
