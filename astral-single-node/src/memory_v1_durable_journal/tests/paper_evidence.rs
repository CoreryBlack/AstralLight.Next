//! memory—v1: Journal fault and identity evidence for the Computers & Security
//! DarkStar paper (sections 3 and 4). The file-level cases J1 to J5 run against
//! the real durable journal owner on real files in a private scratch directory.
//! Fixtures are local to this module because the parent `tests` fixtures are
//! private to their own module. Assertions pin observed behaviour; a `witness_`
//! test asserts current behaviour that is a known gap. Each witness comment names
//! the production code it pins and, where one exists, the paper clause it bears on.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use astral_authorization_root::memory_v1_db_rows::UserCardStatus;
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_root::{
    ManagementMutationV2, RootInstanceId, RootMetadata, RootStatus,
};
use astral_trustgraph::service::memory_v1_mutation_coordinator::{
    DenyJournalRequest, JournalIdentity, MutationAuditCandidate, MutationRequest, RootBinding,
    VerifiedRootAdmission,
};
use astral_types::memory_v1::{CandidateIdentity, MemoryId};
use astral_types::memory_v1_audit::{
    MemoryV1AuditAction, MemoryV1AuditActor, MemoryV1AuditCardState, MemoryV1AuditChange,
    MemoryV1AuditConfirmations, MemoryV1AuditContext, MemoryV1AuditDecisionInput,
    MemoryV1AuditDenySource, MemoryV1AuditEvent, MemoryV1AuditObject, MemoryV1AuditObjectState,
    MemoryV1AuditOperation, MemoryV1AuditRootObservation, MemoryV1AuditRootStatus,
    MemoryV1AuditRootVersion, MemoryV1AuditSource, MemoryV1AuditT2SingleChangeCandidate,
    MemoryV1AuditTime,
};
use astral_types::memory_v1_deny_observation::{
    MemoryV1DenyAffectedBindingState, MemoryV1DenyObservation, MemoryV1DenyRootObservation,
};
use astral_types::memory_v1_journal::{
    decode_record, encode_record, JournalAnchor, JournalError, JournalRecord, RecordKind,
};

use super::{
    DurableJournalError, DurableJournalLimits, JournalAppendDisposition, JournalDurability,
    LocalDurablePrefixReceipt, MemoryV1DurableJournal,
};

const STREAM: [u8; 16] = [10; 16];
const EPOCH: [u8; 16] = [11; 16];
const GENESIS_HASH: [u8; 32] = [5; 32];

// memory—v1: The stream and epoch identifiers the journal fixtures share.
fn stream() -> MemoryId {
    MemoryId::from_bytes(STREAM)
}

// memory—v1: The epoch identifier the journal fixtures share.
fn epoch() -> MemoryId {
    MemoryId::from_bytes(EPOCH)
}

// memory—v1: The external baseline anchor, at a chosen mutation sequence.
fn anchor(mutation_sequence: u64, frame_hash: [u8; 32]) -> JournalAnchor {
    JournalAnchor::new(stream(), 0, mutation_sequence, frame_hash).unwrap()
}

// memory—v1: The default fixture baseline: genesis with the shared hash.
fn genesis() -> JournalAnchor {
    anchor(0, GENESIS_HASH)
}

// memory—v1: Limits identical to production except for the record cap.
fn limits_with_records(max_records: u64) -> DurableJournalLimits {
    DurableJournalLimits {
        max_records,
        ..DurableJournalLimits::conservative()
    }
}

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

// memory—v1: A private scratch directory named by process id and a counter. No
// wall clock or OS randomness is used to name it.
struct ScratchDir(PathBuf);

impl ScratchDir {
    // memory—v1: Create the private directory for one fixture.
    fn new(label: &str) -> Self {
        let index = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "astral-paper-journal-{label}-{}-{index}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    // memory—v1: The journal file path inside the fixture directory.
    fn journal(&self) -> PathBuf {
        self.0.join("journal.bin")
    }
}

// memory—v1: Remove the fixture directory when the test ends.
impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// memory—v1: Create a fresh journal at the scratch path with the given limits.
fn create_with(
    dir: &ScratchDir,
    limits: DurableJournalLimits,
) -> (MemoryV1DurableJournal, JournalDurability) {
    MemoryV1DurableJournal::create(&dir.journal(), stream(), epoch(), genesis(), limits).unwrap()
}

// memory—v1: The reopen procedure the service uses: scan, then open against the
// tail the scan derived from the file itself.
fn reopen_with(
    path: &Path,
    baseline: JournalAnchor,
    limits: DurableJournalLimits,
) -> Result<(MemoryV1DurableJournal, JournalDurability), DurableJournalError> {
    let tail = MemoryV1DurableJournal::scan_tail(path, stream(), epoch(), baseline, limits)?;
    MemoryV1DurableJournal::open(path, stream(), epoch(), baseline, tail, limits)
}

// memory—v1: Reopen the scratch journal with the default genesis and limits.
fn reopen(
    dir: &ScratchDir,
) -> Result<(MemoryV1DurableJournal, JournalDurability), DurableJournalError> {
    reopen_with(
        &dir.journal(),
        genesis(),
        DurableJournalLimits::conservative(),
    )
}

// memory—v1: Extract the refusal of a fallible journal call. The journal
// durability owner has no Debug impl, so `unwrap_err` cannot be used directly.
fn refusal<T>(result: Result<T, DurableJournalError>) -> DurableJournalError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("the journal call was expected to be refused"),
    }
}

// memory—v1: Byte length of a file on disk, read without touching the journal.
fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).unwrap().len()
}

// memory—v1: Cut the file at an exact byte length, as a crash mid-write would.
fn truncate_to(path: &Path, length: u64) {
    let file = OpenOptions::new().write(true).open(path).unwrap();
    file.set_len(length).unwrap();
    file.sync_all().unwrap();
}

// memory—v1: Append raw bytes after the last frame, as a torn write would.
fn append_raw(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

// memory—v1: Invert one byte inside an existing frame.
fn flip_byte(path: &Path, index: u64) {
    let mut bytes = std::fs::read(path).unwrap();
    bytes[index as usize] ^= 0xFF;
    std::fs::write(path, bytes).unwrap();
}

// memory—v1: One DENY observation. The journal checks shape and digests, not the
// live root, so a fixed observation is sufficient for file-level behaviour.
fn deny_observation(operation: &str, fingerprint: u8, tenant: u8) -> MemoryV1DenyObservation {
    let root = MemoryV1DenyRootObservation::try_from_usize(
        MemoryId::from_bytes([1; 16]),
        7,
        [7; 32],
        MemoryV1AuditRootStatus::Serving,
        32,
        4,
        9,
    )
    .unwrap();
    MemoryV1DenyObservation::new(
        root,
        CandidateIdentity {
            user_id: MemoryId::from_bytes([1; 16]),
            identity_card_id: MemoryId::from_bytes([2; 16]),
            user_card_id: MemoryId::from_bytes([4; 16]),
            tenant_id: MemoryId::from_bytes([tenant; 16]),
        },
        1_700_000_000,
        "permission_rule",
        "read",
        None,
        Some(Vec::new()),
        None,
        MemoryV1DenyAffectedBindingState::inapplicable(),
        operation.as_bytes().to_vec(),
        vec![fingerprint; 32],
        MemoryV1AuditDenySource::RuleDeny,
        None,
    )
    .unwrap()
}

// memory—v1: One DENY request at the next journal sequence. DENY frames do not
// advance the mutation sequence, so every DENY-only journal stays at zero.
fn deny_request(
    operation: &str,
    fingerprint: u8,
    tenant: u8,
    journal_sequence: u64,
    message: u8,
) -> DenyJournalRequest {
    let identity = JournalIdentity::new_deny(
        stream(),
        epoch(),
        journal_sequence,
        0,
        MemoryId::from_bytes([message; 16]),
    )
    .unwrap();
    DenyJournalRequest::try_new(deny_observation(operation, fingerprint, tenant), identity).unwrap()
}

// memory—v1: Append one DENY and wait for its receipt, as the owner does.
fn append_deny(
    journal: &mut MemoryV1DurableJournal,
    durability: &JournalDurability,
    request: &DenyJournalRequest,
) -> LocalDurablePrefixReceipt {
    journal
        .prepare_deny(request, durability)
        .unwrap()
        .into_durable_receipt(durability)
        .unwrap()
}

// memory—v1: Three DENY frames written and synced. Returns the file position
// after each frame, which are the exact frame boundaries.
fn write_three_denies(dir: &ScratchDir) -> [u64; 3] {
    let (mut journal, durability) = create_with(dir, DurableJournalLimits::conservative());
    let mut boundaries = [0; 3];
    for (slot, index) in boundaries.iter_mut().zip(0_u8..3) {
        let request = deny_request(
            &format!("deny-{index}"),
            index + 1,
            1,
            u64::from(index) + 1,
            index + 1,
        );
        append_deny(&mut journal, &durability, &request);
        *slot = journal.file_position();
    }
    boundaries
}

// memory—v1: One mutation request at journal shape. The root binding is a
// synthetic serving observation and the audit is an allowed single change; the
// journal verifies identity, digests and sequence, not the live root.
fn mutation_request(
    operation: &str,
    fingerprint: [u8; 32],
    actor: u8,
    identity: JournalIdentity,
) -> MutationRequest {
    let instance = RootInstanceId::from_uuid(uuid::Uuid::from_bytes([3; 16]));
    let instance_id = MemoryId::from_bytes(*instance.as_uuid().as_bytes());
    let metadata = RootMetadata {
        instance_id: instance,
        version: 0,
        digest: [7; 32],
        budget: CandidateBudget {
            max_table_rows: 32,
            max_bindings_per_read: 4,
        },
        row_count: 0,
        status: RootStatus::Serving,
    };
    let mutation = ManagementMutationV2::UserCardStatus {
        user_card_id: [4; 16],
        status: UserCardStatus::Active,
    };
    let summary = MutationAuditCandidate::governance_mutation_summary(&mutation).unwrap();
    let root_version = MemoryV1AuditRootVersion::new(instance_id, 0);
    let context = MemoryV1AuditContext::new(
        MemoryV1AuditActor::new(
            MemoryId::from_bytes([actor; 16]),
            MemoryId::from_bytes([2; 16]),
        ),
        MemoryV1AuditTime::new(1_700_000_000).unwrap(),
        MemoryV1AuditAction::new("user_card", "enable").unwrap(),
        "GOVERNANCE_USER_CARD_ENABLE",
        MemoryV1AuditOperation::new(operation, fingerprint).unwrap(),
        MemoryV1AuditRootObservation::new(
            root_version,
            metadata.digest,
            MemoryV1AuditRootStatus::Serving,
        ),
    )
    .unwrap();
    let change = MemoryV1AuditChange::new(
        Some(MemoryId::from_bytes([actor; 16])),
        Some(MemoryV1AuditObject::UserCard(MemoryId::from_bytes([4; 16]))),
        Some(MemoryV1AuditObject::Tenant(MemoryId::from_bytes([3; 16]))),
        Some(summary),
        Some(MemoryV1AuditObjectState::UserCard(
            MemoryV1AuditCardState::Disabled,
        )),
        Some(MemoryV1AuditObjectState::UserCard(
            MemoryV1AuditCardState::Active,
        )),
        Some(MemoryV1AuditConfirmations::not_applicable()),
        Some(root_version),
        Some(MemoryV1AuditRootVersion::new(instance_id, 1)),
        MemoryV1AuditSource::Ordinary,
    );
    let event =
        MemoryV1AuditEvent::change(context, MemoryV1AuditDecisionInput::Allow, change).unwrap();
    let audit = MutationAuditCandidate::Single(
        MemoryV1AuditT2SingleChangeCandidate::try_from(event).unwrap(),
    );
    let admission =
        VerifiedRootAdmission::mint_from_production_owner(RootBinding::from_metadata(metadata));
    MutationRequest::try_new(operation, fingerprint, mutation, audit, admission, identity).unwrap()
}

// memory—v1: The mutation identity for the next governance position.
fn mutation_identity(
    journal_sequence: u64,
    mutation_sequence: u64,
    message: u8,
) -> JournalIdentity {
    JournalIdentity::new(
        stream(),
        epoch(),
        journal_sequence,
        mutation_sequence,
        MemoryId::from_bytes([message; 16]),
    )
    .unwrap()
}

// memory—v1: J1. A torn tail of trailing garbage after the last complete frame
// is refused by the read-only scan and by the reopen. The variant is pinned.
#[test]
fn j1_trailing_garbage_after_the_last_frame_is_refused() {
    let dir = ScratchDir::new("j1-garbage");
    let boundaries = write_three_denies(&dir);
    append_raw(&dir.journal(), &[0xAB; 7]);
    assert_eq!(file_len(&dir.journal()), boundaries[2] + 7);

    let scan = MemoryV1DurableJournal::scan_tail(
        &dir.journal(),
        stream(),
        epoch(),
        genesis(),
        DurableJournalLimits::conservative(),
    );
    assert_eq!(refusal(scan), DurableJournalError::FileChanged);
    assert_eq!(refusal(reopen(&dir)), DurableJournalError::FileChanged);
}

// memory—v1: J1. A cut inside the third frame is refused, and the two complete
// frames before it are not silently accepted as the whole history.
#[test]
fn j1_mid_frame_truncation_is_refused() {
    let dir = ScratchDir::new("j1-midframe");
    let boundaries = write_three_denies(&dir);
    truncate_to(&dir.journal(), boundaries[1] + 5);

    assert_eq!(refusal(reopen(&dir)), DurableJournalError::FileChanged);
}

// memory—v1: J1. One flipped byte in the last frame's payload is refused by the
// digest check. The exact variant is pinned as observed on this build.
#[test]
fn j1_flipped_byte_in_the_last_frame_is_refused() {
    let dir = ScratchDir::new("j1-flip");
    let boundaries = write_three_denies(&dir);
    flip_byte(&dir.journal(), boundaries[2] - 1);

    let error = refusal(reopen(&dir));
    assert_eq!(
        error,
        DurableJournalError::Frame(JournalError::DigestMismatch)
    );
}

// memory—v1: J1 witness. A cut exactly at a frame boundary is a well-formed
// file. The reopen derives the expected tail from the file itself, so the
// shorter history is accepted. Nothing in the file records the dropped frame.
// The limit is stated in sections/03-protocol.tex line 61 (a valid scan may be
// consistent with a shorter history, and recovery needs an independent anchor)
// and sections/04-implementation.tex line 55 (an external tail learned from the
// same file cannot exclude a missing suffix on its own).
// asserts current behaviour that is a known gap; update when fixed.
#[test]
fn witness_j1_clean_frame_boundary_truncation_is_accepted_as_a_shorter_history() {
    let dir = ScratchDir::new("j1-boundary");
    let boundaries = write_three_denies(&dir);
    truncate_to(&dir.journal(), boundaries[1]);

    let (journal, _durability) =
        reopen(&dir).expect("a clean boundary truncation is accepted by the reopen");
    assert_eq!(journal.record_count(), 2);
    assert_eq!(journal.position().journal_sequence(), 2);
    assert_eq!(journal.file_position(), boundaries[1]);
}

// memory—v1: J1. An existing zero-length file is an untrusted empty baseline in
// both the read-only scan and the reopen.
#[test]
fn j1_empty_existing_file_is_an_untrusted_baseline() {
    let dir = ScratchDir::new("j1-empty");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.journal())
        .unwrap();

    let scan = MemoryV1DurableJournal::scan_tail(
        &dir.journal(),
        stream(),
        epoch(),
        genesis(),
        DurableJournalLimits::conservative(),
    );
    assert_eq!(refusal(scan), DurableJournalError::EmptyExistingFile);
    assert_eq!(
        refusal(reopen(&dir)),
        DurableJournalError::EmptyExistingFile
    );
}

// memory—v1: J1. A missing file is refused by the journal owner itself. Creation
// on a missing path is a separate, explicit call; see the service witness in
// `memory_v1_paper_evidence_tests` for the caller that makes that choice.
#[test]
fn j1_missing_file_is_refused_by_the_journal_owner() {
    let dir = ScratchDir::new("j1-missing");
    assert!(!dir.journal().exists());

    assert_eq!(refusal(reopen(&dir)), DurableJournalError::InvalidTarget);
    assert!(
        !dir.journal().exists(),
        "a refused open must not create the file"
    );
}

// memory—v1: J1. A reopen against the wrong external tail is a chain mismatch,
// even though the file itself is a valid journal.
#[test]
fn j1_wrong_expected_tail_is_a_chain_mismatch() {
    let dir = ScratchDir::new("j1-tail");
    write_three_denies(&dir);
    let honest = MemoryV1DurableJournal::scan_tail(
        &dir.journal(),
        stream(),
        epoch(),
        genesis(),
        DurableJournalLimits::conservative(),
    )
    .unwrap();
    assert_eq!(honest.journal_sequence(), 3);

    // The file holds three frames; an expected tail at sequence 2 is refused.
    let error = refusal(MemoryV1DurableJournal::open(
        &dir.journal(),
        stream(),
        epoch(),
        genesis(),
        JournalAnchor::new(stream(), 2, 0, honest.frame_hash().to_owned()).unwrap(),
        DurableJournalLimits::conservative(),
    ));
    assert_eq!(
        error,
        DurableJournalError::Frame(JournalError::ChainMismatch)
    );
}

// memory—v1: J1. An external baseline with a different frame hash is refused by
// the scan, before any frame is accepted.
#[test]
fn j1_wrong_external_baseline_hash_is_refused_by_the_scan() {
    let dir = ScratchDir::new("j1-hash");
    write_three_denies(&dir);

    let scan = MemoryV1DurableJournal::scan_tail(
        &dir.journal(),
        stream(),
        epoch(),
        anchor(0, [6; 32]),
        DurableJournalLimits::conservative(),
    );
    assert_eq!(
        refusal(scan),
        DurableJournalError::Frame(JournalError::ChainMismatch)
    );
}

// memory—v1: J2. DENY frames share the record cap. At the cap the third append
// is refused before any byte is written, and the refused operation is not
// registered, so its retry is refused by capacity instead of being replayed.
#[test]
fn j2_deny_frames_share_the_record_cap_and_a_refusal_writes_nothing() {
    let dir = ScratchDir::new("j2-cap");
    let (mut journal, durability) = create_with(&dir, limits_with_records(2));
    append_deny(
        &mut journal,
        &durability,
        &deny_request("cap-1", 1, 1, 1, 1),
    );
    append_deny(
        &mut journal,
        &durability,
        &deny_request("cap-2", 2, 1, 2, 2),
    );
    let length = file_len(&dir.journal());
    let position = journal.file_position();

    let refused = refusal(journal.prepare_deny(&deny_request("cap-3", 3, 1, 3, 3), &durability));
    assert_eq!(refused, DurableJournalError::CapacityExceeded);
    assert_eq!(file_len(&dir.journal()), length, "no byte is written");
    assert_eq!(journal.file_position(), position);
    assert_eq!(journal.record_count(), 2);
    assert!(
        !durability.is_failed(),
        "a capacity refusal is not a sync failure"
    );

    let retry = refusal(journal.prepare_deny(&deny_request("cap-3", 3, 1, 3, 3), &durability));
    assert_eq!(retry, DurableJournalError::CapacityExceeded);
    assert_eq!(durability.sync_calls(), 2, "the refusals do not sync");
}

// memory—v1: J3. A mutation whose sequence skips the next contiguous value is
// refused at append with a sequence mismatch and writes nothing.
#[test]
fn j3_mutation_sequence_skip_is_refused_at_append() {
    let dir = ScratchDir::new("j3-skip");
    let (mut journal, durability) = create_with(&dir, DurableJournalLimits::conservative());
    let skipped = mutation_request("skip-op", [9; 32], 1, mutation_identity(1, 2, 1));

    let error = refusal(journal.prepare_mutation(&skipped, &durability));
    assert_eq!(error, DurableJournalError::SequenceMismatch);
    assert_eq!(journal.record_count(), 0);
    assert_eq!(file_len(&dir.journal()), 0);
}

// memory—v1: J3. A file whose first mutation is sequence 2 is a gap against a
// genesis baseline at sequence 0. The refusal observed from the external-baseline
// scan is ChainMismatch, not SequenceGap, so this test does not claim that the
// scan checks sequence gaps. The same file reopens against its own baseline.
#[test]
fn j3_mutation_gap_against_an_external_baseline_is_refused_by_scan_against_wrong_baseline() {
    let dir = ScratchDir::new("j3-gap");
    let shifted = anchor(1, GENESIS_HASH);
    let (mut journal, durability) = MemoryV1DurableJournal::create(
        &dir.journal(),
        stream(),
        epoch(),
        shifted,
        DurableJournalLimits::conservative(),
    )
    .unwrap();
    let request = mutation_request("gap-op", [9; 32], 1, mutation_identity(1, 2, 1));
    journal
        .prepare_mutation(&request, &durability)
        .unwrap()
        .into_durable_receipt(&durability)
        .unwrap();
    drop(journal);
    drop(durability);

    let scan = MemoryV1DurableJournal::scan_tail(
        &dir.journal(),
        stream(),
        epoch(),
        genesis(),
        DurableJournalLimits::conservative(),
    );
    assert_eq!(
        refusal(scan),
        DurableJournalError::Frame(JournalError::ChainMismatch)
    );
    let (reopened, _durability) = reopen_with(
        &dir.journal(),
        shifted,
        DurableJournalLimits::conservative(),
    )
    .expect("the file is valid against its own baseline");
    assert_eq!(reopened.position().mutation_sequence(), 2);
}

// memory—v1: J4 witness. A frame appended without a durable wait, followed by a
// crash, is reopened and treated as confirmed without any sync_data call. The
// reopen seeds the confirmed prefix from the scanned file length (the durability
// state assignment in `open`), and `ensure_durable` returns Ok on its fast path
// when the confirmed end covers the requested end (lines 355-356). The sync at
// open is what sections/03-protocol.tex requires: the Recover step (line 16, and
// the proof at line 52) says to synchronize the retained file before claiming it,
// and the necessity row "Synchronize at open before claiming" (line 84) states
// that omitting it violates d <= S. sections/04-implementation.tex does not
// disclose this reopen case. Adding a sync at open flips the sync_calls
// assertion below.
// asserts current behaviour that is a known gap; update when fixed.
#[test]
fn witness_j4_reopen_marks_unsynced_tail_confirmed_without_sync() {
    let dir = ScratchDir::new("j4");
    let (mut journal, durability) = create_with(&dir, DurableJournalLimits::conservative());
    let request = deny_request("j4-deny", 4, 1, 1, 4);
    let prepared = journal.prepare_deny(&request, &durability).unwrap();
    let end = prepared.durable_end;
    assert_eq!(durability.sync_calls(), 0, "the frame has no receipt yet");
    drop(prepared);
    drop(journal);
    drop(durability);

    let (reopened, reopened_durability) = reopen(&dir).unwrap();
    assert_eq!(reopened.record_count(), 1);
    assert_eq!(reopened.file_position(), end);
    reopened_durability
        .ensure_durable(end)
        .expect("the reopened tail is treated as already confirmed");
    assert_eq!(
        reopened_durability.sync_calls(),
        0,
        "no sync_data ran for the recovered frame"
    );
}

// memory—v1: J5. The same operation, fingerprint and identity return the
// original receipt without a second write.
#[test]
fn j5_same_operation_and_fingerprint_replays_the_original_receipt() {
    let dir = ScratchDir::new("j5-replay");
    let (mut journal, durability) = create_with(&dir, DurableJournalLimits::conservative());
    let request = deny_request("shared", 5, 1, 1, 5);
    let first = append_deny(&mut journal, &durability, &request);
    let length = file_len(&dir.journal());

    let replay = journal
        .prepare_deny(&request, &durability)
        .unwrap()
        .into_durable_receipt(&durability)
        .unwrap();
    assert_eq!(replay.disposition(), JournalAppendDisposition::Replayed);
    assert_eq!(first.disposition(), JournalAppendDisposition::Appended);
    assert_eq!(replay.identity(), first.identity());
    assert_eq!(replay.tail_hash(), first.tail_hash());
    assert_eq!(file_len(&dir.journal()), length, "a replay writes no frame");
    assert_eq!(journal.record_count(), 1);
}

// memory—v1: J5. The same operation with another fingerprint is a conflict and
// is refused before any write.
#[test]
fn j5_same_operation_with_another_fingerprint_conflicts() {
    let dir = ScratchDir::new("j5-fingerprint");
    let (mut journal, durability) = create_with(&dir, DurableJournalLimits::conservative());
    append_deny(
        &mut journal,
        &durability,
        &deny_request("shared", 5, 1, 1, 5),
    );

    let conflict = refusal(journal.prepare_deny(&deny_request("shared", 6, 1, 2, 6), &durability));
    assert_eq!(conflict, DurableJournalError::OperationConflict);
    assert_eq!(journal.record_count(), 1);
}

// memory—v1: J5. The operation namespace is keyed by the client-chosen id alone.
// A second tenant reusing the id with the same fingerprint is refused, but only
// because the observation payload differs. The conflict is detected by payload
// digest, not by any tenant or actor key.
#[test]
fn j5_cross_tenant_reuse_of_an_operation_id_conflicts_on_payload_digest() {
    let dir = ScratchDir::new("j5-tenant");
    let (mut journal, durability) = create_with(&dir, DurableJournalLimits::conservative());
    append_deny(
        &mut journal,
        &durability,
        &deny_request("shared", 5, 1, 1, 5),
    );

    let conflict = refusal(journal.prepare_deny(&deny_request("shared", 5, 2, 2, 6), &durability));
    assert_eq!(conflict, DurableJournalError::OperationConflict);
    assert_eq!(journal.record_count(), 1);
}

// memory—v1: J5. Two mutation requests from different actors that share an
// operation id and fingerprint conflict on the journal payload digest. The
// payload commits to the audit digest (`encode_journal_payload` in the
// coordinator), so the payload check at memory_v1_durable_journal.rs:711 always
// fires before the audit-digest check at line 713. For equal payload digests the
// audit digests are necessarily equal, so line 713 can fail only on a SHA-256
// collision. No fixture isolates the audit-digest comparison, and this test does
// not show that it is operative.
#[test]
fn j5_mutation_replay_with_another_actor_conflicts_on_the_journal_payload_digest() {
    let dir = ScratchDir::new("j5-actor");
    let (mut journal, durability) = create_with(&dir, DurableJournalLimits::conservative());
    let first = mutation_request("shared", [9; 32], 1, mutation_identity(1, 1, 1));
    journal
        .prepare_mutation(&first, &durability)
        .unwrap()
        .into_durable_receipt(&durability)
        .unwrap();

    let other_actor = mutation_request("shared", [9; 32], 2, mutation_identity(1, 1, 1));
    let conflict = refusal(journal.prepare_mutation(&other_actor, &durability));
    assert_eq!(conflict, DurableJournalError::OperationConflict);
    assert_eq!(journal.record_count(), 1);
}

// memory—v1: J5 witness. A DENY replay ignores the identity the caller supplies:
// a non-contiguous journal sequence and a different message id still return the
// original receipt as Replayed. The caller is not told that its identity was
// discarded.
// asserts current behaviour that is a known gap; update when fixed.
#[test]
fn witness_j5_deny_replay_discards_the_supplied_identity() {
    let dir = ScratchDir::new("j5-discard");
    let (mut journal, durability) = create_with(&dir, DurableJournalLimits::conservative());
    let first = append_deny(
        &mut journal,
        &durability,
        &deny_request("shared", 5, 1, 1, 5),
    );

    let replay = journal
        .prepare_deny(&deny_request("shared", 5, 1, 99, 9), &durability)
        .unwrap()
        .into_durable_receipt(&durability)
        .unwrap();
    assert_eq!(replay.disposition(), JournalAppendDisposition::Replayed);
    assert_eq!(replay.identity(), first.identity());
    assert_eq!(journal.position().journal_sequence(), 1);
    assert_eq!(journal.record_count(), 1);
}

// memory—v1: The durable records carry the kind the replay decoder expects.
// Pins that the journal reports DENY kinds for DENY frames only.
#[test]
fn deny_frames_are_reported_with_the_deny_kind_on_reopen() {
    let dir = ScratchDir::new("kind");
    write_three_denies(&dir);
    let (reopened, _durability) = reopen(&dir).unwrap();
    let records = reopened.recovery_records();
    assert_eq!(records.len(), 3);
    assert!(records.iter().all(|record| record.kind == RecordKind::Deny));
    assert!(records.iter().all(|record| record.mutation_sequence == 0));
}

// ---------------------------------------------------------------------------
// Second batch. The production-mutant analysis of the journal (appendix of the
// paper) left guards that no test pinned. Each test below names the guard it
// pins, and each passes on the unmodified code. The tests were written after the
// first mutation round and aim at its survivors; the paper says so. Frames that
// the owner would not write are built with the public codec, so their digests
// are valid and only the property under test can refuse them.
// ---------------------------------------------------------------------------

// memory—v1: The verified tail of a scanned journal. A forged successor frame
// must carry this hash in `prev_hash` for its chain link to be valid.
fn scanned_tail(path: &Path) -> JournalAnchor {
    MemoryV1DurableJournal::scan_tail(
        path,
        stream(),
        epoch(),
        genesis(),
        DurableJournalLimits::conservative(),
    )
    .unwrap()
}

// memory—v1: One DENY frame, encoded by the public codec, at a chosen journal
// sequence and previous hash. The payload is the one the real DENY request
// encodes for this operation, so the scan's payload checks pass and the frame is
// refused only if the placement is wrong. The frame does not advance the
// mutation sequence.
fn forged_deny_frame(
    operation: &str,
    fingerprint: u8,
    journal_sequence: u64,
    message: u8,
    prev_hash: [u8; 32],
) -> Vec<u8> {
    let request = deny_request(operation, fingerprint, 1, journal_sequence, message);
    let payload = request.journal_payload().unwrap();
    encode_record(&JournalRecord {
        stream_id: stream(),
        epoch_id: epoch(),
        journal_sequence,
        message_id: MemoryId::from_bytes([message; 16]),
        operation_id: operation,
        request_fingerprint: request.request_fingerprint(),
        kind: RecordKind::Deny,
        mutation_sequence: 0,
        prev_hash,
        payload: &payload,
    })
    .unwrap()
}

// memory—v1: The i-th fixture DENY, named as `write_three_denies` names it, so
// that the frame lengths of the two helpers agree.
fn deny_n(index: u8) -> DenyJournalRequest {
    deny_request(
        &format!("deny-{index}"),
        index + 1,
        1,
        u64::from(index) + 1,
        index + 1,
    )
}

// memory—v1: The i-th fixture mutation, at the contiguous journal and mutation
// position of a journal that holds only the earlier fixture mutations.
fn mutation_n(index: u8) -> MutationRequest {
    mutation_request(
        &format!("mut-{index}"),
        [index + 1; 32],
        1,
        mutation_identity(u64::from(index) + 1, u64::from(index) + 1, index + 1),
    )
}

// memory—v1: Append one mutation and wait for its receipt, as the owner does.
fn append_mutation(
    journal: &mut MemoryV1DurableJournal,
    durability: &JournalDurability,
    request: &MutationRequest,
) -> LocalDurablePrefixReceipt {
    journal
        .prepare_mutation(request, durability)
        .unwrap()
        .into_durable_receipt(durability)
        .unwrap()
}

// memory—v1: Control for the forged-frame tests. A fourth frame with a fresh
// operation id, the next journal sequence and the tail hash is accepted by the
// scan and by the reopen, so each refusal below comes from the one property its
// forgery violates and not from the way the frame was built.
#[test]
fn forged_contiguous_frame_with_a_fresh_operation_id_is_accepted() {
    let dir = ScratchDir::new("forge-control");
    write_three_denies(&dir);
    let tail = scanned_tail(&dir.journal());
    assert_eq!(tail.journal_sequence(), 3);
    append_raw(
        &dir.journal(),
        &forged_deny_frame("deny-forged", 9, 4, 9, *tail.frame_hash()),
    );

    assert_eq!(scanned_tail(&dir.journal()).journal_sequence(), 4);
    let (journal, _durability) = reopen(&dir).expect("the forged successor is a valid frame");
    assert_eq!(journal.record_count(), 4);
    assert_eq!(journal.position().journal_sequence(), 4);
}

// memory—v1: J5. A file that records one operation id twice is refused by the
// scan and by the open. Every frame is individually valid, chained, and carries
// a payload that matches its own operation id and fingerprint: the duplicate is
// byte-identical to the first frame in operation id, fingerprint and payload, and
// differs in sequence, previous hash and message id. Only the operation ledger
// that `scan_file` builds can refuse it (the insert into `operations`).
#[test]
fn j5_duplicate_operation_id_on_disk_is_refused_by_scan_and_open() {
    let dir = ScratchDir::new("j5-duplicate");
    let boundaries = write_three_denies(&dir);
    let honest = scanned_tail(&dir.journal());
    let duplicate = forged_deny_frame("deny-0", 1, 4, 9, *honest.frame_hash());
    let bytes = std::fs::read(dir.journal()).unwrap();
    let first = decode_record(&bytes[..boundaries[0] as usize]).unwrap();
    let second = decode_record(&duplicate).unwrap();
    assert_eq!(first.record.operation_id, second.record.operation_id);
    assert_eq!(
        first.record.request_fingerprint,
        second.record.request_fingerprint
    );
    assert_eq!(first.record.payload, second.record.payload);
    append_raw(&dir.journal(), &duplicate);

    let scan = MemoryV1DurableJournal::scan_tail(
        &dir.journal(),
        stream(),
        epoch(),
        genesis(),
        DurableJournalLimits::conservative(),
    );
    assert_eq!(refusal(scan), DurableJournalError::OperationConflict);
    let open = MemoryV1DurableJournal::open(
        &dir.journal(),
        stream(),
        epoch(),
        genesis(),
        honest,
        DurableJournalLimits::conservative(),
    );
    assert_eq!(refusal(open), DurableJournalError::OperationConflict);
}

// memory—v1: J3. A gap in the journal sequence is refused by the scan as a chain
// mismatch even though the hash chain is intact. The forged frame claims sequence
// 5 where 4 is next and carries the true tail hash. The same frame at sequence 4
// is accepted (the control above), so the gap alone is refused. This pins the
// sequence-contiguity comparison of the verifier (`JournalVerifier::advance`),
// which is separate from the hash link.
#[test]
fn j3_journal_sequence_gap_with_an_intact_hash_chain_is_refused_by_scan() {
    let dir = ScratchDir::new("j3-journal-gap");
    write_three_denies(&dir);
    let honest = scanned_tail(&dir.journal());
    append_raw(
        &dir.journal(),
        &forged_deny_frame("deny-gap", 9, 5, 9, *honest.frame_hash()),
    );

    let scan = MemoryV1DurableJournal::scan_tail(
        &dir.journal(),
        stream(),
        epoch(),
        genesis(),
        DurableJournalLimits::conservative(),
    );
    assert_eq!(
        refusal(scan),
        DurableJournalError::Frame(JournalError::ChainMismatch)
    );
}

// memory—v1: J1. A reopen under another epoch is refused by the scan with a
// sequence mismatch, before any comparison with the expected tail: every frame
// of the file names the epoch it was written under.
#[test]
fn j1_reopen_under_another_epoch_is_refused_as_a_sequence_mismatch() {
    let dir = ScratchDir::new("j1-epoch");
    write_three_denies(&dir);
    let honest = scanned_tail(&dir.journal());
    let other = MemoryId::from_bytes([12; 16]);

    let scan = MemoryV1DurableJournal::scan_tail(
        &dir.journal(),
        stream(),
        other,
        genesis(),
        DurableJournalLimits::conservative(),
    );
    assert_eq!(refusal(scan), DurableJournalError::SequenceMismatch);
    let open = MemoryV1DurableJournal::open(
        &dir.journal(),
        stream(),
        other,
        genesis(),
        honest,
        DurableJournalLimits::conservative(),
    );
    assert_eq!(refusal(open), DurableJournalError::SequenceMismatch);
}

// memory—v1: J1. A reopen under another stream is refused, but not by the stream
// comparison inside the scan. A baseline that names the other stream makes the
// verifier refuse the first frame as a chain mismatch; a baseline that names the
// file's stream while the owner names another is refused before any frame is
// read. The scan's own stream comparison therefore never decides an outcome:
// after `validate_stream_epoch` and the verifier it cannot be true. The variants
// are pinned as observed on this build.
#[test]
fn j1_reopen_under_another_stream_is_refused_before_the_scan_compares_streams() {
    let dir = ScratchDir::new("j1-stream");
    write_three_denies(&dir);
    let other = MemoryId::from_bytes([12; 16]);

    let consistent = JournalAnchor::new(other, 0, 0, GENESIS_HASH).unwrap();
    let scan = MemoryV1DurableJournal::scan_tail(
        &dir.journal(),
        other,
        epoch(),
        consistent,
        DurableJournalLimits::conservative(),
    );
    assert_eq!(
        refusal(scan),
        DurableJournalError::Frame(JournalError::ChainMismatch)
    );
    let mismatched = MemoryV1DurableJournal::scan_tail(
        &dir.journal(),
        other,
        epoch(),
        genesis(),
        DurableJournalLimits::conservative(),
    );
    assert_eq!(refusal(mismatched), DurableJournalError::SequenceMismatch);
}

// memory—v1: J2. The frame cap is enforced when a file is reopened, not only when
// a frame is written, and it is exact. A file written under the default limits
// is accepted under a cap equal to its frame length and refused under a cap one
// byte smaller, by the scan and by the open. An operator who tightens the cap
// between runs therefore cannot reopen a journal that holds a larger frame.
#[test]
fn j2_frame_cap_is_enforced_at_reopen_and_is_exact() {
    let dir = ScratchDir::new("j2-frame-cap-reopen");
    let boundaries = write_three_denies(&dir);
    let frame = boundaries[0];
    assert_eq!(boundaries[1] - boundaries[0], frame);
    assert_eq!(boundaries[2] - boundaries[1], frame);
    let honest = scanned_tail(&dir.journal());
    let exact = DurableJournalLimits {
        max_frame_bytes: frame,
        ..DurableJournalLimits::conservative()
    };
    let below = DurableJournalLimits {
        max_frame_bytes: frame - 1,
        ..DurableJournalLimits::conservative()
    };

    let at_cap =
        MemoryV1DurableJournal::scan_tail(&dir.journal(), stream(), epoch(), genesis(), exact)
            .expect("a cap equal to the frame length admits the frame");
    assert_eq!(at_cap.journal_sequence(), 3);
    let scan =
        MemoryV1DurableJournal::scan_tail(&dir.journal(), stream(), epoch(), genesis(), below);
    assert_eq!(refusal(scan), DurableJournalError::CapacityExceeded);
    let open =
        MemoryV1DurableJournal::open(&dir.journal(), stream(), epoch(), genesis(), honest, below);
    assert_eq!(refusal(open), DurableJournalError::CapacityExceeded);
}

// memory—v1: J2. The frame cap and the file cap are exact for DENY frames, and a
// refusal writes nothing. A frame of length L is refused under a frame cap of
// L - 1; under a file cap of 2L two frames fit exactly and the third is refused.
// The refused frame leaves the file, the record count and the sync state
// unchanged, and its retry is refused again because the operation was not
// registered. The DENY path has its own comparison for each cap.
#[test]
fn j2_byte_caps_are_exact_for_deny_frames_and_a_refusal_writes_nothing() {
    let probe = ScratchDir::new("j2-deny-probe");
    let frame = write_three_denies(&probe)[0];

    let narrow = ScratchDir::new("j2-deny-frame-cap");
    let (mut journal, durability) = create_with(
        &narrow,
        DurableJournalLimits {
            max_frame_bytes: frame - 1,
            ..DurableJournalLimits::conservative()
        },
    );
    assert_eq!(
        refusal(journal.prepare_deny(&deny_n(0), &durability)),
        DurableJournalError::CapacityExceeded
    );
    assert_eq!(file_len(&narrow.journal()), 0);
    assert_eq!(journal.record_count(), 0);
    assert!(!durability.is_failed());

    let total = ScratchDir::new("j2-deny-file-cap");
    let (mut journal, durability) = create_with(
        &total,
        DurableJournalLimits {
            max_bytes: 2 * frame,
            max_frame_bytes: frame,
            ..DurableJournalLimits::conservative()
        },
    );
    append_deny(&mut journal, &durability, &deny_n(0));
    append_deny(&mut journal, &durability, &deny_n(1));
    assert_eq!(
        file_len(&total.journal()),
        2 * frame,
        "two frames fit exactly"
    );
    let syncs = durability.sync_calls();

    assert_eq!(
        refusal(journal.prepare_deny(&deny_n(2), &durability)),
        DurableJournalError::CapacityExceeded
    );
    assert_eq!(
        refusal(journal.prepare_deny(&deny_n(2), &durability)),
        DurableJournalError::CapacityExceeded,
        "the refused operation is not registered, so its retry is refused again"
    );
    assert_eq!(
        file_len(&total.journal()),
        2 * frame,
        "a refusal writes no byte"
    );
    assert_eq!(journal.record_count(), 2);
    assert_eq!(durability.sync_calls(), syncs, "a refusal does not sync");
    assert!(!durability.is_failed());
}

// memory—v1: J2. The same two caps are exact for mutation frames. The mutation
// path carries its own copy of both comparisons (`prepare_mutation`), so the DENY
// test above does not cover it.
#[test]
fn j2_byte_caps_are_exact_for_mutation_frames_and_a_refusal_writes_nothing() {
    let probe = ScratchDir::new("j2-mut-probe");
    let (mut journal, durability) = create_with(&probe, DurableJournalLimits::conservative());
    append_mutation(&mut journal, &durability, &mutation_n(0));
    let frame = journal.file_position();

    let narrow = ScratchDir::new("j2-mut-frame-cap");
    let (mut journal, durability) = create_with(
        &narrow,
        DurableJournalLimits {
            max_frame_bytes: frame - 1,
            ..DurableJournalLimits::conservative()
        },
    );
    assert_eq!(
        refusal(journal.prepare_mutation(&mutation_n(0), &durability)),
        DurableJournalError::CapacityExceeded
    );
    assert_eq!(file_len(&narrow.journal()), 0);
    assert_eq!(journal.record_count(), 0);
    assert!(!durability.is_failed());

    let total = ScratchDir::new("j2-mut-file-cap");
    let (mut journal, durability) = create_with(
        &total,
        DurableJournalLimits {
            max_bytes: 2 * frame,
            max_frame_bytes: frame,
            ..DurableJournalLimits::conservative()
        },
    );
    append_mutation(&mut journal, &durability, &mutation_n(0));
    append_mutation(&mut journal, &durability, &mutation_n(1));
    assert_eq!(
        file_len(&total.journal()),
        2 * frame,
        "two frames fit exactly"
    );

    assert_eq!(
        refusal(journal.prepare_mutation(&mutation_n(2), &durability)),
        DurableJournalError::CapacityExceeded
    );
    assert_eq!(
        file_len(&total.journal()),
        2 * frame,
        "a refusal writes no byte"
    );
    assert_eq!(journal.record_count(), 2);
    assert_eq!(journal.position().mutation_sequence(), 2);
    assert!(!durability.is_failed());
}

// memory—v1: J5. A replay of a mutation under another identity is refused as an
// existing operation, and the original identity still replays. The journal
// payload does not carry the journal identity, so a request that differs from the
// recorded one only in its message id or in one of its sequences passes the
// fingerprint, mutation-digest, audit-digest and payload-digest comparisons of
// `prepare_mutation`; the identity comparison alone separates it from a replay.
// The refusal is its own variant and writes nothing.
#[test]
fn j5_mutation_replay_under_another_identity_is_refused_as_an_existing_operation() {
    let dir = ScratchDir::new("j5-identity");
    let (mut journal, durability) = create_with(&dir, DurableJournalLimits::conservative());
    let first = mutation_request("shared", [9; 32], 1, mutation_identity(1, 1, 1));
    let original = append_mutation(&mut journal, &durability, &first);
    let length = file_len(&dir.journal());
    let position = journal.file_position();

    for (label, identity) in [
        ("message id", mutation_identity(1, 1, 2)),
        ("journal sequence", mutation_identity(2, 1, 1)),
        ("mutation sequence", mutation_identity(1, 2, 1)),
    ] {
        let other = mutation_request("shared", [9; 32], 1, identity);
        assert_eq!(
            refusal(journal.prepare_mutation(&other, &durability)),
            DurableJournalError::ExistingOperation,
            "a replay that differs in its {label} is not a replay"
        );
    }
    assert_eq!(file_len(&dir.journal()), length, "a refusal writes no byte");
    assert_eq!(journal.file_position(), position);
    assert_eq!(journal.record_count(), 1);
    assert!(!durability.is_failed());

    let replay = journal
        .prepare_mutation(&first, &durability)
        .unwrap()
        .into_durable_receipt(&durability)
        .unwrap();
    assert_eq!(replay.disposition(), JournalAppendDisposition::Replayed);
    assert_eq!(replay.identity(), original.identity());
    assert_eq!(replay.tail_hash(), original.tail_hash());
}

// memory—v1: J4. A reopened journal confirms exactly the length its scan covered
// as durable, and not one byte more. An offset beyond the scanned length is one
// that nothing registered, so confirming it is refused as an invalid record; a
// confirmed prefix that overshot the file by even one byte would accept it. The
// scanned length itself is confirmed without a sync, which is the reopen gap that
// `witness_j4_reopen_marks_unsynced_tail_confirmed_without_sync` pins.
#[test]
fn j4_reopened_tail_is_confirmed_through_the_scanned_length_and_no_further() {
    let dir = ScratchDir::new("j4-exact");
    let boundaries = write_three_denies(&dir);
    let (journal, durability) = reopen(&dir).unwrap();
    assert_eq!(journal.file_position(), boundaries[2]);

    durability
        .ensure_durable(boundaries[2])
        .expect("the scanned length is confirmed");
    assert_eq!(
        refusal(durability.ensure_durable(boundaries[2] + 1)),
        DurableJournalError::InvalidRecord
    );
    assert!(!durability.is_failed());
}

// memory—v1: J4. After a failed flush the journal is sticky: the failing call
// returns the sticky error, a second call returns it without flushing again, the
// prepared frame gets no receipt, and no new frame is admitted. The failure is
// induced the way tampering would induce it: the file is cut below the written
// prefix, so the length floor after the data sync refuses the flush. The call
// runs in a thread with a deadline, because a journal without the sticky refusal
// does not return an error: it retries the failing flush forever, which an
// ordinary assertion cannot report.
#[test]
fn j4_failed_flush_is_sticky_and_returns_without_retrying() {
    let dir = ScratchDir::new("j4-sticky");
    let (mut journal, durability) = create_with(&dir, DurableJournalLimits::conservative());
    let prepared = journal
        .prepare_deny(&deny_request("sticky-1", 1, 1, 1, 1), &durability)
        .unwrap();
    let end = prepared.durable_end;
    truncate_to(&dir.journal(), end - 1);

    let durability = Arc::new(durability);
    let worker = Arc::clone(&durability);
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(worker.ensure_durable(end));
    });
    let first = receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("ensure_durable must return after a failed flush instead of retrying it forever");
    assert_eq!(first, Err(DurableJournalError::StickyUnknown));
    assert!(durability.is_failed());
    assert_eq!(durability.sync_calls(), 1);

    assert_eq!(
        durability.ensure_durable(end),
        Err(DurableJournalError::StickyUnknown)
    );
    assert_eq!(
        durability.sync_calls(),
        1,
        "a sticky refusal does not flush"
    );
    assert_eq!(
        refusal(prepared.into_durable_receipt(&durability)),
        DurableJournalError::StickyUnknown
    );
    assert_eq!(
        refusal(journal.prepare_deny(&deny_request("sticky-2", 2, 1, 2, 2), &durability)),
        DurableJournalError::StickyUnknown
    );
    assert_eq!(
        file_len(&dir.journal()),
        end - 1,
        "no byte is written after the failure"
    );
}
