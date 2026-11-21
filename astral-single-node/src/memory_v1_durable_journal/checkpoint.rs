//! memory—v1: the independent local checkpoint store beside the durable journal.
//!
//! This submodule is a pure record keeper for the per-flush-group local
//! checkpoint. It never reads the journal file and never derives identity from
//! inode, device, or path metadata: stream/epoch/baseline bindings and the
//! installation identity are supplied by the caller, and the journal-side
//! cross-checks (attach and the single-scan verifier) decide whether a record's
//! coverage matches the verified history. Recovery therefore cannot
//! self-certify: a torn slot, a foreign installation, or a rolled-back chain is
//! refused here, and an older slot is only ever adopted with its exact
//! generation and coverage reported.
//!
//! File layout: one base path (for example `<journal_dir>/journal.ckpt`)
//! derives three controlled siblings — `<base>.ckpt.lock`,
//! `<base>.ckpt.slot0`, `<base>.ckpt.slot1`. All are created only by
//! [`LocalCheckpointStore::bootstrap`]; `open` never creates files, so a
//! disaster never auto-provisions a store. Each slot holds exactly one fixed
//! 252-byte record; the writer alternates slots by generation parity and
//! synchronizes slot data after every write. The directory entry was made
//! durable at bootstrap, so later writes synchronize file data only.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sha2::{Digest, Sha256};
use thiserror::Error;

use astral_types::memory_v1::MemoryId;
use astral_types::memory_v1_journal::JournalAnchor;

use super::{configure_new_file, ensure_private_regular_file, resolve_path, DurableJournalLimits};

const CHECKPOINT_MAGIC: [u8; 8] = *b"ALM1CKPT";
const CHECKPOINT_VERSION: u16 = 1;
/// Fixed record body: generation, stream/epoch/install bindings, baseline,
/// covered anchor, journal offset, and the previous record hash.
const CHECKPOINT_BODY_LEN: usize = 208;
const CHECKPOINT_HEADER_LEN: usize = 12;
const CHECKPOINT_HASH_LEN: usize = 32;
pub(crate) const CHECKPOINT_RECORD_LEN: usize =
    CHECKPOINT_HEADER_LEN + CHECKPOINT_BODY_LEN + CHECKPOINT_HASH_LEN;
const CHECKPOINT_HASH_DOMAIN: &[u8] = b"astrallight/memory-v1/local-checkpoint/1\0";

// Body layout offsets (little-endian fields).
const OFF_GENERATION: usize = 0;
const OFF_STREAM: usize = 8;
const OFF_EPOCH: usize = 24;
const OFF_INSTALL: usize = 40;
const OFF_BASELINE_SEQ: usize = 72;
const OFF_BASELINE_MUTATION: usize = 80;
const OFF_BASELINE_HASH: usize = 88;
const OFF_JOURNAL_SEQ: usize = 120;
const OFF_MUTATION_SEQ: usize = 128;
const OFF_FRAME_HASH: usize = 136;
const OFF_JOURNAL_OFFSET: usize = 168;
const OFF_PREV_HASH: usize = 176;

/// Fail-closed errors from the checkpoint sidecar owner.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CheckpointError {
    #[error("checkpoint base path must be absolute and normalized")]
    InvalidPath,
    #[error("checkpoint parent is unavailable or uncontrolled")]
    InvalidParent,
    #[error("checkpoint installation identity must be non-zero")]
    InvalidInstallId,
    #[error("checkpoint coverage is inconsistent with the baseline or beyond limits")]
    InvalidCoverage,
    #[error("checkpoint sidecar target already exists")]
    TargetExists,
    #[error("checkpoint sidecar is missing and requires explicit bootstrap")]
    MissingCheckpoint,
    #[error("checkpoint sidecar files exist but no valid record chain is recoverable")]
    CorruptStore,
    #[error("checkpoint sidecar is bound to another installation")]
    InstallMismatch,
    #[error("checkpoint sidecar is bound to another stream, epoch, or baseline")]
    BindingMismatch,
    #[error("checkpoint coverage claims a journal offset beyond the verified tail")]
    CoverageAhead,
    #[error("checkpoint newest slot is damaged or unclear; ordinary startup refuses")]
    UnclearNewestSlot,
    #[error("checkpoint coverage does not match the journal's verified history")]
    CoverageMismatch,
    #[error("checkpoint coverage {record_offset} is behind the journal tail {journal_offset}")]
    CoverageBehind {
        record_offset: u64,
        journal_offset: u64,
    },
    #[error("checkpoint owner is already attached to this journal")]
    AlreadyAttached,
    #[error("checkpoint sidecar writer lock is unavailable")]
    LockUnavailable,
    #[error("checkpoint sidecar writer lock is unsupported")]
    LockUnsupported,
    #[error("checkpoint generation space is exhausted")]
    CapacityExceeded,
    #[error("checkpoint slot write outcome is unknown")]
    UnknownAfterIo,
    #[error("checkpoint slot changed during the write")]
    FileChanged,
    #[error("checkpoint I/O failed during {operation:?}: {kind:?}")]
    Io {
        operation: CheckpointIoOperation,
        kind: io::ErrorKind,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointIoOperation {
    CreateLock,
    CreateSlot,
    OpenLock,
    OpenSlot,
    LockStore,
    SeekSlot,
    WriteSlot,
    ReadSlot,
    InspectSlot,
    SyncSlot,
    SyncParent,
}

/// The external installation identity carried inside every checkpoint record.
///
/// It must be supplied by the deployment (wiring) owner — never derived from
/// inode, device, path, or wall-clock metadata. Wiring derives stream/epoch/
/// genesis from one non-zero installation UUID and passes that same UUID here.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CheckpointInstallId([u8; 32]);

impl std::fmt::Debug for CheckpointInstallId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CheckpointInstallId([REDACTED])")
    }
}

impl CheckpointInstallId {
    /// Adopt an externally supplied 32-byte installation identity.
    pub fn new(bytes: [u8; 32]) -> Result<Self, CheckpointError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(CheckpointError::InvalidInstallId);
        }
        Ok(Self(bytes))
    }

    /// Adopt the wiring owner's non-zero installation UUID verbatim.
    pub fn from_install_uuid(uuid: [u8; 16]) -> Result<Self, CheckpointError> {
        if uuid.iter().all(|byte| *byte == 0) {
            return Err(CheckpointError::InvalidInstallId);
        }
        let mut bytes = [0_u8; 32];
        bytes[..16].copy_from_slice(&uuid);
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The journal facts one checkpoint record covers: the anchor of the frame that
/// ends at `journal_offset`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalCheckpointCoverage {
    journal_sequence: u64,
    mutation_sequence: u64,
    frame_hash: [u8; 32],
    journal_offset: u64,
}

impl LocalCheckpointCoverage {
    /// Derive the coverage of a verified journal tail anchor at its file offset.
    pub fn from_anchor(anchor: JournalAnchor, journal_offset: u64) -> Self {
        Self {
            journal_sequence: anchor.journal_sequence(),
            mutation_sequence: anchor.mutation_sequence(),
            frame_hash: *anchor.frame_hash(),
            journal_offset,
        }
    }

    pub const fn journal_sequence(&self) -> u64 {
        self.journal_sequence
    }

    pub const fn mutation_sequence(&self) -> u64 {
        self.mutation_sequence
    }

    pub const fn frame_hash(&self) -> &[u8; 32] {
        &self.frame_hash
    }

    pub const fn journal_offset(&self) -> u64 {
        self.journal_offset
    }
}

/// How [`LocalCheckpointStore::open`] recovered the current record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointOpenStatus {
    /// Both slots hold valid, consecutive, chain-linked generations.
    Complete,
    /// Exactly the bootstrap generation 1 record is present (the normal state
    /// of a genesis sidecar before the first group commit flush; slot 0 is
    /// still empty by construction).
    BootstrapOnly,
}

/// One persisted checkpoint record.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct LocalCheckpointRecord {
    generation: u64,
    stream_id: MemoryId,
    epoch_id: MemoryId,
    install_id: [u8; 32],
    baseline: JournalAnchor,
    coverage: LocalCheckpointCoverage,
    prev_record_hash: [u8; 32],
    record_hash: [u8; 32],
}

impl std::fmt::Debug for LocalCheckpointRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LocalCheckpointRecord(gen {}, offset {})",
            self.generation, self.coverage.journal_offset
        )
    }
}

impl LocalCheckpointRecord {
    fn build(
        generation: u64,
        stream_id: MemoryId,
        epoch_id: MemoryId,
        install_id: &[u8; 32],
        baseline: JournalAnchor,
        coverage: LocalCheckpointCoverage,
        prev_record_hash: [u8; 32],
    ) -> Self {
        let mut record = Self {
            generation,
            stream_id,
            epoch_id,
            install_id: *install_id,
            baseline,
            coverage,
            prev_record_hash,
            record_hash: [0; 32],
        };
        record.record_hash = record_hash(&record.encode_body());
        record
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn stream_id(&self) -> MemoryId {
        self.stream_id
    }

    pub const fn epoch_id(&self) -> MemoryId {
        self.epoch_id
    }

    /// The installation identity bytes; compare through
    /// [`CheckpointInstallId::as_bytes`].
    pub const fn install_id_bytes(&self) -> &[u8; 32] {
        &self.install_id
    }

    pub const fn baseline(&self) -> JournalAnchor {
        self.baseline
    }

    pub const fn coverage(&self) -> LocalCheckpointCoverage {
        self.coverage
    }

    /// The covered journal file offset.
    pub const fn journal_offset(&self) -> u64 {
        self.coverage.journal_offset
    }

    /// The covered journal sequence.
    pub const fn journal_sequence(&self) -> u64 {
        self.coverage.journal_sequence
    }

    /// The covered mutation sequence.
    pub const fn mutation_sequence(&self) -> u64 {
        self.coverage.mutation_sequence
    }

    /// The covered journal tail as an anchor shape; `None` is unreachable for
    /// decoded or built records (stream and frame hash are validated non-zero).
    pub fn coverage_anchor(&self) -> Option<JournalAnchor> {
        JournalAnchor::new(
            self.stream_id,
            self.coverage.journal_sequence,
            self.coverage.mutation_sequence,
            self.coverage.frame_hash,
        )
        .ok()
    }

    pub const fn prev_record_hash(&self) -> &[u8; 32] {
        &self.prev_record_hash
    }

    pub const fn record_hash(&self) -> &[u8; 32] {
        &self.record_hash
    }

    /// Whether this record's coverage names exactly `anchor` at `journal_offset`.
    pub(crate) fn covers(&self, journal_offset: u64, anchor: JournalAnchor) -> bool {
        self.coverage.journal_offset == journal_offset
            && self.coverage.journal_sequence == anchor.journal_sequence()
            && self.coverage.mutation_sequence == anchor.mutation_sequence()
            && self.coverage.frame_hash == *anchor.frame_hash()
    }

    fn encode_body(&self) -> [u8; CHECKPOINT_BODY_LEN] {
        let mut body = [0_u8; CHECKPOINT_BODY_LEN];
        body[OFF_GENERATION..OFF_GENERATION + 8].copy_from_slice(&self.generation.to_le_bytes());
        body[OFF_STREAM..OFF_STREAM + 16].copy_from_slice(self.stream_id.as_bytes());
        body[OFF_EPOCH..OFF_EPOCH + 16].copy_from_slice(self.epoch_id.as_bytes());
        body[OFF_INSTALL..OFF_INSTALL + 32].copy_from_slice(&self.install_id);
        body[OFF_BASELINE_SEQ..OFF_BASELINE_SEQ + 8]
            .copy_from_slice(&self.baseline.journal_sequence().to_le_bytes());
        body[OFF_BASELINE_MUTATION..OFF_BASELINE_MUTATION + 8]
            .copy_from_slice(&self.baseline.mutation_sequence().to_le_bytes());
        body[OFF_BASELINE_HASH..OFF_BASELINE_HASH + 32].copy_from_slice(self.baseline.frame_hash());
        body[OFF_JOURNAL_SEQ..OFF_JOURNAL_SEQ + 8]
            .copy_from_slice(&self.coverage.journal_sequence.to_le_bytes());
        body[OFF_MUTATION_SEQ..OFF_MUTATION_SEQ + 8]
            .copy_from_slice(&self.coverage.mutation_sequence.to_le_bytes());
        body[OFF_FRAME_HASH..OFF_FRAME_HASH + 32].copy_from_slice(&self.coverage.frame_hash);
        body[OFF_JOURNAL_OFFSET..OFF_JOURNAL_OFFSET + 8]
            .copy_from_slice(&self.coverage.journal_offset.to_le_bytes());
        body[OFF_PREV_HASH..OFF_PREV_HASH + 32].copy_from_slice(&self.prev_record_hash);
        body
    }

    /// The exact 252-byte slot image.
    fn encode(&self) -> [u8; CHECKPOINT_RECORD_LEN] {
        let body = self.encode_body();
        let mut bytes = [0_u8; CHECKPOINT_RECORD_LEN];
        bytes[..8].copy_from_slice(&CHECKPOINT_MAGIC);
        bytes[8..10].copy_from_slice(&CHECKPOINT_VERSION.to_le_bytes());
        bytes[10..12].copy_from_slice(&(CHECKPOINT_BODY_LEN as u16).to_le_bytes());
        bytes[CHECKPOINT_HEADER_LEN..CHECKPOINT_HEADER_LEN + CHECKPOINT_BODY_LEN]
            .copy_from_slice(&body);
        let hash = record_hash(&body);
        bytes[CHECKPOINT_HEADER_LEN + CHECKPOINT_BODY_LEN..].copy_from_slice(&hash);
        bytes
    }

    /// Parse a slot image. Returns `None` for a torn, foreign-format, or
    /// checksum-invalid image; shape validation only.
    fn decode(bytes: &[u8; CHECKPOINT_RECORD_LEN]) -> Option<Self> {
        if bytes[..8] != CHECKPOINT_MAGIC {
            return None;
        }
        let version = u16::from_le_bytes(bytes[8..10].try_into().ok()?);
        if version != CHECKPOINT_VERSION {
            return None;
        }
        let body_len = u16::from_le_bytes(bytes[10..12].try_into().ok()?);
        if body_len as usize != CHECKPOINT_BODY_LEN {
            return None;
        }
        let body = &bytes[CHECKPOINT_HEADER_LEN..CHECKPOINT_HEADER_LEN + CHECKPOINT_BODY_LEN];
        if record_hash(body) != bytes[CHECKPOINT_HEADER_LEN + CHECKPOINT_BODY_LEN..] {
            return None;
        }
        let generation =
            u64::from_le_bytes(body[OFF_GENERATION..OFF_GENERATION + 8].try_into().ok()?);
        if generation == 0 {
            return None;
        }
        let stream_bytes: [u8; 16] = body[OFF_STREAM..OFF_STREAM + 16].try_into().ok()?;
        if stream_bytes.iter().all(|byte| *byte == 0) {
            return None;
        }
        let stream_id = MemoryId::from_bytes(stream_bytes);
        let epoch_bytes: [u8; 16] = body[OFF_EPOCH..OFF_EPOCH + 16].try_into().ok()?;
        if epoch_bytes.iter().all(|byte| *byte == 0) {
            return None;
        }
        let epoch_id = MemoryId::from_bytes(epoch_bytes);
        let install: [u8; 32] = body[OFF_INSTALL..OFF_INSTALL + 32].try_into().ok()?;
        if install.iter().all(|byte| *byte == 0) {
            return None;
        }
        let baseline_sequence = u64::from_le_bytes(
            body[OFF_BASELINE_SEQ..OFF_BASELINE_SEQ + 8]
                .try_into()
                .ok()?,
        );
        let baseline_mutation = u64::from_le_bytes(
            body[OFF_BASELINE_MUTATION..OFF_BASELINE_MUTATION + 8]
                .try_into()
                .ok()?,
        );
        let baseline_hash: [u8; 32] = body[OFF_BASELINE_HASH..OFF_BASELINE_HASH + 32]
            .try_into()
            .ok()?;
        let baseline = JournalAnchor::new(
            stream_id,
            baseline_sequence,
            baseline_mutation,
            baseline_hash,
        )
        .ok()?;
        let journal_sequence =
            u64::from_le_bytes(body[OFF_JOURNAL_SEQ..OFF_JOURNAL_SEQ + 8].try_into().ok()?);
        let mutation_sequence = u64::from_le_bytes(
            body[OFF_MUTATION_SEQ..OFF_MUTATION_SEQ + 8]
                .try_into()
                .ok()?,
        );
        let frame_hash: [u8; 32] = body[OFF_FRAME_HASH..OFF_FRAME_HASH + 32].try_into().ok()?;
        if frame_hash.iter().all(|byte| *byte == 0) {
            return None;
        }
        let journal_offset = u64::from_le_bytes(
            body[OFF_JOURNAL_OFFSET..OFF_JOURNAL_OFFSET + 8]
                .try_into()
                .ok()?,
        );
        let prev_record_hash: [u8; 32] = body[OFF_PREV_HASH..OFF_PREV_HASH + 32].try_into().ok()?;
        Some(Self {
            generation,
            stream_id,
            epoch_id,
            install_id: install,
            baseline,
            coverage: LocalCheckpointCoverage {
                journal_sequence,
                mutation_sequence,
                frame_hash,
                journal_offset,
            },
            prev_record_hash,
            record_hash: record_hash(body),
        })
    }
}

fn record_hash(body: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(CHECKPOINT_HASH_DOMAIN);
    hash.update(body);
    hash.finalize().into()
}

struct SlotPaths {
    lock: PathBuf,
    slot0: PathBuf,
    slot1: PathBuf,
}

fn slot_paths(base: &Path) -> Result<SlotPaths, CheckpointError> {
    let resolved = resolve_path(base).map_err(|error| match error {
        super::DurableJournalError::InvalidPath => CheckpointError::InvalidPath,
        super::DurableJournalError::InvalidParent => CheckpointError::InvalidParent,
        _ => CheckpointError::InvalidParent,
    })?;
    let name = resolved
        .target
        .file_name()
        .ok_or(CheckpointError::InvalidPath)?;
    let mut lock_name = name.to_os_string();
    lock_name.push(".ckpt.lock");
    let mut slot0_name = name.to_os_string();
    slot0_name.push(".ckpt.slot0");
    let mut slot1_name = name.to_os_string();
    slot1_name.push(".ckpt.slot1");
    Ok(SlotPaths {
        lock: resolved.parent.join(lock_name),
        slot0: resolved.parent.join(slot0_name),
        slot1: resolved.parent.join(slot1_name),
    })
}

fn io_error(operation: CheckpointIoOperation, error: io::Error) -> CheckpointError {
    CheckpointError::Io {
        operation,
        kind: error.kind(),
    }
}

fn create_controlled_file(
    path: &Path,
    operation: CheckpointIoOperation,
) -> Result<File, CheckpointError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                CheckpointError::TargetExists
            } else {
                io_error(operation, error)
            }
        })?;
    configure_new_file(&file).map_err(|error| match error {
        super::DurableJournalError::Io { kind, .. } => CheckpointError::Io { operation, kind },
        super::DurableJournalError::InvalidTarget => CheckpointError::Io {
            operation,
            kind: io::ErrorKind::Other,
        },
        _ => CheckpointError::Io {
            operation,
            kind: io::ErrorKind::Other,
        },
    })?;
    Ok(file)
}

fn open_controlled_file(
    path: &Path,
    operation: CheckpointIoOperation,
) -> Result<File, CheckpointError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                CheckpointError::CorruptStore
            } else {
                io_error(operation, error)
            }
        })?;
    ensure_private_regular_file(&file).map_err(|error| match error {
        super::DurableJournalError::Io { kind, .. } => CheckpointError::Io { operation, kind },
        super::DurableJournalError::InvalidTarget => CheckpointError::CorruptStore,
        _ => CheckpointError::CorruptStore,
    })?;
    Ok(file)
}

fn lock_store(file: &File) -> Result<(), CheckpointError> {
    file.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => CheckpointError::LockUnavailable,
        TryLockError::Error(error) if error.kind() == io::ErrorKind::Unsupported => {
            CheckpointError::LockUnsupported
        }
        TryLockError::Error(error) => io_error(CheckpointIoOperation::LockStore, error),
    })
}

/// One slot's on-disk state after a bounded read.
enum SlotState {
    /// The slot was never written (zero length). Only the bootstrap record's
    /// companion slot is legitimately empty.
    Empty,
    /// A nonzero-length slot that holds no decodable record: a torn write,
    /// foreign bytes, or a damaged file.
    Undecodable,
    /// A structurally valid record (binding checked separately).
    Valid(Box<LocalCheckpointRecord>),
}

/// Read one slot and classify its image. A zero-length slot was never
/// written; anything else that is not a decodable record is torn or foreign —
/// the distinction matters because a torn newest slot means the newest
/// generation's outcome is unknown.
fn slot_state(slot: &mut File) -> Result<SlotState, CheckpointError> {
    let length = slot
        .metadata()
        .map_err(|error| io_error(CheckpointIoOperation::InspectSlot, error))?
        .len();
    if length == 0 {
        return Ok(SlotState::Empty);
    }
    if length != CHECKPOINT_RECORD_LEN as u64 {
        return Ok(SlotState::Undecodable);
    }
    slot.seek(SeekFrom::Start(0))
        .map_err(|error| io_error(CheckpointIoOperation::SeekSlot, error))?;
    let mut bytes = [0_u8; CHECKPOINT_RECORD_LEN];
    slot.read_exact(&mut bytes)
        .map_err(|error| io_error(CheckpointIoOperation::ReadSlot, error))?;
    Ok(LocalCheckpointRecord::decode(&bytes)
        .map(|record| SlotState::Valid(Box::new(record)))
        .unwrap_or(SlotState::Undecodable))
}

/// Overwrite one slot with the exact record image and synchronize its data.
fn write_slot(slot: &mut File, record: &LocalCheckpointRecord) -> Result<(), CheckpointError> {
    let bytes = record.encode();
    slot.seek(SeekFrom::Start(0))
        .map_err(|error| io_error(CheckpointIoOperation::SeekSlot, error))?;
    let mut written = 0_usize;
    while written < bytes.len() {
        let count = slot
            .write(&bytes[written..])
            .map_err(|error| io_error(CheckpointIoOperation::WriteSlot, error))?;
        if count == 0 || count > bytes.len() - written {
            return Err(CheckpointError::UnknownAfterIo);
        }
        written += count;
    }
    let actual = slot
        .metadata()
        .map_err(|error| io_error(CheckpointIoOperation::InspectSlot, error))?
        .len();
    if actual != written as u64 {
        return Err(CheckpointError::FileChanged);
    }
    slot.sync_data()
        .map_err(|error| io_error(CheckpointIoOperation::SyncSlot, error))?;
    Ok(())
}

/// The exclusive local writer/reader for the checkpoint sidecar files.
///
/// The store owns the lock file handle for its lifetime; dropping it releases
/// the lock. One store per installation per base path: a second concurrent
/// holder (writer or recovery reader) receives `LockUnavailable`.
pub struct LocalCheckpointStore {
    /// Holds the writer/reader flock for the store's lifetime; the field is
    /// never read again, and dropping the store releases the lock.
    #[allow(dead_code)]
    lock_file: File,
    state: Mutex<StoreState>,
}

struct StoreState {
    slots: [File; 2],
    latest: LocalCheckpointRecord,
}

impl std::fmt::Debug for LocalCheckpointStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalCheckpointStore([REDACTED])")
    }
}

impl LocalCheckpointStore {
    /// Explicitly create the sidecar and write generation 1 covering `initial`.
    ///
    /// `initial` must come from an independently verified journal state (for a
    /// fresh journal the baseline anchor at offset 0; for a legacy journal the
    /// verified tail of a completed `open`/`scan_tail`). This constructor never
    /// reads the journal and never overwrites an existing store: any existing
    /// controlled file is `TargetExists`, so a disaster can only be repaired by
    /// an explicit out-of-band deletion followed by this bootstrap.
    pub fn bootstrap(
        base: &Path,
        install_id: CheckpointInstallId,
        stream_id: MemoryId,
        epoch_id: MemoryId,
        baseline: JournalAnchor,
        initial: LocalCheckpointCoverage,
        limits: DurableJournalLimits,
    ) -> Result<(Self, LocalCheckpointRecord), CheckpointError> {
        if stream_id.as_bytes().iter().all(|byte| *byte == 0)
            || epoch_id.as_bytes().iter().all(|byte| *byte == 0)
            || baseline.stream_id() != stream_id
        {
            return Err(CheckpointError::BindingMismatch);
        }
        if initial.journal_sequence < baseline.journal_sequence()
            || initial.mutation_sequence < baseline.mutation_sequence()
            || initial.journal_offset > limits.max_bytes
        {
            return Err(CheckpointError::InvalidCoverage);
        }
        if initial.journal_sequence == baseline.journal_sequence()
            && (initial.mutation_sequence != baseline.mutation_sequence()
                || initial.frame_hash() != baseline.frame_hash())
        {
            return Err(CheckpointError::InvalidCoverage);
        }
        let paths = slot_paths(base)?;
        for path in [&paths.lock, &paths.slot0, &paths.slot1] {
            if fs::symlink_metadata(path).is_ok() {
                return Err(CheckpointError::TargetExists);
            }
        }
        let lock_file = create_controlled_file(&paths.lock, CheckpointIoOperation::CreateLock)?;
        lock_store(&lock_file)?;
        let slot0 = create_controlled_file(&paths.slot0, CheckpointIoOperation::CreateSlot)?;
        let slot1 = create_controlled_file(&paths.slot1, CheckpointIoOperation::CreateSlot)?;
        let first = LocalCheckpointRecord::build(
            1,
            stream_id,
            epoch_id,
            install_id.as_bytes(),
            baseline,
            initial,
            [0; 32],
        );
        // Generation 1 lives in slot 1 (generation % 2); slot 0 stays empty
        // until generation 2. Both directory entries are made durable here.
        let mut slot1 = slot1;
        write_slot(&mut slot1, &first)?;
        sync_slot_files(&[&lock_file, &slot0, &slot1])?;
        sync_parent(base)?;
        Ok((
            Self {
                lock_file,
                state: Mutex::new(StoreState {
                    slots: [slot0, slot1],
                    latest: first,
                }),
            },
            first,
        ))
    }

    /// Open an existing sidecar, validate its binding, and report the newest
    /// recoverable record.
    ///
    /// `open` never creates, repairs, or truncates anything. Missing slot files
    /// mean the store was never bootstrapped (`MissingCheckpoint`); files that
    /// exist without a recoverable record chain are `CorruptStore` and require
    /// explicit out-of-band deletion before a fresh bootstrap.
    pub fn open(
        base: &Path,
        install_id: CheckpointInstallId,
        stream_id: MemoryId,
        epoch_id: MemoryId,
        baseline: JournalAnchor,
        limits: DurableJournalLimits,
    ) -> Result<(Self, LocalCheckpointRecord, CheckpointOpenStatus), CheckpointError> {
        if stream_id.as_bytes().iter().all(|byte| *byte == 0)
            || epoch_id.as_bytes().iter().all(|byte| *byte == 0)
            || baseline.stream_id() != stream_id
        {
            return Err(CheckpointError::BindingMismatch);
        }
        let paths = slot_paths(base)?;
        let slot0_present = fs::symlink_metadata(&paths.slot0).is_ok();
        let slot1_present = fs::symlink_metadata(&paths.slot1).is_ok();
        if !slot0_present && !slot1_present {
            return Err(CheckpointError::MissingCheckpoint);
        }
        let lock_file = open_controlled_file(&paths.lock, CheckpointIoOperation::OpenLock)?;
        lock_store(&lock_file)?;
        let mut slot0 = open_controlled_file(&paths.slot0, CheckpointIoOperation::OpenSlot)?;
        let mut slot1 = open_controlled_file(&paths.slot1, CheckpointIoOperation::OpenSlot)?;
        let slot0_state = bound_state(
            slot_state(&mut slot0)?,
            install_id,
            stream_id,
            epoch_id,
            baseline,
        )?;
        let slot1_state = bound_state(
            slot_state(&mut slot1)?,
            install_id,
            stream_id,
            epoch_id,
            baseline,
        )?;
        let (latest, status) = classify_slots(slot0_state, slot1_state)?;
        if latest.coverage.journal_offset > limits.max_bytes {
            return Err(CheckpointError::InvalidCoverage);
        }
        Ok((
            Self {
                lock_file,
                state: Mutex::new(StoreState {
                    slots: [slot0, slot1],
                    latest,
                }),
            },
            latest,
            status,
        ))
    }

    /// Append the next generation covering `coverage`. The caller must hold the
    /// journal writer lease; slot writes are otherwise serialized by the flush
    /// leader protocol. The record is synchronized before returning. A failed
    /// write leaves the in-memory latest untouched; the torn slot is refused
    /// by the next open.
    pub(crate) fn append(
        &self,
        coverage: LocalCheckpointCoverage,
    ) -> Result<LocalCheckpointRecord, CheckpointError> {
        let mut state = self.state.lock().unwrap();
        let generation = state
            .latest
            .generation
            .checked_add(1)
            .ok_or(CheckpointError::CapacityExceeded)?;
        let record = LocalCheckpointRecord::build(
            generation,
            state.latest.stream_id,
            state.latest.epoch_id,
            &state.latest.install_id,
            state.latest.baseline,
            coverage,
            state.latest.record_hash,
        );
        let slot_index = (generation % 2) as usize;
        write_slot(&mut state.slots[slot_index], &record)?;
        state.latest = record;
        Ok(record)
    }

    /// The newest record known to this store handle.
    pub(crate) fn latest_record(&self) -> LocalCheckpointRecord {
        self.state.lock().unwrap().latest
    }
}

impl LocalCheckpointRecord {
    /// Reject a structurally valid record bound to another installation,
    /// stream, epoch, or baseline.
    fn accept_binding(
        self,
        install_id: CheckpointInstallId,
        stream_id: MemoryId,
        epoch_id: MemoryId,
        baseline: JournalAnchor,
    ) -> Result<Self, CheckpointError> {
        if self.install_id != *install_id.as_bytes() {
            return Err(CheckpointError::InstallMismatch);
        }
        if self.stream_id != stream_id || self.epoch_id != epoch_id || self.baseline != baseline {
            return Err(CheckpointError::BindingMismatch);
        }
        Ok(self)
    }
}

/// Keep empty and undecodable slots as they are; check the binding of a valid
/// record and refuse a foreign one immediately.
fn bound_state(
    state: SlotState,
    install_id: CheckpointInstallId,
    stream_id: MemoryId,
    epoch_id: MemoryId,
    baseline: JournalAnchor,
) -> Result<SlotState, CheckpointError> {
    match state {
        SlotState::Valid(record) => Ok(SlotState::Valid(Box::new(
            record.accept_binding(install_id, stream_id, epoch_id, baseline)?,
        ))),
        other => Ok(other),
    }
}

/// Classify the two slot states and return the newest record.
///
/// Slot membership follows generation parity, not position: generation `g`
/// lives in slot `g % 2`, so slot 0 holds even generations and slot 1 odd
/// ones. Two valid records must sit in their parity slots, be consecutive
/// generations (`checked_add`, overflow refused), and chain-link through
/// `prev_record_hash`; anything else is a corrupt or rolled-back store. A
/// valid record paired with a truly empty slot is accepted only for the
/// bootstrap generation 1 in slot 1 (slot 0 unwritten by construction). A
/// valid record paired with an undecodable slot means the newest generation's
/// outcome is unclear, and ordinary startup conservatively refuses it.
fn classify_slots(
    slot0: SlotState,
    slot1: SlotState,
) -> Result<(LocalCheckpointRecord, CheckpointOpenStatus), CheckpointError> {
    match (slot0, slot1) {
        (SlotState::Valid(a), SlotState::Valid(b)) => {
            // Slot parity: slot 0 holds even generations, slot 1 odd ones.
            if a.generation % 2 != 0 || b.generation % 2 != 1 {
                return Err(CheckpointError::CorruptStore);
            }
            let (older, newer) = if a.generation < b.generation {
                (a, b)
            } else {
                (b, a)
            };
            if newer.generation
                != older
                    .generation
                    .checked_add(1)
                    .ok_or(CheckpointError::CorruptStore)?
                || newer.prev_record_hash != older.record_hash
            {
                return Err(CheckpointError::CorruptStore);
            }
            Ok((*newer, CheckpointOpenStatus::Complete))
        }
        (SlotState::Valid(record), SlotState::Empty)
        | (SlotState::Empty, SlotState::Valid(record)) => {
            // Only the bootstrap state pairs a record with a truly empty
            // slot: generation 1 lives in slot 1, whose companion slot 0 has
            // never been written.
            if record.generation == 1 && record.generation % 2 == 1 {
                Ok((*record, CheckpointOpenStatus::BootstrapOnly))
            } else {
                Err(CheckpointError::CorruptStore)
            }
        }
        (SlotState::Valid(_), SlotState::Undecodable)
        | (SlotState::Undecodable, SlotState::Valid(_)) => Err(CheckpointError::UnclearNewestSlot),
        (SlotState::Empty, SlotState::Empty)
        | (SlotState::Undecodable, SlotState::Undecodable)
        | (SlotState::Empty, SlotState::Undecodable)
        | (SlotState::Undecodable, SlotState::Empty) => Err(CheckpointError::CorruptStore),
    }
}

fn sync_slot_files(files: &[&File]) -> Result<(), CheckpointError> {
    for file in files {
        file.sync_all()
            .map_err(|error| io_error(CheckpointIoOperation::SyncSlot, error))?;
    }
    Ok(())
}

fn sync_parent(base: &Path) -> Result<(), CheckpointError> {
    let resolved = resolve_path(base).map_err(|_| CheckpointError::InvalidParent)?;
    let directory = File::open(&resolved.parent)
        .map_err(|error| io_error(CheckpointIoOperation::SyncParent, error))?;
    // Keep the fd alive until the synchronization completes.
    let _fd = directory.as_fd();
    directory
        .sync_all()
        .map_err(|error| io_error(CheckpointIoOperation::SyncParent, error))
}
