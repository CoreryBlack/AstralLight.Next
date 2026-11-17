//! memory—v1: the single durable local-journal owner.
//!
//! This module is the narrow owner between a typed governance mutation and the
//! local A/A1 journal. It owns one stream/epoch, one exclusively locked file,
//! the bounded replay index reconstructed from that file, and the only proof
//! issuance point in this crate. It does not publish a root, apply MySQL, or
//! expose an HTTP route.
//!
//! A returned [`LocalDurablePrefixReceipt`] means that the exact frame was written,
//! the file and parent directory were synchronised, and the complete verified
//! prefix now ends at the returned tail. It remains a local durable-prefix
//! proof: adoption, root atomic publication, audit completeness, and physical
//! power-loss guarantees are separate contracts.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};

use astral_types::memory_v1::MemoryId;
use astral_types::memory_v1_journal::{
    decode_record, encode_record, frame_length, JournalAnchor, JournalError, JournalRecord,
    JournalVerifier, RecordKind, FRAME_PREFIX_BYTES, MAX_FRAME_BYTES,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use astral_trustgraph::service::memory_v1_mutation_coordinator::{
    decode_deny_journal_payload, decode_journal_payload, JournalIdentity, MutationRequest,
};

const MAX_OPERATION_ID_BYTES: usize = 64;
const PAYLOAD_DIGEST_DOMAIN: &[u8] = b"astrallight/memory-v1/durable-journal/payload/1\0";

/// Finite limits for one durable local journal owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableJournalLimits {
    pub max_records: u64,
    pub max_bytes: u64,
    pub max_frame_bytes: u64,
}

impl DurableJournalLimits {
    pub fn new(
        max_records: u64,
        max_bytes: u64,
        max_frame_bytes: u64,
    ) -> Result<Self, DurableJournalError> {
        let limits = Self {
            max_records,
            max_bytes,
            max_frame_bytes,
        };
        if max_records == 0
            || max_bytes == 0
            || max_frame_bytes == 0
            || max_frame_bytes > MAX_FRAME_BYTES as u64
            || max_frame_bytes > max_bytes
        {
            return Err(DurableJournalError::InvalidLimits);
        }
        JournalVerifier::new(
            JournalAnchor::new(MemoryId::from_bytes([1; 16]), 0, 0, [1; 32])
                .map_err(DurableJournalError::Frame)?,
            max_records,
            max_bytes,
        )
        .map_err(DurableJournalError::Frame)?;
        Ok(limits)
    }

    pub const fn conservative() -> Self {
        Self {
            max_records: 65_536,
            max_bytes: 512 * 1024 * 1024,
            max_frame_bytes: MAX_FRAME_BYTES as u64,
        }
    }
}

/// Lifecycle of the unique writer owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableJournalState {
    Ready,
    StickyUnknown,
}

/// Fail-closed errors from the durable journal owner.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DurableJournalError {
    #[error("durable journal limits are invalid")]
    InvalidLimits,
    #[error("durable journal path must be absolute and normalized")]
    InvalidPath,
    #[error("durable journal parent is unavailable or uncontrolled")]
    InvalidParent,
    #[error("durable journal target is missing or not a private regular file")]
    InvalidTarget,
    #[error("durable journal target already exists")]
    TargetExists,
    #[error("durable journal target is an untrusted empty baseline")]
    EmptyExistingFile,
    #[error("durable journal writer lock is unavailable")]
    LockUnavailable,
    #[error("durable journal writer lock is unsupported")]
    LockUnsupported,
    #[error("durable journal is sticky unknown and requires reconciliation")]
    StickyUnknown,
    #[error("durable journal I/O outcome is unknown")]
    UnknownAfterIo,
    #[error("durable journal capacity is exhausted")]
    CapacityExceeded,
    #[error("durable journal operation identity conflicts with an existing record")]
    OperationConflict,
    #[error("durable journal operation is already recorded with another identity")]
    ExistingOperation,
    #[error("durable journal stream, epoch, or sequence does not match the owner")]
    SequenceMismatch,
    #[error("durable journal record is invalid")]
    InvalidRecord,
    #[error("durable journal file changed during verification")]
    FileChanged,
    #[error("durable journal frame validation failed: {0:?}")]
    Frame(JournalError),
    #[error("durable journal I/O failed during {operation:?}: {kind:?}")]
    Io {
        operation: IoOperation,
        kind: io::ErrorKind,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoOperation {
    ResolvePath,
    OpenParent,
    InspectTarget,
    CreateTarget,
    OpenTarget,
    LockTarget,
    Seek,
    Read,
    Write,
    InspectLength,
    SyncFile,
    SyncParent,
}

/// Whether one call appended a new frame or reconciled an already durable one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalAppendDisposition {
    Appended,
    Replayed,
}

/// `JournalDurableProof`: a separate production issuer must bind this receipt to
/// the coordinator only after recovery/adoption and root publication rules are
/// closed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalDurablePrefixReceipt {
    operation_id: String,
    request_fingerprint: [u8; 32],
    mutation_digest: [u8; 32],
    audit_digest: [u8; 32],
    identity: JournalIdentity,
    tail_hash: [u8; 32],
    disposition: JournalAppendDisposition,
    start_offset: u64,
    end_offset: u64,
}

impl LocalDurablePrefixReceipt {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub const fn request_fingerprint(&self) -> &[u8; 32] {
        &self.request_fingerprint
    }

    pub const fn mutation_digest(&self) -> [u8; 32] {
        self.mutation_digest
    }

    pub const fn audit_digest(&self) -> [u8; 32] {
        self.audit_digest
    }

    pub const fn identity(&self) -> JournalIdentity {
        self.identity
    }

    pub const fn tail_hash(&self) -> &[u8; 32] {
        &self.tail_hash
    }

    pub const fn disposition(&self) -> JournalAppendDisposition {
        self.disposition
    }

    pub const fn start_offset(&self) -> u64 {
        self.start_offset
    }

    pub const fn end_offset(&self) -> u64 {
        self.end_offset
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StoredIdentity {
    stream_id: MemoryId,
    epoch_id: MemoryId,
    journal_sequence: u64,
    mutation_sequence: u64,
    message_id: MemoryId,
}

impl StoredIdentity {
    fn from_record(record: &JournalRecord<'_>, epoch_id: MemoryId) -> Self {
        Self {
            stream_id: record.stream_id,
            epoch_id,
            journal_sequence: record.journal_sequence,
            mutation_sequence: record.mutation_sequence,
            message_id: record.message_id,
        }
    }

    fn mutation_identity(self) -> Result<JournalIdentity, DurableJournalError> {
        JournalIdentity::new(
            self.stream_id,
            self.epoch_id,
            self.journal_sequence,
            self.mutation_sequence,
            self.message_id,
        )
        .map_err(|_| DurableJournalError::InvalidRecord)
    }

    /// Round-trip a stored DENY identity, which may carry the zero baseline
    /// mutation sequence that the strict mutation constructor rejects.
    fn mutation_identity_deny(self) -> Option<JournalIdentity> {
        JournalIdentity::new_deny(
            self.stream_id,
            self.epoch_id,
            self.journal_sequence,
            self.mutation_sequence,
            self.message_id,
        )
        .ok()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StoredOperation {
    fingerprint: [u8; 32],
    payload_digest: [u8; 32],
    mutation_digest: Option<[u8; 32]>,
    audit_digest: Option<[u8; 32]>,
    identity: StoredIdentity,
    kind: RecordKind,
    tail_hash: [u8; 32],
}

/// memory—v1: The durability coordinator for one opened journal file.
///
/// The contract revision this type implements: the directory entry is made
/// durable once, at creation (fsync file + fsync directory); every append
/// extends an already-durable entry and therefore requires only the file's
/// data synchronization (`fdatasync`), which always flushes the file size
/// needed for later retrieval. This is the same model PostgreSQL uses for its
/// WAL (`wal_sync_method = fdatasync`).
///
/// Group commit: fsync durability is monotone over the file prefix — one
/// `fdatasync` makes every byte written before it durable. Writers register
/// their end offset and wait on a durable watermark; concurrent writers share
/// one synchronization, so the per-commit fsync cost amortizes to
/// `fsync_time / batch_size` under load without weakening the contract: an
/// acknowledged mutation still implies its bytes and every prior byte are on
/// disk before the receipt is returned.
pub struct JournalDurability {
    file: File,
    state: Mutex<SyncState>,
    cv: Condvar,
    latest_written: AtomicU64,
    #[cfg(test)]
    sync_calls: AtomicU64,
    #[cfg(test)]
    fail_sync: AtomicBool,
}

#[derive(Default)]
struct SyncState {
    /// Bytes confirmed durable by a completed `fdatasync`.
    durable_end: u64,
    /// Set while a leader is running its synchronization.
    in_flight: bool,
    /// A synchronization failure poisons the whole journal: no byte past the
    /// last durable point can be trusted, so every append refuses until an
    /// explicit reconciliation owner takes over.
    failed: bool,
}

impl JournalDurability {
    /// Bind the coordinator to one open journal file. The handle is a clone
    /// that never seeks or writes: it only runs `fdatasync` and stats, so it
    /// cannot disturb the writer's file offset.
    pub fn new(file: &File) -> Result<Self, DurableJournalError> {
        // An independent fd (not a clone of the writer's fd) is used here:
        // the writer's fd holds the cooperative flock, and a try_clone would
        // share that same open file description — preventing reopen after
        // the journal is dropped. This fd is flock-free and only does
        // fdatasync + stat.
        Ok(Self {
            file: file.try_clone().map_err(|error| DurableJournalError::Io {
                operation: IoOperation::OpenTarget,
                kind: error.kind(),
            })?,
            state: Mutex::new(SyncState::default()),
            cv: Condvar::new(),
            latest_written: AtomicU64::new(0),
            #[cfg(test)]
            sync_calls: AtomicU64::new(0),
            #[cfg(test)]
            fail_sync: AtomicBool::new(false),
        })
    }

    /// Record that bytes up to `end` have been written (called by the write
    /// path while holding the writer lock).
    fn mark_written(&self, end: u64) {
        self.latest_written.fetch_max(end, Ordering::AcqRel);
    }

    /// Whether a synchronization failure has poisoned the journal.
    pub fn is_failed(&self) -> bool {
        self.state.lock().unwrap().failed
    }

    /// Wait until every byte up to `end` is confirmed durable. The first
    /// caller without an in-flight synchronization becomes the leader and
    /// flushes the whole written prefix; concurrent writers wait and are
    /// woken by the same flush.
    pub fn ensure_durable(&self, end: u64) -> Result<(), DurableJournalError> {
        loop {
            let mut state = self.state.lock().unwrap();
            if state.failed {
                return Err(DurableJournalError::StickyUnknown);
            }
            if state.durable_end >= end {
                return Ok(());
            }
            if state.in_flight {
                state = self
                    .cv
                    .wait_while(state, |state| !state.failed && state.durable_end < end)
                    .unwrap();
                drop(state);
                continue;
            }
            // Become the leader: flush the whole written prefix.
            state.in_flight = true;
            let target = self.latest_written.load(Ordering::Acquire).max(end);
            drop(state);
            let result = self.flush_upto(target);
            let mut state = self.state.lock().unwrap();
            state.in_flight = false;
            match result {
                Ok(()) => state.durable_end = state.durable_end.max(target),
                Err(_) => state.failed = true,
            }
            self.cv.notify_all();
            drop(state);
        }
    }

    // memory—v1: One fdatasync followed by a length floor check. No locks are
    // held: writers keep appending while the flush runs, and only bytes up to
    // `target` are claimed durable.
    fn flush_upto(&self, target: u64) -> Result<(), DurableJournalError> {
        #[cfg(test)]
        {
            self.sync_calls.fetch_add(1, Ordering::Relaxed);
            if self.fail_sync.load(Ordering::Relaxed) {
                return Err(DurableJournalError::Io {
                    operation: IoOperation::SyncFile,
                    kind: io::ErrorKind::Other,
                });
            }
        }
        self.file
            .sync_data()
            .map_err(|error| DurableJournalError::Io {
                operation: IoOperation::SyncFile,
                kind: error.kind(),
            })?;
        let actual = file_length(&self.file)?;
        if actual < target {
            // The file shrank below the written prefix: external tampering.
            return Err(DurableJournalError::FileChanged);
        }
        Ok(())
    }
}

/// The unique local owner for one journal stream and epoch.
///
/// The owner is intentionally synchronous and requires `&mut self` for every
/// append. The composition layer may put it behind one mutex/lease, but there is
/// no second writer protocol hidden in this type.
pub struct MemoryV1DurableJournal {
    file: File,
    stream_id: MemoryId,
    epoch_id: MemoryId,
    limits: DurableJournalLimits,
    position: JournalAnchor,
    record_count: u64,
    file_position: u64,
    operations: BTreeMap<String, StoredOperation>,
    recovery: Vec<RecoveryRecord>,
    state: DurableJournalState,
}

impl std::fmt::Debug for MemoryV1DurableJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemoryV1DurableJournal([REDACTED])")
    }
}

impl MemoryV1DurableJournal {
    /// Create a new file from an explicitly supplied external anchor.
    ///
    /// The anchor is only trusted when supplied by the recovery/adoption owner;
    /// this constructor does not manufacture a genesis fact.
    pub fn create(
        path: &Path,
        stream_id: MemoryId,
        epoch_id: MemoryId,
        anchor: JournalAnchor,
        limits: DurableJournalLimits,
    ) -> Result<(Self, JournalDurability), DurableJournalError> {
        validate_stream_epoch(stream_id, epoch_id, anchor)?;
        validate_limits(limits)?;
        let resolved = resolve_path(path)?;
        if fs::symlink_metadata(&resolved.target).is_ok() {
            return Err(DurableJournalError::TargetExists);
        }
        let directory = open_directory(&resolved.parent)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&resolved.target)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    DurableJournalError::TargetExists
                } else {
                    DurableJournalError::Io {
                        operation: IoOperation::CreateTarget,
                        kind: error.kind(),
                    }
                }
            })?;
        configure_new_file(&file)?;
        lock_file(&file)?;
        // Creation durability: the file's initial bytes AND its directory
        // entry are made durable once here. Every later append extends an
        // already-durable entry and synchronizes only file data.
        sync_file(&file)?;
        sync_directory(&directory)?;
        let durability = JournalDurability::new(&file)?;
        Ok((
            Self {
                file,
                stream_id,
                epoch_id,
                limits,
                position: anchor,
                record_count: 0,
                file_position: 0,
                operations: BTreeMap::new(),
                recovery: Vec::new(),
                state: DurableJournalState::Ready,
            },
            durability,
        ))
    }

    /// memory—v1: Derive the exact verified tail of one existing journal file.
    ///
    /// This is a read-only recovery helper: the complete bounded scan runs the
    /// same frame verification as `open` and reports the anchor the scan ended
    /// at, so a recovery owner can open the journal against a tail it has just
    /// re-derived instead of trusting a remembered value. The file is not
    /// modified, locked for writing, or replayed.
    pub fn scan_tail(
        path: &Path,
        stream_id: MemoryId,
        epoch_id: MemoryId,
        anchor: JournalAnchor,
        limits: DurableJournalLimits,
    ) -> Result<JournalAnchor, DurableJournalError> {
        validate_stream_epoch(stream_id, epoch_id, anchor)?;
        validate_limits(limits)?;
        if anchor.stream_id() != stream_id {
            return Err(DurableJournalError::SequenceMismatch);
        }
        let resolved = resolve_path(path)?;
        inspect_target(&resolved.target)?;
        let file = OpenOptions::new()
            .read(true)
            .open(&resolved.target)
            .map_err(|error| DurableJournalError::Io {
                operation: IoOperation::OpenTarget,
                kind: error.kind(),
            })?;
        ensure_private_regular_file(&file)?;
        if file_length(&file)? == 0 {
            return Err(DurableJournalError::EmptyExistingFile);
        }
        let verifier = JournalVerifier::new(anchor, limits.max_records, limits.max_bytes)
            .map_err(DurableJournalError::Frame)?;
        let scan = scan_file(file, verifier, stream_id, epoch_id, limits)?;
        Ok(scan.position)
    }

    /// Reopen only after a complete bounded scan and exact external-tail check.
    /// No truncation, repair, or automatic replay is performed.
    pub fn open(
        path: &Path,
        stream_id: MemoryId,
        epoch_id: MemoryId,
        anchor: JournalAnchor,
        expected_tail: JournalAnchor,
        limits: DurableJournalLimits,
    ) -> Result<(Self, JournalDurability), DurableJournalError> {
        validate_stream_epoch(stream_id, epoch_id, anchor)?;
        validate_limits(limits)?;
        if expected_tail.stream_id() != stream_id {
            return Err(DurableJournalError::SequenceMismatch);
        }
        let resolved = resolve_path(path)?;
        inspect_target(&resolved.target)?;
        // No directory sync needed: the entry was made durable at creation.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&resolved.target)
            .map_err(|error| DurableJournalError::Io {
                operation: IoOperation::OpenTarget,
                kind: error.kind(),
            })?;
        ensure_private_regular_file(&file)?;
        lock_file(&file)?;
        let initial_length = file_length(&file)?;
        if initial_length == 0 {
            return Err(DurableJournalError::EmptyExistingFile);
        }
        let verifier = JournalVerifier::new(anchor, limits.max_records, limits.max_bytes)
            .map_err(DurableJournalError::Frame)?;
        let scan = scan_file(
            file.try_clone().map_err(|error| DurableJournalError::Io {
                operation: IoOperation::OpenTarget,
                kind: error.kind(),
            })?,
            verifier,
            stream_id,
            epoch_id,
            limits,
        )?;
        if scan.file_position != initial_length {
            return Err(DurableJournalError::FileChanged);
        }
        scan.verifier
            .finish(expected_tail)
            .map_err(DurableJournalError::Frame)?;
        if scan.position != expected_tail {
            return Err(DurableJournalError::Frame(JournalError::ChainMismatch));
        }
        let mut file = file;
        file.seek(SeekFrom::Start(scan.file_position))
            .map_err(|error| DurableJournalError::Io {
                operation: IoOperation::Seek,
                kind: error.kind(),
            })?;
        if file
            .stream_position()
            .map_err(|error| DurableJournalError::Io {
                operation: IoOperation::Seek,
                kind: error.kind(),
            })?
            != scan.file_position
        {
            return Err(DurableJournalError::FileChanged);
        }
        let durability = JournalDurability::new(&file)?;
        durability
            .latest_written
            .store(scan.file_position, Ordering::Release);
        durability.state.lock().unwrap().durable_end = scan.file_position;
        Ok((
            Self {
                file,
                stream_id,
                epoch_id,
                limits,
                position: scan.position,
                record_count: scan.record_count,
                file_position: scan.file_position,
                operations: scan.operations,
                recovery: scan.recovery,
                state: DurableJournalState::Ready,
            },
            durability,
        ))
    }

    pub const fn state(&self) -> DurableJournalState {
        self.state
    }

    pub const fn stream_id(&self) -> MemoryId {
        self.stream_id
    }

    pub const fn epoch_id(&self) -> MemoryId {
        self.epoch_id
    }

    pub const fn position(&self) -> JournalAnchor {
        self.position
    }

    pub const fn record_count(&self) -> u64 {
        self.record_count
    }

    pub const fn file_position(&self) -> u64 {
        self.file_position
    }

    /// The journaled records in append order, for the recovery owner only.
    /// The list is the scan snapshot taken at open; it does not include
    /// records appended afterwards.
    pub fn recovery_records(&self) -> &[RecoveryRecord] {
        &self.recovery
    }

    /// Phase 1 of the mutation append: write the frame (no synchronization)
    /// and register it with the durability coordinator. The receipt is
    /// completed by [`JournalDurability::ensure_durable`] — group commit
    /// coalesces concurrent writers into one `fdatasync`.
    pub fn prepare_mutation(
        &mut self,
        request: &MutationRequest,
        durability: &JournalDurability,
    ) -> Result<PreparedAppend, DurableJournalError> {
        self.ensure_ready()?;
        let payload = request
            .journal_payload()
            .map_err(|_| DurableJournalError::InvalidRecord)?;
        let payload_digest = payload_digest(&payload);
        let decoded_payload =
            decode_journal_payload(&payload).map_err(|_| DurableJournalError::InvalidRecord)?;
        if decoded_payload.operation_id() != request.operation_id()
            || decoded_payload.request_fingerprint() != request.request_fingerprint()
            || decoded_payload.mutation_digest() != request.mutation_digest()
            || decoded_payload.audit_digest() != request.audit_digest()
        {
            return Err(DurableJournalError::OperationConflict);
        }
        let identity = request.journal();

        if let Some(existing) = self.operations.get(request.operation_id()).copied() {
            if existing.kind != RecordKind::Mutation {
                return Err(DurableJournalError::OperationConflict);
            }
            if existing.fingerprint != *request.request_fingerprint()
                || existing.payload_digest != payload_digest
                || existing.mutation_digest != Some(request.mutation_digest())
                || existing.audit_digest != Some(request.audit_digest())
            {
                return Err(DurableJournalError::OperationConflict);
            }
            if existing.identity.mutation_identity()? != identity {
                return Err(DurableJournalError::ExistingOperation);
            }
            // A replayed record is durable only when the whole written prefix
            // is; the coordinator coalesces this with any in-flight flush.
            durability.mark_written(self.file_position);
            return Ok(PreparedAppend {
                operation_id: request.operation_id().to_owned(),
                request_fingerprint: *request.request_fingerprint(),
                mutation_digest: existing
                    .mutation_digest
                    .ok_or(DurableJournalError::InvalidRecord)?,
                audit_digest: existing
                    .audit_digest
                    .ok_or(DurableJournalError::InvalidRecord)?,
                identity,
                tail_hash: existing.tail_hash,
                disposition: JournalAppendDisposition::Replayed,
                start_offset: 0,
                durable_end: self.file_position,
            });
        }

        self.validate_request_identity(request, identity)?;
        if self.record_count >= self.limits.max_records {
            return Err(DurableJournalError::CapacityExceeded);
        }
        let frame = encode_record(&JournalRecord {
            stream_id: identity.stream_id(),
            epoch_id: identity.epoch_id(),
            journal_sequence: identity.journal_sequence(),
            message_id: identity.message_id(),
            operation_id: request.operation_id(),
            request_fingerprint: *request.request_fingerprint(),
            kind: RecordKind::Mutation,
            mutation_sequence: identity.mutation_sequence(),
            prev_hash: *self.position.frame_hash(),
            payload: &payload,
        })
        .map_err(DurableJournalError::Frame)?;
        if frame.len() as u64 > self.limits.max_frame_bytes
            || self
                .file_position
                .checked_add(frame.len() as u64)
                .is_none_or(|end| end > self.limits.max_bytes)
        {
            return Err(DurableJournalError::CapacityExceeded);
        }
        let start = self.file_position;
        let end = start
            .checked_add(frame.len() as u64)
            .ok_or(DurableJournalError::CapacityExceeded)?;
        self.append_frame(&frame, start, end)?;
        let decoded = decode_record(&frame).map_err(DurableJournalError::Frame)?;
        let tail_hash = decoded.digest;
        let stored = StoredOperation {
            fingerprint: *request.request_fingerprint(),
            payload_digest,
            mutation_digest: Some(decoded_payload.mutation_digest()),
            audit_digest: Some(decoded_payload.audit_digest()),
            identity: StoredIdentity::from_record(&decoded.record, self.epoch_id),
            kind: RecordKind::Mutation,
            tail_hash,
        };
        self.operations
            .insert(request.operation_id().to_owned(), stored);
        self.position = JournalAnchor::new(
            self.stream_id,
            identity.journal_sequence(),
            identity.mutation_sequence(),
            tail_hash,
        )
        .map_err(DurableJournalError::Frame)?;
        self.record_count += 1;
        durability.mark_written(end);
        Ok(PreparedAppend {
            operation_id: request.operation_id().to_owned(),
            request_fingerprint: *request.request_fingerprint(),
            mutation_digest: request.mutation_digest(),
            audit_digest: request.audit_digest(),
            identity,
            tail_hash,
            disposition: JournalAppendDisposition::Appended,
            start_offset: start,
            durable_end: end,
        })
    }

    /// Append one DENY observation as its own journal record and issue its
    /// receipt only after the whole written prefix is durable (group commit).
    ///
    /// A DENY does not advance the mutation sequence; its journal sequence is
    /// the next contiguous frame. An already-recorded operation with the same
    /// identity replays the original receipt without a second write.
    pub fn prepare_deny(
        &mut self,
        request: &astral_trustgraph::service::memory_v1_mutation_coordinator::DenyJournalRequest,
        durability: &JournalDurability,
    ) -> Result<PreparedAppend, DurableJournalError> {
        self.ensure_ready()?;
        let payload = request
            .journal_payload()
            .map_err(|_| DurableJournalError::InvalidRecord)?;
        let payload_digest = payload_digest(&payload);
        let decoded_payload = decode_deny_journal_payload(&payload)
            .map_err(|_| DurableJournalError::InvalidRecord)?;
        let observation_operation_id = String::from_utf8(decoded_payload.operation_id().to_vec())
            .map_err(|_| DurableJournalError::InvalidRecord)?;
        if observation_operation_id != request.operation_id() {
            return Err(DurableJournalError::OperationConflict);
        }
        let identity = request.journal();

        if let Some(existing) = self.operations.get(request.operation_id()).copied() {
            if existing.kind != RecordKind::Deny {
                return Err(DurableJournalError::OperationConflict);
            }
            if existing.fingerprint != request.request_fingerprint()
                || existing.payload_digest != payload_digest
                || existing.mutation_digest.is_some()
                || existing.audit_digest.is_some()
            {
                return Err(DurableJournalError::OperationConflict);
            }
            // A DENY replay is idempotent on the operation identity: the
            // recorded message ID wins, and a caller re-deriving the identity
            // with a fresh counter still receives the original receipt. Only
            // a different stream, epoch or journal position is a conflict.
            if existing.identity.stream_id != identity.stream_id()
                || existing.identity.epoch_id != identity.epoch_id()
            {
                return Err(DurableJournalError::SequenceMismatch);
            }
            let replayed_identity = existing
                .identity
                .mutation_identity_deny()
                .ok_or(DurableJournalError::InvalidRecord)?;
            durability.mark_written(self.file_position);
            return Ok(PreparedAppend {
                operation_id: request.operation_id().to_owned(),
                request_fingerprint: request.request_fingerprint(),
                mutation_digest: [0; 32],
                audit_digest: request.audit_digest(),
                identity: replayed_identity,
                tail_hash: existing.tail_hash,
                disposition: JournalAppendDisposition::Replayed,
                start_offset: 0,
                durable_end: self.file_position,
            });
        }

        self.validate_deny_identity(request, identity)?;
        if self.record_count >= self.limits.max_records {
            return Err(DurableJournalError::CapacityExceeded);
        }
        let frame = encode_record(&JournalRecord {
            stream_id: identity.stream_id(),
            epoch_id: identity.epoch_id(),
            journal_sequence: identity.journal_sequence(),
            message_id: identity.message_id(),
            operation_id: request.operation_id(),
            request_fingerprint: request.request_fingerprint(),
            kind: RecordKind::Deny,
            // A DENY records the mutation sequence it observed; the frame
            // itself does not advance that sequence.
            mutation_sequence: self.position.mutation_sequence(),
            prev_hash: *self.position.frame_hash(),
            payload: &payload,
        })
        .map_err(DurableJournalError::Frame)?;
        if frame.len() as u64 > self.limits.max_frame_bytes
            || self
                .file_position
                .checked_add(frame.len() as u64)
                .is_none_or(|end| end > self.limits.max_bytes)
        {
            return Err(DurableJournalError::CapacityExceeded);
        }
        let start = self.file_position;
        let end = start
            .checked_add(frame.len() as u64)
            .ok_or(DurableJournalError::CapacityExceeded)?;
        self.append_frame(&frame, start, end)?;
        let decoded = decode_record(&frame).map_err(DurableJournalError::Frame)?;
        let tail_hash = decoded.digest;
        let stored = StoredOperation {
            fingerprint: request.request_fingerprint(),
            payload_digest,
            mutation_digest: None,
            audit_digest: None,
            identity: StoredIdentity::from_record(&decoded.record, self.epoch_id),
            kind: RecordKind::Deny,
            tail_hash,
        };
        self.operations
            .insert(request.operation_id().to_owned(), stored);
        self.position = JournalAnchor::new(
            self.stream_id,
            identity.journal_sequence(),
            identity.mutation_sequence(),
            tail_hash,
        )
        .map_err(DurableJournalError::Frame)?;
        self.record_count += 1;
        durability.mark_written(end);
        Ok(PreparedAppend {
            operation_id: request.operation_id().to_owned(),
            request_fingerprint: request.request_fingerprint(),
            mutation_digest: [0; 32],
            audit_digest: request.audit_digest(),
            identity,
            tail_hash,
            disposition: JournalAppendDisposition::Appended,
            start_offset: start,
            durable_end: end,
        })
    }

    /// Validate one DENY append identity: same stream/epoch, next journal
    /// sequence, unchanged mutation sequence.
    fn validate_deny_identity(
        &self,
        request: &astral_trustgraph::service::memory_v1_mutation_coordinator::DenyJournalRequest,
        identity: JournalIdentity,
    ) -> Result<(), DurableJournalError> {
        if identity.stream_id() != self.stream_id
            || identity.epoch_id() != self.epoch_id
            || identity.journal_sequence()
                != self
                    .position
                    .journal_sequence()
                    .checked_add(1)
                    .ok_or(DurableJournalError::CapacityExceeded)?
            || identity.mutation_sequence() != self.position.mutation_sequence()
            || request.payload_bytes() > astral_types::memory_v1_journal::MAX_PAYLOAD_BYTES
        {
            return Err(DurableJournalError::SequenceMismatch);
        }
        Ok(())
    }

    fn validate_request_identity(
        &self,
        request: &MutationRequest,
        identity: JournalIdentity,
    ) -> Result<(), DurableJournalError> {
        if identity.stream_id() != self.stream_id
            || identity.epoch_id() != self.epoch_id
            || identity.journal_sequence()
                != self
                    .position
                    .journal_sequence()
                    .checked_add(1)
                    .ok_or(DurableJournalError::CapacityExceeded)?
            || identity.mutation_sequence()
                != self
                    .position
                    .mutation_sequence()
                    .checked_add(1)
                    .ok_or(DurableJournalError::CapacityExceeded)?
            || request.payload_bytes() > astral_types::memory_v1_journal::MAX_PAYLOAD_BYTES
        {
            return Err(DurableJournalError::SequenceMismatch);
        }
        Ok(())
    }

    fn append_frame(
        &mut self,
        frame: &[u8],
        start: u64,
        end: u64,
    ) -> Result<(), DurableJournalError> {
        let actual = file_length(&self.file)?;
        if actual != start
            || self
                .file
                .stream_position()
                .map_err(|error| DurableJournalError::Io {
                    operation: IoOperation::Seek,
                    kind: error.kind(),
                })?
                != start
        {
            self.state = DurableJournalState::StickyUnknown;
            return Err(DurableJournalError::FileChanged);
        }
        let mut written = 0_usize;
        while written < frame.len() {
            let count = self.file.write(&frame[written..]).map_err(|error| {
                self.state = DurableJournalState::StickyUnknown;
                DurableJournalError::Io {
                    operation: IoOperation::Write,
                    kind: error.kind(),
                }
            })?;
            if count == 0 || count > frame.len() - written {
                self.state = DurableJournalState::StickyUnknown;
                return Err(DurableJournalError::UnknownAfterIo);
            }
            written += count;
        }
        let actual = file_length(&self.file)
            .inspect_err(|_| self.state = DurableJournalState::StickyUnknown)?;
        if actual != end {
            self.state = DurableJournalState::StickyUnknown;
            return Err(DurableJournalError::FileChanged);
        }
        // No synchronization here: the write is flushed by the durability
        // coordinator (group commit). The directory entry was made durable at
        // creation, so appends need only the file's data synchronization.
        self.file_position = end;
        Ok(())
    }

    fn ensure_ready(&self) -> Result<(), DurableJournalError> {
        match self.state {
            DurableJournalState::Ready => Ok(()),
            DurableJournalState::StickyUnknown => Err(DurableJournalError::StickyUnknown),
        }
    }
}

struct ResolvedPath {
    parent: PathBuf,
    target: PathBuf,
}

fn validate_limits(limits: DurableJournalLimits) -> Result<(), DurableJournalError> {
    if limits.max_records == 0
        || limits.max_bytes == 0
        || limits.max_frame_bytes == 0
        || limits.max_frame_bytes > MAX_FRAME_BYTES as u64
        || limits.max_frame_bytes > limits.max_bytes
    {
        return Err(DurableJournalError::InvalidLimits);
    }
    JournalVerifier::new(
        JournalAnchor::new(MemoryId::from_bytes([1; 16]), 0, 0, [1; 32])
            .map_err(DurableJournalError::Frame)?,
        limits.max_records,
        limits.max_bytes,
    )
    .map_err(DurableJournalError::Frame)?;
    Ok(())
}

fn validate_stream_epoch(
    stream_id: MemoryId,
    epoch_id: MemoryId,
    anchor: JournalAnchor,
) -> Result<(), DurableJournalError> {
    if stream_id.as_bytes().iter().all(|byte| *byte == 0)
        || epoch_id.as_bytes().iter().all(|byte| *byte == 0)
        || anchor.stream_id() != stream_id
    {
        return Err(DurableJournalError::SequenceMismatch);
    }
    Ok(())
}

fn resolve_path(path: &Path) -> Result<ResolvedPath, DurableJournalError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(DurableJournalError::InvalidPath);
    }
    let file_name = path.file_name().ok_or(DurableJournalError::InvalidPath)?;
    let parent = path.parent().ok_or(DurableJournalError::InvalidPath)?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| DurableJournalError::InvalidParent)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DurableJournalError::InvalidParent);
    }
    ensure_private_directory(&metadata)?;
    let canonical = fs::canonicalize(parent).map_err(|_| DurableJournalError::InvalidParent)?;
    let canonical_metadata =
        fs::symlink_metadata(&canonical).map_err(|_| DurableJournalError::InvalidParent)?;
    if canonical_metadata.file_type().is_symlink() || !canonical_metadata.is_dir() {
        return Err(DurableJournalError::InvalidParent);
    }
    ensure_private_directory(&canonical_metadata)?;
    Ok(ResolvedPath {
        parent: canonical.clone(),
        target: canonical.join(file_name),
    })
}

fn open_directory(path: &Path) -> Result<File, DurableJournalError> {
    File::open(path).map_err(|error| DurableJournalError::Io {
        operation: IoOperation::OpenParent,
        kind: error.kind(),
    })
}

fn inspect_target(path: &Path) -> Result<(), DurableJournalError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| DurableJournalError::InvalidTarget)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DurableJournalError::InvalidTarget);
    }
    ensure_private_file(&metadata)
}

fn configure_new_file(file: &File) -> Result<(), DurableJournalError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| DurableJournalError::Io {
                operation: IoOperation::CreateTarget,
                kind: error.kind(),
            })?;
    }
    ensure_private_regular_file(file)
}

fn ensure_private_regular_file(file: &File) -> Result<(), DurableJournalError> {
    let metadata = file.metadata().map_err(|error| DurableJournalError::Io {
        operation: IoOperation::InspectTarget,
        kind: error.kind(),
    })?;
    if !metadata.is_file() {
        return Err(DurableJournalError::InvalidTarget);
    }
    ensure_private_file(&metadata)
}

fn ensure_private_directory(metadata: &fs::Metadata) -> Result<(), DurableJournalError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(DurableJournalError::InvalidParent);
        }
    }
    Ok(())
}

fn ensure_private_file(metadata: &fs::Metadata) -> Result<(), DurableJournalError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(DurableJournalError::InvalidTarget);
        }
    }
    Ok(())
}

fn lock_file(file: &File) -> Result<(), DurableJournalError> {
    file.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => DurableJournalError::LockUnavailable,
        TryLockError::Error(error) if error.kind() == io::ErrorKind::Unsupported => {
            DurableJournalError::LockUnsupported
        }
        TryLockError::Error(error) => DurableJournalError::Io {
            operation: IoOperation::LockTarget,
            kind: error.kind(),
        },
    })
}

fn file_length(file: &File) -> Result<u64, DurableJournalError> {
    file.metadata()
        .map(|metadata| metadata.len())
        .map_err(|error| DurableJournalError::Io {
            operation: IoOperation::InspectLength,
            kind: error.kind(),
        })
}

fn sync_file(file: &File) -> Result<(), DurableJournalError> {
    file.sync_all().map_err(|error| DurableJournalError::Io {
        operation: IoOperation::SyncFile,
        kind: error.kind(),
    })
}

fn sync_directory(directory: &File) -> Result<(), DurableJournalError> {
    directory
        .sync_all()
        .map_err(|error| DurableJournalError::Io {
            operation: IoOperation::SyncParent,
            kind: error.kind(),
        })
}

struct ScanResult {
    verifier: JournalVerifier,
    position: JournalAnchor,
    file_position: u64,
    record_count: u64,
    operations: BTreeMap<String, StoredOperation>,
    recovery: Vec<RecoveryRecord>,
}

/// One journaled record in its append order, for the recovery owner only.
///
/// `payload` is the exact encoded envelope bytes (mutation or deny); the
/// caller re-derives both value digests through the coordinator's decoders.
#[derive(Clone, Debug)]
pub struct RecoveryRecord {
    pub operation_id: String,
    pub kind: RecordKind,
    pub journal_sequence: u64,
    /// For a Mutation: the new mutation sequence it produced. For a Deny:
    /// the mutation sequence observed at the denial.
    pub mutation_sequence: u64,
    pub payload: Vec<u8>,
}

/// A written-but-not-yet-confirmed-durable journal record. The receipt is
/// completed by [`JournalDurability::ensure_durable`] — group commit
/// coalesces concurrent writers into one `fdatasync`.
#[derive(Clone, Debug)]
pub struct PreparedAppend {
    pub operation_id: String,
    pub request_fingerprint: [u8; 32],
    pub mutation_digest: [u8; 32],
    pub audit_digest: [u8; 32],
    pub identity: JournalIdentity,
    pub tail_hash: [u8; 32],
    pub disposition: JournalAppendDisposition,
    pub start_offset: u64,
    pub durable_end: u64,
}

impl PreparedAppend {
    /// Wait for the whole written prefix to become durable, then return the
    /// receipt. Under concurrency this shares one `fdatasync` with the other
    /// writers in the same prefix.
    pub fn into_durable_receipt(
        self,
        durability: &JournalDurability,
    ) -> Result<LocalDurablePrefixReceipt, DurableJournalError> {
        durability.ensure_durable(self.durable_end)?;
        Ok(LocalDurablePrefixReceipt {
            operation_id: self.operation_id,
            request_fingerprint: self.request_fingerprint,
            mutation_digest: self.mutation_digest,
            audit_digest: self.audit_digest,
            identity: self.identity,
            tail_hash: self.tail_hash,
            disposition: self.disposition,
            start_offset: self.start_offset,
            end_offset: self.durable_end,
        })
    }
}

fn scan_file(
    mut file: File,
    mut verifier: JournalVerifier,
    stream_id: MemoryId,
    epoch_id: MemoryId,
    limits: DurableJournalLimits,
) -> Result<ScanResult, DurableJournalError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| DurableJournalError::Io {
            operation: IoOperation::Seek,
            kind: error.kind(),
        })?;
    let mut operations = BTreeMap::new();
    let mut recovery = Vec::new();
    let mut file_position = 0_u64;
    let mut record_count = 0_u64;
    loop {
        let mut prefix = [0_u8; FRAME_PREFIX_BYTES];
        let read = read_prefix(&mut file, &mut prefix)?;
        if read == PrefixRead::End {
            break;
        }
        if read == PrefixRead::Incomplete {
            return Err(DurableJournalError::FileChanged);
        }
        let length = frame_length(&prefix).map_err(DurableJournalError::Frame)?;
        if length as u64 > limits.max_frame_bytes {
            return Err(DurableJournalError::CapacityExceeded);
        }
        let next_position = file_position
            .checked_add(length as u64)
            .ok_or(DurableJournalError::CapacityExceeded)?;
        if next_position > limits.max_bytes {
            return Err(DurableJournalError::CapacityExceeded);
        }
        let mut frame = Vec::new();
        frame
            .try_reserve_exact(length)
            .map_err(|_| DurableJournalError::CapacityExceeded)?;
        frame.resize(length, 0);
        frame[..FRAME_PREFIX_BYTES].copy_from_slice(&prefix);
        use std::io::Read;
        file.read_exact(&mut frame[FRAME_PREFIX_BYTES..])
            .map_err(|error| {
                if error.kind() == io::ErrorKind::UnexpectedEof {
                    DurableJournalError::FileChanged
                } else {
                    DurableJournalError::Io {
                        operation: IoOperation::Read,
                        kind: error.kind(),
                    }
                }
            })?;
        let decoded = verifier
            .advance(&frame)
            .map_err(DurableJournalError::Frame)?;
        if decoded.record.stream_id != stream_id || decoded.record.epoch_id != epoch_id {
            return Err(DurableJournalError::SequenceMismatch);
        }
        let operation_id = decoded.record.operation_id.to_owned();
        if operation_id.is_empty() || operation_id.len() > MAX_OPERATION_ID_BYTES {
            return Err(DurableJournalError::InvalidRecord);
        }
        let (mutation_digest, audit_digest) = match decoded.record.kind {
            RecordKind::Mutation => {
                let decoded_payload = decode_journal_payload(decoded.record.payload)
                    .map_err(|_| DurableJournalError::InvalidRecord)?;
                if decoded_payload.operation_id() != operation_id
                    || decoded_payload.request_fingerprint() != &decoded.record.request_fingerprint
                {
                    return Err(DurableJournalError::OperationConflict);
                }
                (
                    Some(decoded_payload.mutation_digest()),
                    Some(decoded_payload.audit_digest()),
                )
            }
            RecordKind::Deny => {
                let decoded_observation = decode_deny_journal_payload(decoded.record.payload)
                    .map_err(|_| DurableJournalError::InvalidRecord)?;
                if decoded_observation.operation_id() != decoded.record.operation_id.as_bytes()
                    || decoded_observation.operation_fingerprint()
                        != decoded.record.request_fingerprint.as_slice()
                {
                    return Err(DurableJournalError::OperationConflict);
                }
                (None, None)
            }
        };
        if operations
            .insert(
                operation_id.clone(),
                StoredOperation {
                    fingerprint: decoded.record.request_fingerprint,
                    payload_digest: payload_digest(decoded.record.payload),
                    mutation_digest,
                    audit_digest,
                    identity: StoredIdentity::from_record(&decoded.record, epoch_id),
                    kind: decoded.record.kind,
                    tail_hash: decoded.digest,
                },
            )
            .is_some()
        {
            return Err(DurableJournalError::OperationConflict);
        }
        recovery.push(RecoveryRecord {
            operation_id,
            kind: decoded.record.kind,
            journal_sequence: decoded.record.journal_sequence,
            mutation_sequence: decoded.record.mutation_sequence,
            payload: decoded.record.payload.to_vec(),
        });
        file_position = next_position;
        record_count = record_count
            .checked_add(1)
            .ok_or(DurableJournalError::CapacityExceeded)?;
    }
    if file_position == 0 {
        return Err(DurableJournalError::EmptyExistingFile);
    }
    Ok(ScanResult {
        position: verifier.position(),
        verifier,
        file_position,
        record_count,
        operations,
        recovery,
    })
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PrefixRead {
    End,
    Complete,
    Incomplete,
}

fn read_prefix(
    file: &mut File,
    prefix: &mut [u8; FRAME_PREFIX_BYTES],
) -> Result<PrefixRead, DurableJournalError> {
    use std::io::Read;
    let mut read = 0;
    while read < prefix.len() {
        match file.read(&mut prefix[read..]) {
            Ok(0) if read == 0 => return Ok(PrefixRead::End),
            Ok(0) => return Ok(PrefixRead::Incomplete),
            Ok(count) => read += count,
            Err(error) => {
                return Err(DurableJournalError::Io {
                    operation: IoOperation::Read,
                    kind: error.kind(),
                })
            }
        }
    }
    Ok(PrefixRead::Complete)
}

fn payload_digest(payload: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(PAYLOAD_DIGEST_DOMAIN);
    hash.update(payload);
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_authorization_root::memory_v1_db_rows::UserCardStatus;
    use astral_authorization_root::memory_v1_root::ManagementMutationV2;
    use astral_trustgraph::service::memory_v1_mutation_coordinator::{
        JournalIdentity, MutationAuditCandidate, RootBinding, VerifiedRootAdmission,
    };
    use astral_types::memory_v1_audit::{
        MemoryV1AuditAction, MemoryV1AuditActor, MemoryV1AuditChange, MemoryV1AuditChangeSummary,
        MemoryV1AuditConfirmationRef, MemoryV1AuditConfirmations, MemoryV1AuditContext,
        MemoryV1AuditDecisionInput, MemoryV1AuditEvent, MemoryV1AuditObject,
        MemoryV1AuditObjectState, MemoryV1AuditRootObservation, MemoryV1AuditRootStatus,
        MemoryV1AuditRootVersion, MemoryV1AuditSource, MemoryV1AuditT2SingleChangeCandidate,
        MemoryV1AuditTime,
    };
    use astral_types::memory_v1_journal::FRAME_DIGEST_BYTES;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};
    use uuid::Uuid;

    fn id(value: u8) -> MemoryId {
        MemoryId::from_bytes([value; 16])
    }

    fn root() -> VerifiedRootAdmission {
        VerifiedRootAdmission::for_contract_tests(RootBinding::new(
            astral_authorization_root::memory_v1_root::RootInstanceId::from_uuid(Uuid::from_bytes(
                [1; 16],
            )),
            7,
            [7; 32],
            astral_authorization_root::memory_v1_root::RootStatus::Serving,
        ))
    }

    fn audit(operation_id: &str, fingerprint: [u8; 32]) -> MutationAuditCandidate {
        let context = MemoryV1AuditContext::new(
            MemoryV1AuditActor::new(id(2), id(3)),
            MemoryV1AuditTime::new(100).unwrap(),
            MemoryV1AuditAction::new("user_card", "disable").unwrap(),
            "MANAGEMENT_MUTATION",
            astral_types::memory_v1_audit::MemoryV1AuditOperation::new(operation_id, fingerprint)
                .unwrap(),
            MemoryV1AuditRootObservation::new(
                MemoryV1AuditRootVersion::new(id(1), 7),
                [7; 32],
                MemoryV1AuditRootStatus::Serving,
            ),
        )
        .unwrap();
        let change = MemoryV1AuditChange::new(
            Some(id(2)),
            Some(MemoryV1AuditObject::UserCard(id(4))),
            Some(MemoryV1AuditObject::Tenant(id(5))),
            Some(MemoryV1AuditChangeSummary::new(&[6; 32]).unwrap()),
            Some(MemoryV1AuditObjectState::UserCard(
                astral_types::memory_v1_audit::MemoryV1AuditCardState::Active,
            )),
            Some(MemoryV1AuditObjectState::UserCard(
                astral_types::memory_v1_audit::MemoryV1AuditCardState::Disabled,
            )),
            Some(
                MemoryV1AuditConfirmations::references(&[MemoryV1AuditConfirmationRef::Binding(
                    id(8),
                )])
                .unwrap(),
            ),
            Some(MemoryV1AuditRootVersion::new(id(1), 7)),
            Some(MemoryV1AuditRootVersion::new(id(1), 8)),
            MemoryV1AuditSource::Ordinary,
        );
        MutationAuditCandidate::Single(
            MemoryV1AuditT2SingleChangeCandidate::try_from(
                MemoryV1AuditEvent::change(context, MemoryV1AuditDecisionInput::Allow, change)
                    .unwrap(),
            )
            .unwrap(),
        )
    }

    fn request(operation_id: &str, journal_sequence: u64) -> MutationRequest {
        let fingerprint = [4; 32];
        MutationRequest::try_new(
            operation_id,
            fingerprint,
            ManagementMutationV2::UserCardStatus {
                user_card_id: [9; 16],
                status: UserCardStatus::Disabled,
            },
            audit(operation_id, fingerprint),
            root(),
            JournalIdentity::new(
                id(10),
                id(11),
                journal_sequence,
                journal_sequence,
                id(journal_sequence as u8 + 20),
            )
            .unwrap(),
        )
        .unwrap()
    }

    static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(1);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let base = fs::canonicalize(std::env::temp_dir()).unwrap();
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            for _ in 0..16 {
                let serial = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
                let path = base.join(format!(
                    "astral-durable-journal-{}-{stamp}-{serial}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                        }
                        return Self(path);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("test directory creation failed: {error:?}"),
                }
            }
            panic!("test directory collision budget exhausted")
        }

        fn path(&self) -> PathBuf {
            self.0.join("journal.bin")
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn anchor() -> JournalAnchor {
        JournalAnchor::new(id(10), 0, 0, [5; 32]).unwrap()
    }

    fn limits() -> DurableJournalLimits {
        DurableJournalLimits::new(32, 1024 * 1024, 1024 * 1024).unwrap()
    }

    fn owner(directory: &TestDir) -> (MemoryV1DurableJournal, JournalDurability) {
        MemoryV1DurableJournal::create(&directory.path(), id(10), id(11), anchor(), limits())
            .unwrap()
    }

    // memory—v1: Prepare + durable receipt in one call for tests.
    fn append_mutation_test(
        journal: &mut MemoryV1DurableJournal,
        durability: &JournalDurability,
        request: &MutationRequest,
    ) -> Result<LocalDurablePrefixReceipt, DurableJournalError> {
        journal
            .prepare_mutation(request, durability)
            .unwrap()
            .into_durable_receipt(durability)
    }

    #[test]
    fn append_replay_and_reopen_reconcile_the_same_operation() {
        let directory = TestDir::new();
        let (mut journal, durability) = owner(&directory);
        let first_request = request("operation-1", 1);
        let first = append_mutation_test(&mut journal, &durability, &first_request).unwrap();
        assert_eq!(first.disposition(), JournalAppendDisposition::Appended);
        assert_eq!(first.identity(), first_request.journal());
        let tail = journal.position();
        let replay = append_mutation_test(&mut journal, &durability, &first_request).unwrap();
        assert_eq!(replay.disposition(), JournalAppendDisposition::Replayed);
        assert_eq!(replay.tail_hash(), first.tail_hash());
        drop(journal);
        drop(durability);

        let (mut reopened, reopened_durability) = MemoryV1DurableJournal::open(
            &directory.path(),
            id(10),
            id(11),
            anchor(),
            tail,
            limits(),
        )
        .unwrap();
        let recovered = reopened
            .prepare_mutation(&first_request, &reopened_durability)
            .unwrap()
            .into_durable_receipt(&reopened_durability)
            .unwrap();
        assert_eq!(recovered.disposition(), JournalAppendDisposition::Replayed);
        assert_eq!(recovered.tail_hash(), first.tail_hash());
    }

    #[test]
    fn wrong_epoch_or_sequence_is_refused_before_file_change() {
        let directory = TestDir::new();
        let (mut journal, durability) = owner(&directory);
        let before = journal.file_position();
        let mut wrong_epoch = request("operation-1", 1);
        wrong_epoch = MutationRequest::try_new(
            wrong_epoch.operation_id(),
            *wrong_epoch.request_fingerprint(),
            wrong_epoch.mutation().clone(),
            wrong_epoch.audit().clone(),
            root(),
            JournalIdentity::new(id(10), id(12), 1, 1, id(21)).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            journal.prepare_mutation(&wrong_epoch, &durability),
            Err(DurableJournalError::SequenceMismatch)
        ));
        assert_eq!(journal.file_position(), before);

        let second = request("operation-2", 2);
        assert!(matches!(
            journal
                .prepare_mutation(&second, &durability)
                .and_then(|p| p.into_durable_receipt(&durability)),
            Err(DurableJournalError::SequenceMismatch)
        ));
        assert_eq!(journal.file_position(), before);
    }

    #[test]
    fn concurrent_replays_are_idempotent_under_one_writer_lease() {
        let directory = TestDir::new();
        let (journal_inner, durability) = owner(&directory);
        let durability = std::sync::Arc::new(durability);
        let journal = Arc::new(Mutex::new(journal_inner));
        let request = Arc::new(request("operation-1", 1));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let journal = Arc::clone(&journal);
            let durability = std::sync::Arc::clone(&durability);
            let request = Arc::clone(&request);
            handles.push(std::thread::spawn(move || {
                journal
                    .lock()
                    .unwrap()
                    .prepare_mutation(&request, &durability)
                    .unwrap()
                    .into_durable_receipt(&durability)
                    .unwrap()
                    .disposition()
            }));
        }
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == JournalAppendDisposition::Appended)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == JournalAppendDisposition::Replayed)
                .count(),
            7
        );
    }

    #[test]
    fn post_write_length_mismatch_sticks_unknown_before_returning() {
        let directory = TestDir::new();
        let (mut journal, durability) = owner(&directory);
        let frame = b"frame";
        let start = journal.file_position();
        let end = start + frame.len() as u64 + 1;

        assert_eq!(
            journal.append_frame(frame, start, end),
            Err(DurableJournalError::FileChanged)
        );
        assert_eq!(journal.state(), DurableJournalState::StickyUnknown);
        assert_eq!(journal.file_position(), start);
        assert_eq!(
            fs::metadata(directory.path()).unwrap().len(),
            frame.len() as u64
        );
        assert!(matches!(
            journal
                .prepare_mutation(&request("operation-1", 1), &durability)
                .and_then(|p| p.into_durable_receipt(&durability)),
            Err(DurableJournalError::StickyUnknown)
        ));
    }

    fn rewrite_payload(path: &Path, mutate: impl FnOnce(&mut Vec<u8>)) {
        let bytes = fs::read(path).unwrap();
        let decoded = decode_record(&bytes).unwrap();
        let mut payload = decoded.record.payload.to_vec();
        mutate(&mut payload);
        let rewritten = encode_record(&JournalRecord {
            stream_id: decoded.record.stream_id,
            epoch_id: decoded.record.epoch_id,
            journal_sequence: decoded.record.journal_sequence,
            message_id: decoded.record.message_id,
            operation_id: decoded.record.operation_id,
            request_fingerprint: decoded.record.request_fingerprint,
            kind: decoded.record.kind,
            mutation_sequence: decoded.record.mutation_sequence,
            prev_hash: decoded.record.prev_hash,
            payload: &payload,
        })
        .unwrap();
        fs::write(path, rewritten).unwrap();
    }

    const JOURNAL_ENVELOPE_DIGEST_OFFSET: usize =
        b"astrallight/memory-v1/journal/mutation-envelope/1\0".len() + 2 + 1 + 1 + 4 + 4 + 4;

    #[test]
    fn reopen_rejects_inner_mutation_digest_tampering_after_outer_rehash() {
        let directory = TestDir::new();
        let (mut journal, durability) = owner(&directory);
        let request = request("operation-1", 1);
        append_mutation_test(&mut journal, &durability, &request).unwrap();
        let tail = journal.position();
        drop(journal);
        drop(durability);

        rewrite_payload(&directory.path(), |payload| {
            payload[JOURNAL_ENVELOPE_DIGEST_OFFSET] ^= 1;
        });
        assert!(matches!(
            MemoryV1DurableJournal::open(
                &directory.path(),
                id(10),
                id(11),
                anchor(),
                tail,
                limits()
            ),
            Err(DurableJournalError::InvalidRecord)
        ));
    }

    #[test]
    fn reopen_rejects_inner_audit_digest_tampering_after_outer_rehash() {
        let directory = TestDir::new();
        let (mut journal, durability) = owner(&directory);
        let request = request("operation-1", 1);
        append_mutation_test(&mut journal, &durability, &request).unwrap();
        let tail = journal.position();
        drop(journal);
        drop(durability);

        rewrite_payload(&directory.path(), |payload| {
            payload[JOURNAL_ENVELOPE_DIGEST_OFFSET + 32] ^= 1;
        });
        assert!(matches!(
            MemoryV1DurableJournal::open(
                &directory.path(),
                id(10),
                id(11),
                anchor(),
                tail,
                limits()
            ),
            Err(DurableJournalError::InvalidRecord)
        ));
    }

    #[test]
    fn reopen_rejects_outer_operation_binding_mismatch() {
        let directory = TestDir::new();
        let (mut journal, durability) = owner(&directory);
        let request = request("operation-1", 1);
        append_mutation_test(&mut journal, &durability, &request).unwrap();
        let tail = journal.position();
        drop(journal);
        drop(durability);

        let bytes = fs::read(directory.path()).unwrap();
        let decoded = decode_record(&bytes).unwrap();
        let rewritten = encode_record(&JournalRecord {
            stream_id: decoded.record.stream_id,
            epoch_id: decoded.record.epoch_id,
            journal_sequence: decoded.record.journal_sequence,
            message_id: decoded.record.message_id,
            operation_id: "other-operation",
            request_fingerprint: decoded.record.request_fingerprint,
            kind: decoded.record.kind,
            mutation_sequence: decoded.record.mutation_sequence,
            prev_hash: decoded.record.prev_hash,
            payload: decoded.record.payload,
        })
        .unwrap();
        fs::write(directory.path(), rewritten).unwrap();
        assert!(matches!(
            MemoryV1DurableJournal::open(
                &directory.path(),
                id(10),
                id(11),
                anchor(),
                tail,
                limits()
            ),
            Err(DurableJournalError::OperationConflict)
        ));
    }

    #[test]
    fn append_replay_uses_recovered_digest_binding() {
        let directory = TestDir::new();
        let (mut journal, durability) = owner(&directory);
        let first_request = request("operation-1", 1);
        let first = append_mutation_test(&mut journal, &durability, &first_request).unwrap();
        drop(journal);
        drop(durability);

        let (mut reopened, reopened_durability) = MemoryV1DurableJournal::open(
            &directory.path(),
            id(10),
            id(11),
            anchor(),
            JournalAnchor::new(id(10), 1, 1, *first.tail_hash()).unwrap(),
            limits(),
        )
        .unwrap();
        let replay = reopened
            .prepare_mutation(&first_request, &reopened_durability)
            .unwrap()
            .into_durable_receipt(&reopened_durability)
            .unwrap();
        assert_eq!(replay.mutation_digest(), first_request.mutation_digest());
        assert_eq!(replay.audit_digest(), first_request.audit_digest());
        assert_eq!(replay.disposition(), JournalAppendDisposition::Replayed);
    }

    #[test]
    fn tampered_tail_cannot_be_reopened_as_a_verified_owner() {
        let directory = TestDir::new();
        let (mut journal, durability) = owner(&directory);
        let request = request("operation-1", 1);
        append_mutation_test(&mut journal, &durability, &request).unwrap();
        let tail = journal.position();
        drop(journal);
        drop(durability);
        let path = directory.path();
        let mut bytes = fs::read(&path).unwrap();
        let tamper_index = bytes.len() - FRAME_DIGEST_BYTES - 1;
        bytes[tamper_index] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(matches!(
            MemoryV1DurableJournal::open(&path, id(10), id(11), anchor(), tail, limits()),
            Err(DurableJournalError::Frame(JournalError::DigestMismatch))
                | Err(DurableJournalError::Frame(JournalError::ChainMismatch))
        ));
    }
}
