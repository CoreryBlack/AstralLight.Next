//! Bounded local-file plumbing for the memory-v1 A/A1 journal candidate.
//!
//! This module owns only a regular local file, a cooperating-writer lock,
//! bounded frame I/O, and fail-closed reopen checks against an independently
//! supplied journal anchor and tail. A successful [`LocalJournalFlush`] means
//! that this handle wrote the checked bytes and that `sync_all` succeeded for
//! both the file and its opened parent directory. It is not a root commit, an
//! audit-completeness result, an authorization result, a crash-recovery proof,
//! or a physical power-loss guarantee.
//!
//! The caller must provide a controlled absolute path whose parent will not be
//! replaced while the handle is in use. The standard library does not expose a
//! race-free directory-relative create operation on every supported platform,
//! so path replacement by an actor that bypasses the file lock remains an
//! integration precondition. This module rejects symlink targets, requires a
//! private regular parent, retains handles for the file and directory, and
//! checks file length before and after appends. Length is only a boundary check;
//! it is never treated as a completeness proof.
//!
//! Existing files are never truncated or repaired. An existing empty file is
//! rejected because this module cannot prove that it is the trusted empty
//! baseline. Use [`JournalFile::create`] for an explicitly new baseline, with a
//! caller-trusted anchor. A non-empty existing file is accepted only after all
//! frames are decoded, bounded, chain-verified, and compared with an external
//! tail.

use std::fmt;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use astral_types::memory_v1_journal::{
    encode_record, frame_length, JournalAnchor, JournalError, JournalRecord, JournalTail,
    JournalVerifier, FRAME_DIGEST_BYTES, FRAME_HEADER_BYTES, FRAME_PREFIX_BYTES, MAX_FRAME_BYTES,
};

const MIN_FRAME_BYTES: u64 = (FRAME_HEADER_BYTES + FRAME_DIGEST_BYTES + 2) as u64;
const MAX_PRECHECK_FAILURES: u8 = 8;

/// Maximum encoded bytes assembled by one append operation.
pub const MAX_APPEND_BATCH_BYTES: u64 = 16 * 1024 * 1024;

/// Finite limits for one local journal file and one append operation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct JournalFileLimits {
    /// Maximum verified records in the file.
    pub max_records: u64,
    /// Maximum sum of encoded frame bytes in the file.
    pub max_bytes: u64,
    /// Maximum sum of encoded frame bytes in one append call.
    pub max_batch_bytes: u64,
    /// Maximum encoded size of one frame.
    pub max_frame_bytes: u64,
}

impl fmt::Debug for JournalFileLimits {
    // memory—v1
    // memory—v1
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JournalFileLimits")
            .field("max_records", &self.max_records)
            .field("max_bytes", &self.max_bytes)
            .field("max_batch_bytes", &self.max_batch_bytes)
            .field("max_frame_bytes", &self.max_frame_bytes)
            .finish()
    }
}

impl JournalFileLimits {
    /// Construct limits that fit the frame verifier and local batch bound.
    // memory—v1
    pub fn new(
        max_records: u64,
        max_bytes: u64,
        max_batch_bytes: u64,
        max_frame_bytes: u64,
    ) -> Result<Self, JournalFileError> {
        let limits = Self {
            max_records,
            max_bytes,
            max_batch_bytes,
            max_frame_bytes,
        };
        limits.validate()?;
        Ok(limits)
    }

    // memory—v1
    // memory—v1
    fn validate(&self) -> Result<(), JournalFileError> {
        if self.max_records == 0
            || self.max_bytes < MIN_FRAME_BYTES
            || self.max_batch_bytes < MIN_FRAME_BYTES
            || self.max_frame_bytes < MIN_FRAME_BYTES
            || self.max_batch_bytes > MAX_APPEND_BATCH_BYTES
            || self.max_frame_bytes > MAX_FRAME_BYTES as u64
            || self.max_batch_bytes > self.max_bytes
            || self.max_frame_bytes > self.max_bytes
        {
            return Err(JournalFileError::InvalidLimits);
        }
        // Use the frame module's own finite caps as the source of truth.
        JournalVerifier::new(
            JournalAnchor::new(
                astral_types::memory_v1::MemoryId::from_bytes([1; 16]),
                0,
                0,
                [1; 32],
            )
            .map_err(JournalFileError::Frame)?,
            self.max_records,
            self.max_bytes,
        )
        .map_err(JournalFileError::Frame)?;
        Ok(())
    }

    /// Conservative limits for a single local journal.
    // memory—v1
    pub const fn conservative() -> Self {
        Self {
            max_records: 4096,
            max_bytes: 64 * 1024 * 1024,
            max_batch_bytes: 4 * 1024 * 1024,
            max_frame_bytes: MAX_FRAME_BYTES as u64,
        }
    }
}

/// OS operations are named without retaining paths or raw error strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileIoOperation {
    ResolveParent,
    OpenParent,
    InspectTarget,
    CreateTarget,
    OpenTarget,
    LockTarget,
    SeekTarget,
    ReadTarget,
    WriteTarget,
    InspectLength,
    SyncTarget,
    SyncParent,
}

/// Fail-closed errors from this file layer. No variant carries message IDs,
/// operation IDs, payloads, paths, or raw OS error strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalFileError {
    InvalidLimits,
    PathMustBeAbsolute,
    PathHasUnnormalizedComponents,
    PathHasNoFileName,
    ParentMissing,
    ParentNotDirectory,
    ParentSymlink,
    ParentNotControlled,
    ParentPersistenceUnavailable,
    /// A failed creation may have left a target behind. The caller must inspect
    /// and reconcile the path before retrying; this is never a success result.
    CreationMayHaveLeftTarget,
    TargetMissing,
    TargetExists,
    TargetSymlink,
    TargetNotRegular,
    TargetPermissions,
    LockUnavailable,
    LockUnsupported,
    ExistingFileEmpty,
    ExistingFileIncomplete,
    ExistingFileChanged,
    FileLengthMismatch,
    CursorMismatch,
    EmptyBatch,
    BatchLimitExceeded,
    FrameLimitExceeded,
    StickyUnknown,
    UnknownAfterIo,
    Frame(JournalError),
    Io {
        operation: FileIoOperation,
        kind: io::ErrorKind,
    },
}

impl fmt::Display for JournalFileError {
    // memory—v1
    // memory—v1
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => f.write_str("invalid journal file limits"),
            Self::PathMustBeAbsolute => f.write_str("journal path must be absolute"),
            Self::PathHasUnnormalizedComponents => {
                f.write_str("journal path has unnormalized components")
            }
            Self::PathHasNoFileName => f.write_str("journal path has no file name"),
            Self::ParentMissing => f.write_str("journal parent is missing"),
            Self::ParentNotDirectory => f.write_str("journal parent is not a directory"),
            Self::ParentSymlink => f.write_str("journal parent is a symlink"),
            Self::ParentNotControlled => f.write_str("journal parent is not controlled"),
            Self::ParentPersistenceUnavailable => {
                f.write_str("journal parent persistence is unavailable")
            }
            Self::CreationMayHaveLeftTarget => {
                f.write_str("journal creation failed; target may have been left behind")
            }
            Self::TargetMissing => f.write_str("journal target is missing"),
            Self::TargetExists => f.write_str("journal target already exists"),
            Self::TargetSymlink => f.write_str("journal target is a symlink"),
            Self::TargetNotRegular => f.write_str("journal target is not a regular file"),
            Self::TargetPermissions => f.write_str("journal target permissions are not private"),
            Self::LockUnavailable => f.write_str("journal writer lock is unavailable"),
            Self::LockUnsupported => f.write_str("journal writer locking is unsupported"),
            Self::ExistingFileEmpty => {
                f.write_str("an existing empty journal is not a trusted baseline")
            }
            Self::ExistingFileIncomplete => f.write_str("existing journal is incomplete"),
            Self::ExistingFileChanged => {
                f.write_str("existing journal changed during verification")
            }
            Self::FileLengthMismatch => {
                f.write_str("journal file length does not match verified frames")
            }
            Self::CursorMismatch => f.write_str("journal file cursor is not at the verified end"),
            Self::EmptyBatch => f.write_str("journal append batch is empty"),
            Self::BatchLimitExceeded => f.write_str("journal append batch limit exceeded"),
            Self::FrameLimitExceeded => f.write_str("journal frame limit exceeded"),
            Self::StickyUnknown => f.write_str("journal state is unknown and append is disabled"),
            Self::UnknownAfterIo => f.write_str("journal write or flush outcome is unknown"),
            Self::Frame(error) => write!(f, "journal frame validation failed: {error:?}"),
            Self::Io { operation, kind } => {
                write!(f, "journal I/O failed during {operation:?}: {kind:?}")
            }
        }
    }
}

impl std::error::Error for JournalFileError {}

impl From<JournalError> for JournalFileError {
    // memory—v1
    // memory—v1
    fn from(error: JournalError) -> Self {
        Self::Frame(error)
    }
}

/// Local result after a checked append and successful file and directory sync.
///
/// This is deliberately not a durable proof. APFS/device power-loss behavior,
/// root atomicity, authorization, and audit completeness require an external
/// protocol and evidence.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct LocalJournalFlush {
    start_offset: u64,
    end_offset: u64,
    records: u64,
    bytes: u64,
}

impl fmt::Debug for LocalJournalFlush {
    // memory—v1
    // memory—v1
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalJournalFlush")
            .field("start_offset", &self.start_offset)
            .field("end_offset", &self.end_offset)
            .field("records", &self.records)
            .field("bytes", &self.bytes)
            .finish()
    }
}

impl LocalJournalFlush {
    // memory—v1
    pub const fn start_offset(&self) -> u64 {
        self.start_offset
    }
    // memory—v1
    pub const fn end_offset(&self) -> u64 {
        self.end_offset
    }
    // memory—v1
    pub const fn records(&self) -> u64 {
        self.records
    }
    // memory—v1
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// Whether a handle may append or confirm a position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalFileState {
    Ready,
    StickyUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalHealth {
    Ready,
    StickyUnknown,
}

/// An exclusively locked, bounded local journal file.
pub struct JournalFile {
    file: File,
    directory: File,
    verifier: JournalVerifier,
    limits: JournalFileLimits,
    file_position: u64,
    record_count: u64,
    health: JournalHealth,
    precheck_failures: u8,
}

impl fmt::Debug for JournalFile {
    // memory—v1
    // memory—v1
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JournalFile([REDACTED])")
    }
}

impl JournalFile {
    /// Create a new target only when the target does not exist. Both file and
    /// parent-directory `sync_all` must succeed before returning a handle.
    // memory—v1
    pub fn create(
        path: &Path,
        anchor: JournalAnchor,
        limits: JournalFileLimits,
    ) -> Result<Self, JournalFileError> {
        limits.validate()?;
        let resolved = resolve_path(path)?;
        reject_existing_target(&resolved.target)?;
        let directory = open_controlled_directory(&resolved.parent)?;
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&resolved.target)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(JournalFileError::TargetExists)
            }
            Err(error) => {
                return Err(JournalFileError::Io {
                    operation: FileIoOperation::CreateTarget,
                    kind: error.kind(),
                })
            }
        };
        let configured = (|| {
            ensure_regular_file(&file)?;
            set_private_permissions(&file)?;
            lock_target(&file)?;
            let verifier = verifier_for(anchor, limits)?;
            if file_len(&file)? != 0 {
                return Err(JournalFileError::FileLengthMismatch);
            }
            sync_file(&file)?;
            sync_directory(&directory)?;
            Ok(Self {
                file,
                directory,
                verifier,
                limits,
                file_position: 0,
                record_count: 0,
                health: JournalHealth::Ready,
                precheck_failures: 0,
            })
        })();
        configured.map_err(|_| JournalFileError::CreationMayHaveLeftTarget)
    }

    /// Reopen a non-empty existing target only after complete bounded scan and
    /// external-tail comparison. No truncation, repair, or automatic recovery.
    // memory—v1
    pub fn open(
        path: &Path,
        anchor: JournalAnchor,
        expected_tail: JournalTail,
        limits: JournalFileLimits,
    ) -> Result<Self, JournalFileError> {
        limits.validate()?;
        let resolved = resolve_path(path)?;
        inspect_existing_target(&resolved.target)?;
        let directory = open_controlled_directory(&resolved.parent)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&resolved.target)
            .map_err(|error| JournalFileError::Io {
                operation: FileIoOperation::OpenTarget,
                kind: error.kind(),
            })?;
        ensure_regular_file(&file)?;
        ensure_private_permissions(&file)?;
        lock_target(&file)?;
        let initial_length = file_len(&file)?;
        if initial_length == 0 {
            return Err(JournalFileError::ExistingFileEmpty);
        }
        if initial_length > limits.max_bytes {
            return Err(JournalFileError::Frame(JournalError::LimitExceeded));
        }
        let verifier = verifier_for(anchor, limits)?;
        let scan_file = file.try_clone().map_err(|error| JournalFileError::Io {
            operation: FileIoOperation::OpenTarget,
            kind: error.kind(),
        })?;
        let (verifier, verified_length, record_count) =
            scan_existing_file(scan_file, verifier, limits)?;
        if verified_length != initial_length {
            return Err(JournalFileError::ExistingFileChanged);
        }
        verifier
            .finish(expected_tail)
            .map_err(JournalFileError::Frame)?;
        let final_length = file_len(&file)?;
        if final_length != verified_length {
            return Err(JournalFileError::ExistingFileChanged);
        }
        file.seek(SeekFrom::Start(verified_length))
            .map_err(|error| JournalFileError::Io {
                operation: FileIoOperation::SeekTarget,
                kind: error.kind(),
            })?;
        let cursor = file
            .stream_position()
            .map_err(|error| JournalFileError::Io {
                operation: FileIoOperation::SeekTarget,
                kind: error.kind(),
            })?;
        if cursor != verified_length {
            return Err(JournalFileError::CursorMismatch);
        }
        Ok(Self {
            file,
            directory,
            verifier,
            limits,
            file_position: verified_length,
            record_count,
            health: JournalHealth::Ready,
            precheck_failures: 0,
        })
    }

    /// Sticky unknown is terminal for this handle.
    // memory—v1
    pub const fn state(&self) -> JournalFileState {
        match self.health {
            JournalHealth::Ready => JournalFileState::Ready,
            JournalHealth::StickyUnknown => JournalFileState::StickyUnknown,
        }
    }

    /// Return the verified chain position while this handle remains known-good.
    // memory—v1
    pub fn position(&self) -> Result<JournalAnchor, JournalFileError> {
        self.ensure_ready()?;
        Ok(self.verifier.position())
    }

    /// Compare with an independently supplied tail. This does not establish
    /// tail provenance, durability, root atomicity, or audit completeness.
    // memory—v1
    pub fn finish(&self, expected_tail: JournalTail) -> Result<(), JournalFileError> {
        self.ensure_ready()?;
        self.verifier
            .finish(expected_tail)
            .map_err(JournalFileError::Frame)
    }

    /// Encode and validate before touching the file.
    // memory—v1
    pub fn append_record(
        &mut self,
        record: &JournalRecord<'_>,
    ) -> Result<LocalJournalFlush, JournalFileError> {
        self.ensure_ready()?;
        let frame = match encode_record(record) {
            Ok(frame) => frame,
            Err(error) => return self.record_precheck_failure(JournalFileError::Frame(error)),
        };
        self.append_frames(&[frame.as_slice()])
    }

    /// Encode all records, validate the complete batch against a cloned
    /// verifier, then append it as one contiguous checked batch.
    // memory—v1
    pub fn append_records<'a>(
        &mut self,
        records: &[JournalRecord<'a>],
    ) -> Result<LocalJournalFlush, JournalFileError> {
        self.ensure_ready()?;
        let requested_records =
            u64::try_from(records.len()).map_err(|_| JournalFileError::BatchLimitExceeded)?;
        let available_records = self
            .limits
            .max_records
            .checked_sub(self.record_count)
            .ok_or(JournalFileError::BatchLimitExceeded)?;
        let max_batch_records = (self.limits.max_batch_bytes / MIN_FRAME_BYTES).max(1);
        if records.is_empty()
            || requested_records > available_records
            || requested_records > max_batch_records
        {
            return self.record_precheck_failure(JournalFileError::BatchLimitExceeded);
        }
        let reserve_records = usize::try_from(requested_records.min(max_batch_records))
            .map_err(|_| JournalFileError::BatchLimitExceeded)?;
        let mut encoded = Vec::new();
        encoded
            .try_reserve(reserve_records)
            .map_err(|_| JournalFileError::BatchLimitExceeded)?;
        let mut total = 0_u64;
        for record in records {
            let frame = match encode_record(record) {
                Ok(frame) => frame,
                Err(error) => return self.record_precheck_failure(JournalFileError::Frame(error)),
            };
            total = match total.checked_add(frame.len() as u64) {
                Some(total) => total,
                None => return self.record_precheck_failure(JournalFileError::BatchLimitExceeded),
            };
            if total > self.limits.max_batch_bytes {
                return self.record_precheck_failure(JournalFileError::BatchLimitExceeded);
            }
            encoded.push(frame);
        }
        let mut frames = Vec::new();
        frames
            .try_reserve(reserve_records)
            .map_err(|_| JournalFileError::BatchLimitExceeded)?;
        frames.extend(encoded.iter().map(Vec::as_slice));
        self.append_frames(&frames)
    }

    /// Validate all frames before writing any byte. The verifier and file
    /// position advance only after file and directory sync both succeed.
    // memory—v1
    pub fn append_frames(
        &mut self,
        frames: &[&[u8]],
    ) -> Result<LocalJournalFlush, JournalFileError> {
        self.ensure_ready()?;
        let requested_records =
            u64::try_from(frames.len()).map_err(|_| JournalFileError::BatchLimitExceeded)?;
        let available_records = self
            .limits
            .max_records
            .checked_sub(self.record_count)
            .ok_or(JournalFileError::BatchLimitExceeded)?;
        let max_batch_records = (self.limits.max_batch_bytes / MIN_FRAME_BYTES).max(1);
        if frames.is_empty()
            || requested_records > available_records
            || requested_records > max_batch_records
        {
            return self.record_precheck_failure(JournalFileError::BatchLimitExceeded);
        }
        let mut next = self.verifier.clone();
        let mut total = 0_u64;
        let mut precheck_records = 0_u64;
        for frame in frames {
            precheck_records = match precheck_records.checked_add(1) {
                Some(count) => count,
                None => return self.record_precheck_failure(JournalFileError::BatchLimitExceeded),
            };
            let length = match u64::try_from(frame.len()) {
                Ok(length) => length,
                Err(_) => {
                    return self.record_precheck_failure(JournalFileError::FrameLimitExceeded)
                }
            };
            if length < MIN_FRAME_BYTES || length > self.limits.max_frame_bytes {
                return self.record_precheck_failure(JournalFileError::FrameLimitExceeded);
            }
            total = match total.checked_add(length) {
                Some(total) => total,
                None => return self.record_precheck_failure(JournalFileError::BatchLimitExceeded),
            };
            if total > self.limits.max_batch_bytes {
                return self.record_precheck_failure(JournalFileError::BatchLimitExceeded);
            }
            if let Err(error) = next.advance(frame) {
                return self.record_precheck_failure(JournalFileError::Frame(error));
            }
        }
        let next_record_count = match self.record_count.checked_add(precheck_records) {
            Some(count) => count,
            None => return self.record_precheck_failure(JournalFileError::BatchLimitExceeded),
        };
        let end_position = match self.file_position.checked_add(total) {
            Some(position) => position,
            None => return self.record_precheck_failure(JournalFileError::BatchLimitExceeded),
        };
        if end_position > self.limits.max_bytes {
            return self
                .record_precheck_failure(JournalFileError::Frame(JournalError::LimitExceeded));
        }
        let total_usize = match usize::try_from(total) {
            Ok(total) => total,
            Err(_) => return self.record_precheck_failure(JournalFileError::BatchLimitExceeded),
        };
        let mut bytes = Vec::new();
        if bytes.try_reserve(total_usize).is_err() {
            return self.record_precheck_failure(JournalFileError::BatchLimitExceeded);
        }
        for frame in frames {
            bytes.extend_from_slice(frame);
        }
        if bytes.len() as u64 != total {
            self.health = JournalHealth::StickyUnknown;
            return Err(JournalFileError::FileLengthMismatch);
        }
        let actual_length = match file_len(&self.file) {
            Ok(length) => length,
            Err(error) => {
                self.health = JournalHealth::StickyUnknown;
                return Err(error);
            }
        };
        if actual_length != self.file_position {
            self.health = JournalHealth::StickyUnknown;
            return Err(JournalFileError::FileLengthMismatch);
        }
        let cursor = match self.file.stream_position() {
            Ok(cursor) => cursor,
            Err(error) => {
                self.health = JournalHealth::StickyUnknown;
                return Err(JournalFileError::Io {
                    operation: FileIoOperation::SeekTarget,
                    kind: error.kind(),
                });
            }
        };
        if cursor != self.file_position {
            self.health = JournalHealth::StickyUnknown;
            return Err(JournalFileError::CursorMismatch);
        }
        let mut file_sink = FileSink(&mut self.file);
        let mut directory_sink = FileSink(&mut self.directory);
        if let Err(error) = commit_to_sinks(
            &mut self.health,
            &mut file_sink,
            &mut directory_sink,
            &bytes,
            self.file_position,
            end_position,
        ) {
            return Err(error.into_file_error());
        }
        self.verifier = next;
        self.file_position = end_position;
        let final_cursor = match self.file.stream_position() {
            Ok(cursor) => cursor,
            Err(error) => {
                self.health = JournalHealth::StickyUnknown;
                return Err(JournalFileError::Io {
                    operation: FileIoOperation::SeekTarget,
                    kind: error.kind(),
                });
            }
        };
        if final_cursor != end_position {
            self.health = JournalHealth::StickyUnknown;
            return Err(JournalFileError::CursorMismatch);
        }
        self.record_count = next_record_count;
        self.precheck_failures = 0;
        Ok(LocalJournalFlush {
            start_offset: end_position - total,
            end_offset: end_position,
            records: frames.len() as u64,
            bytes: total,
        })
    }

    // memory—v1
    // memory—v1
    fn ensure_ready(&self) -> Result<(), JournalFileError> {
        match self.health {
            JournalHealth::Ready => Ok(()),
            JournalHealth::StickyUnknown => Err(JournalFileError::StickyUnknown),
        }
    }

    // memory—v1
    // memory—v1
    fn record_precheck_failure<T>(
        &mut self,
        error: JournalFileError,
    ) -> Result<T, JournalFileError> {
        self.precheck_failures = self.precheck_failures.saturating_add(1);
        if self.precheck_failures >= MAX_PRECHECK_FAILURES {
            self.health = JournalHealth::StickyUnknown;
            return Err(JournalFileError::StickyUnknown);
        }
        Err(error)
    }
}

struct ResolvedPath {
    parent: PathBuf,
    target: PathBuf,
}

// memory—v1
fn resolve_path(path: &Path) -> Result<ResolvedPath, JournalFileError> {
    if !path.is_absolute() {
        return Err(JournalFileError::PathMustBeAbsolute);
    }
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(JournalFileError::PathHasUnnormalizedComponents);
    }
    let file_name = path
        .file_name()
        .ok_or(JournalFileError::PathHasNoFileName)?;
    let parent = path.parent().ok_or(JournalFileError::PathHasNoFileName)?;
    let metadata = fs::symlink_metadata(parent).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => JournalFileError::ParentMissing,
        kind => JournalFileError::Io {
            operation: FileIoOperation::ResolveParent,
            kind,
        },
    })?;
    if metadata.file_type().is_symlink() {
        return Err(JournalFileError::ParentSymlink);
    }
    if !metadata.is_dir() {
        return Err(JournalFileError::ParentNotDirectory);
    }
    ensure_controlled_directory_permissions(&metadata)?;
    let canonical_parent = fs::canonicalize(parent).map_err(|error| JournalFileError::Io {
        operation: FileIoOperation::ResolveParent,
        kind: error.kind(),
    })?;
    let canonical_metadata =
        fs::symlink_metadata(&canonical_parent).map_err(|error| JournalFileError::Io {
            operation: FileIoOperation::ResolveParent,
            kind: error.kind(),
        })?;
    if canonical_metadata.file_type().is_symlink() || !canonical_metadata.is_dir() {
        return Err(JournalFileError::ParentNotDirectory);
    }
    ensure_controlled_directory_permissions(&canonical_metadata)?;
    Ok(ResolvedPath {
        parent: canonical_parent.clone(),
        target: canonical_parent.join(file_name),
    })
}

// memory—v1
fn ensure_controlled_directory_permissions(
    metadata: &fs::Metadata,
) -> Result<(), JournalFileError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(JournalFileError::ParentNotControlled);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(JournalFileError::ParentPersistenceUnavailable)
    }
}

// memory—v1
fn open_controlled_directory(path: &Path) -> Result<File, JournalFileError> {
    let directory = File::open(path).map_err(|error| JournalFileError::Io {
        operation: FileIoOperation::OpenParent,
        kind: error.kind(),
    })?;
    if !directory
        .metadata()
        .map_err(|error| JournalFileError::Io {
            operation: FileIoOperation::OpenParent,
            kind: error.kind(),
        })?
        .is_dir()
    {
        return Err(JournalFileError::ParentNotDirectory);
    }
    Ok(directory)
}

// memory—v1
fn reject_existing_target(path: &Path) -> Result<(), JournalFileError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(JournalFileError::TargetSymlink),
        Ok(_) => Err(JournalFileError::TargetExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(JournalFileError::Io {
            operation: FileIoOperation::InspectTarget,
            kind: error.kind(),
        }),
    }
}

// memory—v1
fn inspect_existing_target(path: &Path) -> Result<(), JournalFileError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => JournalFileError::TargetMissing,
        kind => JournalFileError::Io {
            operation: FileIoOperation::InspectTarget,
            kind,
        },
    })?;
    if metadata.file_type().is_symlink() {
        return Err(JournalFileError::TargetSymlink);
    }
    if !metadata.is_file() {
        return Err(JournalFileError::TargetNotRegular);
    }
    ensure_private_permissions_from_metadata(&metadata)
}

// memory—v1
fn ensure_regular_file(file: &File) -> Result<(), JournalFileError> {
    let metadata = file.metadata().map_err(|error| JournalFileError::Io {
        operation: FileIoOperation::InspectTarget,
        kind: error.kind(),
    })?;
    if !metadata.is_file() {
        return Err(JournalFileError::TargetNotRegular);
    }
    Ok(())
}

// memory—v1
fn set_private_permissions(file: &File) -> Result<(), JournalFileError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| JournalFileError::Io {
                operation: FileIoOperation::CreateTarget,
                kind: error.kind(),
            })?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Err(JournalFileError::ParentPersistenceUnavailable)
    }
}

// memory—v1
fn ensure_private_permissions(file: &File) -> Result<(), JournalFileError> {
    let metadata = file.metadata().map_err(|error| JournalFileError::Io {
        operation: FileIoOperation::InspectTarget,
        kind: error.kind(),
    })?;
    ensure_private_permissions_from_metadata(&metadata)
}

// memory—v1
fn ensure_private_permissions_from_metadata(
    metadata: &fs::Metadata,
) -> Result<(), JournalFileError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(JournalFileError::TargetPermissions);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(JournalFileError::ParentPersistenceUnavailable)
    }
}

// memory—v1
fn lock_target(file: &File) -> Result<(), JournalFileError> {
    file.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => JournalFileError::LockUnavailable,
        TryLockError::Error(error) => match error.kind() {
            io::ErrorKind::Unsupported => JournalFileError::LockUnsupported,
            kind => JournalFileError::Io {
                operation: FileIoOperation::LockTarget,
                kind,
            },
        },
    })
}

// memory—v1
fn verifier_for(
    anchor: JournalAnchor,
    limits: JournalFileLimits,
) -> Result<JournalVerifier, JournalFileError> {
    JournalVerifier::new(anchor, limits.max_records, limits.max_bytes)
        .map_err(JournalFileError::Frame)
}

// memory—v1
fn file_len(file: &File) -> Result<u64, JournalFileError> {
    file.metadata()
        .map(|metadata| metadata.len())
        .map_err(|error| JournalFileError::Io {
            operation: FileIoOperation::InspectLength,
            kind: error.kind(),
        })
}

// memory—v1
fn sync_file(file: &File) -> Result<(), JournalFileError> {
    file.sync_all().map_err(|error| JournalFileError::Io {
        operation: FileIoOperation::SyncTarget,
        kind: error.kind(),
    })
}

// memory—v1
fn sync_directory(directory: &File) -> Result<(), JournalFileError> {
    directory.sync_all().map_err(|error| match error.kind() {
        io::ErrorKind::Unsupported => JournalFileError::ParentPersistenceUnavailable,
        kind => JournalFileError::Io {
            operation: FileIoOperation::SyncParent,
            kind,
        },
    })
}

// memory—v1
fn scan_existing_file(
    mut file: File,
    mut verifier: JournalVerifier,
    limits: JournalFileLimits,
) -> Result<(JournalVerifier, u64, u64), JournalFileError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| JournalFileError::Io {
            operation: FileIoOperation::SeekTarget,
            kind: error.kind(),
        })?;
    let mut verified_length = 0_u64;
    let mut record_count = 0_u64;
    loop {
        let mut prefix = [0_u8; FRAME_PREFIX_BYTES];
        match read_prefix(&mut file, &mut prefix)? {
            PrefixRead::End => break,
            PrefixRead::Complete => {}
            PrefixRead::Incomplete => return Err(JournalFileError::ExistingFileIncomplete),
        }
        let length = frame_length(&prefix).map_err(JournalFileError::Frame)?;
        let length_u64 = length as u64;
        if length_u64 > limits.max_frame_bytes {
            return Err(JournalFileError::FrameLimitExceeded);
        }
        verified_length = verified_length
            .checked_add(length_u64)
            .ok_or(JournalFileError::Frame(JournalError::LimitExceeded))?;
        if verified_length > limits.max_bytes {
            return Err(JournalFileError::Frame(JournalError::LimitExceeded));
        }
        let mut frame = Vec::new();
        frame
            .try_reserve(length)
            .map_err(|_| JournalFileError::FrameLimitExceeded)?;
        frame.resize(length, 0);
        frame[..FRAME_PREFIX_BYTES].copy_from_slice(&prefix);
        file.read_exact(&mut frame[FRAME_PREFIX_BYTES..])
            .map_err(|error| {
                if error.kind() == io::ErrorKind::UnexpectedEof {
                    JournalFileError::ExistingFileIncomplete
                } else {
                    JournalFileError::Io {
                        operation: FileIoOperation::ReadTarget,
                        kind: error.kind(),
                    }
                }
            })?;
        verifier.advance(&frame).map_err(JournalFileError::Frame)?;
        record_count = record_count
            .checked_add(1)
            .ok_or(JournalFileError::Frame(JournalError::LimitExceeded))?;
    }
    let cursor = file
        .stream_position()
        .map_err(|error| JournalFileError::Io {
            operation: FileIoOperation::SeekTarget,
            kind: error.kind(),
        })?;
    if cursor != verified_length {
        return Err(JournalFileError::ExistingFileChanged);
    }
    Ok((verifier, verified_length, record_count))
}

enum PrefixRead {
    End,
    Complete,
    Incomplete,
}

// memory—v1
fn read_prefix(
    file: &mut File,
    prefix: &mut [u8; FRAME_PREFIX_BYTES],
) -> Result<PrefixRead, JournalFileError> {
    let mut read = 0;
    while read < prefix.len() {
        match file.read(&mut prefix[read..]) {
            Ok(0) if read == 0 => return Ok(PrefixRead::End),
            Ok(0) => return Ok(PrefixRead::Incomplete),
            Ok(count) => read += count,
            Err(error) => {
                return Err(JournalFileError::Io {
                    operation: FileIoOperation::ReadTarget,
                    kind: error.kind(),
                })
            }
        }
    }
    Ok(PrefixRead::Complete)
}

trait JournalSink {
    // memory—v1
    fn write_chunk(&mut self, bytes: &[u8]) -> io::Result<usize>;
    // memory—v1
    fn sync(&mut self) -> io::Result<()>;
    // memory—v1
    fn len(&self) -> io::Result<u64>;
}

struct FileSink<'a>(&'a mut File);

impl JournalSink for FileSink<'_> {
    // memory—v1
    fn write_chunk(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write(bytes)
    }
    // memory—v1
    fn sync(&mut self) -> io::Result<()> {
        self.0.sync_all()
    }
    // memory—v1
    fn len(&self) -> io::Result<u64> {
        self.0.metadata().map(|metadata| metadata.len())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommitOperation {
    LengthBeforeWrite,
    Write,
    LengthAfterWrite,
    SyncFile,
    SyncDirectory,
    LengthAfterSync,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommitError {
    Io {
        operation: CommitOperation,
        kind: io::ErrorKind,
    },
    LengthMismatch,
    WriteZero,
    InvalidWriteCount,
    StickyUnknown,
}

impl CommitError {
    // memory—v1
    fn into_file_error(self) -> JournalFileError {
        match self {
            Self::Io { operation, kind } => JournalFileError::Io {
                operation: match operation {
                    CommitOperation::LengthBeforeWrite
                    | CommitOperation::LengthAfterWrite
                    | CommitOperation::LengthAfterSync => FileIoOperation::InspectLength,
                    CommitOperation::Write => FileIoOperation::WriteTarget,
                    CommitOperation::SyncFile => FileIoOperation::SyncTarget,
                    CommitOperation::SyncDirectory => FileIoOperation::SyncParent,
                },
                kind,
            },
            Self::LengthMismatch | Self::InvalidWriteCount => JournalFileError::FileLengthMismatch,
            Self::WriteZero => JournalFileError::UnknownAfterIo,
            Self::StickyUnknown => JournalFileError::StickyUnknown,
        }
    }
}

// memory—v1
fn commit_to_sinks<S: JournalSink, D: JournalSink>(
    health: &mut JournalHealth,
    file: &mut S,
    directory: &mut D,
    bytes: &[u8],
    start_position: u64,
    end_position: u64,
) -> Result<(), CommitError> {
    if *health != JournalHealth::Ready {
        return Err(CommitError::StickyUnknown);
    }
    let before = match file.len() {
        Ok(length) => length,
        Err(error) => {
            *health = JournalHealth::StickyUnknown;
            return Err(CommitError::Io {
                operation: CommitOperation::LengthBeforeWrite,
                kind: error.kind(),
            });
        }
    };
    if before != start_position {
        *health = JournalHealth::StickyUnknown;
        return Err(CommitError::LengthMismatch);
    }
    let mut written = 0;
    while written < bytes.len() {
        let count = match file.write_chunk(&bytes[written..]) {
            Ok(count) => count,
            Err(error) => {
                *health = JournalHealth::StickyUnknown;
                return Err(CommitError::Io {
                    operation: CommitOperation::Write,
                    kind: error.kind(),
                });
            }
        };
        if count == 0 {
            *health = JournalHealth::StickyUnknown;
            return Err(CommitError::WriteZero);
        }
        if count > bytes.len() - written {
            *health = JournalHealth::StickyUnknown;
            return Err(CommitError::InvalidWriteCount);
        }
        written += count;
    }
    let after_write = match file.len() {
        Ok(length) => length,
        Err(error) => {
            *health = JournalHealth::StickyUnknown;
            return Err(CommitError::Io {
                operation: CommitOperation::LengthAfterWrite,
                kind: error.kind(),
            });
        }
    };
    if after_write != end_position {
        *health = JournalHealth::StickyUnknown;
        return Err(CommitError::LengthMismatch);
    }
    file.sync().map_err(|error| {
        *health = JournalHealth::StickyUnknown;
        CommitError::Io {
            operation: CommitOperation::SyncFile,
            kind: error.kind(),
        }
    })?;
    directory.sync().map_err(|error| {
        *health = JournalHealth::StickyUnknown;
        CommitError::Io {
            operation: CommitOperation::SyncDirectory,
            kind: error.kind(),
        }
    })?;
    let after_sync = match file.len() {
        Ok(length) => length,
        Err(error) => {
            *health = JournalHealth::StickyUnknown;
            return Err(CommitError::Io {
                operation: CommitOperation::LengthAfterSync,
                kind: error.kind(),
            });
        }
    };
    if after_sync == end_position {
        Ok(())
    } else {
        *health = JournalHealth::StickyUnknown;
        Err(CommitError::LengthMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::memory_v1::MemoryId;
    use astral_types::memory_v1_journal::{RecordKind, MAX_PAYLOAD_BYTES};
    use std::env;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        // memory—v1
        fn new() -> Self {
            let root = fs::canonicalize(env::temp_dir()).expect("temp root");
            let pid = std::process::id();
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            for _ in 0..8 {
                let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
                let path = root.join(format!(".astral-journal-{pid}-{stamp}-{serial}"));
                match fs::create_dir(&path) {
                    Ok(()) => {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                                .expect("private test directory");
                        }
                        return Self { path };
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("test directory creation failed: {error:?}"),
                }
            }
            panic!("test directory collision budget exhausted")
        }
        // memory—v1
        fn file(&self) -> PathBuf {
            self.path.join("journal.bin")
        }
    }

    impl Drop for TestDir {
        // memory—v1
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    // memory—v1
    fn limits() -> JournalFileLimits {
        JournalFileLimits::new(16, 64 * 1024, 16 * 1024, 64 * 1024).unwrap()
    }
    // memory—v1
    fn id(value: u8) -> MemoryId {
        MemoryId::from_bytes([value; 16])
    }
    // memory—v1
    fn anchor() -> JournalAnchor {
        JournalAnchor::new(id(1), 0, 0, [5; 32]).unwrap()
    }
    // memory—v1
    fn record<'a>(
        kind: RecordKind,
        journal_sequence: u64,
        mutation_sequence: u64,
        prev_hash: [u8; 32],
        payload: &'a [u8],
    ) -> JournalRecord<'a> {
        JournalRecord {
            stream_id: id(1),
            epoch_id: id(2),
            journal_sequence,
            message_id: id(3),
            operation_id: "operation",
            request_fingerprint: [4; 32],
            kind,
            mutation_sequence,
            prev_hash,
            payload,
        }
    }

    // memory—v1
    fn known_record<'a>() -> JournalRecord<'a> {
        JournalRecord {
            stream_id: id(1),
            epoch_id: id(2),
            journal_sequence: 1,
            message_id: id(3),
            operation_id: "op",
            request_fingerprint: [4; 32],
            kind: RecordKind::Mutation,
            mutation_sequence: 1,
            prev_hash: [5; 32],
            payload: &[0xaa],
        }
    }

    // memory—v1
    fn known_external_tail() -> JournalTail {
        JournalAnchor::new(
            id(1),
            1,
            1,
            [
                0x1a, 0xe3, 0x4c, 0xd8, 0x71, 0x65, 0x6b, 0xa3, 0x60, 0x79, 0x23, 0xb4, 0xc2, 0xf3,
                0x58, 0x5f, 0x4c, 0x48, 0xc1, 0x48, 0xcb, 0xb9, 0xe4, 0xf5, 0x9a, 0xb5, 0xb2, 0x30,
                0x0c, 0x5a, 0x88, 0xa9,
            ],
        )
        .unwrap()
    }

    #[test]
    // memory—v1
    fn create_append_reopen_and_tail_check() {
        let directory = TestDir::new();
        let path = directory.file();
        let mut journal = JournalFile::create(&path, anchor(), limits()).unwrap();
        let receipt = journal.append_record(&known_record()).unwrap();
        assert_eq!(receipt.records(), 1);
        assert!(receipt.bytes() > 0);
        let expected_tail = known_external_tail();
        assert_eq!(journal.position().unwrap(), expected_tail);
        drop(journal);
        let reopened = JournalFile::open(&path, anchor(), expected_tail, limits()).unwrap();
        assert_eq!(reopened.position().unwrap(), expected_tail);
        reopened.finish(expected_tail).unwrap();
    }

    #[test]
    // memory—v1
    fn empty_existing_file_is_rejected_without_repair() {
        let directory = TestDir::new();
        let path = directory.file();
        let journal = JournalFile::create(&path, anchor(), limits()).unwrap();
        drop(journal);
        assert!(matches!(
            JournalFile::open(&path, anchor(), anchor(), limits()),
            Err(JournalFileError::ExistingFileEmpty)
        ));
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
    }

    #[test]
    // memory—v1
    fn tamper_and_truncate_fail_closed_without_repair() {
        let directory = TestDir::new();
        let path = directory.file();
        let mut journal = JournalFile::create(&path, anchor(), limits()).unwrap();
        journal
            .append_record(&record(RecordKind::Mutation, 1, 1, [5; 32], b"payload"))
            .unwrap();
        let tail = journal.position().unwrap();
        drop(journal);
        let original = fs::read(&path).unwrap();
        let mut tampered = original.clone();
        tampered[FRAME_PREFIX_BYTES + 1] ^= 1;
        fs::write(&path, &tampered).unwrap();
        assert!(matches!(
            JournalFile::open(&path, anchor(), tail, limits()),
            Err(JournalFileError::Frame(JournalError::DigestMismatch))
        ));
        fs::write(&path, &original[..original.len() - 1]).unwrap();
        assert!(matches!(
            JournalFile::open(&path, anchor(), tail, limits()),
            Err(JournalFileError::ExistingFileIncomplete)
                | Err(JournalFileError::Frame(JournalError::InvalidLength))
        ));
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            (original.len() - 1) as u64
        );
    }

    #[test]
    // memory—v1
    fn capacity_rejection_writes_nothing() {
        let directory = TestDir::new();
        let path = directory.file();
        let small = JournalFileLimits::new(1, 4096, 4096, 4096).unwrap();
        let mut journal = JournalFile::create(&path, anchor(), small).unwrap();
        journal
            .append_record(&record(RecordKind::Mutation, 1, 1, [5; 32], b"one"))
            .unwrap();
        let before = journal.position().unwrap();
        let second = record(RecordKind::Mutation, 2, 2, *before.frame_hash(), b"two");
        let before_len = fs::metadata(&path).unwrap().len();
        assert_eq!(
            journal.append_record(&second),
            Err(JournalFileError::BatchLimitExceeded)
        );
        assert_eq!(journal.position().unwrap(), before);
        assert_eq!(fs::metadata(&path).unwrap().len(), before_len);
    }

    #[test]
    // memory—v1
    fn wrong_order_precheck_budget_becomes_sticky_unknown() {
        let directory = TestDir::new();
        let path = directory.file();
        let small = JournalFileLimits::new(2, 4096, 4096, 4096).unwrap();
        let mut journal = JournalFile::create(&path, anchor(), small).unwrap();
        journal
            .append_record(&record(RecordKind::Mutation, 1, 1, [5; 32], b"one"))
            .unwrap();
        let before = journal.position().unwrap();
        let wrong = record(RecordKind::Mutation, 3, 2, *before.frame_hash(), b"two");
        let before_len = fs::metadata(&path).unwrap().len();
        for _ in 0..(MAX_PRECHECK_FAILURES - 1) {
            assert_eq!(
                journal.append_record(&wrong),
                Err(JournalFileError::Frame(JournalError::ChainMismatch))
            );
            assert_eq!(journal.state(), JournalFileState::Ready);
        }
        assert_eq!(
            journal.append_record(&wrong),
            Err(JournalFileError::StickyUnknown)
        );
        assert_eq!(journal.state(), JournalFileState::StickyUnknown);
        assert_eq!(fs::metadata(&path).unwrap().len(), before_len);
    }

    #[test]
    // memory—v1
    fn oversized_payload_is_rejected_without_write() {
        let directory = TestDir::new();
        let path = directory.file();
        let mut journal = JournalFile::create(&path, anchor(), limits()).unwrap();
        let payload = vec![9_u8; MAX_PAYLOAD_BYTES + 1];
        assert_eq!(
            journal.append_record(&record(RecordKind::Deny, 1, 0, [5; 32], &payload)),
            Err(JournalFileError::Frame(JournalError::LimitExceeded))
        );
        assert_eq!(fs::metadata(&path).unwrap().len(), 0);
    }

    #[test]
    // memory—v1
    fn debug_output_redacts_handle_contents() {
        let directory = TestDir::new();
        let path = directory.file();
        let journal = JournalFile::create(&path, anchor(), limits()).unwrap();
        assert_eq!(format!("{journal:?}"), "JournalFile([REDACTED])");
    }

    struct FakeSink {
        bytes: Vec<u8>,
        max_write: Option<usize>,
        fail_after: Option<usize>,
        fail_sync: bool,
    }

    impl FakeSink {
        // memory—v1
        fn healthy() -> Self {
            Self {
                bytes: Vec::new(),
                max_write: None,
                fail_after: None,
                fail_sync: false,
            }
        }
    }

    impl JournalSink for FakeSink {
        fn write_chunk(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.fail_after == Some(self.bytes.len()) {
                return Err(io::Error::other("injected"));
            }
            let count = self.max_write.unwrap_or(bytes.len()).min(bytes.len());
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn sync(&mut self) -> io::Result<()> {
            if self.fail_sync {
                Err(io::Error::other("injected"))
            } else {
                Ok(())
            }
        }
        fn len(&self) -> io::Result<u64> {
            Ok(self.bytes.len() as u64)
        }
    }

    #[test]
    // memory—v1
    fn partial_write_and_sync_failure_are_sticky_unknown() {
        let mut health = JournalHealth::Ready;
        let mut file = FakeSink {
            max_write: Some(2),
            fail_after: Some(2),
            ..FakeSink::healthy()
        };
        let mut directory = FakeSink::healthy();
        assert!(commit_to_sinks(&mut health, &mut file, &mut directory, b"abcdef", 0, 6).is_err());
        assert_eq!(health, JournalHealth::StickyUnknown);
        assert_eq!(
            commit_to_sinks(&mut health, &mut file, &mut directory, b"abcdef", 0, 6),
            Err(CommitError::StickyUnknown)
        );

        let mut health = JournalHealth::Ready;
        let mut file = FakeSink {
            fail_sync: true,
            ..FakeSink::healthy()
        };
        let mut directory = FakeSink::healthy();
        assert!(commit_to_sinks(&mut health, &mut file, &mut directory, b"abc", 0, 3).is_err());
        assert_eq!(health, JournalHealth::StickyUnknown);
    }

    #[cfg(unix)]
    #[test]
    // memory—v1
    fn same_process_and_child_process_lock_competition_is_rejected() {
        let directory = TestDir::new();
        let path = directory.file();
        let journal = JournalFile::create(&path, anchor(), limits()).unwrap();
        let second = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert_eq!(lock_target(&second), Err(JournalFileError::LockUnavailable));
        drop(second);
        let status = Command::new(env::current_exe().unwrap())
            .arg("--exact")
            .arg("memory_v1_journal_file::tests::child_lock_probe")
            .arg("--nocapture")
            .arg("--ignored")
            .env("ASTRAL_JOURNAL_LOCK_PROBE", &path)
            .status()
            .unwrap();
        assert!(status.success());
        drop(journal);
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "only executed as a child of the lock-competition test"]
    // memory—v1
    // memory—v1
    fn child_lock_probe() {
        let path = env::var_os("ASTRAL_JOURNAL_LOCK_PROBE")
            .expect("child lock probe requires ASTRAL_JOURNAL_LOCK_PROBE");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        assert_eq!(lock_target(&file), Err(JournalFileError::LockUnavailable));
        std::process::exit(0);
    }
}
