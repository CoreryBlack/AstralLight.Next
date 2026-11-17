//! Bounded, in-memory memory-v1 journal framing and chain checks.
//!
//! This module does not authenticate inputs, establish an authoritative initial
//! snapshot, persist bytes, attest to audit payload completeness, or prove that
//! a file ends at a supplied boundary. A checkpoint and an expected tail must
//! come from an independently trusted source. A checksum chain alone supplies
//! neither provenance nor a durable or complete-recovery proof. Epoch lifecycle,
//! durable confirmation, and scheduling of mutation versus DENY are outside
//! this module; the layout does not prescribe a single FIFO writer.

use std::fmt;

use sha2::{Digest, Sha256};

use crate::memory_v1::MemoryId;

/// Maximum opaque payload size per record, in bytes.
pub const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;
/// Maximum operation identifier size, matching request binding.
pub const MAX_OPERATION_ID_BYTES: usize = 64;
/// Bytes needed to inspect the fixed frame prefix before reading its body.
pub const FRAME_PREFIX_BYTES: usize = 16;
/// Fixed header size, including the two variable-field lengths.
pub const FRAME_HEADER_BYTES: usize = 150;
/// SHA-256 digest size.
pub const FRAME_DIGEST_BYTES: usize = 32;
/// Maximum encoded frame size.
pub const MAX_FRAME_BYTES: usize =
    FRAME_HEADER_BYTES + MAX_OPERATION_ID_BYTES + MAX_PAYLOAD_BYTES + FRAME_DIGEST_BYTES;
/// Maximum number of frames one verifier can attempt to process.
/// Rejected frames consume this budget too.
pub const MAX_VERIFY_RECORDS: u64 = 1_000_000;
/// Maximum input bytes one verifier can attempt to process, including rejected frames.
pub const MAX_VERIFY_BYTES: u64 = 1024 * 1024 * 1024;

const MAGIC: &[u8; 8] = b"ALM1JNL\0";
const VERSION: u16 = 1;
const DOMAIN: &[u8] = b"astral-light/memory-v1/journal/frame/v1\0";

/// Closed set of record kinds. A DENY does not advance the mutation sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    /// An authorization mutation; its sequence must advance by one.
    Mutation,
    /// A denial; its sequence identifies the authorization state read.
    Deny,
}

/// A shape, bound, checksum, or chain failure; no supplied data is included.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalError {
    /// Unsupported version, kind, flag, magic, or noncanonical layout.
    InvalidEncoding,
    /// Frame or verification resource limit exceeded.
    LimitExceeded,
    /// Input does not contain exactly one complete frame.
    InvalidLength,
    /// A required identifier, operation identifier, or digest is invalid.
    InvalidField,
    /// Frame digest mismatch.
    DigestMismatch,
    /// Checkpoint, sequence, stream, previous hash, or expected tail mismatch.
    ChainMismatch,
    /// Sequence arithmetic would overflow.
    SequenceOverflow,
    /// No record was verified; an empty input does not establish a complete tail.
    EmptyRange,
}

impl fmt::Display for JournalError {
    // memory—v1
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "memory-v1 journal validation failed: {self:?}")
    }
}
impl std::error::Error for JournalError {}

/// Caller-supplied frame contents. Identifiers and fingerprints are not authenticated.
///
/// `mutation_sequence` is the new mutation sequence for a mutation, or the
/// sequence read by a DENY. An opaque payload is required and its semantics are
/// not validated here. For DENY, zero refers to the external baseline.
#[derive(Clone, Eq, PartialEq)]
pub struct JournalRecord<'a> {
    pub stream_id: MemoryId,
    pub epoch_id: MemoryId,
    pub journal_sequence: u64,
    pub message_id: MemoryId,
    pub operation_id: &'a str,
    pub request_fingerprint: [u8; 32],
    pub kind: RecordKind,
    pub mutation_sequence: u64,
    pub prev_hash: [u8; 32],
    pub payload: &'a [u8],
}

impl fmt::Debug for JournalRecord<'_> {
    // memory—v1
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JournalRecord([REDACTED])")
    }
}

/// A parsed frame and its checksum; the record borrows the input bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct DecodedRecord<'a> {
    pub record: JournalRecord<'a>,
    pub digest: [u8; 32],
}
impl fmt::Debug for DecodedRecord<'_> {
    // memory—v1
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DecodedRecord([REDACTED])")
    }
}

// memory—v1
fn nonzero(bytes: &[u8]) -> bool {
    bytes.iter().any(|byte| *byte != 0)
}

// memory—v1
fn valid_record(record: &JournalRecord<'_>) -> Result<(), JournalError> {
    let op = record.operation_id.as_bytes();
    if !nonzero(record.stream_id.as_bytes())
        || !nonzero(record.epoch_id.as_bytes())
        || !nonzero(record.message_id.as_bytes())
        || record.journal_sequence == 0
        || !nonzero(&record.request_fingerprint)
        || !nonzero(&record.prev_hash)
        || op.is_empty()
        || op.len() > MAX_OPERATION_ID_BYTES
        || !op
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(b))
        || (record.kind == RecordKind::Mutation && record.mutation_sequence == 0)
    {
        return Err(JournalError::InvalidField);
    }
    if record.payload.is_empty() {
        return Err(JournalError::InvalidField);
    }
    if record.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(JournalError::LimitExceeded);
    }
    Ok(())
}

// memory—v1
fn frame_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(bytes);
    hash.finalize().into()
}

/// Encode one canonical big-endian frame, including its domain-separated SHA-256.
///
/// memory—v1: The allocation is bounded by `MAX_FRAME_BYTES`; this creates no
/// persistence or authority evidence.
pub fn encode_record(record: &JournalRecord<'_>) -> Result<Vec<u8>, JournalError> {
    valid_record(record)?;
    let length =
        FRAME_HEADER_BYTES + record.operation_id.len() + record.payload.len() + FRAME_DIGEST_BYTES;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| JournalError::LimitExceeded)?;
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(match record.kind {
        RecordKind::Mutation => 1,
        RecordKind::Deny => 2,
    });
    bytes.push(0); // flags; all other values are reserved
    bytes.extend_from_slice(&(length as u32).to_be_bytes());
    bytes.extend_from_slice(record.stream_id.as_bytes());
    bytes.extend_from_slice(record.epoch_id.as_bytes());
    bytes.extend_from_slice(&record.journal_sequence.to_be_bytes());
    bytes.extend_from_slice(record.message_id.as_bytes());
    bytes.extend_from_slice(&record.mutation_sequence.to_be_bytes());
    bytes.extend_from_slice(&record.request_fingerprint);
    bytes.extend_from_slice(&record.prev_hash);
    bytes.extend_from_slice(&(record.operation_id.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&(record.payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(record.operation_id.as_bytes());
    bytes.extend_from_slice(record.payload);
    bytes.extend_from_slice(&frame_hash(&bytes));
    Ok(bytes)
}

/// Inspect the first 16 bytes to determine a bounded frame size before reading.
///
/// memory—v1: A valid prefix does not validate the rest of the frame. Extra
/// input after the prefix is ignored; use `decode_record` for exact framing.
pub fn frame_length(prefix: &[u8]) -> Result<usize, JournalError> {
    if prefix.len() < FRAME_PREFIX_BYTES {
        return Err(JournalError::InvalidLength);
    }
    if &prefix[..8] != MAGIC
        || prefix[8..10] != VERSION.to_be_bytes()
        || !matches!(prefix[10], 1 | 2)
        || prefix[11] != 0
    {
        return Err(JournalError::InvalidEncoding);
    }
    let length = u32::from_be_bytes(prefix[12..16].try_into().expect("fixed slice")) as usize;
    if length < FRAME_HEADER_BYTES + FRAME_DIGEST_BYTES + 2 {
        return Err(JournalError::InvalidLength);
    }
    if length > MAX_FRAME_BYTES {
        return Err(JournalError::LimitExceeded);
    }
    Ok(length)
}

/// Parse exactly one canonical frame without allocating or trusting its contents.
///
/// memory—v1: A digest verifies only agreement with these supplied bytes; use
/// a verifier anchored externally for chain ordering, and never infer a file tail.
pub fn decode_record(bytes: &[u8]) -> Result<DecodedRecord<'_>, JournalError> {
    let length = frame_length(bytes)?;
    if bytes.len() != length {
        return Err(JournalError::InvalidLength);
    }
    let operation_len =
        u16::from_be_bytes(bytes[144..146].try_into().expect("fixed slice")) as usize;
    let payload_len = u32::from_be_bytes(bytes[146..150].try_into().expect("fixed slice")) as usize;
    if operation_len == 0 || operation_len > MAX_OPERATION_ID_BYTES || payload_len == 0 {
        return Err(JournalError::InvalidField);
    }
    if payload_len > MAX_PAYLOAD_BYTES {
        return Err(JournalError::LimitExceeded);
    }
    let expected = FRAME_HEADER_BYTES
        .checked_add(operation_len)
        .and_then(|v| v.checked_add(payload_len))
        .and_then(|v| v.checked_add(FRAME_DIGEST_BYTES))
        .ok_or(JournalError::LimitExceeded)?;
    if expected != length {
        return Err(JournalError::InvalidLength);
    }
    let body_end = length - FRAME_DIGEST_BYTES;
    let digest: [u8; 32] = bytes[body_end..].try_into().expect("fixed digest length");
    if frame_hash(&bytes[..body_end]) != digest {
        return Err(JournalError::DigestMismatch);
    }
    let op_end = FRAME_HEADER_BYTES + operation_len;
    let operation_id = std::str::from_utf8(&bytes[FRAME_HEADER_BYTES..op_end])
        .map_err(|_| JournalError::InvalidField)?;
    let record = JournalRecord {
        stream_id: MemoryId::from_bytes(bytes[16..32].try_into().expect("fixed slice")),
        epoch_id: MemoryId::from_bytes(bytes[32..48].try_into().expect("fixed slice")),
        journal_sequence: u64::from_be_bytes(bytes[48..56].try_into().expect("fixed slice")),
        message_id: MemoryId::from_bytes(bytes[56..72].try_into().expect("fixed slice")),
        mutation_sequence: u64::from_be_bytes(bytes[72..80].try_into().expect("fixed slice")),
        request_fingerprint: bytes[80..112].try_into().expect("fixed slice"),
        prev_hash: bytes[112..144].try_into().expect("fixed slice"),
        kind: if bytes[10] == 1 {
            RecordKind::Mutation
        } else {
            RecordKind::Deny
        },
        operation_id,
        payload: &bytes[op_end..body_end],
    };
    valid_record(&record)?;
    Ok(DecodedRecord { record, digest })
}

/// External checkpoint or tail values. Construction validates shape only.
///
/// Even sequence zero requires a nonzero externally supplied hash; this module
/// has no trusted genesis. The caller must establish trust and baseline coverage
/// independently. Debug output is redacted.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct JournalAnchor {
    stream_id: MemoryId,
    journal_sequence: u64,
    mutation_sequence: u64,
    frame_hash: [u8; 32],
}
impl fmt::Debug for JournalAnchor {
    // memory—v1
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JournalAnchor([REDACTED])")
    }
}
impl JournalAnchor {
    /// memory—v1: Check shape only; this does not make the checkpoint trusted.
    pub fn new(
        stream_id: MemoryId,
        journal_sequence: u64,
        mutation_sequence: u64,
        frame_hash: [u8; 32],
    ) -> Result<Self, JournalError> {
        if !nonzero(stream_id.as_bytes()) || !nonzero(&frame_hash) {
            return Err(JournalError::InvalidField);
        }
        Ok(Self {
            stream_id,
            journal_sequence,
            mutation_sequence,
            frame_hash,
        })
    }
    /// memory—v1: Return the checkpoint stream.
    pub const fn stream_id(&self) -> MemoryId {
        self.stream_id
    }
    /// memory—v1: Return the checkpoint journal sequence.
    pub const fn journal_sequence(&self) -> u64 {
        self.journal_sequence
    }
    /// memory—v1: Return the checkpoint mutation sequence.
    pub const fn mutation_sequence(&self) -> u64 {
        self.mutation_sequence
    }
    /// memory—v1: Return the caller-supplied or computed frame hash.
    pub const fn frame_hash(&self) -> &[u8; 32] {
        &self.frame_hash
    }
}

/// The expected tail has the same shape as a checkpoint and must be supplied
/// independently; an observed file end or computed position is not trusted.
pub type JournalTail = JournalAnchor;

/// Incremental bounded checker, initialized only with an external checkpoint.
///
/// Checks framing and sequence consistency, not checkpoint/tail provenance,
/// epoch lifecycle, durable writes, or completeness. A DENY referring to a
/// sequence below the anchor is permitted; whether the trusted baseline covers
/// that observation requires separate evidence.
#[derive(Clone)]
pub struct JournalVerifier {
    position: JournalAnchor,
    records: u64,
    attempts: u64,
    bytes: u64,
    max_records: u64,
    max_bytes: u64,
}
impl fmt::Debug for JournalVerifier {
    // memory—v1
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JournalVerifier([REDACTED])")
    }
}
impl JournalVerifier {
    /// memory—v1: Start from a caller-supplied external checkpoint with finite limits.
    pub fn new(
        anchor: JournalAnchor,
        max_records: u64,
        max_bytes: u64,
    ) -> Result<Self, JournalError> {
        if max_records == 0
            || max_records > MAX_VERIFY_RECORDS
            || max_bytes == 0
            || max_bytes > MAX_VERIFY_BYTES
        {
            return Err(JournalError::LimitExceeded);
        }
        Ok(Self {
            position: anchor,
            records: 0,
            attempts: 0,
            bytes: 0,
            max_records,
            max_bytes,
        })
    }

    /// memory—v1: Consume bounded attempt and byte budgets before inspecting a frame.
    /// A rejected frame never changes the verified position, but does consume budget.
    pub fn advance<'a>(&mut self, bytes: &'a [u8]) -> Result<DecodedRecord<'a>, JournalError> {
        let next_attempts = self
            .attempts
            .checked_add(1)
            .ok_or(JournalError::LimitExceeded)?;
        let next_bytes = self
            .bytes
            .checked_add(u64::try_from(bytes.len()).map_err(|_| JournalError::LimitExceeded)?)
            .ok_or(JournalError::LimitExceeded)?;
        if next_attempts > self.max_records || next_bytes > self.max_bytes {
            return Err(JournalError::LimitExceeded);
        }
        self.attempts = next_attempts;
        self.bytes = next_bytes;
        let decoded = decode_record(bytes)?;
        let record = &decoded.record;
        let next_journal = self
            .position
            .journal_sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceOverflow)?;
        if record.stream_id != self.position.stream_id
            || record.journal_sequence != next_journal
            || record.prev_hash != self.position.frame_hash
        {
            return Err(JournalError::ChainMismatch);
        }
        let next_mutation = match record.kind {
            RecordKind::Mutation => {
                let expected = self
                    .position
                    .mutation_sequence
                    .checked_add(1)
                    .ok_or(JournalError::SequenceOverflow)?;
                if record.mutation_sequence != expected {
                    return Err(JournalError::ChainMismatch);
                }
                expected
            }
            RecordKind::Deny => {
                if record.mutation_sequence > self.position.mutation_sequence {
                    return Err(JournalError::ChainMismatch);
                }
                self.position.mutation_sequence
            }
        };
        self.position = JournalAnchor {
            stream_id: self.position.stream_id,
            journal_sequence: next_journal,
            mutation_sequence: next_mutation,
            frame_hash: decoded.digest,
        };
        self.records += 1;
        Ok(decoded)
    }

    /// memory—v1: Return the computed position, which is not independently trusted.
    pub const fn position(&self) -> JournalAnchor {
        self.position
    }

    /// memory—v1: Compare against an independently supplied tail boundary.
    ///
    /// Success establishes only consistency with the supplied values; it cannot
    /// authenticate the boundary, attest durability, or prove complete recovery.
    pub fn finish(&self, expected_tail: JournalTail) -> Result<(), JournalError> {
        if self.records == 0 {
            return Err(JournalError::EmptyRange);
        }
        if self.position != expected_tail {
            return Err(JournalError::ChainMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            operation_id: "op",
            request_fingerprint: [4; 32],
            kind,
            mutation_sequence,
            prev_hash,
            payload,
        }
    }

    // Rehash mutations of the wire representation to test structural checks
    // independently of the checksum rejection path.
    // memory—v1
    fn rehash(bytes: &mut [u8]) {
        let end = bytes.len() - FRAME_DIGEST_BYTES;
        let digest = frame_hash(&bytes[..end]);
        bytes[end..].copy_from_slice(&digest);
    }

    #[test]
    // memory—v1
    fn fixed_wire_vector_and_domain_separated_hash() {
        // Digest independently computed using OpenSSL over the documented domain
        // and the following fixed header/body, not by encode_record.
        let expected = hex::decode(concat!(
            "414c4d314a4e4c0000010100000000b9",
            "01010101010101010101010101010101",
            "02020202020202020202020202020202",
            "0000000000000001",
            "03030303030303030303030303030303",
            "0000000000000001",
            "0404040404040404040404040404040404040404040404040404040404040404",
            "0505050505050505050505050505050505050505050505050505050505050505",
            "0002000000016f70aa",
            "1ae34cd871656ba3607923b4c2f3585f4c48c148cbb9e4f59ab5b2300c5a88a9"
        ))
        .unwrap();
        let input = record(RecordKind::Mutation, 1, 1, [5; 32], &[0xaa]);
        assert_eq!(encode_record(&input).unwrap(), expected);
        let decoded = decode_record(&expected).unwrap();
        assert_eq!(decoded.record, input);
        assert_eq!(
            frame_length(&expected[..FRAME_PREFIX_BYTES]),
            Ok(expected.len())
        );
    }

    #[test]
    // memory—v1
    fn mixed_mutations_and_denials_allow_older_observed_state() {
        let mut verifier = JournalVerifier::new(anchor(), 8, 4096).unwrap();
        let mut prev = [5; 32];
        for (seq, kind, mutation_seq) in [
            (1, RecordKind::Mutation, 1),
            (2, RecordKind::Mutation, 2),
            (3, RecordKind::Deny, 1),
            (4, RecordKind::Deny, 0),
            (5, RecordKind::Mutation, 3),
            (6, RecordKind::Deny, 3),
        ] {
            let mut next = record(kind, seq, mutation_seq, prev, b"payload");
            // Epoch changes are represented but have no trust/lifecycle meaning here.
            next.epoch_id = id(if seq < 4 { 2 } else { 9 });
            let wire = encode_record(&next).unwrap();
            prev = verifier.advance(&wire).unwrap().digest;
        }
        let expected = JournalTail::new(id(1), 6, 3, prev).unwrap();
        assert_eq!(verifier.finish(expected), Ok(()));
        assert_eq!(verifier.position(), expected);
    }

    #[test]
    // memory—v1
    fn rejects_all_truncations_and_trailing_bytes() {
        let wire = encode_record(&record(
            RecordKind::Mutation,
            1,
            1,
            [5; 32],
            b"test payload",
        ))
        .unwrap();
        for length in 0..wire.len() {
            assert!(
                decode_record(&wire[..length]).is_err(),
                "accepted truncation at {length}"
            );
        }
        let mut extra = wire.clone();
        extra.push(0);
        assert_eq!(decode_record(&extra), Err(JournalError::InvalidLength));
    }

    #[test]
    // memory—v1
    fn rejects_corruption_and_noncanonical_fields() {
        let wire = encode_record(&record(RecordKind::Mutation, 1, 1, [5; 32], b"body")).unwrap();
        // Test every byte's checksum coverage and fail-closed prefix parsing.
        for index in 0..wire.len() {
            let mut corrupt = wire.clone();
            corrupt[index] ^= 1;
            assert!(
                decode_record(&corrupt).is_err(),
                "accepted altered byte {index}"
            );
        }
        for (index, value) in [(0, 0), (9, 2), (10, 0), (10, 3), (11, 1)] {
            let mut corrupt = wire.clone();
            corrupt[index] = value;
            rehash(&mut corrupt);
            assert_eq!(decode_record(&corrupt), Err(JournalError::InvalidEncoding));
        }
        for (start, end) in [
            (16, 32),
            (32, 48),
            (48, 56),
            (56, 72),
            (72, 80),
            (80, 112),
            (112, 144),
        ] {
            let mut corrupt = wire.clone();
            corrupt[start..end].fill(0);
            rehash(&mut corrupt);
            assert_eq!(decode_record(&corrupt), Err(JournalError::InvalidField));
        }
        for invalid in [b' ', b'\n', 0xff] {
            let mut corrupt = wire.clone();
            corrupt[FRAME_HEADER_BYTES] = invalid;
            rehash(&mut corrupt);
            assert_eq!(decode_record(&corrupt), Err(JournalError::InvalidField));
        }
    }

    #[test]
    // memory—v1
    fn rejects_wrong_lengths_and_enforces_allocation_limits() {
        let wire = encode_record(&record(RecordKind::Deny, 1, 0, [5; 32], b"p")).unwrap();
        for (start, value) in [(12, u32::MAX), (146, u32::MAX), (146, 0), (146, 2)] {
            let mut corrupt = wire.clone();
            corrupt[start..start + 4].copy_from_slice(&value.to_be_bytes());
            rehash(&mut corrupt);
            assert!(decode_record(&corrupt).is_err());
        }
        for value in [0u16, 1, 65, u16::MAX] {
            let mut corrupt = wire.clone();
            corrupt[144..146].copy_from_slice(&value.to_be_bytes());
            rehash(&mut corrupt);
            assert!(decode_record(&corrupt).is_err());
        }
        let maximum = vec![7; MAX_PAYLOAD_BYTES];
        let frame = encode_record(&record(RecordKind::Deny, 1, 0, [5; 32], &maximum)).unwrap();
        assert_eq!(
            decode_record(&frame).unwrap().record.payload.len(),
            MAX_PAYLOAD_BYTES
        );
        let oversized = vec![7; MAX_PAYLOAD_BYTES + 1];
        assert_eq!(
            encode_record(&record(RecordKind::Deny, 1, 0, [5; 32], &oversized)),
            Err(JournalError::LimitExceeded)
        );
        assert_eq!(
            encode_record(&record(RecordKind::Deny, 1, 0, [5; 32], &[])),
            Err(JournalError::InvalidField)
        );
        let mut huge = wire.clone();
        huge[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(frame_length(&huge), Err(JournalError::LimitExceeded));
    }

    #[test]
    // memory—v1
    fn rejects_cross_stream_wrong_hash_repeats_gaps_and_future_deny() {
        let first = encode_record(&record(RecordKind::Mutation, 1, 1, [5; 32], b"p")).unwrap();
        let mut verifier = JournalVerifier::new(anchor(), 10, 4096).unwrap();
        let hash = verifier.advance(&first).unwrap().digest;
        let before = verifier.position();
        let mut candidate = record(RecordKind::Mutation, 2, 2, hash, b"p");
        candidate.stream_id = id(8);
        assert_eq!(
            verifier.advance(&encode_record(&candidate).unwrap()),
            Err(JournalError::ChainMismatch)
        );
        candidate.stream_id = id(1);
        candidate.prev_hash = [8; 32];
        assert_eq!(
            verifier.advance(&encode_record(&candidate).unwrap()),
            Err(JournalError::ChainMismatch)
        );
        candidate.prev_hash = hash;
        for seq in [1, 3] {
            candidate.journal_sequence = seq;
            assert_eq!(
                verifier.advance(&encode_record(&candidate).unwrap()),
                Err(JournalError::ChainMismatch)
            );
        }
        candidate.journal_sequence = 2;
        for seq in [1, 3] {
            candidate.mutation_sequence = seq;
            assert_eq!(
                verifier.advance(&encode_record(&candidate).unwrap()),
                Err(JournalError::ChainMismatch)
            );
        }
        candidate.kind = RecordKind::Deny;
        candidate.mutation_sequence = 2;
        assert_eq!(
            verifier.advance(&encode_record(&candidate).unwrap()),
            Err(JournalError::ChainMismatch)
        );
        assert_eq!(verifier.position(), before);
        assert_eq!(verifier.advance(&first), Err(JournalError::ChainMismatch));
    }

    #[test]
    // memory—v1: Invalid input consumes both finite budgets without moving the verified tail.
    fn rejected_frames_consume_attempt_and_byte_budgets() {
        let valid = encode_record(&record(RecordKind::Mutation, 1, 1, [5; 32], b"p")).unwrap();
        let wrong_chain =
            encode_record(&record(RecordKind::Mutation, 1, 1, [6; 32], b"p")).unwrap();
        let bytes = (valid.len() * 2) as u64;

        let mut by_attempt = JournalVerifier::new(anchor(), 2, bytes + valid.len() as u64).unwrap();
        for _ in 0..2 {
            assert_eq!(
                by_attempt.advance(&wrong_chain),
                Err(JournalError::ChainMismatch)
            );
            assert_eq!(by_attempt.position(), anchor());
        }
        assert_eq!(by_attempt.advance(&valid), Err(JournalError::LimitExceeded));
        assert_eq!(by_attempt.finish(anchor()), Err(JournalError::EmptyRange));

        let mut by_bytes = JournalVerifier::new(anchor(), 3, bytes).unwrap();
        assert_eq!(
            by_bytes.advance(&wrong_chain),
            Err(JournalError::ChainMismatch)
        );
        assert_eq!(
            by_bytes.advance(&wrong_chain),
            Err(JournalError::ChainMismatch)
        );
        assert_eq!(by_bytes.advance(&valid), Err(JournalError::LimitExceeded));
        assert_eq!(by_bytes.position(), anchor());

        let mut remaining = JournalVerifier::new(anchor(), 2, bytes).unwrap();
        assert_eq!(
            remaining.advance(&wrong_chain),
            Err(JournalError::ChainMismatch)
        );
        assert!(remaining.advance(&valid).is_ok());
        assert_eq!(remaining.advance(&valid), Err(JournalError::LimitExceeded));
    }

    #[test]
    // memory—v1
    fn rejects_sequence_wrap_and_bad_external_bounds() {
        assert_eq!(
            JournalAnchor::new(id(0), 0, 0, [1; 32]),
            Err(JournalError::InvalidField)
        );
        assert_eq!(
            JournalAnchor::new(id(1), 0, 0, [0; 32]),
            Err(JournalError::InvalidField)
        );
        for (records, bytes) in [
            (0, 1),
            (1, 0),
            (MAX_VERIFY_RECORDS + 1, 1),
            (1, MAX_VERIFY_BYTES + 1),
        ] {
            assert!(matches!(
                JournalVerifier::new(anchor(), records, bytes),
                Err(JournalError::LimitExceeded)
            ));
        }
        let mut verifier = JournalVerifier::new(anchor(), 1, 1000).unwrap();
        assert_eq!(verifier.finish(anchor()), Err(JournalError::EmptyRange));
        let wire = encode_record(&record(RecordKind::Mutation, 1, 1, [5; 32], b"p")).unwrap();
        verifier.advance(&wire).unwrap();
        assert_eq!(verifier.finish(anchor()), Err(JournalError::ChainMismatch));
        assert_eq!(verifier.advance(&wire), Err(JournalError::LimitExceeded));
        let mut small = JournalVerifier::new(anchor(), 1, wire.len() as u64 - 1).unwrap();
        assert_eq!(small.advance(&wire), Err(JournalError::LimitExceeded));
        let wrapped = JournalAnchor::new(id(1), u64::MAX, 0, [5; 32]).unwrap();
        assert_eq!(
            JournalVerifier::new(wrapped, 1, 1000)
                .unwrap()
                .advance(&wire),
            Err(JournalError::SequenceOverflow)
        );
        let wrapped = JournalAnchor::new(id(1), 0, u64::MAX, [5; 32]).unwrap();
        assert_eq!(
            JournalVerifier::new(wrapped, 1, 1000)
                .unwrap()
                .advance(&wire),
            Err(JournalError::SequenceOverflow)
        );
        let wrong_anchor = JournalAnchor::new(id(1), 0, 0, [6; 32]).unwrap();
        assert_eq!(
            JournalVerifier::new(wrong_anchor, 1, 1000)
                .unwrap()
                .advance(&wire),
            Err(JournalError::ChainMismatch)
        );
    }

    #[test]
    // memory—v1
    fn redacts_debug_and_errors() {
        let input = record(RecordKind::Deny, 1, 0, [5; 32], b"sensitive_payload");
        let wire = encode_record(&input).unwrap();
        let decoded = decode_record(&wire).unwrap();
        for display in [
            format!("{input:?}"),
            format!("{decoded:?}"),
            format!("{:?}", anchor()),
            format!("{:?}", JournalVerifier::new(anchor(), 1, 1000).unwrap()),
        ] {
            assert!(!display.contains("sensitive_payload"));
            assert!(!display.contains("op"));
        }
        assert!(!JournalError::InvalidField
            .to_string()
            .contains("sensitive_payload"));
    }
}
