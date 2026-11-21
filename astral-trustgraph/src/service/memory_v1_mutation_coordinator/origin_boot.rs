//! memory—v1: Producer incarnation carried by the inner journal envelope.

use std::sync::OnceLock;

use astral_types::memory_v1::MemoryId;

use super::CoordinatorError;

pub(super) const ORIGIN_VERSION: u16 = 2;
pub(super) const ORIGIN_BYTES: usize = 16;

/// memory—v1: Identify the writing process across all of its governance and DENY frames.
/// Recovery obtains the original identity exclusively from the retained bytes.
pub fn journal_producer_boot_id() -> MemoryId {
    static BOOT: OnceLock<MemoryId> = OnceLock::new();
    *BOOT.get_or_init(|| MemoryId::from_bytes(uuid::Uuid::new_v4().into_bytes()))
}

/// memory—v1: Version 1 is readable for inspection but carries no producer identity.
pub(super) fn decode_origin_boot(
    version: u16,
    bytes: &[u8],
    offset: &mut usize,
) -> Result<Option<MemoryId>, CoordinatorError> {
    match version {
        1 => Ok(None),
        ORIGIN_VERSION => {
            let end = offset
                .checked_add(ORIGIN_BYTES)
                .ok_or(CoordinatorError::InvalidJournalPayload)?;
            let raw: [u8; ORIGIN_BYTES] = bytes
                .get(*offset..end)
                .and_then(|field| field.try_into().ok())
                .filter(|field| *field != [0; ORIGIN_BYTES])
                .ok_or(CoordinatorError::InvalidJournalPayload)?;
            *offset = end;
            Ok(Some(MemoryId::from_bytes(raw)))
        }
        _ => Err(CoordinatorError::InvalidJournalPayload),
    }
}
