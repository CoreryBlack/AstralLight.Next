//! memory—v1: bounded, reversible management-mutation payload wire format.
//!
//! This module encodes [`ManagementMutationV2`] for a future journal or MySQL
//! recovery reader. It is a value transport only. Encoding or decoding does not
//! prove authorization, source, provenance, time, audit state, persistence, or
//! that the value may be applied to a serving root.
//!
//! The frame is independent from `memory_v1_mutation_digest`: the digest is a
//! one-way value identifier with different resource ceilings and cannot recover
//! a mutation. The wire format has a fixed domain, a fixed big-endian version,
//! closed variant and enum tags, fixed-width identifiers and integers, and
//! big-endian `u32` length/count prefixes. `Option` values use exactly `0` for
//! `None` and `1` followed by the value for `Some`.
//!
//! The complete encoded frame is limited to the current 1 MiB message payload
//! budget. This deliberately means that a mutation accepted by the underlying
//! candidate/digest limits may still be rejected here. No truncation is ever
//! performed; the envelope and future journal/application budgets must be
//! coordinated before larger governance mutations are supported.

use std::convert::TryInto;

use thiserror::Error;

use crate::memory_v1_db_rows::{
    BinaryId, BindingConfirmationRow, BindingLayer, BindingRow, RuleSetChangeConfirmationRow,
    RuleSetRow, RuleSetStatus, RuleSetVersionRow, UserCardRow, UserCardStatus,
};
use crate::memory_v1_root::ManagementMutationV2;
use crate::memory_v1_rules::{MemoryV1OwnerScope, MemoryV1TenantScope};

/// Fixed domain prefix for the reversible mutation frame.
///
/// The terminating zero is part of the domain and is checked byte-for-byte.
pub const WIRE_DOMAIN: &[u8] = b"astrallight/memory-v1/management-mutation-wire\0";

/// Current wire-format version, encoded as a big-endian `u16` after the domain.
pub const WIRE_VERSION: u16 = 1;

/// Maximum complete encoded frame, matching the current message payload budget.
pub const MAX_WIRE_BYTES: usize = 1024 * 1024;

/// Maximum individual variable byte field inherited from the candidate value
/// limits. The complete wire frame limit is stricter for this payload format.
pub const MAX_FIELD_BYTES: usize = 2 * 1024 * 1024;

/// Maximum number of rows in a confirmation batch.
pub const MAX_BATCH_ROWS: usize = 128;

const TAG_BINDING_CREATE: u8 = 1;
const TAG_BINDING_REMOVE: u8 = 2;
const TAG_CONFIRMATION_CREATE: u8 = 3;
const TAG_CONFIRMATION_REVOKE: u8 = 4;
const TAG_CONFIRMATION_BATCH: u8 = 5;
const TAG_USER_CARD_STATUS: u8 = 6;
const TAG_RULE_SET_CREATE: u8 = 7;
const TAG_VERSION_PUBLISH: u8 = 8;
const TAG_RULE_SET_CHANGE_CONFIRMATION_REVOKE: u8 = 9;
const TAG_RULE_SET_RETIRE: u8 = 10;
const TAG_USER_CARD_CREATE: u8 = 11;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Closed enum-tag fields used in [`MutationWireError`].
pub enum MutationWireTag {
    BindingLayer,
    UserCardStatus,
    RuleSetStatus,
    OwnerScope,
    TenantScope,
}

/// Errors returned by the bounded mutation wire encoder and decoder.
///
/// Error variants carry only lengths, limits, versions, tags, and static field
/// names. They never retain or format the input payload or decoded field bytes.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum MutationWireError {
    #[error("encoded mutation payload exceeds {limit} bytes: {actual}")]
    PayloadTooLarge { actual: usize, limit: usize },
    #[error("input mutation payload exceeds {limit} bytes: {actual}")]
    InputTooLarge { actual: usize, limit: usize },
    #[error("mutation field exceeds {limit} bytes: {actual}")]
    FieldTooLarge { actual: usize, limit: usize },
    #[error("confirmation batch exceeds {limit} rows: {actual}")]
    BatchTooLarge { actual: usize, limit: usize },
    #[error("mutation length cannot be represented safely")]
    LengthOverflow,
    #[error("mutation allocation could not be reserved")]
    AllocationFailed,
    #[error("mutation payload is truncated")]
    Truncated,
    #[error("mutation wire domain is invalid")]
    InvalidDomain,
    #[error("unsupported mutation wire version {actual}; expected {expected}")]
    UnsupportedVersion { actual: u16, expected: u16 },
    #[error("unknown management mutation tag {tag}")]
    UnknownMutationTag { tag: u8 },
    #[error("invalid option tag {tag}")]
    InvalidOptionTag { tag: u8 },
    #[error("invalid {field:?} tag {tag}")]
    InvalidTag { field: MutationWireTag, tag: u8 },
    #[error("mutation payload has {remaining} trailing bytes")]
    TrailingBytes { remaining: usize },
}

struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    // memory—v1
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    // memory—v1: Add bytes only after checking the complete frame budget and
    // reserving without allowing an allocation panic.
    fn raw(&mut self, bytes: &[u8]) -> Result<(), MutationWireError> {
        let actual = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(MutationWireError::LengthOverflow)?;
        if actual > MAX_WIRE_BYTES {
            return Err(MutationWireError::PayloadTooLarge {
                actual,
                limit: MAX_WIRE_BYTES,
            });
        }
        self.bytes
            .try_reserve_exact(bytes.len())
            .map_err(|_| MutationWireError::AllocationFailed)?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    // memory—v1
    fn byte(&mut self, value: u8) -> Result<(), MutationWireError> {
        self.raw(&[value])
    }

    // memory—v1
    fn u16(&mut self, value: u16) -> Result<(), MutationWireError> {
        self.raw(&value.to_be_bytes())
    }

    // memory—v1
    fn u32(&mut self, value: usize) -> Result<(), MutationWireError> {
        let value = u32::try_from(value).map_err(|_| MutationWireError::LengthOverflow)?;
        self.raw(&value.to_be_bytes())
    }

    // memory—v1
    fn i64(&mut self, value: i64) -> Result<(), MutationWireError> {
        self.raw(&value.to_be_bytes())
    }

    // memory—v1
    fn id(&mut self, value: &BinaryId) -> Result<(), MutationWireError> {
        self.raw(value)
    }

    // memory—v1: Frame a variable field only after applying the independent
    // field ceiling. The frame ceiling is checked by `raw` before every write.
    fn field(&mut self, value: &[u8]) -> Result<(), MutationWireError> {
        if value.len() > MAX_FIELD_BYTES {
            return Err(MutationWireError::FieldTooLarge {
                actual: value.len(),
                limit: MAX_FIELD_BYTES,
            });
        }
        self.u32(value.len())?;
        self.raw(value)
    }

    // memory—v1
    fn optional_time(&mut self, value: Option<i64>) -> Result<(), MutationWireError> {
        match value {
            None => self.byte(0),
            Some(value) => {
                self.byte(1)?;
                self.i64(value)
            }
        }
    }

    // memory—v1
    fn optional_id(&mut self, value: Option<BinaryId>) -> Result<(), MutationWireError> {
        match value {
            None => self.byte(0),
            Some(value) => {
                self.byte(1)?;
                self.id(&value)
            }
        }
    }

    // memory—v1
    fn binding(&mut self, row: &BindingRow) -> Result<(), MutationWireError> {
        // memory—v1: Exhaustive destructuring makes every future row field a
        // compile-time encoding decision.
        let BindingRow {
            binding_id,
            user_card_id,
            rule_set_id,
            binding_layer,
            valid_from,
            valid_until,
            owner_scope,
            tenant_scope,
            removed_at,
            removed_by,
        } = row;
        self.id(binding_id)?;
        self.id(user_card_id)?;
        self.id(rule_set_id)?;
        self.byte(match binding_layer {
            BindingLayer::Base => 1,
            BindingLayer::Overlay => 2,
        })?;
        self.optional_time(*valid_from)?;
        self.optional_time(*valid_until)?;
        self.byte(match owner_scope {
            MemoryV1OwnerScope::SelfUser => 1,
            MemoryV1OwnerScope::AllUsers => 2,
        })?;
        self.byte(match tenant_scope {
            MemoryV1TenantScope::SelfTenant => 1,
            MemoryV1TenantScope::SelfAndDescendants => 2,
        })?;
        self.optional_time(*removed_at)?;
        self.optional_id(*removed_by)
    }

    // memory—v1
    fn confirmation(&mut self, row: &BindingConfirmationRow) -> Result<(), MutationWireError> {
        let BindingConfirmationRow {
            confirmation_id,
            binding_id,
            rule_set_id,
            version_bytes,
            confirmer_user_id,
            scope_bytes,
            operation_id,
            confirmed_at_bytes,
            revoked_at,
            revoked_by,
        } = row;
        self.id(confirmation_id)?;
        self.id(binding_id)?;
        self.id(rule_set_id)?;
        self.field(version_bytes)?;
        self.id(confirmer_user_id)?;
        self.field(scope_bytes)?;
        self.field(operation_id)?;
        self.field(confirmed_at_bytes)?;
        self.optional_time(*revoked_at)?;
        self.optional_id(*revoked_by)
    }

    // memory—v1
    fn change_confirmation(
        &mut self,
        row: &RuleSetChangeConfirmationRow,
    ) -> Result<(), MutationWireError> {
        let RuleSetChangeConfirmationRow {
            confirmation_id,
            rule_set_id,
            version_bytes,
            confirmer_user_id,
            affected_scope_bytes,
            operation_id,
            confirmed_at_bytes,
            revoked_at,
            revoked_by,
        } = row;
        self.id(confirmation_id)?;
        self.id(rule_set_id)?;
        self.field(version_bytes)?;
        self.id(confirmer_user_id)?;
        self.field(affected_scope_bytes)?;
        self.field(operation_id)?;
        self.field(confirmed_at_bytes)?;
        self.optional_time(*revoked_at)?;
        self.optional_id(*revoked_by)
    }

    // memory—v1
    fn rule_set(&mut self, row: &RuleSetRow) -> Result<(), MutationWireError> {
        let RuleSetRow {
            rule_set_id,
            owner_tenant_id,
            current_version_bytes,
            status,
        } = row;
        self.id(rule_set_id)?;
        self.id(owner_tenant_id)?;
        self.field(current_version_bytes)?;
        self.byte(match status {
            RuleSetStatus::Active => 1,
            RuleSetStatus::Retired => 2,
        })
    }

    // memory—v1
    fn version(&mut self, row: &RuleSetVersionRow) -> Result<(), MutationWireError> {
        let RuleSetVersionRow {
            rule_set_id,
            version_bytes,
            content_bytes,
            timestamp_bytes,
            hash_input_bytes,
            hash_bytes,
        } = row;
        self.id(rule_set_id)?;
        self.field(version_bytes)?;
        self.field(content_bytes)?;
        self.field(timestamp_bytes)?;
        self.field(hash_input_bytes)?;
        self.field(hash_bytes)
    }

    // memory—v1
    fn user_card(&mut self, row: &UserCardRow) -> Result<(), MutationWireError> {
        let UserCardRow {
            user_card_id,
            user_id,
            tenant_id,
            status,
        } = row;
        self.id(user_card_id)?;
        self.id(user_id)?;
        self.id(tenant_id)?;
        self.byte(match status {
            UserCardStatus::Active => 1,
            UserCardStatus::Disabled => 2,
        })
    }

    // memory—v1
    fn finish(self) -> Result<Vec<u8>, MutationWireError> {
        if self.bytes.len() > MAX_WIRE_BYTES {
            return Err(MutationWireError::PayloadTooLarge {
                actual: self.bytes.len(),
                limit: MAX_WIRE_BYTES,
            });
        }
        Ok(self.bytes)
    }
}

/// Encode one complete management mutation into a bounded reversible frame.
///
/// The match is exhaustive over the current mutation enum. A new mutation
/// variant must choose a tag and field order before this module can compile.
/// `Err` means the value cannot be represented within the current wire budget;
/// no prefix or truncated payload is returned.
/// memory—v1: Encode one complete management mutation within the bounded
/// reversible frame contract.
pub fn encode_mutation(mutation: &ManagementMutationV2) -> Result<Vec<u8>, MutationWireError> {
    let mut encoder = Encoder::new();
    encoder.raw(WIRE_DOMAIN)?;
    encoder.u16(WIRE_VERSION)?;
    match mutation {
        ManagementMutationV2::BindingCreate { row, confirmation } => {
            encoder.byte(TAG_BINDING_CREATE)?;
            encoder.binding(row)?;
            encoder.confirmation(confirmation)?;
        }
        ManagementMutationV2::BindingRemove {
            binding_id,
            removed_at,
            removed_by,
        } => {
            encoder.byte(TAG_BINDING_REMOVE)?;
            encoder.id(binding_id)?;
            encoder.i64(*removed_at)?;
            encoder.id(removed_by)?;
        }
        ManagementMutationV2::ConfirmationCreate { row } => {
            encoder.byte(TAG_CONFIRMATION_CREATE)?;
            encoder.confirmation(row)?;
        }
        ManagementMutationV2::ConfirmationRevoke {
            confirmation_id,
            revoked_at,
            revoked_by,
        } => {
            encoder.byte(TAG_CONFIRMATION_REVOKE)?;
            encoder.id(confirmation_id)?;
            encoder.i64(*revoked_at)?;
            encoder.id(revoked_by)?;
        }
        ManagementMutationV2::RuleSetChangeConfirmationRevoke {
            confirmation_id,
            revoked_at,
            revoked_by,
        } => {
            encoder.byte(TAG_RULE_SET_CHANGE_CONFIRMATION_REVOKE)?;
            encoder.id(confirmation_id)?;
            encoder.i64(*revoked_at)?;
            encoder.id(revoked_by)?;
        }
        ManagementMutationV2::ConfirmationBatch { rows } => {
            encoder.byte(TAG_CONFIRMATION_BATCH)?;
            if rows.len() > MAX_BATCH_ROWS {
                return Err(MutationWireError::BatchTooLarge {
                    actual: rows.len(),
                    limit: MAX_BATCH_ROWS,
                });
            }
            encoder.u32(rows.len())?;
            for row in rows {
                encoder.confirmation(row)?;
            }
        }
        ManagementMutationV2::UserCardCreate { row } => {
            encoder.byte(TAG_USER_CARD_CREATE)?;
            encoder.user_card(row)?;
        }
        ManagementMutationV2::UserCardStatus {
            user_card_id,
            status,
        } => {
            encoder.byte(TAG_USER_CARD_STATUS)?;
            encoder.id(user_card_id)?;
            encoder.byte(match status {
                UserCardStatus::Active => 1,
                UserCardStatus::Disabled => 2,
            })?;
        }
        ManagementMutationV2::RuleSetCreate {
            rule_set,
            version,
            change_confirmation,
        } => {
            encoder.byte(TAG_RULE_SET_CREATE)?;
            encoder.rule_set(rule_set)?;
            encoder.version(version)?;
            encoder.change_confirmation(change_confirmation)?;
        }
        ManagementMutationV2::RuleSetRetire { rule_set_id } => {
            encoder.byte(TAG_RULE_SET_RETIRE)?;
            encoder.id(rule_set_id)?;
        }
        ManagementMutationV2::VersionPublish {
            rule_set_id,
            version_row,
            new_current_version,
            change_confirmation,
        } => {
            encoder.byte(TAG_VERSION_PUBLISH)?;
            encoder.id(rule_set_id)?;
            encoder.version(version_row)?;
            encoder.field(new_current_version)?;
            encoder.change_confirmation(change_confirmation)?;
        }
    }
    encoder.finish()
}

/// Short alias for [`encode_mutation`].
///
/// memory—v1: Preserve the bounded reversible encoding contract through the
/// short public entry point.
pub fn encode(mutation: &ManagementMutationV2) -> Result<Vec<u8>, MutationWireError> {
    encode_mutation(mutation)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    // memory—v1: Reject an oversized complete input before any allocation or
    // content-dependent parsing.
    fn new(bytes: &'a [u8]) -> Result<Self, MutationWireError> {
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(MutationWireError::InputTooLarge {
                actual: bytes.len(),
                limit: MAX_WIRE_BYTES,
            });
        }
        Ok(Self { bytes, position: 0 })
    }

    // memory—v1
    fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    // memory—v1
    fn take(&mut self, length: usize) -> Result<&'a [u8], MutationWireError> {
        if length > self.remaining() {
            return Err(MutationWireError::Truncated);
        }
        let start = self.position;
        self.position += length;
        Ok(&self.bytes[start..self.position])
    }

    // memory—v1
    fn byte(&mut self) -> Result<u8, MutationWireError> {
        Ok(self.take(1)?[0])
    }

    // memory—v1
    fn u16(&mut self) -> Result<u16, MutationWireError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("two bytes were taken"),
        ))
    }

    // memory—v1
    fn u32(&mut self) -> Result<usize, MutationWireError> {
        let value = u32::from_be_bytes(self.take(4)?.try_into().expect("four bytes were taken"));
        usize::try_from(value).map_err(|_| MutationWireError::LengthOverflow)
    }

    // memory—v1
    fn i64(&mut self) -> Result<i64, MutationWireError> {
        Ok(i64::from_be_bytes(
            self.take(8)?.try_into().expect("eight bytes were taken"),
        ))
    }

    // memory—v1
    fn id(&mut self) -> Result<BinaryId, MutationWireError> {
        let bytes = self.take(16)?;
        let mut value = [0_u8; 16];
        value.copy_from_slice(bytes);
        Ok(value)
    }

    // memory—v1: Check both the independent field limit and remaining frame
    // bytes before reserving or copying any variable field.
    fn field(&mut self) -> Result<Vec<u8>, MutationWireError> {
        let length = self.u32()?;
        if length > MAX_FIELD_BYTES {
            return Err(MutationWireError::FieldTooLarge {
                actual: length,
                limit: MAX_FIELD_BYTES,
            });
        }
        let bytes = self.take(length)?;
        let mut value = Vec::new();
        value
            .try_reserve_exact(length)
            .map_err(|_| MutationWireError::AllocationFailed)?;
        value.extend_from_slice(bytes);
        Ok(value)
    }

    // memory—v1
    fn optional_time(&mut self) -> Result<Option<i64>, MutationWireError> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(self.i64()?)),
            tag => Err(MutationWireError::InvalidOptionTag { tag }),
        }
    }

    // memory—v1
    fn optional_id(&mut self) -> Result<Option<BinaryId>, MutationWireError> {
        match self.byte()? {
            0 => Ok(None),
            1 => Ok(Some(self.id()?)),
            tag => Err(MutationWireError::InvalidOptionTag { tag }),
        }
    }

    // memory—v1
    fn binding(&mut self) -> Result<BindingRow, MutationWireError> {
        Ok(BindingRow {
            binding_id: self.id()?,
            user_card_id: self.id()?,
            rule_set_id: self.id()?,
            binding_layer: match self.byte()? {
                1 => BindingLayer::Base,
                2 => BindingLayer::Overlay,
                tag => {
                    return Err(MutationWireError::InvalidTag {
                        field: MutationWireTag::BindingLayer,
                        tag,
                    })
                }
            },
            valid_from: self.optional_time()?,
            valid_until: self.optional_time()?,
            owner_scope: match self.byte()? {
                1 => MemoryV1OwnerScope::SelfUser,
                2 => MemoryV1OwnerScope::AllUsers,
                tag => {
                    return Err(MutationWireError::InvalidTag {
                        field: MutationWireTag::OwnerScope,
                        tag,
                    })
                }
            },
            tenant_scope: match self.byte()? {
                1 => MemoryV1TenantScope::SelfTenant,
                2 => MemoryV1TenantScope::SelfAndDescendants,
                tag => {
                    return Err(MutationWireError::InvalidTag {
                        field: MutationWireTag::TenantScope,
                        tag,
                    })
                }
            },
            removed_at: self.optional_time()?,
            removed_by: self.optional_id()?,
        })
    }

    // memory—v1
    fn confirmation(&mut self) -> Result<BindingConfirmationRow, MutationWireError> {
        Ok(BindingConfirmationRow {
            confirmation_id: self.id()?,
            binding_id: self.id()?,
            rule_set_id: self.id()?,
            version_bytes: self.field()?,
            confirmer_user_id: self.id()?,
            scope_bytes: self.field()?,
            operation_id: self.field()?,
            confirmed_at_bytes: self.field()?,
            revoked_at: self.optional_time()?,
            revoked_by: self.optional_id()?,
        })
    }

    // memory—v1
    fn change_confirmation(&mut self) -> Result<RuleSetChangeConfirmationRow, MutationWireError> {
        Ok(RuleSetChangeConfirmationRow {
            confirmation_id: self.id()?,
            rule_set_id: self.id()?,
            version_bytes: self.field()?,
            confirmer_user_id: self.id()?,
            affected_scope_bytes: self.field()?,
            operation_id: self.field()?,
            confirmed_at_bytes: self.field()?,
            revoked_at: self.optional_time()?,
            revoked_by: self.optional_id()?,
        })
    }

    // memory—v1
    fn rule_set(&mut self) -> Result<RuleSetRow, MutationWireError> {
        Ok(RuleSetRow {
            rule_set_id: self.id()?,
            owner_tenant_id: self.id()?,
            current_version_bytes: self.field()?,
            status: match self.byte()? {
                1 => RuleSetStatus::Active,
                2 => RuleSetStatus::Retired,
                tag => {
                    return Err(MutationWireError::InvalidTag {
                        field: MutationWireTag::RuleSetStatus,
                        tag,
                    })
                }
            },
        })
    }

    // memory—v1
    fn version(&mut self) -> Result<RuleSetVersionRow, MutationWireError> {
        Ok(RuleSetVersionRow {
            rule_set_id: self.id()?,
            version_bytes: self.field()?,
            content_bytes: self.field()?,
            timestamp_bytes: self.field()?,
            hash_input_bytes: self.field()?,
            hash_bytes: self.field()?,
        })
    }

    // memory—v1
    fn user_card(&mut self) -> Result<UserCardRow, MutationWireError> {
        Ok(UserCardRow {
            user_card_id: self.id()?,
            user_id: self.id()?,
            tenant_id: self.id()?,
            status: match self.byte()? {
                1 => UserCardStatus::Active,
                2 => UserCardStatus::Disabled,
                tag => {
                    return Err(MutationWireError::InvalidTag {
                        field: MutationWireTag::UserCardStatus,
                        tag,
                    })
                }
            },
        })
    }
}

/// Decode one complete bounded mutation frame.
///
/// The complete input is budget-checked before parsing. Every declared field
/// length is checked against both the field ceiling and the remaining input
/// before `try_reserve_exact`; unknown tags, noncanonical option tags,
/// truncation, and trailing bytes are rejected.
/// Decode one complete bounded mutation frame.
///
/// memory—v1: Keep input, field, tag, truncation, and trailing-byte checks
/// fail-closed through the public decoder entry point.
pub fn decode_mutation(bytes: &[u8]) -> Result<ManagementMutationV2, MutationWireError> {
    let mut decoder = Decoder::new(bytes)?;
    if decoder.take(WIRE_DOMAIN.len())? != WIRE_DOMAIN {
        return Err(MutationWireError::InvalidDomain);
    }
    let version = decoder.u16()?;
    if version != WIRE_VERSION {
        return Err(MutationWireError::UnsupportedVersion {
            actual: version,
            expected: WIRE_VERSION,
        });
    }
    let tag = decoder.byte()?;
    let mutation = match tag {
        TAG_BINDING_CREATE => ManagementMutationV2::BindingCreate {
            row: decoder.binding()?,
            confirmation: decoder.confirmation()?,
        },
        TAG_BINDING_REMOVE => ManagementMutationV2::BindingRemove {
            binding_id: decoder.id()?,
            removed_at: decoder.i64()?,
            removed_by: decoder.id()?,
        },
        TAG_CONFIRMATION_CREATE => ManagementMutationV2::ConfirmationCreate {
            row: decoder.confirmation()?,
        },
        TAG_CONFIRMATION_REVOKE => ManagementMutationV2::ConfirmationRevoke {
            confirmation_id: decoder.id()?,
            revoked_at: decoder.i64()?,
            revoked_by: decoder.id()?,
        },
        TAG_RULE_SET_CHANGE_CONFIRMATION_REVOKE => {
            ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                confirmation_id: decoder.id()?,
                revoked_at: decoder.i64()?,
                revoked_by: decoder.id()?,
            }
        }
        TAG_CONFIRMATION_BATCH => {
            let count = decoder.u32()?;
            if count > MAX_BATCH_ROWS {
                return Err(MutationWireError::BatchTooLarge {
                    actual: count,
                    limit: MAX_BATCH_ROWS,
                });
            }
            let mut rows = Vec::new();
            rows.try_reserve_exact(count)
                .map_err(|_| MutationWireError::AllocationFailed)?;
            for _ in 0..count {
                rows.push(decoder.confirmation()?);
            }
            ManagementMutationV2::ConfirmationBatch { rows }
        }
        TAG_USER_CARD_STATUS => ManagementMutationV2::UserCardStatus {
            user_card_id: decoder.id()?,
            status: match decoder.byte()? {
                1 => UserCardStatus::Active,
                2 => UserCardStatus::Disabled,
                tag => {
                    return Err(MutationWireError::InvalidTag {
                        field: MutationWireTag::UserCardStatus,
                        tag,
                    })
                }
            },
        },
        TAG_RULE_SET_CREATE => ManagementMutationV2::RuleSetCreate {
            rule_set: decoder.rule_set()?,
            version: decoder.version()?,
            change_confirmation: decoder.change_confirmation()?,
        },
        TAG_RULE_SET_RETIRE => ManagementMutationV2::RuleSetRetire {
            rule_set_id: decoder.id()?,
        },
        TAG_VERSION_PUBLISH => ManagementMutationV2::VersionPublish {
            rule_set_id: decoder.id()?,
            version_row: decoder.version()?,
            new_current_version: decoder.field()?,
            change_confirmation: decoder.change_confirmation()?,
        },
        TAG_USER_CARD_CREATE => ManagementMutationV2::UserCardCreate {
            row: decoder.user_card()?,
        },
        tag => return Err(MutationWireError::UnknownMutationTag { tag }),
    };
    let remaining = decoder.remaining();
    if remaining != 0 {
        return Err(MutationWireError::TrailingBytes { remaining });
    }
    Ok(mutation)
}

/// Short alias for [`decode_mutation`].
///
/// memory—v1: Preserve the bounded fail-closed decoding contract through the
/// short public entry point.
pub fn decode(bytes: &[u8]) -> Result<ManagementMutationV2, MutationWireError> {
    decode_mutation(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // memory—v1
    fn id(value: u8) -> BinaryId {
        [value; 16]
    }

    // memory—v1
    fn binding_row() -> BindingRow {
        BindingRow {
            binding_id: id(1),
            user_card_id: id(2),
            rule_set_id: id(3),
            binding_layer: BindingLayer::Base,
            valid_from: None,
            valid_until: Some(-4),
            owner_scope: MemoryV1OwnerScope::SelfUser,
            tenant_scope: MemoryV1TenantScope::SelfTenant,
            removed_at: None,
            removed_by: Some(id(5)),
        }
    }

    // memory—v1
    fn confirmation_row(seed: u8) -> BindingConfirmationRow {
        BindingConfirmationRow {
            confirmation_id: id(seed),
            binding_id: id(seed.wrapping_add(1)),
            rule_set_id: id(seed.wrapping_add(2)),
            version_bytes: vec![seed, 1],
            confirmer_user_id: id(seed.wrapping_add(3)),
            scope_bytes: vec![seed, 2],
            operation_id: vec![seed, 3],
            confirmed_at_bytes: vec![seed, 4],
            revoked_at: Some(-i64::from(seed)),
            revoked_by: Some(id(seed.wrapping_add(4))),
        }
    }

    // memory—v1
    fn change_confirmation_row(seed: u8) -> RuleSetChangeConfirmationRow {
        RuleSetChangeConfirmationRow {
            confirmation_id: id(seed),
            rule_set_id: id(seed.wrapping_add(1)),
            version_bytes: vec![seed, 5],
            confirmer_user_id: id(seed.wrapping_add(2)),
            affected_scope_bytes: vec![seed, 6],
            operation_id: vec![seed, 7],
            confirmed_at_bytes: vec![seed, 8],
            revoked_at: Some(i64::from(seed)),
            revoked_by: Some(id(seed.wrapping_add(3))),
        }
    }

    // memory—v1
    fn rule_set_row() -> RuleSetRow {
        RuleSetRow {
            rule_set_id: id(21),
            owner_tenant_id: id(22),
            current_version_bytes: vec![21, 1],
            status: RuleSetStatus::Active,
        }
    }

    // memory—v1
    fn version_row() -> RuleSetVersionRow {
        RuleSetVersionRow {
            rule_set_id: id(23),
            version_bytes: vec![23, 1],
            content_bytes: vec![23, 2],
            timestamp_bytes: vec![23, 3],
            hash_input_bytes: vec![23, 4],
            hash_bytes: vec![23, 5],
        }
    }

    // memory—v1
    fn user_card_row() -> UserCardRow {
        UserCardRow {
            user_card_id: id(31),
            user_id: id(32),
            tenant_id: id(33),
            status: UserCardStatus::Active,
        }
    }

    // memory—v1
    fn all_mutations() -> Vec<ManagementMutationV2> {
        vec![
            ManagementMutationV2::BindingCreate {
                row: binding_row(),
                confirmation: confirmation_row(40),
            },
            ManagementMutationV2::BindingRemove {
                binding_id: id(41),
                removed_at: -42,
                removed_by: id(43),
            },
            ManagementMutationV2::ConfirmationCreate {
                row: confirmation_row(44),
            },
            ManagementMutationV2::ConfirmationRevoke {
                confirmation_id: id(45),
                revoked_at: 46,
                revoked_by: id(47),
            },
            ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                confirmation_id: id(48),
                revoked_at: -49,
                revoked_by: id(50),
            },
            ManagementMutationV2::ConfirmationBatch {
                rows: vec![
                    confirmation_row(51),
                    confirmation_row(52),
                    confirmation_row(52),
                ],
            },
            ManagementMutationV2::UserCardCreate {
                row: user_card_row(),
            },
            ManagementMutationV2::UserCardStatus {
                user_card_id: id(53),
                status: UserCardStatus::Disabled,
            },
            ManagementMutationV2::RuleSetCreate {
                rule_set: rule_set_row(),
                version: version_row(),
                change_confirmation: change_confirmation_row(54),
            },
            ManagementMutationV2::RuleSetRetire {
                rule_set_id: id(55),
            },
            ManagementMutationV2::VersionPublish {
                rule_set_id: id(56),
                version_row: version_row(),
                new_current_version: vec![56, 1],
                change_confirmation: change_confirmation_row(57),
            },
        ]
    }

    // memory—v1
    fn expected_tag(mutation: &ManagementMutationV2) -> u8 {
        match mutation {
            ManagementMutationV2::BindingCreate { .. } => TAG_BINDING_CREATE,
            ManagementMutationV2::BindingRemove { .. } => TAG_BINDING_REMOVE,
            ManagementMutationV2::ConfirmationCreate { .. } => TAG_CONFIRMATION_CREATE,
            ManagementMutationV2::ConfirmationRevoke { .. } => TAG_CONFIRMATION_REVOKE,
            ManagementMutationV2::RuleSetChangeConfirmationRevoke { .. } => {
                TAG_RULE_SET_CHANGE_CONFIRMATION_REVOKE
            }
            ManagementMutationV2::ConfirmationBatch { .. } => TAG_CONFIRMATION_BATCH,
            ManagementMutationV2::UserCardCreate { .. } => TAG_USER_CARD_CREATE,
            ManagementMutationV2::UserCardStatus { .. } => TAG_USER_CARD_STATUS,
            ManagementMutationV2::RuleSetCreate { .. } => TAG_RULE_SET_CREATE,
            ManagementMutationV2::RuleSetRetire { .. } => TAG_RULE_SET_RETIRE,
            ManagementMutationV2::VersionPublish { .. } => TAG_VERSION_PUBLISH,
        }
    }

    // memory—v1
    fn assert_same(expected: &ManagementMutationV2, actual: &ManagementMutationV2) {
        match (expected, actual) {
            (
                ManagementMutationV2::BindingCreate {
                    row: expected_row,
                    confirmation: expected_confirmation,
                },
                ManagementMutationV2::BindingCreate {
                    row: actual_row,
                    confirmation: actual_confirmation,
                },
            ) => {
                assert_eq!(expected_row, actual_row);
                assert_eq!(expected_confirmation, actual_confirmation);
            }
            (
                ManagementMutationV2::BindingRemove {
                    binding_id: expected_id,
                    removed_at: expected_at,
                    removed_by: expected_by,
                },
                ManagementMutationV2::BindingRemove {
                    binding_id: actual_id,
                    removed_at: actual_at,
                    removed_by: actual_by,
                },
            ) => assert_eq!(
                (expected_id, expected_at, expected_by),
                (actual_id, actual_at, actual_by)
            ),
            (
                ManagementMutationV2::ConfirmationCreate { row: expected },
                ManagementMutationV2::ConfirmationCreate { row: actual },
            ) => assert_eq!(expected, actual),
            (
                ManagementMutationV2::ConfirmationRevoke {
                    confirmation_id: expected_id,
                    revoked_at: expected_at,
                    revoked_by: expected_by,
                },
                ManagementMutationV2::ConfirmationRevoke {
                    confirmation_id: actual_id,
                    revoked_at: actual_at,
                    revoked_by: actual_by,
                },
            ) => assert_eq!(
                (expected_id, expected_at, expected_by),
                (actual_id, actual_at, actual_by)
            ),
            (
                ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                    confirmation_id: expected_id,
                    revoked_at: expected_at,
                    revoked_by: expected_by,
                },
                ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                    confirmation_id: actual_id,
                    revoked_at: actual_at,
                    revoked_by: actual_by,
                },
            ) => assert_eq!(
                (expected_id, expected_at, expected_by),
                (actual_id, actual_at, actual_by)
            ),
            (
                ManagementMutationV2::ConfirmationBatch { rows: expected },
                ManagementMutationV2::ConfirmationBatch { rows: actual },
            ) => assert_eq!(expected, actual),
            (
                ManagementMutationV2::UserCardCreate { row: expected },
                ManagementMutationV2::UserCardCreate { row: actual },
            ) => assert_eq!(expected, actual),
            (
                ManagementMutationV2::UserCardStatus {
                    user_card_id: expected_id,
                    status: expected_status,
                },
                ManagementMutationV2::UserCardStatus {
                    user_card_id: actual_id,
                    status: actual_status,
                },
            ) => assert_eq!((expected_id, expected_status), (actual_id, actual_status)),
            (
                ManagementMutationV2::RuleSetCreate {
                    rule_set: expected_rule_set,
                    version: expected_version,
                    change_confirmation: expected_confirmation,
                },
                ManagementMutationV2::RuleSetCreate {
                    rule_set: actual_rule_set,
                    version: actual_version,
                    change_confirmation: actual_confirmation,
                },
            ) => {
                assert_eq!(expected_rule_set, actual_rule_set);
                assert_eq!(expected_version, actual_version);
                assert_eq!(expected_confirmation, actual_confirmation);
            }
            (
                ManagementMutationV2::RuleSetRetire {
                    rule_set_id: expected,
                },
                ManagementMutationV2::RuleSetRetire {
                    rule_set_id: actual,
                },
            ) => assert_eq!(expected, actual),
            (
                ManagementMutationV2::VersionPublish {
                    rule_set_id: expected_id,
                    version_row: expected_version,
                    new_current_version: expected_current,
                    change_confirmation: expected_confirmation,
                },
                ManagementMutationV2::VersionPublish {
                    rule_set_id: actual_id,
                    version_row: actual_version,
                    new_current_version: actual_current,
                    change_confirmation: actual_confirmation,
                },
            ) => {
                assert_eq!(expected_id, actual_id);
                assert_eq!(expected_version, actual_version);
                assert_eq!(expected_current, actual_current);
                assert_eq!(expected_confirmation, actual_confirmation);
            }
            _ => panic!("management mutation variant changed during decode"),
        }
    }

    macro_rules! assert_wire_changes {
        ($base:expr, $( $change:expr ),+ $(,)?) => {{
            let original = $base;
            let original_wire = encode_mutation(&original).unwrap();
            $(
                let mut changed = original.clone();
                ($change)(&mut changed);
                let changed_wire = encode_mutation(&changed).unwrap();
                assert_ne!(changed_wire, original_wire, "field change was not encoded");
                let decoded = decode_mutation(&changed_wire).unwrap();
                assert_same(&changed, &decoded);
            )+
        }};
    }

    #[test]
    // memory—v1: Every current mutation variant has a fixed tag and reversible
    // field sequence, including batch order and duplicate rows.
    fn every_variant_round_trips_with_fixed_header_and_tag() {
        for mutation in all_mutations() {
            let encoded = encode_mutation(&mutation).unwrap();
            assert!(encoded.len() <= MAX_WIRE_BYTES);
            assert!(encoded.starts_with(WIRE_DOMAIN));
            let version_start = WIRE_DOMAIN.len();
            assert_eq!(
                &encoded[version_start..version_start + 2],
                &WIRE_VERSION.to_be_bytes()
            );
            assert_eq!(encoded[version_start + 2], expected_tag(&mutation));
            let decoded = decode_mutation(&encoded).unwrap();
            assert_same(&mutation, &decoded);
            assert_eq!(encode_mutation(&decoded).unwrap(), encoded);
        }
    }

    #[test]
    // memory—v1: The frame distinguishes every field of every current variant;
    // this does not rely on a digest or on decode equality.
    fn every_variant_field_changes_wire_bytes() {
        assert_wire_changes!(
            ManagementMutationV2::BindingCreate {
                row: binding_row(),
                confirmation: confirmation_row(60),
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingCreate { row, .. } = m {
                    row.binding_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingCreate { row, .. } = m {
                    row.user_card_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingCreate { row, .. } = m {
                    row.rule_set_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingCreate { row, .. } = m {
                    row.binding_layer = BindingLayer::Overlay;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingCreate { row, .. } = m {
                    row.valid_from = Some(9);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingCreate { row, .. } = m {
                    row.valid_until = None;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingCreate { row, .. } = m {
                    row.owner_scope = MemoryV1OwnerScope::AllUsers;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingCreate { row, .. } = m {
                    row.tenant_scope = MemoryV1TenantScope::SelfAndDescendants;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingCreate { row, .. } = m {
                    row.removed_at = Some(10);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingCreate { row, .. } = m {
                    row.removed_by = None;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingCreate { confirmation, .. } = m {
                    confirmation.confirmation_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingCreate { confirmation, .. } = m {
                    confirmation.binding_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingCreate { confirmation, .. } = m {
                    confirmation.rule_set_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingCreate { confirmation, .. } = m {
                    confirmation.version_bytes.push(61);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingCreate { confirmation, .. } = m {
                    confirmation.confirmer_user_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingCreate { confirmation, .. } = m {
                    confirmation.scope_bytes.clear();
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingCreate { confirmation, .. } = m {
                    confirmation.operation_id.push(62);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingCreate { confirmation, .. } = m {
                    confirmation.confirmed_at_bytes.push(63);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingCreate { confirmation, .. } = m {
                    confirmation.revoked_at = None;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingCreate { confirmation, .. } = m {
                    confirmation.revoked_by = None;
                }
            },
        );

        assert_wire_changes!(
            ManagementMutationV2::BindingRemove {
                binding_id: id(64),
                removed_at: 65,
                removed_by: id(66),
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingRemove { binding_id, .. } = m {
                    binding_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingRemove { removed_at, .. } = m {
                    *removed_at = -*removed_at;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::BindingRemove { removed_by, .. } = m {
                    removed_by[0] ^= 1;
                }
            },
        );

        assert_wire_changes!(
            ManagementMutationV2::ConfirmationCreate {
                row: confirmation_row(67),
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::ConfirmationCreate { row } = m {
                    row.confirmation_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::ConfirmationCreate { row } = m {
                    row.binding_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::ConfirmationCreate { row } = m {
                    row.rule_set_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::ConfirmationCreate { row } = m {
                    row.version_bytes.push(1);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::ConfirmationCreate { row } = m {
                    row.confirmer_user_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::ConfirmationCreate { row } = m {
                    row.scope_bytes.push(2);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::ConfirmationCreate { row } = m {
                    row.operation_id.push(3);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::ConfirmationCreate { row } = m {
                    row.confirmed_at_bytes.push(4);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::ConfirmationCreate { row } = m {
                    row.revoked_at = None;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::ConfirmationCreate { row } = m {
                    row.revoked_by = None;
                }
            },
        );

        assert_wire_changes!(
            ManagementMutationV2::ConfirmationRevoke {
                confirmation_id: id(68),
                revoked_at: 69,
                revoked_by: id(70),
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::ConfirmationRevoke {
                    confirmation_id, ..
                } = m
                {
                    confirmation_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::ConfirmationRevoke { revoked_at, .. } = m {
                    *revoked_at = -*revoked_at;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::ConfirmationRevoke { revoked_by, .. } = m {
                    revoked_by[0] ^= 1;
                }
            },
        );

        assert_wire_changes!(
            ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                confirmation_id: id(71),
                revoked_at: -72,
                revoked_by: id(73),
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                    confirmation_id,
                    ..
                } = m
                {
                    confirmation_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                    revoked_at, ..
                } = m
                {
                    *revoked_at = -*revoked_at;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                    revoked_by, ..
                } = m
                {
                    revoked_by[0] ^= 1;
                }
            },
        );

        assert_wire_changes!(
            ManagementMutationV2::ConfirmationBatch {
                rows: vec![confirmation_row(74)],
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::ConfirmationBatch { rows } = m {
                    rows[0].version_bytes.push(1);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::ConfirmationBatch { rows } = m {
                    rows.push(confirmation_row(75));
                }
            },
        );

        assert_wire_changes!(
            ManagementMutationV2::UserCardCreate {
                row: user_card_row(),
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::UserCardCreate { row } = m {
                    row.user_card_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::UserCardCreate { row } = m {
                    row.user_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::UserCardCreate { row } = m {
                    row.tenant_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::UserCardCreate { row } = m {
                    row.status = UserCardStatus::Disabled;
                }
            },
        );

        assert_wire_changes!(
            ManagementMutationV2::UserCardStatus {
                user_card_id: id(76),
                status: UserCardStatus::Active,
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::UserCardStatus { user_card_id, .. } = m {
                    user_card_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::UserCardStatus { status, .. } = m {
                    *status = UserCardStatus::Disabled;
                }
            },
        );

        assert_wire_changes!(
            ManagementMutationV2::RuleSetCreate {
                rule_set: rule_set_row(),
                version: version_row(),
                change_confirmation: change_confirmation_row(77),
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetCreate { rule_set, .. } = m {
                    rule_set.rule_set_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetCreate { rule_set, .. } = m {
                    rule_set.owner_tenant_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetCreate { rule_set, .. } = m {
                    rule_set.current_version_bytes.push(1);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetCreate { rule_set, .. } = m {
                    rule_set.status = RuleSetStatus::Retired;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetCreate { version, .. } = m {
                    version.rule_set_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetCreate { version, .. } = m {
                    version.version_bytes.push(1);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetCreate { version, .. } = m {
                    version.content_bytes.push(2);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetCreate { version, .. } = m {
                    version.timestamp_bytes.push(3);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetCreate { version, .. } = m {
                    version.hash_input_bytes.push(4);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetCreate { version, .. } = m {
                    version.hash_bytes.push(5);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetCreate {
                    change_confirmation,
                    ..
                } = m
                {
                    change_confirmation.confirmation_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetCreate {
                    change_confirmation,
                    ..
                } = m
                {
                    change_confirmation.rule_set_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetCreate {
                    change_confirmation,
                    ..
                } = m
                {
                    change_confirmation.version_bytes.push(1);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetCreate {
                    change_confirmation,
                    ..
                } = m
                {
                    change_confirmation.confirmer_user_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetCreate {
                    change_confirmation,
                    ..
                } = m
                {
                    change_confirmation.affected_scope_bytes.push(2);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetCreate {
                    change_confirmation,
                    ..
                } = m
                {
                    change_confirmation.operation_id.push(3);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetCreate {
                    change_confirmation,
                    ..
                } = m
                {
                    change_confirmation.confirmed_at_bytes.push(4);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetCreate {
                    change_confirmation,
                    ..
                } = m
                {
                    change_confirmation.revoked_at = None;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetCreate {
                    change_confirmation,
                    ..
                } = m
                {
                    change_confirmation.revoked_by = None;
                }
            },
        );

        assert_wire_changes!(
            ManagementMutationV2::RuleSetRetire {
                rule_set_id: id(78)
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetRetire { rule_set_id } = m {
                    rule_set_id[0] ^= 1;
                }
            },
        );

        assert_wire_changes!(
            ManagementMutationV2::VersionPublish {
                rule_set_id: id(79),
                version_row: version_row(),
                new_current_version: vec![79, 1],
                change_confirmation: change_confirmation_row(80),
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::VersionPublish { rule_set_id, .. } = m {
                    rule_set_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::VersionPublish { version_row, .. } = m {
                    version_row.rule_set_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::VersionPublish { version_row, .. } = m {
                    version_row.version_bytes.push(1);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::VersionPublish { version_row, .. } = m {
                    version_row.content_bytes.push(2);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::VersionPublish { version_row, .. } = m {
                    version_row.timestamp_bytes.push(3);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::VersionPublish { version_row, .. } = m {
                    version_row.hash_input_bytes.push(4);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::VersionPublish { version_row, .. } = m {
                    version_row.hash_bytes.push(5);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::VersionPublish {
                    new_current_version,
                    ..
                } = m
                {
                    new_current_version.push(6);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::VersionPublish {
                    change_confirmation,
                    ..
                } = m
                {
                    change_confirmation.confirmation_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::VersionPublish {
                    change_confirmation,
                    ..
                } = m
                {
                    change_confirmation.rule_set_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::VersionPublish {
                    change_confirmation,
                    ..
                } = m
                {
                    change_confirmation.version_bytes.push(1);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::VersionPublish {
                    change_confirmation,
                    ..
                } = m
                {
                    change_confirmation.confirmer_user_id[0] ^= 1;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::VersionPublish {
                    change_confirmation,
                    ..
                } = m
                {
                    change_confirmation.affected_scope_bytes.push(2);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::VersionPublish {
                    change_confirmation,
                    ..
                } = m
                {
                    change_confirmation.operation_id.push(3);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::VersionPublish {
                    change_confirmation,
                    ..
                } = m
                {
                    change_confirmation.confirmed_at_bytes.push(4);
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::VersionPublish {
                    change_confirmation,
                    ..
                } = m
                {
                    change_confirmation.revoked_at = None;
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::VersionPublish {
                    change_confirmation,
                    ..
                } = m
                {
                    change_confirmation.revoked_by = None;
                }
            },
        );
    }

    #[test]
    // memory—v1: Empty fields, nullable values, batch order, and duplicate rows
    // are represented distinctly and preserved exactly.
    fn empty_values_options_order_and_duplicates_are_preserved() {
        let mut first = confirmation_row(81);
        first.version_bytes.clear();
        first.scope_bytes.clear();
        first.operation_id.clear();
        first.confirmed_at_bytes.clear();
        first.revoked_at = None;
        first.revoked_by = None;
        let mut second = first.clone();
        second.confirmation_id[0] ^= 1;
        let first_wire =
            encode_mutation(&ManagementMutationV2::ConfirmationCreate { row: first.clone() })
                .unwrap();
        let batch = ManagementMutationV2::ConfirmationBatch {
            rows: vec![first.clone(), second.clone(), first.clone()],
        };
        let decoded = decode_mutation(&encode_mutation(&batch).unwrap()).unwrap();
        assert_same(&batch, &decoded);

        // Codec framing permits an empty batch; any business-level rejection is
        // deliberately left to the mutation validator/application layer.
        let empty_batch = ManagementMutationV2::ConfirmationBatch { rows: vec![] };
        let empty_wire = encode_mutation(&empty_batch).unwrap();
        assert_same(&empty_batch, &decode_mutation(&empty_wire).unwrap());

        let reversed = ManagementMutationV2::ConfirmationBatch {
            rows: vec![first.clone(), second.clone()],
        };
        assert_ne!(
            encode_mutation(&batch).unwrap(),
            encode_mutation(&reversed).unwrap()
        );
        let nonempty_wire = encode_mutation(&ManagementMutationV2::ConfirmationCreate {
            row: confirmation_row(81),
        })
        .unwrap();
        assert_ne!(first_wire, nonempty_wire);
    }

    #[test]
    // memory—v1: The exact one-megabyte boundary is accepted and one byte over
    // it fails closed; an individual field above the candidate ceiling fails.
    fn payload_and_field_boundaries_fail_closed() {
        let mut base_row = confirmation_row(82);
        base_row.scope_bytes.clear();
        let base = ManagementMutationV2::ConfirmationCreate {
            row: base_row.clone(),
        };
        let base_len = encode_mutation(&base).unwrap().len();
        let available = MAX_WIRE_BYTES - base_len;
        assert!(available < MAX_FIELD_BYTES);
        let exact = ManagementMutationV2::ConfirmationCreate {
            row: BindingConfirmationRow {
                scope_bytes: vec![0; available],
                ..base_row.clone()
            },
        };
        let exact_wire = encode_mutation(&exact).unwrap();
        assert_eq!(exact_wire.len(), MAX_WIRE_BYTES);
        let over = ManagementMutationV2::ConfirmationCreate {
            row: BindingConfirmationRow {
                scope_bytes: vec![0; available + 1],
                ..base_row
            },
        };
        assert!(matches!(
            encode_mutation(&over),
            Err(MutationWireError::PayloadTooLarge { .. })
        ));

        let field_over = ManagementMutationV2::ConfirmationCreate {
            row: BindingConfirmationRow {
                scope_bytes: vec![0; MAX_FIELD_BYTES + 1],
                ..confirmation_row(83)
            },
        };
        assert!(matches!(
            encode_mutation(&field_over),
            Err(MutationWireError::FieldTooLarge { .. })
        ));
    }

    #[test]
    // memory—v1: Malformed frames never allocate from unbounded declared sizes.
    fn malformed_headers_lengths_and_counts_are_rejected() {
        let valid = encode_mutation(&ManagementMutationV2::BindingCreate {
            row: binding_row(),
            confirmation: confirmation_row(84),
        })
        .unwrap();
        let mut wrong_domain = valid.clone();
        wrong_domain[0] ^= 1;
        assert!(matches!(
            decode_mutation(&wrong_domain),
            Err(MutationWireError::InvalidDomain)
        ));

        let mut wrong_version = valid.clone();
        wrong_version[WIRE_DOMAIN.len()..WIRE_DOMAIN.len() + 2]
            .copy_from_slice(&2_u16.to_be_bytes());
        assert!(matches!(
            decode_mutation(&wrong_version),
            Err(MutationWireError::UnsupportedVersion { .. })
        ));

        let mut wrong_variant = valid.clone();
        wrong_variant[WIRE_DOMAIN.len() + 2] = 0xff;
        assert!(matches!(
            decode_mutation(&wrong_variant),
            Err(MutationWireError::UnknownMutationTag { tag: 0xff })
        ));

        let option_offset = WIRE_DOMAIN.len() + 2 + 1 + 16 * 3 + 1;
        let mut wrong_option = valid.clone();
        wrong_option[option_offset] = 2;
        assert!(matches!(
            decode_mutation(&wrong_option),
            Err(MutationWireError::InvalidOptionTag { tag: 2 })
        ));

        let enum_offset = WIRE_DOMAIN.len() + 2 + 1 + 16 * 3;
        let mut wrong_enum = valid.clone();
        wrong_enum[enum_offset] = 3;
        assert!(matches!(
            decode_mutation(&wrong_enum),
            Err(MutationWireError::InvalidTag {
                field: MutationWireTag::BindingLayer,
                tag: 3
            })
        ));

        let confirmation = encode_mutation(&ManagementMutationV2::ConfirmationCreate {
            row: confirmation_row(85),
        })
        .unwrap();
        let length_offset = WIRE_DOMAIN.len() + 2 + 1 + 16 * 3;
        let mut pseudo_length = confirmation.clone();
        pseudo_length[length_offset..length_offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            decode_mutation(&pseudo_length),
            Err(MutationWireError::FieldTooLarge { .. })
        ));

        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(matches!(
            decode_mutation(&trailing),
            Err(MutationWireError::TrailingBytes { remaining: 1 })
        ));

        let oversized = vec![0_u8; MAX_WIRE_BYTES + 1];
        assert!(matches!(
            decode_mutation(&oversized),
            Err(MutationWireError::InputTooLarge { .. })
        ));

        let batch =
            encode_mutation(&ManagementMutationV2::ConfirmationBatch { rows: vec![] }).unwrap();
        let count_offset = WIRE_DOMAIN.len() + 2 + 1;
        let mut oversized_batch = batch;
        oversized_batch[count_offset..count_offset + 4]
            .copy_from_slice(&(MAX_BATCH_ROWS as u32 + 1).to_be_bytes());
        assert!(matches!(
            decode_mutation(&oversized_batch),
            Err(MutationWireError::BatchTooLarge { .. })
        ));
    }

    #[test]
    // memory—v1: Every strict prefix of a valid frame is rejected as malformed.
    fn every_truncated_prefix_is_rejected() {
        let valid = encode_mutation(&ManagementMutationV2::VersionPublish {
            rule_set_id: id(86),
            version_row: version_row(),
            new_current_version: vec![86, 1],
            change_confirmation: change_confirmation_row(87),
        })
        .unwrap();
        for end in 0..valid.len() {
            assert!(
                decode_mutation(&valid[..end]).is_err(),
                "truncated frame at byte {end} was accepted"
            );
        }
    }
}
