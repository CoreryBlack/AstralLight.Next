//! Deterministic, bounded value encoding for memory-v1 audit candidates.
//!
//! This module encodes only caller-supplied audit values. It does not establish
//! identity, trusted time, authorization, root membership, mutation success,
//! durable persistence, or complete recovery coverage. A future message owner
//! must bind the decoded candidate to its real operation and root facts before
//! treating it as an audit event.
//!
//! The format is a small, fixed-order binary contract. All integers are big
//! endian, all option and enum values have one-byte tags, and every variable
//! field has an explicit bounded length. The component limit is deliberately
//! below the journal envelope's 1 MiB payload limit; the owner must budget the
//! mutation and this audit component together before constructing a message.

use std::fmt;

use crate::memory_v1::MemoryId;
use crate::memory_v1_audit::*;

/// Fixed schema version for this value-level encoding.
pub const MEMORY_V1_AUDIT_WIRE_VERSION: u16 = 1;
/// Header length in bytes: magic, version, kind, flags, and total length.
pub const MEMORY_V1_AUDIT_WIRE_HEADER_BYTES: usize = 16;
/// Maximum encoded audit component size.
///
/// This leaves substantial room inside the journal's 1 MiB envelope for the
/// mutation and other message fields. It is a component limit, not a combined
/// message budget.
pub const MEMORY_V1_AUDIT_WIRE_MAX_BYTES: usize = 256 * 1024;
/// Maximum number of T2 batch entries accepted by this wire.
pub const MEMORY_V1_AUDIT_WIRE_MAX_BATCH_ITEMS: usize = MEMORY_V1_AUDIT_MAX_T2_BATCH_ITEMS;

const MAGIC: &[u8; 8] = b"ALM1AUD\0";
const KIND_T2_ALLOW: u8 = 1;
const KIND_DENY: u8 = 2;
const KIND_T2_SINGLE_ALLOW: u8 = 3;
const FLAG_RESERVED: u8 = 0;

/// Encoding, shape, or bounded-resource failure. No supplied value is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryV1AuditWireError {
    /// Magic, version, flags, enum tag, option tag, or other canonical byte error.
    InvalidEncoding,
    /// The input is truncated or has bytes after the declared record.
    InvalidLength,
    /// A declared or produced value exceeds the local wire bound.
    LimitExceeded,
    /// A field cannot be represented by the public value constructors.
    InvalidField,
    /// The typed entry point received the wrong decision kind.
    WrongDecision,
    /// A PENDING decision has no persistent candidate representation.
    PendingCannotBePersisted,
    /// Operation or batch correlation is inconsistent.
    InvalidCorrelation,
    /// A complete T2 value has an invalid transition shape.
    InconsistentChangeState,
    /// A source marker is not valid for the selected event shape.
    InvalidSource,
}

impl fmt::Display for MemoryV1AuditWireError {
    // memory—v1
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid memory-v1 audit wire value: {self:?}")
    }
}
impl std::error::Error for MemoryV1AuditWireError {}

// memory—v1
fn map_audit_error(error: MemoryV1AuditError) -> MemoryV1AuditWireError {
    match error {
        MemoryV1AuditError::WrongDecision => MemoryV1AuditWireError::WrongDecision,
        MemoryV1AuditError::PendingCannotBePersisted => {
            MemoryV1AuditWireError::PendingCannotBePersisted
        }
        MemoryV1AuditError::InvalidConfirmations => MemoryV1AuditWireError::InvalidCorrelation,
        MemoryV1AuditError::InconsistentChangeState => {
            MemoryV1AuditWireError::InconsistentChangeState
        }
        MemoryV1AuditError::MissingOverlaySource => MemoryV1AuditWireError::InvalidSource,
        _ => MemoryV1AuditWireError::InvalidField,
    }
}

struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    // memory—v1
    fn new(kind: u8) -> Result<Self, MemoryV1AuditWireError> {
        let mut writer = Self { bytes: Vec::new() };
        writer.raw(MAGIC)?;
        writer.u16(MEMORY_V1_AUDIT_WIRE_VERSION)?;
        writer.u8(kind)?;
        writer.u8(FLAG_RESERVED)?;
        writer.u32(0)?;
        Ok(writer)
    }

    // memory—v1
    fn ensure(&mut self, additional: usize) -> Result<(), MemoryV1AuditWireError> {
        let next = self
            .bytes
            .len()
            .checked_add(additional)
            .ok_or(MemoryV1AuditWireError::LimitExceeded)?;
        if next > MEMORY_V1_AUDIT_WIRE_MAX_BYTES {
            return Err(MemoryV1AuditWireError::LimitExceeded);
        }
        self.bytes
            .try_reserve_exact(additional)
            .map_err(|_| MemoryV1AuditWireError::LimitExceeded)
    }

    // memory—v1
    fn raw(&mut self, value: &[u8]) -> Result<(), MemoryV1AuditWireError> {
        self.ensure(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    // memory—v1
    fn u8(&mut self, value: u8) -> Result<(), MemoryV1AuditWireError> {
        self.ensure(1)?;
        self.bytes.push(value);
        Ok(())
    }

    // memory—v1
    fn u16(&mut self, value: u16) -> Result<(), MemoryV1AuditWireError> {
        self.ensure(2)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    // memory—v1
    fn u32(&mut self, value: u32) -> Result<(), MemoryV1AuditWireError> {
        self.ensure(4)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    // memory—v1
    fn u64(&mut self, value: u64) -> Result<(), MemoryV1AuditWireError> {
        self.ensure(8)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    // memory—v1
    fn i64(&mut self, value: i64) -> Result<(), MemoryV1AuditWireError> {
        self.ensure(8)?;
        self.bytes.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    // memory—v1
    fn bytes(&mut self, value: &[u8]) -> Result<(), MemoryV1AuditWireError> {
        let length =
            u32::try_from(value.len()).map_err(|_| MemoryV1AuditWireError::LimitExceeded)?;
        self.u32(length)?;
        self.raw(value)
    }

    // memory—v1
    fn finish(mut self) -> Result<Vec<u8>, MemoryV1AuditWireError> {
        if self.bytes.len() < MEMORY_V1_AUDIT_WIRE_HEADER_BYTES
            || self.bytes.len() > MEMORY_V1_AUDIT_WIRE_MAX_BYTES
        {
            return Err(MemoryV1AuditWireError::LimitExceeded);
        }
        let length =
            u32::try_from(self.bytes.len()).map_err(|_| MemoryV1AuditWireError::LimitExceeded)?;
        self.bytes[12..16].copy_from_slice(&length.to_be_bytes());
        Ok(self.bytes)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    // memory—v1
    fn new(bytes: &'a [u8], expected_kind: u8) -> Result<Self, MemoryV1AuditWireError> {
        if bytes.len() < MEMORY_V1_AUDIT_WIRE_HEADER_BYTES {
            return Err(MemoryV1AuditWireError::InvalidLength);
        }
        if bytes.len() > MEMORY_V1_AUDIT_WIRE_MAX_BYTES {
            return Err(MemoryV1AuditWireError::LimitExceeded);
        }
        if &bytes[..8] != MAGIC
            || u16::from_be_bytes(bytes[8..10].try_into().expect("fixed wire slice"))
                != MEMORY_V1_AUDIT_WIRE_VERSION
            || bytes[10] != expected_kind
            || bytes[11] != FLAG_RESERVED
        {
            return Err(MemoryV1AuditWireError::InvalidEncoding);
        }
        let declared =
            u32::from_be_bytes(bytes[12..16].try_into().expect("fixed wire slice")) as usize;
        if declared < MEMORY_V1_AUDIT_WIRE_HEADER_BYTES {
            return Err(MemoryV1AuditWireError::InvalidLength);
        }
        if declared > MEMORY_V1_AUDIT_WIRE_MAX_BYTES {
            return Err(MemoryV1AuditWireError::LimitExceeded);
        }
        if declared != bytes.len() {
            return Err(MemoryV1AuditWireError::InvalidLength);
        }
        Ok(Self {
            bytes,
            offset: MEMORY_V1_AUDIT_WIRE_HEADER_BYTES,
        })
    }

    // memory—v1
    fn take(&mut self, length: usize) -> Result<&'a [u8], MemoryV1AuditWireError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(MemoryV1AuditWireError::InvalidLength)?;
        if end > self.bytes.len() {
            return Err(MemoryV1AuditWireError::InvalidLength);
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    // memory—v1
    fn u8(&mut self) -> Result<u8, MemoryV1AuditWireError> {
        Ok(self.take(1)?[0])
    }

    // memory—v1
    fn u16(&mut self) -> Result<u16, MemoryV1AuditWireError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("fixed wire slice"),
        ))
    }

    // memory—v1
    fn u32(&mut self) -> Result<u32, MemoryV1AuditWireError> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("fixed wire slice"),
        ))
    }

    // memory—v1
    fn u64(&mut self) -> Result<u64, MemoryV1AuditWireError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("fixed wire slice"),
        ))
    }

    // memory—v1
    fn i64(&mut self) -> Result<i64, MemoryV1AuditWireError> {
        Ok(i64::from_be_bytes(
            self.take(8)?.try_into().expect("fixed wire slice"),
        ))
    }

    // memory—v1
    fn bounded_bytes(&mut self, max: usize) -> Result<&'a [u8], MemoryV1AuditWireError> {
        let length = self.u32()? as usize;
        if length > max {
            return Err(MemoryV1AuditWireError::LimitExceeded);
        }
        self.take(length)
    }

    // memory—v1
    fn text(&mut self, max: usize) -> Result<&'a str, MemoryV1AuditWireError> {
        let bytes = self.bounded_bytes(max)?;
        std::str::from_utf8(bytes).map_err(|_| MemoryV1AuditWireError::InvalidField)
    }

    // memory—v1
    fn count(&mut self, max: usize) -> Result<usize, MemoryV1AuditWireError> {
        let count = self.u16()? as usize;
        if count == 0 {
            return Err(MemoryV1AuditWireError::InvalidField);
        }
        if count > max {
            return Err(MemoryV1AuditWireError::LimitExceeded);
        }
        Ok(count)
    }

    // memory—v1
    fn done(&self) -> Result<(), MemoryV1AuditWireError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(MemoryV1AuditWireError::InvalidLength)
        }
    }
}

// memory—v1
fn write_id(writer: &mut Writer, id: MemoryId) -> Result<(), MemoryV1AuditWireError> {
    writer.raw(id.as_bytes())
}

// memory—v1
fn read_id(reader: &mut Reader<'_>) -> Result<MemoryId, MemoryV1AuditWireError> {
    Ok(MemoryId::from_bytes(
        reader.take(16)?.try_into().expect("fixed id slice"),
    ))
}

// memory—v1
fn write_operation(
    writer: &mut Writer,
    operation: &MemoryV1AuditOperation,
) -> Result<(), MemoryV1AuditWireError> {
    writer.bytes(operation.id().as_bytes())?;
    writer.raw(operation.fingerprint())
}

// memory—v1
fn read_operation(
    reader: &mut Reader<'_>,
) -> Result<MemoryV1AuditOperation, MemoryV1AuditWireError> {
    let id = reader.text(MEMORY_V1_AUDIT_MAX_OPERATION_ID_BYTES)?;
    let fingerprint = reader
        .take(32)?
        .try_into()
        .expect("fixed fingerprint slice");
    MemoryV1AuditOperation::new(id, fingerprint).map_err(map_audit_error)
}

// memory—v1
fn write_root_version(
    writer: &mut Writer,
    version: MemoryV1AuditRootVersion,
) -> Result<(), MemoryV1AuditWireError> {
    write_id(writer, version.instance())?;
    writer.u64(version.version())?;
    Ok(())
}

// memory—v1
fn read_root_version(
    reader: &mut Reader<'_>,
) -> Result<MemoryV1AuditRootVersion, MemoryV1AuditWireError> {
    Ok(MemoryV1AuditRootVersion::new(
        read_id(reader)?,
        reader.u64()?,
    ))
}

// memory—v1
fn write_root_status(
    writer: &mut Writer,
    status: MemoryV1AuditRootStatus,
) -> Result<(), MemoryV1AuditWireError> {
    writer.u8(match status {
        MemoryV1AuditRootStatus::Candidate => 1,
        MemoryV1AuditRootStatus::Serving => 2,
        MemoryV1AuditRootStatus::Invalid => 3,
        MemoryV1AuditRootStatus::Stopped => 4,
    })?;
    Ok(())
}

// memory—v1
fn read_root_status(
    reader: &mut Reader<'_>,
) -> Result<MemoryV1AuditRootStatus, MemoryV1AuditWireError> {
    match reader.u8()? {
        1 => Ok(MemoryV1AuditRootStatus::Candidate),
        2 => Ok(MemoryV1AuditRootStatus::Serving),
        3 => Ok(MemoryV1AuditRootStatus::Invalid),
        4 => Ok(MemoryV1AuditRootStatus::Stopped),
        _ => Err(MemoryV1AuditWireError::InvalidEncoding),
    }
}

// memory—v1
fn write_context(
    writer: &mut Writer,
    context: &MemoryV1AuditContext,
) -> Result<(), MemoryV1AuditWireError> {
    write_id(writer, context.actor().user())?;
    write_id(writer, context.actor().identity_card())?;
    writer.i64(context.time().unix_seconds())?;
    writer.bytes(context.action().resource().as_bytes())?;
    writer.bytes(context.action().action().as_bytes())?;
    writer.bytes(context.reason_code().as_bytes())?;
    write_operation(writer, context.operation())?;
    let root = context.root();
    write_root_version(writer, root.version())?;
    writer.raw(root.content_hash())?;
    write_root_status(writer, root.status())
}

// memory—v1
fn read_context(reader: &mut Reader<'_>) -> Result<MemoryV1AuditContext, MemoryV1AuditWireError> {
    let actor = MemoryV1AuditActor::new(read_id(reader)?, read_id(reader)?);
    let time = MemoryV1AuditTime::new(reader.i64()?).map_err(map_audit_error)?;
    let resource = reader.text(MEMORY_V1_AUDIT_MAX_RESOURCE_BYTES)?;
    let action = reader.text(MEMORY_V1_AUDIT_MAX_ACTION_BYTES)?;
    let action = MemoryV1AuditAction::new(resource, action).map_err(map_audit_error)?;
    let reason = reader.text(MEMORY_V1_AUDIT_MAX_REASON_CODE_BYTES)?;
    let operation = read_operation(reader)?;
    let root_version = read_root_version(reader)?;
    let content_hash = reader.take(32)?.try_into().expect("fixed root hash slice");
    let status = read_root_status(reader)?;
    let root = MemoryV1AuditRootObservation::new(root_version, content_hash, status);
    MemoryV1AuditContext::new(actor, time, action, reason, operation, root).map_err(map_audit_error)
}

// memory—v1
fn write_deny_source(
    writer: &mut Writer,
    source: MemoryV1AuditDenySource,
) -> Result<(), MemoryV1AuditWireError> {
    writer.u8(match source {
        MemoryV1AuditDenySource::RuleDeny => 1,
        MemoryV1AuditDenySource::NoMatch => 2,
        MemoryV1AuditDenySource::ScopeDenied => 3,
        MemoryV1AuditDenySource::CardUnbound => 4,
        MemoryV1AuditDenySource::IdentityMismatch => 5,
        MemoryV1AuditDenySource::UnregisteredResource => 6,
        MemoryV1AuditDenySource::SelfConfirmation => 7,
        MemoryV1AuditDenySource::CardDisabled => 8,
        MemoryV1AuditDenySource::OverlayOnlyCreation => 9,
    })?;
    Ok(())
}

// memory—v1
fn read_deny_source(
    reader: &mut Reader<'_>,
) -> Result<MemoryV1AuditDenySource, MemoryV1AuditWireError> {
    match reader.u8()? {
        1 => Ok(MemoryV1AuditDenySource::RuleDeny),
        2 => Ok(MemoryV1AuditDenySource::NoMatch),
        3 => Ok(MemoryV1AuditDenySource::ScopeDenied),
        4 => Ok(MemoryV1AuditDenySource::CardUnbound),
        5 => Ok(MemoryV1AuditDenySource::IdentityMismatch),
        6 => Ok(MemoryV1AuditDenySource::UnregisteredResource),
        7 => Ok(MemoryV1AuditDenySource::SelfConfirmation),
        8 => Ok(MemoryV1AuditDenySource::CardDisabled),
        9 => Ok(MemoryV1AuditDenySource::OverlayOnlyCreation),
        _ => Err(MemoryV1AuditWireError::InvalidEncoding),
    }
}

// memory—v1
fn write_object(
    writer: &mut Writer,
    object: MemoryV1AuditObject,
) -> Result<(), MemoryV1AuditWireError> {
    let (tag, id) = match object {
        MemoryV1AuditObject::Tenant(id) => (1, id),
        MemoryV1AuditObject::UserCard(id) => (2, id),
        MemoryV1AuditObject::RuleSet(id) => (3, id),
        MemoryV1AuditObject::Binding(id) => (4, id),
        MemoryV1AuditObject::Confirmation(id) => (5, id),
        MemoryV1AuditObject::User(id) => (6, id),
    };
    writer.u8(tag)?;
    write_id(writer, id)
}

// memory—v1
fn read_object(reader: &mut Reader<'_>) -> Result<MemoryV1AuditObject, MemoryV1AuditWireError> {
    let tag = reader.u8()?;
    let id = read_id(reader)?;
    match tag {
        1 => Ok(MemoryV1AuditObject::Tenant(id)),
        2 => Ok(MemoryV1AuditObject::UserCard(id)),
        3 => Ok(MemoryV1AuditObject::RuleSet(id)),
        4 => Ok(MemoryV1AuditObject::Binding(id)),
        5 => Ok(MemoryV1AuditObject::Confirmation(id)),
        6 => Ok(MemoryV1AuditObject::User(id)),
        _ => Err(MemoryV1AuditWireError::InvalidEncoding),
    }
}

// memory—v1
fn write_registry_resource(
    writer: &mut Writer,
    resource: MemoryV1AuditRegistryResource,
) -> Result<(), MemoryV1AuditWireError> {
    writer.bytes(resource.as_bytes())
}

// memory—v1
fn read_registry_resource(
    reader: &mut Reader<'_>,
) -> Result<MemoryV1AuditRegistryResource, MemoryV1AuditWireError> {
    let value = reader.bounded_bytes(MEMORY_V1_AUDIT_MAX_REGISTRY_RESOURCE_BYTES)?;
    let value = std::str::from_utf8(value).map_err(|_| MemoryV1AuditWireError::InvalidField)?;
    MemoryV1AuditRegistryResource::new(value).map_err(map_audit_error)
}

// memory—v1
fn write_target(
    writer: &mut Writer,
    target: MemoryV1AuditTarget,
) -> Result<(), MemoryV1AuditWireError> {
    match target {
        MemoryV1AuditTarget::Object(object) => {
            writer.u8(1)?;
            write_object(writer, object)
        }
        MemoryV1AuditTarget::Registry(registry) => {
            writer.u8(2)?;
            write_registry_resource(writer, registry.resource())
        }
    }
}

// memory—v1
fn read_target(reader: &mut Reader<'_>) -> Result<MemoryV1AuditTarget, MemoryV1AuditWireError> {
    match reader.u8()? {
        1 => Ok(MemoryV1AuditTarget::Object(read_object(reader)?)),
        2 => Ok(MemoryV1AuditTarget::Registry(
            MemoryV1AuditRegistryTarget::new(read_registry_resource(reader)?),
        )),
        _ => Err(MemoryV1AuditWireError::InvalidEncoding),
    }
}

// memory—v1
fn write_state(
    writer: &mut Writer,
    state: &MemoryV1AuditObjectState,
) -> Result<(), MemoryV1AuditWireError> {
    match state {
        MemoryV1AuditObjectState::Absent => writer.u8(0)?,
        MemoryV1AuditObjectState::UserCard(value) => {
            writer.u8(match value {
                MemoryV1AuditCardState::Active => 1,
                MemoryV1AuditCardState::Disabled => 2,
            })?;
        }
        MemoryV1AuditObjectState::Binding(value) => {
            writer.u8(match value {
                MemoryV1AuditBindingState::Active => 3,
                MemoryV1AuditBindingState::Removed => 4,
            })?;
        }
        MemoryV1AuditObjectState::Confirmation(value) => {
            writer.u8(match value {
                MemoryV1AuditConfirmationState::Active => 5,
                MemoryV1AuditConfirmationState::Revoked => 6,
            })?;
        }
        MemoryV1AuditObjectState::Registry(value) => {
            writer.u8(match value {
                MemoryV1AuditRegistryState::Active => 7,
                MemoryV1AuditRegistryState::RetireRequested => 8,
                MemoryV1AuditRegistryState::Retired => 9,
            })?;
        }
        MemoryV1AuditObjectState::RuleSet(value) => {
            writer.u8(10)?;
            writer.bytes(value.current_version())?;
            writer.raw(value.content_hash())?;
            writer.u8(match value.status() {
                None => 0,
                Some(MemoryV1AuditRuleSetStatus::Active) => 1,
                Some(MemoryV1AuditRuleSetStatus::Retired) => 2,
            })?;
        }
    }
    Ok(())
}

// memory—v1
fn read_state(reader: &mut Reader<'_>) -> Result<MemoryV1AuditObjectState, MemoryV1AuditWireError> {
    match reader.u8()? {
        0 => Ok(MemoryV1AuditObjectState::Absent),
        1 => Ok(MemoryV1AuditObjectState::UserCard(
            MemoryV1AuditCardState::Active,
        )),
        2 => Ok(MemoryV1AuditObjectState::UserCard(
            MemoryV1AuditCardState::Disabled,
        )),
        3 => Ok(MemoryV1AuditObjectState::Binding(
            MemoryV1AuditBindingState::Active,
        )),
        4 => Ok(MemoryV1AuditObjectState::Binding(
            MemoryV1AuditBindingState::Removed,
        )),
        5 => Ok(MemoryV1AuditObjectState::Confirmation(
            MemoryV1AuditConfirmationState::Active,
        )),
        6 => Ok(MemoryV1AuditObjectState::Confirmation(
            MemoryV1AuditConfirmationState::Revoked,
        )),
        7 => Ok(MemoryV1AuditObjectState::Registry(
            MemoryV1AuditRegistryState::Active,
        )),
        8 => Ok(MemoryV1AuditObjectState::Registry(
            MemoryV1AuditRegistryState::RetireRequested,
        )),
        9 => Ok(MemoryV1AuditObjectState::Registry(
            MemoryV1AuditRegistryState::Retired,
        )),
        10 => {
            let version = reader.bounded_bytes(MEMORY_V1_AUDIT_MAX_RULE_SET_VERSION_BYTES)?;
            let hash = reader
                .take(32)?
                .try_into()
                .expect("fixed rule-set hash slice");
            let status = match reader.u8()? {
                0 => None,
                1 => Some(MemoryV1AuditRuleSetStatus::Active),
                2 => Some(MemoryV1AuditRuleSetStatus::Retired),
                _ => return Err(MemoryV1AuditWireError::InvalidEncoding),
            };
            Ok(MemoryV1AuditObjectState::RuleSet(
                MemoryV1AuditRuleSetState::new(version, hash)
                    .map_err(map_audit_error)
                    .and_then(|value| {
                        if let Some(status) = status {
                            MemoryV1AuditRuleSetState::new_with_status(
                                value.current_version(),
                                *value.content_hash(),
                                status,
                            )
                            .map_err(map_audit_error)
                        } else {
                            Ok(value)
                        }
                    })?,
            ))
        }
        _ => Err(MemoryV1AuditWireError::InvalidEncoding),
    }
}

// memory—v1
fn write_confirmation(
    writer: &mut Writer,
    confirmation: MemoryV1AuditConfirmationRef,
) -> Result<(), MemoryV1AuditWireError> {
    match confirmation {
        MemoryV1AuditConfirmationRef::Binding(id) => {
            writer.u8(1)?;
            write_id(writer, id)
        }
        MemoryV1AuditConfirmationRef::RuleSetChange(id) => {
            writer.u8(2)?;
            write_id(writer, id)
        }
    }
}

// memory—v1
fn read_confirmation(
    reader: &mut Reader<'_>,
) -> Result<MemoryV1AuditConfirmationRef, MemoryV1AuditWireError> {
    let tag = reader.u8()?;
    let id = read_id(reader)?;
    match tag {
        1 => Ok(MemoryV1AuditConfirmationRef::Binding(id)),
        2 => Ok(MemoryV1AuditConfirmationRef::RuleSetChange(id)),
        _ => Err(MemoryV1AuditWireError::InvalidEncoding),
    }
}

// memory—v1
fn write_confirmations(
    writer: &mut Writer,
    confirmations: &MemoryV1AuditConfirmations,
) -> Result<(), MemoryV1AuditWireError> {
    if confirmations.is_not_applicable() {
        writer.u8(0)?;
        return Ok(());
    }
    if let Some(values) = confirmations.as_references() {
        writer.u8(1)?;
        let count =
            u16::try_from(values.len()).map_err(|_| MemoryV1AuditWireError::LimitExceeded)?;
        writer.u16(count)?;
        for value in values {
            write_confirmation(writer, *value)?;
        }
        return Ok(());
    }
    let Some(batch) = confirmations.as_batch() else {
        return Err(MemoryV1AuditWireError::InvalidField);
    };
    writer.u8(2)?;
    write_operation(writer, batch.operation())?;
    let count =
        u16::try_from(batch.items().len()).map_err(|_| MemoryV1AuditWireError::LimitExceeded)?;
    writer.u16(count)?;
    for item in batch.items() {
        writer.u32(item.sequence())?;
        write_confirmation(writer, item.confirmation())?;
    }
    Ok(())
}

// memory—v1
fn read_confirmations(
    reader: &mut Reader<'_>,
) -> Result<MemoryV1AuditConfirmations, MemoryV1AuditWireError> {
    match reader.u8()? {
        0 => Ok(MemoryV1AuditConfirmations::not_applicable()),
        1 => {
            let count = reader.count(MEMORY_V1_AUDIT_MAX_CONFIRMATIONS)?;
            let mut values = Vec::new();
            values
                .try_reserve_exact(count)
                .map_err(|_| MemoryV1AuditWireError::LimitExceeded)?;
            for _ in 0..count {
                values.push(read_confirmation(reader)?);
            }
            MemoryV1AuditConfirmations::references(&values).map_err(map_audit_error)
        }
        2 => {
            let operation = read_operation(reader)?;
            let count = reader.count(MEMORY_V1_AUDIT_MAX_CONFIRMATIONS)?;
            let mut items = Vec::new();
            items
                .try_reserve_exact(count)
                .map_err(|_| MemoryV1AuditWireError::LimitExceeded)?;
            for _ in 0..count {
                items.push(MemoryV1AuditConfirmationBatchItem::new(
                    reader.u32()?,
                    read_confirmation(reader)?,
                ));
            }
            MemoryV1AuditConfirmations::batch(operation, &items, MEMORY_V1_AUDIT_MAX_CONFIRMATIONS)
                .map_err(map_audit_error)
        }
        _ => Err(MemoryV1AuditWireError::InvalidEncoding),
    }
}

// memory—v1
fn write_source(
    writer: &mut Writer,
    source: MemoryV1AuditSource,
) -> Result<(), MemoryV1AuditWireError> {
    match source {
        MemoryV1AuditSource::Ordinary => writer.u8(0)?,
        MemoryV1AuditSource::OverlayOnlyCreation(value) => {
            writer.u8(1)?;
            write_id(writer, value.creator())?;
            write_id(writer, value.beneficiary())?;
            write_id(writer, value.rule_set())?;
        }
    }
    Ok(())
}

// memory—v1
fn read_source(reader: &mut Reader<'_>) -> Result<MemoryV1AuditSource, MemoryV1AuditWireError> {
    match reader.u8()? {
        0 => Ok(MemoryV1AuditSource::Ordinary),
        1 => Ok(MemoryV1AuditSource::OverlayOnlyCreation(
            MemoryV1AuditOverlayOnly::new(read_id(reader)?, read_id(reader)?, read_id(reader)?),
        )),
        _ => Err(MemoryV1AuditWireError::InvalidEncoding),
    }
}

// memory—v1
fn write_option_id(
    writer: &mut Writer,
    value: Option<MemoryId>,
) -> Result<(), MemoryV1AuditWireError> {
    match value {
        None => writer.u8(0)?,
        Some(value) => {
            writer.u8(1)?;
            write_id(writer, value)?;
        }
    }
    Ok(())
}

// memory—v1
fn read_option_id(reader: &mut Reader<'_>) -> Result<Option<MemoryId>, MemoryV1AuditWireError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(read_id(reader)?)),
        _ => Err(MemoryV1AuditWireError::InvalidEncoding),
    }
}

// memory—v1
fn write_option_object(
    writer: &mut Writer,
    value: Option<MemoryV1AuditObject>,
) -> Result<(), MemoryV1AuditWireError> {
    match value {
        None => writer.u8(0)?,
        Some(value) => {
            writer.u8(1)?;
            write_object(writer, value)?;
        }
    }
    Ok(())
}

// memory—v1
fn read_option_object(
    reader: &mut Reader<'_>,
) -> Result<Option<MemoryV1AuditObject>, MemoryV1AuditWireError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(read_object(reader)?)),
        _ => Err(MemoryV1AuditWireError::InvalidEncoding),
    }
}

// memory—v1
fn write_option_summary(
    writer: &mut Writer,
    value: Option<&MemoryV1AuditChangeSummary>,
) -> Result<(), MemoryV1AuditWireError> {
    match value {
        None => writer.u8(0)?,
        Some(value) => {
            writer.u8(1)?;
            writer.bytes(value.as_bytes())?;
        }
    }
    Ok(())
}

// memory—v1
fn read_option_summary(
    reader: &mut Reader<'_>,
) -> Result<Option<MemoryV1AuditChangeSummary>, MemoryV1AuditWireError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(
            MemoryV1AuditChangeSummary::new(
                reader.bounded_bytes(MEMORY_V1_AUDIT_MAX_CHANGE_SUMMARY_BYTES)?,
            )
            .map_err(map_audit_error)?,
        )),
        _ => Err(MemoryV1AuditWireError::InvalidEncoding),
    }
}

// memory—v1
fn write_option_state(
    writer: &mut Writer,
    value: Option<&MemoryV1AuditObjectState>,
) -> Result<(), MemoryV1AuditWireError> {
    match value {
        None => writer.u8(0)?,
        Some(value) => {
            writer.u8(1)?;
            write_state(writer, value)?;
        }
    }
    Ok(())
}

// memory—v1
fn read_option_state(
    reader: &mut Reader<'_>,
) -> Result<Option<MemoryV1AuditObjectState>, MemoryV1AuditWireError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(read_state(reader)?)),
        _ => Err(MemoryV1AuditWireError::InvalidEncoding),
    }
}

// memory—v1
fn write_option_confirmations(
    writer: &mut Writer,
    value: Option<&MemoryV1AuditConfirmations>,
) -> Result<(), MemoryV1AuditWireError> {
    match value {
        None => writer.u8(0)?,
        Some(value) => {
            writer.u8(1)?;
            write_confirmations(writer, value)?;
        }
    }
    Ok(())
}

// memory—v1
fn read_option_confirmations(
    reader: &mut Reader<'_>,
) -> Result<Option<MemoryV1AuditConfirmations>, MemoryV1AuditWireError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(read_confirmations(reader)?)),
        _ => Err(MemoryV1AuditWireError::InvalidEncoding),
    }
}

// memory—v1
fn write_option_root_version(
    writer: &mut Writer,
    value: Option<MemoryV1AuditRootVersion>,
) -> Result<(), MemoryV1AuditWireError> {
    match value {
        None => writer.u8(0)?,
        Some(value) => {
            writer.u8(1)?;
            write_root_version(writer, value)?;
        }
    }
    Ok(())
}

// memory—v1
fn read_option_root_version(
    reader: &mut Reader<'_>,
) -> Result<Option<MemoryV1AuditRootVersion>, MemoryV1AuditWireError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(read_root_version(reader)?)),
        _ => Err(MemoryV1AuditWireError::InvalidEncoding),
    }
}

// memory—v1
fn write_change(
    writer: &mut Writer,
    change: &MemoryV1AuditChange,
) -> Result<(), MemoryV1AuditWireError> {
    write_option_id(writer, change.approver())?;
    write_option_object(writer, change.target())?;
    write_option_object(writer, change.scope())?;
    write_option_summary(writer, change.change_summary())?;
    write_option_state(writer, change.before())?;
    write_option_state(writer, change.after())?;
    write_option_confirmations(writer, change.confirmations())?;
    write_option_root_version(writer, change.root_before())?;
    write_option_root_version(writer, change.root_after())?;
    write_source(writer, change.source())
}

// memory—v1
fn read_change(reader: &mut Reader<'_>) -> Result<MemoryV1AuditChange, MemoryV1AuditWireError> {
    Ok(MemoryV1AuditChange::new(
        read_option_id(reader)?,
        read_option_object(reader)?,
        read_option_object(reader)?,
        read_option_summary(reader)?,
        read_option_state(reader)?,
        read_option_state(reader)?,
        read_option_confirmations(reader)?,
        read_option_root_version(reader)?,
        read_option_root_version(reader)?,
        read_source(reader)?,
    ))
}

// memory—v1
fn write_t2_registry(
    writer: &mut Writer,
    value: &MemoryV1AuditT2Registry,
) -> Result<(), MemoryV1AuditWireError> {
    write_operation(writer, value.operation())?;
    write_registry_resource(writer, value.target().resource())?;
    write_target(writer, value.scope())?;
    write_state(writer, value.before())?;
    write_state(writer, value.after())?;
    write_confirmation(writer, value.confirmation())
}

// memory—v1
fn read_t2_registry(
    reader: &mut Reader<'_>,
) -> Result<MemoryV1AuditT2Registry, MemoryV1AuditWireError> {
    let operation = read_operation(reader)?;
    let target = MemoryV1AuditRegistryTarget::new(read_registry_resource(reader)?);
    let scope = read_target(reader)?;
    let before = read_state(reader)?;
    let after = read_state(reader)?;
    let confirmation = read_confirmation(reader)?;
    MemoryV1AuditT2Registry::new(operation, target, scope, before, after, confirmation)
        .map_err(map_audit_error)
}

// memory—v1
fn write_t2_batch(
    writer: &mut Writer,
    value: &MemoryV1AuditT2Batch,
) -> Result<(), MemoryV1AuditWireError> {
    write_operation(writer, value.operation())?;
    let count =
        u16::try_from(value.items().len()).map_err(|_| MemoryV1AuditWireError::LimitExceeded)?;
    writer.u16(count)?;
    for item in value.items() {
        writer.u32(item.sequence())?;
        write_target(writer, item.target())?;
        write_target(writer, item.scope())?;
        write_state(writer, item.before())?;
        write_state(writer, item.after())?;
        write_confirmation(writer, item.confirmation())?;
        write_operation(writer, item.operation())?;
    }
    Ok(())
}

// memory—v1
fn read_t2_batch(
    reader: &mut Reader<'_>,
    source: MemoryV1AuditSource,
) -> Result<MemoryV1AuditT2Batch, MemoryV1AuditWireError> {
    let operation = read_operation(reader)?;
    let count = reader.count(MEMORY_V1_AUDIT_WIRE_MAX_BATCH_ITEMS)?;
    let mut items = Vec::new();
    items
        .try_reserve_exact(count)
        .map_err(|_| MemoryV1AuditWireError::LimitExceeded)?;
    for _ in 0..count {
        items.push(MemoryV1AuditT2BatchItem::new(
            reader.u32()?,
            read_target(reader)?,
            read_target(reader)?,
            read_state(reader)?,
            read_state(reader)?,
            read_confirmation(reader)?,
            read_operation(reader)?,
        ));
    }
    let batch =
        MemoryV1AuditT2Batch::new_with_source(&items, MEMORY_V1_AUDIT_WIRE_MAX_BATCH_ITEMS, source)
            .map_err(map_audit_error)?;
    if batch.operation() != &operation {
        return Err(MemoryV1AuditWireError::InvalidCorrelation);
    }
    Ok(batch)
}

/// Encode one complete single-change T2 ALLOW candidate.
///
/// This is the B-4 single-change shape backed by the public wrapper. It is
/// separate from the registry/batch candidate because those payload types cannot
/// represent an ordinary binding, user-card, or rule-set change without inventing
/// a payload variant.
// memory—v1
pub fn encode_t2_single_change_candidate(
    candidate: &MemoryV1AuditT2SingleChangeCandidate,
) -> Result<Vec<u8>, MemoryV1AuditWireError> {
    if candidate.decision() != MemoryV1AuditDecision::Allow {
        return Err(MemoryV1AuditWireError::WrongDecision);
    }
    let mut writer = Writer::new(KIND_T2_SINGLE_ALLOW)?;
    write_context(&mut writer, candidate.context())?;
    writer.u8(1)?;
    write_id(&mut writer, candidate.approver())?;
    write_object(&mut writer, candidate.target())?;
    write_object(&mut writer, candidate.scope())?;
    writer.bytes(candidate.change_summary().as_bytes())?;
    write_state(&mut writer, candidate.before())?;
    write_state(&mut writer, candidate.after())?;
    write_confirmations(&mut writer, candidate.confirmations())?;
    write_root_version(&mut writer, candidate.root_before())?;
    write_root_version(&mut writer, candidate.root_after())?;
    write_source(&mut writer, candidate.source())?;
    writer.finish()
}

/// Decode one complete single-change T2 ALLOW candidate and re-run its public
/// completeness and transition checks before returning it.
// memory—v1
pub fn decode_t2_single_change_candidate(
    bytes: &[u8],
) -> Result<MemoryV1AuditT2SingleChangeCandidate, MemoryV1AuditWireError> {
    let mut reader = Reader::new(bytes, KIND_T2_SINGLE_ALLOW)?;
    let context = read_context(&mut reader)?;
    match reader.u8()? {
        1 => {}
        2 => return Err(MemoryV1AuditWireError::WrongDecision),
        3 => return Err(MemoryV1AuditWireError::PendingCannotBePersisted),
        _ => return Err(MemoryV1AuditWireError::InvalidEncoding),
    }
    let change = MemoryV1AuditChange::new(
        Some(read_id(&mut reader)?),
        Some(read_object(&mut reader)?),
        Some(read_object(&mut reader)?),
        Some(
            MemoryV1AuditChangeSummary::new(
                reader.bounded_bytes(MEMORY_V1_AUDIT_MAX_CHANGE_SUMMARY_BYTES)?,
            )
            .map_err(map_audit_error)?,
        ),
        Some(read_state(&mut reader)?),
        Some(read_state(&mut reader)?),
        Some(read_confirmations(&mut reader)?),
        Some(read_root_version(&mut reader)?),
        Some(read_root_version(&mut reader)?),
        read_source(&mut reader)?,
    );
    reader.done()?;
    let event = MemoryV1AuditEvent::change(context, MemoryV1AuditDecisionInput::Allow, change)
        .map_err(map_audit_error)?;
    MemoryV1AuditT2SingleChangeCandidate::try_from(event).map_err(map_audit_error)
}

/// Encode one complete T2 candidate. The typed entry point accepts ALLOW only.
///
/// `MemoryV1AuditT2EventCandidate` can carry a DENY value at the value layer,
/// but that shape is deliberately rejected here; DENY has its own event entry
/// point so recovery cannot mistake a partial denial for a complete mutation.
// memory—v1
pub fn encode_t2_candidate(
    candidate: &MemoryV1AuditT2EventCandidate,
) -> Result<Vec<u8>, MemoryV1AuditWireError> {
    if candidate.decision() != MemoryV1AuditDecision::Allow {
        return Err(MemoryV1AuditWireError::WrongDecision);
    }
    let mut writer = Writer::new(KIND_T2_ALLOW)?;
    write_context(&mut writer, candidate.context())?;
    writer.u8(1)?; // ALLOW; other decision tags are not valid in this entry point.
    write_id(&mut writer, candidate.approver())?;
    writer.bytes(candidate.change_summary().as_bytes())?;
    write_root_version(&mut writer, candidate.root_before())?;
    write_root_version(&mut writer, candidate.root_after())?;
    write_source(&mut writer, candidate.source())?;
    match candidate.payload() {
        MemoryV1AuditT2EventPayload::Registry(value) => {
            writer.u8(1)?;
            write_t2_registry(&mut writer, value)?;
        }
        MemoryV1AuditT2EventPayload::Batch(value) => {
            writer.u8(2)?;
            write_t2_batch(&mut writer, value)?;
        }
    }
    writer.finish()
}

/// Decode exactly one complete T2 ALLOW candidate.
// memory—v1
pub fn decode_t2_candidate(
    bytes: &[u8],
) -> Result<MemoryV1AuditT2EventCandidate, MemoryV1AuditWireError> {
    let mut reader = Reader::new(bytes, KIND_T2_ALLOW)?;
    let context = read_context(&mut reader)?;
    match reader.u8()? {
        1 => {}
        2 => return Err(MemoryV1AuditWireError::WrongDecision),
        3 => return Err(MemoryV1AuditWireError::PendingCannotBePersisted),
        _ => return Err(MemoryV1AuditWireError::InvalidEncoding),
    }
    let approver = read_id(&mut reader)?;
    let summary = MemoryV1AuditChangeSummary::new(
        reader.bounded_bytes(MEMORY_V1_AUDIT_MAX_CHANGE_SUMMARY_BYTES)?,
    )
    .map_err(map_audit_error)?;
    let root_before = read_root_version(&mut reader)?;
    let root_after = read_root_version(&mut reader)?;
    let source = read_source(&mut reader)?;
    let payload = match reader.u8()? {
        1 => MemoryV1AuditT2EventPayload::Registry(read_t2_registry(&mut reader)?),
        2 => MemoryV1AuditT2EventPayload::Batch(read_t2_batch(&mut reader, source)?),
        _ => return Err(MemoryV1AuditWireError::InvalidEncoding),
    };
    reader.done()?;
    match payload {
        MemoryV1AuditT2EventPayload::Registry(value) => MemoryV1AuditT2EventCandidate::registry(
            context,
            MemoryV1AuditDecisionInput::Allow,
            approver,
            summary,
            root_before,
            root_after,
            source,
            value,
        )
        .map_err(map_audit_error),
        MemoryV1AuditT2EventPayload::Batch(value) => MemoryV1AuditT2EventCandidate::batch(
            context,
            MemoryV1AuditDecisionInput::Allow,
            approver,
            summary,
            root_before,
            root_after,
            source,
            value,
        )
        .map_err(map_audit_error),
    }
}

/// Encode a DENY event, preserving T1 (`change_details == None`) versus T2
/// partial (`change_details == Some(_)`) and every available Option value.
///
/// ALLOW events are rejected even when they contain a complete change; complete
/// successful changes must use [`encode_t2_candidate`].
// memory—v1
pub fn encode_deny_event(event: &MemoryV1AuditEvent) -> Result<Vec<u8>, MemoryV1AuditWireError> {
    let MemoryV1AuditDecision::Deny(source) = event.decision() else {
        return Err(MemoryV1AuditWireError::WrongDecision);
    };
    let mut writer = Writer::new(KIND_DENY)?;
    write_context(&mut writer, event.context())?;
    writer.u8(2)?; // DENY
    write_deny_source(&mut writer, source)?;
    match event.change_details() {
        None => writer.u8(0)?,
        Some(change) => {
            writer.u8(1)?;
            write_change(&mut writer, change)?;
        }
    }
    writer.finish()
}

/// Decode exactly one DENY event. T1 and T2 partial events remain distinct.
// memory—v1
pub fn decode_deny_event(bytes: &[u8]) -> Result<MemoryV1AuditEvent, MemoryV1AuditWireError> {
    let mut reader = Reader::new(bytes, KIND_DENY)?;
    let context = read_context(&mut reader)?;
    match reader.u8()? {
        1 => return Err(MemoryV1AuditWireError::WrongDecision),
        2 => {}
        3 => return Err(MemoryV1AuditWireError::PendingCannotBePersisted),
        _ => return Err(MemoryV1AuditWireError::InvalidEncoding),
    }
    let source = read_deny_source(&mut reader)?;
    let change = match reader.u8()? {
        0 => None,
        1 => Some(read_change(&mut reader)?),
        _ => return Err(MemoryV1AuditWireError::InvalidEncoding),
    };
    reader.done()?;
    match change {
        None => MemoryV1AuditEvent::read(context, MemoryV1AuditDecisionInput::Deny(source)),
        Some(change) => {
            MemoryV1AuditEvent::change(context, MemoryV1AuditDecisionInput::Deny(source), change)
        }
    }
    .map_err(map_audit_error)
}

/// Alias emphasizing that the T2 wire entry point is ALLOW-only.
// memory—v1
pub use decode_t2_candidate as decode_t2_allow;
/// Alias emphasizing that the T2 wire entry point is ALLOW-only.
// memory—v1
pub use encode_t2_candidate as encode_t2_allow;

#[cfg(test)]
mod tests {
    use super::*;

    // memory—v1
    fn id(value: u8) -> MemoryId {
        MemoryId::from_bytes([value; 16])
    }

    // memory—v1
    fn operation() -> MemoryV1AuditOperation {
        MemoryV1AuditOperation::new("op-1", [3; 32]).unwrap()
    }

    // memory—v1
    fn root(value: u64) -> MemoryV1AuditRootVersion {
        MemoryV1AuditRootVersion::new(id(9), value)
    }

    // memory—v1
    fn context() -> MemoryV1AuditContext {
        MemoryV1AuditContext::new(
            MemoryV1AuditActor::new(id(1), id(2)),
            MemoryV1AuditTime::new(7).unwrap(),
            MemoryV1AuditAction::new("resource", "act").unwrap(),
            "reason",
            operation(),
            MemoryV1AuditRootObservation::new(root(1), [4; 32], MemoryV1AuditRootStatus::Serving),
        )
        .unwrap()
    }

    // memory—v1
    fn simple_change() -> MemoryV1AuditChange {
        MemoryV1AuditChange::new(
            Some(id(5)),
            Some(MemoryV1AuditObject::UserCard(id(6))),
            Some(MemoryV1AuditObject::Tenant(id(7))),
            Some(MemoryV1AuditChangeSummary::new(&[0, 0xff, 0x80]).unwrap()),
            Some(MemoryV1AuditObjectState::UserCard(
                MemoryV1AuditCardState::Active,
            )),
            Some(MemoryV1AuditObjectState::UserCard(
                MemoryV1AuditCardState::Disabled,
            )),
            Some(
                MemoryV1AuditConfirmations::references(&[
                    MemoryV1AuditConfirmationRef::Binding(id(8)),
                    MemoryV1AuditConfirmationRef::RuleSetChange(id(10)),
                ])
                .unwrap(),
            ),
            Some(root(1)),
            Some(root(2)),
            MemoryV1AuditSource::Ordinary,
        )
    }

    // memory—v1
    fn simple_t2_candidate() -> MemoryV1AuditT2EventCandidate {
        let item = MemoryV1AuditT2BatchItem::new(
            0,
            MemoryV1AuditTarget::Object(MemoryV1AuditObject::UserCard(id(6))),
            MemoryV1AuditTarget::Object(MemoryV1AuditObject::Tenant(id(7))),
            MemoryV1AuditObjectState::UserCard(MemoryV1AuditCardState::Active),
            MemoryV1AuditObjectState::UserCard(MemoryV1AuditCardState::Disabled),
            MemoryV1AuditConfirmationRef::Binding(id(8)),
            operation(),
        );
        let batch = MemoryV1AuditT2Batch::new(&[item], 1).unwrap();
        MemoryV1AuditT2EventCandidate::batch(
            context(),
            MemoryV1AuditDecisionInput::Allow,
            id(5),
            MemoryV1AuditChangeSummary::new(&[0, 0xff, 0x80]).unwrap(),
            root(1),
            root(2),
            MemoryV1AuditSource::Ordinary,
            batch,
        )
        .unwrap()
    }

    #[test]
    // memory—v1
    fn fixed_t1_deny_vector_is_independent_of_roundtrip() {
        // The bytes are a hand-authored vector for a T1 NoMatch DENY. It has
        // zero IDs, time/version zero, resource `r`, action `a`, reason `x`,
        // operation `op`, and the fixed hashes shown below.
        let expected = hex::decode(concat!(
            "414c4d314155440000010200000000a9",
            "00000000000000000000000000000000",
            "00000000000000000000000000000000",
            "0000000000000000",
            "0000000172",
            "0000000161",
            "0000000178",
            "000000026f70",
            "0303030303030303030303030303030303030303030303030303030303030303",
            "000000000000000000000000000000000000000000000000",
            "0505050505050505050505050505050505050505050505050505050505050505",
            "01",
            "02",
            "02",
            "00",
        ))
        .unwrap();
        let decoded = decode_deny_event(&expected).unwrap();
        assert_eq!(
            decoded.decision(),
            MemoryV1AuditDecision::Deny(MemoryV1AuditDenySource::NoMatch)
        );
        assert!(decoded.change_details().is_none());
        assert_eq!(encode_deny_event(&decoded).unwrap(), expected);
    }

    #[test]
    // memory—v1
    fn t2_allow_roundtrips_all_outer_fields_and_non_utf8_version_bytes() {
        let candidate = simple_t2_candidate();
        let wire = encode_t2_candidate(&candidate).unwrap();
        let decoded = decode_t2_candidate(&wire).unwrap();
        assert_eq!(decoded, candidate);
        assert_eq!(decoded.context().root().content_hash(), &[4; 32]);
        assert_eq!(decoded.root_before(), root(1));
        assert_eq!(decoded.root_after(), root(2));
        assert_eq!(decoded.change_summary().as_bytes(), &[0, 0xff, 0x80]);

        let version = [0, 0xff, 0x80, 1];
        let state = MemoryV1AuditObjectState::RuleSet(
            MemoryV1AuditRuleSetState::new_with_status(
                &version,
                [0xa5; 32],
                MemoryV1AuditRuleSetStatus::Active,
            )
            .unwrap(),
        );
        let change = MemoryV1AuditChange::new(
            None,
            None,
            None,
            None,
            Some(state.clone()),
            Some(state),
            None,
            None,
            None,
            MemoryV1AuditSource::Ordinary,
        );
        let event = MemoryV1AuditEvent::change(
            context(),
            MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::NoMatch),
            change,
        )
        .unwrap();
        let decoded = decode_deny_event(&encode_deny_event(&event).unwrap()).unwrap();
        assert_eq!(decoded, event);
        assert_eq!(
            decoded.change_details().unwrap().before().unwrap(),
            &MemoryV1AuditObjectState::RuleSet(
                MemoryV1AuditRuleSetState::new_with_status(
                    &version,
                    [0xa5; 32],
                    MemoryV1AuditRuleSetStatus::Active,
                )
                .unwrap(),
            )
        );
    }

    #[test]
    // memory—v1
    fn single_t2_allow_roundtrips_complete_object_change() {
        let event = MemoryV1AuditEvent::change(
            context(),
            MemoryV1AuditDecisionInput::Allow,
            simple_change(),
        )
        .unwrap();
        let candidate = MemoryV1AuditT2SingleChangeCandidate::try_from(event.clone()).unwrap();
        let wire = encode_t2_single_change_candidate(&candidate).unwrap();
        assert_eq!(wire[10], KIND_T2_SINGLE_ALLOW);
        let decoded = decode_t2_single_change_candidate(&wire).unwrap();
        assert_eq!(decoded.as_event(), &event);
        assert_eq!(decoded.target(), MemoryV1AuditObject::UserCard(id(6)));
        assert_eq!(decoded.scope(), MemoryV1AuditObject::Tenant(id(7)));
        assert_eq!(decoded.change_summary().as_bytes(), &[0, 0xff, 0x80]);
        assert_eq!(decoded.root_before(), root(1));
        assert_eq!(decoded.root_after(), root(2));
    }

    #[test]
    // memory—v1
    fn single_t2_rejects_truncation_tail_wrong_kind_and_non_allow() {
        let event = MemoryV1AuditEvent::change(
            context(),
            MemoryV1AuditDecisionInput::Allow,
            simple_change(),
        )
        .unwrap();
        let candidate = MemoryV1AuditT2SingleChangeCandidate::try_from(event).unwrap();
        let wire = encode_t2_single_change_candidate(&candidate).unwrap();
        for length in 0..wire.len() {
            assert!(
                decode_t2_single_change_candidate(&wire[..length]).is_err(),
                "accepted single T2 truncation {length}"
            );
        }
        let mut tail = wire.clone();
        tail.push(0);
        assert_eq!(
            decode_t2_single_change_candidate(&tail),
            Err(MemoryV1AuditWireError::InvalidLength)
        );
        let mut wrong_kind = wire.clone();
        wrong_kind[10] = KIND_T2_ALLOW;
        assert_eq!(
            decode_t2_single_change_candidate(&wrong_kind),
            Err(MemoryV1AuditWireError::InvalidEncoding)
        );

        let denied = MemoryV1AuditEvent::change(
            context(),
            MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::NoMatch),
            simple_change(),
        )
        .unwrap();
        assert_eq!(
            MemoryV1AuditT2SingleChangeCandidate::try_from(denied),
            Err(MemoryV1AuditError::WrongDecision)
        );
    }
    #[test]
    // memory—v1
    fn deny_preserves_t1_and_t2_partial_and_rejects_allow_entry() {
        let t1 = MemoryV1AuditEvent::read(
            context(),
            MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::RuleDeny),
        )
        .unwrap();
        let t1_decoded = decode_deny_event(&encode_deny_event(&t1).unwrap()).unwrap();
        assert!(t1_decoded.change_details().is_none());

        let partial = MemoryV1AuditEvent::change(
            context(),
            MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::ScopeDenied),
            MemoryV1AuditChange::new(
                None,
                Some(MemoryV1AuditObject::User(id(4))),
                None,
                None,
                None,
                None,
                Some(MemoryV1AuditConfirmations::not_applicable()),
                None,
                None,
                MemoryV1AuditSource::Ordinary,
            ),
        )
        .unwrap();
        let partial_decoded = decode_deny_event(&encode_deny_event(&partial).unwrap()).unwrap();
        assert_eq!(partial_decoded, partial);
        assert!(partial_decoded.change_details().is_some());

        assert_eq!(
            encode_deny_event(
                &MemoryV1AuditEvent::change(
                    context(),
                    MemoryV1AuditDecisionInput::Allow,
                    simple_change(),
                )
                .unwrap()
            ),
            Err(MemoryV1AuditWireError::WrongDecision)
        );
        let deny_candidate = MemoryV1AuditT2EventCandidate::batch(
            context(),
            MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::NoMatch),
            id(5),
            MemoryV1AuditChangeSummary::new(b"summary").unwrap(),
            root(1),
            root(2),
            MemoryV1AuditSource::Ordinary,
            match simple_t2_candidate().payload() {
                MemoryV1AuditT2EventPayload::Batch(batch) => batch.clone(),
                MemoryV1AuditT2EventPayload::Registry(_) => unreachable!(),
            },
        )
        .unwrap();
        assert_eq!(
            encode_t2_candidate(&deny_candidate),
            Err(MemoryV1AuditWireError::WrongDecision)
        );
    }

    #[test]
    // memory—v1
    fn every_deny_source_is_representable_or_explicitly_requires_t2_source() {
        let sources = [
            MemoryV1AuditDenySource::RuleDeny,
            MemoryV1AuditDenySource::NoMatch,
            MemoryV1AuditDenySource::ScopeDenied,
            MemoryV1AuditDenySource::CardUnbound,
            MemoryV1AuditDenySource::IdentityMismatch,
            MemoryV1AuditDenySource::UnregisteredResource,
            MemoryV1AuditDenySource::SelfConfirmation,
            MemoryV1AuditDenySource::CardDisabled,
        ];
        for source in sources {
            let event =
                MemoryV1AuditEvent::read(context(), MemoryV1AuditDecisionInput::Deny(source))
                    .unwrap();
            assert_eq!(
                decode_deny_event(&encode_deny_event(&event).unwrap()).unwrap(),
                event
            );
        }
        let overlay = MemoryV1AuditEvent::change(
            context(),
            MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::OverlayOnlyCreation),
            MemoryV1AuditChange::new(
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                MemoryV1AuditSource::OverlayOnlyCreation(MemoryV1AuditOverlayOnly::new(
                    id(1),
                    id(2),
                    id(3),
                )),
            ),
        )
        .unwrap();
        assert_eq!(
            decode_deny_event(&encode_deny_event(&overlay).unwrap()).unwrap(),
            overlay
        );
    }

    #[test]
    // memory—v1
    fn rejects_every_truncation_trailing_bytes_unknown_tags_and_bad_lengths() {
        let t2 = encode_t2_candidate(&simple_t2_candidate()).unwrap();
        for length in 0..t2.len() {
            assert!(
                decode_t2_candidate(&t2[..length]).is_err(),
                "accepted T2 truncation {length}"
            );
        }
        let deny = encode_deny_event(
            &MemoryV1AuditEvent::read(
                context(),
                MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::NoMatch),
            )
            .unwrap(),
        )
        .unwrap();
        for length in 0..deny.len() {
            assert!(
                decode_deny_event(&deny[..length]).is_err(),
                "accepted DENY truncation {length}"
            );
        }
        let mut trailing = deny.clone();
        trailing.push(0);
        assert_eq!(
            decode_deny_event(&trailing),
            Err(MemoryV1AuditWireError::InvalidLength)
        );

        let mut bad_magic = deny.clone();
        bad_magic[0] ^= 1;
        assert_eq!(
            decode_deny_event(&bad_magic),
            Err(MemoryV1AuditWireError::InvalidEncoding)
        );
        let mut bad_flags = deny.clone();
        bad_flags[11] = 1;
        assert_eq!(
            decode_deny_event(&bad_flags),
            Err(MemoryV1AuditWireError::InvalidEncoding)
        );
        let mut huge = deny.clone();
        huge[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            decode_deny_event(&huge),
            Err(MemoryV1AuditWireError::LimitExceeded)
        );
    }

    #[test]
    // memory—v1
    fn rejects_unknown_decision_option_and_enum_tags_without_allocating_unbounded_values() {
        let mut deny = encode_deny_event(
            &MemoryV1AuditEvent::read(
                context(),
                MemoryV1AuditDecisionInput::Deny(MemoryV1AuditDenySource::NoMatch),
            )
            .unwrap(),
        )
        .unwrap();
        // Context length is fixed for this fixture; decision tag follows it.
        // Locate it by decoding the context with the same bounded reader.
        let mut reader = Reader::new(&deny, KIND_DENY).unwrap();
        let _ = read_context(&mut reader).unwrap();
        let decision_offset = reader.offset;
        deny[decision_offset] = 0xff;
        assert_eq!(
            decode_deny_event(&deny),
            Err(MemoryV1AuditWireError::InvalidEncoding)
        );

        let mut candidate = encode_t2_candidate(&simple_t2_candidate()).unwrap();
        let mut reader = Reader::new(&candidate, KIND_T2_ALLOW).unwrap();
        let _ = read_context(&mut reader).unwrap();
        let decision_offset = reader.offset;
        candidate[decision_offset] = 0xff;
        assert_eq!(
            decode_t2_candidate(&candidate),
            Err(MemoryV1AuditWireError::InvalidEncoding)
        );
    }
}
