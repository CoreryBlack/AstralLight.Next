//! Offline memory—v1 mutation value identifiers, with no admission or authority.
//!
//! This candidate encoding is local to this module, not an external protocol,
//! proof of provenance, freshness, confirmation validity, or authorization. It
//! does not execute a mutation. A digest cannot substitute for the policy engine,
//! a restricted commit, or any write gate. Equal values have equal digests even
//! across time; SHA-256 collision resistance is assumed, not guaranteed.
//!
//! The encoding uses a distinct domain and variant tags, fixed field order,
//! big-endian integers, presence tags, and u64 length-framed byte strings.
//! Batch count and order are significant, including duplicate rows. Input is
//! borrowed and streamed into SHA-256, without a copy proportional to its size.
//! Limits apply only to this candidate encoder, not to the underlying types or
//! business validity; callers already own the allocation of the input values.

use sha2::{Digest, Sha256};

use crate::memory_v1_db_rows::{
    BinaryId, BindingConfirmationRow, BindingLayer, BindingRow, RuleSetChangeConfirmationRow,
    RuleSetRow, RuleSetStatus, RuleSetVersionRow, UserCardStatus,
};
use crate::memory_v1_root::ManagementMutationV2;
use crate::memory_v1_rules::{MemoryV1OwnerScope, MemoryV1TenantScope};

const DOMAIN: &[u8] = b"astrallight/memory-v1/management-mutation-value/1\0";
/// Maximum length of one variable-length byte field, in bytes.
/// This includes canonical hash input, which can be larger than its content.
pub const MAX_FIELD_BYTES: usize = 2 * 1024 * 1024;
/// Maximum number of confirmation rows in a batch.
pub const MAX_BATCH_ROWS: usize = 128;
/// Maximum total encoded bytes, including domain, tags, lengths and counts.
pub const MAX_ENCODED_BYTES: usize = 16 * 1024 * 1024;

/// A candidate SHA-256 value identifier, without authorization semantics.
pub type MutationDigest = [u8; 32];

/// Failure to encode a mutation within the candidate's resource bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MutationDigestError {
    /// A length, count or accumulated size cannot be represented safely.
    LengthOverflow,
    /// A field, batch or total encoded size exceeds the candidate limit.
    LimitExceeded,
    /// A service-period context load is not a governed change and has no
    /// mutation-digest encoding; its facts live in the root snapshot digest.
    ContextLoadUnsupported,
}

struct Encoder {
    hash: Sha256,
    encoded_bytes: usize,
}

impl Encoder {
    // memory—v1: Stream bounded bytes without creating a serialized copy.
    fn write(&mut self, bytes: &[u8]) -> Result<(), MutationDigestError> {
        self.encoded_bytes = self
            .encoded_bytes
            .checked_add(bytes.len())
            .ok_or(MutationDigestError::LengthOverflow)?;
        if self.encoded_bytes > MAX_ENCODED_BYTES {
            return Err(MutationDigestError::LimitExceeded);
        }
        self.hash.update(bytes);
        Ok(())
    }

    // memory—v1: Encode a fixed one-byte tag.
    fn tag(&mut self, tag: u8) -> Result<(), MutationDigestError> {
        self.write(&[tag])
    }

    // memory—v1: Encode a count or byte length in the fixed width.
    fn count(&mut self, count: usize) -> Result<(), MutationDigestError> {
        let count = u64::try_from(count).map_err(|_| MutationDigestError::LengthOverflow)?;
        self.write(&count.to_be_bytes())
    }

    // memory—v1: Frame variable bytes and reject oversized input before hashing it.
    fn bytes(&mut self, bytes: &[u8]) -> Result<(), MutationDigestError> {
        if bytes.len() > MAX_FIELD_BYTES {
            return Err(MutationDigestError::LimitExceeded);
        }
        self.count(bytes.len())?;
        self.write(bytes)
    }

    // memory—v1: Encode an exact fixed-size identifier.
    fn id(&mut self, id: &BinaryId) -> Result<(), MutationDigestError> {
        self.write(id)
    }

    // memory—v1: Encode a signed timestamp, preserving the full i64 range.
    fn time(&mut self, time: i64) -> Result<(), MutationDigestError> {
        self.write(&time.to_be_bytes())
    }

    // memory—v1: Preserve absence independently from every present timestamp.
    fn optional_time(&mut self, time: Option<i64>) -> Result<(), MutationDigestError> {
        match time {
            None => self.tag(0),
            Some(value) => {
                self.tag(1)?;
                self.time(value)
            }
        }
    }

    // memory—v1: Preserve absence independently from every present identifier.
    fn optional_id(&mut self, id: &Option<BinaryId>) -> Result<(), MutationDigestError> {
        match id {
            None => self.tag(0),
            Some(value) => {
                self.tag(1)?;
                self.id(value)
            }
        }
    }

    // memory—v1: Bind all fields; exhaustive destructuring detects added fields.
    fn binding(&mut self, row: &BindingRow) -> Result<(), MutationDigestError> {
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
        self.tag(match binding_layer {
            BindingLayer::Base => 1,
            BindingLayer::Overlay => 2,
        })?;
        self.optional_time(*valid_from)?;
        self.optional_time(*valid_until)?;
        self.tag(match owner_scope {
            MemoryV1OwnerScope::SelfUser => 1,
            MemoryV1OwnerScope::AllUsers => 2,
        })?;
        self.tag(match tenant_scope {
            MemoryV1TenantScope::SelfTenant => 1,
            MemoryV1TenantScope::SelfAndDescendants => 2,
        })?;
        self.optional_time(*removed_at)?;
        self.optional_id(removed_by)
    }

    // memory—v1: Bind the complete supplied binding confirmation.
    fn confirmation(&mut self, row: &BindingConfirmationRow) -> Result<(), MutationDigestError> {
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
        self.bytes(version_bytes)?;
        self.id(confirmer_user_id)?;
        self.bytes(scope_bytes)?;
        self.bytes(operation_id)?;
        self.bytes(confirmed_at_bytes)?;
        self.optional_time(*revoked_at)?;
        self.optional_id(revoked_by)
    }

    // memory—v1: Bind the complete supplied rule set and explicit current version.
    fn rule_set(&mut self, row: &RuleSetRow) -> Result<(), MutationDigestError> {
        let RuleSetRow {
            rule_set_id,
            owner_tenant_id,
            current_version_bytes,
            status,
        } = row;
        self.id(rule_set_id)?;
        self.id(owner_tenant_id)?;
        self.bytes(current_version_bytes)?;
        self.tag(match status {
            RuleSetStatus::Active => 1,
            RuleSetStatus::Retired => 2,
        })
    }

    // memory—v1: Bind all version data, including purported hash input and hash.
    fn version(&mut self, row: &RuleSetVersionRow) -> Result<(), MutationDigestError> {
        let RuleSetVersionRow {
            rule_set_id,
            version_bytes,
            content_bytes,
            timestamp_bytes,
            hash_input_bytes,
            hash_bytes,
        } = row;
        self.id(rule_set_id)?;
        self.bytes(version_bytes)?;
        self.bytes(content_bytes)?;
        self.bytes(timestamp_bytes)?;
        self.bytes(hash_input_bytes)?;
        self.bytes(hash_bytes)
    }

    // memory—v1: Bind the complete supplied rule-set change confirmation.
    fn change_confirmation(
        &mut self,
        row: &RuleSetChangeConfirmationRow,
    ) -> Result<(), MutationDigestError> {
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
        self.bytes(version_bytes)?;
        self.id(confirmer_user_id)?;
        self.bytes(affected_scope_bytes)?;
        self.bytes(operation_id)?;
        self.bytes(confirmed_at_bytes)?;
        self.optional_time(*revoked_at)?;
        self.optional_id(revoked_by)
    }
}

/// memory—v1: Hash every field of the exact candidate mutation in a local domain.
///
/// Returns an error if a candidate limit or a length conversion is exceeded.
/// This value identifier is neither admission nor authorization and is not a
/// restricted-commit capability or an external wire protocol.
pub fn digest_mutation(
    mutation: &ManagementMutationV2,
) -> Result<MutationDigest, MutationDigestError> {
    let mut encoder = Encoder {
        hash: Sha256::new(),
        encoded_bytes: 0,
    };
    encoder.write(DOMAIN)?;
    match mutation {
        ManagementMutationV2::BindingCreate { row, confirmation } => {
            encoder.tag(1)?;
            encoder.binding(row)?;
            encoder.confirmation(confirmation)?;
        }
        ManagementMutationV2::BindingRemove {
            binding_id,
            removed_at,
            removed_by,
        } => {
            encoder.tag(2)?;
            encoder.id(binding_id)?;
            encoder.time(*removed_at)?;
            encoder.id(removed_by)?;
        }
        ManagementMutationV2::ConfirmationCreate { row } => {
            encoder.tag(3)?;
            encoder.confirmation(row)?;
        }
        ManagementMutationV2::ConfirmationRevoke {
            confirmation_id,
            revoked_at,
            revoked_by,
        } => {
            encoder.tag(4)?;
            encoder.id(confirmation_id)?;
            encoder.time(*revoked_at)?;
            encoder.id(revoked_by)?;
        }
        ManagementMutationV2::RuleSetChangeConfirmationRevoke {
            confirmation_id,
            revoked_at,
            revoked_by,
        } => {
            encoder.tag(9)?;
            encoder.id(confirmation_id)?;
            encoder.time(*revoked_at)?;
            encoder.id(revoked_by)?;
        }
        ManagementMutationV2::ConfirmationBatch { rows } => {
            encoder.tag(5)?;
            if rows.len() > MAX_BATCH_ROWS {
                return Err(MutationDigestError::LimitExceeded);
            }
            encoder.count(rows.len())?;
            for row in rows {
                encoder.confirmation(row)?;
            }
        }
        ManagementMutationV2::UserCardCreate { row } => {
            // Destructure the complete row so added fields require an encoding decision.
            let crate::memory_v1_db_rows::UserCardRow {
                user_card_id,
                user_id,
                tenant_id,
                status,
            } = row;
            encoder.tag(11)?;
            encoder.id(user_card_id)?;
            encoder.id(user_id)?;
            encoder.id(tenant_id)?;
            encoder.tag(match status {
                UserCardStatus::Active => 1,
                UserCardStatus::Disabled => 2,
            })?;
        }
        ManagementMutationV2::UserCardStatus {
            user_card_id,
            status,
        } => {
            encoder.tag(6)?;
            encoder.id(user_card_id)?;
            encoder.tag(match status {
                UserCardStatus::Active => 1,
                UserCardStatus::Disabled => 2,
            })?;
        }
        ManagementMutationV2::RuleSetCreate {
            rule_set,
            version,
            change_confirmation,
        } => {
            encoder.tag(7)?;
            encoder.rule_set(rule_set)?;
            encoder.version(version)?;
            encoder.change_confirmation(change_confirmation)?;
        }
        ManagementMutationV2::RuleSetRetire { rule_set_id } => {
            encoder.tag(10)?;
            encoder.id(rule_set_id)?;
        }
        ManagementMutationV2::VersionPublish {
            rule_set_id,
            version_row,
            new_current_version,
            change_confirmation,
        } => {
            encoder.tag(8)?;
            encoder.id(rule_set_id)?;
            encoder.version(version_row)?;
            encoder.bytes(new_current_version)?;
            encoder.change_confirmation(change_confirmation)?;
        }
        // memory—v1 §15.10.3: A context load carries snapshot facts, not an
        // ordered governed change; it has no mutation-digest encoding.
        ManagementMutationV2::ContextLoad { .. } => {
            return Err(MutationDigestError::ContextLoadUnsupported);
        }
    }
    Ok(encoder.hash.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    // memory—v1: Build a row with distinct values so each field can be varied.
    fn binding() -> BindingRow {
        BindingRow {
            binding_id: [1; 16],
            user_card_id: [2; 16],
            rule_set_id: [3; 16],
            binding_layer: BindingLayer::Base,
            valid_from: Some(-1),
            valid_until: Some(1),
            owner_scope: MemoryV1OwnerScope::SelfUser,
            tenant_scope: MemoryV1TenantScope::SelfTenant,
            removed_at: Some(2),
            removed_by: Some([4; 16]),
        }
    }

    // memory—v1: Build an opaque binary confirmation fixture.
    fn confirmation() -> BindingConfirmationRow {
        BindingConfirmationRow {
            confirmation_id: [5; 16],
            binding_id: [6; 16],
            rule_set_id: [7; 16],
            version_bytes: vec![0, 1],
            confirmer_user_id: [8; 16],
            scope_bytes: vec![0, 2],
            operation_id: vec![0, 3],
            confirmed_at_bytes: vec![0, 4],
            revoked_at: Some(-2),
            revoked_by: Some([9; 16]),
        }
    }

    // memory—v1: Build a rule-set fixture.
    fn rule_set() -> RuleSetRow {
        RuleSetRow {
            rule_set_id: [10; 16],
            owner_tenant_id: [11; 16],
            current_version_bytes: vec![0, 5],
            status: RuleSetStatus::Active,
        }
    }

    // memory—v1: Build a version with independent opaque fields.
    fn version() -> RuleSetVersionRow {
        RuleSetVersionRow {
            rule_set_id: [12; 16],
            version_bytes: vec![0, 6],
            content_bytes: vec![0, 7],
            timestamp_bytes: vec![0, 8],
            hash_input_bytes: vec![0, 9],
            hash_bytes: vec![0, 10],
        }
    }

    // memory—v1: Build a change-confirmation fixture.
    fn change_confirmation() -> RuleSetChangeConfirmationRow {
        RuleSetChangeConfirmationRow {
            confirmation_id: [13; 16],
            rule_set_id: [14; 16],
            version_bytes: vec![0, 11],
            confirmer_user_id: [15; 16],
            affected_scope_bytes: vec![0, 12],
            operation_id: vec![0, 13],
            confirmed_at_bytes: vec![0, 14],
            revoked_at: Some(3),
            revoked_by: Some([16; 16]),
        }
    }

    // memory—v1: Compare each single-field mutation to its unchanged fixture.
    macro_rules! assert_fields_change {
        ($base:expr, $($change:expr),+ $(,)?) => {{
            let original = $base;
            let expected = digest_mutation(&original).unwrap();
            $(
                let mut changed = original.clone();
                ($change)(&mut changed);
                assert_ne!(digest_mutation(&changed).unwrap(), expected, "{}", stringify!($change));
            )+
        }};
    }

    #[test]
    // memory—v1: Each user-card field is part of the mutation value.
    fn user_card_create_digest_binds_every_field() {
        let base = ManagementMutationV2::UserCardCreate {
            row: crate::memory_v1_db_rows::UserCardRow {
                user_card_id: [1; 16],
                user_id: [2; 16],
                tenant_id: [3; 16],
                status: UserCardStatus::Active,
            },
        };
        assert_fields_change!(
            base,
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::UserCardCreate { row } = m {
                row.user_card_id[0] ^= 1
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::UserCardCreate { row } = m {
                row.user_id[0] ^= 1
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::UserCardCreate { row } = m {
                row.tenant_id[0] ^= 1
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::UserCardCreate { row } = m {
                row.status = UserCardStatus::Disabled
            },
        );
    }

    // memory—v1: Verify every binding and confirmation field affects the value.
    #[test]
    fn binding_and_confirmation_fields_are_bound() {
        let base = ManagementMutationV2::BindingCreate {
            row: binding(),
            confirmation: confirmation(),
        };
        assert_fields_change!(
            base,
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingCreate {
                row, ..
            } = m
            {
                row.binding_id[0] ^= 1
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingCreate {
                row, ..
            } = m
            {
                row.user_card_id[0] ^= 1
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingCreate {
                row, ..
            } = m
            {
                row.rule_set_id[0] ^= 1
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingCreate {
                row, ..
            } = m
            {
                row.binding_layer = BindingLayer::Overlay
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingCreate {
                row, ..
            } = m
            {
                row.valid_from = Some(0)
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingCreate {
                row, ..
            } = m
            {
                row.valid_until = Some(0)
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingCreate {
                row, ..
            } = m
            {
                row.owner_scope = MemoryV1OwnerScope::AllUsers
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingCreate {
                row, ..
            } = m
            {
                row.tenant_scope = MemoryV1TenantScope::SelfAndDescendants
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingCreate {
                row, ..
            } = m
            {
                row.removed_at = Some(0)
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingCreate {
                row, ..
            } = m
            {
                row.removed_by = Some([0; 16])
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingCreate {
                confirmation,
                ..
            } = m
            {
                confirmation.confirmation_id[0] ^= 1
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingCreate {
                confirmation,
                ..
            } = m
            {
                confirmation.binding_id[0] ^= 1
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingCreate {
                confirmation,
                ..
            } = m
            {
                confirmation.rule_set_id[0] ^= 1
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingCreate {
                confirmation,
                ..
            } = m
            {
                confirmation.version_bytes.push(0)
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingCreate {
                confirmation,
                ..
            } = m
            {
                confirmation.confirmer_user_id[0] ^= 1
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingCreate {
                confirmation,
                ..
            } = m
            {
                confirmation.scope_bytes.push(0)
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingCreate {
                confirmation,
                ..
            } = m
            {
                confirmation.operation_id.push(0)
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingCreate {
                confirmation,
                ..
            } = m
            {
                confirmation.confirmed_at_bytes.push(0)
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingCreate {
                confirmation,
                ..
            } = m
            {
                confirmation.revoked_at = Some(0)
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingCreate {
                confirmation,
                ..
            } = m
            {
                confirmation.revoked_by = Some([0; 16])
            },
        );
    }

    // memory—v1: Verify rule-set, version and change-confirmation field coverage.
    #[test]
    fn rule_set_version_and_change_confirmation_fields_are_bound() {
        let base = ManagementMutationV2::RuleSetCreate {
            rule_set: rule_set(),
            version: version(),
            change_confirmation: change_confirmation(),
        };
        assert_fields_change!(
            base,
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::RuleSetCreate {
                rule_set,
                ..
            } = m
            {
                rule_set.rule_set_id[0] ^= 1
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::RuleSetCreate {
                rule_set,
                ..
            } = m
            {
                rule_set.owner_tenant_id[0] ^= 1
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::RuleSetCreate {
                rule_set,
                ..
            } = m
            {
                rule_set.current_version_bytes.push(0)
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::RuleSetCreate {
                version,
                ..
            } = m
            {
                version.rule_set_id[0] ^= 1
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::RuleSetCreate {
                version,
                ..
            } = m
            {
                version.version_bytes.push(0)
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::RuleSetCreate {
                version,
                ..
            } = m
            {
                version.content_bytes.push(0)
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::RuleSetCreate {
                version,
                ..
            } = m
            {
                version.timestamp_bytes.push(0)
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::RuleSetCreate {
                version,
                ..
            } = m
            {
                version.hash_input_bytes.push(0)
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::RuleSetCreate {
                version,
                ..
            } = m
            {
                version.hash_bytes.push(0)
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::RuleSetCreate {
                change_confirmation,
                ..
            } = m
            {
                change_confirmation.confirmation_id[0] ^= 1
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::RuleSetCreate {
                change_confirmation,
                ..
            } = m
            {
                change_confirmation.rule_set_id[0] ^= 1
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::RuleSetCreate {
                change_confirmation,
                ..
            } = m
            {
                change_confirmation.version_bytes.push(0)
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::RuleSetCreate {
                change_confirmation,
                ..
            } = m
            {
                change_confirmation.confirmer_user_id[0] ^= 1
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::RuleSetCreate {
                change_confirmation,
                ..
            } = m
            {
                change_confirmation.affected_scope_bytes.push(0)
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::RuleSetCreate {
                change_confirmation,
                ..
            } = m
            {
                change_confirmation.operation_id.push(0)
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::RuleSetCreate {
                change_confirmation,
                ..
            } = m
            {
                change_confirmation.confirmed_at_bytes.push(0)
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::RuleSetCreate {
                change_confirmation,
                ..
            } = m
            {
                change_confirmation.revoked_at = Some(0)
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::RuleSetCreate {
                change_confirmation,
                ..
            } = m
            {
                change_confirmation.revoked_by = Some([0; 16])
            },
        );
    }

    // memory—v1: Exercise the remaining variant-specific fields and full i64 range.
    #[test]
    fn remaining_variant_fields_are_bound() {
        assert_fields_change!(
            ManagementMutationV2::BindingRemove {
                binding_id: [0; 16],
                removed_at: i64::MIN,
                removed_by: [0; 16]
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingRemove {
                binding_id,
                ..
            } = m
            {
                binding_id[0] = 1
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingRemove {
                removed_at,
                ..
            } = m
            {
                *removed_at = i64::MAX
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::BindingRemove {
                removed_by,
                ..
            } = m
            {
                removed_by[0] = 1
            },
        );
        assert_fields_change!(
            ManagementMutationV2::ConfirmationRevoke {
                confirmation_id: [0; 16],
                revoked_at: i64::MIN,
                revoked_by: [0; 16]
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::ConfirmationRevoke {
                confirmation_id,
                ..
            } = m
            {
                confirmation_id[0] = 1
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::ConfirmationRevoke {
                revoked_at,
                ..
            } = m
            {
                *revoked_at = i64::MAX
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::ConfirmationRevoke {
                revoked_by,
                ..
            } = m
            {
                revoked_by[0] = 1
            },
        );
        assert_fields_change!(
            ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                confirmation_id: [0; 16],
                revoked_at: i64::MIN,
                revoked_by: [0; 16]
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                    confirmation_id,
                    ..
                } = m
                {
                    confirmation_id[0] = 1
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                    revoked_at, ..
                } = m
                {
                    *revoked_at = i64::MAX
                }
            },
            |m: &mut ManagementMutationV2| {
                if let ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                    revoked_by, ..
                } = m
                {
                    revoked_by[0] = 1
                }
            },
        );
        assert_fields_change!(
            ManagementMutationV2::UserCardStatus {
                user_card_id: [0; 16],
                status: UserCardStatus::Active
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::UserCardStatus {
                user_card_id,
                ..
            } = m
            {
                user_card_id[0] = 1
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::UserCardStatus {
                status,
                ..
            } = m
            {
                *status = UserCardStatus::Disabled
            },
        );
        assert_fields_change!(
            ManagementMutationV2::VersionPublish {
                rule_set_id: [0; 16],
                version_row: version(),
                new_current_version: vec![0],
                change_confirmation: change_confirmation()
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::VersionPublish {
                rule_set_id,
                ..
            } = m
            {
                rule_set_id[0] = 1
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::VersionPublish {
                version_row,
                ..
            } = m
            {
                version_row.content_bytes.push(0)
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::VersionPublish {
                new_current_version,
                ..
            } = m
            {
                new_current_version.push(0)
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::VersionPublish {
                change_confirmation,
                ..
            } = m
            {
                change_confirmation.affected_scope_bytes.push(0)
            },
        );
        assert_fields_change!(
            ManagementMutationV2::ConfirmationCreate {
                row: confirmation()
            },
            |m: &mut ManagementMutationV2| if let ManagementMutationV2::ConfirmationCreate { row } =
                m
            {
                row.scope_bytes.push(0)
            },
        );
    }

    // memory—v1: Compare absent, empty, zero, and ambiguous unframed sequences.
    #[test]
    fn optional_values_and_byte_framing_are_distinct() {
        let mut row = binding();
        row.valid_from = None;
        row.removed_by = None;
        let make = |row: BindingRow| ManagementMutationV2::BindingCreate {
            row,
            confirmation: confirmation(),
        };
        let absent = digest_mutation(&make(row.clone())).unwrap();
        row.valid_from = Some(0);
        assert_ne!(absent, digest_mutation(&make(row.clone())).unwrap());
        row.valid_from = None;
        row.removed_by = Some([0; 16]);
        assert_ne!(absent, digest_mutation(&make(row)).unwrap());

        let mut row = confirmation();
        row.revoked_at = None;
        row.revoked_by = None;
        let make = |row: BindingConfirmationRow| ManagementMutationV2::ConfirmationCreate { row };
        let absent = digest_mutation(&make(row.clone())).unwrap();
        row.revoked_at = Some(0);
        assert_ne!(absent, digest_mutation(&make(row.clone())).unwrap());
        row.revoked_at = None;
        row.revoked_by = Some([0; 16]);
        assert_ne!(absent, digest_mutation(&make(row.clone())).unwrap());
        row.version_bytes = vec![1];
        row.scope_bytes = vec![2, 3];
        let first = digest_mutation(&make(row.clone())).unwrap();
        row.version_bytes = vec![1, 2];
        row.scope_bytes = vec![3];
        assert_ne!(first, digest_mutation(&make(row)).unwrap());

        // The public rows contain no Option<Vec<u8>>. Test presence framing on
        // the actual optional fixed-size identifier and zero timestamp above.
        let mut row = version();
        row.version_bytes.clear();
        let empty = ManagementMutationV2::VersionPublish {
            rule_set_id: [0; 16],
            version_row: row.clone(),
            new_current_version: vec![],
            change_confirmation: change_confirmation(),
        };
        row.version_bytes.push(0);
        let nonempty = ManagementMutationV2::VersionPublish {
            rule_set_id: [0; 16],
            version_row: row,
            new_current_version: vec![],
            change_confirmation: change_confirmation(),
        };
        assert_ne!(
            digest_mutation(&empty).unwrap(),
            digest_mutation(&nonempty).unwrap()
        );
    }

    // memory—v1: Check all public variants and ordered, duplicate-preserving batches.
    #[test]
    fn variants_batches_and_determinism() {
        let a = confirmation();
        let mut b = a.clone();
        b.confirmation_id[0] ^= 1;
        let mutations = vec![
            ManagementMutationV2::BindingCreate {
                row: binding(),
                confirmation: a.clone(),
            },
            ManagementMutationV2::BindingRemove {
                binding_id: [0; 16],
                removed_at: 0,
                removed_by: [0; 16],
            },
            ManagementMutationV2::ConfirmationCreate { row: a.clone() },
            ManagementMutationV2::ConfirmationRevoke {
                confirmation_id: [0; 16],
                revoked_at: 0,
                revoked_by: [0; 16],
            },
            ManagementMutationV2::RuleSetChangeConfirmationRevoke {
                confirmation_id: [0; 16],
                revoked_at: 0,
                revoked_by: [0; 16],
            },
            ManagementMutationV2::ConfirmationBatch {
                rows: vec![a.clone()],
            },
            ManagementMutationV2::UserCardStatus {
                user_card_id: [0; 16],
                status: UserCardStatus::Active,
            },
            ManagementMutationV2::RuleSetCreate {
                rule_set: rule_set(),
                version: version(),
                change_confirmation: change_confirmation(),
            },
            ManagementMutationV2::RuleSetRetire {
                rule_set_id: [0; 16],
            },
            ManagementMutationV2::VersionPublish {
                rule_set_id: [0; 16],
                version_row: version(),
                new_current_version: vec![],
                change_confirmation: change_confirmation(),
            },
        ];
        let mut values = BTreeSet::new();
        for mutation in &mutations {
            let digest: MutationDigest = digest_mutation(mutation).unwrap();
            assert_eq!(digest, digest_mutation(&mutation.clone()).unwrap());
            assert!(values.insert(digest));
        }
        let hash =
            |rows| digest_mutation(&ManagementMutationV2::ConfirmationBatch { rows }).unwrap();
        assert_ne!(hash(vec![a.clone(), b.clone()]), hash(vec![b, a.clone()]));
        assert_ne!(hash(vec![a.clone()]), hash(vec![a.clone(), a]));
        assert_ne!(hash(vec![]), hash(vec![confirmation()]));
    }

    #[test]
    // memory—v1: Retirement binds its exact target and creation binds status.
    fn retirement_target_and_rule_set_status_are_hashed() {
        let first = ManagementMutationV2::RuleSetRetire {
            rule_set_id: [1; 16],
        };
        let second = ManagementMutationV2::RuleSetRetire {
            rule_set_id: [2; 16],
        };
        assert_ne!(
            digest_mutation(&first).unwrap(),
            digest_mutation(&second).unwrap()
        );
        let mut row = rule_set();
        let active = ManagementMutationV2::RuleSetCreate {
            rule_set: row.clone(),
            version: version(),
            change_confirmation: change_confirmation(),
        };
        row.status = RuleSetStatus::Retired;
        let retired = ManagementMutationV2::RuleSetCreate {
            rule_set: row,
            version: version(),
            change_confirmation: change_confirmation(),
        };
        assert_ne!(
            digest_mutation(&active).unwrap(),
            digest_mutation(&retired).unwrap()
        );
    }

    // memory—v1: Validate successful boundaries, public errors and checked totals.
    #[test]
    fn limits_and_public_result() {
        let mut row = confirmation();
        row.version_bytes = vec![7; MAX_FIELD_BYTES];
        assert!(
            digest_mutation(&ManagementMutationV2::ConfirmationCreate { row: row.clone() }).is_ok()
        );
        row.version_bytes.push(7);
        assert_eq!(
            digest_mutation(&ManagementMutationV2::ConfirmationCreate { row: row.clone() }),
            Err(MutationDigestError::LimitExceeded)
        );
        row.version_bytes.clear();
        assert!(digest_mutation(&ManagementMutationV2::ConfirmationBatch {
            rows: vec![row.clone(); MAX_BATCH_ROWS]
        })
        .is_ok());
        assert_eq!(
            digest_mutation(&ManagementMutationV2::ConfirmationBatch {
                rows: vec![row.clone(); MAX_BATCH_ROWS + 1]
            }),
            Err(MutationDigestError::LimitExceeded)
        );
        row.version_bytes = vec![7; MAX_FIELD_BYTES];
        assert_eq!(
            digest_mutation(&ManagementMutationV2::ConfirmationBatch {
                rows: vec![row; 16]
            }),
            Err(MutationDigestError::LimitExceeded)
        );
        let mut encoder = Encoder {
            hash: Sha256::new(),
            encoded_bytes: usize::MAX,
        };
        assert_eq!(
            encoder.write(&[1]),
            Err(MutationDigestError::LengthOverflow)
        );
        let mut encoder = Encoder {
            hash: Sha256::new(),
            encoded_bytes: MAX_ENCODED_BYTES - 1,
        };
        assert_eq!(encoder.write(&[1]), Ok(()));
        assert_eq!(encoder.write(&[1]), Err(MutationDigestError::LimitExceeded));
    }

    // memory—v1: Include canonical overhead for a maximum-size governance content field.
    #[test]
    fn digest_accepts_governance_content_and_its_canonical_hash_input() {
        let mut version = version();
        version.content_bytes = vec![b'x'; 1024 * 1024];
        version.hash_input_bytes = crate::memory_v1_rules::canonical_version_bytes(
            &version.version_bytes,
            &version.content_bytes,
            &version.timestamp_bytes,
        );
        version.hash_bytes = crate::memory_v1_rules::version_digest(&version.hash_input_bytes);
        assert!(version.hash_input_bytes.len() > version.content_bytes.len());
        let mutation = ManagementMutationV2::RuleSetCreate {
            rule_set: rule_set(),
            version,
            change_confirmation: change_confirmation(),
        };
        assert!(digest_mutation(&mutation).is_ok());
    }

    // memory—v1: Verify the public digest against independently assembled bytes.
    #[test]
    fn public_digest_matches_framed_sha256() {
        let mutation = ManagementMutationV2::BindingRemove {
            binding_id: [1; 16],
            removed_at: -1,
            removed_by: [2; 16],
        };
        let mut hash = Sha256::new();
        hash.update(b"astrallight/memory-v1/management-mutation-value/1\0");
        hash.update([2]);
        hash.update([1; 16]);
        hash.update((-1_i64).to_be_bytes());
        hash.update([2; 16]);
        let expected: [u8; 32] = hash.finalize().into();
        assert_eq!(digest_mutation(&mutation), Ok(expected));
    }
}
