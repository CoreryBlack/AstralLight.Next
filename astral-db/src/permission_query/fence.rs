use std::collections::BTreeSet;

use astral_types::{PublicationSeal, PublicationStamp, PublishedCardAuthorization};
use time::PrimitiveDateTime;

use crate::authorization_projection_repository::AuthorizationEvidenceError;
use crate::DbError;

/// Card-scoped cache fence. A hit requires an exact publication set and pending bit.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CardScopeFenceSnapshot {
    pub manifest_versions: Vec<PermissionCacheManifestVersion>,
    /// Revocation-affecting source work not covered by the published evidence.
    pub card_source_pending: bool,
}

impl CardScopeFenceSnapshot {
    pub(crate) fn is_valid(&self) -> bool {
        self.manifest_versions
            .iter()
            .all(PermissionCacheManifestVersion::is_valid)
            && self.manifest_versions.windows(2).all(|pair| {
                (&pair[0].aggregate_type, pair[0].aggregate_id)
                    < (&pair[1].aggregate_type, pair[1].aggregate_id)
            })
    }
}

/// Compact publication identity plus the existing pointer and revocation fence.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionCacheManifestVersion {
    pub aggregate_type: String,
    pub aggregate_id: i64,
    pub manifest_id: i64,
    pub generation: u64,
    pub revoke_fence: u64,
    pub publication_stamp: PublicationStamp,
}

impl PermissionCacheManifestVersion {
    fn is_valid(&self) -> bool {
        !self.aggregate_type.is_empty()
            && self.aggregate_type.len() <= 32
            && self
                .aggregate_type
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            && self.aggregate_id > 0
            && self.manifest_id > 0
            && self.revoke_fence <= i64::MAX as u64
            && self.publication_stamp.validate().is_ok()
            && self.publication_stamp.generation == self.generation
    }
}

pub(crate) fn evidence_manifest_versions(
    evidence: &PublishedCardAuthorization,
) -> Result<Vec<PermissionCacheManifestVersion>, AuthorizationEvidenceError> {
    let mut versions = evidence
        .manifests
        .iter()
        .map(|manifest| {
            let publication_stamp = manifest.publication_stamp().map_err(|error| {
                AuthorizationEvidenceError::Corrupt(format!(
                    "code=permission_cache.invalid_publication_stamp;detail={error}"
                ))
            })?;
            let version = PermissionCacheManifestVersion {
                aggregate_type: manifest.aggregate_type.clone(),
                aggregate_id: manifest.aggregate_id,
                manifest_id: manifest.manifest_id,
                generation: manifest.generation,
                revoke_fence: manifest.revoke_fence,
                publication_stamp,
            };
            if !version.is_valid() {
                return Err(AuthorizationEvidenceError::Corrupt(
                    "code=permission_cache.invalid_manifest_identity".to_owned(),
                ));
            }
            Ok(version)
        })
        .collect::<Result<Vec<_>, _>>()?;
    versions.sort_by(|left, right| {
        left.aggregate_type
            .cmp(&right.aggregate_type)
            .then(left.aggregate_id.cmp(&right.aggregate_id))
    });
    if versions.windows(2).any(|pair| {
        pair[0].aggregate_type == pair[1].aggregate_type
            && pair[0].aggregate_id == pair[1].aggregate_id
    }) {
        return Err(AuthorizationEvidenceError::Corrupt(
            "code=permission_cache.duplicate_manifest_identity".to_owned(),
        ));
    }
    Ok(versions)
}

/// Only a strict, source-fresh read may establish a baseline with no pending work.
pub(crate) fn evidence_fence_baseline(
    evidence: &PublishedCardAuthorization,
) -> Result<CardScopeFenceSnapshot, AuthorizationEvidenceError> {
    Ok(CardScopeFenceSnapshot {
        manifest_versions: evidence_manifest_versions(evidence)?,
        card_source_pending: false,
    })
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct PointerFenceSqlRow {
    aggregate_type: String,
    aggregate_id: i64,
    manifest_id: i64,
    current_generation: i64,
    revoke_fence: i64,
    revoke_fence_proven: i64,
    current_status: String,
    joined_manifest_id: Option<i64>,
    manifest_generation: Option<i64>,
    manifest_digest: Option<Vec<u8>>,
    manifest_digest_version: Option<u16>,
    sealed_at: Option<PrimitiveDateTime>,
}

fn decode_pointer_fence_row(
    row: PointerFenceSqlRow,
) -> Result<PermissionCacheManifestVersion, DbError> {
    let invalid = |code: &str| DbError::Mapping(format!("code=permission_cache.{code}"));
    if row.current_status != "READY" || row.revoke_fence_proven != 1 {
        return Err(invalid("pointer_not_ready_or_unproven"));
    }
    if row.joined_manifest_id != Some(row.manifest_id) {
        return Err(invalid("pointer_manifest_missing_or_scope_mismatch"));
    }
    if row.manifest_generation != Some(row.current_generation) {
        return Err(invalid("pointer_manifest_generation_mismatch"));
    }
    let generation =
        u64::try_from(row.current_generation).map_err(|_| invalid("invalid_pointer_generation"))?;
    let revoke_fence =
        u64::try_from(row.revoke_fence).map_err(|_| invalid("invalid_pointer_revoke_fence"))?;
    let digest = row
        .manifest_digest
        .ok_or_else(|| invalid("manifest_digest_missing"))?;
    if digest.len() != 32 {
        return Err(invalid("manifest_digest_invalid_length"));
    }
    if row.manifest_digest_version != Some(PublicationSeal::DIGEST_VERSION) {
        return Err(invalid("manifest_digest_version_unsupported"));
    }
    let sealed_at = row
        .sealed_at
        .ok_or_else(|| invalid("manifest_seal_missing"))?;
    let seal = PublicationSeal::new(sealed_at.assume_utc())
        .map_err(|_| invalid("invalid_manifest_seal"))?;
    let publication_stamp = PublicationStamp::new(generation, hex::encode(digest), seal)
        .map_err(|_| invalid("invalid_publication_stamp"))?;
    let version = PermissionCacheManifestVersion {
        aggregate_type: row.aggregate_type,
        aggregate_id: row.aggregate_id,
        manifest_id: row.manifest_id,
        generation,
        revoke_fence,
        publication_stamp,
    };
    if !version.is_valid() {
        return Err(invalid("invalid_manifest_identity"));
    }
    Ok(version)
}

pub(super) fn decode_pointer_fence_rows(
    rows: Vec<PointerFenceSqlRow>,
) -> Result<Vec<PermissionCacheManifestVersion>, DbError> {
    let mut seen = BTreeSet::new();
    let mut versions = Vec::with_capacity(rows.len());
    for row in rows {
        if !seen.insert((row.aggregate_type.clone(), row.aggregate_id)) {
            return Err(DbError::Mapping(
                "code=permission_cache.duplicate_pointer_identity".to_owned(),
            ));
        }
        versions.push(decode_pointer_fence_row(row)?);
    }
    versions.sort_by(|left, right| {
        left.aggregate_type
            .cmp(&right.aggregate_type)
            .then(left.aggregate_id.cmp(&right.aggregate_id))
    });
    Ok(versions)
}

// A broken pointer must remain in the result and fail decoding, not disappear
// through an INNER JOIN or a manifest predicate in WHERE.
pub(super) const POINTER_FENCE_VERSIONS_SQL: &str =
    "SELECT c.aggregate_type, c.aggregate_id, c.manifest_id, \
     c.current_generation, c.revoke_fence, c.revoke_fence_proven, c.status AS current_status, \
     m.manifest_id AS joined_manifest_id, m.generation AS manifest_generation, \
     m.manifest_digest, m.manifest_digest_version, m.sealed_at \
     FROM authorization_projection_current AS c \
     LEFT JOIN authorization_projection_manifest AS m \
       ON m.manifest_id = c.manifest_id \
      AND m.tenant_id = c.tenant_id \
      AND m.card_id <=> c.card_id \
      AND m.aggregate_type = c.aggregate_type \
      AND m.aggregate_id = c.aggregate_id \
      AND m.generation = c.current_generation \
      AND m.revoke_fence = c.revoke_fence \
      AND m.event_id = c.event_id \
      AND m.operation_id = c.operation_id \
      AND m.semantic_hash = c.semantic_hash \
      AND m.dependency_hash = c.dependency_hash \
      AND m.compiler_version = c.compiler_version \
      AND m.status = 'COMMITTED' \
     WHERE c.tenant_id = ? AND c.card_id = ? \
     ORDER BY c.aggregate_type ASC, c.aggregate_id ASC";

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> PointerFenceSqlRow {
        let sealed_at = PublicationSeal::from_unix_seconds(1_700_000_000)
            .unwrap()
            .sealed_at();
        PointerFenceSqlRow {
            aggregate_type: "CARD".to_owned(),
            aggregate_id: 1,
            manifest_id: 9,
            current_generation: 7,
            revoke_fence: 3,
            revoke_fence_proven: 1,
            current_status: "READY".to_owned(),
            joined_manifest_id: Some(9),
            manifest_generation: Some(7),
            manifest_digest: Some(vec![0xab; 32]),
            manifest_digest_version: Some(PublicationSeal::DIGEST_VERSION),
            sealed_at: Some(PrimitiveDateTime::new(sealed_at.date(), sealed_at.time())),
        }
    }

    #[test]
    fn pointer_fence_rejects_missing_unproven_or_inconsistent_publication() {
        let baseline = decode_pointer_fence_row(row()).unwrap();
        assert_eq!(baseline.publication_stamp.generation, 7);
        assert_eq!(
            baseline.publication_stamp.manifest_digest_hex,
            "ab".repeat(32)
        );
        for dimension in 0..16 {
            let mut bad = row();
            match dimension {
                0 => bad.current_status = "BUILDING".to_owned(),
                1 => bad.revoke_fence_proven = 0,
                2 => bad.revoke_fence_proven = 2,
                3 => bad.joined_manifest_id = None,
                4 => bad.joined_manifest_id = Some(10),
                5 => bad.manifest_generation = Some(8),
                6 => bad.current_generation = 0,
                7 => bad.current_generation = -1,
                8 => bad.revoke_fence = -1,
                9 => bad.manifest_digest = None,
                10 => bad.manifest_digest = Some(vec![0; 31]),
                11 => bad.manifest_digest_version = Some(2),
                12 => bad.manifest_digest_version = None,
                13 => bad.sealed_at = None,
                14 => bad.aggregate_id = 0,
                15 => bad.manifest_id = 0,
                _ => unreachable!(),
            }
            assert!(
                decode_pointer_fence_row(bad).is_err(),
                "dimension={dimension}"
            );
        }
        assert!(decode_pointer_fence_rows(vec![row(), row()]).is_err());
    }

    #[test]
    fn same_generation_hash_and_time_changes_invalidate_fence_identity() {
        let baseline = decode_pointer_fence_row(row()).unwrap();
        let mut digest_drift = row();
        digest_drift.manifest_digest = Some(vec![0xcd; 32]);
        assert_ne!(baseline, decode_pointer_fence_row(digest_drift).unwrap());
        let mut time_drift = row();
        time_drift.sealed_at = time_drift
            .sealed_at
            .map(|time| time + time::Duration::seconds(1));
        assert_ne!(baseline, decode_pointer_fence_row(time_drift).unwrap());
        let mut disagreement = baseline.clone();
        disagreement.generation += 1;
        assert!(!disagreement.is_valid());
        let duplicate = CardScopeFenceSnapshot {
            manifest_versions: vec![baseline.clone(), baseline],
            card_source_pending: false,
        };
        assert!(!duplicate.is_valid());
    }

    #[test]
    fn pointer_join_preserves_broken_rows_and_covers_scope_and_provenance() {
        assert!(POINTER_FENCE_VERSIONS_SQL.contains("LEFT JOIN"));
        for predicate in [
            "m.card_id <=> c.card_id",
            "m.tenant_id = c.tenant_id",
            "m.aggregate_type = c.aggregate_type",
            "m.aggregate_id = c.aggregate_id",
            "m.generation = c.current_generation",
            "m.revoke_fence = c.revoke_fence",
            "m.event_id = c.event_id",
            "m.operation_id = c.operation_id",
            "m.semantic_hash = c.semantic_hash",
            "m.dependency_hash = c.dependency_hash",
            "m.compiler_version = c.compiler_version",
            "m.status = 'COMMITTED'",
        ] {
            assert!(
                POINTER_FENCE_VERSIONS_SQL.contains(predicate),
                "{predicate}"
            );
        }
        let (_, filters) = POINTER_FENCE_VERSIONS_SQL.split_once("WHERE ").unwrap();
        assert!(!filters.contains("m."));
    }
}
