use astral_types::{PublicationSeal, AUTHORIZATION_MANIFEST_DIGEST_DOMAIN};

use super::{
    bind_u64, positive_i64, scope_violation, sha256_digest_bytes, AuthorizationProjectionError,
    AuthorizationStageRequest, ManifestRawSqlRow, Sha256Digest, MANIFEST_STATUS_BUILDING,
};

/// Immutable current-edition publication evidence, including the ordered content commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestDigestInput<'a> {
    pub tenant_id: i64,
    pub aggregate_type: &'a str,
    pub aggregate_id: i64,
    pub card_id: Option<i64>,
    pub generation: u64,
    pub source_generation: u64,
    pub projected_generation: u64,
    pub event_id: &'a str,
    pub operation_id: &'a str,
    pub semantic_hash_hex: &'a str,
    pub dependency_hash_hex: &'a str,
    pub compiler_version: &'a str,
    /// Absent only for the first generation.
    pub parent_manifest_id: Option<i64>,
    pub revoke_fence: u64,
    /// First durable candidate seal; retries retain the stored value.
    pub seal: PublicationSeal,
    pub segment_content_digests_hex: Vec<String>,
}

pub(super) fn verify_staged_candidate(
    row: &ManifestRawSqlRow,
    request: &AuthorizationStageRequest,
    parent_manifest_id: Option<i64>,
    ordered_digests: Vec<String>,
) -> Result<(PublicationSeal, Sha256Digest), AuthorizationProjectionError> {
    let seal = row.decode_seal()?;
    let expected = compute_manifest_digest(&ManifestDigestInput {
        tenant_id: request.identity.tenant_id,
        aggregate_type: &request.identity.aggregate_type,
        aggregate_id: request.identity.aggregate_id,
        card_id: request.card_id,
        generation: request.target_generation,
        source_generation: request.source_generation,
        projected_generation: request.projected_generation,
        event_id: &request.event_id,
        operation_id: &request.operation_id,
        semantic_hash_hex: &request.semantic_hash_hex,
        dependency_hash_hex: &request.dependency_hash_hex,
        compiler_version: &request.compiler_version,
        parent_manifest_id,
        revoke_fence: request.revoke_fence,
        seal,
        segment_content_digests_hex: ordered_digests.clone(),
    })?;
    let (semantic_hash, dependency_hash, stored_digest) = row.decode_hashes()?;
    let identical = row.decode_identity()? == request.identity
        && row.card_id == request.card_id
        && row.decode_generations()?
            == (
                request.target_generation,
                request.source_generation,
                request.projected_generation,
            )
        && row.event_id == request.event_id
        && row.operation_id == request.operation_id
        && semantic_hash == Sha256Digest::from_hex(&request.semantic_hash_hex)?
        && dependency_hash == Sha256Digest::from_hex(&request.dependency_hash_hex)?
        && row.compiler_version == request.compiler_version
        && row.decode_parent_manifest_id()? == parent_manifest_id
        && row.decode_revoke_fence()? == request.revoke_fence
        && row.status == MANIFEST_STATUS_BUILDING
        && row.recomputed_digest(ordered_digests)? == expected
        && stored_digest == expected;
    if !identical {
        return Err(AuthorizationProjectionError::DuplicateRow(
            "code=authorization_projection.manifest_identity_conflict".to_owned(),
        ));
    }
    Ok((seal, expected))
}

fn append_text(material: &mut Vec<u8>, value: &str) -> Result<(), AuthorizationProjectionError> {
    if !value.is_ascii() {
        return Err(scope_violation(
            "authorization_projection.non_ascii_manifest_digest_field",
        ));
    }
    let length = u32::try_from(value.len())
        .map_err(|_| scope_violation("authorization_projection.manifest_digest_field_too_long"))?;
    material.extend_from_slice(&length.to_be_bytes());
    material.extend_from_slice(value.as_bytes());
    Ok(())
}

fn append_optional_id(
    material: &mut Vec<u8>,
    value: Option<i64>,
    field: &'static str,
) -> Result<(), AuthorizationProjectionError> {
    match value {
        None => material.push(0),
        Some(value) => {
            positive_i64(value, field)?;
            material.push(1);
            material.extend_from_slice(&value.to_be_bytes());
        }
    }
    Ok(())
}

/// Seal the current-edition publication evidence using fixed-width counters and length-prefixed text.
///
/// UTC seal seconds participate in the manifest commitment, never in immutable
/// segment content addressing. This function has no clock or I/O dependency.
pub fn compute_manifest_digest(
    input: &ManifestDigestInput<'_>,
) -> Result<Sha256Digest, AuthorizationProjectionError> {
    if !input.event_id.is_ascii() || !input.operation_id.is_ascii() {
        return Err(scope_violation(
            "authorization_projection.non_ascii_provenance_digest_field",
        ));
    }
    let mut material = Vec::with_capacity(300);
    material.extend_from_slice(AUTHORIZATION_MANIFEST_DIGEST_DOMAIN);
    material.extend_from_slice(&PublicationSeal::DIGEST_VERSION.to_be_bytes());
    material.extend_from_slice(&input.seal.unix_seconds().to_be_bytes());
    material.extend_from_slice(&input.tenant_id.to_be_bytes());
    append_text(&mut material, input.aggregate_type)?;
    material.extend_from_slice(&input.aggregate_id.to_be_bytes());
    append_optional_id(&mut material, input.card_id, "card_id")?;
    material.extend_from_slice(&bind_u64(input.generation, "generation")?.to_be_bytes());
    material
        .extend_from_slice(&bind_u64(input.source_generation, "source_generation")?.to_be_bytes());
    material.extend_from_slice(
        &bind_u64(input.projected_generation, "projected_generation")?.to_be_bytes(),
    );
    append_text(&mut material, input.event_id)?;
    append_text(&mut material, input.operation_id)?;
    material.extend_from_slice(&Sha256Digest::from_hex(input.semantic_hash_hex)?.as_bytes());
    material.extend_from_slice(&Sha256Digest::from_hex(input.dependency_hash_hex)?.as_bytes());
    append_text(&mut material, input.compiler_version)?;
    append_optional_id(
        &mut material,
        input.parent_manifest_id,
        "parent_manifest_id",
    )?;
    material.extend_from_slice(&bind_u64(input.revoke_fence, "revoke_fence")?.to_be_bytes());
    material.extend_from_slice(&(input.segment_content_digests_hex.len() as u64).to_be_bytes());
    for digest in &input.segment_content_digests_hex {
        material.extend_from_slice(&Sha256Digest::from_hex(digest)?.as_bytes());
    }
    Ok(Sha256Digest::from_raw_bytes(sha256_digest_bytes(&material)))
}
