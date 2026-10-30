use sha2::{Digest, Sha256};
use sqlx::{MySql, Transaction};

use astral_types::{
    AUTHORIZATION_COMPLETION_AUDIT_DOMAIN, AUTHORIZATION_COMPLETION_ITEMS_DOMAIN,
    AUTHORIZATION_EDITION,
};

use super::super::{
    normalize_impact_items, AuthorizationImpactItemInput, AuthorizationImpactPlanRecord,
    AuthorizationProjectionError, NormalizedImpactItem, Sha256Digest,
};

const SEAL_ACTION: &str = "owned_lane_COMPLETION_SEAL";
const SEAL_REASON: &str = "code=projection_execution.completion_item_set_sealed";
const SEAL_EVENT: &str = "AUTHZ_OWNED_PROJECTION_LANE";
const SEAL_RESOURCE: &str = "authorization_projection_owned_lane";

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ItemCommitment<'a> {
    projection_key: &'a str,
    item_type: &'a str,
    grant_id: Option<String>,
    before_digest: Option<String>,
    after_digest: Option<String>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct PlanCommitment<'a> {
    domain: &'static str,
    tenant_id: i64,
    aggregate_type: &'a str,
    aggregate_id: i64,
    card_id: Option<i64>,
    event_id: &'a str,
    operation_id: &'a str,
    source_generation: u64,
    base_generation: u64,
    target_generation: u64,
    base_version: i64,
    target_version: i64,
    semantic_hash: String,
    dependency_hash: String,
    compiler_version: &'a str,
    plan_id: i64,
    manifest_id: i64,
    manifest_digest: String,
    items: Vec<ItemCommitment<'a>>,
}

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompletionSeal {
    version: u16,
    event_id: String,
    operation_id: String,
    plan_id: i64,
    manifest_id: i64,
    item_count: usize,
    digest: String,
}

fn seal_request_id(plan: &AuthorizationImpactPlanRecord, manifest_id: i64) -> String {
    let mut digest = Sha256::new();
    digest.update(AUTHORIZATION_COMPLETION_AUDIT_DOMAIN);
    digest.update(plan.identity.tenant_id.to_be_bytes());
    for value in [&plan.event_id, &plan.operation_id] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    digest.update(manifest_id.to_be_bytes());
    hex::encode(digest.finalize())
}

fn normalized_stored_items(
    plan: &AuthorizationImpactPlanRecord,
) -> Result<Vec<NormalizedImpactItem>, AuthorizationProjectionError> {
    let inputs: Vec<_> = plan
        .items
        .iter()
        .map(|item| AuthorizationImpactItemInput {
            projection_key: item.projection_key.clone(),
            item_type: item.item_type,
            grant_id: item.grant_id,
            before_digest_hex: item.before_digest.map(|value| value.as_hex()),
            after_digest_hex: item.after_digest.map(|value| value.as_hex()),
        })
        .collect();
    normalize_impact_items(&inputs)
}

fn completion_seal(
    plan: &AuthorizationImpactPlanRecord,
    source_generation: u64,
    manifest_id: i64,
    manifest_digest: &Sha256Digest,
    items: &[NormalizedImpactItem],
) -> Result<CompletionSeal, AuthorizationProjectionError> {
    let commitment = PlanCommitment {
        domain: AUTHORIZATION_COMPLETION_ITEMS_DOMAIN,
        tenant_id: plan.identity.tenant_id,
        aggregate_type: &plan.identity.aggregate_type,
        aggregate_id: plan.identity.aggregate_id,
        card_id: plan.card_id,
        event_id: &plan.event_id,
        operation_id: &plan.operation_id,
        source_generation,
        base_generation: plan.base_generation,
        target_generation: plan.target_generation,
        base_version: plan.base_version,
        target_version: plan.target_version,
        semantic_hash: plan.semantic_hash.as_hex(),
        dependency_hash: plan.dependency_hash.as_hex(),
        compiler_version: &plan.compiler_version,
        plan_id: plan.plan_id,
        manifest_id,
        manifest_digest: manifest_digest.as_hex(),
        items: items
            .iter()
            .map(|item| ItemCommitment {
                projection_key: &item.projection_key,
                item_type: item.item_type.as_str(),
                grant_id: item.grant_id.map(|value| value.as_str().to_owned()),
                before_digest: item.before_digest.map(|value| value.as_hex()),
                after_digest: item.after_digest.map(|value| value.as_hex()),
            })
            .collect(),
    };
    let bytes = serde_json::to_vec(&commitment).map_err(|_| {
        AuthorizationProjectionError::Mapping(
            "code=projection_execution.completion_seal_encode_failed".to_owned(),
        )
    })?;
    Ok(CompletionSeal {
        version: AUTHORIZATION_EDITION,
        event_id: plan.event_id.clone(),
        operation_id: plan.operation_id.clone(),
        plan_id: plan.plan_id,
        manifest_id,
        item_count: items.len(),
        digest: hex::encode(Sha256::digest(bytes)),
    })
}

pub(super) async fn record_in_tx(
    tx: &mut Transaction<'_, MySql>,
    plan: &AuthorizationImpactPlanRecord,
    source_generation: u64,
    manifest_id: i64,
    manifest_digest: &Sha256Digest,
    expected_items: &[AuthorizationImpactItemInput],
) -> Result<(), AuthorizationProjectionError> {
    let expected = normalize_impact_items(expected_items)?;
    if expected.is_empty() || expected != normalized_stored_items(plan)? {
        return Err(AuthorizationProjectionError::Corrupt(
            "code=projection_execution.completion_item_set_mismatch".to_owned(),
        ));
    }
    let seal = completion_seal(
        plan,
        source_generation,
        manifest_id,
        manifest_digest,
        &expected,
    )?;
    let detail = serde_json::to_string(&seal).map_err(|_| {
        AuthorizationProjectionError::Mapping(
            "code=projection_execution.completion_seal_encode_failed".to_owned(),
        )
    })?;
    // The commitment is written in the publication transaction, never backfilled
    // from a later possibly truncated item set. Existing audit retention must
    // retain it with the corresponding delta/manifest history.
    sqlx::query(
        "INSERT INTO audit_log (user_id, card_id, action, resource, decision, reason, \
         event_type, request_id, tenant_id, detail) VALUES (?, ?, ?, ?, 'INTERNAL', ?, ?, ?, ?, ?)",
    )
    .bind(astral_types::SYSTEM_ACTOR_ID)
    .bind(plan.card_id)
    .bind(SEAL_ACTION)
    .bind(SEAL_RESOURCE)
    .bind(SEAL_REASON)
    .bind(SEAL_EVENT)
    .bind(seal_request_id(plan, manifest_id))
    .bind(plan.identity.tenant_id)
    .bind(detail)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(super) async fn verify_in_tx(
    tx: &mut Transaction<'_, MySql>,
    plan: &AuthorizationImpactPlanRecord,
    source_generation: u64,
    manifest_id: i64,
    manifest_digest: &Sha256Digest,
) -> Result<bool, AuthorizationProjectionError> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT CAST(detail AS CHAR CHARACTER SET utf8mb4) FROM audit_log \
         WHERE tenant_id = ? AND request_id = ? \
           AND CAST(request_id AS BINARY) = CAST(? AS BINARY) \
           AND CAST(event_type AS BINARY) = CAST(? AS BINARY) \
           AND CAST(resource AS BINARY) = CAST(? AS BINARY) \
           AND CAST(action AS BINARY) = CAST(? AS BINARY) \
           AND CAST(reason AS BINARY) = CAST(? AS BINARY) \
           AND CAST(decision AS BINARY) = CAST('INTERNAL' AS BINARY) \
           AND user_id = ? AND card_id <=> ? LIMIT 2 FOR UPDATE",
    )
    .bind(plan.identity.tenant_id)
    .bind(seal_request_id(plan, manifest_id))
    .bind(seal_request_id(plan, manifest_id))
    .bind(SEAL_EVENT)
    .bind(SEAL_RESOURCE)
    .bind(SEAL_ACTION)
    .bind(SEAL_REASON)
    .bind(astral_types::SYSTEM_ACTOR_ID)
    .bind(plan.card_id)
    .fetch_all(&mut **tx)
    .await?;
    if rows.len() != 1 {
        return Ok(false);
    }
    let stored: CompletionSeal = serde_json::from_str(&rows[0].0).map_err(|_| {
        AuthorizationProjectionError::Corrupt(
            "code=projection_execution.completion_seal_corrupt".to_owned(),
        )
    })?;
    if stored.version != AUTHORIZATION_EDITION {
        return Ok(false);
    }
    let items = normalized_stored_items(plan)?;
    Ok(stored
        == completion_seal(
            plan,
            source_generation,
            manifest_id,
            manifest_digest,
            &items,
        )?)
}

#[cfg(test)]
mod tests {
    use super::super::super::{
        AuthorizationImpactItemType, AuthorizationImpactPlanStatus, ProjectionAggregateIdentity,
    };
    use super::*;

    fn plan() -> AuthorizationImpactPlanRecord {
        AuthorizationImpactPlanRecord {
            plan_id: 3,
            identity: ProjectionAggregateIdentity::new(7, "USER_CARD".to_owned(), 11).unwrap(),
            card_id: Some(11),
            event_id: "completion-seal-event".to_owned(),
            operation_id: "completion-seal-operation".to_owned(),
            base_generation: 0,
            target_generation: 1,
            base_version: 0,
            target_version: 1,
            semantic_hash: Sha256Digest::from_hex(&"11".repeat(32)).unwrap(),
            dependency_hash: Sha256Digest::from_hex(&"22".repeat(32)).unwrap(),
            compiler_version: "seal-test".to_owned(),
            status: AuthorizationImpactPlanStatus::Succeeded,
            attempts: 0,
            cas_version: 0,
            items: Vec::new(),
        }
    }

    #[test]
    fn completion_commitment_binds_current_manifest_seal_time() {
        use crate::authorization_projection_repository::{
            compute_manifest_digest, ManifestDigestInput,
        };
        let mut input = ManifestDigestInput {
            tenant_id: 7,
            aggregate_type: "USER_CARD",
            aggregate_id: 11,
            card_id: Some(11),
            generation: 1,
            source_generation: 9,
            projected_generation: 9,
            event_id: "completion-seal-event",
            operation_id: "completion-seal-operation",
            semantic_hash_hex: &"11".repeat(32),
            dependency_hash_hex: &"22".repeat(32),
            compiler_version: "seal-test",
            parent_manifest_id: None,
            revoke_fence: 0,
            seal: astral_types::PublicationSeal::from_unix_seconds(1_700_000_000).unwrap(),
            segment_content_digests_hex: vec![],
        };
        let before = compute_manifest_digest(&input).unwrap();
        input.seal = astral_types::PublicationSeal::from_unix_seconds(1_700_000_001).unwrap();
        let after = compute_manifest_digest(&input).unwrap();
        assert_ne!(before, after);
        assert_ne!(
            completion_seal(&plan(), 9, 17, &before, &[]).unwrap(),
            completion_seal(&plan(), 9, 17, &after, &[]).unwrap(),
        );
    }

    #[test]
    fn immutable_item_commitment_rejects_subset_and_field_drift() {
        let plan = plan();
        let digest = Sha256Digest::from_hex(&"33".repeat(32)).unwrap();
        let items: Vec<_> = ["a", "b"]
            .into_iter()
            .map(|key| NormalizedImpactItem {
                projection_key: key.to_owned(),
                item_type: AuthorizationImpactItemType::SegmentUpsert,
                grant_id: None,
                before_digest: None,
                after_digest: Some(digest),
            })
            .collect();
        let expected = completion_seal(&plan, 9, 17, &digest, &items).unwrap();
        assert_ne!(
            expected,
            completion_seal(&plan, 9, 17, &digest, &items[..1]).unwrap()
        );
        let mut changed = items.clone();
        changed[1].before_digest = Some(digest);
        assert_ne!(
            expected,
            completion_seal(&plan, 9, 17, &digest, &changed).unwrap()
        );
        assert_ne!(
            expected,
            completion_seal(&plan, 10, 17, &digest, &items).unwrap()
        );
        assert_ne!(
            expected,
            completion_seal(&plan, 9, 18, &digest, &items).unwrap()
        );
    }
}
