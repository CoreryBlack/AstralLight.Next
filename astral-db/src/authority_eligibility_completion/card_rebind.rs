//! Closed zero-contribution template rebinding and independent durable readback.

use std::collections::{BTreeMap, BTreeSet};

use astral_types::{
    AuthorityCardRebindBaseRef, AuthorityCardRebindCardImage, AuthorityCardRebindEvidence,
    AuthorityCardRebindRuleSetAggregate, AuthorizationAdmission, GrantSourceKind, GrantState,
};
use serde_json::Value;
use sqlx::{MySql, Transaction};

use super::*;
use crate::authority_config_source::TypedSourceReadError;

type ReadResult<T> = Result<T, TypedSourceReadError>;
const MAX_RULE_SETS: i64 = 256;
const MAX_REFS: i64 = 1024;

/// Owns the source transaction borrow until the actual rebind is sealed.
pub struct CardRebindCapture<'tx, 'conn> {
    tx: &'tx mut Transaction<'conn, MySql>,
    admission: AuthorizationAdmission,
    evidence: AuthorityCardRebindEvidence,
    inserted_ref_ids: BTreeSet<i64>,
}

fn invalid(message: impl Into<String>) -> TypedSourceReadError {
    TypedSourceReadError::Pending(message.into())
}

fn encode<T: serde::Serialize>(value: &T) -> ReadResult<Value> {
    serde_json::to_value(value).map_err(|error| invalid(error.to_string()))
}

fn sql_error(context: &'static str, error: sqlx::Error) -> TypedSourceReadError {
    TypedSourceReadError::from_sqlx(context, error)
}

fn verification_error(error: TypedSourceReadError) -> EligibilityVerificationError {
    match error {
        TypedSourceReadError::SqlxTransient { context, source } => {
            EligibilityVerificationError::transient(format!("{context}: {source}"))
        }
        error => EligibilityVerificationError::proof(error.to_string()),
    }
}

async fn card_image(
    tx: &mut Transaction<'_, MySql>,
    card_id: i64,
) -> ReadResult<AuthorityCardRebindCardImage> {
    let row: CreatedCardImage = sqlx::query_as(
        "SELECT card_id, card_status, user_id, tenant_id, domain_id, template_id, \
         card_type, level_id, priority, is_primary, CAST(valid_from AS CHAR) AS valid_from, \
         CAST(valid_until AS CHAR) AS valid_until FROM user_card WHERE card_id = ? FOR UPDATE",
    )
    .bind(card_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|error| sql_error("read complete rebind card", error))?;
    serde_json::from_value(encode(&row)?).map_err(|error| invalid(error.to_string()))
}

#[derive(sqlx::FromRow)]
struct BaseRefRow {
    id: i64,
    card_id: i64,
    rule_set_id: i64,
    ref_type: String,
    tenant_id: Option<i64>,
    created_at: String,
}

async fn base_refs(
    tx: &mut Transaction<'_, MySql>,
    card_id: i64,
) -> ReadResult<Vec<AuthorityCardRebindBaseRef>> {
    let rows: Vec<BaseRefRow> = sqlx::query_as(
        "SELECT id, card_id, rule_set_id, CAST(ref_type AS CHAR) AS ref_type, tenant_id, \
         CAST(created_at AS CHAR) AS created_at FROM card_rule_set_ref \
         WHERE card_id = ? AND ref_type = 'BASE' ORDER BY id LIMIT ? FOR UPDATE",
    )
    .bind(card_id)
    .bind(MAX_REFS + 1)
    .fetch_all(&mut **tx)
    .await
    .map_err(|error| sql_error("read complete rebind BASE refs", error))?;
    if rows.len() as i64 > MAX_REFS {
        return Err(invalid("rebind BASE ref set exceeds its bound"));
    }
    Ok(rows
        .into_iter()
        .map(|row| AuthorityCardRebindBaseRef {
            id: row.id,
            card_id: row.card_id,
            rule_set_id: row.rule_set_id,
            ref_type: row.ref_type,
            tenant_id: row.tenant_id,
            created_at: row.created_at,
        })
        .collect())
}

async fn template_rule_sets(
    tx: &mut Transaction<'_, MySql>,
    template_id: i64,
    lock: bool,
) -> ReadResult<Vec<i64>> {
    let statement = if lock {
        "SELECT rule_set_id FROM rule_set WHERE source_type = 'TEMPLATE' AND source_id = ? \
         AND enabled = 1 ORDER BY rule_set_id LIMIT ? FOR UPDATE"
    } else {
        "SELECT rule_set_id FROM rule_set WHERE source_type = 'TEMPLATE' AND source_id = ? \
         AND enabled = 1 ORDER BY rule_set_id LIMIT ?"
    };
    let ids: Vec<i64> = sqlx::query_scalar(statement)
        .bind(template_id)
        .bind(MAX_RULE_SETS + 1)
        .fetch_all(&mut **tx)
        .await
        .map_err(|error| sql_error("read rebind template RuleSets", error))?;
    if ids.len() as i64 > MAX_RULE_SETS {
        return Err(invalid("rebind RuleSet set exceeds its bound"));
    }
    Ok(ids)
}

async fn template_image(tx: &mut Transaction<'_, MySql>, id: i64) -> ReadResult<String> {
    let (_, text) = crate::read_typed_source_row_image_in_tx_typed(
        tx,
        crate::TypedSourceTable::UserCardTemplate,
        &crate::TypedSourceRowLookup::PrimaryId { id },
    )
    .await?
    .ok_or_else(|| invalid("rebind template is missing"))?;
    let value: Value = serde_json::from_str(&text).map_err(|error| invalid(error.to_string()))?;
    serde_json::to_string(&value).map_err(|error| invalid(error.to_string()))
}

async fn aggregates(
    tx: &mut Transaction<'_, MySql>,
    ids: &BTreeSet<i64>,
) -> ReadResult<Vec<AuthorityCardRebindRuleSetAggregate>> {
    let mut rows = Vec::with_capacity(ids.len());
    for id in ids {
        let (_, text) = crate::read_typed_source_row_image_in_tx_typed(
            tx,
            crate::TypedSourceTable::RuleSet,
            &crate::TypedSourceRowLookup::PrimaryId { id: *id },
        )
        .await?
        .ok_or_else(|| invalid("rebind RuleSet aggregate is missing"))?;
        let image: Value =
            serde_json::from_str(&text).map_err(|error| invalid(error.to_string()))?;
        rows.push(AuthorityCardRebindRuleSetAggregate {
            rule_set_id: *id,
            canonical_image: serde_json::to_string(&image)
                .map_err(|error| invalid(error.to_string()))?,
        });
    }
    Ok(rows)
}

fn no_allow_contributions(rows: &[AuthorityCardRebindRuleSetAggregate]) -> ReadResult<bool> {
    for row in rows {
        row.validate().map_err(|error| invalid(error.to_string()))?;
        let value: Value = serde_json::from_str(&row.canonical_image)
            .map_err(|error| invalid(error.to_string()))?;
        for entry in value["entries"]
            .as_array()
            .ok_or_else(|| invalid("rebind entries are missing"))?
        {
            match (entry["enabled"].as_i64(), entry["effect"].as_str()) {
                (Some(0), Some("ALLOW" | "DENY")) | (Some(1), Some("DENY")) => {}
                (Some(1), Some("ALLOW")) => return Ok(false),
                _ => return Err(invalid("rebind RuleSet entry has unknown enabled/effect")),
            }
        }
    }
    Ok(true)
}

async fn no_live_base_grants(
    tx: &mut Transaction<'_, MySql>,
    evidence: &AuthorityCardRebindEvidence,
) -> ReadResult<bool> {
    // This is a current locking read. A repeatable-read snapshot predating a
    // committed revision must not classify a nonempty rebind as empty.
    let rows: Vec<crate::RawLedgerRow> = sqlx::query_as(
        "SELECT revision_no, tenant_id, card_id, aggregate_type, aggregate_id, grant_id, \
         status, is_tombstone, CAST(grant_payload AS CHAR) AS grant_payload, semantic_hash, \
         dependency_hash, operation_id, event_id, compiler_version FROM authorization_grant_revision \
         WHERE tenant_id = ? AND card_id = ? ORDER BY grant_id, revision_no LIMIT ? FOR UPDATE",
    ).bind(evidence.tenant_id).bind(evidence.card_id).bind(crate::MAX_LEDGER_ROWS)
        .fetch_all(&mut **tx).await.map_err(|error| sql_error("lock rebind grant history", error))?;
    if rows.len() as i64 >= crate::MAX_LEDGER_ROWS {
        return Err(invalid("rebind grant history exceeds its bound"));
    }
    let entries =
        crate::latest_entries_from_history(&rows).map_err(|error| invalid(error.to_string()))?;
    let refs: BTreeSet<String> = evidence
        .old_base_refs
        .iter()
        .map(|row| row.id.to_string())
        .collect();
    let rule_sets: BTreeSet<String> = evidence
        .before_rule_sets
        .iter()
        .map(|row| row.rule_set_id.to_string())
        .collect();
    Ok(!entries.iter().any(|entry| {
        entry.grant.source_kind == GrantSourceKind::RuleSet
            && !entry.is_tombstone
            && matches!(entry.grant.state, GrantState::Active | GrantState::Pending)
            && (entry.grant.binding_layer == astral_types::BindingLayer::Base
                || entry
                    .grant
                    .provenance
                    .binding_id
                    .as_ref()
                    .is_some_and(|id| refs.contains(id))
                || rule_sets.contains(&entry.grant.provenance.source_id))
    }))
}

fn target(evidence: &AuthorityCardRebindEvidence) -> ReadResult<IdentityTargetImage> {
    Ok(IdentityTargetImage {
        entity: "user_card".into(),
        key: serde_json::json!({"cardId": evidence.card_id}),
        before: IdentityPresence::Present(encode(&evidence.before_card)?),
        after: IdentityPresence::Present(encode(&evidence.after_card)?),
    })
}

fn binding_value(row: &AuthorityCardRebindBaseRef) -> Value {
    serde_json::json!({"id": row.id, "card_id": row.card_id, "rule_set_id": row.rule_set_id,
        "ref_type": row.ref_type, "tenant_id": row.tenant_id, "created_at": row.created_at})
}

fn validate_aggregate_transition(evidence: &AuthorityCardRebindEvidence) -> ReadResult<()> {
    evidence
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    if !no_allow_contributions(&evidence.before_rule_sets)?
        || !no_allow_contributions(&evidence.after_rule_sets)?
    {
        return Err(invalid("rebind has materializable ALLOW contributions"));
    }
    for (before, after) in evidence
        .before_rule_sets
        .iter()
        .zip(&evidence.after_rule_sets)
    {
        let id = before.rule_set_id;
        let before: Value = serde_json::from_str(&before.canonical_image)
            .map_err(|error| invalid(error.to_string()))?;
        let after: Value = serde_json::from_str(&after.canonical_image)
            .map_err(|error| invalid(error.to_string()))?;
        if before["root"] != after["root"] || before["entries"] != after["entries"] {
            return Err(invalid("rebind changed RuleSet root or entries"));
        }
        let partition = |image: &Value| -> ReadResult<(Vec<Value>, Vec<Value>)> {
            let rows = image["bindings"]
                .as_array()
                .ok_or_else(|| invalid("rebind bindings missing"))?;
            Ok(rows.iter().cloned().partition(|row| {
                row["card_id"].as_i64() == Some(evidence.card_id) && row["ref_type"] == "BASE"
            }))
        };
        let (old, old_other) = partition(&before)?;
        let (new, new_other) = partition(&after)?;
        let expected = |refs: &[AuthorityCardRebindBaseRef]| {
            refs.iter()
                .filter(|row| row.rule_set_id == id)
                .map(binding_value)
                .collect::<Vec<_>>()
        };
        if old != expected(&evidence.old_base_refs)
            || new != expected(&evidence.new_base_refs)
            || old_other != new_other
        {
            return Err(invalid(
                "rebind aggregate bindings differ from exact BASE refs",
            ));
        }
    }
    let ids: BTreeSet<_> = evidence
        .before_rule_sets
        .iter()
        .map(|row| row.rule_set_id)
        .collect();
    if evidence
        .old_base_refs
        .iter()
        .chain(&evidence.new_base_refs)
        .any(|row| !ids.contains(&row.rule_set_id))
    {
        return Err(invalid("rebind omitted a referenced RuleSet aggregate"));
    }
    let referenced_ids: BTreeSet<_> = evidence
        .old_base_refs
        .iter()
        .chain(&evidence.new_base_refs)
        .map(|row| row.rule_set_id)
        .collect();
    if ids != referenced_ids {
        return Err(invalid("rebind RuleSet aggregate union is not exact"));
    }
    for (refs, template_id, images) in [
        (
            &evidence.old_base_refs,
            evidence.old_template_id,
            &evidence.before_rule_sets,
        ),
        (
            &evidence.new_base_refs,
            Some(evidence.new_template_id),
            &evidence.after_rule_sets,
        ),
    ] {
        for reference in refs {
            let aggregate = images
                .iter()
                .find(|row| row.rule_set_id == reference.rule_set_id)
                .ok_or_else(|| invalid("rebind referenced aggregate missing"))?;
            let image: Value = serde_json::from_str(&aggregate.canonical_image)
                .map_err(|error| invalid(error.to_string()))?;
            if image["root"]["source_id"].as_i64() != template_id {
                return Err(invalid("rebind BASE ref belongs to a different template"));
            }
        }
    }
    if evidence
        .old_base_refs
        .iter()
        .any(|old| evidence.new_base_refs.iter().any(|new| old.id == new.id))
    {
        return Err(invalid("rebind reused a deleted BASE ref identity"));
    }
    Ok(())
}

impl<'tx, 'conn> CardRebindCapture<'tx, 'conn> {
    /// Returns None without source writes when real grant publication is required.
    pub async fn try_begin_in_tx(
        tx: &'tx mut Transaction<'conn, MySql>,
        admission: &AuthorizationAdmission,
        card_id: i64,
        new_template_id: i64,
    ) -> Result<Option<Self>, TypedSourceReadError> {
        Self::try_begin_typed(tx, admission, card_id, new_template_id).await
    }

    async fn try_begin_typed(
        tx: &'tx mut Transaction<'conn, MySql>,
        admission: &AuthorizationAdmission,
        card_id: i64,
        new_template_id: i64,
    ) -> ReadResult<Option<Self>> {
        let before = card_image(tx, card_id).await?;
        let tenant_id = before
            .tenant_id
            .filter(|id| *id > 0)
            .ok_or_else(|| invalid("rebind tenant missing"))?;
        let user_id = before
            .user_id
            .filter(|id| *id > 0)
            .ok_or_else(|| invalid("rebind user missing"))?;
        let proof = admission.proof();
        let domain_matches = match proof.scope.domain {
            astral_types::AuthorizationDomainScope::Exact(id) => before.domain_id == Some(id),
            astral_types::AuthorizationDomainScope::NoDomain => before.domain_id.is_none(),
            astral_types::AuthorizationDomainScope::Any => false,
        };
        if proof.scope.card_id != card_id
            || proof.scope.tenant_id != tenant_id
            || proof.scope.user_id != Some(user_id)
            || !domain_matches
            || proof.request_binding_digest.is_none()
            || before.card_status != "ACTIVE"
            || before.template_id == Some(new_template_id)
            || new_template_id <= 0
        {
            return Err(invalid("rebind admission or actual card scope differs"));
        }
        let new_template_image = template_image(tx, new_template_id).await?;
        // Probe only to discover owners. Lock all RuleSet roots in ascending
        // order before their entries/refs, then re-read the complete selectors.
        let old_ids: Vec<i64> = sqlx::query_scalar(
            "SELECT DISTINCT rule_set_id FROM card_rule_set_ref WHERE card_id = ? AND ref_type = 'BASE' \
             ORDER BY rule_set_id LIMIT ?",
        ).bind(card_id).bind(MAX_RULE_SETS + 1).fetch_all(&mut **tx).await
            .map_err(|error| sql_error("probe rebind BASE owners", error))?;
        let new_ids = template_rule_sets(tx, new_template_id, false).await?;
        let ids: BTreeSet<i64> = old_ids.iter().chain(&new_ids).copied().collect();
        if ids.len() as i64 > MAX_RULE_SETS {
            return Err(invalid("rebind aggregate set exceeds its bound"));
        }
        for id in &ids {
            let locked: Option<i64> = sqlx::query_scalar(
                "SELECT rule_set_id FROM rule_set WHERE rule_set_id = ? FOR UPDATE",
            )
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|error| sql_error("lock rebind RuleSet owner", error))?;
            if locked != Some(*id) {
                return Err(invalid("rebind RuleSet owner missing"));
            }
        }
        let refs = base_refs(tx, card_id).await?;
        let locked_new_ids = template_rule_sets(tx, new_template_id, true).await?;
        if locked_new_ids != new_ids
            || refs
                .iter()
                .map(|row| row.rule_set_id)
                .collect::<BTreeSet<_>>()
                != old_ids.into_iter().collect()
        {
            return Err(invalid("rebind owner discovery changed before locking"));
        }
        let before_rule_sets = aggregates(tx, &ids).await?;
        let mut after = before.clone();
        after.template_id = Some(new_template_id);
        let evidence = AuthorityCardRebindEvidence {
            card_id,
            tenant_id,
            user_id,
            domain_id: before.domain_id,
            old_template_id: before.template_id,
            new_template_id,
            new_template_image,
            before_card: before,
            after_card: after,
            old_base_refs: refs,
            new_base_refs: Vec::new(),
            before_rule_sets,
            after_rule_sets: Vec::new(),
        };
        evidence
            .validate_template()
            .map_err(|error| invalid(error.to_string()))?;
        if !no_allow_contributions(&evidence.before_rule_sets)?
            || !no_live_base_grants(tx, &evidence).await?
        {
            return Ok(None);
        }
        for row in &evidence.old_base_refs {
            let result = sqlx::query(
                "DELETE FROM card_rule_set_ref WHERE id = ? AND card_id = ? AND ref_type = 'BASE'",
            )
            .bind(row.id)
            .bind(card_id)
            .execute(&mut **tx)
            .await
            .map_err(|error| sql_error("delete rebind BASE ref", error))?;
            if result.rows_affected() != 1 {
                return Err(invalid("rebind BASE delete was not exact"));
            }
        }
        let mut inserted_ref_ids = BTreeSet::new();
        for id in new_ids {
            let result = sqlx::query("INSERT INTO card_rule_set_ref (card_id, rule_set_id, ref_type, tenant_id) VALUES (?, ?, 'BASE', ?)")
                .bind(card_id).bind(id).bind(tenant_id).execute(&mut **tx).await.map_err(|error| sql_error("insert rebind BASE ref", error))?;
            let generated = i64::try_from(result.last_insert_id())
                .map_err(|_| invalid("rebind BASE generated id exceeds its SQL range"))?;
            if result.rows_affected() != 1 || generated <= 0 || !inserted_ref_ids.insert(generated)
            {
                return Err(invalid("rebind BASE insert was not exact"));
            }
        }
        let result = sqlx::query("UPDATE user_card SET template_id = ? WHERE card_id = ? AND card_status = 'ACTIVE' AND template_id <=> ?")
            .bind(new_template_id).bind(card_id).bind(evidence.old_template_id).execute(&mut **tx).await.map_err(|error| sql_error("update rebind card", error))?;
        if result.rows_affected() != 1 {
            return Err(invalid("rebind card update was not exact"));
        }
        Ok(Some(Self {
            tx,
            admission: admission.clone(),
            evidence,
            inserted_ref_ids,
        }))
    }

    pub fn old_template_id(&self) -> Option<i64> {
        self.evidence.old_template_id
    }
    pub fn tenant_id(&self) -> i64 {
        self.evidence.tenant_id
    }
    pub fn domain_id(&self) -> Option<i64> {
        self.evidence.domain_id
    }
    pub fn with_tx_mut(&mut self) -> &mut Transaction<'conn, MySql> {
        self.tx
    }

    /// Full binding images for the same-transaction user-card mutation audit.
    pub async fn binding_audit_in_tx(&mut self) -> Result<Value, TypedSourceReadError> {
        let new = base_refs(self.tx, self.evidence.card_id).await?;
        Ok(serde_json::json!({"before": self.evidence.old_base_refs, "after": new}))
    }

    pub async fn finish_in_tx(
        mut self,
    ) -> Result<EligibilitySourceEvidenceReceipt, TypedSourceReadError> {
        self.finish_typed().await
    }

    async fn finish_typed(&mut self) -> ReadResult<EligibilitySourceEvidenceReceipt> {
        self.evidence.after_card = card_image(self.tx, self.evidence.card_id).await?;
        self.evidence.new_base_refs = base_refs(self.tx, self.evidence.card_id).await?;
        if self
            .evidence
            .new_base_refs
            .iter()
            .map(|row| row.id)
            .collect::<BTreeSet<_>>()
            != self.inserted_ref_ids
        {
            return Err(invalid(
                "rebind readback differs from actual generated BASE identities",
            ));
        }
        let ids = self
            .evidence
            .before_rule_sets
            .iter()
            .map(|row| row.rule_set_id)
            .collect();
        self.evidence.after_rule_sets = aggregates(self.tx, &ids).await?;
        validate_aggregate_transition(&self.evidence)?;
        validate_ref_sets(self.tx, &self.evidence).await?;
        if !no_live_base_grants(self.tx, &self.evidence).await? {
            return Err(invalid("rebind omitted a live grant"));
        }
        let operation_id = self.admission.operation_id();
        assert_no_delta(self.tx, operation_id).await?;
        let audit = read_audit(self.tx, operation_id).await?;
        let parent = read_parent(self.tx, &audit, &self.evidence, operation_id).await?;
        validate_audit(&audit, &parent, &self.evidence, operation_id)?;
        let target = target(&self.evidence)?;
        let receipts = base_receipts(&self.evidence, &audit, &parent);
        let (captures, receipts) = read_card_completion_receipts(
            self.tx,
            operation_id,
            &[(self.evidence.card_id, Some(self.evidence.tenant_id))],
            receipts,
        )
        .await
        .map_err(|error| invalid(error.to_string()))?;
        let completion = build_eligibility_completion_evidence(&captures)
            .map_err(|error| invalid(format!("rebind completion: {error:?}")))?;
        validate_receipts(
            &receipts,
            &expected_receipts(&self.evidence, &audit, &parent, &completion, operation_id)?,
        )?;
        let (before_image_digest, after_image_digest) =
            identity_image_digests(std::slice::from_ref(&target))
                .map_err(|error| invalid(error.to_string()))?;
        let source_evidence = serde_json::json!({"targets": [target], "receipts": receipts, "fanout": {
            "eligibilityEvents": 1, "affectedCards": [{"cardId": self.evidence.card_id, "tenantId": self.evidence.tenant_id}],
            "cardRebind": self.evidence, "parentCardProjection": parent,
        }});
        Ok(EligibilitySourceEvidenceReceipt {
            completion,
            source_evidence,
            source_target: target,
            source_receipts: receipts,
            before_image_digest,
            after_image_digest,
            operation: EligibilitySourceOperation::CardRebind,
            publication_origin: false,
            card_rebind: Some(self.evidence.clone()),
        })
    }
}

async fn assert_no_delta(tx: &mut Transaction<'_, MySql>, operation_id: &str) -> ReadResult<()> {
    let delta: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM authorization_delta_event WHERE operation_id = ? LIMIT 1 FOR UPDATE",
    )
    .bind(operation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| sql_error("assert empty rebind delta", error))?;
    if delta.is_some() {
        return Err(invalid("rebind completion has actual grant delta"));
    }
    Ok(())
}

async fn validate_ref_sets(
    tx: &mut Transaction<'_, MySql>,
    evidence: &AuthorityCardRebindEvidence,
) -> ReadResult<()> {
    if template_image(tx, evidence.new_template_id).await? != evidence.new_template_image {
        return Err(invalid("rebind template changed from retained source"));
    }
    let expected = template_rule_sets(tx, evidence.new_template_id, true).await?;
    let actual: BTreeSet<_> = evidence
        .new_base_refs
        .iter()
        .map(|row| row.rule_set_id)
        .collect();
    if actual.len() != evidence.new_base_refs.len() || actual != expected.into_iter().collect() {
        return Err(invalid(
            "rebind refs do not cover the complete enabled new template",
        ));
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct RebindAudit {
    id: i64,
    user_id: i64,
    card_id: Option<i64>,
    tenant_id: Option<i64>,
    domain_id: Option<i64>,
    action: String,
    resource: String,
    decision: String,
    event_type: String,
    detail: Option<String>,
}

async fn read_audit(
    tx: &mut Transaction<'_, MySql>,
    operation_id: &str,
) -> ReadResult<RebindAudit> {
    let mut rows: Vec<RebindAudit> = sqlx::query_as(
        "SELECT id, user_id, card_id, tenant_id, domain_id, action, resource, decision, event_type, detail \
         FROM audit_log WHERE request_id = ? LIMIT 2 FOR UPDATE",
    ).bind(operation_id).fetch_all(&mut **tx).await.map_err(|error| sql_error("read rebind audit", error))?;
    if rows.len() != 1 {
        return Err(invalid("rebind audit set is not exact"));
    }
    Ok(rows.remove(0))
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ParentCardProjection {
    event_id: String,
    source_generation: i64,
    revoke_fence: i64,
}

#[derive(sqlx::FromRow)]
struct ParentRow {
    event_id: String,
    aggregate_type: String,
    aggregate_id: i64,
    tenant_id: Option<i64>,
    event_type: String,
    source_generation: i64,
    sequence_number: i64,
    revoke_fence: i64,
    status: String,
    payload_json: Option<String>,
}

fn audit_detail(audit: &RebindAudit) -> ReadResult<Value> {
    serde_json::from_str(
        audit
            .detail
            .as_deref()
            .ok_or_else(|| invalid("rebind audit detail missing"))?,
    )
    .map_err(|error| invalid(error.to_string()))
}

async fn read_parent(
    tx: &mut Transaction<'_, MySql>,
    audit: &RebindAudit,
    evidence: &AuthorityCardRebindEvidence,
    operation_id: &str,
) -> ReadResult<ParentCardProjection> {
    let detail = audit_detail(audit)?;
    let event_id = detail["parentEventId"]
        .as_str()
        .ok_or_else(|| invalid("rebind CARD parent missing"))?;
    let row: ParentRow = sqlx::query_as(
        "SELECT event_id, aggregate_type, aggregate_id, tenant_id, event_type, source_generation, \
         sequence_number, revoke_fence, status, CAST(payload_json AS CHAR) AS payload_json \
         FROM authorization_projection_outbox WHERE event_id = ? FOR UPDATE",
    )
    .bind(event_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|error| sql_error("read rebind CARD parent", error))?;
    let payload: Value = serde_json::from_str(
        row.payload_json
            .as_deref()
            .ok_or_else(|| invalid("rebind CARD payload missing"))?,
    )
    .map_err(|error| invalid(error.to_string()))?;
    if row.event_id != event_id
        || row.aggregate_type != "CARD"
        || row.aggregate_id != evidence.card_id
        || row.tenant_id != Some(evidence.tenant_id)
        || row.event_type != "CARD_UPDATE"
        || row.source_generation <= 0
        || row.sequence_number != row.source_generation
        || row.revoke_fence < 0
        || row.revoke_fence > row.source_generation
        || !matches!(row.status.as_str(), "PENDING" | "PROCESSED")
        || payload["cardId"].as_i64() != Some(evidence.card_id)
        || payload["tenantId"].as_i64() != Some(evidence.tenant_id)
        || payload["actorId"].as_i64() != Some(evidence.user_id)
        || payload["operationId"].as_str() != Some(operation_id)
        || payload["generation"].as_i64() != Some(row.source_generation)
    {
        return Err(invalid("rebind CARD parent identity differs"));
    }
    Ok(ParentCardProjection {
        event_id: row.event_id,
        source_generation: row.source_generation,
        revoke_fence: row.revoke_fence,
    })
}

fn validate_audit(
    audit: &RebindAudit,
    parent: &ParentCardProjection,
    evidence: &AuthorityCardRebindEvidence,
    operation_id: &str,
) -> ReadResult<()> {
    let detail = audit_detail(audit)?;
    if audit.id <= 0
        || audit.user_id != evidence.user_id
        || audit.card_id != Some(evidence.card_id)
        || audit.tenant_id != Some(evidence.tenant_id)
        || audit.domain_id != evidence.domain_id
        || audit.action != "card_template_change"
        || audit.resource != "user_card"
        || audit.decision != "CARD_UPDATED"
        || audit.event_type != "USER_CARD_MUTATION"
        || detail["actorId"].as_i64() != Some(audit.user_id)
        || detail["ownerUserId"].as_i64() != Some(evidence.user_id)
        || detail["operationId"].as_str() != Some(operation_id)
        || detail["targetCardId"].as_i64() != Some(evidence.card_id)
        || detail["fromTemplateId"] != encode(&evidence.old_template_id)?
        || detail["toTemplateId"].as_i64() != Some(evidence.new_template_id)
        || detail["templateChanged"].as_bool() != Some(true)
        || detail["action"] != "card_template_change"
        || detail["parentEventId"].as_str() != Some(parent.event_id.as_str())
        || detail["baseRefs"]["before"] != encode(&evidence.old_base_refs)?
        || detail["baseRefs"]["after"] != encode(&evidence.new_base_refs)?
    {
        return Err(invalid(
            "rebind audit actor/operation/binding transition differs",
        ));
    }
    Ok(())
}

fn receipt(entity: &str, key: Value, kind: &str, id: String) -> IdentityReceipt {
    IdentityReceipt {
        entity: entity.into(),
        key,
        kind: kind.into(),
        rows_affected: 1,
        durable_id: id,
    }
}

fn base_receipts(
    evidence: &AuthorityCardRebindEvidence,
    audit: &RebindAudit,
    parent: &ParentCardProjection,
) -> Vec<IdentityReceipt> {
    let mut rows = vec![
        receipt(
            "user_card",
            serde_json::json!({"cardId": evidence.card_id}),
            "UPDATE",
            evidence.card_id.to_string(),
        ),
        receipt(
            "audit_log",
            serde_json::json!({"id": audit.id, "eventType": "USER_CARD_MUTATION"}),
            "INSERT",
            audit.id.to_string(),
        ),
        receipt(
            "authorization_projection_outbox",
            serde_json::json!({"eventId": parent.event_id, "aggregateId": evidence.card_id}),
            "INSERT",
            parent.event_id.clone(),
        ),
    ];
    for (refs, kind) in [
        (&evidence.old_base_refs, "DELETE"),
        (&evidence.new_base_refs, "INSERT"),
    ] {
        rows.extend(refs.iter().map(|row| receipt("card_rule_set_ref",
            serde_json::json!({"id": row.id, "cardId": row.card_id, "ruleSetId": row.rule_set_id}), kind, row.id.to_string())));
    }
    rows
}

fn expected_receipts(
    evidence: &AuthorityCardRebindEvidence,
    audit: &RebindAudit,
    parent: &ParentCardProjection,
    completion: &AuthorityEligibilityCompletionEvidence,
    operation_id: &str,
) -> ReadResult<Vec<IdentityReceipt>> {
    let card = completion
        .cards
        .first()
        .ok_or_else(|| invalid("rebind completion is empty"))?;
    if card.outbox_event_id == parent.event_id {
        return Err(invalid("rebind CARD and ELIGIBILITY identities alias"));
    }
    let mut rows = base_receipts(evidence, audit, parent);
    rows.push(receipt(
        "authorization_projection_outbox",
        serde_json::json!({"eventId": card.outbox_event_id, "aggregateId": evidence.card_id}),
        "INSERT",
        card.outbox_event_id.clone(),
    ));
    rows.push(receipt(
        "al_message_outbox",
        serde_json::json!({"messageId": card.message_id, "operationId": operation_id}),
        "INSERT",
        card.message_id.clone(),
    ));
    Ok(rows)
}

fn validate_receipts(actual: &[IdentityReceipt], expected: &[IdentityReceipt]) -> ReadResult<()> {
    let index = |rows: &[IdentityReceipt]| -> ReadResult<BTreeMap<(String, String), Value>> {
        let mut result = BTreeMap::new();
        for row in rows {
            if result
                .insert((row.entity.clone(), row.durable_id.clone()), encode(row)?)
                .is_some()
            {
                return Err(invalid("rebind duplicate receipt identity"));
            }
        }
        Ok(result)
    };
    if index(actual)? != index(expected)? {
        return Err(invalid("rebind receipt key/kind/rows/id set differs"));
    }
    Ok(())
}

pub(super) fn classify(
    artifact: &crate::IdentityStagedEvidence,
) -> Option<AuthorityCardRebindEvidence> {
    let evidence: AuthorityCardRebindEvidence =
        serde_json::from_value(artifact.fanout.get("cardRebind")?.clone()).ok()?;
    validate_aggregate_transition(&evidence).ok()?;
    if artifact.targets.len() != 1
        || encode(&artifact.targets[0]).ok()? != encode(&target(&evidence).ok()?).ok()?
    {
        return None;
    }
    Some(evidence)
}

pub(super) async fn verify_in_tx(
    tx: &mut Transaction<'_, MySql>,
    operation_id: &str,
    completion: &AuthorityEligibilityCompletionEvidence,
    artifact: &crate::IdentityStagedEvidence,
) -> Result<(), EligibilityVerificationError> {
    let run = async {
        let evidence =
            classify(artifact).ok_or_else(|| invalid("invalid strict rebind artifact"))?;
        if artifact.delta.is_some()
            || completion.cards.len() != 1
            || completion.zero_card_selection.is_some()
            || completion.cards[0].scope.card_identity()
                != Some((evidence.tenant_id, evidence.card_id))
        {
            return Err(invalid("rebind completion scope/delta differs"));
        }
        if card_image(tx, evidence.card_id).await? != evidence.after_card
            || base_refs(tx, evidence.card_id).await? != evidence.new_base_refs
        {
            return Err(invalid(
                "rebind current card/refs differ from retained source",
            ));
        }
        let ids = evidence
            .after_rule_sets
            .iter()
            .map(|row| row.rule_set_id)
            .collect();
        if aggregates(tx, &ids).await? != evidence.after_rule_sets {
            return Err(invalid("rebind current RuleSet aggregate differs"));
        }
        validate_ref_sets(tx, &evidence).await?;
        if !no_live_base_grants(tx, &evidence).await? {
            return Err(invalid("rebind live grant was omitted"));
        }
        assert_no_delta(tx, operation_id).await?;
        let audit = read_audit(tx, operation_id).await?;
        let parent = read_parent(tx, &audit, &evidence, operation_id).await?;
        validate_audit(&audit, &parent, &evidence, operation_id)?;
        if encode(&parent)? != artifact.fanout["parentCardProjection"] {
            return Err(invalid("rebind retained CARD parent differs"));
        }
        validate_receipts(
            &artifact.receipts,
            &expected_receipts(&evidence, &audit, &parent, completion, operation_id)?,
        )?;
        Ok(())
    }
    .await;
    run.map_err(verification_error)?;
    super::verification::verify_rebind_delivery(tx, operation_id, completion, artifact).await
}

#[cfg(test)]
mod tests;
