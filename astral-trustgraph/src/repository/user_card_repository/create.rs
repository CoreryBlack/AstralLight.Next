//! Closed new-card source capture and template binding in one source transaction.

use super::*;
use crate::repository::authorization_source_transaction::{
    append_eligibility_projection_with_invalidation_on_raw_tx, AuthorizationSourceTransaction,
    CardCreateBindingStart,
};
use astral_db::authority_eligibility_completion::{CardCreateInsertSpec, EligibilitySourceCapture};

pub(super) async fn create_card(
    repository: &SqlxUserCardRepository,
    new: &NewUserCard,
    admission: AuthorizationAdmission,
) -> Result<i64, AstralError> {
    let request_operation_id = validated_request_operation_id(new.request_operation_id.as_deref())?;
    validate_create_card_ledger_scope(new)?;
    let tenant_id = new.tenant_id.ok_or_else(|| {
        AstralError::Validation("admitted card creation requires a tenant scope".into())
    })?;
    validate_create_card_tenant_binding(tenant_id)?;
    let user_id = new.user_id.filter(|id| *id > 0).ok_or_else(|| {
        AstralError::Validation("admitted card creation requires a positive owner".into())
    })?;
    let actor_id = admission
        .proof()
        .scope
        .user_id
        .filter(|id| *id > 0)
        .ok_or_else(|| AstralError::Permission("card creation requires a verified actor".into()))?;
    let operation_id = admission.operation_id().to_owned();
    if request_operation_id
        .as_ref()
        .is_some_and(|id| id != &operation_id)
    {
        return Err(AstralError::Permission(
            "card create request and admission operation differ".into(),
        ));
    }
    let delivery = repository.delivery_context.as_ref().ok_or_else(|| {
        AstralError::Pending("card creation requires the frozen delivery context".into())
    })?;
    let capability = SourceMutationCapability::user(admission.clone());
    let mut tx = begin_source_transaction_with_capability_and_optional_delivery_context(
        &repository.db,
        &capability,
        Some(delivery),
    )
    .await?;
    let locked_tenant: Option<i64> = sqlx::query_scalar(CREATE_CARD_TENANT_LOCK_SQL)
        .bind(tenant_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_error)?;
    if locked_tenant != Some(tenant_id) {
        return Err(AstralError::Validation(
            "refusing to bind user_card.tenant_id to a missing tenant".into(),
        ));
    }
    lock_target_user(&mut tx, user_id, tenant_id, new.domain_id).await?;
    let mut capture = EligibilitySourceCapture::begin_card_create_in_tx(
        &mut tx,
        &admission,
        CardCreateInsertSpec {
            user_id,
            tenant_id,
            domain_id: new.domain_id,
            card_type: new.card_type.clone(),
            template_id: new.template_id,
            level_id: new.level_id,
            priority: new.priority,
            is_primary: new.is_primary,
        },
    )
    .await
    .map_err(AstralError::from)?;
    let card_id = capture.created_card_id().ok_or_else(|| {
        AstralError::Internal("closed card create did not return its generated id".into())
    })?;
    let rule_sets = match new.template_id {
        Some(template_id) => sqlx::query_as::<_, LockedTemplateRuleSetRow>(
            "SELECT rs.rule_set_id, rs.tenant_id, h.source_generation \
             FROM rule_set rs LEFT JOIN authorization_projection_head h \
               ON h.aggregate_type = 'RULE_SET' AND h.aggregate_id = rs.rule_set_id \
             WHERE rs.source_type = 'TEMPLATE' AND rs.source_id = ? AND rs.enabled = 1 \
             ORDER BY rs.rule_set_id ASC LIMIT 1025 FOR UPDATE",
        )
        .bind(template_id)
        .fetch_all(&mut **capture.with_tx_mut())
        .await
        .map_err(db_error)?,
        None => Vec::new(),
    };
    if rule_sets.len() > 1024 {
        return Err(AstralError::Validation(
            "card template binding capacity exceeded".into(),
        ));
    }
    ensure_unique_template_rule_set_ids(&rule_sets)?;
    let mut has_grants = false;
    for row in &rule_sets {
        validate_binding_tenants(row.tenant_id, Some(tenant_id))?;
        let effects: Vec<String> = sqlx::query_scalar(
            "SELECT effect FROM rule_set_entry WHERE rule_set_id = ? AND enabled = 1 \
             ORDER BY entry_id LIMIT 1025 FOR UPDATE",
        )
        .bind(row.rule_set_id)
        .fetch_all(&mut **capture.with_tx_mut())
        .await
        .map_err(db_error)?;
        if effects.len() > 1024 {
            return Err(AstralError::Validation(
                "card template entry capacity exceeded".into(),
            ));
        }
        for effect in effects {
            if effect.trim().eq_ignore_ascii_case("ALLOW") {
                has_grants = true;
            } else if !effect.trim().eq_ignore_ascii_case("DENY") {
                return Err(AstralError::Validation(
                    "card template entry has an unknown effect".into(),
                ));
            }
        }
    }
    let parent = astral_db::append_projection_event_with_metadata_in_tx(
        capture.with_tx_mut(),
        ProjectionAggregate::Card,
        card_id,
        "CARD_CREATED",
        Some(astral_db::ProjectionEventMetadata {
            actor_id,
            operation_id: &operation_id,
        }),
    )
    .await?;
    let (eligibility_projection, eligibility_invalidation) =
        append_eligibility_projection_with_invalidation_on_raw_tx(
            capture.with_tx_mut(),
            delivery,
            card_id,
            &operation_id,
        )
        .await?;
    let detail = serde_json::json!({
        "targetCardId": card_id, "targetUserId": user_id, "actorId": actor_id,
        "tenantId": tenant_id, "domainId": new.domain_id, "templateId": new.template_id,
        "operationId": operation_id, "parentSourceEventId": parent.event_id,
    })
    .to_string();
    let audit = sqlx::query(
        "INSERT INTO audit_log \
         (user_id, card_id, action, resource, decision, event_type, request_id, domain_id, tenant_id, detail) \
         VALUES (?, ?, 'card_create', 'user_card', 'CARD_CREATED', 'USER_CARD_MUTATION', ?, ?, ?, ?)",
    )
    .bind(actor_id)
    .bind(card_id)
    .bind(&operation_id)
    .bind(new.domain_id)
    .bind(tenant_id)
    .bind(detail)
    .execute(&mut **capture.with_tx_mut())
    .await
    .map_err(db_error)?;
    if audit.rows_affected() != 1 || audit.last_insert_id() == 0 {
        return Err(AstralError::Internal(
            "card create audit insert has no exact identity".into(),
        ));
    }
    let origin = if has_grants {
        capture.finish_publication_in_tx().await
    } else {
        capture.finish_in_tx().await
    }
    .map_err(AstralError::from)?;
    tx.record_source_projection_identity(ProjectionAggregate::Card, card_id, parent.clone())?;
    tx.record_source_projection_receipt(eligibility_projection)?;
    tx.record_invalidation_receipt(eligibility_invalidation);
    if has_grants {
        tx.stage_card_publication_origin(origin)?;
    } else {
        tx.stage_eligibility_source(origin)?;
    }
    let context =
        RuleSetMutationContext::user_with_admission(actor_id, Some(&operation_id), admission)?;
    let mut actual_grants = false;
    for row in rule_sets {
        let binding_before = tx
            .begin_card_create_binding(CardCreateBindingStart {
                rule_set_id: row.rule_set_id,
                card_id,
                user_id,
                tenant_id,
                domain_id: new.domain_id,
                operation_id: operation_id.clone(),
            })
            .await?;
        ensure_rule_set_projection_in_tx(
            &mut tx,
            row.rule_set_id,
            row.tenant_id,
            actor_id,
            &operation_id,
        )
        .await?;
        let inserted_ref = sqlx::query(
            "INSERT INTO card_rule_set_ref \
             (card_id, rule_set_id, ref_type, tenant_id) VALUES (?, ?, 'BASE', ?)",
        )
        .bind(card_id)
        .bind(row.rule_set_id)
        .bind(tenant_id)
        .execute(&mut **tx)
        .await
        .map_err(db_error)?;
        let ref_id = i64::try_from(inserted_ref.last_insert_id())
            .ok()
            .filter(|id| *id > 0 && inserted_ref.rows_affected() == 1)
            .ok_or_else(|| {
                AstralError::Internal("card_rule_set_ref insert returned an unusable id".into())
            })?;
        let rule_projection = append_rule_set_projection_in_tx(
            &mut tx,
            row.rule_set_id,
            EVENT_TYPE_RULE_SET_UPDATE,
            astral_db::ProjectionEventMetadata {
                actor_id,
                operation_id: &operation_id,
            },
        )
        .await?;
        let addition = append_card_create_ruleset_entry_adds_in_tx(
            &mut tx,
            row.rule_set_id,
            &parent,
            &context,
            ref_id,
            card_id,
            user_id,
            tenant_id,
            new.domain_id,
            "BASE",
        )
        .await?;
        actual_grants |= !addition.added_entries.is_empty();
        let detail = serde_json::json!({
            "cardId": card_id, "tenantId": tenant_id, "templateId": new.template_id,
            "refId": ref_id, "refType": "BASE", "parentSourceEventId": parent.event_id,
            "contributionEventIds": addition.added_entries.iter().map(|entry| entry.event_id.as_str()).collect::<Vec<_>>(),
            "ruleSetEntryIds": addition.added_entries.iter().map(|entry| entry.entry_id).collect::<Vec<_>>(),
            "boundCardIds": vec![card_id; addition.added_entries.len()],
            "bindingRefIds": vec![ref_id; addition.added_entries.len()],
        }).to_string();
        insert_rule_set_projection_audit_in_tx(
            &mut tx,
            &RuleSetProjectionAuditEntry {
                rule_set_id: row.rule_set_id,
                entry_id: None,
                aggregate_type: ProjectionAggregate::RuleSet.as_str(),
                aggregate_id: row.rule_set_id,
                event_id: &rule_projection.event_id,
                source_generation: rule_projection.source_generation,
                operation_id: &operation_id,
                actor_id,
                change_type: "BIND_CARD",
                old_value_json: None,
                new_value_json: Some(&detail),
                tenant_id: rule_projection.tenant_id,
            },
        )
        .await?;
        tx.finish_card_create_binding(
            binding_before,
            ref_id,
            &rule_projection,
            &parent,
            &addition,
            actor_id,
        )
        .await?;
    }
    if actual_grants != has_grants {
        return Err(AstralError::Pending(
            "card template grant classification changed under lock".into(),
        ));
    }
    tx.commit_consuming().await?;
    Ok(card_id)
}

async fn lock_target_user(
    tx: &mut AuthorizationSourceTransaction,
    user_id: i64,
    tenant_id: i64,
    domain_id: Option<i64>,
) -> Result<(), AstralError> {
    let users: Vec<i64> = sqlx::query_scalar(
        "SELECT u.user_id FROM platform_user u \
         INNER JOIN identity_card ic ON ic.user_id = u.user_id AND ic.status = 'ACTIVE' \
           AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
         INNER JOIN tenant t ON t.tenant_id = ? AND t.status = 'ACTIVE' \
         INNER JOIN tenant_user_map tum ON tum.tenant_id = t.tenant_id \
           AND tum.user_id = u.user_id AND tum.status = 'ACTIVE' \
         WHERE u.user_id = ? AND u.status = 'ACTIVE' AND u.deleted_at IS NULL \
         LIMIT 2 FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(user_id)
    .fetch_all(&mut ***tx)
    .await
    .map_err(db_error)?;
    if users.as_slice() != [user_id] {
        return Err(AstralError::Permission(
            "card owner is not an active tenant member".into(),
        ));
    }
    if let Some(domain_id) = domain_id {
        let domains: Vec<i64> = sqlx::query_scalar(
            "SELECT domain_id FROM tenant_domain_map \
             WHERE tenant_id = ? AND domain_id = ? AND status = 'ACTIVE' LIMIT 2 FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(domain_id)
        .fetch_all(&mut ***tx)
        .await
        .map_err(db_error)?;
        if domains.as_slice() != [domain_id] {
            return Err(AstralError::Permission(
                "card domain is not active for its tenant".into(),
            ));
        }
    }
    Ok(())
}
