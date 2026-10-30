use astral_types::{BindingLayer, CanonicalGrant, GrantEffect, GrantSourceKind};
use sqlx::MySqlPool;

#[derive(sqlx::FromRow)]
struct RuleSetSourceBindingRow {
    rule_set_id: i64,
    resource_type: String,
    resource_id: Option<i64>,
    action_code: String,
    effect: String,
    source_tenant_id: Option<i64>,
    binding_id: i64,
    card_id: i64,
    ref_type: String,
    binding_tenant_id: Option<i64>,
}

pub async fn assert_ruleset_source_binding(
    pool: &MySqlPool,
    grant: &CanonicalGrant,
    tenant_id: i64,
    card_id: i64,
    rule_set_id: i64,
) {
    assert_eq!(grant.source_kind, GrantSourceKind::RuleSet);
    assert_eq!(grant.binding_layer, BindingLayer::Base);
    assert_eq!(grant.effect, GrantEffect::Allow);
    assert_eq!(grant.tenant.tenant_id, tenant_id);
    assert_eq!(grant.card_id, card_id);
    assert_eq!(grant.provenance.source_id, rule_set_id.to_string());

    let entry_id = grant
        .provenance
        .source_entry
        .as_deref()
        .expect("production grant must identify its source entry")
        .parse::<i64>()
        .expect("production source entry identity must be numeric");
    let binding_id = grant
        .provenance
        .binding_id
        .as_deref()
        .expect("production grant must identify its card binding")
        .parse::<i64>()
        .expect("production binding identity must be numeric");

    let source = sqlx::query_as::<_, RuleSetSourceBindingRow>(
        "SELECT e.rule_set_id, e.resource_type, e.resource_id, e.action_code, e.effect, \
         rs.tenant_id AS source_tenant_id, b.id AS binding_id, b.card_id, b.ref_type, \
         b.tenant_id AS binding_tenant_id \
         FROM rule_set_entry e INNER JOIN rule_set rs ON rs.rule_set_id = e.rule_set_id \
         INNER JOIN card_rule_set_ref b \
           ON b.id = ? AND b.card_id = ? AND b.rule_set_id = e.rule_set_id \
         WHERE e.entry_id = ? AND e.rule_set_id = ?",
    )
    .bind(binding_id)
    .bind(card_id)
    .bind(entry_id)
    .bind(rule_set_id)
    .fetch_one(pool)
    .await
    .expect("published grant must resolve to its real RuleSet source and BASE binding");

    assert_eq!(source.rule_set_id, rule_set_id);
    assert_eq!(source.resource_type, "learn_subject");
    assert_eq!(source.resource_id, None);
    assert_eq!(source.action_code, "read");
    assert_eq!(source.effect, "ALLOW");
    assert_eq!(source.source_tenant_id, Some(tenant_id));
    assert_eq!(source.binding_id, binding_id);
    assert_eq!(source.card_id, card_id);
    assert_eq!(source.ref_type, "BASE");
    assert_eq!(source.binding_tenant_id, Some(tenant_id));
}
