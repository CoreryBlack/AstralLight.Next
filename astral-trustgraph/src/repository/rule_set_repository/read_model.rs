use astral_types::{CardRuleSetBinding, RuleSetDefinition, RuleSetEntryDefinition};
use time::PrimitiveDateTime;

use super::CardRuleSetBindingView;

pub(super) const RULE_SET_SELECT: &str =
    "rule_set_id, name, code, description, source_type, source_id, enabled, created_at, \
     updated_at, tenant_id";
pub(super) const ENTRY_SELECT: &str =
    "entry_id, rule_set_id, resource_type, resource_id, action_code, effect, condition_json, \
     priority, enabled, valid_from, valid_to, created_at, updated_at, tenant_id";

#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct RuleSetSqlRow {
    rule_set_id: i64,
    name: String,
    code: String,
    description: Option<String>,
    source_type: String,
    source_id: Option<i64>,
    enabled: i32,
    created_at: PrimitiveDateTime,
    updated_at: PrimitiveDateTime,
    tenant_id: Option<i64>,
}

impl From<RuleSetSqlRow> for RuleSetDefinition {
    fn from(row: RuleSetSqlRow) -> Self {
        Self {
            rule_set_id: row.rule_set_id,
            name: row.name,
            code: row.code,
            description: row.description,
            source_type: row.source_type,
            source_id: row.source_id,
            enabled: row.enabled != 0,
            created_at: row.created_at.assume_utc(),
            updated_at: row.updated_at.assume_utc(),
            tenant_id: row.tenant_id,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct RuleSetEntrySqlRow {
    entry_id: i64,
    rule_set_id: i64,
    resource_type: String,
    resource_id: Option<i64>,
    action_code: String,
    effect: String,
    condition_json: Option<String>,
    priority: i32,
    enabled: i32,
    valid_from: Option<PrimitiveDateTime>,
    valid_to: Option<PrimitiveDateTime>,
    created_at: PrimitiveDateTime,
    updated_at: PrimitiveDateTime,
    tenant_id: Option<i64>,
}

impl From<RuleSetEntrySqlRow> for RuleSetEntryDefinition {
    fn from(row: RuleSetEntrySqlRow) -> Self {
        Self {
            entry_id: row.entry_id,
            rule_set_id: row.rule_set_id,
            resource_type: row.resource_type,
            resource_id: row.resource_id,
            action_code: row.action_code,
            effect: row.effect,
            condition_json: row.condition_json,
            priority: row.priority,
            enabled: row.enabled != 0,
            valid_from: row.valid_from.map(PrimitiveDateTime::assume_utc),
            valid_to: row.valid_to.map(PrimitiveDateTime::assume_utc),
            created_at: row.created_at.assume_utc(),
            updated_at: row.updated_at.assume_utc(),
            tenant_id: row.tenant_id,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub(super) struct CardRuleSetBindingSqlRow {
    id: i64,
    card_id: i64,
    rule_set_id: i64,
    ref_type: String,
    created_at: PrimitiveDateTime,
    tenant_id: Option<i64>,
    rule_set_name: String,
    rule_set_code: String,
}

impl From<CardRuleSetBindingSqlRow> for CardRuleSetBindingView {
    fn from(row: CardRuleSetBindingSqlRow) -> Self {
        Self {
            binding: CardRuleSetBinding {
                id: row.id,
                card_id: row.card_id,
                rule_set_id: row.rule_set_id,
                ref_type: row.ref_type,
                created_at: row.created_at.assume_utc(),
                tenant_id: row.tenant_id,
            },
            rule_set_name: row.rule_set_name,
            rule_set_code: row.rule_set_code,
        }
    }
}
