//! Canonical RuleSet source records.
//!
//! These records mirror the active `rule_set`, `rule_set_entry`, and
//! `card_rule_set_ref` source tables. They deliberately do not depend on SQLx
//! so repositories can keep database row decoding private.

use serde::{Deserialize, Deserializer, Serializer};
use time::{format_description::well_known::Rfc3339, OffsetDateTime, UtcOffset};

/// Serde helpers for UTC RFC3339 values with a canonical `Z` suffix.
pub mod utc_rfc3339 {
    use super::*;

    fn format(value: &OffsetDateTime) -> Result<String, time::error::Format> {
        let encoded = value.to_offset(UtcOffset::UTC).format(&Rfc3339)?;
        if let Some(prefix) = encoded.strip_suffix("+00:00") {
            Ok(format!("{prefix}Z"))
        } else {
            Ok(encoded)
        }
    }

    pub fn serialize<S>(value: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format(value).map_err(serde::ser::Error::custom)?)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        OffsetDateTime::parse(&value, &Rfc3339)
            .map(|parsed| parsed.to_offset(UtcOffset::UTC))
            .map_err(serde::de::Error::custom)
    }

    pub mod option {
        use super::*;

        pub fn serialize<S>(
            value: &Option<OffsetDateTime>,
            serializer: S,
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match value {
                Some(value) => {
                    serializer.serialize_some(&format(value).map_err(serde::ser::Error::custom)?)
                }
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<OffsetDateTime>, D::Error>
        where
            D: Deserializer<'de>,
        {
            Option::<String>::deserialize(deserializer)?
                .map(|value| {
                    OffsetDateTime::parse(&value, &Rfc3339)
                        .map(|parsed| parsed.to_offset(UtcOffset::UTC))
                        .map_err(serde::de::Error::custom)
                })
                .transpose()
        }
    }
}

/// Complete source row for `rule_set`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetDefinition {
    pub rule_set_id: i64,
    pub name: String,
    pub code: String,
    pub description: Option<String>,
    pub source_type: String,
    pub source_id: Option<i64>,
    pub enabled: bool,
    #[serde(with = "utc_rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "utc_rfc3339")]
    pub updated_at: OffsetDateTime,
    pub tenant_id: Option<i64>,
}

/// Complete source row for `rule_set_entry`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetEntryDefinition {
    pub entry_id: i64,
    pub rule_set_id: i64,
    pub resource_type: String,
    pub resource_id: Option<i64>,
    pub action_code: String,
    pub effect: String,
    pub condition_json: Option<String>,
    pub priority: i32,
    pub enabled: bool,
    #[serde(with = "utc_rfc3339::option")]
    pub valid_from: Option<OffsetDateTime>,
    #[serde(with = "utc_rfc3339::option")]
    pub valid_to: Option<OffsetDateTime>,
    #[serde(with = "utc_rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "utc_rfc3339")]
    pub updated_at: OffsetDateTime,
    pub tenant_id: Option<i64>,
}

/// Complete source row for `card_rule_set_ref`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CardRuleSetBinding {
    pub id: i64,
    pub card_id: i64,
    pub rule_set_id: i64,
    pub ref_type: String,
    #[serde(with = "utc_rfc3339")]
    pub created_at: OffsetDateTime,
    pub tenant_id: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::{CardRuleSetBinding, RuleSetDefinition, RuleSetEntryDefinition};
    use serde_json::Value;
    use time::{Duration, OffsetDateTime, UtcOffset};

    fn utc_time() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_798_000_000)
            .expect("test timestamp")
            .to_offset(UtcOffset::UTC)
    }

    fn local_time() -> OffsetDateTime {
        utc_time().to_offset(UtcOffset::from_hms(5, 30, 0).expect("test offset"))
    }

    #[test]
    fn ruleset_definition_round_trips_every_source_field() {
        let created_at = utc_time();
        let value = RuleSetDefinition {
            rule_set_id: 7,
            name: "rules".into(),
            code: "rules-code".into(),
            description: Some("description".into()),
            source_type: "CUSTOM".into(),
            source_id: Some(88),
            enabled: true,
            created_at,
            updated_at: created_at + Duration::seconds(1),
            tenant_id: Some(11),
        };
        let json = serde_json::to_string(&value).expect("RuleSetDefinition must serialize");
        let fields: Value = serde_json::from_str(&json).expect("valid JSON");
        for field in [
            "ruleSetId",
            "name",
            "code",
            "description",
            "sourceType",
            "sourceId",
            "enabled",
            "createdAt",
            "updatedAt",
            "tenantId",
        ] {
            assert!(fields.get(field).is_some(), "missing source field {field}");
        }
        let decoded: RuleSetDefinition =
            serde_json::from_str(&json).expect("RuleSetDefinition must deserialize");
        assert_eq!(decoded.rule_set_id, value.rule_set_id);
        assert_eq!(decoded.name, value.name);
        assert_eq!(decoded.code, value.code);
        assert_eq!(decoded.description, value.description);
        assert_eq!(decoded.source_type, value.source_type);
        assert_eq!(decoded.source_id, value.source_id);
        assert_eq!(decoded.enabled, value.enabled);
        assert_eq!(decoded.created_at, value.created_at);
        assert_eq!(decoded.updated_at, value.updated_at);
        assert_eq!(decoded.tenant_id, value.tenant_id);
    }

    #[test]
    fn non_utc_source_times_are_normalized_to_rfc3339_z() {
        let local = local_time();
        let value = RuleSetDefinition {
            rule_set_id: 7,
            name: "rules".into(),
            code: "rules".into(),
            description: None,
            source_type: "CUSTOM".into(),
            source_id: None,
            enabled: true,
            created_at: local,
            updated_at: local,
            tenant_id: None,
        };
        let json = serde_json::to_string(&value).expect("RuleSetDefinition must serialize");
        assert!(json.contains("createdAt\":\"2026-12-23T"));
        assert!(json.contains("Z\""));
        assert!(!json.contains("+05:30"));
        let decoded: RuleSetDefinition =
            serde_json::from_str(&json).expect("normalized UTC value must deserialize");
        assert_eq!(decoded.created_at, local.to_offset(UtcOffset::UTC));
        assert_eq!(decoded.updated_at, local.to_offset(UtcOffset::UTC));
    }

    #[test]
    fn entry_and_binding_round_trip_nullable_fields_and_full_shapes() {
        let created_at = utc_time();
        let valid_from = local_time();
        let entry = RuleSetEntryDefinition {
            entry_id: 8,
            rule_set_id: 7,
            resource_type: "learn_course".into(),
            resource_id: Some(3),
            action_code: "read".into(),
            effect: "ALLOW".into(),
            condition_json: Some(r#"{"ownerOnly":true}"#.into()),
            priority: 4,
            enabled: true,
            valid_from: Some(valid_from),
            valid_to: None,
            created_at,
            updated_at: created_at,
            tenant_id: Some(11),
        };
        let entry_json = serde_json::to_string(&entry).expect("entry must serialize");
        let entry_fields: Value = serde_json::from_str(&entry_json).expect("valid entry JSON");
        for field in [
            "entryId",
            "ruleSetId",
            "resourceType",
            "resourceId",
            "actionCode",
            "effect",
            "conditionJson",
            "priority",
            "enabled",
            "validFrom",
            "validTo",
            "createdAt",
            "updatedAt",
            "tenantId",
        ] {
            assert!(
                entry_fields.get(field).is_some(),
                "missing entry field {field}"
            );
        }
        assert!(entry_json.contains("validFrom"));
        assert!(entry_json.contains("Z\""));
        assert!(entry_json.contains("\"validTo\":null"));
        let decoded_entry: RuleSetEntryDefinition =
            serde_json::from_str(&entry_json).expect("entry must deserialize");
        assert_eq!(decoded_entry.entry_id, entry.entry_id);
        assert_eq!(decoded_entry.rule_set_id, entry.rule_set_id);
        assert_eq!(decoded_entry.resource_type, entry.resource_type);
        assert_eq!(decoded_entry.resource_id, entry.resource_id);
        assert_eq!(decoded_entry.action_code, entry.action_code);
        assert_eq!(decoded_entry.effect, entry.effect);
        assert_eq!(decoded_entry.condition_json, entry.condition_json);
        assert_eq!(decoded_entry.priority, entry.priority);
        assert_eq!(decoded_entry.enabled, entry.enabled);
        assert_eq!(
            decoded_entry.valid_from,
            Some(valid_from.to_offset(UtcOffset::UTC))
        );
        assert_eq!(decoded_entry.valid_to, None);
        assert_eq!(decoded_entry.created_at, entry.created_at);
        assert_eq!(decoded_entry.updated_at, entry.updated_at);
        assert_eq!(decoded_entry.tenant_id, entry.tenant_id);

        let binding = CardRuleSetBinding {
            id: 9,
            card_id: 10,
            rule_set_id: 7,
            ref_type: "BASE".into(),
            created_at,
            tenant_id: Some(11),
        };
        let binding_json = serde_json::to_string(&binding).expect("binding must serialize");
        let binding_fields: Value =
            serde_json::from_str(&binding_json).expect("valid binding JSON");
        for field in [
            "id",
            "cardId",
            "ruleSetId",
            "refType",
            "createdAt",
            "tenantId",
        ] {
            assert!(
                binding_fields.get(field).is_some(),
                "missing binding field {field}"
            );
        }
        let decoded_binding: CardRuleSetBinding =
            serde_json::from_str(&binding_json).expect("binding must deserialize");
        assert_eq!(decoded_binding.id, binding.id);
        assert_eq!(decoded_binding.card_id, binding.card_id);
        assert_eq!(decoded_binding.rule_set_id, binding.rule_set_id);
        assert_eq!(decoded_binding.ref_type, binding.ref_type);
        assert_eq!(decoded_binding.created_at, binding.created_at);
        assert_eq!(decoded_binding.tenant_id, binding.tenant_id);
    }
}
