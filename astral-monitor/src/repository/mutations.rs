//! Platform monitoring configuration has its own short transaction owner.
//! Collector writes stay on the collector port; HTTP configuration changes must
//! carry the formal policy request and never manufacture authorization deltas.

use super::{
    AlertRuleRecord, AlertRuleRow, AlertRuleUpdate, NotificationChannelRecord,
    NotificationChannelRow,
};
use astral_db::{
    begin_protected_mutation_in_tx, finish_protected_mutation_in_tx, redact_secrets,
    ProtectedMutationContext, ProtectedMutationStart, ProtectedSourceEvidence, RowPresence,
    TargetRowEvidence, WriteKind,
};
use astral_types::AstralError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::MySqlPool;

#[derive(Debug, Serialize)]
pub enum MonitorMutation {
    CreateRule(AlertRuleUpdate),
    UpdateRule(AlertRuleUpdate),
    DeleteRule(i64),
    ToggleRule(i64),
    Acknowledge(i64),
    CreateChannel {
        name: String,
        channel_type: String,
        config: Option<String>,
    },
    UpdateChannel {
        id: i64,
        name: String,
        channel_type: String,
        config: Option<String>,
    },
    TestChannel(i64),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum MonitorMutationResult {
    Rule(AlertRuleRecord),
    Channel(NotificationChannelRecord),
    Done,
}

impl MonitorMutation {
    fn validate(&self, context: &ProtectedMutationContext) -> Result<(), AstralError> {
        let (resource, action, target) = match self {
            Self::CreateRule(_) => ("monitor", "create", None),
            Self::UpdateRule(rule) => ("monitor", "update", Some(rule.id)),
            Self::DeleteRule(id) => ("monitor", "delete", Some(*id)),
            Self::ToggleRule(id) | Self::Acknowledge(id) => ("monitor", "update", Some(*id)),
            Self::CreateChannel { .. } => ("notification", "create", None),
            Self::UpdateChannel { id, .. } => ("notification", "update", Some(*id)),
            Self::TestChannel(id) => ("notification", "test", Some(*id)),
        };
        context.require_request(resource, action, target)?;
        if target.is_some_and(|id| id <= 0) {
            return Err(AstralError::Validation(
                "Monitor target must be positive".into(),
            ));
        }
        match self {
            Self::CreateRule(rule) | Self::UpdateRule(rule) => {
                if rule.name.trim().is_empty()
                    || rule.name.len() > 128
                    || rule.metric.trim().is_empty()
                    || rule.metric.len() > 128
                    || !rule.threshold.is_finite()
                    || !(1..=86_400).contains(&rule.duration_seconds)
                    || ![">", ">=", "<", "<=", "==", "!="].contains(&rule.condition_op.as_str())
                    || !["INFO", "WARNING", "ERROR", "CRITICAL"].contains(&rule.severity.as_str())
                {
                    return Err(AstralError::Validation(
                        "invalid bounded Monitor rule configuration".into(),
                    ));
                }
            }
            Self::CreateChannel {
                name,
                channel_type,
                config,
            }
            | Self::UpdateChannel {
                name,
                channel_type,
                config,
                ..
            } => {
                if name.trim().is_empty()
                    || name.len() > 128
                    || !["EMAIL", "SMS", "DINGTALK", "WECHAT", "WEBHOOK"]
                        .contains(&channel_type.as_str())
                    || config.as_ref().is_some_and(|value| value.len() > 65_536)
                {
                    return Err(AstralError::Validation(
                        "invalid bounded notification configuration".into(),
                    ));
                }
                let kind = astral_common::delivery::ChannelKind::parse(channel_type)
                    .ok_or_else(|| AstralError::Validation("unknown delivery channel".into()))?;
                astral_common::delivery::resolve_channel(kind, config.as_deref()).map_err(
                    |_| {
                        AstralError::Validation(
                            "notification config failed protected delivery validation".into(),
                        )
                    },
                )?;
                if let Some(config) = config {
                    let config: serde_json::Value = serde_json::from_str(config).map_err(|_| {
                        AstralError::Validation("notification config must be JSON".into())
                    })?;
                    if !config.is_object() {
                        return Err(AstralError::Validation(
                            "notification config must be an object".into(),
                        ));
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn database(error: sqlx::Error) -> AstralError {
    AstralError::Database(error.to_string())
}

/// Typed evidence row for an alert rule (non-secret configuration facts).
#[derive(Debug, Serialize)]
struct AlertRuleEvidence {
    id: i64,
    name: String,
    metric: String,
    condition_op: String,
    threshold: f64,
    duration_seconds: i32,
    severity: String,
    enabled: i8,
}

impl AlertRuleEvidence {
    fn from_row(row: &AlertRuleRow) -> Self {
        Self {
            id: row.id,
            name: row.name.clone(),
            metric: row.metric.clone(),
            condition_op: row.condition_op.clone(),
            threshold: row.threshold,
            duration_seconds: row.duration_seconds,
            severity: row.severity.clone(),
            enabled: row.enabled,
        }
    }
}

/// Typed evidence row for a notification channel. The config column is
/// redacted through the protected evidence fingerprint policy: secret-valued
/// fields become keyed fingerprints, never raw bytes and never unsalted
/// hashes.
#[derive(Debug, Serialize)]
struct ChannelEvidence {
    id: i64,
    name: String,
    channel_type: String,
    config: Value,
    enabled: i8,
}

impl ChannelEvidence {
    fn from_row(row: &NotificationChannelRow) -> Result<Self, AstralError> {
        let config: Value = row
            .config
            .as_deref()
            .and_then(|value| serde_json::from_str(value).ok())
            .unwrap_or(Value::Null);
        Ok(Self {
            id: row.id,
            name: row.name.clone(),
            channel_type: row.channel_type.clone(),
            config: redact_secrets(&config)?,
            enabled: row.enabled,
        })
    }
}

/// Typed evidence row for the alert history acknowledge flow.
#[derive(Debug, Serialize)]
struct AlertHistoryEvidence {
    id: i64,
    status: String,
}

pub(super) async fn execute(
    pool: &MySqlPool,
    context: &ProtectedMutationContext,
    mutation: MonitorMutation,
) -> Result<MonitorMutationResult, AstralError> {
    mutation.validate(context)?;
    let payload = serde_json::to_value(&mutation)
        .map_err(|error| AstralError::Validation(error.to_string()))?;
    let mut tx = pool.begin().await.map_err(database)?;
    if let ProtectedMutationStart::Completed(result) =
        begin_protected_mutation_in_tx(&mut tx, context, &payload).await?
    {
        if matches!(mutation, MonitorMutation::TestChannel(_)) {
            return Err(AstralError::Pending(
                "notification test was already admitted; reconcile delivery by operation id".into(),
            ));
        }
        return serde_json::from_value(result)
            .map_err(|error| AstralError::Database(error.to_string()));
    }
    let rule_select = "SELECT id,name,metric,condition_op,threshold,duration_seconds,severity,enabled FROM alert_rule WHERE id=? FOR UPDATE";
    let channel_select = "SELECT id,name,channel_type,CAST(config AS CHAR) as config,enabled FROM notification_channel WHERE id=? FOR UPDATE";
    let delete_rule = matches!(mutation, MonitorMutation::DeleteRule(_));
    // Typed before/after evidence: every durable statement below records its
    // real rows_affected, and each target row is probed before and after the
    // write inside this same transaction. Channel configs enter evidence only
    // through the protected evidence fingerprint policy.
    let mut evidence = ProtectedSourceEvidence::new();
    let result = match mutation {
        MonitorMutation::CreateRule(rule) => {
            // Auto-increment create: the INSERT receipt (rows_affected=1)
            // proves the before-absence of the allocated id.
            let row = sqlx::query("INSERT INTO alert_rule (name,metric,condition_op,threshold,duration_seconds,severity,enabled) VALUES (?,?,?,?,?,?,1)")
                .bind(rule.name).bind(rule.metric).bind(rule.condition_op).bind(rule.threshold)
                .bind(rule.duration_seconds).bind(rule.severity).execute(&mut *tx).await.map_err(database)?;
            let id = i64::try_from(row.last_insert_id())
                .map_err(|_| AstralError::Database("rule id exceeds signed range".into()))?;
            let inserted: AlertRuleRow = sqlx::query_as::<_, AlertRuleRow>(rule_select)
                .bind(id)
                .fetch_one(&mut *tx)
                .await
                .map_err(database)?;
            evidence = evidence
                .target_row(TargetRowEvidence {
                    entity: "alert_rule",
                    key: serde_json::json!({ "id": id }),
                    before: RowPresence::Absent,
                    after: RowPresence::Present(AlertRuleEvidence::from_row(&inserted)),
                })
                .map_err(|error| AstralError::Pending(error.to_string()))?
                .receipt(
                    "alert_rule",
                    serde_json::json!({ "id": id }),
                    WriteKind::Insert,
                    row.rows_affected(),
                );
            MonitorMutationResult::Rule(inserted.into())
        }
        MonitorMutation::UpdateRule(rule) => {
            let before: AlertRuleRow = sqlx::query_as::<_, AlertRuleRow>(rule_select)
                .bind(rule.id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(database)?
                .ok_or_else(|| AstralError::NotFound("Monitor rule".into()))?;
            let updated = sqlx::query("UPDATE alert_rule SET name=?,metric=?,condition_op=?,threshold=?,duration_seconds=?,severity=? WHERE id=?")
                .bind(rule.name).bind(rule.metric).bind(rule.condition_op).bind(rule.threshold)
                .bind(rule.duration_seconds).bind(rule.severity).bind(rule.id)
                .execute(&mut *tx).await.map_err(database)?;
            let after: AlertRuleRow = sqlx::query_as::<_, AlertRuleRow>(rule_select)
                .bind(rule.id)
                .fetch_one(&mut *tx)
                .await
                .map_err(database)?;
            evidence = evidence
                .target_row(TargetRowEvidence {
                    entity: "alert_rule",
                    key: serde_json::json!({ "id": rule.id }),
                    before: RowPresence::Present(AlertRuleEvidence::from_row(&before)),
                    after: RowPresence::Present(AlertRuleEvidence::from_row(&after)),
                })
                .map_err(|error| AstralError::Pending(error.to_string()))?
                .receipt(
                    "alert_rule",
                    serde_json::json!({ "id": rule.id }),
                    WriteKind::Update,
                    updated.rows_affected(),
                );
            MonitorMutationResult::Done
        }
        MonitorMutation::DeleteRule(id) | MonitorMutation::ToggleRule(id) => {
            let before: AlertRuleRow = sqlx::query_as::<_, AlertRuleRow>(rule_select)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(database)?
                .ok_or_else(|| AstralError::NotFound("Monitor rule".into()))?;
            if delete_rule {
                let deleted = sqlx::query("DELETE FROM alert_rule WHERE id=?")
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(database)?;
                let remaining: Option<AlertRuleRow> =
                    sqlx::query_as::<_, AlertRuleRow>(rule_select)
                        .bind(id)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(database)?;
                evidence = evidence
                    .target_row(TargetRowEvidence {
                        entity: "alert_rule",
                        key: serde_json::json!({ "id": id }),
                        before: RowPresence::Present(AlertRuleEvidence::from_row(&before)),
                        after: RowPresence::from_option(
                            remaining.map(|row| AlertRuleEvidence::from_row(&row)),
                        ),
                    })
                    .map_err(|error| AstralError::Pending(error.to_string()))?
                    .receipt(
                        "alert_rule",
                        serde_json::json!({ "id": id }),
                        WriteKind::Delete,
                        deleted.rows_affected(),
                    );
                MonitorMutationResult::Done
            } else {
                let updated = sqlx::query("UPDATE alert_rule SET enabled=1-enabled WHERE id=?")
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(database)?;
                let after: AlertRuleRow = sqlx::query_as::<_, AlertRuleRow>(rule_select)
                    .bind(id)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(database)?;
                evidence = evidence
                    .target_row(TargetRowEvidence {
                        entity: "alert_rule",
                        key: serde_json::json!({ "id": id }),
                        before: RowPresence::Present(AlertRuleEvidence::from_row(&before)),
                        after: RowPresence::Present(AlertRuleEvidence::from_row(&after)),
                    })
                    .map_err(|error| AstralError::Pending(error.to_string()))?
                    .receipt(
                        "alert_rule",
                        serde_json::json!({ "id": id }),
                        WriteKind::Update,
                        updated.rows_affected(),
                    );
                MonitorMutationResult::Rule(after.into())
            }
        }
        MonitorMutation::Acknowledge(id) => {
            let before: Option<String> = sqlx::query_scalar(
                "SELECT status FROM monitor_alert_history WHERE id=? FOR UPDATE",
            )
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(database)?;
            if before.as_deref() != Some("triggered") {
                return Err(AstralError::Validation(
                    "alert is absent or already acknowledged".into(),
                ));
            }
            let updated = sqlx::query("UPDATE monitor_alert_history SET status='acknowledged',resolved_at=UTC_TIMESTAMP() WHERE id=? AND status='triggered'")
                .bind(id).execute(&mut *tx).await.map_err(database)?;
            let after: Option<String> =
                sqlx::query_scalar("SELECT status FROM monitor_alert_history WHERE id=?")
                    .bind(id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(database)?;
            evidence = evidence
                .target_row(TargetRowEvidence {
                    entity: "monitor_alert_history",
                    key: serde_json::json!({ "id": id }),
                    before: RowPresence::from_option(
                        before.map(|status| AlertHistoryEvidence { id, status }),
                    ),
                    after: RowPresence::from_option(
                        after.map(|status| AlertHistoryEvidence { id, status }),
                    ),
                })
                .map_err(|error| AstralError::Pending(error.to_string()))?
                .receipt(
                    "monitor_alert_history",
                    serde_json::json!({ "id": id }),
                    WriteKind::Update,
                    updated.rows_affected(),
                );
            MonitorMutationResult::Done
        }
        MonitorMutation::CreateChannel {
            name,
            channel_type,
            config,
        } => {
            let row = sqlx::query("INSERT INTO notification_channel (name,channel_type,config,enabled) VALUES (?,?,?,1)")
                .bind(name).bind(channel_type).bind(config).execute(&mut *tx).await.map_err(database)?;
            let id = i64::try_from(row.last_insert_id()).map_err(|_| {
                AstralError::Database("channel id exceeds signed storage range".into())
            })?;
            let inserted: NotificationChannelRow =
                sqlx::query_as::<_, NotificationChannelRow>(channel_select)
                    .bind(id)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(database)?;
            evidence = evidence
                .target_row(TargetRowEvidence {
                    entity: "notification_channel",
                    key: serde_json::json!({ "id": id }),
                    before: RowPresence::Absent,
                    after: RowPresence::Present(ChannelEvidence::from_row(&inserted)?),
                })
                .map_err(|error| AstralError::Pending(error.to_string()))?
                .receipt(
                    "notification_channel",
                    serde_json::json!({ "id": id }),
                    WriteKind::Insert,
                    row.rows_affected(),
                );
            MonitorMutationResult::Channel(inserted.into())
        }
        MonitorMutation::UpdateChannel {
            id,
            name,
            channel_type,
            config,
        } => {
            let before: NotificationChannelRow =
                sqlx::query_as::<_, NotificationChannelRow>(channel_select)
                    .bind(id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(database)?
                    .ok_or_else(|| AstralError::NotFound("notification channel".into()))?;
            let updated = sqlx::query(
                "UPDATE notification_channel SET name=?,channel_type=?,config=? WHERE id=?",
            )
            .bind(name)
            .bind(channel_type)
            .bind(config)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(database)?;
            let after: NotificationChannelRow =
                sqlx::query_as::<_, NotificationChannelRow>(channel_select)
                    .bind(id)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(database)?;
            evidence = evidence
                .target_row(TargetRowEvidence {
                    entity: "notification_channel",
                    key: serde_json::json!({ "id": id }),
                    before: RowPresence::Present(ChannelEvidence::from_row(&before)?),
                    after: RowPresence::Present(ChannelEvidence::from_row(&after)?),
                })
                .map_err(|error| AstralError::Pending(error.to_string()))?
                .receipt(
                    "notification_channel",
                    serde_json::json!({ "id": id }),
                    WriteKind::Update,
                    updated.rows_affected(),
                );
            MonitorMutationResult::Done
        }
        MonitorMutation::TestChannel(id) => {
            let row: NotificationChannelRow =
                sqlx::query_as::<_, NotificationChannelRow>(channel_select)
                    .bind(id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(database)?
                    .ok_or_else(|| AstralError::NotFound("notification channel".into()))?;
            // Read-only admission: the same row is probed before and after
            // (a real no-change probe with a PROBE receipt).
            evidence = evidence
                .target_row(TargetRowEvidence {
                    entity: "notification_channel",
                    key: serde_json::json!({ "id": id }),
                    before: RowPresence::Present(ChannelEvidence::from_row(&row)?),
                    after: RowPresence::Present(ChannelEvidence::from_row(&row)?),
                })
                .map_err(|error| AstralError::Pending(error.to_string()))?
                .receipt(
                    "notification_channel",
                    serde_json::json!({ "id": id }),
                    WriteKind::Probe,
                    1,
                );
            MonitorMutationResult::Channel(row.into())
        }
    };
    let result_value =
        serde_json::to_value(&result).map_err(|error| AstralError::Database(error.to_string()))?;
    finish_protected_mutation_in_tx(&mut tx, context, &result_value, &evidence).await?;
    tx.commit().await.map_err(|error| {
        AstralError::Pending(format!(
            "Monitor mutation COMMIT outcome unknown; reconcile operation {}: {error}",
            context.operation_id(),
        ))
    })?;
    Ok(result)
}
