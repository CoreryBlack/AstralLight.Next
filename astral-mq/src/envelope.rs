//! Transport-neutral message envelope shared by the local outbox and Rabbit adapter.
//!
//! Broker-specific delivery metadata (delivery tags, x-death, ACK/NACK) must
//! stay outside this type. The envelope carries the fields needed to validate
//! scope, deduplicate effects, and reconcile an unknown transport result.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MessageEnvelope {
    pub message_id: String,
    pub operation_id: String,
    pub message_type: String,
    pub schema_version: i32,
    pub tenant_id: Option<i64>,
    pub origin_region: String,
    pub target_region: Option<String>,
    pub ordering_key: Option<String>,
    pub trace_id: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub payload_sha256: String,
    pub payload: Value,
}

impl MessageEnvelope {
    pub fn new(
        message_id: impl Into<String>,
        operation_id: impl Into<String>,
        message_type: impl Into<String>,
        schema_version: i32,
        origin_region: impl Into<String>,
        payload: Value,
    ) -> Result<Self, String> {
        let payload_sha256 = payload_digest(&payload)?;
        Ok(Self {
            message_id: message_id.into(),
            operation_id: operation_id.into(),
            message_type: message_type.into(),
            schema_version,
            tenant_id: None,
            origin_region: origin_region.into(),
            target_region: None,
            ordering_key: None,
            trace_id: None,
            created_at: astral_mq_timestamp(),
            expires_at: None,
            payload_sha256,
            payload,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("messageId", self.message_id.as_str()),
            ("operationId", self.operation_id.as_str()),
            ("messageType", self.message_type.as_str()),
            ("originRegion", self.origin_region.as_str()),
            ("createdAt", self.created_at.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(format!("{name} is required"));
            }
        }
        if self.schema_version <= 0 {
            return Err("schemaVersion must be positive".into());
        }
        if self.tenant_id.is_some_and(|tenant_id| tenant_id <= 0) {
            return Err("tenantId must be positive when present".into());
        }
        if let Some(target) = &self.target_region {
            if target.trim().is_empty() {
                return Err("targetRegion must not be blank when present".into());
            }
        }
        if self.payload_sha256 != payload_digest(&self.payload)? {
            return Err("payload digest mismatch".into());
        }
        Ok(())
    }

    pub fn payload_json(&self) -> Result<String, String> {
        serde_json::to_string(&self.payload).map_err(|error| error.to_string())
    }

    /// Serialize the complete transport envelope for durable outbox storage.
    /// The payload digest remains the digest of the inner business payload.
    pub fn envelope_json(&self) -> Result<String, String> {
        serde_json::to_string(self).map_err(|error| error.to_string())
    }
}

pub fn payload_digest(payload: &Value) -> Result<String, String> {
    let canonical = serde_json::to_vec(payload).map_err(|error| error.to_string())?;
    Ok(format!("{:x}", Sha256::digest(canonical)))
}

fn astral_mq_timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn envelope_digest_is_stable_and_validated() {
        let mut envelope = MessageEnvelope::new(
            "message-1",
            "operation-1",
            "AUDIT_LOG",
            1,
            "local",
            json!({"action": "read", "tenantId": 7}),
        )
        .unwrap();
        envelope.validate().unwrap();
        envelope.payload["action"] = json!("write");
        assert!(envelope.validate().is_err());
    }

    #[test]
    fn full_envelope_round_trips_while_digest_covers_inner_payload() {
        let mut envelope = MessageEnvelope::new(
            "message-1",
            "operation-1",
            "EVIDENCE_INVALIDATED",
            1,
            "local",
            json!({"tenantId": 7, "cardId": 42}),
        )
        .unwrap();
        envelope.tenant_id = Some(7);
        envelope.ordering_key = Some("authorization:evidence:tenant/7".into());

        let encoded = envelope.envelope_json().unwrap();
        let decoded: MessageEnvelope = serde_json::from_str(&encoded).unwrap();
        decoded.validate().unwrap();
        assert_eq!(decoded, envelope);
        assert_eq!(decoded.payload, json!({"tenantId": 7, "cardId": 42}));
    }

    #[test]
    fn envelope_json_is_not_the_inner_payload_json() {
        let envelope = MessageEnvelope::new(
            "message-1",
            "operation-1",
            "EVIDENCE_INVALIDATED",
            1,
            "local",
            json!({"tenantId": 7}),
        )
        .unwrap();
        assert_ne!(
            envelope.envelope_json().unwrap(),
            envelope.payload_json().unwrap()
        );
    }

    #[test]
    fn envelope_rejects_invalid_scope() {
        let mut envelope = MessageEnvelope::new(
            "message-1",
            "operation-1",
            "AUDIT_LOG",
            1,
            "local",
            json!({}),
        )
        .unwrap();
        envelope.tenant_id = Some(0);
        assert!(envelope.validate().is_err());
    }
}
