//! Transport-neutral message envelope shared by the local outbox and Rabbit adapter.
//!
//! Broker-specific delivery metadata (delivery tags, x-death, ACK/NACK) must
//! stay outside this type. The envelope carries the fields needed to validate
//! scope, deduplicate effects, and reconcile an unknown transport result.

use astral_types::AuthorizationMessageMetadata;
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
    /// Verified authority provenance, when this message is bound to an
    /// authorization proof. This is independent of the business payload and
    /// never derived from transport liveness or broker acknowledgements.
    #[serde(default)]
    pub authority_metadata: Option<AuthorizationMessageMetadata>,
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
            authority_metadata: None,
            payload,
        })
    }

    /// Attach provenance projected from a proof that has already passed the
    /// authority contract. This method performs no local-state lookup.
    pub fn with_authority_metadata(
        mut self,
        metadata: AuthorizationMessageMetadata,
    ) -> Result<Self, String> {
        metadata.validate().map_err(|error| error.to_string())?;
        self.authority_metadata = Some(metadata);
        self.validate()?;
        Ok(self)
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
        if let Some(metadata) = &self.authority_metadata {
            metadata.validate().map_err(|error| error.to_string())?;
        }
        if self.payload_sha256 != payload_digest(&self.payload)? {
            return Err("payload digest mismatch".into());
        }
        Ok(())
    }

    /// Serialize the independent durable authority provenance column.
    pub fn authority_metadata_json(&self) -> Result<Option<String>, String> {
        self.authority_metadata
            .as_ref()
            .map(|metadata| serde_json::to_string(metadata).map_err(|error| error.to_string()))
            .transpose()
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
    fn envelope_preserves_independent_authority_metadata() {
        let metadata = AuthorizationMessageMetadata {
            authorization_edition: astral_types::AUTHORIZATION_EDITION,
            authority_id: "authority-1".into(),
            authority_term: 4,
            global_fence_sequence: 9,
            key_id: "key-1".into(),
            key_epoch: 2,
            proof_id: "proof-1".into(),
            scope_generation: 12,
            revoke_watermark: 8,
            snapshot_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
        };
        let envelope = MessageEnvelope::new(
            "message-1",
            "operation-1",
            "EVIDENCE_INVALIDATED",
            1,
            "local",
            json!({"tenantId": 7}),
        )
        .unwrap()
        .with_authority_metadata(metadata.clone())
        .unwrap();

        assert_eq!(
            envelope.authority_metadata_json().unwrap(),
            Some(serde_json::to_string(&metadata).unwrap())
        );
        assert_eq!(
            envelope.payload_sha256,
            payload_digest(&json!({"tenantId": 7})).unwrap()
        );
        assert!(envelope
            .envelope_json()
            .unwrap()
            .contains("authorityMetadata"));
    }

    #[test]
    fn envelope_rejects_unknown_authority_metadata_fields() {
        let json = r#"{"authorizationEdition":1,"authorityId":"authority-1","authorityTerm":4,"globalFenceSequence":9,"keyId":"key-1","keyEpoch":2,"proofId":"proof-1","scopeGeneration":12,"revokeWatermark":8,"snapshotHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","extra":true}"#;
        assert!(serde_json::from_str::<AuthorizationMessageMetadata>(json).is_err());
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
