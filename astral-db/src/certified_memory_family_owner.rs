//! Ledger-backed CertifiedMemory family owners.
//!
//! These adapters consume only the durable completion ledger. They do not query
//! source tables, infer inventory from empty results, or turn a local read into
//! an authority completion. The production composition root must supply an
//! explicit ledger context before these owners can be used.

use std::sync::Arc;

use astral_types::authority_protocol::AuthorityCertifiedMemoryFamily;
use astral_types::org_scope::OrgAdmissionEvidence;
use astral_types::{
    DomainScopeRequirement, PublishedCardAuthorization, PublishedCardEvidenceScope,
};
use policy_engine::OrgAuthorityRead;
use serde::Deserialize;

use crate::certified_memory_authority::{
    CardContextKey, CertifiedCardContext, GlobalAdminStatus, OrgReadKey, OwnershipReadKey,
};
use crate::certified_memory_completion::{
    CertifiedMemoryCompletionError, CertifiedMemoryDurableOwnerContext,
};
use crate::certified_memory_materializer::{
    CertifiedMemoryFamilyMaterialization, CertifiedMemoryFamilyOwner,
    CertifiedMemoryFamilyOwnerRequest, CertifiedMemoryFamilyPayload,
    CertifiedMemoryMaterializerError,
};
use crate::resource_ownership::ResourceOwnershipResolution;

/// One explicit owner implementation for one closed family.
#[derive(Clone)]
pub struct CertifiedMemoryLedgerFamilyOwner {
    context: CertifiedMemoryDurableOwnerContext,
    family: AuthorityCertifiedMemoryFamily,
}

impl std::fmt::Debug for CertifiedMemoryLedgerFamilyOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CertifiedMemoryLedgerFamilyOwner")
            .field("family", &self.family)
            .finish()
    }
}

impl CertifiedMemoryLedgerFamilyOwner {
    pub fn new(
        context: CertifiedMemoryDurableOwnerContext,
        family: AuthorityCertifiedMemoryFamily,
    ) -> Self {
        Self { context, family }
    }

    pub fn family(&self) -> AuthorityCertifiedMemoryFamily {
        self.family
    }
}

#[async_trait::async_trait]
impl CertifiedMemoryFamilyOwner for CertifiedMemoryLedgerFamilyOwner {
    fn family(&self) -> AuthorityCertifiedMemoryFamily {
        self.family
    }

    async fn materialize(
        &self,
        request: &CertifiedMemoryFamilyOwnerRequest,
    ) -> Result<CertifiedMemoryFamilyMaterialization, CertifiedMemoryMaterializerError> {
        let record = self
            .context
            .read_completion(request, self.family)
            .await
            .map_err(|error| map_completion_error(self.family, error))?;
        if record.completion.family != self.family {
            return Err(CertifiedMemoryMaterializerError::Invalid(
                "ledger completion family does not match owner".into(),
            ));
        }
        let payload = decode_payload(self.family, &record.payload_json)?;
        Ok(CertifiedMemoryFamilyMaterialization {
            family: self.family,
            completion: record.completion,
            payload,
        })
    }
}

/// Construct the six explicit ledger adapters in the protocol's fixed order.
/// This factory does not install them into a composition root automatically.
pub fn certified_memory_ledger_owners(
    context: CertifiedMemoryDurableOwnerContext,
) -> Vec<Arc<dyn CertifiedMemoryFamilyOwner>> {
    AuthorityCertifiedMemoryFamily::required()
        .into_iter()
        .map(|family| {
            Arc::new(CertifiedMemoryLedgerFamilyOwner::new(
                context.clone(),
                family,
            )) as Arc<dyn CertifiedMemoryFamilyOwner>
        })
        .collect()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CardContextPayload {
    key: CardContextKey,
    value: CertifiedCardContext,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GlobalAdminPayload {
    user_id: i64,
    status: GlobalAdminStatus,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublishedEvidencePayload {
    scope: PublishedEvidenceScopeWire,
    evidence: PublishedCardAuthorization,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublishedEvidenceScopeWire {
    tenant_id: i64,
    card_id: i64,
    user_filter: Option<i64>,
    domain: PublishedEvidenceDomainWire,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
enum PublishedEvidenceDomainWire {
    Any,
    None,
    Exact { id: i64 },
}

impl PublishedEvidenceScopeWire {
    fn into_scope(self) -> Result<PublishedCardEvidenceScope, String> {
        let scope = PublishedCardEvidenceScope {
            tenant_id: self.tenant_id,
            card_id: self.card_id,
            user_filter: self.user_filter,
            domain: match self.domain {
                PublishedEvidenceDomainWire::Any => DomainScopeRequirement::Unconstrained,
                PublishedEvidenceDomainWire::None => DomainScopeRequirement::ExactlyNone,
                PublishedEvidenceDomainWire::Exact { id } => {
                    DomainScopeRequirement::ExactlySome(id)
                }
            },
        };
        scope
            .validate()
            .map_err(|error| format!("invalid published evidence scope: {error}"))?;
        Ok(scope)
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
enum OrgAuthorityWireRead {
    Unmanaged,
    Disabled,
    Pending { code: String },
    Unavailable { code: String },
    Ready { evidence: Box<OrgAdmissionEvidence> },
}

impl OrgAuthorityWireRead {
    fn into_read(self) -> OrgAuthorityRead {
        match self {
            Self::Unmanaged => OrgAuthorityRead::Unmanaged,
            Self::Disabled => OrgAuthorityRead::Disabled,
            Self::Pending { code } => OrgAuthorityRead::Pending { code },
            Self::Unavailable { code } => OrgAuthorityRead::Unavailable { code },
            Self::Ready { evidence } => OrgAuthorityRead::Ready(evidence),
        }
    }
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OrgAuthorizationPayload {
    key: OrgReadKey,
    value: OrgAuthorityWireRead,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnershipPayload {
    key: OwnershipReadKey,
    resolution: OwnershipWireResolution,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
enum OwnershipWireResolution {
    TenantScoped {
        #[serde(rename = "targetId")]
        target_id: Option<i64>,
        #[serde(rename = "tenantId")]
        tenant_id: i64,
        #[serde(rename = "domainId")]
        domain_id: Option<i64>,
        #[serde(rename = "ownerId")]
        owner_id: Option<i64>,
    },
    Global {
        #[serde(rename = "targetId")]
        target_id: Option<i64>,
        #[serde(rename = "accessRequirement")]
        access_requirement: astral_types::GlobalAccessRequirement,
    },
}

impl OwnershipWireResolution {
    fn into_resolution(self) -> ResourceOwnershipResolution {
        match self {
            Self::TenantScoped {
                target_id,
                tenant_id,
                domain_id,
                owner_id,
            } => ResourceOwnershipResolution::TenantScoped {
                target_id,
                tenant_id,
                domain_id,
                owner_id,
            },
            Self::Global {
                target_id,
                access_requirement,
            } => ResourceOwnershipResolution::Global {
                target_id,
                access_requirement,
            },
        }
    }
}

pub(crate) fn decode_certified_memory_payload(
    family: AuthorityCertifiedMemoryFamily,
    payload_json: &str,
) -> Result<CertifiedMemoryFamilyPayload, CertifiedMemoryMaterializerError> {
    decode_payload(family, payload_json)
}

fn decode_payload(
    family: AuthorityCertifiedMemoryFamily,
    payload_json: &str,
) -> Result<CertifiedMemoryFamilyPayload, CertifiedMemoryMaterializerError> {
    match family {
        AuthorityCertifiedMemoryFamily::CardContext => {
            let values: Vec<CardContextPayload> = decode(payload_json, family)?;
            Ok(CertifiedMemoryFamilyPayload::CardContext(
                values
                    .into_iter()
                    .map(|value| (value.key, value.value))
                    .collect(),
            ))
        }
        AuthorityCertifiedMemoryFamily::GlobalAdmin => {
            let values: Vec<GlobalAdminPayload> = decode(payload_json, family)?;
            Ok(CertifiedMemoryFamilyPayload::GlobalAdmin(
                values
                    .into_iter()
                    .map(|value| (value.user_id, value.status))
                    .collect(),
            ))
        }
        AuthorityCertifiedMemoryFamily::PublishedEvidence => {
            let values: Vec<PublishedEvidencePayload> = decode(payload_json, family)?;
            let mut decoded = Vec::with_capacity(values.len());
            for value in values {
                let scope = value
                    .scope
                    .into_scope()
                    .map_err(CertifiedMemoryMaterializerError::Invalid)?;
                decoded.push((scope, Arc::new(value.evidence)));
            }
            Ok(CertifiedMemoryFamilyPayload::PublishedEvidence(decoded))
        }
        AuthorityCertifiedMemoryFamily::OrgAuthorization => {
            let values: Vec<OrgAuthorizationPayload> = decode(payload_json, family)?;
            Ok(CertifiedMemoryFamilyPayload::OrgAuthorization(
                values
                    .into_iter()
                    .map(|value| (value.key, value.value.into_read()))
                    .collect(),
            ))
        }
        AuthorityCertifiedMemoryFamily::Ownership => {
            let values: Vec<OwnershipPayload> = decode(payload_json, family)?;
            Ok(CertifiedMemoryFamilyPayload::Ownership(
                values
                    .into_iter()
                    .map(|value| (value.key, value.resolution.into_resolution()))
                    .collect(),
            ))
        }
        AuthorityCertifiedMemoryFamily::SodPolicy => {
            if payload_json.trim_start().starts_with('[') {
                let values: Vec<crate::certified_memory_authority::CertifiedSodPolicy> =
                    decode(payload_json, family)?;
                for value in &values {
                    value.validate().map_err(|error| {
                        CertifiedMemoryMaterializerError::Invalid(format!(
                            "invalid certified SoD policy: {error}"
                        ))
                    })?;
                }
                Ok(CertifiedMemoryFamilyPayload::SodPolicy(values))
            } else {
                let value: crate::certified_memory_source_owner_producer::SodPolicySourcePayload =
                    decode(payload_json, family)?;
                Ok(CertifiedMemoryFamilyPayload::SodPolicyWithProvenance(value))
            }
        }
    }
}

fn decode<T: serde::de::DeserializeOwned>(
    payload_json: &str,
    family: AuthorityCertifiedMemoryFamily,
) -> Result<T, CertifiedMemoryMaterializerError> {
    serde_json::from_str(payload_json).map_err(|error| {
        CertifiedMemoryMaterializerError::Invalid(format!(
            "invalid {family:?} certified-memory payload: {error}"
        ))
    })
}

fn map_completion_error(
    family: AuthorityCertifiedMemoryFamily,
    error: CertifiedMemoryCompletionError,
) -> CertifiedMemoryMaterializerError {
    match error {
        CertifiedMemoryCompletionError::Pending { code } => {
            CertifiedMemoryMaterializerError::Pending { family, code }
        }
        CertifiedMemoryCompletionError::Unknown { code } => {
            CertifiedMemoryMaterializerError::Unknown { family, code }
        }
        CertifiedMemoryCompletionError::Quarantined { code } => {
            CertifiedMemoryMaterializerError::Quarantined { family, code }
        }
        CertifiedMemoryCompletionError::ScopeMismatch => {
            CertifiedMemoryMaterializerError::FrontierMismatch { family }
        }
        CertifiedMemoryCompletionError::Invalid(message) => {
            CertifiedMemoryMaterializerError::Invalid(message)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::authority_protocol::AuthorityCertifiedMemoryFamily;

    #[test]
    fn factory_registers_exactly_the_closed_six_families() {
        let families: Vec<_> = AuthorityCertifiedMemoryFamily::required().to_vec();
        assert_eq!(families.len(), 6);
        assert_eq!(families[0], AuthorityCertifiedMemoryFamily::CardContext);
        assert_eq!(families[5], AuthorityCertifiedMemoryFamily::SodPolicy);
    }

    #[test]
    fn unverified_authority_receipt_remains_unknown_at_owner_boundary() {
        for family in AuthorityCertifiedMemoryFamily::required() {
            assert!(matches!(
                map_completion_error(
                    family,
                    CertifiedMemoryCompletionError::Unknown {
                        code: "certified_memory.completion_authority_receipt_unverified",
                    },
                ),
                CertifiedMemoryMaterializerError::Unknown {
                    family: actual,
                    code: "certified_memory.completion_authority_receipt_unverified",
                } if actual == family
            ));
        }
    }

    #[test]
    fn sod_wire_preserves_and_requires_provenance() {
        let payload = format!(
            r#"{{"provenance":{{"orgContributionDigest":"{}"}},"facts":[{{"policy":{{"policy_name":"conflict","conflict_type":"Dynamic","permission_a":null,"permission_b":null,"condition_script":"resourceOwnerId == currentUserId","resource_type":"rules","action_code":"read"}},"dynamicOwnerDigest":"{}"}}]}}"#,
            "33".repeat(32),
            "44".repeat(32)
        );
        let decoded = decode_payload(AuthorityCertifiedMemoryFamily::SodPolicy, &payload)
            .expect("valid SoD source payload");
        match decoded {
            CertifiedMemoryFamilyPayload::SodPolicyWithProvenance(value) => {
                assert_eq!(value.provenance.org_contribution_digest, "33".repeat(32));
                assert_eq!(
                    value.facts[0].dynamic_owner_digest.as_deref(),
                    Some("44".repeat(32).as_str())
                );
            }
            _ => panic!("source identities must be retained"),
        }
        assert!(
            decode_payload(AuthorityCertifiedMemoryFamily::SodPolicy, r#"{"facts":[]}"#).is_err()
        );
    }

    #[test]
    fn ownership_wire_payload_has_no_unresolved_positive_shape() {
        let payload = r#"[{"key":{"resource":"rules","path":"/rules","method":"GET","targetId":null,"actorCardId":7,"actorUserId":9},"resolution":{"kind":"TENANT_SCOPED","targetId":null,"tenantId":3,"domainId":4,"ownerId":9}}]"#;
        let decoded: Vec<OwnershipPayload> = serde_json::from_str(payload).expect("wire payload");
        assert!(matches!(
            decoded[0].resolution,
            OwnershipWireResolution::TenantScoped { .. }
        ));
    }
    #[test]
    fn published_scope_wire_requires_valid_explicit_domain() {
        let payload = r#"[{"scope":{"tenantId":3,"cardId":7,"userFilter":null,"domain":"ANY"},"evidence":{}}]"#;
        let error = decode_payload(AuthorityCertifiedMemoryFamily::PublishedEvidence, payload)
            .expect_err("incomplete evidence must fail closed");
        assert!(matches!(
            error,
            CertifiedMemoryMaterializerError::Invalid(_)
        ));
    }

    #[test]
    fn org_wire_value_is_converted_before_materialization() {
        let payload = r#"[{"key":{"tenantId":3,"userId":9,"identityCardId":11,"cardId":7},"value":{"kind":"PENDING","code":"org.pending"}}]"#;
        let decoded = decode_payload(AuthorityCertifiedMemoryFamily::OrgAuthorization, payload)
            .expect("valid org wire payload");
        assert!(matches!(
            decoded,
            CertifiedMemoryFamilyPayload::OrgAuthorization(values)
                if matches!(values[0].1, OrgAuthorityRead::Pending { .. })
        ));
    }
}
