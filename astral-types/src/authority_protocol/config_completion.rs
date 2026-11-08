//! Distinct V7 terminal completion contract for non-grant configuration writes.
//!
//! This protocol accepts only retained actual row images captured in the
//! source transaction, their same-transaction audit correlation, and empty
//! grant-publication side effects. It never creates a scope certificate or
//! current pointer.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    authority_digest, authority_sha256_hex, authority_text, authority_timestamp,
    AuthorityCallerIdentity, AuthorityCommitBinding, AuthorityProtocolError, AuthorityReadGate,
    AuthorityReservationDisposition, AuthorityScopeReservation, AuthorityStagedSourceEvidence,
    GlobalAuthorityFrontier,
};
use crate::{AuthorityMutationKind, AuthorityRetainedStagedEvidence, AUTHORIZATION_EDITION};

pub const AUTHORITY_PATH_CONFIG_COMPLETIONS: &str = "/main/api/v1/authority-config-completions";
pub const AUTHORITY_OPERATION_CONFIG_COMPLETION: &str = "config_completion";
pub const AUTHORITY_CONFIG_COMPLETION_KIND: &str = "CONFIG_COMPLETION";
pub const AUTHORITY_CONFIG_GATE_CONTRACT: &str = "DURABLE_CONFIG_V7";
const MAX_SOURCE_IMAGES: usize = 1024;
const MAX_AUDITS: usize = 64;
const MAX_IMAGE_BYTES: usize = 256 * 1024;

mod metadata;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityConfigSourceTable {
    #[serde(rename = "sod_policy")]
    SodPolicy,
    #[serde(rename = "admin_group")]
    AdminGroup,
    #[serde(rename = "admin_group_member")]
    AdminGroupMember,
    #[serde(rename = "identity_user_grading")]
    Grading,
    #[serde(rename = "permission_action")]
    PermissionAction,
    #[serde(rename = "resource_type_registry")]
    ResourceType,
    #[serde(rename = "user_card_level_definition")]
    UserCardLevelDefinition,
    #[serde(rename = "identity_level_template")]
    IdentityLevelTemplate,
    #[serde(rename = "user_card_template")]
    UserCardTemplate,
    #[serde(rename = "permission_inheritance_config")]
    InheritanceConfig,
    #[serde(rename = "department")]
    Department,
    #[serde(rename = "domain")]
    Domain,
    #[serde(rename = "tenant")]
    Tenant,
    #[serde(rename = "rule_set")]
    RuleSet,
    #[serde(rename = "permission_rule_template")]
    PermissionRuleTemplate,
}

impl AuthorityConfigSourceTable {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SodPolicy => "sod_policy",
            Self::AdminGroup => "admin_group",
            Self::AdminGroupMember => "admin_group_member",
            Self::Grading => "identity_user_grading",
            Self::PermissionAction => "permission_action",
            Self::ResourceType => "resource_type_registry",
            Self::UserCardLevelDefinition => "user_card_level_definition",
            Self::IdentityLevelTemplate => "identity_level_template",
            Self::UserCardTemplate => "user_card_template",
            Self::InheritanceConfig => "permission_inheritance_config",
            Self::Department => "department",
            Self::Domain => "domain",
            Self::Tenant => "tenant",
            Self::RuleSet => "rule_set",
            Self::PermissionRuleTemplate => "permission_rule_template",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityConfigSourceOperation {
    Insert,
    Upsert,
    Update,
    Delete,
}

/// Closed lookup shape emitted by the typed capture owner. Its canonical,
/// compact JSON text is retained in each row-image evidence entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum AuthorityConfigSourceLookup {
    PrimaryId {
        id: i64,
    },
    DepartmentInsertIntent {
        id: i64,
        tenant_id: i64,
        sub_tenant_id: Option<i64>,
        dept_name: String,
        dept_code: Option<String>,
        parent_dept_id: Option<i64>,
        sort_order: i32,
        description: Option<String>,
    },
    DomainInsertIntent {
        id: i64,
        domain_code: Option<String>,
        domain_name: String,
        domain_description: Option<String>,
        status: String,
    },
    TenantInsertIntent {
        id: i64,
        tenant_code: String,
        tenant_name: String,
        tenant_type: String,
        parent_tenant_id: Option<i64>,
        path: String,
        depth: i32,
    },
    SodPolicyName {
        name: String,
    },
    AdminGroupInsertIntent {
        id: i64,
        name: String,
        description: Option<String>,
        scope: Option<String>,
    },
    AdminGroupMember {
        group_id: i64,
        user_id: i64,
    },
    GradingUserDomain {
        user_id: i64,
        domain_id: i64,
    },
    PermissionActionCode {
        resource_type_id: i64,
        action_code: String,
    },
    ResourceTypeCode {
        code: String,
    },
    LevelNatural {
        domain_id: i64,
        level_code: String,
    },
    LevelTemplateNatural {
        domain_id: i64,
        template_code: String,
    },
    CardTemplateNatural {
        domain_id: i64,
        template_code: String,
    },
    InheritanceResourceType {
        resource_type: String,
    },
    RuleSetCode {
        code: String,
    },
    PermissionRuleTemplateAggregate {
        template_id: i64,
    },
}

impl AuthorityConfigSourceLookup {
    pub fn validate_for_table(
        &self,
        table: AuthorityConfigSourceTable,
    ) -> Result<(), AuthorityProtocolError> {
        let valid = match (table, self) {
            (AuthorityConfigSourceTable::SodPolicy, Self::PrimaryId { id }) => *id > 0,
            (AuthorityConfigSourceTable::SodPolicy, Self::SodPolicyName { name }) => {
                valid_lookup_text(name, 128)
            }
            (AuthorityConfigSourceTable::AdminGroup, Self::PrimaryId { id }) => *id > 0,
            (
                AuthorityConfigSourceTable::AdminGroup,
                Self::AdminGroupInsertIntent {
                    id,
                    name,
                    description,
                    scope,
                },
            ) => {
                *id > 0
                    && valid_lookup_text(name, 255)
                    && description.as_ref().is_none_or(|v| v.len() <= 4096)
                    && scope.as_ref().is_none_or(|v| valid_lookup_text(v, 128))
            }
            (
                AuthorityConfigSourceTable::AdminGroupMember,
                Self::AdminGroupMember { group_id, user_id },
            ) => *group_id > 0 && *user_id > 0,
            (AuthorityConfigSourceTable::Grading, Self::PrimaryId { id }) => *id > 0,
            (
                AuthorityConfigSourceTable::Grading,
                Self::GradingUserDomain { user_id, domain_id },
            ) => *user_id > 0 && *domain_id > 0,
            (AuthorityConfigSourceTable::PermissionAction, Self::PrimaryId { id }) => *id > 0,
            (
                AuthorityConfigSourceTable::PermissionAction,
                Self::PermissionActionCode {
                    resource_type_id,
                    action_code,
                },
            ) => *resource_type_id > 0 && valid_lookup_text(action_code, 64),
            (AuthorityConfigSourceTable::ResourceType, Self::PrimaryId { id }) => *id > 0,
            (AuthorityConfigSourceTable::ResourceType, Self::ResourceTypeCode { code }) => {
                valid_lookup_text(code, 128)
            }
            (AuthorityConfigSourceTable::UserCardLevelDefinition, Self::PrimaryId { id }) => {
                *id > 0
            }
            (
                AuthorityConfigSourceTable::UserCardLevelDefinition,
                Self::LevelNatural {
                    domain_id,
                    level_code,
                },
            ) => *domain_id > 0 && valid_lookup_text(level_code, 64),
            (AuthorityConfigSourceTable::IdentityLevelTemplate, Self::PrimaryId { id }) => *id > 0,
            (
                AuthorityConfigSourceTable::IdentityLevelTemplate,
                Self::LevelTemplateNatural {
                    domain_id,
                    template_code,
                },
            ) => *domain_id > 0 && valid_lookup_text(template_code, 64),
            (AuthorityConfigSourceTable::UserCardTemplate, Self::PrimaryId { id }) => *id > 0,
            (
                AuthorityConfigSourceTable::UserCardTemplate,
                Self::CardTemplateNatural {
                    domain_id,
                    template_code,
                },
            ) => *domain_id > 0 && valid_lookup_text(template_code, 128),
            (AuthorityConfigSourceTable::InheritanceConfig, Self::PrimaryId { id }) => *id > 0,
            (
                AuthorityConfigSourceTable::InheritanceConfig,
                Self::InheritanceResourceType { resource_type },
            ) => valid_lookup_text(resource_type, 128),
            (AuthorityConfigSourceTable::Department, Self::PrimaryId { id }) => *id > 0,
            (
                AuthorityConfigSourceTable::Department,
                Self::DepartmentInsertIntent {
                    id,
                    tenant_id,
                    sub_tenant_id,
                    dept_name,
                    dept_code,
                    parent_dept_id,
                    sort_order: _,
                    description,
                },
            ) => {
                *id > 0
                    && *tenant_id > 0
                    && sub_tenant_id.is_none_or(|value| value > 0)
                    && valid_lookup_text(dept_name, 128)
                    && dept_code
                        .as_ref()
                        .is_none_or(|value| valid_lookup_text(value, 64))
                    && parent_dept_id.is_none_or(|value| value > 0)
                    && description.as_ref().is_none_or(|value| value.len() <= 512)
            }
            (AuthorityConfigSourceTable::Domain, Self::PrimaryId { id }) => *id > 0,
            (
                AuthorityConfigSourceTable::Domain,
                Self::DomainInsertIntent {
                    id,
                    domain_code,
                    domain_name,
                    domain_description,
                    status,
                },
            ) => {
                *id > 0
                    && domain_code
                        .as_ref()
                        .is_none_or(|value| valid_lookup_text(value, 512))
                    && valid_lookup_text(domain_name, 128)
                    && domain_description
                        .as_ref()
                        .is_none_or(|value| value.len() <= 512)
                    && valid_lookup_text(status, 32)
            }
            (AuthorityConfigSourceTable::Tenant, Self::PrimaryId { id }) => *id > 0,
            (
                AuthorityConfigSourceTable::Tenant,
                Self::TenantInsertIntent {
                    id,
                    tenant_code,
                    tenant_name,
                    tenant_type,
                    parent_tenant_id,
                    path,
                    depth,
                },
            ) => {
                *id > 0
                    && valid_lookup_text(tenant_code, 64)
                    && valid_lookup_text(tenant_name, 128)
                    && tenant_type == "ENTERPRISE"
                    && parent_tenant_id.is_none_or(|value| value > 0)
                    && valid_lookup_text(path, 512)
                    && *depth >= 0
            }
            (AuthorityConfigSourceTable::RuleSet, Self::PrimaryId { id }) => *id > 0,
            (AuthorityConfigSourceTable::RuleSet, Self::RuleSetCode { code }) => {
                valid_lookup_text(code, 64)
            }
            (
                AuthorityConfigSourceTable::PermissionRuleTemplate,
                Self::PermissionRuleTemplateAggregate { template_id },
            ) => *template_id > 0,
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(AuthorityProtocolError::InvalidCoverage)
        }
    }
}

fn valid_lookup_text(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value.trim() == value
        && !value.chars().any(|ch| ch.is_control())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityConfigGateContract {
    #[serde(rename = "DURABLE_CONFIG_V7")]
    DurableConfigV7,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorityConfigCompletionKind {
    #[serde(rename = "CONFIG_COMPLETION")]
    ConfigCompletion,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityConfigSourceBatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta: Option<serde_json::Value>,
    pub source_images: Vec<AuthorityConfigSourceImage>,
    pub audits: Vec<AuthorityConfigAudit>,
    pub source_projection: Vec<serde_json::Value>,
    pub invalidations: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityConfigSourceImage {
    pub table: AuthorityConfigSourceTable,
    pub key: i64,
    pub lookup: String,
    pub operation: AuthorityConfigSourceOperation,
    pub before_image_digest: String,
    pub after_image_digest: String,
    pub before_image: String,
    pub after_image: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityConfigAudit {
    pub audit_log_id: i64,
    pub user_id: i64,
    pub action: String,
    pub resource: String,
    pub decision: String,
    pub event_type: String,
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityConfigCompletionEvidence {
    pub kind: AuthorityConfigCompletionKind,
    pub gate_contract: AuthorityConfigGateContract,
    pub source_batch: AuthorityConfigSourceBatch,
}

impl AuthorityConfigCompletionEvidence {
    pub fn validate(&self, operation_id: &str) -> Result<(), AuthorityProtocolError> {
        let batch = &self.source_batch;
        if batch.delta.is_some()
            || !batch.source_projection.is_empty()
            || !batch.invalidations.is_empty()
            || batch.source_images.is_empty()
            || batch.source_images.len() > MAX_SOURCE_IMAGES
            || batch.audits.is_empty()
            || batch.audits.len() > MAX_AUDITS
        {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }
        let mut previous_image: Option<(String, i64)> = None;
        let mut any_changed = false;
        for image in &batch.source_images {
            if image.key <= 0 {
                return Err(AuthorityProtocolError::InvalidIdentifier {
                    field: "source_image_key",
                });
            }
            let lookup: AuthorityConfigSourceLookup =
                serde_json::from_str(&image.lookup).map_err(|_| {
                    AuthorityProtocolError::InvalidText {
                        field: "source_image_lookup",
                    }
                })?;
            lookup.validate_for_table(image.table)?;
            if serde_json::to_string(&lookup)
                .map_err(|_| AuthorityProtocolError::CanonicalSerialization)?
                != image.lookup
            {
                return Err(AuthorityProtocolError::InvalidText {
                    field: "source_image_lookup",
                });
            }
            let identity = (image.table.as_str().to_owned(), image.key);
            if previous_image
                .as_ref()
                .is_some_and(|previous| previous >= &identity)
            {
                return Err(AuthorityProtocolError::InvalidCoverage);
            }
            previous_image = Some(identity);
            let before_absent =
                validate_image(image, &image.before_image, &image.before_image_digest, true)?;
            let after_absent =
                validate_image(image, &image.after_image, &image.after_image_digest, false)?;
            match image.operation {
                AuthorityConfigSourceOperation::Insert if !before_absent || after_absent => {
                    return Err(AuthorityProtocolError::ScopeMismatch)
                }
                AuthorityConfigSourceOperation::Upsert if after_absent => {
                    return Err(AuthorityProtocolError::ScopeMismatch)
                }
                AuthorityConfigSourceOperation::Update if before_absent || after_absent => {
                    return Err(AuthorityProtocolError::ScopeMismatch)
                }
                AuthorityConfigSourceOperation::Delete if before_absent || !after_absent => {
                    return Err(AuthorityProtocolError::ScopeMismatch)
                }
                _ => {}
            }
            any_changed |= image.before_image_digest != image.after_image_digest;
        }
        if !any_changed {
            return Err(AuthorityProtocolError::DigestMismatch {
                field: "source_images_unchanged",
            });
        }
        let mut previous_audit = 0;
        for audit in &batch.audits {
            if audit.audit_log_id <= 0 || audit.user_id <= 0 {
                return Err(AuthorityProtocolError::InvalidIdentifier {
                    field: "audit_log_id",
                });
            }
            if audit.audit_log_id <= previous_audit
                || audit.request_id.as_deref() != Some(operation_id)
            {
                return Err(AuthorityProtocolError::ScopeMismatch);
            }
            previous_audit = audit.audit_log_id;
            authority_text(&audit.action, "audit_action")?;
            authority_text(&audit.resource, "audit_resource")?;
            authority_text(&audit.decision, "audit_decision")?;
            authority_text(&audit.event_type, "audit_event_type")?;
        }
        Ok(())
    }
}

fn validate_image(
    receipt: &AuthorityConfigSourceImage,
    image_text: &str,
    digest: &str,
    before_side: bool,
) -> Result<bool, AuthorityProtocolError> {
    super::authority_digest(digest, "source_image_digest")?;
    if image_text.is_empty() || image_text.len() > MAX_IMAGE_BYTES {
        return Err(AuthorityProtocolError::InvalidText {
            field: "source_image",
        });
    }
    if super::authority_sha256_hex(image_text.as_bytes()) != digest {
        return Err(AuthorityProtocolError::DigestMismatch {
            field: "source_image_digest",
        });
    }
    let lookup: AuthorityConfigSourceLookup =
        serde_json::from_str(&receipt.lookup).map_err(|_| AuthorityProtocolError::InvalidText {
            field: "source_image_lookup",
        })?;
    let value: serde_json::Value =
        serde_json::from_str(image_text).map_err(|_| AuthorityProtocolError::InvalidText {
            field: "source_image",
        })?;
    if value.get("presence").and_then(serde_json::Value::as_str) == Some("ABSENT") {
        #[derive(Deserialize, Serialize, PartialEq, Eq)]
        #[serde(deny_unknown_fields)]
        struct AbsentMarker {
            table: String,
            lookup: String,
            presence: String,
        }
        let marker: AbsentMarker =
            serde_json::from_str(image_text).map_err(|_| AuthorityProtocolError::InvalidText {
                field: "source_absent_marker",
            })?;
        let canonical = serde_json::to_string(&marker)
            .map_err(|_| AuthorityProtocolError::CanonicalSerialization)?;
        if marker
            != (AbsentMarker {
                table: receipt.table.as_str().to_owned(),
                lookup: receipt.lookup.clone(),
                presence: "ABSENT".to_owned(),
            })
            || canonical != image_text
            || (before_side
                && !matches!(
                    receipt.operation,
                    AuthorityConfigSourceOperation::Insert | AuthorityConfigSourceOperation::Upsert
                ))
            || (!before_side && receipt.operation != AuthorityConfigSourceOperation::Delete)
        {
            return Err(AuthorityProtocolError::DigestMismatch {
                field: "source_absent_marker",
            });
        }
        return Ok(true);
    }
    validate_actual_row(receipt, &lookup, image_text)?;

    Ok(false)
}

macro_rules! image_row {
    ($name:ident { $($field:ident : $ty:ty),+ $(,)? }) => {
        #[derive(Debug, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct $name { $($field: $ty),+ }
    };
}
image_row!(SodPolicyImage { policy_id:i64, policy_name:Option<String>, description:Option<String>, conflict_type:Option<String>, resource_type:Option<String>, action_code:Option<String>, permission_a:Option<String>, permission_b:Option<String>, condition_script:Option<String>, limit_count:Option<i64>, limit_window:Option<String>, status:Option<String>, created_at:Option<String>, updated_at:Option<String> });
image_row!(AdminGroupImage { id:i64, name:Option<String>, description:Option<String>, scope:Option<String>, created_at:Option<String> });
image_row!(AdminGroupMemberImage { id:i64, group_id:Option<i64>, user_id:Option<i64>, created_at:Option<String> });
image_row!(GradingImage { id:i64, user_id:Option<i64>, level_id:Option<i64>, domain_id:Option<i64>, created_at:Option<String>, updated_at:Option<String> });
image_row!(PermissionActionImage { action_id:i64, domain_id:Option<i64>, resource_type_id:Option<i64>, action_code:Option<String>, action_name:Option<String>, action_description:Option<String>, created_at:Option<String>, updated_at:Option<String> });
image_row!(ResourceTypeImage { id:i64, resource_type:Option<String>, actions_json:Option<String>, description:Option<String>, created_at:Option<String>, updated_at:Option<String> });
image_row!(UserCardLevelDefinitionImage {
    level_id:i64, domain_id:i64, level_no:i32, level_code:String, level_name:String,
    status:String, upgrade_strategy_json:Option<String>, description:Option<String>,
    created_at:Option<String>, updated_at:Option<String>
});
image_row!(LevelTemplateResourceMapImage {
    id:i64, template_id:i64, resource_type_id:i64, priority:i32,
    created_at:Option<String>, updated_at:Option<String>
});
image_row!(LevelTemplateActionMapImage {
    id:i64, template_id:i64, action_id:i64, effect:String,
    created_at:Option<String>, updated_at:Option<String>
});
image_row!(IdentityLevelTemplateImage {
    template_id:i64, template_code:String, template_name:String, domain_id:i64,
    principal_type:String, grant_type:String, level_no:i32,
    user_card_template_id:Option<i64>, status:String, version_no:i32,
    force_cover:bool, description:Option<String>, created_at:Option<String>,
    updated_at:Option<String>, resource_maps:Vec<LevelTemplateResourceMapImage>,
    action_maps:Vec<LevelTemplateActionMapImage>
});
image_row!(UserCardTemplateImage {
    template_id:i64, domain_id:i64, tenant_id:Option<i64>, parent_template_id:Option<i64>,
    template_code:String, template_name:String, card_type:String, template_scope:String,
    version_no:i32, default_priority:i32, default_roles_json:Option<String>,
    resource_scope_json:Option<String>, status:String, created_at:Option<String>,
    updated_at:Option<String>
});
pub(super) fn validate_card_rebind_template(
    evidence: &super::AuthorityCardRebindEvidence,
) -> Result<(), AuthorityProtocolError> {
    if evidence.new_template_image.is_empty() || evidence.new_template_image.len() > MAX_IMAGE_BYTES
    {
        return Err(AuthorityProtocolError::InvalidCoverage);
    }
    let image: UserCardTemplateImage = serde_json::from_str(&evidence.new_template_image)
        .map_err(|_| AuthorityProtocolError::InvalidCoverage)?;
    let canonical: serde_json::Value = serde_json::from_str(&evidence.new_template_image)
        .map_err(|_| AuthorityProtocolError::InvalidCoverage)?;
    if serde_json::to_string(&canonical)
        .map_err(|_| AuthorityProtocolError::CanonicalSerialization)?
        != evidence.new_template_image
        || image.template_id != evidence.new_template_id
        || image.status != "ACTIVE"
        || image.domain_id <= 0
        || Some(image.domain_id) != evidence.domain_id
        || image.tenant_id.is_some_and(|id| id != evidence.tenant_id)
        || image.card_type != evidence.before_card.card_type
        || !matches!(image.template_scope.as_str(), "SYSTEM" | "DOMAIN" | "ORG")
    {
        return Err(AuthorityProtocolError::ScopeMismatch);
    }
    Ok(())
}

image_row!(InheritanceConfigImage {
    id:i64, resource_type:String, inheritance_mode:String, updated_at:Option<String>
});
image_row!(RuleSetRootImage {
    rule_set_id:i64, name:String, code:String, description:Option<String>, source_type:String,
    source_id:Option<i64>, enabled:i32, created_at:Option<String>, updated_at:Option<String>,
    tenant_id:Option<i64>
});
image_row!(RuleSetEntryImage {
    entry_id:i64, rule_set_id:i64, resource_type:String, resource_id:Option<i64>,
    action_code:String, effect:String, condition_json:Option<String>, priority:i32,
    enabled:i32, valid_from:Option<String>, valid_to:Option<String>,
    created_at:Option<String>, updated_at:Option<String>, tenant_id:Option<i64>
});
image_row!(RuleSetBindingImage {
    id:i64, card_id:i64, rule_set_id:i64, ref_type:String, created_at:Option<String>, tenant_id:Option<i64>
});
image_row!(RuleSetAggregateImage { root:RuleSetRootImage, entries:Vec<RuleSetEntryImage>, bindings:Vec<RuleSetBindingImage> });
image_row!(UserCardTemplateRootImage {
    template_id:i64, domain_id:i64, tenant_id:Option<i64>, parent_template_id:Option<i64>,
    template_code:String, template_name:String, card_type:String, template_scope:String,
    version_no:i32, default_priority:i32, default_roles_json:Option<String>,
    resource_scope_json:Option<String>, status:String, created_at:Option<String>, updated_at:Option<String>
});
image_row!(PermissionRuleTemplateRowImage {
    template_rule_id:i64, template_id:i64, effect:String, resource_type:Option<String>,
    resource_id:Option<i64>, action_code:Option<String>, condition_json:Option<String>,
    priority:i32, enabled:i32, created_at:Option<String>, updated_at:Option<String>
});
image_row!(PermissionRuleTemplateAggregateImage {
    template_root:UserCardTemplateRootImage, permission_rules:Vec<PermissionRuleTemplateRowImage>,
    linked_rule_set:RuleSetAggregateImage
});

fn validate_actual_row(
    receipt: &AuthorityConfigSourceImage,
    lookup: &AuthorityConfigSourceLookup,
    image_text: &str,
) -> Result<(), AuthorityProtocolError> {
    fn decode<T: for<'de> Deserialize<'de> + Serialize>(
        text: &str,
    ) -> Result<T, AuthorityProtocolError> {
        let row: T =
            serde_json::from_str(text).map_err(|_| AuthorityProtocolError::InvalidText {
                field: "source_row_image",
            })?;
        let encoded = serde_json::to_string(&row)
            .map_err(|_| AuthorityProtocolError::CanonicalSerialization)?;
        if encoded != text {
            return Err(AuthorityProtocolError::InvalidText {
                field: "source_row_canonical",
            });
        }
        Ok(row)
    }
    if receipt.table == AuthorityConfigSourceTable::RuleSet {
        let image: RuleSetAggregateImage = decode(image_text)?;
        validate_rule_set_aggregate(&image)?;
        if image.root.rule_set_id != receipt.key || !matches_rule_set_lookup(&image.root, lookup) {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        return Ok(());
    }
    if receipt.table == AuthorityConfigSourceTable::PermissionRuleTemplate {
        let image: PermissionRuleTemplateAggregateImage = decode(image_text)?;
        validate_permission_rule_template_aggregate(&image)?;
        if image.template_root.template_id != receipt.key
            || !matches!(lookup, AuthorityConfigSourceLookup::PermissionRuleTemplateAggregate { template_id } if *template_id == receipt.key)
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        return Ok(());
    }
    if matches!(
        receipt.table,
        AuthorityConfigSourceTable::Department
            | AuthorityConfigSourceTable::Domain
            | AuthorityConfigSourceTable::Tenant
    ) {
        return metadata::validate_actual_row(receipt, lookup, image_text);
    }
    let value: serde_json::Value =
        serde_json::from_str(image_text).map_err(|_| AuthorityProtocolError::InvalidText {
            field: "source_row_image",
        })?;
    let object = value
        .as_object()
        .ok_or(AuthorityProtocolError::InvalidText {
            field: "source_row_image",
        })?;
    let (pk_field, lookup_ok) = match (receipt.table, lookup) {
        (
            AuthorityConfigSourceTable::SodPolicy,
            AuthorityConfigSourceLookup::SodPolicyName { name },
        ) => (
            "policy_id",
            object
                .get("policy_name")
                .and_then(serde_json::Value::as_str)
                == Some(name),
        ),
        (
            AuthorityConfigSourceTable::AdminGroup,
            AuthorityConfigSourceLookup::AdminGroupInsertIntent {
                id,
                name,
                description,
                scope,
            },
        ) => (
            "id",
            *id == receipt.key
                && object.get("id").and_then(serde_json::Value::as_i64) == Some(*id)
                && object.get("name").and_then(serde_json::Value::as_str) == Some(name)
                && object
                    .get("description")
                    .and_then(serde_json::Value::as_str)
                    == description.as_deref()
                && object.get("scope").and_then(serde_json::Value::as_str) == scope.as_deref(),
        ),
        (
            AuthorityConfigSourceTable::AdminGroupMember,
            AuthorityConfigSourceLookup::AdminGroupMember { group_id, user_id },
        ) => (
            "id",
            object.get("group_id").and_then(serde_json::Value::as_i64) == Some(*group_id)
                && object.get("user_id").and_then(serde_json::Value::as_i64) == Some(*user_id),
        ),
        (
            AuthorityConfigSourceTable::Grading,
            AuthorityConfigSourceLookup::GradingUserDomain { user_id, domain_id },
        ) => (
            "id",
            object.get("user_id").and_then(serde_json::Value::as_i64) == Some(*user_id)
                && object.get("domain_id").and_then(serde_json::Value::as_i64) == Some(*domain_id),
        ),
        (
            AuthorityConfigSourceTable::PermissionAction,
            AuthorityConfigSourceLookup::PermissionActionCode {
                resource_type_id,
                action_code,
            },
        ) => (
            "action_id",
            object
                .get("resource_type_id")
                .and_then(serde_json::Value::as_i64)
                == Some(*resource_type_id)
                && object
                    .get("action_code")
                    .and_then(serde_json::Value::as_str)
                    == Some(action_code),
        ),
        (
            AuthorityConfigSourceTable::ResourceType,
            AuthorityConfigSourceLookup::ResourceTypeCode { code },
        ) => (
            "id",
            object
                .get("resource_type")
                .and_then(serde_json::Value::as_str)
                == Some(code),
        ),
        (
            AuthorityConfigSourceTable::UserCardLevelDefinition,
            AuthorityConfigSourceLookup::LevelNatural {
                domain_id,
                level_code,
            },
        ) => (
            "level_id",
            object.get("domain_id").and_then(serde_json::Value::as_i64) == Some(*domain_id)
                && object.get("level_code").and_then(serde_json::Value::as_str) == Some(level_code),
        ),
        (
            AuthorityConfigSourceTable::IdentityLevelTemplate,
            AuthorityConfigSourceLookup::LevelTemplateNatural {
                domain_id,
                template_code,
            },
        ) => (
            "template_id",
            object.get("domain_id").and_then(serde_json::Value::as_i64) == Some(*domain_id)
                && object
                    .get("template_code")
                    .and_then(serde_json::Value::as_str)
                    == Some(template_code),
        ),
        (
            AuthorityConfigSourceTable::UserCardTemplate,
            AuthorityConfigSourceLookup::CardTemplateNatural {
                domain_id,
                template_code,
            },
        ) => (
            "template_id",
            object.get("domain_id").and_then(serde_json::Value::as_i64) == Some(*domain_id)
                && object
                    .get("template_code")
                    .and_then(serde_json::Value::as_str)
                    == Some(template_code),
        ),
        (
            AuthorityConfigSourceTable::InheritanceConfig,
            AuthorityConfigSourceLookup::InheritanceResourceType { resource_type },
        ) => (
            "id",
            object
                .get("resource_type")
                .and_then(serde_json::Value::as_str)
                == Some(resource_type),
        ),
        (
            AuthorityConfigSourceTable::Department | AuthorityConfigSourceTable::Domain,
            AuthorityConfigSourceLookup::PrimaryId { id },
        ) => (
            if receipt.table == AuthorityConfigSourceTable::Department {
                "dept_id"
            } else {
                "domain_id"
            },
            *id == receipt.key,
        ),
        (AuthorityConfigSourceTable::Tenant, AuthorityConfigSourceLookup::PrimaryId { id }) => {
            ("tenant_id", *id == receipt.key)
        }
        (
            AuthorityConfigSourceTable::Department
            | AuthorityConfigSourceTable::Domain
            | AuthorityConfigSourceTable::Tenant,
            _,
        ) => return Err(AuthorityProtocolError::ScopeMismatch),
        (AuthorityConfigSourceTable::RuleSet, AuthorityConfigSourceLookup::RuleSetCode { .. }) => {
            ("rule_set_id", true)
        }
        (
            AuthorityConfigSourceTable::PermissionRuleTemplate,
            AuthorityConfigSourceLookup::PermissionRuleTemplateAggregate { template_id },
        ) => ("template_id", *template_id == receipt.key),
        (_, AuthorityConfigSourceLookup::PrimaryId { id }) => {
            let field = match receipt.table {
                AuthorityConfigSourceTable::SodPolicy => "policy_id",
                AuthorityConfigSourceTable::PermissionAction => "action_id",
                AuthorityConfigSourceTable::UserCardLevelDefinition => "level_id",
                AuthorityConfigSourceTable::IdentityLevelTemplate
                | AuthorityConfigSourceTable::UserCardTemplate => "template_id",
                AuthorityConfigSourceTable::Department
                | AuthorityConfigSourceTable::Domain
                | AuthorityConfigSourceTable::Tenant
                | AuthorityConfigSourceTable::RuleSet
                | AuthorityConfigSourceTable::PermissionRuleTemplate => {
                    return Err(AuthorityProtocolError::InvalidCoverage)
                }
                _ => "id",
            };
            (field, *id == receipt.key)
        }
        _ => return Err(AuthorityProtocolError::ScopeMismatch),
    };
    if object.get(pk_field).and_then(serde_json::Value::as_i64) != Some(receipt.key) || !lookup_ok {
        return Err(AuthorityProtocolError::ScopeMismatch);
    }
    // Decode THIS side, not the after image unconditionally. This allows a
    // DELETE's after side to be ABSENT while still validating its before row.
    match receipt.table {
        AuthorityConfigSourceTable::SodPolicy => {
            let _ = decode::<SodPolicyImage>(image_text)?;
        }
        AuthorityConfigSourceTable::AdminGroup => {
            let _ = decode::<AdminGroupImage>(image_text)?;
        }
        AuthorityConfigSourceTable::AdminGroupMember => {
            let _ = decode::<AdminGroupMemberImage>(image_text)?;
        }
        AuthorityConfigSourceTable::Grading => {
            let _ = decode::<GradingImage>(image_text)?;
        }
        AuthorityConfigSourceTable::PermissionAction => {
            let _ = decode::<PermissionActionImage>(image_text)?;
        }
        AuthorityConfigSourceTable::ResourceType => {
            let _ = decode::<ResourceTypeImage>(image_text)?;
        }
        AuthorityConfigSourceTable::UserCardLevelDefinition => {
            let _ = decode::<UserCardLevelDefinitionImage>(image_text)?;
        }
        AuthorityConfigSourceTable::IdentityLevelTemplate => {
            let row: IdentityLevelTemplateImage = decode(image_text)?;
            if row.template_id <= 0
                || row.resource_maps.iter().any(|child| {
                    child.id <= 0
                        || child.template_id != row.template_id
                        || child.resource_type_id <= 0
                })
                || row.action_maps.iter().any(|child| {
                    child.id <= 0 || child.template_id != row.template_id || child.action_id <= 0
                })
                || !strictly_increasing(row.resource_maps.iter().map(|child| child.id))
                || !strictly_increasing(row.action_maps.iter().map(|child| child.id))
            {
                return Err(AuthorityProtocolError::ScopeMismatch);
            }
        }
        AuthorityConfigSourceTable::UserCardTemplate => {
            let _ = decode::<UserCardTemplateImage>(image_text)?;
        }
        AuthorityConfigSourceTable::InheritanceConfig => {
            let _ = decode::<InheritanceConfigImage>(image_text)?;
        }
        AuthorityConfigSourceTable::Department
        | AuthorityConfigSourceTable::Domain
        | AuthorityConfigSourceTable::Tenant
        | AuthorityConfigSourceTable::RuleSet
        | AuthorityConfigSourceTable::PermissionRuleTemplate => {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }
    }
    Ok(())
}

pub(super) fn validate_card_rebind_aggregate(
    aggregate: &super::AuthorityCardRebindRuleSetAggregate,
) -> Result<(), AuthorityProtocolError> {
    let image: RuleSetAggregateImage = serde_json::from_str(&aggregate.canonical_image)
        .map_err(|_| AuthorityProtocolError::InvalidCoverage)?;
    validate_rule_set_aggregate(&image)?;
    if image.root.rule_set_id != aggregate.rule_set_id
        || image.entries.len() > 512
        || image.bindings.len() > 512
        || image
            .entries
            .iter()
            .any(|row| !matches!(row.effect.as_str(), "ALLOW" | "DENY"))
        || image.bindings.iter().any(|row| {
            row.created_at
                .as_deref()
                .is_none_or(|text| text.trim().is_empty())
        })
    {
        return Err(AuthorityProtocolError::InvalidCoverage);
    }
    Ok(())
}

fn matches_rule_set_lookup(root: &RuleSetRootImage, lookup: &AuthorityConfigSourceLookup) -> bool {
    match lookup {
        AuthorityConfigSourceLookup::PrimaryId { id } => root.rule_set_id == *id,
        AuthorityConfigSourceLookup::RuleSetCode { code } => root.code == *code,
        _ => false,
    }
}

fn validate_rule_set_aggregate(
    image: &RuleSetAggregateImage,
) -> Result<(), AuthorityProtocolError> {
    let root = &image.root;
    if root.rule_set_id <= 0
        || root.tenant_id.is_some_and(|id| id <= 0)
        || root.source_id.is_some_and(|id| id <= 0)
        || !valid_lookup_text(&root.name, 128)
        || !valid_lookup_text(&root.code, 64)
        || !valid_lookup_text(&root.source_type, 32)
        || !matches!(root.enabled, 0 | 1)
        || image.entries.iter().any(|row| {
            row.entry_id <= 0
                || row.rule_set_id != root.rule_set_id
                || !valid_lookup_text(&row.resource_type, 64)
                || !valid_lookup_text(&row.action_code, 64)
                || !valid_lookup_text(&row.effect, 16)
                || !matches!(row.enabled, 0 | 1)
                || row.tenant_id.is_some_and(|id| id <= 0)
                || row
                    .condition_json
                    .as_deref()
                    .is_some_and(|text| serde_json::from_str::<serde_json::Value>(text).is_err())
        })
        || image.bindings.iter().any(|row| {
            row.id <= 0
                || row.card_id <= 0
                || row.rule_set_id != root.rule_set_id
                || !valid_lookup_text(&row.ref_type, 16)
                || row.tenant_id.is_some_and(|id| id <= 0)
        })
        || !strictly_increasing(image.entries.iter().map(|row| row.entry_id))
        || !strictly_increasing(image.bindings.iter().map(|row| row.id))
    {
        return Err(AuthorityProtocolError::ScopeMismatch);
    }
    Ok(())
}

fn validate_permission_rule_template_aggregate(
    image: &PermissionRuleTemplateAggregateImage,
) -> Result<(), AuthorityProtocolError> {
    let template = &image.template_root;
    let template_id = template.template_id;
    if template_id <= 0
        || template.domain_id <= 0
        || template.tenant_id.is_some_and(|id| id <= 0)
        || template.parent_template_id.is_some_and(|id| id <= 0)
        || !valid_lookup_text(&template.template_code, 128)
        || !valid_lookup_text(&template.template_name, 128)
        || !valid_lookup_text(&template.card_type, 32)
        || !valid_lookup_text(&template.template_scope, 32)
        || !valid_lookup_text(&template.status, 32)
        || template.version_no <= 0
        || template.default_priority < 0
        || image.permission_rules.iter().any(|row| {
            row.template_rule_id <= 0
                || row.template_id != template_id
                || !valid_lookup_text(&row.effect, 16)
                || row
                    .resource_type
                    .as_deref()
                    .is_some_and(|value| !valid_lookup_text(value, 64))
                || row.resource_id.is_some_and(|id| id <= 0)
                || row
                    .action_code
                    .as_deref()
                    .is_some_and(|value| !valid_lookup_text(value, 64))
                || row.enabled != 0 && row.enabled != 1
                || row
                    .condition_json
                    .as_deref()
                    .is_some_and(|text| serde_json::from_str::<serde_json::Value>(text).is_err())
        })
        || !strictly_increasing(
            image
                .permission_rules
                .iter()
                .map(|row| row.template_rule_id),
        )
    {
        return Err(AuthorityProtocolError::ScopeMismatch);
    }
    validate_rule_set_aggregate(&image.linked_rule_set)?;
    let linked = &image.linked_rule_set.root;
    if linked.source_type != "TEMPLATE"
        || linked.source_id != Some(template_id)
        || linked.tenant_id != template.tenant_id
    {
        return Err(AuthorityProtocolError::ScopeMismatch);
    }
    Ok(())
}

fn strictly_increasing(values: impl IntoIterator<Item = i64>) -> bool {
    let mut previous = None;
    for value in values {
        if previous.is_some_and(|prior| prior >= value) {
            return false;
        }
        previous = Some(value);
    }
    true
}

/// Produce a one-way integrity commitment for a non-null sensitive tenant field.
/// This is not an authorization capability or a confidentiality guarantee.
pub fn authority_config_sensitive_field_digest(
    tenant_id: i64,
    field: &str,
    value: &str,
) -> Result<String, AuthorityProtocolError> {
    if tenant_id <= 0 {
        return Err(AuthorityProtocolError::InvalidIdentifier { field: "tenant_id" });
    }
    if !matches!(
        field,
        "license_key" | "contact_person" | "contact_phone" | "contact_email"
    ) {
        return Err(AuthorityProtocolError::InvalidText {
            field: "sensitive_tenant_field",
        });
    }
    let field_len =
        u32::try_from(field.len()).map_err(|_| AuthorityProtocolError::InvalidText {
            field: "sensitive_tenant_field",
        })?;
    let value_len =
        u64::try_from(value.len()).map_err(|_| AuthorityProtocolError::InvalidText {
            field: "sensitive_tenant_value",
        })?;
    let mut bytes = Vec::with_capacity(36 + field.len() + value.len());
    bytes.extend_from_slice(b"ASTRAL_CONFIG_SENSITIVE_FIELD_V7\0");
    bytes.extend_from_slice(&tenant_id.to_be_bytes());
    bytes.extend_from_slice(&field_len.to_be_bytes());
    bytes.extend_from_slice(field.as_bytes());
    bytes.extend_from_slice(&value_len.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(hex::encode(Sha256::digest(bytes)))
}

/// Produce the V7 source-commit digest over the complete staged wrapper.
///
/// The wrapper is deliberately reconstructed from the shared typed evidence,
/// rather than hashing a producer-specific JSON fragment. This keeps the
/// producer, worker, and authority on the same canonical bytes after durable
/// JSON storage normalization.
pub fn config_source_commit_digest(
    completion: &AuthorityConfigCompletionEvidence,
) -> Result<String, AuthorityProtocolError> {
    let envelope = AuthorityStagedSourceEvidence {
        coverage: None,
        evidence: serde_json::to_value(completion)
            .map_err(|_| AuthorityProtocolError::CanonicalSerialization)?,
    };
    let canonical = serde_json::to_vec(&envelope)
        .map_err(|_| AuthorityProtocolError::CanonicalSerialization)?;
    let mut bytes = Vec::with_capacity(40 + canonical.len());
    bytes.extend_from_slice(b"ASTRAL_TRUSTGRAPH_SOURCE_BATCH_V7\0");
    bytes.extend_from_slice(
        &u64::try_from(canonical.len())
            .map_err(|_| AuthorityProtocolError::InvalidText { field: "evidence" })?
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&canonical);
    Ok(authority_sha256_hex(&bytes))
}

/// Produce the typed before/after batch digests used by source outcomes.
///
/// This preserves the established framing: each side has its own domain, the
/// ordered digest count, and a u64 length before every lowercase digest. The
/// input is checked against the retained image bytes before the framed digest
/// is derived, so a copied or corrupted digest cannot become a binding.
pub fn config_image_digests(
    images: &[AuthorityConfigSourceImage],
) -> Result<(String, String), AuthorityProtocolError> {
    const BEFORE_DOMAIN: &[u8] = b"ASTRAL_TRUSTGRAPH_TYPED_BEFORE_V7\0";
    const AFTER_DOMAIN: &[u8] = b"ASTRAL_TRUSTGRAPH_TYPED_AFTER_V7\0";

    fn side_digest(
        domain: &[u8],
        mut digests: Vec<String>,
    ) -> Result<String, AuthorityProtocolError> {
        digests.sort();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(domain);
        bytes.extend_from_slice(
            &u64::try_from(digests.len())
                .map_err(|_| AuthorityProtocolError::InvalidCoverage)?
                .to_be_bytes(),
        );
        for digest in digests {
            bytes.extend_from_slice(
                &u64::try_from(digest.len())
                    .map_err(|_| AuthorityProtocolError::InvalidDigest {
                        field: "source_image_digest",
                    })?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(digest.as_bytes());
        }
        Ok(authority_sha256_hex(&bytes))
    }

    let mut before = Vec::with_capacity(images.len());
    let mut after = Vec::with_capacity(images.len());
    for image in images {
        for (field, digest, content) in [
            (
                "source_before_image_digest",
                &image.before_image_digest,
                &image.before_image,
            ),
            (
                "source_after_image_digest",
                &image.after_image_digest,
                &image.after_image,
            ),
        ] {
            authority_digest(digest, field)?;
            if authority_sha256_hex(content.as_bytes()) != *digest {
                return Err(AuthorityProtocolError::DigestMismatch { field });
            }
        }
        before.push(image.before_image_digest.clone());
        after.push(image.after_image_digest.clone());
    }
    Ok((
        side_digest(BEFORE_DOMAIN, before)?,
        side_digest(AFTER_DOMAIN, after)?,
    ))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityConfigCompletionRequest {
    pub caller: AuthorityCallerIdentity,
    pub binding: AuthorityCommitBinding,
    pub completion: AuthorityConfigCompletionEvidence,
    pub retained_staged_evidence: AuthorityRetainedStagedEvidence,
}

impl AuthorityConfigCompletionRequest {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.caller.validate()?;
        self.binding.validate()?;
        if self.binding.mutation_kind != AuthorityMutationKind::AuthorizationSource {
            return Err(AuthorityProtocolError::StateConflict {
                record: "reservation",
                state: self.binding.mutation_kind.as_text().to_owned(),
            });
        }
        if self.binding.service_id != self.caller.service_id {
            return Err(AuthorityProtocolError::CallerIdentityMismatch);
        }
        self.completion.validate(&self.binding.operation_id)?;
        let envelope: AuthorityStagedSourceEvidence =
            self.retained_staged_evidence.staged_envelope()?;
        if envelope.coverage.is_some() {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }
        let completion: AuthorityConfigCompletionEvidence =
            serde_json::from_value(envelope.evidence)
                .map_err(|_| AuthorityProtocolError::DigestMismatch { field: "evidence" })?;
        completion.validate(&self.binding.operation_id)?;
        let (before_digest, after_digest) =
            config_image_digests(&self.completion.source_batch.source_images)?;
        if self.binding.before_image_digest.as_deref() != Some(before_digest.as_str())
            || self.binding.after_image_digest != after_digest
            || config_source_commit_digest(&self.completion)? != self.binding.source_commit_digest
        {
            return Err(AuthorityProtocolError::DigestMismatch {
                field: "source_commit_binding",
            });
        }
        if completion != self.completion
            || self.retained_staged_evidence.canonical_digest()?
                != self.binding.staged_evidence_digest
        {
            return Err(AuthorityProtocolError::DigestMismatch {
                field: "staged_evidence_digest",
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityConfigCompletionReceipt {
    pub receipt_id: String,
    pub reservation_id: String,
    pub operation_id: String,
    pub event_id: String,
    pub binding: AuthorityCommitBinding,
    pub completion: AuthorityConfigCompletionEvidence,
    pub completed_at: i64,
    pub global_frontier: GlobalAuthorityFrontier,
}

impl AuthorityConfigCompletionReceipt {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        authority_text(&self.receipt_id, "receipt_id")?;
        authority_text(&self.reservation_id, "reservation_id")?;
        authority_text(&self.operation_id, "operation_id")?;
        authority_text(&self.event_id, "event_id")?;
        self.binding.validate()?;
        self.completion.validate(&self.operation_id)?;
        authority_timestamp(self.completed_at, "completed_at")?;
        self.global_frontier.validate()?;
        if self.binding.reservation_id != self.reservation_id
            || self.binding.operation_id != self.operation_id
            || self.binding.event_id != self.event_id
            || self.binding.mutation_kind != AuthorityMutationKind::AuthorizationSource
            || self.global_frontier.authorization_edition != AUTHORIZATION_EDITION
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityConfigCompletionResponse {
    pub disposition: AuthorityReservationDisposition,
    pub reservation: AuthorityScopeReservation,
    pub receipt: AuthorityConfigCompletionReceipt,
    pub global_frontier: GlobalAuthorityFrontier,
    pub read_gate: AuthorityReadGate,
}

impl AuthorityConfigCompletionResponse {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.receipt.validate()?;
        self.reservation.validate()?;
        self.global_frontier.validate()?;
        self.read_gate.validate()?;
        let binding = &self.receipt.binding;
        if self.disposition != AuthorityReservationDisposition::Completed
            || self.reservation.state != super::AuthorityReservationState::Completed
            || self.reservation.intent.mutation_kind != AuthorityMutationKind::AuthorizationSource
            || self.reservation.reservation_id != self.receipt.reservation_id
            || self.reservation.intent.operation_id != self.receipt.operation_id
            || self.reservation.intent.event_id != self.receipt.event_id
            || self.reservation.intent.service_id != binding.service_id
            || self.reservation.intent.database_id != binding.database_id
            || self.reservation.intent.request_digest != binding.request_digest
            || self.reservation.source_commit_digest.as_deref()
                != Some(binding.source_commit_digest.as_str())
            || self.reservation.after_image_digest.as_deref()
                != Some(binding.after_image_digest.as_str())
            || self.reservation.source_outcome_digest.as_deref()
                != Some(binding.source_outcome_digest.as_str())
            || self.reservation.certificate_id.is_some()
            || !self.reservation.certified_scopes.is_empty()
            || self.global_frontier != self.receipt.global_frontier
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
