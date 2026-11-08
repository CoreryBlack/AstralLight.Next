//! ROOT-signed source-bootstrap database bridge.
//!
//! This owner contains only the database-side composite transaction. Authority
//! prepare/finalize/reconcile calls happen outside the transaction. The write
//! entry point accepts only [`VerifiedSourceBootstrapPermit`], whose fields are
//! private and are produced by the fresh authority-client verification path.
//! It never accepts a raw ticket/capability DTO and never converts the source
//! capability into an ordinary `AuthorizationAdmission`.

use astral_authority::{client::AuthorityClient, error::AuthorityClientError};
use astral_types::{
    AuthoritySourceBootstrapCapability, AuthoritySourceBootstrapCompletion,
    AuthoritySourceBootstrapPrepareResponse, AuthoritySourceBootstrapReservation,
    AuthoritySourceBootstrapState, AuthoritySourceBootstrapTicket, PolicyError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{MySql, Pool, Transaction};
use time::OffsetDateTime;

use crate::{
    read_typed_source_row_image_in_tx_typed, typed_source_absent_image, TypedSourceReadError,
    TypedSourceRowLookup, TypedSourceTable,
};

const USE_TABLE: &str = "authority_source_bootstrap_use";
const IMAGE_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_SOURCE_BOOTSTRAP_IMAGES_V1\0";
const OUTCOME_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_SOURCE_BOOTSTRAP_OUTCOME_V1\0";
const CAPABILITY_DIGEST_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_SOURCE_BOOTSTRAP_CAPABILITY_DIGEST_V1\0";
const AUDIT_EVENT_TYPE: &str = "AUTHORITY_SOURCE_BOOTSTRAP";
const AUDIT_ACTION: &str = "source_bootstrap";
const AUDIT_RESOURCE: &str = "template_rule_set";
const AUDIT_DECISION: &str = "ALLOW";
const USE_STATE_PENDING: &str = "PENDING";

/// A ROOT source-bootstrap permit after the authority client has performed its
/// fresh attestation, ROOT-ticket verification, capability signature check, and
/// exact reservation binding checks. Fields are private so callers cannot forge
/// a permit by constructing a DTO.
#[derive(Debug, Clone)]
pub struct VerifiedSourceBootstrapPermit {
    ticket: AuthoritySourceBootstrapTicket,
    capability: AuthoritySourceBootstrapCapability,
    reservation: AuthoritySourceBootstrapReservation,
    ticket_digest: String,
    capability_digest: String,
    payload_digest: String,
}

impl VerifiedSourceBootstrapPermit {
    /// Verify the ROOT ticket and obtain the one-use source capability outside
    /// the DB transaction. `AuthorityClient::prepare_source_bootstrap` performs
    /// fresh attestation, server-side ROOT-key lookup/verification, response
    /// validation, and capability signature verification against the verified
    /// authority session.
    pub async fn prepare(
        client: &AuthorityClient,
        ticket: AuthoritySourceBootstrapTicket,
    ) -> Result<Self, PolicyError> {
        ticket
            .validate()
            .map_err(|error| PolicyError::InvalidContext(error.to_string()))?;
        let ticket_digest = ticket
            .artifact_digest()
            .map_err(|error| PolicyError::InvalidContext(error.to_string()))?;
        let payload_digest = ticket
            .payload_digest()
            .map_err(|error| PolicyError::InvalidContext(error.to_string()))?;
        let prepared = client
            .prepare_source_bootstrap(ticket.clone())
            .await
            .map_err(|error| {
                PolicyError::Repository(format!(
                    "source bootstrap authority prepare failed: {error}"
                ))
            })?;
        Self::from_verified_prepare(ticket, ticket_digest, payload_digest, prepared)
    }

    fn from_verified_prepare(
        ticket: AuthoritySourceBootstrapTicket,
        ticket_digest: String,
        payload_digest: String,
        prepared: AuthoritySourceBootstrapPrepareResponse,
    ) -> Result<Self, PolicyError> {
        prepared
            .validate()
            .map_err(|error| PolicyError::InvalidContext(error.to_string()))?;
        if prepared.reservation.state != AuthoritySourceBootstrapState::Reserved
            && prepared.reservation.state != AuthoritySourceBootstrapState::Completed
        {
            return Err(PolicyError::Repository(
                "source bootstrap authority reservation is not usable".into(),
            ));
        }
        let capability = prepared.capability;
        let reservation = prepared.reservation;
        validate_permit_binding(&ticket, &ticket_digest, &capability, &reservation)
            .map_err(|error| PolicyError::InvalidContext(error.to_owned()))?;
        Ok(Self {
            capability_digest: capability_digest(&capability)?,
            ticket,
            capability,
            reservation,
            ticket_digest,
            payload_digest,
        })
    }

    /// Reconcile a previously issued source-bootstrap capability without calling
    /// prepare and without changing the authority reservation. The authority
    /// client verifies the response frontier, capability signer, and any
    /// historical completion receipt; this method additionally re-verifies the
    /// ROOT ticket against the freshly trusted ROOT key before constructing the
    /// opaque permit.
    pub async fn reconcile(
        client: &AuthorityClient,
        ticket: AuthoritySourceBootstrapTicket,
    ) -> Result<Option<Self>, AuthorityClientError> {
        ticket
            .validate()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        let ticket_digest = ticket
            .artifact_digest()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        let payload_digest = ticket
            .payload_digest()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;

        let signer = client.verified_active_signer().await?;
        let attestation = client.attest_startup().await?;
        let trust_root_digest = signer
            .trust_root
            .digest()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        if ticket.authority_id != attestation.authority_id
            || ticket.root_id != signer.trust_root.root_id
            || ticket.trust_root_digest != trust_root_digest
        {
            return Err(AuthorityClientError::Protocol(
                "source bootstrap reconciliation ticket does not bind the attested trust root"
                    .to_owned(),
            ));
        }
        let root_key = signer
            .trust_root
            .key_by_id(&ticket.root_key_id)
            .filter(|key| key.role == astral_types::AuthorityRootKeyRole::Root)
            .ok_or_else(|| {
                AuthorityClientError::Protocol(
                    "source bootstrap reconciliation ticket does not name an attested ROOT key"
                        .to_owned(),
                )
            })?
            .verifying_key()
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        ticket
            .verify(&root_key)
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;

        let response = client
            .reconcile_source_bootstrap(ticket.operation_id.clone(), ticket_digest.clone())
            .await?;
        if response.operation_id != ticket.operation_id || response.ticket_digest != ticket_digest {
            return Err(AuthorityClientError::Protocol(
                "source bootstrap reconciliation response does not echo the requested operation and ticket digest"
                    .to_owned(),
            ));
        }
        let Some(capability) = response.capability else {
            if response.reservation.is_some() || response.receipt.is_some() {
                return Err(AuthorityClientError::Protocol(
                    "source bootstrap reconciliation returned an incomplete historical permit"
                        .to_owned(),
                ));
            }
            return Ok(None);
        };
        let reservation = response.reservation.ok_or_else(|| {
            AuthorityClientError::Protocol(
                "source bootstrap reconciliation returned a capability without its reservation"
                    .to_owned(),
            )
        })?;
        validate_permit_binding(&ticket, &ticket_digest, &capability, &reservation)
            .map_err(|error| AuthorityClientError::Protocol(error.to_owned()))?;
        match (&reservation.state, response.receipt.as_ref()) {
            (AuthoritySourceBootstrapState::Reserved, None)
            | (AuthoritySourceBootstrapState::Completed, Some(_)) => {}
            _ => {
                return Err(AuthorityClientError::Protocol(
                    "source bootstrap reconciliation reservation and receipt state disagree"
                        .to_owned(),
                ));
            }
        }
        if let Some(receipt) = response.receipt.as_ref() {
            if receipt.completion.reservation_id != reservation.reservation_id
                || receipt.completion.operation_id != ticket.operation_id
                || receipt.completion.event_id != ticket.event_id
                || receipt.completion.ticket_digest != ticket_digest
                || receipt.completion.source_payload_digest != payload_digest
            {
                return Err(AuthorityClientError::Protocol(
                    "source bootstrap historical receipt does not bind the ticket payload"
                        .to_owned(),
                ));
            }
        }
        let capability_digest = capability_digest(&capability)
            .map_err(|error| AuthorityClientError::Protocol(error.to_string()))?;
        Ok(Some(Self {
            ticket,
            capability,
            reservation,
            ticket_digest,
            capability_digest,
            payload_digest,
        }))
    }
    /// The exact capability to pass to authority finalize after DB COMMIT.
    pub fn capability(&self) -> &AuthoritySourceBootstrapCapability {
        &self.capability
    }

    pub fn operation_id(&self) -> &str {
        &self.ticket.operation_id
    }

    pub fn ticket_digest(&self) -> &str {
        &self.ticket_digest
    }
}

/// The only caller-supplied audit context. The audit action/resource/decision
/// are fixed by this bridge; no caller can turn the ROOT bootstrap into a
/// different authorization event.
#[derive(Debug, Clone, Copy)]
pub struct SourceBootstrapAuditContext {
    pub actor_user_id: i64,
}

/// Durable DB receipt returned only after the source/use/audit transaction has
/// committed. The completion is suitable for authority finalize outside the
/// transaction. The JSON fields are canonical retained evidence for exact
/// reconciliation and operator inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceBootstrapDbReceipt {
    pub completion: AuthoritySourceBootstrapCompletion,
    pub generated_ids_json: String,
    pub source_receipts_json: String,
    pub outcome_json: String,
    pub staged_evidence_json: String,
    pub audit_log_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GeneratedIds {
    template_id: i64,
    template_rule_ids: Vec<i64>,
    rule_set_id: i64,
    entry_ids: Vec<i64>,
    binding_ids: Vec<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReceiptIdentity {
    identity_kind: String,
    identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BootstrapImageEvidence {
    table: String,
    image: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuditReceiptImage {
    id: i64,
    user_id: i64,
    action: String,
    resource: String,
    decision: String,
    reason: Option<String>,
    card_id: Option<i64>,
    detail: Option<String>,
    event_type: Option<String>,
    source_ip: Option<String>,
    request_id: Option<String>,
    domain_id: Option<i64>,
    tenant_id: Option<i64>,
    created_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BootstrapStagedEvidence {
    ticket: AuthoritySourceBootstrapTicket,
    capability: AuthoritySourceBootstrapCapability,
    payload_digest: String,
    capability_digest: String,
    generated_ids: GeneratedIds,
    before_images: Vec<BootstrapImageEvidence>,
    after_images: Vec<BootstrapImageEvidence>,
    audit_receipt: AuditReceiptImage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BootstrapOutcome {
    operation_id: String,
    event_id: String,
    reservation_id: String,
    ticket_digest: String,
    payload_digest: String,
    generated_ids: GeneratedIds,
    before_image_digest: String,
    after_image_digest: String,
    audit_log_id: i64,
    source_receipts: Vec<ReceiptIdentity>,
    before_images: Vec<BootstrapImageEvidence>,
    after_images: Vec<BootstrapImageEvidence>,
    audit_receipt: AuditReceiptImage,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct StoredBootstrapUse {
    reservation_id: String,
    operation_id: String,
    event_id: String,
    capability_nonce: String,
    authority_id: String,
    service_id: String,
    database_id: String,
    authority_term: i64,
    global_fence_sequence: i64,
    key_epoch: i64,
    ticket_digest: Vec<u8>,
    capability_digest: Vec<u8>,
    source_payload_digest: Vec<u8>,
    before_image_digest: Vec<u8>,
    source_commit_digest: Vec<u8>,
    after_image_digest: Vec<u8>,
    source_outcome_digest: Vec<u8>,
    staged_evidence_digest: Vec<u8>,
    audit_receipt_digest: Vec<u8>,
    generated_ids: String,
    source_receipts: String,
    outcome_json: String,
    staged_evidence: String,
    state: String,
    committed_at: i64,
}

/// Read-only ROOT source-bootstrap preflight. The authority client must already
/// have verified the ROOT signature and current trust root before calling this
/// function. This DB check only proves the exact target keys are still absent;
/// it does not reserve, consume, audit, or write any source row.
pub async fn preflight_source_bootstrap(
    pool: &Pool<MySql>,
    ticket: &AuthoritySourceBootstrapTicket,
) -> Result<(), PolicyError> {
    ticket
        .validate()
        .map_err(|error| PolicyError::InvalidContext(error.to_string()))?;
    ticket.payload.validate().map_err(|error| {
        PolicyError::InvalidContext(format!("source bootstrap payload rejected: {error}"))
    })?;
    if !ticket.payload.bindings.is_empty() {
        return Err(PolicyError::InvalidContext(
            "source bootstrap bindings require a real WorkerOwned delta path; refusing to drop signed bindings".into(),
        ));
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|error| db_error("begin source bootstrap preflight", error))?;
    let result = preflight_source_bootstrap_in_tx(&mut tx, ticket).await;
    tx.rollback()
        .await
        .map_err(|error| db_error("rollback source bootstrap preflight", error))?;
    result
}

async fn preflight_source_bootstrap_in_tx(
    tx: &mut Transaction<'_, MySql>,
    ticket: &AuthoritySourceBootstrapTicket,
) -> Result<(), PolicyError> {
    let template = &ticket.payload.template;
    let template_lookup = TypedSourceRowLookup::CardTemplateNatural {
        domain_id: template.domain_id,
        template_code: template.template_code.clone(),
    };
    let rule_set_lookup = TypedSourceRowLookup::RuleSetCode {
        code: ticket.payload.rule_set.code.clone(),
    };
    let template_row = read_typed_source_row_image_in_tx_typed(
        tx,
        TypedSourceTable::UserCardTemplate,
        &template_lookup,
    )
    .await
    .map_err(map_typed_reader_error)?;
    if template_row.is_some() {
        return Err(PolicyError::Repository(
            "source bootstrap preflight template natural key is not ABSENT".into(),
        ));
    }
    let rule_set_row =
        read_typed_source_row_image_in_tx_typed(tx, TypedSourceTable::RuleSet, &rule_set_lookup)
            .await
            .map_err(map_typed_reader_error)?;
    if rule_set_row.is_some() {
        return Err(PolicyError::Repository(
            "source bootstrap preflight RuleSet code is not ABSENT".into(),
        ));
    }
    let absent_images = [
        typed_source_absent_image(TypedSourceTable::UserCardTemplate, &template_lookup)
            .map_err(|error| PolicyError::InvalidContext(error.to_string()))?,
        permission_template_absent_image(template)?,
        typed_source_absent_image(TypedSourceTable::RuleSet, &rule_set_lookup)
            .map_err(|error| PolicyError::InvalidContext(error.to_string()))?,
    ];
    for image in absent_images {
        let value = serde_json::from_str::<Value>(&image).map_err(|error| {
            PolicyError::Repository(format!(
                "source bootstrap preflight ABSENT image is malformed: {error}"
            ))
        })?;
        if value.get("presence") != Some(&Value::String("ABSENT".to_owned())) {
            return Err(PolicyError::Repository(
                "source bootstrap preflight did not produce typed ABSENT evidence".into(),
            ));
        }
    }
    Ok(())
}

/// Apply the complete source aggregate in one transaction. The caller must
/// commit this transaction before invoking authority finalize. No network call
/// is made while the transaction is held.
pub async fn create_source_bootstrap_in_tx(
    tx: &mut Transaction<'_, MySql>,
    permit: &VerifiedSourceBootstrapPermit,
    audit: SourceBootstrapAuditContext,
) -> Result<SourceBootstrapDbReceipt, PolicyError> {
    permit.ticket.payload.validate().map_err(|error| {
        PolicyError::InvalidContext(format!("source bootstrap payload rejected: {error}"))
    })?;
    if audit.actor_user_id <= 0 {
        return Err(PolicyError::InvalidContext(
            "source bootstrap audit actor must be a positive user id".into(),
        ));
    }
    if !permit.ticket.payload.bindings.is_empty() {
        return Err(PolicyError::InvalidContext(
            "source bootstrap bindings require a real WorkerOwned delta path; refusing to drop signed bindings".into(),
        ));
    }

    if let Some(existing) = read_existing_use(tx, permit).await? {
        return receipt_from_exact_row(tx, existing, permit).await;
    }
    if permit.reservation.state != AuthoritySourceBootstrapState::Reserved {
        return Err(PolicyError::Repository(
            "authority source bootstrap is already completed; reconcile exact DB and quorum state before any write".into(),
        ));
    }

    let template_lookup = TypedSourceRowLookup::CardTemplateNatural {
        domain_id: permit.ticket.payload.template.domain_id,
        template_code: permit.ticket.payload.template.template_code.clone(),
    };
    let rule_set_lookup = TypedSourceRowLookup::RuleSetCode {
        code: permit.ticket.payload.rule_set.code.clone(),
    };
    let template = &permit.ticket.payload.template;
    let template_before = read_typed_source_row_image_in_tx_typed(
        tx,
        TypedSourceTable::UserCardTemplate,
        &template_lookup,
    )
    .await
    .map_err(map_typed_reader_error)?;
    if template_before.is_some() {
        return Err(PolicyError::Repository(
            "source bootstrap template natural key is already present".into(),
        ));
    }
    let rule_set_before =
        read_typed_source_row_image_in_tx_typed(tx, TypedSourceTable::RuleSet, &rule_set_lookup)
            .await
            .map_err(map_typed_reader_error)?;
    if rule_set_before.is_some() {
        return Err(PolicyError::Repository(
            "source bootstrap RuleSet code is already present".into(),
        ));
    }
    let before_images = vec![
        (
            TypedSourceTable::UserCardTemplate.as_str(),
            typed_source_absent_image(TypedSourceTable::UserCardTemplate, &template_lookup)
                .map_err(|error| PolicyError::InvalidContext(error.to_string()))?,
        ),
        (
            TypedSourceTable::PermissionRuleTemplate.as_str(),
            permission_template_absent_image(template)?,
        ),
        (
            TypedSourceTable::RuleSet.as_str(),
            typed_source_absent_image(TypedSourceTable::RuleSet, &rule_set_lookup)
                .map_err(|error| PolicyError::InvalidContext(error.to_string()))?,
        ),
    ];
    let before_image_evidence = image_evidence(&before_images)?;
    let before_image_digest = digest_image_evidence(&before_image_evidence)?;

    let template_scope = template.template_scope.as_deref().unwrap_or("SYSTEM");
    if !matches!(template_scope, "SYSTEM" | "DOMAIN" | "ORG") {
        return Err(PolicyError::InvalidContext(
            "source bootstrap template_scope is outside the closed schema set".into(),
        ));
    }
    let version_no = template.version_no.unwrap_or(1);
    let default_priority = template.default_priority.unwrap_or(100);
    if version_no <= 0 || default_priority < 0 {
        return Err(PolicyError::InvalidContext(
            "source bootstrap template defaults are invalid".into(),
        ));
    }
    let default_roles_json =
        canonical_optional_json(template.default_roles_json.as_deref(), "default_roles_json")?;
    let resource_scope_json = canonical_optional_json(
        template.resource_scope_json.as_deref(),
        "resource_scope_json",
    )?;
    if let Some(parent_template_id) = template.parent_template_id {
        let parent: Option<(i64, i64, Option<i64>)> = sqlx::query_as(
            "SELECT template_id, domain_id, tenant_id FROM user_card_template WHERE template_id = ? FOR UPDATE",
        )
        .bind(parent_template_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| db_error("lock source bootstrap parent template", error))?;
        let Some((_, parent_domain_id, parent_tenant_id)) = parent else {
            return Err(PolicyError::Repository(
                "source bootstrap parent template is missing".into(),
            ));
        };
        if parent_domain_id != template.domain_id || parent_tenant_id != template.tenant_id {
            return Err(PolicyError::InvalidContext(
                "source bootstrap parent template crosses domain or tenant boundary".into(),
            ));
        }
    }

    let template_result = sqlx::query(
        "INSERT INTO user_card_template \
         (domain_id, tenant_id, parent_template_id, template_code, template_name, card_type, \
          template_scope, version_no, default_priority, default_roles_json, resource_scope_json, status) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(template.domain_id)
    .bind(template.tenant_id)
    .bind(template.parent_template_id)
    .bind(&template.template_code)
    .bind(&template.template_name)
    .bind(&template.card_type)
    .bind(template_scope)
    .bind(version_no)
    .bind(default_priority)
    .bind(default_roles_json.as_deref())
    .bind(resource_scope_json.as_deref())
    .bind(&template.status)
    .execute(&mut **tx)
    .await
    .map_err(|error| db_error("insert source bootstrap template", error))?;
    if template_result.rows_affected() != 1 || template_result.last_insert_id() == 0 {
        return Err(PolicyError::Repository(
            "source bootstrap template insert did not return one generated id".into(),
        ));
    }
    let template_id = i64::try_from(template_result.last_insert_id())
        .map_err(|_| PolicyError::InvalidContext("generated template id exceeds i64".into()))?;

    let mut template_rule_ids = Vec::with_capacity(permit.ticket.payload.template_rules.len());
    for rule in &permit.ticket.payload.template_rules {
        let condition_json = canonical_optional_json(
            rule.condition_json.as_deref(),
            "template_rule.condition_json",
        )?;
        let result = sqlx::query(
            "INSERT INTO permission_rule_template \
             (template_id, resource_type, resource_id, action_code, effect, condition_json, priority, enabled) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(template_id)
        .bind(&rule.resource_type)
        .bind(rule.resource_id)
        .bind(&rule.action_code)
        .bind(&rule.effect)
        .bind(condition_json.as_deref())
        .bind(rule.priority)
        .bind(rule.enabled)
        .execute(&mut **tx)
        .await
        .map_err(|error| db_error("insert source bootstrap template rule", error))?;
        if result.rows_affected() != 1 || result.last_insert_id() == 0 {
            return Err(PolicyError::Repository(
                "source bootstrap template rule insert did not return one generated id".into(),
            ));
        }
        template_rule_ids.push(i64::try_from(result.last_insert_id()).map_err(|_| {
            PolicyError::InvalidContext("generated template rule id exceeds i64".into())
        })?);
    }

    let rule_set = &permit.ticket.payload.rule_set;
    let rule_set_result = sqlx::query(
        "INSERT INTO rule_set \
         (name, code, description, source_type, source_id, enabled, tenant_id) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&rule_set.name)
    .bind(&rule_set.code)
    .bind(&rule_set.description)
    .bind(&rule_set.source_type)
    .bind(template_id)
    .bind(rule_set.enabled)
    .bind(rule_set.tenant_id)
    .execute(&mut **tx)
    .await
    .map_err(|error| db_error("insert source bootstrap RuleSet", error))?;
    if rule_set_result.rows_affected() != 1 || rule_set_result.last_insert_id() == 0 {
        return Err(PolicyError::Repository(
            "source bootstrap RuleSet insert did not return one generated id".into(),
        ));
    }
    let rule_set_id = i64::try_from(rule_set_result.last_insert_id())
        .map_err(|_| PolicyError::InvalidContext("generated RuleSet id exceeds i64".into()))?;

    let mut entry_ids = Vec::with_capacity(permit.ticket.payload.rule_set_entries.len());
    for entry in &permit.ticket.payload.rule_set_entries {
        let condition_json = canonical_optional_json(
            entry.condition_json.as_deref(),
            "rule_set_entry.condition_json",
        )?;
        let result = sqlx::query(
            "INSERT INTO rule_set_entry \
             (rule_set_id, resource_type, resource_id, action_code, effect, condition_json, priority, enabled, valid_from, valid_to, tenant_id) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(rule_set_id)
        .bind(&entry.resource_type)
        .bind(entry.resource_id)
        .bind(&entry.action_code)
        .bind(&entry.effect)
        .bind(condition_json.as_deref())
        .bind(entry.priority)
        .bind(entry.enabled)
        .bind(&entry.valid_from)
        .bind(&entry.valid_to)
        .bind(entry.tenant_id)
        .execute(&mut **tx)
        .await
        .map_err(|error| db_error("insert source bootstrap RuleSet entry", error))?;
        if result.rows_affected() != 1 || result.last_insert_id() == 0 {
            return Err(PolicyError::Repository(
                "source bootstrap RuleSet entry insert did not return one generated id".into(),
            ));
        }
        entry_ids.push(i64::try_from(result.last_insert_id()).map_err(|_| {
            PolicyError::InvalidContext("generated RuleSet entry id exceeds i64".into())
        })?);
    }

    let generated_ids = GeneratedIds {
        template_id,
        template_rule_ids,
        rule_set_id,
        entry_ids,
        binding_ids: Vec::new(),
    };
    let template_after_lookup =
        TypedSourceRowLookup::PermissionRuleTemplateAggregate { template_id };
    let template_after = read_typed_source_row_image_in_tx_typed(
        tx,
        TypedSourceTable::PermissionRuleTemplate,
        &template_after_lookup,
    )
    .await
    .map_err(map_typed_reader_error)?
    .ok_or_else(|| {
        PolicyError::Repository("source bootstrap aggregate after image is missing".into())
    })?;
    let template_root_after = read_typed_source_row_image_in_tx_typed(
        tx,
        TypedSourceTable::UserCardTemplate,
        &TypedSourceRowLookup::PrimaryId { id: template_id },
    )
    .await
    .map_err(map_typed_reader_error)?
    .ok_or_else(|| {
        PolicyError::Repository("source bootstrap template after image is missing".into())
    })?;
    let rule_set_after =
        read_typed_source_row_image_in_tx_typed(tx, TypedSourceTable::RuleSet, &rule_set_lookup)
            .await
            .map_err(map_typed_reader_error)?
            .ok_or_else(|| {
                PolicyError::Repository("source bootstrap RuleSet after image is missing".into())
            })?;
    if template_after.0 != template_id || rule_set_after.0 != rule_set_id {
        return Err(PolicyError::Repository(
            "source bootstrap after image generated ids do not match inserted ids".into(),
        ));
    }
    let after_images = vec![
        (
            TypedSourceTable::UserCardTemplate.as_str(),
            template_root_after.1,
        ),
        (
            TypedSourceTable::PermissionRuleTemplate.as_str(),
            template_after.1,
        ),
        (TypedSourceTable::RuleSet.as_str(), rule_set_after.1),
    ];
    let after_image_evidence = image_evidence(&after_images)?;
    validate_signed_payload_images_from_evidence(
        &permit.ticket,
        &generated_ids,
        &after_image_evidence,
    )?;
    let after_image_digest = digest_image_evidence(&after_image_evidence)?;

    let mut source_receipts = Vec::new();
    source_receipts.push(receipt("user_card_template", template_id));
    source_receipts.extend(
        generated_ids
            .template_rule_ids
            .iter()
            .copied()
            .map(|id| receipt("permission_rule_template", id)),
    );
    source_receipts.push(receipt("rule_set", rule_set_id));
    source_receipts.extend(
        generated_ids
            .entry_ids
            .iter()
            .copied()
            .map(|id| receipt("rule_set_entry", id)),
    );

    let detail_json = bootstrap_audit_detail(BootstrapAuditDetail {
        ticket: &permit.ticket,
        actor_user_id: audit.actor_user_id,
        ticket_digest: &permit.ticket_digest,
        payload_digest: &permit.payload_digest,
        capability_digest: &permit.capability_digest,
        generated_ids: &generated_ids,
        before_image_digest: &before_image_digest,
        after_image_digest: &after_image_digest,
    })?;

    let audit_result = sqlx::query(
        "INSERT INTO audit_log \
         (user_id, action, resource, decision, reason, detail, event_type, request_id, domain_id, tenant_id) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(audit.actor_user_id)
    .bind(AUDIT_ACTION)
    .bind(AUDIT_RESOURCE)
    .bind(AUDIT_DECISION)
    .bind("ROOT_SIGNED_SOURCE_BOOTSTRAP")
    .bind(&detail_json)
    .bind(AUDIT_EVENT_TYPE)
    .bind(&permit.ticket.operation_id)
    .bind(permit.ticket.payload.template.domain_id)
    .bind(permit.ticket.payload.template.tenant_id)
    .execute(&mut **tx)
    .await
    .map_err(|error| db_error("insert source bootstrap audit", error))?;
    if audit_result.rows_affected() != 1 || audit_result.last_insert_id() == 0 {
        return Err(PolicyError::Repository(
            "source bootstrap audit insert did not return one generated id".into(),
        ));
    }
    let audit_log_id = i64::try_from(audit_result.last_insert_id())
        .map_err(|_| PolicyError::InvalidContext("generated audit id exceeds i64".into()))?;
    let audit_receipt = read_audit_receipt_in_tx(tx, audit_log_id).await?;
    validate_audit_receipt(
        &audit_receipt,
        audit.actor_user_id,
        &permit.ticket,
        &detail_json,
    )?;
    source_receipts.push(receipt("audit_log", audit_log_id));
    let audit_receipt_digest = digest_audit_receipt(&audit_receipt)?;

    let staged = BootstrapStagedEvidence {
        ticket: permit.ticket.clone(),
        capability: permit.capability.clone(),
        payload_digest: permit.payload_digest.clone(),
        capability_digest: permit.capability_digest.clone(),
        generated_ids: generated_ids.clone(),
        before_images: before_image_evidence.clone(),
        after_images: after_image_evidence.clone(),
        audit_receipt: audit_receipt.clone(),
    };
    let staged_evidence_json = canonical_json(&staged, "staged evidence")?;
    let outcome = BootstrapOutcome {
        operation_id: permit.ticket.operation_id.clone(),
        event_id: permit.ticket.event_id.clone(),
        reservation_id: permit.reservation.reservation_id.clone(),
        ticket_digest: permit.ticket_digest.clone(),
        payload_digest: permit.payload_digest.clone(),
        generated_ids: generated_ids.clone(),
        before_image_digest: before_image_digest.clone(),
        after_image_digest: after_image_digest.clone(),
        audit_log_id,
        source_receipts: source_receipts.clone(),
        before_images: before_image_evidence,
        after_images: after_image_evidence,
        audit_receipt,
    };
    let outcome_json = canonical_json(&outcome, "source outcome")?;
    let source_commit_digest = crate::source_commit_digest(&staged_evidence_json, &outcome_json);
    let source_outcome_digest = digest_domain_json(OUTCOME_DOMAIN, &outcome_json);
    let staged_evidence_digest = digest_bytes(staged_evidence_json.as_bytes());
    let generated_ids_json = canonical_json(&generated_ids, "generated ids")?;
    let source_receipts_json = canonical_json(&source_receipts, "source receipts")?;
    let committed_at = OffsetDateTime::now_utc().unix_timestamp();
    let completion = AuthoritySourceBootstrapCompletion {
        reservation_id: permit.reservation.reservation_id.clone(),
        operation_id: permit.ticket.operation_id.clone(),
        event_id: permit.ticket.event_id.clone(),
        ticket_digest: permit.ticket_digest.clone(),
        source_payload_digest: permit.payload_digest.clone(),
        before_image_digest,
        source_commit_digest: source_commit_digest.clone(),
        after_image_digest,
        source_outcome_digest: source_outcome_digest.clone(),
        staged_evidence_digest: staged_evidence_digest.clone(),
        audit_receipt_digest: audit_receipt_digest.clone(),
        committed_at,
    };
    completion
        .validate()
        .map_err(|error| PolicyError::InvalidContext(error.to_string()))?;

    let use_result = sqlx::query(
        "INSERT INTO authority_source_bootstrap_use \
         (reservation_id, operation_id, event_id, capability_nonce, authority_id, service_id, database_id, \
          authority_term, global_fence_sequence, key_epoch, ticket_digest, capability_digest, source_payload_digest, \
          before_image_digest, source_commit_digest, after_image_digest, source_outcome_digest, staged_evidence_digest, \
          audit_receipt_digest, generated_ids, source_receipts, outcome_json, staged_evidence, state, committed_at, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, UNHEX(?), UNHEX(?), UNHEX(?), UNHEX(?), UNHEX(?), UNHEX(?), UNHEX(?), UNHEX(?), UNHEX(?), ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&permit.reservation.reservation_id)
    .bind(&permit.ticket.operation_id)
    .bind(&permit.ticket.event_id)
    .bind(&permit.capability.capability_nonce)
    .bind(&permit.capability.authority_id)
    .bind(&permit.ticket.service_id)
    .bind(&permit.ticket.database_id)
    .bind(storage_counter(permit.capability.authority_term)?)
    .bind(storage_counter(permit.capability.global_fence_sequence)?)
    .bind(storage_counter(permit.capability.key_epoch)?)
    .bind(&permit.ticket_digest)
    .bind(&permit.capability_digest)
    .bind(&permit.payload_digest)
    .bind(&completion.before_image_digest)
    .bind(&completion.source_commit_digest)
    .bind(&completion.after_image_digest)
    .bind(&completion.source_outcome_digest)
    .bind(&completion.staged_evidence_digest)
    .bind(&completion.audit_receipt_digest)
    .bind(&generated_ids_json)
    .bind(&source_receipts_json)
    .bind(&outcome_json)
    .bind(&staged_evidence_json)
    .bind(USE_STATE_PENDING)
    .bind(committed_at)
    .bind(committed_at)
    .bind(committed_at)
    .execute(&mut **tx)
    .await
    .map_err(|error| db_error("consume source bootstrap capability", error))?;
    if use_result.rows_affected() != 1 {
        return Err(PolicyError::Repository(
            "source bootstrap capability-use did not affect exactly one row".into(),
        ));
    }

    Ok(SourceBootstrapDbReceipt {
        completion,
        generated_ids_json,
        source_receipts_json,
        outcome_json,
        staged_evidence_json,
        audit_log_id,
    })
}

/// Begin, apply, and commit one DB bridge transaction. Authority finalize must
/// be called only after this returns. A commit error is intentionally reported as
/// UNKNOWN; callers must reconcile the exact operation before any retry.
pub async fn create_source_bootstrap(
    pool: &Pool<MySql>,
    permit: &VerifiedSourceBootstrapPermit,
    audit: SourceBootstrapAuditContext,
) -> Result<SourceBootstrapDbReceipt, PolicyError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| db_error("begin source bootstrap transaction", error))?;
    let receipt = create_source_bootstrap_in_tx(&mut tx, permit, audit).await?;
    tx.commit().await.map_err(|error| {
        PolicyError::Repository(format!(
            "UNKNOWN source bootstrap DB COMMIT for operation {}; reconcile exact DB and quorum state before retry: {error}",
            permit.ticket.operation_id
        ))
    })?;
    Ok(receipt)
}

/// Exact DB-only reconciliation. It performs no source write and never retries
/// an unknown transaction. The caller must pair this with authority quorum
/// reconciliation using the same operation and ticket digest.
pub async fn reconcile_source_bootstrap_db(
    pool: &Pool<MySql>,
    permit: &VerifiedSourceBootstrapPermit,
) -> Result<Option<SourceBootstrapDbReceipt>, PolicyError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| db_error("begin source bootstrap DB reconciliation", error))?;
    let row = read_existing_use(&mut tx, permit).await?;
    let result = if let Some(row) = row {
        Some(receipt_from_exact_row(&mut tx, row, permit).await?)
    } else {
        None
    };
    tx.rollback()
        .await
        .map_err(|error| db_error("rollback source bootstrap DB reconciliation", error))?;
    Ok(result)
}

async fn read_existing_use(
    tx: &mut Transaction<'_, MySql>,
    permit: &VerifiedSourceBootstrapPermit,
) -> Result<Option<StoredBootstrapUse>, PolicyError> {
    sqlx::query_as::<_, StoredBootstrapUse>(&format!(
        "SELECT reservation_id, operation_id, event_id, capability_nonce, authority_id, service_id, database_id, \
         authority_term, global_fence_sequence, key_epoch, ticket_digest, capability_digest, source_payload_digest, \
         before_image_digest, source_commit_digest, after_image_digest, source_outcome_digest, staged_evidence_digest, \
         audit_receipt_digest, CAST(generated_ids AS CHAR) AS generated_ids, CAST(source_receipts AS CHAR) AS source_receipts, CAST(outcome_json AS CHAR) AS outcome_json, \
         CAST(staged_evidence AS CHAR) AS staged_evidence, state, committed_at FROM {USE_TABLE} \
         WHERE reservation_id = ? OR operation_id = ? OR event_id = ? OR capability_nonce = ? \
         ORDER BY reservation_id LIMIT 2 FOR UPDATE"
    ))
    .bind(&permit.reservation.reservation_id)
    .bind(&permit.ticket.operation_id)
    .bind(&permit.ticket.event_id)
    .bind(&permit.capability.capability_nonce)
    .fetch_all(&mut **tx)
    .await
    .map_err(|error| db_error("read source bootstrap capability-use", error))
    .and_then(|rows| match rows.as_slice() {
        [] => Ok(None),
        [row] => Ok(Some(row.clone())),
        _ => Err(PolicyError::Repository(
            "source bootstrap capability-use unique identity rows contradict each other".into(),
        )),
    })
}

async fn read_audit_receipt_in_tx(
    tx: &mut Transaction<'_, MySql>,
    audit_log_id: i64,
) -> Result<AuditReceiptImage, PolicyError> {
    if audit_log_id <= 0 {
        return Err(PolicyError::Repository(
            "source bootstrap audit id must be positive".into(),
        ));
    }
    sqlx::query_as::<_, AuditReceiptImage>(
        "SELECT id, user_id, CAST(action AS CHAR) AS action, CAST(resource AS CHAR) AS resource, \
         CAST(decision AS CHAR) AS decision, CAST(reason AS CHAR) AS reason, card_id, \
         CAST(detail AS CHAR) AS detail, CAST(event_type AS CHAR) AS event_type, \
         CAST(source_ip AS CHAR) AS source_ip, CAST(request_id AS CHAR) AS request_id, \
         domain_id, tenant_id, CAST(created_at AS CHAR) AS created_at \
         FROM audit_log WHERE id = ? FOR UPDATE",
    )
    .bind(audit_log_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| db_error("read source bootstrap audit receipt", error))?
    .ok_or_else(|| {
        PolicyError::Repository(
            "source bootstrap audit row disappeared before receipt capture".into(),
        )
    })
}

fn validate_audit_receipt(
    actual: &AuditReceiptImage,
    actor_user_id: i64,
    ticket: &AuthoritySourceBootstrapTicket,
    expected_detail: &str,
) -> Result<(), PolicyError> {
    let detail: Value = serde_json::from_str(expected_detail).map_err(|error| {
        PolicyError::Repository(format!(
            "source bootstrap audit detail is malformed: {error}"
        ))
    })?;
    let detail_object = detail.as_object().ok_or_else(|| {
        PolicyError::Repository("source bootstrap audit detail is not an object".into())
    })?;
    let detail_identity_matches = detail_object.get("actorUserId")
        == Some(&serde_json::json!(actor_user_id))
        && detail_object.get("operationId") == Some(&Value::String(ticket.operation_id.clone()))
        && detail_object.get("eventId") == Some(&Value::String(ticket.event_id.clone()))
        && detail_object.get("ticketDigest")
            == Some(&Value::String(
                ticket
                    .artifact_digest()
                    .map_err(|error| PolicyError::Repository(error.to_string()))?,
            ))
        && detail_object.get("payloadDigest")
            == Some(&Value::String(
                ticket
                    .payload_digest()
                    .map_err(|error| PolicyError::Repository(error.to_string()))?,
            ));
    if actual.id <= 0
        || actual.user_id != actor_user_id
        || actual.action != AUDIT_ACTION
        || actual.resource != AUDIT_RESOURCE
        || actual.decision != AUDIT_DECISION
        || actual.reason.as_deref() != Some("ROOT_SIGNED_SOURCE_BOOTSTRAP")
        || actual.card_id.is_some()
        || actual.detail.as_deref() != Some(expected_detail)
        || actual.event_type.as_deref() != Some(AUDIT_EVENT_TYPE)
        || actual.source_ip.is_some()
        || actual.request_id.as_deref() != Some(ticket.operation_id.as_str())
        || actual.domain_id != Some(ticket.payload.template.domain_id)
        || actual.tenant_id != ticket.payload.template.tenant_id
        || actual.created_at.is_none()
        || !detail_identity_matches
    {
        return Err(PolicyError::Repository(
            "source bootstrap audit receipt differs from the fixed inserted audit row".into(),
        ));
    }
    Ok(())
}

struct BootstrapAuditDetail<'a> {
    ticket: &'a AuthoritySourceBootstrapTicket,
    actor_user_id: i64,
    ticket_digest: &'a str,
    payload_digest: &'a str,
    capability_digest: &'a str,
    generated_ids: &'a GeneratedIds,
    before_image_digest: &'a str,
    after_image_digest: &'a str,
}

fn bootstrap_audit_detail(input: BootstrapAuditDetail<'_>) -> Result<String, PolicyError> {
    let BootstrapAuditDetail {
        ticket,
        actor_user_id,
        ticket_digest,
        payload_digest,
        capability_digest,
        generated_ids,
        before_image_digest,
        after_image_digest,
    } = input;
    canonical_json(
        &serde_json::json!({
            "actorUserId": actor_user_id,
            "operationId": ticket.operation_id,
            "eventId": ticket.event_id,
            "ticketDigest": ticket_digest,
            "payloadDigest": payload_digest,
            "capabilityDigest": capability_digest,
            "generatedIds": generated_ids,
            "beforeImageDigest": before_image_digest,
            "afterImageDigest": after_image_digest,
        }),
        "bootstrap audit detail",
    )
}

fn digest_audit_receipt(receipt: &AuditReceiptImage) -> Result<String, PolicyError> {
    let json = canonical_json(receipt, "audit receipt")?;
    Ok(digest_domain_json(
        b"ASTRAL_AUTHORITY_SOURCE_BOOTSTRAP_RECEIPT_V1\0",
        &json,
    ))
}

fn canonicalize_stored_json<T>(raw: &str, field: &'static str) -> Result<(T, String), PolicyError>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let parsed = serde_json::from_str::<T>(raw).map_err(|error| {
        PolicyError::Repository(format!("stored bootstrap {field} is malformed: {error}"))
    })?;
    let canonical = canonical_json(&parsed, field)
        .map_err(|error| PolicyError::Repository(error.to_string()))?;
    Ok((parsed, canonical))
}

async fn receipt_from_exact_row(
    tx: &mut Transaction<'_, MySql>,
    row: StoredBootstrapUse,
    permit: &VerifiedSourceBootstrapPermit,
) -> Result<SourceBootstrapDbReceipt, PolicyError> {
    permit.ticket.validate().map_err(|error| {
        PolicyError::Repository(format!(
            "stored bootstrap permit ticket is invalid: {error}"
        ))
    })?;
    let expected = [
        (
            "reservation_id",
            row.reservation_id.as_str(),
            permit.reservation.reservation_id.as_str(),
        ),
        (
            "operation_id",
            row.operation_id.as_str(),
            permit.ticket.operation_id.as_str(),
        ),
        (
            "event_id",
            row.event_id.as_str(),
            permit.ticket.event_id.as_str(),
        ),
        (
            "capability_nonce",
            row.capability_nonce.as_str(),
            permit.capability.capability_nonce.as_str(),
        ),
        (
            "authority_id",
            row.authority_id.as_str(),
            permit.capability.authority_id.as_str(),
        ),
        (
            "service_id",
            row.service_id.as_str(),
            permit.ticket.service_id.as_str(),
        ),
        (
            "database_id",
            row.database_id.as_str(),
            permit.ticket.database_id.as_str(),
        ),
    ];
    let expected_capability_digest = capability_digest(&permit.capability)?;
    if expected.iter().any(|(_, actual, wanted)| actual != wanted)
        || row.authority_term != storage_counter(permit.capability.authority_term)?
        || row.global_fence_sequence != storage_counter(permit.capability.global_fence_sequence)?
        || row.key_epoch != storage_counter(permit.capability.key_epoch)?
        || !digest_matches(&row.ticket_digest, &permit.ticket_digest)
        || !digest_matches(&row.capability_digest, &expected_capability_digest)
        || !digest_matches(&row.source_payload_digest, &permit.payload_digest)
        || row.state != USE_STATE_PENDING
    {
        return Err(PolicyError::Repository(
            "source bootstrap capability-use exact identity readback mismatch".into(),
        ));
    }

    let (outcome, outcome_json) =
        canonicalize_stored_json::<BootstrapOutcome>(&row.outcome_json, "source outcome")?;
    let (generated_ids, generated_ids_json) =
        canonicalize_stored_json::<GeneratedIds>(&row.generated_ids, "generated ids")?;
    let (source_receipts, source_receipts_json) =
        canonicalize_stored_json::<Vec<ReceiptIdentity>>(&row.source_receipts, "source receipts")?;
    let (staged, staged_evidence_json) = canonicalize_stored_json::<BootstrapStagedEvidence>(
        &row.staged_evidence,
        "staged evidence",
    )?;
    let audit_receipt = read_audit_receipt_in_tx(tx, outcome.audit_log_id).await?;

    validate_generated_ids(&generated_ids, &permit.ticket)?;
    let expected_receipts = expected_source_receipts(&generated_ids, outcome.audit_log_id);
    if source_receipts != expected_receipts
        || outcome.generated_ids != generated_ids
        || outcome.source_receipts != source_receipts
        || staged.generated_ids != generated_ids
        || staged.payload_digest != permit.payload_digest
        || staged.capability_digest != expected_capability_digest
        || staged.ticket != permit.ticket
        || staged.capability != permit.capability
        || staged.audit_receipt != audit_receipt
        || outcome.audit_receipt != audit_receipt
        || outcome.operation_id != permit.ticket.operation_id
        || outcome.event_id != permit.ticket.event_id
        || outcome.reservation_id != permit.reservation.reservation_id
        || outcome.ticket_digest != permit.ticket_digest
        || outcome.payload_digest != permit.payload_digest
        || outcome.audit_log_id <= 0
        || staged.before_images != outcome.before_images
        || staged.after_images != outcome.after_images
    {
        return Err(PolicyError::Repository(
            "source bootstrap capability-use retained identity or evidence differs from the verified permit".into(),
        ));
    }

    let expected_before = expected_before_images(permit)?;
    if staged.before_images != expected_before {
        return Err(PolicyError::Repository(
            "source bootstrap retained before images differ from the typed ABSENT proof".into(),
        ));
    }
    validate_signed_payload_images_from_evidence(
        &permit.ticket,
        &generated_ids,
        &staged.after_images,
    )?;
    let before_image_digest = digest_image_evidence(&staged.before_images)?;
    let after_image_digest = digest_image_evidence(&staged.after_images)?;
    let staged_evidence_digest = digest_bytes(staged_evidence_json.as_bytes());
    let source_outcome_digest = digest_domain_json(OUTCOME_DOMAIN, &outcome_json);
    let source_commit_digest = crate::source_commit_digest(&staged_evidence_json, &outcome_json);
    let audit_receipt_digest = digest_audit_receipt(&audit_receipt)?;
    let expected_detail = bootstrap_audit_detail(BootstrapAuditDetail {
        ticket: &permit.ticket,
        actor_user_id: audit_receipt.user_id,
        ticket_digest: &permit.ticket_digest,
        payload_digest: &permit.payload_digest,
        capability_digest: &expected_capability_digest,
        generated_ids: &generated_ids,
        before_image_digest: &before_image_digest,
        after_image_digest: &after_image_digest,
    })?;
    validate_audit_receipt(
        &audit_receipt,
        audit_receipt.user_id,
        &permit.ticket,
        &expected_detail,
    )?;
    if outcome.before_image_digest != before_image_digest
        || outcome.after_image_digest != after_image_digest
        || !digest_matches(&row.before_image_digest, &before_image_digest)
        || !digest_matches(&row.after_image_digest, &after_image_digest)
        || !digest_matches(&row.source_commit_digest, &source_commit_digest)
        || !digest_matches(&row.source_outcome_digest, &source_outcome_digest)
        || !digest_matches(&row.staged_evidence_digest, &staged_evidence_digest)
        || !digest_matches(&row.audit_receipt_digest, &audit_receipt_digest)
    {
        return Err(PolicyError::Repository(
            "source bootstrap capability-use canonical evidence digest mismatch".into(),
        ));
    }

    let completion = AuthoritySourceBootstrapCompletion {
        reservation_id: row.reservation_id,
        operation_id: row.operation_id,
        event_id: row.event_id,
        ticket_digest: permit.ticket_digest.clone(),
        source_payload_digest: permit.payload_digest.clone(),
        before_image_digest: hex32(&row.before_image_digest, "before_image_digest")?,
        source_commit_digest: hex32(&row.source_commit_digest, "source_commit_digest")?,
        after_image_digest: hex32(&row.after_image_digest, "after_image_digest")?,
        source_outcome_digest: hex32(&row.source_outcome_digest, "source_outcome_digest")?,
        staged_evidence_digest: hex32(&row.staged_evidence_digest, "staged_evidence_digest")?,
        audit_receipt_digest: hex32(&row.audit_receipt_digest, "audit_receipt_digest")?,
        committed_at: row.committed_at,
    };
    completion
        .validate()
        .map_err(|error| PolicyError::Repository(error.to_string()))?;
    Ok(SourceBootstrapDbReceipt {
        completion,
        generated_ids_json,
        source_receipts_json,
        outcome_json,
        staged_evidence_json,
        audit_log_id: outcome.audit_log_id,
    })
}

fn validate_permit_binding(
    ticket: &AuthoritySourceBootstrapTicket,
    ticket_digest: &str,
    capability: &AuthoritySourceBootstrapCapability,
    reservation: &AuthoritySourceBootstrapReservation,
) -> Result<(), &'static str> {
    if capability.ticket_digest != ticket_digest
        || capability.operation_id != ticket.operation_id
        || capability.event_id != ticket.event_id
        || capability.service_id != ticket.service_id
        || capability.database_id != ticket.database_id
        || capability.root_key_id != ticket.root_key_id
        || capability.trust_root_digest != ticket.trust_root_digest
        || capability.authority_id != ticket.authority_id
        || reservation.ticket_digest != ticket_digest
        || reservation.operation_id != ticket.operation_id
        || reservation.event_id != ticket.event_id
        || reservation.service_id != ticket.service_id
        || reservation.database_id != ticket.database_id
        || reservation.authority_term != capability.authority_term
        || reservation.global_fence_sequence != capability.global_fence_sequence
        || capability.reservation_id != reservation.reservation_id
    {
        return Err("source bootstrap permit does not bind ticket and reservation");
    }
    Ok(())
}

fn permission_template_absent_image(
    template: &astral_types::SourceBootstrapTemplateRoot,
) -> Result<String, PolicyError> {
    let lookup = canonical_json(
        &serde_json::json!({
            "kind": "permission_rule_template_aggregate",
            "templateId": null,
            "domainId": template.domain_id,
            "templateCode": template.template_code,
        }),
        "permission template absent lookup",
    )?;
    canonical_json(
        &serde_json::json!({
            "table": TypedSourceTable::PermissionRuleTemplate.as_str(),
            "lookup": lookup,
            "presence": "ABSENT",
        }),
        "permission template absent image",
    )
}

fn image_evidence(images: &[(&str, String)]) -> Result<Vec<BootstrapImageEvidence>, PolicyError> {
    images
        .iter()
        .map(|(table, image)| {
            let value = serde_json::from_str::<Value>(image).map_err(|error| {
                PolicyError::Repository(format!("typed source image is not JSON: {error}"))
            })?;
            Ok(BootstrapImageEvidence {
                table: (*table).to_owned(),
                image: canonical_json(&value, "typed source image")?,
            })
        })
        .collect()
}

fn image_evidence_pairs(
    images: &[BootstrapImageEvidence],
) -> Result<Vec<(&str, String)>, PolicyError> {
    images
        .iter()
        .map(|image| {
            let value = serde_json::from_str::<Value>(&image.image).map_err(|error| {
                PolicyError::Repository(format!(
                    "retained typed source image is malformed: {error}"
                ))
            })?;
            Ok((
                image.table.as_str(),
                canonical_json(&value, "retained typed source image")?,
            ))
        })
        .collect()
}

fn digest_image_evidence(images: &[BootstrapImageEvidence]) -> Result<String, PolicyError> {
    Ok(digest_images(&image_evidence_pairs(images)?))
}

fn expected_before_images(
    permit: &VerifiedSourceBootstrapPermit,
) -> Result<Vec<BootstrapImageEvidence>, PolicyError> {
    let template = &permit.ticket.payload.template;
    let template_lookup = TypedSourceRowLookup::CardTemplateNatural {
        domain_id: template.domain_id,
        template_code: template.template_code.clone(),
    };
    let rule_set_lookup = TypedSourceRowLookup::RuleSetCode {
        code: permit.ticket.payload.rule_set.code.clone(),
    };
    image_evidence(&[
        (
            TypedSourceTable::UserCardTemplate.as_str(),
            typed_source_absent_image(TypedSourceTable::UserCardTemplate, &template_lookup)
                .map_err(|error| PolicyError::Repository(error.to_string()))?,
        ),
        (
            TypedSourceTable::PermissionRuleTemplate.as_str(),
            permission_template_absent_image(template)?,
        ),
        (
            TypedSourceTable::RuleSet.as_str(),
            typed_source_absent_image(TypedSourceTable::RuleSet, &rule_set_lookup)
                .map_err(|error| PolicyError::Repository(error.to_string()))?,
        ),
    ])
}

fn expected_source_receipts(generated: &GeneratedIds, audit_log_id: i64) -> Vec<ReceiptIdentity> {
    let mut receipts =
        Vec::with_capacity(3 + generated.template_rule_ids.len() + generated.entry_ids.len());
    receipts.push(receipt("user_card_template", generated.template_id));
    receipts.extend(
        generated
            .template_rule_ids
            .iter()
            .copied()
            .map(|id| receipt("permission_rule_template", id)),
    );
    receipts.push(receipt("rule_set", generated.rule_set_id));
    receipts.extend(
        generated
            .entry_ids
            .iter()
            .copied()
            .map(|id| receipt("rule_set_entry", id)),
    );
    receipts.push(receipt("audit_log", audit_log_id));
    receipts
}

fn validate_generated_ids(
    generated: &GeneratedIds,
    ticket: &AuthoritySourceBootstrapTicket,
) -> Result<(), PolicyError> {
    if generated.template_id <= 0
        || generated.rule_set_id <= 0
        || generated.template_rule_ids.len() != ticket.payload.template_rules.len()
        || generated.entry_ids.len() != ticket.payload.rule_set_entries.len()
        || !generated.binding_ids.is_empty()
        || generated.template_rule_ids.iter().any(|id| *id <= 0)
        || generated.entry_ids.iter().any(|id| *id <= 0)
    {
        return Err(PolicyError::Repository(
            "source bootstrap generated IDs or counts are not exact".into(),
        ));
    }
    let mut seen_template_rule_ids = std::collections::BTreeSet::new();
    if generated
        .template_rule_ids
        .iter()
        .any(|id| !seen_template_rule_ids.insert(*id))
    {
        return Err(PolicyError::Repository(
            "source bootstrap generated template rule IDs are not unique within their table".into(),
        ));
    }
    let mut seen_entry_ids = std::collections::BTreeSet::new();
    if generated
        .entry_ids
        .iter()
        .any(|id| !seen_entry_ids.insert(*id))
    {
        return Err(PolicyError::Repository(
            "source bootstrap generated RuleSet entry IDs are not unique within their table".into(),
        ));
    }
    Ok(())
}

fn json_field<'a>(value: &'a Value, field: &str) -> Result<&'a Value, PolicyError> {
    value.get(field).ok_or_else(|| {
        PolicyError::Repository(format!("typed source image is missing field {field}"))
    })
}

fn canonical_value(value: &Value, field: &str) -> Result<Value, PolicyError> {
    let json = canonical_json(value, field)?;
    serde_json::from_str(&json)
        .map_err(|error| PolicyError::Repository(format!("{field} is not canonical JSON: {error}")))
}

fn assert_field(value: &Value, field: &str, expected: &Value) -> Result<(), PolicyError> {
    if canonical_value(json_field(value, field)?, field)? != canonical_value(expected, field)? {
        return Err(PolicyError::Repository(format!(
            "typed source image field {field} differs from signed payload"
        )));
    }
    Ok(())
}

fn assert_optional_json_field(
    value: &Value,
    field: &str,
    expected: Option<&str>,
) -> Result<(), PolicyError> {
    let actual = json_field(value, field)?;
    let actual = if actual.is_null() {
        None
    } else {
        let text = actual.as_str().ok_or_else(|| {
            PolicyError::Repository(format!("typed source image JSON field {field} is not text"))
        })?;
        Some(canonical_json(
            &serde_json::from_str::<Value>(text).map_err(|error| {
                PolicyError::Repository(format!(
                    "typed source image JSON field {field} is invalid: {error}"
                ))
            })?,
            field,
        )?)
    };
    let expected = expected
        .map(|text| {
            serde_json::from_str::<Value>(text)
                .map_err(|error| {
                    PolicyError::Repository(format!("signed {field} is invalid: {error}"))
                })
                .and_then(|value| canonical_json(&value, field))
        })
        .transpose()?;
    if actual != expected {
        return Err(PolicyError::Repository(format!(
            "typed source image JSON field {field} differs from signed payload"
        )));
    }
    Ok(())
}

fn validate_signed_payload_images_from_evidence(
    ticket: &AuthoritySourceBootstrapTicket,
    generated: &GeneratedIds,
    images: &[BootstrapImageEvidence],
) -> Result<(), PolicyError> {
    validate_generated_ids(generated, ticket)?;
    if images.len() != 3 {
        return Err(PolicyError::Repository(
            "source bootstrap retained after images are incomplete".into(),
        ));
    }
    let mut by_table = std::collections::BTreeMap::new();
    for image in images {
        if by_table
            .insert(image.table.as_str(), image.image.as_str())
            .is_some()
        {
            return Err(PolicyError::Repository(
                "source bootstrap retained after images contain duplicate tables".into(),
            ));
        }
    }
    let template_image = serde_json::from_str::<Value>(
        by_table
            .get(TypedSourceTable::UserCardTemplate.as_str())
            .ok_or_else(|| PolicyError::Repository("template after image is missing".into()))?,
    )
    .map_err(|error| {
        PolicyError::Repository(format!("template after image is malformed: {error}"))
    })?;
    let template = &ticket.payload.template;
    assert_field(
        &template_image,
        "template_id",
        &serde_json::json!(generated.template_id),
    )?;
    assert_field(
        &template_image,
        "domain_id",
        &serde_json::json!(template.domain_id),
    )?;
    assert_field(
        &template_image,
        "tenant_id",
        &serde_json::json!(template.tenant_id),
    )?;
    assert_field(
        &template_image,
        "parent_template_id",
        &serde_json::json!(template.parent_template_id),
    )?;
    assert_field(
        &template_image,
        "template_code",
        &serde_json::json!(template.template_code),
    )?;
    assert_field(
        &template_image,
        "template_name",
        &serde_json::json!(template.template_name),
    )?;
    assert_field(
        &template_image,
        "card_type",
        &serde_json::json!(template.card_type),
    )?;
    assert_field(
        &template_image,
        "template_scope",
        &serde_json::json!(template.template_scope.as_deref().unwrap_or("SYSTEM")),
    )?;
    assert_field(
        &template_image,
        "version_no",
        &serde_json::json!(template.version_no.unwrap_or(1)),
    )?;
    assert_field(
        &template_image,
        "default_priority",
        &serde_json::json!(template.default_priority.unwrap_or(100)),
    )?;
    assert_optional_json_field(
        &template_image,
        "default_roles_json",
        template.default_roles_json.as_deref(),
    )?;
    assert_optional_json_field(
        &template_image,
        "resource_scope_json",
        template.resource_scope_json.as_deref(),
    )?;
    assert_field(
        &template_image,
        "status",
        &serde_json::json!(template.status),
    )?;

    let aggregate = serde_json::from_str::<Value>(
        by_table
            .get(TypedSourceTable::PermissionRuleTemplate.as_str())
            .ok_or_else(|| {
                PolicyError::Repository("permission template after image is missing".into())
            })?,
    )
    .map_err(|error| {
        PolicyError::Repository(format!(
            "permission template after image is malformed: {error}"
        ))
    })?;
    assert_field(&aggregate, "template_root", &template_image)?;
    let rules = json_field(&aggregate, "permission_rules")?
        .as_array()
        .ok_or_else(|| {
            PolicyError::Repository("permission template rules image is not an array".into())
        })?;
    if rules.len() != ticket.payload.template_rules.len()
        || rules.len() != generated.template_rule_ids.len()
    {
        return Err(PolicyError::Repository(
            "permission template rule count differs from signed payload".into(),
        ));
    }
    for ((actual, signed), generated_id) in rules
        .iter()
        .zip(&ticket.payload.template_rules)
        .zip(&generated.template_rule_ids)
    {
        assert_field(actual, "template_rule_id", &serde_json::json!(generated_id))?;
        assert_field(
            actual,
            "template_id",
            &serde_json::json!(generated.template_id),
        )?;
        assert_field(actual, "effect", &serde_json::json!(signed.effect))?;
        assert_field(
            actual,
            "resource_type",
            &serde_json::json!(signed.resource_type),
        )?;
        assert_field(
            actual,
            "resource_id",
            &serde_json::json!(signed.resource_id),
        )?;
        assert_field(
            actual,
            "action_code",
            &serde_json::json!(signed.action_code),
        )?;
        assert_optional_json_field(actual, "condition_json", signed.condition_json.as_deref())?;
        assert_field(actual, "priority", &serde_json::json!(signed.priority))?;
        assert_field(
            actual,
            "enabled",
            &serde_json::json!(i32::from(signed.enabled)),
        )?;
    }

    let ruleset_image = serde_json::from_str::<Value>(
        by_table
            .get(TypedSourceTable::RuleSet.as_str())
            .ok_or_else(|| PolicyError::Repository("RuleSet after image is missing".into()))?,
    )
    .map_err(|error| {
        PolicyError::Repository(format!("RuleSet after image is malformed: {error}"))
    })?;
    assert_field(&aggregate, "linked_rule_set", &ruleset_image)?;
    let root = json_field(&ruleset_image, "root")?;
    let signed_root = &ticket.payload.rule_set;
    assert_field(
        root,
        "rule_set_id",
        &serde_json::json!(generated.rule_set_id),
    )?;
    assert_field(root, "name", &serde_json::json!(signed_root.name))?;
    assert_field(root, "code", &serde_json::json!(signed_root.code))?;
    assert_field(
        root,
        "description",
        &serde_json::json!(signed_root.description),
    )?;
    assert_field(
        root,
        "source_type",
        &serde_json::json!(signed_root.source_type),
    )?;
    assert_field(root, "source_id", &serde_json::json!(generated.template_id))?;
    assert_field(
        root,
        "enabled",
        &serde_json::json!(i32::from(signed_root.enabled)),
    )?;
    assert_field(root, "tenant_id", &serde_json::json!(signed_root.tenant_id))?;
    let entries = json_field(&ruleset_image, "entries")?
        .as_array()
        .ok_or_else(|| PolicyError::Repository("RuleSet entries image is not an array".into()))?;
    if entries.len() != ticket.payload.rule_set_entries.len()
        || entries.len() != generated.entry_ids.len()
    {
        return Err(PolicyError::Repository(
            "RuleSet entry count differs from signed payload".into(),
        ));
    }
    for ((actual, signed), generated_id) in entries
        .iter()
        .zip(&ticket.payload.rule_set_entries)
        .zip(&generated.entry_ids)
    {
        assert_field(actual, "entry_id", &serde_json::json!(generated_id))?;
        assert_field(
            actual,
            "rule_set_id",
            &serde_json::json!(generated.rule_set_id),
        )?;
        assert_field(
            actual,
            "resource_type",
            &serde_json::json!(signed.resource_type),
        )?;
        assert_field(
            actual,
            "resource_id",
            &serde_json::json!(signed.resource_id),
        )?;
        assert_field(
            actual,
            "action_code",
            &serde_json::json!(signed.action_code),
        )?;
        assert_field(actual, "effect", &serde_json::json!(signed.effect))?;
        assert_optional_json_field(actual, "condition_json", signed.condition_json.as_deref())?;
        assert_field(actual, "priority", &serde_json::json!(signed.priority))?;
        assert_field(
            actual,
            "enabled",
            &serde_json::json!(i32::from(signed.enabled)),
        )?;
        assert_field(actual, "valid_from", &serde_json::json!(signed.valid_from))?;
        assert_field(actual, "valid_to", &serde_json::json!(signed.valid_to))?;
        assert_field(actual, "tenant_id", &serde_json::json!(signed.tenant_id))?;
    }
    let bindings = json_field(&ruleset_image, "bindings")?
        .as_array()
        .ok_or_else(|| PolicyError::Repository("RuleSet bindings image is not an array".into()))?;
    if !bindings.is_empty()
        || !ticket.payload.bindings.is_empty()
        || !generated.binding_ids.is_empty()
    {
        return Err(PolicyError::Repository(
            "source bootstrap signed bindings are not represented by a WorkerOwned delta path"
                .into(),
        ));
    }
    Ok(())
}

fn receipt(kind: &str, id: i64) -> ReceiptIdentity {
    ReceiptIdentity {
        identity_kind: kind.to_owned(),
        identity: id.to_string(),
    }
}

fn canonical_optional_json(
    value: Option<&str>,
    field: &str,
) -> Result<Option<String>, PolicyError> {
    value
        .map(|value| {
            serde_json::from_str::<serde_json::Value>(value)
                .map_err(|error| {
                    PolicyError::InvalidContext(format!("{field} is invalid JSON: {error}"))
                })
                .and_then(|parsed| canonical_json(&parsed, field))
        })
        .transpose()
}

fn canonical_json<T: Serialize>(value: &T, field: &str) -> Result<String, PolicyError> {
    serde_json::to_string(value)
        .map_err(|error| PolicyError::InvalidContext(format!("{field} cannot be encoded: {error}")))
}

fn digest_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn digest_domain_json(domain: &[u8], json: &str) -> String {
    let mut bytes = Vec::with_capacity(domain.len() + json.len() + 8);
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(&(json.len() as u64).to_be_bytes());
    bytes.extend_from_slice(json.as_bytes());
    digest_bytes(&bytes)
}

fn digest_images(images: &[(&str, String)]) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(IMAGE_DOMAIN);
    bytes.extend_from_slice(&(images.len() as u64).to_be_bytes());
    for (table, image) in images {
        bytes.extend_from_slice(&(table.len() as u64).to_be_bytes());
        bytes.extend_from_slice(table.as_bytes());
        bytes.extend_from_slice(&(image.len() as u64).to_be_bytes());
        bytes.extend_from_slice(image.as_bytes());
    }
    digest_bytes(&bytes)
}

fn capability_digest(
    capability: &AuthoritySourceBootstrapCapability,
) -> Result<String, PolicyError> {
    let bytes = canonical_json(capability, "source bootstrap capability")?;
    let mut framed = Vec::with_capacity(CAPABILITY_DIGEST_DOMAIN.len() + bytes.len() + 8);
    framed.extend_from_slice(CAPABILITY_DIGEST_DOMAIN);
    framed.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    framed.extend_from_slice(bytes.as_bytes());
    Ok(digest_bytes(&framed))
}

fn digest_matches(raw: &[u8], expected: &str) -> bool {
    hex::decode(expected)
        .ok()
        .is_some_and(|decoded| decoded == raw)
}

fn hex32(raw: &[u8], field: &'static str) -> Result<String, PolicyError> {
    if raw.len() != 32 {
        return Err(PolicyError::Repository(format!(
            "stored {field} is not BINARY(32)"
        )));
    }
    Ok(hex::encode(raw))
}

fn storage_counter(value: u64) -> Result<i64, PolicyError> {
    i64::try_from(value)
        .map_err(|_| PolicyError::InvalidContext("authority counter exceeds BIGINT storage".into()))
}

fn map_typed_reader_error(error: TypedSourceReadError) -> PolicyError {
    PolicyError::Repository(format!("typed source bootstrap readback failed: {error}"))
}

fn db_error(context: &str, error: sqlx::Error) -> PolicyError {
    PolicyError::Repository(format!("{context}: {error}"))
}

#[cfg(test)]
#[path = "authority_source_bootstrap/tests.rs"]
mod tests;
