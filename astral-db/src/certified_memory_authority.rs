//! Certified, process-local authorization read model.
//!
//! This module is deliberately independent of SQL, connection pools, middleware,
//! sessions, and authority quorum clients. A caller may install only an already
//! validated/certified immutable snapshot. The module owns the serving gate,
//! bounded residency, atomic replacement, and fail-closed reads; it does not
//! manufacture authority evidence.
//!
//! A read is positive only when all of these conditions hold:
//!
//! - the store is [`CertifiedMemoryServing::Serving`];
//! - the snapshot is complete, within its expiry, and within configured bounds;
//! - the read token still identifies the current snapshot and store epoch; and
//! - the requested value exists and passes its value-level validation.
//!
//! Missing values are ordinary misses. Stale, gap, unknown, failed, invalid, or
//! replaced state is returned as a non-positive error. No method in this module
//! falls back to SQL or treats a local heartbeat as authority proof.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use astral_types::{
    CardEligibility, DomainScopeRequirement, GlobalAccessRequirement, PolicyContext,
    PublishedCardAuthorization, PublishedCardEvidenceScope,
};
pub use astral_types::{CertifiedSodConflictType, CertifiedSodPolicy};
use policy_engine::OrgAuthorityRead;

use crate::resource_ownership::ResourceOwnershipResolution;

/// Hard upper bound for the default number of indexed values in one snapshot.
pub const DEFAULT_CERTIFIED_MEMORY_MAX_ENTRIES: usize = 65_536;
/// Hard upper bound for the default estimated snapshot allocation.
pub const DEFAULT_CERTIFIED_MEMORY_MAX_BYTES: usize = 32 * 1024 * 1024;
/// Default residency bound for a certified snapshot.
pub const DEFAULT_CERTIFIED_MEMORY_TTL_SECONDS: i64 = 300;

/// Serving/readiness state for the memory-only authority read model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CertifiedMemoryServing {
    /// No snapshot has been installed.
    Cold,
    /// A snapshot exists, but the owner has not completed its readiness checks.
    Warming,
    /// Positive reads are permitted subject to token, expiry, and value checks.
    Serving,
    /// The installed snapshot is known to be too old for positive reads.
    Stale,
    /// Coverage is incomplete or a frontier gap was observed.
    Gap,
    /// A known failure prevents positive reads.
    Failed,
    /// The authority state cannot currently be established.
    Unknown,
}

impl CertifiedMemoryServing {
    fn permits_positive_reads(self) -> bool {
        matches!(self, Self::Serving)
    }
}

/// Bounded residency policy for one immutable snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertifiedMemoryConfig {
    max_entries: usize,
    max_bytes: usize,
    ttl_seconds: i64,
}

impl CertifiedMemoryConfig {
    /// Construct bounds. All bounds must be positive.
    pub const fn new(
        max_entries: usize,
        max_bytes: usize,
        ttl_seconds: i64,
    ) -> Result<Self, CertifiedMemoryConfigError> {
        if max_entries == 0 {
            return Err(CertifiedMemoryConfigError::ZeroEntries);
        }
        if max_bytes == 0 {
            return Err(CertifiedMemoryConfigError::ZeroBytes);
        }
        if ttl_seconds <= 0 {
            return Err(CertifiedMemoryConfigError::NonPositiveTtl);
        }
        Ok(Self {
            max_entries,
            max_bytes,
            ttl_seconds,
        })
    }

    /// Conservative production defaults. The caller still controls installation.
    pub const fn default_bounds() -> Self {
        Self {
            max_entries: DEFAULT_CERTIFIED_MEMORY_MAX_ENTRIES,
            max_bytes: DEFAULT_CERTIFIED_MEMORY_MAX_BYTES,
            ttl_seconds: DEFAULT_CERTIFIED_MEMORY_TTL_SECONDS,
        }
    }

    pub const fn max_entries(self) -> usize {
        self.max_entries
    }

    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }

    pub const fn ttl_seconds(self) -> i64 {
        self.ttl_seconds
    }
}

impl Default for CertifiedMemoryConfig {
    fn default() -> Self {
        Self::default_bounds()
    }
}

/// Configuration errors for the bounded read model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertifiedMemoryConfigError {
    ZeroEntries,
    ZeroBytes,
    NonPositiveTtl,
}

/// Non-positive outcome from the memory serving gate or a value read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertifiedMemoryFailure {
    /// The store is not in the only state that permits positive reads.
    NotServing(CertifiedMemoryServing),
    /// The requested key is absent from an otherwise usable snapshot.
    Missing,
    /// The snapshot or value failed structural validation.
    Invalid { code: String },
    /// The snapshot's bounded residency window has elapsed.
    Stale,
    /// The snapshot has incomplete coverage or a detected frontier gap.
    Gap,
    /// The authority state is not known well enough to serve.
    Unknown,
    /// The snapshot exceeds configured entry or byte limits.
    CapacityExceeded,
    /// A token no longer identifies the current installed snapshot.
    TokenNotCurrent,
}

impl std::fmt::Display for CertifiedMemoryFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotServing(state) => write!(formatter, "not_serving.{state:?}"),
            Self::Missing => formatter.write_str("missing"),
            Self::Invalid { code } => write!(formatter, "invalid;{code}"),
            Self::Stale => formatter.write_str("stale"),
            Self::Gap => formatter.write_str("gap"),
            Self::Unknown => formatter.write_str("unknown"),
            Self::CapacityExceeded => formatter.write_str("capacity_exceeded"),
            Self::TokenNotCurrent => formatter.write_str("token_not_current"),
        }
    }
}

impl std::error::Error for CertifiedMemoryFailure {}

/// Explicit invalidation causes used by a runtime owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertifiedMemoryInvalidation {
    /// The bounded residency window or an equivalent freshness check failed.
    Stale,
    /// Durable coverage/frontier is incomplete or contradictory.
    Gap,
    /// Authority, worker ownership, or transport state is not established.
    Unknown,
    /// The installed root cannot be used until an operator-controlled rebuild.
    Failed,
}

/// A validated card context stored in the immutable snapshot.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CertifiedCardContext {
    pub user_id: i64,
    pub eligibility: CardEligibility,
}

impl CertifiedCardContext {
    pub(crate) fn validate_for(&self, key: &CardContextKey) -> Result<(), String> {
        if self.user_id != key.user_id
            || self.eligibility.identity_card_id != key.identity_card_id
            || self.eligibility.user_card_id != key.user_card_id
            || self.user_id <= 0
            || self.eligibility.identity_card_id <= 0
            || self.eligibility.user_card_id <= 0
            || self.eligibility.user_card_tenant_id <= 0
            || self.eligibility.user_card_domain_id <= 0
        {
            return Err("card context identity or eligibility binding is invalid".to_owned());
        }
        Ok(())
    }
}

/// Exact identity key for card-context/eligibility reads.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub struct CardContextKey {
    pub user_id: i64,
    pub identity_card_id: i64,
    pub user_card_id: i64,
}

impl CardContextKey {
    /// Build an exact key from a trusted policy context. Missing facts do not
    /// become a wildcard.
    pub fn from_policy_context(context: &PolicyContext) -> Option<Self> {
        let key = Self {
            user_id: context.user_id?,
            identity_card_id: context.identity_card_id?,
            user_card_id: context.card_id?,
        };
        (key.user_id > 0 && key.identity_card_id > 0 && key.user_card_id > 0).then_some(key)
    }
}

/// Exact identity key for an ORG authority read.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub struct OrgReadKey {
    pub tenant_id: i64,
    pub user_id: i64,
    pub identity_card_id: i64,
    pub card_id: i64,
}

impl OrgReadKey {
    pub fn from_policy_context(context: &PolicyContext) -> Option<Self> {
        let key = Self {
            tenant_id: context.tenant_id?,
            user_id: context.user_id?,
            identity_card_id: context.identity_card_id?,
            card_id: context.card_id?,
        };
        (key.tenant_id > 0 && key.user_id > 0 && key.identity_card_id > 0 && key.card_id > 0)
            .then_some(key)
    }
}

/// Exact route/actor key for a server-side ownership resolution.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub struct OwnershipReadKey {
    pub resource: String,
    pub path: String,
    pub method: String,
    pub target_id: Option<i64>,
    pub actor_card_id: Option<i64>,
    pub actor_user_id: Option<i64>,
}

impl OwnershipReadKey {
    pub fn new(
        resource: String,
        path: String,
        method: String,
        target_id: Option<i64>,
        actor_card_id: Option<i64>,
        actor_user_id: Option<i64>,
    ) -> Result<Self, String> {
        if resource.trim().is_empty() || path.trim().is_empty() || method.trim().is_empty() {
            return Err("ownership key route fields must be non-empty".to_owned());
        }
        if [target_id, actor_card_id, actor_user_id]
            .into_iter()
            .flatten()
            .any(|id| id <= 0)
        {
            return Err("ownership key identifiers must be positive".to_owned());
        }
        Ok(Self {
            resource,
            path,
            method,
            target_id,
            actor_card_id,
            actor_user_id,
        })
    }

    fn estimated_bytes(&self) -> usize {
        std::mem::size_of_val(self)
            .saturating_add(self.resource.len())
            .saturating_add(self.path.len())
            .saturating_add(self.method.len())
    }
}

/// Exact key for a published card evidence lens.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PublishedCardEvidenceKey {
    pub tenant_id: i64,
    pub card_id: i64,
    pub user_filter: Option<i64>,
    pub domain: DomainScopeRequirement,
}

impl From<&PublishedCardEvidenceScope> for PublishedCardEvidenceKey {
    fn from(scope: &PublishedCardEvidenceScope) -> Self {
        Self {
            tenant_id: scope.tenant_id,
            card_id: scope.card_id,
            user_filter: scope.user_filter,
            domain: scope.domain,
        }
    }
}

impl PublishedCardEvidenceKey {
    fn validate(&self) -> Result<(), String> {
        let scope = PublishedCardEvidenceScope {
            tenant_id: self.tenant_id,
            card_id: self.card_id,
            user_filter: self.user_filter,
            domain: self.domain,
        };
        scope
            .validate()
            .map_err(|error| format!("published evidence scope is invalid: {error}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedMemoryAttestation {
    pub authority_term: u64,
    pub global_fence_sequence: u64,
    pub key_epoch: u64,
    pub scope_generation: u64,
    pub revoke_watermark: u64,
    pub snapshot_hash: String,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
}

impl CertifiedMemoryAttestation {
    pub fn validate_at(&self, generation: u64, now_unix: i64) -> Result<(), String> {
        if self.authority_term == 0
            || self.global_fence_sequence == 0
            || self.key_epoch == 0
            || self.scope_generation != generation
            || self.revoke_watermark > self.scope_generation
            || self.snapshot_hash.len() != 64
            || !self
                .snapshot_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || self.expires_at_unix <= self.issued_at_unix
            || now_unix < self.issued_at_unix
            || now_unix >= self.expires_at_unix
        {
            return Err("certified memory attestation is invalid or expired".to_owned());
        }
        Ok(())
    }
}

/// An immutable, complete-or-gap snapshot of memory-only read facts.
#[derive(Debug)]
pub struct CertifiedMemorySnapshot {
    generation: u64,
    installed_at_unix: i64,
    expires_at_unix: i64,
    coverage: CertifiedMemoryCoverage,
    coverage_contract: CertifiedMemoryCoverageContract,
    attestation: Option<CertifiedMemoryAttestation>,
    card_contexts: HashMap<CardContextKey, CertifiedCardContext>,
    global_admins: HashMap<i64, GlobalAdminStatus>,
    org_reads: HashMap<OrgReadKey, Arc<OrgAuthorityRead>>,
    ownership: HashMap<OwnershipReadKey, ResourceOwnershipResolution>,
    published_cards: HashMap<PublishedCardEvidenceKey, Arc<PublishedCardAuthorization>>,
    sod_policies: Vec<CertifiedSodPolicy>,
    estimated_bytes: usize,
}

/// Snapshot coverage status. A gap can be installed for diagnosis/warm-up but
/// can never transition to serving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertifiedMemoryCoverage {
    Complete,
    Gap,
}

/// Explicit production coverage contract for one certified snapshot.
///
/// `CertifiedMemoryCoverage::Complete` describes the transport/frontier shape;
/// this contract describes whether every fact family required by the serving
/// composition has actually been materialized. A complete-but-empty family is
/// represented by `true`, while an omitted family remains `false`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CertifiedMemoryCoverageContract {
    pub card_context: bool,
    pub global_admin: bool,
    pub published_evidence: bool,
    pub org_authorization: bool,
    pub ownership: bool,
    pub sod_policy: bool,
}

impl CertifiedMemoryCoverageContract {
    pub const fn complete() -> Self {
        Self {
            card_context: true,
            global_admin: true,
            published_evidence: true,
            org_authorization: true,
            ownership: true,
            sod_policy: true,
        }
    }

    pub const fn is_complete(self) -> bool {
        self.card_context
            && self.global_admin
            && self.published_evidence
            && self.org_authorization
            && self.ownership
            && self.sod_policy
    }
}

/// Whether a user is an active global administrator in the certified snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GlobalAdminStatus {
    Active,
    Inactive,
}

impl CertifiedMemorySnapshot {
    /// Create an empty immutable-snapshot candidate. Values are added before the
    /// candidate is wrapped in `Arc` and installed into a store.
    pub fn empty(
        generation: u64,
        installed_at_unix: i64,
        expires_at_unix: i64,
        coverage: CertifiedMemoryCoverage,
    ) -> Result<Self, String> {
        if generation == 0 {
            return Err("snapshot generation must be non-zero".to_owned());
        }
        if expires_at_unix <= installed_at_unix {
            return Err("snapshot expiry must be after installation".to_owned());
        }
        Ok(Self {
            generation,
            installed_at_unix,
            expires_at_unix,
            coverage,
            coverage_contract: CertifiedMemoryCoverageContract::default(),
            attestation: None,
            card_contexts: HashMap::new(),
            global_admins: HashMap::new(),
            org_reads: HashMap::new(),
            ownership: HashMap::new(),
            published_cards: HashMap::new(),
            sod_policies: Vec::new(),
            estimated_bytes: 256,
        })
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn installed_at_unix(&self) -> i64 {
        self.installed_at_unix
    }

    pub const fn expires_at_unix(&self) -> i64 {
        self.expires_at_unix
    }

    pub const fn coverage(&self) -> CertifiedMemoryCoverage {
        self.coverage
    }

    pub const fn coverage_contract(&self) -> CertifiedMemoryCoverageContract {
        self.coverage_contract
    }

    /// Declare which fact families were completely materialized by the builder.
    /// This is immutable after installation and is required before Serving.
    pub fn set_coverage_contract(
        &mut self,
        contract: CertifiedMemoryCoverageContract,
    ) -> Result<(), String> {
        if self.coverage != CertifiedMemoryCoverage::Complete && contract.is_complete() {
            return Err("a gap snapshot cannot claim complete fact coverage".to_owned());
        }
        self.coverage_contract = contract;
        Ok(())
    }

    pub fn attestation(&self) -> Option<CertifiedMemoryAttestation> {
        self.attestation.clone()
    }

    /// Canonical content identity of this immutable snapshot.
    ///
    /// The attestation is deliberately excluded: the authority root signs this
    /// digest, while the attestation binds that root back to the snapshot. All
    /// unordered collections are sorted by their exact read key before encoding.
    pub fn canonical_content_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::with_capacity(self.estimated_bytes.saturating_add(512));
        snapshot_field(&mut bytes, "ASTRAL_CERTIFIED_MEMORY_SNAPSHOT_CONTENT_V1");
        snapshot_field(&mut bytes, &self.generation.to_string());
        snapshot_field(
            &mut bytes,
            match self.coverage {
                CertifiedMemoryCoverage::Complete => "COMPLETE",
                CertifiedMemoryCoverage::Gap => "GAP",
            },
        );
        for value in [
            self.coverage_contract.card_context,
            self.coverage_contract.global_admin,
            self.coverage_contract.published_evidence,
            self.coverage_contract.org_authorization,
            self.coverage_contract.ownership,
            self.coverage_contract.sod_policy,
        ] {
            snapshot_field(&mut bytes, if value { "1" } else { "0" });
        }

        let mut cards: Vec<_> = self.card_contexts.iter().collect();
        cards.sort_by_key(|(key, _)| **key);
        snapshot_field(&mut bytes, &cards.len().to_string());
        for (key, value) in cards {
            snapshot_field(&mut bytes, &key.user_id.to_string());
            snapshot_field(&mut bytes, &key.identity_card_id.to_string());
            snapshot_field(&mut bytes, &key.user_card_id.to_string());
            snapshot_field(&mut bytes, &value.user_id.to_string());
            snapshot_field(&mut bytes, &value.eligibility.identity_card_id.to_string());
            snapshot_field(&mut bytes, &value.eligibility.user_card_id.to_string());
            snapshot_field(
                &mut bytes,
                &value.eligibility.user_card_tenant_id.to_string(),
            );
            snapshot_field(
                &mut bytes,
                &value.eligibility.user_card_domain_id.to_string(),
            );
            snapshot_field(
                &mut bytes,
                &value
                    .eligibility
                    .effective_expiry
                    .map_or_else(|| "-".to_owned(), |expiry| expiry.to_string()),
            );
        }

        let mut admins: Vec<_> = self.global_admins.iter().collect();
        admins.sort_by_key(|(user_id, _)| **user_id);
        snapshot_field(&mut bytes, &admins.len().to_string());
        for (user_id, status) in admins {
            snapshot_field(&mut bytes, &user_id.to_string());
            snapshot_field(
                &mut bytes,
                match status {
                    GlobalAdminStatus::Active => "ACTIVE",
                    GlobalAdminStatus::Inactive => "INACTIVE",
                },
            );
        }

        let mut org_reads: Vec<_> = self.org_reads.iter().collect();
        org_reads.sort_by_key(|(key, _)| **key);
        snapshot_field(&mut bytes, &org_reads.len().to_string());
        for (key, value) in org_reads {
            snapshot_field(&mut bytes, &key.tenant_id.to_string());
            snapshot_field(&mut bytes, &key.user_id.to_string());
            snapshot_field(&mut bytes, &key.identity_card_id.to_string());
            snapshot_field(&mut bytes, &key.card_id.to_string());
            snapshot_org_read(&mut bytes, value)?;
        }

        let mut ownership: Vec<_> = self.ownership.iter().collect();
        ownership.sort_by_key(|(key, _)| (*key).clone());
        snapshot_field(&mut bytes, &ownership.len().to_string());
        for (key, value) in ownership {
            snapshot_field(&mut bytes, &key.resource);
            snapshot_field(&mut bytes, &key.path);
            snapshot_field(&mut bytes, &key.method);
            snapshot_field(
                &mut bytes,
                &key.target_id
                    .map_or_else(|| "-".to_owned(), |id| id.to_string()),
            );
            snapshot_field(
                &mut bytes,
                &key.actor_card_id
                    .map_or_else(|| "-".to_owned(), |id| id.to_string()),
            );
            snapshot_field(
                &mut bytes,
                &key.actor_user_id
                    .map_or_else(|| "-".to_owned(), |id| id.to_string()),
            );
            snapshot_ownership(&mut bytes, value);
        }

        let mut published: Vec<_> = self.published_cards.iter().collect();
        published.sort_by(|(left, _), (right, _)| {
            left.tenant_id
                .cmp(&right.tenant_id)
                .then(left.card_id.cmp(&right.card_id))
                .then(left.user_filter.cmp(&right.user_filter))
                .then(domain_sort_key(left.domain).cmp(&domain_sort_key(right.domain)))
        });
        snapshot_field(&mut bytes, &published.len().to_string());
        for (key, value) in published {
            snapshot_field(&mut bytes, &key.tenant_id.to_string());
            snapshot_field(&mut bytes, &key.card_id.to_string());
            snapshot_field(
                &mut bytes,
                &key.user_filter
                    .map_or_else(|| "-".to_owned(), |id| id.to_string()),
            );
            snapshot_field(&mut bytes, &domain_sort_key(key.domain));
            let encoded = serde_json::to_vec(value.as_ref()).map_err(|error| {
                format!("published evidence canonical encoding failed: {error}")
            })?;
            snapshot_bytes(&mut bytes, &encoded);
        }

        let mut policies = self.sod_policies.clone();
        policies.sort_by(|left, right| {
            left.policy_name.cmp(&right.policy_name).then(
                sod_conflict_sort_key(left.conflict_type)
                    .cmp(sod_conflict_sort_key(right.conflict_type)),
            )
        });
        snapshot_field(&mut bytes, &policies.len().to_string());
        for policy in policies {
            snapshot_field(&mut bytes, &policy.policy_name);
            snapshot_field(
                &mut bytes,
                match policy.conflict_type {
                    CertifiedSodConflictType::Static => "STATIC",
                    CertifiedSodConflictType::Dynamic => "DYNAMIC",
                },
            );
            for value in [
                policy.permission_a.as_deref().unwrap_or("-"),
                policy.permission_b.as_deref().unwrap_or("-"),
                policy.condition_script.as_deref().unwrap_or("-"),
                policy.resource_type.as_deref().unwrap_or("-"),
                policy.action_code.as_deref().unwrap_or("-"),
            ] {
                snapshot_field(&mut bytes, value);
            }
        }
        Ok(bytes)
    }

    pub fn content_digest(&self) -> Result<String, String> {
        use sha2::{Digest, Sha256};
        Ok(hex::encode(Sha256::digest(
            &self.canonical_content_bytes()?,
        )))
    }

    pub fn attach_attestation(
        &mut self,
        attestation: CertifiedMemoryAttestation,
    ) -> Result<(), String> {
        attestation.validate_at(self.generation, self.installed_at_unix)?;
        if attestation.expires_at_unix > self.expires_at_unix {
            return Err("attestation outlives the snapshot".to_owned());
        }
        self.attestation = Some(attestation);
        Ok(())
    }

    pub const fn estimated_bytes(&self) -> usize {
        self.estimated_bytes
    }

    pub fn entry_count(&self) -> usize {
        self.card_contexts.len()
            + self.global_admins.len()
            + self.org_reads.len()
            + self.ownership.len()
            + self.published_cards.len()
            + self.sod_policies.len()
    }

    pub fn insert_card_context(
        &mut self,
        key: CardContextKey,
        value: CertifiedCardContext,
    ) -> Result<(), String> {
        value.validate_for(&key)?;
        self.insert_size(std::mem::size_of_val(&key) + std::mem::size_of_val(&value))?;
        self.card_contexts.insert(key, value);
        Ok(())
    }

    pub fn insert_global_admin(
        &mut self,
        user_id: i64,
        status: GlobalAdminStatus,
    ) -> Result<(), String> {
        if user_id <= 0 {
            return Err("global-admin user id must be positive".to_owned());
        }
        self.insert_size(std::mem::size_of::<i64>() + std::mem::size_of::<GlobalAdminStatus>())?;
        self.global_admins.insert(user_id, status);
        Ok(())
    }

    pub fn insert_org_read(
        &mut self,
        key: OrgReadKey,
        value: OrgAuthorityRead,
    ) -> Result<(), String> {
        if key.tenant_id <= 0 || key.user_id <= 0 || key.identity_card_id <= 0 || key.card_id <= 0 {
            return Err("ORG read key identifiers must be positive".to_owned());
        }
        validate_org_read(&key, &value)?;
        let value_size = match &value {
            OrgAuthorityRead::Ready(evidence) => serde_json::to_vec(evidence.as_ref())
                .map(|bytes| bytes.len())
                .map_err(|error| format!("ORG evidence cannot be measured: {error}"))?,
            _ => 64,
        };
        self.insert_size(std::mem::size_of_val(&key) + value_size)?;
        self.org_reads.insert(key, Arc::new(value));
        Ok(())
    }

    pub fn insert_ownership(
        &mut self,
        key: OwnershipReadKey,
        value: ResourceOwnershipResolution,
    ) -> Result<(), String> {
        validate_ownership(&value)?;
        let value_size = ownership_size(&value);
        self.insert_size(key.estimated_bytes() + value_size)?;
        self.ownership.insert(key, value);
        Ok(())
    }

    pub fn insert_published_card(
        &mut self,
        scope: PublishedCardEvidenceScope,
        evidence: Arc<PublishedCardAuthorization>,
    ) -> Result<(), String> {
        scope
            .validate()
            .map_err(|error| format!("published evidence scope is invalid: {error}"))?;
        evidence
            .validate()
            .map_err(|error| format!("published card evidence is invalid: {error}"))?;
        if evidence.tenant_id != scope.tenant_id || evidence.card_id != scope.card_id {
            return Err("published evidence does not match its scope".to_owned());
        }
        let key = PublishedCardEvidenceKey::from(&scope);
        key.validate()?;
        let value_size = serde_json::to_vec(evidence.as_ref())
            .map_err(|error| format!("published evidence cannot be measured: {error}"))?
            .len();
        self.insert_size(key_size(&key) + value_size)?;
        self.published_cards.insert(key, evidence);
        Ok(())
    }

    pub fn insert_sod_policy(&mut self, policy: CertifiedSodPolicy) -> Result<(), String> {
        policy.validate()?;
        self.insert_size(
            std::mem::size_of_val(&policy)
                + policy.policy_name.len()
                + policy.permission_a.as_deref().map_or(0, str::len)
                + policy.permission_b.as_deref().map_or(0, str::len)
                + policy.condition_script.as_deref().map_or(0, str::len)
                + policy.resource_type.as_deref().map_or(0, str::len)
                + policy.action_code.as_deref().map_or(0, str::len),
        )?;
        self.sod_policies.push(policy);
        Ok(())
    }

    pub fn sod_policy_count(&self) -> usize {
        self.sod_policies.len()
    }

    fn insert_size(&mut self, additional: usize) -> Result<(), String> {
        self.estimated_bytes = self
            .estimated_bytes
            .checked_add(additional)
            .ok_or_else(|| "snapshot estimated size overflow".to_owned())?;
        Ok(())
    }

    fn is_fresh_at(&self, now_unix: i64) -> bool {
        now_unix >= self.installed_at_unix && now_unix < self.expires_at_unix
    }
}

fn key_size<K>(key: &K) -> usize {
    std::mem::size_of_val(key)
}

fn snapshot_field(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn snapshot_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value);
}

fn domain_sort_key(domain: DomainScopeRequirement) -> String {
    match domain {
        DomainScopeRequirement::Unconstrained => "ANY".to_owned(),
        DomainScopeRequirement::ExactlySome(id) => format!("S:{id}"),
        DomainScopeRequirement::ExactlyNone => "NONE".to_owned(),
    }
}

fn sod_conflict_sort_key(conflict: CertifiedSodConflictType) -> &'static str {
    match conflict {
        CertifiedSodConflictType::Static => "STATIC",
        CertifiedSodConflictType::Dynamic => "DYNAMIC",
    }
}

fn snapshot_org_read(bytes: &mut Vec<u8>, value: &OrgAuthorityRead) -> Result<(), String> {
    match value {
        OrgAuthorityRead::Unmanaged => snapshot_field(bytes, "UNMANAGED"),
        OrgAuthorityRead::Disabled => snapshot_field(bytes, "DISABLED"),
        OrgAuthorityRead::Pending { code } => {
            snapshot_field(bytes, "PENDING");
            snapshot_field(bytes, code);
        }
        OrgAuthorityRead::Unavailable { code } => {
            snapshot_field(bytes, "UNAVAILABLE");
            snapshot_field(bytes, code);
        }
        OrgAuthorityRead::Ready(evidence) => {
            snapshot_field(bytes, "READY");
            let encoded = serde_json::to_vec(evidence.as_ref())
                .map_err(|error| format!("ORG evidence canonical encoding failed: {error}"))?;
            snapshot_bytes(bytes, &encoded);
        }
    }
    Ok(())
}

fn snapshot_ownership(bytes: &mut Vec<u8>, value: &ResourceOwnershipResolution) {
    match value {
        ResourceOwnershipResolution::TenantScoped {
            target_id,
            tenant_id,
            domain_id,
            owner_id,
        } => {
            snapshot_field(bytes, "TENANT_SCOPED");
            for value in [
                target_id.map_or_else(|| "-".to_owned(), |id| id.to_string()),
                tenant_id.to_string(),
                domain_id.map_or_else(|| "-".to_owned(), |id| id.to_string()),
                owner_id.map_or_else(|| "-".to_owned(), |id| id.to_string()),
            ] {
                snapshot_field(bytes, &value);
            }
        }
        ResourceOwnershipResolution::Global {
            target_id,
            access_requirement,
        } => {
            snapshot_field(bytes, "GLOBAL");
            snapshot_field(
                bytes,
                &target_id.map_or_else(|| "-".to_owned(), |id| id.to_string()),
            );
            snapshot_field(bytes, access_requirement_tag(*access_requirement));
        }
        ResourceOwnershipResolution::Unresolved { code } => {
            snapshot_field(bytes, "UNRESOLVED");
            snapshot_field(bytes, code);
        }
        ResourceOwnershipResolution::Unavailable { code } => {
            snapshot_field(bytes, "UNAVAILABLE");
            snapshot_field(bytes, code);
        }
    }
}

fn access_requirement_tag(requirement: GlobalAccessRequirement) -> &'static str {
    match requirement {
        GlobalAccessRequirement::Unspecified => "UNSPECIFIED",
        GlobalAccessRequirement::ActiveGlobalAdmin => "ACTIVE_GLOBAL_ADMIN",
        GlobalAccessRequirement::PolicyEvidence => "POLICY_EVIDENCE",
    }
}

fn ownership_size(value: &ResourceOwnershipResolution) -> usize {
    std::mem::size_of_val(value)
        + match value {
            ResourceOwnershipResolution::Unresolved { code }
            | ResourceOwnershipResolution::Unavailable { code } => code.len(),
            _ => 0,
        }
}

fn validate_ownership(value: &ResourceOwnershipResolution) -> Result<(), String> {
    match value {
        ResourceOwnershipResolution::TenantScoped {
            tenant_id,
            domain_id,
            owner_id,
            ..
        } => {
            if *tenant_id <= 0
                || domain_id.is_some_and(|id| id <= 0)
                || owner_id.is_some_and(|id| id <= 0)
            {
                return Err("tenant ownership contains a non-positive identifier".to_owned());
            }
        }
        ResourceOwnershipResolution::Global {
            access_requirement, ..
        } if *access_requirement == GlobalAccessRequirement::Unspecified => {
            return Err("global ownership lacks an explicit access requirement".to_owned());
        }
        ResourceOwnershipResolution::Global { .. }
        | ResourceOwnershipResolution::Unresolved { .. }
        | ResourceOwnershipResolution::Unavailable { .. } => {}
    }
    Ok(())
}

fn validate_org_read(key: &OrgReadKey, value: &OrgAuthorityRead) -> Result<(), String> {
    if let OrgAuthorityRead::Ready(evidence) = value {
        evidence
            .validate()
            .map_err(|error| format!("ORG evidence is invalid: {error}"))?;
        if evidence.node.tenant_id != key.tenant_id
            || evidence.membership.user_id != key.user_id
            || evidence.membership.identity_card_id != key.identity_card_id
            || evidence.membership.card_id != key.card_id
        {
            return Err("ORG evidence does not match its read key".to_owned());
        }
    }
    Ok(())
}

/// A token pins one immutable snapshot and one store epoch for a read batch.
#[derive(Debug, Clone)]
pub struct CertifiedMemoryReadToken {
    snapshot: Arc<CertifiedMemorySnapshot>,
    store_epoch: u64,
}

impl CertifiedMemoryReadToken {
    pub fn generation(&self) -> u64 {
        self.snapshot.generation
    }

    pub fn attestation(&self) -> Option<CertifiedMemoryAttestation> {
        self.snapshot.attestation.clone()
    }

    pub(crate) fn content_digest(&self) -> Result<String, String> {
        self.snapshot.content_digest()
    }
}

#[derive(Debug)]
struct StoreState {
    epoch: u64,
    serving: CertifiedMemoryServing,
    snapshot: Option<Arc<CertifiedMemorySnapshot>>,
}

/// Atomic installer and token gate for certified memory reads.
#[derive(Debug)]
pub struct CertifiedMemoryStore {
    config: CertifiedMemoryConfig,
    state: RwLock<StoreState>,
}

impl CertifiedMemoryStore {
    pub fn new(config: CertifiedMemoryConfig) -> Self {
        Self {
            config,
            state: RwLock::new(StoreState {
                epoch: 0,
                serving: CertifiedMemoryServing::Cold,
                snapshot: None,
            }),
        }
    }

    pub const fn config(&self) -> CertifiedMemoryConfig {
        self.config
    }

    /// Return the installed generation for diagnostics and readiness reporting.
    pub fn installed_generation(&self) -> Option<u64> {
        self.state
            .read()
            .ok()
            .and_then(|state| state.snapshot.as_ref().map(|snapshot| snapshot.generation))
    }

    pub fn serving_state(&self) -> CertifiedMemoryServing {
        self.state
            .read()
            .map(|state| state.serving)
            .unwrap_or(CertifiedMemoryServing::Unknown)
    }

    /// Legacy direct installation is not an authority proof.
    pub fn install(
        &self,
        _snapshot: Arc<CertifiedMemorySnapshot>,
        _now_unix: i64,
    ) -> Result<u64, CertifiedMemoryFailure> {
        Err(CertifiedMemoryFailure::Unknown)
    }

    pub(crate) fn install_coordinated(
        &self,
        snapshot: Arc<CertifiedMemorySnapshot>,
        now_unix: i64,
    ) -> Result<u64, CertifiedMemoryFailure> {
        validate_snapshot(&snapshot, self.config, now_unix)?;
        let mut state = self
            .state
            .write()
            .map_err(|_| CertifiedMemoryFailure::Unknown)?;
        if state
            .snapshot
            .as_ref()
            .is_some_and(|current| snapshot.generation <= current.generation)
        {
            return Err(CertifiedMemoryFailure::Invalid {
                code: "snapshot_generation_not_monotonic".to_owned(),
            });
        }
        if snapshot.coverage == CertifiedMemoryCoverage::Gap {
            state.epoch = state.epoch.wrapping_add(1);
            state.snapshot = Some(snapshot);
            state.serving = CertifiedMemoryServing::Gap;
            return Ok(state.epoch);
        }
        state.epoch = state.epoch.wrapping_add(1);
        state.snapshot = Some(snapshot);
        state.serving = CertifiedMemoryServing::Warming;
        Ok(state.epoch)
    }

    /// Legacy direct activation does not establish readiness.
    pub fn mark_serving(
        &self,
        _generation: u64,
        _now_unix: i64,
    ) -> Result<(), CertifiedMemoryFailure> {
        Err(CertifiedMemoryFailure::Unknown)
    }

    pub(crate) fn mark_serving_coordinated(
        &self,
        generation: u64,
        now_unix: i64,
    ) -> Result<(), CertifiedMemoryFailure> {
        let mut state = self
            .state
            .write()
            .map_err(|_| CertifiedMemoryFailure::Unknown)?;
        if state.serving != CertifiedMemoryServing::Warming {
            return Err(CertifiedMemoryFailure::NotServing(state.serving));
        }
        let Some(snapshot) = state.snapshot.as_ref() else {
            return Err(CertifiedMemoryFailure::NotServing(
                CertifiedMemoryServing::Cold,
            ));
        };
        if snapshot.generation != generation {
            return Err(CertifiedMemoryFailure::TokenNotCurrent);
        }
        if snapshot.coverage != CertifiedMemoryCoverage::Complete {
            state.serving = CertifiedMemoryServing::Gap;
            state.epoch = state.epoch.wrapping_add(1);
            return Err(CertifiedMemoryFailure::Gap);
        }
        if !snapshot.coverage_contract.is_complete() {
            state.serving = CertifiedMemoryServing::Unknown;
            state.epoch = state.epoch.wrapping_add(1);
            return Err(CertifiedMemoryFailure::Unknown);
        }
        if snapshot.attestation.as_ref().is_none_or(|attestation| {
            attestation
                .validate_at(snapshot.generation, now_unix)
                .is_err()
        }) {
            state.serving = CertifiedMemoryServing::Unknown;
            state.epoch = state.epoch.wrapping_add(1);
            return Err(CertifiedMemoryFailure::Unknown);
        }
        if !snapshot.is_fresh_at(now_unix) {
            state.serving = CertifiedMemoryServing::Stale;
            state.epoch = state.epoch.wrapping_add(1);
            return Err(CertifiedMemoryFailure::Stale);
        }
        state.serving = CertifiedMemoryServing::Serving;
        state.epoch = state.epoch.wrapping_add(1);
        Ok(())
    }

    /// Enter a known non-serving state. `Serving`, `Cold`, and `Warming` are
    /// controlled by the install/readiness methods and cannot be forged here.
    pub fn mark_failure(
        &self,
        serving: CertifiedMemoryServing,
    ) -> Result<(), CertifiedMemoryFailure> {
        if matches!(
            serving,
            CertifiedMemoryServing::Serving
                | CertifiedMemoryServing::Cold
                | CertifiedMemoryServing::Warming
        ) {
            return Err(CertifiedMemoryFailure::Invalid {
                code: "invalid_failure_state".to_owned(),
            });
        }
        let mut state = self
            .state
            .write()
            .map_err(|_| CertifiedMemoryFailure::Unknown)?;
        state.serving = serving;
        state.epoch = state.epoch.wrapping_add(1);
        Ok(())
    }

    /// Mark the serving root stale without dropping it, so readers fail closed
    /// while diagnostics can still inspect the last installed generation.
    pub fn mark_stale(&self) -> Result<(), CertifiedMemoryFailure> {
        self.mark_failure(CertifiedMemoryServing::Stale)
    }

    /// Mark a transport/frontier coverage gap. The next install must use a
    /// strictly newer generation before positive reads can be reconsidered.
    pub fn mark_gap(&self) -> Result<(), CertifiedMemoryFailure> {
        self.mark_failure(CertifiedMemoryServing::Gap)
    }

    /// Mark authority state unknown, for example after a quorum timeout or
    /// worker ownership loss. Unknown never falls back to the old snapshot.
    pub fn mark_unknown(&self) -> Result<(), CertifiedMemoryFailure> {
        self.mark_failure(CertifiedMemoryServing::Unknown)
    }

    /// Mark an unrecoverable serving failure while retaining the last snapshot
    /// for inspection only.
    pub fn mark_failed(&self) -> Result<(), CertifiedMemoryFailure> {
        self.mark_failure(CertifiedMemoryServing::Failed)
    }

    /// Close the positive read gate for an explicit owner-observed cause.
    pub fn invalidate(
        &self,
        invalidation: CertifiedMemoryInvalidation,
    ) -> Result<(), CertifiedMemoryFailure> {
        match invalidation {
            CertifiedMemoryInvalidation::Stale => self.mark_stale(),
            CertifiedMemoryInvalidation::Gap => self.mark_gap(),
            CertifiedMemoryInvalidation::Unknown => self.mark_unknown(),
            CertifiedMemoryInvalidation::Failed => self.mark_failed(),
        }
    }

    pub fn begin_read(
        &self,
        now_unix: i64,
    ) -> Result<CertifiedMemoryReadToken, CertifiedMemoryFailure> {
        let state = self
            .state
            .read()
            .map_err(|_| CertifiedMemoryFailure::Unknown)?;
        if !state.serving.permits_positive_reads() {
            return Err(CertifiedMemoryFailure::NotServing(state.serving));
        }
        let snapshot = state
            .snapshot
            .as_ref()
            .ok_or(CertifiedMemoryFailure::NotServing(
                CertifiedMemoryServing::Cold,
            ))?;
        if snapshot.coverage != CertifiedMemoryCoverage::Complete {
            return Err(CertifiedMemoryFailure::Gap);
        }
        if !snapshot.is_fresh_at(now_unix) {
            return Err(CertifiedMemoryFailure::Stale);
        }
        if snapshot.attestation.as_ref().is_none_or(|attestation| {
            attestation
                .validate_at(snapshot.generation, now_unix)
                .is_err()
        }) {
            return Err(CertifiedMemoryFailure::Stale);
        }
        Ok(CertifiedMemoryReadToken {
            snapshot: Arc::clone(snapshot),
            store_epoch: state.epoch,
        })
    }

    pub fn validate_read_token(
        &self,
        token: &CertifiedMemoryReadToken,
        now_unix: i64,
    ) -> Result<(), CertifiedMemoryFailure> {
        let state = self
            .state
            .read()
            .map_err(|_| CertifiedMemoryFailure::Unknown)?;
        Self::validate_token(&state, token, now_unix).map(|_| ())
    }

    pub fn read_sod_policies(
        &self,
        token: &CertifiedMemoryReadToken,
        now_unix: i64,
    ) -> Result<Vec<CertifiedSodPolicy>, CertifiedMemoryFailure> {
        self.with_validated_token(token, now_unix, |snapshot| {
            Ok(snapshot.sod_policies.clone())
        })
    }

    /// Validate the token and copy the requested fact while the same store read
    /// guard is held. This gives the operation one linearization point relative
    /// to invalidation/replacement: an invalidation that acquires the write lock
    /// first makes this operation fail, while one that acquires it afterwards
    /// cannot undo a read that already completed under this guard. Callers that
    /// need a stronger post-invalidation guarantee must perform a final recheck
    /// after this method returns.
    fn with_validated_token<T>(
        &self,
        token: &CertifiedMemoryReadToken,
        now_unix: i64,
        read: impl FnOnce(&CertifiedMemorySnapshot) -> Result<T, CertifiedMemoryFailure>,
    ) -> Result<T, CertifiedMemoryFailure> {
        let state = self
            .state
            .read()
            .map_err(|_| CertifiedMemoryFailure::Unknown)?;
        let snapshot = Self::validate_token(&state, token, now_unix)?;
        read(snapshot)
    }

    fn validate_token<'state>(
        state: &'state StoreState,
        token: &CertifiedMemoryReadToken,
        now_unix: i64,
    ) -> Result<&'state CertifiedMemorySnapshot, CertifiedMemoryFailure> {
        if !state.serving.permits_positive_reads() {
            return Err(CertifiedMemoryFailure::NotServing(state.serving));
        }
        let Some(snapshot) = state.snapshot.as_ref() else {
            return Err(CertifiedMemoryFailure::TokenNotCurrent);
        };
        if state.epoch != token.store_epoch || !Arc::ptr_eq(snapshot, &token.snapshot) {
            return Err(CertifiedMemoryFailure::TokenNotCurrent);
        }
        if token.snapshot.coverage != CertifiedMemoryCoverage::Complete {
            return Err(CertifiedMemoryFailure::Gap);
        }
        if !token.snapshot.is_fresh_at(now_unix) {
            return Err(CertifiedMemoryFailure::Stale);
        }
        if token
            .snapshot
            .attestation
            .as_ref()
            .is_none_or(|attestation| {
                attestation
                    .validate_at(token.snapshot.generation, now_unix)
                    .is_err()
            })
        {
            return Err(CertifiedMemoryFailure::Stale);
        }
        Ok(snapshot.as_ref())
    }
}

fn validate_snapshot(
    snapshot: &CertifiedMemorySnapshot,
    config: CertifiedMemoryConfig,
    now_unix: i64,
) -> Result<(), CertifiedMemoryFailure> {
    if snapshot.entry_count() > config.max_entries || snapshot.estimated_bytes() > config.max_bytes
    {
        return Err(CertifiedMemoryFailure::CapacityExceeded);
    }
    if !snapshot.is_fresh_at(now_unix) {
        return Err(CertifiedMemoryFailure::Stale);
    }
    if snapshot.expires_at_unix - snapshot.installed_at_unix > config.ttl_seconds {
        return Err(CertifiedMemoryFailure::Invalid {
            code: "snapshot_ttl_exceeds_config".to_owned(),
        });
    }
    Ok(())
}

/// Narrow synchronous read port for future memory-only authorization adapters.
pub trait CertifiedMemoryReadModel {
    fn read_card_context(
        &self,
        token: &CertifiedMemoryReadToken,
        key: &CardContextKey,
        now_unix: i64,
    ) -> Result<Option<CertifiedCardContext>, CertifiedMemoryFailure>;

    fn read_global_admin(
        &self,
        token: &CertifiedMemoryReadToken,
        user_id: i64,
        now_unix: i64,
    ) -> Result<bool, CertifiedMemoryFailure>;

    fn read_org_authorization(
        &self,
        token: &CertifiedMemoryReadToken,
        key: &OrgReadKey,
        now_unix: i64,
    ) -> Result<Option<OrgAuthorityRead>, CertifiedMemoryFailure>;

    fn read_ownership(
        &self,
        token: &CertifiedMemoryReadToken,
        key: &OwnershipReadKey,
        now_unix: i64,
    ) -> Result<Option<ResourceOwnershipResolution>, CertifiedMemoryFailure>;

    fn read_published_card_evidence(
        &self,
        token: &CertifiedMemoryReadToken,
        scope: &PublishedCardEvidenceScope,
        now_unix: i64,
    ) -> Result<Option<Arc<PublishedCardAuthorization>>, CertifiedMemoryFailure>;

    fn read_sod_policies(
        &self,
        token: &CertifiedMemoryReadToken,
        now_unix: i64,
    ) -> Result<Vec<CertifiedSodPolicy>, CertifiedMemoryFailure>;
}

impl CertifiedMemoryReadModel for CertifiedMemoryStore {
    fn read_card_context(
        &self,
        token: &CertifiedMemoryReadToken,
        key: &CardContextKey,
        now_unix: i64,
    ) -> Result<Option<CertifiedCardContext>, CertifiedMemoryFailure> {
        self.with_validated_token(token, now_unix, |snapshot| {
            let Some(value) = snapshot.card_contexts.get(key).cloned() else {
                return Ok(None);
            };
            value
                .validate_for(key)
                .map_err(|code| CertifiedMemoryFailure::Invalid { code })?;
            if value
                .eligibility
                .effective_expiry
                .is_some_and(|expires_at| expires_at <= now_unix)
            {
                return Ok(None);
            }
            Ok(Some(value))
        })
    }

    fn read_global_admin(
        &self,
        token: &CertifiedMemoryReadToken,
        user_id: i64,
        now_unix: i64,
    ) -> Result<bool, CertifiedMemoryFailure> {
        self.with_validated_token(token, now_unix, |snapshot| {
            if user_id <= 0 {
                return Ok(false);
            }
            Ok(matches!(
                snapshot.global_admins.get(&user_id),
                Some(GlobalAdminStatus::Active)
            ))
        })
    }

    fn read_org_authorization(
        &self,
        token: &CertifiedMemoryReadToken,
        key: &OrgReadKey,
        now_unix: i64,
    ) -> Result<Option<OrgAuthorityRead>, CertifiedMemoryFailure> {
        self.with_validated_token(token, now_unix, |snapshot| {
            let Some(value) = snapshot.org_reads.get(key) else {
                return Ok(None);
            };
            validate_org_read(key, value.as_ref())
                .map_err(|code| CertifiedMemoryFailure::Invalid { code })?;
            Ok(Some(value.as_ref().clone()))
        })
    }

    fn read_ownership(
        &self,
        token: &CertifiedMemoryReadToken,
        key: &OwnershipReadKey,
        now_unix: i64,
    ) -> Result<Option<ResourceOwnershipResolution>, CertifiedMemoryFailure> {
        self.with_validated_token(token, now_unix, |snapshot| {
            let Some(value) = snapshot.ownership.get(key) else {
                return Ok(None);
            };
            validate_ownership(value).map_err(|code| CertifiedMemoryFailure::Invalid { code })?;
            Ok(Some(value.clone()))
        })
    }

    fn read_published_card_evidence(
        &self,
        token: &CertifiedMemoryReadToken,
        scope: &PublishedCardEvidenceScope,
        now_unix: i64,
    ) -> Result<Option<Arc<PublishedCardAuthorization>>, CertifiedMemoryFailure> {
        self.with_validated_token(token, now_unix, |snapshot| {
            let key = PublishedCardEvidenceKey::from(scope);
            key.validate()
                .map_err(|code| CertifiedMemoryFailure::Invalid { code })?;
            let Some(evidence) = snapshot.published_cards.get(&key) else {
                return Ok(None);
            };
            evidence
                .validate()
                .map_err(|error| CertifiedMemoryFailure::Invalid {
                    code: format!("published card evidence is invalid: {error}"),
                })?;
            if evidence.tenant_id != scope.tenant_id || evidence.card_id != scope.card_id {
                return Err(CertifiedMemoryFailure::Invalid {
                    code: "published evidence scope mismatch".to_owned(),
                });
            }
            Ok(Some(Arc::clone(evidence)))
        })
    }

    fn read_sod_policies(
        &self,
        token: &CertifiedMemoryReadToken,
        now_unix: i64,
    ) -> Result<Vec<CertifiedSodPolicy>, CertifiedMemoryFailure> {
        CertifiedMemoryStore::read_sod_policies(self, token, now_unix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000;

    fn store() -> CertifiedMemoryStore {
        CertifiedMemoryStore::new(
            CertifiedMemoryConfig::new(16, 64 * 1024, 60).expect("test bounds"),
        )
    }

    fn snapshot() -> CertifiedMemorySnapshot {
        let mut snapshot =
            CertifiedMemorySnapshot::empty(1, NOW, NOW + 60, CertifiedMemoryCoverage::Complete)
                .expect("test snapshot");
        snapshot
            .attach_attestation(CertifiedMemoryAttestation {
                authority_term: 1,
                global_fence_sequence: 1,
                key_epoch: 1,
                scope_generation: 1,
                revoke_watermark: 0,
                snapshot_hash: "0".repeat(64),
                issued_at_unix: NOW,
                expires_at_unix: NOW + 60,
            })
            .expect("test attestation");
        snapshot
            .set_coverage_contract(CertifiedMemoryCoverageContract::complete())
            .expect("test coverage");
        snapshot
            .set_coverage_contract(CertifiedMemoryCoverageContract::complete())
            .expect("test coverage");
        snapshot
    }

    fn card_key() -> CardContextKey {
        CardContextKey {
            user_id: 7,
            identity_card_id: 8,
            user_card_id: 9,
        }
    }

    fn card_context() -> CertifiedCardContext {
        CertifiedCardContext {
            user_id: 7,
            eligibility: CardEligibility {
                identity_card_id: 8,
                user_card_id: 9,
                user_card_tenant_id: 10,
                user_card_domain_id: 11,
                effective_expiry: Some(NOW + 30),
            },
        }
    }

    #[test]
    fn expired_attestation_rejects_new_and_existing_reads() {
        let store = store();
        let mut snapshot = snapshot();
        snapshot.attestation.as_mut().unwrap().expires_at_unix = NOW + 30;
        snapshot
            .insert_global_admin(7, GlobalAdminStatus::Active)
            .unwrap();
        store
            .install_coordinated(Arc::new(snapshot), NOW + 1)
            .unwrap();
        store.mark_serving_coordinated(1, NOW + 1).unwrap();
        let token = store.begin_read(NOW + 29).unwrap();
        assert!(store.read_global_admin(&token, 7, NOW + 29).unwrap());
        assert!(matches!(
            store.begin_read(NOW + 30),
            Err(CertifiedMemoryFailure::Stale)
        ));
        assert!(matches!(
            store.validate_read_token(&token, NOW + 30),
            Err(CertifiedMemoryFailure::Stale)
        ));
        assert!(matches!(
            store.read_global_admin(&token, 7, NOW + 31),
            Err(CertifiedMemoryFailure::Stale)
        ));
    }

    #[test]
    fn read_lock_serializes_fact_access_with_invalidation() {
        use std::sync::{mpsc, Arc};
        let store = Arc::new(store());
        store
            .install_coordinated(Arc::new(snapshot()), NOW + 1)
            .unwrap();
        store.mark_serving_coordinated(1, NOW + 1).unwrap();
        let token = store.begin_read(NOW + 1).unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let reader_store = Arc::clone(&store);
        let reader = std::thread::spawn(move || {
            reader_store
                .with_validated_token(&token, NOW + 1, |_| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(())
                })
                .unwrap();
        });
        entered_rx.recv().unwrap();
        assert!(matches!(
            store.state.try_write(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        release_tx.send(()).unwrap();
        reader.join().unwrap();
        store
            .invalidate(CertifiedMemoryInvalidation::Unknown)
            .unwrap();
        assert!(store.begin_read(NOW + 1).is_err());
    }

    #[test]
    fn canonical_content_digest_is_independent_of_map_insertion_order() {
        let mut first = snapshot();
        first
            .insert_global_admin(7, GlobalAdminStatus::Active)
            .expect("admin seven");
        first
            .insert_global_admin(3, GlobalAdminStatus::Inactive)
            .expect("admin three");
        let mut second = snapshot();
        second
            .insert_global_admin(3, GlobalAdminStatus::Inactive)
            .expect("admin three");
        second
            .insert_global_admin(7, GlobalAdminStatus::Active)
            .expect("admin seven");
        assert_eq!(
            first.content_digest().expect("first digest"),
            second.content_digest().expect("second digest")
        );
        assert_eq!(
            first.canonical_content_bytes().expect("first bytes"),
            second.canonical_content_bytes().expect("second bytes")
        );
    }

    #[test]
    fn canonical_content_digest_changes_when_fact_content_changes() {
        let mut active = snapshot();
        active
            .insert_global_admin(7, GlobalAdminStatus::Active)
            .expect("active admin");
        let mut inactive = snapshot();
        inactive
            .insert_global_admin(7, GlobalAdminStatus::Inactive)
            .expect("inactive admin");
        assert_ne!(
            active.content_digest().expect("active digest"),
            inactive.content_digest().expect("inactive digest")
        );
    }

    #[test]
    fn snapshot_miss_never_returns_positive() {
        let store = store();
        assert_eq!(store.serving_state(), CertifiedMemoryServing::Cold);
        assert!(matches!(
            store.begin_read(NOW),
            Err(CertifiedMemoryFailure::NotServing(
                CertifiedMemoryServing::Cold
            ))
        ));
    }

    #[test]
    fn warming_and_invalid_state_never_return_positive() {
        let store = store();
        let mut snapshot = snapshot();
        snapshot
            .insert_global_admin(7, GlobalAdminStatus::Active)
            .expect("global admin");
        let generation = snapshot.generation();
        store
            .install_coordinated(Arc::new(snapshot), NOW + 1)
            .expect("install");
        assert!(matches!(
            store.begin_read(NOW + 1),
            Err(CertifiedMemoryFailure::NotServing(
                CertifiedMemoryServing::Warming
            ))
        ));
        store
            .mark_serving_coordinated(generation, NOW + 1)
            .expect("serve");
        let token = store.begin_read(NOW + 1).expect("token");
        assert!(store.read_global_admin(&token, 7, NOW + 1).expect("read"));
        store
            .mark_failure(CertifiedMemoryServing::Unknown)
            .expect("unknown");
        assert!(!matches!(
            store.read_global_admin(&token, 7, NOW + 1),
            Ok(true)
        ));
    }

    #[test]
    fn delayed_serving_cannot_reopen_an_invalidated_snapshot() {
        for invalidation in [
            CertifiedMemoryInvalidation::Stale,
            CertifiedMemoryInvalidation::Gap,
            CertifiedMemoryInvalidation::Unknown,
            CertifiedMemoryInvalidation::Failed,
        ] {
            let store = store();
            store
                .install_coordinated(Arc::new(snapshot()), NOW + 1)
                .expect("install");
            store.invalidate(invalidation).expect("invalidate");
            assert!(matches!(
                store.mark_serving_coordinated(1, NOW + 1),
                Err(CertifiedMemoryFailure::NotServing(_))
            ));
            assert!(store.begin_read(NOW + 1).is_err());
        }
    }

    #[test]
    fn stable_snapshot_reads_need_no_sql_or_pool() {
        let store = store();
        let mut snapshot = snapshot();
        snapshot
            .insert_card_context(card_key(), card_context())
            .expect("card context");
        snapshot
            .insert_global_admin(7, GlobalAdminStatus::Active)
            .expect("global admin");
        let generation = snapshot.generation();
        store
            .install_coordinated(Arc::new(snapshot), NOW + 1)
            .expect("install");
        store
            .mark_serving_coordinated(generation, NOW + 1)
            .expect("serve");
        let token = store.begin_read(NOW + 2).expect("token");
        assert_eq!(
            store
                .read_card_context(&token, &card_key(), NOW + 2)
                .expect("card read"),
            Some(card_context())
        );
        assert!(store
            .read_global_admin(&token, 7, NOW + 2)
            .expect("admin read"));
    }

    #[test]
    fn stale_reads_and_replaced_tokens_fail_closed() {
        let store = store();
        let generation = snapshot().generation();
        store
            .install_coordinated(Arc::new(snapshot()), NOW + 1)
            .expect("install");
        store
            .mark_serving_coordinated(generation, NOW + 1)
            .expect("serve");
        let token = store.begin_read(NOW + 1).expect("token");
        assert!(matches!(
            store.read_global_admin(&token, 7, NOW + 60),
            Err(CertifiedMemoryFailure::Stale)
        ));

        let replacement =
            CertifiedMemorySnapshot::empty(2, NOW + 2, NOW + 62, CertifiedMemoryCoverage::Complete)
                .expect("replacement");
        store
            .install_coordinated(Arc::new(replacement), NOW + 2)
            .expect("replace");
        assert!(matches!(
            store.read_global_admin(&token, 7, NOW + 2),
            Err(CertifiedMemoryFailure::NotServing(
                CertifiedMemoryServing::Warming
            ))
        ));
    }

    #[test]
    fn replacement_generation_must_increase_and_invalidations_close_read_gate() {
        let store = store();
        let first = snapshot();
        store
            .install_coordinated(Arc::new(first), NOW + 1)
            .expect("install");
        store.mark_serving_coordinated(1, NOW + 1).expect("serve");
        assert!(store.mark_stale().is_ok());
        assert!(matches!(
            store.begin_read(NOW + 1),
            Err(CertifiedMemoryFailure::NotServing(
                CertifiedMemoryServing::Stale
            ))
        ));

        let mut stale_generation =
            CertifiedMemorySnapshot::empty(1, NOW + 2, NOW + 62, CertifiedMemoryCoverage::Complete)
                .expect("snapshot");
        stale_generation
            .attach_attestation(CertifiedMemoryAttestation {
                authority_term: 1,
                global_fence_sequence: 2,
                key_epoch: 1,
                scope_generation: 1,
                revoke_watermark: 0,
                snapshot_hash: "0".repeat(64),
                issued_at_unix: NOW + 2,
                expires_at_unix: NOW + 62,
            })
            .expect("attestation");
        stale_generation
            .set_coverage_contract(CertifiedMemoryCoverageContract::complete())
            .expect("coverage");
        assert!(matches!(
            store.install_coordinated(Arc::new(stale_generation), NOW + 2),
            Err(CertifiedMemoryFailure::Invalid { .. })
        ));

        assert!(store.mark_gap().is_ok());
        assert!(store.mark_unknown().is_ok());
        assert!(store.mark_failed().is_ok());
    }

    #[test]
    fn incomplete_fact_coverage_cannot_enter_serving() {
        let store = store();
        let snapshot =
            CertifiedMemorySnapshot::empty(4, NOW, NOW + 60, CertifiedMemoryCoverage::Complete)
                .expect("snapshot");
        store
            .install_coordinated(Arc::new(snapshot), NOW + 1)
            .expect("install");
        assert_eq!(
            store.mark_serving_coordinated(4, NOW + 1),
            Err(CertifiedMemoryFailure::Unknown)
        );
        assert_eq!(store.serving_state(), CertifiedMemoryServing::Unknown);
    }

    #[test]
    fn gap_and_capacity_never_enter_serving() {
        let bounded = CertifiedMemoryStore::new(
            CertifiedMemoryConfig::new(1, 64 * 1024, 60).expect("bounds"),
        );
        let mut too_many = snapshot();
        too_many
            .insert_global_admin(1, GlobalAdminStatus::Active)
            .expect("first");
        too_many
            .insert_global_admin(2, GlobalAdminStatus::Active)
            .expect("second");
        assert_eq!(
            bounded.install_coordinated(Arc::new(too_many), NOW + 1),
            Err(CertifiedMemoryFailure::CapacityExceeded)
        );

        let gap = CertifiedMemorySnapshot::empty(3, NOW, NOW + 60, CertifiedMemoryCoverage::Gap)
            .expect("gap snapshot");
        let gap_store = store();
        gap_store
            .install_coordinated(Arc::new(gap), NOW + 1)
            .expect("install gap");
        assert_eq!(gap_store.serving_state(), CertifiedMemoryServing::Gap);
        assert!(matches!(
            gap_store.begin_read(NOW + 1),
            Err(CertifiedMemoryFailure::NotServing(
                CertifiedMemoryServing::Gap
            ))
        ));
    }
}
