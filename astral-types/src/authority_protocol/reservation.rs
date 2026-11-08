//! Generic protocol scope, source intents, reservations and reconciliation.
//!
//! The protocol scope is deliberately generic: the existing actor-card scope
//! ([`AuthorizationAuthorityScope`]) is reused unchanged, and ORG publication
//! units get their own scope kind so the service is not card-hardcoded. Source
//! operations (prepare/commit/reconcile) reserve scopes; while a reservation
//! is pending, unknown or quarantined, positive reads for the covered scopes
//! fail closed.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::{
    authority_counter, authority_digest, authority_field, authority_optional_i64,
    authority_positive_id, authority_signature_encoding, authority_text, authority_time_window,
    authority_timestamp, authority_verify_strict, AuthorityProtocolError,
};
use crate::{AuthorizationAuthorityScope, AuthorizationDomainScope, AUTHORIZATION_EDITION};

const INTENT_ACCEPTANCE_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_INTENT_ACCEPTANCE_V1\0";

/// The kind of source mutation a reservation authorizes.
///
/// [`AuthorityMutationKind::AuthorizationSource`] mutations affect effective
/// authorization: their GLOBAL reservations block positive reads until
/// certified coverage — closed by an operator, or (V7 late-coverage contract)
/// automatically once a COMPLETE finite coverage declared at COMMIT, bound to
/// the source-outcome/staged-evidence digests, is certified for every
/// declared scope while the authority policy `exact_scope_coverage_enabled`
/// is on AND the trusted source carries the explicit operator-configured
/// `commit_finite_coverage` allowed operation. [`AuthorityMutationKind::
/// ProtectedBusiness`] mutations are still bound to a one-use authority proof
/// and a registered trusted executor, but never block authorization reads and
/// terminate on the proven source commit — no publication, no barrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityMutationKind {
    AuthorizationSource,
    ProtectedBusiness,
}

impl AuthorityMutationKind {
    /// Whether reservations of this kind block positive authorization reads.
    pub const fn blocks_positive_reads(self) -> bool {
        matches!(self, Self::AuthorizationSource)
    }

    pub const fn as_text(self) -> &'static str {
        match self {
            Self::AuthorizationSource => "AUTHORIZATION_SOURCE",
            Self::ProtectedBusiness => "PROTECTED_BUSINESS",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "AUTHORIZATION_SOURCE" => Some(Self::AuthorizationSource),
            "PROTECTED_BUSINESS" => Some(Self::ProtectedBusiness),
            _ => None,
        }
    }
}

/// ORG publication-unit scope. ORG evidence is certified at the publication
/// unit level; the snapshot hash bound to the certificate is the canonical
/// full ORG publication/member frontier digest supplied by the source owner.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityOrgScope {
    pub tenant_id: i64,
    /// Administrative root tenant of the publication unit, when pinned.
    pub root_tenant_id: Option<i64>,
    /// Exact actor membership identity bound to this scope. ORG certificates
    /// are member-exact: two members of one publication never share a scope.
    pub member: AuthorityOrgMemberSubject,
}

/// The exact actor membership identity (mirrors the ORG membership facts:
/// user, identity card, and actor card must all match).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityOrgMemberSubject {
    pub user_id: i64,
    pub identity_card_id: i64,
    pub card_id: i64,
}

impl AuthorityOrgMemberSubject {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        authority_positive_id(self.user_id, "user_id")?;
        authority_positive_id(self.identity_card_id, "identity_card_id")?;
        authority_positive_id(self.card_id, "card_id")?;
        Ok(())
    }
}

impl AuthorityOrgScope {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        authority_positive_id(self.tenant_id, "tenant_id")?;
        if let Some(root_tenant_id) = self.root_tenant_id {
            authority_positive_id(root_tenant_id, "root_tenant_id")?;
        }
        self.member.validate()
    }
}

/// Generic protocol scope: one exact identity that a reservation blocks or a
/// certificate publishes. Never a prefix, never a wildcard.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
pub enum AuthorityProtocolScope {
    /// Actor-card scope, reusing the existing contract unchanged.
    Card(AuthorizationAuthorityScope),
    /// ORG publication-unit scope, member-exact.
    Org(AuthorityOrgScope),
}

impl AuthorityProtocolScope {
    /// Exact card identity behind a CARD scope: `(tenant_id, card_id)`.
    /// ORG scopes have no card identity.
    pub fn card_identity(&self) -> Option<(i64, i64)> {
        match self {
            Self::Card(scope) => Some((scope.tenant_id, scope.card_id)),
            Self::Org(_) => None,
        }
    }

    /// Whether two scopes address the same card identity: CARD↔CARD with the
    /// same `(tenant_id, card_id)` regardless of user/domain lens. ORG scopes
    /// never cover a card. This is an identity comparison, never a prefix or
    /// wildcard match.
    pub fn covers_same_card(&self, other: &Self) -> bool {
        match (self.card_identity(), other.card_identity()) {
            (Some(left), Some(right)) => left == right,
            _ => false,
        }
    }

    /// Canonical CARD publication scope of one scope: the same
    /// `(tenant_id, card_id)` identity with the lens fields dropped
    /// (`user_id: None`, `domain: Any`). ORG scopes have no canonical card
    /// form. Certificates for card scopes are published at exactly this
    /// canonical identity; request proofs stay at the exact actor lens.
    pub fn canonical_card_publication_scope(&self) -> Option<Self> {
        match self {
            Self::Card(scope) => Some(Self::Card(AuthorizationAuthorityScope {
                tenant_id: scope.tenant_id,
                card_id: scope.card_id,
                user_id: None,
                domain: AuthorizationDomainScope::Any,
            })),
            Self::Org(_) => None,
        }
    }
}

impl AuthorityProtocolScope {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        match self {
            Self::Card(scope) => {
                scope
                    .validate()
                    .map_err(|_| AuthorityProtocolError::InvalidIdentifier {
                        field: "card_scope",
                    })
            }
            Self::Org(scope) => scope.validate(),
        }
    }

    pub fn kind_text(&self) -> &'static str {
        match self {
            Self::Card(_) => "CARD",
            Self::Org(_) => "ORG",
        }
    }

    /// Canonical, bounded, injective text identity used as the durable key.
    pub fn store_key_text(&self) -> Result<String, AuthorityProtocolError> {
        self.validate()?;
        Ok(match self {
            Self::Card(scope) => {
                let user = authority_optional_i64(scope.user_id);
                let domain = match &scope.domain {
                    AuthorizationDomainScope::Any => "ANY".to_owned(),
                    AuthorizationDomainScope::NoDomain => "NONE".to_owned(),
                    AuthorizationDomainScope::Exact(value) => format!("EXACT:{value}"),
                };
                format!(
                    "CARD:{}:{}:{}:{}",
                    scope.tenant_id, scope.card_id, user, domain
                )
            }
            Self::Org(scope) => format!(
                "ORG:{}:{}:{}:{}:{}",
                scope.tenant_id,
                authority_optional_i64(scope.root_tenant_id),
                scope.member.user_id,
                scope.member.identity_card_id,
                scope.member.card_id
            ),
        })
    }
}

/// Which scopes one source reservation blocks.
///
/// The conservative production path is [`Self::Global`]: every reservation
/// blocks ALL scopes until exact affected-scope coverage is established, so a
/// stale `ALLOW` can never be served while any source operation is in flight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    content = "scopes",
    rename_all = "SCREAMING_SNAKE_CASE",
    rename_all_fields = "camelCase"
)]
pub enum AuthorityReservationCoverage {
    /// Block every scope (conservative default).
    Global,
    /// Block exactly the listed scopes.
    Exact(Vec<AuthorityProtocolScope>),
}

impl AuthorityReservationCoverage {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        match self {
            Self::Global => Ok(()),
            Self::Exact(scopes) => {
                // A finite EXACT set is the automatic-closure contract: the
                // complete declared set is bound at COMMIT (late coverage,
                // digest-tied to the durable source outcome) and the
                // authority tracks certified_scopes; the barrier clears only
                // when EVERY declared scope is certified, under the
                // exact_scope_coverage_enabled policy with the source's
                // explicit commit_finite_coverage permission. Cap keeps the
                // signing bytes bounded.
                if scopes.is_empty() || scopes.len() > 256 {
                    return Err(AuthorityProtocolError::InvalidCoverage);
                }
                let mut keys = std::collections::HashSet::with_capacity(scopes.len());
                for scope in scopes {
                    if !keys.insert(scope.store_key_text()?) {
                        return Err(AuthorityProtocolError::InvalidCoverage);
                    }
                }
                Ok(())
            }
        }
    }

    /// Whether this coverage blocks the given scope.
    ///
    /// CARD coverage is lens-closed by card identity: a declared CARD scope
    /// blocks every user/domain lens of the same `(tenant_id, card_id)` — a
    /// lens-bearing declared key conservatively blocks the whole card. ORG
    /// coverage only ever matches its exact ORG scope. This remains an
    /// identity comparison, never a prefix or wildcard match.
    pub fn covers(&self, scope: &AuthorityProtocolScope) -> Result<bool, AuthorityProtocolError> {
        self.validate()?;
        Ok(match self {
            Self::Global => true,
            Self::Exact(scopes) => scopes
                .iter()
                .any(|declared| declared == scope || declared.covers_same_card(scope)),
        })
    }

    /// Whether this coverage blocks every scope.
    pub const fn is_global(&self) -> bool {
        matches!(self, Self::Global)
    }
}

/// Durable reservation states. Lease expiry never clears any of them: only an
/// explicit commit/certify/abort/quarantine transition applied by the quorum
/// changes the state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityReservationState {
    /// Accepted by quorum; source mutation not yet durably committed.
    Reserved,
    /// Source commit durably acknowledged; awaiting publication certification.
    Committed,
    /// Publication certified; terminal success; positive reads unblocked.
    Certified,
    /// Distinct ELIGIBILITY completion terminal success (V7): the immutable
    /// eligibility completion receipt is durable, no grant publication ever
    /// existed for this reservation, and positive reads are unblocked.
    /// Terminal: never abortable, never closeable, never certifiable.
    Completed,
    /// Certified under GLOBAL coverage: the publication certificate exists,
    /// but the conservative barrier stays UP until the reservation is closed —
    /// by an operator, or (V7 late-coverage contract) automatically once a
    /// COMPLETE finite coverage declared at COMMIT is certified for every
    /// declared scope under the `exact_scope_coverage_enabled` policy with the
    /// source's explicit `commit_finite_coverage` permission. The GLOBAL
    /// barrier itself never shrinks mid-flight and the intent never changes.
    Published,
    /// Explicitly aborted before commit; terminal; positive reads unblocked.
    Aborted,
    /// Reconcile found an inconsistency; terminal until operator action;
    /// positive reads stay blocked.
    Quarantined,
}

impl AuthorityReservationState {
    /// Whether positive reads for covered scopes are blocked in this state.
    pub const fn blocks_positive_reads(self) -> bool {
        matches!(
            self,
            Self::Reserved | Self::Committed | Self::Published | Self::Quarantined
        )
    }

    pub const fn as_text(self) -> &'static str {
        match self {
            Self::Reserved => "RESERVED",
            Self::Committed => "COMMITTED",
            Self::Certified => "CERTIFIED",
            Self::Completed => "COMPLETED",
            Self::Published => "PUBLISHED",
            Self::Aborted => "ABORTED",
            Self::Quarantined => "QUARANTINED",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "RESERVED" => Some(Self::Reserved),
            "COMMITTED" => Some(Self::Committed),
            "CERTIFIED" => Some(Self::Certified),
            "COMPLETED" => Some(Self::Completed),
            "PUBLISHED" => Some(Self::Published),
            "ABORTED" => Some(Self::Aborted),
            "QUARANTINED" => Some(Self::Quarantined),
            _ => None,
        }
    }
}

/// The approved source intent accepted by the authority.
///
/// `admission_proof_id` is the F1 identity of the authority-issued
/// [`AuthorizationFenceProof`] consumed by the source commit owner's durable
/// one-use admission row; `request_digest` is the approved immutable target
/// request digest. Together they tie the trusted source process identity to
/// exactly one approved mutation: the database alone cannot self-certify.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySourceIntent {
    pub authorization_edition: u16,
    /// The mutation kind declared by the approved intent; must equal the
    /// kind recorded on the referenced proof receipt.
    pub mutation_kind: AuthorityMutationKind,
    pub operation_id: String,
    pub event_id: String,
    pub admission_proof_id: String,
    /// SHA-256 of the approved, immutable target request content.
    pub request_digest: String,
    /// Trusted source process identity (must equal the mTLS-derived identity).
    pub service_id: String,
    /// Registered database identity executing the source transaction.
    pub database_id: String,
    pub coverage: AuthorityReservationCoverage,
    /// Reserved-phase before-image binding.
    ///
    /// `Some(value)` means single-phase: the certification must supply
    /// exactly this digest.
    /// `None` means two-phase pinning (the DEFAULT, not "first publication
    /// only"): the reservation carries no content claim, and the source
    /// transaction pins the ACTUAL before-image digest when it promotes its
    /// durable outcome row; certification must then supply that pinned
    /// digest. The actor authorization snapshot hash is never a valid
    /// substitute for the source before-image, in either phase.
    pub before_image_digest: Option<String>,
    /// Lease window of the admitting authorization. After expiry a source
    /// replay is refused even when the original prepare never became visible.
    pub lease_not_before: i64,
    pub lease_expires_at: i64,
    pub intent_nonce: String,
}

impl AuthoritySourceIntent {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        if self.authorization_edition != AUTHORIZATION_EDITION {
            return Err(AuthorityProtocolError::WrongEdition);
        }
        authority_text(&self.operation_id, "operation_id")?;
        authority_text(&self.event_id, "event_id")?;
        authority_text(&self.admission_proof_id, "admission_proof_id")?;
        authority_digest(&self.request_digest, "request_digest")?;
        authority_text(&self.service_id, "service_id")?;
        authority_text(&self.database_id, "database_id")?;
        self.coverage.validate()?;
        if let Some(before_image_digest) = &self.before_image_digest {
            authority_digest(before_image_digest, "before_image_digest")?;
        }
        authority_time_window(
            self.lease_not_before,
            self.lease_not_before,
            self.lease_expires_at,
        )?;
        authority_text(&self.intent_nonce, "intent_nonce")?;
        Ok(())
    }

    /// Canonical intent digest: the stable identity of the approved mutation
    /// binding. One intent digest may be accepted exactly once.
    pub fn digest(&self) -> Result<String, AuthorityProtocolError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(b"ASTRAL_AUTHORITY_SOURCE_INTENT_V1\0");
        authority_field(&mut bytes, &self.authorization_edition.to_string());
        authority_field(&mut bytes, self.mutation_kind.as_text());
        authority_field(&mut bytes, &self.operation_id);
        authority_field(&mut bytes, &self.event_id);
        authority_field(&mut bytes, &self.admission_proof_id);
        authority_field(&mut bytes, &self.request_digest);
        authority_field(&mut bytes, &self.service_id);
        authority_field(&mut bytes, &self.database_id);
        authority_field(&mut bytes, &self.coverage_mode_text()?);
        if let Some(before_image_digest) = &self.before_image_digest {
            authority_field(&mut bytes, before_image_digest);
        } else {
            authority_field(&mut bytes, "-");
        }
        authority_field(&mut bytes, &self.lease_not_before.to_string());
        authority_field(&mut bytes, &self.lease_expires_at.to_string());
        authority_field(&mut bytes, &self.intent_nonce);
        Ok(super::authority_sha256_hex(&bytes))
    }

    fn coverage_mode_text(&self) -> Result<String, AuthorityProtocolError> {
        match &self.coverage {
            AuthorityReservationCoverage::Global => Ok("GLOBAL".to_owned()),
            AuthorityReservationCoverage::Exact(scopes) => {
                let mut joined = String::from("EXACT:");
                for scope in scopes {
                    joined.push_str(
                        &scope
                            .store_key_text()
                            .map_err(|_| AuthorityProtocolError::InvalidCoverage)?,
                    );
                    joined.push('|');
                }
                Ok(joined)
            }
        }
    }
}

/// The authority-signed acceptance of one intent. Callers persist it as the
/// durable receipt that a prepare was accepted at a specific frontier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityIntentAcceptance {
    pub authorization_edition: u16,
    pub authority_id: String,
    pub intent_digest: String,
    pub reservation_id: String,
    pub authority_term: u64,
    pub global_fence_sequence: u64,
    pub key_id: String,
    pub key_epoch: u64,
    pub accepted_at: i64,
    pub acceptance_nonce: String,
    /// Lowercase hex Ed25519 signature by the authority signer.
    pub signature: String,
}

impl AuthorityIntentAcceptance {
    /// Validate the acceptance except the signature encoding, used on the
    /// unsigned signing path.
    pub fn validate_unsigned(&self) -> Result<(), AuthorityProtocolError> {
        if self.authorization_edition != AUTHORIZATION_EDITION {
            return Err(AuthorityProtocolError::WrongEdition);
        }
        authority_text(&self.authority_id, "authority_id")?;
        authority_digest(&self.intent_digest, "intent_digest")?;
        authority_text(&self.reservation_id, "reservation_id")?;
        authority_counter(self.authority_term, "authority_term")?;
        authority_counter(self.global_fence_sequence, "global_fence_sequence")?;
        authority_text(&self.key_id, "key_id")?;
        authority_counter(self.key_epoch, "key_epoch")?;
        authority_timestamp(self.accepted_at, "accepted_at")?;
        authority_text(&self.acceptance_nonce, "acceptance_nonce")?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.validate_unsigned()?;
        authority_signature_encoding(&self.signature)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, AuthorityProtocolError> {
        self.validate_unsigned()?;
        let mut bytes = Vec::with_capacity(320);
        bytes.extend_from_slice(INTENT_ACCEPTANCE_DOMAIN);
        authority_field(&mut bytes, &self.authorization_edition.to_string());
        authority_field(&mut bytes, &self.authority_id);
        authority_field(&mut bytes, &self.intent_digest);
        authority_field(&mut bytes, &self.reservation_id);
        authority_field(&mut bytes, &self.authority_term.to_string());
        authority_field(&mut bytes, &self.global_fence_sequence.to_string());
        authority_field(&mut bytes, &self.key_id);
        authority_field(&mut bytes, &self.key_epoch.to_string());
        authority_field(&mut bytes, &self.accepted_at.to_string());
        authority_field(&mut bytes, &self.acceptance_nonce);
        Ok(bytes)
    }

    pub fn sign_with(&mut self, signing_key: &SigningKey) -> Result<(), AuthorityProtocolError> {
        self.signature = String::new();
        self.validate_unsigned()?;
        let signature = signing_key.sign(&self.signing_bytes()?);
        self.signature = hex::encode(signature.to_bytes());
        Ok(())
    }

    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), AuthorityProtocolError> {
        self.validate()?;
        authority_verify_strict(verifying_key, &self.signing_bytes()?, &self.signature)
    }
}

/// The durable reservation record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityScopeReservation {
    pub reservation_id: String,
    pub intent_digest: String,
    pub intent: AuthoritySourceIntent,
    pub state: AuthorityReservationState,
    pub authority_term: u64,
    pub fence_sequence_at_prepare: u64,
    pub created_at: i64,
    pub updated_at: i64,
    pub committed_at: Option<i64>,
    /// SHA-256 of the durable source commit evidence, set at commit.
    pub source_commit_digest: Option<String>,
    /// SHA-256 of the after-image, set at commit.
    pub after_image_digest: Option<String>,
    /// Certificate identity of the certifying publication, set at certify.
    pub certificate_id: Option<String>,
    /// Canonical store keys of scopes certified so far. The barrier clears
    /// ONLY when this covers every declared EXACT scope.
    #[serde(default)]
    pub certified_scopes: Vec<String>,
    /// Canonical digest of the durable source-outcome record, bound at
    /// source commit and echoed in every response binding.
    #[serde(default)]
    pub source_outcome_digest: Option<String>,
}

impl AuthorityScopeReservation {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        authority_text(&self.reservation_id, "reservation_id")?;
        authority_digest(&self.intent_digest, "intent_digest")?;
        self.intent.validate()?;
        authority_counter(self.authority_term, "authority_term")?;
        authority_counter(self.fence_sequence_at_prepare, "fence_sequence_at_prepare")?;
        authority_timestamp(self.created_at, "created_at")?;
        authority_timestamp(self.updated_at, "updated_at")?;
        if self.created_at > self.updated_at {
            return Err(AuthorityProtocolError::InvalidTimeWindow);
        }
        if let Some(committed_at) = self.committed_at {
            authority_timestamp(committed_at, "committed_at")?;
        }
        if let Some(source_commit_digest) = &self.source_commit_digest {
            authority_digest(source_commit_digest, "source_commit_digest")?;
        }
        if let Some(after_image_digest) = &self.after_image_digest {
            authority_digest(after_image_digest, "after_image_digest")?;
        }
        if let Some(certificate_id) = &self.certificate_id {
            authority_text(certificate_id, "certificate_id")?;
        }
        if let Some(digest) = &self.source_outcome_digest {
            authority_digest(digest, "source_outcome_digest")?;
        }
        if self.certified_scopes.len() > 256 {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }
        let mut scopes = std::collections::BTreeSet::new();
        for key in &self.certified_scopes {
            authority_text(key, "certified_scope")?;
            if !scopes.insert(key) {
                return Err(AuthorityProtocolError::InvalidCoverage);
            }
            if let AuthorityReservationCoverage::Exact(covered) = &self.intent.coverage {
                if !covered
                    .iter()
                    .any(|scope| scope.store_key_text().is_ok_and(|value| &value == key))
                {
                    return Err(AuthorityProtocolError::InvalidCoverage);
                }
            }
        }
        Ok(())
    }

    /// Whether positive reads for covered scopes are blocked by THIS
    /// reservation. Mutation-kind aware: a ProtectedBusiness reservation
    /// never blocks authorization reads regardless of its durable state, so
    /// the public contract cannot mislead gate builders into blanket blocking.
    pub fn blocks_positive_reads(&self) -> Result<bool, AuthorityProtocolError> {
        self.validate()?;
        Ok(self.state.blocks_positive_reads() && self.intent.mutation_kind.blocks_positive_reads())
    }
}

/// Summary returned inside the read gate for every blocking reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityReservationSummary {
    pub reservation_id: String,
    pub operation_id: String,
    pub mutation_kind: AuthorityMutationKind,
    pub state: AuthorityReservationState,
    pub coverage: AuthorityReservationCoverage,
    pub created_at: i64,
}

impl AuthorityReservationSummary {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        authority_text(&self.reservation_id, "reservation_id")?;
        authority_text(&self.operation_id, "operation_id")?;
        self.coverage.validate()?;
        authority_timestamp(self.created_at, "created_at")?;
        if !self.state.blocks_positive_reads() || !self.mutation_kind.blocks_positive_reads() {
            return Err(AuthorityProtocolError::InvalidText {
                field: "blocking_reservation",
            });
        }
        Ok(())
    }
}

/// The durable source commit acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySourceCommitRecord {
    pub reservation_id: String,
    pub operation_id: String,
    /// SHA-256 over the durable source commit evidence (receipt rows, digests).
    pub source_commit_digest: String,
    /// SHA-256 over the actual before-image of the affected rows, pinned by
    /// the source transaction (two-phase binding).
    pub before_image_digest: Option<String>,
    /// SHA-256 over the after-image produced by the source transaction.
    pub after_image_digest: String,
    /// Canonical digest of the durable source-outcome record (combined
    /// record + retained staged evidence) — the strong protocol binding to
    /// the exact committed DB evidence.
    pub source_outcome_digest: String,
    /// SHA-256 of the typed staged evidence JSON retained on the outcome row.
    pub staged_evidence_digest: String,
    pub committed_at: i64,
}

impl AuthoritySourceCommitRecord {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        authority_text(&self.reservation_id, "reservation_id")?;
        authority_text(&self.operation_id, "operation_id")?;
        authority_digest(&self.source_commit_digest, "source_commit_digest")?;
        if let Some(before_image_digest) = &self.before_image_digest {
            authority_digest(before_image_digest, "before_image_digest")?;
        }
        authority_digest(&self.after_image_digest, "after_image_digest")?;
        authority_digest(&self.source_outcome_digest, "source_outcome_digest")?;
        authority_digest(&self.staged_evidence_digest, "staged_evidence_digest")?;
        authority_timestamp(self.committed_at, "committed_at")?;
        Ok(())
    }
}

/// Reconciliation disposition for one reservation. `Unknown` is terminal for
/// the current attempt: callers reconcile by stable identity; nothing in the
/// protocol auto-retries an unknown outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityReservationDisposition {
    Pending,
    Reserved,
    Committed,
    Certified,
    Completed,
    Published,
    Aborted,
    Quarantined,
    NotFound,
    Unknown,
}

impl AuthorityReservationDisposition {
    /// Whether positive reads for the covered scopes are blocked. Pending and
    /// Unknown fail closed together with every non-terminal durable state.
    pub const fn blocks_positive_reads(self) -> bool {
        matches!(
            self,
            Self::Pending
                | Self::Unknown
                | Self::Reserved
                | Self::Committed
                | Self::Published
                | Self::Quarantined
        )
    }

    pub fn from_reservation(reservation: &AuthorityScopeReservation) -> Self {
        match reservation.state {
            AuthorityReservationState::Reserved => Self::Reserved,
            AuthorityReservationState::Committed => Self::Committed,
            AuthorityReservationState::Certified => Self::Certified,
            AuthorityReservationState::Completed => Self::Completed,
            AuthorityReservationState::Published => Self::Published,
            AuthorityReservationState::Aborted => Self::Aborted,
            AuthorityReservationState::Quarantined => Self::Quarantined,
        }
    }

    /// Stable uppercase text form (matches the serde representation).
    pub const fn as_text(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Reserved => "RESERVED",
            Self::Committed => "COMMITTED",
            Self::Certified => "CERTIFIED",
            Self::Completed => "COMPLETED",
            Self::Published => "PUBLISHED",
            Self::Aborted => "ABORTED",
            Self::Quarantined => "QUARANTINED",
            Self::NotFound => "NOT_FOUND",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Reconciliation result for one stable reservation identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityReconciliation {
    pub reservation_id: String,
    pub operation_id: String,
    pub disposition: AuthorityReservationDisposition,
    /// The reservation itself when a durable record was found.
    pub reservation: Option<AuthorityScopeReservation>,
}

impl AuthorityReconciliation {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        authority_text(&self.reservation_id, "reservation_id")?;
        authority_text(&self.operation_id, "operation_id")?;
        if let Some(reservation) = &self.reservation {
            reservation.validate()?;
            if reservation.reservation_id != self.reservation_id {
                return Err(AuthorityProtocolError::ScopeMismatch);
            }
            if reservation.intent.operation_id != self.operation_id
                || self.disposition
                    != AuthorityReservationDisposition::from_reservation(reservation)
            {
                return Err(AuthorityProtocolError::ScopeMismatch);
            }
        } else if !matches!(
            self.disposition,
            AuthorityReservationDisposition::NotFound
                | AuthorityReservationDisposition::Unknown
                | AuthorityReservationDisposition::Pending
        ) {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        Ok(())
    }
}

/// The fail-closed read gate returned with every read and mutation response.
///
/// `positive_reads_allowed` is the single authoritative signal: when false,
/// no positive authorization may be served for any covered scope. Pending and
/// unknown source operations always produce `false` here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityReadGate {
    pub positive_reads_allowed: bool,
    /// True when a reservation with GLOBAL coverage is active or unresolved.
    pub global_pending: bool,
    /// Every blocking reservation visible to this read.
    pub blocking_reservations: Vec<AuthorityReservationSummary>,
}

impl AuthorityReadGate {
    /// Canonical digest used when a signed capability binds the exact
    /// fail-closed barrier observed by the authority.
    pub fn digest(&self) -> Result<String, AuthorityProtocolError> {
        self.validate()?;
        let bytes =
            serde_json::to_vec(self).map_err(|_| AuthorityProtocolError::CanonicalSerialization)?;
        let mut canonical = Vec::with_capacity(64 + bytes.len());
        canonical.extend_from_slice(b"ASTRAL_AUTHORITY_READ_GATE_V1\0");
        authority_field(&mut canonical, &bytes.len().to_string());
        canonical.extend_from_slice(&bytes);
        Ok(super::authority_sha256_hex(&canonical))
    }

    /// The all-blocked gate used whenever the authority cannot prove safety.
    pub fn blocked() -> Self {
        Self {
            positive_reads_allowed: false,
            global_pending: true,
            blocking_reservations: Vec::new(),
        }
    }

    /// Derive the gate from the durable reservation set.
    pub fn evaluate(
        blocking_reservations: Vec<AuthorityReservationSummary>,
    ) -> Result<Self, AuthorityProtocolError> {
        let mut global_pending = false;
        for reservation in &blocking_reservations {
            reservation.validate()?;
            if reservation.coverage.is_global() {
                global_pending = true;
            }
        }
        Ok(Self {
            positive_reads_allowed: blocking_reservations.is_empty(),
            global_pending,
            blocking_reservations,
        })
    }

    /// Whether this gate blocks a scope identified by its canonical store
    /// key text (the durable receipt carries keys, not scope objects).
    /// Unknown/pending always blocks, as does any GLOBAL coverage reservation.
    pub fn blocks_scope_key(&self, scope_key_text: &str) -> Result<bool, AuthorityProtocolError> {
        self.validate()?;
        if self.positive_reads_allowed {
            return Ok(false);
        }
        for reservation in &self.blocking_reservations {
            match &reservation.coverage {
                AuthorityReservationCoverage::Global => return Ok(true),
                AuthorityReservationCoverage::Exact(scopes) => {
                    for scope in scopes {
                        if scope.store_key_text()? == scope_key_text {
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(self.global_pending)
    }

    /// Whether this gate blocks the given exact scope. Unknown/pending always
    /// blocks, as does any GLOBAL coverage reservation.
    pub fn blocks(&self, scope: &AuthorityProtocolScope) -> Result<bool, AuthorityProtocolError> {
        scope.validate()?;
        self.validate()?;
        if self.positive_reads_allowed {
            return Ok(false);
        }
        for reservation in &self.blocking_reservations {
            if reservation.coverage.covers(scope)? {
                return Ok(true);
            }
        }
        Ok(self.global_pending)
    }

    /// Whether positive reads for ANY user/domain lens of one card identity
    /// are blocked. Lens-closed by identity: any blocking reservation whose
    /// CARD coverage matches the `(tenant_id, card_id)` identity blocks every
    /// lens of the card (a lens-bearing declared key conservatively blocks the
    /// whole card). GLOBAL coverage blocks every card; ORG reservations never
    /// block a card identity. Unknown/pending always blocks.
    pub fn blocks_card(
        &self,
        tenant_id: i64,
        card_id: i64,
    ) -> Result<bool, AuthorityProtocolError> {
        self.validate()?;
        if self.positive_reads_allowed {
            return Ok(false);
        }
        for reservation in &self.blocking_reservations {
            match &reservation.coverage {
                AuthorityReservationCoverage::Global => return Ok(true),
                AuthorityReservationCoverage::Exact(scopes) => {
                    if scopes
                        .iter()
                        .any(|scope| scope.card_identity() == Some((tenant_id, card_id)))
                    {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(self.global_pending)
    }

    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        if self.positive_reads_allowed
            && (self.global_pending || !self.blocking_reservations.is_empty())
        {
            return Err(AuthorityProtocolError::InvalidText { field: "read_gate" });
        }
        if !self.positive_reads_allowed
            && self.blocking_reservations.is_empty()
            && !self.global_pending
        {
            // A blocked gate must state at least one reason. This keeps the
            // gate from silently becoming a blanket deny without provenance.
            return Err(AuthorityProtocolError::InvalidText { field: "read_gate" });
        }
        for reservation in &self.blocking_reservations {
            reservation.validate()?;
            if reservation.coverage.is_global() && !self.global_pending {
                return Err(AuthorityProtocolError::InvalidText { field: "read_gate" });
            }
        }
        Ok(())
    }
}

/// Typed staged coverage contract: the complete, finite affected-scope set
/// the trusted source declares for one reservation, serialized into the
/// staged evidence and digest-bound there.
///
/// Closure contract (V7 late coverage): the GLOBAL barrier itself never
/// shrinks mid-flight and the prepared intent never changes. A COMPLETE
/// finite coverage retained at COMMIT (the existing commit-coverage binding,
/// digest-tied to the durable source-outcome and staged-evidence records)
/// may drive AUTOMATIC closure only when the authority policy
/// `exact_scope_coverage_enabled` is enabled AND the committing source holds
/// the explicit operator-configured `commit_finite_coverage` allowed
/// operation, and only after EVERY declared scope is certified. Unknown,
/// incomplete or unapproved coverage (`None`) keeps the operator-authorized
/// close as the only barrier-clearing path.
///
/// Typed envelope for the staged evidence retained on the outcome row: the
/// REAL actual source/delta/outbox evidence stays verbatim in `evidence`
/// (opaque bounded JSON), while `coverage` is the optional declared
/// affected-scope contract. `coverage: None` means the selector could not
/// prove a complete finite set (unknown GLOBAL stays pending/operator) or
/// the mutation kind needs no publication coverage (ProtectedBusiness).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityStagedSourceEvidence {
    pub coverage: Option<AuthorityStagedScopeCoverage>,
    pub evidence: serde_json::Value,
}

impl AuthorityStagedSourceEvidence {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        let encoded = serde_json::to_vec(&self.evidence)
            .map_err(|_| AuthorityProtocolError::CanonicalSerialization)?;
        if encoded.len() > 256 * 1024 {
            return Err(AuthorityProtocolError::InvalidText { field: "evidence" });
        }
        if let Some(coverage) = &self.coverage {
            coverage.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityStagedScopeCoverage {
    pub scopes: Vec<AuthorityProtocolScope>,
}

impl AuthorityStagedScopeCoverage {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        if self.scopes.is_empty() || self.scopes.len() > 256 {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }
        let mut keys = std::collections::HashSet::with_capacity(self.scopes.len());
        for scope in &self.scopes {
            if !keys.insert(scope.store_key_text()?) {
                return Err(AuthorityProtocolError::InvalidCoverage);
            }
        }
        Ok(())
    }

    /// Canonical digest over the declared set (order-independent via sorting
    /// the injective store keys).
    pub fn coverage_digest(&self) -> Result<String, AuthorityProtocolError> {
        self.validate()?;
        let mut keys: Vec<String> = self
            .scopes
            .iter()
            .map(|scope| scope.store_key_text())
            .collect::<Result<_, _>>()?;
        keys.sort();
        keys.dedup();
        if keys.len() != self.scopes.len() {
            return Err(AuthorityProtocolError::InvalidCoverage);
        }
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(b"ASTRAL_AUTHORITY_STAGED_COVERAGE_V1\0");
        authority_field(&mut bytes, &keys.len().to_string());
        for key in &keys {
            authority_field(&mut bytes, key);
        }
        Ok(super::authority_sha256_hex(&bytes))
    }

    /// Whether the declared set covers the given scope.
    pub fn covers(&self, scope: &AuthorityProtocolScope) -> Result<bool, AuthorityProtocolError> {
        self.validate()?;
        Ok(self.scopes.contains(scope))
    }
}

/// Exact binding echoed by every commit/reconcile response: the full
/// request/event/proof/kind/owner/digest set, verified by the client against
/// its own records — never a bare disposition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityCommitBinding {
    pub reservation_id: String,
    pub operation_id: String,
    pub event_id: String,
    pub admission_proof_id: String,
    pub mutation_kind: AuthorityMutationKind,
    pub service_id: String,
    pub database_id: String,
    pub request_digest: String,
    pub source_commit_digest: String,
    pub before_image_digest: Option<String>,
    pub after_image_digest: String,
    pub source_outcome_digest: String,
    pub staged_evidence_digest: String,
}

impl AuthorityCommitBinding {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        authority_text(&self.reservation_id, "reservation_id")?;
        authority_text(&self.operation_id, "operation_id")?;
        authority_text(&self.event_id, "event_id")?;
        authority_text(&self.admission_proof_id, "admission_proof_id")?;
        authority_text(&self.service_id, "service_id")?;
        authority_text(&self.database_id, "database_id")?;
        authority_digest(&self.request_digest, "request_digest")?;
        authority_digest(&self.source_commit_digest, "source_commit_digest")?;
        if let Some(before_image_digest) = &self.before_image_digest {
            authority_digest(before_image_digest, "before_image_digest")?;
        }
        authority_digest(&self.after_image_digest, "after_image_digest")?;
        authority_digest(&self.source_outcome_digest, "source_outcome_digest")?;
        authority_digest(&self.staged_evidence_digest, "staged_evidence_digest")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card_scope() -> AuthorityProtocolScope {
        AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
            tenant_id: 7,
            card_id: 17,
            user_id: Some(23),
            domain: AuthorizationDomainScope::Exact(31),
        })
    }

    fn intent(coverage: AuthorityReservationCoverage) -> AuthoritySourceIntent {
        AuthoritySourceIntent {
            authorization_edition: AUTHORIZATION_EDITION,
            mutation_kind: AuthorityMutationKind::AuthorizationSource,
            operation_id: "operation-1".to_owned(),
            event_id: "event-1".to_owned(),
            admission_proof_id: "proof-1".to_owned(),
            request_digest: "ab".repeat(32),
            service_id: "astral-db-primary".to_owned(),
            database_id: "db-1".to_owned(),
            coverage,
            before_image_digest: Some("cd".repeat(32)),
            lease_not_before: 1_000,
            lease_expires_at: 2_000,
            intent_nonce: "intent-nonce-1".to_owned(),
        }
    }

    #[test]
    fn coverage_wire_roundtrip_is_exact_and_rejects_duplicate_scopes() {
        let coverage = AuthorityReservationCoverage::Exact(vec![card_scope()]);
        let encoded = serde_json::to_value(&coverage).unwrap();
        assert_eq!(encoded["mode"], "EXACT");
        assert_eq!(encoded["scopes"].as_array().unwrap().len(), 1);
        assert_eq!(
            serde_json::from_value::<AuthorityReservationCoverage>(encoded).unwrap(),
            coverage
        );
        assert_eq!(
            serde_json::to_value(AuthorityReservationCoverage::Global).unwrap(),
            serde_json::json!({"mode": "GLOBAL"})
        );
        assert!(
            AuthorityReservationCoverage::Exact(vec![card_scope(), card_scope()])
                .validate()
                .is_err()
        );
        assert!(AuthorityStagedScopeCoverage {
            scopes: vec![card_scope(), card_scope()]
        }
        .validate()
        .is_err());
    }

    #[test]
    fn generic_scope_is_injective_across_kinds() {
        let card = card_scope();
        let org = AuthorityProtocolScope::Org(AuthorityOrgScope {
            tenant_id: 7,
            root_tenant_id: Some(1),
            member: AuthorityOrgMemberSubject {
                user_id: 1,
                identity_card_id: 2,
                card_id: 3,
            },
        });
        assert!(card
            .store_key_text()
            .unwrap()
            .starts_with("CARD:7:17:23:EXACT:31"));
        assert_eq!(org.store_key_text().unwrap(), "ORG:7:1:1:2:3");
        assert_ne!(
            card.store_key_text().unwrap(),
            org.store_key_text().unwrap()
        );
    }

    #[test]
    fn intent_digest_binds_all_fields_and_rejects_tampering() {
        let base = intent(AuthorityReservationCoverage::Global);
        let digest = base.digest().unwrap();
        assert_eq!(digest, base.digest().unwrap());
        let mut other = base.clone();
        other.request_digest = "ef".repeat(32);
        assert_ne!(digest, other.digest().unwrap());

        let mut expired = base.clone();
        expired.lease_not_before = 2_000;
        expired.lease_expires_at = 1_000;
        assert!(matches!(
            expired.validate(),
            Err(AuthorityProtocolError::InvalidTimeWindow)
        ));

        let mut empty_exact = intent(AuthorityReservationCoverage::Exact(Vec::new()));
        empty_exact.intent_nonce = "intent-nonce-2".to_owned();
        assert!(matches!(
            empty_exact.validate(),
            Err(AuthorityProtocolError::InvalidCoverage)
        ));
        // Multi-scope EXACT is valid since the automatic-closure amendment:
        // the declared finite set is bound at prepare and tracked per scope.
        let mut multi_exact = intent(AuthorityReservationCoverage::Exact(vec![
            card_scope(),
            AuthorityProtocolScope::Org(AuthorityOrgScope {
                tenant_id: 9,
                root_tenant_id: None,
                member: AuthorityOrgMemberSubject {
                    user_id: 1,
                    identity_card_id: 2,
                    card_id: 3,
                },
            }),
        ]));
        multi_exact.intent_nonce = "intent-nonce-5".to_owned();
        assert!(multi_exact.validate().is_ok());
    }

    #[test]
    fn coverage_blocking_semantics_are_explicit() {
        let global = AuthorityReservationCoverage::Global;
        assert!(global.covers(&card_scope()).unwrap());
        assert!(global.is_global());

        let exact = AuthorityReservationCoverage::Exact(vec![card_scope()]);
        assert!(exact.covers(&card_scope()).unwrap());
        let org = AuthorityProtocolScope::Org(AuthorityOrgScope {
            tenant_id: 9,
            root_tenant_id: None,
            member: AuthorityOrgMemberSubject {
                user_id: 1,
                identity_card_id: 2,
                card_id: 3,
            },
        });
        assert!(!exact.covers(&org).unwrap());
        assert!(global.is_global());
    }

    #[test]
    fn reservation_states_block_fail_closed_and_expiry_never_clears() {
        for (state, blocks) in [
            (AuthorityReservationState::Reserved, true),
            (AuthorityReservationState::Committed, true),
            (AuthorityReservationState::Published, true),
            (AuthorityReservationState::Quarantined, true),
            (AuthorityReservationState::Certified, false),
            (AuthorityReservationState::Aborted, false),
        ] {
            assert_eq!(state.blocks_positive_reads(), blocks);
        }
        assert!(AuthorityReservationDisposition::Unknown.blocks_positive_reads());
        assert!(AuthorityReservationDisposition::Pending.blocks_positive_reads());
        assert!(AuthorityReservationDisposition::Published.blocks_positive_reads());
        assert!(!AuthorityReservationDisposition::Aborted.blocks_positive_reads());
        assert_eq!(
            AuthorityReservationState::parse("RESERVED"),
            Some(AuthorityReservationState::Reserved)
        );
        assert_eq!(AuthorityReservationState::parse("EXPIRED"), None);
    }

    #[test]
    fn reservation_blocking_is_mutation_kind_aware() {
        fn reservation(
            state: AuthorityReservationState,
            kind: AuthorityMutationKind,
        ) -> AuthorityScopeReservation {
            AuthorityScopeReservation {
                reservation_id: "res-1".to_owned(),
                intent_digest: "ab".repeat(32),
                intent: AuthoritySourceIntent {
                    authorization_edition: AUTHORIZATION_EDITION,
                    mutation_kind: kind,
                    operation_id: "operation-1".to_owned(),
                    event_id: "event-1".to_owned(),
                    admission_proof_id: "proof-1".to_owned(),
                    request_digest: "bb".repeat(32),
                    service_id: "source-svc".to_owned(),
                    database_id: "db-1".to_owned(),
                    coverage: AuthorityReservationCoverage::Global,
                    before_image_digest: None,
                    lease_not_before: 1_000,
                    lease_expires_at: 2_000,
                    intent_nonce: "nonce-1".to_owned(),
                },
                state,
                authority_term: 1,
                fence_sequence_at_prepare: 1,
                created_at: 1_000,
                updated_at: 1_000,
                committed_at: None,
                source_commit_digest: None,
                after_image_digest: None,
                certificate_id: None,
                certified_scopes: Vec::new(),
                source_outcome_digest: None,
            }
        }

        // ProtectedBusiness never blocks, in any state.
        for state in [
            AuthorityReservationState::Reserved,
            AuthorityReservationState::Committed,
            AuthorityReservationState::Quarantined,
        ] {
            assert!(
                !reservation(state, AuthorityMutationKind::ProtectedBusiness)
                    .blocks_positive_reads()
                    .unwrap()
            );
        }
        // AuthorizationSource blocks in every non-terminal state, incl. PUBLISHED.
        for (state, blocks) in [
            (AuthorityReservationState::Reserved, true),
            (AuthorityReservationState::Committed, true),
            (AuthorityReservationState::Published, true),
            (AuthorityReservationState::Quarantined, true),
            (AuthorityReservationState::Certified, false),
            (AuthorityReservationState::Aborted, false),
        ] {
            assert_eq!(
                reservation(state, AuthorityMutationKind::AuthorizationSource)
                    .blocks_positive_reads()
                    .unwrap(),
                blocks
            );
        }
    }

    #[test]
    fn positive_read_gate_cannot_hide_pending_reservations() {
        let scope = card_scope();
        let mut gate = AuthorityReadGate::blocked();
        gate.positive_reads_allowed = true;
        assert!(gate.validate().is_err());
        assert!(gate.blocks(&scope).is_err());
        assert!(gate
            .blocks_scope_key(&scope.store_key_text().unwrap())
            .is_err());
        gate.global_pending = false;
        gate.blocking_reservations
            .push(AuthorityReservationSummary {
                reservation_id: "reservation".into(),
                operation_id: "operation".into(),
                mutation_kind: AuthorityMutationKind::AuthorizationSource,
                state: AuthorityReservationState::Reserved,
                coverage: AuthorityReservationCoverage::Exact(vec![scope.clone()]),
                created_at: 1_000,
            });
        assert!(gate.validate().is_err());
        assert!(gate.blocks(&scope).is_err());
        gate.positive_reads_allowed = false;
        assert!(gate.validate().is_ok());
        assert!(gate.blocks(&scope).unwrap());
        gate.blocking_reservations.clear();
        assert!(gate.validate().is_err());
    }

    #[test]
    fn read_gate_rejects_nonblocking_and_unmarked_global_summaries() {
        let summary = AuthorityReservationSummary {
            reservation_id: "reservation".into(),
            operation_id: "operation".into(),
            mutation_kind: AuthorityMutationKind::AuthorizationSource,
            state: AuthorityReservationState::Reserved,
            coverage: AuthorityReservationCoverage::Global,
            created_at: 1_000,
        };
        let mut gate = AuthorityReadGate::evaluate(vec![summary]).unwrap();
        gate.global_pending = false;
        assert!(gate.validate().is_err());
        gate.global_pending = true;
        gate.blocking_reservations[0].state = AuthorityReservationState::Certified;
        assert!(gate.validate().is_err());
        gate.blocking_reservations[0].state = AuthorityReservationState::Reserved;
        gate.blocking_reservations[0].mutation_kind = AuthorityMutationKind::ProtectedBusiness;
        assert!(gate.validate().is_err());
    }

    #[test]
    fn reconciliation_without_record_cannot_claim_a_durable_terminal_state() {
        for disposition in [
            AuthorityReservationDisposition::Committed,
            AuthorityReservationDisposition::Published,
            AuthorityReservationDisposition::Certified,
            AuthorityReservationDisposition::Reserved,
            AuthorityReservationDisposition::Aborted,
        ] {
            let result = AuthorityReconciliation {
                reservation_id: "reservation".into(),
                operation_id: "operation".into(),
                disposition,
                reservation: None,
            };
            assert!(result.validate().is_err());
        }
    }

    #[test]
    fn acceptance_signature_binds_reservation_and_frontier() {
        let signing = SigningKey::from_bytes(&[5; 32]);
        let mut acceptance = AuthorityIntentAcceptance {
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "authority-1".to_owned(),
            intent_digest: "ab".repeat(32),
            reservation_id: "reservation-1".to_owned(),
            authority_term: 1,
            global_fence_sequence: 4,
            key_id: "signer-1".to_owned(),
            key_epoch: 1,
            accepted_at: 1_500,
            acceptance_nonce: "accept-nonce-1".to_owned(),
            signature: String::new(),
        };
        acceptance.sign_with(&signing).unwrap();
        acceptance.verify(&signing.verifying_key()).unwrap();

        let mut tampered = acceptance.clone();
        tampered.global_fence_sequence = 5;
        assert!(matches!(
            tampered.verify(&signing.verifying_key()),
            Err(AuthorityProtocolError::InvalidSignature)
        ));
    }

    fn org_scope() -> AuthorityProtocolScope {
        AuthorityProtocolScope::Org(AuthorityOrgScope {
            tenant_id: 9,
            root_tenant_id: None,
            member: AuthorityOrgMemberSubject {
                user_id: 1,
                identity_card_id: 2,
                card_id: 3,
            },
        })
    }

    fn canonical_card() -> AuthorityProtocolScope {
        AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
            tenant_id: 7,
            card_id: 17,
            user_id: None,
            domain: AuthorizationDomainScope::Any,
        })
    }

    #[test]
    fn canonical_card_publication_scope_drops_the_lens() {
        let canonical = card_scope().canonical_card_publication_scope().unwrap();
        assert_eq!(canonical, canonical_card());
        // Canonicalization is idempotent.
        assert_eq!(
            canonical.canonical_card_publication_scope().unwrap(),
            canonical
        );
        assert_eq!(canonical_card().card_identity(), Some((7, 17)));
        // ORG scopes have no canonical card form and no card identity.
        assert_eq!(org_scope().canonical_card_publication_scope(), None);
        assert_eq!(org_scope().card_identity(), None);
    }

    #[test]
    fn card_coverage_is_lens_closed_by_identity_not_prefix() {
        // Same card identity across any lens combination blocks both ways.
        assert!(canonical_card().covers_same_card(&card_scope()));
        assert!(card_scope().covers_same_card(&canonical_card()));
        let other_card = AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
            tenant_id: 7,
            card_id: 18,
            user_id: None,
            domain: AuthorizationDomainScope::Any,
        });
        let other_tenant = AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
            tenant_id: 8,
            card_id: 17,
            user_id: None,
            domain: AuthorizationDomainScope::Any,
        });
        assert!(!canonical_card().covers_same_card(&other_card));
        assert!(!canonical_card().covers_same_card(&other_tenant));
        // ORG scopes never cover a card identity.
        assert!(!canonical_card().covers_same_card(&org_scope()));

        // A lens-bearing declared key conservatively blocks the whole card.
        let exact_lensed = AuthorityReservationCoverage::Exact(vec![card_scope()]);
        assert!(exact_lensed.covers(&card_scope()).unwrap());
        assert!(exact_lensed.covers(&canonical_card()).unwrap());
        assert!(!exact_lensed.covers(&other_card).unwrap());
        assert!(!exact_lensed.covers(&org_scope()).unwrap());
        // A card-level declared key blocks every lens of the card.
        let exact_canonical = AuthorityReservationCoverage::Exact(vec![canonical_card()]);
        assert!(exact_canonical.covers(&card_scope()).unwrap());
        assert!(exact_canonical.covers(&canonical_card()).unwrap());
    }

    #[test]
    fn read_gate_blocks_every_lens_of_one_card_without_prefix_matching() {
        let gate = AuthorityReadGate::evaluate(vec![AuthorityReservationSummary {
            reservation_id: "res-1".to_owned(),
            operation_id: "operation-1".to_owned(),
            mutation_kind: AuthorityMutationKind::AuthorizationSource,
            state: AuthorityReservationState::Reserved,
            coverage: AuthorityReservationCoverage::Exact(vec![card_scope()]),
            created_at: 1_000,
        }])
        .unwrap();
        // Every lens of the declared card is blocked; other cards/tenants and
        // ORG scopes are not.
        assert!(gate.blocks_card(7, 17).unwrap());
        assert!(gate.blocks(&card_scope()).unwrap());
        assert!(gate.blocks(&canonical_card()).unwrap());
        assert!(!gate.blocks_card(7, 18).unwrap());
        assert!(!gate.blocks_card(8, 17).unwrap());
        assert!(!gate.blocks(&org_scope()).unwrap());

        // Global coverage blocks every card identity.
        let global = AuthorityReadGate::evaluate(vec![AuthorityReservationSummary {
            reservation_id: "res-global".to_owned(),
            operation_id: "operation-global".to_owned(),
            mutation_kind: AuthorityMutationKind::AuthorizationSource,
            state: AuthorityReservationState::Reserved,
            coverage: AuthorityReservationCoverage::Global,
            created_at: 1_000,
        }])
        .unwrap();
        assert!(global.blocks_card(7, 17).unwrap());
        assert!(global.blocks_card(9, 9).unwrap());

        // Open gate never blocks any card identity.
        let open = AuthorityReadGate::evaluate(Vec::new()).unwrap();
        assert!(!open.blocks_card(7, 17).unwrap());
    }
}
