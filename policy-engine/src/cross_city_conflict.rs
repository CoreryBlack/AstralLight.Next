//! Rejection-only cross-city conflict arbiter boundary (stage 1, pure).
//!
//! # Security boundary (read before any caller wiring)
//!
//! This module resolves ONE question only: given a [`MutationProposal`] and exactly
//! two [`CityVoteCertificate`]s, is there a *definite, machine-provable conflict*
//! between them, or can no such conflict be proven right now? It is deliberately
//! three things at once and none of the things below:
//!
//! - **It is NOT PolicyEngine authorization.** The outcome can only be
//!   [`CrossCityConflictOutcome::Reject`] or [`CrossCityConflictOutcome::Defer`];
//!   there is no allow path by construction. A structurally consistent, fully
//!   consistent pair still returns `DEFER` with
//!   [`CrossCityConflictReason::ArbiterAllowOutOfScope`], because approving a
//!   cross-city operation belongs exclusively to the cross-city agreement path
//!   (`astral_types::CrossCityAgreementCertificate` plus its future durable
//!   coordinator). This component can never approve.
//! - **It is NOT a vote certificate issuer.** Certificates are never created,
//!   stored, or returned here. `CrossCityAgreementCertificate::reach` is used
//!   strictly as a validation oracle; its output is discarded and its success maps
//!   to `DEFER`, never to approval.
//! - **It is NOT cryptographic signature verification.** Signature blobs are only
//!   format-checked (opaque bytes with sane bounds). Every caller MUST verify node
//!   evidence signatures through the separate astral-common cross-city signature
//!   capability (Ed25519 verification over the certificate's evidence digests)
//!   BEFORE persisting anything or reusing any certificate in an authorization
//!   path. This module's verdicts alone must never gate persistence.
//!
//! Operationally: this module is a pure function with **no I/O of any kind** — no
//! network, database, cache, filesystem, process, thread, or global state. It
//! cannot write source data, L3/L1/L2 layers, projections, or any durable state,
//! and it emits no messages. Its result type carries only closed-enum data, so it
//! is safe for audit/metrics rendering: no caller-supplied string can leak into
//! `Debug`/`Display` output.
//!
//! The canonical outcome/reason enums are shared contract types owned by
//! `astral_types::cross_city` and are re-exported here unchanged, so existing
//! callers keep compiling with the same names. This module additionally offers
//! ONE pure mapping, [`build_cross_city_conflict_audit_record`], from a resolved
//! verdict onto the shared closed `astral_types::CrossCityConflictAuditRecord`
//! (retry-stable `event_id`, copied canonical proposal fields, no free-form
//! text). The mapping performs no I/O and adds no runtime caller: persisting
//! audit records is a LATER batch, whose durable writer must use a NEW
//! append-only idempotent table keyed by `event_id` — never `audit_log`,
//! `operation.last_error`, the vote tables, or the outbox — and must not map an
//! arbiter `DEFER` to `CrossCityOperationState::Deferred` or a `REJECT` to any
//! coordinator state transition in this batch.
//!
//! # Verdict rules (fail-closed)
//!
//! | Situation | Verdict | Reason code |
//! |-----------|---------|-------------|
//! | No city vote certificates supplied | `DEFER` | `EVIDENCE_MISSING` |
//! | Vote count is not exactly two | `DEFER` | `EVIDENCE_COUNT_INVALID` |
//! | Proposal malformed or not presentable in canonical form (as received, never repaired) | `DEFER` | `EVIDENCE_UNVERIFIABLE` |
//! | Proposal or a vote expired at the caller-supplied time | `DEFER` | `EVIDENCE_EXPIRED` |
//! | Structural validation otherwise unprovable / unknown contract error | `DEFER` | `EVIDENCE_UNVERIFIABLE` |
//! | Vote `operation_id` disagrees with the proposal | `REJECT` | `OPERATION_MISMATCH` |
//! | Vote `proposal_digest` (binding scope/request/generation content) disagrees | `REJECT` | `SCOPE_MISMATCH` |
//! | Vote `frontier_digest` disagrees with the proposal's base frontier | `REJECT` | `FRONTIER_MISMATCH` |
//! | Vote `mutation_digest` disagrees with the proposal | `REJECT` | `MUTATION_MISMATCH` |
//! | Vote `expires_at` disagrees with the proposal's expiry binding | `REJECT` | `EXPIRY_MISMATCH` |
//! | Recorded decision content conflicts with the vote context (reserved; allow-only by construction) | `REJECT` | `DECISION_MISMATCH` |
//! | Node identity invalid or one node attested twice | `REJECT` | `NODE_IDENTITY_INVALID` |
//! | Both votes claim the same city identity | `REJECT` | `CITY_IDENTITY_DUPLICATE` |
//! | Vote signature blob malformed | `REJECT` | `SIGNATURE_INVALID` |
//! | Vote certificate fails integrity/canonical-form proof (tampered or not issuably formed) | `REJECT` | `CERTIFICATE_INVALID` |
//! | Structurally consistent pair | `DEFER` | `ARBITER_ALLOW_OUT_OF_SCOPE` |
//!
//! Documented fail-closed decisions (stage-1 policy, kept conservative):
//!
//! - **Proposal vs. evidence asymmetry.** The proposal is the arbitrated request,
//!   not node evidence: a malformed or non-canonical proposal leaves the binding
//!   target unprovable, so it `DEFER`s (`EVIDENCE_UNVERIFIABLE` is never upgraded
//!   to a rejection). Vote certificates ARE evidence: one that fails structural
//!   integrity, canonical-form proof, or carries malformed identity/signature
//!   fields is provably not a certificate the issuing contract could have
//!   produced — a definite conflict — and therefore `REJECT`s.
//! - **Time staleness precedes content judgment.** Expired inputs are judged
//!   `EVIDENCE_EXPIRED` → `DEFER` before binding comparisons, because stale
//!   evidence is untrusted to decide anything (even a rejection). Content
//!   integrity (tampering) precedes time staleness within a single vote: a
//!   tampered vote is rejected even if it is also expired.
//! - **Evidence integrity precedes binding comparison.** Both votes are proven
//!   intact and canonical before any binding disagreement is reported, so a
//!   reason code always describes conflict on top of structurally valid evidence.
//! - **Unknown never rejects by default.** Contract error variants that are not
//!   explicitly classifiable (including variants added to
//!   `CrossCityContractError` in the future) map to `EVIDENCE_UNVERIFIABLE` →
//!   `DEFER`. Only explicit, known conflicts ever `REJECT`.

use astral_types::{
    CityVoteCertificate, CrossCityAgreementCertificate, CrossCityConflictAuditError,
    CrossCityConflictAuditRecord, CrossCityContractError, MutationProposal, CROSS_CITY_CITY_COUNT,
};

/// The shared, closed conflict-outcome and reason-code contract types.
///
/// These canonical enums are owned by `astral_types::cross_city` (the shared
/// contract owner, where audit records can bind them) and are re-exported here
/// unchanged, so existing policy-engine callers and tests keep compiling with
/// the same names and identical `as_str`/`ALL`/`outcome` semantics. Neither
/// type is widened here, and neither gains an allow variant.
pub use astral_types::{CrossCityConflictOutcome, CrossCityConflictReason};

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// Typed, secret-free, caller-safe result of the conflict resolution.
///
/// Contains only closed-enum data: the outcome and the stable machine reason
/// code. There is no free-form reason string by design, so no caller-controlled
/// input can ever reach `Debug`, `Display`, or an audit pipeline through this
/// type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CrossCityConflictResolution {
    /// Verdict: `REJECT` or `DEFER` - never an approval.
    outcome: CrossCityConflictOutcome,
    /// Stable machine reason code; always consistent with `outcome`.
    reason: CrossCityConflictReason,
}

impl CrossCityConflictResolution {
    /// Build a resolution from a reason code. The outcome is derived from the
    /// reason via [`CrossCityConflictReason::outcome`], so the pair is always
    /// consistent by construction.
    pub const fn from_reason(reason: CrossCityConflictReason) -> Self {
        Self {
            outcome: reason.outcome(),
            reason,
        }
    }

    /// The closed conflict outcome.
    pub const fn outcome(&self) -> CrossCityConflictOutcome {
        self.outcome
    }

    /// The closed reason code explaining the outcome.
    pub const fn reason(&self) -> CrossCityConflictReason {
        self.reason
    }

    /// Stable machine reason code (convenience for audit/metrics call sites).
    pub const fn reason_code(&self) -> &'static str {
        self.reason.as_str()
    }
}

/// Single construction point for every verdict produced below.
fn decide(reason: CrossCityConflictReason) -> CrossCityConflictResolution {
    CrossCityConflictResolution::from_reason(reason)
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

/// Classify one vote-level cross-city contract error into the closed reason set.
///
/// Fail-closed default: anything not explicitly classifiable — including variants
/// added to `CrossCityContractError` later — maps to
/// [`CrossCityConflictReason::EvidenceUnverifiable`] (defer), never to a
/// rejection and never to approval.
fn classify_vote_contract_error(error: &CrossCityContractError) -> CrossCityConflictReason {
    use CrossCityConflictReason as Reason;

    match error {
        // Time staleness is never a content conflict.
        CrossCityContractError::Expired { .. } => Reason::EvidenceExpired,
        // Definite identity conflicts.
        CrossCityContractError::DuplicateNode { .. }
        | CrossCityContractError::CityMismatch { .. } => Reason::NodeIdentityInvalid,
        CrossCityContractError::DuplicateCity { .. } => Reason::CityIdentityDuplicate,
        CrossCityContractError::DecisionNotAllow { .. } => Reason::DecisionMismatch,
        // Definite evidence-integrity conflicts: the certificate as received is
        // not one the issuing contract could have produced.
        CrossCityContractError::NonCanonicalForm { .. }
        | CrossCityContractError::DigestMismatch { .. }
        | CrossCityContractError::EvidenceCountMismatch { .. } => Reason::CertificateInvalid,
        CrossCityContractError::CityVoteCountMismatch { .. } => Reason::EvidenceCountInvalid,
        // Field-scoped identity/signature violations.
        CrossCityContractError::EmptyIdentifier { field: "signature" }
        | CrossCityContractError::MalformedIdentifier { field: "signature" }
        | CrossCityContractError::IdentifierTooLong { field: "signature" } => {
            Reason::SignatureInvalid
        }
        CrossCityContractError::EmptyIdentifier { field: "node_id" }
        | CrossCityContractError::MalformedIdentifier { field: "node_id" }
        | CrossCityContractError::IdentifierTooLong { field: "node_id" } => {
            Reason::NodeIdentityInvalid
        }
        // Explicit binding disagreements. The resolver detects these directly
        // before classification; the mapping is kept complete so the classifier
        // stays correct if reused for contract-level diagnostics.
        CrossCityContractError::FieldMismatch {
            field: "operation_id",
            ..
        } => Reason::OperationMismatch,
        CrossCityContractError::FieldMismatch {
            field: "proposal_digest",
            ..
        } => Reason::ScopeMismatch,
        CrossCityContractError::FieldMismatch {
            field: "frontier_digest",
            ..
        } => Reason::FrontierMismatch,
        CrossCityContractError::FieldMismatch {
            field: "mutation_digest",
            ..
        } => Reason::MutationMismatch,
        CrossCityContractError::FieldMismatch {
            field: "expires_at",
            ..
        } => Reason::ExpiryMismatch,
        // Every remaining structural violation proves the vote is not a
        // certificate the issuing contract could have produced.
        CrossCityContractError::EmptyIdentifier { .. }
        | CrossCityContractError::MalformedIdentifier { .. }
        | CrossCityContractError::IdentifierTooLong { .. }
        | CrossCityContractError::InvalidDigest { .. }
        | CrossCityContractError::InvalidOperationId { .. }
        | CrossCityContractError::NilOperationId { .. }
        | CrossCityContractError::NonPositiveNumber { .. }
        | CrossCityContractError::InvalidExpiry { .. } => Reason::CertificateInvalid,
        // Unknown or not applicable at vote level: fail closed with DEFER.
        _ => Reason::EvidenceUnverifiable,
    }
}

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

/// Resolve the rejection-only cross-city conflict for one proposal and exactly
/// two city vote certificates, evaluated at the caller-supplied time.
///
/// Inputs are judged **exactly as received** — nothing is canonicalized, trimmed,
/// or repaired — and the result is deterministic. The full verdict table is in
/// the module docs; the hard guarantees are:
///
/// - missing or wrong vote count → `DEFER`;
/// - expired proposal or vote → `DEFER`, no panic;
/// - exact disagreement on `operation_id`, proposal digest (scope binding),
///   frontier digest, mutation digest, or expiry binding → `REJECT`;
/// - two votes from one city → `REJECT`;
/// - malformed/tampered/non-canonical vote evidence → `REJECT`;
/// - a fully consistent pair → `DEFER` with `ARBITER_ALLOW_OUT_OF_SCOPE`
///   (this component can never approve);
/// - no input, under any circumstance, produces an approval result.
pub fn resolve_cross_city_conflict(
    proposal: &MutationProposal,
    city_votes: &[CityVoteCertificate],
    now_seconds: i64,
) -> CrossCityConflictResolution {
    // Stage 1 — vote count. Missing evidence can never decide anything, and no
    // pair size other than exactly two is arbitral.
    if city_votes.is_empty() {
        return decide(CrossCityConflictReason::EvidenceMissing);
    }
    if city_votes.len() != CROSS_CITY_CITY_COUNT {
        return decide(CrossCityConflictReason::EvidenceCountInvalid);
    }

    // Stage 2 — the proposal is validated as received and proven presentable in
    // canonical form. The canonical value is used ONLY for this equality proof:
    // it is never substituted for the input, and a proposal that is not exactly
    // its own canonical form defers without repair.
    let canonical_proposal = match proposal.canonicalized() {
        Ok(canonical) => canonical,
        Err(_) => return decide(CrossCityConflictReason::EvidenceUnverifiable),
    };
    if canonical_proposal != *proposal {
        return decide(CrossCityConflictReason::EvidenceUnverifiable);
    }

    // Stage 3 — time staleness of the proposal defers before any content
    // judgment: expired requests are pending, not conflicting.
    if proposal.is_expired_at(now_seconds) {
        return decide(CrossCityConflictReason::EvidenceExpired);
    }

    // Stage 4 — per-vote, as-received validation: structural integrity, strict
    // canonical-form proof, then time staleness. Evidence must be intact before
    // its content is judged, and staleness defers before binding comparisons.
    for vote in city_votes {
        if let Err(error) = vote.validate() {
            return decide(classify_vote_contract_error(&error));
        }
        if !vote.is_canonical() {
            return decide(CrossCityConflictReason::CertificateInvalid);
        }
        if vote.is_expired_at(now_seconds) {
            return decide(CrossCityConflictReason::EvidenceExpired);
        }
    }

    // Stage 5 — distinct city identity: two spellings of one city can never
    // count as two cities (canonical-form proof above keeps the spellings
    // exact, so byte equality here is the decisive check).
    if city_votes[0].city_id == city_votes[1].city_id {
        return decide(CrossCityConflictReason::CityIdentityDuplicate);
    }

    // Stage 6 — exact binding comparisons against the as-received proposal (which
    // stage 2 proved canonical, so as-received equals canonical here). The
    // proposal digest is the contract's own domain-separated digest — it pins the
    // full proposal content (scope, request, generations, versions), so any
    // disagreement is a definite scope conflict.
    let proposal_digest = match proposal.proposal_digest() {
        Ok(digest) => digest,
        Err(_) => return decide(CrossCityConflictReason::EvidenceUnverifiable),
    };
    for vote in city_votes {
        if vote.operation_id != proposal.operation_id {
            return decide(CrossCityConflictReason::OperationMismatch);
        }
        if vote.frontier_digest != proposal.base_frontier_digest {
            return decide(CrossCityConflictReason::FrontierMismatch);
        }
        if vote.mutation_digest != proposal.mutation_digest {
            return decide(CrossCityConflictReason::MutationMismatch);
        }
        if vote.expires_at != proposal.expires_at {
            return decide(CrossCityConflictReason::ExpiryMismatch);
        }
        if vote.proposal_digest != proposal_digest {
            return decide(CrossCityConflictReason::ScopeMismatch);
        }
    }

    // Stage 7 — contract-level consistency oracle. `reach` re-proves the whole
    // chain under the issuing contract's own rules. It is used STRICTLY as a
    // validation oracle: the produced agreement value is discarded, and success
    // still maps to DEFER, because this component can never approve.
    if CrossCityAgreementCertificate::reach(proposal, city_votes, now_seconds).is_ok() {
        return decide(CrossCityConflictReason::ArbiterAllowOutOfScope);
    }
    // Defensive drift guard: every check above mirrors the contract, so reaching
    // this line means an unclassified disagreement surfaced after all explicit
    // checks passed. Fail closed with DEFER — never a rejection guess, never an
    // approval.
    decide(CrossCityConflictReason::EvidenceUnverifiable)
}

// ---------------------------------------------------------------------------
// Conflict-audit record mapping (pure, contract-only)
// ---------------------------------------------------------------------------

/// Map an already-resolved conflict verdict onto the shared, closed
/// [`CrossCityConflictAuditRecord`] from `astral-types`.
///
/// Pure mapping, no I/O: this never persists, sends, reads, or renders the
/// record anywhere, and it adds no runtime caller for the audit contract. It
/// also never produces an approval-shaped value: the record's outcome is the
/// resolution's outcome (`REJECT`/`DEFER` only), and the reason/outcome pairing
/// is re-validated by the record constructor, never assumed.
///
/// Fail-closed behavior:
/// - the proposal must validate structurally and be exactly its own canonical
///   form (never repaired); an EXPIRED proposal is still recordable (audit must
///   capture stale evidence — `resolve_cross_city_conflict` defers on
///   staleness, and that verdict must leave durable evidence);
/// - `observed_at_seconds` must be a positive UTC Unix second;
/// - every copied field is bound to the recomputed `proposal_digest`, and
///   `event_id` is derived over `(operation_id, proposal_digest, outcome code,
///   reason code)` excluding the observed time, so retries of the same verdict
///   reuse the same durable identity.
///
/// # Durable writer boundary
///
/// This function is a contract mapping ONLY. A durable writer is a later
/// batch: it must write to a NEW append-only idempotent table keyed by
/// `event_id` — never `audit_log`, `operation.last_error`, the vote tables, or
/// the outbox — and must NOT translate an arbiter `DEFER` into
/// `CrossCityOperationState::Deferred` or a `REJECT` into any coordinator
/// state transition in this batch.
pub fn build_cross_city_conflict_audit_record(
    proposal: &MutationProposal,
    resolution: &CrossCityConflictResolution,
    observed_at_seconds: i64,
) -> Result<CrossCityConflictAuditRecord, CrossCityConflictAuditError> {
    CrossCityConflictAuditRecord::new(
        proposal,
        resolution.outcome(),
        resolution.reason(),
        observed_at_seconds,
    )
}

// ---------------------------------------------------------------------------
// Tests (pure, deterministic, no I/O)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::{CityVoteCertificate, MutationProposal, NodeDecision, ZeroDecisionEvidence};

    /// Fixed operation id (canonical lowercase hyphenated UUID, non-nil).
    const OP_ID_A: &str = "00000000-0000-0000-0000-0000000000a1";
    /// Second operation id for mismatch fixtures.
    const OP_ID_B: &str = "00000000-0000-0000-0000-0000000000b2";
    const CITY_A: &str = "city-alpha";
    const CITY_B: &str = "city-beta";
    /// Caller-supplied evaluation time: strictly before `EXPIRES_AT`.
    const NOW: i64 = 1_799_999_000;
    /// Exclusive expiry bound of the canonical fixture proposal.
    const EXPIRES_AT: i64 = 1_800_000_000;
    /// Later expiry used to build vote fixtures whose expiry binding disagrees.
    const LATER_EXPIRES_AT: i64 = 1_800_001_000;
    /// Earlier expiry used to build vote fixtures that are already stale.
    const EARLIER_EXPIRES_AT: i64 = 1_799_998_000;

    /// Deterministic 64-character lowercase hex string (SHA-256 output form)
    /// derived from a seed via FNV-1a — no crypto dependency needed for fixtures.
    fn fixture_digest(seed: &str) -> String {
        let mut state: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in seed.as_bytes() {
            state ^= u64::from(*byte);
            state = state.wrapping_mul(0x0000_0100_0000_01b3);
        }
        let mut out = String::with_capacity(64);
        // 4 chunks of 16 lowercase hex characters = exactly 64 characters.
        for _ in 0..4 {
            state = state
                .wrapping_mul(0x0000_0100_0000_01b3)
                .wrapping_add(0x9e37_79b9_7f4a_7c15);
            out.push_str(&format!("{state:016x}"));
        }
        out
    }

    fn fixture_proposal() -> MutationProposal {
        MutationProposal::new(
            OP_ID_A,
            &fixture_digest("scope"),
            &fixture_digest("request"),
            &fixture_digest("mutation"),
            &fixture_digest("frontier"),
            10,
            2,
            11,
            3,
            "compiler-v1",
            "policy-v1",
            EXPIRES_AT,
        )
        .expect("fixture proposal must be valid")
    }

    /// Variant proposal: identical to [`fixture_proposal`] except for the fields
    /// named by the overrides.
    fn variant_proposal(
        operation_id: &str,
        frontier_digest: &str,
        mutation_digest: &str,
        request_digest: &str,
        expires_at: i64,
    ) -> MutationProposal {
        MutationProposal::new(
            operation_id,
            &fixture_digest("scope"),
            request_digest,
            mutation_digest,
            frontier_digest,
            10,
            2,
            11,
            3,
            "compiler-v1",
            "policy-v1",
            expires_at,
        )
        .expect("fixture variant proposal must be valid")
    }

    fn fixture_vote(proposal: &MutationProposal, city: &str) -> CityVoteCertificate {
        fixture_vote_at(proposal, city, NOW)
    }

    /// Issue a vote at an explicit time (needed when the fixture proposal expires
    /// before `NOW`, e.g. stale-vote fixtures).
    fn fixture_vote_at(
        proposal: &MutationProposal,
        city: &str,
        issued_at: i64,
    ) -> CityVoteCertificate {
        let proposal_digest = proposal
            .proposal_digest()
            .expect("fixture proposal digest must compute");
        let evidence = |node: &str| {
            ZeroDecisionEvidence::new(
                city,
                node,
                1,
                NodeDecision::Allow,
                &proposal_digest,
                &proposal.base_frontier_digest,
                &proposal.mutation_digest,
                &format!("nonce-{city}-{node}"),
                proposal.expires_at,
                &format!("sig-{city}-{node}"),
            )
            .expect("fixture evidence must be valid")
        };
        CityVoteCertificate::issue(
            proposal,
            &[evidence("node-a"), evidence("node-b")],
            issued_at,
        )
        .expect("fixture city vote must issue")
    }

    /// Canonical fixture: a valid proposal plus two votes from distinct cities.
    fn consistent_pair() -> (MutationProposal, Vec<CityVoteCertificate>) {
        let proposal = fixture_proposal();
        let votes = vec![
            fixture_vote(&proposal, CITY_A),
            fixture_vote(&proposal, CITY_B),
        ];
        (proposal, votes)
    }

    fn resolve(
        proposal: &MutationProposal,
        votes: &[CityVoteCertificate],
    ) -> CrossCityConflictResolution {
        resolve_cross_city_conflict(proposal, votes, NOW)
    }

    // ===== verdict table =====

    #[test]
    fn empty_city_votes_defer() {
        let proposal = fixture_proposal();
        let resolution = resolve(&proposal, &[]);
        assert_eq!(resolution.outcome(), CrossCityConflictOutcome::Defer);
        assert_eq!(
            resolution.reason(),
            CrossCityConflictReason::EvidenceMissing
        );
        assert_eq!(resolution.reason_code(), "EVIDENCE_MISSING");
    }

    #[test]
    fn wrong_vote_count_defers() {
        let (proposal, votes) = consistent_pair();

        let single = resolve(&proposal, &votes[..1]);
        assert_eq!(single.outcome, CrossCityConflictOutcome::Defer);
        assert_eq!(single.reason, CrossCityConflictReason::EvidenceCountInvalid);

        let mut oversized = votes.clone();
        oversized.push(votes[0].clone());
        let oversized = resolve(&proposal, &oversized);
        assert_eq!(oversized.outcome, CrossCityConflictOutcome::Defer);
        assert_eq!(
            oversized.reason,
            CrossCityConflictReason::EvidenceCountInvalid
        );
    }

    #[test]
    fn expired_proposal_defers_without_panic() {
        let (proposal, votes) = consistent_pair();
        // Boundary: expiry is exclusive, so now == expires_at is already expired.
        for now in [EXPIRES_AT, EXPIRES_AT + 3_600] {
            let resolution = resolve_cross_city_conflict(&proposal, &votes, now);
            assert_eq!(resolution.outcome(), CrossCityConflictOutcome::Defer);
            assert_eq!(
                resolution.reason(),
                CrossCityConflictReason::EvidenceExpired
            );
        }
    }

    #[test]
    fn expired_vote_defers_without_panic() {
        // Votes issued against a proposal that expires EARLIER: at NOW they are
        // stale, while the presented proposal itself is still valid. Time
        // staleness defers before the expiry-binding mismatch could reject.
        let proposal = fixture_proposal();
        let stale_source = variant_proposal(
            OP_ID_A,
            &fixture_digest("frontier"),
            &fixture_digest("mutation"),
            &fixture_digest("request"),
            EARLIER_EXPIRES_AT,
        );
        let votes = vec![
            fixture_vote_at(&stale_source, CITY_A, EARLIER_EXPIRES_AT - 1),
            fixture_vote_at(&stale_source, CITY_B, EARLIER_EXPIRES_AT - 1),
        ];
        assert!(votes[0].is_expired_at(NOW));
        let resolution = resolve(&proposal, &votes);
        assert_eq!(resolution.outcome(), CrossCityConflictOutcome::Defer);
        assert_eq!(
            resolution.reason(),
            CrossCityConflictReason::EvidenceExpired
        );
    }

    #[test]
    fn operation_mismatch_rejects() {
        let proposal = fixture_proposal();
        let other = variant_proposal(
            OP_ID_B,
            &fixture_digest("frontier"),
            &fixture_digest("mutation"),
            &fixture_digest("request"),
            EXPIRES_AT,
        );
        let votes = vec![fixture_vote(&other, CITY_A), fixture_vote(&other, CITY_B)];
        let resolution = resolve(&proposal, &votes);
        assert_eq!(resolution.outcome(), CrossCityConflictOutcome::Reject);
        assert_eq!(
            resolution.reason(),
            CrossCityConflictReason::OperationMismatch
        );
    }

    #[test]
    fn frontier_mismatch_rejects() {
        let proposal = fixture_proposal();
        let other = variant_proposal(
            OP_ID_A,
            &fixture_digest("frontier-alt"),
            &fixture_digest("mutation"),
            &fixture_digest("request"),
            EXPIRES_AT,
        );
        let votes = vec![fixture_vote(&other, CITY_A), fixture_vote(&other, CITY_B)];
        let resolution = resolve(&proposal, &votes);
        assert_eq!(resolution.outcome(), CrossCityConflictOutcome::Reject);
        assert_eq!(
            resolution.reason(),
            CrossCityConflictReason::FrontierMismatch
        );
    }

    #[test]
    fn mutation_mismatch_rejects() {
        let proposal = fixture_proposal();
        let other = variant_proposal(
            OP_ID_A,
            &fixture_digest("frontier"),
            &fixture_digest("mutation-alt"),
            &fixture_digest("request"),
            EXPIRES_AT,
        );
        let votes = vec![fixture_vote(&other, CITY_A), fixture_vote(&other, CITY_B)];
        let resolution = resolve(&proposal, &votes);
        assert_eq!(resolution.outcome(), CrossCityConflictOutcome::Reject);
        assert_eq!(
            resolution.reason(),
            CrossCityConflictReason::MutationMismatch
        );
    }

    #[test]
    fn expiry_binding_mismatch_rejects() {
        // Votes whose expiry binding disagrees but that are still fresh at NOW.
        let proposal = fixture_proposal();
        let other = variant_proposal(
            OP_ID_A,
            &fixture_digest("frontier"),
            &fixture_digest("mutation"),
            &fixture_digest("request"),
            LATER_EXPIRES_AT,
        );
        let votes = vec![fixture_vote(&other, CITY_A), fixture_vote(&other, CITY_B)];
        assert!(!votes[0].is_expired_at(NOW));
        let resolution = resolve(&proposal, &votes);
        assert_eq!(resolution.outcome(), CrossCityConflictOutcome::Reject);
        assert_eq!(resolution.reason(), CrossCityConflictReason::ExpiryMismatch);
    }

    #[test]
    fn scope_mismatch_rejects() {
        // Only the request digest differs, so operation/frontier/mutation/expiry
        // bindings all agree while the full-proposal digest cannot: the votes
        // certify different proposal content (scope binding conflict).
        let proposal = fixture_proposal();
        let other = variant_proposal(
            OP_ID_A,
            &fixture_digest("frontier"),
            &fixture_digest("mutation"),
            &fixture_digest("request-alt"),
            EXPIRES_AT,
        );
        let votes = vec![fixture_vote(&other, CITY_A), fixture_vote(&other, CITY_B)];
        let resolution = resolve(&proposal, &votes);
        assert_eq!(resolution.outcome(), CrossCityConflictOutcome::Reject);
        assert_eq!(resolution.reason(), CrossCityConflictReason::ScopeMismatch);
    }

    #[test]
    fn duplicate_city_rejects() {
        let (proposal, votes) = consistent_pair();
        let duplicated = vec![votes[0].clone(), fixture_vote(&proposal, CITY_A)];
        let resolution = resolve(&proposal, &duplicated);
        assert_eq!(resolution.outcome(), CrossCityConflictOutcome::Reject);
        assert_eq!(
            resolution.reason(),
            CrossCityConflictReason::CityIdentityDuplicate
        );
    }

    // ===== evidence integrity (malformed / non-canonical) =====

    #[test]
    fn tampered_certificate_digest_rejects() {
        let (proposal, votes) = consistent_pair();
        let mut tampered = votes[0].clone();
        tampered.certificate_digest = fixture_digest("tampered");
        let resolution = resolve(&proposal, &[tampered, votes[1].clone()]);
        assert_eq!(resolution.outcome(), CrossCityConflictOutcome::Reject);
        assert_eq!(
            resolution.reason(),
            CrossCityConflictReason::CertificateInvalid
        );
    }

    #[test]
    fn non_canonical_node_order_rejects() {
        let (proposal, votes) = consistent_pair();
        let mut reordered = votes[0].clone();
        reordered.nodes.reverse();
        let resolution = resolve(&proposal, &[reordered, votes[1].clone()]);
        assert_eq!(resolution.outcome(), CrossCityConflictOutcome::Reject);
        assert_eq!(
            resolution.reason(),
            CrossCityConflictReason::CertificateInvalid
        );
    }

    #[test]
    fn malformed_node_identity_rejects() {
        let (proposal, votes) = consistent_pair();
        let mut broken = votes[0].clone();
        broken.nodes[0].node_id = "bad node".to_string();
        let resolution = resolve(&proposal, &[broken, votes[1].clone()]);
        assert_eq!(resolution.outcome(), CrossCityConflictOutcome::Reject);
        assert_eq!(
            resolution.reason(),
            CrossCityConflictReason::NodeIdentityInvalid
        );
    }

    #[test]
    fn duplicate_node_attestation_rejects() {
        let (proposal, votes) = consistent_pair();
        let mut broken = votes[0].clone();
        broken.nodes[1].node_id = broken.nodes[0].node_id.clone();
        let resolution = resolve(&proposal, &[broken, votes[1].clone()]);
        assert_eq!(resolution.outcome(), CrossCityConflictOutcome::Reject);
        assert_eq!(
            resolution.reason(),
            CrossCityConflictReason::NodeIdentityInvalid
        );
    }

    #[test]
    fn malformed_signature_rejects() {
        let (proposal, votes) = consistent_pair();
        let mut broken = votes[0].clone();
        broken.nodes[0].signature = "bad sig".to_string();
        let resolution = resolve(&proposal, &[broken, votes[1].clone()]);
        assert_eq!(resolution.outcome(), CrossCityConflictOutcome::Reject);
        assert_eq!(
            resolution.reason(),
            CrossCityConflictReason::SignatureInvalid
        );
    }

    // ===== unprovable states defer =====

    #[test]
    fn malformed_proposal_defers() {
        let (proposal, votes) = consistent_pair();
        let mut broken = proposal.clone();
        broken.scope_digest = "not-a-digest".to_string();
        let resolution = resolve(&broken, &votes);
        assert_eq!(resolution.outcome(), CrossCityConflictOutcome::Defer);
        assert_eq!(
            resolution.reason(),
            CrossCityConflictReason::EvidenceUnverifiable
        );
    }

    #[test]
    fn non_canonical_proposal_defers_without_repair() {
        let (proposal, votes) = consistent_pair();
        // Padded compiler version: the proposal is not exactly its own canonical
        // form. It must defer unrepaired — never be silently trimmed into a
        // different value, and never rejected as evidence (it is the request).
        let mut padded = proposal.clone();
        padded.compiler_version = " compiler-v1".to_string();
        assert_ne!(padded.canonicalized().expect("pads normalize"), padded);
        let resolution = resolve(&padded, &votes);
        assert_eq!(resolution.outcome(), CrossCityConflictOutcome::Defer);
        assert_eq!(
            resolution.reason(),
            CrossCityConflictReason::EvidenceUnverifiable
        );
    }

    // ===== the no-approval guarantee =====

    #[test]
    fn consistent_pair_defers_with_explicit_no_approval_reason() {
        let (proposal, votes) = consistent_pair();
        let resolution = resolve(&proposal, &votes);
        assert_eq!(resolution.outcome(), CrossCityConflictOutcome::Defer);
        assert_eq!(
            resolution.reason(),
            CrossCityConflictReason::ArbiterAllowOutOfScope
        );
        assert_eq!(resolution.reason_code(), "ARBITER_ALLOW_OUT_OF_SCOPE");
        assert_eq!(resolution.outcome().as_str(), "DEFER");
    }

    #[test]
    fn vote_order_is_irrelevant() {
        let (proposal, votes) = consistent_pair();
        let forward = resolve(&proposal, &votes);
        let reversed = resolve(&proposal, &[votes[1].clone(), votes[0].clone()]);
        assert_eq!(forward, reversed);
    }

    #[test]
    fn resolution_is_deterministic() {
        let (proposal, votes) = consistent_pair();
        assert_eq!(resolve(&proposal, &votes), resolve(&proposal, &votes));
    }

    // ===== shape guards =====

    /// Compile-time shape guard: the exhaustive match (no wildcard) fails to
    /// compile if a third outcome variant is ever added, proving the outcome type
    /// carries exactly `Reject` and `Defer` — and never an allow variant. It also
    /// proves the type is not `ArbitrationVerdict`, which cannot be matched here.
    #[test]
    fn outcome_has_exactly_reject_and_defer() {
        fn render(outcome: CrossCityConflictOutcome) -> &'static str {
            match outcome {
                CrossCityConflictOutcome::Reject => "REJECT",
                CrossCityConflictOutcome::Defer => "DEFER",
            }
        }
        assert_eq!(render(CrossCityConflictOutcome::Reject), "REJECT");
        assert_eq!(render(CrossCityConflictOutcome::Defer), "DEFER");
        assert_eq!(CrossCityConflictOutcome::Reject.as_str(), "REJECT");
        assert_eq!(CrossCityConflictOutcome::Defer.as_str(), "DEFER");
    }

    #[test]
    fn resolution_fields_are_private_and_accessors_are_stable() {
        const SOURCE: &str = include_str!("cross_city_conflict.rs");
        let struct_start = SOURCE
            .find("pub struct CrossCityConflictResolution {")
            .expect("resolution struct exists");
        let struct_end = struct_start
            + SOURCE[struct_start..]
                .find("\n}")
                .expect("resolution struct ends");
        let struct_block = &SOURCE[struct_start..struct_end];
        assert!(!struct_block.contains("pub outcome"));
        assert!(!struct_block.contains("pub reason"));
        assert!(SOURCE.contains("pub const fn outcome(&self)"));
        assert!(SOURCE.contains("pub const fn reason(&self)"));
    }

    #[test]
    fn reason_outcome_mapping_is_closed_and_stable() {
        const DEFER_REASONS: [CrossCityConflictReason; 5] = [
            CrossCityConflictReason::EvidenceMissing,
            CrossCityConflictReason::EvidenceCountInvalid,
            CrossCityConflictReason::EvidenceExpired,
            CrossCityConflictReason::EvidenceUnverifiable,
            CrossCityConflictReason::ArbiterAllowOutOfScope,
        ];
        const REJECT_REASONS: [CrossCityConflictReason; 10] = [
            CrossCityConflictReason::OperationMismatch,
            CrossCityConflictReason::ScopeMismatch,
            CrossCityConflictReason::FrontierMismatch,
            CrossCityConflictReason::MutationMismatch,
            CrossCityConflictReason::ExpiryMismatch,
            CrossCityConflictReason::DecisionMismatch,
            CrossCityConflictReason::NodeIdentityInvalid,
            CrossCityConflictReason::CityIdentityDuplicate,
            CrossCityConflictReason::SignatureInvalid,
            CrossCityConflictReason::CertificateInvalid,
        ];

        assert_eq!(
            CrossCityConflictReason::ALL.len(),
            DEFER_REASONS.len() + REJECT_REASONS.len()
        );
        for reason in DEFER_REASONS {
            assert_eq!(reason.outcome(), CrossCityConflictOutcome::Defer);
        }
        for reason in REJECT_REASONS {
            assert_eq!(reason.outcome(), CrossCityConflictOutcome::Reject);
        }
        // Every code is a stable, uppercase, underscore-separated machine token
        // suitable for audit/metrics. No code can promise approval: the only
        // allow-adjacent code is ARBITER_ALLOW_OUT_OF_SCOPE, which records that
        // approval is out of this component's authority, and no outcome other
        // than REJECT/DEFER exists to be paired with any code.
        for reason in CrossCityConflictReason::ALL {
            let code = reason.as_str();
            assert!(!code.is_empty());
            assert!(code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b'_'));
            assert_ne!(code, "ALLOW");
            assert_ne!(code, "ARBITER_ALLOW");
            assert_eq!(
                CrossCityConflictResolution::from_reason(reason).outcome(),
                reason.outcome()
            );
        }
    }

    #[test]
    fn resolution_never_renders_caller_input() {
        // Fixtures carry a marker in every caller-controlled field; the marker
        // must never surface through Debug/Display of the resolution, outcome, or
        // reason (all of which render only closed-enum, static text).
        let marker = "LEAK_MARKER_7f3a";
        let proposal = MutationProposal::new(
            OP_ID_A,
            &fixture_digest("scope"),
            &fixture_digest(marker),
            &fixture_digest("mutation"),
            &fixture_digest("frontier"),
            10,
            2,
            11,
            3,
            "compiler-v1",
            "policy-v1",
            EXPIRES_AT,
        )
        .expect("marker proposal must be valid");
        let conflicting = variant_proposal(
            OP_ID_B,
            &fixture_digest("frontier"),
            &fixture_digest("mutation"),
            &fixture_digest("request"),
            EXPIRES_AT,
        );
        let votes = vec![
            fixture_vote(&conflicting, marker),
            fixture_vote(&conflicting, CITY_B),
        ];
        let resolution = resolve(&proposal, &votes);

        let rendered = format!(
            "{:?}|{:?}|{}|{}|{}|{}",
            resolution,
            resolution.reason(),
            resolution.outcome(),
            resolution.reason(),
            resolution.outcome().as_str(),
            resolution.reason_code()
        );
        assert!(!rendered.contains(marker));
        assert!(rendered.contains(resolution.reason_code()));
    }

    #[test]
    fn source_has_no_io_or_transport_primitives() {
        // Compile-time source-shape guard: this pure module must not reference
        // I/O, transport, cache, or global-state primitives. Tokens are assembled
        // from fragments so the joined form never appears in this source.
        const SOURCE: &str = include_str!("cross_city_conflict.rs");
        const FORBIDDEN: [&str; 16] = [
            concat!("std:", ":fs"),
            concat!("std:", ":net"),
            concat!("std:", ":process"),
            concat!("std:", ":thread"),
            concat!("std:", ":io"),
            concat!("Tc", "pStream"),
            concat!("Ud", "pSocket"),
            concat!("to", "kio"),
            concat!("sq", "lx"),
            concat!("re", "dis"),
            concat!("la", "pin"),
            concat!("req", "west"),
            concat!("Comm", "and"),
            concat!("Fi", "le::"),
            concat!("Once", "Lock"),
            concat!("tra", "cing"),
        ];
        for token in FORBIDDEN {
            assert!(
                !SOURCE.contains(token),
                "pure boundary violated: forbidden primitive {token} found in source"
            );
        }
    }

    // ===== shared contract enums + pure audit mapping =====

    #[test]
    fn outcome_and_reason_are_shared_contract_types() {
        // The canonical enums moved to astral-types (shared contract owner);
        // the names here are re-exports of the same types, so existing callers
        // keep compiling with identical semantics and wire codes.
        let moved_outcome: astral_types::CrossCityConflictOutcome = CrossCityConflictOutcome::Defer;
        assert_eq!(moved_outcome, CrossCityConflictOutcome::Defer);
        let moved_reason: astral_types::CrossCityConflictReason =
            CrossCityConflictReason::ArbiterAllowOutOfScope;
        assert_eq!(
            moved_reason,
            CrossCityConflictReason::ArbiterAllowOutOfScope
        );
        assert_eq!(CrossCityConflictReason::ALL.len(), 15);
        assert_eq!(CrossCityConflictOutcome::Reject.as_str(), "REJECT");
        assert_eq!(CrossCityConflictOutcome::Defer.as_str(), "DEFER");
        assert_eq!(CrossCityConflictOutcome::Reject.to_string(), "REJECT");
        assert_eq!(
            CrossCityConflictReason::EvidenceMissing.to_string(),
            "EVIDENCE_MISSING"
        );
    }

    #[test]
    fn audit_mapping_preserves_verdict_for_every_reason() {
        let proposal = fixture_proposal();
        for reason in CrossCityConflictReason::ALL {
            let resolution = CrossCityConflictResolution::from_reason(reason);
            let record = build_cross_city_conflict_audit_record(&proposal, &resolution, NOW)
                .unwrap_or_else(|error| {
                    panic!(
                        "reason {} must map to an audit record: {error:?}",
                        reason.as_str()
                    )
                });
            // The mapping preserves the verdict exactly: outcome and reason
            // survive, the copied correlation fields match the proposal.
            assert_eq!(record.outcome, resolution.outcome());
            assert_eq!(record.reason_code, resolution.reason());
            assert_eq!(record.reason_code.as_str(), resolution.reason_code());
            assert_eq!(record.operation_id, proposal.operation_id);
            assert_eq!(
                record.proposal_digest,
                proposal.proposal_digest().expect("fixture proposal digest")
            );
            assert_eq!(record.observed_at_seconds, NOW);
            // The record outcome is REJECT or DEFER - never an approval.
            let code = record.outcome.as_str();
            assert!(matches!(code, "REJECT" | "DEFER"));
            assert_eq!(code, resolution.outcome().as_str());
            // Pairing holds and the record validates fail-closed.
            assert_eq!(record.reason_code.outcome(), record.outcome);
            record.validate().expect("mapped record must validate");
        }
    }

    #[test]
    fn audit_mapping_never_creates_an_allow() {
        let proposal = fixture_proposal();
        for reason in CrossCityConflictReason::ALL {
            let resolution = CrossCityConflictResolution::from_reason(reason);
            let record = build_cross_city_conflict_audit_record(&proposal, &resolution, NOW)
                .expect("mapping must succeed for a canonical proposal");
            // Compile-time guard: the exhaustive match has no allow arm to
            // fall into, because no allow variant exists on the shared type.
            match record.outcome {
                CrossCityConflictOutcome::Reject | CrossCityConflictOutcome::Defer => {}
            }
            assert_ne!(record.outcome.as_str(), "ALLOW");
            assert_ne!(record.outcome.as_str(), "ARBITER_ALLOW");
        }
    }

    #[test]
    fn audit_mapping_is_fail_closed_on_bad_inputs() {
        let proposal = fixture_proposal();
        let resolution =
            CrossCityConflictResolution::from_reason(CrossCityConflictReason::ScopeMismatch);

        // A non-canonical proposal is never repaired into a record.
        let mut padded = proposal.clone();
        padded.compiler_version = " compiler-v1".to_owned();
        assert!(build_cross_city_conflict_audit_record(&padded, &resolution, NOW).is_err());

        // A malformed proposal fails closed.
        let mut malformed = proposal.clone();
        malformed.scope_digest = "not-a-digest".to_owned();
        assert!(build_cross_city_conflict_audit_record(&malformed, &resolution, NOW).is_err());

        // The observation time must be a positive UTC Unix second.
        for bad_time in [0, -1] {
            assert!(matches!(
                build_cross_city_conflict_audit_record(&proposal, &resolution, bad_time),
                Err(CrossCityConflictAuditError::InvalidObservedTime { .. })
            ));
        }
    }

    #[test]
    fn audit_mapping_records_expired_proposal_evidence() {
        // An expired proposal resolves to DEFER/EVIDENCE_EXPIRED, and the
        // mapping must still produce a record: audit captures stale evidence.
        let (proposal, votes) = consistent_pair();
        let observed = EXPIRES_AT + 3_600;
        let resolution = resolve_cross_city_conflict(&proposal, &votes, observed);
        assert_eq!(resolution.outcome(), CrossCityConflictOutcome::Defer);
        assert_eq!(
            resolution.reason(),
            CrossCityConflictReason::EvidenceExpired
        );
        let record = build_cross_city_conflict_audit_record(&proposal, &resolution, observed)
            .expect("stale evidence must remain recordable");
        assert_eq!(record.outcome, CrossCityConflictOutcome::Defer);
        assert_eq!(record.reason_code, CrossCityConflictReason::EvidenceExpired);
        assert!(record.observed_at_seconds >= proposal.expires_at);
        record.validate().expect("stale record must validate");
    }

    #[test]
    fn audit_record_diagnostics_do_not_leak_caller_text() {
        const MARKER: &str = "LEAK_MARKER_7f3a";
        let marked = MutationProposal::new(
            OP_ID_A,
            &fixture_digest("scope"),
            &fixture_digest("request"),
            &fixture_digest("mutation"),
            &fixture_digest("frontier"),
            10,
            2,
            11,
            3,
            MARKER,
            MARKER,
            EXPIRES_AT,
        )
        .expect("marker proposal must be valid");
        let resolution = resolve_cross_city_conflict(&marked, &[], NOW);
        let record = build_cross_city_conflict_audit_record(&marked, &resolution, NOW)
            .expect("marker record must build");
        // The marker IS carried in the durable evidence fields...
        assert_eq!(record.compiler_version, MARKER);
        assert_eq!(record.policy_version, MARKER);
        // ...but never surfaces through Debug of the record, its enums, or the
        // resolution (closed, redacted, or static text only; the resolution
        // has no Display by design - only Debug over closed-enum fields).
        let rendered = format!(
            "{:?}|{}|{:?}|{}|{:?}|{}|{:?}",
            record,
            record,
            record.outcome,
            record.outcome,
            record.reason_code,
            record.reason_code,
            resolution,
        );
        assert!(!rendered.contains(MARKER));
        assert!(rendered.contains(record.event_id.as_str()));
        assert!(rendered.contains(record.reason_code.as_str()));
    }
}
