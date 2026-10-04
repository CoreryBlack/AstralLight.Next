//! 事件处置纯计划层（candidate assembly / ledger 计划 / 失败分类）。
//!
//! 全部为纯函数：输入 claimed durable 事实与 ledger/frontier 证据，输出
//! EventDisposition 与发布计划；不做 I/O、不改租约、不发布。worker 执行见
//! 主 worker 区块，durable 边界见 [`super::runtime`]。

use sha2::{Digest, Sha256};

use astral_db::{
    decode_delta_event_payload, decode_ledger_row, hot_state_from_entries,
    impact_plan_request_from_compiler_plan, partition_ledger_at_published_frontier,
    AuthorizationImpactItemInput, AuthorizationImpactItemType,
    AuthorizationImpactPlanAppendRequest, AuthorizationProjectionError, AuthorizationStageRequest,
    ClaimedDeltaEvent, CompileModeEvidence, DeltaEventType, DeltaLeaseIdentity,
    DeltaProjectorExpectation, DeltaProjectorPublishCommand, GrantLedgerEntry, ParentReferenceView,
    PartitionedGrantLedgerAtFrontier, ProjectionAggregateIdentity, PublishRevokeFenceEvidence,
    RawLedgerRow, StagedSegmentContent, MAX_MANIFEST_LEASE_SECONDS,
};
use astral_types::{DependencyVector, DependencyVersion, ProjectionCompileMode, TenantScope};
use policy_engine::{
    AuthorizationCompiler, CompileOutcome, CompilerConflict, FullCompilerOracle, FullRebuildReason,
    HotState,
};

use super::*;
pub(crate) fn reconcile_lease_mutation_loss(
    identity: &DeltaLeaseIdentity,
    mutation: &str,
    error: &astral_db::GrantRepositoryError,
) {
    tracing::warn!(
        event_id = %identity.event_id,
        delta_event_id = identity.delta_event_id,
        mutation,
        error = %error,
        "delta lease mutation matched zero rows; treating as UNKNOWN, \
         reconciliation required before any retry"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure decision pipeline (unit-tested without MySQL)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub(crate) enum EventDisposition {
    /// Fully assembled single-transaction publish command. Secret lease token
    /// is attached ONLY afterwards by the orchestrator, never logged.
    Publish(Box<DeltaProjectorPublishCommand>),
    /// Transient failure; scheduling goes through [`plan_retry_schedule`] in
    /// `act_on_disposition`. Carries NO hand-picked backoff seconds — fixed
    /// short sleeps bypassing the attempt budget are forbidden.
    Retry { reason: String },
    /// Divergence needing operator review. Writes the REAL terminal
    /// `QUARANTINED` status through [`AuthorizationProjectorRuntime::
    /// mark_event_quarantined`]; unknown CAS/query outcomes stop all further
    /// mutation until reconciliation.
    Quarantine { reason: String },
    /// Candidate completeness unprovable with current public APIs; publishing
    /// partial state is forbidden.
    Blocked { reason: String },
    /// The live manifest chain moved beyond what this event's input can prove;
    /// reserved for future explicit front-loader-driven supersession checks
    /// (release-without-poison semantics live in `act_on_disposition`).
    #[allow(dead_code)]
    Superseded { reason: String },
}

/// Everything the pure decider needs about one claimed event.
pub(crate) struct EventDecisionInput<'a> {
    pub(crate) claimed: &'a ClaimedDeltaEvent,
    /// Observed short-transaction publication world. `None` means the
    /// aggregate has no current pointer at all (genuine first-publication
    /// ground); `Some` carries the strict published frontier plus the parent
    /// reference hints. PLANNING INPUTS ONLY — the publish transaction
    /// re-verifies pointers, fences, lineage and parent content durably.
    pub(crate) publication: Option<&'a PublicationContext>,
    pub(crate) ledger_rows: &'a [RawLedgerRow],
    pub(crate) identity: ProjectionAggregateIdentity,
}

pub(crate) struct AssembledCandidate {
    candidate: HotState,
    /// `true`: incremental compiler application. `false`: deterministic
    /// full-oracle product (first publication or a recorded full-rebuild
    /// reason). BOTH continuation arms carry their compiler outcome, so their
    /// impact items map from the outcome's `ImpactPlan`; ONLY the
    /// first-publication REPLAY (no plan, no base) synthesizes items directly
    /// from candidate key-level hashes.
    incremental: bool,
    incremental_outcome: Option<policy_engine::CompiledProjection>,
    full_rebuild_reason: Option<FullRebuildReason>,
    base: Option<HotState>,
}

/// Outcome of the ledger ⇆ published-frontier planning split for one claimed
/// event.
#[derive(Debug)]
pub(crate) enum LedgerPlan {
    /// First publication: no frontier exists and the scope ledger provably
    /// contains ONLY this event's own contiguous chain ending exactly at the
    /// claimed revision with `base_version == 0`.
    FirstPublication { own_latest: Box<GrantLedgerEntry> },
    /// Incremental continuation over proven published heads. `base_entries`
    /// derive exclusively from the partition's frontier-proven heads (each
    /// grant's last proven head; tombstones stay included while authorizing
    /// nothing). The claimed continuation row was already strictly matched to
    /// every immutable claimed field AND positioned directly above its own
    /// grant's frontier-proven target before this variant exists.
    Continuation { base_entries: Vec<GrantLedgerEntry> },
    /// Candidate completeness unprovable without guessing sibling order or
    /// waiting on sibling tails; transiently retried under the attempt budget.
    Blocked { reason: String },
    /// Immutable divergence / durable corruption requiring operator review
    /// (own stale claim, missing/ambiguous candidate rows, partition-level
    /// bridge failures — never silently repaired).
    Quarantine { reason: String },
}

/// How the claim's own event was located inside a partition outcome.
#[derive(Debug)]
pub(crate) enum LocatedCandidate<'p> {
    Found(&'p GrantLedgerEntry),
    BehindUnpublishedSiblings,
    StaleBehindPublishedFrontier,
    OwnClaimNotRecognized,
    MissingFromLedger,
    Ambiguous,
}

/// Locate the claimed event inside an already-computed partition outcome.
///
/// The partitioner receives `claimed_event_ids = [claimed.event_id]`, so:
/// - a direct hit among `candidate_rows` is our continuation;
/// - excluded rows carrying OUR event id classify precisely by their kind;
/// - `NotProvenPublished` on our own id would contradict that claimed-set
///   membership and surfaces defensively instead of being assumed away;
/// - multiple matches cannot survive the partitioner's duplicate-event abort,
///   yet the contradiction is still reported as ambiguous.
pub(crate) fn locate_claimed_candidate<'p>(
    partition: &'p PartitionedGrantLedgerAtFrontier,
    event_id: &str,
) -> LocatedCandidate<'p> {
    let mut located: Option<&GrantLedgerEntry> = None;
    let mut candidate_hits = 0usize;
    for row in &partition.candidate_rows {
        if row.entry.event_id == event_id {
            candidate_hits += 1;
            located = Some(&row.entry);
        }
    }
    if candidate_hits > 1 {
        return LocatedCandidate::Ambiguous;
    }
    if let Some(entry) = located {
        return LocatedCandidate::Found(entry);
    }
    let mut classified: Option<astral_db::LedgerExclusionKind> = None;
    let mut exclusion_hits = 0usize;
    for row in &partition.excluded_rows {
        if row.entry.event_id == event_id {
            exclusion_hits += 1;
            classified = Some(row.kind);
        }
    }
    match exclusion_hits {
        1 => match classified.expect("single exclusion hit carries its kind") {
            astral_db::LedgerExclusionKind::ClaimedBehindUnpublishedSiblings => {
                LocatedCandidate::BehindUnpublishedSiblings
            }
            astral_db::LedgerExclusionKind::StaleClaimBehindPublishedFrontier => {
                LocatedCandidate::StaleBehindPublishedFrontier
            }
            astral_db::LedgerExclusionKind::NotProvenPublished => {
                LocatedCandidate::OwnClaimNotRecognized
            }
        },
        // Zero hits (and >1 cannot survive the partitioner's duplicate-event
        // abort): the claimed event has no revision row in this scope.
        _ => LocatedCandidate::MissingFromLedger,
    }
}

/// Field-level equality between one ledger entry and every immutable claimed
/// field: any drift means queue row and revision history no longer describe
/// the same delta and refuses to proceed (fail-closed).
pub(crate) fn verify_candidate_matches_claimed(
    entry: &GrantLedgerEntry,
    claimed: &ClaimedDeltaEvent,
) -> Result<(), String> {
    let checks: [(bool, &str); 9] = [
        (
            entry.revision_no == claimed.target_version as u64,
            "revision_no",
        ),
        (entry.event_id == claimed.event_id, "event_id"),
        (entry.operation_id == claimed.operation_id, "operation_id"),
        (
            entry.semantic_hash.as_hex() == claimed.semantic_hash.as_hex(),
            "semantic_hash",
        ),
        (
            entry.dependency_hash.as_hex() == claimed.dependency_hash.as_hex(),
            "dependency_hash",
        ),
        (
            entry.compiler_version == claimed.compiler_version,
            "compiler_version",
        ),
        (entry.tenant_id == claimed.tenant_id, "tenant_id"),
        (entry.card_id == claimed.card_id, "card_id"),
        (
            entry.aggregate_type == claimed.aggregate_type
                && entry.aggregate_id == claimed.aggregate_id,
            "aggregate_identity",
        ),
    ];
    for (holds, field) in checks {
        if !holds {
            return Err(format!(
                "code=auth_projector.candidate_field_mismatch;field={field}"
            ));
        }
    }
    Ok(())
}

/// First-publication proof WITHOUT any frontier: the claimed grant's OWN
/// revision chain must run contiguously from 1, contain the claimed revision,
/// and agree with every immutable claimed field. Rows of OTHER grants
/// (independent initial chains) and the claimed grant's own later revisions are
/// ignored — under per-grant versioning each chain is independently provable,
/// so cross-grant publication order carries no ambiguity and every sibling
/// converges through its own claim (this arm again, or the Some-arm
/// continuation once a pointer exists). The source-freshness read gate keeps
/// the scope `PENDING` for authorization until every sibling delta reaches a
/// terminal state, so an intermediate single-grant publication is never served.
pub(crate) fn prove_first_publication_chain(
    rows: &[RawLedgerRow],
    claimed: &ClaimedDeltaEvent,
) -> Result<GrantLedgerEntry, String> {
    let own_grant_text = claimed.grant_id.as_str();
    // The ledger query orders rows by (grant_id ASC, revision_no ASC); the
    // filtered slice therefore keeps the own-grant revision order.
    let own_rows: Vec<&RawLedgerRow> = rows
        .iter()
        .filter(|row| row.grant_id == own_grant_text)
        .collect();
    if own_rows.is_empty() {
        return Err("code=auth_projector.own_revision_missing".to_owned());
    }
    let mut expected_revision: u64 = 1;
    for row in &own_rows {
        if row.revision_no <= 0 || row.revision_no as u64 != expected_revision {
            return Err("code=auth_projector.first_publication_chain_gap".to_owned());
        }
        expected_revision = expected_revision.saturating_add(1);
    }
    // The claimed row is the chain head being published; own later revisions
    // (beyond the claim) stay unpublished and continue via the Some arm.
    let claimed_row = own_rows
        .iter()
        .find(|row| row.event_id == claimed.event_id)
        .ok_or_else(|| "code=auth_projector.own_revision_missing".to_owned())?;
    let own_latest = decode_ledger_row(claimed_row)
        .map_err(|error| format!("code=auth_projector.own_revision_unreadable;error={error}"))?;
    verify_candidate_matches_claimed(&own_latest, claimed)?;
    Ok(own_latest)
}

/// Split the scope ledger against the observed publication world.
///
/// With a frontier, [`partition_ledger_at_published_frontier`] classifies the
/// append-only history against the strictly verified published generations;
/// its errors are DURABLE CORRUPTION, not transient conditions. The resulting
/// base derives exclusively from `published_heads`, so unproven sibling tails
/// (`PENDING` / `LEASED` / `QUARANTINED` work of other events) can never leak
/// into the compiled pre-state. Without a frontier the claimed grant's own
/// initial chain must be provably contiguous from revision 1 (sibling grants'
/// independent chains are ignored — each converges through its own claim);
/// aggregate generations and per-grant versions are separate domains connected
/// solely through the frontier events — they are never compared directly here.
pub(crate) fn plan_ledger_against_publication(input: &EventDecisionInput<'_>) -> LedgerPlan {
    let claimed = input.claimed;
    match input.publication {
        None => match prove_first_publication_chain(input.ledger_rows, claimed) {
            Ok(own_latest) => {
                if claimed.base_version != 0 {
                    LedgerPlan::Quarantine {
                        reason: "code=auth_projector.first_publication_requires_initial_chain"
                            .to_owned(),
                    }
                } else {
                    LedgerPlan::FirstPublication {
                        own_latest: Box::new(own_latest),
                    }
                }
            }
            Err(reason) => {
                // The None-arm proof only fails on durable contradictions
                // (missing/unreadable own revision, chain gap, field drift) —
                // all terminal Quarantine. Sibling initial chains no longer
                // block: each grant publishes through its own claim.
                LedgerPlan::Quarantine { reason }
            }
        },
        Some(publication) => {
            let frontier = &publication.frontier;
            let partition = match partition_ledger_at_published_frontier(
                input.ledger_rows,
                frontier,
                std::slice::from_ref(&claimed.event_id),
            ) {
                Ok(partition) => partition,
                Err(error) => {
                    return LedgerPlan::Quarantine {
                        reason: format!("code=auth_projector.partition_corrupt;error={error}"),
                    };
                }
            };
            match locate_claimed_candidate(&partition, &claimed.event_id) {
                LocatedCandidate::Found(candidate_entry) => {
                    if let Err(reason) = verify_candidate_matches_claimed(candidate_entry, claimed)
                    {
                        return LedgerPlan::Quarantine { reason };
                    }
                    // Per-grant successor rule: this claim must sit DIRECTLY
                    // above its own grant's last frontier-proven target (zero
                    // when the grant has never published). The AGGREGATE
                    // generation of the pointer stays untouched here.
                    let expected_base_version = frontier
                        .events
                        .iter()
                        .rev()
                        .find(|event| event.grant_id == claimed.grant_id)
                        .map_or(0, |event| event.delta_target_version);
                    if claimed.base_version != expected_base_version {
                        return LedgerPlan::Quarantine {
                            reason: format!(
                                "code=auth_projector.per_grant_chain_gap;base={};expected={expected_base_version}",
                                claimed.base_version
                            ),
                        };
                    }
                    LedgerPlan::Continuation {
                        base_entries: partition
                            .published_heads
                            .iter()
                            .map(|head| head.entry.clone())
                            .collect(),
                    }
                }
                LocatedCandidate::BehindUnpublishedSiblings => LedgerPlan::Blocked {
                    reason: format!(
                        "code=auth_projector.claimed_behind_unpublished_siblings;grant={}",
                        claimed.grant_id
                    ),
                },
                LocatedCandidate::StaleBehindPublishedFrontier => LedgerPlan::Quarantine {
                    reason: format!(
                        "code=auth_projector.stale_claim_behind_published_frontier;grant={}",
                        claimed.grant_id
                    ),
                },
                LocatedCandidate::MissingFromLedger => LedgerPlan::Quarantine {
                    reason: "code=auth_projector.own_revision_missing".to_owned(),
                },
                LocatedCandidate::Ambiguous | LocatedCandidate::OwnClaimNotRecognized => {
                    LedgerPlan::Quarantine {
                        reason: format!(
                            "code=auth_projector.partition_candidate_ambiguous;event={}",
                            claimed.event_id
                        ),
                    }
                }
            }
        }
    }
}

/// Reconstruct the producer-side dependency vector from durable claimed fields.
///
/// Producers bind one contribution to its CARD batch identity through
/// `card:{card_id}` + (generation, fence). Reconstruction is verified against
/// the stored dependency hash; any mismatch means the delta was not written by
/// the documented producer shape and refuses to proceed (fail-closed).
pub(crate) fn reconstruct_dependency_vector(
    claimed_card_id: Option<i64>,
    source_generation: u64,
    revoke_fence: u64,
) -> Result<(DependencyVector, String), String> {
    let Some(card_id) = claimed_card_id else {
        return Err("code=auth_projector.card_scoped_dependency_required".to_owned());
    };
    let version =
        DependencyVersion::new(format!("card:{card_id}"), source_generation, revoke_fence)
            .map_err(|error| {
                format!("code=auth_projector.dependency_version_invalid;error={error}")
            })?;
    let vector = DependencyVector::new(vec![version])
        .map_err(|error| format!("code=auth_projector.dependency_vector_invalid;error={error}"))?;
    let hash = vector
        .canonical_hash()
        .map_err(|error| format!("code=auth_projector.dependency_hash_failed;error={error}"))?;
    Ok((vector, hash))
}

#[allow(dead_code)]
pub(crate) fn claimed_tenant(claimed: &ClaimedDeltaEvent) -> Result<TenantScope, String> {
    TenantScope::new(claimed.tenant_id, claimed.card_id)
        .map_err(|error| format!("code=auth_projector.tenant_scope_invalid;error={error}"))
}

pub(crate) fn claimed_deltas(
    claimed: &ClaimedDeltaEvent,
) -> Result<Vec<astral_types::GrantDelta>, String> {
    std::iter::once(decode_delta_event_payload(&claimed.delta_json))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("code=auth_projector.delta_payload_invalid;error={error}"))
}

/// Shared compile gate: the producer compiler version must be recognized and
/// the claimed delta payload must decode before ANY branch is taken.
pub(crate) fn prepare_compile_inputs(
    input: &EventDecisionInput<'_>,
) -> Result<Vec<astral_types::GrantDelta>, String> {
    let claimed = input.claimed;
    let compiler = AuthorizationCompiler::new();
    if compiler.compiler_version() != claimed.compiler_version {
        return Err(format!(
            "code=auth_projector.unsupported_producer_compiler;expected={};claimed={}",
            compiler.compiler_version(),
            claimed.compiler_version
        ));
    }
    let deltas = claimed_deltas(claimed)?;
    if deltas.is_empty() {
        return Err("code=auth_projector.delta_payload_empty".to_owned());
    }
    Ok(deltas)
}

/// Deterministic REPLAY/oracle candidate for a first publication.
///
/// An honest first publication cannot fabricate a base hot state at version 0
/// and must not invent a misleading full-rebuild reason: the sanctioned oracle
/// rebuilds generation 1 directly from the proven initial ledger chain while
/// the claimed delta payload was only proven decodable above (the ledger truth
/// it describes IS the input, so applying it once more would double-apply).
pub(crate) fn assemble_first_publication_candidate(
    input: &EventDecisionInput<'_>,
    own_latest: &GrantLedgerEntry,
    dependency_vector: &DependencyVector,
) -> Result<Result<AssembledCandidate, CompilerConflict>, String> {
    let claimed = input.claimed;
    // Both entry points refuse an inconsistent first delta near the compiler,
    // even after future refactors of the planning layer.
    if claimed.base_version != 0 {
        return Err("code=auth_projector.first_publication_requires_initial_chain".to_owned());
    }
    let Some(target_generation) = 0u64.checked_add(1) else {
        return Err("code=auth_projector.generation_overflow".to_owned());
    };
    let _deltas_proven_decodable = prepare_compile_inputs(input)?;
    // F3 e2e fix: the hot-state tenant scope must come from the proven ledger
    // grant itself (claimed_tenant fabricated domain_id from card_id, which
    // rejected every legitimate first publication with a domain-scoped grant).
    let tenant = own_latest.grant.tenant.clone();
    let candidate = FullCompilerOracle::new()
        .rebuild_from_grants(
            tenant,
            target_generation,
            std::iter::once(own_latest.grant.clone()),
            dependency_vector.clone(),
        )
        .map_err(|error| {
            format!("code=auth_projector.first_publication_rebuild_failed;error={error}")
        })?;
    Ok(Ok(AssembledCandidate {
        candidate,
        incremental: false,
        incremental_outcome: None,
        full_rebuild_reason: None,
        base: None,
    }))
}

/// Incremental (and explicit-full-oracle fallback) candidate over the
/// frontier-proven published heads.
///
/// Base construction binds THREE domains that must never be mixed up:
/// - the HotState VERSION is the aggregate generation `G` locked by the
///   observed frontier pointer (`G + 1` becomes the target);
/// - the per-grant projection window lives ONLY in the claimed/base-target
///   expectation fields and in the per-grant successor rule already enforced
///   during partition planning;
/// - the dependency vector reuses the documented producer reconstruction for
///   this event's card batch (`card:{id}` @ source_generation/fence), whose
///   stored hash was verified against the claim — keeping candidate lineage
///   consistent with what the publish CAS pins.
///
/// `FullRebuildRequired` resolves by running the sanctioned full oracle ON THE
/// SAME VERIFIED base (reason kept as evidence); never by silently relabeling
/// the outcome or rebuilding from an unverified wider input.
#[allow(clippy::too_many_lines)]
pub(crate) fn assemble_continuation_candidate(
    input: &EventDecisionInput<'_>,
    base_generation: u64,
    base_entries: &[GrantLedgerEntry],
    dependency_vector: &DependencyVector,
) -> Result<Result<AssembledCandidate, CompilerConflict>, String> {
    let claimed = input.claimed;
    if base_generation == 0 {
        return Err("code=auth_projector.continuation_requires_published_frontier".to_owned());
    }
    let Some(target_generation) = base_generation.checked_add(1) else {
        return Err("code=auth_projector.generation_overflow".to_owned());
    };
    let deltas = prepare_compile_inputs(input)?;
    // F3 e2e fix: same misderived-scope issue as the first-publication path —
    // derive the aggregate hot-state tenant from the proven base entries
    // (fallback: the claimed Add delta grant scope) instead of card_id-as-domain.
    let tenant = base_entries
        .first()
        .map(|entry| entry.grant.tenant.clone())
        .or_else(|| match claimed_deltas(claimed).ok()?.into_iter().next()? {
            astral_types::GrantDelta::Add { grant } => Some(grant.tenant.clone()),
            _ => None,
        })
        .ok_or_else(|| "code=auth_projector.continuation_tenant_unavailable".to_owned())?;
    let base = hot_state_from_entries(
        &tenant,
        base_generation,
        dependency_vector.clone(),
        claimed.compiler_version.clone(),
        base_entries,
    )
    .map_err(|error| format!("code=auth_projector.base_state_build_failed;error={error}"))?;
    let compiler = AuthorizationCompiler::new();
    match compiler.compile_incremental(&base, target_generation, dependency_vector.clone(), deltas)
    {
        Ok(CompileOutcome::Applied(compiled)) => {
            if compiled.target_version != target_generation
                || compiled.state.version != target_generation
            {
                return Err("code=auth_projector.compile_version_fence_broken".to_owned());
            }
            Ok(Ok(AssembledCandidate {
                candidate: compiled.state.clone(),
                incremental: true,
                incremental_outcome: Some(compiled),
                full_rebuild_reason: None,
                base: Some(base),
            }))
        }
        Ok(CompileOutcome::FullRebuildRequired(required)) => {
            let rebuilt = compiler.full_rebuild(
                &base,
                target_generation,
                dependency_vector.clone(),
                claimed_deltas(claimed)?,
            );
            let outcome = match rebuilt
                .map_err(|error| format!("code=auth_projector.full_rebuild_failed;error={error}"))?
            {
                CompileOutcome::Applied(compiled) => compiled,
                CompileOutcome::FullRebuildRequired(inner) => {
                    return Err(format!(
                        "code=auth_projector.full_rebuild_stuck;reason={:?}",
                        inner.reason
                    ));
                }
                CompileOutcome::Conflict(conflict) => return Ok(Err(conflict)),
            };
            Ok(Ok(AssembledCandidate {
                candidate: outcome.state.clone(),
                incremental: false,
                incremental_outcome: Some(outcome),
                full_rebuild_reason: Some(required.reason),
                base: Some(base),
            }))
        }
        Ok(CompileOutcome::Conflict(conflict)) => Ok(Err(conflict)),
        Err(error) => Err(format!("code=auth_projector.compile_error;error={error}")),
    }
}

/// Derive the stage segment plan from the candidate hot state.
///
/// With `Some(parent references)` a candidate segment whose canonical payload
/// digest equals an UNUSED parent reference digest reuses that exact ordinal:
/// matching is digest-based (never positional inference) and content-safe, and
/// the staging transaction still re-verifies the referenced row under lock.
/// Without references — today's production reality, see module-gap notes —
/// every entry is [`StagedSegmentContent::New`]: identical payloads dedupe onto
/// the same content-addressed segment row, nothing is deleted or rewritten.
pub(crate) fn plan_stage_segments(
    candidate: &HotState,
    parent_references: Option<&[(u64, ParentReferenceView)]>,
) -> Result<Vec<StagedSegmentContent>, String> {
    let mut plan: Vec<StagedSegmentContent> = Vec::with_capacity(candidate.segments.len());
    for (_key, segment) in candidate.segments.iter() {
        let payload = astral_db::encode_segment_payload(&segment.grants)
            .map_err(|error| format!("code=auth_projector.segment_encode_failed;error={error}"))?;
        let digest_hex = hex_lower(&Sha256::digest(&payload));
        let mut reused: Option<u64> = None;
        if let Some(references) = parent_references {
            for (ordinal, view) in references {
                if view.content_digest_hex != digest_hex {
                    continue;
                }
                let ordinal_claimed = plan.iter().any(|entry| match entry {
                    StagedSegmentContent::ReuseParent { parent_ordinal } => {
                        parent_ordinal == ordinal
                    }
                    StagedSegmentContent::New(_) => false,
                });
                if !ordinal_claimed {
                    reused = Some(*ordinal);
                    break;
                }
            }
        }
        match reused {
            Some(parent_ordinal) => plan.push(StagedSegmentContent::ReuseParent { parent_ordinal }),
            None => plan.push(StagedSegmentContent::New(
                segment.grants.as_slice().to_vec(),
            )),
        }
    }
    Ok(plan)
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Synthesize impact items for a REPLAY/oracle candidate directly from
/// key-level compiler hashes. `before` reuses the base state's own recorded
/// hash when that key existed — evidence is never invented.
pub(crate) fn synthesize_replay_items(
    candidate: &HotState,
    base: Option<&HotState>,
) -> Result<Vec<AuthorizationImpactItemInput>, String> {
    let mut items = Vec::with_capacity(candidate.segments.len());
    for (key, segment) in candidate.segments.iter() {
        let projection_key = key.canonical_input().map_err(|error| {
            format!("code=auth_projector.projection_key_canonicalization;error={error}")
        })?;
        let before_digest_hex = base
            .and_then(|state| state.segment_content(key))
            .map(|content| content.content_hash.clone());
        items.push(AuthorizationImpactItemInput {
            projection_key,
            item_type: AuthorizationImpactItemType::SegmentUpsert,
            grant_id: None,
            before_digest_hex,
            after_digest_hex: Some(segment.content_hash.clone()),
        });
    }
    Ok(items)
}

pub(crate) fn classify_compiler_conflict(conflict: &CompilerConflict) -> EventDisposition {
    // Already-applied signatures indicate either a previous successful attempt
    // of THIS event or reflected sibling state; even with a proven frontier,
    // neither can be re-derived locally once the compiler reports them, so
    // operator reconciliation wins over blind retries.
    let reason = format!("code=auth_projector.compile_conflict;conflict={conflict}");
    match conflict {
        CompilerConflict::DuplicateDelta { .. } | CompilerConflict::ExistingGrant { .. } => {
            EventDisposition::Quarantine { reason }
        }
        _ => EventDisposition::Retry { reason },
    }
}

/// Aggregate generation observed as the compile base: `0` only for a genuine
/// first publication (no pointer exists); otherwise the frontier pointer's
/// locked `current_generation`. NEVER mixed with per-grant versions.
pub(crate) fn publication_base_generation(input: &EventDecisionInput<'_>) -> u64 {
    input
        .publication
        .map_or(0u64, |context| context.frontier.pointer.current_generation)
}

/// Map an assembly-stage failure onto dispositions exactly like before: the
/// listed codes are deterministic divergence (terminal quarantine), everything
/// else stays transiently undecidable under the unified attempt budget.
///
/// Classification is EXACT-TOKEN over the stable machine code this module
/// itself embeds at every construction site (`code=auth_projector.<token>` up
/// to the first `;`). Dynamic detail after the `;` (embedded error displays,
/// operator-supplied compiler versions, event ids …) can therefore never flip
/// the disposition — the failure mode of the previous `reason.contains(...)`
/// matching.
pub(crate) fn classify_compile_stage_error(reason: String) -> EventDisposition {
    match AssemblyStageCode::from_reason(&reason) {
        Some(code) if code.is_deterministic_divergence() => EventDisposition::Quarantine { reason },
        // Unknown/unparseable codes keep the bounded-retry default: no
        // deterministic divergence has been proven for this event.
        _ => EventDisposition::Retry { reason },
    }
}

/// Stable machine codes of the assembly stage that prove DETERMINISTIC
/// divergence. Single-sourced here so the constructor sites and the
/// classifier can never drift apart; every reason this module builds starts
/// with `code=auth_projector.<token>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AssemblyStageCode {
    UnsupportedProducerCompiler,
    GenerationOverflow,
    FirstPublicationRequiresInitialChain,
    FullRebuildStuck,
    CompileVersionFenceBroken,
    FirstPublicationRebuildFailed,
    BaseStateBuildFailed,
    ContinuationRequiresPublishedFrontier,
}

impl AssemblyStageCode {
    /// Exact-token parse of the leading machine code. Returns `None` for any
    /// reason whose FIRST token is not one of the enumerated codes — detail
    /// text is never scanned.
    fn from_reason(reason: &str) -> Option<Self> {
        let token = reason
            .strip_prefix("code=auth_projector.")?
            .split(';')
            .next()?;
        Some(match token {
            "unsupported_producer_compiler" => Self::UnsupportedProducerCompiler,
            "generation_overflow" => Self::GenerationOverflow,
            "first_publication_requires_initial_chain" => {
                Self::FirstPublicationRequiresInitialChain
            }
            "full_rebuild_stuck" => Self::FullRebuildStuck,
            "compile_version_fence_broken" => Self::CompileVersionFenceBroken,
            "first_publication_rebuild_failed" => Self::FirstPublicationRebuildFailed,
            "base_state_build_failed" => Self::BaseStateBuildFailed,
            "continuation_requires_published_frontier" => {
                Self::ContinuationRequiresPublishedFrontier
            }
            _ => return None,
        })
    }

    /// Deterministic divergence: the same claimed inputs reproduce this
    /// outcome on every attempt, so retries are futile and the event goes to
    /// terminal quarantine (attempt-budget independent).
    const fn is_deterministic_divergence(self) -> bool {
        matches!(
            self,
            Self::UnsupportedProducerCompiler
                | Self::GenerationOverflow
                | Self::FirstPublicationRequiresInitialChain
                | Self::FullRebuildStuck
                | Self::CompileVersionFenceBroken
                | Self::FirstPublicationRebuildFailed
                | Self::BaseStateBuildFailed
                | Self::ContinuationRequiresPublishedFrontier
        )
    }
}

/// Map a publish-transaction failure onto the retry taxonomy (pure, pinned by
/// unit tests).
pub(crate) enum PublishFailureHandling {
    /// The live publication pointer moved between planning and the publish
    /// transaction. The orchestrator replans in-place under the same lease a
    /// bounded number of times before falling back to the normal retry budget.
    PointerMoved { reason: String },
    /// Our lease died mid-flight; NOTHING may be mutated for this event.
    LeaseLost { reason: String },
    /// Commit is unknown; no further writes are allowed.
    PublicationUnknown { reason: String },
    /// Commit is proven, but local installation requires recovery.
    CommittedMirrorUnavailable { reason: String },
    /// Immutable divergence needing operator review.
    ImmutableDivergence { reason: String },
    /// Byte-identical segment content already exists but was stamped by a
    /// different producer compiler version
    /// ([`astral_db::SEGMENT_COMPILER_STAMP_DIVERGENCE_CODE`]). Deterministic
    /// Phase 1 modeling limit — NOT durable corruption: the payload is proven
    /// intact, so the conservative outcome is terminal quarantine with a
    /// dedicated machine code and operator stamp-ownership reconciliation.
    /// Nothing invalid can ever be published this way because nothing is
    /// published at all.
    CompilerStampDivergence { reason: String },
    /// Publication refused on UNPROVEN history evidence: the locked current
    /// pointer predates the durable proof latch, so astral-db refuses with
    /// `AuthorizationProjectionError::NotReady` carrying the stable machine
    /// code `backfill_or_rehearsal_required`. Not event corruption, not
    /// self-healing by immediate retry, but recoverable by an explicit
    /// operator backfill/rehearsal pass that installs a proof-bearing
    /// pointer. The event stays PENDING under the bounded attempt budget
    /// (max-cap backoff once exhausted) instead of burning a terminal
    /// quarantine on a condition an operator resolves.
    Blocked { reason: String },
    /// Everything else (transient DB faults included) backs off normally.
    GenericRetry { reason: String },
}

/// Exact leading `code=authorization_projection.<token>` of an embedded
/// repository machine code; detail after the first `;` is never scanned.
pub(crate) fn projection_machine_code(message: &str) -> Option<&str> {
    message
        .strip_prefix("code=authorization_projection.")?
        .split(';')
        .next()
}

pub(crate) fn classify_publish_failure(error: &RuntimeAccessError) -> PublishFailureHandling {
    let rendered = error.to_string();
    match error {
        RuntimeAccessError::PublicationUnknown(_) => {
            PublishFailureHandling::PublicationUnknown { reason: rendered }
        }
        RuntimeAccessError::CommittedMirrorUnavailable(_) => {
            PublishFailureHandling::CommittedMirrorUnavailable { reason: rendered }
        }
        // Query/connection trouble before commit stays under the attempt budget.
        RuntimeAccessError::Database(_) => {
            PublishFailureHandling::GenericRetry { reason: rendered }
        }
        RuntimeAccessError::Repository(rejection) => match rejection {
            // Typed grant-repository refusals (M2): a lost lease CAS
            // (heartbeat/completion/readback) or a claim race means UNKNOWN
            // ownership — zero further mutation, never a `fail_delta_event`.
            // Every other grant refusal (contract/scope/mapping) proves no
            // deterministic divergence and stays under the attempt budget.
            RepositoryRejection::Grant(grant) => match grant {
                astral_db::GrantRepositoryError::ClaimRace
                | astral_db::GrantRepositoryError::LeaseCasFailed(_) => {
                    PublishFailureHandling::LeaseLost { reason: rendered }
                }
                _ => PublishFailureHandling::GenericRetry { reason: rendered },
            },
            // Projector-side non-typed refusals carry no variant evidence; no
            // deterministic divergence is proven.
            RepositoryRejection::Other(_) => {
                PublishFailureHandling::GenericRetry { reason: rendered }
            }
            RepositoryRejection::Projection(projection) => {
                classify_projection_failure(projection, rendered)
            }
        },
    }
}

/// Typed variant mapping + stable machine codes, in one place. The mapping
/// preserves the prior substring router's outcome for every real
/// construction site while eliminating its failure modes (Display wording was
/// never a contract, and detail text could flip dispositions; the
/// `ClaimRace`/`DuplicateRow` arms were even unreachable against Display
/// text — they now classify by variant as originally intended).
pub(crate) fn classify_projection_failure(
    error: &AuthorizationProjectionError,
    rendered: String,
) -> PublishFailureHandling {
    match error {
        // Lease/CAS ownership evidence died mid-flight: unknown result, zero
        // further mutation. `ClaimRace` is variant-classified here (its
        // Display wording never contained the old `ClaimRace` needle).
        AuthorizationProjectionError::LeaseCasFailed(_)
        | AuthorizationProjectionError::ClaimRace => {
            PublishFailureHandling::LeaseLost { reason: rendered }
        }
        // The chain moved past our assumption (or the pointer/manifest pair
        // disagrees with the claimed world): fresh-world retry.
        AuthorizationProjectionError::CurrentPointerCasConflict(_)
        | AuthorizationProjectionError::IdentityMismatch(_) => {
            PublishFailureHandling::PointerMoved { reason: rendered }
        }
        // Publish-precondition conflicts: only the two codes proving the chain
        // advanced are fast-abandon retries; everything else (fence/semantics/
        // compiler expectation mismatches) stays under the attempt budget.
        AuthorizationProjectionError::ManifestPublishConflict(message) => {
            match projection_machine_code(message) {
                Some("publish_generation_gap" | "publish_same_manifest") => {
                    PublishFailureHandling::PointerMoved { reason: rendered }
                }
                _ => PublishFailureHandling::GenericRetry { reason: rendered },
            }
        }
        // Not-ready mid-flight preconditions retry EXCEPT the codes that prove
        // the world moved or require operator repair of an unproven pointer.
        AuthorizationProjectionError::NotReady(message) => match projection_machine_code(message) {
            Some("backfill_or_rehearsal_required") => {
                PublishFailureHandling::Blocked { reason: rendered }
            }
            Some("stage_generation_gap" | "current_pointer_missing") => {
                PublishFailureHandling::PointerMoved { reason: rendered }
            }
            _ => PublishFailureHandling::GenericRetry { reason: rendered },
        },
        // The one mapping code proving generation space exhaustion routes with
        // the chain-advanced family; other mappings stay transient.
        AuthorizationProjectionError::Mapping(message) => match projection_machine_code(message) {
            Some("generation_overflow") => {
                PublishFailureHandling::PointerMoved { reason: rendered }
            }
            _ => PublishFailureHandling::GenericRetry { reason: rendered },
        },
        AuthorizationProjectionError::SegmentDigestCollision(message) => {
            match projection_machine_code(message) {
                // Proven-intact payload with a diverging compiler stamp: the
                // dedicated conservative path — terminal quarantine with its
                // own stable reason code, never labeled as corruption, and
                // never a publish.
                Some("segment_compiler_stamp_divergence") => {
                    PublishFailureHandling::CompilerStampDivergence {
                        reason: format!(
                            "code=auth_projector.compiler_stamp_divergence;error={rendered}"
                        ),
                    }
                }
                _ => PublishFailureHandling::ImmutableDivergence { reason: rendered },
            }
        }
        // Deterministic immutable-history divergence family: these recur
        // identically on every attempt, so they go to terminal quarantine
        // regardless of the attempt budget. `DuplicateRow` is variant-
        // classified (the old `DuplicateRow` needle could never match its
        // Display wording); its `manifest_identity_conflict` construction is
        // deterministic divergence, as are every unproven unique-race winner
        // and the immutable replay conflicts.
        AuthorizationProjectionError::ImmutableConflict(_)
        | AuthorizationProjectionError::DuplicateRow(_) => {
            PublishFailureHandling::ImmutableDivergence { reason: rendered }
        }
        // Corrupt durable evidence is deterministic divergence and therefore
        // terminal quarantine; unproven history is handled by the NotReady arm.
        AuthorizationProjectionError::Corrupt(_) => {
            PublishFailureHandling::ImmutableDivergence { reason: rendered }
        }
        // No deterministic divergence proven by variant or machine code:
        // bounded-retry default (contract/scope/mapping refusals, illegal
        // transitions, generic state gaps).
        AuthorizationProjectionError::Contract(_)
        | AuthorizationProjectionError::IllegalStatusTransition { .. } => {
            PublishFailureHandling::GenericRetry { reason: rendered }
        }
        AuthorizationProjectionError::ScopeViolation(message) => {
            match projection_machine_code(message) {
                // The publish transaction re-checks the authoritative pointer after
                // planning. A generation mismatch proves only that another valid
                // publisher won the race; it is a fresh-world replan, not a generic
                // infrastructure failure or deterministic corruption.
                Some("command_base_generation_mismatch") => {
                    PublishFailureHandling::PointerMoved { reason: rendered }
                }
                _ => PublishFailureHandling::GenericRetry { reason: rendered },
            }
        }
        // Defensive: `Query` never survives the `From` conversion, but the
        // transient default keeps any future construction fail-safe.
        AuthorizationProjectionError::Query(_) => {
            PublishFailureHandling::GenericRetry { reason: rendered }
        }
    }
}

/// Pure top-level decision for one claimed event.
pub(crate) fn decide_event_disposition(input: &EventDecisionInput<'_>) -> EventDisposition {
    let claimed = input.claimed;
    if claimed.event_type == DeltaEventType::Revoke && claimed.revoke_fence == 0 {
        return EventDisposition::Quarantine {
            reason: "code=auth_projector.revoke_without_fence_progress".to_owned(),
        };
    }

    // 1. Dependency vector reconstruction + stored-hash verification.
    let (dependency_vector, dependency_hash_hex) = match reconstruct_dependency_vector(
        claimed.card_id,
        claimed.source_generation,
        claimed.revoke_fence,
    ) {
        Ok(pair) => pair,
        Err(reason) => return EventDisposition::Quarantine { reason },
    };
    if dependency_hash_hex != claimed.dependency_hash.as_hex() {
        return EventDisposition::Quarantine {
            reason: format!(
                "code=auth_projector.dependency_hash_drift;stored={};reconstructed={dependency_hash_hex}",
                claimed.dependency_hash.as_hex()
            ),
        };
    }

    // 2. Publication-aware ledger partition: proves which effects are already
    //    covered by the published frontier chain and which sibling tails stay
    //    OUT of the compiled base. Terminal corruption never becomes Retry.
    let ledger_plan = plan_ledger_against_publication(input);

    // 3. Compile the candidate (pure, outside any transaction). Compiler
    //    conflicts propagate verbatim to their own classification layer.
    let assembly_outcome = match &ledger_plan {
        LedgerPlan::Blocked { reason } => {
            return EventDisposition::Blocked {
                reason: reason.clone(),
            }
        }
        LedgerPlan::Quarantine { reason } => {
            return EventDisposition::Quarantine {
                reason: reason.clone(),
            }
        }
        LedgerPlan::FirstPublication { own_latest } => {
            assemble_first_publication_candidate(input, own_latest, &dependency_vector)
        }
        LedgerPlan::Continuation { base_entries, .. } => {
            let base_generation = publication_base_generation(input);
            assemble_continuation_candidate(
                input,
                base_generation,
                base_entries,
                &dependency_vector,
            )
        }
    };
    let assembled = match assembly_outcome {
        Ok(Ok(assembled)) => assembled,
        Ok(Err(conflict)) => return classify_compiler_conflict(&conflict),
        Err(reason) => return classify_compile_stage_error(reason),
    };

    let base_generation = publication_base_generation(input);
    let target_generation = match base_generation.checked_add(1) {
        Some(next) => next,
        None => {
            return EventDisposition::Quarantine {
                reason: "code=auth_projector.generation_overflow".to_owned(),
            }
        }
    };

    // 4. Impact plan inputs (non-empty is enforced here and downstream again).
    //
    // Both continuation arms map their items from the compiler outcome's
    // `ImpactPlan` instead of synthesizing them; plan coverage differs by arm:
    // - the FULL-REBUILD continuation runs the sanctioned oracle, whose plan
    //   covers `candidate ∪ base ∪ known` keys — so a segment the compile
    //   REMOVED from the base (e.g. a revoked type-level wildcard that was
    //   the grant's only Active contribution) maps to a `SegmentRemove` item
    //   carrying the base digest as `before` and no `after`;
    // - the INCREMENTAL outcome's plan covers only the deltas' known-affected
    //   keys, and every legal delta changes at least one of them (the grant
    //   revision is part of the segment content hash; `Add` payloads must be
    //   Active, tombstone-carrying Adds are refused at the decode gate), so
    //   its mapped items are never empty.
    // Mapping the plan is evidence-preserving: unchanged segments produce no
    // item and a vanished key can never be synthesized away. The key-level
    // synthesis fallback only walks `candidate.segments` and therefore cannot
    // see vanished keys; it stays reserved for the first-publication REPLAY,
    // which has no compiler plan and no base to remove from (a tombstone seed
    // first publication keeps its empty-impact QUARANTINE — no empty
    // generation is published here).
    let impact_items = match (&assembled.incremental, &assembled.incremental_outcome) {
        (_, Some(outcome)) => {
            match impact_plan_request_from_compiler_plan(
                input.identity.clone(),
                claimed.card_id,
                claimed.event_id.clone(),
                claimed.operation_id.clone(),
                base_generation,
                target_generation,
                claimed.base_version,
                claimed.target_version,
                claimed.semantic_hash.as_hex(),
                claimed.dependency_hash.as_hex(),
                claimed.compiler_version.clone(),
                &outcome.plan,
            ) {
                Ok(request) => request.items,
                Err(error) => {
                    return EventDisposition::Quarantine {
                        reason: format!(
                            "code=auth_projector.impact_plan_mapping_failed;error={error}"
                        ),
                    }
                }
            }
        }
        // First-publication REPLAY: no compiler plan exists and no base from
        // which a segment could vanish; synthesize from the oracle-rebuilt
        // candidate only. An oracle-rebuilt tombstone seed yields an empty
        // candidate and therefore the empty-impact quarantine below stays the
        // contract-consistent terminal outcome (never an empty publication).
        (false, None) => {
            match synthesize_replay_items(&assembled.candidate, assembled.base.as_ref()) {
                Ok(items) => items,
                Err(reason) => return EventDisposition::Quarantine { reason },
            }
        }
        // Unreachable by construction (an incremental application always
        // carries its Applied outcome); fail closed instead of guessing.
        (true, None) => {
            return EventDisposition::Quarantine {
                reason: "code=auth_projector.impact_outcome_missing".to_owned(),
            }
        }
    };
    if impact_items.is_empty() {
        // Every affected segment came out unchanged ⇒ the effect already sits
        // inside the reconstructed candidate. Publishing would create an
        // immutable no-op manifest; operator reconciliation decides instead
        // (mirror of the legacy AlreadyCurrent nuance, without faking success).
        return EventDisposition::Quarantine {
            reason: "code=auth_projector.no_effective_change".to_owned(),
        };
    }

    // 5. Stage segments + publish command assembly. Observed parent
    //    references are PLANNING HINTS for digest-based reuse; the staging
    //    transaction re-locks the pointer + parent chain and re-verifies every
    //    reference before any reuse becomes durable, and a pointer that moved
    //    in between maps to a fast PointerMoved retry.
    let parent_references: Option<&[(u64, ParentReferenceView)]> = input
        .publication
        .map(|context| context.parent_references.as_slice());
    let stage_segments = match plan_stage_segments(&assembled.candidate, parent_references) {
        Ok(segments) => segments,
        Err(reason) => return EventDisposition::Quarantine { reason },
    };

    // The authoritative previous fence comes from the observed frontier
    // pointer (`None` ⇒ 0 first-publication sentinel); the publish
    // transaction re-reads it under lock and refuses stale evidence.
    let previous_revoke_fence = input
        .publication
        .map_or(0, |context| context.frontier.pointer.revoke_fence);
    let new_revoke_fence = previous_revoke_fence.max(claimed.revoke_fence);

    EventDisposition::Publish(Box::new(DeltaProjectorPublishCommand {
        delta_lease_identity: DeltaLeaseIdentity {
            delta_event_id: claimed.delta_event_id,
            event_id: claimed.event_id.clone(),
            lease_owner: claimed.lease_owner.clone(),
            // Secret replaced by the orchestrator from the live claim before
            // any execution; the pure assembler never sees tokens and uses the
            // always-available (not test-gated) placeholder constructor.
            lease_token: astral_db::DeltaLeaseToken::placeholder_for_assembly(),
        },
        expectation: DeltaProjectorExpectation {
            identity: input.identity.clone(),
            card_id: claimed.card_id,
            event_id: claimed.event_id.clone(),
            operation_id: claimed.operation_id.clone(),
            base_version: claimed.base_version,
            target_version: claimed.target_version,
            source_generation: claimed.source_generation,
            semantic_hash_hex: claimed.semantic_hash.as_hex(),
            dependency_hash_hex: claimed.dependency_hash.as_hex(),
            compiler_version: claimed.compiler_version.clone(),
        },
        fences: PublishRevokeFenceEvidence {
            previous_revoke_fence,
            new_revoke_fence,
        },
        mode: CompileModeEvidence {
            compile_mode: match (
                assembled.incremental,
                assembled.full_rebuild_reason.is_some(),
            ) {
                (true, _) => ProjectionCompileMode::Incremental,
                // ONLY a genuine compiler FullRebuildRequired outcome may
                // declare FULL_REBUILD mode, always paired with its reason.
                (false, true) => ProjectionCompileMode::FullRebuild,
                // First publication: deterministic ledger replay via the
                // sanctioned oracle, no invented fallback reason.
                (false, false) => ProjectionCompileMode::Replay,
            },
            full_rebuild_reason: assembled.full_rebuild_reason,
        },
        stage: AuthorizationStageRequest {
            identity: input.identity.clone(),
            card_id: claimed.card_id,
            target_generation,
            source_generation: claimed.source_generation,
            projected_generation: claimed.source_generation,
            event_id: claimed.event_id.clone(),
            operation_id: claimed.operation_id.clone(),
            semantic_hash_hex: claimed.semantic_hash.as_hex(),
            dependency_hash_hex: claimed.dependency_hash.as_hex(),
            compiler_version: claimed.compiler_version.clone(),
            revoke_fence: new_revoke_fence,
            segments: stage_segments,
        },
        finalize_expected_reference_count: None,
        impact_plan: AuthorizationImpactPlanAppendRequest {
            identity: input.identity.clone(),
            card_id: claimed.card_id,
            event_id: claimed.event_id.clone(),
            operation_id: claimed.operation_id.clone(),
            base_generation,
            target_generation,
            base_version: claimed.base_version,
            target_version: claimed.target_version,
            semantic_hash_hex: claimed.semantic_hash.as_hex(),
            dependency_hash_hex: claimed.dependency_hash.as_hex(),
            compiler_version: claimed.compiler_version.clone(),
            items: impact_items,
        },
        manifest_lease_owner: String::new(),
        manifest_lease_seconds: MAX_MANIFEST_LEASE_SECONDS.min(600),
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Orchestrator: claim → readback → observe → decide → publish/dispose, with
// monotonic per-phase timing and bounded retry accounting.
// ─────────────────────────────────────────────────────────────────────────────
