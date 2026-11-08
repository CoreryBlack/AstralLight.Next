//! Owner-scoped publication reconciliation; source writes are never replayed.
//!
//! Budget model (publication leg): one COMMITTED row per cycle; `attempts`
//! tracks CONSECUTIVE no-progress passes and is reset ONLY by a durable
//! per-scope progress checkpoint under the live lease, so a row that keeps
//! certifying new scopes can never structurally exhaust its budget, while a
//! stuck row still quarantines after [`MAX_ATTEMPTS`] failed passes. PUBLISHED
//! rows reconcile separately at a limited frequency and never consume the
//! certification attempt budget.

use super::empty_card_origin::reconcile_empty_card_origin;
use super::*;
use astral_authority::client::AuthorityClient;
use astral_types::{
    AuthorityMutationKind, AuthorityReservationState, AuthorityStagedSourceEvidence,
};
use sqlx::MySqlPool;

use crate::authority_source_outcome::AuthoritySourceOutcomeRecord;

mod history;

pub(super) async fn persist_authority_certificate(
    pool: &MySqlPool,
    certificate: &AuthorityScopePublicationCertificate,
) -> Result<(), PolicyError> {
    history::persist_certificate(pool, certificate).await?;
    Ok(())
}

use history::PersistOutcome;

/// One COMMITTED row per cycle: the certification window is bounded by the
/// shared cycle deadline, so per-pass progress stays observable and the
/// attempt budget tracks consecutive no-progress passes only.
const BATCH_SIZE: u32 = 1;
const MAX_ATTEMPTS: u32 = 24;
const LEASE_SECONDS: i64 = 30;
/// A pass that persisted at least one NEW durable record releases the lease
/// with a short reclaim backoff instead of waiting out the full lease.
const PROGRESS_RECLAIM_SECONDS: i64 = 2;
/// PUBLISHED rows wait for an operator-authorized close; they reconcile at a
/// limited frequency (lease backoff) and never consume the attempt budget.
const PUBLISHED_RECONCILE_SECONDS: i64 = 30;
const PUBLISHED_BATCH_SIZE: u32 = 1;
/// Hard bound for budget checkpoints per pass. Declared coverage admits at
/// most 256 scopes and each newly persisted scope fires at most one
/// checkpoint, so this cap can only bind on a contract violation.
const MAX_BUDGET_CHECKPOINTS_PER_PASS: u32 = 256;

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct PublicationReport {
    pub leased: u64,
    pub certified: u64,
    pub pending: u64,
    /// Budget checkpoints that fired after durable per-scope progress.
    pub budget_resets: u64,
    /// PUBLISHED reconciliation observations (reconcile-only leg).
    pub published_leased: u64,
    pub published_completed: u64,
    pub published_waiting: u64,
}

/// Per-pass progress accumulated by [`certify_row`]. `new_records` counts
/// NEW durable certificate records (history insertions and pointer advances);
/// `checkpoints` counts executed attempt-budget resets under the live lease.
#[derive(Debug, Default, Clone, Copy)]
struct PassProgress {
    new_records: u32,
    checkpoints: u32,
}

const COLUMNS: &str = "reservation_id, operation_id, event_id, admission_proof_id, request_binding_digest, \
    mutation_kind, service_id, database_id, source_commit_digest, before_image_digest, after_image_digest, \
    CAST(source_receipts AS CHAR) AS source_receipts, CAST(staged_evidence AS CHAR) AS staged_evidence, \
    status, attempts, generation, outcome_digest, committed_at";

pub(crate) async fn reconcile_publications(
    pool: &MySqlPool,
    client: &AuthorityClient,
    service_id: &str,
    database_id: &str,
    run_id: &str,
) -> Result<PublicationReport, PolicyError> {
    let owner = format!("publication/{run_id}");
    if owner.len() > 128 || run_id.is_empty() {
        return Err(pending("invalid publication run identity"));
    }
    let mut report = PublicationReport::default();
    // Only a source owner that recorded a finite coverage contract may enter
    // automatic certification. Unknown GLOBAL coverage remains operator-owned.
    let candidates: Vec<(String, u64, u32)> = sqlx::query_as(
        "SELECT reservation_id, generation, attempts FROM authority_source_outcome \
         WHERE status = 'COMMITTED' AND mutation_kind = 'AUTHORIZATION_SOURCE' \
         AND service_id = ? AND database_id = ? \
         AND JSON_TYPE(JSON_EXTRACT(staged_evidence, '$.coverage')) = 'OBJECT' \
         AND (lease_until IS NULL OR lease_until <= UNIX_TIMESTAMP()) \
         ORDER BY reservation_id LIMIT ?",
    )
    .bind(service_id)
    .bind(database_id)
    .bind(BATCH_SIZE)
    .fetch_all(pool)
    .await
    .map_err(pending)?;
    for (reservation_id, generation, attempts) in candidates {
        if attempts >= MAX_ATTEMPTS {
            sqlx::query("UPDATE authority_source_outcome SET status = 'QUARANTINED', \
                last_error = 'publication reconciliation budget exhausted; operator reconciliation required', \
                generation = generation + 1, lease_owner = NULL, lease_until = NULL, updated_at = UNIX_TIMESTAMP() \
                WHERE reservation_id = ? AND generation = ? AND status = 'COMMITTED' \
                AND service_id = ? AND database_id = ? AND attempts >= ? \
                AND (lease_until IS NULL OR lease_until <= UNIX_TIMESTAMP())")
                .bind(&reservation_id).bind(generation).bind(service_id).bind(database_id).bind(MAX_ATTEMPTS)
                .execute(pool).await.map_err(pending)?;
            continue;
        }
        let next_generation = generation
            .checked_add(1)
            .ok_or_else(|| pending("lease generation exhausted"))?;
        let claimed = sqlx::query("UPDATE authority_source_outcome SET lease_owner = ?, \
            lease_until = UNIX_TIMESTAMP() + ?, generation = generation + 1, attempts = attempts + 1, \
            updated_at = UNIX_TIMESTAMP() WHERE reservation_id = ? AND generation = ? AND status = 'COMMITTED' \
            AND service_id = ? AND database_id = ? AND attempts < ? \
            AND (lease_until IS NULL OR lease_until <= UNIX_TIMESTAMP())")
            .bind(&owner).bind(LEASE_SECONDS).bind(&reservation_id).bind(generation)
            .bind(service_id).bind(database_id).bind(MAX_ATTEMPTS).execute(pool).await.map_err(pending)?;
        if claimed.rows_affected() != 1 {
            continue;
        }
        report.leased += 1;
        let statement = format!(
            "SELECT {COLUMNS} FROM authority_source_outcome WHERE reservation_id = ? \
            AND service_id = ? AND database_id = ? AND status = 'COMMITTED' AND lease_owner = ? \
            AND generation = ? AND lease_until > UNIX_TIMESTAMP()"
        );
        let row: Option<crate::authority_source_outcome::AuthoritySourceOutcomeRow> =
            sqlx::query_as(&statement)
                .bind(&reservation_id)
                .bind(service_id)
                .bind(database_id)
                .bind(&owner)
                .bind(next_generation)
                .fetch_optional(pool)
                .await
                .map_err(pending)?;
        let Some(row) = row else {
            continue;
        };
        let phase = std::time::Instant::now();
        let fence = CertificationLease {
            pool,
            reservation_id: &reservation_id,
            service_id,
            database_id,
            owner: &owner,
            generation: next_generation,
        };
        let mut progress = PassProgress::default();
        match certify_row(&fence, client, &row, &mut progress).await {
            Ok(state) => {
                report.budget_resets += u64::from(progress.checkpoints);
                // Local terminal state requires a durable certificate for EVERY
                // declared scope. GLOBAL remains barrier-blocked at authority.
                let updated = sqlx::query("UPDATE authority_source_outcome SET status = ?, \
                    authority_disposition = ?, generation = generation + 1, lease_owner = NULL, lease_until = NULL, \
                    updated_at = UNIX_TIMESTAMP() WHERE reservation_id = ? AND status = 'COMMITTED' \
                    AND service_id = ? AND database_id = ? AND lease_owner = ? AND generation = ? \
                    AND lease_until > UNIX_TIMESTAMP() AND attempts <= ?")
                    .bind(if state == AuthorityReservationState::Certified { "COMPLETE" } else { "PUBLISHED" })
                    .bind(state.as_text()).bind(&reservation_id).bind(service_id).bind(database_id)
                    .bind(&owner).bind(next_generation).bind(MAX_ATTEMPTS).execute(pool).await.map_err(pending)?;
                if updated.rows_affected() == 1 {
                    report.certified += 1;
                }
            }
            Err(error) => {
                report.pending += 1;
                report.budget_resets += u64::from(progress.checkpoints);
                if progress.new_records > 0 {
                    // This pass durably advanced at least one scope: release the
                    // lease with a short reclaim backoff so the next pass starts
                    // promptly. Attempts were already reset at each checkpoint.
                    let released = sqlx::query("UPDATE authority_source_outcome SET lease_owner = NULL, \
                        lease_until = UNIX_TIMESTAMP() + ?, updated_at = UNIX_TIMESTAMP() \
                        WHERE reservation_id = ? AND status = 'COMMITTED' AND service_id = ? AND database_id = ? \
                        AND lease_owner = ? AND generation = ? AND lease_until > UNIX_TIMESTAMP()")
                        .bind(PROGRESS_RECLAIM_SECONDS).bind(&reservation_id).bind(service_id)
                        .bind(database_id).bind(&owner).bind(next_generation)
                        .execute(pool).await.map_err(pending)?;
                    if released.rows_affected() != 1 {
                        // The lease was lost mid-pass (expiry handover): natural
                        // lease expiry paces the reclaim; progress is durable.
                        tracing::debug!(reservation_id = %reservation_id, run_id,
                            "publication progress lease release lost the CAS; natural expiry paces reclaim");
                    }
                }
                // Without progress the lease stands: the row retries only after
                // DB-UTC lease expiry, keeping no-progress attempts bounded.
                tracing::warn!(reservation_id = %reservation_id, run_id, generation = next_generation,
                    attempt = attempts + 1, new_records = progress.new_records,
                    checkpoints = progress.checkpoints, elapsed_ms = phase.elapsed().as_millis(), error = %error,
                    "publication remains leased pending; reconcile before another certification attempt");
            }
        }
    }
    let (published_leased, published_completed, published_waiting) =
        reconcile_published_rows(pool, client, service_id, database_id, &owner).await?;
    report.published_leased = published_leased;
    report.published_completed = published_completed;
    report.published_waiting = published_waiting;
    if report.published_leased > 0 || report.budget_resets > 0 {
        tracing::info!(
            run_id,
            leased = report.leased,
            certified = report.certified,
            pending = report.pending,
            budget_resets = report.budget_resets,
            published_leased = report.published_leased,
            published_completed = report.published_completed,
            published_waiting = report.published_waiting,
            "publication reconciliation observations (certification budget is progress-reset, \
             PUBLISHED reconciliation is operator-close only)"
        );
    }
    Ok(report)
}

/// Live-lease fence for one claimed COMMITTED row. Every budget checkpoint is
/// CAS-guarded on status/owner/generation/unexpired-lease, so a worker that
/// lost ownership can never reset another worker's budget.
struct CertificationLease<'a> {
    pool: &'a MySqlPool,
    reservation_id: &'a str,
    service_id: &'a str,
    database_id: &'a str,
    owner: &'a str,
    generation: u64,
}

impl CertificationLease<'_> {
    /// Progress-budget checkpoint: zero the certification attempt budget and
    /// renew the lease, ONLY under the live lease fence and ONLY right after a
    /// NEW durable record was persisted. Bounded: at most one checkpoint per
    /// newly persisted scope (coverage <= 256) per pass.
    async fn reset_budget_after_progress(&self) -> Result<bool, PolicyError> {
        let updated = sqlx::query("UPDATE authority_source_outcome SET attempts = 0, \
            lease_until = UNIX_TIMESTAMP() + ?, updated_at = UNIX_TIMESTAMP() \
            WHERE reservation_id = ? AND status = 'COMMITTED' AND service_id = ? AND database_id = ? \
            AND lease_owner = ? AND generation = ? AND lease_until > UNIX_TIMESTAMP()")
            .bind(LEASE_SECONDS).bind(self.reservation_id).bind(self.service_id)
            .bind(self.database_id).bind(self.owner).bind(self.generation)
            .execute(self.pool).await.map_err(pending)?;
        Ok(updated.rows_affected() == 1)
    }
}

/// Checkpoint once per NEW durable record (bounded by the per-pass cap).
async fn record_progress(
    fence: &CertificationLease<'_>,
    progress: &mut PassProgress,
    outcome: PersistOutcome,
) -> Result<(), PolicyError> {
    if !outcome.is_progress() {
        return Ok(());
    }
    progress.new_records = progress.new_records.saturating_add(1);
    if progress.checkpoints >= MAX_BUDGET_CHECKPOINTS_PER_PASS {
        return Ok(());
    }
    if fence.reset_budget_after_progress().await? {
        progress.checkpoints += 1;
    }
    Ok(())
}

/// Exactly rebuilt durable source outcome shared by the certification and the
/// PUBLISHED reconciliation legs: the source outcome owner's promoted-record
/// verification (canonical self-digest over record + retained staged evidence,
/// exact per-leg status gate), plus the typed envelope with a declared finite
/// coverage. Source-specific publication owners decode and verify their own
/// retained artifacts after this shared durable row boundary.
struct VerifiedSourceOutcome {
    record: AuthoritySourceOutcomeRecord,
    envelope: AuthorityStagedSourceEvidence,
}

/// Verify one acknowledged source outcome row EXACTLY as durably stored for
/// the leg's expected status via the shared owner entry point, then enforce
/// the typed envelope with a declared finite coverage. A corrupted or foreign
/// row is never presented to the authority and never completed locally.
fn verify_durable_source_outcome(
    row: &crate::authority_source_outcome::AuthoritySourceOutcomeRow,
    expected_status: &str,
) -> Result<VerifiedSourceOutcome, PolicyError> {
    let record = row.to_verified_publication_record(expected_status)?;
    let envelope: AuthorityStagedSourceEvidence = serde_json::from_str(
        row.staged_evidence
            .as_deref()
            .ok_or_else(|| pending("retained source evidence missing"))?,
    )
    .map_err(pending)?;
    envelope.validate().map_err(pending)?;
    if envelope.coverage.is_none() {
        return Err(pending("finite affected scope coverage missing"));
    }
    Ok(VerifiedSourceOutcome { record, envelope })
}

async fn load_source_candidate_in_tx(
    tx: &mut Transaction<'_, MySql>,
    scope: &AuthorityProtocolScope,
    staged: &serde_json::Value,
    baseline: Option<&AuthorityScopePublicationCertificate>,
    empty_card_origin: Option<&super::empty_card_origin::VerifiedEmptyCardOrigin>,
) -> Result<AuthorityPublicationCandidate, PolicyError> {
    if staged.get("targets").is_some() {
        return super::identity::load_identity_candidate_in_tx(
            tx,
            scope,
            staged,
            baseline,
            empty_card_origin,
        )
        .await;
    }
    if matches!(scope, AuthorityProtocolScope::Org(_)) {
        return super::org::load_org_candidate_in_tx(tx, scope, staged, baseline).await;
    }
    let delta: DeltaSourceOutcomeEvidence =
        serde_json::from_value(staged.get("delta").unwrap_or(staged).clone()).map_err(pending)?;
    load_candidate_in_tx(tx, scope, &delta, baseline, empty_card_origin).await
}

/// Field-by-field authority commit binding check shared by both legs: the
/// echoed binding must be the exact durable row identity, the rebuilt record
/// identity/images, and the raw stored outcome/staged digests. A Certified
/// disposition alone never justifies local completion.
fn assert_exact_commit_binding(
    row: &crate::authority_source_outcome::AuthoritySourceOutcomeRow,
    record: &AuthoritySourceOutcomeRecord,
    binding: &astral_types::AuthorityCommitBinding,
) -> Result<(), PolicyError> {
    binding.validate().map_err(pending)?;
    if binding.reservation_id != record.reservation_id
        || binding.operation_id != record.operation_id
        || binding.event_id != record.event_id
        || binding.admission_proof_id != record.admission_proof_id
        || binding.mutation_kind != AuthorityMutationKind::AuthorizationSource
        || binding.service_id != record.service_id
        || binding.database_id != record.database_id
        || binding.request_digest != record.request_binding_digest
        || binding.source_commit_digest != record.source_commit_digest
        || binding.before_image_digest != record.before_image_digest
        || binding.after_image_digest != record.after_image_digest.clone().unwrap_or_default()
        || binding.source_outcome_digest != hex::encode(&row.outcome_digest)
        || binding.staged_evidence_digest != row.staged_digest()?
    {
        return Err(pending(
            "authority does not acknowledge the complete exact source binding",
        ));
    }
    Ok(())
}

async fn certify_row(
    fence: &CertificationLease<'_>,
    client: &AuthorityClient,
    row: &crate::authority_source_outcome::AuthoritySourceOutcomeRow,
    progress: &mut PassProgress,
) -> Result<AuthorityReservationState, PolicyError> {
    let pool = fence.pool;
    let verified = verify_durable_source_outcome(row, "COMMITTED")?;
    let scopes = verified
        .envelope
        .coverage
        .as_ref()
        .ok_or_else(|| pending("finite affected scope coverage missing"))?;
    let record = &verified.record;
    let reconciled = client
        .reconcile(record.reservation_id.clone(), record.operation_id.clone())
        .await
        .map_err(pending)?;
    let binding = reconciled
        .commit_binding
        .as_ref()
        .ok_or_else(|| pending("authority commit binding missing"))?;
    assert_exact_commit_binding(row, record, binding)?;
    let mut reservation = reconciled
        .reconciliation
        .reservation
        .ok_or_else(|| pending("authority reservation missing"))?;
    if !matches!(
        reservation.state,
        AuthorityReservationState::Committed
            | AuthorityReservationState::Published
            | AuthorityReservationState::Certified
    ) {
        return Err(pending(
            "authority does not acknowledge the complete exact source binding",
        ));
    }
    for scope in &scopes.scopes {
        let scope_key = scope.store_key_text().map_err(pending)?;
        if reservation.certified_scopes.contains(&scope_key) {
            let certificate = reconciled
                .certified_publications
                .iter()
                .find(|certificate| certificate.scope == *scope)
                .ok_or_else(|| pending("certified reservation scope record unavailable"))?;
            let outcome = history::persist_certificate(pool, certificate).await?;
            record_progress(fence, progress, outcome).await?;
            continue;
        }
        let current = client
            .read_fence(Some(scope.clone()), None, None)
            .await
            .map_err(pending)?;
        let new_card_insert = match scope {
            AuthorityProtocolScope::Card(card)
                if verified.envelope.evidence.get("targets").is_some() =>
            {
                let artifact: IdentityStagedEvidence =
                    serde_json::from_value(verified.envelope.evidence.clone()).map_err(pending)?;
                artifact.proves_new_card_insert(card)
            }
            _ => false,
        };
        let empty_card_origin = if current.scope_certificate.is_none() && !new_card_insert {
            match scope {
                AuthorityProtocolScope::Card(card) => {
                    reconcile_empty_card_origin(pool, client, card.tenant_id, card.card_id).await?
                }
                AuthorityProtocolScope::Org(_) => None,
            }
        } else {
            None
        };
        let mut tx = pool.begin().await.map_err(pending)?;
        let candidate = load_source_candidate_in_tx(
            &mut tx,
            scope,
            &verified.envelope.evidence,
            current.scope_certificate.as_ref(),
            empty_card_origin.as_ref(),
        )
        .await?;
        tx.rollback().await.map_err(pending)?;
        let request = candidate.request(
            astral_types::AuthorityCallerIdentity {
                service_id: record.service_id.clone(),
                request_nonce: uuid::Uuid::now_v7().to_string(),
                issued_at: time::OffsetDateTime::now_utc().unix_timestamp(),
            },
            &reservation,
            record,
            binding.source_outcome_digest.clone(),
            current.global_frontier.authority_id,
        )?;
        // No retries here: interruption leaves the lease and stable scope
        // identity intact. The next pass begins with authority reconciliation.
        let response = client.certify(request).await.map_err(pending)?;
        let outcome = history::persist_certificate(pool, &response.certificate).await?;
        record_progress(fence, progress, outcome).await?;
        reservation = response.reservation;
    }
    Ok(reservation.state)
}

/// Reconcile-only pass over locally PUBLISHED rows. These rows wait for an
/// operator-authorized close at the authority; this leg NEVER re-issues
/// certify or commit and never consumes the certification attempt budget.
/// Each row reconciles at a limited frequency via its lease backoff.
async fn reconcile_published_rows(
    pool: &MySqlPool,
    client: &AuthorityClient,
    service_id: &str,
    database_id: &str,
    owner: &str,
) -> Result<(u64, u64, u64), PolicyError> {
    let candidates: Vec<(String, u64)> = sqlx::query_as(
        "SELECT reservation_id, generation FROM authority_source_outcome \
         WHERE status = 'PUBLISHED' AND mutation_kind = 'AUTHORIZATION_SOURCE' \
         AND service_id = ? AND database_id = ? \
         AND JSON_TYPE(JSON_EXTRACT(staged_evidence, '$.coverage')) = 'OBJECT' \
         AND (lease_until IS NULL OR lease_until <= UNIX_TIMESTAMP()) \
         ORDER BY reservation_id LIMIT ?",
    )
    .bind(service_id)
    .bind(database_id)
    .bind(PUBLISHED_BATCH_SIZE)
    .fetch_all(pool)
    .await
    .map_err(pending)?;
    let mut leased = 0_u64;
    let mut completed = 0_u64;
    let mut waiting = 0_u64;
    for (reservation_id, generation) in candidates {
        // The claim deliberately does NOT touch `attempts`: PUBLISHED rows are
        // an operator-close waiting state, not a certification retry budget.
        let next_generation = generation
            .checked_add(1)
            .ok_or_else(|| pending("lease generation exhausted"))?;
        let claimed = sqlx::query("UPDATE authority_source_outcome SET lease_owner = ?, \
            lease_until = UNIX_TIMESTAMP() + ?, generation = generation + 1, updated_at = UNIX_TIMESTAMP() \
            WHERE reservation_id = ? AND status = 'PUBLISHED' AND generation = ? \
            AND service_id = ? AND database_id = ? \
            AND (lease_until IS NULL OR lease_until <= UNIX_TIMESTAMP())")
            .bind(owner).bind(LEASE_SECONDS).bind(&reservation_id).bind(generation)
            .bind(service_id).bind(database_id).execute(pool).await.map_err(pending)?;
        if claimed.rows_affected() != 1 {
            continue;
        }
        leased += 1;
        let statement = format!(
            "SELECT {COLUMNS} FROM authority_source_outcome WHERE reservation_id = ? \
            AND service_id = ? AND database_id = ? AND status = 'PUBLISHED' AND lease_owner = ? \
            AND generation = ? AND lease_until > UNIX_TIMESTAMP()"
        );
        let row: Option<crate::authority_source_outcome::AuthoritySourceOutcomeRow> =
            sqlx::query_as(&statement)
                .bind(&reservation_id)
                .bind(service_id)
                .bind(database_id)
                .bind(owner)
                .bind(next_generation)
                .fetch_optional(pool)
                .await
                .map_err(pending)?;
        let Some(row) = row else {
            continue;
        };
        match confirm_published_row(pool, client, &row).await {
            Ok(true) => {
                let updated = sqlx::query("UPDATE authority_source_outcome SET status = 'COMPLETE', \
                    authority_disposition = ?, generation = generation + 1, lease_owner = NULL, lease_until = NULL, \
                    updated_at = UNIX_TIMESTAMP() WHERE reservation_id = ? AND status = 'PUBLISHED' \
                    AND service_id = ? AND database_id = ? AND lease_owner = ? AND generation = ? \
                    AND lease_until > UNIX_TIMESTAMP()")
                    .bind(AuthorityReservationState::Certified.as_text()).bind(&reservation_id)
                    .bind(service_id).bind(database_id).bind(owner).bind(next_generation)
                    .execute(pool).await.map_err(pending)?;
                if updated.rows_affected() == 1 {
                    completed += 1;
                }
            }
            Ok(false) => {
                waiting += 1;
                release_published_lease(pool, &reservation_id, owner, next_generation).await?;
            }
            Err(error) => {
                // A failed reconcile never fails the whole leg: the row stays
                // PUBLISHED and retries after the bounded backoff.
                waiting += 1;
                release_published_lease(pool, &reservation_id, owner, next_generation).await?;
                tracing::warn!(reservation_id = %reservation_id, generation = next_generation, error = %error,
                    "PUBLISHED row reconcile-only confirmation failed; stays PUBLISHED with lease backoff");
            }
        }
    }
    Ok((leased, completed, waiting))
}

async fn release_published_lease(
    pool: &MySqlPool,
    reservation_id: &str,
    owner: &str,
    generation: u64,
) -> Result<(), PolicyError> {
    sqlx::query(
        "UPDATE authority_source_outcome SET lease_owner = NULL, \
        lease_until = UNIX_TIMESTAMP() + ?, updated_at = UNIX_TIMESTAMP() \
        WHERE reservation_id = ? AND status = 'PUBLISHED' AND lease_owner = ? AND generation = ? \
        AND lease_until > UNIX_TIMESTAMP()",
    )
    .bind(PUBLISHED_RECONCILE_SECONDS)
    .bind(reservation_id)
    .bind(owner)
    .bind(generation)
    .execute(pool)
    .await
    .map_err(pending)?;
    Ok(())
}

/// Confirm one locally PUBLISHED row against the authority, reconcile-only:
/// the durable row must pass the SAME exact durable binding verification as
/// the certification leg (canonical self-digest + field-by-field authority
/// commit binding), the reservation must match the durable row identity
/// exactly, be CERTIFIED, and cover EVERY declared coverage scope. A Certified
/// disposition alone never completes the row. Verified certificates for
/// declared scopes are recorded into local history before completion.
async fn confirm_published_row(
    pool: &MySqlPool,
    client: &AuthorityClient,
    row: &crate::authority_source_outcome::AuthoritySourceOutcomeRow,
) -> Result<bool, PolicyError> {
    let verified = verify_durable_source_outcome(row, "PUBLISHED")?;
    let scopes = verified
        .envelope
        .coverage
        .as_ref()
        .ok_or_else(|| pending("declared coverage missing on a published row"))?;
    let record = &verified.record;
    let reconciled = client
        .reconcile(record.reservation_id.clone(), record.operation_id.clone())
        .await
        .map_err(pending)?;
    let binding = reconciled
        .commit_binding
        .as_ref()
        .ok_or_else(|| pending("published reservation lacks its exact commit binding"))?;
    assert_exact_commit_binding(row, record, binding)?;
    let Some(reservation) = reconciled.reconciliation.reservation else {
        return Ok(false);
    };
    reservation.validate().map_err(pending)?;
    if reconciled.reconciliation.reservation_id != row.reservation_id
        || reconciled.reconciliation.operation_id != row.operation_id
        || reservation.reservation_id != record.reservation_id
        || reservation.intent.operation_id != record.operation_id
        || reservation.intent.event_id != record.event_id
        || reservation.intent.admission_proof_id != record.admission_proof_id
        || reservation.intent.request_digest != record.request_binding_digest
        || reservation.intent.mutation_kind != AuthorityMutationKind::AuthorizationSource
        || reservation.intent.service_id != record.service_id
        || reservation.intent.database_id != record.database_id
    {
        return Err(pending(
            "published reservation identity diverged from the durable row",
        ));
    }
    if !matches!(reservation.state, AuthorityReservationState::Certified) {
        return Ok(false);
    }
    for scope in &scopes.scopes {
        let scope_key = scope.store_key_text().map_err(pending)?;
        if !reservation.certified_scopes.contains(&scope_key) {
            return Ok(false);
        }
    }
    for certificate in &reconciled.certified_publications {
        if scopes.scopes.contains(&certificate.scope) {
            history::persist_certificate(pool, certificate).await?;
        }
    }
    Ok(true)
}

#[cfg(test)]
mod binding_tests {
    use super::*;
    use crate::authority_source_outcome::{canonical_outcome_digest, AuthoritySourceOutcomeRow};
    use astral_types::AuthorityCommitBinding;
    use astral_types::{
        AuthorityProtocolScope, AuthorityStagedScopeCoverage, AuthorizationAuthorityScope,
        AuthorizationDomainScope,
    };
    use serde_json::json;

    fn card_scope() -> AuthorityProtocolScope {
        AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
            tenant_id: 7,
            card_id: 17,
            user_id: None,
            domain: AuthorizationDomainScope::Any,
        })
    }

    fn delta_json() -> serde_json::Value {
        json!({
            "events": [], "receipts": [],
            "beforeDigestHex": "00".repeat(32),
            "afterDigestHex": "11".repeat(32),
            "commitDigestHex": "22".repeat(32),
        })
    }

    fn staged_json(coverage: bool) -> String {
        let envelope = AuthorityStagedSourceEvidence {
            coverage: coverage.then(|| AuthorityStagedScopeCoverage {
                scopes: vec![card_scope()],
            }),
            evidence: json!({ "delta": delta_json() }),
        };
        serde_json::to_string(&envelope).unwrap()
    }

    fn durable_record() -> AuthoritySourceOutcomeRecord {
        AuthoritySourceOutcomeRecord {
            reservation_id: "res-abc".to_owned(),
            operation_id: "operation-1".to_owned(),
            event_id: "event-1".to_owned(),
            admission_proof_id: "prf-1".to_owned(),
            request_binding_digest: "aa".repeat(32),
            mutation_kind: AuthorityMutationKind::AuthorizationSource,
            service_id: "source-svc".to_owned(),
            database_id: "db-1".to_owned(),
            source_commit_digest: "bb".repeat(32),
            before_image_digest: Some("cc".repeat(32)),
            after_image_digest: Some("dd".repeat(32)),
            source_receipts: vec![
                crate::authority_source_outcome::AuthoritySourceReceiptIdentity {
                    identity_kind: "ADMISSION_USE_ROW".to_owned(),
                    identity: "42".to_owned(),
                },
                crate::authority_source_outcome::AuthoritySourceReceiptIdentity {
                    identity_kind: "OUTBOX_MESSAGE".to_owned(),
                    identity: "msg-7".to_owned(),
                },
            ],
            committed_at: 1_790_000_000,
        }
    }

    fn durable_row(status: &str) -> (AuthoritySourceOutcomeRow, AuthoritySourceOutcomeRecord) {
        let record = durable_record();
        let staged = staged_json(true);
        let outcome_digest = canonical_outcome_digest(&record, Some(&staged)).unwrap();
        let row = AuthoritySourceOutcomeRow {
            reservation_id: record.reservation_id.clone(),
            operation_id: record.operation_id.clone(),
            event_id: record.event_id.clone(),
            admission_proof_id: record.admission_proof_id.clone(),
            request_binding_digest: hex::decode(&record.request_binding_digest).unwrap(),
            mutation_kind: "AUTHORIZATION_SOURCE".to_owned(),
            service_id: record.service_id.clone(),
            database_id: record.database_id.clone(),
            source_commit_digest: Some(hex::decode(&record.source_commit_digest).unwrap()),
            before_image_digest: Some(
                hex::decode(record.before_image_digest.as_deref().unwrap()).unwrap(),
            ),
            after_image_digest: Some(
                hex::decode(record.after_image_digest.as_deref().unwrap()).unwrap(),
            ),
            source_receipts: Some(serde_json::to_string(&record.source_receipts).unwrap()),
            staged_evidence: Some(staged),
            status: status.to_owned(),
            attempts: 1,
            generation: 1,
            outcome_digest: hex::decode(&outcome_digest).unwrap(),
            committed_at: record.committed_at,
        };
        (row, record)
    }

    fn expected_binding(
        row: &AuthoritySourceOutcomeRow,
        record: &AuthoritySourceOutcomeRecord,
    ) -> AuthorityCommitBinding {
        AuthorityCommitBinding {
            reservation_id: record.reservation_id.clone(),
            operation_id: record.operation_id.clone(),
            event_id: record.event_id.clone(),
            admission_proof_id: record.admission_proof_id.clone(),
            mutation_kind: record.mutation_kind,
            service_id: record.service_id.clone(),
            database_id: record.database_id.clone(),
            request_digest: record.request_binding_digest.clone(),
            source_commit_digest: record.source_commit_digest.clone(),
            before_image_digest: record.before_image_digest.clone(),
            after_image_digest: record.after_image_digest.clone().unwrap_or_default(),
            source_outcome_digest: hex::encode(&row.outcome_digest),
            staged_evidence_digest: row.staged_digest().unwrap(),
        }
    }

    #[test]
    fn durable_outcome_and_exact_binding_verify_together() {
        let (row, record) = durable_row("PUBLISHED");
        let verified = verify_durable_source_outcome(&row, "PUBLISHED").unwrap();
        assert_eq!(verified.record, record);
        assert_eq!(verified.envelope.coverage.as_ref().unwrap().scopes.len(), 1);
        assert_exact_commit_binding(&row, &record, &expected_binding(&row, &record)).unwrap();
        // The COMMITTED leg reuses the identical verifier.
        let (committed_row, _) = durable_row("COMMITTED");
        verify_durable_source_outcome(&committed_row, "COMMITTED").unwrap();
    }

    #[test]
    fn status_gate_is_exact_per_leg() {
        let (published_row, _) = durable_row("PUBLISHED");
        let (committed_row, _) = durable_row("COMMITTED");
        assert!(verify_durable_source_outcome(&published_row, "COMMITTED").is_err());
        assert!(verify_durable_source_outcome(&committed_row, "PUBLISHED").is_err());
    }

    #[test]
    fn corrupted_self_digest_or_evidence_is_refused() {
        let (mut row, record) = durable_row("PUBLISHED");
        row.outcome_digest[0] ^= 0xff;
        assert!(verify_durable_source_outcome(&row, "PUBLISHED").is_err());
        row.outcome_digest[0] ^= 0xff;
        verify_durable_source_outcome(&row, "PUBLISHED").unwrap();

        let (mut no_coverage, _) = durable_row("PUBLISHED");
        no_coverage.staged_evidence = Some(staged_json(false));
        let forged_digest =
            canonical_outcome_digest(&record, no_coverage.staged_evidence.as_deref()).unwrap();
        no_coverage.outcome_digest = hex::decode(&forged_digest).unwrap();
        // A syntactically valid digest over coverage-less evidence is still refused.
        assert!(verify_durable_source_outcome(&no_coverage, "PUBLISHED").is_err());

        let (mut malformed, _) = durable_row("PUBLISHED");
        malformed.staged_evidence = Some("{invalid".to_owned());
        assert!(verify_durable_source_outcome(&malformed, "PUBLISHED").is_err());

        let (mut bad_receipts, _) = durable_row("PUBLISHED");
        bad_receipts.source_receipts = Some("[-not-json".to_owned());
        assert!(verify_durable_source_outcome(&bad_receipts, "PUBLISHED").is_err());

        let (mut truncated, _) = durable_row("PUBLISHED");
        truncated.source_commit_digest = Some(vec![0_u8; 31]);
        assert!(verify_durable_source_outcome(&truncated, "PUBLISHED").is_err());
    }

    #[test]
    fn every_binding_field_mutation_is_refused() {
        let (row, record) = durable_row("PUBLISHED");
        let base = expected_binding(&row, &record);
        assert_exact_commit_binding(&row, &record, &base).unwrap();

        let mutations: Vec<(&str, AuthorityCommitBinding)> = vec![
            (
                "reservation_id",
                AuthorityCommitBinding {
                    reservation_id: "res-other".into(),
                    ..base.clone()
                },
            ),
            (
                "operation_id",
                AuthorityCommitBinding {
                    operation_id: "operation-2".into(),
                    ..base.clone()
                },
            ),
            (
                "event_id",
                AuthorityCommitBinding {
                    event_id: "event-2".into(),
                    ..base.clone()
                },
            ),
            (
                "admission_proof_id",
                AuthorityCommitBinding {
                    admission_proof_id: "prf-2".into(),
                    ..base.clone()
                },
            ),
            (
                "mutation_kind",
                AuthorityCommitBinding {
                    mutation_kind: AuthorityMutationKind::ProtectedBusiness,
                    ..base.clone()
                },
            ),
            (
                "service_id",
                AuthorityCommitBinding {
                    service_id: "other-svc".into(),
                    ..base.clone()
                },
            ),
            (
                "database_id",
                AuthorityCommitBinding {
                    database_id: "db-2".into(),
                    ..base.clone()
                },
            ),
            (
                "request_digest",
                AuthorityCommitBinding {
                    request_digest: "01".repeat(32),
                    ..base.clone()
                },
            ),
            (
                "source_commit_digest",
                AuthorityCommitBinding {
                    source_commit_digest: "02".repeat(32),
                    ..base.clone()
                },
            ),
            (
                "before_image_digest",
                AuthorityCommitBinding {
                    before_image_digest: Some("03".repeat(32)),
                    ..base.clone()
                },
            ),
            (
                "after_image_digest",
                AuthorityCommitBinding {
                    after_image_digest: "04".repeat(32),
                    ..base.clone()
                },
            ),
            (
                "source_outcome_digest",
                AuthorityCommitBinding {
                    source_outcome_digest: "05".repeat(32),
                    ..base.clone()
                },
            ),
            (
                "staged_evidence_digest",
                AuthorityCommitBinding {
                    staged_evidence_digest: "06".repeat(32),
                    ..base.clone()
                },
            ),
        ];
        assert_eq!(mutations.len(), 13);
        for (field, mutated) in mutations {
            assert!(
                assert_exact_commit_binding(&row, &record, &mutated).is_err(),
                "binding field {field} mutation was not refused"
            );
        }
    }
}
