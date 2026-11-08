//! Owner-only explicit abort of one reserved source mutation (V7).
//!
//! This module closes the post-prepare failure window: after the authority
//! accepted an intent (`RESERVED`, GLOBAL barrier up) and the local source
//! transaction provably rolled back — or never began — the reservation must
//! be able to reach the terminal `Aborted` state instead of blocking positive
//! reads forever.
//!
//! Fail-closed rules implemented here:
//! - Reconcile FIRST by stable reservation identity. A `Committed`,
//!   `Published`, `Certified`, `Quarantined` or unknown authority state NEVER
//!   aborts: an unknown source commit is reconciled, never replayed, never
//!   aborted.
//! - The local tombstone is a durable CAS on the SAME row the consume/stage
//!   paths lock (`authorization_source_reservation`, disposition
//!   `RESERVED -> ABORTED`) taken while also proving — UNDER that row lock —
//!   that the one-use admission was never consumed and no source-outcome row
//!   exists. Absence of an outcome is only meaningful while holding the same
//!   lock the commit path takes; lease expiry and transport errors are never
//!   criteria. After this tombstone commits, `quorum::validate_in_tx` and
//!   `stage_admitted_source_outcome_*` structurally refuse this reservation
//!   forever, so no later source commit can consume it.
//! - The tombstone commit must be PROVEN (COMMIT acknowledged) before any
//!   authority call. An unknown tombstone commit surfaces as an error the
//!   caller must treat as unknown and reconcile; it never reaches the
//!   network.
//! - The authority call presents the canonical `source_tombstone_digest` of
//!   the durable local row (read back after the CAS). `NotFound` on the
//!   authority is reported as `RemoteNotFound` and is NEVER claimed as a
//!   successful abort; local safety is preserved and reconciliation remains
//!   the recovery path.
//! - Unknown abort outcomes reconcile by stable identity; the exact same
//!   abort (stable abort id + tombstone digest + reason) may be re-issued at
//!   most once per call. The source mutation itself is never replayed.
//! - Reserve remote-success/local-persist-UNKNOWN is handled by reading back
//!   the existing row; only when the caller can supply the REAL prepare
//!   response may a tombstone row be INSERTED (never an overwrite, never a
//!   fabricated record).

use astral_authority::{AuthorityClient, AuthorityClientError};
use astral_types::{
    AuthorityAbortRequest, AuthorityAbortResponse, AuthorityPrepareResponse,
    AuthorityReconcileResponse, AuthorityReservationDisposition, AuthoritySourceTombstone,
    PolicyError,
};
use sha2::{Digest, Sha256};
use sqlx::{MySql, MySqlPool, Transaction};
use std::time::Duration;

/// Stable reason bound into every source-owner abort tombstone and receipt.
/// Recovery reconstructs this exact value from the ABORTED row; changing it is
/// a protocol change because it changes the immutable tombstone digest.
pub const SOURCE_RESERVATION_ABORT_REASON: &str =
    "source owner proved no admission-use or outcome under reservation lock";
const AUTHORITY_ABORT_CALL_TIMEOUT: Duration = Duration::from_secs(8);

/// The abort identity and binding the owning source must present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceReservationAbort {
    /// Stable operation identity of the reserved intent.
    pub operation_id: String,
    /// Admission proof identity of the reserved intent.
    pub proof_id: String,
    /// Approved immutable request digest of the reserved intent.
    pub request_digest: String,
    /// Stable reservation identity returned by the prepare acceptance.
    pub reservation_id: String,
    /// Exact stable owner audit reason recorded in the durable tombstone/receipt.
    pub reason: String,
    /// The serialized `AuthorityPrepareResponse` the caller retained. Needed
    /// ONLY when the local reservation row was never durably persisted
    /// (reserve remote success / local persist UNKNOWN): the tombstone row is
    /// then INSERTED from this real evidence. Never used to overwrite.
    pub prepare_response_json: Option<String>,
}

/// Terminal outcome of one bounded abort attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceAbortOutcome {
    /// The authority durably flipped the reservation to `Aborted`; the local
    /// tombstone was durably applied first.
    Aborted,
    /// The authority already held the EXACT same abort (idempotent read-back
    /// or prior attempt); the local tombstone is ensured.
    AlreadyAborted,
    /// The authority has NO reservation for this identity. The local
    /// tombstone is ensured for local safety; this is NOT an authority abort
    /// and later reconciliation may still change the picture.
    RemoteNotFound,
    /// A proven commit exists (authority-side or a locally consumed
    /// admission): abort refused. Reconcile; never replay, never abort.
    RefusedCommitExists,
    /// The local row or the response binding is in a non-abortable state;
    /// operator action is required.
    RefusedState(String),
    /// Reconciliation or abort outcome is unknown: nothing was decided.
    /// Retry later by stable identity.
    Unknown,
    /// A tombstone is mandatory but impossible: no local row and no retained
    /// prepare response. Nothing was changed anywhere.
    NoLocalTombstone,
}

/// Bounded attempt report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceAbortReport {
    pub reservation_id: String,
    pub operation_id: String,
    pub outcome: SourceAbortOutcome,
    /// The authority-side disposition observed at decision time, when known.
    pub observed_disposition: Option<String>,
}

/// The authority-facing surface for abort/reconcile. Implemented by the real
/// client; tests stub it. No method retries automatically.
#[async_trait::async_trait]
pub trait SourceReservationAbortGateway: Send + Sync {
    async fn reconcile(
        &self,
        reservation_id: String,
        operation_id: String,
    ) -> Result<AuthorityReconcileResponse, AuthorityClientError>;
    #[allow(clippy::too_many_arguments)]
    async fn abort(
        &self,
        reservation_id: String,
        operation_id: String,
        database_id: String,
        request_digest: String,
        abort_id: String,
        source_tombstone_digest: String,
        reason: String,
    ) -> Result<AuthorityAbortResponse, AuthorityClientError>;
}

#[async_trait::async_trait]
impl SourceReservationAbortGateway for AuthorityClient {
    async fn reconcile(
        &self,
        reservation_id: String,
        operation_id: String,
    ) -> Result<AuthorityReconcileResponse, AuthorityClientError> {
        AuthorityClient::reconcile(self, reservation_id, operation_id).await
    }
    async fn abort(
        &self,
        reservation_id: String,
        operation_id: String,
        database_id: String,
        request_digest: String,
        abort_id: String,
        source_tombstone_digest: String,
        reason: String,
    ) -> Result<AuthorityAbortResponse, AuthorityClientError> {
        AuthorityClient::abort(
            self,
            reservation_id,
            operation_id,
            database_id,
            request_digest,
            abort_id,
            source_tombstone_digest,
            reason,
        )
        .await
    }
}

/// Pure gate from the reconciled authority disposition to the abort step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileStep {
    /// Authority still `Reserved`: tombstone locally, then abort remotely.
    Proceed,
    /// Authority is already `Aborted`: tombstone locally, then request the
    /// exact abort receipt by stable idempotency identity.
    TombstoneAndVerify,
    /// A proven commit exists on the authority: never abort.
    RefuseCommit,
    /// Quarantined: terminal operator state; abort refused.
    RefuseQuarantined,
    /// Pending/unknown: no proof either way; do nothing.
    Unknown,
}

/// Pure mapping. Unknown and pending fail closed; committed-family states
/// (including any terminal committed state added later) refuse the abort.
pub fn reconcile_step(disposition: &AuthorityReservationDisposition) -> ReconcileStep {
    match disposition {
        AuthorityReservationDisposition::Reserved => ReconcileStep::Proceed,
        AuthorityReservationDisposition::Aborted => ReconcileStep::TombstoneAndVerify,
        AuthorityReservationDisposition::NotFound => ReconcileStep::Unknown,
        AuthorityReservationDisposition::Committed
        | AuthorityReservationDisposition::Published
        | AuthorityReservationDisposition::Certified
        | AuthorityReservationDisposition::Completed => ReconcileStep::RefuseCommit,
        AuthorityReservationDisposition::Quarantined => ReconcileStep::RefuseQuarantined,
        AuthorityReservationDisposition::Pending | AuthorityReservationDisposition::Unknown => {
            ReconcileStep::Unknown
        }
    }
}

/// Pure refusal reasons of the tombstone CAS precondition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TombstoneRefusal {
    /// The row is not `RESERVED` (and not already `ABORTED`).
    NotReserved,
    /// The one-use admission was consumed: a source transaction committed.
    AdmissionConsumed,
    /// A durable source-outcome row exists: a source transaction committed.
    OutcomeExists,
}

/// Pure tombstone CAS precondition, evaluated while HOLDING the reservation
/// row lock (`SELECT ... FOR UPDATE` on `authorization_source_reservation`).
/// This is the commit-vs-abort exclusion: a source commit transaction locks
/// this same row before consuming its admission, so a clean check under the
/// lock proves the transaction never began or fully rolled back. Lease
/// expiry, transport errors and outcome absence alone are never criteria.
pub fn tombstone_precondition(
    disposition: &str,
    admission_consumed: bool,
    outcome_row_exists: bool,
) -> Result<(), TombstoneRefusal> {
    if admission_consumed {
        return Err(TombstoneRefusal::AdmissionConsumed);
    }
    if outcome_row_exists {
        return Err(TombstoneRefusal::OutcomeExists);
    }
    if disposition != "RESERVED" {
        return Err(TombstoneRefusal::NotReserved);
    }
    Ok(())
}

/// Pure mapping of an abort client error onto the bounded recovery step:
/// every error reconciles by stable identity. Unknown outcomes must never be
/// assumed applied or unapplied, and refusals must be re-proven.
pub fn abort_error_step(_error: &astral_authority::AuthorityClientError) -> AbortErrorStep {
    AbortErrorStep::Reconcile
}

/// The only bounded recovery step after an abort error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortErrorStep {
    Reconcile,
}

fn pending(message: impl Into<String>) -> PolicyError {
    PolicyError::Repository(message.into())
}

/// Decode the durable reservation-record bytes of one local row.
fn parse_reservation_row(reservation_json: &str) -> Result<AuthorityPrepareResponse, PolicyError> {
    let response: AuthorityPrepareResponse = serde_json::from_str(reservation_json)
        .map_err(|_| pending("local reservation record cannot be decoded"))?;
    response
        .validate()
        .map_err(|error| pending(format!("local reservation record is invalid: {error}")))?;
    Ok(response)
}

/// Build the canonical tombstone binding of one aborted local row. The
/// binding covers the EXACT durable row bytes plus the abort identity, so a
/// stable tombstone digest always identifies exactly one durable closure.
fn build_tombstone(
    response: &AuthorityPrepareResponse,
    reservation_json: &str,
    tombstoned_at: i64,
    reason: &str,
) -> Result<AuthoritySourceTombstone, PolicyError> {
    let reservation_id = response.reservation.reservation_id.clone();
    let tombstone = astral_types::source_tombstone_for_reservation(
        &response.reservation,
        hex::encode(Sha256::digest(reservation_json.as_bytes())),
        tombstoned_at,
        AuthorityAbortRequest::stable_abort_id(&reservation_id)
            .map_err(|error| pending(format!("stable abort id: {error}")))?,
        reason.to_owned(),
    )
    .map_err(|error| pending(format!("tombstone binding: {error}")))?;
    Ok(tombstone)
}

/// Whether the durable row binding matches the abort identity exactly.
fn binding_matches(tombstone: &AuthoritySourceTombstone, abort: &SourceReservationAbort) -> bool {
    tombstone.reservation_id == abort.reservation_id
        && tombstone.operation_id == abort.operation_id
        && tombstone.admission_proof_id == abort.proof_id
        && tombstone.request_digest == abort.request_digest
}

/// Proof queries run while HOLDING the reservation row lock: the admission is
/// unconsumed and no source-outcome row exists.
async fn proven_no_source_commit(
    tx: &mut Transaction<'_, MySql>,
    proof_id: &str,
    reservation_id: &str,
) -> Result<(bool, bool), PolicyError> {
    let consumed: Option<i64> = sqlx::query_scalar(
        "SELECT consumed_at FROM authorization_admission_use WHERE proof_id = ? FOR UPDATE",
    )
    .bind(proof_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| pending(format!("abort admission lock failed: {error}")))?;
    let outcome_row: Option<i64> = sqlx::query_scalar(
        "SELECT committed_at FROM authority_source_outcome WHERE reservation_id = ? FOR UPDATE",
    )
    .bind(reservation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| pending(format!("abort outcome lock failed: {error}")))?;
    Ok((consumed.is_some(), outcome_row.is_some()))
}

/// What the local tombstone step produced.
enum LocalTombstone {
    /// The row is durably `ABORTED` with its canonical tombstone binding.
    Tombstoned(Box<AuthoritySourceTombstone>),
    /// No local row exists and none could be created; the local consume path
    /// is already structurally dead (it requires the row).
    Absent,
    /// The CAS precondition refused under the row lock.
    Refused(&'static str),
}

/// Apply the durable local tombstone: lock the reservation row, prove under
/// the lock that no source transaction committed (admission unconsumed, no
/// outcome row), then CAS `RESERVED -> ABORTED` — or INSERT the tombstone row
/// from the caller's real prepare response when the row never persisted.
/// COMMIT must be acknowledged (error otherwise) before any authority call.
async fn apply_local_tombstone(
    pool: &MySqlPool,
    abort: &SourceReservationAbort,
) -> Result<Result<LocalTombstone, PolicyError>, PolicyError> {
    let mut tx: Transaction<'_, MySql> = pool
        .begin()
        .await
        .map_err(|error| pending(format!("abort tombstone begin failed: {error}")))?;
    let row: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT CAST(reservation_json AS CHAR), disposition, updated_at \
         FROM authorization_source_reservation \
         WHERE operation_id = ? AND proof_id = ? FOR UPDATE",
    )
    .bind(&abort.operation_id)
    .bind(&abort.proof_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| pending(format!("abort tombstone row lock failed: {error}")))?;

    if let Some((reservation_json, disposition, row_updated_at)) = row {
        let response = parse_reservation_row(&reservation_json)?;
        if disposition == "ABORTED" {
            // A tombstone is only recoverable while the same reservation row
            // remains the commit-vs-abort exclusion. Verify no admission use or
            // durable source outcome has appeared, under this row lock.
            let (consumed, outcome_exists) =
                proven_no_source_commit(&mut tx, &abort.proof_id, &abort.reservation_id).await?;
            if consumed || outcome_exists {
                tx.rollback().await.ok();
                return Ok(Ok(LocalTombstone::Refused(
                    "source evidence exists under an ABORTED reservation; abort refused",
                )));
            }
            // Idempotent read-back: a previous attempt tombstoned the row but
            // may have died before the remote abort. Rebuild the SAME
            // binding from the row's own durable marker time and fixed reason.
            let tombstone = build_tombstone(
                &response,
                &reservation_json,
                row_updated_at,
                SOURCE_RESERVATION_ABORT_REASON,
            )
            .map_err(|_| pending("aborted reservation row lost its prepare evidence"))?;
            if !binding_matches(&tombstone, abort)
                || abort.reason.trim() != SOURCE_RESERVATION_ABORT_REASON
            {
                tx.rollback().await.ok();
                return Ok(Ok(LocalTombstone::Refused(
                    "abort binding does not match the tombstoned reservation",
                )));
            }
            tx.commit()
                .await
                .map_err(|_| pending("abort tombstone read-back commit is unknown"))?;
            return Ok(Ok(LocalTombstone::Tombstoned(Box::new(tombstone))));
        }
        // Proof under the row lock: the admission is unconsumed and no
        // source-outcome row exists. A source commit transaction locks this
        // same row first, so nothing can be mid-flight here.
        let (consumed, outcome_exists) =
            proven_no_source_commit(&mut tx, &abort.proof_id, &abort.reservation_id).await?;
        if let Err(refusal) = tombstone_precondition(&disposition, consumed, outcome_exists) {
            tx.rollback().await.ok();
            return Ok(Ok(LocalTombstone::Refused(match refusal {
                TombstoneRefusal::AdmissionConsumed => {
                    "admission was consumed; a source commit exists; abort refused"
                }
                TombstoneRefusal::OutcomeExists => "durable source outcome exists; abort refused",
                TombstoneRefusal::NotReserved => "reservation is not RESERVED; abort refused",
            })));
        }
        // Validate the caller's identity binding against the durable row
        // before flipping: the abort must be for EXACTLY this reservation.
        let probe = build_tombstone(&response, &reservation_json, 1, &abort.reason)
            .map_err(|_| pending("reservation row lost its prepare evidence"))?;
        if !binding_matches(&probe, abort) {
            tx.rollback().await.ok();
            return Ok(Ok(LocalTombstone::Refused(
                "abort binding does not match the durable reservation",
            )));
        }
        let tombstoned_at: i64 = sqlx::query_scalar("SELECT CAST(UNIX_TIMESTAMP() AS SIGNED)")
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| pending(format!("abort clock read failed: {error}")))?;
        let tombstone =
            build_tombstone(&response, &reservation_json, tombstoned_at, &abort.reason)?;
        // The CAS: only a still-RESERVED row can be tombstoned. Everything
        // else was already excluded above under the same lock.
        let flipped = sqlx::query(
            "UPDATE authorization_source_reservation \
             SET disposition = 'ABORTED', updated_at = ? \
             WHERE operation_id = ? AND proof_id = ? AND disposition = 'RESERVED'",
        )
        .bind(tombstoned_at)
        .bind(&abort.operation_id)
        .bind(&abort.proof_id)
        .execute(&mut *tx)
        .await
        .map_err(|error| pending(format!("abort tombstone CAS failed: {error}")))?;
        if flipped.rows_affected() != 1 {
            tx.rollback().await.ok();
            return Ok(Ok(LocalTombstone::Refused(
                "reservation row changed concurrently; abort refused",
            )));
        }
        // COMMIT must be proven: an unknown commit outcome never reaches the
        // authority (the caller treats this error as unknown and reconciles).
        tx.commit()
            .await
            .map_err(|_| pending("abort tombstone commit is unknown"))?;
        return Ok(Ok(LocalTombstone::Tombstoned(Box::new(tombstone))));
    }

    // No local row: the reserve's local persist may have failed while the
    // prepare succeeded remotely. Only the caller's REAL prepare response may
    // become the tombstone row (audit integrity); never a fabricated record,
    // never an overwrite of an existing row.
    if abort.reason.trim() != SOURCE_RESERVATION_ABORT_REASON {
        tx.rollback().await.ok();
        return Err(pending(
            "abort reason does not match the stable owner contract",
        ));
    }
    let Some(reservation_json) = abort.prepare_response_json.as_deref() else {
        tx.rollback().await.ok();
        return Ok(Ok(LocalTombstone::Absent));
    };
    let response = parse_reservation_row(reservation_json)?;
    if response.reservation.reservation_id != abort.reservation_id
        || response.reservation.intent.operation_id != abort.operation_id
        || response.reservation.intent.admission_proof_id != abort.proof_id
        || response.reservation.intent.request_digest != abort.request_digest
        || response.reservation.state.as_text() != "RESERVED"
    {
        tx.rollback().await.ok();
        return Ok(Ok(LocalTombstone::Refused(
            "retained prepare response does not match the abort identity",
        )));
    }
    // Same under-lock proof for the absent-row path.
    let (consumed, outcome_exists) =
        proven_no_source_commit(&mut tx, &abort.proof_id, &abort.reservation_id).await?;
    if consumed || outcome_exists {
        tx.rollback().await.ok();
        return Ok(Ok(LocalTombstone::Refused(
            "source evidence exists; abort refused",
        )));
    }
    let tombstoned_at: i64 = sqlx::query_scalar("SELECT CAST(UNIX_TIMESTAMP() AS SIGNED)")
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| pending(format!("abort clock read failed: {error}")))?;
    let tombstone = build_tombstone(&response, reservation_json, tombstoned_at, &abort.reason)?;
    let inserted = sqlx::query(
        "INSERT INTO authorization_source_reservation \
         (operation_id, proof_id, request_digest, reservation_json, disposition, updated_at) \
         VALUES (?, ?, UNHEX(?), ?, 'ABORTED', ?)",
    )
    .bind(&abort.operation_id)
    .bind(&abort.proof_id)
    .bind(&abort.request_digest)
    .bind(reservation_json)
    .bind(tombstoned_at)
    .execute(&mut *tx)
    .await;
    if inserted.is_err() {
        // A concurrent reserve committed its own row between our locked read
        // and this INSERT: refuse and let the caller retry the whole
        // reconcile-first flow. The tombstone is never written on top of it.
        tx.rollback().await.ok();
        return Ok(Ok(LocalTombstone::Refused(
            "reservation row appeared concurrently; retry the abort",
        )));
    }
    tx.commit()
        .await
        .map_err(|_| pending("abort tombstone insert commit is unknown"))?;
    Ok(Ok(LocalTombstone::Tombstoned(Box::new(tombstone))))
}

/// Defense-in-depth verification of the echoed receipt against this exact
/// abort (the client library already verifies; the source owner re-checks).
fn verify_abort_response(
    response: &AuthorityAbortResponse,
    abort: &SourceReservationAbort,
    tombstone: &AuthoritySourceTombstone,
) -> Result<(), PolicyError> {
    response
        .validate()
        .map_err(|error| pending(format!("abort response is invalid: {error}")))?;
    let receipt = &response.receipt;
    let digest = tombstone
        .digest()
        .map_err(|error| pending(format!("tombstone digest: {error}")))?;
    if response.reservation.state.as_text() != "ABORTED"
        || receipt.reservation_id != abort.reservation_id
        || receipt.operation_id != abort.operation_id
        || receipt.request_digest != abort.request_digest
        || receipt.admission_proof_id != abort.proof_id
        || receipt.abort_id != tombstone.abort_id
        || receipt.source_tombstone_digest != digest
        || receipt.reason != abort.reason.trim()
    {
        return Err(pending("abort receipt does not bind the requested abort"));
    }
    Ok(())
}

/// Send the abort with one bounded recovery pass: an unknown or refused
/// outcome reconciles by stable identity, and only a still-`Reserved`
/// authority state may receive the EXACT same abort once more. The source
/// mutation itself is never replayed.
async fn call_reconcile_bounded<G: SourceReservationAbortGateway>(
    gateway: &G,
    reservation_id: String,
    operation_id: String,
) -> Result<AuthorityReconcileResponse, ()> {
    tokio::time::timeout(
        AUTHORITY_ABORT_CALL_TIMEOUT,
        gateway.reconcile(reservation_id, operation_id),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())
}

async fn send_abort_once_bounded<G: SourceReservationAbortGateway>(
    gateway: &G,
    abort: &SourceReservationAbort,
    tombstone: &AuthoritySourceTombstone,
    digest: &str,
) -> Result<AuthorityAbortResponse, AuthorityClientError> {
    send_abort_once_with_timeout(
        gateway,
        abort,
        tombstone,
        digest,
        AUTHORITY_ABORT_CALL_TIMEOUT,
    )
    .await
}

async fn send_abort_once_with_timeout<G: SourceReservationAbortGateway>(
    gateway: &G,
    abort: &SourceReservationAbort,
    tombstone: &AuthoritySourceTombstone,
    digest: &str,
    timeout: Duration,
) -> Result<AuthorityAbortResponse, AuthorityClientError> {
    let database_id = tombstone.database_id.clone();
    let reservation_id = abort.reservation_id.clone();
    let operation_id = abort.operation_id.clone();
    let request_digest = abort.request_digest.clone();
    let abort_id = tombstone.abort_id.clone();
    let digest = digest.to_owned();
    let reason = tombstone.reason.clone();
    tokio::time::timeout(
        timeout,
        gateway.abort(
            reservation_id,
            operation_id,
            database_id,
            request_digest,
            abort_id,
            digest,
            reason,
        ),
    )
    .await
    .map_err(|_| AuthorityClientError::UnknownOutcome {
        operation_hint: "reservation-abort timeout".to_owned(),
    })?
}

async fn send_abort_bounded<G: SourceReservationAbortGateway>(
    gateway: &G,
    abort: &SourceReservationAbort,
    tombstone: &AuthoritySourceTombstone,
) -> Result<SourceAbortReport, PolicyError> {
    let report = |outcome: SourceAbortOutcome, observed: Option<String>| -> SourceAbortReport {
        SourceAbortReport {
            reservation_id: abort.reservation_id.clone(),
            operation_id: abort.operation_id.clone(),
            outcome,
            observed_disposition: observed,
        }
    };
    let digest = tombstone
        .digest()
        .map_err(|error| pending(format!("tombstone digest: {error}")))?;
    match send_abort_once_bounded(gateway, abort, tombstone, &digest).await {
        Ok(response) => verify_abort_response(&response, abort, tombstone)
            .map(|_| report(SourceAbortOutcome::Aborted, Some("ABORTED".to_owned()))),
        Err(error) => {
            let AbortErrorStep::Reconcile = abort_error_step(&error);
            // Reconcile by stable identity; no source replay, no blind retry.
            match call_reconcile_bounded(
                gateway,
                abort.reservation_id.clone(),
                abort.operation_id.clone(),
            )
            .await
            {
                Err(()) => Ok(report(SourceAbortOutcome::Unknown, None)),
                Ok(reconciliation) => {
                    let observed = reconciliation.reconciliation.disposition;
                    let observed_text = observed.as_text().to_owned();
                    match observed {
                        AuthorityReservationDisposition::Reserved
                        | AuthorityReservationDisposition::Aborted => {
                            // A stable read of ABORTED is not proof that the
                            // receipt matches this tombstone/reason. Re-issue
                            // the EXACT same idempotency key once; the authority
                            // returns its immutable receipt only for an exact
                            // match, which is then checked field-by-field.
                            match send_abort_once_bounded(gateway, abort, tombstone, &digest).await
                            {
                                Ok(response) => verify_abort_response(&response, abort, tombstone)
                                    .map(|_| {
                                        let outcome = if observed
                                            == AuthorityReservationDisposition::Aborted
                                        {
                                            SourceAbortOutcome::AlreadyAborted
                                        } else {
                                            SourceAbortOutcome::Aborted
                                        };
                                        report(outcome, Some("ABORTED".to_owned()))
                                    }),
                                Err(_) => {
                                    Ok(report(SourceAbortOutcome::Unknown, Some(observed_text)))
                                }
                            }
                        }

                        AuthorityReservationDisposition::NotFound => Ok(report(
                            SourceAbortOutcome::RemoteNotFound,
                            Some(observed_text),
                        )),
                        AuthorityReservationDisposition::Committed
                        | AuthorityReservationDisposition::Published
                        | AuthorityReservationDisposition::Certified
                        | AuthorityReservationDisposition::Completed => Ok(report(
                            SourceAbortOutcome::RefusedCommitExists,
                            Some(observed_text),
                        )),
                        AuthorityReservationDisposition::Quarantined => Ok(report(
                            SourceAbortOutcome::RefusedState(
                                "authority reservation is quarantined".to_owned(),
                            ),
                            Some(observed_text),
                        )),
                        AuthorityReservationDisposition::Pending
                        | AuthorityReservationDisposition::Unknown => {
                            Ok(report(SourceAbortOutcome::Unknown, Some(observed_text)))
                        }
                    }
                }
            }
        }
    }
}

/// Abort one reserved source mutation end to end: reconcile-first gate,
/// durable row-lock CAS tombstone, then the authority abort with one bounded
/// recovery pass. Returns a report; never replays the source mutation. A
/// returned `Err` (for example an unknown tombstone COMMIT) means the durable
/// state is unproven: treat it as unknown and reconcile by stable identity.
pub async fn abort_source_reservation<G: SourceReservationAbortGateway>(
    pool: &MySqlPool,
    gateway: &G,
    abort: &SourceReservationAbort,
) -> Result<SourceAbortReport, PolicyError> {
    let report = |outcome: SourceAbortOutcome,
                  observed: Option<String>|
     -> Result<SourceAbortReport, PolicyError> {
        Ok(SourceAbortReport {
            reservation_id: abort.reservation_id.clone(),
            operation_id: abort.operation_id.clone(),
            outcome,
            observed_disposition: observed,
        })
    };
    if abort.reason.trim() != SOURCE_RESERVATION_ABORT_REASON {
        return report(
            SourceAbortOutcome::RefusedState(
                "abort reason does not match the stable source-owner contract".to_owned(),
            ),
            None,
        );
    }
    // 1. Reconcile-first: an unknown source commit is NEVER aborted.
    let reconciliation = match call_reconcile_bounded(
        gateway,
        abort.reservation_id.clone(),
        abort.operation_id.clone(),
    )
    .await
    {
        Ok(reconciliation) => reconciliation,
        Err(()) => return report(SourceAbortOutcome::Unknown, None),
    };
    // Exact binding: the durable reservation (when present) must be THIS
    // identity before any state transition is considered.
    if reconciliation.reconciliation.reservation.is_none() {
        return report(
            SourceAbortOutcome::Unknown,
            Some(
                reconciliation
                    .reconciliation
                    .disposition
                    .as_text()
                    .to_owned(),
            ),
        );
    }
    if let Some(reservation) = &reconciliation.reconciliation.reservation {
        if reservation.reservation_id != abort.reservation_id
            || reservation.intent.request_digest != abort.request_digest
            || reservation.intent.operation_id != abort.operation_id
            || reservation.intent.admission_proof_id != abort.proof_id
        {
            return report(
                SourceAbortOutcome::RefusedState(
                    "authority reservation does not match the abort identity".to_owned(),
                ),
                Some(
                    reconciliation
                        .reconciliation
                        .disposition
                        .as_text()
                        .to_owned(),
                ),
            );
        }
    }
    let observed = reconciliation.reconciliation.disposition;
    let observed_text = observed.as_text().to_owned();
    match reconcile_step(&observed) {
        ReconcileStep::Unknown => report(SourceAbortOutcome::Unknown, Some(observed_text)),
        ReconcileStep::RefuseCommit => {
            report(SourceAbortOutcome::RefusedCommitExists, Some(observed_text))
        }
        ReconcileStep::RefuseQuarantined => report(
            SourceAbortOutcome::RefusedState("authority reservation is quarantined".to_owned()),
            Some(observed_text),
        ),
        ReconcileStep::TombstoneAndVerify => {
            // The authority is terminal. Reconstruct the source tombstone and
            // ask for an exact idempotent receipt; reconciliation disposition
            // alone is never treated as an abort acknowledgement.
            match apply_local_tombstone(pool, abort).await? {
                Ok(LocalTombstone::Tombstoned(tombstone)) => {
                    send_abort_bounded(gateway, abort, &tombstone).await
                }
                Ok(LocalTombstone::Absent) => {
                    report(SourceAbortOutcome::NoLocalTombstone, Some(observed_text))
                }
                Ok(LocalTombstone::Refused(reason)) => report(
                    SourceAbortOutcome::RefusedState(reason.to_owned()),
                    Some(observed_text),
                ),
                Err(_) => report(SourceAbortOutcome::Unknown, Some(observed_text)),
            }
        }
        ReconcileStep::Proceed => {
            // 2. Durable local tombstone; COMMIT proven before any network.
            match apply_local_tombstone(pool, abort).await? {
                Ok(LocalTombstone::Tombstoned(tombstone)) => {
                    // 3. Authority abort with one bounded recovery pass.
                    send_abort_bounded(gateway, abort, &tombstone).await
                }
                Ok(LocalTombstone::Absent) => {
                    report(SourceAbortOutcome::NoLocalTombstone, Some(observed_text))
                }
                Ok(LocalTombstone::Refused(reason)) => report(
                    SourceAbortOutcome::RefusedState(reason.to_owned()),
                    Some(observed_text),
                ),
                // The tombstone commit is unproven: surface as unknown.
                Err(commit_error) => Err(commit_error),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::AuthorityReservationDisposition as D;

    #[test]
    fn reconcile_step_maps_every_disposition_fail_closed() {
        assert_eq!(reconcile_step(&D::Reserved), ReconcileStep::Proceed);
        assert_eq!(
            reconcile_step(&D::Aborted),
            ReconcileStep::TombstoneAndVerify
        );
        assert_eq!(reconcile_step(&D::NotFound), ReconcileStep::Unknown);
        assert_eq!(reconcile_step(&D::Committed), ReconcileStep::RefuseCommit);
        assert_eq!(reconcile_step(&D::Published), ReconcileStep::RefuseCommit);
        assert_eq!(reconcile_step(&D::Certified), ReconcileStep::RefuseCommit);
        assert_eq!(reconcile_step(&D::Completed), ReconcileStep::RefuseCommit);
        assert_eq!(
            reconcile_step(&D::Quarantined),
            ReconcileStep::RefuseQuarantined
        );
        assert_eq!(reconcile_step(&D::Pending), ReconcileStep::Unknown);
        assert_eq!(reconcile_step(&D::Unknown), ReconcileStep::Unknown);
    }

    #[test]
    fn tombstone_precondition_is_the_commit_vs_abort_exclusion() {
        // Clean RESERVED row under the lock: the only abortable state.
        assert_eq!(tombstone_precondition("RESERVED", false, false), Ok(()));
        // A consumed admission means a source transaction COMMITTED: refuse.
        assert_eq!(
            tombstone_precondition("RESERVED", true, false),
            Err(TombstoneRefusal::AdmissionConsumed)
        );
        // A durable source outcome means a source transaction COMMITTED.
        assert_eq!(
            tombstone_precondition("RESERVED", false, true),
            Err(TombstoneRefusal::OutcomeExists)
        );
        // A consumed admission or outcome beats the disposition check.
        assert_eq!(
            tombstone_precondition("ABORTED", true, false),
            Err(TombstoneRefusal::AdmissionConsumed)
        );
        // Non-RESERVED rows are never flipped again.
        assert_eq!(
            tombstone_precondition("COMMITTED", false, false),
            Err(TombstoneRefusal::NotReserved)
        );
        assert_eq!(
            tombstone_precondition("ABORTED", false, false),
            Err(TombstoneRefusal::NotReserved)
        );
    }

    #[tokio::test]
    async fn abort_helper_preserves_exact_stable_binding_and_times_out_as_unknown() {
        use std::sync::{Arc, Mutex};

        type AbortBinding = (String, String, String, String, String, String, String);

        #[derive(Clone)]
        struct RecordingGateway {
            captured: Arc<Mutex<Vec<AbortBinding>>>,
            delay: Duration,
        }

        #[async_trait::async_trait]
        impl SourceReservationAbortGateway for RecordingGateway {
            async fn reconcile(
                &self,
                _reservation_id: String,
                _operation_id: String,
            ) -> Result<AuthorityReconcileResponse, AuthorityClientError> {
                unreachable!("the single-send helper must not reconcile")
            }

            async fn abort(
                &self,
                reservation_id: String,
                operation_id: String,
                database_id: String,
                request_digest: String,
                abort_id: String,
                tombstone_digest: String,
                reason: String,
            ) -> Result<AuthorityAbortResponse, AuthorityClientError> {
                self.captured.lock().unwrap().push((
                    reservation_id,
                    operation_id,
                    database_id,
                    request_digest,
                    abort_id,
                    tombstone_digest,
                    reason,
                ));
                tokio::time::sleep(self.delay).await;
                Err(AuthorityClientError::Transport("test response".into()))
            }
        }

        let prepare_json = test_reservation_json();
        let prepare = parse_reservation_row(&prepare_json).unwrap();
        let abort = SourceReservationAbort {
            operation_id: "operation-1".into(),
            proof_id: "proof-1".into(),
            request_digest: "cd".repeat(32),
            reservation_id: "res-1".into(),
            reason: "proven rollback".into(),
            prepare_response_json: None,
        };
        let tombstone = build_tombstone(&prepare, &prepare_json, 7_000, &abort.reason).unwrap();
        let digest = tombstone.digest().unwrap();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let gateway = RecordingGateway {
            captured: Arc::clone(&captured),
            delay: Duration::ZERO,
        };

        let result = send_abort_once_with_timeout(
            &gateway,
            &abort,
            &tombstone,
            &digest,
            Duration::from_secs(1),
        )
        .await;
        assert!(matches!(result, Err(AuthorityClientError::Transport(_))));
        assert_eq!(
            *captured.lock().unwrap(),
            vec![(
                "res-1".into(),
                "operation-1".into(),
                "db-1".into(),
                "cd".repeat(32),
                "abort-res-1".into(),
                digest.clone(),
                "proven rollback".into(),
            )],
            "helper forwards the stable reservation, request, tombstone, and reason bindings"
        );

        let timeout_gateway = RecordingGateway {
            captured: Arc::new(Mutex::new(Vec::new())),
            delay: Duration::from_millis(30),
        };
        let timeout_result = send_abort_once_with_timeout(
            &timeout_gateway,
            &abort,
            &tombstone,
            &digest,
            Duration::from_millis(1),
        )
        .await;
        assert!(matches!(
            timeout_result,
            Err(AuthorityClientError::UnknownOutcome { .. })
        ));

        let mut altered_tombstone = tombstone.clone();
        altered_tombstone.database_id = "db-owner-2".into();
        let altered_digest = altered_tombstone.digest().unwrap();
        let altered_capture = Arc::new(Mutex::new(Vec::new()));
        let altered_gateway = RecordingGateway {
            captured: Arc::clone(&altered_capture),
            delay: Duration::ZERO,
        };
        let _ = send_abort_once_with_timeout(
            &altered_gateway,
            &abort,
            &altered_tombstone,
            &altered_digest,
            Duration::from_secs(1),
        )
        .await;
        let calls = altered_capture.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].2, "db-owner-2");
        assert_eq!(calls[0].5, altered_digest);
        assert_ne!(
            calls[0].5, digest,
            "a changed tombstone has a different digest"
        );
    }

    #[test]
    fn every_client_error_reconciles_instead_of_replaying() {
        let errors = [
            astral_authority::AuthorityClientError::UnknownOutcome {
                operation_hint: "abort".to_owned(),
            },
            astral_authority::AuthorityClientError::Transport("connection reset".to_owned()),
            astral_authority::AuthorityClientError::Rejected {
                code: "StateConflict".to_owned(),
                message: "concurrent".to_owned(),
            },
            astral_authority::AuthorityClientError::Attestation("pin".to_owned()),
            astral_authority::AuthorityClientError::InsecureEndpoint,
            astral_authority::AuthorityClientError::Protocol("bad body".to_owned()),
        ];
        for error in &errors {
            let AbortErrorStep::Reconcile = abort_error_step(error);
        }
    }

    #[test]
    fn tombstone_binding_is_deterministic_and_row_exact() {
        let reservation_json = test_reservation_json();
        let response = parse_reservation_row(&reservation_json).unwrap();
        let first =
            build_tombstone(&response, &reservation_json, 7_000, "proven rollback").unwrap();
        let second =
            build_tombstone(&response, &reservation_json, 7_000, "proven rollback").unwrap();
        assert_eq!(first, second, "the same row must yield the same binding");
        assert_eq!(first.disposition, "ABORTED");
        assert_eq!(
            first.reservation_record_digest,
            hex::encode(Sha256::digest(reservation_json.as_bytes()))
        );
        let different_time =
            build_tombstone(&response, &reservation_json, 7_001, "proven rollback").unwrap();
        assert_ne!(first.digest().unwrap(), different_time.digest().unwrap());
        assert!(binding_matches(
            &first,
            &SourceReservationAbort {
                operation_id: "operation-1".to_owned(),
                proof_id: "proof-1".to_owned(),
                request_digest: "cd".repeat(32),
                reservation_id: "res-1".to_owned(),
                reason: "proven rollback".to_owned(),
                prepare_response_json: None,
            }
        ));
        assert!(!binding_matches(
            &first,
            &SourceReservationAbort {
                operation_id: "operation-other".to_owned(),
                proof_id: "proof-1".to_owned(),
                request_digest: "cd".repeat(32),
                reservation_id: "res-1".to_owned(),
                reason: "proven rollback".to_owned(),
                prepare_response_json: None,
            }
        ));
    }

    fn test_reservation_json() -> String {
        // A minimal structurally valid prepare response fixture (the
        // acceptance signature is shape-checked only on this path; the row
        // bytes are the evidence identity, not a trust decision).
        let mut response = AuthorityPrepareResponse {
            acceptance: astral_types::AuthorityIntentAcceptance {
                authorization_edition: astral_types::AUTHORIZATION_EDITION,
                authority_id: "authority-1".to_owned(),
                intent_digest: "ab".repeat(32),
                reservation_id: "res-1".to_owned(),
                authority_term: 1,
                global_fence_sequence: 2,
                key_id: "signer-1".to_owned(),
                key_epoch: 1,
                accepted_at: 1_000,
                acceptance_nonce: "acc-1".to_owned(),
                signature: "0".repeat(128),
            },
            reservation: astral_types::AuthorityScopeReservation {
                reservation_id: "res-1".to_owned(),
                intent_digest: "ab".repeat(32),
                intent: astral_types::AuthoritySourceIntent {
                    authorization_edition: astral_types::AUTHORIZATION_EDITION,
                    mutation_kind: astral_types::AuthorityMutationKind::AuthorizationSource,
                    operation_id: "operation-1".to_owned(),
                    event_id: "event-1".to_owned(),
                    admission_proof_id: "proof-1".to_owned(),
                    request_digest: "cd".repeat(32),
                    service_id: "source-svc".to_owned(),
                    database_id: "db-1".to_owned(),
                    coverage: astral_types::AuthorityReservationCoverage::Global,
                    before_image_digest: None,
                    lease_not_before: 1_000,
                    lease_expires_at: 2_000,
                    intent_nonce: "nonce-1".to_owned(),
                },
                state: astral_types::AuthorityReservationState::Reserved,
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
            },
            global_frontier: astral_types::GlobalAuthorityFrontier {
                authorization_edition: astral_types::AUTHORIZATION_EDITION,
                authority_id: "authority-1".to_owned(),
                authority_term: 1,
                global_fence_sequence: 2,
                key_id: "signer-1".to_owned(),
                key_epoch: 1,
                root_id: "root-1".to_owned(),
                trust_root_digest: "aa".repeat(32),
                global_chain_digest: "bb".repeat(32),
                updated_at: 1_000,
            },
            read_gate: astral_types::AuthorityReadGate::blocked(),
        };
        let intent_digest = response.reservation.intent.digest().unwrap();
        response.reservation.intent_digest = intent_digest.clone();
        response.acceptance.intent_digest = intent_digest;
        response.validate().unwrap();
        serde_json::to_string(&response).unwrap()
    }
}
