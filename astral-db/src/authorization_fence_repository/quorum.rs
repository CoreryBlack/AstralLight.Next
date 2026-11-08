//! Quorum client and local durable evidence projections. Network I/O precedes every transaction.

use super::{AuthorizationTrustRoot, SqlxAuthorizationFenceProvider};
use crate::authority_config_completion::{
    reconcile_config_completions, ConfigCompletionGateway, ConfigCompletionReconcilerConfig,
};
use crate::authority_eligibility_completion::{
    reconcile_eligibility_completions, EligibilityCompletionGateway,
    EligibilityCompletionReconcilerConfig,
};
use crate::authority_source_outcome::{
    AuthoritySourceOutcomeReconciler, AuthoritySourceOutcomeReconcilerConfig,
    AuthoritySourceOwnerEntry,
};
use crate::authorization_fence_repository::abort::SourceReservationAbort;
use astral_authority::{client::AuthorityClientConfig, AuthorityClient};
use astral_types::{
    authorization_request_digest, AuthorityFenceReadResponse, AuthorityProtocolScope,
    AuthorityReadProofRequest, AuthorityScopePublicationCertificate, AuthorityTrustRoot,
    AuthorizationAdmission, AuthorizationAuthorityScope, AuthorizationFenceProof,
    CertifiedAuthorizationState, GlobalAuthorityFrontier, PolicyContext, PolicyError,
    PublishedCardAuthorization, PublishedCardEvidenceScope,
};
use sha2::{Digest, Sha256};
use sqlx::{MySql, MySqlPool, Transaction};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};
use time::OffsetDateTime;

const MAX_CERTIFICATE_CACHE_ENTRIES: usize = 4096;
const CERTIFICATE_CACHE_TTL: Duration = Duration::from_secs(300);
/// Keep recovery of one durable ABORTED row within the source-outcome cycle's
/// 2-second cadence; unfinished work is retried by stable identity next pass.
const ABORTED_RESERVATION_RECOVERY_BUDGET: Duration = Duration::from_secs(2);
/// Bound every recovery query to one durable tombstone per cycle.
const ABORTED_RESERVATION_RECOVERY_BATCH_SIZE: i64 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
struct AbortedRecoveryCursor(Option<(i64, String)>);

impl AbortedRecoveryCursor {
    fn next_page(&self) -> Option<&(i64, String)> {
        self.0.as_ref()
    }

    fn observe(&mut self, updated_at: i64, operation_id: String) {
        self.0 = Some((updated_at, operation_id));
    }

    fn reset(&mut self) {
        self.0 = None;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AbortedRecoveryTrigger {
    ForegroundReservation,
    BackgroundCycle,
}

enum AbortedRecoveryAttempt {
    Skipped,
    Attempted(Result<(), PolicyError>),
}

/// Build the one-row scan query for the durable ABORTED-only recovery cursor.
fn aborted_reservation_recovery_query(has_cursor: bool) -> String {
    let cursor_predicate = if has_cursor {
        " AND (updated_at, operation_id) > (?, ?)"
    } else {
        ""
    };
    format!(
        "SELECT operation_id, proof_id, CAST(reservation_json AS CHAR), request_digest, disposition, updated_at \
         FROM authorization_source_reservation WHERE disposition = 'ABORTED'{cursor_predicate} \
         ORDER BY updated_at, operation_id LIMIT {ABORTED_RESERVATION_RECOVERY_BATCH_SIZE}"
    )
}

async fn observe_recovery_cursor_before<F, Fut, T>(
    cursor: &Mutex<AbortedRecoveryCursor>,
    updated_at: i64,
    operation_id: &str,
    operation: F,
) -> Result<T, PolicyError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    cursor
        .lock()
        .map_err(|_| pending("abort recovery cursor lock unavailable"))?
        .observe(updated_at, operation_id.to_owned());
    Ok(operation().await)
}

async fn maybe_recover_aborted_reservations<F, Fut>(
    trigger: AbortedRecoveryTrigger,
    budget: Duration,
    recover: F,
) -> AbortedRecoveryAttempt
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), PolicyError>>,
{
    if trigger == AbortedRecoveryTrigger::ForegroundReservation {
        return AbortedRecoveryAttempt::Skipped;
    }
    let result = match tokio::time::timeout(budget, recover()).await {
        Ok(result) => result,
        Err(_) => Err(pending("ABORTED reservation recovery budget exhausted")),
    };
    AbortedRecoveryAttempt::Attempted(result)
}

#[cfg(test)]
mod abort_recovery_tests {
    use super::*;
    use astral_types::AuthorityMutationKind;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn platform_package_is_protected_only_for_trusted_registered_actions() {
        let mut context = PolicyContext::builder()
            .resource(Some("platform_package".into()))
            .action("create".into())
            .build();
        context.request_mutation_kind = Some(AuthorityMutationKind::ProtectedBusiness);
        assert_eq!(
            mutation_kind(&context),
            AuthorityMutationKind::ProtectedBusiness
        );

        context.request_mutation_kind = None;
        assert_eq!(
            mutation_kind(&context),
            AuthorityMutationKind::AuthorizationSource
        );

        context.request_mutation_kind = Some(AuthorityMutationKind::ProtectedBusiness);
        context.action = "publish".into();
        assert_eq!(
            mutation_kind(&context),
            AuthorityMutationKind::AuthorizationSource
        );

        for action in ["create", "update", "delete"] {
            context.action = action.into();
            assert_eq!(
                mutation_kind(&context),
                AuthorityMutationKind::ProtectedBusiness
            );
        }
    }

    #[test]
    fn permission_request_business_kind_requires_trusted_workflow_marker() {
        let mut context = PolicyContext::builder()
            .resource(Some("permission_request".into()))
            .action("create".into())
            .build();
        for action in ["create", "update", "approve"] {
            context.action = action.into();
            context.request_mutation_kind = None;
            assert_eq!(
                mutation_kind(&context),
                AuthorityMutationKind::AuthorizationSource
            );
            context.request_mutation_kind = Some(AuthorityMutationKind::ProtectedBusiness);
            assert_eq!(
                mutation_kind(&context),
                AuthorityMutationKind::ProtectedBusiness
            );
        }
        context.action = "delete".into();
        assert_eq!(
            mutation_kind(&context),
            AuthorityMutationKind::AuthorizationSource
        );
    }

    #[tokio::test]
    async fn foreground_reservation_skips_recovery_without_polling_the_future() {
        let calls = AtomicUsize::new(0);
        let attempt = maybe_recover_aborted_reservations(
            AbortedRecoveryTrigger::ForegroundReservation,
            ABORTED_RESERVATION_RECOVERY_BUDGET,
            || async {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;
        assert!(matches!(attempt, AbortedRecoveryAttempt::Skipped));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn background_recovery_stays_within_budget_and_runs_one_row_per_pass() {
        use std::sync::Arc;
        let rows = Arc::new(std::sync::Mutex::new(vec!["row-1", "row-2"]));
        let calls = AtomicUsize::new(0);
        let observed_rows = Arc::clone(&rows);
        let attempt = maybe_recover_aborted_reservations(
            AbortedRecoveryTrigger::BackgroundCycle,
            ABORTED_RESERVATION_RECOVERY_BUDGET,
            || async {
                calls.fetch_add(1, Ordering::SeqCst);
                let mut rows = observed_rows.lock().unwrap();
                assert_eq!(
                    ABORTED_RESERVATION_RECOVERY_BATCH_SIZE, 1,
                    "recovery may claim one durable ABORTED tombstone per cycle"
                );
                rows.remove(0);
                Ok(())
            },
        )
        .await;
        assert!(matches!(attempt, AbortedRecoveryAttempt::Attempted(Ok(()))));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(*rows.lock().unwrap(), vec!["row-2"]);
        for has_cursor in [false, true] {
            let query = aborted_reservation_recovery_query(has_cursor);
            assert!(query.contains("WHERE disposition = 'ABORTED'"));
            assert!(query.contains("LIMIT 1"));
            assert_eq!(
                query.contains("(updated_at, operation_id) > (?, ?)"),
                has_cursor,
                "the cursor predicate is present only after the first page"
            );
        }

        let timed = maybe_recover_aborted_reservations(
            AbortedRecoveryTrigger::BackgroundCycle,
            Duration::from_millis(1),
            || async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok(())
            },
        )
        .await;
        match timed {
            AbortedRecoveryAttempt::Attempted(Err(error)) => {
                assert!(error.to_string().contains("budget exhausted"));
            }
            _ => panic!("slow recovery must remain bounded and report pending"),
        }
    }

    #[tokio::test]
    async fn timed_out_first_row_advances_scan_cursor_for_later_rows() {
        let cursor = std::sync::Mutex::new(AbortedRecoveryCursor(None));
        let rows = [(10_i64, "operation-a"), (11_i64, "operation-b")];
        let select_after_cursor = |cursor: &AbortedRecoveryCursor| {
            rows.iter()
                .find(|(updated_at, operation_id)| {
                    cursor.next_page().is_none_or(|(last_updated, last_id)| {
                        (*updated_at, *operation_id) > (*last_updated, last_id.as_str())
                    })
                })
                .map(|(updated_at, operation_id)| (*updated_at, (*operation_id).to_owned()))
        };

        let first = select_after_cursor(&cursor.lock().unwrap()).unwrap();
        assert_eq!(first.1, "operation-a");
        let operation = observe_recovery_cursor_before(&cursor, first.0, &first.1, || async {
            tokio::time::sleep(Duration::from_millis(20)).await;
        });
        let timed = tokio::time::timeout(Duration::from_millis(1), operation).await;
        assert!(timed.is_err(), "first row models an abort call over budget");
        assert_eq!(
            cursor.lock().unwrap().next_page(),
            Some(&(10, "operation-a".to_owned())),
            "scan position advances before cancellable network work"
        );
        let second = select_after_cursor(&cursor.lock().unwrap()).unwrap();
        assert_eq!(second.1, "operation-b");
        observe_recovery_cursor_before(&cursor, second.0, &second.1, || async {})
            .await
            .unwrap();
        assert_eq!(
            cursor.lock().unwrap().next_page(),
            Some(&(11, "operation-b".to_owned()))
        );
        cursor.lock().unwrap().reset();
        assert!(
            select_after_cursor(&cursor.lock().unwrap()).is_some(),
            "after the terminal page resets, the next cycle starts a fresh scan"
        );
    }
}

mod attestation;

#[derive(sqlx::FromRow)]
struct DurableRequestProof {
    proof_json: String,
    scope_hash: Vec<u8>,
    certificate_hash: Vec<u8>,
    request_digest: Vec<u8>,
}

struct CachedCertificate {
    certificate: AuthorityScopePublicationCertificate,
    observed: Instant,
}

pub(super) struct QuorumProvider {
    client: AuthorityClient,
    roots: RwLock<AuthorityTrustRoot>,
    certificates: RwLock<HashMap<String, CachedCertificate>>,
    service_id: String,
    database_id: String,
    abort_recovery_cursor: Mutex<AbortedRecoveryCursor>,
}

fn pending(message: impl std::fmt::Display) -> PolicyError {
    PolicyError::Repository(format!("quorum authority pending: {message}"))
}

fn required(name: &str) -> Result<String, PolicyError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| pending(format!("{name} is required")))
}

async fn pem(name: &str) -> Result<Vec<u8>, PolicyError> {
    let path = required(name)?;
    let metadata = tokio::fs::metadata(&path)
        .await
        .map_err(|_| pending(format!("{name} is unreadable")))?;
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err(pending(format!("{name} must reference a bounded PEM file")));
    }
    tokio::fs::read(path)
        .await
        .map_err(|_| pending(format!("{name} read failed")))
}

pub(super) async fn provider_from_env(
    pool: MySqlPool,
) -> Result<Option<Arc<SqlxAuthorizationFenceProvider>>, PolicyError> {
    if std::env::var("ASTRAL_AUTHORITY_ENDPOINT").is_err() {
        if [
            "ASTRAL_AUTHORITY_ID",
            "ASTRAL_AUTHORITY_PUBLIC_KEY_HEX",
            "ASTRAL_AUTHORITY_GENESIS_PIN",
            "ASTRAL_AUTHORITY_SERVICE_ID",
            "ASTRAL_AUTHORITY_DATABASE_ID",
            "ASTRAL_AUTHORITY_CA_FILE",
            "ASTRAL_AUTHORITY_CLIENT_IDENTITY_FILE",
        ]
        .iter()
        .any(|name| std::env::var_os(name).is_some())
        {
            return Err(pending(
                "production requires ASTRAL_AUTHORITY_ENDPOINT and pinned mTLS configuration",
            ));
        }
        return Ok(None);
    }
    let service_id = required("ASTRAL_AUTHORITY_SERVICE_ID")?;
    let database_id = required("ASTRAL_AUTHORITY_DATABASE_ID")?;
    let client = AuthorityClient::new(AuthorityClientConfig {
        base_url: required("ASTRAL_AUTHORITY_ENDPOINT")?,
        server_ca_pem: pem("ASTRAL_AUTHORITY_CA_FILE").await?,
        client_identity_pem: pem("ASTRAL_AUTHORITY_CLIENT_IDENTITY_FILE").await?,
        service_id: service_id.clone(),
        pinned_genesis_trust_root_digest: required("ASTRAL_AUTHORITY_GENESIS_PIN")?,
        request_timeout: Duration::from_secs(3),
    })
    .map_err(pending)?;
    let attestation = client.attest_startup().await.map_err(pending)?;
    let signer = attestation.trust_root.signer_key().map_err(pending)?;
    let root = AuthorizationTrustRoot::new(
        attestation.authority_id,
        signer.key_id.clone(),
        signer.key_epoch,
        signer.verifying_key().map_err(pending)?,
    )?;
    let mut provider = SqlxAuthorizationFenceProvider::new(pool, root)?;
    provider.quorum = Some(Arc::new(QuorumProvider {
        client,
        roots: RwLock::new(attestation.trust_root),
        certificates: RwLock::new(HashMap::new()),
        service_id,
        database_id,
        abort_recovery_cursor: Mutex::new(AbortedRecoveryCursor(None)),
    }));
    Ok(Some(Arc::new(provider)))
}

fn mutation_kind(context: &PolicyContext) -> astral_types::AuthorityMutationKind {
    use astral_types::AuthorityMutationKind;
    match (context.resource.as_deref(), context.action.as_str()) {
        (Some("domain"), "update")
        | (Some("platform_tenant"), "create")
        | (Some("platform_package"), "create" | "update" | "delete")
        | (Some("permission_request"), "create" | "update" | "approve")
            if context.request_mutation_kind == Some(AuthorityMutationKind::ProtectedBusiness) =>
        {
            AuthorityMutationKind::ProtectedBusiness
        }
        (Some("monitor" | "notification" | "audit_quarantine"), _) => {
            AuthorityMutationKind::ProtectedBusiness
        }
        _ => AuthorityMutationKind::AuthorizationSource,
    }
}

/// Publication scope of one fence read. An explicitly supplied source scope
/// (ORG publication units pass their exact member scope) passes through
/// unchanged; card reads normalize to the CANONICAL card publication scope
/// (`Card{tenant, card, user: None, domain: Any}`) so publication
/// certificates are published and looked up exactly once per card identity,
/// while the minted request proof must still carry the exact actor lens
/// (`verify_response` asserts that separately).
fn publication_scope_for_read(
    source_scope: Option<AuthorityProtocolScope>,
    actor_scope: &AuthorityProtocolScope,
) -> Result<AuthorityProtocolScope, PolicyError> {
    match source_scope {
        Some(scope) => Ok(scope),
        None => actor_scope
            .canonical_card_publication_scope()
            .ok_or_else(|| pending("card fence reads require a card scope")),
    }
}

fn scope_hash(scope: &AuthorityProtocolScope) -> Result<Vec<u8>, PolicyError> {
    let mut digest = Sha256::new();
    digest.update(b"ASTRAL_AUTHORITY_SCOPE_KEY_V7\0");
    digest.update(scope.store_key_text().map_err(pending)?.as_bytes());
    Ok(digest.finalize().to_vec())
}

fn digest_bytes(value: &str) -> Result<Vec<u8>, PolicyError> {
    if !astral_types::authority_protocol_digest_shape(value) {
        return Err(pending("invalid digest"));
    }
    hex::decode(value).map_err(pending)
}

fn encoded<T: serde::Serialize>(value: &T) -> Result<String, PolicyError> {
    serde_json::to_string(value).map_err(pending)
}

fn decoded<T: serde::de::DeserializeOwned>(value: &str) -> Result<T, PolicyError> {
    serde_json::from_str(value).map_err(pending)
}

fn signed_counter(value: u64) -> Result<i64, PolicyError> {
    i64::try_from(value).map_err(|_| pending("authority counter exceeds local storage range"))
}

impl QuorumProvider {
    pub(super) async fn abort_reservation(
        &self,
        pool: &MySqlPool,
        abort: &SourceReservationAbort,
    ) -> Result<super::abort::SourceAbortReport, PolicyError> {
        tokio::time::timeout(
            Duration::from_secs(8),
            super::abort_source_reservation(pool, &self.client, abort),
        )
        .await
        .map_err(|_| {
            pending("source abort deadline exceeded; reconcile stable reservation identity")
        })?
    }

    async fn recover_aborted_reservations(&self, pool: &MySqlPool) -> Result<(), PolicyError> {
        let cursor = self
            .abort_recovery_cursor
            .lock()
            .map_err(|_| pending("abort recovery cursor lock unavailable"))?
            .clone();
        let query = aborted_reservation_recovery_query(cursor.next_page().is_some());
        let rows: Vec<(String, String, String, Vec<u8>, String, i64)> = match cursor.next_page() {
            Some((updated_at, operation_id)) => sqlx::query_as(&query)
                .bind(*updated_at)
                .bind(operation_id)
                .fetch_all(pool)
                .await
                .map_err(pending)?,
            None => sqlx::query_as(&query)
                .fetch_all(pool)
                .await
                .map_err(pending)?,
        };
        if rows.is_empty() {
            self.abort_recovery_cursor
                .lock()
                .map_err(|_| pending("abort recovery cursor lock unavailable"))?
                .reset();
            return Ok(());
        }
        if rows.len() > ABORTED_RESERVATION_RECOVERY_BATCH_SIZE as usize {
            return Err(pending(
                "ABORTED reservation recovery exceeded its batch bound",
            ));
        }
        for (operation_id, proof_id, reservation_json, request_digest, disposition, updated_at) in
            rows
        {
            let response: astral_types::AuthorityPrepareResponse = if disposition == "ABORTED" {
                match serde_json::from_str(&reservation_json) {
                    Ok(response) => response,
                    Err(error) => {
                        self.abort_recovery_cursor
                            .lock()
                            .map_err(|_| pending("abort recovery cursor lock unavailable"))?
                            .observe(updated_at, operation_id.clone());
                        tracing::error!(operation_id, proof_id, %error, "aborted source row prepare evidence is corrupt; recovery remains pending");
                        continue;
                    }
                }
            } else {
                self.abort_recovery_cursor
                    .lock()
                    .map_err(|_| pending("abort recovery cursor lock unavailable"))?
                    .observe(updated_at, operation_id);
                continue;
            };
            if let Err(error) = response.validate() {
                self.abort_recovery_cursor
                    .lock()
                    .map_err(|_| pending("abort recovery cursor lock unavailable"))?
                    .observe(updated_at, operation_id.clone());
                tracing::error!(operation_id, proof_id, %error, "aborted source row prepare evidence is invalid; recovery remains pending");
                continue;
            }
            let proof_digest = hex::encode(request_digest);
            if response.reservation.intent.operation_id != operation_id
                || response.reservation.intent.admission_proof_id != proof_id
                || response.reservation.intent.request_digest != proof_digest
                || response.reservation.state.as_text() != "RESERVED"
            {
                self.abort_recovery_cursor
                    .lock()
                    .map_err(|_| pending("abort recovery cursor lock unavailable"))?
                    .observe(updated_at, operation_id.clone());
                tracing::error!(
                    operation_id,
                    proof_id,
                    "aborted source row binding is corrupt; recovery remains pending"
                );
                continue;
            }
            let abort = SourceReservationAbort {
                operation_id,
                proof_id,
                request_digest: proof_digest,
                reservation_id: response.reservation.reservation_id.clone(),
                reason: super::abort::SOURCE_RESERVATION_ABORT_REASON.to_owned(),
                prepare_response_json: Some(reservation_json),
            };
            // Advance scan position before the authority await. Cancellation or
            // timeout must not pin the next cycle to this tombstone; unresolved
            // abort state remains durable and is reconciled by its stable id.
            let report = observe_recovery_cursor_before(
                &self.abort_recovery_cursor,
                updated_at,
                &abort.operation_id,
                || self.abort_reservation(pool, &abort),
            )
            .await?;
            match report {
                Ok(report) => tracing::debug!(
                    operation_id = %abort.operation_id,
                    reservation_id = %abort.reservation_id,
                    tombstone_updated_at = updated_at,
                    outcome = ?report.outcome,
                    "aborted reservation recovery reconciled stable authority identity"
                ),
                Err(error) => tracing::warn!(
                    operation_id = %abort.operation_id,
                    reservation_id = %abort.reservation_id,
                    error = %error,
                    "aborted reservation recovery remains pending"
                ),
            }
        }
        Ok(())
    }

    pub(super) async fn reconcile_source_outcomes(
        &self,
        pool: &MySqlPool,
        run_instance_id: &str,
    ) -> Result<crate::authority_source_outcome::AuthoritySourceOutcomeReconcileReport, PolicyError>
    {
        // Recovery must not spend the outer 10s source/publication cycle
        // deadline or starve its two owners. Its scan cursor advances before
        // each authority await; unresolved aborts remain durable for stable-ID
        // reconciliation when the cursor wraps on a later cycle.
        match maybe_recover_aborted_reservations(
            AbortedRecoveryTrigger::BackgroundCycle,
            ABORTED_RESERVATION_RECOVERY_BUDGET,
            || self.recover_aborted_reservations(pool),
        )
        .await
        {
            AbortedRecoveryAttempt::Skipped => {
                unreachable!("background recovery cannot be skipped")
            }
            AbortedRecoveryAttempt::Attempted(Ok(())) => {}
            AbortedRecoveryAttempt::Attempted(Err(error)) => tracing::warn!(
                run_instance_id,
                error = %error,
                "ABORTED reservation recovery failed; proceeding with source/publication reconciliation"
            ),
        }
        let owned = AuthoritySourceOwnerEntry {
            service_id: self.service_id.clone(),
            database_ids: vec![self.database_id.clone()],
        };
        let source = AuthoritySourceOutcomeReconciler::new(
            pool.clone(),
            Arc::new(self.client.clone()),
            AuthoritySourceOutcomeReconcilerConfig {
                batch_size: 1,
                run_instance_id: run_instance_id.to_owned(),
                owned: owned.clone(),
                ..Default::default()
            },
        )?;
        let eligibility_gateway: Arc<dyn EligibilityCompletionGateway> =
            Arc::new(self.client.clone());
        let eligibility_config = EligibilityCompletionReconcilerConfig {
            batch_size: 1,
            run_instance_id: run_instance_id.to_owned(),
            owned: owned.clone(),
            ..Default::default()
        };
        let config_gateway: Arc<dyn ConfigCompletionGateway> = Arc::new(self.client.clone());
        let config_config = ConfigCompletionReconcilerConfig {
            batch_size: 1,
            run_instance_id: run_instance_id.to_owned(),
            owned,
            ..Default::default()
        };

        // Each leg has a disjoint status predicate and default worker identity,
        // hence distinct DB-UTC leases. Run all bounded owners concurrently so
        // one slow endpoint cannot consume another leg's cycle budget. The
        // preceding ABORTED tombstone scan retains its independent 2s budget.
        let (source, publication, eligibility, config) = tokio::join!(
            source.run_once(),
            crate::authority_publication::reconcile_publications(
                pool,
                &self.client,
                &self.service_id,
                &self.database_id,
                run_instance_id,
            ),
            reconcile_eligibility_completions(
                pool.clone(),
                eligibility_gateway,
                &eligibility_config,
            ),
            reconcile_config_completions(pool.clone(), config_gateway, &config_config),
        );

        match &source {
            Ok(report) => tracing::debug!(
                leg = "source",
                phase = "run_once",
                run_instance_id,
                leased = report.leased,
                marked_committed = report.marked_committed,
                confirmed_committed = report.confirmed_committed,
                retried_after_unknown = report.retried_after_unknown,
                stayed_pending = report.stayed_pending,
                quarantined = report.quarantined,
                skipped = report.skipped,
                "authority source-outcome reconciliation leg completed"
            ),
            Err(error) => tracing::warn!(
                leg = "source",
                phase = "run_once",
                run_instance_id,
                error = %error,
                "authority source-outcome reconciliation leg failed; its lease remains fail-closed"
            ),
        }
        match publication {
            Ok(report) => tracing::debug!(
                leg = "publication",
                phase = "run_once",
                run_instance_id,
                leased = report.leased,
                certified = report.certified,
                pending = report.pending,
                budget_resets = report.budget_resets,
                published_leased = report.published_leased,
                published_completed = report.published_completed,
                published_waiting = report.published_waiting,
                "authority publication reconciliation leg completed"
            ),
            Err(error) => tracing::warn!(
                leg = "publication",
                phase = "run_once",
                run_instance_id,
                error = %error,
                "authority publication reconciliation leg failed; its lease remains fail-closed"
            ),
        }
        match eligibility {
            Ok(report) => tracing::debug!(
                leg = "eligibility",
                phase = "run_once",
                run_instance_id,
                leased = report.leased,
                completed = report.completed,
                confirmed_completed = report.confirmed_completed,
                stayed_pending = report.stayed_pending,
                quarantined = report.quarantined,
                skipped = report.skipped,
                "authority eligibility completion reconciliation leg completed"
            ),
            Err(error) => tracing::warn!(
                leg = "eligibility",
                phase = "run_once",
                run_instance_id,
                error = %error,
                "authority eligibility completion reconciliation leg failed; its lease remains fail-closed"
            ),
        }
        match config {
            Ok(report) => tracing::debug!(
                leg = "config",
                phase = "run_once",
                run_instance_id,
                leased = report.leased,
                completed = report.completed,
                confirmed_completed = report.confirmed_completed,
                stayed_pending = report.stayed_pending,
                quarantined = report.quarantined,
                skipped = report.skipped,
                "authority config completion reconciliation leg completed"
            ),
            Err(error) => tracing::warn!(
                leg = "config",
                phase = "run_once",
                run_instance_id,
                error = %error,
                "authority config completion reconciliation leg failed; its lease remains fail-closed"
            ),
        }
        let source = source?;
        Ok(source)
    }

    pub(super) async fn read(
        &self,
        pool: &MySqlPool,
        context: &PolicyContext,
        scope: &PublishedCardEvidenceScope,
        nonce: &str,
        source_scope: Option<AuthorityProtocolScope>,
    ) -> Result<AuthorizationFenceProof, PolicyError> {
        scope.validate().map_err(pending)?;
        let binding = authorization_request_digest(context)?;
        let actor_scope =
            AuthorityProtocolScope::Card(AuthorizationAuthorityScope::from_evidence_scope(scope));
        let publication_scope = publication_scope_for_read(source_scope.clone(), &actor_scope)?;
        let operation_id = context
            .request_operation_id
            .clone()
            .ok_or_else(|| pending("request operation missing"))?;
        let response = self
            .client
            .read_fence(
                Some(publication_scope.clone()),
                None,
                Some(AuthorityReadProofRequest {
                    actor_scope: actor_scope.clone(),
                    source_scope,
                    request_nonce: nonce.to_owned(),
                    operation_id: operation_id.clone(),
                    event_id: format!("{operation_id}:commit"),
                    mutation_kind: mutation_kind(context),
                    request_binding_digest: binding.clone(),
                    expected_frontier: None,
                    proof_ttl_seconds: Some(30),
                }),
            )
            .await
            .map_err(pending)?;
        let attestation = self.client.attest_startup().await.map_err(pending)?;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        verify_response(
            &response,
            &attestation.trust_root,
            &actor_scope,
            &publication_scope,
            nonce,
            &binding,
            now,
        )?;
        let proof = response
            .proof
            .as_ref()
            .ok_or_else(|| pending("fresh request proof missing"))?;
        if proof.operation_id != operation_id || proof.event_id != format!("{operation_id}:commit")
        {
            return Err(pending(
                "authority changed request operation or event identity",
            ));
        }
        *self
            .roots
            .write()
            .map_err(|_| pending("public trust registry unavailable"))? = attestation.trust_root;
        persist_response(pool, &response, &publication_scope, &binding).await?;
        if let Some(certificate) = response.scope_certificate.as_ref() {
            let hash = certificate.record_digest().map_err(pending)?;
            let mut certificates = self
                .certificates
                .write()
                .map_err(|_| pending("certificate cache unavailable"))?;
            certificates.retain(|_, entry| entry.observed.elapsed() < CERTIFICATE_CACHE_TTL);
            if !certificates.contains_key(&hash)
                && certificates.len() >= MAX_CERTIFICATE_CACHE_ENTRIES
            {
                return Err(pending("certificate cache capacity exhausted"));
            }
            certificates.insert(
                hash,
                CachedCertificate {
                    certificate: certificate.clone(),
                    observed: Instant::now(),
                },
            );
        }
        response
            .proof
            .ok_or_else(|| pending("fresh request proof missing"))
    }

    pub(super) async fn reserve(
        &self,
        pool: &MySqlPool,
        context: &PolicyContext,
        admission: &AuthorizationAdmission,
    ) -> Result<SourceReservationAbort, PolicyError> {
        match maybe_recover_aborted_reservations(
            AbortedRecoveryTrigger::ForegroundReservation,
            ABORTED_RESERVATION_RECOVERY_BUDGET,
            || self.recover_aborted_reservations(pool),
        )
        .await
        {
            AbortedRecoveryAttempt::Skipped => {}
            AbortedRecoveryAttempt::Attempted(_) => {
                unreachable!("foreground reservation must not run recovery")
            }
        }
        let proof = admission.proof();
        let binding = authorization_request_digest(context)?;
        if proof.request_binding_digest.as_deref() != Some(binding.as_str())
            || context.request_operation_id.as_deref() != Some(proof.operation_id.as_str())
        {
            return Err(pending("mutation admission request identity mismatch"));
        }
        let intent = astral_types::AuthoritySourceIntent {
            authorization_edition: astral_types::AUTHORIZATION_EDITION,
            mutation_kind: mutation_kind(context),
            operation_id: proof.operation_id.clone(),
            event_id: proof.event_id.clone(),
            admission_proof_id: proof.proof_id.clone(),
            request_digest: binding.clone(),
            service_id: self.service_id.clone(),
            database_id: self.database_id.clone(),
            coverage: astral_types::AuthorityReservationCoverage::Global,
            before_image_digest: None,
            lease_not_before: proof.not_before,
            lease_expires_at: proof.expires_at,
            intent_nonce: format!("{}:intent", proof.proof_id),
        };
        // A failed/unknown prepare remains quorum-owned and must not be automatically replayed.
        let response = self.client.prepare(intent.clone()).await.map_err(pending)?;
        if response.reservation.intent != intent {
            return Err(pending("reserved intent mismatch"));
        }
        let abort = SourceReservationAbort {
            operation_id: proof.operation_id.clone(),
            proof_id: proof.proof_id.clone(),
            request_digest: binding.clone(),
            reservation_id: response.reservation.reservation_id.clone(),
            reason: crate::authorization_fence_repository::abort::SOURCE_RESERVATION_ABORT_REASON
                .to_owned(),
            prepare_response_json: Some(encoded(&response)?),
        };
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let persist_result = async {
            let mut tx = pool.begin().await.map_err(pending)?;
            if let Err(error) = sqlx::query("INSERT INTO authorization_source_reservation (operation_id,proof_id,request_digest,reservation_json,disposition,updated_at) VALUES (?,?,?,?,?,?)")
                .bind(&proof.operation_id).bind(&proof.proof_id).bind(digest_bytes(&binding)?).bind(encoded(&response)?).bind("RESERVED").bind(now)
                .execute(&mut *tx).await
            {
                // Duplicate reservation: read the durable disposition back under
                // lock. An ABORTED tombstone is terminal and must NEVER be reset.
                let existing: Option<String> = sqlx::query_scalar(
                    "SELECT disposition FROM authorization_source_reservation \
                     WHERE operation_id = ? OR proof_id = ? FOR UPDATE",
                )
                .bind(&proof.operation_id)
                .bind(&proof.proof_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(pending)?;
                let message = if existing.as_deref() == Some("ABORTED") {
                    "source reservation is durably ABORTED; prepare can never reset the tombstone".to_owned()
                } else {
                    format!("local source reservation persist failed: {error}")
                };
                tx.rollback().await.ok();
                return Err(pending(message));
            }
            tx.commit()
                .await
                .map_err(|_| pending("local source reservation COMMIT unknown; reconcile operation"))
        }
        .await;
        if let Err(persist_error) = persist_result {
            // Prepare is remotely durable but local persistence may be unknown.
            // Reconcile first and let the same-row tombstone CAS decide whether
            // it is safe; the real prepare response is retained in `abort`.
            let cleanup = self.abort_reservation(pool, &abort).await;
            tracing::warn!(
                operation_id = %abort.operation_id,
                reservation_id = %abort.reservation_id,
                cleanup = ?cleanup,
                "local reservation persistence failed; attempted bounded stable-id reconciliation/abort"
            );
            return Err(persist_error);
        }
        Ok(abort)
    }

    pub(super) fn certify(
        &self,
        proof: AuthorizationFenceProof,
        evidence: Arc<PublishedCardAuthorization>,
        scope: &PublishedCardEvidenceScope,
        now: i64,
    ) -> Result<CertifiedAuthorizationState, PolicyError> {
        if proof.request_binding_digest.is_none() || proof.scope_certificate_hash.is_none() {
            return Err(pending(
                "production proof lacks request or certificate identity",
            ));
        }
        let roots = self
            .roots
            .read()
            .map_err(|_| pending("public trust registry unavailable"))?;
        let key = roots.signer_key().map_err(pending)?;
        if key.key_id != proof.key_id || key.key_epoch != proof.key_epoch {
            return Err(pending("proof signer is no longer active"));
        }
        let hash = proof
            .scope_certificate_hash
            .as_ref()
            .ok_or_else(|| pending("publication certificate missing"))?;
        let certificates = self
            .certificates
            .read()
            .map_err(|_| pending("certificate cache unavailable"))?;
        let entry = certificates
            .get(hash)
            .filter(|entry| entry.observed.elapsed() < CERTIFICATE_CACHE_TTL)
            .ok_or_else(|| pending("verified publication certificate expired or evicted"))?;
        let certificate_key = roots
            .key_by_id(&entry.certificate.key_id)
            .ok_or_else(|| pending("certificate key unavailable"))?;
        if certificate_key.role != astral_types::AuthorityRootKeyRole::Signer
            || certificate_key.key_epoch != entry.certificate.key_epoch
        {
            return Err(pending("certificate key role or epoch mismatch"));
        }
        CertifiedAuthorizationState::new_with_certificate(
            proof,
            evidence,
            entry.certificate.clone(),
            &key.verifying_key().map_err(pending)?,
            &certificate_key.verifying_key().map_err(pending)?,
            now,
            scope,
        )
        .map_err(pending)
    }
}

fn verify_response(
    response: &AuthorityFenceReadResponse,
    roots: &AuthorityTrustRoot,
    actor_scope: &AuthorityProtocolScope,
    publication_scope: &AuthorityProtocolScope,
    nonce: &str,
    binding: &str,
    now: i64,
) -> Result<(), PolicyError> {
    response.validate().map_err(pending)?;
    response
        .global_frontier
        .matches_trust_root(roots)
        .map_err(pending)?;
    if response.read_gate.blocks(actor_scope).map_err(pending)?
        || response
            .read_gate
            .blocks(publication_scope)
            .map_err(pending)?
    {
        return Err(pending("source reservation blocks reads"));
    }
    let certificate = response
        .scope_certificate
        .as_ref()
        .ok_or_else(|| pending("scope certificate missing"))?;
    if &certificate.scope != publication_scope {
        return Err(pending("scope certificate mismatch"));
    }
    let certificate_key = roots
        .key_by_id(&certificate.key_id)
        .ok_or_else(|| pending("certificate signer missing"))?;
    if certificate_key.role != astral_types::AuthorityRootKeyRole::Signer
        || certificate_key.key_epoch != certificate.key_epoch
    {
        return Err(pending("certificate key role or epoch mismatch"));
    }
    if certificate.authority_id != response.global_frontier.authority_id
        || certificate.authority_term > response.global_frontier.authority_term
        || certificate.global_fence_sequence > response.global_frontier.global_fence_sequence
        || certificate.key_epoch > response.global_frontier.key_epoch
        || response.observed_at > now
        || now.saturating_sub(response.observed_at) > 30
    {
        return Err(pending(
            "certificate or observation is outside the attested frontier",
        ));
    }
    certificate
        .verify_at(&certificate_key.verifying_key().map_err(pending)?, now)
        .map_err(pending)?;
    let certificate_hash = certificate.record_digest().map_err(pending)?;
    let proof = response
        .proof
        .as_ref()
        .ok_or_else(|| pending("fresh proof missing"))?;
    let signer = roots.signer_key().map_err(pending)?;
    proof
        .verify_at(&signer.verifying_key().map_err(pending)?, now)
        .map_err(pending)?;
    let frontier = &response.global_frontier;
    if actor_scope != &AuthorityProtocolScope::Card(proof.scope.clone())
        || proof.request_nonce != nonce
        || proof.request_binding_digest.as_deref() != Some(binding)
        || proof.scope_certificate_hash.as_deref() != Some(certificate_hash.as_str())
        || proof.authority_id != frontier.authority_id
        || proof.authority_term != frontier.authority_term
        || proof.global_fence_sequence != frontier.global_fence_sequence
        || proof.key_id != frontier.key_id
        || proof.key_epoch != frontier.key_epoch
        || proof.snapshot_hash != certificate.snapshot_hash
        || proof.expires_at - proof.not_before > super::MAX_AUTHORITY_PROOF_WINDOW_SECONDS
    {
        return Err(pending("fresh proof response binding mismatch"));
    }
    Ok(())
}

fn monotonic_frontier(
    previous: &GlobalAuthorityFrontier,
    next: &GlobalAuthorityFrontier,
) -> Result<(), PolicyError> {
    if previous.authority_id != next.authority_id
        || previous.root_id != next.root_id
        || next.authority_term < previous.authority_term
        || next.global_fence_sequence < previous.global_fence_sequence
        || next.key_epoch < previous.key_epoch
        || (next.authority_term == previous.authority_term
            && next.global_fence_sequence == previous.global_fence_sequence
            && next != previous)
    {
        return Err(pending(
            "global frontier rollback or same-frontier divergence",
        ));
    }
    Ok(())
}

async fn persist_response(
    pool: &MySqlPool,
    response: &AuthorityFenceReadResponse,
    scope: &AuthorityProtocolScope,
    binding: &str,
) -> Result<(), PolicyError> {
    let frontier = &response.global_frontier;
    let certificate = response
        .scope_certificate
        .as_ref()
        .ok_or_else(|| pending("certificate missing"))?;
    let certificate_hash = digest_bytes(&certificate.record_digest().map_err(pending)?)?;
    let scope_hash = scope_hash(scope)?;
    let proof = response
        .proof
        .as_ref()
        .ok_or_else(|| pending("proof missing"))?;
    // Single certificate-persistence owner: the shared publication-history
    // entry records the verified certificate immutably and advances the
    // current pointer only through its ancestry decision, in its own
    // transaction. The read response already verified signature/trust root;
    // any failure here persists NOTHING else (no proof row, no frontier
    // update) and the read stays pending — fail closed, no replay.
    crate::authority_publication::persist_authority_certificate(pool, certificate).await?;
    let mut tx = pool.begin().await.map_err(pending)?;
    sqlx::query("INSERT INTO authorization_global_projection (projection_id,authority_id,authority_term,global_fence_sequence,key_epoch,chain_digest,frontier_json,observed_at) VALUES (1,?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE projection_id=projection_id")
        .bind(&frontier.authority_id).bind(signed_counter(frontier.authority_term)?).bind(signed_counter(frontier.global_fence_sequence)?).bind(signed_counter(frontier.key_epoch)?).bind(digest_bytes(&frontier.global_chain_digest)?).bind(encoded(frontier)?).bind(response.observed_at).execute(&mut *tx).await.map_err(pending)?;
    let previous: String = sqlx::query_scalar("SELECT CAST(frontier_json AS CHAR) FROM authorization_global_projection WHERE projection_id=1 FOR UPDATE").fetch_one(&mut *tx).await.map_err(pending)?;
    monotonic_frontier(&decoded(&previous)?, frontier)?;
    sqlx::query("UPDATE authorization_global_projection SET authority_term=?,global_fence_sequence=?,key_epoch=?,chain_digest=?,frontier_json=?,observed_at=? WHERE projection_id=1")
        .bind(signed_counter(frontier.authority_term)?).bind(signed_counter(frontier.global_fence_sequence)?).bind(signed_counter(frontier.key_epoch)?).bind(digest_bytes(&frontier.global_chain_digest)?).bind(encoded(frontier)?).bind(response.observed_at).execute(&mut *tx).await.map_err(pending)?;
    sqlx::query("INSERT INTO authorization_request_proof (proof_id,request_nonce,scope_hash,certificate_hash,request_digest,proof_json,expires_at) VALUES (?,?,?,?,?,?,?)")
        .bind(&proof.proof_id).bind(&proof.request_nonce).bind(&scope_hash).bind(&certificate_hash).bind(digest_bytes(binding)?).bind(encoded(proof)?).bind(proof.expires_at).execute(&mut *tx).await.map_err(pending)?;
    tx.commit()
        .await
        .map_err(|_| pending("local proof COMMIT unknown; do not replay nonce"))?;
    Ok(())
}

pub(super) async fn validate_in_tx(
    tx: &mut Transaction<'_, MySql>,
    admission: &AuthorizationAdmission,
) -> Result<(), PolicyError> {
    let proof = admission.proof();
    let binding = proof
        .request_binding_digest
        .as_deref()
        .ok_or_else(|| pending("unbound admission"))?;
    let certificate_hash = proof
        .scope_certificate_hash
        .as_deref()
        .ok_or_else(|| pending("admission has no scope certificate"))?;
    let frontier: Option<String> = sqlx::query_scalar("SELECT CAST(frontier_json AS CHAR) FROM authorization_global_projection WHERE projection_id=1 FOR UPDATE").fetch_optional(&mut **tx).await.map_err(pending)?;
    let frontier: GlobalAuthorityFrontier =
        decoded(&frontier.ok_or_else(|| pending("local global projection missing"))?)?;
    if proof.authority_id != frontier.authority_id
        || proof.authority_term != frontier.authority_term
        || proof.global_fence_sequence != frontier.global_fence_sequence
        || proof.key_id != frontier.key_id
        || proof.key_epoch != frontier.key_epoch
    {
        return Err(pending("admission global frontier changed"));
    }
    let row: Option<DurableRequestProof> = sqlx::query_as("SELECT CAST(proof_json AS CHAR) AS proof_json,scope_hash,certificate_hash,request_digest FROM authorization_request_proof WHERE proof_id=? AND request_nonce=? FOR UPDATE")
        .bind(&proof.proof_id).bind(&proof.request_nonce).fetch_optional(&mut **tx).await.map_err(pending)?;
    let DurableRequestProof {
        proof_json: stored,
        scope_hash,
        certificate_hash: stored_certificate,
        request_digest: stored_binding,
    } = row.ok_or_else(|| pending("durable request proof missing"))?;
    if decoded::<AuthorizationFenceProof>(&stored)? != *proof
        || stored_binding != digest_bytes(binding)?
        || stored_certificate != digest_bytes(certificate_hash)?
    {
        return Err(pending("durable request proof diverged"));
    }
    let current: Option<Vec<u8>> = sqlx::query_scalar("SELECT certificate_hash FROM authorization_scope_certificate WHERE scope_hash=? FOR UPDATE").bind(scope_hash).fetch_optional(&mut **tx).await.map_err(pending)?;
    if current.as_deref() != Some(stored_certificate.as_slice()) {
        return Err(pending("admission scope certificate changed"));
    }
    let reservation: Option<(String, Vec<u8>, String)> = sqlx::query_as(
        "SELECT CAST(reservation_json AS CHAR),request_digest,disposition FROM authorization_source_reservation WHERE operation_id=? AND proof_id=? FOR UPDATE",
    ).bind(&proof.operation_id).bind(&proof.proof_id).fetch_optional(&mut **tx).await.map_err(pending)?;
    let (reservation, request_digest, disposition) =
        reservation.ok_or_else(|| pending("source mutation has no global reservation"))?;
    let reservation: astral_types::AuthorityPrepareResponse = decoded(&reservation)?;
    reservation.validate().map_err(pending)?;
    if disposition != "RESERVED"
        || request_digest != stored_binding
        || reservation.reservation.intent.admission_proof_id != proof.proof_id
        || reservation.reservation.intent.request_digest != binding
        || reservation.reservation.intent.operation_id != proof.operation_id
        || reservation.reservation.intent.event_id != proof.event_id
        || reservation.reservation.state != astral_types::AuthorityReservationState::Reserved
        || reservation.acceptance.authority_term != proof.authority_term
    {
        return Err(pending("source reservation diverged from admission"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::AuthorizationDomainScope;

    #[test]
    fn tenant_targets_alone_do_not_select_business_mutations() {
        use astral_types::AuthorityMutationKind;
        let mut context = PolicyContext::builder()
            .resource(Some("platform_tenant".into()))
            .action("create".into())
            .target_id(Some(17))
            .build();
        assert_eq!(
            mutation_kind(&context),
            AuthorityMutationKind::AuthorizationSource
        );
        context.request_mutation_kind = Some(AuthorityMutationKind::ProtectedBusiness);
        assert_eq!(
            mutation_kind(&context),
            AuthorityMutationKind::ProtectedBusiness
        );
        context.action = "update".into();
        assert_eq!(
            mutation_kind(&context),
            AuthorityMutationKind::AuthorizationSource
        );
        context.resource = Some("permission_rule".into());
        context.action = "create".into();
        assert_eq!(
            mutation_kind(&context),
            AuthorityMutationKind::AuthorizationSource
        );
    }

    #[test]
    fn card_reads_normalize_the_publication_scope_to_the_canonical_card() {
        // A lensed actor scope (user filter + exact domain) publishes and
        // looks up ONE canonical certificate per card identity.
        let lensed = AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
            tenant_id: 7,
            card_id: 17,
            user_id: Some(23),
            domain: AuthorizationDomainScope::Exact(31),
        });
        let canonical = publication_scope_for_read(None, &lensed).unwrap();
        assert_eq!(
            canonical,
            AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
                tenant_id: 7,
                card_id: 17,
                user_id: None,
                domain: AuthorizationDomainScope::Any,
            })
        );
        // The card-level lens normalizes to the same identity.
        let card_level = AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
            tenant_id: 7,
            card_id: 17,
            user_id: None,
            domain: AuthorizationDomainScope::Any,
        });
        assert_eq!(
            publication_scope_for_read(None, &card_level).unwrap(),
            canonical
        );
    }

    #[test]
    fn org_source_scopes_pass_through_unchanged() {
        let org = AuthorityProtocolScope::Org(astral_types::AuthorityOrgScope {
            tenant_id: 9,
            root_tenant_id: Some(1),
            member: astral_types::AuthorityOrgMemberSubject {
                user_id: 1,
                identity_card_id: 2,
                card_id: 3,
            },
        });
        assert_eq!(
            publication_scope_for_read(Some(org.clone()), &org).unwrap(),
            org
        );
    }

    #[test]
    fn card_reads_without_a_card_scope_fail_closed() {
        // Unreachable by type today (the actor scope is always a Card scope),
        // but the normalization must not invent a publication scope.
        let org = AuthorityProtocolScope::Org(astral_types::AuthorityOrgScope {
            tenant_id: 9,
            root_tenant_id: None,
            member: astral_types::AuthorityOrgMemberSubject {
                user_id: 1,
                identity_card_id: 2,
                card_id: 3,
            },
        });
        assert!(publication_scope_for_read(None, &org).is_err());
    }
}
