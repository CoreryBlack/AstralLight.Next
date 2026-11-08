//! Durable terminal closure for typed non-grant configuration source outcomes.
//!
//! This fourth source-outcome leg is deliberately disjoint from source commit
//! acknowledgement (`PENDING`), grant publication (`coverage` OBJECT), and
//! eligibility completion (its distinct typed kind). It verifies the retained
//! config envelope and current durable post-images in a short DB transaction,
//! then calls the authority only after releasing those DB locks. It never
//! replays source mutations or writes grant/projection/invalidation state.

use std::sync::Arc;
use std::time::Duration;

use astral_types::{
    config_image_digests, config_source_commit_digest, AuthorityCommitBinding,
    AuthorityConfigCompletionEvidence, AuthorityConfigCompletionResponse,
    AuthorityConfigSourceImage, AuthorityConfigSourceLookup, AuthorityConfigSourceOperation,
    AuthorityMutationKind, AuthorityRetainedStagedEvidence, AuthorityStagedSourceEvidence,
    PolicyError, AUTHORITY_CONFIG_COMPLETION_KIND,
};
use sha2::{Digest, Sha256};
use sqlx::{MySql, Pool};

use crate::authority_config_source::TypedSourceReadError;
use crate::authority_source_outcome::{AuthoritySourceOutcomeRow, AuthoritySourceOwnerEntry};

const CONFIG_VERIFICATION_TIMEOUT: Duration = Duration::from_secs(3);

const CONFIG_COMPLETION_TAG_PREDICATE: &str =
    "JSON_TYPE(JSON_EXTRACT(staged_evidence, '$.coverage')) = 'NULL' \
     AND JSON_UNQUOTE(JSON_EXTRACT(staged_evidence, '$.evidence.kind')) = 'CONFIG_COMPLETION' \
     AND JSON_UNQUOTE(JSON_EXTRACT(staged_evidence, '$.evidence.gateContract')) = 'DURABLE_CONFIG_V7'";

const CONFIG_COMPLETION_ROW_COLUMNS: &str =
    "reservation_id, operation_id, event_id, admission_proof_id, \
     request_binding_digest, mutation_kind, service_id, database_id, \
     source_commit_digest, before_image_digest, after_image_digest, source_receipts, \
     staged_evidence, status, attempts, generation, outcome_digest, committed_at";

fn map_sqlx_error(error: sqlx::Error, context: &'static str) -> PolicyError {
    if let sqlx::Error::Database(database) = &error {
        if database.is_unique_violation() {
            return PolicyError::Repository(format!(
                "{context}: durable source outcome identity already exists; reconcile it"
            ));
        }
    }
    PolicyError::Repository(format!("{context}: {error}"))
}

/// The authority-facing gateway; every method receives the same immutable
/// binding/evidence pair and stable identity. No source mutation is exposed.
#[async_trait::async_trait]
pub trait ConfigCompletionGateway: Send + Sync {
    async fn complete_config(
        &self,
        binding: AuthorityCommitBinding,
        completion: AuthorityConfigCompletionEvidence,
        retained: AuthorityRetainedStagedEvidence,
    ) -> Result<AuthorityConfigCompletionResponse, astral_authority::AuthorityClientError>;

    async fn reconcile_config(
        &self,
        binding: AuthorityCommitBinding,
        completion: AuthorityConfigCompletionEvidence,
        retained: AuthorityRetainedStagedEvidence,
    ) -> Result<AuthorityConfigCompletionResponse, astral_authority::AuthorityClientError>;
}

#[async_trait::async_trait]
impl ConfigCompletionGateway for astral_authority::client::AuthorityClient {
    async fn complete_config(
        &self,
        binding: AuthorityCommitBinding,
        completion: AuthorityConfigCompletionEvidence,
        retained: AuthorityRetainedStagedEvidence,
    ) -> Result<AuthorityConfigCompletionResponse, astral_authority::AuthorityClientError> {
        astral_authority::client::AuthorityClient::complete_config(
            self, binding, completion, retained,
        )
        .await
    }

    async fn reconcile_config(
        &self,
        binding: AuthorityCommitBinding,
        completion: AuthorityConfigCompletionEvidence,
        retained: AuthorityRetainedStagedEvidence,
    ) -> Result<AuthorityConfigCompletionResponse, astral_authority::AuthorityClientError> {
        astral_authority::client::AuthorityClient::reconcile_config(
            self, binding, completion, retained,
        )
        .await
    }
}

/// One batch size is intentionally small; workers own separate lease identities.
#[derive(Debug, Clone)]
pub struct ConfigCompletionReconcilerConfig {
    pub batch_size: u32,
    pub lease_seconds: i64,
    pub max_attempts: u32,
    pub worker_id: String,
    pub run_instance_id: String,
    pub owned: AuthoritySourceOwnerEntry,
}

impl Default for ConfigCompletionReconcilerConfig {
    fn default() -> Self {
        Self {
            batch_size: 1,
            lease_seconds: 30,
            max_attempts: 8,
            worker_id: "authority-config-completion-worker".to_owned(),
            run_instance_id: String::new(),
            owned: AuthoritySourceOwnerEntry {
                service_id: String::new(),
                database_ids: Vec::new(),
            },
        }
    }
}

impl ConfigCompletionReconcilerConfig {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if !(1..=8).contains(&self.batch_size)
            || !(5..=3600).contains(&self.lease_seconds)
            || !(1..=64).contains(&self.max_attempts)
        {
            return Err(PolicyError::InvalidContext(
                "config completion worker bounds are invalid".into(),
            ));
        }
        for (field, value) in [
            ("worker_id", self.worker_id.as_str()),
            ("run_instance_id", self.run_instance_id.as_str()),
            ("service_id", self.owned.service_id.as_str()),
        ] {
            validate_owner_text(field, value)?;
        }
        if self.worker_id.len() + self.run_instance_id.len() + 1 > 128 {
            return Err(PolicyError::InvalidContext(
                "config completion lease owner exceeds 128 characters".into(),
            ));
        }
        if self.owned.database_ids.is_empty() || self.owned.database_ids.len() > 64 {
            return Err(PolicyError::InvalidContext(
                "config completion owner must register 1..=64 database identities".into(),
            ));
        }
        for database_id in &self.owned.database_ids {
            validate_owner_text("database_id", database_id)?;
        }
        Ok(())
    }

    fn lease_owner(&self) -> String {
        format!("{}/{}", self.worker_id, self.run_instance_id)
    }

    fn owns(&self, service_id: &str, database_id: &str) -> bool {
        self.owned.service_id == service_id
            && self.owned.database_ids.iter().any(|id| id == database_id)
    }
}

fn validate_owner_text(field: &'static str, value: &str) -> Result<(), PolicyError> {
    if value.is_empty()
        || value.len() > 128
        || value.trim() != value
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(PolicyError::InvalidContext(format!(
            "config completion {field} is not canonical bounded text"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConfigCompletionReconcileReport {
    pub leased: u64,
    pub completed: u64,
    pub confirmed_completed: u64,
    pub stayed_pending: u64,
    pub quarantined: u64,
    pub skipped: u64,
}

/// Bounded DB-UTC lease/CAS/generation reconciler for CONFIG_COMPLETION only.
pub struct AuthorityConfigCompletionReconciler {
    pool: Pool<MySql>,
    gateway: Arc<dyn ConfigCompletionGateway>,
    config: ConfigCompletionReconcilerConfig,
}

impl AuthorityConfigCompletionReconciler {
    pub fn new(
        pool: Pool<MySql>,
        gateway: Arc<dyn ConfigCompletionGateway>,
        config: ConfigCompletionReconcilerConfig,
    ) -> Result<Self, PolicyError> {
        config.validate()?;
        Ok(Self {
            pool,
            gateway,
            config,
        })
    }

    fn push_owner_predicate(&self, query: &mut sqlx::QueryBuilder<'_, MySql>) {
        query
            .push(" AND service_id = ")
            .push_bind(self.config.owned.service_id.clone());
        query.push(" AND database_id IN (");
        let mut ids = query.separated(", ");
        for database_id in &self.config.owned.database_ids {
            ids.push_bind(database_id.clone());
        }
        ids.push_unseparated(")");
    }

    async fn lease_batch(&self) -> Result<(Vec<AuthoritySourceOutcomeRow>, u64, u64), PolicyError> {
        let mut selection = sqlx::QueryBuilder::<MySql>::new(
            "SELECT reservation_id, generation, attempts FROM authority_source_outcome \
             WHERE status = 'COMMITTED' AND mutation_kind = 'AUTHORIZATION_SOURCE' \
             AND (lease_until IS NULL OR lease_until <= UNIX_TIMESTAMP()) AND ",
        );
        selection.push(CONFIG_COMPLETION_TAG_PREDICATE);
        self.push_owner_predicate(&mut selection);
        selection
            .push(" ORDER BY reservation_id LIMIT ")
            .push_bind(self.config.batch_size);
        let candidates: Vec<(String, u64, u32)> = selection
            .build_query_as()
            .fetch_all(&self.pool)
            .await
            .map_err(|error| map_sqlx_error(error, "select config completion outcomes"))?;

        let mut rows = Vec::with_capacity(candidates.len());
        let mut skipped = 0;
        let mut exhausted = 0;
        for (reservation_id, observed_generation, attempts) in candidates {
            if attempts >= self.config.max_attempts {
                let mut quarantine = sqlx::QueryBuilder::<MySql>::new(
                    "UPDATE authority_source_outcome SET status = 'QUARANTINED', \
                     last_error = 'config completion retry budget exhausted; reconcile before recovery', \
                     generation = generation + 1, lease_owner = NULL, lease_until = NULL, \
                     updated_at = UNIX_TIMESTAMP() WHERE status = 'COMMITTED' \
                     AND mutation_kind = 'AUTHORIZATION_SOURCE' \
                     AND (lease_until IS NULL OR lease_until <= UNIX_TIMESTAMP()) AND reservation_id = ",
                );
                quarantine
                    .push_bind(reservation_id)
                    .push(" AND generation = ")
                    .push_bind(observed_generation)
                    .push(" AND attempts >= ")
                    .push_bind(self.config.max_attempts)
                    .push(" AND ")
                    .push(CONFIG_COMPLETION_TAG_PREDICATE);
                self.push_owner_predicate(&mut quarantine);
                let result = quarantine
                    .build()
                    .execute(&self.pool)
                    .await
                    .map_err(|error| {
                        map_sqlx_error(error, "quarantine exhausted config completion outcome")
                    })?;
                if result.rows_affected() == 1 {
                    exhausted += 1;
                } else {
                    skipped += 1;
                }
                continue;
            }
            let expected_generation = observed_generation.checked_add(1).ok_or_else(|| {
                PolicyError::InvalidContext("config completion generation exhausted".into())
            })?;
            let mut claim = sqlx::QueryBuilder::<MySql>::new(
                "UPDATE authority_source_outcome SET lease_owner = ",
            );
            claim
                .push_bind(self.config.lease_owner())
                .push(", lease_until = UNIX_TIMESTAMP() + ")
                .push_bind(self.config.lease_seconds)
                .push(", generation = generation + 1, attempts = attempts + 1, updated_at = UNIX_TIMESTAMP() \
                       WHERE reservation_id = ")
                .push_bind(reservation_id.clone())
                .push(" AND status = 'COMMITTED' AND mutation_kind = 'AUTHORIZATION_SOURCE' AND generation = ")
                .push_bind(observed_generation)
                .push(" AND (lease_until IS NULL OR lease_until <= UNIX_TIMESTAMP()) AND attempts < ")
                .push_bind(self.config.max_attempts)
                .push(" AND ")
                .push(CONFIG_COMPLETION_TAG_PREDICATE);
            self.push_owner_predicate(&mut claim);
            let result = claim
                .build()
                .execute(&self.pool)
                .await
                .map_err(|error| map_sqlx_error(error, "lease config completion outcome"))?;
            if result.rows_affected() != 1 {
                skipped += 1;
                continue;
            }
            let mut readback = sqlx::QueryBuilder::<MySql>::new(format!(
                "SELECT {CONFIG_COMPLETION_ROW_COLUMNS} FROM authority_source_outcome WHERE reservation_id = ",
            ));
            readback
                .push_bind(reservation_id)
                .push(" AND status = 'COMMITTED' AND mutation_kind = 'AUTHORIZATION_SOURCE' AND lease_owner = ")
                .push_bind(self.config.lease_owner())
                .push(" AND lease_until > UNIX_TIMESTAMP() AND generation = ")
                .push_bind(expected_generation)
                .push(" AND attempts <= ")
                .push_bind(self.config.max_attempts)
                .push(" AND ")
                .push(CONFIG_COMPLETION_TAG_PREDICATE);
            self.push_owner_predicate(&mut readback);
            let row: Option<AuthoritySourceOutcomeRow> = readback
                .build_query_as()
                .fetch_optional(&self.pool)
                .await
                .map_err(|error| {
                    map_sqlx_error(error, "reread leased config completion outcome")
                })?;
            match row {
                Some(row) if self.config.owns(&row.service_id, &row.database_id) => rows.push(row),
                _ => skipped += 1,
            }
        }
        Ok((rows, skipped, exhausted))
    }

    async fn finalize(
        &self,
        row: &AuthoritySourceOutcomeRow,
        completed: bool,
        response: Option<&AuthorityConfigCompletionResponse>,
        reason: Option<&str>,
    ) -> Result<bool, PolicyError> {
        if !self.config.owns(&row.service_id, &row.database_id) {
            return Ok(false);
        }
        let (kind, response_json, response_digest) = if completed {
            let response = response.ok_or_else(|| {
                PolicyError::InvalidContext(
                    "completed config outcome requires its full authority response".into(),
                )
            })?;
            response
                .validate()
                .map_err(|error| PolicyError::InvalidContext(error.to_string()))?;
            let response_bytes = serde_json::to_vec(response).map_err(|_| {
                PolicyError::InvalidContext("config authority response cannot be encoded".into())
            })?;
            let digest = hex::encode(Sha256::digest(&response_bytes));
            (
                Some(AUTHORITY_CONFIG_COMPLETION_KIND),
                Some(serde_json::to_string(response).map_err(|_| {
                    PolicyError::InvalidContext(
                        "config authority response cannot be encoded".into(),
                    )
                })?),
                Some(digest),
            )
        } else {
            (None, None, None)
        };
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| map_sqlx_error(error, "begin config completion finalization"))?;
        let mut query = sqlx::QueryBuilder::<MySql>::new(if completed {
            "UPDATE authority_source_outcome SET status = 'COMPLETED', authority_disposition = 'COMPLETED', authority_terminal_kind = "
        } else {
            "UPDATE authority_source_outcome SET status = 'QUARANTINED', last_error = "
        });
        if completed {
            query
                .push_bind(kind.expect("completed terminal kind"))
                .push(", authority_terminal_response = ")
                .push_bind(response_json.expect("completed terminal response"))
                .push(", authority_terminal_response_digest = UNHEX(")
                .push_bind(response_digest.expect("completed terminal digest"))
                .push(")");
        } else {
            query.push_bind(reason.unwrap_or("config completion quarantined"));
        }
        query
            .push(", lease_owner = NULL, lease_until = NULL, updated_at = UNIX_TIMESTAMP() \
                   WHERE reservation_id = ")
            .push_bind(row.reservation_id.clone())
            .push(" AND status = 'COMMITTED' AND mutation_kind = 'AUTHORIZATION_SOURCE' AND lease_owner = ")
            .push_bind(self.config.lease_owner())
            .push(" AND lease_until > UNIX_TIMESTAMP() AND generation = ")
            .push_bind(row.generation)
            .push(" AND attempts <= ")
            .push_bind(self.config.max_attempts)
            .push(" AND ")
            .push(CONFIG_COMPLETION_TAG_PREDICATE);
        self.push_owner_predicate(&mut query);
        let result = query
            .build()
            .execute(&mut *tx)
            .await
            .map_err(|error| map_sqlx_error(error, "finalize config completion outcome"))?;
        if result.rows_affected() != 1 {
            tx.rollback().await.map_err(|error| {
                map_sqlx_error(error, "rollback skipped config completion finalization")
            })?;
            return Ok(false);
        }
        if completed {
            let stored: Option<(String, String, Vec<u8>)> = sqlx::query_as(
                "SELECT authority_terminal_kind, CAST(authority_terminal_response AS CHAR), \
                 authority_terminal_response_digest FROM authority_source_outcome \
                 WHERE reservation_id = ? AND status = 'COMPLETED' FOR UPDATE",
            )
            .bind(&row.reservation_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| map_sqlx_error(error, "read back config terminal response"))?;
            let Some((stored_kind, stored_json, stored_digest)) = stored else {
                tx.rollback().await.map_err(|error| {
                    map_sqlx_error(error, "rollback missing config terminal response")
                })?;
                return Err(PolicyError::Repository(
                    "completed config outcome has no terminal response".into(),
                ));
            };
            let stored_response: AuthorityConfigCompletionResponse =
                serde_json::from_str(&stored_json).map_err(|_| {
                    PolicyError::Repository("stored config terminal response is malformed".into())
                })?;
            stored_response
                .validate()
                .map_err(|error| PolicyError::Repository(error.to_string()))?;
            let expected = hex::decode(hex::encode(Sha256::digest(
                serde_json::to_vec(&stored_response).map_err(|_| {
                    PolicyError::Repository(
                        "stored config terminal response cannot be encoded".into(),
                    )
                })?,
            )))
            .map_err(|_| {
                PolicyError::Repository("stored config terminal digest is invalid".into())
            })?;
            if stored_kind != AUTHORITY_CONFIG_COMPLETION_KIND
                || stored_response != *response.expect("completed response")
                || stored_digest != expected
            {
                tx.rollback().await.map_err(|error| {
                    map_sqlx_error(error, "rollback corrupt config terminal response")
                })?;
                return Err(PolicyError::Repository(
                    "stored config terminal response failed exact validation".into(),
                ));
            }
        }
        tx.commit()
            .await
            .map_err(|error| map_sqlx_error(error, "commit config completion finalization"))?;
        Ok(true)
    }

    pub async fn run_once(&self) -> Result<ConfigCompletionReconcileReport, PolicyError> {
        let (rows, skipped, exhausted) = self.lease_batch().await?;
        let mut report = ConfigCompletionReconcileReport {
            leased: rows.len() as u64,
            skipped: skipped + exhausted,
            ..Default::default()
        };
        for row in rows {
            match self.process_row(&row).await {
                Processed::Completed => report.completed += 1,
                Processed::ConfirmedCompleted => report.confirmed_completed += 1,
                Processed::StayedPending => report.stayed_pending += 1,
                Processed::Quarantined => report.quarantined += 1,
            }
        }
        Ok(report)
    }

    async fn process_row(&self, row: &AuthoritySourceOutcomeRow) -> Processed {
        let record = match row.to_verified_publication_record("COMMITTED") {
            Ok(record) => record,
            Err(error) => {
                return self
                    .quarantine_row(
                        row,
                        &format!("config outcome failed its self-digest: {error}"),
                    )
                    .await
            }
        };
        let Some(staged_json) = row.staged_evidence.as_deref() else {
            return self
                .quarantine_row(row, "config outcome lacks retained staged evidence")
                .await;
        };
        let staged_digest = match row.staged_digest() {
            Ok(digest) => digest,
            Err(error) => {
                return self
                    .quarantine_row(
                        row,
                        &format!("config retained evidence digest failed: {error}"),
                    )
                    .await
            }
        };
        let staged_envelope: AuthorityStagedSourceEvidence = match serde_json::from_str(staged_json)
        {
            Ok(envelope) => envelope,
            Err(error) => {
                return self
                    .quarantine_row(
                        row,
                        &format!("config source envelope is malformed: {error}"),
                    )
                    .await
            }
        };
        if staged_envelope.coverage.is_some() {
            return self
                .quarantine_row(row, "config source outcome unexpectedly declares coverage")
                .await;
        }
        let completion: AuthorityConfigCompletionEvidence =
            match serde_json::from_value(staged_envelope.evidence.clone()) {
                Ok(completion) => completion,
                Err(error) => {
                    return self
                        .quarantine_row(
                            row,
                            &format!("config completion evidence is malformed: {error}"),
                        )
                        .await
                }
            };
        if let Err(error) = completion.validate(&record.operation_id) {
            return self
                .quarantine_row(
                    row,
                    &format!("config completion evidence failed validation: {error}"),
                )
                .await;
        }
        if let Err(error) = completion.validate(&record.operation_id) {
            return self
                .quarantine_row(
                    row,
                    &format!("config completion evidence failed validation: {error}"),
                )
                .await;
        }
        let (expected_before_digest, expected_after_digest) =
            match config_image_digests(&completion.source_batch.source_images) {
                Ok(digests) => digests,
                Err(error) => {
                    return self
                        .quarantine_row(
                            row,
                            &format!("config image digest framing failed validation: {error}"),
                        )
                        .await
                }
            };
        if record.before_image_digest.as_deref() != Some(expected_before_digest.as_str())
            || record.after_image_digest.as_deref() != Some(expected_after_digest.as_str())
        {
            return self
                .quarantine_row(
                    row,
                    "config source outcome before/after binding is not the shared typed digest",
                )
                .await;
        }
        let expected_source_commit_digest = match config_source_commit_digest(&completion) {
            Ok(digest) => digest,
            Err(error) => {
                return self
                    .quarantine_row(
                        row,
                        &format!("config source commit digest framing failed: {error}"),
                    )
                    .await
            }
        };
        if expected_source_commit_digest != record.source_commit_digest {
            return self
                .quarantine_row(
                    row,
                    "config source commit digest does not bind the canonical shared wrapper",
                )
                .await;
        }
        if row.mutation_kind != AuthorityMutationKind::AuthorizationSource.as_text()
            || row.status != "COMMITTED"
            || row.committed_at <= 0
            || !self.config.owns(&row.service_id, &row.database_id)
        {
            return self
                .quarantine_row(
                    row,
                    "config source outcome binding is not a committed registered source",
                )
                .await;
        }

        if let Err(error) = tokio::time::timeout(
            CONFIG_VERIFICATION_TIMEOUT,
            verify_config_durable_facts(
                &self.pool,
                &record.operation_id,
                &record.event_id,
                &record.source_receipts,
                &completion,
            ),
        )
        .await
        .map_err(|_| {
            ConfigVerificationError::transient("config durable verification exceeded 3 seconds")
        })
        .and_then(|result| result)
        {
            return match error {
                ConfigVerificationError::Transient(reason) => {
                    tracing::warn!(
                        reservation_id = %row.reservation_id,
                        operation_id = %row.operation_id,
                        reason = %reason,
                        "config durable verification stayed pending after a transient read failure"
                    );
                    Processed::StayedPending
                }
                ConfigVerificationError::Proof(reason) => {
                    self.quarantine_row(
                        row,
                        &format!("config durable post-image verification failed: {reason}"),
                    )
                    .await
                }
            };
        }

        let (Some(before_image_digest), Some(after_image_digest)) = (
            record.before_image_digest.clone(),
            record.after_image_digest.clone(),
        ) else {
            return self
                .quarantine_row(
                    row,
                    "config source outcome lacks full before/after binding digests",
                )
                .await;
        };
        let binding = AuthorityCommitBinding {
            reservation_id: record.reservation_id.clone(),
            operation_id: record.operation_id.clone(),
            event_id: record.event_id.clone(),
            admission_proof_id: record.admission_proof_id.clone(),
            mutation_kind: record.mutation_kind,
            service_id: record.service_id.clone(),
            database_id: record.database_id.clone(),
            request_digest: record.request_binding_digest.clone(),
            source_commit_digest: record.source_commit_digest.clone(),
            before_image_digest: Some(before_image_digest),
            after_image_digest,
            source_outcome_digest: hex::encode(&row.outcome_digest),
            staged_evidence_digest: staged_digest,
        };
        if binding.validate().is_err() {
            return self
                .quarantine_row(
                    row,
                    "config source outcome cannot form its full commit binding",
                )
                .await;
        }
        let retained = AuthorityRetainedStagedEvidence::new(staged_json.to_owned());
        match self
            .gateway
            .complete_config(binding.clone(), completion.clone(), retained.clone())
            .await
        {
            Ok(response) => {
                if !terminal_matches_request(&response, &binding, &completion) {
                    return self
                        .quarantine_row(
                            row,
                            "authority config receipt does not match the exact request",
                        )
                        .await;
                }
                if self
                    .finalize(row, true, Some(&response), None)
                    .await
                    .unwrap_or(false)
                {
                    Processed::Completed
                } else {
                    Processed::StayedPending
                }
            }
            Err(error) if should_quarantine_authority_error(&error) => {
                self.quarantine_row(
                    row,
                    &format!("authority rejected config completion: {error}"),
                )
                .await
            }
            Err(_unknown_or_conflict) => {
                // Reconcile the stable reservation/operation identity. The
                // client may idempotently close the authority-side terminal;
                // this path never replays the source transaction.
                match self
                    .gateway
                    .reconcile_config(binding.clone(), completion.clone(), retained)
                    .await
                {
                    Ok(response) if terminal_matches_request(&response, &binding, &completion) => {
                        if self
                            .finalize(row, true, Some(&response), None)
                            .await
                            .unwrap_or(false)
                        {
                            Processed::ConfirmedCompleted
                        } else {
                            Processed::StayedPending
                        }
                    }
                    Ok(_) => {
                        self.quarantine_row(
                            row,
                            "stable-identity reconciliation returned a non-matching config receipt",
                        )
                        .await
                    }
                    Err(error) if should_quarantine_authority_error(&error) => {
                        self.quarantine_row(
                            row,
                            &format!(
                                "authority stable-identity config reconciliation rejected: {error}"
                            ),
                        )
                        .await
                    }
                    Err(_) => Processed::StayedPending,
                }
            }
        }
    }

    async fn quarantine_row(&self, row: &AuthoritySourceOutcomeRow, reason: &str) -> Processed {
        match self.finalize(row, false, None, Some(reason)).await {
            Ok(true) => {
                tracing::error!(
                    error_code = "AUTHORITY_CONFIG_COMPLETION_QUARANTINED",
                    reservation_id = %row.reservation_id,
                    operation_id = %row.operation_id,
                    reason = %reason,
                    "config completion quarantined for operator reconciliation"
                );
                Processed::Quarantined
            }
            _ => Processed::StayedPending,
        }
    }
}

enum Processed {
    Completed,
    ConfirmedCompleted,
    StayedPending,
    Quarantined,
}

fn should_quarantine_authority_error(error: &astral_authority::AuthorityClientError) -> bool {
    match error {
        astral_authority::AuthorityClientError::Rejected { code, .. } => matches!(
            code.as_str(),
            "NotFound"
                | "LeaseExpired"
                | "CallerIdentityMismatch"
                | "DigestMismatch"
                | "TrustRootMismatch"
                | "EditionMismatch"
        ),
        _ => false,
    }
}

fn terminal_matches_request(
    response: &AuthorityConfigCompletionResponse,
    binding: &AuthorityCommitBinding,
    completion: &AuthorityConfigCompletionEvidence,
) -> bool {
    response.validate().is_ok()
        && response.receipt.binding == *binding
        && response.receipt.completion == *completion
        && response.receipt.reservation_id == binding.reservation_id
        && response.receipt.operation_id == binding.operation_id
        && response.receipt.event_id == binding.event_id
        && response.reservation.reservation_id == binding.reservation_id
        && response.reservation.intent.operation_id == binding.operation_id
        && response.reservation.intent.event_id == binding.event_id
        && response.reservation.intent.admission_proof_id == binding.admission_proof_id
        && response.reservation.intent.service_id == binding.service_id
        && response.reservation.intent.database_id == binding.database_id
}

/// Verify actual current source post-images, audit readbacks, and absence of all
/// grant/projection/invalidation side effects. The authority call occurs only
/// after this short read transaction has been rolled back and released.
enum ConfigVerificationError {
    /// The durable read transaction or its rollback was not proven complete.
    /// The outcome remains COMMITTED/PENDING and must be reconciled later.
    Transient(String),
    /// The durable rows were read successfully but contradict the retained
    /// source proof. This is corruption or an actual proof mismatch.
    Proof(String),
}

impl ConfigVerificationError {
    fn transient(message: impl Into<String>) -> Self {
        Self::Transient(message.into())
    }

    fn proof(message: impl Into<String>) -> Self {
        Self::Proof(message.into())
    }
}

fn map_typed_source_read_error(error: TypedSourceReadError) -> ConfigVerificationError {
    match error {
        TypedSourceReadError::SqlxTransient { context, source } => {
            ConfigVerificationError::transient(format!("{context}: {source}"))
        }
        other => ConfigVerificationError::proof(other.to_string()),
    }
}

fn map_verification_sql_error(
    error: sqlx::Error,
    context: &'static str,
) -> ConfigVerificationError {
    map_typed_source_read_error(TypedSourceReadError::from_sqlx(context, error))
}

async fn verify_config_durable_facts(
    pool: &Pool<MySql>,
    operation_id: &str,
    event_id: &str,
    source_receipts: &[crate::authority_source_outcome::AuthoritySourceReceiptIdentity],
    completion: &AuthorityConfigCompletionEvidence,
) -> Result<(), ConfigVerificationError> {
    let mut tx = pool.begin().await.map_err(|error| {
        map_verification_sql_error(error, "config verification transaction begin")
    })?;
    let result = verify_config_durable_facts_in_tx(
        &mut tx,
        operation_id,
        event_id,
        source_receipts,
        completion,
    )
    .await;
    let rollback = tx.rollback().await.map_err(|error| {
        map_verification_sql_error(error, "config verification transaction rollback")
    });
    match (result, rollback) {
        (_, Err(error)) => Err(error),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

async fn verify_config_durable_facts_in_tx(
    tx: &mut sqlx::Transaction<'_, MySql>,
    operation_id: &str,
    event_id: &str,
    source_receipts: &[crate::authority_source_outcome::AuthoritySourceReceiptIdentity],
    completion: &AuthorityConfigCompletionEvidence,
) -> Result<(), ConfigVerificationError> {
    completion.validate(operation_id).map_err(|error| {
        ConfigVerificationError::proof(format!("typed completion contract rejected: {error}"))
    })?;
    let batch = &completion.source_batch;
    if batch.delta.is_some()
        || !batch.source_projection.is_empty()
        || !batch.invalidations.is_empty()
    {
        return Err(ConfigVerificationError::proof(
            "config completion contains grant/projection/invalidation payload",
        ));
    }

    // Every source image is exact current post-state; DELETE is exact canonical
    // absence. The closed shared reader locks the complete aggregate and its
    // owned children (including LevelTemplate and RuleSet aggregates).
    let mut expected_receipts = Vec::with_capacity(batch.source_images.len() + batch.audits.len());
    for image in &batch.source_images {
        verify_current_source_image(tx, image).await?;
        expected_receipts.push((
            "typed_source_row_image".to_owned(),
            format!(
                "{}:{}:{}",
                image.table.as_str(),
                image.key,
                operation_as_text(image.operation)
            ),
        ));
    }
    for audit in &batch.audits {
        type AuditRow = (
            i64,
            i64,
            String,
            String,
            String,
            Option<String>,
            Option<String>,
        );
        let row: Option<AuditRow> = sqlx::query_as(
            "SELECT id, user_id, action, resource, decision, event_type, request_id \
             FROM audit_log WHERE id = ? FOR UPDATE",
        )
        .bind(audit.audit_log_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| map_verification_sql_error(error, "config audit readback"))?;
        let Some(row) = row else {
            return Err(ConfigVerificationError::proof(
                "config audit receipt has no durable audit row",
            ));
        };
        if row.0 != audit.audit_log_id
            || row.1 != audit.user_id
            || row.2 != audit.action
            || row.3 != audit.resource
            || row.4 != audit.decision
            || row.5 != Some(audit.event_type.clone())
            || row.6 != Some(operation_id.to_owned())
            || audit.request_id.as_deref() != Some(operation_id)
        {
            return Err(ConfigVerificationError::proof(
                "config audit receipt differs from its correlated durable row",
            ));
        }
        expected_receipts.push(("audit_log".to_owned(), audit.audit_log_id.to_string()));
    }
    expected_receipts.sort();
    let mut actual_receipts: Vec<_> = source_receipts
        .iter()
        .map(|receipt| (receipt.identity_kind.clone(), receipt.identity.clone()))
        .collect();
    actual_receipts.sort();
    if actual_receipts != expected_receipts {
        return Err(ConfigVerificationError::proof(
            "source outcome receipt identities differ from exact config image/audit set",
        ));
    }

    // The config operation must not own grant delta/revision/publication rows.
    // Table and column names below are fixed code constants, never user input.
    const GRANT_OPERATION_TABLES: &[&str] = &[
        "authorization_grant_revision",
        "authorization_delta_event",
        "authorization_impact_plan",
        "authorization_impact_plan_item",
        "authorization_projection_manifest",
        "authorization_projection_manifest_segment",
        "authorization_projection_current",
        "authorization_archive_outbox",
        "authorization_archive_manifest",
        "authorization_scope_certificate_history",
    ];
    for table in GRANT_OPERATION_TABLES {
        let sql = format!("SELECT 1 FROM {table} WHERE operation_id = ? LIMIT 1 FOR UPDATE");
        let existing: Option<i32> = sqlx::query_scalar(&sql)
            .bind(operation_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|error| {
                let classified =
                    map_verification_sql_error(error, "config grant-side-effect guard");
                match classified {
                    ConfigVerificationError::Transient(message) => {
                        ConfigVerificationError::transient(format!("{message} on {table}"))
                    }
                    ConfigVerificationError::Proof(message) => {
                        ConfigVerificationError::proof(format!("{message} on {table}"))
                    }
                }
            })?;
        if existing.is_some() {
            return Err(ConfigVerificationError::proof(format!(
                "config operation has a forbidden row in {table}"
            )));
        }
    }
    let projection_head: Option<i64> = sqlx::query_scalar(
        "SELECT head_id FROM authorization_projection_head WHERE last_event_id = ? LIMIT 1 FOR UPDATE",
    )
    .bind(event_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| map_verification_sql_error(error, "config projection-head guard"))?;
    let projection_outbox: Option<i64> = sqlx::query_scalar(
        "SELECT outbox_id FROM authorization_projection_outbox WHERE event_id = ? LIMIT 1 FOR UPDATE",
    )
    .bind(event_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| map_verification_sql_error(error, "config projection-outbox guard"))?;
    let invalidation: Option<String> = sqlx::query_scalar(
        "SELECT message_id FROM al_message_outbox WHERE operation_id = ? LIMIT 1 FOR UPDATE",
    )
    .bind(operation_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| map_verification_sql_error(error, "config invalidation guard"))?;
    if projection_head.is_some() || projection_outbox.is_some() || invalidation.is_some() {
        return Err(ConfigVerificationError::proof(
            "config operation has a forbidden projection or invalidation side effect",
        ));
    }
    Ok(())
}

async fn verify_current_source_image(
    tx: &mut sqlx::Transaction<'_, MySql>,
    image: &AuthorityConfigSourceImage,
) -> Result<(), ConfigVerificationError> {
    let lookup: AuthorityConfigSourceLookup =
        serde_json::from_str(&image.lookup).map_err(|error| {
            ConfigVerificationError::proof(format!("config source lookup is malformed: {error}"))
        })?;
    lookup.validate_for_table(image.table).map_err(|error| {
        ConfigVerificationError::proof(format!(
            "config source lookup does not match its table: {error}"
        ))
    })?;
    let current = crate::authority_config_source::read_typed_source_row_image_in_tx_typed(
        tx,
        image.table,
        &lookup,
    )
    .await
    .map_err(map_typed_source_read_error)?;
    let after_absent = serde_json::from_str::<serde_json::Value>(&image.after_image)
        .ok()
        .and_then(|value| {
            value
                .get("presence")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .as_deref()
        == Some("ABSENT");
    match (image.operation, current, after_absent) {
        (AuthorityConfigSourceOperation::Delete, None, true) => {
            let expected =
                crate::authority_config_source::typed_source_absent_image(image.table, &lookup)
                    .map_err(|error| {
                        ConfigVerificationError::proof(format!(
                            "config DELETE absence marker failed: {error}"
                        ))
                    })?;
            if expected != image.after_image {
                return Err(ConfigVerificationError::proof(
                    "config DELETE after image is not its canonical typed absence",
                ));
            }
        }
        (_, Some((key, bytes)), false) if key == image.key && bytes == image.after_image => {}
        (AuthorityConfigSourceOperation::Delete, Some(_), true) => {
            return Err(ConfigVerificationError::proof(
                "config DELETE source row still exists",
            ))
        }
        (_, None, true) => {
            return Err(ConfigVerificationError::proof(
                "non-DELETE config operation has an absent after row",
            ))
        }
        _ => {
            return Err(ConfigVerificationError::proof(
                "current config source row differs from its retained after image",
            ))
        }
    }
    Ok(())
}

fn operation_as_text(operation: AuthorityConfigSourceOperation) -> &'static str {
    match operation {
        AuthorityConfigSourceOperation::Insert => "INSERT",
        AuthorityConfigSourceOperation::Upsert => "UPSERT",
        AuthorityConfigSourceOperation::Update => "UPDATE",
        AuthorityConfigSourceOperation::Delete => "DELETE",
    }
}

pub async fn reconcile_config_completions(
    pool: Pool<MySql>,
    gateway: Arc<dyn ConfigCompletionGateway>,
    config: &ConfigCompletionReconcilerConfig,
) -> Result<ConfigCompletionReconcileReport, PolicyError> {
    AuthorityConfigCompletionReconciler::new(pool, gateway, config.clone())?
        .run_once()
        .await
}

#[cfg(test)]
mod tests {
    #[test]
    fn forbidden_side_effect_guards_use_existence_only_queries() {
        let source = include_str!("authority_config_completion.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(
            production.contains("SELECT 1 FROM {table} WHERE operation_id = ? LIMIT 1 FOR UPDATE")
        );
        assert!(production.contains("let existing: Option<i32>"));
    }
}
