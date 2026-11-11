//! Immutable source coverage recorded with the exact source commit binding.
//!
//! A late declaration never narrows a GLOBAL barrier. Only an explicitly
//! registered source capability may make that barrier terminal after every
//! declared publication has been certified.

use std::collections::BTreeSet;

use astral_types::{
    AuthorityCommitBinding, AuthorityCommitRequest, AuthorityMutationKind, AuthorityProtocolError,
    AuthorityReservationCoverage, AuthorityScopePublicationCertificate, AuthorityScopeReservation,
    AuthorityStagedScopeCoverage,
};

use super::{decode, AuthorityService, AuthorityServiceError};
use crate::error::AuthorityStoreError;

#[derive(serde::Serialize, serde::Deserialize)]
pub(super) struct StoredCommitCoverage {
    binding: AuthorityCommitBinding,
    coverage: Option<AuthorityStagedScopeCoverage>,
    automatic_closure_authorized: bool,
}

impl AuthorityService {
    pub(super) fn source_commit_coverage(
        &self,
        request: &AuthorityCommitRequest,
        reservation: &AuthorityScopeReservation,
        binding: &AuthorityCommitBinding,
    ) -> Result<StoredCommitCoverage, AuthorityServiceError> {
        let source = self
            .config
            .trusted_source_by_id(&request.caller.service_id)
            .ok_or_else(|| AuthorityServiceError::NotAuthorized {
                caller: request.caller.service_id.clone(),
                operation: "commit",
            })?;
        if !source.allowed_database_ids.contains(&request.database_id) {
            return Err(AuthorityServiceError::NotAuthorized {
                caller: request.database_id.clone(),
                operation: "commit",
            });
        }
        if reservation.intent.mutation_kind == AuthorityMutationKind::ProtectedBusiness
            && request.declared_coverage.is_some()
        {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::InvalidCoverage,
            ));
        }
        let automatic_closure_authorized = self.config.policy.exact_scope_coverage_enabled
            && source
                .allowed_operations
                .iter()
                .any(|operation| operation == "commit_finite_coverage");
        Ok(StoredCommitCoverage {
            binding: binding.clone(),
            coverage: request.declared_coverage.clone(),
            automatic_closure_authorized,
        })
    }

    pub(super) async fn load_commit_coverage(
        &self,
        reservation: &AuthorityScopeReservation,
        binding: &AuthorityCommitBinding,
    ) -> Result<StoredCommitCoverage, AuthorityServiceError> {
        let record = self
            .store
            .get(&self.keys.commit_coverage(&reservation.reservation_id))
            .await?
            .ok_or_else(|| {
                AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                    "source commit coverage is missing".to_owned(),
                ))
            })?;
        let coverage: StoredCommitCoverage = decode(&record.value, "source commit coverage")?;
        if coverage.binding != *binding {
            return Err(AuthorityServiceError::Protocol(
                AuthorityProtocolError::ScopeMismatch,
            ));
        }
        if let Some(declared) = &coverage.coverage {
            declared
                .validate()
                .map_err(AuthorityServiceError::Protocol)?;
        }
        if let AuthorityReservationCoverage::Exact(scopes) = &reservation.intent.coverage {
            let expected = AuthorityStagedScopeCoverage {
                scopes: scopes.clone(),
            };
            if coverage
                .coverage
                .as_ref()
                .map(AuthorityStagedScopeCoverage::coverage_digest)
                .transpose()
                .map_err(AuthorityServiceError::Protocol)?
                != Some(
                    expected
                        .coverage_digest()
                        .map_err(AuthorityServiceError::Protocol)?,
                )
            {
                return Err(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::InvalidCoverage,
                ));
            }
        }
        Ok(coverage)
    }

    /// Verify the COMPLETE set of immutable scope certificates a close
    /// decision may rely on: every declared scope must resolve to an indexed
    /// certificate record that is re-proven end to end — registered signer
    /// entry, signature, certificate identity, and the full binding
    /// (scope key, reservation, intent digest, operation/event, approved
    /// request digest, source commit/before/after/outcome digests, and the
    /// IMMUTABLE prepare frontier). The scope current pointer is never a
    /// substitute for the indexed history, and the reservation's
    /// `certified_scopes` list is never trusted alone.
    ///
    /// `pending` is the not-yet-CAS-committed certificate of the in-flight
    /// certify: it is verified exactly like an indexed record so the close
    /// decision can count it before the same transaction lands. A present
    /// but drifted record is a loud error; a missing index entry simply
    /// leaves that scope unverified (the close is then refused).
    ///
    /// Returns the set of declared scope keys whose evidence is fully
    /// verified. The index is append-only under PutIfAbsent, so the verified
    /// set is monotone between this read and the caller's CAS: no revision
    /// pinning is required here, but a caller that CAS-writes against the
    /// index itself must supply its own StoreOps.
    pub(super) async fn verify_certified_scope_records(
        &self,
        reservation: &AuthorityScopeReservation,
        binding: &AuthorityCommitBinding,
        declared: &AuthorityStagedScopeCoverage,
        pending: Option<&AuthorityScopePublicationCertificate>,
    ) -> Result<BTreeSet<String>, AuthorityServiceError> {
        let state = self.load_verified_state().await?;
        let mut verified = BTreeSet::new();
        for scope in &declared.scopes {
            let scope_key = scope
                .store_key_text()
                .map_err(AuthorityServiceError::Protocol)?;
            let certificate = match self
                .store
                .get(
                    &self
                        .keys
                        .reservation_certificate(&reservation.reservation_id, &scope_key),
                )
                .await?
            {
                Some(record) => {
                    let certificate_id: String =
                        decode(&record.value, "scope certification index")?;
                    let stored = self
                        .store
                        .get(&self.keys.certificate(&certificate_id))
                        .await?
                        .ok_or_else(|| {
                            AuthorityServiceError::Store(AuthorityStoreError::Corrupt(
                                "scope certificate is missing".to_owned(),
                            ))
                        })?;
                    let certificate: AuthorityScopePublicationCertificate =
                        decode(&stored.value, "scope certificate")?;
                    super::certificate_records::verify_certificate_record(
                        &state,
                        &certificate_id,
                        &certificate,
                    )?;
                    certificate
                }
                None => match pending {
                    Some(pending) if pending.scope == *scope => {
                        super::certificate_records::verify_certificate_record(
                            &state,
                            &pending.certificate_id,
                            pending,
                        )?;
                        pending.clone()
                    }
                    _ => continue,
                },
            };
            // Exact binding: the certificate must bind THIS reservation's
            // stable identity, the coverage record's commit binding, and the
            // immutable prepare frontier — never a look-alike.
            if certificate
                .scope
                .store_key_text()
                .map_err(AuthorityServiceError::Protocol)?
                != scope_key
                || certificate.reservation_id != binding.reservation_id
                || certificate.intent_digest != reservation.intent_digest
                || certificate.operation_id != binding.operation_id
                || certificate.event_id != binding.event_id
                || certificate.approved_request_digest != binding.request_digest
                || certificate.source_commit_digest != binding.source_commit_digest
                || certificate.before_image_digest != binding.before_image_digest
                || certificate.after_image_digest != binding.after_image_digest
                || certificate.source_outcome_digest != binding.source_outcome_digest
                || certificate.authority_term != reservation.authority_term
                || certificate.global_fence_sequence != reservation.fence_sequence_at_prepare
            {
                return Err(AuthorityServiceError::Protocol(
                    AuthorityProtocolError::ScopeMismatch,
                ));
            }
            verified.insert(scope_key);
        }
        Ok(verified)
    }

    /// Whether every declared scope publication is proven and the automatic
    /// close may advance the reservation to CERTIFIED. Completeness is
    /// proven against the VERIFIED durable certificate set — never against
    /// the reservation's `certified_scopes` list alone — and the capability
    /// is re-checked at close time: removing it must never silently retain
    /// an old right to open the global gate. An unknown or unverified scope
    /// never passes.
    pub(super) async fn coverage_allows_automatic_close(
        &self,
        coverage: &StoredCommitCoverage,
        reservation: &AuthorityScopeReservation,
        pending: Option<&AuthorityScopePublicationCertificate>,
    ) -> Result<bool, AuthorityServiceError> {
        let Some(declared) = &coverage.coverage else {
            return Ok(false);
        };
        let verified = self
            .verify_certified_scope_records(reservation, &coverage.binding, declared, pending)
            .await?;
        let complete = declared.scopes.iter().all(|scope| {
            scope
                .store_key_text()
                .is_ok_and(|key| verified.contains(&key))
        });
        if !complete {
            return Ok(false);
        }
        if matches!(
            reservation.intent.coverage,
            AuthorityReservationCoverage::Exact(_)
        ) {
            return Ok(true);
        }
        // Recheck current policy as well: removing the capability must never
        // silently retain an old right to open the global gate.
        let currently_authorized = self.config.policy.exact_scope_coverage_enabled
            && self
                .config
                .trusted_source_by_id(&reservation.intent.service_id)
                .is_some_and(|source| {
                    source
                        .allowed_database_ids
                        .contains(&reservation.intent.database_id)
                        && source
                            .allowed_operations
                            .iter()
                            .any(|operation| operation == "commit_finite_coverage")
                });
        Ok(coverage.automatic_closure_authorized && currently_authorized)
    }
}

impl StoredCommitCoverage {
    pub(super) fn binding(&self) -> &AuthorityCommitBinding {
        &self.binding
    }

    /// The declared finite coverage the source recorded with this commit, if
    /// any. Read-only accessor for terminal-completeness checks on close and
    /// reconcile: `None` means the classic conservative GLOBAL commit without
    /// a declared set.
    pub(super) fn declared_coverage(&self) -> Option<&AuthorityStagedScopeCoverage> {
        self.coverage.as_ref()
    }

    pub(super) fn permits_scope(
        &self,
        scope: &astral_types::AuthorityProtocolScope,
    ) -> Result<bool, AuthorityServiceError> {
        self.coverage
            .as_ref()
            .map(|coverage| coverage.covers(scope))
            .transpose()
            .map_err(AuthorityServiceError::Protocol)
            .map(|covered| covered.unwrap_or(true))
    }
}
