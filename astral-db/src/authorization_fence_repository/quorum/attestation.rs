//! Runtime attestation of a bounded card-scope serving partition.

use super::{decoded, pending, persist_response, scope_hash, verify_response, QuorumProvider};
use crate::memory_projection_hub::MemoryProjectionHub;
use astral_types::{
    AuthorityProtocolScope, AuthorityReadProofRequest, CertifiedAuthorizationState, PolicyError,
    PublishedCardEvidenceScope,
};
use sha2::{Digest, Sha256};
use sqlx::MySqlPool;
use std::sync::Arc;
use time::OffsetDateTime;

const MAX_STARTUP_SCOPES: usize = 256;
const ATTESTATION_CONCURRENCY: usize = 8;
const MAX_SCOPE_HINT_BYTES: usize = 2048;

impl QuorumProvider {
    pub(in crate::authorization_fence_repository) async fn observe_serving_partition(
        &self,
        hub: &MemoryProjectionHub,
    ) -> Result<(), PolicyError> {
        let response = self
            .client
            .read_fence(None, None, None)
            .await
            .map_err(pending)?;
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if response.observed_at > now || now.saturating_sub(response.observed_at) > 5 {
            return Err(pending(
                "authority observation is outside the supervisor freshness window",
            ));
        }
        hub.verify_serving_authority_observation(&response)
            .map_err(pending)
    }

    pub(in crate::authorization_fence_repository) async fn attest_partition(
        self: &Arc<Self>,
        pool: &MySqlPool,
        hub: &MemoryProjectionHub,
    ) -> Result<usize, PolicyError> {
        let token = hub.capture_certified_partition_token().map_err(pending)?;
        let hints = scope_hints(pool).await?;
        let run_id = uuid::Uuid::now_v7().to_string();
        let mut scopes = hints.clone().into_iter();
        let mut tasks = tokio::task::JoinSet::new();
        let mut certified = Vec::with_capacity(hints.len());
        loop {
            while tasks.len() < ATTESTATION_CONCURRENCY {
                let Some(scope) = scopes.next() else { break };
                let provider = self.clone();
                let pool = pool.clone();
                let run_id = run_id.clone();
                tasks.spawn(async move { provider.attest_scope(&pool, scope, &run_id).await });
            }
            match tasks.join_next().await {
                Some(Ok(Ok(entry))) => certified.push(entry),
                Some(Ok(Err(error))) => return Err(error),
                Some(Err(_)) => return Err(pending("scope attestation task interrupted")),
                None => break,
            }
        }
        if hints != scope_hints(pool).await? {
            return Err(pending("local scope inventory changed during attestation"));
        }
        let installed = hub
            .install_certified_partition(token, certified)
            .map_err(pending)?;
        self.certified_read_state.mark_warmed();
        Ok(installed)
    }

    async fn attest_scope(
        &self,
        pool: &MySqlPool,
        scope: AuthorityProtocolScope,
        run_id: &str,
    ) -> Result<(PublishedCardEvidenceScope, CertifiedAuthorizationState), PolicyError> {
        let AuthorityProtocolScope::Card(card) = &scope else {
            return Err(pending(
                "startup card partition received an organization scope",
            ));
        };
        let evidence_scope = super::super::evidence_scope_from_authority_scope(card)?;
        let binding = startup_binding(&scope, &self.service_id, &self.database_id, run_id)?;
        let nonce = uuid::Uuid::now_v7().to_string();
        let operation_id = format!("attest:{run_id}");
        let response = self
            .client
            .read_fence(
                Some(scope.clone()),
                None,
                Some(AuthorityReadProofRequest {
                    actor_scope: scope.clone(),
                    source_scope: None,
                    request_nonce: nonce.clone(),
                    operation_id: operation_id.clone(),
                    event_id: format!("{operation_id}:read"),
                    mutation_kind: astral_types::AuthorityMutationKind::AuthorizationSource,
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
            &scope,
            &scope,
            &nonce,
            &binding,
            now,
        )?;
        let proof = response
            .proof
            .as_ref()
            .ok_or_else(|| pending("startup proof missing"))?;
        if proof.operation_id != operation_id || proof.event_id != format!("{operation_id}:read") {
            return Err(pending("startup proof request identity changed"));
        }
        let certificate = response
            .scope_certificate
            .as_ref()
            .ok_or_else(|| pending("startup certificate missing"))?;
        let evidence =
            crate::authorization_projection_repository::load_published_card_grant_evidence(
                pool,
                &evidence_scope,
            )
            .await
            .map_err(pending)?;
        let roots = &attestation.trust_root;
        let proof_key = roots
            .signer_key()
            .map_err(pending)?
            .verifying_key()
            .map_err(pending)?;
        let certificate_key = roots
            .key_by_id(&certificate.key_id)
            .ok_or_else(|| pending("startup certificate signer missing"))?
            .verifying_key()
            .map_err(pending)?;
        let certified = CertifiedAuthorizationState::new_with_certificate(
            proof.clone(),
            Arc::new(evidence),
            certificate.clone(),
            &proof_key,
            &certificate_key,
            now,
            &evidence_scope,
        )
        .map_err(pending)?;
        if matches!(self.read_mode, super::AuthorityReadMode::Durable) {
            persist_response(
                &self.warmup_response_persistence(pool),
                &response,
                &scope,
                &binding,
            )
            .await?;
        }
        *self
            .roots
            .write()
            .map_err(|_| pending("public trust registry unavailable"))? = attestation.trust_root;
        Ok((evidence_scope, certified))
    }
}

async fn scope_hints(pool: &MySqlPool) -> Result<Vec<AuthorityProtocolScope>, PolicyError> {
    // Read only bounded scope hints. The cached certificate is never promoted
    // into authority: every scope is fetched and verified independently above.
    let rows: Vec<(Vec<u8>, Option<String>)> = sqlx::query_as(
        "SELECT scope_hash, CASE WHEN OCTET_LENGTH(CAST(JSON_EXTRACT(certificate_json, '$.scope') AS CHAR)) <= ? \
         THEN CAST(JSON_EXTRACT(certificate_json, '$.scope') AS CHAR) ELSE NULL END \
         FROM authorization_scope_certificate ORDER BY scope_hash LIMIT ?",
    ).bind(MAX_SCOPE_HINT_BYTES as u32).bind((MAX_STARTUP_SCOPES + 1) as u32)
        .fetch_all(pool).await.map_err(pending)?;
    if rows.len() > MAX_STARTUP_SCOPES {
        return Err(pending(
            "startup scope inventory exceeds bounded partition capacity",
        ));
    }
    let mut scopes = Vec::with_capacity(rows.len());
    for (stored_hash, text) in rows {
        let scope: AuthorityProtocolScope =
            decoded(&text.ok_or_else(|| pending("scope hint missing or oversized"))?)?;
        scope.validate().map_err(pending)?;
        if scope_hash(&scope)? != stored_hash {
            return Err(pending("scope hint identity differs from its durable key"));
        }
        if matches!(scope, AuthorityProtocolScope::Card(_)) {
            scopes.push(scope);
        }
    }
    if scopes.is_empty() {
        return Err(pending(
            "startup has no card scope hints; approved bootstrap is required",
        ));
    }
    Ok(scopes)
}

fn startup_binding(
    scope: &AuthorityProtocolScope,
    service: &str,
    database: &str,
    run: &str,
) -> Result<String, PolicyError> {
    let mut digest = Sha256::new();
    digest.update(b"ASTRAL_STARTUP_ATTESTATION_V7\0");
    for field in [
        service,
        database,
        run,
        &scope.store_key_text().map_err(pending)?,
    ] {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    Ok(hex::encode(digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_binding_separates_scope_owner_and_run() {
        let scope = AuthorityProtocolScope::Card(astral_types::AuthorizationAuthorityScope {
            tenant_id: 1,
            card_id: 2,
            user_id: Some(3),
            domain: astral_types::AuthorizationDomainScope::NoDomain,
        });
        let expected = startup_binding(&scope, "service", "database", "run").unwrap();
        assert_ne!(
            expected,
            startup_binding(&scope, "other", "database", "run").unwrap()
        );
        assert_ne!(
            expected,
            startup_binding(&scope, "service", "other", "run").unwrap()
        );
        assert_ne!(
            expected,
            startup_binding(&scope, "service", "database", "other").unwrap()
        );
        let mut other_scope = scope.clone();
        if let AuthorityProtocolScope::Card(card) = &mut other_scope {
            card.card_id = 4;
        }
        assert_ne!(
            expected,
            startup_binding(&other_scope, "service", "database", "run").unwrap()
        );
    }
}
