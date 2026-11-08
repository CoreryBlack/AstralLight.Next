//! Durable one-use boundary shared by authorization source owners.

use astral_types::{AuthorizationAdmission, AuthorizationFenceProof, PolicyError};
use sha2::{Digest, Sha256};
use sqlx::{MySql, Transaction};
use time::OffsetDateTime;

const ADMISSION_USE_DOMAIN: &[u8] = b"ASTRAL_AUTHORIZATION_ADMISSION_USE_V7\0";

/// Consume the exact proof in the source transaction after locking and validating
/// its current durable authority rows. Rollback also rolls back this reservation;
/// an unknown COMMIT must be reconciled by proof/operation identity, never replayed.
pub async fn consume_authorization_admission_in_tx(
    tx: &mut Transaction<'_, MySql>,
    admission: &AuthorizationAdmission,
) -> Result<(), PolicyError> {
    crate::validate_authorization_admission_in_tx(tx, admission).await?;
    let proof = admission.proof();
    let digest = admission_proof_digest(proof)?;
    sqlx::query(
        "INSERT INTO authorization_admission_use \
         (proof_id, request_nonce, operation_id, event_id, authority_id, authority_term, \
          global_fence_sequence, key_epoch, proof_digest, consumed_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&proof.proof_id)
    .bind(&proof.request_nonce)
    .bind(&proof.operation_id)
    .bind(&proof.event_id)
    .bind(&proof.authority_id)
    .bind(storage_counter(proof.authority_term)?)
    .bind(storage_counter(proof.global_fence_sequence)?)
    .bind(storage_counter(proof.key_epoch)?)
    .bind(digest.as_slice())
    .bind(OffsetDateTime::now_utc().unix_timestamp())
    .execute(&mut **tx)
    .await
    .map_err(|error| match &error {
        sqlx::Error::Database(database) if database.is_unique_violation() => {
            PolicyError::Repository(
                "authorization admission has a durable consumption; reconcile its operation before retry"
                    .to_owned(),
            )
        }
        _ => PolicyError::Repository(format!(
            "authorization admission durable consumption failed: {error}"
        )),
    })?;
    Ok(())
}

fn storage_counter(value: u64) -> Result<i64, PolicyError> {
    i64::try_from(value).map_err(|_| {
        PolicyError::InvalidContext("authority counter exceeds durable storage range".to_owned())
    })
}

fn admission_proof_digest(proof: &AuthorizationFenceProof) -> Result<[u8; 32], PolicyError> {
    proof
        .validate()
        .map_err(|error| PolicyError::InvalidContext(error.to_string()))?;
    let bytes = proof
        .signing_bytes()
        .map_err(|error| PolicyError::InvalidContext(error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(ADMISSION_USE_DOMAIN);
    digest.update(bytes);
    digest.update(proof.signature.as_bytes());
    Ok(digest.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::{
        AuthorizationAuthorityScope, AuthorizationDomainScope, AUTHORIZATION_EDITION,
    };

    fn proof() -> AuthorizationFenceProof {
        AuthorizationFenceProof {
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "authority-test".into(),
            authority_term: 1,
            global_fence_sequence: 2,
            scope: AuthorizationAuthorityScope {
                tenant_id: 3,
                card_id: 4,
                user_id: Some(5),
                domain: AuthorizationDomainScope::Exact(6),
            },
            scope_generation: 1,
            revoke_watermark: 0,
            snapshot_hash: "11".repeat(32),
            parent_hash: None,
            operation_id: "operation-test".into(),
            event_id: "event-test".into(),
            key_id: "key-test".into(),
            key_epoch: 1,
            issued_at: 100,
            not_before: 100,
            expires_at: 160,
            request_nonce: "nonce-test".into(),
            request_binding_digest: None,
            scope_certificate_hash: None,
            proof_id: "proof-test".into(),
            signature: "22".repeat(64),
        }
    }

    #[test]
    fn reconstructed_handles_have_the_same_durable_identity() {
        let proof = proof();
        let first = AuthorizationAdmission::from_verified_proof(proof.clone()).unwrap();
        let reconstructed = AuthorizationAdmission::from_verified_proof(proof).unwrap();
        first.consume_once().unwrap();
        reconstructed.consume_once().unwrap();
        assert_eq!(
            admission_proof_digest(first.proof()).unwrap(),
            admission_proof_digest(reconstructed.proof()).unwrap()
        );
    }

    #[test]
    fn durable_identity_binds_nonce_operation_scope_and_signature() {
        let original = proof();
        let baseline = admission_proof_digest(&original).unwrap();
        let mut alternatives = vec![original.clone(); 5];
        alternatives[0].request_nonce = "nonce-other".into();
        alternatives[1].operation_id = "operation-other".into();
        alternatives[2].scope.tenant_id += 1;
        alternatives[3].signature = "33".repeat(64);
        alternatives[4].snapshot_hash = "44".repeat(32);
        for alternative in alternatives {
            assert_ne!(baseline, admission_proof_digest(&alternative).unwrap());
        }
    }
}
