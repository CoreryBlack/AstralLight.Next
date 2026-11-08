//! Durable scope-certificate history, separated from the current pointer.
//!
//! Every authority-signed certificate this database observes is recorded
//! immutably in `authorization_scope_certificate_history` (insert-only). The
//! current-pointer row in `authorization_scope_certificate` advances ONLY onto
//! a certificate whose exact parent is the current record with non-decreasing
//! authority counters; historical (behind or out-of-chain) certificates never
//! roll the pointer back. Re-observing an already-certified scope after the
//! pointer moved on (lost certify response, lease handover) therefore succeeds
//! durably without weakening the pointer chain and without deriving ancestry
//! from term/fence order alone.

use astral_types::{AuthorityScopePublicationCertificate, PolicyError};
use sqlx::MySqlPool;

use super::super::pending;

/// Outcome of persisting one verified certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PersistOutcome {
    /// The certificate is already fully durable locally: it is the current
    /// pointer (or already recorded) and no NEW evidence row was written.
    Known,
    /// A NEW verified certificate was recorded into history; the pointer did
    /// not move. Counts as durable progress for the attempt-budget checkpoint.
    Recorded,
    /// The pointer advanced onto this certificate (first observation or the
    /// exact-parent child). Counts as durable progress.
    Advanced,
}

impl PersistOutcome {
    /// Whether this outcome produced a NEW durable record. Budget checkpoints
    /// fire only on progress, so a row without progress can never reset its
    /// own certification attempt budget.
    pub(super) fn is_progress(self) -> bool {
        !matches!(self, PersistOutcome::Known)
    }
}

/// Pure current-pointer decision for one verified incoming certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PointerDecision {
    /// The pointer already is this exact certificate.
    Known,
    /// The pointer advances onto this certificate: first observation for the
    /// scope, or the exact-parent child with non-decreasing counters.
    Advance,
    /// Verified historical certificate that must NOT move the pointer:
    /// behind the pointer, out-of-chain, or counter-regressing.
    RecordOnly,
}

fn pointer_decision(
    previous: Option<&AuthorityScopePublicationCertificate>,
    incoming: &AuthorityScopePublicationCertificate,
) -> Result<PointerDecision, PolicyError> {
    let Some(previous) = previous else {
        // First observation for this scope key seeds the pointer.
        return Ok(PointerDecision::Advance);
    };
    if previous.scope != incoming.scope {
        return Err(pending("certificate scope diverges from the pointer scope"));
    }
    if previous.record_digest().map_err(pending)? == incoming.record_digest().map_err(pending)? {
        return Ok(PointerDecision::Known);
    }
    let exact_parent = incoming.parent_certificate_hash.as_deref()
        == Some(previous.record_digest().map_err(pending)?.as_str());
    let counters_advance = incoming.authority_term >= previous.authority_term
        && incoming.global_fence_sequence >= previous.global_fence_sequence;
    if exact_parent && counters_advance {
        Ok(PointerDecision::Advance)
    } else {
        Ok(PointerDecision::RecordOnly)
    }
}

fn scope_key_hash(
    certificate: &AuthorityScopePublicationCertificate,
) -> Result<Vec<u8>, PolicyError> {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"ASTRAL_AUTHORITY_SCOPE_KEY_V7\0");
    hash.update(
        certificate
            .scope
            .store_key_text()
            .map_err(pending)?
            .as_bytes(),
    );
    Ok(hash.finalize().to_vec())
}

/// Persist one client-verified authority certificate: always into the
/// immutable history, and onto the current pointer only per
/// [`pointer_decision`]. The caller (AuthorityClient) verified the signature
/// and trust root before this boundary; this function re-validates the
/// record structure before any write.
pub(super) async fn persist_certificate(
    pool: &MySqlPool,
    certificate: &AuthorityScopePublicationCertificate,
) -> Result<PersistOutcome, PolicyError> {
    certificate.validate().map_err(pending)?;
    let scope_hash = scope_key_hash(certificate)?;
    let certificate_hash =
        hex::decode(certificate.record_digest().map_err(pending)?).map_err(pending)?;
    let mut tx = pool.begin().await.map_err(pending)?;
    // The pointer row itself must be internally consistent before it may act
    // as the chain parent: stored hash column vs the record digest of its
    // stored JSON. A poisoned pointer row is never durable proof; the caller
    // leaves the outcome row PENDING instead.
    let pointer: Option<(Vec<u8>, String)> = sqlx::query_as(
        "SELECT certificate_hash, CAST(certificate_json AS CHAR) \
             FROM authorization_scope_certificate WHERE scope_hash = ? FOR UPDATE",
    )
    .bind(&scope_hash)
    .fetch_optional(&mut *tx)
    .await
    .map_err(pending)?;
    let previous = pointer
        .map(|(stored_hash, stored_json)| -> Result<AuthorityScopePublicationCertificate, PolicyError> {
            let decoded: AuthorityScopePublicationCertificate =
                serde_json::from_str(&stored_json).map_err(pending)?;
            if stored_hash
                != hex::decode(decoded.record_digest().map_err(pending)?).map_err(pending)?
            {
                return Err(pending(
                    "current pointer row hash diverges from its certificate JSON",
                ));
            }
            Ok(decoded)
        })
        .transpose()?;
    match pointer_decision(previous.as_ref(), certificate)? {
        PointerDecision::Known => {
            // The pointer already is this certificate; backfill its history
            // row only if absent. Never budget progress: no NEW evidence.
            record_history(&mut tx, certificate, &scope_hash, &certificate_hash).await?;
            tx.commit().await.map_err(|_| {
                pending("local certificate history COMMIT unknown; read back before retry")
            })?;
            Ok(PersistOutcome::Known)
        }
        PointerDecision::RecordOnly => {
            let inserted =
                record_history(&mut tx, certificate, &scope_hash, &certificate_hash).await?;
            tx.commit().await.map_err(|_| {
                pending("local certificate history COMMIT unknown; read back before retry")
            })?;
            if inserted {
                tracing::warn!(
                    reservation_id = %certificate.reservation_id,
                    operation_id = %certificate.operation_id,
                    authority_term = certificate.authority_term,
                    global_fence_sequence = certificate.global_fence_sequence,
                    "recorded an out-of-chain authority certificate into local history; \
                     the current pointer stays unchanged"
                );
                Ok(PersistOutcome::Recorded)
            } else {
                Ok(PersistOutcome::Known)
            }
        }
        PointerDecision::Advance => {
            record_history(&mut tx, certificate, &scope_hash, &certificate_hash).await?;
            match previous.as_ref() {
                None => {
                    sqlx::query(
                        "INSERT INTO authorization_scope_certificate \
                         (scope_hash,certificate_hash,certificate_json,observed_at) \
                         VALUES (?,?,?,UNIX_TIMESTAMP())",
                    )
                    .bind(&scope_hash)
                    .bind(&certificate_hash)
                    .bind(serde_json::to_string(certificate).map_err(pending)?)
                    .execute(&mut *tx)
                    .await
                    .map_err(pending)?;
                }
                Some(_) => {
                    sqlx::query(
                        "UPDATE authorization_scope_certificate \
                         SET certificate_hash=?,certificate_json=?,observed_at=UNIX_TIMESTAMP() \
                         WHERE scope_hash=?",
                    )
                    .bind(&certificate_hash)
                    .bind(serde_json::to_string(certificate).map_err(pending)?)
                    .bind(&scope_hash)
                    .execute(&mut *tx)
                    .await
                    .map_err(pending)?;
                }
            }
            // Read the pointer write back and prove the stored bytes before the
            // COMMIT: the pointer advance is durable proof only as written.
            let (written_hash, written_json): (Vec<u8>, String) = sqlx::query_as(
                "SELECT certificate_hash, CAST(certificate_json AS CHAR) \
                     FROM authorization_scope_certificate WHERE scope_hash = ? FOR UPDATE",
            )
            .bind(&scope_hash)
            .fetch_one(&mut *tx)
            .await
            .map_err(pending)?;
            if written_hash != certificate_hash
                || serde_json::from_str::<AuthorityScopePublicationCertificate>(&written_json)
                    .map_err(pending)?
                    != *certificate
            {
                return Err(pending(
                    "current pointer write diverged from the verified certificate",
                ));
            }
            tx.commit()
                .await
                .map_err(|_| pending("local certificate COMMIT unknown; read back before retry"))?;
            Ok(PersistOutcome::Advanced)
        }
    }
}

/// Locked read-back shape of one durable history row.
#[derive(Debug, Clone, sqlx::FromRow)]
struct HistoryReadback {
    scope_hash: Vec<u8>,
    reservation_id: String,
    operation_id: String,
    certificate_id: String,
    authority_id: String,
    authority_term: i64,
    global_fence_sequence: i64,
    parent_certificate_hash: Option<Vec<u8>>,
    certificate_json: String,
}

/// Pure consistency proof of a durable history row against the certificate it
/// claims to hold: exact scope key, full scope/reservation/operation identity,
/// counters, parent hash, and a byte-faithful JSON round trip whose record
/// digest matches the certificate. A mismatched or poisoned row is NEVER
/// durable proof: the caller fails PENDING instead of completing.
fn verify_history_artifact(
    expected_scope_hash: &[u8],
    stored: &HistoryReadback,
    certificate: &AuthorityScopePublicationCertificate,
) -> Result<(), PolicyError> {
    if stored.scope_hash != expected_scope_hash {
        return Err(pending(
            "history row scope key diverges from the certificate",
        ));
    }
    if stored.reservation_id != certificate.reservation_id
        || stored.operation_id != certificate.operation_id
        || stored.certificate_id != certificate.certificate_id
        || stored.authority_id != certificate.authority_id
    {
        return Err(pending(
            "history row identity diverges from the certificate",
        ));
    }
    let expected_term = i64::try_from(certificate.authority_term)
        .map_err(|_| pending("authority term exceeds local storage range"))?;
    let expected_fence = i64::try_from(certificate.global_fence_sequence)
        .map_err(|_| pending("global fence sequence exceeds local storage range"))?;
    if stored.authority_term != expected_term || stored.global_fence_sequence != expected_fence {
        return Err(pending("history row counters diverge from the certificate"));
    }
    let expected_parent = certificate
        .parent_certificate_hash
        .as_ref()
        .map(|hash| hex::decode(hash).map_err(pending))
        .transpose()?;
    if stored.parent_certificate_hash != expected_parent {
        return Err(pending(
            "history row parent hash diverges from the certificate",
        ));
    }
    let decoded: AuthorityScopePublicationCertificate =
        serde_json::from_str(&stored.certificate_json).map_err(pending)?;
    if decoded != *certificate
        || decoded.record_digest().map_err(pending)?
            != certificate.record_digest().map_err(pending)?
    {
        return Err(pending(
            "history row certificate JSON diverges from the certificate",
        ));
    }
    Ok(())
}

/// Insert-only history write. Content equality is proven by a locked read-back
/// through [`verify_history_artifact`] — never inferred from `rows_affected`;
/// the affected count only classifies a NEW insertion for budget-progress
/// accounting. Any inconsistency fails PENDING and preserves immutability
/// (rows are never updated in place).
async fn record_history(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    certificate: &AuthorityScopePublicationCertificate,
    scope_hash: &[u8],
    certificate_hash: &[u8],
) -> Result<bool, PolicyError> {
    let authority_term = i64::try_from(certificate.authority_term)
        .map_err(|_| pending("authority term exceeds local storage range"))?;
    let global_fence_sequence = i64::try_from(certificate.global_fence_sequence)
        .map_err(|_| pending("global fence sequence exceeds local storage range"))?;
    let parent_certificate_hash = match &certificate.parent_certificate_hash {
        Some(hash) => Some(hex::decode(hash).map_err(pending)?),
        None => None,
    };
    let inserted = sqlx::query(
        "INSERT INTO authorization_scope_certificate_history \
         (certificate_hash,scope_hash,reservation_id,operation_id,certificate_id,authority_id, \
          authority_term,global_fence_sequence,parent_certificate_hash,certificate_json,observed_at) \
         VALUES (?,?,?,?,?,?,?,?,?,?,UNIX_TIMESTAMP()) \
         ON DUPLICATE KEY UPDATE certificate_hash = certificate_hash",
    )
    .bind(certificate_hash)
    .bind(scope_hash)
    .bind(&certificate.reservation_id)
    .bind(&certificate.operation_id)
    .bind(&certificate.certificate_id)
    .bind(&certificate.authority_id)
    .bind(authority_term)
    .bind(global_fence_sequence)
    .bind(parent_certificate_hash)
    .bind(serde_json::to_string(certificate).map_err(pending)?)
    .execute(&mut **tx)
    .await
    .map_err(pending)?;
    let stored: HistoryReadback = sqlx::query_as(
        "SELECT scope_hash, reservation_id, operation_id, certificate_id, authority_id, \
         authority_term, global_fence_sequence, parent_certificate_hash, \
         CAST(certificate_json AS CHAR) AS certificate_json \
         FROM authorization_scope_certificate_history WHERE certificate_hash = ? FOR UPDATE",
    )
    .bind(certificate_hash)
    .fetch_one(&mut **tx)
    .await
    .map_err(pending)?;
    verify_history_artifact(scope_hash, &stored, certificate)?;
    Ok(inserted.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::{
        AuthorityManifestIdentity, AuthorityProtocolScope, AuthorizationAuthorityScope,
        AuthorizationDomainScope, AUTHORIZATION_EDITION,
    };
    use ed25519_dalek::SigningKey;

    const KEY_ID: &str = "signer-1";

    fn card_scope(card_id: i64) -> AuthorityProtocolScope {
        AuthorityProtocolScope::Card(AuthorizationAuthorityScope {
            tenant_id: 7,
            card_id,
            user_id: None,
            domain: AuthorizationDomainScope::Any,
        })
    }

    fn manifests() -> Vec<AuthorityManifestIdentity> {
        vec![AuthorityManifestIdentity {
            aggregate_type: "USER_CARD".to_owned(),
            aggregate_id: 17,
            manifest_digest_hex: "aa".repeat(32),
            dependency_hash_hex: "bb".repeat(32),
            semantic_hash_hex: "cc".repeat(32),
            generation: 4,
            revoke_fence: 2,
            event_id: "event-1".to_owned(),
            operation_id: "operation-1".to_owned(),
        }]
    }

    /// Build one signed certificate with explicit chain/counter inputs.
    fn signed(
        signing: &SigningKey,
        scope: &AuthorityProtocolScope,
        certificate_nonce: &str,
        parent: Option<String>,
        authority_term: u64,
        global_fence_sequence: u64,
    ) -> AuthorityScopePublicationCertificate {
        let mut certificate = AuthorityScopePublicationCertificate {
            protocol_version: astral_types::AUTHORITY_PROTOCOL_VERSION,
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "authority-1".to_owned(),
            authority_term,
            global_fence_sequence,
            certificate_id: format!("certificate-{certificate_nonce}"),
            intent_digest: "11".repeat(32),
            reservation_id: "reservation-1".to_owned(),
            operation_id: "operation-1".to_owned(),
            event_id: "event-1".to_owned(),
            scope: scope.clone(),
            approved_request_digest: "22".repeat(32),
            before_image_digest: Some("33".repeat(32)),
            after_image_digest: "44".repeat(32),
            source_commit_digest: "55".repeat(32),
            completion_digest: "00".repeat(32),
            snapshot_hash: "66".repeat(32),
            source_outcome_digest: "99".repeat(32),
            parent_certificate_hash: parent,
            manifests: manifests(),
            key_id: KEY_ID.to_owned(),
            key_epoch: 1,
            issued_at: 2_000,
            not_before: 2_000,
            expires_at: None,
            certificate_nonce: certificate_nonce.to_owned(),
            signature: String::new(),
        };
        certificate.completion_digest = certificate.recompute_completion_digest().unwrap();
        certificate.sign(signing).unwrap();
        certificate
    }

    #[test]
    fn first_observation_seeds_the_pointer() {
        let signing = SigningKey::from_bytes(&[8; 32]);
        let first = signed(&signing, &card_scope(17), "a", None, 1, 5);
        assert_eq!(
            pointer_decision(None, &first).unwrap(),
            PointerDecision::Advance
        );
    }

    #[test]
    fn identical_pointer_is_known() {
        let signing = SigningKey::from_bytes(&[8; 32]);
        let first = signed(&signing, &card_scope(17), "a", None, 1, 5);
        assert_eq!(
            pointer_decision(Some(&first), &first).unwrap(),
            PointerDecision::Known
        );
    }

    #[test]
    fn exact_parent_with_non_decreasing_counters_advances() {
        let signing = SigningKey::from_bytes(&[8; 32]);
        let first = signed(&signing, &card_scope(17), "a", None, 1, 5);
        let parent = first.record_digest().unwrap();
        let child = signed(&signing, &card_scope(17), "b", Some(parent.clone()), 1, 6);
        assert_eq!(
            pointer_decision(Some(&first), &child).unwrap(),
            PointerDecision::Advance
        );
        // Equal counters still advance: only regressions are refused.
        let sibling_child = signed(&signing, &card_scope(17), "b", Some(parent.clone()), 1, 5);
        assert_eq!(
            pointer_decision(Some(&first), &sibling_child).unwrap(),
            PointerDecision::Advance
        );
    }

    #[test]
    fn behind_ancestor_only_records_history() {
        let signing = SigningKey::from_bytes(&[8; 32]);
        let first = signed(&signing, &card_scope(17), "a", None, 1, 5);
        let parent = first.record_digest().unwrap();
        let child = signed(&signing, &card_scope(17), "b", Some(parent), 1, 6);
        // Re-observing the ancestor after the pointer advanced (lost certify
        // response, lease handover): durable history, pointer unchanged.
        assert_eq!(
            pointer_decision(Some(&child), &first).unwrap(),
            PointerDecision::RecordOnly
        );
    }

    #[test]
    fn exact_parent_with_counter_regression_never_rolls_back() {
        let signing = SigningKey::from_bytes(&[8; 32]);
        let first = signed(&signing, &card_scope(17), "a", None, 3, 9);
        let parent = first.record_digest().unwrap();
        let regressing = signed(&signing, &card_scope(17), "b", Some(parent), 2, 8);
        assert_eq!(
            pointer_decision(Some(&first), &regressing).unwrap(),
            PointerDecision::RecordOnly
        );
    }

    #[test]
    fn divergent_sibling_only_records_history() {
        let signing = SigningKey::from_bytes(&[8; 32]);
        let first = signed(&signing, &card_scope(17), "a", None, 1, 5);
        let parent = first.record_digest().unwrap();
        let child = signed(&signing, &card_scope(17), "b", Some(parent.clone()), 1, 6);
        let fork = signed(&signing, &card_scope(17), "b-fork", Some(parent), 1, 6);
        assert_eq!(
            pointer_decision(Some(&child), &fork).unwrap(),
            PointerDecision::RecordOnly
        );
    }

    #[test]
    fn pointer_scope_mismatch_is_refused() {
        let signing = SigningKey::from_bytes(&[8; 32]);
        let first = signed(&signing, &card_scope(17), "a", None, 1, 5);
        let other_scope = signed(&signing, &card_scope(18), "b", None, 1, 6);
        assert!(pointer_decision(Some(&first), &other_scope).is_err());
    }

    #[test]
    fn persisted_signatures_stay_verifiable_after_a_serde_round_trip() {
        let signing = SigningKey::from_bytes(&[8; 32]);
        let first = signed(&signing, &card_scope(17), "a", None, 1, 5);
        let json = serde_json::to_string(&first).unwrap();
        let decoded: AuthorityScopePublicationCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(
            decoded.record_digest().unwrap(),
            first.record_digest().unwrap()
        );
    }

    fn readback_for(
        certificate: &AuthorityScopePublicationCertificate,
        scope_hash: &[u8],
    ) -> HistoryReadback {
        HistoryReadback {
            scope_hash: scope_hash.to_vec(),
            reservation_id: certificate.reservation_id.clone(),
            operation_id: certificate.operation_id.clone(),
            certificate_id: certificate.certificate_id.clone(),
            authority_id: certificate.authority_id.clone(),
            authority_term: certificate.authority_term as i64,
            global_fence_sequence: certificate.global_fence_sequence as i64,
            parent_certificate_hash: certificate
                .parent_certificate_hash
                .as_ref()
                .map(|hash| hex::decode(hash).unwrap()),
            certificate_json: serde_json::to_string(certificate).unwrap(),
        }
    }

    #[test]
    fn consistent_history_readback_verifies() {
        let signing = SigningKey::from_bytes(&[8; 32]);
        let parent = signed(&signing, &card_scope(17), "a", None, 1, 5);
        let child = signed(
            &signing,
            &card_scope(17),
            "b",
            Some(parent.record_digest().unwrap()),
            1,
            6,
        );
        let scope_hash = scope_key_hash(&child).unwrap();
        verify_history_artifact(&scope_hash, &readback_for(&child, &scope_hash), &child).unwrap();
    }

    #[test]
    fn every_history_readback_mismatch_is_refused() {
        let signing = SigningKey::from_bytes(&[8; 32]);
        let parent = signed(&signing, &card_scope(17), "a", None, 1, 5);
        let child = signed(
            &signing,
            &card_scope(17),
            "b",
            Some(parent.record_digest().unwrap()),
            1,
            6,
        );
        let scope_hash = scope_key_hash(&child).unwrap();
        let good = readback_for(&child, &scope_hash);

        let mut wrong_scope = good.clone();
        wrong_scope.scope_hash = vec![0_u8; 32];
        assert!(verify_history_artifact(&scope_hash, &wrong_scope, &child).is_err());

        let mut wrong_reservation = good.clone();
        wrong_reservation.reservation_id = "reservation-other".into();
        assert!(verify_history_artifact(&scope_hash, &wrong_reservation, &child).is_err());

        let mut wrong_operation = good.clone();
        wrong_operation.operation_id = "operation-2".into();
        assert!(verify_history_artifact(&scope_hash, &wrong_operation, &child).is_err());

        let mut wrong_certificate_id = good.clone();
        wrong_certificate_id.certificate_id = "certificate-other".into();
        assert!(verify_history_artifact(&scope_hash, &wrong_certificate_id, &child).is_err());

        let mut wrong_authority = good.clone();
        wrong_authority.authority_id = "authority-2".into();
        assert!(verify_history_artifact(&scope_hash, &wrong_authority, &child).is_err());

        let mut wrong_term = good.clone();
        wrong_term.authority_term = 2;
        assert!(verify_history_artifact(&scope_hash, &wrong_term, &child).is_err());

        let mut wrong_fence = good.clone();
        wrong_fence.global_fence_sequence = 7;
        assert!(verify_history_artifact(&scope_hash, &wrong_fence, &child).is_err());

        let mut wrong_parent = good.clone();
        wrong_parent.parent_certificate_hash = Some(vec![1_u8; 32]);
        assert!(verify_history_artifact(&scope_hash, &wrong_parent, &child).is_err());

        // A tampered JSON body (a different certificate under the same hash
        // key) is never durable proof.
        let mut tampered = good.clone();
        let mut forged = child.clone();
        forged.certificate_nonce = "forged-nonce".into();
        forged.completion_digest = forged.recompute_completion_digest().unwrap();
        forged.sign(&signing).unwrap();
        tampered.certificate_json = serde_json::to_string(&forged).unwrap();
        assert!(verify_history_artifact(&scope_hash, &tampered, &child).is_err());

        let mut unparseable = good;
        unparseable.certificate_json = "{invalid".into();
        assert!(verify_history_artifact(&scope_hash, &unparseable, &child).is_err());
    }
}
