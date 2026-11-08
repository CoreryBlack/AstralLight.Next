//! Durable leadership fence (spec: Rust后端编码规范 §15.9.1).
//!
//! The in-process leader flag is a liveness hint only. Every mutating quorum
//! transaction — and every read-only signing artifact such as the startup
//! attestation — must be gated by the durable leader key:
//!
//! - The leader key is written once per term by the election, attached to a
//!   REAL etcd lease (`PutOptions::with_lease`), and carries an exact
//!   [`LeadershipTokenRecord`] value (term identity: authority, instance,
//!   lease). Etcd deletes the key the moment the lease expires, so the fence
//!   compare fails for every stale term automatically.
//! - [`AuthorityService::execute_leader_txn`] appends a compare-only
//!   [`StoreOp::RequireValue`] on the canonical leader key to the final
//!   transaction. A stale owner (expired lease, newer term) can therefore
//!   never land a write, even when its local flag is still `true`.
//! - [`AuthorityService::bind_leadership_token`] is the ONLY install path:
//!   it verifies, through a linearizable read, that the canonical leader key
//!   holds exactly these token bytes before installing the fence. The
//!   election, the ephemeral CLI paths, and external contract tests all go
//!   through it; there is no install path that skips the durable check.
//!
//! Error discipline: leadership loss surfaces as
//! [`AuthorityServiceError::NotLeader`] and revokes the local fence
//! immediately; the write is refused, never retried against a possibly newer
//! term. Unknown store outcomes keep their explicit unknown semantics.

use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use crate::error::{AuthorityServiceError, AuthorityStoreError};
use crate::service::AuthorityService;
use crate::store::etcd::EtcdAuthorityStore;
use crate::store::{StoreOp, StoreTxn, StoreTxnOutcome};

/// Canonical leader key for one authority deployment. The same layout is
/// used by the election task, the ephemeral CLI paths, and every fence
/// compare, so the guarded record is always exactly one well-known key.
pub fn leader_key(key_prefix: &str, authority_name: &str) -> String {
    format!(
        "{}/leader/{}",
        key_prefix.trim_end_matches('/'),
        authority_name
    )
}

/// The durable value written into the leader key for one term. Encoded as
/// canonical JSON; the exact bytes are the fence compare anchor, so every
/// field must round-trip byte-identically (serde struct order is stable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeadershipTokenRecord {
    /// Wire version of the token value; only 1 is defined.
    pub v: u32,
    /// Authority identity from the quorum configuration.
    pub authority: String,
    /// Instance id of the term owner (UUID, generated per process).
    pub instance: String,
    /// The etcd lease backing this term; the leader key is deleted when the
    /// lease expires. Non-zero: a token without a real lease never binds.
    pub lease: i64,
}

impl LeadershipTokenRecord {
    pub fn new(authority: &str, instance: &str, lease_id: i64) -> Self {
        Self {
            v: 1,
            authority: authority.to_owned(),
            instance: instance.to_owned(),
            lease: lease_id,
        }
    }

    /// Canonical JSON bytes of this record (the exact leader-key value).
    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("leadership token record serializes")
    }

    /// Decode and structurally validate; `None` when the bytes are not a
    /// valid v1 token value.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let record: Self = serde_json::from_slice(bytes).ok()?;
        if record.v != 1
            || record.authority.is_empty()
            || record.instance.is_empty()
            || record.lease == 0
        {
            return None;
        }
        Some(record)
    }
}

/// One leadership term's fence anchor: the canonical leader key plus the
/// exact bytes that were written there under a real lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeadershipToken {
    pub(crate) key: String,
    pub(crate) value: Vec<u8>,
}

impl LeadershipToken {
    /// Build the term token for `record` at `leader_key`. The value is the
    /// canonical encoding of the record; binding verifies these exact bytes
    /// against the durable record.
    pub fn from_record(
        leader_key: String,
        record: &LeadershipTokenRecord,
    ) -> Result<Self, AuthorityServiceError> {
        if record.lease == 0 {
            return Err(AuthorityServiceError::Store(
                AuthorityStoreError::Configuration(
                    "leadership token requires a real non-zero lease".to_owned(),
                ),
            ));
        }
        Ok(Self {
            key: leader_key,
            value: record.encode(),
        })
    }

    /// Rebuild a token handle from the exact durable bytes, e.g. read back
    /// from the store to join the live term. [`AuthorityService::
    /// bind_leadership_token`] still verifies these bytes with a linearizable
    /// read, so a stale or forged value is always refused.
    pub fn from_durable_bytes(key: String, value: Vec<u8>) -> Self {
        Self { key, value }
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    /// The exact durable bytes this term was written under (public, non-secret:
    /// they are stored in the quorum-visible leader key).
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Decoded term identity, for logging/audit only (the value is public).
    pub fn record(&self) -> Option<LeadershipTokenRecord> {
        LeadershipTokenRecord::decode(&self.value)
    }
}

/// The service-side fence state: the currently bound term, if any.
///
/// Install goes exclusively through
/// [`AuthorityService::bind_leadership_token`], which requires the durable
/// record to match first; revocation is idempotent and immediate on any
/// liveness loss or fence refusal.
#[derive(Debug, Default)]
pub(crate) struct LeadershipFence {
    state: RwLock<Option<LeadershipToken>>,
}

impl LeadershipFence {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn install(&self, token: LeadershipToken) {
        *self.state.write().expect("leadership fence poisoned") = Some(token);
    }

    /// Drop the bound term (idempotent). Returns true when a term was held.
    pub(crate) fn revoke(&self) -> bool {
        self.state
            .write()
            .expect("leadership fence poisoned")
            .take()
            .is_some()
    }

    pub(crate) fn current(&self) -> Option<LeadershipToken> {
        self.state
            .read()
            .expect("leadership fence poisoned")
            .clone()
    }
}

impl AuthorityService {
    /// The fence state (crate-internal; election and CLI paths only).
    pub(crate) fn leadership(&self) -> &LeadershipFence {
        &self.leadership
    }

    /// Bind one leadership term to this service.
    ///
    /// The ONLY install path for the leadership fence, safe for production
    /// and external contract tests alike:
    ///
    /// 1. `token.key` must be the CANONICAL leader key derived from this
    ///    service's quorum configuration,
    /// 2. the token value must decode to a valid v1 record whose authority
    ///    matches this service's configured authority name and whose lease is
    ///    a real non-zero lease,
    /// 3. a LINEARIZABLE read must show the leader key holding exactly these
    ///    token bytes right now.
    ///
    /// Only then is the term installed and the leader flag published. There
    /// is no bypass: a token that does not correspond to a currently visible
    /// durable leader record is refused with [`AuthorityServiceError::NotLeader`]
    /// and nothing is installed.
    pub async fn bind_leadership_token(
        &self,
        token: &LeadershipToken,
    ) -> Result<(), AuthorityServiceError> {
        let canonical_key = leader_key(
            &self.config.quorum.key_prefix,
            &self.config.quorum.authority_name,
        );
        if token.key != canonical_key {
            return Err(AuthorityServiceError::Store(
                AuthorityStoreError::Configuration(format!(
                    "leadership token key {} is not the canonical leader key {canonical_key}",
                    token.key
                )),
            ));
        }
        let Some(record) = token.record() else {
            return Err(AuthorityServiceError::Store(
                AuthorityStoreError::Configuration(
                    "leadership token value is not a valid v1 record".to_owned(),
                ),
            ));
        };
        if record.authority != self.config.quorum.authority_name {
            return Err(AuthorityServiceError::Store(
                AuthorityStoreError::Configuration(format!(
                    "leadership token authority {} does not match configured authority {}",
                    record.authority, self.config.quorum.authority_name
                )),
            ));
        }
        // Linearizable read (never serializable/stale): the exact bytes must
        // be visible in the quorum store right now.
        match self.store.get(&token.key).await? {
            Some(stored) if stored.value == token.value => {}
            _ => {
                return Err(AuthorityServiceError::NotLeader);
            }
        }
        self.leadership.install(token.clone());
        // Publish liveness only after the durable term is verified and bound.
        self.leader
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// Compare-only leadership verification with ZERO writes, for read-only
    /// signing artifacts (e.g. the startup attestation): the canonical leader
    /// key must hold exactly the bound term's bytes in a linearizable read.
    /// Call it before signing AND before returning the response; on any
    /// mismatch the local fence is revoked and signing must be refused.
    /// A service that never bound a term (standby) fails fast.
    pub(crate) async fn verify_leadership_fenced(
        &self,
    ) -> Result<LeadershipToken, AuthorityServiceError> {
        let token = self
            .leadership
            .current()
            .ok_or(AuthorityServiceError::NotLeader)?;
        if self.leader_record_matches(&token).await? {
            Ok(token)
        } else {
            self.leadership.revoke();
            Err(AuthorityServiceError::NotLeader)
        }
    }

    /// Execute one mutating quorum transaction under the durable leadership
    /// fence. Replacement for direct `self.store.execute(txn)` calls on all
    /// mutating paths (prepare, reserve, mint, commit, certify, close,
    /// rotation, bootstrap).
    ///
    /// A compare-only `RequireValue` op on the canonical leader key is
    /// appended to the FINAL transaction, so the write lands atomically only
    /// while the bound term's lease is still alive and this exact term still
    /// owns the leader key. On precondition failure the fence re-checks the
    /// leader key linearizably: leadership loss is reported as
    /// [`AuthorityServiceError::NotLeader`] with the local term revoked;
    /// an unrelated business precondition is returned unchanged.
    pub(crate) async fn execute_leader_txn(
        &self,
        txn: StoreTxn,
    ) -> Result<StoreTxnOutcome, AuthorityServiceError> {
        let token = self
            .leadership
            .current()
            .ok_or(AuthorityServiceError::NotLeader)?;
        let fenced = txn.with_op(StoreOp::RequireValue {
            key: token.key.clone(),
            value: token.value.clone(),
        });
        let outcome = match self.store.execute(fenced).await {
            Ok(outcome) => outcome,
            Err(error) => return Err(AuthorityServiceError::Store(error)),
        };
        if let StoreTxnOutcome::PreconditionFailed { .. } = &outcome {
            // Distinguish fence loss from a business precondition with one
            // linearizable re-read of the leader key.
            if !self.leader_record_matches(&token).await? {
                self.leadership.revoke();
                tracing::warn!(
                    key = %token.key,
                    "leadership fence lost; mutation refused and local term revoked"
                );
                return Err(AuthorityServiceError::NotLeader);
            }
        }
        Ok(outcome)
    }

    /// Linearizable exact-bytes check of the bound term against the durable
    /// leader record. Missing key, divergent bytes and store unavailability
    /// are all fence failures (fail-closed).
    async fn leader_record_matches(
        &self,
        token: &LeadershipToken,
    ) -> Result<bool, AuthorityServiceError> {
        let record = self
            .store
            .get(&token.key)
            .await
            .map_err(AuthorityServiceError::Store)?;
        Ok(record
            .map(|stored| stored.value == token.value)
            .unwrap_or(false))
    }
}

/// Single-term leadership for short-lived CLI paths (key rotation, bootstrap):
/// grant a real lease, CAS-acquire the canonical leader key, and bind the
/// verified token to the service. Dropping the guard revokes the lease
/// best-effort (which deletes the leader key immediately); the lease TTL is
/// the hard upper bound of the term either way.
///
/// The caller's deadline MUST be strictly shorter than the lease TTL — the
/// helper refuses otherwise — because the term is not kept alive during the
/// operation. If the operation runs past the TTL, the fence refuses the final
/// transaction (fail-closed) instead of extending ownership.
pub(crate) struct EphemeralLeadership {
    store: EtcdAuthorityStore,
    lease_id: i64,
}

impl EphemeralLeadership {
    /// Bound acquisition attempts; each is a fresh CAS on the leader key.
    /// This is leadership liveness for a one-shot tool, not operation retry.
    const MAX_ACQUIRE_ATTEMPTS: usize = 3;

    /// The caller's deadline must be positive and strictly below the lease
    /// TTL: the term is not kept alive during the operation, so running past
    /// the TTL must end in a fence refusal (fail-closed), never an extension.
    pub(crate) fn validate_ephemeral_deadline(
        ttl_seconds: i64,
        deadline_seconds: i64,
    ) -> Result<(), AuthorityServiceError> {
        if deadline_seconds <= 0 || deadline_seconds >= ttl_seconds {
            return Err(AuthorityServiceError::Store(
                AuthorityStoreError::Configuration(format!(
                    "operation deadline {deadline_seconds}s must be positive and strictly below the leadership lease TTL {ttl_seconds}s"
                )),
            ));
        }
        Ok(())
    }

    /// Acquire an ephemeral term. The WHOLE acquisition — lease grant, every
    /// leader-key CAS attempt, and the leadership bind — is executed under
    /// `acquire_budget` (each step is raced against the REMAINING budget, not
    /// just checked between steps). On success the returned `Duration` is the
    /// wall-clock time the acquisition took; the caller MUST deduct it from
    /// its remaining operation timeout budget. On ANY failure after the lease
    /// was granted, the lease is revoked before the error is returned; a
    /// revoke failure there is logged at error level (the primary error is
    /// returned) — it is never silently swallowed, and the lease TTL remains
    /// the hard bound in that case.
    pub(crate) async fn acquire(
        service: &AuthorityService,
        store: &EtcdAuthorityStore,
        instance: &str,
        ttl_seconds: i64,
        deadline_seconds: i64,
        acquire_budget: std::time::Duration,
    ) -> Result<(Self, std::time::Duration), AuthorityServiceError> {
        Self::validate_ephemeral_deadline(ttl_seconds, deadline_seconds)?;
        let started = std::time::Instant::now();
        let authority = &service.config.quorum.authority_name;
        let key = leader_key(
            &service.config.quorum.key_prefix,
            &service.config.quorum.authority_name,
        );

        // lease grant under the remaining acquisition budget.
        let lease_id = tokio::time::timeout(
            acquire_budget.saturating_sub(started.elapsed()),
            store.lease_grant(ttl_seconds),
        )
        .await
        .map_err(|_| {
            AuthorityServiceError::Store(AuthorityStoreError::Unavailable(
                "ephemeral leadership acquisition budget exhausted at lease grant".to_owned(),
            ))
        })?
        .map_err(AuthorityServiceError::Store)?;
        let token = LeadershipToken::from_record(
            key,
            &LeadershipTokenRecord::new(authority, instance, lease_id),
        )?;

        // Bounded attempts + bind; any error from here revokes the lease.
        let bound = async {
            let mut acquired = false;
            for attempt in 1..=Self::MAX_ACQUIRE_ATTEMPTS {
                let remaining = acquire_budget.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    return Err(AuthorityServiceError::NotLeader);
                }
                if tokio::time::timeout(
                    remaining,
                    store.try_acquire_leader_key(&token.key, lease_id, &token.value),
                )
                .await
                .map_err(|_| {
                    AuthorityServiceError::Store(AuthorityStoreError::Unavailable(
                        "ephemeral leadership acquisition budget exhausted during leader key CAS"
                            .to_owned(),
                    ))
                })?
                .map_err(AuthorityServiceError::Store)?
                {
                    acquired = true;
                    break;
                }
                if attempt < Self::MAX_ACQUIRE_ATTEMPTS {
                    // Wait for the other term's lease, never past the budget.
                    let wait = std::time::Duration::from_secs((ttl_seconds as u64 / 2).max(1))
                        .min(acquire_budget.saturating_sub(started.elapsed()));
                    if !wait.is_zero() {
                        tokio::time::sleep(wait).await;
                    }
                }
            }
            if !acquired {
                return Err(AuthorityServiceError::NotLeader);
            }
            let bind_remaining = acquire_budget.saturating_sub(started.elapsed());
            tokio::time::timeout(bind_remaining, service.bind_leadership_token(&token))
                .await
                .map_err(|_| {
                    AuthorityServiceError::Store(AuthorityStoreError::Unavailable(
                        "ephemeral leadership acquisition budget exhausted during leadership bind"
                            .to_owned(),
                    ))
                })?
        }
        .await;

        if let Err(error) = bound {
            // Failure path: no live lease may outlive a refused acquisition.
            // Both the timeout and the inner revoke error are surfaced.
            let revoke = match tokio::time::timeout(
                std::time::Duration::from_secs(3),
                store.lease_revoke(lease_id),
            )
            .await
            {
                Ok(inner) => inner.map_err(AuthorityServiceError::Store),
                Err(_) => Err(AuthorityServiceError::Store(
                    AuthorityStoreError::Unavailable(
                        "ephemeral leadership revoke timed out on the acquisition failure path"
                            .to_owned(),
                    ),
                )),
            };
            if let Err(revoke_error) = revoke {
                tracing::error!(
                    lease = lease_id,
                    error = %revoke_error,
                    "ephemeral leadership acquisition failed AND its lease revoke failed; the term is bounded only by the lease TTL"
                );
            }
            return Err(error);
        }

        let elapsed = started.elapsed();
        tracing::info!(
            lease = lease_id,
            instance,
            ?elapsed,
            "ephemeral leadership acquired for CLI operation"
        );
        Ok((
            Self {
                store: store.clone(),
                lease_id,
            },
            elapsed,
        ))
    }

    /// Explicit, AWAITED release: revoke the lease; etcd deletes the leader
    /// key immediately, so the next election is not delayed by the TTL. The
    /// revoke has its OWN bounded release budget (3s, independent of the
    /// caller's operation deadline) and its error is RETURNED, never
    /// swallowed: a failed revoke leaves the term bounded by the lease TTL
    /// and must be visible to the operator. Call on every exit path — there
    /// is no detached drop task.
    pub(crate) async fn release(self) -> Result<(), AuthorityServiceError> {
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            self.store.lease_revoke(self.lease_id),
        )
        .await
            .map_err(|_| {
            AuthorityServiceError::Store(AuthorityStoreError::Unavailable(
                "ephemeral leadership revoke timed out (release budget 3s); the term is bounded by the lease TTL".to_owned(),
            ))
        })?
        .map_err(AuthorityServiceError::Store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthorityServiceConfig;
    use crate::service::AuthorityService;
    use crate::signing::ProtectedAuthoritySigner;
    use crate::store::memory::MemoryAuthorityStore;
    use crate::store::AuthorityStore;
    use astral_types::{
        AuthorityRootKey, AuthorityRootKeyRole, AuthorityTrustRoot, GlobalAuthorityFrontier,
    };
    use std::sync::Arc;

    /// Runtime-election-parity test injection for in-crate unit tests: seed a
    /// REAL lease-backed leader record in the memory store and bind it through
    /// the production `bind_leadership_token` path. There is no other install
    /// path. External integration tests (compiled without cfg(test)) replicate
    /// this shape with their own fixture instead of calling this helper.
    pub(crate) async fn install_test_leadership(
        service: &AuthorityService,
        store: &MemoryAuthorityStore,
        instance: &str,
    ) -> Result<i64, AuthorityServiceError> {
        let authority = &service.config().quorum.authority_name;
        let lease_id = store.grant_lease(service.config().quorum.lease_ttl_seconds);
        let token = LeadershipToken::from_record(
            leader_key(&service.config().quorum.key_prefix, authority),
            &LeadershipTokenRecord::new(authority, instance, lease_id),
        )?;
        if !store.try_acquire_leader_key(&token.key, lease_id, &token.value) {
            return Err(AuthorityServiceError::NotLeader);
        }
        service.bind_leadership_token(&token).await?;
        Ok(lease_id)
    }

    fn root_key(
        seed: u8,
        key_id: &str,
        epoch: u64,
        role: AuthorityRootKeyRole,
    ) -> AuthorityRootKey {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        AuthorityRootKey {
            key_id: key_id.to_owned(),
            key_epoch: epoch,
            role,
            verifying_key_hex: hex::encode(signing.verifying_key().as_bytes()),
        }
    }

    /// A real signer bound to a real trust root (mirrors the runtime-test
    /// shape); the service construction path is honest, never a stub.
    fn test_service(store: Arc<MemoryAuthorityStore>) -> AuthorityService {
        let seed = [0x42u8; 32];
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        let trust_root = AuthorityTrustRoot {
            root_id: "root-test".to_owned(),
            keys: vec![
                AuthorityRootKey {
                    key_id: "signer-1".to_owned(),
                    key_epoch: 1,
                    role: AuthorityRootKeyRole::Signer,
                    verifying_key_hex: hex::encode(signing.verifying_key().as_bytes()),
                },
                root_key(2, "root-1", 1, AuthorityRootKeyRole::Root),
                root_key(3, "genesis-1", 1, AuthorityRootKeyRole::Genesis),
            ],
            created_at: 1_000,
        };
        let signer = Arc::new(
            ProtectedAuthoritySigner::from_seed(seed, "signer-1", &trust_root)
                .expect("test signer binds to the trust root"),
        );
        AuthorityService::new(AuthorityServiceConfig::default(), store, signer)
    }

    fn put_if_absent(key: &str, value: &str) -> StoreTxn {
        StoreTxn::new().with_op(StoreOp::PutIfAbsent {
            key: key.to_owned(),
            value: value.as_bytes().to_vec(),
        })
    }

    #[tokio::test]
    async fn lease_generation_change_refuses_the_old_owner_write() {
        let store = Arc::new(MemoryAuthorityStore::new());
        let service = test_service(Arc::clone(&store));
        let canonical = leader_key(
            &service.config().quorum.key_prefix,
            &service.config().quorum.authority_name,
        );

        // Term A: real lease-backed leader record, bound through the
        // production path; the mutation lands under the fence.
        let lease_a = install_test_leadership(&service, &store, "instance-a")
            .await
            .unwrap();
        let outcome = service.execute_leader_txn(put_if_absent("m1", "a")).await;
        assert!(matches!(outcome, Ok(StoreTxnOutcome::Applied { .. })));
        assert!(store.get("m1").await.unwrap().is_some());

        // Lease A expires: etcd deletes the leader key; the OLD owner still
        // reports the stale liveness flag, and its token can no longer write.
        assert!(store.expire_lease(lease_a));
        assert!(store.get(&canonical).await.unwrap().is_none());
        assert!(
            service.is_leader(),
            "stale flag must not substitute the fence"
        );
        let refused = service
            .execute_leader_txn(put_if_absent("m2", "a-stale"))
            .await
            .unwrap_err();
        assert!(matches!(refused, AuthorityServiceError::NotLeader));
        assert!(
            store.get("m2").await.unwrap().is_none(),
            "nothing written by the stale owner"
        );
        assert!(
            service.leadership().current().is_none(),
            "the refused term is revoked locally"
        );

        // Term B: the new owner acquires the freed key and writes again.
        install_test_leadership(&service, &store, "instance-b")
            .await
            .unwrap();
        let outcome = service.execute_leader_txn(put_if_absent("m2", "b")).await;
        assert!(matches!(outcome, Ok(StoreTxnOutcome::Applied { .. })));
        // History written under term A is untouched (no overwrite, no rollback).
        let m1 = store.get("m1").await.unwrap().unwrap();
        assert_eq!(m1.value, b"a");
    }

    #[tokio::test]
    async fn mutations_without_leadership_are_refused_with_zero_writes() {
        let store = Arc::new(MemoryAuthorityStore::new());
        let service = test_service(Arc::clone(&store));
        let refused = service
            .execute_leader_txn(put_if_absent("m1", "a"))
            .await
            .unwrap_err();
        assert!(matches!(refused, AuthorityServiceError::NotLeader));
        assert!(store.get("m1").await.unwrap().is_none());

        // verify_leadership_fenced on a standby fails fast as well.
        assert!(matches!(
            service.verify_leadership_fenced().await,
            Err(AuthorityServiceError::NotLeader)
        ));
    }

    #[tokio::test]
    async fn stale_token_bytes_are_refused_by_the_exact_compare() {
        let store = Arc::new(MemoryAuthorityStore::new());
        let service = test_service(Arc::clone(&store));
        let canonical = leader_key(
            &service.config().quorum.key_prefix,
            &service.config().quorum.authority_name,
        );
        let _lease_a = install_test_leadership(&service, &store, "instance-a")
            .await
            .unwrap();

        // A newer term overwrites the leader key value in the store (fresh
        // lease, fresh bytes) while the old owner still holds term A locally.
        let lease_b = store.grant_lease(15);
        let new_value = LeadershipTokenRecord::new(
            &service.config().quorum.authority_name,
            "instance-b",
            lease_b,
        )
        .encode();
        store
            .execute(StoreTxn::new().with_op(StoreOp::Put {
                key: canonical.clone(),
                value: new_value,
            }))
            .await
            .unwrap();

        // The stale term is refused on the exact-bytes compare...
        let refused = service
            .execute_leader_txn(put_if_absent("m1", "a-stale"))
            .await
            .unwrap_err();
        assert!(matches!(refused, AuthorityServiceError::NotLeader));
        assert!(store.get("m1").await.unwrap().is_none());

        // ...and read-only signing objects fail the same fence.
        assert!(matches!(
            service.verify_leadership_fenced().await,
            Err(AuthorityServiceError::NotLeader)
        ));
    }

    #[tokio::test]
    async fn bind_rejects_tokens_that_do_not_match_the_durable_record() {
        let store = Arc::new(MemoryAuthorityStore::new());
        let service = test_service(Arc::clone(&store));
        let authority = &service.config().quorum.authority_name;
        let canonical = leader_key(&service.config().quorum.key_prefix, authority);

        // Non-canonical key.
        let token = LeadershipToken::from_record(
            "other/leader".to_owned(),
            &LeadershipTokenRecord::new(authority, "i", 7),
        )
        .unwrap();
        assert!(service.bind_leadership_token(&token).await.is_err());

        // Foreign authority name.
        let token = LeadershipToken::from_record(
            canonical.clone(),
            &LeadershipTokenRecord::new("other-authority", "i", 7),
        )
        .unwrap();
        assert!(service.bind_leadership_token(&token).await.is_err());

        // Zero lease is not a real term.
        let zero_lease_error = LeadershipToken::from_record(
            canonical.clone(),
            &LeadershipTokenRecord::new(authority, "i", 0),
        )
        .unwrap_err();
        assert!(matches!(
            zero_lease_error,
            AuthorityServiceError::Store(AuthorityStoreError::Configuration(_))
        ));

        // Durable record missing: the exact-bytes readback refuses.
        let token = LeadershipToken::from_record(
            canonical.clone(),
            &LeadershipTokenRecord::new(authority, "i", 7),
        )
        .unwrap();
        assert!(matches!(
            service.bind_leadership_token(&token).await,
            Err(AuthorityServiceError::NotLeader)
        ));

        // Seed a REAL record with different bytes than the token: refused.
        let lease = store.grant_lease(15);
        let durable = LeadershipTokenRecord::new(authority, "real", lease).encode();
        assert!(store.try_acquire_leader_key(&canonical, lease, &durable));
        let forged_bytes = LeadershipTokenRecord::new(authority, "forged", lease).encode();
        let forged = LeadershipToken {
            key: canonical.clone(),
            value: forged_bytes,
        };
        assert!(matches!(
            service.bind_leadership_token(&forged).await,
            Err(AuthorityServiceError::NotLeader)
        ));
        // The genuine record still binds.
        let genuine = LeadershipToken {
            key: canonical.clone(),
            value: durable,
        };
        service.bind_leadership_token(&genuine).await.unwrap();
        assert!(service.verify_leadership_fenced().await.is_ok());
    }

    #[tokio::test]
    async fn business_precondition_failure_is_not_misread_as_leadership_loss() {
        let store = Arc::new(MemoryAuthorityStore::new());
        let service = test_service(Arc::clone(&store));
        install_test_leadership(&service, &store, "instance-a")
            .await
            .unwrap();
        // A ReplaceIfRevision on a missing key fails on business grounds while
        // leadership stays intact: the fence re-read confirms the term.
        let outcome = service
            .execute_leader_txn(StoreTxn::new().with_op(StoreOp::ReplaceIfRevision {
                key: "frontier".to_owned(),
                expected_revision: 999,
                value: Vec::new(),
            }))
            .await
            .unwrap();
        assert_eq!(
            outcome,
            StoreTxnOutcome::PreconditionFailed {
                key: "frontier".to_owned()
            }
        );
        assert!(service.leadership().current().is_some());
        assert!(service.verify_leadership_fenced().await.is_ok());
    }

    #[tokio::test]
    async fn ephemeral_leadership_refuses_deadline_at_or_above_ttl() {
        // The deadline contract is validated before any store call; the
        // extracted rule is the exact code the acquire path runs.
        assert!(EphemeralLeadership::validate_ephemeral_deadline(15, 14).is_ok());
        assert!(matches!(
            EphemeralLeadership::validate_ephemeral_deadline(15, 15),
            Err(AuthorityServiceError::Store(
                AuthorityStoreError::Configuration(_)
            ))
        ));
        assert!(matches!(
            EphemeralLeadership::validate_ephemeral_deadline(15, 0),
            Err(AuthorityServiceError::Store(
                AuthorityStoreError::Configuration(_)
            ))
        ));
    }

    /// A pre-rotation signer must fail the new-issuance gate (`AuthorityService::
    /// require_active_signer`): the rotated root RETAINS the historical key for
    /// verification, but the ACTIVE signer entry is the new key, and only that
    /// one may sign new artifacts.
    #[test]
    fn require_active_signer_refuses_historical_key_after_rotation() {
        let store = Arc::new(MemoryAuthorityStore::new());
        let service = test_service(Arc::clone(&store));
        let old_seed = [0x11u8; 32];
        let new_seed = [0x22u8; 32];
        let old_signing = ed25519_dalek::SigningKey::from_bytes(&old_seed);
        let new_signing = ed25519_dalek::SigningKey::from_bytes(&new_seed);
        // Rotated (folded) root: full history retained, signer_key() selects
        // the highest-epoch SIGNER entry.
        let rotated_root = AuthorityTrustRoot {
            root_id: "root-test".to_owned(),
            keys: vec![
                AuthorityRootKey {
                    key_id: "signer-1".to_owned(),
                    key_epoch: 1,
                    role: AuthorityRootKeyRole::Signer,
                    verifying_key_hex: hex::encode(old_signing.verifying_key().as_bytes()),
                },
                AuthorityRootKey {
                    key_id: "signer-2".to_owned(),
                    key_epoch: 2,
                    role: AuthorityRootKeyRole::Signer,
                    verifying_key_hex: hex::encode(new_signing.verifying_key().as_bytes()),
                },
                root_key(2, "root-1", 1, AuthorityRootKeyRole::Root),
                root_key(3, "genesis-1", 1, AuthorityRootKeyRole::Genesis),
            ],
            created_at: 2_000,
        };
        let frontier = GlobalAuthorityFrontier::genesis(
            "authority-1",
            "root-test",
            &rotated_root.digest().unwrap(),
            "signer-2",
            2,
            2_000,
        )
        .unwrap();
        let state = crate::service::VerifiedAuthorityState {
            genesis_trust_root: rotated_root.clone(),
            rotations: Vec::new(),
            trust_root: rotated_root.clone(),
            frontier,
            frontier_revision: 1,
            gate_epoch: 1,
            gate_epoch_revision: 1,
        };

        // The OLD signer (still in the key set for history verification) is
        // refused for new signing: bind it against the HISTORICAL root — the
        // rotated root itself refuses this seed at construction, because
        // from_seed binds only to the ACTIVE signer entry.
        let historical_root = AuthorityTrustRoot {
            keys: rotated_root
                .keys
                .iter()
                .filter(|entry| entry.key_id != "signer-2")
                .cloned()
                .collect(),
            ..rotated_root.clone()
        };
        let old_signer =
            ProtectedAuthoritySigner::from_seed(old_seed, "signer-1", &historical_root)
                .expect("old signer binds to the historical root");
        assert!(!old_signer.matches_trust_root(&state.trust_root).unwrap());

        // The service gate refuses to sign with the historical signer even
        // while the pre-rotation service instance holds it (and leadership).
        assert!(service.require_active_signer(&state).is_err());

        // A service whose signer IS the active signer passes.
        let new_signer = ProtectedAuthoritySigner::from_seed(new_seed, "signer-2", &rotated_root)
            .expect("new signer binds to the rotated root");
        let rotated_service = AuthorityService::new(
            crate::config::AuthorityServiceConfig::default(),
            store,
            Arc::new(new_signer),
        );
        assert!(rotated_service.require_active_signer(&state).is_ok());
    }
}
