//! etcd-backed authority store: linearizable reads and atomic Txn CAS.
//!
//! Built on the mature `etcd-client` crate (etcd v3 gRPC). Every read uses
//! etcd's default (linearizable) consistency — `with_serializable` is never
//! set, so a stale replica can never serve authority state. Every mutation
//! batch is a single etcd transaction whose compares encode the
//! preconditions (`create_revision == 0` for put-if-absent, `mod_revision ==
//! expected` for compare-and-swap), so either the whole batch lands at one
//! shared revision or nothing is written. Network failures surface as
//! `Unavailable`; the service layer turns them into explicit unknown outcomes
//! and never retries them automatically.
//!
//! Build note: `etcd-client` compiles the etcd protos at build time and
//! requires a system `protoc` binary (via `PATH` or the `PROTOC` env var).

use etcd_client::{
    Certificate, Client, Compare, CompareOp, ConnectOptions, GetOptions, Identity, PutOptions,
    TlsOptions, Txn, TxnOp, TxnOpResponse,
};

use async_trait::async_trait;

use crate::error::AuthorityStoreError;
use crate::store::{
    validate_snapshot_reads, AuthorityStore, SnapshotRead, StoreOp, StoreSnapshot, StoreTxn,
    StoreTxnOutcome, StoredRecord,
};

/// Hard upper bound for every etcd request. Authority mutations and fence
/// reads must never hang on a wedged quorum connection: the timeout surfaces
/// as `Unavailable`, which the service maps to explicit unknown/refusal
/// outcomes instead of unbounded waiting.
const ETCD_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Hard upper bound for one lease keep-alive round trip. Liveness checks are
/// only useful while they are bounded; an unbounded keep-alive would hide a
/// lost quorum and keep a stale leader flag alive. Shared with the election
/// loop, which wraps each keep-alive in the same bound.
pub(crate) const LEASE_KEEP_ALIVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Production etcd store.
#[derive(Clone)]
pub struct EtcdAuthorityStore {
    client: Client,
}

impl std::fmt::Debug for EtcdAuthorityStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EtcdAuthorityStore")
            .field("client", &"<etcd channel>")
            .finish()
    }
}

impl EtcdAuthorityStore {
    /// Connect with mandatory TLS when `tls_enabled`; insecure etcd is only
    /// allowed when the deployment explicitly disables etcd TLS.
    pub async fn connect(
        endpoints: &[String],
        tls_enabled: bool,
        tls_ca_path: Option<&std::path::Path>,
        tls_client_cert_path: Option<&std::path::Path>,
        tls_client_key_path: Option<&std::path::Path>,
        tls_domain_name: Option<&str>,
    ) -> Result<Self, AuthorityStoreError> {
        let mut options = ConnectOptions::new()
            .with_connect_timeout(std::time::Duration::from_secs(5))
            .with_timeout(ETCD_REQUEST_TIMEOUT)
            .with_keep_alive(
                std::time::Duration::from_secs(5),
                std::time::Duration::from_secs(3),
            );
        if tls_enabled {
            let ca_path = tls_ca_path.ok_or_else(|| {
                AuthorityStoreError::Configuration(
                    "etcd TLS enabled but ca path missing".to_owned(),
                )
            })?;
            let ca_pem = std::fs::read(ca_path).map_err(|error| {
                AuthorityStoreError::Configuration(format!("read etcd CA: {error}"))
            })?;
            let mut tls = TlsOptions::new().ca_certificate(Certificate::from_pem(ca_pem));
            if let (Some(cert_path), Some(key_path)) = (tls_client_cert_path, tls_client_key_path) {
                let cert_pem = std::fs::read(cert_path).map_err(|error| {
                    AuthorityStoreError::Configuration(format!("read etcd client cert: {error}"))
                })?;
                let key_pem = std::fs::read(key_path).map_err(|error| {
                    AuthorityStoreError::Configuration(format!("read etcd client key: {error}"))
                })?;
                tls = tls.identity(Identity::from_pem(cert_pem, key_pem));
            }
            if let Some(domain_name) = tls_domain_name {
                tls = tls.domain_name(domain_name.to_owned());
            }
            options = options.with_tls(tls);
        }
        let client = Client::connect(endpoints, Some(options))
            .await
            .map_err(|error| AuthorityStoreError::Unavailable(format!("connect etcd: {error}")))?;
        Ok(Self { client })
    }

    /// Grant a leader lease (election liveness).
    pub async fn lease_grant(&self, ttl_seconds: i64) -> Result<i64, AuthorityStoreError> {
        let response = self
            .client
            .clone()
            .lease_grant(ttl_seconds, None)
            .await
            .map_err(|error| AuthorityStoreError::Unavailable(format!("lease grant: {error}")))?;
        Ok(response.id())
    }

    /// One-shot lease keepalive; returns true while the lease is alive.
    ///
    /// Both the request send and the response wait are bounded by
    /// [`LEASE_KEEP_ALIVE_TIMEOUT`]; a timeout is surfaced as `Unavailable`
    /// so the election treats it as liveness loss instead of hanging.
    pub async fn lease_keep_alive(&self, lease_id: i64) -> Result<bool, AuthorityStoreError> {
        let mut client = self.client.clone();
        let (mut keeper, mut stream) = client
            .lease_keep_alive(lease_id)
            .await
            .map_err(|error| AuthorityStoreError::Unavailable(format!("keep alive: {error}")))?;
        tokio::time::timeout(LEASE_KEEP_ALIVE_TIMEOUT, keeper.keep_alive())
            .await
            .map_err(|_| AuthorityStoreError::Unavailable("keep alive send timed out".to_owned()))?
            .map_err(|error| AuthorityStoreError::Unavailable(format!("keep alive: {error}")))?;
        let response = tokio::time::timeout(LEASE_KEEP_ALIVE_TIMEOUT, stream.message())
            .await
            .map_err(|_| {
                AuthorityStoreError::Unavailable("keep alive response timed out".to_owned())
            })?;
        match response {
            Ok(Some(message)) => Ok(message.ttl() > 0),
            Ok(None) => Ok(false),
            Err(error) => Err(AuthorityStoreError::Unavailable(format!(
                "keep alive stream: {error}"
            ))),
        }
    }

    /// Revoke the lease; etcd deletes every key attached to it (the leader
    /// key included) immediately. Used for orderly drain on shutdown.
    pub async fn lease_revoke(&self, lease_id: i64) -> Result<(), AuthorityStoreError> {
        let mut client = self.client.clone();
        client
            .lease_revoke(lease_id)
            .await
            .map_err(|error| AuthorityStoreError::Unavailable(format!("lease revoke: {error}")))?;
        Ok(())
    }

    /// Try to acquire the leader key via CAS create_revision==0.
    ///
    /// `token_value` is the exact durable bytes written for this term; the
    /// put is attached to `lease_id` (`PutOptions::with_lease`), so etcd
    /// deletes the leader key the moment the lease expires and every
    /// `RequireValue` fence compare against these bytes fails afterwards.
    pub async fn try_acquire_leader_key(
        &self,
        key: &str,
        lease_id: i64,
        token_value: &[u8],
    ) -> Result<bool, AuthorityStoreError> {
        let mut client = self.client.clone();
        let txn = Txn::new()
            .when(vec![Compare::create_revision(key, CompareOp::Equal, 0)])
            .and_then(vec![TxnOp::put(
                key,
                token_value.to_vec(),
                Some(PutOptions::new().with_lease(lease_id)),
            )])
            .or_else(Vec::new());
        let response = client
            .txn(txn)
            .await
            .map_err(|error| AuthorityStoreError::Unavailable(format!("leader CAS: {error}")))?;
        Ok(response.succeeded())
    }

    /// Read the current leader key value, when present.
    pub async fn read_leader_key(&self, key: &str) -> Result<Option<Vec<u8>>, AuthorityStoreError> {
        Ok(self.get(key).await?.map(|record| record.value))
    }
}

fn map_etcd_error(error: etcd_client::Error) -> AuthorityStoreError {
    AuthorityStoreError::Unavailable(error.to_string())
}

// A zero mod_revision represents an absent key in etcd. Every store guard
// documented as requiring an existing record must compare existence in the
// same transaction, including when the supplied revision or value is empty.
fn compare_existing(key: &str, comparison: Compare) -> [Compare; 2] {
    [
        Compare::create_revision(key.as_bytes(), CompareOp::Greater, 0),
        comparison,
    ]
}

fn compare_existing_revision(key: &str, revision: u64) -> Option<[Compare; 2]> {
    let revision = i64::try_from(revision).ok()?;
    Some(compare_existing(
        key,
        Compare::mod_revision(key.as_bytes(), CompareOp::Equal, revision),
    ))
}

fn refuse_unbounded_snapshot(reads: &[SnapshotRead]) -> Result<StoreSnapshot, AuthorityStoreError> {
    validate_snapshot_reads(reads)?;
    // etcd RangeRequest limits key count, not bytes. RangeResponse.more can
    // reveal truncation, but neither a per-range key limit nor a client decode
    // limit bounds the bytes the server materializes across the transaction,
    // including a single large value. The JSON gateway exposes the same Range
    // and Txn semantics. Refuse before any RPC until a server-side aggregate
    // byte budget is enforced and verified for this API.
    Err(AuthorityStoreError::Unavailable(
        "etcd snapshot server-side byte budget is not proven".to_owned(),
    ))
}

#[async_trait]
impl AuthorityStore for EtcdAuthorityStore {
    async fn get(&self, key: &str) -> Result<Option<StoredRecord>, AuthorityStoreError> {
        let mut client = self.client.clone();
        let response = client.get(key, None).await.map_err(map_etcd_error)?;
        Ok(response.kvs().first().map(|kv| StoredRecord {
            revision: kv.mod_revision().max(0) as u64,
            value: kv.value().to_vec(),
        }))
    }

    async fn get_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<(String, StoredRecord)>, AuthorityStoreError> {
        let mut client = self.client.clone();
        let response = client
            .get(prefix, Some(GetOptions::new().with_prefix()))
            .await
            .map_err(map_etcd_error)?;
        let mut records = Vec::new();
        for kv in response.kvs() {
            let key = String::from_utf8(kv.key().to_vec()).map_err(|_| {
                AuthorityStoreError::Corrupt("etcd key is not valid UTF-8".to_owned())
            })?;
            records.push((
                key,
                StoredRecord {
                    revision: kv.mod_revision().max(0) as u64,
                    value: kv.value().to_vec(),
                },
            ));
        }
        // etcd returns prefix ranges in ascending key order already; keep the
        // contract explicit.
        records.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(records)
    }

    async fn read_snapshot(
        &self,
        reads: &[SnapshotRead],
    ) -> Result<StoreSnapshot, AuthorityStoreError> {
        refuse_unbounded_snapshot(reads)
    }

    async fn execute(&self, txn: StoreTxn) -> Result<StoreTxnOutcome, AuthorityStoreError> {
        if txn.ops.is_empty() {
            return Ok(StoreTxnOutcome::Applied {
                revisions: Vec::new(),
            });
        }
        let mut compares = Vec::with_capacity(txn.ops.len());
        let mut operations = Vec::with_capacity(txn.ops.len());
        let mut first_guarded_key: Option<String> = None;
        for op in &txn.ops {
            match op {
                StoreOp::PutIfAbsent { key, value } => {
                    compares.push(Compare::create_revision(
                        key.as_bytes(),
                        CompareOp::Equal,
                        0,
                    ));
                    operations.push(TxnOp::put(key.as_bytes(), value.clone(), None));
                    if first_guarded_key.is_none() {
                        first_guarded_key = Some(key.clone());
                    }
                }
                StoreOp::ReplaceIfRevision {
                    key,
                    expected_revision,
                    value,
                } => {
                    let Some(guard) = compare_existing_revision(key, *expected_revision) else {
                        return Ok(StoreTxnOutcome::PreconditionFailed { key: key.clone() });
                    };
                    compares.extend(guard);
                    operations.push(TxnOp::put(key.as_bytes(), value.clone(), None));
                    if first_guarded_key.is_none() {
                        first_guarded_key = Some(key.clone());
                    }
                }
                StoreOp::Put { key, value } => {
                    operations.push(TxnOp::put(key.as_bytes(), value.clone(), None));
                }
                StoreOp::Delete { key } => {
                    operations.push(TxnOp::delete(key.as_bytes(), None));
                }
                StoreOp::DeleteIfRevision {
                    key,
                    expected_revision,
                } => {
                    let Some(guard) = compare_existing_revision(key, *expected_revision) else {
                        return Ok(StoreTxnOutcome::PreconditionFailed { key: key.clone() });
                    };
                    compares.extend(guard);
                    operations.push(TxnOp::delete(key.as_bytes(), None));
                    if first_guarded_key.is_none() {
                        first_guarded_key = Some(key.clone());
                    }
                }
                StoreOp::RequireValue { key, value } => {
                    // Compare-only guard: no TxnOp, so the guarded record is
                    // never overwritten and its lease attachment is intact.
                    compares.extend(compare_existing(
                        key,
                        Compare::value(key.as_bytes(), CompareOp::Equal, value.clone()),
                    ));
                    if first_guarded_key.is_none() {
                        first_guarded_key = Some(key.clone());
                    }
                }
                StoreOp::RequireRevision {
                    key,
                    expected_revision,
                } => {
                    // Both compares leave the record and its lease intact.
                    let Some(guard) = compare_existing_revision(key, *expected_revision) else {
                        return Ok(StoreTxnOutcome::PreconditionFailed { key: key.clone() });
                    };
                    compares.extend(guard);
                    if first_guarded_key.is_none() {
                        first_guarded_key = Some(key.clone());
                    }
                }
                StoreOp::RequireAbsent { key } => {
                    compares.push(Compare::create_revision(
                        key.as_bytes(),
                        CompareOp::Equal,
                        0,
                    ));
                    if first_guarded_key.is_none() {
                        first_guarded_key = Some(key.clone());
                    }
                }
            }
        }
        let etcd_txn = Txn::new()
            .when(compares)
            .and_then(operations)
            .or_else(Vec::new());
        let mut client = self.client.clone();
        let response = client.txn(etcd_txn).await.map_err(map_etcd_error)?;
        if !response.succeeded() {
            return Ok(StoreTxnOutcome::PreconditionFailed {
                key: first_guarded_key.unwrap_or_default(),
            });
        }
        let mut revisions = Vec::with_capacity(txn.ops.len());
        for op_response in response.op_responses() {
            let revision = match op_response {
                TxnOpResponse::Put(put) => put.header().map(|header| header.revision()),
                TxnOpResponse::Delete(delete) => delete.header().map(|header| header.revision()),
                _ => None,
            };
            revisions.push(revision.unwrap_or(0).max(0) as u64);
        }
        Ok(StoreTxnOutcome::Applied { revisions })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_guard_contains_an_existence_compare_and_original_compare() {
        let key = "leader";
        for expected in [
            Compare::value(key.as_bytes(), CompareOp::Equal, Vec::new()),
            Compare::mod_revision(key.as_bytes(), CompareOp::Equal, 0),
        ] {
            let comparisons = compare_existing(key, expected.clone());
            assert_eq!(
                format!("{:?}", comparisons[0]),
                format!(
                    "{:?}",
                    Compare::create_revision(key.as_bytes(), CompareOp::Greater, 0)
                )
            );
            assert_eq!(format!("{:?}", comparisons[1]), format!("{expected:?}"));
        }
    }

    #[test]
    fn revision_guards_reject_unsigned_overflow_instead_of_wrapping() {
        assert!(compare_existing_revision("key", 0).is_some());
        assert!(compare_existing_revision("key", i64::MAX as u64).is_some());
        assert!(compare_existing_revision("key", i64::MAX as u64 + 1).is_none());
        assert!(compare_existing_revision("key", u64::MAX).is_none());
    }

    #[test]
    fn snapshot_refuses_before_rpc_without_a_server_byte_budget() {
        for reads in [
            vec![SnapshotRead::Key("frontier".into())],
            vec![
                SnapshotRead::Prefix("scope/".into()),
                SnapshotRead::Prefix("certificate/".into()),
            ],
        ] {
            assert!(matches!(
                refuse_unbounded_snapshot(&reads),
                Err(AuthorityStoreError::Unavailable(_))
            ));
        }
        assert!(matches!(
            refuse_unbounded_snapshot(&[
                SnapshotRead::Prefix("scope/".into()),
                SnapshotRead::Key("scope/a".into()),
            ]),
            Err(AuthorityStoreError::Configuration(_))
        ));
    }
}
