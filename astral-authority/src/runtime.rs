//! Runtime assembly: startup, leader election, and the root-owned
//! `genesis` / `rotate-key` tooling entry points.
//!
//! Startup order is fail-closed:
//! 1. load and validate configuration (mandatory TLS, pin, registrations),
//! 2. connect the etcd quorum store (mandatory TLS for etcd when enabled),
//! 3. verify the genesis signature and rotation chain against the pinned
//!    genesis trust-root digest,
//! 4. construct the protected signer bound to the active trust root,
//! 5. join the leader election; mutations are refused until leadership is
//!    held and are refused again the moment the lease is lost.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, Semaphore};

use astral_types::{
    AuthorityGenesisRecord, AuthorityKeyRotationCertificate, AuthorityRootKey,
    AuthorityRootKeyRole, AuthorityTrustRoot, GlobalAuthorityFrontier,
};

use crate::config::AuthorityServiceConfig;
use crate::error::AuthorityServiceError;
use crate::service::leadership::{leader_key, LeadershipToken, LeadershipTokenRecord};
use crate::service::{AuthorityService, StoredGenesis, StoredTrustRootState};
use crate::signing::ProtectedAuthoritySigner;
use crate::store::etcd::{EtcdAuthorityStore, LEASE_KEEP_ALIVE_TIMEOUT};
use crate::store::AuthorityStore;

#[async_trait::async_trait]
trait ElectionStore: Send + Sync {
    async fn election_lease_grant(
        &self,
        ttl_seconds: i64,
    ) -> Result<i64, crate::error::AuthorityStoreError>;
    async fn election_try_acquire_leader_key(
        &self,
        key: &str,
        lease_id: i64,
        token_value: &[u8],
    ) -> Result<bool, crate::error::AuthorityStoreError>;
    async fn election_lease_keep_alive(
        &self,
        lease_id: i64,
    ) -> Result<bool, crate::error::AuthorityStoreError>;
    async fn election_lease_revoke(
        &self,
        lease_id: i64,
    ) -> Result<(), crate::error::AuthorityStoreError>;
}

#[async_trait::async_trait]
impl ElectionStore for EtcdAuthorityStore {
    async fn election_lease_grant(
        &self,
        ttl_seconds: i64,
    ) -> Result<i64, crate::error::AuthorityStoreError> {
        self.lease_grant(ttl_seconds).await
    }

    async fn election_try_acquire_leader_key(
        &self,
        key: &str,
        lease_id: i64,
        token_value: &[u8],
    ) -> Result<bool, crate::error::AuthorityStoreError> {
        self.try_acquire_leader_key(key, lease_id, token_value)
            .await
    }

    async fn election_lease_keep_alive(
        &self,
        lease_id: i64,
    ) -> Result<bool, crate::error::AuthorityStoreError> {
        self.lease_keep_alive(lease_id).await
    }

    async fn election_lease_revoke(
        &self,
        lease_id: i64,
    ) -> Result<(), crate::error::AuthorityStoreError> {
        self.lease_revoke(lease_id).await
    }
}

/// Load the protected signer from the configured seed source, bound exactly
/// to `trust_root`'s SIGNER-role key. `ProtectedAuthoritySigner::from_seed`
/// verifies the derived verifying key against the trust root, so an
/// arbitrary or placeholder seed can never construct: when no seed source is
/// configured the error is a clear fail-closed refusal, never a fake signer.
/// Shared by the server loader and the root-owned genesis tool.
fn load_signer_from_config(
    config: &AuthorityServiceConfig,
    trust_root: &AuthorityTrustRoot,
) -> Result<ProtectedAuthoritySigner, AuthorityServiceError> {
    if let Some(path) = &config.signer.signing_key_path {
        return ProtectedAuthoritySigner::from_seed_file(
            path,
            &config.signer.expected_signer_key_id,
            trust_root,
        )
        .map_err(AuthorityServiceError::Store);
    }
    if let Some(env_name) = &config.signer.signing_key_env {
        let seed = std::env::var(env_name).map_err(|_| {
            AuthorityServiceError::Store(crate::error::AuthorityStoreError::Configuration(format!(
                "environment variable {env_name} for the signing seed is not set"
            )))
        })?;
        return ProtectedAuthoritySigner::from_seed_hex(
            &seed,
            &config.signer.expected_signer_key_id,
            trust_root,
        )
        .map_err(AuthorityServiceError::Store);
    }
    Err(AuthorityServiceError::Store(
        crate::error::AuthorityStoreError::Configuration("signer seed source missing".to_owned()),
    ))
}

/// Verify the durable genesis record and its pinned trust root before any
/// caller relies on the stored authority identity.
fn verify_stored_genesis(
    config: &AuthorityServiceConfig,
    stored_genesis: &StoredGenesis,
) -> Result<(), AuthorityServiceError> {
    stored_genesis
        .record
        .validate()
        .map_err(AuthorityServiceError::Protocol)?;
    stored_genesis
        .trust_root
        .validate()
        .map_err(AuthorityServiceError::Protocol)?;
    if stored_genesis.record.trust_root_digest != config.identity.pinned_genesis_trust_root_digest
        || stored_genesis.record.trust_root_digest
            != stored_genesis
                .trust_root
                .digest()
                .map_err(AuthorityServiceError::Protocol)?
    {
        return Err(AuthorityServiceError::Protocol(
            astral_types::AuthorityProtocolError::TrustRootMismatch,
        ));
    }
    let genesis_key = stored_genesis
        .trust_root
        .genesis_key()
        .map_err(AuthorityServiceError::Protocol)?
        .verifying_key()
        .map_err(AuthorityServiceError::Protocol)?;
    stored_genesis
        .record
        .verify(&stored_genesis.trust_root, &genesis_key)
        .map_err(AuthorityServiceError::Protocol)?;
    if stored_genesis.record.authority_id != config.identity.authority_id {
        return Err(AuthorityServiceError::Protocol(
            astral_types::AuthorityProtocolError::CallerIdentityMismatch,
        ));
    }
    Ok(())
}

/// Verify the durable trust chain against the configuration pin and build
/// the signer. Shared by the server and the CLI tools.
pub async fn load_trust_root_and_signer(
    config: &AuthorityServiceConfig,
    store: &Arc<dyn AuthorityStore>,
) -> Result<
    (
        AuthorityTrustRoot,
        GlobalAuthorityFrontier,
        Arc<ProtectedAuthoritySigner>,
    ),
    AuthorityServiceError,
> {
    let keys = crate::store::KeyLayout::new(&config.quorum.key_prefix);
    let genesis_record = store
        .get(&keys.genesis())
        .await
        .map_err(AuthorityServiceError::Store)?
        .ok_or_else(|| {
            AuthorityServiceError::Store(crate::error::AuthorityStoreError::Corrupt(
                "genesis record missing; run the root-owned genesis tool".to_owned(),
            ))
        })?;
    let stored_genesis: StoredGenesis =
        serde_json::from_slice(&genesis_record.value).map_err(|_| {
            AuthorityServiceError::Store(crate::error::AuthorityStoreError::Corrupt(
                "genesis record".to_owned(),
            ))
        })?;
    verify_stored_genesis(config, &stored_genesis)?;
    let root_record = store
        .get(&keys.trust_root())
        .await
        .map_err(AuthorityServiceError::Store)?
        .ok_or_else(|| {
            AuthorityServiceError::Store(crate::error::AuthorityStoreError::Corrupt(
                "trust root state missing".to_owned(),
            ))
        })?;
    let root_state: StoredTrustRootState =
        serde_json::from_slice(&root_record.value).map_err(|_| {
            AuthorityServiceError::Store(crate::error::AuthorityStoreError::Corrupt(
                "trust root state".to_owned(),
            ))
        })?;
    if root_state.genesis_trust_root_digest != stored_genesis.record.trust_root_digest
        || root_state.root_id != stored_genesis.record.root_id
    {
        return Err(AuthorityServiceError::Protocol(
            astral_types::AuthorityProtocolError::TrustRootMismatch,
        ));
    }
    let mut active = stored_genesis.trust_root.clone();
    for rotation in &root_state.rotations {
        if rotation.authority_id != config.identity.authority_id {
            return Err(AuthorityServiceError::Protocol(
                astral_types::AuthorityProtocolError::CallerIdentityMismatch,
            ));
        }
        let root_key = active
            .root_key()
            .map_err(AuthorityServiceError::Protocol)?
            .verifying_key()
            .map_err(AuthorityServiceError::Protocol)?;
        active = rotation
            .verify_after(&active, &root_key)
            .map_err(AuthorityServiceError::Protocol)?;
    }
    if root_state.active != active {
        return Err(AuthorityServiceError::Protocol(
            astral_types::AuthorityProtocolError::TrustRootMismatch,
        ));
    }
    let frontier_record = store
        .get(&keys.frontier())
        .await
        .map_err(AuthorityServiceError::Store)?
        .ok_or_else(|| {
            AuthorityServiceError::Store(crate::error::AuthorityStoreError::Corrupt(
                "global frontier missing".to_owned(),
            ))
        })?;
    let frontier: GlobalAuthorityFrontier = serde_json::from_slice(&frontier_record.value)
        .map_err(|_| {
            AuthorityServiceError::Store(crate::error::AuthorityStoreError::Corrupt(
                "global frontier".to_owned(),
            ))
        })?;
    frontier
        .matches_trust_root(&active)
        .map_err(AuthorityServiceError::Protocol)?;
    if frontier.authority_id != config.identity.authority_id {
        return Err(AuthorityServiceError::Protocol(
            astral_types::AuthorityProtocolError::CallerIdentityMismatch,
        ));
    }

    // Protected signer: seed from file or env, bound exactly to the active
    // root's SIGNER-role key.
    let signer = load_signer_from_config(config, &active)?;
    Ok((active, frontier, Arc::new(signer)))
}

/// Run the authority server. Never returns Ok; serves until stopped.
pub async fn run_serve(config: AuthorityServiceConfig) -> Result<(), String> {
    config
        .validate()
        .map_err(|error| format!("configuration: {error}"))?;
    let store = Arc::new(
        EtcdAuthorityStore::connect(
            &config.quorum.endpoints,
            config.quorum.tls_enabled,
            config.quorum.tls_ca_path.as_deref(),
            config.quorum.tls_client_cert_path.as_deref(),
            config.quorum.tls_client_key_path.as_deref(),
            config.quorum.tls_domain_name.as_deref(),
        )
        .await
        .map_err(|error| format!("quorum store: {error}"))?,
    );
    let dyn_store: Arc<dyn AuthorityStore> = store.clone();
    let (_trust_root, _frontier, signer) = load_trust_root_and_signer(&config, &dyn_store)
        .await
        .map_err(|error| format!("trust chain: {error}"))?;
    let service = Arc::new(AuthorityService::new(
        config.clone(),
        Arc::clone(&store) as Arc<dyn AuthorityStore>,
        signer,
    ));

    let tls_acceptor = crate::http::build_tls_acceptor(
        &config.listener.server_cert_path,
        &config.listener.server_key_path,
        &config.listener.client_ca_path,
    )
    .map_err(|error| format!("TLS: {error}"))?;
    let connection_limit = Arc::new(Semaphore::new(config.listener.max_concurrent_signing));
    let (election_shutdown, election_shutdown_rx) = watch::channel(false);
    let election = run_election_task(
        Arc::clone(&service),
        Arc::clone(&store),
        leader_key(&config.quorum.key_prefix, &config.quorum.authority_name),
        uuid::Uuid::new_v4().simple().to_string(),
        config.quorum.lease_ttl_seconds.max(5),
        election_shutdown_rx,
    );
    tokio::pin!(election);
    let serve_result = tokio::select! {
        result = crate::http::serve(
            Arc::clone(&service),
            &config.listener.bind_address,
            tls_acceptor,
            Duration::from_secs(config.listener.request_timeout_seconds),
            connection_limit,
        ) => result,
        () = &mut election => {
            return Err("authority election stopped while the listener was serving".to_owned());
        }
    };

    let _ = election_shutdown.send(true);
    if tokio::time::timeout(Duration::from_secs(5), &mut election)
        .await
        .is_err()
    {
        tracing::warn!("authority election did not drain in time; dropping its owned future");
    }
    serve_result
}

struct ElectionOwnership<'a>(&'a AuthorityService);

impl Drop for ElectionOwnership<'_> {
    fn drop(&mut self) {
        lose_leadership(self.0);
    }
}

/// Owned election loop. Cancellation revokes the local fence through its guard;
/// the lease TTL bounds a term whose quorum revoke cannot finish.
async fn run_election_task<S: ElectionStore + 'static>(
    service: Arc<AuthorityService>,
    store: Arc<S>,
    leader_key: String,
    instance_id: String,
    lease_ttl: i64,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let _ownership = ElectionOwnership(&service);
    loop {
        if *shutdown.borrow() {
            break;
        }
        let pause = match run_election_cycle(
            &service,
            store.as_ref(),
            &leader_key,
            &instance_id,
            lease_ttl,
            &mut shutdown,
        )
        .await
        {
            Ok(()) => {
                // Lost cleanly or drained on shutdown; acquire again after a
                // short pause (the outer check exits immediately on shutdown).
                Duration::from_secs(2)
            }
            Err(error) => {
                tracing::warn!(%error, "authority election cycle failed; retrying after pause");
                Duration::from_secs(5)
            }
        };
        lose_leadership(&service);
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _ = tokio::time::sleep(pause) => {}
            _ = shutdown.changed() => break,
        }
    }
    lose_leadership(&service);
}

/// Liveness drop: clear the flag (a hint only) and revoke the local term.
/// Idempotent; the durable fence stays authoritative either way.
fn lose_leadership(service: &AuthorityService) {
    service
        .leader_flag()
        .store(false, std::sync::atomic::Ordering::Release);
    service.leadership().revoke();
}

/// One election cycle: grant a lease, CAS-acquire the leader key with the
/// exact term token, bind the verified leadership to the service, then keep
/// the lease alive until it is lost or shutdown is requested. Shutdown
/// drains by revoking the lease (the leader key disappears immediately).
async fn run_election_cycle<S: ElectionStore>(
    service: &AuthorityService,
    store: &S,
    leader_key: &str,
    instance_id: &str,
    lease_ttl: i64,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    let authority_name = &service.config().quorum.authority_name;
    let lease_id = store
        .election_lease_grant(lease_ttl)
        .await
        .map_err(|error| format!("lease grant: {error}"))?;
    let result = async {
        let token = LeadershipToken::from_record(
            leader_key.to_owned(),
            &LeadershipTokenRecord::new(authority_name, instance_id, lease_id),
        )
        .map_err(|error| format!("leadership token: {error}"))?;

        let mut acquired = false;
        for _ in 0..3 {
            if *shutdown.borrow() {
                return Ok(());
            }
            if store
                .election_try_acquire_leader_key(token.key(), lease_id, token.value())
                .await
                .map_err(|error| format!("leader key CAS: {error}"))?
            {
                acquired = true;
                break;
            }
            let wait = Duration::from_secs((lease_ttl as u64 / 2).max(1));
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                _ = shutdown.changed() => return Ok(()),
            }
        }
        if !acquired {
            return Err("leader key is held by another instance".to_owned());
        }
        service
            .bind_leadership_token(&token)
            .await
            .map_err(|error| format!("leadership bind: {error}"))?;
        tracing::info!(instance = %instance_id, lease = lease_id, "authority leadership acquired");

        let interval = Duration::from_secs((lease_ttl as u64 / 3).max(1));
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown.changed() => return Ok(()),
            }
            match tokio::time::timeout(
                LEASE_KEEP_ALIVE_TIMEOUT,
                store.election_lease_keep_alive(lease_id),
            )
            .await
            {
                Ok(Ok(true)) => continue,
                Ok(Ok(false)) => return Err("lease expired; leadership lost".to_owned()),
                Ok(Err(error)) => return Err(format!("keep alive: {error}")),
                Err(_) => return Err("keep alive timed out; leadership lost".to_owned()),
            }
        }
    }
    .await;
    lose_leadership(service);
    match tokio::time::timeout(
        Duration::from_secs(3),
        store.election_lease_revoke(lease_id),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            tracing::warn!(lease = lease_id, %error, "lease cleanup failed; TTL bounds ownership")
        }
        Err(_) => tracing::warn!(
            lease = lease_id,
            "lease cleanup timed out; TTL bounds ownership"
        ),
    }
    result
}

/// Root-owned genesis tool: create the explicitly signed genesis record.
///
/// `trust_root` is the operator-provided key set; `genesis_signing_key` must
/// be the GENESIS-role key of that set. Returns true when created.
pub async fn run_genesis(
    config: AuthorityServiceConfig,
    trust_root: AuthorityTrustRoot,
    genesis_signing_key: &ed25519_dalek::SigningKey,
) -> Result<bool, String> {
    config
        .validate()
        .map_err(|error| format!("configuration: {error}"))?;
    let store = Arc::new(
        EtcdAuthorityStore::connect(
            &config.quorum.endpoints,
            config.quorum.tls_enabled,
            config.quorum.tls_ca_path.as_deref(),
            config.quorum.tls_client_cert_path.as_deref(),
            config.quorum.tls_client_key_path.as_deref(),
            config.quorum.tls_domain_name.as_deref(),
        )
        .await
        .map_err(|error| format!("quorum store: {error}"))?,
    );
    let genesis_key_entry = trust_root
        .genesis_key()
        .map_err(|error| format!("trust root: {error}"))?;
    let genesis_verifying = genesis_key_entry
        .verifying_key()
        .map_err(|error| format!("genesis key: {error}"))?;
    if genesis_verifying != genesis_signing_key.verifying_key() {
        return Err("genesis signing key does not match the trust root genesis key".to_owned());
    }
    let trust_root_digest = trust_root
        .digest()
        .map_err(|error| format!("trust root digest: {error}"))?;
    if trust_root_digest != config.identity.pinned_genesis_trust_root_digest {
        return Err(format!(
            "trust root digest {trust_root_digest} does not match the configuration pin"
        ));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0);
    let mut record = AuthorityGenesisRecord {
        authorization_edition: astral_types::AUTHORIZATION_EDITION,
        authority_id: config.identity.authority_id.clone(),
        root_id: trust_root.root_id.clone(),
        trust_root_digest: trust_root_digest.clone(),
        created_at: now,
        genesis_nonce: uuid::Uuid::new_v4().simple().to_string(),
        signed_by_key_id: String::new(),
        signature: String::new(),
    };
    record
        .sign(genesis_signing_key, &genesis_key_entry.key_id)
        .map_err(|error| format!("sign genesis: {error}"))?;
    let genesis = StoredGenesis { record, trust_root };
    let keys = crate::store::KeyLayout::new(&config.quorum.key_prefix);
    // Genesis constructs the service with the REAL signer bound to the root
    // being blessed. `from_seed` verifies the derived verifying key against
    // the SIGNER-role entry, so the former [0; 32] placeholder could never
    // construct and made every genesis run fail before the durable write;
    // the seed source is mandatory here (config.validate enforces one). The
    // signer still never signs genesis artifacts — the construction is what
    // must be honest.
    let signer = Arc::new(
        load_signer_from_config(&config, &genesis.trust_root)
            .map_err(|error| format!("signer bind: {error}"))?,
    );
    let service = AuthorityService::new(
        config,
        Arc::clone(&store) as Arc<dyn AuthorityStore>,
        signer,
    );
    let created = service
        .initialize_genesis(&genesis)
        .await
        .map_err(|error| format!("initialize genesis: {error}"))?;
    let _ = keys;
    Ok(created)
}

/// Wall-clock seconds used once per tool invocation so every stamped field
/// comes from the same clock read.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0)
}

/// Pure rotation precheck and fold, shared with
/// `AuthorityKeyRotationCertificate::verify_after` (which the service re-runs
/// against durable state):
/// - only a SIGNER-role key may be installed by a rotation,
/// - the new signer epoch must STRICTLY exceed the previous ACTIVE signer
///   epoch (no rollback, no ties), not merely the root authorizer epoch,
/// - the new key id must be fresh across the entire chain history,
/// - the fold retains the FULL previous key set: history is never erased and
///   previously issued durable artifacts stay verifiable,
/// - one `now` stamps both the folded next root and the certificate, so
///   `next_root.created_at` and `certificate.issued_at` can never straddle a
///   second boundary.
///
/// `previous_key_epoch` keeps its wire meaning: the ROOT authorizer epoch.
fn prepare_rotation_certificate(
    active: &AuthorityTrustRoot,
    new_key: &AuthorityRootKey,
    authority_id: &str,
    now: i64,
) -> Result<(AuthorityTrustRoot, AuthorityKeyRotationCertificate), String> {
    if new_key.role != AuthorityRootKeyRole::Signer {
        return Err("rotation must replace the SIGNER-role key".to_owned());
    }
    let active_signer_epoch = active
        .signer_key()
        .map_err(|error| format!("trust root: {error}"))?
        .key_epoch;
    if new_key.key_epoch <= active_signer_epoch {
        return Err(format!(
            "rotation key epoch {} must be strictly greater than the active signer epoch {active_signer_epoch}",
            new_key.key_epoch
        ));
    }
    if active.key_by_id(&new_key.key_id).is_some() {
        return Err(format!(
            "rotation key id {} already exists in the trust root chain",
            new_key.key_id
        ));
    }
    // Full-history fold: every previous key is retained; signer_key() then
    // selects the new highest-epoch signer as the active key.
    let mut keys = active.keys.clone();
    keys.push(new_key.clone());
    let next_root = AuthorityTrustRoot {
        root_id: active.root_id.clone(),
        keys,
        created_at: now,
    };
    next_root
        .validate()
        .map_err(|error| format!("folded trust root: {error}"))?;
    let certificate = AuthorityKeyRotationCertificate {
        authorization_edition: astral_types::AUTHORIZATION_EDITION,
        authority_id: authority_id.to_owned(),
        root_id: active.root_id.clone(),
        previous_key_epoch: active
            .root_key()
            .map_err(|error| format!("trust root: {error}"))?
            .key_epoch,
        new_key: new_key.clone(),
        previous_trust_root_digest: active
            .digest()
            .map_err(|error| format!("active root digest: {error}"))?,
        new_trust_root_digest: next_root
            .digest()
            .map_err(|error| format!("next root digest: {error}"))?,
        rotation_nonce: uuid::Uuid::new_v4().simple().to_string(),
        issued_at: now,
        not_before: now,
        expires_at: now + 600,
        signed_by_key_id: String::new(),
        signature: String::new(),
    };
    Ok((next_root, certificate))
}

/// Root-owned key rotation tool: sign and apply one rotation certificate.
pub async fn run_rotate_key(
    config: AuthorityServiceConfig,
    new_key: AuthorityRootKey,
    root_signing_key: &ed25519_dalek::SigningKey,
    new_signer_seed: [u8; 32],
) -> Result<(), String> {
    config
        .validate()
        .map_err(|error| format!("configuration: {error}"))?;
    let store = Arc::new(
        EtcdAuthorityStore::connect(
            &config.quorum.endpoints,
            config.quorum.tls_enabled,
            config.quorum.tls_ca_path.as_deref(),
            config.quorum.tls_client_cert_path.as_deref(),
            config.quorum.tls_client_key_path.as_deref(),
            config.quorum.tls_domain_name.as_deref(),
        )
        .await
        .map_err(|error| format!("quorum store: {error}"))?,
    );
    let dyn_store: Arc<dyn AuthorityStore> = store.clone();
    let (active, _frontier, signer) = load_trust_root_and_signer(&config, &dyn_store)
        .await
        .map_err(|error| format!("trust chain: {error}"))?;
    let root_entry = active
        .root_key()
        .map_err(|error| format!("trust root: {error}"))?;
    if root_entry.verifying_key().map_err(|e| e.to_string())? != root_signing_key.verifying_key() {
        return Err("root signing key does not match the active trust root".to_owned());
    }
    // One clock read stamps the folded root and the whole certificate.
    let now = now_unix();
    let (next_root, mut certificate) =
        prepare_rotation_certificate(&active, &new_key, &config.identity.authority_id, now)?;
    certificate
        .sign(root_signing_key, &root_entry.key_id)
        .map_err(|error| format!("sign rotation: {error}"))?;

    let new_signer = Arc::new(
        ProtectedAuthoritySigner::from_seed(new_signer_seed, &new_key.key_id, &next_root)
            .map_err(|error| format!("bind new signer: {error}"))?,
    );
    // The service is constructed with the verified ACTIVE signer loaded and
    // bound above. A placeholder seed can never bind to the trust root
    // (`from_seed` verifies the derived verifying key), so discarding the
    // loaded signer here made every rotation fail before it could apply.
    let ttl_seconds = config.quorum.lease_ttl_seconds;
    let deadline_seconds = ttl_seconds.saturating_sub(1).min(30);
    let service = AuthorityService::new(
        config,
        Arc::clone(&store) as Arc<dyn AuthorityStore>,
        Arc::clone(&signer),
    );
    let budget = Duration::from_secs(deadline_seconds.max(0) as u64);
    let instance = format!("rotate-key:{}", certificate.rotation_nonce);
    let (leadership, elapsed) = crate::service::leadership::EphemeralLeadership::acquire(
        &service,
        &store,
        &instance,
        ttl_seconds,
        deadline_seconds,
        budget.min(Duration::from_secs(5)),
    )
    .await
    .map_err(|error| format!("rotation leadership: {error}"))?;
    let remaining = budget.saturating_sub(elapsed);
    let outcome = match tokio::time::timeout(
        remaining,
        service.apply_rotation(&certificate, new_signer),
    )
    .await
    {
        Ok(result) => result.map_err(|error| {
            format!(
                "apply rotation {}: {error}; reconcile this exact rotation nonce before any new attempt",
                certificate.rotation_nonce
            )
        }),
        Err(_) => Err(format!(
            "rotation {} outcome UNKNOWN after deadline; reconcile this exact rotation nonce before any new attempt",
            certificate.rotation_nonce
        )),
    };
    let released = leadership.release().await;
    match (outcome, released) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(format!(
            "rotation {} applied; leadership release unconfirmed: {error}",
            certificate.rotation_nonce
        )),
        (Err(error), Err(release_error)) => Err(format!(
            "{error}; leadership release unconfirmed: {release_error}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::service::{AuthorityService, StoredGenesis};
    use crate::signing::ProtectedAuthoritySigner;
    use crate::store::memory::MemoryAuthorityStore;
    use crate::store::AuthorityStore;
    use astral_types::AuthorityProtocolError;

    #[async_trait::async_trait]
    impl ElectionStore for MemoryAuthorityStore {
        async fn election_lease_grant(
            &self,
            ttl_seconds: i64,
        ) -> Result<i64, crate::error::AuthorityStoreError> {
            Ok(self.grant_lease(ttl_seconds))
        }

        async fn election_try_acquire_leader_key(
            &self,
            key: &str,
            lease_id: i64,
            token_value: &[u8],
        ) -> Result<bool, crate::error::AuthorityStoreError> {
            Ok(self.try_acquire_leader_key(key, lease_id, token_value))
        }

        async fn election_lease_keep_alive(
            &self,
            lease_id: i64,
        ) -> Result<bool, crate::error::AuthorityStoreError> {
            Ok(self.lease_keep_alive(lease_id))
        }

        async fn election_lease_revoke(
            &self,
            lease_id: i64,
        ) -> Result<(), crate::error::AuthorityStoreError> {
            self.expire_lease(lease_id);
            Ok(())
        }
    }

    fn test_service(store: Arc<MemoryAuthorityStore>) -> Arc<AuthorityService> {
        let seed = [0x42; 32];
        let root = root_with_real_signer(seed);
        let signer = Arc::new(
            ProtectedAuthoritySigner::from_seed(seed, "signer-1", &root)
                .expect("fixture signer binds to root"),
        );
        Arc::new(AuthorityService::new(
            AuthorityServiceConfig::default(),
            store as Arc<dyn AuthorityStore>,
            signer,
        ))
    }

    #[tokio::test]
    async fn election_shutdown_awaits_lease_revoke_and_clears_local_ownership() {
        let store = Arc::new(MemoryAuthorityStore::new());
        let service = test_service(Arc::clone(&store));
        let leader = leader_key(
            &service.config().quorum.key_prefix,
            &service.config().quorum.authority_name,
        );
        let (shutdown, receiver) = watch::channel(false);
        let task = tokio::spawn(run_election_task(
            Arc::clone(&service),
            Arc::clone(&store),
            leader.clone(),
            "runtime-shutdown-test".to_owned(),
            15,
            receiver,
        ));

        tokio::time::timeout(Duration::from_secs(2), async {
            while !service.is_leader() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("election must bind a real memory-store lease term");
        assert!(service.leadership().current().is_some());
        assert!(store.get(&leader).await.unwrap().is_some());

        shutdown.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("election task must drain")
            .unwrap();

        assert!(!service.is_leader());
        assert!(service.leadership().current().is_none());
        assert!(store.get(&leader).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn election_cancellation_drops_local_fence_without_detached_revoke() {
        let store = Arc::new(MemoryAuthorityStore::new());
        let service = test_service(Arc::clone(&store));
        let leader = leader_key(
            &service.config().quorum.key_prefix,
            &service.config().quorum.authority_name,
        );
        let (_shutdown, receiver) = watch::channel(false);
        let task = tokio::spawn(run_election_task(
            Arc::clone(&service),
            Arc::clone(&store),
            leader.clone(),
            "runtime-cancel-test".to_owned(),
            15,
            receiver,
        ));

        tokio::time::timeout(Duration::from_secs(2), async {
            while !service.is_leader() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("election must bind a real memory-store lease term");
        task.abort();
        let _ = task.await;

        assert!(
            !service.is_leader(),
            "cancel guard clears the liveness hint"
        );
        assert!(
            service.leadership().current().is_none(),
            "cancel guard revokes local term"
        );
        let durable = store
            .get(&leader)
            .await
            .unwrap()
            .expect("lease remains until revoke/TTL");
        let token = LeadershipTokenRecord::decode(&durable.value).expect("stored lease token");
        assert!(store.expire_lease(token.lease));
        assert!(store.get(&leader).await.unwrap().is_none());
    }

    #[test]
    fn startup_genesis_verification_checks_pin_signature_and_identity() {
        let root = genesis_root();
        let digest = root.digest().unwrap();
        let mut record = AuthorityGenesisRecord {
            authorization_edition: astral_types::AUTHORIZATION_EDITION,
            authority_id: "astral-authority-1".to_owned(),
            root_id: root.root_id.clone(),
            trust_root_digest: digest.clone(),
            created_at: 1_010,
            genesis_nonce: "genesis-test-nonce".to_owned(),
            signed_by_key_id: String::new(),
            signature: String::new(),
        };
        record
            .sign(
                &ed25519_dalek::SigningKey::from_bytes(&[3; 32]),
                "genesis-1",
            )
            .unwrap();
        let stored = StoredGenesis {
            record: record.clone(),
            trust_root: root,
        };
        let config = AuthorityServiceConfig {
            identity: crate::config::AuthorityIdentityConfig {
                authority_id: "astral-authority-1".to_owned(),
                pinned_genesis_trust_root_digest: digest,
            },
            ..Default::default()
        };
        assert!(verify_stored_genesis(&config, &stored).is_ok());

        let mut invalid_signature = stored.clone();
        let first = invalid_signature.record.signature.remove(0);
        invalid_signature
            .record
            .signature
            .insert(0, if first == '0' { '1' } else { '0' });
        assert!(verify_stored_genesis(&config, &invalid_signature).is_err());

        let mut wrong_identity = stored.clone();
        wrong_identity.record.authority_id = "other-authority".to_owned();
        wrong_identity
            .record
            .sign(
                &ed25519_dalek::SigningKey::from_bytes(&[3; 32]),
                "genesis-1",
            )
            .unwrap();
        assert!(verify_stored_genesis(&config, &wrong_identity).is_err());

        let wrong_pin = AuthorityServiceConfig {
            identity: crate::config::AuthorityIdentityConfig {
                authority_id: config.identity.authority_id.clone(),
                pinned_genesis_trust_root_digest: "0".repeat(64),
            },
            ..Default::default()
        };
        assert!(verify_stored_genesis(&wrong_pin, &stored).is_err());
    }

    fn key(seed: u8, key_id: &str, epoch: u64, role: AuthorityRootKeyRole) -> AuthorityRootKey {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        AuthorityRootKey {
            key_id: key_id.to_owned(),
            key_epoch: epoch,
            role,
            verifying_key_hex: hex::encode(signing.verifying_key().as_bytes()),
        }
    }

    fn genesis_root() -> AuthorityTrustRoot {
        AuthorityTrustRoot {
            root_id: "root-1".to_owned(),
            keys: vec![
                key(1, "signer-1", 1, AuthorityRootKeyRole::Signer),
                key(2, "root-1", 1, AuthorityRootKeyRole::Root),
                key(3, "genesis-1", 1, AuthorityRootKeyRole::Genesis),
            ],
            created_at: 1_000,
        }
    }

    /// A chain whose signer already rotated to epoch 3 while the root
    /// authorizer epoch stayed at 1: exactly the shape where comparing the
    /// new epoch against the root epoch alone would accept a rollback.
    fn chain_with_signer_epoch_3() -> AuthorityTrustRoot {
        AuthorityTrustRoot {
            root_id: "root-1".to_owned(),
            keys: vec![
                key(1, "signer-1", 1, AuthorityRootKeyRole::Signer),
                key(5, "signer-3", 3, AuthorityRootKeyRole::Signer),
                key(2, "root-1", 1, AuthorityRootKeyRole::Root),
                key(3, "genesis-1", 1, AuthorityRootKeyRole::Genesis),
            ],
            created_at: 1_000,
        }
    }

    #[test]
    fn prepared_rotations_chain_twice_and_match_verify_after() {
        let genesis = genesis_root();
        let root_signing = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
        let mut active = genesis.clone();
        for (now, (key_id, seed, epoch)) in
            (5_000i64..).zip([("signer-2", 4u8, 2u64), ("signer-3", 5u8, 3u64)])
        {
            let new_key = key(seed, key_id, epoch, AuthorityRootKeyRole::Signer);
            let (next_root, mut certificate) =
                prepare_rotation_certificate(&active, &new_key, "authority-1", now).unwrap();
            // One clock read stamps the folded root and the whole
            // certificate identically, even when rotations straddle seconds.
            assert_eq!(next_root.created_at, now);
            assert_eq!(certificate.issued_at, now);
            assert_eq!(certificate.not_before, now);
            // previous_key_epoch keeps its wire meaning: the ROOT epoch.
            assert_eq!(
                certificate.previous_key_epoch,
                active.root_key().unwrap().key_epoch
            );
            certificate.sign(&root_signing, "root-1").unwrap();
            let verified = certificate
                .verify_after(
                    &active,
                    &active.root_key().unwrap().verifying_key().unwrap(),
                )
                .unwrap();
            assert_eq!(
                verified, next_root,
                "runtime fold must equal the protocol fold"
            );
            assert_eq!(verified.signer_key().unwrap().key_id, key_id);
            active = verified;
        }
        // Both rotations retain the full history; root/genesis survive.
        for retained in ["signer-1", "signer-2", "signer-3"] {
            assert!(active.key_by_id(retained).is_some());
        }
        assert_eq!(active.root_key().unwrap(), genesis.root_key().unwrap());
        assert_eq!(
            active.genesis_key().unwrap(),
            genesis.genesis_key().unwrap()
        );
    }

    #[test]
    fn prepared_rotation_rejects_rollback_reuse_and_role() {
        let active = chain_with_signer_epoch_3();

        // Rollback: epoch 2 is unused but below the active signer epoch 3.
        let rollback = key(9, "signer-2", 2, AuthorityRootKeyRole::Signer);
        let error =
            prepare_rotation_certificate(&active, &rollback, "authority-1", 2_000).unwrap_err();
        assert!(error.contains("strictly greater than the active signer epoch 3"));

        // Key-id reuse across the whole chain history is refused.
        let reused = key(9, "signer-1", 4, AuthorityRootKeyRole::Signer);
        let error =
            prepare_rotation_certificate(&active, &reused, "authority-1", 2_000).unwrap_err();
        assert!(error.contains("already exists"));

        // Only SIGNER-role keys may be installed by a rotation.
        let root_role = key(9, "root-2", 4, AuthorityRootKeyRole::Root);
        let error =
            prepare_rotation_certificate(&active, &root_role, "authority-1", 2_000).unwrap_err();
        assert!(error.contains("SIGNER-role key"));

        // Protocol-side backstop: the same rollback with a properly signed,
        // digest-consistent certificate is refused by verify_after too.
        let root_signing = ed25519_dalek::SigningKey::from_bytes(&[2; 32]);
        let mut keys = active.keys.clone();
        keys.push(key(9, "signer-2", 2, AuthorityRootKeyRole::Signer));
        let folded = AuthorityTrustRoot {
            root_id: active.root_id.clone(),
            keys,
            created_at: 2_000,
        };
        let mut certificate = AuthorityKeyRotationCertificate {
            authorization_edition: astral_types::AUTHORIZATION_EDITION,
            authority_id: "authority-1".to_owned(),
            root_id: active.root_id.clone(),
            previous_key_epoch: 1,
            new_key: key(9, "signer-2", 2, AuthorityRootKeyRole::Signer),
            previous_trust_root_digest: active.digest().unwrap(),
            new_trust_root_digest: folded.digest().unwrap(),
            rotation_nonce: "nonce".to_owned(),
            issued_at: 2_000,
            not_before: 2_000,
            expires_at: 2_600,
            signed_by_key_id: String::new(),
            signature: String::new(),
        };
        certificate.sign(&root_signing, "root-1").unwrap();
        assert!(matches!(
            certificate.verify_after(
                &active,
                &active.root_key().unwrap().verifying_key().unwrap()
            ),
            Err(AuthorityProtocolError::KeyEpochNonMonotonic)
        ));
    }

    /// Write a run-scoped 0600 signer seed file; the caller removes it.
    fn write_signer_seed_file(seed: [u8; 32]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "astral-authority-rotation-test-{}.seed",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::write(&path, seed).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    /// A genesis-style trust root whose SIGNER entry carries the verifying
    /// key of the given real seed.
    fn root_with_real_signer(signer_seed: [u8; 32]) -> AuthorityTrustRoot {
        let signing = ed25519_dalek::SigningKey::from_bytes(&signer_seed);
        AuthorityTrustRoot {
            root_id: "root-1".to_owned(),
            keys: vec![
                AuthorityRootKey {
                    key_id: "signer-1".to_owned(),
                    key_epoch: 1,
                    role: AuthorityRootKeyRole::Signer,
                    verifying_key_hex: hex::encode(signing.verifying_key().as_bytes()),
                },
                key(2, "root-1", 1, AuthorityRootKeyRole::Root),
                key(3, "genesis-1", 1, AuthorityRootKeyRole::Genesis),
            ],
            created_at: 1_000,
        }
    }

    #[test]
    fn genesis_signer_load_binds_the_signed_trust_root_exactly() {
        let signer_seed = [0xA5u8; 32];
        let trust_root = root_with_real_signer(signer_seed);
        let path = write_signer_seed_file(signer_seed);
        let config = AuthorityServiceConfig {
            signer: crate::config::AuthoritySignerConfig {
                signing_key_path: Some(path.clone()),
                signing_key_env: None,
                expected_signer_key_id: "signer-1".to_owned(),
            },
            ..Default::default()
        };
        // The real production construction path: the signer loaded from the
        // configured seed source binds exactly to the blessed root's SIGNER
        // entry (id and verifying key), so the service construction is honest.
        let signer = load_signer_from_config(&config, &trust_root).unwrap();
        assert!(signer.matches_trust_root(&trust_root).unwrap());
        assert_eq!(signer.key_id(), "signer-1");
        assert_eq!(signer.key_epoch(), 1);

        // Regression: the former placeholder construction (all-zero seed
        // bound to the signer entry) can never build, because from_seed
        // verifies the derived verifying key against the trust root.
        assert!(ProtectedAuthoritySigner::from_seed([0u8; 32], "signer-1", &trust_root).is_err());

        // Signer ownership is exact: a wrong expected key id and a foreign
        // seed are both refused; nothing is silently substituted.
        let mut wrong_id = config.clone();
        wrong_id.signer.expected_signer_key_id = "signer-2".to_owned();
        assert!(load_signer_from_config(&wrong_id, &trust_root).is_err());
        let foreign_path = write_signer_seed_file([0x11u8; 32]);
        let mut foreign = config.clone();
        foreign.signer.signing_key_path = Some(foreign_path.clone());
        assert!(load_signer_from_config(&foreign, &trust_root).is_err());

        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(&foreign_path).unwrap();
    }

    #[test]
    fn signer_seed_source_rules_fail_closed() {
        let signer_seed = [0xA7u8; 32];
        let trust_root = root_with_real_signer(signer_seed);

        // No configured source: clear configuration refusal, never a fake.
        assert!(load_signer_from_config(&AuthorityServiceConfig::default(), &trust_root).is_err());

        // Env source: an unset variable errors before any signer exists.
        let env_name = format!(
            "ASTRAL_AUTHORITY_TEST_SIGNER_SEED_{}",
            uuid::Uuid::new_v4().simple()
        );
        let mut env_config = AuthorityServiceConfig::default();
        env_config.signer.signing_key_env = Some(env_name.clone());
        env_config.signer.expected_signer_key_id = "signer-1".to_owned();
        assert!(load_signer_from_config(&env_config, &trust_root).is_err());
        // A set variable binds the real signer exactly like the file source.
        std::env::set_var(&env_name, hex::encode(signer_seed));
        let signer = load_signer_from_config(&env_config, &trust_root).unwrap();
        assert!(signer.matches_trust_root(&trust_root).unwrap());
        std::env::remove_var(&env_name);
    }
}
