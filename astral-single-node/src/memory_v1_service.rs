//! memory—v1: the unified loopback-only single-node service.
//!
//! Production admission precedes listener binding. A cold capture and a locally
//! verified journal do not supply independent authorization or recovery facts;
//! missing evidence stops startup rather than selecting a weaker grade.

use std::future::{Future, IntoFuture};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use std::collections::{BTreeMap, BTreeSet};

use astral_authorization_root::memory_v1_adoption::{
    startup::AuthenticatedStartupEvidence, AdoptionLimit, ColdLoadFacts,
};
use astral_authorization_root::memory_v1_db_rows::CandidateRows;
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_root::{
    install_process_root_with_headroom, RootHandle, RootOwner,
};
use astral_common::config::{AppConfig, JwtValidationRole, MessageTransport};
use astral_db::memory_v1_candidate_loader::UnverifiedCandidateRows;
use astral_identity::memory_v1_service::{memory_v1_auth_router, MemoryV1FileCredentials};
use astral_identity::runtime::memory_v1::MemoryV1CredentialAuthenticator;
use astral_single_node::memory_v1_cold_install::{ColdInstallError, ReconciledColdInstall};
use astral_trustgraph::{build_memory_v1_offline_app_state, build_router, RouterIntegrationConfig};
use astral_types::memory_v1::MemoryId;
use astral_types::memory_v1_journal::JournalAnchor;
use axum::Router;
use policy_engine::PolicyEngine;
use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions, MySqlSslMode};
use tokio::net::TcpListener;

use crate::memory_v1_composition::{require_serving_root, MemoryV1Composition};

const LISTEN_ADDR_ENV: &str = "SINGLE_NODE_GATEWAY_ADDR";
const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:9001";
const CREDENTIALS_FILE_ENV: &str = "ASTRAL_MEMORY_V1_CREDENTIALS_FILE";
const ACKNOWLEDGE_ENV: &str = "ASTRAL_MEMORY_V1_ACKNOWLEDGE_LIMITS";
const JOURNAL_DIR_ENV: &str = "ASTRAL_MEMORY_V1_JOURNAL_DIR";
const INSTALLATION_ID_ENV: &str = "ASTRAL_MEMORY_V1_INSTALLATION_ID";
const JOURNAL_FILE_NAME: &str = "memory-v1-durable.bin";
const CHECKPOINT_BASE: &str = "memory-v1-durable";

/// Login lifetime fixed by the server; the client cannot request one. The
/// Identity session authority enforces its own (longer) maximum on top of this.
const SESSION_LIFETIME_SECONDS: i64 = 1_800;
#[path = "memory_v1_headroom.rs"]
mod capacity;
#[path = "memory_v1_startup_evidence.rs"]
mod startup_evidence;
/// One pool connection suffices for a single read-only snapshot transaction.
const CAPTURE_POOL_CONNECTIONS: u32 = 2;
const CAPTURE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Bound on the graceful HTTP drain; after it, remaining connections are dropped.
const HTTP_DRAIN_TIMEOUT: Duration = Duration::from_secs(35);

/// Operator inputs of the single production startup path, validated before any I/O.
#[derive(Debug)]
pub(crate) struct ServiceSettings {
    pub(crate) listen: SocketAddr,
    pub(crate) credentials_path: PathBuf,
    pub(crate) journal_dir: PathBuf,
    /// Provisioned once outside the journal directory and retained across boots.
    pub(crate) installation_id: MemoryId,
    /// Test-only acknowledgement surface of the experimental grade; the
    /// unified production path ignores it.
    #[allow(dead_code)]
    pub(crate) acknowledged: Vec<AdoptionLimit>,
}

impl ServiceSettings {
    // memory—v1: Read the settings from the process environment.
    fn from_env() -> Result<Self> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    // memory—v1: Validate the settings from any variable source; the listener must be
    // loopback, the credentials file must be named explicitly, and the durable
    // journal directory must be an absolute controlled path.
    pub(crate) fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let listen_raw = get(LISTEN_ADDR_ENV).unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_owned());
        let listen: SocketAddr = listen_raw
            .trim()
            .parse()
            .with_context(|| format!("{LISTEN_ADDR_ENV} must be an ip:port socket address"))?;
        if !listen.ip().is_loopback() {
            bail!("{LISTEN_ADDR_ENV} must be a loopback address in the experimental profile");
        }
        let credentials_path = match get(CREDENTIALS_FILE_ENV) {
            Some(path) if !path.trim().is_empty() => PathBuf::from(path.trim()),
            _ => bail!("{CREDENTIALS_FILE_ENV} must name the private credentials file"),
        };
        let journal_dir = match get(JOURNAL_DIR_ENV) {
            Some(path) if !path.trim().is_empty() => PathBuf::from(path.trim()),
            _ => bail!("{JOURNAL_DIR_ENV} must name the durable journal directory"),
        };
        let installation_id = get(INSTALLATION_ID_ENV)
            .and_then(|value| value.parse::<MemoryId>().ok())
            .filter(|id| *id.as_bytes() != [0; 16])
            .ok_or_else(|| {
                anyhow!("{INSTALLATION_ID_ENV} must name the provisioned nonzero installation UUID")
            })?;
        let acknowledged = parse_acknowledged(get(ACKNOWLEDGE_ENV).as_deref().unwrap_or(""))?;
        #[allow(dead_code)] // test-only acknowledgement surface of the experimental grade
        Ok(Self {
            listen,
            credentials_path,
            journal_dir,
            installation_id,
            acknowledged,
        })
    }
}

// memory—v1: Parse the named, comma-separated limits. Unknown names are refused; an
// empty list is allowed here and fails at adoption because nothing is acknowledged.
pub(crate) fn parse_acknowledged(raw: &str) -> Result<Vec<AdoptionLimit>> {
    let mut limits = Vec::new();
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        let limit = AdoptionLimit::parse(token)
            .ok_or_else(|| anyhow!("{ACKNOWLEDGE_ENV} names an unknown limit: {token}"))?;
        if !limits.contains(&limit) {
            limits.push(limit);
        }
    }
    Ok(limits)
}

// memory—v1: The single-node composition runs on the in-process bus only.
fn require_local_transport(config: &AppConfig) -> Result<()> {
    if config.message_transport()? != MessageTransport::Local {
        bail!("the memory-v1 experimental profile requires ASTRAL_MESSAGE_TRANSPORT=local");
    }
    Ok(())
}

// memory—v1: Bootstrap and reopen derive the same initial history from an
// independently provisioned installation ID. Only the checkpoint proves its tail.
fn initial_history(installation_id: MemoryId) -> (MemoryId, MemoryId, JournalAnchor) {
    use sha2::{Digest, Sha256};
    let digest = |label: &[u8]| -> [u8; 32] {
        Sha256::new()
            .chain_update(label)
            .chain_update(installation_id.as_bytes())
            .finalize()
            .into()
    };
    let id = |label| MemoryId::from_bytes(digest(label)[..16].try_into().expect("16-byte slice"));
    let stream = id(b"astrallight/memory-v1/installation/stream/1\0");
    let epoch = id(b"astrallight/memory-v1/installation/epoch/1\0");
    let genesis = digest(b"astrallight/memory-v1/installation/genesis/1\0");
    let baseline = JournalAnchor::new(stream, 0, 0, genesis).expect("well-formed genesis anchor");
    (stream, epoch, baseline)
}

// memory—v1: Reopen a retained journal without creating a fresh baseline.
// Normal startup cannot distinguish first bootstrap from a lost journal.
pub(crate) fn open_durable_journal(
    journal_dir: &std::path::Path,
    installation_id: MemoryId,
) -> Result<(
    astral_single_node::memory_v1_durable_journal::MemoryV1DurableJournal,
    astral_single_node::memory_v1_durable_journal::JournalDurability,
)> {
    use astral_single_node::memory_v1_durable_journal::{
        DurableJournalLimits, MemoryV1DurableJournal,
    };
    if !journal_dir.is_absolute() {
        bail!("{JOURNAL_DIR_ENV} must be an absolute path");
    }
    let metadata = std::fs::metadata(journal_dir)
        .map_err(|error| anyhow!("{JOURNAL_DIR_ENV} is unavailable: {error}"))?;
    if !metadata.is_dir() {
        bail!("{JOURNAL_DIR_ENV} must name a directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            bail!("{JOURNAL_DIR_ENV} must be private (no group/other access)");
        }
    }
    let (stream, epoch, anchor) = initial_history(installation_id);
    let target = journal_dir.join(JOURNAL_FILE_NAME);
    let metadata = std::fs::symlink_metadata(&target).context(
        "the retained journal is missing or unreadable; bootstrap or reconciliation required",
    )?;
    if !metadata.is_file() {
        bail!("the retained journal is not a regular file; reconciliation required");
    }
    let install =
        astral_single_node::memory_v1_durable_journal::CheckpointInstallId::from_install_uuid(
            installation_id.into_bytes(),
        )
        .map_err(|error| anyhow!("invalid checkpoint installation: {error:?}"))?;
    MemoryV1DurableJournal::open_checkpointed(
        &target,
        &journal_dir.join(CHECKPOINT_BASE),
        install,
        stream,
        epoch,
        anchor,
        DurableJournalLimits::conservative(),
    )
    .map_err(|error| {
        anyhow!("verify the retained journal against its installation checkpoint: {error:?}")
    })
}

// memory—v1: Remote addresses require a verified MySQL server identity.
fn startup_database_options(database_url: &str) -> Result<MySqlConnectOptions> {
    let options: MySqlConnectOptions = database_url
        .parse()
        .map_err(|_| anyhow!("invalid memory-v1 candidate database options"))?;
    let local = options.get_socket().is_some()
        || options
            .get_host()
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if !local && !matches!(options.get_ssl_mode(), MySqlSslMode::VerifyIdentity) {
        bail!("a nonlocal memory-v1 candidate database requires MySQL TLS verify-identity");
    }
    Ok(options)
}

// memory—v1: Offline operator handoff. Only inspect already-applied history;
// never apply a suffix, publish Serving, mint authority, or bind a listener.
pub(crate) async fn inspect_startup_subject() -> Result<()> {
    let settings = ServiceSettings::from_env()?;
    let config =
        AppConfig::from_files_for_memory_v1_experimental("application", JwtValidationRole::Gateway)
            .context("load the memory-v1 configuration")?;
    let (journal, _durability) =
        open_durable_journal(&settings.journal_dir, settings.installation_id)?;
    let budget = capacity::capture_budget()
        .ok_or_else(|| anyhow!("insufficient or unknown memory headroom for cold capture"))?;
    let pool = MySqlPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(CAPTURE_CONNECT_TIMEOUT)
        .connect_with(startup_database_options(&config.database_url)?)
        .await
        .context("connect for read-only memory-v1 startup inspection")?;
    let captured = ReconciledColdInstall::capture_at_checkpoint(&pool, &journal, budget).await;
    pool.close().await;
    let subject = captured?.into_startup_subject(
        capacity::headroom,
        &registry_declarations(),
        settings.installation_id,
    )?;
    println!("{}", serde_json::to_string(&subject)?);
    Ok(())
}

// memory—v1: Verify the retained applied history and capture the candidate
// snapshot bound to its reconciled governance position in one integrated step,
// then release the pool. The database is not consulted again after this
// returns. The returned value is sealed: the governance position, the rows and
// the cold-load facts travel together, and the position never detaches as a
// parameter on the formal path.
pub(crate) async fn capture_from_database(
    database_url: &str,
    journal: &astral_single_node::memory_v1_durable_journal::MemoryV1DurableJournal,
    durability: &astral_single_node::memory_v1_durable_journal::JournalDurability,
    installation_id: MemoryId,
) -> Result<(ReconciledColdInstall, Arc<AuthenticatedStartupEvidence>)> {
    let budget = capacity::capture_budget()
        .ok_or_else(|| anyhow!("insufficient or unknown memory headroom for cold capture"))?;
    let evidence = startup_evidence::load(|name| std::env::var(name).ok())?;
    evidence.check_checkpoint(installation_id, journal.epoch_id(), journal.position())?;
    let options = startup_database_options(database_url)?;
    let scope_check = Arc::new(evidence);
    let connection_check = Arc::clone(&scope_check);
    let pool = MySqlPoolOptions::new()
        .max_connections(CAPTURE_POOL_CONNECTIONS)
        .acquire_timeout(CAPTURE_CONNECT_TIMEOUT)
        .after_connect(move |connection, _| {
            let evidence = std::sync::Arc::clone(&connection_check);
            Box::pin(async move {
                let scope =
                    astral_db::memory_v1_candidate_loader::read_startup_database_scope(connection)
                        .await
                        .map_err(|_| {
                            sqlx::Error::Protocol(
                                "cannot verify the startup database identity".into(),
                            )
                        })?;
                evidence.check_current_window().map_err(|_| {
                    sqlx::Error::Protocol(
                        "startup evidence expired before opening a recovery connection".into(),
                    )
                })?;
                evidence.check_database_scope(&scope).map_err(|_| {
                    sqlx::Error::Protocol("startup evidence does not bind this database".into())
                })
            })
        })
        .connect_with(options)
        .await
        .map_err(|error| anyhow!("connect the memory-v1 candidate database: {error}"))?;
    let cold = ReconciledColdInstall::capture_and_bind(&pool, journal, durability, budget).await;
    pool.close().await;
    let cold = cold.map_err(|error| match error {
        ColdInstallError::AppliedHistoryDeadline => {
            anyhow!("deadline verifying retained receipts before cold capture")
        }
        other => anyhow!("cold-install the memory-v1 candidate: {other}"),
    })?;
    Ok((cold, scope_check))
}

// memory—v1: Separate a capture into its candidate rows and the cold-load facts the root is
// verified with. A capture without a complete scan report yields nothing.
#[allow(dead_code)] // retained for the isolated lifecycle tests of the experimental sequence
pub(crate) fn split_capture(
    capture: UnverifiedCandidateRows,
) -> Result<(CandidateRows, ColdLoadFacts)> {
    let UnverifiedCandidateRows { rows, report, .. } = capture;
    let report = report.ok_or_else(|| anyhow!("the candidate capture carries no report"))?;
    let facts = report
        .cold_load_facts()
        .ok_or_else(|| anyhow!("the candidate capture did not scan every table exactly once"))?;
    Ok((rows, facts))
}

// memory—v1: Install the captured rows as the process root and adopt it under the
// experimental grade. Anything the root cannot re-derive or the operator did not
// acknowledge fails here, before any listener exists.
#[allow(dead_code)] // test-only experimental sequence; the unified path uses production adoption
pub(crate) fn adopt_captured(
    capture: UnverifiedCandidateRows,
    acknowledged: &[AdoptionLimit],
) -> Result<RootOwner> {
    let (rows, facts) = split_capture(capture)?;
    adopt_rows(rows, &facts, acknowledged)
}

// memory—v1: Recheck headroom with the archive resident; only the fully
// constructed candidate and digest can occupy the one process slot.
pub(crate) fn install_rows(rows: CandidateRows) -> Result<RootOwner> {
    let selections = rows.current_version_selections().map_err(|error| {
        anyhow!("the candidate has no valid current rule-set version pointer: {error:?}")
    })?;
    install_process_root_with_headroom(rows, selections, capacity::headroom)
        .context("install the memory-v1 process root")
}

// memory—v1: Adopt already captured rows with the adapter's cold-load facts.
#[allow(dead_code)] // test-only experimental sequence; the unified path uses production adoption
pub(crate) fn adopt_rows(
    rows: CandidateRows,
    facts: &ColdLoadFacts,
    acknowledged: &[AdoptionLimit],
) -> Result<RootOwner> {
    let owner = install_rows(rows)?;
    // memory—v1 §4.9: the registry must be installed before adoption because
    // adoption validates every current rule reference against route metadata.
    owner
        .install_registry(&registry_declarations())
        .context("install the memory-v1 resource registry")?;
    owner
        .adopt_experimental(facts, acknowledged)
        .context("adopt the memory-v1 root under the experimental grade")?;
    Ok(owner)
}

// memory—v1 §4.9: aggregate the adapted route metadata of every service into
// registry declarations. Today only TrustGraph ships adapted routes.
pub(crate) fn registry_declarations() -> Vec<RegistryDeclaration> {
    let mut by_resource: BTreeMap<&'static str, BTreeSet<&'static str>> = BTreeMap::new();
    for declaration in astral_trustgraph::api::permission_check::MEMORY_V1_ROUTE_REGISTRATIONS {
        let actions = by_resource.entry(declaration.resource).or_default();
        actions.insert(declaration.action);
        actions.extend(declaration.additional_actions.iter().copied());
    }
    by_resource
        .into_iter()
        .map(|(resource, actions)| RegistryDeclaration {
            resource: resource.to_owned(),
            actions: actions.into_iter().map(str::to_owned).collect(),
        })
        .collect()
}

// memory—v1: Compose Identity (file-credential login), TrustGraph (offline state) and
// the Gateway around the one adopted root. Identity is built by the composition so it
// receives the matching session authority.
#[allow(dead_code)] // test-only experimental assembly; the unified path uses assemble_production
pub(crate) fn assemble(
    owner: RootOwner,
    config: AppConfig,
    credentials: MemoryV1FileCredentials,
) -> Result<MemoryV1Composition> {
    let engine = Arc::new(PolicyEngine::new());
    let trustgraph = build_router(
        build_memory_v1_offline_app_state(config.clone(), engine),
        RouterIntegrationConfig::disabled(),
    );
    let credentials = Arc::new(credentials);
    let authenticator =
        MemoryV1CredentialAuthenticator::from_file_credentials(Arc::clone(&credentials));
    MemoryV1Composition::new_with_file_credentials(
        owner,
        credentials,
        move |session| memory_v1_auth_router(session, authenticator, SESSION_LIFETIME_SECONDS),
        trustgraph,
        config,
        SESSION_LIFETIME_SECONDS,
    )
    .context("bind the memory-v1 session authority to the root")
}

/// memory—v1: Compose the production path with the durable commit owner.
///
/// The journal must already be open and chain-verified; the writer and commit
/// owner are the only serving-root mutation path and live for the composition.
pub(crate) fn assemble_production(
    owner: std::sync::Arc<RootOwner>,
    admission: Arc<astral_authorization_root::memory_v1_root::ProductionAdmission>,
    journal_durability: (
        astral_single_node::memory_v1_durable_journal::MemoryV1DurableJournal,
        astral_single_node::memory_v1_durable_journal::JournalDurability,
    ),
    config: AppConfig,
    credentials: MemoryV1FileCredentials,
) -> Result<MemoryV1Composition> {
    let credentials = Arc::new(credentials);
    let authenticator =
        MemoryV1CredentialAuthenticator::from_file_credentials(Arc::clone(&credentials));
    MemoryV1Composition::new_with_file_credentials_production(
        owner,
        admission,
        journal_durability,
        credentials,
        move |session| memory_v1_auth_router(session, authenticator, SESSION_LIFETIME_SECONDS),
        config,
        SESSION_LIFETIME_SECONDS,
    )
    .context("bind the memory-v1 production session authority to the root")
}

// memory—v1: Describe what the root was adopted with; this is a description of the
// adoption, never authorization evidence.
fn readiness_line(root: &RootHandle, addr: SocketAddr) -> Result<String> {
    let metadata = root.metadata().context("read the serving root metadata")?;
    let record = root
        .adoption_record()
        .context("read the adoption record")?
        .ok_or_else(|| anyhow!("the serving root carries no adoption record"))?;
    let unverified = record
        .unverified
        .iter()
        .map(|limit| limit.name())
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "ASTRAL_MEMORY_V1_READY addr={addr} grade={:?} root_version={} rows={} unverified={unverified} recovery=unverified formal_authorization=unverified",
        record.grade, metadata.version, metadata.row_count
    ))
}

/// memory—v1: Serve `router` on `listener` until `shutdown` resolves.
///
/// Requests carry their peer address so the Gateway can attribute and limit them.
/// The drain is bounded; connections still open after it are dropped.
pub(crate) async fn serve(
    listener: TcpListener,
    router: Router,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let (drain_started_tx, drain_started_rx) = tokio::sync::oneshot::channel::<()>();
    let server = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown.await;
        let _ = drain_started_tx.send(());
    });
    let mut server = std::pin::pin!(server.into_future());
    tokio::select! {
        result = &mut server => result.context("memory-v1 HTTP server stopped unexpectedly"),
        _ = drain_started_rx => {
            match tokio::time::timeout(HTTP_DRAIN_TIMEOUT, &mut server).await {
                Ok(result) => result.context("memory-v1 HTTP server failed while draining"),
                Err(_) => {
                    tracing::warn!("memory-v1 HTTP drain exceeded its budget; dropping open connections");
                    Ok(())
                }
            }
        }
    }
}

// memory—v1: Resolve when the process is asked to stop (Ctrl-C, or SIGTERM on Unix).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(error) => {
                tracing::warn!(error = %error, "SIGTERM handler unavailable; Ctrl-C only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// memory—v1: Validate the retained history before cold capture, require
/// production adoption before binding loopback, and drain before owner drop.
pub(crate) async fn run() -> Result<()> {
    let settings = ServiceSettings::from_env()?;
    let config =
        AppConfig::from_files_for_memory_v1_experimental("application", JwtValidationRole::Gateway)
            .context("load the memory-v1 configuration")?;
    config
        .validate_memory_v1_experimental_for(JwtValidationRole::Identity)
        .context("validate the memory-v1 configuration for Identity")?;
    require_local_transport(&config)?;
    let credentials = MemoryV1FileCredentials::load(&settings.credentials_path)
        .context("load the memory-v1 credentials file")?;
    if credentials.is_empty() {
        bail!("the memory-v1 credentials file defines no credentials");
    }

    // Opening the retained journal verifies the local chain, not its coverage
    // of this installation or the database's consumed prefix.
    let (journal, durability) =
        open_durable_journal(&settings.journal_dir, settings.installation_id)
            .context("open the durable memory-v1 journal")?;
    tracing::info!(
        records = journal.record_count(),
        file_bytes = journal.file_position(),
        "memory-v1 durable journal verified"
    );

    let (cold, evidence) = capture_from_database(
        &config.database_url,
        &journal,
        &durability,
        settings.installation_id,
    )
    .await?;
    // The capture transaction and pool have closed. Only a fresh capture whose
    // timestamp overlaps the current trusted interval may settle before install.
    cold.settle_capture_time(&evidence)
        .await
        .context("settle the cold capture against trusted time")?;
    // memory—v1: Install only the exact applied-prefix snapshot covered by the
    // independent reports. The verification and registry generation are
    // checked before the root CAS and before opening any listener.
    let (owner, admission) = cold
        .install_and_adopt_signed_startup(
            capacity::headroom,
            &registry_declarations(),
            settings.installation_id,
            &evidence,
        )
        .context("cold-install and adopt the memory-v1 root")?;
    let owner = Arc::new(owner);
    let root = owner.handle();
    require_serving_root(&root).context("memory-v1 serving root admission")?;

    let composition =
        assemble_production(owner, admission, (journal, durability), config, credentials)?;
    evidence.check_current_window()?;
    let listener = TcpListener::bind(settings.listen)
        .await
        .context("bind the memory-v1 listener")?;
    let bound = listener.local_addr().context("read the bound address")?;
    if !bound.ip().is_loopback() {
        bail!("the memory-v1 listener bound a non-loopback address");
    }
    let ready = readiness_line(&root, bound)?;
    evidence.check_current_window()?;
    tracing::info!(addr = %bound, "memory-v1 service ready");
    println!("{ready}");

    let result = serve(listener, composition.router(), shutdown_signal()).await;
    let live_scopes = composition.request_scope_budget().active();
    if live_scopes != 0 {
        tracing::warn!(
            live_scopes,
            "request scopes were still live when the HTTP server stopped"
        );
    }
    // The root owner is dropped last, after the HTTP server has drained.
    drop(composition);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    #[test]
    // memory—v1: The listener must be loopback; the default is loopback; garbage is refused.
    fn settings_require_a_loopback_listener() {
        let settings = ServiceSettings::from_lookup(lookup(&[
            (CREDENTIALS_FILE_ENV, "/private/credentials.json"),
            (JOURNAL_DIR_ENV, "/private/journal"),
            (INSTALLATION_ID_ENV, "00000000-0000-4000-8000-000000000001"),
        ]))
        .unwrap();
        assert_eq!(settings.listen, "127.0.0.1:9001".parse().unwrap());
        assert!(settings.acknowledged.is_empty());

        for accepted in ["127.0.0.1:0", "127.0.0.1:9001", "[::1]:9001"] {
            let settings = ServiceSettings::from_lookup(lookup(&[
                (LISTEN_ADDR_ENV, accepted),
                (CREDENTIALS_FILE_ENV, "/private/credentials.json"),
                (JOURNAL_DIR_ENV, "/private/journal"),
                (INSTALLATION_ID_ENV, "00000000-0000-4000-8000-000000000001"),
            ]))
            .unwrap();
            assert!(settings.listen.ip().is_loopback());
        }
        for refused in [
            "0.0.0.0:9001",
            "[::]:9001",
            "192.0.2.10:9001",
            "localhost:9001",
            "9001",
            "",
        ] {
            let error = ServiceSettings::from_lookup(lookup(&[
                (LISTEN_ADDR_ENV, refused),
                (CREDENTIALS_FILE_ENV, "/private/credentials.json"),
                (JOURNAL_DIR_ENV, "/private/journal"),
                (INSTALLATION_ID_ENV, "00000000-0000-4000-8000-000000000001"),
            ]))
            .unwrap_err();
            assert!(
                error.to_string().contains(LISTEN_ADDR_ENV),
                "{refused:?} must be refused by name: {error}"
            );
        }
    }

    #[test]
    // memory—v1: Reboots retain the installation's history. Foreign histories must differ
    // even at genesis, before either journal contains any frames.
    fn installation_identity_binds_the_initial_history() {
        let id = MemoryId::from_bytes([1; 16]);
        let (stream, epoch, genesis) = initial_history(id);
        assert_eq!(initial_history(id), (stream, epoch, genesis));
        let foreign = initial_history(MemoryId::from_bytes([2; 16]));
        assert_ne!(stream, epoch);
        assert_ne!(stream, foreign.0);
        assert_ne!(epoch, foreign.1);
        assert_ne!(genesis.frame_hash(), foreign.2.frame_hash());
        for value in [
            None,
            Some(""),
            Some("bad"),
            Some("00000000-0000-0000-0000-000000000000"),
        ] {
            let settings = ServiceSettings::from_lookup(|name| match name {
                CREDENTIALS_FILE_ENV | JOURNAL_DIR_ENV => Some("/private/fixture".into()),
                INSTALLATION_ID_ENV => value.map(str::to_owned),
                _ => None,
            });
            assert!(settings
                .unwrap_err()
                .to_string()
                .contains(INSTALLATION_ID_ENV));
        }
    }

    #[test]
    // memory—v1: The credentials file must be named explicitly; there is no default.
    fn settings_require_a_credentials_file() {
        for value in [None, Some(""), Some("   ")] {
            let pairs: Vec<(&str, &str)> = value
                .map(|value| vec![(CREDENTIALS_FILE_ENV, value)])
                .unwrap_or_default();
            let error = ServiceSettings::from_lookup(lookup(&pairs)).unwrap_err();
            assert!(error.to_string().contains(CREDENTIALS_FILE_ENV));
        }
    }

    #[test]
    // memory—v1: Limits are acknowledged by name; unknown names are refused, duplicates collapse.
    fn acknowledged_limits_are_named_and_checked() {
        assert!(parse_acknowledged("").unwrap().is_empty());
        assert!(parse_acknowledged(" , ").unwrap().is_empty());
        let all = AdoptionLimit::EXPERIMENTAL
            .iter()
            .map(|limit| limit.name())
            .collect::<Vec<_>>()
            .join(", ");
        assert_eq!(
            parse_acknowledged(&all).unwrap(),
            AdoptionLimit::EXPERIMENTAL.to_vec()
        );
        assert_eq!(
            parse_acknowledged("writer-coverage,writer-coverage,eligibility").unwrap(),
            vec![AdoptionLimit::WriterCoverage, AdoptionLimit::Eligibility]
        );
        let error = parse_acknowledged("writer-coverage,everything").unwrap_err();
        assert!(error.to_string().contains("everything"));
        assert!(parse_acknowledged("all").is_err());
    }

    #[test]
    // memory—v1: The service never runs over the Rabbit transport.
    fn local_transport_is_required() {
        let with = |transport: &str| AppConfig {
            message_transport: transport.into(),
            ..AppConfig::default()
        };
        assert!(require_local_transport(&with("local")).is_ok());
        assert!(require_local_transport(&with("rabbit")).is_err());
    }

    #[test]
    // memory—v1: The dependency boundary: the formal path stays closed and this module
    // names no production-adoption constructor.
    fn profile_does_not_reach_the_production_adoption_path() {
        let source = include_str!("memory_v1_service.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("adopt_experimental("));
        assert!(!production.contains("complete_for_test"));
        assert!(!production.contains("test-support"));
        assert!(!production.contains("0.0.0.0"));
    }

    #[test]
    // memory—v1: The cold-install slice binds the reconciled governance position
    // inside the sealed capture instead of refusing a non-baseline journal: the
    // old run-time refusal is gone and the sealed binding is the only formal
    // prefix carrier.
    fn cold_install_binds_the_reconciled_prefix_instead_of_refusing() {
        let source = include_str!("memory_v1_service.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(
            !production.contains("cold root installation requires the recovered governance prefix")
        );
        assert!(production.contains("ReconciledColdInstall::capture_and_bind("));
        assert!(production.contains("install_and_adopt_signed_startup("));
        assert!(!production.contains("install_and_adopt_production("));
        // The prefix never appears as a detached parameter on the formal path.
        assert!(!production.contains("prefix: Option<GovernancePrefix>"));
    }
}

// memory—v1: The real-socket lifecycle acceptance tests. Declared after the unit tests so
// source guards that slice this file at its first `#[cfg(test)]` keep the complete
// production region.
#[cfg(test)]
#[path = "memory_v1_service_fixture.rs"]
mod production_fixture;

#[cfg(test)]
#[path = "memory_v1_service_tests.rs"]
mod lifecycle_tests;

#[cfg(test)]
#[path = "memory_v1_lifecycle_stress_tests.rs"]
mod lifecycle_stress_tests;
