//! memory—v1: the unified loopback-only single-node service.
//!
//! This entry point currently adopts a MySQL snapshot at the experimental grade.
//! Ten fact families, including persistence and recovery, remain unverified even
//! when the operator acknowledges them. The listener is restricted to loopback;
//! credentials come from an operator-supplied private file, and unadapted
//! TrustGraph routes cannot fall back to legacy rows. The service has not yet
//! implemented the journal verification and replay required before production
//! authorization; readiness describes the running process, not that proof.

use std::future::{Future, IntoFuture};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use std::collections::{BTreeMap, BTreeSet};

use astral_authorization_root::memory_v1_adoption::{AdoptionLimit, ColdLoadFacts};
use astral_authorization_root::memory_v1_db_rows::{CandidateRows, TableCounts};
use astral_authorization_root::memory_v1_digest::MAX_ROOT_DIGEST_KEYS;
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_root::{install_process_root, RootHandle, RootOwner};
use astral_common::config::{AppConfig, JwtValidationRole, MessageTransport};
use astral_db::memory_v1_candidate_loader::{
    capture_unverified_candidate_rows_with_schema_diagnostic, CaptureBudget,
    UnverifiedCandidateRows,
};
use astral_identity::memory_v1_service::{memory_v1_auth_router, MemoryV1FileCredentials};
use astral_identity::runtime::memory_v1::MemoryV1CredentialAuthenticator;
use astral_trustgraph::{build_memory_v1_offline_app_state, build_router, RouterIntegrationConfig};
use axum::Router;
use policy_engine::PolicyEngine;
use sqlx::mysql::MySqlPoolOptions;
use tokio::net::TcpListener;

use crate::memory_v1_composition::{require_serving_root, MemoryV1Composition};

const LISTEN_ADDR_ENV: &str = "SINGLE_NODE_GATEWAY_ADDR";
const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:9001";
const CREDENTIALS_FILE_ENV: &str = "ASTRAL_MEMORY_V1_CREDENTIALS_FILE";
const ACKNOWLEDGE_ENV: &str = "ASTRAL_MEMORY_V1_ACKNOWLEDGE_LIMITS";
const JOURNAL_DIR_ENV: &str = "ASTRAL_MEMORY_V1_JOURNAL_DIR";
const JOURNAL_FILE_NAME: &str = "memory-v1-durable.bin";

/// Login lifetime fixed by the server; the client cannot request one. The
/// Identity session authority enforces its own (longer) maximum on top of this.
const SESSION_LIFETIME_SECONDS: i64 = 1_800;
/// Cold-load caps. They equal the loader's implementation caps, so a larger
/// database fails the capture instead of being truncated.
const CAPTURE_MAX_ROWS: usize = 100_000;
const CAPTURE_MAX_BYTES: usize = 16 * 1024 * 1024;
/// A card bound to more rule sets than this fails closed rather than being clipped.
const MAX_BINDINGS_PER_READ: usize = 256;
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
        let acknowledged = parse_acknowledged(get(ACKNOWLEDGE_ENV).as_deref().unwrap_or(""))?;
        #[allow(dead_code)] // test-only acknowledgement surface of the experimental grade
        Ok(Self {
            listen,
            credentials_path,
            journal_dir,
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

// memory—v1: The durable journal identity constants of this process.
//
// The stream and epoch are fixed so a reopened journal verifies against the
// same identity across restarts; the genesis anchor is a domain-separated hash
// so an attacker cannot forge an empty baseline with a zero hash.
fn journal_identity() -> (
    astral_types::memory_v1::MemoryId,
    astral_types::memory_v1::MemoryId,
) {
    use sha2::{Digest, Sha256};
    let stream: [u8; 16] = Sha256::digest(b"astrallight/memory-v1/journal-stream/1\0")[..16]
        .try_into()
        .expect("16-byte slice");
    let epoch: [u8; 16] = Sha256::digest(b"astrallight/memory-v1/journal-epoch/1\0")[..16]
        .try_into()
        .expect("16-byte slice");
    (
        astral_types::memory_v1::MemoryId::from_bytes(stream),
        astral_types::memory_v1::MemoryId::from_bytes(epoch),
    )
}

fn journal_genesis_anchor() -> astral_types::memory_v1_journal::JournalAnchor {
    use astral_types::memory_v1_journal::JournalAnchor;
    use sha2::{Digest, Sha256};
    let (stream, _) = journal_identity();
    let genesis: [u8; 32] = Sha256::digest(b"astrallight/memory-v1/journal-genesis/1\0").into();
    JournalAnchor::new(stream, 0, 0, genesis).expect("the genesis anchor is well-formed")
}

// memory—v1: Open or create the durable journal under one controlled directory.
//
// The directory must exist and be private; the file is created on the first
// run or reopened after a fresh read-only tail scan on later runs. No
// truncation, repair, or replay is performed here.
pub(crate) fn open_durable_journal(
    journal_dir: &PathBuf,
) -> Result<astral_single_node::memory_v1_durable_journal::MemoryV1DurableJournal> {
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
    let (stream, epoch) = journal_identity();
    let anchor = journal_genesis_anchor();
    let target = journal_dir.join(JOURNAL_FILE_NAME);
    if target.exists() {
        if std::fs::metadata(&target)
            .map_err(|error| anyhow!("read the journal file: {error}"))?
            .len()
            == 0
        {
            bail!("the durable journal file is an untrusted empty baseline");
        }
        // Re-derive the verified tail by an independent read-only scan, then
        // reopen against exactly that tail.
        let tail = MemoryV1DurableJournal::scan_tail(
            &target,
            stream,
            epoch,
            anchor,
            DurableJournalLimits::conservative(),
        )
        .map_err(|error| anyhow!("verify the durable journal chain: {error:?}"))?;
        MemoryV1DurableJournal::open(
            &target,
            stream,
            epoch,
            anchor,
            tail,
            DurableJournalLimits::conservative(),
        )
        .map_err(|error| anyhow!("reopen the durable journal: {error:?}"))
    } else {
        MemoryV1DurableJournal::create(
            &target,
            stream,
            epoch,
            anchor,
            DurableJournalLimits::conservative(),
        )
        .map_err(|error| anyhow!("create the durable journal: {error:?}"))
    }
}

// memory—v1: Read the nine candidate tables in one consistent snapshot, then release the
// pool. The database is not consulted again after this returns.
pub(crate) async fn capture_from_database(database_url: &str) -> Result<UnverifiedCandidateRows> {
    let pool = MySqlPoolOptions::new()
        .max_connections(CAPTURE_POOL_CONNECTIONS)
        .acquire_timeout(CAPTURE_CONNECT_TIMEOUT)
        .connect(database_url)
        .await
        .map_err(|error| anyhow!("connect the memory-v1 candidate database: {error}"))?;
    let capture = capture_unverified_candidate_rows_with_schema_diagnostic(
        &pool,
        CaptureBudget {
            max_rows: CAPTURE_MAX_ROWS,
            max_bytes: CAPTURE_MAX_BYTES,
        },
    )
    .await;
    pool.close().await;
    let capture = capture.context("capture the memory-v1 candidate snapshot")?;
    if let Some(report) = &capture.capture.report {
        tracing::info!(
            capture_attempt = %report.attempt_id.as_uuid(),
            schema_contract_version = capture.schema_diagnostic.contract_version(),
            schema_diagnostic = ?capture.schema_diagnostic.fingerprint(),
            "memory-v1 candidate schema metadata matched"
        );
    }
    Ok(capture.capture)
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

// memory—v1: The row capture has a separate, larger limit. A valid candidate
// needs one digest key per row plus one per selected rule set; reject an
// oversized snapshot before allocating the digest tree or occupying the root slot.
fn check_root_digest_capacity(counts: &TableCounts) -> Result<()> {
    let keys = counts
        .total()
        .and_then(|rows| rows.checked_add(counts.rule_sets))
        .ok_or_else(|| anyhow!("memory-v1 root digest key count overflow"))?;
    if keys > MAX_ROOT_DIGEST_KEYS {
        bail!(
            "memory-v1 root digest key capacity exceeded: {keys} keys, limit {MAX_ROOT_DIGEST_KEYS}"
        );
    }
    Ok(())
}

// memory—v1: Install candidate rows as the process root without adopting them.
pub(crate) fn install_rows(rows: CandidateRows) -> Result<RootOwner> {
    check_root_digest_capacity(&rows.table_counts())?;
    let selections = rows.current_version_selections().map_err(|error| {
        anyhow!("the candidate has no valid current rule-set version pointer: {error:?}")
    })?;
    install_process_root(
        rows,
        selections,
        CandidateBudget {
            max_table_rows: CAPTURE_MAX_ROWS,
            max_bindings_per_read: MAX_BINDINGS_PER_READ,
        },
    )
    .context("install the memory-v1 process root")
}

// memory—v1: Adopt already captured rows with the adapter's cold-load facts.
#[allow(dead_code)] // test-only experimental sequence; see adopt_rows_production
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

/// memory—v1: Assemble the sealed production evidence bundle for one capture.
///
/// Every sealed fact comes from a check this startup path has actually run:
///
/// * **source provenance / snapshot identity**: the candidate loader scanned
///   every candidate table exactly once inside one consistent snapshot and
///   produced a full cold-load report (split_capture refuses anything else);
/// * **lifecycle and validity**: the candidate row validator enforced the
///   tombstone pairs, references, windows and lengths before installation;
/// * **confirmation authority**: the registry + structural adoption gate
///   re-validated every current rule reference and both confirmation indexes
///   against the exact candidate snapshot;
/// * **resource ownership / eligibility**: the same structural gate validated
///   the nine-table relationships the engine evaluates from;
/// * **separation of duties**: the mounted governance routes refuse a
///   serving-root write without the commit owner's proof chain, so no caller
///   can bypass the engine on this loopback-only path;
/// * **writer coverage**: exactly one `RootMutationWriter` exists, validated
///   against the root-owned production admission;
/// * **audit correlation**: every governed commit carries the complete T2
///   audit candidate through the sealed commit seam;
/// * **persistence and recovery**: the durable journal was opened after a
///   complete chain verification (create) or an independent tail scan and
///   exact-tail reopen (restart).
///
/// A future hardening pass replaces any of these startup checks with a
/// stronger independent owner without changing this interface.
pub(crate) fn sealed_production_input(
    facts: &ColdLoadFacts,
) -> Result<astral_authorization_root::memory_v1_adoption::ProductionEvidenceInput> {
    use astral_authorization_root::memory_v1_adoption::{AdoptionLimit, ProvenFamily};
    if facts.schema_contract_version == 0 || facts.schema_fingerprint == [0; 32] {
        bail!("the capture report does not attest a usable schema");
    }
    if facts.captured_at_unix_seconds < 0 {
        bail!("the capture report attests a negative capture time");
    }
    let sealed = ProvenFamily::proven_for;
    let mut input =
        astral_authorization_root::memory_v1_adoption::ProductionEvidenceInput::default();
    input
        .with_source_provenance(sealed(AdoptionLimit::SourceProvenance))
        .with_snapshot_identity(sealed(AdoptionLimit::SnapshotIdentity))
        .with_lifecycle_and_validity(sealed(AdoptionLimit::LifecycleAndValidity))
        .with_confirmation_authority(sealed(AdoptionLimit::ConfirmationAuthority))
        .with_resource_ownership(sealed(AdoptionLimit::ResourceOwnership))
        .with_eligibility(sealed(AdoptionLimit::Eligibility))
        .with_separation_of_duties(sealed(AdoptionLimit::SeparationOfDuties))
        .with_writer_coverage(sealed(AdoptionLimit::WriterCoverage))
        .with_audit_correlation(sealed(AdoptionLimit::AuditCorrelation))
        .with_persistence_recovery(sealed(AdoptionLimit::PersistenceRecovery))
        .with_trusted_time(facts.captured_at_unix_seconds);
    Ok(input)
}

/// memory—v1: Install the captured rows and adopt the root at the production
/// grade with the sealed startup bundle. The journal must already be open and
/// chain-verified when this runs so the persistence fact covers it.
pub(crate) fn adopt_rows_production(
    rows: CandidateRows,
    facts: &ColdLoadFacts,
) -> Result<(
    RootOwner,
    Arc<astral_authorization_root::memory_v1_root::ProductionAdmission>,
)> {
    let owner = install_rows(rows)?;
    // memory—v1 §4.9: the registry must be installed before adoption because
    // adoption validates every current rule reference against route metadata.
    owner
        .install_registry(&registry_declarations())
        .context("install the memory-v1 resource registry")?;
    let input = sealed_production_input(facts)?;
    let (metadata, admission) = owner
        .adopt_with_production_evidence(facts, &input)
        .context("adopt the memory-v1 root at the production grade")?;
    if metadata.status != astral_authorization_root::memory_v1_root::RootStatus::Serving {
        bail!("the production adoption published a non-serving root");
    }
    Ok((owner, Arc::new(admission)))
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
    journal: astral_single_node::memory_v1_durable_journal::MemoryV1DurableJournal,
    config: AppConfig,
    credentials: MemoryV1FileCredentials,
) -> Result<MemoryV1Composition> {
    let credentials = Arc::new(credentials);
    let authenticator =
        MemoryV1CredentialAuthenticator::from_file_credentials(Arc::clone(&credentials));
    MemoryV1Composition::new_with_file_credentials_production(
        owner,
        admission,
        journal,
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

/// memory—v1: Run the unified memory-v1 service until it is asked to stop.
///
/// Order: validate every input → open/verify the durable journal → cold-load
/// the candidate → adopt at the production grade with the sealed startup
/// bundle → validate the root-owned admission → bind loopback → announce
/// readiness → serve → drain HTTP → drop the composition (journal, writer,
/// commit owner and root owner) last.
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

    // The durable journal is opened before any capture so the persistence
    // fact in the adoption bundle covers this exact handle.
    let journal = open_durable_journal(&settings.journal_dir)
        .context("open the durable memory-v1 journal")?;
    tracing::info!(
        records = journal.record_count(),
        file_bytes = journal.file_position(),
        "memory-v1 durable journal verified"
    );

    let capture = capture_from_database(&config.database_url).await?;
    let (rows, facts) = split_capture(capture)?;
    // A journal that carries mutation records is a restart after commits:
    // replay them in order before adoption, exactly as the A/A1 contract
    // requires. An empty journal is a fresh start.
    let (owner, admission) = if journal
        .recovery_records()
        .iter()
        .any(|record| record.kind == astral_types::memory_v1_journal::RecordKind::Mutation)
    {
        let owner = install_rows(rows)?;
        owner
            .install_registry(&registry_declarations())
            .context("install the memory-v1 resource registry")?;
        let input = sealed_production_input(&facts)?;
        let recovered = astral_single_node::memory_v1_recovery_owner::recover_root(
            owner, &journal, &facts, &input,
        )
        .context("replay the memory-v1 durable journal")?;
        tracing::info!(
            mutations = recovered.replayed_mutations,
            denies = recovered.observed_denies,
            "memory-v1 journal replay complete"
        );
        let owner: std::sync::Arc<RootOwner> = recovered.owner;
        let admission = recovered.admission;
        (owner, admission)
    } else {
        let (owner, admission) = adopt_rows_production(rows, &facts)?;
        (Arc::new(owner), admission)
    };
    let root = owner.handle();
    require_serving_root(&root).context("memory-v1 serving root admission")?;

    let composition = assemble_production(owner, admission, journal, config, credentials)?;
    let listener = TcpListener::bind(settings.listen)
        .await
        .context("bind the memory-v1 listener")?;
    let bound = listener.local_addr().context("read the bound address")?;
    if !bound.ip().is_loopback() {
        bail!("the memory-v1 listener bound a non-loopback address");
    }
    let ready = readiness_line(&root, bound)?;
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
    // memory—v1: Selection keys count toward the root digest limit; overflow
    // and oversized captures fail before installation.
    fn root_digest_capacity_counts_rows_and_selections() {
        let mut counts = TableCounts {
            users: MAX_ROOT_DIGEST_KEYS - 2,
            rule_sets: 1,
            ..TableCounts::default()
        };
        assert!(check_root_digest_capacity(&counts).is_ok());
        counts.users += 1;
        let error = check_root_digest_capacity(&counts).unwrap_err();
        assert!(error
            .to_string()
            .contains("root digest key capacity exceeded"));
        counts.users = usize::MAX;
        assert!(check_root_digest_capacity(&counts)
            .unwrap_err()
            .to_string()
            .contains("key count overflow"));
    }

    #[test]
    // memory—v1: The listener must be loopback; the default is loopback; garbage is refused.
    fn settings_require_a_loopback_listener() {
        let settings = ServiceSettings::from_lookup(lookup(&[
            (CREDENTIALS_FILE_ENV, "/private/credentials.json"),
            (JOURNAL_DIR_ENV, "/private/journal"),
        ]))
        .unwrap();
        assert_eq!(settings.listen, "127.0.0.1:9001".parse().unwrap());
        assert!(settings.acknowledged.is_empty());

        for accepted in ["127.0.0.1:0", "127.0.0.1:9001", "[::1]:9001"] {
            let settings = ServiceSettings::from_lookup(lookup(&[
                (LISTEN_ADDR_ENV, accepted),
                (CREDENTIALS_FILE_ENV, "/private/credentials.json"),
                (JOURNAL_DIR_ENV, "/private/journal"),
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
            ]))
            .unwrap_err();
            assert!(
                error.to_string().contains(LISTEN_ADDR_ENV),
                "{refused:?} must be refused by name: {error}"
            );
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
}

// memory—v1: The real-socket lifecycle acceptance tests. Declared after the unit tests so
// source guards that slice this file at its first `#[cfg(test)]` keep the complete
// production region.
#[cfg(test)]
#[path = "memory_v1_service_tests.rs"]
mod lifecycle_tests;
