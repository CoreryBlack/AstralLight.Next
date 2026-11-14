//! memory—v1 experimental: the loopback-only real-service profile.
//!
//! This module turns the candidate composition into a process that serves real
//! HTTP, so a lifecycle request (login → authorized read → logout) can be driven
//! end to end against a running service. It is an explicit, operator-selected
//! experiment, not production adoption:
//!
//! - The profile must be requested by name (`ASTRAL_SINGLE_NODE_PROFILE`). The
//!   formal single-node path never starts this service; it runs only the read-only
//!   startup preflight in `memory_v1_preflight` before its readiness refusal.
//! - The listener binds loopback only. A non-loopback address is refused before
//!   any database access and the bound address is re-checked after binding.
//! - The root is loaded once from one consistent MySQL snapshot and adopted under
//!   the experimental grade. Every fact family the schema cannot prove stays
//!   `Unverified` and is served only because the operator named it in
//!   `ASTRAL_MEMORY_V1_ACKNOWLEDGE_LIMITS`; the limits are printed at readiness.
//! - After the cold load the database is not consulted again. Credentials come
//!   from an operator-supplied private file, never from the database.
//! - TrustGraph is built over an offline pool, so a route that has not been
//!   adapted to memory—v1 cannot fall back to legacy rows.

use std::future::{Future, IntoFuture};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use std::collections::{BTreeMap, BTreeSet};

use astral_authorization_root::memory_v1_adoption::{AdoptionLimit, ColdLoadFacts};
use astral_authorization_root::memory_v1_db_rows::CandidateRows;
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
use astral_authorization_root::memory_v1_root::{install_process_root, RootHandle, RootOwner};
use astral_common::config::{AppConfig, JwtValidationRole, MessageTransport};
use astral_db::memory_v1_candidate_loader::{
    capture_unverified_candidate_rows, CaptureBudget, UnverifiedCandidateRows,
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
    pub(crate) acknowledged: Vec<AdoptionLimit>,
}

impl ServiceSettings {
    // memory—v1: Read the settings from the process environment.
    fn from_env() -> Result<Self> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    // memory—v1: Validate the settings from any variable source; the listener must be
    // loopback and the credentials file must be named explicitly.
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
        let acknowledged = parse_acknowledged(get(ACKNOWLEDGE_ENV).as_deref().unwrap_or(""))?;
        Ok(Self {
            listen,
            credentials_path,
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

// memory—v1: Read the nine candidate tables in one consistent snapshot, then release the
// pool. The database is not consulted again after this returns.
pub(crate) async fn capture_from_database(database_url: &str) -> Result<UnverifiedCandidateRows> {
    let pool = MySqlPoolOptions::new()
        .max_connections(CAPTURE_POOL_CONNECTIONS)
        .acquire_timeout(CAPTURE_CONNECT_TIMEOUT)
        .connect(database_url)
        .await
        .map_err(|error| anyhow!("connect the memory-v1 candidate database: {error}"))?;
    let capture = capture_unverified_candidate_rows(
        &pool,
        CaptureBudget {
            max_rows: CAPTURE_MAX_ROWS,
            max_bytes: CAPTURE_MAX_BYTES,
        },
    )
    .await;
    pool.close().await;
    capture.context("capture the memory-v1 candidate snapshot")
}

// memory—v1: Separate a capture into its candidate rows and the cold-load facts the root is
// verified with. A capture without a complete scan report yields nothing.
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
pub(crate) fn adopt_captured(
    capture: UnverifiedCandidateRows,
    acknowledged: &[AdoptionLimit],
) -> Result<RootOwner> {
    let (rows, facts) = split_capture(capture)?;
    adopt_rows(rows, &facts, acknowledged)
}

// memory—v1: Install candidate rows as the process root without adopting them.
pub(crate) fn install_rows(rows: CandidateRows) -> Result<RootOwner> {
    let selections = rows.single_version_selections().map_err(|error| {
        anyhow!("the candidate has no unambiguous current rule-set version: {error:?}")
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
pub(crate) fn adopt_rows(
    rows: CandidateRows,
    facts: &ColdLoadFacts,
    acknowledged: &[AdoptionLimit],
) -> Result<RootOwner> {
    let owner = install_rows(rows)?;
    owner
        .adopt_experimental(facts, acknowledged)
        .context("adopt the memory-v1 root under the experimental grade")?;
    // memory—v1 §4.9: install the aggregated route-metadata registry before any
    // formal evaluation; an uninstalled registry refuses every evaluation.
    owner
        .install_registry(&registry_declarations())
        .context("install the memory-v1 resource registry")?;
    Ok(owner)
}

// memory—v1 §4.9: aggregate the adapted route metadata of every service into
// registry declarations. Today only TrustGraph ships adapted routes.
fn registry_declarations() -> Vec<RegistryDeclaration> {
    let mut by_resource: BTreeMap<&'static str, BTreeSet<&'static str>> = BTreeMap::new();
    for declaration in astral_trustgraph::api::permission_check::MEMORY_V1_ROUTE_DECLARATIONS {
        by_resource
            .entry(declaration.resource)
            .or_default()
            .insert(declaration.action);
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
pub(crate) fn assemble(
    owner: RootOwner,
    config: AppConfig,
    credentials: MemoryV1FileCredentials,
) -> MemoryV1Composition {
    let engine = Arc::new(PolicyEngine::new());
    let trustgraph = build_router(
        build_memory_v1_offline_app_state(config.clone(), engine),
        RouterIntegrationConfig::disabled(),
    );
    let authenticator = MemoryV1CredentialAuthenticator::new(Arc::new(credentials));
    MemoryV1Composition::new(
        owner,
        move |session| memory_v1_auth_router(session, authenticator, SESSION_LIFETIME_SECONDS),
        trustgraph,
        config,
    )
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
        "ASTRAL_MEMORY_V1_READY addr={addr} grade={:?} root_version={} rows={} unverified={unverified}",
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

/// memory—v1: Run the experimental real service until it is asked to stop.
///
/// Order: validate every input → load credentials → cold-load and adopt the root →
/// bind loopback → announce readiness → serve → drain HTTP → drop the composition
/// (and with it the root owner) last.
pub(crate) async fn run() -> Result<()> {
    let settings = ServiceSettings::from_env()?;
    let config =
        AppConfig::from_files_for_memory_v1_experimental("application", JwtValidationRole::Gateway)
            .context("load the memory-v1 experimental configuration")?;
    config
        .validate_memory_v1_experimental_for(JwtValidationRole::Identity)
        .context("validate the memory-v1 experimental configuration for Identity")?;
    require_local_transport(&config)?;
    let credentials = MemoryV1FileCredentials::load(&settings.credentials_path)
        .context("load the memory-v1 credentials file")?;
    if credentials.is_empty() {
        bail!("the memory-v1 credentials file defines no credentials");
    }

    let capture = capture_from_database(&config.database_url).await?;
    let owner = adopt_captured(capture, &settings.acknowledged)?;
    let root = owner.handle();
    require_serving_root(&root).context("memory-v1 serving root admission")?;

    let composition = assemble(owner, config, credentials);
    let listener = TcpListener::bind(settings.listen)
        .await
        .context("bind the memory-v1 experimental listener")?;
    let bound = listener.local_addr().context("read the bound address")?;
    if !bound.ip().is_loopback() {
        bail!("the memory-v1 experimental listener bound a non-loopback address");
    }
    let ready = readiness_line(&root, bound)?;
    tracing::info!(addr = %bound, "memory-v1 experimental service ready");
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
        let settings = ServiceSettings::from_lookup(lookup(&[(
            CREDENTIALS_FILE_ENV,
            "/private/credentials.json",
        )]))
        .unwrap();
        assert_eq!(settings.listen, "127.0.0.1:9001".parse().unwrap());
        assert!(settings.acknowledged.is_empty());

        for accepted in ["127.0.0.1:0", "127.0.0.1:9001", "[::1]:9001"] {
            let settings = ServiceSettings::from_lookup(lookup(&[
                (LISTEN_ADDR_ENV, accepted),
                (CREDENTIALS_FILE_ENV, "/private/credentials.json"),
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
