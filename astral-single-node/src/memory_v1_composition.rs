//! Candidate in-process assembly; it does not establish service readiness.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use astral_authorization_root::memory_v1_db_rows::CurrentSelection;
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_request::RequestRootBudget;
use astral_authorization_root::memory_v1_root::{
    install_process_root, RootError, RootHandle, RootOwner, RootStatus,
};
use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
use astral_common::config::AppConfig;
use astral_db::memory_v1_candidate_loader::{CandidateCaptureError, UnverifiedCandidateRows};
use astral_gateway::proxy::DEFAULT_MAX_ACTIVE_REQUEST_SCOPES;
use astral_identity::MemoryV1IdentitySession;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::Router;

/// Capture measurements only; they do not establish provenance or coverage.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CandidateCaptureDiagnostics {
    pub(crate) row_count: usize,
    pub(crate) field_bytes: usize,
}

/// Owns the one installed candidate together with the capture measurements.
#[allow(dead_code)]
pub(crate) struct InstalledCandidate {
    pub(crate) root: RootOwner,
    pub(crate) diagnostics: CandidateCaptureDiagnostics,
}

/// Failure before or during candidate installation; no fallback root is created.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum CandidateInstallationError {
    Capture(CandidateCaptureError),
    Root(RootError),
}

/// memory—v1: Install captured rows as the sole process-local candidate root.
///
/// The caller provides the capture result, selections and root budget explicitly.
/// Measurements are diagnostic only, including when they describe an empty capture;
/// success does not establish completeness, trust, readiness or authorization.
#[allow(dead_code)]
pub(crate) fn install_captured_candidate(
    capture: Result<UnverifiedCandidateRows, CandidateCaptureError>,
    selections: Vec<CurrentSelection>,
    budget: CandidateBudget,
) -> Result<InstalledCandidate, CandidateInstallationError> {
    let UnverifiedCandidateRows {
        rows,
        row_count,
        field_bytes,
        report,
    } = capture.map_err(CandidateInstallationError::Capture)?;
    let root =
        install_process_root(rows, selections, budget).map_err(CandidateInstallationError::Root)?;
    let _ = report;
    Ok(InstalledCandidate {
        root,
        diagnostics: CandidateCaptureDiagnostics {
            row_count,
            field_bytes,
        },
    })
}

/// Owns the already installed root for the lifetime of an in-process router.
///
/// This candidate does not start services or establish readiness. Before any
/// future listener is admitted, the caller must validate configuration, prove
/// that every trusted consumer uses this same root, and pass the existing
/// readiness gates. Shut down and drain consumers before dropping this owner.
pub(crate) struct MemoryV1Composition {
    _root: RootOwner,
    _session_authority: MemoryV1SessionAuthority,
    request_scopes: RequestRootBudget,
    router: Router,
}

impl MemoryV1Composition {
    /// memory—v1: Assemble already constructed service routers around one root
    /// and one session authority. Identity is built only after this constructor
    /// creates the authority, so the caller cannot accidentally build a second
    /// authority before the Identity-owned capability is injected. Every Gateway
    /// request scope is admitted through one composition-owned budget.
    pub(crate) fn new<F>(
        root: RootOwner,
        build_identity: F,
        trustgraph: Router,
        config: AppConfig,
    ) -> Self
    where
        F: FnOnce(Arc<MemoryV1IdentitySession>) -> Router,
    {
        let handle = root.handle();
        let session_authority = MemoryV1SessionAuthority::new();
        let identity_session = Arc::new(MemoryV1IdentitySession::from_session_adapter(
            session_authority.identity_session_adapter(),
        ));
        let identity = build_identity(identity_session);
        let request_scopes = RequestRootBudget::new(DEFAULT_MAX_ACTIVE_REQUEST_SCOPES);
        let router =
            astral_gateway::runtime::build_in_process_gateway_router_with_session_verifier_and_budget(
                config,
                identity,
                trustgraph,
                handle.clone(),
                session_authority.verifier(),
                request_scopes.clone(),
            )
            .layer(middleware::from_fn_with_state(handle, require_live_root));
        Self {
            _root: root,
            _session_authority: session_authority,
            request_scopes,
            router,
        }
    }

    /// memory—v1: Clone a router handle without extending root ownership.
    pub(crate) fn router(&self) -> Router {
        self.router.clone()
    }

    /// memory—v1: Observe the composition's live request scopes (diagnostic).
    ///
    /// The count returns to zero only after each request's scope and every
    /// reader lease derived from it have been released.
    pub(crate) fn request_scope_budget(&self) -> RequestRootBudget {
        self.request_scopes.clone()
    }
}

/// memory—v1: A listener is admissible only after a verified serving root exists.
///
/// The current database capture is intentionally unverified, so this gate returns
/// an error until a verifier-owned `AdoptionEvidence` path is wired in.
pub(crate) fn require_serving_root(root: &RootHandle) -> Result<()> {
    let metadata = root
        .metadata()
        .map_err(|error| anyhow!("memory-v1 root is unavailable: {error}"))?;
    if metadata.status != RootStatus::Serving {
        return Err(anyhow!(
            "memory-v1 serving root is not adopted; status={:?}",
            metadata.status
        ));
    }
    Ok(())
}

// memory—v1: Reject requests if the composition no longer owns a readable root.
async fn require_live_root(
    State(root): State<RootHandle>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    root.metadata()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::{
        install_captured_candidate, require_serving_root, CandidateInstallationError,
        MemoryV1Composition,
    };
    use astral_authorization_root::memory_v1_db_rows::{
        BindingLayer, BindingRow, CandidateRows, CurrentSelection, IdentityCardRow, RuleSetRow,
        RuleSetVersionRow, Table, TenantRow, UserCardRow, UserRow, ValidationError,
    };
    use astral_authorization_root::memory_v1_hamt::{CandidateBudget, CandidateError};
    use astral_authorization_root::memory_v1_request::{
        RequestRootAccessError, RequestRootExtension,
    };
    use astral_authorization_root::memory_v1_root::{
        install_process_root, process_root_handle, RootError, RootStatus,
    };
    use astral_authorization_root::memory_v1_rules::{MemoryV1OwnerScope, MemoryV1TenantScope};
    use astral_common::config::AppConfig;
    use astral_db::memory_v1_candidate_loader::{CandidateCaptureError, UnverifiedCandidateRows};
    use axum::body::Body;
    use axum::extract::Extension;
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use std::time::Duration;
    use tokio::sync::{mpsc, oneshot};
    use tokio::time::timeout;
    use tower::ServiceExt;

    // memory—v1: Exercise the real one-time process slot in a separate test process.
    #[test]
    fn captured_candidate_installation_isolated_process() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_CANDIDATE_INSTALL_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            // The child's output is captured, never inherited: an inherited summary line
            // would be counted a second time by any runner that sums `test result:` lines.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "memory_v1_composition::tests::captured_candidate_installation_isolated_process",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .expect("failed to start isolated test process");
            assert!(
                output.status.success(),
                "isolated test process failed: {}\nstdout: {}\nstderr: {}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            return;
        }

        // memory—v1: Construct fixed candidate identifiers for this isolated test.
        fn id(value: u8) -> [u8; 16] {
            [value; 16]
        }

        // memory—v1: Build two versions so the caller's selection is observable.
        fn rows() -> CandidateRows {
            let version = |number| RuleSetVersionRow {
                rule_set_id: id(5),
                version_bytes: vec![number],
                content_bytes: vec![number],
                timestamp_bytes: vec![number],
                hash_input_bytes: vec![number],
                hash_bytes: vec![number],
            };
            CandidateRows {
                users: vec![UserRow { user_id: id(1) }],
                identity_cards: vec![IdentityCardRow {
                    identity_card_id: id(2),
                    user_id: id(1),
                }],
                tenants: vec![TenantRow {
                    tenant_id: id(3),
                    parent_tenant_id: None,
                }],
                user_cards: vec![UserCardRow {
                    user_card_id: id(4),
                    user_id: id(1),
                    tenant_id: id(3),
                    status: UserCardStatus::Active,
                }],
                rule_sets: vec![RuleSetRow {
                    rule_set_id: id(5),
                    owner_tenant_id: id(3),
                    current_version_bytes: Vec::new(),                }],
                rule_set_versions: vec![version(1), version(2)],
                bindings: vec![BindingRow {
                    binding_id: id(6),
                    user_card_id: id(4),
                    rule_set_id: id(5),
                    binding_layer: BindingLayer::Base,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::default(),
                    tenant_scope: MemoryV1TenantScope::default(),
                    removed_at: None,
                    removed_by: None,                }],
                ..CandidateRows::default()
            }
        }

        // memory—v1: Supply diagnostic measurements without invoking the database.
        fn capture(rows: CandidateRows) -> Result<UnverifiedCandidateRows, CandidateCaptureError> {
            Ok(UnverifiedCandidateRows {
                rows,
                row_count: 8,
                field_bytes: 123,
                report: None,
            })
        }

        // memory—v1: Bound the candidate and its binding reads for the fixture.
        fn budget() -> CandidateBudget {
            CandidateBudget {
                max_table_rows: 8,
                max_bindings_per_read: 1,
            }
        }

        assert!(matches!(
            process_root_handle(),
            Err(RootError::NotInstalled)
        ));
        assert!(matches!(
            install_captured_candidate(Err(CandidateCaptureError::Deadline), vec![], budget()),
            Err(CandidateInstallationError::Capture(
                CandidateCaptureError::Deadline
            ))
        ));
        assert!(matches!(
            process_root_handle(),
            Err(RootError::NotInstalled)
        ));

        let mut missing_reference = rows();
        missing_reference.user_cards[0].tenant_id = id(99);
        assert!(matches!(
            install_captured_candidate(capture(missing_reference), vec![], budget()),
            Err(CandidateInstallationError::Root(RootError::Candidate(
                CandidateError::Rows(ValidationError::MissingReference {
                    table: Table::UserCard,
                    field: "tenant_id",
                    ..
                })
            )))
        ));
        assert!(matches!(
            process_root_handle(),
            Err(RootError::NotInstalled)
        ));

        assert!(matches!(
            install_captured_candidate(
                capture(rows()),
                vec![CurrentSelection {
                    rule_set_id: id(5),
                    version_bytes: vec![3],
                }],
                budget(),
            ),
            Err(CandidateInstallationError::Root(RootError::Candidate(
                CandidateError::UnknownVersion { .. }
            )))
        ));
        assert!(matches!(
            process_root_handle(),
            Err(RootError::NotInstalled)
        ));

        assert!(matches!(
            install_captured_candidate(
                capture(rows()),
                vec![],
                CandidateBudget {
                    max_table_rows: 7,
                    ..budget()
                },
            ),
            Err(CandidateInstallationError::Root(RootError::Candidate(
                CandidateError::RowBudgetExceeded { max: 7 }
            )))
        ));
        assert!(matches!(
            process_root_handle(),
            Err(RootError::NotInstalled)
        ));

        let installed = install_captured_candidate(
            capture(rows()),
            vec![CurrentSelection {
                rule_set_id: id(5),
                version_bytes: vec![1],
            }],
            budget(),
        )
        .unwrap_or_else(|error| panic!("candidate installation failed: {error:?}"));
        assert_eq!(installed.diagnostics.row_count, 8);
        assert_eq!(installed.diagnostics.field_bytes, 123);
        let handle = installed.root.handle();
        let metadata = handle.metadata().unwrap();
        assert_eq!(metadata.status, RootStatus::Candidate);
        assert!(require_serving_root(&handle).is_err());
        assert_eq!(handle.metadata().unwrap().status, RootStatus::Candidate);
        assert_eq!(metadata.row_count, 8);
        assert_eq!(metadata.budget, budget());
        let selected = handle
            .read_card(id(4), |context| {
                context.bindings[0]
                    .selected
                    .map(|version| version.version_bytes.clone())
            })
            .unwrap();
        assert_eq!(selected.value, Some(vec![1]));
        assert_eq!(process_root_handle().unwrap().metadata().unwrap(), metadata);

        assert!(matches!(
            install_captured_candidate(capture(rows()), vec![], budget()),
            Err(CandidateInstallationError::Root(
                RootError::AlreadyInstalled
            ))
        ));
        assert_eq!(handle.metadata().unwrap(), metadata);
        drop(installed);
        assert!(matches!(process_root_handle(), Err(RootError::OwnerGone)));
        assert!(require_serving_root(&handle).is_err());
        assert!(matches!(
            install_captured_candidate(capture(rows()), vec![], budget()),
            Err(CandidateInstallationError::Root(
                RootError::AlreadyInstalled
            ))
        ));
    }

    // memory—v1: The factory receives the Identity-owned capability before the
    // Gateway receives the matching verifier; both originate from one authority.
    #[test]
    fn composition_passes_identity_capability_before_gateway_assembly() {
        let source = include_str!("memory_v1_composition.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert_eq!(
            production
                .matches("MemoryV1SessionAuthority::new()")
                .count(),
            1,
            "composition must create one session authority"
        );
        let authority = production
            .find("let session_authority = MemoryV1SessionAuthority::new();")
            .expect("composition must create the authority before capability distribution");
        let identity = source
            .find("let identity_session = Arc::new(MemoryV1IdentitySession::from_session_adapter(")
            .expect("composition must create the Identity-owned session boundary");
        let identity_factory = source
            .find("let identity = build_identity(identity_session);")
            .expect("composition must build Identity from the injected boundary");
        let verifier = source
            .find("session_authority.verifier(),")
            .expect("Gateway must receive the matching verifier");
        assert!(authority < identity);
        assert!(identity < identity_factory);
        assert!(identity_factory < verifier);
    }

    // memory—v1: Exercise cancellation, request isolation and owner loss through the Gateway.
    #[tokio::test]
    async fn gateway_request_scopes_follow_composition_lifecycle() {
        let root = install_process_root(
            CandidateRows::default(),
            vec![],
            CandidateBudget {
                max_table_rows: 16,
                max_bindings_per_read: 4,
            },
        )
        .unwrap();
        let handle = root.handle();
        let count = Arc::new(AtomicUsize::new(0));
        let downstream_count = Arc::clone(&count);
        let (captured_tx, mut captured_rx) = mpsc::unbounded_channel();
        let identity = Router::new().route(
            "/api/v1/auth/sessions",
            post(move |Extension(root): Extension<RequestRootExtension>| {
                let count = Arc::clone(&downstream_count);
                let captured_tx = captured_tx.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    let first = root
                        .with_reader(|reader| (reader.request_id(), reader.metadata()))
                        .unwrap();
                    let second = root
                        .clone()
                        .with_reader(|reader| (reader.request_id(), reader.metadata()))
                        .unwrap();
                    assert_eq!(first, second);
                    assert_eq!(first.1.status, RootStatus::Candidate);
                    let (release_tx, release_rx) = oneshot::channel();
                    captured_tx.send((root.clone(), release_tx)).unwrap();
                    if release_rx.await.is_err() || root.with_reader(|_| ()).is_err() {
                        return StatusCode::SERVICE_UNAVAILABLE;
                    }
                    // This public fixture response is not an authorization decision.
                    StatusCode::NO_CONTENT
                }
            }),
        );
        let mut config = AppConfig::default();
        config.gateway.hmac_secret = uuid::Uuid::new_v4().to_string();
        let composition = MemoryV1Composition::new(root, |_| identity, Router::new(), config);
        let router = composition.router();
        let request = || {
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/sessions")
                .extension(axum::extract::ConnectInfo(SocketAddr::from((
                    Ipv4Addr::LOCALHOST,
                    12345,
                ))))
                .body(Body::empty())
                .unwrap()
        };

        assert!(handle.metadata().is_ok());
        let first_task = tokio::spawn(router.clone().oneshot(request()));
        let (first, _first_release) = timeout(Duration::from_secs(5), captured_rx.recv())
            .await
            .expect("first request did not reach the downstream")
            .expect("downstream capture channel closed");
        let second_task = tokio::spawn(router.clone().oneshot(request()));
        let (second, second_release) = timeout(Duration::from_secs(5), captured_rx.recv())
            .await
            .expect("second request did not reach the downstream")
            .expect("downstream capture channel closed");

        let first_id = first.with_reader(|reader| reader.request_id()).unwrap();
        let second_id = second.with_reader(|reader| reader.request_id()).unwrap();
        assert_ne!(first_id, second_id);
        assert_eq!(count.load(Ordering::SeqCst), 2);

        first_task.abort();
        assert!(first_task.await.unwrap_err().is_cancelled());
        assert!(matches!(
            first.with_reader(|_| ()),
            Err(RequestRootAccessError::ScopeEnded)
        ));
        assert_eq!(
            second.with_reader(|reader| reader.request_id()).unwrap(),
            second_id
        );
        second_release.send(()).unwrap();
        let response = timeout(Duration::from_secs(5), second_task)
            .await
            .expect("second request did not finish")
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(matches!(
            second.with_reader(|_| ()),
            Err(RequestRootAccessError::ScopeEnded)
        ));

        let third_task = tokio::spawn(router.clone().oneshot(request()));
        let (third, third_release) = timeout(Duration::from_secs(5), captured_rx.recv())
            .await
            .expect("third request did not reach the downstream")
            .expect("downstream capture channel closed");
        assert!(third.with_reader(|_| ()).is_ok());
        assert_eq!(count.load(Ordering::SeqCst), 3);
        drop(composition);
        assert!(matches!(handle.metadata(), Err(RootError::OwnerGone)));
        assert!(matches!(
            third.with_reader(|_| ()),
            Err(RequestRootAccessError::Root(RootError::OwnerGone))
        ));
        third_release.send(()).unwrap();
        let response = timeout(Duration::from_secs(5), third_task)
            .await
            .expect("third request did not finish")
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(matches!(
            third.with_reader(|_| ()),
            Err(RequestRootAccessError::ScopeEnded)
        ));
        let response = router.oneshot(request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }
}

// memory—v1: The isolated full-path lifecycle acceptance test. Declared after the
// unit tests so source guards that slice this file at its first `#[cfg(test)]`
// keep the complete production region.
#[cfg(test)]
#[path = "memory_v1_full_path_tests.rs"]
pub(crate) mod full_path_tests;
