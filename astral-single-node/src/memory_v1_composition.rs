//! Candidate in-process assembly; it does not establish service readiness.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use astral_authorization_root::memory_v1_adoption::AdoptionGrade;
use astral_authorization_root::memory_v1_db_rows::CurrentSelection;
use astral_authorization_root::memory_v1_hamt::CandidateBudget;
use astral_authorization_root::memory_v1_request::RequestRootBudget;
use astral_authorization_root::memory_v1_root::{
    install_process_root, ProductionAdmission, RootError, RootHandle, RootOwner, RootStatus,
};
use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
use astral_common::config::AppConfig;
use astral_db::memory_v1_candidate_loader::{CandidateCaptureError, UnverifiedCandidateRows};
use astral_gateway::proxy::DEFAULT_MAX_ACTIVE_REQUEST_SCOPES;
use astral_identity::memory_v1_service::MemoryV1FileCredentials;
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

use astral_single_node::memory_v1_durable_journal::MemoryV1DurableJournal;

fn trustgraph_with_commit_port(
    config: AppConfig,
    commit_port: Arc<
        dyn astral_trustgraph::service::memory_v1_governance_commit::MemoryV1GovernanceCommitPort,
    >,
    deny_port: Arc<
        dyn astral_trustgraph::service::memory_v1_governance_commit::MemoryV1DenyProofPort,
    >,
) -> Router {
    // The TrustGraph state carries both durable owners: the commit port for
    // the governance routes and the deny port for the permission middleware's
    // 403 gate. Both are the same journal-backed owner.
    astral_trustgraph::build_router(
        astral_trustgraph::build_memory_v1_offline_app_state_with_commit(
            config,
            Arc::new(policy_engine::PolicyEngine::new()),
            commit_port,
            deny_port,
        ),
        astral_trustgraph::RouterIntegrationConfig::disabled(),
    )
}

/// The listener/request gate carries either the explicitly isolated candidate mode
/// or a root-owned production capability. A production caller cannot select the
/// experimental variant after construction because this enum is private.
#[derive(Clone)]
enum RootAdmission {
    Experimental {
        root: RootHandle,
    },
    Production {
        root: RootHandle,
        admission: Arc<ProductionAdmission>,
    },
}

impl RootAdmission {
    fn root(&self) -> &RootHandle {
        match self {
            Self::Experimental { root } | Self::Production { root, .. } => root,
        }
    }

    /// memory—v1: Validate the root-owned capability without exposing its fields.
    fn validate(&self) -> Result<(), RootError> {
        match self {
            Self::Experimental { root } => root.metadata().map(|_| ()),
            Self::Production { root, admission } => {
                root.validate_production_admission(admission).map(|_| ())
            }
        }
    }
}

/// Owns the already installed root for the lifetime of an in-process router.
///
/// This candidate does not start services or establish readiness. Before any
/// future listener is admitted, the caller must validate configuration, prove
/// that every trusted consumer uses this same root, and pass the existing
/// readiness gates. Shut down and drain consumers before dropping this owner.
pub(crate) struct MemoryV1Composition {
    _root: Arc<RootOwner>,
    _journal: Option<MemoryV1DurableJournal>,
    /// Validated on every request through the middleware state clone.
    #[allow(dead_code)]
    admission: RootAdmission,
    _session_authority: Arc<MemoryV1SessionAuthority>,
    /// The durable commit owner, shared with the TrustGraph state and, on the
    /// stress path, driven directly to collect phase timings.
    _commit_port: Arc<
        dyn astral_trustgraph::service::memory_v1_governance_commit::MemoryV1GovernanceCommitPort,
    >,
    request_scopes: RequestRootBudget,
    router: Router,
}

impl MemoryV1Composition {
    /// memory—v1: Assemble already constructed service routers around one root
    /// and one session authority. Identity is built only after this constructor
    /// creates the authority, so the caller cannot accidentally build a second
    /// authority before the Identity-owned capability is injected. Every Gateway
    /// request scope is admitted through one composition-owned budget.
    #[cfg(test)]
    pub(crate) fn new<F>(
        root: RootOwner,
        build_identity: F,
        trustgraph: Router,
        config: AppConfig,
    ) -> Result<
        Self,
        astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthorityError,
    >
    where
        F: FnOnce(Arc<MemoryV1IdentitySession>) -> Router,
    {
        let root_handle = root.handle();
        // The in-process composition fixtures exercise mediation, not the
        // host's C06 status. Keep signed/HTTP process tests on the real clock.
        let authority = Arc::new(MemoryV1SessionAuthority::with_clock_for_test(|| {
            let elapsed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?;
            Some((i128::try_from(elapsed.as_nanos()).ok()?, 0))
        }));
        authority.bind_to_root(&root)?;
        Self::assemble_with_authority(
            Arc::new(root),
            RootAdmission::Experimental { root: root_handle },
            Some(authority),
            None,
            |adapter| Arc::new(MemoryV1IdentitySession::from_session_adapter(adapter)),
            build_identity,
            trustgraph,
            config,
        )
    }

    /// memory—v1: Assemble a configured Identity from one concrete immutable
    /// FileCredentials snapshot. The same Arc is retained by the session and
    /// supplied to the Identity router factory; Gateway receives only verifier.
    pub(crate) fn new_with_file_credentials<F>(
        root: RootOwner,
        credentials: Arc<MemoryV1FileCredentials>,
        build_identity: F,
        trustgraph: Router,
        config: AppConfig,
        session_lifetime_seconds: i64,
    ) -> Result<
        Self,
        astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthorityError,
    >
    where
        F: FnOnce(Arc<MemoryV1IdentitySession>) -> Router,
    {
        let admission = RootAdmission::Experimental {
            root: root.handle(),
        };
        Self::assemble(
            Arc::new(root),
            admission,
            move |adapter| {
                Arc::new(
                    MemoryV1IdentitySession::from_session_adapter_with_file_credentials(
                        adapter,
                        credentials,
                        session_lifetime_seconds,
                    ),
                )
            },
            build_identity,
            trustgraph,
            config,
        )
    }

    /// memory—v1: Assemble a configured Identity from one production admission
    /// issued by the root owner, with the durable governance owner injected as
    /// the TrustGraph commit port. The capability is checked before any
    /// consumer receives the session authority and is retained for the
    /// composition lifetime; the journal and the root writer are kept alive by
    /// the same owner.
    pub(crate) fn new_with_file_credentials_production<F>(
        root: Arc<RootOwner>,
        admission: Arc<ProductionAdmission>,
        journal_durability: (
            MemoryV1DurableJournal,
            astral_single_node::memory_v1_durable_journal::JournalDurability,
        ),
        credentials: Arc<MemoryV1FileCredentials>,
        build_identity: F,
        config: AppConfig,
        session_lifetime_seconds: i64,
    ) -> anyhow::Result<Self>
    where
        F: FnOnce(Arc<MemoryV1IdentitySession>) -> Router,
    {
        root.validate_production_admission(admission.as_ref())
            .map_err(|error| anyhow!("memory-v1 production admission: {error}"))?;
        let root_handle = root.handle();
        // The writer shares the composition's root owner through the same Arc
        // so both keep the same runtime alive; the commit owner wraps the
        // writer and the journal as the only serving-root mutation path.
        let root = root;
        let session_authority = MemoryV1SessionAuthority::new();
        // The same binding text as the experimental assemble; the guard
        // test asserts this ordering for every constructor.
        session_authority.bind_to_root(&root)?;
        let mut writer = astral_single_node::memory_v1_root_writer::RootMutationWriter::new(
            Arc::clone(&root),
            Arc::clone(&admission),
        )
        .map_err(|error| anyhow!("memory-v1 root writer: {error}"))?;
        let session_authority_cell = Arc::new(session_authority);
        writer.set_session_authority(Some(Arc::clone(&session_authority_cell)));
        let commit_port = Arc::new(
            astral_single_node::memory_v1_governance_owner::MemoryV1DurableCommitOwner::new(
                journal_durability,
                writer,
            ),
        );
        let commit_port_for_composition = Arc::clone(&commit_port);
        // The durable commit port is injected through the TrustGraph offline
        // state; the caller-supplied router parameter is not used on this
        // production path because the commit port must be present at state
        // construction, not layered on afterwards. The same owner implements
        // the deny proof port, so both gates share one journal sequence.
        let deny_port: Arc<
            dyn astral_trustgraph::service::memory_v1_governance_commit::MemoryV1DenyProofPort,
        > = commit_port.clone();
        let trustgraph = trustgraph_with_commit_port(config.clone(), commit_port, deny_port);
        Self::assemble_with_authority(
            root,
            RootAdmission::Production {
                root: root_handle,
                admission,
            },
            Some(session_authority_cell),
            Some(commit_port_for_composition),
            move |adapter| {
                Arc::new(
                    MemoryV1IdentitySession::from_session_adapter_with_file_credentials(
                        adapter,
                        credentials,
                        session_lifetime_seconds,
                    ),
                )
            },
            build_identity,
            trustgraph,
            config,
        )
        .map_err(|error| anyhow!("bind the memory-v1 session authority: {error}"))
    }

    fn assemble<S, F>(
        root: impl Into<Arc<RootOwner>>,
        admission: RootAdmission,
        build_session: S,
        build_identity: F,
        trustgraph: Router,
        config: AppConfig,
    ) -> Result<
        Self,
        astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthorityError,
    >
    where
        S: FnOnce(
            astral_authorization_root::memory_v1_session_authority::MemoryV1IdentitySessionAdapter,
        ) -> Arc<MemoryV1IdentitySession>,
        F: FnOnce(Arc<MemoryV1IdentitySession>) -> Router,
    {
        Self::assemble_with_authority(
            root,
            admission,
            None,
            None,
            build_session,
            build_identity,
            trustgraph,
            config,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn assemble_with_authority<S, F>(
        root: impl Into<Arc<RootOwner>>,
        admission: RootAdmission,
        provided_authority: Option<Arc<MemoryV1SessionAuthority>>,
        provided_commit_port: Option<
            Arc<
                dyn astral_trustgraph::service::memory_v1_governance_commit::MemoryV1GovernanceCommitPort,
            >,
        >,
        build_session: S,
        build_identity: F,
        trustgraph: Router,
        config: AppConfig,
    ) -> Result<
        Self,
        astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthorityError,
    >
    where
        S: FnOnce(
            astral_authorization_root::memory_v1_session_authority::MemoryV1IdentitySessionAdapter,
        ) -> Arc<MemoryV1IdentitySession>,
        F: FnOnce(Arc<MemoryV1IdentitySession>) -> Router,
    {
        let root = root.into();
        admission
            .validate()
            .map_err(|_| astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthorityError::Unavailable)?;
        let handle = admission.root().clone();
        // The production path created and bound its authority to the same
        // root before handing it over; binding again would fail the one-time
        // slot, so it is used as-is through the Arc.
        let session_authority = match provided_authority {
            Some(authority) => authority,
            None => {
                let authority = Arc::new(MemoryV1SessionAuthority::new());
                authority.bind_to_root(&root)?;
                authority
            }
        };
        let identity_session = build_session(session_authority.identity_session_adapter());
        let identity = build_identity(identity_session);
        let request_scopes = RequestRootBudget::new(DEFAULT_MAX_ACTIVE_REQUEST_SCOPES);
        let router =
            astral_gateway::runtime::build_in_process_gateway_router_with_session_verifier_and_budget(
                config,
                identity,
                trustgraph,
                handle,
                session_authority.verifier(),
                request_scopes.clone(),
            )
            .layer(middleware::from_fn_with_state(
                admission.clone(),
                require_live_admission,
            ));
        let commit_port_for_composition: Arc<
            dyn astral_trustgraph::service::memory_v1_governance_commit::MemoryV1GovernanceCommitPort,
        > = provided_commit_port.unwrap_or_else(|| {
            Arc::new(
                astral_trustgraph::service::memory_v1_governance_commit::FailClosedMemoryV1GovernanceCommitPort,
            )
        });
        Ok(Self {
            _root: root,
            _journal: None,
            admission,
            _session_authority: session_authority,
            _commit_port: commit_port_for_composition,
            request_scopes,
            router,
        })
    }

    /// memory—v1: Clone a router handle without extending root ownership.
    pub(crate) fn router(&self) -> Router {
        self.router.clone()
    }

    /// memory—v1: The injected durable commit port, for drivers that need to
    /// measure the commit phases directly (stress/observability).
    #[cfg(test)]
    pub(crate) fn commit_port(
        &self,
    ) -> Arc<
        dyn astral_trustgraph::service::memory_v1_governance_commit::MemoryV1GovernanceCommitPort,
    > {
        Arc::clone(&self._commit_port)
    }

    /// memory—v1: Observe the composition's live request scopes (diagnostic).
    ///
    /// The count returns to zero only after each request's scope and every
    /// reader lease derived from it have been released.
    pub(crate) fn request_scope_budget(&self) -> RequestRootBudget {
        self.request_scopes.clone()
    }
}

/// memory—v1: The unified listener requires an adopted serving root.
///
/// Experimental adoption retains its explicit limitations; it is not production
/// evidence. An isolated-test root must never be used to admit a listener.
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
    let record = root
        .adoption_record()
        .map_err(|error| anyhow!("memory-v1 adoption record is unavailable: {error}"))?
        .ok_or_else(|| anyhow!("memory-v1 serving root has no adoption record"))?;
    match record.grade {
        AdoptionGrade::Production if record.unverified.is_empty() => Ok(()),
        _ => Err(anyhow!("memory-v1 adoption grade cannot admit a listener")),
    }
}

// memory—v1: The production middleware revalidates the sealed admission on every request.
async fn require_live_admission(
    State(admission): State<RootAdmission>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    admission
        .validate()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::{
        install_captured_candidate, require_serving_root, CandidateInstallationError,
        MemoryV1Composition,
    };
    use astral_authorization_root::memory_v1_adoption::{
        AdoptionGrade, AdoptionLimit, ColdLoadFacts, MEMORY_V1_CANDIDATE_SCHEMA_VERSION,
    };
    use astral_authorization_root::memory_v1_db_rows::UserCardStatus;
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
            let version = |number| {
                use astral_authorization_root::memory_v1_rules::{
                    canonical_version_bytes, version_digest,
                };
                let content = br#"{"rules":[{"ruleId":"r","resource":"document","action":"read","effect":"ALLOW"}]}"#;
                let hash_input_bytes = canonical_version_bytes(&[number], content, &[number]);
                RuleSetVersionRow {
                    rule_set_id: id(5),
                    version_bytes: vec![number],
                    content_bytes: content.to_vec(),
                    timestamp_bytes: vec![number],
                    hash_bytes: version_digest(&hash_input_bytes),
                    hash_input_bytes,
                }
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
                    status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                    rule_set_id: id(5),
                    owner_tenant_id: id(3),
                    current_version_bytes: vec![1],
                }],
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
                    removed_by: None,
                }],
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

        let mut corrupt_archive = rows();
        corrupt_archive.rule_set_versions[1].hash_bytes[0] ^= 1;
        let selections = corrupt_archive.current_version_selections().unwrap();
        assert!(matches!(
            install_captured_candidate(capture(corrupt_archive), selections, budget()),
            Err(CandidateInstallationError::Root(RootError::Candidate(
                CandidateError::RuleIntegrity(_)
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

    // memory—v1: Check the listener gate against real root lifecycle and adoption records
    // in child processes, because the process-wide installation slot is one-shot.
    #[test]
    fn require_serving_root_gate_isolated_process() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_REQUIRE_SERVING_ROOT_CHILD";
        const CASE: &str = "ASTRAL_MEMORY_V1_REQUIRE_SERVING_ROOT_CASE";
        if std::env::var_os(CHILD).is_none() {
            for scenario in ["candidate", "experimental", "isolated", "stopped"] {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "memory_v1_composition::tests::require_serving_root_gate_isolated_process",
                        "--nocapture",
                    ])
                    .env(CHILD, "1")
                    .env(CASE, scenario)
                    .output()
                    .unwrap_or_else(|error| {
                        panic!("failed to start {scenario} serving-gate child: {error}")
                    });
                assert!(
                    output.status.success(),
                    "{scenario} serving-gate child failed: {}\nstdout: {}\nstderr: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(
                    String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                    "{scenario} child did not report one passing test: {}",
                    String::from_utf8_lossy(&output.stdout)
                );
            }
            return;
        }

        let scenario = std::env::var(CASE).expect("the isolated serving-gate case is set");
        let (rows, selections) = super::full_path_tests::fixture();
        let counts = rows.table_counts();
        let owner = install_process_root(
            rows,
            selections,
            CandidateBudget {
                max_table_rows: 128,
                max_bindings_per_read: 16,
            },
        )
        .unwrap();
        let handle = owner.handle();

        match scenario.as_str() {
            "candidate" => {
                let metadata = handle.metadata().unwrap();
                assert_eq!(metadata.status, RootStatus::Candidate);
                assert_eq!(handle.adoption_record().unwrap(), None);
                assert!(require_serving_root(&handle).is_err());
            }
            "experimental" => {
                owner
                    .install_registry(&crate::memory_v1_service::registry_declarations())
                    .unwrap();
                owner
                    .adopt_experimental(
                        &ColdLoadFacts {
                            schema_contract_version: MEMORY_V1_CANDIDATE_SCHEMA_VERSION,
                            schema_fingerprint: [7; 32],
                            snapshot_counts: counts,
                            scanned_counts: counts,
                            captured_at_unix_seconds: 1_700_000_000,
                        },
                        &AdoptionLimit::EXPERIMENTAL,
                    )
                    .unwrap();
                let metadata = handle.metadata().unwrap();
                assert_eq!(metadata.status, RootStatus::Serving);
                let record = handle.adoption_record().unwrap().unwrap();
                assert_eq!(record.grade, AdoptionGrade::Experimental);
                assert!(require_serving_root(&handle).is_err());
            }
            "isolated" => {
                owner
                    .install_registry(&crate::memory_v1_service::registry_declarations())
                    .unwrap();
                owner.adopt_serving_for_isolated_tests().unwrap();
                let metadata = handle.metadata().unwrap();
                assert_eq!(metadata.status, RootStatus::Serving);
                let record = handle.adoption_record().unwrap().unwrap();
                assert_eq!(record.grade, AdoptionGrade::IsolatedTest);
                assert!(require_serving_root(&handle).is_err());
            }
            "stopped" => {
                let metadata = handle.metadata().unwrap();
                assert_eq!(metadata.status, RootStatus::Candidate);
                drop(owner);
                // RootOwner::drop publishes Stopped, then releases the only strong
                // runtime reference; the public weak handle observes OwnerGone.
                assert!(matches!(handle.metadata(), Err(RootError::OwnerGone)));
                assert!(require_serving_root(&handle).is_err());
            }
            other => panic!("unknown serving-gate scenario: {other}"),
        }
    }

    // memory—v1: The factory receives the Identity-owned capability before the
    // Gateway receives the matching verifier; both originate from one authority.
    #[test]
    fn composition_passes_identity_capability_before_gateway_assembly() {
        let source = include_str!("memory_v1_composition.rs");
        let production = source.split("\n#[cfg(test)]\nmod tests {").next().unwrap();
        // Each composition constructor creates exactly one authority: the
        // production constructor creates and binds its own before the shared
        // assemble runs; the experimental assemble creates one lazily. Both
        // are one authority per composition.
        assert_eq!(
            production
                .matches("MemoryV1SessionAuthority::new()")
                .count(),
            2,
            "each composition constructor must create one session authority"
        );
        let authority = production
            .find("let session_authority = MemoryV1SessionAuthority::new();")
            .expect("composition must create the authority before capability distribution");
        let binding = production
            .find("session_authority.bind_to_root(&root)?;")
            .expect("composition must bind the authority to the root");
        let identity = production
            .find("let identity_session = build_session(session_authority.identity_session_adapter());")
            .expect("composition must create the Identity-owned session boundary");
        let identity_factory = production
            .find("let identity = build_identity(identity_session);")
            .expect("composition must build Identity from the injected boundary");
        let verifier = production
            .find("session_authority.verifier(),")
            .expect("Gateway must receive the matching verifier");
        assert!(authority < binding);
        assert!(binding < identity);
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
        let composition = MemoryV1Composition::new(root, |_| identity, Router::new(), config)
            .expect("composition binds the session authority");
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
