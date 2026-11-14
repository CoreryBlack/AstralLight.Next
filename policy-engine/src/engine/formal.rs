//! memory—v1 fail-closed formal authorization entry points.
//!
//! The legacy CURRENT V6/V7 execution chain (AUTHN → CARD_CONTEXT → ownership
//! → GlobalAdmin → ORG_SCOPE admission → published CARD evidence, with its
//! authorization-fence proofs and ALLOW-time rechecks) has been physically
//! retired per `memory-v1-retire-legacy-read-20261112` (Rust 规范 §15.10)。
//! Positive authorization is reserved for the memory-v1 shared root; until that
//! contract completes adoption, every formal evaluation fails closed and no
//! repository method is consulted.

use astral_types::{Effect, EvaluationStep, PolicyContext, PolicyDecision};

use super::ports::RuleRepository;
use super::PolicyEngine;
use crate::hit_stats::TimingBreakdown;

tokio::task_local! {
    static REQUEST_ROOT: astral_authorization_root::memory_v1_request::RequestRootExtension;
    static REQUEST_CANDIDATE_IDENTITY: Option<astral_types::memory_v1::CandidateIdentity>;
}

tokio::task_local! {
    static TEST_READER_ADDRESS: std::cell::Cell<Option<usize>>;
    static TEST_INSPECTION: std::cell::Cell<Option<crate::memory_v1_candidate::CandidateInspection>>;
}

// The formal signature still requires a repository, but this candidate path
// never uses legacy reads. Every port also fails closed if called accidentally.
struct RetiredRepository;

#[async_trait::async_trait]
impl RuleRepository for RetiredRepository {
    // memory—v1: Retired card lookups are unavailable.
    async fn check_card_active(
        &self,
        _: &PolicyContext,
    ) -> Result<bool, astral_types::PolicyError> {
        Err(astral_types::PolicyError::Repository("retired".into()))
    }

    // memory—v1: A legacy administrator marker cannot grant authority.
    async fn is_active_global_admin(&self, _: i64) -> Result<bool, astral_types::PolicyError> {
        Err(astral_types::PolicyError::Repository("retired".into()))
    }

    // memory—v1: Published legacy evidence is unavailable.
    async fn load_published_card_authorization(
        &self,
        _: &astral_types::PublishedCardEvidenceScope,
    ) -> Result<
        Option<std::sync::Arc<astral_types::PublishedCardAuthorization>>,
        astral_types::PolicyError,
    > {
        Err(astral_types::PolicyError::Repository("retired".into()))
    }

    // memory—v1: Legacy organization evidence is unavailable.
    async fn load_org_authorization(
        &self,
        _: &PolicyContext,
    ) -> Result<crate::OrgAuthorityRead, astral_types::PolicyError> {
        Err(astral_types::PolicyError::Repository("retired".into()))
    }
}

impl PolicyEngine {
    /// memory—v1: Evaluate one request through the fail-closed formal entry.
    ///
    /// The legacy V6/V7 gate-and-evidence chain is retired; the engine reads no
    /// repository state and always returns `AUTHORIZATION_PENDING`. Missing,
    /// stale, or retired evaluation capability never expands authority.
    pub async fn evaluate<R: RuleRepository>(
        &self,
        ctx: &PolicyContext,
        repo: &R,
    ) -> PolicyDecision {
        let _ = REQUEST_ROOT.try_with(|extension| {
            let outcome = extension.with_reader(|reader| {
                #[cfg(test)]
                let _ = TEST_READER_ADDRESS.try_with(|slot| {
                    slot.set(Some(std::ptr::from_ref(reader) as usize));
                });
                let identity = REQUEST_CANDIDATE_IDENTITY.try_with(|identity| *identity);
                if let Ok(Some(identity)) = identity {
                    let inspection = crate::memory_v1_candidate::inspect_typed_request_candidate(
                        reader, &identity,
                    );
                    #[cfg(test)]
                    let _ = TEST_INSPECTION.try_with(|slot| slot.set(Some(inspection)));
                    // Inspection outcomes are not authorization evidence or identity logs.
                    let _ = inspection;
                }
                reader.is_current()
            });
            let status = match outcome {
                Ok(Ok(true)) => "current_candidate",
                Ok(Ok(false)) => "changed",
                Ok(Err(_)) | Err(_) => "unavailable",
            };
            tracing::debug!(
                status,
                "memory-v1 request root observation; authorization pending"
            );
        });
        self.evaluate_with_admission(ctx, repo).await.decision
    }

    /// memory—v1: Evaluate using one explicit request-local candidate reader.
    ///
    /// The capability is scoped to this future and never stored on the engine or
    /// repository. It carries no identity or authorization evidence. Missing,
    /// expired, changed and readable roots all retain the formal pending result.
    pub async fn evaluate_with_request_root(
        &self,
        ctx: &PolicyContext,
        root: astral_authorization_root::memory_v1_request::RequestRootExtension,
    ) -> PolicyDecision {
        REQUEST_ROOT
            .scope(
                root,
                REQUEST_CANDIDATE_IDENTITY.scope(None, self.evaluate(ctx, &RetiredRepository)),
            )
            .await
    }

    /// memory—v1: Inspect an explicitly supplied candidate identity on the request reader.
    ///
    /// This input is not an authentication proof. The observation does not grant
    /// authority or alter the pending decision, and no identity is logged.
    pub async fn evaluate_with_request_root_and_candidate_identity(
        &self,
        ctx: &PolicyContext,
        root: astral_authorization_root::memory_v1_request::RequestRootExtension,
        identity: astral_types::memory_v1::CandidateIdentity,
    ) -> PolicyDecision {
        REQUEST_ROOT
            .scope(
                root,
                REQUEST_CANDIDATE_IDENTITY
                    .scope(Some(identity), self.evaluate(ctx, &RetiredRepository)),
            )
            .await
    }

    /// memory—v1: Evaluate one request against its request-lifecycle root reader.
    ///
    /// This is the memory—v1 formal decision entry. `root` must be the request's
    /// one scope extension and `session` the authority-verified facts bound to
    /// that same scope; identity comes only from the session, never from headers.
    /// The evaluation reads the reader's single phase, requires a `Serving` root,
    /// and rechecks root metadata and trusted time before `Allow`. Any root,
    /// session, scope, rule or time failure yields `Pending`; a complete phase
    /// without a matching confirmed allow (or with a matching deny) yields `Deny`.
    pub fn evaluate_memory_v1(
        &self,
        root: &astral_authorization_root::memory_v1_request::RequestRootExtension,
        session: &astral_authorization_root::memory_v1_session::RequestSessionExtension,
        request: &crate::memory_v1_formal::MemoryV1Request<'_>,
    ) -> crate::memory_v1_formal::MemoryV1Evaluation {
        let start = std::time::Instant::now();
        let evaluation = crate::memory_v1_formal::evaluate_memory_v1(root, session, request);
        let timing = TimingBreakdown {
            total_ns: start.elapsed().as_nanos() as u64,
            ..TimingBreakdown::default()
        };
        self.record_evaluation(
            evaluation.decision == crate::memory_v1_formal::MemoryV1Decision::Allow,
            &timing,
        );
        evaluation
    }

    /// memory—v1: Evaluate a request and retain the admission slot for the
    /// future memory-v1 positive path. The retired evaluator never certifies an
    /// admission, so `admission()` is always `None` for now. Existing callers
    /// keep receiving the serializable decision via `evaluate`.
    pub async fn evaluate_with_admission<R: RuleRepository>(
        &self,
        ctx: &PolicyContext,
        _repo: &R,
    ) -> crate::engine::PolicyEvaluation {
        let start = std::time::Instant::now();
        // Fail-closed: no gate walk, no evidence read, no fence proof, and no
        // dependency failure accounting — the retired engine has no dependency
        // reads to fail. The request is still counted as a completed
        // non-allowing evaluation for observability.
        let decision = Self::retired_evaluation_pending(ctx);
        let timing = TimingBreakdown {
            total_ns: start.elapsed().as_nanos() as u64,
            ..TimingBreakdown::default()
        };
        self.record_evaluation(false, &timing);
        crate::engine::PolicyEvaluation::without_admission(decision)
    }

    /// memory—v1: Build the auditable retirement decision for one request.
    fn retired_evaluation_pending(ctx: &PolicyContext) -> PolicyDecision {
        PolicyDecision {
            allowed: false,
            reason: "AUTHORIZATION_PENDING".to_owned(),
            matched_rule: Some("policy_engine:legacy_formal_evaluation_retired".to_owned()),
            audit_required: true,
            evaluation_path: vec![EvaluationStep {
                phase: "FORMAL_EVALUATION".to_owned(),
                result: Effect::Deny,
                detail: format!(
                    "legacy V6/V7 formal evaluation chain retired (memory—v1); fail-closed pending, resource={}",
                    ctx.resource.as_deref().unwrap_or("")
                ),
                matched_rule_id: None,
                source: None,
            }],
            matched_rule_id: None,
            condition_results: None,
            snapshot_version: None,
            org_provenance: None,
        }
    }

    /// Return the stable source category for an ALLOW decision.
    ///
    /// memory—v1: the retired evaluator never returns ALLOW, so this currently
    /// yields `None` for every decision the engine can produce; the classifier
    /// is kept for the memory-v1 positive path and existing callers.
    pub fn allow_source_phase(decision: &PolicyDecision) -> Option<&'static str> {
        if !decision.allowed {
            return None;
        }
        decision
            .evaluation_path
            .iter()
            .rev()
            .find(|step| step.result == astral_types::Effect::Allow)
            .and_then(|step| {
                if step.phase == "PUBLISHED_EVIDENCE" {
                    return match step.source.as_deref() {
                        Some("RULE_SET_BASE") | Some("RULE_SET_OVERLAY") | Some("RULE_SET") => {
                            Some("RULE_SET")
                        }
                        Some("DIRECT") => Some("DIRECT"),
                        Some("APPROVAL") => Some("APPROVAL"),
                        Some("DELEGATION") => Some("DELEGATION"),
                        _ => None,
                    };
                }
                match step.phase.as_str() {
                    "ORG_AUTHORITY" => Some("ORG_AUTHORITY"),
                    _ => None,
                }
            })
    }

    /// memory—v1: Simulated permission evaluation follows the same fail-closed
    /// formal entry; simulation can never mint an ALLOW the formal path would
    /// not mint.
    pub async fn simulate<R: RuleRepository>(
        &self,
        ctx: &PolicyContext,
        repo: &R,
    ) -> PolicyDecision {
        self.evaluate(ctx, repo).await
    }
}

#[cfg(test)]
mod request_root_tests {
    use astral_authorization_root::memory_v1_db_rows::UserCardStatus;
    use super::*;
    use crate::memory_v1_candidate::CandidateInspection;
    use astral_authorization_root::memory_v1_db_rows::{
        CandidateRows, IdentityCardRow, TenantRow, UserCardRow, UserRow,
    };
    use astral_authorization_root::memory_v1_hamt::CandidateBudget;
    use astral_authorization_root::memory_v1_request::{RequestRootAccessError, RequestRootScope};
    use astral_authorization_root::memory_v1_root::install_process_root;
    use astral_types::memory_v1::{CandidateIdentity, MemoryId};
    use std::cell::Cell;

    // memory—v1: Construct explicit byte identities independently of legacy IDs.
    fn identity(user: u8, card: u8, tenant: u8, identity_card: u8) -> CandidateIdentity {
        CandidateIdentity {
            user_id: MemoryId::from_bytes([user; 16]),
            user_card_id: MemoryId::from_bytes([card; 16]),
            tenant_id: MemoryId::from_bytes([tenant; 16]),
            identity_card_id: MemoryId::from_bytes([identity_card; 16]),
        }
    }

    // memory—v1: Any legacy required read is a test failure.
    struct PanicRepository;

    #[async_trait::async_trait]
    impl RuleRepository for PanicRepository {
        // memory—v1: No legacy card read may occur.
        async fn check_card_active(
            &self,
            _: &PolicyContext,
        ) -> Result<bool, astral_types::PolicyError> {
            panic!("legacy repository consulted")
        }
        // memory—v1: No legacy administrator read may occur.
        async fn is_active_global_admin(&self, _: i64) -> Result<bool, astral_types::PolicyError> {
            panic!("legacy repository consulted")
        }
        // memory—v1: No legacy published evidence read may occur.
        async fn load_published_card_authorization(
            &self,
            _: &astral_types::PublishedCardEvidenceScope,
        ) -> Result<
            Option<std::sync::Arc<astral_types::PublishedCardAuthorization>>,
            astral_types::PolicyError,
        > {
            panic!("legacy repository consulted")
        }
        // memory—v1: No legacy organization read may occur.
        async fn load_org_authorization(
            &self,
            _: &PolicyContext,
        ) -> Result<crate::OrgAuthorityRead, astral_types::PolicyError> {
            panic!("legacy repository consulted")
        }
    }

    // memory—v1: Exercise the real reader without minting an authorization.
    #[tokio::test]
    async fn formal_evaluate_observes_the_same_request_reader_and_stays_pending() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_FORMAL_READER_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "engine::formal::request_root_tests::formal_evaluate_observes_the_same_request_reader_and_stays_pending", "--nocapture"])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "isolated test failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            return;
        }
        let rows = CandidateRows {
            users: vec![UserRow { user_id: [1; 16] }, UserRow { user_id: [5; 16] }],
            identity_cards: vec![
                IdentityCardRow {
                    identity_card_id: [2; 16],
                    user_id: [1; 16],
                },
                IdentityCardRow {
                    identity_card_id: [6; 16],
                    user_id: [5; 16],
                },
            ],
            tenants: vec![
                TenantRow {
                    tenant_id: [3; 16],
                    parent_tenant_id: None,
                },
                TenantRow {
                    tenant_id: [7; 16],
                    parent_tenant_id: None,
                },
            ],
            user_cards: vec![
                UserCardRow {
                    user_card_id: [4; 16],
                    user_id: [1; 16],
                    tenant_id: [3; 16],
                    status: UserCardStatus::Active,
                },
                UserCardRow {
                    user_card_id: [8; 16],
                    user_id: [5; 16],
                    tenant_id: [7; 16],
                    status: UserCardStatus::Active,
                },
            ],
            ..CandidateRows::default()
        };
        let owner = install_process_root(
            rows,
            vec![],
            CandidateBudget {
                max_table_rows: 16,
                max_bindings_per_read: 4,
            },
        )
        .unwrap();
        let scope = RequestRootScope::new(
            owner.handle(),
            "00000000-0000-4000-8000-000000000001".parse().unwrap(),
        );
        let root = scope.extension();
        let address = root
            .with_reader(|reader| std::ptr::from_ref(reader) as usize)
            .unwrap();
        let ctx = PolicyContext::builder().action("read".into()).build();
        let engine = PolicyEngine::new();
        let second_scope = RequestRootScope::new(
            owner.handle(),
            "00000000-0000-4000-8000-000000000002".parse().unwrap(),
        );
        let second_root = second_scope.extension();
        let second_address = second_root
            .with_reader(|reader| std::ptr::from_ref(reader) as usize)
            .unwrap();
        assert_ne!(address, second_address);
        let (first, second) = tokio::join!(
            TEST_READER_ADDRESS.scope(
                Cell::new(None),
                TEST_INSPECTION.scope(Cell::new(None), async {
                    let decision = engine
                        .evaluate_with_request_root_and_candidate_identity(
                            &ctx,
                            root.clone(),
                            identity(1, 4, 3, 2),
                        )
                        .await;
                    (
                        decision,
                        TEST_READER_ADDRESS.with(Cell::get),
                        TEST_INSPECTION.with(Cell::get),
                    )
                })
            ),
            TEST_READER_ADDRESS.scope(
                Cell::new(None),
                TEST_INSPECTION.scope(Cell::new(None), async {
                    let decision = engine
                        .evaluate_with_request_root_and_candidate_identity(
                            &ctx,
                            second_root.clone(),
                            identity(5, 8, 7, 6),
                        )
                        .await;
                    (
                        decision,
                        TEST_READER_ADDRESS.with(Cell::get),
                        TEST_INSPECTION.with(Cell::get),
                    )
                })
            ),
        );
        assert_eq!(first.1, Some(address));
        assert_eq!(second.1, Some(second_address));
        assert_eq!(first.2, Some(CandidateInspection::Unverified));
        assert_eq!(second.2, Some(CandidateInspection::Unverified));
        assert!(!first.0.allowed && !second.0.allowed);
        TEST_INSPECTION
            .scope(Cell::new(None), async {
                let mixed = identity(5, 4, 3, 2);
                let decision = engine
                    .evaluate_with_request_root_and_candidate_identity(&ctx, root.clone(), mixed)
                    .await;
                assert_eq!(
                    TEST_INSPECTION.with(Cell::get),
                    Some(CandidateInspection::IdentityMismatch)
                );
                assert!(!decision.allowed);
                assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
            })
            .await;
        TEST_INSPECTION
            .scope(Cell::new(None), async {
                REQUEST_CANDIDATE_IDENTITY
                    .scope(Some(identity(1, 4, 3, 2)), async {
                        engine.evaluate_with_request_root(&ctx, root.clone()).await;
                        assert_eq!(TEST_INSPECTION.with(Cell::get), None);
                    })
                    .await;
            })
            .await;
        TEST_INSPECTION
            .scope(Cell::new(None), async {
                REQUEST_ROOT
                    .scope(
                        root.clone(),
                        REQUEST_CANDIDATE_IDENTITY.scope(Some(identity(1, 4, 3, 2)), async {
                            let decision = engine.evaluate(&ctx, &PanicRepository).await;
                            assert_eq!(
                                TEST_INSPECTION.with(Cell::get),
                                Some(CandidateInspection::Unverified)
                            );
                            assert!(!decision.allowed);
                            assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
                            assert!(engine
                                .evaluate_with_admission(&ctx, &PanicRepository)
                                .await
                                .admission()
                                .is_none());
                        }),
                    )
                    .await;
            })
            .await;
        REQUEST_ROOT
            .scope(root.clone(), async {
                engine.evaluate_with_request_root(&ctx, second_root).await;
                let restored = REQUEST_ROOT.with(|extension| {
                    extension
                        .with_reader(|reader| std::ptr::from_ref(reader) as usize)
                        .unwrap()
                });
                assert_eq!(restored, address);
            })
            .await;
        assert!(REQUEST_ROOT.try_with(|_| ()).is_err());
        {
            use std::future::Future;
            use std::task::{Context, Poll, Waker};
            let mut pending =
                Box::pin(REQUEST_ROOT.scope(root.clone(), std::future::pending::<()>()));
            let mut context = Context::from_waker(Waker::noop());
            assert!(matches!(pending.as_mut().poll(&mut context), Poll::Pending));
            drop(pending);
            assert!(REQUEST_ROOT.try_with(|_| ()).is_err());
        }
        TEST_READER_ADDRESS
            .scope(Cell::new(None), async {
                let decision = engine.evaluate_with_request_root(&ctx, root.clone()).await;
                assert_eq!(TEST_READER_ADDRESS.with(Cell::get), Some(address));
                assert!(!decision.allowed);
                assert_eq!(decision.reason, "AUTHORIZATION_PENDING");
                assert!(decision.audit_required);
                let evaluation = engine
                    .evaluate_with_admission(&ctx, &RetiredRepository)
                    .await;
                assert!(evaluation.admission().is_none());
            })
            .await;
        drop(scope);
        assert_eq!(
            root.with_reader(|_| ()),
            Err(RequestRootAccessError::ScopeEnded)
        );
        TEST_INSPECTION
            .scope(Cell::new(None), async {
                let expired = engine
                    .evaluate_with_request_root_and_candidate_identity(
                        &ctx,
                        root,
                        identity(1, 4, 3, 2),
                    )
                    .await;
                assert_eq!(TEST_INSPECTION.with(Cell::get), None);
                assert!(!expired.allowed);
                assert_eq!(expired.reason, "AUTHORIZATION_PENDING");
            })
            .await;
    }
}
