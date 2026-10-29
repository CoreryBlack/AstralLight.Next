use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use astral_db::grant_ledger::{
    derive_ruleset_contribution_event_id, derive_ruleset_identity, RuleSetEntryLedgerFacts,
    RuleSetMutationKind,
};
use astral_db::{
    load_owned_delta_completion, load_published_card_state_bundle,
    AuthorizationCurrentPointerRecord, AuthorizationPublishedState, DeltaEventAppendRequest,
    DeltaEventType, OwnedCompletionIdentity,
};
use astral_trustgraph::repository::audit_log_repository::RuleSetMutationContext;
use astral_trustgraph::repository::rule_set_repository::SqlxRuleSetRepository;
use astral_trustgraph::service::authorization_projector::{
    shutdown_authorization_projector, start_authorization_projector_with_runtime,
    AuthorizationProjectorConfig, AuthorizationProjectorHandle, SqlxAuthorizationProjectorRuntime,
};
use astral_trustgraph::service::rule_set_write_service::{
    AddEntryRequest, BindCardRequest, RuleSetWriteService,
};
use astral_types::{DomainScopeRequirement, GrantId, PublishedCardEvidenceScope};
use sha2::{Digest, Sha256};
use sqlx::{MySqlPool, Row};

const RECEIPT_CAP: usize = 1024;
const DB_TIMEOUT: Duration = Duration::from_secs(10);
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(120);

fn ensure_fixture_origin() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        if astral_mq::invalidation::origin_region().is_err() {
            astral_mq::invalidation::install_origin_region("testsuite-source-publication")
                .expect("fixture origin identity must be installed before source writes");
        }
    });
}

pub struct PublishedCardFixture {
    pub pointer: AuthorizationCurrentPointerRecord,
    pub published_state: Arc<AuthorizationPublishedState>,
}

struct FixtureProjector {
    handle: Option<AuthorizationProjectorHandle>,
    tenant_id: i64,
    operation_ids: [String; 2],
}

impl FixtureProjector {
    async fn stop(mut self, exact_receipt_count: usize) {
        let handle = self.handle.take().unwrap();
        let run_id = handle.run_id.clone();
        let report = shutdown_authorization_projector(handle, DB_TIMEOUT).await;
        let summary = match report.summary {
            Ok(summary) => summary,
            Err(error) => {
                eprintln!(
                    "[UNKNOWN] fixture projector shutdown did not prove worker termination; run_id={run_id} tenant_id={} operation_ids={:?} elapsed={:?}; source commit remains durable and must not be replayed",
                    self.tenant_id, self.operation_ids, report.join_elapsed
                );
                panic!("fixture projector must stop cleanly within {DB_TIMEOUT:?}: {error}");
            }
        };
        assert!(report.join_elapsed <= DB_TIMEOUT);
        // Each receipt has a separate exact durable proof; counters only describe
        // the worker's claims and terminal outcomes.
        assert_eq!(summary.events_claimed, summary.events_published);
        assert!(summary.events_published >= exact_receipt_count as u64);
        assert_eq!(summary.events_released_retry, 0);
        assert_eq!(summary.events_quarantined, 0);
        assert_eq!(summary.events_blocked, 0);
        assert_eq!(summary.events_lease_lost, 0);
        assert_eq!(summary.events_publication_unknown, 0);
        assert_eq!(summary.events_committed_mirror_unavailable, 0);
        assert_eq!(summary.events_budget_exhausted, 0);
        assert_eq!(summary.events_quarantine_unknown, 0);
        assert_eq!(summary.events_deadline_exceeded, 0);
    }
}

impl Drop for FixtureProjector {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.cancellation.cancel();
            eprintln!(
                "[UNKNOWN] fixture projector dropped without awaited shutdown; run_id={} tenant_id={} operation_ids={:?}; cancellation was requested but the join was not proven, so worker-owned leases and fixture cleanup require reconciliation",
                handle.run_id, self.tenant_id, self.operation_ids
            );
            // Drop cannot await the supervisor and its children. Detaching the
            // join permits cancellation to drain; it does not prove termination.
        }
    }
}

#[derive(Debug)]
struct ExpectedContribution {
    event_id: String,
    grant_id: GrantId,
    entry_id: i64,
    ref_id: i64,
    event_type: DeltaEventType,
}

struct CardSourceEvent {
    event_id: String,
    generation: u64,
    fence: u64,
    event_type: String,
}

struct SourceMutationProof {
    cards: Vec<CardSourceEvent>,
    audit_old_value: Option<String>,
}

/// Publish a real source change and prove all of its durable contributions.
/// `run` binds the caller's stable episode tag to its isolated fixture salt.
pub async fn publish_card_manifest(
    pool: &MySqlPool,
    tenant_id: i64,
    card_id: i64,
    rule_set_id: i64,
    actor_user_id: i64,
    entries: Vec<AddEntryRequest>,
    run: (&str, u128),
) -> PublishedCardFixture {
    ensure_fixture_origin();
    assert!(tenant_id > 0 && card_id > 0 && rule_set_id > 0 && actor_user_id > 0);
    assert!(entries.len() <= RECEIPT_CAP);
    let (tag, salt) = run;
    assert!(!tag.trim().is_empty());
    let operation_id = format!(
        "ts:{}",
        &hex::encode(Sha256::digest(
            format!("{salt:032x}:{tag}:{tenant_id}:{card_id}:{rule_set_id}").as_bytes()
        ))[..56]
    );
    let bind_operation = format!("{operation_id}:b");
    let context = RuleSetMutationContext::user(actor_user_id, Some(&operation_id)).unwrap();
    let bind_context = RuleSetMutationContext::user(actor_user_id, Some(&bind_operation)).unwrap();
    assert_operation_ids_unused(pool, [&operation_id, &bind_operation]).await;
    let unfinished: i64 = tokio::time::timeout(
        DB_TIMEOUT,
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM authorization_delta_event WHERE tenant_id = ? AND status <> 'SUCCEEDED'",
        )
        .bind(tenant_id)
        .fetch_one(pool),
    )
    .await
    .expect("fixture backlog preflight timed out")
    .expect("fixture backlog preflight failed");
    assert_eq!(unfinished, 0, "prior unknown work requires reconciliation");
    let bindings: Vec<(i64, String, Option<i64>)> = tokio::time::timeout(
        DB_TIMEOUT,
        sqlx::query_as(
            "SELECT card_id, ref_type, tenant_id FROM card_rule_set_ref \
             WHERE rule_set_id = ? ORDER BY id LIMIT 2",
        )
        .bind(rule_set_id)
        .fetch_all(pool),
    )
    .await
    .expect("RuleSet binding preflight timed out")
    .expect("RuleSet binding preflight failed");
    assert!(bindings.len() <= 1, "fixture RuleSet must affect one card");
    if let Some((bound_card_id, ref_type, binding_tenant)) = bindings.first() {
        assert_eq!(*bound_card_id, card_id);
        assert_eq!(ref_type, "BASE");
        assert_eq!(*binding_tenant, Some(tenant_id));
    }
    let (stored_tenant, domain_id, card_status): (Option<i64>, Option<i64>, String) =
        tokio::time::timeout(
            DB_TIMEOUT,
            sqlx::query_as(
                "SELECT tenant_id, domain_id, card_status FROM user_card WHERE card_id = ?",
            )
            .bind(card_id)
            .fetch_one(pool),
        )
        .await
        .expect("card scope read timed out")
        .expect("fixture card must exist");
    assert_eq!(stored_tenant, Some(tenant_id));
    assert_eq!(card_status, "ACTIVE");
    let (rule_set_tenant, source_type, enabled): (Option<i64>, String, i32) = tokio::time::timeout(
        DB_TIMEOUT,
        sqlx::query_as(
            "SELECT tenant_id, source_type, enabled FROM rule_set WHERE rule_set_id = ?",
        )
        .bind(rule_set_id)
        .fetch_one(pool),
    )
    .await
    .expect("RuleSet scope read timed out")
    .expect("fixture RuleSet must exist");
    assert_eq!(rule_set_tenant, Some(tenant_id));
    assert_eq!(source_type, "MANUAL");
    assert_eq!(enabled, 1);
    let actor_status: String = tokio::time::timeout(
        DB_TIMEOUT,
        sqlx::query_scalar("SELECT status FROM platform_user WHERE user_id = ?")
            .bind(actor_user_id)
            .fetch_one(pool),
    )
    .await
    .expect("fixture actor lookup timed out")
    .expect("fixture actor must exist");
    assert_eq!(actor_status, "ACTIVE");
    let tenant_status: String = tokio::time::timeout(
        DB_TIMEOUT,
        sqlx::query_scalar("SELECT status FROM tenant WHERE tenant_id = ?")
            .bind(tenant_id)
            .fetch_one(pool),
    )
    .await
    .expect("fixture tenant lookup timed out")
    .expect("fixture tenant must exist");
    assert!(matches!(tenant_status.as_str(), "ACTIVE" | "SUSPENDED"));
    let scope = PublishedCardEvidenceScope {
        tenant_id,
        card_id,
        user_filter: None,
        domain: domain_id.map_or(
            DomainScopeRequirement::ExactlyNone,
            DomainScopeRequirement::ExactlySome,
        ),
    };
    if entries.is_empty() {
        let prior =
            tokio::time::timeout(DB_TIMEOUT, load_published_card_state_bundle(pool, &scope))
                .await
                .expect("prior publication read timed out")
                .expect("empty target requires a real prior published ADD");
        assert!(
            prior.states().iter().any(|state| {
                state.pointer.identity.aggregate_type == "RULE_SET"
                    && state.pointer.identity.aggregate_id == rule_set_id
                    && state.total_grant_count > 0
            }),
            "initial empty publication must not manufacture a Ready proof"
        );
    }

    let runtime = Arc::new(SqlxAuthorizationProjectorRuntime::new(pool.clone()));
    let projector = FixtureProjector {
        handle: Some(start_authorization_projector_with_runtime(
            runtime,
            AuthorizationProjectorConfig {
                tenants: vec![tenant_id],
                poll_interval_secs: 1,
                ..Default::default()
            },
        )),
        tenant_id,
        operation_ids: [operation_id.clone(), bind_operation.clone()],
    };
    let service = RuleSetWriteService::new(Arc::new(SqlxRuleSetRepository::new(pool.clone())));
    let mut exact_receipt_count = 0;
    if bindings.is_empty() {
        tokio::time::timeout(
            COMPLETION_TIMEOUT,
            service.bind_card(
                rule_set_id,
                &BindCardRequest {
                    card_id,
                    ref_type: "BASE".into(),
                },
                &bind_context,
            ),
        )
        .await
        .expect("[UNKNOWN] source binding timed out; do not replay the mutation")
        .expect("source binding must use the production writer");
        let expected = load_source_contributions(
            pool,
            tenant_id,
            card_id,
            rule_set_id,
            &bind_operation,
            RuleSetMutationKind::Add,
        )
        .await;
        let source = load_source_mutation_proof(
            pool,
            tenant_id,
            card_id,
            rule_set_id,
            &bind_context,
            "BIND_CARD",
            1,
        )
        .await;
        assert_eq!(source.cards[0].event_type, "RULE_SET_BOUND");
        let receipts = load_receipts(pool, tenant_id, &bind_operation).await;
        assert_exact_receipt_set(
            &receipts,
            &expected,
            &source.cards,
            tenant_id,
            card_id,
            rule_set_id,
        );
        prove_receipts(pool, &receipts).await;
        exact_receipt_count += receipts.len();
    }
    let mut expected = load_source_contributions(
        pool,
        tenant_id,
        card_id,
        rule_set_id,
        &operation_id,
        RuleSetMutationKind::Remove,
    )
    .await;
    let removed_count = expected.len();
    assert!(removed_count + entries.len() <= RECEIPT_CAP);
    tokio::time::timeout(
        COMPLETION_TIMEOUT,
        service.replace_entries(rule_set_id, &entries, &context),
    )
    .await
    .expect("[UNKNOWN] source replacement timed out; do not replay the mutation")
    .expect("fixture replacement must use the production source writer");
    let additions = load_source_contributions(
        pool,
        tenant_id,
        card_id,
        rule_set_id,
        &operation_id,
        RuleSetMutationKind::Add,
    )
    .await;
    assert_eq!(additions.len(), entries.len());
    expected.extend(additions);
    assert!(!expected.is_empty(), "a no-op is not a publication fixture");
    let source = load_source_mutation_proof(
        pool,
        tenant_id,
        card_id,
        rule_set_id,
        &context,
        "BATCH_REPLACE_ENTRIES",
        1 + usize::from(removed_count > 0),
    )
    .await;
    if removed_count > 0 {
        assert_eq!(source.cards[0].event_type, "REVOKE");
    }
    assert_eq!(source.cards.last().unwrap().event_type, "RULE_SET_UPDATE");
    assert_replacement_audit(&source, &expected, card_id);
    let receipts = load_receipts(pool, tenant_id, &operation_id).await;
    assert_exact_receipt_set(
        &receipts,
        &expected,
        &source.cards,
        tenant_id,
        card_id,
        rule_set_id,
    );
    prove_receipts(pool, &receipts).await;
    exact_receipt_count += receipts.len();
    projector.stop(exact_receipt_count).await;

    let bundle = tokio::time::timeout(DB_TIMEOUT, load_published_card_state_bundle(pool, &scope))
        .await
        .expect("strict fixture read timed out")
        .expect("completed source batch must pass the strict published reader");
    let state = bundle
        .into_states()
        .into_iter()
        .find(|state| {
            state.pointer.identity.aggregate_type == "RULE_SET"
                && state.pointer.identity.aggregate_id == rule_set_id
        })
        .expect("owned publication must include the RuleSet aggregate");
    assert_eq!(
        state.pointer.compiler_version,
        astral_types::AUTHORIZATION_COMPILER_VERSION
    );
    assert_eq!(state.pointer.card_id, Some(card_id));
    assert_eq!(state.pointer.operation_id, operation_id);
    assert_eq!(state.total_grant_count, entries.len() as u64);
    PublishedCardFixture {
        pointer: state.pointer.clone(),
        published_state: Arc::new(state),
    }
}

async fn assert_operation_ids_unused(pool: &MySqlPool, operation_ids: [&str; 2]) {
    for operation_id in operation_ids {
        for table in [
            "authorization_delta_event",
            "authorization_grant_revision",
            "authorization_projection_manifest",
            "authorization_impact_plan",
            "authorization_archive_outbox",
            "rule_set_projection_audit",
            "al_message_outbox",
        ] {
            let count: i64 = tokio::time::timeout(
                DB_TIMEOUT,
                sqlx::query_scalar(&format!(
                    "SELECT COUNT(*) FROM {table} WHERE operation_id = ?"
                ))
                .bind(operation_id)
                .fetch_one(pool),
            )
            .await
            .expect("operation collision preflight timed out")
            .expect("operation collision preflight failed");
            assert_eq!(
                count, 0,
                "operation id already belongs to {table}; do not replay"
            );
        }
        let count: i64 = tokio::time::timeout(
            DB_TIMEOUT,
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM authorization_projection_outbox \
                 WHERE JSON_UNQUOTE(JSON_EXTRACT(payload_json, '$.operationId')) = ?",
            )
            .bind(operation_id)
            .fetch_one(pool),
        )
        .await
        .expect("source operation collision read timed out")
        .expect("source operation collision read failed");
        assert_eq!(count, 0, "source operation already exists; do not replay");
    }
}

async fn load_source_contributions(
    pool: &MySqlPool,
    tenant_id: i64,
    card_id: i64,
    rule_set_id: i64,
    operation_id: &str,
    kind: RuleSetMutationKind,
) -> Vec<ExpectedContribution> {
    let rows = tokio::time::timeout(
        DB_TIMEOUT,
        sqlx::query(
            "SELECT e.entry_id, e.effect, e.resource_type, e.resource_id, e.action_code, \
         CAST(e.condition_json AS CHAR) AS condition_json, \
         DATE_FORMAT(e.valid_from, '%Y-%m-%dT%H:%i:%s') AS valid_from, \
         DATE_FORMAT(e.valid_to, '%Y-%m-%dT%H:%i:%s') AS valid_to, \
         b.id AS ref_id, b.ref_type, b.tenant_id AS binding_tenant, \
         uc.user_id, uc.domain_id, uc.tenant_id AS card_tenant, rs.tenant_id AS source_tenant \
         FROM rule_set_entry e INNER JOIN rule_set rs ON rs.rule_set_id = e.rule_set_id \
         INNER JOIN card_rule_set_ref b ON b.rule_set_id = e.rule_set_id AND b.card_id = ? \
         INNER JOIN user_card uc ON uc.card_id = b.card_id \
         WHERE e.rule_set_id = ? AND e.enabled = 1 ORDER BY e.entry_id, b.id LIMIT 1025",
        )
        .bind(card_id)
        .bind(rule_set_id)
        .fetch_all(pool),
    )
    .await
    .expect("source contribution read timed out")
    .expect("source contribution read failed");
    assert!(
        rows.len() <= RECEIPT_CAP,
        "fixture source exceeds receipt budget"
    );
    rows.into_iter()
        .map(|row| {
            assert_eq!(row.get::<Option<i64>, _>("binding_tenant"), Some(tenant_id));
            assert_eq!(row.get::<Option<i64>, _>("card_tenant"), Some(tenant_id));
            assert_eq!(row.get::<Option<i64>, _>("source_tenant"), Some(tenant_id));
            assert_eq!(row.get::<String, _>("ref_type"), "BASE");
            assert_eq!(row.get::<String, _>("effect"), "ALLOW");
            let resource: String = row
                .get::<Option<String>, _>("resource_type")
                .expect("source resource");
            let action: String = row
                .get::<Option<String>, _>("action_code")
                .expect("source action");
            let condition: Option<String> = row.get("condition_json");
            let valid_from: Option<String> = row.get("valid_from");
            let valid_to: Option<String> = row.get("valid_to");
            let facts = RuleSetEntryLedgerFacts {
                tenant_id,
                domain_id: row.get("domain_id"),
                card_id,
                user_id: row
                    .get::<Option<i64>, _>("user_id")
                    .expect("source card owner"),
                rule_set_id,
                entry_id: row.get("entry_id"),
                ref_id: row.get("ref_id"),
                ref_type: "BASE",
                resource: &resource,
                resource_id: row.get("resource_id"),
                action: &action,
                condition_json: condition.as_deref(),
                valid_from: valid_from.as_deref(),
                valid_to: valid_to.as_deref(),
            };
            ExpectedContribution {
                event_id: derive_ruleset_contribution_event_id(operation_id, &facts, kind).unwrap(),
                grant_id: derive_ruleset_identity(&facts).unwrap(),
                entry_id: facts.entry_id,
                ref_id: facts.ref_id,
                event_type: match kind {
                    RuleSetMutationKind::Add => DeltaEventType::Add,
                    RuleSetMutationKind::Remove => DeltaEventType::Remove,
                    RuleSetMutationKind::Update => unreachable!("fixture uses source replacement"),
                },
            }
        })
        .collect()
}

async fn load_source_mutation_proof(
    pool: &MySqlPool,
    tenant_id: i64,
    card_id: i64,
    rule_set_id: i64,
    context: &RuleSetMutationContext,
    change_type: &str,
    expected_card_count: usize,
) -> SourceMutationProof {
    let rows = tokio::time::timeout(DB_TIMEOUT, sqlx::query(
        "SELECT event_id, aggregate_type, aggregate_id, tenant_id, event_type, source_generation, \
         revoke_fence, sequence_number, CAST(payload_json AS CHAR) AS payload_json \
         FROM authorization_projection_outbox \
         WHERE JSON_UNQUOTE(JSON_EXTRACT(payload_json, '$.operationId')) = ? \
         ORDER BY source_generation, event_id LIMIT 5",
    ).bind(context.operation_id()).fetch_all(pool))
        .await.expect("source outbox read timed out").expect("source outbox read failed");
    assert_eq!(
        rows.len(),
        expected_card_count + 1,
        "complete source operation set"
    );
    let mut cards = Vec::new();
    let mut rule_set = None;
    let mut event_ids = HashSet::new();
    for row in rows {
        assert_eq!(row.get::<Option<i64>, _>("tenant_id"), Some(tenant_id));
        let event_id: String = row.get("event_id");
        assert!(event_ids.insert(event_id.clone()), "duplicate source event");
        let generation: i64 = row.get("source_generation");
        let fence: i64 = row.get("revoke_fence");
        assert!(generation > 0 && fence >= 0 && fence <= generation);
        assert_eq!(row.get::<i64, _>("sequence_number"), generation);
        let payload: serde_json::Value = serde_json::from_str(row.get("payload_json")).unwrap();
        assert_eq!(
            payload["operationId"].as_str(),
            Some(context.operation_id())
        );
        assert_eq!(payload["actorId"].as_i64(), Some(context.actor_id()));
        assert_eq!(payload["tenantId"].as_i64(), Some(tenant_id));
        assert_eq!(payload["generation"].as_i64(), Some(generation));
        match row.get::<String, _>("aggregate_type").as_str() {
            "CARD" => {
                assert_eq!(row.get::<i64, _>("aggregate_id"), card_id);
                assert_eq!(payload["cardId"].as_i64(), Some(card_id));
                cards.push(CardSourceEvent {
                    event_id,
                    generation: u64::try_from(generation).unwrap(),
                    fence: u64::try_from(fence).unwrap(),
                    event_type: row.get("event_type"),
                });
            }
            "RULE_SET" => {
                assert_eq!(row.get::<i64, _>("aggregate_id"), rule_set_id);
                assert_eq!(payload["ruleSetId"].as_i64(), Some(rule_set_id));
                assert!(rule_set.replace((event_id, generation)).is_none());
            }
            _ => panic!("operation affected an unexpected source aggregate"),
        }
    }
    cards.sort_by_key(|event| event.generation);
    assert_eq!(cards.len(), expected_card_count);
    assert!(cards
        .windows(2)
        .all(|pair| pair[1].generation == pair[0].generation + 1));
    let (parent_event, source_generation) = rule_set.expect("RuleSet parent source event");
    let audits = tokio::time::timeout(
        DB_TIMEOUT,
        sqlx::query(
            "SELECT event_id, source_generation, changed_by, change_type, \
         CAST(old_value_json AS CHAR) AS old_value_json \
         FROM rule_set_projection_audit WHERE tenant_id = ? AND rule_set_id = ? \
           AND aggregate_type = 'RULE_SET' AND aggregate_id = ? AND operation_id = ? LIMIT 2",
        )
        .bind(tenant_id)
        .bind(rule_set_id)
        .bind(rule_set_id)
        .bind(context.operation_id())
        .fetch_all(pool),
    )
    .await
    .expect("source audit read timed out")
    .expect("source audit read failed");
    assert_eq!(audits.len(), 1, "one exact source audit correlation");
    let audit = &audits[0];
    assert_eq!(audit.get::<String, _>("event_id"), parent_event);
    assert_eq!(audit.get::<i64, _>("source_generation"), source_generation);
    assert_eq!(audit.get::<i64, _>("changed_by"), context.actor_id());
    assert_eq!(audit.get::<String, _>("change_type"), change_type);
    SourceMutationProof {
        cards,
        audit_old_value: audit.get("old_value_json"),
    }
}

fn assert_exact_receipt_set(
    receipts: &[DeltaEventAppendRequest],
    expected: &[ExpectedContribution],
    card_events: &[CardSourceEvent],
    tenant_id: i64,
    card_id: i64,
    rule_set_id: i64,
) {
    assert_eq!(
        receipts.len(),
        expected.len(),
        "complete immutable receipt set"
    );
    let expected_by_event: HashMap<_, _> = expected
        .iter()
        .map(|item| (item.event_id.as_str(), item))
        .collect();
    assert_eq!(
        expected_by_event.len(),
        expected.len(),
        "source contribution identities are unique"
    );
    let mut seen = HashSet::new();
    for receipt in receipts {
        assert!(seen.insert(receipt.event_id.as_str()), "duplicate receipt");
        let contribution = expected_by_event
            .get(receipt.event_id.as_str())
            .expect("unexpected contribution event");
        assert_eq!(receipt.tenant_id, tenant_id);
        assert_eq!(receipt.card_id, Some(card_id));
        assert_eq!(receipt.aggregate_type, "RULE_SET");
        assert_eq!(receipt.aggregate_id, rule_set_id);
        assert_eq!(receipt.grant_id, contribution.grant_id);
        assert_eq!(receipt.event_type, contribution.event_type);
        let parent = match receipt.event_type {
            DeltaEventType::Add => card_events.last().unwrap(),
            DeltaEventType::Remove => {
                assert_eq!(card_events.len(), 2);
                &card_events[0]
            }
            _ => panic!("fixture source did not request this delta kind"),
        };
        assert_ne!(
            receipt.event_id, parent.event_id,
            "contribution and parent identities are distinct"
        );
        assert_eq!(receipt.source_generation, parent.generation);
        assert_eq!(receipt.revoke_fence, parent.fence);
        OwnedCompletionIdentity::from_request(receipt).expect("exact source receipt must validate");
    }
}

fn assert_replacement_audit(
    source: &SourceMutationProof,
    expected: &[ExpectedContribution],
    card_id: i64,
) {
    let detail: serde_json::Value = serde_json::from_str(
        source
            .audit_old_value
            .as_deref()
            .expect("replacement audit detail"),
    )
    .unwrap();
    for (prefix, kind) in [
        ("removed", DeltaEventType::Remove),
        ("added", DeltaEventType::Add),
    ] {
        let events = detail[format!("{prefix}ContributionEventIds")]
            .as_array()
            .unwrap();
        let entries = detail[format!("{prefix}RuleSetEntryIds")]
            .as_array()
            .unwrap();
        let cards = detail[format!("{prefix}BoundCardIds")].as_array().unwrap();
        let refs = detail[format!("{prefix}BindingRefIds")].as_array().unwrap();
        assert_eq!(events.len(), entries.len());
        assert_eq!(events.len(), cards.len());
        assert_eq!(events.len(), refs.len());
        let actual: HashSet<_> = (0..events.len())
            .map(|index| {
                (
                    events[index].as_str().unwrap(),
                    entries[index].as_i64().unwrap(),
                    cards[index].as_i64().unwrap(),
                    refs[index].as_i64().unwrap(),
                )
            })
            .collect();
        let intended: HashSet<_> = expected
            .iter()
            .filter(|item| item.event_type == kind)
            .map(|item| (item.event_id.as_str(), item.entry_id, card_id, item.ref_id))
            .collect();
        assert_eq!(
            actual.len(),
            events.len(),
            "audit contribution identities are unique"
        );
        assert_eq!(
            actual, intended,
            "source audit must cover the exact contribution set"
        );
    }
}

async fn load_receipts(
    pool: &MySqlPool,
    tenant_id: i64,
    operation_id: &str,
) -> Vec<DeltaEventAppendRequest> {
    let rows = tokio::time::timeout(DB_TIMEOUT, sqlx::query(
        "SELECT tenant_id, card_id, aggregate_type, aggregate_id, grant_id, event_id, operation_id, \
         event_type, base_version, target_version, source_generation, revoke_fence, invalidates_published_evidence, \
         CAST(before_image_json AS CHAR) AS before_image_json, HEX(before_digest) AS before_digest_hex, \
         CAST(delta_json AS CHAR) AS delta_json, HEX(semantic_hash) AS semantic_hash_hex, \
         HEX(dependency_hash) AS dependency_hash_hex, compiler_version, next_attempt_at \
         FROM authorization_delta_event WHERE tenant_id = ? AND operation_id = ? \
         ORDER BY delta_event_id LIMIT 1025",
    ).bind(tenant_id).bind(operation_id).fetch_all(pool))
        .await.expect("immutable receipt read timed out").expect("immutable receipt read failed");
    assert!(
        rows.len() <= RECEIPT_CAP,
        "fixture receipt batch exceeds bound"
    );
    rows.into_iter()
        .map(|row| {
            let kind: String = row.get("event_type");
            let request = DeltaEventAppendRequest {
                tenant_id: row.get("tenant_id"),
                card_id: row.get("card_id"),
                aggregate_type: row.get("aggregate_type"),
                aggregate_id: row.get("aggregate_id"),
                grant_id: astral_db::decode_grant_id_sql(row.get::<&str, _>("grant_id")).unwrap(),
                event_id: row.get("event_id"),
                operation_id: row.get("operation_id"),
                event_type: match kind.as_str() {
                    "ADD" => DeltaEventType::Add,
                    "UPDATE" => DeltaEventType::Update,
                    "REMOVE" => DeltaEventType::Remove,
                    "REVOKE" => DeltaEventType::Revoke,
                    _ => panic!("unknown source contribution kind"),
                },
                base_version: row.get("base_version"),
                target_version: row.get("target_version"),
                source_generation: u64::try_from(row.get::<i64, _>("source_generation")).unwrap(),
                revoke_fence: u64::try_from(row.get::<i64, _>("revoke_fence")).unwrap(),
                invalidates_published_evidence: row.get::<i8, _>("invalidates_published_evidence")
                    != 0,
                before_image_json: row.get("before_image_json"),
                before_digest_hex: row
                    .get::<Option<String>, _>("before_digest_hex")
                    .map(|value| value.to_ascii_lowercase()),
                delta_json: row.get("delta_json"),
                semantic_hash_hex: row
                    .get::<String, _>("semantic_hash_hex")
                    .to_ascii_lowercase(),
                dependency_hash_hex: row
                    .get::<String, _>("dependency_hash_hex")
                    .to_ascii_lowercase(),
                compiler_version: row.get("compiler_version"),
                next_attempt_at: row.get("next_attempt_at"),
            };
            assert_eq!(request.tenant_id, tenant_id);
            assert_eq!(request.operation_id, operation_id);
            assert_eq!(
                request.compiler_version,
                astral_types::AUTHORIZATION_COMPILER_VERSION
            );
            OwnedCompletionIdentity::from_request(&request)
                .expect("complete source receipt must validate");
            request
        })
        .collect()
}

async fn prove_receipts(pool: &MySqlPool, receipts: &[DeltaEventAppendRequest]) {
    tokio::time::timeout(COMPLETION_TIMEOUT, async {
        let mut proven = vec![false; receipts.len()];
        while proven.iter().any(|value| !*value) {
            for (index, receipt) in receipts.iter().enumerate() {
                if !proven[index] {
                    proven[index] = tokio::time::timeout(
                        DB_TIMEOUT,
                        load_owned_delta_completion(pool, receipt),
                    )
                    .await
                    .expect("completion read timed out")
                    .expect("exact completion read failed")
                    .is_some();
                }
            }
            if proven.iter().any(|value| !*value) {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    })
    .await
    .expect("[UNKNOWN] exact completion deadline exceeded; ownership remains durable");
}
