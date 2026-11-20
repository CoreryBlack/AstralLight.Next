//! memory—v1: Trusted-host object attribution through the real composition.
//!
//! A representative business route (`GET /main/api/v1/documents/{id}`) lets the
//! trusted host bind the object ID, its tenant and its owner from local,
//! non-circular host facts (documented host records), never from client input
//! and never from the authorization root. The host resolves the three facts and
//! supplies them to `PolicyEngine::evaluate_memory_v1` as the exact
//! `MemoryV1Request` target triple the permission middleware builds for real
//! adapted routes; the engine's §4.10 scope predicates decide the outcome on
//! the request's one request-scoped reader with its final recheck.
//!
//! Proven here: legitimate own-object access is allowed; cross-owner or
//! cross-tenant attribution is a deterministic denial with no admission;
//! missing attribution stays pending (fail-closed); a revoking publication
//! turns the held view stale and fresh readers deny; an unrelated publication
//! neither revokes nor creates access; and the composed router's adapted
//! objectless route plus the forged-header stripping still hold for the same
//! session.
//!
//! The document host facts are the test's own fixed records. This does not
//! prove the deployed production route resolves ownership for every host, nor
//! that every deployed writer is covered; it proves one real composed session
//! honors host-supplied attribution exactly as the paper specifies.

use astral_authorization_root::memory_v1_session::RequestSessionExtension;
use policy_engine::memory_v1_formal::{MemoryV1Decision, MemoryV1Evaluation, MemoryV1Request};

use super::*;

// memory—v1: One base rule set per owner tenant: documents may be read only by
// their owner, inside the card's tenant. Absent entry scopes default to the
// strictest self/self, so a binding cannot widen them. A binding's card tenant
// must equal the rule set's owner tenant, so tenant B needs its own set.
const RULES_DOCUMENT: [u8; 16] = [0x45; 16];
const RULES_DOCUMENT_B: [u8; 16] = [0x46; 16];
const CARD_DOCUMENT: [u8; 16] = [0x38; 16];
const TENANT_B: [u8; 16] = [0x63; 16];
const ALICE_DOCUMENT: [u8; 16] = [0x71; 16];
const BOB_DOCUMENT: [u8; 16] = [0x72; 16];
const BOB_DOCUMENT_TENANT_B: [u8; 16] = [0x73; 16];
const BOB_CARD_TENANT_B: [u8; 16] = [0x39; 16];

// memory—v1: The fixed host-side document records. These are host facts, not
// authorization facts: the authorization root has no document table and the
// client only chooses which document id to ask for.
struct DocumentRecord {
    document_id: [u8; 16],
    tenant_id: [u8; 16],
    owner_user_id: [u8; 16],
}

const DOCUMENTS_FIXTURE: [DocumentRecord; 3] = [
    DocumentRecord {
        document_id: ALICE_DOCUMENT,
        tenant_id: TENANT,
        owner_user_id: ALICE,
    },
    DocumentRecord {
        document_id: BOB_DOCUMENT,
        tenant_id: TENANT,
        owner_user_id: BOB,
    },
    DocumentRecord {
        document_id: BOB_DOCUMENT_TENANT_B,
        tenant_id: TENANT_B,
        owner_user_id: BOB,
    },
];

// memory—v1: The trusted host resolves attribution for one document id from its
// own records. An unknown id yields no attribution; the host never invents one.
fn host_attribution(document_id: [u8; 16]) -> Option<([u8; 16], [u8; 16])> {
    DOCUMENTS_FIXTURE
        .iter()
        .find(|record| record.document_id == document_id)
        .map(|record| (record.tenant_id, record.owner_user_id))
}

// memory—v1: Extend the base fixture with the document rule sets, the tenant-B
// principal facts and every binding confirmed by the same in-fixture rules.
fn object_fixture() -> (CandidateRows, Vec<CurrentSelection>) {
    let (mut rows, mut selections) = fixture();
    let document =
        br#"{"rules":[{"ruleId":"D1","resource":"document","action":"read","effect":"ALLOW"}]}"#;
    for (rule_set_id, owner_tenant_id, confirmation_id) in [
        (RULES_DOCUMENT, TENANT, 0x92_u8),
        (RULES_DOCUMENT_B, TENANT_B, 0x93),
    ] {
        selections.push(CurrentSelection {
            rule_set_id,
            version_bytes: vec![1],
        });
        rows.rule_sets.push(RuleSetRow {
            rule_set_id,
            owner_tenant_id,
            current_version_bytes: vec![1],
            status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
        });
        rows.rule_set_versions
            .push(version_row(rule_set_id, document));
        rows.rule_set_change_confirmations
            .push(RuleSetChangeConfirmationRow {
                confirmation_id: [confirmation_id; 16],
                rule_set_id,
                version_bytes: vec![1],
                confirmer_user_id: BOB,
                affected_scope_bytes: vec![1],
                operation_id: vec![1],
                confirmed_at_bytes: vec![1],
                revoked_at: None,
                revoked_by: None,
            });
    }
    rows.tenants.push(TenantRow {
        tenant_id: TENANT_B,
        parent_tenant_id: Some(TENANT),
    });
    // memory—v1: Bob keeps his single identity card (0x22); a user owns exactly
    // one identity card. Only user cards carry tenants, so no extra identity row.
    // Alice gains a dedicated document-rule card in the base tenant (0x38); Bob
    // gains the tenant-B document card (0x39). Both bindings confirm through the
    // fixture's existing confirmation authority.
    let bindings = [
        ([0x55; 16], CARD_DOCUMENT, RULES_DOCUMENT, TENANT, ALICE),
        (
            [0x56; 16],
            BOB_CARD_TENANT_B,
            RULES_DOCUMENT_B,
            TENANT_B,
            BOB,
        ),
    ];
    for (binding_id, user_card_id, rule_set_id, tenant_id, user_id) in bindings {
        rows.user_cards.push(UserCardRow {
            user_card_id,
            user_id,
            tenant_id,
            status: UserCardStatus::Active,
        });
        rows.bindings.push(BindingRow {
            binding_id,
            user_card_id,
            rule_set_id,
            binding_layer: BindingLayer::Base,
            valid_from: None,
            valid_until: None,
            owner_scope: MemoryV1OwnerScope::default(),
            tenant_scope: MemoryV1TenantScope::default(),
            removed_at: None,
            removed_by: None,
        });
        rows.binding_confirmations.push(BindingConfirmationRow {
            confirmation_id: [binding_id[0] + 0x10; 16],
            binding_id,
            rule_set_id,
            version_bytes: vec![1],
            confirmer_user_id: ALICE,
            scope_bytes: vec![1],
            operation_id: vec![1],
            confirmed_at_bytes: vec![1],
            revoked_at: None,
            revoked_by: None,
        });
    }
    (rows, selections)
}

// memory—v1: The trusted host binds one document read: the object triple comes
// from host records only, the operation identity is frozen by the caller, and
// the evaluation runs on this request's one reader with its final recheck —
// exactly the request the permission middleware builds for a real adapted
// object-bearing route.
fn read_document(
    engine: &PolicyEngine,
    root: &RequestRootExtension,
    session: &RequestSessionExtension,
    document_id: [u8; 16],
) -> MemoryV1Evaluation {
    let (target_tenant, target_owner) = match host_attribution(document_id) {
        Some((tenant, owner)) => (Some(tenant), Some(owner)),
        // memory—v1: An unknown object carries no attribution; the request
        // stays object-bearing but unverifiable, so the engine must pend.
        None => (None, None),
    };
    engine.evaluate_memory_v1(
        root,
        session,
        &MemoryV1Request {
            resource: "document",
            action: "read",
            target: Some(&document_id),
            target_tenant: target_tenant.as_ref().map(|tenant| tenant.as_slice()),
            target_owner: target_owner.as_ref().map(|owner| owner.as_slice()),
            operation_id: b"paper-document-read",
            operation_fingerprint: b"paper-document-read-fingerprint",
        },
    )
}

#[test]
fn object_attribution_isolated_process() {
    const CHILD: &str = "ASTRAL_MEMORY_V1_OBJECT_ATTRIBUTION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "memory_v1_composition::full_path_tests::object_attribution::object_attribution_isolated_process",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if line.starts_with("attribution:") {
                println!("{line}");
            }
        }
        return;
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(object_attribution());
}

async fn object_attribution() {
    let (rows, selections) = object_fixture();
    let budget = CandidateBudget {
        max_table_rows: 128,
        max_bindings_per_read: 8,
    };
    let owner = install_process_root(rows, selections, budget).unwrap();
    // memory—v1: The representative document resource is registered like any
    // adapted route would be; rules referencing it cannot serve without it.
    let mut declarations = crate::memory_v1_service::registry_declarations();
    declarations.push(
        astral_authorization_root::memory_v1_registry::RegistryDeclaration {
            resource: "document".to_owned(),
            actions: vec!["read".to_owned()],
        },
    );
    owner.install_registry(&declarations).unwrap();
    let mut config = AppConfig::default();
    config.gateway.hmac_secret = uuid::Uuid::new_v4().to_string();
    let engine = Arc::new(PolicyEngine::new());
    let observations: Observations = Arc::default();
    let trustgraph = build_router(
        build_memory_v1_offline_app_state(config.clone(), Arc::clone(&engine)),
        RouterIntegrationConfig::disabled(),
    )
    .layer(middleware::from_fn_with_state(
        Arc::clone(&observations),
        observe,
    ));
    let identity_slot = Arc::new(OnceLock::new());
    let slot = Arc::clone(&identity_slot);
    let composition = MemoryV1Composition::new(
        owner,
        move |identity| {
            assert!(slot.set(identity).is_ok());
            Router::new()
        },
        trustgraph,
        config,
    )
    .unwrap();
    let identity = identity_slot.get().unwrap();
    let handle = composition._root.handle();
    let serving = composition
        ._root
        .adopt_serving_for_isolated_tests()
        .unwrap();
    let router = composition.router();
    let auth = authenticator();
    let alice = login(
        identity,
        &auth,
        &handle,
        "alice",
        "alice-secret",
        CARD_DOCUMENT,
    )
    .await
    .unwrap();
    let bob_b = login(
        identity,
        &auth,
        &handle,
        "bob",
        "bob-secret",
        BOB_CARD_TENANT_B,
    )
    .await
    .unwrap();

    // 0. The composed objectless route still admits the base-card session and
    //    strips forged headers; this is the same live root the document reads
    //    use, and the document card's credential is refused there.
    let base_alice = login(
        identity,
        &auth,
        &handle,
        "alice",
        "alice-secret",
        CARD_ALLOW,
    )
    .await
    .unwrap();
    let (status, _) = send(&router, Some(&base_alice)).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(&router, Some(&alice)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let pinned = observations.lock().unwrap().pop().unwrap();
    assert_eq!(pinned.metadata, serving);
    assert!(pinned.forged_headers_absent && pinned.bearer_absent);

    // 1. Sessions bind to their own request scopes through the real Identity
    //    path; each document read runs on its own scope with the host triple.
    let alice_scope = astral_authorization_root::memory_v1_request::RequestRootScope::new(
        handle.clone(),
        uuid::Uuid::new_v4(),
    );
    let alice_root = alice_scope.extension();
    let bob_scope = astral_authorization_root::memory_v1_request::RequestRootScope::new(
        handle.clone(),
        uuid::Uuid::new_v4(),
    );
    let bob_root = bob_scope.extension();
    let alice_session = composition
        ._session_authority
        .verifier()
        .verify_and_bind(&alice, super::now(), &alice_root)
        .unwrap();
    let bob_session = composition
        ._session_authority
        .verifier()
        .verify_and_bind(&bob_b, super::now(), &bob_root)
        .unwrap();

    // 2. Alice reads her own document: own tenant, own owner — allowed.
    let allowed = read_document(&engine, &alice_root, &alice_session, ALICE_DOCUMENT);
    assert_eq!(allowed.decision, MemoryV1Decision::Allow, "{allowed:?}");
    let admission = allowed
        .admission
        .expect("the allowed read binds an admission");
    assert_eq!(admission.root(), serving);
    assert_eq!(admission.target_owner(), Some(ALICE.as_slice()));
    assert_eq!(admission.target_tenant(), Some(TENANT.as_slice()));
    assert_eq!(
        admission.effective_owner_scope(),
        MemoryV1OwnerScope::SelfUser
    );

    // 3. Cross-owner: a real host record says Bob owns the document; the
    //    engine denies deterministically and binds no admission.
    let denied = read_document(&engine, &alice_root, &alice_session, BOB_DOCUMENT);
    assert_eq!(denied.decision, MemoryV1Decision::Deny);
    assert!(denied.admission.is_none());

    // 4. Cross-tenant: Bob's tenant-B document against Alice's tenant-scoped
    //    binding is the same deterministic refusal.
    let denied = read_document(&engine, &alice_root, &alice_session, BOB_DOCUMENT_TENANT_B);
    assert_eq!(denied.decision, MemoryV1Decision::Deny);
    assert!(denied.admission.is_none());

    // 5. Unknown document: the host produces no attribution at all, so the
    //    object-bearing request is unverifiable and stays pending (fail-closed),
    //    never a silent type-level allow.
    let pending = read_document(&engine, &alice_root, &alice_session, [0x7f; 16]);
    assert_eq!(pending.decision, MemoryV1Decision::Pending);

    // 6. Bob in tenant B reads his own tenant-B document through his card.
    let allowed = read_document(&engine, &bob_root, &bob_session, BOB_DOCUMENT_TENANT_B);
    assert_eq!(allowed.decision, MemoryV1Decision::Allow);

    // 7. The held view from step 2 keeps its pinned root; a revoking publication
    //    must not be bypassed by it, and an unrelated publication neither
    //    revokes nor creates anything.
    let unrelated = composition
        ._root
        .execute_mutation_with_precondition_for_isolated_tests(
            &astral_authorization_root::memory_v1_root::ManagementMutationV2::UserCardCreate {
                row: astral_authorization_root::memory_v1_db_rows::UserCardRow {
                    user_card_id: [0x3a; 16],
                    user_id: BOB,
                    tenant_id: TENANT_B,
                    status: UserCardStatus::Active,
                },
            },
            &astral_authorization_root::memory_v1_root::MutationPrecondition {
                evaluated_root_version: serving.version,
            },
        )
        .unwrap();
    assert_eq!(unrelated.version, serving.version + 1);
    let still_allowed = read_document(&engine, &alice_root, &alice_session, ALICE_DOCUMENT);
    assert_eq!(still_allowed.decision, MemoryV1Decision::Allow);

    // memory—v1: Withdraw Alice's document binding through the restricted
    // mutation surface; the held reader cannot see it, fresh readers deny.
    let binding_id: [u8; 16] = [0x55; 16];
    let revoked = composition
        ._root
        .execute_mutation_with_precondition_for_isolated_tests(
            &astral_authorization_root::memory_v1_root::ManagementMutationV2::BindingRemove {
                binding_id,
                removed_at: super::now() + 1,
                removed_by: BOB,
            },
            &astral_authorization_root::memory_v1_root::MutationPrecondition {
                evaluated_root_version: unrelated.version,
            },
        )
        .unwrap();
    assert_eq!(revoked.version, unrelated.version + 1);
    assert_ne!(revoked.digest, unrelated.digest);
    // Held reader: recheck against the advanced root fails — the stale
    // evaluation can no longer reach an allow on this scope.
    let held = read_document(&engine, &alice_root, &alice_session, ALICE_DOCUMENT);
    assert_eq!(held.decision, MemoryV1Decision::Pending);
    assert!(held.admission.is_none());
    assert_eq!(
        alice_root.with_reader(|reader| reader.metadata()).unwrap(),
        serving,
        "the held reader never re-pins to the newer root"
    );
    // Fresh scope: the document binding is gone, so the read denies.
    let fresh_scope = astral_authorization_root::memory_v1_request::RequestRootScope::new(
        handle.clone(),
        uuid::Uuid::new_v4(),
    );
    let fresh_root = fresh_scope.extension();
    let fresh_session = composition
        ._session_authority
        .verifier()
        .verify_and_bind(&alice, super::now(), &fresh_root)
        .unwrap();
    let fresh = read_document(&engine, &fresh_root, &fresh_session, ALICE_DOCUMENT);
    assert_eq!(fresh.decision, MemoryV1Decision::Deny);
    assert!(fresh.admission.is_none());
    // Bob's tenant-B path is untouched by Alice's withdrawal.
    let bob_allowed = read_document(&engine, &bob_root, &bob_session, BOB_DOCUMENT_TENANT_B);
    assert_eq!(bob_allowed.decision, MemoryV1Decision::Allow);

    let stats = engine.get_stats();
    println!(
        "attribution: host-bound object triple admitted own reads, denied cross-owner and cross-tenant, pended the unattributed unknown, kept the unrelated publication harmless; binding withdrawal pends the held view and denies fresh readers only for the affected card; composed-route controls stayed intact; evaluations={}",
        stats.evaluation_count
    );
    assert_eq!(composition.request_scope_budget().active(), 0);
}
