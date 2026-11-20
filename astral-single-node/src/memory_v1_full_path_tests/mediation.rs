//! memory—v1: Card and tenant isolation at the composed ordinary HTTP route.

use super::*;

#[test]
fn ordinary_mediation_isolated_process() {
    const CHILD: &str = "ASTRAL_MEMORY_V1_ORDINARY_MEDIATION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // Use the exact test name rather than admitting another process-slot user.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "memory_v1_composition::full_path_tests::mediation::ordinary_mediation_isolated_process",
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
            if line.starts_with("mediation:") {
                println!("{line}");
            }
        }
        return;
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(ordinary_mediation());
}

// memory—v1: The real objectless registry route sees only the selected card's rules.
async fn ordinary_mediation() {
    const CHILD_TENANT: [u8; 16] = [0x78; 16];
    let (mut rows, selections) = fixture();
    rows.tenants.push(TenantRow {
        tenant_id: CHILD_TENANT,
        parent_tenant_id: Some(TENANT),
    });
    rows.user_cards
        .iter_mut()
        .find(|row| row.user_card_id == CARD_BOB)
        .unwrap()
        .tenant_id = CHILD_TENANT;
    let bob_binding = rows
        .bindings
        .iter()
        .find(|row| row.user_card_id == CARD_BOB)
        .unwrap()
        .binding_id;
    rows.bindings.retain(|row| row.binding_id != bob_binding);
    rows.binding_confirmations
        .retain(|row| row.binding_id != bob_binding);
    let budget = CandidateBudget {
        max_table_rows: 64,
        max_bindings_per_read: 8,
    };
    let owner = install_process_root(rows.clone(), selections.clone(), budget).unwrap();
    assert!(matches!(
        install_process_root(rows, selections, budget),
        Err(astral_authorization_root::memory_v1_root::RootError::AlreadyInstalled)
    ));
    owner
        .install_registry(&crate::memory_v1_service::registry_declarations())
        .unwrap();
    let serving = owner.adopt_serving_for_isolated_tests().unwrap();
    let handle = owner.handle();
    assert_eq!(
        astral_authorization_root::memory_v1_root::process_root_handle()
            .unwrap()
            .metadata()
            .unwrap(),
        serving
    );
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
    let auth = authenticator();
    assert_eq!(
        login(identity, &auth, &handle, "bob", "bob-secret", CARD_ALLOW).await,
        Err(MemoryV1LoginError::CardNotOwned)
    );
    let parent = login(
        identity,
        &auth,
        &handle,
        "alice",
        "alice-secret",
        CARD_ALLOW,
    )
    .await
    .unwrap();
    let child = login(identity, &auth, &handle, "bob", "bob-secret", CARD_BOB)
        .await
        .unwrap();
    let router = composition.router();
    let (status, body) = send(&router, Some(&parent)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["data"].is_array());
    let (status, body) = send(&router, Some(&child)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["decision"], "AUTHORIZATION_CARD_UNBOUND");
    assert_eq!(body["reasonCode"], "AUTHORIZATION_AUDIT_UNAVAILABLE");
    assert!(body["data"].is_null());
    assert_eq!(
        (
            engine.get_stats().evaluation_count,
            engine.get_stats().allow_count
        ),
        (2, 1)
    );
    let observed = observations.lock().unwrap();
    assert_eq!(observed.len(), 2);
    assert_ne!(
        observed[0].request_id_at_entry,
        observed[1].request_id_at_entry
    );
    for request in observed.iter() {
        assert_eq!(request.request_id_at_entry, request.request_id_at_exit);
        assert_eq!(request.metadata, serving);
        assert!(request.forged_headers_absent && request.bearer_absent);
        assert!(matches!(
            request.root.with_reader(|_| ()),
            Err(RequestRootAccessError::ScopeEnded)
        ));
    }
    assert_eq!(composition.request_scope_budget().active(), 0);
    println!("mediation: one installation, foreign-card login refused; parent registry 200, unbound child no admission; 2 evaluations, 1 allow, 0 live scopes");
}
