//! MT-E4 多租户混合极限:跨租户失效风暴。
//!
//! 16 个租户各自发布 gen1 后,**全部租户同时**通过生产 source writer 将 BASE
//! entries 替换为两条独立 source entry。风暴期间读者检查同租户 grant 的身份、
//! source row 与 BASE binding 始终一致;结束后所有租户收敛到两条真实授权。
//!
//! 运行:`cargo test -p testsuite --test mt_extreme_cross_storm -- --ignored`

use astral_db::load_published_card_grant_evidence;
#[path = "../MT-E1/support/source_identity.rs"]
mod source_identity;

use astral_trustgraph::service::rule_set_write_service::AddEntryRequest;
use astral_types::PublishedEvidenceGateStatus;
use testsuite::{
    cleanup_suite_rows, connect_suite, publish_card_manifest, seed_all_tenants, SuiteFixture,
    TenantRole,
};

fn allow_entry(priority: i32) -> AddEntryRequest {
    AddEntryRequest {
        effect: "ALLOW".to_owned(),
        resource_type: Some("learn_subject".to_owned()),
        resource_id: None,
        action_code: Some("read".to_owned()),
        condition_json: None,
        priority,
    }
}

const TENANTS: usize = 16;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires isolated MySQL via DATABASE_URL (multi-tenant extreme)"]
async fn mt_e4_cross_tenant_invalidation_storm() {
    let Some(pool) = connect_suite().await else {
        return;
    };
    let roles = vec![TenantRole::AllowActive; TENANTS];
    let fixture = SuiteFixture::new("mt-e4", &roles);
    seed_all_tenants(&pool, &fixture).await.unwrap();

    // gen1:每租户通过 source mutation 创建自己的真实 BASE entry。
    for tenant in &fixture.tenants {
        let tag = format!("g1-{}", tenant.ordinal);
        let outcome = publish_card_manifest(
            &pool,
            tenant.tenant_id,
            tenant.card_id,
            tenant.rule_set_id,
            tenant.user_id,
            vec![allow_entry(2)],
            (&tag, fixture.salt),
        )
        .await;
        assert_eq!(outcome.published_state.total_grant_count, 1);
    }

    let pool = std::sync::Arc::new(pool);
    let fixture = std::sync::Arc::new(fixture);

    // 风暴期间并发读取全体租户，验证授权始终属于自身 source 与 binding。
    let mut side_readers = Vec::new();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    for reader in 0..4usize {
        let pool = pool.clone();
        let fixture = fixture.clone();
        let stop = stop.clone();
        side_readers.push(tokio::spawn(async move {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                for tenant in fixture.tenants.iter().skip(reader).step_by(4) {
                    let evidence = load_published_card_grant_evidence(&pool, &tenant.card_scope())
                        .await
                        .expect("side read must load evidence");
                    // The tenant remains on its own strict Ready state while other
                    // tenants replace their entries concurrently.
                    assert_eq!(evidence.gate.status, PublishedEvidenceGateStatus::Ready);
                    assert_eq!(evidence.gate.effective_grant_count, 1);
                    let grant = &evidence.effective_grants[0];
                    assert_eq!(grant.tenant.tenant_id, tenant.tenant_id);
                    source_identity::assert_ruleset_source_binding(
                        &pool,
                        grant,
                        tenant.tenant_id,
                        tenant.card_id,
                        tenant.rule_set_id,
                    )
                    .await;
                }
            }
        }));
    }

    // 风暴:16 个租户并发发布 gen2(独立 tail 2)。
    let mut storm = Vec::new();
    for tenant in &fixture.tenants {
        let tenant = *tenant;
        let pool = pool.clone();
        let fixture = fixture.clone();
        storm.push(tokio::spawn(async move {
            let tag = format!("g2-{}", tenant.ordinal);
            publish_card_manifest(
                &pool,
                tenant.tenant_id,
                tenant.card_id,
                tenant.rule_set_id,
                tenant.user_id,
                vec![allow_entry(3), allow_entry(4)],
                (&tag, fixture.salt),
            )
            .await
        }));
    }
    for handle in storm {
        handle.await.unwrap();
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for reader in side_readers {
        reader.await.unwrap();
    }

    // 收敛:全部租户各自拥有两条可回溯到真实 source 的 ALLOW grants。
    for tenant in &fixture.tenants {
        let evidence = load_published_card_grant_evidence(&pool, &tenant.card_scope())
            .await
            .expect("post-storm evidence must load");
        assert_eq!(evidence.gate.status, PublishedEvidenceGateStatus::Ready);
        assert_eq!(evidence.gate.effective_grant_count, 2);
        for grant in &evidence.effective_grants {
            source_identity::assert_ruleset_source_binding(
                &pool,
                grant,
                tenant.tenant_id,
                tenant.card_id,
                tenant.rule_set_id,
            )
            .await;
        }
    }

    cleanup_suite_rows(&pool, &fixture).await.unwrap();
}
