//! MT-E4 多租户混合极限:跨租户失效风暴。
//!
//! 16 个租户各自发布 gen1 后,**全部租户同时**发布 gen2(每租户独立的新
//! grant)。风暴期间,针对"未在本轮翻转的租户"的读者必须持续观察到 gen1
//! 证据原样不变(失效隔离:一个租户的发布绝不惊动其他租户的已发布证据);
//! 风暴结束后所有租户收敛到 gen2 的独立新授权。
//!
//! 运行:`cargo test -p testsuite --test mt_extreme_cross_storm -- --ignored`

use astral_db::load_published_card_grant_evidence;
use astral_types::{GrantEffect, PublishedEvidenceGateStatus};
use testsuite::{
    allow_rule_set_grant, cleanup_suite_rows, connect_suite, publish_card_manifest,
    seed_all_tenants, SuiteFixture, TenantRole,
};

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

    // gen1:每租户 1 条 ALLOW(tail 1);记录 gen1 grant_id 作为"未被惊动"的锚。
    let mut pointers = Vec::new();
    for tenant in &fixture.tenants {
        let grants = vec![allow_rule_set_grant(
            fixture.salt,
            tenant.tenant_id,
            tenant.domain_id,
            tenant.card_id,
            tenant.user_id,
            "learn_subject:*",
            tenant.entry_id,
            tenant.card_rule_set_ref_id,
            1,
        )];
        let outcome = publish_card_manifest(
            &pool,
            tenant.tenant_id,
            tenant.card_id,
            grants,
            &format!("g1-{}", tenant.ordinal),
            fixture.salt,
            1,
            None,
        )
        .await;
        pointers.push(outcome.pointer);
    }

    let pool = std::sync::Arc::new(pool);
    let fixture = std::sync::Arc::new(fixture);
    let pointers = std::sync::Arc::new(pointers);

    // 风暴期间的"旁证读者":持续读取其他租户,断言 gen1 证据原样。
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
                    // gen2 写入中:本租户可能已是 gen2(tail 2)——但**绝不**
                    // 出现他人的 grant 或混合代际。
                    assert_eq!(evidence.gate.status, PublishedEvidenceGateStatus::Ready);
                    assert_eq!(evidence.gate.effective_grant_count, 1);
                    let grant = &evidence.effective_grants[0];
                    assert_eq!(grant.tenant.tenant_id, tenant.tenant_id);
                    assert_eq!(grant.action, "read");
                    assert_eq!(grant.effect, GrantEffect::Allow);
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
        let pointers = pointers.clone();
        storm.push(tokio::spawn(async move {
            let grants = vec![allow_rule_set_grant(
                fixture.salt,
                tenant.tenant_id,
                tenant.domain_id,
                tenant.card_id,
                tenant.user_id,
                "learn_subject:*",
                tenant.entry_id,
                tenant.card_rule_set_ref_id,
                2,
            )];
            publish_card_manifest(
                &pool,
                tenant.tenant_id,
                tenant.card_id,
                grants,
                &format!("g2-{}", tenant.ordinal),
                fixture.salt,
                2,
                Some(pointers[tenant.ordinal as usize - 1].as_view()),
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

    // 收敛:全部租户 gen2 独立授权(每租户恰 1 条、租户匹配、tail 2 身份)。
    for tenant in &fixture.tenants {
        let evidence = load_published_card_grant_evidence(&pool, &tenant.card_scope())
            .await
            .expect("post-storm evidence must load");
        assert_eq!(evidence.gate.status, PublishedEvidenceGateStatus::Ready);
        assert_eq!(evidence.gate.effective_grant_count, 1);
        let grant = &evidence.effective_grants[0];
        assert_eq!(grant.tenant.tenant_id, tenant.tenant_id);
        assert_eq!(
            grant.provenance.source_id,
            format!("rule-set-entry:{}", tenant.entry_id)
        );
    }

    cleanup_suite_rows(&pool, &fixture).await.unwrap();
}
