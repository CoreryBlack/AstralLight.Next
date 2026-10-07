//! MT-E5 多租户混合极限:容量极限(512 租户)。
//!
//! 播种 512 个 ACTIVE/ALLOW 租户,逐卡发布 gen1,然后**全量回读 512 张卡**
//! 断言:每张卡 Ready、恰 1 条属于本租户的授权、provenance 指回本租户的
//! 绑定链。耗时仅打印不入断言(不因阈值美观改动语义)。
//!
//! 运行:`cargo test -p testsuite --test mt_extreme_capacity -- --ignored`
//! 预期运行时长数分钟(512 × 4 短事务发布 + 512 次严格读取)。

use astral_db::load_published_card_grant_evidence;
use astral_types::PublishedEvidenceGateStatus;
use testsuite::{
    allow_rule_set_grant, cleanup_suite_rows, connect_suite, publish_card_manifest,
    seed_all_tenants, SuiteFixture, TenantRole,
};

const TENANTS: usize = 512;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires isolated MySQL via DATABASE_URL (multi-tenant extreme; runs minutes)"]
async fn mt_e5_capacity_512_tenants() {
    let Some(pool) = connect_suite().await else {
        return;
    };
    let roles = vec![TenantRole::AllowActive; TENANTS];
    let fixture = SuiteFixture::new("mt-e5", &roles);

    let seed_started = std::time::Instant::now();
    seed_all_tenants(&pool, &fixture).await.unwrap();
    let seed_elapsed = seed_started.elapsed();

    let publish_started = std::time::Instant::now();
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
        publish_card_manifest(
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
    }
    let publish_elapsed = publish_started.elapsed();

    // 全量严格回读:512 张卡逐一断言。
    let read_started = std::time::Instant::now();
    let mut max_read_us: u128 = 0;
    for tenant in &fixture.tenants {
        let started = std::time::Instant::now();
        let evidence = load_published_card_grant_evidence(&pool, &tenant.card_scope())
            .await
            .expect("capacity read must load evidence");
        max_read_us = max_read_us.max(started.elapsed().as_micros());
        assert_eq!(evidence.gate.status, PublishedEvidenceGateStatus::Ready);
        assert_eq!(evidence.gate.effective_grant_count, 1);
        let grant = &evidence.effective_grants[0];
        assert_eq!(grant.tenant.tenant_id, tenant.tenant_id);
        assert_eq!(grant.card_id, tenant.card_id);
        assert_eq!(grant.user_id, tenant.user_id);
    }
    let read_elapsed = read_started.elapsed();

    println!(
        "MT-E5 capacity envelope: tenants={TENANTS} seed={seed_elapsed:?} \
         publish={:?} read={:?} max_single_read_us={max_read_us}",
        publish_elapsed, read_elapsed
    );

    cleanup_suite_rows(&pool, &fixture).await.unwrap();
}
