//! MT-E3 多租户混合极限:租户授权状态搅动。
//!
//! 8 个 AllowActive 租户在"授权 ↔ 撤销"之间连续翻转 4 代
//! (gen2=撤销零有效授权,gen3=恢复授权,gen4=再撤销,gen5=再恢复),
//! 读者全程并发读取,断言每个读非 Ready 即 fail-closed、Ready 即与当前代
//! 或上一代语义一致(绝不出现第三种形态,绝不跨租户)。
//!
//! 运行:`cargo test -p testsuite --test mt_extreme_churn -- --ignored`

use astral_db::load_published_card_grant_evidence;
use astral_types::PublishedEvidenceGateStatus;
use testsuite::{
    allow_rule_set_grant, cleanup_suite_rows, connect_suite, publish_card_manifest,
    seed_all_tenants, SuiteFixture, TenantRole,
};

const TENANTS: usize = 8;
const ROUNDS: u64 = 4;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires isolated MySQL via DATABASE_URL (multi-tenant extreme)"]
async fn mt_e3_tenant_grant_churn() {
    let Some(pool) = connect_suite().await else {
        return;
    };
    let roles = vec![TenantRole::AllowActive; TENANTS];
    let fixture = SuiteFixture::new("mt-e3", &roles);
    seed_all_tenants(&pool, &fixture).await.unwrap();

    // gen1:全部发布 1 条 ALLOW(tail 1)。
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

    for round in 1..=ROUNDS {
        let generation = round + 1;
        let revoked = round % 2 == 1; // gen2/gen4 撤销,gen3/gen5 恢复

        // 并发读者:writers 翻转期间,读者断言"仅当前代或上一代语义"。
        let mut readers = Vec::new();
        for reader in 0..4usize {
            let pool = pool.clone();
            let fixture = fixture.clone();
            readers.push(tokio::spawn(async move {
                for tenant in fixture.tenants.iter().skip(reader).step_by(4) {
                    let evidence = load_published_card_grant_evidence(&pool, &tenant.card_scope())
                        .await
                        .expect("churn read must load evidence");
                    assert_eq!(evidence.gate.status, PublishedEvidenceGateStatus::Ready);
                    let count = evidence.gate.effective_grant_count;
                    assert!(
                        count == 0 || count == 1,
                        "tenant {} churn count out of envelope: {}",
                        tenant.tenant_id,
                        count
                    );
                    assert!(evidence
                        .effective_grants
                        .iter()
                        .all(|grant| grant.tenant.tenant_id == tenant.tenant_id));
                }
            }));
        }

        // 写者:全租户推进到 generation。
        for tenant in &fixture.tenants {
            let grants = if revoked {
                Vec::new()
            } else {
                vec![allow_rule_set_grant(
                    fixture.salt,
                    tenant.tenant_id,
                    tenant.domain_id,
                    tenant.card_id,
                    tenant.user_id,
                    "learn_subject:*",
                    tenant.entry_id,
                    tenant.card_rule_set_ref_id,
                    (round + 2) as u16,
                )]
            };
            let outcome = publish_card_manifest(
                &pool,
                tenant.tenant_id,
                tenant.card_id,
                grants,
                &format!("churn-r{round}-{}", tenant.ordinal),
                fixture.salt,
                generation,
                Some(pointers[tenant.ordinal as usize - 1].as_view()),
            )
            .await;
            pointers[tenant.ordinal as usize - 1] = outcome.pointer;
        }
        for reader in readers {
            reader.await.unwrap();
        }

        // 本代收敛:语义精确匹配。
        for tenant in &fixture.tenants {
            let evidence = load_published_card_grant_evidence(&pool, &tenant.card_scope())
                .await
                .expect("post-round evidence must load");
            assert_eq!(evidence.gate.status, PublishedEvidenceGateStatus::Ready);
            let expected = if revoked { 0usize } else { 1usize };
            assert_eq!(
                evidence.gate.effective_grant_count, expected,
                "tenant {} round {round} convergence failed",
                tenant.tenant_id
            );
        }
    }

    // 终态(第 4 轮 = 恢复):全部 1 条有效授权,READY 而非 Pending。
    for tenant in &fixture.tenants {
        let evidence = load_published_card_grant_evidence(&pool, &tenant.card_scope())
            .await
            .unwrap();
        assert_eq!(evidence.gate.status, PublishedEvidenceGateStatus::Ready);
        assert_eq!(evidence.gate.effective_grant_count, 1);
    }

    cleanup_suite_rows(&pool, &fixture).await.unwrap();
}
