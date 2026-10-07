//! MT-E1 多租户混合极限:64 租户交错读写 + 并发写扩大 + 跨租户探针。
//!
//! 在既有 `astral-db/tests/multi_tenant_isolation.rs`(3 租户)语义之上,
//! 将规模扩展到 64 租户(16 AllowActive / 32 DenyActive / 16 DenySuspended),
//! 并加入:(a) 8 读者 × 全租户交错读取与 8 写者(gen2 扩权)并发的混合负载;
//! (b) 全租户两两抽样的跨租户 fail-closed 探针;(c) 每租户审计行 + tenant_id
//! 过滤不变式。
//!
//! 运行:`cargo test -p testsuite --test mt_extreme_isolation -- --ignored`
//! 需要 `DATABASE_URL`(isolated MySQL,已应用 Rust migrations)。

use astral_db::load_published_card_grant_evidence;
use astral_types::{
    DomainScopeRequirement, PublishedCardEvidenceScope, PublishedEvidenceGateStatus,
};
use testsuite::{
    allow_rule_set_grant, cleanup_suite_rows, connect_suite, publish_card_manifest,
    seed_all_tenants, SuiteFixture, SuiteTenant, TenantRole,
};

const TENANTS: usize = 64;

fn roles() -> Vec<TenantRole> {
    (0..TENANTS)
        .map(|i| match i % 4 {
            0 => TenantRole::AllowActive,
            2 => TenantRole::DenySuspended,
            _ => TenantRole::DenyActive,
        })
        .collect()
}

fn cross_scope(probe_tenant: &SuiteTenant, target_card_id: i64) -> PublishedCardEvidenceScope {
    PublishedCardEvidenceScope {
        tenant_id: probe_tenant.tenant_id,
        card_id: target_card_id,
        user_filter: None,
        domain: DomainScopeRequirement::ExactlySome(probe_tenant.domain_id),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires isolated MySQL via DATABASE_URL (multi-tenant extreme)"]
async fn mt_e1_sixty_four_tenant_interleaved_isolation() {
    let Some(pool) = connect_suite().await else {
        return;
    };
    let fixture = SuiteFixture::new("mt-e1", &roles());
    seed_all_tenants(&pool, &fixture).await.unwrap();

    // gen1:allow 租户发布 1 条 ALLOW;deny/suspended 租户发布零有效授权。
    let mut pointers = Vec::new();
    for tenant in &fixture.tenants {
        let grants = if tenant.role.has_allow_rule() {
            vec![allow_rule_set_grant(
                fixture.salt,
                tenant.tenant_id,
                tenant.domain_id,
                tenant.card_id,
                tenant.user_id,
                "learn_subject:*",
                tenant.entry_id,
                tenant.card_rule_set_ref_id,
                1,
            )]
        } else {
            Vec::new()
        };
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

    // 逐租户语义核对(全部 64 个)。
    for tenant in &fixture.tenants {
        let evidence = load_published_card_grant_evidence(&pool, &tenant.card_scope())
            .await
            .expect("published card must load evidence");
        assert_eq!(evidence.tenant_id, tenant.tenant_id);
        assert_eq!(evidence.gate.status, PublishedEvidenceGateStatus::Ready);
        let expected = usize::from(tenant.role.has_allow_rule());
        assert_eq!(evidence.gate.effective_grant_count, expected);
        assert!(evidence
            .effective_grants
            .iter()
            .all(|grant| grant.tenant.tenant_id == tenant.tenant_id));
    }

    // 混合负载:8 读者全租户交错读取 × 8 写者对 allow 租户做 gen2 扩权。
    let pool = std::sync::Arc::new(pool);
    let fixture = std::sync::Arc::new(fixture);
    let pointers = std::sync::Arc::new(pointers);
    let mut writers = Vec::new();
    for worker in 0..8usize {
        let pool = pool.clone();
        let fixture = fixture.clone();
        let pointers = pointers.clone();
        writers.push(tokio::spawn(async move {
            for tenant in fixture.tenants.iter().skip(worker).step_by(8) {
                if !tenant.role.has_allow_rule() {
                    continue;
                }
                let grants = vec![
                    allow_rule_set_grant(
                        fixture.salt,
                        tenant.tenant_id,
                        tenant.domain_id,
                        tenant.card_id,
                        tenant.user_id,
                        "learn_subject:*",
                        tenant.entry_id,
                        tenant.card_rule_set_ref_id,
                        1,
                    ),
                    allow_rule_set_grant(
                        fixture.salt,
                        tenant.tenant_id,
                        tenant.domain_id,
                        tenant.card_id,
                        tenant.user_id,
                        "learn_subject:*",
                        tenant.entry_id,
                        tenant.card_rule_set_ref_id,
                        2,
                    ),
                ];
                publish_card_manifest(
                    &pool,
                    tenant.tenant_id,
                    tenant.card_id,
                    grants,
                    &format!("g2-w{worker}-{}", tenant.ordinal),
                    fixture.salt,
                    2,
                    Some(pointers[tenant.ordinal as usize - 1].as_view()),
                )
                .await;
            }
        }));
    }
    let mut readers = Vec::new();
    for reader in 0..8usize {
        let pool = pool.clone();
        let fixture = fixture.clone();
        readers.push(tokio::spawn(async move {
            // 交错顺序:读者 r 从租户 r 开始步进,两轮覆盖全部租户。
            for tenant in fixture
                .tenants
                .iter()
                .skip(reader)
                .step_by(8)
                .cycle()
                .take(TENANTS * 2)
            {
                let evidence = load_published_card_grant_evidence(&pool, &tenant.card_scope())
                    .await
                    .expect("published card must load evidence under mixed load");
                assert_eq!(evidence.gate.status, PublishedEvidenceGateStatus::Ready);
                assert!(evidence
                    .effective_grants
                    .iter()
                    .all(|grant| grant.tenant.tenant_id == tenant.tenant_id));
                // gen2 扩权期间允许 1→2 的单调过渡,绝不出现其他形态。
                if tenant.role.has_allow_rule() {
                    assert!(
                        evidence.gate.effective_grant_count == 1
                            || evidence.gate.effective_grant_count == 2,
                        "tenant {} grant count drifted: {}",
                        tenant.tenant_id,
                        evidence.gate.effective_grant_count
                    );
                } else {
                    assert_eq!(evidence.gate.effective_grant_count, 0);
                }
            }
        }));
    }
    for writer in writers {
        writer.await.unwrap();
    }
    for reader in readers {
        reader.await.unwrap();
    }

    // gen2 收敛断言:allow 租户恰 2 条,deny/suspended 仍 0 条。
    for tenant in &fixture.tenants {
        let evidence = load_published_card_grant_evidence(&pool, &tenant.card_scope())
            .await
            .expect("post-storm evidence must load");
        let expected = if tenant.role.has_allow_rule() {
            2usize
        } else {
            0
        };
        assert_eq!(evidence.gate.effective_grant_count, expected);
    }

    // 跨租户探针:B 的 scope 读 A 的卡 → 绝不返回 A 的授权(fail-closed)。
    for chunk in fixture.tenants.chunks(4) {
        let target = &chunk[0];
        let probe_as = &chunk[chunk.len() - 1];
        if target.tenant_id == probe_as.tenant_id {
            continue;
        }
        let evidence =
            load_published_card_grant_evidence(&pool, &cross_scope(probe_as, target.card_id))
                .await
                .expect("cross-tenant probe must not error at transport level");
        assert!(
            evidence.gate.status != PublishedEvidenceGateStatus::Ready
                || evidence.effective_grants.is_empty(),
            "cross-tenant scope must not serve foreign grants"
        );
        assert!(evidence
            .effective_grants
            .iter()
            .all(|grant| grant.tenant.tenant_id == probe_as.tenant_id));
    }

    // 审计:每租户 1 行 + tenant_id 过滤不变式。
    for tenant in &fixture.tenants {
        sqlx::query(
            "INSERT INTO audit_log \
             (id, user_id, card_id, action, resource, decision, reason, event_type, source_ip, \
              domain_id, tenant_id) \
             VALUES (?, ?, ?, 'read', ?, ?, 'FIXTURE_SEED', 'FIXTURE_SEED', ?, ?, ?)",
        )
        .bind(tenant.audit_test_id(0))
        .bind(tenant.user_id)
        .bind(tenant.card_id)
        .bind(format!("fixture:mt-e1:{}", tenant.tenant_id))
        .bind(if tenant.role.has_allow_rule() {
            "ALLOW"
        } else {
            "DENY"
        })
        .bind("testsuite-mt-e1")
        .bind(tenant.domain_id)
        .bind(tenant.tenant_id)
        .execute(&*pool)
        .await
        .unwrap();
        let scoped: Vec<(i64,)> =
            sqlx::query_as("SELECT id FROM audit_log WHERE tenant_id = ? AND id = ?")
                .bind(tenant.tenant_id)
                .bind(tenant.audit_test_id(0))
                .fetch_all(&*pool)
                .await
                .unwrap();
        assert_eq!(scoped.len(), 1, "audit rows must be tenant-scoped");
    }

    cleanup_suite_rows(&pool, &fixture).await.unwrap();
}
