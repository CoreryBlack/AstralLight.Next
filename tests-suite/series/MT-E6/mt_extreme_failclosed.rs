//! MT-E6 多租户混合极限:混合状态全景下的 fail-closed。
//!
//! 12 个租户构成一张"混合状态全景图":正常授权 / 已撤销 / SUSPENDED /
//! 从未发布 / 跨租户读取,断言每一种非授权形态都必须给出**显式的非 Ready
//! 或零授权**结果(绝不静默放行、绝不返回他人授权),且正常租户在全景中
//! 不受任何其他租户异常状态影响。
//!
//! 运行:`cargo test -p testsuite --test mt_extreme_failclosed -- --ignored`

use astral_db::load_published_card_grant_evidence;
#[path = "../MT-E1/support/source_identity.rs"]
mod source_identity;

use astral_trustgraph::service::rule_set_write_service::AddEntryRequest;
use astral_types::{
    DomainScopeRequirement, PublishedCardEvidenceScope, PublishedEvidenceGateStatus,
};
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

#[tokio::test]
#[ignore = "requires isolated MySQL via DATABASE_URL (multi-tenant extreme)"]
async fn mt_e6_mixed_state_fail_closed_landscape() {
    let Some(pool) = connect_suite().await else {
        return;
    };
    // 12 租户:0-3 正常授权;4-5 授权后撤销;6-7 SUSPENDED;8-11 正常授权
    // (对照面),其中 8/9 的卡**不发布**(从未发布形态用独立卡 id)。
    let mut roles = vec![TenantRole::AllowActive; 12];
    roles[6] = TenantRole::DenySuspended;
    roles[7] = TenantRole::DenySuspended;
    let fixture = SuiteFixture::new("mt-e6", &roles);
    seed_all_tenants(&pool, &fixture).await.unwrap();

    let unpublished = [8usize, 9];
    for tenant in &fixture.tenants {
        if unpublished.contains(&(tenant.ordinal as usize - 1)) {
            continue; // 保持未发布形态
        }
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

    // 4-5 号租户:真实 source REMOVE episode 撤销(零有效授权)。
    for tenant in fixture.tenants.iter().take(6).skip(4) {
        let tag = format!("revoke-{}", tenant.ordinal);
        let revoked = publish_card_manifest(
            &pool,
            tenant.tenant_id,
            tenant.card_id,
            tenant.rule_set_id,
            tenant.user_id,
            Vec::new(),
            (&tag, fixture.salt),
        )
        .await;
        assert_eq!(revoked.published_state.total_grant_count, 0);
    }

    // ── 全景断言 ──
    for tenant in &fixture.tenants {
        let ordinal = tenant.ordinal as usize - 1;
        let result = load_published_card_grant_evidence(&pool, &tenant.card_scope()).await;
        if unpublished.contains(&ordinal) {
            let error = result.expect_err("unpublished card must not yield READY evidence");
            assert!(
                matches!(error, astral_db::AuthorizationEvidenceError::NotReady(ref code)
                if code.contains("current_pointer_missing")),
                "unexpected refusal: {error}"
            );
            assert_eq!(error.as_gate_status(), PublishedEvidenceGateStatus::Pending);
            continue;
        }
        let evidence = result.expect("published landscape read must not error");
        assert_eq!(evidence.gate.status, PublishedEvidenceGateStatus::Ready);
        let expected = if ordinal <= 3 || ordinal >= 10 {
            1usize
        } else {
            0usize
        };
        assert_eq!(
            evidence.gate.effective_grant_count, expected,
            "tenant {} landscape mismatch",
            tenant.tenant_id
        );
        assert!(evidence
            .effective_grants
            .iter()
            .all(|grant| grant.tenant.tenant_id == tenant.tenant_id));
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

    // 跨租户读取全景:每个正常租户的卡,被其余每个租户的 scope 读取,
    // 都必须 fail-closed(非 Ready 或零授权),绝不泄露。
    let normal = &fixture.tenants[0];
    for probe in &fixture.tenants {
        if probe.tenant_id == normal.tenant_id {
            continue;
        }
        let scope = PublishedCardEvidenceScope {
            tenant_id: probe.tenant_id,
            card_id: normal.card_id,
            user_filter: None,
            domain: DomainScopeRequirement::ExactlySome(probe.domain_id),
        };
        let error = load_published_card_grant_evidence(&pool, &scope)
            .await
            .expect_err("foreign card must not yield published evidence");
        assert!(
            matches!(error, astral_db::AuthorizationEvidenceError::NotReady(ref code)
            if code.contains("current_pointer_missing")),
            "unexpected refusal: {error}"
        );
        assert_eq!(error.as_gate_status(), PublishedEvidenceGateStatus::Pending);
    }

    // 正常租户在全景中的对照面:其证据与单租户场景完全一致(隔离无扰)。
    let normal = &fixture.tenants[10];
    let evidence = load_published_card_grant_evidence(&pool, &normal.card_scope())
        .await
        .unwrap();
    assert_eq!(evidence.gate.effective_grant_count, 1);
    source_identity::assert_ruleset_source_binding(
        &pool,
        &evidence.effective_grants[0],
        normal.tenant_id,
        normal.card_id,
        normal.rule_set_id,
    )
    .await;

    cleanup_suite_rows(&pool, &fixture).await.unwrap();
}
