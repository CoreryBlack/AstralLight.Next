//! 安全前提 P-Hub:内存权威读面的失效通道遗漏危害与全契约闭合。
//!
//! 架构契约(Rust内存权威读面与失效通道架构方案_V0.1):
//! MemoryProjectionHub 是进程内权威读面,已发布状态安装后 **Serve**;
//! 发布后的失效通知(apply_evidence_invalidation)是**新鲜度栅栏**——
//! 只有它能把读面推进到 DeferToDurable(fail-closed 回落权威 DB)。
//! 本前提证明两件事:
//! 1. **遗漏危害**:失效通知未应用时,hub 持续 Serve 旧代证据
//!    (通知是承重结构,不是可选项);
//! 2. **全契约闭合**:通知一经应用(更高 source_generation),同 scope
//!    的读取立即 DeferToDurable,绝不 Serve 陈旧状态。
//!
//! 纯进程内(不依赖 DB);hub 为进程级 OnceLock,故本文件是独立测试二进制。
//!
//! 运行:`cargo test -p testsuite --test premise_hub_invalidation`
//! (testsuite 默认 feature 已启用 astral-db/test-support)。

use astral_db::memory_projection_hub::{
    install_memory_projection_hub, memory_projection_hub, EvidenceInvalidationRequest,
};
use astral_db::AuthorizationPublishedState;
use astral_types::{
    DependencyVersion, DomainScopeRequirement, GrantEffect, PublishedCardEvidenceScope,
    PublishedEvidenceAggregate,
};
use policy_engine::HotState;
use testsuite::allow_rule_set_grant;

const SUITE_SALT: u128 = 0x5EED_5EED_5EED_0001;

fn hot_state() -> HotState {
    let grant = allow_rule_set_grant(
        SUITE_SALT,
        7,
        11,
        17,
        42,
        "learn_subject:*",
        9,
        3,
        1,
    );
    let dependency = astral_types::DependencyVector::new(vec![
        DependencyVersion::new("card", 1, 0).unwrap(),
        DependencyVersion::new("rule-set", 1, 0).unwrap(),
    ])
    .unwrap();
    HotState::from_grants(
        astral_types::TenantScope::new(7, Some(11)).unwrap(),
        17,
        vec![grant],
        dependency,
    )
    .unwrap()
}

fn scope() -> PublishedCardEvidenceScope {
    PublishedCardEvidenceScope {
        tenant_id: 7,
        card_id: 17,
        user_filter: Some(42),
        domain: DomainScopeRequirement::Unconstrained,
    }
}

fn sealed_generation(generation: u64) -> AuthorizationPublishedState {
    let identity =
        astral_db::ProjectionAggregateIdentity::new(7, "USER_CARD", 17).unwrap();
    testsuite::seal_published_state_for_tests(&identity, 17, generation, hot_state(), None, 0)
}

fn invalidation(source_generation: u64, published_generation: u64) -> EvidenceInvalidationRequest {
    EvidenceInvalidationRequest {
        tenant_id: 7,
        card_id: Some(17),
        aggregate_type: PublishedEvidenceAggregate::UserCard,
        aggregate_id: 17,
        event_id: format!("event-{source_generation}"),
        operation_id: format!("operation-{source_generation}"),
        source_generation,
        published_generation,
        revoke_fence: 0,
    }
}

#[test]
fn hub_invalidation_notification_is_the_load_bearing_freshness_fence() {
    assert!(
        install_memory_projection_hub(),
        "hub must install exactly once per process (file-isolated test binary)"
    );
    let hub = memory_projection_hub().expect("installed hub must be retrievable");

    // 全契约:安装 gen1 已发布状态后,同 scope 读取 Serve 且证据指向本租户。
    hub.install_published_state(sealed_generation(1));
    let served = match hub.try_memory_evidence(&scope()) {
        astral_db::MemoryEvidenceOutcome::Serve(evidence) => evidence,
        other => panic!("freshly installed state must Serve, got {other:?}"),
    };
    assert_eq!(served.gate.effective_grant_count, 1);
    assert_eq!(served.effective_grants[0].effect, GrantEffect::Allow);
    assert_eq!(served.effective_grants[0].tenant.tenant_id, 7);

    // 遗漏危害(文档化):不应用失效通知时,hub 持续 Serve 旧代——
    // 这正是失效通知承重的原因(生产由 local bus/组合进程保证通知必达)。
    let still_serving = hub.try_memory_evidence(&scope());
    assert!(matches!(
        still_serving,
        astral_db::MemoryEvidenceOutcome::Serve(_)
    ));

    // 全契约闭合:更高 source_generation 的失效通知应用后,读取立即
    // DeferToDurable(fail-closed 回落权威 DB),绝不 Serve 陈旧状态。
    hub.apply_evidence_invalidation(invalidation(2, 1))
        .expect("well-formed invalidation must be accepted");
    let deferred = hub.try_memory_evidence(&scope());
    assert!(
        matches!(
            deferred,
            astral_db::MemoryEvidenceOutcome::DeferToDurable
        ),
        "after invalidation the hub must defer to durable instead of serving stale evidence"
    );
}
