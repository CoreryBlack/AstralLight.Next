//! CachedRuleRepository — RuleRepository 转发装饰器
//!
//! 旧的 `permission:snapshot:{card_id}` TTL 缓存不包含 generation、revoke
//! fence 或 manifest identity，不能作为正式授权证据。本装饰器不再读取或
//! 写入该缓存；`evict_card()` 仅保留删除旧部署残留 key 的兼容清理能力。
//!
//! 所有 read/gate 端口（包括 legacy snapshot、依赖门禁、卡上下文、委派、
//! 投影门禁和 published evidence）都精确转发 inner，不缓存、不转换。
//!
//! 用装饰器模式包装底层 `RuleRepository`，调用方无感知。

use std::sync::Arc;

use astral_types::{
    PolicyContext, PolicyError, PublishedCardAuthorization, PublishedCardEvidenceScope,
};
use policy_engine::{
    PermissionRule, ProjectionGate, RuleRepository, RuleSetDependencyStatus, RuleSetSnapshot,
    SnapshotWinner,
};
use redis::AsyncCommands;
use tracing::instrument;

/// 仅用于清理旧部署残留的缓存 key 前缀。
const KEY_PREFIX_SNAPSHOT: &str = "permission:snapshot";

/// 带 Redis 缓存的 RuleRepository 装饰器
pub struct CachedRuleRepository<R: RuleRepository> {
    inner: Arc<R>,
    redis: redis::aio::ConnectionManager,
}

impl<R: RuleRepository> CachedRuleRepository<R> {
    /// 创建缓存装饰器
    pub fn new(inner: R, redis: redis::aio::ConnectionManager) -> Self {
        Self {
            inner: Arc::new(inner),
            redis,
        }
    }

    /// 从 Redis 连接字符串创建
    pub async fn from_url(inner: R, url: &str) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(url)?;
        let mgr = client.get_connection_manager().await?;
        Ok(Self::new(inner, mgr))
    }

    /// 为指定卡片清除缓存（规则变更后调用）
    pub async fn evict_card(&self, card_id: i64) -> Result<(), redis::RedisError> {
        let key = format!("{KEY_PREFIX_SNAPSHOT}:{card_id}");
        let mut conn = self.redis.clone();
        conn.del::<_, ()>(&key).await?;
        tracing::debug!(card_id, "evicted permission cache");
        Ok(())
    }

    /// 判断快照是否含通配符
    pub fn has_wildcard(snapshots: &[RuleSetSnapshot]) -> bool {
        snapshots.iter().any(|s| {
            s.entries
                .iter()
                .any(|e| e.resource.as_deref() == Some("*") || e.action.as_deref() == Some("*"))
        })
    }
}

#[async_trait::async_trait]
impl<R: RuleRepository + Send + Sync> RuleRepository for CachedRuleRepository<R> {
    /// Capability marker 必须与 inner 保持一致；否则包装生产 SQLx
    /// repository 会继承 trait 默认 `false`，绕过 published-evidence strict gate。
    fn requires_published_card_evidence(&self) -> bool {
        self.inner.requires_published_card_evidence()
    }

    #[instrument(skip(self), fields(card_id))]
    async fn load_rule_set_snapshots(
        &self,
        card_id: i64,
    ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
        self.inner.load_rule_set_snapshots(card_id).await
    }

    #[instrument(skip(self), fields(card_id))]
    async fn load_permission_rules(
        &self,
        card_id: i64,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        // permission_rule 仅用于 CARD_ONLY 回退路径，查询频率低，不做缓存
        self.inner.load_permission_rules(card_id).await
    }

    // ---- 以下 read/gate 端口全部精确转发 inner（不缓存、不转换）----
    //
    // 任一端口若缺失转发，trait default（Ok(None)/空集合）会遮蔽生产
    // repository 的真实实现，使依赖门禁、卡上下文校验、委派读取、投影门禁
    // 与 published evidence 退化为 unavailable/PENDING。

    /// 依赖门禁：必须转发 inner 的 durable projection 状态，不得用 default
    /// `Ok(None)` 遮蔽生产实现。
    async fn load_rule_set_dependency_statuses(
        &self,
        card_id: i64,
    ) -> Result<Option<Vec<RuleSetDependencyStatus>>, PolicyError> {
        self.inner.load_rule_set_dependency_statuses(card_id).await
    }

    /// 卡上下文有效性：双卡权威校验属于 inner repository，装饰器不得用
    /// default（纯策略测试用）替代。
    async fn check_card_active(&self, ctx: &PolicyContext) -> Result<bool, PolicyError> {
        self.inner.check_card_active(ctx).await
    }

    async fn is_active_global_admin(&self, user_id: i64) -> Result<bool, PolicyError> {
        self.inner.is_active_global_admin(user_id).await
    }

    /// 预计算快照胜者：default 是空集合（回退 snapshot 加载路径），
    /// 生产 inner 的快速路径必须原样可达。
    async fn load_snapshot_winners(
        &self,
        card_id: i64,
    ) -> Result<Vec<SnapshotWinner>, PolicyError> {
        self.inner.load_snapshot_winners(card_id).await
    }

    /// 一致性检查专用 raw 读取：default 为空集合会静默跳过一致性检查的 L1，
    /// 必须转发 inner。
    async fn load_rule_set_entries_raw(
        &self,
        card_id: i64,
    ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
        self.inner.load_rule_set_entries_raw(card_id).await
    }

    /// 一致性检查专用 raw 读取：同上，必须转发 inner。
    async fn load_permission_rules_raw(
        &self,
        card_id: i64,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        self.inner.load_permission_rules_raw(card_id).await
    }

    /// Raw/realtime 委派读取（仅一致性路径）：参数原样透传。
    async fn load_delegated_rules(
        &self,
        delegate_id: i64,
        resource: &str,
        action: &str,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        self.inner
            .load_delegated_rules(delegate_id, resource, action)
            .await
    }

    /// 正式评估使用的 durable 委派投影读取：参数原样透传，
    /// 不得用 default 空集合遮蔽生产实现。
    async fn load_projected_delegated_rules(
        &self,
        delegate_id: i64,
        resource: &str,
        action: &str,
    ) -> Result<Vec<PermissionRule>, PolicyError> {
        self.inner
            .load_projected_delegated_rules(delegate_id, resource, action)
            .await
    }

    /// 投影门禁：default `Ok(None)` 仅服务于 test/default repository；
    /// 生产 inner 的显式 gate 必须原样转发。
    async fn get_projection_gate(
        &self,
        card_id: i64,
    ) -> Result<Option<ProjectionGate>, PolicyError> {
        self.inner.get_projection_gate(card_id).await
    }

    /// Published card authorization evidence：正式严格只读端口，
    /// 必须整体精确转发 inner——绝不缓存（证据新鲜度由 manifest
    /// generation/revoke fence 决定，任何 TTL 缓存都可能放行已撤销授权）、
    /// 绝不转换、绝不把 `Ok(None)`/`Err` 替换成任何其它结果。
    async fn load_published_card_authorization(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<PublishedCardAuthorization>, PolicyError> {
        self.inner.load_published_card_authorization(scope).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::{
        DomainScopeRequirement, Effect, PolicyContext, PublishedCardAuthorizationGate,
        PublishedEvidenceGateStatus,
    };
    use policy_engine::RuleSetEntry;
    use std::sync::{Arc, Mutex};

    struct MockRepo;

    #[async_trait::async_trait]
    impl RuleRepository for MockRepo {
        async fn load_rule_set_snapshots(
            &self,
            _card_id: i64,
        ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
            Ok(vec![RuleSetSnapshot {
                rule_set_id: 1,
                ref_type: "BASE".into(),
                entries: vec![RuleSetEntry {
                    effect: Effect::Allow,
                    resource: Some("test".into()),
                    action: Some("read".into()),
                    condition: None,
                }],
            }])
        }
        async fn load_permission_rules(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(vec![])
        }
    }

    #[test]
    fn test_has_wildcard() {
        let wild = vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "BASE".into(),
            entries: vec![RuleSetEntry {
                effect: Effect::Allow,
                resource: Some("*".into()),
                action: Some("read".into()),
                condition: None,
            }],
        }];
        assert!(CachedRuleRepository::<MockRepo>::has_wildcard(&wild));

        let no_wild = vec![RuleSetSnapshot {
            rule_set_id: 1,
            ref_type: "BASE".into(),
            entries: vec![RuleSetEntry {
                effect: Effect::Allow,
                resource: Some("learn_subject".into()),
                action: Some("read".into()),
                condition: None,
            }],
        }];
        assert!(!CachedRuleRepository::<MockRepo>::has_wildcard(&no_wild));
    }

    // ===== 转发测试（不依赖外部 Redis） =====
    //
    // 通过 redis 的惰性 ConnectionManager 构造包装器：构造阶段不发起任何
    // TCP 连接。转发方法不得触碰 Redis——一旦误走缓存路径，首个 Redis
    // 命令会因地址不可达（127.0.0.1:1）而失败，测试随之失败。

    fn forwarding_wrapper<R: RuleRepository>(inner: R) -> CachedRuleRepository<R> {
        let client = redis::Client::open("redis://127.0.0.1:1/").expect("valid redis url");
        let manager = redis::aio::ConnectionManager::new_lazy_with_config(
            client,
            redis::aio::ConnectionManagerConfig::new(),
        )
        .expect("lazy manager construction must not contact redis");
        CachedRuleRepository::new(inner, manager)
    }

    /// 构造最小 Ready 证据（空集合计数一致；包装器不调用 validate，
    /// 且该形状本身也满足合同）。
    fn ready_evidence(tenant_id: i64, card_id: i64) -> PublishedCardAuthorization {
        PublishedCardAuthorization {
            tenant_id,
            card_id,
            read_unix_seconds: 1_800_000_000,
            gate: PublishedCardAuthorizationGate {
                status: PublishedEvidenceGateStatus::Ready,
                aggregate_manifest_count: 0,
                verified_record_count: 0,
                effective_grant_count: 0,
                not_in_effective_count: 0,
                equivalent_duplicate_collapsed_count: 0,
            },
            manifests: vec![],
            records: vec![],
            effective_grants: vec![],
        }
    }

    type PublishedOutcome = Result<Option<PublishedCardAuthorization>, PolicyError>;

    /// 记录到达 inner 的 scope，并按注入的闭包返回结果。
    struct ScopeRecordingRepo<F>
    where
        F: Fn(&PublishedCardEvidenceScope) -> PublishedOutcome + Send + Sync,
    {
        seen_scopes: Arc<Mutex<Vec<PublishedCardEvidenceScope>>>,
        respond: F,
    }

    #[async_trait::async_trait]
    impl<F> RuleRepository for ScopeRecordingRepo<F>
    where
        F: Fn(&PublishedCardEvidenceScope) -> PublishedOutcome + Send + Sync,
    {
        async fn load_rule_set_snapshots(
            &self,
            _card_id: i64,
        ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
            Ok(vec![])
        }
        async fn load_permission_rules(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(vec![])
        }
        async fn load_published_card_authorization(
            &self,
            scope: &PublishedCardEvidenceScope,
        ) -> PublishedOutcome {
            self.seen_scopes
                .lock()
                .expect("scope recorder")
                .push(scope.clone());
            (self.respond)(scope)
        }
    }

    fn evidence_scope() -> PublishedCardEvidenceScope {
        PublishedCardEvidenceScope {
            tenant_id: 7,
            card_id: 42,
            user_filter: Some(99),
            domain: DomainScopeRequirement::ExactlySome(3),
        }
    }

    #[tokio::test]
    async fn test_published_evidence_scope_and_ready_result_forwarded_exactly() {
        let scope = evidence_scope();
        let expected = ready_evidence(7, 42);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let wrapper = forwarding_wrapper(ScopeRecordingRepo {
            seen_scopes: Arc::clone(&seen),
            respond: |_scope: &PublishedCardEvidenceScope| -> PublishedOutcome {
                Ok(Some(ready_evidence(7, 42)))
            },
        });

        let got = wrapper
            .load_published_card_authorization(&scope)
            .await
            .unwrap();

        // Ready 证据整体一致：不缓存、不转换
        assert_eq!(got, Some(expected));
        // scope 原样到达 inner
        assert_eq!(*seen.lock().unwrap(), vec![scope.clone()]);
    }

    #[tokio::test]
    async fn test_published_evidence_unavailable_and_error_forwarded_exactly() {
        let scope = PublishedCardEvidenceScope {
            tenant_id: 7,
            card_id: 42,
            user_filter: None,
            domain: DomainScopeRequirement::Unconstrained,
        };

        // Ok(None)：legacy/test unavailable 标记必须原样转发，
        // 包装器不得把它变成空集合或任何可用证据
        let seen_none = Arc::new(Mutex::new(Vec::new()));
        let wrapper = forwarding_wrapper(ScopeRecordingRepo {
            seen_scopes: Arc::clone(&seen_none),
            respond: |_scope: &PublishedCardEvidenceScope| -> PublishedOutcome { Ok(None) },
        });
        let got = wrapper
            .load_published_card_authorization(&scope)
            .await
            .unwrap();
        assert_eq!(got, None);

        // Err：pending/corrupt/query 失败必须原样转发（fail-closed 由调用方
        // 处理），包装器不得吞掉错误或回退其它数据源
        let seen_err = Arc::new(Mutex::new(Vec::new()));
        let wrapper = forwarding_wrapper(ScopeRecordingRepo {
            seen_scopes: Arc::clone(&seen_err),
            respond: |_scope: &PublishedCardEvidenceScope| -> PublishedOutcome {
                Err(PolicyError::Repository(
                    "published_card_evidence.pending: gate unavailable".into(),
                ))
            },
        });
        let got = wrapper.load_published_card_authorization(&scope).await;
        match got {
            Err(PolicyError::Repository(msg)) => {
                assert!(
                    msg.contains("published_card_evidence.pending"),
                    "error message must be forwarded as-is: {msg}"
                );
            }
            other => panic!("published evidence error must be forwarded as-is, got {other:?}"),
        }

        // 两次调用的 scope 都原样到达 inner
        assert_eq!(*seen_none.lock().unwrap(), vec![scope.clone()]);
        assert_eq!(*seen_err.lock().unwrap(), vec![scope.clone()]);
    }

    /// 生产 inner：对全部 default read/gate 端口返回非 default 值。
    struct NonDefaultGateRepo;

    fn sample_dependency_status() -> RuleSetDependencyStatus {
        RuleSetDependencyStatus {
            rule_set_id: 5,
            ref_type: "BASE".into(),
            rule_set_active: true,
            head_ready: true,
            source_generation: 3,
            projected_generation: 3,
            revoke_fence: 1,
            snapshot_generation: Some(3),
            snapshot_row_count: 2,
            stale_snapshot_rows: 0,
        }
    }

    fn sample_rule(id: i64) -> PermissionRule {
        PermissionRule {
            id,
            effect: Effect::Allow,
            resource: "learn_subject".into(),
            action: "read".into(),
            condition: None,
        }
    }

    #[async_trait::async_trait]
    impl RuleRepository for NonDefaultGateRepo {
        fn requires_published_card_evidence(&self) -> bool {
            true
        }

        async fn load_rule_set_snapshots(
            &self,
            _card_id: i64,
        ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
            Ok(vec![])
        }
        async fn load_permission_rules(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(vec![])
        }
        async fn load_rule_set_dependency_statuses(
            &self,
            _card_id: i64,
        ) -> Result<Option<Vec<RuleSetDependencyStatus>>, PolicyError> {
            Ok(Some(vec![sample_dependency_status()]))
        }
        // 与 trait default（非 PLATFORM_USER → Ok(true)）相反，
        // 证明包装器转发的是 inner 而不是 default 放行。
        async fn check_card_active(&self, _ctx: &PolicyContext) -> Result<bool, PolicyError> {
            Ok(false)
        }
        // The trait default is deny-only. Returning a user-specific value proves
        // the wrapper preserves the inner authoritative GlobalAdmin port.
        async fn is_active_global_admin(&self, user_id: i64) -> Result<bool, PolicyError> {
            Ok(user_id == 73)
        }
        async fn load_snapshot_winners(
            &self,
            _card_id: i64,
        ) -> Result<Vec<SnapshotWinner>, PolicyError> {
            Ok(vec![SnapshotWinner {
                ref_type: "OVERLAY".into(),
                rule_set_id: 5,
                resource_key: "learn_subject".into(),
                action_code: "read".into(),
                final_effect: "ALLOW".into(),
            }])
        }
        async fn load_rule_set_entries_raw(
            &self,
            _card_id: i64,
        ) -> Result<Vec<RuleSetSnapshot>, PolicyError> {
            Ok(vec![RuleSetSnapshot {
                rule_set_id: 9,
                ref_type: "BASE".into(),
                entries: vec![],
            }])
        }
        async fn load_permission_rules_raw(
            &self,
            _card_id: i64,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(vec![sample_rule(77)])
        }
        // 用入参构造返回值，间接断言参数被原样透传给 inner
        async fn load_delegated_rules(
            &self,
            delegate_id: i64,
            resource: &str,
            action: &str,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(vec![PermissionRule {
                id: delegate_id,
                effect: Effect::Allow,
                resource: resource.to_string(),
                action: action.to_string(),
                condition: None,
            }])
        }
        async fn load_projected_delegated_rules(
            &self,
            delegate_id: i64,
            resource: &str,
            action: &str,
        ) -> Result<Vec<PermissionRule>, PolicyError> {
            Ok(vec![PermissionRule {
                id: delegate_id,
                effect: Effect::Deny,
                resource: resource.to_string(),
                action: action.to_string(),
                condition: None,
            }])
        }
        async fn get_projection_gate(
            &self,
            _card_id: i64,
        ) -> Result<Option<ProjectionGate>, PolicyError> {
            Ok(Some(ProjectionGate {
                ready: true,
                source_generation: 3,
                revoke_fence: 1,
            }))
        }
    }

    #[tokio::test]
    async fn test_defaulted_gate_and_read_methods_forward_inner() {
        let wrapper = forwarding_wrapper(NonDefaultGateRepo);

        // capability marker：生产 inner 声明 strict gate 时，包装器不得继承
        // trait 默认 false，否则正式 evaluate 会绕过 published evidence。
        assert!(wrapper.requires_published_card_evidence());

        // 依赖门禁：default 是 Ok(None)，inner 返回显式状态 → 必须转发
        let statuses = wrapper.load_rule_set_dependency_statuses(42).await.unwrap();
        assert_eq!(statuses, Some(vec![sample_dependency_status()]));

        // 卡上下文校验：default 对非 PLATFORM_USER 是 Ok(true)，
        // inner 返回 Ok(false) → 必须转发，不得用 default 放行
        let ctx = PolicyContext::builder().action("read".to_string()).build();
        assert!(!wrapper.check_card_active(&ctx).await.unwrap());
        assert!(wrapper.is_active_global_admin(73).await.unwrap());
        assert!(!wrapper.is_active_global_admin(74).await.unwrap());

        // 快照胜者：default 是空集合，inner 返回快速路径条目
        let winners = wrapper.load_snapshot_winners(42).await.unwrap();
        assert_eq!(winners.len(), 1);
        assert_eq!(winners[0].resource_key, "learn_subject");
        assert_eq!(winners[0].final_effect, "ALLOW");

        // 一致性检查 raw 读取：default 是空集合，inner 返回真实条目
        let entries_raw = wrapper.load_rule_set_entries_raw(42).await.unwrap();
        assert_eq!(entries_raw.len(), 1);
        assert_eq!(entries_raw[0].rule_set_id, 9);
        assert_eq!(entries_raw[0].ref_type, "BASE");

        let rules_raw = wrapper.load_permission_rules_raw(42).await.unwrap();
        assert_eq!(rules_raw.len(), 1);
        assert_eq!(rules_raw[0].id, 77);

        // 委派读取：入参必须原样透传给 inner（返回值由入参构造）
        let delegated = wrapper
            .load_delegated_rules(9, "learn_subject", "read")
            .await
            .unwrap();
        assert_eq!(delegated.len(), 1);
        assert_eq!(delegated[0].id, 9);
        assert_eq!(delegated[0].resource, "learn_subject");
        assert_eq!(delegated[0].action, "read");

        let projected = wrapper
            .load_projected_delegated_rules(11, "learn_doc", "download")
            .await
            .unwrap();
        assert_eq!(projected.len(), 1);
        assert_eq!(projected[0].id, 11);
        assert_eq!(projected[0].resource, "learn_doc");
        assert_eq!(projected[0].action, "download");
        assert_eq!(projected[0].effect, Effect::Deny);

        // 投影门禁：default 是 Ok(None)，inner 返回显式 gate → 必须转发
        let gate = wrapper.get_projection_gate(42).await.unwrap();
        assert_eq!(
            gate,
            Some(ProjectionGate {
                ready: true,
                source_generation: 3,
                revoke_fence: 1,
            })
        );
    }
}
