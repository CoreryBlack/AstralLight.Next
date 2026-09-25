//! TrustGraph 应用服务层
//!
//! 对齐 Java `PermissionRuleWriteCoordinator` / `RuleSetService` /
//! `DelegationService` 编排边界：source mutation 与 durable 投影事件/快照重建/缓存失效等
//! 副作用的编排收口在 service，handler 只做 HTTP 适配。
//! `side_effects.rs` 的内部实现（乐观锁重建、Redis evict、补偿、MQ）不动。

use astral_types::AstralError;

/// Canonical grant/source mutation 的 effect 策略：ALLOW-only。
///
/// 拒绝结果由 PolicyEngine 的 DEFAULT_DENY/PENDING 表达，不再持久化普通
/// `effect='DENY'` 权限规则；删除/撤销继续走 subtraction/revoke 生命周期事件，
/// 而不是 DENY grant。所有 canonical 写路径（规则 create/update、个人授权
/// grant、审批 approve、RuleSet entry/template create/update/replace）都必须
/// 先经过本校验；repository 层不得成为旁路。
///
/// fail-closed 契约：
/// - 去除首尾空白后按 ASCII 大写归一，只接受 `ALLOW`；
/// - 空 / 纯空白值一律拒绝，不得默认放行；
/// - 除 `ALLOW` 外的任何值（含 `DENY`、未知值）拒绝且**不做转换**
///   （绝不把 DENY grant 改写成 ALLOW grant）。
/// - 返回归一化后的 effect 字符串（恒为 `"ALLOW"`），调用方必须把返回值写入
///   source，而不是原始入参。
pub(crate) fn validate_canonical_grant_effect(effect: &str) -> Result<String, AstralError> {
    let normalized = effect.trim().to_ascii_uppercase();
    if normalized == "ALLOW" {
        Ok(normalized)
    } else {
        Err(AstralError::Validation(
            "effect must be ALLOW; canonical source mutations do not persist DENY \
             (denials are expressed by PolicyEngine DEFAULT_DENY/PENDING)"
                .into(),
        ))
    }
}

pub mod approval_service;
pub mod arbiter;
pub mod audit_replay_worker;
// 新 Rust-owned 版本化授权投影 durable worker（20260825000002/20260827000001 新表
// 队列的唯一消费者；旧 projection_worker 的 legacy outbox 职责保持不变，互不越界）。
pub mod authorization_projector;
// 归档 worker：只消费 authorization_archive_outbox 的 PENDING/过期 LEASED 意图，
// 证明被取代的旧 sealed chain 并落 durable proof + SUCCEEDED；绝不发布当前版本、
// 不做 GC、不触碰 MQ/cache 与旧快照职责。
pub mod authorization_archive_worker;
pub mod delegation_service;
// 委托到期对账 worker：只周期性调用 DelegationWriteService::
// reconcile_expired_delegations（显式有界批次、幂等收敛）；不复制 SQL、
// 不新增 source mutation，事务边界语义保持不变。
pub mod delegation_expiry_worker;
pub mod level_template_service;
pub mod org_authorities;
// ORG_SCOPE outbox 投影 worker（Phase 2 default-off）：生产可见（pub mod），
// 但启动仍由 main 以启动期冻结的共享 org_scope_enabled 旗标唯一门禁——旗标
// 关闭时不读专属 env、不 spawn、不注册关闭责任；旗标开启时由 main 按其
// "main 接线契约"（org_scope_projector 模块文档）fail-fast 解析配置后启动，
// 关闭严格逆序 cancel→bounded join。
pub mod org_scope_projector;
pub mod personal_permission_service;
pub mod projection_worker;
pub mod rule_set_write_service;
pub mod rule_write_service;
pub mod side_effect;
// 读链规模化 Batch E：授权投影「同步发布混合模式」——source 事务提交后，影响面
// ≤ 阈值的单卡/小变更经 worker 同一原语在请求内发布 delta（消除撤销传播延迟
// 窗口）；大扇出与任何失败都降级为 worker 异步消化，绝不阻塞写请求。
pub mod sync_publish;
pub mod template_service;
pub mod tenant_service;
pub mod user_card_service;

#[cfg(test)]
mod tests {
    use super::validate_canonical_grant_effect;
    use astral_types::AstralError;

    #[test]
    fn accepts_allow_and_normalizes_case_and_whitespace() {
        assert_eq!(validate_canonical_grant_effect("ALLOW").unwrap(), "ALLOW");
        assert_eq!(validate_canonical_grant_effect("allow").unwrap(), "ALLOW");
        assert_eq!(validate_canonical_grant_effect(" Allow ").unwrap(), "ALLOW");
    }

    #[test]
    fn rejects_deny_unknown_empty_without_conversion() {
        for rejected in [
            "DENY",
            "deny",
            "Deny",
            "GRANT",
            "ALLOW,DENY",
            "",
            "   ",
            "\t\n",
        ] {
            let error = validate_canonical_grant_effect(rejected)
                .expect_err("non-ALLOW effect must be rejected");
            match error {
                AstralError::Validation(message)
                    if message.contains("effect") && message.contains("ALLOW") => {}
                other => panic!("rejected={rejected:?} unexpected error={other:?}"),
            }
        }
    }
}
