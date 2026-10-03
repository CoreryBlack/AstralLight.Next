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
// 跨城授权 coordinator（P4 runtime slice，DEFAULT-OFF）：库服务（无 HTTP 路由、
// 无自启动 worker），把「纯验签 → durable replay reservation + verified vote
// 同事务、证据推导 agreement seal、持久 commit receipt、双城 durable completion
// 才 mint activation、gate 激活、unknown 只 IN_DOUBT、transport typed trait
// 注入 + durable outbox 先行」接成一条 fail-closed 流水线。启用必须显式
// try_enable（配置缺失拒绝）；main 负责唯一接线（node key snapshot 固定
// provider、MQ transport 适配器、audit sink），本模块不提供 HTTP 入口。
pub mod cross_city_coordinator;
// 跨城 runtime 装配（P4 default-off 的唯一运行入口）：start_cross_city_runtime
// 由外层 runtime 调用一次并 RAII 持有关停。default-off（ASTRAL_CROSS_CITY_ENABLED
// 缺省/false）零 I/O；启用即 fail-closed 启动许可（node key/authority scope
// 注册表缺失拒绝启动），真实 lapin 传输（publisher confirm）+ durable
// outbox/inbox 先于 ACK，预算有界；不伪造远端 source apply——COMMIT_CONFIRMED
// 必须是精确 authoritative city 的签名回执，broker confirm 只是传输语义、
// 绝不充当 activation proof。本模块不提供 HTTP 入口、不触碰 AppState；
// 启动/关停生命周期由外层 runtime 唯一持有。
pub mod cross_city_runtime_wiring;
pub mod delegation_service;
// 委托到期对账 worker：只周期性调用 DelegationWriteService::
// reconcile_expired_delegations（显式有界批次、幂等收敛）；不复制 SQL、
// 不新增 source mutation，事务边界语义保持不变。
pub mod delegation_expiry_worker;
// 失效 fanout / MQ bootstrap runtime 接线（P3/P4 per-node Rabbit，default-off）：
// 有界 MQ bootstrap、RAII 任务句柄、hub suspect/reconcile supervisor、
// listener/apply 适配；启动由 runtime.rs 以 ASTRAL_INVALIDATION_FANOUT_ENABLED
// 唯一门禁（严格 bool），关闭按启动逆序有界 join / RAII Drop abort。
// IN_DOUBT 失效恢复运维闭环（只读 inspect；requeue/quarantine 策略门零 I/O
// 显式拒绝；唯一 DB 访问面是 LocalMessageRepository::load_in_doubt）。配套
// 运维 CLI 见 src/bin/invalidation_recovery.rs；不触碰 MQ/DB/Identity 共享文件。
pub mod invalidation_recovery;
pub mod invalidation_runtime;
pub mod level_template_service;
// 单机组合路径的进程内投影 worker（由组合安装门禁）：消费
// astral_db::LocalProjectionBus 的 commit-proven delta（source 事务提交后
// dispatch），按稳定事件身份单事务 CAS claim + 同事务 payload binding，
// 复用既有 pure decide 管线发布；scope plan mirror 仅承载 durable 证明的
// planning hint，缺证明一律回落 DB strict 读。启动由
// start_authorization_projector 在 bus+hub 已安装时唯一选择本路径。
pub mod local_projection_worker;
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
