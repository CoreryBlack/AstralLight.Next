# Rust 授权投影：用 generation 与 CAS 让撤权不被旧读覆盖

> 面向：Rust 后端、数据库与分布式系统开发者
> 关键词：Rust、SQLx、Tokio、CAS、generation、授权撤权

授权系统里的并发难题，常常不是“能否找到一条匹配规则”，而是：A worker 正在编译旧状态时，撤权已经到达；新 candidate 随后发布，会不会把授权又带回来？

要回答这个问题，不能只给事件排队，也不能把“worker 收到消息”当作发布完成。AstralLight.Next 将授权变化拆成**不可变版本输入、事务外纯编译、事务内 CAS 发布，以及正式读取时的证据复核**。下面重点看这条 Rust 实现链怎样把陈旧 candidate 挡在 current pointer 之外。

## 一、把 source mutation 与投影发布分成两笔事务

source mutation 的数据库事务只负责记录授权事实：追加 grant revision 与稳定标识的 delta event。事务提交后，Tokio worker claim 事件、读取对应授权账本，在事务外执行纯编译，得到 candidate 与 impact plan。

把编译放到事务外有两个好处：不在长时间计算期间占着 source 行锁；也迫使发布阶段重新验证 candidate 的 base，而不是相信先前观察到的状态一直没变。

```text
source transaction:
  grant revision + delta event

worker, outside transaction:
  lease claim -> read ledger -> verify -> compile candidate

publish transaction:
  recheck lease + pointer + generation + revoke fence
  stage manifest/segments -> CAS current pointer -> complete event
```

delta lease 使用 run-scoped token。token 的原始值不作为数据库中的可重用凭据长期明文保存；repository 将其散列后存储，`Debug` 输出也隐藏秘密。claim 完成后，worker 从数据库读回服务端过期时间和递增后的 durable attempt counter，而不是拿客户端时间或旧行快照推算租约状态。

## 二、发布时重新证明“我还基于当前版本”

candidate 生成后，发布事务首先锁定并验证 claim lease，再锁定 `authorization_projection_current` 中的 pointer。它核对 impact plan 声明的 base generation 与刚读到的 current generation 一致，同时要求前一版 revoke fence 来自数据库当前 pointer，而不是由调用方凭历史状态重建。

事务随后 stage/finalize 目标 manifest，校验 segment 引用与 hash，并在需要时写入 parent archive intent。真正移动 current 的 SQL 使用乐观并发控制：WHERE 条件绑定刚刚读到的 generation、manifest ID、CAS version 与旧 fence；更新必须影响恰好一行。

在锁定并复核 `previous` pointer 和目标 manifest 后，repository 用 SQLx 执行带版本谓词的更新：

```rust
let cas_update = sqlx::query(POINTER_CAS_UPDATE_SQL)
    .bind(bind_u64(request.target_generation, "publish.current_generation")?)
    .bind(request.card_id)
    .bind(request.target_manifest_id)
    .bind(&target.event_id)
    .bind(&target.operation_id)
    .bind(target_semantic.as_bytes().to_vec())
    .bind(target_dependency.as_bytes().to_vec())
    .bind(&request.expected_target_compiler_version)
    .bind(bind_u64(request.fences.new_revoke_fence, "publish.cas_revoke_fence")?)
    .bind(previous.identity.tenant_id)
    .bind(&previous.identity.aggregate_type)
    .bind(previous.identity.aggregate_id)
    .bind(request.card_id)
    .bind(bind_u64(previous.current_generation, "publish.expected_current_generation")?)
    .bind(previous.manifest_id)
    .bind(previous.cas_version)
    .bind(bind_u64(previous.revoke_fence, "publish.expected_previous_revoke_fence")?)
    .execute(&mut **tx)
    .await?;

if cas_update.rows_affected() != 1 {
    return Err(AuthorizationProjectionError::CurrentPointerCasConflict(format!(
        "code=authorization_projection.pointer_cas_zero_rows;expected_manifest={};expected_generation={};expected_cas={}",
        previous.manifest_id, previous.current_generation, previous.cas_version
    )));
}
```

这里的 `WHERE` 同时 pin 住 tenant/aggregate/card scope、旧 generation、manifest、CAS version 和 revoke fence；`SET` 写入 candidate 的 generation、manifest、hash、compiler 与新 fence。生产实现还会在更新前复核 target manifest 和每个 segment。CAS 失败不会“当作已经是最新版本”吞掉，而是让整笔发布事务回滚；worker 再按失败类型决定重新规划、退避或隔离。

另一个关键顺序是：先成功移动 pointer，再将旧 manifest 标记为 `SUPERSEDED`。旧证据保留为历史记录，不靠删除旧行来伪造一致性。delta 的完成状态、impact plan 终态与 pointer 移动也处于同一事务边界，避免出现“事件显示完成，但读端拿不到对应 current”的中间提交。

## 三、Rust trait capability 把正式读取路径选清楚

PolicyEngine 不直接依赖 SQLx。它通过 `RuleRepository` port 读取授权证据；生产 `SqlxRuleRepository` 显式声明需要 published evidence，测试或 legacy repository 默认不声明该 capability。

```rust
#[async_trait::async_trait]
pub trait RuleRepository: Send + Sync {
    fn requires_published_card_evidence(&self) -> bool {
        false
    }

    async fn load_published_card_authorization(
        &self,
        _scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<PublishedCardAuthorization>, PolicyError> {
        Ok(None)
    }
}
```

正式 `evaluate()` 先完成认证、卡上下文和 resource/action 校验，再通过 repository port 读取完整的 published evidence。若严格 evidence read 不可用，它不会回退到 legacy snapshot、raw source 或未经当前发布证明的旧结果；`None`、读取错误、非 Ready gate、tenant/card 不匹配或证据校验失败，都会返回 PENDING/DENY。可选的 memory/cache repository decorator 只能提供与同一 durable published state 对牌的证据，不能在 strict read 失败时放宽结果。

找到匹配 grant 也还不够。返回 ALLOW 前，PolicyEngine 再读一次 evidence，并比较 tenant/card、gate、manifest 摘要和被命中的 grant。如果读期间 current pointer 已推进，或匹配 grant 不再存在，这次 ALLOW 被转为 `AUTHORIZATION_PENDING`。这次复读不是全局锁，不能阻止它之后发生新的变更；它提供的是 ALLOW 交付前的证据一致性检查。

## 四、为什么这不是“Exactly Once”

Tokio worker、SQL transaction 与消息系统并不构成分布式 exactly-once。内部一致性依靠稳定 event/operation ID、CAS lease、generation/fence、幂等写入和持久化状态对账。

例如数据库提交返回连接错误时，客户端可能无法判断 COMMIT 是否已在服务端生效。此时 worker 将结果视为 UNKNOWN，不盲目调用 `fail_event`、release 或重复发布。后续由 durable 状态和租约到期/reclaim 机制确定事件是否已完成；不能证明时，strict reader 继续拒绝旧证据。

## 五、实现状态也要与设计目标区分

这条 canonical Rust projection 链及 production strict gate 已有代码接线，但代码存在并不等于生产切流已验收。既有数据 backfill/rehearsal、缓存与摘要读侧迁移、真实 MySQL 集成验收和部署 postcondition 仍须分别证明。

**核心经验：** 把昂贵编译移到事务外，把短小但关键的发布校验放回事务内；以 generation、fence 和 CAS 证明 candidate 仍基于当前状态；再由 strict reader 在 ALLOW 前复核证据。这样遇到未知状态时，系统默认 PENDING/DENY，而不是猜测旧授权还有效。
