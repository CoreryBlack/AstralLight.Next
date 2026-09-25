# Pointer 对牌模式 B 设计 V1.0

> 状态：**讨论稿（未批准实施）**。本文档仅为性能优化卡点 2（pointer 对牌迁移至 Redis 提示）的详细设计计划，供架构讨论与批准评审。**批准前不做任何代码修改**；本文档不改变任何现行 fail-closed 语义。

## 1. 目标与动机

10 万 QPS 单机目标下，pointer 对牌（每次授权判定一次 MySQL 点查）达到单实例极限（~10 万点查/s）。模式 B 将对牌从 MySQL 点查迁移为 Redis 提示 GET（~0.1ms），MySQL 退出热路径（仅剩归档 + 写事务角色）——这是 10 万 QPS 的必要条件。

### 1.1 现行对牌协议（模式 A）

现行实现位于 `astral-db`：

- 指针事实源：`authorization_projection_current`（tenant_id, card_id 作用域的聚合指针行：aggregate_type / aggregate_id / manifest_id / current_generation / revoke_fence）；
- 轻读入口：`permission_query::load_pointer_fence_versions(pool, tenant_id, card_id)` —— 无锁单条 SQL，返回 `Vec<PermissionCacheManifestVersion>` 版本组（**集合形状敏感**：逐项相等才可对牌）；
- 消费方：`evidence_cache` 的 published card evidence 命中协议 ——
  **读前对牌**（允许进程级微缓存，TTL 5ms，仅合并同请求内多次 load）→ L2/L1 命中校验 → **读后复读对牌（红线：绝不走微缓存，协议层固定真读）**；
- 撤销正确性由对牌承担：REVOKE/发布推进写入指针行后，其它实例下一次读后复读对牌必然失败 → miss 回源严格 reader（撤销延迟 ≈ 0）。

### 1.2 问题

每次授权判定至少 1 次（读前）+ 1 次（读后复读）DB 指针点查；10 万 QPS 下仅对牌即 20 万点查/s，超出单 MySQL 实例点查极限。读前对牌微缓存（5ms）只能合并同请求内的重复读，无法降低每请求 2 次的底数。

## 2. 方案空间

| 方案 | 撤销传播窗口 | Redis failover 丢提示 | 复杂度 |
|---|---|---|---|
| **B-保守**：提示 miss/不确定 → 回退 DB 对牌；提示只加速"确定新鲜"读 | 混合（命中提示=毫秒级，miss=DB 点查） | 自动全量回退 DB（零窗口扩大） | 低 |
| **B-标准**：提示 + WAIT 同步副本 + TTL 5s | ≤5s（写延迟+） | TTL 封顶 | 中 |
| **B-激进**：纯提示 + TTL 30s | ≤30s | TTL 封顶 | 低 |

方案间只差两个自由度：**提示不可信时的行为**（回源 DB vs 带陈旧放行）与 **TTL 长度**（放行窗口上限）。任何方案的共同红线：提示只承担"对牌基准输入"，**不直接产生授权**；严格 reader 回源路径与读后复读对牌红线保持不变。

## 3. 推荐方案与理由

**推荐 B-标准**：提示写入（发布 commit 后 SET，`WAIT 1` 同步副本）+ TTL 5s + 撤销广播 evict。

- 撤销传播 ≤5s（显式定价，与资格 L1 化的 5s 窗口同一定价口径）；
- Redis failover 丢提示 → TTL 封顶（≤5s，不扩大）；
- 提示版本**落后**可检测（与对牌基准比较后回源）；**超前**不可信（回源）；**相等但实际已推进**（failover 丢更新）= 唯一残余窗口，由 TTL 封顶；
- 相比 B-保守：B-保守在提示 miss 时回退 DB 点查，failover 期间 DB 压力回落到模式 A 水平（10 万 QPS 峰值下 DB 直接过载，等于没有故障降级能力）；B-标准以 5s 窗口换取 failover 期间的可用性，且窗口有界、方向单一（见 §6）；
- 相比 B-激进：30s 撤销窗口不可接受（禁用卡最长 30s 放行），且 `WAIT 1` 的写入延迟代价（亚毫秒级，发生在发布侧低频路径）足以把丢提示概率压到故障切换瞬间的极小窗口。

## 4. 接口设计（trait 抽象，双实现可切换）

```rust
use astral_db::permission_query::PermissionCacheManifestVersion;
use astral_types::grant::PublishedCardEvidenceScope;

/// 对牌基准版本组的权威来源抽象（模式 B 引入；模式 A 行为即 MySql 实现）。
#[async_trait]
pub trait FenceAuthority: Send + Sync {
    /// 返回当前权威版本组。
    /// `None` = 无法确定（提示 miss/解析失败/版本不可信）——调用方必须回源
    /// DB pointer（`load_pointer_fence_versions`），不得以任何缓存回退替代。
    async fn current_fence(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Option<Vec<PermissionCacheManifestVersion>>;

    /// 实现标识（观测/审计字段，非授权输入）。
    fn authority_kind(&self) -> FenceAuthorityKind;
}

pub enum FenceAuthorityKind { MySql, RedisHint }
```

- `MySqlFenceAuthority`：现行为（每次真读 `load_pointer_fence_versions`）——**默认实现**，配置关闭/回退时使用；
- `RedisHintFenceAuthority`：
  - 读：`GET astral:pointer:fence:{tenant_id}:{card_id}`（O(1)），载荷为版本组 JSON + 写入时刻 generation 摘要；
  - 提示 miss / 解码失败 / 版本组为空 → 返回 `None`（调用方回源 DB）；
  - 写（发布侧 post-commit，事务外）：SET + TTL 5s + `WAIT 1 100ms` 同步副本；
  - 撤销/发布推进路径复用现有 post-commit side-effect 通道做**广播 evict**（同进程 L1/提示即时失效，跨实例靠 TTL 与对牌）；
- 调用方（`evidence_cache` 对牌协议）**零语义变化**：拿不到确定版本组 → 回源严格 reader 完整读；读后复读对牌仍固定真读（切换为 FenceAuthority 后即其 `current_fence`），红线保持；
- 切换方式：运行配置开关（如 `authorization.pointer_fence_authority = "mysql" | "redis_hint"`），启动期选定、静态分发；不支持运行中热切换（避免半途语义混杂）。

## 5. 命中协议（B-标准）

```
读前对牌输入：
  hint = RedisHintFenceAuthority::current_fence(scope)
  match hint:
    Some(versions) => 以 versions 为对牌基准（与 L2 条目内版本组逐项比较）
    None           => MySqlFenceAuthority::current_fence(scope)   // 回源 DB 点查
读后复读对牌：
  FenceAuthority::current_fence(scope)（同上分发；仍绝不走读前微缓存）
对牌失败/不确定：
  → 回源严格 evidence reader（锁定 + 整链校验），绝不以旧快照/缓存放行
```

## 6. 风险登记

| 风险 | 缓解 | 残余 |
|---|---|---|
| Redis failover 丢提示**写**（提示停留在旧版本组） | 发布侧 `WAIT 1` 同步副本 + TTL 5s 封顶 | **低概率放行窗口（唯一放行方向窗口）**：failover 瞬间丢更新 → 旧提示与新指针"相等比较"失配前，撤销检测丢失至 TTL（≤5s）。属业务决断项，须评审显式接受 |
| 提示版本回退（脑裂/旧副本提升） | 版本单调比较：落后 → 回源；超前 → 不可信回源 | 无 |
| Redis 不可用 | `current_fence` 返回 None → 自动回退 MySql 对牌 | 无（性能降级非安全降级） |
| 提示与 DB 指针漂移（写侧 bug） | 对牌基准逐项比较 + 读后复读兜底；监控 hint/mysql 版本组不一致率 | 低（可观测、可回退） |
| 广播 evict 丢失 | TTL 封顶 + 对牌兜底 | ≤5s |

**方向性结论**：提示的所有失效模式都只可能造成"**已撤销仍放行 ≤5s**"（放行方向）或"**未撤销被拒绝**"（fail-closed 方向）；不存在"未授权被放行"的新通道——授权内容仍由严格 reader / 已发布 evidence 承载，提示只是对牌基准的加速输入。

## 7. 与批次 H/I 的关系

- 批次 H（O(1) HotState）：不依赖本改造；HotState 解决进程内状态机开销，对牌输入来源与本改造正交；
- 批次 I（资格 L1 化 + 消费者批量合并）：独立——资格 L1（`astral-db::eligibility`）优化的是 `perm:card:active` 链路（ELIGIBILITY head 点查 + Redis 读），不动 published evidence 对牌链路；本改造不动资格链路；
- 本改造是 10 万 QPS 的最后一块（MySQL 退出热路径），建议在前两者完成并验证后实施。

## 8. 迁移与回滚

1. **阶段 1（只读影子）**：RedisHintFenceAuthority 与 MySql 并行读，仅记录不一致率，不改变生效路径；验证提示读写链路与监控指标；
2. **阶段 2（灰度生效）**：配置切换 `redis_hint`，观察撤销传播窗口指标（REVOKE → 首次 DENY 延迟分布）与不一致率；
3. **回滚**：配置切回 `mysql` 即恢复模式 A（提示写入可保留为影子，不阻断）；无需数据回滚——提示是可丢弃缓存，TTL 5s 自然清空；
4. 全程不改 DDL、不改消息协议、不改 `authorization_projection_current` 语义。

## 9. 测试计划（批准实施后执行）

- 单元：FenceAuthority 双实现分发、提示 miss/None → 回源、版本组逐项比较（落后/超前/相等）、TTL 注入；
- 集成（真实 MySQL+Redis）：发布推进 → 提示更新 → 命中；REVOKE → 提示 evict/推进 → 对牌失败 → 回源严格 reader；Redis 停机 → 自动回退 MySQL；
- 故障注入：failover 丢提示写场景验证残余窗口 ≤ TTL；影子模式不一致率指标校准。

## 10. 性能预期

| 指标 | 模式 A（MySQL 对牌） | 模式 B（Redis 提示） |
|---|---|---|
| 单请求 DB I/O | 2 次点查（读前+读后复读，~0.3ms/次） | 0 |
| 单请求 Redis I/O | 0（对牌） | 2 GET（~0.1ms/次） |
| 单机 QPS 上限 | ~10 万（MySQL 点查极限） | ~30 万+（Redis GET 上限） |
| 撤销传播 | ≈0（主库强一致 + 对牌） | ≤5s（TTL/广播封顶） |
