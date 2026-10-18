# Rust 授权证据缓存的 freshness fence：`ReadToken` 加返回前复核

> 面向：Rust 后端、缓存与并发系统开发者
> 关键词：Rust、`RwLock`、`Mutex`、cache stamp、失效竞态、fail-closed

授权证据加缓存后，最大的坑不是 TTL 设得太长，而是这段窗口：读线程拿到旧镜像，另一个任务开始 source mutation 或安装新 projection，读线程却在检查发生之前将旧证据返回。

AstralLight.Next 的 `MemoryProjectionHub` 是一个可选的进程内镜像读面，不是 PolicyEngine 授权链之外的新入口。它将证据装配缓存分成两层：**先判断镜像是否有资格服务，再按读取版本给装配结果加 stamp。** 真正返回前，它重新计算 `ReadToken`。任何一个版本维度变化，当前请求就退回 durable 路径：先按配置尝试 strict refill，不适用时再调用 inner repository，而不是用旧 ALLOW 猜测授权仍然有效。

## 一、`ReadToken` 把隐式失效状态变成可比较版本

hub 的 token 由四个修订值组成：

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReadToken {
    health: u64,
    source: u64,
    tenant: u64,
    card: u64,
}
```

`health` 跟踪 hub 健康状态变化，`source` 跟踪 source writer/提交视图，`tenant` 和 `card` 则是对应 scope 的 epoch。`ReadToken::for_scope` 从当前 `HubMaps` 计算 token。把失效条件编码成版本后，读路径不必只依赖“某处是否发过通知”，而可以在交付结果前比较两次观察到的状态。

## 二、缓存准入早于 cache lookup

`try_memory_evidence` 先在 hub 的读锁下检查 warmup、authority fence、active source writers、uncertain source、channel health、卡片索引、pending invalidation 和镜像 TTL。任一条件不满足时，直接返回 `DeferToDurable`。

通过准入后，才会快照当前 scope 对应的 published states，计算 `ReadToken` 与 `AssemblyStamp`，再查询组装缓存。缓存 key `RefillScope` 包含 tenant、card、可选 user filter 和 domain；stamp 除 token 与读时间外，还包含排序后的 publication 信息：current pointer、manifest、generation、source/projected generation、revoke fence 和 manifest digest。

因此，不同 scope 不共享同一 evidence；即使 scope 相同，pointer 或 fence 已变化也不会复用旧条目。

## 三、返回之前重新读取 token

缓存 miss 时，hub 从已安装的不可变发布状态组装 evidence；cache hit 则复用之前组装的 `Arc<PublishedCardAuthorization>`。两条路径都会在返回前重新获取 hub 读锁并校验状态：

```rust
if token != ReadToken::for_scope(&maps, scope)
    || maps.warming_up
    || maps.authority_fence_unavailable()
    || maps.active_source_writers != 0
    || maps.uncertain_source
    || channel_blocks(&maps.channel, Instant::now())
{
    return MemoryEvidenceOutcome::DeferToDurable;
}
```

这段守卫的语义比“缓存没过期”更强：结果是在 token 未变、writer 没开始、source 状态可信、通道允许服务时才交付。若 mutation 或 invalidation 恰好发生在 assemble 与返回之间，token/health gate 会使这次内存读取退出，交给权威 DB reader 重新判断。

这不是跨数据库与内存的全局事务，也不保证结果返回后世界永不变化。它建立的是本进程内存优化路径的交付栅栏：读期间检测到变化，就不把该次证据当作当前授权继续使用。

## 四、bounded cache 与 `Mutex` 的实际取舍

当前 `AssemblyCache` 内部使用 `Mutex<Entries>`，其中用 `HashMap` 存条目、`BTreeMap` 维护 LRU 顺序。命中时会提升最近使用位置，所以这不是无锁、只读命中路径。

容量策略是明确的：最多 1,024 条、总保留字节估算上限 32 MiB、单条最多 8 MiB，cache TTL 为 1 秒。插入时周期性清理过期条目，并在条数或估算字节预算超限时淘汰最旧项；太大的 evidence 不缓存。这里的字节数是 retained-size 估算，不是进程 RSS 的精确计量。

需要区分两种时间边界：装配缓存条目 TTL 为 1 秒；内存镜像自身另有 `MIRROR_TTL`。即使两者未过期，pending/source-writer/token gate 仍能阻止不安全的内存读取。TTL 是附加约束，不是授权新鲜度的唯一证明。

## 五、失败方向必须是回源，而不是放宽

cache mutex poison、条目超限或 stamp 不匹配会让装配缓存退化为 miss；若已安装的不可变 published states 仍通过 hub 准入检查，读路径可以重新组装 evidence。若镜像状态不适合服务或组装失败，则内存装饰器交回 durable 路径：尝试已配置的 strict refill，或调用 inner repository。镜像刷新失败时 pending 保留，读者继续走权威数据库路径。任何失败都不应制造一份“空但 Ready”的 evidence。

**核心经验：** 对授权证据缓存，TTL 是容量与新鲜度的辅助界限；真正的安全边界是 scope、publication stamp、pending gate 与返回前 token 复核。命中缓存只减少重复组装，不新增授权事实，也不应改变 fail-closed 的读取语义。
