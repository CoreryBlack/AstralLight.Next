# Rust 授权增量编译：用 `im::HashMap` 与 `Arc` 只重建受影响 segment

> 面向：Rust 性能工程、编译器与不可变数据结构开发者
> 关键词：Rust、HAMT、persistent data structure、copy-on-write、incremental compilation

一份授权账本有几十万条 grant，每次 mutation 却只改变一个 resource/action key。如果每次都克隆全量 map、重建所有 segment，再给每个结果重新计算摘要，单条变更也会退化成全量成本。

AstralLight.Next 的 `AuthorizationCompiler` 将问题拆成两个层次：**账本如何共享结构，segment 如何限定重建范围。** `HotState` 用 `im::HashMap` 保存持久化 map，segment 内容再通过 `Arc` 共享；每个增量请求必须带着明确的版本、semantic hash 和 dependency vector。优化的是 candidate 构造，不是跳过版本验证。

## 一、把增量编译建模为纯函数

编译入口接收 immutable base 和 `CompileRequest`，返回三态结果：

```rust
pub enum CompileOutcome {
    Applied(CompiledProjection),
    FullRebuildRequired(FullRebuildRequired),
    Conflict(CompilerConflict),
}
```

`CompileRequest` 携带调用方读取的 `base_version`、`base_semantic_hash`、目标版本、依赖向量、可选 expected dependency hash 和稳定 ID 的 delta 列表。编译器不做 I/O、不写数据库、不移动 current pointer；candidate 只有后续 durable publish transaction 提交后才算已发布。

```rust
if let Some(conflict) = request_base_conflict(base, request) {
    return Ok(CompileOutcome::Conflict(conflict));
}

if base.compiler_version != self.compiler_version {
    let known_keys = known_affected_keys(base, &request.deltas)?;
    return Ok(full_rebuild_outcome(
        base,
        &request.deltas,
        known_keys,
        FullRebuildReason::CompilerVersionMismatch,
    ));
}
```

这里的关键不是具体 if，而是结果类型表达的协议：base 不匹配属于 conflict；编译器版本、依赖或影响范围使局部更新不安全，就显式返回 `FullRebuildRequired`。编译器不把“无法增量处理”伪装成 Applied。

## 二、用持久化 map 共享版本，而不是复制整个状态

`HotState` 的核心字段可以概括为：

```rust
pub struct HotState {
    pub tenant: TenantScope,
    pub version: u64,
    pub shared_entries: im::HashMap<String, Arc<SharedRuleSetEntry>>,
    pub bindings: im::HashMap<i64, BindingCounts>,
    pub ruleset_records: im::HashMap<GrantId, RuleSetGrantRecord>,
    pub private_grants: im::HashMap<GrantId, CanonicalGrant>,
    pub segments: im::HashMap<ProjectionKey, Arc<SegmentContent>>,
    pub semantic_hash: String,
    pub dependency_hash: String,
    pub compiler_version: String,
    dependency_vector: DependencyVector,
}
```

这是当前 `HotState` 的字段布局；相关领域类型在编译器模块内定义。`im::HashMap` 是持久化 HAMT：clone 复用树结构，修改时复制受影响的路径，而不是对所有键深拷贝。`Arc<SegmentContent>` 则让新版本可以继续引用未变化的 segment；受影响 key 才生成新 segment。

RULE_SET grant 还采用 factored ledger：共享层存放与卡归属无关、按内容 hash 去重的条目；绑定层记录卡与规则集的关联；记录层保留逐 grant revision/state/CAS 生命周期；DIRECT、APPROVAL、DELEGATION 等卡私有来源保留在独立层。不能只保留“卡绑定规则集”这一层，因为冻结的 delta 契约以 `GrantId` 为粒度，同一卡中不同 entry 的撤销和 revision 必须独立表达。

## 三、按 affected key 重建 segment

增量候选构造先 clone 持久化 segment map，再仅遍历 `affected_keys`。对每个受影响 key，算法从 base segment 取现存 Active grant，过滤掉本批被 Update/Remove/Revoke 的 ID，再加上本批新落到这个 key 的 Active grant，最后只重建该 segment：

```rust
let mut segments: im::HashMap<ProjectionKey, Arc<SegmentContent>> =
    base.segments.clone();

for key in affected_keys {
    let mut contributions: Vec<CanonicalGrant> = match base.segments.get(key) {
        Some(segment) => segment
            .grants
            .iter()
            .filter(|grant| !removed_ids.contains(&grant.grant_id))
            .cloned()
            .collect(),
        None => Vec::new(),
    };
    if let Some(added) = added_by_key.get(key) {
        contributions.extend(added.iter().cloned());
    }
    if contributions.is_empty() {
        segments.remove(key);
        continue;
    }
    let segment = build_single_segment(key, contributions, &compiler_version)?;
    segments.insert(key.clone(), segment);
}
```

这是生产 candidate 构造逻辑的摘录，省略了前面的 delta 分组代码。实现还要保证失效态不进入 Active segment、同一 GrantId 的 revision/state 转换符合账本规则、affected set 覆盖旧 key 与新 key，并以确定顺序构造 segment 内容。HAMT 内部迭代顺序不稳定，所以对发布摘要有影响的遍历会显式排序。

## 四、用结构断言证明复用，而不是迷信 allocator 数字

单条 Add 的测试检查受影响 key/segment 恰好一个、candidate version 正确、grant 基数只增加一、base 未变，以及未受影响 segment 满足 `Arc::ptr_eq`。核心断言如下：

```rust
let untouched_in_base = base
    .segment_content(&untouched_key)
    .expect("untouched key must exist in base");
let untouched_in_candidate = candidate
    .state
    .segment_content(&untouched_key)
    .expect("untouched key must survive the Add");
assert!(
    Arc::ptr_eq(&untouched_in_base, &untouched_in_candidate),
    "untouched segment must be physically reused"
);
```

这里能直接证明“没有为未变化内容构造新 `Arc`”，不依赖 allocator 的全局计数器。

分配次数/字节数可以用于观察与基准分析，但它们会受到进程预热、allocator 复用和并行测试影响，不宜作为跨运行稳定门槛。测试中 4050 个 grant 对应 81 条共享 RULE_SET 内容，也是一个特定 fixture 的结构证据，不是通用内存收益或吞吐承诺。

## 五、纯编译内核返回 FullRebuildRequired，orchestrator 决定怎么做

依赖向量变化、compiler version 不兼容、wildcard 影响或 delta 超阈值时，局部 affected set 可能不足以证明正确性。`AuthorizationCompiler` 只返回 `FullRebuildRequired { reason, plan }`，不在纯编译函数内部偷偷重建。

当前 projector 收到这一变体后，会显式调用 `full_rebuild`，并将 `full_rebuild_reason` 放进候选汇总；若全量重建仍不能产生 candidate，则将该路径作为失败处理。把这两个层次分开很重要：compiler 负责纯决策与 outcome，orchestrator 负责是否执行 full rebuild 和记录原因。

这次 factored 优化只针对内存 HotState 和 candidate 的构造。durable segment、每卡 manifest/current pointer、CAS generation 与授权语义保持既有契约；它不是数据库表跨卡共享改造。

**核心经验：** 增量性能来自结构共享与精确 affected set；正确性来自版本前置条件、显式 fallback outcome、确定性序列化与结构测试。Rust 的持久化集合只有嵌入这些语义边界时，才是可靠的优化，而不只是换一个容器。
