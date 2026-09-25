# FactoredHotState 设计（授权编译内核共享层改造）V1.0

> 状态：已实施（配套代码：`policy-engine/src/authorization_compiler.rs`）
> 日期：2026-08-28
> 关联：[`Rust权限投影快照与版本栅栏_V1.0.md`](./Rust权限投影快照与版本栅栏_V1.0.md)、[`Rust增量重建与实时授权边界_V1.0.md`](./Rust增量重建与实时授权边界_V1.0.md)、[`BACKEND_STANDARD.md`](../../规范/Rust后端编码规范_V1.0.md)
>
> 本文是 HotState factored 共享层改造的设计事实源：类型定义、转换规则、匹配/评估语义、
> 语义等价性论证与安全论证。工程门禁仍以仓库 AGENTS.md 为准；本文不复制规范正文。

---

## 1. 背景与目标

授权编译内核（Phase 2 hot-state compiler）的 HotState 此前以
`im::HashMap<GrantId, CanonicalGrant>` 逐 grant 存储全部 ledger 记录。每条
`CanonicalGrant` 携带完整的 resource/action/effect/validity 与
card_id/user_id/binding 归属。当 N 张卡共享同一 RuleSet（E 条 entry）时，ledger 中存在
`N × E` 条独立 grant 记录，其中内容字段（resource/action/effect/validity/source_id/
source_entry）完全相同、仅归属字段不同——内存冗余随卡数线性增长，且不存在任何
跨卡的共享结构。

DB 源数据层本来就是 factored 的（`rule_set`/`rule_set_entry` 共享 +
`card_rule_set_ref` 绑定），冗余只产生在编译产物层。

**目标**：把 HotState 的 ledger 内部表示重构为 factored 三层（共享层 + 绑定层 +
卡私有层），在保持以下不变式的前提下消除共享内容冗余：

1. 编译输入输出不变（`GrantLedgerEntry` / `GrantDelta` 逐字节不变）；
2. 段（segment）表示与 durable 发布契约不变（逐 key 段载荷、内容寻址行、
   per-card manifest/pointer、CAS generation）；
3. 增量编译仍为 O(affected)，全量 oracle parity 语义不变；
4. semantic hash（v4 版本绑定语义）不变——`COMPILER_VERSION` 不升版
   （见 §8.3）；
5. ALLOW-only、fail-closed、墓碑保留等授权语义不变。

**非目标（本期不做，见 §9 路线图）**：durable 段行的跨卡共享（card-less 载荷）、
`PublishedCardAuthorization` 组合视图化、rule-set 级 delta 契约。

---

## 2. Phase 1 共享性验证（前提成立性证据）

改造前提：**同 `rule_set_id` 的多个卡归属的 grant，其 resource/action/effect/validity
相同（仅归属字段不同）**。该前提由 RULE_SET 物化代码路径静态证明：

1. **内容只来自 entry 行**。`build_ruleset_add_draft`（`astral-db/src/grant_ledger.rs`）
   组装 RULE_SET grant 时：
   - `resource = canonical_resource_key(facts.resource, facts.resource_id)`，
     `action = facts.action`、`validity = parse_validity_window(facts.valid_from,
     facts.valid_to)` 全部来自 `ruleset_entry_facts()` 的 entry 侧字段
     （`canonical_entry_grant_fields(entry)`，来自共享的 `rule_set_entry` 行）；
   - `effect` 硬编码 `GrantEffect::Allow`（ALLOW-only 纵深防御，UPDATE 同样钉死）。
2. **归属只来自绑定行**。`facts` 的 card_id/user_id/ref_id/ref_type/tenant/domain
   来自 `ProvableBoundCard`（`card_rule_set_ref` × `user_card` 行），按卡独立。
3. **fanout 同源**。`append_ruleset_entry_{add,update,remove}_fanout_in_tx`
   （`astral-trustgraph/src/repository/rule_set_repository.rs`）对"每个绑定卡 × 每个
   entry"循环物化，同一 mutation 内所有卡对同一 entry 使用同一 entry 侧 facts，
   且在同一 source 事务内完成；`build_ruleset_update_draft` 的内容字段同样全部取自
   entry facts 而非 head。因此收敛态下跨卡内容逐字段相同。
4. **身份不含内容**。`resolve_ruleset_identity` 的注释与实现明确：grant 身份 =
   (tenant, layer, rule_set_id, entry_id, binding_key=卡×绑定行×层标)，
   "资源/action/priority/validity 不进入身份"——内容变更复用同一 grant，跨卡内容
   一致性不依赖身份机制。

**结论：前提成立，改造可以实施。**

**运行时守护（fail-safe 而非 fail-stop）**：编译器共享层采用**内容寻址**键
（§3.1），不把前提作为运行时假设——若收敛前提被暂时打破（例如 entry 更新 fanout 的
跨卡事件处于中间态），共享自动退化为"少共享/不共享"，每张卡的段内容始终只由该卡
自身的 ledger 事实组装，绝不出现跨卡内容污染，也不产生编译错误。前提成立时
内容寻址在收敛态下与"按 (rule_set_id, entry_id) 去重"严格等价（定理见 §5.2）。

---

## 3. 三层结构定义

### 3.1 共享层（shared layer）——RULE_SET 条目授权内容，只存一份

```rust
/// RULE_SET 条目授权的内容事实，不含任何卡/绑定归属。
pub struct SharedRuleSetEntry {
    /// 内容身份 = sha256(canonical content JSON)，同时是共享层 map 的键。
    pub content_hash: String,
    /// rule_set_id（ledger provenance.source_id）。
    pub source_id: String,
    /// entry_id（ledger provenance.source_entry）。
    pub source_entry: Option<String>,
    pub resource: String,
    pub action: String,
    pub effect: GrantEffect,
    pub validity: ValidityWindow,
    /// 该内容首次进入共享层时的 hot-state version（可观测性字段）。
    pub first_seen_version: u64,
}

// HotState 内：
pub shared_entries: im::HashMap<String /*content_hash*/, Arc<SharedRuleSetEntry>>,
```

- **粒度取 entry 级而非 rule_set 级**：ledger 的变更单元是 entry
  （`append_ruleset_entry_*_fanout_in_tx` 支持 entry 子集更新），rule_set 级分组会
  迫使单 entry 更新复制整组。entry 级是内容去重的最小正确单元；任务书
  `SharedRuleSetContent{entries: Vec, version, content_hash}` 的"版本 + 内容 hash"
  语义由每条目的 `first_seen_version` + `content_hash` 承载。
- **键取内容 hash 而非 (source_id, source_entry)**：见 §2 运行时守护与 §5.2 等价
  定理。hash 冲突防御：命中后逐字段比对实际内容，不一致即视为不同内容分别入库
  （sha256 下实际不可达，属纵深防御）。
- **陈旧条目残留**：派生状态中不再被任何记录引用的共享条目会残留在该状态的共享层
  map 中（im 持久化结构下按快照隔离，不影响旧快照），由下一次全量重建（ledger
  重放，`hot_state_from_entries` 路径）剪枝；生产路径每次发布都从 ledger 重建，
  残留不跨发布累积。

### 3.2 绑定层（binding layer）——每卡的规则集绑定关系

```rust
// HotState 内：
/// card_id → (rule_set source_id → 引用计数)。派生自 ledger 事实
/// （RULE_SET 记录的 provenance.source_id），含墓碑（墓碑保留在 ledger，
/// 绑定事实随之保留）。引用计数覆盖"同卡多绑定/多 entry 指向同一规则集"。
pub bindings: im::HashMap<i64 /*card_id*/, im::OrdMap<String /*source_id*/, u64>>,
```

- 任务书形状 `im::HashMap<CardId, im::OrdSet<RuleSetId>>` 的引用计数等价结构：
  同一卡的多条 entry grant / BASE+OVERLAY 双绑定都指向同一 source_id，集合语义需要
  计数才能正确增删。
- BASE/OVERLAY 层标不进入绑定键：层标是 grant/绑定行属性，保留在记录层
  （`binding_layer` 字段）；绑定层的消费面（"该规则集影响哪些卡"）不需要层粒度。
- 增量维护：记录插入时 `+1`；Update 迁移 source_id 时旧 `-1`/新 `+1`；墓碑不变。
- **冻结契约下的消费面**：编译受影响面计算不消费绑定层（§5.1）；它是
  "rule-set 级 delta 的受影响面 = 绑定该规则集的卡"这一未来路径的结构基础
  （§9），本期以不变式测试与查询 API（`card_rule_set_sources`）提供价值。

### 3.3 记录层（RULE_SET grant 生命周期面）——绑定层必需的 per-grant 明细

冻结的 `GrantDelta` 契约按 **GrantId** 个体操作且携带独立 revision/state/CAS 语义
（同一卡的 entry-1 可被 REVOKE 而 entry-2 保持 Active；同一 entry 的跨卡 grant 各有
独立 revision 链）。"card → rule set 集合"的绑定层无法表达 per-entry/per-grant 的
revision 与墓碑，因此事实化 ledger 必须保留一个 per-grant 记录层：

```rust
/// RULE_SET 来源 grant 的卡归属记录：身份/生命周期 + 指向共享层的引用。
pub struct RuleSetGrantRecord {
    pub revision: GrantRevision,
    pub state: GrantState,
    pub binding_layer: BindingLayer,
    pub card_id: i64,
    pub user_id: i64,
    /// provenance.binding_id（合同强制 RULE_SET 携带，构造期 None 即 fail-closed）。
    pub binding_id: String,
    pub operation_id: String,
    pub event_id: Option<String>,
    pub actor_user_id: Option<i64>,
    /// → 共享层条目（内容事实）。
    pub entry: Arc<SharedRuleSetEntry>,
}

// HotState 内：
pub ruleset_records: im::HashMap<GrantId, RuleSetGrantRecord>,
```

- 记录不含 tenant/domain：`from_grants` 已验证 `grant.tenant == HotState.tenant`，
  组装时取 HotState 租户（与现行实现同构——现行 HotState 也把 tenant 提升到状态级）。
- 记录不含 resource/action/effect/validity/source_id/source_entry：经
  `entry: Arc<SharedRuleSetEntry>` 引用共享层。

### 3.4 卡私有层（card-private layer）——非规则集来源 grant

```rust
// HotState 内：
/// DIRECT / APPROVAL / DELEGATION / SYSTEM 来源 grant（本就按卡私有，无跨卡共享面）。
pub private_grants: im::HashMap<GrantId, CanonicalGrant>,
```

私有层 grant 保持完整 `CanonicalGrant`（含归属），CAS/墓碑逻辑与改造前逐字节一致。

### 3.5 HotState 汇总

```rust
pub struct HotState {
    pub tenant: TenantScope,
    pub version: u64,
    // ── factored ledger（上述三层 + 记录层）──
    pub shared_entries: im::HashMap<String, Arc<SharedRuleSetEntry>>,
    pub bindings: im::HashMap<i64, im::OrdMap<String, u64>>,
    pub ruleset_records: im::HashMap<GrantId, RuleSetGrantRecord>,
    pub private_grants: im::HashMap<GrantId, CanonicalGrant>,
    // ── 不变 ──
    pub segments: im::HashMap<ProjectionKey, Arc<SegmentContent>>,
    pub semantic_hash: String,
    pub dependency_hash: String,
    pub compiler_version: String,
    dependency_vector: DependencyVector,
}
```

全部 ledger 字段保持 `im` 持久化结构：`clone` 仍为 O(1) 结构共享，单键查/增/删仍为
O(1) 平均（HAMT）或 O(log n)（OrdMap 绑定计数），COW 语义不变。
`grants: im::HashMap<GrantId, CanonicalGrant>` 字段移除，由
`private_grants` + `ruleset_records` 替代；导出 API（`grant`/`all_grants`/
`active_grants`）改为按需组装的 owned 语义（§4.3）。

---

## 4. 转换规则

### 4.1 构造（`HotState::from_grants_with_compiler`）

输入 `impl IntoIterator<Item = CanonicalGrant>` 不变。逐条：

1. `canonicalized()` 合同校验（不变）；租户一致性校验（不变）。
2. 路由：`source_kind == RuleSet` → 记录层 + 共享层 intern + 绑定层计数；
   其余 → 私有层。`GrantId` 在两层间全局唯一，跨层重复 = `DuplicateGrant`。
3. 共享层 intern：对 grant 的内容七元组
   `(source_id, source_entry, resource, action, effect, validity)` 计算
   `content_hash = sha256(canonical JSON)`；命中 → 复用既有 `Arc`（逐字段比对防
   碰撞）；未命中 → 新建条目（`first_seen_version = 构造 version`）。
4. 记录层构造：RULE_SET grant 的 `provenance.binding_id` 为 `None` 时
   `CompilerError::InvalidState`（fail-closed；合同校验本应拒绝，此为纵深第二层）。

### 4.2 增量 delta 应用（`apply_deltas_to_ledger`）

`GrantDelta` 四形态的 CAS/墓碑/复活判定与改造前**逐分支一致**，仅存储面改变：

| delta | 定位既有记录 | 应用 |
|-------|-------------|------|
| `Add{grant}` | 双层查找 `grant_id` | Active→`ExistingGrant`；Inactive→严格 next-revision 才可复活；按载荷 `source_kind` 落层（跨层复活=移除旧层残留） |
| `Update{grant, expected_revision}` | 双层查找 | CAS 等值、Active、next-revision 三道判定后替换；载荷 kind 决定目标层（kind 漂移已被 `BindingImpact` 在增量路径拦截，全量 oracle 路径允许跨层替换） |
| `Remove/Revoke{grant_id, expected_revision}` | 双层查找 | 墓碑 = 既有记录仅推进 revision/state，**内容与层不变**；同墓碑同 revision → `DuplicateDelta` |

绑定层维护：记录被替换/新增时按 (card_id, source_id) 增量计数；墓碑不改变计数；
Update 改变 source_id 时旧减新增。

### 4.3 导出与视图（组装规则）

- `grant(grant_id) -> Option<CanonicalGrant>`：私有层直返；记录层按
  `to_grant(&HotState.tenant, grant_id)` 组装。签名从引用改为 owned（组装产物
  无处安放引用）。
- `all_grants() -> Vec<CanonicalGrant>` / `active_grants() -> Vec<CanonicalGrant>`：
  两层合并后按 `GrantId` 排序（保持确定序契约）。
- 组装的逐字段来源见 §3.3 结构定义；对同一输入 grant，组装产物与原 grant
  **逐字节相等**（由 parity 测试锚定）。
- 记录层 → `ProjectionKey`：`ProjectionKey::new(card_id, user_id,
  entry.resource, entry.action)`，无需组装完整 grant。

### 4.4 段构建

- 全量（`build_segments`）：遍历私有层 Active grant + 记录层 Active 记录
  （记录按需组装），按 `ProjectionKey` 分组（BTreeMap 确定序），段内贡献仍由
  `build_single_segment` 按 `(grant_id, revision, source_id)` 排序——段内容与
  改造前逐字节一致。
- 增量（`materialize_incremental_candidate`）：逻辑不变——未受影响 key 继承 base
  段 `Arc`，affected key 段由"base 段贡献 − 本批移除 + 本批 Active 新增"重建。
  该路径只消费 base 段（具体 `CanonicalGrant`）与 delta 载荷（具体
  `CanonicalGrant`），**从不**触碰 factored ledger 的组装，因此增量路径不引入
  组装开销。

---

## 5. 匹配/评估语义与等价性论证

### 5.1 评估 = 运行时组合（不变）

授权匹配从不直接消费 HotState 内部 ledger：

- **读路径**：`PolicyEngine.evaluate()` 消费 `PublishedCardAuthorization`
  （strict DB reader 从 durable 段行组装的 per-card 证据），
  `match_published_effective_grant` 按 card/user/tenant/validity/resource/action
  匹配——与 HotState 表示无关，本期零改动。
- **投影路径**：projector 从 factored HotState 消费的只有
  `segments`/`segment_content`/`segment_references`/impact plan——段仍是逐 key
  的 card-owned 具体贡献集（§6），发布事务、pointer CAS、manifest digest 全部不变。
- **受影响面**：冻结契约的 delta 按 GrantId 个体携带新旧内容，受影响 key 恒等于
  "本批 delta 的新旧 key 集合"。共享层内容变更不会隐式影响其他卡——其他卡的记录
  引用的是各自的共享条目（内容寻址），其内容只随**其自身**的 delta 变化。
  因此"共享层变更 → affected = 绑定该 rule_set 的卡"在冻结 per-grant 契约下是
  空集语义（跨卡传播不存在），绑定层的该消费面留给 rule-set 级 delta 契约（§9）。

### 5.2 语义等价性定理

**定理（去重等价）**：设 ledger 收敛（同一 (rule_set_id, entry_id) 的全部跨卡
grant 内容一致，§2 前提）。则内容寻址共享层对同 (source_id, source_entry) 的全部
grant 恰好落入同一 `content_hash` 桶，共享条目数 = 不同 (source_id, source_entry)
数——与"按 (rule_set_id, entry_id) 键控"的共享层产生完全相同的共享条目集。

*证明*：内容七元组由 (source_id, source_entry) 函数性决定（前提）+ canonical JSON
序列化与 sha256 的确定性 ⇒ 同 (source_id, source_entry) ⇒ 同 content_hash；反之
不同 (source_id, source_entry) 至少 source 字段不同 ⇒ hash 不同。∎

**定理（评估等价）**：对任意 ledger 状态 L（收敛或不收敛），factored HotState 与
per-card HotState 产生相同的段集合、相同的 semantic/dependency hash、相同的
导出 grant 集合与相同的增量/冲突判定。

*证明要点*（由构造与测试双锚定）：
1. 段：`build_segments` 的输入语义 = "Active ALLOW 贡献按 ProjectionKey 分组"。
   factored 路径组装出的贡献与 per-card 路径存储的 grant 逐字段相等（每字段来源
   固定且唯一，组装是纯函数）⇒ 段逐字节相等。
2. 导出：组装函数覆盖 `CanonicalGrant` 全部字段且 tenant 来自已验证的状态租户
   ⇒ `all_grants`/`active_grants`/`grant` 与 per-card 形态相等。
3. CAS/冲突：`apply_deltas` 的判定只读取 (revision, state, source_kind,
   binding_layer, resource, action)——记录层完整保留这些字段（resource/action 经
   共享条目引用）⇒ 判定结果逐分支一致。
4. hash：semantic hash 为 v4 版本绑定语义（O(1) 字段），dependency hash 不变，
   段 content hash 输入为段贡献集（相等）⇒ 全部 hash 相等。
5. 不收敛态（前提暂时打破）：内容寻址使每张卡引用各自的共享条目，段仍由各卡自身
   事实组装 ⇒ 评估等价性不依赖收敛前提（这正是选择内容寻址的原因）。∎

---

## 6. 段（segment）与 durable 契约的边界

**本期段表示不变**：`segments: im::HashMap<ProjectionKey, Arc<SegmentContent>>`，
段载荷仍是逐 key 的 card-owned `Vec<CanonicalGrant>`。理由（约束优先级）：

1. durable 发布契约不变是任务硬约束：段行按内容寻址去重的前提是载荷含卡归属
   （读侧 `PublishedCardAuthorization.records[].grant` 必须携带完整归属，astral-types
   合同不可改动）；card-less 共享段行需要重写发布/读取/校验全链与证据合同。
2. 冻结消费方（astral-trustgraph projector）以
   `candidate.segments.iter()` / `segment_content()` 消费段结构。
3. 现网投影按 (card, aggregate) 作用域构建 HotState，段规模 = 单卡 key 数，
   不构成共享规则集场景下的主要成本；成本集中在 ledger（任务书 §背景 的 600MB
   估算即 grant 记录面）。

因此本期消除的冗余是 **ledger 内容冗余**（每条 RULE_SET grant 的
resource/action/effect/validity/source 字符串与窗口字段）；段面冗余的消除是
§9 路线图的第一项。内存收益量级：每条 RULE_SET grant 的独占字节从
"内容字段（约 55%–70%）+ 归属字段"降为"归属字段 + 一个 Arc"，收敛态
N 卡 × E 条目场景下 ledger 内存约为改造前的 30%–50%（内容字段越长收益越高）。

---

## 7. 安全论证（变更五链）

| 链 | 结论 |
|----|------|
| 调用链 | 导出 API 签名由引用改 owned（`grant`/`all_grants`/`active_grants`）；全部仓内调用方已核对（编译器测试、`grant_repository` 测试、trustgraph projector/bench 均兼容 owned 语义或只消费 `segments`/hash）。段/引用/计划 API 签名不变。 |
| 逻辑链 | 授权判定路径（`PolicyEngine`/`match_published_effective_grant`）不消费 HotState 内部表示，零变化；CAS/墓碑/复活判定逐分支保持；跨层 kind 漂移在增量路径由 `BindingImpact` 拦截、在全量 oracle 路径以"旧层移除 + 新层插入"显式迁移，不产生双活记录。**租户 fail-closed 收紧**：旧实现在 delta 路径未校验载荷租户与 base 租户一致（fail-open 潜伏缺陷，生产上游由 ledger head 对齐保证不可达）；factored 记录层不存 tenant，delta 边界显式校验并返回既有声明的 `TenantMismatch` 冲突，与 `from_grants` 拒绝语义对齐（现网行为不变，不可达路径由 fail-open 转 fail-closed，测试锚定）。 |
| 事故链 | 共享层是纯内存去重，无外部依赖；任何共享结构损坏等价于该次编译失败（编译器纯函数，无 durable 副作用）；`Arc` 生命周期由持久化结构托管，不存在引用计数错误面。前提打破时自动退化共享（§2），不降级授权语义。 |
| 数据链 | 编译输入输出（`GrantLedgerEntry`/`GrantDelta`）、段载荷、manifest/pointer、hash 语义全部不变；factored ledger 只存在于编译器内存中间态，可由 ledger 全量重建（`hot_state_from_entries` 路径即恢复路径）。 |
| 审计链 | N/A——纯内存表示重构，不新增/减少任何审计事件；provenance 字段在记录层完整保留并参与组装。 |

失败默认不扩大权限：组装/构造中的任何合同违规（如 RULE_SET 缺 binding_id）在
构造期 fail-closed（`CompilerError`），不产生部分授权。

---

## 8. 验证策略

1. **共享性/dedup 测试**：N 卡 × E 条目（同 source_id/source_entry、不同归属）→
   `shared_entries.len() == E`、`ruleset_records.len() == N×E`、绑定计数正确；
   每卡段只含本卡归属（无跨卡泄漏）；导出 grant 与构造输入逐字节相等。
2. **退化容忍测试**：同 (source_id, source_entry) 不同 validity 的两卡 →
   共享层两条目、各自段携带各自内容、无编译错误、无跨卡污染。
3. **等价性 parity 测试**：factored 多卡状态 vs 逐卡单卡参考模型——
   段内容、导出 grant、增量/全量候选 equality。
4. **绑定层不变式测试**：绑定层 ≡ 记录层分组派生；Update 迁移 source_id 计数
   正确移动；墓碑保留绑定事实；多卡增量只重建本卡段（其他卡段 Arc 继承）；
   卡私有层（DIRECT）CAS/墓碑回归；跨租户 delta 显式 `TenantMismatch`。
5. **既有 G1/G2 边界测试**全部保留（四种 delta 边界、oracle parity、hash 语义、
   持久化结构共享）。
6. **bench 前后对照**：`authorization_compiler_bench` 全场景
   （增量路径预期持平；全量路径因组装引入分配，允许小幅回退并在报告中如实记录）。

### 8.3 关于 `COMPILER_VERSION` 不升版

`COMPILER_VERSION` 门控"通配/窗口/排序/段语义"变化及 producer↔projector 版本互认
（`prepare_compile_inputs` 拒绝 producer 版本不一致的事件）。本次改造不改变任何
段/hash/匹配语义，且升版会导致滚动发布窗口内 in-flight delta 事件被
`unsupported_producer_compiler` 拒绝。故保持 `phase2-authorization-kernel-v4`，
在代码注释与本设计文档记录布局变化。

---

## 9. 路线图（本期不做）

1. **段面跨卡共享**：card-less 共享段载荷 + 读侧归属虚拟化 +
   `PublishedCardAuthorization` 组合视图/延迟物化句柄（需 astral-types 合同演进，
   属 `Docs/api` 契约变更）。
2. **rule-set 级 delta 契约**：单事件携带"规则集内容变更 + 绑定卡集合"，
   编译器经绑定层把受影响面收敛为一次共享条目替换 + 绑定卡段重建，消除
   source→ledger→projection 的 O(N) 扇出（`card_rule_set_sources` 查询 API
   与绑定层已就位）。
3. **operation_id/event_id 池化**：fanout 同一 operation 的字符串 intern，
   进一步压缩记录层残留字节。
