# Rust 权限判定与规则集语义 V1.0

> 版本：V1.0
> 日期：2026-08-22
> 适用范围：`AstralLight-Rust` 的 `PolicyEngine`、RuleSet/permission rule 读模型、双卡资格门禁、委托回退与冲突检测。
> 文档性质：**非规范性架构设计/证据材料**，记录当前态事实、审计缺口与目标决策对照；目标决策不表示已经实施。工程规范与实施约束以 [Docs/规范/](../../规范/) 和仓库根目录 [AGENTS.md](../../../AGENTS.md) 为准。
> 证据口径：所有当前态结论以 Rust 源码、migration/schema 或已登记审计为依据；本文不把 Java 历史设计或目标态描述冒充 Rust 当前实现。

## 1. 标记、关联文档与术语

本文使用以下标记：

- **事实**：可由当前代码/schema 直接核验的行为。
- **缺口**：审计已识别或从当前调用/数据链可证明的未闭合边界。
- **目标决策**：2026-08-22 记录的设计选择；尚未实施的内容保持未来时态。

关联资料：

- [Rust 权限投影快照与版本栅栏](./Rust权限投影快照与版本栅栏_V1.0.md)：source mutation、projection worker、snapshot/cache/MQ、版本栅栏与审计旁路。
- [Rust 架构模型设计修正记录](./Rust架构模型设计修正记录.md)：问题 4（L2 错误与委托）、问题 9/14（资格投影）等核实记录。
- [物理双卡权限链路评估与设计](./物理双卡权限链路评估与设计_V1.0.md)：双卡事实线路、CARD gate、ELIGIBILITY gate 与残余边界。
- [Rust 迁移 Java 等价适配状态](../../迁移/Rust迁移Java等价适配状态_2026-08-05.md)：L2 exact-first、投影 gate、条件语义和未完成项。
- 规则模式权限体系设计：规则模式历史/模型基线；其中的建议条款不自动等于当前 Rust 事实。
- [Rust 后端编码规范](../../规范/Rust后端编码规范_V1.0.md)：PolicyEngine 与 `astral-db` 的 owner 边界。
- Structurizr 授权决策链路
- Structurizr 权限投影链路
- 授权决策排查图

术语：

- **CARD**：以 `user_card.card_id` 关联授权来源的历史/兼容聚合；旧 CARD snapshot/head 只用于迁移、对账或未声明 strict capability 的测试 repository。生产授权证据来自 canonical grant ledger 与 published current pointer。
- **ELIGIBILITY**：以同一 `user_card.card_id` 为聚合 ID 的物理资格投影；只维护资格缓存门禁，不重建规则快照。
- **RuleSet L1（legacy/test 语义标签）**：通过 `card_rule_set_ref` 找到绑定的 BASE/OVERLAY 规则集，并在兼容路径读取带旧 RULE_SET gate 的 `rule_set_snapshot` winner；该 staged first-match 语义也是 canonical compiler 输入语言的一部分，但不是生产 reader 的数据来源。
- **permission-rule L2 / L2.5（legacy/test 语义标签）**：旧 L2 读取卡级 `permission_rule_snapshot`，L2.5 读取带代次证明的委托投影；raw reader 只给 realtime/一致性巡检。生产 `SqlxRuleRepository` 不进入这些阶段，而是读取 published evidence 中的 `effective_grants`。无论哪条兼容路径，读取失败或未证明状态都不得交给下一阶段产生 ALLOW。
- **grant 合同（2026-08-26 增补，2026-08-27 同步）**：新 Rust-owned 授权账本为 ALLOW-only——普通 DENY 是评估/规则层关注点，不持久化为正授权 grant，撤销以 tombstone/fence 表达；RULE_SET 贡献携带 BASE/OVERLAY 优先级标签（`BindingLayer`），DELEGATION 贡献恒为 layer=None。该合同已接入正式授权读侧：生产 `SqlxRuleRepository` 声明 capability marker 后，`PolicyEngine::evaluate()` 以统一 ALLOW-only 匹配器消费 published evidence 中的 `effective_grants`（严格 strict gate，fail-closed）。新账本 source 侧已由 `grant_ledger_adapter` 把 Direct（USER_CARD 聚合）/Approval/RuleSet/Delegation typed 贡献在 source transaction 内写入授权账本并追加 delta event，projector 按 aggregate 消费新 delta 队列，不限于 `GrantSourceKind::RuleSet`；`GrantSourceKind::System` 预留给 migration/backfill 溯源（backfill 本身待办）。真实 MySQL/Redis/RabbitMQ 集成与正式切流验收未完成前不得宣称生产验收。本节其余判定语义（L1/L2/L2.5 阶段标签）在 legacy/test repository 路径上保持不变。

## 2. 当前判定总链路

**事实（2026-08-27 同步）**：生产 `SqlxRuleRepository` 声明 capability marker `requires_published_card_evidence() == true` 后，`PolicyEngine::evaluate()` 在 AUTHN/CARD_CONTEXT 与 resource/action 校验之后直接进入 published-evidence strict gate（见 §9.6），不再进入本节下述 CARD projection gate 与六阶段序列；下述顺序适用于未声明 marker 的 legacy/test repository 路径。证据：[`engine.rs:460-471`](../../../policy-engine/src/engine.rs#L460-L471)、[`repository.rs:342-351`](../../../astral-db/src/repository.rs#L342-L351)。

### 2.1 入口与双卡资格

**事实**：`PolicyEngine::evaluate` 的生产入口先进行 AUTHN、card context 和 resource/action 检查；生产 `SqlxRuleRepository` 随后进入 published-evidence strict gate。真实 `PLATFORM_USER` 的物理双卡资格由 `astral-db::CardEligibilityService` 负责。旧 CARD projection gate 仅在未声明 strict capability 的 legacy/test repository 中存在。引擎入口和资格服务证据：[`policy-engine/src/engine.rs:182-190`](../../../policy-engine/src/engine.rs#L182-L190)、[`engine.rs:209-357`](../../../policy-engine/src/engine.rs#L209-L357)。

**事实**：资格服务的权威 JOIN 将 identity_card 作为身份事实，将 user_card 作为授权/组织事实，并要求两卡通过同一 user_id 对齐；identity_card 不参与 tenant/domain 比较。见 [`astral-db/src/eligibility.rs:80-153`](../../../astral-db/src/eligibility.rs#L80-L153)、[`eligibility.rs:235-276`](../../../astral-db/src/eligibility.rs#L235-L276)。

**事实**：运行期资格缓存使用 ELIGIBILITY head 的三项版本和物理上下文，命中前校验 `projection_type`、user/identity/user-card/tenant/domain、`source_generation`、`projected_generation`、`revoke_fence` 以及自然到期时间；缓存失配或异常回到权威 SQL。见 [`eligibility.rs:156-231`](../../../astral-db/src/eligibility.rs#L156-L231)、[`eligibility.rs:338-373`](../../../astral-db/src/eligibility.rs#L338-L373)。

### 2.2 生产 strict gate 与 legacy 六阶段

**事实**：生产 `SqlxRuleRepository` 声明 `requires_published_card_evidence() == true`。`PolicyEngine::evaluate()` 在 AUTHN/CARD_CONTEXT 与 resource/action 校验后直接调用 published-evidence reader，使用 canonical `effective_grants` 进行 ALLOW-only 匹配；current、manifest/segment seal、scope、lineage、generation 或 `revoke_fence_proven` 任一证明不足时只能 `AUTHORIZATION_PENDING`/DENY，不进入旧 L1/L2/L2.5，也不回退旧 snapshot/raw source/cache。证据：[`engine.rs:460-471`](../../../policy-engine/src/engine.rs#L460-L471)、[`repository.rs:342-351`](../../../astral-db/src/repository.rs#L342-L351)。

**兼容事实**：未声明 marker 的 legacy/test repository 仍可执行 CARD/RULE_SET gate → L1 RuleSet → L2 `permission_rule_snapshot` → L2.5 generation-gated delegation → `DEFAULT_DENY`。本节后续的六阶段规则和 first-match 语义只适用于该兼容/诊断模型，不能写成生产 `SqlxRuleRepository` 的当前放行链。

**事实**：L1 命中 ALLOW、L2 命中 ALLOW、L2.5 委托命中 ALLOW 前都复检 projection gate；复检为 stale 或 error 时，旧 ALLOW 转为 `AUTHORIZATION_PENDING`。见 [`engine.rs:371-408`](../../../policy-engine/src/engine.rs#L371-L408)、[`engine.rs:424-462`](../../../policy-engine/src/engine.rs#L424-L462)、[`engine.rs:493-565`](../../../policy-engine/src/engine.rs#L493-L565)。

## 3. RuleSet 当前语义

### 3.1 数据与读取 owner

**事实**：`rule_set`、`rule_set_entry` 和 `card_rule_set_ref` 仍是 RuleSet 规则语言的 source 模型；`rule_set_snapshot` 是 legacy/迁移对照中的 winner 读模型。其结构和 winner 字段可由 baseline/migration 核验，但生产 `SqlxRuleRepository` 不以该表作为授权来源。canonical projector 将 RuleSet 贡献编译到 grant ledger，并通过 manifest/segment/current 发布证据。见 [`20240630000001_baseline.sql:7-58`](../../../astral-db/migrations/20240630000001_baseline.sql#L7-L58)、[`authorization_compiler.rs`](../../../policy-engine/src/authorization_compiler.rs#L1-L72)。

**兼容事实**：`load_rule_set_snapshots`、`load_snapshot_winners` 等方法仍保留在 `RuleRepository` trait 中，供未声明 strict capability 的 legacy/test repository、迁移对照和显式诊断使用；它们不能成为生产 `SqlxRuleRepository` 的授权入口。生产读侧调用 `load_published_card_authorization`，并验证 current pointer 指向的 manifest/segment 链、scope、lineage、generation、摘要/seal 与 `revoke_fence_proven`。

### 3.2 跨层顺序：OVERLAY 先于 BASE（规则语言语义）

**事实**：`OVERLAY > BASE` 是 RuleSet 规则语言和 canonical compiler 输入的跨层优先级：OVERLAY 中命中 DENY 或 ALLOW 都先于 BASE，只有 OVERLAY 全部 no-match 才进入 BASE。生产 reader 不逐表读取这些 refs，而是消费已由 compiler/projector 证明的 `effective_grants`；该顺序用于解释 grant provenance 和兼容/test 结果。见 [`engine.rs:966-1064`](../../../policy-engine/src/engine.rs#L966-L1064)。

这意味着当前 Rust 语义不是“BASE ALLOW 与 OVERLAY DENY 再做一次全局优先级比较”，而是分阶段：

```text
OVERLAY refs：首个命中即结束
  no match -> BASE refs：首个命中即结束
  no match -> 进入 L2
```

### 3.3 层内顺序：ref first-match-wins

**兼容事实**：每一层的旧规则集 ref 按兼容 repository 返回顺序遍历；单个 ref 有命中就立即返回。该 first-match 规则仍是 canonical compiler 必须保留的输入语义，但生产读侧以 published evidence 的稳定 grant/provenance 结果为准，不依赖运行时数据库返回顺序。`match_layer_first_match` 的实现见 [`engine.rs:1066-1091`](../../../policy-engine/src/engine.rs#L1066-L1091)。

**事实**：单 ref 内当前快照匹配顺序为：

1. exact `resource_key + action_code`；
2. 具体对象请求的 forward wildcard，例如 `type:42` → `type:*`；
3. 类型级请求的 reverse wildcard，扫描对象级条目，若存在 DENY 则 DENY，否则有对象 ALLOW 则 ALLOW；
4. 对动作别名重复上述顺序。

证据：[`engine.rs:1093-1188`](../../../policy-engine/src/engine.rs#L1093-L1188)、[`engine.rs:1223-1281`](../../../policy-engine/src/engine.rs#L1223-L1281)。

**事实**：在 legacy/raw 的 `RuleSetSnapshot.entries` 扫描路径中，条目按查询的 `priority DESC, effect DESC` 顺序进入单 pass；第一个匹配条目决定效果，运行时条件条目被跳过。见 [`engine.rs:1340-1441`](../../../policy-engine/src/engine.rs#L1340-L1441)。这一路径与正式 winner lookup 的 exact/forward/reverse 语义不可混写。

### 3.4 winner 语义与 canonical 编译边界

**事实**：`OVERLAY → BASE`、单 ref first-match、exact/forward/reverse wildcard、动作别名和同优先级 `entry_id` tie-break 是当前 RuleSet 规则语言/编译内核需要保持的语义。旧 `ProjectionWorker` 的 snapshot winner 重建只保留为 legacy/迁移证据；生产 canonical `AuthorizationCompiler` 将已验证的 RuleSet 贡献编译为 ALLOW-only grant candidate，再由 `AuthorizationProjector` 通过 manifest/segment/current durable CAS 发布。旧 snapshot 的 `valid_from/valid_to` 写入缺口不等于 canonical wall-clock expiry 已实现。见 [`authorization_compiler.rs`](../../../policy-engine/src/authorization_compiler.rs#L1-L72)、[`side_effects.rs:704-761`](../../../astral-trustgraph/src/api/side_effects.rs#L704-L761)。

**兼容事实**：在未声明 strict capability 的 repository 中，旧 winner 读取仍以 `MAX(version_no)` 和旧 `projection_generation`/head 进行对账；这些值不能单独授权，也不能替代 canonical current proof。
**事实**：equal-priority 且 effect 相同的 RuleSet 条目使用最低 `entry_id` 作为最终 tie-break，不再依赖数据库返回顺序。

## 4. `permission_rule_snapshot` 与 `rule_set_snapshot`

### 4.1 语义与生产数据来源

| 维度 | `permission_rule_snapshot`（legacy） | `rule_set_snapshot`（legacy） | canonical published evidence |
|------|----------------------------|---------------------|------------------------------|
| 逻辑来源 | 卡级 `permission_rule` | `rule_set_entry` + `rule_set` | grant revision ledger + typed delta |
| 绑定粒度 | `card_id` | `rule_set_id` 经绑定关系使用 | card/tenant scope 由 current/manifest 证明 |
| 兼容消费者 | 未声明 strict capability 的 L2/test/迁移对照 | 未声明 strict capability 的 L1/test/迁移对照 | 生产 `SqlxRuleRepository` → `load_published_card_authorization` |
| 版本选择 | 旧表 `MAX(version_no)` | 旧表 `MAX(version_no)` | current pointer → manifest/segment seal + generation/lineage/fence |
| source fallback | 仅 raw/一致性巡检；不作为生产 fallback | 仅 raw/一致性巡检；不作为生产 fallback | 无 source/snapshot/cache fallback |
| 未证明行为 | legacy/test 读取失败或 gate 不足 → PENDING/DENY | 同左 | current/manifest/segment 任一 proof 不足 → PENDING/DENY |

表结构与旧兼容读取实现仍可作为历史证据核验，但不能将两张 snapshot 表称为生产 canonical 授权来源。

### 4.2 legacy snapshot 行与源规则行的匹配语义

**兼容事实**：在未声明 strict capability 的 repository 中，旧 L2 根据返回行的 `id` 区分预编译 snapshot winner 与源规则行。`PermissionRule.id == 0` 的旧 winner 使用 exact-first 两段式匹配；源规则行使用带 priority 的单 pass。该差异只描述 legacy/test/迁移对照输入，不是生产 `SqlxRuleRepository` 的读取路径。见 [`engine.rs:1476-1559`](../../../policy-engine/src/engine.rs#L1476-L1559)。

**兼容事实**：旧 snapshot winner 的 exact-first 语义是具体对象先找完全相同的 `resource_key`，再找类型/全局通配；类型级请求不命中对象级条目。源规则单 pass 按 `priority DESC, effect DESC` 排序。生产 canonical reader 不消费这些行，而是匹配 published evidence 的 `effective_grants`。见 [`engine.rs:1563-1667`](../../../policy-engine/src/engine.rs#L1563-L1667)。

旧 snapshot 为空时，legacy/test 路径可把空集视为已证明的空授权结果且不回读 source；生产 strict gate 的“无有效证据”由 current/manifest/segment proof 决定，不能用旧空快照代替。

### 4.3 当前唯一键与版本号事实

**事实**：canonical SQL 设计中，`permission_rule_snapshot` 的唯一键是 `(card_id, resource_key, action_code)`，`rule_set_snapshot` 的唯一键是 `(rule_set_id, resource_key, action_code)`，同时两者均有 `version_no`。见 [full_schema_v4.sql permission snapshot](../../sql/full_schema_v4.sql#L1340-L1353) 与 [full_schema_v4.sql RuleSet snapshot](../../sql/full_schema_v4.sql#L1567-L1579)。

**事实**：Rust baseline 对两表只声明普通索引；`permission_rule_snapshot` 的 `version_no` 后续由 migration 添加并建 `(card_id, version_no)` 索引；RuleSet winner migration 只增加字段和 lookup index。对 `rule_set_snapshot` 而言，baseline 声明的是 `version` 列，而当前 RuleSet 重建/读取 SQL 使用 `version_no`；在已读取的 Rust migrations 中没有看到将 `version` 显式迁移/重命名为 `version_no` 的步骤。见 [`20240630000001_baseline.sql:35-86`](../../../astral-db/migrations/20240630000001_baseline.sql#L35-L86)、[`20240630000009_snapshot_version.sql:1-9`](../../../astral-db/migrations/20240630000009_snapshot_version.sql#L1-L9)、[`20240630000006_snapshot_winners.sql:1-13`](../../../astral-db/migrations/20240630000006_snapshot_winners.sql#L1-L13)、[`side_effects.rs:651-769`](../../../astral-trustgraph/src/api/side_effects.rs#L651-L769)。

**缺口**：若部署库仍只有 baseline 的 `version` 而没有代码所需的 `version_no`，RuleSet snapshot 的重建/读取会发生 schema 运行时错误；本文不假设部署库已完成对齐。

**事实（legacy/迁移对照）**：legacy/test 读路径仍使用每个快照的 `MAX(version_no)` 选择行，但不会单独以该值证明可读性：CARD cache 绑定旧 CARD head 三元版本，RuleSet dependency gate 还要求旧 `RULE_SET` head READY、source/projected 对齐、snapshot 行 `projection_generation` 等于 projected generation；未证明时安全 miss/PENDING。生产 `SqlxRuleRepository` 不经过该路径，直接消费 canonical published evidence。见 [`permission_query.rs:342-420`](../../../astral-db/src/permission_query.rs#L342-L420)、[`permission_query.rs:531-556`](../../../astral-db/src/permission_query.rs#L531-L556)。

**缺口**：如果部署 schema 未应用 canonical snapshot 唯一键，当前 Rust baseline 不能由自身保证每个逻辑 key 的数据库唯一性；应用侧 winner 去重和最新版本过滤不能替代唯一约束。

**事实**：`projection_generation` 是 RuleSet snapshot 与 durable RULE_SET head 的关联栅栏；`20260822000001_rule_set_projection_schema_repair.sql` 给既有 schema 添加该列并以 0 作为未证明哨兵，显式 migration backfill 为既有 RuleSet 创建/修复 head、outbox marker 和审计关联，再由 worker 重建后转 READY。`20260822000002_snapshot_validity_windows.sql` 另行添加两张 snapshot 表的 `valid_from/valid_to`，从仍可证明的 source identity 回填窗口并删除无法证明来源的旧行。迁移或回填失败时不推断 READY，读侧保持 fail-closed。见 [`20260822000001_rule_set_projection_schema_repair.sql`](../../../astral-db/migrations/20260822000001_rule_set_projection_schema_repair.sql)、[`20260822000002_snapshot_validity_windows.sql`](../../../astral-db/migrations/20260822000002_snapshot_validity_windows.sql)、[`migration.rs:3233-3638`](../../../astral-db/src/migration.rs#L3233-L3638)。

## 5. L2、L2.5 与 source-type ownership

### 5.1 legacy L2/L2.5 repository-error 行为

**兼容事实**：未声明 strict capability 的 repository 在旧 L2 `permission_rule_snapshot` 读取失败时立即返回 `DEPENDENCY_UNAVAILABLE`，不会进入旧 L2.5；只有明确无匹配才继续。旧 L2.5 使用 `load_projected_delegated_rules`，要求 CARD 代次证明；raw/source reader 只供 realtime/一致性巡检。见 [`engine.rs:554-625`](../../../policy-engine/src/engine.rs#L554-L625)、[`repository.rs:776-895`](../../../astral-db/src/repository.rs#L776-L895)。

**生产边界**：`SqlxRuleRepository` 不执行上述旧阶段，而是直接读取 canonical published evidence；current/manifest/segment 读取错误或证明不足保持 PENDING/DENY。

### 5.2 source_type 当前分布

**事实**：`permission_rule` 写入记录带 `source_type` 与可选 `source_id`；普通规则 repository 接受 `NewRule.source_type`，并从目标 user_card source row 派生 tenant_id。见 [`rule_repository.rs:181-223`](../../../astral-trustgraph/src/repository/rule_repository.rs#L181-L223)。

**事实**：legacy/test 阶段与巡检读取对来源有不同过滤：raw permission rules 使用 `MANUAL`/`DELEGATION`，delegation 另从 `permission_delegation` 查询；RuleSet 则从 `rule_set_entry`/snapshot 读取。生产 strict reader 只消费 canonical published evidence，不做上述旧 source/type 过滤。见 [`astral-db/src/repository.rs:517-615`](../../../astral-db/src/repository.rs#L517-L615)。

**事实**：委托 repository 在创建/更新时以同一 transaction 写 `permission_delegation` 与 `permission_rule(source_type='DELEGATION')`，并追加被委托卡 CARD projection。见 [`delegation_repository.rs:43-67`](../../../astral-trustgraph/src/repository/delegation_repository.rs#L43-L67)、[`delegation_repository.rs:162-181`](../../../astral-trustgraph/src/repository/delegation_repository.rs#L162-L181)、[`delegation_repository.rs:262-289`](../../../astral-trustgraph/src/repository/delegation_repository.rs#L262-L289)。

**缺口**：当前没有跨 RuleSet、permission_rule、delegation、snapshot 和 projection aggregate 的统一 source-type owner 合同。字段存在不等于 ownership 已闭合：无法仅从 `source_type` 全局推出写入 owner、投影 aggregate、快照消费者、撤销 fence 与审计事件的完整对应关系。该缺口仍与共享 RuleSet fan-out 和 L2/L2.5 双路径耦合；`version_no` 的行选择问题不能替代或削弱已落地的 RULE_SET durable generation gate。

## 6. 一致性巡检与 Arbiter

### 6.1 realtime 对照路径

**事实**：`evaluate_realtime` 是一致性检查专用路径，绕过 RuleSet snapshot 与 permission_rule_snapshot，读取原始 `rule_set_entry` 和 `permission_rule`；正常正式授权不使用这条路径作为宽松 fallback。见 [`engine.rs:663-670`](../../../policy-engine/src/engine.rs#L663-L670)、[`engine.rs:766-871`](../../../policy-engine/src/engine.rs#L766-L871)。

**事实**：realtime 路径也读取 projection gate，并在 gate 不 ready 或评估期间版本推进时返回 PENDING 语义；它不是绕过版本栅栏的旁路授权入口。见 [`engine.rs:724-755`](../../../policy-engine/src/engine.rs#L724-L755)、[`engine.rs:789-844`](../../../policy-engine/src/engine.rs#L789-L844)。

### 6.2 Arbiter 当前定位

**事实**：Arbiter 是无 IO 的冲突解析器。它只对已经带版本/来源证明的对照证据发出冲突信号；旧 snapshot gate 的 READY 语义仅适用于 legacy/test 对照，canonical 生产读门仍由 current/manifest/segment proof 决定。gate 未证明的收敛窗口不进入仲裁。见 [`arbiter.rs:1-16`](../../../policy-engine/src/arbiter.rs#L1-L16)、[`arbiter.rs:112-133`](../../../policy-engine/src/arbiter.rs#L112-L133)。

**事实**：Arbiter 按 `(source_generation, revoke_fence)` 版本序处理证据；无法证明时返回 `Defer`，其安全出口对应 `AUTHORIZATION_PENDING`，不是新的日常授权来源。见 [`arbiter.rs:160-229`](../../../policy-engine/src/arbiter.rs#L160-L229)。

**事实**：PolicyEngine 在一致性违规时调用 `detect_conflict` 并发出 signal；当前信号 sink 默认可为 no-op，仲裁执行不插入正常 evaluate 的 L1/L2/L2.5 顺序。见 [`engine.rs:605-615`](../../../policy-engine/src/engine.rs#L605-L615)。

## 7. 已识别缺口汇总

### 7.1 canonical published evidence 与 legacy gate 边界

**事实**：生产 `SqlxRuleRepository` 的 strict capability 已接线，正式授权只接受 current pointer 指向的 manifest/segment 完整证明、scope、lineage、generation、摘要/seal 与 `revoke_fence_proven`；任一缺失或读取错误均为 `AUTHORIZATION_PENDING`/DENY。旧 RuleSet head、旧 snapshot `projection_generation` 和旧 CARD gate 仍可作为 legacy/test/迁移对照，但不是生产授权完成证明。

证据：[published reader](../../../astral-db/src/authorization_projection_repository.rs#L1-L44)、[strict repository marker](../../../astral-db/src/repository.rs#L342-L351)、[projector](../../../astral-trustgraph/src/service/authorization_projector.rs#L741-L847)。

### 7.2 legacy snapshot version 与 canonical generation

**事实**：旧两张 snapshot 表的 `MAX(version_no)`、旧 head 的 `source_generation/projected_generation` 和 RuleSet 的 `projection_generation` 只用于兼容路径、迁移和对账。它们不能单独证明生产授权可读，也不能使 canonical current pointer 的证明状态回退或前进。

canonical generation 由 current pointer、manifest/segment seal、parent lineage、semantic/dependency hash 和 `revoke_fence_proven` 联合证明；proof 不足时保持 PENDING/DENY。

### 7.3 equal-priority ordering 的当前边界

**事实**：RuleSet winner 对同 priority、同 effect 的候选使用最低 `entry_id` 作为最终 tie-break；CARD 纯逻辑 winner 选择仍保留输入先序语义，不能把 CARD 与 RuleSet 的排序合同混写。见 [`side_effects.rs:704-761`](../../../astral-trustgraph/src/api/side_effects.rs#L704-L761)、[`side_effects.rs:396-439`](../../../astral-trustgraph/src/api/side_effects.rs#L396-L439)。

**剩余边界**：CARD 同 priority、同 effect 的规则尚未引入统一 `rule_id` tie-break；这不影响 RuleSet durable generation gate。

### 7.4 L2 repository-error delegation 已 fail-closed

**事实（legacy/test 路径）**：旧 L2 `permission_rule_snapshot` repository error 在进入旧 L2.5 前返回 `DEPENDENCY_UNAVAILABLE`；只有明确无匹配才继续。旧 L2.5 使用 generation-gated projected delegation reader，raw/source reader 只供 realtime/一致性巡检；生产 strict gate 不经过这些阶段。见 §5.1。

### 7.5 source-type ownership gap

**缺口**：`source_type` 分散在多条写/读路径，尚无统一 owner 矩阵或注册合同，不能仅凭字段值证明 projection、快照、审计和撤销链完整对应。见 §5.2。

### 7.6 CARD/ELIGIBILITY gate 的范围边界

**事实**：legacy CARD gate 决定旧规则授权 snapshot 是否可读；ELIGIBILITY gate 决定物理资格缓存是否可命中；生产正式授权由 canonical published-evidence gate 决定。CARD 与 ELIGIBILITY 共享 aggregate id 但不共享版本来源。见 [Rust 权限投影快照与版本栅栏](./Rust权限投影快照与版本栅栏_V1.0.md#5-card-与-eligibility-的投影产物)。

**缺口**：若未来新增影响资格的 source mutation、tenant/domain fan-out 或 identity 显式到期变更，必须明确事件进入 ELIGIBILITY、CARD 还是新的 aggregate；当前不存在 `IDENTITY` aggregate，不能默认由现有 CARD/ELIGIBILITY 代替。

## 8. 五链审查结论

### 8.1 调用链

**事实**：生产调用链为 Gateway/下游中间件构造 `PolicyContext` → `PolicyEngine::evaluate` → canonical published-evidence reader → ALLOW-only `effective_grants` matcher → `DEFAULT_DENY`；一致性巡检另走 `evaluate_realtime` 与 Arbiter signal。未声明 strict capability 的 legacy/test repository 才使用本文记录的 CARD/RULE_SET gate、L1、L2、L2.5 兼容阶段。

**结论**：本文没有增加第二个授权入口，也没有把 realtime、Arbiter 或旧 snapshot reader 写成生产授权 fallback。

### 8.2 逻辑链

**事实**：`OVERLAY → BASE`、层内 ref first-match、单 ref exact/forward/reverse/alias 是 legacy/test 规则语言和 canonical compiler 输入的语义；生产 reader 不从旧 snapshot 读取，而验证 current/manifest/segment proof 后匹配 `effective_grants`。旧 L2 repository error 的 fail-closed 规则只约束兼容路径。

**结论**：任何版本、来源或绑定变化都必须保持 proof-before-ALLOW；旧 snapshot/head 的 READY 或 `MAX(version_no)` 不能替代 canonical 证据。

### 8.3 事故链

**事实**：canonical current/manifest/segment 读取失败、scope/lineage/fence/hash 证明不足、projector lease/CAS 未知或 archive proof 未完成，都保持 PENDING/DENY 或进入有界 Blocked/Quarantine/Unknown；不会回退旧 snapshot/source/cache。legacy/test 路径的 L2/L2.5 repository error 也保持 fail-closed。

**结论**：组合故障和真实部署验收仍需独立覆盖，不能用 typed/mock 测试或旧 worker 的可重试状态宣布生产集成通过。

### 8.4 数据链

**事实**：旧 RuleSet/permission snapshot 是不同 source、粒度和兼容匹配语义的历史读模型；canonical 数据链是 grant revision → delta event → manifest/segment/current → published evidence。ELIGIBILITY head 只门禁物理资格缓存，不替代 canonical 授权证据。

**结论**：未来任何规则来源、编译字段、版本或唯一键调整，都必须同步 ledger、delta、manifest/segment seal、lineage/fence、reader dispatch、realtime comparator 和 stale-message consumer。

### 8.5 审计链

**事实**：权限检查审计通过 `AuditDualWrite::record_permission_check` 走 MQ-first/DB-fallback，MQ consumer 以 messageId/processing lease 做幂等，失败可重试；审计旁路不改变 PolicyEngine 的 decision。见 [`astral-common/src/audit.rs:165-195`](../../../astral-common/src/audit.rs#L165-L195)、[`astral-mq/src/consumer.rs:368-464`](../../../astral-mq/src/consumer.rs#L368-L464)。

**结论**：RuleSet/permission-rule source ownership gap 也必须在审计中可追踪到来源和聚合，但当前审计消息完成不等于 projection READY。

## 9. 目标决策（2026-08-22，非当前实现）

### 9.1 决策：保持 staged first-match

**目标决策**：保留并正式记录当前 RuleSet 的 staged first-match 语义：

```text
OVERLAY refs（按稳定 ref 顺序逐个 first-match）
  -> 若无命中，BASE refs（按稳定 ref 顺序逐个 first-match）
  -> 若无命中，进入 permission_rule_snapshot L2
  -> 若无命中，进入 delegation L2.5
  -> DEFAULT_DENY
```

“staged”表示跨层先后是阶段边界；“first-match”表示层内 ref 与单 ref 匹配顺序的首个有效命中决定效果。该决策不把当前 SQL 返回顺序的不确定性当作稳定排序合同；ref/entry tie-break 仍须在实施时补齐。

### 9.2 决策：当前行 + CAS `version_no`

**目标决策**：RuleSet snapshot 与 permission_rule_snapshot 的长期实现采用“当前行 + CAS `version_no`”写入合同，并与独立 durable aggregate head 对齐：

- 当前逻辑 key 在当前版本内必须唯一；
- writer 以已读 `version_no` 做 CAS，冲突不覆盖新版本；
- 读侧以 aggregate head 证明版本，不单独以 `MAX(version_no)` 证明跨模型一致；
- 删除旧快照不能使 durable version barrier 回到 0；
- version reset、重复逻辑 key、source mutation 与 snapshot 重建不在同一可证明事务内时，读侧进入 PENDING/安全 miss。

这是目标数据/版本合同，不声称当前 Rust migration 已具备完整实现。

### 9.3 决策：Arbiter 仍是冲突检测器

**目标决策**：Arbiter 保持冲突检测器/证据裁决器定位，不成为第四个日常授权阶段，不覆盖 L1/L2/L2.5 的 staged first-match 结果，也不绕过 projection gate。版本不可证明时保持 DEFER/PENDING；只有 READY 版本之间出现可区分分歧才生成冲突信号。

### 9.4 决策：来源 owner 显式化

**目标决策**：未来为每个 source type 建立显式 owner 矩阵，至少记录：source table、写入 owner、投影 aggregate、snapshot target、读侧阶段、撤销/fence 语义、审计事件和补偿入口。此项用于解决 §7.5 ownership gap，当前各局部路径的 source_type 字段不能被视为该矩阵已经存在。

### 9.5 决策：L2 错误在 L2.5 前 fail-closed

**当前实现**：L2 repository error 已在进入 L2.5 delegation 前 fail-closed，返回 `DEPENDENCY_UNAVAILABLE`；只有 L2 明确 `NoMatch` 才允许继续读取 L2.5。L2.5 使用受 CARD gate 与 snapshot provenance 保护的 `load_projected_delegated_rules`，raw/source reader 只供 realtime/一致性巡检，不是正式授权 fallback。组合故障下仍需持续验证断路器计数、审计 reason_code 与回滚策略。

### 9.6 决策：L1/L2/L2.5 为阶段标签、ALLOW-only 账本（2026-08-26，切片已入库；strict gate 已接线代码层、正式切流验收未完成）

**目标决策**：L1/L2/L2.5 继续作为三类授权来源（共享规则集 BASE/OVERLAY、卡级规则、委托）的阶段标签，不是互相回退链；任一层的读取失败/未证明状态只能 PENDING/DENY，不得转化为下一层的放行输入。新授权账本持久化 ALLOW-only grant（`GrantEffect` 只接受 ALLOW，普通 DENY 不持久化，撤销走 tombstone/fence），并把 BASE/OVERLAY 作为 RULE_SET 贡献的源标签（`BindingLayer`，DELEGATION 恒 None）。读侧现状：生产 `SqlxRuleRepository` 以 capability marker `requires_published_card_evidence() == true` 声明正式授权走 published evidence，`PolicyEngine::evaluate()` 在 marker 为真时以 ALLOW-only 匹配器消费账本 `effective_grants`（证据：[`repository.rs`](../../../astral-db/src/repository.rs#L342-L351)、[`engine.rs`](../../../policy-engine/src/engine.rs#L933-L960)），当前由 typed 测试覆盖。尚未完成：既有数据 backfill/rehearsal、缓存/摘要读侧迁移、真实 MySQL 集成验收与正式切流验收，均不得写成已完成或宣称生产验收；direct/approval/delegation/rule-set 贡献已由 `grant_ledger_adapter` 接线进入新账本（projector 按 aggregate 消费），其真实集成与切流验收包含在上述待办内。

## 10. 文档验收要点

- **事实/缺口/目标决策分离**：staged first-match、CARD/RULE_SET generation gate、Arbiter 定位和 L2 error fail-closed 均有源码证据；未实施项保持未来时态。
- **RuleSet 语义完整**：OVERLAY/BASE 跨层顺序、层内 ref first-match、单 ref exact/forward/reverse/alias、winner 编译和 entry_id tie-break 均有说明。
- **两类快照分离**：`permission_rule_snapshot` 与 `rule_set_snapshot` 的 source、owner、消费者、版本和 gate 差异明确。
- **剩余边界完整**：snapshot validity migration、RuleSet worker 尚未写入 winner validity、无 wall-clock expiry scheduler/event、CARD 同 effect tie-break、source-type ownership 和组合部署验收均明确标记。
- **安全约束**：本文不含绝对文件 URI、服务器 IP、密码、Token 或密钥；源码引用使用仓库相对链接。
