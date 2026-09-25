# Rust 增量重建与实时授权边界 V1.0

> 版本：V1.0
> 日期：2026-08-22
> 状态：架构边界说明；本文不代表已完成的实现承诺。
> 适用范围：`` 的 `policy-engine`、`astral-db`、`astral-cache`、`astral-mq` 与 `astral-trustgraph` 权限投影链路。

## 0. 结论摘要

当前 Rust 权限系统需要区分两条并存的投影边界：

1. `AuthorizationCompiler` 是当前保留的**无 IO、版本化热状态编译内核**。它以稳定 `GrantId`/`GrantRevision` 和 typed delta 生成 candidate 或显式 full-rebuild oracle；它不是旧数组索引 `SnapshotCompiler` 的别名，也不单独证明任何数据库状态已经发布。
2. 生产授权投影由 `AuthorizationProjector` 消费 `authorization_delta_event`，在事务外读取并编译 ledger，在发布事务内重新校验 lease、lineage、fence、generation 与 pointer，完成 manifest/segment/current 的 durable CAS；`AuthorizationArchiveWorker` 只负责对已替代 manifest 做 DB 内 proof-before-complete 归档。旧 `ProjectionWorker` 仅终结 CARD/RULE_SET writer-correlation 事件并处理 ELIGIBILITY 资格缓存失效，不再重建旧快照或推进旧 READY 状态。

生产 `SqlxRuleRepository` 声明 `requires_published_card_evidence() == true`。因此正式 `PolicyEngine.evaluate()` 在 AUTHN、卡上下文和 resource/action 校验后直接进入 published-evidence strict gate；缺 current、未证明、错误、scope 不符或证据畸形只能 PENDING/DENY，不能回退旧快照、raw source 或缓存。未声明该 capability 的 legacy/test repository 仍可保留 L1/L2/L2.5 兼容阶段，但这些阶段不代表生产 repository 的当前放行路径。

旧 `permission_rule_snapshot`、`rule_set_snapshot` 和 `authorization_projection_head` 的旧状态列仍可能存在于兼容源码、历史 schema 或待执行的迁移材料中。`20260827000002_legacy_snapshot_tables_decommission.sql` 明确是带前置条件的 standby script；迁移文件存在、代码路径退出与目标数据库已完成 DROP 不是同一事实，必须分别验证。

本文将事实、缺口和目标状态分开。源码行号是当前仓库证据，随代码变更可能需要同步更新。

**2026-09-09 同步**：上述新链 projector/archive worker 已在 TrustGraph main 接线，typed/shape 测试覆盖关键合同；既有数据 backfill/rehearsal、缓存/摘要读侧迁移以及真实 MySQL/Redis/RabbitMQ 集成和正式切流验收仍未完成。

## 1. 边界与术语

### 1.1 三类数据

| 名称 | 当前含义 | 典型表/接口 |
|---|---|---|
| source | 授权事实及其绑定关系 | `permission_rule`、`rule_set_entry`、`card_rule_set_ref`、授权账本 |
| legacy durable projection | 旧兼容读模型，处于退役路径 | `permission_rule_snapshot`、`rule_set_snapshot`、旧 `authorization_projection_head/outbox` |
| canonical durable projection | 当前 Rust-owned 发布证据链 | `authorization_grant_revision`、`authorization_delta_event`、`authorization_projection_manifest`、`authorization_projection_segment`、`authorization_projection_current` |
| projection/read gate | 允许正式读取已发布证据的版本与完整性证明 | current pointer、manifest/segment seal、generation、revoke-fence proof；旧 head 的 `projected_generation`/`projection_status` 不属于新链合同 |

本文中的旧 head/outbox、`permission_rule_snapshot` 和 `rule_set_snapshot` 段落均属于 legacy/迁移对照，不能被理解为生产 `SqlxRuleRepository` 的正式授权路径。当前生产路径由 grant ledger、delta event 和 published-evidence reader 组成。

### 1.2 三条授权相关路径

| 路径 | 目的 | 是否正式授权依据 | 是否允许绕过投影 gate |
|---|---|---:|---:|
| `PolicyEngine.evaluate()` | 业务请求的正式授权 | 是 | 否；生产 repository 提供显式 gate |
| `PolicyEngine.evaluate_realtime()` | 一致性巡检的显式 raw-source 对照 | 否，仅诊断/采样 | 否；仍要求 gate READY，并在返回前复检 |
| simulation / What-If | 管理员模拟当前或假设规则 | 否 | 由模拟 repository 自己决定；当前实现没有覆盖 `get_projection_gate`，属于显式隔离的模拟缺口，不是正式授权 fallback |

正式 TrustGraph 权限中间件构造物理策略上下文后调用 `state.engine.evaluate(&ctx, &repo)`。[`astral-trustgraph/src/api/permission_check.rs#L157-L166`](../../../astral-trustgraph/src/api/permission_check.rs#L157-L166)

## 2. 当前事实：增量编译器

### 2.1 已移除的旧数组索引编译器（历史边界）

早期版本曾有名为 `SnapshotCompiler` 的纯内存实验实现，使用 `RuleSetSnapshot` 数组索引表达 Add/Remove/Update，并把裸 `*`、操作数量和传入版本作为局部判断。该实现已经从 `policy-engine` workspace 移除；它的越界 no-op、数组索引不稳定和缺少 durable CAS 等问题只保留在历史审计中，不能作为当前 Rust API、测试入口或生产投影路径。

因此，本文后续关于旧数组索引、`SnapshotDelta` 和 `MAX_DELTA` 的描述均是历史对照，不应与当前 typed grant 编译合同混用。

### 2.2 当前 `AuthorizationCompiler` 职责

[`authorization_compiler.rs`](../../../policy-engine/src/authorization_compiler.rs#L1-L72) 是当前保留的无 IO 编译内核。它以 `GrantId`/`GrantRevision` 为稳定身份，接收 typed `GrantDelta`，要求调用方提供准确的 base version、semantic hash 和 dependency hash；冲突、版本不连续、重复 grant 或未知身份会产生显式错误/`FullRebuildRequired`，不会静默当作空操作。

当前内核的可验证行为包括：

- `MAX_INCREMENTAL_DELTAS = 100`；超过阈值、wildcard/action alias 影响、绑定层影响、compiler version 或 dependency 变化等情况进入带 `FullRebuildReason` 的 full-rebuild oracle；
- `HotState` 使用持久化 map 共享结构，稳定 key 的单键增删改为 O(1) 平均路径，受影响 segment 重新材料化；需要稳定导出或完整 oracle 时显式排序；
- semantic/dependency hash 与 `COMPILER_VERSION = phase2-authorization-kernel-v4` 一起绑定 candidate，hash 相同也不能替代 durable generation/CAS 证明；
- 账本为 ALLOW-only，撤销由 tombstone/fence 表达，普通 DENY 不作为正授权 grant 持久化。

### 2.3 编译内核与 durable 接线边界

当前 typed 单元测试覆盖 compiler contract、增量/全量等价、冲突分类、hash/version fence 和 factored shared layer；这些测试不等于数据库、缓存或消息基础设施验收。

生产 [`AuthorizationProjector`](../../../astral-trustgraph/src/service/authorization_projector.rs#L1-L25) 已消费 `authorization_delta_event`：事务外读取已证明的 ledger 并调用 `AuthorizationCompiler`，发布事务内重新验证 lease、lineage、revoke fence、generation、parent references 和 current-pointer CAS。发布成功后才可执行提交后的 L2 evidence 推送；任何 lease/CAS 未知结果都停止后续 mutation 并要求对账。

当前没有把 compiler candidate 写入旧 `permission_rule_snapshot`/`rule_set_snapshot` 的生产接线，也没有以旧快照重建作为新链的 fallback。真实 MySQL/Redis/RabbitMQ 集成、既有数据 backfill/rehearsal、缓存/摘要读侧迁移和正式切流仍是独立待办。

### 2.4 绑定层变更的编译语义决策（2026-08-28 正式决策）

实施计划草案中曾列有第五类 delta `BindingChange`（绑定层 BASE/OVERLAY 变更的独立增量语义）。**正式决策：不实现独立 `BindingChange` delta，绑定层变更统一走保守全量重建**——实现为 `FullRebuildReason::BindingImpact`：任何影响绑定层/来源层的 delta 在编译期被 `grant_requires_full_rebuild`/`grant_impact_reason` 判定后强制走 full oracle 重建，而不是作为独立增量 delta 推进。理由：绑定层变化可能改变同 key 多 provenance 的优先级语义，保守全量重建在正确性上无歧义，且绑定变更在真实负载中属低频事件，全量重建的性能代价可接受。该决策取代计划草案中的 `BindingChange` 条目；未来若需要绑定层增量语义，必须先扩展 `FullRebuildReason` 分类并重新审计优先级语义，不得在现有 delta 通道上私自扩展。

## 3. 当前事实：新授权投影器与 legacy writer-correlation 通道

### 3.1 `AuthorizationProjector` 的真实流程

当前生产授权投影由 [`AuthorizationProjector`](../../../astral-trustgraph/src/service/authorization_projector.rs#L1-L25) 消费 `authorization_delta_event`。每个事件的处理边界为：

1. 使用稳定 `event_id`/`operation_id` 和 run-scoped lease claim；
2. 在事务外严格重读 claimed event、published frontier、parent references 与完整 ledger，调用 `AuthorizationCompiler` 生成增量 candidate 或显式 full-rebuild oracle；
3. 在发布事务内重新校验 lease/token、lineage、revoke fence、generation、segment digest/seal 和 current pointer CAS；
4. 只有 manifest/segment/current 与 impact-plan durable 提交成功后，才把事件计为 published；提交后 L2 evidence 推送只是可选优化，失败不能扩大授权；
5. 确定性分歧通过 live-lease CAS 进入 `QUARANTINED`，未证明历史按 `Blocked` 有界退避，lease/CAS 未知结果停止后续 mutation 并要求对账。

该 worker 已在 TrustGraph `main` 接线，并且不写旧 snapshot 表、不消费旧 head/outbox 队列、不发布旧 refresh MQ、不执行旧 cache eviction。源码证据见 [`main.rs`](../../../astral-trustgraph/src/main.rs#L307-L349) 与 [`authorization_projector.rs`](../../../astral-trustgraph/src/service/authorization_projector.rs#L741-L847)。

### 3.2 旧 `ProjectionWorker` 的保留边界

旧 [`ProjectionWorker`](../../../astral-trustgraph/src/service/projection_worker.rs#L1-L31) 仍由进程持有，但其当前行为已收敛为兼容 writer-correlation/ELIGIBILITY 通道：CARD/RULE_SET 事件只做终态 `mark_processed`，不重建 `permission_rule_snapshot` 或 `rule_set_snapshot`；ELIGIBILITY 只失效 `perm:card:active:{card_id}` 资格缓存，不推进已删除的旧 READY 状态列。它不是新授权投影器，也不是生产 strict gate 的完成证明。

因此，旧代码中的 `rebuild_card_snapshot_inner`、`rebuild_rule_set_snapshot`、`ProjectionAdvance` 和 `permission.refresh` 相关段落只能作为 legacy/迁移审计材料阅读。当前生产授权的 durable 完成证明来自新链的 current pointer、manifest/segment seal、generation 和 revoke-fence proof；不能从旧 head 的 `projected_generation`/`projection_status` 推导。

读链切换批次 2 对“ELIGIBILITY head/outbox 通道与 ProjectionWorker 的 ELIGIBILITY 分支是否随旧 CARD/RULE_SET 读链一并下线”作出决策。**正式决策：方案 b——保留 ELIGIBILITY head/outbox 通道与 `projection_worker` 的 ELIGIBILITY 分支**；CARD/RULE_SET 分支在读链切换批次 3 下线后，worker 收敛为 ELIGIBILITY-only，ELIGIBILITY 分支仍是该 worker 的存续职责，不得随旧读链迁移被误删。理由：ELIGIBILITY 链与旧 head/snapshot 读链没有表级耦合，`eligibility.rs` 读取的是独立聚合 `ELIGIBILITY` 自己的 head（[`astral-db/src/eligibility.rs#L284-L309`](../../../astral-db/src/eligibility.rs#L284-L309)），其“旧”只是因为与旧 worker 分支共存于同一 worker，而非语义上依附旧快照读链；保留后 Chat realtime 以 `require_projection_ready=true` 硬依赖 ELIGIBILITY head READY 的语义（[`astral-chat/src/srv/realtime.rs#L399-L412`](../../../astral-chat/src/srv/realtime.rs#L399-L412)）与 PolicyEngine 侧 `require_projection_ready=false` + 三版本栅栏（资格缓存载荷携带 source/projected generation 与 revoke_fence，任一不匹配即整键 miss 回权威 SQL，授权 gate 未 READY 时仍由引擎拒绝；[`astral-db/src/eligibility.rs#L163-L231`](../../../astral-db/src/eligibility.rs#L163-L231)、[`astral-db/src/repository.rs#L186-L198`](../../../astral-db/src/repository.rs#L186-L198)）均保持不变，零语义风险。测试锁定见 [`astral-trustgraph/src/service/projection_worker.rs`](../../../astral-trustgraph/src/service/projection_worker.rs) 测试模块的 ELIGIBILITY 三态行为测试与 `eligibility_branch_is_survival_responsibility_of_worker` 结构锁定。

替代方案否决记录：方案 a（把 ELIGIBILITY 失效嫁接到 CARD manifest/快照 bump）把资格缓存失效语义混入授权快照投影，属于语义污染，且每次资格变更都会牵动 CARD 投影、成本爆炸，否决；方案 c'（写侧在 source mutation 提交后同步失效缓存并推进 ELIGIBILITY head READY，“去 worker 化”）技术可行但改动面大，且 Redis 故障时失效窗口退化为缓存 TTL（evict 失败只能等 TTL 自然过期，无 head gate 版本栅栏兜底），本批次不采用。方案 c' 仅可作为后续独立切片重新立项，前置条件：1) 先完成“Redis 故障窗口 = TTL”风险的登记与读侧补偿语义验收；2) 写侧同步 evict 必须补齐 restore/bind/identity 全部 ELIGIBILITY source mutation 路径并逐一审计；3) 迁移期间保留 head/outbox 兼容读法与回滚方案。

## 4. 当前事实：正式 `evaluate()`、实时评估与模拟的分离

### 4.1 生产 `evaluate()` 的 canonical 读路径

生产 `SqlxRuleRepository` 声明 `requires_published_card_evidence() == true`。正式权限请求在 AUTHN、CARD_CONTEXT 与 resource/action 校验后直接读取 published card evidence：current pointer 必须指向完整的 manifest/segment 链，并通过 scope、摘要/seal、parent lineage、generation 与 `revoke_fence_proven` 校验；有效 ALLOW 前还要复读证据。缺 current、证明闩、链完整性或读取结果时只能 `AUTHORIZATION_PENDING`/DENY，不进入旧 L1/L2/L2.5，也不回退旧 snapshot、raw source 或未认证缓存。

未声明 strict capability 的 legacy/test repository 才保留 CARD/RULE_SET gate → L1 RuleSet → L2 `permission_rule_snapshot` → L2.5 generation-gated delegation 的兼容阶段。该阶段的规则语义见 [Rust权限判定与规则集语义](./Rust权限判定与规则集语义_V1.0.md)，不能被误读为生产 `SqlxRuleRepository` 的当前放行链。

### 4.2 为什么不存在隐式 live-source ALLOW fallback

“投影未完成时直接读 source 以获得最新 ALLOW”会造成 source 与 durable projection 的判定时点不一致，也可能在撤销已写入 source、快照尚未重建时重新放行。当前设计选择 fail-closed（下列 gate/snapshot 读取行为属于未声明 strict capability 的 legacy/test repository 合同；生产 `SqlxRuleRepository` 直接进入 published-evidence strict gate）：

- SQLx repository 的 gate 查询总是返回显式状态；head 缺失映射为 `ready=false`。[`astral-db/src/repository.rs#L73-L106`](../../../astral-db/src/repository.rs#L73-L106) [`astral-db/src/repository.rs#L617-L625`](../../../astral-db/src/repository.rs#L617-L625)
- `load_rule_set_snapshots()` 在 gate 不可读时返回空，并只在版本兼容的 `perm:refs` 缓存命中或 durable snapshot 查询上继续。[`astral-db/src/repository.rs#L219-L350`](../../../astral-db/src/repository.rs#L219-L350)
- `load_snapshot_winners()` 同样要求 gate 可读后查询规则集快照，而不是查询 `rule_set_entry`。[`astral-db/src/repository.rs#L405-L450`](../../../astral-db/src/repository.rs#L405-L450)
- raw source 的两个 trait 方法明确标注为一致性检查专用；正式 `evaluate()` 不调用它们。[`policy-engine/src/engine.rs#L56-L72`](../../../policy-engine/src/engine.rs#L56-L72) [`astral-db/src/repository.rs#L517-L559`](../../../astral-db/src/repository.rs#L517-L559)

因此，`evaluate()` 没有“projection product miss → live source ALLOW”的隐式分支。对未声明 capability marker 的 legacy/test repository，L1/L2 的正式读取只消费通过 CARD/RULE_SET gate 认证的 `rule_set_snapshot` / `permission_rule_snapshot`；L2.5 只消费带 CARD generation 证明的 projected delegation rows，raw source reader 不参与正式授权。生产 `SqlxRuleRepository` 声明 `requires_published_card_evidence() == true` 后，正式请求在 AUTHN/CARD_CONTEXT 之后整体进入 published-evidence strict gate，不再触碰 L1/L2/L2.5 读取器（见本文开头 2026-08-26 增补）。`Ok(None)` gate 只在未接入 durable gate 的 test/default repository 中保留 legacy-compatible 行为；缺失/失败 fail-closed。对应测试区分 pending、ready 和 legacy test repository。[`policy-engine/src/engine.rs#L88-L126`](../../../policy-engine/src/engine.rs#L88-L126) [`policy-engine/src/engine.rs#L453-L495`](../../../policy-engine/src/engine.rs#L453-L495) [`astral-db/src/repository.rs#L342-L351`](../../../astral-db/src/repository.rs#L342-L351)

### 4.3 显式 `evaluate_realtime()`

`evaluate_realtime()` 是一致性检查专用路径，明确跳过快照预计算层：L1 读 raw `rule_set_entry`，L2 读 raw `permission_rule`，但仍执行认证、卡资格和 projection gate，并在每个可能的 ALLOW 返回前复检 generation/fence。[`policy-engine/src/engine.rs#L664-L755`](../../../policy-engine/src/engine.rs#L664-L755) [`policy-engine/src/engine.rs#L767-L927`](../../../policy-engine/src/engine.rs#L767-L927)

它的结果不能替代正式 `evaluate()` 的生产决策。若 gate 在评估期间推进，实时路径也转为 `AUTHORIZATION_PENDING`；它不是“强制读最新 source 并放行”的通道。

### 4.4 一致性采样

`SnapshotConsistencyChecker` 用原子计数器每 100 次调用采样一次，即约 1%，而不是每个请求都进行双路径评估。采样前读取 gate；未 READY、gate 读取失败、采样前后 generation/fence 改变，均跳过违规比较。只有同一可读 projection generation 下，才比较正式快照决策和实时决策的 `allowed` 值，并记录违规。[`policy-engine/src/consistency.rs#L1-L16`](../../../policy-engine/src/consistency.rs#L1-L40) [`policy-engine/src/consistency.rs#L59-L125`](../../../policy-engine/src/consistency.rs#L59-L125)

采样在正式 `evaluate()` 决策完成后调用，作用是观测和发出冲突信号，不把 realtime 结果写回正式决策。[`policy-engine/src/engine.rs#L604-L617`](../../../policy-engine/src/engine.rs#L604-L617)

### 4.5 simulation / What-If

模拟 API 由已验证的 platform admin 调用，分别计算 current decision 和叠加 proposed overlay 后的 proposed decision；它面向 What-If，不是业务请求的授权路径。[`astral-trustgraph/src/api/simulation.rs#L167-L250`](../../../astral-trustgraph/src/api/simulation.rs#L167-L250)

当前 `SimulationRepo` 没有实现 `get_projection_gate()`，因此继承 `RuleRepository` 的 `Ok(None)` 默认行为；同时它自己从 `rule_set_snapshot + rule_set_entry` 和 `permission_rule` 加载模拟数据。这个默认行为只应被理解为模拟隔离，不得复制到正式 repository 或正式中间件。[`astral-trustgraph/src/api/simulation.rs#L61-L159`](../../../astral-trustgraph/src/api/simulation.rs#L61-L159) [`policy-engine/src/engine.rs#L88-L101`](../../../policy-engine/src/engine.rs#L88-L101)

## 5. 当前事实：published evidence、缓存与版本拒绝

### 5.1 生产权限查询的 evidence cache-aside

生产共享权限查询以 `load_published_card_authorization` 为唯一授权读端口。进程内 evidence cache 与 L2 Redis evidence cache 只能缓存已验证的 current/manifest/segment 证据；命中前必须做 pointer 对牌、tenant/card scope、时钟/TTL、HMAC/content hash 和完整性校验。任何 miss、过期、MAC/摘要失配或 Redis 故障都回源 strict reader，不能读取旧 snapshot、raw source 或旧 head，也不能把缓存命中当作 durable proof。证据入口：[`astral-db/src/permission_query.rs`](../../../astral-db/src/permission_query.rs#L1-L18)、[`evidence_cache.rs`](../../../astral-db/src/evidence_cache.rs#L1-L40)、[`repository.rs`](../../../astral-db/src/repository.rs#L342-L351)。

published evidence 的载荷绑定 manifest 版本组、scope、generation、lineage、revoke-fence proof 和 content hash；缓存 TTL/容量/GC 只限制停留时间，不改变严格读门。strict reader 或数据库不可用时保持 PENDING/DENY。旧 `perm:refs:{card_id}` 等 cache-aside 仅供 legacy/test/迁移对照，不能成为生产 `SqlxRuleRepository` 的授权来源。

### 5.2 ELIGIBILITY 资格缓存的时间感知回退

`perm:card:active:{card_id}` 是独立 ELIGIBILITY 资格缓存，不等同于 CARD 授权规则快照。Redis 异常、载荷解析失败、投影版本不匹配或缓存到期都会回到同一条双卡权威 SQL；SQL 失败返回 repository error，不能默认 ALLOW。[`astral-db/src/eligibility.rs#L156-L231`](../../../astral-db/src/eligibility.rs#L156-L231)

资格有效期取 `min(identity_card.expires_at, user_card.valid_until)`；读时再次检查自然到期，写缓存 TTL 以剩余有效时间为上限并带抖动。[`astral-db/src/eligibility.rs#L235-L268`](../../../astral-db/src/eligibility.rs#L235-L268) [`astral-db/src/eligibility.rs#L377-L461`](../../../astral-db/src/eligibility.rs#L377-L461)

### 5.3 旧缓存装饰器与风险

`astral-cache::CachedRuleRepository` 仍保留另一种装饰器语义：使用 `permission:snapshot:{card_id}`，普通快照 TTL 30 秒，检测到裸 `*` 时 TTL 10 秒；Redis GET 错误直接返回 `PolicyError::Repository`，该装饰器自身没有像 `find_effective_permissions_cached()` 那样的 DB fallback，也没有把 projection 三项版本写入 payload。[`astral-cache/src/cache_repository.rs#L1-L24`](../../../astral-cache/src/cache_repository.rs#L1-L24) [`astral-cache/src/cache_repository.rs#L46-L112`](../../../astral-cache/src/cache_repository.rs#L46-L112)

该装饰器若被接入没有 gate/version 校验的 repository，风险包括：

- TTL 只提供时间上限，不证明缓存对应当前 source generation；
- 裸 `*` 检查仍不覆盖 `type:*` 等完整授权 wildcard 语义；
- Redis 故障可能表现为 repository failure，而不是 DB-only 读；
- `evict_card()` 是显式删除，不是 durable projection 完成证明。

因此它只能作为兼容组件审计，不能成为目标增量编译链的唯一一致性保证。

## 6. 当前缺口：兼容入口、直接重建、时间和生命周期

### 6.1 兼容 cache / direct rebuild 路径

`PermissionSideEffects` trait 仍保留 `rebuild_card_snapshot`、`rebuild_rule_set_snapshot`、`evict_card_cache` 等兼容方法。它们属于旧 writer-correlation、迁移或测试适配面：`rebuild_card_snapshot()` 可转发为 source-side `request_card_projection()`，`rebuild_rule_set_snapshot()` 兼容实现为 no-op；当前生产授权投影不通过这些方法写旧 snapshot，而由 `AuthorizationProjector` 消费 `authorization_delta_event` 并发布 manifest/segment/current 证据。相关兼容接口见 [`astral-trustgraph/src/service/side_effect.rs#L14-L88`](../../../astral-trustgraph/src/service/side_effect.rs#L14-L88)。

补偿/回放必须重放带稳定 event/operation id 的 durable delta，并重新走 lease、lineage、fence、generation 和 current-pointer CAS；不能直接写旧 snapshot 来制造授权完成。`AuthorizationArchiveWorker` 也必须先完成整链 proof，再将 archive intent 标记完成。

旧缓存失效函数仍可能是 fire-and-forget；Redis 打不开或 DEL 失败只影响兼容副作用。生产 evidence cache 的 miss/失配只能回到 strict published reader，ELIGIBILITY cache 失配才回到权威资格 SQL；任何路径都不能以旧缓存、旧 snapshot 或 raw source 产生 ALLOW。

### 6.2 规则有效期与快照新鲜度

**legacy 路径**：旧重建 SQL（writer-correlation/迁移对照面）在构建时使用 `UTC_TIMESTAMP()` 过滤 `valid_from/valid_to`，RuleSet 和卡快照只把构建时当前有效、可预计算规则写入快照。[`astral-trustgraph/src/api/side_effects.rs#L451-L460`](../../../astral-trustgraph/src/api/side_effects.rs#L451-L460) [`astral-trustgraph/src/api/side_effects.rs#L825-L836`](../../../astral-trustgraph/src/api/side_effects.rs#L825-L836)

**明确剩余限制**：规则的 wall-clock 时间窗自然到期本身未必产生 source mutation，因此 canonical 链与 legacy 链目前都没有独立 expiry scheduler/event 自动触发授权投影更新。正式 `evaluate()` 读取 published evidence，不会把 `valid_to` 再作为 generation 变更；较短缓存 TTL 只能减少停留时间，不能更新 durable 证据。`evaluate_realtime()` 的 raw SQL 时间过滤只是显式诊断路径，不能自动修复正式投影，也不能成为隐式 ALLOW fallback。

身份/卡资格自然到期由资格服务在读时检查并以 TTL 截断；这不等于 RuleSet `valid_to` 已有 wall-clock 投影调度。任何将规则到期纳入生产授权的方案仍需补事件/调度、迁移、审计、回滚和到期前后 gate 验收。

### 6.3 worker 超时与生命周期

**当前事实**：`AuthorizationProjector` 已有事件级 deadline、bounded attempts、lease/token fence、pointer-moved replan、Blocked/Quarantine/Unknown 分类；`AuthorizationArchiveWorker` 已有 cancellation 检查、有限 claim、proof-before-complete、过期 lease recovery 和 bounded join。TrustGraph `main` 持有旧 projection worker、新 projector、archive worker 等句柄，并按逆序 cancel/join；这些代码级事实不等于真实基础设施或故障注入验收已通过。证据：[`authorization_projector.rs`](../../../astral-trustgraph/src/service/authorization_projector.rs#L741-L847)、[`authorization_archive_worker.rs`](../../../astral-trustgraph/src/service/authorization_archive_worker.rs#L577-L735)、[`main.rs`](../../../astral-trustgraph/src/main.rs#L307-L365)。

**legacy 边界**：旧 `ProjectionWorker` 的 poll/lease/退避只处理 writer-correlation 与 ELIGIBILITY 兼容通道；旧 `project_one()`、`rebuild_card_snapshot_inner()`、旧 MQ publish/mark 顺序不能作为 canonical projector 的生命周期合同。旧通道的 lease 过期可能造成重复终态尝试，但不得影响 canonical pointer proof；未知结果仍需停止相关 mutation 并对账。

**剩余边界**：DB/Redis/RabbitMQ 组合故障、进程重启、租约接管和 shutdown 的真实集成证据仍待执行；不能用 typed/mock 测试宣布生产恢复闭环。

## 7. 当前已有的安全门

当前实现已具备下列重要防护，但它们不等于真实集成或正式切流已完成：

1. source mutation 可在同一事务落 grant revision/delta event；旧 head/outbox 仅作为兼容 writer-correlation，不是 canonical 发布证明。
2. `AuthorizationProjector` 对新 delta 事件使用稳定 id、lease、lineage、revoke fence、generation、segment seal 和 current-pointer CAS；确定性 divergence 进入 quarantine，未证明历史按 Blocked 退避，未知结果先对账。
3. `AuthorizationArchiveWorker` 只在整条 superseded manifest 链 proof 成功后记录 durable archive proof 并完成 intent；失败不伪造完成。
4. 生产 `SqlxRuleRepository` strict reader 只消费 published evidence；current/manifest/segment 证明不足、scope 不符、缓存 MAC/摘要失配或 Redis/DB 失败均不扩大授权。
5. ELIGIBILITY 资格缓存独立绑定物理双卡上下文和版本；失配回权威 SQL，不能作为规则授权 fallback。
6. 旧 CARD/RULE_SET worker 只终结兼容事件，ELIGIBILITY 分支只做资格缓存失效；旧 snapshot/head/refresh 副作用不再构成生产授权链。

## 8. 迁移、回填与发布/回滚边界

旧 `20260822000001_rule_set_projection_schema_repair.sql` 与 `20260822000002_snapshot_validity_windows.sql` 只修复/回填 legacy snapshot/head 形状，不能证明 canonical 授权已发布。`20260825000002_incremental_projection_archive.sql` 是 canonical grant/delta/manifest/segment/current 的 creator-only migration，不负责既有数据 backfill；`20260827000001_authorization_projection_lineage_fence.sql` 增加 lineage/revoke-fence proof 字段；`20260827000002_legacy_snapshot_tables_decommission.sql` 是带前置条件的 standby script。迁移文件存在、代码路径退出、目标库已应用、旧表已 DROP 和既有账本已 rehearsal 不是同一事实。

发布前必须在隔离/预演库分别核对 schema/migration postcondition、grant ledger backfill、current pointer 的 `revoke_fence_proven`、manifest/segment seal、lineage、projector replay、archive proof、evidence cache 和审计关联，再切换正式读侧。回滚以停止新写入、保留 durable delta/current/审计证据、修复或重放失败事件为主；不得删除 canonical current、清空证明闩、恢复未证明旧 snapshot 或以旧 head READY 制造授权放行。任何 lease/CAS/commit 未知结果都先对账，不能盲目重试或宣布成功。
规则集投影及已删除旧接口属于 Rust 0.x workspace 内部接口迁移：同一变更必须同步仓内调用方、测试和文档，并在提交/PR 中标注 `BREAKING CHANGE`，列明删除清单、替代入口、影响范围、生效时间、迁移方案和回滚方案；稳定 `pub` API、外部 HTTP、消息/数据库协议不适用内部接口例外。

## 9. 目标状态：安全的增量编译设计

本节是目标设计，不是当前实现。落地前需要独立的代码、DDL、消息、迁移、回滚和测试变更，并遵循 Rust 工程规范中“契约由文档驱动、每次改动同步相关文档”的要求。[`Rust后端编码规范_V1.0.md#L9-L15`](../../../Docs/规范/Rust后端编码规范_V1.0.md#L9-L15)

2026-08-26 备注：§2.4 记录的 `AuthorizationCompiler` 内核、新表链持久化原语与 projector/archive worker 是朝本节目标的第一批切片；但针对旧 `SnapshotCompiler` 快照路径的“source → 增量 candidate/全量 → CAS → READY → 正式 evaluate”端到端增量接线、既有数据 backfill/rehearsal、缓存/摘要读侧迁移与真实集成验收仍未发生，本节其余内容继续按目标态阅读。

### 9.1 稳定身份与规范化输入

目标 `DeltaOp` 不应再以数组索引作为长期定位身份。每个操作至少应带有：

- `aggregate_type`、`aggregate_id` 和 `ref_type`；
- source entry 的稳定 `entry_id`，必要时包括 rule id / delegation id；
- 规范化的 `(resource_key, action_code, effect, priority, condition)`；
- 产生该操作的 `event_id`、`source_generation` 和 `revoke_fence`；
- 受影响的投影类型和编译输入版本。

删除未知稳定 ID、重复 event、同一事件重放和操作顺序冲突必须是显式结果，而不是当前越界索引的静默 no-op。

### 9.2 event / generation / CAS 提交协议

建议的最小提交协议（以 2026-08-22 的旧 head/outbox 词汇表述目标合同；canonical 对应物由 `AuthorizationProjector` 的 lease/lineage/fence 校验与 current-pointer CAS 承担）：

1. source mutation 与 head/outbox 在同一事务内产生唯一 `event_id` 和递增 `source_generation`；
2. compiler 读取明确的 base projection generation，并验证 source generation 连续；
3. compiler 在内存中生成 candidate snapshot，不对外暴露；
4. 以 `aggregate_id + expected_source_generation + expected_projected_generation` 做 SQL CAS，或在持有 head 行锁的事务内确认；
5. 只有 candidate snapshot durable 写入成功、head 推进到同代 READY 后，才允许 evict/cache publish；
6. CAS 冲突、generation gap、事件重复或 head 超前均不得发布 ALLOW 相关刷新，转入重试或 full rebuild。

**legacy/目标协议对照**：旧 `ProjectionAdvance`、发布前 head 复查和 consumer 旧代拒绝只是 legacy/迁移对照材料，不能把纯内存 `current_version+1` 当成 durable CAS；canonical 的同等保证来自发布事务内的复查与 reader 的 generation/lineage/`revoke_fence_proven` 校验。[`astral-trustgraph/src/repository/projection_repository.rs#L96-L133`](../../../astral-trustgraph/src/repository/projection_repository.rs#L96-L133) [`astral-trustgraph/src/service/projection_worker.rs#L222-L256`](../../../astral-trustgraph/src/service/projection_worker.rs#L222-L256)

### 9.3 semantic hash

candidate snapshot 应计算稳定的 semantic hash，而不是只比较行数或版本号。建议 hash 输入包括：

- 按稳定 ID 和规范化 key 排序后的有效 entry；
- effect、priority、资源对象级/类型级 wildcard、动作别名展开结果；
- runtime condition 的分类和是否进入预计算；
- 当前时间窗口策略及其版本；
- CARD/ELIGIBILITY、BASE/OVERLAY 绑定上下文；
- compiler version。

hash 用于：

- 证明增量基底仍与 source 语义一致；
- 检测遗漏事件、乱序、旧 cache 或跨版本编译；
- 对 candidate 和 full rebuild 做等价性校验；
- 相同 hash 的重放直接进入幂等完成路径，但仍必须满足 head/owner fence。

semantic hash 不能替代 generation/CAS。hash 相同只说明语义候选相同，不证明当前事件已被 durable 消费。

### 9.4 compiler version

snapshot metadata 应持久化 `compiler_version`，并将它与 semantic hash、source/projected generation 一起作为可读性条件。编译语义、wildcard 解释、runtime condition 分类或排序规则变化时，旧版本快照不得继续被当作新编译器的等价结果；应标记为不可读并 full rebuild。

### 9.5 full-rebuild fallback

以下情况必须回退到 `AuthorizationCompiler` 显式 full-rebuild oracle，由 `AuthorizationProjector` 完成 durable full rebuild：

- `DeltaOp` 数量超过阈值；
- 任何可能影响未知集合的 wildcard、动作别名、规则集绑定或 overlay/base 优先级变化；
- runtime condition、时间窗口、删除、未知稳定 ID 或语义 hash 无法安全局部化；
- generation 不连续、event 顺序不明、重复事件无法证明幂等；
- CAS 冲突耗尽、compiler version 不兼容、base hash 不匹配；
- candidate 落库、缓存失效或消息发布超过操作预算，无法证明 gate 已推进。

full rebuild 不是失败吞并：必须留下可观测原因、保留 durable outbox 状态，并在 head 未 READY 前让正式授权返回 `AUTHORIZATION_PENDING` 或 DENY。不能通过“临时直接读 source”绕过 fallback。

### 9.6 时间到期与调度

目标方案必须把 `valid_from/valid_to` 的到期纳入 projection 事件模型。可选实现包括：

- 在到期前后由调度器产生带 generation 的 projection event；
- 将时间窗口语义纳入可验证的读侧动态条件，但只在正式策略语义和缓存版本协议明确支持后使用；
- 对含无法安全增量处理的时间/runtime 条件强制走 full rebuild。

无论选择哪种方式，都必须说明到期窗口内是否 PENDING、DENY 或使用已证明有效的旧投影；不能仅依赖 Redis TTL，也不能把诊断 realtime 路径当作生产兜底。

### 9.7 worker 生命周期与操作预算

目标 worker 至少应具备：

- 每事件 DB/Redis/MQ timeout 和 cancellation；
- 可续租的 owner-fenced lease，过期后旧 worker 不能完成 processed、发布旧消息或覆盖新 candidate；
- main 持有并在 graceful shutdown 取消、等待 projection worker；
- 每事件 attempt、耗时、generation、hash、compiler version、fallback reason 的指标和审计日志；
- MQ/Redis 失败与 snapshot commit 的明确补偿状态；
- full rebuild 和 incremental compile 的结果等价性抽样测试。

### 10. 目标授权边界

目标状态仍保持以下单向约束：

```text
source mutation
  -> grant revision + typed delta event
  -> AuthorizationCompiler candidate OR explicit full-rebuild oracle
  -> AuthorizationProjector lease/lineage/fence/generation validation
  -> manifest/segment seal + authorization_projection_current CAS
  -> published-evidence reader / effective_grants
  -> formal PolicyEngine.evaluate()
```

`evaluate_realtime()` 只能作为显式诊断/一致性采样入口；simulation 只能作为显式管理模拟入口。二者都不能在正式请求中隐式替代 `evaluate()`，也不能因为“source 更新更快”就授予 ALLOW。旧 head 的 `projected_generation == source_generation && READY`、旧 snapshot 行和旧 cache-aside 只能出现在 legacy/迁移对照，不属于 canonical 目标准入条件。

即使目标增量编译完成，系统仍应表述为异步投影、可验证代际收敛、lag 期间 fail-closed/PENDING；它不提供硬实时保证，也不宣称跨 source、projection、Redis、MQ 和所有读副本的强一致。

## 11. 验收与证据清单

落地增量编译前，至少应补充以下测试类别：

| 类别 | 最低验收点 |
|---|---|
| 纯编译 | stable ID 增删改、乱序、重复 event、越界/未知 ID、阈值和全量 wildcard |
| 语义等价 | candidate 与 full rebuild 的 snapshot rows、winner、hash、compiler version 一致 |
| durable CAS | source/projected generation 竞争、CAS 冲突、worker 重试、AlreadyCurrent、Superseded |
| gate | current pointer 缺失、PENDING、generation gap、revoke fence/证明闩推进、stale ALLOW 变 PENDING |
| cache-aside | Redis 命中、miss、版本不匹配、Redis 故障 DB fallback、旧/legacy payload 拒绝 |
| 时间 | valid_from 尚未生效、valid_to 到期、自然卡过期、时间事件缺失与补偿 |
| 生命周期 | 单事件超时、取消、租约续期/丢失、shutdown join、MQ publish/processed 失败重放 |
| 安全边界 | 生产 formal evaluate 只读 published evidence；legacy/test 的 L1/L2 才读取旧投影，L2.5 仅在旧 CARD gate 通过后查询委托源；realtime/simulation 必须保持显式隔离；无 projection-miss 到 source ALLOW fallback |

当前仓库已有的投影门禁、代际围栏、缓存版本校验和 stale ALLOW 拒绝测试可作为基线，但它们验证的是现有全量 durable projection 边界，不是 `AuthorizationCompiler`/`AuthorizationProjector` 已完成生产切流验收的证据。[`policy-engine/src/engine.rs#L2354-L2418`](../../../policy-engine/src/engine.rs#L2354-L2418) [`astral-trustgraph/src/service/projection_worker.rs#L560-L719`](../../../astral-trustgraph/src/service/projection_worker.rs#L560-L719) [`astral-trustgraph/src/repository/projection_repository.rs#L508-L640`](../../../astral-trustgraph/src/repository/projection_repository.rs#L508-L640)

相关架构基线：[物理双卡权限链路评估与设计_V1.0.md](物理双卡权限链路评估与设计_V1.0.md)；[Rust 后端编码规范 V1.0](../../../Docs/规范/Rust后端编码规范_V1.0.md)；全栈工程规范。
