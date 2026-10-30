# Rust 增量重建与实时授权边界 V1.0

> 版本：V1.0
> 原始版本日期：2026-08-22；CURRENT V6 现状补记：2026-10-28
> 状态：架构边界说明；本文不代表已完成的实现承诺。
> 适用范围：`policy-engine`、`astral-db`、`astral-mq` 与 `astral-trustgraph` 权限投影链路。CURRENT V6 已退役 Redis L2/MAC/shared-unit、session compatibility adapters 与 `astral-cache`；本文旧段落仅在明确标为历史/迁移对照时保留。

## 0. 结论摘要

CURRENT V6 下，授权投影与正式读门构成一个不可分割的授权 bundle：compiler/admission/read gates、publication、segments、archive/completion、invalidation、snapshot 和 wire contract 必须一致切换。`AuthorizationCompiler` 是无 IO、版本化热状态编译内核；它以稳定 `GrantId`/`GrantRevision` 和 typed delta 生成 candidate 或显式 full-rebuild oracle，但不单独证明 durable 发布。

生产 `AuthorizationProjector` 是授权 delta 的唯一执行 owner。source transaction COMMIT 被证明成功后，才向其交付完整不可变 receipt batch；请求侧只可在 COMMIT proof 后对完整 batch 做只读 exact-completion observation wait，限时 5 秒、25 ms 轮询，最多 64 个事件和 50 个 distinct card scopes。超限 batch 不截断，完整交给 worker；请求不得 claim、compile、publish、release 或竞争 worker，超时不代表完成。`AuthorizationProjector` 在事务外读取并编译 ledger，在发布事务内重新校验 lease、lineage、fence、generation 与 pointer，完成 manifest/segment/current durable CAS；`AuthorizationArchiveWorker` 仅对已替代 manifest 执行 DB 内 proof-before-complete 归档。旧 `ProjectionWorker` 只处理保留的 source-correlation/revoke/RuleSet 初始化关联及 ELIGIBILITY invalidation，不重建旧授权快照或推进旧 READY。

正式 `PolicyEngine::evaluate()` 使用恰好四个无默认实现的 required `RuleRepository` ports：`check_card_active`、`is_active_global_admin`、`load_published_card_authorization`、`load_org_authorization`。认证、卡上下文和 resource/action 检查后进入 CURRENT V6 published-evidence strict gate；缺 current、未证明、读取错误、scope 不符或证据畸形只能 PENDING/DENY，不回退旧快照、raw source、realtime evaluator 或 legacy 阶段。当前授权不存在 capability-marker dispatch、可选 legacy path、L1/L2/L2.5 evaluator 或 `evaluate_realtime()` raw-source 授权。

旧 `permission_rule_snapshot`、`rule_set_snapshot` 和 `authorization_projection_head` 状态列只在历史/迁移对照材料中出现；迁移文件存在、代码路径退出、目标数据库完成 DROP、migration 已应用、旧数据 backfill/rehearsal 和正式切流是不同事实，必须分别取证。head/outbox 仍只承载 source correlation、revoke/RuleSet initialization correlation 与 ELIGIBILITY invalidation，不是 canonical publication proof。CURRENT V6 缓存仅为有界进程内 L1（TTL、容量、GC），miss/expiry/failure 回到 strict DB reader 或 PENDING/DENY；Redis L2/MAC/shared-unit/session compatibility adapters 与 `astral-cache` 已退出当前软件合同，且不声称 Redis 跨实例等价行为。

本文将事实、缺口、明确历史和目标状态分开。源码链接是当前代码级证据，不能代替真实 DB、消息或部署验证。

## 1. 边界与术语

### 1.1 三类数据

| 名称 | 当前含义 | 典型表/接口 |
|---|---|---|
| source | 授权事实及其绑定关系 | `permission_rule`、`rule_set_entry`、`card_rule_set_ref`、授权账本 |
| legacy durable projection | 历史/迁移对照读模型，不属于当前正式授权路径 | `permission_rule_snapshot`、`rule_set_snapshot`、旧 snapshot/head schema |
| canonical durable projection | CURRENT V6 Rust-owned 发布证据链 | `authorization_grant_revision`、`authorization_delta_event`、`authorization_projection_manifest`、`authorization_projection_segment`、`authorization_projection_current` |
| projection/read gate | 允许正式读取已发布证据的版本与完整性证明 | current pointer、manifest/segment seal、generation、revoke-fence proof；保留的 source head/outbox 不作发布证明 |

旧 head/outbox 的保留用途仅限 source correlation、revoke/RuleSet initialization correlation 与 ELIGIBILITY invalidation；其持久存在不证明 canonical 授权已发布。`permission_rule_snapshot`、`rule_set_snapshot` 的历史定义、旧 worker 和旧状态语义只作明确标注的历史/迁移对照，不能理解为当前授权入口、兼容 evaluator 或 fallback。当前正式路径由 grant ledger、delta event 和 CURRENT V6 published-evidence reader 组成。

### 1.2 正式授权入口

CURRENT V6 的正式授权只有 `PolicyEngine::evaluate()`，其 required `RuleRepository` ports 无默认实现，生产授权消费 strict published evidence；缺失或无法证明时只允许 PENDING/DENY。当前不存在 capability-marker dispatch、可选 legacy evaluator、旧 L1/L2/L2.5 阶段或 `evaluate_realtime()` raw-source 授权/诊断 evaluator。历史文档中曾描述的 realtime/raw-source 对照不属于当前 API 或授权合同。管理模拟若启用，属于独立管理用途，不是正式授权入口，也不能回退生产 read gate。

正式 TrustGraph 权限中间件构造物理策略上下文后调用 `PolicyEngine::evaluate(&ctx, &repo)`；此调用路径的具体代码位置以当前源码为准。[`astral-trustgraph/src/api/permission_check.rs`](../../../astral-trustgraph/src/api/permission_check.rs)

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

当前 typed 单元测试覆盖 compiler contract、增量/全量等价、冲突分类、hash/version fence 和 factored shared layer；这些测试不等于数据库、缓存或消息基础设施验收。worker 的 pointer-moved 竞争采用有界同 lease replan：最多 3 次原地 replan，连同首次共最多 4 次 publication attempt；额度内不计 execution failure，耗尽后仅在一次 owned charged transition 有 durable Applied proof 时计一次失败。lease loss/UNKNOWN 不作额外失败记账，UNKNOWN 先对账。细节见 §3.1.1 与 §6.3。

生产 [`AuthorizationProjector`](../../../astral-trustgraph/src/service/authorization_projector.rs#L1-L25) 已消费 `authorization_delta_event`：事务外读取已证明的 ledger 并调用 `AuthorizationCompiler`，发布事务内重新验证 lease、lineage、revoke fence、generation、parent references 和 current-pointer CAS。发布成功的 durable proof 由 manifest/segment/current 与相应完成证据构成；当前没有 Redis L2 evidence push 作为读侧发布步骤。任何 lease/CAS 未知结果都停止后续 mutation 并要求对账。

当前没有把 compiler candidate 写入旧 `permission_rule_snapshot`/`rule_set_snapshot` 的生产接线，也没有以旧快照重建作为新链的 fallback。真实 MySQL/RabbitMQ 集成、既有数据 backfill/rehearsal 和正式切流仍需独立取证，本文不据此声明已完成部署或运行验收；CURRENT V6 evidence cache 仅为带 TTL、容量和清理边界的进程内 L1，不包含 Redis L2。

### 2.4 绑定层变更的编译语义决策（2026-08-28 正式决策）

实施计划草案中曾列有第五类 delta `BindingChange`（绑定层 BASE/OVERLAY 变更的独立增量语义）。**正式决策：不实现独立 `BindingChange` delta，绑定层变更统一走保守全量重建**——实现为 `FullRebuildReason::BindingImpact`：任何影响绑定层/来源层的 delta 在编译期被 `grant_requires_full_rebuild`/`grant_impact_reason` 判定后强制走 full oracle 重建，而不是作为独立增量 delta 推进。理由：绑定层变化可能改变同 key 多 provenance 的优先级语义，保守全量重建在正确性上无歧义，且绑定变更在真实负载中属低频事件，全量重建的性能代价可接受。该决策取代计划草案中的 `BindingChange` 条目；未来若需要绑定层增量语义，必须先扩展 `FullRebuildReason` 分类并重新审计优先级语义，不得在现有 delta 通道上私自扩展。

## 3. 当前事实：新授权投影器与 legacy writer-correlation 通道

### 3.1 `AuthorizationProjector` 的真实流程

当前生产授权投影由 [`AuthorizationProjector`](../../../astral-trustgraph/src/service/authorization_projector.rs#L1-L25) 消费 `authorization_delta_event`。每个事件的处理边界为：

1. 使用稳定 `event_id`/`operation_id` 和 run-scoped lease claim；
2. 在事务外严格重读 claimed event、published frontier、parent references 与完整 ledger，调用 `AuthorizationCompiler` 生成增量 candidate 或显式 full-rebuild oracle；
3. 在发布事务内重新校验 lease/token、lineage、revoke fence、generation、segment digest/seal 和 current pointer CAS；
4. 只有 manifest/segment/current 与 impact-plan durable 提交成功后，才把事件计为 published；不存在 Redis L2 evidence 推送步骤，授权完成仍以 CURRENT V6 durable proof 为准；
5. 确定性分歧通过 live-lease CAS 进入 `QUARANTINED`，未证明历史按 `Blocked` 有界退避，lease/CAS 未知结果停止后续 mutation 并要求对账。

该 worker 已在 TrustGraph `main` 接线，并且不写旧 snapshot 表、不消费旧 head/outbox 队列、不发布旧 refresh MQ、不执行旧 cache eviction。源码证据见 [`main.rs`](../../../astral-trustgraph/src/main.rs#L307-L349) 与 [`authorization_projector.rs`](../../../astral-trustgraph/src/service/authorization_projector.rs#L741-L847)。

### 3.1.1 聚合单执行者组合路径（WorkerOwned only；CURRENT V6）

CURRENT V6 只有 `WorkerOwned` 授权 projection execution protocol；旧 `ProjectionExecutionMode`/`ASTRAL_PROJECTION_EXECUTION_MODE`、`legacy-hybrid` selector、request-side claim/release 与 synchronous publisher execution surface 已退出当前软件合同。`TenantSerial` 与 `Partitioned` 是独立 scheduling topology，仍保留原默认值；本文件不改变其默认值或 ORG_SCOPE 的 default-off 状态。

只有 source COMMIT 已证明成功后，才将完整不可变 receipt batch 交付唯一 WorkerOwned owner。请求侧仅可只读观察 exact durable completion，预算 5 秒、25 ms 轮询、最多 64 个 event 与 50 个 distinct card scopes；超过边界的 batch 保持完整交给 worker，不截断。`operation_id` 可对应多个 contribution event，等待必须绑定完整事件批次；COMMIT UNKNOWN 不 dispatch，不得重放 source，须先对账。

同一 current pointer 的 worker paths 共用 aggregate lane、持久 epoch、fresh token 和单 active slot。publication generation 与 lane epoch 分离，事件 token 不能绕过 owner 发布。请求等待不 claim、compile、publish、release 或竞争 worker，亦不影响 worker lease/执行失败预算；等待超时不证明完成，完整 receipt 仍由唯一 worker 处理。

owned 发布事务还将规范化 impact item 集合与 plan、source generation、目标 manifest/digest 的 commitment 写入既有审计表，完成验证要求唯一且相符的 seal；不能从已删减的现存 item 反向补造证明。读取会重验当前指针与保留的连续 manifest/reference/segment 历史。完整保留的 `SUPERSEDED` manifest 和同事务 archive intent 可证明历史发布，但不是归档完成；archive intent 已成功却缺 terminal proof 时拒绝完成证据。ACK、bus admission、单一状态或最新 pointer 不能替代 exact completion proof。历史记录中的配置/模式选择仅供迁移审计，不是可切回的现行 selector。

pointer-moved 时，projector 在原 live lease 下最多进行 3 次原地 replan；计入首次执行后，同一 owned episode 最多有 4 次 publication attempt。额度内 replan 不消耗 durable execution-failure budget，也不增加新的 claim attempt。全部额度耗尽后，才通过一次 WorkerOwned owned-failure transition 计入一次执行失败并进入有界退避；只有该 transition 的 durable `Applied` proof 才能确认记账，`LeaseLost`/`Unknown` 不继续发起额外 mutation，Unknown 须先对账。源码定位：[`config.rs`](../../../astral-trustgraph/src/service/authorization_projector/config.rs#L21-L32)、[`worker.rs`](../../../astral-trustgraph/src/service/authorization_projector/worker.rs#L1126-L1302)、[`owned_worker.rs`](../../../astral-trustgraph/src/service/authorization_projector/owned_worker.rs#L12-L65)。

有界模型仅验证其显式状态空间；真实 SQL、同负载压力、进程内生产签名 HTTP 与跨节点部署分别验收。任一层通过都不能替代另一层，也不宣称所有负载下的全局最优。采用与回退须依 CURRENT V6 完整 bundle 的批准流程及规范 §15.5 / 迁移决策执行。

### 3.2 旧 `ProjectionWorker` 的保留边界

旧 [`ProjectionWorker`](../../../astral-trustgraph/src/service/projection_worker.rs#L1-L31) 仍由进程持有，但其当前行为已收敛为兼容 writer-correlation/ELIGIBILITY 通道：CARD/RULE_SET 事件只做终态 `mark_processed`，不重建 `permission_rule_snapshot` 或 `rule_set_snapshot`；ELIGIBILITY 只失效 `perm:card:active:{card_id}` 资格缓存，不推进已删除的旧 READY 状态列。它不是新授权投影器，也不是生产 strict gate 的完成证明。

因此，旧代码中的 `rebuild_card_snapshot_inner`、`rebuild_rule_set_snapshot`、`ProjectionAdvance` 和 `permission.refresh` 相关段落只能作为 legacy/迁移审计材料阅读。当前生产授权的 durable 完成证明来自新链的 current pointer、manifest/segment seal、generation 和 revoke-fence proof；不能从旧 head 的 `projected_generation`/`projection_status` 推导。

**历史决策记录（读链切换批次 2/3）**：当时选择保留 ELIGIBILITY head/outbox 与 `ProjectionWorker` 的 ELIGIBILITY 分支，使资格缓存失效不依附旧 CARD/RULE_SET snapshot 链；反对把资格 invalidation 合并到 CARD manifest，也未采用提交后同步失效并推进 READY 的 worker 化替代方案。历史讨论曾以 Chat realtime 对 ELIGIBILITY READY 的依赖、PolicyEngine 资格 cache 三版本栅栏、Redis 故障 TTL 窗口及方案 a/c' 为理由。该段仅保留当时决策依据：当前资格缓存已为有界进程内边界，Redis 失效窗口/adapter、旧 READY、旧 Chat 路径都不能据此推断为 CURRENT V6 合同；当前 topology/defaults 与 ORG_SCOPE default-off 不因本文改变。

## 4. 当前正式授权入口与历史对照边界（CURRENT V6）

### 4.1 正式 `PolicyEngine::evaluate()`

正式授权唯一入口为 `PolicyEngine::evaluate()`，经过 `RuleRepository` 四个无默认实现 required ports：`check_card_active`、`is_active_global_admin`、`load_published_card_authorization`、`load_org_authorization`。AUTHN/CARD_CONTEXT 与 resource/action/ownership 校验后进入 CURRENT V6 published-evidence gate；校验 current pointer、manifest/segment seal、scope、lineage、generation/dependency 与 revoke fence，并在 ALLOW 前复读。任何证据缺失、错误、scope 不符或复读漂移均 PENDING/DENY。不存在 capability-marker dispatch、legacy evaluator、旧 L1/L2/L2.5 阶段、realtime/raw-source evaluator 或 snapshot/cache fallback。

### 4.2 source fallback 禁止边界

正式读门不因投影 pending、缺失或缓存 miss 而读取 raw source 产生 ALLOW。source mutation 与已发布证据异步收敛；缺失/未知状态保持 PENDING/DENY，所有 completion 必须由 CURRENT V6 durable proof 决定。旧 snapshot/head、compatibility cache 与旧 `Ok(None)` evaluator 语义均不是当前 compatibility path。

### 4.3 历史 realtime evaluator 与模拟记录

旧文档曾描述 `evaluate_realtime()` raw-source consistency checker、旧 L1/L2 快照读侧与 simulation repository。上述记录仅作为历史源码/设计材料，不是当前 `PolicyEngine` API 或 formal read route；管理模拟若在其他控制面明确保留，也不构成授权读路径。不得将旧 realtime/simulation 结果用于正式 ALLOW。

### 4.4 边界

CURRENT V6 source/compiler/admission/wire 与 evidence read gate 是同一完整 bundle。正式 evaluator contract 不定义单独 realtime diagnosis gate。数据库、消息、迁移、部署、恢复或实际流量状态须独立取证；本文没有执行真实 DB/MQ/integration/deployment 验收。

## 5. 当前事实：published evidence、缓存与版本拒绝

### 5.1 CURRENT V6 evidence L1 cache

生产共享权限查询以 `load_published_card_authorization` 为唯一授权读端口。当前 cache 仅为有界进程内 L1，可缓存已验证的 current/manifest/segment evidence；entry 绑定完整 scope、CURRENT V6 stamp、generation/dependency/fence 与 content integrity，并受 TTL、容量和 GC 约束。miss、expiry、malformed payload、失配或 cache unavailable 只回 strict DB reader 或 PENDING/DENY；缓存不是 durable proof，也不提供跨实例共享语义。旧 `perm:refs:{card_id}` 等 cache-aside 属历史/迁移材料，不是当前 compatibility reader。代码入口：[`astral-db/src/evidence_cache.rs`](../../../astral-db/src/evidence_cache.rs)、[`astral-db/src/authorization_projection_repository.rs`](../../../astral-db/src/authorization_projection_repository.rs)。

### 5.2 ELIGIBILITY qualification cache

ELIGIBILITY 是独立物理资格边界，不是规则授权 evidence，也不等同旧 CARD snapshot。当前 qualification cache/mirror 仅有界进程内运行；miss、失配、过期或不可用回到 strict authority SQL/安全拒绝。资格的自然到期依据 identity/user-card authority facts 处理，资格 cache 的行为不构成规则 `valid_to` 的授权投影证明。详见 [`astral-db/src/eligibility.rs`](../../../astral-db/src/eligibility.rs) 与 [`astral-common/src/session_projection_store.rs`](../../../astral-common/src/session_projection_store.rs) 的 session-only 分离合同。

### 5.3 Redis 与 `astral-cache` 的历史边界

旧 Redis evidence/session adapters、MAC/shared-unit protocol 与 `astral-cache::CachedRuleRepository` 已从 CURRENT V6 软件合同退役；其旧 key、TTL、故障语义和 Redis fallback 只可引用为历史实现证据，不是当前 cache behavior、compatibility surface 或恢复路径。文档保留这些历史名词不代表 crate/runtime、Redis service/profile 或外部环境仍存在，也不证明外部清理已执行。当前认证 durable facts 读取 MySQL；session mirror 仅为 bounded in-process option。

## 6. 当前边界：退役投影接口、有效期、SoD 与 worker 生命周期

### 6.1 退役的兼容 cache / direct-rebuild surface

旧 `PermissionSideEffects` / `rebuild_card_snapshot` / `rebuild_rule_set_snapshot` 设计不再是当前实现接口；`astral-trustgraph/src/service/side_effect.rs` 已从当前 checkout 移除。当前 [`api/side_effects.rs`](../../../astral-trustgraph/src/api/side_effects.rs) 的 durable side effect 是在 source commit 后投递已有的 session-revocation intent，不负责授权快照重建、授权投影申请或 cache eviction。旧方法名和旧快照 SQL 只保留为历史/迁移证据，不能称为当前 compatibility API、test repository path 或正式投影路径。

当前 direct-rule source transaction 由 [`rule_repository.rs`](../../../astral-trustgraph/src/repository/rule_repository.rs) 负责；其他授权 source owner 按其聚合合同写入 typed grant revision/delta 与审计关联。只有 COMMIT 已证明后才交付完整不可变 receipt batch，由唯一 `AuthorizationProjector` 处理。补偿/恢复不能直接写旧 snapshot 来制造授权完成；未知结果须先对账，再由现有稳定 operation/event identity、lease、lineage、fence、generation 和 current-pointer CAS 路径收敛。`AuthorizationArchiveWorker` 先完成整链 proof，才把 archive intent 标记完成。

CURRENT V6 evidence cache 是带 TTL、容量和 GC 边界的进程内 L1；miss、过期、时钟失配或读取失败只回 strict published reader 或 PENDING/DENY。ELIGIBILITY 资格 cache 是独立的 bounded local qualification read 面，失配回权威资格 SQL 或拒绝。Redis eviction/failure、旧 cache-aside 与旧 snapshot 均不是当前运行副作用或授权回退合同。

### 6.2 CURRENT V6 grant 有效期与 projection 新鲜度

历史旧 snapshot rebuild SQL 曾在构建时使用 `UTC_TIMESTAMP()` 过滤 `valid_from/valid_to`，只将当时有效且可预计算的规则写入 snapshot；该历史行为不是当前授权合同。旧 rebuild SQL 的历史来源见迁移/代码记录；当前 `api/side_effects.rs` 不再提供这些 rebuild handlers。

**当前读时语义**：CURRENT V6 strict published-evidence reader 对每个 grant 使用该次读取的统一 UTC 时间检查 `not_before`（含）与 `expires_at`（不含），把未生效或已过期贡献排除在 `effective_grants` 外；`PolicyEngine` matcher 也在评估时检查 grant validity。缓存命中前会按当前时间重验窗口；时间边界翻转时 miss 并回 strict reader。因此，本文件不把规则自然到期描述为依赖旧 realtime evaluator、旧快照重建、Redis TTL 或隐式 source fallback 才能拒绝过期 grant。

自然到期本身仍不会新增 source mutation、delta event、publication generation 或单独 expiry event；因此 projection/audit lifecycle 不会仅因 wall-clock 到期而推进。若业务要求到期事件、投影版本推进或单独的到期审计，应另行定义受控调度/事件合同。身份卡、用户卡资格的自然到期由资格服务按权威时间窗在读时检查；这与 RuleSet grant 的 publication generation 是不同语义。

### 6.3 Worker 超时与生命周期

**当前代码边界**：`AuthorizationProjector` 有事件级 deadline、bounded attempts、lease/token fence、pointer-moved replan、Blocked/Quarantine/Unknown 分类；`AuthorizationArchiveWorker` 有 cancellation 检查、有限 claim、proof-before-complete、过期 lease recovery 和 bounded join。pointer-moved 在同一 live lease 下最多 3 次原地 replan（加首次执行共最多 4 次 publication attempt）；额度内不计 durable execution failure，额度耗尽后只经一次 owned charged transition 计一次失败，Unknown/Lost lease 不补记或盲目重试。TrustGraph `main` 持有 projection/archive worker 句柄并按既定顺序 cancel/join；这些代码级事实不等于真实基础设施或故障注入验收已通过。证据：[`config.rs`](../../../astral-trustgraph/src/service/authorization_projector/config.rs#L21-L32)、[`worker.rs`](../../../astral-trustgraph/src/service/authorization_projector/worker.rs#L1126-L1302)、[`owned_worker.rs`](../../../astral-trustgraph/src/service/authorization_projector/owned_worker.rs#L12-L65)、[`authorization_archive_worker.rs`](../../../astral-trustgraph/src/service/authorization_archive_worker.rs#L577-L735)、[`main.rs`](../../../astral-trustgraph/src/main.rs#L307-L365)。

**保留 head/outbox 边界**：旧 `ProjectionWorker` 只负责保留的 writer-correlation/ELIGIBILITY invalidation 通道；CARD/RULE_SET 不重建 legacy snapshot、不推进旧 READY，也不构成 canonical projector 的生命周期合同。未知结果必须先对账，不能从旧 worker mark/ACK 推导 canonical completion。

**尚未由本文件证明**：当前 MySQL 与适用 MQ transport 的组合故障、进程重启、租约接管和 shutdown 的真实集成证据仍未执行；Redis 不属于 CURRENT V6 authorization runtime dependency。typed/mock 或源码形状检查不能单独宣布生产恢复闭环。

### 6.4 Direct-grant SoD：early validation 与事务内重查

直接授权 create/update 在 `RuleWriteService` 先执行 mandatory published-only SoD validator；source repository 在同一个 source transaction 内、INSERT/UPDATE 之前无条件调用 `astral_db::check_grant_sod_conflict_in_tx` 再检查。交易内检查锁定 active/current `user_card`，拒绝该卡级或 aggregate-wide 的任何未完成 ADD/UPDATE/REMOVE/REVOKE contribution，在同一事务 strict 读取 published evidence，并以 `FOR SHARE` 读取有界 ACTIVE STATIC/DYNAMIC policy。冲突、pending contribution、证据缺失、策略读取失败或 deadline 超时均 fail-closed。相关源码：[`rule_write_service.rs`](../../../astral-trustgraph/src/service/rule_write_service.rs)、[`rule_repository.rs`](../../../astral-trustgraph/src/repository/rule_repository.rs)、[`sod_check.rs`](../../../astral-db/src/sod_check.rs)。

交易内重查目前有源码调用链证据；真实 MySQL 并发、锁序、死锁与恢复验证未执行，不能宣称已完成 real-DB acceptance。即使 early validator 成功，也不能替代 transaction-bound recheck。

## 7. 当前已有的安全门

当前实现已具备下列重要防护，但它们不等于真实集成或正式切流已完成：

1. source mutation 可在同一事务落 grant revision/delta event；head/outbox 仅用于 source correlation、revoke/RuleSet initialization correlation 与 ELIGIBILITY invalidation，不是 canonical 发布证明。
2. `AuthorizationProjector` 对新 delta 事件使用稳定 id、lease、lineage、revoke fence、generation、segment seal 和 current-pointer CAS；确定性 divergence 进入 quarantine，未证明历史按 Blocked 退避，未知结果先对账。
3. `AuthorizationArchiveWorker` 只在整条 superseded manifest 链 proof 成功后记录 durable archive proof 并完成 intent；失败不伪造完成。
4. 生产 `SqlxRuleRepository` strict reader 只消费 CURRENT V6 published evidence；current/manifest/segment 证明不足、scope 不符或 DB/L1 证据读取失败均不扩大授权。Redis L2/MAC/shared-unit 与 `astral-cache` 已退休，不属于当前 fallback。
5. ELIGIBILITY 资格缓存独立绑定物理双卡上下文和版本；失配回权威 SQL，不能作为规则授权 fallback。
6. 旧 CARD/RULE_SET worker 只终结保留的 correlation 事件，ELIGIBILITY 分支只做资格缓存失效；旧 snapshot/head/refresh 不是 canonical 授权发布链。

## 8. 迁移、回填与发布/回滚边界

历史 snapshot/head repair 与 decommission migrations 只描述旧 schema 和迁移工具，不能证明 canonical 授权已经发布。`20260825000002_incremental_projection_archive.sql` 是 canonical grant/delta/manifest/segment/current 的 creator-only migration，不负责既有数据 backfill；`20260827000001_authorization_projection_lineage_fence.sql` 增加 lineage/revoke-fence proof 字段；`20260827000002_legacy_snapshot_tables_decommission.sql` 是带前置条件的 standby script。迁移文件存在、代码路径退出、目标库已应用、旧表已 DROP 和既有账本已 rehearsal 不是同一事实。保留的 source head/outbox 仅承担 source correlation、revoke/RuleSet initialization correlation 与 ELIGIBILITY invalidation；它们不是发布证明，也不意味着发生 DROP 或 migration。

任何未来获批的环境 adoption 都须在隔离/预演环境分别核对 schema/migration postcondition、grant ledger backfill、current pointer 的 `revoke_fence_proven`、manifest/segment seal、lineage、projector replay、archive proof、evidence cache 和审计关联。升级或回滚须按 CURRENT V6 完整 bundle 设计与执行，不得删除 canonical current、清空证明闩、恢复未证明旧 snapshot 或用旧 head READY 制造授权放行；任何 lease/CAS/commit 未知结果都先对账。实际 migration、backfill、部署或回滚均未由本文记载为已执行。

## 9. 历史目标状态：安全的增量编译设计

> **历史设计/验证提案（2026-08-22/26；已被 CURRENT V6 §2–§8 取代）**：本节至 §11 保留旧目标、术语和验证清单供迁移/审计追溯，不是 CURRENT V6 的实施计划、待办、API、依赖或验收清单。与 V6 冲突的旧 snapshot/READY、Redis cache-aside、L1/L2/L2.5、`evaluate_realtime()`、Arbiter 或兼容 repository 描述均属历史，不代表当前实现面；CURRENT V6 的实际合同以本文 §2–§8 和 `Docs/规范/Rust后端编码规范_V1.0.md` §§15.5–15.8 为准。下面历史段落中的测试覆盖、切流、backfill 与 migration 状态未经本次运行或环境核验，不能据此宣称已完成或仍是当前 TODO。

历史方案草案原计划在落地前另行安排代码、DDL、消息、迁移、回滚和测试变更，并遵循 Rust 工程规范中“契约由文档驱动、每次改动同步相关文档”的要求。[`Rust后端编码规范_V1.0.md#L9-L15`](../../../Docs/规范/Rust后端编码规范_V1.0.md#L9-L15)

**历史记录（2026-08-26，非当前状态）**：当时将 `AuthorizationCompiler` 内核、新表链持久化原语与 projector/archive worker 记作朝该目标的第一批切片，并把旧 `SnapshotCompiler` 的端到端接线、backfill/rehearsal、缓存/摘要读侧迁移和真实集成验收列为未完成事项。该状态快照已被 CURRENT V6 的当前事实段落取代；不能将其中旧 evaluator、旧缓存或 read-side migration 作为当前待办。

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

### 10. 历史授权边界提案（已由 CURRENT V6 取代）

以下 pipeline 是早期目标态对照；当前授权链以本文 §2–§4 的 CURRENT V6 formal path 为准，不表示旧 realtime/simulation API 仍存在。

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

## 11. 历史验收与证据提案（非 CURRENT V6 待办）

下表保留旧方案的测试类别提案，表中 Redis/cache-aside、legacy staged evaluator、realtime/simulation 与旧 snapshot 项不属于 CURRENT V6 的当前测试接口或运行时依赖；不可据此推断覆盖已执行或仍欠缺。当前验证门由仓库根 `AGENTS.md`、CURRENT V6 规范和具体测试 profile 决定；本文件未运行本次 Cargo、DB/MQ integration、migration、deployment 或 traffic-cutover 验收。

| 类别 | 最低验收点 |
|---|---|
| 纯编译 | stable ID 增删改、乱序、重复 event、越界/未知 ID、阈值和全量 wildcard |
| 语义等价 | candidate 与 full rebuild 的 snapshot rows、winner、hash、compiler version 一致 |
| durable CAS | source/projected generation 竞争、CAS 冲突、worker 重试、AlreadyCurrent、Superseded |
| gate | current pointer 缺失、PENDING、generation gap、revoke fence/证明闩推进、stale ALLOW 变 PENDING |
| cache-aside | Redis 命中、miss、版本不匹配、Redis 故障 DB fallback、旧/legacy payload 拒绝 |
| 时间（历史提案） | valid_from/valid_to 读时边界、natural expiry 与旧 proposed time-event/补偿策略；不表示 CURRENT V6 需要 realtime 兜底 |
| 生命周期 | 单事件超时、取消、租约续期/丢失、shutdown join、MQ publish/processed 失败重放 |
| 安全边界 | 生产 formal evaluate 只读 published evidence；legacy/test 的 L1/L2 才读取旧投影，L2.5 仅在旧 CARD gate 通过后查询委托源；realtime/simulation 必须保持显式隔离；无 projection-miss 到 source ALLOW fallback |

**历史证据注记**：当时记录的投影门禁、代际围栏、缓存版本校验与 stale-ALLOW 测试描述不作为 CURRENT V6 的当前测试覆盖或运行结果声明。本任务未执行测试，也未以历史源码行号证明此次最终快照的覆盖。

相关架构基线：[物理双卡权限链路评估与设计_V1.0.md](物理双卡权限链路评估与设计_V1.0.md)；[Rust 后端编码规范 V1.0](../../../Docs/规范/Rust后端编码规范_V1.0.md)；全栈工程规范。
