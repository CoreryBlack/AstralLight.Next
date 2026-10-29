# Rust 权限投影快照与版本栅栏 V1.0

> 版本：V1.0
> 原始版本日期：2026-09-09；CURRENT V6 现状补记：2026-10-28
> 适用范围：`AstralLight-Rust` 权限 source mutation、canonical durable projection、legacy 快照兼容面、strict published-evidence 读门禁与审计旁路。
> 文档性质：**当前态事实、审计缺口与目标决策对照**。目标决策不表示已经实施。
> 证据口径：代码级结论以文中相对路径与函数/行号为准；未做运行时故障注入的结论标注为代码级观察。

## 1. 阅读约定与关联文档

本文使用以下标记：

- **事实**：截至本文日期可由 Rust 源码或迁移/schema 直接核验的当前行为。
- **缺口**：前次审计或本次源代码核对识别出的未闭合边界；不等同于已经修复。
- **目标决策**：2026-08-22 记录的架构决策或待实施约束；不能回写为当前实现。

权威关联资料：

- [Rust 架构模型设计修正记录](./Rust架构模型设计修正记录.md)：问题陈述、核实记录与修正状态。
- [物理双卡权限链路评估与设计](./物理双卡权限链路评估与设计_V1.0.md)：双卡事实线路、投影门禁与残余边界。
- [物理双卡权限链路设计](./物理双卡权限链路设计_V1.0.md)：目标态双卡与投影不变式。
- [Rust 迁移 Java 等价适配状态](../../迁移/Rust迁移Java等价适配状态_2026-08-05.md)：投影、精确匹配、补偿与尚未验证项。
- [Rust 后端编码规范](../../规范/Rust后端编码规范_V1.0.md)：crate owner、错误传播与分层约束。
- [技术专题解析与架构取舍（2026-10-25）](../../技术专题解析与架构取舍_2026-10-25.md)：本报告对 canonical grant ledger/published evidence 与 legacy snapshot 的架构职责作跨专题说明；不替代本文件的源码和 migration 证据。
- Structurizr 维护说明：架构 DSL、动态视图与代码事实的维护规则。

相关动态视图：

- 权限写入投影链路
- 权限变更投影排查图
- 授权决策链路
- 授权决策排查图
- Structurizr workspace DSL

## 2. 范围与核心结论

### 2.1 范围

本文以 CURRENT V6 canonical publication 与 strict published-evidence read gate 为当前授权链；旧 snapshot/rebuild、旧缓存与旧 refresh 消息只作历史/迁移材料，不作为当前运行合同。source mutation 的 canonical 编译/发布、保留 head/outbox 的有限 correlation/ELIGIBILITY 职责、版本栅栏和审计关联分别说明。身份卡本身的显式到期 mutation 另列为缺口，不把自然到期误写成已有的 `IDENTITY` 投影通道。

### 2.2 当前态摘要

当前授权链分为两个明确边界：

1. **CURRENT V6 canonical Rust-owned 链**：`authorization_grant_revision` → `authorization_delta_event` → `authorization_projection_manifest`/`authorization_projection_segment` → `authorization_projection_current`，由 `AuthorizationProjector` 编译并以 pointer/manifest/segment seal 证明发布；`AuthorizationArchiveWorker` 对 superseded parent 生成 DB 内归档 proof，proof 先于 `SUCCEEDED`。CURRENT V6 的 compiler、admission/read gate、publication、segment、archive/completion、invalidation、snapshot 与 wire 合同属于同一不可分割授权 bundle。
2. **保留的 source-correlation/资格边界**：旧 `authorization_projection_head/outbox` 与相关 compatibility 状态只用于 source correlation、revoke / RuleSet 初始化关联和 ELIGIBILITY invalidation。不得将它们视为 canonical 发布证明，也不得据此推断数据库表已经删除、迁移已执行或环境已部署。旧 snapshot/reader 不属于当前授权路径，历史定义与 schema 只作为已明确标注的历史/迁移证据。

`PolicyEngine::evaluate()` 当前唯一正式授权入口，其 `RuleRepository` 由四个无默认实现的 required read port 组成：`check_card_active`、`is_active_global_admin`、`load_published_card_authorization`、`load_org_authorization`。身份、目标 ownership、GlobalAdmin（适用时）、ORG_SCOPE（受其当前启用状态约束）及完整 CURRENT V6 published-evidence gates 均 fail-closed；普通卡授权读取已发布 evidence，校验 scope、manifest/segment seal、lineage、generation 与 revoke-fence proof，并在 ALLOW 前复读。任何缺失、冲突、读取错误或无法证明都只能 PENDING/DENY。没有 capability marker dispatch、旧 L1/L2/L2.5 evaluator、raw/realtime source 授权路径或 fallback。

canonical source mutation / projection 的代码级流程如下：

```text
source mutation + audit correlation
  -> 同一 SQL transaction 写 grant revision + typed delta event（稳定 event/operation id）
  -> COMMIT 被证明成功后，完整 immutable receipt batch 交给唯一 WorkerOwned projector
  -> worker 按 aggregate ownership/lease/fence 读取已证明 frontier 与完整 ledger，AuthorizationCompiler 生成 candidate/full oracle
  -> 发布事务重新验证 lease、lineage、fence、generation、segment seal
  -> impact plan + manifest/segment + current pointer CAS 同事务提交
  -> superseded parent 追加 archive intent；ArchiveWorker proof 后才将 intent SUCCEEDED
  -> PolicyEngine::evaluate() 的 strict CURRENT V6 published-evidence read
```

请求侧只允许对 COMMIT 已证明交付的完整 receipt batch 作只读 exact-completion observation wait：总预算 5 秒、25 ms 轮询、最多 64 个事件和 50 个 distinct card scopes；超界仍把完整 batch 交给 worker，不截断。请求侧不得 claim、compile、publish、release 或竞争 worker；timeout、ACK、LocalBus admission、单一 `SUCCEEDED` 状态或 latest pointer 都不是完成证明，未证明结果继续由 worker 持有并异步收敛。

source transaction 只写 source、durable correlation/outbox 与 audit correlation；不执行网络、MQ、缓存或投影构建。当前 evidence L1 是有界进程内缓存，有 TTL、容量与 GC；miss/failure 回到 strict DB reader 或 PENDING/DENY，不等价替代 Redis 跨实例行为。`astral-cache` 与 Redis L2/MAC/shared-unit adapter 不属于当前软件合同。真实数据库、消息、迁移、集成和部署状态须分别取得证据；本节不宣称任何表已删除或真实环境已切流。

**事实（2026-08-26 增补：新 Rust-owned canonical 投影链切片；strict gate 已接线代码层，真实集成与部署验收未完成）**：已批准的“版本化可变热状态 + 异步旧版本归档”模型已有代码与 schema artifact。creator-only 迁移 [`20260825000002_incremental_projection_archive.sql`](../../../astral-db/migrations/20260825000002_incremental_projection_archive.sql) 定义 `authorization_grant_revision`（append-only revision ledger，含 tombstone）、`authorization_delta_event`（typed delta 队列，携带 `before_image_json`/`before_digest` 与 CAS/lease 状态）、`authorization_impact_plan(_item)`、manifest、内容寻址不可变 segment（segment-local seal）、manifest-segment references、current pointer、archive outbox 与 archive manifest；[`20260827000001_authorization_projection_lineage_fence.sql`](../../../astral-db/migrations/20260827000001_authorization_projection_lineage_fence.sql) 增加 lineage 与 revoke-fence proof，0 为“未证明历史”哨兵，任何人不得从 0 推断放宽授权。发布通过 current pointer affected-rows-exactly-one CAS；archive worker 重读旧链、重算摘要并写 durable 归档证明后才完成。授权账本为 ALLOW-only：普通 DENY 不持久化为正授权 grant，撤销以 tombstone/fence 表达；RULE_SET 贡献带 BASE/OVERLAY 标签，DELEGATION contribution 的 layer 为 None。TrustGraph 的 canonical projector/archive worker 已接线，projector 是 delta 队列唯一授权消费者。

**事实（CURRENT V6 source/API 边界）**：生产 `PolicyEngine::evaluate()` 只使用四个 required `RuleRepository` ports：`check_card_active`、`is_active_global_admin`、`load_published_card_authorization`、`load_org_authorization`；没有 capability marker、legacy evaluator 或 fallback。canonical delta dispatch 仅为 source COMMIT 被证明后的完整不可变 receipt batch，执行 ownership 属唯一 `WorkerOwned` projector。请求侧只可进行 exact historical completion proof 的只读等待，限制 5 秒、25 ms poll、最多 64 events 与 50 distinct card scopes；超限 batch 保持完整并由 worker 处理，绝不截断，超时不表示完成。请求不能 claim、compile、publish、release 或竞争 worker。旧 head/outbox 仅保留 source correlation、revoke/RuleSet initialization correlation 与 ELIGIBILITY invalidation 责任。

**事实（CURRENT V6 strict read/cache 边界）**：普通卡授权严格读取 CURRENT V6 published evidence；缺 current、proof 未就绪/不完整、格式或 scope 不符、generation/lineage/fence/hash/seal 不一致、DB 读取错误或 ALLOW 前复读漂移都只能 PENDING/DENY。正式授权不存在 legacy L1/L2/L2.5、raw-source 或 realtime evaluator。CURRENT V6 只保留有界进程内 L1（TTL、容量、GC）；miss/expiry/malformed/failure 回 strict DB reader 或 PENDING/DENY。Redis L2/MAC/shared-unit/session compatibility adapters 与 `astral-cache` 已退出当前软件合同，不声称等价替代 Redis 跨实例表现。ORM/code artifact 不证明 schema 已部署、旧表已 DROP、backfill/rehearsal 已完成、真实 MySQL/MQ 集成或正式流量切换。

### 2.3 历史 v3 代际封存 artifact 与 CURRENT V6 edition（2026-10-27/28）

2026-10-27 的 v3 是历史代际封存请求及其不可变 schema artifact，不是当前授权 release number。当前授权 edition 为 V6，由共享 `astral-types/src/edition.rs` 的单一 `authorization_edition!(6)` 定义；manifest digest/seal、compiler、segment semantic/dependency、archive/completion、四类 invalidation、ORG_SCOPE publication、snapshot schema/payload 与 wire 合同均随该 edition 成套派生。Redis L2/MAC/shared-unit 和 `astral-cache` 已退出当前合同，不应描述为 V6 内容或兼容层。具体合同以[规范 §15.6 的历史锚点](../../规范/Rust后端编码规范_V1.0.md#156-授权代际-v3-封存合同2026-10-27)和 CURRENT V6 的[规范 §15.7](../../规范/Rust后端编码规范_V1.0.md#157-规则集完整结构与轻量发布栅栏标准2026-10-28)为准。V6 是 authorization edition；不得据此重编号通用 MQ envelope schema、JWT claim/version 或 HTTP v1。

`sealed_at` 记录候选首次成功持久化封存时间；重试按 aggregate＋target generation 找到并验证同一候选，复用存储时间，COMMIT 未知先对账。服务器 NTP 校时后应用读取系统 UTC，编译器仍无 IO；时间不取代 generation、CAS、lease 或撤销栅栏，也不单独证明发布者和 source mutation 合法。CURRENT V6 的 digest/seal/compiler、segment semantic/dependency、archive/completion domain 均由共享 edition 宏派生，不能由调用方另造数字或字符串。

内存、admission/read gates、父代/恢复、归档、completion、invalidation、wire 与快照必须统一核验 CURRENT V6。快照 frame/schema 与授权 payload 均只接受 CURRENT V6，先重算完整内容证据，再与同一 durable 读取事务取得的 pointer＋stamp＋最终摘要对牌；文件自洽不能代替 durable current 证明。旧 V1/V2 快照、旧 v3 seal 或缺少 CURRENT V6 edition 的数据拒绝，不补造时间、不原地重标。MQ 失效消息只传播 metadata 并触发严格重读，四类 invalidation event family 全部属于 V6 bundle；generic envelope schema version 不随 authorization edition 重新编号。

新迁移 `20261027000001_authorization_projection_manifest_v3.sql` 及其历史 SQL/checksum、migration ID 和文件字节保持不变；它只提供历史 v3 schema artifact。当前 schema gate/runtime 只接受共享 edition 对应的 CURRENT V6 seal/digest/compiler/domain；现有 v3 rows 或旧开发 manifest 缺少 V6 证明时保持 BLOCKED，必须通过另行批准的 derived-state rebuild 从 source/ledger、撤销和审计事实重建，不能自动重写或重置 generation。运行时不自动 DDL，数据重建/真实迁移/部署另行批准，操作边界见[迁移决策 §2.5](../../迁移/Rust后端迁移架构决策_V1.0.md#25-仅-v3-的代际封存切换2026-10-27)。本节登记源码结构，不宣称真实 MySQL、崩溃恢复或多节点验收已完成。

### 2.4 完整规则集与轻量发布身份（2026-10-28）

规则集 source 由本体、条目和卡片绑定组成；生产读视图采用完整源模型，命令只接受显式允许的可变字段。具体字段、UTC 表达、公开兼容面及写入拒绝规则统一见[规范 §15.7](../../规范/Rust后端编码规范_V1.0.md#157-规则集完整结构与轻量发布栅栏标准2026-10-28)，不以旧简化 `RuleSet` 结构冒充实际 schema。

发布后拦截与传播使用 `PublicationStamp { generation, manifest_digest_hex, seal }`，seal 当前必须为 V6 edition。它不携带规则条目，scope 由外层 tenant/card/aggregate identity 持有；完整内容仍在 references/segments。发布摘要、失效 metadata、缓存身份和快照 frontier/token 统一比较版本、最终 hash 和封存时间；同代分歧不能凭较新时间覆盖。source pending、lease、ELIGIBILITY 和进程内 token 不是 publication，不制造封存证明。

失效事件可标记它观察并将失效的已提交发布基线，该 stamp 不证明同事务 source mutation 已物化。读取必须继续检查 pending/revoke fence 与完成证明，不能把消息到达、ACK 或 baseline stamp 当成新授权。CURRENT V6 wire/domain 与本地 snapshot schema/payload 是同一切换单元；旧消息/文件拒绝而非补造 hash/time、自动协商或降级。真实数据库、消息和切换验收仍须独立证据。

### 2.5 Direct grant 的 SoD 检查边界

enabled `MANUAL` 直接授权 create/update 均由 source repository 在 mutation transaction 内、INSERT/UPDATE 之前无条件调用 `astral_db::check_grant_sod_conflict_in_tx`；CREATE 另保留显式注入的 published-only early validator。事务内锁定 active/current 卡并核对 source-rule/card/fresh tenant、user/domain，阻断卡级与 NULL-card aggregate-wide 未完成贡献，strict 读取 evidence 与有界 ACTIVE policy。UPDATE 须证明唯一 exact published before-image，只从 STATIC held grants 排除该项稳定 `GrantId`，其余 grant 与全部 DYNAMIC 检查保留；事实不足、pending、错误或 deadline 超时均拒绝。完整合同以 [Rust 后端编码规范 §15.4](../../规范/Rust后端编码规范_V1.0.md#154-单机内存读写生命周期sod-与审计边界) 为准。

这说明 source-code call chain 中已经存在交易内 SoD recheck；其 MySQL 锁序、并发阻塞/deadlock 与恢复语义未在真实数据库上验证，不得声明 real-DB concurrency 验收已完成。入口见 [`rule_write_service.rs`](../../../astral-trustgraph/src/service/rule_write_service.rs)、[`rule_repository.rs`](../../../astral-trustgraph/src/repository/rule_repository.rs) 与 [`sod_check.rs`](../../../astral-db/src/sod_check.rs)。

### 2.6 CURRENT V6 grant validity window

canonical published-evidence reader 按每次读取的统一 UTC 时间检查 grant 的 validity：`not_before` 含边界，`expires_at` 不含边界；未生效或过期 contribution 不进入 `effective_grants`，正式 matcher 也在评估时复核 validity。进程内 evidence L1 命中还会以当前时钟重验窗口翻转；miss 时严格回源。因此，不应把“formal evaluator 完全不检查 `valid_to`”或“必须依靠旧 realtime/source SQL 才能拒绝过期授权”写成 CURRENT V6 事实。

自然 wall-clock 到期本身不产生新的 source mutation、delta event 或 publication generation；它会影响读时 effective set，但不自动推进 projection/audit lifecycle。若需要独立 expiry event、代际推进或到期审计，须另立受控合同。实现复核入口：[`authorization_projection_repository.rs`](../../../astral-db/src/authorization_projection_repository.rs#L4682-L4769)、[`published.rs`](../../../policy-engine/src/engine/published.rs#L640-L705)、[`evidence_cache.rs`](../../../astral-db/src/evidence_cache.rs#L34-L43)。

## 3. Source mutation 与 legacy writer-correlation 通道

本节记录仍存在于兼容代码和迁移材料中的旧 `authorization_projection_head/outbox` 写侧形状。它可以承载历史 writer-correlation、ELIGIBILITY 资格缓存失效所需的事件以及迁移/对账信息，但不再证明 CARD/RULE_SET 的生产授权已经发布。生产授权发布只由 §2.2 的 grant ledger、delta event、manifest/segment/current 链证明。

### 3.1 事务边界

**事实**：`append_projection_event_in_tx` 在调用方已有 transaction 中：

1. 按 `aggregate_type + aggregate_id FOR UPDATE` 读取 head；
2. `source_generation` 递增，首事件从 1 开始；
3. 只有事件类型为 `REVOKE` 时递增 `revoke_fence`；
4. 更新或插入 head 为 `PENDING`；
5. 插入 outbox `PENDING`，并令 `sequence_number = source_generation`。

实现证据：[`astral-db/src/projection.rs:22-45`](../../../astral-db/src/projection.rs#L22-L45)、[`append_projection_event_in_tx:79-149`](../../../astral-db/src/projection.rs#L79-L149)。

**事实**：数据库约束为：head 对 `(aggregate_type, aggregate_id)` 唯一；outbox 对 `event_id` 唯一，并对 `(aggregate_type, aggregate_id, source_generation, sequence_number)` 唯一。见 [`20260729000003_authorization_projection.sql:4-50`](../../../astral-db/migrations/20260729000003_authorization_projection.sql#L4-L50)。这保证同一聚合/代次/序列不会因重复调用形成相同 durable 事件，但不等于快照行本身有唯一约束。

### 3.2 当前已覆盖的 CARD 与 ELIGIBILITY mutation

**事实**：`user_card` 创建在同一 transaction 中追加 CARD 与 ELIGIBILITY 事件；状态更新先追加 CARD，若状态字段影响资格，再追加 ELIGIBILITY；删除级联清理 `permission_rule`、`permission_rule_snapshot`、`card_rule_set_ref` 后追加两类事件；恢复和绑定也追加两类事件。证据：[`user_card_repository.rs:249-295`](../../../astral-trustgraph/src/repository/user_card_repository.rs#L249-L295)、[`user_card_repository.rs:298-360`](../../../astral-trustgraph/src/repository/user_card_repository.rs#L298-L360)、[`user_card_repository.rs:364-438`](../../../astral-trustgraph/src/repository/user_card_repository.rs#L364-L438)、[`user_card_repository.rs:442-480`](../../../astral-trustgraph/src/repository/user_card_repository.rs#L442-L480)。

**事实**：`permission_rule` 的 create/update/delete 以卡为聚合追加 CARD projection；DENY 或删除使用 `REVOKE` 语义。见 [`rule_repository.rs:181-223`](../../../astral-trustgraph/src/repository/rule_repository.rs#L181-L223)、[`rule_repository.rs:226-317`](../../../astral-trustgraph/src/repository/rule_repository.rs#L226-L317)、[`rule_repository.rs:345-375`](../../../astral-trustgraph/src/repository/rule_repository.rs#L345-L375)。委托创建/更新同样最终绑定到被委托卡并追加 CARD projection，见 [`delegation_repository.rs:162-181`](../../../astral-trustgraph/src/repository/delegation_repository.rs#L162-L181) 与 [`delegation_repository.rs:262-289`](../../../astral-trustgraph/src/repository/delegation_repository.rs#L262-L289)。

### 3.3 RULE_SET source mutation（legacy/迁移对照）

**事实（兼容边界）**：规则集 CRUD、entry CRUD、绑定变化和模板同步的旧写侧仍可能追加 RULE_SET head/outbox、绑定卡 CARD 事件及 RuleSet source audit correlation；这些记录用于 writer-correlation、迁移和对账。当前旧 `ProjectionWorker` 对 CARD/RULE_SET 事件只做终态 `mark_processed`，不再重建 `rule_set_snapshot`、写入 `projection_generation`、清理规则集/绑定卡缓存或推进旧 READY。新 `AuthorizationProjector` 才消费 `authorization_delta_event` 并发布 canonical manifest/segment/current 证据。旧 `rebuild_rule_set_snapshot` 入口不属于当前 checkout，也不是当前兼容入口或生产授权完成路径。相关 source 写入证据：[`rule_set_repository.rs:431-623`](../../../astral-trustgraph/src/repository/rule_set_repository.rs#L431-L623)、[`rule_set_write_service.rs:179-307`](../../../astral-trustgraph/src/service/rule_set_write_service.rs#L179-L307)、旧 worker 边界：[`projection_worker.rs`](../../../astral-trustgraph/src/service/projection_worker.rs#L297-L445)。

旧 RULE_SET outbox 可能处于 pending/retry，绑定卡 CARD 事件也独立收敛；这些状态只能用于迁移/对账，不能作为当前授权输入。canonical 发布是否可读必须重新验证 current pointer、manifest/segment seal、lineage、generation 与 `revoke_fence_proven`；任一证明不足都保持 PENDING/DENY。旧 `rebuild_rule_set_snapshot` 方法/接口已不属于当前 checkout，任何保留的同名文本都只是历史/迁移证据。

### 3.4 身份资格与自然到期边界

**事实**：运行期双卡资格由 `CardEligibilityService` 统一校验。identity_card 只校验身份归属、状态和 `expires_at`；user_card 承载 tenant/domain、有效窗口及组织状态。权威 JOIN 见 [`eligibility.rs:235-276`](../../../astral-db/src/eligibility.rs#L235-L276)。

**事实**：资格缓存使用独立 `ELIGIBILITY` head。缓存 payload 包含 `source_generation`、`projected_generation`、`revoke_fence`、物理双卡上下文和 `projection_type = ELIGIBILITY`，读命中必须全部匹配，并在读取时比较自然到期时间。见 [`eligibility.rs:32-54`](../../../astral-db/src/eligibility.rs#L32-L54)、[`eligibility.rs:279-359`](../../../astral-db/src/eligibility.rs#L279-L359)、[`eligibility.rs:438-460`](../../../astral-db/src/eligibility.rs#L438-L460)。

**缺口**：当前没有 `aggregate_type='IDENTITY'` head/outbox/MQ expiry event。identity_card.expires_at 的自然到期由读时 SQL/缓存时间判断处理，但外部或 DBA 显式修改 identity 状态/到期字段没有独立 source mutation 失效链。该结论在 [Rust 架构模型设计修正记录](./Rust架构模型设计修正记录.md)问题 9 的实施边界中已有记录。

**缺口**：tenant/domain 状态变化对受影响 user_card 的可靠 fan-out 尚未形成完整事件合同；当前资格 SQL 在读时 JOIN 组织状态。不能把现有 ELIGIBILITY 事件写成已经覆盖租户/域状态 fan-out。依据：[V5 模型修正筹划](./V5模型修正筹划_专供Rust_V1.0.md)§五“后续”中的 fan-out 说明。

## 4. Worker、lease 与 supersession

### 4.1 认领与 lease

**事实（当前 worker 分工）**：TrustGraph 进程同时持有旧 `ProjectionWorker`、`AuthorizationProjector` 和 `AuthorizationArchiveWorker`。旧 worker 每 5 秒轮询、每批最多 100 条并使用旧 head/outbox lease，只负责兼容 writer-correlation 终态和 ELIGIBILITY 资格缓存失效；CARD/RULE_SET 不再由它重建旧快照。`AuthorizationProjector` 对 `authorization_delta_event` 使用独立的事件 lease、generation/lineage/fence 校验和 current-pointer CAS；遇到 pointer-moved 时保留原 live lease，最多做 3 次原地 replan（包含首次共最多 4 次 publication attempt），额度内不消耗 durable execution-failure budget；全部耗尽后只经一次 owned charged transition 记一次执行失败。未知 transition 结果或 lease loss 不额外记账，须对账。`AuthorizationArchiveWorker` 对归档意图执行 proof-before-complete。源码证据：[`projection_worker.rs:46-59`](../../../astral-trustgraph/src/service/projection_worker.rs#L46-L59)、[`config.rs`](../../../astral-trustgraph/src/service/authorization_projector/config.rs#L21-L32)、[`worker.rs`](../../../astral-trustgraph/src/service/authorization_projector/worker.rs#L1126-L1302)、[`owned_worker.rs`](../../../astral-trustgraph/src/service/authorization_projector/owned_worker.rs#L12-L65)、[`authorization_archive_worker.rs`](../../../astral-trustgraph/src/service/authorization_archive_worker.rs#L1-L25)。

旧 worker 的完成、obsolete、失败释放 lease 条件更新和 1 到 300 秒退避只约束 legacy 通道；canonical projector 的 attempt/deadline、live lease CAS、Blocked/Quarantine/Unknown 处置以其自身代码合同为准。任何 lease/CAS 未知结果都不能计为已发布，必须先对账。

### 4.2 旧 worker 的认领与代次（legacy/迁移对照）

**事实（兼容边界）**：旧 `ProjectionWorker` 仍按旧 head/outbox 形状轮询、领取和终结 writer-correlation 事件；完成、obsolete、失败释放 lease 的条件更新及退避只约束这条兼容通道，不构成 canonical manifest/current 的发布证明。CARD/RULE_SET 事件在当前实现中只做 `mark_processed`，ELIGIBILITY 分支才执行资格缓存失效。canonical 授权事件由 `AuthorizationProjector` 使用独立的 delta lease、lineage/fence 校验和 current-pointer CAS 处理。

旧代码中的 `ProjectionAdvance`、`source_generation/projected_generation`、`projection_status` 和发布前旧 head 复查只能作为迁移/审计材料；`20260831000001` 已退役旧 head 的状态列，不能从这些字段推导生产 READY。

## 5. CARD、ELIGIBILITY 与 RULE_SET 的投影产物

| 维度 | CARD（legacy writer-correlation） | ELIGIBILITY | RULE_SET（legacy writer-correlation） |
|------|------|-------------|----------|
| 聚合 ID | `user_card.card_id` | `user_card.card_id` | `rule_set.rule_set_id` |
| source 事实 | 历史卡授权、规则、绑定变更 | 双卡物理资格、卡状态/有效期/组织有效性相关变更 | 历史 `rule_set`、`rule_set_entry`、绑定关系变更 |
| durable head | 旧 `aggregate_type='CARD'`，仅兼容/对账 | `aggregate_type='ELIGIBILITY'` | 旧 `aggregate_type='RULE_SET'`，仅兼容/对账 |
| 当前 worker 作用 | 只终结旧事件，不再重建 snapshot/evict/refresh | 失效 `perm:card:active:{card_id}` 资格缓存 | 只终结旧事件，不再重建 snapshot/推进旧 READY |
| canonical 生产投影 | `authorization_delta_event` → manifest/segment/current | 不替代资格 head；资格仍走独立链 | `authorization_delta_event` → manifest/segment/current |
| 兼容副作用 | 旧 refresh/cache side effects 仅作历史/迁移材料，不是发布证明 | 独立资格缓存失效；不发布规则授权 refresh | 旧 refresh/cache side effects 仅作历史/迁移材料，不是发布证明 |
| 生产读侧 gate | canonical current pointer、manifest/segment seal、lineage、generation、`revoke_fence_proven` | ELIGIBILITY head + 资格载荷物理上下文/版本匹配 | 同左；不使用旧 READY 或 snapshot generation |
| 失效方式 | canonical 证明缺失/不一致 → PENDING/DENY | 版本/上下文不匹配 → 回权威 SQL或拒绝 | canonical 证明缺失/不一致 → PENDING/DENY |

**事实**：上述分派在 worker 中明确互斥：CARD 走 [`project_card:195-289`](../../../astral-trustgraph/src/service/projection_worker.rs#L195-L289)，RULE_SET 走 [`project_rule_set:298-445`](../../../astral-trustgraph/src/service/projection_worker.rs#L298-L445)，ELIGIBILITY 走 [`project_eligibility:447-496`](../../../astral-trustgraph/src/service/projection_worker.rs#L447-L496)。

**历史边界**：旧 CARD cache eviction、Redis DEL warning 和旧 refresh side effect 只作迁移/审计记录；当前 [`api/side_effects.rs`](../../../astral-trustgraph/src/api/side_effects.rs) 处理的是已提交 session-revocation intent，不是权限快照或授权缓存执行器。CURRENT V6 published-evidence L1 的读时栅栏见 [`evidence_cache.rs`](../../../astral-db/src/evidence_cache.rs)；独立资格缓存失效仍由 ELIGIBILITY 通道负责，不能重建规则快照或发布 CARD refresh。

## 6. 快照表、缓存与版本语义

### 6.1 `permission_rule_snapshot`（legacy/迁移对照）

**历史 schema 证据（非当前 API）**：Rust baseline 曾将该表定义为按卡的编译权限快照，后续 migration 增加 `version_no` 与 `(card_id, version_no)` 索引；这些历史 schema/rebuild 语义只用于迁移 inventory、历史数据对账或取证，不表示当前存在 legacy evaluator、strict-capability selector 或 snapshot-reading test repository。CURRENT V6 `RuleRepository` 无 capability marker/兼容 dispatch，生产读侧只消费 published card evidence；旧快照缺失、过期或读取错误不是当前授权分支。结构证据：[`20240630000001_baseline.sql:75-86`](../../../astral-db/migrations/20240630000001_baseline.sql#L75-L86)、[`20240630000009_snapshot_version.sql:1-9`](../../../astral-db/migrations/20240630000009_snapshot_version.sql#L1-L9)。

旧 CARD rebuild 的 `MAX(version_no)`、删除/重插和乐观锁行为只作为历史实现记录；不能用其证明 canonical current pointer 已发布。

### 6.2 `rule_set_snapshot`（legacy/迁移对照）

**历史 schema 证据（非当前 API）**：Rust-owned schema repair 曾为 `rule_set_snapshot` 补齐/验证 `version_no`、逻辑 winner 键和 `projection_generation`；这些列和旧 winner 行只用于迁移、对账或历史取证，不表示当前存在未声明 strict-capability 的测试 repository。当前旧 worker 不再写该表，生产 `SqlxRuleRepository` 也不从该表读取授权；`projection_generation = 0` 或缺失只能说明未证明的旧历史，不能单独授权。见 [`20260822000001_rule_set_projection_schema_repair.sql`](../../../astral-db/migrations/20260822000001_rule_set_projection_schema_repair.sql)、[`migration.rs:2056-2200`](../../../astral-db/src/migration.rs#L2056-L2200)。

旧 RuleSet rebuild 的有效窗口、winner tie-break、空 source 清理和 `MAX(version_no)` 行选择保留为历史实现证据；不能把它们写成 canonical 发布证明。旧 `valid_from/valid_to` 修复不证明旧快照存在持续到期调度，也不能否定当前 strict reader、matcher 与 bounded evidence L1 对 grant validity 的读时检查（见 §2.6）；自然到期不自动产生 delta 或 publication-generation advance。

### 6.3 旧快照版本与 canonical evidence 的边界

**事实**：旧 snapshot 表仍可能以每个 card/rule_set 的 `MAX(version_no)` 定位历史当前行；该值只描述旧表内的行选择，不能证明生产授权可读。旧快照的唯一键、版本列和 validity migration 可能因部署 schema 版本不同而不一致，必须由目标环境的 migration/postcondition 单独确认。

**当前生产读门**：`SqlxRuleRepository` 通过 `load_published_card_authorization` 读取 `authorization_projection_current` 指针锁定的 manifest/segment 链，并验证 scope、摘要/seal、lineage、generation 与 `revoke_fence_proven`。缺失 current、未证明指针、链不完整、摘要失配、scope 不符或提交/读取错误只能返回 PENDING/DENY；不使用旧 `MAX(version_no)`、旧 `projection_generation`、raw source 或未认证缓存作为回退。

**剩余边界**：canonical 表链的 creator-only migration 不负责既有数据 backfill；`20260827000002_legacy_snapshot_tables_decommission.sql` 仍是带前置条件的 standby script。migration 文件存在、旧代码路径退出、目标库完成 DROP、既有账本完成 backfill/rehearsal 和正式流量切换必须分别取得证据。

## 7. 已识别缺口

### 7.1 canonical published-evidence gate 与 legacy head 边界

**事实（CURRENT V6 formal path）**：`PolicyEngine::evaluate()` 通过四个 required `RuleRepository` ports 直接进入 CURRENT V6 published-evidence read gate。`authorization_projection_current` 必须指向可验证的 manifest/segment 链；读侧检查 scope、摘要/seal、lineage、generation 与 `revoke_fence_proven`，并在有效 ALLOW 返回前复读证据。current 缺失、未证明、链不完整、摘要失配、scope 不符或读取错误均保持 PENDING/DENY，不回退旧 head、snapshot、raw source 或未认证缓存。证据：[`policy-engine/src/engine/ports.rs`](../../../policy-engine/src/engine/ports.rs)、[`engine/formal.rs`](../../../policy-engine/src/engine/formal.rs)、[`engine/published.rs`](../../../policy-engine/src/engine/published.rs)、[`authorization_projection_repository.rs`](../../../astral-db/src/authorization_projection_repository.rs)。

**历史边界**：旧 `authorization_projection_head/outbox`、`projection_generation` 与 `READY` 语义只作为 schema/迁移/对账历史；不属于当前 evaluator 或兼容 repository dispatch。保留 head/outbox 的有限责任见 §2.2，不作为 canonical 发布证明。ELIGIBILITY qualification/invalidation 独立于规则授权 evidence。

### 7.2 migration/backfill 与旧数据收敛边界

**事实**：`20260822000001_rule_set_projection_schema_repair.sql`、`20260822000002_snapshot_validity_windows.sql` 等旧链修复 migration 只描述 schema/backfill 工具和历史快照证据；`20260825000002_incremental_projection_archive.sql` 是 canonical grant/delta/manifest/segment/current 的 creator-only migration，不负责既有数据 backfill。`20260827000002_legacy_snapshot_tables_decommission.sql` 是带前置条件的 standby script，不能据文件存在推断旧表已经 DROP。

**剩余边界**：目标环境必须分别证明 migration 已应用、旧 writer 已停止写快照、既有 grant ledger 已 backfill/rehearsal、current pointer 的证明闩已建立、worker 已 drain/replay、strict read gate 已验收和正式流量已切换。任一 schema shape、历史 lineage、摘要或数据库状态无法证明时，canonical projector/read gate 保持 Blocked/PENDING/DENY。

### 7.3 旧 snapshot version 与 canonical generation 的分层边界

**事实**：`version_no`、旧 `projection_generation` 和旧 head 状态只描述 legacy snapshot 表/兼容 writer-correlation 的历史版本关系。删除旧快照或重置旧版本不能改变 canonical current pointer 的证明状态，也不能使未证明历史变成可读授权。

canonical 证据的版本关系由 current pointer 指向的 manifest/segment、parent lineage、generation、semantic/dependency hash 和 `revoke_fence_proven` 共同证明；任何 proof 缺失或不一致都进入 PENDING/DENY。

### 7.4 历史 snapshot winner ordering

旧 RuleSet/CARD snapshot winner 的 `entry_id` tie-break 与输入顺序语义仅作为历史排序记录，不是 CURRENT V6 production matcher 合同。正式 matcher 消费 ALLOW-only `effective_grants`；其当前规范以 CURRENT V6 RuleSet/compiler 合同和源码为准，不从旧 snapshot 代码推导排序或准入行为。

### 7.5 历史 staged fail-closed 语义

旧 L2/L2.5 repository-error handling 与 realtime/raw-source reader 仅为历史 evaluator 记录，不是当前 API 或 compatibility dispatch。CURRENT V6 formal reader 不进入旧阶段；published-evidence current/manifest/segment 读取错误、未证明或 scope 不符均保持 PENDING/DENY。

### 7.6 typed grant-source ownership 与 legacy source-field 边界

**CURRENT V6 事实**：规范化授权账本使用封闭的 `GrantSourceKind` 与 `BindingLayer` 合同：`RULE_SET` contribution 必须是 `BASE` 或 `OVERLAY`；`DIRECT`、`DELEGATION`、`APPROVAL`、`SYSTEM` 的 layer 为 `NONE`。新建 direct `permission_rule` 只接受 enabled `MANUAL`；历史 `CARD_ONLY` 只读/删除、不自动改写；`SYSTEM` 当前 reserved-unused，没有生产 append path。RuleSet、direct rule、delegation 与 approval 分别由其 source owner 构造 typed grant contribution，并在 source transaction 中关联 revision/delta 和审计，再由唯一 projector 物化。入口见 [`astral-types/src/grant.rs`](../../../astral-types/src/grant.rs)、[`rule_write_service.rs`](../../../astral-trustgraph/src/service/rule_write_service.rs)、[`grant_ledger_adapter.rs`](../../../astral-trustgraph/src/repository/grant_ledger_adapter.rs) 与 CURRENT V6 [规范 §15.8](../../规范/Rust后端编码规范_V1.0.md#158-current-v6-breaking-change-inventory-与-adoption-notice)。

旧 `permission_rule.source_type`、legacy reader filters 与 snapshot/source-table 并列关系不等同 canonical typed source registry，也不表示当前存在旧 L2/L2.5/realtime 读取阶段；CURRENT V6 formal reader 不按旧 `source_type` 过滤 snapshot/raw rows。历史 writer/source-type owner 缺口及所提全局矩阵属于已被 typed source contract 取代的旧审计材料，不是当前 evaluator、repository dispatch 或 V6 owner 缺口。以上为代码与类型合同事实，不证明历史 source rows 已迁移、目标数据库 schema 已更新或任一环境完成 backfill。

### 7.7 审计旁路与投影主状态分离

**事实**：审计写入是 MQ-first；MQ 未初始化或发布失败时走 DB fallback，DB fallback 重试一次，最终调用 `record_audit` 结构化留痕，且不阻塞权限判定。见 [`astral-common/src/audit.rs:88-163`](../../../astral-common/src/audit.rs#L88-L163)。RabbitMQ producer 的 payload 有 `message_id` 字段，通用 envelope 由 producer 生成 messageId；见 [`astral-mq/src/producer.rs:231-247`](../../../astral-mq/src/producer.rs#L231-L247)。

**事实**：MQ 消费幂等使用短 processing lease，成功后写 24 小时完成标记，失败释放 lease，可再次投递；见 [`astral-mq/src/consumer.rs:360-464`](../../../astral-mq/src/consumer.rs#L360-L464)。审计 quarantine replay worker 另有 60 秒 SQL lease，并且只在 broker publish confirmation 后确认 durable replay row，见 [`audit_replay_worker.rs:1-8`](../../../astral-trustgraph/src/service/audit_replay_worker.rs#L1-L8)、[`audit_replay_worker.rs:282-299`](../../../astral-trustgraph/src/service/audit_replay_worker.rs#L282-L299)。

**事实（legacy 边界）**：普通审计旁路不改变投影状态。“RULE_SET worker 推进旧 head READY 前写入 `REBUILD_SNAPSHOT` 审计证据”的合同只属于 legacy/迁移对照历史：旧 worker 现在对 CARD/RULE_SET 事件只做终态 `mark_processed`，不再重建快照、写 `projection_generation` 或推进已删除的旧 READY。RuleSet source mutation 仍在同一事务写入 `event_id`、`source_generation`、`operation_id` 关联证据；canonical 侧的发布审计关联由 `AuthorizationProjector` 在发布事务内落盘，`AuthorizationArchiveWorker` 在归档 proof 中保留整链证据。旧 projection worker 的兼容状态推进见 [`projection_worker.rs:195-443`](../../../astral-trustgraph/src/service/projection_worker.rs#L195-L443)。

**事实**：审计与投影各自拥有 durable/lease/retry 机制，但 RuleSet source/rebuild 证据通过 `event_id`、`source_generation`、`operation_id` 关联；migration backfill 使用稳定 operation id 与幂等 upsert。审计证据存在不单独授权；普通 audit consumer 已处理也不替代 projection READY。

## 8. 五链审查结论

### 8.1 调用链

**事实**：CURRENT V6 canonical call chain 为 source repository/service → grant ledger + delta event → proven-COMMIT immutable receipt batch → 唯一 `WorkerOwned` `AuthorizationProjector` → manifest/segment/current durable CAS → published-evidence reader → `PolicyEngine::evaluate()`；`AuthorizationArchiveWorker` 独立处理 superseded manifest 的 proof-before-complete。保留的 source head/outbox 不作为发布证明，只承担 §2.2 中列明的 correlation/invalidation 职责。
**结论**：生产授权只走 V6 canonical evidence gate；ELIGIBILITY qualification/cache invalidation 为独立边界，旧 CARD/RULE_SET snapshot reader 不作为当前授权或兼容 evaluator。

### 8.2 逻辑链

**事实**：CURRENT V6 production reader 只验证 current pointer 指向的 manifest/segment 完整链、scope、摘要/seal、parent lineage、generation/dependency 与 `revoke_fence_proven`，并在有效 ALLOW 前复读；旧 head、`READY`、snapshot `projection_generation` 不作为当前授权输入。
**结论**：未能证明版本时 PENDING/拒绝；任何旧 snapshot/head 或 staged delegation 语义均不能代替 V6 published evidence。

### 8.3 事故链

**事实**：canonical projector 对 lease/CAS/lineage/fence/摘要冲突分别执行有界 retry、Blocked、Quarantine 或 Unknown 处置；未知结果停止后续 mutation 并要求先对账。旧 `ProjectionWorker` 的 retry/mark_processed 和 ELIGIBILITY cache eviction 失败只影响兼容通道，不改变 canonical read gate。canonical current/manifest/segment 读取失败、证明闩未置位或 scope 不符均保持 PENDING/DENY。

### 8.4 数据链

**事实**：canonical 数据链由 grant revision、typed delta、complete receipt、impact plan、manifest/segment/current、archive intent/proof 和 strict evidence reader 组成；保留 source head/outbox、旧 snapshot 和 ELIGIBILITY cache 是各自独立的 correlation/historical/qualification 边界，均不是授权 durable proof。
**结论**：任何 schema/worker 变更必须同步 source、ledger/delta、manifest/segment/current、archive/completion、cache payload、consumer stale check、migration/backfill 和读侧 gate。

### 8.5 审计链

**事实**：权限判定审计通过 `AuditDualWrite::record_permission_check` 进入 MQ-first/DB-fallback；审计失败不改变授权结果。见 [`audit.rs:165-195`](../../../astral-common/src/audit.rs#L165-L195)。

**结论**：审计可追溯性是旁路不变式，不能绕过；但审计状态不替代 projection 状态，二者必须分别有 messageId/lease/retry/回放证据。

## 9. 目标决策（2026-08-22，非当前实现）

### 9.1 决策：投影版本栅栏分层

**决策基线（2026-08-22；CARD/RULE_SET 部分现为 legacy/迁移对照）**：`CARD`、`ELIGIBILITY`、`RULE_SET` 三类 durable aggregate 已落地。其中卡授权读侧现验证 canonical current/manifest/segment 证据，旧 CARD head 仅保留 writer-correlation；资格缓存验证 ELIGIBILITY head；旧 RULE_SET head 与 `rule_set_snapshot.projection_generation` 仅用于迁移对账。未来变更不得删除 ELIGIBILITY 资格 gate，也不得把旧 CARD/RULE_SET READY 重新当成共享 RuleSet 完成证明。

### 9.2 决策：当前行 + durable generation

**决策基线（2026-08-22；现为 legacy/迁移对照）**：旧快照表使用 `version_no` 定位历史当前行，RULE_SET snapshot 的 `projection_generation` 与旧 head projected generation 的比较只保留在 legacy/迁移对照路径。canonical 读侧由 current pointer、manifest/segment seal、lineage、generation 和 `revoke_fence_proven` 联合证明；CAS/lease 冲突、旧代事件、generation 不连续或 proof 不足时按 Blocked/有界重试处理，读侧 PENDING/DENY。

### 9.3 决策：Arbiter 保持冲突检测器

**目标决策**：Arbiter 继续是冲突检测与证据裁决组件，不成为第四个日常授权投票者，也不替代 projection gate。当前纯函数已经只在 READY 且出现可区分版本的快照/实时分歧时生成冲突信号，见 [`arbiter.rs:112-133`](../../../policy-engine/src/arbiter.rs#L112-L133)；其版本序和 fail-closed DEFER 语义见 [`arbiter.rs:160-229`](../../../policy-engine/src/arbiter.rs#L160-L229)。目标实现必须继续遵守：无法证明版本时进入 PENDING/DEFER，而不是由多数票绕过版本栅栏。

### 9.4 决策：审计为独立可追溯旁路

**目标决策**：投影主状态机与审计旁路继续分离；任何 source mutation、授权决策和权限刷新都应能通过 messageId/operationId、lease、重试和回放记录关联，但审计消费完成不作为授权 READY 条件。当前实现已具备部分 MQ-first/DB-fallback 与 replay 基础，未来完善不能回写为当前 projection 已包含审计确认。

### 9.5 历史决策：版本化热状态 + 异步旧版本归档（2026-08-26；CURRENT V6 已取代旧阶段与 marker 描述）

**历史决策（当时记录的目标及状态，不是 CURRENT V6 当前 API）**：已批准的 Rust canonical 投影采用版本化可变热状态：热状态当前版本随增量可变（测试中的 111→112 仅为版本推进示例）；增量事件携带 before-image/旧 segment 引用；发布经 current 指针原子 CAS；旧版本由异步归档 worker 产出 DB 内归档证明；segment 为内容寻址不可变行并带 segment-local seal；账本 ALLOW-only（普通 DENY 不持久化为 grant）；RULE_SET 贡献带 BASE/OVERLAY 标签。读侧目标门是严格 published evidence：`Ok(None)`/`Err`/非 Ready 一律 PENDING/DENY，禁止回退旧快照、raw source 或缓存。该读门已接线到代码层：当时记录的生产 `SqlxRuleRepository` 以 capability marker 声明正式授权必须走 published evidence（该 selector 已由 CURRENT V6 移除；不再是当前合同），当时 `PolicyEngine::evaluate()` 在 marker 为真时消费严格读门并 fail-closed；`evaluate_realtime()` 不消费该端口。当前无 marker dispatch、旧 L1/L2/L2.5 或 realtime evaluator；实际 V6 四个 required ports 与 published-evidence gate 见本文 §2.2–§2.4。历史真实 MySQL 集成、既有数据 backfill/rehearsal、正式切流等状态只反映当时记录，不代表本次完成或当前仍是同一 TODO；direct/approval/delegation/rule-set 贡献与当前 owner 以 §7.6 及 typed grant contract 为准。

### 10. 验收要点（文档范围）

- **事实/缺口/目标决策可区分**：canonical grant/delta/manifest/segment/current 链、legacy head/snapshot 边界、ELIGIBILITY 资格链、migration/backfill 和剩余时间到期边界分开记录。
- **链路覆盖完整**：source mutation → grant revision/delta → compiler/projector lease → manifest/segment/current CAS → published-evidence reader → archive proof；旧 head/outbox、快照、缓存/MQ 仅作为兼容/迁移对照。
- **三类语义分离**：CARD/RULE_SET 旧 worker 只做 writer-correlation 终态收口，ELIGIBILITY 仍负责资格缓存失效；canonical 授权投影由 `AuthorizationProjector` 统一发布，`AuthorizationArchiveWorker` proof 后完成归档。
- **生产读门明确**：current pointer、manifest/segment seal、scope、lineage、generation 和 `revoke_fence_proven` 任一不足即 PENDING/DENY；旧 `READY`、`projected_generation`、`projection_generation` 或 `MAX(version_no)` 不能单独准入。
- **剩余边界诚实**：canonical creator-only migration 不负责既有数据 backfill；旧表 decommission、backfill/rehearsal、缓存/摘要迁移、wall-clock expiry、真实基础设施集成和正式切流均需独立证据。
