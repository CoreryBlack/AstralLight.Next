# Rust 权限投影快照与版本栅栏 V1.0

> 版本：V1.0
> 日期：2026-09-09
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
- Structurizr 维护说明：架构 DSL、动态视图与代码事实的维护规则。

相关动态视图：

- 权限写入投影链路
- 权限变更投影排查图
- 授权决策链路
- 授权决策排查图
- Structurizr workspace DSL

## 2. 范围与核心结论

### 2.1 范围

本文只描述授权相关 source mutation 进入 durable projection 后，如何形成读取快照、版本缓存、刷新消息和审计记录。身份卡本身的显式到期 mutation 另列为缺口，不把自然到期误写成已有的 `IDENTITY` 投影通道。

### 2.2 当前态摘要

当前授权链分为两个明确边界：

1. **canonical Rust-owned 链**：`authorization_grant_revision` → `authorization_delta_event` → `authorization_projection_manifest`/`authorization_projection_segment` → `authorization_projection_current`，由 `AuthorizationProjector` 编译并以 pointer/manifest/segment seal 证明发布；`AuthorizationArchiveWorker` 对 superseded parent 生成 DB 内归档 proof，proof 先于 `SUCCEEDED`。
2. **legacy 兼容链**：`authorization_projection_head/outbox`、`permission_rule_snapshot`、`rule_set_snapshot` 及其旧 refresh/cache 表面仍可能存在，用于 writer-correlation、ELIGIBILITY 资格缓存失效、legacy/test reader 或待执行的 decommission 迁移；旧 CARD/RULE_SET 快照重建不再是生产授权投影职责。

生产 `SqlxRuleRepository` 的 `requires_published_card_evidence()` 为 true，`PolicyEngine::evaluate()` 在认证、卡上下文和 resource/action 校验后直接使用 published-evidence strict gate。current 缺失、证明闩未置位、manifest/segment 校验失败、scope 不符或读取错误只能 PENDING/DENY，不回退 legacy snapshot、raw source 或缓存。L1/L2/L2.5 旧阶段仅适用于未声明 capability 的 legacy/test repository 与诊断对照。

canonical source mutation / projection 的代码级流程如下：

```text
source mutation
  -> 同一 SQL transaction 写 grant revision + delta event（稳定 event/operation id）
  -> AuthorizationProjector claim/lease
  -> 事务外读取已证明 frontier 与完整 ledger，AuthorizationCompiler 生成 candidate/full oracle
  -> 发布事务重新验证 lease、lineage、fence、generation、segment seal
  -> impact plan + manifest/segment + current pointer CAS 同事务提交
  -> commit proof 后可选推送 L2 evidence（失败不扩大授权）
  -> superseded parent 追加 archive intent；ArchiveWorker proof 后才将 intent SUCCEEDED
  -> PolicyEngine strict published-evidence read
```

source transaction 不访问 Redis 或 RabbitMQ；发布后的缓存推送、归档和审计均在事务外或独立 durable 边界处理。旧链的具体表/列和迁移状态见 §6 与 [旧链退役迁移](../../../astral-db/migrations/20260827000002_legacy_snapshot_tables_decommission.sql)。

**事实（2026-08-26 增补：新 Rust-owned canonical 投影链切片；strict gate 已接线代码层，正式切流验收未完成）**：除上述旧链外，已批准的“版本化可变热状态 + 异步旧版本归档”模型已落第一批切片。creator-only 迁移 [`20260825000002_incremental_projection_archive.sql`](../../../astral-db/migrations/20260825000002_incremental_projection_archive.sql) 创建 `authorization_grant_revision`（append-only revision ledger，含 tombstone）、`authorization_delta_event`（typed delta 队列，携带 `before_image_json`/`before_digest` 即旧 segment 引用与 CAS/lease 状态）、`authorization_impact_plan(_item)`、`authorization_projection_manifest`、内容寻址不可变的 `authorization_projection_segment`（segment-local seal）、`authorization_projection_manifest_segment`（不变 segment 复用父引用，不删除重插）、CAS 指针表 `authorization_projection_current`、`authorization_archive_outbox` 与 `authorization_archive_manifest`；[`20260827000001_authorization_projection_lineage_fence.sql`](../../../astral-db/migrations/20260827000001_authorization_projection_lineage_fence.sql) 追加 `parent_manifest_id` lineage 列与 revoke fence 列，0 为“未证明历史”哨兵，任何人不得从 0 推断放宽授权。发布通过 `authorization_projection_current` 的 affected-rows-exactly-one CAS 原子移动 current 指针；旧 manifest 的归档由异步 archive worker 在锁内重读整条旧链、重算摘要后写 DB 内归档证明，proof 先于 ACK；归档失败不回滚已发布的 current 指针。授权账本为 ALLOW-only：普通 DENY 是评估/规则层关注点，不持久化为正授权 grant，撤销以 tombstone/fence 表达；RULE_SET 贡献携带 BASE/OVERLAY 优先级标签，DELEGATION 贡献恒为 layer=None。TrustGraph 已接线新 projector（新队列唯一消费者，不触旧快照/旧 outbox/旧缓存/旧 MQ）与 archive worker。

**缺口（2026-08-26 增补同步：strict gate 代码层已实现，真实集成与切流验收未完成）**：该新链与旧 `authorization_projection_head`/outbox、两张旧快照表、Redis 缓存与 MQ 互不读写（双链并存）。读侧已实现的代码层边界：生产 [`SqlxRuleRepository`](../../../astral-db/src/repository.rs#L342-L351) 声明 capability marker `requires_published_card_evidence() == true`，[`PolicyEngine::evaluate()`](../../../policy-engine/src/engine.rs#L460-L471) 据此在 AUTHN/CARD_CONTEXT 之后进入严格 published-evidence strict gate（缺 current 指针 ⇒ NotReady、无 empty-ALLOW 形态；`Ok(None)`/`Err`/非 Ready/证据畸形/scope 不符一律 fail-closed `AUTHORIZATION_PENDING`；无旧快照/raw source/cache 回退；ALLOW 返回前复读证据并校验 gate 计数、manifest 摘要与命中 grant 一致），L1/L2/L2.5 union 不消费该端口；`evaluate_realtime()` 仍仅作一致性/oracle 路径，不消费该端口。新链 source 侧已由 `grant_ledger_adapter` 把 direct/approval/delegation/rule-set typed 贡献在 source transaction 内写入授权账本并追加 delta event，projector 按 aggregate 消费新 delta 队列，不限于 RULE_SET 源。上述边界当前由 typed 测试覆盖；尚未完成：既有数据 backfill/rehearsal、缓存与权限摘要读侧迁移、真实 MySQL 集成验收与正式切流验收——真实集成未完成前不得宣称生产验收或完整授权覆盖。迁移注释明确“不 backfill、不改删既有 source/projection 数据”，不得把已建表写成已完成迁移。

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

**事实（兼容边界）**：规则集 CRUD、entry CRUD、绑定变化和模板同步的旧写侧仍可能追加 RULE_SET head/outbox、绑定卡 CARD 事件及 RuleSet source audit correlation；这些记录用于 writer-correlation、迁移和对账。当前旧 `ProjectionWorker` 对 CARD/RULE_SET 事件只做终态 `mark_processed`，不再重建 `rule_set_snapshot`、写入 `projection_generation`、清理规则集/绑定卡缓存或推进旧 READY。新 `AuthorizationProjector` 才消费 `authorization_delta_event` 并发布 canonical manifest/segment/current 证据。旧 `rebuild_rule_set_snapshot` 入口仅保留兼容形状，不是生产授权完成路径。相关 source 写入证据：[`rule_set_repository.rs:431-623`](../../../astral-trustgraph/src/repository/rule_set_repository.rs#L431-L623)、[`rule_set_write_service.rs:179-307`](../../../astral-trustgraph/src/service/rule_set_write_service.rs#L179-L307)、旧 worker 边界：[`projection_worker.rs`](../../../astral-trustgraph/src/service/projection_worker.rs#L297-L445)。

旧 RULE_SET outbox 可能处于 pending/retry，绑定卡 CARD 事件也独立收敛；这些状态只能用于迁移/对账，不能作为当前授权输入。canonical 发布是否可读必须重新验证 current pointer、manifest/segment seal、lineage、generation 与 `revoke_fence_proven`；任一证明不足都保持 PENDING/DENY。

### 3.4 身份资格与自然到期边界

**事实**：运行期双卡资格由 `CardEligibilityService` 统一校验。identity_card 只校验身份归属、状态和 `expires_at`；user_card 承载 tenant/domain、有效窗口及组织状态。权威 JOIN 见 [`eligibility.rs:235-276`](../../../astral-db/src/eligibility.rs#L235-L276)。

**事实**：资格缓存使用独立 `ELIGIBILITY` head。缓存 payload 包含 `source_generation`、`projected_generation`、`revoke_fence`、物理双卡上下文和 `projection_type = ELIGIBILITY`，读命中必须全部匹配，并在读取时比较自然到期时间。见 [`eligibility.rs:32-54`](../../../astral-db/src/eligibility.rs#L32-L54)、[`eligibility.rs:279-359`](../../../astral-db/src/eligibility.rs#L279-L359)、[`eligibility.rs:438-460`](../../../astral-db/src/eligibility.rs#L438-L460)。

**缺口**：当前没有 `aggregate_type='IDENTITY'` head/outbox/MQ expiry event。identity_card.expires_at 的自然到期由读时 SQL/缓存时间判断处理，但外部或 DBA 显式修改 identity 状态/到期字段没有独立 source mutation 失效链。该结论在 [Rust 架构模型设计修正记录](./Rust架构模型设计修正记录.md)问题 9 的实施边界中已有记录。

**缺口**：tenant/domain 状态变化对受影响 user_card 的可靠 fan-out 尚未形成完整事件合同；当前资格 SQL 在读时 JOIN 组织状态。不能把现有 ELIGIBILITY 事件写成已经覆盖租户/域状态 fan-out。依据：[V5 模型修正筹划](./V5模型修正筹划_专供Rust_V1.0.md)§五“后续”中的 fan-out 说明。

## 4. Worker、lease 与 supersession

### 4.1 认领与 lease

**事实（当前 worker 分工）**：TrustGraph 进程同时持有旧 `ProjectionWorker`、`AuthorizationProjector` 和 `AuthorizationArchiveWorker`。旧 worker 每 5 秒轮询、每批最多 100 条并使用旧 head/outbox lease，只负责兼容 writer-correlation 终态和 ELIGIBILITY 资格缓存失效；CARD/RULE_SET 不再由它重建旧快照。`AuthorizationProjector` 对 `authorization_delta_event` 使用独立的事件 lease、generation/lineage/fence 校验和 current-pointer CAS；`AuthorizationArchiveWorker` 对归档意图执行 proof-before-complete。源码证据：[`projection_worker.rs:46-59`](../../../astral-trustgraph/src/service/projection_worker.rs#L46-L59)、[`authorization_projector.rs`](../../../astral-trustgraph/src/service/authorization_projector.rs#L741-L847)、[`authorization_archive_worker.rs`](../../../astral-trustgraph/src/service/authorization_archive_worker.rs#L1-L25)。

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
| Redis/MQ | 旧副作用仅作迁移材料，不是发布证明 | 资格缓存失效；不发布 CARD refresh | 旧副作用仅作迁移材料，不是发布证明 |
| 生产读侧 gate | canonical current pointer、manifest/segment seal、lineage、generation、`revoke_fence_proven` | ELIGIBILITY head + 资格载荷物理上下文/版本匹配 | 同左；不使用旧 READY 或 snapshot generation |
| 失效方式 | canonical 证明缺失/不一致 → PENDING/DENY | 版本/上下文不匹配 → 回权威 SQL或拒绝 | canonical 证明缺失/不一致 → PENDING/DENY |

**事实**：上述分派在 worker 中明确互斥：CARD 走 [`project_card:195-289`](../../../astral-trustgraph/src/service/projection_worker.rs#L195-L289)，RULE_SET 走 [`project_rule_set:298-445`](../../../astral-trustgraph/src/service/projection_worker.rs#L298-L445)，ELIGIBILITY 走 [`project_eligibility:447-496`](../../../astral-trustgraph/src/service/projection_worker.rs#L447-L496)。

**事实**：CARD cache evict 是 side-effect-only；Redis 失败仅 warning，但读侧的 head/version gate 不因此放宽。见 [`side_effects.rs:207-257`](../../../astral-trustgraph/src/api/side_effects.rs#L207-L257)。ELIGIBILITY 也只删除资格 key，不重建规则快照或发布 CARD refresh，见 [`side_effects.rs:225-235`](../../../astral-trustgraph/src/api/side_effects.rs#L225-L235)。

## 6. 快照表、缓存与版本语义

### 6.1 `permission_rule_snapshot`（legacy/迁移对照）

**事实（历史兼容面）**：Rust baseline 曾将其定义为按卡的编译权限快照，后续 migration 增加 `version_no` 与 `(card_id, version_no)` 索引；这些 schema 和旧 rebuild 实现仍可供迁移、对账或未声明 strict capability 的测试 repository 读取，但不属于生产 `SqlxRuleRepository` 的授权来源。生产读侧只消费 published card evidence；旧快照缺失、过期或读取错误不会回退到 raw `permission_rule`，而是保持 PENDING/DENY。结构证据：[`20240630000001_baseline.sql:75-86`](../../../astral-db/migrations/20240630000001_baseline.sql#L75-L86)、[`20240630000009_snapshot_version.sql:1-9`](../../../astral-db/migrations/20240630000009_snapshot_version.sql#L1-L9)。

旧 CARD rebuild 的 `MAX(version_no)`、删除/重插和乐观锁行为只作为历史实现记录；不能用其证明 canonical current pointer 已发布。

### 6.2 `rule_set_snapshot`（legacy/迁移对照）

**事实（历史兼容面）**：Rust-owned schema repair 曾为 `rule_set_snapshot` 补齐/验证 `version_no`、逻辑 winner 键和 `projection_generation`；这些列和旧 winner 行可用于迁移、对账或未声明 strict capability 的测试 repository。当前旧 worker 不再写该表，且生产 `SqlxRuleRepository` 不从该表读取授权。`projection_generation = 0` 或缺失只能说明未证明的旧历史，不能单独授权。见 [`20260822000001_rule_set_projection_schema_repair.sql`](../../../astral-db/migrations/20260822000001_rule_set_projection_schema_repair.sql)、[`migration.rs:2056-2200`](../../../astral-db/src/migration.rs#L2056-L2200)。

旧 RuleSet rebuild 的有效窗口、winner tie-break、空 source 清理和 `MAX(version_no)` 行选择保留为历史实现证据；不能把它们写成 canonical 发布或 wall-clock expiry 证明。旧 `valid_from/valid_to` 修复也不等于已完成生产到期调度。

### 6.3 旧快照版本与 canonical evidence 的边界

**事实**：旧 snapshot 表仍可能以每个 card/rule_set 的 `MAX(version_no)` 定位历史当前行；该值只描述旧表内的行选择，不能证明生产授权可读。旧快照的唯一键、版本列和 validity migration 可能因部署 schema 版本不同而不一致，必须由目标环境的 migration/postcondition 单独确认。

**当前生产读门**：`SqlxRuleRepository` 通过 `load_published_card_authorization` 读取 `authorization_projection_current` 指针锁定的 manifest/segment 链，并验证 scope、摘要/seal、lineage、generation 与 `revoke_fence_proven`。缺失 current、未证明指针、链不完整、摘要失配、scope 不符或提交/读取错误只能返回 PENDING/DENY；不使用旧 `MAX(version_no)`、旧 `projection_generation`、raw source 或未认证缓存作为回退。

**剩余边界**：canonical 表链的 creator-only migration 不负责既有数据 backfill；`20260827000002_legacy_snapshot_tables_decommission.sql` 仍是带前置条件的 standby script。migration 文件存在、旧代码路径退出、目标库完成 DROP、既有账本完成 backfill/rehearsal 和正式流量切换必须分别取得证据。

## 7. 已识别缺口

### 7.1 canonical published-evidence gate 与 legacy head 边界

**事实（当前生产路径）**：生产 `SqlxRuleRepository` 的 capability marker 为 true，`PolicyEngine::evaluate()` 在 AUTHN/CARD_CONTEXT 和 resource/action 校验后直接读取 published card evidence。`authorization_projection_current` 必须指向可验证的 manifest/segment 链；读侧同时检查 scope、摘要/seal、lineage、generation 和 `revoke_fence_proven`，并在有效 ALLOW 返回前复读证据。current 缺失、未证明、链不完整、摘要失配、scope 不符或读取错误均保持 PENDING/DENY，不回退旧 head、snapshot、raw source 或未认证缓存。证据：[`repository.rs:342-351`](../../../astral-db/src/repository.rs#L342-L351)、[`engine.rs:460-471`](../../../policy-engine/src/engine.rs#L460-L471)、[`authorization_projection_repository.rs`](../../../astral-db/src/authorization_projection_repository.rs#L1-L44)。

**legacy 边界**：旧 `authorization_projection_head/outbox`、`projection_generation` 与 `READY` 语义仍可在迁移/对账和未声明 strict capability 的测试 repository 中出现；旧 `ProjectionWorker` 不再把 CARD/RULE_SET snapshot rebuild 或旧 READY 推进作为当前生产完成证明。ELIGIBILITY head 仍独立服务于资格缓存失效，不替代 canonical 授权证据。

### 7.2 migration/backfill 与旧数据收敛边界

**事实**：`20260822000001_rule_set_projection_schema_repair.sql`、`20260822000002_snapshot_validity_windows.sql` 等旧链修复 migration 只描述 schema/backfill 工具和历史快照证据；`20260825000002_incremental_projection_archive.sql` 是 canonical grant/delta/manifest/segment/current 的 creator-only migration，不负责既有数据 backfill。`20260827000002_legacy_snapshot_tables_decommission.sql` 是带前置条件的 standby script，不能据文件存在推断旧表已经 DROP。

**剩余边界**：目标环境必须分别证明 migration 已应用、旧 writer 已停止写快照、既有 grant ledger 已 backfill/rehearsal、current pointer 的证明闩已建立、worker 已 drain/replay、strict read gate 已验收和正式流量已切换。任一 schema shape、历史 lineage、摘要或数据库状态无法证明时，canonical projector/read gate 保持 Blocked/PENDING/DENY。

### 7.3 旧 snapshot version 与 canonical generation 的分层边界

**事实**：`version_no`、旧 `projection_generation` 和旧 head 状态只描述 legacy snapshot 表/兼容 writer-correlation 的历史版本关系。删除旧快照或重置旧版本不能改变 canonical current pointer 的证明状态，也不能使未证明历史变成可读授权。

canonical 证据的版本关系由 current pointer 指向的 manifest/segment、parent lineage、generation、semantic/dependency hash 和 `revoke_fence_proven` 共同证明；任何 proof 缺失或不一致都进入 PENDING/DENY。

### 7.4 equal-priority winner 的当前排序边界

**事实**：RuleSet 快照 winner 对 priority 相同且 effect 相同的候选使用最低 `entry_id` 作为最终 tie-break，已不依赖数据库返回顺序；CARD 纯逻辑 winner 选择仍保留输入先序语义，不能把两条排序合同混写。证据：RuleSet 重建排序 [`side_effects.rs:704-761`](../../../astral-trustgraph/src/api/side_effects.rs#L704-L761)；卡快照排序 [`side_effects.rs:396-439`](../../../astral-trustgraph/src/api/side_effects.rs#L396-L439)。

**剩余边界**：CARD 路径尚未在同 priority、同 effect 时引入统一 `rule_id` tie-break；该局部确定性边界不影响已落地的 RULE_SET `projection_generation` read gate。

### 7.5 legacy L2/L2.5 fail-closed 与 canonical reader 分界

**事实**：未声明 strict capability 的 legacy/test repository 仍对旧 L2/L2.5 阶段保持 fail-closed：旧 `permission_rule_snapshot` 读取错误不会被委托路径遮蔽，只有明确无匹配才继续读取带代次证明的 projected delegation；raw/source reader 仅用于 realtime/一致性巡检。该兼容行为不代表生产 `SqlxRuleRepository` 仍使用旧阶段。

生产 repository 直接使用 published-evidence reader；current/manifest/segment 读取错误、未证明或 scope 不符均不进入旧 L2/L2.5，也不产生 ALLOW。

### 7.6 source-type ownership gap

**缺口**：`permission_rule` 当前同时承载 `MANUAL`、`DELEGATION` 等来源，RuleSet 则通过 `rule_set`/`rule_set_entry`/`card_rule_set_ref` 另行承载共享规则。读侧对 legacy L2 快照、实时巡检、legacy L2.5 委托源查询分别使用不同 source/type 过滤（生产 strict reader 只消费 canonical published evidence，不按旧 source/type 过滤旧快照）：[`astral-db/src/repository.rs:517-615`](../../../astral-db/src/repository.rs#L517-L615)；写侧 `RuleRepository::create_rule` 接受调用方传入 `source_type`，见 [`rule_repository.rs:181-205`](../../../astral-trustgraph/src/repository/rule_repository.rs#L181-L205)。

当前没有一个跨 `rule_set_entry`、`permission_rule`、`permission_delegation` 与快照表的统一 source-type owner 注册/校验契约，能够回答“某一来源由谁写、由哪个 aggregate 递增、由哪个快照消费、由哪个审计事件追踪”。这会使“规则集共享变化如何完整 fan-out 到卡”“DELEGATION 规则与 delegation 表的双写是否始终同事务”等问题依赖调用路径约定，而不是一张可验证的 owner 矩阵。该项是架构 ownership gap，不将现有各路径的局部事务描述为全局闭合。

### 7.7 审计旁路与投影主状态分离

**事实**：审计写入是 MQ-first；MQ 未初始化或发布失败时走 DB fallback，DB fallback 重试一次，最终调用 `record_audit` 结构化留痕，且不阻塞权限判定。见 [`astral-common/src/audit.rs:88-163`](../../../astral-common/src/audit.rs#L88-L163)。RabbitMQ producer 的 payload 有 `message_id` 字段，通用 envelope 由 producer 生成 messageId；见 [`astral-mq/src/producer.rs:231-247`](../../../astral-mq/src/producer.rs#L231-L247)。

**事实**：MQ 消费幂等使用短 processing lease，成功后写 24 小时完成标记，失败释放 lease，可再次投递；见 [`astral-mq/src/consumer.rs:360-464`](../../../astral-mq/src/consumer.rs#L360-L464)。审计 quarantine replay worker 另有 60 秒 SQL lease，并且只在 broker publish confirmation 后确认 durable replay row，见 [`audit_replay_worker.rs:1-8`](../../../astral-trustgraph/src/service/audit_replay_worker.rs#L1-L8)、[`audit_replay_worker.rs:282-299`](../../../astral-trustgraph/src/service/audit_replay_worker.rs#L282-L299)。

**事实（legacy 边界）**：普通审计旁路不改变投影状态。“RULE_SET worker 推进旧 head READY 前写入 `REBUILD_SNAPSHOT` 审计证据”的合同只属于 legacy/迁移对照历史：旧 worker 现在对 CARD/RULE_SET 事件只做终态 `mark_processed`，不再重建快照、写 `projection_generation` 或推进已删除的旧 READY。RuleSet source mutation 仍在同一事务写入 `event_id`、`source_generation`、`operation_id` 关联证据；canonical 侧的发布审计关联由 `AuthorizationProjector` 在发布事务内落盘，`AuthorizationArchiveWorker` 在归档 proof 中保留整链证据。旧 projection worker 的兼容状态推进见 [`projection_worker.rs:195-443`](../../../astral-trustgraph/src/service/projection_worker.rs#L195-L443)。

**事实**：审计与投影各自拥有 durable/lease/retry 机制，但 RuleSet source/rebuild 证据通过 `event_id`、`source_generation`、`operation_id` 关联；migration backfill 使用稳定 operation id 与幂等 upsert。审计证据存在不单独授权；普通 audit consumer 已处理也不替代 projection READY。

## 8. 五链审查结论

### 8.1 调用链

**事实**：canonical 调用链为 source repository/service → grant ledger + delta event → `AuthorizationProjector` → manifest/segment/current durable CAS → published-evidence reader → `PolicyEngine`; `AuthorizationArchiveWorker` 独立处理 superseded manifest 的 proof-before-complete。旧 `ProjectionWorker` 只处理 legacy writer-correlation 与 ELIGIBILITY 资格缓存失效。
**结论**：文档将 CARD per-card、ELIGIBILITY qualification、RULE_SET shared snapshot 三条投影通道分开；兼容入口只保留 API/trait 形状，不代表仍有旧的 `PermissionRuleService` 或 `SqlxRuleRepositoryExt` 运行时 owner。

### 8.2 逻辑链

**事实**：canonical 生产读侧不以旧 head 的 `READY`、`source_generation == projected_generation` 或 snapshot `projection_generation` 作为单独准入条件，而是验证 current pointer 指向的 manifest/segment 完整链、scope、摘要/seal、parent lineage、generation 与 `revoke_fence_proven`，并在有效 ALLOW 前复读。旧 head/snapshot 的代次比较仅保留在 legacy/test 或迁移对账路径。
**结论**：任何目标设计都必须保留“未能证明版本时 PENDING/拒绝”的默认方向，不能用旧 snapshot 或 L2.5 的受 CARD gate 委托源查询代替缺失的共享 RuleSet 栅栏。

### 8.3 事故链

**事实**：canonical projector 对 lease/CAS/lineage/fence/摘要冲突分别执行有界 retry、Blocked、Quarantine 或 Unknown 处置；未知结果停止后续 mutation 并要求先对账。旧 `ProjectionWorker` 的 retry/mark_processed 和 ELIGIBILITY cache eviction 失败只影响兼容通道，不改变 canonical read gate。canonical current/manifest/segment 读取失败、证明闩未置位或 scope 不符均保持 PENDING/DENY。

### 8.4 数据链

**事实**：canonical 数据链由 grant revision、typed delta、impact plan、manifest/segment/current、archive intent/proof 和 evidence reader 组成；`version_no`、旧 head/outbox、旧 snapshot 与资格缓存属于不同的兼容或资格边界。canonical 读侧不会把旧表的行选择、旧 generation 或缓存命中当作 durable proof。
**结论**：任何 schema/worker 变更必须同步 source table、snapshot、head/outbox、cache payload、consumer stale check、migration/backfill 和读侧 gate。

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

### 9.5 决策：版本化热状态 + 异步旧版本归档（2026-08-26，切片已入库；strict gate 已接线代码层、正式切流验收未完成）

**目标决策**：已批准的 Rust canonical 投影采用版本化可变热状态：热状态当前版本随增量可变（测试中的 111→112 仅为版本推进示例）；增量事件携带 before-image/旧 segment 引用；发布经 current 指针原子 CAS；旧版本由异步归档 worker 产出 DB 内归档证明；segment 为内容寻址不可变行并带 segment-local seal；账本 ALLOW-only（普通 DENY 不持久化为 grant）；RULE_SET 贡献带 BASE/OVERLAY 标签。读侧目标门是严格 published evidence：`Ok(None)`/`Err`/非 Ready 一律 PENDING/DENY，禁止回退旧快照、raw source 或缓存。该读门已接线到代码层：生产 `SqlxRuleRepository` 以 capability marker 声明正式授权必须走 published evidence，`PolicyEngine::evaluate()` 在 marker 为真时消费严格读门并全程 fail-closed（证据：[`repository.rs`](../../../astral-db/src/repository.rs#L342-L351)、[`engine.rs`](../../../policy-engine/src/engine.rs#L933-L960)）；`evaluate_realtime()` 仍不消费该端口。真实 MySQL 集成验收、既有数据 backfill/rehearsal、缓存/摘要读侧迁移与正式切流验收保持待办，不得写成已完成，也不得据此宣称生产验收；direct/approval/delegation/rule-set 贡献已由 `grant_ledger_adapter` 接线进入新账本（projector 按 aggregate 消费），其真实集成验收包含在上述集成与切流待办内。

### 10. 验收要点（文档范围）

- **事实/缺口/目标决策可区分**：canonical grant/delta/manifest/segment/current 链、legacy head/snapshot 边界、ELIGIBILITY 资格链、migration/backfill 和剩余时间到期边界分开记录。
- **链路覆盖完整**：source mutation → grant revision/delta → compiler/projector lease → manifest/segment/current CAS → published-evidence reader → archive proof；旧 head/outbox、快照、缓存/MQ 仅作为兼容/迁移对照。
- **三类语义分离**：CARD/RULE_SET 旧 worker 只做 writer-correlation 终态收口，ELIGIBILITY 仍负责资格缓存失效；canonical 授权投影由 `AuthorizationProjector` 统一发布，`AuthorizationArchiveWorker` proof 后完成归档。
- **生产读门明确**：current pointer、manifest/segment seal、scope、lineage、generation 和 `revoke_fence_proven` 任一不足即 PENDING/DENY；旧 `READY`、`projected_generation`、`projection_generation` 或 `MAX(version_no)` 不能单独准入。
- **剩余边界诚实**：canonical creator-only migration 不负责既有数据 backfill；旧表 decommission、backfill/rehearsal、缓存/摘要迁移、wall-clock expiry、真实基础设施集成和正式切流均需独立证据。