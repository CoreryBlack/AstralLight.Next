# 分布式授权集群测试

> 继承说明：本目录及 `rust-s15/`、`pipeline/`、`archives/` 资产来自私有仓库 S15 提交
> `b38aaa7680f6c80e6841d05a17e08cd0e50627b1`。历史报告/JSON 已继承并对节点地址脱敏；
> 它们只用于回溯历史实验，不代表当前 `AstralLight.Next` 代码、当前部署或当前运行结果。
>
> CURRENT V6 证据边界：本目录的 Chat/Learn、Redis、旧 OPA 和三节点 runtime
> 叙述均为历史 baseline/comparison 或 retired compatibility evidence。即使历史
> 报告保留 `PASS` 场景数，也不得将其解释为当前 runtime、当前 Redis 依赖或真实
> 集成 `PASS`；当前 native profile 不使用 Redis。Direct Monitor health 只表示
> 服务直连运维观察，不能替代受保护 Monitor contract。资源退役须等待 canonical
> revoke、generation、published-evidence barrier；密码 delivery 只有在 notifier
> handoff 被证明时才可从 unavailable/`PENDING` 升级。`UNKNOWN`/`PENDING` 和跨
> aggregate completion 必须先按完整 receipt/evidence 对账。

把 `AuthorizationProjectionThreeNodeIntegrationTest` 从"同一 JVM 三 context + Testcontainers"升级为**真实的分布式架构测试**：
三个独立的 TrustGraph 进程（真实网络、真实共享 MySQL/Redis/RabbitMQ、真实消息投递）作为节点，测试协调器通过 HTTP 控制平面驱动场景。

## 一致性声明（security-preserving eventual consistency）

本实验验证的一致性是 **deny-biased eventual consistency with generation fencing**
（security-preserving，见 `Docs/实验/基准测试/scripts/README.md` 的 CS 场景定义）：

- **不承诺**强一致 / 线性化：收敛窗口内允许节点观察到 `AUTHORIZATION_PENDING` 或"fence 前窗口"的**前一合法状态**（该窗口与基准测试 CS_1 的"允许的 fence 前窗口单独计量"一致）。
- **禁止** unsafe authorization：revoke 世代 READY 之后，任何节点不得再产出 stale ALLOW；旧世代消息不得复活旧决策；并发 projector 不得产生重复终态。
- 每个场景绑定一个命名安全不变量（I1..I9、I12、I13，见下），断言即证据，指标写入结构化报告（invariants JSON），供论文逐条引用。

### 安全不变量矩阵

| 不变量 | 声明 | 指标 | 场景 |
|---|---|---|---|
| I1 | 至多一个有效投影 owner / 唯一终态 | `terminal_transitions == 1`、`losing_claim_processed == 0` | S1、S10 |
| I2 | revoke fence READY 后无 stale ALLOW | `stale_allow == 0`、`stale_allow_snapshots == 0` | S2、S3、S9 |
| I3 | 过期 owner 不能提交副作用 | `obsolete_owner_commit == 0`、`terminal_transitions == 1` | S5 |
| I4 | 世代不丢失 | `source_generation == 变更数`、`superseded == N-1`、`processed == 1` | S6、S9 |
| I5 | 幂等标记不抑制重投递的失效副作用 | `cache_key_deleted == true` | S7 |
| I6 | ABAC 资源属性变更跨节点收敛 | `all_nodes_deny == true` | S8 |
| I7 | 解绑推进 revoke fence 并跨节点生效 | `node_b_deny && node_c_deny` | S4 |
| I8 | 收敛窗口有界（revoke → READY → 全节点 DENY） | `window_ms > 0`、`projection_latency_ms` | S2 |
| I9 | 决策证据链跨节点自洽 | `evidence_rows`、`revoke_fence_advanced` | S11 |
| I10 | fence 前进后旧 ALLOW 被仲裁拒绝 | `arbiter_deny == 1`、`verdict_reason == R1_FENCE_DENY` | S12 |
| I11 | 仲裁不可证明时 fail-closed（DEFER → 拒绝） | `arbiter_defer == 1`、`reason_code == EVIDENCE_MISSING/R4_UNPROVABLE` | S13 |
| I12 | 节点 JVM 被 kill/restart 后不复活 stale ALLOW | `allow_during_down == 0`、`restart_window_ms` | S14 |
| I13 | 专用 Redis 容器 stop/restart 后不复活 stale ALLOW | `allow_during_down == 0`、`allow_after_restart == 0`、`down_window_ms` | S15 |

> 说明：S14/S15 由编排脚本执行**真实故障注入**（按 run-scoped pidfile 精确 kill 节点 JVM；对 run-scoped 专用 Redis 容器执行 `docker stop/start`），通过 marker/ack 协议与协调器 JUnit 同步；`processActuallyRestarted` / `redisActuallyRestarted` 与故障计数器写入 `ScenarioReport`。**不触碰共享 `astral_bench_redis`(6381) 与其它共享容器。**

## 实验注册表与统一术语

### 执行层

| 层 | 拓扑 | 驱动适配器 | 可证明内容 | 不能自动继承的内容 |
|---|---|---|---|---|
| `contract` | 同一 JVM 内三个 Spring context + Testcontainers | `InJvmClusterNode` | 共享 MySQL/Redis/Rabbit 语义、并发断言、AB-A/B/C/D | 进程隔离、真实跨主机网络、真实进程崩溃 |
| `remote` | 三个独立 TrustGraph JVM + HTTP 控制面 + 共享 MySQL/Redis/Rabbit | `RemoteHttpClusterNode` | 进程隔离、真实控制面调用、真实共享基础设施连接 | 未实现的 broker fault、`process-crash`、`tc/netem` |
| `single-host-three-processes` | 当前主机三个独立 JVM | 编排脚本 + remote adapter | 先验证进程隔离和控制面协议 | 不等价于三主机网络或异构硬件结果 |
| `three-hosts` | 三台主机经 SSH/SCP 和真实网络 | 编排脚本 + remote adapter | 真实主机/网络部署形态 | 当前仍使用 synthetic 状态刺激，不等价于主动网络攻击 |

### 场景编号与故障标签

`S1..S13` 是文档稳定编号，`scenarioKey` 是报告和代码使用的稳定名称；编号不依赖 Java 列表顺序。运行级 `faultMode=synthetic` 只表示本轮允许 synthetic stimulus，不代表每个场景都注入故障。场景级 profile 分为：

- `none`：正常 mutation/并发/证据链验证，没有手工故障注入；
- `stale-generation-message`：直接发布旧世代 refresh message；
- `expired-lease`：直接修改 lease 时间并配合 claim probe；
- `idempotency-mark-residue`：预置幂等标记和陈旧缓存后重投递；
- `attribute-refresh`：直接修改测试资源属性并发布刷新消息；
- `workload`：连续 mutation 或 projector contention，属于测试负载，不是节点故障。

当前代码的 `ScenarioReport` 仍以字符串 `metric/detail` 记录观察结果；下述 `expected/observed/unit/source` 是描述层语义，后续 schema 演进时再结构化，不能视为当前 JSON 已输出的字段。

### 正向场景注册表

| 编号 | `scenarioKey` | 测试方法 | 不变量 | 层级 | profile |
|---|---|---|---|---|---|
| S1 | `concurrentFirstProjectionRequests` | `AuthorizationClusterScenarios#concurrentFirstProjectionRequestsCreateOneHeadAndContiguousOutbox` | I1 | contract/remote | workload |
| S2 | `mutationVisibilityAfterRevoke` | `#mutationVisibilityAcrossNodesNeverReturnsStaleAllowAfterRevoke` | I2, I8 | contract/remote | none |
| S3 | `outOfOrderReadyMessages` | `#outOfOrderReadyMessagesNeverResurrectOlderDecision` | I2 | contract/remote | stale-generation-message |
| S4 | `ruleSetUnbind` | `#ruleSetUnbindPropagatesRevokeFenceAcrossNodes` | I7 | contract/remote | none |
| S5 | `staleLeaseReclaim` | `#staleLeaseIsReclaimedAndProjectionCompletesOnAnotherNode` | I3 | contract/remote | expired-lease |
| S6 | `alternatingMutations` | `#alternatingMutationsConvergeOnEveryNodeWithoutGenerationLoss` | I4 | contract/remote | workload |
| S7 | `crashAfterIdempotencyClaim` | `#crashAfterIdempotencyClaimStillInvalidatesCacheOnRedelivery` | I5 | contract/remote | idempotency-mark-residue |
| S8 | `abacAttributeChange` | `#abacResourceAttributeChangeConvergesAcrossNodes` | I6 | contract/remote | attribute-refresh |
| S9 | `mutationStorm` | `#mutationStormNeverExposesStaleAllowAndConvergesWithoutLoss` | I2, I4 | contract/remote | workload |
| S10 | `concurrentProjectors` | `#concurrentProjectorsDoNotDuplicateTerminalState` | I1 | contract/remote | workload |
| S11 | `decisionEvidenceChain` | `#decisionEvidenceChainIsSelfConsistentAcrossNodes` | I9 | contract/remote | none |
| S12 | `conflictingDecisionArbitration` | Rust `arbiter::tests::s12_conflicting_decision_arbitration_denies` | I10 | contract（Rust 纯函数）/remote（控制面 `/arbiter/arbitrate`） | none |
| S13 | `arbiterUnavailableFailsClosed` | Rust `arbiter::tests::s13_arbiter_unavailable_fails_closed` | I11 | contract（Rust 纯函数）/remote（控制面） | none |
| S14 | `processCrashMidRevoke` | `#processCrashMidRevokeNeverResurrectsStaleAllow` | I12 | remote（`faultMode=process-crash`） | process-crash |
| S15 | `redisRestartMidRevoke` | `#redisRestartMidRevokeNeverResurrectsStaleAllow` | I13 | remote（`faultMode=redis-restart`） | redis-restart |

## 正向场景卡片

每张场景卡统一描述：研究问题、fixture、刺激序列、观测与通过条件。所有场景都在 `@BeforeEach` 通过 `ClusterTopology.resetDatabase()` 和 `flushRedis()` 清理测试数据；远端执行仍要求显式 data-reset approval。

### S1：并发首次投影请求

- **研究问题**：两个节点同时提交同一卡片的首次授权变更时，是否只产生一个 durable head，并保持连续 generation？
- **Fixture**：card `7001`，node-a/node-b 并发写入 `resource=99` 的 ALLOW rule，priority `50`。
- **操作序列**：`CountDownLatch` 同时释放两个 writer；等待写入完成；由协调器逐节点 pump，直到 head `READY` 且三节点均有 refresh receipt。
- **观测**：head 是否存在且 `READY`；`source_generation`、`projected_generation`；outbox 行数和 generation 序列。
- **通过条件**：head source/projected 均为 `2`；outbox generation 精确为 `[1,2]`；没有丢行或重复 head。
- **证据与边界**：报告写入 I1 的 generation/outbox 指标。并发调度是测试刺激，数据库事务、head/outbox 和 projector 是真实路径；不模拟消息故障或进程崩溃。
- **代码**：`AuthorizationClusterScenarios.java:73-115`。

### S2：撤销可见性与全节点收敛

- **研究问题**：revoke commit 到 READY 之间，系统是否避免新的 stale ALLOW，并在 timeout 内让所有节点稳定 DENY？
- **Fixture**：card `7002`、resource `42`；先创建 ALLOW 并确认 node-c 可见。
- **操作序列**：node-a 删除规则；在 PENDING/投影过程中循环评估 node-c 并统计 `staleAllow`、`pending`；继续 pump；再等待 node-a/b/c stable DENY。
- **观测**：stale ALLOW 数、`AUTHORIZATION_PENDING` 样本数、READY 时间、全节点 DENY 时间、refresh receipts。
- **通过条件**：`staleAllow == 0`；READY 后三节点均 DENY；I8 记录窗口和投影延迟。
- **收敛解释**：`windowMs` 表示本次运行在配置 timeout 内观察到的 revoke-to-safe 窗口，不是理论上界、SLO 或跨所有硬件的固定保证；当前只有 S2 记录 convergence。
- **代码**：`AuthorizationClusterScenarios.java:128-193`。

### S3：旧世代 READY 消息乱序

- **研究问题**：generation 1 的迟到消息能否在 generation 2 revoke 后复活旧授权？
- **Fixture**：card `7003`、resource `7`；先完成 grant generation 1，再完成 revoke generation 2。
- **操作序列**：构造 `sourceGeneration=1`、`revokeFence=0` 的旧 `PermissionRefreshMessage`，直接发送 Rabbit exchange/routing key；等待消费者处理。
- **观测**：node-a/node-c 决策、obsolete-generation 处理结果、快照和缓存是否保持 revoked 状态。
- **通过条件**：两节点均 DENY，旧 generation 不得产生 ALLOW 或覆盖新快照。
- **边界**：Rabbit consumer 和 generation fence 是真实路径；旧消息由协调器直接注入，属于 synthetic message injection，不是真实网络乱序，也不证明 broker 被攻击时的安全性。
- **代码**：`AuthorizationClusterScenarios.java:204-249`。

### S4：规则集解绑与 revoke fence

- **研究问题**：BASE ruleset 解绑后，权限是否沿投影、消息和 L1 缓存失效链路跨节点关闭？
- **Fixture**：card `7001`、resource `8`；创建 MANUAL ruleset 和 ALLOW entry。
- **操作序列**：绑定 `BASE`；pump 并确认 node-c ALLOW；解绑；再次 pump 直到 READY/receipts；评估 node-b/node-c。
- **观测**：bind/unbind 后的 head generation/revoke fence、node-b/node-c decision、`perm:refs`/ruleset 缓存失效结果。
- **通过条件**：解绑后 node-b/node-c 均 DENY，且 I7 的 revoke fence 跨节点生效。
- **边界**：没有手工消息、Redis 或 lease 故障注入；README 中 stale-cache threat 是模型覆盖，不代表 S4 每次都人为制造缓存故障。
- **代码**：`AuthorizationClusterScenarios.java:260-286`。

### S5：过期 lease reclaim

- **研究问题**：一个 projector 失去 lease 后，另一个节点能否安全 reclaim，且旧 owner 不得提交副作用？
- **Fixture**：card `7002`、resource `11`，node-a 创建 ALLOW pending event。
- **操作序列**：node-b 安装 claim probe 并 claim；确认 active lease；通过 SQL 将 `lease_expires_at` 设置为过去时间；node-c pump reclaim；释放 node-b probe。
- **观测**：lease owner/status、node-b/node-c pump 结果、`processed_by`、`terminal_transitions`、最终 decision。
- **通过条件**：node-c 完成；node-b obsolete owner commit 为 `0`；outbox `PROCESSED`、lease 释放、`terminal_transitions == 1`。
- **边界**：lease CAS、reclaim 和 owner-fenced terminal update 是真实机制；SQL 过期时间和 probe 是 synthetic crash/lease-expiry substitute，不是真实 JVM 被杀或自动恢复。
- **代码**：`AuthorizationClusterScenarios.java:298-381`。

### S6：交替 grant/revoke

- **研究问题**：连续交替变更是否丢失 generation，且每次 READY 状态都与源授权一致？
- **Fixture**：card `7003`、resource `13`。
- **操作序列**：5 轮保存 ALLOW、pump、确认 node-b ALLOW，再删除同一 rule、pump、确认 node-b DENY；共 10 次 mutation。
- **观测**：每轮 source generation 单调性、node-b decision、最终三节点 decision。
- **通过条件**：每轮 generation 严格递增；最终三节点 DENY；`finalGeneration == 10`；I4 通过。
- **边界**：这是 workload，不是故障注入；不等价于高并发生产吞吐或性能 benchmark。
- **代码**：`AuthorizationClusterScenarios.java:392-436`。

### S7：幂等标记残留后的重投递

- **研究问题**：consumer 在幂等 claim 后崩溃时，重投递是否仍执行安全相关 cache invalidation？
- **Fixture**：card `7002`、resource `14`；先完成 ALLOW，再写入 stale card cache。
- **操作序列**：预置 `mq:idempotent:PERMISSION_REFRESH:<messageId>`；构造相同 messageId 的 refresh；直接发布 Rabbit；轮询 card cache。
- **观测**：stale card cache 是否删除、重复消息是否被短路、最终 decision/cache 状态。
- **通过条件**：cache key 在 10 秒内消失；I5 `cache_key_deleted=true`。
- **边界**：redelivery 处理和实际失效逻辑被测；Redis mark/cache/message 是 synthetic 构造，不是真 consumer 进程崩溃。
- **代码**：`AuthorizationClusterScenarios.java:447-499`。

### S8：ABAC 属性变化

- **研究问题**：资源属性从满足条件变为不满足条件后，三节点本地属性缓存是否都被刷新？
- **Fixture**：subject `15` 初始 `ACTIVE`；card `7004`、resource `15`；ALLOW 条件为 `status == ACTIVE`。
- **操作序列**：三节点先评估 ALLOW 以热身；直接 JDBC 更新为 `ARCHIVED`；构造当前 generation/fence refresh 并发布；循环评估三节点。
- **观测**：三节点 decision、属性缓存刷新后的重新读取、all-node deny 时间。
- **通过条件**：三节点最终全部 DENY；I6 `all_nodes_deny=true`。
- **边界**：属性更新和 refresh 由测试直接注入，属于 synthetic stimulus；不代表真实业务属性 API、网络延迟或恶意修改数据库。
- **代码**：`AuthorizationClusterScenarios.java:509-562`。

### S9：mutation storm 与 generation fence

- **研究问题**：projector 尚未运行时连续 grant/revoke 是否会产生 stale ALLOW、丢 generation 或错误终态？
- **Fixture**：card `7005`、resource `19`。
- **操作序列**：连续保存 6 条 ALLOW，再连续删除 6 条；中间不 pump；storm 中对 node-c 评估 20 次；随后统一 pump。
- **观测**：storm 期间 stale ALLOW/pending 样本；head generation；outbox 状态和 last_error；最终 snapshot。
- **通过条件**：`staleAllow == 0`；source generation `12`；12 行 outbox 中 11 行 superseded、1 行真正 processed；无 PENDING；最终无 ALLOW snapshot；I2/I4 通过。
- **边界**：连续 mutation 是 workload，不是消息丢失、网络分区或进程故障注入。
- **代码**：`AuthorizationClusterScenarios.java:575-665`。

### S10：并发 projector claim

- **研究问题**：两个 projector 同时面对一个 pending outbox 时，lease CAS 是否保证唯一 owner 和唯一终态？
- **Fixture**：card `7006`、resource `21`；node-a 创建 ALLOW pending event。
- **操作序列**：node-b claim 后由 probe 阻塞；确认 active lease；node-c 并发 pump；检查失败者无 snapshot且 outbox仍 PENDING；释放 node-b。
- **观测**：node-c processed 结果、lease owner/status、snapshot 行数、terminal transition、最终 decision。
- **通过条件**：node-c `processed == 0`；无失败者 snapshot；最终一行 PROCESSED、lease 释放、`terminal_transitions == 1`；I1 通过。
- **边界**：claim probe 是 synthetic slow-node synchronization；真实被测的是 lease CAS、owner fence 和 terminal transition，不是真实进程 crash 或网络分区。
- **代码**：`AuthorizationClusterScenarios.java:677-758`。

### S11：决策证据链

- **研究问题**：decision 与 projection metadata 是否来自同一次 `PolicyEngine.evaluate()`，而不是与事后读取的 mutable head 错配？
- **Fixture**：card `7002`、resource `23`；grant READY 后再 revoke READY。
- **操作序列**：三节点调用 `evaluateWithEvidence` 记录 grant rows；删除 rule 并再次投影；三节点记录 revoke rows。
- **观测**：`requestId`、nodeId、decision、reason、projection status、head/projected generation、revoke fence、cacheSource。
- **通过条件**：grant 阶段三节点 ALLOW/READY 且 head==projected；revoke 阶段三节点 DENY/READY 且 revoke fence 增长；I9 通过。
- **证据边界**：`requestId` 是控制面报告行标识，不等价于生产 trace/span ID；projection metadata 已绑定同次 evaluation，但当前 validator 主要做最低字段/数量校验，不是完整的独立证据重算。
- **代码**：`AuthorizationClusterScenarios.java:773-838`。

### S12：冲突决策仲裁（执剑人）

- **研究问题**：当某节点在 revoke fence 前进后仍产出旧 ALLOW 时，执剑人仲裁是否按版本序拒绝，而不是按票数放行？
- **Fixture**：card `7007`、resource `24`；node-a 在 gen105/fence0 产出 READY ALLOW（stale），node-b/node-c 在 gen106/fence1 产出 READY DENY。
- **操作序列**：协调器从三节点 `evaluateWithEvidence` 收集证据行（decision + gate 版本字段），调用 `POST /arbiter/arbitrate`；断言 verdict/reasonCode。
- **观测**：`verdict`、`reasonCode`、`arbiter/stats` 的 `signals/arbitrations/denies`。
- **通过条件**：`verdict == DENY` 且 `reasonCode == R1_FENCE_DENY`；I10 通过（`arbiter_deny == 1`）。
- **裁决语义**：执剑人依据 `(source_generation, revoke_fence)` 版本序，最新 READY DENY 严格新于最新 READY ALLOW → DENY；同版本分歧走多数一致，平局/非多数 DENY（fail-closed）。裁决不是第四投票者。
- **边界**：Rust 侧已落地纯函数内核（`policy-engine/src/arbiter.rs`）与控制面端点（TrustGraph `POST /main/api/v1/arbiter/arbitrate`）；真实三主机 campaign 需在 `RemoteHttpClusterNode` 增加证据收集与 `/arbiter` 调用，当前远端闭环未实现该编排。
- **代码（Rust）**：`policy-engine/src/arbiter.rs`（`arbitrate`）、`astral-trustgraph/src/api/arbiter.rs`、`astral-trustgraph/src/service/arbiter.rs`。

### S13：仲裁不可用 → fail-closed

- **研究问题**：执剑人自身不可用（证据缺失 / gate 不可读 / 证据收集失败）时，系统是否拒绝而不是放行？
- **Fixture**：card `7008`、resource `25`；证据收集失败（空证据或全部 gate 缺失/未 READY）。
- **操作序列**：直接调用 `POST /arbiter/arbitrate` 传入不可证明证据；断言 DEFER 且调用方按 fail-closed 处理。
- **观测**：`verdict == DEFER`、`reasonCode == EVIDENCE_MISSING / R4_UNPROVABLE`、`arbiter/stats` 的 `defers`。
- **通过条件**：DEFER 被映射为拒绝（现有 `AUTHORIZATION_PENDING` 出口），I11 通过（`arbiter_defer == 1`）；不允许"无法证明 → 猜一个"。
- **边界**：仲裁可用性只影响"冲突能否被解析"，不影响"无法解析时拒绝"这一安全底线；执剑人不构成 Byzantine 容错（README A4/A5 边界不变）。
- **代码（Rust）**：`policy-engine/src/arbiter.rs`（`arbitrate` / `R4_UNPROVABLE`）。



**考虑的故障类型（threat scope）**：

1. **消息延迟 / jitter** —— 作为威胁模型和后续故障注入目标；当前正向场景没有 `tc/netem` 或 broker delay 注入。
2. **消息乱序** —— S3 通过直接发布旧世代消息进行 synthetic 替代；不是实际网络乱序。
3. **节点崩溃** —— S5/S7 通过 lease 过期、probe 和幂等标记残留模拟 crash 后状态；当前没有真实进程 kill/restart。
4. **资源不对称** —— S5/S10 通过 claim probe 观察慢 worker/owner contention；不等价于真实资源耗尽。
5. **缓存陈旧** —— S4/S7/S8/S9 覆盖缓存失效语义；其中部分陈旧状态由测试直接构造。

**明确排除（out of scope）**：

- **恶意篡改数据库**、**root 攻击**、**Byzantine 节点**。
- **为何不建模恶意节点伪造 generation**：head/outbox 的世代计数器由 owner-fenced 事务在同一授权系统内写入；伪造 generation 等价于获得数据库写权限，已超出授权系统的信任边界。本实验的安全性质建立在"命令侧与投影侧都是可信内部进程"的前提上，审稿需要的 adversarial 边界在此明示。

### 攻击者模型（Attacker Model）

本节定义主动攻击者与前述故障模型的边界。当前实验不是 Byzantine-resilience 或入侵检测实验；它验证的是在可信服务进程和共享基础设施前提下，授权系统对主动请求以及可观测消息/缓存异常的安全响应。

#### 保护资产

1. **授权决策**：用户、租户、卡片、资源和动作之间的 ALLOW/DENY 结果，尤其是 revoke 后不得继续产生的 stale ALLOW。
2. **投影状态**：`authorization_projection_head` 的 generation/revoke fence、outbox 终态和快照版本关系。
3. **跨节点失效语义**：规则解绑、ABAC 属性变化和缓存失效必须传播到所有节点。
4. **证据完整性**：一次 decision 的 projection metadata、generation、revoke fence、decision 和 reason 必须来自同一次引擎评估。
5. **控制面与运行隔离**：test-control token、run-scoped DB/Redis/队列/receipt 前缀以及 destructive reset 的审批边界。

#### 攻击者类别与能力

| 类别 | 假设能力 | 当前实验处理 | 边界 |
|---|---|---|---|
| A0 未认证外部请求者 | 可访问 test-control HTTP 路径并发送任意请求，但没有有效 `X-Test-Control-Token` | 控制器要求非空 token，并使用 constant-time 比较；错误 token 的单测覆盖拒绝路径 | 不等价于完整网关、TLS 或生产身份认证评估 |
| A1 已认证但无权用户 | 可调用正常业务授权入口，尝试读取或继续使用已撤销卡片权限 | `PolicyEngine.evaluate()` 的投影 gate、revoke fence 和 I2/I6/I7/I8 场景约束结果 | 当前没有独立的恶意用户流量生成器或越权攻击率统计 |
| A2 重放/延迟消息的观察者 | 可使旧世代消息重复或延迟到达，但不能伪造可信数据库 generation | I2、I4、I5 及 synthetic out-of-order/idempotency 场景验证旧消息不会恢复旧授权 | 当前消息注入由可信测试协调器执行，不代表 RabbitMQ 已被攻击者控制 |
| A3 被盗 test-control token 的攻击者 | 可调用测试控制面的 mutation、pump、ruleset 和 evaluate 接口 | token 必须显式配置，默认控制面关闭，脚本要求双重实验门禁和 run-scoped 目录 | token 泄露、密钥轮换、mTLS 和端到端密钥吊销不在本实验范围 |
| A4 被攻陷或恶意的 TrustGraph 节点 | 可伪造 worker、generation、projection 或消息内容 | 明确排除；I1-I9 不构成 Byzantine 防御证明 | 需要节点认证、消息签名/证明、仲裁或拜占庭容错协议 |
| A5 共享存储攻击者 | 可直接写 MySQL、Redis 或 RabbitMQ，或执行跨 run 的删除/篡改 | 明确排除；脚本只对 runId、专用 DB、Redis DB 和 reset approval 做编排级门禁 | 不证明数据库/RabbitMQ/Redis 被攻陷后的完整性 |
| A6 网络主动攻击者 | 可监听、重放或篡改节点间 HTTP 流量 | 当前脚本支持 `http://`，控制面主要依赖 token；此能力不纳入安全结论 | HTTPS/mTLS、请求签名、nonce/重放窗口和网络隔离需单独实验 |

#### 攻击目标与安全目标

攻击者目标被定义为：

- 在 revoke fence 已 READY 后制造 stale ALLOW；
- 重放旧 generation 或重复消息，使旧快照重新生效；
- 在没有有效控制 token 时执行 mutation、ruleset bind/unbind 或 projection pump；
- 让 evidence 中的 decision 与另一时刻的 head/generation/fence 拼接，伪造审计结论；
- 通过跨 run 的 DB/Redis/队列复用污染其他实验或触发未授权 destructive reset。

对应的安全目标是：

- **G1**：I2/I7/I8 保证撤销后授权结果以 deny-biased 方式收敛，不产生 unsafe ALLOW；
- **G2**：I1/I3/I4/I5 保证 owner、generation、终态和重投递副作用不会因并发或重放失控；
- **G3**：I9 保证 decision evidence chain 与同一次 PolicyEngine evaluation 绑定；
- **G4**：控制面在缺少有效 token、实验批准或 run 隔离条件时 fail-closed；
- **G5**：对 A4-A6 不作防御性结论，只将其列为后续主动攻击实验。

#### 结论边界

因此，本文可以声称的是：**在 A0/A1 的有限请求模型、A2 的非 Byzantine 消息重放/延迟模型，以及可信节点和共享存储假设下，系统保持 deny-biased eventual consistency 和 generation fencing。** 本文不能声称系统已经抵抗被攻陷节点、被盗凭据、数据库篡改、消息代理入侵或网络中间人攻击。

### 消融实验注册表

| 消融 | 机制 | 契约层 | 远端层 | 关闭后的可观测 failure |
|---|---|---:|---:|---|
| AB-A | worker generation fence | 可执行 | 可执行 | 旧 generation 重建 stale snapshot，outbox 保持 PENDING |
| AB-B | L1 refs/status eviction | 可执行 | 可执行 | `perm:refs` 残留，revoke 后 node-c 继续 ALLOW |
| AB-C | publisher confirm | 可执行 | 未实现 | head/outbox 看似终态但 refresh event 丢失、零 receipt |
| AB-D | owner fence | 可执行 | 可执行 | 第二 projector 越过 active lease 并完成 outbox |

AB-C 不进入远端 validator、远端完成分母或真实三主机结论。远端需要 RabbitMQ binding fault、插件/shovel 断链或等价 broker 注入能力；当前没有实现，因此只报告契约层结果。

### AB-A：关闭 worker generation fence

- **研究问题**：旧 generation 事件到达 newer READY head 后，generation fence 是否阻止旧快照重建？
- **操作**：card `7002`/resource `31` 保存 ALLOW；直接把 head 人工推进至 generation `2`/`READY`；再 pump generation `1`。
- **机制开启**：事件被标记 `SUPERSEDED_BY_NEWER_GENERATION`；outbox `PROCESSED`、terminal transition 为 `1`、stale ALLOW snapshot 为 `0`。
- **机制关闭**：旧 generation 重建 stale ALLOW snapshot，outbox 保持 `PENDING`；报告 failure observation 为 `stale_allow_snapshot`。
- **观测**：head generation/status、outbox `status/last_error/terminal_transitions`、ALLOW snapshot count。
- **执行边界**：contract/remote 均可执行；直接 SQL 推进 head 是 synthetic MySQL state fabrication，不是真实 broker 延迟或网络乱序。
- **代码**：`AuthorizationClusterAblationScenarios.java:60-113`。

### AB-B：关闭 L1 refs/status eviction

- **研究问题**：解绑后共享 Redis 中的 unversioned refs/status 缓存是否必须失效，才能阻止 stale ALLOW？
- **操作**：card `7001`/resource `32` 创建并绑定 BASE ruleset；确认 `perm:refs:1:7001` 存在且 node-c ALLOW；解绑并等待投影 READY。
- **机制开启**：refs key 被删除，node-c DENY；报告 `stale_allow=0`、`refs_cache_present=false`。
- **机制关闭**：refs key 保留，node-c 继续 ALLOW；报告 failure observation 为 `stale_allow`。
- **观测**：Redis refs key、node-c decision、投影 READY 和三节点 receipts。
- **执行边界**：contract/remote 均可执行；这是共享 Redis 状态观察和 synthetic control-plane pump，不是缓存分区或恶意 Redis 写入。
- **代码**：`AuthorizationClusterAblationScenarios.java:122-163`。

### AB-C：关闭 publisher confirm

- **研究问题**：publisher confirm 是否阻止“消息未路由但 head/outbox 已终态”的丢事件状态？
- **操作**：仅 contract 层通过 RabbitAdmin 删除 refresh routing binding；保存 card `7004`/resource `34` 的 ALLOW 并 pump；恢复 binding。
- **机制开启**：returned/nack 被检测；head 和 outbox 保持非终态/PENDING，保留 at-least-once retry。
- **机制关闭**：publish 被当作成功；head `READY`、outbox `PROCESSED`，但 receipts 为 `0`。
- **观测**：processed count、head status、outbox status/attempts、refresh receipts。
- **执行边界**：只在 `AuthorizationProjectionClusterAblationTest` contract 层执行；远端 `RemoteHttpClusterNode` 不提供 broker binding fault 操作，不能将 AB-C 契约结果当成远端结果。
- **代码**：`AuthorizationClusterAblationScenarios.java:181-231`。

### AB-D：关闭 owner fence

- **研究问题**：active lease 是否能阻止第二 projector 抢占并完成同一 outbox？
- **操作**：card `7006`/resource `33` 创建 pending event；node-b claim 后由 probe 阻塞；确认 active lease；node-c 并发 pump。
- **机制开启**：node-c processed `0`、row 保持 `PENDING`；node-b 释放后唯一完成。
- **机制关闭**：node-c 越过 active lease，processed `1`，row 由 node-c 终态完成；failure observation 为 `concurrent_claim_processed`。
- **观测**：worker IDs、lease owner/status、node-c result、processed_by、terminal transitions、snapshot count。
- **执行边界**：contract/remote 均可执行；claim probe 是 synthetic contention/slow-node synchronization，不是真实 JVM crash 或网络分区。
- **代码**：`AuthorizationClusterAblationScenarios.java:241-311`。

### 消融报告解释

契约层消融测试每个 JUnit 方法独立启动三个同 JVM context；远端消融每次只运行一个受支持的 AB-A/B/D 模式，并由 validator 检查对应 invariant/scenario/failure observation。`expectedFailure == observedFailure` 只证明报告字段结构一致，当前 validator 不会重新执行 SQL/Redis/Rabbit 语义，因此论文仍应同时保留 JUnit log、报告和 validation artifact。


## 分层、角色与运行限制

### 能力矩阵

| 能力 | contract | remote |
|---|---:|---:|
| 三节点逻辑拓扑和共享场景断言 | 有 | 有 |
| 三个 Spring context | 有 | 无 |
| 生产 boot jar 进程隔离 | 无 | 有 |
| HTTP test-control plane | 无 | 有 |
| 真实跨主机网络 | 无 | 拓扑依赖 |
| 直接 SQL/Redis/Rabbit synthetic stimulus | 有 | 有，协调器操作共享 store |
| AB-A/B/D | 有 | 有 |
| AB-C broker binding fault | 有 | 无 |
| 自动 owner 三轮轮换 | 无 | 无 |
| `replicate > 1` 矩阵 | 无 | 无，脚本 fail-closed |

### 角色语义

`DIST_TEST_OWNER_NODE`/`APP_NODE_OWNER` 表示启动期模板、默认域和一致性修复的 startup writer，不等于投影 outbox 的 lease owner。S5/S10 中的 projection owner 由 `workerId` 和 outbox `lease_owner` 表示，reclaiming node 可能与 startup writer 不同。当前脚本只执行单轮 owner 配置；README 中的 node-a/node-b/node-c 表是计划轮换，不是已经自动执行的 campaign matrix。

### 统一测量定义

- **source generation**：命令侧为卡片 source mutation 分配的单调世代；每次有效 mutation 应增加 1。
- **projected generation**：快照和缓存投影已经成功准备并由 head 发布的世代。
- **READY**：head 可供 PolicyEngine 使用，且 source/projected generation 满足稳定性条件。
- **PENDING**：新 source generation 尚未安全发布；PolicyEngine 允许返回 `AUTHORIZATION_PENDING`，不能把它解释为最终 DENY。
- **SUPERSEDED**：旧 outbox generation 被 newer head 取代，不能重建或发布旧快照。
- **terminal transition**：outbox 从 PENDING 到最终 PROCESSED/obsolete 终态的有效一次转换；I1/I3 要求不能重复。
- **refresh receipt**：节点 consumer 对 run-scoped refresh 消息的处理回执；它证明消费者处理过消息，不单独证明 decision 一定正确。
- **stale ALLOW**：revoke fence 已 READY 或 source 状态已不再允许时仍返回 ALLOW，属于安全失败。

S2 的 `windowMs` 和 `projectionLatencyMs` 是本次测试中用 epoch timestamps 计算出的观测时长；“bounded”只表示在预设 timeout 内观测到全节点安全状态，不是理论上界或生产 SLO。当前只有 S2 写入 `Convergence`，其余场景的等待成功由断言和 helper 体现。

|---|---|---|---|
| 契约层（CI 快速） | `AuthorizationProjectionThreeNodeIntegrationTest`（`@Tag("cluster")`） | 本地 Docker + Testcontainers，同 JVM 三 Spring context | 共享存储/消息语义 |
| 消融层（契约） | `AuthorizationProjectionClusterAblationTest`（`@Tag("cluster")`） | 同上，每方法以对应消融开关起 3 context | 机制必要性（负向实验） |
| **分布式层（真实）** | `RemoteClusterAuthorizationTest`（`@Tag("cluster-remote")`） | 三台主机（或单机三进程）+ 生产 boot jar + 共享基础设施 | 真实进程隔离、真实网络、真实跨节点消息投递 |

两层共享同一套场景逻辑：

- `cluster/remote/ClusterNode` — 节点抽象（evaluate / saveRule / deleteRule / ruleset / pump / claim-probe / **evaluateWithEvidence**）
- `cluster/remote/InJvmClusterNode` — Spring context 实现（契约层）
- `cluster/remote/RemoteHttpClusterNode` — HTTP 控制平面实现（分布式层，仅 JDK HttpClient）
- `cluster/remote/ClusterTopology` — 协调者视图（共享 JDBC/Redis/Rabbit + fixture reset + 投影收敛 + **收敛窗口测量**）
- `cluster/remote/AuthorizationClusterScenarios` — 13 个共享场景（S1..S13，见不变量矩阵），每场景记录不变量/证据/收敛到 `ScenarioReport`
- `cluster/remote/AuthorizationClusterAblationScenarios` — 4 个消融配方（AB-A..AB-D）；其中 AB-C 仅由契约层执行，远端闭环只支持 AB-A/B/D。
- `cluster/remote/ScenarioReport` — 结构化报告（invariants / evidence / convergences），驱动写 `target/cluster-report/*.json` 或 `-Ddist.test.report.dir`

### 决策证据链

`POST /evaluate/with-evidence` 返回同一次 `PolicyEngine.evaluate()` 捕获的 projection metadata；控制器不再在决策返回后重新读取可变 head。每行记录 `{request_id, node_id, card_id, resource_id, projection_status, head_generation, projected_generation, revoke_fence, cache_source, decision, reason}`。
审稿人可逐条回答"为什么这个节点返回 ALLOW/DENY"（S11，I9）。

## 论文研究问题映射

场景不应在论文中按 Java 方法顺序平铺，而应按安全问题组织：

| 研究问题 | 核心实验 | 扩展/消融 | 主要结论 |
|---|---|---|---|
| RQ1：generation fencing 能否阻止撤销后的授权复活？ | S2 | S3、AB-A | revoke fence READY 后无 stale ALLOW；旧世代消息不能覆盖新状态 |
| RQ2：分布式投影能否保持唯一 owner 和唯一终态？ | S1、S10 | S5、AB-D | 并发创建、lease reclaim 和 projector contention 不产生重复终态 |
| RQ3：缓存和属性失效能否保持撤销安全？ | S4、S8 | S7、AB-B | ruleset、card cache 和 ABAC 属性变化跨节点收敛到安全结果 |
| RQ4：授权 decision 的证据链能否保持自洽？ | S11 | 无 | decision 与同次 evaluation 的 projection metadata、generation 和 fence 一致 |
| RQ5：冲突仲裁能否进一步降低 unsafe authorization 的观测概率？ | S12 | S13 | fence 前进后旧 ALLOW 被版本序仲裁拒绝；仲裁不可证明时 fail-closed（DEFER → 拒绝） |

S2 是核心安全实验；S3/AB-A 是 generation ordering 扩展，S4/S7/S8/AB-B 是缓存和属性扩展，S1/S5/S10/AB-D 是 ownership 扩展，S11 是证据链实验，S12/S13 是冲突仲裁扩展（执剑人）。该组织用于论文叙事，不改变报告中的 S1-S13 稳定引用。

### 安全机会指标

S2 除 `staleAllow == 0` 外，报告还统计撤销期间的 `evaluationCount`、`allowCount`、`pendingCount`、`denyCount`、`unsafeAllowCount` 和 `unsafeAuthorizationWindowMs`。当前操作性定义为：

```text
unsafeAllowCount = ALLOW observations after revoke commit
                    and before the node is in a valid pre-revoke window
unsafeAuthorizationWindowMs = first deny-biased observation - revoke commit time
```

该指标用于证明测试确实进行了评估采样，而不是仅在最终状态做一次检查。它不把所有 pre-fence 合法窗口都当成 unsafe ALLOW；正式论文应同时报告评估计数、PENDING 计数和 DENY 计数。

#### S2 多轮统计（三主机真实运行，n=6）

S2 采用三阶段采样（200 次 PENDING 窗口紧循环 → pump 至 READY → READY 后继续采样直到捕获 ≥5 次稳定 DENY），三台主机独立无故障共跑六轮，得到撤销窗口的统计分布：

| 指标 | mean | sd | 95% CI（t=2.571, df=5） |
|---|---|---|---|
| S2 windowMs | 2548.7 | 207.1 | [2331.3, 2766.1] |
| S2 projectionLatencyMs | 2373.3 | 201.9 | [2161.4, 2585.2] |
| S2 evaluationCount | 206.0 | 0.0 | [206.0, 206.0] |
| unsafeAllowCount | 0（六轮合计） | — | — |

六轮每轮均为 `eval=206 allow=0 pending=201 deny=5 unsafe=0`；`deny=5` 来自 READY 后过渡采样，证明 PENDING→DENY 转换可观测，而非仅在协调器事后断言。n=6 下 CI 宽度较 n=3 收窄约 42%。

#### tc/netem 故障注入梯度（50ms 延迟 + 丢包/乱序）

`run_netem_delay.sh` 支持 `DIST_TEST_NETEM_LOSS`（如 `1%`/`5%`）与 `DIST_TEST_NETEM_REORDER` 参数，写入 fault ledger。三主机实测（节点 A→共享基础设施路径）：

| 注入 | S2 window (ms) | projection (ms) | unsafeAllow | gate |
|---|---|---|---|---|
| 0（基线，n=6 均值） | 2549 | 2373 | 0 | PASS |
| 50ms 延迟 | 4149 | 3481 | 0 | PASS |
| 100ms 延迟 | 9239 | 7968 | 0 | PASS |
| 150ms 延迟 | 12607 | 10786 | 0 | PASS |
| 50ms + 丢包 1% | 6318 | 5611 | 0 | PASS |
| 50ms + 丢包 5% | 6491 | 5583 | 0 | PASS |
| 50ms + 乱序 1% | 5880 | 5228 | 0 | PASS |
| 50ms + 乱序 5% | 5780 | 5175 | 0 | PASS |
| node-c 路径 50ms（对称） | 17455 | 15959 | 0 | PASS |

结论：延迟、丢包与乱序梯度下收敛窗口单调放大，但 206 次窗口评估全部保持 `unsafeAllow=0` 且最终全节点 DENY；延迟/丢包/乱序只影响收敛时长，不破坏 deny-biased 安全性。200ms 延迟时节点 A 启动连不上共享基础设施会 fail-closed 中止，属于可用性边界而非安全失败。

### 节点独立性证据

远端 `/worker-id` 探针返回并写入报告的节点证据包括：

- `nodeId`：逻辑节点身份；
- `workerId`：该 JVM projection worker 的实例身份；
- `configFingerprint`：运行配置摘要；
- `jvmStartTime`：JVM 启动时间；
- `processIdentityHash`：由进程管理器 identity 摘要得到的非敏感哈希。

远端启动门禁要求三个节点的 workerId、JVM 启动时间和 process identity hash 唯一，报告 validator 也会再次校验。该证据用于证明三个 endpoint 对应三个独立 runtime，不是性能指标，也不等价于主机可信证明。

### Linux 网络延迟实验（独立、默认关闭）

`run_netem_delay.sh` 是独立的 Linux-only harness。它不会自行启动授权 campaign，而是包裹一条已批准的 campaign 命令：

```text
DIST_TEST_APPROVED=true
DIST_TEST_NETEM_APPROVED=true
DIST_TEST_NETEM_CLEANUP_APPROVED=true
DIST_TEST_RUN_ID=<run-id>
DIST_TEST_NETEM_INTERFACE=<interface>
DIST_TEST_NETEM_TARGET_NODE=node-a|node-b|node-c
DIST_TEST_NETEM_DELAY=200ms
DIST_TEST_NETEM_JITTER=50ms
./run_netem_delay.sh ./run_distributed_cluster_test.sh
```

脚本在缺少 Linux、`tc`、批准项、runId、网卡、目标节点或待执行命令时 fail-closed；应用 qdisc 后无论 campaign 成功或失败都会尝试删除 qdisc，并把 `REQUESTED/APPLIED/CLEARED/ABORTED` 写入 fault ledger。可选 `DIST_TEST_NETEM_LOSS`（丢包率，如 `1%`/`5%`）与 `DIST_TEST_NETEM_REORDER`（乱序率）会追加到 netem qdisc 参数并记录在 ledger。以上三主机实测数据见「tc/netem 故障注入梯度」；本 harness 仍要求用户批准、节点级网卡确认和恢复验证。

## 生产侧改动（默认行为不变）

| 改动 | 配置 | 说明 |
|---|---|---|
| 条件化调度 | `TrustGraphSchedulingConfiguration`（`app.scheduling.enabled`，默认 true） | 分布式节点 `app.scheduling.enabled=false` 关闭投影 job/每日 cron 竞争 |
| 测试控制平面 | `TestControlController`（`app.test-control.enabled`，默认 false）+ `X-Test-Control-Token` | 仅在显式开启且 token 非空时注册可用路由；每次请求都必须通过 constant-time token 校验。含 `POST /evaluate/with-evidence`（决策证据链） |
| 启动写入门控 | `app.node-owner`（默认 true） | 仅 owner 节点（`DIST_TEST_OWNER_NODE` 指定）执行 SuperAdmin 模板/默认域/一致性修复写入 |
| DLX 队列属性化 | `app.messaging.permission-refresh-dlx-queue`（默认 `astral.dlx.permission.refresh`） | 每 run 隔离 DLX 重试队列 |
| 消融开关（默认 false） | `app.authorization-projection.ablation.skip-worker-generation-fence` / `skip-l1-refs-status-eviction` / `skip-owner-fence`、`app.messaging.ablation.skip-publisher-confirm` | 负向实验专用；默认路径（含 unfenced mapper）不变，见消融矩阵 |

## 节点运行时（生产 boot jar）

每个节点以真实 `AstralTrustGraph-*-boot.jar` 启动，环境变量全量覆盖（不依赖 gitignored `application.yml` 默认值）：

- `DB_HOST/DB_PORT/DB_NAME/DB_USERNAME/DB_PASSWORD`、`REDIS_HOST/REDIS_PORT/REDIS_PASSWORD`、`RABBIT_HOST/RABBIT_PORT/RABBIT_USERNAME/RABBIT_PASSWORD`、`JWT_SECRET`/`SPRING_JWT_SECRET`
- `SERVER_PORT`（每节点不同，如 9011/9012/9013）
- `APP_SCHEDULING_ENABLED=false`、`APP_PERMISSION_CONSISTENCY_CHECK_SAMPLE_RATE=0`
- `APP_TEST_CONTROL_ENABLED=true`、`APP_TEST_CONTROL_TOKEN`
- `APP_NODE_OWNER`（仅 `DIST_TEST_OWNER_NODE` 指定节点=true，可轮换）
- `APP_MESSAGING_PERMISSION_REFRESH_QUEUE` / `APP_MESSAGING_PERMISSION_REFRESH_DLX_QUEUE` / `APP_MESSAGING_REFRESH_RECEIPT_PREFIX`（run+node 隔离）
- `SPRING_DATA_REDIS_DATABASE`（run 专属 DB index，与共享 Redis 隔离）
- 当前共享场景中的 lease 过期、幂等标记残留和旧世代消息注入均属于 `faultMode=synthetic` 的契约化故障，不是进程 crash 或网络乱序。远端脚本默认使用 `synthetic` 标签；真实 `process-crash`、`tc/netem` 和 owner×replicate 矩阵尚未实现，相关输入会 fail-closed，不进入真实结果分母。

### 节点硬件

授权路径**不涉及 GPU / 加速器**：三节点为异构 CPU 服务器（Intel Xeon Platinum 8268 / Xeon E5-2690 v2 / AMD Ryzen 7 7735HS），
每节点报告 CPU / 内存 / NIC 即可，无 A100 类硬件参与。
遵循 benchmark 既有规则：**P99 等指标不跨异构硬件平均**，安全性质的结论与硬件无关（见"角色轮换"）。

### 角色轮换

节点角色（WRITER = 启动期 owner 写库）不固定：`DIST_TEST_OWNER_NODE` 指定本轮 owner，三轮轮换各节点任一次 WRITER。

| Run | WRITER（APP_NODE_OWNER=true） | 硬件 |
|---|---|---|
| 1 | node-a | Xeon E5-2690 v2 |
| 2 | node-b | Xeon Platinum 8268 |
| 3 | node-c | Ryzen 7 7735HS |

安全性质（I1..I9）必须三轮均成立——证明结论依赖**架构**而非"恰好某台硬件当协调者"。
正确性实验的结论不随角色轮换变化；基准测试的吞吐/延迟结果另按硬件异构分别报告。

## 编排脚本

`Docs/实验/分布式测试/run_distributed_cluster_test.sh`（fail-closed）：

1. 校验全部环境变量；缺失即写 `ATTEMPT_ABORTED.json` 并退出 78，不执行任何 SSH/启动。终态 marker（`ATTEMPT_COMPLETE.json` / `ATTEMPT_ABORTED.json`）从不被覆盖或删除：复用已有 campaign 目录（显式 `DIST_TEST_CAMPAIGN_DIR`）时，先于目录门禁触发的 preflight 失败只输出脱敏 reason/status 并保留既有证据；marker 提交经 no-clobber rename（`mv -n`）+ 哈希校验完成，临时 `.tmp` 文件在拒绝/失败路径一律清理。
2. 以 run 专属目录部署 boot jar（校验 JAR 存在；SHA-256 校验由使用者先行确认）。`DIST_TEST_MODE=rust` 时改为部署预构建的 `astral-trustgraph` 二进制（`DIST_TEST_RUST_BIN_PATH`），env 文件使用 Rust 侧显式契约变量（`DATABASE_URL`/`REDIS_URL`/`RABBITMQ_URL`/`JWT_ACCESS_SECRET`/`JWT_REFRESH_SECRET`/`JWT_ACCESS_ISSUER`/`JWT_REFRESH_ISSUER`/`JWT_ACCESS_AUDIENCE`/`JWT_REFRESH_AUDIENCE`/`GATEWAY_HMAC_SECRET`/`INTERNAL_SERVICE_SECRET`/`GATEWAY_INTERNAL_SERVICE_SECRET`/`CORS_ALLOWED_ORIGINS`/`CORS_ALLOW_CREDENTIALS`/`SESSION_GRANT_CLAIMS_MODE`/`LISTEN_ADDR`/`ASTRAL_NODE_ID`/`ASTRAL_TEST_CONTROL_*`）。这些 flat 名到配置字段的映射由 `astral-common/src/config/mod.rs` 的 `apply_flat_env_overrides` **显式**完成（config-rs 会把 `_` 当层级分隔符，`DATABASE_URL` 之类会展开成 `database.url` 而永远无法命中扁平字段），不依赖 config-rs 推断；harness 从不复制 `application.yml` 到节点目录。凭据经 python3 标准库百分号编码后只写入 0600 env 文件。
3. 节点以 env 文件（`umask 077`）启动——密钥不落命令行/日志。
4. 就绪探针：轮询每节点 `worker-id` 端点。Java 模式发送 `X-Test-Control-Token`；Rust 模式必须走完整中间件链，改用带 Gateway v3 签名的 `probe_worker_id.py`（`X-Gateway-Auth/Ts/Signature` + 身份头 + `X-Test-Control-Token`），不新增任何 `SKIP_PATHS` 或认证旁路。
5. 运行 `RemoteClusterAuthorizationTest`（基线）或按 `DIST_TEST_ABLATION` 单方法（generation-fence / l1-eviction / owner-fence，每轮以对应开关重启节点）。Rust 模式没有场景协调器（见下节），探针成功后按 BLOCKED 终止。
6. 结果写入 `ATTEMPT_COMPLETE.json`（含 `ownerNode` / `ablation` / `reportPaths`）或 `ATTEMPT_ABORTED.json`；两者经同一 no-clobber 提交路径写入，绝不覆盖既有终态 marker（refusal 时保留原证据并只输出脱敏 reason）。
7. 仅当 `DIST_TEST_CLEANUP_APPROVED=true` 才按 run 专属 pidfile 停止节点（无 `pkill -f` 通配）。

两种拓扑：

- **单机三进程（首次验证）**：`DIST_TEST_SINGLE_HOST=1`，同一主机 3 个独立 java 进程 + 本地/远端共享 MySQL/Redis/Rabbit。
- **三主机（真实异构）**：`DIST_TEST_SSH_USER` + `DIST_TEST_NODE_{A,B,C}_HOST`，经 SSH/SCP 分发与启动。

### 环境变量清单

```text
DIST_TEST_MODE=java|rust                                                                  # 缺省 java（行为不变）；rust 见下节
DIST_TEST_APPROVED=true
DIST_TEST_DATA_RESET_APPROVED=true
DIST_TEST_DB_HOST / DIST_TEST_DB_PORT / DIST_TEST_DB_NAME / DIST_TEST_DB_USER / DIST_TEST_DB_PASSWORD
DIST_TEST_REDIS_HOST / DIST_TEST_REDIS_PORT / DIST_TEST_REDIS_DATABASE（必填，1..15 专用 DB） / DIST_TEST_REDIS_PASSWORD（可选）
DIST_TEST_RABBIT_HOST / DIST_TEST_RABBIT_PORT / DIST_TEST_RABBIT_USER / DIST_TEST_RABBIT_PASSWORD
DIST_TEST_JWT_SECRET                                                                      # 仅 java 模式；Rust 模式用下面两条独立 JWT 密钥
TEST_CONTROL_TOKEN
DIST_TEST_TEST_GROUP=cluster-remote                                                       # 仅 java 模式
DIST_TEST_NODE_A_URL / DIST_TEST_NODE_B_URL / DIST_TEST_NODE_C_URL
JAR_PATH=<AstralTrustGraph-*-boot.jar>                                                    # 仅 java 模式
DIST_TEST_SSH_USER / DIST_TEST_NODE_A_HOST / DIST_TEST_NODE_B_HOST / DIST_TEST_NODE_C_HOST   # 三主机拓扑
DIST_TEST_OWNER_NODE=node-a|node-b|node-c                                                     # 可选，角色轮换
DIST_TEST_ABLATION=generation-fence|l1-eviction|owner-fence                                   # 可选，消融运行（仅 java 模式）
DIST_TEST_REPORT_DIR=target/cluster-report                                                     # 可选，相对于 AstralLight/ 项目根
DIST_TEST_FAULT_MODE=synthetic                                                           # 当前远端共享场景的明确标签；process-crash 未实现（仅 java 模式）
DIST_TEST_CLEANUP_APPROVED=true                                                          # 可选，显式清理
```

### Rust 模式（DIST_TEST_MODE=rust）：签名就绪探针，BLOCKED 边界

Java 模式行为逐字节不变；`DIST_TEST_MODE=rust` 是显式 opt-in 的 Rust 侧 harness 适配。

**做什么**：校验全部输入（缺失、格式非法，或探针必需变量未 export——`PROBE_ENV_NOT_EXPORTED:<NAME>`——即写 `ATTEMPT_ABORTED.json` + exit 78，不做任何 SSH/启动）→ 部署预构建 `astral-trustgraph` 二进制（与 Java 相同的 run 专属 env 文件 + pidfile + 批准式清理信封）→ 以 `probe_worker_id.py` 对三个节点做带签名的 `worker-id` 就绪探针 → 校验三节点 `workerId` 两两不同（进程独立性证据）→ 写 `ATTEMPT_ABORTED.json`（`RUST_SCENARIO_COORDINATOR_NOT_IMPLEMENTED`）并以 78 退出。

**BLOCKED 边界（如实分类，绝不 PASS）**：仓库内唯一场景协调器是 Java `RemoteClusterAuthorizationTest` 套件；Rust 场景协调器不存在，因此 rust 模式**只产出就绪证据（三节点签名探针通过 + workerId 互异），不产出任何场景结果**，按证据契约记为 BLOCKED，不进入结果分母。`DIST_TEST_ABLATION`、`DIST_TEST_FAULT_MODE≠synthetic`、`DIST_TEST_EXPERIMENT` 在 rust 模式一律 fail-closed 拒绝，不静默忽略。

**Rust 模式必填环境变量（全部 fail-closed）**：

```text
DIST_TEST_MODE=rust
DIST_TEST_RUST_BIN_PATH=<预构建 astral-trustgraph 二进制>
DIST_TEST_JWT_ACCESS_SECRET=              # >=32 字符，写入节点 env 的 JWT_ACCESS_SECRET
DIST_TEST_JWT_REFRESH_SECRET=             # >=32 字符，写入 JWT_REFRESH_SECRET；
                                          # 与 access 密钥相互独立（不存在 JWT_SECRET
                                          # 共享别名，refresh 签名材料绝不与 access 共用）
GATEWAY_HMAC_SECRET=                      # >=32 字符，与节点运行值一致；占位标记/空白被拒绝
INTERNAL_SERVICE_SECRET=                  # >=32 字符（K_LG）；独立密钥，禁止复用/派生自
                                          # GATEWAY_HMAC_SECRET
GATEWAY_INTERNAL_SERVICE_SECRET=          # >=32 字符（K_GI）；独立密钥
DIST_TEST_PROBE_ACTION=read               # GET → monitor:read，固定契约
DIST_TEST_PROBE_PRINCIPAL_KIND=PLATFORM_USER
DIST_TEST_PROBE_USER_ID / _IDENTITY_CARD_ID / _USER_CARD_ID / _USER_CARD_DOMAIN_ID / _USER_CARD_TENANT_ID
                                          # 正整数；该身份必须已持有已发布的 monitor:read 授权
DIST_TEST_PROBE_TOKEN_ID / _TOKEN_USE / _CLAIMS_VERSION / _ACTION_CODES / _USER_ROLES
                                          # 签名绑定文本字段（无空白）
```

五把密钥输入（Gateway HMAC、K_LG、K_GI、JWT access、JWT refresh）必须两两不同；任一对相等即在任何 SSH/启动之前以 `INDEPENDENT_SECRETS_MUST_BE_DISTINCT` 中止。shell preflight 现按探针（`probe_worker_id.py`）同等口径对全部五把密钥做形状校验，并在任何 SSH/节点启动之前执行：长度不足 32（`INVALID_SECRET_TOO_SHORT:<NAME>`）、含任何空白或控制字符（`SECRET_HAS_WHITESPACE_OR_CONTROL:<NAME>`——比探针更严：节点 source 的是 env 原值而探针签名用 trim 后副本，任何空白都会让两者失同步、只能落进 240s 就绪轮询，故提前拒绝）、或大小写不敏感地命中占位标记子串 `change-me`/`changeme`/`replace`/`example`/`todo`/`tbd`/`xxxx`/`password`/`test`（`SECRET_IS_KNOWN_PLACEHOLDER:<NAME>`，与探针 `SECRET_PLACEHOLDER_MARKERS` 同一集合）。marker 只记录变量名等脱敏 reason token，绝不回显值，也不含任何密钥或密钥片段。

**探针环境继承契约（显式 export，不依赖调用方隐式行为）**：`probe_worker_id.py` 是子进程，只从进程环境读取输入；`wait_ready_rust` 在每次调用探针前显式 `export` 且仅 export 探针必需的变量（`GATEWAY_HMAC_SECRET`、`TEST_CONTROL_TOKEN`、`DIST_TEST_PROBE_ACTION`、`DIST_TEST_PROBE_PRINCIPAL_KIND`、五个 `DIST_TEST_PROBE_*_ID` 正整数字段、五个签名文本字段，共 14 个名字），值只经进程环境传递，绝不放入 argv/日志/marker。其余凭据（JWT access/refresh、K_LG、K_GI、DB/Redis/Rabbit）不做 broad-export，仍只写入 0600 节点 env 文件。preflight 对上述每个名字做 presence + exported 双重校验（`declare -p` 属性检查，值不回显）：缺失（`MISSING_ENV:<NAME>`）或未 export（`PROBE_ENV_NOT_EXPORTED:<NAME>`）都在任何 SSH/启动与 240s 就绪轮询之前以 exit 78 中止。协调器侧 export 范围按模式收敛：schema preflight 之前的那组共享存储/协调器 export（`DIST_TEST_DB_*`/`DIST_TEST_REDIS_*`/`DIST_TEST_RABBIT_*` 凭据及其余同名共享变量）只属于 Java 模式——Rust 模式没有 JUnit 协调器或 preflight fork，脚本自身不做这批 export，即不新增任何 DB/Redis/Rabbit 凭据 broad-export；探针子进程实际继承的环境等于调用方已 export 的全部变量，加上 `wait_ready_rust` 在调用探针前显式 export 的 14 个探针名字。脚本只保证自己不新增导出这批凭据；调用方自行 export 的值不在本脚本控制内，也无法被脚本隐藏（与 `wait_ready_rust` 的注释一致）。Java 模式的两处 export 块行为不变。

**flat env 契约（显式别名，非 config-rs 推断）**：`astral-trustgraph` 经 `AppConfig::from_files("application")` 启动；远程节点目录没有 `application.yml`，而 config-rs 的 `Environment` 源把 `_` 当层级分隔符（`DATABASE_URL` → `database.url`），flat 部署名原本全部丢失、节点在 secret/URL/CORS 校验处退出。现由 `astral-common/src/config/mod.rs` 的 `apply_flat_env_overrides` 显式映射：`DATABASE_URL`/`REDIS_URL`/`RABBITMQ_URL` → 连接串字段，`JWT_ACCESS_SECRET`/`JWT_REFRESH_SECRET`/`JWT_ACCESS_ISSUER`/`JWT_REFRESH_ISSUER`/`JWT_ACCESS_AUDIENCE`/`JWT_REFRESH_AUDIENCE` → 双 token profile（access 与 refresh 签名材料相互独立），`GATEWAY_HMAC_SECRET` → `gateway.hmac_secret`，`INTERNAL_SERVICE_SECRET` → K_LG，`GATEWAY_INTERNAL_SERVICE_SECRET` → K_GI，`CORS_ALLOWED_ORIGINS`（逗号分隔，条目 trim，空条目拒绝）与 `CORS_ALLOW_CREDENTIALS`（严格 bool，非法值启动失败且错误不回显值）→ CORS，`SESSION_GRANT_CLAIMS_MODE` → 同名字段。env 存在且非空白即覆盖，缺失或为空时保留 YAML/默认值。issuer/audience 与 CORS 值由 harness 写入固定非密钥合成常量（`dist-test-astral-access`/`dist-test-astral-refresh`/`dist-test-astral-api`/`dist-test-astral-session`、`https://dist-test.astral-cluster.invalid`——显式 https origin，绝不为通配符）。`LISTEN_ADDR` 与 `ASTRAL_*` 在 `AppConfig` 之外读取，不属于该契约。

**Rust 端点为什么需要签名探针**：`astral-trustgraph` 的 `GET /main/api/v1/internal/test-control/worker-id` 位于完整中间件链之后——(a) Gateway v3 身份头 HMAC 验签（`astral_common::middleware::gateway_signature`）、(b) `permission_check` 的 `monitor:read` 授权（路径映射复用已注册资源 `monitor`）、(c) 模块内常量时间 `X-Test-Control-Token` 校验。探针发送完整、如实签名的请求；harness 不新增 `SKIP_PATHS` 或任何中间件旁路（对应 `test_control.rs` 安全不变式 3）。探针签名的 canonical payload 为 15 行 Gateway v3（`astral-gateway-v3` 前缀 + method/path/user_id/principal_kind/token_id/identity_card_id/user_card_id/user_card_domain_id/user_card_tenant_id/token_use/claims_version/action_codes/user_roles/timestamp），与 Rust 实现 `compute_hmac_signature_v3` 逐字段对齐。离线验证（无网络）：

```bash
python3 "Docs/实验/分布式测试/probe_worker_id.py" --self-test
# 期望输出 SELF-TEST:PASS（复算 gateway_signature 单测锁定的 v3 golden vector）
```

**操作者前置责任（harness 不代替）**：rust 模式不运行任何迁移、不创建任何数据、不向节点复制 `application.yml`（或任何含凭据的配置文件）——专用数据库（含 schema/增量 DDL）与探针身份的 `monitor:read` 授权（经正式 source mutation 路径发放）必须事先就绪；`DIST_TEST_DB_NAME` 仍必须包含 `DIST_TEST_RUN_ID`。主机名/DB 名限 URL 安全字符（IPv6 字面量 fail-closed）；探针密钥只经进程环境传递（不落 argv/日志），探针日志只含脱敏 reason token 与非敏感身份 JSON。

### 报告产物

协调器把场景报告写入 `DIST_TEST_REPORT_DIR`（默认 `target/cluster-report/`），脚本收集到
`<campaign_dir>/reports/` 并在 `ATTEMPT_COMPLETE.json` 记录 `reportPaths`：

- `invariants-<runId>.json` — 每个场景的不变量检查（I1..I9，含 metric/detail）
- 证据链行（decision-evidence）与收敛窗口（window_ms / projection_latency_ms）同文件内

## 与 benchmark 三节点 campaign 的关系

- `AstralBenchmark` 的 `ClusterRunContext`/`run_native_cluster_campaign.sh` 属于**性能实验**（吞吐/延迟/故障注入），其 phase controller 与 reader workload 尚未实现，入口保持 fail-closed（exit 78）。
- 本分布式测试属于**正确性实验**：验证跨真实进程/主机的授权一致性语义。二者共享"三节点 + ZeroTier + 共享 MySQL/Redis/Rabbit"的部署形态，但本测试不伪造 benchmark 结果，benchmark 也不承担本测试的正确性断言。
- 消融边界：benchmark 的 `run_ablation_campaign.sh` 如实报告 `skipProjectionGate` / `skipGenerationFence` "关闭后行为不变、测不出差异"——那是**数值消融**。本实验的 `app.*.ablation.*` 开关关闭后**行为必然改变且可观测失败**——那是**机制必要性消融**。两类开关互不混淆：前者在 PolicyEngine 评估路径（`benchmark.ablation.*`），后者在投影 worker / 缓存失效 / 发布确认 / lease 路径（`app.*.ablation.*`），默认全部 false。

## 安全边界

- 仓库不出现真实主机/IP/凭据：全部经环境变量注入，`application.yml`（gitignored）不参与。
- 控制平面默认关闭；开启时必须配置非空 `app.test-control.token`，且每次请求都要求 `X-Test-Control-Token` 匹配。
- `DIST_TEST_DB_NAME` 必须是本轮专用数据库名，并包含 `DIST_TEST_RUN_ID`；脚本会在任何 schema/seed 或 `FLUSHDB` 之前拒绝未绑定 runId 的数据库名。
- 失败即中止并保留审计 marker；终态 marker（`ATTEMPT_COMPLETE.json` / `ATTEMPT_ABORTED.json`）从不被覆盖或删除——复用已有 campaign 目录时既有证据保留、只输出脱敏 reason/status，提交经 no-clobber rename（`mv -n`）+ 哈希校验，临时 `.tmp` 文件在拒绝/失败路径一律清理；不做隐式破坏性清理。
- 消融开关全部默认 false，默认路径（含 unfenced mapper）逐字节不变；负向实验仅由显式编排触发。
- 报告不含真实 IP/凭据：`ATTEMPT_COMPLETE/ABORTED.json` 只记录 runId/ownerNode/ablation/reportPaths。

### S14：节点 JVM 进程崩溃（真实 kill/restart）

- **研究问题**：grant READY 后 revoke commit（head PENDING），此时节点 JVM 被 kill 并重启，是否会产生 stale ALLOW 或丢失唯一终态？
- **Fixture**：card `7010`、resource `30`；node-a 创建 ALLOW 并 READY；node-a 删除规则。
- **操作序列**：协调器写 `process-crash-requested` → 编排脚本按 run-scoped `node.pid` 精确 `kill` 崩溃节点 JVM → 从同一 `node.env` 重启 `trustgraph-boot.jar`（新 workerId/processIdentityHash）→ 写 `process-crash-ack` → 协调器等待新 identity 后继续 pump 至 READY。
- **观测**：down 窗口期间 node-c 的 decision 采样（eval/pending/deny/allow）、restart 窗口 ms、最终三节点 decision。
- **通过条件**：`allowDuringDown == 0`；重启后三节点 DENY；`processActuallyRestarted=true`；I12 通过。
- **边界**：kill 目标严格来自 run-scoped pidfile，不使用 `pkill -f` 通配；这是真实进程崩溃/恢复，不等价于磁盘损坏、主机掉电或节点被攻陷。
- **代码**：`AuthorizationClusterScenarios.java`（S14），编排 `run_distributed_cluster_test.sh` 的 `process-crash` 分支。

### S15：专用 Redis 容器停机/恢复（真实 stop/start）

- **研究问题**：revoke commit 后专用 Redis 容器被 stop/start，down 窗口与恢复后是否产生 stale ALLOW？
- **Fixture**：card `7011`、resource `31`；node-a 创建 ALLOW 并 READY；node-a 删除规则。
- **操作序列**：协调器写 `redis-down-requested` → 编排脚本 `docker stop` **本轮专用**容器（`astral_dist_redis_<runId>`，独立端口，不触碰共享 `astral_bench_redis`）→ 写 `redis-down-ack` → 协调器在 down 窗口采样 node-c → 写 `redis-restart-requested` → 脚本 `docker start` 并等 healthy → 写 `redis-restart-ack` → 协调器恢复后采样并 pump 至三节点 DENY。
- **观测**：down/up 两阶段 decision 采样计数、down window ms、最终三节点 decision。
- **通过条件**：`allowDuringDown == 0 && allowAfterRestart == 0`；`redisActuallyRestarted=true`；I13 通过。
- **边界**：只对 run-scoped 专用容器操作；容器在退出时由清理 trap 删除（仅 `DIST_TEST_CLEANUP_APPROVED=true` 时）。
- **代码**：`AuthorizationClusterScenarios.java`（S15），编排 `redis-restart` 分支与专用容器生命周期。

## 2026-08-10 实测结果（三主机，节点2 驱动）

`Docs/实验/复现运行/dist-20260810/` 收录 33 个 COMPLETE campaign 的净化归档（marker、validation、reports、fault markers；不含 node.env 等凭据文件），`summary.csv` 为逐轮汇总。三主机为 Xeon Platinum 8268 / Xeon E5-2690 v2 / Ryzen 7 7735HS，共享 MySQL/Redis/RabbitMQ 部署在节点2，所有运行均通过 `validate_cluster_report.py` 校验。

| 组 | 轮次 | 结果 |
|---|---|---|
| 基线正向（11 场景，I1–I9） | 24 轮（owner-a×18、owner-b×3、owner-c×3；含 S2 hi-sampling） | 全部 `allPassed=true` |
| 无故障基线 S2 收敛窗口 | 15 轮 | windowMs mean 1952、sd 891、范围 346–2916；eval 合计 2320，`unsafeAllow=0` |
| netem/loss/reorder 梯度 | 9 轮 | 50/100/150ms 延迟、50ms+loss 1%/5%、50ms+reorder 1%/5%、node-c 50ms；windowMs 4128–17455，`unsafeAllow=0` |
| process-crash（S14/I12） | 3 轮 | `allowDuringDown=0`（23/22/24 采样），restart window 12.3–14.1s，全部通过 |
| redis-restart（S15/I13） | 3 轮 | down 采样 7/8/8（全部 PENDING）、up 采样 140–141（全部 PENDING），`allow=0`，down window ≈40.3–40.4s，全部通过 |
| 消融 | AB-A/B/D 各 1 轮 | `stale_allow_snapshot`、`stale_allow`、`concurrent_claim_processed` 与预期一致 |

> 说明：netem 与故障轮次的采样数差异来自受控窗口长度（15s 采样紧循环 vs marker/ack 等待期间采样）；所有轮次 `unsafeAllow=0`。S2 的 `windowMs` 是当轮观测窗口，不是理论上界或 SLO。消融开关默认全部 false，生产路径逐字节不变。
