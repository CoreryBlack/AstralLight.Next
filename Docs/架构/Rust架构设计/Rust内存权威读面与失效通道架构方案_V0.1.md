# Rust 内存权威读面与失效通道架构方案（V0.1）

> 状态：P0–P5 本地实现、主审及隔离验证已收口；2026-10-03 提交前重新执行 workspace check/clippy/test、整仓 fmt 与显式兼容全目标 lint，均通过。真实基础设施验收未执行，本文不构成部署或生产验收证明。
> 更新日期：2026-10-03
> 规范入口：[Rust 后端编码规范](../../规范/Rust后端编码规范_V1.0.md)。本文记录架构、实现边界和恢复语义，不覆盖仓库执行门禁。

## 1. 目标与边界

单机以一个 Tokio 组合进程承载 Identity、TrustGraph 和 Gateway。普通消息通过有界 `LocalBus` 传播，授权增量通过 `LocalProjectionBus` 交给单一投影 owner，在 Rust 进程内编译。正常直发不以数据库轮询、Redis 或 RabbitMQ 作为消息传输；MySQL 继续保存必须跨崩溃证明的业务事实。

正常、已预热且所有读门满足的权限评估和会话验证使用内存。零 DB 往返只覆盖已登记的读端口与资源类型，不覆盖管理列表、审计写入、统计、登录签发、冷回填、恢复或冻结的 Chat/Learn 业务。它也不表示整个 HTTP 请求绝无数据库操作。

多机和跨城保留 RabbitMQ。通道只传播失效与协调元数据，不把未证明的内存内容变成授权事实。没有实现分布式内存共识，也没有把权限消息另存为通用磁盘队列。

MySQL 的提交仍是 source 变更的线性化点。进程内入列、handler 返回、镜像安装、Rabbit confirm、ACK 和命令退出码分别表达不同阶段，均不能单独证明端到端业务完成。

## 2. 存储与传输职责

| 表面 | 当前职责 | 不承担的职责 |
|---|---|---|
| 进程内读面 | 已验证 published evidence、资格事实、组织准入、GlobalAdmin 事实、会话与受支持的资源归属、SoD 输入 | 未经严格证明的 source fallback、跨进程共识 |
| LocalBus / LocalProjectionBus | 有界路由、owner、顺序、去重、背压、完成等待与内存投影计算 | 崩溃后的 source 或发布证明 |
| RabbitMQ | 跨机器/区域传播，durable 节点队列、确认、DLX 与隔离 | 全局跨队列顺序、业务 exactly-once 或授权权威 |
| MySQL | source、grant revision/delta、head/outbox、审计关联、published pointer/manifest/segment、幂等和恢复事实 | 正常单机消息搬运 |
| Redis 兼容层 | 显式 `redis-compat` 构建及运行开关下的历史 adapter | 默认构建依赖或正式授权旁路 |
| 可选本地快照 | 缩短 warm-up 的 hint | authority、发布证明或恢复完成证明 |

默认 workspace 为 11 个成员；`astral-cache` 已移入 `exclude` 并保留自包含 manifest 和源码，Chat/Learn 继续冻结。`Cargo.lock` 中的 optional Redis 条目不等于默认编译树包含 Redis。兼容 API 的变更、替代入口、迁移和回滚登记见规范 §15.3；兼容窗口复核日为 2026-12-31，日期不会自动删除 API。

每个宿主在连接 DB 或启动 worker 之前，以自身 `cfg!(feature = "redis-compat")` 检查能力，并安装共同的冻结开关。公共 marker 的 feature 统一化不能代替宿主能力检查。宿主安装和历史库的环境回落共用一个 `OnceLock`：首值生效，同值幂等，异值拒绝，运行中不重新读取环境改变行为。

## 3. 单机组合运行时

```text
                 同一 Tokio 进程
  Gateway ── Identity ── TrustGraph / PolicyEngine
     │             │             │
     └──── 完整绑定、版本与健康读门 ─┘
                   │
      LocalBus + LocalProjectionBus + memory hub
                   │
      MySQL source / publication / audit / recovery
```

启动依次完成配置门、总线单次安装、单写者租约、可信状态预热、owner 装配和 readiness。MySQL `GET_LOCK` 的连接由组合进程持有；运行期监督同时核对连接身份和锁 owner。失联或身份变化不自动重新抢锁，停止对外服务并关闭读门。咨询锁只约束合作式写者，不能阻止未遵守协议的外部 SQL；生产环境仍须限制旁路写入。

必需 owner、投影 worker、会话恢复 worker 的死亡必须可观察。不可把进程存活、普通 LocalBus owner 存活当作投影 owner 可服务。必需 owner 失败进入独立、粘性的 runtime 故障门，普通心跳或 pointer 对账不能清除此门。恢复采取进程级重建，避免自动重放未知副作用。

任务由运行时持有，取消和退出按有界等待处理，超时 abort 并报告未证明结果为 UNKNOWN。关闭 future 取消、尚未开始 poll 的 supervisor 被丢弃和运行时提前退出均不得把内部恢复 task 脱离 owner；回收等待同样有期限。readiness 同时要求 LocalBus owners、投影 worker Alive 和 hub 健康，NotStarted 只在启动期限内等待，死亡和状态锁中毒拒绝服务。纯测试只验证这些状态机和受控任务语义；真实连接断开与崩溃验收仍未执行。

## 4. 写入与完成证明

### 4.1 Source 事务

CARD/RULE_SET 有效授权变更在同一短事务写入必要 source、grant revision/delta、适用 head/outbox 和审计关联。ELIGIBILITY 写入独立资格/缓存失效意图，不制造规则快照刷新。事务不包含网络、MQ/Redis、编译、镜像安装、重试或验收。

在 DB begin 前取得对应 source guard。hub 未安装时保留原部署语义；hub 已安装却无法取得 guard 时拒绝写入。guard 持有期间，正向内存读取和受保护的严格回退均拒绝。COMMIT 或 autocommit await 前武装取消栅栏，只有证明成功才解除；错误或取消保留 `uncertain_source`。另一个成功写者不能清除这次未知结果。

通用写者推进 source 与辅助纪元；组织专用写者只推进组织辅助纪元，但共享 active writer 门。begin/drop 清除正向会话和资格缓存，撤销 marker 保留。网络投递位于 source 提交之后。取消发生在已证明提交与直发之间时，由已落盘意图恢复，不能把未直发报为完成。

### 4.2 投影发布

投影 owner 在事务外编译，在发布事务内验证 lease、generation/token fence、lineage、manifest/segment/reference 和 current-pointer CAS。发布者与严格 reader 共用完整状态校验，返回不可变 `Arc<AuthorizationPublishedState>`。只有 COMMIT 已证明，才安装内存状态并解除对应事件的 pending。

pending 的完成身份包含 aggregate、event、operation、source generation 和覆盖的 revoke fence。同 source generation 的兄弟事件分别收口；per-grant `target_version` 不与 aggregate publication generation 比较。普通读回或镜像安装不能清除未证明事件。

未知发布使用 `PublicationUnknown`；提交已证明而镜像不可用使用 `CommittedMirrorUnavailable`。两者均不虚报本地完成；已成功 source 或 publication 不自动重放。已证明镜像故障可经严格回填/有界 durable 对账恢复；未知 source 需要独立写者结果证明。

### 4.3 直发与恢复

提交后先投影 delta 直发，再派发相同事务保存的 typed invalidation。LocalBus 完成等待有总时间预算；队列满、无 owner、关闭和超时分别返回明确失败或 UNKNOWN。Rabbit publisher confirm 仅证明 broker admission，远端完成须依赖 durable consumer/application proof。

`al_message_outbox` 保留为 typed intent、恢复和未知结果对账事实，未退役或删除。正常传输走直发；低频 claim-one relay 是提交后崩溃或 admission 失败的恢复路径。授权 delta 与 session outbox 的低频恢复 worker 同样不承担正常消息搬运。

健康本地 supervisor 只检查 owner 并更新单调心跳，不周期全表读取 MySQL。启动、suspect 或明确恢复时才执行有界 durable 对账。Rabbit 节点还需要 durable 水位/丢通知对账。心跳只能证明活性，不能清除 suspect 或未知 source。

## 5. 内存读取合同

### 5.1 Published evidence 与完整卡

卡片读面预登记全部 current 聚合，任一缺失、过期、pending、scope/lineage/generation/fence 不满足时不返回部分卡证据。命中在读取前后复检同域 token、active writer、健康和 source 状态；当前有效期在每次读取时重验。

冷 miss 使用有界 single-flight，严格 reader 返回整卡 commit-proven bundle。回填安装后确认每个状态确实安装、健康未因容量或同代冲突改变，再进行返回前同 token 检查。refill 自己推进的镜像版本不允许用来覆盖宿主早先读取的依据：宿主准入 token 仍失配时本次请求安全拒绝，后续请求重新评估。

### 5.2 资格、组织与 GlobalAdmin

资格正缓存以完整物理上下文、自然到期、每卡唯一纪元和 hub 原子读 token 绑定。installed hub 只有 Ready 才命中；active/unknown 拒绝；通道不健康绕过正缓存，执行有界严格读并最终复检 source token。每卡纪元 GC 先推进全局 floor，再清映射，旧回填不能发生 ABA 复用。计数耗尽关闭正缓存；hub token 计数耗尽关闭 authority 读写门。

组织与 GlobalAdmin 的 strict refill 先捕获一个完整 token，持同键锁到查询和安装结束，检查等待期、安装前及返回前竞态。组织 `TenantUnmanaged` 只缓存“表存在且该租户无 node”的严格事实；node 创建进入组织 source 栅栏。缺 schema 的 `SchemaUnmanaged` 不缓存。DDL/迁移不属于 runtime 纪元保护范围。

### 5.3 会话与 Gateway

MySQL 严格会话事实绑定 JTI、session/family、用户、身份卡、授权卡、租户和 domain；正向 cache 的物理截止取 JTI、identity card、user card、family 和 session 的最早有效期。未提供物理有效期证明的 source implementor 不能安装正缓存。旧 epoch 不取代新 epoch，锁中毒、时钟异常、suspect、回填竞态均为 miss 或 Unavailable。

`session_grant_mirror_enabled` 默认 true，显式 false 和 `positive_disabled` 保留。正缓存只允许单写者组合进程的 hub/owner/readiness 门；独立 Gateway 保持 DenyOnly/严格 DB 读取。Gateway 使用同一完整会话事实避免重复租户查询之前，必须验证它证明了请求的租户绑定，并保留整个准入窗口的最终 token 检查。

### 5.4 资源归属与 SoD

资源归属只缓存严格 resolver 的正向 `TenantScoped` 结果，键包含 resource、path、method、query target、actor card/user。14 类受支持 lookup 的实际 source 写者受 guard 保护；3 类 Chat lookup 永久排除。Global 和路由 Unresolved 是原有纯路由结果；否定/不可用结果不驻留。

SoD 是 ALLOW 之后的拒绝层，不能成为替代授权入口。组织输入必须与 PolicyEngine 返回的 provenance、context、publication 和 membership 对牌；卡片持有事实来自同一严格 published evidence。策略全量快照有 row/byte cap、single-flight、30s TTL 和 source token；新策略收紧不能通过旧快照被遗漏。context-aware 宿主在冷/热路径都只按已发布有效贡献判断持有，旧 `check_sod_conflict` / `check_sod_conflict_with_org` 诊断入口保留 raw-rule 额外拒绝扫描，实际宿主使用 additive `check_sod_conflict_with_context` / `check_sod_conflict_with_context_and_org`。冷读取和组织镜像 fallback 在读取前拒绝不可得栅栏、以原 token 终检，并有 3s 查询上限。仅存在 raw 行的历史请求可能由拒绝变为放行，这属于已登记的 BREAKING CHANGE，不是等同优化；部署前须核验历史规则是否依赖这一拒绝语义，迁移和回滚边界见规范 §15.4。

TrustGraph/Identity 的实际宿主在资源归属和其他 authority 读取之前捕获 opaque `AuthorityReadFence`，在 SoD 之后、调用下游 handler 之前复检。hub 已安装但发不出 token 时拒绝；不能把它等同未安装。Monitor 仍是独立严格读部署，不计入组合进程零 DB 范围。

### 5.5 容量与 GC

| 表面 | 上限与过期策略 |
|---|---|
| Published hub | 131,072 states/聚合索引，256 MiB 估算载荷，600s TTL；容量不足 suspect |
| Pending / completion | 100,000 pending；65,536 completion receipts，TTL 清理 |
| 资格 positive/head/纪元 | 各 65,536；positive/head TTL 5s，纪元唯一 floor GC |
| 组织 / GlobalAdmin | 各 4,096 entries，300s TTL；组织序列化载荷 32 MiB，另有固定 GA/键/map 开销 |
| 会话 | 至多 100,000，grant TTL 至多 900s，并截断至严格物理有效期 |
| 资源归属 | 8,192 entries，8 MiB 估算载荷，300s TTL；path/resource 2,048 bytes、method 16 bytes |
| SoD 策略快照 | STATIC/DYNAMIC 各 4,096 rows，合计 4 MiB 估算字符串，30s TTL；全快照一个 refill 锁 |
| 回填 | 各按键 read surface 同键 single-flight 至多 1,024 scopes；等待和查询各 3s |
| 资格扇出 / 模板审计 scope | 512，SQL cap+1 在变更前拒绝 |
| SessionRevoked | 单命令 32,768 JTIs、单事件 1,024 JTIs；每 JTI 128 bytes |
| Snapshot | pointer/pending 扫描各 100,000，SQL cap+1；容器文件 256 MiB，hint 年龄至多 24h |

估算预算不等同精确进程 RSS。TTL 只控制驻留，不能代替 source/健康/版本证明；容量拒绝或 GC 不扩大授权。完整卡索引保持缺失信息，不能通过淘汰某个聚合使剩余聚合看起来完整。

## 6. 城内失效与跨城协调

三类闭集 typed 事件为 `EVIDENCE_INVALIDATED`、`ELIGIBILITY_INVALIDATED`、`SESSION_REVOKED`，使用稳定 message/operation identity、scope ordering key 和 envelope 交叉校验。只有失效元数据在通道上传播，不传 permission state。

JTI 快照在 source 事务内确定，排序去重后分片。operation ID 保留 128-byte 原合同；短 base 使用已有 suffix，116–128-byte base 使用带域分隔的 SHA-256 稳定 message ID。完整 operation ID 不变；同 operation/index 改变 body 仍触发 durable payload conflict。

Rabbit 使用 mandatory persistent publish、durable 节点队列/inbox、confirm 和 DLX。消息 returned 即不可路由；确认未知不可当成功。消费者只处理该 delivery 的 exact claim，在 application proof 提交后 ACK；RetryScheduled、IN_DOUBT 或隔离停车不等于业务成功。重复、乱序、心跳和水位缺口都有显式状态，不能宣称 ACK 排除了所有丢失。

Rabbit fanout 的单写者 ownership 是部署前置条件，当前 runtime 不强制取得组合进程的 `GET_LOCK`，不能把同城多节点共库启动理解为允许多个授权 source writer。启用前必须证明写入 owner 和旁路隔离；周期 2s durable 全量对账仅用于检测与恢复，不保证消除两个写者并发时的陈旧 ALLOW 窗口，实际窗口还受调度、查询和传播耗时影响。该周期扫描的容量与数据库负载也须实测；相关外部验收完成前保持默认关闭，不据此宣称多写者安全或跨节点零窗口。

跨城 P4 默认关闭，启用前需要 Ed25519 evidence、持久 replay/nonce reservation、authority scope、两城 receipt 与 activation mint。IN_DOUBT/QUARANTINED、runtime caller、required worker 监督和有界关闭已有代码；真实双城 DB/MQ、分区、部署与窗口测量未执行。

## 7. 语义修订登记（R1–R4）

| 登记 | 本地实现语义 | 验收边界 |
|---|---|---|
| R1 跨节点撤销 | 通知、水位与 strict fallback；异常或证明不足 PENDING/DENY | δ 尚未实测；不宣称任何跨节点零窗口 |
| R2 L1 evidence | 已验证完整状态 + 前后 token + writer/健康/最终宿主门；warm 命中无 DB | 外部非合作 writer、真实租约断连与 crash 未验收 |
| R3 资格 | 正向物理事实/head 有界缓存 + 唯一纪元 + typed eviction + final token | 独立非 hub 路径仍有既有 5s TTL 边界；不能扩展为跨节点 authority |
| R4 Redis | 默认编译退役，显式兼容 feature + 启动能力门 + 单槽冻结配置 | 真正环境切换与兼容 adapter 集成尚未验收 |

正式授权唯一入口仍为 `PolicyEngine.evaluate()`；任何正式 evidence 缺失、failed、unknown 或 stale 只能 PENDING/DENY。以上实现登记不授权部署或降低外部验收门禁。

## 8. 恢复与运维边界

- source commit 未知：记录稳定 operation/event、最后完整证据和实际结果，保持读门关闭。通用投影对账不能证明凭据、会话或组织 writer 的结果；需要独立 writer 结果对账后的受控恢复。当前没有通用在线解除 API，不能自动重放；重启也须先核实 durable source 并完成启动恢复。
- direct dispatch 缺失：已提交 delta/outbox 由恢复 owner 按 durable claim 和 fence 接管；revoke-class pending 持续阻止旧权限。
- IN_DOUBT：`invalidation_recovery inspect --message-id <ID>` 实际只读 exact 行，连接和查询各有 5s 上限。只输出 scope、hash、状态、时序和大小/存在性，不输出 payload、headers、lease token 或原始错误。
- `settle requeue` 始终拒绝；`settle quarantine` 在当前没有同事务 approval/audit 入口时明确 BLOCKED，并在环境读取/连接之前退出。hash 是内容身份，不是人工批准。未来恢复 mutation 需独立 approved 入口和终审，本 CLI 不制造批准。
- snapshot 只作 hint：每 aggregate 重验当前 pointer、manifest、reference/segment 与版本；过旧、损坏、超限或证明失配走账本恢复。快照缺失不影响正确性，Windows 文件/crash 耐久性未验收。

卡模板 metadata 为 issuance-only；已发行授权依赖 canonical rule entries，不能制造无效果的 RULE_SET/CARD 刷新。模板更新保留 source fence 和同事务治理审计；实际管理员路径传播已验证 actor/operation。Level template 引用卡集合仅作审计观察，受 512 上限约束，不作为授权扇出。

## 9. 阶段与验证

| 阶段 | 代码状态 | 尚未证明 |
|---|---|---|
| P0/P1 | LocalBus、组合装配、撤销 intent、完成等待与 UNKNOWN 已实现 | 真实会话 outbox/consumer/application proof |
| P2 | 完整 published mirror、事件 pending、source cancellation、writer lease 监督、辅助读面和最终准入门已接线；本地门禁已执行 | 真实源/发布/crash/租约行为 |
| P3 | typed fanout、inbox、水位、回填、默认 Redis 编译退役已接线 | 默认全服务启动、DB/MQ/兼容 Redis、节点撤销窗口 |
| P4 | 签名、replay/receipt/activation、运行期调用和 required worker 监督已接线 | 两城真实依赖、故障与部署 |
| P5 | 有界 snapshot capture/load/warm/shutdown hint 已接线 | Windows/crash/真实重启耐久性 |

本轮全部本地实现、故障/并发测试、主审、范围格式和现有文档已收口。2026-10-02 冻结快照的 `cargo check --locked --workspace`、`cargo clippy --locked --workspace -- -D warnings` 与隔离 workspace tests 均 exit 0；2,610 harness passed、0 failed、77 ignored，内部 `[SKIP]` 为 0。兼容 feature 全目标 lint 通过，兼容默认并行测试 1,295 passed、1 ignored；资源归属/辅助镜像并行回归分别 13/35 passed。113 个目标 Rust 文件范围格式通过；该日整仓 fmt 因受保护的既有 policy-engine 三处差异失败，未修改。2026-10-03 用户要求提交全部更新后，仅调整这三处测试排版，重新执行 workspace check/clippy/fmt/test、兼容全目标 lint、归档 crate check 与默认依赖树检查，均 exit 0；测试仍为 2,610 passed、0 failed、77 ignored，内部 `[SKIP]` 为 0，默认依赖树 Redis rows 为 0。隔离测试移除外部连接环境，未执行 `--ignored` 集成或真实 migration；mock、source-shape、纯 seam、ACK 和 exit 0 均不作为外部集成 PASS。

最终快照的精确命令、stdout/stderr、退出码、SKIP/ignored/excluded、失败修复与受保护工作区核对记入既有计划的当前证据段。历史 P1/P2 测试结果只对应历史快照，不重写为当前完成证明。

[多机双通道冗余投递](Rust多机双通道冗余投递技术储备_V0.1.md)和[巨卡三条优化路线](Rust内存镜像读面巨卡优化技术储备_V0.1.md)继续作为储备，未在本方案实施。
