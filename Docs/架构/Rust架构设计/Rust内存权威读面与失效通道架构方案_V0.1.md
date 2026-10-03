# Rust 内存权威读面与失效通道架构方案（V0.1）

> 状态：P0–P5 主体已接线；2026-10-03 五链审查发现的源码缺口已修补并冻结，默认 workspace、显式 Redis 兼容、冻结 Chat/Learn 与离线工具的本地门禁已执行，结果及跳过项见第 10 节。真实基础设施、迁移、并发/崩溃及部署验收仍 BLOCKED，本文不构成整体 PASS 或部署/生产验收证明。
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

以下为修补前快照的历史记录，不是 §10 当前五链修补的验证结果。2026-10-02 冻结快照的 `cargo check --locked --workspace`、`cargo clippy --locked --workspace -- -D warnings` 与隔离 workspace tests 均 exit 0；2,610 harness passed、0 failed、77 ignored，内部 `[SKIP]` 为 0。兼容 feature 全目标 lint 通过，兼容默认并行测试 1,295 passed、1 ignored；资源归属/辅助镜像并行回归分别 13/35 passed。113 个目标 Rust 文件范围格式通过；该日整仓 fmt 因受保护的既有 policy-engine 三处差异失败，未修改。2026-10-03 的历史快照仅调整这三处测试排版，重新执行 workspace check/clippy/fmt/test、兼容全目标 lint、归档 crate check 与默认依赖树检查，均 exit 0；测试仍为 2,610 passed、0 failed、77 ignored，内部 `[SKIP]` 为 0，默认依赖树 Redis rows 为 0。隔离测试移除外部连接环境，未执行 `--ignored` 集成或真实 migration；mock、source-shape、纯 seam、ACK 和 exit 0 均不作为外部集成 PASS。

最终快照的精确命令、stdout/stderr、退出码、SKIP/ignored/excluded、失败修复与受保护工作区核对记入既有计划的当前证据段。历史 P1/P2 测试结果只对应历史快照，不重写为当前完成证明。

[多机双通道冗余投递](Rust多机双通道冗余投递技术储备_V0.1.md)和[巨卡三条优化路线](Rust内存镜像读面巨卡优化技术储备_V0.1.md)继续作为储备，未在本方案实施。

## 10. 2026-10-03 五链修补证据

### 10.1 范围与身份

本记录对应用户要求“补齐这些缺口”的源码修补，不授权部署、迁移执行、生产数据变更、业务消息发送、外部通知、提交或推送。基线及当前 HEAD 均为 `6b3d8cd4000d881b22d274ba6a7fc8b4711f6f3c`，工作分支为 `fix/five-chain-review-gaps`，固定工作目录为 `/Users/coreryblack/Code/AstralLight.Next`。源码修补及本地验证已收口；真实基础设施验收尚未启动，不能据此宣布整体 PASS 或允许部署。

责任分工采用独立文件 ownership 并行修补；主 Agent 完成接口接线、等同审查、失败接管、最终构建及本记录。所有写入 owner 已冻结；子 Agent 不递归委派，不执行基础设施操作、提交或推送。主 Agent 于 `2026-10-03T17:47:35Z` 收集最终 Chat/Learn 三条命令的完整结果，随后仅更新本证据文档。

最终内容身份按 `git ls-files -z --cached --others --exclude-standard` 枚举并排序，排除且只排除本文；逐文件计算原始字节 SHA-256，再向总 SHA-256 输入 `path + NUL + file_sha256_hex + newline`。总枚举为 676 个文件，排除本文后 675 个文件；可复算总 hash 为 `19e67e37925249afaa38f711b5e177a42c905aa35191cb838904cedec76a8cea`。Ruby 与 Perl 独立复算相同。先前交接所报的 676 文件/`5d871024...` 无法按该排除算法复现，已被本次实测身份替代，不作为冻结凭据。本文的后续证据编辑不改变上述源码身份；若其他文件再写入，必须重新冻结和验证。

| 任务单元 | 责任与范围 | 主 Agent 最终复核及证据边界 |
|---|---|---|
| Gateway | Gateway/common 入口 owner，主 Agent 复核 | HMAC v3 wire、精确 signed-empty allowlist、8 MiB 响应 cap、冻结 upstream 配置；默认和兼容门禁已执行 |
| 凭证/MFA | Identity 认证 owner，主 Agent 完成共享闭包和调用方 | credential revision、因子消费、物理双卡、事务审计/会话撤销同闭包；源码及本地回归完成，真实并发未验收 |
| Local/MQ/runtime | Local/composite/MQ owner，主 Agent 接线及终审 | exact durable claim、handler/completion CAS、单行 fanout、producer barrier、sticky failure；物理 DB/MQ 合同未实测 |
| 治理 | SoD/卡片/注册表 owner，主 Agent 复核 | 受限 parser、锁内 owner、正式 PolicyEngine、最终 opaque fence；默认门禁已执行 |
| 审计/批量 | replay/业务审计/异步任务 owner，主 Agent 复核 | 精确 requester/anchor、tracker-owned registration、joined poll snapshot、原子 item 完成；重启/事务交错未实测 |
| Schema | migration/validator owner，主 Agent 冻结字节 | 精确列/default/charset/collation/index/InnoDB、artifact pins、optional IO 分离；五份新增 SQL hash 已核对，均未执行 |
| 验收工具 | Python/bench/scripts/bootstrap owner，主 Agent 终验 | Python 473、S15 5、独立 Rust 30 项纯测试通过；PowerShell/Java 外部边界未运行 |
| Chat | 冻结 Chat owner，后续 receipt owner，主 Agent 接管 runtime/WS/API | 原始 admission fence、当前 session/policy 出站门、全物理卡去重、有界 socket drain、effective watermark；48 项通过、15 integration ignored |
| Learn | 冻结 Learn owner，后续 lifecycle owner，主 Agent 接管未完成修补 | partial owner 显式 cleanup、VARCHAR(32) marker、exact committed cascade scope、拒绝猜测 legacy namespace；54 项通过、16 integration ignored |
| Monitor/辅助 | Monitor/tenant helper owner，主 Agent 复核 | owned collector/audit、UNKNOWN 与 SIMULATED_NOT_DELIVERED、task-local bypass；默认及兼容门禁已执行 |

### 10.2 五链处理与兼容边界

- 调用链：Gateway v3 wire 保留；signed-empty 只覆盖精确 POST allowlist 且全部身份字段为空，部分上下文拒绝。既有 `run` / `run_with_listen_addr` 保留，shutdown/drain 入口为 additive。密码、MFA、session closure、Chat durable send、batch registration 的仓内调用方已接线；handler 不管理事务。Chat `MessageService::new` 原四参数入口保留，`new_durable` 为替代装配入口。
- 逻辑链：正式授权仍为 `PolicyEngine.evaluate()`，SoD 只作 ALLOW 后 deny-only 检查，最终准入复检读取前捕获的 opaque fence。身份卡和授权卡必须按同一精确 user 配对，不使用不存在的 `user_card.identity_card_id`；physical IDs/status/expiry/tenant/domain 全部对牌。批量轮询使用原始 requester tuple、最初 anchor 和当前 `domain:update`，Foreign-owner polling 只读；GlobalAdmin 合法跨租户发起不被目标 scope 错误拒绝。tenant bypass 是任务局部/origin-bound，spawn task 不继承；非法 legacy scope 返回零行而非扩大查询。
- 事故链：Local 直发先 claim exact committed row 并校验原始 bytes，直发和恢复共用 handler/completion CAS，AlreadyProcessed 仍校验 bytes。过期或缺 lease 的 PROCESSING 转 IN_DOUBT，不能按时间自动重放。fanout 内部 claim-one，发布前有 token-CAS bounded heartbeat，publication/settlement 预算留在 lease 内；未知 heartbeat 不发布、未知 publish/settlement 停止并待对账。关停先关闭 sticky admission，Gateway drain 后停止 producer，经跨服务 barrier 后关闭 Local receiver，并 drain 已 admission 的交付；panic、取消、未知 close、worker death 和 active source writer 不能形成成功 snapshot。
- 数据链：平台 session/JTI epoch 必须相等，session 正数非 NULL credential revision 必须等于当前 ACTIVE credential；AppUser 保留 identity-only、NULL credential revision 合同。密码 revision、reset token、bounded JTI/session/family 撤销与稳定 auth-session outbox 在同一事务；guard 在 begin 前取得、COMMIT await 前武装、仅 proven commit 后 settle。batch item 的 source/audit/projection/invalidation/COMPLETED/parent counter 原子，parent+children 单次 joined SELECT；request 取消不丢 tracker-owned registration/worker，ambiguous registration 负查询不是 rollback proof。迁移只新增，不修改已应用 SQL；精确 schema/pre-adoption 和 pinned artifact ownership 不允许空建遗失 proof table 掩盖历史丢失。
- 审计链：replay transition、actor/operation audit 同事务；组织/租户 mutation 的 verified context、审计及资格失效同 source closure。旧缺 context API 签名保留但拒绝写入。owned audit manager 有容量 1024、sticky interruption 和有限 drain；普通 ALLOW 未被强制改为每次同步 durable audit。task drain、broker ACK/confirm、队列 admission、handler Ok、镜像安装和 exit 0 都不是同一 durable proof。

原始 Local PENDING 发现是完成合同和重复工作风险，不是已证明的 stale authorization，也不新增内部消息 blanket exactly-once 承诺。

#### 10.2.1 兼容、启用与回滚

以下行为变化在本次未提交源码快照生效，部署前必须进行兼容验收；旧 API 不被日期自动删除。本记录不授权解除 Chat/Learn exclude 或启用 Redis、Rabbit fanout/cross-city。

| BREAKING CHANGE / 边界 | 替代和迁移 | 回滚约束 |
|---|---|---|
| 旧平台 NULL revision session 不再被严格 reader 接纳 | 重新登录，签发匹配当前 credential revision 的 session；不 grandfather/backfill 旧会话。AppUser identity-only 不变 | 不得通过旧 NULL fallback 恢复权限；保持入口关闭并核验 durable session/revocation |
| MFA 管理需当前密码/现有因子及稳定 canonical `x-request-id` | 共用锁内 verify/consume/mutate/audit；login 不激活 staged factor，active factor 不被 Stage 覆盖，因子/attempt ambiguity 拒绝 | 不自动重放已消费 recovery/TOTP，不泄露 secret/hash；unknown commit 先独立对账 |
| 原密码 `update_password_hash` / `update_password_hash_tx` 签名保留，行为扩展为原子撤销闭包 | DB wrapper 拥有 guard/commit/postcommit JTI projection；caller-owned tx helper 不提交、不作 postcommit IO，caller 拥有 guard/commit/rollback | 不能只恢复旧单条 password UPDATE 而遗失 revision/session/outbox 合同 |
| 动态 SoD 无效或不支持脚本拒绝；旧组织/租户无 verified context 写入入口拒绝 | 使用受限语法、context-aware deny-only SoD 和已验证 mutation context；全部仓内调用方已接线 | 不允许旧 raw/source 或 unchecked actor fallback，历史规则需专项验收 |
| Chat `register` / `unregister` 的原 `UnboundedSender` 签名保留，但无界注册明确拒绝 | `register_bounded` / `unregister_bounded` 为有界替代；实际 runtime 使用 cancellation-aware bounded socket ownership。旧返回 `()` 的 `send_to_scope` / `send_to_member_scopes` 保留，需状态的调用方改用 `try_*`；durable relay 已迁移 | 这是行为变化而非等价兼容。旧入口不建立 unbounded bridge；回滚不能恢复无界队列或把 queue admission 当 delivered |
| Chat 当前 session/read policy 不再只在入站检查 | 握手使用原 middleware fence；每个 queued frame 在 socket send 前重验当前 session/所需 policy，未知类型拒绝；READ_RECEIPT 走 scoped member/message 校验并返回实际持久 watermark | Broker PUBLISHED 只证明 admission，不证明 recipient delivered/read；不能以旧队列内容绕过撤销 |
| Learn 缺服务端评分/关卡/进度依据接口明确 NotImplemented | 新 default grade 仅使用 exact `DEFAULT_GRADE` marker；历史 `system_role=NULL` 不按标题/状态/最小 ID/提交推断 | 历史默认行需要独立证明的明确映射；不盲目 backfill 或把客户端分数当权威 |
| Learn subject cascade 不再猜测 legacy `course.id` 与 `learn_course.course_id` 对应 | 必须 exact committed PROCESSING intent、canonical envelope、DISABLED source 和匹配 tenant/domain；课程/章节/问题/关卡先有界锁定并验证归属，任何 DELETE 前完成 preflight | `announcement` / `discussion_post` / `class` / `course_workflow` 无已证明 crosswalk 时只检测。任一 legacy 表非空即保守阻断，即使可能仅含无关行；等待明确映射/对账，不删除、不盲重放 |

Chat callback 在 upgrade 前计入 owned socket reservation；关闭 gate 与注册共用锁，关闭后不接纳新 socket。正常 owner exit、panic/cancellation 和 drain timeout 分别记账；15s socket drain 只证明 owner exit，未证明真实 TCP 对端关闭。Text/Pong/Close send 有 2s 上限，queue 128、frame 64 KiB；queued-frame admission 10s，durable session/presence DB 检查 3s。Chat relay、audit、Rabbit 关闭发生在 HTTP/socket drain 之后，close 未证明仍保留失败。

Learn startup owner 放在可取消 startup future 之外；partial init/stop/timeout 都必须 await consumer cleanup，不能用 Drop 假称关闭。stop 可中断 30s startup；2s task drain + 5s explicit Rabbit close 位于 12s worker shutdown 内。未知 startup/heartbeat/dispatch 不自动 retry/quarantine。Rabbit subject-delete delivery 只确认 exact durable completed Local receipt，不凭 broker payload 删除 source。所有期限是最大等待，不是强制 sleep。

#### 10.2.2 新增迁移字节

以下五份 additive SQL 均未执行。2026-10-03 主 Agent `shasum -a 384 astral-db/migrations/2026100300000{1,2,3,4,5}_*.sql` 复算，并逐项核对 `migration.rs` pins；原历史 migration 字节无修改。Learn runtime 和 shared schema validator 均要求 nullable/default NULL、utf8mb4/utf8mb4_bin 的 `system_role VARCHAR(32)` 及 exact `(course_id, system_role)` unique index；没有 marker width fallback。

| 未执行 artifact | SHA-384 |
|---|---|
| `20261003000001_identity_credential_fence.sql` | `67b0e206506af2e724d08951bcdeb8b297ca8a83f75c540c1ace98bfc18375b0167e40fbe10ea27ef6e0a7f3b71fdfda` |
| `20261003000002_operation_audit_correlation.sql` | `9f923f7efe47307ca895eba96674384967e1e29317abd2661d07ca2f8be4fa92b543220d44e58354fc2fa5eeccef3089` |
| `20261003000003_review_schema_contract_repair.sql` | `ef67f67303bc20bb9a82677550272d92892f43c0303629600d14b45aae054210546c196dcd818e54095c0a6e854420bd` |
| `20261003000004_chat_delivery_intent.sql` | `9e54275dbd398508eb4daac9dcbb4c5f1a75902b66757e9110410d9e85e9abce82bbbb372a25c6591d0be2464f7620c7` |
| `20261003000005_learn_atomic_intents.sql` | `102705f5df0183e0bcd4fc4d39fe1c8e8ff994c66d198d0c7d738a992a3469cc9b453d9b52c7721d4bd48591ca2905de` |

可选 runtime disabled 时不执行其 runtime IO；present-table preflight 不因此忽略现存不兼容表。记录过却遗失的 proof table 必须恢复而非空建。旧 standby DROP 的运行前置仍需 explicit allowlist、backup/drain/cutover proof，不得 skip 后伪造 applied history。迁移/部署回滚需经授权的恢复或 forward-fix；保持新增可选功能关闭和拒绝门，禁止自动 DROP 新表、删除 migration history、放开旧不安全 fallback 或重放未知 source。没有运行备份、恢复、迁移或回滚演练。

#### 10.2.3 安全控制的适用性

新控制对应的威胁是被撤销/跨租户或持旧凭证的调用者、可重放的消息/因子、取消/失联的 owner，以及缺失/冲突的 durable/schema 证明；不假定攻击者已拥有数据库管理员权限。非合作 DB writer 仍是运维隔离前置，单机 guard 不替代该隔离。

| 控制组 | 故障/阻断点 | 误放行与误拒绝代价及验证 |
|---|---|---|
| credential/MFA/正式准入 | locked exact credential/card、one-time consume、原始 fence final check、transaction audit/closure | 误放行可导致旧凭证/权限生效；旧 NULL session 或 fence 竞争会安全拒绝。本地 source/纯状态回归已跑，真实锁争用/commit cancellation 未实测 |
| Local/fanout/Chat intent | exact committed bytes、stable identity、token/generation/lease CAS、finite budget；unknown 停车 | 误放行可重复外部发送或虚报完成；误拒绝保持 IN_DOUBT/暂不可用。mock 验证状态和预算，不证明真实 publish/consumer/crash |
| batch/治理/audit | requester+original anchor、owned registration、joined snapshot、同事务 source/evidence/audit | 误放行可越权轮询或部分 mutation；未知注册/source 和 legacy context 拒绝会需人工对账。本地测试覆盖，真实跨进程 restart/SQL atomicity 待实测 |
| Chat WS / Learn cascade | current session/policy、bounded owned socket；committed deletion anchor、tenant/domain preflight、拒绝猜测 legacy IDs | 误放行会暴露已撤销内容或删除外租户数据；慢连接取消、legacy 表非空的保守阻断会影响可用性。pure regression 已跑，物理 TCP/FK/crosswalk 未验收 |
| schema/验收工具 | exact metadata/artifact ownership、read-only gate、缺/歧义/截断证据不转绿 | 误放行会把未知数据库或 campaign 当成功；误拒绝要求恢复或补证。offline contract/tool 测试已跑，migration/restore/campaign 尚未启动 |

### 10.3 本地验证环境与过程

验证工具隔离在 `/tmp/astrallight-five-chain-build.MgM6QC`，未修改用户 profile/PATH 或全局 toolchain。`rustc 1.99.0 (b940084d7 2026-09-28)`，`stable-aarch64-apple-darwin`；命令显式使用根 manifest。共同环境为：

```text
RUSTUP_HOME=/tmp/astrallight-five-chain-build.MgM6QC/rustup
CARGO_HOME=/tmp/astrallight-five-chain-build.MgM6QC/cargo
RUSTUP_TOOLCHAIN=stable
CARGO_TARGET_DIR=/tmp/astrallight-five-chain-build.MgM6QC/target
CARGO_INCREMENTAL=0
PATH=/tmp/astrallight-five-chain-build.MgM6QC/cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin
```

测试移除 `DATABASE_URL`、`REDIS_URL`、`RABBITMQ_URL` 和 `RUST_INTEGRATION_REQUIRED`。`--locked` 因新增直接依赖或 feature edge 拒绝时，使用 `--offline` 机械同步 lock，随后必须从冻结源码重新执行 locked gate。该同步不升级已有依赖版本。临时编译不会连接业务基础设施；mock、loopback 转发 seam、source-shape 和纯函数测试不是真实部署验收。

过程日志位于 `/Users/coreryblack/.zcode/cli/exec/sess_9a35f87e-1d84-4930-9126-64518484d88e/`，命令 stdout/stderr 合并在 `*-stdout.log`。已观察的失败保留，不改写为 PASS：多个移动源码快照的 workspace/all-target check exit 101，原因包括未完成的调用方、签名测试参数、schema helper、worker 类型和 lock 更新；主 Agent 已接管并在冻结输入上重跑。以下表格保留当时局部/过程证据，不把旧副本视为最终源码证明；当前冻结结果另见 §10.3.1。

| 命令/证据单元 | 结果 | 日志/局限 |
|---|---|---|
| `cargo fetch --locked` | exit 0 | `call_L09wy1EwbGGAwEpGj5AG5dXW-stdout.log`；仅依赖获取 |
| `cargo test ... -p astral-common --lib audit::tests` | 10 passed、0 failed、0 ignored | `call_oiCTrVNAaloW5dtltNTubWJr-stdout.log`；当时 audit 快照，非最终全部源码 |
| `cargo test --locked --manifest-path <root>/Cargo.toml -p astral-types --lib registry::tests` | exit 0；16 passed、0 failed、0 ignored、111 filtered | `call_juuqCj4OnbMkxYq0eOdNsz87-stdout.log`；当时 registry 快照 |
| `cargo test --offline --manifest-path <root>/Cargo.toml -p astral-common -p astral-gateway -p astral-mq --lib` | exit 0；分别 200/52/139 passed，0 failed、0 ignored | `call_3pWR3kC7cPel0hJxjNbYRLwD-stdout.log`；局部快照，不是真实 MySQL/MQ 验收 |
| `cargo test --offline --manifest-path <root>/Cargo.toml -p policy-engine -p astral-monitor --lib --bins` | exit 0；policy-engine 294，Monitor 24+2 passed | `call_PzHJsH9i1GV7aEyAGYvlFUPo-stdout.log`；早于 Monitor 末端补丁 |
| `cargo test --offline --manifest-path <root>/Cargo.toml -p astral-monitor --lib --bins` | exit 0；27+3 passed，0 failed、0 ignored | `call_FoncxX8JcLpHWm7x2q6mI6Nb-stdout.log`；已覆盖 HTTP 故障排空及 collector 所有权补丁 |
| `cargo tree --offline --locked --manifest-path <root>/Cargo.toml --workspace -e normal --prefix none` | exit 0；Redis 行为 0 | `call_Gq7nTWgovBDkOsW8D8Ku13xL-stdout.log`；此前 `-i redis` exit 101 是未匹配到包，不作为成功命令 |
| disposable `bench/loadgen` / `astral-cache` `cargo check --offline --locked --all-targets` | 均 exit 0 | `call_blAdapLSLrHP6gyuB3SNK9gI-stdout.log` / `call_GETGpZLA6kfLm5Uac0CZOxJ3-stdout.log`；未运行压测或 Redis IO |
| disposable `bench/engine-comparison` `cargo check --offline --locked --all-targets` | exit 0 | `call_tjVJSRJVQdbwBvAFrnDN5i5h-stdout.log`；未执行 benchmark 或 OPA 请求 |
| `cargo test --offline --locked ... -p astral-common -p astral-gateway --lib` | exit 0；201/53 passed，0 failed、0 ignored | `call_rpIV3FeS5uGKioXaTLGKicrC-stdout.log`；追加 internal-session owned audit 与信号错误保留 |
| common strict lint / lib + contracts | lint exit 0；201 lib + 32 audit/tenant + 7 gateway tests passed，0 failed、0 ignored | `call_0quSX9ICK4eARP619rxDnMXl-stdout.log` / `call_gol9TNSlE3UBi3NzvhYH0S9D-stdout.log`；早先 manual async / nested branch lint 与空租户旧断言失败保留于 `call_BW9Eiuqu8PrXUEQInE8V8VMA-stdout.log`、`call_T16ZFwVY6tt8uNAlwZP0pS3j-stdout.log`、`call_3UQy72pT98cJZzB2dxDwhzKX-stdout.log`，生产缺租户合同仍为零行 |
| shared policy/types `cargo test --offline --locked ... --lib --tests` | exit 0；types 127、policy 294 lib + 17 extra contract tests passed，0 failed、0 ignored | `call_99Wevf5G4CHIQlK4VHqLA3Dj-stdout.log`；含 task-local bypass 跨 await/取消/跨 task 隔离；第三方 `proc-macro-error2` future-incompatibility 预警不作源码失败 |
| `cargo test --offline --locked ... -p e2e-bootstrap --bin e2e-bootstrap` | 修正后 exit 0；3 passed | `call_RCkmsL1vzZCfE6z54Z4j8lds-stdout.log`；之前 IPv6 方括号导致 1 failed，见 `call_ntbTNwJL9jyG0urnuRi6HaZP-stdout.log` |
| disposable bench strict lint / pure tests | `clippy --offline --locked --all-targets -- -D warnings` 均 exit 0；重新测试 loadgen 1、engine-comparison 8 passed | lint `call_55bczrVheojdgg1lf5KViz1J-stdout.log` / `call_Mv3rddnVuyCw01weArZyjS6s-stdout.log`；tests `call_AGZt9zvUisoWhd9cAp80imm3-stdout.log` / `call_fASmtzjRpkgaQ68hTk1r8Xmw-stdout.log`；初次 lint exit 101 保留于 `call_a52QD0d5lKDJ3Ok4ovAFHUpF-stdout.log` / `call_3W37gLSKHWJtpZ9SwP9B3iQJ-stdout.log`，未运行压测或 OPA |
| disposable archive cache strict lint / tests | lint exit 0；5 lib + 16 key-scope tests passed，0 failed、0 ignored | `call_Fw8qaeufZ0Hbjafiq9cSyqcc-stdout.log` / `call_TNj3VkN3aLo6Tq4Vw4eLftHz-stdout.log`；惰性 Redis wrapper 不连接 Redis，不证明 adapter 集成 |
| disposable MQ `cargo test --offline --locked ... -p astral-mq --lib` | exit 0；144 passed，0 failed、0 ignored | `call_Q6g87Il8xUp4ub25wBvg4SIH-stdout.log`；包括 Local 消费 join 取消 ownership 与已提交 Chat envelope digest，早于当前 fanout 修补 |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s <root>/Docs/authorization-validation/tools -p 'test_*.py'` | exit 0；473 tests、OK，400.857s | `call_Eubd1oF5XiMxopgp1xaXwwX2-stdout.log`；fixture 的 BLOCKED 不是实际基础设施运行 |
| disposable Gateway/Monitor/MQ lib+bin+tests | exit 0；Gateway 53、Monitor 27+3、MQ 144 passed，0 failed；Monitor integration 5 ignored | `call_1imOaQnzK4Kb8UhppxtMbV1N-stdout.log`；shared/runtime 源码局部副本，DB/schema/fanout 仍是旧副本，不能作最终整仓证明；严格 lint `call_PNDgCs7AbDEhLPw7nPQaD4Rj-stdout.log` exit 101 被旧 DB 未接线/注释错误挡住，不计为通过 |
| S15 `test_s15_validation.py` | exit 0；5 tests、OK | `call_PijQe9Ss2s0W0Nho1NchBOWY-stdout.log`；纯完整性判定 |
| shell syntax / parser / invalid RUN_ID | syntax exit 0；parser 自检 exit 0；无效 RUN_ID 按预期 exit 1，未到 Docker | 主 Agent 工具输出；PowerShell 不存在，因此其脚本仅静态复核、未执行 |
| 最终 workspace/compat/excluded gate | 已执行，逐项结果见 §10.3.1 | 旧局部结果不替代最终门禁，ignored 与外部 BLOCKED 独立登记 |

### 10.3.1 冻结门禁结果

主 Agent 为责任人。本地动作限 Exec-L1 构建/可丢弃副本、纯测试及 Exec-L0 读取；实际源修补在已授权分支，未产生业务 durable 或外部副作用。默认 11-member workspace 的最终输入在最后 Chat API 补丁前已冻结；该补丁只涉及 excluded Chat，随后专门重跑 Chat/Learn check/lint/tests。全部源码最终与验证副本 checksum 对齐，未来不得把本次结果套到后续字节。

`ROOT` 为 §10.1 工作目录；`COPY=/tmp/astrallight-five-chain-excluded.HHR6qG` 是可丢弃副本。仅 COPY root manifest 额外列入 Chat/Learn，真实 `Cargo.toml` 和 `AGENTS.md` 相对 HEAD 零 diff。COPY 保持已 offline 解析的独立 lock；刷新使用 `rsync -a --exclude=/Cargo.toml --exclude=Cargo.lock --exclude=.git/ --exclude=target/ --exclude=.zcode/ --exclude=__pycache__/ "$ROOT/" "$COPY/"`。最终同参数 `rsync -ani --checksum` 在文档更新前输出为空，证明除列明 manifests/locks/产物外的内容一致，而不是通过 inode 判断。COPY/standalone 命令使用 `CARGO_TARGET_DIR=/tmp/astrallight-five-chain-build.MgM6QC/target-standalone`，其他环境同上；真实 worktree 的 lock 没有被临时 standalone lock 覆盖。

下列命令参数记录使用 ROOT/COPY 展开式，测试统一前置 `env -u DATABASE_URL -u REDIS_URL -u RABBITMQ_URL -u RUST_INTEGRATION_REQUIRED`。兼容 feature 字符串是 `astral-common/redis-compat,astral-db/redis-compat,astral-mq/redis-compat,astral-gateway/redis-compat,astral-identity/redis-compat,astral-trustgraph/redis-compat,astral-monitor/redis-compat`；相应 package 集为这七个 package，非 `--all-features`。`astral-single-node` 没有 `redis-compat` feature，不伪造该 feature 的测试覆盖。

```sh
cargo check --manifest-path "$ROOT/Cargo.toml" --offline --locked --workspace --all-targets
cargo clippy --manifest-path "$ROOT/Cargo.toml" --offline --locked --workspace --all-targets -- -D warnings
cargo test --manifest-path "$ROOT/Cargo.toml" --offline --locked --workspace -- --test-threads=1 --nocapture
cargo fmt --manifest-path "$ROOT/Cargo.toml" --all -- --check
cargo tree --manifest-path "$ROOT/Cargo.toml" --offline --locked --workspace -e normal --prefix none

cargo clippy --manifest-path "$ROOT/Cargo.toml" --offline --locked \
  -p astral-common -p astral-db -p astral-mq -p astral-gateway -p astral-identity \
  -p astral-trustgraph -p astral-monitor --all-targets --features "$FEATURES" -- -D warnings
cargo test --manifest-path "$ROOT/Cargo.toml" --offline --locked \
  -p astral-common -p astral-db -p astral-mq -p astral-gateway -p astral-identity \
  -p astral-trustgraph -p astral-monitor --lib --features "$FEATURES" -- --test-threads=1 --nocapture

cargo check --manifest-path "$COPY/Cargo.toml" --offline --locked -p astral-chat -p astral-learn --all-targets
cargo clippy --manifest-path "$COPY/Cargo.toml" --offline --locked -p astral-chat -p astral-learn --all-targets -- -D warnings
cargo test --manifest-path "$COPY/Cargo.toml" --offline --locked -p astral-chat -p astral-learn -- --test-threads=1 --nocapture
cargo clippy --manifest-path "$COPY/Cargo.toml" --offline --locked -p astral-learn --all-targets --features astral-learn/redis-compat -- -D warnings
```

| 冻结 gate | 实际结果 | 完整合并日志（相对上文日志目录） |
|---|---|---|
| 默认 workspace all-target check | exit 0 | `call_V7bX2gtGTYZYfvyeXyeoxIzW-stdout.log` |
| 默认 workspace all-target strict lint | exit 0 | `call_XRhDs5RrqfnxfWUdjUxYhWHO-stdout.log` |
| 默认 workspace 串行 tests/doc tests | exit 0；41 harnesses，2,711 passed、0 failed、78 ignored、内部 `[SKIP]` 0 | `call_8Dr2NmqoaXzITCmIMmzS1ApK-stdout.log`；此前同总数串行成功为 `call_HrNnkkxjSqZ5eCmiPjp4AS0S-stdout.log` |
| 显式七 package Redis-compatible all-target strict lint | exit 0 | `call_TqPn062qvrlbsSfv7pzGBKDF-stdout.log` |
| 显式七 package Redis-compatible lib tests | exit 0；7 harnesses，2,234 passed、0 failed、1 ignored、内部 `[SKIP]` 0 | `call_TXyVHKtS7kqhLoEPhzz7FUem-stdout.log`；不代表 Redis adapter integration |
| 默认 normal dependency tree | exit 0，Redis rows 0 | `call_67vRyyN3kF81Kl7kCSYnDTrG-stdout.log` |
| 最后 Chat public API adapter 后 all-target check | exit 0 | `call_ir7NkSkMVVpVy4pr1wa0iX6S-stdout.log`，task `exec_8decdea1-be7d-4902-95b4-f26ea625127a` |
| 最后 Chat public API adapter 后 all-target strict lint | exit 0 | `call_U6E50Q0KuAG01wSyixHbnlkQ-stdout.log`，task `exec_97d74ee6-efe1-4f76-813d-6a5603202392` |
| 最后 Chat public API adapter 后 Chat/Learn tests/doc tests | exit 0；8 harnesses，102 passed、0 failed、31 ignored、内部 `[SKIP]` 0 | `call_roNUm2IJ5bW76bjhSNSCg9Zw-stdout.log`，task `exec_eed9b76a-8157-4a14-a314-ab2fd1ea932c`；Chat 42 lib + 6 bin，Learn 41 lib + 13 bin |
| 冻结 Learn optional Redis-compatible all-target strict lint | exit 0 | `call_SC1lZbQbq5YDjl89TQXaIG6D-stdout.log`；不是 feature 实际运行或 Redis 测试 |
| 当前格式及 diff hygiene | active `cargo fmt --all -- --check`、excluded/bench recursive `rustfmt --edition 2021 --check`、`git diff --check` 均 exit 0 | 主 Agent 工具结果；文档写入后只重复适用文档/身份检查，不冒称重新运行 Rust tests |

默认测试中的 78 ignored 包含唯一库内 ignored 和实际集成/文档跳过项；Chat/Learn 的 15/16 ignored 单列为 SKIP，不能计作 passed。兼容测试总数与默认总数覆盖交叠，不相加。成功 doctest 日志中预期 compile-fail 的编译诊断不代表 gate 失败；`proc-macro-error2 v2.0.1` 第三方 future-incompatibility warning 保留，未升级依赖以掩盖。

Standalone 的等价完整参数为 `cargo clippy --manifest-path "$COPY/<crate>/Cargo.toml" --offline --locked --all-targets -- -D warnings` 及 `cargo test --manifest-path "$COPY/<crate>/Cargo.toml" --offline --locked -- --test-threads=1 --nocapture`，三条 `<crate>` 为 `bench/engine-comparison`、`bench/loadgen`、`astral-cache`，不执行 benchmark/压测/OPA/Redis IO。

| 离线单元 | 实际结果 | 最后日志 |
|---|---|---|
| `bench/engine-comparison` | strict lint exit 0；8 tests passed | `call_L0lKXgOkcmOOo7UCmzKuj824-stdout.log` / `call_rLODpboGQMmMj97XxjqPvLXO-stdout.log` |
| `bench/loadgen` | strict lint exit 0；1 test passed | `call_62ZI0PMfW3fzexDOskxyiLS3-stdout.log` / `call_IOfLS1p98EV5jXZPXQP5D1jZ-stdout.log` |
| `astral-cache` archive | strict lint exit 0；5 lib + 16 key-scope tests passed | `call_kr1o3r4fNz4SP6Fx8YzDWrKB-stdout.log` / `call_xFg7f8ba0qdEYGNbKENu5fyD-stdout.log` |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s "$ROOT/Docs/authorization-validation/tools" -p 'test_*.py'` | exit 0；473 tests OK，359.955s | `call_CeVdyBjtTpPXyIgOCvOxdMMg-stdout.log`；fixture 输出 BLOCKED 不是真实 campaign PASS |
| `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s "$ROOT/Docs/实验/分布式测试/rust-s15" -p test_s15_validation.py` | exit 0；5 tests OK | `call_PIrdKHmVrZsin5nRlz25At02-stdout.log`，最后文档闭合阶段又纯测试复跑 exit 0 |
| `bash -n "$ROOT/scripts/run-tests.sh" "$ROOT/scripts/org_scope_preflight.sh"` | exit 0 | 主 Agent 工具结果；只语法，不启动脚本基础设施流程 |
| `env -u ORG_MYSQL_URL bash "$ROOT/scripts/org_scope_preflight.sh" self-test` | exit 0，connection parser self-test passed | 主 Agent 工具结果；不读取真实连接、不执行 SQL |
| PowerShell / Java 外部父模块 | 未执行，BLOCKED | `command -v pwsh` exit 1；PowerShell 仅静态 review，Java benchmark 不在当前 Rust gate |

各日志保留 Cargo build/harness 单调耗时；绝对开始/结束时间和累计 turn 时间未完整独立持久记录，不补造或从 mtime 反推。已确证最终结果收集时间见 §10.1，不能当每条命令的开始时间。最终收集过程无 stream 断流、截断或仍在运行的 gate；前期 owner 中断与失败保留在下一节。没有因单个 exit 0 将未启动外部 gate 转绿。

### 10.3.2 失败、接管与重跑

以下都是修补过程中实际失败或未开始的 gate；后续成功只证明纠正后的输入，旧日志不被覆盖。所有源码 repair owners 已停止写入。先检查真实 worktree、未跟踪文件、现有 partial ownership 和日志后，主 Agent 接管；peer 没有回报不被等同为没有写入。

| 原失败/未完成证据 | 诊断与处置 | 最后证明/残余边界 |
|---|---|---|
| `call_9ufQhoN70KtQICVuQEHGM2dM-stdout.log`，MQ 145 passed、2 failed | Local lease error text 已变；fanout 测试忽略 heartbeat action。核验生产预算后只改断言，FIFO 测试逐项要求 heartbeat/complete 交替且 claim limit 为 1 | MQ 最后 147 passed；没有放松 lease predicate |
| `call_JArXIV0s0K1a9pUhCk9XArq8-stdout.log`，composite 17 passed、1 failed | 源码形状测试错误寻找直接 abort token；改验 sticky suspect 先于 `graceful_stop_or_abort` | 最后 composite 18 passed；终态 handle 不二次 poll |
| `call_f7XbJKXguShsILjv1s6WiPDW-stdout.log`，TrustGraph 822 passed、2 failed、1 ignored | 锁测试跨两个 SQL 字符串比较字符位置；改验实际 upsert/remove 函数锁顺序。alias fixture 的 monitor 写动作已合法，改用仅 read 的 learn_device | 最后 TG 824 passed、1 ignored；未削弱权限 |
| `call_3Aa6ZwMvGtekerGgYuRIl9su-stdout.log` 及 excluded lint `call_WQ9tWbCrG4SeLiIUINgqAjZA-stdout.log` / `call_FQWhuwQGSRsZIaGXelYxMEpH-stdout.log` | 修复 Chat watch borrow、Learn ownership import/Send+Sync error conversion、未用 private helper、文档 lint。Axum Response 只加窄 `result_large_err` allow，公开类型未改 | 最终 excluded check/lint/tests exit 0 |
| `call_vYQpeGouf30n7VjaNkx324mK-stdout.log`，compatible lint unused state | `project_password_revocation` 两 feature 变体统一 `_state`，signature/行为保留 | compatible strict lint exit 0；默认最后测试也复跑 |
| `call_0FQAKgXo2UYPvPIaE8VZLtJ9-stdout.log`，DB 829 passed、1 throughput failed | 多个构建和 Python 并行时只有 16,081 reads/s，低于 sanity floor；失败保留。不下调 threshold，同一测试在隔离负载下复跑 | `call_pkMDXqlF27wMmxW4ljjpABjh-stdout.log`：68,864 sequential / 135,121 concurrent reads/s；随后全 workspace 串行两次通过，不当生产性能证明 |
| `call_z9eSoCmYVJYZTAaucp2jlRYl-stdout.log` / `call_oPLpatZWhCUODmxlDH2Sueyn-stdout.log` | Chat fake owner-transfer/atomic create port 不符合生产合同，bin source marker 缺 connections 参数。修正 fake 精确 owner/membership 和原子 port、实际 serve 参数 | 旧 101-test 快照成功为 `call_olfWt29ZfTuFiXXcq589JPom-stdout.log`；其后又保留 old unbounded/`() API` 并新增拒绝回归，最后 102 passed 的日志取代它 |
| `call_dTsDKQZhPWQRwmi6aTs0cyAk-stdout.log` / `call_3YQQrwLYwmMWqjrZ5sEpTtrS-stdout.log` | Learn ownership actor fixture 错用 subject ID、cascade marker 匹配早期 hard_delete；仅修正对应 fixture/slice。MQ trace scan 加 supervisor 实际日志块，保留禁止 credential source patterns | Learn 最后 41 lib + 13 bin passed |
| `call_YOGuIUjWQs7ksg3FYA6WlqpV-stdout.log` / `call_NOUQuRznbgBjRJqF6ztBuwv5-stdout.log`，standalone locked 未开始 | COPY standalone lock 陈旧；仅 disposable copy offline 解析并保留 locks，再执行 locked lint/tests | 三个 standalone 最后 exit 0；real Cargo.lock 未被临时锁覆盖 |
| 原/后续 Learn lifecycle owner 未完成；主 Agent 接管 partial scaffold | 后续 owner `agent_2b6d9cb9-f23a-4b69-9aeb-4dfa0b6d4abe` 已冻结；现有 main/repository 状态先核对。主 Agent 完成 awaited partial close、stop-interrupt startup、exact marker width、committed cascade/tenant scope 和无 legacy-ID 猜测 | 实际当前源码不存在 handoff 所称 undefined close constant/scope helper。早先 owner `agent_62918e1c-c67b-4974-b385-b7b514198bf8` 未完成也由主 Agent 接管；只以最终门禁为准 |

主 Agent 的最终 Chat 增量安全修补不止 fixture：握手保留原 authority fence，出站 queued frame 当前 session/policy gate，完整 physical-card recipient 去重，socket owner drain，scoped effective read watermark；receipt owner `agent_0054ec6d-51ea-40ea-a76f-2261324de6fd` 仅负责 member/receipt slice，已冻结。Learn 最终 preflight 禁止错误 legacy namespace 删除、约束所有课程 tenant 及 child domain；不把缺 source 视为清理证明。早期 apply_patch 不可用已检测，采用专用 Edit；incremental Rust ICE 后所有本地 Cargo 统一 `CARGO_INCREMENTAL=0`，未清除或回滚用户文件。peer 末次写入导致一次 stale-read Edit 拒绝，拒绝调用无写入，冻结并重读后才由主 Agent 接管。

### 10.4 未执行与最终交付边界

源码级缺口及其本地回归已完成；最终结论不是整体 PASS。所有外部 required gate 尚未启动，因本次没有部署/基础设施/迁移批准或真实环境前置，标记为 BLOCKED，而非 FAIL 或 PASS。未启动 gate 的不确定性不是某个已执行 durable 操作的 UNKNOWN 终态；本次没有实际业务 PENDING 操作。源码中的 UNKNOWN/IN_DOUBT 恢复合同仍需真实验收。

| 尚未执行的 required evidence | 状态及原因 |
|---|---|
| 五份 migration/pre-adoption、真实 schema drift/constraint/FK、standby 条件和 backup/restore/forward-fix 演练 | BLOCKED；五份 SQL 仅准备并 pin，未连接数据库或执行 DDL/DML |
| credential revision/MFA 抢占、password/reset/session/JTI closure、物理双卡、replay/audit 和 batch item 原子性 | BLOCKED；本地纯/mock/source-shape 不能证明真实 MySQL locking/commit/cancellation |
| Local exact-row concurrent claim/FIFO/token、handler 完成 CAS、expired PROCESSING 对账、fanout lease/publish/inbox/ACK | BLOCKED；DB/RabbitMQ 服务和 ignored 集成未运行，不能由 mock confirm 推导 delivery |
| batch request cancellation/unknown registration 的物理 DB 对账、跨 owner restart、shutdown/socket/connection/source-writer/crash proof | BLOCKED；只执行 controlled task 状态测试，未故障注入真实进程/连接 |
| Chat durable intent/recipient idempotence/read watermark、Learn cascade/default-grade/capacity/legacy crosswalk | BLOCKED；冻结 excluded 不变，historical NULL marker/legacy namespace 需独立数据映射与验收 |
| 实际 Redis adapter/默认所有服务启动、单机 cold/warm 启动和授权 read-port zero-DB 观测 | BLOCKED；default normal tree Redis rows 0 与兼容 lint/tests 不构成运行时证明 |
| 跨节点/跨城 stale-ALLOW 窗口、单写者/旁路隔离、分区/双城 receipt/activation、snapshot Windows/crash/restart | BLOCKED；未建立真实两城依赖和运行证据，保持 default-off |
| PowerShell 执行、Java benchmark 外部父模块兼容、真实 campaign/压测/OPA | BLOCKED；pwsh 不存在，Rust/pure validation 不替代其他 toolchain 或真实 traffic |
| 历史 DENY/BASE/OVERLAY、旧 NULL session、raw-rule SoD 及各 BREAKING CHANGE 兼容验收 | BLOCKED；不盲填历史证明、不启用旧 unsafe fallback |

未启动 MySQL、RabbitMQ、Redis、Docker、Identity/TrustGraph/Gateway/Monitor 或冻结服务；未执行迁移、ignored integration、通知、业务消息、部署、提交或推送。default active workspace、explicit-compatible、excluded、archive/bench/offline 工具的覆盖和 skipped 已分别登记，不能合计为“整个项目外部集成通过”。部署仍需用户批准、allowlist/runId/preflight、适用 backup/restore/rollback、明确 postcondition 和人工终审。

主 Agent 最后确认：真实 root `Cargo.toml`、`AGENTS.md`、tracked historical migration 均零 diff；tracked 文件没有删除。真实 `Cargo.lock` 只增加 dependency edges 和 `wasm-streams 0.5.0`，没有已有版本升级；Chat sha2、Gateway reqwest stream、bootstrap uuid、Learn default-empty compatibility feature 及 policy-engine task-local Tokio edge 为本次所需。安全 Explore owner `agent_5e48c196-4017-4ca0-bfe5-13a3c65b38e2` 的有界检查覆盖当时 25,928 added tracked lines 和 1,558 untracked lines，未识别真实 credential/provider token/private key/非 loopback server IP；主 Agent 对最后 Chat adapter/relay/本文再执行不输出匹配值的 pattern 检查，候选为 0。以上是有界 review，不宣称普遍 secret-free 保证。

最终必需 command/process 均已结束，runner 没有 pending 验证；文档引用的日志全部存在，relative links、heading/fence 结构、`git diff --check` 均通过。文档更新后的 675-file source hash 仍为 §10.1 身份；COPY 与实际源码通过忽略本文及明确 temporary inputs 的 checksum 比较，只有目录 mtime 变化，不存在文件内容差异。纯证据修改不冒称再跑 Rust tests。

Exec-L1 资源已清理：主 Agent 先检查 owned `/tmp/astrallight-five-chain-build.MgM6QC` 和 `/tmp/astrallight-five-chain-excluded.HHR6qG` 的类型、owner、内容及运行状态，再删除本次 toolchain/target/副本，约回收 29 GiB。全局 profile/toolchain 和真实 worktree 不受影响。复现所需 COPY manifest、root lock 及三个 standalone lock 在删除前归档为日志目录下的 `five-chain-disposable-lock-inputs.tar`（仅上述五个输入文件），SHA-256 `5970f273c08c90ad60c9de0b42859bbfd44a542a5e9f7528c08e47bd17a5f022`；命令日志持续保留，不另造第二份验收记录。临时路径现在不存在，重复验证需重新建立隔离环境，不能声称原二进制仍可用。

截至 §10.4 源码修补收口时，工作为 repair 分支的未提交源码/测试/SQL/工具/本文变更；外部审批和部署验收不在该次源码修补的完成结论内。后续 Git 发布批准单独记于 §10.5，不改变此前未执行项。

### 10.5 2026-10-04 Git 发布批准与前置

用户随后明确要求“推送并将PR合并到main分支”，并要求“安装git并配置”“通过GitHub登录的方式获取git配置”。此批准限于已验证修补的 commit、推送到 `CoreryBlack/AstralLight.Next` 的 `fix/five-chain-review-gaps`、创建 PR 并经 PR 合并至 `main`，不批准部署、迁移执行、数据库操作、服务启动、业务消息/通知、force push、删除分支或修改保护规则。

本任务由主 Agent 负责，Git 外部发布按 Exec-L3；`runId=astrallight-pr-merge-20261004-PtGW9l`，源码 operation identity 为 §10.1 SHA-256，基线仍为 `6b3d8cd4000d881b22d274ba6a7fc8b4711f6f3c`。2026-10-03T18:31:29Z 开始发布前置检查；源码及证据文档与上次最终 hash 一致，之后仅本节的证据说明改动，`git diff --check` 及文档/源码身份检查按本次新增文档范围再执行，不冒称重新跑 Rust。stage/commit 只包含前轮复核的 136 tracked changes 和 9 additive files。

系统已有 Apple Git 2.50.1，无需重复安装。用户级官方 GitHub CLI 2.102.0 的包经官方 checksum 校验后安装，不修改系统 toolchain；GitHub device login 已完成，账户为 `CoreryBlack`，Git 作者名称/邮箱从认证后的 user 与 verified primary email API 取得，HTTPS credential helper 由 `gh auth setup-git` 配置，拉取仅 fast-forward、推送 simple。token、密码及验证码不写入仓库或本文。

主 Agent 及只读规范 owner 完成 preflight：远程 main 与基线相同，目标远程 repair 分支/PR 不存在；登录账户为 ADMIN，允许 merge commit；main 未受 GitHub branch/ruleset 保护，仓库 Actions workflows 为 0、server webhook 为 0，checkout 无 `.github` 或 active Git hooks。本地规范仍要求只通过 PR 合并 main，不因远程未保护而直接 push main，不使用 admin bypass。合并方式采用与 PR #1/#2 一致的 merge commit。规范检查见 `AGENTS.md` §1/§5/§7、Rust 规范 §17 和 `CONTRIBUTING.md`，没有运行手动 deploy/migrate/test-infrastructure 脚本。

完整本地技术门禁、ignored 和真实集成 BLOCKED 保持 §10.3/§10.4 的原状态；Git 合并不构成 deployment acceptance。发布 rollback 为独立审批的 revert/forward-fix PR，不自动 reset/rebase/force push main，也不改变新 schema 或重放未知操作。

实际 postcondition 必须分别确认 pushed branch OID 等于本次 commit、PR base 为 main/head 为该 OID、无 conflict/pending/failing required check、PR merged state/merge commit OID，以及远程 main 包含该 merge commit且文件树与已发布快照一致。发生网络/runner unknown 时先通过只读 API/remote refs 对账，不盲目重复 create/merge。前期远程 refs lookup 的 HTTP/2 framing 和 HTTP/1.1 empty-reply 失败均只读，没有外部 write；认证后改用本次 DNS 解析的 IPv4 与单次 `http.version=HTTP/1.1`、`http.curloptResolve` 参数，读取远程 main 已成功且等于基线，不修改全局网络配置、不将地址写入 tracked 文件。

最终暂存验证揭示此前 unstaged `git diff --check` 未包含 additive/untracked SQL：`git diff --cached --check` exit 2，仅报告 `20261003000001_identity_credential_fence.sql` 的尾部空行（第 117 行），无功能/SQL 合同差异。为保留已冻结原始字节和 SHA-384 pin，不在发布时改写迁移；明确接受这一条 EOF 空白警告，而非默认 staged check PASS。另以单次 `git -c core.whitespace=-blank-at-eof diff --cached --check` 检查其他空白错误，且不改仓库或全局 whitespace 配置。§10.3/§10.4 的旧 unstaged exit 0 只对应其当时范围。

commit/push/PR/merge 的实际结果保留在同一会话命令日志和 GitHub PR 中，不伪填本文的未来成功状态。
