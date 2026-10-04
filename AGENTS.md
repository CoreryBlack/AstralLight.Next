# AstralLight Rust 项目编码规范（Agent 规则入口）

> 版本：2.5.0
> 更新日期：2026-10-04
>
> **本文档是仓库唯一的 Agent 规则入口**。CLAUDE.md、`.trae/rules/project_rules.md`、`.trae/skills/project_rules.md` 已移除，不新增规则副本。
> **工程规范正文的唯一规范源是 `Docs/规范/`**，其目录清单以 [`Docs/规范/README.md`](Docs/规范/README.md) 为准。
> API、架构、迁移、DDL、部署、JSA、实验和用户手册是各自主题的事实/证据来源，但不能覆盖本文件的 Agent 执行门禁，也不能冒充 Agent 规则。
> AGENTS.md 只负责 Agent 执行门禁、风险分层、关键不变式、最小验证入口和规范导航；Java、Rust、GitHub 及其他实现细节以对应 Docs 正文为准。

## 0. 使用方式（必读）

1. 会话开始时阅读本文档（AGENTS.md 由 Agent 自动加载）。
2. AGENTS.md 对 Agent 委派范围、主 Agent 审查、证据记录、用户 `git push` 审批以及只读/写入边界具有执行门禁效力；这些门禁不得被其他文档覆盖或绕过。
3. 实现、架构、Java、Rust、GitHub、消息、迁移和部署语义，按变更面读取 §8 与 [`Docs/规范/README.md`](Docs/规范/README.md) 中对应的规范正文；不要求无关任务通读全部规范。
4. 工程规范正文只认 `Docs/规范/`；AGENTS.md 的 Agent 执行门禁不受其他资料覆盖。API、架构、迁移、DDL、部署、JSA、实验和用户手册只作为各自主题的事实/证据来源；实现和领域语义按对应 Docs 正文读取，只有 Agent 执行门禁、关键不变式或规范入口变化时才同步 AGENTS.md。
5. 任何不确定的权限、数据、消息、迁移或部署语义，先暂停写入并补读对应规范、契约或验收材料。

---

## 0A. Agent 协作模式（按风险、依赖与成本自主调度）

### 0A.1 职责边界

- 软件与模型根据风险、依赖、并行收益、上下文成本、交接成本和供应商可用性，自主选择由主 Agent 连续执行、委派子 Agent，或在 ownership 清晰且合并/对账方案明确时批量并行；不得把是否启动子 Agent 与 `Exec-L0`/`Exec-L1`/`Exec-L2`/`Exec-L3` 机械绑定。`Exec-L*` 只决定安全控制、审批和验证要求。
- 主 Agent 可以直接执行可控的局部写入和验证；涉及高风险动作时必须指定责任 Agent 并完成完整审查，责任 Agent 可以是主 Agent 或子 Agent。发生委派时由主 Agent 审查；不委派时由责任 Agent 承担等同审查和最终验收责任。
- 委派任务必须限定目标、文件/模块范围、风险等级、验收标准和不执行项。子 Agent 不得递归委派，不得擅自扩大范围，不得绕过主 Agent 直接向用户汇报、提交、推送或宣布验收。
- 互不依赖的任务仅在 ownership、合并/对账方案和收益均清晰且为正时批量并行；存在共享写入、数据、事务或部署依赖时按序执行。交接成本更高或供应商不可用时，允许单 Agent 连续完成。
- 子 Agent 限流、stream 断流、超时、空返回或不可用时，主 Agent 可以接管；接管仍须遵守用户批准、五链审查和对应 `Exec-L*` 门禁。

### 0A.2 计划、接管与审查

1. 变更前明确目标、涉及文件、风险等级、验收标准、不执行项，以及是否委派和选择依据。
2. 低风险产出以证据核对为主：确认文件范围、命令结果、未修改其他文件和验收项；高风险产出须闭合调用链、权限与数据边界、失败和恢复路径、幂等/并发、审计和验证证据。
3. 发生子 Agent 失败后的接管是新尝试。接管前先检查 `git status`、`diff`、未跟踪文件、进程/命令状态和适用的 durable postcondition；没有回报不等于没有执行。
4. 只有在存在稳定 `operationId`/`messageId`、幂等、CAS/lease 且已完成对账时才可重试；应设置有限的 dispatch/retry 预算，连续失败后由主 Agent 接管或报告 `BLOCKED`，不得无限重复派发。
5. 所有执行共用一份可追溯证据记录。发生委派时记录子 Agent 回报；未委派时由责任 Agent 填写等价字段。发生委派时主 Agent 审查通过，未委派时责任 Agent 完成等同审查和最终验收，之后才可向用户汇报。

---

## 0B. 变更五链审查（按适用范围强制）

五链仅对以下变更强制：外部行为、认证授权、schema/migration、projection/cache、消息或异步副作用、审计、故障降级或恢复。纯文档、格式、注释、只读调研和无行为测试可标记 N/A，不得因形式审查阻塞交付。

| 链 | 必查内容 |
|----|----------|
| **调用链** | 所有调用方对返回值、副作用时序、异常传播、异步边界的假设是否仍成立。 |
| **逻辑链** | 分支、权限、租户隔离、缓存失效、事务边界、投影状态和兼容入口是否产生绕过或遗漏。 |
| **事故链** | DB/缓存/MQ 不可用、超时、并发冲突、熔断、worker 重启或部分写入时，降级是否保持 PENDING/DENY 或安全默认。 |
| **数据链** | 数据来源、类型转换、持久化、head/outbox、projection/cache、读取门、空值与 generation 是否一致且可恢复。 |
| **审计链** | 授权、敏感访问和权限变更是否有可关联、去重、可重试的审计事件；旁路失败和降级是否仍可追溯。 |

实施前识别受影响链，实施后用同一份证据记录处理方式和验证结果；不适用链标记 N/A 并说明原因。

---

## 0C. 执行分层与安全预算

执行前为动作标注 `Exec-L0`/`Exec-L1`/`Exec-L2`/`Exec-L3`；`Exec-L*` 只表示 Agent/工具动作风险。Rust/Java Docs 中 PolicyEngine 评估阶段的 `L1/L2/L2.5/L3` 与缓存路径级别属于另一命名空间，禁止混用。执行预算包括有限的时间、重试、并发和外部影响。Exec-L0 文档/检索不要求重试上限、审计/指标、phase timing 或 stream disconnect 等运维仪式；Exec-L1 及以上，或存在 durable/外部副作用、异步/流式边界或安全控制的动作，按适用项设置有限重试上限并记录审计/指标、phase timing 和 stream disconnect。预计有 durable 或外部可见副作用时，必须立即按副作用类型升级到 Exec-L2/Exec-L3。具有 durable 或外部可见副作用的操作必须使用稳定的 `operationId`/`messageId`；Exec-L1 临时资源使用 run-scoped 标识并自动清理。身份和完整性只认内容 hash、协议字段或稳定的 operation/message id，不得绑定 inode、设备号或其他易漂移的环境元数据；需要并发占有时使用 CAS lease，需要防止陈旧执行时使用 generation/token fence。

| 等级 | 定义与最低要求 |
|------|----------------|
| **Exec-L0 只读** | 检索、解释、状态/结构检查、规范导航。不得写工作区、切分支、启动服务/容器/迁移或产生外部副作用。 |
| **Exec-L1 隔离临时副作用** | 仅允许临时目录、临时构建产物或可丢弃沙箱内的隔离动作；限制权限、范围、时长和容量，资源必须有 run-scoped 标识并自动清理，失败可清理。绝不写入 durable 数据、发布消息、改变外部系统或产生外部可见结果；预计有 durable 或外部可见副作用时立即升级到 Exec-L2/Exec-L3。 |
| **Exec-L2 durable 内部可重试动作** | 只处理已批准的 durable 内部事件、projection、outbox、DLX、quarantine、compensation 等，不直接向外部承诺结果。projector/worker 只能物化事件已批准的 source mutation，不能自行创造新授权或新的 source mutation。`READY`/materialization 不要求每个 worker 周期重新人工审批，但必须继承事件的 `operationId`/`runId`、审计和 generation/token fence。必须有 stable operation/message id、CAS lease、generation/token fence、有限重试、审计/指标，并在 ACK 前证明 durable state 已落盘；未知内部结果先对账再重试。 |
| **Exec-L3 外部可见或破坏性动作** | 批准对象是生产 source authorization mutation、部署，或外部可见/破坏性动作。迁移、删除和破坏性数据操作需要备份及恢复或 forward-fix；外部发布/通知需要幂等、补偿或撤回；权限生效需要已批准 source mutation、generation/revoke/rollback；部署需要 rollback。所有 Exec-L3 都必须有用户批准、allowlist 与 `runId`、preflight、明确 postcondition/验收和人工终审；不得把备份无条件套用于所有动作，也不得通用自动重放。 |

- 失败仅在确认无 durable side effect，或已有稳定 id + CAS/lease/幂等保护且未知结果已完成对账时可重试；不能仅凭“没看到外部变化”重放。
- `exactly-once` 只对外部可见副作用承诺；内部动作依靠幂等键、CAS、generation/token fence 和 durable proof 实现可重试的一致语义。
- 任何动作都不得把缓存、旧快照、source 读取或“看似成功”的 ACK 当作 durable proof；无法证明时返回 PENDING/DENY 或报告未知，不得扩大授权。

---

## 0D. 效率、交接与观测规则

- 确定性检查前移：先完成路径、类型、契约、权限边界、文件范围和静态检查，再进行高成本验证。
- 自造包装门禁连续两轮无法修好时，仅允许在 Exec-L0/Exec-L1 且确认无 durable/external side effect 的路径降级到标准工具；不得用于认证、授权、projection、migration、audit、消息发布或任何 Exec-L2/Exec-L3。必须记录降级原因、覆盖缺口和残余风险。Exec-L3 不得以此绕过人工终审。
- 按风险适用：仅对 Exec-L2/Exec-L3、认证授权、数据/schema/projection、消息/审计或其他会产生 durable/外部影响的新增安全控制，要求写明攻击者模型、目标故障、阻断点、误放行/误拒绝代价和验证方法；Exec-L0/Exec-L1 的纯读取、临时构建/测试和无行为变化检查只需记录适用性与残余风险，不得因形式记录制造额外仪式。
- 缓存必须有 TTL、容量边界和 GC/清理策略；缓存失败、过期、污染或不可用不得扩大授权，默认转为 PENDING/DENY 或安全降级。
- 交接或 worker 重启时记录停用记录、恢复/重启/重载步骤，保留并验证 worker ownership；readiness 与 liveness 必须分开判断，不能用存活代替可接管或可服务。
- Exec-L1 及以上，或涉及 durable/外部副作用、异步/流式边界或安全控制的动作，按适用项记录单调递增的 phase timing、retry 次数和 stream disconnect；同时区分墙钟时间与累计 turn 时间，避免用其中一者冒充另一者。Exec-L0 文档/检索不产生这些运维仪式。

---

## 0E. 耦合审查与大文件治理（随任务执行）

高内聚、低耦合检查是代码任务自身的一部分，不默认另开独立审查任务、不强制启动审查子 Agent，也不另造报告或规则副本。模块职责、依赖方向、分层和 trait 设计仍以 [`Rust后端编码规范_V1.0.md`](Docs/规范/Rust后端编码规范_V1.0.md) 为准；本节只规定 Agent 何时检查、如何控制改造范围与验收。

### 0E.1 日常变更门禁

1. 新增功能、Bug 修复和重构均检查**本次修改模块与直接调用方**的耦合，不默认全仓扫描。只读任务只报告；纯文档、格式和注释可标记 N/A，不为完成检查扩大写入范围。
2. 修改前识别职责 owner、输入输出与公共导出、直接依赖、共享状态，以及事务/异步副作用的边界；同时检索受移动影响的调用方、测试、`include_str!` 和源码文本锚点。沿用 §0A 的任务计划与 §7 的证据记录，不额外要求架构图或独立审查流程。
3. 修改目标文件时，生产逻辑超过约 **1,000 行**、总行数超过约 **2,000 行**，或混合多个独立职责/业务域/副作用 owner，应检查局部拆分机会。生产逻辑、测试、静态契约表和 fixtures 分别看待；行数只是审查提示，不是硬性上限，不得机械切割事务或单一算法。
4. 在现有 owner 内可闭合调用方、保持行为与契约并完成验证的必要局部抽取，默认**在同一任务内完成**，优先复用已有模块与注入接口。不继续向大文件、万能状态对象或宽泛 trait 叠加无关职责，也不把已明确的局部耦合问题只留作“以后另开优化任务”。
5. 独立任务只用于确实超出当前目标的跨域 ownership、公共契约、schema 或事务/恢复语义改造，以及无法在本次安全验证的广泛重构。此时保留现状并记录具体边界、暂缓原因与风险；不得为解耦擅自扩大授权、删除兼容入口或改动无关文件。

### 0E.2 当前耦合审查重点

本次审查发现的主要问题是职责集中、共享状态传播和源码布局依赖；下表作为后续触及这些模块时的检查导航，不要求每项任务逐项全仓重审。文件规模、依赖和拆分状态须以当次源码核对，不以历史报告宣称已经解耦。

| 热点 | 定位入口 | 随任务检查重点 |
|------|----------|----------------|
| 组合根与共享状态 | Identity/TrustGraph 的 `runtime.rs`、`lib.rs`、`AppState` | 装配、路由与 worker/consumer 生命周期是否纠缠；是否把仅单个用例需要的依赖继续扩散到全局请求状态。 |
| 共享 port 与授权/投影路径 | `policy-engine/src/engine/`、`astral-trustgraph/src/service/authorization_projector/` | port/DTO、正式与 realtime 路径、纯 planning 与 durable runtime 的边界是否清晰；是否又把已分离职责合回单文件或扩大共享接口。 |
| 授权持久化与迁移 | `astral-db/src/authorization_projection_repository.rs`、`migration.rs`、`grant_repository.rs`，以及卡片/规则集写仓储 | 按 aggregate/table owner 定位职责；source、ledger/delta、审计关联及提交后副作用是否仍有明确边界；拆分是否保持原事务与锁序。 |
| 缓存、传输与审计 | `astral-db` 的 evidence cache/memory hub/eligibility，`astral-mq/src/consumers.rs`、`astral-common/src/audit.rs` | 严格证据读取、缓存策略、业务消息处理、传输适配和任务 ownership 是否互相侵入；是否引入新的全局状态或重复失效逻辑。 |
| 导出与源码形状测试 | façade/re-export、`include_str!`、`include_bytes!`、`split()` 源码守卫 | 物理文件移动是否改变公开路径或测试覆盖；是否遗漏拆出的生产文件，或由测试自己的字符串字面量造成自引用假阳性。 |

### 0E.3 拆分与完成核对

- 按职责和数据/副作用 owner 拆分，不按行数搬代码。测试外移只能算生产/测试分离，入口文件变短也不代表依赖已减少；最终说明实际职责与依赖边界的变化，不把旧的待拆生产代码宣称为已完成。
- 结构移动与行为修复分别审查。公共 API 按 §3.3 保持兼容；内部可见性取最小范围，不得仅为解决拆分后的编译错误扩大到 `pub(crate)`/`pub`，也不靠新的全局对象、宽泛通配导入/导出或重复实现重新粘合模块。
- 源码守卫必须只扫描真实生产区域，并覆盖拆出的相关文件；同步修正相对路径与锚点，保留原安全断言。可行时用行为/契约测试替代布局断言，不通过放宽断言、遗漏扫描或 lint 豁免制造通过。
- 授权 fail-closed、租户边界、事务与锁序、lease/CAS/fence、worker ownership/关闭顺序和审计关联按 §0B、§3 审查；按 §5 执行最小充分验证。在同一份证据记录中写明职责/依赖变化、保留的耦合及原因、验证结果与未执行项，避免再为本次变更新建独立优化审查。

---

## 1. Agent 写入与提交流程（按任务类型适用）

### 1.1 写入或提交任务

1. 写入、提交或其他 durable 任务开始前执行 `git status`，确认分支、工作区现状、目标文件和影响范围；不得覆盖或回滚用户已有修改。
2. 按 [`Docs/规范/README.md`](Docs/规范/README.md) 管理分支和提交。禁止直接在 `main` 开发或推送，禁止强推；每项变更关联 Issue 或文档。分支命名、Commit、PR 和发布细节只以该规范正文为准。
3. 阶段冻结例外只是不受“功能新增冻结”阻塞，仍须执行适用的 Exec 分层、五链、验证、Issue/PR、审批和 Exec-L3 门禁；其范围包括安全修复、Bug 修复、迁移、测试、文档、内部重构和只读调研。
4. 只读取与变更面直接相关的规范和同类文件；不把 Java/Rust/GitHub 正文复制到 AGENTS.md。
5. 只进行按 Exec 风险等级允许的最小充分验证；明确报告已执行、未执行、失败、降级和残余风险。
6. 提交只暂存本次变更文件，遵循 Conventional Commits；提交和推送是两件事，Agent 不得擅自推送。
7. 所有 `git push` 必须先获得用户明确审批；`main` 仅通过 PR 合并，其他分支也不得绕过仓库保护。

### 1.2 只读任务

只读任务不切分支、不修改工作区、不执行写入命令，不启动服务/容器/迁移；可直接做检索、规范导航、单文件解释和简单状态检查，并报告证据边界与未执行项。

### 1.3 Squash 后清理

只有用户明确要求、工作区干净且待清理分支没有独有提交时，才适用本地分支清理。dirty worktree 禁止 `git reset --hard`，不得用分支切换或清理动作覆盖未提交内容。详细协作规则见 [`Docs/规范/README.md`](Docs/规范/README.md)。

---

## 2. 架构速览

```
AstralLight-Next/             # Rust workspace + Rust-specific Docs
├── astral-types/              # 共享类型、实体、错误模型与资源注册表
├── policy-engine/             # 权限评估、编译内核、strict evidence gate
├── astral-common/             # 配置、错误、API 契约、中间件、审计与可观测性
├── astral-db/                 # SQLx repository、迁移、投影与证据持久化
├── astral-cache/              # Redis 缓存与消息幂等；已退出 workspace（exclude 自包含 archive，源码零删除，见规范 15.3）
├── astral-mq/                 # RabbitMQ 消息契约与传输
├── astral-gateway/            # Gateway 身份校验与请求转发
├── astral-identity/           # 身份、会话、JWT 与卡片管理
├── astral-trustgraph/         # 治理、审批、审计与授权投影
├── astral-monitor/            # 监控、指标与告警
├── e2e-bootstrap/             # 隔离启动入口
├── astral-chat/               # 冻结源码，Cargo workspace exclude
├── astral-learn/              # 冻结源码，Cargo workspace exclude
└── Docs/                      # Rust 工程规范、架构、迁移与 schema
```

模块边界、投影 owner、MQ 消费者和消息幂等以 [`Docs/规范/Rust后端编码规范_V1.0.md`](Docs/规范/Rust后端编码规范_V1.0.md)、[`Docs/规范/统一消息协议与智能层消息规范_2026-03-18.md`](Docs/规范/统一消息协议与智能层消息规范_2026-03-18.md) 及 [`Docs/规范/README.md`](Docs/规范/README.md) 为准。

---

## 3. 关键不变式（严禁违反）

> 本节保留跨模块、权限、数据安全和恢复所需的不变式；源单仓库中 Java/前端专属条目在本独立 Rust 仓库中标记为不适用，但不删除执行门禁。

### 3.1 Gateway 与统一授权链路

1. Gateway 是外部认证事实入口；下游只有在验证 Gateway 身份头签名、时间戳和来源后，才能信任身份字段。带有网关元数据但验签失败时必须拒绝，不得回退原始头、伪造头或客户端自带身份。
2. Identity 负责身份/会话生命周期，TrustGraph 负责授权决策；授权唯一入口是 `PolicyEngine.evaluate()`。
3. 禁止角色、`isSuperAdmin()`、旧角色映射、客户端菜单或直接查询 source/snapshot 作为授权旁路。`isSuperAdmin()` 只可用于日志、审计或 UI 展示，不得用于放行。
4. 权限采用规则/规则集模型；评估必须同时满足用户、有效 `user_card`、资源、动作和租户隔离约束，任何缺失或不一致均 PENDING/DENY。

### 3.2 双卡、租户与有效授权变更

- `identity_card` 表示认证身份，每人一张；`user_card` 表示授权载体，每人可多张。两者不得混用，权限不得从旧角色映射旁路取得。
- 所有有效授权读取和写入都必须带租户边界；跨租户数据、缓存键、projection 和审计关联不得相互污染。
- **凡影响有效授权或资格的 source mutation**，必须按对应 aggregate contract 进入 durable source/evidence path；CARD/RULE_SET 使用 head/outbox + audit correlation，ELIGIBILITY 使用其自身记录的资格/缓存失效路径，不能被遗漏，也不能被误当成规则快照刷新。正式授权路径的 projection/read-gate 不足时只能返回 `PENDING` 或 `DENY`。
- source transaction 只覆盖必要的 source、durable head/outbox 和 audit correlation 写入；不得把网络、MQ/Redis、快照构建、重试、安装或验收放进事务。提交后由 projector/worker 处理 durable projection、缓存失效、消息和审计。
- `CARD` refresh 与 `ELIGIBILITY` cache eviction 是不同语义，必须分别记录、分别失效和分别验证，不得用一个事件代替另一个。
- 正式授权路径必须同时满足 generation、dependency、`READY` 和 read-gate；任一不足、unknown、failed 或 stale 时只能 `PENDING`/`DENY`，禁止使用旧快照、source/raw 读取或缓存回退放行，不得以 ACK 代替 durable proof。
- 如必须保留 Java `CARD_ONLY` 迁移兼容，只能是对应 Docs 已登记、default-off 或仅在明确迁移窗口配置时启用的逐卡/租户边界例外；必须有审计、指标、到期日和替代路径。unknown/failed/stale gate 仍只能 `PENDING`/`DENY`，不得授权于 raw/source 读取或未证明的旧快照；仍必须经过 `PolicyEngine.evaluate()`，不得扩展为通用 fallback。

### 3.3 规则、资源与路径

- 新资源和动作先注册到 `ResourceRegistry.REGISTRY`，再使用 `@RequirePermission`；启动扫描必须能发现未注册资源/动作。
- 规则集共享和 BASE/OVERLAY 语义遵循实现规范；新的长期路径不得直接制造旧 TEMPLATE `permission_rule` 写入或旧映射 owner。
- 新接口使用已冻结主路径、复数资源名和 `kebab-case`；不得新增 camelCase 路径段、裸资源、`/duo/**` 或新的外部 `/identity/**` 路径。
- 路径规则不得误伤已冻结的 TrustGraph `/main/api/v1/**`；该路径是现有主入口，不应被“禁止新增 `/main/**`”之类的宽泛规则错误拦截。其他冻结路径和兼容窗口以 [`统一接口路径规范_V5.md`](Docs/规范/统一接口路径规范_V5.md) 为准。
- Rust 0.x workspace 内部接口只有在本次变更清单逐项列明、同步迁移全部仓内调用方/测试/文档，并标注 `BREAKING CHANGE`、替代入口、影响范围、生效时间、迁移方案和回滚方案时，才可直接下线；稳定 `pub` API、跨仓或外部 HTTP、消息及消息协议、数据库协议和既有 `compatibility`/`legacy` 入口不适用，不得隐式删除。

### 3.4 事务、投影、消息与恢复

- Rust 的分层、事务、projection、消息和错误语义以 [`Rust后端编码规范_V1.0.md`](Docs/规范/Rust后端编码规范_V1.0.md) 为准；Java 专属实现不在本独立仓库范围内，本文件不复制实现正文。
- 对 CARD/RULE_SET 授权 projection 而言，durable head/outbox 是 source mutation 与提交后 worker 的边界；ELIGIBILITY 只处理其自身资格记录和缓存失效语义。projector/worker 只能物化已批准的 source mutation，不得自行创造新授权；worker 必须保留 ownership、CAS lease、generation/token fence、幂等和有限重试，未知结果先对账。
- source transaction 必须保持短事务边界，只覆盖必要的 source、durable head/outbox 和 audit correlation 写入；网络、MQ/Redis、projection/快照构建、重试、安装和验收均在事务外执行。
- 迁移必须按所在技术栈规范设计可回滚、可恢复、可重入的步骤，并完成 preflight、备份/恢复演练和 postcondition 验证后才可进入 Exec-L3。
- 投影不一致、消息 ACK 无 durable proof 或恢复状态未知时默认 `PENDING`/`DENY`；其中因审计证据不足而触发 `PENDING`/`DENY`，仅限授权变更、敏感访问、关键写操作及 projection audit correlation。普通成功 `ALLOW` 的审计频率和是否同步由对应技术栈 Docs 决定，本文件不新增“每次 `ALLOW` 必须同步审计”的要求。

### 3.5 迁移、秘密与敏感事件

- 迁移接口、表名、顺序、回滚和验收遵循栈对应规范与 [`Docs/迁移/README.md`](Docs/迁移/README.md)；迁移不是普通重试任务。
- Git 跟踪文件不得硬编码 IP、密码、Token、密钥或数据库连接串；脚本使用环境变量占位符，文档不得记录服务器 IP。
- SQL 必须使用参数化查询/绑定参数；禁止把用户输入或未经白名单约束的值拼接进 SQL。
- 发现秘密泄露或敏感事件时，处置顺序为撤销/轮换、隔离、清理、审计和验证；对外推送或历史清理必须按 Exec-L3 批准流程执行，不得擅自推送。

### 3.6 文件读取与 Unicode 安全

- 非源码文件（`.md`/`.log`/`.txt`/`.json`）优先按行范围读取，单次不超过 200 行；日志优先关键词检索。
- 只读任务发现乱码、无效代理对或不可见字符时，仅报告异常、位置和影响，不原样输出字符，也不修改无关文件。
- 只有在写入任务明确包含该文件时，才按任务范围修复编码问题；修复后按变更面验证并报告。

---

## 4. 规范遵循与事实源

- `Docs/规范/` 是工程规范正文的唯一规范源，`Docs/规范/README.md` 是其目录清单；AGENTS.md 不复制 Java、Rust、前端、GitHub、消息或迁移规范正文。
- 后端分层、认证授权、事务、审计、检查脚本读取 [`Rust后端编码规范_V1.0.md`](Docs/规范/Rust后端编码规范_V1.0.md)；前端工程质量门在本独立 Rust 仓库中 **N/A**，如未来重新引入前端目录，必须恢复对应规范；分支/Commit/PR 读取 [`Docs/规范/README.md`](Docs/规范/README.md)。
- API 路径读取 [`统一接口路径规范_V5.md`](Docs/规范/统一接口路径规范_V5.md)，消息/ACK/trace/audit 字段读取 [`统一消息协议与智能层消息规范_2026-03-18.md`](Docs/规范/统一消息协议与智能层消息规范_2026-03-18.md)，Rust 读取 [`Rust后端编码规范_V1.0.md`](Docs/规范/Rust后端编码规范_V1.0.md)。
- API、架构、迁移、DDL、部署、JSA、实验和用户手册按 §8 相关文档读取；它们是各自主题的事实/证据来源，不能覆盖 AGENTS 执行门禁，也不能冒充 Agent 规则。若 Docs 正文更新且影响 §3 不变式，只同步摘要，不在 AGENTS 中复制正文。

---

## 5. 按变更面最小充分验证

验证范围随风险和变更面增加，不以“全量命令”替代风险判断。本地检查可按变更面最小化，但 Rust 提交/合并/CI 仍保留 workspace gate。共享契约、权限链、schema/migration、跨模块/跨 crate 或 Exec-L3 变更，合并前必须完整验证；其余任务优先使用相关模块的最小检查。

| 变更面 | 最小充分验证 |
|--------|--------------|
| 只读、纯文档、格式、注释 | 文件范围、Markdown 结构/链接（适用时）和工作区未误改；五链 N/A。 |
| Java/Web 前端或后端 | **N/A（本独立 Rust 仓库不包含这些技术栈）**；如未来重新引入对应目录，必须恢复其栈专用质量门，不得用 Rust gate 替代。 |
| Rust 后端 | 局部优先目标 package/crate 的 `cargo check -p <package>`、相关测试和必要 lint；共享契约、权限链、schema/migration、跨 crate 或 Exec-L3 才扩展到全 workspace。Rust 提交/合并/CI 的 workspace gate 保留为 `cargo check --workspace`、`cargo clippy --workspace -- -D warnings`、`cargo test --workspace`、`cargo fmt --all -- --check`；不是所有本地局部检查的默认要求。 |
| schema/migration/部署 | 按栈规范执行 preflight、备份/恢复演练、迁移/回滚和 postcondition；不得用普通编译替代。 |

每次报告必须列出已执行命令及结果、未执行项及原因、失败或降级路径、残余风险；命令未运行就明确写“未执行”。

---

## 6. 通用约束

- 同一业务能力只能有一个长期主入口，兼容入口必须有下线日期；前后端契约由文档驱动。
- 安全控制必须可解释、可观测、可恢复；失败默认不扩大权限，不以旧快照或 source fallback 隐藏不一致。
- Exec-L1 仅可执行可丢弃且隔离的临时服务或容器，具备 run-scoped 标识并自动清理，且绝不产生 durable 或外部可见副作用；共享服务、数据库迁移、外部可见或破坏性操作仍需用户批准和 Exec-L3 门禁。
- 除上述 Exec-L1 条件外，不启动服务、容器或迁移，不执行外部可见或破坏性操作，除非任务明确、风险分层允许且满足用户批准与 Exec-L3 门禁。
- 不提交密钥、密码、Token、数据库连接串或服务器 IP；不创建规则副本或未经请求的文档。

---

## 7. 任务交接与报告

所有执行共用一份可追溯证据记录，不得另造重复记录。发生委派时记录子 Agent 回报；未委派时由责任 Agent 填写等价字段。记录至少包含：完成项、修改文件、证据/命令结果、五链适用性、未执行项、失败/重试/未知结果、风险和需要决策的事项。发生委派时主 Agent 审查通过，未委派时责任 Agent 完成等同审查和最终验收，之后才可向用户汇报；任何 Agent 均不得绕过该审查直接提交、推送或宣布验收。

### 7.1 证据闭合与最终验证契约

- 每个任务/证据单元必须记录：`taskId`；是否委派；责任 Agent；选择依据；目标文件/模块；固定工作目录；精确命令；环境/依赖前置；开始/结束时间；退出码；`stdout`/`stderr` 或 artifact 路径；日志完整性；预期/实际 postcondition；未执行、跳过、阻塞、失败、重试和未知项。
- 状态定义如下：
  - `PASS`：实际执行、断言和 postcondition 均有证据，且没有未披露的 `SKIP`/`BLOCKED`/`UNKNOWN`。
  - `FAIL`：命令或断言失败，或已经进入 required gate 后，依赖连接失败、健康检查失败或其他 required 前置失败。
  - `BLOCKED`：测试或 required integration gate 尚未启动，且启动所需的前置批准、工具、权限或环境缺失；尚未进入 required gate 的前置缺失不得记为 `FAIL`。
  - `SKIP`：因显式范围、测试框架层过滤、`#[ignore]` 或测试内部主动返回 `[SKIP]` 未执行，不得计为 `PASS`；不能由 `exit 0` 折算为 `PASS`。
  - `UNKNOWN`：stream/runner/远程命令中断、取消、被杀死、超时、管道或日志不完整，或无法证明 durable postcondition；必须先对账。
  - `PENDING`：异步 durable 操作已启动但尚未到达可证明终态。
- 测试内部 `[SKIP]`、Cargo ignored 统计和 `RUST_INTEGRATION_REQUIRED` 必须与退出码分开记录；`exit 0` 不等于业务 `PASS`。不得以历史报告、mock/unit 测试或文档单独证明外部集成成功。
- 发生 stream 断流或 runner 不可用时，记录阶段、时间、重试次数、最后完整证据、退出码和 artifact 完整性，默认标记 `UNKNOWN`。只有独立对账确认工作区、进程、durable state、head/outbox、业务消费、审计和 postcondition 后，才能转为 `PASS` 或 `FAIL`；未知结果不得盲目重试。
- Rust workspace 命令必须从新仓库根目录执行，或显式使用 `--manifest-path E:\OfficialVersion\AstralLight-Next\Cargo.toml`。在上层目录找不到 `Cargo.toml` 只算验证未开始。workspace 只覆盖当前 `members`；`exclude` crate 必须单列为未覆盖并执行专用验证。`cargo test --workspace` 不代表 ignored integration 已执行；完整 integration 必须使用显式 ignored 命令和真实依赖。设置 `SKIP_DOCKER` 或缺少 MySQL/Redis/RabbitMQ 时，不得报告绿色的真实集成 `PASS`。Rust 验证必须记录 cwd、命令、环境、退出码、日志/artifact 和 postcondition。

### 7.2 断流、接管与最终冻结

- 子 Agent 失败后的接管属于新尝试，必须先按 §0A.2 检查状态和 postcondition；保留并关联原 taskId、operationId/messageId、最后完整证据和未知项。dispatch/retry 必须有有限预算；连续失败后主 Agent 接管或报告 `BLOCKED`，不得无限重复派发。
- 最终冻结按以下顺序执行：停止所有写入 Agent/责任 Agent 新增修改；审查 `git status`、`diff`、未跟踪文件和范围；固定最终工作区及 `E:\OfficialVersion\AstralLight-Next` 目录；从最终快照重新执行 required gate；保存证据；独立检查 migration/backfill、head/outbox、generation/fence、snapshot/cache、audit correlation 和业务 consumer evidence；形成最终状态。
- 最终验证后任何写入都会使旧结果只对应旧快照，必须重新验证。单个 `exit 0`、ACK、历史报告、mock/unit 测试或文档不能单独宣布外部集成 `PASS`；必需证据缺失、`UNKNOWN`/`PENDING` 或集成阻塞时不能整体 `PASS`。

---

## 8. 规范导航（以 README 清单为准）

[`Docs/规范/README.md`](Docs/规范/README.md) 是 `Docs/规范/` 的目录清单和维护入口；`Docs/规范/` 是工程规范正文的唯一规范源。以下只提供常用主题导航；其他 API、架构、迁移、DDL、部署、JSA、实验和用户手册链接是各自主题的事实/证据来源，不能覆盖 AGENTS 执行门禁或冒充 Agent 规则。新增或删除规范时，先更新 README 清单，再按 §9 判断是否同步本节。

| 主题 | 规范或资料 |
|------|------------|
| 全栈工程、认证授权、事务、审计、检查脚本 | [`Docs/规范/Rust后端编码规范_V1.0.md`](Docs/规范/Rust后端编码规范_V1.0.md) |
| 前端工程、TypeScript、Vue、CSS、质量检查 | **N/A（本独立 Rust 仓库不包含前端）**；如未来重新引入前端目录，必须恢复其栈专用质量门。 |
| 分支、Commit、PR、审核、发布 | [`Docs/规范/README.md`](Docs/规范/README.md) 与仓库根目录执行门禁 |
| API 路径冻结清单 | [`Docs/规范/统一接口路径规范_V5.md`](Docs/规范/统一接口路径规范_V5.md) |
| 响应、消息、ACK、trace、audit、流式协议 | [`Docs/规范/统一消息协议与智能层消息规范_2026-03-18.md`](Docs/规范/统一消息协议与智能层消息规范_2026-03-18.md) |
| Rust workspace、projection、migration、fail-closed | [`Docs/规范/Rust后端编码规范_V1.0.md`](Docs/规范/Rust后端编码规范_V1.0.md)（文件名保留现状；正文版本以文件头和 [`Docs/规范/README.md`](Docs/规范/README.md) 为准） |
| projection、read-gate、generation 与快照版本栅栏 | [`Docs/架构/Rust架构设计/Rust权限投影快照与版本栅栏_V1.0.md`](Docs/架构/Rust架构设计/Rust权限投影快照与版本栅栏_V1.0.md)、[`Docs/架构/Rust架构设计/Rust增量重建与实时授权边界_V1.0.md`](Docs/架构/Rust架构设计/Rust增量重建与实时授权边界_V1.0.md) |
| audit、reliability、消息恢复与审查证据 | [`Docs/规范/统一消息协议与智能层消息规范_2026-03-18.md`](Docs/规范/统一消息协议与智能层消息规范_2026-03-18.md) |
| migration、rollback、preflight 与 acceptance | [`Docs/迁移/README.md`](Docs/迁移/README.md) |
| 数据迁移 API 与操作指南 | [`Docs/迁移/README.md`](Docs/迁移/README.md)、[`Docs/迁移/README.md`](Docs/迁移/README.md) |
| MQ 部署与架构 | [`Docs/规范/统一消息协议与智能层消息规范_2026-03-18.md`](Docs/规范/统一消息协议与智能层消息规范_2026-03-18.md) |
| 规则模式与权限模型 | [`Docs/架构/Rust架构设计/Rust权限判定与规则集语义_V1.0.md`](Docs/架构/Rust架构设计/Rust权限判定与规则集语义_V1.0.md) |
| 规则模型分析与规则集 DDL | [`Docs/sql/full_schema_v4.sql`](Docs/sql/full_schema_v4.sql) 与 Rust 架构文档 |
| 分布式授权集群测试 | 测试源码与 harness 已公开于 [`Docs/实验/分布式测试/rust-s15/`](Docs/实验/分布式测试/rust-s15/) 和 [`Docs/authorization-validation/`](Docs/authorization-validation/)；历史运行 evidence、节点路由、二进制和部署状态未复制，真实三节点集成需受保护环境、审批和状态证据。 |

---

## 9. 文档维护规则（强制）

1. AGENTS.md 是唯一 Agent 规则入口；禁止新增 CLAUDE.md、`.trae/rules/`、`.trae/skills/` 或其他规则副本。
2. 规范正文只修改 `Docs/规范/` 对应文档，并同步 `Docs/规范/README.md` 清单；AGENTS.md 只在 Agent 执行门禁、规范入口或 §3 关键不变式变化时更新，不承载重构批次进度或完整实现审查报告。API、架构、迁移、DDL、部署、JSA、实验和用户手册不属于 Agent 规则副本。
3. AGENTS.md 负责 Agent 执行门禁和跨模块不变式；Java、Rust、GitHub、前端、消息、路径、迁移和部署细节必须回到对应 Docs 正文维护。
4. 链接统一使用相对路径，禁止 `file:///e:/...` 绝对路径。
