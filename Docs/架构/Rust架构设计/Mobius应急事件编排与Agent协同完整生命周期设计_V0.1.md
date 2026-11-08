# Mobius 应急事件编排与 Agent 协同完整生命周期设计

> 版本：V0.1
> 日期：2026-11-04
> 状态：**未批准的目标设计、Agent/模型选型与工程估算**
> 范围：从应急事件首次预警、初级标准预案推荐与审批，到持续监控、已有策略组合升级、恢复、结案和审计归档
>
> 本文件是面向评审的设计提案，不是已批准架构、实现说明或验收报告。当前仓库已有的审批、授权账本、投影、消息、审计和告警构件只能作为可复用基础，不能被引用为 Mobius 已实现。现有证据边界见[技术储备-Mobius应急策略模板库](技术储备-Mobius应急策略模板库.md)。

## 1. 结论摘要

Mobius 应定义为一个以 `Incident` 为核心聚合的应急事件编排控制面：

```text
预警/信号接入
  -> 事件识别与关联
  -> Agent 推荐初级标准预案
  -> 操作员批准精确计划
  -> 计划验证与执行
  -> 持续监控控制目标
  -> Agent 从已发布策略库组合升级计划
  -> 有界自动执行或重新等待批准
  -> 恢复/回滚/撤销
  -> 结案核验与审计归档
```

设计的关键约束：

1. **事件是生命周期边界**：事件从首次可信预警开始，到控制目标恢复、动作结果核验、临时状态收敛和结案证据完整后才结束。
2. **策略库是封闭世界**：Agent 只能引用已发布、未过期、digest 匹配的策略和调度模板，不能生成新的响应策略模板。
3. **Agent 不是授权者**：Agent 可以分析、推荐、组合和跟踪，但不能批准自己提出的计划，不能直接写业务数据库，不能执行任意脚本、SQL、URL 或未注册工具。
4. **操作员批准精确对象**：批准对象必须绑定事件、计划版本、模板 revision、digest、目标范围、预算、有效期和升级边界，不能使用笼统的“同意本次应急处理”。
5. **自动升级必须有界**：操作员如希望初级预案失败后自动组合策略，必须同时批准明确的 `EscalationProfile`。超出该包的策略、范围、预算、并发、持续时间或动作等级，必须重新审批。
6. **计划执行不等于生效**：执行器返回成功不等于业务状态已经达到目标。必须通过业务 owner 的 durable proof、观察窗口和结案核验确认结果。
7. **未知结果不重放**：超时、断流、worker 重启或外部系统无响应时，状态进入 `UNKNOWN`/`IN_DOUBT`，先按稳定身份对账，再决定重试、补偿或人工接管。
8. **授权变更不能旁路**：若策略涉及权限、会话、卡片或租户资格，必须调用既有 source owner、grant ledger、canonical projection 和 strict read-gate；Mobius 不建立第二套授权引擎。

## 2. 目标、范围与非目标

### 2.1 目标

本设计覆盖：

- 独立策略配置和调度模板库；
- 模板的 owner、版本、审核、发布、暂停、废弃和归档；
- 可信预警信号到应急事件的识别、关联和去重；
- Agent 推荐初级标准预案并等待操作员批准；
- 已批准计划的串行、并行、条件分支、重试和停止条件；
- 事件持续监控、控制目标评估和升级判断；
- 仅从现有策略模板中组合多项策略和调度；
- 有界自动升级或再次人工审批；
- 执行超时、未知结果、重启、重复消息和并发冲突恢复；
- 恢复、撤销、回滚、补偿、结案和审计归档；
- 多租户隔离、操作员/Agent/执行器职责分离和最小权限。

### 2.2 首版范围假设

本文件的首版工期按以下范围估算：

- 单区域部署；
- 多租户边界从第一版开始保留；
- 一个业务域或一组同一 owner 管理的资源；
- 3 至 5 个已审核策略模板；
- 1 至 2 个类型化执行适配器；
- 支持初级预案审批、持续监控和有界自动升级；
- MySQL、RabbitMQ 和多 worker lease/recovery 纳入集成验收；
- 不包含跨城双活、跨组织行政授权、任意外部供应商适配和无限制自然语言执行。

### 2.3 非目标

以下内容不属于首版，也不能通过本设计默认获得批准：

- Agent 运行时生成并发布新策略模板；
- Agent 修改已发布模板或降低模板审批等级；
- 以自然语言作为执行器输入；
- Mobius 直接写入其他业务系统数据库；
- 用告警严重级别替代审批或授权；
- 用缓存 TTL、旧快照或前端成功提示证明动作已生效；
- 用一次初级预案批准获得无限期、无限范围的自治权；
- 将 PolicyEngine、Arbiter、GlobalAdmin 或角色字符串作为 Mobius 的授权旁路；
- 在没有稳定 operation identity 和对账合同的情况下承诺 exactly-once 外部副作用。

## 3. 核心对象与职责

### 3.1 对象分层

策略模板、调度模板、事件计划和事件本身必须是不同对象：

| 对象 | 职责 | Agent 是否可创建 |
|---|---|---|
| `StrategyTemplate` | 一个经过治理的响应能力，如隔离节点、降低流量、撤销会话 | 否 |
| `ScheduleTemplate` | 定义时序、并发、重试、超时、观察和停止规则 | 否 |
| `Capability` | 由业务 owner 注册的类型化执行能力及输入/输出合同 | 否 |
| `ControlObjective` | 成功、恶化、升级和恢复的可观测条件 | 否，必须来自已发布模板 |
| `Incident` | 一次从预警到结案的应急事件聚合 | 系统创建/推进 |
| `Plan` | 绑定事件和模板 revision 的计划版本 | Agent 可生成实例，但需服务端校验 |
| `EscalationProfile` | 初次批准时授予的有界自动升级权限 | 操作员批准 |
| `Execution` | 一个计划项的实际执行、结果和对账记录 | 执行器创建 |
| `Observation` | 监控窗口中的事实、指标和控制目标结果 | 观测 worker 创建 |
| `Closure` | 结案前的 postcondition、补偿、审计和人工确认 | 系统生成，按等级可需人工确认 |

### 3.2 策略模板

`StrategyTemplateRevision` 建议至少包含：

- `template_id`、`revision`、`digest`、`status`；
- owner、维护者、审核者和适用租户/域范围；
- `capability_id` 与 capability schema version；
- 参数 JSON Schema 或等价的类型化约束；
- 前置条件、影响范围和资源选择约束；
- 预期观测、成功条件、失败条件和停止条件；
- 最大持续时间、重试上限、并发上限和资源预算；
- 回滚/补偿 capability 引用；
- 所需审批等级和是否允许纳入自动升级包；
- 敏感级别、保留期和审计要求。

模板不得保存任意 SQL、shell、脚本、可执行 URL、动态代码或隐藏授权表达式。模板只声明意图、边界和类型化 capability 引用，实际副作用由对应业务 owner 的执行适配器完成。

### 3.3 调度模板

`ScheduleTemplateRevision` 建议使用受限 DAG 或等价声明式结构：

- 步骤及依赖关系；
- 允许的串行/并行组；
- 每组最大并发；
- 单步骤 timeout、重试和退避；
- 观察窗口和条件分支；
- 停止、暂停、撤销和回滚触发条件；
- 计划级最大持续时间和总预算；
- 禁止组合和互斥策略；
- 失败后是否允许进入升级候选。

调度模板不得提供任意表达式执行能力。条件必须引用已注册的观测指标、状态谓词或模板内已发布的条件 ID。

### 3.4 事件计划

Agent 生成的不是新模板，而是绑定既有 revision 的 `PlanRevision`：

```json
{
  "incidentId": "inc_01...",
  "planId": "plan_01...",
  "planRevision": 2,
  "strategyRefs": [
    {"templateId": "reduce_traffic", "revision": 2, "digest": "sha256:..."},
    {"templateId": "isolate_node", "revision": 3, "digest": "sha256:..."}
  ],
  "scheduleRef": {
    "templateId": "serial_health_check",
    "revision": 1,
    "digest": "sha256:..."
  },
  "composition": {
    "nodes": ["reduce_traffic", "isolate_node"],
    "edges": [
      {"from": "reduce_traffic", "to": "isolate_node", "when": "control_not_recovered"}
    ]
  },
  "operationId": "op_01..."
}
```

服务端必须重新解析和校验所有引用，不能信任 Agent 返回的名称、范围、权限等级或参数。

## 4. 总体架构与 owner 边界

```text
Gateway / trusted signal ingress
        |
        v
Mobius API and Incident Correlator
        |
        +--> Strategy Registry / Template Validator
        |
        +--> Agent Adapter
        |       +--> recommend
        |       +--> compose existing refs
        |       +--> explain / observe
        |
        +--> Plan Validator + Approval Gate
        |
        +--> Incident Coordinator / Scheduler
        |       +--> Worker lease / fence
        |       +--> Execution Adapter ports
        |       +--> Observation / Reconciliation
        |
        +--> MySQL source state + durable outbox
        +--> RabbitMQ / typed consumers
        +--> Audit / Notification

Domain owner adapters
        +--> monitoring/operations actions
        +--> TrustGraph authorization source path when applicable
        +--> external systems with idempotency and reconciliation contracts
```

职责边界：

- **Gateway**：验证外部身份和可信头；Mobius 不接受客户端自带的 Agent、operator 或 tenant 身份作为事实。
- **Mobius**：拥有事件、计划、审批包、编排状态、观测关联和结案状态；不拥有其他业务域的授权事实。
- **Strategy Registry**：拥有模板 revision、digest、发布状态和组合兼容矩阵。
- **Agent Adapter**：对接模型或 Agent runtime；只能访问显式工具端口，不能直接访问数据库或执行器。
- **Plan Validator**：在提交、审批、激活和每次升级前重新校验封闭策略库、版本、范围、预算和审批包。
- **Coordinator/Scheduler**：根据已批准计划调度执行，不创造新的业务事实；每个动作结果都通过执行器合同返回。
- **Domain Owner Adapter**：实际修改业务状态。它必须提供稳定 operationId、幂等、结果查询和必要的补偿接口。
- **TrustGraph**：当动作影响授权、会话或卡片时，继续拥有 source mutation、grant ledger 和 revoke owner。
- **PolicyEngine**：仍是正式授权唯一入口。Mobius 不能以事件紧急等级绕过 `evaluate()` 和 published-evidence strict gate。
- **Monitor**：提供可信观测数据；事件控制目标和状态由 Mobius 关联，不直接把告警记录当作结案证明。

## 5. 完整生命周期

### 5.1 阶段 0：模板定义、审核和发布

1. 业务 owner 注册 capability 及输入/输出合同。
2. 维护者创建策略或调度模板草稿。
3. 服务端校验资源范围、参数 schema、回滚引用、预算和禁止组合。
4. 指定审核人和审批等级，执行职责分离。
5. 发布生成不可变 revision 和 digest。
6. 发布后 revision 只能被暂停、废弃或归档，不能原地修改。

发布后的事件实例必须固定引用当时的 revision 和 digest。模板新版本只影响新计划。

### 5.2 阶段 1：信号接入和事件创建

事件可以由监控告警、业务系统事件、人工报告或受保护的 Agent 输入触发。进入 Mobius 前必须：

- 验证来源身份和消息完整性；
- 校验 tenant/domain/resource scope；
- 使用稳定 `signalId` 去重；
- 记录原始信号摘要，不默认保存完整敏感 payload；
- 按批准的关联规则合并或新建事件；
- 生成稳定 `incidentId` 和初始 `operationId`。

事件识别只能引用已批准的关联规则，不能由 Agent 临时改变跨租户或跨资源的合并边界。

### 5.3 阶段 2：评估和初级预案推荐

Mobius 为事件建立不可变的事实快照：

- 触发信号及 digest；
- 当前 tenant/domain/资源范围；
- 影响指标和时间窗口；
- 已有执行动作和未完成动作；
- 可用模板 revision；
- 操作员权限和当前审批约束；
- 事件预算、期限和禁止动作。

Agent 使用只读工具：

- `read_incident_snapshot`；
- `list_published_strategy_revisions`；
- `get_strategy_contract`；
- `simulate_plan`；
- `get_observation_window`。

Agent 输出推荐理由、候选模板引用、计划草案、预期结果、风险和所需批准等级。输出必须被记录为 recommendation artifact，不能直接成为执行命令。

### 5.4 阶段 3：操作员批准初级标准预案

操作员批准的对象必须包括：

- `incidentId` 和当前事实快照 digest；
- `planId`、计划 revision 和 plan digest；
- 每个 strategy/schedule template 的 revision 和 digest；
- tenant/domain、目标资源和主体范围；
- 生效时间、最长持续时间和预算；
- 允许的执行器和动作等级；
- 是否允许自动升级；
- 具体 `EscalationProfile`；
- 审批人、审批理由和审批时刻。

如果事实快照、模板 digest 或目标范围在审批前发生变化，原计划必须失效并重新评估。审批结果只允许：

```text
APPROVED(plan_revision, approval_envelope)
REJECTED(reason)
EXPIRED(before_activation)
CANCELLED(by_authorized_operator)
```

同一操作员不得在没有明确 SoD 例外批准的情况下同时维护高权限模板、批准事件计划并执行对应动作。

### 5.5 阶段 4：计划验证、激活和执行

激活前由服务端做最终验证：

- 所有模板仍是 `PUBLISHED`；
- digest 和 revision 完全匹配；
- capability 仍可用且 owner 合同未撤销；
- 组合满足兼容矩阵和互斥约束；
- 目标范围仍属于事件批准范围；
- 预算、并发和期限未超限；
- 执行适配器健康并具备结果查询能力；
- 对授权动作，source owner 和正式授权链路可用。

激活时写入 durable source state 和消息 outbox。事务内只写必要的事件/计划状态、source correlation、outbox 和 audit correlation，不执行网络调用、MQ 外发或缓存操作。

执行器在事务提交后领取计划项：

- 使用 `(incidentId, planId, planRevision, planItemId, operationId)` 作为稳定身份；
- 通过 lease/CAS/fence 保证单一 active owner；
- 按调度模板执行顺序和并发预算；
- 每次重试前先对账前一次未知结果；
- 将明确成功、明确失败、未知和人工接管分开记录。

### 5.6 阶段 5：持续监控和控制目标

每个策略模板必须提供已发布的 `ControlObjective`，至少定义：

- 观测指标和数据源；
- 成功窗口和最小稳定时间；
- 恶化和升级条件；
- 最大等待时间；
- 回滚或停止条件；
- 观测数据缺失时的安全状态。

监控结果分为：

```text
CONTROLLED
DEGRADED
NOT_CONTROLLED
OBSERVATION_UNKNOWN
```

`OBSERVATION_UNKNOWN` 不能被解释为成功，也不能触发无限制的自动升级。观测 worker 需要记录数据快照、来源、时间窗口、generation 或事件版本和计算结果。

### 5.7 阶段 6：已有策略组合和自动升级

初级计划没有达到控制目标时，Agent 可以在 `EscalationProfile` 范围内组合已有策略。组合过程必须经过：

1. 读取最新事件快照和已完成动作；
2. 排除已执行、互斥、过期或暂停的模板 revision；
3. 从已发布策略库选择 strategy/schedule refs；
4. 生成新的 `PlanRevision`，而不是修改旧计划；
5. 服务端验证兼容矩阵、目标范围、预算、并发和动作等级；
6. 检查是否仍在批准的升级包内；
7. 在允许自动执行时直接进入激活，否则进入 `WAITING_OPERATOR_APPROVAL`；
8. 记录 Agent 推荐、验证结果和最终执行决定。

`EscalationProfile` 至少包含：

```text
allowed_strategy_revisions
allowed_schedule_revisions
allowed_capabilities
allowed_target_scope
max_escalation_level
max_parallelism
max_duration
max_retry_count
resource_budget
forbidden_combinations
manual_approval_required_for
stop_conditions
```

以下任一条件成立时必须重新审批：

- 引用批准包之外的模板或 capability；
- 扩大 tenant/domain/resource scope；
- 提升动作等级或进入高风险 capability；
- 超过时间、并发、重试或资源预算；
- 触发禁止组合或新的外部系统；
- 需要改变控制目标或回滚策略；
- 事件事实快照与批准时不再一致。

### 5.8 阶段 7：恢复、撤销、回滚和补偿

恢复不等同于“停止新的动作”。Mobius 必须按每个计划项核对：

- 是否已经提交到业务 owner；
- 是否执行成功；
- 是否需要撤销临时状态；
- 是否需要回滚或补偿；
- 是否仍有异步消息待处理；
- 是否存在未知的外部副作用。

涉及授权的恢复必须由 TrustGraph source owner 写入 revoke/tombstone、推进 generation/fence 并通过 canonical projector 收敛。仅修改事件状态、模板状态或缓存 TTL 不构成撤销。

涉及外部系统的恢复必须使用适配器提供的查询或补偿合同。没有查询能力且结果未知时，状态进入 `REQUIRES_MANUAL_INTERVENTION`，不得盲目重放。

### 5.9 阶段 8：结案和归档

事件只能在以下证据全部满足时进入 `CLOSED`：

- 控制目标在规定窗口内满足；
- 所有执行项已有明确终态或已转人工处理；
- 临时授权、限流、隔离和调度状态已恢复或有明确保留理由；
- 所需回滚/补偿已完成或由责任人接管；
- source、outbox、投影和外部执行结果已对账；
- 审计事件关联完整；
- 结案操作员或自动结案规则满足审批等级；
- 事件时间线和计划版本可重放。

归档只改变 Mobius 查询保留状态，不删除授权 owner 的历史账本、撤销事实或必需审计记录。

## 6. 状态机

### 6.1 Incident 状态

```text
SIGNAL_RECEIVED
  -> OPEN
  -> ASSESSING
  -> BASELINE_PLAN_PROPOSED
  -> WAITING_OPERATOR_APPROVAL
  -> EXECUTING
  -> MONITORING

MONITORING
  -> CONTROLLED
  -> ESCALATION_PROPOSED
  -> WAITING_OPERATOR_APPROVAL
  -> EXECUTING
  -> RECOVERING
  -> VERIFYING
  -> CLOSED

任意可运行状态
  -> PAUSED
  -> UNKNOWN
  -> REQUIRES_MANUAL_INTERVENTION
  -> CANCELLED
```

状态转移必须由服务端根据当前 durable state 和 CAS 条件执行，Agent 不能直接发送任意状态值。

### 6.2 Plan 状态

```text
DRAFT
  -> VALIDATED
  -> WAITING_APPROVAL
  -> APPROVED
  -> ACTIVATION_PENDING
  -> ACTIVE
  -> SUCCEEDED
  -> FAILED
  -> UNKNOWN
  -> CANCELLED
  -> SUPERSEDED
```

一个已批准计划不可被 Agent 原地修改。新的组合必须创建新 revision，并保留父计划、原因、事实快照 digest 和推荐证据。

### 6.3 Execution 状态

```text
PENDING
  -> CLAIMED
  -> RUNNING
  -> SUCCEEDED
  -> FAILED
  -> IN_DOUBT
  -> QUARANTINED
  -> COMPENSATING
  -> COMPENSATED
  -> MANUAL_RECONCILIATION
```

`IN_DOUBT` 不是超时后的自动重试许可。必须先证明外部副作用不存在，或通过精确身份查询到已完成结果，才允许重新排队或标记成功。

## 7. Agent 协议与安全边界

### 7.1 Agent 能力

Agent 仅通过显式、版本化的工具端口工作：

| 工具 | 读写 | 作用 |
|---|---|---|
| `read_incident_snapshot` | 只读 | 读取事件事实和当前计划 |
| `list_published_strategy_revisions` | 只读 | 查询可用模板及 digest |
| `get_strategy_contract` | 只读 | 读取参数、前置条件、风险和控制目标 |
| `simulate_plan` | 只读 | 计算组合的兼容性、预算和预期影响 |
| `recommend_baseline_plan` | 产生 recommendation artifact | 推荐初级预案，不改变状态 |
| `compose_escalation_plan` | 产生 plan draft | 只引用已发布模板，不执行 |
| `read_observation_window` | 只读 | 读取控制目标观测结果 |
| `request_operator_approval` | 写 proposal | 提交审批请求，不批准 |
| `read_execution_status` | 只读 | 读取执行和对账状态 |

禁止提供通用 `execute_shell`、`execute_sql`、`http_request` 或任意 capability 名称工具。

### 7.2 Agent 输出合同

每次推荐或组合都必须记录：

- `agentRunId`、provider、model/version 和工具调用序列；
- 输入事件快照 digest 和策略库快照 digest；
- 计划候选、模板 revision/digest、组合图和参数；
- 解释、风险、未满足条件和所需审批；
- parent plan、operationId 和 traceId；
- 输出 schema version。

模型原始 prompt、敏感业务 payload 和不必要的凭证不得进入普通事件时间线。AI 决策依据、关键写操作和拒绝仍须形成可关联的 audit message。

### 7.3 服务端强校验

服务端不得假设 Agent 遵守规则。每次提交、审批、激活和升级都必须重新校验：

- 模板存在、已发布、版本和 digest 匹配；
- capability 在 allowlist 内；
- 参数通过类型 schema；
- 组合图无环、无互斥冲突和越权依赖；
- 目标 tenant/domain/resource 在事件 scope 内；
- 预算、并发、TTL、重试和动作等级不超限；
- 计划未被暂停、撤销或替代；
- 当前 operator/Agent/executor identity 满足职责分离。

### 7.4 Agent 框架选型

这里必须区分两个经常被混淆的层次：

- **Agent Runtime**：负责上下文、模型调用、工具调用、输出解析和预算控制；它不拥有事件状态和业务执行权。
- **Durable Workflow/Coordinator**：负责事件状态机、计划版本、审批、lease、CAS、重试、未知结果对账和结案；它才是 Mobius 的事实 owner。

首版推荐采用 **Rust 原生受限 Agent Runtime + 供应商无关的 Model Gateway**：

| 方案 | 结论 | 原因 |
|---|---|---|
| `astral-mobius-agent` 自研 Rust runtime | **生产首选** | 与现有 Rust/Tokio/SQLx/WorkerOwned 边界一致；可把工具、预算、状态和错误定义成 typed port，避免引入第二个持久化状态机 |
| LangGraph 等通用图 Agent 框架 | 仅用于离线原型/方案演示 | 图状态和 Python/Node 运行时不应成为生产授权、审批或执行事实；若作为 sidecar，必须由 Rust 服务重新校验全部输出 |
| OpenAI Agents SDK、Anthropic Agent SDK 等供应商框架 | 仅作为模型/工具适配参考 | 不能让供应商框架持有 Mobius 状态、审批权或业务写工具；供应商切换时不应迁移业务状态 |
| MCP | 可选的受限工具传输协议 | 只允许经 Mobius proxy 暴露的 typed、allowlisted 工具；不开放通用 MCP server、任意网络访问或原始执行工具 |
| Temporal/Restate 等通用 workflow | 多域 saga 的后续评估项 | 首版已有 DB/outbox/lease/fence/WorkerOwned 合同，先不引入第二套 workflow owner；跨系统补偿复杂到现有协调器无法安全闭合时再单独评审 |

因此，生产架构不采用“通用 Agent 框架直接连接工具并自行循环”的形态。建议新增：

- `astral-mobius-agent`：模型会话、工具注册、结构化输出、预算和模型路由；
- `ModelGateway` port：统一不同供应商的请求、响应、超时、限流和审计；
- `MobiusToolRegistry`：只注册 Mobius 明确批准的 typed tools；
- `AgentRunStore`：保存运行状态和结果摘要，但不把模型上下文当作业务事实；
- `PlanValidator`：与 Agent runtime 分离，负责所有确定性安全校验。

Agent runtime 可以重启、替换或整体禁用，而不影响 `Incident`、`Plan`、`Approval`、`Execution` 和 `Closure` 的持久化语义。

### 7.5 模型角色选型

首版不应让一个模型同时承担分流、规划、批评、审批和执行。推荐按角色路由，并通过稳定的逻辑别名配置模型：

| 逻辑角色 | 推荐职责 | 工具权限 | 默认推理档位 |
|---|---|---|---|
| `mobius-router-v1` | 信号分类、事件关联候选、选择是否需要规划 | 只读事件摘要和模板索引 | low/medium |
| `mobius-planner-v1` | 推荐初级预案、组合已有策略、生成结构化 `PlanDraft` | 只读快照、模板合同、模拟和观测；不得执行 | high |
| `mobius-critic-v1` | 独立检查计划的范围、冲突、遗漏、风险和是否需要人工审批 | 只读计划、模板合同和批准包 | high |
| `mobius-summarizer-v1` | 面向操作员生成状态摘要、风险说明和时间线 | 只读已脱敏事实 | low/medium |

推荐的**起始评估组合**如下，名称仅作为当前模型市场的候选，不是已签订的供应商合同：

- `mobius-planner-v1`：以 GPT-6.1-Sol 或同等级高能力模型作为第一候选；
- `mobius-critic-v1`：以 Claude Sonnet 5.5 或同等级、不同模型家族的高能力模型作为独立交叉检查候选；
- `mobius-router-v1`：以 Claude Haiku 5.5、GLM-5.3-Flash 或同等级低延迟模型作为候选；
- `mobius-summarizer-v1`：复用 router 级模型，禁止为摘要单独获得写工具。

这里的选择不是基于模型自述的“安全”或“会推理”，而要在 P0 用固定 Rust 评测集实测：结构化输出合规率、非法工具拒绝率、租户/范围保持率、模板引用准确率、组合冲突发现率、延迟、token 成本、超时恢复和 provider 可用性。最终生产配置只保存逻辑别名到具体 provider/model/version 的映射，并支持无迁移切换和回滚。

模型不是安全边界。即使 planner 和 critic 一致，仍必须经过确定性 `PlanValidator`；critic 不能代替操作员，也不能代替 source owner 或 PolicyEngine。

### 7.6 模型限制和信任分层

模型输出应按风险等级限制，不允许“首个审批”自动扩大成无限自治：

| 风险级别 | 允许模型做什么 | 是否允许自动激活 |
|---|---|---|
| `R0` 只读分析 | 事件摘要、模板检索、候选推荐、影响解释 | 否，只有展示/提交建议 |
| `R1` 已批准的低风险组合 | 在既有 `EscalationProfile` 内组合已发布模板，生成新 `PlanRevision` | 仅在确定性校验、预算和批准包全部通过时允许 |
| `R2` 授权/会话/跨域/外部副作用 | 生成建议、模拟和审批请求 | 否，每个计划或动作按审批合同执行 |
| `R3` 破坏性、高权限或无法补偿动作 | 可提供只读分析 | 否，模型不得调用执行工具，必须人工决策和人工接管 |

`R1` 也不是模型直接获得执行权。自动激活只表示 coordinator 发现该计划满足既有批准包；真实副作用仍由业务 owner adapter 执行并返回 durable proof。

### 7.7 限制模型的八层控制

1. **网络层**：模型请求只能经 `ModelGateway` 出站；Agent runtime 不得直接访问互联网、任意 URL、数据库、消息 broker 或文件系统。provider endpoint、区域、重定向和证书必须 allowlist。
2. **身份层**：Agent run 使用独立 service identity、租户 scope 和短期 run token；绝不复用操作员 session、JWT、卡片凭证或执行器密钥。模型永远不能伪造 operator 身份。
3. **输入层**：只注入服务端生成的事件快照、已发布模板摘要、批准包和观测事实；告警文本、人工描述、外部 payload 和工具返回都按不可信数据处理，不得把其中的指令当作 system/developer instruction。
4. **工具层**：工具使用静态 registry、typed schema、参数上限和 per-run allowlist。工具只返回最小必要数据；写工具只允许 `request_operator_approval` 或生成 draft，不提供通用 shell/SQL/HTTP/文件/浏览器工具。
5. **输出层**：强制 JSON Schema、`deny_unknown_fields`、固定枚举、大小上限和 digest 引用；任何自由文本动作、未注册模板、任意 capability、动态 URL、SQL、脚本或隐藏字段都拒绝。
6. **策略层**：每次提交、审批、激活和升级重新执行确定性校验：模板状态/revision/digest、tenant/domain/resource scope、组合图、预算、并发、TTL、动作等级、SoD 和 `EscalationProfile`。模型不能修改校验规则。
7. **运行层**：每次 run 设置 wall-clock timeout、最大 model turns、最大 tool calls、最大计划节点、最大组合深度、最大输出字节、token/cost budget 和单事件并发额度。默认建议：planner 最多 3 轮/8 次工具调用，critic 最多 2 轮/4 次工具调用；超限进入 `PENDING` 或人工处理。
8. **数据与审计层**：provider 必须满足数据区域、传输加密、保留期、不得用于训练或等价隔离的合同；敏感字段先脱敏。记录 provider/model/version、prompt policy hash、输入快照 digest、输出 digest、tool call、validator 结果和审批关联；不在普通时间线保存原始 secret、完整敏感 prompt 或隐藏 chain-of-thought。

### 7.8 Prompt、工具调用和模型退化防护

- system/developer prompt 由服务端版本化并签名/哈希；事件内容不能覆盖它。
- 每次模型调用绑定 `policyVersion`、`templateCatalogDigest`、`incidentSnapshotDigest` 和 `agentRunId`。
- 模型只能引用 `templateId + revision + digest`，不能仅提交模板名称；服务端从 registry 重新加载内容。
- `tool_call` 必须带 `messageId`、`operationId`、`meta.idempotencyKey`、`audit.decisionPath` 和 policy version，遵循统一消息协议的 AI 工具调用约定。
- 工具结果只作为下一轮上下文，不改变业务状态；只有 coordinator/owner adapter 能改变状态。
- 模型版本、prompt policy 或模板目录变更时，旧的未激活 `PlanDraft` 必须重新校验；已批准计划不因模型更新而被原地改写。
- 不能把模型生成的解释当作证据。证据必须引用可追溯的 signal、observation、template revision、approval 和 execution record。
- 不采用生产级多 Agent 自由协商或递归 Agent swarm。首版使用“一个 planner + 一个独立 critic + 确定性 validator”；并行模型只用于比较，不直接增加权限。

### 7.9 模型失败、降级和回退

| 情况 | 安全处理 |
|---|---|
| provider 超时、限流、网络失败 | 保留 `AgentRun` 为 `UNKNOWN`/`FAILED`，事件不自动升级，转人工或按已有批准包等待下一次有界重试 |
| 输出不是合法 schema | 丢弃 draft，记录 validator/audit 结果，不把文本修补成命令 |
| planner 与 critic 不一致 | 不自动激活；进入 `WAITING_OPERATOR_APPROVAL` 或 `REQUIRES_MANUAL_INTERVENTION` |
| fallback 模型能力低于当前风险等级 | 禁止自动降级；只能返回待处理/人工审批 |
| provider/model/version 发生漂移 | 重新运行 validator；高风险计划必须重新生成并重新审批 |
| 模型无法读取最新事件事实 | 不使用旧快照继续组合；保持 `PENDING`/`DENY` |
| Agent runtime 重启 | 从 `AgentRunStore` 和 Mobius durable state 恢复；不重放未知工具调用 |
| 模型服务不可用但已批准计划仍在执行 | 不影响已批准 coordinator 执行；只暂停新的模型推荐和自动升级 |

模型 fallback 只能切换到在 `ModelPolicy` 中预先批准的同等级或更高等级模型。对于 `R2/R3`，没有可用模型不应阻断人工已批准的确定性执行，但绝不能用更弱模型替代人工审批。

### 7.10 Agent/模型验收门槛

模型选型不能只看通用 benchmark。P0 必须建立不含生产秘密的 Rust 固定评测集，至少覆盖：

- prompt injection、恶意告警文本和伪造 operator 指令；
- 未发布/过期/digest 不匹配模板；
- 跨租户、跨域、超范围和错误 card/resource；
- 组合环路、互斥策略、预算超限、重复动作和过期计划；
- planner/critic 冲突、provider timeout、半截 JSON 和重复 tool call；
- 观测未知、旧快照、执行结果未知和人工接管；
- 敏感字段脱敏、模型 provider 数据保留和审计关联。

通过条件不是“模型永不出错”，而是：

1. 任何非法输出都在执行前被确定性 validator 拒绝；
2. 评测中没有未批准的工具调用抵达执行器；
3. 所有自动激活计划都能从批准包和模板 digest 重建；
4. 超时/断流/模型不可用默认进入可解释的 `PENDING`、`UNKNOWN` 或人工路径；
5. planner、critic、validator 和 coordinator 的证据可关联、可回放、可对账；
6. provider 切换不改变事件、计划和审批的持久化语义。

### 7.11 模型策略配置示例

以下是逻辑配置示例，不是生产密钥或最终供应商合同。生产配置应由服务端加载、校验、审计，并在变更时生成新的 policy revision：

```toml
[model_policy.mobius-planner-v1]
risk_levels = ["R0", "R1"]
primary = "new-provider/gpt-6.1-sol"
fallback = ["openrouter/openai/gpt-6.1-sol"]
max_turns = 3
max_tool_calls = 8
max_output_bytes = 65536
max_tokens = 12000
allowed_tools = [
  "read_incident_snapshot",
  "list_published_strategy_revisions",
  "get_strategy_contract",
  "simulate_plan",
  "read_observation_window",
  "request_operator_approval",
]
auto_activation = false

[model_policy.mobius-critic-v1]
risk_levels = ["R0", "R1"]
primary = "openrouter/anthropic/claude-sonnet-5.5"
fallback = []
max_turns = 2
max_tool_calls = 4
max_output_bytes = 32768
max_tokens = 8000
allowed_tools = [
  "read_incident_snapshot",
  "get_strategy_contract",
  "simulate_plan",
  "read_observation_window",
]
auto_activation = false
```

该配置仍不能直接授予模型执行权：

- `primary`/`fallback` 只表示模型路由，不表示信任等级；provider 必须先通过数据区域、保留、加密、限流和评测准入。
- `allowed_tools` 由服务端与风险等级求交，模型返回的 tool name 不得扩大该集合。
- `auto_activation` 只能作为 coordinator 的候选开关；最终还要通过批准包、`PlanValidator`、预算和 owner adapter 门禁。
- provider、model、prompt policy、模板目录或风险映射任何一项变化都生成新 policy revision；运行中的已批准计划不被原地改写。
- provider secret 只从部署环境注入，不能写进 TOML、数据库、Agent prompt、审计 payload 或模型上下文。

### 7.12 选型决策

在当前仓库和本项目边界下，推荐的生产选型是：

1. **框架**：Rust 原生 `astral-mobius-agent`，只实现会话、结构化输出、工具注册、预算、超时、模型路由和审计 port；不实现第二套持久化 workflow。
2. **状态与执行**：由 `astral-mobius` coordinator、`astral-db` durable state、outbox、lease/fence 和业务 owner adapter 负责；不交给 LangGraph、MCP server 或供应商 Agents SDK。
3. **模型组合**：高能力 planner + 不同模型家族的 critic + 低成本 router/summarizer；planner/critic 只生成建议或 plan draft，不能写授权或执行状态。
4. **模型路由**：使用 `mobius-*-v1` 逻辑别名，provider/model/version 仅在 `mobius_model_policy` 中映射，支持灰度、回滚和逐租户启用。
5. **工具协议**：遵循统一 `tool_call`/`tool_result`/`audit` 消息结构；工具是 Mobius proxy 暴露的 typed port，不开放通用 MCP 或任意网络工具。
6. **安全判断**：模型本身不进入信任根。安全性来自 allowlist、Schema、digest、scope、预算、审批、owner adapter、durable proof 和 reconciliation 的组合。

因此，首版不推荐直接引入一个“能自主操作生产系统”的通用 Agent 框架。若未来需要外部 workflow 引擎或多 Agent 协作，必须先证明现有 coordinator 无法覆盖跨系统 saga，并单独评审新的状态 owner、恢复协议和 Exec-L3 部署边界。

## 8. 持久化模型建议

以下是建议的逻辑表名，不代表已创建迁移：

| 表 | 主要职责 | 关键约束 |
|---|---|---|
| `mobius_strategy_template` | 模板逻辑身份、owner、当前生命周期 | 模板身份稳定，revision 不原地覆盖 |
| `mobius_strategy_revision` | 不可变策略内容、schema、digest、控制目标 | `(template_id, revision)` 唯一，发布后不可变 |
| `mobius_schedule_template` | 调度模板逻辑身份 | owner、风险等级、生命周期 |
| `mobius_schedule_revision` | DAG、并发、重试、停止和预算约束 | digest、发布状态、禁止任意代码 |
| `mobius_capability_registry` | capability owner、版本、输入/输出和补偿合同 | capability 必须 allowlist 注册 |
| `mobius_incident` | 事件聚合和状态 | tenant/domain、稳定 incidentId、当前版本 CAS |
| `mobius_incident_signal` | 原始信号摘要、来源和关联 | `signalId` 去重，保留来源 digest |
| `mobius_plan` | 计划逻辑身份和事件绑定 | incident scope、parent plan、当前 revision |
| `mobius_plan_revision` | 模板引用、组合图、事实快照、plan digest | 只追加 revision，不能原地修改 |
| `mobius_escalation_profile` | 初次批准的自动升级边界 | 模板/能力/范围/预算/期限白名单 |
| `mobius_approval` | operator 审批、理由、SoD 和审批包 | 绑定精确 plan digest 和 profile digest |
| `mobius_execution` | 单计划项执行、lease、attempt、结果和对账 | operationId 幂等，UNKNOWN 不自动清除 |
| `mobius_observation` | 指标窗口、控制目标和评估结果 | 来源、时间窗、事件/计划版本绑定 |
| `mobius_reconciliation` | UNKNOWN、补偿、人工接管和结果证明 | 精确身份和 CAS，保留决策证据 |
| `mobius_closure` | 结案检查、责任人和归档信息 | 必须满足 postcondition 清单 |
| `mobius_model_policy` | Agent 角色到 provider/model/version 的路由、区域、数据策略、预算和 fallback | 逻辑别名稳定；fallback 必须同等级或更高等级 |
| `mobius_agent_run` | 一次 Agent run 的输入/输出 digest、模型版本、状态和预算消耗 | 不保存为授权事实；运行身份和 incident/plan 绑定 |
| `mobius_agent_tool_call` | 工具调用、参数摘要、结果摘要、校验结果和幂等身份 | 只允许 registry 工具；禁止保存 secrets 和完整敏感上下文 |
| `mobius_prompt_policy` | system/developer policy 版本、hash、适用风险等级和发布时间 | 变更后未激活 draft 必须重新校验 |

现有 `al_message_outbox`、审计表和授权 ledger 可以复用，但不能把 outbox ACK、通知发送成功或消息 watermark 直接当成业务执行成功。`mobius_model_policy` 不应保存 provider secret；密钥由部署环境的 secret store 注入，且模型路由变更必须有审计和回滚记录。

## 9. 消息和异步边界

建议使用独立、版本化的 Mobius 领域事件类型：

```text
MOBIUS_INCIDENT_OPENED
MOBIUS_SIGNAL_ATTACHED
MOBIUS_PLAN_RECOMMENDED
MOBIUS_PLAN_SUBMITTED
MOBIUS_PLAN_APPROVED
MOBIUS_PLAN_REJECTED
MOBIUS_PLAN_ACTIVATED
MOBIUS_EXECUTION_STARTED
MOBIUS_EXECUTION_RESULT
MOBIUS_OBSERVATION_UPDATED
MOBIUS_ESCALATION_PROPOSED
MOBIUS_RECONCILIATION_REQUIRED
MOBIUS_RECOVERY_STARTED
MOBIUS_INCIDENT_RESOLVED
MOBIUS_INCIDENT_CLOSED
```

每个消息至少关联：

- `schemaVersion`；
- `messageId`；
- `operationId`；
- `incidentId`、`planId`、`planRevision`；
- tenant/domain；
- aggregate version 或 generation；
- `traceId`；
- payload digest；
- source/target owner；
- 创建时间和状态。

消息生产必须在 source transaction 提交边界内写入 durable outbox，提交后由有 owner lease 的消费者处理。MQ ACK、通知 admission 和进程内事件都不能替代精确 durable completion proof。

通知是状态传播，不是审批、授权或执行证据。严重级别不得改变权限、审批或租户隔离合同。

## 10. 现有模块改造面

### 10.1 新增模块

| 模块 | 改造内容 | 首版是否必需 | 难度 |
|---|---|---:|---|
| `astral-mobius`（建议新增 crate） | Incident domain、模板 registry port、plan validator、approval envelope、coordinator、scheduler、reconciliation、API port 和 Agent adapter port | 是 | 极高 |
| `astral-mobius` 的 `agent`/`planner` | Provider 适配、工具 allowlist、推荐 artifact、组合器、模型失败和上下文隔离；包含 `ModelGateway`、模型路由、prompt policy 和 Agent run 审计 | 是 | 高 |
| `astral-mobius` 的 `execution` | 类型化 capability 调度、DAG、lease、预算、停止、补偿和 UNKNOWN | 是 | 极高 |

建议将 Mobius 事件和编排 owner 放在独立 crate，而不是塞进 `astral-trustgraph`。TrustGraph 只保留授权 source owner 适配，避免把事件编排、策略配置和授权账本合并成万能状态对象。

### 10.2 现有 crate 改造

| crate/组件 | 需要改造的内容 | 首版是否必需 | 难度 |
|---|---|---:|---:|
| `astral-types` | 跨 crate 稳定 ID、状态/错误/消息 DTO；只放真正共享的类型 | 是 | 中 |
| `astral-db` | 上述 `mobius_*` migration、repository、CAS、lease、outbox correlation、reconciliation 查询 | 是 | 高 |
| `astral-common` | Mobius audit event、trace/operation 关联、统一错误和观测指标 | 是 | 中高 |
| `astral-mq` | typed Mobius messages、producer/consumer、重试、quarantine 和恢复 | 是 | 高 |
| `astral-gateway` | 受保护事件/模板/审批/计划 API 路由、Gateway identity 和 tenant scope | 是 | 中高 |
| `astral-trustgraph` | 仅当策略影响授权、会话、卡片或资格时接入 source owner、grant/revoke、projection 和 strict gate | 条件必需 | 极高 |
| `policy-engine` | 首版原则上不新增授权旁路；若引入新的 grant source kind 或证据语义则需正式扩展 | 条件必需 | 极高 |
| `astral-monitor` | 信号输入 adapter、事件观测端口、控制目标数据读取和状态回传；保留 Monitor 自有告警 owner | 是 | 高 |
| `astral-identity` | 仅在 operator 生命周期、会话撤销或 Agent 身份注册需要新增 source mutation 时修改 | 条件必需 | 高 |
| `e2e-bootstrap`/runtime | 装配 coordinator、scheduler、observation、reconciliation worker，定义关闭顺序和健康状态 | 是 | 高 |
| `tests-suite` | Rust 契约、并发、故障注入、MySQL/RabbitMQ、重启和多 worker 验收 | 是 | 极高 |
| 部署/运维配置 | worker ownership、lease、积压、指标、告警、runbook、回滚和逐租户 rollout | 是 | 高 |

首版不应直接修改已有授权 source schema 来“顺便支持 Mobius”。如果需要临时授权或会话撤销，应通过现有 owner 的正式 port 和已批准 source mutation；任何新 grant source kind 都应单列设计、迁移、审计和回滚。

### 10.3 可能不在本仓库内的部分

- 具体业务系统的执行适配器；
- 外部通知渠道和接收端幂等/查询合同；
- Web 控制台、审批页面和事件大屏；
- 模型服务供应商的生产合同、限流和数据保留策略。

这些系统必须提供明确的 adapter contract，不能因为 Mobius 已有 coordinator 就视为已接入。

## 11. 工期与难度估算

### 11.1 估算口径

以下估算不是承诺，基于：

- 2 名熟悉 Rust、SQLx、Tokio 和现有授权链的后端工程师；
- 1 名基础设施/测试工程师按 0.5 至 1 人投入；
- 产品/安全评审可在每个阶段及时完成；
- 单区域、一个业务域、3 至 5 个策略模板、1 至 2 个执行适配器；
- 真实 MySQL、RabbitMQ 和多 worker 验收可用；
- 至少两个候选模型 provider 可用于固定评测、故障注入和数据治理核查；
- provider 的区域、保留、训练隔离、限流、成本和 secret 注入合同可由部署侧提供；
- 不把已经存在的邻接代码当作 Mobius 完成度；
- 工期包含 Rust 测试、故障恢复、模型固定评测、provider fallback 和文档，不包含等待外部业务系统提供适配器的时间。

人日是有效工程投入，不等同于日历天。各阶段有依赖，不能简单把所有阶段完全并行。

### 11.2 分阶段估算

| 阶段 | 主要交付 | 人日 | 日历时间 | 难度 |
|---|---|---:|---:|---|
| P0 领域和安全合同 | 场景清单、状态机、模板/能力/审批/升级合同、威胁评审、验收矩阵；模型固定评测集、数据分类、provider 准入和 fallback policy | 30-45 | 3-4 周 | 高 |
| P1 策略库与事件底座 | template/schedule revision、digest、capability registry、incident/signal、只读查询；Agent run、model policy、prompt policy 和脱敏 port | 35-55 | 4-5 周 | 高 |
| P2 初级预案闭环 | Agent 推荐 artifact、ModelGateway、结构化工具调用、operator approval、plan validator、单一执行适配器、审计 | 50-80 | 5-7 周 | 高 |
| P3 持续监控与结案 | control objective、observation worker、事件状态推进、恢复/撤销、closure proof | 30-45 | 3-4 周 | 高 |
| P4 有界组合与自动升级 | Plan revision、DAG/调度、EscalationProfile、兼容矩阵、预算和重新审批 | 60-95 | 6-9 周 | 极高 |
| P5 消息恢复与运行验收 | outbox、lease/fence、UNKNOWN 对账、quarantine、重启、积压、provider 故障注入和真实依赖集成 | 50-85 | 5-9 周 | 极高 |
| **首版合计** | **单区域、单业务域、有限策略库、1-2 个适配器和受限 Agent/模型闭环** | **255-405** | **约 7-10 个月** | **极高** |

日历估算包括设计评审、跨模块等待、修复回归和集成环境准备。若只有 1 名工程师，首版应按约 11-18 个月估算，不建议采用该组织方式。

### 11.3 扩展到多域/跨系统

在首版之外，每增加一个复杂外部业务域，预计增加：

- 简单只读/单写适配器：10-20 人日；
- 有异步执行、查询和补偿的适配器：25-50 人日；
- 跨系统事务、部分成功和人工恢复：50-100+ 人日。

实现多域编排、跨区域故障域、多个外部通知渠道和完整 saga/补偿后，整体估算为 **350-600+ 人日、约 9-15 个月日历时间**，难度为平台级。此区间取决于外部系统是否提供稳定 operationId、状态查询、幂等和补偿合同，不能只按 Rust 代码量估算。

### 11.4 难度分解

| 难点 | 评级 | 原因 |
|---|---|---|
| 不可变模板与封闭策略库 | 高 | 版本、digest、owner、发布和兼容矩阵必须长期治理 |
| Agent 只组合不创造 | 高 | 模型输出不可信，所有边界必须由服务端二次校验 |
| 初次批准与自动升级边界 | 极高 | 需要把一次操作员批准明确转换为有界升级授权包 |
| 计划调度与并发 | 极高 | DAG、lease、CAS、预算、前驱顺序和取消/重试互相影响 |
| 外部执行结果未知 | 极高 | 超时后可能已产生副作用，不能用普通重试解决 |
| 持续观测与结案 | 高 | 告警、指标、控制目标和业务 postcondition 不是同一事实 |
| 授权 source 集成 | 极高 | 必须保持 source owner、grant ledger、generation/fence 和 strict gate |
| 多 worker 恢复 | 极高 | 需要 ownership、fence、重启对账、quarantine 和人工接管 |
| 真实集成验收 | 极高 | 单元测试不能证明 MySQL/RabbitMQ/外部系统的 durable 行为 |

## 12. 验收和质量门

### 12.1 Rust 单元和契约测试

必须使用 Rust/Cargo，至少覆盖：

- 模板 revision 不可变、digest 和发布/暂停/废弃；
- Agent 只能引用已发布 revision，未知 capability、脚本、SQL 和 URL 被拒绝；
- 组合图环路、互斥、范围、预算和并发上限校验；
- 事实快照变化导致旧批准失效；
- operator 批准精确 plan digest，Agent 无法自批准；
- escalation profile 内外的自动执行差异；
- 多次推荐、重复提交和稳定 operationId；
- 并发 approve/reject/cancel/revoke 的 CAS 和幂等；
- observation unknown 不误判为 controlled；
- 计划项超时、UNKNOWN、重试、quarantine 和人工接管；
- 已批准计划不可被新 Agent 输出原地覆盖；
- 结案前缺 postcondition、审计或补偿证据时拒绝关闭。

### 12.2 集成和故障验收

真实或受保护隔离环境必须覆盖：

- MySQL migration preflight、回滚和 postcondition；
- RabbitMQ outbox、redelivery、顺序、DLQ/quarantine 和重启；
- 多 worker lease 竞争、lease 丢失和 token fence；
- Agent provider 超时、重复返回、返回非法模板和模型不可用；
- 执行器明确失败、外部已完成但响应丢失、查询不可用三种结果；
- 事件在执行中暂停、取消、升级和恢复；
- 模板在事件运行中被暂停或新版本发布；
- 跨 tenant/domain 目标混入、资源 owner 变化和身份失效；
- 授权动作的 source mutation、projection 延迟、generation/fence 和 strict read-gate；
- 进程崩溃、worker 重启、积压恢复和人工 reconciliation；
- 结案后查询、审计回放和保留策略。

### 12.3 五链审查

| 链 | Mobius 必查项 |
|---|---|
| 调用链 | Agent -> validator -> approval -> coordinator -> adapter -> observation 的返回值、异常和异步边界 |
| 逻辑链 | 模板封闭世界、租户/资源范围、审批/执行 SoD、升级包和唯一授权入口 |
| 事故链 | DB/MQ/Agent/adapter/worker 不可用、超时、并发、重启和未知结果默认行为 |
| 数据链 | template digest、plan revision、operation/message ID、source/outbox、execution、observation、closure 的关联 |
| 审计链 | 推荐、组合、审批、激活、执行、重试、拒绝、升级、撤销、补偿、人工接管和结案 |

## 13. 运行、部署与回滚要求

- 默认关闭 Mobius 自动执行；先以只读推荐和人工审批模式逐租户启用。
- 每个 coordinator、scheduler、observation 和 reconciliation worker 必须有稳定 owner、lease、generation/token fence 和有界关闭流程。
- readiness 与 liveness 分开；worker 存活不代表可以接管或安全执行。
- 迁移、默认启用、策略发布和外部适配器上线必须有 allowlist、preflight、postcondition 和回滚步骤。
- 模板发布、升级包启用和执行器 capability 注册均需可审计，禁止在生产直接修改 JSON 后绕过 revision。
- 指标至少包括事件积压、计划等待批准时长、执行延迟、UNKNOWN、quarantine、重试、控制目标失败、自动升级次数、人工接管和结案耗时。
- 通知失败不应阻断 source mutation 或执行状态持久化，但通知状态必须可恢复、可观测和可对账。
- 未知外部结果不得以进程重启或定时器自动清除；必须由精确 operation identity 的 reconciliation 处理。

## 14. 待决策事项

在进入 P0 之前必须由产品、安全和业务 owner 明确：

1. 首版具体应急场景和明确排除范围。
2. 初级预案批准是否同时批准 `EscalationProfile`，以及哪些动作必须二次审批。
3. 模板 owner、审核人、发布人、operator 和执行器的职责分离规则。
4. capability registry 的 owner、版本淘汰、兼容矩阵和回滚合同。
5. 事件关联规则、跨信号合并窗口和跨租户禁止边界。
6. 控制目标的来源、观测窗口、时钟和数据缺失语义。
7. 外部执行器的 operationId、幂等、查询、补偿和人工接管接口。
8. 需要接入授权 source 的策略清单，以及是否需要新的 grant source kind。
9. 高风险动作、跨域动作和扩大 scope 的审批等级。
10. 事件和审计数据保留、脱敏、加密和访问范围。
11. 首版接受的最大自动化范围、RTO/RPO、SLO 和积压预算。
12. 真实 MySQL、RabbitMQ、多 worker 和外部业务系统的验收环境。

未完成上述决策前，不能把本文件中的状态名、表名、消息名、工期或自动升级语义当作最终产品合同。

## 15. 当前状态与最终判断

当前仓库已具备部分可复用基础：普通 `RULE` 审批及 `APPROVAL` grant 接线、授权 ledger/delta、canonical projector、strict read-gate、durable message outbox、审计和局部告警能力。仓库没有 Mobius 专属事件、模板 revision、Agent 工具合同、计划组合验证、事件 coordinator、自动升级包、执行适配器、结案核验或专项验收证据。

因此，按本设计实现的首版属于：

- **改造类型**：大型跨 crate、跨 worker、跨数据和异步边界的控制面改造；
- **首版难度**：极高，平台级；
- **合理工期**：单区域、单业务域、1-2 个执行适配器和受限 Agent/模型闭环约 7-10 个月日历时间，约 255-405 人日；
- **多域完整形态**：约 10-16 个月或更长，约 380-650+ 人日，主要受外部适配器、模型数据治理和真实恢复验收影响；
- **最重要的前置决策**：初次批准是否包含有界自动升级授权包，以及所有可执行 capability 的 owner、幂等和补偿合同。

本文件不宣称 Mobius 已批准、已实现、已迁移、已部署或已通过真实依赖验收。
