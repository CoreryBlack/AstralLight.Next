# Rust Arbiter 与 GlobalAdmin 治理链 V1.0

> 文档版本：V1.0
>
> 基线日期：2026-08-22
>
> 文档性质：Rust 当前实现与治理边界说明。本文档只记录架构、约束、缺口和目标变更，不改变任何运行时代码、API 契约或数据库结构。

## 1. 范围与结论

本文档覆盖两条容易被混淆、但职责不同的治理链：

1. **Arbiter（执剑人）链**：位于授权一致性治理面，用于发现并解析已经可证明的快照/实时决策冲突；其纯函数对调用方提交的同版本 evidence 执行确定性多数解析。它不是正常 `PolicyEngine` 授权链中的投票阶段，也不是普通请求的授权入口，不能单独授予普通请求权限。
2. **GlobalAdmin/SuperAdmin 链**：位于平台管理员生命周期和特权卡发放面。GlobalAdmin 是平台级管理员资格记录；SuperAdmin 是绑定到该资格的专用 `user_card` 及其 `__SUPERADMIN__` BASE RuleSet 授权载体。

当前基线的核心结论如下：

- Arbiter 的纯函数规则已经表达了 READY、generation/fence、DENY、多数、平局和 DEFER 语义，但其中的“多数”仅针对调用方提供的同版本 evidence vector 做计数，不等同于已认证节点 quorum；控制面目前接受调用方提交的上下文和证据，证据真实性尚未建立。
- 因此，Arbiter 返回的 `ALLOW` 只能作为一致性治理结果、审计和观测结果，**不得进入正常 `PolicyEngine.evaluate()` 的 ALLOW 链路，也不得替代正常 PolicyEngine 决策**。
- 只有在具备签名节点身份、请求上下文绑定、nonce/replay protection 和明确 quorum 成员/阈值后，才可以评估是否允许 Arbiter 结果参与受控的授权决策；在此之前，Arbiter 只能作为 `PolicyEngine` 之外的冲突检测器和控制面 resolver，用于一致性治理、审计和观测。
- GlobalAdmin/SuperAdmin 的正常权限来源已经收敛到双卡上下文、`__SUPERADMIN__` 模板、BASE RuleSet、投影门禁和 `PolicyEngine` 评估；禁止用 `isSuperAdmin()`、角色字符串或通配权限直接放行。
- GlobalAdmin 的发放/启用/禁用已经覆盖卡片投影、资格投影、会话撤销和最后活跃管理员保护，但 GlobalAdmin 生命周期 API 的 ACTIVE 管理员范围守卫和操作级审计仍未完全统一。
- audit-quarantine replay 是当前已存在的特权运维路径：仅 ACTIVE GlobalAdmin 可申请重放，申请有 durable 操作审计，worker 通过 allowlist、租约、代次和 CAS 确认完成；它不是授权决策路径，也不应被 Arbiter 结果绕过。

## 2. 术语和职责边界

| 术语 | 当前含义 | 不应解释为 |
| --- | --- | --- |
| `PolicyEngine` | 正常权限决策唯一入口，按 AUTHN、卡片上下文、投影门禁、RuleSet、`permission_rule`、L2.5 委托和 DEFAULT_DENY 评估 | 可被 Arbiter、GlobalAdmin 状态或角色字符串旁路的函数 |
| Arbiter / 执剑人 | 对跨节点/快照与实时证据做确定性冲突解析的治理组件；同版本输入证据可按多数解析 | 正常 `PolicyEngine` 授权链中的投票阶段、节点身份认证器、正常请求 PDP 或普通请求授权器 |
| `ProjectionGate` | `source_generation`、`projected_generation`、`revoke_fence` 与 READY 状态组成的读侧证据门禁 | 证明提交者身份或证明 HTTP 请求未被重放的凭据 |
| GlobalAdmin | `identity_global_admin` 中的 ACTIVE/DISABLED 平台管理员资格记录 | 直接等价于全量权限或 `['*']` |
| SuperAdmin card | `user_card.card_type = SUPER_ADMIN` 的授权卡，绑定 `__SUPERADMIN__` BASE RuleSet | 可被 `card_type` 检测后直接放行的角色标记 |
| audit quarantine replay | 对隔离审计消息执行受控查看、申请、租约领取、校验、原始重发和确认的运维路径 | 普通业务消息重放、权限放行或 Arbiter 的证据收集机制 |

规范要求权限判定统一经 `PolicyEngine.evaluate()`，规则模式由 `permission_rule`、RuleSet 和 BASE/OVERLAY 绑定驱动；这些边界见 [AGENTS.md 关键不变式](../../../AGENTS.md#L143-L164) 和 [BACKEND_STANDARD.md 权限模型与评估链](../../规范/Rust后端编码规范_V1.0.md#L141-L173)。

## 3. Arbiter（执剑人）当前实现

### 3.1 定位：PolicyEngine 冲突检测器与控制面 resolver，不是正常授权器

`policy-engine` crate 将 Arbiter 实现为无 I/O 的冲突仲裁纯函数。它只在投影门禁可证明且快照决策与实时重评估的 `allowed` 值不一致时收到冲突信号；投影未 READY、版本仍在追赶或决策本身一致时，不应把正常收敛窗口误报为冲突。纯函数的 R3 分支在同版本分歧时确实按传入 evidence 数量做多数解析，但该计数没有节点身份、请求绑定或 quorum 证明。[`policy-engine/src/arbiter.rs` 模块定位](../../../policy-engine/src/arbiter.rs#L1-L15)；[`DecisionEvidence` 输入模型](../../../policy-engine/src/arbiter.rs#L24-L33)；[`arbitrate()` 多数与版本规则](../../../policy-engine/src/arbiter.rs#L160-L229)

一致性巡检当前按约 1% 采样，先确认基线 gate READY，再执行实时评估，并在评估期间复读 gate；generation、projected generation 或 revoke fence 变化时跳过该样本。只有 `allowed` 真正分歧时才产生 `ConsistencyViolation`。[`policy-engine/src/consistency.rs` 一致性检查](../../../policy-engine/src/consistency.rs#L66-L153)

`PolicyEngine.evaluate()` 在完成正常决策后，将满足 gate 条件的分歧交给 `detect_conflict()`，再通过全局 sink 发出信号；当前阶段 A 只发信号，阶段 B 由 TrustGraph 服务负责统计和执行控制面仲裁。[`policy-engine/src/engine.rs` 哨兵挂接](../../../policy-engine/src/engine.rs#L606-L617)

因此当前调用链是：

```text
PolicyEngine.evaluate()
  -> SnapshotConsistencyChecker（采样、复读 gate、实时重评估）
  -> detect_conflict（仅 READY 且 allowed 分歧）
  -> ConflictSignal sink
  -> TrustGraph ArbiterService 统计/控制面仲裁
```

该链路中的冲突信号不会改变原始 `PolicyEngine.evaluate()` 返回值。正常请求仍由 PolicyEngine 自己完成 ALLOW/DENY/PENDING 处理。

### 3.2 证据模型与 READY 含义

当前 `DecisionEvidence` 最小包含：

- `node_id`：证据声明来自哪个节点；
- `decision`：该节点声称的 `PolicyDecision`；
- `gate`：可选的 `ProjectionGate`；缺失表示无法证明决策基于哪个投影版本；
- `observed_at_ms`：观测时间，仅用于审计排序，不参与裁决。[`DecisionEvidence` 定义](../../../policy-engine/src/arbiter.rs#L24-L33)

`ProjectionGate` 的设计语义是 head READY 且 `source_generation == projected_generation`，并携带 `revoke_fence`；投影链路规定 source generation 每次 source mutation 递增，REVOKE 同时推进 fence，读侧只能在 source 与 projected 对齐时读取。[`ProjectionGate` 与投影门禁](../../../policy-engine/src/engine.rs#L88-L112)；[`projection_repository.rs` 版本语义](../../../astral-trustgraph/src/repository/projection_repository.rs#L18-L23)

需要特别区分两个事实：

1. 在正常 PolicyEngine 读路径中，gate 来自 repository 对 `authorization_projection_head` 的读取，并在 ALLOW 前复检，读取失败或未 READY 会进入 `AUTHORIZATION_PENDING`/拒绝语义。[`PolicyEngine` 投影门禁与 ALLOW 前复检](../../../policy-engine/src/engine.rs#L298-L355)；[`PolicyEngine` 投影复检](../../../policy-engine/src/engine.rs#L359-L408)
2. 在当前 Arbiter HTTP 端点中，`ready`、generation、fence、`node_id`、`allowed` 和 `reason` 都由请求体转成 `DecisionEvidence`；纯函数只检查 `gate.ready`，不会重新查询节点、数据库或签名。[`arbiter.rs` 请求输入与证据组装](../../../astral-trustgraph/src/api/arbiter.rs#L24-L51)；[`arbiter.rs` 请求到 DecisionEvidence 的转换](../../../astral-trustgraph/src/api/arbiter.rs#L76-L115)

所以，当前 Arbiter 的 READY 是**证据对象中的声明**，不是当前控制面已经验证过的节点事实。它可用于测试确定性规则和观测投影一致性，但不能独立成为授权信任根。

### 3.3 当前裁决规则

版本序使用 `(source_generation, revoke_fence)` 的字典序。当前实现的规则是：

| 规则 | 当前行为 | reason code |
| --- | --- | --- |
| 证据为空 | 无法裁决，返回 `DEFER` | `EVIDENCE_MISSING` |
| 没有任何 READY 证据 | 无法证明，返回 `DEFER` | `R4_UNPROVABLE` |
| 最新 READY DENY 版本严格新于最新 READY ALLOW | 新 fence/generation 的拒绝覆盖旧允许，返回 `DENY` | `R1_FENCE_DENY` |
| 最新 DENY 与最新 ALLOW 版本相同 | 同版本分歧按传入 READY evidence 数量决定；ALLOW 严格过半才 `ALLOW` | `R3_MAJORITY_ALLOW` |
| 同版本分歧平局或 ALLOW 不过半 | fail-closed，返回 `DENY` | `R3_VERSION_AGREED_DIVERGED` |
| 没有 READY DENY，但存在 gate 缺失或未 READY 的 ALLOW | 无法排除旧授权复活，返回 `DEFER` | `R2_STALE_ALLOW_UNPROVABLE` |
| 最新可证明版本全为 ALLOW，较旧 READY ALLOW 仍在合法收敛窗口 | 返回 `ALLOW` | `R2_NEWEST_ALLOW` |

实现和对应测试见 [`arbitrate()` 及 R1/R2/R3/R4](../../../policy-engine/src/arbiter.rs#L160-L229) 与 [`S12/S13` 场景测试](../../../policy-engine/src/arbiter.rs#L405-L441)。

这里的“多数”是纯函数对调用方提交的同版本 evidence vector 做的算法计数，不是已认证节点 quorum，也不是正常 `PolicyEngine` 授权链中的投票阶段。重复 `node_id`、未知节点或缺少请求绑定时，当前实现仍可能把输入计入多数；因此该结果不能授予普通请求权限。

这里的 `DEFER` 与既有 `AUTHORIZATION_PENDING` 同语义，不是向业务暴露的第三种放行结果；服务注释也明确要求调用方对 `DEFER` fail-closed。[`ArbiterService` DEFER 约束](../../../astral-trustgraph/src/service/arbiter.rs#L1-L10)

### 3.4 TrustGraph service、API 和启动 wiring

TrustGraph 的 `ArbiterService` 当前职责是：

- 注册 `policy_engine::set_conflict_signal_sink`，把 READY 快照/实时分歧计入信号统计；
- 接收一组跨节点证据并调用纯函数 `policy_engine::arbitrate`；
- 累加仲裁和结果统计；
- 通过公共权限审计入口记录裁决结果；
- 对 `DEFER` 记录告警，但把 fail-closed 责任留给调用方。[`ArbiterService` 实现](../../../astral-trustgraph/src/service/arbiter.rs#L54-L124)

TrustGraph 暴露两个控制面端点：

- `POST /arbiter/arbitrate`：输入 `context` 和 `evidence`，返回 `verdict`、`reason_code`、`reason`；
- `GET /arbiter/stats`：返回 signal、arbitration、ALLOW、DENY、DEFER 计数。[`arbiter_routes()`](../../../astral-trustgraph/src/api/arbiter.rs#L62-L135)

端点当前位于 `/main/api/v1` 子路由，外层挂 Gateway 签名，路由组挂 `permission_check`；`/arbiter` 资源映射为 `monitor`。这只证明请求经过 Gateway/路由权限链，不等价于请求体中的每一份跨节点证据已经由证据来源签名。[`TRUSTGRAPH_PATH_RESOURCE_MAP` 与权限中间件](../../../astral-trustgraph/src/api/permission_check.rs#L25-L60)；[`permission_check_middleware` PolicyEngine 调用](../../../astral-trustgraph/src/api/permission_check.rs#L119-L189)；[`main.rs` 路由合并与 middleware](../../../astral-trustgraph/src/main.rs#L322-L366)

启动时 TrustGraph 创建共享 `ArbiterService`，放入 `AppState`，然后注册唯一冲突信号 sink；当前注释明确仲裁由 `POST /arbiter/arbitrate` 触发。[`AppState` Arbiter 字段](../../../astral-trustgraph/src/lib.rs#L47-L97)；[`main.rs` 创建、注入和注册 sink](../../../astral-trustgraph/src/main.rs#L210-L263)

### 3.5 证据真实性缺口

当前控制面存在以下真实性缺口：

- `ArbitrateRequest.context` 直接取请求体，handler 没有使用 Gateway 头部重建并复验物理双卡上下文；
- `node_id` 是调用方字符串，未绑定到已注册节点公钥或 mTLS 身份；
- `allowed`、`reason`、gate 版本和 `observed_at_ms` 由调用方提交，未验证来自对应节点的签名；
- 请求没有把 `user_id/card_id/resource/action/target_id/tenant_id/domain_id` 与每个节点证据做不可变绑定；
- 没有 nonce、请求序列号、过期时间或已消费记录来阻止旧证据重放；
- 没有节点成员清单、唯一节点计数、quorum 阈值或重复节点拒绝；当前“多数”只是传入 vector 内的计数；
- `arbitrate()` 的 `ctx` 当前仅被读取后丢弃，纯函数不会验证 evidence 与 context 的一致性。[`arbitrate()` ctx 未参与证据真实性验证](../../../policy-engine/src/arbiter.rs#L160-L189)

既有双卡上下文本身在普通 Gateway/TrustGraph 路径有更强的校验边界：Gateway session grant 会绑定 platform user 的 identity card、user card、tenant 和 domain，TrustGraph 普通权限中间件也可从 Gateway 头部构建物理 `PolicyContext`。[`Gateway` session grant 上下文匹配](../../../astral-gateway/src/middleware.rs#L197-L261)；[`physical_policy_context()`](../../../astral-common/src/middleware/permission_check_shared.rs#L103-L165)

但这套普通请求校验并不会自动验证 Arbiter 请求体中的跨节点证据。因此，当前实现必须按以下边界解释：

> **Arbiter 的当前 `ALLOW` 是“纯函数根据调用方提交证据（同版本时可按其数量形成多数）得出的控制面结果”，不是已认证、已绑定、已达 quorum 的授权事实。**

## 4. 非规范性架构边界

### 4.1 当前架构边界

1. 正常权限唯一入口是 `PolicyEngine.evaluate()`；Arbiter 不得在其前面做特判，也不得在其后把 `ALLOW` 改写成业务放行。
2. 投影未 READY、generation/projected 不一致、fence 读取失败、证据缺失或证据无法认证时，默认出口必须是 DENY 或 `AUTHORIZATION_PENDING`/`DEFER` 的 fail-closed 语义。
3. 规则集评估顺序保持 `OVERLAY DENY -> OVERLAY ALLOW -> BASE DENY -> BASE ALLOW -> permission_rule -> L2.5 delegation -> DEFAULT_DENY`，不可因 Arbiter 增加新的特权层。[`PolicyEngine` L1/L2/L2.5/L3 执行顺序](../../../policy-engine/src/engine.rs#L360-L603)
4. Arbiter 的审计必须保留 context、裁决结果、reason code、证据摘要和关联请求标识；审计失败不能转换为 ALLOW。
5. Arbiter 控制面必须继续受 Gateway 签名和 TrustGraph 路由权限保护，但这两个保护不能被写成“证据已认证”的替代品。

当前实现的 L2 错误路径仍会在 `load_permission_rules()` 失败后记录 repository error、返回“无匹配”，并继续尝试 L2.5；如果委托规则命中 ALLOW，结果仍可能被返回为 ALLOW。[`evaluate_permission_rules()` L2 错误处理](../../../policy-engine/src/engine.rs#L1443-L1473)；[`evaluate()` L2 到 L2.5 流程](../../../policy-engine/src/engine.rs#L412-L575)

**目标 P0（尚未实现）**：L2 `permission_rule` 读取错误必须在进入 L2.5 前走 fail-closed 的拒绝/PENDING 终止路径，不能由委托命中覆盖 L2 故障。当前源码尚未实现该目标。

这些要求与 Rust crate 边界一致：`policy-engine` 不直接依赖 MySQL、Redis、RabbitMQ，TrustGraph 负责治理编排和控制面。[Rust 后端规范的 crate 边界](../../规范/Rust后端编码规范_V1.0.md#L19-L62)

### 4.2 目标变更：证据认证完成前保持在 PolicyEngine ALLOW 之外

在以下条件全部满足前，不允许把 Arbiter 结果接入正常授权 ALLOW：

1. **签名节点身份**：节点有可轮换的公钥身份，`node_id` 与已注册公钥和节点状态绑定；节点签名覆盖 decision、gate、观测时间、上下文摘要和请求 nonce。
2. **请求绑定**：Arbiter 请求必须由受信任的 Gateway/TrustGraph 生成或签名，绑定经过验证的 user/card/identity-card、tenant、domain、resource、action、target 和当前投影 head 摘要；不得信任调用方自由提交的 context。
3. **nonce 与 replay protection**：每次仲裁请求有唯一 nonce/operation id、有效期和 durable/分布式消费记录；相同 nonce、node、context digest 的重复提交必须幂等或拒绝，旧版本证据不得替代新版本。
4. **quorum**：服务端根据已注册、未撤销且满足版本条件的节点集合计算唯一节点数和 quorum；不能把 vector 中的重复 `node_id` 当作多数，不能由请求方声明 quorum。
5. **证据一致性校验**：服务端重新验证 `(source_generation, revoke_fence)`、READY 条件、上下文摘要和签名时间窗；证据缺失、签名错误、版本冲突无法解释时只能 DENY/DEFER。
6. **授权接入审查**：即使上述机制完成，也必须单独定义 Arbiter 作为 PolicyEngine 的何种受控输入，保留原始 PolicyEngine 评估、审计和 fail-closed fallback；不能直接让 Arbiter endpoint 的 `ALLOW` 充当通用权限结果。

在目标变更完成前，Arbiter 的 `ALLOW` 只允许用于冲突统计、测试断言、审计和运维分析。任何业务 handler 或权限 middleware 都必须继续使用自己的物理 `PolicyContext` 和 `PolicyEngine.evaluate()`。

## 5. GlobalAdmin/SuperAdmin 当前治理链

### 5.1 双卡语义

- `identity_card` 证明用户身份，是认证上下文；
- `user_card` 承载用户所属的授权、tenant/domain 和投影状态；
- PlatformUser 的 PolicyContext 必须同时携带 identity card 与 user card scope；AppUser 是 identity-only，不能送入需要 `user_card` 的平台 PolicyEngine 路径。[`physical_policy_context()` 双卡边界](../../../astral-common/src/middleware/permission_check_shared.rs#L103-L165)

所以 GlobalAdmin 发放不是“给用户加一个角色字符串”，而是完成以下聚合：

```text
identity_global_admin（ACTIVE 资格）
  -> user_card（SUPER_ADMIN、ACTIVE、template_id、tenant_id、domain_id）
  -> card_rule_set_ref（SUPER_ADMIN card -> __SUPERADMIN__ BASE RuleSet）
  -> authorization_projection_head/outbox
  -> projection worker -> snapshot/cache/MQ refresh
  -> PolicyEngine.evaluate()
```

### 5.2 启动期 SuperAdmin 模板和 RuleSet

TrustGraph 启动先校验 `user_card_template` 所需 schema 列，查找或创建 ACTIVE 的 `__SUPERADMIN__` 模板；创建时从 ACTIVE platform domain 和 ACTIVE tenant/domain 关系取得物理 scope。随后遍历 `ResourceRegistry` 的资源和动作，将缺失动作补到 `permission_rule_template`。[`init_superadmin_template()` 模板初始化](../../../astral-trustgraph/src/main.rs#L484-L621)

初始化第二阶段以 `create_rule_set_from_template(template_id, "__SUPERADMIN__")` 幂等创建/重同步 TEMPLATE RuleSet，把模板 ALLOW 投影为 `rule_set_entry` 和 `rule_set_snapshot`，新版本使用递增的 snapshot version，避免版本回退。[`main.rs` 启动时创建 SuperAdmin BASE RuleSet](../../../astral-trustgraph/src/main.rs#L623-L641)；[`create_rule_set_from_template()` 投影语义](../../../astral-trustgraph/src/repository/rule_set_repository.rs#L157-L167)；[`rule_set_repository.rs` 模板到 entry/snapshot](../../../astral-trustgraph/src/repository/rule_set_repository.rs#L656-L749)

当前启动失败会拒绝 TrustGraph 启动，避免出现模板、RuleSet 或动作集合未就绪却继续提供治理 API 的半初始化状态。[`main.rs` 超管初始化失败处理](../../../astral-trustgraph/src/main.rs#L139-L151)

### 5.3 Grant/enable 的事务和 PolicyEngine 路径

`POST /global-admins/grant` 和 `POST /global-admins/enable` 先解析 ACTIVE `__SUPERADMIN__` 模板及其 TEMPLATE RuleSet，再进入 repository 的单事务聚合。事务内：

1. 锁定并确认模板的 domain/tenant scope；
2. 确认目标 TEMPLATE RuleSet 启用；
3. 插入或更新 `identity_global_admin` 为 ACTIVE，并保存 `granted_by`/reason；
4. 插入或恢复目标用户的专用 `SUPER_ADMIN` user card；
5. 确保该卡以 `BASE` 绑定 `__SUPERADMIN__` RuleSet；
6. 检查当前 CARD projection head；未 READY 或 card/binding 发生变化时，同事务追加 CARD projection 事件和 ELIGIBILITY 事件；
7. 提交后返回 `projection_ready`，未 READY 时返回 `PENDING` 而不是伪装为完成。[`GlobalAdminRepository` 发放结果和接口契约](../../../astral-trustgraph/src/repository/global_admin_repository.rs#L57-L104)；[`grant_with_superadmin_privilege()` 单事务聚合](../../../astral-trustgraph/src/repository/global_admin_repository.rs#L189-L377)

API 随后发布目标用户会话撤销命令；MQ 未初始化或发布失败时写补偿并返回 `PENDING`，不把撤销失败报告为 READY。[`global_admin.rs` grant/enable 会话撤销与 provisioning 状态](../../../astral-trustgraph/src/api/global_admin.rs#L153-L223)；[`side_effects.rs` 会话撤销 pending/补偿](../../../astral-trustgraph/src/api/side_effects.rs#L92-L145)

最终正常访问仍需经过：

```text
Gateway 验证 JWT/session grant 和双卡头
  -> TrustGraph permission_check 构建物理 PolicyContext
  -> PolicyEngine AUTHN/CARD_CONTEXT/PROJECTION
  -> L1 RuleSet（OVERLAY > BASE）
  -> L2 permission_rule（仅允许的 CARD_ONLY 回退）
  -> L2.5 delegation（委托降级评估）
  -> L3 DEFAULT_DENY
```

PolicyEngine 明确把 AUTHN、卡片上下文、RuleSet、`permission_rule`、L2.5 委托和 DEFAULT_DENY 作为统一评估链；卡片无效、投影不可用或未 READY 时拒绝。[`PolicyEngine.evaluate()` 主入口与早期拒绝](../../../policy-engine/src/engine.rs#L182-L350)；[`PolicyEngine.evaluate()` L2/L2.5/L3](../../../policy-engine/src/engine.rs#L412-L603)

### 5.4 Disable、最后活跃管理员保护和撤销

`POST /global-admins/disable` 的 repository 事务会先锁定全部 ACTIVE GlobalAdmin 行。若目标是最后一位 ACTIVE 管理员，返回 `LastAdminProtected`；否则锁定该用户的 ACTIVE SUPER_ADMIN 卡、将管理员行置为 DISABLED、将卡置为 DISABLED，并在同一事务追加 CARD `REVOKE` 和 ELIGIBILITY projection 事件。[`disable_protected()` 并发保护和撤销投影](../../../astral-trustgraph/src/repository/global_admin_repository.rs#L380-L452)

API 将 `LAST_GLOBAL_ADMIN_PROTECTED` 映射为校验错误，并在成功禁用后发布会话撤销；撤销消息 pending 时返回 `PENDING`。[`global_admin.rs` disable 处理](../../../astral-trustgraph/src/api/global_admin.rs#L234-L296)

该链路解决了几个关键事故窗口：

- 管理员行已经 DISABLED、特权卡仍 ACTIVE 的权限旁路；
- 卡片状态变更但资格缓存仍为 ACTIVE 的 stale-ALLOW；
- REVOKE 不递增 fence 导致旧 refresh 消息重新生效；
- 并发禁用两个管理员造成零 ACTIVE 管理员。

projection 的当前实现不是单一重建入口：source mutation 与 head/outbox 在同一事务闭合后，CARD 事件由 durable worker 重建卡级快照、失效缓存并发布 refresh；RuleSet 写路径当前仍同步重建共享 `rule_set_snapshot`，受影响卡的 per-card projection 则由 durable CARD 事件交给 worker 处理。禁止写路径绕过各自已定义的事务/事件边界直接同步 evict 或发布；统一 RULE_SET 版本契约仍是待完成项。[`projection_repository.rs` durable projection 说明](../../../astral-trustgraph/src/repository/projection_repository.rs#L1-L23)；[`side_effects.rs` projection 副作用边界](../../../astral-trustgraph/src/api/side_effects.rs#L1-L6)

## 6. GlobalAdmin 当前守卫、审计与缺口

### 6.1 ACTIVE 管理员守卫的当前分布

TrustGraph 已有 `require_platform_admin()`：从 Gateway 注入的 `x-user-id` 解析用户，并通过 `GlobalAdminRepository.is_active_admin()` 查询 ACTIVE 状态；它不解析角色字符串，也不把 caller-supplied scope 当作跨范围管理凭据。[`api/mod.rs` 平台管理员守卫](../../../astral-trustgraph/src/api/mod.rs#L7-L37)

该守卫已经用于审计隔离重放、审批全表查询、RuleSet、模板、域、动作、卡片模板等平台治理端点。例如 audit-quarantine 的列表、详情和 replay 申请都在 handler 内调用该守卫。[`audit_replay.rs` ACTIVE GlobalAdmin 门禁](../../../astral-trustgraph/src/api/audit_replay.rs#L121-L180)

但 GlobalAdmin 自身的五个生命周期端点目前只在外层 `permission_check` 中把 `/global-admins` 映射到 `authorization` 资源；handler 仅提取 `x-user-id` 作为 `caller_id`，没有显式调用 `require_platform_admin()`。[`global_admin_routes()` 与 caller 提取](../../../astral-trustgraph/src/api/global_admin.rs#L83-L103)；[`global_admin` list/summary/grant/disable handler](../../../astral-trustgraph/src/api/global_admin.rs#L106-L184)

这不是允许匿名访问的结论：外层路由仍经过 Gateway 和 PolicyEngine。但它留下了明确的治理缺口：

- 统一的 ACTIVE GlobalAdmin operator guard 尚未覆盖 GlobalAdmin lifecycle 自身；
- `grant`/`enable`/`disable` 的目标用户、目标卡、tenant/domain scope 没有在 handler 内形成独立的 operator-to-target scope proof；
- caller identity 的来源只在 Gateway 签名链中可信，handler 没有把完整物理双卡上下文作为生命周期操作的显式输入；
- grant/enable 是否允许由当前唯一管理员、另一个平台管理员或更细粒度治理规则执行，尚未形成独立的规范化策略。

#### 6.1.1 Formal Global resource contract and fresh authority proof (implemented 2026-09-22)

The formal HTTP authorization path no longer treats every targetless route as ordinary
actor-card scope. `physical_policy_context()` starts every protected HTTP request as
`Unresolved`; `astral_db::resolve_resource_ownership()` is the only component that may
classify the target before `PolicyEngine.evaluate()`.

- `TenantScoped` carries target `tenant_id`/`domain_id`/owner facts read from an
  authoritative server-side row. Gateway headers remain actor facts and are never copied
  into this target tuple.
- `Global` is available only for an explicitly enumerated route contract. An unspecified
  or unmapped target remains `Unresolved` and returns fail-closed `AUTHORIZATION_PENDING`.
- `GlobalAccessRequirement::ActiveGlobalAdmin` requires **both** a fresh, uncached
  `identity_global_admin.status = 'ACTIVE'` source read and matching strict published
  policy evidence. The engine repeats the source read immediately before its final ALLOW,
  after the evidence stability recheck; a disable committed during evaluation therefore
  turns the result into `GLOBAL_ADMIN_REQUIRED` rather than a stale ALLOW.
- `GlobalAccessRequirement::PolicyEvidence` is reserved for the small, explicitly
  self-scoped or static-metadata utility set. It still requires ordinary strict published
  evidence and any handler-specific server-side subject check; it is not a GlobalAdmin
  bypass.
- A GlobalAdmin source-read failure returns `AUTHORIZATION_PENDING` and accrues the
  repository circuit-breaker failure. A non-strict legacy/test repository cannot authorize
  an `ActiveGlobalAdmin` Global route because it has no equivalent durable evidence and
  final authority recheck.

The existing five-second `GlobalAdminRepository::is_active_admin()` cache remains a
handler-level convenience/defense-in-depth check only. It is not used as the formal
`PolicyEngine` proof; formal evaluation uses the shared uncached source predicate through
`SqlxRuleRepository`, including through the published-evidence cache wrapper. This closes
the prior Identity `/domains*` and broad TrustGraph/Monitor control-plane classification
gap without introducing a role-string, `isSuperAdmin()`, or handler-level ALLOW bypass.

Current code evidence: [resource ownership resolver](../../../astral-db/src/resource_ownership.rs), [formal ownership and GlobalAdmin gates](../../../policy-engine/src/engine.rs), [production repository port](../../../astral-db/src/repository.rs), and [TrustGraph decision observability](../../../astral-trustgraph/src/observability.rs). Real MySQL outage, disable/re-enable, and end-to-end route evidence remains a deployment/integration acceptance task; this implementation has not applied a migration or started any service.

#### 6.1.2 Resolver route inventory and intentionally closed self-service views (implemented 2026-09-22)

`resource_ownership.rs` now exposes a pure, closed route-contract decision before its
SQL lookup dispatch. Its unit inventory scans the declared protected routers for Identity,
TrustGraph, Monitor, Chat, and Learn, then requires each route to resolve to exactly one of:

- an authoritative target-row lookup;
- a narrowly verified current-card actor-unit operation;
- an explicit Global contract (`ActiveGlobalAdmin` or the narrow `PolicyEvidence` set); or
- a named intentionally fail-closed outcome.

The Chat and Learn inventories are tied to the exact `.merge(...)` builder lists used by
`api_routes`, `admin_routes`, `app_learn_routes`, and `app_user_routes`; adding a protected
builder without updating the inventory fails the resolver unit suite. Chat only keeps the
body-addressed `POST /messages` and `POST /receipts` closed, because their request-body
`conversation_id` is not ownership evidence. Learn's `learn_*` routes remain intentionally
fail-closed until each resource has a separately specified authoritative ownership contract.
The existing `/announcements*` admin routes are explicitly recorded as pre-resolver denials
because they have no `LEARN_PATH_MAP` entry. `/login` and `/logout` remain authentication
exemptions, while the existing `APP_USER` profile bypass is recorded separately rather than
being reclassified as a resolver-derived tenant or Global contract.

This prevents a new protected router declaration from silently becoming an unreviewed
`target_missing` path. Monitor's `/alert-rules*` and `/alerts-summary` are covered by
both its path map and `ActiveGlobalAdmin` resolver contract; Identity's platform-wide
`/users`, `/admin/*`, `/orgs`, and `/tenants` collections likewise require fresh
GlobalAdmin proof plus strict published policy evidence.

The inventory deliberately does **not** convert a user-scoped multi-tenant view into the
active card's tenant/domain. `GET /permission-requests/mine`, `GET /tenants/mine`, and
verified self-service Identity card/MFA operations use the narrow `PolicyEvidence` contract:
the handler binds the data or mutation to the signed caller, while the selected card still
must carry matching strict published policy evidence. They do not invent a target tenant or
use actor-card facts as target facts.

Body-addressed creates and code-based cross-tenant invitation use remain closed: no request
body, query identifier, or invitation code is copied into `resource_tenant_id` or
`resource_domain_id`. Reopening those routes requires a separately specified user-bound or
server-resolved target contract, with handler proof and regression coverage; it must not use
an actor-card fallback.

### 6.2 mutation projection、session revocation 与当前审计状态

当前已经存在的副作用覆盖：

| 操作 | 当前 durable/异步副作用 | 当前状态 |
| --- | --- | --- |
| grant/enable | `identity_global_admin`、SUPER_ADMIN card、BASE binding、CARD/ELIGIBILITY head/outbox 同事务；之后会话撤销 | 已实现；projection 或 session revocation 未就绪时返回 `PENDING` |
| disable | 管理员状态、SUPER_ADMIN card DISABLED、CARD `REVOKE`、ELIGIBILITY event 同事务；之后会话撤销 | 已实现；最后活跃管理员 fail-closed 保护 |
| 普通权限评估 | `permission_check_middleware` 和 ArbiterService 通过 MQ-first/DB-fallback 权限审计入口记录授权判定 | 已实现；审计 I/O 不改变授权结果 [`record_permission_audit`](../../../astral-common/src/audit.rs#L301-L344) |
| GlobalAdmin lifecycle 操作 | `granted_by`、`granted_reason`、状态和时间写入 `identity_global_admin` | 缺少专门的 `GLOBAL_ADMIN_GRANTED/ENABLED/DISABLED` durable operation audit |

当前 `grant/enable/disable` 的 `granted_by` 和 reason 是业务表字段，不等价于审计事件：它们没有统一的 operation id/message id、旧状态/新状态、操作者完整上下文、卡片变更、projection generation/fence、session revocation delivery status 和失败补偿关联。

因此当前审计结论是：

- 授权判定有通用审计；
- GlobalAdmin 的状态 mutation 有业务字段和日志/响应状态；
- GlobalAdmin 生命周期的操作级、事务级、可重放审计仍是缺口；
- audit-quarantine replay 已有独立且更严格的操作审计，不应假定 GlobalAdmin lifecycle 自动享有同等审计完整性。

### 6.3 目标变更

后续治理变更应至少补齐：

1. **Scope guard integration**：所有 GlobalAdmin lifecycle handler 统一使用已验证 ACTIVE operator 身份，并重新构建/校验物理双卡上下文；目标 user/card 的 tenant/domain、状态和操作范围必须由服务端事实查询证明，不能只依赖请求头或请求体字段。
2. **Operation audit**：grant/enable/disable 在同一 source transaction 内写入结构化操作审计，至少包含 operation id/message id、actor、target user、target card、旧/新 GlobalAdmin 状态、旧/新 card 状态、template/rule set、projection event/generation/fence、reason、session revocation 状态。审计写失败必须阻止敏感 mutation 提交，或进入明确的 durable compensation，不得静默成功。
3. **Idempotency and replay**：操作 id 必须可去重；重复 grant/enable/disable 必须返回既有 operation 结果或明确冲突，不能重复产生不可区分的副作用。
4. **Audit chain**：审计事件继续遵守 MQ-first/DB-fallback、`messageId` 去重和失败可追踪；状态 mutation、projection、session revocation 和审计之间要能通过 operation id 关联。
5. **No privilege bypass**：任何新实现都不得增加 `isSuperAdmin()`、`card_type == SUPER_ADMIN`、GlobalAdmin 字符串或 `['*']` 的直接 ALLOW 分支。

## 7. audit-quarantine replay：当前特权运维路径

### 7.1 为什么它是特权路径

audit-quarantine 保存 RabbitMQ 审计消息达到重试上限后的 raw payload 和失败元数据。普通列表/详情只返回 metadata，不暴露 raw payload、租约 token 或 token hash；raw record 只在显式 worker claim 时返回。[`astral-db/src/quarantine.rs` 元数据/raw/租约边界](../../../astral-db/src/quarantine.rs#L1-L8)；[`AuditQuarantineMetadata` 与 privileged claim](../../../astral-db/src/quarantine.rs#L391-L503)

当前 HTTP 路径是：

```text
ACTIVE GlobalAdmin
  -> GET /audit-quarantine（metadata list）
  -> GET /audit-quarantine/{id}（metadata detail）
  -> POST /audit-quarantine/{id}/replay（申请）
  -> REPLAY_REQUESTED
  -> TrustGraph replay worker claim
  -> REPLAYING + lease/generation
  -> allowlist/identity/payload validation
  -> publisher confirm
  -> REPLAY_CONFIRMED
```

列表、详情和申请都调用 `require_platform_admin()`；申请只推进到 `REPLAY_REQUESTED`，不会在 HTTP handler 中读取 raw body、租约 secret 或直接发布 MQ。[`audit_replay.rs` 端点与 ACTIVE GlobalAdmin 守卫](../../../astral-trustgraph/src/api/audit_replay.rs#L1-L18)；[`audit_replay.rs` request replay](../../../astral-trustgraph/src/api/audit_replay.rs#L161-L214)

### 7.2 当前 replay 防护

申请阶段：

- 校验源 queue/exchange/routing key/message type 必须属于 TrustGraph audit allowlist；
- 使用 `x-request-id` 或生成 operation id，并限制字符集和长度；
- 仅第一次从 `QUARANTINED` 转为 `REPLAY_REQUESTED` 时写 durable operator audit，幂等重试不重复写同一操作审计。[`audit_replay.rs` route、operation id 与 operator audit](../../../astral-trustgraph/src/api/audit_replay.rs#L180-L298)

数据库/worker 阶段：

- replay operation id 只存 hash；lease token 只存 hash；worker 需要 owner、operation identity、lease generation 和 token 才能确认/失败转移；
- requested replay 优先，过期 `REPLAYING` 通过 generation/owner/token CAS 重新领取；
- lease 过期、attempt 超限、generation 溢出或 CAS 条件不满足时不应覆盖其他 worker 的状态。[`quarantine.rs` replay 状态与 CAS SQL](../../../astral-db/src/quarantine.rs#L83-L218)

worker 在发布前验证：

- route allowlist；
- message id 非空且与 envelope 一致；
- payload 大小、JSON 对象、字段 allowlist、RFC3339 timestamp；
- `MqMessage<AuditLogPayload>` 反序列化和审计字段边界；
- RabbitMQ publisher confirm 成功后才将行置为 `REPLAY_CONFIRMED`。[`audit_replay_worker.rs` claim 处理与 validate](../../../astral-trustgraph/src/service/audit_replay_worker.rs#L204-L307)；[`audit_replay_worker.rs` replay payload validation](../../../astral-trustgraph/src/service/audit_replay_worker.rs#L323-L455)

`REPLAY_CONFIRMED` 当前只表示 broker publish confirmation，不表示普通 audit consumer 已经处理完成；worker 注释明确区分这两个状态。[`audit_replay_worker.rs` 状态语义](../../../astral-trustgraph/src/service/audit_replay_worker.rs#L1-L7)

### 7.3 与 Arbiter/GlobalAdmin 的边界

- replay 的 ACTIVE GlobalAdmin 守卫不能由 Arbiter `ALLOW` 替代；
- replay 只恢复受控 audit message，不接收或传播跨节点 PolicyEngine decision evidence；
- replay worker 的 lease/generation 是消息运维 CAS，不是 Arbiter 的节点 quorum；
- operator audit 是 replay 申请的审计，不等价于 GlobalAdmin grant/disable 的生命周期审计；
- replay 失败或 audit consumer 未处理完成时，不得影响正常权限评估为 ALLOW。

## 8. 当前实现、规范约束、目标变更、历史参考

| 主题 | 当前实现 | 规范性约束 | 目标变更 | 历史参考的处理 |
| --- | --- | --- | --- | --- |
| Arbiter 角色 | 冲突信号 + 纯函数仲裁 + TrustGraph 控制面 API | 不得成为正常授权旁路 | 签名证据、上下文绑定、nonce/replay、quorum 后再评估受控接入 | Java/JSA 中的旧冲突/旁路描述仅作迁移背景 |
| READY/fence | gate 携带 ready、generation、revoke fence；纯函数按版本序裁决 | 不可证明时 DENY/DEFER；REVOKE fence 必须单调 | 服务端重新读取 head、验证签名和版本证明 | 早期单节点/未版本化描述不能覆盖当前投影契约 |
| Arbiter ALLOW | 可能由调用方提交的全 ALLOW READY 证据产生 | 不能替代 `PolicyEngine.evaluate()` | 在证据认证完成前永远停留在治理/审计面 | JSA 的 `GLOBAL_ADMIN_BYPASS` 不是当前 Rust 规范 |
| GlobalAdmin | ACTIVE grant row + SUPER_ADMIN card + BASE RuleSet + projection | 禁止 `isSuperAdmin()`/通配权限直接放行 | lifecycle 统一 ACTIVE operator/scope guard | Java initializer/lifecycle 是迁移参考，不是 Rust 运行时事实 |
| Projection | grant/disable 同事务追加 CARD/ELIGIBILITY event，worker 后续投影 | source mutation 必须和 projection request 同事务 | 继续补齐 operation audit 与补偿关联 | Java `PermissionRefreshService` 用于语义对照 |
| GlobalAdmin audit | `granted_by`/reason、通用权限审计、日志 | 敏感 mutation 必须可追踪、幂等、可重试 | 专门 operation audit + messageId + generation/fence | JSA 旧实现中的旁路判断不能作为审计证明 |
| Quarantine replay | ACTIVE GlobalAdmin + request audit + worker lease/CAS + allowlist | raw payload 与租约 secret 不得暴露普通 API | 将 operator audit、consumer completion、失败补偿关联得更完整 | 不属于 Java/JSA 权限评估链 |

## 9. 历史 Java/JSA 参考与禁止误读

### 9.1 Java 参考实现

以下 Java 文件用于解释迁移来源和语义映射，不是当前 Rust 运行时的直接事实：

- Java `GlobalAdminService` 的当前历史适配器只做 ACTIVE grant 查询，并在依赖不可用时返回 false，体现 fail-closed 读取边界。`GlobalAdminService.java`
- Java `SuperAdminTemplateInitializer` 在启动生命周期中同步模板动作、RuleSet 和专用 SuperAdmin card，并用 BASE 绑定共享 RuleSet；Rust 启动 wiring 保留了这一概念，但 Rust 的事务、projection 和返回状态以本文件第 5 节所列源码为准。`SuperAdminTemplateInitializer.java`；`SuperAdminTemplateInitializer.java` 专用卡与 BASE binding
- Java lifecycle facade 将 GlobalAdmin mutation、SuperAdmin card provisioning、会话撤销和 card refresh 组合起来，是 Rust `grant_with_superadmin_privilege()`、projection outbox 和 revocation status 设计的历史参照。`GlobalAdminLifecycleServiceImpl.java`
- Java `PolicyEngine` 的 RuleSet 优先级、投影 gate 和 ALLOW 前稳定性复检，是 Rust PolicyEngine 迁移时的语义参照；当前 Rust 行为应以 Rust 源码为准。`PolicyEngine.java`；`PolicyEngine.java` RuleSet 评估

### 9.2 JSA 历史描述

JSA 早期设计/实现详解中曾出现 `isGlobalAdmin` 通配权限和 `isSuperAdmin() || isGlobalAdmin() -> true` 的旁路示例。[`规则模式权限体系代码实现详解.md` 历史示例](../../规范/Rust后端编码规范_V1.0.md#L1040-L1078)

这些段落属于历史参考，不能与当前规范混读。当前不可协商约束是：禁止任何 `SUPER_ADMIN`/`isSuperAdmin()` 特判放行，特权只能由启动期模板同步形成 RuleSet，再经 PolicyEngine 评估。[`AGENTS.md` SuperAdmin 禁令](../../../AGENTS.md#L192-L198)

已有 Rust 架构审查也明确记录 Arbiter 端点“接受请求体 context 和证据 gate、没有双卡复验”，并将 handler 使用物理上下文重建与复验列为待实施修正；这应被视为当前缺口和目标变更，不应被引用成已经完成的保证。[`Rust架构模型设计修正记录.md` Arbiter 缺口](Rust架构模型设计修正记录.md#L81-L91)；[`物理双卡权限链路评估与设计_V1.0.md` R3 评估](物理双卡权限链路评估与设计_V1.0.md#L399-L437)

## 10. 验收标准

本文档对应的后续实现或审查至少应能回答：

- Arbiter 的每份 evidence 是否有可验证 node identity、签名、context digest、nonce 和有效期？
- 相同 node 是否能被重复计票？旧 generation/fence 或旧 nonce 是否能重新触发 ALLOW？
- Arbiter `DEFER`、证据缺失、quorum 不足、签名错误和 head 不可读是否全部走 DENY/PENDING，而不是放行？
- 普通请求是否仍只通过物理双卡上下文和 `PolicyEngine.evaluate()` 获取 ALLOW？
- GlobalAdmin grant/enable/disable 是否统一经过 ACTIVE operator 和目标 scope 守卫？
- GlobalAdmin mutation 是否和 CARD/ELIGIBILITY projection、session revocation、operation audit 具有可追溯 operation id？
- 最后一位 ACTIVE 管理员并发禁用、MQ 不可用、projection 未 READY、Redis 不可用和 worker lease 过期时，结果是否仍然 fail-closed？
- audit-quarantine replay 是否只允许 ACTIVE GlobalAdmin，是否保持 metadata/raw 分离、lease fencing、message id 一致性和 publisher confirm 语义？

在上述问题全部有代码和测试证据前，本文件的结论保持不变：**Arbiter 是治理控制面，不是正常 PolicyEngine ALLOW 的来源；GlobalAdmin/SuperAdmin 的特权必须沿双卡、RuleSet、投影和 PolicyEngine 链路生效。**
