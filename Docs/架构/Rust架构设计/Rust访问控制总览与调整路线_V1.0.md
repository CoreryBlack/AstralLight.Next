# Rust 访问控制总览与调整路线 V1.0

> 版本：V1.0
> 日期：2026-09-09
> 适用：`` workspace 的 Gateway、Identity、TrustGraph、PolicyEngine、数据库投影、缓存、消息与审计链路。
> 文档性质：**非规范性架构设计/证据材料**。本文记录当前事实、缺口和已选择的目标决策，不替代 [Docs/规范/](../../规范/) 或仓库根目录 [AGENTS.md](../../../AGENTS.md)。
> 说明：本文不表示本次会话修改了 Rust 代码；调整项和未实现项集中列在[调整路线](#12-调整路线)。

## 1. 阅读边界

本文把四种材料分开：

- **当前源码**：判断运行时行为的第一证据，引用 `**` 的文件和行号。
- **工程规范**：规定 Rust 应遵守的 crate 边界、双卡不变式、投影/错误/测试门和实施流程；权威来源是 `Docs/规范/` 与仓库根目录 `AGENTS.md`。
- **架构材料**：记录当前事实、证据、缺口和目标决策；本目录材料是非规范性的，不能把目标态写成已实现，也不能替代工程规范。
- **Java 参考**：用于迁移语义对照，不覆盖 Rust 当前事实。
- **JSA/历史材料**：解释规则模型的来源和演进，不作为当前 Rust 已实现能力的证明。

当前 workspace 明确 exclude `astral-learn` 与 `astral-chat`；它们的源码仍在仓库中，但不参加默认 workspace 编译和测试。依据见 [`Cargo.toml`](../../../Cargo.toml#L1-L15)。因此，本文对 Learn/Chat 的实现描述必须注明“源码存在、默认验证边界之外”。

## 2. 当前结论

1. **认证锚点由 Gateway/Identity 共同形成**：Identity 在 login/refresh/switch-card 签发前校验身份卡与用户卡对应关系；Gateway 清洗客户端身份头、校验 JWT 和 Redis 会话投影，然后以 HMAC v3 把可信身份上下文交给下游。
2. **双卡不是两套授权系统**：`identity_card` 只证明身份/会话事实；`user_card` 承载授权和组织事实。PlatformUser 进入完整双卡路径，AppUser 只有 identity-only context，不能用身份卡回退成用户卡授权。
3. **授权唯一入口是 `PolicyEngine::evaluate()`**：服务中间件先完成路由到 `(resource, action)` 的解析、资源注册校验和 `PolicyContext` 构造。生产 `SqlxRuleRepository` 在认证、卡上下文和资源/动作校验后进入 published-evidence strict gate；未声明 capability 的 legacy/test repository 才保留 L1 RuleSet、L2 旧 snapshot、L2.5 委托阶段用于兼容和诊断。
4. **投影是授权读模型的安全门**：canonical current pointer、manifest/segment seal、generation 与 revoke-fence proof 缺失或不可验证时不能产生 ALLOW；旧 `permission_rule_snapshot`/`rule_set_snapshot` 不能作为生产 strict gate 的回退。ELIGIBILITY head 单独服务于物理卡资格缓存，不替代授权证据门禁。
5. **新授权投影链已接线，旧链处于退役边界**：`AuthorizationCompiler`、`AuthorizationProjector`、`AuthorizationArchiveWorker` 和 strict published-evidence reader 已有代码级接线；旧 `ProjectionWorker` 只终结 CARD/RULE_SET writer-correlation 事件并处理 ELIGIBILITY 资格缓存失效。既有数据 backfill/rehearsal、缓存/摘要迁移、真实基础设施集成和正式切流验收仍未完成。具体排序见[调整路线](#12-调整路线)。
6. **已批准的 Rust canonical 模型是“版本化可变热状态 + 异步旧版本归档”，已入库但未切流**：热状态当前版本可变（`AuthorizationCompiler` 测试中的 111→112 只是版本推进示例，不是固定生产版本号）；增量事件携带 before-image/旧 segment 引用；发布经 `authorization_projection_current` 的原子 CAS 指针；旧 manifest 由异步 archive worker 产出 DB 内归档证明（proof 先于 ACK）；segment 为内容寻址不可变行并带 segment-local seal；授权账本 ALLOW-only，普通 DENY 不持久化为 grant；RULE_SET 贡献带 BASE/OVERLAY 标签。读侧代码层现状：`astral-db` 提供严格 published-evidence 读门（缺 current 指针 ⇒ NotReady、无 empty-ALLOW 形态、无旧快照/raw source/cache 回退），生产 `SqlxRuleRepository` 声明 capability marker `requires_published_card_evidence() == true`，正式 `evaluate()` 在 marker 为真时于 AUTHN/CARD_CONTEXT 之后进入 strict gate 并全程 fail-closed；`evaluate_realtime()` 与 L1/L2/L2.5 union 不消费该端口。真实 MySQL/Redis/RabbitMQ 集成验收、既有数据 backfill/rehearsal、缓存/摘要读侧迁移与正式切流验收均未完成，真实集成未完成前不得宣称生产验收。证据与边界见 §8/§14 与[投影快照与版本栅栏](./Rust权限投影快照与版本栅栏_V1.0.md)。

## 3. 端到端调用链

### 3.1 总链路

```text
客户端请求
  -> Gateway 清洗客户端身份头
  -> route_credential_policy + JWT v2 校验
  -> Redis revoked / access:jti / access:grant / tenant status
  -> 注入可信双卡身份头
  -> Gateway HMAC v3 转发
  -> 下游 gateway_signature 验签
  -> 服务 path/resource/action 映射 + ResourceRegistry 校验
  -> physical_policy_context 构建双卡 PolicyContext
  -> PolicyEngine.evaluate()
       -> AUTHN / CARD_CONTEXT
       -> resource/action 校验
       -> canonical published-evidence strict gate
            current pointer + manifest/segment seal + lineage/generation/fence proof
       -> ALLOW-only effective_grants matcher
       -> DEFAULT_DENY
  -> 允许时进入业务 handler
  -> 权限审计（MQ-first / DB-fallback / tracing）
```

Gateway 路由和 middleware 装配在 [`astral-gateway/src/main.rs`](../../../astral-gateway/src/main.rs#L203-L289)；清洗和 JWT 主流程在 [`astral-gateway/src/middleware.rs`](../../../astral-gateway/src/middleware.rs#L898-L980)。下游 HMAC v3 验签及 PlatformUser/AppUser 头字段约束在 [`astral-common/src/middleware/gateway_signature.rs`](../../../astral-common/src/middleware/gateway_signature.rs#L17-L74) 和 [`#L161-L258`](../../../astral-common/src/middleware/gateway_signature.rs#L161-L258)。

### 3.2 L0：Identity 签发与 SessionGrant

Identity login 先读取 ACTIVE 身份聚合、选择用户卡，然后调用 `CardEligibilityService::verify_platform_card_pair`。该调用证明：

- `identity_card` 属于当前用户、ACTIVE 且未过期；
- `user_card` 属于当前用户、ACTIVE、在有效时间窗内，且不是模板卡；
- 两张卡通过同一 `platform_user`/`user_id` 对齐；
- user-card 的 `tenant/domain` 非空，租户和域映射有效。

login 的调用点见 [`astral-identity/src/srv/auth_service.rs`](../../../astral-identity/src/srv/auth_service.rs#L205-L289)。统一资格服务及权威 JOIN 见 [`astral-db/src/eligibility.rs`](../../../astral-db/src/eligibility.rs#L74-L154) 和 [`#L235-L277`](../../../astral-db/src/eligibility.rs#L235-L277)。refresh/switch-card 也复用同一资格服务，事实与目标边界见[物理双卡权限链路评估与设计 §2.1](./物理双卡权限链路评估与设计_V1.0.md#21-当前链路rust-双卡分离后)。

签发后 Identity 把 `access:jti:{jti}` 标量、`access:grant:{jti}` v2 grant 和数据库 JTI 索引写入 Redis/DB；写入任一部分失败会清理已写投影并返回错误。实现见 [`astral-identity/src/srv/session.rs`](../../../astral-identity/src/srv/session.rs#L796-L838)。这一步是 Gateway 后续会话有效性检查的输入，不是权限规则本身。

### 3.3 L1：Gateway 认证、会话和可信头

Gateway 运行时的实际顺序是：

1. `sanitize_internal_auth_headers` 移除客户端可能伪造的身份、权限、网关和内部服务头。
2. `jwt_auth_middleware` 依据路由凭证策略校验 Access/Refresh/Public 语义，拒绝错误 token purpose。
3. Access token 校验 revoked key、`access:jti` 标量和 `access:grant` v2 内容；租户状态同时检查 token 声明和 Redis 状态。
4. Gateway 从 JWT claims 注入 `x-user-id`、`x-identity-card-id`、`x-user-card-id`、`x-user-card-tenant-id`、`x-user-card-domain-id`、principal/token/claims headers。
5. Proxy 以 HMAC v3 签名外部路径和身份字段；下游只信任验签通过的头。

Gateway 的路由凭证策略类型和会话 grant 校验在 [`middleware.rs`](../../../astral-gateway/src/middleware.rs#L166-L290)，中间件入口在 [`#L898-L980`](../../../astral-gateway/src/middleware.rs#L898-L980)。下游验签在 [`gateway_signature.rs`](../../../astral-common/src/middleware/gateway_signature.rs#L64-L258)。

**当前边界**：Gateway 负责认证、撤销和可信头，不代替下游 PolicyEngine 做资源动作授权。Gateway 路径层的 principal 守卫仍属于纵深加固路线；当前 AppUser 对需要用户卡的授权路径依赖下游 `CARD_REQUIRED`，见[物理双卡权限链路评估与设计 §3.3 D2](./物理双卡权限链路评估与设计_V1.0.md#d2--网关-principal-路由守卫可选加固不冻结路径)。

### 3.4 L2：下游可信头、资源注册和 PolicyContext

下游权限中间件不接受请求体或客户端自报的身份上下文。`physical_policy_context` 从 Gateway 验签后的头读取：

- `user_id`、principal kind、`identity_card_id` 缺失或非正数，返回未认证；
- PlatformUser 缺少任一用户卡 ID/tenant/domain，返回拒绝；
- AppUser 构造 identity-only context，`card_id/tenant_id/domain_id` 为空，进入要求用户卡的引擎路径时由 `CARD_REQUIRED` 拒绝。

实现见 [`permission_check_shared.rs`](../../../astral-common/src/middleware/permission_check_shared.rs#L102-L165)。

请求路径先由各服务的 path map 解析资源类型和动作；缺少映射直接拒绝，未知 HTTP 方法才跳过业务权限检查。随后调用 `engine.evaluate(&ctx, repo)`。实现见 [`check_permission`](../../../astral-common/src/middleware/permission_check_shared.rs#L284-L347)。

`ResourceRegistry` 是 `astral-types` 的集中注册表，提供资源/动作/条件校验；启动期 `validate_path_map` 交叉检查 path map 是否引用未注册资源，但当前检查记录错误并继续启动，不能当作强制启动失败门禁。注册表和校验见 [`registry.rs`](../../../astral-types/src/registry.rs#L113-L144) 与 [`#L319-L383`](../../../astral-types/src/registry.rs#L319-L383)。

### 3.5 L3：PolicyEngine.evaluate、strict published-evidence gate 与 legacy 兼容路径

生产 `PolicyEngine::evaluate()` 的主顺序是：

```text
断路器 OPEN -> DENY
  -> AUTHN / CARD_CONTEXT
  -> resource/action 校验
  -> strict published-evidence gate（生产 SqlxRuleRepository）
       current pointer + manifest/segment seal + generation/fence proof
       缺失/未证明/错误/scope 不符 -> AUTHORIZATION_PENDING 或 DENY
       有效 ALLOW 前复读证据
  -> 无命中 -> DEFAULT_DENY
```

生产读门的证据入口见 [`engine.rs`](../../../policy-engine/src/engine.rs#L455-L474)、[`repository.rs`](../../../astral-db/src/repository.rs#L447-L478) 与 [`authorization_projection_repository.rs`](../../../astral-db/src/authorization_projection_repository.rs#L1-L44)。生产 repository 的 capability marker 为 true，因此该路径不调用 legacy L1/L2/L2.5 reader，也不回退旧快照、raw source 或缓存。

未声明 `requires_published_card_evidence()` 的 legacy/test repository 仍可执行下列兼容阶段：CARD/RULE_SET gate → L1 RuleSet → L2 `permission_rule_snapshot` → L2.5 generation-gated delegation → DEFAULT_DENY。该序列用于测试、迁移对照和诊断，不应写成生产 `SqlxRuleRepository` 的当前放行链；L2 读取错误在 L2.5 前仍必须 fail-closed，raw/source reader 只能用于 realtime/一致性巡检。

### 3.6 L4：审计

授权中间件/仲裁服务通过 `record_permission_audit` 记录决策、resource、action、card、租户域、reason 和路径。MQ 可用时先发审计消息；MQ 未就绪或失败时走 DB fallback，DB fallback 共执行两次尝试（首次写入 + 一次重试），最终保留结构化 `audit_log` tracing。实现见 [`astral-common/src/audit.rs`](../../../astral-common/src/audit.rs#L88-L163) 的 [`for attempt in 1..=2`](../../../astral-common/src/audit.rs#L141-L161) 和 [`record_permission_audit`](../../../astral-common/src/audit.rs#L302-L367)。

当前审计是**授权决策后的异步/旁路记录**，不改变 ALLOW/DENY；因此审计写入失败不应反向放宽授权，但审计链仍需关注 message id 幂等、重试与最终可追溯性。GlobalAdmin 和 Arbiter 的特定审计边界列在路线 P1-4/P1-5。

## 4. 双卡上下文与投影关系

### 4.1 双卡不变式

| 上下文 | 身份卡 `identity_card` | 用户卡 `user_card` |
|--------|------------------------|--------------------|
| 语义 | 你是谁、身份/会话锚点、状态和过期时间 | 你能做什么、有效期、租户/域和规则集绑定 |
| 组织归属 | 不承载 tenant/domain，不提供授权范围 | 唯一组织事实来源 |
| PlatformUser token | `identityCardId` 必带 | `userCardId/userCardTenantId/userCardDomainId` 全带且为正 |
| AppUser token | `identityCardId` 必带 | 三字段必须全缺 |
| 证明点 | 与用户卡通过同一 `user_id`/platform user 对齐 | 对齐成功后才进入规则授权 |

实现类型见 [`PolicyContext`](../../../astral-types/src/context.rs#L7-L85)；权威资格服务说明见 [`eligibility.rs`](../../../astral-db/src/eligibility.rs#L1-L17)。任何 `identity_card` -> user-card tenant/domain fallback 都违反当前 Rust 语义。

### 4.2 CARD、ELIGIBILITY 与 RULE_SET 三条投影通道

`ProjectionAggregate` 将投影 head/outbox 分为三个类型：

- **CARD**：legacy 兼容投影通道。历史 source mutation 可能仍写旧 head/outbox；旧 worker 目前只终结 CARD writer-correlation，不再重建 `permission_rule_snapshot`、清理 CARD 缓存或发布旧 `permission.refresh`。生产授权不以该旧链作为 strict gate。
- **ELIGIBILITY**：资格投影通道。worker 只失效 `perm:card:active:{card_id}`，资格读侧仍单独验证 ELIGIBILITY 版本和双卡上下文；它不重建规则快照、不发布 CARD refresh。
- **RULE_SET**：legacy 兼容规则集通道。历史 source mutation 可能仍写 RULE_SET head/outbox；旧 worker 只终结 writer-correlation，不再重建 `rule_set_snapshot`、写旧 `projection_generation`、清理规则集缓存或推进旧 READY。新 canonical delta 链才是生产授权投影的发布路径。

上述 legacy 通道仍可作为迁移/对账材料读取，但不能与 canonical `authorization_projection_current` 的 published-evidence gate 混写。

聚合类型和事件常量见 [`astral-types/src/projection.rs`](../../../astral-types/src/projection.rs#L9-L92)。事务写入器见 [`astral-db/src/projection.rs`](../../../astral-db/src/projection.rs#L1-L16) 和 [`#L48-L151`](../../../astral-db/src/projection.rs#L48-L151)。

TrustGraph 同时装配旧 `ProjectionWorker`、新的 `AuthorizationProjector` 和 `AuthorizationArchiveWorker`。旧 worker 只承担 ELIGIBILITY 资格缓存失效及 CARD/RULE_SET writer-correlation 终结；新 projector 是 `authorization_delta_event` 的唯一授权投影消费者，archive worker 负责旧 manifest 的 proof-before-complete 归档。启动装配见 [`astral-trustgraph/src/main.rs`](../../../astral-trustgraph/src/main.rs#L307-L365)。

### 4.3 版本和缓存契约

CARD/ELIGIBILITY/RULE_SET 旧 head 的状态列不再作为 canonical 生产读门。`source_generation`、`projected_generation`、`projection_status` 等字段若出现在旧兼容 schema 或历史代码中，只能用于迁移/对账；canonical 读门由 current pointer、manifest/segment seal、generation、lineage 和 `revoke_fence_proven` 共同证明。

`perm:refs:{card_id}` 缓存把三项版本随载荷保存，版本不匹配按 miss 处理；物理资格缓存额外绑定 `projection_type=ELIGIBILITY`、双卡上下文和自然到期时间。实现见 [`astral-db/src/repository.rs`](../../../astral-db/src/repository.rs#L148-L166) 和 [`astral-db/src/eligibility.rs`](../../../astral-db/src/eligibility.rs#L32-L54)。缓存异常的确切降级语义与生命周期仍列为路线项，不能只依据注释推断为生产全覆盖。

## 5. Crate 与 owner 地图

| Crate/目录 | 当前 owner | 访问控制责任 | 关键证据 |
|------------|-------------|--------------|----------|
| `astral-types` | 类型/契约 owner | `PolicyContext`、`PolicyDecision`、`ResourceRegistry`、投影聚合枚举与事件常量 | [`context.rs`](../../../astral-types/src/context.rs#L7-L85)；[`registry.rs`](../../../astral-types/src/registry.rs#L113-L144)；[`projection.rs`](../../../astral-types/src/projection.rs#L9-L92) |
| `policy-engine` | 纯授权内核 owner | `PolicyEngine.evaluate`、L1/L2/L2.5/DEFAULT_DENY、实时一致性、断路器、Arbiter 纯函数 | [`engine.rs`](../../../policy-engine/src/engine.rs#L163-L215)；[`arbiter.rs`](../../../policy-engine/src/arbiter.rs#L1-L15) |
| `astral-common` | 共享运行时/契约 owner | Gateway HMAC 下游验签、权限中间件、审计端口和双写适配 | [`permission_check_shared.rs`](../../../astral-common/src/middleware/permission_check_shared.rs#L284-L347)；[`audit.rs`](../../../astral-common/src/audit.rs#L88-L163) |
| `astral-gateway` | Gateway runtime owner | 路由、凭证策略、JWT、Redis session/grant/revocation、可信头、转发签名、限流 | [`main.rs`](../../../astral-gateway/src/main.rs#L203-L289)；[`middleware.rs`](../../../astral-gateway/src/middleware.rs#L898-L980) |
| `astral-identity` | 身份/会话 owner | login/refresh/switch-card、JWT/SessionGrant 签发、会话撤销投影 | [`auth_service.rs`](../../../astral-identity/src/srv/auth_service.rs#L205-L289)；[`session.rs`](../../../astral-identity/src/srv/session.rs#L796-L838) |
| `astral-db` | SQL/资格读取 owner | `SqlxRuleRepository`、双卡资格 JOIN、CARD/ELIGIBILITY/RULE_SET 读门禁和缓存读写、公共投影事务 helper | [`repository.rs`](../../../astral-db/src/repository.rs#L181-L217)；[`eligibility.rs`](../../../astral-db/src/eligibility.rs#L80-L186)；[`projection.rs`](../../../astral-db/src/projection.rs#L48-L151) |
| `astral-trustgraph` | 权限治理/投影控制面 owner | 规则集、规则写入、委托、GlobalAdmin、canonical authorization projector/archive、legacy ELIGIBILITY worker、Arbiter control plane、审计消费 | [`authorization_projector.rs`](../../../astral-trustgraph/src/service/authorization_projector.rs#L1-L25)；[`authorization_archive_worker.rs`](../../../astral-trustgraph/src/service/authorization_archive_worker.rs#L1-L25)；[`projection_worker.rs`](../../../astral-trustgraph/src/service/projection_worker.rs#L1-L31)；[`main.rs`](../../../astral-trustgraph/src/main.rs#L307-L365) |
| `astral-cache` | 缓存装饰 owner | `RuleRepository` 缓存装饰和 Redis key scope 测试；不得改变引擎的 fail-closed 语义 | [`cache_repository.rs`](../../../astral-cache/src/cache_repository.rs#L31-L113) |
| `astral-mq` | 消息传输 owner | permission.refresh、audit.log 和消息确认/消费基础设施 | [`astral-mq/src`](../../../astral-mq/src/lib.rs#L1-L21) |
| `astral-learn` / `astral-chat` | 源码保留、当前 workspace exclude | Learn/Chat 路由、业务 handler、Chat realtime scope；解冻前不计入默认 CI 证据 | [`Cargo.toml`](../../../Cargo.toml#L1-L15)；[Gateway Chat 路由](../../../astral-gateway/src/main.rs#L128-L172) |
| `astral-monitor` | 监控 owner | 健康/指标/一致性和 Arbiter 统计观察面；不得成为授权旁路 | [`astral-monitor/src`](../../../astral-monitor/src/lib.rs#L1-L37) |

2026-08-26 增补（canonical 模型切片的当前 owner；其中严格 published-evidence 读门已由生产 `SqlxRuleRepository` 的 capability marker 门控接入正式 `evaluate()`，读侧现状见 §2 第 6 条与 §8/§14）：`policy-engine` 另有无 IO 的 [`authorization_compiler.rs`](../../../policy-engine/src/authorization_compiler.rs#L1)（版本化热状态编译内核，candidate/full-rebuild oracle）；`astral-db` 另有 [`authorization_projection_repository.rs`](../../../astral-db/src/authorization_projection_repository.rs#L1)（manifest/segment/current/archive 表链与严格 published-evidence 读门）与 [`grant_repository.rs`](../../../astral-db/src/grant_repository.rs)（revision ledger + delta queue，ALLOW-only 合同 gate）；`astral-trustgraph` 另有 [`authorization_projector.rs`](../../../astral-trustgraph/src/service/authorization_projector.rs#L1)（新 delta 队列唯一消费者）、[`authorization_archive_worker.rs`](../../../astral-trustgraph/src/service/authorization_archive_worker.rs#L1)（异步归档证明）与 [`grant_ledger_adapter.rs`](../../../astral-trustgraph/src/repository/grant_ledger_adapter.rs#L1)（审批→typed 账本 DTO 组装）。

## 6. 专门文档索引

### 6.1 双卡、Gateway 与模型修正

- [Rust双卡身份与授权上下文_V1.0.md](./Rust双卡身份与授权上下文_V1.0.md)
- [物理双卡权限链路设计_V1.0.md](./物理双卡权限链路设计_V1.0.md)
- [物理双卡权限链路评估与设计_V1.0.md](./物理双卡权限链路评估与设计_V1.0.md)
- [Rust-Gateway当前实际链路与解耦对照设计_V1.0.md](./Rust-Gateway当前实际链路与解耦对照设计_V1.0.md)
- [Rust架构模型设计修正记录.md](./Rust架构模型设计修正记录.md)
- [V5模型修正筹划_专供Rust_V1.0.md](./V5模型修正筹划_专供Rust_V1.0.md)

### 6.2 规则语义、投影和版本

- [规则模式权限体系Merge语义规范_V1.0.md](../../规范/Rust后端编码规范_V1.0.md)
- 规则模式权限体系设计_V1.0.md
- [规则模式权限体系代码实现详解.md](../../规范/Rust后端编码规范_V1.0.md)
- [Rust后端迁移架构决策_V1.0.md](../../迁移/Rust后端迁移架构决策_V1.0.md)
- [Rust迁移Java等价适配状态_2026-08-05.md](../../迁移/Rust迁移Java等价适配状态_2026-08-05.md)
- [权限引擎优化方向_2026-06-22.md](./Rust增量重建与实时授权边界_V1.0.md)
- permission-projection-sequence.mmd

### 6.3 委托、Arbiter 和 GlobalAdmin

- [委托 API 与生命周期](../../../astral-trustgraph/src/api/delegation.rs#L230)
- [委托 repository 事务边界](../../../astral-trustgraph/src/repository/delegation_repository.rs#L41-L89)
- [Arbiter 内核](../../../policy-engine/src/arbiter.rs#L1-L219)
- [Arbiter service](../../../astral-trustgraph/src/service/arbiter.rs#L1-L124)
- [Arbiter API](../../../astral-trustgraph/src/api/arbiter.rs#L1-L126)
- [GlobalAdmin API](../../../astral-trustgraph/src/api/global_admin.rs#L85-L298)
- [GlobalAdmin repository](../../../astral-trustgraph/src/repository/global_admin_repository.rs#L74-L429)

## 7. 当前 CI/test 证据边界

### 7.1 CI 定义了什么

当前 CI 在 `.github/workflows/ci.yml` 定义两个相关 job：

- **Rust Check**：启动 MySQL/Redis/RabbitMQ 服务容器，加载 canonical schema，执行 Rust migration；随后运行 `cargo fmt --all -- --check`、`cargo check --workspace --all-targets`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo test --workspace --lib` 和 ignored integration tests。
- **Replay Integration**：独立服务容器和 schema/migration 后，运行 TrustGraph audit replay 以及两个 quarantine integration 测试。

对应 workflow 行号见 [Rust Check](../../README.md#L136-L249) 和 [Replay Integration](../../README.md#L251-L361)。

### 7.2 不能从 CI 定义推出什么

1. **本文没有运行本次 Rust CI**：workflow 行号是仓库定义的证据入口，不是本次会话的通过结果。
2. `astral-learn`/`astral-chat` 位于 workspace `exclude`，因此默认 `--workspace` 检查不会证明这两个源码目录全量编译或测试通过。
3. CI 的 unit/integration/replay 覆盖不能自动证明所有生产 source mutation 都经过 CARD/ELIGIBILITY projection，也不能证明所有跨节点 Arbiter 证据都来自可信节点。
4. canonical `AuthorizationCompiler`、`AuthorizationProjector`、`evaluate_realtime`、Arbiter 纯函数和 mock repository 测试证明接口/纯逻辑或代码接线存在，不等同于真实 MySQL/Redis/RabbitMQ 生产切流已完成。
5. 历史迁移材料中的“对齐率”是历史快照，不能替代当前源码和当前 CI 结果；以当前源码和测试为准。
6. 2026-08-26 增补：canonical 模型切片（`AuthorizationCompiler`、新表链 repository、projector/archive worker、严格 published-evidence 读门）当前只有无 DB 的 typed/shape 测试覆盖；生产 `SqlxRuleRepository` 已声明 capability marker 且正式 `evaluate()` 在 marker 为真时进入 strict gate，但真实 MySQL/Redis/RabbitMQ 集成与正式切流验收均未执行，CI 未运行，不能据此宣称集成通过。Java、Chat、Learn、Duo 的行为或部署不是该模型验收依赖；`astral-learn`/`astral-chat` 仍按 workspace `exclude` 边界处理。

## 8. 当前已实现、当前有边界、明确未实现

### 已有源码证据的能力

- 物理双卡签发资格校验和运行期资格检查。
- Gateway JWT/Redis session grant/revocation、可信身份头清洗和 HMAC v3 下游验签。
- ResourceRegistry/path map/PolicyContext/PolicyEngine.evaluate 的主链路。
- canonical grant revision/delta/manifest/segment/current 表链、`AuthorizationCompiler`、`AuthorizationProjector`、`AuthorizationArchiveWorker` 和 strict published-evidence reader 的代码级接线；旧 head/outbox 仅作为兼容 writer-correlation，ELIGIBILITY 仍有独立资格缓存失效职责。
- ALLOW-only `effective_grants` 匹配、DEFAULT_DENY、断路器 deny、current/manifest/segment proof 不足时的 PENDING/DENY 和 MQ-first/DB-fallback 审计基础设施。

2026-08-26 增补（canonical 模型切片，源码证据见 §5 注记）：版本化热状态 typed 合同（ALLOW-only grant、BASE/OVERLAY 标签、canonical GrantId）；无 IO 编译内核与 full-rebuild oracle；新 Rust-owned 表链（delta/impact-plan/manifest/segment/current/archive，creator-only 迁移，lineage + revoke fence，0 哨兵 fail-closed）；projector 与异步 archive worker 已在 TrustGraph main 接线；严格 published-evidence 读门已由生产 `SqlxRuleRepository` 的 capability marker 门控接入正式 `evaluate()`（`evaluate_realtime()` 与 L1/L2/L2.5 union 不消费该端口）。`AuthorizationCompiler` 内核与新表链仍未接触旧生产 snapshot 写路径；真实 MySQL/Redis/RabbitMQ 集成、backfill/rehearsal、缓存/摘要读侧迁移与正式切流验收未完成，不得据此宣称生产验收。

### 当前边界或证据不足

- L2 source read 错误已在 L2.5 前 fail-closed；仍需对组合故障、审计 reason 和部署验收持续验证。
- `source_type` 的写入 owner、跨 crate 允许值和审计约束尚未形成单一强制白名单契约。
- 委托表的 `delegator_card_id`/caller 授权 scope 与 API 操作者上下文尚未在所有入口形成独立、可证明的 caller scope。
- 规则集更新已经接入 durable RULE_SET 事件、`projection_generation`、migration/backfill、correlated audit 和读侧 generation gate；剩余是部署 schema/backfill/worker replay 验收以及 validity/wall-clock 到期边界，不再描述为缺少 RULE_SET durable 协议。
- 增量编译器是 `policy-engine` 纯逻辑接口；生产数据库投影当前仍包含全量重建/回退路径，不能称为生产增量编译已完成。
- `evaluate_realtime` 是一致性/诊断路径；需要明确它不成为生产授权放行的旁路，并定义可访问性、限流、超时和审计边界。
- 缓存读失败、写失败、自然过期、Redis 生命周期、DB/MQ timeout 和 worker shutdown 的组合语义仍需统一验收。
- Arbiter 能够对请求体 evidence 做确定性裁决，但当前 API 的 `context` 来自请求体；操作者双卡复验、节点证据来源认证和 replay 防护仍需补齐。
- GlobalAdmin 发放/禁用已有事务、投影和 session revocation 路径，但“超管只是规则集来源，不是 PolicyEngine 旁路”以及全链审计需要持续门禁。

上述项目都属于[调整路线](#12-调整路线)中的未实现或待确认工作；本次没有代码修改。

## 9. 权威性矩阵

| 材料层级 | 代表文档/来源 | 可回答的问题 | 不可替代的内容 |
|----------|---------------|--------------|----------------|
| **工程规范/政策** | [Rust后端编码规范_V1.0.md](../../规范/Rust后端编码规范_V1.0.md)、[BACKEND_STANDARD.md](../../规范/Rust后端编码规范_V1.0.md)、[AGENTS.md](../../../AGENTS.md) | 工程分层、权限不变式、实施约束、测试和协作流程 | 不能替代当前源码行为或本目录的架构证据；架构材料也不能修改这些规范 |
| **非规范性架构/设计材料** | [物理双卡权限链路设计_V1.0.md](./物理双卡权限链路设计_V1.0.md)、[Rust架构模型设计修正记录.md](./Rust架构模型设计修正记录.md)、本总览 | 目标架构、双卡边界、已登记修正、路线和证据索引 | 不能伪造当前源码行为；目标决策不等同于已实现 |
| **当前源码** | `**` 对应实现及行号链接 | 当前实际调用链、数据来源、异常路径、owner 和默认 workspace 边界 | 不能单独决定目标语义；代码中遗留行为可能就是待修复缺口 |
| **Java 参考** | Java参考实现架构_V1.0.md、[Rust后端迁移架构决策_V1.0.md](../../迁移/Rust后端迁移架构决策_V1.0.md) | 迁移等价语义、历史接口和 owner 对照 | 不能覆盖 Rust v3 HMAC、Rust 双卡、Rust 双投影或当前 Rust 路由事实 |
| **JSA/历史** | [规则模式权限体系Merge语义规范_V1.0.md](../../规范/Rust后端编码规范_V1.0.md)、[规则模式权限体系代码实现详解.md](../../规范/Rust后端编码规范_V1.0.md)、历史迁移/设计资料 | 规则模型来源、形式化语义、事故背景和曾经的设计取舍 | 不能证明当前 Rust 已实现；与当前 Rust 语义冲突时仅作为历史背景 |

> 注意：上表最后一行的 Merge 语义文档实际路径是 `Docs/设计/权限模型/规则模式权限体系Merge语义规范_V1.0.md`；本目录所有链接均应指向该相对路径。

## 10. 三项架构决策

### AD-1：授权决策只能由 PolicyEngine.evaluate 产生

**决策**：Gateway 只认证和签发可信头；服务中间件只解析资源动作并构造 context；所有需要资源/动作授权的请求必须进入 `PolicyEngine::evaluate()`。任何 `isSuperAdmin()`、角色字符串、请求体 context、身份卡 fallback 或直接 `permission_rule` 查询都不能在引擎前形成 ALLOW。

**理由**：将身份事实、授权卡事实、规则集语义和故障降级集中到一个入口，避免同一变更在 Gateway、Controller、Service 和 raw SQL 各自产生不同放行口径。代码级入口见 [`check_permission`](../../../astral-common/src/middleware/permission_check_shared.rs#L284-L347) 和 [`PolicyEngine::evaluate`](../../../policy-engine/src/engine.rs#L191-L215)。

### AD-2：投影是授权读模型的 durable admission gate

**决策**：CARD、ELIGIBILITY、RULE_SET 的 legacy head/outbox 只保留为兼容写入、资格缓存失效或迁移对账边界；canonical 授权 source mutation 通过 grant revision + delta event 进入 `AuthorizationProjector`，由 manifest/segment/current durable CAS 发布。ELIGIBILITY 仍独立处理资格缓存。正式读侧只接受 published-evidence proof；版本不明、current/manifest/segment 缺失、worker 未完成或复检失败按 `AUTHORIZATION_PENDING`/DENY 处理。

**理由**：授权读模型可以暂时落后，但不能把未证明的旧 ALLOW 当成当前事实。canonical current pointer、manifest/segment seal、lineage、generation 和 revoke-fence proof 是正式 admission gate；旧 head、snapshot 或资格缓存不能替代它们。当前新链 projector、archive worker 与 strict reader 见 [`authorization_projector.rs`](../../../astral-trustgraph/src/service/authorization_projector.rs#L741-L847)、[`authorization_archive_worker.rs`](../../../astral-trustgraph/src/service/authorization_archive_worker.rs#L577-L735) 和 [`authorization_projection_repository.rs`](../../../astral-db/src/authorization_projection_repository.rs#L1-L44)。

### AD-3：委托与仲裁都是受限的证据路径，不是特权旁路

**决策**：委托 ALLOW 必须绑定当前 `user_card`、资源/动作、有效期和 caller scope；L2 依赖错误不得被委托遮蔽。Arbiter 只在投影 gate 可证明且版本可区分的冲突上工作；操作者 context 必须从可信 Gateway 头重建，跨节点 evidence 必须带来源、版本、时间和 replay/幂等约束；无法证明一律 DEFER=`AUTHORIZATION_PENDING`。

**理由**：委托和 Arbiter 都可能产生 ALLOW，若其输入不是经过同一双卡与版本证明的证据，便会成为绕过主授权链的替代入口。纯函数 Arbiter 的 deny-biased 语义见 [`policy-engine/src/arbiter.rs`](../../../policy-engine/src/arbiter.rs#L112-L219)；当前 API 输入边界见 [`astral-trustgraph/src/api/arbiter.rs`](../../../astral-trustgraph/src/api/arbiter.rs#L45-L125)。

## 11. 文档维护规则

- 本文只记录当前代码和已批准的 Rust 架构边界，不把路线项写成“已完成”。
- 源码行号变动后，应更新本总览和导航 README 的链接；行号只用于复核入口，不替代测试。
- 任何权限、卡片、投影、委托、GlobalAdmin 或审计变更，必须同步审查调用链、逻辑链、事故链、数据链和审计链。
- 本文及相关文档只使用仓库相对链接，不记录绝对文件 URL、服务器地址、密码、Token 或密钥。
- 本文及本目录其他架构材料均为**非规范性设计/证据材料**；工程规范、实施约束和验收入口只由 `Docs/规范/` 与仓库根目录 `AGENTS.md` 提供。

## 12. 调整路线

> 本节是路线与设计决策，不是实施报告。所有标记“未实现/待确认”的项目在本次会话中没有代码修改。

### 12.1 P0/P1 顺序总览

| 优先级 | 项目 | 当前状态 | 依赖 | 结果门 |
|--------|------|----------|------|--------|
| P0-1 | L2 error fail-closed | **已实现** | PolicyEngine decision contract | L2 读取错误不能进入可产生 ALLOW 的委托分支 |
| P0-2 | source_type owner whitelist | **未形成统一强制契约** | owner、允许值和迁移兼容值清单 | 非 owner 不能写对应 source_type；未知值拒绝 |
| P0-3 | delegation caller scope | **未实现为全入口可信证明** | 双卡 context、caller card 与目标 card 规则 | caller 只能创建/修改其 scope 内委托 |
| P0-4 | canonical authorization projection | **projector/archive/strict reader 已接线；backfill、切流与真实集成待验收** | grant ledger、delta event、manifest/segment/current、migration/rehearsal | 所有受影响 source mutation 形成 durable delta；current pointer proof 可回放，archive proof 先于完成 |
| P0-5 | version/evidence contract | **canonical chain 已接线；组合部署/故障场景仍需验收** | current/manifest/segment seal、lineage、generation、revoke-fence proof | 读、写、缓存、归档和审计均不以未证明旧 snapshot/head 放行 |
| P1-1 | production incremental compiler | **纯逻辑接口存在，生产接线未完成** | P0-4/P0-5 | 增量编译或安全全量回退可证明等价 |
| P1-2 | realtime boundary | **实时路径存在，生产边界待冻结** | P0-1/P0-5 | 只用于一致性/诊断，受限流、超时、审计和 raw-read policy 保护 |
| P1-3 | cache/timeout/lifecycle | **局部有实现，组合语义未统一验收** | P0-5 | Redis/DB/MQ/worker 故障、超时、重启和租约恢复均 deny-biased |
| P1-4 | Arbiter trust boundary | **内核已存在，控制面输入仍需收紧** | P0-1/P0-5 | context 来自可信头，evidence 可认证、可追溯、可防重放；不可证明即 DEFER |
| P1-5 | GlobalAdmin/audit closure | **核心事务存在，审计/特权门禁需补强** | P0-2/P0-4 | 超管只通过规则集，发放/禁用/撤销/投影 pending 全可追溯 |

### 12.2 P0-1：L2 error fail-closed

**当前事实**：对未声明 strict capability 的 legacy/test repository，`PolicyEngine::evaluate()` 在旧 L2 `load_permission_rules` 失败时立即返回 `DEPENDENCY_UNAVAILABLE`，不进入旧 L2.5；只有旧 L2 明确 `NoMatch` 才能继续。旧 L2.5 调用 `load_projected_delegated_rules`，要求 CARD generation-gated projected rows；raw/source readers 只供 realtime/一致性巡检。生产 `SqlxRuleRepository` 声明 strict capability，正式授权直接走 published-evidence gate，不经过旧 L2/L2.5。证据见 [`engine.rs`](../../../policy-engine/src/engine.rs#L554-L636) 和 [`repository.rs`](../../../astral-db/src/repository.rs#L776-L895)。

**当前实现**：legacy 路径的旧 L2 repository error 已在旧 L2.5 前返回 `DEPENDENCY_UNAVAILABLE`；旧 L2.5 只读取 generation-gated projected delegation，不能用 raw/source reader 遮蔽 L2 故障。生产正式授权由 strict published-evidence gate 承担；空快照与 repository error 保持区分，realtime 仍不是授权 fallback。

**状态与验收**：**核心行为已实现，仍需组合故障与部署验收**。持续验证 L2 失败加有效委托必为 DENY/PENDING、委托投影缺失或 source/projection 不一致不产生 ALLOW，并同步核对断路器计数、审计 reason 和 HTTP 映射。

### 12.3 P0-2：source_type owner whitelist

**当前事实**：通用规则写入的旧 `service_ext.rs`/`PermissionRuleService` owner 已移除；当前 `permission_rule` 写入由 TrustGraph rule/delegation owner 负责，`source_type='MANUAL'`/`'DELEGATION'` 仍需按 owner 约束。规则集使用 `rule_set`/`rule_set_entry`/`rule_set_snapshot` 与 RULE_SET projection，见 [`rule_set_repository.rs`](../../../astral-trustgraph/src/repository/rule_set_repository.rs#L441-L623)。当前仍没有所有 owner 共享的强制 source whitelist。

**路线**：冻结最小 source matrix：`MANUAL` 只由 TrustGraph rule write owner 生成 CARD_ONLY 特例；`DELEGATION` 只由 delegation owner 生成被委托卡规则；模板权限只走 `rule_set/rule_set_entry/rule_set_snapshot`；未知或空值无 owner、无读取放行。以 typed enum/validated constructor 或单一 helper 收口，禁止 DTO 任意传入 source_type。

**状态与验收**：**未形成统一强制契约**。未知 source、owner 不匹配、source_id 缺失/不匹配必须在事务提交前拒绝；兼容值只能列入显式迁移清单。

### 12.4 P0-3：delegation caller scope

**当前事实**：委托请求体有 `delegator_id`/`delegate_id`，但 API 当前主要把请求转给 service；路由见 [`delegation.rs`](../../../astral-trustgraph/src/api/delegation.rs#L75-L114) 和 [`#L292-L357`](../../../astral-trustgraph/src/api/delegation.rs#L292-L357)。service/repository 已有幂等、委托规则和 projection 生命周期，见 [`delegation_service.rs`](../../../astral-trustgraph/src/service/delegation_service.rs#L39-L155) 与 [`delegation_repository.rs`](../../../astral-trustgraph/src/repository/delegation_repository.rs#L115-L230)，但这不能证明 HTTP caller 有权操作指定 delegator card。

**路线**：从可信 Gateway 头构建操作者 `PolicyContext`；创建前证明 caller 双卡、caller card ACTIVE 和 delegation resource/action 管理权限；将 caller card 与 `delegator_card_id` 显式绑定；update/revoke 先读真实 delegation row 再做 caller scope 检查；审计 caller、caller card、delegator/delegate、resource/action 和结果。

**状态与验收**：**未实现为全入口可信证明**。修改请求体 delegator、越租户目标卡、过期/撤销卡或无动作权限均拒绝；并发 create/revoke/update 不复活 DELEGATION ALLOW。

### 12.5 P0-4：canonical authorization projection

**当前事实**：规则集、卡级规则、审批和委托等 source mutation 已由 `grant_ledger_adapter` 组装为 typed grant revision，并在 source transaction 内追加 `authorization_delta_event`。`AuthorizationProjector` 是新 delta 队列的唯一授权投影消费者：事务外调用 `AuthorizationCompiler`，发布事务内验证 lease、lineage、revoke fence、generation、segment seal 和 current-pointer CAS；`AuthorizationArchiveWorker` 对被替代 manifest 执行 proof-before-complete。旧 `ProjectionWorker` 对 CARD/RULE_SET 事件只做 writer-correlation 终态收口，ELIGIBILITY 分支仍只负责资格缓存失效，不再重建旧 snapshot 或推进旧 READY。证据见 [`grant_ledger_adapter.rs`](../../../astral-trustgraph/src/repository/grant_ledger_adapter.rs#L1-L25)、[`authorization_projector.rs`](../../../astral-trustgraph/src/service/authorization_projector.rs#L741-L847)、[`authorization_archive_worker.rs`](../../../astral-trustgraph/src/service/authorization_archive_worker.rs#L577-L735)。

**迁移/回填**：`20260825000002_incremental_projection_archive.sql` 仅创建 canonical grant/delta/manifest/segment/current/archive 表链；`20260827000001_authorization_projection_lineage_fence.sql` 增加 lineage 与 revoke-fence proof；旧 snapshot 修复 migration 和 `20260827000002_legacy_snapshot_tables_decommission.sql` 仍属于 legacy/迁移材料。上述文件存在不代表目标库已应用、既有账本已 backfill/rehearsal、旧表已 DROP 或正式流量已切换。

**状态与验收**：**新链 projector/archive/strict reader 已接线；backfill、缓存/摘要迁移、真实 MySQL/Redis/RabbitMQ 集成和正式切流未完成**。canonical current/manifest/segment proof 不足、lease/CAS 未知或 archive proof 未完成时只能 PENDING/DENY、Blocked/Quarantine/Unknown；不得用旧 snapshot/head 或 typed/shape 测试宣布生产授权完成。

### 12.6 P0-5：version/evidence contract

**当前事实**：canonical 生产证据由 `authorization_projection_current`、manifest/segment seal、parent lineage、generation、semantic/dependency hash 和 `revoke_fence_proven` 联合证明；`AuthorizationProjector` 的 lease/token fence、CAS 和 archive proof 形成写侧完成边界。旧 CARD/RULE_SET head 的 `source_generation`、`projected_generation`、`projection_status`、旧 `READY`、`ProjectionAdvance` 和 snapshot `version_no` 仅保留在 legacy/test/迁移对账语境，不能作为生产授权完成证明。

**持续验收**：继续核对 `event_id`/`message_id`/`operation_id` 的生产者、消费者、单调性、重放、旧代、current 缺失、证明闩未置位、manifest/segment 失配、scope/lineage/fence 不一致和 stale ALLOW 语义；自然 wall-clock RuleSet `valid_to` 仍无独立 expiry scheduler/event。
**状态与验收**：**核心契约已接线；组合部署/故障场景仍需验收**。迁移未完成、schema 不符、worker 失败、audit evidence 缺失或 gate 不一致时保持 PENDING/DENY。

### 12.7 P1-1：生产 incremental compiler

**当前事实**：`AuthorizationCompiler` 已替代已删除的旧数组索引编译器，提供稳定 `GrantId`/`GrantRevision`、base version、semantic/dependency hash 和显式 `FullRebuildReason`。生产 projector 在事务外调用该内核，在发布事务内通过 `authorization_projection_current` 完成 pointer/manifest/segment 的 durable CAS；旧快照 SQL 重建只保留在 legacy/兼容源码与退役材料中，不是新链的 full-rebuild 实现。证据见 [`authorization_compiler.rs`](../../../policy-engine/src/authorization_compiler.rs#L1-L72)、[`authorization_projector.rs`](../../../astral-trustgraph/src/service/authorization_projector.rs#L1598-L1759) 和 [`authorization_projection_repository.rs`](../../../astral-db/src/authorization_projection_repository.rs#L1-L44)。

**路线**：继续完成既有授权数据的 backfill/rehearsal、缓存/摘要读侧迁移和真实基础设施切流；wildcard、动作别名、绑定影响、版本/依赖漂移和 CAS 冲突必须保持显式 full-rebuild/quarantine 或有界重试，不得通过旧 snapshot/raw source 旁路放行。

**状态与验收**：**新编译内核、projector 与 archive worker 已接线；生产切流和集成验收未完成**。typed/shape 测试不能替代真实 MySQL/Redis/RabbitMQ 与部署验收。

### 12.8 P1-2：realtime boundary

**当前事实**：`evaluate_realtime()` 绕过快照/缓存读 raw source，用于一致性检查，见 [`engine.rs`](../../../policy-engine/src/engine.rs#L664-L710)；`SnapshotConsistencyChecker` 采样调用，见 [`consistency.rs`](../../../policy-engine/src/consistency.rs#L43-L82)。

**路线**：将 realtime 标为 `diagnostic/consistency-only`；限制 raw read 的 owner、采样预算、DB timeout、结果行数、并发和速率；结果必须携带 source timestamp/version，不能生成没有 projection gate 的生产 ALLOW；冲突信号记录 decision、gate 和 context hash。

**状态与验收**：**路径已存在，生产边界未完全冻结**。生产 `check_permission` 不因 realtime 失败而放行；超时/DB 故障/结果过大 deny/defer；sampling 与 Arbiter 不递归或无限重试。

### 12.9 P1-3：cache/timeout/lifecycle

**当前事实**：Gateway Redis check 和 ELIGIBILITY 资格缓存均在依赖失败时 fail-closed；生产权限 evidence cache 只缓存已验证的 current/manifest/segment 证据，失配或 Redis 故障回 strict reader，不回旧 snapshot。`AuthorizationProjector` 已有事件级 deadline、bounded attempt、lease/token fence、pointer-moved replan、Blocked/Quarantine/Unknown；`AuthorizationArchiveWorker` 已有 cancellation、过期 lease recovery、proof-before-complete 和 bounded join，TrustGraph `main` 持有并逆序关闭相关 worker。组合生命周期的真实基础设施验收仍未完成。
**路线**：统一 DB/Redis/MQ/HTTP/worker timeout budget 和 reason code；区分 cache read/write failure、stale payload、old scalar、reconnect；明确启动、关闭、lease 接管、MQ 重连、重复 publish/mark 的幂等；补足 tenant/domain fan-out、identity expiry/status mutation 和 user-card validity API；监控 pending age、retry、generation lag、cache miss、audit fallback 和 circuit state。

**状态与验收**：**部分实现，组合生命周期验收未完成**。依赖故障无 stale ALLOW；worker 重启可接管 lease；publish 成功而 mark 失败可安全重放；已提交 source mutation 不因 shutdown 丢失 outbox。

### 12.10 P1-4：Arbiter trust boundary

**当前事实**：PolicyEngine Arbiter 是无 IO 纯函数，按 source/fence 版本序裁决，最新 DENY 优先，不可证明时 DEFER，见 [`policy-engine/src/arbiter.rs`](../../../policy-engine/src/arbiter.rs#L1-L15) 和 [`#L160-L219`](../../../policy-engine/src/arbiter.rs#L160-L219)。TrustGraph service 挂接冲突 sink 并写审计，见 [`service/arbiter.rs`](../../../astral-trustgraph/src/service/arbiter.rs#L54-L124)。当前 API 直接接收请求体 `PolicyContext`/evidence，见 [`api/arbiter.rs`](../../../astral-trustgraph/src/api/arbiter.rs#L34-L125)。

**路线**：handler 内从可信 Gateway 头重建操作者 context；evidence 必须包含可信 node identity、source/projected/fence、snapshot version、observed time、event/message id 和 idempotency key；只接收已登记节点和允许 schema；只在 READY 且版本可区分分歧时裁决；DEFER 强制映射 PENDING/拒绝，caller 不能自转 ALLOW。

**状态与验收**：**内核已实现，控制面信任边界未完成**。修改请求体 context 不扩大权限；伪造节点、旧代或跨卡 evidence 被拒绝/DEFER；replay 幂等；Arbiter ALLOW 可追溯到 caller、evidence 和 projection contract。问题登记见[模型修正记录问题5](./Rust架构模型设计修正记录.md#问题-5--arbiter-端点接受请求体-ctx-无双卡复验r3)。

### 12.11 P1-5：GlobalAdmin/audit closure

**当前事实**：GlobalAdmin API 从 Gateway `x-user-id` 提取 caller，并由 permission middleware 处理资源权限，见 [`global_admin.rs`](../../../astral-trustgraph/src/api/global_admin.rs#L85-L103)。授予事务包含管理员行、SUPER_ADMIN 用户卡、`__SUPERADMIN__` BASE binding 和 CARD/ELIGIBILITY event，见 [`global_admin_repository.rs`](../../../astral-trustgraph/src/repository/global_admin_repository.rs#L189-L377)；禁用路径保护最后一个管理员并触发撤销，见 [`#L380-L429`](../../../astral-trustgraph/src/repository/global_admin_repository.rs#L380-L429)。

**路线**：保持超管权限唯一来自 `__SUPERADMIN__` rule set -> PolicyEngine；caller scope 复用 P0-3 的可信双卡 context；grant/enable/disable、last-admin protection、projection/session revocation pending、retry/exhaustion 全部结构化审计；补 MQ-first/DB-fallback、audit replay、撤销 pending 和投影 pending 的最终追溯检查。

**状态与验收**：**核心事务和投影已有实现，全链审计/调用者 scope 门禁仍需补齐**。不得将超管写成 token/menu/前端/API handler 的全量放行。

### 12.12 实施阶段

```text
P0-1 L2 fail-closed
       |
P0-2 source_type owner whitelist ----+
       |                              |
P0-3 delegation caller scope --------+--> P0-4 canonical authorization projection
                                      |          |
                                      +--------> P0-5 version/evidence contract
                                                   |
                 +---------------------------------+---------------------+
                 |                                 |                     |
       P1-1 production incremental       P1-2 realtime boundary   P1-3 cache/timeout/lifecycle
                 |                                 |                     |
                 +---------------------------------+---------------------+
                                                   |
                                      P1-4 Arbiter trust boundary
                                                   |
                                      P1-5 GlobalAdmin/audit closure
```

- **Phase A：错误放行收敛**：完成 P0-1/P0-2/P0-3；覆盖 delegation create/update/revoke/list 的 caller scope；不新增 raw source authorization 或特权旁路。
- **Phase B：durable projection 与版本冻结**：完成 P0-4/P0-5；将所有写路径、补偿、cache、MQ consumer、decision evidence、audit、Arbiter 接到同一 contract。
- **Phase C：生产性能与实时边界**：在 Phase B 稳定后完成 P1-1/P1-2/P1-3；增量编译必须有等价 oracle，realtime 必须诊断隔离，生命周期必须有重启/租约/replay 测试。
- **Phase D：仲裁与治理闭环**：完成 P1-4/P1-5；通过跨节点 evidence、撤销 fence、投影 lag、委托撤销和审计降级联合验收后，才可宣称 Rust 访问控制闭环。

### 12.13 路线五链审查矩阵

每个实施 PR 必须记录调用链、逻辑链、事故链、数据链、审计链：

| 项目 | 调用链 | 逻辑/事故链 | 数据链 | 审计链 |
|------|--------|-------------|--------|--------|
| P0-1 | `evaluate` caller、HTTP reason | L2 error 不进 delegation；timeout/CB open -> DENY/PENDING | permission snapshot 与 raw read 分离 | reason/message id 定位失败阶段 |
| P0-2/P0-3 | rule/delegation owner 到 repository | source/caller scope 不可由请求体扩大 | source_id、双卡、tenant、委托 row 和规则一致 | owner、actor、create/update/revoke 可追溯 |
| P0-4/P0-5 | source mutation -> grant revision + delta event -> projector -> reader（旧 head/outbox 仅 writer-correlation） | current/manifest/segment 缺失、跳代、fence 未证明 -> PENDING/DENY | delta/manifest/segment/current/audit 同代；旧 head/outbox 单独对账 | event/message/retry/archive proof 可回放 |
| P1-1/P1-2 | compiler/realtime 到 read port | unknown impact/timeout -> full rebuild/defer | source version 与 snapshot version 可比较 | compiler、sampling、冲突和 context hash 可追踪 |
| P1-3/P1-4/P1-5 | lifecycle/API caller -> context -> audit | 依赖故障、evidence 不可证明、撤销 pending 均不放行 | TTL、fence、caller/evidence/projection 一致 | GlobalAdmin/Arbiter、fallback、replay 全链闭环 |

## 13. 路线验证门与证据边界

实施每一阶段时，最低验证集沿用仓库 CI：

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --lib
cargo test --workspace --test '*' -- --ignored --test-threads=1
```

真实 MySQL/Redis/RabbitMQ 集成和 replay 必须走 [`.github/workflows/ci.yml`](../../README.md#L136-L361) 的服务容器路径。以上是验收命令和 CI 定义，不是本次会话已执行或已通过的结果；默认 workspace 不包含 `astral-learn`/`astral-chat`，解冻前不能声称它们通过全工作区验证。纯函数、mock repository、benchmark 和历史报告只能证明局部逻辑或方法存在，不能证明生产 source mutation、跨节点 evidence、生命周期故障和审计降级闭环。

## 14. 未实现项清单

以下项目在本文版本中明确保持为未实现或待确认，不能在 PR、发布说明或运行手册中写成已完成：

- [x] L2 repository error 在委托前强制 fail-closed（组合故障与部署验收仍需持续）；
- [ ] source_type owner whitelist 及未知值拒绝契约；
- [ ] delegation caller scope 的所有入口复验；
- [x] RULE_SET durable projection 的统一聚合/版本契约和全 source mutation 清单（迁移/backfill/replay 仍需发布验收）；
- [x] `snapshot_version` 与 head generation/fence 的统一 wire/evidence contract（snapshot validity columns/read-time filtering 已接入部分读路径；wall-clock expiry scheduler/event 仍未实现）；
- [ ] 生产增量 compiler 接线、等价 oracle 和安全回退；
- [ ] realtime 诊断边界、限流、timeout、raw-read 和审计约束；
- [ ] Redis/DB/MQ/worker cache、timeout、lease、shutdown、replay 全组合验收；
- [ ] Arbiter caller context、节点 evidence provenance、签名/重放/幂等和 DEFER 强制出口；
- [ ] GlobalAdmin caller scope 与全链审计/补偿 replay 闭环；
- [ ] tenant/domain status fan-out、identity expiry/status source mutation、user-card validity API 等生命周期补齐，参见 [V5 迁移路线](./V5模型修正筹划_专供Rust_V1.0.md#五迁移路径v4--v5专供-rust)。

2026-08-26 增补（canonical 模型“版本化热状态 + 异步归档”切片；已实现项同样列出以免被误写为待办）：

- [x] 新 Rust-owned 表链 creator-only 迁移（`20260825000002`/`20260827000001`，含 lineage 列与 revoke fence 列、0 哨兵 fail-closed 合同）；
- [x] ALLOW-only typed grant 合同（普通 DENY 不持久化为 grant；BASE/OVERLAY 为 RULE_SET 贡献标签，DELEGATION 恒 layer=None）；
- [x] 无 IO `AuthorizationCompiler` 内核 + full-rebuild oracle + compiler version（热状态当前版本可变，111→112 仅为测试示例）；
- [x] TrustGraph projector（新 delta 队列唯一消费者）与异步 archive worker（DB 内归档证明，proof 先于 ACK）接线；
- [x] 严格 published-evidence 读门（缺 current 指针 ⇒ NotReady，无 empty-ALLOW，无旧快照/raw/cache 回退），生产 `SqlxRuleRepository` capability marker 门控接入正式 `evaluate()`；`evaluate_realtime()` 与 L1/L2/L2.5 union 不消费该端口；
- [ ] `evaluate_realtime()` 切换到 published evidence（当前仍仅作一致性/oracle 路径，不消费该端口）；
- [x] 新授权账本的 direct/approval/delegation/rule-set typed 贡献接线（`grant_ledger_adapter` 在 source transaction 内追加 revision + delta event，projector 按 aggregate 消费新 delta 队列，不限于 RULE_SET 源；typed 测试覆盖，真实集成与切流验收仍为待办）；
- [ ] 既有授权数据到新表链的 backfill/rehearsal（迁移 creator-only，0 哨兵要求显式回填，未实现）；
- [ ] 缓存与权限摘要读侧迁移到 published evidence；
- [ ] 真实 MySQL/Redis/RabbitMQ 集成与部署验收。

本文件只新增文档，不表示代码已改变、测试已运行、提交已创建或推送已发生。
