# Rust 访问控制总览与调整路线 V1.0

> 版本：V1.0
> 原始版本日期：2026-09-09；CURRENT V6 现状补记：2026-10-28
> 适用：`AstralLight-Rust` workspace 的 Gateway、Identity、TrustGraph、PolicyEngine、数据库投影、进程内缓存、消息与审计链路。
> 文档性质：**非规范性架构设计/证据材料**。本文记录当前事实、缺口和目标决策，不替代 [Docs/规范/](../../规范/) 或仓库根目录 [AGENTS.md](../../../AGENTS.md)。
> 说明：本文不表示本次会话修改了 Rust 代码。原 §12–14 的调整路线、状态和验收清单是 2026-09-09 历史快照，已被 CURRENT V6 现状取代，仅供历史追溯。

## 1. 阅读边界

本文把四种材料分开：

- **当前源码**：判断运行时行为的第一证据，引用仓库相对路径和行号。
- **工程规范**：规定 Rust 应遵守的 crate 边界、双卡不变式、投影/错误/测试门和实施流程；权威来源是 `Docs/规范/` 与仓库根目录 `AGENTS.md`。
- **架构材料**：记录当前事实、证据、缺口和目标决策；本目录材料是非规范性的，不能把目标态写成已实现，也不能替代工程规范。
- **Java 参考**：用于迁移语义对照，不覆盖 Rust 当前事实。
- **JSA/历史材料**：解释规则模型的来源和演进，不作为当前 Rust 已实现能力的证明。
- **跨专题技术分析与运行测量**：[技术专题解析与架构取舍（2026-10-25）](../../技术专题解析与架构取舍_2026-10-25.md)区分迁移决策、当前实现与候选方案；[授权执行期能力曲线（2026-10-25）](../../实验/基准测试/授权执行期能力曲线_20261025.md)只说明本机 fixture 下的完整 `PolicyEngine::evaluate()` CPU 测量，不替代本文引用的授权源码、迁移或集成证据。

当前 workspace 明确 exclude `astral-learn` 与 `astral-chat`；它们的源码仍在仓库中，但不参加默认 workspace 编译和测试。依据见 [`Cargo.toml`](../../../Cargo.toml#L1-L15)。因此，本文对 Learn/Chat 的实现描述必须注明“源码存在、默认验证边界之外”。

## 2. 当前结论（CURRENT V6）

1. **认证事实由 Gateway/Identity 共同形成**：Gateway 清洗客户端身份头、校验 JWT 与 MySQL durable session/JTI/replay facts，并以 HMAC v3 将可信身份上下文交给下游。可选 session mirror 仅为有界进程内适配；不再有当前 Redis session compatibility adapter。strict DB 读取失败按 fail-closed 处理。
2. **双卡不是两套授权系统**：`identity_card` 只证明身份/会话事实；`user_card` 承载授权和组织事实。PlatformUser 进入完整双卡路径，AppUser 只有 identity-only context，不能用身份卡回退成用户卡授权。
3. **正式授权唯一入口是 `PolicyEngine::evaluate()`**：服务中间件先解析 `(resource, action)`、构造可信 `PolicyContext` 并验证目标 ownership。`RuleRepository` 仅有四个无默认实现的 required read ports：`check_card_active`、`is_active_global_admin`、`load_published_card_authorization`、`load_org_authorization`。不存在 capability-marker dispatch、可选 legacy evaluator、L1/L2/L2.5 阶段、`evaluate_realtime()` raw-source 授权或 fallback。
4. **CURRENT V6 是完整、不可拆分的授权 bundle**：compiler/admission/read gates、publication、segments、archive/completion、invalidation、snapshot 与 wire contracts 一致切换。普通卡授权只接受严格 published evidence；缺失/错误/冲突/过期或最终复读不稳定一律 PENDING/DENY。V6 仅为 authorization edition，不重编号通用 MQ schema、JWT versions 或 HTTP `/v1`。
5. **投影唯一执行协议为 `WorkerOwned`**：只有 source COMMIT 被证明成功，才将完整不可变 receipt batch 交付唯一 worker；请求侧只允许对完整 batch 做只读 exact-completion wait（5 秒、25 ms poll、最多 64 events 和 50 distinct card scopes），不得截断、claim、compile、publish、release 或竞争 worker。超时不证明完成。保留的 head/outbox 仅用于 source correlation、revoke/RuleSet initialization correlation 与 ELIGIBILITY invalidation，不是 canonical publication proof。`TenantSerial`/`Partitioned` topology defaults 与 ORG_SCOPE default-off 保持不变。
6. **权限投影、缓存与账户合同均 fail-closed**：当前 evidence cache 仅为有界进程内 L1（TTL、capacity、GC），失配只回 strict DB reader 或 PENDING/DENY，不等价 Redis 跨实例行为；Redis L2/MAC/shared-unit/session compatibility 与 `astral-cache` 已退出当前软件合同。密码验证仅 Argon2id，旧 BCrypt/MD5 credential 要求显式 reset；JWT v2 `roles` 只接受 string array，legacy scalar/null reject，`permissions` 不是授权输入。enabled `MANUAL` direct create/update 在 source transaction 内强制执行 published-only SoD gate，CREATE 另保留 early validator；UPDATE 证明 exact locked before-image 与 source/card tenant、user/domain 后，只能从 STATIC held grants 排除唯一 self `GrantId`。其余 grant、DYNAMIC 检查、pending contribution、strict evidence 与有界 ACTIVE policy 读取门保留，完整合同见 [Rust 规范 §15.4](../../规范/Rust后端编码规范_V1.0.md#154-单机内存读写生命周期sod-与审计边界)。此交易内并发语义**未在真实 MySQL 上验证**。

上述为代码级合同，不代表 migration、backfill/rehearsal、真实 DB/MQ integration 或正式切流已完成；旧路线快照见[历史调整路线](#12-调整路线)。

## 3. 端到端调用链

### 3.1 总链路

```text
客户端请求
  -> Gateway 清洗客户端身份头
  -> route_credential_policy + JWT v2 校验
  -> strict MySQL session/JTI/family/card facts（可选 bounded local mirror 仅依明示策略加速）
  -> 注入可信双卡身份头
  -> Gateway HMAC v3 转发
  -> 下游 gateway_signature 验签
  -> 服务 path/resource/action 映射 + ResourceRegistry 校验
  -> physical_policy_context 构建双卡 actor context
  -> 服务专属 resource-owner resolver 解析/验证目标归属；失败时 PENDING/DENY
  -> PolicyEngine.evaluate()
       -> AUTHN / CARD_CONTEXT
       -> resource/action + ownership 校验
       -> GlobalAdmin fresh proof（适用时）与 ORG_SCOPE admission（若当前启用）
       -> CURRENT V6 published-evidence strict gate
            current pointer + manifest/segment seal + lineage/generation/fence proof
       -> ALLOW-only effective_grants matcher
       -> DEFAULT_DENY
  -> 允许时进入业务 handler
  -> 权限审计（MQ-first / DB-fallback / tracing）
```

Gateway route/middleware 与下游 HMAC v3 验签的源码位置见 [`astral-gateway/src/middleware.rs`](../../../astral-gateway/src/middleware.rs)、[`astral-common/src/middleware/gateway_signature.rs`](../../../astral-common/src/middleware/gateway_signature.rs)；strict session facts 由 [`astral-db/src/session_state_repository.rs`](../../../astral-db/src/session_state_repository.rs) 提供。实现位置只作复核入口，不证明真实部署验收。

### 3.2 L0：Identity 签发与 SessionGrant（CURRENT V6）

Identity login 先读取 ACTIVE 身份聚合、选择用户卡，然后调用 `CardEligibilityService::verify_platform_card_pair`。该调用证明：

- `identity_card` 属于当前用户、ACTIVE 且未过期；
- `user_card` 属于当前用户、ACTIVE、在有效时间窗内，且不是模板卡；
- 两张卡通过同一 `platform_user`/`user_id` 对齐；
- user-card 的 `tenant/domain` 非空，租户和域映射有效。

login 的调用点见 [`astral-identity/src/srv/auth_service.rs`](../../../astral-identity/src/srv/auth_service.rs#L205-L289)。统一资格服务及权威 JOIN 见 [`astral-db/src/eligibility.rs`](../../../astral-db/src/eligibility.rs#L74-L154) 和 [`#L235-L277`](../../../astral-db/src/eligibility.rs#L235-L277)。refresh/switch-card 也复用同一资格服务，事实与目标边界见[物理双卡权限链路评估与设计 §2.1](./物理双卡权限链路评估与设计_V1.0.md#21-当前链路rust-双卡分离后)。

会话/JTI/replay 的 durable source 是 MySQL strict session facts；运行时可以配置有界进程内镜像加速，但镜像 miss、过期、suspect 或 unavailable 只回 strict DB 读取或拒绝，不宣称跨实例共享语义。历史 `access:jti`/`access:grant` Redis 投影属于已退役兼容设计，不是当前 V6 adapter 或 session contract。会话状态是 Gateway 认证输入，不是权限规则或 `PolicyEngine` 授权。

### 3.3 L1：Gateway 认证、会话和可信头

Gateway 运行时的实际顺序是：

1. `sanitize_internal_auth_headers` 移除客户端可能伪造的身份、权限、网关和内部服务头。
2. `jwt_auth_middleware` 依据路由凭证策略校验 Access/Refresh/Public 语义，拒绝错误 token purpose。
3. Access token 依据 strict MySQL session/JTI/family/card facts 校验；可选的 bounded in-process mirror 只按已证明策略加速，miss/suspect/expiry 回 strict DB；tenant status 也走 strict owner proof。Redis session compatibility path 已退休。
4. Gateway 从 JWT claims 注入 `x-user-id`、`x-identity-card-id`、`x-user-card-id`、`x-user-card-tenant-id`、`x-user-card-domain-id`、principal/token/claims headers。
5. Proxy 以 HMAC v3 签名外部路径和身份字段；下游只信任验签通过的头。

Gateway 的路由凭证策略类型和会话检查在 [`middleware.rs`](../../../astral-gateway/src/middleware.rs)，strict MySQL session facts 由 [`astral-db/src/session_state_repository.rs`](../../../astral-db/src/session_state_repository.rs) 提供；下游验签在 [`gateway_signature.rs`](../../../astral-common/src/middleware/gateway_signature.rs)。实现代码级观察不代替真实部署验收。

**当前边界**：Gateway 负责认证、撤销和可信头，不代替下游 PolicyEngine 做资源动作授权。Gateway 路径层的 principal 守卫仍属于纵深加固路线；当前 AppUser 对需要用户卡的授权路径依赖下游 `CARD_REQUIRED`，见[物理双卡权限链路评估与设计 §3.3 D2](./物理双卡权限链路评估与设计_V1.0.md#L257)。

### 3.4 L2：下游可信头、资源注册和 PolicyContext

下游权限中间件不接受请求体或客户端自报的身份上下文。`physical_policy_context` 从 Gateway 验签后的头读取：

- `user_id`、principal kind、`identity_card_id` 缺失或非正数，返回未认证；
- PlatformUser 缺少任一用户卡 ID/tenant/domain，返回拒绝；
- AppUser 构造 identity-only context，`card_id/tenant_id/domain_id` 为空，进入要求用户卡的引擎路径时由 `CARD_REQUIRED` 拒绝。

实现见 [`physical_policy_context`](../../../astral-common/src/middleware/permission_check_shared.rs#L55-L118)。

请求路径由各服务中间件按各自 path map 解析资源类型和动作，先通过服务专属 owner resolver 建立目标所有权，再调用 `engine.evaluate(&ctx, repo)`。公开 helper `astral_common::middleware::permission_check_shared::check_permission` 保留为兼容入口：它提交 `Unresolved` 目标上下文，不能授权受保护资源，也不能替代服务专属 owner resolver；生产路径必须在评估前解析目标 owner。另一个公开兼容 helper `astral_common::middleware::permission::require_permission` 仍保留；它同样不能替代 owner resolver，且当前仓内没有调用方，不得作为生产授权入口。共享解析与双卡上下文 helper 仍由各服务中间件复用。

`ResourceRegistry` 是 `astral-types` 的集中注册表，提供资源/动作/条件校验；启动期 `validate_path_map` 交叉检查 path map 是否引用未注册资源，但当前检查记录错误并继续启动，不能当作强制启动失败门禁。注册表和校验见 [`registry.rs`](../../../astral-types/src/registry.rs#L113-L144) 与 [`#L319-L383`](../../../astral-types/src/registry.rs#L319-L383)。

### 3.5 L3：PolicyEngine.evaluate 与 CURRENT V6 strict published-evidence gate

CURRENT V6 正式 `PolicyEngine::evaluate()` 只有一条授权顺序：

```text
断路器 OPEN -> DENY
  -> AUTHN / CARD_CONTEXT
  -> target ownership 与 resource/action 校验
  -> GlobalAdmin fresh proof（适用时）
  -> ORG_SCOPE admission（受当前 default-off 状态约束）
  -> CURRENT V6 published-evidence strict gate
       current pointer + manifest/segment seal + generation/lineage/revoke-fence proof
       缺失/未证明/错误/scope 不符 -> AUTHORIZATION_PENDING 或 DENY
       有效 ALLOW 前复读证据；GlobalAdmin 适用时再复读其 proof
  -> 无命中 -> DEFAULT_DENY
```

`RuleRepository` 只有四个无默认实现的 required ports：`check_card_active`、`is_active_global_admin`、`load_published_card_authorization`、`load_org_authorization`。接口定义见 [`ports.rs`](../../../policy-engine/src/engine/ports.rs)，执行顺序见 [`formal.rs`](../../../policy-engine/src/engine/formal.rs)，published-card gate 见 [`published.rs`](../../../policy-engine/src/engine/published.rs)，production SQLx reader 在 [`authorization.rs`](../../../astral-db/src/repository/authorization.rs)。正式授权不存在 capability marker、可选 legacy dispatch、旧 L1/L2/L2.5 evaluator、`evaluate_realtime()` raw-source 路径或 source/snapshot/cache fallback。legacy staged evaluator 只可作为明确标注的历史材料，不是当前 test/compatibility API。

### 3.6 L4：审计

授权中间件通过 `record_permission_audit` 记录决策、resource、action、card、租户域、reason 和路径。MQ 可用时先发审计消息；MQ 未就绪或失败时走 DB fallback，DB fallback 共执行两次尝试（首次写入 + 一次重试），最终保留结构化 `audit_log` tracing。实现见 [`astral-common/src/audit.rs`](../../../astral-common/src/audit.rs#L88-L163) 的 [`for attempt in 1..=2`](../../../astral-common/src/audit.rs#L141-L161) 和 [`record_permission_audit`](../../../astral-common/src/audit.rs#L302-L367)。

当前审计是**授权决策后的异步/旁路记录**，不改变 ALLOW/DENY；因此审计写入失败不应反向放宽授权，但审计链仍需关注 message id 幂等、重试与最终可追溯性。GlobalAdmin 审计的当前调用链应按对应源码复核；旧 Arbiter 审计边界仅见已退役的 P1-4 历史路线，不构成 CURRENT V6 runtime feature。

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

### 4.2 canonical 授权投影与保留 head/outbox 责任

CURRENT V6 canonical 授权 source mutation 通过 grant revision + typed delta event 进入唯一 `WorkerOwned` projector，由其发布 manifest/segment/current，并由 archive worker 对 superseded manifest 做 proof-before-complete。完整调用/等待合同见[增量重建与实时授权边界](./Rust增量重建与实时授权边界_V1.0.md)。

保留的 head/outbox 只承担已登记的 source correlation、revoke/RuleSet initialization correlation 和 ELIGIBILITY invalidation；其状态不构成 canonical publication proof。旧 `permission_rule_snapshot` / `rule_set_snapshot` 读写、CARD/RULE_SET READY 推进和旧 refresh 链只作为明确标注的历史/迁移证据，不是当前授权或兼容 evaluator。

ELIGIBILITY 是独立的物理资格缓存失效语义，不等同卡规则授权 evidence。资格读侧以双卡上下文和独立 authority checks 为准；其 default/readiness 行为不因 CURRENT V6 改变。聚合类型和事件历史材料可见 [`astral-types/src/projection.rs`](../../../astral-types/src/projection.rs)，source/worker 当前细节以对应实现为准。

### 4.3 版本和缓存契约

CURRENT V6 canonical 读门由 current pointer、manifest/segment seal、generation、lineage 与 `revoke_fence_proven` 联合证明。保留的 source head/outbox 不作发布证明，只用于 source correlation、revoke/RuleSet initialization correlation 与 ELIGIBILITY invalidation；旧 snapshot/head 状态仅作历史/迁移证据。

正式 evidence L1 为有界进程内缓存，绑定完整 scope、CURRENT V6 stamp、generation/dependency/fence 与 content integrity，并有 TTL、capacity、GC；失配或异常回 strict DB reader 或 PENDING/DENY。物理资格 L1 与规则授权 evidence 分离，按 ELIGIBILITY 物理上下文和 source-generation/revoke-fence 栅栏服务；它不是授权 proof。Redis L2/MAC/shared-unit、Redis session compatibility 与 `astral-cache` 已退出当前软件合同，不宣称其等价跨实例行为。

## 5. Crate 与 owner 地图

| Crate/目录 | 当前 owner | 访问控制责任 | 关键证据 |
|------------|-------------|--------------|----------|
| `astral-types` | 类型/契约 owner | `PolicyContext`、`PolicyDecision`、`ResourceRegistry`、CURRENT V6 edition、授权/投影类型 | [`context.rs`](../../../astral-types/src/context.rs)；[`registry.rs`](../../../astral-types/src/registry.rs)；[`edition.rs`](../../../astral-types/src/edition.rs) |
| `policy-engine` | 纯授权内核 owner | `PolicyEngine::evaluate`、四个 required repository ports、CURRENT V6 published gate/DEFAULT_DENY、断路器；正式调用链不含 Arbiter/oracle decision stage | [`engine/ports.rs`](../../../policy-engine/src/engine/ports.rs)；[`engine/formal.rs`](../../../policy-engine/src/engine/formal.rs)；[`engine/published.rs`](../../../policy-engine/src/engine/published.rs) |
| `astral-common` | 共享运行时/契约 owner | Gateway HMAC 下游验签、双卡上下文/路由解析 helper、session projection mirror contract、审计端口和双写适配 | [`permission_check_shared.rs`](../../../astral-common/src/middleware/permission_check_shared.rs)；[`session_projection_store.rs`](../../../astral-common/src/session_projection_store.rs)；[`audit.rs`](../../../astral-common/src/audit.rs) |
| `astral-gateway` | Gateway runtime owner | 路由、凭证策略、JWT、strict session/JTI/family facts 调用、可信头、转发签名、限流；无 Redis session adapter | [`middleware.rs`](../../../astral-gateway/src/middleware.rs) |
| `astral-identity` | 身份/会话 owner | login/refresh/switch-card、JWT/SessionGrant 签发、会话撤销投影、Argon2id-only 密码验证 | [`auth_service.rs`](../../../astral-identity/src/srv/auth_service.rs)；[`session.rs`](../../../astral-identity/src/srv/session.rs)；[`auth.rs`](../../../astral-identity/src/auth.rs) |
| `astral-db` | SQL/资格读取 owner | strict `SqlxRuleRepository`、双卡资格 JOIN、published evidence、SoD grant-time transaction recheck、session durable facts、进程内 cache adapters | [`repository/authorization.rs`](../../../astral-db/src/repository/authorization.rs)；[`eligibility.rs`](../../../astral-db/src/eligibility.rs)；[`sod_check.rs`](../../../astral-db/src/sod_check.rs)；[`session_state_repository.rs`](../../../astral-db/src/session_state_repository.rs) |
| `astral-trustgraph` | 权限治理/投影控制面 owner | 规则集与授权 source mutation、SoD early validator、WorkerOwned authorization projector、archive/completion、委托 caller-card/scope lifecycle、ELIGIBILITY invalidation、审计消费 | [`authorization_projector.rs`](../../../astral-trustgraph/src/service/authorization_projector.rs)；[`sync_publish.rs`](../../../astral-trustgraph/src/service/sync_publish.rs)；[`rule_write_service.rs`](../../../astral-trustgraph/src/service/rule_write_service.rs)；[`delegation.rs`](../../../astral-trustgraph/src/api/delegation.rs)；[`delegation_repository.rs`](../../../astral-trustgraph/src/repository/delegation_repository.rs) |
| `astral-mq` | 消息传输 owner | CURRENT V6 invalidation wire、audit/业务消息传输及 durable transport; generic envelope schema 版本独立于 V6 | [`astral-mq/src`](../../../astral-mq/src/lib.rs) |
| `astral-learn` / `astral-chat` | 源码保留、当前 workspace exclude | Learn/Chat 路由与业务 handler；解冻前不计入默认 workspace 验证证据 | [`Cargo.toml`](../../../Cargo.toml) |
| `astral-monitor` | 监控 owner | 当前健康与指标观察面不得成为授权旁路；Redis health/metrics 已退役 | [`astral-monitor/src`](../../../astral-monitor/src/lib.rs) |

CURRENT V6 owner 补充：`policy-engine` 提供无 IO 的 [`authorization_compiler.rs`](../../../policy-engine/src/authorization_compiler.rs)（版本化热状态编译内核及显式 full-rebuild oracle）；`astral-db` 提供 [`authorization_projection_repository.rs`](../../../astral-db/src/authorization_projection_repository.rs)（manifest/segment/current/archive 表链与 strict published-evidence reader）及 [`grant_repository.rs`](../../../astral-db/src/grant_repository.rs)（revision ledger + delta queue，ALLOW-only contract）；`astral-trustgraph` 的 [`authorization_projector.rs`](../../../astral-trustgraph/src/service/authorization_projector.rs) 是唯一授权 delta worker owner，[`authorization_archive_worker.rs`](../../../astral-trustgraph/src/service/authorization_archive_worker.rs) 负责 archive proof-before-complete，`grant_ledger_adapter.rs` 组装 typed grant DTO。上述源码链接证明代码结构，不证明数据库、消息或部署已验收。

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
- [权限引擎优化方向_2026-06-22.md](./Rust增量重建与实时授权边界_V1.0.md)（历史名称/链接别名，当前语义以该 V6 边界文档正文为准）
- permission-projection-sequence.mmd

### 6.3 委托与 GlobalAdmin（CURRENT V6）

- [委托 API：由 Gateway 注入的 `PolicyContext` 构造 caller context，并核对 caller card](../../../astral-trustgraph/src/api/delegation.rs#L99-L107)
- [委托 repository：caller identity、active status、tenant/domain scope 与授权来源 proof](../../../astral-trustgraph/src/repository/delegation_repository.rs#L349-L407)
- [GlobalAdmin API](../../../astral-trustgraph/src/api/global_admin.rs#L85-L298)
- [GlobalAdmin repository](../../../astral-trustgraph/src/repository/global_admin_repository.rs#L74-L429)

CURRENT V6 formal authorization 不包含 Arbiter/oracle decision stage；旧 Arbiter 内核、service/API 路径只保留为历史文档或迁移索引，不是当前 owner map 或有效源码链接。

## 7. 当前测试入口与证据边界

### 7.1 仓库提供的测试入口

当前 checkout 未跟踪 `.github/workflows/ci.yml` 或其他 Rust GitHub Actions workflow；本仓库的自动化发布 workflow 状态不能从测试文档或 README 反推。可确认的测试入口是各 crate 的 Cargo tests、`tests-suite/` 编目，以及 `README.md` 所列 `scripts/run-tests.sh` 等显式 runner。其依赖前置、ignored/blocked profile、外部服务约束与执行结果应以对应入口和本次运行日志为准；文档列出命令不等于它已执行或通过。

- workspace 默认检查应遵循根 `AGENTS.md` 中的最小充分验证与 workspace gate；`astral-learn`/`astral-chat` 位于 workspace `exclude`，不会被默认 workspace 检查覆盖。
- 需要真实 MySQL/RabbitMQ 的 integration/replay profile（及其当前合同实际依赖的其他服务）必须显式使用隔离依赖并按测试入口完成前置；不得用 mock、静态清单或无依赖 `exit 0` 替代真实集成验收。Redis/`astral-cache` 历史 profile 不代表当前 V6 软件合同。
- `tests-suite/README.md` 说明默认与显式 opt-in 覆盖边界；测试编排和 campaign 状态见 `README.md` 与 `scripts/run-tests.sh`，运行结果必须绑定当前源码快照和完整日志。

### 7.2 不能从测试定义或源码推出什么

1. **本文未运行本次 Rust tests、真实集成或 replay**：测试入口是执行方式的证据，不是本次会话的通过结果。
2. 由于默认 workspace 排除 `astral-learn`/`astral-chat`，workspace 检查不会证明这两个源码目录全量编译或测试通过。
3. crate unit/integration/replay 覆盖不能自动证明所有生产 source mutation 都经过资格 projection，也不能证明跨节点恢复或多云权威协议已经闭合；CURRENT V6 formal authorization 不含 Arbiter evidence 决策阶段。
4. `AuthorizationCompiler`、`AuthorizationProjector`、strict `PolicyEngine::evaluate()` 和 mock repository 的代码/测试证据不等同于真实 MySQL/RabbitMQ 集成、migration/backfill/rehearsal 或正式切流完成。真实数据库、消息和部署验证均须独立取证。
5. mandatory SoD early validator 与 transaction-bound published-only recheck 已在代码路径中；source-level call chain 不等于真实 MySQL 并发/锁序验收。本次不声称该项 real-DB test 已执行。
6. 历史迁移材料中的“对齐率”、历史 Redis fixtures 与报告不能替代当前源码和本次 test result；compiled/no-run、ignored 或未执行均不得当作 PASS。`TenantSerial`/`Partitioned` 与 ORG_SCOPE defaults 不因本文说明而变更。

## 8. 当前已实现、当前有边界、明确未实现（CURRENT V6）

### 已有源码证据的能力

- 物理双卡签发资格校验和运行期资格检查；Gateway 使用 strict MySQL session/JTI/family facts，可选 bounded process-local mirror 仅按明示策略加速，可信身份头清洗和 HMAC v3 下游验签。
- `ResourceRegistry`/path map/`PolicyContext`/`PolicyEngine::evaluate()` 主链；唯一授权入口使用四个 required repository ports 与 CURRENT V6 published-evidence gate。
- canonical grant revision/delta/manifest/segment/current 表链、`AuthorizationCompiler`、唯一 `AuthorizationProjector`、`AuthorizationArchiveWorker` 和 strict reader 的代码级接线；完整 receipt batch 仅在 proven COMMIT 后交付，request side 仅作有界只读 exact-completion wait；旧 head/outbox 只保留已登记 correlation 与 ELIGIBILITY invalidation 职责。pointer-moved 时 worker 在原 live lease 下最多 3 次原地 replan（加首次共最多 4 次 publication attempt），额度内不计执行失败；全部耗尽后仅由一次 owned charged transition 计一次失败，Unknown/Lost lease 需对账而不盲目补记。
- ALLOW-only `effective_grants` 匹配、DEFAULT_DENY、断路器 deny、current/manifest/segment proof 不足时 PENDING/DENY、MQ-first/DB-fallback 审计基础设施；mandatory SoD early validator 后还有 source-transaction 内 unconditional published-only recheck。
- 密码验证仅 Argon2id；JWT v2 `roles` 为 string array，旧 scalar/null shape reject，`permissions` 不作为授权输入。

### 当前边界或证据不足

- CURRENT V6 grant source 已由封闭 `GrantSourceKind` / `BindingLayer` 表达：RULE_SET 只用 BASE/OVERLAY，其余 DIRECT/DELEGATION/APPROVAL/SYSTEM 使用 NONE；新 direct `permission_rule` 仅接受 enabled MANUAL，CARD_ONLY 只读/删除、SYSTEM reserved-unused。该 typed contract 不证明历史 source rows 已迁移或 backfill。
- delegation API 从可信 Gateway `PolicyContext` 构造 caller；create 要求 `delegator_id` 等于 caller card，repository 在事务中锁卡并核验 caller user/card、ACTIVE、tenant/domain 与 delegate scope；update/revoke 也依锁定 delegation row 复核 caller ownership/scope。该调用链有源码证据，不是全环境集成验收证明。Arbiter 不属于 CURRENT V6 formal authorization decision path。
- `AuthorizationCompiler` 是纯编译内核，生产 durable projector 已接线；迁移/backfill/rehearsal、部署 schema、真实 MySQL/RabbitMQ 集成和正式切流验收仍须独立证据。SoD 交易内复查虽已实现，真实 MySQL 锁序/并发验证未执行。
- CURRENT V6 strict reader、matcher 与 bounded evidence L1 按读时/命中时检查 grant `not_before`/`expires_at`；自然到期不自动产生 source mutation、delta 或 publication-generation advance。独立 expiry scheduler/event 是否需要属于剩余时间语义，不得把旧 `rule_set_snapshot` 状态当作 V6 生产读门。
- CURRENT V6 evidence 与 ELIGIBILITY qualification 使用各自 bounded process-local cache/mirror；Redis L2/MAC/shared-unit/session compatibility、`astral-cache` 与 Redis lifecycle 不是当前合同。故障/重启/租约接管及审计组合场景仍需按当前依赖与真实环境单独验收。
- GlobalAdmin、Arbiter、委托和审计的代码调用链应持续按当前源码复核；旧 staged L1/L2/L2.5、raw/realtime evaluator 及其所谓待补边界不属于当前路线。

本节当前事实不把旧§12历史路线中的项目状态当作现状；完整 V6 部署/数据/运行时验证须另行取证，本文件没有执行代码、迁移或服务操作。

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

**决策**：Gateway 只认证和签发可信头；服务中间件解析资源动作、用共享 helper 构造 actor context，再由服务专属 owner resolver 确认目标归属；所有需要资源/动作授权的请求只有在 owner resolution 满足资源合同后，才能进入 `PolicyEngine::evaluate()`。未解析/不可用的 ownership 保持 `PENDING`/`DENY`。任何 `isSuperAdmin()`、角色字符串、请求体 context、身份卡 fallback 或直接 `permission_rule` 查询都不能在引擎前形成 ALLOW。

**理由**：将身份事实、授权卡事实、规则集语义和故障降级集中到 `PolicyEngine::evaluate()`，避免同一变更在 Gateway、Controller、Service 和 raw SQL 各自产生不同放行口径。各服务 middleware 先用共享 helper 构造 actor context，再调用目标资源 owner resolver 并将其结果写入 context；只在 resolver 成功且资源合同满足后才评估。公开的 `astral_common::middleware::permission_check_shared::check_permission` 保留为 deprecated compatibility helper，但其 `Unresolved` ownership 不能证明目标归属、不能授权受保护目标，也不能替代服务 owner resolver。另一个公开 helper `astral_common::middleware::permission::require_permission` 同样无法证明目标 ownership、当前无仓内调用方，不能用于受保护目标授权或替代服务 owner resolver。

### AD-2：投影是授权读模型的 durable admission gate

**决策**：CURRENT V6 canonical 授权 source mutation 通过 grant revision + 完整 typed delta receipt batch 进入唯一 `WorkerOwned` `AuthorizationProjector`，由 manifest/segment/current durable CAS 发布；仅在 source COMMIT 已证明后交付，request-side completion 仅作有界只读 exact observation。保留的 head/outbox 仅承担 source correlation、revoke/RuleSet initialization correlation 与 ELIGIBILITY invalidation，不是 canonical 发布证明。ELIGIBILITY qualification 保持独立，不混入规则授权 evidence。正式读侧只接受 CURRENT V6 published-evidence proof；版本不明、current/manifest/segment 缺失、worker 尚未证明完成或复读失败按 `AUTHORIZATION_PENDING`/DENY 处理。

**理由**：授权读模型可以暂时落后，但不能把未证明的旧 ALLOW 当成当前事实。canonical current pointer、manifest/segment seal、lineage、generation 和 revoke-fence proof 是正式 admission gate；旧 head、snapshot 或资格缓存不能替代它们。当前新链 projector、archive worker 与 strict reader 见 [`authorization_projector.rs`](../../../astral-trustgraph/src/service/authorization_projector.rs#L741-L847)、[`authorization_archive_worker.rs`](../../../astral-trustgraph/src/service/authorization_archive_worker.rs#L577-L735) 和 [`authorization_projection_repository.rs`](../../../astral-db/src/authorization_projection_repository.rs#L1-L44)。

### AD-3：委托写入与查询绑定已验证 caller scope；非正式决策面不产生 ALLOW

**CURRENT V6 事实**：委托 API 从 middleware 注入的可信 `PolicyContext` 派生 mutation context；create 拒绝 `delegator_id` 与 verified caller card 不一致。repository 在同一 source transaction 内锁定 caller/delegator/delegate cards，检查 caller user、ACTIVE 状态、tenant/domain scope 与 target scope，并在 create/必要的 update 中 strict published evidence 证明 delegator 持有相应授权；list 查询限定在 caller card 与相同 tenant/domain。update/revoke 不接受请求体重指定 delegator/delegate，而从锁定的 delegation row 决定真实端点并复核 caller scope。源码入口见 [`delegation.rs`](../../../astral-trustgraph/src/api/delegation.rs#L99-L107)、[`#L305-L369`](../../../astral-trustgraph/src/api/delegation.rs#L305-L369) 与 [`delegation_repository.rs`](../../../astral-trustgraph/src/repository/delegation_repository.rs#L349-L407)。这些是源码级合同，不代替真实 MySQL 并发/部署验证。

Arbiter/oracle 不属于 CURRENT V6 formal `PolicyEngine::evaluate()` decision path，也不作为普通请求 ALLOW 来源。跨云/半区冲突恢复协议仍是独立设计问题；不以已退役 Arbiter 源码链接或历史路线描述推断当前授权能力。

## 11. 文档维护规则

- 本文只记录当前代码和已批准的 Rust 架构边界，不把路线项写成“已完成”。
- 源码行号变动后，应更新本总览和导航 README 的链接；行号只用于复核入口，不替代测试。
- 任何权限、卡片、投影、委托、GlobalAdmin 或审计变更，必须同步审查调用链、逻辑链、事故链、数据链和审计链。
- 本文及相关文档只使用仓库相对链接，不记录绝对文件 URL、服务器地址、密码、Token 或密钥。
- 本文及本目录其他架构材料均为**非规范性设计/证据材料**；工程规范、实施约束和验收入口只由 `Docs/规范/` 与仓库根目录 `AGENTS.md` 提供。

## 12. 调整路线

> **历史快照（2026-09-09，已被 CURRENT V6 现状取代）**：以下路线、依赖关系、源码入口与状态均保留为当时记录，不是 CURRENT V6 的待办或实施报告，不得用于推断当前 evaluator、cache adapter、realtime API、schema 或部署状态。仅可作为历史设计/迁移证据；如需当前结论，以本文 §2–§8、CURRENT V6 规范及当次源码为准。

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

**状态与验收**：**诊断路径已存在，生产边界未完全冻结**。生产服务 middleware 先解析目标资源 owner，再调用正式 `PolicyEngine::evaluate()`；realtime 不因失败而放行；超时/DB 故障/结果过大 deny/defer；sampling 与 Arbiter 不递归或无限重试。

### 12.9 P1-3：cache/timeout/lifecycle

**当前事实**：Gateway Redis check 和 ELIGIBILITY 资格缓存均在依赖失败时 fail-closed；生产权限 evidence cache 只缓存已验证的 current/manifest/segment 证据，失配或 Redis 故障回 strict reader，不回旧 snapshot。`AuthorizationProjector` 已有事件级 deadline、bounded attempt、lease/token fence、pointer-moved replan、Blocked/Quarantine/Unknown；`AuthorizationArchiveWorker` 已有 cancellation、过期 lease recovery、proof-before-complete 和 bounded join，TrustGraph `main` 持有并逆序关闭相关 worker。组合生命周期的真实基础设施验收仍未完成。
**路线**：统一 DB/Redis/MQ/HTTP/worker timeout budget 和 reason code；区分 cache read/write failure、stale payload、old scalar、reconnect；明确启动、关闭、lease 接管、MQ 重连、重复 publish/mark 的幂等；补足 tenant/domain fan-out、identity expiry/status mutation 和 user-card validity API；监控 pending age、retry、generation lag、cache miss、audit fallback 和 circuit state。

**状态与验收**：**部分实现，组合生命周期验收未完成**。依赖故障无 stale ALLOW；worker 重启可接管 lease；publish 成功而 mark 失败可安全重放；已提交 source mutation 不因 shutdown 丢失 outbox。

### 12.10 P1-4：Arbiter trust boundary

**当前事实**：PolicyEngine Arbiter 是无 IO 纯函数，按 source/fence 版本序裁决，最新 DENY 优先，不可证明时 DEFER，见 [`policy-engine/src/arbiter.rs`](../../../policy-engine/src/arbiter.rs#L1-L15) 和 [`#L160-L219`](../../../policy-engine/src/arbiter.rs#L160-L219)。TrustGraph service 挂接冲突 sink 并写审计，见 [`service/arbiter.rs`](../../../astral-trustgraph/src/service/arbiter.rs#L54-L124)。当前 API 直接接收请求体 `PolicyContext`/evidence，见 [`api/arbiter.rs`](../../../astral-trustgraph/src/api/arbiter.rs#L34-L125)。

**路线**：handler 内从可信 Gateway 头重建操作者 context；evidence 必须包含可信 node identity、source/projected/fence、snapshot version、observed time、event/message id 和 idempotency key；只接收已登记节点和允许 schema；只在 READY 且版本可区分分歧时裁决；DEFER 强制映射 PENDING/拒绝，caller 不能自转 ALLOW。

**状态与验收**：**内核已实现，控制面信任边界未完成**。修改请求体 context 不扩大权限；伪造节点、旧代或跨卡 evidence 被拒绝/DEFER；replay 幂等；Arbiter ALLOW 可追溯到 caller、evidence 和 projection contract。问题登记见[模型修正记录问题5](./Rust架构模型设计修正记录.md#L83)。

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

## 13. 历史路线验证门与证据边界（2026-09-09）

以下命令和阶段条件属于已取代路线快照，只用于说明当时的验证设计，不是 CURRENT V6 的当前 CI、运行状态或本次执行证据。任何当前验证须按仓库根目录 `AGENTS.md`、Rust 后端规范与当次变更风险选择，并依据当次完整日志报告：

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --lib
cargo test --workspace --test '*' -- --ignored --test-threads=1
```

真实 MySQL/Redis/RabbitMQ 集成和 replay 必须按 [`tests-suite/README.md`](../../../tests-suite/README.md) 与仓库测试入口的隔离依赖约束显式运行；本文列出的命令只是验证方式，不是本次会话已执行或已通过的结果。默认 workspace 不包含 `astral-learn`/`astral-chat`，解冻前不能声称它们通过全工作区验证。纯函数、mock repository、benchmark 和历史报告只能证明局部逻辑或方法存在，不能证明生产 source mutation、跨节点 evidence、生命周期故障和审计降级闭环。

## 14. 历史待办与切片记录（2026-09-09，已被 CURRENT V6 现状取代）

以下清单及其状态保留为当时快照，不是当前未实现项清单，不得据其判断 CURRENT V6 的当前能力。其 `[x]`/`[ ]` 仅表示原记录，不构成当前实施或验收证明；当前事实与边界见 §2–§8，迁移和部署状态必须单独取证：

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
- [ ] tenant/domain status fan-out、identity expiry/status source mutation、user-card validity API 等生命周期补齐，参见 [V5 迁移路线](./V5模型修正筹划_专供Rust_V1.0.md#L131)。

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
