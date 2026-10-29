# Rust 双卡身份与授权上下文 V1.0

> 版本：V1.0
> 核对基线：2026-08-22
> 文档性质：当前事实 / 证据索引 / 缺口与目标决策
> 适用范围：当前 checkout 的 Gateway、Identity、TrustGraph、公共权限上下文与认证会话链路。Learn/Chat 生产 runtime 已退役并物理移除；独立 SDK consumer sample 与历史资料不属于当前服务链路。

## 0. 阅读口径

本文是 `Docs/架构/Rust架构设计/` 下的**非规范性架构材料**，用于记录当前代码、schema/migration 与测试能够证明的行为。`Docs/规范/` 与仓库根目录 [`AGENTS.md`](../../../AGENTS.md) 仍是工程政策、实施约束和验收入口；本文不替代、不修改它们。

- **当前事实**：能由当前 Rust 源码、migration/schema 或可定位测试直接核验的行为。
- **缺口**：当前调用链、数据链或测试覆盖仍不能闭合的边界；缺口不是“已经修复”。
- **目标决策**：后续架构应保持或补齐的方向；目标决策不表示已经实施。
- **证据优先级**：运行时代码与实际 schema/migration 高于历史设计稿；测试证明的是测试覆盖的契约，不自动证明所有部署环境都已迁移。
- **事实判定边界**：当前运行事实只能由 Rust source、schema/migration 与 tests 共同确定；本文不以目标设计、历史文档或未执行的测试命令替代这些证据。

本文不记录服务器地址、凭据、Token、密钥或其他敏感配置。所有源码引用使用仓库相对链接并带 1-based 行号范围；行号以本次核对的工作区文件为准。

## 1. 一页结论

当前 Rust 链路把“认证你是谁”和“授权你能做什么”拆成两条物理事实线路：`identity_card` 提供身份事实，`user_card` 提供授权与组织 scope。`PolicyContext` 只把 `identity_card_id` 放在身份字段，把 `card_id`、`tenant_id`、`domain_id` 映射为 user-card 上下文；`identity_card` 不再作为 tenant/domain 的来源。权威双卡资格由 `CardEligibilityService` 的单条 JOIN 与运行期资格缓存/SQL 回退共同守门。

PlatformUser 的 ACCESS credential 必须带完整双卡 scope；历史 `APP_USER` credential 只作为拒绝/迁移识别，不再有 active issuance 或 refresh 路径。REFRESH credential 由 Identity 按持久化 PlatformUser session 重新读取并校验目标 user-card。Learn/Chat 生产 runtime 已退役；当前 Gateway→下游可信转发统一使用 Gateway HMAC v3。

## 2. 两张卡与 owner 边界

| 对象 | 当前职责 | 当前 owner / 主要生产者 | 当前消费者与约束 | 证据 |
|---|---|---|---|---|
| `identity_card` | 认证身份事实：`user_id`、ACTIVE 状态、token version、有效期；不承载 tenant/domain scope | Identity 的 `CardRepository` 负责当前 PlatformUser 身份卡查询与校验 | Gateway 注入 `x-identity-card-id`；下游把它映射到 `PolicyContext.identity_card_id`；资格服务只用它做身份线路检查 | [`card_repository.rs`](../../../astral-identity/src/srv/card_repository.rs)、[`context.rs:21-24`](../../../astral-types/src/context.rs#L21-L24) |
| `user_card` | 授权卡实例：卡类型、模板/等级、ACTIVE 与有效窗口、`tenant_id`、`domain_id`；承载业务授权 scope | TrustGraph 的 user-card API/repository 负责管理与读取；Identity 在登录、刷新、切卡时消费所选卡并重签 access | Gateway 注入 `x-user-card-id`、`x-user-card-tenant-id`、`x-user-card-domain-id`；`PolicyContext.card_id` 指向它；不得从 identity 侧 scope 回退 | [`user_cards.rs:189-250`](../../../astral-trustgraph/src/api/user_cards.rs#L189-L250)、[`user_card_repository.rs:90-138`](../../../astral-trustgraph/src/repository/user_card_repository.rs#L90-L138)、[`physical_policy_context()`](../../../astral-common/src/middleware/permission_check_shared.rs#L55-L118) |

### 2.1 当前身份事实与授权事实

- `CardEligibilityService::verify_platform_card_pair` 要求 `identity_card.user_id == user_card.user_id == 请求 user_id`，身份卡只检查归属、ACTIVE、过期；tenant/domain 只从 user-card 与组织关联读取。见 [`eligibility.rs:81-155`](../../../astral-db/src/eligibility.rs#L81-L155)。
- 权威 SQL 同时约束 `platform_user` ACTIVE、`user_card` ACTIVE/非模板/有效窗口、`identity_card` ACTIVE/未过期、tenant ACTIVE 与 `tenant_domain_map` ACTIVE；tenant/domain 不能从 identity-card 线路补齐。见 [`eligibility.rs:236-277`](../../../astral-db/src/eligibility.rs#L236-L277)。
- user-card 的管理范围也只读取 `x-user-card-tenant-id` / `x-user-card-domain-id`，明确禁止回退到 identity 侧字段。见 [`user_cards.rs:189-204`](../../../astral-trustgraph/src/api/user_cards.rs#L189-L204)。

### 2.2 owner 结论

**当前事实**：Identity owner 认证身份与 PlatformUser session/token；TrustGraph owner user-card、模板、规则和授权投影。Learn/Chat 生产 runtime 已退役，独立 SDK consumer sample 不属于当前授权服务链路。

**缺口**：历史 baseline 仍把两张卡描述成旧字段组合，不能单独作为当前运行 schema 证据，见第 10 节。任何跨 owner 的卡片变更仍需同时检查 session projection、eligibility projection、规则快照和审计副作用。

**目标决策**：继续保持双卡物理分离；所有需要业务授权的路径必须显式要求 PlatformUser 的完整 user-card scope；任何新的身份头、JWT claim 或 session 字段都必须明确属于 identity namespace 或 user-card namespace，不允许使用模糊的 `card_id` 语义。

## 3. `PolicyContext` 映射

`PolicyContext` 当前同时保存主体、双卡、组织、资源和动作字段。`identity_card_id` 与 `card_id` 是不同字段；`domain_id` / `tenant_id` 的来源是 user-card。见 [`context.rs:7-85`](../../../astral-types/src/context.rs#L7-L85)。

### 3.1 Gateway 头到上下文

当前正式授权上下文只接受 `PLATFORM_USER`，并要求 identity card 与 user-card 的完整 scope。`APP_USER` 仍可在 token/parser 与拒绝测试中被识别，但不进入当前业务授权路径。

| Gateway 头 | `PolicyContext` 字段 | 当前 PlatformUser 合同 | 旧/非法主体 |
|---|---|---|---|
| `x-user-id` | `user_id` | 必须为正数 | 缺失或非法则拒绝 |
| `x-principal-kind` | `principal_kind` | 必须为 `PLATFORM_USER` | `APP_USER` 或未知值只用于拒绝/迁移识别 |
| `x-identity-card-id` | `identity_card_id` | 必须存在且为正数 | 缺失或非法则拒绝 |
| `x-user-card-id` | `card_id` | 必须存在且为正数 | 缺失则拒绝 |
| `x-user-card-tenant-id` | `tenant_id` | 必须存在且为正数 | 缺失则拒绝 |
| `x-user-card-domain-id` | `domain_id` | 必须存在且为正数 | 缺失则拒绝 |
| 路径映射与方法 | `resource` / `action` | 由 service middleware 解析 | 未注册资源/动作拒绝 |
| 显式 query ID | `target_id` | 作为对象级授权目标 | 不从未知路径段推断 |

`physical_policy_context()` 对缺任一 PlatformUser user-card 字段返回 `FORBIDDEN`，对非 PlatformUser 主体不构造可用于业务授权的 identity-only 放行上下文；它不会把 identity-card 的任何 tenant/domain 旧头转换成授权 scope。见 [`physical_policy_context()`](../../../astral-common/src/middleware/permission_check_shared.rs#L55-L118)。

### 3.2 PolicyEngine 入口

业务权限中间件先解析 path/action，并调用共享 `physical_policy_context` 构造身份/双卡 actor context；该 helper 将 `resource_ownership_scope` 保持为 `Unresolved`，不证明目标资源 owner。服务必须先运行自己的 owner resolver 并将解析结果应用到 context；resolver 未解析或不可用时拒绝/defer，只有 owner 结果满足契约后才调用 `PolicyEngine::evaluate()`。当前 active resolver 入口位于 Identity、Monitor 与 TrustGraph 的服务中；Learn/Chat resolver 已随生产 runtime 物理移除。
## 4. SessionGrant 与身份头

### 4.1 SessionGrant producer / consumer

`SessionGrant` 是 Identity 在签发后用于登记 access JTI durable proof 的版本化内部结构；当前 Gateway 准入事实不是 Redis grant，而是 MySQL `auth_session_jti_index` 与 `auth_device_session`、`auth_token_family`、identity/user-card 事实的 strict JOIN。生产结构见 [`auth.rs:319-369`](../../../astral-identity/src/auth.rs#L319-L369)，strict 读取与绑定校验见 [`session_state_repository.rs:35-109`](../../../astral-db/src/session_state_repository.rs#L35-L109) 和 [`session_projection_store.rs:145-257`](../../../astral-common/src/session_projection_store.rs#L145-L257)。

| 字段 | 当前 PlatformUser producer 语义 | consumer 校验/用途 |
|---|---|---|
| `formatVersion` | 固定 `2`，属于 session-grant wire contract | 未知版本拒绝 |
| `principalKind` | 固定 `PLATFORM_USER` | 必须与 JWT principal 一致；其他主体拒绝 |
| `userId` / `sessionId` | 用户与设备 session 绑定 | 与 JWT `sub` / `sid` 及 durable row 一致 |
| `identityCardId` | 当前身份卡绑定 | 必须为正数并与 durable identity fact 一致 |
| `userCardId` | 当前授权卡绑定 | 必须与 session/current user-card 及 JWT 一致 |
| `userCardTenantId` / `userCardDomainId` | user-card 组织 scope | 必须与 durable tenant/domain facts 一致且处于有效状态 |
| `sessionVersion` / `sessionEpoch` | session 轮换栅栏 | 逐项绑定，阻止旧版本继续存活 |
| `tokenFamilyId` / `sessionState` | family 及 ACTIVE 状态 | family/session 非 ACTIVE 不接受 |
| `issuedAtEpochSecond` / `expiresAtEpochSecond` | grant 生命周期 | JWT 时间必须落在 durable proof 窗口内 |

Identity 只为 PlatformUser 写入严格 JTI proof；proof 写入失败时签发失败并关闭 family，镜像安装只能在 durable proof 完成后作为有界进程内加速，不能替代 strict DB。见 [`session.rs:817-899`](../../../astral-identity/src/srv/session.rs#L817-L899)。Gateway 在每次带 Bearer 的请求上执行 strict session admission；镜像 miss、过期、suspect 或未安装时回到 MySQL，DB 不可用时 fail-closed。见 [`gateway/middleware.rs:606-666`](../../../astral-gateway/src/middleware.rs#L606-L666)。

### 4.2 Gateway 注入与下游可信边界

ACCESS 校验通过后，Gateway 将 `x-user-id`、`x-identity-card-id`、`x-user-card-id`、user-card tenant/domain、principal、token 与权限摘要等头写入内部请求；refresh credential 在 Gateway 侧提前返回，不产生业务身份头。见 [`gateway/middleware.rs:1030-1034`](../../../astral-gateway/src/middleware.rs#L1030-L1034)、[`gateway/middleware.rs:1163-1219`](../../../astral-gateway/src/middleware.rs#L1163-L1219)。

Gateway 转发时只从认证后的头重新取值并将同一组字段绑定到 HMAC v3；客户端的敏感头不会直接覆盖这些值。见 [`gateway/proxy.rs:897-997`](../../../astral-gateway/src/proxy.rs#L897-L997)。

## 5. PlatformUser 与历史主体拒绝边界

### 5.1 PlatformUser

当前 PlatformUser 登录流程要求选定 identity card 与 user card，调用 `verify_platform_card_pair` 作为最终签发门禁；成功后 ACCESS JWT 带 `identity_card_id`、`user_card_id`、user-card tenant/domain 与 session claim。见 [`auth_service.rs:205-290`](../../../astral-identity/src/srv/auth_service.rs#L205-L290)、[`auth.rs:200-248`](../../../astral-identity/src/auth.rs#L200-L248)。

PlatformUser 的业务权限链为：

```text
ACCESS JWT
  -> Gateway strict MySQL session admission + 身份头注入
  -> Gateway HMAC v3
  -> Identity / TrustGraph / Monitor gateway_signature_middleware
  -> physical_policy_context（双卡完整 scope）
  -> PolicyEngine.evaluate()
```

### 5.2 `APP_USER` 与旧主体

`APP_USER` 不再有 active issuance、refresh、Gateway route 或业务授权入口。token/parser、permission-context 与 session-proof 代码中保留的 `APP_USER` 分支只用于识别历史凭证并 fail-closed 拒绝；它们不是当前能力，也不提供 identity-only 放行。当前 Identity refresh、switch-card、revoke/logout 和受保护 middleware 均要求 `PLATFORM_USER`。

Learn/Chat 生产 runtime、AppUser repository、Identity internal session route 与对应服务间签名模块已物理移除。历史测试清单、迁移说明和归档资料仍可能出现这些名称，但只能作为历史事实或旧输入拒绝证据，不得作为当前路由、部署 profile 或 PASS 证据。

## 6. Access、Refresh 与 Gateway HMAC v3

### 6.1 ACCESS 链

1. Identity 只签发 `PLATFORM_USER` JWT；ACCESS 必须携带 identity card、user-card、tenant/domain 与 session 绑定字段。见 [`auth.rs:150-248`](../../../astral-identity/src/auth.rs#L150-L248)。
2. Gateway 按路径分类 credential policy，再解码 JWT。公共路径只有在没有 Authorization 时匿名放行；带 Bearer 的公共路径仍需通过 access 校验。见 [`gateway/middleware.rs:953-1008`](../../../astral-gateway/src/middleware.rs#L953-L1008)。
3. Gateway 检查 revoked JTI，并通过 MySQL `auth_session_jti_index`、session/family、identity-card 和 user-card strict facts 做逐项绑定判定；缺失、过期、撤销、scope 不一致或 DB 不可用均拒绝。见 [`gateway/middleware.rs:606-666`](../../../astral-gateway/src/middleware.rs#L606-L666)、[`session_state_repository.rs:35-109`](../../../astral-db/src/session_state_repository.rs#L35-L109)。
4. Gateway 注入可信身份头，代理为下游计算 HMAC v3；下游先验签，再使用身份头。见 [`gateway/proxy.rs:335-452`](../../../astral-gateway/src/proxy.rs#L335-L452)、[`gateway_signature.rs:65-74`](../../../astral-common/src/middleware/gateway_signature.rs#L65-L74)。

### 6.2 REFRESH 链

Gateway 的 refresh 与 switch-card 路由只接受 REFRESH；logout/revoke 接受 ACCESS 或 REFRESH。Identity refresh 会先拒绝非 PlatformUser principal，再读取 refresh token 对应的持久化 session，校验 family/过期/版本/epoch，从 `current_user_card_id` 重建双卡上下文并再次执行资格检查。关键状态失败时不返回可用的新 access。见 [`session.rs:47-90`](../../../astral-identity/src/srv/session.rs#L47-L90)、[`session.rs:164-299`](../../../astral-identity/src/srv/session.rs#L164-L299)。

REFRESH JWT 自身不携带可直接用于下游授权的完整业务 scope；它只携带 refresh 所需的主体、session、family 与轮换元数据。因此 REFRESH 不能直接作为业务身份凭证，必须由 Identity 重新读取 durable session/card facts 后签发新的 PlatformUser access。见 [`auth.rs:250-315`](../../../astral-identity/src/auth.rs#L250-L315)。

### 6.3 旧协议边界

`astral-internal-v1`、Learn→Gateway→Identity AppUser session chain、Chat WebSocket credential conversion 和 Redis replay/idempotency runtime 已从当前 checkout 物理移除。历史代码、归档文档或拒绝测试中的同名字符串不构成 active caller、route、feature 或启动 profile；当前 Gateway→下游可信转发只使用 HMAC v3。

## 7. Gateway HMAC v3 与身份边界

Gateway HMAC v3 是当前唯一的 Gateway→下游可信转发协议。其 canonical payload 绑定 method/path、user/principal/token、双卡字段、token use、claims version、action/roles 与 timestamp；下游验签失败、缺头、时钟偏差或主体/卡字段不一致均拒绝。见 [`gateway_signature.rs:18-63`](../../../astral-common/src/middleware/gateway_signature.rs#L18-L63)、[`gateway_signature.rs:215-280`](../../../astral-common/src/middleware/gateway_signature.rs#L215-L280)。Gateway HMAC v3 不接受 legacy v2；现有契约测试验证旧签名不会到达 handler。见 [`gateway_contract_tests.rs:461-478`](../../../tests-suite/series/E1/gateway_contract_tests.rs#L461-L478)。

## 8. Gateway 及服务 middleware 矩阵

### 8.1 当前服务挂载矩阵

| 服务 / 路由 | Gateway 入口行为 | 服务侧签名边界 | 服务侧权限行为 | 例外 / 备注 |
|---|---|---|---|---|
| Gateway `/api/v1/auth/**` | 清洗客户端敏感身份头，执行 route credential policy 与 strict MySQL session admission | Gateway 自身是 HMAC producer | 不执行下游 verifier | 只暴露 Identity 当前明确注册的固定路由 |
| Identity `/api/v1/auth/**` | Gateway 转发的正常请求携带 v3 头 | 统一挂 `gateway_signature_middleware` | 认证 bootstrap 按路径例外；受保护入口要求 PlatformUser、资源映射和 PolicyEngine | 无 internal session 子路由 |
| TrustGraph `/main/api/v1/**` | Gateway 生成 v3 | 主路由挂 `gateway_signature_middleware` | 资源路由挂 `permission_check_middleware`；未映射路径拒绝 | `/main/api/v1/**` 是现有冻结主入口 |
| Monitor `/api/v1/monitor/{*path}` | Gateway 生成 v3 | 按当前 Monitor runtime 校验 Gateway 身份 | 健康/指标入口按当前显式 route policy 处理 | 不再探测或依赖 Redis、Learn、Chat |

### 8.2 Gateway middleware 例外

1. `OPTIONS` 预检直接继续，不进入 Bearer 解码；没有任何 internal session route 例外。见 [`gateway/middleware.rs:920-950`](../../../astral-gateway/src/middleware.rs#L920-L950)。
2. `sanitize_internal_auth_headers` 对普通请求移除客户端伪造的 internal、auth、identity、gateway 头；可信身份头只由 Gateway 在 JWT strict admission 后重新注入。见 [`gateway/middleware.rs:898-915`](../../../astral-gateway/src/middleware.rs#L898-L915)。
3. 匿名放行只适用于 Gateway 已注册的 public route 且没有 Authorization；一旦带 Bearer，即使路径是 public，也必须是有效的 PlatformUser access credential。见 [`gateway/middleware.rs:300-331`](../../../astral-gateway/src/middleware.rs#L300-L331)、[`gateway/middleware.rs:953-1008`](../../../astral-gateway/src/middleware.rs#L953-L1008)。
4. REFRESH 只作为 session capability 进入 Identity refresh/switch/logout/revoke，不产生业务身份头；ACCESS 才进入 Gateway strict MySQL session admission。见 [`gateway/middleware.rs:1019-1034`](../../../astral-gateway/src/middleware.rs#L1019-L1034)。

## 9. 卡资格、session switch 与 refresh

### 9.1 签发资格

- PlatformUser login 在选卡后调用双卡资格服务，失败即拒绝签发；见 [`auth_service.rs:257-290`](../../../astral-identity/src/srv/auth_service.rs#L257-L290)。
- PlatformUser refresh 读取 session 持久化的 `current_user_card_id`，重新读取 user-card 并调用同一资格服务；非 PlatformUser refresh 在进入 session lookup 前拒绝。见 [`session.rs:47-90`](../../../astral-identity/src/srv/session.rs#L47-L90)、[`session.rs:164-299`](../../../astral-identity/src/srv/session.rs#L164-L299)。
- PolicyEngine 运行期资格检查优先读取 `ELIGIBILITY` projection gate 与带物理上下文的缓存，缓存 miss/版本不匹配再回权威 SQL；要求 projection ready 时未 READY 直接拒绝。见 [`eligibility.rs:157-230`](../../../astral-db/src/eligibility.rs#L157-L230)、[`eligibility.rs:280-307`](../../../astral-db/src/eligibility.rs#L280-L307)。

### 9.2 Session refresh

当前 refresh 的安全顺序是：解析 REFRESH → 读取并匹配 session/family/version/epoch → 检查 family 与过期 → 重建 identity/user-card context → 增加 version/epoch → 先删除旧 projection → refresh token CAS 轮换 → 写新 access grant；关键状态失败时不返回可用的新 access。见 [`session.rs:93-161`](../../../astral-identity/src/srv/session.rs#L93-L161)、[`session.rs:300-423`](../../../astral-identity/src/srv/session.rs#L300-L423)。

### 9.3 Session switch

`POST /api/v1/auth/sessions/switch-card` 使用 REFRESH credential。当前实现：

1. 校验 refresh 对应 session、family、user、当前 user-card、version/epoch；见 [`session.rs:1021-1089`](../../../astral-identity/src/srv/session.rs#L1021-L1089)。
2. 查找目标 user-card 与 ACTIVE identity card，并调用双卡资格服务补齐 tenant/domain ACTIVE 与对应关系证明；见 [`session.rs:1338-1421`](../../../astral-identity/src/srv/session.rs#L1338-L1421)。
3. 增加 session version/epoch，签发新的 PlatformUser access 与 refresh，保留同一 family，CAS 更新 `current_user_card_id`、refresh hash 和版本；见 [`session.rs:1423-1563`](../../../astral-identity/src/srv/session.rs#L1423-L1563)。
4. 通过 `SwitchCardRequest.target_user_card_id` 暴露 HTTP adapter，并记录 CardSwitch 审计；见 [`cards.rs:35-38`](../../../astral-identity/src/srv/cards.rs#L35-L38)、[`cards.rs:191-206`](../../../astral-identity/src/srv/cards.rs#L191-L206)。

**当前语义注意**：切卡代码的注释称保留长期 credential，但实际代码重新签发并更新 refresh hash；可确认不变的是 family 继续复用、session version/epoch 与 access projection 轮换。后续应把“保留 family”与“是否轮换 refresh token”两个概念分开命名并补测试，避免调用方按注释而不是按持久化状态理解行为。

## 10. Schema / baseline 漂移与验证边界

### 10.1 已确认的漂移

历史 baseline 的 `identity_card` 使用 `id`、`card_number`、`valid_from/valid_until`，`user_card` 使用 `id`、`status`、`identity_card_id` 等字段；见 [`20240630000001_baseline.sql:100-139`](../../../astral-db/migrations/20240630000001_baseline.sql#L100-L139)。当前 Rust runtime SQL 则使用 `identity_card.card_id/status/token_version/expires_at` 与 `user_card.card_id/card_status/valid_from/valid_until` 等 canonical 名称，见 [`card_repository.rs:85-112`](../../../astral-identity/src/srv/card_repository.rs#L85-L112)、[`eligibility.rs:249-277`](../../../astral-db/src/eligibility.rs#L249-L277)。因此 baseline 文件本身不能证明当前部署库已经具备 runtime 所需列。

认证会话 schema 已有明确的 canonicalization 轨迹：旧 family/session 标识会迁移到 BIGINT `family_id` / `session_id` 与 `family_key`，并显式说明旧部署存在不同列类型；见 [`20260714000001_auth_family_schema_contract.sql:1-11`](../../../astral-db/migrations/20260714000001_auth_family_schema_contract.sql#L1-L11)。`auth_device_session` 的当前 baseline contract 包含 `current_user_card_id`、`session_state`、`session_version`、`session_epoch`；见 [`20240630000005_auth_session.sql:7-34`](../../../astral-db/migrations/20240630000005_auth_session.sql#L7-L34)，resilience migration 还会补齐并归一化版本/epoch；见 [`20260728000001_auth_session_resilience.sql:1-28`](../../../astral-db/migrations/20260728000001_auth_session_resilience.sql#L1-L28)。

### 10.2 当前验证边界

- Identity 集成测试明确以 Docker MySQL 验证真实 `platform_user`、凭证、`identity_card`、`auth_token_family`、`auth_device_session` 列名与 FromRow 映射；测试默认不是无条件本地单元测试。见 [`identity/tests/integration.rs:1-9`](../../../tests-suite/series/CORE/identity_integration.rs#L1-L9)。
- Gateway contract tests 覆盖 v3 字段篡改、主体卡字段关系、缺字段、legacy v2 拒绝和 handler 不执行；见 [`gateway_contract_tests.rs:270-347`](../../../tests-suite/series/E1/gateway_contract_tests.rs#L270-L347)、[`gateway_contract_tests.rs:413-478`](../../../tests-suite/series/E1/gateway_contract_tests.rs#L413-L478)。
- 当前材料未把 migration 执行结果、实际 Redis 历史数据、各服务线上路由探活结果或未运行的集成命令当作事实。Redis 不属于当前 runtime；如需验证部署一致性，应补充对应 MySQL/RabbitMQ/服务环境证据，而不是从源码或历史 Redis 报告推断部署状态。

## 11. 当前事实、缺口、目标决策

| 主题 | 当前事实 | 当前缺口 | 目标决策（未实施声明） |
|---|---|---|---|
| 双卡 ownership | Identity 生产/消费 identity-card 身份事实；TrustGraph 管理 user-card 与授权 scope | 历史 baseline 与 runtime canonical 字段漂移 | 维持单一 owner，跨 owner 只通过明确 DTO/查询契约交互 |
| 上下文映射 | `physical_policy_context` 要求 PlatformUser 完整双卡 scope；非 PlatformUser 仅作拒绝识别 | 历史 permission-context 负向测试仍保留旧主体字符串 | 新增业务路径继续只接受 PlatformUser，并以 PolicyEngine.evaluate() 完成授权 |
| SessionGrant | Identity 只为 PlatformUser 写入 proof；Gateway 以 MySQL durable facts strict admission，镜像只作有界加速 | 真实数据库 schema、服务启动和故障恢复仍需环境验收 | 继续以 JTI proof + session version/epoch + card/scope fence 作为 access live gate，失败 fail-closed |
| ACCESS / REFRESH | ACCESS 承载完整双卡身份；REFRESH 由 Identity 按 durable session/card facts 重建，非 PlatformUser 拒绝 | 切卡注释与实际 refresh token 轮换语义仍需补充回归证据 | 保持 family、version/epoch、JTI proof、CAS 与撤销顺序一致 |
| Gateway HMAC v3 | Gateway 生成；Identity/TrustGraph/Monitor 验证；旧 v2 与伪造头拒绝 | 运行时密钥配置和多服务部署一致性不由源码证明 | v3 只用于 Gateway→当前下游可信转发，不恢复旧 internal-v1 域 |
| middleware | 当前主业务入口有 v3 verifier；Identity 受保护入口要求 PlatformUser 与资源映射 | skip/public 路径新增时仍需同步 route policy、签名层、权限层和测试 | 新增路由必须登记固定 Gateway 路由、服务签名层、PolicyEngine 入口和拒绝测试 |
| schema | auth family/session 有 canonical migration；integration test 记录真实列契约 | identity/user-card baseline 仍是旧形态，不能单独作为部署基线 | 将 runtime 所需 identity/user-card schema 形成可验证 canonical migration，并在 CI/集成环境执行 |
| 审计与副作用 | 登录、内部会话、切卡、权限决策已有审计调用；切卡 adapter 记录 CardSwitch | 异步审计和 projection 的运行失败重试/最终一致性仍需按环境核验 | 权限/卡片/session mutation 保持审计、幂等、补偿与 fail-closed 验收 |

## 12. 证据索引与维护边界

本文件最小证据集合如下：

- 双卡与资格：[`physical_policy_context()`](../../../astral-common/src/middleware/permission_check_shared.rs#L55-L118)、[`context.rs:7-85`](../../../astral-types/src/context.rs#L7-L85)、[`eligibility.rs:236-307`](../../../astral-db/src/eligibility.rs#L236-L307)。
- Gateway route/auth/forward：[`gateway/runtime.rs:38-285`](../../../astral-gateway/src/runtime.rs#L38-L285)、[`gateway/middleware.rs:606-724`](../../../astral-gateway/src/middleware.rs#L606-L724)、[`gateway/proxy.rs:231-452`](../../../astral-gateway/src/proxy.rs#L231-L452)。
- Identity PlatformUser auth/session：[`auth.rs:150-369`](../../../astral-identity/src/auth.rs#L150-L369)、[`session.rs:47-90`](../../../astral-identity/src/srv/session.rs#L47-L90)、[`session.rs:817-899`](../../../astral-identity/src/srv/session.rs#L817-L899)、[`session.rs:1021-1563`](../../../astral-identity/src/srv/session.rs#L1021-L1563)。
- Durable session admission：[`session_state_repository.rs:35-109`](../../../astral-db/src/session_state_repository.rs#L35-L109)、[`session_projection_store.rs:145-257`](../../../astral-common/src/session_projection_store.rs#L145-L257)。
- 服务 middleware：[`identity/middleware.rs:65-115`](../../../astral-identity/src/middleware.rs#L65-L115)、[`trustgraph/runtime.rs:253-269`](../../../astral-trustgraph/src/runtime.rs#L253-L269)、[`gateway_signature.rs:139-330`](../../../astral-common/src/middleware/gateway_signature.rs#L139-L330)。
- 规范边界：[`Rust 后端编码规范`](../../规范/Rust后端编码规范_V1.0.md)、[`统一接口路径规范 V5`](../../规范/统一接口路径规范_V5.md)。

维护本文时，先重新核对源码、schema/migration 和测试，再更新当前事实与行号；不要把目标决策写成已完成，不要用历史 Java/JSA、Learn/Chat 归档或 Redis 比较资料覆盖 Rust 当前证据。本文可以记录退役边界和旧输入拒绝守卫，但不得把已删除源码、旧 profile 或历史报告写成当前 runtime。
