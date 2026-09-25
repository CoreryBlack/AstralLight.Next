# Rust 双卡身份与授权上下文 V1.0

> 版本：V1.0
> 核对基线：2026-08-22
> 文档性质：当前事实 / 证据索引 / 缺口与目标决策
> 适用范围：`` 的 Gateway、Identity、Learn、TrustGraph、公共权限上下文与认证会话链路。

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

PlatformUser 的 ACCESS credential 必须带完整双卡 scope；AppUser 的 ACCESS credential 只带 identity-card 上下文，不能把缺失的 user-card scope 当作授权。REFRESH credential 两类主体都不带业务卡字段，由 Identity 按持久化 session 重新读取并在 PlatformUser 路径重新校验目标 user-card。Learn App 登录不是 Gateway HMAC v3 身份转发的替代路径，而是 `astral-internal-v1` 的 Learn → Gateway → Identity 会话签发链；Gateway HMAC v3 用于 Gateway → 下游服务的可信身份转发，两个签名域必须保持分离。

## 2. 两张卡与 owner 边界

| 对象 | 当前职责 | 当前 owner / 主要生产者 | 当前消费者与约束 | 证据 |
|---|---|---|---|---|
| `identity_card` | 认证身份事实：`user_id`、ACTIVE 状态、token version、有效期；不承载 tenant/domain scope | Identity 的 `CardRepository` 负责查询/确保 App 会话所需的 ACTIVE identity card；Identity 登录、App 内部会话签发和 access token 生产使用它 | Gateway 注入 `x-identity-card-id`；下游把它映射到 `PolicyContext.identity_card_id`；资格服务只用它做身份线路检查 | [`card_repository.rs:16-49`](../../../astral-identity/src/srv/card_repository.rs#L16-L49)、[`internal.rs:389-411`](../../../astral-identity/src/srv/internal.rs#L389-L411)、[`context.rs:21-24`](../../../astral-types/src/context.rs#L21-L24) |
| `user_card` | 授权卡实例：卡类型、模板/等级、ACTIVE 与有效窗口、`tenant_id`、`domain_id`；承载业务授权 scope | TrustGraph 的 user-card API/repository 负责管理与读取；Identity 在登录、刷新、切卡时消费所选卡并重签 access | Gateway 注入 `x-user-card-id`、`x-user-card-tenant-id`、`x-user-card-domain-id`；`PolicyContext.card_id` 指向它；不得从 identity 侧 scope 回退 | [`user_cards.rs:189-250`](../../../astral-trustgraph/src/api/user_cards.rs#L189-L250)、[`user_card_repository.rs:90-138`](../../../astral-trustgraph/src/repository/user_card_repository.rs#L90-L138)、[`permission_check_shared.rs:123-165`](../../../astral-common/src/middleware/permission_check_shared.rs#L123-L165) |

### 2.1 当前身份事实与授权事实

- `CardEligibilityService::verify_platform_card_pair` 要求 `identity_card.user_id == user_card.user_id == 请求 user_id`，身份卡只检查归属、ACTIVE、过期；tenant/domain 只从 user-card 与组织关联读取。见 [`eligibility.rs:81-155`](../../../astral-db/src/eligibility.rs#L81-L155)。
- 权威 SQL 同时约束 `platform_user` ACTIVE、`user_card` ACTIVE/非模板/有效窗口、`identity_card` ACTIVE/未过期、tenant ACTIVE 与 `tenant_domain_map` ACTIVE；tenant/domain 不能从 identity-card 线路补齐。见 [`eligibility.rs:236-277`](../../../astral-db/src/eligibility.rs#L236-L277)。
- user-card 的管理范围也只读取 `x-user-card-tenant-id` / `x-user-card-domain-id`，明确禁止回退到 identity 侧字段。见 [`user_cards.rs:189-204`](../../../astral-trustgraph/src/api/user_cards.rs#L189-L204)。

### 2.2 owner 结论

**当前事实**：Identity owner 认证身份与 session/token；TrustGraph owner user-card、模板、规则和授权投影。Identity 可以在签发时读取 user-card，但这不改变 user-card 的领域 owner。Learn 只消费已签发的 principal/context，并通过公共权限中间件进入 `PolicyEngine`。

**缺口**：历史 baseline 仍把两张卡描述成旧字段组合，不能单独作为当前运行 schema 证据，见第 10 节。任何跨 owner 的卡片变更仍需同时检查 session projection、eligibility projection、规则快照和审计副作用。

**目标决策**：继续保持双卡物理分离；所有需要业务授权的路径必须显式要求 PlatformUser 的完整 user-card scope；任何新的身份头、JWT claim 或 session 字段都必须明确属于 identity namespace 或 user-card namespace，不允许使用模糊的 `card_id` 语义。

## 3. `PolicyContext` 映射

`PolicyContext` 当前同时保存主体、双卡、组织、资源和动作字段。`identity_card_id` 与 `card_id` 是不同字段；`domain_id` / `tenant_id` 的来源是 user-card。见 [`context.rs:7-85`](../../../astral-types/src/context.rs#L7-L85)。

### 3.1 Gateway 头到上下文

| Gateway 头 | `PolicyContext` 字段 | PlatformUser | AppUser |
|---|---|---:|---:|
| `x-user-id` | `user_id` | 必须为正数 | 必须为正数 |
| `x-principal-kind` | `principal_kind` | `PLATFORM_USER` | `APP_USER` |
| `x-identity-card-id` | `identity_card_id` | 必须存在 | 必须存在 |
| `x-user-card-id` | `card_id` | 必须存在 | 必须不存在 |
| `x-user-card-tenant-id` | `tenant_id` | 必须存在 | 必须不存在 |
| `x-user-card-domain-id` | `domain_id` | 必须存在 | 必须不存在 |
| 路径映射与方法 | `resource` / `action` | 由 service middleware 解析 | 仅 identity-only 路径可使用 |
| 显式 query ID | `target_id` | 作为对象级授权目标 | 仅在允许的 identity-only 业务中可用 |

映射函数对 PlatformUser 缺任一 user-card 字段返回 `FORBIDDEN`，对 AppUser 明确返回 `(None, None, None)` 的 user-card scope；它不会把 identity-card 的任何 tenant/domain 旧头转换成授权 scope。见 [`permission_check_shared.rs:103-166`](../../../astral-common/src/middleware/permission_check_shared.rs#L103-L166)。

### 3.2 PolicyEngine 入口

Identity、Learn、TrustGraph 的业务权限中间件都先调用共享 `physical_policy_context`，再调用 `state.engine.evaluate(&ctx, &repo)`；路由未匹配资源映射或上下文缺失时拒绝。TrustGraph 的具体入口见 [`permission_check.rs:120-180`](../../../astral-trustgraph/src/api/permission_check.rs#L120-L180)，Identity 的对应入口见 [`middleware.rs:114-128`](../../../astral-identity/src/middleware.rs#L114-L128)，Learn 的对应入口见 [`learn/middleware.rs:107-136`](../../../astral-learn/src/middleware.rs#L107-L136)。

**当前事实**：AppUser 只在 Learn 的 `learn-app-users` service 且主体为 `APP_USER` 时被显式放行；登录/登出认证端点也在资源策略之外。见 [`learn/middleware.rs:116-129`](../../../astral-learn/src/middleware.rs#L116-L129)、[`learn/middleware.rs:258-279`](../../../astral-learn/src/middleware.rs#L258-L279)。

**缺口**：`/v1/app/learn` 使用与管理端相同的物理上下文与 PolicyEngine 入口，而 AppUser 上下文没有 user-card scope。当前代码能够证明“identity-only 被保留并拒绝补 scope”，但不能仅凭中间件源码证明所有 App Learn 业务都具备可用的 AppUser 授权模型；需要按实际路由和运行数据补充契约测试或明确其身份-only 边界。

## 4. SessionGrant 与身份头

### 4.1 SessionGrant producer / consumer

`SessionGrant` 存储在 `access:grant:{jti}`，生产结构与 Gateway 消费结构字段一致，`formatVersion` 当前为 `2`。生产结构见 [`auth.rs:421-472`](../../../astral-identity/src/auth.rs#L421-L472)，Gateway 反序列化与校验见 [`gateway/middleware.rs:167-267`](../../../astral-gateway/src/middleware.rs#L167-L267)。

| 字段 | producer 语义 | consumer 校验/用途 |
|---|---|---|
| `formatVersion` | 固定 `2` | 仅接受 `2`，未知字段拒绝 |
| `principalKind` | `PLATFORM_USER` 或 `APP_USER` | 必须与 JWT principal 一致 |
| `userId` / `sessionId` | 用户与设备 session 绑定 | 与 JWT `sub` / `sid` 一致 |
| `identityCardId` | 两类 session 都带身份卡 ID | 必须为正数，且与 JWT 一致 |
| `userCardId` | PlatformUser 带；AppUser 为 `null` | PlatformUser 必须为正数并一致；AppUser 必须为空 |
| `userCardTenantId` / `userCardDomainId` | PlatformUser 的 user-card 组织 scope；AppUser 为空 | PlatformUser 必须为正数并一致；AppUser 必须为空 |
| `sessionVersion` / `sessionEpoch` | session 轮换栅栏 | 与 JWT 一致，阻止旧版本继续存活 |
| `tokenFamilyId` / `sessionState` | family 及 ACTIVE 状态 | 与 JWT/family 约束一致，非 ACTIVE 不接受 |
| `issuedAtEpochSecond` / `expiresAtEpochSecond` | grant 生命周期 | JWT 时间必须落在 grant 窗口内，grant 不能已过期 |

Identity 登录会用 PlatformUser 双卡字段写入 grant，见 [`auth_service.rs:398-429`](../../../astral-identity/src/srv/auth_service.rs#L398-L429)；Learn App internal-v1 会话用 AppUser + identity-only 字段写入 grant，见 [`internal.rs:549-585`](../../../astral-identity/src/srv/internal.rs#L549-L585)。Gateway 在 `EMIT` / `REQUIRE` 模式读取并按上述字段校验；`REQUIRE` 不匹配时拒绝，读取依赖失败时 fail-closed。见 [`gateway/middleware.rs:1099-1160`](../../../astral-gateway/src/middleware.rs#L1099-L1160)。

### 4.2 Gateway 注入与下游可信边界

ACCESS 校验通过后，Gateway 将 `x-user-id`、`x-identity-card-id`、`x-user-card-id`、user-card tenant/domain、principal、token 与权限摘要等头写入内部请求；refresh credential 在 Gateway 侧提前返回，不产生业务身份头。见 [`gateway/middleware.rs:1030-1034`](../../../astral-gateway/src/middleware.rs#L1030-L1034)、[`gateway/middleware.rs:1163-1219`](../../../astral-gateway/src/middleware.rs#L1163-L1219)。

Gateway 转发时只从认证后的头重新取值并将同一组字段绑定到 HMAC v3；客户端的敏感头不会直接覆盖这些值。见 [`gateway/proxy.rs:897-997`](../../../astral-gateway/src/proxy.rs#L897-L997)。

## 5. PlatformUser 与 AppUser

### 5.1 PlatformUser

当前 PlatformUser 登录流程要求选定 identity card 与 user card，调用 `verify_platform_card_pair` 作为最终签发门禁；成功后 ACCESS JWT 带 `identity_card_id`、`user_card_id`、user-card tenant/domain 与 session claim。见 [`auth_service.rs:205-290`](../../../astral-identity/src/srv/auth_service.rs#L205-L290)、[`auth.rs:200-248`](../../../astral-identity/src/auth.rs#L200-L248)。

PlatformUser 的业务权限链为：

```text
ACCESS JWT
  -> Gateway session/grant 校验与身份头注入
  -> Gateway HMAC v3
  -> Learn / Identity / TrustGraph gateway_signature_middleware
  -> physical_policy_context（双卡完整 scope）
  -> PolicyEngine.evaluate()
```

### 5.2 AppUser

AppUser 是一个独立的 `principal_kind` 会话形态，不等于“拥有一张隐含的 user_card”。Learn 登录流程先原子消费验证码、find-or-create `app_user`，再调用 `AppSessionIssuer` 请求内部会话；失败时对新建用户执行补偿删除。见 [`app_user_service.rs:21-39`](../../../astral-learn/src/service/app_user_service.rs#L21-L39)、[`app_user_service.rs:146-232`](../../../astral-learn/src/service/app_user_service.rs#L146-L232)。

Identity 收到内部请求后校验 active `app_user`，确保 ACTIVE identity card，并通过 `issue_access_token_for_identity_only` 生成 `APP_USER` ACCESS；该路径明确没有 user-card 绑定。见 [`internal.rs:341-411`](../../../astral-identity/src/srv/internal.rs#L341-L411)、[`internal.rs:467-498`](../../../astral-identity/src/srv/internal.rs#L467-L498)、[`auth.rs:251-293`](../../../astral-identity/src/auth.rs#L251-L293)。当前实现还要求该 `app_user` 存在 ACTIVE 的 platform identity mapping，见 [`card_repository.rs:115-143`](../../../astral-identity/src/srv/card_repository.rs#L115-L143)；这说明“AppUser principal”与“底层身份卡记录”并非同一概念。

AppUser 的允许边界是：身份-only 的 App 用户端点可以消费 `identity_card_id`，但任何需要 user-card、tenant 或 domain 授权的路径都必须拒绝或拥有另行定义且已测试的授权模型。测试已覆盖 AppUser 携带任一 user-card 头时拒绝、PlatformUser 缺任一 user-card 头时拒绝。见 [`gateway_contract_tests.rs:350-410`](../../../astral-common/tests/gateway_contract_tests.rs#L350-L410)。

## 6. Access、Refresh 与 internal-v1 三条链

### 6.1 ACCESS 链

1. Identity 负责签发 JWT；PlatformUser 使用双卡 access，AppUser 使用 identity-only access。见 [`auth.rs:200-293`](../../../astral-identity/src/auth.rs#L200-L293)。
2. Gateway 按路径先分类 credential policy，再解码 JWT。公共路径只有在没有 Authorization 时匿名放行；带 Bearer 的公共路径仍需通过 access 校验。见 [`gateway/middleware.rs:953-1008`](../../../astral-gateway/src/middleware.rs#L953-L1008)。
3. Gateway 检查 revoked JTI、`access:jti:{jti}` subject 投影，并按配置读取 `access:grant:{jti}`。见 [`gateway/middleware.rs:1066-1159`](../../../astral-gateway/src/middleware.rs#L1066-L1159)。
4. Gateway 注入可信身份头，代理为下游计算 HMAC v3；下游先验签，再使用身份头。见 [`gateway/proxy.rs:963-993`](../../../astral-gateway/src/proxy.rs#L963-L993)、[`gateway_signature.rs:65-74`](../../../astral-common/src/middleware/gateway_signature.rs#L65-L74)。

### 6.2 REFRESH 链

Gateway 的 refresh 与 switch-card 路由只接受 REFRESH；logout/revoke 接受 ACCESS 或 REFRESH。见 [`gateway/middleware.rs:505-523`](../../../astral-gateway/src/middleware.rs#L505-L523)。Identity refresh 会读取 refresh token 对应的持久化 session、校验 family/过期/版本，然后按主体重建身份上下文；PlatformUser 从 `current_user_card_id` 读取 user-card 并再次执行双卡资格检查，AppUser 保持无 user-card。见 [`session.rs:47-90`](../../../astral-identity/src/srv/session.rs#L47-L90)、[`session.rs:164-299`](../../../astral-identity/src/srv/session.rs#L164-L299)。

REFRESH JWT 自身不携带 identity card、user card、roles 或 permissions；它只携带 refresh 用的主体、session 和 family 元数据。见 [`auth.rs:295-338`](../../../astral-identity/src/auth.rs#L295-L338)、[`auth.rs:895-903`](../../../astral-identity/src/auth.rs#L895-L903)。因此 REFRESH 不能直接作为下游业务身份凭证。

### 6.3 `astral-internal-v1` 链

内部链与 Gateway HMAC v3 完全分离，签名 canonical payload 绑定 protocol、key id、caller、method/path/query、body hash、target user、timestamp、nonce、request id、idempotency key 和 route。常量与字段定义见 [`internal_signature.rs:1-31`](../../../astral-common/src/middleware/internal_signature.rs#L1-L31)，canonical payload、计算和验证见 [`internal_signature.rs:35-100`](../../../astral-common/src/middleware/internal_signature.rs#L35-L100)。

当前 App 登录链为：

```text
Client
  -> Gateway /v1/app/users/login
  -> Learn AppUserService
  -> Learn -- astral-internal-v1 / k-lg / learn-to-gateway --> Gateway
  -> Gateway -- astral-internal-v1 / k-gi / gateway-to-identity --> Identity
  -> Identity 签发 APP_USER ACCESS + REFRESH
```

- Learn 是 internal-v1 的第一段 producer，向 `/api/v1/auth/internal/sessions` 发送 `userId`、body hash、replay/idempotency 与 Learn→Gateway 签名。见 [`app_user_service.rs:41-115`](../../../astral-learn/src/service/app_user_service.rs#L41-L115)。
- Gateway 只在精确的 POST internal route 上运行专用断言中间件：禁止 query 与 Authorization，检查完整 internal headers、body hash、target user、时间窗、HMAC、replay 与 idempotency。见 [`gateway/middleware.rs:678-877`](../../../astral-gateway/src/middleware.rs#L678-L877)。
- Gateway 验证 Learn→Gateway 后，再以 Gateway→Identity 的 key/route 重签并转发请求；故障会释放内部幂等占位并通过 circuit breaker 返回错误。见 [`gateway/proxy.rs:257-455`](../../../astral-gateway/src/proxy.rs#L257-L455)。
- Identity 只接受 Gateway caller、Gateway route 和 Gateway→Identity key，并在 cryptographic verification 后才写 Redis replay/idempotency 状态；直接 Learn headers 或旧内部头被拒绝。见 [`internal.rs:136-221`](../../../astral-identity/src/srv/internal.rs#L136-L221)、[`internal.rs:224-315`](../../../astral-identity/src/srv/internal.rs#L224-L315)。

## 7. Gateway HMAC v3 与内部签名边界

| 项目 | Gateway HMAC v3 | `astral-internal-v1` |
|---|---|---|
| 目的 | Gateway 向下游证明请求及身份头来源可信 | 服务间证明调用者、完整请求和目标用户可信 |
| 主要方向 | Gateway → Identity / Learn / TrustGraph / 其他下游 | Learn → Gateway；Gateway → Identity |
| 绑定内容 | method/path、user/principal/token、双卡字段、token use、claims version、action/roles、timestamp | protocol/key/caller、method/path/query、body hash、target user、timestamp、nonce、request/idempotency、route |
| 接收方 | Identity/Learn/TrustGraph 的 `gateway_signature_middleware` | Gateway internal middleware 与 Identity internal assertion verifier |
| Gateway 自身 | 只生成，不给自身入口加下游验签中间件 | 精确 internal route 使用专用 verifier，绕过普通 Bearer policy |
| 失败语义 | 缺头、时钟偏差、主体/卡字段不一致、签名不匹配均拒绝 | 缺断言、body hash/签名/时间窗失败、replay/idempotency 冲突或 Redis 不可用均拒绝 |

v3 canonical payload 的字段顺序与前缀由 `compute_hmac_signature_v3` 固定，且 verifier 会按 principal kind 要求双卡字段的存在/缺失关系。见 [`gateway_signature.rs:18-63`](../../../astral-common/src/middleware/gateway_signature.rs#L18-L63)、[`gateway_signature.rs:215-280`](../../../astral-common/src/middleware/gateway_signature.rs#L215-L280)。Gateway HMAC v3 不接受 legacy v2；现有契约测试验证 v2 签名不会到达 handler。见 [`gateway_contract_tests.rs:461-478`](../../../astral-common/tests/gateway_contract_tests.rs#L461-L478)。

## 8. Gateway 及三服务 middleware 矩阵

### 8.1 服务挂载矩阵

| 服务 / 路由 | Gateway 入口行为 | 服务侧签名边界 | 服务侧权限行为 | 例外 / 备注 |
|---|---|---|---|---|
| Gateway `/api/v1/auth/**`、`/v1/admin/learn/**`、`/v1/app/learn/**`、`/v1/app/users/**`、`/main/api/v1/**` | 先清洗客户端敏感身份头，再执行 route credential policy 与 JWT session/grant 校验 | Gateway 自己是 HMAC producer | 不执行下游 `gateway_signature_middleware` | 精确 internal session route 单独使用 internal-v1 verifier；Gateway route 表与层挂载见 [`main.rs:203-287`](../../../astral-gateway/src/main.rs#L203-L287) |
| Identity `/api/v1/auth/**` | Gateway 转发的正常请求携带 v3 头 | `public_routes` 统一挂 `gateway_signature_middleware` | auth routes 挂 `identity_permission_middleware`；bootstrap/self-service 按路径例外 | internal routes 在 public_routes 外单独合并，使用自己的 internal-v1 verifier，不依赖 Gateway v3；挂载见 [`identity/main.rs:212-242`](../../../astral-identity/src/main.rs#L212-L242) |
| Learn `/v1/admin/learn/**` | Gateway 生成 v3 | 整个 Learn app 挂 `gateway_signature_middleware` | admin 使用 `learn_permission_middleware` | 所有业务资源先映射再进入 PolicyEngine |
| Learn `/v1/app/learn/**` | Gateway 生成 v3；AppUser 若无 user-card 仍只有 identity-only context | 同上 | 使用 `learn_app_permission_middleware`，当前未因 AppUser 自动跳过 | 需明确 AppUser 的 App Learn 授权能力或保持拒绝 |
| Learn `/v1/app/users/**` | 登录为 Gateway public route；登录后其他请求走 access | 整个 Learn app 仍验 v3 | `learn_app_user_permission_middleware`；`APP_USER` 对 profile 类资源有显式例外，login/logout 是认证例外 | 见 [`learn/main.rs:312-377`](../../../astral-learn/src/main.rs#L312-L377)、[`learn/middleware.rs:224-279`](../../../astral-learn/src/middleware.rs#L224-L279) |
| TrustGraph `/main/api/v1/**` | Gateway 生成 v3 | 整个主路由挂 `gateway_signature_middleware` | 所有资源路由挂 `permission_check_middleware`；未映射路径拒绝 | health 不在主业务 permission map 内；挂载见 [`trustgraph/main.rs:323-367`](../../../astral-trustgraph/src/main.rs#L323-L367) |

### 8.2 Gateway middleware 例外

1. `OPTIONS` 预检直接继续，不进入 Bearer 解码；精确 internal session route 直接交给专用 internal verifier，不进入普通 public/Bearer policy。见 [`gateway/middleware.rs:920-950`](../../../astral-gateway/src/middleware.rs#L920-L950)。
2. `sanitize_internal_auth_headers` 对精确 internal session route 保留 internal assertion 头；其他请求移除 internal headers 以及客户端伪造的敏感 auth/identity/gateway 头。见 [`gateway/middleware.rs:898-915`](../../../astral-gateway/src/middleware.rs#L898-L915)。
3. 匿名放行只适用于 Gateway 已注册的 public route 且没有 Authorization；一旦带 Bearer，即使路径是 public，也必须是有效的 access credential。见 [`gateway/middleware.rs:300-331`](../../../astral-gateway/src/middleware.rs#L300-L331)、[`gateway/middleware.rs:953-1008`](../../../astral-gateway/src/middleware.rs#L953-L1008)。
4. REFRESH 只作为 session capability 进入 Identity refresh/switch/logout/revoke，不读取 access grant，不产生业务身份头；ACCESS 才进入 Redis live-session 与 grant 校验。见 [`gateway/middleware.rs:1019-1034`](../../../astral-gateway/src/middleware.rs#L1019-L1034)。
5. Chat WebSocket 仅在 canonical chat route 将受控 subprotocol credential 转成普通 Bearer；其他路径不接受这种转换。见 [`gateway/middleware.rs:938-950`](../../../astral-gateway/src/middleware.rs#L938-L950)。

## 9. 卡资格、session switch 与 refresh

### 9.1 签发资格

- PlatformUser login 在选卡后调用双卡资格服务，失败即拒绝签发；见 [`auth_service.rs:257-290`](../../../astral-identity/src/srv/auth_service.rs#L257-L290)。
- PlatformUser refresh 读取 session 持久化的 `current_user_card_id`，重新读取 user-card 并调用同一资格服务；AppUser refresh 不读取 user-card；见 [`session.rs:193-299`](../../../astral-identity/src/srv/session.rs#L193-L299)。
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

- Identity 集成测试明确以 Docker MySQL 验证真实 `platform_user`、凭证、`identity_card`、`auth_token_family`、`auth_device_session` 列名与 FromRow 映射；测试默认不是无条件本地单元测试。见 [`identity/tests/integration.rs:1-9`](../../../astral-identity/tests/integration.rs#L1-L9)。
- Gateway contract tests 覆盖 v3 字段篡改、主体卡字段关系、缺字段、legacy v2 拒绝和 handler 不执行；见 [`gateway_contract_tests.rs:270-347`](../../../astral-common/tests/gateway_contract_tests.rs#L270-L347)、[`gateway_contract_tests.rs:413-478`](../../../astral-common/tests/gateway_contract_tests.rs#L413-L478)。
- 当前材料未把 migration 执行结果、实际 Redis `access:grant` 数据或各服务线上路由探活结果当作事实。需要运行环境证据时，应补充对应部署/集成测试记录，而不是从源码推断部署一致性。

## 11. 当前事实、缺口、目标决策

| 主题 | 当前事实 | 当前缺口 | 目标决策（未实施声明） |
|---|---|---|---|
| 双卡 ownership | Identity 生产/消费 identity-card 身份事实；TrustGraph 管理 user-card 与授权 scope | 历史 baseline 与 runtime canonical 字段漂移 | 维持单一 owner，跨 owner 只通过明确 DTO/查询契约交互 |
| 上下文映射 | `physical_policy_context` 强制 PlatformUser 双卡，AppUser identity-only | AppUser 对 `/v1/app/learn` 的业务授权边界未由统一契约完全说明 | 为每条 App 路径明确 identity-only 或 user-card-required，并以测试锁定 |
| SessionGrant | producer/consumer 已有 v2 字段契约，Platform/App 条件分支明确 | 运行环境 grant mode、Redis projection 完整性仍需部署验证 | 继续以 grant + session version/epoch 作为 access live gate，失败 fail-closed |
| ACCESS / REFRESH | ACCESS 承载身份，REFRESH 不承载业务卡；refresh 重新读取 session/card | 切卡注释与实际 refresh token 轮换语义不完全一致 | 明确 family 保留、refresh 是否轮换、projection 删除与 CAS 顺序，并补回归测试 |
| internal-v1 | Learn→Gateway→Identity 有双段签名、body hash、replay/idempotency | 未证明所有未来内部调用都不会复用 Gateway v3 或 legacy internal header | 内部调用统一声明 caller/key/route，禁止把 Bearer 或 v3 身份头当服务间认证 |
| Gateway HMAC v3 | Gateway 生成；Identity/Learn/TrustGraph 验证；v2 测试拒绝 | 运行时密钥配置和多服务部署一致性不由源码证明 | v3 只用于 Gateway→下游可信转发，服务间调用继续使用 internal-v1 |
| middleware | 三个服务的主业务入口均有 v3 verifier；Identity internal route 有专用 verifier | skip/public/identity-only 例外较多，新增 route 易遗漏矩阵 | 新增路由必须同时登记 Gateway route policy、服务签名层、权限层和测试 |
| schema | auth family/session 有 canonical migration；integration test 记录真实列契约 | identity/user-card baseline 仍是旧形态，不能单独作为部署基线 | 将 runtime 所需 identity/user-card schema 形成可验证 canonical migration，并在 CI/集成环境执行 |
| 审计与副作用 | 登录、内部会话、切卡、权限决策已有审计调用；切卡 adapter 记录 CardSwitch | 异步审计和 projection 的运行失败重试/最终一致性仍需按环境核验 | 权限/卡片/session mutation 保持审计、幂等、补偿与 fail-closed 验收 |

## 12. 证据索引与维护边界

本文件最小证据集合如下：

- 双卡与资格：[`permission_check_shared.rs:103-166`](../../../astral-common/src/middleware/permission_check_shared.rs#L103-L166)、[`context.rs:7-85`](../../../astral-types/src/context.rs#L7-L85)、[`eligibility.rs:236-307`](../../../astral-db/src/eligibility.rs#L236-L307)。
- Gateway route/internal/auth/forward：[`gateway/main.rs:203-287`](../../../astral-gateway/src/main.rs#L203-L287)、[`gateway/middleware.rs:678-877`](../../../astral-gateway/src/middleware.rs#L678-L877)、[`gateway/proxy.rs:257-455`](../../../astral-gateway/src/proxy.rs#L257-L455)、[`gateway/proxy.rs:866-997`](../../../astral-gateway/src/proxy.rs#L866-L997)。
- Learn AppUser producer：[`app_user_service.rs:41-115`](../../../astral-learn/src/service/app_user_service.rs#L41-L115)。
- Identity internal/auth/session：[`internal.rs:136-221`](../../../astral-identity/src/srv/internal.rs#L136-L221)、[`auth.rs:251-338`](../../../astral-identity/src/auth.rs#L251-L338)、[`session.rs:47-90`](../../../astral-identity/src/srv/session.rs#L47-L90)、[`session.rs:1021-1563`](../../../astral-identity/src/srv/session.rs#L1021-L1563)。
- 三服务 middleware：[`identity/main.rs:212-242`](../../../astral-identity/src/main.rs#L212-L242)、[`learn/main.rs:312-377`](../../../astral-learn/src/main.rs#L312-L377)、[`trustgraph/main.rs:323-367`](../../../astral-trustgraph/src/main.rs#L323-L367)。
- 规范边界：[`Rust 后端编码规范`](../../规范/Rust后端编码规范_V1.0.md)、[`BACKEND_STANDARD`](../../规范/Rust后端编码规范_V1.0.md)、[`统一接口路径规范 V5`](../../规范/统一接口路径规范_V5.md)。

维护本文时，先重新核对源码、schema/migration 和测试，再更新当前事实与行号；不要把目标决策写成已完成，不要用历史 Java/JSA 文档覆盖 Rust 当前证据。任何工程规范变化仍只修改 `Docs/规范/` 与按 AGENTS.md 要求同步的入口文件；本任务不修改既有文档。
