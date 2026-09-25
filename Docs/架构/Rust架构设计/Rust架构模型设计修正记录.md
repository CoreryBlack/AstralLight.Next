# Rust 架构模型设计修正记录

> 版本：V1.0
> 日期：2026-08-10
> 状态：**活文档** — 当前所有 Rust 链路问题统一在此登记，后续新问题按编号追加。
> 文档性质：**非规范性架构设计/证据材料**。工程规范与实施约束以 [Docs/规范/](../../规范/) 和仓库根目录 [AGENTS.md](../../../AGENTS.md) 为准。
> 格式：每条 = **问题陈述 → 核实记录 → 修正决策**（言简意赅）。
> 规则：先核实后记录；核实必须基于代码/schema 只读事实；本文档是本目录的修正记录与证据索引，不替代 `Docs/规范/`；代码实施后更新状态。
> 关联：评估与处置细节见《物理双卡权限链路评估与设计_V1.0.md》；目标态见《物理双卡权限链路设计_V1.0.md》。

---

## 问题 1 — identity_card 承担 tenant/domain（建模错误）

### 问题陈述
identity_card 对应身份证，却承载 tenant_id/domain_id 作为 JWT identityTenantId/identityDomainId 来源。身份证不承担"属于哪个单位"，组织归属是成员关系、不是身份属性——单卡时代"card_id 承载一切"的复制残留。

### 核实记录
- canonical `full_schema_v4.sql`：identity_card 有 domain_id（注释"默认领域上下文"）/tenant_id 列。
- Rust baseline migration（20240630000001_baseline.sql）：identity_card **连这些列都没有**（与 canonical 漂移）。
- Rust 生产代码仅 `INSERT (user_id,status,token_version)`，**从不写** tenant/domain（仅测试夹具 UPDATE）。
- Java `IdentityCard` 实体有字段，`IdentityCardMapper` 无写入 SQL。
- Rust 约 20 文件读取该字段；部署库未填 → identityTenantId=None → 网关拒绝（死 token）。

### 修正决策
identity_card 回归纯身份证（user_id/status/token_version/expires_at），**不承担 tenant/domain**；组织归属由 **user_card 唯一承载**。
- JWT/header 移除 identityTenantId/identityDomainId；租户拦截改 `userCardTenantId`。
- `check_card_active` 撤销"双卡 tenant/domain 互相匹配"断言（保留 identity_card 归属/状态/expires_at + user_card 归属/状态/有效期 + user_card scope 有效）。
- ChatScope 去掉 identity 租户字段；D1 退化为两卡各自校验。
- 影响约 20 文件（token_contract/middleware/proxy/repository/context/auth/session/scope/trustgraph）。
- 前置核实：Java 是否依赖 identityTenantId；部署库 schema。
- **状态：已实施（2026-08-11）**：Rust claims/header/ctx/ChatScope/HMAC 已移除 identity tenant/domain 依赖，identity_card 只身份事实，user_card 唯一组织来源；静态扫描未发现 Java 依赖，但部署 schema/集成兼容仍待核实。

---

## 问题 2 — Rust baseline schema 与 canonical 漂移（R6）

### 问题陈述
`astral-db/migrations/20240630000001_baseline.sql` 的 identity_card 无 tenant_id/domain_id/expires_at/token_version 列，代码按 canonical（platform_v4）schema 引用——部署库与迁移漂移则运行期查询失败。

### 核实记录
- canonical identity_card：有 domain_id/tenant_id/expires_at/token_version/disabled_reason。
- Rust baseline identity_card：仅 id/user_id/card_number/password_hash/real_name/status/valid_from/valid_until/deleted_at。
- 代码大量引用 canonical 列（check_card_active、refresh、switch 等）。

### 修正决策
以部署库实际 schema 为准核实；问题 1 修正后 Rust 不再读 identity_card.tenant/domain，漂移暴露面缩小；expires_at/token_version 是否缺失需单独核对。
- **状态：待核实部署库**

---

## 问题 3 — Chat 会话/群组管理无物理 scope（R1）

### 问题陈述
会话/群组管理（sessions/groups handler、service、conversation_repository）仍以 user_id 主链路，创建写 `domain_id = 0`。

### 核实记录
- create_conversation/create_group 仍 `VALUES (?, ?, 0)`；member 操作按 (conversation_id, user_id)。
- 消息链路已 scope 化（is_member_scoped/list_member_scopes/insert_message_scoped）。

### 修正决策
Chat 冻结期内保持现状并记录为已知边界（消息链路已 fail-closed）；解冻后按 scoped 迁移（create_scoped 写真实 domain、handler 改 ChatScope、member scoped 化、跨租户回归）。conversation tenant 归属需 DDL，另评估。
- **状态：冻结中，解冻后实施**

---

## 问题 4 — 引擎 L2 失败可被委托遮蔽（R2，已修正）

### 问题陈述
`load_permission_rules`（L2）失败仅记录 repo_error 继续 L2.5；若委托 ALLOW 命中，最终仍 ALLOW——依赖故障可被委托遮蔽。

### 核实记录
- engine.rs L2 Err → repo_error，继续 L2.5；L2.5 命中 ALLOW → allow。
- L1 快照失败已 DENY 不降级；L2/L2.5 是两个独立聚合的独立读取。

### 修正决策
L2 repository error 必须在进入 L2.5 delegation 前终止授权聚合，返回 `DEPENDENCY_UNAVAILABLE`/PENDING；只有 L2 明确无匹配时才允许继续读取 L2.5。L2.5 使用 generation-gated projected delegation reader，raw/source reader 仅供 realtime/一致性巡检，不得作为正式授权 fallback。
- **状态：已实施（2026-08-22）**：`PolicyEngine` 在 L2 snapshot 读取错误时 fail-closed，正式 delegation 读取验证 CARD generation、source/projection 一致性和 snapshot rows；L2 error 不再被委托 ALLOW 遮蔽。

---

## 问题 5 — arbiter 端点接受请求体 ctx 无双卡复验（R3）

### 问题陈述
`trustgraph/api/arbiter.rs` 接受请求体 `ArbitrateRequest.context` 与证据 gate，无双卡复验。

### 核实记录
- handler 直接使用请求体 ctx 裁决；唯一防护为路由 monitor 权限中间件。

### 修正决策
handler 内用 `physical_policy_context(headers, ...)` 构建操作者 ctx 复验；请求体 ctx 仅作裁决证据输入，不与操作者授权混用。
- **状态：待实施（低成本）**

---

## 问题 6 — Learn app-users nest 对 APP_USER 整体放行（R4）

### 问题陈述
`astral-learn/middleware.rs` 对 learn-app-users + APP_USER 无条件 `return Ok(())`，nest 内全部路径 handler 级同用户校验兜底。

### 核实记录
- AppUser 仅可达 `/v1/app/users/**`；admin/app-learn 路径被引擎 CARD_REQUIRED 拒绝（无逃逸）。

### 修正决策
保持（设计内 identity-only 路径）；将 nest 子路径资源映射显式化（登录/登出外逐路径声明），并加代码评审巡检"app-users handler 必须有同用户校验"。
- **状态：设计内保持 + 巡检要求**

---

## 问题 7 — Monitor `/actuator/status` 无鉴权（R5）

### 问题陈述
`monitor/endpoints.rs` /actuator/status 在权限中间件之外，匿名可读各服务 reachability。

### 核实记录
- 仅返回服务状态/连通性，无身份/权限敏感字段；健康探针需匿名可达。

### 修正决策
保持公开（reachability 非敏感）；响应不返回身份/权限字段；未来暴露敏感指标时移入权限中间件覆盖路径。
- **状态：设计保持**

---

## 问题 8 — 签发层未强制双卡匹配（D1）

### 问题陈述
login/refresh/switch-card 三路径签发时未强制 identity_card 与 user_card 的 tenant/domain 匹配（错误前提下的双卡比对）；修正后语义为"两卡各自有效"。

### 核实记录
- 三处签发各自手写卡查询（find_login_cards/refresh 重读/load_active_switch_cards），无统一校验。
- 运行期由 check_card_active 兜底拒绝。

### 修正决策
落地 `CardEligibilityService::verify_platform_card_pair`（单条权威 SQL）供三处复用；按问题 1 修正后简化为 identity_card 校验 + user_card 校验（归属/状态/有效期/scope 有效），不再比对身份侧租户；tenantStatus 统一用 user_card tenant。
- **状态：已实施（2026-08-11）**：实现收敛至 `astral-db::CardEligibilityService`（`astral-db/src/eligibility.rs`），login/refresh/switch-card 三处签发复用 `verify_platform_card_pair`，switch 签发前补 tenant/domain ACTIVE 校验；运行期 `check_card_active_cached` 委托 `check_cached`，资格缓存绑定 ELIGIBILITY head。详细方案/边界/未覆盖项见问题 14。

---

## 问题 9 — check_card_active 专属校验通道改造（时间感知投影化缓存）

### 问题陈述
`check_card_active` 每请求实时 JOIN 四表，是与规则集快照并行的"专属校验通道"。过期（expires_at/valid_until）是**时间函数**、无失效事件，不能并入 rule_set_snapshot（快照是事件驱动版本化，到期无 DB 变更 → 若并入且不含时间，缓存 TTL 内会放行过期卡，违反不变式 6）。

### 核实记录
- 现有 `perm:card:active:{card_id}` 缓存 value 仅 `"1"`，且 `_cache_hit` 读而不校验（死代码，repository.rs）。
- `perm:refs` 已用 `refs_cache_compatible`（三项投影版本比对）——机制可复用。
- 卡状态写入方已全部走 projection（CARD_CREATED/UPDATE/DISABLED），无新增失效钩子需求。

### 修正决策
升级为**与规则集共用投影门禁的时间感知缓存**（问题 1 校验语义之上叠加）：
- value `"1"` → JSON `{ valid, expires_at, source_generation, projected_generation, revoke_fence }`；key 后缀**不变**（冻结约束满足，value 变更与 perm:refs 先例一致）。
- 命中判定：`valid == true && now < min(expires_at, TTL)`——到期由**读取侧时间比较**即时拒绝（时间驱动，不等事件，保持 fail-closed 即时性）。
- 未命中（冷启动/已到期/版本不匹配）→ 回实时 JOIN → 写缓存（带三项投影版本）；复用 `refs_cache_compatible` 语义。
- 吊销/禁用仍即时失效（投影 fence 版本不匹配 → miss）。
- Chat `revalidate_ws_scope` 复用同一缓存（TTL 可更短）。
- fail-closed 边界：缓存写失败不阻塞（后续重复 JOIN）；**缓存读失败回实时查询**（不允许"读失败即拒绝"，避免 Redis 单点）。
- 效果：鉴权 `check_card_active` 从 O(SQL×QPS) → O(Redis×QPS) + 冷启动 SQL；到期卡精确即时拒绝。
- 变更面：`astral-db/repository.rs`（check_card_active 缓存接线 + 清理 `_cache_hit` 死代码）、`astral-chat/src/srv/realtime.rs`（复用）；无 DDL。
- **状态：已实施（2026-08-10）**：`astral-db/src/repository.rs` 已将 `perm:card:active:{card_id}` 升级为物理上下文绑定、投影三版本校验和读取侧过期比较的 JSON 缓存；`PolicyEngine` 复用该校验，`astral-chat/src/srv/realtime.rs` 使用短 TTL + READY 门禁复用同一 helper。旧 `"1"` payload 按 miss 处理，缓存读失败回实时 JOIN，缓存写失败不放宽授权；未新增 DDL、Redis key 后缀或 MQ topology。

### 实施边界 / 后续缺口（2026-08-11 审查记录）

- `astral-db` 的 `check_card_active_cached` 已使用 **ELIGIBILITY** projection head 的 `source_generation`/`projected_generation`/`revoke_fence` + Redis JSON 资格缓存（2026-08-11 从 CARD head 切换，见问题 14），并以 `identity_card.expires_at` 与 `user_card.valid_until` 的最早值封顶 TTL。
- Identity login/refresh/switch 已统一复用 `CardEligibilityService::verify_platform_card_pair`（签发侧权威校验）；internal session（AppUser，identity-only）与 Gateway 仍使用 SQL/JWT 时间校验，未复用该 projection+cache（AppUser 无 user_card 事实，符合语义）。
- 当前没有 `identity_card.expires_at` 的 source mutation、`aggregate_type='IDENTITY'` projection head、outbox/MQ expiry event。
- 因而 DBA/外部直接修改 `expires_at` 不会有独立身份投影失效链，后续需在新规范中定义。

> 本次仅记录审查结论，不改变现有 DDL、Redis key、MQ topology。

---

## 问题 10 — `/actuator/health` 可能被 JWT 默认 AccessOnly 拦截

### 问题陈述
`/actuator/health` 未在 `route_credential_policy` 中显式声明，命中 `_ => AccessOnly` 默认分支；无 Authorization 头时 JWT 中间件返回 401，健康 handler 不可达。`/api/health` 同样可能受影响（同一中间件覆盖全 Router）。

### 核实记录
- `astral-gateway/src/middleware.rs` 的 `jwt_auth_middleware` 调用 `route_credential_policy_with_config`；该函数经 `configured_public_route` 判断公共路由。
- `configured_public_route` 先要求请求方法和路径命中 Gateway 内置 `APPROVED_PUBLIC_ROUTES`，再按 `config.public_paths` 过滤：`public_paths` 为空时不增加限制，否则必须命中配置项。
- `astral-common/src/config/mod.rs` 的默认 `public_paths` 仍包含 `/actuator/health`、`/api/health`、`/api/health/**` 等路径，但这些健康路径当前不在 `APPROVED_PUBLIC_ROUTES`；因此仅出现在配置中不会使它们成为匿名公共路由。
- `astral-gateway/src/main.rs` 注册 `/actuator/health`、`/api/health`、`/api/health/{*path}` 路由，并对整个 Router 加 JWT layer；健康路径未命中批准公共路由时仍受默认 `AccessOnly` 约束，无 Authorization 头会被拦截。

### 修正决策
待定。候选方向：JWT 中间件按 `config.public_paths` 前缀放行健康探针路径，或在网关路由层对健康路径免除 JWT layer；现状行为需运行验证确认后再定。
- **状态：代码级观察，待运行验证；修正决策待定**

---

## 问题 11 — 未知路径在路由 fallback 前被全局 JWT 中间件拦截

### 问题陈述
未知路径可能在 axum 路由 fallback（默认 404）之前就被全局 JWT 中间件拦截：无 token 时返回 401 而非 axum 默认 404。

### 核实记录
- `astral-gateway/src/main.rs` 无自定义 fallback（未调用 `Router::fallback`），JWT layer 包裹整个 Router。
- `astral-gateway/src/middleware.rs` `route_credential_policy` 对未知路径默认 `_ => RouteCredentialPolicy::AccessOnly`。
- `astral-gateway/src/middleware.rs`：非 `AnonymousOnly`/`InternalOnly` 且无 token → 401。

### 修正决策
这是 fail-closed 路由策略与 HTTP 404 语义之间的设计待决问题，不直接认定为安全漏洞（无 token 被拒属 fail-closed，未产生越权暴露面）；未知路径是否应返回 404 以对齐 HTTP 语义需决策后实施。
- **状态：待决策，待运行验证**

---

## 问题 12 — identity_card / user_card 双线路与对应关系证明边界

### 问题陈述
当前鉴权链路中 identity_card 与 user_card 的事实确认、双卡对应关系证明与授权判断在实现层合并，职责边界未显式化——身份线路易被误认为可提供组织/授权事实，授权线路易在对应关系证明前被提前触发。

### 核实记录
- 问题 1 已确认 identity_card 回归纯身份证（user_id/status/token_version/expires_at），不承担 tenant/domain；组织归属由 user_card 唯一承载。
- 问题 8 已将签发校验（CardEligibilityService）简化为 identity_card 校验 + user_card 校验（归属/状态/有效期/scope 有效），不再比对身份侧租户。
- 当前代码映射：`physical_policy_context` 从已验签头构造物理上下文；`check_card_active`/Repository 权威校验逻辑上承担身份事实、用户卡事实与双卡对应关系的联合证明；`PolicyEngine` 承载后续规则集评估。
- PlatformUser 与 AppUser 线路差异：AppUser 仅可达 identity-only 路径（问题 6 已记录），无 user_card 事实来源。

### 修正决策
- **identity_card 线路只确认身份事实**：用户、身份卡归属、状态、expires_at、会话身份锚点；identity_card 不承担 tenant/domain，不负责资源、动作、rule_set 或授权结论。
- **user_card 线路只确认授权与组织事实**：用户卡归属、状态、valid_from/valid_until、tenant/domain 及组织状态；它是后续授权主体，但在线路本身只确认事实，不提前做资源权限判断。
- **中间层是"对应关系证明"**：证明 identity_card 与 user_card 属于同一 user_id，并与当前 Token/SessionGrant 声明一致；tenant/domain 来源只能是 user_card；不得用 identity_card 回退或提供组织范围。
- **对应关系证明成功后，才进入 `user_card + 对应 rule_set` 的授权线路**：解析 resource/action/target，解析 BASE/OVERLAY rule_set，执行规则集、permission_rule、委托和 DEFAULT_DENY；资源和权限属于 user_card 授权线路，不属于 identity_card 线路或对应关系证明层。
- **当前代码映射**：`physical_policy_context` 负责从已验签头构造上下文；`check_card_active`/Repository 权威校验逻辑上承担身份事实、用户卡事实与双卡对应关系的联合证明；`PolicyEngine` 后续规则集评估应被记录为 user_card 授权阶段。若当前实现把这些步骤合并，明确这是实现合并而非职责混淆的目标边界。
- **平台用户与 App 用户**：PlatformUser 必须走完整两条事实线路并通过对应关系；AppUser 只有 identity-only 线路，不能伪造 user_card，进入需要 user_card 的授权线路应拒绝或走明确的 AppUser 专用路径。
- **状态：方案已确认，代码边界拆分待实施**

---

## 问题 13 — Rust Gateway HMAC v3 与 `astral-internal-v1` internal session 两跳协议边界

### 问题陈述
`Gateway→下游` 的业务转发 HMAC v3 与 AppUser internal session 的服务间断言语义未在修正记录中分离，容易把 Learn→Gateway→Identity 的两跳 internal control flow 误写成 Learn 直连 Identity，或把 `astral-internal-v1` 误写成普通 Gateway HMAC v3。当前需要记录两套协议的 producer/consumer、路由注册、Identity-only 会话签发及其与 PlatformUser 双卡策略链的边界。

### 核实记录
- Gateway HTTP/WS 业务转发继续使用 `compute_hmac_signature_v3`，下游 `gateway_signature_middleware` 只接受 Gateway HMAC v3；该结论与 internal session 协议分开记录。
- Learn 冻结源码的 `HmacAppSessionIssuer` 使用 `gateway_service_uri`（[app_user_service.rs:42](../../../astral-learn/src/service/app_user_service.rs#L42)），向 Gateway `POST /api/v1/auth/internal/sessions` 发送 `astral-internal-v1` Learn→Gateway assertion。
- Gateway 在 [main.rs:205](../../../astral-gateway/src/main.rs#L205) 注册该 exact route；专用 middleware 在 [middleware.rs:680](../../../astral-gateway/src/middleware.rs#L680) 接收请求，并从 [middleware.rs:755](../../../astral-gateway/src/middleware.rs#L755) 起校验用户、协议、caller、route、时间戳、nonce、body hash、request id、幂等键和签名。
- Gateway 的 [proxy.rs:257](../../../astral-gateway/src/proxy.rs#L257) `forward_internal_session` 不透传 Learn assertion，而是使用 Gateway caller/route/key-id 与 Gateway internal secret 生成 Gateway→Identity 的另一跳 `astral-internal-v1` assertion。
- Identity 在 [internal.rs:341](../../../astral-identity/src/srv/internal.rs#L341) 处理内部会话请求，在 [internal.rs:389](../../../astral-identity/src/srv/internal.rs#L389) 确保 active identity card，并通过 [auth.rs:251](../../../astral-identity/src/auth.rs#L251) 的 identity-only access token 与 [auth.rs:295](../../../astral-identity/src/auth.rs#L295) 的 AppUser refresh token 签发路径创建会话。该 AppUser 会话没有 user-card 事实，因此绕过普通 PlatformUser 双卡策略链，但不是未认证或未受保护的直连。

### 修正决策
- Gateway HTTP/WS 业务转发继续保持 **Gateway HMAC v3-only**：下游验签只接受 Gateway HMAC v3，v2 接受路径下线；既有 v2 拒绝测试与 v3 golden 测试结论保持有效。该结论不适用于 `astral-internal-v1` internal session assertion。
- `astral-internal-v1` 作为独立 internal wire protocol：Learn→Gateway 与 Gateway→Identity 各自使用对应 caller、route、key-id 和 internal secret；Gateway 必须先验证前一跳，再生成并转发后一跳，不得把 Learn assertion 原样透传给 Identity。
- AppUser internal session 的 identity-only access/refresh 签发路径保持现状：它绕过普通 PlatformUser 双卡策略链，但仍是经过 Gateway assertion 校验、Identity assertion 校验、重放/幂等控制与审计保护的已认证内部控制流。
- 正式 internal contract crate、两跳 producer/consumer 的统一声明及契约测试仍属于阶段 B/阶段 F 目标门禁；不得把该目标态要求倒写成当前 Learn 直连 Identity 或 Gateway 未注册端点。
- **状态：当前代码链路已核实（2026-08-22 文档修正）**；`astral-learn` / `astral-chat` 仍处于 exclude 编译冻结态，完整 workspace 与 excluded crate 的运行验证仍待解冻后补做。

---

## 问题 14 — 公共资格服务 + CARD/ELIGIBILITY/RULE_SET 三条投影通道（D1 落地与分离）

### 问题陈述
问题 8 的 D1 统一签发校验与运行期资格校验需要单点权威实现；同时 `perm:card:active:{card_id}` 此前被 `check_card_active_cached` 当作"投影缓存"误绑定 CARD projection head，卡片资格（身份过期/user_card 有效期）是**时间函数**而非事件驱动快照，需要与规则快照（`rule_set_snapshot`/`permission_rule_snapshot`）分离为独立通道，避免"资格事件触发全量规则重建 / CARD refresh"的过度失效。

### 核实记录
- **资格服务（已建立）**：`astral-db::CardEligibilityService`（`astral-db/src/eligibility.rs`）提供：
  - `verify_platform_card_pair`：签发侧权威校验，单条 JOIN（`query_card_active_row`）同时验证两条事实线路 + 对应关系证明 + user_card 组织有效性；identity 只读身份事实（归属/状态/expires_at），**不读 tenant/domain**；
  - `check_cached`：运行期资格检查（时间感知 `perm:card:active:{card_id}` 缓存 + 权威 SQL 回退），兼容 wrapper `check_card_active_cached[_with_options]`（`astral-db/src/repository.rs`）；
  - login（`astral-identity/src/srv/auth_service.rs::login_inner`）、refresh / switch（`astral-identity/src/srv/session.rs`）统一调用 `verify_platform_card_pair`；switch 签发前补 user_card tenant/domain ACTIVE 校验（原 `load_active_switch_cards` 缺口闭合）。
- **资格缓存（不是规则快照）**：`perm:card:active:{card_id}` payload 明确 `projection_type=ELIGIBILITY`，绑定 ELIGIBILITY head 的 source/projected/revoke 版本 + 物理双卡上下文；自然到期由读时 SQL/时间检查 + TTL 截断（`min(identity.expires_at, user_card.valid_until)` 封顶）fail-closed；旧 `"1"`/`"0"` scalar 与旧 JSON（无 `projection_type`）一律 miss 回权威 SQL。
- **投影通道（已建立）**：`astral-types::ProjectionAggregate::Card/Eligibility/RuleSet`（`astral-types/src/projection.rs`）为 head/outbox `aggregate_type` 唯一事实源；公共事务 helper `astral-db::append_projection_event_in_tx`（`astral-db/src/projection.rs`）与 source mutation 同事务写 head/outbox；TrustGraph 单 worker（`astral-trustgraph/src/service/projection_worker.rs`）按 aggregate 分派：
  - **CARD 通道**：重建 `permission_rule_snapshot` + 完整 CARD 缓存 evict + 推进 CARD head + 发布现有 CARD `permission.refresh`；PolicyEngine 的 CARD projection gate、L1/L2/L2.5/DEFAULT_DENY 语义不变；
  - **ELIGIBILITY 通道**：仅 evict `perm:card:active:{card_id}`（`side_effects::evict_eligibility_gate_cache`）+ 推进 ELIGIBILITY head，不重建规则快照、不发 CARD refresh；资格 head 不作为 PolicyEngine CARD gate（`check_cached` 内独立读取 ELIGIBILITY head，`require_projection_ready` 由调用方控制：Chat=true，PolicyEngine=false）；
  - **RULE_SET 通道**：由 RuleSet source mutation 同事务写 RULE_SET head/outbox，worker 重建共享 `rule_set_snapshot`、写 `projection_generation`、记录 correlated rebuild audit、失效规则集/绑定卡缓存并推进 RULE_SET head；正式读侧逐绑定规则集检查 READY/代次/快照证明，未 READY 不回读 source 放行；
  - 未知 aggregate fail-closed（release_failed 退避重试，绝不 mark processed）；`mark_aggregate_projected` 并发不推进时不发旧 CARD MQ、不标记 PROCESSED（superseded/retry 处置）。
- **写路径接入（已建立）**：Identity starter card 注册、user_card create/status（`astral-identity/src/srv/auth_repository.rs`、`srv/card_repository.rs`）同事务写 CARD + ELIGIBILITY 事件；TrustGraph user-card status/create/delete/restore/bind（`astral-trustgraph/src/repository/user_card_repository.rs`，`patch_affects_eligibility` 判定 card_status 变更才发资格事件）与 global-admin card status（`repository/global_admin_repository.rs`）同样接入。

### 修正决策
1. **资格服务与规则投影通道分离**：`perm:card:active` 为资格缓存（ELIGIBILITY head 门禁），卡级规则快照由 CARD 通道维护，共享规则集快照由 RULE_SET 通道维护；`20260822000002_snapshot_validity_windows.sql` 已为两张 snapshot 表补充 validity 列并修复可证明历史行，但当前 RuleSet worker INSERT 尚未写入 winner validity，且没有独立 wall-clock expiry scheduler/event，不能宣称 RuleSet 时间到期自动投影已完成。
2. **D1 已收敛**：签发侧统一 `verify_platform_card_pair`，运行期统一 `check_cached`，两套路径同语义互为兜底。
3. **五链边界**：
   - 调用链：三处签发调用方已统一到资格服务，错误映射 `map_eligibility_error`（NotEligible→业务码、Repository→Database，fail-closed）；
   - 逻辑链：ELIGIBILITY 事件不触发 CARD 重建，CARD gate 语义不变；`patch_affects_eligibility` 保证非资格字段变更不误发资格事件；
   - 事故链：Redis 读失败/解析失败回权威 SQL（不因缓存拒绝合法授权，也不因缓存放行过期卡）；TTL 以自然到期截断；worker 未知 aggregate / stale mark 一律 fail-closed；
   - 数据链：head/outbox 按 aggregate_type 分离，source mutation 与事件同事务；RULE_SET snapshot 以 `projection_generation` 绑定 head，validity migration 只修复可证明窗口行；缓存 payload 带 `projection_type`，旧 scalar/旧 JSON 显式 miss；
   - 审计链：CARD refresh 仍发现有 permission.refresh；ELIGIBILITY 通道不发 CARD MQ；RULE_SET source/rebuild 使用 event/generation/operation correlation，资格与授权决策仍分别走既有审计链。
- **状态：已实施（2026-08-11）**，`astral-learn`/`astral-chat` 处于 exclude 编译冻结态，完整 workspace 验证需在解冻后补做。

### 未覆盖项（诚实保留，未写成 ELIGIBILITY 事件已覆盖）
- tenant/domain status 变化**尚未**做可靠的 user_card 影响范围 fan-out（当前依赖运行期 JOIN；TrustGraph `update_tenant_status` 未写投影事件），不得宣称 ELIGIBILITY 事件已覆盖组织级停服。
- `identity_card.expires_at`/status **没有**正式更新入口/独立 source mutation 事件（无 `aggregate_type='IDENTITY'` head/outbox/MQ expiry event）；自然到期可读时拒绝，显式变更失效链仍待设计。
- `user_card.valid_from/valid_until` 当前**没有**正式更新 API；现有写入路径为 NULL/读时校验，未来更新必须走 ELIGIBILITY 事件。
