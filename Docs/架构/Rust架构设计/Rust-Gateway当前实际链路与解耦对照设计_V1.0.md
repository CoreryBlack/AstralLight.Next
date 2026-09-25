# Rust Gateway 当前实际链路与解耦对照设计 V1.0

> 版本：V1.0
> 日期：2026-08-11
> 适用：AstralLight-Rust（`` workspace）Gateway 层，以及与其相连的下游服务（Identity / Learn / Chat / TrustGraph / Monitor）。
> 读者：负责 Rust 服务边界重构、网关解耦的开发者与架构评审。
> 文档性质：**2026-08-11 当前态历史快照 + 解耦目标对照**。本文档记录该日期代码边界内的链路与耦合；目标态一律显式标注"目标态，非当前实现"，不代表 2026-08-22 已对全文重新核验。

---

## 1. 文档元信息与适用范围

### 1.1 元信息

| 项 | 内容 |
|----|------|
| 文档名 | Rust-Gateway 当前实际链路与解耦对照设计 V1.0 |
| 仓库相对路径 | `Docs/架构/Rust架构设计/Rust-Gateway当前实际链路与解耦对照设计_V1.0.md` |
| 版本 / 日期 | V1.0 / 2026-08-11 |
| 状态 | 历史快照：当前态（源代码边界为 2026-08-11 的 `AstralLight-Rust` 代码）+ 解耦目标对照 |
| 上游依据 | 《物理双卡权限链路设计_V1.0.md》《物理双卡权限链路评估与设计_V1.0.md》`Docs/规范/统一接口路径规范_V5.md` |

### 1.2 适用范围

- **覆盖**：`astral-gateway` 与 `astral-common` 的请求链路（路由匹配、凭证策略、JWT 验证、Redis 判定、身份头注入、HMAC 签名转发、下游验签、PolicyEngine 评估、审计），以及 Chat WebSocket 双向桥、断路器、Learn→Gateway→Identity 内部会话两跳链路。Learn 使用 `gateway_service_uri`，Gateway 校验 `astral-internal-v1` 的 Learn→Gateway 断言，再向 Identity 发送 Gateway→Identity 内部断言。
- **不覆盖**：Java 侧实现、前端权限展示、权限模型本身的设计评审、`Docs/规范/` 下的工程规范正文。
- **符号引用约定**：本文所有文件引用使用仓库相对路径（如 `astral-gateway/src/proxy.rs`），函数/符号名以代码中实际标识符为准；不记录任何 IP、密码、token、密钥。

### 1.3 当前态 / 目标态声明

- **当前态**：描述源代码边界为 2026-08-11 时 `AstralLight-Rust` 工作区中真实存在的行为，属于历史快照；本次仅对 `astral-gateway/src/middleware.rs` 的公共路径配置读取链路做局部复核，不代表全文已于 2026-08-22 重新验证。每个结论都尽量给出代码位置。凡是从代码阅读推断、未经运行验证的结论，标注"（代码级观察，待运行验证）"。
- **目标态**：第 7、9 章的"目标"小节全部为**目标设计，非当前实现**。本仓库其他设计文档（如《物理双卡权限链路设计_V1.0.md》）描述的目标态链条，若与当前代码不一致，以本文档"当前态"章节为事实基准。

---

## 2. 当前 Rust workspace 状态

### 2.1 workspace 成员与 exclude

来源：`Cargo.toml`（顶部注释原文：`# Learn/Chat 源码暂存但冻结：默认 workspace 不纳入这两个服务，待新规范建立后再恢复。`）。

```toml
members = [
    "policy-engine",
    "astral-types",
    "astral-common",
    "astral-db",
    "astral-cache",
    "astral-mq",
    "astral-gateway",
    "astral-identity",
    "astral-trustgraph",
    "astral-monitor",
]
exclude = ["astral-learn", "astral-chat"]
resolver = "2"
```

- **保留在 workspace 并参与编译**：`astral-gateway`、`astral-identity`、`astral-trustgraph`、`astral-monitor`、`astral-common`、`astral-db`、`astral-cache`、`astral-mq`、`astral-types`、`policy-engine`。
- **源码保留但已 exclude（编译冻结）**：`astral-learn`、`astral-chat`。两者源码仍在 `astral-learn/`、`astral-chat/` 下（各自含 `src/main.rs`、`src/service/`、`src/repository/`、`src/srv/` 等），但不参与 `cargo build` / `cargo test` 的 workspace 编译。

### 2.2 exclude 只表示编译冻结，不等于 HTTP 解耦

需要明确的事实（均有代码佐证）：

1. **Learn 仍依赖 Gateway 转发路径**：`astral-gateway/src/main.rs` 中硬编码注册 `/v1/admin/learn/{*path}`、`/v1/app/learn/{*path}`、`/v1/app/users/{*path}`、`/duo/v1/**`（learn 兼容）等路由，转发目标仍为 `config.learn_service_uri`（`astral-gateway/src/proxy.rs` 的 `forward_to_learn_admin` / `forward_to_learn_app` / `forward_to_learn_app_users` 等）。
2. **Chat 仍依赖 Gateway 转发与 WS 桥**：`forward_to_chat`（HTTP）与 `forward_chat_ws`（WebSocket 双向桥）均在 `astral-gateway/src/proxy.rs`。
3. **Learn 的内部会话请求经过 Gateway**：`astral-learn/src/service/app_user_service.rs::HmacAppSessionIssuer` 使用 `gateway_service_uri`，向 Gateway `POST /api/v1/auth/internal/sessions` 发送 `astral-internal-v1` 的 Learn→Gateway 断言（[app_user_service.rs:42](../../../astral-learn/src/service/app_user_service.rs#L42)、[app_user_service.rs:72-L103](../../../astral-learn/src/service/app_user_service.rs#L72-L103)）。Gateway 在 [main.rs:205-L221](../../../astral-gateway/src/main.rs#L205-L221) 注册该路由，在 [middleware.rs:680-L680](../../../astral-gateway/src/middleware.rs#L680) 及 [middleware.rs:789-L827](../../../astral-gateway/src/middleware.rs#L789-L827) 校验 Learn→Gateway 断言；随后 [proxy.rs:257-L383](../../../astral-gateway/src/proxy.rs#L257-L383) 以 Gateway→Identity 内部断言转发。Identity 在 [internal.rs:341-L365](../../../astral-identity/src/srv/internal.rs#L341-L365) 验证该内部请求，并在 [internal.rs:389-L400](../../../astral-identity/src/srv/internal.rs#L389-L400) 确保身份卡后，通过 [auth.rs:251-L293](../../../astral-identity/src/auth.rs#L251-L293) 的 identity-only 签发路径创建 AppUser 会话。该链路不等于 PlatformUser 的完整双卡策略链，但仍是已认证的内部控制流。
4. **Learn / Chat 仍引用 `astral-common` 的共享中间件**：`astral-learn/src/main.rs` 与 `astral-chat/src/main.rs` 均使用 `astral_common::middleware::gateway_signature::gateway_signature_middleware`、`astral_common::audit`、`astral_common::service`（MQ producer 抽象）等；exclude 仅使它们不再被 workspace 编译，源码层面的共享依赖原样保留。

因此：**exclude = 编译冻结；HTTP 解耦尚未开始**。后续解冻 Learn/Chat 时，共享依赖与内部会话 wire contract 必须先按第 7 章门禁处理。

### 2.3 workspace 级依赖（仅列与 Gateway 相关的关键项）

`Cargo.toml` 的 `[workspace.dependencies]`：`axum 0.8`、`tokio 1`、`tower 0.5`、`tower-http 0.7`、`reqwest 0.13`（json/rustls）、`jsonwebtoken 10`（rust_crypto）、`hmac 0.12`、`sha2 0.10`、`hex 0.4`、`redis 1`、`sqlx 0.8`、`lapin 4`、`time 0.3`、`uuid 1` 等。

---

## 3. Gateway 组件与依赖边界

### 3.1 组件清单

| 组件 | 位置 | 职责 |
|------|------|------|
| Gateway 入口 | `astral-gateway/src/main.rs` | 路由表注册、中间件链装配（CORS、全局异常、限流、清洗头、JWT）、健康检查 |
| 转发处理器 | `astral-gateway/src/proxy.rs` | 每上游断路器、路由前缀重写、请求体读取、HMAC v3 签名注入、HTTP 转发、WS 双向桥、501 桩、统一 JSON 错误 |
| JWT/清洗中间件 | `astral-gateway/src/middleware.rs` | `sanitize_internal_auth_headers`、`jwt_auth_middleware`、`verify_session_grant`、`SessionGrant`（消费侧定义）、`dependency_unavailable`；共享 JWT 解码 `decode_v2_token` / `JwtClaims` 仍在 `astral-common/src/middleware/mod.rs` |
| 速率限制中间件 | `astral-gateway/src/rate_limit.rs` | `rate_limit_middleware`、`RateLimiter`（基于 IP 的 bucket + 周期清理，配置注入自 `AppConfig.rate_limit`） |
| 凭证与路由契约 | `astral-gateway/src/middleware.rs`（`route_credential_policy_with_config` / `configured_public_route` / `RouteCredentialPolicy`，Gateway 本地）+ `astral-common/src/token_contract.rs`（`TokenUse` / `PrincipalKind` / 身份头常量，共享） | `config.public_paths` 仅对 `APPROVED_PUBLIC_ROUTES` 中的已注册 method/path 生效并映射为 `PublicOnly`；其余按凭证策略分类，未知路径默认 `AccessOnly`；共享 token purpose / principal kind / 身份头常量 |
| 网关签名 | `astral-common/src/middleware/gateway_signature.rs` | `compute_hmac_signature_v3`（Gateway 对下游唯一签名计算函数，HMAC v3-only）、`gateway_signature_middleware`（下游验签，只接受 v3） |
| 配置 | `astral-common/src/config/mod.rs` | `AppConfig`、`JwtConfig`/`JwtTokenProfile`、`GatewayCfg`、`session_grant_claims_mode`、密钥占位符校验 |
| 统一响应契约 | `astral-common/src/contract/mod.rs` | `ApiResponse<T>`、`PageResponse<T>`、`PaginationParams` |
| 统一错误 | `astral-common/src/error/mod.rs` | `AppError`、`global_exception_handler` |
| 共享权限检查 | `astral-common/src/middleware/permission_check_shared.rs` | `physical_policy_context`、`resolve_permission_action`、`check_permission`、`validate_path_map` |
| 审计 | `astral-common/src/audit.rs` | `AuditDualWrite`（MQ-first / DB-fallback）、`record_permission_audit` |

### 3.2 Gateway 依赖图（当前）

```
astral-gateway (bin)
  └─ astral-common      # JWT claims 解码（decode_v2_token/JwtClaims）/ HMAC 签名 / 配置 / 错误与响应契约（共享部分）
  └─ astral-types       # PolicyContext 等类型（间接经 astral-common）
  └─ axum / reqwest / tokio-tungstenite / tower / ...

astral-common（被 Gateway 与所有下游服务共享）
  ├─ astral-types        # PolicyError / PolicyContext / ResourceRegistry
  ├─ policy-engine       # PolicyEngine（permission_check_shared / service 依赖）
  ├─ redis / jsonwebtoken / hmac / sha2 / hex
  └─ axum / reqwest / tower / config / ...
```

**依赖边界说明（当前态）**：JWT claims 解码（`decode_v2_token` / `JwtClaims`）、HMAC 签名函数族（`gateway_signature`）、配置与统一响应/错误契约仍由 `astral-common` 共享；而 **Redis 会话/租户判定、清洗头、Gateway 错误 envelope、速率限制、路由凭证策略** 五个 Gateway 专属运行时已迁入 `astral-gateway`（`src/middleware.rs` 与 `src/rate_limit.rs`），Gateway 仅在共享契约层依赖 `astral-common`。

### 3.3 中间件执行顺序（当前）

`astral-gateway/src/main.rs` 按如下顺序 `.layer()`（axum/tower 语义：后 `layer()` 者在外层，先执行）：

```
TraceLayer → CORS → global_exception_handler → rate_limit_middleware
  → sanitize_internal_auth_headers → jwt_auth_middleware → 路由 handler
```

- 请求先过 `sanitize_internal_auth_headers`（剥离 `INTERNAL_AUTH_HEADERS`，共 30 个内部身份/网关头），再进入 `jwt_auth_middleware` 做凭证策略与 JWT 判定。
- `jwt_auth_middleware` 与 `proxy` 的转发函数均使用 axum 的 `State<AppConfig>` 注入配置。

> 执行顺序保持不变；`rate_limit_middleware`、`sanitize_internal_auth_headers`、`jwt_auth_middleware` 的实现位置已随 Gateway 专属运行时迁移至 `astral-gateway/src/middleware.rs` 与 `src/rate_limit.rs`，但中间件装配顺序与行为均不变。

### 3.4 关键符号清单（当前）

| 符号 | 位置 | 说明 |
|------|------|------|
| `route_credential_policy_with_config` / `configured_public_route` | `astral-gateway/src/middleware.rs` | 结合 `config.public_paths` 与 Gateway-owned `APPROVED_PUBLIC_ROUTES` 做公共路由门禁，再映射为 `PublicOnly` / `AccessOnly` / `RefreshOnly` / `AccessOrRefresh` / `InternalOnly`（未知路径默认 `AccessOnly`） |
| `jwt_auth_middleware` | `astral-gateway/src/middleware.rs` | 认证主流程（Step 0~6） |
| `decode_v2_token` | `astral-common/src/middleware/mod.rs` | typ/kid/alg/iss/aud 校验 + claims 校验（Gateway 与 Identity 共享） |
| `verify_session_grant` | `astral-gateway/src/middleware.rs` | `access:grant:{jti}` 版本化会话校验 |
| `sanitize_internal_auth_headers` | `astral-gateway/src/middleware.rs` | 剥离 30 个内部头 |
| `rate_limit_middleware` | `astral-gateway/src/rate_limit.rs` | 基于 IP 的速率限制（bucket + 周期清理，`AppConfig.rate_limit` 注入） |
| `compute_hmac_signature_v3` | `astral-common/src/middleware/gateway_signature.rs` | canonical payload 签名计算（HMAC v3-only；`compute_hmac_signature_v2` 已从生产代码移除） |
| `gateway_signature_middleware` | 同上 | 下游验签（只接受 v3，v2 签名拒绝） |
| `physical_policy_context` | `astral-common/src/middleware/permission_check_shared.rs` | 下游从身份头构建 `PolicyContext` |
| `forward` / `forward_chat_ws` / `bridge_websocket` | `astral-gateway/src/proxy.rs` | HTTP 转发与 WS 双向桥 |
| `CircuitBreaker` / `CB_LEARN`…`CB_CHAT` | 同上 | 每上游静态断路器 |
| `store_session_grant_in_redis` | `astral-identity/src/srv/session.rs` | `access:jti` / `access:grant` 写入方 |
| `issue_app_session` | `astral-identity/src/srv/internal.rs` | Learn App 登录内部会话签发端点 |
| `HmacAppSessionIssuer` | `astral-learn/src/service/app_user_service.rs` | Learn→Gateway 内部会话客户端（冻结源码） |

---

## 4. 从请求进入到下游的实际链路

### 4.1 主链路（HTTP）

#### ① 路由匹配 / forward handler

- `astral-gateway/src/main.rs` 注册全部路由（共 37 条，含 `/actuator/health` 与 36 条转发/桩路由）。转发/桩路由绑定 `astral-gateway/src/proxy.rs` 的 handler（`forward_*` 转发 / `not_implemented` 桩；`/actuator/health` 绑定 main.rs 内 `health_check`），`forward_*` handler 内先查对应上游 `CircuitBreaker` 是否 OPEN（打开则返回 503 `SERVICE_UNAVAILABLE`），再调用通用 `forward(&config, base_uri, rewritten_path, req)`。
- 未注册路径由 axum 默认 404（无自定义 fallback）。
- 兼容路径未实现的部分注册到 `proxy::not_implemented`（返回 501 `NOT_IMPLEMENTED`），包括：`/v1/app/users/checkins/{*path}`、`/v1/app/users/{user_id}/checkins`、`/v1/app/users/{user_id}/checkins/{*path}`、`/duo/v1/app/users/checkins/{*path}`、`/duo/v1/app/users/{user_id}/checkins`、`/duo/v1/app/users/{user_id}/checkins/{*path}`、`/ws`、`/ws/{*path}`。注意 `/v1/app/users/checkins` 与 `/duo/v1/app/users/checkins` 两个根路径**不是** 501 桩，实际注册到 `proxy::forward_to_learn_app_checkins_root`（重写转发 Learn `/v1/app/learn/checkins`）。
- **代码级观察（待运行验证）**：`/api/v1/auth/register`、`/api/v1/auth/profile`、`/api/v1/auth/change-password`、`/api/v1/auth/providers` 四个静态路由绑定了带 `Path(path): Path<String>` 参数的 `forward_to_identity`，而路由本身无捕获段。按 axum `Path` 提取器语义，无捕获段时提取失败会拒绝该请求（预期 400 而非转发）；此行为未经运行验证，需在解耦前确认。

#### ② 凭证策略与清洗头

- `sanitize_internal_auth_headers` 在 JWT 之前剥离 `INTERNAL_AUTH_HEADERS`（`x-user-id`、`x-card-id`、`x-identity-card-id`、`x-user-card-*`、`x-token-id`、`x-action-codes`、`x-gateway-*`、`x-internal-service-*`、`x-has-required`、`x-required-permission`、`x-resource-owner-id` 等 30 项），防止客户端伪造。
- `jwt_auth_middleware` Step 0：`OPTIONS` 直接放行；随后以 `route_credential_policy_with_config`（内部调用 `configured_public_route`）按 `method/path` 与 `config.public_paths` 进行公共路由门禁和凭证策略分类（见 §5.1）。`Authorization: Bearer` 头缺失时，仅 `PublicOnly` / `InternalOnly` 策略放行，其余 401 `UNAUTHORIZED`。

#### ③ JWT 验证

- `decode_v2_token`：按 JWT `typ`（`astral-access+jwt` / `astral-refresh+jwt`）分流到 access/refresh profile；校验 `kid`、算法（HS256/RS256）、`iss`、`aud`，然后 `validated_access_claims` / `validated_refresh_claims` 做 claims 级校验：
  - access：`claimsVersion==2`、`jti` 非空、`tokenUse==ACCESS`、`principalKind` 合法、`sid/sessionVersion/sessionEpoch/familyId` 全部 >0；PlatformUser 必须携带 `userCardId/userCardTenantId/userCardDomainId` 且 >0；AppUser 三个 user-card 字段必须全缺。
  - refresh：除基本 v2 校验外，`identityCardId/userCardId/.../tenantStatus/permissions/roles` 等授权上下文必须全缺。
- 凭证与路由策略匹配：`policy.accepts(token_use)` 不匹配 → 401 `TOKEN_ROUTE_MISMATCH`（该检查先于 `InternalOnly` 特判，见下方代码级观察）。
- **refresh 分支**：`token_use == Refresh` 时在完成 JWT 校验后**直接 `next.run` 放行**，不读 Redis、不注入身份头（refresh 凭证只是会话能力凭证，claims 授权上下文字段必须全缺）；请求随后经**标准 `proxy::forward` 路径**（HMAC v3，身份头字段为空）仅转发到 Identity 的 refresh 业务入口，**Gateway 认证职责到此结束**——会话续期/令牌轮换与 grant 重写由 Identity `srv/session.rs::refresh_token` 继续（见 §4.2、§9.1）。

#### ④ Redis revoked / access:jti / access:grant / tenant status

仅 access token 进入此阶段。`jwt_auth_middleware` 内用 `redis::aio::ConnectionManager`（3 秒超时）依次检查：

1. `EXISTS jwt:revoked:{jti}` → 存在则 401 `TOKEN_REVOKED`。
2. `GET access:jti:{jti}` → 标量值必须等于 JWT `sub`（OFF 模式同样强制值比对，防"投影残留仅剩 key"绕过）；不匹配/缺失 → 401 `SESSION_NOT_FOUND`。
3. `session_grant_claims_mode`（默认 `REQUIRE`）为 `EMIT` 或 `REQUIRE` 时 `GET access:grant:{jti}` 并 `verify_session_grant`（SessionGrant v2 JSON，见 §5.4）。`REQUIRE` 模式下校验失败 → 401 `TOKEN_REVOKED`；`EMIT` 模式读取失败 fail-closed（503）但校验结果不阻塞（对齐 Java）。
4. Redis 连接/读取任何一步失败 → `dependency_unavailable`：503 `SERVICE_UNAVAILABLE` + `Retry-After: 3`，fail-closed。

随后（Step 5/6）租户状态检查：
- 先查 JWT claims 内 `tenantStatus`（SUSPENDED/TERMINATED → 401 `TENANT_NOT_ACTIVE`）。
- 再查 `GET tenant:status:{tenant_id}`（`tenant_id` 来自 `userCardTenantId`，正数时才检查）。缓存缺失或 Redis 故障 → 503 fail-closed；SUSPENDED/TERMINATED → 401 `TENANT_NOT_ACTIVE`。

**注意**：当前仓库中 `tenant:status:{tenant_id}` 只有 Gateway 读取（`astral-gateway/src/middleware.rs` 的 `fetch_cached_tenant_status`），未找到任何 Rust 生产者写入该 key；生产写入方需在解耦前澄清（见 §6、§10）。

#### ⑤ 身份头注入

`jwt_auth_middleware` 从 claims 注入（Step 4~4.7）：

| 头 | 来源 |
|----|------|
| `x-user-id` | `sub` |
| `x-identity-card-id` | `identityCardId` |
| `x-user-card-id` / `x-user-card-tenant-id` / `x-user-card-domain-id` | `userCard*` |
| `x-template-id` / `x-tenant-status` | `templateId` / `tenantStatus` |
| `x-token-id` / `x-token-use` / `x-principal-kind` / `x-claims-version` | `jti` / `tokenUse` / `principalKind` / `claimsVersion` |
| `x-user-roles` | `roles`（逗号拼接） |
| `x-action-codes` | `derive_action_codes(roles)` → 当前恒为 `"read"`（见 §5.2 备注），超过 `max_permission_header_length`（默认 16000）时截断并置 `x-permissions-truncated: true` |
| `x-perms-ref` | `user-card:{userCardId}` |
| `x-request-id` / `x-trace-id` | 不存在时生成（`req-{jti前8}` / `jti`） |

AppUser 不注入 user-card 三头（claims 校验已强制其为空）。

#### ⑥ HTTP HMAC 签名转发

`astral-gateway/src/proxy.rs::forward`：

1. 读请求体（上限 10 MB）。
2. 提取 11 个身份头作为签名 payload（`x-user-id`、`x-token-id`、`x-identity-card-id`、`x-principal-kind`、`x-user-card-id`、`x-user-card-domain-id`、`x-user-card-tenant-id`、`x-token-use`、`x-claims-version`、`x-action-codes`、`x-user-roles`）。
3. 生成毫秒时间戳，调 `compute_hmac_signature_v3(hmac_secret, method, external_path, …)`。
4. 重建上游请求：`base_uri + rewritten_path + query`；转发客户端头时跳过 `x-gateway-*`、`x-forwarded-*`、`host`、`x-resource-owner-id`；注入 `X-Gateway-Auth: verified`、`X-Gateway-Ts`、`X-Gateway-Signature`、`X-Original-Path: external_path`（签名用外部原始路径，重写用内部路径）。
5. 上游响应透传：状态码 + 头（剔除 `transfer-encoding` / `connection`）+ 响应体；上游 502~504 计入断路器失败，其余计入成功。
6. 上游连接/读取失败 → 502 `BAD_GATEWAY`（统一 JSON）。

#### ⑦ 下游 gateway_signature 验签

- `gateway_signature_middleware`（`astral-common/src/middleware/gateway_signature.rs`）被 `astral-learn`、`astral-chat`、`astral-identity`、`astral-trustgraph`、`astral-monitor` 的 `main.rs` 装配（Gateway 自身不加，它是签名生产者）。
- 校验顺序：`x-gateway-auth == verified`（否则 403 `GATEWAY_AUTH_INVALID`）→ `x-gateway-ts` / `x-gateway-signature` 存在（否则 403 `GATEWAY_SIGNATURE_MISSING`）→ 时间戳偏差 ≤ `gateway.timestamp_tolerance_secs`（默认 30s；偏差过大 403 `GATEWAY_TIMESTAMP_SKEW`）→ 用 `x-original-path`（缺省回落 `req.uri().path()`）**只重算并匹配 v3 签名**（HMAC v3-only，见 §5.4）。失败 reason 保持不变（`GATEWAY_SIGNATURE_MISSING` / `GATEWAY_TIMESTAMP_SKEW` / `GATEWAY_SIGNATURE_MISMATCH`）。
- 失败统一走 `gateway_error` 信封（`code/message/traceId/requestPath/requestMethod/errorType/decision/reasonCode` + `X-Trace-Id`；503 附加 `Retry-After: 3`）。

#### ⑧ physical_policy_context / PolicyEngine

- 下游服务中间件（`astral-learn/src/middleware.rs`、`astral-chat/src/middleware.rs`、`astral-identity/src/middleware.rs`、`astral-trustgraph/src/api/permission_check.rs`）先按各自 `*_PATH_MAP` 把路径解析为 `(resource, action)`（`resolve_permission_action` 做业务动作覆盖，如 `learn_level_play`→`play`），再调用 `physical_policy_context(headers, resource, action, target_id)` 构建 `PolicyContext`：
  - PlatformUser：`x-user-id` / `x-principal-kind` / `x-identity-card-id` 缺失 → 401；`x-user-card-id` / `x-user-card-tenant-id` / `x-user-card-domain-id` 缺失 → 403；三者组成完整物理双卡上下文。
  - AppUser：返回 identity-only 上下文（三个 user-card 字段为 None），进入引擎后由 `CARD_REQUIRED` 拒绝（除 Learn app-users 的 `APP_USER` 放行分支）。
- 随后调 `PolicyEngine::evaluate(&ctx, &repo)`（`policy-engine` crate），按 前置校验 → `check_card_active`（权威双卡 SQL）→ 投影门禁（`authorization_projection_head`）→ L1 规则集（OVERLAY DENY→ALLOW→BASE DENY→ALLOW）→ L2 `permission_rule` → L2.5 委托 → `DEFAULT_DENY` 评估。
- Learn/Chat/Identity 中间件在 evaluate 后还执行 SoD 冲突检查（`check_sod_conflict`，失败 fail-closed 503）。

#### ⑨ 业务 handler / 审计

- 授权通过后进入各服务 `srv/*` handler（如 `astral-learn/src/srv/*`、`astral-chat/src/srv/*`、`astral-identity/src/srv/*`、`astral-trustgraph/src/api/*`）。
- 权限审计：各中间件在 evaluate 后 `tokio::spawn` 异步调 `astral_common::audit::record_permission_audit` → 全局 `AuditDualWrite`（MQ-first 经 `MqProducerRef` 发布 `audit.log`；MQ 未就绪/失败走 DB fallback 共执行两次尝试（首次写入 + 一次重试），见 [`for attempt in 1..=2`](../../../astral-common/src/audit.rs#L141-L161)；再失败留 `tracing` 结构化日志 `target="audit_log"`）。ALLOW 命中时额外 `record_permission_hit` 写命中统计。
- 审计异步且故障不阻塞权限决策（设计意图）；审计消息 `messageId` 用 `uuid::Uuid::new_v4()` 保证幂等键唯一（`astral-identity/src/main.rs` / `astral-trustgraph/src/main.rs` 的 `*MqProducer` 均有注释说明派生键回退会丢审计行）。

### 4.2 分支：refresh / internal / anonymous

| 分支 | 行为 |
|------|------|
| **anonymous** | 配置命中的已注册公开路由（`PublicOnly`）在无 `Authorization` 头时直接放行到对应 handler；本快照中 `config.public_paths` 默认包含 `/api/v1/auth/register`、`/v1/app/users/login` 等，`jwt_auth_middleware` 通过 `route_credential_policy_with_config` → `configured_public_route` 读取并应用该字段（[middleware.rs:372-L379](../../../astral-gateway/src/middleware.rs#L372)、[middleware.rs:526-L532](../../../astral-gateway/src/middleware.rs#L526)、[middleware.rs:920-L955](../../../astral-gateway/src/middleware.rs#L920)）。配置只能启用 `APPROVED_PUBLIC_ROUTES` 中已注册的 method/path；未配置命中时仍按 `AccessOnly` 等策略处理。带 Bearer 时仍须通过 access JWT、Redis 会话与后续校验。 |
| **refresh** | `POST /api/v1/auth/sessions/refresh`、`/switch-card`（`RefreshOnly`）：仅接受 REFRESH 类型 token，Gateway 只做 Refresh JWT v2 的 typ/签名/claims 结构校验（refresh 不带授权上下文），验签后**不查 Redis、不注入身份头**，仅经标准 `proxy::forward`（HMAC v3，身份头字段为空）转发到 Identity 的 refresh 业务入口；**Gateway 认证职责结束**，会话续期/令牌轮换由 Identity `srv/session.rs::refresh_token` 继续。`/logout`、`/revoke`（`AccessOrRefresh`）：access 或 refresh 皆可，access 走完整 Redis 判定。 |
| **internal** | Gateway 已注册 `POST /api/v1/auth/internal/sessions`（[main.rs:205](../../../astral-gateway/src/main.rs#L205)）。Learn `HmacAppSessionIssuer` 使用 `gateway_service_uri`（[app_user_service.rs:42](../../../astral-learn/src/service/app_user_service.rs#L42)）发送 `astral-internal-v1` 的 Learn→Gateway assertion；Gateway 在 [middleware.rs:680](../../../astral-gateway/src/middleware.rs#L680) 接收专用校验，并从 [middleware.rs:755](../../../astral-gateway/src/middleware.rs#L755) 起校验请求上下文，之后由 [proxy.rs:257](../../../astral-gateway/src/proxy.rs#L257) 生成 Gateway→Identity internal assertion 并转发。Identity 在 [internal.rs:341](../../../astral-identity/src/srv/internal.rs#L341) 校验该断言，在 [internal.rs:389](../../../astral-identity/src/srv/internal.rs#L389) 确保 identity card，并通过 [auth.rs:251](../../../astral-identity/src/auth.rs#L251) 的 identity-only access 签发和 [auth.rs:295](../../../astral-identity/src/auth.rs#L295) 的 AppUser refresh 签发创建会话。该内部控制流绕过普通 PlatformUser 双卡策略链，但仍是已认证的内部控制流。 |

### 4.3 分支：WebSocket（Chat）

`astral-gateway/src/proxy.rs::forward_chat_ws`（注册于 canonical `/v1/chat/ws/{*path}`，当前 Chat handler 使用 `/v1/chat/ws/{user_id}`）：

1. `CB_CHAT` 断路器检查（OPEN → 503）。目标路径重写为 `/v1/chat/ws/{path}`；上游 URL 由 `websocket_upstream_url` 计算（`http(s)` → `ws(s)`），不携带 query。浏览器握手仅在 Gateway exact `GET /v1/chat/ws/{positive-user-id}` 路径接受 `Sec-WebSocket-Protocol: astral-chat-v1, bearer.<JWT>`；Gateway 提取 bearer credential 为 `Authorization: Bearer ...` 后进入既有认证链，并将握手协议归一化为稳定的 `astral-chat-v1`。
2. 子协议缺失、重复、包含未知协议、缺失/重复/空 bearer、query credential 或 header/query 冲突时拒绝；提取后继续复用同一 `AccessOnly` 路由策略、JWT v2 签名/claims 校验、撤销状态、`access:jti`、session grant 与租户状态检查。认证失败保持 401，Redis/认证依赖不可用保持 fail-closed 503。
3. 从入站头读取身份头（`x-user-id`、`x-token-id`、`x-identity-card-id`、`x-principal-kind`、`x-user-card-*`、`x-token-use`、`x-claims-version`、`x-action-codes`、`x-user-roles`），对**外部原始 path**计算 HMAC v3；bearer 子协议和 credential query 不进入 HMAC/下游 URL。
4. 透传客户端头（剔除 `authorization/connection/host/upgrade/sec-websocket-*`，包括 bearer/客户端协议头、`x-gateway-*`、`x-original-path`、`x-resource-owner-id`），向 Chat upstream 仅发送稳定协议 `astral-chat-v1`，并注入 `x-gateway-auth: verified`、`x-gateway-ts`、`x-gateway-signature`、`x-original-path`。Gateway trace span 与错误 envelope 只记录 path，不记录包含 credential 的完整 URI。
5. `tokio_tungstenite::connect_async`（3 秒超时）握手失败 → 502/503；成功后 `ws.on_upgrade` 进入 `bridge_websocket`：客户端↔上游双向消息转换（Text/Binary/Ping/Pong/Close）与 `tokio::select!` 中继。
6. 连接建立后由 Chat 进程负责身份验证：`astral-chat/src/srv/realtime.rs::ws_handler` 调 `authenticate_ws`（`ChatScope::from_headers` 校验 `x-user-id` 与路径 `user_id` 一致），并 `revalidate_ws_scope` → `check_card_active_cached_with_options`（`astral-db::CardEligibilityService::check_cached`：权威 SQL + `perm:card:active:{card_id}` **ELIGIBILITY 资格缓存**，30s 缓存 TTL/5s 抖动、`require_projection_ready=true` 要求 ELIGIBILITY head READY，见 §5.5）逐消息周期复核物理卡上下文；失效则发 `ERROR`/`Close`。

---

## 5. 当前契约清单（producer / consumer / 失败语义 / 不能直接改的原因）

> 约定：任何"改"都必须同步修改 §5.1~§5.7 中相关的所有 producer 与 consumer；否则出现网关与下游判定口径漂移。

### 5.1 route_credential_policy_with_config（路由凭证策略）

| 项 | 内容 |
|----|------|
| 定义 | `astral-gateway/src/middleware.rs::route_credential_policy_with_config(config, method, path)`（内部经 `configured_public_route` 读取 `config.public_paths`，Gateway 本地；策略实现已从 `astral-common/src/token_contract.rs` 解耦，行为不变；共享的 `TokenUse` / `PrincipalKind` / 身份头常量仍留在 `astral-common/src/token_contract.rs`） |
| 矩阵 | `config.public_paths` 命中 `APPROVED_PUBLIC_ROUTES` 中的已注册 method/path → PublicOnly；`POST /api/v1/auth/sessions/refresh`、`/sessions/switch-card` → RefreshOnly；`POST /api/v1/auth/sessions/logout`、`/sessions/revoke` → AccessOrRefresh；`POST /api/v1/auth/internal/sessions` → InternalOnly；其余全部 → AccessOnly（默认） |
| Producer | 契约常量本身（无状态） |
| Consumer | `jwt_auth_middleware`（`astral-gateway/src/middleware.rs`）——当前唯一消费者 |
| 失败语义 | 未知认证路径默认 AccessOnly（fail-closed，防未注册路径变成匿名/refresh 凭证入口）。`POST /api/v1/auth/internal/sessions` 的 exact route 由专用 internal assertion middleware 先校验；缺失、非法、过期、重放或 Redis 依赖不可用分别返回 401/503，之后才进入 Gateway 的 Identity 转发 handler（见 §4.2、§6.7）。 |
| 不能直接改的原因 | 与 Java `JwtGlobalFilter` 路径矩阵对齐；前端登录/刷新/切卡/登出流程的凭证面完全依赖它；Identity 会话端点（`srv/session.rs`）隐式信任"网关只放行其接受的凭证"。该策略曾以"共享契约"名义留在 `astral-common` 却只被 Gateway 消费（§6 的耦合点之一），本次已迁移为 Gateway 本地归属，行为不变 |

### 5.2 JWT claims v2

| 项 | 内容 |
|----|------|
| 定义 | `CLAIMS_VERSION = 2`；`typ`：`astral-access+jwt` / `astral-refresh+jwt`；`astral-common/src/middleware/mod.rs::JwtClaims`（Gateway 侧）、`astral-identity/src/auth.rs`（签发侧） |
| 字段 | `claimsVersion/iss/aud/sub/jti/tokenUse/principalKind/identityCardId/userCardId/userCardTenantId/userCardDomainId/templateId/structureNodeId/tenantStatus/sid/sessionVersion/sessionEpoch/familyId/exp/iat/nbf`；`roles`（兼容）；`permissions`（v2 中废弃，`skip_serializing`，仅供权限响应路径内部用） |
| Producer | `astral-identity`（`auth.rs::issue_access_token_for_identity_only` / `issue_refresh_token` 等；签发材料在 `config.jwt.access` / `config.jwt.refresh` profile） |
| Consumer | Gateway `decode_v2_token` + claims 校验；Identity 自身中间件（`verify_active_identity_context` / `verify_active_card_context`）再查库复核 |
| 失败语义 | 任何字段不合法 → 401 及具体 reason（`TOKEN_*` / `SESSION_CONTEXT_INVALID` / `APP_USER_CARD_CONTEXT_FORBIDDEN` / `REFRESH_AUTHORIZATION_CONTEXT_FORBIDDEN` 等） |
| 不能直接改的原因 | 与 Java 侧共享验签密钥、`kid`、`iss`/`aud` 与 claims 结构；Gateway 的 `verify_session_grant` 要求 claims 与 `access:grant` 投影字段逐一匹配；AppUser/PlatformUser 隔离语义硬绑定在 claims 字段存在性上 |

**备注（当前态）**：`derive_action_codes` 对任意 roles 恒返回 `"read"`（`astral-gateway/src/middleware.rs`），`x-action-codes` 只是兼容透传，不作 Rust 授权放行条件——这是对 AGENTS.md §3.8（禁止 SUPER_ADMIN 特判）的实现落实，但也意味着该头当前不表达任何真实权限面。

### 5.3 身份头（Gateway 注入）

| 项 | 内容 |
|----|------|
| 定义 | `astral-common/src/token_contract.rs` 身份头常量 + `jwt_auth_middleware` 注入逻辑（`astral-gateway/src/middleware.rs`）+ `INTERNAL_AUTH_HEADERS` 剥离清单（`astral-gateway/src/middleware.rs`） |
| Producer | Gateway `jwt_auth_middleware`（从 claims 注入）；剥离侧 `sanitize_internal_auth_headers` |
| Consumer | `proxy.rs` HMAC payload；下游 `gateway_signature_middleware` 验签字段；`physical_policy_context`；`ChatScope::from_headers`（`astral-chat/src/scope.rs`）；各业务 handler |
| 失败语义 | 客户端伪造头在网关最内层剥离；下游仅在 HMAC 验签通过后才信任身份头；改任何头名/取值都会同时影响签名 payload、下游解析与 HMAC v3 canonical 字段序 |
| 不能直接改的原因 | 与 Java `GatewayIdentityHeaders` 契约一致；Learn/Chat/Identity/TrustGraph/Monitor 的所有中间件与业务 handler 都从这些头读身份；新增/删除头必须同步改 §5.4 的 HMAC canonical payload 与全部验签方 |

### 5.4 HMAC v3-only

| 项 | 内容 |
|----|------|
| 定义 | `astral-common/src/middleware/gateway_signature.rs`：`compute_hmac_signature_v3`（前缀 `astral-gateway-v3`，14 段 canonical payload，字段序固定）：`method` / `path` / `user_id` / `principal_kind` / `token_id` / `identity_card_id` / `user_card_id` / `user_card_domain_id` / `user_card_tenant_id` / `token_use` / `claims_version` / `action_codes` / `user_roles` / `timestamp`。生产代码中 v2 计算函数已移除；`compute_hmac_signature_v2` 仅保留在测试内作为 legacy v2 签名构造辅助，用于验证 v3-only 中间件拒绝 v2 |
| Producer | Gateway `forward` / `forward_chat_ws`（**只签 Gateway HMAC v3**）；internal session 不使用这条 Gateway HMAC 生产路径，Learn→Gateway 与 Gateway→Identity 均使用独立的 `astral-internal-v1` assertion（详见 §4.2、§6.7） |
| Consumer | 下游 `gateway_signature_middleware`：**只接受 Gateway HMAC v3**（v2 签名拒绝）；internal session 则由 Gateway 专用 middleware 与 Identity `verify_internal_service_request` 分别消费 `astral-internal-v1` assertion |
| 失败语义 | Gateway HMAC 时间戳偏差 > 容差（默认 30s）→ 403 `GATEWAY_TIMESTAMP_SKEW`；签名不匹配 → 403 `GATEWAY_SIGNATURE_MISMATCH`；缺头 → 403 `GATEWAY_SIGNATURE_MISSING`；容差配置非法 → 500 `GATEWAY_TIMESTAMP_TOLERANCE_INVALID`；internal session 的 assertion 缺失/非法/过期/重放或依赖不可用 → 401/503（见 §4.2、§6.7） |
| 不能直接改的原因 | **Rust Gateway HMAC v3 与 internal `astral-internal-v1` 是两套独立协议**：Gateway→下游业务转发只签 HMAC v3；Learn→Gateway 与 Gateway→Identity 的 internal session hop 使用 `astral-internal-v1` assertion。两套协议的 canonical payload、头语义与密钥边界不可混用；Java legacy 11 字段 HMAC 契约（含 `x-org-id` 空位占位）是独立历史 contract，与 Rust v3 canonical 不互通、不属于本次变更范围；后续 internal wire contract 的统一声明仍需按阶段 B 决策推进。 |

### 5.5 Redis key / value / TTL

| Key | Value | TTL | Producer | Consumer | 失败语义 |
|-----|-------|-----|----------|----------|----------|
| `jwt:revoked:{jti}` | `"1"` | 7 天（`REVOKED_TTL_SECS`，覆盖 access token 最大生命周期） | Identity 撤销路径（`astral-identity/src/srv/session.rs` 各 `delete_*projections` / `mark_jti_revoked_at`） | Gateway `jwt_auth_middleware`（EXISTS） | Redis 故障 → 503 fail-closed；存在 → 401 `TOKEN_REVOKED` |
| `access:jti:{jti}` | 用户 ID 字符串（== JWT `sub`） | access token 剩余有效期（`token.expires_in.max(60)`） | Identity `store_session_grant_in_redis`（`astral-identity/src/srv/session.rs:786`） | Gateway（GET 后与 `sub` 强比对） | 缺失/不匹配 → 401 `SESSION_NOT_FOUND` |
| `access:grant:{jti}` | SessionGrant v2 JSON（`formatVersion/principalKind/userId/sessionId/cardId(legacy)/identityCardId/userCardId/userCardTenantId/userCardDomainId/sessionVersion/sessionEpoch/tokenFamilyId/sessionState/issuedAt/expiresAt`，camelCase） | 同上 | Identity（同上；`SessionGrant::active` 构造） | Gateway `verify_session_grant`（REQUIRE 阻塞 / EMIT 不阻塞） | REQUIRE 不匹配 → 401 `TOKEN_REVOKED`；读取失败 → 503 |
| `tenant:status:{tenant_id}` | 状态字符串 | 未在本仓库确认 | **仓库内无 Rust 生产者**（仅 Gateway 读取 `astral-gateway/src/middleware.rs` 的 `fetch_cached_tenant_status`） | Gateway | 缺失/故障 → 503 fail-closed；SUSPENDED/TERMINATED → 401 `TENANT_NOT_ACTIVE` |
| `perm:card:active:{card_id}` | 版本化 JSON（`valid`、最早卡过期时间、**`projection_type=ELIGIBILITY`**、ELIGIBILITY head 的 source/projected/revoke 版本及物理双卡上下文） | TTL 以自然到期时间（`min(identity.expires_at, user_card.valid_until)`）为上限截断，不超过最早卡过期时间 | **ELIGIBILITY 投影链路**（`astral-db/src/eligibility.rs::CardEligibilityService::check_cached`） | Chat `check_card_active_cached_with_options`、PolicyEngine 卡校验（经 `check_cached`） | **资格缓存，不是规则快照**；读取侧时间/版本/物理上下文校验，旧 `"1"`/`"0"` scalar 与旧 JSON（无 `projection_type`）一律 miss 回权威 SQL（fail-closed） |
| `perm:refs:{card_id}` | RefsCacheWrapper JSON（规则集快照缓存，携带投影版本） | — | 投影链路 | PolicyEngine L1 | 未 READY → PENDING |
| `mq:idempotent:{message_type}:{message_id}` | 去重 | 24h | MQ 消费者 | 消费方 | 防重复处理 |

> 注：`access:jti` / `access:grant` 的 key 后缀、`jwt:revoked` 后缀、TTL 语义均与 Java"删投影等价撤销"对齐，属于冻结基础设施（《物理双卡权限链路设计_V1.0.md》§1.2）。**不能直接改**：改 key/TTL 会同时破坏 Java 侧与既有 Redis 中存量投影；改 value 结构必须同步 Gateway `SessionGrant`（消费侧声明于 `astral-gateway/src/middleware.rs`）与 Identity 签发侧 `SessionGrant`（`astral-identity/src/auth.rs`）两处——两者当前是**重复声明**，是 §6 的耦合点。

### 5.6 错误 envelope

| 项 | 内容 |
|----|------|
| Gateway 错误 | `astral-gateway/src/middleware.rs::json_error`（JWT 中间件）与 `astral-gateway/src/proxy.rs::json_error`（转发）：`code/message/traceId/requestPath/requestMethod/errorType/decision/reasonCode` + `X-Trace-Id` 头（对齐 Java `JwtGlobalFilter.writeErrorResponse`） |
| 依赖不可用 | `dependency_unavailable`（中间件）/ 503 分支（proxy）：503 `DEPENDENCY_UNAVAILABLE` / `AUTH_STATE_UNAVAILABLE` + `Retry-After: 3`（前端对 401 会触发登出，503 视为可重试瞬时故障） |
| 下游成功/业务失败 | `astral-common/src/contract/mod.rs::ApiResponse<T>`：`success/code/message/data/errorType/decision/reasonCode/requiredPermission/requestPath/requestMethod/timestamp/traceId` |
| 全局异常 | `astral-common/src/error/mod.rs::global_exception_handler`：panic → 500，`code/message/success/errorType/timestamp` |
| Consumer | 前端（`AstralLight-Web`、`you-web`、小程序）、外部调用方 |
| 不能直接改的原因 | 三套 envelope 形状被不同层消费，且与 Java 基线逐字段对齐；改字段名/状态码语义会破坏前端错误分支（尤其 401 触发会话失效 vs 503 重试的区分） |

### 5.7 路由前缀重写

| 外部路径（客户端） | 上游 | 重写后内部路径 |
|--------------------|------|----------------|
| `/api/v1/auth/sessions[/{*path}]` | Identity | 原样 |
| `/api/v1/auth/register\|profile\|change-password\|providers` | Identity | `/api/v1/auth/{path}`（见 §4.1① Path 提取器观察项） |
| `/api/v1/users[/{*path}]` | Identity | 原样 |
| `/v1/admin/users[/{*path}]` | Identity | `/api/v1/auth/admin/{path}` |
| `/v1/admin/learn/{*path}` | Learn | 原样 |
| `/v1/app/learn/{*path}` | Learn | 原样 |
| `/v1/app/users[/{*path}]` | Learn | 原样 |
| `/duo/v1/app/**` / `/duo/v1/admin/learn/**` | Learn | 剥 `/duo`（对齐 Java StripPrefix=1） |
| `/v1/chat/{*path}` | Chat | `/v1/chat/{path}`；WS canonical 子路径 `/v1/chat/ws/{user_id}` 由 Gateway exact route 提取 `bearer.<JWT>` subprotocol 后转发为 `/v1/chat/ws/{user_id}`，上游仅接收 `astral-chat-v1`，不转发 credential query |
| `/main/api/v1/{*path}` | TrustGraph | 原样 |
| `/api/v1/monitor/{*path}`、`/v1/monitor/{*path}`、`/api/health[/{*path}]` | Monitor | `/api/v1/monitor/{path}` 或 `/api/health{path}` |
| `/ws`、`/ws/{*path}`、部分 checkins 兼容路径 | — | 501 `NOT_IMPLEMENTED`（`proxy::not_implemented`） |

- 生产者：`astral-gateway/src/main.rs`（路由表）与 `proxy.rs`（`format!` 重写）；消费者：下游 `nest()` 前缀。
- 失败语义：未注册路由 404；501 桩返回 `NOT_IMPLEMENTED`。
- 不能直接改的原因：与 `Docs/规范/统一接口路径规范_V5.md` 冻结主路径一致（Learn Admin/App、Identity、TrustGraph `/main/api/v1/**`）；`/duo/**` 兼容路径被小程序消费，`/v1` 与 `/duo` 两套并存是既有对外契约。

---

## 6. 当前真实耦合点与 owner 错位

### 6.1 Gateway 直接读 Identity 写的 Redis session grant

- `jwt_auth_middleware` 在 Gateway 进程内直接 Redis `EXISTS jwt:revoked:{jti}`、`GET access:jti:{jti}`、`GET access:grant:{jti}`、`GET tenant:status:{tenant_id}`。
- 这些 key 的**写入方是 Identity**（`astral-identity/src/srv/session.rs::store_session_grant_in_redis` 等）。即：会话有效性的**事实 owner 是 Identity**（签发/撤销/投影），但**判定逻辑复制了一份在 Gateway**（`verify_session_grant`、`SessionGrant` 结构、EMIT/REQUIRE 语义）。
- `SessionGrant` 结构在 `astral-identity/src/auth.rs`（签发侧）与 `astral-gateway/src/middleware.rs`（消费侧）各声明一份，wire 格式靠人工保持一致。
- 后果：改 Redis 投影格式/TTL 必须双端同步；无法对 Gateway 判定做与 Identity 解耦的隔离测试；任何一方漂移都会造成"Identity 认为有效、Gateway 认为无效"或反向。

### 6.2 Gateway HMAC 与服务间 internal assertion 的协议边界

- Gateway→下游业务转发使用 `compute_hmac_signature_v3` + `x-gateway-*` 头，密钥为 `config.gateway.hmac_secret`；该链路由 `proxy::forward` / `forward_chat_ws` 产生，下游 `gateway_signature_middleware` 消费。
- Learn App 内部会话使用 `gateway_service_uri` 调用 Gateway `POST /api/v1/auth/internal/sessions`，发送 `astral-internal-v1` Learn→Gateway assertion；Gateway 专用 `internal_session_auth_middleware_with_config` 消费该断言后，`forward_internal_session` 使用 `astral-internal-v1` Gateway→Identity assertion 转发到 Identity。
- 两跳 internal assertion 与 Gateway HMAC v3 具有不同的头语义、canonical payload、密钥边界和 consumer，不能把 internal session 描述为 Learn 直接发送 Gateway HMAC 或直接调用 Identity。internal assertion 的正式 wire contract 仍是阶段 B/阶段 F 的后续收敛项。

### 6.3 硬编码业务路由

- `astral-gateway/src/main.rs` 全部路由与 `proxy.rs` 的重写规则硬编码；新增 Learn/Chat/Identity 端点必须改 Gateway 代码并重新发布。`public_paths` 不是未使用字段：`astral-common/src/config/mod.rs` 定义并由 `ensure_required_public_paths` 强制补全，`astral-gateway/src/middleware.rs::configured_public_route` 在 `jwt_auth_middleware` 的配置化策略链中读取它；当前仍有的边界是，配置只能启用 `APPROVED_PUBLIC_ROUTES` 中已注册的 method/path，不能将任意未注册路径变为公开路由。

### 6.4 Chat WS 双向桥

- `proxy.rs::forward_chat_ws` + `bridge_websocket` 在 Gateway 进程内做完整双向中继（axum ws ↔ tokio-tungstenite 消息互转）。
- WS 的**身份验证与连接生命周期 owner 在 Chat**（`realtime.rs`：`ChatScope::from_headers` + `revalidate_ws_scope`），但**桥代码在 Gateway**；Gateway 对 WS 只注入签名、不做业务级认证。任何协议调整（STOMP/SockJS 兼容）都牵动 Gateway 桥与 Chat 两侧。

### 6.5 手写断路器

- `proxy.rs` 每个上游一个 `static` `CircuitBreaker`（`CB_LEARN/CB_IDENTITY/CB_TRUSTGRAPH/CB_MONITOR/CB_CHAT`），阈值 5、恢复 30s、半开单探针，状态保存在进程内 `Atomic`，无集中配置、无 metrics/面板暴露、重启即清零。

### 6.6 astral-common 混合承载 Gateway 与下游 runtime

- `astral-common` 依赖 `policy-engine`、`astral-types`、`redis`、`jsonwebtoken`、`hmac/sha2/hex`，同时被：
  - **Gateway**：JWT claims 解码（`decode_v2_token` / `JwtClaims`）、HMAC 签名计算、配置与统一响应/错误契约；Redis 判定、清洗头、Gateway 错误 envelope 已随专属运行时迁入 Gateway 本地；
  - **下游**：`gateway_signature_middleware` 验签、`permission_check_shared`（`physical_policy_context` 等）、`audit`、`service`（`MqProducerRef` 抽象）、`ResourceRegistry` 重导出。
- 没有独立的"纯 wire contract"crate：Gateway 运行时（redis/jsonwebtoken）与下游权限运行时（policy-engine/astral-db）在同一 crate 内，无法独立演进与复用（例如未来 Java/其他语言的 wire 消费者）。
- **收敛说明（当前态）**：Gateway 专属运行时已部分收敛（`astral-gateway/src/middleware.rs` / `src/rate_limit.rs`），纯 wire contract crate 仍未建立，`SessionGrant` 仍双声明。

### 6.7 Learn→Gateway→Identity 内部会话两跳（冻结源码仍在 workspace 外）

- `astral-learn/src/service/app_user_service.rs::HmacAppSessionIssuer` 使用 `gateway_service_uri`，向 Gateway `POST /api/v1/auth/internal/sessions` 发送 `astral-internal-v1` Learn→Gateway assertion（[app_user_service.rs:42](../../../astral-learn/src/service/app_user_service.rs#L42)）。
- Gateway 在 [main.rs:205](../../../astral-gateway/src/main.rs#L205) 注册该 exact route；[middleware.rs:680](../../../astral-gateway/src/middleware.rs#L680) 的专用 middleware 校验请求，且 [middleware.rs:755](../../../astral-gateway/src/middleware.rs#L755) 起读取并验证用户、协议、route、timestamp、nonce、request-id、幂等键和签名上下文。
- Gateway 的 [proxy.rs:257](../../../astral-gateway/src/proxy.rs#L257) `forward_internal_session` 不把 Learn 的 assertion 原样转给 Identity，而是以 Gateway caller、Gateway→Identity route 和 Gateway internal secret 生成下一跳 `astral-internal-v1` assertion；Identity 的 [internal.rs:341](../../../astral-identity/src/srv/internal.rs#L341) handler/校验链消费该 assertion。
- Identity 在 [internal.rs:389](../../../astral-identity/src/srv/internal.rs#L389) 确保 active identity card，使用 [auth.rs:251](../../../astral-identity/src/auth.rs#L251) 的 identity-only access token 与 [auth.rs:295](../../../astral-identity/src/auth.rs#L295) 的 AppUser refresh token 签发路径创建会话；该 AppUser 会话没有 user-card 事实，因此不进入普通 PlatformUser 双卡 PolicyEngine 链，但仍是已认证、受重放/幂等/审计保护的内部控制流。
- 该事实不取消阶段 F 对 internal wire contract 的目标态要求：阶段 F 仍可要求 contract crate、配置边界和 excluded crate 解冻验收，但不能再把当前实现描述为 Learn 直连 Identity 或 Gateway 未注册该端点。

---

## 7. 解耦路线（从 Gateway 开始，分阶段）

> 阶段 A→F 按依赖排序；每阶段均列"不做什么 / 验收标准 / 回滚点"。**当前规划先推进 A、B（阶段 A 的 golden 测试与阶段 B 的 contract crate 均尚未实施，属拟推进项）**，C 之后需 §10 决策先行。
>
> 阶段进展说明：工作区未提交的第一步已完成——Gateway 专属运行时归属迁移（JWT/清洗/限流/凭证策略从 `astral-common` 迁入 `astral-gateway`，见 §3.1、§5.1），行为不变。**这是归属收敛的第一步，不代表阶段 A 的 golden 契约测试或阶段 B 的纯 wire contract crate 已经完成**，后两者仍是拟推进项。

### 阶段 A — 契约冻结与 golden tests

- **做什么**：把 §5 全部契约（route_credential_policy、JWT claims v2、身份头、HMAC v3-only、Redis key/value/TTL、错误 envelope、路由重写表）固化为可执行 golden 测试。已有局部测试、需补全：`astral-common/tests/gateway_contract_tests.rs`（v3 验签 + 篡改拒绝 + **已新增 v2 签名拒绝测试** `legacy_v2_signature_is_rejected_by_v3_only_middleware`）与 `gateway_signature.rs` 内的 **v3 golden** 对照测试（`v3_golden_vector_is_stable`，锁定 14 段 canonical；目前为 Rust 实现独立计算值，跨语言黄金值对照仍未建立）。**阶段 A 的全部 golden 契约表仍未完成**，以下待补全：路由重写矩阵、Redis key 判定矩阵（REQUIRE/EMIT/OFF）、错误 envelope 形状快照、身份头注入快照。
- **不做什么**：不改任何 wire 值；不新增/删除/重写路由；不动 Redis key/TTL；不改签名 canonical payload；不引入新配置。
- **验收标准**：契约表（§5）每条至少一个自动化用例，producer/consumer 双测；CI 全绿；发现与代码不符处冻结为"已知偏差"记录。
- **回滚点**：测试只增不改，无运行回滚面；若后续重构触犯冻结契约，CI 即失败。

### 阶段 B — 纯 wire contract 拆分

- **做什么**：把"纯 wire"部分拆出 `astral-common` 为独立 crate（如 `astral-contract`），仅含：`token_contract`（`route_credential_policy`/常量）、`gateway_signature` 的**签名计算函数**（v3，HMAC v3-only，不含验签中间件）、身份头常量、错误 envelope 形状、`SessionGrant` wire 结构（**单一声明**）。该 crate 只依赖 serde/jsonwebtoken/hex 等，不依赖 `policy-engine`/`astral-types`/`astral-db`。
- **不做什么**：不改变对外路径/头/HMAC 算法/Redis key；不把 JWT 验证或 Redis 判定移出 Gateway 进程；不改配置项。
- **验收标准**：Gateway 与 Identity 都依赖同一 `astral-contract`，`SessionGrant` 不再双处声明；`cargo check` 与阶段 A golden 测试全绿。
- **回滚点**：`astral-contract` 以独立版本发布（0.x），任何 crate 可 pin 旧版回退；代码侧保留 `astral-common` 再导出以便平滑迁移。

### 阶段 C — 会话有效性 owner 迁移（先 Port/adapter/双读观测，再移除 Gateway Redis 业务判断）

- **做什么**（分三步，前提是 §10 决策 1/2 有结论）：
  1. **抽象 Port**：定义 `SessionValidationPort`（校验 jti 撤销、access 投影、grant、租户状态），Gateway 只依赖该 Port。
  2. **双读观测**：adapter 保留现有 Redis 直读作为主判定，同时把 Identity 侧权威口径（如投影 head、撤销事件流）作为对照采样，对拍所有拒因（revoked / jti 缺失 / grant 不匹配 / 租户状态）并记录偏差。
  3. **收敛 owner**：观测通过后，选择"Identity 权威发布投影 + Gateway 只读投影"或"Gateway 调 Identity 校验端点"之一落地；**最后**才删除 Gateway 内 `verify_session_grant` 的复制实现。
- **不做什么**：观测未通过前不删 Gateway 现有判定；不改变 Redis 写入方；不把任何判定改为 fail-open；不改 TTL；不新增对 Identity 的同步阻塞调用（除非 §10 决策明确）。
- **验收标准**：双读观测偏差为 0 或逐项归因；单一 owner 落地后，契约 golden 测试全部改用权威口径重新固化。
- **回滚点**：每一步独立 commit 可 revert；双读期间 Gateway 行为不变，无用户可见回滚面。

### 阶段 D — 路由 / WS / 断路器拆分

- **做什么**：路由表从 `main.rs`/`proxy.rs` 抽出为声明式 route registry（外部路径 → 内部重写 → 上游服务 + 断路器组）；WS 桥与手写 `CircuitBreaker` 移入可替换的 transport 组件（保持对外行为）；breaker 状态接 metrics/日志。
- **不做什么**：不新增路径；不改重写规则；不改 501 桩行为；不动 HMAC 与身份头注入。
- **验收标准**：阶段 A 的路由重写 golden 全覆盖新 registry；WS 桥组件化后 Chat 连通性（含鉴权、断开、PING/PONG）行为不变；断路器半开/恢复语义有测试。
- **回滚点**：registry 与旧硬编码可开关切换，配置回退即可。

### 阶段 E — 配置拆分

- **做什么**：`AppConfig` 按服务裁剪：Gateway 只读 `gateway/jwt/redis/cors/rate_limit` 相关字段；下游不再持有 `gateway.hmac_secret`（internal 签名独立 key）；清理或明确归属 `public_paths` 等配置项。
- **不做什么**：不新增全局配置项；不改变 env/YAML 优先级（环境变量 > YAML > 默认值）。
- **验收标准**：各服务启动配置面收敛；代码审计确认无跨服务密钥泄漏；配置校验测试（`ConfigValidationError` 各分支）全绿。
- **回滚点**：配置结构带版本字段兼容读取旧 key，旧 YAML 可直接启动。

### 阶段 F — Learn / Chat 解冻前置条件（门禁清单）

- **做什么**（解冻前必须全部满足）：
  1. internal 会话当前已经经 Gateway 两跳完成（Learn→Gateway→Identity）；解冻前仍需把 `astral-internal-v1` 的 producer/consumer、密钥边界和 wire contract 纳入正式 contract crate，并完成对应契约测试（§10 决策 6）。
  2. internal 会话协议（`astral-internal-v1` 两跳 assertion；Learn→Gateway 与 Gateway→Identity 使用各自 caller/route/key-id，Gateway 不透传 Learn assertion）正式纳入阶段 B 的 contract crate。
  3. Chat WS owner 与协议适配决策落地（§10 决策 4）；`/ws` STOMP 桩（当前 501）去向明确（§10 决策 5）。
  4. 从 `exclude` 移除 `astral-learn`、`astral-chat` 并接入统一启动/配置。
- **不做什么**：未满足门禁前不修改 `Cargo.toml` 移除 exclude；不解冻期改动 Learn/Chat 业务逻辑本体（除门禁要求的接口收敛）。
- **验收标准**：Learn/Chat 纳入 workspace 编译通过；阶段 A golden 测试覆盖其全部对外路径；内部会话与 WS 链路契约测试全绿。
- **回滚点**：exclude 是单行配置，任何时刻可重新 exclude；各服务独立发布，互不阻塞。

---

## 8. 禁止的直接操作与五链审查点

### 8.1 禁止的直接操作

1. **禁止绕过 Gateway 直接修改/伪造身份头**：下游任何服务不得信任客户端直连时的 `x-user-*`/`x-gateway-*` 头（网关最内层剥离）；不得在业务 service 内绕过 `physical_policy_context` + `PolicyEngine::evaluate` 直接查 `permission_rule` 做授权判定（AGENTS.md §3.5）。
2. **禁止超管特判**：任何代码路径禁止检测 `SUPER_ADMIN`/`isSuperAdmin()` 直接放行；`derive_action_codes` 不得返回特权动作码（AGENTS.md §3.8，违规 P0）。
3. **禁止在 Git 跟踪文件中硬编码密钥/IP**：`astral-common/src/config/mod.rs` 已有占位符校验（`is_placeholder_secret`）；`application.yml` 已 `.gitignore`，不得提交。
4. **禁止直接改 Redis key/TTL 或 gateway_signature payload**：必须走阶段 A 冻结 → B 拆分 → C 迁移，任何一步都不得先于 golden 测试。Gateway HMAC v3 与 `astral-internal-v1` internal assertion 是不同协议，任一 canonical payload、头语义或密钥边界变更都要求对应 producer/consumer lockstep 同批升级。
5. **禁止新增绕过 Gateway 的服务间直连**：新增服务间 HTTP 调用必须走 Gateway 转发或正式 internal wire contract（阶段 F 门禁）。现有 Learn App 会话已走 Learn→Gateway→Identity 两跳；禁止退回 Learn 直连 Identity 的模式。
6. **禁止在未完成双读观测前删除 Gateway 的会话有效性判定**（阶段 C 顺序强约束）。
7. **禁止直接移除 `exclude`**（阶段 F 门禁未满足前）。
8. **禁止新增裸路径、camelCase 路径段、`/duo/**`/`/main/**` 外新路径**（`Docs/规范/统一接口路径规范_V5.md`）。

### 8.2 五链审查点（每次变更对照）

| 链 | 变更覆盖场景 | 本链路重点 |
|----|--------------|-----------|
| 调用链 | 返回值语义、副作用时序、异常传播 | 改 `route_credential_policy_with_config` / `configured_public_route` 或 `decode_v2_token` 返回值 → 追踪 `jwt_auth_middleware` 全部分支；改 `forward` 注入头 → 追踪所有下游验签与业务 handler |
| 逻辑链 | 分支/权限/缓存/事务隐性冲突 | Gateway Redis 判定（revoked/jti/grant/tenant status）与 Identity 投影链路的一致性；`x-action-codes` 只作透传不作放行；AppUser/PlatformUser 隔离不得被新分支绕过 |
| 事故链 | 缓存不可用/DB 超时/重试耗尽/熔断打开 | 全部授权相关判定必须 fail-closed（Redis 故障 503，禁 fail-open）；断路器半开探针、`Retry-After: 3`、审计 MQ→DB→tracing 降级不得吞决策 |
| 数据链 | 来源/类型/持久化/缓存/投影/读取路径 | `SessionGrant` wire 格式（双声明）、`access:jti` 标量==sub 强比对、`perm:card:active` 版本化缓存、`x-original-path` 签名用外部路径 vs 转发用内部路径；字段变更必须同步 Gateway 与 Identity |
| 审计链 | 审计事件、幂等、旁路降级、禁止绕过 | 权限决策审计 `AUTHZ_CHECK`（MQ-first/DB-fallback）；审计消息 `messageId` 必须唯一（UUID），禁止恒 None 回退派生键；权限/卡片变更不得绕过审计直接改数据 |

---

## 9. 链路图

### 9.1 当前链路图（历史快照，源代码边界截至 2026-08-11）

> 图中 `[]` 内为代码位置；错误语义 401/503 已简写，具体 reason 见 §5。链路顺序与边界以代码为准；标注"（待运行验证）"的项为代码级观察，未经运行确认。

```
客户端 / 前端（AstralLight-Web / you-web / 小程序）
   │ GET/POST（Bearer JWT v2：typ=astral-access+jwt / astral-refresh+jwt）
   ▼
astral-gateway（监听端口 9001）                              astral-gateway/src/main.rs
   │  中间件装配顺序（main.rs .layer 顺序；后 layer 者在外层先执行）
   ├─ TraceLayer（tower-http trace）→ CORS → global_exception_handler（panic→500 统一 envelope）
   │      → rate_limit_middleware（基于 IP 滑动窗口 bucket；超限 429 + Retry-After: 1）  src/rate_limit.rs
   ├─ sanitize_internal_auth_headers          剥离 INTERNAL_AUTH_HEADERS（30 项内部身份/网关头）  src/middleware.rs
   ├─ jwt_auth_middleware                     src/middleware.rs
   │    ├─ route_credential_policy_with_config(config, method, path) → `configured_public_route`（`config.public_paths` + `APPROVED_PUBLIC_ROUTES`）→ PublicOnly / refresh / access / internal 分流：
   │    │     POST /api/v1/auth/sessions 匿名；/sessions/refresh、/sessions/switch-card 仅 refresh；
   │    │     /sessions/logout、/sessions/revoke access|refresh；/internal/sessions InternalOnly；
   │    │     其余 /api/v1/auth/** 与未知路径默认 AccessOnly（fail-closed）
   │    ├─ internal session exact route `POST /api/v1/auth/internal/sessions`（main.rs:205）→ 专用 `astral-internal-v1` Learn→Gateway assertion 校验（middleware.rs:680、middleware.rs:755 起）→ `proxy::forward_internal_session`（proxy.rs:257）生成 Gateway→Identity assertion → Identity internal handler（internal.rs:341）
   │    ├─ decode_v2_token（typ / kid / alg / iss / aud + claims v2 结构校验）  astral-common/src/middleware/mod.rs
   │    │     PlatformUser：identityCardId + userCardId / userCardTenantId / userCardDomainId 均 > 0
   │    │     AppUser：三个 user-card 字段必须全缺（identity-only）
   │    │     refresh：授权上下文字段必须全缺（refresh 不带授权上下文）
   │    ├─ [access] Redis fail-closed 链（连接 3s 超时；任一步失败 → 503 + Retry-After: 3）
   │    │     ① jwt:revoked:{jti} EXISTS？       → 存在 401 TOKEN_REVOKED
   │    │     ② access:jti:{jti} 标量 == sub？    → 否 401 SESSION_NOT_FOUND（OFF 模式同样强制值比对）
   │    │     ③ access:grant:{jti}（EMIT/REQUIRE）→ REQUIRE 不匹配 401 TOKEN_REVOKED；
   │    │          EMIT 读取失败 fail-closed(503) 但校验结果不阻塞
   │    │     ④ tenant:status:{tenant_id}        → tenant_id 仅取 userCardTenantId；
   │    │          SUSPENDED/TERMINATED 401 TENANT_NOT_ACTIVE；缺失/故障 503
   │    ├─ [access] 身份头注入（x-user-id / x-identity-card-id / x-user-card-id|tenant-id|domain-id /
   │    │      x-token-id / x-token-use / x-principal-kind / x-claims-version / x-user-roles /
   │    │      x-action-codes="read"（恒 "read"）/ x-perms-ref / x-tenant-status / x-request-id / x-trace-id）
   │    └─ [refresh] Refresh 校验成功（RefreshOnly 策略 + Refresh JWT v2 的
   │         typ/签名/claims 结构校验；授权上下文字段全缺，不带授权上下文）
   │         → 不读 Access Redis（jwt:revoked/access:jti/access:grant/tenant:status）、
   │         不注入可信身份头，仅转发 Identity refresh handler；Gateway 认证职责结束
   │         （转发仍经下方 proxy::forward 标准路径 + HMAC v3，身份头字段为空；
   │         不进入授权链：physical_policy_context / check_card_active_cached /
   │         projection gate / PolicyEngine 资源授权）
   ├─ 路由匹配（main.rs 共 37 条）
   │     /actuator/health → health_check（本进程 200）（待运行验证，修正记录 问题 10）
   │     /api/v1/auth/sessions[/{*path}] 等 36 条转发/桩路由；未知路径 → axum 默认 404
   │       （未知路径 401 vs 404 边界待运行验证，修正记录 问题 11）
   ├─ HTTP：proxy::forward_*（每上游静态 CircuitBreaker：阈值 5 / 恢复 30s / 半开单探针）  src/proxy.rs
   │     └─ forward()：读体(≤10MB) → 提取 11 个身份头 → 对【外部原始路径】算 HMAC v3
   │          注入 X-Gateway-Auth / X-Gateway-Ts / X-Gateway-Signature / X-Original-Path
   │          → reqwest 转发（内部重写路径）→ 上游响应透传（剔除 transfer-encoding / connection）
   └─ WS：forward_chat_ws()（/v1/chat/ws/{*path}；exact `/v1/chat/ws/{user_id}` 的 `bearer.<JWT>` 仅用于 Gateway Bearer 校验，上游仅接收 `astral-chat-v1`）  src/proxy.rs
         HMAC v3（外部原路径）→ tokio-tungstenite 握手(3s) → bridge_websocket 双向中继
         （/ws、/ws/{*path} 及部分 checkins 兼容子路径 → 501 NOT_IMPLEMENTED 桩）
   │
   │  Gateway 注入可信身份头 + HMAC v3 签名转发；Rust 下游只接受 v3，v2 拒绝。
   │  （Java legacy 11 字段 HMAC 是独立历史 Java contract，与 Rust v3 canonical 不互通，不属 Rust 兼容面）
   ▼
────────────────────── 下游服务边界（Rust） ──────────────────────
   示例服务（端口见 application.yml 与各 main.rs）：
     astral-trustgraph :9005 │ astral-identity :9004 │ astral-learn :9002
     astral-chat :9003 │ astral-monitor :9006（learn / chat 源码暂 exclude，仅作示例）

   每个下游统一按以下顺序执行（astral-common 共享中间件 + 各服务权限中间件）；
   例外：Identity 对 `/sessions/refresh`、`/sessions/switch-card` 等凭证引导路径
   （`IDENTITY_SKIP_PATHS` + `is_credential_bootstrap_path`）直接放行到业务 handler，
   不进入第 2~5 步的授权链（见下方图例注释 6）：
   1) gateway_signature_middleware 验签（v3-only）
      x-gateway-auth==verified → ts 容差 30s → 常量时间重算 v3 比对
      （失败 403 GATEWAY_AUTH_INVALID / GATEWAY_SIGNATURE_MISSING /
        GATEWAY_TIMESTAMP_SKEW / GATEWAY_SIGNATURE_MISMATCH）
   2) 权限中间件：路径 → (resource, action)（resolve_permission_action）
      → physical_policy_context 从已验签头构建 PolicyContext
        PlatformUser：缺 user-card 三头 → 403；AppUser：identity-only 上下文
   3) correspondence / 物理双卡资格：identity_card 身份事实 + user_card 授权/组织事实
      （不做 identity 侧 tenant/domain 互匹；组织归属只来自 user-card）
      → check_card_active_cached[_with_options]（权威 SQL + perm:card:active ELIGIBILITY 资格缓存，
        astral-db::CardEligibilityService::check_cached，astral-db/src/eligibility.rs）
   4) projection gate：authorization_projection_head（未 READY → PENDING）
   5) PolicyEngine::evaluate 规则顺序：
      OVERLAY DENY → OVERLAY ALLOW → BASE DENY → BASE ALLOW
        → permission_rule → delegation → DEFAULT_DENY
      （无 user_card 上下文进入平台授权路径 → CARD_REQUIRED fail-closed；
        AppUser 仅显式 identity-only app 路径例外）
   6) audit：record_permission_audit（MQ-first / DB-fallback，异步不阻塞决策）；
      ALLOW 命中额外 record_permission_hit
   │
   ▼
Redis：jwt:revoked:{jti}(7d) / access:jti:{jti}（==sub，token TTL）/ access:grant:{jti}（v2 JSON）
        —— Gateway 读、Identity 写（耦合点 §6.1）
        tenant:status:{tid}（仓库内无 Rust 生产者，仅 Gateway 读取）
        perm:card:active（ELIGIBILITY 资格缓存）/ perm:refs（规则快照缓存）（astral-db 投影链路）

内部会话两跳：astral-learn HmacAppSessionIssuer ──► astral-gateway ──► astral-identity
   POST /api/v1/auth/internal/sessions（Learn→Gateway 与 Gateway→Identity 均为 `astral-internal-v1` assertion；§6.7 / §10 决策 6）
```

**图例 / 事实注释**：

1. **Gateway 只负责认证 / 会话 / 转发，不做最终资源授权**：`jwt_auth_middleware` 只校验凭证、判定会话有效性、注入身份头并签名转发；`x-action-codes` 当前恒为 `"read"`（`derive_action_codes` 恒返回 `"read"`，`astral-gateway/src/middleware.rs`），仅兼容透传，不作放行条件（§5.2）。
2. **最终授权唯一发生在下游 PolicyEngine**：下游 `gateway_signature_middleware` 验签后，由 `physical_policy_context` 构建授权上下文并交给 `PolicyEngine::evaluate` 产出 ALLOW/DENY（`astral-common/src/middleware/permission_check_shared.rs` + `policy-engine` crate）；Gateway 进程内不存在任何资源/动作授权判定。
3. **D1 已收敛：`astral-db::CardEligibilityService` 已实现**（`astral-db/src/eligibility.rs`，见修正记录问题 14）：`verify_platform_card_pair`（单条权威 SQL：identity 身份事实 + user_card 授权/组织事实 + 对应关系证明，**identity 不读 tenant/domain**）已被 login / refresh / switch-card 三处签发统一复用（login `auth_service.rs::login_inner`、refresh/switch `srv/session.rs`），switch 签发前补 tenant/domain ACTIVE 校验；`check_cached`（兼容 wrapper `check_card_active_cached[_with_options]`）供 PolicyEngine / Chat 运行期复用。**Gateway 本身不执行资格投影**，本链路图只记录签发侧调用事实与运行期资格 helper。
4. **`perm:card:active:{card_id}` 是资格缓存，不是规则快照**（`astral-db/src/eligibility.rs`）：payload 明确 `projection_type=ELIGIBILITY`，绑定 ELIGIBILITY head 的 source/projected/revoke 版本与物理双卡上下文；自然到期由读时 SQL/时间检查 + TTL 截断 fail-closed；旧 `"1"`/`"0"` scalar 与旧 JSON（无 `projection_type`）一律 miss 回权威 SQL。运行期物理资格校验（身份事实 + 授权/组织事实 + 对应关系证明 + ELIGIBILITY 版本门禁）与签发期校验是两条独立路径，互不替代。
5. **待运行验证项（对齐修正记录 问题 10/11，未擅自标为已修复）**：`/actuator/health` 未在 `route_credential_policy_with_config` 的 `APPROVED_PUBLIC_ROUTES` 中显式声明，若未被 `config.public_paths` 配置命中则按默认 `AccessOnly` 处理，无 token 时预期 401（健康 handler 不可达）；未知路径在 axum 默认 404 之前先被全局 JWT 中间件拦截（无 token 时预期 401 而非 404）。两者均为代码级观察，修正决策待定。
6. **Refresh 边界说明（Access 授权链 ≠ Refresh 会话续期链）**：Gateway 对 Refresh 只做 `RefreshOnly` 凭证策略 + Refresh JWT v2 的 typ/签名/claims 结构校验（refresh 不带授权上下文），**不进入 Access 的 Redis `jwt:revoked/access:jti/access:grant/tenant:status` 链、不注入可信身份头、不进入 `physical_policy_context` / `check_card_active_cached` / projection gate / PolicyEngine 资源授权链**；校验通过后仅经标准 `proxy::forward`（HMAC v3，身份头字段为空）转发到 Identity 的 refresh 业务入口，**Gateway 的认证职责到此结束**。此后是 **Identity 的 Refresh 会话续期业务仍继续**：Identity `srv/session.rs::refresh_token` 重新读取会话（`load_active_refresh_session`）、family 有效性、`identity_card` 与当前 `user_card`（PlatformUser 强制绑定），执行过期/scope 校验——签发资格统一经 `astral-db::CardEligibilityService::verify_platform_card_pair`（D1，见事实注释 3）——然后原子轮换 refresh token、签发新 access/refresh 对并重写 `access:grant` 投影（`store_session_grant_in_redis`）；Identity 中间件将 `/sessions/refresh`、`/sessions/switch-card` 视为**凭证引导路径**（`IDENTITY_SKIP_PATHS` + `is_credential_bootstrap_path`），下游同样不进入 PolicyEngine 资源授权链。**因此：Access 的授权链（含 Redis 会话判定 + 身份头 + 下游 PolicyEngine）与 Refresh 的会话续期链是两条不同链路，不得混淆。**

> **运行时归属边界**：Gateway-only runtime（Redis 会话/租户判定、清洗头、限流、路由凭证策略、Gateway 错误 envelope）位于 `astral-gateway`（`src/middleware.rs`、`src/rate_limit.rs`、`src/proxy.rs`）；`astral-common` 仅共享 JWT claims（`decode_v2_token` / `JwtClaims`）、下游验签（`gateway_signature`）、权限上下文与审计等下游中间件（§3.2）。

### 9.2 解耦后目标边界图（目标态，非当前实现）

> 以下为**目标设计**。边界以"每个决策只有单一 owner、跨服务仅经显式契约"为原则；尚未决策处标注"待 §10 决策"。

```
客户端
   │ Bearer JWT v2
   ▼
astral-gateway（边界职责收敛）
   ├─ 清洗伪造头 / 路由匹配（声明式 route registry，阶段 D）
   ├─ JWT 解码 + 凭证策略（wire contract，阶段 B）
   ├─ 会话有效性判定 → SessionValidationPort（阶段 C）
   │      └─ adapter：Identity 权威投影只读 / 或 Identity 校验端点（待决策 1）
   ├─ 身份头注入（wire contract）
   ├─ HMAC v3-only 签名转发（Rust v2 已下线）
   └─ WS / 断路器 → 可替换 transport 组件（阶段 D；Chat WS owner 待决策 4）
   │
   ├─► astral-identity   （session/sign/revoke 唯一 owner；签发 grant 投影；认证审计）
   ├─► astral-learn      （解冻，阶段 F 门禁；内部会话经 Gateway 或正式 internal 契约，待决策 6）
   ├─► astral-chat       （解冻，阶段 F 门禁；WS 连接与协议 owner，待决策 4/5）
   ├─► astral-trustgraph （授权决策与投影唯一 owner）
   └─► astral-monitor

服务间显式契约（阶段 B astral-contract）：
   route_credential_policy / JWT claims v2 / 身份头 / HMAC v3 / SessionGrant（单一声明）/ 错误 envelope / internal 服务签名（待决策 6）
   —— 不再依赖 astral-common 的运行时中间件
```

**当前态 vs 目标态的差异一栏**：目标态中 Gateway 不再持有 `verify_session_grant` 的复制实现与 Redis 业务判断（决策 1 前不落地）；不再硬编码业务路由；`astral-common` 不再同时承载 Gateway 运行时与下游权限运行时；Learn/Chat 不再以 excluded 姿态存在。

---

## 10. 未决决策清单

| # | 决策项 | 当前态事实 | 决策影响面 |
|---|--------|-----------|-----------|
| 1 | **session validation owner** | Gateway 直接读 Identity 写的 Redis 投影并复制判定逻辑（§6.1） | 决定阶段 C 走"只读投影"还是"调 Identity 校验端点"；影响 Gateway 是否保留 Redis 客户端依赖 |
| 2 | **identity expiry 是否独立 projection** | 当前 `SessionGrant` 内 `expiresAt` 随 access token TTL 写入；`identity_card.expires_at` 由 Identity 维护，**尚无正式更新入口/独立 source mutation 事件**（无 `aggregate_type='IDENTITY'` head/outbox/MQ expiry event；见修正记录问题 14 未覆盖项） | 若 identity 卡有效期需要独立投影/撤销语义，将影响 `access:grant` 结构与 Gateway 校验；需与 §5.5 冻结基础设施协调。自然到期由读时 SQL/时间检查拒绝（fail-closed），但显式变更失效链仍待设计，**不误标为已覆盖** |
| 3 | **Rust Gateway HMAC v3 与 internal assertion 协议边界** | Gateway HTTP/WS 下游转发使用 HMAC v3；Learn App 会话当前经 Gateway exact route 走两跳 `astral-internal-v1` assertion（Learn→Gateway、Gateway→Identity），Gateway 不把 Learn assertion 原样透传；Identity 端 internal handler 确保 identity card 并签发 AppUser identity-only access/refresh 会话 | 两套协议的 canonical payload、头语义、caller/route/key-id 与密钥边界分别冻结；后续统一 wire contract 纳入阶段 B contract crate，不能把 AppUser internal session 混入普通 Gateway HMAC 或 PlatformUser 双卡授权链 |
| 4 | **Chat WS owner** | 桥接代码在 Gateway（`bridge_websocket`），连接生命周期/鉴权在 Chat（`realtime.rs`） | 决定 WS 桥是否移出 Gateway、协议适配（STOMP/SockJS 兼容、`/ws` 501 桩）归属 |
| 5 | **route 501 桩** | `proxy::not_implemented` 对 checkins 兼容子路径（`/v1/app/users/checkins/{*path}`、`/v1/app/users/{user_id}/checkins[/{*path}]`、`/duo/**` 对应子路径）与 `/ws`、`/ws/{*path}` 返回 501；`/v1/app/users/checkins`、`/duo/v1/app/users/checkins` 两个根路径则实际转发到 Learn `/v1/app/learn/checkins` | 决定这些路径是补实现、下线还是长期桩；涉及 Java 兼容契约与前端/Duo 调用方 |
| 6 | **Learn internal session 协议** | Learn `HmacAppSessionIssuer` 使用 `gateway_service_uri` 调用 Gateway `POST /api/v1/auth/internal/sessions`；Gateway 校验 Learn→Gateway `astral-internal-v1` assertion 后，以 Gateway→Identity `astral-internal-v1` assertion 转发；Identity 创建 AppUser identity-only access/refresh 会话，该流程不进入普通 PlatformUser 双卡策略链 | 当前两跳已实现；解冻 Learn 前仍需将两跳 producer/consumer、密钥隔离、幂等/重放语义和 wire contract 纳入正式 contract crate 与契约测试（阶段 F 门禁） |

---

## 附注：本文档的边界声明

1. 本文档不修改任何源代码、不新增其他文件、不提交不推送。
2. 本文为 2026-08-11 源代码边界的当前态历史快照；本次仅局部复核 `astral-gateway/src/middleware.rs` 的公共路径配置读取链路，不代表全文已于 2026-08-22 重新验证。本文仍尽量为结论给出代码位置；标注"（代码级观察，待运行验证）"的结论未经运行时验证，不得直接作为缺陷结论引用。
3. 未声称任何未验证的测试结果；涉及测试的描述均引用仓库中已存在的测试文件与断言。
4. 本文不记录任何 IP、密码、token、密钥；`application.yml` 中出现的连接串与密钥不在本文出现。
