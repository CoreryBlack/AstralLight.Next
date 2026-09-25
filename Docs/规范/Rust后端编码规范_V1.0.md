# Rust 后端编码规范 V1.0

> 版本：1.2.0
> 日期：2026-09-09
> 状态：当前实现同步版（正式授权链与 workspace 边界已按 2026-09-09 源码核对）
> 适用范围：`` 工作区所有 Rust crate
>
> 本版同步当前授权投影边界：canonical grant revision/delta/manifest/segment/current 链、`AuthorizationCompiler`、`AuthorizationProjector`、`AuthorizationArchiveWorker` 与生产 `SqlxRuleRepository` 的 published-evidence strict gate；旧 `authorization_projection_head/outbox`、`permission_rule_snapshot`、`rule_set_snapshot` 和旧 CARD/RULE_SET worker 仅作为兼容、迁移、对账或测试材料。本文是工程规范；架构解释和证据索引见 [Rust访问控制总览与调整路线](../架构/Rust架构设计/Rust访问控制总览与调整路线_V1.0.md) 与 [Rust权限投影快照与版本栅栏](../架构/Rust架构设计/Rust权限投影快照与版本栅栏_V1.0.md)。
>
> 2026-09-09 实现同步：workspace 当前成员为 `policy-engine`、`astral-types`、`astral-common`、`astral-db`、`astral-cache`、`astral-mq`、`astral-gateway`、`astral-identity`、`astral-trustgraph`、`astral-monitor`；`astral-learn` 与 `astral-chat` 源码仍在仓库但由 `Cargo.toml` 的 `exclude` 明确冻结，不属于默认 workspace 编译/测试边界。正式生产授权由 `SqlxRuleRepository` 的 published-evidence strict gate 驱动；`AuthorizationCompiler`/`AuthorizationProjector` 是当前新链实现，旧 `snapshot.rs`、旧快照表读写和旧 CARD/RULE_SET 重建通道属于退役/兼容材料。迁移 `20260830000001`、`20260831000001`、`20260831000002`、`20260903000001` 已存在于源码，但目标数据库是否应用仍须由显式 migration 与部署验收证明。

---


## 1. 总体约束

1. 同一业务能力只能有一个长期主入口，兼容入口必须有下线日期。
2. 前后端契约统一由文档驱动，Rust 端的 API 响应格式必须与 Java `ApiResponse` 对齐。
3. 认证、授权、数据隔离必须走统一链路，不允许模块私有实现长期并存。
4. 每次改动必须同步更新相关文档（设计、接口、迁移、回滚、验收）。
5. **所有代码必须通过 `cargo clippy -- -D warnings`**，不允许 `#[allow(...)]` 绕过关键 lint。

---


## 2. 工作区模块边界


### 2.1 Crate 职责

| Crate | 类型 | 职责 |
|-------|------|------|
| `astral-types` | 库 | 共享类型、实体、错误模型、资源注册表。不依赖任何外部基础设施 |
| `policy-engine` | 库 | 权限评估引擎核心。不直接依赖 MySQL/Redis/RabbitMQ，通过 trait 注入 |
| `astral-common` | 库 | 公共基础设施：配置、错误处理、API 契约、日志、中间件、公共服务 |
| `astral-db` | 库 | 数据库访问层：sqlx Repository 实现、迁移管理 |
| `astral-cache` | 库 | Redis 缓存层：缓存装饰器、消息幂等 |
| `astral-mq` | 库 | 消息队列层：RabbitMQ 队列声明、Producer/Consumer |
| `astral-gateway` | 二进制 | API 网关：JWT 验证、路由转发、限流、断路器 |
| `astral-identity` | 二进制 | 身份认证服务：登录/注册/JWT 签发/用户管理/卡片管理/MFA |
| `astral-learn` | 库+二进制（源码冻结，workspace exclude） | 教育业务服务源码；不参加默认 workspace 编译/测试，解冻前不得宣称默认 gate 覆盖 |
| `astral-trustgraph` | 库+二进制 | 权限治理中心：规则管理/规则集/审批/审计/新授权投影 |
| `astral-chat` | 库+二进制（源码冻结，workspace exclude） | 即时通讯服务源码；不参加默认 workspace 编译/测试，解冻前不得宣称默认 gate 覆盖 |
| `astral-monitor` | 库+二进制 | 监控与告警服务：健康检查/指标/告警规则 |


### 2.2 依赖方向

```
astral-types (零外部依赖)
    ↑
policy-engine → astral-types
    ↑
astral-common → astral-types
    ↑
astral-db → policy-engine + astral-common
astral-cache → policy-engine + astral-common
astral-mq → astral-common
    ↑
astral-gateway → astral-common
astral-identity → astral-common + astral-db
astral-learn → astral-common + astral-db
astral-trustgraph → astral-common + astral-db + policy-engine
astral-chat → astral-common + astral-db
astral-monitor → astral-common + astral-db
```

**禁止事项**：
- ❌ 禁止循环依赖（crate A → B → A）
- ❌ 禁止业务 crate 直接依赖 `sqlx`（应通过 `astral-db` 封装）
- ❌ 禁止二进制 crate 被其他 crate 依赖（二进制是入口，不是库）

---


## 3. 命名规范


### 3.1 Rust 标准命名

| 项 | 规范 | 示例 |
|----|------|------|
| 类型（struct/enum/trait） | `UpperCamelCase` | `PolicyContext`, `Effect`, `RuleRepository` |
| 函数/方法 | `snake_case` | `check_permission()`, `load_rule_sets()` |
| 变量/字段 | `snake_case` | `user_id`, `card_name` |
| 常量/静态 | `SCREAMING_SNAKE_CASE` | `MAX_DELTA`, `DEFAULT_TIMEOUT` |
| 模块名 | `snake_case` | `mod rules`, `mod rule_sets` |
| Crate 名 | `kebab-case` | `policy-engine`, `astral-common` |
| 类型参数 | 简短 UpperCamelCase | `T`, `R: RuleRepository` |
| 生命周期 | 单字母 | `'a`, `'ctx` |


### 3.2 文件命名

```
src/
├── lib.rs              # 库根（crate 入口）
├── main.rs             # 二进制根
├── engine.rs           # 核心引擎
├── condition.rs        # 条件评估器
├── client.rs           # 客户端 API
├── authorization_compiler.rs # 版本化授权热状态编译内核
├── engine.rs              # PolicyEngine 正式评估与 strict gate
├── service/            # 业务服务
│   ├── mod.rs          # 子模块声明
│   ├── users.rs        # 用户服务
│   └── cards.rs        # 卡片服务
├── api/                # API 路由层
│   ├── mod.rs
│   ├── rules.rs
│   └── rule_sets.rs
└── srv/                # 业务逻辑层
    ├── mod.rs
    └── subjects.rs
```

---


## 4. 分层架构


### 4.1 三层结构

```rust
// 1. API 层（api/）：仅处理 HTTP 输入输出
pub async fn list_rules(State(db): State<MySqlPool>) -> Result<Json<ApiResponse<Vec<RuleDto>>>, AppError> {
    let rows = sqlx::query_as::<_, RuleRow>("SELECT ...")
        .fetch_all(&db).await?;
    Ok(Json(ApiResponse::success(rows.into_iter().map(row_to_dto).collect())))
}

// 2. 业务服务层（service/ 或 srv/）：业务逻辑编排
impl RuleSetWriteService {
    pub async fn add_entry(
        &self,
        rule_set_id: i64,
        req: &AddEntryRequest,
        context: &RuleSetMutationContext,
    ) -> Result<i64, AstralError> {
        // source transaction 只写 grant revision + delta event；
        // AuthorizationProjector 在事务外编译、事务内 CAS 发布 canonical evidence。
        self.repo.add_entry(rule_set_id, req, context).await
    }
}

// 3. 数据访问层（通过 trait + astral-db）：仅数据访问
#[async_trait]
pub trait RuleRepository: Send + Sync {
    async fn load_rule_set_snapshots(&self, card_id: i64) -> Result<Vec<RuleSetSnapshot>, PolicyError>;
    async fn load_permission_rules(&self, card_id: i64) -> Result<Vec<PermissionRule>, PolicyError>;
    async fn load_rule_set_dependency_statuses(
        &self,
        card_id: i64,
    ) -> Result<Option<Vec<RuleSetDependencyStatus>>, PolicyError>;
    async fn load_projected_delegated_rules(
        &self,
        card_id: i64,
        resource: &str,
        action: &str,
    ) -> Result<Vec<PermissionRule>, PolicyError>;
}

> 注意：旧 `PermissionRuleService`、`RuleRepositoryExt` 和 `SqlxRuleRepositoryExt` 已从 Rust 0.x workspace 内部实现移除。不得重新引入旧 owner；`load_rule_set_snapshots`、`load_permission_rules` 和 `load_projected_delegated_rules` 只供未声明 strict capability 的 legacy/test、迁移或诊断路径；生产 `SqlxRuleRepository` 唯一授权读端口是 `load_published_card_authorization`，raw/source reader 仅用于 realtime/一致性巡检。
```


### 4.2 禁止事项

- ❌ 禁止 API handler 直接调用 sqlx（应通过 Repository trait）
- ❌ 禁止 API handler 拼装复杂 SQL
- ❌ 禁止 Service 层直接暴露数据库连接

---


## 5. 错误处理规范


### 5.1 错误类型分层

```rust
// 库错误（thiserror）：定义在 astral-types
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("Invalid policy context: {0}")]
    InvalidContext(String),
    #[error("Repository error: {0}")]
    Repository(String),
}

// 应用错误（AppError）：定义在 astral-common，包装 AstralError 实现 IntoResponse
pub struct AppError(pub AstralError);

impl IntoResponse for AppError { ... }

// 业务错误：定义在各自 crate
#[derive(Debug, thiserror::Error)]
pub enum RuleServiceError {
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Database error: {0}")]
    Database(String),
}
```


### 5.2 错误传播规则

- 库内部使用 `thiserror` 定义错误枚举
- 库间边界使用 `?` 操作符自动转换（通过 `From` impl）
- API handler 统一返回 `Result<Json<ApiResponse<T>>, AppError>`
- 禁止在 handler 中 `unwrap()` 或 `expect()`（除测试和 main 函数）

---


## 6. 异步规范


### 6.1 运行时

- 所有 crate 统一使用 `tokio` 作为异步运行时
- 禁止混合使用 `tokio` + `async-std` + `smol`
- 默认使用 `#[tokio::main]`，配置多线程调度器
- MQ Consumer 和 WebSocket 等长连接任务使用 `tokio::spawn`


### 6.2 Async Trait

```rust
// 使用 async-trait crate 定义异步 trait
#[async_trait]
pub trait RuleRepository: Send + Sync {
    async fn load_rule_sets(&self, card_id: i64) -> Result<Vec<RuleSet>, PolicyError>;
}
```

- 优先使用 `#[async_trait]` 宏
- 对简单场景可直接返回 `impl Future` 或使用 `Box<dyn Future>`
- 禁止在 trait 中使用裸 `async fn`（需要 nightly 特性）

---


## 7. 数据库访问规范


### 7.1 sqlx 使用原则

```rust
// ✅ 正确：使用 query_as 带编译期类型检查
let rows = sqlx::query_as::<_, RuleRow>(
    "SELECT id, card_id, effect, resource, action FROM permission_rule WHERE card_id = ? ORDER BY priority"
)
    .bind(card_id)
    .fetch_all(&pool).await?;

// ✅ 正确：使用 query 执行 DML
sqlx::query("INSERT INTO rule_set (name, ref_type) VALUES (?, ?)")
    .bind(&name).bind(&ref_type)
    .execute(&pool).await?;

// ❌ 禁止：字符串拼接 SQL
let sql = format!("SELECT * FROM rule_set WHERE name = '{}'", name);
```


### 7.2 Repository 模式

正式权限读取由 `policy_engine::RuleRepository` trait 约束，生产实现位于 `astral-db::SqlxRuleRepository`。当前生产实现通过 `requires_published_card_evidence() == true` 进入 Rust-owned published-evidence strict gate；授权账本、delta 队列、manifest/segment/current 指针和归档证明分别由 `astral-db`/`astral-trustgraph` 的对应 owner 管理。旧 `authorization_projection_head/outbox` 仍可作为 writer-correlation 与 ELIGIBILITY 资格缓存失效表面存在，但不再是 CARD/RULE_SET 授权投影的生产完成证明。

`RuleRepository` 中的 L1/L2/L2.5 读取方法仍为 legacy/test 或诊断兼容合同，必须明确与生产 strict gate 隔离：

- `load_rule_set_snapshots` / `load_snapshot_winners`：仅供未声明 strict capability 的 legacy/test 路径读取旧 RuleSet snapshot；不能成为生产 `SqlxRuleRepository` 的授权入口；
- `load_permission_rules`：仅供 legacy/test 路径读取旧 `permission_rule_snapshot`；空结果不回读 source；
- `load_projected_delegated_rules`：仅供 legacy/test 的 generation-gated delegation 路径；raw/source reader 只用于 realtime/一致性巡检；
- `load_published_card_authorization`：生产正式入口使用的唯一 published-evidence 读端口，缺 current、证明闩、scope 或完整性证据时只能 PENDING/DENY。

旧 `PermissionRuleService`、`RuleRepositoryExt`、`SqlxRuleRepositoryExt` 和直接 `rebuild_snapshot` owner 不再是有效实现入口。Rust 0.x workspace 内部接口的删除必须同一变更迁移全部仓内调用方、测试和文档，并在提交/PR 中标注 `BREAKING CHANGE`，列出删除清单、替代入口、影响范围、生效时间、迁移方案和回滚方案；稳定 `pub` API、外部 HTTP、消息和数据库协议不适用该内部例外。

2026-09-09 同步：生产 `SqlxRuleRepository` 的 strict gate 由 `PolicyEngine::evaluate()` 在 AUTHN/CARD_CONTEXT 与 resource/action 校验之后调用；`Ok(None)`、`Err`、非 Ready、证据畸形或 scope 不符均 fail-closed，禁止旧快照、raw source 或缓存回退。真实 MySQL/Redis/RabbitMQ 集成与正式切流仍需独立验收。


### 7.3 事务规范

- 使用 `sqlx::Transaction` 或 `pool.begin().await?`
- source mutation 的必要 source 写入、grant revision/delta event（或 legacy writer-correlation head/outbox）与 audit correlation 必须在同一短事务提交；事务内不访问 Redis/MQ
- canonical manifest/segment/current 发布由 `AuthorizationProjector` 在提交后事务外编译、发布事务内 CAS 完成；旧 snapshot rebuild、cache eviction、MQ publish 与旧 head READY 只属于 legacy/迁移对照通道
- 写入失败、schema/migration/backfill 未完成、current/manifest/segment proof 不足、lease/CAS 未知或审计证据失败必须保持 PENDING/DENY、Blocked/Quarantine/Unknown 或 fail-closed；禁止通过旧 snapshot/source fallback 放行
- 禁止在 handler 中直接管理事务

---


## 8. API 层规范


### 8.1 响应格式

所有 API 统一返回 `ApiResponse<T>`，字段与 Java `com.coreryblack.astral_general.common.contract.ApiResponse` 完全对齐。

**成功响应**（`ApiResponse::success(data)`）：

```json
{
  "code": 200,
  "message": "操作成功",
  "data": { ... },
  "timestamp": "2026-07-01T12:00:00",
  "traceId": "uuid"
}
```

**错误响应**（`ApiResponse::error(...)`）：

```json
{
  "code": 403,
  "message": "权限不足",
  "data": null,
  "timestamp": "2026-07-01T12:00:00",
  "traceId": "uuid",
  "requestPath": "/main/api/v1/permission-rules",
  "requestMethod": "POST",
  "errorType": "PERMISSION_DENIED",
  "decision": "DENY",
  "requiredPermission": "permission_rules:create",
  "reasonCode": "DENY"
}
```

**完整字段列表**（12 个字段，以 Java `ApiResponse` 为准）：

| 字段 | 类型 | 成功时 | 错误时 | 说明 |
|------|------|--------|--------|------|
| `code` | `int` | `200` | HTTP 状态码 | 不使用 `"SUCCESS"` 字符串 |
| `message` | `String` | `"操作成功"` | 错误描述 | |
| `data` | `T` | 业务数据 | `null` | |
| `timestamp` | `LocalDateTime` | 自动填充 | 自动填充 | ISO 格式 `"2026-07-01T12:00:00"` |
| `traceId` | `String` | 自动填充 | 自动填充 | 请求追踪 ID |
| `requestPath` | `String` | — | 请求路径 | 仅错误时填充 |
| `requestMethod` | `String` | — | 请求方法 | 仅错误时填充 |
| `errorType` | `String` | — | 错误分类 | 如 `AUTH_FAILED`、`PERMISSION_DENIED` |
| `decision` | `String` | — | 权限决策 | 如 `DENY`、`DEFAULT_DENY` |
| `requiredPermission` | `String` | — | 所需权限 | 格式 `resource_type:action_code` |
| `reasonCode` | `String` | — | 原因编码 | 如 `DENY`、`NO_ACTIVE_CARD` |
| `operationId` | `String` | 可选 | 可选 | durable 操作或异步副作用关联 ID；不是每个响应都必须填充 |

**Rust struct 定义参考**：

```rust
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiResponse<T: Serialize> {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    pub timestamp: String,       // ISO 8601
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_permission: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
}
```

**禁止事项**：
- ❌ 禁止使用 `success: bool` 字段（Java 端无此字段）
- ❌ 禁止 `code` 使用字符串（如 `"SUCCESS"`），必须为 int
- ❌ 禁止 `timestamp` 使用 Unix 时间戳，必须为 ISO 8601 字符串


### 8.2 Handler 签名

```rust
// GET - 列表
async fn list_items(State(db): State<MySqlPool>) -> Result<Json<ApiResponse<Vec<ItemDto>>>, AppError>

// GET - 单条
async fn get_item(State(db): State<MySqlPool>, Path(id): Path<i64>) -> Result<Json<ApiResponse<ItemDto>>, AppError>

// POST - 创建
async fn create_item(State(db): State<MySqlPool>, Json(req): Json<CreateItemRequest>) -> Result<Json<ApiResponse<ItemDto>>, AppError>

// PUT - 更新
async fn update_item(State(db): State<MySqlPool>, Path(id): Path<i64>, Json(req): Json<UpdateItemRequest>) -> Result<Json<ApiResponse<EmptyResponse>>, AppError>

// DELETE - 删除
async fn delete_item(State(db): State<MySqlPool>, Path(id): Path<i64>) -> Result<Json<ApiResponse<EmptyResponse>>, AppError>
```


### 8.3 路由定义

```rust
// 路由函数返回 Router<AppState>，使用 from_fn_with_state 注入中间件
pub fn item_routes() -> Router<AppState> {
    Router::new()
        .route("/items", get(list_items))
        .route("/items", post(create_item))
        .route("/items/{id}", get(get_item))
        .route("/items/{id}", put(update_item))
        .route("/items/{id}", delete(delete_item))
}
```


### 8.4 内部身份头

> **下表为 Java `GatewayIdentityHeaders` 头名表，仅作为 Java 参考保留**：它是独立的 Java legacy contract（11 字段 canonical、含 `x-org-id` 空位占位），与 Rust v3 canonical payload **不互通**，不得当作 Rust v3 payload 使用。Rust 当前签名规范见下方"Rust HMAC-SHA256 签名规范（v3-only）"。

Java `GatewayIdentityHeaders` 头名表（共 17 个，独立历史 Java contract，仅供参考）：

| 头名称 | Java 常量 | 说明 |
|--------|----------|------|
| `X-User-Id` | `USER_ID_HEADER` | 用户 ID |
| `X-Token-Id` | `TOKEN_ID_HEADER` | Token ID |
| `X-User-Roles` | `USER_ROLES_HEADER` | 角色列表（逗号分隔） |
| `X-Action-Codes` | `ACTION_CODES_HEADER` | 动作码列表（逗号分隔） |
| `X-Token-Use` | `TOKEN_USE_HEADER` | Token 用途（ACCESS/REFRESH） |
| `X-Card-Id` | `CARD_ID_HEADER` | 当前卡片 ID |
| `X-Template-Id` | `TEMPLATE_ID_HEADER` | 当前模板 ID |
| `X-Domain-Id` | `DOMAIN_ID_HEADER` | 域 ID |
| `X-Tenant-Id` | `TENANT_ID_HEADER` | 租户 ID |
| `X-Org-Id` | `ORG_ID_HEADER` | ~~组织 ID~~ **@Deprecated(since="2026-05-12")**，由 `X-Tenant-Id` 替代，签名中该位传空串 |
| `X-Gateway-Auth` | `GATEWAY_AUTH_HEADER` | 网关验证标记（值=`verified`） |
| `X-Gateway-Ts` | `GATEWAY_TIMESTAMP_HEADER` | 网关时间戳（毫秒） |
| `X-Gateway-Signature` | `GATEWAY_SIGNATURE_HEADER` | HMAC-SHA256 签名 |
| `X-Has-Required` | `HAS_REQUIRED_HEADER` | 是否满足所需权限 |
| `X-Required-Permission` | `REQUIRED_PERMISSION_HEADER` | 所需权限标识 |
| `X-Perms-Ref` | `PERMS_REF_HEADER` | 权限引用标识 |
| `X-Permissions-Truncated` | `PERMISSIONS_TRUNCATED_HEADER` | 权限列表是否被截断 |

**Rust HMAC-SHA256 签名规范（v3-only）**：

Rust 网关签名统一使用 `compute_hmac_signature_v3`（`astral-common/src/middleware/gateway_signature.rs`），canonical payload 前缀 `astral-gateway-v3`，共 14 段、字段顺序固定、以 `\n` 分隔：

```
astral-gateway-v3
method
path
user_id
principal_kind
token_id
identity_card_id
user_card_id
user_card_domain_id
user_card_tenant_id
token_use
claims_version
action_codes
user_roles
timestamp
```

即字段序：`method` / `path` / `user_id` / `principal_kind` / `token_id` / `identity_card_id` / `user_card_id` / `user_card_domain_id` / `user_card_tenant_id` / `token_use` / `claims_version` / `action_codes` / `user_roles` / `timestamp`。

- **Rust 下游只接受 v3**：`gateway_signature_middleware` 为 v3-only，v2 签名一律拒绝（生产代码不含 v2 计算函数）。
- 缺头（`X-Gateway-Auth` / `X-Gateway-Ts` / `X-Gateway-Signature`）、时间戳非法/超时（默认容差 ≤30s）、签名不匹配，仍按既有错误语义拒绝（`GATEWAY_AUTH_INVALID` / `GATEWAY_SIGNATURE_MISSING` / `GATEWAY_TIMESTAMP_INVALID` / `GATEWAY_TIMESTAMP_SKEW` / `GATEWAY_SIGNATURE_MISMATCH`）。
- 下游服务必须先校验 `X-Gateway-Auth` = `verified` 并对 v3 签名验签通过，**之后**才信任身份头。

---


## 9. 配置管理


### 9.1 加载方式

```rust
// 使用 config-rs，优先级：环境变量 > YAML > 默认值
let config = AppConfig::from_env()?;   // 仅环境变量
let config = AppConfig::from_files("app.yml")?;  // YAML + 环境变量覆盖
```


### 9.2 环境变量命名

```rust
LEARN_SERVICE_URI=http://localhost:9002
DATABASE_URL=${DATABASE_URL:?DATABASE_URL is required}
REDIS_URL=redis://localhost:6379
RABBITMQ_URL=${RABBITMQ_URL:?RABBITMQ_URL is required}
JWT_SECRET=${JWT_SECRET:?JWT_SECRET is required}
GATEWAY_HMAC_SECRET=${GATEWAY_HMAC_SECRET:?GATEWAY_HMAC_SECRET is required}
RUST_LOG=info
```

---


## 10. 测试规范


### 10.1 单元测试

```rust
// 每个模块内嵌 #[cfg(test)] mod tests
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_deny() {
        let engine = PolicyEngine::new();
        let ctx = PolicyContext::builder()
            .card_id(Some(1))
            .action("read".into())
            .resource(Some("learn_subject".into()))
            .build();
        let decision = engine.evaluate(&ctx, &repo).await;
        assert!(!decision.allowed);
    }
}
```

- 测试函数使用 `#[tokio::test]`
- 使用 mock repository 而非真实数据库
- Handler 测试使用 `axum::Router::with_state()` + 随机端口绑定


### 10.2 集成测试

- 在 `tests/` 目录下创建集成测试文件
- 使用 `testcontainers` crate 管理 MySQL/Redis/RabbitMQ 容器
- 标记需要 Docker 的测试为 `#[ignore = "Requires Docker"]`


### 10.3 基准测试

```rust
// 使用 criterion 建立性能基线
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_evaluate(c: &mut Criterion) {
    let engine = PolicyEngine::new();
    let rt = tokio::runtime::Runtime::new().unwrap();
    c.bench_function("engine/l1_allow", |b| {
        b.iter(|| rt.block_on(async {
            let _ = black_box(engine.evaluate(&ctx, &repo).await);
        }));
    });
}
```


### 10.4 语义等价性测试（Oracle）

- JSON oracle 文件存放在 `tests/oracle/` 目录
- 从 Java 版 DecisionDerivationTable 导出测试数据
- Rust 版断言与 oracle 输出完全一致

---


## 11. 代码质量


### 11.1 编译检查（CI 必跑）

```bash
cargo check --workspace           # 类型检查
cargo clippy --workspace -- -D warnings  # lint（禁止 warnings）
cargo test --workspace            # 测试
cargo fmt --check                 # 格式（可选）
```


### 11.2 Clippy 规则

- 必须通过 `-D warnings`（所有 warnings 视为错误）
- 允许的例外（需团队评审）：
  - `#[allow(clippy::too_many_arguments)]` — 仅对复杂查询条件
  - `#[allow(clippy::type_complexity)]` — 仅对嵌套泛型
- 禁止的绕过：
  - ❌ `#[allow(dead_code)]` — 未使用的代码应删除而非忽略
  - ❌ `#[allow(unused_variables)]` — 使用 `_` 前缀命名

---


## 12. Rust Idioms（所有权、借用、Trait、生命周期）


### 12.1 所有权原则

```rust
// ✅ 正确：函数获取所有权，调用方主动 clone
fn process(decision: PolicyDecision) -> PolicyDecision {
    let mut d = decision;
    d.reason = "MODIFIED".into();
    d
}

// ✅ 正确：只读访问使用 & 引用
fn log_decision(d: &PolicyDecision) {
    tracing::info!(allowed = d.allowed, reason = %d.reason);
}

// ❌ 违反：不必要的 clone
fn process(decision: PolicyDecision) -> PolicyDecision {
    let d = decision.clone();  // 如果不需要保留原值，直接使用
    d
}
```


### 12.2 Borrow 与生命周期

```rust
// ✅ 正确：显式生命周期标注，明确借用关系
pub struct PolicyContext<'a> {
    pub resource: Option<&'a str>,
    pub action: &'a str,
}

// ✅ 正确：使用 `'static` 仅当引用确实存活整个程序生命周期
pub static RESOURCE_REGISTRY: OnceLock<ResourceRegistry> = OnceLock::new();

// ❌ 违反：不必要的生命周期复杂化——如果 struct 持有数据，使用 owned 类型
pub struct PolicyContext {              // ✅ 使用 String 而非 &str
    pub resource: Option<String>,
    pub action: String,
}
```

**生命周期选择矩阵**：

| 场景 | 推荐 | 原因 |
|------|------|------|
| API 参数（request body） | `Json<T>` + 反序列化 | 框架自动处理 |
| 函数内部处理 | 引用 `&T` | 借用，不转移所有权 |
| 配置共享 | `Arc<Config>` + `FromRef` | 线程安全共享 |
| 跨 await 点使用 | `Arc<T>` 或 owned `T` | 编译器防止借用跨越 yield |
| 全局单例 | `OnceLock<T>` / `LazyLock<T>` | 线程安全延迟初始化 |


### 12.3 Trait 设计

```rust
// ✅ 正确：trait 边界清晰，方法最少化
#[async_trait]
pub trait RuleRepository: Send + Sync {
    async fn load_rule_set_snapshots(&self, card_id: i64) -> Result<Vec<RuleSetSnapshot>, PolicyError>;
    async fn check_card_active(&self, card_id: i64) -> bool { true }  // 默认实现
}

// ✅ 正确：使用 supertrait 表达层次关系
pub trait WriteRepository: RuleRepository {
    async fn insert_rule(&self, rule: RuleDto) -> Result<i64, RuleServiceError>;
    async fn delete_rule(&self, id: i64) -> Result<(), RuleServiceError>;
}

// ❌ 违反：trait 过大（违反接口隔离原则）
pub trait MegaRepository {              // ❌ 不要包含 20+ 方法
    async fn do_everything(&self);      // 拆分为多个小 trait
}
```

**Trait 设计原则**：

| 原则 | 说明 |
|------|------|
| **最小接口** | trait 只包含该抽象的最小方法集，默认方法提供扩展 |
| **单一职责** | 一个 trait 只做一件事（如 `RuleRepository` 只做规则查询） |
| **Send + Sync** | trait 对象若跨线程必须标注 |
| **#[async_trait]** | 异步 trait 必须使用该宏（稳定前） |
| **Borrow 而非 Own** | trait 方法参数优先用 `&self` 而非 `self` |


### 12.4 枚举 vs 字符串

```rust
// ✅ 正确：使用枚举表达有限集合
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
    NotMatch,
}

// ❌ 违反：使用字符串表达有限集合
pub struct Rule {
    pub effect: String,  // ❌ 编译器不检查 "allow" vs "Allow" vs "ALLOW"
}
```


### 12.5 Result 与 Option 处理

```rust
// ✅ 正确：使用 ? 传播错误
pub async fn check(&self, ctx: PolicyContext) -> Result<PolicyDecision, ClientError> {
    if ctx.action.is_empty() {
        return Err(ClientError::InvalidContext("action must not be empty".into()));
    }
    let decision = self.engine.load().evaluate(&ctx, self.repo.as_ref()).await;
    Ok(decision)
}

// ✅ 正确：使用 map_err 转换错误类型
sqlx::query_as::<_, RuleRow>("SELECT * FROM rule_set WHERE id=?")
    .bind(id)
    .fetch_optional(&db).await
    .map_err(|e| RuleServiceError::Database(e.to_string()))?;

// ❌ 违反：无谓的 unwrap（除测试和 main）
let result = some_fallible_fn().unwrap();       // ❌ 生产代码禁止
let result = some_fallible_fn().expect("msg");  // ❌ 同样禁止

// ⚠️ 允许 unwrap 的场景：
// 1. 测试代码中
// 2. main() 函数中
// 3. 确定不可能失败的操作（如已知配置值）
let once = OnceLock::new().get_or_init(|| /* 初始化 */);
```

---


## 13. Performance & Memory Guidelines


### 13.1 堆分配策略

```rust
// ✅ 正确：优先栈分配
let decision = PolicyDecision { allowed: true, reason: "ALLOW".into(), ... };  // 栈

// ✅ 正确：需要堆时使用 Box
let evaluator: Box<dyn ConditionEvaluator> = Box::new(TimeRangeCondition);

// ✅ 正确：高频路径使用 Arc 共享
let engine = Arc::new(PolicyEngine::new());  // 只创建一次，共享引用

// ❌ 违反：热点路径中不必要的堆分配
pub fn evaluate(&self) -> PolicyDecision {
    let steps: Vec<EvaluationStep> = Vec::new();  // ❌ 每次都堆分配
    // 应使用: let mut steps = Vec::with_capacity(8);
}
```

**分配策略表**：

| 场景 | 推荐 | 原因 |
|------|------|------|
| 局部变量 | 栈（默认） | 零开销 |
| 动态分发 | `Box<dyn Trait>` | 需要虚表 |
| 线程间共享 | `Arc<T>` | 引用计数 |
| 共享可变状态 | `Arc<RwLock<T>>` | 读写锁 |
| 配置热更新 | `ArcSwap<T>` | 无锁读取 |
| 大对象传递 | `Box<T>` | 避免栈溢出 |
| 写时复制 | `Cow<'_, T>` | 减少克隆 |
| 连续内存 | `Vec<T>` | 缓存友好 |


### 13.2 Vec 容量预分配

```rust
// ✅ 正确：预分配已知容量
let mut entries = Vec::with_capacity(rule_count);  // 避免多次 realloc

// ❌ 违反：反复 push 未知大小
let mut entries = Vec::new();
for i in 0..1000 {
    entries.push(entry(i));  // 多次 realloc
}
```


### 13.3 Strings 与 Cow

```rust
// ✅ 正确：已知修改时使用 String，可能不需要改时使用 Cow
fn normalize_action(action: &str) -> Cow<'_, str> {
    let lower = action.to_lowercase();
    if lower.as_str() == action {
        Cow::Borrowed(action)    // 零拷贝
    } else {
        Cow::Owned(lower)        // 仅此路径有分配
    }
}

// ✅ 正确：API 参数使用 &str
pub fn check_permission(&self, resource: &str, action: &str) { ... }  // 接受所有字符串类型

// ❌ 违反：API 参数使用 String（要求调用方 transfer 所有权）
pub fn check_permission(&self, resource: String, action: String) { ... }  // ❌
```


### 13.4 Bytes 与零拷贝

```rust
// ✅ 正确：使用 bytes::Bytes 表示网络包
async fn handle_packet(payload: Bytes) {  // 共享引用计数，零拷贝
    let header = &payload[..4];           // 不复制
    let body = &payload[4..];             // 不复制
}

// ✅ 正确：HTTP 代理使用 reqwest + Body
async fn forward(body: Body) -> Response {
    // Body 在转发过程中不反序列化，零拷贝
    upstream.send(body).await
}

// ❌ 违反：非必要拷贝
let header = payload[..4].to_vec();  // ❌ 堆分配 + 复制
```


### 13.5 异步热点路径

```rust
// ✅ 正确：tokio::select! 优先于 spawn
tokio::select! {
    msg = rx.recv() => handle(msg),
    ws_msg = socket.recv() => handle_ws(ws_msg),
}

// ✅ 正确：使用 tokio::spawn 用于真正并行的任务
tokio::spawn(async move {
    // CPU 密集或长时间运行的任务
});

// ❌ 违反：为每次请求 spawn 新任务（创建 1000 个轻量任务）
for ctx in requests {
    tokio::spawn(async { engine.evaluate(&ctx).await });  // 应批量处理
}
```


### 13.6 序列化性能

```rust
// ✅ 正确：优先 serde_json，避免不必要的序列化
let json = serde_json::to_string(&data)?;

// ✅ 正确：API 返回使用 Json 类型，框架自动处理
async fn get_data() -> Json<ApiResponse<Data>> { ... }

// ⚠️ 注意：json! 宏在热点路径有解析开销
let body = json!({ "code": "OK" });  // 在常量位置使用 json! 或定义 static
```

---


## 14. API Evolution & Stability


### 14.1 可见性控制

```rust
// 可见性层级（从严到宽）
fn private_helper() {}                    // 私有：仅当前模块
pub(crate) fn crate_only() {}             // 仅当前 crate
pub(super) fn parent_module() {}          // 仅父模块
pub fn public_api() {}                    // 公开 API（语义版本约束）
```

**原则**：

| 可见性 | 使用场景 | 版本约束 |
|--------|---------|---------|
| 默认（私密） | 实现细节、内部辅助函数 | 无 |
| `pub(crate)` | crate 内部共享，不对外暴露 | 小版本可改 |
| `pub` | 对外 API | **大版本锁定** |


### 14.2 API 兼容性保证

```rust
// ✅ 正确：新增字段使用 Option 或默认值
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_required: Option<bool>,    // ✅ 新增字段，不影响旧消费者
}

// ✅ 正确：使用 #[non_exhaustive] 允许未来扩展
#[non_exhaustive]
pub enum Effect {
    Allow,
    Deny,
    NotMatch,
}

// ❌ 违反：删除公开字段（breaking change）
pub struct PolicyDecision {
    // pub audit_required: bool,  // ❌ 删除会破坏下游 match
}

// ❌ 违反：重命名公开项（不经弃用流程）
// 应先用 #[deprecated] + 别名过渡
```


### 14.3 弃用流程

```rust
// 1️⃣ 标注 @deprecated
#[deprecated(since = "2.0.0", note = "Use PermissionClient::check() instead")]
pub fn check_permission_old(ctx: PolicyContext) -> PolicyDecision {
    // ...
}

// 2️⃣ 提供迁移引导
impl PolicyEngine {
    /// 权限检查（旧接口，请使用 [`PermissionClient::check`]）
    #[deprecated(since = "2.0.0", note = "Use PermissionClient::check() instead")]
    pub fn evaluate_old(&self, ctx: &PolicyContext) -> PolicyDecision {
        let client = PermissionClient::new(...);
        client.check(ctx)
    }
}

// 3️⃣ 弃用后保留至少一个小版本
// 4️⃣ 大版本发布时移除
```

**弃用生命周期**：

```
Phase 1:  标记 #[deprecated] + 文档说明替代方案 → 仍在 API 中可用
Phase 2:  保留兼容性（使用旧 API 时发出编译警告）
Phase 3:  大版本发布时 —— 移除（breaking change）
```


### 14.4 0.x workspace 内部破坏性变更例外

`` 仍处于 0.x workspace 阶段时，允许对可在同一仓库内同步迁移的内部接口直接下线，但 0.x 版本号本身不构成自动删除授权。适用范围仅包括：

- `pub(crate)` 项；
- 仅供 workspace 内部调用、可在同一 PR 内完成迁移的内部接口；
- workspace 内部 HTTP/RPC 接口。

仅当本次变更清单逐项列明时，才允许直接删除 Rust HTTP 旧入口、旧协议、旧字段或 fallback。稳定 `pub` API、跨仓或外部 HTTP 接口、消息及消息协议、数据库协议均排除在本例外之外；这些接口仍须遵循稳定性和兼容性要求。

**与弃用流程的优先级**：仅满足上述范围和清单条件的 0.x workspace 内部接口，才可优先适用本例外并跳过 §14.3 的 `#[deprecated]` 过渡；不满足任一条件的接口，必须遵循 §14.3。既有 `compatibility`/`legacy` 入口不得因重构、路由整理或清理 dead code 被隐式删除。

**同一 PR 的强制要求**：

1. 同步迁移全部仓内调用方、测试和相关文档，不得留下旧入口的有效引用。
2. 在提交信息或 PR 描述中明确标注 `BREAKING CHANGE`，并列出删除清单、替代入口、影响范围、生效时间、迁移方案和回滚方案。
3. 对不在本例外范围内的稳定 `pub` API、跨仓/外部 HTTP、消息或数据库协议，不得以 0.x workspace 例外规避兼容性审查。


### 14.5 版本策略

```toml
# Cargo.toml 版本约定
# - 所有 crate 版本号对齐
# - 0.1.x = 开发阶段，可随时 break
# - 1.0.0 = 首次稳定发布
# - 1.x.x = 兼容性发布

[package]
name = "astral-common"
version = "0.1.0"     # 当前开发阶段
```

| 版本变化 | 允许的变更 | 实践 |
|---------|-----------|------|
| **补丁** (0.1.0 → 0.1.1) | Bug 修复、内部重构 | 不改变公开 API |
| **小版本** (0.1.0 → 0.2.0) | 新增 API、弃用旧 API | 保持向后兼容 |
| **大版本** (0.1.0 → 1.0.0) | 移除弃用 API、重构 | 集中 breaking changes |


### 14.6 Feature Flag 控制

```toml
# Cargo.toml：使用 feature flags 控制渐进式功能发布
[features]
default = ["full"]
full = ["v2-api", "experimental-metrics"]
v2-api = []
experimental-metrics = []
```

```rust
// 条件编译新 API
/// V2 API — 新的批量检查接口（实验性）
#[cfg(feature = "v2-api")]
pub async fn batch_check_v2(ctx: &[PolicyContext]) -> Vec<PolicyDecision> { ... }
```


### 14.7 文档中的兼容性标注

```rust
/// 获取用户列表
///
/// # Stability
/// ✅ Stable — 已发布的正式 API
///
/// # Pagination
/// 使用 cursor 分页，limit 最大 100。
pub async fn list_users(cursor: Option<String>, limit: i32) -> Result<Vec<UserDto>>;

/// 实验性 API
///
/// # Stability
/// ⚠️ Experimental — 可能在小版本中变更或移除
/// 使用前请与团队确认。
pub async fn experimental_api() -> Result<()>;
```


### 14.8 投影、读门禁与故障降级


#### 14.8.1 canonical published-evidence 与 legacy aggregate 边界

旧 `authorization_projection_head/outbox` 仍可能承载 `CARD`、`ELIGIBILITY`、`RULE_SET` 的 writer-correlation 或资格缓存失效事件，但 `20260831000001` 已退役旧 head 的状态列。旧 aggregate/head、`permission_rule_snapshot`、`rule_set_snapshot`、`projection_generation` 和 `READY` 只适用于 legacy/test、迁移和对账；不构成生产授权完成证明。

| 边界 | 兼容/资格用途 | 生产授权证明 |
|-----------|---------|-------------|
| `CARD` | 旧事件终态收口；不再由旧 worker 重建 snapshot/evict/refresh | current pointer → manifest/segment seal + scope/lineage/generation/`revoke_fence_proven` |
| `ELIGIBILITY` | 资格缓存失效与物理双卡上下文校验 | ELIGIBILITY 资格 head/载荷版本匹配；不替代授权 evidence |
| `RULE_SET` | 旧事件终态收口、迁移/对账 | current pointer → manifest/segment seal + scope/lineage/generation/`revoke_fence_proven` |

source mutation 的必要 source、grant revision/delta 和 audit correlation 必须在短事务内落盘；事务内不访问 Redis/RabbitMQ。`AuthorizationProjector` 在事务外编译、在发布事务内验证 lease、lineage、fence、generation、segment seal 和 current-pointer CAS；只有 durable commit proof 后才可进行可选的 evidence cache 推送。`AuthorizationArchiveWorker` 必须先完成整链归档 proof，再把 archive intent 标记完成。

未知 aggregate、current/manifest/segment 缺失、证明闩未置位、scope/摘要不一致、lease/CAS 未知或 worker 失败必须保持 PENDING/DENY、Blocked、Quarantine 或 Unknown 的安全状态，不得通过旧 snapshot/source/cache 放行。

#### 14.8.2 legacy migration/backfill 与审计关联

`20260822000001_rule_set_projection_schema_repair.sql` 与 `20260822000002_snapshot_validity_windows.sql` 只修复/回填 legacy RuleSet snapshot/head 形状；`20260825000002_incremental_projection_archive.sql` 创建 canonical grant/delta/manifest/segment/current/archive 表链但不负责既有数据 backfill。`20260827000001_authorization_projection_lineage_fence.sql` 增加 lineage 与 revoke-fence proof；`20260827000002_legacy_snapshot_tables_decommission.sql` 是带前置条件的 standby script。migration 文件存在不等于目标库已应用、旧表已 DROP、账本已 backfill/rehearsal 或正式流量已切换。

发布前必须在隔离/预演库验证 migration postcondition、账本回填、current pointer proof、manifest/segment seal、projector replay、archive proof、evidence cache 和 audit correlation。回滚以停止新写入、保留 durable delta/current/审计证据、修复或重放为主；禁止删除 canonical current、清空证明闩或恢复未证明旧 snapshot 制造授权放行。自然 wall-clock RuleSet `valid_to` 尚无独立 expiry scheduler/event。

#### 14.8.3 正式授权 fail-closed

- 生产 `SqlxRuleRepository` 的 strict capability 为 true；`PolicyEngine::evaluate()` 在 AUTHN/CARD_CONTEXT 与 resource/action 校验后只读取 `load_published_card_authorization` 返回的 canonical evidence。
- current pointer 缺失、`revoke_fence_proven` 未证明、manifest/segment 缺失或摘要失配、scope/lineage/generation 不一致、证据读取失败或有效 ALLOW 前复读失败 → `AUTHORIZATION_PENDING`/DENY。
- 不得回退 `permission_rule_snapshot`、`rule_set_snapshot`、旧 head、raw source、`evaluate_realtime()` 或未认证缓存。
- 未声明 strict capability 的 legacy/test repository 可保留旧 L1/L2/L2.5 阶段；旧 L2 repository error 在旧 L2.5 前 `DEPENDENCY_UNAVAILABLE`，但该兼容行为不能扩大生产路径。
- 生产 evidence cache 只能缓存已认证的 current/manifest/segment 证据；MAC、content hash、TTL、scope 或 cache epoch 失配时回 strict reader，不能授权。


#### 14.8.4 授权投影 lineage fence、归档意图与 projector 失败处置（2026-08-27 同步）

Rust-owned `20260827000001_authorization_projection_lineage_fence.sql` 为授权投影链补充 durable 证明语义，与 `astral-db` 仓储代码（证明门 [`validate_pointer_proof_state`](../../astral-db/src/authorization_projection_repository.rs#L1257-L1269)）共同维护以下不变式：

- **证明闩而非数值判定历史**：`authorization_projection_current.revoke_fence_proven` 是单调证明闩，由它（而不是数值 `revoke_fence` 本身）区分 legacy 未证明历史与 Rust 发布路径写入的指针。`revoke_fence_proven = 0` 表示该行早于本契约，其数值 fence（包括 0）不构成历史完整性证据；`revoke_fence_proven = 1` 表示指针由 Rust 发布路径写入，此时数值 0 是合法初值，已证明的 0 可在后续发布中原子推进为正 fence。禁止从数值 fence 反推证明闩。
- **未证明指针 fail-closed 并转显式恢复**：current 指针未证明时，正式授权读取（`read_published_authorization_state_in_tx`）、staging（`stage_authorization_manifest_in_tx`）与发布（`publish_current_pointer_in_tx`）一律失败，携带稳定机器码 `authorization_projection.backfill_or_rehearsal_required;pointer_proof_unproven`，不得以旧快照、raw source 或缓存放行。恢复只能由 operator 显式 backfill/rehearsal 写入带证明的指针；禁止 blanket/silent 的闩更新——正常 pointer CAS 的 `WHERE` 同样要求 `revoke_fence_proven = 1`，未证明行不会被常规发布路径推进。
- **归档意图字段来自加锁证据**：`authorization_archive_outbox.archived_revoke_fence` 与 `authorization_archive_manifest.archived_revoke_fence` 在写入 archive intent 与 proof 时从加锁的父 manifest/current 证据复制；调用方不得猜测或自带该值，caller 权威不构成 provenance。
- **NotReady backfill 与损坏分开处置**：projector 对 `backfill_or_rehearsal_required`（unproven history）按 `Blocked` 处理——事件保持 PENDING、在有界尝试预算内退避（预算耗尽后 max-cap），不是终态 quarantine，也不得用立即重试自愈，由 operator backfill/rehearsal 解决；确定性分歧或损坏（hash 漂移、immutable divergence、compiler stamp divergence、不可读 payload 等）按终态 quarantine 经 live-lease CAS 持久标记，quarantine 写入结果未知时停止后续 mutation 并单独计数（`events_quarantine_unknown`）。任何 unproven/unknown 状态都不得在任何一层扩大授权。


#### 14.8.5 L2 evidence 缓存 v3 认证契约（2026-08-29 同步）

published card evidence 的 L2 Redis 分发层（[`astral-db/src/evidence_cache.rs`](../../astral-db/src/evidence_cache.rs)，键族 `astral:auth:l2ev:*`/`astral:auth:l2sh:*`）是可认证缓存而非默认可信存储，v3 契约如下：

- **专用密钥强制，fail-closed 旁路**：L2 读、写与发布后推送一律要求专用环境变量 `ASTRAL_L2_EVIDENCE_HMAC_SECRET`（仅接受非占位符且 ≥32 字节/字符的值；绝不复用网关/内部签名密钥，绝不硬编码）。未设置或无效时 L2 读/写/推送整体旁路，直接回源严格 reader `load_published_card_grant_evidence`（fail-closed）——绝不在未认证缓存字节上授权，进程内 warn 一次。
- **HMAC-SHA256 绑定**：每张卡证据条目携带 `mac = HMAC-SHA256(专用密钥, 规范 cover)`，cover 绑定域分隔符 `astral:l2-evidence:v3:hmac-sha256`、精确 Redis 键（防键间重放）、schema 版本、manifest 版本组与重建后完整 payload 的 content_hash；读侧常数时间重验，缺失/失配/污染 → purge 回源，绝无"部分条目被接受"的路径。
- **共享单元 storage-only**：跨卡共享仅限 RULE_SET 内容寻址存储单元（`astral:auth:l2sh:{cache_epoch}:{tenant_id}:{digest}`，tenant+时代限定）——只是存储字节，永远不是授权来源；身份字段全部来自逐卡 envelope，单元缺失/摘要失配 = miss 回源，绝不降级放行。
- **单密钥语义与轮换**：每进程只解析一次密钥，不接受双密钥并存。轮换 = 更换 `ASTRAL_L2_EVIDENCE_HMAC_SECRET` 并轮换共享时代键 `astral:auth:cache_epoch`（Exec-L3 运维动作）；旧密钥条目在新密钥下 MAC 失配自然 purge 自愈。密钥泄露等同获得缓存伪造能力，轮换完成前属于 TCB 风险，须按敏感事件处置（撤销/轮换优先）。
- **范围与验收现状**：本契约只覆盖 `astral:auth:l2ev:*`/`astral:auth:l2sh:*` 两个 Rust 专属键族；Java 缓存家族（`perm:card:status` 等）与 permission_query v4 envelope 不在范围内。当前以 typed 单元测试与 `#[ignore]` 真实 Redis 集成测试（`REDIS_URL`/`DATABASE_URL` 环境门禁，未设置时显式 `[SKIP]`）覆盖；真实 Redis/MySQL 集成验收与生产切流仍是待办门禁，不得据此宣称生产验收。


### 14.9 文档注释

```rust
/// PolicyEngine 生产授权入口
///
/// AUTHN/CARD_CONTEXT 与 resource/action 校验后，生产 SqlxRuleRepository
/// 进入 published-evidence strict gate；旧 L1/L2/L2.5 仅为 legacy/test 兼容阶段。
/// current/manifest/segment proof 不足时返回 PENDING/DENY。
///
/// # 参数
/// - `ctx`: 权限检查上下文
/// - `repo`: 规则数据源
///
/// # 返回
/// `PolicyDecision` 包含是否允许、原因和完整评估路径
pub async fn evaluate<R: RuleRepository>(&self, ctx: &PolicyContext, repo: &R) -> PolicyDecision

// 模块级文档
//! 权限策略评估引擎核心
//!
//! 生产路径消费 canonical published evidence；
//! legacy/test 路径才使用 L1/L2/L2.5 规则阶段；所有失败默认 fail-closed。
```

- 所有 `pub` 项必须有 doc 注释
- crate 根必须有模块级文档（`//!`）
- 复杂逻辑必须注释说明意图

---


## 15. Cargo.toml 规范


### 15.1 依赖管理

- 所有公共依赖版本定义在 workspace `Cargo.toml` 的 `[workspace.dependencies]` 中
- 子 crate 通过 `{ workspace = true }` 引用
- 仅当子 crate 需要与 workspace 不同版本时，才直接指定版本


### 15.2 Crate 元信息

```toml
[package]
name = "astral-learn"
version = "0.1.0"
edition = "2021"
description = "AstralLight 教育域业务 — 学科/题目/考试"

[[bin]]
name = "astral-learn"
path = "src/main.rs"
```

> 注：`astral-learn` 当前位于默认 workspace 之外（根 `Cargo.toml` 的 `exclude`），解冻前不计入默认 `cargo --workspace` 检查/测试边界；此处仅作 crate 元信息示例。

---


## 16. 安全规范


### 16.1 敏感信息

- ❌ 禁止在代码中硬编码密码、Token、密钥
- ✅ 使用环境变量注入（`${VAR_NAME:?}`）
- ✅ 配置文件中的默认值使用 `change-me-in-production`


### 16.2 SQL 注入防护

- ✅ 始终使用参数化查询（`?` 占位符）
- ❌ 禁止字符串拼接 SQL
- ✅ 用户输入作为 resource/action 时，仅做字符串匹配，不拼接到 SQL


### 16.3 权限安全

- 所有 API 端点必须经过 Gateway JWT 验证（公开路径除外）
- 权限判定必须通过 `PolicyEngine.evaluate()` 统一入口
- 禁止在 handler 中判断角色做权限放行（`is_super_admin()` 等）

---


## 17. Git 提交规范


### 17.1 提交信息格式

```
<type>(<scope>): <subject>

<body>

<footer>
```

| 字段 | 说明 | 示例 |
|------|------|------|
| `type` | `feat` / `fix` / `docs` / `refactor` / `test` / `chore` | `feat` |
| `scope` | `engine` / `gateway` / `identity` / `learn` / `db` / `auth` | `engine` |
| `subject` | 英文小写，不超过 72 字符，祈使语气 | `add card status check` |


### 17.2 分支规范

- `dev` — 日常开发，可直接提交
- `fix/<issue-id>-<description>` — Bug 修复，从 dev 创建
- 禁止直接推送到 `main`

---


## 18. 本标准与 Java 标准的对应关系

| Java 规范 | Rust 对应 | 差异说明 |
|-----------|----------|---------|
| Controller | `api/` 模块中的 axum handler | Rust 无反射，handler 是普通 async fn |
| Service | `service/` 或 `srv/` 模块 | 通过 impl 和 trait 实现 |
| Mapper | `astral-db` 中的 Repository | sqlx query_as 替代 MyBatis XML |
| DTO | `serde` 派生 struct | 自动 Serialize/Deserialize，无 getter/setter |
| Lombok | `derive_builder` / `typed-builder` | 编译期生成 Builder |
| @Autowired | 构造函数注入 | Rust 无运行时注入 |
| @Transactional | 无直接等价物 | 使用 sqlx::Transaction 手动管理 |
| application.yml | `AppConfig` + config-rs | 环境变量优先级最高 |
| Logback | `tracing-subscriber` | 结构化日志，JSON 格式 |
| JWT filter | `jwt_auth_middleware` | axum middleware layer |
| @RequirePermission | `PolicyEngine::evaluate()` | 无注解反射，显式调用 |
| @Async | `tokio::spawn` | 显式任务生成 |
| OpenFeign | `reqwest` | 无框架代理，直接 HTTP 调用 |

---


## 附录 A：快速参考


### A.1 新 crate 创建流程

```bash
# 1. 创建目录
mkdir -p astral-xxx/src

# 2. 创建 Cargo.toml
# 3. 创建 src/lib.rs（库）或 src/main.rs（二进制）
# 4. 加入 workspace
# 5. cargo check 验证
```


### A.2 常用命令

```bash
cargo check                     # 类型检查
cargo check --workspace         # 全工作区检查
cargo fix                       # 自动修复 warnings
cargo test --workspace          # 全部测试
cargo test -p policy-engine     # 指定 crate 测试
cargo clippy -- -D warnings     # lint 检查
cargo fmt                       # 格式化
cargo doc --open                # 生成文档
cargo bench --workspace         # 基准测试
```


### A.3 依赖添加

```bash
# 添加到 workspace Cargo.toml（共享依赖）
[workspace.dependencies]
my-crate = "1.0"

# 在子 crate 中引用
[dependencies]
my-crate = { workspace = true }

# 或直接添加（独立依赖）
cargo add my-crate
```
