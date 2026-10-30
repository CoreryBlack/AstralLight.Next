# Rust 后端编码规范 V1.0

> 版本：1.4.0
> 日期：2026-10-28
> 状态：当前实现同步版（规则集完整结构与轻量发布凭证见 §15.7；运行时验收单列）
> 适用范围：`` 工作区所有 Rust crate
>
> 本版同步当前授权投影边界：canonical grant revision/delta/manifest/segment/current 链、`AuthorizationCompiler`、`AuthorizationProjector`、`AuthorizationArchiveWorker` 与生产 `SqlxRuleRepository` 的 published-evidence strict gate；旧 `authorization_projection_head/outbox`、`permission_rule_snapshot`、`rule_set_snapshot` 和旧 CARD/RULE_SET worker 仅作为兼容、迁移、对账或测试材料。本文是工程规范；架构解释和证据索引见 [Rust访问控制总览与调整路线](../架构/Rust架构设计/Rust访问控制总览与调整路线_V1.0.md) 与 [Rust权限投影快照与版本栅栏](../架构/Rust架构设计/Rust权限投影快照与版本栅栏_V1.0.md)。
>
> 2026-10-01 实现同步：workspace 当前成员为 `policy-engine`、`astral-types`、`astral-common`、`astral-db`、`astral-mq`、`astral-gateway`、`astral-identity`、`astral-trustgraph`、`astral-monitor`、`astral-single-node`、`e2e-bootstrap`；`astral-learn` 与 `astral-chat` 源码仍在仓库但由 `Cargo.toml` 的 `exclude` 明确冻结，`astral-cache` 随 Redis 编译层退役（`redis-layer-retirement-20261002`，BREAKING CHANGE 登记与兼容窗见 15.3）以同样的 `exclude` 方式退出 workspace，三者均不属于默认 workspace 编译/测试边界（`astral-cache` 源码零删除，manifest 已改为自包含 archive crate）。默认构建（不带 `redis-compat`）零 Redis 编译与链接；Redis 兼容路径收敛到各 runtime 显式 `redis-compat` feature 与 `ASTRAL_REDIS_PROJECTION_COMPAT` 运行时门。正式生产授权由 `SqlxRuleRepository` 的 published-evidence strict gate 驱动；`AuthorizationCompiler`/`AuthorizationProjector` 是当前新链实现，旧 `snapshot.rs`、旧快照表读写和旧 CARD/RULE_SET 重建通道属于退役/兼容材料。迁移 `20260830000001`、`20260831000001`、`20260831000002`、`20260903000001` 已存在于源码，但目标数据库是否应用仍须由显式 migration 与部署验收证明。

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
| `astral-cache` | 库（workspace exclude，自包含 archive） | Redis 缓存层：缓存装饰器、消息幂等；随 Redis 编译层退役退出 workspace（源码零删除，不参加默认编译/测试，恢复方式见 15.3） |
| `astral-mq` | 库 | 消息队列层：RabbitMQ 队列声明、Producer/Consumer |
| `astral-gateway` | 二进制 | API 网关：JWT 验证、路由转发、限流、断路器 |
| `astral-identity` | 二进制 | 身份认证服务：登录/注册/JWT 签发/用户管理/卡片管理/MFA |
| `astral-learn` | 库+二进制（源码冻结，workspace exclude） | 教育业务服务源码；不参加默认 workspace 编译/测试，解冻前不得宣称默认 gate 覆盖 |
| `astral-trustgraph` | 库+二进制 | 权限治理中心：规则管理/规则集/审批/审计/新授权投影 |
| `astral-chat` | 库+二进制（源码冻结，workspace exclude） | 即时通讯服务源码；不参加默认 workspace 编译/测试，解冻前不得宣称默认 gate 覆盖 |
| `astral-monitor` | 库+二进制 | 监控与告警服务：健康检查/指标/告警规则 |
| `astral-single-node` | 二进制 | 单机组合进程运行时：同进程装配 Gateway/Identity/MQ/TrustGraph（单机降级形态） |
| `e2e-bootstrap` | 二进制 | e2e 实验隔离启动入口 |


### 2.2 依赖方向

```
astral-types (零外部依赖)
    ↑
policy-engine → astral-types
    ↑
astral-common → astral-types
    ↑
astral-db → policy-engine + astral-common
astral-cache → policy-engine + astral-common      # workspace exclude（自包含 archive，默认不编译）
astral-mq → astral-common
    ↑
astral-gateway → astral-common
astral-identity → astral-common + astral-db
astral-learn → astral-common + astral-db
astral-trustgraph → astral-common + astral-db + policy-engine
astral-chat → astral-common + astral-db
astral-monitor → astral-common + astral-db
astral-single-node → astral-common + astral-db + astral-gateway + astral-identity + astral-mq + astral-trustgraph
e2e-bootstrap → astral-types + astral-db
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
# REDIS_URL 仅被显式启用 redis-compat 的部署消费（须同时 ASTRAL_REDIS_PROJECTION_COMPAT=true，见 15.3）；默认构建零 Redis 依赖。
REDIS_URL=redis://localhost:6379
RABBITMQ_URL=${RABBITMQ_URL:?RABBITMQ_URL is required}
JWT_SECRET=${JWT_SECRET:?JWT_SECRET is required}
GATEWAY_HMAC_SECRET=${GATEWAY_HMAC_SECRET:?GATEWAY_HMAC_SECRET is required}
RUST_LOG=info
```

---


## 10. 测试规范

### 10.0 测试语言与执行入口

- 本项目全部测试必须使用 Rust，包括单元、集成、端到端、契约、安全、故障注入、性能/基准测试，以及测试 harness、断言和结果判定；禁止使用 Python、JavaScript、Shell 或其他语言实现测试逻辑。
- 统一通过 Cargo 与 Rust 测试工具链执行。Shell 仅可启动 Cargo/标准工具和收集原始日志，不得承载测试用例、断言、参考算法或通过/失败判定。JSON/SQL 等可作为 fixture 或被测输入，其校验与判定由 Rust 测试完成。
- 既有其他语言测试不得作为验收证据；涉及其覆盖的变更时，应将相关测试迁移为 Rust 后验证，不得通过其他语言包装或生成测试判定来绕过此限制。

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
- Redis 集成示例/测试仅在显式 `redis-compat` feature 下编译（`required-features = ["redis-compat"]`）；feature 关闭时 cargo 将其整体 SKIP 且不计入通过数——SKIP 与 `#[ignore]` 统计必须与退出码分开记录，`exit 0` 不得折算为集成 PASS
- 标记需要 Docker 的测试为 `#[ignore = "Requires Docker"]`；外部依赖（MySQL/Redis/RabbitMQ）集成必须用显式 ignored 命令在真实依赖上执行，未执行不得宣称 PASS


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


#### 14.8.5 L2 evidence 缓存 CURRENT V6 认证契约（2026-10-28 同步）

published card evidence 的 L2 Redis 分发层（[`astral-db/src/evidence_cache.rs`](../../astral-db/src/evidence_cache.rs)，键族 `astral:auth:l2ev:*`/`astral:auth:l2sh:*`；`RedisL2EvidenceStore` 仅在显式 `redis-compat` feature 下编译，default-off，见 15.3）是可认证缓存而非默认可信存储，当前 V6 契约如下（stamp 语义见 §15.7）：

- **专用密钥强制，fail-closed 旁路**：L2 读、写与发布后推送一律要求专用环境变量 `ASTRAL_L2_EVIDENCE_HMAC_SECRET`（仅接受非占位符且 ≥32 字节/字符的值；绝不复用网关/内部签名密钥，绝不硬编码）。未设置或无效时 L2 读/写/推送整体旁路，直接回源严格 reader `load_published_card_grant_evidence`（fail-closed）——绝不在未认证缓存字节上授权，进程内 warn 一次。
- **HMAC-SHA256 绑定**：每张卡证据条目携带 `mac = HMAC-SHA256(专用密钥, 规范 cover)`，cover 绑定域分隔符 `astral:l2-evidence:v6:hmac-sha256`、精确 Redis 键（防键间重放）、V6 schema 版本、包含完整 stamp 的 manifest 版本组、`card_source_pending`、重建后完整 payload 及其 content_hash；读侧常数时间重验，缺失/失配/污染 → purge 回源，绝无“部分条目被接受”的路径。
- **共享单元 storage-only**：跨卡共享仅限 RULE_SET 内容寻址存储单元（`astral:auth:l2sh:{cache_epoch}:{tenant_id}:{digest}`，tenant+时代限定）——只是存储字节，永远不是授权来源；身份字段全部来自逐卡 envelope，单元缺失/摘要失配 = miss 回源，绝不降级放行。
- **单密钥语义与轮换**：每进程只解析一次密钥，不接受双密钥并存。轮换 = 更换 `ASTRAL_L2_EVIDENCE_HMAC_SECRET` 并轮换共享时代键 `astral:auth:cache_epoch`（Exec-L3 运维动作）；旧密钥条目在新密钥下 MAC 失配自然 purge 自愈。密钥泄露等同获得缓存伪造能力，轮换完成前属于 TCB 风险，须按敏感事件处置（撤销/轮换优先）。
- **范围与验收现状**：本契约只覆盖 `astral:auth:l2ev:*`/`astral:auth:l2sh:*` 两个 Rust 专属键族；Java 缓存家族（`perm:card:status` 等）与 permission_query CURRENT V6 envelope 不在本节的 L2 HMAC 范围内，但同样须满足 §15.7 的完整 stamp 栅栏。共享内容单元当前 schema/标识为 V6，属于授权 bundle，不改变稳定业务 grant/delta identity。当前以 typed 单元测试与 `#[ignore]` 真实 Redis 集成测试（`required-features = ["redis-compat"]` 编译门 + `REDIS_URL`/`DATABASE_URL` 环境门禁；feature 关闭时整组 SKIP，环境未设置时显式 `[SKIP]`，二者均不得计为 PASS）覆盖；真实 Redis/MySQL 集成验收与生产切流仍是待办门禁，不得据此宣称生产验收。


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


### 15.3 Redis 编译层退役与 `redis-compat` 兼容窗（2026-10-01 同步）

> 变更登记：`redis-layer-retirement-20261002`。本节按根 `Cargo.toml`、各 crate manifest 与 `astral-common` 启动校验源码核对；**BREAKING CHANGE 自本次变更部署起生效**（本文描述的是源码/manifest 当前状态，不代表任何环境已完成安装）。

**Workspace 边界（BREAKING CHANGE）**：

- `astral-cache` 从 workspace `members` 移入 `exclude`，源码保留，manifest 使用自包含依赖声明。归档验证从其 manifest 单独执行；恢复 workspace 成员前核对依赖版本和兼容调用方。
- 默认构建（不带 `redis-compat`）的编译/链接树为零 Redis；`Cargo.lock` 仍保留 optional `redis` 条目，但它不属于默认编译树。

**Feature 模型**：`astral-db`、`astral-mq`、Gateway、Identity、TrustGraph、Monitor 显式声明 default-off 的 `redis-compat`，Redis 依赖为 optional。`astral-common/redis-compat` 是零依赖 marker，不能证明某个宿主编译了 adapter；每个宿主必须在 DB/worker 启动前以自身 `cfg!(feature = "redis-compat")` 调用 `validate_redis_adapter_support`。组合 `astral-single-node` 不提供 Redis adapter。

**BREAKING CHANGE 清单与替代路径**（默认路径均已切换；下列兼容 API 未删除，仅收敛到 feature 门内）：

| 受影响消费方 | 默认替代路径 | 保留的兼容入口（未删除） |
|--------------|--------------|--------------------------|
| `astral-mq` consumer 消息幂等 | durable DB 幂等 `init_idempotency_db` 为默认要求 | `init_idempotency_redis`、`shared_idempotency_redis` |
| `astral-mq` consumers 会话撤销投影 | 进程内 LocalBus 撤销 handler + durable outbox | `set_session_revocation_redis` |
| `astral-gateway` 网关 Redis 初始化 | redis-free 默认路径 | `init_gateway_redis` |
| `astral-identity` 会话加速面 | MySQL durable proof 与进程内撤销面；默认构建没有 Redis 字段 | `AppState.redis` 字段仅 feature 开启时存在，类型仍为 `Option` |
| Identity 会话投影 worker | `spawn_without_redis_owned` 为默认装配入口，持有死亡信号和有界关闭句柄 | `spawn_without_redis` 与 feature 门内 `spawn(pool, redis)` 保留 detached 兼容合同，`spawn_owned` 提供兼容 adapter 的 owned 入口 |
| `astral-trustgraph` 缓存逐出 | 默认路径不触达 Redis | `delete_redis_keys` eviction compat 路径 |
| `astral-db` evidence L2 与缓存适配 | 进程内 TTL/容量 evidence 缓存 + strict DB 回源 | `RedisL2EvidenceStore`、perm/资格缓存、连接池、共享 cache epoch 适配 |

**迁移与运行时门**：需要 Redis 兼容路径的部署必须在构建期启用 `--features redis-compat`（含 feature 传播），并在运行期显式设置 `ASTRAL_REDIS_PROJECTION_COMPAT=true`（严格 bool，default-off，`astral-common::config` 唯一共享实现；开启时启动校验强制 `redis_url` 非空，`RedisCompatRequiresUrl`）。**未编译 redis-compat 的二进制在 env 置 true 时必须在启动期 fail-closed 拒绝**（`RedisCompatRequiresFeatureBuild`），不得静默 Redis-free 化或回退 raw/source 读取。

**回滚**：回滚 = 重新构建并部署兼容变体（`--features redis-compat` + `ASTRAL_REDIS_PROJECTION_COMPAT=true`）沿原链路恢复服务；**不得以删除 durable 事实（outbox/幂等行/投影/审计）作为回滚手段**。

**兼容窗到期**：显式 adapter 的当前登记期限为 **2026-12-31**。到期前核对剩余调用方、真实验收和切换批准；到期日不会自动删除 API 或改变部署配置。未完成验收前不得宣称生产迁移完成。

### 15.4 单机内存读写生命周期（2026-10-01 实现登记）

本节登记 R1–R4 的代码语义与兼容边界；架构、容量和恢复入口见[内存权威读面与失效通道方案](../架构/Rust架构设计/Rust内存权威读面与失效通道架构方案_V0.1.md)。真实环境未据此完成验收。

- **R1 失效传播**：单机使用有界 LocalBus/LocalProjectionBus 直发，低频 DB worker 仅恢复已提交意图。健康本地 supervisor 不执行周期全量 DB scan。多机保留 Rabbit durable 节点队列、exact inbox、application proof、confirm/ACK、DLX、水位和粘性 suspect；跨节点 δ 未实测，不宣称异常回退等于已证明的跨节点零窗口。
- **R2 正式 evidence 内存化**：只复用完整严格校验的 published 状态；卡片全部 aggregate、generation/dependency/fence/read-gate、source/health token 与有效期均须满足。source guard 在 begin 前取得，COMMIT/autocommit await 前 arm，仅已证明成功 disarm；取消或未知结果关闭 authority 读取，不用普通投影对账替代 writer 结果证明。宿主在 ownership/authority 读取前捕获 opaque fence，在 SoD 后最终复检；hub 已安装但 token 不可得即拒绝。容量、GC 或版本耗尽不得把缺失状态变成完整证据。
- **R3 资格及辅助镜像**：只缓存严格来源、完整物理绑定和期限的事实；每卡纪元 GC 不复用旧身份。组织 TenantUnmanaged 可缓存严格的“表存在且无 node”事实，SchemaUnmanaged 不缓存。资源归属仅支持已登记并覆盖 source writer 的类型，Chat 冻结表排除。SoD 仍为 deny-only 复核，策略收紧、provenance/context 或 read token 失配必须拒绝。
- **R4 Redis 退役**：保留 §15.3 的编译兼容 API；宿主和 legacy 环境回落共用同一冻结值，同值幂等、异值拒绝。`session_grant_mirror_enabled` 默认 true，显式 false 和 positive-disabled 保留；只有组合进程强门下安装 VerifiedPositive，独立 Gateway 保持严格 DB/DenyOnly。
- **SoD 持有语义（BREAKING CHANGE，随本次代码部署生效）**：context-aware 宿主路径以已经发布且当前有效的 `effective_grants` 与经过 provenance 对牌的组织贡献判断持有权限，冷/热同一合同；它不再把未经发布的 raw `permission_rule` 行当作额外拒绝依据。旧公开 `check_sod_conflict` 诊断入口保留 raw deny-biased 扫描。该变更可能使只有 raw 行、没有对应 published 授权的历史请求从拒绝变为放行，不能称为逐字节等同优化。替代入口为 `check_sod_conflict_with_context` 与 additive `check_sod_conflict_with_context_and_org`，旧 `check_sod_conflict_with_org` 保留诊断合同，影响 TrustGraph/Identity 的 SoD 宿主；部署前须对账依赖 raw 拒绝的历史规则并核验已发布贡献，回滚可恢复原诊断读取模式，不能删除 source、published 或审计事实。
- **生命周期与恢复**：运行期监督单写者锁身份与必需 owner。owner 失败设置独立粘性故障门，心跳或 pointer 对账不清除此门；不以虚构 source writer 表达任务死亡，不自动重放未知副作用。快照仅作 warm hint，当前 pointer/manifest/reference/segment 重验失败从账本恢复，不能作为授权证明。
- **source metadata**：卡/level template metadata 属于发行或治理事实，不制造无效果的授权 delta；保留 source fence 和同事务治理审计，实际管理员操作传播验证后的 actor/operation。受影响卡审计/资格扇出采用 SQL cap+1 和变更前拒绝，不能截断后报告成功。
- **兼容与验收**：既有公开 strict/诊断接口及消息 wire 保留，新增 context-aware/有界/owned 接口以 additive 方式装配。默认 workspace 编译、lint、非 ignored 测试和范围格式须从最终冻结快照执行；真实 DB/MQ/兼容 Redis、migration、crash、跨节点和跨城验收单独记录，未执行不得报 PASS。

---


### 15.5 聚合发布 ownership 与请求完成等待（2026-10-15，default-off）

`ASTRAL_PROJECTION_EXECUTION_MODE` 只接受 `legacy-hybrid`（缺省）或 `worker-owned`；启动时冻结，同值幂等、异值或未知值拒绝。配置冻结不执行 SQL；连接后必须先验证对应 schema，再启动 worker 和请求。调度拓扑 `TenantSerial` / `Partitioned` 与执行协议是不同维度，不得按是否安装 LocalBus 临时切换协议。

- **请求边界**：source transaction 保持短事务。只有已证明 COMMIT 成功才交付事务中保存的完整 `DeltaEventAppendRequest` 批次；commit 未知时不投递、不重放 source。`worker-owned` 请求只对完整 receipt 做有界 durable completion 等待，不 claim、编译、发布、release 或取消 worker lease。批次超过等待上限整体交回 worker，不能只完成前缀就报告全部完成。
- **执行边界**：本地通知、DB polling 和恢复共用 `(tenant_id, aggregate_type, aggregate_id)` 聚合能力、持久单调 epoch、fresh token 和唯一 active-event slot。event lease、operation id、通知 admission 或 ACK 都不能替代聚合能力。互斥不替代发布顺序：同 aggregate 按 `(source_generation, delta_event_id)` 推进，存在更早的未成功贡献时，在安装 event lease 前返回 `Busy`；轮询发现使用相同前驱门。前驱退避、隔离或未知不能由后继越过，且等待不增加认领、execution 或 failure 计数。worker 只物化已批准 source mutation，不产生新的授权事实。
- **发布与完成**：发布事务保持 lane → active delta → pointer → plan/manifest；只读完成观察使用 lane → pointer → exact delta → plan/manifest，并且仅接受 `SUCCEEDED` delta。完成观察不得先持历史 delta 再等待 pointer，否则会与 pointer-first 的规划读取形成锁环；lane 互斥保证它不会与同 aggregate 的 owned 发布并行持锁。规划 frontier 只纳入当前 generation 以内的已成功贡献，不把 active 未完成事件当作历史完成。impact plan、完整 manifest/segment/current CAS、delta `SUCCEEDED`、完成 seal 与 active slot 清理必须在同一事务。完成观察按精确不可变绑定验证历史发布，并验证目标 plan 的完整 item-set commitment、当前指针和保留历史的连续 parent/reference/segment seal；后继 pointer 不否定已证明的历史完成，但单看最新 pointer、status 或 join count 也不能证明完成。完整保留且通过校验的 `SUPERSEDED` manifest 必须有同一发布事务写入的 archive intent，可以证明历史发布，不能证明归档完成；已标记 `SUCCEEDED` 的 archive intent 必须匹配完整 terminal archive proof。历史被移除、损坏、缺 intent 或缺完成 seal 时不返回完成证明，也不从剩余行静默回填。
- **完成 commitment 与保留**：owned 发布将规范化 impact item 集合及 plan 身份、版本、generation、目标 manifest/digest 的 SHA-256 commitment 写入既有 `audit_log` 的 `owned_lane_COMPLETION_SEAL` 事件，严格要求唯一匹配。该记录与对应 delta/plan/manifest 历史共同保留；审计清理不得独立删除它后仍承诺历史完成。目标故障是部分 item 删除、字段漂移、重复/缺失 seal 和历史链破坏；阻断点是原子发布或只读完成验证，证据不足只会延迟/拒绝完成，不扩大授权。此 commitment 检测存储损坏或越界写入，不防御同时可任意重写事实与 seal 的数据库管理员；数据库和审计写入权限仍属可信计算基。保留历史验证成本随历史及载荷增长，不是常数时间；请求等待超时只交回 worker，不释放或重放未知执行。
- **预算与失败**：旧 `attempts` 保留为认领统计；真实执行次数与已证明执行失败分别计数。绑定校验、前驱等待、调度让行、dependency 和 pointer-moved replan 不污染 failure budget。历史计数不能无证据归零；切换前 drain/对账，首次加入 owned accounting 保守继承旧预算。UNKNOWN 先对账，不自动释放、失败标记或重放；已提交但镜像不可用只恢复镜像。
- **切换与回退**：新迁移 `20261015000001` 只增加 owned lane 与 execution accounting 列，release 保留 epoch 墓碑。启用前停止所有旧执行者并对账 source、delta、lane、manifest/current 和审计；不支持旧二进制与新协议混跑。回退先停新执行者并证明无 active/unknown episode，保留新增列和所有 durable 事实，按兼容模式重新启动；再次启用必须重新对账预算，不靠改 env 热切换。
- **读安全和证据边界**：撤销/收窄 pending-invalidates gate 与最终严格复读保持；普通新增不作为全卡阻塞。模型、单元测试、进程内签名 HTTP、真实 MySQL 与部署验收分别记录，未执行或缺 durable proof 不计 `PASS`。精确索引点查仍是 B-tree 查找，统一 owner 不消除全 manifest 物化成本。

<a id="156-授权代际-v3-封存合同2026-10-27"></a>

### 15.6 授权代际 v3 封存合同（2026-10-27，历史请求；CURRENT V6 见本节与 §15.7）

变更登记 `generation-v3-20261027`。本节保留 2026-10-27 的历史 v3 请求、代码/schema 形状与链接锚点；它不是当前授权 edition。当前授权合同统一为 **CURRENT V6**，由 `astral-types/src/edition.rs` 的单一 `authorization_edition!(6)` 定义派生，升级/回退按一个授权 bundle 处理。本节不证明任何环境已迁移或完成真实集成验收。

- **结构和公共入口（历史 v3 记录）**：`AuthorizationPublishedState`、`AuthorizationRecoveryState`、`AuthorizationStageOutcome`、`PublishedGenerationSummary`、`PublishedAggregateManifestSummary` 和 `ManifestDigestInput` 在该历史请求中增加必填 `PublicationSeal`。它封装摘要格式 3 与 UTC `sealed_at`；其余范围、generation、source/projected generation、父代、撤销栅栏、event/operation、编译器及有序内容引用仍组成同一完整发布证据。不将 per-grant revision 与 publication generation 混比。该形状仅说明历史 v3 artifact，不是 CURRENT release number。
- **摘要合同（历史 v3 记录）**：历史 `compute_manifest_digest()` 使用 `astral-auth-manifest-v3` 域，按固定顺序绑定格式、UTC 秒、范围、版本、来源、语义/依赖摘要、编译器、父代、撤销栅栏和有序 segment 内容摘要。整数为大端固定宽度，文本为 u32 长度前缀 ASCII，可选 ID 有显式存在标记，内容引用包含数量与顺序。CURRENT V6 的 digest domain 必须改由共享 edition 宏派生为 `astral-auth-manifest-v6`，不得在文档、调用方或测试中另造 release number。
- **时间职责**：`sealed_at` 是候选首次成功持久化封存时间，不是精确 COMMIT 时刻、请求时间、缓存读取时间、消息时间或快照捕获时间。NTP 由服务器保证；应用读取系统 UTC，编译器不读时钟、不访问网络。时间限制为 MySQL DATETIME 年份 1000–9999 的整秒，JSON 使用规范 RFC 3339 UTC 字符串。允许同秒或时钟小幅回调，排序和并发由 generation/CAS/fence 维持，不用时间单独授权。
- **稳定重试**：staging 在 pointer、父 manifest、目标 manifest 的锁序内按 aggregate＋target generation 查找候选，核对全部不可变维度及内容后复用原时间和摘要；仅首次插入采样时间。同代冲突不覆写。已证明回滚的尝试没有形成持久封存；COMMIT 未知先按 event/operation 对账，不重新取时间自动重放。
- **内容与读门（历史 v3 记录）**：时间仅进入代际 manifest 摘要，不进入 segment 内容地址。parent、finalize、publish、strict read、recovery、completion 和 archive 共用历史 v3 验证；内存安装核对 stage 与已提交状态的封存证据，同代分歧进入 suspect/PENDING。快照 payload 仅接受 CURRENT V6 payload，完整内容通过公共验证器，并在同一 durable 读取事务对照 pointer＋seal＋最终 manifest 摘要；旧 V1/V2 及缺字段或失配拒绝，不补造时间。MQ invalidation 只传 metadata，由严格读取获取完整证据；其 wire、segment/archive/completion domain 和快照 digest domain 均随 CURRENT V6 edition 成套升级。
- **schema 和替代路径（历史 v3 artifact）**：不可变 migration `20261027000001_authorization_projection_manifest_v3.sql` 增加必填无默认值的 `manifest_digest_version` 与 `sealed_at`；文件名、migration ID、SQLx checksum 和历史 SQL 内容保持原样。运行时 CURRENT V6 只接受共享 edition 对应的 seal/digest；旧开发 manifest 或现有 v3 rows 不得由新 reader 自动改写，缺少 CURRENT V6 证明时必须 BLOCKED，按批准的 derived-state rebuild 从保留 source/ledger、撤销和审计事实重建。仅供旧快照内部使用且已无调用方的旧锁定入口是否移除由代码变更另行记录；本节不把文件版本名当作 release number。
- **威胁与故障边界**：针对时间字段漂移、同代候选分歧、旧格式降级解释及快照文件自洽但与 durable 不同的故障，在 schema、封存摘要、严格读取和安装处拒绝。误放行代价是接受不一致授权证据，故默认 PENDING/DENY；误拒绝会延迟服务，需对账/重建恢复。普通 SHA-256 不认证发布者，数据库与审计权限仍属于既有可信计算基；本轮不实现恶意管理员防御、多云共识或自动覆盖数据库。
- **迁移和回退（历史 v3 记录，CURRENT V6 适用）**：停旧执行者并对账 UNKNOWN 后才可显式迁移；运行时不自动 DDL。V6 是代码、digest/seal、compiler、manifest/segment/archive/completion、invalidation、cache/MAC、snapshot schema/payload 与 reader gate 的原子 bundle，升级或回退都必须停止、reconcile、validate 后执行经批准的环境操作。不得把旧 v3 durable proof/MAC 原地重标为 V6，不得自动协商或接受低版本；不得重置 generation、恢复 revoked access、删除 pending 或用旧 snapshot/source fallback 放行。真实迁移/清理/部署另走批准、备份/恢复或 forward-fix、postcondition 和人工终审。

<a id="157-规则集完整结构与轻量发布栅栏标准2026-10-28"></a>

### 15.7 规则集完整结构与轻量发布栅栏标准（2026-10-28，CURRENT V6）

变更登记 `ruleset-standard-20261028` / `authorization-edition-20261028`。本节是规则集结构和相关发布读面的规范源；架构、API 和迁移材料只引用本合同。适用范围为当前 workspace 的规则集 source/read view、canonical 授权发布、发布摘要、失效传输、内存/缓存与本地恢复；冻结的 exclude crate 不因本次变更解冻。**CURRENT V6** 是本次统一 edition，结构升级不表示目标环境已迁移，也不授权执行 DDL、删除数据、发布消息或部署。

#### 15.7.0 CURRENT V6 单一授权 edition 与派生标识

`AUTHORIZATION_EDITION=6` 是当前授权发布号的唯一 live numeric source；选择 V6 是因为当前 permission envelope 的最高现行版本为 V6。该值定义于共享 `astral-types/src/edition.rs` 的单一 `authorization_edition!(6)` 宏。所有当前数字和字符串标识必须由该宏派生；跨 crate Rust contract test 必须验证各 crate 使用同一 edition，禁止在 policy-engine、DB、MQ、cache、snapshot、ORG_SCOPE 或文档中另造 release-number 常量。以下标识属于同一 CURRENT V6 bundle：

| 语义 | CURRENT V6 标识 |
|---|---|
| seal / manifest digest version | `6` / `digestVersion: 6` |
| manifest digest domain | `astral-auth-manifest-v6` |
| compiler | `astral-authorization-v6` |
| segment format | `authorization_grants_json_v6` |
| segment seal domains | `astral-auth-segment-seal-v6/semantic`、`astral-auth-segment-seal-v6/dependency` |
| archive proof domain | `astral-auth-archive-proof-v6` |
| completion audit/item-set domains | `astral-owned-completion-audit-v6`、`astral-owned-completion-item-set-v6` |
| ORG_SCOPE publication compiler | `astral-org-authorization-v6` (default-off) |
| ORG_SCOPE dependency/segment/manifest proof domains | `astral-org-dependencies-v6`、`astral-org-segment-v6`、`astral-org-publication-v6` (default-off) |
| invalidation event families | `EVIDENCE_INVALIDATED`、`ELIGIBILITY_INVALIDATED`、`SESSION_REVOKED`、`INVALIDATION_HEARTBEAT` all V6 |
| permission/L2 evidence/shared content unit | permission envelope V6; L2 evidence V6; shared content unit V6 |
| L2 MAC | `astral:l2-evidence:v6:hmac-sha256` |
| snapshot | CURRENT frame/schema V6 and authorization payload V6; old V1/V2 names retained only for rejection diagnostics |

上述 release labels 不改变稳定业务 grant/delta identity encoding、UUIDv5 algorithm、generation/revoke/lease 语义、HTTP API routes、Cargo semver、schema migration IDs、历史 SQL/checksums 或文档文件名版本。版本一致性也不等于权限或 generation downgrade，不以 NTP 时间排序取代 generation/CAS/fence/lease。

旧 V1/V2/V3/V5 constants 如因公共 API、历史数据或错误诊断保留，必须明确标为 retired/rejection-only；新 reader/runtime 不接受旧 proof、旧 MAC、旧 wire、旧 cache 或旧 snapshot，且不自动协商、补字段、重标 durable proof 或降级放行。



#### 15.7.1 完整规则集结构与源模型

完整规则集由 `rule_set` 本体、`rule_set_entry` 条目集合和 `card_rule_set_ref` 绑定组成。共享完整源模型分别为 `RuleSetDefinition`、`RuleSetEntryDefinition`、`CardRuleSetBinding`；共享层不依赖 SQLx，仓储私有 row 明确转换到源模型。

| 源模型 | 完整字段 |
|---|---|
| `RuleSetDefinition` | `rule_set_id`、`name`、`code`、`description`、`source_type`、`source_id`、`enabled`、`created_at`、`updated_at`、`tenant_id` |
| `RuleSetEntryDefinition` | `entry_id`、`rule_set_id`、`resource_type`、`resource_id`、`action_code`、`effect`、`condition_json`、`priority`、`enabled`、`valid_from`、`valid_to`、`created_at`、`updated_at`、`tenant_id` |
| `CardRuleSetBinding` | `id`、`card_id`、`rule_set_id`、`ref_type`、`created_at`、`tenant_id` |

- `source_type` 是规则集来源/ownership 判别；`ref_type` 是绑定层级 `BASE`/`OVERLAY`。二者不得混用。源表没有 `version` 列；不得把旧共享实体的 `version` 当作 canonical publication generation。
- 一个规则集包含多条条目，可由多张卡引用；绑定以 `(card_id, rule_set_id)` 唯一。来源、绑定、条目及实际授权贡献的租户与卡片范围须一致；SQL 历史 nullable `tenant_id` 不表示正式授权允许无租户，缺失或不一致必须 PENDING/DENY。
- SQL `DATETIME` 按 UTC 解释，私有 row 使用 `PrimitiveDateTime` 解码并显式转换到 UTC；完整共享源模型使用 UTC `OffsetDateTime`，wire 使用 RFC 3339 UTC `Z`。source 创建/更新时间、条目有效期、发布封存时间、消息时间和快照捕获时间是不同字段，不得相互补齐。
- `enabled`、有效窗口、租户与来源字段必须在完整读取中保留，不得由简化 DTO 静默丢弃。列表计数和绑定后的名称/code 是派生展示字段，不属于源行。
- 源表保留 `ALLOW`/`DENY`、条件、priority 等表达槽位，不表示 canonical positive grant 已支持全部表达。当前正式匹配器只消费可忠实表示的无条件 ALLOW；未支持的效果/条件写入仍在副作用前拒绝。此次结构升级不放宽授权语言。

#### 15.7.2 命令、读视图与公开兼容面

- 生产 repository/API 读视图必须从上述完整源模型生成。响应保留既有 `id`、`refType`、`resource`、`action` 等公开键，并补齐 canonical 字段；别名必须从同一源字段生成，不得独立写入。`refType` 在规则集摘要中是历史 `source_type` 别名，在 binding 中才是 `BASE`/`OVERLAY`。
- 写命令是受限输入，不能直接反序列化完整 source response。生成 ID、tenant、source owner、服务器时间及其他未开放字段不能由客户端覆盖；未知或未支持字段必须显式拒绝，不能接受后忽略。既有 immutable 字段若作为兼容输入保留，只能作为与现值一致的断言，不能改写 ownership。
- 稳定公开的旧 `RuleSet`、`RuleSetEntry`、`CardRuleSetRef` 保留原 Rust 字段和 serde 形状，仅作为 legacy 兼容模型；生产路径改用完整模型。不得用 type alias 或伪造缺失字段把旧实体解释为完整规则集。HTTP 兼容键、共享 public API 和数据库协议不得因仓内接口升级被隐式删除。
- `CanonicalGrant` 仍保存 grant identity、revision/state、source/binding、tenant/domain/card/user、resource/action/effect、validity 和 provenance；RULE_SET 贡献必须保留 binding 与 source entry。source revision 与 source/publication generation 分属不同版本域。

#### 15.7.3 轻量发布身份：版本号＋哈希＋时间戳

已封存代际的统一轻量表示为 `PublicationStamp`，不包含完整规则条目、grant 列表或 segment payload：

```json
{
  "generation": 7,
  "manifestDigestHex": "abababababababababababababababababababababababababababababababab",
  "seal": {
    "digestVersion": 6,
    "sealedAt": "2023-11-14T22:13:20Z"
  }
}
```

- `generation` 是正数且不超过 SQL BIGINT 正值范围；`manifestDigestHex` 是规范小写 64 位 SHA-256 hex；`seal` 遵守 §15.6 的历史封存字段形状，但其 CURRENT edition 必须为 V6。缺任一字段、未知字段、旧格式或非法值均拒绝。scope 由外层 tenant/card/aggregate identity 约束，不能跨 scope 比较。
- stamp 从同一已严格验证的 manifest/state 派生，哈希使用最终 `manifest_digest`。当前 compiler 标识必须是共享 edition 派生的 `astral-authorization-v6`；`semantic_hash` 是 compiler/tenant/projection version/dependency 绑定的版本标识，不是完整内容哈希，不能代替最终 manifest 摘要。
- 完整内容继续由 references 和不可变 segments 承载。CURRENT V6 manifest 摘要使用共享 edition 派生的 `astral-auth-manifest-v6`，绑定封存时间与有序 segment 内容摘要；segment semantic/dependency、archive proof 和 completion audit/item-set domain 同样使用 V6。只传 stamp 不重复携带规则内容。
- 发布摘要/frontier、发布后的失效 metadata、缓存身份和快照 frontier/token 必须携带或能无损派生完整 stamp。相同 scope/generation 的哈希或封存时间分歧是证据冲突，不得用时间较大、相同 generation 或多数消息覆盖；应保持 suspect/PENDING 或显式拒绝。
- CAS pointer、source generation、pending delta、lease/owner epoch、ELIGIBILITY 和进程内 read token 各有自己的拦截职责；它们不是已发布代际凭证。尚未封存/提交的 source 事件不能补造当前时间或哈希来伪装成 stamp，不能据此宣称发布完成。旧 head/snapshot gate 仅作既有兼容/资格/诊断，不能替代 canonical 发布证明。
- stamp 的相等性是版本、hash、时间三者共同相等；时间只参与完整性，不是授权排序。更大 generation、较新时间或消息到达均不独立授予权限。

#### 15.7.4 发布、传输与恢复

source 短事务仍只写必要 source、ledger/delta 和审计关联；source COMMIT 成功后才交付 receipt。projector 仅物化已批准 mutation；BUILDING/READY 和事务内 pointer CAS 均不能替代 publication COMMIT。COMMIT 成功后才安装内存和分发发布证据；UNKNOWN 先对账，不重放、补时间或清除撤权。

失效消息只传 scope/provenance/fence 和轻量 stamp，不传规则条目，也不独立批准新授权。source mutation 的失效 metadata 可携带同一 source 事务严格读取的已提交发布基线；它表示被观察/即将失效的旧发布，并不证明该 source mutation 已物化。没有已发布 pointer 时不造 stamp，原 pending/source generation/revoke fence 仍独立拦截。consumer 在 typed wire、durable receipt、内存应用和后续严格读取中保持同一 stamp；缺失/旧 wire 和冲突进入失败隔离或 PENDING，不能凭 ACK 当作完成。消息 envelope 的发送时间不替代 seal。当前 `EVIDENCE_INVALIDATED`、`ELIGIBILITY_INVALIDATED`、`SESSION_REVOKED` 与 `INVALIDATION_HEARTBEAT` 全部使用 CURRENT V6 wire/domain；旧 V1/V2 仅作拒绝诊断。

缓存的逐聚合身份从同 scope 的 COMMITTED manifest 派生完整 stamp。轻读以 LEFT JOIN 保留损坏 pointer 行，再校验 READY、撤销 proof、scope、generation、revoke fence 和 provenance；缺失 manifest、重复聚合、旧格式或非法时间一律拒绝，不能以 INNER JOIN 漏行或哨兵值制造相等。permission envelope、L2 evidence 与共享内容单元当前均为 V6；L2 MAC 域为 `astral:l2-evidence:v6:hmac-sha256`，cover 包含完整 stamp、pending 位和完整 evidence。旧 permission V1–V5、L2 V1–V5 及更早条目 miss/purge 后严格回源，不补字段。permission envelope 在统一前已使用数字 6：非空旧条目中的 seal 旧版会拒绝，但空 manifest 元数据可能仍能按当前形状解码，不能声称 schema gate 能区分全部旧 V6 字节。切换需按批准的缓存清理/时代轮换方案处理旧条目；空集也不能替代 pending、完整 fence、epoch 与 strict read-gate。TTL、容量、GC 和 source pending 防线继续独立生效。

本地快照当前只接受 `CURRENT` frame/schema V6（`SNAPSHOT_SCHEMA_VERSION = 6`），内层授权 payload 当前只接受同一 CURRENT V6 edition（`SNAPSHOT_PAYLOAD_VERSION = 6`）；外层 frame 与内层 payload 是两个字段/校验层，但共同消费同一个授权 edition，不能各自协商、混用或独立回退。旧 V1/V2 常量如保留只用于拒绝诊断。快照保留完整发布状态，frontier 只保存 compact stamp。恢复先验证文件完整性，再在同一有界 pointer-first durable 事务严格读取链并核对 pointer＋stamp；generation-only 或 pointer-only 相等不足以取得信任。hint 只进入 Warming，`warm_from_durable` 与通道实活/对账门仍适用。PolicyEngine 正式 ALLOW 前复读比较完整 manifest 身份，hash/time 漂移均拒绝。

#### 15.7.5 验证、切换和回退

本次新增 `PublicationStamp` 和完整源模型为 additive 公共入口；生产内部 repository read view、post-publication invalidation wire 和本地 snapshot frontier 是登记的切换单元（**BREAKING CHANGE 自采用新代码起生效**）。仓内生产者、消费者、fixture 和 Rust 测试须同步，不能新旧混跑；稳定旧 HTTP 键和共享兼容实体继续保留。相关公共语义、影响和替代入口见本节，不删除数据库事实或改历史 migration checksum。

验证至少覆盖完整字段往返、UTC wire、客户端生成字段/所有权改写拒绝、stamp 缺失/非法/旧版本、同代 hash/time 分歧、V6 producer/consumer 一致、四类 invalidation family 的版本一致、内存/缓存失配、快照 CURRENT V6 frontier/payload/token 与 durable 失配、source pending 与已发布身份隔离，以及共享 edition 的跨 crate contract test。所有测试与判定使用 Rust/Cargo；最终冻结快照执行 workspace gate。真实 MySQL/MQ/Redis、旧队列/inbox drain、migration、崩溃/UNKNOWN、多节点和部署须单列，当前验证仍 pending，未执行不得以单测或 exit 0 计 PASS。

切换前停止旧执行者，对账 UNKNOWN 与未完成 source/撤权/投影；消息旧版本和 snapshot 旧文件不能补造 stamp。旧 durable 消息需按原 operation/message identity 对账并在批准后处理；代码不自动删行或把旧消息伪装成 CURRENT V6 新证明。升级或回退必须以 digest/seal、compiler、segment/archive/completion、invalidation、cache/MAC、snapshot schema/payload 和 reader gate 为一个原子 bundle，完成 stop/reconcile/validate 后才执行批准的环境操作；不得把旧 proof/MAC 原地重标、自动协商、在当前 reader 中接受其他 edition、重置 generation、恢复 revoked access、删除 pending 或降低 read-gate。后续从统一 edition Vn 回退至 Vm 时，上述组件必须全部采用 Vm，并按获批方案核验或重建 Vm 派生证据；Vm reader 不得直接消费 Vn 证明。本次统一前各自编号的旧二进制不构成可混用的回退组合；必要时使用理解当前 edition 的修复版本或经批准 forward-fix。

威胁/故障模型是存储/传输漂移、同代分歧、缺字段和旧格式错误解释；阻断点为类型解析、严格读取、安装、缓存身份、传输及最终复读。误放行可能接受不一致授权，因此默认拒绝；误拒绝会延迟可用性，须通过严格对账恢复。普通 SHA-256、NTP 和进程内 fence 不认证恶意数据库管理员或构成多云共识，本次不新增跨云批准或自动数据库纠偏。

#### 15.7.6 ORG_SCOPE 组织发布证明（default-off）

ORG_SCOPE 的组织级 publication compiler、dependency proof、segment proof 与 manifest proof 也属于 CURRENT V6 版本一致性合同，但本条不启用 ORG_SCOPE default-off feature，也不改变稳定 grant/delta identity encoding、UUIDv5 algorithm、事务边界、generation/revoke/lease 或 owner 解析语义。它们统一由 `astral-types/src/edition.rs` 的同一 `authorization_edition!(6)` 宏派生：`astral-org-authorization-v6`、`astral-org-dependencies-v6`、`astral-org-segment-v6` 与 `astral-org-publication-v6`。组织 payload 保持自身 `OrgSegment { index, digestHex, content }` 合同，不与 canonical `authorization_grants_json_v6` segment 格式合并；组织证明只能在其显式启用且通过同一 strict publication/read gate 时生效。

ORG_SCOPE proof 与 canonical card/rule-set proof 必须作为同一 V6 bundle 做 producer/consumer、缓存、快照、失效和回退一致性检查。default-off 路径不得因 edition 对齐而自动放行、自动迁移、改变组织范围或绕过 PolicyEngine；旧组织 proof、缺失 edition、同代 digest/time/provenance 分歧只能拒绝、隔离或保持 PENDING。升级/回退仍须 stop、reconcile、validate 后进行批准的完整 bundle 操作，不得部分接受组织 proof 或用旧 proof/MAC/snapshot 补字段。

验证至少覆盖 organization compiler、dependency/segment/manifest domains 与共享 edition 的跨 crate contract test 一致；当前 ORG_SCOPE 真实迁移、owner resolver、跨云部署和 feature 启用验收仍不在本轮源码与文档变更范围内。


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
