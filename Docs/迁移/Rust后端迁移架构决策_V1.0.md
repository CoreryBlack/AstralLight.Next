# Rust 后端迁移架构决策 V1.0

> 版本：1.0.0
> 日期：2026-06-29
> 状态：决策确认稿
> 对应：Java → Rust 全量迁移，AstralLight 后端重构计划

---

## 1. 迁移总纲

### 1.1 动机

| 维度 | Java（当前） | Rust（目标） | 收益 |
|------|-------------|-------------|------|
| **内存安全** | 运行时 NPE、null 泛滥 | 编译期所有权 + borrow checker | 消除整类安全漏洞 |
| **表达力** | 规则靠字符串比较 | enum + match 穷举检查 | 编译期验证权限语义 |
| **并发安全** | 锁 + volatile + 人肉 review | Send + Sync trait 编译期保证 | 数据竞争零容忍 |
| **性能** | JVM 预热、GC 停顿 | 零成本抽象、无 GC | 可预测的延迟曲线 |
| **工程适配** | 基于正确性、可维护性和部署约束评估 | 以 Rust 类型与所有权模型加强边界检查 | 通过验证确认行为 |
| **商业落地** | 甲骨文授权费、JVM 运维成本 | Distroless 单二进制部署 | 降低部署复杂度 |

### 1.2 工作量估计

| 模块 | Java 行数 | Java 文件数 | Rust 估算行数 | 迁移阶段 |
|------|-----------|------------|--------------|---------|
| AstralPermissionClient | ~7,415 | ~33 | ~4,500 | Phase 1 |
| AstralGeneral（核心） | ~6,000 | ~60 | ~4,000 | Phase 2 |
| Gateway | ~683 | ~8 | ~800 | Phase 3 |
| AstralIdentity | ~8,083 | ~52 | ~5,500 | Phase 3 |
| AstralTrustGraph | ~21,604 | ~86 | ~14,000 | Phase 4 |
| AstralLearn | ~12,521 | ~127 | ~8,000 | Phase 4 |
| AstralChat | ~3,350 | ~49 | ~2,200 | Phase 4 |
| AstralMonitor | ~2,359 | ~23 | ~1,500 | Phase 4 |
| AstralBenchmark | ~19,836 | ~53 | ~15,000 | Phase 4 |
| AstralGeneral（辅助） | ~5,342 | ~43 | ~3,500 | Phase 4 |
| AstralCommonApi | ~60 | ~2 | ~100 | Phase 3 |
| **合计** | **~87,193** | **~536** | **~59,100** | |

> Rust 代码量约为 Java 的 68%（去除样板代码、Lombok 生成的 getter/setter、Spring 配置胶水代码）。

### 1.3 时间线

```
Phase 1 — 学术核心      2026 Q3 → 2026 Q4   (~4 个月)
Phase 2 — 基础设施      2026 Q4 → 2027 Q2   (~6 个月)
Phase 3 — Gateway+Identity 2027 Q1 → 2027 Q3 (~6 个月)
Phase 4 — 业务服务       2027 Q2 → 2028 Q2   (~12 个月)
```

---

## 2. 关键事实决策依据

### 2.1 Nacos 已禁用

当前所有模块 `application.yml` 中：

```yaml
spring:
  cloud:
    nacos:
      config:
        enabled: false
      discovery:
        enabled: false
        register-enabled: false
```

服务间通信通过环境变量直接指定 URI：

```yaml
LEARN_SERVICE_URI:http://localhost:9002
CHAT_SERVICE_URI:http://localhost:9003
IDENTITY_SERVICE_URI:http://localhost:9004
TRUST_GRAPH_URI:http://localhost:9005
MONITOR_SERVICE_URI:http://localhost:9006
```

**决策：迁移初期跳过 etcd/Consul，直接使用 config-rs + 环境变量。**

### 2.2 RocketMQ 未实际使用

pom.xml 中存在 RocketMQ 依赖，但：
- 无 RocketMQ 配置类
- 无 RocketMQ 生产者或消费者
- 所有 MQ 通信均通过 RabbitMQ（Spring AMQP）
- `AstralMonitorApplication` 显式排除 `RocketMQAutoConfiguration.class`

**决策：NATS/Pulsar 替换 RocketMQ 优先级降至最低，初期仅迁移 RabbitMQ（lapin）。**

### 2.3 无生产环境 Flyway 迁移

`src/main/resources/db/migration/` 不存在。仅测试用 SQL 文件在 `src/test/resources/sql/` 下。

**决策：Rust 迁移期间引入 sqlx migrate 管理数据库 Schema 变更，但初期不直接接管既有 Java 生产表。**

迁移边界：
- Phase 1 不执行生产 DDL，仅在测试库和 Rust 专用验证库中使用 `sqlx migrate`。
- Phase 2 先生成 baseline migration 固化当前既有 Schema，作为 sqlx 编译期校验输入，不回放到生产库。
- `sqlx migrate` 初期仅管理 Rust 新增表、影子比对表、兼容视图和测试夹具。
- Java 与 Rust 双引擎并行期间，任何会影响既有业务表的 DDL 必须走单独评审，避免 Java/MyBatis 与 Rust/sqlx 的 Schema 管理权冲突。

---

## 3. 组件替换矩阵

### 3.1 框架层

| Java 组件 | Rust 替代 | crate | 确认 |
|-----------|-----------|-------|------|
| Spring Boot (Tomcat) | Axum (Tokio) | `axum` | ✅ |
| Spring Cloud Gateway | Axum + Tower | `axum` + `tower` | ✅ |
| WebFlux | Tokio 异步运行时 | `tokio` | ✅ |
| Spring AOP | Tower Middleware | `tower` | ✅ |
| Jackson 序列化 | serde | `serde` + `serde_json` | ✅ |
| Lombok | derive 宏 | `typed-builder` / 手动实现 | ✅ |
| RestTemplate / WebClient | HTTP 客户端 | `reqwest` | ✅ |
| Hutool 工具类 | Rust 标准库 + crates | — | ✅ |

### 3.2 数据层

| Java 组件 | Rust 替代 | crate | 确认 |
|-----------|-----------|-------|------|
| MyBatis-Plus | **sqlx** | `sqlx` | ⬅ 关键决策 |
| Dynamic Datasource | 多命名连接池 | `sqlx::Pool<MySql>` 多实例 | ✅ |
| MySQL 驱动 | sqlx mysql | `sqlx` feature `mysql` | ✅ |
| Redis (Lettuce) | redis-rs | `redis` | ✅ |
| Redis Hash 缓存 | redis-rs hash 操作 | `redis` | ✅ |
| Flyway 迁移 | sqlx migrate | `sqlx-cli` | ✅ |

**ORM 选型理由（sqlx > SeaORM > Diesel）：**

| 维度 | sqlx | SeaORM | Diesel |
|------|------|--------|--------|
| 异步原生（tokio） | ✅ 原生 | ✅ | ❌ 需 spawn_blocking |
| 编译期 SQL 校验 | ✅ | ❌ | ✅ DSL 编译期 |
| 快照增量编译（复杂 SQL） | ✅ 原生 SQL 原子操作 | ⚠️ 抽象层限制 | ⚠️ DSL 嵌套困难 |
| 与 MyBatis 模式对齐 | ✅ 写 SQL 精确控制 | ❌ ORM 自动映射 | ⚠️ 非 SQL DSL |
| 学习曲线 | ✅ 会 SQL 即可 | ⚠️ ORM 概念 | ⚠️ 独有 DSL |

**核心论据：PolicyEngine 的快照增量编译、乐观锁原子更新、winner 语义需要精细的原生 SQL 控制。sqlx 是唯一提供编译期校验 + 异步原生 + 完整 SQL 表达能力的选项。**

**连接池说明**：`sqlx::Pool<MySql>` 自带高性能异步连接池，无需额外引入 `deadpool` 或 `bb8`。多数据源场景通过在应用层管理多个命名 `Pool` 实例实现，与 Java `DynamicDataSource` 模式等价。

**动态 SQL 风险与 hedge**：PolicyEngine 的规则匹配涉及运行时动态组合条件（`allOf`/`anyOf`/`not` + `TimeRangeCondition`/`IpRangeCondition` 等），纯手写字符串拼接 SQL 容易引入 SQL 注入或类型错误。当动态 WHERE 子句复杂度超出 sqlx `QueryBuilder` 安全范围时，引入 `sea-query`（`v1`，feature `sqlx-utils`）做类型安全查询构建。Phase 1 先用已知静态 SQL 跑通 oracle，Phase 2 根据实际动态 SQL 复杂度决定是否启用 `sea-query`。

### 3.3 消息队列层

| Java 组件 | Rust 替代 | crate | 确认 |
|-----------|-----------|-------|------|
| RabbitMQ (Spring AMQP) | lapin | `lapin` | ✅ |
| RabbitMQ 替代方案 | amqprs | `amqprs` | ⬅ 备选 |

**MQ crate 选型（lapin > amqprs）：**

| 维度 | lapin 4.x | amqprs 2.x |
|------|-----------|------------|
| 社区成熟度 | ✅ 最广泛使用的 Rust AMQP 客户端 | ⚠️ 较新但活跃 |
| 异步原生（tokio） | ✅ feature `tokio` | ✅ 原生异步 |
| 连接恢复 | ✅ 内置重连 | ✅ 内置 |
| 与 Spring AMQP 行为对齐 | ✅ 声明式 exchange/queue/binding | ✅ 声明式 |
| DLX / TTL 支持 | ✅ 声明参数 | ✅ 声明参数 |
| 文档与示例 | ✅ 丰富 | ⚠️ 较少 |

`lapin` 4.x 是最广泛验证的 Rust AMQP 客户端，与 `axum` + `tokio` 生态兼容最好，初期默认选择。`amqprs` 作为备选方案，在 lapin 出现兼容性问题时切换。

| 12 个队列 + DLX 模式 | lapin 声明 | `lapin` | ✅ |
| Jackson2JsonMessageConverter | serde_json 序列化 | `serde_json` | ✅ |
| MessageIdempotentService | Redis SETNX | `redis` | ✅ |
| 消息重试（DLX + maxRetry=3） | 自定义 Consumer 逻辑 | `lapin` | ✅ |

**MQ 队列清单（迁移时逐一对应）：**

| 队列名 | 路由键 | 类型 | 消费者模块 |
|--------|--------|------|-----------|
| `astral.audit.log` | `audit.log` | Direct | TrustGraph |
| `astral.notification` | `notification.send` | Topic | Learn |
| `astral.learning.progress` | `learning.progress` | Direct | Learn |
| `astral.login.event` | `login.event` | Direct | Identity |
| `astral.permission.refresh` | `permission.refresh` | Direct | TrustGraph |
| `astral.subject.delete` | `subject.delete` | Direct | Learn |
| `astral.chat.message` | `chat.message` | Direct | Chat |
| `astral.business.chat` | `business.chat.#` | Topic | Chat |
| `astral.delivery.ack` | `delivery.ack` | Direct | Chat |
| `astral.read.receipt` | `read.receipt` | Direct | Chat |
| `astral.question.comment` | `question.comment` | Direct | Chat |
| `astral.question.share` | `question.share` | Direct | Chat |

全部绑定 DLX 死信队列，TTL = 86400000ms（24h）。

### 3.4 安全层

| Java 组件 | Rust 替代 | crate | 确认 |
|-----------|-----------|-------|------|
| JJWT (0.11.5, HS256) | jsonwebtoken | `jsonwebtoken` | ✅ |
| HMAC-SHA256（网关签名） | hmac + sha2 | `hmac` + `sha2` | ✅ |
| Argon2 密码编码 | argon2 | `argon2` | ✅ |
| BouncyCastle (bcprov) | RustCrypto 系列 | `aes` `rsa` `sha2` 等 | ✅ |
| Gateway HMAC 签名 | hmac crate | `hmac` + `sha2` | ✅ |

**JWT Payload 结构（Java → Rust 一致）：**

Rust 字段命名采用 snake_case，但序列化/反序列化必须通过 `serde(rename = "...")` 与 Java 当前 JWT Claim 名完全对齐；不得因为 Rust 字段风格改变 Token 契约。

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwtClaims {
    sub: String,          // userId
    jti: String,          // token ID
    roles: Vec<String>,
    #[serde(rename = "tokenUse")]
    token_use: String,    // "ACCESS"
    #[serde(rename = "cardId")]
    card_id: Option<i64>,
    #[serde(rename = "templateId")]
    template_id: Option<i64>,
    #[serde(rename = "domainId")]
    domain_id: Option<i64>,
    #[serde(rename = "tenantId")]
    tenant_id: Option<i64>,
    #[serde(rename = "userId")]
    user_id: Option<i64>,
    #[serde(rename = "structureNodeId")]
    structure_node_id: Option<i64>,
    #[serde(rename = "tenantStatus")]
    tenant_status: Option<String>,
    exp: usize,
    iat: usize,
}
```

迁移前必须用 Java 生产样例 Token 做解码回归测试，确保 Rust 解析出的 `card_id`、`domain_id`、`tenant_id`、`tenant_status` 与 Java 完全一致。

**网关签名头（Java → Rust 一致）：**
```
算法：HMAC-SHA256
签名内容：method + "\n" + path + "\n" + userId + "\n" + tokenId + "\n" +
          cardId + "\n" + domainId + "\n" + tenantId + "\n" +
          actionCodes + "\n" + userRoles + "\n" + timestamp
头部：
  X-Gateway-Auth      = 签名 (Base64)
  X-Gateway-Timestamp = 时间戳（用于容差校验，默认 30s 偏差）
  X-Gateway-Signature = 签名算法标识
```

Gateway 迁移约束：
- Rust Gateway 不新增 `X-Gateway-Ts` 等临时签名头，避免下游签名校验出现双字段歧义。
- Rust Gateway 必须先清洗外部请求携带的 `X-Gateway-*`、`X-User-Id`、`X-Card-Id` 等内部身份头，再由网关重新签发。
- 签名串字段顺序、空值占位、Base64 编码方式必须与 Java `GatewayIdentityHeaders` 完全一致。

### 3.5 弹性与可观测性层

| Java 组件 | Rust 替代 | crate | 确认 |
|-----------|-----------|-------|------|
| Resilience4j 断路器 | Tower CircuitBreaker 中间件 | 自研 Tower Layer / `failsafe` 候选 | ◻ |
| Resilience4j 重试 | Tower Retry 中间件 | `tower` 内置 | ✅ |
| Resilience4j 限流 | Tower RateLimit / `governor` | `governor` | ✅ |
| Zipkin/Brave 链路追踪 | Tokio-rs `tracing` + OpenTelemetry | `tracing-opentelemetry` | ✅ |
| Prometheus 指标 | `metrics` + `metrics-exporter-prometheus` | `metrics` | ✅ |
| SLF4J/Logback 日志 | tracing-subscriber | `tracing-subscriber` | ✅ |

**断路器配置（从 Resilience4j 原样迁移）：**

断路器实现先保持候选状态，Phase 1 仅固化行为语义：打开、半开、依赖不可用或状态异常时一律 fail-closed，不得为了可用性返回 ALLOW。最终选型需比较自研 Tower Layer 与 `failsafe` 的异步支持、维护活跃度、指标暴露和半开探测可控性。

| 名称 | 故障率阈值 | 开路等待 | 半开调用 | 滑动窗口 |
|------|-----------|---------|---------|---------|
| `permission` | 50% | 30s | 5 | 20（计数） |
| `menu` | 40% | 20s | 3 | 15（计数） |

### 3.6 网关层（Gateway 细节）

当前网关（683 行，8 文件）执行以下职责，Rust 版本逐一对应：

| 功能 | Java 实现 | Rust 实现 |
|------|-----------|-----------|
| JWT 验证 | `JwtGlobalFilter` + `JwtTokenVerifier` | Axum middleware（`jsonwebtoken` crate） |
| 内部头清洗 | 移除 `X-Gateway-*` / `X-User-Id` 等 | Tower Layer：清洗后注入 |
| 公开路径跳过 | `GatewayAuthProperties.publicPaths` | config-rs 加载路径前缀白名单 |
| HMAC 签名转发 | `GatewayIdentityHeaders` | `hmac` + `sha2` crate |
| 租户状态检查 | JWT 中的 `tenantStatus` 字段 | middleware 层校验 |
| 限流 | RateLimiter (Spring Cloud Gateway) | `governor` crate + Redis |
| CORS | `CorsWebFilter` | `tower-http` `CorsLayer` |
| 路由转发 | Spring Cloud Gateway 路由表 | Axum Router + `reqwest` 反向代理 |

**路由配置（环境变量驱动，同 Java 模式）：**

```rust
/// Rust 版路由配置（config-rs 从环境变量 + YAML fallback 加载）
#[derive(Deserialize)]
struct GatewayConfig {
    learn_service_uri: String,    // 默认 http://localhost:9002
    chat_service_uri: String,     // 默认 http://localhost:9003
    identity_service_uri: String, // 默认 http://localhost:9004
    trust_graph_uri: String,      // 默认 http://localhost:9005
    monitor_service_uri: String,  // 默认 http://localhost:9006
    public_paths: Vec<String>,    // /api/v1/auth/login, /actuator/health 等
    max_permission_header_length: usize,  // 默认 16000
}
```

---

## 4. Cargo Workspace 结构

### 4.1 仓库组织

```
astral-light/                    # 原 AstralLight 仓库
├── AstralLight/                 # Java 版本（逐步退役）
├── AstralLight-Web/             # Vue 3 + TS 前端（保持不变）
├── crates/                      # Rust 工作区
│   ├── Cargo.toml               # workspace root
│   ├── policy-engine/           # Phase 1：政策引核心
│   ├── astral-types/            # Phase 1：共享类型
│   ├── astral-db/               # Phase 2：数据库层
│   ├── astral-mq/               # Phase 2：消息队列
│   ├── astral-cache/            # Phase 2：缓存层
│   ├── astral-gateway/          # Phase 3：API 网关
│   ├── astral-identity/         # Phase 3：认证服务
│   ├── astral-trustgraph/       # Phase 4：权限管理
│   ├── astral-learn/            # Phase 4：教育服务
│   ├── astral-chat/             # Phase 4：通讯服务
│   ├── astral-monitor/          # Phase 4：监控服务
│   ├── astral-benchmark/        # Phase 4：基准测试
│   └── astral-common/           # 公共基础设施
│       ├── config/              # 配置加载
│       ├── error/               # 统一错误类型
│       └── middleware/          # 共享 Tower 中间件
├── you/                         # Java（保持独立项目）
└── you-web/                     # Vue 3（保持独立）
```

### 4.2 Cargo.toml（Workspace 定义）

```toml
[workspace]
members = [
    "crates/policy-engine",
    "crates/astral-types",
    "crates/astral-common",
    "crates/astral-db",
    "crates/astral-mq",
    "crates/astral-cache",
    "crates/astral-gateway",
    "crates/astral-identity",
    "crates/astral-trustgraph",
    "crates/astral-learn",
    "crates/astral-chat",
    "crates/astral-monitor",
    "crates/astral-benchmark",
]
resolver = "2"

[workspace.dependencies]
# 框架与运行时
axum = "0.8"
tokio = { version = "1", features = ["full"] }
tower = "0.5"
tower-http = { version = "0.7", features = ["cors", "trace"] }
reqwest = { version = "0.13", features = ["json", "rustls"] }

# 序列化
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# 数据库
sqlx = { version = "0.9", features = ["runtime-tokio", "mysql", "time", "migrate"] }
# 可选：复杂动态 SQL 场景可使用 sea-query 构建类型安全的 WHERE 子句
# sea-query = { version = "1", features = ["sqlx-utils"] }

# 缓存
redis = { version = "1", features = ["tokio-comp", "connection-manager", "json"] }

# 消息队列
lapin = { version = "4", features = ["tokio"] }

# 安全
jsonwebtoken = { version = "10", features = ["rust_crypto"] }
argon2 = "0.5"
hmac = "0.12"
sha2 = "0.10"

# 配置
config = { version = "0.15", features = ["yaml", "env"] }

# 可观测性
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
tracing-opentelemetry = "0.33"
metrics = "0.24"
metrics-exporter-prometheus = "0.18"

# 弹性
# 断路器实现待 Phase 1 spike 后确认：候选为自研 Tower Layer 或 failsafe
governor = "0.10"

# 工具
time = { version = "0.3", features = ["serde"] }
uuid = { version = "1", features = ["v4", "v7", "serde"] }
typed-builder = "0.23"
thiserror = "2"
anyhow = "1"
garde = { version = "0.23", features = ["derive"] }
arc-swap = "1"
# once_cell 已内置于 std::sync::OnceLock (Rust 1.70+)
# dashmap 已移除：ResourceRegistry 启动期静态注册后只读，std::sync::RwLock<HashMap> 或 OnceLock 即可满足

# 测试
[workspace.dev-dependencies]
tokio-test = "0.4"
mockall = "0.13"
criterion = { version = "0.5", features = ["async_futures"] }
testcontainers = "0.27"
```

### 4.3 依赖版本校准说明

以下 crate 在初稿出具后已发布大版本升级，已校准至当前（2026-06-29）最新稳定版：

| Crate | 初稿版本 | 校准版本 | 变化性质 |
|-------|---------|---------|---------|
| `sqlx` | 0.8 | **0.9** | 小版本升级，feature 兼容 |
| `redis` | 0.27 | **1.0+** | **大版本**：移除 `async-std-comp`、`keep-alive` 默认 feature、`tcp_nodelay` 等。tokio 用户无影响 |
| `lapin` | 2.5 | **4.x** | **大版本**：新增显式 `tokio` runtime feature，MSRV 升至 1.88，edition 2024 |
| `jsonwebtoken` | 9 | **10.x** | **大版本**：引入 `rust_crypto`/`aws_lc_rs` 替代加密后端，MSRV 升至 1.85，edition 2024 |
| `tower-http` | 0.6 | **0.7** | 小版本升级 |
| `tracing-opentelemetry` | 0.28 | **0.33** | 适配 OpenTelemetry SDK 演进 |
| `metrics-exporter-prometheus` | 0.16 | **0.18** | 小版本升级 |
| `governor` | 0.8 | **0.10** | 小版本升级 |
| `testcontainers` | 0.23 | **0.27** | 小版本升级 |
| `once_cell` | 1 | **移除** | `std::sync::OnceLock` 自 Rust 1.70 起内置 |
| `dashmap` | 6 | **移除** | ResourceRegistry 启动后只读，`std::sync::RwLock<HashMap>` 足够 |
| `uuid` | v4 only | **+v7** | UUIDv7 时间有序，适配 MySQL InnoDB 主键，减少页分裂 |
| `chrono` | 0.4 | → **`time` 0.3** | **Rust 生态标准**：chrono RUSTSEC-2020-0071 长期未修复且维护放缓；`time` 纯 Rust，API 更安全。sqlx feature 切为 `time` |
| `derive_builder` | 0.20 | → **`typed-builder` 0.23** | **编译期必填校验**：`PolicyContext.action` 缺失在编译期报错而非 `build().unwrap()` panic |
| `config` | 0.14 | **0.15** | 小版本升级。保留 `config` 而非 `figment`：`config` 支持文件监听热更新（`File::watch`）和远程配置源（`AsyncSource`），为 Phase 3 Gateway 白名单热更新和未来配置中心集成预留能力 |

**新增依赖说明**：

| Crate | 版本 | 用途 | 选型理由 |
|-------|------|------|---------|
| `reqwest` | 0.13 | HTTP 客户端 | Gateway 反向代理 + 服务间调用。基于 `hyper` + `tokio`，Rust 生态事实标准 |
| `time` | 0.3 | 日期时间 | 替代 `chrono`。纯 Rust，零 unsafe，Rust 生态新的事实标准。sqlx 通过 feature `time` 兼容 |
| `typed-builder` | 0.23 | Builder 宏 | 替代 `derive_builder`。编译期强制必填字段（`build()` 无 `Result` 包装），更符合 Rust "让编译器做校验"哲学 |
| `garde` | 0.23 | 请求校验 | 派生宏式校验，与 axum extractor 配合优于 `validator`（更现代、async 兼容） |
| `anyhow` | 1 | 应用级错误 | 与 `thiserror`（库级错误）互补，简化 `main`/`fn` 级错误传播 |
| `sea-query` | 1（可选） | 动态 SQL 构建 | 当权限规则条件需要运行时动态拼装复杂 WHERE 子句时，提供类型安全替代手写字符串拼接 |

**安全 crate 说明**：
- `jsonwebtoken` 10.x 默认使用 `rust_crypto` feature（纯 Rust 实现），与 Java `io.jsonwebtoken:jjwt` 的 HS256/HMACSHA256 兼容。不引入 `aws_lc_rs`，避免 FIPS/OpenSSL 许可复杂性。
- `hmac 0.12` + `sha2 0.10` 组合用于 Gateway 签名头，算法与 Java `javax.crypto.Mac.getInstance("HmacSHA256")` 完全等价。

**lapin 4.x feature 说明**：
- `default = ["rustls", "default-runtime"]` → `default-runtime = ["tokio"]`
- 显式启用 `tokio` feature 确保与 `axum` 共享同一 tokio runtime，避免多 runtime 死锁。
- 4.x 连接恢复策略为 `Connection::run()` 循环 + `Channel::status().connected()` 探测，与 Spring AMQP `CachingConnectionFactory` 行为对齐。

**辅助依赖选型说明**：

- **`uuid` v7**：UUIDv7 是时间有序的（前 48 位为 Unix 毫秒时间戳），作为 MySQL InnoDB 主键时显著减少页分裂和 B+Tree 碎片化，写入性能优于随机 UUIDv4。`uuid` crate v1.23+ 通过 feature `v7` 提供支持。

- **`garde` > `validator`**：`validator`（0.20）在 async context 下需要显式调用 `.validate()`，且错误消息国际化依赖额外的 crate。`garde`（0.23）的派生宏直接生成校验代码，支持 async 校验和自定义错误类型，与 axum `FromRef`/`FromRequest` extractor 模式集成更自然。

- **`reqwest` 0.13 features**：`json` 启用 `serde_json` 集成（自动序列化/反序列化 API 响应），`rustls` 使用纯 Rust TLS 实现（与 lapin 的 TLS 后端统一为 rustls，避免混用 native-tls 与 rustls 导致的链接冲突）。

- **`typed-builder` 0.23**：项目中 `PolicyContext`（15+ 可选字段，`action` 必填）、`PolicyDecision`、`GatewayConfig` 等复杂结构体都需要 Builder 模式。与 `derive_builder` 不同，`typed-builder` 的 `.build()` 不带 `Result` 封装——必填字段未设置会在**编译期**报错，而非运行时 panic。这符合 Rust "让编译器做校验"的核心哲学。

- **`time` 0.3**：替代 `chrono`。Rust 生态当前首选 datetime 库。纯 Rust 实现，零 unsafe，API 设计避免了 chrono 的 `localtime_r` unsoundness（RUSTSEC-2020-0071，chrono 长期未修复）。`sqlx` 通过 feature `time` 实现 `OffsetDateTime` ↔ MySQL `DATETIME` 自动映射。JWT `exp`/`iat` 通过 `time::OffsetDateTime` + `unix_timestamp()` 计算。

- **`config` 0.15**：`config` 支持 `File::watch`（文件监听热更新）和 `AsyncSource`（远程配置源），为 Phase 3 Gateway 白名单热更新和未来配置中心集成预留能力。API 层面 `figment` 更简洁，但 `config` 的能力边界更适配项目长期演进需求。

- **`criterion` 0.5**：Phase 4 的性能验证核心不是"PolicyEngine 跑多快"，而是"Rust 版相对 Java 版快多少，且后续版本没有退化"。`criterion` 的基线对比（`with_baseline`）和回归检测是 `divan` 不具备的能力，对持续数月的 Rust vs Java 性能追踪不可或缺。

- **测试 mock 策略**：`mockall` 的 `#[automock]` 与 `#[async_trait]` 组合在复杂 trait（多方法、泛型参数）时有限制。对于 `RuleRepository` trait，建议手写 mock struct 实现，避免 automock 的 Send/Sync 边界问题。`mockall` 保留用于简单依赖的快速 mock，复杂 mock 走手动实现。

---

## 5. Phase 1 详细方案：PolicyEngine 核心迁移

### 5.1 目标

将 AstralPermissionClient 模块的 PolicyEngine 核心逻辑从 Java 翻译为 Rust，保持 API 语义完全一致。

### 5.2 Rust 核心类型定义

```rust
// === decision.rs：评估结果类型 ===

/// 策略评估效果
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
    NotMatch,
}

/// 单步评估记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationStep {
    pub phase: String,          // "L1_RULESET", "L2_PERMISSION_RULE", "L3_DEFAULT_DENY"
    pub result: Effect,
    pub detail: String,
    pub matched_rule_id: Option<i64>,
    pub source: Option<String>, // "OVERLAY", "BASE", "CARD_ONLY"
}

/// 策略决策结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: String,
    pub matched_rule: Option<String>,
    pub audit_required: bool,
    pub evaluation_path: Vec<EvaluationStep>,
}

// === context.rs：评估上下文 ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    pub user_id: Option<i64>,
    pub card_id: Option<i64>,
    pub template_id: Option<i64>,
    pub action_codes: Vec<String>,
    pub domain_id: Option<i64>,
    pub tenant_id: Option<i64>,
    pub structure_node_id: Option<i64>,
    pub resource: Option<String>,
    pub action: String,
    pub target_id: Option<i64>,
    pub sensitivity_level: Option<i32>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub request: Option<serde_json::Value>,
}

impl PolicyContext {
    /// 校验必填字段
    pub fn validate(&self) -> Result<(), ValidationError> {
        // Rust 编译期 + 运行时双层校验
    }
}

// === registry.rs：资源注册表 ===

use once_cell::sync::Lazy;
use dashmap::DashMap;

/// 资源类型注册表（启动期静态注册 + 运行时只读校验）
pub static RESOURCE_REGISTRY: Lazy<ResourceRegistry> = Lazy::new(|| {
    let mut reg = ResourceRegistry::new();
    reg.register("learn_subject", &["read", "create", "update", "delete", "import", "export"]);
    reg.register("permission_rule", &["read", "create", "update", "delete", "bind-permission"]);
    reg.register("permission_request", &["read", "create", "update", "approve"]);
    reg.register("organization", &["read", "create", "update", "delete"]);
    reg.register("domain", &["read", "create", "update", "delete"]);
    reg.register("audit", &["read", "export"]);
    // ... 全部 26+ 资源类型
    reg.register("chat_message", &["read", "create", "delete"]);
    reg
});

pub struct ResourceRegistry {
    inner: DashMap<String, std::collections::HashSet<String>>,
}

impl ResourceRegistry {
    /// 启动期静态注册，运行期只读校验。
    ///
    /// 生产代码不得在请求处理链路动态注册资源类型；新增资源必须先与 Java
    /// ResourceRegistry 快照比对，再通过代码变更进入内置注册表。
    pub fn validate(&self, resource: &str, action: &str) -> Result<(), RegistryError> {
        self.inner
            .get(resource)
            .ok_or(RegistryError::UnregisteredResource(resource.to_string()))
            .and_then(|actions| {
                if actions.contains(action) {
                    Ok(())
                } else {
                    Err(RegistryError::InvalidAction {
                        resource: resource.to_string(),
                        action: action.to_string(),
                    })
                }
            })
    }
}
```

### 5.3 PolicyEngine 核心（Rust 版）

`policy-engine` crate 只承载纯规则评估、类型定义和决策推导，不直接依赖 MySQL、Redis 或 RabbitMQ。数据库、缓存和消息队列访问分别放入 `astral-db`、`astral-cache`、`astral-mq`，由上层应用服务组合。

正式 authorization 路径为：L1 使用 `load_snapshot_winners` 读取 `rule_set_snapshot` 预计算胜者，L2 使用投影后的 `permission_rule_snapshot`（通过 `load_permission_rules` 暴露）。`load_rule_set_snapshots` 不属于正式 L1；它仅保留给 legacy/cache/test/consistency/simulation 兼容实现。raw source reads 仅用于 consistency/realtime/diagnostics，不得用于正式 authorization 放行。

建议通过仓储 trait 隔离外部依赖，并明确正式授权路径与兼容读取路径：

```rust
#[async_trait]
pub trait RuleRepository: Send + Sync {
    /// 正式 L1 authorization：读取预计算的 rule_set_snapshot 胜者。
    async fn load_snapshot_winners(&self, card_id: i64) -> Result<Vec<SnapshotWinner>, PolicyError>;

    /// 正式 L2 authorization：读取投影后的 permission snapshot。
    async fn load_permission_rules(&self, card_id: i64) -> Result<Vec<PermissionRule>, PolicyError>;

    /// 仅供 legacy/cache/test/consistency/simulation 兼容实现。
    async fn load_rule_set_snapshots(&self, card_id: i64) -> Result<Vec<RuleSetSnapshot>, PolicyError>;

    /// 原始 source reads 仅供 consistency/realtime/diagnostics 使用。
    async fn load_rule_set_entries_raw(&self, card_id: i64) -> Result<Vec<RuleSetSnapshot>, PolicyError>;
    async fn load_permission_rules_raw(&self, card_id: i64) -> Result<Vec<PermissionRule>, PolicyError>;
}
```

这样可在单元测试中注入 fake repository，在集成测试中注入 sqlx repository，并保证正式引擎路径不因数据库故障绕过 fail-closed 语义。

```rust
// === engine.rs：评估引擎 ===

use arc_swap::ArcSwap;
use std::sync::Arc;

/// L1/L2/L3 三层命中计数器
#[derive(Debug, Default, Clone, Serialize)]
pub struct HitStats {
    pub l1_hits: u64,
    pub l2_hits: u64,
    pub l3_hits: u64,
    // 时延分布（微秒）
    pub timing_ns: TimingBreakdown,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct TimingBreakdown {
    pub card_active_check_ns: u64,
    pub refs_load_ns: u64,
    pub overlay_eval_ns: u64,
    pub base_eval_ns: u64,
    pub perm_rule_eval_ns: u64,
    pub total_ns: u64,
}

/// PolicyEngine（线程安全，ArcSwap 实现运行时配置热更新）
pub struct PolicyEngine {
    stats: ArcSwap<HitStats>,
    circuit_breaker: ArcSwap<CircuitBreakerState>,
}

impl PolicyEngine {
    /// 三层评估主入口
    ///
    /// L1: RuleSet 预计算胜者匹配（先 OVERLAY 后 BASE）
    /// L2: 投影 permission snapshot 评估
    /// L3: DEFAULT_DENY
    pub async fn evaluate(&self, ctx: &PolicyContext) -> PolicyDecision {
        let mut steps = Vec::new();
        let start = std::time::Instant::now();

        // L1: RuleSet 评估
        if let Some(decision) = self.evaluate_rule_sets(ctx, &mut steps).await {
            return decision;
        }

        // L2: PermissionRule 回退
        if let Some(decision) = self.evaluate_permission_rules(ctx, &mut steps).await {
            return decision;
        }

        // L3: 默认拒绝（fail-closed）
        steps.push(EvaluationStep {
            phase: "L3_DEFAULT_DENY".into(),
            result: Effect::Deny,
            detail: "No matching rule found, default deny".into(),
            matched_rule_id: None,
            source: None,
        });

        PolicyDecision {
            allowed: false,
            reason: "DEFAULT_DENY".into(),
            matched_rule: None,
            audit_required: false,
            evaluation_path: steps,
        }
    }

    /// 规则集评估（OVERLAY 优先，DENY 短路）
    async fn evaluate_rule_sets(
        &self,
        ctx: &PolicyContext,
        steps: &mut Vec<EvaluationStep>,
    ) -> Option<PolicyDecision> {
        // 1. 加载 CardRuleSetRef（OVERLAY + BASE）
        // 2. OVERLAY DENY → 直接返回 DENY（fail-closed）
        // 3. OVERLAY ALLOW → 直接返回 ALLOW
        // 4. BASE DENY → 直接返回 DENY（不得被 L2 permission_rule 覆盖）
        // 5. BASE ALLOW → 直接返回 ALLOW
        // 6. 仅当 L1 规则集完全无匹配时，才回退 L2 permission_rule
        // 7. 优先级：OVERLAY DENY > OVERLAY ALLOW > BASE DENY > BASE ALLOW
        todo!()
    }

    /// PermissionRule 回退
    async fn evaluate_permission_rules(
        &self,
        ctx: &PolicyContext,
        steps: &mut Vec<EvaluationStep>,
    ) -> Option<PolicyDecision> {
        todo!()
    }

    /// 模拟评估（What-If 场景，不影响计数器）
    pub async fn simulate(&self, ctx: &PolicyContext) -> PolicyDecision {
        todo!()
    }

    /// 降级路径（断路器打开时调用，fail-closed）
    pub fn evaluate_fallback(&self, ctx: &PolicyContext) -> PolicyDecision {
        PolicyDecision {
            allowed: false,
            reason: "CIRCUIT_BREAKER_OPEN".into(),
            matched_rule: None,
            audit_required: true,
            evaluation_path: vec![],
        }
    }
}
```

L2 投影 permission snapshot（`permission_rule_snapshot`）边界：
- 仅用于未绑定 `card_rule_set_ref` 的历史卡片、`CARD_ONLY` 卡级特例规则和迁移过渡期兼容数据；正式读取通过 `load_permission_rules`，不得改读 raw source。
- 禁止 Rust 新增 TEMPLATE 类型 `permission_rule` 写入路径；模板级权限必须通过 `rule_set` / `rule_set_entry` / `rule_set_snapshot`。
- 一旦 L1 命中 DENY 或 ALLOW，L2 不得再次覆盖该决策。

### 5.4 ConditionEvaluator（Rust 特质系统）

```rust
// === condition.rs：条件评估器 ===

/// 条件评估器特质（Rust trait 替代 Java 接口）
#[async_trait]
pub trait ConditionEvaluator: Send + Sync {
    fn condition_type(&self) -> &'static str;
    async fn evaluate(&self, condition: &Condition, ctx: &PolicyContext) -> Result<bool, ConditionError>;
}

/// 内置条件实现
pub struct TimeRangeCondition;
pub struct IpRangeCondition;
pub struct RateLimitCondition;
pub struct DeviceTypeCondition;
pub struct ResourcePropertyCondition;
pub struct OwnerOnlyCondition;
pub struct BelongsToTenantCondition;
pub struct ScopeCondition;

/// 布尔逻辑组合（allOf / anyOf / not）
pub enum ConditionGroup {
    AllOf(Vec<Condition>),
    AnyOf(Vec<Condition>),
    Not(Box<Condition>),
}

/// 条件定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub condition_type: String,
    pub params: serde_json::Value,  // 例如 { "start": "08:00", "end": "18:00" }
}
```

### 5.5 与 Java 版的语义等价性验证

Phase 1 完成后，以下测试必须全部通过。测试数据采用 Java oracle 导出机制：Java 版对同一组 `PolicyContext`、数据库快照、规则集快照输出 `PolicyDecision`，Rust 版读取 JSON oracle 并逐字段断言 `allowed`、`reason`、`matchedRule`、`auditRequired`、`evaluationPath` 一致。

建议 oracle 目录结构：

```text
crates/policy-engine/tests/oracle/
├── overlay_deny_base_allow.json
├── expired_card_default_deny.json
├── wildcard_rule_match.json
├── condition_time_range.json
├── permission_rule_fallback.json
└── circuit_breaker_fail_closed.json
```

安全相关字段必须 100% 一致；耗时、traceId、日志顺序等非安全字段不参与一致性断言。

Phase 1 完成后，以下测试必须全部通过：

| 测试 | Java 版 | Rust 版 | 验证方法 |
|------|---------|---------|---------|
| 空上下文拒绝 | ✅ | ✅ | 同一输入比对输出 |
| 失效卡片拒绝 | ✅ | ✅ | 同一输入比对输出 |
| OVERLAY DENY 覆盖 BASE ALLOW | ✅ | ✅ | 同一输入比对输出 |
| 断路器降级 | ✅ | ✅ | 模拟断路器状态比对 |
| 50 条规则交替 DENY/ALLOW (500轮) | ✅ | ✅ | DecisionDerivationTable oracle 验证 |
| 1000 增量更新 + oracle | ✅ | ✅ | 同上 |
| 4写8读并发 2400 操作 | ✅ | ✅ | 快照一致性检查 |
| 乐观锁冲突重试 | ✅ | ✅ | 模拟冲突场景 |
| SQL 注入 | ✅ | ✅ | 同攻击向量 |

---

## 6. 双引擎运行策略

### 6.1 阶段示意

```
Phase 1-2:    Java（生产主力） + Rust（单测验证）
Phase 3:      Java（生产） + Rust Gateway（初步上线，流量转发到 Java 后端）
Phase 4 初期: Java（生产）+ Rust（A/B 影子模式，双引擎同时评估，结果比对）
Phase 4 后期: Rust（生产主力）+ Java（回退备用）
退役:          Java 下线，Rust 全量承接
```

### 6.2 影子模式 A/B 验证（Phase 4 初期）

```
客户端 → Rust Gateway（主）
          ├─ 转发 → Rust 后端服务
          └─ 影子复制 → Java 后端（异步，不返回给客户端）

Rust 和 Java 的评估结果记录到比对表：
  ┌─────────────────────────────────────────────┐
  │ 比对字段         │ Rust │ Java │ 一致？      │
  ├─────────────────────────────────────────────┤
  │ evaluate() 结果   │ DENY │ DENY │ ✅         │
  │ 匹配规则 ID      │ 42   │ 42   │ ✅         │
  │ 评估路径         │ L1→L3│ L1→L3│ ✅         │
  │ 耗时             │ 1.2μs│ 23μs │ ⚠️ 预期差 │
  └─────────────────────────────────────────────┘
安全决策字段（ALLOW/DENY、reason、matchedRule、evaluationPath）差异率必须为 0；仅耗时、traceId、日志顺序等非安全字段允许存在预期差异。连续观察期内安全差异为 0，且回滚演练通过后，才允许切换生产主路径。
```

---

## 7. 首阶段执行计划（Phase 1）

### 7.1 可交付物

```
crates/policy-engine/src/
├── lib.rs              # 模块导出
├── engine.rs           # PolicyEngine struct + evaluate()
├── condition.rs        # ConditionEvaluator trait + 条件实现
├── decision.rs         # Decision / Effect / EvaluationStep
├── context.rs          # PolicyContext
├── registry.rs         # ResourceRegistry（全部 26+ 类型）
├── circuit_breaker.rs  # 断路器实现
└── hit_stats.rs        # 命中计数器 + 时延统计
```

### 7.2 验证标准

1. `cargo test` 全部通过
2. `cargo clippy --workspace -- -D warnings` 全部通过
3. 与 Java 版对同一组测试数据输出完全一致
4. `cargo bench` 建立性能基线（作为 Phase 4 性能对比的依据，不作为普通 PR CI 必跑项）

### 7.3 模块退役准入标准

每个 Java 模块退役前必须满足：
1. Rust 模块接口契约、鉴权行为、审计字段覆盖 Java 当前能力。
2. 影子模式连续观察期内安全决策差异为 0。
3. 数据库写路径已单一化，不存在 Java/Rust 对同一业务表的无协调双写。
4. 回滚开关和回滚演练通过，回退到 Java 主路径不需要生产 DDL。
5. 指标、日志、链路追踪、告警接入完成。
6. 相关 API 文档、运维手册、验收记录同步更新。

### 7.4 前置依赖

| 依赖 | 状态 | 备注 |
|------|------|------|
| Rust 工具链安装 | ✅ | 需要 `rustup` + `stable` |
| MySQL 测试库 | ✅ | 复用现有测试配置 |
| Redis 测试实例 | ✅ | 复用现有测试配置 |
| Java 版测试数据导出 | ◻ | 需要导出 DecisionDerivationTable 的 oracle 数据 |
| sqlx-cli 安装 | ◻ | `cargo install sqlx-cli` |

---

## 8. 未决问题清单

| # | 问题 | 建议 | 等待决策 |
|---|------|------|---------|
| 1 | ORM：sqlx vs SeaORM vs Diesel | **sqlx** | 🔴 **需确认** |
| 2 | Gateway 迁移时机 | Phase 3（PolicyEngine 跑通后） | 🟢 建议通过 |
| 3 | 双引擎策略 | 影子模式比对 | 🟢 建议通过 |
| 4 | etcd/Consul | 跳过初期，env 即可 | 🟢 建议通过 |
| 5 | NATS/Pulsar 替换 RocketMQ | 推迟至 Phase 4 | 🟢 建议通过 |
| 6 | 配置管理 | config-rs + env + YAML fallback | 🟢 建议通过 |
| 7 | 网关路由配置 | env 驱动，同 Java 模式 | 🟢 建议通过 |
| 8 | 前端 Vue 3 是否同步调整 | 保持不动 | 🟢 已确认 |
| 9 | 测试数据迁移 | Java → Rust oracle JSON 导出 + Rust 回放断言 | 🟡 需工具支持 |
| 10 | CI/CD 迁移 | 普通 CI 跑 check/clippy/test，benchmark 独立工作流 | 🟡 后期规划 |
| 11 | 断路器实现 | 自研 Tower Layer vs failsafe 需 spike 验证 | 🟡 待验证 |

---

## 附录 A：GitHub Action CI 配置（未来）

```yaml
name: Rust CI
on: [push, pull_request]
jobs:
  check:
    runs-on: ubuntu-latest
    services:
      mysql:
        image: mysql:8.0
        env:
          MYSQL_ROOT_PASSWORD: test
          MYSQL_DATABASE: astral_test
        ports: [3306/tcp]
      redis:
        image: redis:7
        ports: [6379/tcp]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo check --workspace
      - run: cargo clippy --workspace -- -D warnings
      - run: cargo test --workspace
```

`cargo bench --workspace` 不进入普通 PR CI，另建手动或定时 Benchmark 工作流，避免性能波动导致 PR 检查不稳定。

## 附录 B：代码行数估算依据

```
估算逻辑：
- Java：  Lombok（getter/setter/Builder）= 每实体 ~30 行模板代码 → Rust 自动由编译器生成
- Java：  Spring 注解（@Component/@Service/@Autowired）= 每类 ~5 行胶水 → Rust 无运行时注入
- Java：  AOP 配置 + 反射 = ~10% 框架代码 → Rust Tower 中间件 1:1 替换
- Rust：  类型系统（enum + match）= 比 Java 的 if/switch 多 20% 但更精确
- Rust：  错误处理（Result/Option）= 比 Java 的 try/catch 多 15% 但更安全

综合系数：Rust ≈ Java × 0.68（保守估计）
```
