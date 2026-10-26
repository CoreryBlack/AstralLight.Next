# Gateway A–F 解耦路线的当前源码复核

> 核对日期：2026-10-25
> 主解析：[Rust Gateway 当前链路与 A–F 解耦路线](Rust-Gateway当前实际链路与解耦对照设计_V1.0.md)
> 状态：本专题只把当前 checkout 中可定位的源码/测试与原计划逐项对照。它不是运行态验收、线上拓扑证明、阶段批准或 Gateway 重构方案；A–F 的阶段名沿用 2026-08-11 历史文档。

## 1. 判断口径

原解耦文档记录的是 2026-08-11 链路快照和目标路线，后续有局部代码迁移，故不能把原文“当前态”直接套用到 2026-10-25。以下只问：“当前源码具备哪些阶段相关结构/断言？”不以模块存在、局部测试或工作区文件推断整个阶段 PASS。

阶段含义：A 冻结完整 wire/route 行为 golden；B 把多个 producer/consumer 共用的纯 wire contract 拆成单一声明；C 将 session validity owner 收敛并完成有序双读；D 抽取声明式路由 registry 和 transport 组件；E 收敛 Gateway 与下游的配置 owner；F 满足 Chat/Learn 解冻前置与集成门禁。

## 2. A–F 静态证据矩阵

| 阶段 | 技术问题与计划机制 | 当前 checkout 证据 | 当前状态与不能推断的内容 |
|---|---|---|---|
| A：契约冻结与 golden tests | 固定 route/method 到 credential policy、JWT claims、身份头、HMAC、Redis/session 分支、错误 envelope 和路径重写；对 producer/consumer 以 golden 契约阻止无意漂移。 | `astral-common/src/middleware/gateway_signature.rs::v3_golden_vector_is_stable` 固定本地 v3 canonical vector；`tests-suite/series/E1/gateway_contract_tests.rs::legacy_v2_signature_is_rejected_by_v3_only_middleware` 覆盖拒绝 v2。相邻测试也覆盖身份形态和签名篡改。 | **局部存在，不是完整阶段 A。** 尚需以当前源码逐项确认完整 route rewrite、credential policy、session outcome、error envelope、header snapshot 与跨 producer/consumer 对照。静态找到两个签名测试不证明矩阵已全部冻结，未运行测试不作 PASS。 |
| B：纯 wire contract crate | 将稳定 wire 类型/常量与运行时 middleware、PolicyEngine/DB 依赖分开，使 producer 与 consumer 引用同一 contract owner。 | HMAC v3 计算/验签仍在 `astral-common/src/middleware/gateway_signature.rs`；Gateway 与 Identity 各自定义 `SessionGrant`（`astral-gateway/src/middleware.rs`、`astral-identity/src/auth.rs`）。`astral-sdk-contracts` 是 SDK 外部授权请求/签名的独立合约 crate，README 描述的是另一套协议。 | **原计划未闭合。** SDK contracts 的存在不能替代 Gateway 的 token/header/session/internal wire crate，也不能证明 `SessionGrant` 单一声明。具体拆分方式和兼容再导出仍属于原阶段设计。 |
| C：Session validity owner | 先抽 `SessionValidationPort`，再以双读对账，最后移除 Gateway 自行解析的复制逻辑；所有故障需 fail-closed。 | 当前 Gateway middleware 已优先调用 `astral_db::verify_access_via_global_store`；`astral-common/src/session_projection_store.rs` 定义 MySQL strict durable facts 与可选有界镜像，Redis 是显式 default-off 兼容路径；`astral-gateway/src/runtime.rs` 启动时调用 `install_gateway_session_auth`。单写者组合进程与独立 Gateway 的镜像政策不同。 | **运行机制已有明显演进，但不能称阶段 C 全完成。** 默认 strict MySQL 路径与原文“Gateway 直接读 Redis”的历史描述不一致；原阶段要求的正式 Port/adapter、双读观测证据和单一 owner 决策不因新路径存在而自动满足。identity/tenant status 分支也需按当前调用链分别核对。 |
| D：路由 / WS / breaker 分层 | 由集中硬编码改为可审计的 declarative route registry；WS 与 circuit breaker 拥有明确 transport 边界，保留公开路由/签名语义。 | `astral-gateway/src/runtime.rs` 中已按 Identity users/me/sessions、Chat HTTP/WS 等抽出 route-construction helpers；大部分路径仍以 Axum `.route()` 在源码中声明。`astral-gateway/src/proxy.rs` 仍持有 `forward_chat_ws`、`bridge_websocket` 和静态 `CB_*` 断路器。 | **模块内局部拆分，不等于目标 registry/transport。** helper 函数不证明生成式注册表/数据驱动路由已实现；WS、breaker 仍由 proxy 承担，运行行为需单独测试。 |
| E：服务配置 owner | Gateway 只持有 Gateway/JWT/Redis/CORS/rate-limit 所需字段；下游不持 Gateway-only secret/配置。 | `astral-common/src/config/mod.rs` 仍定义共享 `AppConfig` 与 `GatewayCfg`；Gateway runtime 从共享 `AppConfig` 加载。具体 Gateway secret 与其他 service 配置的归属需按结构字段、使用方及启动配置逐项审视。 | **未证明完成。** 模块中存在 GatewayCfg 是共享配置事实，尚不能从该结构本身推断密钥实际泄露；也没有 service-specific config owner 已完全拆分的证据。配置校验与部署配置迁移未运行。 |
| F：Learn / Chat 解冻门 | 证明冻结 crate 的完整编译、统一启动配置、内部 wire/golden 测试、WS/鉴权行为和路由合同后，才移出 workspace exclude。 | 根 `Cargo.toml` 仍 `exclude = ["astral-learn", "astral-chat", ...]`；Gateway 有 `/api/v1/auth/internal/sessions` 等路由与两跳 `astral-internal-v1` 请求链；`tests-suite/series/E1/gateway_contract_tests.rs` 有局部 Gateway HTTP 契约测试。 | **局部链路在源码中，解冻门未闭合。** Learn/Chat 仍在默认 workspace 外；internal assertion 与 HMAC v3 是不同协议。单个 Gateway contract test 不代表被冻结服务编译、完整 WS/内部 wire contract、external dependency 或解冻验收通过。 |

## 3. 机制取舍及跨阶段依赖

A 应先于对外协议边界重构：没有 pinned 的 header、签名、路由和错误合同，移动 Gateway 逻辑会把行为差异埋进结构改造。B 解决协议型数据的单一声明/依赖方向，不应把 JWT 认证、会话 source 查询或授权决策一并塞进“纯 contract”。C 是数据 owner 变更：双读期间旧路径仍是权威结果，影子差异须逐项对账；未知或不可用不得 fail-open。D 是组件所有权与可替换性重构，必须以 A 的兼容矩阵作为行为基线。E 独立于 wire 类型拆分，重点是 secret/read ownership、配置 validation 与部署迁移。F 是整体集成门，不是排期标签；其包含依赖 A/B/D/E 的前置，不应以“源码已存在”跳过真实构建与依赖验收。

本组阶段互相依赖，但不能机械视作六个全部未动或全部完成的批次。当前能确认部分 A 测试、Gateway 专属中间件归属移动以及 C 相关默认 MySQL strict session 路径等局部事实；这些代码变化不自动证明历史阶段中的完整验收合同已通过。Gateway HMAC v3、`astral-internal-v1` 与 SDK `SignedAuthorizationRequest` 是不同 wire contract；不得把它们合成一个签名协议或将一个协议的测试覆盖移植为另一个协议已验收。

## 4. 风险、故障与恢复边界

- 凭证头伪造、signature canonicalization 或 route policy 偏差会跨越外部请求信任边界；任何契约变更需 producer/consumer 同步，不允许仅因 refactor 改 wire 值。
- session mirror miss/过期不证明 ACTIVE；strict store unavailable 需拒绝/503。Redis compatibility 必须保持显式 opt-in；不能把其可运行等同 canonical owner 已迁移。
- route registry 生成错误可能扩大上游可达路径。未知路由和未实现桩需继续保持显式拒绝/404/501，不得 wildcard 放宽。
- WS disconnect 与 proxy timeout 可能留下部分执行或 UNKNOWN；验证需区分握手、转发、双向关闭、PING/PONG 和上游不可用，不用普通 HTTP 测试替代。
- 配置拆分失败必须在启动期报错或保持安全默认，不可静默加载弱密钥、跨服务 secret 或不同 session-validation policy。
- F 阶段还涉及 `astral-learn`/`astral-chat` 编译边界、内部签名调用者和真实服务配置。执行前置条件未满足时不移除 `exclude`。

## 5. 复核结论

当前材料支持“Gateway 有局部契约测试、源码结构已分出部分路由 helper、会话读路径已有 MySQL strict store 接线”的窄结论；不支持“阶段 A–F 已全部完成”，也不支持“原 2026-08-11 当前态仍是 2026-10-25 当前行为”。阶段状态用于指引下一次逐项工程核验；当前源码静态复核没有运行 Cargo suite、连接 Redis/MySQL、执行迁移、启动服务、测试 Chat/Learn 真实链路或验证线上配置，因此没有任何新的运行/集成 PASS。

## 6. 主要证据入口

- [Gateway 历史快照与 A–F 目标路线](Rust-Gateway当前实际链路与解耦对照设计_V1.0.md) §7、§10。
- [`astral-gateway/src/runtime.rs`](../../../astral-gateway/src/runtime.rs)：路由 helpers、启动与 session-auth wiring。
- [`astral-gateway/src/middleware.rs`](../../../astral-gateway/src/middleware.rs)：`install_gateway_session_auth`、canonical store 与显式 Redis 兼容判定。
- [`astral-common/src/session_projection_store.rs`](../../../astral-common/src/session_projection_store.rs)：strict durable session facts、镜像策略和 fail-closed 读路径。
- [`astral-gateway/src/proxy.rs`](../../../astral-gateway/src/proxy.rs)：HTTP/WS proxy 和静态断路器。
- [`astral-common/src/middleware/gateway_signature.rs`](../../../astral-common/src/middleware/gateway_signature.rs)：Gateway HMAC v3。
- [`tests-suite/series/E1/gateway_contract_tests.rs`](../../../tests-suite/series/E1/gateway_contract_tests.rs)：现有 Gateway contract 断言。
- [`astral-sdk-contracts/README.md`](../../../astral-sdk-contracts/README.md)：SDK 外部授权请求合同；与 Gateway 内部/外部会话 wire 分开。
- [`Cargo.toml`](../../../Cargo.toml)：Learn/Chat 当前 default workspace exclude。
