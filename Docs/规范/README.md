# Rust 规范

本目录是独立 Rust 仓库的工程规范入口。

- [Rust 后端编码规范](Rust后端编码规范_V1.0.md)：workspace、crate 边界、分层、错误、异步、测试和 CURRENT V6 strict authorization 约束；§7.2 定义四个 required `RuleRepository` port，§10.0 规定全部测试与测试判定仅使用 Rust/Cargo，禁止其他语言实现测试逻辑；§15.3 登记 Redis/`astral-cache` runtime compatibility 与旧 Python campaign/adapter 工具完全退役、Rust-only 验收及不等价替代边界，§15.4 登记单机读写栅栏、owner 生命周期、ELIGIBILITY head/token fencing、直接 MANUAL create/update 的事务内 SoD（含锁定 tenant/before-image、唯一 self-grant 排除与有界读取）及 compensation 语义，§15.5 定义唯一 `WorkerOwned` 执行协议、5s/25ms/64-event/50-card 有界 observation-only receipt 等待、exact completion proof、lane/active-slot/epoch/token/predecessor 不变式和 stop/reconcile 回退；§15.6 保留历史 v3 schema artifact，§15.7 定义 CURRENT V6 bundle 与 canonical RuleSet/condition DTO，§15.8 登记 API/Rust compatibility breaking-change 清单（含 JWT roles、tenant query、同步 data-scope 兼容 API、MQ 旧 polling/generic starter、password snapshot API、actor-scoped template update、fabricated DTO field removal）及采用/离线迁移/rebuild/preflight/rollback 合同。V6 是授权 edition，不重编号 generic MQ `schemaVersion`、JWT 版本或 HTTP v1。
- [统一消息协议与智能层消息规范](统一消息协议与智能层消息规范_2026-03-18.md)：响应、消息、ACK、trace 和 audit 字段；§8.5 约束 Rust CURRENT V6 MQ business-message flat root JSON，与通用 durable transport envelope/schemaVersion 分离。
- [统一接口路径规范](统一接口路径规范_V5.md)：Rust 服务使用的冻结主路径与资源命名约束。

执行门禁和 Agent 规则见仓库根目录 [`AGENTS.md`](../../AGENTS.md)。本仓库不复制 Java、前端或源单仓库专属规范；遇到规范与源码冲突时，以源码、迁移和测试证据为准，并先登记差异再修改。
