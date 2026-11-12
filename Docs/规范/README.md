# Rust 规范

本目录是独立 Rust 仓库的工程规范入口。

- [Rust 后端编码规范](Rust后端编码规范_V1.0.md)：§15.10 定义 memory-v1 新数据库、单机唯一关系对象根、请求级共享读者、冷启动预建关系、服务期缺失请求受控查库并原子补根、原子生效、跨崩溃丢失边界和采用门禁；§14.9 定义新增或改造方法的 `memory—v1`（U+2014）标记。该 profile 不要求旧 V6/V7 发布链；本分支旧授权读面及旧正式评估执行链已退役，正式入口在新版共享根采用前一律 PENDING；其他源码残留与新版采用状态以 §15.10 的 BREAKING CHANGE 及任务证据为准，登记不代表实现、真实依赖或生产验收。workspace、分层、安全和测试等通用约束继续适用。§7.2 登记旧路径的四个 required `RuleRepository` port；§10.0 规定全部测试与测试判定仅使用 Rust/Cargo；§§15.3–15.9 登记旧路径的 runtime、source、projection、edition、迁移、adoption 和恢复合同。实现、真实依赖、迁移及部署状态以任务证据为准。
- [统一消息协议与智能层消息规范](统一消息协议与智能层消息规范_2026-03-18.md)：响应、消息、ACK、trace 和 audit 字段；§8.5 约束 Rust CURRENT V6 MQ business-message flat root JSON，与通用 durable transport envelope/schemaVersion 分离；§8.6 为旧授权发布失效消息，memory-v1 单机消息按其适用合同另行设计。
- [统一接口路径规范](统一接口路径规范_V5.md)：Rust 服务使用的冻结主路径与资源命名约束。

执行门禁和 Agent 规则见仓库根目录 [`AGENTS.md`](../../AGENTS.md)。本仓库不复制 Java、前端或源单仓库专属规范；遇到规范与源码冲突时，以源码、迁移和测试证据为准，并先登记差异再修改。
