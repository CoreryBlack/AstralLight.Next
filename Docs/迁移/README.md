# Rust 迁移与运维

本目录仅保留 Rust 后端迁移、schema、ORG_SCOPE 和验证边界相关资料。

- [SDK 身份映射迁移与恢复](SDK身份映射迁移与恢复_V1.0.md)
- [Rust 后端迁移架构决策](Rust后端迁移架构决策_V1.0.md)：包含唯一 `WorkerOwned` additive schema、lane/receipt 证明与 stop/reconcile 回退合同，以及 §2.5 的历史 v3 immutable migration artifact、§2.6 的 **CURRENT V6** 完整规则集视图与 breaking-change adoption notice。升级前须 offline inventory/preflight、调用方/数据形状核对、必要的派生状态 rebuild 和 postcondition 验证；回退为停止新执行者、reconcile UNKNOWN，再恢复基线 `62b4349`。文档不声称环境迁移、数据库表删除或 rollback 已执行；历史 SQL/checksum、migration ID 与报告不改写。V6 software contract includes WorkerOwned receipt observation, canonical RuleSet/condition fields, strict JWT `roles` array, tenant-query Result APIs, exact-snapshot password mutation, actor-scoped template update and the removal of fabricated domain/tenant DTO fields; details live in normative Rust standard §15.8. Test counts and command results belong in the task evidence, not this normative navigation entry; real MySQL/RabbitMQ, migration and deployment require their own executed postconditions.
- [ORG_SCOPE 迁移与回滚操作手册](ORG_SCOPE迁移与回滚操作手册_V0.1.md)
- [Rust/Java 等价适配状态](Rust迁移Java等价适配状态_2026-08-05.md)

迁移不是普通重试任务。执行真实迁移前必须遵循根目录 `AGENTS.md` 的 preflight、备份/恢复或 forward-fix、postcondition、审计和人工终审要求。文档本身不构成迁移执行证据。
