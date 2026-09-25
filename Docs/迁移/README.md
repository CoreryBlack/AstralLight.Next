# Rust 迁移与运维

本目录仅保留 Rust 后端迁移、schema、ORG_SCOPE 和验证边界相关资料。

- [Rust 后端迁移架构决策](Rust后端迁移架构决策_V1.0.md)
- [ORG_SCOPE 迁移与回滚操作手册](ORG_SCOPE迁移与回滚操作手册_V0.1.md)
- [Rust/Java 等价适配状态](Rust迁移Java等价适配状态_2026-08-05.md)

迁移不是普通重试任务。执行真实迁移前必须遵循根目录 `AGENTS.md` 的 preflight、备份/恢复或 forward-fix、postcondition、审计和人工终审要求。文档本身不构成迁移执行证据。
