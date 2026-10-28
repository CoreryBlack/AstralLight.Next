# Rust 迁移与运维

本目录仅保留 Rust 后端迁移、schema、ORG_SCOPE 和验证边界相关资料。

- [SDK 身份映射迁移与恢复](SDK身份映射迁移与恢复_V1.0.md)
- [Rust 后端迁移架构决策](Rust后端迁移架构决策_V1.0.md)：包含 worker-owned additive schema、历史预算保守继承与停机切换/回退合同，以及 §2.5 所记录的历史 v3 封存 migration artifact、旧开发证据拒绝与重建边界，§2.6 的 **CURRENT V6** 完整规则集视图、轻量发布证据和消息/快照切换对账。V6 是一次性升级/回退的授权 bundle；不改写历史 SQL/checksum、migration ID 或文档文件名。
- [ORG_SCOPE 迁移与回滚操作手册](ORG_SCOPE迁移与回滚操作手册_V0.1.md)
- [Rust/Java 等价适配状态](Rust迁移Java等价适配状态_2026-08-05.md)

迁移不是普通重试任务。执行真实迁移前必须遵循根目录 `AGENTS.md` 的 preflight、备份/恢复或 forward-fix、postcondition、审计和人工终审要求。文档本身不构成迁移执行证据。
