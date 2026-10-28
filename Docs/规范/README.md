# Rust 规范

本目录是独立 Rust 仓库的工程规范入口。

- [Rust 后端编码规范](Rust后端编码规范_V1.0.md)：workspace、crate 边界、分层、错误、异步、测试和授权投影约束；§10.0 规定全部测试与测试判定仅使用 Rust/Cargo，禁止其他语言实现测试逻辑；§15.3 登记 Redis 默认编译退役与 `redis-compat` 兼容窗，§15.4 登记单机读写栅栏、owner 生命周期和 R1–R4 语义边界，§15.5 登记 default-off 的 worker-owned 发布协议、聚合前驱顺序、lane 串行化下的发布/完成读取锁序、完成 commitment/归档边界、证据保留与切换边界，§15.6/§15.7 登记授权代际 **CURRENT V6** 的统一封存、摘要、编译、消息、缓存、快照与 schema 读门合同；2026-10-27 的 v3 是历史请求与不可变 migration artifact，不是当前 edition。当前数字与字符串只由 `astral-types/src/edition.rs` 的 `AUTHORIZATION_EDITION=6` 单一宏定义派生，并由 Rust 跨 crate contract test 校验；canonical permission envelope、L2 evidence、共享内容单元、所有 invalidation family 和 default-off ORG_SCOPE publication proofs 均属于 V6 bundle，组织编译器/依赖/segment/manifest domains 由同一宏派生但保留组织自己的 payload contract；L2 MAC 为 `astral:l2-evidence:v6:hmac-sha256`。
- [统一消息协议与智能层消息规范](统一消息协议与智能层消息规范_2026-03-18.md)：响应、消息、ACK、trace 和 audit 字段。
- [统一接口路径规范](统一接口路径规范_V5.md)：Rust 服务使用的冻结主路径与资源命名约束。

执行门禁和 Agent 规则见仓库根目录 [`AGENTS.md`](../../AGENTS.md)。本仓库不复制 Java、前端或源单仓库专属规范；遇到规范与源码冲突时，以源码、迁移和测试证据为准，并先登记差异再修改。
