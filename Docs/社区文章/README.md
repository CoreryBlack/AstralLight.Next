# Rust 社区技术文章草稿

面向稀土掘金等 Rust 技术社区和 Reddit 技术社区，聚焦项目中的异步 worker、持久化集合、并发缓存、请求签名与授权投影实现。中文稿和英文稿均为可独立阅读的实现文章，包含源码对应的 Rust 示例、设计取舍和明确的验证边界。英文稿按 Reddit 自帖的阅读节奏撰写，尚未发布到 Reddit。

## 中文版

1. [Rust 授权投影：用 generation 与 CAS 让撤权不被旧读覆盖](01-authorization-revocation-and-strict-read.md)
2. [Rust 授权增量编译：用 `im::HashMap` 与 `Arc` 只重建受影响 segment](02-incremental-authorization-compiler.md)
3. [Rust 授权证据缓存的 freshness fence：`ReadToken` 加返回前复核](03-freshness-fenced-evidence-cache.md)
4. [Rust Tokio durable worker 的重试边界：lease、timeout 与 UNKNOWN](04-tokio-projection-worker.md)
5. [Rust SDK 如何把 ALLOW 变成请求绑定的 proof](05-sdk-authorization-proof.md)

## English editions for Reddit

1. [Preventing stale ALLOWs in a Rust authorization projector](01-authorization-revocation-and-strict-read-en.md)
2. [Incremental authorization compilation in Rust with `im::HashMap` and `Arc`](02-incremental-authorization-compiler-en.md)
3. [A freshness fence for Rust authorization caches: `ReadToken` plus a final check](03-freshness-fenced-evidence-cache-en.md)
4. [When a Rust Tokio worker times out, should it retry?](04-tokio-projection-worker-en.md)
5. [A Rust authorization proof should be a value, not a reusable boolean](05-sdk-authorization-proof-en.md)

Reddit copies are written as standalone technical posts with an implementation-focused opening, code excerpts, limitations, and a discussion question. They are drafts for the user to publish; no external post has been submitted.

## 发布注意

- 文章描述当前实现，不代表生产迁移或正式切流已完成。
- 第 1 篇的 canonical projection 与 production strict gate 已有代码接线；既有数据 backfill/rehearsal、缓存与摘要读侧迁移、真实 MySQL 集成验收和正式切流仍须单独证明。
- 第 2 篇的 fixture 数量是结构正确性证据，不是通用吞吐或内存性能承诺；allocator 数值只是观察项。
- 第 3 篇介绍的是当前 `Mutex` 缓存、1 秒 TTL、条目数/字节上限和读取 token 二次检查，不应称为无锁缓存或跨进程一致性协议。
- 第 4 篇的 timeout/cancellation 不能证明数据库提交失败；UNKNOWN 路径不盲目重试，而是由 durable lease 状态和对账收敛。
- 第 5 篇的 Learn/Chat 集成使用有界内存示例；它们不证明生产 SQL 事务、跨进程 exactly-once、真实平台身份映射或生产部署。消费方必须持久化 operation ID、payload digest 和 receipt，并在本地提交前复检事实与版本。
