# tests-suite — 分类测试套件总入口

> 本目录是全仓测试的**汇集点**:新增套件物理存放于此,既有测试通过
> `MANIFEST.toml` 全量编目分类。本目录不替代 Cargo 的测试发现机制——
> `cargo test --workspace` 行为不变。

## 分类体系

| category | 含义 | 运行方式 |
|---|---|---|
| `unit-inline` | 内联单元测试(`#[cfg(test)]`,物理上属于属主 crate) | `cargo test --workspace --lib` |
| `integration` | Redis-free MySQL 集成(`#[ignore]` 门控);Rabbit/Redis 为显式专项 | `bash scripts/run-tests.sh --integration` |
| `multi-tenant` | 租户隔离/租户拓扑测试 | 同上 + `testsuite` 套件 |
| `multi-tenant-extreme` | **新增**:多租户混合极限(大规模交错/搅动/风暴/容量/失败注入) | `scripts/run-tests.sh --mt-extreme` |
| `security` | 安全前提测试(E2 omission 风格 + 新架构前提) | 见 MANIFEST 每条 `run` |
| `performance` | CPU-only 回归矩阵 + cargo bench + 引擎对比 | `cargo bench -p policy-engine` 等 |
| `compat-guard` | 兼容语义守卫(Java 基线语义对齐、legacy 拒绝断言) | 随所属 crate 测试运行 |
| `e2e` | 端到端(单机 composite 部署 + loadgen、SDK adapters) | `tests-suite/e2e/` 配方 |
| `archive` | 不适用当前架构/退役面(每条带书面理由) | 不运行 |

## 运行前置(集成/多租户/安全真依赖类)

- MySQL 8.0(`DATABASE_URL`,127.0.0.1:3308,isolated 环境)
- `ASTRAL_MIGRATION_ENV=isolated` + `RUST_INTEGRATION_REQUIRED=1`
- 默认只需要 MySQL;LocalBus/LocalProjectionBus 的进程内测试不需要消息中间件。
- `unit`/`--check` 不启动容器;`--integration`/`--mt-extreme` 默认启动 MySQL 并显式迁移。
- `TEST_USE_EXISTING=1` 复用已迁移的隔离库,不启动/删除容器、不执行 DDL,各测试仍严格验证 schema。
- 破坏性待命迁移保持批准与证明门禁,脚本不自动填入 allowlist 或证明引用。
- `--rabbit` 单独验证 MySQL 租约 + RabbitMQ 审计重放;不需要 Redis。
- `--redis-compat` 是兼容窗专项,不是新架构 gate;脚本仅在此模式启用 Redis adapter。
- 专属 SDK 映射库通过 `--identity-mapping` 单独验证;不放宽专属库名守卫,不自动建库/迁移。
- 每阶段完整日志/退出码/耗时在 repo 外的 run-scoped 目录(或 `TEST_ARTIFACT_DIR`);内部 `[SKIP]` 不计 PASS,超时标 UNKNOWN 并停止后续派发。

### 安全前提与入口回归

`Cargo.toml` 显式注册 `tests/security/` 下四个目标。hub 失效测试从真实已提交
publication 构造镜像,身份映射与单写者租约测试使用真实 MySQL;Redis-free
composite 配置门不依赖外部服务,随 `unit` 执行。集成只跑 ignored 真依赖目标,
不把被过滤的纯配置门当作集成通过。

```bash
bash scripts/tests/test-run-tests.sh
bash scripts/run-tests.sh unit
bash scripts/run-tests.sh --integration
bash scripts/run-tests.sh --rabbit
bash tests-suite/matrix/run-mt-matrix.sh --suites "mt_extreme_churn mt_extreme_capacity"
```

矩阵默认只运行 Redis-free profile;显式 `--profile redis-compat` 才启用兼容
特性与旗标,并要求调用方预先准备 Redis。`--suites` 实际选择目标且拒绝未知项。
忽略的 CPU-only 性能矩阵、专属映射库、Rabbit 专项、Redis 兼容和 excluded crates
不属于默认 MySQL gate,须单列证据。架构依据见
[内存权威读面与失效通道方案](../Docs/架构/Rust架构设计/Rust内存权威读面与失效通道架构方案_V0.1.md)。

## ID 段隔离

| 段 | 起点 | 归属 |
|---|---|---|
| 1e12 起 | astral-db/tests/multi_tenant_isolation.rs | 既有 mt 测试 |
| 9e12 附近 | Docs/实验/分布式测试/rust-s15 | 分布式 e2e |
| **2e16 起** | testsuite/src/lib.rs(`SUITE_BASE_MIN`) | testsuite 新套件 |

## 完整性约束(本目录的立目录原则)

1. 既有测试不删除、不弱化、不改阈值;只做加法与编目。
2. 归档条目必须带书面理由(`archive/` 内 README)。
3. 新套件深度只增不减:既有覆盖的断言语义在新套件中保持,并扩展到
   多租户/多配置维度。
4. 安全证明(E2 omission / M1-M5 映射)随架构演进而更新,前提命名由
   `Docs/authorization-validation/tools/experiment_register.py` 锁定。
