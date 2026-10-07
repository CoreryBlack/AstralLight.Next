# tests-suite — 分类测试套件总入口

> 本目录是全仓测试的**汇集点**:新增套件物理存放于此,既有测试通过
> `MANIFEST.toml` 全量编目分类。本目录不替代 Cargo 的测试发现机制——
> `cargo test --workspace` 行为不变。

## 分类体系

| category | 含义 | 运行方式 |
|---|---|---|
| `unit-inline` | 内联单元测试(`#[cfg(test)]`,物理上属于属主 crate) | `cargo test --workspace --lib` |
| `integration` | 真实依赖集成测试(MySQL/Redis/RabbitMQ,`#[ignore]` 门控) | `scripts/run-tests.sh --integration` |
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
- Redis/RabbitMQ 仅部分套件需要(见 MANIFEST 每条 `requires`)
- `scripts/run-tests.sh` 负责起停 docker-compose 隔离环境

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
