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

- 所有入口只选择 manifest 中的 suite，不启动容器、服务或迁移；隔离资源准备是独立的批准动作。
- MySQL 8.0、`TEST_USE_EXISTING=1`、`ASTRAL_MIGRATION_ENV=isolated`、`RUST_INTEGRATION_REQUIRED=1` 是真实集成前置。
- 普通集成库只允许 loopback:3308 的 `astral_rehearsal_<run-suffix>`，且必须与 `ASTRAL_TEST_DATABASE_NAME` 完全一致；源库 `astral_test` 和旧共享 rehearsal 库不得作为本轮目标。native 使用进程内 LocalBus/LocalProjectionBus，不需要消息中间件。
- Rabbit 专项只使用 MySQL + RabbitMQ，要求 loopback:5673 和显式 vhost。
- Redis 只属于 `redis-evidence-compat` 专项，要求 loopback:6380；MT 矩阵不再附加无关 Redis 兼容 feature。
- 专属映射 suite 只接受 `INTEGRATION_IDENTITY_MAPPING_DATABASE_URL` 和一致的 `INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE`，库名必须为 `sdk_identity_mapping_test_*`，loopback:3308，预先迁移。
- 所有被选择项先做统一前置检查；任一项 BLOCKED 时不派发任何命令。运行首个非 PASS 后停止，后续项只记录未执行，不计成功。

### 安全前提与入口回归

`Cargo.toml` 显式注册 `tests/security/` 下四个目标。真实 MySQL 测试和 native lifecycle
使用 ignored 命令单列；纯配置、生命周期清理条件与排空等待的单测不需要数据库。

```bash
bash scripts/tests/test-run-tests.sh
bash scripts/run-tests.sh --all
bash scripts/run-tests.sh --integration
bash scripts/run-tests.sh --rabbit
bash tests-suite/matrix/run-mt-matrix.sh --suites "mt_extreme_churn mt_extreme_capacity"
```

shell 和矩阵均只是 `scripts/test_campaign.py` 的选择别名，没有第二份命令清单或
数据库校验实现。旧自动 Docker/DDL 行为已移除；已批准的资源不得由测试入口自动
创建或删除。架构依据见
[内存权威读面与失效通道方案](../Docs/架构/Rust架构设计/Rust内存权威读面与失效通道架构方案_V0.1.md)。

## 统一 Profile 与系列入口

`MANIFEST.toml` 保留全量 `entry` 分类，并新增机器可读的 `profile`、`series`、
`suite` 索引。`scripts/test_campaign.py` 是统一执行入口（Python 3.11+），不使用
shell `eval`，不启动容器/服务，不迁移，不注入 live fault，也不重试 UNKNOWN。
每个 suite 声明属主、精确 argv、生产/测试服务、源码、断言数量和证明边界；
测试服务与生产 profile 不一致时，在派发前拒绝。

| profile | 服务依赖 | 证明范围 |
|---|---|---|
| `native-kernel` | 无 | 生产组件/strict 注入夹具；不证明 durable DB 或 HTTP |
| `offline-validation` | 无 | Python 标准库协议与有界模型 |
| `native-single-node` | MySQL | LocalBus/LocalProjectionBus/MemoryProjectionHub 真实本地链路 |
| `standalone-rabbit` | MySQL + RabbitMQ | 独立服务传输与 durable consumer 证明；无 Redis |
| `distributed` | MySQL + RabbitMQ | 当前多进程目标；历史 Redis/OPA harness 不自动派发 |
| `redis-compat` | MySQL + Redis | 显式 adapter 兼容窗口，登记到期 2026-12-31 |
| `performance-kernel` | 无 | compiler/policy/hub CPU 与分配数据 |
| `performance-native` | MySQL | native composite 签名 HTTP/收敛/负载，需独立部署证据 |

```bash
python -B scripts/test_campaign.py --list --json
bash scripts/run-tests.sh --list-series --series RQ
python -B scripts/test_campaign.py --run --profile native-kernel --series E2
python -B scripts/test_campaign.py --run --profile offline-validation --suite offline-validation-tools
python -B scripts/test_campaign.py --run --profile native-single-node --suite native-projection-lifecycle
python -B scripts/test_campaign.py --run --profile performance-kernel --suite strict-policy-benchmark
```

真实依赖 profile 只复用 `TEST_USE_EXISTING=1` 的已批准、已迁移隔离库，并要求
`ASTRAL_MIGRATION_ENV=isolated`、`RUST_INTEGRATION_REQUIRED=1`。MySQL 必须是
loopback:3308 的 run-scoped `astral_rehearsal_<run-suffix>`，并通过
`ASTRAL_TEST_DATABASE_NAME` 与 URL 中数据库名精确比对；不得指向源库或复用旧共享克隆。
Rabbit 必须显式 vhost，Redis 只出现在 compat；父进程传入但不属于该 profile
的连接变量会被清除。专属映射
suite 使用 `INTEGRATION_IDENTITY_MAPPING_DATABASE_URL` 和
`INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE`，不会拿普通测试库代替。

未指定 profile 的 `--run` 选择可执行的 kernel/offline/CPU 性能集合，不自动扩大到集成。
`bash scripts/run-tests.sh --all` 加上 `--verify-items`：同一冻结源码下逐项验证，全部 PASS
后从第一项重新运行完整集合；两阶段日志分开保存，不复用逐项 PASS。`--full` 选择全
manifest（含真实集成和显式 BLOCKED 项），任何前置缺失都会阻止整个集合派发。
`--list --json` 始终保留全部注册项；默认集合未选的项目进入 `outside_selection`，不是 PASS。
可重复传 `--profile`、`--series`、`--suite`，未知或空选择拒绝。首个 FAIL/SKIP/BLOCKED/
UNKNOWN/PENDING 会停止派发；先修复或对账该项、重测单项，再用新 runId 从头重跑原集合。
runner 不自动修源码、不盲目重试、不缓存历史 PASS。

RQ1-5 登记组件覆盖与完整 campaign 边界，RQ2-D 是结构性 N/A。M1-5 是
source capture、monotone publication、faithful representation、trusted
storage/processes、complete mediation 假设映射，不是五个独立证明，也不是
架构交付 M1-M3。E1-5 保留独立协议、模型与 live campaign；E2 的五个精确
Rust 目标必须各执行一例，host_mediation 仍为 model-only。MT-E1/E3/E4/E5/E6
保持真实 MySQL suite，未实现的 MT-E2 明确 BLOCKED，不补造一个成功编号。

CPU-only 的三组 `PERF_MATRIX` 还须分别输出完整 82/15/40 个唯一 case、
每项至少 15 个有效样本，原始指标进入同一份 result.json；只执行一个 Rust
函数、被 `ASTRAL_PERF_CASE` 过滤或没有测量输出都不能计完整性能 PASS。
这些矩阵验证组件结果等价和采集完整性，比较数据没有额外性能阈值时不宣称
统计上“无回退”。独立现有吞吐下限仍由原测试严格断言，runner 不降低它们。

每次执行在仓库外创建不可覆盖的 run 目录，记录 taskId、源码内容 hash、cwd、
argv、环境名称、墙钟/单调耗时、退出码、完整脱敏 stdout/stderr、断言和 ignored
数量、postcondition 与重试次数（固定零）。源码在冻结后变化，或超时/取消/
日志中断时标 UNKNOWN 并停止后续派发。内部 `[SKIP]`、ignored、零测试不能
折算成 PASS；依赖前置未满足是 BLOCKED，已进入 required 测试后的失败是 FAIL。
`series_results` 只汇总本次选择，并保留 component/offline/integration/live 的
边界，不能当作完整系列 campaign 已通过。E5 的 omission 反例不等于完整合同
失败，但完整合同必须真的完成探索。

失败或未知结果停止集合，修复或对账后必须从头重跑，不能跳过单项。workspace
非 ignored 集合只证明实际执行的单测：ignored 数单列为未执行的独立集成/性能项，
不折算成它们的 PASS。模型同时核验精确身份、bracket/strict、六个 omission，universal
必须含 single/two 与 U1-U10；tenant 模型只含 T1/T3/T4/T5，不冒充 U 系列。
Criterion 要求完整 8/9/30 个精确案例与有效 timing interval，Divan 要求全部 6 项及
真实分配输出。每阶段独立 CRITERION_HOME，不接受测试模式输出为性能证据。
两次变更模型与 universal CLI 显式使用最多 4 个独立配置进程；原 bound、
模式、omission、lattice 和 below-bound 检查不变，结果仍按原配置顺序汇总。
仅在一次调用内按精确配置去重，不读取或复用其他 run 的 PASS；进程或日志
中断仍是 UNKNOWN。运行中顶层 status 保持 PENDING，只有完整终态才写 PASS。

新增 `native_projection_lifecycle` 是一个独立 binary 的单个 ignored 集成测试，加上
独立的无依赖清理条件与排空等待单测：只有消息数和字节占用都归零才结束排空等待；
超时、内部失败或未证明关闭时保留本次 fixture/operation
标识，输出 UNKNOWN，不删除 durable 行、不自动重试。
通过真实 TrustGraph source repository add/revoke，验证 COMMIT 后 dispatch、
durable delta/audit、LocalProjectionBus 单 owner、生产 local worker、published
pointer/fence 与 PolicyEngine strict 读取；source API 也可能在 COMMIT 后同步
完成 publication，因此不能把每次推进都归因为异步 worker。测试不伪造
committed envelope、不用 Redis/Rabbit，不替代签名 HTTP 的完整单机 campaign。strict tenant tests 与两组
policy benches 使用 published-evidence 夹具，禁止 legacy/raw ports，并在计时
前检查 ALLOW/DENY/PENDING，避免把身份校验失败当作授权性能。

历史 RQ/S15 Redis/OPA 编排、真实 HTTP 负载、native live fault controller、TLC、
Linux/Valgrind IAI 与 frozen/excluded 项有各自明确阻塞原因，统一入口不会为了
使其可运行而给当前 native 架构添加中间件。它们仍保留源码及专用验证入口，
但本次局部/离线结果不能升级它们的状态。

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
4. 授权假设 M1-M5 的映射由 `IMPLEMENTATION_MAP.md` 说明；E2 稳定前提和
   profile 故障分类由 `Docs/authorization-validation/tools/experiment_register.py`
   及其离线契约锁定，两套编号不可混用。
