# tests-suite — 分类测试套件总入口

> 本目录是全仓测试的**汇集点**:集成测试按主系列物理存放于
> `series/<系列>/`,单元测试按 Cargo 语义留在属主 crate。`MANIFEST.toml`
> 保留全部测试的编目、多系列归属和 suite 执行索引。

## 当前 Rust 测试入口

当前 Cargo 测试目标以 workspace 与 [`Cargo.toml`](Cargo.toml) 的显式 `[[test]]` 登记为准；完整 suite、profile、series、精确命令与边界以 [`MANIFEST.toml`](MANIFEST.toml) 为准。唯一 campaign 执行器是 Rust `test-harness` crate 的 `test-campaign`；`scripts/run-tests.sh` 只是转发到该入口的便利别名，不另有一套 runner。V6 当前严格授权与 WorkerOwned 测试不提供旧 L1/L2、legacy fallback、Redis 兼容 feature、Redis profile 或 Redis test target。本次文档修订未运行 Cargo、服务或真实集成，不构成测试结果或 PASS。

```bash
cargo run --locked -p test-harness --bin test-campaign -- --list --json
bash scripts/run-tests.sh --campaign --run --profile native-kernel
bash scripts/run-tests.sh --campaign --run --suite native-projection-lifecycle
```

MANIFEST 中单独标记的 `COMPAT`/历史 campaign 条目是历史分类或阻塞边界，不是当前 Cargo 可执行目标；独立历史结果保持原样，不由当前文档改写为新的 PASS/FAIL。已退役 runner/probe 实现不作为执行入口或推荐路径。

## 物理系列目录

集成测试按**主系列**集中存放;一个测试仍可在 MANIFEST 中归属多个系列。

| 目录 | 主要测试 |
|---|---|
| `series/CORE/` | DB、Identity、Monitor、TrustGraph 基础集成 |
| `series/E1/` | Gateway 契约 |
| `series/E3/` | audit replay、ORG scope projector |
| `series/E4/` | quarantine、安全前提(hub / 身份映射 / 单写者租约) |
| `series/M5/` | 强制身份映射 |
| `series/MT-E1/` | 租户隔离、ORG scope、strict tenant、MT 隔离 |
| `series/MT-E3/` ~ `series/MT-E6/` | MT 搅动、跨租户风暴、容量、失败注入 |
| `series/RQ3/` | 授权投影、projection-owned、native lifecycle、projection HTTP |
| `series/RQ4/` | local message、partition lease、native storm |
| `series/PERF/` | 分配契约 |

`Cargo.toml` 显式登记当前嵌套目标，单项 Rust 测试按 [`MANIFEST.toml`](MANIFEST.toml) 登记的精确命令选择。单元测试(`#[cfg(test)]`)仍留在各属主 crate,不能脱离 crate 访问内部实现。

## 分类体系

| category | 含义 | 运行方式 |
|---|---|---|
| `unit-inline` | 内联单元测试(`#[cfg(test)]`,物理上属于属主 crate) | 经 MANIFEST 的 `workspace-tests` suite 运行 `cargo test --workspace --locked`；ignored 项单独计数 |
| `integration` | 当前 strict/native MySQL 集成(`#[ignore]` 门控);RabbitMQ 仅属 `standalone-rabbit` / `distributed` profile | 按 MANIFEST 选择 suite |
| `multi-tenant` | 租户隔离/租户拓扑测试 | 按 MANIFEST 选择 suite |
| `multi-tenant-extreme` | 多租户混合极限(大规模交错/搅动/风暴/容量/失败注入) | 按 MANIFEST suite 选择 `native-single-node` profile |
| `security` | 安全前提测试(E2 omission 风格 + 新架构前提) | 按 MANIFEST 的 Rust suite 选择 |
| `performance` | CPU-only 回归矩阵、分配及引擎评估 | 按 MANIFEST 的性能 suite 选择 |
| `e2e` | 单机 native composite、分布式与历史 campaign 分类 | 边界和状态见 MANIFEST `entry`；分类不代表存在可执行命令 |
| `archive` | 不适用当前架构/退役面(每条带理由) | 不运行 |

`native-kernel`、`offline-validation`、`native-single-node`、`standalone-rabbit`、
`distributed`、`performance-kernel` 与 `performance-native` 是当前七个 profile，
以 MANIFEST 为准；当前七个 profile 均不依赖 Redis，RabbitMQ 仅用于
`standalone-rabbit` 与 `distributed`。历史 `COMPAT`、Java/Rust oracle、Redis 专项与已删除的 Cargo targets 不能按本节命令执行；既有历史结果保持原貌，仅按其历史边界引用，不重算或重写。

## 运行前置(集成/多租户/安全真依赖类)

- 所有入口只选择 manifest 中的 suite，不启动容器、服务或迁移；隔离资源准备是独立的批准动作。
- MySQL 8.0、`TEST_USE_EXISTING=1`、`ASTRAL_MIGRATION_ENV=isolated`、`RUST_INTEGRATION_REQUIRED=1` 是真实集成前置。
- 普通集成库只允许 loopback:3308 的 `astral_rehearsal_<run-suffix>`，且必须与 `ASTRAL_TEST_DATABASE_NAME` 完全一致；源库 `astral_test` 和旧共享 rehearsal 库不得作为本轮目标。native 使用进程内 LocalBus/LocalProjectionBus，不需要消息中间件。
- Rabbit 专项只使用 MySQL + RabbitMQ，要求 loopback:5673 和显式 vhost。
- 专属映射 suite 只接受 `INTEGRATION_IDENTITY_MAPPING_DATABASE_URL` 和一致的 `INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE`，库名必须为 `sdk_identity_mapping_test_*`，loopback:3308，预先迁移。
- 所有被选择项先做统一前置检查；任一项 BLOCKED 时不派发任何命令。运行首个非 PASS 后停止，后续项只记录未执行，不计成功。

### 安全前提与入口回归

`Cargo.toml` 显式注册 `series/E4/` 下四个安全前提目标。真实 MySQL 测试和 native lifecycle
在 MANIFEST 中以 ignored suite 单列；纯配置、生命周期清理条件与排空等待的 Rust 测试不需要数据库。本 README 修订未运行这些集成。

脚本/矩阵别名不得替代 Rust `test-campaign` 与 MANIFEST 中的精确 suite/argv。纯组件回归可经 `scripts/run-tests.sh --campaign --run --profile native-kernel` 选择；真实依赖和多租户场景应按 MANIFEST 逐项选择，先通过适用的批准、环境和隔离数据库前置。当前统一入口不会启动容器/服务、执行迁移或 live fault；已批准资源不得由测试入口自动创建或删除。旧 Python runner/probe 不是当前入口，也不作为推荐迁移或复跑命令。

## 统一 Profile 与系列入口

`MANIFEST.toml` 保留全量 `entry` 分类，并新增机器可读的 `profile`、`series`、
`suite` 索引。统一执行入口是 Rust `test-harness`（由 `scripts/run-tests.sh`
调用），不使用 shell `eval`，不启动容器/服务，不迁移，不注入 live fault，也不重试 UNKNOWN。
每个 suite 声明属主、精确 argv、生产/测试服务、源码、断言数量和证明边界；
测试服务与生产 profile 不一致时，在派发前拒绝。

| profile | 服务依赖 | 证明范围 |
|---|---|---|
| `native-kernel` | 无 | 生产组件/strict 注入夹具；不证明 durable DB 或 HTTP |
| `offline-validation` | 无 | Rust 协议合约与有界模型（含 E5 单 mutation 报告差分）；归档 Python 方法/结果仅为历史记录，不运行、不作为当前 gate；未由 Rust suite 覆盖的运行证据缺口按 MANIFEST 保持 BLOCKED；形式模型/实装证据边界保持分离 |
| `native-single-node` | MySQL | LocalBus/LocalProjectionBus/MemoryProjectionHub 真实本地链路 |
| `standalone-rabbit` | MySQL + RabbitMQ | 独立服务传输与 durable consumer 证明；无 Redis |
| `distributed` | MySQL + RabbitMQ | 当前多进程 profile；完整 live distributed campaign 仍按 MANIFEST 标记为 BLOCKED，未由本次文档更新执行；不含历史 Redis/OPA harness |
| `performance-kernel` | 无 | compiler/policy/hub CPU 与分配数据 |
| `performance-native` | MySQL | native composite 签名 HTTP/收敛/负载；须有独立批准的部署、SUT 资源/积压采样和完整终态证据；loadgen 仅提供客户端测量 |

```bash
bash scripts/run-tests.sh --campaign --list --json
bash scripts/run-tests.sh --list-series --series RQ
bash scripts/run-tests.sh --campaign --run --profile native-kernel --series E2
bash scripts/run-tests.sh --campaign --run --profile offline-validation --suite offline-validation-tools
bash scripts/run-tests.sh --campaign --run --profile native-single-node --suite native-projection-lifecycle
bash scripts/run-tests.sh --campaign --run --profile performance-kernel --suite strict-policy-benchmark
```

真实 local-message outbox 压力与幂等覆盖可单独选择 `db-local-message-duplicate-stress` 或 `db-local-message-load`；两者需要已迁移隔离 MySQL，计数器高水位保留，负载测试覆盖单一热点 scope，不代表 HTTP、broker 或多节点吞吐。

真实依赖 profile 只复用 `TEST_USE_EXISTING=1` 的已批准、已迁移隔离库，并要求
`ASTRAL_MIGRATION_ENV=isolated`、`RUST_INTEGRATION_REQUIRED=1`。MySQL 必须是
loopback:3308 的 run-scoped `astral_rehearsal_<run-suffix>`，并通过
`ASTRAL_TEST_DATABASE_NAME` 与 URL 中数据库名精确比对；不得指向源库或复用旧共享克隆。
Rabbit profile 必须显式 vhost；runner 会清除父进程传入但不属于当前 profile
的连接变量。专属映射
suite 使用 `INTEGRATION_IDENTITY_MAPPING_DATABASE_URL` 和
`INTEGRATION_IDENTITY_MAPPING_TEST_DATABASE`，不会拿普通测试库代替。

未指定 profile 的 `--run` 选择 runner 默认的 `native-kernel`、`offline-validation`、
`performance-kernel` 集合，不自动扩大到集成。`--run --verify-items` 会在同一冻结源码下
先逐项验证，再运行集合；两阶段日志分开保存，不复用逐项 PASS。`--all-profiles --run`
选择全部 profile 的注册 suite（包含真实依赖与 BLOCKED 项），前置缺失会阻止整个集合派发。
历史或兼容 `entry` 不等于 Cargo target，也不会因列在 manifest 中而自动派发。
`--list --json` 始终保留全部注册项；默认集合未选的项目进入 `outside_selection`，不是 PASS。
可重复传 `--profile`、`--series`、`--suite`，未知或空选择拒绝。首个 FAIL/SKIP/BLOCKED/
UNKNOWN/PENDING 会停止派发；先修复或对账该项、重测单项，再用新 runId 从头重跑原集合。
runner 不自动修源码、不盲目重试、不缓存历史 PASS。

Authorization validation 的历史 Python 测试结果与 source archive 仅作为历史记录，不作为当前 Rust gate、parity PASS、fallback 或运行入口。当前可执行项以 `tests-suite/Cargo.toml` 的显式 targets 与 `MANIFEST.toml` 中注册的 Rust suite 为准；未迁移、部署或外部工具证据缺口维持各自记录状态，不由本 README 改写历史结果。已退役 Python runner/probe 实现不用于复跑或推荐。

RQ1-5 是主标签;`RQ-A` / `RQ-B` / `RQ-Compare` / `RQ5-E` 子系列已登记。
RQ-A/RQ-B/RQ-Compare 的外部 comparator/paper-scale 运行和 RQ5-E 的 live
signed HTTP/三节点运行未在本机验证；MANIFEST 为这些项登记了 Rust gate/static
contract，boundary 明确 live 未执行，不能据此宣称 live PASS。逐项证据边界见
[`Docs/测试/RQ子系列覆盖账本_2026-10-20.md`](../Docs/测试/RQ子系列覆盖账本_2026-10-20.md)。
RQ2-D 是结构性 N/A。M1-5 是
source capture、monotone publication、faithful representation、trusted
storage/processes、complete mediation 假设映射，不是五个独立证明，也不是
架构交付 M1-M3。E1-5 保留独立协议、模型与 live campaign；E2 的五个精确
Rust 目标必须各执行一例，host_mediation 仍为 model-only。E5 单 mutation 已由 Rust
显式状态空间与旧报告 fixture 差分覆盖；双 mutation 的 strict 完整界已有独立
离线 suite，prefix shard 按序执行；bracket omission 仍只找到有限反例且不完整。另有
Rust scoped-thread suite 对实际 single-mutation 配置检查并发/串行报告一致性，仅在该 suite 运行时构成本次证据。projection-owner 有限 BFS 与
U1-U10 evaluator fixture contract 已登记为 Rust 离线 suite；双模型 universal
枚举有 `e5-universal-bounded` release suite 的执行定义。仅当该 suite 独立运行并有本次证据时才可报告执行结果；fixture/manifest 登记不构成本次模型运行证据。
MT-E1/E3/E4/E5/E6
对应真实 MySQL suites；本次未运行这些真实集成。MT-E2 尚无实现，MANIFEST 只保留显式的 unimplemented
占位合同，不补造成功编号，也不把占位合同当作 MT-E2 已覆盖。

CPU-only 的三组 `PERF_MATRIX` acceptance 定义要求分别输出完整 82/15/40 个唯一 case、
每项至少 15 个有效样本，原始指标进入同一份 result.json；只有运行时满足该验收才构成性能证据；只执行一个 Rust
函数、被 `ASTRAL_PERF_CASE` 过滤或没有测量输出都不能计完整性能 PASS。
这些矩阵验证组件结果等价和采集完整性，比较数据没有额外性能阈值时不宣称
统计上“无回退”。独立现有吞吐下限仍由原测试严格断言，runner 不降低它们。

登记的 `policy-evaluate-benefit` suite acceptance 定义为测量实际
`PolicyEngine.evaluate()` 调用直到完整 `PolicyDecision` 返回，而非只测 hub 热读；协议保留
AUTHN、卡片上下文、资源 ownership、ORG 端口分类、初始证据校验/匹配、ALLOW 最终复读、统计和断路器开销。注册和契约本身不证明该基准本次已运行。
卡片/ORG/资源归属仍是明确的本地夹具，不是数据库身份或 managed ORG_SCOPE 查询。
当前 repository 返回 owned evidence，Arc 只在装配缓存内部共享，两次 ALLOW 读取仍深拷贝。
不能把此结果表述为共享 Arc 穿过评估器或签名 HTTP 的端到端收益。

```bash
bash scripts/run-tests.sh --campaign --run --suite policy-evaluate-benefit-controls --suite policy-evaluate-evidence-contracts --suite policy-evaluate-benefit
```

suite acceptance 定义固定 45 个 case（1/8/128/512/2048 grants × 1/4/8 threads × 首/尾命中 ALLOW 与无匹配 DENY），
每项 18 个配对批次，三组使用全部六种顺序各三次：固定秒缓存命中、每次读取跨秒强制装配、
生产 UTC 时钟参考。此定义不表示基准已运行。suite 执行时强制装配保留真实 miss 的填充成本；仅用 perpetual grants，逐项检查
证据/决策等价。实际 1 秒 TTL 不关闭，理想热读组必须证明全部 evidence read 命中，
生产时钟组按实际命中率报告。每个请求核对完整决策、ALLOW 两次/DEFAULT_DENY 一次读取，
正向、PENDING、跨秒过期和最终撤权控制在计时前独立执行。

登记 suite 的 acceptance 仅在 `--release` 完整矩阵通过时满足；runner 逐个核验 case、样本、线程/请求数、scope、
卡片/ORG/read 调用、grant 数、缓存命中、两阶段耗时和完整结束后置条件，并归档原始
逐决策 ns 与批次 wall ns。此处说明不表示该矩阵已运行。延迟不含返回后的断言/销毁，吞吐 wall 包含同步唤醒、结果核对、
记录/销毁和 join，不含线程/runtime 构造与预热。配对收益由原始数据独立计算，
几何平均比的 bootstrap 95% 区间是同次本地批次的探索性、不校正多重比较估计，
不是跨机器或部署置信保证。采集 PASS 不要求加速，负收益和不确定结果也必须报告。
收益分析以该 run 的 `result.json` 和 stdout 为事实来源，不复用历史 hub-only 样本。
首轮实测、阶段归因与未覆盖边界见
[完整评估装配缓存收益记录](../Docs/实验/基准测试/policy-evaluate-benefit-20261010.md)；
该记录只针对明确的本地 CPU run，不将采集 PASS 写成线上端到端验收。

campaign 实际执行时在仓库外创建不可覆盖的 run 目录，记录 taskId、源码内容 hash、cwd、
argv、环境名称、墙钟/单调耗时、退出码、完整脱敏 stdout/stderr、断言和 ignored
数量、postcondition 与重试次数（固定零）。源码在冻结后变化，或超时/取消/
日志中断时标 UNKNOWN 并停止后续派发；文档登记与命令示例不构成执行结果。内部 `[SKIP]`、ignored、零测试不能
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
两次变更模型与 universal 的 suite 边界由 MANIFEST 登记为最多 4 个独立配置进程；原 bound、
模式、omission、lattice 和 below-bound 检查不变，结果按原配置顺序汇总。
只有独立执行相应 suite 才产生本次证据；运行器不读取或复用其他 run 的 PASS。进程或日志
中断仍是 UNKNOWN；运行中顶层 status 保持 PENDING，只有完整终态才写 PASS。

MANIFEST 登记的 `native_projection_lifecycle` 是一个独立 binary 的单个 ignored 集成
suite，并有独立的无依赖清理条件与排空等待测试：验收要求消息数和字节占用均归零；
超时、内部失败或未证明关闭时保留本次 fixture/operation 标识，结果应为 UNKNOWN，
不得删除 durable 行或自动重试。suite 的目标覆盖真实 TrustGraph source repository
add/revoke、COMMIT 后 dispatch、durable delta/audit、LocalProjectionBus 单 owner、生产
local worker、published pointer/fence 与 PolicyEngine strict 读取；source API 也可能在
COMMIT 后同步完成 publication，因此不能把每次推进都归因为异步 worker。它不伪造
committed envelope、不用 Redis/Rabbit，也不替代签名 HTTP 的完整单机 campaign。本次
文档更新未运行该集成。strict tenant tests 与 policy benches 的已登记边界为
published-evidence 夹具、禁止 legacy/raw ports，并在计时前检查 ALLOW/DENY/PENDING；
这些边界不是本次测量结果，避免把身份校验失败当作授权性能。

历史 RQ/S15 Redis/OPA 编排、真实 HTTP 负载、native live fault controller、TLC、
Linux/Valgrind IAI 与 frozen/excluded 项有各自记录的边界或阻塞状态，统一入口不会为了
复跑它们而给当前 native 架构添加中间件。独立历史报告与结果保持原样；本地局部/离线结果
不能升级其状态，也不构成推荐执行入口。

## ID 段隔离

| 段 | 起点 | 归属 |
|---|---|---|
| 1e12 起 | tests-suite/series/MT-E1/multi_tenant_isolation.rs | 既有 mt 测试 |
| 9e12 附近 | Docs/实验/分布式测试/rust-s15 | 分布式 e2e |
| **2e16 起** | testsuite/src/lib.rs(`SUITE_BASE_MIN`) | testsuite 新套件 |

## 完整性约束(本目录的立目录原则)

1. 既有测试不删除、不弱化、不改阈值;只做加法与编目。
2. 归档条目必须带书面理由(`archive/` 内 README)。
3. 新套件深度只增不减:既有覆盖的断言语义在新套件中保持,并扩展到
   多租户/多配置维度。
4. 授权假设 M1-M5 的映射由 `IMPLEMENTATION_MAP.md` 说明；E2 稳定前提和
   profile 故障分类由 Rust `test-harness` 的 `experiment_register`、`dependency_profiles`
   合约及 MANIFEST 登记共同说明，两套编号不可混用；已退役 Python probe/runner 不构成入口。
