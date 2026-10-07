# AstralLight 基准测试运行指南

> 版本 1.30.0 | 2026-07-25

---

## 一、系统要求

| 项目 | 最低要求 | 推荐配置 |
|------|---------|---------|
| **操作系统** | Linux (x86_64) / macOS (aarch64) | Ubuntu 22.04 LTS |
| **JDK** | 21+ | 21 LTS（GraalVM 21 可选） |
| **Maven** | 3.9+ | 3.9.6 |
| **Docker** | 24+ | 26+ |
| **Docker Compose** | v2 | v2.27 |
| **内存** | 32 GB | 64 GB（JVM 16G + Docker 服务） |
| **磁盘** | 50 GB 可用 | SSD，100 GB |
| **网络** | 需拉取 Docker 镜像 | — |

---

## 二、快速开始（一键运行）

```bash
# 1. 进入项目根目录
cd AstralLight/AstralLight

# 2. 编译项目（跳过测试）
mvn clean package -DskipTests -pl AstralGeneral,AstralBenchmark -am -q

# 3. 启动基础设施（偏移端口，不与本地服务冲突）
docker compose -f docker/docker-compose-test.yml up -d

# 4. 等待健康检查通过（约 30 秒）
sleep 30

# 5. 运行完整原生基准测试套件
bash run_benchmark_full.sh
```

结果输出到 `benchmark-results/native-{timestamp}/`，包含 CSV 数据文件和原始样本。

### 2.1 跨系统对比基准一键脚本（comparison-5x-run.sh）

自包含版：自动启动 MySQL/Redis/OPA 容器、等待健康、导入 schema（如空）、
采集硬件快照，然后运行 N 次对比基准（默认 5×，fresh state 独立重复），
每次运行后复制结果目录、汇总 `summary.csv`，并合并 LaTeX 表格。

```bash
# 前置：构建 comparison jar（使用 legacy-benchmark profile，主类为 BenchmarkRunner）
cd AstralLight/AstralLight
mvn clean package -DskipTests -pl AstralGeneral,AstralBenchmark -am -Plegacy-benchmark -q

# 运行
export BENCHMARK_MYSQL_ROOT_PASSWORD='<你的 MySQL root 密码>'
bash Docs/实验/基准测试/scripts/comparison-5x-run.sh               # 完整对比 5×
bash Docs/实验/基准测试/scripts/comparison-5x-run.sh --repeats=3    # 完整对比 3×
bash Docs/实验/基准测试/scripts/comparison-5x-run.sh --only-rq2      # 仅 RQ-Compare-2（规则复杂度+卡数敏感性）
bash Docs/实验/基准测试/scripts/comparison-5x-run.sh --only-appendix # 仅 Cedar appendix
bash Docs/实验/基准测试/scripts/comparison-5x-run.sh --dry-run       # 仅环境检查并打印命令
```

参数说明：

| 参数 | 含义 |
|------|------|
| `--repeats=N` | 重复次数（默认 5），每次 fresh state 独立运行 |
| `--only-rq2` | 仅测量 RQ-Compare-2，传 `-Dbenchmark.rq2.only=true`（跳过 Layer A gate/分歧分析） |
| `--only-appendix` | 仅跑 Cedar appendix，传 `-Dbenchmark.appendix.only=true` |
| `--dry-run` | 不启动容器/JVM，仅打印将执行的命令与输出目录 |

**远端部署版**：`remote-comparison-5x-run.sh` 为适配 `AstralLight-benchmark/` 工作区
（脚本置于 `AstralLight-benchmark/scripts/`）的版本，`REPO_DIR` 推导已调整；
连同 `docker-compose-benchmark.yml`、`full_schema_v4.sql`、`import-schema.sh` 一起
拷贝到远端 `scripts/` 目录即可一键运行。

> ⚠️ 新开关依赖 BenchmarkRunner 已支持 `-Dbenchmark.rq2.only` / `-Dbenchmark.appendix.only`，
> 请使用本仓库最新代码构建的 jar。

---

### 2.2 独立 native campaign（保留失败尝试）

需要在确认数据库和 Redis 都是专用实例后显式设置环境变量；脚本会在 JVM 启动前拒绝未配置的 secret、连接信息、环境 ID 或清理批准，不会自动删除已有 `benchmark-results` 归档：

```bash
export BENCH_JWT_SECRET='<injected-secret>'
export DB_HOST='<dedicated-db-host>' DB_PORT='<dedicated-db-port>' DB_NAME='<dedicated-db-name>'
export DB_USER='<dedicated-db-user>' DB_PASSWORD='<injected-db-password>'
export REDIS_HOST='<dedicated-redis-host>' REDIS_PORT='<dedicated-redis-port>'
export BENCHMARK_ENV_ID='dedicated-benchmark-environment'
export BENCHMARK_DESTRUCTIVE_CLEANUP_APPROVED=true

bash Docs/实验/基准测试/scripts/run_native_campaign.sh \
  --protocol rq1 --replicates 3 \
  --campaign-dir Docs/实验/复现运行/native-campaign-<timestamp>
python Docs/实验/基准测试/scripts/summarize_native_campaign.py \
  Docs/实验/复现运行/native-campaign-<timestamp>
```

每个 attempt 独立保存 `manifest.json`、`status.json`、日志、原始输出、派生目录和 `checksums.sha256`。汇总器按完整 attempt 的 summary CSV 计算 run-level 均值、SD、中位数、MAD 和范围；它不把 operation samples 当作独立 runs，也不合并或平均各 run 的 P99 成 pooled percentile。setup-blocked、failed、partial 和 excluded attempts 保留在计数中。

### 2.3 Java 集成场景的仓库边界

原 Java Testcontainers 授权场景依赖 `AstralTrustGraph` 多模块源码，本 Rust 仓库不包含该模块，因此这里不提供可执行命令或集成通过结论。Rust 授权验证入口见 `Docs/authorization-validation/`。

### 2.4 三节点异构集群授权一致性（Phase 2）

三台异构服务器（Intel Xeon Platinum 8000 / Xeon E5-2690 v3 / Ryzen 7 7735HS）通过 overlay 网络组成共享 MySQL/Redis/RabbitMQ 集群，验证 Phase 1 修复后的分布式授权状态安全。**硬件性能与分布式一致性分开报告**：硬件效应用各节点自身 no-fault baseline 估计，分布式一致性效应用同节点在 no-fault 与 fault 阶段的配对差值估计；不跨异构硬件平均 P99。

**三节点集成测试**（Testcontainers 启动 MySQL 8 + Redis 7 + RabbitMQ 3，3 个独立 Spring context，`@Tag("cluster")` 默认排除，需 Docker）：

```bash
mvn -pl AstralTrustGraph -am \
  -Dtest=AuthorizationProjectionThreeNodeIntegrationTest \
  -Dgroups=cluster -DexcludedGroups= \
  -Dsurefire.failIfNoSpecifiedTests=false test
```

覆盖：并发首个 head 创建（唯一 head、generation 连续、无 orphan outbox）；mutation 后跨节点可见性（revoke READY 后 stale ALLOW 必须为 0）；真实 command/outbox/projector/lease 竞争。

**真实分布式授权测试**（`@Tag("cluster-remote")`，3 个独立 TrustGraph 进程 + 共享 MySQL/Redis/Rabbit，经 HTTP 控制平面驱动；编排见 `Docs/实验/分布式测试/`）：

```bash
bash Docs/实验/分布式测试/run_distributed_cluster_test.sh
```

**三节点 benchmark campaign**（no-fault 编排；fault 编排脚本 `run_native_cluster_fault_campaign.sh` 尚未实现，勿引用）：

```bash
# 环境变量注入，不硬编码地址/凭据
export CLUSTER_DESTRUCTIVE_CLEANUP_APPROVED=true
export CLUSTER_SSH_USER=... NODE_A_HOST=... NODE_B_HOST=... NODE_C_HOST=...
export NODE_A_HARDWARE=xeon-platinum-8000 NODE_B_HARDWARE=xeon-e5-2690-v3 NODE_C_HARDWARE=ryzen-7-7735hs
export JAR_PATH=... BENCH_JWT_SECRET=... DB_HOST=... DB_PORT=... DB_NAME=... DB_PASSWORD=...
export REDIS_HOST=... REDIS_PORT=... RABBIT_HOST=... RABBIT_PORT=... BENCHMARK_ENV_ID=...
bash run_native_cluster_campaign.sh
```

- `native-cluster-3nodes.json`：只声明 node/hardware/role/phase，不含任何地址或凭据。
- 角色 `WRITER/READER_A/READER_B` 与 3 种硬件做 6 个 permutation；每节点同一 JAR SHA-256、同一 seed=42、同一 fixed clock。
- `ClusterRunContext`（`benchmark.cluster.*` 系统属性）驱动节点身份/角色/phase/全局序列；`DecisionOutcomeRecorder` 新增 node_id/node_role/global_sequence/operation_id/source_generation/projected_generation/revoke_fence/projection_status/fault_state 列。
- 每节点输出 `rq4a_native_decision_outcomes.csv` 等 artifact，`checksums.sha256` 覆盖最终产物；只保留通过 validity audit 的 attempt。


基准测试分为两个独立套件，互不影响，可独立运行。

### 3.1 原生日志基准测试（NativeBenchmark）

**入口类**：`com.coreryblack.benchmark.nativebenchmark.NativeAstralBenchmark`

仅测试 AstralLight 自身各项指标，不涉及外部对比系统。

| 套件 | 内容 | 子项 |
|---------|------|------|
| **RQ1** | 存储空间效率 | 快照存储开销 |
| **RQ2** | 决策性能 | A:规则复杂度 B:卡片规模 C:叠加深度 D:冲突密度 E:SOD 策略 F:租户隔离 G:模板隔离 H:卡片隔离 I:叠加引用数 J:ABAC 复杂度 K:权限规则 |
| **RQ3** | 增量编译开销 | 正常增量 / 优胜者删除退化 / 高频写入 / SCAN vs HDEL |
| **RQ4** | 系统韧性 | A:缓存故障+熔断器 B:高频写入+一致性检验 C:乐观锁+版本链 |
| **RQ5** | 补充验证套件 | E2:TOCTOU 切换原子性 E4:缓存窗口 E11:旧令牌回放 E3+E5:吞吐量 QPS 可扩展性 |
| **AUTHZ-SAFETY** | Java 授权安全场景 | 撤销 fence、投影门控、源规则 Oracle、Redis 故障逐决策结果 |

### 3.2 多系统对比基准测试（ComparisonBenchmark）

**入口类**：`com.coreryblack.benchmark.runner.BenchmarkRunner`

- **Layer 1**：AstralLight vs Casbin vs OPA vs Cedar（基于规则的访问控制）
- **Layer 2**：AstralLight vs SpiceDB（基于关系的访问控制）
- 包含正确性验证门控（`CrossSystemCorrectnessVerifier`）

---

## 四、基础设施配置

项目提供了三个 docker-compose 文件，按需选择：

### 4.1 单元/集成测试环境

```bash
docker compose -f docker/docker-compose-test.yml up -d
```

| 服务 | 容器端口 | 宿主机端口 | 用途 |
|------|---------|-----------|------|
| MySQL 8.0 | 3306 | **3307** | 测试数据库 `astral_test`，用户 `test/test` |
| Redis 7 | 6379 | **6380** | 缓存 |
| RabbitMQ 3 (管理端) | 5672/15672 | **5673/15673** | 消息队列 |
| OPA | 8181 | **8181** | 策略引擎 |

> 端口已偏移，可与本地安装的 MySQL/Redis 共存。

### 4.2 原生基准测试环境

```bash
docker compose -f docker/docker-compose-benchmark-native.yml up -d
```

| 服务 | 端口 | 调优 |
|------|------|------|
| MySQL 8.0 | 3306 | `innodb-buffer-pool-size=512M`, `max-connections=200` |
| Redis 7 | 6379 | `maxmemory 512mb`, 关闭持久化 |
| RabbitMQ 3 | 5672/15672 | 标准配置 |

### 4.3 多系统对比基准测试环境

```bash
docker compose -f docker/docker-compose-benchmark-compare.yml up -d
```

除 4.2 所有服务外，额外包含：

| 服务 | 端口 | 用途 |
|------|------|------|
| OPA | 8181 | Layer 1 对比系统 |
| **SpiceDB** | **50051** (gRPC) | Layer 2 对比系统 |
| PostgreSQL 16 | 5432 | SpiceDB 数据后端 |

> 使用 SpiceDB 对比时需设置环境变量：
> ```bash
> export SPICEDB_ENDPOINT=localhost:50051
> export SPICEDB_PRESHARED_KEY=benchmark-key
> ```

---

## 五、详细运行说明

### 5.1 原生基准测试

**完整运行**（所有 RQ，约 4-6 小时）：

```bash
# 方式一：使用脚本
bash run_benchmark_full.sh

# 方式二：直接运行 JAR
java -Xms8G -Xmx16G \
  -XX:+UseZGC -XX:+ZGenerational -XX:+AlwaysPreTouch -XX:ConcGCThreads=4 \
  -jar evaluation/benchmark-java/target/AstralBenchmark-0.0.1-SNAPSHOT.jar \
  --spring.profiles.active=benchmark
```

**选择性运行**：

```bash
# 仅运行 RQ2（决策性能）
java -Xms8G -Xmx16G \
  -XX:+UseZGC -XX:+ZGenerational -XX:+AlwaysPreTouch \
  -jar evaluation/benchmark-java/target/AstralBenchmark-0.0.1-SNAPSHOT.jar \
  --spring.profiles.active=benchmark \
  --only-rq2

# 跳过 RQ1 和 RQ3
java ... --spring.profiles.active=benchmark --skip-rq1 --skip-rq3

# 从 RQ2 第 F 个子项断点续跑
java ... --spring.profiles.active=benchmark --start-from=F

# 从 RQ4 第 B 个子项断点续跑
java ... --spring.profiles.active=benchmark --start-from-rq4=B
```

**CLI 参数一览**：

| 参数 | 作用 |
|------|------|
| `--skip-rq1` / `--skip-rq2` / `--skip-rq3` / `--skip-rq4` / `--skip-rq5` | 跳过指定 RQ |
| `--only-rq1` / `--only-rq2` / `--only-rq3` / `--only-rq4` / `--only-rq5` | 仅运行指定 RQ |
| `--start-from={A..K}` | RQ2 从指定子项续跑 |
| `--start-from-rq4={A..C}` | RQ4 从指定子项续跑 |

> **RQ5** 包含 E2 (TOCTOU 切换原子性)、E4 (缓存窗口)、E11 (旧令牌回放) 和 E3+E5 (吞吐量可扩展性)。配置参数集中在 `RQ5Configs.java` 中，与 `SupplementaryExperimentRunner` 共享，确保独立运行与全套件运行结果可比。

**GC 配置说明**：

| 参数 | 作用 |
|------|------|
| `-XX:+UseZGC` | ZGC：暂停 <1ms，适合延迟敏感型基准测试 |
| `-XX:+ZGenerational` | 分代 ZGC（Java 21+），提升吞吐量 |
| `-XX:+AlwaysPreTouch` | 预触所有堆页，消除运行时 page-fault 延迟尖刺 |
| `-XX:ConcGCThreads=4` | 4 个并发 GC 线程，避免与基准测试线程争抢 CPU |

> 如果 JDK 不支持 ZGC，回退方案：
> ```bash
> -XX:+UseG1GC -XX:MaxGCPauseMillis=50 -XX:+AlwaysPreTouch
> ```

### 5.1.1 RQ5 补充验证套件

RQ5 可通过两种方式独立运行：

**方式一：通过主入口的 CLI 参数**

```bash
# 仅运行 RQ5（跳过 RQ1-RQ4）
java -Xms8G -Xmx16G \
  -XX:+UseZGC -XX:+ZGenerational -XX:+AlwaysPreTouch \
  -jar evaluation/benchmark-java/target/AstralBenchmark-0.0.1-SNAPSHOT.jar \
  --spring.profiles.active=benchmark \
  --only-rq5
```

**方式二：通过独立 Runner（推荐用于隔离重复运行）**

`SupplementaryExperimentRunner` 是独立的入口类，不加载 RQ1-RQ4 的上下文，启动更快且写入环境元数据快照（`environment.json`）用于复现审查：

```bash
java -Xms8G -Xmx16G \
  -XX:+UseZGC -XX:+ZGenerational -XX:+AlwaysPreTouch \
  -cp evaluation/benchmark-java/target/AstralBenchmark-0.0.1-SNAPSHOT.jar \
  com.coreryblack.benchmark.nativebenchmark.SupplementaryExperimentRunner
```

输出目录：`benchmark-results/supp-{timestamp}/`，包含 `environment.json`（JVM/OS/CPU 元数据，不含密码）。

**环境变量配置**（方式二必需，方式一使用 `application-benchmark.yml`）：

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `BENCH_MYSQL_HOST` | `localhost` | MySQL 主机 |
| `BENCH_MYSQL_PORT` | `3307` | MySQL 端口（偏移端口，避免冲突） |
| `BENCH_MYSQL_USER` | `test` | MySQL 用户名 |
| `BENCH_MYSQL_PASSWORD` | `test` | MySQL 密码（**仅从环境变量读取，禁止硬编码**） |
| `BENCH_REDIS_HOST` | `localhost` | Redis 主机 |
| `BENCH_REDIS_PORT` | `6380` | Redis 端口（偏移端口） |

示例：连接到自定义数据库实例

```bash
export BENCH_MYSQL_HOST=benchmark-db.example.invalid
export BENCH_MYSQL_PORT=3306
export BENCH_MYSQL_USER=researcher
export BENCH_MYSQL_PASSWORD='${DB_PASSWORD:?}'  # 从环境注入，不出现在命令行历史
export BENCH_REDIS_HOST=benchmark-cache.example.invalid
export BENCH_REDIS_PORT=6379

java -Xms8G -Xmx16G \
  -XX:+UseZGC -XX:+ZGenerational -XX:+AlwaysPreTouch \
  -cp evaluation/benchmark-java/target/AstralBenchmark-0.0.1-SNAPSHOT.jar \
  com.coreryblack.benchmark.nativebenchmark.SupplementaryExperimentRunner
```

> **敏感信息规范**：密码仅通过 `BENCH_MYSQL_PASSWORD` 环境变量传入，不出现在源码、命令行参数或 `environment.json` 元数据中。仓库级执行门禁见 [`AGENTS.md`](../../../../AGENTS.md)。

### 5.2 多系统对比基准测试

**完整运行**（约 2-3 小时）：

```bash
# 1. 启动对比测试基础设施
docker compose -f docker/docker-compose-benchmark-compare.yml up -d
sleep 30

# 2. 设置 SpiceDB 连接（可选；不设置则使用内存回退模式）
export SPICEDB_ENDPOINT=localhost:50051
export SPICEDB_PRESHARED_KEY=benchmark-key

# 3. 编译
mvn clean package -DskipTests -pl AstralGeneral,AstralBenchmark -am -q

# 4. 运行
java -Xms8G -Xmx16G \
  -XX:+UseZGC -XX:+ZGenerational -XX:+AlwaysPreTouch -XX:ConcGCThreads=4 \
  -jar evaluation/benchmark-java/target/AstralBenchmark-0.0.1-SNAPSHOT.jar \
  --spring.profiles.active=benchmark \
  --comparison-mode
```

> 注意：对比基准测试的主类是 `BenchmarkRunner`（非 `NativeAstralBenchmark`），如果使用脚本方式运行需指定主类。

---

## 六、输出结果说明

### 6.1 目录结构

```
benchmark-results/
├── native-{timestamp}/               # 原生基准测试
│   ├── rq1_native_space_efficiency.csv
│   ├── rq1_native_summary.csv
│   ├── rq2a_native_rule_complexity.csv
│   ├── rq2b_native_card_scale.csv
│   ├── rq2b_native_storage_tps.csv
│   ├── rq2c_native_overlay_depth.csv
│   ├── rq2d_native_conflict_density.csv
│   ├── rq2e_native_sod_policy.csv
│   ├── rq2e_native_sod_correctness.csv
│   ├── rq2f_native_tenant_isolation.csv
│   ├── rq2g_native_template_isolation.csv
│   ├── rq2g_native_template_o1.csv
│   ├── rq2h_native_card_isolation.csv
│   ├── rq2h_native_card_o1.csv
│   ├── rq2i_native_overlay_ref.csv
│   ├── rq2i_native_overlay_ref_ok.csv
│   ├── rq2j_native_abac_complexity.csv
│   ├── rq2j_native_abac_oc.csv
│   ├── rq2k_native_perm_rule.csv
│   ├── rq2k_native_perm_rule_l2.csv
│   ├── rq2_native_latency_data.csv
│   ├── rq2_native_latency_table.tex
│   ├── rq2_native_latency_table_ci.tex
│   ├── rq2_native_statistical_tests.csv
│   ├── rq3_native_incremental_data.csv
│   ├── rq4a_native_cache_failure.csv
│   ├── rq4a_native_decision_outcomes.csv
│   ├── rq4a_native_decision_summary.csv
│   ├── rq4b_native_high_freq_write.csv
│   ├── rq4c_native_optimistic_lock.csv
│   └── *native_raw/                 # 原始样本（用于 merge + stddev）
│
├── supp-{timestamp}/                 # RQ5 补充实验（SupplementaryExperimentRunner）
│   ├── environment.json              # 环境元数据（JVM/OS/CPU，不含密码）
│   └── (stdout 日志输出 QPS/延迟/TOCTOU 指标)
│
├── comparison-{timestamp}/           # 多系统对比测试
│   ├── layer1/                       # RQ-Compare-1,2,3
│   │   ├── comparison_report.csv
│   │   ├── comparison_summary.csv
│   │   ├── rule_update_overhead.csv
│   │   └── raw_samples/
│   └── layer2/                       # RQ-Compare-4
│       ├── comparison_report.csv
│       ├── depth_scalability.csv
│       └── raw_samples/
```

### 6.2 关键指标

所有 CSV 文件包含以下列（因实验而异）：

| 列名 | 含义 |
|------|------|
| `mean_us` | 平均延迟（微秒） |
| `p50_us` | 中位延迟（微秒） |
| `p99_us` | 99 分位延迟（微秒） |
| `sample_count` | 样本数量 |
| `throughput_ops` | 吞吐量（操作/秒） |
| `l1_hit_rate` / `l2_hit_rate` / `l3_hit_rate` | 三级缓存命中率 |
| `rq4a_native_decision_outcomes.csv` | 每个授权请求一行，包含 phase、ALLOW/DENY/ERROR、reason、decision_source、decision_path、延迟和预期结果 |
| `rq4a_native_decision_summary.csv` | 按 phase/outcome/reason/decision_source/decision_path 聚合的计数与平均延迟 |
| `rq4a_native_decision_validity.txt` | 检查 phase 行数守恒、实际 PolicyEngine 调用、错误 ALLOW 和 circuit-breaker DENY 语义 |

`REDIS_DOWN` 阶段的语义必须在结果中单独标记：

- `FLUSHDB`：冷缓存/缓存丢失，不是 Redis transport outage；
- `LettuceConnectionFactory.resetConnection()`：客户端连接重置，不是服务端宕机；
- marker protocol + `docker stop`：真实 Redis 进程故障，只有该模式可用于报告 transport-fault decision samples。

`CIRCUIT_BREAKER_OPEN` 是一个可观测的 DENY，不应计入异常错误；连接异常则单独记录为 `ERROR`。

### 6.3 多次重复运行取均值

运行 3 次后，可使用 `LatencyRecorder.LatencySnapshot.merge()` 合并原始样本并计算均值与标准差：

```java
// 示例：合并三次运行结果
LatencySnapshot run1 = LatencySnapshot.load("run1/rq2_native_raw");
LatencySnapshot run2 = LatencySnapshot.load("run2/rq2_native_raw");
LatencySnapshot run3 = LatencySnapshot.load("run3/rq2_native_raw");
LatencySnapshot merged = LatencySnapshot.merge(List.of(run1, run2, run3));
// 输出: mean ± stddev = merged.meanUs() ± merged.stddevUs()
```

---

## 七、验证正确性

### 7.1 数据完整性检查

```bash
# 检查是否所有 CSV 文件都有有效数据
for f in benchmark-results/native-*/*.csv; do
  lines=$(wc -l < "$f")
  if [ "$lines" -le 1 ]; then
    echo "WARNING: $f has only header, no data"
  fi
done
```

### 7.2 跨系统正确性门控

对比基准测试内置 `CrossSystemCorrectnessVerifier`，自动验证：
- AstralLight 与 Casbin 决策一致性
- AstralLight 与 OPA 决策一致性
- 差异 > 5 时输出 ERROR，阻塞报告生成

### 7.3 基准测试有效性审计

原生基准测试调用 `BenchmarkValidityAudit`，验证：
- 数据生成与加载一致性
- 预热充分性
- 无 GC 异常干预

---

## 八、常见问题

### Q1: Docker 服务未启动

```bash
docker compose -f docker/docker-compose-test.yml ps
# 确认所有服务状态为 "healthy" 或 "running"
```

### Q2: 内存不足

```bash
# 降低 JVM 堆大小（可能影响 benchmark 结果可比性）
export JAVA_OPTS="-Xms4G -Xmx8G -XX:+UseZGC -XX:+ZGenerational -XX:+AlwaysPreTouch"

# 或仅运行小规模子集
java ... --only-rq2
```

### Q3: SpiceDB 不可用（对比测试）

如果不设置 `SPICEDB_ENDPOINT`，SpiceDB 将使用内存回退模式。**注意**：内存回退不代表真实 SpiceDB 语义，不适合发表级对比。日志会输出警告 `NOT publication-quality`。

### Q4: 端口冲突

测试环境使用偏移端口（3307/6380/5673），不会冲突。基准测试使用标准端口（3306/6379/5672），如冲突请先停掉本地实例。

### Q5: 编译失败

```bash
# 确保 JDK 版本正确
java -version  # 应为 21+

# 清理后重新编译
mvn clean install -DskipTests -pl AstralGeneral -am -q
mvn clean package -DskipTests -pl AstralBenchmark -am -q
```

### Q6: 想要更快地获得初步结果

```bash
# 仅运行 RQ2 的主决策性能测试（约 30 分钟）
java -Xms8G -Xmx16G \
  -XX:+UseZGC -XX:+ZGenerational -XX:+AlwaysPreTouch -XX:ConcGCThreads=4 \
  -jar evaluation/benchmark-java/target/AstralBenchmark-0.0.1-SNAPSHOT.jar \
  --spring.profiles.active=benchmark \
  --only-rq2
```

---

## 九、公平性声明

所有对比系统均使用厂商推荐的生产配置：

| 系统 | 配置 | SDK |
|------|------|-----|
| **AstralLight** | 三级缓存 + ZGC + RuleSet 快照 | 自身 |
| **Casbin** | Cached Mode via jCasbin 1.99.0 | jcasbin |
| **OPA** | Docker `openpolicyagent/opa:latest` | REST API |
| **Cedar** | cedar-java 4.10.0 Rust 引擎 (JNI) | 官方 SDK |
| **SpiceDB** | Docker `authzed/spicedb:latest` via authzed-java 1.6.0 gRPC | 官方 SDK |

所有系统使用相同数据集（`seed=42`），通过 `CrossSystemCorrectnessVerifier` 验证语义一致性。
