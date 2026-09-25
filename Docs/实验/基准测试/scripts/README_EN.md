# AstralLight Benchmark Run Guide

> Version 1.30.0 | 2026-07-25

---

## 1. System Requirements

| Item | Minimum | Recommended |
|------|---------|-------------|
| **OS** | Linux (x86_64) / macOS (aarch64) | Ubuntu 22.04 LTS |
| **JDK** | 21+ | 21 LTS (GraalVM 21 optional) |
| **Maven** | 3.9+ | 3.9.6 |
| **Docker** | 24+ | 26+ |
| **Docker Compose** | v2 | v2.27 |
| **Memory** | 32 GB | 64 GB (16G JVM + Docker services) |
| **Disk** | 50 GB free | SSD, 100 GB |
| **Network** | Docker image pull access | — |

---

## 2. Quick Start (One Command)

```bash
# 1. Enter project root
cd AstralLight/AstralLight

# 2. Build (skip tests)
mvn clean package -DskipTests -pl AstralGeneral,AstralBenchmark -am -q

# 3. Start infrastructure (offset ports, won't conflict with local services)
docker compose -f docker/docker-compose-test.yml up -d

# 4. Wait for health checks (~30 seconds)
sleep 30

# 5. Run full native benchmark suite
bash run_benchmark_full.sh
```

Results are written to `benchmark-results/native-{timestamp}/` with CSV data files and raw samples.

### 2.1 Java integration scope

The Java Testcontainers authorization scenario depends on the `AstralTrustGraph` multi-module source, which is not included in this Rust repository. No runnable command or integration result is claimed here. Rust authorization validation entry points are under `Docs/authorization-validation/`.

### 2.2 Three-node heterogeneous cluster authorization consistency (Phase 2)

Three heterogeneous machines (Intel Xeon Platinum 8000 / Xeon E5-2690 v3 / Ryzen 7 7735HS) form a shared MySQL/Redis/RabbitMQ cluster over an overlay network to validate the Phase 1 distributed-authorization-state fixes. Hardware effects and distributed-consistency effects are reported separately: hardware is estimated from each node's own no-fault baseline, distributed consistency from paired no-fault vs fault phase deltas on the same node. P99 is never averaged across heterogeneous hardware.

**Three-node integration test** (Testcontainers starts MySQL 8 + Redis 7 + RabbitMQ 3; three independent Spring contexts; `@Tag("cluster")` excluded by default; requires Docker):

```bash
mvn -pl AstralTrustGraph -am \
  -Dtest=AuthorizationProjectionThreeNodeIntegrationTest \
  -Dgroups=cluster -DexcludedGroups= \
  -Dsurefire.failIfNoSpecifiedTests=false test
```

Covers: concurrent first-head creation (single head, contiguous generations, no orphan outbox); cross-node mutation visibility (stale ALLOW must be zero after a revoke becomes READY); real command/outbox/projector/lease contention.

**Real distributed authorization test** (`@Tag("cluster-remote")`: three independent TrustGraph processes + shared MySQL/Redis/Rabbit, driven over an HTTP control plane; orchestration under `Docs/实验/分布式测试/`):

```bash
bash Docs/实验/分布式测试/run_distributed_cluster_test.sh
```

**Three-node benchmark campaign** (no-fault orchestration; the fault orchestration script `run_native_cluster_fault_campaign.sh` is not implemented yet — do not reference it):

```bash
# All endpoints and credentials are injected via environment variables
export CLUSTER_DESTRUCTIVE_CLEANUP_APPROVED=true
export CLUSTER_SSH_USER=... NODE_A_HOST=... NODE_B_HOST=... NODE_C_HOST=...
export NODE_A_HARDWARE=xeon-platinum-8000 NODE_B_HARDWARE=xeon-e5-2690-v3 NODE_C_HARDWARE=ryzen-7-7735hs
export JAR_PATH=... BENCH_JWT_SECRET=... DB_HOST=... DB_PORT=... DB_NAME=... DB_PASSWORD=...
export REDIS_HOST=... REDIS_PORT=... RABBIT_HOST=... RABBIT_PORT=... BENCHMARK_ENV_ID=...
bash run_native_cluster_campaign.sh
```

- `native-cluster-3nodes.json`: declares only node/hardware/role/phase; no addresses or credentials.
- Roles `WRITER/READER_A/READER_B` are crossed with the three hardware labels over 6 permutations; every node runs the same JAR SHA-256, seed=42, and fixed clock.
- `ClusterRunContext` (system properties `benchmark.cluster.*`) drives node identity/role/phase/global sequence; `DecisionOutcomeRecorder` adds node_id/node_role/global_sequence/operation_id/source_generation/projected_generation/revoke_fence/projection_status/fault_state columns.
- Per-node artifacts such as `rq4a_native_decision_outcomes.csv` are retained with a final `checksums.sha256`; only attempts that pass the validity audit are reported.

---

## 3. Benchmark Architecture

Two independent benchmark suites. They can be run separately.

### 3.1 Native Benchmark

**Entry point**: `com.coreryblack.benchmark.nativebenchmark.NativeAstralBenchmark`

Evaluates AstralLight internals only — NO external comparison systems.

| Suite | Topic | Sub-benchmarks |
|----|-------|---------------|
| **RQ1** | Storage Space Efficiency | Snapshot storage overhead |
| **RQ2** | Decision Performance | A:Rule Complexity B:Card Scale C:Overlay Depth D:Conflict Density E:SOD Policy F:Tenant Isolation G:Template Isolation H:Card Isolation I:Overlay Ref Count J:ABAC Complexity K:Permission Rule |
| **RQ3** | Incremental Compile | Normal incremental / Delete-winner degradation / High-frequency write / SCAN vs HDEL |
| **RQ4** | System Resilience | A:Cache Failure+Circuit Breaker B:High-Freq Write+Consistency Check C:Optimistic Lock+Version Chain |
| **AUTHZ-SAFETY** | Java authorization scenarios | Revoke fence, projection gate, source-rule oracle, and per-decision Redis-fault outcomes |

### 3.2 Comparison Benchmark

**Entry point**: `com.coreryblack.benchmark.runner.BenchmarkRunner`

- **Layer 1**: AstralLight vs Casbin vs OPA vs Cedar (rule-based access control)
- **Layer 2**: AstralLight vs SpiceDB (relationship-based access control)
- Built-in correctness gating (`CrossSystemCorrectnessVerifier`)

---

## 4. Infrastructure

Three docker-compose files for different scenarios:

### 4.1 Unit / Integration Test Environment

```bash
docker compose -f docker/docker-compose-test.yml up -d
```

| Service | Container Port | Host Port | Purpose |
|---------|---------------|-----------|---------|
| MySQL 8.0 | 3306 | **3307** | Test DB `astral_test`, user `test/test` |
| Redis 7 | 6379 | **6380** | Cache |
| RabbitMQ 3 (management) | 5672/15672 | **5673/15673** | Message queue |
| OPA | 8181 | **8181** | Policy engine |

> Offset ports ensure no conflicts with locally installed MySQL/Redis.

### 4.2 Native Benchmark Environment

```bash
docker compose -f docker/docker-compose-benchmark-native.yml up -d
```

| Service | Port | Tuning |
|---------|------|--------|
| MySQL 8.0 | 3306 | `innodb-buffer-pool-size=512M`, `max-connections=200` |
| Redis 7 | 6379 | `maxmemory 512mb`, persistence disabled |
| RabbitMQ 3 | 5672/15672 | Standard config |

### 4.3 Comparison Benchmark Environment

```bash
docker compose -f docker/docker-compose-benchmark-compare.yml up -d
```

All §4.2 services plus:

| Service | Port | Purpose |
|---------|------|---------|
| OPA | 8181 | Layer 1 comparison target |
| **SpiceDB** | **50051** (gRPC) | Layer 2 comparison target |
| PostgreSQL 16 | 5432 | SpiceDB datastore backend |

> Required environment variables for SpiceDB comparison:
> ```bash
> export SPICEDB_ENDPOINT=localhost:50051
> export SPICEDB_PRESHARED_KEY=benchmark-key
> ```

---

## 5. Detailed Run Instructions

### 5.1 Native Benchmark

**Full run** (all RQs, ~4–6 hours):

```bash
# Option 1: Shell script
bash run_benchmark_full.sh

# Option 2: Direct JAR
java -Xms8G -Xmx16G \
  -XX:+UseZGC -XX:+ZGenerational -XX:+AlwaysPreTouch -XX:ConcGCThreads=4 \
  -jar evaluation/benchmark-java/target/AstralBenchmark-0.0.1-SNAPSHOT.jar \
  --spring.profiles.active=benchmark
```

**Selective runs**:

```bash
# Only RQ2 (decision performance)
java -Xms8G -Xmx16G \
  -XX:+UseZGC -XX:+ZGenerational -XX:+AlwaysPreTouch \
  -jar evaluation/benchmark-java/target/AstralBenchmark-0.0.1-SNAPSHOT.jar \
  --spring.profiles.active=benchmark \
  --only-rq2

# Skip RQ1 and RQ3
java ... --spring.profiles.active=benchmark --skip-rq1 --skip-rq3

# Resume RQ2 from sub-benchmark F
java ... --spring.profiles.active=benchmark --start-from=F

# Resume RQ4 from sub-benchmark B
java ... --spring.profiles.active=benchmark --start-from-rq4=B
```

**CLI Arguments**:

| Argument | Effect |
|----------|--------|
| `--skip-rq1` / `--skip-rq2` / `--skip-rq3` / `--skip-rq4` | Skip specified RQ |
| `--only-rq1` / `--only-rq2` / `--only-rq3` / `--only-rq4` | Run only specified RQ |
| `--start-from={A..K}` | Resume RQ2 from given sub-benchmark |
| `--start-from-rq4={A..C}` | Resume RQ4 from given sub-benchmark |

**GC Configuration**:

| Flag | Purpose |
|------|---------|
| `-XX:+UseZGC` | ZGC: sub-millisecond pause times, ideal for latency-sensitive benchmarks |
| `-XX:+ZGenerational` | Generational ZGC (Java 21+), improves throughput ~10–15% |
| `-XX:+AlwaysPreTouch` | Pre-touch all heap pages, eliminates runtime page-fault latency spikes |
| `-XX:ConcGCThreads=4` | 4 concurrent GC threads, avoids competing with benchmark threads for CPU |

> G1GC fallback if ZGC is unavailable on your JDK:
> ```bash
> -XX:+UseG1GC -XX:MaxGCPauseMillis=50 -XX:+AlwaysPreTouch
> ```

### 5.2 Comparison Benchmark

**Full run** (~2–3 hours):

```bash
# 1. Start comparison infrastructure
docker compose -f docker/docker-compose-benchmark-compare.yml up -d
sleep 30

# 2. Set SpiceDB connection (optional; skips to in-memory fallback if unset)
export SPICEDB_ENDPOINT=localhost:50051
export SPICEDB_PRESHARED_KEY=benchmark-key

# 3. Build
mvn clean package -DskipTests -pl AstralGeneral,AstralBenchmark -am -q

# 4. Run
java -Xms8G -Xmx16G \
  -XX:+UseZGC -XX:+ZGenerational -XX:+AlwaysPreTouch -XX:ConcGCThreads=4 \
  -jar evaluation/benchmark-java/target/AstralBenchmark-0.0.1-SNAPSHOT.jar \
  --spring.profiles.active=benchmark \
  --comparison-mode
```

> Note: The comparison benchmark main class is `BenchmarkRunner` (not `NativeAstralBenchmark`). When using a script, pass the correct main class.

---

## 6. Output

### 6.1 Directory Structure

```
benchmark-results/
├── native-{timestamp}/               # Native benchmark
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
│   ├── rq4a_native_decision_validity.txt
│   ├── rq4b_native_high_freq_write.csv
│   ├── rq4c_native_optimistic_lock.csv
│   └── *native_raw/                 # Raw samples (for merge + stddev)
│
├── comparison-{timestamp}/           # Multi-system comparison
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

### 6.2 Key Metrics

All CSV files contain the following columns (varies by experiment):

| Column | Meaning |
|--------|---------|
| `mean_us` | Mean latency (microseconds) |
| `p50_us` | Median latency (microseconds) |
| `p99_us` | 99th percentile latency (microseconds) |
| `sample_count` | Number of samples |
| `throughput_ops` | Throughput (operations/sec) |
| `l1_hit_rate` / `l2_hit_rate` / `l3_hit_rate` | Three-tier cache hit rates |
| `rq4a_native_decision_outcomes.csv` | One row per authorization request: phase, ALLOW/DENY/ERROR, reason, decision_source, decision_path, latency, and expected outcome |
| `rq4a_native_decision_summary.csv` | Counts and mean latency grouped by phase/outcome/reason/decision_source/decision_path |
| `rq4a_native_decision_validity.txt` | Audit of phase row conservation, actual PolicyEngine calls, erroneous ALLOW, and circuit-breaker DENY semantics |

Failure semantics are intentionally separated:

- `FLUSHDB` models a cold or empty cache, not a Redis transport outage;
- `LettuceConnectionFactory.resetConnection()` models a client connection reset, not server shutdown;
- marker protocol plus `docker stop` is the real Redis process fault and is the only mode suitable for reporting transport-fault decision samples.

`CIRCUIT_BREAKER_OPEN` is an observable DENY and must not be counted as an exception. Transport exceptions are recorded separately as `ERROR`.

### 6.3 Aggregating Multiple Runs

After 3 runs, merge raw samples using `LatencyRecorder.LatencySnapshot.merge()` to compute the mean and standard deviation:

```java
// Example: merge three runs
LatencySnapshot run1 = LatencySnapshot.load("run1/rq2_native_raw");
LatencySnapshot run2 = LatencySnapshot.load("run2/rq2_native_raw");
LatencySnapshot run3 = LatencySnapshot.load("run3/rq2_native_raw");
LatencySnapshot merged = LatencySnapshot.merge(List.of(run1, run2, run3));
// Output: mean ± stddev = merged.meanUs() ± merged.stddevUs()
```

---

## 7. Correctness Verification

### 7.1 Data Integrity Check

```bash
# Verify all CSV files contain actual data
for f in benchmark-results/native-*/*.csv; do
  lines=$(wc -l < "$f")
  if [ "$lines" -le 1 ]; then
    echo "WARNING: $f has only header, no data"
  fi
done
```

### 7.2 Cross-System Correctness Gate

The comparison benchmark includes `CrossSystemCorrectnessVerifier`, which automatically:
- Compares AstralLight vs Casbin decision outputs
- Compares AstralLight vs OPA decision outputs
- Emits ERROR if discrepancies > 5, blocking report generation

### 7.3 Benchmark Validity Audit

The native benchmark invokes `BenchmarkValidityAudit` to verify:
- Data generation-to-loading consistency
- Warm-up sufficiency
- No GC anomaly interference

---

## 8. Troubleshooting

### Q1: Docker services not starting

```bash
docker compose -f docker/docker-compose-test.yml ps
# Ensure all services show "healthy" or "running"
```

### Q2: Out of memory

```bash
# Reduce JVM heap (may affect result comparability)
export JAVA_OPTS="-Xms4G -Xmx8G -XX:+UseZGC -XX:+ZGenerational -XX:+AlwaysPreTouch"

# Or run only a smaller subset
java ... --only-rq2
```

### Q3: SpiceDB unavailable (comparison benchmark)

If `SPICEDB_ENDPOINT` is not set, SpiceDB falls back to in-memory emulation. **WARNING**: In-memory mode does NOT represent true SpiceDB semantics and is NOT suitable for publication-quality comparisons. The log will show `NOT publication-quality`.

### Q4: Port conflicts

Test environment uses offset ports (3307/6380/5673) — no conflicts. Benchmark environment uses standard ports (3306/6379/5672). If these are in use, stop local instances first.

### Q5: Compilation failure

```bash
# Verify JDK version
java -version  # Should be 21+

# Clean rebuild
mvn clean install -DskipTests -pl AstralGeneral -am -q
mvn clean package -DskipTests -pl AstralBenchmark -am -q
```

### Q6: Quick preliminary results

```bash
# Only run RQ2 main decision performance (~30 minutes)
java -Xms8G -Xmx16G \
  -XX:+UseZGC -XX:+ZGenerational -XX:+AlwaysPreTouch -XX:ConcGCThreads=4 \
  -jar evaluation/benchmark-java/target/AstralBenchmark-0.0.1-SNAPSHOT.jar \
  --spring.profiles.active=benchmark \
  --only-rq2
```

---

## 9. Fairness Statement

All comparison systems use vendor-recommended production configurations:

| System | Configuration | SDK |
|--------|---------------|-----|
| **AstralLight** | Three-tier cache + ZGC + RuleSet snapshots | Native |
| **Casbin** | Cached Mode via jCasbin 1.99.0 | jcasbin |
| **OPA** | Docker `openpolicyagent/opa:latest` | REST API |
| **Cedar** | cedar-java 4.10.0 Rust engine (JNI) | Official SDK |
| **SpiceDB** | Docker `authzed/spicedb:latest` via authzed-java 1.6.0 gRPC | Official SDK |

All systems share the same dataset (`seed=42`), with semantic consistency verified by `CrossSystemCorrectnessVerifier`.
