#!/bin/bash
# =============================================================================
# AstralLight Benchmark + 5系统对比测试
# 前置条件: 单元/集成测试已通过，MySQL/Redis/OPA 容器已运行
# 用法:
#   bash scripts/run-benchmark.sh
#   bash scripts/run-benchmark.sh --only-rq1          # 仅跑 RQ1
#   bash scripts/run-benchmark.sh --only-rq2          # 仅跑 RQ2+RQ-A/B+L3
#   bash scripts/run-benchmark.sh --only-rq3          # 仅跑 RQ3
#   bash scripts/run-benchmark.sh --only-layer4       # 仅跑 Layer4
#   bash scripts/run-benchmark.sh --only-probe        # 仅跑 Probe
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
PROJECT_DIR="${REPO_DIR}/evaluation/benchmark-java"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RESULTS_DIR="$PROJECT_DIR/test-results/benchmark-$TIMESTAMP"
PHASE_LOG="$RESULTS_DIR/phases.log"

ONLY_RQ1=false
ONLY_RQ2=false
ONLY_RQ3=false
ONLY_LAYER4=false
ONLY_PROBE=false

for arg in "$@"; do
    case "$arg" in
        --only-rq1)    ONLY_RQ1=true ;;
        --only-rq2)    ONLY_RQ2=true ;;
        --only-rq3)    ONLY_RQ3=true ;;
        --only-layer4) ONLY_LAYER4=true ;;
        --only-probe)  ONLY_PROBE=true ;;
    esac
done

HAS_ONLY=false
if [ "$ONLY_RQ1" = true ] || [ "$ONLY_RQ2" = true ] || [ "$ONLY_RQ3" = true ] || [ "$ONLY_LAYER4" = true ] || [ "$ONLY_PROBE" = true ]; then
    HAS_ONLY=true
fi

mkdir -p "$RESULTS_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$PHASE_LOG"
}

phase() {
    echo "" | tee -a "$PHASE_LOG"
    echo "================================================================" | tee -a "$PHASE_LOG"
    log ">>> PHASE $1: $2 <<<"
    echo "================================================================" | tee -a "$PHASE_LOG"
}

summary() {
    local phase_name=$1
    local log_file=$2
    local pass_count
    local fail_count

    pass_count=$(grep -c "Tests run:.*Failures: 0, Errors: 0" "$log_file" 2>/dev/null || echo 0)
    fail_count=$(grep -c "FAILURE!" "$log_file" 2>/dev/null || echo 0)

    echo "  ┌─────────────────────────────────────────────────────" | tee -a "$PHASE_LOG"
    echo "  │ $phase_name" | tee -a "$PHASE_LOG"
    echo "  │   Passed classes: $pass_count" | tee -a "$PHASE_LOG"
    echo "  │   Failures:       $fail_count" | tee -a "$PHASE_LOG"
    if [ -f "$log_file" ]; then
        echo "  │   Log:            $log_file" | tee -a "$PHASE_LOG"
    fi
    echo "  └─────────────────────────────────────────────────────" | tee -a "$PHASE_LOG"
}

run_benchmark() {
    local log_file=$1
    shift
    local timeout_seconds=${1:-600}
    shift 2>/dev/null || true

    log "  Starting benchmark (timeout=${timeout_seconds}s)..."

    timeout "$timeout_seconds" $BENCHMARK_CMD "$@" 2>&1 | tee "$log_file" || {
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            log "  WARNING: Benchmark timed out after ${timeout_seconds}s"
        else
            log "  Benchmark exited with code $exit_code"
        fi
    }

    pkill -f "AstralBenchmark" 2>/dev/null || true
    sleep 3
}

cd "$PROJECT_DIR"

# =============================================================================
# Phase 0: Environment check
# =============================================================================
phase "0" "BENCHMARK ENVIRONMENT CHECK"

echo "  Project: $PROJECT_DIR" | tee -a "$PHASE_LOG"
echo "  Results: $RESULTS_DIR" | tee -a "$PHASE_LOG"

if ! docker info >/dev/null 2>&1; then
    echo "  ERROR: Docker not available." | tee -a "$PHASE_LOG"
    exit 1
fi
echo "  [OK] Docker is available" | tee -a "$PHASE_LOG"

for svc in "astral_bench_mysql:3308" "astral_bench_redis:6381" "astral_bench_opa:8181"; do
    name="${svc%%:*}"
    port="${svc##*:}"
    if docker ps --format '{{.Names}}' | grep -q "^$name$"; then
        echo "  [OK] $name (port $port)" | tee -a "$PHASE_LOG"
    else
        echo "  [ERROR] $name is NOT running — benchmark requires it" | tee -a "$PHASE_LOG"
        exit 1
    fi
done

# =============================================================================
# Phase 1: Package Benchmark JAR
# =============================================================================
phase "1" "PACKAGE BENCHMARK JAR"

mvn package -DskipTests -pl AstralBenchmark -am -q 2>&1 | tee "$RESULTS_DIR/package.log"
if [ ${PIPESTATUS[0]} -ne 0 ]; then
    echo "  ERROR: Benchmark packaging failed" | tee -a "$PHASE_LOG"
    exit 1
fi
echo "  [OK] Benchmark JAR packaged" | tee -a "$PHASE_LOG"

BENCHMARK_JAR=$(ls -t target/AstralBenchmark-*.jar 2>/dev/null | head -1)
if [ -z "$BENCHMARK_JAR" ]; then
    echo "  ERROR: No benchmark JAR found in target/" | tee -a "$PHASE_LOG"
    exit 1
fi
echo "  JAR: $BENCHMARK_JAR" | tee -a "$PHASE_LOG"

export DB_HOST=localhost
export DB_PORT=3308
export DB_NAME="${BENCHMARK_DB_NAME:-astrallight}"
export DB_USER=root
export DB_PASSWORD="${BENCHMARK_MYSQL_ROOT_PASSWORD:?BENCHMARK_MYSQL_ROOT_PASSWORD is required}"
export REDIS_HOST=localhost
export REDIS_PORT=6381

BENCHMARK_CMD="java -Xmx6g -Xms2g -jar $BENCHMARK_JAR --spring.profiles.active=benchmark"

# =============================================================================
# Phase 2a: RQ1 — Space Efficiency
# =============================================================================
if [ "$HAS_ONLY" = false ] || [ "$ONLY_RQ1" = true ]; then
    phase "2a" "BENCHMARK — RQ1: Space Efficiency (vs NaiveFullCopy)"

    run_benchmark "$RESULTS_DIR/benchmark-rq1.log" 900 --skip-rq2 --skip-rq3 --skip-industrial --skip-layer4

    summary "RQ1: Space Efficiency" "$RESULTS_DIR/benchmark-rq1.log"
fi

# =============================================================================
# Phase 2b: RQ2 — Decision Performance + RQ-A/B + L3 (5-system comparison)
# =============================================================================
if [ "$HAS_ONLY" = false ] || [ "$ONLY_RQ2" = true ]; then
    phase "2b" "BENCHMARK — RQ2: Decision Performance + RQ-A/B + L3 (5-system comparison)"

    run_benchmark "$RESULTS_DIR/benchmark-rq2.log" 7200 --skip-rq1 --skip-rq3 --skip-industrial --skip-layer4 --skip-rq2-gradients --skip-rq-a

    summary "RQ2 + RQ-A/B + L3" "$RESULTS_DIR/benchmark-rq2.log"
fi

# =============================================================================
# Phase 2c: RQ3 — Incremental Compile
# =============================================================================
if [ "$HAS_ONLY" = false ] || [ "$ONLY_RQ3" = true ]; then
    phase "2c" "BENCHMARK — RQ3: Incremental Compile"

    run_benchmark "$RESULTS_DIR/benchmark-rq3.log" 1200 --skip-rq1 --skip-rq2 --skip-industrial --skip-layer4

    summary "RQ3: Incremental Compile" "$RESULTS_DIR/benchmark-rq3.log"
fi

# =============================================================================
# Phase 2d: Layer 4 — Engineering Capability
# =============================================================================
if [ "$HAS_ONLY" = false ] || [ "$ONLY_LAYER4" = true ]; then
    phase "2d" "BENCHMARK — Layer 4: Engineering Capability"

    run_benchmark "$RESULTS_DIR/benchmark-layer4.log" 1800 --skip-rq1 --skip-rq2 --skip-rq3 --skip-industrial

    summary "Layer 4: Engineering" "$RESULTS_DIR/benchmark-layer4.log"
fi

# =============================================================================
# Phase 2e: Industrial — Production Data Collection
# =============================================================================
if [ "$HAS_ONLY" = false ] || [ "$ONLY_PROBE" = true ]; then
    phase "2e" "BENCHMARK — Probe: Production Data Collection"

    run_benchmark "$RESULTS_DIR/benchmark-industrial.log" --skip-rq1 --skip-rq2 --skip-rq3 --skip-layer4

    summary "Production Probe" "$RESULTS_DIR/benchmark-industrial.log"
fi

# =============================================================================
# Phase 3: Collect benchmark output files
# =============================================================================
phase "3" "COLLECT BENCHMARK OUTPUTS"

if [ -d "benchmark-results" ]; then
    LATEST_BENCHMARK_DIR=$(ls -td benchmark-results/*/ 2>/dev/null | head -1)
    if [ -n "$LATEST_BENCHMARK_DIR" ]; then
        cp -r "$LATEST_BENCHMARK_DIR" "$RESULTS_DIR/benchmark-outputs/"
        echo "  Benchmark outputs: $RESULTS_DIR/benchmark-outputs/" | tee -a "$PHASE_LOG"
        ls -la "$RESULTS_DIR/benchmark-outputs/" | tee -a "$PHASE_LOG"
    fi
fi

# =============================================================================
# Final Summary
# =============================================================================
phase "FINAL" "BENCHMARK COMPLETE"

sleep 2

echo "" | tee -a "$PHASE_LOG"
echo "╔═══════════════════════════════════════════════════════════╗" | tee -a "$PHASE_LOG"
echo "║              AstralLight — BENCHMARK COMPLETE            ║" | tee -a "$PHASE_LOG"
echo "╠═══════════════════════════════════════════════════════════╣" | tee -a "$PHASE_LOG"
echo "║  Results directory:" | tee -a "$PHASE_LOG"
echo "║    $RESULTS_DIR" | tee -a "$PHASE_LOG"
echo "║" | tee -a "$PHASE_LOG"
echo "║  Benchmark logs:" | tee -a "$PHASE_LOG"
for f in "$RESULTS_DIR"/benchmark-*.log; do
    [ -f "$f" ] && echo "║    - $(basename "$f")" | tee -a "$PHASE_LOG"
done

if [ -d "$RESULTS_DIR/benchmark-outputs/" ]; then
    echo "║" | tee -a "$PHASE_LOG"
    echo "║  Benchmark output files:" | tee -a "$PHASE_LOG"
    for f in "$RESULTS_DIR/benchmark-outputs/"*; do
        [ -f "$f" ] && echo "║    - $(basename "$f")" | tee -a "$PHASE_LOG"
    done
fi

echo "╚═══════════════════════════════════════════════════════════╝" | tee -a "$PHASE_LOG"
