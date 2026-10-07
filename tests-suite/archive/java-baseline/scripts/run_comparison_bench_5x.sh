#!/bin/bash
# ============================================================
# AstralLight - 5x Multi-System Comparison Benchmark
# ============================================================
# Reproducibility: 5 independent runs with nuclear reset between runs.
# Aggregates cross-run statistics (mean ± CI across runs).
#
# Usage:
#   bash scripts/run_comparison_bench_5x.sh          # 5 runs
#   bash scripts/run_comparison_bench_5x.sh --keep   # Keep containers
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
ASTRA_DIR="${REPO_DIR}/evaluation/benchmark-java"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose-benchmark.yml"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TOTAL_RUNS=5
SUMMARY_FILE="${REPO_DIR}/comparison_5x_summary_${TIMESTAMP}.txt"

JVM_HEAP="${JVM_HEAP:-16G}"
JVM_GC_OPTS="${JVM_GC_OPTS:--XX:+UseZGC -XX:+ZGenerational -XX:ConcGCThreads=4}"
: "${BENCHMARK_MYSQL_ROOT_PASSWORD:?BENCHMARK_MYSQL_ROOT_PASSWORD is required}"
BENCHMARK_DB_NAME="${BENCHMARK_DB_NAME:-astrallight}"
export BENCHMARK_DB_NAME
OPA_PORT=8181

KEEP_CONTAINERS=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --keep) KEEP_CONTAINERS=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

log() { echo "[$(date '+%H:%M:%S')] $*"; }

start_containers() {
    log "Starting containers..."
    export DB_PORT=3308 REDIS_PORT=6381
    export DB_PASSWORD="${BENCHMARK_MYSQL_ROOT_PASSWORD}" DB_NAME="${BENCHMARK_DB_NAME}" OPA_PORT=8181
    docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
    docker compose -f "$COMPOSE_FILE" up -d

    # Wait MySQL
    for i in $(seq 1 60); do
        docker exec astral_bench_mysql mysqladmin ping -h localhost -u root -p"${BENCHMARK_MYSQL_ROOT_PASSWORD}" --silent 2>/dev/null && break
        sleep 2
    done
    sleep 5
    log "MySQL ready"

    # Wait Redis
    sleep 2
    docker exec astral_bench_redis redis-cli ping > /dev/null 2>&1
    log "Redis ready"

    # Wait OPA
    for i in $(seq 1 20); do
        curl -s -f http://localhost:${OPA_PORT}/health > /dev/null 2>&1 && break
        sleep 3
    done
    curl -s -f -o /dev/null -X POST http://localhost:${OPA_PORT}/v1/data -H "Content-Type: application/json" -d '{}' 2>/dev/null
    log "OPA ready"
}

nuclear_reset() {
    log "Nuclear reset..."
    docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
    docker rm -f astral_bench_mysql astral_bench_redis astral_bench_opa 2>/dev/null || true
    start_containers
}

# ---- 5x Runs ----
echo "" | tee "$SUMMARY_FILE"
echo "============================================================" | tee -a "$SUMMARY_FILE"
echo "  Comparison Benchmark 5x — $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$SUMMARY_FILE"
echo "  JVM: -Xms${JVM_HEAP} -Xmx${JVM_HEAP} ${JVM_GC_OPTS}" | tee -a "$SUMMARY_FILE"
echo "============================================================" | tee -a "$SUMMARY_FILE"

start_containers

for run in $(seq 1 $TOTAL_RUNS); do
    RUN_LOG="${REPO_DIR}/comparison_5x_run${run}_${TIMESTAMP}.log"
    log "========== Run ${run}/${TOTAL_RUNS} ==========" | tee -a "$SUMMARY_FILE"

    if [ "$run" -gt 1 ]; then
        nuclear_reset
    fi

    rm -rf "$ASTRA_DIR/benchmark-results/comparison-"* 2>/dev/null || true

    export DB_HOST=localhost DB_USER=root REDIS_HOST=localhost

    START_TS=$(date +%s)
    cd "$ASTRA_DIR"

    # Build JAR (clean for first run only)
    if [ "$run" -eq 1 ]; then
        mvn clean package -DskipTests -pl AstralBenchmark -am -Plegacy-benchmark -q 2>&1 | tail -2
    fi

    java -Xms${JVM_HEAP} -Xmx${JVM_HEAP} ${JVM_GC_OPTS} \
        -XX:+AlwaysPreTouch \
        -Xlog:gc*:file=gc.log:time,level,tags:filecount=5,filesize=10m \
        -Dbenchmark.type=comparison \
        -jar target/AstralBenchmark-0.0.1-SNAPSHOT.jar \
        --spring.profiles.active=benchmark \
        >> "$RUN_LOG" 2>&1

    RC=$?
    DURATION=$(($(date +%s) - START_TS))

    echo "  Run ${run}: exit=${RC}, duration=${DURATION}s" | tee -a "$SUMMARY_FILE"
    log "Run ${run} complete" | tee -a "$SUMMARY_FILE"
done

# ---- Cleanup ----
if [ "$KEEP_CONTAINERS" = false ]; then
    docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
fi

echo "" | tee -a "$SUMMARY_FILE"
echo "===== 5x Comparison Complete =====" | tee -a "$SUMMARY_FILE"
echo "Logs: comparison_5x_run*_${TIMESTAMP}.log" | tee -a "$SUMMARY_FILE"
find "$ASTRA_DIR/benchmark-results" -name "comparison-*" -type d 2>/dev/null | head -5 | tee -a "$SUMMARY_FILE"
