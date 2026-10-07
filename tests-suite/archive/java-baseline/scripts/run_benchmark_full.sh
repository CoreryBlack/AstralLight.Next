#!/bin/bash
# AstralLight NativeAstralBenchmark Full Suite (RQ1-RQ4)
# Uses benchmark database (astrallight:3308) and Redis (6381)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
cd "${REPO_DIR}/evaluation/benchmark-java"
export DB_HOST=localhost
export DB_PORT=3308
export DB_NAME="${BENCHMARK_DB_NAME:-astrallight}"
export DB_USER=root
export DB_PASSWORD="${BENCHMARK_MYSQL_ROOT_PASSWORD:?BENCHMARK_MYSQL_ROOT_PASSWORD is required}"
export REDIS_HOST=localhost
export REDIS_PORT=6381
# ZGC (Generational) — sub-millisecond pauses, ideal for latency-sensitive benchmarks
# AlwaysPreTouch avoids runtime page-fault latency spikes
export JAVA_OPTS="-Xms8G -Xmx16G -XX:+UseZGC -XX:+ZGenerational -XX:+AlwaysPreTouch -XX:ConcGCThreads=4"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${REPO_DIR}/benchmark-full-${TIMESTAMP}.log"

echo "[$(date)] Starting full benchmark suite (RQ1-RQ4)" | tee -a ${LOG_FILE}
echo "[$(date)] DB: ${DB_HOST}:${DB_PORT}/${DB_NAME}, Redis: ${REDIS_HOST}:${REDIS_PORT}" | tee -a ${LOG_FILE}
echo "[$(date)] JVM: ${JAVA_OPTS}" | tee -a ${LOG_FILE}

java ${JAVA_OPTS} -jar target/AstralBenchmark-0.0.1-SNAPSHOT.jar \
  --spring.profiles.active=benchmark \
  2>&1 | tee -a ${LOG_FILE}

EXIT_CODE=${PIPESTATUS[0]}
echo "[$(date)] Benchmark suite completed with exit code: ${EXIT_CODE}" | tee -a ${LOG_FILE}
exit ${EXIT_CODE}
