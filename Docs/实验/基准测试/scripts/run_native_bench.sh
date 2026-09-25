#!/bin/bash
# ============================================================
# AstralLight - Native Benchmark Runner
# ============================================================
# Prerequisites:
#   - Docker & docker-compose installed
#   - AstralBenchmark JAR built (mvn clean package -DskipTests)
#   - SSH key for git pull (if syncing code)
#
# Usage:
#   ./run_native_bench.sh          # Full run with fresh DB
#   ./run_native_bench.sh --keep   # Keep containers after run
# ============================================================
set -e

KEEP_CONTAINERS=false
if [[ "$1" == "--keep" ]]; then
  KEEP_CONTAINERS=true
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
PROJECT_DIR="${REPO_DIR}/evaluation/benchmark-java"
DOCKER_DIR="$SCRIPT_DIR"
COMPOSE_FILE=$DOCKER_DIR/docker-compose-benchmark.yml
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG="${REPO_DIR}/benchmark-native-${TIMESTAMP}.log"

echo "[$(date)] === NativeAstralBenchmark (RQ1-RQ4) ===" | tee $LOG
echo "[$(date)] Phase 1: Clean up old benchmark environment" | tee -a $LOG

# --- Phase 1: Clean up old containers and volumes ---
# Stop and remove old benchmark containers + volumes (ensures fresh DB schema)
docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true

# Also remove any dangling benchmark containers by name
docker rm -f astral_bench_mysql astral_bench_redis 2>/dev/null || true

# Keep only latest 3 result archives; remove older ones
cd $PROJECT_DIR/benchmark-results 2>/dev/null && ls -dt native-* 2>/dev/null | tail -n +4 | xargs rm -rf 2>/dev/null || true
cd $PROJECT_DIR

# Clean up old benchmark logs (>7 days)
find "${REPO_DIR}" -maxdepth 1 -name 'benchmark-native-*.log' -mtime +7 -delete 2>/dev/null || true

echo "[$(date)] Phase 2: Start infrastructure via docker-compose" | tee -a $LOG

# --- Phase 2: Start infrastructure ---
# Use non-default ports to avoid conflicts with production containers
: "${BENCHMARK_MYSQL_ROOT_PASSWORD:?BENCHMARK_MYSQL_ROOT_PASSWORD is required}"
export DB_PORT=3308
export REDIS_PORT=6381
export DB_PASSWORD="${BENCHMARK_MYSQL_ROOT_PASSWORD}"
export DB_NAME="${BENCHMARK_DB_NAME:-astrallight}"
export BENCHMARK_DB_NAME="${DB_NAME}"

docker compose -f "$COMPOSE_FILE" up -d

echo "[$(date)] Phase 3: Wait for MySQL to be healthy" | tee -a $LOG

# --- Phase 3: Wait for MySQL healthy ---
MAX_WAIT=120
WAITED=0
while ! docker exec astral_bench_mysql mysqladmin ping -h localhost -u root -p"${BENCHMARK_MYSQL_ROOT_PASSWORD}" --silent 2>/dev/null; do
  sleep 2
  WAITED=$((WAITED + 2))
  if [ $WAITED -ge $MAX_WAIT ]; then
    echo "[$(date)] ERROR: MySQL not ready after ${MAX_WAIT}s, aborting" | tee -a $LOG
    docker compose -f "$COMPOSE_FILE" logs mysql
    exit 1
  fi
done
echo "[$(date)] MySQL ready after ${WAITED}s" | tee -a $LOG

# Wait a bit more for init scripts to complete
sleep 5

# Verify schema was loaded
TABLE_COUNT=$(docker exec astral_bench_mysql mysql -u root -p"${BENCHMARK_MYSQL_ROOT_PASSWORD}" "${DB_NAME}" -sN -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${DB_NAME}'" 2>/dev/null)
echo "[$(date)] Schema loaded: ${TABLE_COUNT} tables in astrallight database" | tee -a $LOG

if [ "$TABLE_COUNT" -lt 10 ]; then
  echo "[$(date)] ERROR: Too few tables (${TABLE_COUNT}), schema init may have failed" | tee -a $LOG
  docker compose -f "$COMPOSE_FILE" logs mysql
  exit 1
fi

# Wait for Redis
sleep 2
docker exec astral_bench_redis redis-cli ping > /dev/null 2>&1
echo "[$(date)] Redis ready" | tee -a $LOG

echo "[$(date)] Phase 4: Run NativeAstralBenchmark" | tee -a $LOG

# --- Phase 4: Run benchmark ---
cd $PROJECT_DIR

export DB_HOST=localhost
export DB_USER=root
export REDIS_HOST=localhost

echo "[$(date)] DB: localhost:${DB_PORT}/astrallight  Redis: localhost:${REDIS_PORT}" | tee -a $LOG
echo "[$(date)] JVM: ZGC Generational -Xms16G -Xmx16G" | tee -a $LOG

java -Xms16G -Xmx16G -XX:+UseZGC -XX:+ZGenerational -XX:+AlwaysPreTouch -XX:ConcGCThreads=4 \
  -jar target/AstralBenchmark-0.0.1-SNAPSHOT.jar \
  --spring.profiles.active=benchmark >> $LOG 2>&1
RC=$?

echo "[$(date)] Benchmark exit code: $RC" | tee -a $LOG

# --- Archive log into results directory ---
RESULT_DIR=$(ls -dt $PROJECT_DIR/benchmark-results/native-* 2>/dev/null | head -1)
if [ -n "$RESULT_DIR" ] && [ -f "$LOG" ]; then
  cp "$LOG" "$RESULT_DIR/benchmark.log"
  echo "[$(date)] Log archived to $RESULT_DIR/benchmark.log" | tee -a $LOG
fi

# --- Phase 5: Cleanup ---
if [ "$KEEP_CONTAINERS" = false ]; then
  echo "[$(date)] Phase 5: Stopping containers" | tee -a $LOG
  docker compose -f "$COMPOSE_FILE" down -v
  echo "[$(date)] Containers and volumes removed" | tee -a $LOG
else
  echo "[$(date)] Phase 5: Keeping containers (--keep flag)" | tee -a $LOG
fi

echo "[$(date)] === Done ===" | tee -a $LOG
exit $RC
