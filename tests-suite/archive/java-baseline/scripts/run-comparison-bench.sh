#!/bin/bash
# ============================================================
# AstralLight - Multi-System Comparison Benchmark
# ============================================================
# Compares AstralLight against Casbin, OPA, Cedar, SpiceDB
# with vendor-recommended production configurations.
#
# Prerequisites:
#   - Docker & docker-compose installed
#   - SSH key for git pull
#
# Usage:
#   ./run-comparison-bench.sh          # Full comparison
#   ./run-comparison-bench.sh --keep   # Keep containers after run
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
LOG="${REPO_DIR}/comparison-bench-${TIMESTAMP}.log"

echo "[$(date)] === Multi-System Comparison Benchmark (AL vs Casbin vs OPA vs Cedar vs SpiceDB) ===" | tee $LOG
echo "[$(date)] Phase 1: Clean up old benchmark environment" | tee -a $LOG

docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
docker rm -f astral_bench_mysql astral_bench_redis astral_bench_opa 2>/dev/null || true

# Keep only latest 3 result archives
cd $PROJECT_DIR/benchmark-results 2>/dev/null && ls -dt comparison-* 2>/dev/null | tail -n +4 | xargs rm -rf 2>/dev/null || true
cd $PROJECT_DIR

find "${REPO_DIR}" -maxdepth 1 -name 'comparison-bench-*.log' -mtime +7 -delete 2>/dev/null || true

echo "[$(date)] Phase 2: Start infrastructure (MySQL, Redis, OPA)" | tee -a $LOG

export DB_PORT=3308
export REDIS_PORT=6381
export OPA_PORT=8181
export DB_PASSWORD="${BENCHMARK_MYSQL_ROOT_PASSWORD:?BENCHMARK_MYSQL_ROOT_PASSWORD is required}"
export DB_NAME="${BENCHMARK_DB_NAME:-astrallight}"
export BENCHMARK_DB_NAME="${DB_NAME}"

docker compose -f "$COMPOSE_FILE" up -d
echo "[$(date)] All containers starting..." | tee -a $LOG

echo "[$(date)] Phase 3: Wait for services" | tee -a $LOG

# Wait for MySQL
MAX_WAIT=120
WAITED=0
while ! docker exec astral_bench_mysql mysqladmin ping -h localhost -u root -p"${BENCHMARK_MYSQL_ROOT_PASSWORD}" --silent 2>/dev/null; do
  sleep 2
  WAITED=$((WAITED + 2))
  if [ $WAITED -ge $MAX_WAIT ]; then
    echo "[$(date)] ERROR: MySQL not ready" | tee -a $LOG
    exit 1
  fi
done
echo "[$(date)] MySQL ready" | tee -a $LOG

sleep 5
TABLE_COUNT=$(docker exec astral_bench_mysql mysql -u root -p"${BENCHMARK_MYSQL_ROOT_PASSWORD}" "${DB_NAME}" -sN -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${DB_NAME}'" 2>/dev/null)
echo "[$(date)] Schema loaded: ${TABLE_COUNT} tables" | tee -a $LOG

# Wait for Redis
sleep 2
docker exec astral_bench_redis redis-cli ping > /dev/null 2>&1
echo "[$(date)] Redis ready" | tee -a $LOG

# Wait for OPA
WAITED=0
while ! curl -s -f http://localhost:${OPA_PORT}/health > /dev/null 2>&1; do
  sleep 3
  WAITED=$((WAITED + 3))
  if [ $WAITED -ge 60 ]; then
    echo "[$(date)] ERROR: OPA not ready after ${WAITED}s, aborting" | tee -a $LOG
    exit 1
  fi
done

# Verify OPA can serve policy queries (not just health ping)
if ! curl -s -f -o /dev/null -X POST http://localhost:${OPA_PORT}/v1/data -H "Content-Type: application/json" -d '{}' 2>/dev/null; then
  echo "[$(date)] ERROR: OPA health passed but /v1/data unreachable" | tee -a $LOG
  exit 1
fi
echo "[$(date)] OPA ready and serving" | tee -a $LOG

echo "[$(date)] Phase 4: Build BenchmarkRunner JAR (legacy-benchmark profile)" | tee -a $LOG

cd $PROJECT_DIR
mvn clean package -DskipTests -pl AstralBenchmark -am -Plegacy-benchmark -q 2>&1 | tee -a $LOG
echo "[$(date)] JAR built" | tee -a $LOG

echo "[$(date)] Phase 5: Run Multi-System Comparison Benchmark" | tee -a $LOG

export DB_HOST=localhost
export DB_USER=root
export REDIS_HOST=localhost

echo "[$(date)] JVM: ${JVM_GC:-ZGC Generational} -Xms${JVM_HEAP:-16G} -Xmx${JVM_HEAP:-16G}" | tee -a $LOG

java -Xms${JVM_HEAP:-16G} -Xmx${JVM_HEAP:-16G} \
  ${JVM_GC_OPTS:--XX:+UseZGC -XX:+ZGenerational -XX:ConcGCThreads=${JVM_GC_THREADS:-4}} \
  -XX:+AlwaysPreTouch \
  -Xlog:gc*:file=gc.log:time,level,tags:filecount=5,filesize=10m \
  -Dbenchmark.type=comparison \
  -jar target/AstralBenchmark-0.0.1-SNAPSHOT.jar \
  --spring.profiles.active=benchmark >> $LOG 2>&1
RC=$?

echo "[$(date)] Benchmark exit code: $RC" | tee -a $LOG

RESULT_DIR=$(ls -dt $PROJECT_DIR/benchmark-results/comparison-* 2>/dev/null | head -1)
if [ -n "$RESULT_DIR" ] && [ -f "$LOG" ]; then
  cp "$LOG" "$RESULT_DIR/benchmark.log"
  echo "[$(date)] Log archived to $RESULT_DIR/benchmark.log" | tee -a $LOG
fi

if [ "$KEEP_CONTAINERS" = false ]; then
  echo "[$(date)] Phase 6: Stopping containers" | tee -a $LOG
  cd $DOCKER_DIR
  docker compose -f "$COMPOSE_FILE" down -v
  echo "[$(date)] Containers and volumes removed" | tee -a $LOG
else
  echo "[$(date)] Phase 6: Keeping containers (--keep flag)" | tee -a $LOG
fi

echo "[$(date)] === Done ===" | tee -a $LOG
exit $RC
