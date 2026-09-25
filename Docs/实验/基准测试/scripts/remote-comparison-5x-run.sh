#!/usr/bin/env bash
# ============================================================================
# 5× 重复对比基准运行脚本（自包含版）
# ============================================================================
# 说明：
#   自动启动 MySQL/Redis/OPA Docker 容器，等待健康后运行 5 次对比基准测试。
#   所有文件均使用 SCRIPT_DIR 相对路径，不依赖外部路径。
#
# 用法：
#   chmod +x Docs/实验/基准测试/scripts/comparison-5x-run.sh
#   bash Docs/实验/基准测试/scripts/comparison-5x-run.sh                # 完整对比（5x）
#   bash Docs/实验/基准测试/scripts/comparison-5x-run.sh --only-rq2      # 仅 RQ-Compare-2（规则复杂度+卡数敏感性）
#   bash Docs/实验/基准测试/scripts/comparison-5x-run.sh --only-appendix # 仅 Cedar appendix
#   bash Docs/实验/基准测试/scripts/comparison-5x-run.sh --repeats 3     # 重复次数（默认 5）
#   bash Docs/实验/基准测试/scripts/comparison-5x-run.sh --dry-run       # 仅检查环境并打印命令
# 说明：
#   --only-rq2 / --only-appendix 会传 -Dbenchmark.rq2.only=true /
#   -Dbenchmark.appendix.only=true 给 jar；依赖 BenchmarkRunner 已支持对应开关。
# ============================================================================

set -o errexit
set -o nounset
# 不要 set -o pipefail，允许单次运行失败后继续

# ── 参数解析 ────────────────────────────────────────────────────────────
MODE="full"      # full | rq2 | appendix
REPEATS=5
DRY_RUN=false
for arg in "$@"; do
    case "$arg" in
        --only-rq2)      MODE="rq2" ;;
        --only-appendix) MODE="appendix" ;;
        --dry-run)       DRY_RUN=true ;;
        --repeats=*)     REPEATS="${arg#--repeats=}" ;;
        --repeats)       echo "[ERROR] --repeats 需要一个数值参数，如 --repeats=3"; exit 1 ;;
        *)               echo "[WARN] 忽略未知参数: $arg" ;;
    esac
done

# ── 路径（全部基于脚本自身位置）────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
PROJECT_DIR="${REPO_DIR}/evaluation/benchmark-java"
JAR="${PROJECT_DIR}/target/AstralBenchmark-0.0.1-SNAPSHOT.jar"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose-benchmark.yml"
BASE_DIR="${PROJECT_DIR}/benchmark-5x"
if [[ "$MODE" != "full" ]]; then
    BASE_DIR="${BASE_DIR}_${MODE}"
fi
JAVA_OPTS="-Xms16G -Xmx16G -XX:+UseZGC -XX:+ZGenerational -XX:ConcGCThreads=4 -XX:+AlwaysPreTouch"

# 依据模式追加 benchmark 开关
JAVA_BENCH_FLAGS="-Dbenchmark.type=comparison"
if [[ "$MODE" == "rq2" ]]; then
    JAVA_BENCH_FLAGS="$JAVA_BENCH_FLAGS -Dbenchmark.rq2.only=true"
elif [[ "$MODE" == "appendix" ]]; then
    JAVA_BENCH_FLAGS="$JAVA_BENCH_FLAGS -Dbenchmark.appendix.only=true"
fi

# ── 环境变量 ───────────────────────────────────────────────────────────
: "${BENCHMARK_MYSQL_ROOT_PASSWORD:?BENCHMARK_MYSQL_ROOT_PASSWORD is required}"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-3308}"
DB_NAME="${DB_NAME:-${BENCHMARK_DB_NAME:-astrallight}}"
DB_USER="${DB_USER:-root}"
DB_PASSWORD="${DB_PASSWORD:-${BENCHMARK_MYSQL_ROOT_PASSWORD}}"
REDIS_HOST="${REDIS_HOST:-127.0.0.1}"
REDIS_PORT="${REDIS_PORT:-6381}"
REDIS_PASSWORD="${REDIS_PASSWORD:-}"

# ── 前置检查 ─────────────────────────────────────────────────────────
if [[ ! -f "$JAR" ]]; then
    echo "[FATAL] JAR 未找到: $JAR"
    echo "        请先执行: mvn -pl AstralBenchmark -am -DskipTests -Plegacy-benchmark package"
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "[FATAL] docker 未安装或不可用"
    exit 1
fi

if [[ ! -f "$COMPOSE_FILE" ]]; then
    echo "[FATAL] docker-compose 文件未找到: $COMPOSE_FILE"
    echo "        请确保 Docs/实验/基准测试/scripts/docker-compose-benchmark.yml 存在"
    exit 1
fi

echo "============================================"
echo " 5× 重复对比基准运行"
echo " 主机:      $(hostname)"
echo " 日期:      $(date '+%Y-%m-%d %H:%M:%S')"
echo " JAR:       $JAR"
echo " Compose:   $COMPOSE_FILE"
echo " 模式:      $MODE (flags: $JAVA_BENCH_FLAGS)"
echo " 重复次数:  $REPEATS"
echo " 输出目录:  $BASE_DIR"
echo " DB:        ${DB_HOST}:${DB_PORT}/${DB_NAME}"
echo " Redis:     ${REDIS_HOST}:${REDIS_PORT}"
echo "============================================"

mkdir -p "$BASE_DIR"

# ── Dry-run：仅验证环境并打印将执行的命令 ─────────────────────────────
if [[ "$DRY_RUN" == "true" ]]; then
    echo ""
    echo "=== [DRY-RUN] 环境检查通过，将执行的基准命令（${REPEATS} 次）==="
    echo "  env DB_HOST=$DB_HOST DB_PORT=$DB_PORT DB_NAME=$DB_NAME DB_USER=$DB_USER \\"
    echo "      REDIS_HOST=$REDIS_HOST REDIS_PORT=$REDIS_PORT \\"
    echo "      java $JAVA_OPTS $JAVA_BENCH_FLAGS \\"
    echo "      -Dspring.output.ansi.enabled=NEVER -jar $JAR --spring.profiles.active=benchmark"
    echo "  → 输出目录: $BASE_DIR"
    echo "  [DRY-RUN] 未启动任何容器或 JVM，退出。"
    exit 0
fi

# ── 0/6: 启动并等待基准基础设施 ──────────────────────────────────────
echo ""
echo "=== 0/6: 启动并等待基准基础设施 ==="
docker compose -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null || true
docker compose -f "$COMPOSE_FILE" up -d

echo "  Waiting for MySQL/Redis/OPA health..."
MAX_WAIT=180
WAITED=0
while true; do
    MYSQL_OK=$(docker inspect astral_bench_mysql --format='{{.State.Health.Status}}' 2>/dev/null | tr -d '\n' || echo "starting")
    REDIS_OK=$(docker inspect astral_bench_redis --format='{{.State.Health.Status}}' 2>/dev/null | tr -d '\n' || echo "starting")
    # OPA distroless 镜像无 healthcheck，检查容器是否 running
    OPA_STATE=$(docker inspect astral_bench_opa --format='{{.State.Status}}' 2>/dev/null | tr -d '\n' || echo "missing")
    OPA_HC=$(docker inspect astral_bench_opa --format='{{.State.Health.Status}}' 2>/dev/null | tr -d '\n' || echo "")

    MYSQL_READY="no"; REDIS_READY="no"; OPA_READY="no"
    [[ "$MYSQL_OK" == "healthy" ]] && MYSQL_READY="yes"
    [[ "$REDIS_OK" == "healthy" ]] && REDIS_READY="yes"
    # OPA: healthy OR (no healthcheck AND running)
    if [[ "$OPA_HC" == "healthy" ]]; then
        OPA_READY="yes"
    elif [[ -z "$OPA_HC" && "$OPA_STATE" == "running" ]]; then
        OPA_READY="yes"
    fi

    if [[ "$MYSQL_READY" == "yes" && "$REDIS_READY" == "yes" && "$OPA_READY" == "yes" ]]; then
        break
    fi
    sleep 3
    WAITED=$((WAITED + 3))
    if [[ $WAITED -ge $MAX_WAIT ]]; then
        echo "[FATAL] 基础设施在 ${MAX_WAIT}s 内未就绪"
        echo "  MySQL: ${MYSQL_OK}"
        echo "  Redis: ${REDIS_OK}"
        echo "  OPA:   hc=${OPA_HC} state=${OPA_STATE}"
        docker compose -f "$COMPOSE_FILE" ps
        exit 1
    fi
done
echo "  Infrastructure ready after ${WAITED}s"

# 确认 OPA HTTP 可达
for i in $(seq 1 10); do
    if curl -sf http://localhost:8181/health >/dev/null 2>&1; then
        echo "  OPA confirmed serving"
        break
    fi
    sleep 1
done

SCHEMA_FILE="${SCRIPT_DIR}/full_schema_v4.sql"
# 等待 MySQL 完全就绪（healthcheck 通过后可能还有短暂窗口）
sleep 5
TABLE_COUNT=$(docker exec astral_bench_mysql mysql -u root -p"${BENCHMARK_MYSQL_ROOT_PASSWORD}" -sN "${DB_NAME}" -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${DB_NAME}'" 2>/dev/null | tr -d '[:space:]' || echo "0")
if [[ "$TABLE_COUNT" -lt 10 ]]; then
    echo "  Schema empty (${TABLE_COUNT} tables), importing from ${SCHEMA_FILE}..."
    if [[ ! -f "$SCHEMA_FILE" ]]; then
        echo "[FATAL] Schema file not found: $SCHEMA_FILE"
        exit 1
    fi
    bash "${SCRIPT_DIR}/import-schema.sh" "$SCHEMA_FILE" "${DB_NAME}"
    sleep 2
    TABLE_COUNT=$(docker exec astral_bench_mysql mysql -u root -p"${BENCHMARK_MYSQL_ROOT_PASSWORD}" -sN "${DB_NAME}" -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${DB_NAME}'" 2>/dev/null | tr -d '[:space:]' || echo "0")
    echo "  Final table count: ${TABLE_COUNT}"
    if [[ "$TABLE_COUNT" -lt 10 ]]; then
        echo "[FATAL] Schema import failed — too few tables (${TABLE_COUNT})"
        exit 1
    fi
else
    echo "  Schema already loaded: ${TABLE_COUNT} tables"
fi

# ── 1/6: 采集硬件快照 ──────────────────────────────────────────────
echo ""
echo "=== 1/6: 采集硬件快照 ==="
HARDWARE_LOG="${BASE_DIR}/hardware-snapshot.txt"
{
    echo "=== Hardware Snapshot ==="
    echo "Date:       $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Hostname:   $(hostname)"
    echo "CPU:        $(lscpu | grep 'Model name' | head -1 | sed 's/Model name:\s*//')"
    echo "Cores:      $(nproc)"
    echo "Memory:     $(free -h | grep Mem | awk '{print $2}')"
    echo "Kernel:     $(uname -r)"
    echo "Java:       $(java -version 2>&1 | head -1)"
    echo ""
    echo "--- Docker Containers ---"
    docker ps --filter name='astral_bench*' --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || echo "(docker not available)"
    echo ""
    echo "--- CPU Info ---"
    cat /proc/cpuinfo | grep -E 'model name|MHz|cache size' | sort -u 2>/dev/null || echo "(not available)"
} 2>&1 | tee "$HARDWARE_LOG"

# ── 2/6: 运行 5 次基准测试 ─────────────────────────────────────────
echo ""
echo "=== 2/6: 运行 ${REPEATS} 次基准测试 ==="

SUMMARY_LOG="${BASE_DIR}/summary.csv"
echo "run,start_time,end_time,elapsed_min,status,single_thread_100_mean,single_thread_1000_mean,single_thread_10000_mean,concurrent_100_tps,concurrent_1000_tps,concurrent_10000_tps,cold_100_mean" > "$SUMMARY_LOG"

for i in $(seq 1 $REPEATS); do
    RUN_DIR="${BASE_DIR}/run-${i}"
    RUN_LOG="${RUN_DIR}/benchmark.log"
    EPOCH=$(date '+%Y%m%d_%H%M%S')
    START_TS=$(date '+%Y-%m-%d %H:%M:%S')
    START_EPOCH=$(date +%s)

    echo ""
    echo "  ── Run ${i}/${REPEATS} (${EPOCH}) ──"
    echo "      Output: ${RUN_DIR}/"
    mkdir -p "$RUN_DIR"

    # 启动基准测试
    set +o errexit
    env DB_HOST="$DB_HOST" DB_PORT="$DB_PORT" DB_NAME="$DB_NAME" \
        DB_USER="$DB_USER" DB_PASSWORD="$DB_PASSWORD" \
        REDIS_HOST="$REDIS_HOST" REDIS_PORT="$REDIS_PORT" REDIS_PASSWORD="$REDIS_PASSWORD" \
        java $JAVA_OPTS \
        $JAVA_BENCH_FLAGS \
        -Dspring.output.ansi.enabled=NEVER \
        -jar "$JAR" \
        --spring.profiles.active=benchmark \
        > "$RUN_LOG" 2>&1
    EXIT_CODE=$?
    set -o errexit

    END_TS=$(date '+%Y-%m-%d %H:%M:%S')
    END_EPOCH=$(date +%s)
    ELAPSED_MIN=$(( (END_EPOCH - START_EPOCH) / 60 ))

    # 判断状态（注意：Exception 可能出现在非关键路径的 WARN 中，优先检查成功标志）
    if grep -q "comparison benchmark complete" "$RUN_LOG" 2>/dev/null; then
        STATUS="COMPLETE"
    elif [[ $EXIT_CODE -ne 0 ]]; then
        STATUS="CRASH"
    elif grep -q "CORRECTNESS GATE FAILED" "$RUN_LOG" 2>/dev/null; then
        STATUS="GATE_BLOCKED"
    else
        STATUS="UNKNOWN"
    fi

    echo "      Exit=$EXIT_CODE, Status=$STATUS, Elapsed=${ELAPSED_MIN}min"

    # 提取关键指标
    ST_100=$(grep -E 'AstralLight \[single-thread\].*C=100' "$RUN_LOG" 2>/dev/null | head -1 | sed -n 's/.*mean=\([0-9.]*\).*/\1/p')
    ST_1000=$(grep -E 'AstralLight \[single-thread\].*C=1000' "$RUN_LOG" 2>/dev/null | head -1 | sed -n 's/.*mean=\([0-9.]*\).*/\1/p')

    # 写入摘要
    echo "${i},${START_TS},${END_TS},${ELAPSED_MIN},${STATUS},${ST_100:-NA},${ST_1000:-NA},,${ELAPSED_MIN}" >> "$SUMMARY_LOG"

    # 复制结果目录
    if [[ -d "${PROJECT_DIR}/benchmark-results" ]]; then
        LATEST_DIR=$(ls -td "${PROJECT_DIR}/benchmark-results"/comparison-* 2>/dev/null | head -1)
        if [[ -n "$LATEST_DIR" ]]; then
            echo "      Copying results: $LATEST_DIR → ${RUN_DIR}/results"
            cp -r "$LATEST_DIR" "${RUN_DIR}/results" 2>/dev/null || true
        fi
    fi

    # 运行间冷却
    echo "      Cooling 10s..."
    sleep 10
done

# ── 3/6: 聚合统计 ──────────────────────────────────────────────────
echo ""
echo "=== 3/6: 聚合统计 ==="
echo ""
echo "Run 摘要（来自 summary.csv）："
column -t -s',' "$SUMMARY_LOG" 2>/dev/null || cat "$SUMMARY_LOG"

echo ""
echo ""
echo "=== 4/6: 成功运行的输出目录 ==="
for i in $(seq 1 $REPEATS); do
    RESULTS_DIR="${BASE_DIR}/run-${i}/results"
    if [[ -d "$RESULTS_DIR" ]]; then
        LATEX_FILES=$(find "$RESULTS_DIR" -name '*.tex' 2>/dev/null | wc -l)
        CSV_FILES=$(find "$RESULTS_DIR" -name '*.csv' 2>/dev/null | wc -l)
        echo "  Run ${i}: ${RESULTS_DIR} (LaTeX: ${LATEX_FILES}, CSV: ${CSV_FILES})"
    fi
done

echo ""
echo "=== 5/6: LaTeX 表格合并 ==="
echo "    cd $BASE_DIR && for i in 1 2 3 4 5; do"
echo '      if [[ -f "run-${i}/results/layer1/comparison_latency.tex" ]]; then'
echo '        cat "run-${i}/results/layer1/comparison_latency.tex"'
echo "      fi"
echo "    done > all-latency-tables.tex"

echo ""
echo "=== 6/6: 清理临时文件 ==="

echo ""
echo "============================================"
echo " 全部完成！"
echo " 输出目录: ${BASE_DIR}/"
echo "============================================"
