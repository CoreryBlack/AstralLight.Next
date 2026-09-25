#!/bin/bash
# ============================================================
# AstralLight - 5x Native Benchmark Runs with Cross-Run Comparison
# ============================================================
# Prerequisites:
#   - Docker & docker-compose installed
#   - AstralBenchmark JAR built (mvn clean package -DskipTests)
#
# Usage:
#   bash scripts/run_native_bench_5x.sh          # 5 independent runs
#   bash scripts/run_native_bench_5x.sh --keep   # Keep containers after all runs
#   bash scripts/run_native_bench_5x.sh --help   # Show this help
#
# For a single run, use:
#   bash scripts/run_native_bench.sh
#
# Default: 5 independent runs, nuclear container reset between runs,
#          cross-run CSV comparison of RQ metrics
# ============================================================

set -euo pipefail

# ---- Configuration ----
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
ASTRA_DIR="${REPO_DIR}/evaluation/benchmark-java"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose-benchmark.yml"
REPORT_BASE="$ASTRA_DIR/benchmark-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TOTAL_RUNS=5

# Benchmark JVM options
: "${BENCHMARK_MYSQL_ROOT_PASSWORD:?BENCHMARK_MYSQL_ROOT_PASSWORD is required}"
BENCHMARK_DB_NAME="${BENCHMARK_DB_NAME:-astrallight}"
export BENCHMARK_DB_NAME
JAVA_XMS="16G"
JAVA_XMX="16G"
JAVA_GC_OPTS="-XX:+UseZGC -XX:+ZGenerational -XX:+AlwaysPreTouch -XX:ConcGCThreads=4"

# ---- Parse Arguments ----
KEEP_CONTAINERS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --keep) KEEP_CONTAINERS=true; shift ;;
        --help)
            sed -n '2,17p' "$0" | sed 's/^# \?//'
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ---- Helper Functions ----

log() {
    echo "[$(date '+%H:%M:%S')] $*"
}

phase_log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

# Wait for MySQL to be healthy
wait_for_mysql() {
    local max_wait=120
    local waited=0
    while ! docker exec astral_bench_mysql mysqladmin ping -h localhost -u root -p"${BENCHMARK_MYSQL_ROOT_PASSWORD}" --silent 2>/dev/null; do
        sleep 2
        waited=$((waited + 2))
        if [ $waited -ge $max_wait ]; then
            log "ERROR: MySQL not ready after ${max_wait}s"
            docker compose -f "$COMPOSE_FILE" logs mysql 2>/dev/null || true
            return 1
        fi
    done
    log "MySQL ready after ${waited}s"
    return 0
}

# Verify schema was loaded
verify_schema() {
    sleep 5
    local table_count
    table_count=$(docker exec astral_bench_mysql mysql -u root -p"${BENCHMARK_MYSQL_ROOT_PASSWORD}" "${BENCHMARK_DB_NAME}" -sN \
        -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${BENCHMARK_DB_NAME}'" 2>/dev/null || echo "0")
    log "Schema loaded: ${table_count} tables"
    if [ "$table_count" -lt 10 ]; then
        log "ERROR: Too few tables (${table_count}), schema init may have failed"
        docker compose -f "$COMPOSE_FILE" logs mysql 2>/dev/null || true
        return 1
    fi
    return 0
}

# Wait for Redis
wait_for_redis() {
    sleep 2
    if docker exec astral_bench_redis redis-cli ping > /dev/null 2>&1; then
        log "Redis ready"
        return 0
    fi
    log "WARN: Redis not responding"
    return 1
}

# Full infrastructure startup with health checks
start_infrastructure() {
    log "Starting benchmark infrastructure..."

    # Export ports/env for docker-compose variable substitution
    export DB_PORT=3308
    export REDIS_PORT=6381
    export DB_PASSWORD="${BENCHMARK_MYSQL_ROOT_PASSWORD}"
    export DB_NAME="${BENCHMARK_DB_NAME}"

    docker compose -f "$COMPOSE_FILE" up -d

    if ! wait_for_mysql; then
        return 1
    fi

    if ! verify_schema; then
        return 1
    fi

    wait_for_redis

    log "Infrastructure ready"
    return 0
}

# Nuclear reset: destroy and recreate all containers
restart_infrastructure() {
    log "Recreating benchmark infrastructure from scratch (nuclear reset)..."
    docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
    docker rm -f astral_bench_mysql astral_bench_redis 2>/dev/null || true
    start_infrastructure
}

# Stop infrastructure
stop_infrastructure() {
    log "Stopping benchmark infrastructure..."
    docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
    docker rm -f astral_bench_mysql astral_bench_redis 2>/dev/null || true
}

# Run a single benchmark iteration
run_single_iteration() {
    local run_num=$1
    local run_dir="${REPORT_BASE}/native_5x_run${run_num}_${TIMESTAMP}"
    local run_log="${run_dir}/benchmark.log"

    log "========== Run ${run_num}/${TOTAL_RUNS} =========="
    log "Report directory: ${run_dir}"

    mkdir -p "$run_dir"

    # Nuclear reset for runs 2+ to guarantee zero contamination
    if [ "$run_num" -gt 1 ]; then
        restart_infrastructure
        log "Full infrastructure reset complete"
    fi

    # Clean benchmark-results to isolate this run's output
    rm -rf "$REPORT_BASE/native-"* 2>/dev/null || true

    # ---- Execute benchmark ----
    local start_time=$(date +%s)

    export DB_HOST=localhost
    export DB_USER=root
    export REDIS_HOST=localhost

    phase_log "DB: localhost:${DB_PORT}/astrallight  Redis: localhost:${REDIS_PORT}" | tee "$run_log"
    phase_log "JVM: ZGC Generational -Xms${JAVA_XMS} -Xmx${JAVA_XMX}" | tee -a "$run_log"

    # Background progress indicator — prints elapsed time every 30s
    local progress_pid=""
    (
        while true; do
            sleep 30
            local elapsed=$(($(date +%s) - start_time))
            log "  [progress] Run ${run_num} running... ${elapsed}s elapsed"
        done
    ) &
    progress_pid=$!

    local exit_code=0
    cd "$ASTRA_DIR"

    java -Xms${JAVA_XMS} -Xmx${JAVA_XMX} ${JAVA_GC_OPTS} \
        -jar target/AstralBenchmark-0.0.1-SNAPSHOT.jar \
        --spring.profiles.active=benchmark \
        >> "$run_log" 2>&1 || exit_code=$?

    # Stop progress indicator
    if [ -n "$progress_pid" ]; then
        kill "$progress_pid" 2>/dev/null || true
        wait "$progress_pid" 2>/dev/null || true
    fi

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    phase_log "Benchmark exit code: $exit_code" | tee -a "$run_log"

    # ---- Collect benchmark output ----
    log "Collecting benchmark outputs for run ${run_num}..."

    local result_dir=$(ls -dt "$REPORT_BASE/native-"* 2>/dev/null | head -1)
    if [ -n "$result_dir" ]; then
        mkdir -p "${run_dir}/benchmark-output/"
        cp -r "$result_dir"/* "${run_dir}/benchmark-output/" 2>/dev/null || true
        log "Benchmark outputs archived from: $(basename "$result_dir")"
    else
        log "WARN: No benchmark output directory found (native-*)"
    fi

    # ---- Generate run summary ----
    generate_run_summary "$run_num" "$run_dir" "$duration" "$exit_code"

    log "Run ${run_num} completed in ${duration}s (exit=${exit_code})"
    return $exit_code
}

# Generate per-run summary
generate_run_summary() {
    local run_num=$1
    local run_dir=$2
    local duration=$3
    local exit_code=$4
    local summary_file="${run_dir}/summary.txt"

    {
        echo "============================================================"
        echo "AstralLight Native Benchmark Run #${run_num} Summary"
        echo "============================================================"
        echo "Timestamp:    $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Duration:     ${duration}s ($((duration / 60))m $((duration % 60))s)"
        echo "Exit Code:    ${exit_code}"
        echo "JVM:          -Xms${JAVA_XMS} -Xmx${JAVA_XMX} ZGC Generational"
        echo ""

        # List benchmark output files
        local output_dir="${run_dir}/benchmark-output"
        if [ -d "$output_dir" ] && [ "$(ls -A "$output_dir" 2>/dev/null)" ]; then
            echo "---- Benchmark Output Files ----"
            for f in "$output_dir"/*.csv "$output_dir"/*.log "$output_dir"/*.txt; do
                [ -f "$f" ] && echo "  $(basename "$f")"
            done
            echo ""

            # Count RQ CSV files
            local rq1_count rq2_count rq3_count rq4_count
            rq1_count=$(ls "$output_dir"/rq1_*.csv 2>/dev/null | wc -l)
            rq2_count=$(ls "$output_dir"/rq2_*.csv 2>/dev/null | wc -l)
            rq3_count=$(ls "$output_dir"/rq3_*.csv 2>/dev/null | wc -l)
            rq4_count=$(ls "$output_dir"/rq4_*.csv 2>/dev/null | wc -l)
            echo "  RQ1 files: ${rq1_count}"
            echo "  RQ2 files: ${rq2_count}"
            echo "  RQ3 files: ${rq3_count}"
            echo "  RQ4 files: ${rq4_count}"
        else
            echo "  No benchmark output files collected"
        fi
    } > "$summary_file"

    cat "$summary_file"
}

# Generate cross-run comparison report
generate_cross_run_report() {
    local cross_dir="${REPORT_BASE}/native_5x_cross_${TIMESTAMP}"
    mkdir -p "$cross_dir"

    log "Generating cross-run comparison report..."

    {
        echo "============================================================"
        echo "AstralLight Native Benchmark — 5-Run Cross-Comparison"
        echo "============================================================"
        echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "JVM: -Xms${JAVA_XMS} -Xmx${JAVA_XMX} ZGC Generational"
        echo ""

        # Header
        printf "%-8s %-12s %-10s %-14s %-14s %-14s %-14s\n" \
            "Run" "Duration" "Exit" "RQ1_Files" "RQ2_Files" "RQ3_Files" "RQ4_Files"
        printf "%-8s %-12s %-10s %-14s %-14s %-14s %-14s\n" \
            "--------" "------------" "----------" "--------------" "--------------" "--------------" "--------------"

        for i in $(seq 1 $TOTAL_RUNS); do
            local run_dir="${REPORT_BASE}/native_5x_run${i}_${TIMESTAMP}"
            local summary="${run_dir}/summary.txt"

            if [ ! -f "$summary" ]; then
                printf "%-8s (missing)\n" "Run ${i}"
                continue
            fi

            local dur exit_c
            dur=$(grep "^Duration:" "$summary" 2>/dev/null | awk '{print $2}' || echo "?")
            exit_c=$(grep "^Exit Code:" "$summary" 2>/dev/null | awk '{print $3}' || echo "?")

            local output_dir="${run_dir}/benchmark-output"
            local rq1=0 rq2=0 rq3=0 rq4=0
            if [ -d "$output_dir" ]; then
                rq1=$(ls "$output_dir"/rq1_*.csv 2>/dev/null | wc -l)
                rq2=$(ls "$output_dir"/rq2_*.csv 2>/dev/null | wc -l)
                rq3=$(ls "$output_dir"/rq3_*.csv 2>/dev/null | wc -l)
                rq4=$(ls "$output_dir"/rq4_*.csv 2>/dev/null | wc -l)
            fi

            printf "%-8s %-12s %-10s %-14s %-14s %-14s %-14s\n" \
                "Run ${i}" "$dur" "$exit_c" "$rq1" "$rq2" "$rq3" "$rq4"
        done

        echo ""
        echo "---- Consistency Check ----"
        echo "All 5 runs should produce identical RQ output file counts."
        echo "Any variation indicates non-deterministic benchmark behavior"
        echo "or infrastructure-level interference."

    } > "${cross_dir}/comparison.txt"

    cat "${cross_dir}/comparison.txt"

    # Also generate CSV for easy analysis
    {
        echo "run,duration_s,exit_code,rq1_files,rq2_files,rq3_files,rq4_files"

        for i in $(seq 1 $TOTAL_RUNS); do
            local run_dir="${REPORT_BASE}/native_5x_run${i}_${TIMESTAMP}"
            local summary="${run_dir}/summary.txt"

            local dur="0" exit_c="-1" rq1="0" rq2="0" rq3="0" rq4="0"

            if [ -f "$summary" ]; then
                dur=$(grep "^Duration:" "$summary" 2>/dev/null | awk '{print $2}' || echo "0")
                exit_c=$(grep "^Exit Code:" "$summary" 2>/dev/null | awk '{print $3}' || echo "-1")
            fi

            local output_dir="${run_dir}/benchmark-output"
            if [ -d "$output_dir" ]; then
                rq1=$(ls "$output_dir"/rq1_*.csv 2>/dev/null | wc -l)
                rq2=$(ls "$output_dir"/rq2_*.csv 2>/dev/null | wc -l)
                rq3=$(ls "$output_dir"/rq3_*.csv 2>/dev/null | wc -l)
                rq4=$(ls "$output_dir"/rq4_*.csv 2>/dev/null | wc -l)
            fi

            echo "${i},${dur},${exit_c},${rq1},${rq2},${rq3},${rq4}"
        done
    } > "${cross_dir}/comparison.csv"

    log "Cross-run report saved to: ${cross_dir}/"
}

# Clean old results (keep latest 3 sets)
clean_old_results() {
    cd "$REPORT_BASE" 2>/dev/null || return 0
    # Clean old native_5x_cross_* directories (keep latest 3)
    ls -dt native_5x_cross_* 2>/dev/null | tail -n +4 | xargs rm -rf 2>/dev/null || true
    # Clean old native_5x_run* directories (keep latest 3 sets = 15 directories)
    ls -dt native_5x_run* 2>/dev/null | tail -n +16 | xargs rm -rf 2>/dev/null || true
    cd "$ASTRA_DIR"
}

# ============================================================
# Main
# ============================================================

main() {
    log "============================================================"
    log "AstralLight Native Benchmark — 5x Independent Runner"
    log "============================================================"
    log "Project:     ${ASTRA_DIR}"
    log "Compose:     ${COMPOSE_FILE}"
    log "Total runs:  ${TOTAL_RUNS}"
    log "Keep:        ${KEEP_CONTAINERS}"
    echo ""

    # ---- Step 0: Clean old results ----
    log "Cleaning old benchmark results (keeping latest 3)..."
    clean_old_results

    # ---- Step 1: Build ----
    log "Building AstralBenchmark JAR (native-benchmark profile)..."
    cd "$ASTRA_DIR"
    mvn clean package -DskipTests -pl AstralBenchmark -am -Pdefault -q 2>&1 | tail -5
    if [ ${PIPESTATUS[0]} -ne 0 ]; then
        log "ERROR: Build failed"
        exit 1
    fi
    log "Build complete"

    # ---- Step 2: Start infrastructure for first run ----
    if ! start_infrastructure; then
        log "ERROR: Failed to start infrastructure"
        exit 1
    fi

    # ---- Step 3: Run benchmark iterations ----
    local failed_runs=0

    log "Running ${TOTAL_RUNS} independent benchmark iterations"

    for i in $(seq 1 $TOTAL_RUNS); do
        if ! run_single_iteration "$i"; then
            failed_runs=$((failed_runs + 1))
            log "WARNING: Run ${i} had failures"
        fi

        if [ "$i" -lt "$TOTAL_RUNS" ]; then
            log "Pausing 10s before next run..."
            sleep 10
        fi
    done

    # ---- Step 4: Stop infrastructure ----
    if [ "$KEEP_CONTAINERS" = false ]; then
        stop_infrastructure
        log "Containers and volumes removed"
    else
        log "Keeping containers (--keep flag)"
    fi

    # ---- Step 5: Cross-run comparison ----
    generate_cross_run_report

    # ---- Final summary ----
    echo ""
    log "============================================================"
    log "All benchmark runs complete"
    log "  Total runs:    ${TOTAL_RUNS}"
    log "  Failed runs:   ${failed_runs}"
    log "  Reports:       ${REPORT_BASE}/native_5x_run*_${TIMESTAMP}/"
    log "  Cross-run:     ${REPORT_BASE}/native_5x_cross_${TIMESTAMP}/"
    log "============================================================"

    if [ $failed_runs -gt 0 ]; then
        exit 1
    fi
}

main "$@"
