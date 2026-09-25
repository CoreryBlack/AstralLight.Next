#!/bin/bash
# ============================================================
# AstralLight - 5x Independent Test Runs with Isolated Reports
# ============================================================
# Usage:
#   bash run_tests_5x.sh [OPTIONS]
#
# Options:
#   --skip-build      Skip Maven compilation (use existing JARs)
#   --module <name>   Test specific module only (general|identity|trustgraph)
#   --with-pit        Include PIT mutation testing (slow, ~10min per run)
#   --no-jacoco       Disable JaCoCo coverage report
#   --help            Show this help
#
# For a single run without cross-run comparison, use:
#   bash run_tests.sh
#
# Default: 5 independent runs, Surefire + JaCoCo, all modules
# ============================================================

set -euo pipefail

# ---- Configuration ----
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="docker/docker-compose-test.yml"
REPORT_BASE="test-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TOTAL_RUNS=5

# JVM / Maven options
MAVEN_OPTS="-Xms2G -Xmx4G"
REMOTE_TEST_PROP="-Dremote.test=true"
SUREFIRE_OPTS="-Dtestcontainers.dockerclient.strategy=org.testcontainers.dockerclient.UnixSocketClientProviderStrategy"

# ---- Parse Arguments ----
SKIP_BUILD=false
MODULE=""
WITH_PIT=false
WITH_JACOCO=true

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build)   SKIP_BUILD=true; shift ;;
        --module)       MODULE="$2"; shift 2 ;;
        --with-pit)     WITH_PIT=true; shift ;;
        --no-jacoco)    WITH_JACOCO=false; shift ;;
        --help)
            head -15 "$0" | grep '^#' | sed 's/^# \?//'
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# ---- Determine Module List ----
if [ -n "$MODULE" ]; then
    case "$MODULE" in
        general)    MODULES="AstralGeneral" ;;
        identity)   MODULES="AstralIdentity" ;;
        trustgraph) MODULES="AstralTrustGraph" ;;
        *) echo "Unknown module: $MODULE (general|identity|trustgraph)"; exit 1 ;;
    esac
else
    MODULES="AstralGeneral,AstralIdentity,AstralTrustGraph"
fi

# ---- Helper Functions ----

log() {
    echo "[$(date '+%H:%M:%S')] $*"
}

wait_for_services() {
    log "Waiting for Docker services to become healthy..."
    local max_wait=120
    local elapsed=0
    while [ $elapsed -lt $max_wait ]; do
        local mysql_ok redis_ok rabbitmq_ok
        mysql_ok=$(docker exec astral_test_mysql mysqladmin ping -h localhost -u root -proot 2>/dev/null && echo "OK" || echo "FAIL")
        redis_ok=$(docker exec astral_test_redis redis-cli ping 2>/dev/null | grep -c PONG || echo "0")
        rabbitmq_ok=$(docker exec astral_test_rabbitmq rabbitmq-diagnostics ping 2>/dev/null | grep -c 'Ping succeeded' || true)
        if [[ "$mysql_ok" == *"OK"* ]] && [[ "$redis_ok" -ge 1 ]] && [[ "$rabbitmq_ok" -ge 1 ]]; then
            log "All services healthy (waited ${elapsed}s)"
            return 0
        fi
        sleep 5
        elapsed=$((elapsed + 5))
    done
    log "WARNING: Services may not be fully healthy after ${max_wait}s, proceeding anyway"
}

start_infrastructure() {
    log "Starting test infrastructure via docker-compose..."
    # Pre-clean stale containers from previous runs
    docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" down -v 2>/dev/null || true
    docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" up -d
    wait_for_services
}

stop_infrastructure() {
    log "Stopping test infrastructure..."
    docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" down -v 2>/dev/null || true
}

restart_infrastructure() {
    log "Recreating test infrastructure from scratch (nuclear reset)..."
    docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" down -v 2>/dev/null || true
    docker compose -f "$PROJECT_ROOT/$COMPOSE_FILE" up -d
    wait_for_services
}

run_single_iteration() {
    local run_num=$1
    local run_dir="$REPORT_BASE/run_${run_num}_${TIMESTAMP}"

    log "========== Run ${run_num}/${TOTAL_RUNS} =========="
    log "Report directory: ${run_dir}"

    mkdir -p "$run_dir"

    # ---- Clean cross-run residue ----
    # Nuclear reset: destroy and recreate all containers to guarantee zero contamination
    # (auto-increment counters, Spring context caches, RabbitMQ queues, Redis state)
    if [ "$run_num" -gt 1 ]; then
        restart_infrastructure
        log "Full infrastructure reset complete"
    fi

    # 2. Local build artifacts
    for mod in $(echo "$MODULES" | tr ',' ' '); do
        rm -rf "${PROJECT_ROOT}/${mod}/target/surefire-reports"
        rm -rf "${PROJECT_ROOT}/${mod}/target/site/jacoco"
        rm -rf "${PROJECT_ROOT}/${mod}/target/pit-reports"
    done

    # ---- Build Maven command ----
    local mvn_goals
    local mvn_props="${REMOTE_TEST_PROP} ${SUREFIRE_OPTS}"
    # Use 'verify' when JaCoCo is enabled (report bound to verify phase in AstralGeneral)
    if [ "$WITH_JACOCO" = true ]; then
        mvn_goals="verify"
    else
        mvn_goals="test"
    fi

    if [ "$WITH_PIT" = true ]; then
        mvn_goals="test pitest:mutationCoverage"
    fi

    # ---- Execute tests ----
    local start_time=$(date +%s)

    export MAVEN_OPTS="$MAVEN_OPTS"
    cd "$PROJECT_ROOT"

    # Test execution timeout (seconds) — prevents infinite hangs from Redis reconnection loops
    local TEST_TIMEOUT=${TEST_TIMEOUT:-1800}

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

    # Use process substitution to capture exit code correctly with set -e
    # Use stdbuf -oL for line buffering to prevent pipe stalls with tee
    # Remove -q flag to show test progress in real time
    local exit_code=0
    timeout ${TEST_TIMEOUT} \
        mvn ${mvn_goals} \
        -pl "${MODULES}" \
        -am \
        -Dspring.profiles.active=test \
        ${mvn_props} \
        -Dmaven.test.failure.ignore=false \
        2>&1 | stdbuf -oL tee "${run_dir}/console.log" || exit_code=$?

    # Stop progress indicator
    if [ -n "$progress_pid" ]; then
        kill "$progress_pid" 2>/dev/null || true
        wait "$progress_pid" 2>/dev/null || true
    fi

    # Handle timeout exit code (124 = timed out)
    if [ $exit_code -eq 124 ]; then
        log "WARNING: Run ${run_num} timed out after ${TEST_TIMEOUT}s"
    fi

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # ---- Collect reports ----
    log "Collecting reports for run ${run_num}..."

    for mod in $(echo "$MODULES" | tr ',' ' '); do
        local mod_dir="${PROJECT_ROOT}/${mod}/target"
        local mod_name=$(echo "$mod" | tr '[:upper:]' '[:lower:]')

        # Surefire XML + TXT reports
        if [ -d "${mod_dir}/surefire-reports" ]; then
            mkdir -p "${run_dir}/${mod_name}/surefire"
            cp -r "${mod_dir}/surefire-reports/"* "${run_dir}/${mod_name}/surefire/" 2>/dev/null || true
        fi

        # JaCoCo coverage report
        if [ -d "${mod_dir}/site/jacoco" ] && [ "$WITH_JACOCO" = true ]; then
            mkdir -p "${run_dir}/${mod_name}/jacoco"
            cp -r "${mod_dir}/site/jacoco/"* "${run_dir}/${mod_name}/jacoco/" 2>/dev/null || true
        fi

        # PIT mutation report
        if [ -d "${mod_dir}/pit-reports" ] && [ "$WITH_PIT" = true ]; then
            mkdir -p "${run_dir}/${mod_name}/pit"
            cp -r "${mod_dir}/pit-reports/"* "${run_dir}/${mod_name}/pit/" 2>/dev/null || true
        fi
    done

    # ---- Generate run summary ----
    generate_run_summary "$run_num" "$run_dir" "$duration" "$exit_code"

    log "Run ${run_num} completed in ${duration}s (exit=${exit_code})"
    return $exit_code
}

generate_run_summary() {
    local run_num=$1
    local run_dir=$2
    local duration=$3
    local exit_code=$4

    local summary_file="${run_dir}/summary.txt"

    {
        echo "============================================================"
        echo "AstralLight Test Run #${run_num} Summary"
        echo "============================================================"
        echo "Timestamp:    $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Duration:     ${duration}s"
        echo "Exit Code:    ${exit_code}"
        echo "Modules:      ${MODULES}"
        echo "JaCoCo:       ${WITH_JACOCO}"
        echo "PIT:          ${WITH_PIT}"
        echo ""

        # Parse Surefire results per module
        for mod in $(echo "$MODULES" | tr ',' ' '); do
            local mod_name=$(echo "$mod" | tr '[:upper:]' '[:lower:]')
            local surefire_dir="${run_dir}/${mod_name}/surefire"

            echo "---- ${mod} ----"
            if [ -d "$surefire_dir" ]; then
                local total_tests=0
                local total_failures=0
                local total_errors=0
                local total_skipped=0

                for xml_file in "${surefire_dir}"/*.xml; do
                    if [ -f "$xml_file" ]; then
                        local tests failures errors skipped
                        tests=$(grep -oP 'tests="\K[0-9]+' "$xml_file" 2>/dev/null || echo "0")
                        failures=$(grep -oP 'failures="\K[0-9]+' "$xml_file" 2>/dev/null || echo "0")
                        errors=$(grep -oP 'errors="\K[0-9]+' "$xml_file" 2>/dev/null || echo "0")
                        skipped=$(grep -oP 'skipped="\K[0-9]+' "$xml_file" 2>/dev/null || echo "0")
                        total_tests=$((total_tests + tests))
                        total_failures=$((total_failures + failures))
                        total_errors=$((total_errors + errors))
                        total_skipped=$((total_skipped + skipped))
                    fi
                done

                echo "  Tests:    ${total_tests}"
                echo "  Failures: ${total_failures}"
                echo "  Errors:   ${total_errors}"
                echo "  Skipped:  ${total_skipped}"
                echo "  Pass Rate: $(awk "BEGIN {if(${total_tests}>0) printf \"%.1f%%\", (${total_tests}-${total_failures}-${total_errors})/${total_tests}*100; else print \"N/A\"}")"
            else
                echo "  No Surefire reports found"
            fi
            echo ""
        done

        # JaCoCo summary
        if [ "$WITH_JACOCO" = true ]; then
            echo "---- JaCoCo Coverage ----"
            for mod in $(echo "$MODULES" | tr ',' ' '); do
                local mod_name=$(echo "$mod" | tr '[:upper:]' '[:lower:]')
                local jacoco_csv="${run_dir}/${mod_name}/jacoco/jacoco.csv"
                if [ -f "$jacoco_csv" ]; then
                    echo "  ${mod}:"
                    # Extract line coverage from CSV (header + data rows)
                    awk -F',' 'NR>1 {printf "    %s: %s/%s lines (%.1f%%)\n", $3, $11, $10, ($11/$10)*100}' "$jacoco_csv" 2>/dev/null || echo "    (parse error)"
                else
                    echo "  ${mod}: No JaCoCo report"
                fi
            done
            echo ""
        fi

    } > "$summary_file"

    cat "$summary_file"
}

generate_cross_run_report() {
    local cross_dir="${REPORT_BASE}/cross_run_${TIMESTAMP}"
    mkdir -p "$cross_dir"

    log "Generating cross-run comparison report..."

    {
        echo "============================================================"
        echo "AstralLight - 5-Run Cross-Comparison Report"
        echo "============================================================"
        echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Modules:   ${MODULES}"
        echo ""

        # Header
        printf "%-8s" "Run"
        for mod in $(echo "$MODULES" | tr ',' ' '); do
            local mod_name=$(echo "$mod" | tr '[:upper:]' '[:lower:]')
            printf "%-12s %-10s %-10s %-10s" \
                "${mod_name}_tests" "${mod_name}_fail" "${mod_name}_err" "${mod_name}_rate"
        done
        printf "%-10s\n" "Duration"

        # Data rows
        for i in $(seq 1 $TOTAL_RUNS); do
            local run_dir="${REPORT_BASE}/run_${i}_${TIMESTAMP}"
            local summary="${run_dir}/summary.txt"

            if [ ! -f "$summary" ]; then
                printf "%-8s (missing)\n" "Run ${i}"
                continue
            fi

            printf "%-8s" "Run ${i}"

            for mod in $(echo "$MODULES" | tr ',' ' '); do
                local mod_name=$(echo "$mod" | tr '[:upper:]' '[:lower:]')
                local surefire_dir="${run_dir}/${mod_name}/surefire"

                local total_tests=0 total_failures=0 total_errors=0
                if [ -d "$surefire_dir" ]; then
                    for xml_file in "${surefire_dir}"/*.xml; do
                        if [ -f "$xml_file" ]; then
                            total_tests=$((total_tests + $(grep -oP 'tests="\K[0-9]+' "$xml_file" 2>/dev/null || echo "0")))
                            total_failures=$((total_failures + $(grep -oP 'failures="\K[0-9]+' "$xml_file" 2>/dev/null || echo "0")))
                            total_errors=$((total_errors + $(grep -oP 'errors="\K[0-9]+' "$xml_file" 2>/dev/null || echo "0")))
                        fi
                    done
                fi

                local pass_rate="N/A"
                if [ $total_tests -gt 0 ]; then
                    pass_rate="$(awk "BEGIN {printf \"%.1f%%\", (${total_tests}-${total_failures}-${total_errors})/${total_tests}*100}")"
                fi

                printf "%-12s %-10s %-10s %-10s" \
                    "$total_tests" "$total_failures" "$total_errors" "$pass_rate"
            done

            # Extract duration from summary
            local dur=$(grep "^Duration:" "$summary" 2>/dev/null | awk '{print $2}' || echo "?")
            printf "%-10s\n" "${dur}s"
        done

        echo ""
        echo "---- Consistency Check ----"
        echo "All 5 runs should produce identical test counts and pass rates."
        echo "Any variation indicates non-deterministic test behavior."

    } > "${cross_dir}/comparison.txt"

    cat "${cross_dir}/comparison.txt"

    # Also generate CSV for easy analysis
    {
        echo "run,module,tests,failures,errors,skipped,pass_rate,duration_s"

        for i in $(seq 1 $TOTAL_RUNS); do
            local run_dir="${REPORT_BASE}/run_${i}_${TIMESTAMP}"
            local dur=$(grep "^Duration:" "${run_dir}/summary.txt" 2>/dev/null | awk '{print $2}' || echo "0")

            for mod in $(echo "$MODULES" | tr ',' ' '); do
                local mod_name=$(echo "$mod" | tr '[:upper:]' '[:lower:]')
                local surefire_dir="${run_dir}/${mod_name}/surefire"

                local total_tests=0 total_failures=0 total_errors=0 total_skipped=0
                if [ -d "$surefire_dir" ]; then
                    for xml_file in "${surefire_dir}"/*.xml; do
                        if [ -f "$xml_file" ]; then
                            total_tests=$((total_tests + $(grep -oP 'tests="\K[0-9]+' "$xml_file" 2>/dev/null || echo "0")))
                            total_failures=$((total_failures + $(grep -oP 'failures="\K[0-9]+' "$xml_file" 2>/dev/null || echo "0")))
                            total_errors=$((total_errors + $(grep -oP 'errors="\K[0-9]+' "$xml_file" 2>/dev/null || echo "0")))
                            total_skipped=$((total_skipped + $(grep -oP 'skipped="\K[0-9]+' "$xml_file" 2>/dev/null || echo "0")))
                        fi
                    done
                fi

                local pass_rate="0"
                if [ $total_tests -gt 0 ]; then
                    pass_rate="$(awk "BEGIN {printf \"%.4f\", (${total_tests}-${total_failures}-${total_errors})/${total_tests}}")"
                fi

                echo "${i},${mod_name},${total_tests},${total_failures},${total_errors},${total_skipped},${pass_rate},${dur}"
            done
        done
    } > "${cross_dir}/comparison.csv"

    log "Cross-run report saved to: ${cross_dir}/"
}

# ============================================================
# Main
# ============================================================

main() {
    log "AstralLight 5x Independent Test Runner"
    log "Project root: ${PROJECT_ROOT}"
    log "Modules: ${MODULES}"
    log "JaCoCo: ${WITH_JACOCO}, PIT: ${WITH_PIT}"
    log "Report base: ${REPORT_BASE}/"
    echo ""

    # ---- Step 1: Build ----
    if [ "$SKIP_BUILD" = false ]; then
        log "Building project..."
        cd "$PROJECT_ROOT"
        # Show build progress with line-buffered output (avoid pipe buffering stalls)
        mvn clean install -DskipTests \
            -pl "AstralGeneral,${MODULES}" \
            -am 2>&1 | stdbuf -oL grep -E '^\[INFO\] BUILD|^\[ERROR\]|^\[WARNING\] |Reactor Summary' || true
        log "Build complete"
    else
        log "Skipping build (--skip-build)"
    fi

    # ---- Step 2: Start infrastructure ----
    start_infrastructure

    # ---- Step 3: Run tests ----
    local failed_runs=0

    log "Running ${TOTAL_RUNS} independent iterations"

    for i in $(seq 1 $TOTAL_RUNS); do
        if ! run_single_iteration "$i"; then
            failed_runs=$((failed_runs + 1))
            log "WARNING: Run ${i} had test failures"
        fi

        if [ "$i" -lt "$TOTAL_RUNS" ]; then
            log "Pausing 10s before next run..."
            sleep 10
        fi
    done

    # ---- Step 4: Stop infrastructure ----
    stop_infrastructure

    # ---- Step 5: Cross-run comparison ----
    generate_cross_run_report

    # ---- Final summary ----
    echo ""
    log "============================================================"
    log "All runs complete"
    log "  Total runs:    ${TOTAL_RUNS}"
    log "  Failed runs:   ${failed_runs}"
    log "  Reports:       ${REPORT_BASE}/"
    log "  Cross-run:     ${REPORT_BASE}/cross_run_${TIMESTAMP}/"
    log "============================================================"

    if [ $failed_runs -gt 0 ]; then
        exit 1
    fi
}

main "$@"
